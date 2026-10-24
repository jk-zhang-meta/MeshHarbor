// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P4a — the MEMBER side of an org-relay session: the 3-way bind, and
//! a [`RelayConn`] that carries WireGuard ciphertext through the relay.
//!
//! The server mints a session and pushes it (`rc:overlay.relay_session`);
//! this module is what a member does with it. Two halves:
//!
//! * [`bind`] / [`bind_any`] — the handshake of `docs/fr/FR-19-peer-relays.md`
//!   §4 from the client's chair: `Bind{nonce, tag₁}` → `Challenge{nonce,
//!   cookie}` → `Answer{nonce, cookie, tag₂}`. ⚠️ `tag₁` covers NO address —
//!   a NAT'd member cannot know its own mapped `addr:port` on its first
//!   packet, and the first implementation of the relay side got this wrong
//!   (P2a, corrected in P2c). The relay binds the observed source at the
//!   challenge step, which is why a member never has to know it.
//! * [`OrgRelayConn`] — the carrier. `send_to` prefixes the 8-byte org-relay
//!   header; `recv_from` returns only THIS session's data frames arriving from
//!   the relay's address, so a stray datagram on the socket can never reach
//!   the WireGuard decapsulator as if it came through the relay. The existing
//!   `Carrier::Relay { conn: Arc<dyn RelayConn>, .. }` is fully opaque to the
//!   send path, so nothing above this file changes (§6).
//!
//! ## What "bound" means from here
//!
//! The wire has no bind-ack. A **Challenge is the success signal**: the relay
//! challenges only a `Bind` whose `tag₁` verifies against one of the
//! session's member secrets, so receiving one proves the relay is reachable,
//! holds this session, and accepted this member's identity. After the
//! `Answer` the relay is bound to this source; whether the OTHER member has
//! bound yet is not knowable here and does not need to be — WireGuard's own
//! handshake retries cover the gap, and the carrier-health sweep convicts a
//! leg that never comes up, exactly as it does for TURN.
//!
//! ## Re-binding
//!
//! A symmetric NAT can remap a member mid-session. The relay permits a
//! re-bind under a valid `tag₁` (§4, load-bearing for exactly that
//! population), and from here that is simply [`bind`] again on whatever
//! socket the member now sends from — same VNI, same secret, new source. The
//! runtime re-binds on every carrier (re)build, which is where a roam
//! surfaces.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::debug;

use super::bind::{BindSecret, Nonce, tag1, tag2};
use super::wire::{ControlFrame, build_data, parse_data};
use crate::transport::relay::{RelayConn, RelayTransport};

/// Receive buffer for control frames. A challenge is one fixed-size frame; a
/// larger buffer only means a stray datagram is read whole and dropped.
const CTRL_BUF: usize = 256;
/// Data frames: the overlay MTU plus WireGuard and org-relay overhead, with
/// headroom. Anything larger is not ours.
const DATA_BUF: usize = 2048;

/// Why a bind did not complete.
#[derive(Debug)]
pub enum BindError {
    /// No valid challenge arrived in time. ⚠️ Indistinguishable by design from
    /// "the relay refused us" — a relay never answers a bind it will not
    /// honour (a wrong secret, an unknown VNI), because an answer would be
    /// an oracle. Both read as "this endpoint did not work for us".
    Timeout,
    /// The socket reported the endpoint unreachable while waiting — an ICMP
    /// port-unreachable surfaces as a `recv` error on Windows rather than as
    /// silence. Means what [`Self::Timeout`] means: this endpoint did not work.
    Unreachable(io::Error),
    /// No endpoint to try.
    NoEndpoint,
    /// The socket itself failed on send — not about the endpoint.
    Io(io::Error),
}

impl BindError {
    /// "This endpoint did not answer" in either of the two forms it takes.
    pub fn is_no_answer(&self) -> bool {
        matches!(self, BindError::Timeout | BindError::Unreachable(_))
    }
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::Timeout => write!(f, "no challenge from the relay before the deadline"),
            BindError::Unreachable(e) => write!(f, "relay endpoint unreachable: {e}"),
            BindError::NoEndpoint => write!(f, "no relay endpoint to bind to"),
            BindError::Io(e) => write!(f, "socket error during bind: {e}"),
        }
    }
}

impl std::error::Error for BindError {}

impl From<io::Error> for BindError {
    fn from(e: io::Error) -> Self {
        BindError::Io(e)
    }
}

fn fresh_nonce() -> Nonce {
    let mut n = [0u8; super::bind::NONCE_LEN];
    rand::rng().fill_bytes(&mut n);
    n
}

/// Run the member's half of the bind against `relay` on `sock`.
///
/// Returns the round-trip time to the challenge on success. The nonce is
/// fresh per attempt, echoed by the relay and covered by both MACs, so a
/// captured exchange does not replay into a later attempt.
pub async fn bind(
    sock: &UdpSocket,
    relay: SocketAddr,
    vni: u32,
    generation: u64,
    secret: &BindSecret,
    deadline: Duration,
) -> Result<Duration, BindError> {
    // A Serve push and this member's first UDP Bind arrive over independent
    // connections. Loss/reordering must not strand a valid candidate for the
    // entire budget. Retransmit one fresh attempt's EXACT Bind, never expand
    // its original deadline, and never exceed eight sends per endpoint.
    const MAX_SENDS: usize = 8;
    const RETRY_BASE: Duration = Duration::from_millis(250);
    const RETRY_MAX: Duration = Duration::from_secs(2);
    let nonce = fresh_nonce();
    let t1 = tag1(secret, vni, generation, &nonce);
    let request = ControlFrame::Bind { nonce, tag1: t1 }.encode(vni);
    let started = Instant::now();
    let mut sent = 0usize;
    let mut next_send = Duration::ZERO;
    let mut retry_gap = RETRY_BASE;
    let mut buf = [0u8; CTRL_BUF];
    let cookie = loop {
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            return Err(BindError::Timeout);
        }
        if sent < MAX_SENDS && elapsed >= next_send {
            match timeout(
                deadline.saturating_sub(started.elapsed()),
                sock.send_to(&request, relay),
            )
            .await
            {
                Ok(result) => {
                    result?;
                }
                Err(_) => return Err(BindError::Timeout),
            }
            sent += 1;
            next_send = started.elapsed().saturating_add(retry_gap);
            retry_gap = retry_gap.saturating_mul(2).min(RETRY_MAX);
        }
        let wake = if sent < MAX_SENDS {
            deadline.min(next_send)
        } else {
            deadline
        };
        let wait = wake.saturating_sub(started.elapsed());
        if wait.is_zero() {
            continue;
        }
        let (n, from) = match timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(BindError::Unreachable(e)),
            Err(_) => continue,
        };
        // Receiving noise cannot reset the retry timer or the original budget.
        // Only the exact relay, VNI, and this attempt's nonce can challenge us.
        if from != relay {
            continue;
        }
        match ControlFrame::decode(&buf[..n]) {
            Some((
                v,
                ControlFrame::Challenge {
                    nonce: echoed,
                    cookie,
                },
            )) if v == vni && echoed == nonce => {
                break cookie;
            }
            _ => continue,
        }
    };
    let rtt = started.elapsed();
    let t2 = tag2(secret, &cookie, &nonce);
    let remaining = deadline.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(BindError::Timeout);
    }
    match timeout(
        remaining,
        sock.send_to(
            &ControlFrame::Answer {
                nonce,
                cookie,
                tag2: t2,
            }
            .encode(vni),
            relay,
        ),
    )
    .await
    {
        Ok(result) => {
            result?;
        }
        Err(_) => return Err(BindError::Timeout),
    }
    Ok(rtt)
}

/// One endpoint's outcome from [`bind_any`] — what the member reports upstream
/// as `rc:overlay.relay_probe`, one row per endpoint tried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointOutcome {
    pub endpoint: SocketAddr,
    pub reachable: bool,
    pub rtt: Option<Duration>,
}

/// Try the minted endpoints in the order the server gave them, stopping at
/// the first that challenges. `per_endpoint` bounds each attempt so a dead
/// first endpoint cannot eat the whole bind budget.
///
/// Returns the actual bound socket, endpoint, and every outcome observed on the way
/// (including the winner's), so the caller can report each one.
pub async fn bind_any(
    endpoints: &[SocketAddr],
    vni: u32,
    generation: u64,
    secret: &BindSecret,
    per_endpoint: Duration,
) -> Result<(UdpSocket, SocketAddr, Vec<EndpointOutcome>), (BindError, Vec<EndpointOutcome>)> {
    if endpoints.is_empty() {
        return Err((BindError::NoEndpoint, Vec::new()));
    }
    let mut outcomes = Vec::with_capacity(endpoints.len());
    for &ep in endpoints {
        // Each endpoint owns a matching-family socket. Keep the winning socket:
        // the relay authenticated its observed source, not a later replacement.
        let addr = if ep.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = match UdpSocket::bind(addr).await {
            Ok(sock) => sock,
            Err(error) => {
                outcomes.push(EndpointOutcome {
                    endpoint: ep,
                    reachable: false,
                    rtt: None,
                });
                return Err((BindError::Io(error), outcomes));
            }
        };
        match bind(&sock, ep, vni, generation, secret, per_endpoint).await {
            Ok(rtt) => {
                outcomes.push(EndpointOutcome {
                    endpoint: ep,
                    reachable: true,
                    rtt: Some(rtt),
                });
                return Ok((sock, ep, outcomes));
            }
            Err(e) if e.is_no_answer() => {
                debug!(relay = %ep, vni, %e, "org-relay bind: no challenge from this endpoint");
                outcomes.push(EndpointOutcome {
                    endpoint: ep,
                    reachable: false,
                    rtt: None,
                });
            }
            Err(e) => {
                outcomes.push(EndpointOutcome {
                    endpoint: ep,
                    reachable: false,
                    rtt: None,
                });
                return Err((e, outcomes));
            }
        }
    }
    Err((BindError::Timeout, outcomes))
}

/// A bound member's carrier: WireGuard ciphertext in, org-relay data frames
/// out, and back.
pub struct OrgRelayConn {
    sock: Arc<UdpSocket>,
    relay: SocketAddr,
    vni: u32,
    /// The stable placeholder `dst` a `Carrier::Relay` is built with. The
    /// carrier discards it on recv — a session is one peer by construction —
    /// so it only has to be consistent and valid, the DERP convention.
    synth_peer: SocketAddr,
    /// Operator-facing name of the relay node, for `roomler peers`'
    /// `relay_via`.
    label: String,
    alive: AtomicBool,
}

impl OrgRelayConn {
    /// Wrap an already-bound socket. `synth_peer` is derived from the VNI so
    /// two sessions on one node never share a placeholder.
    pub fn new(sock: Arc<UdpSocket>, relay: SocketAddr, vni: u32, label: String) -> Self {
        let v = vni.to_be_bytes();
        let synth_peer = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, v[1], v[2], v[3].max(1))),
            0x8000 | u16::from(v[3]),
        );
        Self {
            sock,
            relay,
            vni,
            synth_peer,
            label,
            alive: AtomicBool::new(true),
        }
    }

    pub fn synth_peer(&self) -> SocketAddr {
        self.synth_peer
    }

    pub fn vni(&self) -> u32 {
        self.vni
    }

    pub fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    /// Stop the carrier: the next `recv_from`/`send_to` fails, which is how the
    /// owning `Carrier` learns it is dead (the DERP convention, via the `dead`
    /// latch). Used on `rc:overlay.relay_revoke` and on session expiry.
    pub fn close(&self) {
        self.alive.store(false, Ordering::Relaxed);
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl RelayConn for OrgRelayConn {
    async fn send_to(&self, buf: &[u8], _dst: SocketAddr) -> io::Result<usize> {
        if !self.is_alive() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "org-relay session closed",
            ));
        }
        self.sock
            .send_to(&build_data(self.vni, buf), self.relay)
            .await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut tmp = [0u8; DATA_BUF];
        loop {
            if !self.is_alive() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "org-relay session closed",
                ));
            }
            let (n, from) = self.sock.recv_from(&mut tmp).await?;
            // Only the relay, only our session's data. Control frames (a
            // re-challenge, a probe echo) and anything from elsewhere are
            // not the peer's ciphertext and never reach the decapsulator.
            if from != self.relay {
                continue;
            }
            let Some((vni, payload)) = parse_data(&tmp[..n]) else {
                continue;
            };
            if vni != self.vni {
                continue;
            }
            let len = payload.len().min(buf.len());
            buf[..len].copy_from_slice(&payload[..len]);
            return Ok((len, self.synth_peer));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    fn relay_transport(&self) -> RelayTransport {
        RelayTransport::Udp
    }

    fn relay_server(&self) -> Option<String> {
        Some(self.label.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::orgrelay::bind::CookieKey;
    use crate::overlay::orgrelay::server::{RelayServer, RelayStats};
    use crate::overlay::orgrelay::session::{Member, Session};

    const VNI: u32 = 0x00_00_2A;
    const GEN: u64 = 3;

    async fn relay_with_session(secrets: [[u8; 32]; 2]) -> (SocketAddr, Arc<RelayStats>) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());
        let (server, handle) = RelayServer::new(CookieKey::from_bytes([7; 32]), stats.clone());
        tokio::spawn(server.serve(sock));
        let now = Instant::now();
        assert!(handle.install(Session {
            vni: VNI,
            generation: GEN,
            members: [
                Member {
                    wg_public: [0xAA; 32],
                    secret: BindSecret::from_bytes(secrets[0]),
                },
                Member {
                    wg_public: [0xBB; 32],
                    secret: BindSecret::from_bytes(secrets[1]),
                },
            ],
            bound: [None, None],
            max_lifetime: now + Duration::from_secs(60),
            idle_deadline: now + Duration::from_secs(60),
            bind_deadline: now + Duration::from_secs(30),
        }));
        (addr, stats)
    }

    fn retry_fixture_session() -> Session {
        let now = Instant::now();
        Session {
            vni: VNI,
            generation: GEN,
            members: [
                Member {
                    wg_public: [0xAA; 32],
                    secret: BindSecret::from_bytes([1; 32]),
                },
                Member {
                    wg_public: [0xBB; 32],
                    secret: BindSecret::from_bytes([2; 32]),
                },
            ],
            bound: [None, None],
            max_lifetime: now + Duration::from_secs(60),
            idle_deadline: now + Duration::from_secs(60),
            bind_deadline: now + Duration::from_secs(30),
        }
    }

    #[tokio::test]
    async fn bind_retries_after_actual_unknown_vni_then_late_session_install() {
        use crate::overlay::orgrelay::server::RelayCommand;
        tokio::time::timeout(Duration::from_secs(3), async {
            let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let relay = relay_sock.local_addr().unwrap();
            let stats = Arc::new(RelayStats::default());
            let (mut server, _handle) =
                RelayServer::new(CookieKey::from_bytes([7; 32]), stats.clone());
            let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let bind_client = client.clone();
            let task = tokio::spawn(async move {
                bind(
                    &bind_client,
                    relay,
                    VNI,
                    GEN,
                    &BindSecret::from_bytes([1; 32]),
                    Duration::from_millis(1200),
                )
                .await
            });
            let mut packet = [0u8; CTRL_BUF];
            let (n, from) = timeout(Duration::from_secs(1), relay_sock.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                ControlFrame::decode(&packet[..n]),
                Some((VNI, ControlFrame::Bind { .. }))
            ));
            assert!(server.handle(from, &packet[..n], Instant::now()).is_none());
            assert_eq!(
                stats.snapshot().drop_unknown_vni,
                1,
                "the FIRST real Bind actually arrived before its grant"
            );
            server.apply(RelayCommand::Install(Box::new(retry_fixture_session())));
            assert_eq!(server.sessions_active(), 1);
            let serving = tokio::spawn(server.serve(relay_sock));
            let result = task.await.unwrap();
            // Stop the owned server on the RED path too, before asserting.
            if result.is_ok() {
                timeout(Duration::from_millis(300), async {
                    while stats.snapshot().bound != 1 {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("real Answer must authenticate at the production server");
            }
            serving.abort();
            let _ = serving.await;
            assert!(
                result.is_ok(),
                "late authorized Serve must be recoverable inside the original deadline: {result:?}"
            );
            assert_eq!(stats.snapshot().bound, 1);
            assert_eq!(stats.snapshot().drop_bad_tag1, 0);
            assert_eq!(stats.snapshot().drop_bad_tag2, 0);
        })
        .await
        .expect("bounded late-Serve regression");
    }

    #[tokio::test]
    async fn bind_retries_zero_budget_sends_nothing_and_short_budget_has_one_attempt() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = relay.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let secret = BindSecret::from_bytes([1; 32]);
        let mut buf = [0u8; CTRL_BUF];
        assert!(matches!(
            bind(&client, addr, VNI, GEN, &secret, Duration::ZERO).await,
            Err(BindError::Timeout)
        ));
        assert!(
            timeout(Duration::from_millis(50), relay.recv_from(&mut buf))
                .await
                .is_err(),
            "zero budget must emit no datagram"
        );
        assert!(matches!(
            bind(&client, addr, VNI, GEN, &secret, Duration::from_millis(100)).await,
            Err(BindError::Timeout)
        ));
        let (n, _) = timeout(Duration::from_millis(50), relay.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            ControlFrame::decode(&buf[..n]),
            Some((VNI, ControlFrame::Bind { .. }))
        ));
        assert!(
            timeout(Duration::from_millis(50), relay.recv_from(&mut buf))
                .await
                .is_err(),
            "short budget must not trigger an extra send after expiry"
        );
    }

    #[tokio::test]
    async fn bind_retries_invalid_challenges_do_not_extend_deadline_or_suppress_pacing() {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = relay.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let secret = BindSecret::from_bytes([1; 32]);
        let started = Instant::now();
        let capture = async {
            let mut received = Vec::new();
            let mut buf = [0u8; CTRL_BUF];
            let mut destination = None;
            let mut nonce = None;
            while started.elapsed() < Duration::from_millis(1200) {
                if let Ok(Ok((n, from))) =
                    timeout(Duration::from_millis(20), relay.recv_from(&mut buf)).await
                {
                    let Some((VNI, ControlFrame::Bind { nonce: seen, .. })) =
                        ControlFrame::decode(&buf[..n])
                    else {
                        panic!("only Bind is allowed before an authenticated matching Challenge")
                    };
                    if let Some(previous) = nonce {
                        assert_eq!(
                            previous, seen,
                            "all retry packets keep one fresh attempt nonce"
                        );
                    }
                    nonce = Some(seen);
                    destination = Some(from);
                    received.push((started.elapsed(), buf[..n].to_vec()));
                }
                if let (Some(dst), Some(mut wrong)) = (destination, nonce) {
                    wrong[0] ^= 1;
                    relay
                        .send_to(
                            &ControlFrame::Challenge {
                                nonce: wrong,
                                cookie: [0; 16],
                            }
                            .encode(VNI),
                            dst,
                        )
                        .await
                        .unwrap();
                }
            }
            received
        };
        let attempt = async {
            let result = bind(&client, addr, VNI, GEN, &secret, Duration::from_secs(1)).await;
            (result, started.elapsed())
        };
        let ((result, elapsed), packets) = tokio::join!(attempt, capture);
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(1300),
            "invalid packets cannot reset the absolute deadline: {elapsed:?}"
        );
        assert!(
            matches!(result, Err(BindError::Timeout)),
            "wrong nonce never authenticates"
        );
        assert!(
            (2..=3).contains(&packets.len()),
            "invalid RX cannot suppress paced retries or create a flood; count={}",
            packets.len()
        );
        assert!(
            packets.windows(2).all(|p| p[0].1 == p[1].1),
            "retries preserve the exact authenticated Bind bytes"
        );
        assert!(
            packets
                .windows(2)
                .all(|p| p[1].0.saturating_sub(p[0].0) >= Duration::from_millis(200))
        );
        assert!(
            packets.iter().all(|p| p.0 < Duration::from_secs(1)),
            "no retransmit beyond the original deadline"
        );
    }

    #[tokio::test]
    async fn bind_retries_silent_endpoint_has_absolute_deadline_and_eight_send_cap() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = relay.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let secret = BindSecret::from_bytes([1; 32]);
        let started = Instant::now();
        let capture = async {
            let mut packets = Vec::new();
            let mut buf = [0u8; CTRL_BUF];
            while started.elapsed() < Duration::from_millis(11200) {
                let left = Duration::from_millis(11200).saturating_sub(started.elapsed());
                match timeout(left, relay.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) => packets.push((started.elapsed(), buf[..n].to_vec())),
                    Err(_) => break,
                    other => panic!("owned silent UDP endpoint failed: {other:?}"),
                }
            }
            packets
        };
        let (result, packets) = tokio::join!(
            bind(&client, addr, VNI, GEN, &secret, Duration::from_secs(11)),
            capture
        );
        assert!(matches!(result, Err(BindError::Timeout)));
        assert_eq!(
            packets.len(),
            8,
            "initial + at most seven retries, no unbounded control traffic"
        );
        assert!(packets.windows(2).all(|p| p[0].1 == p[1].1));
        assert!(
            packets
                .windows(2)
                .all(|p| p[1].0.saturating_sub(p[0].0) >= Duration::from_millis(200))
        );
        assert!(packets.iter().all(|p| p.0 < Duration::from_secs(11)));
    }

    /// A member's proof that its handshake matches the relay's: bind on both
    /// sides, then ciphertext-shaped bytes cross in both directions and come
    /// out as the payload alone.
    #[tokio::test]
    async fn members_bind_and_bytes_round_trip_through_the_real_relay() {
        let (relay, _stats) = relay_with_session([[1; 32], [2; 32]]).await;
        let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sa = BindSecret::from_bytes([1; 32]);
        let sb = BindSecret::from_bytes([2; 32]);

        let rtt = bind(&a_sock, relay, VNI, GEN, &sa, Duration::from_secs(5))
            .await
            .expect("a binds");
        assert!(rtt < Duration::from_secs(1));
        bind(&b_sock, relay, VNI, GEN, &sb, Duration::from_secs(5))
            .await
            .expect("b binds");

        let a = OrgRelayConn::new(a_sock, relay, VNI, "relay-a".into());
        let b = OrgRelayConn::new(b_sock, relay, VNI, "relay-a".into());
        let payload = b"wireguard-looking bytes go here";
        // `bind` returns once its Answer is SENT; the relay binds `b` only when
        // it processes that Answer, and a datagram that overtakes it is dropped
        // as `NotYetBound`. On a loaded host one did, about one run in three
        // (WSL, 2026-10-17), and a single send then waited out its 5 s. A real
        // member rides WireGuard's own retransmits; the test resends the same
        // way, so what it checks is the round trip, not the race.
        let mut buf = [0u8; 256];
        let mut received = None;
        for _ in 0..20 {
            a.send_to(payload, a.synth_peer()).await.unwrap();
            if let Ok(r) = timeout(Duration::from_millis(250), b.recv_from(&mut buf)).await {
                received = Some(r.unwrap());
                break;
            }
        }
        let (n, from) = received.expect("b receives");
        assert_eq!(
            &buf[..n],
            payload,
            "the header is stripped, the payload is verbatim"
        );
        assert_eq!(
            from,
            b.synth_peer(),
            "recv names the placeholder peer, never the relay"
        );

        b.send_to(b"reply", b.synth_peer()).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(5), a.recv_from(&mut buf))
            .await
            .expect("a receives")
            .unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(a.relay_transport(), RelayTransport::Udp);
        assert_eq!(a.relay_server().as_deref(), Some("relay-a"));
    }

    /// The relay never answers a bind it will not honour, so a wrong secret
    /// and a silent endpoint look the same from here — both a timeout, both
    /// bounded by the deadline the caller set.
    #[tokio::test]
    async fn a_wrong_secret_and_a_silent_relay_both_time_out_within_the_deadline() {
        let (relay, _) = relay_with_session([[1; 32], [2; 32]]).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong = BindSecret::from_bytes([9; 32]);
        let t = Instant::now();
        let r = bind(&sock, relay, VNI, GEN, &wrong, Duration::from_millis(300)).await;
        assert!(matches!(r, Err(BindError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(2));

        // Nothing listens here at all — silence on Linux, an ICMP-driven recv
        // error on Windows; both are "no answer".
        let silent: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let right = BindSecret::from_bytes([1; 32]);
        let r = bind(&sock, silent, VNI, GEN, &right, Duration::from_millis(300)).await;
        assert!(r.as_ref().is_err_and(BindError::is_no_answer), "{r:?}");
    }

    /// Endpoints are tried in the server's order; the first that challenges
    /// wins, and every attempt is reported — the probe report's raw material.
    #[tokio::test]
    async fn bind_any_tries_endpoints_in_order_and_reports_each_one() {
        let (relay, _) = relay_with_session([[1; 32], [2; 32]]).await;
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let secret = BindSecret::from_bytes([1; 32]);
        let (_sock, winner, outcomes) = bind_any(
            &[dead, relay],
            VNI,
            GEN,
            &secret,
            Duration::from_millis(400),
        )
        .await
        .expect("the live endpoint answers");
        assert_eq!(winner, relay);
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].endpoint, dead);
        assert!(!outcomes[0].reachable);
        assert_eq!(outcomes[1].endpoint, relay);
        assert!(outcomes[1].reachable && outcomes[1].rtt.is_some());

        let (e, outcomes) = bind_any(&[], VNI, GEN, &secret, Duration::from_millis(100))
            .await
            .expect_err("no endpoints");
        assert!(matches!(e, BindError::NoEndpoint));
        assert!(outcomes.is_empty());
    }

    /// Only this session's data frames, only from the relay: a datagram from
    /// elsewhere, a control frame, or another VNI never surfaces as peer
    /// traffic.
    #[tokio::test]
    async fn recv_surfaces_only_this_sessions_data_from_the_relay() {
        let (relay, _) = relay_with_session([[1; 32], [2; 32]]).await;
        let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        bind(
            &a_sock,
            relay,
            VNI,
            GEN,
            &BindSecret::from_bytes([1; 32]),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        bind(
            &b_sock,
            relay,
            VNI,
            GEN,
            &BindSecret::from_bytes([2; 32]),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        let a = OrgRelayConn::new(a_sock, relay, VNI, "r".into());
        let b = OrgRelayConn::new(b_sock, relay, VNI, "r".into());

        // A stranger writes a perfectly-shaped data frame straight to b.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger
            .send_to(&build_data(VNI, b"not from the relay"), b_addr)
            .await
            .unwrap();
        // Then the real thing.
        a.send_to(b"genuine", a.synth_peer()).await.unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = timeout(Duration::from_secs(5), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            &buf[..n],
            b"genuine",
            "the stranger's frame was skipped, not surfaced"
        );

        // Closing makes the carrier report dead on its next use.
        b.close();
        assert!(b.send_to(b"x", b.synth_peer()).await.is_err());
    }

    /// A symmetric NAT remaps a member: it re-binds from a NEW source with the
    /// same VNI and secret, and traffic flows to the new address.
    #[tokio::test]
    async fn a_member_rebinds_from_a_new_source_and_keeps_the_session() {
        let (relay, stats) = relay_with_session([[1; 32], [2; 32]]).await;
        let sa = BindSecret::from_bytes([1; 32]);
        let sb = BindSecret::from_bytes([2; 32]);
        let a_old = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        bind(&a_old, relay, VNI, GEN, &sa, Duration::from_secs(5))
            .await
            .unwrap();
        bind(&b_sock, relay, VNI, GEN, &sb, Duration::from_secs(5))
            .await
            .unwrap();

        // The "NAT remapped us" event: a fresh socket, the same identity.
        let a_new = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        bind(&a_new, relay, VNI, GEN, &sa, Duration::from_secs(5))
            .await
            .expect("re-bind under a valid tag1 from a new source");
        // #1859 — `bind` returns once the Answer is SENT, not once the relay
        // has applied it, and loopback does not order datagrams across
        // sockets: b's frame could reach the relay first and go to a's OLD
        // source, a 5 s timeout about one run in five. Wait until the relay has
        // counted the third bind (a_old, b, a_new) before sending.
        let applied = timeout(Duration::from_secs(5), async {
            while stats.snapshot().bound < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(applied.is_ok(), "the relay never applied the re-bind");
        let a = OrgRelayConn::new(a_new, relay, VNI, "r".into());
        let b = OrgRelayConn::new(b_sock, relay, VNI, "r".into());
        b.send_to(b"to the new address", b.synth_peer())
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = timeout(Duration::from_secs(5), a.recv_from(&mut buf))
            .await
            .expect("the relay now forwards to a's NEW source")
            .unwrap();
        assert_eq!(&buf[..n], b"to the new address");
    }
}
