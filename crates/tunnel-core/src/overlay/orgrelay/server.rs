// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P2c — the org-relay server: one UDP socket that answers probes, runs
//! the authenticated bind, and forwards ciphertext between bound members.
//!
//! This is the first point in FR-19 where a relay carries traffic, so it is
//! also where the three hardening commitments from the spec land together:
//!
//! * **Shape first, rate-limit second, crypto last.** A datagram that is not
//!   org-relay shaped costs a header decode and nothing else; one that is
//!   shaped but over its source's budget costs a table lookup; only a datagram
//!   past both is allowed to cost a MAC. The order is the point — it is what
//!   keeps a flood from turning the cheap path into the expensive one.
//! * **One bad datagram costs one datagram.** [`RelayServer::handle`] is a pure
//!   function and it is called under `catch_unwind`, so a parser bug degrades
//!   the relay by one packet rather than ending the service. This daemon runs
//!   as SYSTEM on Windows and root under systemd, alongside remote desktop,
//!   tunnels and SSH; a panic on this socket must never reach them.
//! * **Every drop has a reason, and every reason has a counter with a reader.**
//!   [`RelayStats::snapshot`] is that reader. A counter without one is the
//!   FR-18 `dropped_stale` failure: an acceptance criterion nobody can
//!   evaluate.
//!
//! Sessions arrive **only** through [`RelayHandle`] — the server mints them and
//! (in P3) pushes them over the authenticated control WS. Nothing an inbound
//! packet can do creates one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::bind::{BindRefusal, BindVerifier, CookieKey};
use super::responder::{ProbeGate, ProbeVerdict, ResponderCounts, ResponderStats};
use super::session::{DropReason, Inbound, RelayAction, Session, SessionTable};
use super::wire::{ControlFrame, OrgRelayHeader, is_org_relay_shaped, parse_data};

/// How often expired sessions are swept. Expiry is also checked on every
/// datagram, so this only bounds how long a *silent* dead session lingers.
pub const REAP_EVERY: Duration = Duration::from_secs(30);

/// Counters for everything the relay does and refuses. All cumulative since
/// start; readers DIFF two snapshots, they never judge an absolute.
#[derive(Debug, Default)]
pub struct RelayStats {
    /// The probe responder's own counters (answered / refused-by-reason).
    pub probe: ResponderStats,
    forwarded: AtomicU64,
    bound: AtomicU64,
    sessions_installed: AtomicU64,
    sessions_refused_cap: AtomicU64,
    sessions_revoked: AtomicU64,
    sessions_reaped: AtomicU64,
    refused_not_shaped: AtomicU64,
    refused_unknown_control: AtomicU64,
    refused_rate_limited: AtomicU64,
    drop_unknown_vni: AtomicU64,
    drop_unbound_source: AtomicU64,
    drop_not_yet_bound: AtomicU64,
    drop_session_expired: AtomicU64,
    drop_session_idle: AtomicU64,
    drop_bind_deadline: AtomicU64,
    drop_bad_tag1: AtomicU64,
    drop_bad_cookie: AtomicU64,
    drop_bad_tag2: AtomicU64,
    panics_caught: AtomicU64,
    #[cfg(feature = "path-trial-test-support")]
    rejected_data_fixture: std::sync::Mutex<Option<RejectedDataFixture>>,
}

#[cfg(feature = "path-trial-test-support")]
#[derive(Debug)]
struct RejectedDataFixture {
    source: SocketAddr,
    vni: u32,
    wg_len: usize,
    count: u64,
}

/// A plain snapshot — the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayCounts {
    pub probe: ResponderCounts,
    pub forwarded: u64,
    pub bound: u64,
    pub sessions_installed: u64,
    pub sessions_refused_cap: u64,
    pub sessions_revoked: u64,
    pub sessions_reaped: u64,
    pub refused_not_shaped: u64,
    pub refused_unknown_control: u64,
    pub refused_rate_limited: u64,
    pub drop_unknown_vni: u64,
    /// The open-proxy tripwire: data on a known VNI from a source that is not
    /// one of its two bound members. Nonzero means someone is *trying*.
    pub drop_unbound_source: u64,
    pub drop_not_yet_bound: u64,
    pub drop_session_expired: u64,
    pub drop_session_idle: u64,
    pub drop_bind_deadline: u64,
    pub drop_bad_tag1: u64,
    pub drop_bad_cookie: u64,
    pub drop_bad_tag2: u64,
    /// Handler panics survived. Every one is a bug; the relay is still up.
    pub panics_caught: u64,
}

impl RelayStats {
    /// Fixture-only observation; scoped to one source, VNI and WG data length.
    #[cfg(feature = "path-trial-test-support")]
    pub fn fixture_watch_rejected_data(&self, source: SocketAddr, vni: u32, wg_len: usize) {
        *self
            .rejected_data_fixture
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(RejectedDataFixture {
            source,
            vni,
            wg_len,
            count: 0,
        });
    }

    #[cfg(feature = "path-trial-test-support")]
    pub fn fixture_rejected_data_count(&self) -> u64 {
        self.rejected_data_fixture
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(0, |fixture| fixture.count)
    }

    pub fn snapshot(&self) -> RelayCounts {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        RelayCounts {
            probe: self.probe.snapshot(),
            forwarded: l(&self.forwarded),
            bound: l(&self.bound),
            sessions_installed: l(&self.sessions_installed),
            sessions_refused_cap: l(&self.sessions_refused_cap),
            sessions_revoked: l(&self.sessions_revoked),
            sessions_reaped: l(&self.sessions_reaped),
            refused_not_shaped: l(&self.refused_not_shaped),
            refused_unknown_control: l(&self.refused_unknown_control),
            refused_rate_limited: l(&self.refused_rate_limited),
            drop_unknown_vni: l(&self.drop_unknown_vni),
            drop_unbound_source: l(&self.drop_unbound_source),
            drop_not_yet_bound: l(&self.drop_not_yet_bound),
            drop_session_expired: l(&self.drop_session_expired),
            drop_session_idle: l(&self.drop_session_idle),
            drop_bind_deadline: l(&self.drop_bind_deadline),
            drop_bad_tag1: l(&self.drop_bad_tag1),
            drop_bad_cookie: l(&self.drop_bad_cookie),
            drop_bad_tag2: l(&self.drop_bad_tag2),
            panics_caught: l(&self.panics_caught),
        }
    }

    fn record_drop(&self, r: DropReason) {
        let c = match r {
            DropReason::UnknownVni => &self.drop_unknown_vni,
            DropReason::UnboundSource => &self.drop_unbound_source,
            DropReason::NotYetBound => &self.drop_not_yet_bound,
            DropReason::SessionExpired => &self.drop_session_expired,
            DropReason::SessionIdle => &self.drop_session_idle,
            DropReason::BindDeadlinePassed => &self.drop_bind_deadline,
            DropReason::Bind(BindRefusal::BadTag1) => &self.drop_bad_tag1,
            DropReason::Bind(BindRefusal::BadCookie) => &self.drop_bad_cookie,
            DropReason::Bind(BindRefusal::BadTag2) => &self.drop_bad_tag2,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// The only way a session enters or leaves a running relay.
pub enum RelayCommand {
    /// Boxed: a Session is ~250 bytes and Revoke is 4, and clippy is right that
    /// every queued Revoke should not pay for the larger variant.
    Install(Box<Session>),
    Revoke(u32),
}

/// A cloneable handle to a running [`RelayServer`]. P3 holds one per relay and
/// drives it from the control-WS mint/revoke messages.
#[derive(Clone)]
pub struct RelayHandle {
    tx: mpsc::UnboundedSender<RelayCommand>,
}

impl RelayHandle {
    /// `false` if the server has stopped.
    pub fn install(&self, s: Session) -> bool {
        self.tx.send(RelayCommand::Install(Box::new(s))).is_ok()
    }

    pub fn revoke(&self, vni: u32) -> bool {
        self.tx.send(RelayCommand::Revoke(vni)).is_ok()
    }
}

/// Something to put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    pub to: SocketAddr,
    pub bytes: Vec<u8>,
}

pub struct RelayServer {
    gate: ProbeGate,
    sessions: SessionTable,
    stats: Arc<RelayStats>,
    cmd_rx: Option<mpsc::UnboundedReceiver<RelayCommand>>,
    /// Test-only: make `handle` panic on this VNI, so `catch_unwind` is
    /// verified rather than assumed.
    #[cfg(test)]
    panic_on_vni: Option<u32>,
}

impl RelayServer {
    pub fn new(cookie_key: CookieKey, stats: Arc<RelayStats>) -> (Self, RelayHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                gate: ProbeGate::new(),
                sessions: SessionTable::new(BindVerifier::new(cookie_key, None)),
                stats,
                cmd_rx: Some(rx),
                #[cfg(test)]
                panic_on_vni: None,
            },
            RelayHandle { tx },
        )
    }

    pub fn sessions_active(&self) -> usize {
        self.sessions.len()
    }

    pub fn apply(&mut self, cmd: RelayCommand) {
        match cmd {
            RelayCommand::Install(s) => match self.sessions.insert(*s) {
                Ok(()) => {
                    self.stats
                        .sessions_installed
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    self.stats
                        .sessions_refused_cap
                        .fetch_add(1, Ordering::Relaxed);
                }
            },
            RelayCommand::Revoke(vni) => {
                if self.sessions.revoke(vni) {
                    self.stats.sessions_revoked.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn reap(&mut self, now: Instant) {
        let n = self.sessions.reap(now) as u64;
        if n > 0 {
            self.stats.sessions_reaped.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// The whole per-datagram decision. Pure: no I/O, no clock of its own.
    pub fn handle(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Option<Outbound> {
        // 1. Shape. Costs a header decode; refuses everything that is not ours
        //    before any table is consulted.
        if !is_org_relay_shaped(pkt) {
            self.stats
                .refused_not_shaped
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let hdr = OrgRelayHeader::decode(pkt).expect("shaped implies decodable");

        #[cfg(test)]
        if self.panic_on_vni == Some(hdr.vni) {
            panic!("test-induced handler panic on vni {}", hdr.vni);
        }

        if hdr.control {
            let Some((vni, frame)) = ControlFrame::decode(pkt) else {
                self.stats
                    .refused_unknown_control
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            };
            match frame {
                ControlFrame::Probe { .. } => {
                    // The gate does shape + length + rate limit itself.
                    let v = self.gate.classify(src, pkt, now);
                    self.stats.probe.record(&v);
                    match v {
                        ProbeVerdict::Answer(bytes) => Some(Outbound { to: src, bytes }),
                        _ => None,
                    }
                }
                ControlFrame::Bind { nonce, tag1 } => {
                    // 2. Rate limit, BEFORE the MAC: a bind costs a MAC only if
                    //    the source still has budget.
                    if !self.gate.admit(src, now) {
                        self.stats
                            .refused_rate_limited
                            .fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    match self
                        .sessions
                        .decide(vni, src, Inbound::Bind { nonce, tag1 }, now)
                    {
                        RelayAction::Challenge(cookie) => Some(Outbound {
                            to: src,
                            bytes: ControlFrame::Challenge { nonce, cookie }
                                .encode(vni)
                                .to_vec(),
                        }),
                        RelayAction::Drop(r) => {
                            self.stats.record_drop(r);
                            None
                        }
                        RelayAction::Bound | RelayAction::Forward { .. } => None,
                    }
                }
                ControlFrame::Answer {
                    nonce,
                    cookie,
                    tag2,
                } => {
                    if !self.gate.admit(src, now) {
                        self.stats
                            .refused_rate_limited
                            .fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    match self.sessions.decide(
                        vni,
                        src,
                        Inbound::Answer {
                            nonce,
                            cookie,
                            tag2,
                        },
                        now,
                    ) {
                        RelayAction::Bound => {
                            self.stats.bound.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                        RelayAction::Drop(r) => {
                            self.stats.record_drop(r);
                            None
                        }
                        RelayAction::Challenge(_) | RelayAction::Forward { .. } => None,
                    }
                }
                // A relay issues challenges; it never receives one. Anything
                // sending us one is confused or probing, and is counted as
                // such rather than silently ignored.
                ControlFrame::Challenge { .. } => {
                    self.stats
                        .refused_unknown_control
                        .fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        } else {
            let Some((vni, payload)) = parse_data(pkt) else {
                self.stats
                    .refused_not_shaped
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            };
            // No rate limit on data: the lookup is a hash probe, and a data
            // frame from an unbound source is dropped BY the lookup. Limiting
            // here would let a flooder starve a bound member's real traffic.
            match self.sessions.decide(vni, src, Inbound::Data(payload), now) {
                RelayAction::Forward { to } => {
                    self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                    // The WHOLE frame, verbatim. The relay never re-frames, so
                    // it can never emit more than it received.
                    Some(Outbound {
                        to,
                        bytes: pkt.to_vec(),
                    })
                }
                RelayAction::Drop(r) => {
                    #[cfg(feature = "path-trial-test-support")]
                    if r == DropReason::UnknownVni
                        && let Some(fixture) = self
                            .stats
                            .rejected_data_fixture
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_mut()
                        && fixture.source == src
                        && fixture.vni == vni
                        && fixture.wg_len == payload.len()
                        && payload.starts_with(&[4, 0, 0, 0])
                    {
                        fixture.count = fixture.count.saturating_add(1);
                    }
                    self.stats.record_drop(r);
                    None
                }
                RelayAction::Challenge(_) | RelayAction::Bound => None,
            }
        }
    }

    /// Own `sock` and serve until it dies.
    ///
    /// The loop shape is the one the P1 responder earned the hard way (#832):
    /// a generous read buffer, recv errors treated as transient up to a bound,
    /// and — new here — `catch_unwind` around the handler so one bad datagram
    /// costs one datagram.
    pub async fn serve(mut self, sock: Arc<tokio::net::UdpSocket>) {
        let local = sock.local_addr().ok();
        tracing::info!(
            ?local,
            "org-relay server listening (probes, authenticated bind, forwarding; a \
             successful bind does NOT prove reachability -- a DNAT can eat this port \
             upstream of the socket)"
        );
        let mut cmd_rx = self.cmd_rx.take().expect("serve is called once");
        const READ_BUF: usize = 2048;
        const MAX_CONSECUTIVE_ERRORS: u32 = 64;
        let mut buf = [0u8; READ_BUF];
        let mut consecutive_errors: u32 = 0;
        let mut reaper = tokio::time::interval(REAP_EVERY);

        loop {
            tokio::select! {
                r = sock.recv_from(&mut buf) => {
                    let (n, src) = match r {
                        Ok(v) => { consecutive_errors = 0; v }
                        Err(e) => {
                            consecutive_errors += 1;
                            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                                tracing::warn!(?local, error = %e, consecutive_errors,
                                    "org-relay server giving up: the socket keeps failing");
                                return;
                            }
                            tracing::debug!(?local, error = %e, "org-relay recv error (transient)");
                            continue;
                        }
                    };
                    let now = Instant::now();
                    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.handle(src, &buf[..n], now)
                    }));
                    match out {
                        Ok(Some(o)) => {
                            if let Err(e) = sock.send_to(&o.bytes, o.to).await {
                                tracing::debug!(to = %o.to, error = %e, "org-relay send failed");
                            }
                        }
                        Ok(None) => {}
                        Err(_) => {
                            let n_panics = self.stats.panics_caught.fetch_add(1, Ordering::Relaxed) + 1;
                            // Every one is a bug worth a report; a flood of
                            // them is not worth a flood of log lines.
                            if n_panics <= 10 || n_panics.is_multiple_of(1000) {
                                tracing::error!(%src, len = n, n_panics,
                                    "org-relay: handler PANICKED on a datagram -- caught, the relay \
                                     keeps serving. This is a parser bug: report it with the len.");
                            }
                        }
                    }
                }
                Some(cmd) = cmd_rx.recv() => {
                    self.apply(cmd);
                }
                _ = reaper.tick() => {
                    self.reap(Instant::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::orgrelay::bind::{BindSecret, Nonce, tag1, tag2};
    use crate::overlay::orgrelay::session::{IDLE_REFRESH, Member};
    use crate::overlay::orgrelay::wire::{build_data, build_probe, parse_data};
    use tokio::net::UdpSocket;
    use tokio::time::{Duration as TDuration, timeout};

    const VNI: u32 = 0x0042_4242;
    const N: Nonce = [0x33; 16];

    fn session(now: Instant) -> Session {
        Session {
            vni: VNI,
            generation: 1,
            members: [
                Member {
                    wg_public: [0xA; 32],
                    secret: BindSecret::from_bytes([0xA1; 32]),
                },
                Member {
                    wg_public: [0xB; 32],
                    secret: BindSecret::from_bytes([0xB1; 32]),
                },
            ],
            bound: [None, None],
            max_lifetime: now + Duration::from_secs(3600),
            idle_deadline: now + IDLE_REFRESH,
            bind_deadline: now + Duration::from_secs(30),
        }
    }

    #[cfg(feature = "path-trial-test-support")]
    #[test]
    fn rejected_data_fixture_is_scoped_and_requires_unknown_vni() {
        let now = Instant::now();
        let stats = Arc::new(RelayStats::default());
        let (mut server, _) = RelayServer::new(CookieKey::from_bytes([1; 32]), stats.clone());
        let source: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let other: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        let mut data = vec![0u8; 48];
        data[0] = 4;
        stats.fixture_watch_rejected_data(source, VNI, data.len());
        assert!(
            server
                .handle(source, &build_data(VNI, &data), now)
                .is_none()
        );
        assert_eq!(stats.fixture_rejected_data_count(), 1);
        server.handle(other, &build_data(VNI, &data), now);
        server.handle(source, &build_data(VNI + 1, &data), now);
        server.handle(source, &build_data(VNI, &data[..47]), now);
        let mut wrong_type = data.clone();
        wrong_type[0] = 1;
        server.handle(source, &build_data(VNI, &wrong_type), now);
        assert_eq!(stats.fixture_rejected_data_count(), 1);
        server.apply(RelayCommand::Install(Box::new(session(now))));
        server.handle(source, &build_data(VNI, &data), now);
        assert_eq!(
            stats.fixture_rejected_data_count(),
            1,
            "an existing unbound session is not UnknownVni"
        );
        server.apply(RelayCommand::Revoke(VNI));
        server.handle(source, &build_data(VNI, &data), now);
        assert_eq!(stats.fixture_rejected_data_count(), 2);
    }

    /// The CLIENT side of the handshake, over a real socket, knowing nothing
    /// about its own mapped address -- which is the property that forced the
    /// P2a design change.
    async fn client_bind(sock: &UdpSocket, relay: SocketAddr, secret: &BindSecret) {
        let t1 = tag1(secret, VNI, 1, &N);
        sock.send_to(
            &ControlFrame::Bind { nonce: N, tag1: t1 }.encode(VNI),
            relay,
        )
        .await
        .unwrap();
        let mut buf = [0u8; 256];
        let n = timeout(TDuration::from_secs(5), sock.recv(&mut buf))
            .await
            .expect("no challenge from the relay")
            .unwrap();
        let (vni, frame) = ControlFrame::decode(&buf[..n]).expect("a challenge frame");
        assert_eq!(vni, VNI);
        let ControlFrame::Challenge { nonce, cookie } = frame else {
            panic!("expected a Challenge, got {frame:?}");
        };
        assert_eq!(nonce, N, "the challenge must echo our nonce");
        let t2 = tag2(secret, &cookie, &N);
        sock.send_to(
            &ControlFrame::Answer {
                nonce: N,
                cookie,
                tag2: t2,
            }
            .encode(VNI),
            relay,
        )
        .await
        .unwrap();
    }

    async fn wait_until(stats: &RelayStats, pred: impl Fn(&RelayCounts) -> bool) {
        timeout(TDuration::from_secs(5), async {
            loop {
                if pred(&stats.snapshot()) {
                    return;
                }
                tokio::time::sleep(TDuration::from_millis(10)).await;
            }
        })
        .await
        .expect("counter never reached the expected value");
    }

    async fn expect_silence(sock: &UdpSocket, what: &str) {
        let mut buf = [0u8; 256];
        assert!(
            timeout(TDuration::from_millis(300), sock.recv(&mut buf))
                .await
                .is_err(),
            "{what}"
        );
    }

    /// The spec's `three_node_relay_roundtrip`, in the crate that can actually
    /// compile the data plane: three loopback sockets, no TUN, no root.
    #[tokio::test]
    async fn three_sockets_relay_ciphertext_between_bound_members_and_nobody_else() {
        let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = relay_sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());
        let (server, handle) = RelayServer::new(CookieKey::from_bytes([1; 32]), stats.clone());
        tokio::spawn(server.serve(relay_sock));

        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sa = BindSecret::from_bytes([0xA1; 32]);
        let sb = BindSecret::from_bytes([0xB1; 32]);

        // A session exists only because the SERVER minted it.
        assert!(handle.install(session(Instant::now())));
        wait_until(&stats, |c| c.sessions_installed == 1).await;

        client_bind(&a, relay, &sa).await;
        client_bind(&b, relay, &sb).await;
        wait_until(&stats, |c| c.bound == 2).await;

        // A -> B, and the frame B receives is A's frame, untouched.
        let from_a = b"ciphertext-from-a";
        a.send_to(&build_data(VNI, from_a), relay).await.unwrap();
        let mut buf = [0u8; 256];
        let n = timeout(TDuration::from_secs(5), b.recv(&mut buf))
            .await
            .expect("B never received A's frame")
            .unwrap();
        let (v, got) = parse_data(&buf[..n]).unwrap();
        assert_eq!((v, got), (VNI, &from_a[..]));

        // B -> A.
        let from_b = b"ciphertext-from-b";
        b.send_to(&build_data(VNI, from_b), relay).await.unwrap();
        let n = timeout(TDuration::from_secs(5), a.recv(&mut buf))
            .await
            .expect("A never received B's frame")
            .unwrap();
        assert_eq!(parse_data(&buf[..n]).unwrap().1, &from_b[..]);
        wait_until(&stats, |c| c.forwarded == 2).await;

        // An intruder on the KNOWN vni: forwarded to nobody, counted by the
        // open-proxy tripwire.
        intruder
            .send_to(&build_data(VNI, b"not-a-member"), relay)
            .await
            .unwrap();
        wait_until(&stats, |c| c.drop_unbound_source == 1).await;
        expect_silence(&a, "A must not receive the intruder's frame").await;
        expect_silence(&b, "B must not receive the intruder's frame").await;

        // The intruder cannot bind either: no secret ⇒ tag1 refused.
        let bogus = tag1(&BindSecret::from_bytes([0xEE; 32]), VNI, 1, &N);
        intruder
            .send_to(
                &ControlFrame::Bind {
                    nonce: N,
                    tag1: bogus,
                }
                .encode(VNI),
                relay,
            )
            .await
            .unwrap();
        wait_until(&stats, |c| c.drop_bad_tag1 == 1).await;
        expect_silence(&intruder, "a refused bind draws no reply at all").await;

        // Revocation kills the LIVE session: A's next frame goes nowhere.
        assert!(handle.revoke(VNI));
        wait_until(&stats, |c| c.sessions_revoked == 1).await;
        a.send_to(&build_data(VNI, b"after-revoke"), relay)
            .await
            .unwrap();
        wait_until(&stats, |c| c.drop_unknown_vni >= 1).await;
        expect_silence(&b, "a revoked session must forward nothing").await;

        // And through all of it the relay still answers a probe -- alive.
        intruder
            .send_to(&build_probe(7, &[9; 16]), relay)
            .await
            .unwrap();
        let n = timeout(TDuration::from_secs(5), intruder.recv(&mut buf))
            .await
            .expect("relay died")
            .unwrap();
        assert_eq!(n, 64);
    }

    /// `catch_unwind` verified, not assumed: a handler panic on one datagram
    /// costs that datagram, increments a counter, and the relay keeps serving.
    #[tokio::test]
    async fn a_handler_panic_costs_one_datagram_not_the_service() {
        let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = relay_sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());
        let (mut server, _handle) = RelayServer::new(CookieKey::from_bytes([1; 32]), stats.clone());
        server.panic_on_vni = Some(0x0BAD);
        tokio::spawn(server.serve(relay_sock));

        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(&build_probe(0x0BAD, &[0; 16]), relay)
            .await
            .unwrap();
        wait_until(&stats, |c| c.panics_caught == 1).await;

        // Still alive: a probe on a healthy VNI is echoed.
        c.send_to(&build_probe(7, &[1; 16]), relay).await.unwrap();
        let mut buf = [0u8; 256];
        let n = timeout(TDuration::from_secs(5), c.recv(&mut buf))
            .await
            .expect("relay did not survive a handler panic")
            .unwrap();
        assert_eq!(n, 64);
    }

    /// The reply to a bind is the same size as the bind; a probe echoes
    /// itself; nothing else replies. Asserted over the socket so it covers the
    /// framing the relay actually emits, not just what `wire` promises.
    #[tokio::test]
    async fn no_control_reply_is_larger_than_its_request() {
        let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = relay_sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());
        let (server, handle) = RelayServer::new(CookieKey::from_bytes([1; 32]), stats.clone());
        tokio::spawn(server.serve(relay_sock));
        handle.install(session(Instant::now()));
        wait_until(&stats, |c| c.sessions_installed == 1).await;

        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sa = BindSecret::from_bytes([0xA1; 32]);
        let req = ControlFrame::Bind {
            nonce: N,
            tag1: tag1(&sa, VNI, 1, &N),
        }
        .encode(VNI);
        c.send_to(&req, relay).await.unwrap();
        let mut buf = [0u8; 256];
        let n = timeout(TDuration::from_secs(5), c.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(
            n <= req.len(),
            "a {}-byte bind drew a {n}-byte reply -- amplification",
            req.len()
        );
    }

    /// "Shape first, rate-limit second, crypto last" as a measurement rather
    /// than a comment: a flood of BAD binds from one source costs exactly the
    /// per-source allowance in MAC computations, and every bind past that is
    /// refused before the MAC runs. Mutation-verified — moving the limiter
    /// after the session decision makes all fifty reach the MAC.
    #[test]
    fn a_bind_flood_is_rate_limited_before_it_can_cost_a_mac() {
        use crate::overlay::orgrelay::responder::PER_SOURCE_PER_WINDOW;
        let stats = Arc::new(RelayStats::default());
        let (mut server, _h) = RelayServer::new(CookieKey::from_bytes([1; 32]), stats.clone());
        let now = Instant::now();
        server.apply(RelayCommand::Install(Box::new(session(now))));

        let src: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let bogus = ControlFrame::Bind {
            nonce: N,
            tag1: [0xEE; 16],
        }
        .encode(VNI);
        for _ in 0..50 {
            assert!(server.handle(src, &bogus, now).is_none());
        }
        let c = stats.snapshot();
        assert_eq!(
            c.drop_bad_tag1, PER_SOURCE_PER_WINDOW as u64,
            "only the allowance may reach the MAC"
        );
        assert_eq!(
            c.refused_rate_limited,
            50 - PER_SOURCE_PER_WINDOW as u64,
            "everything past the allowance is refused pre-crypto"
        );
    }

    /// Sessions are minted by the server and capped; the cap refuses rather
    /// than grows, and the refusal is counted.
    #[tokio::test]
    async fn the_handle_cannot_push_the_table_past_its_cap() {
        let stats = Arc::new(RelayStats::default());
        let (mut server, _h) = RelayServer::new(CookieKey::from_bytes([1; 32]), stats.clone());
        let now = Instant::now();
        for vni in 1..=crate::overlay::orgrelay::session::MAX_SESSIONS as u32 {
            let mut s = session(now);
            s.vni = vni;
            server.apply(RelayCommand::Install(Box::new(s)));
        }
        let mut extra = session(now);
        extra.vni = 0x00FF_0000;
        server.apply(RelayCommand::Install(Box::new(extra)));
        let c = stats.snapshot();
        assert_eq!(
            c.sessions_installed as usize,
            crate::overlay::orgrelay::session::MAX_SESSIONS
        );
        assert_eq!(c.sessions_refused_cap, 1);
        assert_eq!(
            server.sessions_active(),
            crate::overlay::orgrelay::session::MAX_SESSIONS
        );
    }
}
