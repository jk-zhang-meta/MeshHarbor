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
//!
//! A member carrier built [`OrgRelayConn::with_rebind`] also re-binds IN
//! BAND, on its own socket, when it sends after [`IDLE_REBIND`] of silence:
//! the relay's NAT-mapping assumption is a 25 s WireGuard keepalive, and a
//! B6-dormant peer (or a quiet B8 standby leg) sends nothing for minutes. A
//! NAT that re-creates the mapping on a new port after that silence would
//! otherwise strand the leg both ways: the relay forwards to the dead old
//! source and drops the member's frames from the unbound new one (lab R8
//! lc-odlate-as, handoff 267). The Bind carries a fresh nonce; the receive
//! path answers only the Challenge that echoes it.
//!
//! ## Liveness of the bound leg
//!
//! A relay that stops forwarding without closing anything (a frozen process,
//! a dead host, a dropped route) leaves the member sending into silence, and
//! the only detectors above this file are WireGuard-sized: three one-way
//! sweeps (15–20 s) while traffic flows, a forced rekey judged over the relay
//! tier's 45 s establishment deadline when it does not (field, 2026-11-11:
//! 62–84 s). A carrier built [`OrgRelayConn::with_liveness`] asks the relay
//! itself instead: when traffic it sent has gone unanswered for
//! [`LIVENESS_SILENCE`], it re-binds in band, and a relay that leaves
//! [`LIVENESS_FAST_BINDS`] of those unanswered is declared dead
//! ([`OrgRelayConn::poll_liveness`]), about a second and a half after it
//! stopped (two on a leg whose bind round trip is above 100 ms).
//!
//! The question is "does the relay still answer for this session", never
//! "did the peer answer": a Challenge settles the round whatever the peer
//! does, so a silent, sleeping or one-way peer is never a dead relay. The
//! same exchange re-binds a member whose NAT mapping moved, without waiting
//! out [`IDLE_REBIND`]. The member only convicts its own carrier; where the
//! pair goes next stays the server's decision.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
/// Silence after which a member's next send re-binds in band — under the
/// 25 s keepalive the relay's NAT-mapping assumption rests on.
pub const IDLE_REBIND: Duration = Duration::from_secs(20);
/// An unanswered in-band re-bind is retried this often, at most
/// [`REBIND_ATTEMPTS`] times per silence, and only while the member sends.
const REBIND_RETRY: Duration = Duration::from_secs(1);
const REBIND_ATTEMPTS: u32 = 4;
/// Data frames: the overlay MTU plus WireGuard and org-relay overhead, with
/// headroom. Anything larger is not ours.
const DATA_BUF: usize = 2048;

/// Traffic unanswered for this long, with nothing heard from the relay for
/// as long, starts a liveness round. Above a request's ordinary wait for its
/// answer (it is raised to three bind round trips on a slow leg), so a
/// healthy exchange never starts one.
pub const LIVENESS_SILENCE: Duration = Duration::from_millis(400);
/// Binds a round sends when the peer's frames were arriving until just
/// before ([`LIVENESS_FLOWING`]): a stream that stops at once, and then
/// three unanswered binds, is the relay and not the peer.
pub const LIVENESS_FAST_BINDS: u32 = 3;
/// Spacing of those binds. With [`LIVENESS_SILENCE`] and
/// [`LIVENESS_ECHO_WAIT`] the verdict falls 1.4 s after the last frame heard
/// (it was 1.65 s with 450 and 350 ms; the field run of 2026-11-12 put the
/// pair back on a working carrier at 2.3 s, and the session riding it resumes
/// one retransmission and a round trip later, which left too little of the
/// 3 s the stall is allowed).
pub const LIVENESS_FAST_GAP: Duration = Duration::from_millis(350);
/// Binds a round sends when nothing was arriving anyway (a one-way stream,
/// an idle pair's keepalive, the first packet after a pause). No abrupt stop
/// backs the verdict there, so it takes more of them, further apart: random
/// loss on a healthy leg must not be able to convict it.
pub const LIVENESS_SLOW_BINDS: u32 = 5;
/// Spacing of those binds. Every round stays inside the relay's per-source
/// budget for unauthenticated control frames (4 per 2 s, `responder.rs`).
pub const LIVENESS_SLOW_GAP: Duration = Duration::from_millis(700);
/// How long the last bind of a round may stay unanswered before the verdict
/// (raised to two bind round trips plus a margin on a slow leg).
pub const LIVENESS_ECHO_WAIT: Duration = Duration::from_millis(300);
/// A peer frame this recently before a round starts makes the round fast.
pub const LIVENESS_FLOWING: Duration = Duration::from_secs(2);
/// After a Challenge proved the relay while the peer stays silent, the next
/// round waits this long: a one-way stream costs one re-bind per interval.
pub const LIVENESS_RECHECK: Duration = Duration::from_secs(2);
/// The bind round trip a leg's timing is scaled by is capped here, so a
/// mismeasured bind cannot stretch the verdict without bound.
const LIVENESS_RTT_CAP: Duration = Duration::from_secs(1);

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
    /// Operator-facing name of the relay node, for `mh peers`'
    /// `relay_via`.
    label: String,
    alive: AtomicBool,
    /// In-band re-bind after silence ([`Self::with_rebind`]); `None` keeps
    /// the carrier exactly as bound.
    rebind: Option<Rebind>,
    /// Liveness of the bound leg ([`Self::with_liveness`]); `None` leaves the
    /// carrier to the health sweep alone.
    liveness: Option<Liveness>,
}

/// What a member carrier needs to re-bind itself, and its one outstanding
/// attempt.
struct Rebind {
    generation: u64,
    secret: BindSecret,
    idle_after: Duration,
    /// Monotonic milliseconds since `born` of the last send.
    last_tx_ms: std::sync::atomic::AtomicU64,
    born: Instant,
    pending: std::sync::Mutex<Option<PendingRebind>>,
}

#[derive(Clone, Copy)]
struct PendingRebind {
    nonce: Nonce,
    at: Instant,
    attempts: u32,
}

impl Rebind {
    /// The Bind to send before the frame being sent now, if this send ends a
    /// silence or retries an unanswered re-bind.
    fn bind_before_send(&self, vni: u32) -> Option<[u8; super::wire::CONTROL_FRAME_LEN]> {
        let now_ms = u64::try_from(self.born.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_tx_ms.swap(now_ms, Ordering::AcqRel);
        let idle = now_ms.saturating_sub(last)
            >= u64::try_from(self.idle_after.as_millis()).unwrap_or(u64::MAX);
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let attempts = match *pending {
            _ if idle => 1,
            Some(p) if p.attempts < REBIND_ATTEMPTS && p.at.elapsed() >= REBIND_RETRY => {
                p.attempts + 1
            }
            _ => return None,
        };
        let nonce = fresh_nonce();
        *pending = Some(PendingRebind {
            nonce,
            at: Instant::now(),
            attempts,
        });
        Some(
            ControlFrame::Bind {
                nonce,
                tag1: tag1(&self.secret, vni, self.generation, &nonce),
            }
            .encode(vni),
        )
    }

    /// The Answer to a Challenge echoing the outstanding attempt's nonce.
    fn answer(
        &self,
        vni: u32,
        nonce: Nonce,
        cookie: super::bind::Mac,
    ) -> Option<[u8; super::wire::CONTROL_FRAME_LEN]> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.is_none_or(|p| p.nonce != nonce) {
            return None;
        }
        *pending = None;
        Some(self.answer_frame(vni, nonce, cookie))
    }

    fn bind_frame(&self, vni: u32, nonce: Nonce) -> [u8; super::wire::CONTROL_FRAME_LEN] {
        ControlFrame::Bind {
            nonce,
            tag1: tag1(&self.secret, vni, self.generation, &nonce),
        }
        .encode(vni)
    }

    fn answer_frame(
        &self,
        vni: u32,
        nonce: Nonce,
        cookie: super::bind::Mac,
    ) -> [u8; super::wire::CONTROL_FRAME_LEN] {
        ControlFrame::Answer {
            nonce,
            cookie,
            tag2: tag2(&self.secret, &cookie, &nonce),
        }
        .encode(vni)
    }
}

/// What [`OrgRelayConn::poll_liveness`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessPoll {
    /// Nothing was sent since the relay's last word (a peer frame it
    /// forwarded, or its own Challenge): there is nothing to ask about.
    Quiet,
    /// Traffic sent since then is unanswered, and the relay is being asked
    /// or was heard from recently enough. Poll again soon.
    Watching,
    /// The relay left a whole round of binds unanswered. The carrier is
    /// closed; reported once.
    Dead {
        /// Binds the round sent.
        binds: u32,
        /// How long the relay had been silent on this leg at the verdict.
        silent: Duration,
    },
}

/// A leg's liveness timing, in milliseconds: the module constants, raised
/// where the leg's own bind round trip is slow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LivenessTiming {
    silence: u64,
    fast_gap: u64,
    slow_gap: u64,
    echo_wait: u64,
    flowing: u64,
    recheck: u64,
}

impl LivenessTiming {
    fn for_rtt(rtt: Duration) -> Self {
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let rtt = ms(rtt.min(LIVENESS_RTT_CAP));
        let echo_wait = ms(LIVENESS_ECHO_WAIT).max(rtt * 2 + 100);
        Self {
            silence: ms(LIVENESS_SILENCE).max(rtt * 3),
            // A bind's answer is due before the next one leaves.
            fast_gap: ms(LIVENESS_FAST_GAP).max(echo_wait),
            slow_gap: ms(LIVENESS_SLOW_GAP).max(echo_wait),
            echo_wait,
            flowing: ms(LIVENESS_FLOWING),
            recheck: ms(LIVENESS_RECHECK),
        }
    }
}

/// The leg's clocks as the send and receive paths stamp them: milliseconds
/// since the carrier was built, `0` = never.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LivenessSample {
    /// The peer's last frame through the relay.
    last_data_rx: u64,
    /// The relay's last word: a peer frame it forwarded, or its Challenge.
    last_relay_rx: u64,
    /// The first frame sent since the relay's last word.
    pending_since: u64,
}

/// One round of binds; all zero between rounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LivenessRound {
    binds: u32,
    first: u64,
    last: u64,
    fast: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LivenessStep {
    Quiet,
    Wait,
    /// Send one bind now.
    Bind,
    Dead,
}

/// The whole rule, free of sockets and clocks.
///
/// Only traffic sent since the relay's last word is in question: a
/// Challenge answers for everything sent before it, so an idle pair's
/// keepalive costs one round, not one per `recheck` until the peer speaks.
/// A round starts once such traffic has waited `silence` and the relay has
/// been silent as long (`recheck` when its last word was a Challenge, so a
/// one-way stream is asked once per interval). It ends the moment the relay
/// says anything. It convicts only after every bind of the round has gone
/// unanswered and the last one has had `echo_wait`.
fn liveness_step(
    t: &LivenessTiming,
    round: &mut LivenessRound,
    s: LivenessSample,
    now: u64,
) -> LivenessStep {
    if round.binds > 0 && s.last_relay_rx >= round.first {
        *round = LivenessRound::default();
    }
    if s.pending_since <= s.last_relay_rx {
        *round = LivenessRound::default();
        return LivenessStep::Quiet;
    }
    if round.binds == 0 {
        let wait = if s.last_relay_rx > s.last_data_rx {
            t.recheck
        } else {
            t.silence
        };
        if now.saturating_sub(s.last_relay_rx) < wait
            || now.saturating_sub(s.pending_since) < t.silence
        {
            return LivenessStep::Wait;
        }
        *round = LivenessRound {
            binds: 1,
            first: now,
            last: now,
            fast: s.last_data_rx != 0 && now.saturating_sub(s.last_data_rx) <= t.flowing,
        };
        return LivenessStep::Bind;
    }
    let (need, gap) = if round.fast {
        (LIVENESS_FAST_BINDS, t.fast_gap)
    } else {
        (LIVENESS_SLOW_BINDS, t.slow_gap)
    };
    if round.binds < need {
        if now.saturating_sub(round.last) < gap {
            return LivenessStep::Wait;
        }
        round.binds += 1;
        round.last = now;
        return LivenessStep::Bind;
    }
    if now.saturating_sub(round.last) >= t.echo_wait {
        LivenessStep::Dead
    } else {
        LivenessStep::Wait
    }
}

/// A member carrier's liveness state ([`OrgRelayConn::with_liveness`]).
struct Liveness {
    timing: LivenessTiming,
    born: Instant,
    last_data_rx: AtomicU64,
    last_relay_rx: AtomicU64,
    pending_since: AtomicU64,
    /// The poller's round and the nonces of its binds: a Challenge echoing
    /// any of them counts, so a slow answer to an earlier bind is not lost.
    round: std::sync::Mutex<(LivenessRound, Vec<Nonce>)>,
}

impl Liveness {
    /// Milliseconds since the carrier was built; never `0`.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.born.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(1)
    }

    fn sample(&self) -> LivenessSample {
        LivenessSample {
            last_data_rx: self.last_data_rx.load(Ordering::Relaxed),
            last_relay_rx: self.last_relay_rx.load(Ordering::Relaxed),
            pending_since: self.pending_since.load(Ordering::Relaxed),
        }
    }

    /// A frame is leaving for the peer: the first one since the relay's last
    /// word starts the unanswered clock.
    fn on_send(&self) {
        let heard = self.last_relay_rx.load(Ordering::Relaxed);
        if self.pending_since.load(Ordering::Relaxed) <= heard {
            // Strictly after the relay's last word, even inside its millisecond.
            self.pending_since.store(
                self.now_ms().max(heard.saturating_add(1)),
                Ordering::Relaxed,
            );
        }
    }

    fn on_peer_frame(&self) {
        let now = self.now_ms();
        self.last_data_rx.store(now, Ordering::Relaxed);
        self.last_relay_rx.store(now, Ordering::Relaxed);
    }

    fn on_challenge(&self) {
        self.last_relay_rx.store(self.now_ms(), Ordering::Relaxed);
    }

    /// Is `nonce` one of the current round's binds?
    fn owns(&self, nonce: &Nonce) -> bool {
        self.round
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .contains(nonce)
    }
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
            rebind: None,
            liveness: None,
        }
    }

    /// Re-bind in band after [`IDLE_REBIND`] of silence (module docs). The
    /// carrier was just bound, so the silence clock starts now.
    pub fn with_rebind(mut self, generation: u64, secret: BindSecret) -> Self {
        self.rebind = Some(Rebind {
            generation,
            secret,
            idle_after: IDLE_REBIND,
            last_tx_ms: std::sync::atomic::AtomicU64::new(0),
            born: Instant::now(),
            pending: std::sync::Mutex::new(None),
        });
        self
    }

    /// Watch the bound leg (module docs). `rtt` is the bind round trip just
    /// measured to this relay; a slow leg gets proportionally more patience.
    /// A no-op without [`Self::with_rebind`]: the question is asked with the
    /// session's bind secret. The clocks start now, so the bind itself is
    /// the first word heard from the relay.
    pub fn with_liveness(mut self, rtt: Duration) -> Self {
        if self.rebind.is_some() {
            self.liveness = Some(Liveness {
                timing: LivenessTiming::for_rtt(rtt),
                born: Instant::now(),
                last_data_rx: AtomicU64::new(0),
                last_relay_rx: AtomicU64::new(1),
                pending_since: AtomicU64::new(0),
                round: std::sync::Mutex::new((LivenessRound::default(), Vec::new())),
            });
        }
        self
    }

    /// One liveness poll: cheap, never blocks, and safe to call at any rate.
    /// Sends at most one bind. On [`LivenessPoll::Dead`] the carrier is
    /// already closed and every later poll answers [`LivenessPoll::Quiet`].
    pub fn poll_liveness(&self) -> LivenessPoll {
        let (Some(live), Some(rebind)) = (&self.liveness, &self.rebind) else {
            return LivenessPoll::Quiet;
        };
        if !self.is_alive() {
            return LivenessPoll::Quiet;
        }
        let now = live.now_ms();
        let sample = live.sample();
        let mut held = live.round.lock().unwrap_or_else(|e| e.into_inner());
        let mut round = held.0;
        match liveness_step(&live.timing, &mut round, sample, now) {
            LivenessStep::Quiet => {
                *held = (round, Vec::new());
                LivenessPoll::Quiet
            }
            LivenessStep::Wait => {
                if round.binds == 0 {
                    held.1.clear();
                }
                held.0 = round;
                LivenessPoll::Watching
            }
            LivenessStep::Bind => {
                let nonce = fresh_nonce();
                // A bind the socket did not take was not sent: the round
                // keeps its previous state and the next poll tries again.
                if self
                    .sock
                    .try_send_to(&rebind.bind_frame(self.vni, nonce), self.relay)
                    .is_ok()
                {
                    if round.binds == 1 {
                        held.1.clear();
                    }
                    held.1.push(nonce);
                    held.0 = round;
                }
                LivenessPoll::Watching
            }
            LivenessStep::Dead => {
                *held = (LivenessRound::default(), Vec::new());
                drop(held);
                self.close();
                LivenessPoll::Dead {
                    binds: round.binds,
                    silent: Duration::from_millis(now.saturating_sub(sample.last_relay_rx)),
                }
            }
        }
    }

    #[cfg(test)]
    fn rebind_after(mut self, idle_after: Duration) -> Self {
        if let Some(r) = self.rebind.as_mut() {
            r.idle_after = idle_after;
        }
        self
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
        if let Some(bind) = self
            .rebind
            .as_ref()
            .and_then(|r| r.bind_before_send(self.vni))
        {
            self.sock.send_to(&bind, self.relay).await?;
        }
        self.sock
            .send_to(&build_data(self.vni, buf), self.relay)
            .await?;
        if let Some(live) = &self.liveness {
            live.on_send();
        }
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
            if let Some(r) = &self.rebind
                && let Some((vni, ControlFrame::Challenge { nonce, cookie })) =
                    ControlFrame::decode(&tmp[..n])
            {
                if vni == self.vni {
                    // The idle re-bind's attempt, or one of the liveness
                    // round's binds: either way the relay just answered for
                    // this session, and the Answer (re)binds this source.
                    let answer = r.answer(vni, nonce, cookie).or_else(|| {
                        self.liveness
                            .as_ref()
                            .is_some_and(|l| l.owns(&nonce))
                            .then(|| r.answer_frame(vni, nonce, cookie))
                    });
                    if let Some(answer) = answer {
                        if let Some(live) = &self.liveness {
                            live.on_challenge();
                        }
                        let _ = self.sock.send_to(&answer, self.relay).await;
                    }
                }
                continue;
            }
            let Some((vni, payload)) = parse_data(&tmp[..n]) else {
                continue;
            };
            if vni != self.vni {
                continue;
            }
            if let Some(live) = &self.liveness {
                live.on_peer_frame();
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

    async fn bound_count(stats: &RelayStats, at_least: u64) -> bool {
        timeout(Duration::from_secs(5), async {
            while stats.snapshot().bound < at_least {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok()
    }

    /// The NAT re-created a silent member's mapping on a new port (B6
    /// dormancy, lab R8 lc-odlate-as): the relay still forwards to the old
    /// source. The member's first send after the silence re-binds in band,
    /// on its own socket, and the relay forwards to the new source again.
    #[tokio::test]
    async fn a_silent_member_rebinds_in_band_from_a_remapped_source() {
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
        assert!(bound_count(&stats, 2).await);
        // The remap: a's traffic now leaves from a socket the relay never saw.
        let a_new = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a = Arc::new(
            OrgRelayConn::new(a_new, relay, VNI, "r".into())
                .with_rebind(GEN, sa)
                .rebind_after(Duration::from_millis(200)),
        );
        let b = OrgRelayConn::new(b_sock, relay, VNI, "r".into());
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let reader = a.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while let Ok((n, _)) = reader.recv_from(&mut buf).await {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        b.send_to(b"to the old source", b.synth_peer())
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "before a re-binds, the relay forwards to the dead old source"
        );
        a.send_to(b"after the silence", a.synth_peer())
            .await
            .unwrap();
        assert!(
            bound_count(&stats, 3).await,
            "the in-band re-bind was applied"
        );
        b.send_to(b"to the new source", b.synth_peer())
            .await
            .unwrap();
        let got = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the relay forwards to a's new source")
            .unwrap();
        assert_eq!(got, b"to the new source");
    }

    /// A member that keeps sending never re-binds, and a re-bind from an
    /// unchanged source leaves forwarding as it was.
    #[tokio::test]
    async fn a_busy_member_never_rebinds_and_an_unchanged_source_keeps_forwarding() {
        let (relay, stats) = relay_with_session([[1; 32], [2; 32]]).await;
        let sa = BindSecret::from_bytes([1; 32]);
        let sb = BindSecret::from_bytes([2; 32]);
        let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        bind(&a_sock, relay, VNI, GEN, &sa, Duration::from_secs(5))
            .await
            .unwrap();
        bind(&b_sock, relay, VNI, GEN, &sb, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(bound_count(&stats, 2).await);
        let a = Arc::new(
            OrgRelayConn::new(a_sock, relay, VNI, "r".into())
                .with_rebind(GEN, sa)
                .rebind_after(Duration::from_millis(400)),
        );
        let b = OrgRelayConn::new(b_sock, relay, VNI, "r".into());
        let reader = a.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while let Ok((n, _)) = reader.recv_from(&mut buf).await {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        for _ in 0..5 {
            a.send_to(b"busy", a.synth_peer()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(stats.snapshot().bound, 2, "no re-bind while busy");
        tokio::time::sleep(Duration::from_millis(500)).await;
        a.send_to(b"after the silence", a.synth_peer())
            .await
            .unwrap();
        assert!(
            bound_count(&stats, 3).await,
            "re-bound from the same source"
        );
        b.send_to(b"still here", b.synth_peer()).await.unwrap();
        let got = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("forwarding unchanged")
            .unwrap();
        assert_eq!(got, b"still here");
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

    // ─── Liveness of the bound leg (acceptance item 6) ─────────────────────

    fn timing() -> LivenessTiming {
        LivenessTiming::for_rtt(Duration::ZERO)
    }

    fn sample(last_data_rx: u64, last_relay_rx: u64, pending_since: u64) -> LivenessSample {
        LivenessSample {
            last_data_rx,
            last_relay_rx,
            pending_since,
        }
    }

    /// The stamping of [`Liveness`] on a virtual clock.
    #[derive(Default)]
    struct Leg(LivenessSample);

    impl Leg {
        fn send(&mut self, now: u64) {
            if self.0.pending_since <= self.0.last_relay_rx {
                self.0.pending_since = now.max(self.0.last_relay_rx + 1);
            }
        }
        fn peer_frame(&mut self, now: u64) {
            self.0.last_data_rx = now;
            self.0.last_relay_rx = now;
        }
        fn challenge(&mut self, now: u64) {
            self.0.last_relay_rx = now;
        }
    }

    /// Poll every 100 ms (the hot tick) from `from` to `until` against a relay
    /// that never answers: when each bind left, and when the verdict fell.
    fn silent_relay(
        t: &LivenessTiming,
        s: LivenessSample,
        from: u64,
        until: u64,
    ) -> (Vec<u64>, Option<u64>) {
        let mut round = LivenessRound::default();
        let mut binds = Vec::new();
        let mut now = from;
        while now <= until {
            match liveness_step(t, &mut round, s, now) {
                LivenessStep::Bind => binds.push(now),
                LivenessStep::Dead => return (binds, Some(now)),
                LivenessStep::Quiet | LivenessStep::Wait => {}
            }
            now += 100;
        }
        (binds, None)
    }

    #[test]
    fn answered_traffic_is_quiet_and_a_fresh_send_only_waits() {
        let t = timing();
        let mut round = LivenessRound::default();
        // The peer's frame came after our last send: nothing is unanswered.
        assert_eq!(
            liveness_step(&t, &mut round, sample(1_000, 1_000, 900), 9_000),
            LivenessStep::Quiet
        );
        // A send 300 ms old is a request still waiting for its answer.
        assert_eq!(
            liveness_step(&t, &mut round, sample(1_000, 1_000, 1_010), 1_310),
            LivenessStep::Wait
        );
        assert_eq!(round, LivenessRound::default(), "no round was started");
    }

    /// The oracle's case: frames were flowing, the relay froze. Three binds,
    /// and the verdict inside two seconds of the last frame heard.
    #[test]
    fn a_stream_that_stops_is_convicted_inside_two_seconds() {
        let (binds, dead) = silent_relay(&timing(), sample(10_000, 10_000, 10_050), 10_100, 20_000);
        assert_eq!(binds.len() as u32, LIVENESS_FAST_BINDS, "{binds:?}");
        assert!(
            binds[0] - 10_050 >= 400,
            "not before the silence: {binds:?}"
        );
        let dead = dead.expect("a relay that answers nothing is convicted");
        assert!(
            (11_400..=11_800).contains(&dead),
            "verdict {} ms after the last frame; binds {binds:?}",
            dead - 10_000
        );
    }

    /// A Challenge settles the round whatever the peer does: behind a healthy
    /// relay a peer that never answers a stream costs one bind per recheck
    /// and is never a death.
    #[test]
    fn an_answering_relay_is_never_convicted_however_silent_the_peer() {
        let t = timing();
        let mut round = LivenessRound::default();
        let mut leg = Leg::default();
        leg.peer_frame(10_000);
        let mut challenge_at = None;
        let mut binds = Vec::new();
        let mut now = 10_050;
        while now <= 20_000 {
            if challenge_at.is_some_and(|at| at <= now) {
                leg.challenge(challenge_at.take().unwrap());
            }
            leg.send(now); // a one-way stream: a frame every 50 ms
            if now % 100 == 0 {
                match liveness_step(&t, &mut round, leg.0, now) {
                    LivenessStep::Bind => {
                        binds.push(now);
                        challenge_at = Some(now + 60);
                    }
                    LivenessStep::Dead => panic!("convicted an answering relay at {now}"),
                    LivenessStep::Quiet | LivenessStep::Wait => {}
                }
            }
            now += 50;
        }
        assert!((4..=6).contains(&binds.len()), "one per recheck: {binds:?}");
        assert!(
            binds.windows(2).all(|w| w[1] - w[0] >= 2_000),
            "never closer than the recheck: {binds:?}"
        );
    }

    /// An idle pair: one keepalive every 25 s, a peer that says nothing in
    /// between. The relay's Challenge answers for the keepalive, so each one
    /// costs a single bind; nothing is asked again until something is sent.
    #[test]
    fn an_idle_pairs_keepalive_costs_one_bind_and_then_nothing() {
        let t = timing();
        let mut round = LivenessRound::default();
        let mut leg = Leg::default();
        leg.peer_frame(1_000);
        let mut challenge_at = None;
        let (mut binds, mut watching) = (Vec::new(), 0u64);
        let mut now = 30_000;
        while now <= 90_000 {
            if challenge_at.is_some_and(|at| at <= now) {
                leg.challenge(challenge_at.take().unwrap());
            }
            if now % 25_000 == 5_000 {
                leg.send(now); // 30 s, 55 s, 80 s
            }
            match liveness_step(&t, &mut round, leg.0, now) {
                LivenessStep::Bind => {
                    binds.push(now);
                    challenge_at = Some(now + 60);
                    watching += 100;
                }
                LivenessStep::Wait => watching += 100,
                LivenessStep::Dead => panic!("convicted an answering relay at {now}"),
                LivenessStep::Quiet => {}
            }
            now += 100;
        }
        assert_eq!(binds, [30_400, 55_400, 80_400], "one bind per keepalive");
        assert!(
            watching <= 3 * 600,
            "the scan is hot for {watching} ms of 60 s, not all of it"
        );
    }

    /// One lost Challenge is not a verdict: the round's later bind is
    /// answered and the round ends.
    #[test]
    fn a_lost_answer_is_absorbed_by_the_next_bind() {
        let t = timing();
        let mut round = LivenessRound::default();
        let mut last_relay_rx = 10_000;
        let mut binds = 0;
        let mut now = 10_100;
        while now <= 13_000 {
            let s = sample(10_000, last_relay_rx, 10_050);
            match liveness_step(&t, &mut round, s, now) {
                LivenessStep::Bind => {
                    binds += 1;
                    if binds == 2 {
                        last_relay_rx = now + 60; // only the second is answered
                    }
                }
                LivenessStep::Dead => panic!("one lost answer convicted the relay"),
                LivenessStep::Quiet | LivenessStep::Wait => {}
            }
            now += 100;
        }
        assert!(binds >= 2);
    }

    /// With nothing arriving beforehand there is no abrupt stop to back the
    /// verdict (a one-way stream, an idle pair's keepalive, the first packet
    /// after a pause, a candidate the peer has not bound yet): five binds,
    /// further apart.
    #[test]
    fn without_a_recent_peer_frame_the_round_is_slow() {
        for last_data_rx in [1_000, 0] {
            let s = sample(last_data_rx, 1_000, 20_000);
            let (binds, dead) = silent_relay(&timing(), s, 20_000, 40_000);
            assert_eq!(binds.len() as u32, LIVENESS_SLOW_BINDS, "{binds:?}");
            assert!(binds.windows(2).all(|w| w[1] - w[0] >= 700), "{binds:?}");
            let dead = dead.expect("still convicted, later");
            assert!(dead - 20_000 >= 3_500, "verdict after {} ms", dead - 20_000);
            // Never more than four control frames in any 2 s: the relay's
            // per-source budget is what an answer has to fit in.
            assert!(binds.windows(4).all(|w| w[3] - w[0] >= 2_000), "{binds:?}");
        }
    }

    #[test]
    fn a_peer_frame_mid_round_ends_it() {
        let t = timing();
        let mut round = LivenessRound::default();
        let s = sample(10_000, 10_000, 10_050);
        assert_eq!(liveness_step(&t, &mut round, s, 10_500), LivenessStep::Bind);
        assert_eq!(liveness_step(&t, &mut round, s, 11_000), LivenessStep::Bind);
        let heard = sample(11_200, 11_200, 10_050);
        assert_eq!(
            liveness_step(&t, &mut round, heard, 11_300),
            LivenessStep::Quiet
        );
        assert_eq!(round, LivenessRound::default());
    }

    #[test]
    fn a_slow_leg_gets_proportionally_more_patience() {
        let fast = timing();
        assert_eq!(
            (fast.silence, fast.fast_gap, fast.echo_wait),
            (400, 350, 300)
        );
        let slow = LivenessTiming::for_rtt(Duration::from_millis(300));
        assert_eq!(
            (slow.silence, slow.fast_gap, slow.echo_wait),
            (900, 700, 700)
        );
        assert_eq!(slow.slow_gap, 700);
        // A mismeasured bind cannot stretch the verdict without bound.
        let capped = LivenessTiming::for_rtt(Duration::from_secs(30));
        assert_eq!(capped, LivenessTiming::for_rtt(Duration::from_secs(1)));
    }

    /// A relay whose serve task can be stopped while its socket stays open:
    /// a frozen process, not a closed port.
    async fn stoppable_relay(
        secrets: [[u8; 32]; 2],
    ) -> (
        SocketAddr,
        Arc<RelayStats>,
        tokio::task::JoinHandle<()>,
        Arc<UdpSocket>,
    ) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());
        let (server, handle) = RelayServer::new(CookieKey::from_bytes([7; 32]), stats.clone());
        let serve = tokio::spawn(server.serve(sock.clone()));
        let mut session = retry_fixture_session();
        session.members[0].secret = BindSecret::from_bytes(secrets[0]);
        session.members[1].secret = BindSecret::from_bytes(secrets[1]);
        assert!(handle.install(session));
        (addr, stats, serve, sock)
    }

    /// Both members bound. `a` is the carrier under test, liveness on, its
    /// reader running; `b` is the peer.
    async fn live_pair(
        relay: SocketAddr,
        stats: &RelayStats,
    ) -> (
        Arc<OrgRelayConn>,
        OrgRelayConn,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        let sa = BindSecret::from_bytes([1; 32]);
        let sb = BindSecret::from_bytes([2; 32]);
        let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        bind(&a_sock, relay, VNI, GEN, &sa, Duration::from_secs(5))
            .await
            .unwrap();
        bind(&b_sock, relay, VNI, GEN, &sb, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(bound_count(stats, 2).await);
        let a = Arc::new(
            OrgRelayConn::new(a_sock, relay, VNI, "r".into())
                .with_rebind(GEN, sa)
                .with_liveness(Duration::ZERO),
        );
        let b = OrgRelayConn::new(b_sock, relay, VNI, "r".into());
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let reader = a.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while let Ok((n, _)) = reader.recv_from(&mut buf).await {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        (a, b, rx)
    }

    /// One answered exchange: `a` sends, the peer answers, `a` hears it.
    async fn exchange(
        a: &OrgRelayConn,
        b: &OrgRelayConn,
        rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        a.send_to(b"ping", a.synth_peer()).await.unwrap();
        b.send_to(b"pong", b.synth_peer()).await.unwrap();
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the relay forwards the peer's answer")
            .unwrap();
    }

    /// The field failure, end to end on a real relay: frames flow, the relay
    /// freezes with its socket open, and the member that keeps sending
    /// convicts the carrier inside three seconds and closes it.
    #[tokio::test]
    async fn a_frozen_relay_is_convicted_inside_three_seconds_and_the_carrier_closes() {
        let (relay, stats, serve, _open_socket) = stoppable_relay([[1; 32], [2; 32]]).await;
        let (a, b, mut rx) = live_pair(relay, &stats).await;
        for _ in 0..5 {
            exchange(&a, &b, &mut rx).await;
            assert!(!matches!(a.poll_liveness(), LivenessPoll::Dead { .. }));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(stats.snapshot().bound, 2, "a live exchange asks nothing");

        serve.abort();
        let _ = serve.await;
        let frozen = Instant::now();
        let binds = loop {
            let _ = a.send_to(b"into the silence", a.synth_peer()).await;
            if let LivenessPoll::Dead { binds, .. } = a.poll_liveness() {
                break binds;
            }
            assert!(
                frozen.elapsed() < Duration::from_secs(5),
                "a frozen relay was never convicted"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let took = frozen.elapsed();
        assert_eq!(binds, LIVENESS_FAST_BINDS);
        assert!(
            took > Duration::from_millis(1_100) && took < Duration::from_millis(2_200),
            "convicted after {took:?}"
        );
        assert!(!a.is_alive(), "the verdict closes the carrier");
        assert!(a.send_to(b"x", a.synth_peer()).await.is_err());
        assert_eq!(a.poll_liveness(), LivenessPoll::Quiet, "reported once");
    }

    /// The peer goes silent, the relay does not: the member keeps sending for
    /// 4.5 s, is answered by the relay each round, and convicts nothing.
    #[tokio::test]
    async fn a_silent_peer_behind_a_healthy_relay_is_never_convicted() {
        let (relay, stats, _serve, _sock) = stoppable_relay([[1; 32], [2; 32]]).await;
        let (a, b, mut rx) = live_pair(relay, &stats).await;
        exchange(&a, &b, &mut rx).await;
        let began = Instant::now();
        while began.elapsed() < Duration::from_millis(4_500) {
            a.send_to(b"one way", a.synth_peer()).await.unwrap();
            assert!(
                !matches!(a.poll_liveness(), LivenessPoll::Dead { .. }),
                "convicted a healthy relay after {:?}",
                began.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(a.is_alive());
        let rebinds = stats.snapshot().bound - 2;
        assert!(
            (1..=4).contains(&rebinds),
            "one answered re-bind per recheck, got {rebinds}"
        );
        // And the leg still carries the peer's frames afterwards.
        exchange(&a, &b, &mut rx).await;
    }

    /// The round is the re-bind: a member whose mapping moved (its frames
    /// now leave from a source the relay never saw) is re-bound by its first
    /// round while it keeps sending, where the idle re-bind never fires.
    #[tokio::test]
    async fn a_liveness_round_rebinds_a_member_whose_mapping_moved() {
        let (relay, stats, _serve, _sock) = stoppable_relay([[1; 32], [2; 32]]).await;
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
        assert!(bound_count(&stats, 2).await);
        let a_new = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a = Arc::new(
            OrgRelayConn::new(a_new, relay, VNI, "r".into())
                .with_rebind(GEN, sa)
                .with_liveness(Duration::ZERO),
        );
        let b = OrgRelayConn::new(b_sock, relay, VNI, "r".into());
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let reader = a.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            while let Ok((n, _)) = reader.recv_from(&mut buf).await {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        let began = Instant::now();
        while stats.snapshot().bound < 3 {
            a.send_to(b"from the new source", a.synth_peer())
                .await
                .unwrap();
            assert!(!matches!(a.poll_liveness(), LivenessPoll::Dead { .. }));
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "the round never re-bound the member"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        b.send_to(b"to the new source", b.synth_peer())
            .await
            .unwrap();
        let got = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the relay forwards to a's new source")
            .unwrap();
        assert_eq!(got, b"to the new source");
    }

    /// Liveness is opt-in per carrier: without it (the kill switch, a path
    /// trial's carrier) a frozen relay is never judged here.
    #[tokio::test]
    async fn a_carrier_built_without_liveness_is_never_judged() {
        let (relay, stats, serve, _open_socket) = stoppable_relay([[1; 32], [2; 32]]).await;
        let sa = BindSecret::from_bytes([1; 32]);
        let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        bind(&a_sock, relay, VNI, GEN, &sa, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(bound_count(&stats, 1).await);
        let a = OrgRelayConn::new(a_sock, relay, VNI, "r".into()).with_rebind(GEN, sa);
        serve.abort();
        let _ = serve.await;
        let began = Instant::now();
        while began.elapsed() < Duration::from_millis(2_500) {
            a.send_to(b"into the silence", a.synth_peer())
                .await
                .unwrap();
            assert_eq!(a.poll_liveness(), LivenessPoll::Quiet);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(a.is_alive());
    }
}
