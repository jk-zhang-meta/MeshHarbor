// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #1761 — the exit's TURN-relayed QUIC setup runs OFF its signaling loop.
//!
//! `ServerMsg::TunnelQuicSetup` used to await `allocate_relay_from_ice`
//! inline inside `handle_server_msg`, on the org's signaling loop. On a
//! UDP-hostile network every allocation walks the whole relay ladder —
//! measured at ~20 s per setup on a corporate-laptop exit — and for that
//! long the loop read nothing: no pings answered, nothing sent, no other
//! session's setup, no ICE, no terminate, no remote-control signaling. N
//! routes opened together meant N × 20 s of backlog, so a quic-derp setup
//! (synchronous, instant) queued behind them answered ~38 s after the
//! client opened it, past the client's 30 s `QUIC_READY_TIMEOUT`, and the
//! routes cycled QUIC → quic-derp → webrtc-dc → dead, every ~90 s.
//!
//! Now the TURN branch spawns [`begin_quic_turn_setup`]'s task and returns
//! at once; the task allocates, builds the peer, and reports on a per-org
//! channel ([`QuicSetupSender`]) the loop drains in its own `select!` arm.
//! The direct-bind and quic-derp branches stay inline — both synchronous.
//!
//! What the loop must keep straight while a setup is in flight lives in
//! [`PendingQuicSetups`], kept free of I/O so tests can drive it:
//!
//! - a `TunnelQuicCandidate` for the session is **buffered** and applied
//!   when the peer lands — without its TURN permission coturn drops the
//!   client's opening QUIC Initials, so a dropped candidate is a session
//!   that silently never connects;
//! - a `TunnelTerminate` **cancels** it: the result is closed, never
//!   inserted (the #1754 leak class — a peer in no map is closed by nobody);
//! - a result for an attempt the connection does not hold — it finished
//!   after a reconnect, or after a cancel-and-retry — is **late**: closed.
//!
//! One channel per ORG loop, created beside the reap channel in
//! `signaling::run` and borrowed into every connection; a process-global
//! sender would land a secondary org's peer in the primary's maps.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bson::oid::ObjectId;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tunnel_core::transport::relay::{self, RelayConn};

use super::quic_peer::AgentQuicPeer;
use super::reap::ReapSender;

/// Most TURN-relayed setups one control-WS connection keeps in flight; a
/// setup past it is refused with a warn and no ready, so the client
/// soft-falls back exactly as after a failed allocation. Each in-flight
/// setup is one task and one allocation (a UDP socket, then a TCP one on
/// the TLS tier), so the bound is a socket bound above all. Sized above
/// the largest legitimate burst — every client daemon re-opening every
/// declared route to this exit at once after a server roll — and two
/// orders of magnitude under the ephemeral-range exhaustion this daemon
/// has actually suffered (`docs/tunnels.md`, the `close()` rule).
pub const QUIC_SETUP_IN_FLIGHT_CAP: usize = 64;

/// Candidates buffered per in-flight setup. A client sends one or two (its
/// relayed address per relay it allocated); the cap keeps a replay from
/// growing an entry without bound for the life of the setup.
pub const MAX_BUFFERED_CANDIDATES: usize = 16;

/// The setup task's own deadline: a leak guard on the in-flight slot, not
/// a policy. The relay ladder bounds every step itself (~65 s worst case:
/// four UDP candidates × 5 s, the corp-VPN rescue retry, two TLS
/// candidates × 10 s, DNS 3 s per host), and the client gave up at 30 s
/// anyway; this only guarantees a slot is released if some future ladder
/// change stalls unboundedly.
pub const QUIC_TURN_SETUP_DEADLINE: Duration = Duration::from_secs(120);

/// Capacity of the per-org outcome channel. Senders are the in-flight
/// tasks, at most [`QUIC_SETUP_IN_FLIGHT_CAP`] per connection plus the
/// stragglers of the previous one; a full channel parks a task's send
/// (its own task — nothing else waits on it), never drops a result.
pub const QUIC_SETUP_OUTCOME_CAP: usize = QUIC_SETUP_IN_FLIGHT_CAP;

/// The sender half a setup task holds.
pub type QuicSetupSender = mpsc::Sender<QuicSetupOutcome>;
/// The receiver half the signaling loop's outcome arm drains.
pub type QuicSetupReceiver = mpsc::Receiver<QuicSetupOutcome>;

/// Why a TURN-branch setup produced no peer. Two variants because the
/// loop keeps the two warn lines the field greps for.
#[derive(Debug)]
pub enum QuicSetupError {
    /// The relay ladder found nothing (or the task's deadline elapsed):
    /// "TURN allocate failed — no QUIC relay this session".
    Allocate(anyhow::Error),
    /// The allocation succeeded but the quinn endpoint over it did not:
    /// "AgentQuicPeer setup failed".
    Setup(anyhow::Error),
}

impl std::fmt::Display for QuicSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicSetupError::Allocate(e) => write!(f, "TURN allocate failed: {e}"),
            QuicSetupError::Setup(e) => write!(f, "AgentQuicPeer setup failed: {e}"),
        }
    }
}

/// What a setup task hands back to the loop — the whole message.
pub struct QuicSetupOutcome {
    pub session_id: ObjectId,
    /// The attempt this result belongs to (from [`Begin::Started`]); the
    /// loop inserts only the attempt it still holds.
    pub attempt: u64,
    pub result: Result<Arc<AgentQuicPeer>, QuicSetupError>,
}

/// One setup in flight on its task.
#[derive(Debug)]
struct InFlight {
    attempt: u64,
    /// The client's relayed address(es) that arrived while the peer was
    /// still being built; permitted the moment it lands.
    candidates: Vec<SocketAddr>,
    /// A `rc:tunnel.terminate` arrived meanwhile: close the result.
    cancelled: bool,
}

/// The verdict of [`PendingQuicSetups::begin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Begin {
    /// Spawn the task; `attempt` goes with it and comes back in the outcome.
    Started { attempt: u64 },
    /// A live attempt for this session is already in flight. The server
    /// sends one setup per open, so a second is a replay or a bug; the
    /// first attempt's ready (or failure) already answers the session, and
    /// a second ~20 s allocation per duplicate would be the very amplifier
    /// the bound exists to stop. Refused, nothing spawned.
    AlreadyPending,
    /// [`QUIC_SETUP_IN_FLIGHT_CAP`] reached. Refused, nothing spawned.
    AtCapacity,
}

/// The verdict of [`PendingQuicSetups::complete`] — what the caller does
/// with the attempt's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// The attempt is the one held and nobody cancelled it: insert the
    /// peer, permit `candidates`, send the ready.
    Insert { candidates: Vec<SocketAddr> },
    /// A terminate arrived while it ran: close the peer, insert nothing.
    CloseCancelled,
    /// No entry for this attempt — it finished after the connection that
    /// started it ended, or a newer attempt replaced it: close the peer.
    CloseLate,
}

/// What [`PendingQuicSetups::settle`] left the loop to do.
pub enum Settled {
    /// Insert `peer`, permit `candidates`, send `rc:tunnel.quic.ready`.
    Ready {
        peer: Arc<AgentQuicPeer>,
        candidates: Vec<SocketAddr>,
    },
    /// The held attempt failed: warn as before, send no ready.
    Failed(QuicSetupError),
    /// Nothing to insert — `verdict` is `CloseCancelled` or `CloseLate`,
    /// and a peer the attempt built (`had_peer`) has been closed here.
    Closed { verdict: Completion, had_peer: bool },
}

/// By hand: `AgentQuicPeer` has no `Debug`, and a peer prints as what the
/// ready would carry — its fingerprint and addresses.
impl std::fmt::Debug for Settled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Settled::Ready { peer, candidates } => f
                .debug_struct("Ready")
                .field("fingerprint", &peer.cert_fingerprint())
                .field("addrs", &peer.addrs())
                .field("candidates", candidates)
                .finish(),
            Settled::Failed(e) => f.debug_tuple("Failed").field(e).finish(),
            Settled::Closed { verdict, had_peer } => f
                .debug_struct("Closed")
                .field("verdict", verdict)
                .field("had_peer", had_peer)
                .finish(),
        }
    }
}

/// The TURN-relayed setups one control-WS connection has in flight. Fresh
/// per connection (like the session maps), so a setup that outlives its
/// connection reports to the next one, which holds no entry for it and
/// closes what it built. Pure bookkeeping — the loop does the I/O.
#[derive(Default)]
pub struct PendingQuicSetups {
    inflight: HashMap<ObjectId, InFlight>,
}

/// Attempt ids are process-unique, not per connection: two connections'
/// first attempts must never look alike to [`PendingQuicSetups::complete`].
static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

impl PendingQuicSetups {
    /// Claim a slot for `session_id`'s setup. A cancelled entry does not
    /// block a new attempt — it is a tombstone for the OLD attempt, whose
    /// result then comes back `CloseLate` — but it counts toward the cap
    /// until that result lands, because its allocation is still running.
    pub fn begin(&mut self, session_id: ObjectId) -> Begin {
        if let Some(existing) = self.inflight.get(&session_id)
            && !existing.cancelled
        {
            return Begin::AlreadyPending;
        }
        if self.inflight.len() >= QUIC_SETUP_IN_FLIGHT_CAP
            && !self.inflight.contains_key(&session_id)
        {
            return Begin::AtCapacity;
        }
        let attempt = NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
        self.inflight.insert(
            session_id,
            InFlight {
                attempt,
                candidates: Vec::new(),
                cancelled: false,
            },
        );
        Begin::Started { attempt }
    }

    /// Is a setup (live or cancelled) in flight for `session_id`?
    pub fn is_pending(&self, session_id: ObjectId) -> bool {
        self.inflight.contains_key(&session_id)
    }

    /// Hold `addr` for the peer this session's setup will produce. `false`
    /// when no setup is in flight for it — the caller then takes today's
    /// path (a live peer is permitted at once, an unknown session dropped).
    /// Past [`MAX_BUFFERED_CANDIDATES`] the address is dropped (a client
    /// sends one or two); still `true`, the entry exists.
    pub fn buffer_candidate(&mut self, session_id: ObjectId, addr: SocketAddr) -> bool {
        let Some(entry) = self.inflight.get_mut(&session_id) else {
            return false;
        };
        if entry.candidates.len() >= MAX_BUFFERED_CANDIDATES {
            debug!(%session_id, %addr, "tunnel quic: candidate buffer full — dropping");
            return true;
        }
        entry.candidates.push(addr);
        true
    }

    /// A `rc:tunnel.terminate` for a session whose setup is in flight: its
    /// result will be closed, not inserted. `false` when nothing is in
    /// flight for it (the ordinary terminate — the maps handle it).
    pub fn cancel(&mut self, session_id: ObjectId) -> bool {
        match self.inflight.get_mut(&session_id) {
            Some(entry) => {
                entry.cancelled = true;
                true
            }
            None => false,
        }
    }

    /// The decision for a finished attempt, pure so a test can pin it. The
    /// entry is consumed only when the attempt matches: a stale attempt's
    /// result must not evict the newer attempt still running for the same
    /// session.
    pub fn complete(&mut self, session_id: ObjectId, attempt: u64) -> Completion {
        match self.inflight.get(&session_id) {
            Some(entry) if entry.attempt == attempt => {}
            _ => return Completion::CloseLate,
        }
        let entry = self
            .inflight
            .remove(&session_id)
            .expect("checked present above");
        if entry.cancelled {
            Completion::CloseCancelled
        } else {
            Completion::Insert {
                candidates: entry.candidates,
            }
        }
    }

    /// [`complete`](Self::complete) applied to an outcome: what the loop's
    /// arm does with it. A peer that is not going to be inserted is
    /// `close()`d HERE — an `AgentQuicPeer` dropped without `close()` keeps
    /// its accept task, its endpoint socket and its TURN allocation alive
    /// until its one connection ends, which for a client that never dials
    /// is never (the #1754 leak class). Closing aborts the accept task, so
    /// it also never reports a `QuicConnEnded` reap for a session id the
    /// maps may by now hold a NEWER peer under.
    pub fn settle(&mut self, outcome: QuicSetupOutcome) -> Settled {
        let QuicSetupOutcome {
            session_id,
            attempt,
            result,
        } = outcome;
        match self.complete(session_id, attempt) {
            Completion::Insert { candidates } => match result {
                Ok(peer) => Settled::Ready { peer, candidates },
                Err(e) => Settled::Failed(e),
            },
            verdict @ (Completion::CloseCancelled | Completion::CloseLate) => {
                let had_peer = match result {
                    Ok(peer) => {
                        peer.close();
                        true
                    }
                    Err(e) => {
                        debug!(%session_id, attempt, %e, "tunnel quic: a discarded setup had also failed");
                        false
                    }
                };
                Settled::Closed { verdict, had_peer }
            }
        }
    }

    /// Setups in flight, cancelled ones included (their allocations run).
    pub fn len(&self) -> usize {
        self.inflight.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inflight.is_empty()
    }
}

impl Drop for PendingQuicSetups {
    /// The connection ended with setups still running. Their results reach
    /// the next connection over the per-org channel and are closed there
    /// (`CloseLate`); this line is what tells a field log that the ready
    /// for those sessions was never going to come.
    fn drop(&mut self) {
        if !self.inflight.is_empty() {
            info!(
                count = self.inflight.len(),
                "tunnel quic: setups still in flight at control-WS exit — their results are closed on arrival (#1761)"
            );
        }
    }
}

/// What the `TunnelQuicSetup` arm hands to [`begin_quic_turn_setup`]: the
/// session, its token, and the coturn credentials the server minted.
pub struct QuicTurnSetup {
    pub session_id: ObjectId,
    pub quic_auth_token: String,
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

/// The production allocator: the relay ladder, as an `Arc<dyn RelayConn>`
/// for [`AgentQuicPeer::setup_over_relay`]. The seam a test replaces with
/// an allocator that parks.
pub async fn allocate_turn_relay(
    urls: Vec<String>,
    username: String,
    credential: String,
) -> anyhow::Result<Arc<dyn RelayConn>> {
    let relay = relay::allocate_relay_from_ice(&urls, &username, &credential).await?;
    Ok(Arc::new(relay))
}

/// Start `req`'s TURN-relayed setup OFF the signaling loop: claim a slot in
/// `pending`, spawn the task that allocates + builds the peer + reports on
/// `outcome_tx`, and return at once. `async` only so the arm's flow reads
/// top to bottom; nothing here waits on the network — that is the whole
/// fix (#1761). A refused verdict spawns nothing; the arm logs it and sends
/// no ready, and the client soft-falls back as after a failed allocation.
pub async fn begin_quic_turn_setup<A, F>(
    pending: &mut PendingQuicSetups,
    req: QuicTurnSetup,
    reap_tx: ReapSender,
    outcome_tx: QuicSetupSender,
    allocate: A,
) -> Begin
where
    A: FnOnce(Vec<String>, String, String) -> F + Send + 'static,
    F: Future<Output = anyhow::Result<Arc<dyn RelayConn>>> + Send + 'static,
{
    let verdict = pending.begin(req.session_id);
    let Begin::Started { attempt } = verdict else {
        return verdict;
    };
    let work = run_quic_turn_setup(req, attempt, reap_tx, outcome_tx, allocate);
    // The allocation walks the relay ladder — ~20 s on a UDP-hostile
    // network — and the loop that called us must keep reading meanwhile.
    tokio::spawn(work);
    verdict
}

/// The task: allocate, stand the quinn server up over the relay, report.
/// A report the loop cannot receive (the org loop is gone) is closed here
/// — a peer nobody holds is a peer nobody closes.
async fn run_quic_turn_setup<A, F>(
    req: QuicTurnSetup,
    attempt: u64,
    reap_tx: ReapSender,
    outcome_tx: QuicSetupSender,
    allocate: A,
) where
    A: FnOnce(Vec<String>, String, String) -> F + Send + 'static,
    F: Future<Output = anyhow::Result<Arc<dyn RelayConn>>> + Send + 'static,
{
    let QuicTurnSetup {
        session_id,
        quic_auth_token,
        urls,
        username,
        credential,
    } = req;
    let build = async {
        let relay_conn = allocate(urls, username, credential)
            .await
            .map_err(QuicSetupError::Allocate)?;
        AgentQuicPeer::setup_over_relay(session_id, quic_auth_token, relay_conn, reap_tx)
            .map(Arc::new)
            .map_err(QuicSetupError::Setup)
    };
    let result = match tokio::time::timeout(QUIC_TURN_SETUP_DEADLINE, build).await {
        Ok(r) => r,
        Err(_elapsed) => Err(QuicSetupError::Allocate(anyhow::anyhow!(
            "no relay within the setup deadline ({} s)",
            QUIC_TURN_SETUP_DEADLINE.as_secs()
        ))),
    };
    let outcome = QuicSetupOutcome {
        session_id,
        attempt,
        result,
    };
    if let Err(mpsc::error::SendError(returned)) = outcome_tx.send(outcome).await {
        if let Ok(peer) = returned.result {
            peer.close();
        }
        warn!(%session_id, attempt, "tunnel quic: setup finished but the org loop is gone — closed (#1761)");
    }
}

/// The candidate arm's parse, shared with the outcome arm: every
/// well-formed `host:port` in `addrs`; an unparseable one is logged and
/// skipped, as before.
pub fn parse_candidate_addrs(session_id: ObjectId, addrs: &[String]) -> Vec<SocketAddr> {
    addrs
        .iter()
        .filter_map(|a| match a.parse::<SocketAddr>() {
            Ok(sa) => Some(sa),
            Err(e) => {
                debug!(%session_id, addr = %a, %e, "tunnel quic: unparseable candidate addr");
                None
            }
        })
        .collect()
}

/// Install `peer`'s TURN permission for each client address — one
/// bootstrap datagram through its own allocation, the same for a candidate
/// that arrives after the peer exists and for the ones buffered while it
/// was being built. A failed permit is logged and the rest still go.
pub async fn permit_candidates(peer: &AgentQuicPeer, session_id: ObjectId, addrs: &[SocketAddr]) {
    for sa in addrs {
        if let Err(e) = peer.permit(*sa).await {
            debug!(%session_id, addr = %sa, %e, "tunnel quic: permit failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    use tunnel_core::transport::relay::UdpRelayConn;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }

    fn reap_channel() -> (ReapSender, mpsc::Receiver<super::super::reap::TunnelReap>) {
        mpsc::channel(super::super::reap::TUNNEL_REAP_CAP)
    }

    fn outcome_channel() -> (QuicSetupSender, QuicSetupReceiver) {
        mpsc::channel(QUIC_SETUP_OUTCOME_CAP)
    }

    /// A loopback UDP socket standing in for a coturn allocation, as the
    /// quic_peer tests do (the real permission-gated path is proven in
    /// tunnel-core's `quinn_runs_over_two_turn_allocations`).
    async fn loopback_relay() -> Arc<dyn RelayConn> {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("loopback udp");
        Arc::new(UdpRelayConn(sock))
    }

    /// A peer built the way the task builds one, on a loopback relay.
    async fn relay_peer(sid: ObjectId, reap_tx: &ReapSender) -> Arc<AgentQuicPeer> {
        Arc::new(
            AgentQuicPeer::setup_over_relay(
                sid,
                "tok".to_string(),
                loopback_relay().await,
                reap_tx.clone(),
            )
            .expect("quic peer over a loopback relay"),
        )
    }

    fn req(sid: ObjectId) -> QuicTurnSetup {
        QuicTurnSetup {
            session_id: sid,
            quic_auth_token: "tok".to_string(),
            urls: vec!["turn:relay.example:3478?transport=udp".to_string()],
            username: "u".to_string(),
            credential: "c".to_string(),
        }
    }

    async fn ended(peer: &AgentQuicPeer) -> bool {
        for _ in 0..100 {
            if peer.accept_ended() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// (a) Candidates that arrive while the peer is still being built are
    /// handed back, in order, when the attempt completes — the permission
    /// each one needs is installed on the peer the setup produces, not
    /// dropped on the floor for want of one.
    #[test]
    fn candidates_buffered_before_completion_are_returned_on_insert() {
        let mut pending = PendingQuicSetups::default();
        let sid = ObjectId::new();
        let Begin::Started { attempt } = pending.begin(sid) else {
            panic!("a fresh session starts");
        };
        assert!(pending.buffer_candidate(sid, addr(1)));
        assert!(pending.buffer_candidate(sid, addr(2)));
        assert!(
            !pending.buffer_candidate(ObjectId::new(), addr(3)),
            "no setup in flight for that session — the caller takes the live-peer path"
        );
        assert_eq!(
            pending.complete(sid, attempt),
            Completion::Insert {
                candidates: vec![addr(1), addr(2)]
            }
        );
        assert!(
            pending.is_empty(),
            "the entry is consumed by its completion"
        );
    }

    /// (b) A terminate that lands while the setup runs turns its result into
    /// a close: never an insert, whatever candidates it had.
    #[test]
    fn a_cancel_before_completion_closes_never_inserts() {
        let mut pending = PendingQuicSetups::default();
        let sid = ObjectId::new();
        let Begin::Started { attempt } = pending.begin(sid) else {
            panic!("a fresh session starts");
        };
        assert!(pending.buffer_candidate(sid, addr(1)));
        assert!(pending.cancel(sid), "the in-flight setup is cancelled");
        assert!(
            !pending.cancel(ObjectId::new()),
            "nothing in flight for that session"
        );
        assert!(
            pending.is_pending(sid),
            "a cancelled entry still holds its slot"
        );
        assert_eq!(pending.complete(sid, attempt), Completion::CloseCancelled);
        assert!(pending.is_empty());
    }

    /// (c) A result no entry claims — the connection that started it is
    /// gone, or a newer attempt replaced it — is closed, and a stale
    /// attempt's result leaves the newer entry untouched.
    #[test]
    fn a_completion_with_no_entry_or_a_stale_attempt_is_closed_late() {
        let mut pending = PendingQuicSetups::default();
        assert_eq!(
            pending.complete(ObjectId::new(), 1),
            Completion::CloseLate,
            "a result from a previous connection finds no entry"
        );
        let sid = ObjectId::new();
        let Begin::Started { attempt } = pending.begin(sid) else {
            panic!("a fresh session starts");
        };
        assert!(pending.buffer_candidate(sid, addr(9)));
        assert_eq!(
            pending.complete(sid, attempt + 1),
            Completion::CloseLate,
            "another attempt's result never completes this one"
        );
        assert!(
            pending.is_pending(sid),
            "the held attempt survives a stale result"
        );
        assert_eq!(
            pending.complete(sid, attempt),
            Completion::Insert {
                candidates: vec![addr(9)]
            },
            "and its own result still inserts, candidates intact"
        );
    }

    /// (d) A second setup for a session whose first is live in flight is
    /// refused and changes nothing about the first; after a cancel, a new
    /// attempt may start, and the old attempt's result is then late.
    #[test]
    fn a_duplicate_setup_is_refused_while_live_and_allowed_after_a_cancel() {
        let mut pending = PendingQuicSetups::default();
        let sid = ObjectId::new();
        let Begin::Started { attempt: first } = pending.begin(sid) else {
            panic!("a fresh session starts");
        };
        assert!(pending.buffer_candidate(sid, addr(1)));
        assert_eq!(pending.begin(sid), Begin::AlreadyPending);
        assert_eq!(pending.len(), 1, "the duplicate took no slot");
        assert_eq!(
            pending.complete(sid, first),
            Completion::Insert {
                candidates: vec![addr(1)]
            },
            "the first attempt keeps its candidates"
        );

        let Begin::Started { attempt: second } = pending.begin(sid) else {
            panic!("a completed session may be set up again");
        };
        assert!(pending.cancel(sid));
        let Begin::Started { attempt: third } = pending.begin(sid) else {
            panic!("a cancelled entry is a tombstone for the OLD attempt, not a block");
        };
        assert_ne!(second, third);
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending.complete(sid, second),
            Completion::CloseLate,
            "the cancelled attempt's result is late, and does not evict the new one"
        );
        assert!(pending.is_pending(sid));
        assert_eq!(
            pending.complete(sid, third),
            Completion::Insert { candidates: vec![] },
            "the retry started clean"
        );
    }

    /// The bound: the cap-th setup starts, the next is refused, and a
    /// completion frees a slot. Cancelled entries keep theirs — their
    /// allocation is still running.
    #[test]
    fn the_in_flight_bound_refuses_the_extra_setup_until_one_completes() {
        let mut pending = PendingQuicSetups::default();
        let mut started = Vec::new();
        for _ in 0..QUIC_SETUP_IN_FLIGHT_CAP {
            let sid = ObjectId::new();
            let Begin::Started { attempt } = pending.begin(sid) else {
                panic!("under the cap every setup starts");
            };
            started.push((sid, attempt));
        }
        assert_eq!(pending.begin(ObjectId::new()), Begin::AtCapacity);
        let (cancelled, _) = started[0];
        assert!(pending.cancel(cancelled));
        assert_eq!(
            pending.begin(ObjectId::new()),
            Begin::AtCapacity,
            "a cancelled setup's allocation still runs — it keeps its slot"
        );
        assert!(
            matches!(pending.begin(cancelled), Begin::Started { .. }),
            "re-setting up the cancelled session replaces its tombstone, no extra slot"
        );
        assert_eq!(pending.len(), QUIC_SETUP_IN_FLIGHT_CAP);
        let (done, attempt) = started[1];
        assert_eq!(
            pending.complete(done, attempt),
            Completion::Insert { candidates: vec![] }
        );
        assert!(
            matches!(pending.begin(ObjectId::new()), Begin::Started { .. }),
            "a completion frees a slot"
        );
    }

    /// `settle` closes what it does not insert: a cancelled attempt's peer
    /// and a late one's are both `close()`d (their accept tasks end), and
    /// the held attempt's peer comes back untouched for the loop to insert.
    #[tokio::test(flavor = "multi_thread")]
    async fn settle_closes_a_cancelled_or_late_peer_and_returns_the_held_one() {
        let (reap_tx, _reap_rx) = reap_channel();
        let mut pending = PendingQuicSetups::default();

        let cancelled = ObjectId::new();
        let Begin::Started { attempt } = pending.begin(cancelled) else {
            panic!("starts");
        };
        assert!(pending.cancel(cancelled));
        let peer = relay_peer(cancelled, &reap_tx).await;
        let settled = pending.settle(QuicSetupOutcome {
            session_id: cancelled,
            attempt,
            result: Ok(Arc::clone(&peer)),
        });
        assert!(
            matches!(
                settled,
                Settled::Closed {
                    verdict: Completion::CloseCancelled,
                    had_peer: true
                }
            ),
            "a cancelled attempt's peer is not inserted: {settled:?}"
        );
        assert!(ended(&peer).await, "…and it was closed, not merely dropped");

        let late = ObjectId::new();
        let peer = relay_peer(late, &reap_tx).await;
        let settled = pending.settle(QuicSetupOutcome {
            session_id: late,
            attempt: 0,
            result: Ok(Arc::clone(&peer)),
        });
        assert!(
            matches!(
                settled,
                Settled::Closed {
                    verdict: Completion::CloseLate,
                    had_peer: true
                }
            ),
            "a result no entry claims is not inserted: {settled:?}"
        );
        assert!(ended(&peer).await, "…and closed");

        let held = ObjectId::new();
        let Begin::Started { attempt } = pending.begin(held) else {
            panic!("starts");
        };
        assert!(pending.buffer_candidate(held, addr(4)));
        let peer = relay_peer(held, &reap_tx).await;
        match pending.settle(QuicSetupOutcome {
            session_id: held,
            attempt,
            result: Ok(Arc::clone(&peer)),
        }) {
            Settled::Ready {
                peer: ready,
                candidates,
            } => {
                assert!(Arc::ptr_eq(&ready, &peer), "the very peer the task built");
                assert_eq!(candidates, vec![addr(4)]);
                assert!(!ready.accept_ended(), "a peer about to be inserted is live");
                ready.close();
            }
            other => panic!("the held attempt is inserted, got {other:?}"),
        }
        let settled = pending.settle(QuicSetupOutcome {
            session_id: ObjectId::new(),
            attempt: 0,
            result: Err(QuicSetupError::Allocate(anyhow::anyhow!("no relay"))),
        });
        assert!(
            matches!(
                settled,
                Settled::Closed {
                    verdict: Completion::CloseLate,
                    had_peer: false
                }
            ),
            "a late failure has nothing to close: {settled:?}"
        );
    }

    /// The bug (#1761): a setup whose allocation takes as long as it likes
    /// holds nothing up. Session A's allocator parks until released; the
    /// TURN branch returns at once regardless, session B's setup completes
    /// and is ready while A is still allocating, and A lands when its
    /// allocation does. Negative control: await the task's work inline in
    /// `begin_quic_turn_setup` instead of spawning it — the first assertion
    /// times out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_turn_allocation_never_holds_the_loop() {
        let (reap_tx, _reap_rx) = reap_channel();
        let (out_tx, mut out_rx) = outcome_channel();
        let mut pending = PendingQuicSetups::default();
        let a = ObjectId::new();
        let b = ObjectId::new();

        let (release_tx, release_rx) = oneshot::channel::<()>();
        let slow = move |_urls: Vec<String>, _user: String, _cred: String| async move {
            let _ = release_rx.await;
            Ok(loopback_relay().await)
        };
        let began = tokio::time::timeout(
            Duration::from_secs(1),
            begin_quic_turn_setup(&mut pending, req(a), reap_tx.clone(), out_tx.clone(), slow),
        )
        .await
        .expect("the TURN branch returned before its allocation finished (#1761)");
        assert!(matches!(began, Begin::Started { .. }));
        assert!(pending.is_pending(a));
        // A's candidate arrives while it allocates — the loop buffers it.
        assert!(pending.buffer_candidate(a, addr(5)));

        let fast = |_urls: Vec<String>, _user: String, _cred: String| async move {
            Ok(loopback_relay().await)
        };
        let began =
            begin_quic_turn_setup(&mut pending, req(b), reap_tx.clone(), out_tx.clone(), fast)
                .await;
        assert!(matches!(began, Begin::Started { .. }));

        let first = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("B's setup completes while A is still allocating")
            .expect("channel open");
        assert_eq!(first.session_id, b, "B finished first; A is parked");
        assert!(pending.is_pending(a), "A is still in flight");
        match pending.settle(first) {
            Settled::Ready { peer, candidates } => {
                assert!(candidates.is_empty());
                assert_eq!(
                    peer.addrs().len(),
                    1,
                    "a relay peer advertises its relayed address"
                );
                peer.close();
            }
            other => panic!("B is inserted: {other:?}"),
        }
        assert!(
            matches!(out_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "nothing from A before its allocation is released"
        );

        release_tx
            .send(())
            .expect("A's allocator is parked on this");
        let second = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("A lands once its allocation does")
            .expect("channel open");
        assert_eq!(second.session_id, a);
        match pending.settle(second) {
            Settled::Ready { peer, candidates } => {
                assert_eq!(
                    candidates,
                    vec![addr(5)],
                    "A's buffered candidate is applied on insert"
                );
                peer.close();
            }
            other => panic!("A is inserted: {other:?}"),
        }
        assert!(pending.is_empty());
    }

    /// The task, not the loop, is the last holder of a peer the loop can no
    /// longer receive: when the org loop is gone the report fails and the
    /// task closes the peer it built. Observed through the relay the
    /// allocator handed out — the peer's endpoint is its only other holder.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_result_the_loop_cannot_receive_is_closed_by_the_task() {
        let (reap_tx, _reap_rx) = reap_channel();
        let (out_tx, out_rx) = outcome_channel();
        drop(out_rx); // the org loop is gone
        let mut pending = PendingQuicSetups::default();
        let relay = loopback_relay().await;
        let handout = Arc::clone(&relay);
        let allocate =
            move |_urls: Vec<String>, _user: String, _cred: String| async move { Ok(handout) };
        let began = begin_quic_turn_setup(
            &mut pending,
            req(ObjectId::new()),
            reap_tx,
            out_tx,
            allocate,
        )
        .await;
        assert!(matches!(began, Begin::Started { .. }));
        for _ in 0..100 {
            if Arc::strong_count(&relay) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            Arc::strong_count(&relay),
            1,
            "the task closed and dropped the peer nobody could receive"
        );
    }

    /// The candidate parse keeps every well-formed address and skips the
    /// rest, as the arm always did.
    #[test]
    fn candidate_parse_skips_the_unparseable() {
        let sid = ObjectId::new();
        let parsed = parse_candidate_addrs(
            sid,
            &[
                "203.0.113.7:3478".to_string(),
                "not-an-addr".to_string(),
                "[2001:db8::1]:443".to_string(),
            ],
        );
        assert_eq!(
            parsed,
            vec![
                addr(3478),
                "[2001:db8::1]:443".parse::<SocketAddr>().unwrap()
            ]
        );
    }
}
