// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Tunnel-client **session driver** — the reusable engine behind the CLI's
//! `forward`/`socks5`/`mesh` and (P3b-2) the daemon's outbound tunnels.
//!
//! P3b-1 landed the shared **flow vocabulary** here — the per-flow
//! reply-correlation types + the open-timeout. P3b-1b folds in the session
//! orchestration itself (moved from `roomler::forward`) behind the
//! [`crate::signaling_link`] seam: [`run_tunnel_session`] speaks the
//! `rc:tunnel.*` control protocol over a cloneable
//! [`TunnelSignalingSink`](crate::signaling_link::TunnelSignalingSink) + a
//! single-consumer
//! [`TunnelSignalingSource`](crate::signaling_link::TunnelSignalingSource)
//! instead of owning a WebSocket, so the SAME engine serves the CLI (WS-backed)
//! and — at P3b-2 — the `roomlerd` daemon (agent-WS-multiplexer-backed).
//!
//! FR-86 P1 split a session into **establishment** and **carrying**:
//! [`establish_tunnel_session`] does the hello/open, the transport handshake
//! and brings the data plane to ready — everything a session used to do up to
//! (not including) binding its loopback listener — and returns a [`Carrier`],
//! which runs the per-connection code the session's accept loop used to run.
//! Who owns the port is the caller's choice: [`run_tunnel_session`] (the
//! standalone CLI) binds one per session as before; the daemon's flow binds
//! once for its whole life ([`crate::flow_listener`]) and installs each
//! carrier behind it, so a reconnect no longer refuses connections and — the
//! reason for the split — a second carrier can be established beside the
//! first (P2's make-before-break re-upgrade).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bson::oid::ObjectId;
use roomler_ai_remote_control::signaling::{
    ClientMsg, CloseReason, Direction, IceServer, REJECT_REASON_NO_SESSION,
    REJECT_REASON_SESSION_GONE, REJECT_REASON_SESSION_MISMATCH, RejectKind, ServerMsg, TunnelRole,
};
use roomler_ai_remote_control::vault::NET_GRANT_REFUSED;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, oneshot, watch};
use tracing::{debug, error, info, warn};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;

use crate::flow_listener::Carry;
use crate::forward::{
    FlowCancel, FlowCanceller, FlowDemux, FlowPoolRegistration, HalfCloseSink, SessionThroughput,
    run_flow, run_flow_quic,
};
use crate::signaling_link::{TunnelSignalingSink, TunnelSignalingSource};
use crate::transport::quic::{self, QuicConnection, QuicPeer};
use crate::transport::relay;
use crate::transport::webrtc_dc::TunnelPeer;
use crate::transport::{TRANSPORT_QUIC_DERP_V1, TRANSPORT_QUIC_V1, TRANSPORT_WEBRTC_DC_V1};

/// A `JoinHandle` that aborts its task when dropped.
///
/// **Dropping a bare `JoinHandle` DETACHES the task — it keeps running.** That
/// is the trap this type exists to close. The session drivers below spawn a
/// dispatcher that holds `Arc<TunnelPeer>` and a `sink` clone; the explicit
/// `abort()` at the end of each driver (the "F1" fix) covers the *normal* exit,
/// but every `?` between the spawn and that line returned without it, leaving
/// a detached task pinning the peer — and therefore its ICE agent's UDP
/// sockets, the WS and the TURN allocation — for the life of the process.
///
/// Field 2026-08-22 (devbox): failing flows take exactly those early returns, so
/// `roomlerd` accumulated **15,446 UDP sockets in 12 h**, exhausted the host's
/// 16,384-port ephemeral range, and every process on the machine lost DNS with
/// `WSAENOBUFS`. The bug was not the missing abort *call* — one was already
/// there and correct — it was that the rule lived in a call site instead of in
/// the type. Wrapping the handle makes "aborted on every path" structural.
///
/// `pub(crate)` since FR-86 P1: the flow listener's accept task
/// (`crate::flow_listener`) must die with the listener for the same reason.
pub(crate) struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> AbortOnDrop<T> {
    pub(crate) fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(handle)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> std::ops::Deref for AbortOnDrop<T> {
    type Target = tokio::task::JoinHandle<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for AbortOnDrop<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Tells the server (and through it the exit agent) that a tunnel session is
/// over, the moment the session driver stops owning it — **including when the
/// owning task is aborted**.
///
/// **The exit agent keeps its per-session `AgentTunnelPeer` — the ICE sockets
/// plus the DataChannel pool (WebRTC) or the quinn endpoint (QUIC) — until it is
/// told to drop it.** The only thing that tells it is a `rc:tunnel.terminate`
/// the *client* sends: the server relays it on to the agent
/// (`network::tunnel::relay_tunnel_client_msg_from_agent`), and no idle timeout
/// reaps it otherwise.
///
/// Before this guard, every client path that ended a session *without* sending
/// one leaked that agent-side peer: `kill_flow` aborted the supervisor task, and
/// every `?` early return after `rc:tunnel.opened` (the 30 s `PEER_READY_TIMEOUT`
/// toward a target whose DC pool never opens, a failed local bind, an
/// `accept_answer` error, a QUIC-setup soft-fall) returned without a word to the
/// far side. Field-measured on `0.4.110` (#1754): a macOS root exit agent's UDP
/// socket count climbed 5 → 11 → 16 across five kills of one WebRTC forward, and
/// a declared route whose target never comes up left one agent-side peer *per
/// retry*, every 1–30 s, unbounded.
///
/// This is [`AbortOnDrop`]'s lesson one layer up: the rule ("tell the far side
/// on every exit path") belongs in a type, not in each call site that kept
/// forgetting it. `Drop` cannot await, so it spawns the send — and because the
/// spawned task is independent of the one being torn down, it still delivers
/// even when this guard drops *because* its task was aborted. Outside a runtime
/// (process teardown) there is nothing to reap that will not die with us anyway.
///
/// Duplicates are harmless by construction: the server's terminate handling is
/// idempotent (`sessions.remove` is a no-op for an already-reaped session, and
/// an unknown session's terminate is dropped), so a path that also sends its own
/// terminate — the `session_dead` backstop, the dispatch loop's session-gone /
/// server-terminate / revoked arms, or `kill_flow`'s synchronous fast path —
/// only ever costs one extra, absorbed frame.
struct TerminateOnDrop {
    sink: Arc<dyn TunnelSignalingSink>,
    session_id: ObjectId,
    fired: std::sync::atomic::AtomicBool,
}

impl TerminateOnDrop {
    fn new(sink: Arc<dyn TunnelSignalingSink>, session_id: ObjectId) -> Self {
        Self {
            sink,
            session_id,
            fired: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Mark the terminate as already handled so `Drop` stays silent — for a path
    /// that has itself sent (or deliberately suppressed) the terminate. Kept
    /// `cfg(test)` because the live drivers accept the harmless duplicate rather
    /// than thread this through the spawned dispatch tasks; without the gate it
    /// would be dead code under `-D warnings` in normal builds.
    #[cfg(test)]
    fn disarm(&self) {
        self.fired.store(true, Ordering::SeqCst);
    }
}

impl Drop for TerminateOnDrop {
    fn drop(&mut self) {
        if self.fired.swap(true, Ordering::SeqCst) {
            return;
        }
        let sink = Arc::clone(&self.sink);
        let session_id = self.session_id;
        // Drop can't await; spawn the send. `try_current()` succeeds even when
        // this runs because the owning task is being ABORTED — the spawned task
        // is independent of the aborted one, so it still delivers.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = sink
                    .send(ClientMsg::TunnelTerminate {
                        session_id,
                        reason: CloseReason::ClientShutdown,
                    })
                    .await
                {
                    debug!(%session_id, %e, "terminate-on-drop: link already gone");
                }
            });
        } else {
            debug!(%session_id, "terminate-on-drop: no runtime to spawn on; skipping");
        }
    }
}

/// Per-flow open round-trip cap: `TcpForwardRequest` / `UdpForwardRequest` →
/// `Accept` / `Reject`. Server-side ACL eval is local, but the request rides the
/// agent's dial timeout in the relay case. Shared by the TCP session driver and
/// the UDP relay (`crate::udp`).
pub const FLOW_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// True when a forward reject is the agent's canonical "I don't know this
/// session" signal (see [`REJECT_REASON_SESSION_GONE`]): the agent lost its
/// per-connection tunnel state (its WS reconnected after a network flap), so
/// this session can never carry another flow — every future forward would
/// get the same reject. The dispatch loops treat it as session death so the
/// flow supervisor re-opens with fresh state instead of failing every local
/// connection forever. Substring match so a wrapped/prefixed reason from an
/// older or newer agent still qualifies.
fn is_session_gone_reject(kind: RejectKind, reason: &str) -> bool {
    // All three reasons are `AgentError` session-death signals: the agent
    // forgot the session ([`REJECT_REASON_SESSION_GONE`]), or the SERVER holds
    // no session / a different one for this connection
    // ([`REJECT_REASON_NO_SESSION`] / [`REJECT_REASON_SESSION_MISMATCH`] —
    // field 2026-07-25: a forward route zombied at rc.223 precisely because
    // these two server reasons weren't matched, so the session never ended
    // and the supervisor never re-opened). `contains` so a wrapped/prefixed
    // reason from another hop still qualifies.
    kind == RejectKind::AgentError
        && (reason.contains(REJECT_REASON_SESSION_GONE)
            || reason.contains(REJECT_REASON_NO_SESSION)
            || reason.contains(REJECT_REASON_SESSION_MISMATCH))
}

/// After this many **TCP** forward-open timeouts on one session with NO reply
/// of any kind (accept or reject) in between, the session is presumed wedged:
/// the far side silently stopped answering (a lost-reply relay, or an agent
/// that forgot us without even sending a reject). End the session so the flow
/// supervisor re-opens. This is the backstop for the silent variant that
/// [`is_session_gone_reject`] (a *reply*-driven signal) can't see.
///
/// Semantics + limits, precisely (a reply of any kind resets the streak):
/// - Isolated timeouts *interleaved with* successful replies never accumulate
///   — a live route can't trip it.
/// - A genuine ≥`FLOW_OPEN_TIMEOUT` control-plane brownout with ≥N *parallel*
///   opens can trip it in one round; that's correct — the control plane was
///   provably dead for that window — and the cost is one ~1 s re-open.
/// - UDP-ASSOCIATE opens (`crate::udp`) are NOT counted; a purely-UDP silent
///   wedge isn't covered here (its amnesia *rejects* still self-heal via the
///   dispatch loop). TCP is the observed/motivating case.
const MAX_CONSECUTIVE_FLOW_TIMEOUTS: u32 = 3;

/// Record one forward-open timeout; returns true once the consecutive count
/// reaches [`MAX_CONSECUTIVE_FLOW_TIMEOUTS`] (⇒ end the session).
fn record_flow_timeout(streak: &std::sync::atomic::AtomicU32) -> bool {
    streak.fetch_add(1, Ordering::Relaxed) + 1 >= MAX_CONSECUTIVE_FLOW_TIMEOUTS
}

/// Reset the consecutive-timeout streak — called when a forward reply of ANY
/// kind arrives (accept OR reject), which proves the control plane still
/// round-trips end to end, so the wedge this backstop targets (total silence)
/// isn't happening.
fn record_flow_progress(streak: &std::sync::atomic::AtomicU32) {
    streak.store(0, Ordering::Relaxed);
}

/// Reply registry: per-flow oneshot for the server's accept/reject. Shared
/// across the TCP session driver and the UDP relay so flow-ids stay a single
/// correlation space across TCP + UDP within a session.
pub type ReplyRegistry = Arc<Mutex<HashMap<u32, oneshot::Sender<ForwardReply>>>>;

/// Active-flow registry: which DC index a given flow is bound to, so the WS
/// dispatch can route inbound `TcpHalfClose` audit signals (no demux action —
/// the in-band marker handles the data-plane close).
pub type ActiveFlows = Arc<Mutex<HashMap<u32, u8>>>;

/// The server's per-flow decision, delivered to the waiting opener via the
/// [`ReplyRegistry`] oneshot.
#[derive(Debug)]
pub enum ForwardReply {
    Accept { dc_index: u8 },
    Reject { kind: RejectKind, reason: String },
}

/// Cap on how long we wait for `rc:tunnel.opened` after sending
/// `rc:tunnel.open`. Round-trip + server-side cross-tenant gate.
const TUNNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on the SDP / ICE / DC-pool handshake. Includes ICE gathering
/// plus relay candidate establishment which can take a few seconds
/// on TURN paths.
const PEER_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on waiting for `rc:tunnel.quic.ready` after `rc:tunnel.opened`
/// negotiated `quic-v1`. The agent may walk several TURN-relay candidates
/// before replying — on a corp net that blocks UDP, a UDP attempt
/// (`:3478`, ~5 s) then a TURNS/TCP allocate (`:443`) — so this must cover
/// the agent's full tier walk, not just one RTT. 30 s comfortably bounds
/// 1–2 UDP timeouts + a TLS allocate. On timeout the client abandons QUIC
/// and (for `--transport auto`) re-opens over WebRTC.
const QUIC_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Phase 3d: head start we give the agent's TURN-permission install (it
/// fires when our `rc:tunnel.quic.candidate` reaches the agent over WS)
/// before we send the first QUIC Initial over the relay. QUIC's Initial
/// retransmission covers any remaining race, so this is just a latency
/// optimisation to avoid the first-packet drop + retransmit wait.
const QUIC_PERMIT_SETTLE: Duration = Duration::from_millis(300);

/// Operator's transport preference. Drives which transports the client
/// advertises in `rc:tunnel.hello` and which it requests in
/// `rc:tunnel.open`; the server is authoritative for the final pick. The CLI
/// wraps this in a `clap::ValueEnum` shim (`main.rs::CliTransport`) so the
/// driver stays clap-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPref {
    /// Prefer QUIC; transparently fall back to WebRTC if QUIC setup
    /// fails. The default: server-side QUIC negotiation (Phase 1c) is
    /// deployed and gates on the agent's reported version, so QUIC is
    /// only attempted against agents that actually speak it — no wasted
    /// setup round-trip against an older agent.
    #[default]
    Auto,
    /// Force QUIC; error out if it can't be established (no fallback).
    Quic,
    /// Force the proven WebRTC SCTP DataChannel transport (the pre-QUIC
    /// default; still the right pick for a forced, no-fallback run).
    Webrtc,
}

impl TransportPref {
    /// Transports advertised in `rc:tunnel.hello`, in preference order.
    pub fn supported_transports(self) -> Vec<String> {
        match self {
            TransportPref::Auto => vec![
                TRANSPORT_QUIC_V1.to_string(),
                TRANSPORT_WEBRTC_DC_V1.to_string(),
            ],
            TransportPref::Quic => vec![TRANSPORT_QUIC_V1.to_string()],
            TransportPref::Webrtc => vec![TRANSPORT_WEBRTC_DC_V1.to_string()],
        }
    }

    /// The single transport requested in `rc:tunnel.open`.
    pub fn request_transport(self) -> &'static str {
        match self {
            TransportPref::Auto | TransportPref::Quic => TRANSPORT_QUIC_V1,
            TransportPref::Webrtc => TRANSPORT_WEBRTC_DC_V1,
        }
    }
}

/// Outcome of one [`run_tunnel_session`] attempt, so the caller can decide
/// whether to fall back to WebRTC.
pub enum SessionOutcome {
    /// The session ran its data plane (listener loop entered).
    Completed,
    /// A QUIC session couldn't be established during setup; the caller
    /// may re-open over WebRTC.
    QuicSetupFailed,
}

/// Outcome of one [`establish_tunnel_session`] attempt — [`SessionOutcome`]'s
/// shape, one step earlier: the session is up and ready to carry, or QUIC
/// setup soft-failed and the caller may re-open over WebRTC. Every other
/// failure is an `Err`, exactly as before the split.
pub enum Establishment {
    /// The data plane is ready; connections can be carried. Boxed: a
    /// `Carrier` is a few hundred bytes next to the unit variant (clippy
    /// `large_enum_variant`), and it is built once per attempt.
    Established(Box<Carrier>),
    /// A QUIC flavor couldn't be established during setup. The session it
    /// opened is already over (its terminate went out with the guard).
    QuicSetupFailed,
}

/// What each accepted local connection forwards to.
#[derive(Debug, Clone)]
pub enum Target {
    /// Static `--remote host:port` (the `forward` command) — every local
    /// connection dials the same destination.
    Static { host: String, port: u16 },
    /// Per-connection SOCKS5 CONNECT target (the `socks5` command) — the local
    /// port is a SOCKS5 proxy and each connection names its own destination.
    /// This is the tunnel's userspace mode: no OS routing, so it works on strict
    /// full-tunnel corp VPNs that capture the L3 overlay's routes.
    Socks5,
    /// FR-90 P3-7-3b — an agent session's SOCKS5 listener: RFC 1929 with this
    /// credential alone, and CONNECT alone
    /// ([`crate::socks5::accept_connect_authenticated`]).
    SessionSocks5(crate::socks5::Socks5Credential),
}

/// #1685 — called by [`run_tunnel_session`] the moment the session's local
/// listener is bound, with the address it serves on. That bind is the ONLY
/// point at which "this route is active" becomes true: `rc:tunnel.opened` is
/// the server accepting the open, and the QUIC / DC-pool setup after it can
/// still fail — toward an offline node it does, every cycle. The standalone
/// CLI passes `None`. Since FR-86 P1 the daemon binds its own listener
/// (`crate::flow_listener`) and flips its liveness itself when a carrier is
/// installed behind it, so it passes `None` too; [`establish_tunnel_session`]
/// binds nothing and never calls this.
pub type ListeningHook = Arc<dyn Fn(std::net::SocketAddr) + Send + Sync>;

/// Everything the caller must supply to identify + version a tunnel session,
/// beyond the signaling seam + local port. Bundled so the driver's public
/// entry point stays a manageable arity and so the daemon (P3b-2) can build it
/// once per outbound tunnel.
pub struct SessionParams {
    /// Hex `agent_id` of the target agent (already parsed).
    pub agent_id: ObjectId,
    /// What each accepted local connection dials.
    pub target: Target,
    /// This client's version string, advertised in `rc:tunnel.hello`. The CLI
    /// passes its `CARGO_PKG_VERSION`; the daemon its own.
    pub client_version: String,
    /// R4 — the node's DERP mux + identity for the `quic-derp-v1` flavor.
    /// `Some` only in the daemon (an overlay node with an established `/derp`
    /// WS); the standalone CLI passes `None` and keeps the classic ladder.
    pub derp: Option<crate::transport::derp::DerpTunnelHandle>,
    /// #1685 — told when [`run_tunnel_session`]'s local listener is bound (see
    /// [`ListeningHook`]). `None` when the caller has no liveness state to
    /// publish, or owns the listener itself (the daemon, FR-86 P1).
    pub on_listening: Option<ListeningHook>,
    /// FR-90 P3-7-3a — an agent session's grant ([`SessionGrantRef`]): the
    /// tunnel carries the session's flows, or none. `None` for a person's or
    /// a device's own tunnel.
    pub net_grant: Option<SessionGrantRef>,
}

/// Bind the session's loopback listener and, once it is bound, tell the owner
/// (#1685). The hook fires only on success: a failed bind is an error the
/// caller propagates, never a serving route.
async fn bind_local_listener(
    local: u16,
    on_listening: Option<&ListeningHook>,
) -> Result<TcpListener> {
    let listener = TcpListener::bind(("127.0.0.1", local))
        .await
        .with_context(|| format!("binding 127.0.0.1:{local}"))?;
    if let Some(hook) = on_listening {
        hook(listener.local_addr()?);
    }
    Ok(listener)
}

/// FR-86 P1 — an established tunnel session as a **connection carrier**: the
/// data plane is up (the DC pool open, or the QUIC connection authenticated),
/// the dispatcher task runs, the keepalive is armed and the #1754 terminate
/// guard is held. It carries local TCP connections through the session
/// exactly as the session's own accept loop did; who accepts them — a
/// per-session listener ([`run_tunnel_session`]) or the flow's
/// ([`crate::flow_listener::FlowListener`]) — is the caller's business.
///
/// One type for both transports rather than a trait with two impls: a carrier
/// is the same object either way — sink, session id, target, reply registry,
/// the P7 backstop, the dispatcher, the guard — and only the plane it pumps
/// bytes on differs ([`Plane`]). The per-connection code keeps its two
/// transport-specific bodies inside [`Carrier::carry`], verbatim, and the
/// listener side needs one method of it ([`Carry`]), which is what lets the
/// flow listener be tested with a fake.
///
/// **Dropping the carrier ends the session** the way the end of the session
/// function used to: the dispatcher is aborted (it holds the peer and a sink
/// clone), the plane drops (the last `TunnelPeer` reference spawns `close()`;
/// the last QUIC connection reference closes it), and the terminate guard
/// tells the exit. Connections already in flight keep pumping on the old plane
/// until it dies, as before.
pub struct Carrier {
    transport: &'static str,
    session_id: ObjectId,
    sink: Arc<dyn TunnelSignalingSink>,
    target: Target,
    session: Arc<SessionThroughput>,
    reply_registry: ReplyRegistry,
    active_flows: ActiveFlows,
    flow_counter: Arc<AtomicU32>,
    /// P7 backstop — shared across this session's connections: reset on any
    /// reply, incremented on a timeout; `session_dead` fires when it trips.
    flow_timeout_streak: Arc<AtomicU32>,
    session_dead: Arc<Notify>,
    /// Connections in flight on this carrier ([`Carrier::active`]).
    in_flight: Arc<AtomicU64>,
    /// FR-86 P2 — notified when [`in_flight`](Self::in_flight) falls to 0, so a
    /// draining carrier can be closed the instant its last connection ends
    /// without a tight poll ([`Carrier::drained`]). `notify_waiters` (not
    /// `notify_one`): it wakes only current waiters and stores no permit, so
    /// `drained` arms the wait BEFORE it re-reads the count.
    idle: Arc<Notify>,
    /// Closed (its sender dropped) when the dispatcher task ends — by
    /// returning or by being aborted — which is how [`Carrier::dead`] sees
    /// "the control channel is gone" through a shared reference.
    dispatcher_done: watch::Receiver<()>,
    // Declaration order is drop order: abort the dispatcher first (it holds a
    // peer clone and a sink clone), then the plane (the last peer reference
    // spawns the close), then tell the exit.
    _dispatcher: AbortOnDrop<()>,
    plane: Plane,
    _terminate: TerminateOnDrop,
}

/// #2129 — the client-side trigger: ends a DC carrier's live flows when the
/// carrier is dropped. Wraps the session's [`FlowCanceller`] and fires it from
/// [`Drop`], so every way a carrier stops owning its session — `kill_flow`
/// aborting the flow task, the session dying, a re-upgrade drain reaching
/// zero, [`run_tunnel_session`] returning — ends the live flows with it. The
/// exit side triggers the same cancel explicitly from `AgentTunnelPeer::close`
/// instead; this type exists because the client has no equivalent method — the
/// carrier is simply dropped.
struct CancelOnDrop(FlowCanceller);

impl CancelOnDrop {
    fn new() -> Self {
        Self(FlowCanceller::new())
    }

    /// A per-flow handle onto the canceller.
    fn handle(&self) -> FlowCancel {
        self.0.handle()
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// The data plane a [`Carrier`] pumps bytes on.
enum Plane {
    /// `webrtc-dc-v1`: the DC pool, one [`FlowDemux`] per channel, flows
    /// spread round-robin.
    Dc {
        /// Kept so the peer lives exactly as long as the carrier.
        _peer: Arc<TunnelPeer>,
        demuxes: Arc<Vec<FlowDemux>>,
        rr_counter: Arc<AtomicUsize>,
        /// #2129 — cancels this carrier's live DC flows when the carrier is
        /// dropped (a kill, the session dying, a re-upgrade cycle's drain
        /// reaching zero, the standalone CLI's session end). Its [`Drop`]
        /// fires the cancel; an FR-86 drain drops the carrier only at 0
        /// in-flight connections, so there is nothing to cancel there.
        cancel: CancelOnDrop,
    },
    /// `quic-v1` / `quic-derp-v1`: one bidirectional stream per flow on the
    /// session's connection.
    Quic {
        conn: Arc<QuicConnection>,
        /// The endpoint — dropping it closes quinn.
        _peer: Arc<QuicPeer>,
    },
}

/// RAII count of one connection in flight on a carrier: decrements when the
/// connection's task returns OR is aborted. When the decrement brings the count
/// to 0 it wakes [`Carrier::drained`] (FR-86 P2), so a draining carrier closes
/// the instant its last connection ends.
struct InFlight {
    counter: Arc<AtomicU64>,
    idle: Arc<Notify>,
}

impl InFlight {
    fn new(counter: &Arc<AtomicU64>, idle: &Arc<Notify>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self {
            counter: Arc::clone(counter),
            idle: Arc::clone(idle),
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        // `fetch_sub` returns the PREVIOUS value, so `== 1` means this was the
        // last connection and the count is now 0.
        if self.counter.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.idle.notify_waiters();
        }
    }
}

impl Carrier {
    /// The negotiated transport this carrier runs (`quic-v1`, `quic-derp-v1`
    /// or `webrtc-dc-v1`).
    pub fn transport(&self) -> &'static str {
        self.transport
    }

    /// The server-side session id.
    pub fn session_id(&self) -> ObjectId {
        self.session_id
    }

    /// Connections currently in flight on this carrier.
    pub fn active(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// FR-86 P2 — resolves once this carrier has **no connections in flight**.
    /// A draining carrier (one the flow re-upgraded away from) is closed the
    /// moment this fires, so its established connections run to their natural
    /// end and none is ever cut. Returns at once if the carrier is already idle.
    ///
    /// Race-free against a concurrent last-connection close: the `Notified`
    /// future is armed with `enable()` BEFORE the count is re-read, so a
    /// `notify_waiters` that fires between the read and the await is not lost.
    /// Cancel-safe — nothing is consumed before it resolves, so a `select!` may
    /// drop and re-create it freely.
    pub async fn drained(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Arm the waiter first, then check: if the last connection ends now,
            // either the check sees 0 (we return) or the armed waiter catches
            // the wake (we loop and then see 0).
            notified.as_mut().enable();
            if self.active() == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Forward one accepted local connection through this session — the
    /// per-connection task the session's accept loop used to spawn, unchanged:
    /// socket tuning, SOCKS5 / static target resolution, UDP ASSOCIATE, the
    /// forward request and the pump. Never blocks the caller: the flow listener
    /// calls it under its own lock (#1816, [`crate::flow_listener::Carry`]).
    pub fn carry(&self, mut tcp: tokio::net::TcpStream, peer_addr: std::net::SocketAddr) {
        tune_local_socket(&tcp, peer_addr);
        debug!(%peer_addr, transport = self.transport, "accepted local TCP connection");

        let flow_id = self.flow_counter.fetch_add(1, Ordering::Relaxed);
        let in_flight = InFlight::new(&self.in_flight, &self.idle);
        let session_id = self.session_id;
        let reply_registry = Arc::clone(&self.reply_registry);
        let active_flows = Arc::clone(&self.active_flows);
        let sink = self.sink.clone();
        let target = self.target.clone();
        let flow_counter_for_udp = Arc::clone(&self.flow_counter);
        let session = Arc::clone(&self.session);
        let flow_timeout_streak = Arc::clone(&self.flow_timeout_streak);
        let session_dead = Arc::clone(&self.session_dead);
        match &self.plane {
            Plane::Dc {
                demuxes,
                rr_counter,
                cancel,
                ..
            } => {
                let dc_index_chosen =
                    (rr_counter.fetch_add(1, Ordering::Relaxed) % demuxes.len()) as u8;
                let demuxes = Arc::clone(demuxes);
                // #2129 — this flow observes the carrier's cancellation.
                let cancel = cancel.handle();
                tokio::spawn(async move {
                    let _in_flight = in_flight;
                    // Resolve the destination: the static `--remote`, or the
                    // per-connection SOCKS5 request (userspace mode). A SOCKS5
                    // UDP ASSOCIATE forks off the UDP relay and never uses the
                    // pre-allocated TCP flow_id.
                    let (host, port, socks) = match &target {
                        Target::Static { host, port } => (host.clone(), *port, false),
                        Target::Socks5 => match crate::socks5::accept_request(&mut tcp).await {
                            Ok(crate::socks5::Socks5Request::Connect { host, port }) => {
                                (host, port, true)
                            }
                            Ok(crate::socks5::Socks5Request::UdpAssociate) => {
                                if let Err(e) = crate::udp::handle_associate(
                                    tcp,
                                    session_id,
                                    crate::udp::AssocCarrier::Dc { demuxes },
                                    reply_registry,
                                    sink,
                                    flow_counter_for_udp,
                                    session,
                                )
                                .await
                                {
                                    warn!(%peer_addr, %e, "socks5 UDP associate ended with error");
                                }
                                return;
                            }
                            Err(e) => {
                                warn!(%peer_addr, %e, "socks5 handshake failed; dropping");
                                return;
                            }
                        },
                        // FR-90 P3-7-3b — a session's listener: its credential, CONNECT.
                        Target::SessionSocks5(cred) => {
                            match crate::socks5::accept_connect_authenticated(&mut tcp, cred).await
                            {
                                Ok((host, port)) => (host, port, true),
                                Err(e) => {
                                    warn!(%peer_addr, %e, "session socks5 handshake refused; dropping");
                                    return;
                                }
                            }
                        }
                    };
                    // Register the reply mailbox now that we're proceeding — before the
                    // request is sent, so the dispatcher can route the accept/reject.
                    let (reply_tx, reply_rx) = oneshot::channel::<ForwardReply>();
                    reply_registry.lock().await.insert(flow_id, reply_tx);
                    if let Err(e) = handle_local_connection(
                        tcp,
                        peer_addr,
                        flow_id,
                        dc_index_chosen,
                        session_id,
                        &host,
                        port,
                        sink,
                        reply_rx,
                        reply_registry,
                        active_flows,
                        demuxes,
                        socks,
                        flow_timeout_streak,
                        session_dead,
                        cancel,
                    )
                    .await
                    {
                        warn!(flow_id, %e, "flow ended with error");
                    }
                });
            }
            Plane::Quic { conn, .. } => {
                let conn = Arc::clone(conn);
                tokio::spawn(async move {
                    let _in_flight = in_flight;
                    // Resolve the destination: static `--remote`, or the per-connection
                    // SOCKS5 request (userspace mode). UDP ASSOCIATE forks off the UDP
                    // relay over this session's QUIC connection.
                    let (host, port, socks) = match &target {
                        Target::Static { host, port } => (host.clone(), *port, false),
                        Target::Socks5 => match crate::socks5::accept_request(&mut tcp).await {
                            Ok(crate::socks5::Socks5Request::Connect { host, port }) => {
                                (host, port, true)
                            }
                            Ok(crate::socks5::Socks5Request::UdpAssociate) => {
                                if let Err(e) = crate::udp::handle_associate(
                                    tcp,
                                    session_id,
                                    crate::udp::AssocCarrier::Quic { conn },
                                    reply_registry,
                                    sink,
                                    flow_counter_for_udp,
                                    session,
                                )
                                .await
                                {
                                    warn!(%peer_addr, %e, "socks5 UDP associate ended with error");
                                }
                                return;
                            }
                            Err(e) => {
                                warn!(%peer_addr, %e, "socks5 handshake failed; dropping");
                                return;
                            }
                        },
                        // FR-90 P3-7-3b — a session's listener: its credential, CONNECT.
                        Target::SessionSocks5(cred) => {
                            match crate::socks5::accept_connect_authenticated(&mut tcp, cred).await
                            {
                                Ok((host, port)) => (host, port, true),
                                Err(e) => {
                                    warn!(%peer_addr, %e, "session socks5 handshake refused; dropping");
                                    return;
                                }
                            }
                        }
                    };
                    let (reply_tx, reply_rx) = oneshot::channel::<ForwardReply>();
                    reply_registry.lock().await.insert(flow_id, reply_tx);
                    if let Err(e) = handle_local_connection_quic(
                        tcp,
                        peer_addr,
                        flow_id,
                        session_id,
                        conn,
                        &host,
                        port,
                        sink,
                        reply_rx,
                        reply_registry,
                        active_flows,
                        socks,
                        session,
                        flow_timeout_streak,
                        session_dead,
                    )
                    .await
                    {
                        warn!(flow_id, %e, "quic flow ended with error");
                    }
                });
            }
        }
    }

    /// Resolves when this carrier can carry no more — the session accept
    /// loop's own exit arms, unchanged: the dispatcher task ended (the control
    /// channel is gone, so no new flow can be requested); the P7 backstop
    /// tripped (forward opens timing out repeatedly with no reply of any kind
    /// — the far side went silent; the stale-permit re-check is kept); or the
    /// QUIC connection itself died (quinn's keepalive/idle-timeout noticed the
    /// peer is gone while the WS control plane outlived it — without this the
    /// session would keep taking connections whose flows can never open). The
    /// latter two send the `rc:tunnel.terminate { io_error }` the loops sent,
    /// a best-effort server-side reap so an old server doesn't carry a zombie
    /// entry until the WS drops. Cancel-safe: nothing is consumed before it
    /// resolves, so a `select!` may drop and re-create it freely.
    pub async fn dead(&self) {
        let mut dispatcher_done = self.dispatcher_done.clone();
        tokio::select! {
            _ = dispatcher_done.changed() => {
                warn!(transport = self.transport, "control channel closed; ending session to reconnect");
            }
            _ = self.wedged() => {
                warn!(
                    transport = self.transport,
                    "forward opens timing out repeatedly (far side silent) — ending session to re-open"
                );
                let _ = self
                    .sink
                    .send(ClientMsg::TunnelTerminate {
                        session_id: self.session_id,
                        reason: CloseReason::IoError,
                    })
                    .await;
            }
            err = self.plane_lost() => {
                warn!(%err, "QUIC connection lost; ending quic session to reconnect");
                let _ = self
                    .sink
                    .send(ClientMsg::TunnelTerminate {
                        session_id: self.session_id,
                        reason: CloseReason::IoError,
                    })
                    .await;
            }
        }
    }

    /// The P7 backstop, with its stale-permit re-check: `notify_one` may have
    /// stored a permit that a later reply's streak-reset made stale, and the
    /// `AtomicU32` is authoritative, so a stale wakeup is ignored rather than
    /// killing a now-healthy session.
    async fn wedged(&self) {
        loop {
            self.session_dead.notified().await;
            if self.flow_timeout_streak.load(Ordering::Relaxed) >= MAX_CONSECUTIVE_FLOW_TIMEOUTS {
                return;
            }
        }
    }

    /// The plane's own death signal: QUIC has one (`conn.closed()`); the DC
    /// pool has none (its death surfaces through the dispatcher — the exit's
    /// #1754 reap terminates the session — or the P7 backstop).
    async fn plane_lost(&self) -> quinn::ConnectionError {
        match &self.plane {
            Plane::Quic { conn, .. } => conn.closed().await,
            Plane::Dc { .. } => std::future::pending().await,
        }
    }
}

impl Carry for Carrier {
    fn carry(&self, tcp: tokio::net::TcpStream, peer_addr: std::net::SocketAddr) {
        Carrier::carry(self, tcp, peer_addr);
    }
}

/// Per-accepted-socket tuning, identical for both transports.
fn tune_local_socket(tcp: &tokio::net::TcpStream, peer_addr: std::net::SocketAddr) {
    // P0 throughput fix (rc.64, field-repro 2026-05-26): disable
    // Nagle on the local listener's accepted TCP socket. The agent
    // side already sets TCP_NODELAY on its outbound (corp-side)
    // dialer (see agents/roomlerd/src/tunnel/dialer.rs); the
    // asymmetry meant TDS row tokens flowing FROM the server,
    // through the DC, OUT to the local SSMS/psql/JDBC client got
    // Nagle-coalesced on this socket. Under MSSQL TDS the small
    // row tokens batch up waiting for ACKs that don't come until
    // ~40 ms later (delayed ACK + Nagle interaction), collapsing
    // sustained throughput to tens of KB/s and triggering server-
    // side ASYNC_NETWORK_IO suspensions. Setting nodelay is
    // canonical for tunnels; no downside.
    if let Err(e) = tcp.set_nodelay(true) {
        warn!(%peer_addr, %e, "set_nodelay(true) on local TCP failed");
    }
    // rc.66 throughput follow-on: bump SO_SNDBUF on the accepted
    // loopback socket from the OS default (Windows: 64 KiB-ish,
    // can be as low as 8 KiB on some kernels) to 4 MiB. Windows
    // loopback under TDS bulk-read fills the default send buffer
    // in milliseconds; once full, every `write_all` in
    // `pump_dc_to_tcp` blocks waiting for the local app to read,
    // and that backpressures all the way up the chain. A 4 MiB
    // ceiling absorbs the burst so the producer can keep pumping
    // while the consumer drains. Best-effort: Windows may cap
    // below 4 MiB silently (autotune); the actual ceiling is
    // observable via `getsockopt` if needed, but the request
    // alone is enough to lift the floor. socket2 on the raw
    // fd/socket is the portable path.
    const LOCAL_SNDBUF_BYTES: usize = 4 * 1024 * 1024;
    #[cfg(any(unix, windows))]
    {
        use socket2::SockRef;
        let sock = SockRef::from(tcp);
        if let Err(e) = sock.set_send_buffer_size(LOCAL_SNDBUF_BYTES) {
            warn!(%peer_addr, %e, "set_send_buffer_size(4MiB) on local TCP failed");
        }
    }
}

/// One session attempt over a caller-supplied signaling link: handshake, open
/// the tunnel requesting `request_transport`, then run whichever data plane the
/// server negotiated behind a listener bound **per session** on `local`.
/// Returns [`SessionOutcome::QuicSetupFailed`] (not an `Err`) when a QUIC
/// session can't be established, so the caller can fall back to WebRTC.
///
/// This is the standalone CLI's contract (`roomler forward` / `socks5`),
/// unchanged by FR-86 P1: it composes [`establish_tunnel_session`] with a
/// private accept loop that binds after the data plane is ready (so a QUIC
/// soft-fall never held the port) and runs until the carrier is [`dead`]
/// (`Carrier::dead`). The daemon binds once per flow instead and does not
/// come through here.
///
/// The caller owns the transport: `sink` funnels every outbound `ClientMsg`
/// (the CLI's `WsSink` puts them through one mpsc + one WS writer task so FIFO
/// order matches the pre-seam behaviour), and `source` yields typed
/// `ServerMsg`s (the CLI's `WsSource` absorbs the WS Ping/Close/parse layer).
///
/// [`dead`]: Carrier::dead
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_session(
    sink: Arc<dyn TunnelSignalingSink>,
    source: Box<dyn TunnelSignalingSource>,
    local: u16,
    params: SessionParams,
    supported_transports: Vec<String>,
    request_transport: &str,
    session: Arc<SessionThroughput>,
) -> Result<SessionOutcome> {
    let on_listening = params.on_listening.clone();
    let carrier = match establish_tunnel_session(
        sink,
        source,
        params,
        supported_transports,
        request_transport,
        session,
    )
    .await?
    {
        Establishment::Established(carrier) => *carrier,
        Establishment::QuicSetupFailed => return Ok(SessionOutcome::QuicSetupFailed),
    };

    // ────────────── Local TCP listener ─────────────────────────────
    // A failed bind is an `Err` with the carrier dropped on the way out —
    // the terminate guard tells the exit, exactly as the `?` did before.
    let listener = bind_local_listener(local, on_listening.as_ref()).await?;
    info!(
        local = %listener.local_addr()?,
        transport = carrier.transport(),
        "listening for local TCP connections"
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer_addr)) => carrier.carry(tcp, peer_addr),
                Err(e) => error!(%e, "accept failed"),
            },
            _ = carrier.dead() => break,
        }
    }
    // Dropping the carrier is the old end of the session function: the
    // dispatcher is aborted so it releases its `sink` clone (else the
    // standalone CLI's WS keepalive pins the old WS + peer + TURN allocation
    // open per re-open, F1), the peer closes, the exit is told.
    drop(carrier);
    Ok(SessionOutcome::Completed)
}

/// FR-86 P1 — one session attempt up to **ready to carry**: the hello/open
/// handshake, then whichever data plane the server negotiated brought up to
/// the point where connections can be forwarded — the DC pool open with its
/// demuxes and keepalive, or the QUIC connection authenticated — with the
/// dispatcher task running and the #1754 terminate guard armed. Everything a
/// session did before binding its listener, and nothing after: the returned
/// [`Carrier`] takes the connections, whoever accepts them.
///
/// Returns [`Establishment::QuicSetupFailed`] (not an `Err`) when a QUIC
/// flavor can't be established, so the caller can re-open over WebRTC — the
/// soft-fall [`run_tunnel_session`] always had. Every `?` after
/// `rc:tunnel.opened` drops the guard on the way out, so the exit is told.
pub async fn establish_tunnel_session(
    sink: Arc<dyn TunnelSignalingSink>,
    mut source: Box<dyn TunnelSignalingSource>,
    params: SessionParams,
    supported_transports: Vec<String>,
    request_transport: &str,
    session: Arc<SessionThroughput>,
) -> Result<Establishment> {
    // P3b-3: zero the per-session `active_flows` gauge at the start of each
    // attempt so a prior session's leaked count (unclean WS teardown) can't
    // carry over. Cumulative `bytes_*` are untouched — they accumulate for
    // the whole forward's life across reconnects.
    session.reset_active_flows();

    // Say hello — advertise every transport this client supports.
    sink.send(ClientMsg::TunnelHello {
        role: TunnelRole::Client,
        version: params.client_version.clone(),
        supported_transports,
    })
    .await
    .context("send TunnelHello")?;

    // Open the tunnel requesting our preferred transport; the server is
    // authoritative and echoes the negotiated one in `TunnelOpened`.
    sink.send(ClientMsg::TunnelOpen {
        agent_id: params.agent_id,
        transport: request_transport.to_string(),
        // Single in-flight open per driver invocation, so the reply is
        // matched positionally and no nonce is needed. The daemon that
        // multiplexes many opens over one agent WS stamps a real nonce
        // (P3b-2 PR-C) and demuxes the reply by it.
        open_nonce: None,
        // R4 — our DERP identity, so the server can hand it to the agent
        // when the derp flavor is negotiated. Harmless on other flavors.
        derp_pubkey: params.derp.as_ref().map(|d| d.self_pubkey_hex.clone()),
        // FR-90 P3-7-3a — a session's grant, when this tunnel is a session's;
        // none for a person's or a device's own.
        net_grant: params.net_grant.as_ref().map(|g| g.token.clone()),
    })
    .await
    .context("send TunnelOpen")?;

    // ────────────── Wait for `rc:tunnel.opened` ────────────────────
    let opened = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, async {
        loop {
            let parsed = source
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("WS closed before rc:tunnel.opened"))?;
            match parsed {
                ServerMsg::TunnelOpened {
                    session_id,
                    transport,
                    dc_pool_size,
                    sctp_rwnd_bytes,
                    ice_servers,
                    quic_auth_token,
                    // The daemon's shared-WS demux already consumed the
                    // nonce to route this frame here; the single-session
                    // driver doesn't need it.
                    open_nonce: _,
                    net_grant_id,
                } => {
                    info!(
                        %session_id, %transport, dc_pool_size, sctp_rwnd_bytes,
                        ice_servers = ice_servers.len(),
                        quic = quic_auth_token.is_some(),
                        grant = ?net_grant_id,
                        "rc:tunnel.opened"
                    );
                    break anyhow::Ok((
                        session_id,
                        transport,
                        ice_servers,
                        quic_auth_token,
                        net_grant_id,
                    ));
                }
                ServerMsg::TunnelRevoked { reason } => {
                    bail!("tunnel revoked by server during open: {reason}");
                }
                ServerMsg::Error {
                    session_id: _,
                    code,
                    message,
                    open_nonce: _,
                } => {
                    // FR-90 P3-7-3a — the session's grant does not hold: the
                    // end of that grant, never a reason to open again.
                    if params.net_grant.is_some() && code == NET_GRANT_REFUSED {
                        return Err(GrantError::Refused(message).into());
                    }
                    bail!("server error during tunnel.open: {code}: {message}");
                }
                other => debug!(?other, "ignoring pre-opened ServerMsg"),
            }
        }
    })
    .await
    .context("waiting for rc:tunnel.opened")??;
    let (session_id, negotiated_transport, ice_servers, quic_auth_token, net_grant_id) = opened;

    // #1754 — from here we hold a server-side session id, and the exit agent
    // builds its per-session `AgentTunnelPeer` as soon as it sees our offer /
    // QUIC setup. It frees that peer ONLY when told, so EVERY way the session
    // can now end — an early `?` (`PEER_READY_TIMEOUT`, an `accept_answer`
    // error), a `QuicSetupFailed` soft-fall before the WebRTC re-open, the
    // carrier being dropped by its owner (the end of `run_tunnel_session`, the
    // flow supervisor ending a dead session), or the whole future being
    // ABORTED by `kill_flow` — must tell the server so it relays
    // `rc:tunnel.terminate` on to the agent. The guard makes that structural;
    // its `Drop` survives the abort by spawning the send. It moves INTO the
    // carrier on success (FR-86 P1), so the carrier's drop is the session's end.
    let terminate_guard = TerminateOnDrop::new(sink.clone(), session_id);

    // FR-90 P3-7-3a — a session's tunnel carries its flows only where the
    // server bound its grant: a server from before P3-7-2a ignores the grant
    // and opens the tunnel as the device's own. Checked after the guard, so
    // the exit is told as the session ends here.
    if let Some(g) = &params.net_grant
        && net_grant_id.as_deref() != Some(g.grant_id.as_str())
    {
        warn!(
            %session_id, grant = %g.grant_id, echoed = ?net_grant_id,
            "tunnel opened without the session's grant bound; ending it"
        );
        return Err(GrantError::NotBound.into());
    }

    // ────────────── Dispatch on the negotiated transport ───────────
    if negotiated_transport == TRANSPORT_QUIC_DERP_V1 {
        let Some(derp) = params.derp.clone() else {
            // The server can only negotiate this flavor when WE requested +
            // advertised it, so a missing handle here is a caller bug — but
            // soft-fail like every other QUIC setup problem so the session
            // re-opens over webrtc-dc instead of erroring the supervisor.
            warn!("server negotiated quic-derp-v1 but this client has no derp handle");
            return Ok(Establishment::QuicSetupFailed);
        };
        return establish_quic(
            source,
            sink,
            session_id,
            quic_auth_token,
            ice_servers,
            params.target,
            session,
            Some(derp),
            terminate_guard,
        )
        .await;
    }
    if negotiated_transport == TRANSPORT_QUIC_V1 {
        return establish_quic(
            source,
            sink,
            session_id,
            quic_auth_token,
            ice_servers,
            params.target,
            session,
            None,
            terminate_guard,
        )
        .await;
    }
    let carrier = establish_webrtc(
        source,
        sink,
        session_id,
        ice_servers,
        params.target,
        session,
        terminate_guard,
    )
    .await?;
    Ok(Establishment::Established(Box::new(carrier)))
}

/// The proven WebRTC SCTP DataChannel data plane (`webrtc-dc-v1`):
/// build the peer, run the SDP/ICE handshake, open the DC pool and install
/// its demuxes + keepalive, then hand back a [`Carrier`] that serves local
/// TCP connections over round-robin flows.
async fn establish_webrtc(
    source: Box<dyn TunnelSignalingSource>,
    sink: Arc<dyn TunnelSignalingSink>,
    session_id: ObjectId,
    ice_servers: Vec<IceServer>,
    target: Target,
    session: Arc<SessionThroughput>,
    terminate: TerminateOnDrop,
) -> Result<Carrier> {
    // ────────────── Build TunnelPeer + SDP/ICE handshake ───────────
    let rtc_ice_servers: Vec<RTCIceServer> = ice_servers
        .into_iter()
        .map(|ice| RTCIceServer {
            urls: ice.urls,
            username: ice.username.unwrap_or_default(),
            credential: ice.credential.unwrap_or_default(),
        })
        .collect();

    let peer = TunnelPeer::new(rtc_ice_servers)
        .await
        .context("constructing TunnelPeer")?;

    // Trickle ICE upstream.
    {
        let outbound = sink.clone();
        peer.on_local_ice_candidate(move |c| {
            let outbound = outbound.clone();
            Box::pin(async move {
                let Some(c) = c else {
                    debug!("ICE gathering complete (local)");
                    return;
                };
                let init = match c.to_json() {
                    Ok(i) => i,
                    Err(e) => {
                        warn!(%e, "local candidate to_json failed");
                        return;
                    }
                };
                let candidate = match serde_json::to_value(&init) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(%e, "local candidate serialise failed");
                        return;
                    }
                };
                if let Err(e) = outbound
                    .send(ClientMsg::TunnelIce {
                        session_id,
                        candidate,
                    })
                    .await
                {
                    warn!(%e, "ICE trickle send failed");
                }
            })
        });
    }

    let offer = peer.create_offer().await.context("create_offer")?;
    sink.send(ClientMsg::TunnelSdpOffer {
        session_id,
        sdp: offer.sdp.clone(),
    })
    .await
    .context("send TunnelSdpOffer")?;

    // Spawn the WS dispatcher. It handles every inbound ServerMsg
    // from this point on (SdpAnswer, Ice, TcpForwardAccept/Reject,
    // TcpHalfClose audit, TcpClosed audit, TunnelTerminate,
    // TunnelRevoked).
    let reply_registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
    let active_flows: ActiveFlows = Arc::new(Mutex::new(HashMap::new()));
    let peer_for_dispatch = Arc::new(peer);
    let pool_ready = Arc::new(tokio::sync::Notify::new());

    let (dispatcher_done_tx, dispatcher_done) = watch::channel(());
    let dispatcher_task = AbortOnDrop({
        let peer = Arc::clone(&peer_for_dispatch);
        let reply_registry = Arc::clone(&reply_registry);
        let active_flows = Arc::clone(&active_flows);
        let pool_ready = Arc::clone(&pool_ready);
        let sink = sink.clone();
        tokio::spawn(async move {
            // Held for the task's life: dropped when the loop returns OR the
            // task is aborted, which closes `dispatcher_done` for
            // `Carrier::dead`.
            let _done = dispatcher_done_tx;
            dispatch_loop(
                source,
                &peer,
                session_id,
                reply_registry,
                active_flows,
                pool_ready,
                sink,
            )
            .await
        })
    });

    // ────────────── Wait for pool open ─────────────────────────────
    tokio::time::timeout(PEER_READY_TIMEOUT, peer_for_dispatch.wait_pool_open())
        .await
        .context("waiting for DC pool to open")?
        .context("DC pool open failed")?;
    info!(
        "DC pool fully open ({} channels)",
        peer_for_dispatch.pool_size()
    );
    pool_ready.notify_waiters();

    // Install one FlowDemux per DC. Hold them in a Vec so the local
    // TCP listener can borrow by dc_index.
    let mut demuxes: Vec<FlowDemux> = Vec::with_capacity(peer_for_dispatch.pool_size() as usize);
    for idx in 0..peer_for_dispatch.pool_size() {
        let dc = peer_for_dispatch
            .dc(idx)
            .with_context(|| format!("dc({idx}) returned None after pool_open"))?;
        // All DCs in this session feed the same per-forward throughput
        // aggregate (P3b-3) — every registered flow stamps it onto its stats.
        demuxes.push(FlowDemux::install(dc, Some(session.clone())).await);
    }
    let demuxes = Arc::new(demuxes);

    // Idle keepalive: webrtc-dc has no built-in keepalive (QUIC does), so
    // without periodic traffic an idle tunnel's TURN-relay permission /
    // NAT mapping lapses (~5 min) and the DTLS/SCTP association dies. Send
    // a tiny frame over dc(0); the agent mirrors it. Detached — it
    // self-exits when the pool drops at session end.
    if let Some(dc0) = peer_for_dispatch.dc(0) {
        crate::forward::spawn_dc_keepalive(dc0);
    }

    // Ready to carry. The listener is the caller's (FR-86 P1): the standalone
    // CLI binds one per session in `run_tunnel_session`, the daemon's flow owns
    // one for its whole life. The dispatcher abort that used to sit at the end
    // of the accept loop (F1 — drop the `sink` clone so the standalone CLI's
    // WS keepalive can't pin the old WS + peer + TURN allocation open per
    // re-open) is the carrier's drop now, via `AbortOnDrop`.
    Ok(Carrier {
        transport: TRANSPORT_WEBRTC_DC_V1,
        session_id,
        sink,
        target,
        session,
        reply_registry,
        active_flows,
        flow_counter: Arc::new(AtomicU32::new(1)),
        // P7 backstop — see the identical block + rationale in `establish_quic`.
        flow_timeout_streak: Arc::new(AtomicU32::new(0)),
        session_dead: Arc::new(Notify::new()),
        in_flight: Arc::new(AtomicU64::new(0)),
        idle: Arc::new(Notify::new()),
        dispatcher_done,
        _dispatcher: dispatcher_task,
        plane: Plane::Dc {
            _peer: peer_for_dispatch,
            demuxes,
            rr_counter: Arc::new(AtomicUsize::new(0)),
            // #2129 — dropping this carrier ends its live DC flows.
            cancel: CancelOnDrop::new(),
        },
        _terminate: terminate,
    })
}

/// Send `TcpForwardRequest`, await accept/reject, and on accept drive
/// [`run_flow`] until it returns.
///
/// The `_dc_index_hint` is the round-robin pick from the listen loop;
/// the server is authoritative and may return a different DC index
/// in its Accept message (e.g. fairness/load-balancing across the
/// pool). The hint is currently unused but plumbed so a future
/// `rc:tunnel.tcp.request` variant can carry a preference.
#[allow(clippy::too_many_arguments)]
async fn handle_local_connection(
    mut tcp: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    flow_id: u32,
    _dc_index_hint: u8,
    session_id: ObjectId,
    dst_host: &str,
    dst_port: u16,
    sink: Arc<dyn TunnelSignalingSink>,
    reply_rx: oneshot::Receiver<ForwardReply>,
    reply_registry: ReplyRegistry,
    active_flows: ActiveFlows,
    demuxes: Arc<Vec<FlowDemux>>,
    // SOCKS5 mode — send the CONNECT reply on this stream once the agent
    // accepts/rejects the forward (userspace mode); `false` for static forwards.
    socks: bool,
    // P7 backstop — see `handle_local_connection_quic`.
    flow_timeout_streak: Arc<std::sync::atomic::AtomicU32>,
    session_dead: Arc<Notify>,
    // #2129 — the carrier's cancellation; ends this flow if the session ends
    // while it is live.
    cancel: FlowCancel,
) -> Result<()> {
    // The exit may send server-first bytes over its fast DC before the slower
    // WS Accept reaches us. Reserve this known flow BEFORE announcing it.
    let mut registration = match FlowPoolRegistration::reserve(demuxes.clone(), flow_id).await {
        Ok(r) => r,
        Err(e) => {
            reply_registry.lock().await.remove(&flow_id);
            return Err(e);
        }
    };
    // Send the request.
    let request = sink.send(ClientMsg::TcpForwardRequest {
        session_id,
        flow_id,
        dst_host: dst_host.to_string(),
        dst_port,
    });
    let sent = tokio::select! {
        biased;
        _ = cancel.cancelled() => { reply_registry.lock().await.remove(&flow_id); return Ok(()); }
        sent = request => sent,
    };
    if let Err(e) = sent {
        reply_registry.lock().await.remove(&flow_id);
        return Err(e).context("send TcpForwardRequest");
    }

    // Wait for reply.
    let outcome = tokio::select! {
        biased;
        _ = cancel.cancelled() => { reply_registry.lock().await.remove(&flow_id); return Ok(()); }
        outcome = tokio::time::timeout(FLOW_OPEN_TIMEOUT, reply_rx) => outcome,
    };
    let reply = match outcome {
        Ok(Ok(r)) => {
            record_flow_progress(&flow_timeout_streak);
            r
        }
        Ok(Err(_canceled)) => {
            reply_registry.lock().await.remove(&flow_id);
            bail!("reply oneshot dropped — dispatcher exited?");
        }
        Err(_) => {
            reply_registry.lock().await.remove(&flow_id);
            if record_flow_timeout(&flow_timeout_streak) {
                warn!(
                    flow_id,
                    streak = MAX_CONSECUTIVE_FLOW_TIMEOUTS,
                    "forward opens timed out repeatedly — signalling session death"
                );
                session_dead.notify_one();
            } else {
                warn!(flow_id, "TcpForwardRequest timed out");
            }
            bail!("forward request timed out after {FLOW_OPEN_TIMEOUT:?}");
        }
    };

    let dc_index = match reply {
        ForwardReply::Accept { dc_index } => {
            info!(flow_id, dc_index, "rc:tunnel.tcp.accept");
            dc_index
        }
        ForwardReply::Reject { kind, reason } => {
            warn!(flow_id, ?kind, %reason, "rc:tunnel.tcp.reject — dropping local conn");
            if socks {
                crate::socks5::reply(&mut tcp, crate::socks5::REP_GENERAL_FAILURE).await;
            }
            drop(tcp);
            return Ok(());
        }
    };

    // Choose the demux for the dc_index the server picked. (Round-
    // robin gave us a CHOICE; server is authoritative.)
    let Some(demux) = demuxes.get(dc_index as usize) else {
        warn!(flow_id, dc_index, "server returned out-of-range dc_index");
        close_failed_forward(&sink, session_id, flow_id).await;
        drop(tcp);
        bail!("server returned out-of-range dc_index {dc_index}");
    };
    let demux = demux.clone();

    // Preserve the SAME receiver/stats: re-registering here would drop the
    // already-buffered SSH banner. Retire only non-authoritative DC aliases.
    let (from_dc, stats) = match registration.activate(dc_index).await {
        Ok(accepted) => accepted,
        Err(error) => {
            close_failed_forward(&sink, session_id, flow_id).await;
            return Err(error).context("activate accepted DC flow");
        }
    };
    if socks {
        crate::socks5::reply(&mut tcp, crate::socks5::REP_SUCCESS).await;
    }
    active_flows.lock().await.insert(flow_id, dc_index);

    // Half-close audit callback. The in-band sentinel in the pump
    // closes the peer's mailbox; this wire message is for audit only.
    let outbound_for_audit = sink.clone();
    let on_local_eof: HalfCloseSink = Arc::new(move |fid: u32| {
        let outbound = outbound_for_audit.clone();
        // Spawn so we don't await inside a sync Fn closure.
        tokio::spawn(async move {
            let _ = outbound
                .send(ClientMsg::TcpHalfClose {
                    session_id,
                    flow_id: fid,
                    direction: Direction::SrcToDst,
                })
                .await;
        });
    });

    let dc = demux.dc();
    debug!(flow_id, dc_index, %peer_addr, "running flow");
    // Keep a handle so the close can report the flow's totals: only the
    // endpoints ever see tunnel payload (it rides the data channel), so
    // if we don't send them the audit row records zero forever.
    let stats_for_audit = Arc::clone(&stats);
    let close_reason = run_flow(tcp, dc, flow_id, from_dc, on_local_eof, stats, cancel).await;
    info!(flow_id, ?close_reason, "flow ended");

    // Audit close. TCP-side counters, not `dc_send`/`dc_recv`: those carry
    // the 4-byte frame prefix, so they wouldn't be comparable with QUIC.
    let (tcp_read, _dc_send, _dc_recv, tcp_write, _depth) = stats_for_audit.snapshot();
    let _ = sink
        .send(ClientMsg::TcpClosed {
            session_id,
            flow_id,
            reason: close_reason,
            // Named from the local app's side: `in` is what it received.
            bytes_in: tcp_write,
            bytes_out: tcp_read,
        })
        .await;

    active_flows.lock().await.remove(&flow_id);
    demux.unregister(flow_id).await;
    Ok(())
}

// An Accepted target may already own a destination socket. If local binding
// fails, close that exact flow as well as removing local aliases. A congested
// signalling sink must not turn failure cleanup into an unbounded wait.
async fn close_failed_forward(
    sink: &Arc<dyn TunnelSignalingSink>,
    session_id: ObjectId,
    flow_id: u32,
) {
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        sink.send(ClientMsg::TcpClosed {
            session_id,
            flow_id,
            reason: CloseReason::IoError,
            bytes_in: 0,
            bytes_out: 0,
        }),
    )
    .await;
}

/// WS read loop. Owns every inbound `ServerMsg` after the
/// `TunnelOpened` was consumed by [`establish_tunnel_session`]. Forwards SDP/ICE
/// into the [`TunnelPeer`], routes per-flow accept/reject into the
/// `reply_registry`, and logs the audit-side TcpHalfClose / TcpClosed.
#[allow(clippy::too_many_arguments)]
async fn dispatch_loop(
    mut source: Box<dyn TunnelSignalingSource>,
    peer: &Arc<TunnelPeer>,
    session_id: ObjectId,
    reply_registry: ReplyRegistry,
    active_flows: ActiveFlows,
    _pool_ready: Arc<tokio::sync::Notify>,
    sink: Arc<dyn TunnelSignalingSink>,
) {
    while let Some(parsed) = source.recv().await {
        match parsed {
            ServerMsg::TunnelSdpAnswer {
                session_id: sid,
                sdp,
            } if sid == session_id => {
                if let Err(e) = peer.accept_answer(&sdp).await {
                    error!(%e, "accept_answer failed");
                }
            }
            ServerMsg::TunnelIce {
                session_id: sid,
                candidate,
            } if sid == session_id => {
                let init: RTCIceCandidateInit = match serde_json::from_value(candidate) {
                    Ok(i) => i,
                    Err(e) => {
                        warn!(%e, "remote ICE candidate parse failed");
                        continue;
                    }
                };
                if let Err(e) = peer.add_remote_ice_candidate(init).await {
                    warn!(%e, "add_remote_ice_candidate failed");
                }
            }
            ServerMsg::TcpForwardAccept {
                session_id: sid,
                flow_id,
                dc_index,
            } if sid == session_id => {
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Accept { dc_index });
                } else {
                    warn!(flow_id, "accept for unknown flow_id");
                }
            }
            ServerMsg::TcpForwardReject {
                session_id: sid,
                flow_id,
                kind,
                reason,
            } if sid == session_id => {
                let session_gone = is_session_gone_reject(kind, &reason);
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Reject { kind, reason });
                } else {
                    warn!(flow_id, ?kind, %reason, "reject for unknown flow_id");
                }
                if session_gone {
                    warn!(
                        flow_id,
                        "agent no longer knows this session (WS reconnect after a network flap?) — ending session to re-open"
                    );
                    // Best-effort: tell the server we consider the session
                    // dead so it reaps its entry + relays teardown to the
                    // agent now, instead of carrying a zombie entry until
                    // our WS drops. Idempotent if the server's own
                    // terminate push raced us.
                    let _ = sink
                        .send(ClientMsg::TunnelTerminate {
                            session_id,
                            reason: CloseReason::IoError,
                        })
                        .await;
                    return;
                }
            }
            ServerMsg::TcpHalfClose {
                session_id: sid,
                flow_id,
                direction,
            } if sid == session_id => {
                // Audit only — the in-band marker on the DC drives
                // the actual data-plane close. See
                // `tunnel_core::forward` module docs.
                debug!(flow_id, ?direction, "rc:tunnel.tcp.half_close (audit)");
            }
            ServerMsg::TcpClosed {
                session_id: sid,
                flow_id,
                reason,
            } if sid == session_id => {
                debug!(flow_id, ?reason, "rc:tunnel.tcp.closed (audit)");
                active_flows.lock().await.remove(&flow_id);
            }
            ServerMsg::UdpForwardAccept {
                session_id: sid,
                flow_id,
                dc_index,
            } if sid == session_id => {
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Accept { dc_index });
                } else {
                    warn!(flow_id, "udp accept for unknown flow_id");
                }
            }
            ServerMsg::UdpForwardReject {
                session_id: sid,
                flow_id,
                kind,
                reason,
            } if sid == session_id => {
                let session_gone = is_session_gone_reject(kind, &reason);
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Reject { kind, reason });
                } else {
                    warn!(flow_id, ?kind, %reason, "udp reject for unknown flow_id");
                }
                if session_gone {
                    warn!(
                        flow_id,
                        "agent no longer knows this session (WS reconnect after a network flap?) — ending session to re-open"
                    );
                    // Best-effort: tell the server we consider the session
                    // dead so it reaps its entry + relays teardown to the
                    // agent now, instead of carrying a zombie entry until
                    // our WS drops. Idempotent if the server's own
                    // terminate push raced us.
                    let _ = sink
                        .send(ClientMsg::TunnelTerminate {
                            session_id,
                            reason: CloseReason::IoError,
                        })
                        .await;
                    return;
                }
            }
            ServerMsg::UdpClosed {
                session_id: sid,
                flow_id,
                reason,
            } if sid == session_id => {
                debug!(flow_id, ?reason, "rc:tunnel.udp.closed (audit)");
                active_flows.lock().await.remove(&flow_id);
            }
            ServerMsg::TunnelTerminate {
                session_id: sid,
                reason,
            } if sid == session_id => {
                info!(?reason, "rc:tunnel.terminate — peer torn down by server");
                // Ack with our own terminate (mirroring the Revoked arm) so
                // the server runs its normal per-connection teardown + audit
                // for this session instead of carrying a zombie entry until
                // our WS drops. Server handling is idempotent; pre-P7 servers
                // already accept client terminates for unknown sessions.
                let _ = sink
                    .send(ClientMsg::TunnelTerminate { session_id, reason })
                    .await;
                return;
            }
            ServerMsg::TunnelRevoked { reason } => {
                error!(%reason, "rc:tunnel.revoked — admin revoked our enrollment");
                let _ = sink
                    .send(ClientMsg::TunnelTerminate {
                        session_id,
                        reason: CloseReason::ServerTerminated,
                    })
                    .await;
                return;
            }
            other => debug!(?other, "dispatch: ignoring ServerMsg"),
        }
    }
    debug!("WS source ended; dispatch loop exiting");
}

/// The QUIC data plane (`quic-v1` / `quic-derp-v1`). Awaits the agent's
/// `rc:tunnel.quic.ready` (relayed by the server), connects to the
/// agent's quinn endpoint (cert pinned from that message, authed with
/// the server-minted token), then hands back a [`Carrier`] that serves
/// local TCP connections — one QUIC bidirectional stream per flow.
/// Returns [`Establishment::QuicSetupFailed`] (not an `Err`) if the QUIC
/// link can't be established during setup, so the caller can fall back to
/// WebRTC. Once flows can start it's committed (no WebRTC fallback; the
/// carrier runs until it is dead or dropped, like the WebRTC path).
#[allow(clippy::too_many_arguments)]
async fn establish_quic(
    mut source: Box<dyn TunnelSignalingSource>,
    sink: Arc<dyn TunnelSignalingSink>,
    session_id: ObjectId,
    quic_auth_token: Option<String>,
    ice_servers: Vec<IceServer>,
    target: Target,
    session: Arc<SessionThroughput>,
    // R4 — `Some` iff the server negotiated `quic-derp-v1`: QUIC rides the
    // established `/derp` WS toward the agent's pubkey instead of a TURN
    // relay. Everything after the connection (auth, dispatcher, flows) is
    // transport-agnostic and shared.
    derp: Option<crate::transport::derp::DerpTunnelHandle>,
    terminate: TerminateOnDrop,
) -> Result<Establishment> {
    let Some(token) = quic_auth_token else {
        warn!("server negotiated a quic flavor but sent no quic_auth_token — cannot authenticate");
        return Ok(Establishment::QuicSetupFailed);
    };

    // Await `rc:tunnel.quic.ready`: the agent's ephemeral cert
    // fingerprint to pin + the dialable addrs (+ the agent's derp pubkey
    // on the derp flavor).
    let ready = tokio::time::timeout(QUIC_READY_TIMEOUT, async {
        loop {
            match source
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("WS closed before rc:tunnel.quic.ready"))?
            {
                ServerMsg::TunnelQuicReady {
                    session_id: sid,
                    cert_fingerprint,
                    addrs,
                    derp_pubkey,
                } if sid == session_id => break anyhow::Ok((cert_fingerprint, addrs, derp_pubkey)),
                ServerMsg::TunnelRevoked { reason } => {
                    bail!("tunnel revoked during quic setup: {reason}")
                }
                ServerMsg::TunnelTerminate { reason, .. } => {
                    bail!("tunnel terminated during quic setup: {reason:?}")
                }
                other => debug!(?other, "ignoring pre-quic-ready ServerMsg"),
            }
        }
    })
    .await;
    let (cert_fingerprint, addrs, agent_derp_pubkey) = match ready {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!(%e, "error awaiting rc:tunnel.quic.ready");
            return Ok(Establishment::QuicSetupFailed);
        }
        Err(_) => {
            warn!("timed out waiting for rc:tunnel.quic.ready");
            return Ok(Establishment::QuicSetupFailed);
        }
    };
    info!(
        addrs = ?addrs,
        fp_prefix = %cert_fingerprint.chars().take(12).collect::<String>(),
        derp = agent_derp_pubkey.is_some(),
        "rc:tunnel.quic.ready"
    );

    // Establish the QUIC connection. Phase 3d: when the server minted
    // coturn creds we ride QUIC-over-TURN (Tier 2) — the agent advertised
    // its relay address, and we dial it through our OWN relay so coturn's
    // permission model lets the datagrams flow. Otherwise (no creds) dial
    // the agent's direct host candidates (Phase 1e/2a). Either branch
    // yields a connected `(peer, conn)`; auth + the data plane below are
    // transport-agnostic.
    let flavor = if derp.is_some() {
        TRANSPORT_QUIC_DERP_V1
    } else {
        TRANSPORT_QUIC_V1
    };
    let (peer, conn, path) = if let Some(handle) = derp {
        // R4 — quic-derp-v1: QUIC over the node's ESTABLISHED `/derp` WS,
        // addressed at the agent's DERP pubkey. No TURN allocation, no
        // permission dance (`quic.candidate` is not sent — the relay is
        // pubkey-addressed), and the transport config is MTU-clamped under
        // the server's 2048-byte frame cap.
        let Some(agent_pk) = agent_derp_pubkey
            .as_deref()
            .and_then(crate::transport::derp::parse_pubkey_hex)
        else {
            warn!("quic-derp-v1 negotiated but the agent sent no parseable derp_pubkey");
            return Ok(Establishment::QuicSetupFailed);
        };
        let derp_conn = handle.mux.tunnel_conn_for(agent_pk);
        let dial = derp_conn.synth_peer();
        let relay_conn: Arc<dyn relay::RelayConn> = Arc::new(derp_conn);
        let sock = match relay::RelayUdpSocket::new(relay_conn) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                warn!(%e, "quic-derp: relay socket bridge");
                return Ok(Establishment::QuicSetupFailed);
            }
        };
        let peer = match QuicPeer::client_over_derp(sock, &cert_fingerprint) {
            Ok(p) => p,
            Err(e) => {
                warn!(%e, "quic-derp: endpoint over derp conn");
                return Ok(Establishment::QuicSetupFailed);
            }
        };
        match peer.connect(dial).await {
            Ok(conn) => (peer, conn, "derp"),
            Err(e) => {
                warn!(%e, "quic-derp: handshake over the derp leg failed");
                return Ok(Establishment::QuicSetupFailed);
            }
        }
    } else if let Some((urls, user, cred)) = pick_turn_creds(&ice_servers) {
        info!("QUIC: server provided TURN creds — establishing QUIC-over-TURN (relay)");
        match setup_quic_over_relay(
            &urls,
            &user,
            &cred,
            &cert_fingerprint,
            &addrs,
            session_id,
            &sink,
        )
        .await
        {
            // Relay sub-tier — UDP (Tier 2) vs TURNS/TCP (Tier 3) — is
            // logged by the allocation itself ("TURN allocation established"
            // vs "TURNS/TCP …"); at the QUIC level both are the relay path.
            Some((peer, conn)) => (peer, conn, "relay"),
            None => return Ok(Establishment::QuicSetupFailed),
        }
    } else {
        let bind: std::net::SocketAddr =
            "0.0.0.0:0".parse().expect("0.0.0.0:0 is a valid bind addr");
        let peer = match QuicPeer::client(bind, &cert_fingerprint) {
            Ok(p) => p,
            Err(e) => {
                warn!(%e, "QuicPeer::client failed");
                return Ok(Establishment::QuicSetupFailed);
            }
        };
        // Dial the advertised addrs in priority order (direct host /
        // srflx candidates).
        let Some(conn) = connect_first(&peer, &addrs).await else {
            warn!(addrs = ?addrs, "could not connect QUIC to any advertised addr");
            return Ok(Establishment::QuicSetupFailed);
        };
        (peer, conn, "direct")
    };
    if let Err(e) = quic::client_authenticate(&conn, &token).await {
        warn!(%e, "QUIC client_authenticate failed");
        return Ok(Establishment::QuicSetupFailed);
    }
    // Per-tier connection summary — one greppable line for field
    // diagnosis: transport + path (relay vs direct hole-punch) + the
    // negotiated peer address. The relay sub-tier (UDP Tier 2 / TURNS-TCP
    // Tier 3) and our own relay address are in the adjacent
    // relay-allocation log lines; throughput follows in the 2 s logger.
    info!(
        transport = flavor,
        path,
        remote = %conn.remote_address(),
        "tunnel established"
    );

    // From here the QUIC link is live; we're committed (no WebRTC
    // fallback once flows can start). Spawn the WS dispatcher for
    // per-flow accept/reject + teardown signals.
    let reply_registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
    let active_flows: ActiveFlows = Arc::new(Mutex::new(HashMap::new()));
    let (dispatcher_done_tx, dispatcher_done) = watch::channel(());
    let dispatcher_task = AbortOnDrop({
        let reply_registry = Arc::clone(&reply_registry);
        let active_flows = Arc::clone(&active_flows);
        let sink = sink.clone();
        tokio::spawn(async move {
            // Held for the task's life: dropped when the loop returns OR the
            // task is aborted, which closes `dispatcher_done` for
            // `Carrier::dead`.
            let _done = dispatcher_done_tx;
            quic_dispatch_loop(source, session_id, reply_registry, active_flows, sink).await
        })
    });

    // Keep the endpoint + connection alive for the session lifetime
    // (dropping the endpoint closes quinn; dropping the last `conn`
    // Arc closes the connection). Both live in the carrier's plane.
    let conn = Arc::new(conn);
    let _peer = Arc::new(peer);

    // Ready to carry — the listener is the caller's (FR-86 P1, see
    // `establish_webrtc`). The `conn.closed()` / `session_dead` /
    // dispatcher-exit arms of the old accept loop are `Carrier::dead`.
    Ok(Establishment::Established(Box::new(Carrier {
        transport: flavor,
        session_id,
        sink,
        target,
        session,
        reply_registry,
        active_flows,
        flow_counter: Arc::new(AtomicU32::new(1)),
        // P7 backstop: shared consecutive-forward-timeout streak + a "session is
        // wedged" signal the per-connection tasks fire when it trips.
        flow_timeout_streak: Arc::new(AtomicU32::new(0)),
        session_dead: Arc::new(Notify::new()),
        in_flight: Arc::new(AtomicU64::new(0)),
        idle: Arc::new(Notify::new()),
        dispatcher_done,
        _dispatcher: dispatcher_task,
        plane: Plane::Quic { conn, _peer },
        _terminate: terminate,
    })))
}

/// Try each advertised addr in order; return the first QUIC connection
/// that handshakes. Logs + skips unparseable / unreachable addrs.
async fn connect_first(peer: &QuicPeer, addrs: &[String]) -> Option<QuicConnection> {
    for a in addrs {
        let Ok(sa) = a.parse::<std::net::SocketAddr>() else {
            warn!(addr = %a, "skipping unparseable quic addr");
            continue;
        };
        match peer.connect(sa).await {
            Ok(c) => return Some(c),
            Err(e) => warn!(addr = %sa, %e, "quic connect failed; trying next addr"),
        }
    }
    None
}

/// Pick the first ICE server carrying usable plain-UDP TURN relay creds
/// (a `turn:…?transport=udp` url plus username + credential). Returns the
/// `(urls, username, credential)` for [`setup_quic_over_relay`], or
/// `None` when the server sent only STUN / TLS-TCP entries (→ direct
/// QUIC). Phase 3d.
fn pick_turn_creds(ice_servers: &[IceServer]) -> Option<(Vec<String>, String, String)> {
    ice_servers
        .iter()
        .find_map(|s| match (&s.username, &s.credential) {
            (Some(u), Some(c)) if relay::turn_udp_server(&s.urls).is_some() => {
                Some((s.urls.clone(), u.clone(), c.clone()))
            }
            _ => None,
        })
}

/// Phase 3d: bring the client's QUIC endpoint up over its OWN coturn TURN
/// relay and dial the agent's relay address (QUIC-over-TURN, Tier 2).
///
/// 1. Allocate a relay from the session creds → a [`relay::RelayUdpSocket`]
///    quinn rides; the relayed address is what coturn handed us.
/// 2. Send `rc:tunnel.quic.candidate { our relay addr }` so the agent
///    installs a TURN permission for us (it's the QUIC server + never
///    sends first).
/// 3. Bootstrap our OWN permission for each agent relay addr (one stray
///    datagram each — the webrtc-rs TURN client auto-creates the
///    CreatePermission on first send; the agent's quinn discards the
///    byte). This is the mutual half coturn needs to relay the agent's
///    handshake replies back to us.
/// 4. After a short settle, dial the agent's relay addr over our relay.
///
/// Returns the connected `(peer, conn)` or `None` on any setup failure
/// (caller soft-falls back to webrtc-dc-v1). The full Tier-2 datagram +
/// permission path is proven in tunnel-core's
/// `quinn_runs_over_two_turn_allocations`.
#[allow(clippy::too_many_arguments)]
async fn setup_quic_over_relay(
    urls: &[String],
    username: &str,
    credential: &str,
    cert_fingerprint: &str,
    agent_addrs: &[String],
    session_id: ObjectId,
    sink: &Arc<dyn TunnelSignalingSink>,
) -> Option<(QuicPeer, QuicConnection)> {
    // Same-worker pin: coturn relays between two allocations on the SAME
    // worker via hairpin, but cross-worker relay-to-relay breaks on this
    // cluster (the dual-public-IP SNAT rewrites the relay's egress source
    // so the peer's CreatePermission no longer matches). The agent — often
    // UDP-blocked — can't be pinned (its TLS allocate needs the coturn
    // hostname for SNI), so the CLIENT follows the agent onto its worker by
    // allocating its UDP relay directly on the agent's relay IP. Falls back
    // to the round-robin hostname urls if that UDP allocate fails (e.g. a
    // UDP-blocked controller), which lands cross-worker but at least tries.
    let mut alloc_urls: Vec<String> = Vec::new();
    if let Some(ip) = agent_addrs
        .iter()
        .find_map(|a| a.parse::<std::net::SocketAddr>().ok().map(|s| s.ip()))
    {
        let host = if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        // Dial the grant's own UDP port on the pinned IP (regional PoPs may
        // serve TURN off 3478; the granted url list is authoritative).
        let udp_port =
            roomler_ai_remote_control::turn_url::first_udp_port(urls.iter().map(String::as_str));
        alloc_urls.push(format!("turn:{host}:{udp_port}?transport=udp"));
        info!(%ip, "QUIC client: pinning relay to the agent's coturn worker (hairpin)");
    }
    alloc_urls.extend_from_slice(urls);
    let turn_relay = match relay::allocate_relay_from_ice(&alloc_urls, username, credential).await {
        Ok(r) => r,
        Err(e) => {
            warn!(%e, "QUIC client: TURN allocate failed");
            return None;
        }
    };
    let relay_conn: Arc<dyn relay::RelayConn> = Arc::new(turn_relay);
    let our_relay_addr = match relay_conn.local_addr() {
        Ok(a) => a,
        Err(e) => {
            warn!(%e, "QUIC client: relay local_addr");
            return None;
        }
    };
    info!(relay_addr = %our_relay_addr, "QUIC client: TURN relay allocated");

    let sock = match relay::RelayUdpSocket::new(Arc::clone(&relay_conn)) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(%e, "QUIC client: relay socket bridge");
            return None;
        }
    };
    let peer = match QuicPeer::client_over_abstract_socket(sock, cert_fingerprint) {
        Ok(p) => p,
        Err(e) => {
            warn!(%e, "QUIC client: endpoint over relay");
            return None;
        }
    };

    // Tell the agent our relay addr so it permits us (server relays this
    // candidate to the agent, which installs the TURN permission).
    if let Err(e) = sink
        .send(ClientMsg::TunnelQuicCandidate {
            session_id,
            addrs: vec![our_relay_addr.to_string()],
        })
        .await
    {
        warn!(%e, "QUIC client: send relay candidate failed");
        return None;
    }
    // Bootstrap our side of the mutual permission for each agent relay
    // addr.
    for a in agent_addrs {
        if let Ok(sa) = a.parse::<std::net::SocketAddr>()
            && let Err(e) = relay_conn.send_to(b"\x00", sa).await
        {
            debug!(addr = %sa, %e, "QUIC client: permission bootstrap datagram failed");
        }
    }
    tokio::time::sleep(QUIC_PERMIT_SETTLE).await;

    match connect_first(&peer, agent_addrs).await {
        Some(conn) => Some((peer, conn)),
        None => {
            warn!(addrs = ?agent_addrs, "QUIC client: could not connect over the relay");
            None
        }
    }
}

/// WS read loop for a QUIC session. Routes per-flow accept/reject into
/// the `reply_registry` and handles teardown. Unlike the WebRTC
/// [`dispatch_loop`] it has no SDP/ICE to forward — QUIC carries its
/// own handshake — so it only consumes the control-plane signals.
async fn quic_dispatch_loop(
    mut source: Box<dyn TunnelSignalingSource>,
    session_id: ObjectId,
    reply_registry: ReplyRegistry,
    active_flows: ActiveFlows,
    sink: Arc<dyn TunnelSignalingSink>,
) {
    while let Some(parsed) = source.recv().await {
        match parsed {
            ServerMsg::TcpForwardAccept {
                session_id: sid,
                flow_id,
                dc_index,
            } if sid == session_id => {
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Accept { dc_index });
                } else {
                    warn!(flow_id, "accept for unknown flow_id");
                }
            }
            ServerMsg::TcpForwardReject {
                session_id: sid,
                flow_id,
                kind,
                reason,
            } if sid == session_id => {
                let session_gone = is_session_gone_reject(kind, &reason);
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Reject { kind, reason });
                } else {
                    warn!(flow_id, ?kind, %reason, "reject for unknown flow_id");
                }
                if session_gone {
                    warn!(
                        flow_id,
                        "agent no longer knows this session (WS reconnect after a network flap?) — ending quic session to re-open"
                    );
                    // Best-effort server-side reap — see the identical
                    // comment in the WebRTC dispatch loop.
                    let _ = sink
                        .send(ClientMsg::TunnelTerminate {
                            session_id,
                            reason: CloseReason::IoError,
                        })
                        .await;
                    return;
                }
            }
            ServerMsg::TcpHalfClose {
                session_id: sid,
                flow_id,
                direction,
            } if sid == session_id => {
                debug!(flow_id, ?direction, "rc:tunnel.tcp.half_close (audit)");
            }
            ServerMsg::TcpClosed {
                session_id: sid,
                flow_id,
                reason,
            } if sid == session_id => {
                debug!(flow_id, ?reason, "rc:tunnel.tcp.closed (audit)");
                active_flows.lock().await.remove(&flow_id);
            }
            ServerMsg::UdpForwardAccept {
                session_id: sid,
                flow_id,
                dc_index,
            } if sid == session_id => {
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Accept { dc_index });
                } else {
                    warn!(flow_id, "udp accept for unknown flow_id");
                }
            }
            ServerMsg::UdpForwardReject {
                session_id: sid,
                flow_id,
                kind,
                reason,
            } if sid == session_id => {
                let session_gone = is_session_gone_reject(kind, &reason);
                if let Some(tx) = reply_registry.lock().await.remove(&flow_id) {
                    let _ = tx.send(ForwardReply::Reject { kind, reason });
                } else {
                    warn!(flow_id, ?kind, %reason, "udp reject for unknown flow_id");
                }
                if session_gone {
                    warn!(
                        flow_id,
                        "agent no longer knows this session (WS reconnect after a network flap?) — ending session to re-open"
                    );
                    // Best-effort: tell the server we consider the session
                    // dead so it reaps its entry + relays teardown to the
                    // agent now, instead of carrying a zombie entry until
                    // our WS drops. Idempotent if the server's own
                    // terminate push raced us.
                    let _ = sink
                        .send(ClientMsg::TunnelTerminate {
                            session_id,
                            reason: CloseReason::IoError,
                        })
                        .await;
                    return;
                }
            }
            ServerMsg::UdpClosed {
                session_id: sid,
                flow_id,
                reason,
            } if sid == session_id => {
                debug!(flow_id, ?reason, "rc:tunnel.udp.closed (audit)");
                active_flows.lock().await.remove(&flow_id);
            }
            ServerMsg::TunnelTerminate {
                session_id: sid,
                reason,
            } if sid == session_id => {
                info!(?reason, "rc:tunnel.terminate — peer torn down by server");
                // Ack with our own terminate (mirroring the Revoked arm) so
                // the server runs its normal per-connection teardown + audit
                // for this session instead of carrying a zombie entry until
                // our WS drops. Server handling is idempotent; pre-P7 servers
                // already accept client terminates for unknown sessions.
                let _ = sink
                    .send(ClientMsg::TunnelTerminate { session_id, reason })
                    .await;
                return;
            }
            ServerMsg::TunnelRevoked { reason } => {
                error!(%reason, "rc:tunnel.revoked — admin revoked our enrollment");
                let _ = sink
                    .send(ClientMsg::TunnelTerminate {
                        session_id,
                        reason: CloseReason::ServerTerminated,
                    })
                    .await;
                return;
            }
            other => debug!(?other, "quic dispatch: ignoring ServerMsg"),
        }
    }
    debug!("WS source ended; quic dispatch loop exiting");
}

/// QUIC analogue of [`handle_local_connection`]: request the forward,
/// await accept/reject, then open a QUIC bidirectional stream for the
/// flow and pump it with [`run_flow_quic`]. No DC pool / round-robin —
/// each flow is its own stream.
#[allow(clippy::too_many_arguments)]
async fn handle_local_connection_quic(
    mut tcp: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    flow_id: u32,
    session_id: ObjectId,
    conn: Arc<QuicConnection>,
    dst_host: &str,
    dst_port: u16,
    sink: Arc<dyn TunnelSignalingSink>,
    reply_rx: oneshot::Receiver<ForwardReply>,
    reply_registry: ReplyRegistry,
    active_flows: ActiveFlows,
    socks: bool,
    session: Arc<SessionThroughput>,
    // P7 backstop: shared across the session's flows — reset on any reply,
    // incremented on timeout; `session_dead` is fired when the streak trips.
    flow_timeout_streak: Arc<std::sync::atomic::AtomicU32>,
    session_dead: Arc<Notify>,
) -> Result<()> {
    // Request the forward.
    sink.send(ClientMsg::TcpForwardRequest {
        session_id,
        flow_id,
        dst_host: dst_host.to_string(),
        dst_port,
    })
    .await
    .context("send TcpForwardRequest")?;

    // Await accept/reject.
    let reply = match tokio::time::timeout(FLOW_OPEN_TIMEOUT, reply_rx).await {
        Ok(Ok(r)) => {
            record_flow_progress(&flow_timeout_streak);
            r
        }
        Ok(Err(_canceled)) => {
            reply_registry.lock().await.remove(&flow_id);
            bail!("reply oneshot dropped — dispatcher exited?");
        }
        Err(_) => {
            reply_registry.lock().await.remove(&flow_id);
            if record_flow_timeout(&flow_timeout_streak) {
                warn!(
                    flow_id,
                    streak = MAX_CONSECUTIVE_FLOW_TIMEOUTS,
                    "forward opens timed out repeatedly — signalling session death"
                );
                session_dead.notify_one();
            } else {
                warn!(flow_id, "TcpForwardRequest timed out");
            }
            bail!("forward request timed out after {FLOW_OPEN_TIMEOUT:?}");
        }
    };
    match reply {
        ForwardReply::Accept { dc_index } => {
            // dc_index is meaningless for QUIC (the agent sends 0);
            // logged only for symmetry with the WebRTC path.
            debug!(flow_id, dc_index, "rc:tunnel.tcp.accept (quic)");
            if socks {
                crate::socks5::reply(&mut tcp, crate::socks5::REP_SUCCESS).await;
            }
        }
        ForwardReply::Reject { kind, reason } => {
            warn!(flow_id, ?kind, %reason, "rc:tunnel.tcp.reject — dropping local conn");
            if socks {
                crate::socks5::reply(&mut tcp, crate::socks5::REP_GENERAL_FAILURE).await;
            }
            drop(tcp);
            return Ok(());
        }
    }

    active_flows.lock().await.insert(flow_id, 0);
    // Open the QUIC stream for this flow (writes the 4-byte flow_id
    // preamble the agent reads to correlate the stream to the dialed
    // dst via its `take_flow` rendezvous).
    let (send, recv) = match quic::open_flow(&conn, flow_id).await {
        Ok(s) => s,
        Err(e) => {
            active_flows.lock().await.remove(&flow_id);
            drop(tcp);
            bail!("quic open_flow for flow {flow_id}: {e}");
        }
    };

    // Stamp the per-forward throughput aggregate (P3b-3) onto the flow's
    // stats so `run_flow_quic`'s pumps mirror bytes + hold the active-flows
    // gauge. (The `active_flows` map above is the QUIC path's own flow-id
    // bookkeeping — distinct from the SessionThroughput gauge.)
    let stats = Arc::new(crate::forward::FlowStats {
        session: Some(session),
        ..Default::default()
    });
    debug!(flow_id, %peer_addr, "running quic flow");
    let stats_for_audit = Arc::clone(&stats);
    let close_reason = run_flow_quic(tcp, send, recv, flow_id, stats).await;
    info!(flow_id, ?close_reason, "quic flow ended");
    // Same TCP-side counters as the WebRTC path, which is the point of
    // measuring there: the two transports stay directly comparable.
    let (tcp_read, _dc_send, _dc_recv, tcp_write, _depth) = stats_for_audit.snapshot();
    let _ = sink
        .send(ClientMsg::TcpClosed {
            session_id,
            flow_id,
            reason: close_reason,
            bytes_in: tcp_write,
            bytes_out: tcp_read,
        })
        .await;
    active_flows.lock().await.remove(&flow_id);
    Ok(())
}

/// FR-90 P3-7-3a — an agent session's grant, as its device presents it at
/// `rc:tunnel.open` ([`SessionParams::net_grant`]): the token the vault signed
/// (P3-7-1b) and the grant's id. The server binds the tunnel to it and holds
/// every flow of the tunnel to it, or refuses the open (P3-7-2a).
///
/// ⚠️ The token is a credential until its end, at most 900 s: `Debug` names the
/// grant by its id alone, and nothing here logs the token.
#[derive(Clone)]
pub struct SessionGrantRef {
    pub token: String,
    pub grant_id: String,
}

impl std::fmt::Debug for SessionGrantRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGrantRef")
            .field("grant_id", &self.grant_id)
            .finish_non_exhaustive()
    }
}

/// FR-90 P3-7-3a — why a tunnel opened for a session's grant carries none of
/// the session's flows. Each is the end of that grant, never a reason to open
/// again: the session asks the vault for another.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// The server refused the open (`NET_GRANT_REFUSED`), in its words.
    #[error("the server refused the session's grant: {0}")]
    Refused(String),
    /// `rc:tunnel.opened` did not echo the grant. A server from before
    /// P3-7-2a ignores the field and opens the tunnel as the device's own,
    /// which would carry the session's flows as the device's.
    #[error("the server opened the tunnel without binding the session's grant")]
    NotBound,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling_link::TunnelSignalingSink;
    use async_trait::async_trait;
    use tokio::sync::mpsc;

    // Force the fast ordered DC prefix to be processed before permitting the
    // signalling Accept. The second/probe flow is an ordered application-level
    // receipt barrier, not a sleep or an assumption about dc.send completion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn server_first_ssh_prefix_survives_dc_before_ws_accept() {
        use bytes::Bytes;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const FLOW: u32 = 1;
        const PROBE: u32 = 99;
        const INDEX: u8 = 1; // authoritative, deliberately not the hint (0)
        const BANNER: &[u8] = b"SSH-2.0-MeshHarbor-server-first\r\n";
        struct DelayedAccept {
            dc: Arc<webrtc::data_channel::RTCDataChannel>,
            probe: Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
            ready: Mutex<Option<oneshot::Sender<()>>>,
            release: Mutex<Option<oneshot::Receiver<()>>>,
            registry: ReplyRegistry,
        }
        #[async_trait]
        impl TunnelSignalingSink for DelayedAccept {
            async fn send(&self, msg: ClientMsg) -> Result<()> {
                if let ClientMsg::TcpForwardRequest { flow_id, .. } = msg {
                    assert_eq!(flow_id, FLOW);
                    self.dc.send(&Bytes::from(crate::mux::encode(FLOW, BANNER))).await?;
                    self.dc.send(&Bytes::from(crate::mux::encode(PROBE, b"prefix-processed"))).await?;
                    assert_eq!(self.probe.lock().await.recv().await.unwrap().as_ref(), b"prefix-processed");
                    self.ready.lock().await.take().unwrap().send(()).unwrap();
                    self.release.lock().await.take().unwrap().await.unwrap();
                    self.registry.lock().await.remove(&FLOW).unwrap().send(ForwardReply::Accept { dc_index: INDEX }).unwrap();
                }
                Ok(())
            }
        }
        let origin = TunnelPeer::new(vec![]).await.unwrap();
        let target = TunnelPeer::new(vec![]).await.unwrap();
        let target_pc = target.peer_connection();
        origin.on_local_ice_candidate(move |candidate| {
            let pc = target_pc.clone();
            Box::pin(async move { if let Some(candidate) = candidate { let _ = pc.add_ice_candidate(candidate.to_json().unwrap()).await; } })
        });
        let origin_pc = origin.peer_connection();
        target.on_local_ice_candidate(move |candidate| {
            let pc = origin_pc.clone();
            Box::pin(async move { if let Some(candidate) = candidate { let _ = pc.add_ice_candidate(candidate.to_json().unwrap()).await; } })
        });
        let offer = origin.create_offer().await.unwrap();
        let answer = target.accept_offer(&offer.sdp).await.unwrap();
        origin.accept_answer(&answer.sdp).await.unwrap();
        tokio::time::timeout(Duration::from_secs(15), origin.wait_pool_open()).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(15), target.wait_pool_open()).await.unwrap().unwrap();
        let mut demuxes = Vec::new();
        for idx in 0..origin.pool_size() { demuxes.push(FlowDemux::install(origin.dc(idx).unwrap(), None).await); }
        let demuxes = Arc::new(demuxes);
        let (probe, _) = demuxes[INDEX as usize].register(PROBE).await;
        let remote = FlowDemux::install(target.dc(INDEX).unwrap(), None).await;
        let (mut client_prefix, _) = remote.register(FLOW).await;
        let remote_dc = target.dc(INDEX).unwrap();
        // A real SSH server sends KEXINIT only after the client identification.
        // Baseline drops the prior server banner and exposes this binary prefix
        // to the app instead (the observed OpenSSH invalid-format failure).
        let kex = tokio::spawn(async move {
            let bytes = client_prefix.recv().await.unwrap();
            assert!(bytes.starts_with(b"SSH-2.0-"));
            remote_dc.send(&Bytes::from(crate::mux::encode(FLOW, &[0u8; 64]))).await.unwrap();
        });
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = tokio::net::TcpStream::connect(local.local_addr().unwrap()).await.unwrap();
        let (tcp, peer_addr) = local.accept().await.unwrap();
        let registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (reply_tx, reply_rx) = oneshot::channel();
        registry.lock().await.insert(FLOW, reply_tx);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let sink = Arc::new(DelayedAccept { dc: target.dc(INDEX).unwrap(), probe: Mutex::new(probe), ready: Mutex::new(Some(ready_tx)), release: Mutex::new(Some(release_rx)), registry: registry.clone() });
        let cancellation = FlowCanceller::new();
        let flow = tokio::spawn(handle_local_connection(tcp, peer_addr, FLOW, 0, ObjectId::new(), "embedded-ssh", 22, sink, reply_rx, registry, Arc::new(Mutex::new(HashMap::new())), demuxes.clone(), false, Arc::new(AtomicU32::new(0)), Arc::new(Notify::new()), cancellation.handle()));
        tokio::time::timeout(Duration::from_secs(5), ready_rx).await.unwrap().unwrap();
        let mut no_early_release = [0u8; 1];
        assert_eq!(app.try_read(&mut no_early_release).unwrap_err().kind(), std::io::ErrorKind::WouldBlock, "DC bytes cannot reach TCP before accepted scope");
        release_tx.send(()).unwrap();
        app.write_all(b"SSH-2.0-regression-client\r\n").await.unwrap();
        let mut received = vec![0u8; BANNER.len()];
        let received_result = tokio::time::timeout(Duration::from_secs(3), app.read_exact(&mut received)).await;
        let kex_result = tokio::time::timeout(Duration::from_secs(3), kex).await;
        cancellation.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), flow).await.unwrap();
        kex_result.unwrap().unwrap();
        origin.close().await;
        target.close().await;
        assert!(matches!(received_result, Ok(Ok(_))), "SSH prefix did not arrive intact");
        assert_eq!(received.as_slice(), BANNER, "server-first SSH banner lost before WS Accept; binary KEX exposed");
    }

    #[tokio::test]
    async fn preaccept_driver_cleans_aliases_on_send_reject_cancel_timeout_and_abort() {
        struct Sink {
            mode: u8,
            ready: Mutex<Option<oneshot::Sender<()>>>,
            registry: ReplyRegistry,
            pool: Arc<Vec<FlowDemux>>,
        }
        #[async_trait]
        impl TunnelSignalingSink for Sink {
            async fn send(&self, msg: ClientMsg) -> Result<()> {
                if let ClientMsg::TcpForwardRequest { flow_id, .. } = msg {
                    for d in self.pool.iter() {
                        assert!(
                            d.registered_for_test(flow_id).await,
                            "must register before request"
                        );
                    }
                    let _ = self.ready.lock().await.take().unwrap().send(());
                    match self.mode {
                        0 => anyhow::bail!("deliberate send failure"),
                        1 => {
                            let _ = self.registry.lock().await.remove(&flow_id).unwrap().send(
                                ForwardReply::Reject {
                                    kind: RejectKind::AgentError,
                                    reason: "fixture reject".into(),
                                },
                            );
                        }
                        2 => {
                            self.registry.lock().await.remove(&flow_id);
                        }
                        4 => return std::future::pending().await,
                        _ => {}
                    }
                }
                Ok(())
            }
        }
        let peer = TunnelPeer::new(vec![]).await.unwrap();
        let mut pool = Vec::new();
        for idx in 0..peer.pool_size() {
            pool.push(FlowDemux::install(peer.dc(idx).unwrap(), None).await);
        }
        let pool = Arc::new(pool);
        for mode in 0..=6u8 {
            let flow_id = mode as u32 + 1;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _app = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (tcp, addr) = listener.accept().await.unwrap();
            let registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
            let (tx, rx) = oneshot::channel();
            registry.lock().await.insert(flow_id, tx);
            let active: ActiveFlows = Arc::new(Mutex::new(HashMap::new()));
            let (ready_tx, ready_rx) = oneshot::channel();
            let sink = Arc::new(Sink {
                mode,
                ready: Mutex::new(Some(ready_tx)),
                registry: registry.clone(),
                pool: pool.clone(),
            });
            let cancellation = FlowCanceller::new();
            let task = tokio::spawn(handle_local_connection(
                tcp,
                addr,
                flow_id,
                0,
                ObjectId::new(),
                "fixture",
                22,
                sink,
                rx,
                registry.clone(),
                active.clone(),
                pool.clone(),
                false,
                Arc::new(AtomicU32::new(0)),
                Arc::new(Notify::new()),
                cancellation.handle(),
            ));
            tokio::time::timeout(Duration::from_secs(2), ready_rx)
                .await
                .unwrap()
                .unwrap();
            match mode {
                3 | 4 => cancellation.cancel(), // cancel waiting Accept / stuck signalling send
                6 => task.abort(),
                _ => {}
            }
            let result = tokio::time::timeout(FLOW_OPEN_TIMEOUT + Duration::from_secs(2), task)
                .await
                .unwrap();
            if mode == 6 {
                assert!(matches!(result, Err(e) if e.is_cancelled()));
            } else {
                let result = result.unwrap();
                assert_eq!(result.is_err(), matches!(mode, 0 | 2 | 5));
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let mut any = false;
                    for d in pool.iter() {
                        any |= d.registered_for_test(flow_id).await;
                    }
                    if !any {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("all pending aliases must be removed on every exit");
            assert!(active.lock().await.is_empty());
            if mode != 6 {
                assert!(registry.lock().await.is_empty());
            }
            // Task-abort reply removal remains the dispatcher's ownership;
            // this test checks the new reservation's cancellation-safe aliases.
            registry.lock().await.clear();
        }
        peer.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn preaccept_invalid_binding_closes_target_bounded_without_releasing_bytes() {
        use bytes::Bytes;
        use tokio::io::AsyncReadExt;
        struct Sink {
            mode: u8,
            dc: Arc<webrtc::data_channel::RTCDataChannel>,
            probe: Mutex<mpsc::Receiver<Bytes>>,
            registry: ReplyRegistry,
            closed: Mutex<Vec<(ObjectId, u32, CloseReason, u64, u64)>>,
        }
        #[async_trait]
        impl TunnelSignalingSink for Sink {
            async fn send(&self, msg: ClientMsg) -> Result<()> {
                match msg {
                    ClientMsg::TcpForwardRequest { flow_id, .. } => {
                        if self.mode != 2 {
                            let prefix = if self.mode == 1 {
                                vec![42; 1]
                            } else {
                                vec![42; 60 * 1024]
                            };
                            for _ in 0..if self.mode == 1 { 1 } else { 5 } {
                                self.dc
                                    .send(&Bytes::from(crate::mux::encode(flow_id, &prefix)))
                                    .await?;
                            }
                            self.dc
                                .send(&Bytes::from(crate::mux::encode(99, b"processed")))
                                .await?;
                            assert_eq!(
                                self.probe.lock().await.recv().await.unwrap().as_ref(),
                                b"processed"
                            );
                        }
                        let index = match self.mode {
                            1 => 1,
                            2 => 255,
                            _ => 0,
                        };
                        self.registry
                            .lock()
                            .await
                            .remove(&flow_id)
                            .unwrap()
                            .send(ForwardReply::Accept { dc_index: index })
                            .unwrap();
                    }
                    ClientMsg::TcpClosed {
                        session_id,
                        flow_id,
                        reason,
                        bytes_in,
                        bytes_out,
                    } => {
                        self.closed
                            .lock()
                            .await
                            .push((session_id, flow_id, reason, bytes_in, bytes_out));
                        if self.mode == 3 {
                            return std::future::pending().await;
                        }
                    }
                    _ => {}
                }
                Ok(())
            }
        }
        let origin = TunnelPeer::new(vec![]).await.unwrap();
        let target = TunnelPeer::new(vec![]).await.unwrap();
        let pc = target.peer_connection();
        origin.on_local_ice_candidate(move |candidate| {
            let pc = pc.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    let _ = pc.add_ice_candidate(c.to_json().unwrap()).await;
                }
            })
        });
        let pc = origin.peer_connection();
        target.on_local_ice_candidate(move |candidate| {
            let pc = pc.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    let _ = pc.add_ice_candidate(c.to_json().unwrap()).await;
                }
            })
        });
        let offer = origin.create_offer().await.unwrap();
        let answer = target.accept_offer(&offer.sdp).await.unwrap();
        origin.accept_answer(&answer.sdp).await.unwrap();
        tokio::time::timeout(Duration::from_secs(15), origin.wait_pool_open())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), target.wait_pool_open())
            .await
            .unwrap()
            .unwrap();
        let mut pool = Vec::new();
        for idx in 0..origin.pool_size() {
            pool.push(FlowDemux::install(origin.dc(idx).unwrap(), None).await);
        }
        let pool = Arc::new(pool);
        for mode in 0..=3u8 {
            let flow_id = mode as u32 + 1;
            let session_id = ObjectId::new();
            let (probe, _) = pool[0].register(99).await;
            let registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
            let (tx, rx) = oneshot::channel();
            registry.lock().await.insert(flow_id, tx);
            let sink = Arc::new(Sink {
                mode,
                dc: target.dc(0).unwrap(),
                probe: Mutex::new(probe),
                registry: registry.clone(),
                closed: Mutex::new(Vec::new()),
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut app = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (tcp, addr) = listener.accept().await.unwrap();
            let cancel = FlowCanceller::new();
            let result = tokio::time::timeout(
                Duration::from_secs(4),
                handle_local_connection(
                    tcp,
                    addr,
                    flow_id,
                    0,
                    session_id,
                    "fixture",
                    22,
                    sink.clone(),
                    rx,
                    registry,
                    Arc::new(Mutex::new(HashMap::new())),
                    pool.clone(),
                    false,
                    Arc::new(AtomicU32::new(0)),
                    Arc::new(Notify::new()),
                    cancel.handle(),
                ),
            )
            .await
            .expect("failed-flow close must stay bounded");
            assert!(result.is_err());
            let mut received = Vec::new();
            app.read_to_end(&mut received).await.unwrap();
            assert!(
                received.is_empty(),
                "invalid/unaccepted scope cannot release buffered data"
            );
            assert_eq!(
                sink.closed.lock().await.as_slice(),
                &[(session_id, flow_id, CloseReason::IoError, 0, 0)]
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let mut any = false;
                    for d in pool.iter() {
                        any |= d.registered_for_test(flow_id).await;
                    }
                    if !any {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            pool[0].unregister(99).await;
        }
        origin.close().await;
        target.close().await;
    }

    /// #1685 — the owner learns that the listener serves from the bind
    /// itself: never before it, never from a failed bind, and a caller with
    /// no hook (the standalone CLI) is fine.
    #[tokio::test]
    async fn the_listening_hook_fires_after_a_successful_bind_only() {
        let fired = Arc::new(std::sync::Mutex::new(Vec::<std::net::SocketAddr>::new()));
        let hook: ListeningHook = {
            let fired = fired.clone();
            Arc::new(move |addr| fired.lock().unwrap().push(addr))
        };
        // Occupy the port so the first bind fails.
        let held = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = held.local_addr().unwrap().port();
        let err = bind_local_listener(port, Some(&hook))
            .await
            .expect_err("the port is held");
        assert!(
            format!("{err:#}").contains(&format!("binding 127.0.0.1:{port}")),
            "{err:#}"
        );
        assert!(
            fired.lock().unwrap().is_empty(),
            "a failed bind is not a serving listener"
        );
        drop(held);

        let listener = bind_local_listener(port, Some(&hook)).await.unwrap();
        assert_eq!(
            fired.lock().unwrap().as_slice(),
            &[listener.local_addr().unwrap()],
            "fired once, with the bound address"
        );
        drop(listener);
        assert!(bind_local_listener(port, None).await.is_ok());
        assert_eq!(fired.lock().unwrap().len(), 1, "no hook, no call");
    }

    /// The whole point of [`AbortOnDrop`]: a bare `JoinHandle` DETACHES on
    /// drop, so an early `?` left the dispatcher running and pinning the peer
    /// — which is how devbox accumulated 15,446 UDP sockets and lost DNS.
    #[tokio::test]
    async fn a_dropped_guard_aborts_its_task_rather_than_detaching_it() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Simulate a driver that returns early: the guard goes out of scope
        // while the task is still parked.
        {
            let flag = Arc::clone(&flag);
            let _guard = AbortOnDrop(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                flag.store(true, Ordering::SeqCst);
            }));
        }

        // Well past the task's own sleep. A detached task would have fired.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !flag.load(Ordering::SeqCst),
            "the task kept running after its guard was dropped — \
             this is the detach that leaked the peer"
        );
    }

    /// Sanity: the guard is transparent, so `select!`ing on it and calling
    /// `abort()` through it keep working (both are live call sites).
    #[tokio::test]
    async fn the_guard_derefs_to_its_handle() {
        let mut guard = AbortOnDrop(tokio::spawn(async { 7u8 }));
        let got = (&mut *guard).await.expect("task completed");
        assert_eq!(got, 7);
        guard.abort(); // already finished — must not panic
    }

    /// Test sink that forwards every emitted `ClientMsg` onto an unbounded
    /// channel the test drains, standing in for the CLI's `WsSink`. Replaces
    /// the pre-seam `outbound_tx: mpsc::Sender<ClientMsg>` the moved functions
    /// took directly.
    struct MockSink {
        tx: mpsc::UnboundedSender<ClientMsg>,
    }

    #[async_trait]
    impl TunnelSignalingSink for MockSink {
        async fn send(&self, msg: ClientMsg) -> anyhow::Result<()> {
            self.tx
                .send(msg)
                .map_err(|e| anyhow::anyhow!("mock sink closed: {e}"))
        }
    }

    /// #1754 — a live [`TerminateOnDrop`] that is simply dropped sends exactly
    /// one `rc:tunnel.terminate` (reason `ClientShutdown`) for its session. This
    /// is the early-`?`-return / normal-completion path: the driver returns and
    /// the guard tells the far side to reap its per-session peer.
    #[tokio::test]
    async fn terminate_guard_sends_one_terminate_on_drop() {
        let (tx, mut rx) = mpsc::unbounded_channel::<ClientMsg>();
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx });
        let sid = ObjectId::new();
        {
            let _g = TerminateOnDrop::new(sink.clone(), sid);
        } // dropped here → Drop spawns the send

        let msg = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("the guard must send a terminate within the deadline")
            .expect("a message reached the sink");
        match msg {
            ClientMsg::TunnelTerminate { session_id, reason } => {
                assert_eq!(session_id, sid, "the terminate names the guard's session");
                assert_eq!(
                    reason,
                    CloseReason::ClientShutdown,
                    "a client-abandoned session terminates as ClientShutdown"
                );
            }
            other => panic!("expected TunnelTerminate, got {other:?}"),
        }
        // Exactly one — the guard fires once, not per poll.
        assert!(
            rx.try_recv().is_err(),
            "the guard must send exactly one terminate"
        );
    }

    /// #1754 — a guard whose terminate was already handled (`disarm`) stays
    /// silent on drop, so a path that sent its own terminate doesn't force a
    /// second. (The live drivers instead accept the harmless duplicate; this
    /// locks the suppression the `fired` flag provides.)
    #[tokio::test]
    async fn a_disarmed_terminate_guard_stays_silent() {
        let (tx, mut rx) = mpsc::unbounded_channel::<ClientMsg>();
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx });
        {
            let g = TerminateOnDrop::new(sink.clone(), ObjectId::new());
            g.disarm();
        } // dropped here → Drop must NOT spawn a send

        // Give any (erroneously) spawned send real time to run before asserting,
        // so this is a genuine check and not a race that passes vacuously.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            rx.try_recv().is_err(),
            "a disarmed guard must not send a terminate"
        );
    }

    /// #1754, the crux: the guard delivers a terminate **even when its owning
    /// task is aborted** — which is exactly what `kill_flow` does to the flow
    /// supervisor. `Drop` runs as the aborted future is torn down and spawns an
    /// INDEPENDENT task for the send, so the abort that killed the owner can't
    /// kill the delivery. Mirrors `AbortOnDrop`'s own detach test, inverted.
    #[tokio::test]
    async fn terminate_guard_fires_even_when_its_task_is_aborted() {
        let (tx, mut rx) = mpsc::unbounded_channel::<ClientMsg>();
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx });
        let sid = ObjectId::new();

        let task = tokio::spawn(async move {
            let _g = TerminateOnDrop::new(sink, sid);
            // Park with the guard live in scope, the way the driver parks on
            // `wait_pool_open` / the accept loop when `kill_flow` aborts it.
            std::future::pending::<()>().await;
        });
        // Let the task reach the park with the guard in scope.
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();

        let msg = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("the guard must deliver a terminate from the aborted task")
            .expect("a message reached the sink");
        assert!(
            matches!(
                msg,
                ClientMsg::TunnelTerminate { session_id, reason }
                    if session_id == sid && reason == CloseReason::ClientShutdown
            ),
            "the aborted task's guard must still send the session's terminate"
        );
    }

    /// Phase 3d: `pick_turn_creds` must select the TURN ICE server (with
    /// usable UDP creds) out of the production list — which leads with a
    /// credential-less STUN entry — and ignore a creds-less or
    /// TLS/TCP-only list (→ direct QUIC, no relay).
    #[test]
    fn pick_turn_creds_selects_the_udp_turn_server() {
        let ice = vec![
            IceServer {
                urls: vec!["stun:stun.l.google.com:19302".into()],
                username: None,
                credential: None,
            },
            IceServer {
                urls: vec![
                    "turn:coturn.roomler.ai:3478?transport=udp".into(),
                    "turns:coturn.roomler.ai:5349?transport=tcp".into(),
                ],
                username: Some("1780000000:sess".into()),
                credential: Some("base64hmac".into()),
            },
        ];
        let (urls, user, cred) = pick_turn_creds(&ice).expect("must find the TURN server");
        assert!(urls.iter().any(|u| u.starts_with("turn:")));
        assert_eq!(user, "1780000000:sess");
        assert_eq!(cred, "base64hmac");

        // STUN-only → no relay creds.
        let stun_only = vec![IceServer {
            urls: vec!["stun:stun.l.google.com:19302".into()],
            username: None,
            credential: None,
        }];
        assert!(pick_turn_creds(&stun_only).is_none());

        // TURN url present but no creds → unusable.
        let no_creds = vec![IceServer {
            urls: vec!["turn:coturn.roomler.ai:3478?transport=udp".into()],
            username: None,
            credential: None,
        }];
        assert!(pick_turn_creds(&no_creds).is_none());
    }

    #[test]
    fn transport_pref_advertises_and_requests_correctly() {
        // Locks the exact wire strings transport negotiation depends on
        // (catches accidental drift in the tunnel_core consts).
        assert_eq!(
            TransportPref::Webrtc.supported_transports(),
            vec!["webrtc-dc-v1".to_string()]
        );
        assert_eq!(TransportPref::Webrtc.request_transport(), "webrtc-dc-v1");

        assert_eq!(
            TransportPref::Quic.supported_transports(),
            vec!["quic-v1".to_string()]
        );
        assert_eq!(TransportPref::Quic.request_transport(), "quic-v1");

        // Auto advertises BOTH (quic first = preference order) + requests quic.
        assert_eq!(
            TransportPref::Auto.supported_transports(),
            vec!["quic-v1".to_string(), "webrtc-dc-v1".to_string()]
        );
        assert_eq!(TransportPref::Auto.request_transport(), "quic-v1");

        // Default is Auto now that server-side QUIC negotiation (Phase
        // 1c) is deployed: prefer QUIC, fall back to WebRTC on failure.
        assert_eq!(TransportPref::default(), TransportPref::Auto);
    }

    /// Client glue: [`handle_local_connection_quic`] sends the forward
    /// request, on `Accept` opens a QUIC flow, and `run_flow_quic` pumps
    /// the local TCP socket to the agent and back. The "agent" here is
    /// built from tunnel-core primitives (server endpoint + auth +
    /// accept_flow + run_flow_quic to a loopback echo dst) — the
    /// symmetric counterpart to the agent crate's
    /// `handle_forward_request_quic` test.
    #[tokio::test(flavor = "multi_thread")]
    async fn quic_local_connection_requests_accepts_and_pumps() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Loopback TCP echo "dst" the agent dials.
        let dst = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst_port = dst.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = dst.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // "Agent": quinn server endpoint that authenticates the client,
        // accepts one flow, dials the echo dst, and pumps it.
        let (agent, fp) = QuicPeer::server("127.0.0.1:0".parse().unwrap()).unwrap();
        let agent_addr = agent.local_addr().unwrap();
        let token = "client-glue-token".to_string();
        let token_a = token.clone();
        // Keep the agent-side Connection + Endpoint alive until the
        // client has drained the echo: run_flow_quic hands the tail
        // bytes + FIN to quinn's send buffer and returns, and if the
        // task then drops `conn`/`agent` the implicit CONNECTION_CLOSE
        // races delivery. On a loaded CI runner the close wins → the
        // client's read_to_end comes back short (the every-other-run
        // CI flake on this test). Production is immune — real call
        // sites pump flows on a session-long connection.
        let (agent_done_tx, agent_done_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let conn = agent.accept().await.unwrap().unwrap();
            quic::server_authenticate(&conn, &token_a).await.unwrap();
            let (flow_id, send, recv) = quic::accept_flow(&conn).await.unwrap();
            let dst_tcp = tokio::net::TcpStream::connect(("127.0.0.1", dst_port))
                .await
                .unwrap();
            let stats = Arc::new(crate::forward::FlowStats::default());
            run_flow_quic(dst_tcp, send, recv, flow_id, stats).await;
            let _ = agent_done_rx.await;
            drop((conn, agent));
        });

        // Client: connect + authenticate (cert pinned to the agent's fp).
        let client = QuicPeer::client("127.0.0.1:0".parse().unwrap(), &fp).unwrap();
        let conn = Arc::new(client.connect(agent_addr).await.unwrap());
        quic::client_authenticate(&conn, &token).await.unwrap();

        // Local app socket <-> the `tcp` we hand to the glue.
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let app = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        let (tcp, _) = local_listener.accept().await.unwrap();

        // Pre-arm the reply oneshot with Accept (in production the WS
        // dispatcher fills this from the server's TcpForwardAccept).
        let (reply_tx, reply_rx) = oneshot::channel::<ForwardReply>();
        reply_tx.send(ForwardReply::Accept { dc_index: 0 }).unwrap();

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx: outbound_tx });
        let reply_registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
        let active_flows: ActiveFlows = Arc::new(Mutex::new(HashMap::new()));
        let session_id = ObjectId::new();
        let flow_id = 1u32;

        let conn_c = Arc::clone(&conn);
        let glue = tokio::spawn(async move {
            handle_local_connection_quic(
                tcp,
                "127.0.0.1:0".parse().unwrap(),
                flow_id,
                session_id,
                conn_c,
                "echo.intranet",
                dst_port,
                sink,
                reply_rx,
                reply_registry,
                active_flows,
                false,
                Arc::new(SessionThroughput::default()),
                Arc::new(std::sync::atomic::AtomicU32::new(0)),
                Arc::new(Notify::new()),
            )
            .await
        });

        // The glue sends a TcpForwardRequest first.
        match outbound_rx
            .recv()
            .await
            .expect("expected TcpForwardRequest from glue")
        {
            ClientMsg::TcpForwardRequest {
                flow_id: f,
                dst_port: p,
                ..
            } => {
                assert_eq!(f, flow_id);
                assert_eq!(p, dst_port);
            }
            other => panic!("expected TcpForwardRequest, got {other:?}"),
        }

        // Local app writes, half-closes; expects the echo back over QUIC.
        let (mut app_r, mut app_w) = app.into_split();
        app_w.write_all(b"ping over client quic").await.unwrap();
        app_w.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        app_r.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(
            &echoed, b"ping over client quic",
            "bytes must round-trip the local TCP ↔ QUIC ↔ agent ↔ dst loop"
        );
        // Echo fully read — the agent task may now release its
        // Connection/Endpoint.
        let _ = agent_done_tx.send(());

        glue.await.unwrap().expect("glue returns Ok");
        // After the flow ends the glue emits TcpClosed for audit.
        match outbound_rx
            .recv()
            .await
            .expect("expected TcpClosed after flow end")
        {
            ClientMsg::TcpClosed {
                flow_id: f,
                bytes_in,
                bytes_out,
                ..
            } => {
                assert_eq!(f, flow_id);
                // Wave 3 — the close carries the flow's REAL totals. Only
                // the endpoints ever see tunnel payload, so if these were
                // plumbed but never populated the audit row would keep
                // recording zero and nobody would notice. The echo loop
                // moved the same payload each way.
                let n = b"ping over client quic".len() as u64;
                assert_eq!(
                    bytes_out, n,
                    "bytes_out must be what the local app SENT (tcp_read)"
                );
                assert_eq!(
                    bytes_in, n,
                    "bytes_in must be what the local app RECEIVED (tcp_write)"
                );
            }
            other => panic!("expected TcpClosed, got {other:?}"),
        }
    }

    /// Test source that yields `ServerMsg`s from an mpsc channel, standing in
    /// for the CLI's `WsSource` / the daemon's per-session demux receiver.
    struct MockSource {
        rx: mpsc::Receiver<ServerMsg>,
    }

    #[async_trait]
    impl crate::signaling_link::TunnelSignalingSource for MockSource {
        async fn recv(&mut self) -> Option<ServerMsg> {
            self.rx.recv().await
        }
    }

    /// P7 flap resilience: the agent's canonical "tunnel session not open on
    /// agent" reject (`RejectKind::AgentError` + `REJECT_REASON_SESSION_GONE`)
    /// must END the dispatch loop — the agent lost its session state on a WS
    /// reconnect and will reject every future forward, so the session fn has
    /// to return and let the flow supervisor re-open. An ordinary reject
    /// (here: `DialFailed`) must NOT end the loop; those are per-flow
    /// failures on a healthy session. Locks the session-death signature.
    #[tokio::test]
    async fn quic_dispatch_loop_exits_on_session_gone_reject() {
        let session_id = ObjectId::new();
        let (src_tx, src_rx) = mpsc::channel::<ServerMsg>(8);
        let (sink_tx, _sink_rx) = mpsc::unbounded_channel();
        let source: Box<dyn crate::signaling_link::TunnelSignalingSource> =
            Box::new(MockSource { rx: src_rx });
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx: sink_tx });
        let reply_registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
        let active_flows: ActiveFlows = Arc::new(Mutex::new(HashMap::new()));

        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        reply_registry.lock().await.insert(1, tx1);
        reply_registry.lock().await.insert(2, tx2);

        let loop_task = tokio::spawn(quic_dispatch_loop(
            source,
            session_id,
            Arc::clone(&reply_registry),
            active_flows,
            sink,
        ));

        // An ordinary reject is delivered to its flow and the loop survives.
        src_tx
            .send(ServerMsg::TcpForwardReject {
                session_id,
                flow_id: 1,
                kind: RejectKind::DialFailed,
                reason: "connection refused".into(),
            })
            .await
            .unwrap();
        match tokio::time::timeout(Duration::from_secs(2), rx1)
            .await
            .expect("reply for flow 1")
            .expect("oneshot delivered")
        {
            ForwardReply::Reject { kind, .. } => assert_eq!(kind, RejectKind::DialFailed),
            ForwardReply::Accept { .. } => panic!("expected reject for flow 1"),
        }
        assert!(
            !loop_task.is_finished(),
            "an ordinary reject must not end the dispatch loop"
        );

        // The session-gone reject is delivered AND ends the loop.
        src_tx
            .send(ServerMsg::TcpForwardReject {
                session_id,
                flow_id: 2,
                kind: RejectKind::AgentError,
                reason: REJECT_REASON_SESSION_GONE.into(),
            })
            .await
            .unwrap();
        match tokio::time::timeout(Duration::from_secs(2), rx2)
            .await
            .expect("reply for flow 2")
            .expect("oneshot delivered")
        {
            ForwardReply::Reject { kind, .. } => assert_eq!(kind, RejectKind::AgentError),
            ForwardReply::Accept { .. } => panic!("expected reject for flow 2"),
        }
        tokio::time::timeout(Duration::from_secs(2), loop_task)
            .await
            .expect("dispatch loop must exit on the session-gone reject")
            .expect("loop task must not panic");
    }

    /// The session-death matcher must fire for ALL THREE `AgentError`
    /// session-death reasons — the agent's `SESSION_GONE` plus the two SERVER
    /// reasons added 2026-07-25 (`NO_SESSION`, `SESSION_MISMATCH`) whose
    /// absence left the pcon-mssql forward route zombied at rc.223 — including
    /// a wrapped/prefixed form, and must NOT fire for ordinary per-flow
    /// rejects (dial failure, ACL deny) or an unrelated AgentError.
    #[test]
    fn session_death_reject_matcher() {
        for reason in [
            REJECT_REASON_SESSION_GONE,
            REJECT_REASON_NO_SESSION,
            REJECT_REASON_SESSION_MISMATCH,
        ] {
            assert!(
                is_session_gone_reject(RejectKind::AgentError, reason),
                "session-death reason {reason:?} must match"
            );
        }
        assert!(
            is_session_gone_reject(
                RejectKind::AgentError,
                &format!("relay: {REJECT_REASON_NO_SESSION}")
            ),
            "a wrapped session-death reason must still match (contains)"
        );
        // Ordinary per-flow failures on a HEALTHY session must NOT end it.
        assert!(!is_session_gone_reject(
            RejectKind::DialFailed,
            "connection refused"
        ));
        assert!(!is_session_gone_reject(
            RejectKind::AclDenied,
            "dst not in allowlist"
        ));
        assert!(!is_session_gone_reject(
            RejectKind::AgentError,
            "DC pool not ready on agent"
        ));
    }

    /// The consecutive-forward-timeout backstop trips at exactly
    /// `MAX_CONSECUTIVE_FLOW_TIMEOUTS`, and any reply (`record_flow_progress`)
    /// resets the streak so intermittent single timeouts never accumulate to a
    /// spurious session kill.
    #[test]
    fn consecutive_flow_timeout_backstop() {
        use std::sync::atomic::AtomicU32;
        let streak = AtomicU32::new(0);
        // The first MAX-1 timeouts are non-fatal.
        for i in 1..MAX_CONSECUTIVE_FLOW_TIMEOUTS {
            assert!(
                !record_flow_timeout(&streak),
                "timeout {i} of {MAX_CONSECUTIVE_FLOW_TIMEOUTS} must not be fatal"
            );
        }
        // A reply resets the streak.
        record_flow_progress(&streak);
        // So the count has to climb from scratch again.
        for i in 1..MAX_CONSECUTIVE_FLOW_TIMEOUTS {
            assert!(
                !record_flow_timeout(&streak),
                "post-reset timeout {i} must not be fatal"
            );
        }
        // Reaching the threshold is fatal.
        assert!(
            record_flow_timeout(&streak),
            "the {MAX_CONSECUTIVE_FLOW_TIMEOUTS}th consecutive timeout must be fatal"
        );
    }

    /// A loopback "exit": a QUIC server endpoint that authenticates one
    /// client, then serves every flow it opens by dialing the loopback echo
    /// `dst_port` and pumping — until `stop` fires or the connection ends.
    /// Returns the cert fingerprint to pin and the dial address.
    fn spawn_quic_exit(
        token: &str,
        dst_port: u16,
        stop: oneshot::Receiver<()>,
    ) -> (String, std::net::SocketAddr) {
        let (agent, fp) = QuicPeer::server("127.0.0.1:0".parse().unwrap()).unwrap();
        let agent_addr = agent.local_addr().unwrap();
        let token = token.to_string();
        tokio::spawn(async move {
            let conn = agent.accept().await.unwrap().unwrap();
            quic::server_authenticate(&conn, &token).await.unwrap();
            let serve = async {
                while let Ok((flow_id, send, recv)) = quic::accept_flow(&conn).await {
                    let dst_tcp = tokio::net::TcpStream::connect(("127.0.0.1", dst_port))
                        .await
                        .unwrap();
                    tokio::spawn(async move {
                        let stats = Arc::new(crate::forward::FlowStats::default());
                        run_flow_quic(dst_tcp, send, recv, flow_id, stats).await;
                    });
                }
            };
            tokio::select! {
                _ = serve => {}
                _ = stop => {}
            }
            // An explicit close so the client's `conn.closed()` fires at once
            // rather than at quinn's idle timeout.
            conn.close(0u32.into(), b"exit stopped");
            drop(agent);
        });
        (fp, agent_addr)
    }

    /// A loopback TCP echo the exit dials.
    async fn spawn_echo_dst() -> u16 {
        let dst = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dst.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = dst.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    /// The control plane a test drives: the sink it reads, the source it feeds.
    struct TestControl {
        sink_rx: mpsc::UnboundedReceiver<ClientMsg>,
        src_tx: mpsc::Sender<ServerMsg>,
    }

    /// Build a real QUIC [`Carrier`] the way `establish_quic` does — the real
    /// `quic_dispatch_loop` over a channel source, the real guard — over a
    /// connection the test already authenticated.
    fn quic_carrier_for_test(
        conn: QuicConnection,
        client: QuicPeer,
        session_id: ObjectId,
        dst_port: u16,
    ) -> (Carrier, TestControl) {
        let (sink_tx, sink_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx: sink_tx });
        let (src_tx, src_rx) = mpsc::channel::<ServerMsg>(8);
        let source: Box<dyn TunnelSignalingSource> = Box::new(MockSource { rx: src_rx });
        let reply_registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
        let active_flows: ActiveFlows = Arc::new(Mutex::new(HashMap::new()));
        let (done_tx, dispatcher_done) = watch::channel(());
        let dispatcher = AbortOnDrop({
            let reply_registry = Arc::clone(&reply_registry);
            let active_flows = Arc::clone(&active_flows);
            let sink = sink.clone();
            tokio::spawn(async move {
                let _done = done_tx;
                quic_dispatch_loop(source, session_id, reply_registry, active_flows, sink).await
            })
        });
        let carrier = Carrier {
            transport: TRANSPORT_QUIC_V1,
            session_id,
            sink: sink.clone(),
            target: Target::Static {
                host: "echo.intranet".into(),
                port: dst_port,
            },
            session: Arc::new(SessionThroughput::default()),
            reply_registry,
            active_flows,
            flow_counter: Arc::new(AtomicU32::new(1)),
            flow_timeout_streak: Arc::new(AtomicU32::new(0)),
            session_dead: Arc::new(Notify::new()),
            in_flight: Arc::new(AtomicU64::new(0)),
            idle: Arc::new(Notify::new()),
            dispatcher_done,
            _dispatcher: dispatcher,
            plane: Plane::Quic {
                conn: Arc::new(conn),
                _peer: Arc::new(client),
            },
            _terminate: TerminateOnDrop::new(sink, session_id),
        };
        (carrier, TestControl { sink_rx, src_tx })
    }

    async fn next_client_msg(rx: &mut mpsc::UnboundedReceiver<ClientMsg>, what: &str) -> ClientMsg {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected {what} within 2 s"))
            .expect("sink open")
    }

    /// FR-86 P1 — a real [`Carrier`] over a loopback QUIC pair: `carry`
    /// forwards an accepted connection through the session end to end (the
    /// forward request → the real dispatcher's accept → a QUIC flow → the
    /// pump, bytes round-tripping through the exit's echo), `active()` counts
    /// it while it runs and drops back when it ends, `dead()` stays pending on
    /// a healthy session and resolves when the control channel ends (the WS
    /// dropped), and dropping the carrier sends the session's terminate — the
    /// #1754 guard that moved into it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_quic_carrier_carries_counts_dies_and_terminates() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dst_port = spawn_echo_dst().await;
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let (fp, agent_addr) = spawn_quic_exit("carrier-token", dst_port, stop_rx);
        let client = QuicPeer::client("127.0.0.1:0".parse().unwrap(), &fp).unwrap();
        let conn = client.connect(agent_addr).await.unwrap();
        quic::client_authenticate(&conn, "carrier-token")
            .await
            .unwrap();
        let session_id = ObjectId::new();
        let (carrier, mut ctl) = quic_carrier_for_test(conn, client, session_id, dst_port);
        assert_eq!(carrier.transport(), TRANSPORT_QUIC_V1);
        assert_eq!(carrier.session_id(), session_id);
        assert_eq!(carrier.active(), 0);

        // A local app connects to "the flow's listener" — a bare listener the
        // test accepts on — and the accepted side is carried.
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = tokio::net::TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (tcp, peer_addr) = local.accept().await.unwrap();
        carrier.carry(tcp, peer_addr);
        assert_eq!(carrier.active(), 1, "a carried connection is in flight");

        // The carrier asked for the forward; answer through the real dispatcher.
        let flow_id = match next_client_msg(&mut ctl.sink_rx, "TcpForwardRequest").await {
            ClientMsg::TcpForwardRequest {
                session_id: sid,
                flow_id,
                dst_host,
                dst_port: p,
            } => {
                assert_eq!(sid, session_id);
                assert_eq!(dst_host, "echo.intranet");
                assert_eq!(p, dst_port);
                flow_id
            }
            other => panic!("expected TcpForwardRequest, got {other:?}"),
        };
        ctl.src_tx
            .send(ServerMsg::TcpForwardAccept {
                session_id,
                flow_id,
                dc_index: 0,
            })
            .await
            .unwrap();

        // Bytes round-trip: app → carrier → QUIC → exit → echo → back.
        let (mut app_r, mut app_w) = app.into_split();
        app_w.write_all(b"ping through a carrier").await.unwrap();
        app_w.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        app_r.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping through a carrier");
        match next_client_msg(&mut ctl.sink_rx, "TcpClosed").await {
            ClientMsg::TcpClosed { flow_id: f, .. } => assert_eq!(f, flow_id),
            other => panic!("expected TcpClosed, got {other:?}"),
        }
        for _ in 0..40 {
            if carrier.active() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            carrier.active(),
            0,
            "the in-flight count drops when the connection's task ends"
        );

        // Healthy: `dead()` stays pending (and is cancel-safe — this drops it).
        assert!(
            tokio::time::timeout(Duration::from_millis(300), carrier.dead())
                .await
                .is_err(),
            "a healthy carrier is not dead"
        );
        // The control channel ends (the WS dropped): the dispatcher exits and
        // `dead()` resolves — the old "control channel closed" arm.
        drop(ctl.src_tx);
        tokio::time::timeout(Duration::from_secs(2), carrier.dead())
            .await
            .expect("dead() resolves when the control channel closes");
        assert!(
            ctl.sink_rx.try_recv().is_err(),
            "a control-channel close sends no terminate of its own (the guard does, on drop)"
        );

        // Dropping the carrier ends the session: the guard's terminate goes out.
        drop(carrier);
        let msg = next_client_msg(&mut ctl.sink_rx, "the guard's TunnelTerminate").await;
        assert!(
            matches!(
                msg,
                ClientMsg::TunnelTerminate { session_id: sid, reason: CloseReason::ClientShutdown }
                    if sid == session_id
            ),
            "dropping the carrier must terminate its session: {msg:?}"
        );
        let _ = stop_tx.send(());
    }

    /// FR-86 P1 — the QUIC connection dying is the carrier's death (the P7
    /// flap-resilience arm, unchanged): `dead()` resolves, the `io_error`
    /// terminate the accept loop used to send goes out, and the guard's own
    /// follows on drop — the harmless duplicate the server absorbs.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_quic_carrier_is_dead_when_its_connection_closes() {
        let dst_port = spawn_echo_dst().await;
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let (fp, agent_addr) = spawn_quic_exit("carrier-token-2", dst_port, stop_rx);
        let client = QuicPeer::client("127.0.0.1:0".parse().unwrap(), &fp).unwrap();
        let conn = client.connect(agent_addr).await.unwrap();
        quic::client_authenticate(&conn, "carrier-token-2")
            .await
            .unwrap();
        let session_id = ObjectId::new();
        let (carrier, mut ctl) = quic_carrier_for_test(conn, client, session_id, dst_port);

        assert!(
            tokio::time::timeout(Duration::from_millis(300), carrier.dead())
                .await
                .is_err(),
            "a healthy carrier is not dead"
        );
        // The exit closes the connection under us.
        let _ = stop_tx.send(());
        tokio::time::timeout(Duration::from_secs(5), carrier.dead())
            .await
            .expect("dead() resolves when the QUIC connection closes");
        let msg = next_client_msg(&mut ctl.sink_rx, "the io_error TunnelTerminate").await;
        assert!(
            matches!(
                msg,
                ClientMsg::TunnelTerminate { session_id: sid, reason: CloseReason::IoError }
                    if sid == session_id
            ),
            "a lost QUIC connection must terminate the session as io_error: {msg:?}"
        );
        drop(carrier);
        let msg = next_client_msg(&mut ctl.sink_rx, "the guard's TunnelTerminate").await;
        assert!(
            matches!(
                msg,
                ClientMsg::TunnelTerminate { session_id: sid, reason: CloseReason::ClientShutdown }
                    if sid == session_id
            ),
            "the guard still fires on drop: {msg:?}"
        );
    }

    /// FR-86 P2 — [`Carrier::drained`]: an idle carrier is already drained; a
    /// carrier with a connection in flight is NOT drained until that connection
    /// ends, at which point `drained()` resolves (the signal a draining carrier
    /// is closed on). Real QUIC loopback so the count is driven by a real flow.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_carrier_is_drained_when_idle_and_pends_until_its_last_connection_ends() {
        let dst_port = spawn_echo_dst().await;
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let (fp, agent_addr) = spawn_quic_exit("drain-token", dst_port, stop_rx);
        let client = QuicPeer::client("127.0.0.1:0".parse().unwrap(), &fp).unwrap();
        let conn = client.connect(agent_addr).await.unwrap();
        quic::client_authenticate(&conn, "drain-token")
            .await
            .unwrap();
        let session_id = ObjectId::new();
        let (carrier, mut ctl) = quic_carrier_for_test(conn, client, session_id, dst_port);

        // Idle at construction: drained() resolves at once.
        tokio::time::timeout(Duration::from_millis(500), carrier.drained())
            .await
            .expect("an idle carrier is already drained");

        // Carry one connection: now busy.
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = tokio::net::TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (tcp, peer_addr) = local.accept().await.unwrap();
        carrier.carry(tcp, peer_addr);
        assert_eq!(carrier.active(), 1);
        let flow_id = match next_client_msg(&mut ctl.sink_rx, "TcpForwardRequest").await {
            ClientMsg::TcpForwardRequest { flow_id, .. } => flow_id,
            other => panic!("expected TcpForwardRequest, got {other:?}"),
        };
        ctl.src_tx
            .send(ServerMsg::TcpForwardAccept {
                session_id,
                flow_id,
                dc_index: 0,
            })
            .await
            .unwrap();
        // Busy: drained() must NOT resolve.
        assert!(
            tokio::time::timeout(Duration::from_millis(400), carrier.drained())
                .await
                .is_err(),
            "a carrier with a connection in flight is not drained"
        );

        // The app closes: the flow ends, active → 0, drained() resolves.
        drop(app);
        tokio::time::timeout(Duration::from_secs(5), carrier.drained())
            .await
            .expect("drained() resolves once the last connection ends");
        assert_eq!(carrier.active(), 0);
        let _ = stop_tx.send(());
    }

    /// FR-86 P2, the make-before-break core (AC2), end to end over TWO real
    /// QUIC carriers behind one [`FlowListener`]: a connection established on
    /// carrier A keeps flowing bytes AFTER carrier B is installed (promoted),
    /// while a NEW connection rides B — and A drains only when its own
    /// connection ends. The promotion is `listener.install(B)`; A is never
    /// touched by it. (The supervisor's decision to DROP a drained carrier is
    /// covered, with its promote-by-cut negative control, in
    /// `client_mgr`'s `drain_carrier` test.)
    #[tokio::test(flavor = "multi_thread")]
    async fn make_before_break_a_keeps_flowing_while_b_takes_new_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;

        let dst_port = spawn_echo_dst().await;

        // ── Carrier A + its exit ──────────────────────────────────────
        let (stop_a, stop_a_rx) = oneshot::channel::<()>();
        let (fp_a, addr_a) = spawn_quic_exit("mbb-a", dst_port, stop_a_rx);
        let client_a = QuicPeer::client("127.0.0.1:0".parse().unwrap(), &fp_a).unwrap();
        let conn_a = client_a.connect(addr_a).await.unwrap();
        quic::client_authenticate(&conn_a, "mbb-a").await.unwrap();
        let sid_a = ObjectId::new();
        let (carrier_a, mut ctl_a) = quic_carrier_for_test(conn_a, client_a, sid_a, dst_port);
        let carrier_a = Arc::new(carrier_a);

        // ── The flow's listener, A installed ──────────────────────────
        let listener = crate::flow_listener::FlowListener::bind(
            0,
            crate::flow_listener::HoldPolicy::default(),
        )
        .await
        .unwrap();
        let laddr = listener.local_addr();
        listener.install(Arc::clone(&carrier_a));

        // A local app connects → carried by A; drive its forward accept.
        let app1 = tokio::net::TcpStream::connect(laddr).await.unwrap();
        let fid1 = match next_client_msg(&mut ctl_a.sink_rx, "A TcpForwardRequest").await {
            ClientMsg::TcpForwardRequest {
                session_id,
                flow_id,
                ..
            } => {
                assert_eq!(session_id, sid_a);
                flow_id
            }
            other => panic!("expected TcpForwardRequest on A, got {other:?}"),
        };
        ctl_a
            .src_tx
            .send(ServerMsg::TcpForwardAccept {
                session_id: sid_a,
                flow_id: fid1,
                dc_index: 0,
            })
            .await
            .unwrap();
        let (mut r1, mut w1) = app1.into_split();
        let mut buf = [0u8; 2];
        w1.write_all(b"a1").await.unwrap();
        timeout(Duration::from_secs(5), r1.read_exact(&mut buf))
            .await
            .expect("A echo timely")
            .unwrap();
        assert_eq!(&buf, b"a1");
        assert_eq!(carrier_a.active(), 1);

        // ── PROMOTE: build carrier B + its exit, install it ───────────
        let (stop_b, stop_b_rx) = oneshot::channel::<()>();
        let (fp_b, addr_b) = spawn_quic_exit("mbb-b", dst_port, stop_b_rx);
        let client_b = QuicPeer::client("127.0.0.1:0".parse().unwrap(), &fp_b).unwrap();
        let conn_b = client_b.connect(addr_b).await.unwrap();
        quic::client_authenticate(&conn_b, "mbb-b").await.unwrap();
        let sid_b = ObjectId::new();
        let (carrier_b, mut ctl_b) = quic_carrier_for_test(conn_b, client_b, sid_b, dst_port);
        let carrier_b = Arc::new(carrier_b);
        listener.install(Arc::clone(&carrier_b)); // new connections → B; A untouched

        // A's established connection KEEPS FLOWING after the swap.
        w1.write_all(b"a2").await.unwrap();
        timeout(Duration::from_secs(5), r1.read_exact(&mut buf))
            .await
            .expect("A still echoes after B is promoted")
            .unwrap();
        assert_eq!(
            &buf, b"a2",
            "an established connection keeps flowing on carrier A after B is promoted"
        );
        assert_eq!(
            carrier_a.active(),
            1,
            "A still carries its established connection"
        );

        // A NEW connection rides B.
        let app2 = tokio::net::TcpStream::connect(laddr).await.unwrap();
        let fid2 = match next_client_msg(&mut ctl_b.sink_rx, "B TcpForwardRequest").await {
            ClientMsg::TcpForwardRequest {
                session_id,
                flow_id,
                ..
            } => {
                assert_eq!(session_id, sid_b);
                flow_id
            }
            other => panic!("expected TcpForwardRequest on B, got {other:?}"),
        };
        ctl_b
            .src_tx
            .send(ServerMsg::TcpForwardAccept {
                session_id: sid_b,
                flow_id: fid2,
                dc_index: 0,
            })
            .await
            .unwrap();
        let (mut r2, mut w2) = app2.into_split();
        w2.write_all(b"b1").await.unwrap();
        timeout(Duration::from_secs(5), r2.read_exact(&mut buf))
            .await
            .expect("B echo timely")
            .unwrap();
        assert_eq!(&buf, b"b1", "a new connection rides carrier B");
        assert_eq!(carrier_b.active(), 1);
        assert!(
            ctl_a.sink_rx.try_recv().is_err(),
            "the new connection must not touch the draining carrier A"
        );

        // ── DRAIN A: close its connection; drained() resolves ─────────
        w1.shutdown().await.unwrap();
        let mut rest = Vec::new();
        let _ = timeout(Duration::from_secs(5), r1.read_to_end(&mut rest)).await;
        timeout(Duration::from_secs(5), carrier_a.drained())
            .await
            .expect("A drains once its established connection ends");
        assert_eq!(carrier_a.active(), 0);
        // B is still serving its connection.
        assert_eq!(carrier_b.active(), 1);

        let _ = stop_a.send(());
        let _ = stop_b.send(());
    }

    /// Build a real client-side WebRTC-DC [`Carrier`] over a loopback peer
    /// pair: the offerer is the client, the answerer stands in for the exit.
    /// Both are returned so the caller can keep them alive — holding the exit
    /// keeps the DC pool open, so the ONLY thing that can end a live flow is
    /// the carrier being dropped. The real [`dispatch_loop`] routes
    /// `TcpForwardAccept` from `TestControl::src_tx` into the reply registry.
    async fn dc_carrier_for_test(
        session_id: ObjectId,
    ) -> (Carrier, TestControl, Arc<TunnelPeer>, TunnelPeer) {
        let offerer = TunnelPeer::new(vec![]).await.unwrap();
        let answerer = TunnelPeer::new(vec![]).await.unwrap();
        let answerer_pc = answerer.peer_connection();
        offerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&answerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });
        let offerer_pc = offerer.peer_connection();
        answerer.on_local_ice_candidate(move |c| {
            let pc = Arc::clone(&offerer_pc);
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc.add_ice_candidate(init).await;
                }
            })
        });
        let offer = offerer.create_offer().await.unwrap();
        let answer = answerer.accept_offer(&offer.sdp).await.unwrap();
        offerer.accept_answer(&answer.sdp).await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), offerer.wait_pool_open())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), answerer.wait_pool_open())
            .await
            .unwrap()
            .unwrap();

        let session = Arc::new(SessionThroughput::default());
        let peer = Arc::new(offerer);
        let mut demuxes = Vec::with_capacity(peer.pool_size() as usize);
        for idx in 0..peer.pool_size() {
            demuxes.push(FlowDemux::install(peer.dc(idx).unwrap(), Some(session.clone())).await);
        }
        let demuxes = Arc::new(demuxes);

        let (sink_tx, sink_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx: sink_tx });
        let (src_tx, src_rx) = mpsc::channel::<ServerMsg>(8);
        let source: Box<dyn TunnelSignalingSource> = Box::new(MockSource { rx: src_rx });
        let reply_registry: ReplyRegistry = Arc::new(Mutex::new(HashMap::new()));
        let active_flows: ActiveFlows = Arc::new(Mutex::new(HashMap::new()));
        let pool_ready = Arc::new(Notify::new());
        let (done_tx, dispatcher_done) = watch::channel(());
        let dispatcher = AbortOnDrop({
            let peer = Arc::clone(&peer);
            let reply_registry = Arc::clone(&reply_registry);
            let active_flows = Arc::clone(&active_flows);
            let pool_ready = Arc::clone(&pool_ready);
            let sink = sink.clone();
            tokio::spawn(async move {
                let _done = done_tx;
                dispatch_loop(
                    source,
                    &peer,
                    session_id,
                    reply_registry,
                    active_flows,
                    pool_ready,
                    sink,
                )
                .await
            })
        });
        let carrier = Carrier {
            transport: TRANSPORT_WEBRTC_DC_V1,
            session_id,
            sink: sink.clone(),
            target: Target::Static {
                host: "echo.intranet".into(),
                port: 22,
            },
            session,
            reply_registry,
            active_flows,
            flow_counter: Arc::new(AtomicU32::new(1)),
            flow_timeout_streak: Arc::new(AtomicU32::new(0)),
            session_dead: Arc::new(Notify::new()),
            in_flight: Arc::new(AtomicU64::new(0)),
            idle: Arc::new(Notify::new()),
            dispatcher_done,
            _dispatcher: dispatcher,
            plane: Plane::Dc {
                _peer: Arc::clone(&peer),
                demuxes,
                rr_counter: Arc::new(AtomicUsize::new(0)),
                cancel: CancelOnDrop::new(),
            },
            _terminate: TerminateOnDrop::new(sink, session_id),
        };
        (carrier, TestControl { sink_rx, src_tx }, peer, answerer)
    }

    /// FR-90 P3-7-3b — a session's carrier takes its listener's credential and
    /// forwards only then: a connection with another password is dropped at
    /// RFC 1929 and asks the exit for nothing; one with the credential asks
    /// for the destination it CONNECTs to.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_carrier_forwards_its_credentials_connections_alone() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        /// RFC 1929 as a client: greet, authenticate as `user` with `pass`,
        /// and CONNECT db.internal:5432 if it was taken.
        async fn socks(
            addr: std::net::SocketAddr,
            user: Vec<u8>,
            pass: Vec<u8>,
        ) -> (TcpStream, u8) {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut sel = [0u8; 2];
            c.read_exact(&mut sel).await.unwrap();
            assert_eq!(sel, [0x05, 0x02], "RFC 1929 selected");
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(&user);
            auth.push(pass.len() as u8);
            auth.extend_from_slice(&pass);
            c.write_all(&auth).await.unwrap();
            let mut status = [0u8; 2];
            c.read_exact(&mut status).await.unwrap();
            if status[1] == 0x00 {
                let host = b"db.internal";
                let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
                req.extend_from_slice(host);
                req.extend_from_slice(&5432u16.to_be_bytes());
                c.write_all(&req).await.unwrap();
            }
            (c, status[1])
        }

        let session_id = ObjectId::new();
        let (mut carrier, mut ctl, _client_peer, _exit_peer) =
            dc_carrier_for_test(session_id).await;
        let cred = crate::socks5::test_credential();
        carrier.target = Target::SessionSocks5(cred.clone());
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = local.local_addr().unwrap();
        let user = cred.username.clone().into_bytes();

        // Another password: refused, and nothing asked of the exit.
        let another = format!("{}x", cred.password).into_bytes();
        let refused = tokio::spawn(socks(addr, user.clone(), another));
        let (tcp, peer_addr) = local.accept().await.unwrap();
        carrier.carry(tcp, peer_addr);
        let (_refused, status) = refused.await.unwrap();
        assert_eq!(status, 0x01, "RFC 1929 failure");
        tokio::time::sleep(Duration::from_millis(200)).await;
        while let Ok(msg) = ctl.sink_rx.try_recv() {
            assert!(
                !matches!(msg, ClientMsg::TcpForwardRequest { .. }),
                "refused, yet forwarded: {msg:?}"
            );
        }

        // Its credential: the exit is asked for the CONNECT's destination.
        let admitted = tokio::spawn(socks(addr, user, cred.password.clone().into_bytes()));
        let (tcp, peer_addr) = local.accept().await.unwrap();
        carrier.carry(tcp, peer_addr);
        let (_admitted, status) = admitted.await.unwrap();
        assert_eq!(status, 0x00, "RFC 1929 success");
        match next_client_msg(&mut ctl.sink_rx, "TcpForwardRequest").await {
            ClientMsg::TcpForwardRequest {
                dst_host, dst_port, ..
            } => assert_eq!((dst_host.as_str(), dst_port), ("db.internal", 5432)),
            other => panic!("expected TcpForwardRequest, got {other:?}"),
        }
    }

    /// #2129 — dropping a WebRTC-DC carrier with a LIVE connection ends that
    /// connection: the app sees EOF/RST and the flow stops, rather than the
    /// flow hanging on an idle app + an idle exit while the DC stays open. The
    /// exit stand-in is held alive precisely so the ONLY thing that can end
    /// the flow is the carrier drop. (An FR-86 drain drops a carrier only at 0
    /// in-flight connections, so the same drop cancels nothing there.) Run
    /// under a timeout so a regression fails red instead of hanging.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_a_dc_carrier_ends_its_live_connection() {
        use tokio::io::AsyncReadExt;

        let session_id = ObjectId::new();
        let (carrier, mut ctl, _client_peer, _exit_peer) = dc_carrier_for_test(session_id).await;

        // A local app connects; the accepted side is carried.
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = tokio::net::TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (tcp, peer_addr) = local.accept().await.unwrap();
        carrier.carry(tcp, peer_addr);
        assert_eq!(carrier.active(), 1, "the carried connection is in flight");

        // Drive the forward accept through the real dispatcher so the flow runs.
        let flow_id = match next_client_msg(&mut ctl.sink_rx, "TcpForwardRequest").await {
            ClientMsg::TcpForwardRequest {
                session_id: sid,
                flow_id,
                ..
            } => {
                assert_eq!(sid, session_id);
                flow_id
            }
            other => panic!("expected TcpForwardRequest, got {other:?}"),
        };
        ctl.src_tx
            .send(ServerMsg::TcpForwardAccept {
                session_id,
                flow_id,
                dc_index: 0,
            })
            .await
            .unwrap();

        // The flow is live; the app and the exit are both idle. It must not
        // end on its own while the carrier lives.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut b = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), app.read(&mut b))
                .await
                .is_err(),
            "the live connection stays open while the carrier lives"
        );

        // Drop the carrier: its DC plane's cancel-on-drop ends the live flow.
        drop(carrier);

        let eof = tokio::time::timeout(Duration::from_secs(2), app.read(&mut b))
            .await
            .expect("dropping the carrier must end the live connection within 2 s");
        assert!(
            matches!(eof, Ok(0) | Err(_)),
            "the app sees EOF or RST, not live bytes: {eof:?}"
        );

        // Keep the exit peer alive until here, so only the carrier drop could
        // have ended the flow.
        drop(_exit_peer);
        drop(_client_peer);
    }

    /// FR-90 P3-7-3a — drive one `establish_tunnel_session` under `grant`:
    /// the frames it sends, the channel the test answers it on, and the task.
    #[allow(clippy::type_complexity)]
    fn open_under(
        grant: Option<SessionGrantRef>,
    ) -> (
        mpsc::UnboundedReceiver<ClientMsg>,
        mpsc::Sender<ServerMsg>,
        tokio::task::JoinHandle<Result<Establishment>>,
    ) {
        let (sink_tx, sink_rx) = mpsc::unbounded_channel::<ClientMsg>();
        let (src_tx, src_rx) = mpsc::channel::<ServerMsg>(8);
        let sink: Arc<dyn TunnelSignalingSink> = Arc::new(MockSink { tx: sink_tx });
        let source: Box<dyn TunnelSignalingSource> = Box::new(MockSource { rx: src_rx });
        let params = SessionParams {
            agent_id: ObjectId::new(),
            target: Target::Socks5,
            client_version: "test".into(),
            derp: None,
            on_listening: None,
            net_grant: grant,
        };
        let task = tokio::spawn(establish_tunnel_session(
            sink,
            source,
            params,
            vec![TRANSPORT_WEBRTC_DC_V1.to_string()],
            TRANSPORT_WEBRTC_DC_V1,
            Arc::new(SessionThroughput::default()),
        ));
        (sink_rx, src_tx, task)
    }

    fn opened_frame(session_id: ObjectId, net_grant_id: Option<&str>) -> ServerMsg {
        ServerMsg::TunnelOpened {
            session_id,
            transport: TRANSPORT_WEBRTC_DC_V1.into(),
            dc_pool_size: 1,
            sctp_rwnd_bytes: 1 << 20,
            ice_servers: vec![],
            quic_auth_token: None,
            open_nonce: None,
            net_grant_id: net_grant_id.map(str::to_string),
        }
    }

    fn a_grant() -> SessionGrantRef {
        SessionGrantRef {
            token: "header.claims.signature".into(),
            grant_id: "g1".into(),
        }
    }

    /// FR-90 P3-7-3a — a grant prints by its id alone: its token is a
    /// credential until its end.
    #[test]
    fn a_grant_ref_prints_its_id_not_its_token() {
        let shown = format!("{:?}", a_grant());
        assert!(shown.contains("g1"), "{shown}");
        assert!(!shown.contains("header.claims.signature"), "{shown}");
    }

    /// The grant's token, as the open carried it.
    async fn open_carried(sink: &mut mpsc::UnboundedReceiver<ClientMsg>) -> Option<String> {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(2), sink.recv())
                .await
                .expect("the driver sends its hello and open")
                .expect("sink open");
            if let ClientMsg::TunnelOpen { net_grant, .. } = msg {
                return net_grant;
            }
        }
    }

    /// FR-90 P3-7-3a — a session's tunnel presents its grant at the open, and
    /// carries none of its flows unless the server bound it: an `opened` with
    /// no echo, or another grant's, ends the tunnel `NotBound`, and the exit is
    /// told.
    #[tokio::test]
    async fn a_session_tunnel_whose_grant_is_not_bound_ends() {
        for echo in [None, Some("another grant")] {
            let (mut sink, src, task) = open_under(Some(a_grant()));
            assert_eq!(
                open_carried(&mut sink).await.as_deref(),
                Some("header.claims.signature")
            );
            let sid = ObjectId::new();
            src.send(opened_frame(sid, echo)).await.unwrap();
            let err = match tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("the open ends")
                .expect("no panic")
            {
                Ok(_) => panic!("{echo:?}: an unbound grant carried the session's flows"),
                Err(e) => e,
            };
            assert_eq!(
                err.downcast_ref::<GrantError>(),
                Some(&GrantError::NotBound),
                "{echo:?}: {err:#}"
            );
            let told = loop {
                match tokio::time::timeout(Duration::from_secs(1), sink.recv()).await {
                    Ok(Some(ClientMsg::TunnelTerminate { session_id, .. })) => break session_id,
                    Ok(Some(_)) => continue,
                    other => panic!("{echo:?}: the exit was never told: {other:?}"),
                }
            };
            assert_eq!(told, sid);
        }
    }

    /// FR-90 P3-7-3a — a refused grant ends the open as `Refused`, in the
    /// server's words. The same code on a tunnel that presented no grant is an
    /// ordinary failure, not a grant's.
    #[tokio::test]
    async fn a_refused_grant_ends_the_open() {
        for grant in [Some(a_grant()), None] {
            let presented = grant.is_some();
            let (mut sink, src, task) = open_under(grant);
            let _ = open_carried(&mut sink).await;
            src.send(ServerMsg::Error {
                session_id: None,
                code: NET_GRANT_REFUSED.into(),
                message: "a grant for another exit".into(),
                open_nonce: None,
            })
            .await
            .unwrap();
            let err = match tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("the open ends")
                .expect("no panic")
            {
                Ok(_) => panic!("a refused open established"),
                Err(e) => e,
            };
            let want = presented.then(|| GrantError::Refused("a grant for another exit".into()));
            assert_eq!(err.downcast_ref::<GrantError>(), want.as_ref(), "{err:#}");
        }
    }

    /// FR-90 P3-7-3a — a grant the server bound (its id echoed) lets the
    /// tunnel go on to its data plane, as a device's own tunnel does with no
    /// grant and no echo.
    #[tokio::test]
    async fn a_bound_grant_goes_on_to_the_data_plane() {
        for (grant, echo) in [(Some(a_grant()), Some("g1")), (None, None)] {
            let (mut sink, src, task) = open_under(grant);
            let _ = open_carried(&mut sink).await;
            src.send(opened_frame(ObjectId::new(), echo)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            if task.is_finished() {
                if let Err(e) = task.await.expect("no panic") {
                    assert!(
                        e.downcast_ref::<GrantError>().is_none(),
                        "{echo:?}: a bound grant ended the tunnel: {e:#}"
                    );
                }
            } else {
                task.abort();
            }
        }
    }
}
