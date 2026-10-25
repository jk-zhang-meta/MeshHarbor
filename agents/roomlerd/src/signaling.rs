// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! WebSocket signaling loop against `/ws?role=agent&token=...`.
//!
//! Handles the full rc:* handshake and owns a map of per-session
//! [`AgentPeer`] values that back each live WebRTC PeerConnection.
//!
//! Reconnect strategy: exponential backoff capped at 60 s, restarted at 1 s by
//! a connection that lived (#2221). An HTTP 401 on upgrade is `AuthRejected`:
//! one token recovery (FR-103), then the auth ladder (30 s, 60 s, 5 min, then
//! hourly) with the re-enrollment sentinel; it never exits. A device whose row
//! is gone hears that 401 too (#2463). Only a typed `rc:goodbye` is fatal.

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use roomler_ai_remote_control::{
    models::{AgentCaps, DisplayInfo, EndReason, OsKind, RpcCap},
    signaling::{AgentCloseReason, ClientMsg, CloseReason, LIMIT_NO_COMMON_CODEC, ServerMsg},
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::AgentConfig;
use crate::indicator::ViewerIndicator;
use crate::notify;
use crate::peer::AgentPeer;
use crate::tunnel::quic_setup::{Begin, QuicSetupError, Settled};
use crate::watchdog;
use tunnel_core::localapi::OverlayView;
use tunnel_core::transport::relay;

/// Capacity of the outbound channel peers use to push `ClientMsg` back into
/// the signaling loop (ICE trickles, terminate signals). 64 is generous for
/// one session's ICE gather phase.
const PEER_OUTBOUND_CAP: usize = 64;

/// Per-flow `connect()` budget for `rc:tunnel.tcp.forward` requests.
/// Matches the dialer's default — see `tunnel::dialer::DEFAULT_TIMEOUT`.
const TUNNEL_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// rc.58: hard upper bound on a single `connect_async` attempt. Without
/// a wrapper, a hung TLS handshake (e.g. server-side renegotiation
/// race against a rustls client that refuses re-negotiation) sits
/// inside `connect_async` indefinitely and the outer backoff ladder
/// never fires. 30 s is much longer than a healthy WSS handshake
/// (<1 s typical) and short enough that the operator notices in field
/// logs. Timeouts are routed through `ConnectError::Transient` so the
/// backoff loop handles them like any other connection failure.
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Receive-liveness deadline for the ESTABLISHED control WS. The server
/// auto-pongs our 25 s keepalive Pings, so a healthy link never goes this
/// long (3 keepalive periods + margin) without SOME inbound frame. Send
/// success alone proves nothing: a TLS-inspecting corp middlebox terminates
/// TCP locally and keeps ACKing our Pings after its upstream leg has died —
/// field case WINHOST-A 2026-08-02, where the agent sat "connected" for 45+
/// minutes after a server pod roll while registered on no pod (heartbeats,
/// log uploads and overlay all fine; rc/tunnel dead). Reconnect must key on
/// frames RECEIVED, not frames sent.
pub(crate) const WS_RX_DEADLINE: Duration = Duration::from_secs(80);

/// Hard bound on a single WS frame WRITE on the established connection.
/// Every select arm awaits its sends inline, so one wedged `ws.send`
/// freezes the whole loop: no arm runs, no `watchdog::tick`, and at 90 s
/// the process watchdog kills the worker. Field case WINHOST-A 2026-08-15
/// 13:42:47Z — a corp-VPN connect captured the default route mid-flight,
/// the kernel kept retransmitting the WS TCP stream into the void, the
/// loop froze on a send and `stalled=signaling=92s` turned a routing
/// blip into a process death: full overlay teardown, warm relay
/// allocations lost, >2 min blackout. A send that can't complete in 15 s
/// IS a dead connection — surface it as `ConnectError::Transient` and
/// let the reconnect ladder cycle the WS (the persistent overlay runtime
/// rides through WS reconnects untouched; the `SignalingPumpGuard`
/// disarms the stall budget during backoff). 15 s tolerates a slow-but-
/// alive link (3 missed RTOs) and leaves 75 s of watchdog headroom.
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Hard bound on one session's `get_stats()` read in the heartbeat arm.
/// webrtc-rs stats await internal ICE locks; on a peer whose network was
/// just captured (corp-VPN connect mid-RC-session) those locks are held by
/// tasks retransmitting into the void, and the await blocks for MINUTES —
/// field WINHOST-A 2026-08-15, FOUR `stalled=signaling=9xs` process deaths
/// in one day (09:48, 13:42, 18:22, 19:13), the last two AFTER the WS
/// writes were bounded: the freeze was never only the socket. Telemetry is
/// decorative — a wedged peer forfeits its stats round, the loop moves on.
const SESSION_STATS_BUDGET: Duration = Duration::from_secs(3);

/// Hard bound on one peer's `pc.close()` during connection teardown — the
/// same webrtc-internals hang class as [`SESSION_STATS_BUDGET`], on the
/// paths that run BEFORE the reconnect can start (`close_all_peers` &c.).
/// Bounding it is safe: the P6 session-scoped teardown (arbiter dereg,
/// display-match release) runs in `AgentPeer`'s Drop on every path, so an
/// expired close forfeits only the polite goodbye to a peer that is
/// unreachable anyway.
const PEER_CLOSE_BUDGET: Duration = Duration::from_secs(5);

/// FR-27 P10 — how long the host's Disconnect keeps the peer up AFTER the
/// server has been told, so the viewer hears the reason over signalling
/// before it sees the peer die.
///
/// The order is the whole fix. Before P10 the peer was closed first (up to
/// [`PEER_CLOSE_BUDGET`]) and the server told after, and the browser's
/// control data-channel `onclose` won every time: it read the drop as an
/// ordinary one, scheduled a reconnect, and hung the old session up itself
/// — so the audit said `controller_hangup` and the viewer was back within
/// 3 s of the person at the device sending it away. Now the Terminate goes
/// out first; the hub forwards it to the controller BEFORE it echoes it to
/// us; the viewer closes as "ended by the person at the device" and tears
/// its own peer down. The grace only covers a slow signalling path. On a
/// dead control WS there is nothing to wait for and the close is immediate.
///
/// `ROOMLERD_HOST_DISCONNECT_GRACE_MS` overrides it, `0` restoring the
/// pre-P10 timing (the kill switch), capped at [`PEER_CLOSE_BUDGET`].
const HOST_DISCONNECT_GRACE_DEFAULT: Duration = Duration::from_millis(1000);

/// The grace from the environment, or the default. Read per Disconnect: it
/// is a field knob, and a daemon that has to restart to honour it is one
/// nobody will set.
fn host_disconnect_grace() -> Duration {
    host_disconnect_grace_from(
        std::env::var("ROOMLERD_HOST_DISCONNECT_GRACE_MS")
            .ok()
            .as_deref(),
    )
}

fn host_disconnect_grace_from(raw: Option<&str>) -> Duration {
    match raw.map(str::trim).and_then(|s| s.parse::<u64>().ok()) {
        Some(ms) => Duration::from_millis(ms).min(PEER_CLOSE_BUDGET),
        None => HOST_DISCONNECT_GRACE_DEFAULT,
    }
}

/// The one message the host's Disconnect puts on the wire. A function so a
/// test can hold the daemon to the spelling the viewer and the audit key on.
fn host_disconnect_terminate(session_id: bson::oid::ObjectId) -> ClientMsg {
    ClientMsg::Terminate {
        session_id,
        reason: EndReason::HostDisconnect,
        limit: None,
    }
}

/// FR-101 P4b-2 — the one message the idle limit puts on the wire: the reason
/// every server already knows, and the limit a newer one names to the viewer
/// and the audit (an older server ignores `limit` and ends the session as
/// `IdleTimeout` all the same).
fn idle_terminate(session_id: bson::oid::ObjectId) -> ClientMsg {
    ClientMsg::Terminate {
        session_id,
        reason: EndReason::IdleTimeout,
        limit: Some("idle".to_string()),
    }
}

/// FR-101 P4b-2 — why the DEVICE is ending a session: the person at it
/// pressed Disconnect (FR-27 P10), or the session sat idle past its limit
/// (`session_idle`). Both end it the same way, saying so first and closing
/// after the grace, under their own reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceEnd {
    HostDisconnect,
    Idle,
}

impl DeviceEnd {
    fn terminate(self, session_id: bson::oid::ObjectId) -> ClientMsg {
        match self {
            Self::HostDisconnect => host_disconnect_terminate(session_id),
            Self::Idle => idle_terminate(session_id),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::HostDisconnect => "host_disconnect",
            Self::Idle => "idle_timeout",
        }
    }
}

/// The next session the device ends, from either channel. Both `recv`s are
/// cancel-safe, so losing the outer `select!` drops no hand-back.
async fn device_end(
    kill_rx: &mut mpsc::Receiver<bson::oid::ObjectId>,
    idle_rx: &mut mpsc::Receiver<bson::oid::ObjectId>,
) -> Option<(bson::oid::ObjectId, DeviceEnd)> {
    tokio::select! {
        Some(sid) = kill_rx.recv() => Some((sid, DeviceEnd::HostDisconnect)),
        Some(sid) = idle_rx.recv() => Some((sid, DeviceEnd::Idle)),
        else => None,
    }
}

/// Run a session's peer close (a remote-control or a tunnel peer) within
/// [`PEER_CLOSE_BUDGET`], and SAY so when the budget runs out (#1738). The
/// session-scoped teardown still runs in Drop, but a close dropped at its
/// budget never reaches `RTCPeerConnection::close`'s ICE step, and the
/// webrtc internals it did not reach (the ICE agent's connectivity checker, a
/// 200 ms tick) stay alive for the life of the process. Every close site goes
/// through here so that it never happens without a line.
async fn close_within_budget(
    close: impl std::future::Future<Output = ()>,
    session: bson::oid::ObjectId,
    why: &'static str,
) {
    if tokio::time::timeout(PEER_CLOSE_BUDGET, close)
        .await
        .is_err()
    {
        warn!(
            session = %session,
            why,
            budget_ms = PEER_CLOSE_BUDGET.as_millis() as u64,
            "peer close overran its budget — dropping it (webrtc internals it did not reach stay alive)"
        );
    }
}

/// FR-27 — how long to wait for `companion::ensure_running` before deciding
/// this host has no on-screen prompt surface.
///
/// Bounded because the probe shells out (`launchctl`, `loginctl`,
/// `systemd-run`, `tasklist`) and the attended prompt is already counting down
/// against a 30 s window the controller shares: spending a large slice of it
/// waiting on a wedged helper would turn a slow answer into no answer. A
/// timeout is treated as "no surface", which is the same thing the operator
/// experiences.
pub(crate) const COMPANION_START_BUDGET: Duration = Duration::from_secs(3);

/// What `rc:request` resolves for a session and `rc:sdp.offer` consumes:
/// P6's controller display name and the device policy's input mode, FR-27's
/// asking org (the "Being viewed by" banner is raised at peer-build time, not
/// request time), FR-85 P3b's record-channel context, #1882's overlay
/// decision, FR-101 P4b-2's idle limit in seconds (armed once the session
/// is live), and FR-99 P3b's lock ask (handed to `lock_on_end` as the session
/// goes live).
type SessionMeta = (
    String,
    Option<roomler_ai_remote_control::models::InputMode>,
    Option<String>,
    Option<RecordMeta>,
    crate::rc_overlay::RcOverlay,
    Option<u32>,
    Option<roomler_ai_remote_control::models::LockOnEnd>,
);

/// FR-85 P3b — what a session's `record` channel needs, resolved when the
/// session is requested and consumed when its peer is built.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "recording"), allow(dead_code))]
pub(crate) struct RecordMeta {
    controller_user_id: bson::oid::ObjectId,
    /// `Some(window)` = the session was consented on the host, so a
    /// recording asks again; `None` = auto-granted.
    prompt_window: Option<Duration>,
}

/// What the agent puts on the wire for a resolved host consent prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsentReply {
    pub granted: bool,
    /// FR-27 — WHY, when the answer is no. A bare `false` reaches the
    /// controller as "the user denied your request", which is a lie whenever
    /// the truth is that the prompt stood unanswered, or that nothing could
    /// raise one.
    pub reason: Option<roomler_ai_remote_control::consent::ConsentDenyReason>,
}

/// Map a prompt's [`crate::consent::Decision`] to the `rc:consent` the agent
/// sends — or to `None`, meaning **send nothing**.
///
/// `have_surface` is whether a human could have been asked at all: a timeout
/// with no surface is `no_prompt_surface`, not `timeout`.
///
/// #1632 — `Cancelled` is the one decision with no reply. The prompt was
/// withdrawn because the session it asked about was terminated (the
/// controller closed its tab, switched device, or the server timed the
/// session out first), so the server has already forgotten the session and
/// no verdict is owed; a `granted:false` would only be audited against
/// nothing, or read as a refusal nobody made.
/// #2416 — a consent prompt's answer, or [`Decision::Cancelled`] once the
/// control socket it came over has closed (a server roll reset it, the network
/// dropped). Its session went with that socket: a viewer that redials asks
/// again under a new session id, and an answer to this one could only fail to
/// send. On 0.4.141 the native panel stayed up, answerable, beside the new
/// session's question, and its Approve did nothing ("outbound consent send
/// failed (channel closed)"). Withdrawn here, as a `Terminate` would withdraw
/// it: dropping `prompt` clears the broker's pending entry and the companion's
/// `.pending` marker, and the caller takes the panel and the notification down.
///
/// `outbound` is this connection's sender. Its receiver lives in the
/// connection's loop, so `closed()` resolves when that connection ends and
/// never before. A decision that is ready at the same moment wins.
///
/// [`Decision::Cancelled`]: crate::consent::Decision::Cancelled
pub(crate) async fn await_prompt_or_socket_end(
    prompt: impl std::future::Future<Output = crate::consent::Decision>,
    outbound: &mpsc::Sender<ClientMsg>,
    session_hex: &str,
) -> crate::consent::Decision {
    tokio::select! {
        biased;
        decision = prompt => decision,
        () = outbound.closed() => {
            info!(
                session = %session_hex,
                "consent prompt withdrawn — its control socket closed before an answer (#2416)"
            );
            crate::consent::Decision::Cancelled
        }
    }
}

pub(crate) fn consent_reply(
    decision: crate::consent::Decision,
    have_surface: bool,
) -> Option<ConsentReply> {
    use crate::consent::Decision;
    use roomler_ai_remote_control::consent::ConsentDenyReason;
    let reason = match decision {
        Decision::Granted | Decision::Denied => None,
        Decision::Timeout if !have_surface => Some(ConsentDenyReason::NoPromptSurface),
        Decision::Timeout => Some(ConsentDenyReason::HostTimeout),
        Decision::Cancelled => return None,
    };
    Some(ConsentReply {
        granted: decision.granted(),
        reason,
    })
}

/// Pong-RTT degradation bound for the control WS. Field winhost-a 2026-08-15
/// ~20:00Z: a WS that SURVIVED a corp-VPN route capture kept "working"
/// with application round-trips over 60 s — every send completed into the
/// local TCP
/// buffer ([`WS_SEND_TIMEOUT`] never fired) and frames DID eventually
/// arrive (the RX deadline never fired), but overlay relay grants and
/// fleet-RPC rode a molasses path: the primary org's pairs sat
/// carrier-less while the SECONDARY org, whose WS had reconnected fresh
/// after the capture, relayed fine. Liveness checks cannot see this; only
/// latency can. The keepalive ping carries its send time and the echoed
/// pong measures the true round trip.
const WS_PONG_RTT_DEGRADED: Duration = Duration::from_secs(20);

/// Consecutive degraded pongs before the WS is cycled — one slow pong can
/// be a scheduler/GC blip; two spaced a keepalive interval apart is a path
/// verdict. A ping whose pong hasn't arrived within
/// [`WS_PONG_RTT_DEGRADED`] by the next keepalive check counts as a strike
/// too — waiting for the late pong itself made each verdict cost a full
/// zombie round-trip (field 2026-08-15: 41 s RTT ⇒ conviction at ~90 s;
/// with missing-pong strikes + [`WS_PING_RETRY_ACCEL`] it lands ≈ 50-65 s,
/// and the relay rebuild escapes the zombie one round-trip sooner).
const WS_PONG_RTT_STRIKES: u32 = 2;

/// After the FIRST strike the keepalive re-arms at this interval instead of
/// the normal 25 s, so the confirming verdict lands quickly. Only the
/// cadence accelerates — the [`WS_PONG_RTT_DEGRADED`] deadline per ping is
/// unchanged, so a healthy-but-jittery link still gets its full window to
/// answer before the second strike.
const WS_PING_RETRY_ACCEL: Duration = Duration::from_secs(10);

/// Slowness-cycle treadmill cap: consecutive YOUNG connections (see
/// [`WS_TREADMILL_FRESH_WINDOW`]) convicted for RTT degradation before the
/// loop stops cycling and HOLDS the alive-but-slow WS instead.
///
/// The degraded-cycle verdict exists for the regime where a fresh
/// connection escapes a zombie (field 2026-08-15: the secondary org
/// reconnected fresh after a capture and relayed fine while the primary's
/// grandfathered WS crawled). But the OPPOSITE regime is just as real
/// (field 2026-08-17, winhost-a in-VPN morning): Check Point throttled EVERY
/// connection to ~41 s RTTs, so each cycle bought a fresh WS that
/// re-convicted within 2-3 min — a treadmill whose collateral was worse
/// than the slowness itself (each cycle flaps server presence
/// offline→online, so every peer's netmap churns and half-rebuilt pairs
/// park "blocked"; grants/netmap/exec stall in every down-window). Two
/// consecutive fresh connections that ALSO went slow prove cycling is not
/// helping — from then on slowness only detects (logged, strikes reset),
/// never selects the cycle. True deadness still convicts: the
/// [`WS_RX_DEADLINE`] path and send failures are untouched.
const WS_SLOWNESS_TREADMILL_CAP: u32 = 2;

/// A connection that stayed healthy at least this long before its first
/// degradation verdict starts a FRESH slowness episode (treadmill counter
/// rearms at 1): the path evidently worked, so cycling deserves another
/// chance. Connections convicted younger than this are treadmill evidence.
const WS_TREADMILL_FRESH_WINDOW: Duration = Duration::from_secs(600);

/// `true` = HOLD the degraded-but-alive WS (cycling has been shown not to
/// help); `false` = cycle as before. Books this conviction on the
/// cross-connection counter either way.
fn slowness_treadmill_holds(cycles: &mut u32, connection_age: Duration) -> bool {
    if connection_age >= WS_TREADMILL_FRESH_WINDOW {
        *cycles = 1;
        return false;
    }
    *cycles = cycles.saturating_add(1);
    *cycles > WS_SLOWNESS_TREADMILL_CAP
}

/// netstate PR-2 — a MAJOR network change (default route moved / addresses
/// vanished) probes the control WS immediately: a ping with this deadline,
/// [`WS_NETCHANGE_PROBE_STRIKES`] chances. The first cut (5 s, single
/// strike) cycled WORKING sockets all over an in-VPN host: under Check
/// Point throttle a healthy WS legitimately answers in 6-15 s, and the
/// route-flap storm re-fired the probe every couple of minutes — reattach
/// loops, netmap/grant starvation, every pair "blocked" (field 2026-08-16
/// 19:0xZ). 2×10 s convicts a genuinely dead socket in ≤20 s — still 2-4×
/// faster than the organic path — while a slow-but-alive one survives.
const WS_NETCHANGE_PROBE_DEADLINE: Duration = Duration::from_secs(10);

/// Missed probe windows before the WS is cycled (see above).
const WS_NETCHANGE_PROBE_STRIKES: u8 = 2;

/// netstate PR-2 — the delta receiver, feature-shaped: the overlay builds
/// subscribe to the process-wide monitor; a no-overlay build has no
/// subsystem and the arm pends forever.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
type NetDeltaRx = tokio::sync::broadcast::Receiver<tunnel_core::overlay::netstate::NetDelta>;
#[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
type NetDeltaRx = std::convert::Infallible;

/// Yield the summary of the next MATERIAL+MAJOR network delta; pend forever
/// with no subscription (or after the monitor closes). Minor/immaterial
/// deltas and `Lagged` are absorbed here — the probe is strictly for "the
/// network moved" moments. Cancel-safe (broadcast `recv` is cancel-safe).
async fn next_major_netchange(rx: &mut Option<NetDeltaRx>) -> String {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        use tokio::sync::broadcast::error::RecvError;
        use tunnel_core::overlay::netstate::Severity;
        while let Some(r) = rx.as_mut() {
            match r.recv().await {
                Ok(d) if d.material && d.severity == Severity::Major => return d.summary,
                Ok(_) | Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => {
                    *rx = None;
                    break;
                }
            }
        }
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    let _ = rx;
    std::future::pending().await
}

/// A5 — minimum wall-vs-monotonic skew that reads as suspend/resume at a
/// keepalive tick (mirrors the overlay runtime's `RESUME_SKEW_THRESHOLD`).
/// Below this it's scheduler jitter; above it the host slept and the WS is
/// cycled proactively instead of trusting a possibly-dead socket for up to
/// another RX-deadline window.
const RESUME_SKEW_MIN: Duration = Duration::from_secs(120);

/// A5 — a control-WS outage this long (or longer) triggers an immediate
/// update check on reconnect: the standing fleet-heal path for an agent
/// that missed a server-pushed `rc:agent.update` while its socket was
/// wedged/split (the push rides this very WS). One hour matches "a broken
/// agent should pick up the fixed build within minutes of recovering, not
/// at the next periodic check".
const UPDATE_RECHECK_AFTER_DOWN: Duration = Duration::from_secs(3600);

/// #2221 — a connection that sent its hello and then ran this long proves the
/// path, so the outage that ends it retries from 1 s instead of from wherever
/// the LAST outage left the ladder. The bar is the session's life, not the
/// handshake: a server that accepts and drops at once must still climb the
/// ladder, or a fleet would reconnect to it every second.
const LADDER_PROVEN_AFTER: Duration = Duration::from_secs(30);

/// #2221 — the reconnect ladder after a transient drop. `started_outage`: the
/// attempt that just ended had sent its hello (see [`OrgCtx::note_ws_down`]);
/// `lasted`: how long that attempt ran.
fn ladder_after_drop(backoff: Duration, started_outage: bool, lasted: Duration) -> Duration {
    if started_outage && lasted >= LADDER_PROVEN_AFTER {
        Duration::from_secs(1)
    } else {
        backoff
    }
}

/// Multi-org P1 — per-enrollment context for one supervised signaling loop.
/// `run_cmd` builds one per enabled enrollment (the config's scalar primary
/// + each `[[orgs]]` entry) and spawns one [`run`] per context.
#[derive(Clone)]
pub struct OrgCtx {
    /// `primary` or the `[[orgs]]` label. Log/CLI-facing.
    pub label: String,
    /// Only the primary enrollment drives PROCESS-WIDE effects: the
    /// self-updater (`rc:agent.update` + the long-outage recheck),
    /// attention sentinels (the notify subsystem has no per-org files),
    /// exit-route purges, and the `process::exit` escalations — a secondary
    /// org's terminal conditions stop ITS loop, never the daemon.
    pub is_primary: bool,
    /// Watchdog pump name, registered by `run_cmd` before spawn:
    /// `signaling` for the primary (kept verbatim for log/tooling
    /// continuity) and `signaling:<label>` for secondaries — per-org pumps
    /// so one org's healthy ticks can't mask another org's stalled loop.
    /// `&'static` because the watchdog registry is keyed on static strs;
    /// secondary names are INTERNED once per [`OrgCtx::secondary`] call
    /// (bounded by the org count for the process lifetime — `run_cmd`
    /// builds each org's ctx exactly once and clones it thereafter).
    pub pump: &'static str,
    /// A5 — epoch-ms of the moment THIS org's control WS first went down in
    /// the current outage; 0 = up (or never connected). Was a process-global
    /// static pre-multi-org: one org's reconnect would have erased another
    /// org's outage stamp (and fired the update recheck off the wrong org).
    down_since_ms: Arc<std::sync::atomic::AtomicI64>,
    /// `rc:agent.update` pushes ignored on this org's WS because it is not
    /// the primary. Surfaced in the LocalAPI `OrgStatus`.
    pub updates_ignored: Arc<std::sync::atomic::AtomicU32>,
    /// FR-103 — this enrollment's LIVE agent token. The socket, the DERP
    /// dialer, the device-list requests and the uploaders read it at the
    /// moment of use, so a renewal, or a token re-enrolled on disk, reaches
    /// all of them on their next use without a restart.
    pub token: crate::token_slot::TokenSlot,
    /// FR-103 — the renewal knobs. [`crate::token_renewal::Settings::default`]
    /// unless `run_cmd` read the environment's ([`Self::with_renewal`]).
    pub renewal: crate::token_renewal::Settings,
    /// FR-103 — rung once the server has ACCEPTED the token on a connect:
    /// the renewal task looks after every connect.
    renewal_connected: Arc<tokio::sync::Notify>,
}

impl OrgCtx {
    pub fn primary(token: crate::token_slot::TokenSlot) -> Self {
        Self {
            label: crate::config::PRIMARY_ORG_LABEL.to_string(),
            is_primary: true,
            pump: "signaling",
            down_since_ms: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            updates_ignored: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            token,
            renewal: Default::default(),
            renewal_connected: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn secondary(label: &str, token: crate::token_slot::TokenSlot) -> Self {
        Self {
            label: label.to_string(),
            is_primary: false,
            // Interned (see the `pump` field doc): the watchdog registry
            // wants `&'static str`; one bounded leak per org per process.
            pump: Box::leak(format!("signaling:{label}").into_boxed_str()),
            down_since_ms: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            updates_ignored: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            token,
            renewal: Default::default(),
            renewal_connected: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// FR-103 — replace the renewal knobs (`run_cmd` passes the
    /// environment's; a test passes its own).
    pub fn with_renewal(mut self, renewal: crate::token_renewal::Settings) -> Self {
        self.renewal = renewal;
        self
    }

    /// Stamp the start of an outage. `true` when this failure STARTED one: the
    /// attempt before it had sent its hello (which clears the stamp), or no
    /// attempt had failed yet (#2221).
    fn note_ws_down(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        // Only the FIRST failure of an outage stamps (CAS from 0).
        self.down_since_ms
            .compare_exchange(
                0,
                now,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    }

    fn note_ws_up_and_maybe_recheck_update(&self) {
        let since = self
            .down_since_ms
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        if since == 0 {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let down_ms = now.saturating_sub(since);
        if down_ms < UPDATE_RECHECK_AFTER_DOWN.as_millis() as i64 {
            return;
        }
        if self.is_primary {
            let fired = crate::updater::request_update_now(None);
            info!(
                down_mins = down_ms / 60_000,
                update_check_fired = fired,
                "control WS recovered after a long outage — requesting an immediate update check"
            );
        } else {
            // The machine-wide updater is the primary's to drive; a
            // secondary's outage recovering says nothing about the
            // primary's ability to receive pushes.
            info!(
                org = %self.label,
                down_mins = down_ms / 60_000,
                "org control WS recovered after a long outage (update recheck is primary-only)"
            );
        }
    }
}

/// rc.58: format an error chain by walking `source()` so the top-level
/// `Display` (which `tokio_tungstenite::Error` keeps deliberately
/// terse) doesn't hide the root cause — TLS handshake error,
/// ECONNREFUSED, EAI_NONAME, etc. Field repro 2026-05-24: a flaky
/// network turned every cold start into `error=ws connect` with no
/// further detail, making it impossible to tell a DNS failure from a
/// TLS failure without packet capture. The `preflight` module ships
/// the same helper; duplicated here to avoid forcing every consumer
/// crate to depend on `preflight`.
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(cause) = src {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        src = cause.source();
    }
    out
}

/// rc.58: RAII guard that flips the watchdog's `signaling` pump on
/// for the lifetime of a single live WebSocket connection. On drop
/// (every return path from `connect_once`, including `?` early-exit)
/// the pump goes back to gated-off so the next reconnect-backoff loop
/// doesn't count its silence against the 90 s stall threshold.
///
/// Before rc.58 the pump was registered with `active=true` from
/// process start, so the watchdog's 90 s timer ran during initial
/// exponential backoff against an unreachable server — every cold
/// start with a flaky network got force-exited at 90 s and the
/// supervisor crash-looped forever. See `main.rs` register call for
/// the symmetric flip there.
struct SignalingPumpGuard {
    pump: &'static str,
}

impl SignalingPumpGuard {
    /// Activate the watchdog pump for THIS org's loop and reset its
    /// `last_tick` (the `gate(false → true)` transition resets the
    /// timer; see `watchdog.rs::Watchdog::gate`). Use right after
    /// `connect_async` returns Ok.
    fn activate(pump: &'static str) -> Self {
        watchdog::gate(pump, true);
        Self { pump }
    }
}

impl Drop for SignalingPumpGuard {
    fn drop(&mut self) {
        watchdog::gate(self.pump, false);
    }
}

/// Unification P1 — RAII flag that marks the daemon "connected to the
/// coordination server" for the LocalAPI (`roomler status`) while a WS
/// connection is live, and clears it on EVERY exit path from `connect_once`
/// (Ok, `?`-propagated Err, explicit return) — same discipline as
/// [`SignalingPumpGuard`]. The `DaemonState` reads this flag; while it's false
/// `peers()` reports none (the overlay carriers are torn down on disconnect).
struct ConnectedGuard(Arc<AtomicBool>);

impl ConnectedGuard {
    fn mark(flag: Arc<AtomicBool>, clear_attention: bool) -> Self {
        flag.store(true, Ordering::Relaxed);
        // S1b — a healthy authenticated connect resolves (almost) every
        // attention reason by definition: auth works, no goodbye, no live
        // duel. Clear stale sentinels in BOTH locations so the desktop's
        // "Attention required" banner can't outlive the condition (the old
        // code cleared only after a same-process auth-failure streak, so
        // e.g. test-artifact sentinels stuck forever).
        //
        // FR-53: `rollback_failed` used to be spared unconditionally, which
        // left a recovered device claiming a crash loop in a build it no
        // longer runs — measured on a host asserting "0.4.34 has crashed 3
        // times, reinstall manually" while running 0.4.41. It is now spared
        // only while the accused build is the one connecting, which is the
        // case the exemption was actually written for. The version passed
        // here is this binary's own, so it is a fact and not a claim.
        //
        // Multi-org P1: PRIMARY-only. The notify subsystem has no per-org
        // sentinel files, so a healthy SECONDARY connect must not clear a
        // sentinel the (possibly still-broken) primary raised.
        if clear_attention {
            crate::notify::clear_attention_on_healthy_connect_from(env!("CARGO_PKG_VERSION"));
        }
        Self(flag)
    }
}

impl Drop for ConnectedGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Aborts a task when dropped: ties a helper task (FR-103's renewal) to the
/// loop that owns it, on every return path.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Drive the signaling loop forever. Returns only on fatal error (e.g.
/// auth rejection) or shutdown signal.
/// B1 — the CURRENT connection's RTT-sample sink. Each overlay start
/// installs a hook wrapping a WEAK handle to its runtime's event
/// channel (weak by design — the runtime tears down when its
/// connection's `evt_tx` drops, and a strong clone held by the
/// process-lifetime prober would defeat that; a dead weak sender just
/// drops the sample). Type-erased so this compiles without the overlay
/// features (`tunnel_core::overlay` is feature-gated): the slot simply
/// stays `None` and the prober's hook is inert.
pub type RttSampleSlot = Arc<std::sync::RwLock<Option<crate::localapi_state::RttSampleHook>>>;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    // Multi-org P1 — which enrollment this loop serves ([`OrgCtx::primary`]
    // for the config's scalar identity; `run_cmd` synthesizes a per-org
    // `AgentConfig` via `AgentConfig::for_org` for secondaries).
    ctx: OrgCtx,
    // FR-43 P2b — this process's part in delegation. Owned so the reconnect
    // loop can lend it per attempt. Only the PRIMARY org's loop ever acts on it
    // (`handle_server_msg` gates on `ctx.is_primary`), but it is passed to all
    // of them so the gate lives in one place rather than at three call sites
    // that could each forget it.
    mut delegation: crate::delegate::Delegation,
    // `mut` for exactly one reason: FR-40 key rotation swaps the overlay
    // secret in this snapshot between two connections (see
    // `ConnectError::KeyRotated`). Nothing else writes it after start.
    mut cfg: AgentConfig,
    encoder_preference: crate::encode::EncoderPreference,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    // Unification P1 — LocalAPI live handles (stable across reconnects, owned by
    // `run_cmd`): a flag flipped while connected, and the channel the overlay
    // runtime publishes its mesh view on.
    connected: Arc<AtomicBool>,
    overlay_view_tx: tokio::sync::watch::Sender<OverlayView>,
    // B1 — where each connection publishes its (downgraded) overlay event
    // sender for the RTT prober bridge.
    rtt_sample_slot: RttSampleSlot,
    // P2b — the operator-consent broker, created in `run_cmd` and SHARED with the
    // LocalAPI's DaemonState so its live `pending` set gates LocalAPI decisions.
    consent_broker: crate::consent::ConsentBroker,
    // P3b-2 PR-C — the tunnel-client hub, created in `run_cmd` and SHARED with the
    // LocalAPI's DaemonState (create/kill/flows verbs). The signaling loop
    // publishes the live agent-WS egress into it + demuxes client-bound replies.
    tunnel_hub: crate::tunnel::client_mgr::TunnelClientHub,
    // Remote config (docs/remote-config.md) — the config path, the daemon-wide
    // write lock and the LIVE `exec_enabled` as one value. Machine-wide, so the
    // SAME instance is shared by every org loop; only the primary ever applies.
    remote_cfg: crate::remote_config::RemoteConfigServices,
    // FR-27 — the daemon-wide live-session registry, so a thin client can see
    // "Being viewed by …" and end a session. Each loop registers its OWN kill
    // channel per session, which is what makes a Disconnect on a multi-org
    // daemon reach the loop that actually owns that session.
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) -> Result<()> {
    // Overlay "Disconnect" control → this channel → the connect_once
    // loop, which tears the session down (peer close + ClientMsg::Terminate).
    // Created once; the receiver is polled inside connect_once across
    // reconnects. A `kill_tx` clone is retained below for the whole loop
    // so the channel never fully closes — a closed receiver would busy-
    // spin the select! — even when the overlay is disabled.
    let (kill_tx, mut kill_rx) = mpsc::channel::<bson::oid::ObjectId>(4);
    // #1754 — where a tunnel peer reports that its client is gone, so the
    // loop reaps it without waiting for a `rc:tunnel.terminate` that an
    // older client, a crashed one or a dead network never sends. Same
    // shape as `kill_tx`: created once per ORG loop (a process-global
    // sender would land a secondary org's reap in the primary's maps),
    // the receiver borrowed into every connection so a report that lands
    // during a reconnect gap is drained by the next connection, and this
    // sender retained for the loop's life so the receiver never closes.
    // Each connection's peers get a clone via `handle_server_msg`.
    let (tunnel_reap_tx, mut tunnel_reap_rx) =
        mpsc::channel::<crate::tunnel::reap::TunnelReap>(crate::tunnel::reap::TUNNEL_REAP_CAP);
    // #1761 — where a TURN-relayed QUIC setup, run on its own task, hands
    // the peer it built back to the loop. Same shape as the reap channel:
    // per ORG loop (a secondary org's peer must never land in the primary's
    // maps), the receiver borrowed into every connection so a setup that
    // finishes during a reconnect gap is drained — and closed, its
    // connection being gone — by the next one, and this sender retained
    // for the loop's life so the receiver never closes.
    let (quic_setup_tx, mut quic_setup_rx) =
        mpsc::channel::<crate::tunnel::quic_setup::QuicSetupOutcome>(
            crate::tunnel::quic_setup::QUIC_SETUP_OUTCOME_CAP,
        );
    // FR-101 P4b-2 — where a live session's idle watcher hands the session
    // back when its limit is reached. Same shape as the reap channel: per ORG
    // loop (a secondary org's session must be ended by the loop that holds
    // it), the receiver borrowed into every connection, and this sender held
    // for the loop's life so the receiver never closes and never busy-spins
    // the `select!`. A hand-back during a reconnect gap is drained by the next
    // connection, whose maps no longer hold the session: nothing to end.
    let (idle_tx, mut idle_rx) = mpsc::channel::<bson::oid::ObjectId>(16);
    // FR-102 P9d — where a live session's carrier observation reports that it
    // has LANDED, so this loop sends ONE `rc:session.stats` for it promptly
    // instead of waiting for the free-running 30 s tick (a session shorter than
    // one tick's gap after the observation would otherwise record no carrier at
    // all — the P9d field evidence). Same shape as `idle_tx`: created once per
    // ORG loop, the receiver borrowed into every connection so a signal that
    // lands during a reconnect gap is drained by the next connection (whose
    // `peers` map no longer holds the session — nothing to send), and this
    // sender held for the loop's life so the receiver never closes and never
    // busy-spins the `select!`. Each live peer gets a clone via
    // `handle_server_msg` → `AgentPeer::new`.
    let (carrier_ready_tx, mut carrier_ready_rx) = mpsc::channel::<bson::oid::ObjectId>(32);
    // rc.307 (B) — multi-region DERP admission-ticket cache, hoisted from
    // connect_once scope: the PERSISTENT overlay runtime's regional-DERP
    // factory captures this slot ONCE, so a per-connection slot went stale
    // after the first reconnect (nothing refilled the captured copy →
    // tickets expired → regional relays permanently degraded to central).
    // Process-scope + threaded into every connection, like rtt_sample_slot.
    let derp_ticket_slot: crate::relay_probe::DerpTicketSlot = Default::default();
    // One overlay handle, reused across reconnects. Failing to bring up
    // the indicator is non-fatal — the session still works, the user
    // just doesn't get the visual "you're being watched" cue.
    // FR-27 — where a NATIVE consent panel's Approve/Deny comes back. The
    // backend never resolves consent itself: the answer lands here, the loop
    // below feeds it to the broker, and the broker applies the gate it already
    // has. One decision point for the native panel, the companion and the CLI
    // — three would be three chances to disagree about whether a session was
    // approved. A retained sender keeps the receiver from closing (same reason
    // as `kill_tx`), so the `select!` cannot busy-spin where no panel exists.
    let (consent_tx, mut consent_rx) = mpsc::channel::<(String, bool)>(4);
    let indicator =
        match ViewerIndicator::new(kill_tx.clone(), rc_sessions.clone(), consent_tx.clone()) {
            Ok(v) => {
                // FR-99 — the overlay that draws a privacy curtain is running,
                // so the device may say a curtain is possible here.
                #[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
                crate::privacy::set_overlay_up(true);
                v
            }
            Err(e) => {
                warn!(%e, "viewer-indicator init failed; continuing without overlay");
                // FR-27 — an overlay that could not start must NOT also cost the
                // device its session registry: `disabled()` carries a private one,
                // so rebuild the real handle around it. This is the ordinary case
                // on macOS and Linux, where there is no native overlay at all and
                // the companion's banner is the only one.
                ViewerIndicator::disabled().with_registry(kill_tx.clone(), rc_sessions.clone())
            }
        };
    let _consent_keepalive = consent_tx;
    // Keep the sender alive for the loop's lifetime (see above).
    let _kill_keepalive = kill_tx;
    // Operator-consent broker: created in `run_cmd` and passed in (P2b), so the
    // LocalAPI shares the SAME instance and its live `pending` set. Lives across
    // reconnects, so a sentinel dropped while the WS was down is still honoured.
    let mut backoff = Duration::from_secs(1);
    // netstate PR-2b — a MAJOR network change during a reconnect backoff
    // cuts the wait and resets the ladder: the transition that killed this
    // WS has ended (or moved again), and an exponential grown to 60 s while
    // the corp path blackholed fresh TLS must not ALSO delay the recovery
    // attempt. Field 2026-08-16, org{label=jovanov}: the WS spent most of a
    // 5-minute captive window parked in backoff — no WS ⇒ no grants, no
    // netmap, no honored pins ⇒ the org's entire overlay sat dark until the
    // ladder happened to line up with a reconnectable path.
    let mut ladder_net_rx: Option<NetDeltaRx> = {
        #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
        {
            tunnel_core::overlay::netstate::handle().map(|h| h.subscribe())
        }
        #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
        {
            None
        }
    };
    let mut auth_failures: u32 = 0;
    // rc.53: rolling window of recent `ReplacedByNewerConnection`
    // events. Three within 5 min escalates from "back off 60 s and
    // hope the duel settles" to "operator action required +
    // process::exit(AGENT_DELETED_EXIT_CODE)" — at that point the
    // duel is real, neither instance can win, and the operator needs
    // to find + stop the duplicate (or re-enrol THIS host with a
    // fresh enrollment JWT to mint a new agent_id).
    let mut recent_replacements: Vec<std::time::Instant> = Vec::new();
    // Slowness-cycle treadmill (see [`WS_SLOWNESS_TREADMILL_CAP`]): spans
    // reconnects so "the fresh connection ALSO went slow" is countable.
    let mut slowness_cycles: u32 = 0;
    // FR-103 — this enrollment's token renewal, for exactly as long as this
    // loop runs: a secondary org's loop that stops takes its task with it.
    let renewal = crate::token_renewal::Enrollment {
        label: ctx.label.clone(),
        server_url: cfg.server_url.clone(),
        tenant_id: cfg.tenant_id.clone(),
        agent_id: cfg.agent_id.clone(),
        token: ctx.token.clone(),
    };
    let _renewal_task = AbortOnDrop(tokio::spawn(crate::token_renewal::run(
        renewal.clone(),
        remote_cfg.clone(),
        ctx.renewal,
        ctx.renewal_connected.clone(),
    )));
    // FR-103 — the previous attempt was a recovery's prompt retry (see the
    // `AuthRejected` arm): a second refusal in a row waits out the ladder.
    let mut recovered_last = false;
    loop {
        if *shutdown.borrow() {
            info!("shutdown signalled; exiting signaling loop");
            return Ok(());
        }

        // #2221 — how long this attempt runs decides whether its drop
        // restarts the ladder (see `ladder_after_drop`).
        let attempt_started = std::time::Instant::now();
        let attempt = connect_once(
            &ctx,
            &cfg,
            &remote_cfg,
            encoder_preference,
            shutdown.clone(),
            indicator.clone(),
            consent_broker.clone(),
            connected.clone(),
            overlay_view_tx.clone(),
            rtt_sample_slot.clone(),
            derp_ticket_slot.clone(),
            tunnel_hub.clone(),
            &mut slowness_cycles,
            &mut delegation,
            &mut kill_rx,
            &mut consent_rx,
            &tunnel_reap_tx,
            &mut tunnel_reap_rx,
            &quic_setup_tx,
            &mut quic_setup_rx,
            &idle_tx,
            &mut idle_rx,
            &carrier_ready_tx,
            &mut carrier_ready_rx,
        )
        .await;
        if !matches!(attempt, Err(ConnectError::AuthRejected)) {
            recovered_last = false;
        }
        match attempt {
            Ok(()) => {
                info!("signaling connection closed cleanly, reconnecting");
                backoff = Duration::from_secs(1);
                slowness_cycles = 0;
                if auth_failures > 0 {
                    info!(
                        prior_auth_failures = auth_failures,
                        "auth recovered; clearing attention sentinel"
                    );
                    // Multi-org P1: sentinels are primary-owned (no per-org
                    // files) — a secondary's recovery must not clear one.
                    if ctx.is_primary {
                        notify::clear_attention();
                    }
                    auth_failures = 0;
                }
            }
            Err(ConnectError::AuthRejected) => {
                // FR-103 — before the ladder: a newer token in the config file
                // (re-enrolled while this ran), else a renewal, which the
                // server grants up to 90 days past expiry. Either puts a
                // different token in use, worth ONE prompt retry; a refusal
                // right after a recovery waits out the ladder, so a server
                // that renews a token its socket then refuses cannot spin
                // this loop.
                if !recovered_last
                    && crate::token_renewal::recover(&renewal, &remote_cfg, ctx.renewal).await
                {
                    recovered_last = true;
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() { return Ok(()); }
                        },
                    }
                    continue;
                }
                recovered_last = false;
                auth_failures = auth_failures.saturating_add(1);
                let auth_backoff = auth_backoff_for(auth_failures);
                warn!(
                    consecutive = auth_failures,
                    retry_in_secs = auth_backoff.as_secs(),
                    "agent token rejected; will retry — re-enrollment may be required"
                );
                // Raise the attention sentinel after the third
                // consecutive 401 — by then a transient server-side
                // JWT-cache miss has had time to recover and the
                // operator genuinely needs to act. Multi-org P1: the
                // sentinel is primary-only; a secondary org's auth death
                // is surfaced via the LocalAPI `OrgStatus` + logs.
                if auth_failures == 3 && ctx.is_primary {
                    let msg = "Roomler agent: re-enrollment required.\n\n\
                              The server is rejecting this agent's token. \
                              Either the device was removed or re-enrolled \
                              elsewhere, or its token expired and could not \
                              be renewed. Run:\n\n\
                              \troomlerd re-enroll --token <new-jwt>\n\n\
                              with a fresh enrollment JWT from the admin UI \
                              to restore service.";
                    match notify::raise_attention_with_reason(notify::REASON_AUTH, msg) {
                        Ok(path) => warn!(
                            path = %path.display(),
                            "wrote needs-attention sentinel"
                        ),
                        Err(e) => warn!(error = %e, "failed to write needs-attention sentinel"),
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(auth_backoff) => {},
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { return Ok(()); }
                    },
                }
            }
            Err(ConnectError::FatalGoodbye { reason, message }) => {
                // Multi-org P1: a SECONDARY org's goodbye (row deleted /
                // policy refused in THAT org) terminates only its own loop.
                // No sentinel (primary-owned), no exit-route purge (the
                // primary's overlay owns those routes), no process exit —
                // the supervisor in `run_cmd` records the terminal error
                // for the LocalAPI `OrgStatus`.
                if !ctx.is_primary {
                    // #1750 — the ONE line this org gets per start; the
                    // goodbye arm and the supervisor stay at DEBUG for it.
                    let gone = SecondaryGoodbye {
                        label: ctx.label.clone(),
                        reason,
                        message,
                    };
                    warn!(
                        org = %ctx.label,
                        "{gone} — stopping this org's loop (other orgs unaffected)"
                    );
                    return Err(gone.into());
                }
                // rc.53: server told us to stop reconnecting. The
                // teardown of in-flight peers already ran in the
                // `handle_server_msg::ServerMsg::Goodbye` arm
                // (close_all_peers + close_all_tunnel_peers) — this
                // arm only writes the operator sentinel + exits.
                // #2293 — the last line names what brings this install back:
                // systemd never restarts exit 7.
                let after =
                    crate::service::Install::detect(remote_cfg.config_path()).after_removal();
                let body = format!(
                    "Roomler agent: server-side close — {reason:?}.\n\n{message}\n\n\
                     The agent will not reconnect. Re-enrol with a fresh enrollment \
                     JWT from the admin UI:\n\n\
                     \troomlerd re-enroll --token <new-jwt>\n\n\
                     {after}"
                );
                match notify::raise_attention_machine_aware_with_reason(
                    notify::REASON_GOODBYE,
                    &body,
                ) {
                    Ok(path) => warn!(
                        path = %path.display(),
                        ?reason,
                        "wrote needs-attention sentinel for FatalGoodbye"
                    ),
                    Err(e) => warn!(
                        error = %e,
                        ?reason,
                        "failed to write needs-attention sentinel for FatalGoodbye"
                    ),
                }
                // Exit with the documented code so the SCM
                // supervisor's rc.53 code-7 fast-alarm fires on this
                // FIRST exit (not after 8). Operator sees the
                // structured error within <1 minute.
                // P5/A2 — a fatal goodbye is a PERMANENT stop (the row is gone);
                // no restart will run the boot reconciler, so drop any exit-node
                // split-default now or the host stays blackholed until reboot.
                crate::purge_exit_routes();
                // #2294 — and the removal purge Hive started (FR-90 P2g-4a)
                // finishes first: the removal's goodbye follows its frame on
                // this socket, and a pod roll mid-purge ends in this same
                // goodbye at the reconnect. Bounded; none in flight, no wait.
                // The build's `hive-purge-drain` is what lets the kick tell it.
                #[cfg(hive_host)]
                crate::hive::finish_removal_purge(crate::hive::REMOVAL_PURGE_LIMIT).await;
                std::process::exit(watchdog::AGENT_DELETED_EXIT_CODE);
            }
            Err(ConnectError::KeyRotated {
                secret_base64,
                key_epoch,
            }) => {
                // FR-40 — the handler already persisted the new key (persist
                // FIRST, or a restart would bring the retired key back). Adopt
                // it here, in the one snapshot `connect_once` reads, and go
                // straight back: this is one device re-joining, not a fleet
                // event, so no stagger. `overlay::maybe_start` sees the
                // fingerprint change (it includes the public key) and rebuilds
                // the runtime; the join carries the new key + epoch.
                cfg.overlay_wg_secret_key = Some(secret_base64);
                cfg.overlay_wg_key_epoch = key_epoch;
                info!(
                    org = %ctx.label,
                    key_epoch,
                    "overlay key rotated — reconnecting under the new identity"
                );
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {},
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { return Ok(()); }
                    },
                }
            }
            Err(ConnectError::ReplacedByNewer { message }) => {
                let now = std::time::Instant::now();
                // Drop events older than the rolling window BEFORE pushing
                // the new one (so escalation depends only on what's actually
                // within the window). W4(d): 30 min, not 5 — the backoff
                // ladder below reaches 15 min, and a 5 min window would have
                // emptied mid-sleep and reset a live duel back to full speed.
                recent_replacements
                    .retain(|t| now.duration_since(*t) < Duration::from_secs(30 * 60));
                recent_replacements.push(now);
                let displacements = recent_replacements.len();
                warn!(
                    %message,
                    count = displacements,
                    "server signalled this connection was replaced; staggering reconnect to break the duel"
                );

                // Legacy escalation (`ws_replaced_exit = true`): sentinel +
                // process exit at the 3rd displacement, exactly as before
                // W4(d). Off by default — see below.
                if displacements >= 3 && cfg.ws_replaced_exit.unwrap_or(false) {
                    // Multi-org P1: a secondary org's duel terminates only
                    // its own loop (see the FatalGoodbye arm's rationale).
                    if !ctx.is_primary {
                        warn!(
                            org = %ctx.label,
                            displacements,
                            "duplicate-instance duel on this org — stopping its loop \
                             (other orgs unaffected)"
                        );
                        return Err(anyhow::anyhow!(
                            "duplicate-instance duel: displaced {displacements}× in the \
                             window — another process is using this org's agent_id ({message})",
                        ));
                    }
                    write_replaced_sentinel(&message, displacements);
                    // P5/A2 — bypasses RAII; drop any exit-node split-default so
                    // a duel-losing instance doesn't leave the host blackholed.
                    crate::purge_exit_routes();
                    std::process::exit(watchdog::AGENT_DELETED_EXIT_CODE);
                }

                // W4(d) — NO process exit by default. Field (winhost-a, every
                // VPN transition): displacement storms on TLS-inspected paths
                // are ZOMBIE half-open WSes — self-limiting once the server's
                // receive-liveness reaps them — and each exit tore down the
                // WHOLE overlay (carriers, TUN, routes) for an event that
                // needed none of it. A TRUE duplicate-instance duel (copied
                // config.toml on another machine) isn't fixed by exiting
                // either: the supervisor respawns straight back into the
                // duel. Instead the operator sentinel is raised once per
                // storm and the ladder parks the loser at 15 min; the
                // overlay keeps running on its last netmap throughout.
                if displacements == 3 && ctx.is_primary {
                    write_replaced_sentinel(&message, displacements);
                }

                // 60 s minimum — long enough that two duelling instances
                // stagger out of phase and one wins; sustained duels climb
                // the ladder instead of escalating to an exit.
                tokio::select! {
                    _ = tokio::time::sleep(replaced_backoff_for(displacements)) => {},
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { return Ok(()); }
                    },
                }
                // Reset the transient backoff — the next reconnect
                // attempt is paced by the 60 s above, not by the
                // exponential ladder.
                backoff = Duration::from_secs(1);
            }
            Err(ConnectError::Transient(e)) => {
                // A5 — first failure of this outage stamps the clock the
                // reconnect-recovery update check keys off.
                let started_outage = ctx.note_ws_down();
                // #2221 — a session that lived ends with a 1 s first retry.
                // The ladder used to survive a successful reconnect, so every
                // later drop waited out the PREVIOUS outage's step (8 s in the
                // field after a pod roll; up to 60 s).
                backoff = ladder_after_drop(backoff, started_outage, attempt_started.elapsed());
                // rc.58: log the full `source()` chain alongside the
                // top-level Display — `tokio_tungstenite::Error`'s top
                // message is just "ws connect" / "ws read" without the
                // underlying TLS / DNS / ECONNREFUSED detail. Field
                // repro 2026-05-24: a flaky WSS handshake produced
                // identical-looking `error=ws connect` lines for
                // every failure mode, blocking root-cause analysis.
                let cause = error_chain(e.as_ref());
                warn!(error = %e, %cause, "signaling connect failed; backing off");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                    },
                    // netstate PR-2b — the network moved: retry NOW with a
                    // reset ladder instead of waiting out a backoff sized
                    // for the network that no longer exists.
                    _ = next_major_netchange(&mut ladder_net_rx) => {
                        info!("network changed during reconnect backoff — retrying immediately");
                        backoff = Duration::from_secs(1);
                        // New network = new throttle regime: the slowness
                        // treadmill re-earns its verdict from scratch.
                        slowness_cycles = 0;
                    },
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { return Ok(()); }
                    },
                }
            }
        }
    }
}

/// Auth-rejection backoff ladder. Tuned for "transient server JWT
/// cache miss recovers fast; persistent revocation gets surfaced to
/// the operator without burning CPU on retry storms."
///
/// 1st failure → 30 s (server might just be deploying)
/// 2nd → 60 s
/// 3rd → 5 min (sentinel raises here too)
/// 4th and beyond → 1 hour (stable steady-state)
pub(crate) fn auth_backoff_for(consecutive_failures: u32) -> Duration {
    match consecutive_failures {
        0 | 1 => Duration::from_secs(30),
        2 => Duration::from_secs(60),
        3 => Duration::from_secs(5 * 60),
        _ => Duration::from_secs(60 * 60),
    }
}

/// W4(d) — ReplacedByNewer backoff ladder (displacements counted over a
/// 30 min rolling window). Zombie half-open WSes self-limit once the
/// server reaps them, so early rungs stay quick; a sustained TRUE duel
/// parks the loser at the 15 min cap with the operator sentinel raised —
/// it never exits the process (the overlay keeps carrying traffic on its
/// last netmap; `ws_replaced_exit = true` restores the legacy exit).
///
/// 1st/2nd → 60 s (stagger two live dialers out of phase)
/// 3rd → 2 min, 4th → 4 min, 5th → 8 min, 6th+ → 15 min
pub(crate) fn replaced_backoff_for(displacements: usize) -> Duration {
    match displacements {
        0..=2 => Duration::from_secs(60),
        3 => Duration::from_secs(120),
        4 => Duration::from_secs(240),
        5 => Duration::from_secs(480),
        _ => Duration::from_secs(900),
    }
}

/// The ReplacedByNewer operator sentinel — written once per storm (at the
/// 3rd displacement in the window), whether or not the legacy exit is on.
fn write_replaced_sentinel(message: &str, displacements: usize) {
    let body = format!(
        "Roomler agent: duplicate-instance duel detected.\n\n{message}\n\n\
         This connection has been displaced {displacements} times in the current \
         window — another process (different physical host with a copy of this \
         config.toml, or a stale half-open connection through a TLS-inspecting \
         middlebox) is using the same agent_id. The agent stays up and backs \
         off; if this persists, stop the duplicate or re-enrol THIS host with \
         a fresh enrollment JWT to mint a new agent_id."
    );
    match notify::raise_attention_machine_aware_with_reason(notify::REASON_DUPLICATE, &body) {
        Ok(path) => warn!(
            path = %path.display(),
            displacements,
            "wrote needs-attention sentinel for ReplacedByNewer escalation"
        ),
        Err(e) => warn!(
            error = %e,
            "failed to write needs-attention sentinel for ReplacedByNewer escalation"
        ),
    }
}

/// #1750 — a SECONDARY org's loop ended because that org's server refuses this
/// enrollment for good (`AgentDeleted` / `PolicyRejected`).
///
/// Typed so the supervisors in `run_cmd` can tell it from a fault by
/// [`is_secondary_goodbye`] — never by the text — and log it ONCE: before, a
/// dead secondary org cost two ERRORs and a WARN on every daemon start, for a
/// machine whose primary was perfectly healthy (field: a MacBook carried three
/// such enrollments for a month). The text is also what `roomler status`
/// shows for the org, so it names every way out.
///
/// Nothing here removes the enrollment: `AgentDeleted` also covers a
/// QUARANTINED row (`auth_agent::refusal_reason`), which an admin can lift, so
/// dropping the org is the owner's call.
#[derive(Debug, thiserror::Error)]
#[error(
    "server goodbye ({reason:?}): {message} — org {label:?} refuses this machine \
     (removed, quarantined or refused by policy there). Re-enroll it with \
     `roomlerd re-enroll --org {label} --token <new-jwt>`, or stop serving it: \
     `roomlerd org disable {label}` (kept; `roomlerd org enable {label}` restores it) \
     or `roomlerd org rm {label}`. Restart the daemon to apply"
)]
pub struct SecondaryGoodbye {
    pub label: String,
    pub reason: AgentCloseReason,
    pub message: String,
}

/// Whether an org loop ended on a [`SecondaryGoodbye`] — an outcome the loop
/// has already reported as its one WARN, not a fault. Sees through
/// `anyhow::Context` layers.
pub fn is_secondary_goodbye(e: &anyhow::Error) -> bool {
    e.downcast_ref::<SecondaryGoodbye>().is_some()
}

#[derive(Debug, thiserror::Error)]
enum ConnectError {
    #[error("auth rejected")]
    AuthRejected,
    /// rc.53: server explicitly told us to stop reconnecting (row
    /// deleted, policy refused, or any unknown future-variant reason
    /// which `AgentCloseReason::Deserialize` rounds to
    /// `PolicyRejected`). The outer `run()` loop responds with a
    /// needs-attention sentinel + `process::exit(AGENT_DELETED_EXIT_CODE)`
    /// so the SCM supervisor's code-7 fast-alarm fires immediately.
    #[error("fatal goodbye: {reason:?}: {message}")]
    FatalGoodbye {
        reason: AgentCloseReason,
        message: String,
    },
    /// rc.53: server told us a newer WS connection displaced us
    /// (duplicate-instance duel). The outer loop backs off ≥60 s on
    /// the first 1-2 events (so two duelling instances stagger out
    /// of phase and one wins); escalates to fatal +
    /// process::exit(AGENT_DELETED_EXIT_CODE) on the 3rd event
    /// within a 5 min rolling window.
    #[error("replaced by newer connection: {message}")]
    ReplacedByNewer { message: String },
    /// FR-40 — the `rc:agent.key_rotate` handler minted + PERSISTED a new
    /// overlay key for this org. The outer `run()` loop adopts it in its
    /// config snapshot (the only copy `connect_once` ever reads) and
    /// reconnects at once: the overlay runtime's fingerprint includes the
    /// public key, so the reconnect rebuilds it and joins under the new
    /// identity. Carries the secret in-process only — it never crosses a
    /// socket.
    #[error("overlay key rotated (epoch {key_epoch}); reconnecting under the new identity")]
    KeyRotated {
        secret_base64: String,
        key_epoch: u32,
    },
    #[error(transparent)]
    Transient(#[from] anyhow::Error),
}

#[allow(clippy::too_many_arguments)]
async fn connect_once(
    ctx: &OrgCtx,
    cfg: &AgentConfig,
    // Remote config — the live `exec_enabled` and the persist path.
    remote_cfg: &crate::remote_config::RemoteConfigServices,
    encoder_preference: crate::encode::EncoderPreference,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    indicator: ViewerIndicator,
    consent_broker: crate::consent::ConsentBroker,
    connected: Arc<AtomicBool>,
    overlay_view_tx: tokio::sync::watch::Sender<OverlayView>,
    // B1 — this connection publishes its downgraded overlay event sender
    // here (the RTT prober bridge reads it).
    rtt_sample_slot: RttSampleSlot,
    // rc.307 (B) — process-scope DERP admission-ticket cache (see run()).
    derp_ticket_slot: crate::relay_probe::DerpTicketSlot,
    tunnel_hub: crate::tunnel::client_mgr::TunnelClientHub,
    // Slowness-cycle treadmill counter (see [`WS_SLOWNESS_TREADMILL_CAP`]) —
    // lives in `run`'s loop so it spans reconnects; reset on a clean close
    // and on a netstate Major (new network = new regime).
    slowness_cycles: &mut u32,
    // FR-43 P2b — this process's part in delegation: the daemon's channel, the
    // worker's two ends, or neither.
    delegation: &mut crate::delegate::Delegation,
    // Overlay "Disconnect" → session ObjectId to tear down. Borrowed
    // (not owned) so the same receiver survives across reconnects.
    kill_rx: &mut mpsc::Receiver<bson::oid::ObjectId>,
    // FR-27 — Approve/Deny from a NATIVE consent panel.
    consent_rx: &mut mpsc::Receiver<(String, bool)>,
    // #1754 — the tunnel-peer reap channel: the sender every new tunnel
    // peer gets a clone of, and the receiver the reap arm drains. Both
    // borrowed from `run` so they span reconnects (see the channel's doc).
    tunnel_reap_tx: &crate::tunnel::reap::ReapSender,
    tunnel_reap_rx: &mut mpsc::Receiver<crate::tunnel::reap::TunnelReap>,
    // #1761 — the QUIC-setup outcome channel: the sender each spawned
    // TURN-relayed setup reports on, and the receiver the outcome arm
    // drains. Both borrowed from `run` so they span reconnects.
    quic_setup_tx: &crate::tunnel::quic_setup::QuicSetupSender,
    quic_setup_rx: &mut crate::tunnel::quic_setup::QuicSetupReceiver,
    // FR-101 P4b-2 — the idle-limit channel: the sender each live session's
    // watcher gets a clone of, and the receiver the device-end arm drains
    // beside `kill_rx`. Both borrowed from `run` so they span reconnects.
    idle_tx: &mpsc::Sender<bson::oid::ObjectId>,
    idle_rx: &mut mpsc::Receiver<bson::oid::ObjectId>,
    // FR-102 P9d — handed (cloned) to every live session's peer so its carrier
    // observation can signal this loop, and the receiver the `carrier_ready_rx`
    // arm drains. Both borrowed from `run` so they span reconnects (see the
    // channel's doc).
    carrier_ready_tx: &mpsc::Sender<bson::oid::ObjectId>,
    carrier_ready_rx: &mut mpsc::Receiver<bson::oid::ObjectId>,
) -> Result<(), ConnectError> {
    // S6 — `tid` is the tenant-affinity key the server-front LB hashes
    // on, co-locating this agent's WS with its tenant's controllers on
    // one pod (the rc-hub is pod-local). Server validates it against
    // the JWT's tenant claim; pre-S6 servers just ignore the param.
    // FR-103 — the token as of THIS connect, never the startup copy.
    let token = ctx.token.get();
    let url = format!(
        "{}?token={}&role=agent&tid={}",
        cfg.ws_url(),
        urlencode(&token),
        urlencode(&cfg.tenant_id)
    );
    // Log the endpoint WITHOUT the token: the URL carries the long-lived agent
    // JWT (a 1-year credential), and this line lands in the rolling log a user
    // might paste into a chat / issue (field 2026-07-25 — a controller shared a
    // log with the full token in it). The token itself never adds diagnostic
    // value here; `{server}/ws (role=agent)` is enough to see WHERE we dial.
    info!(server = %cfg.ws_url(), "connecting to signaling server (role=agent)");

    // rc.58: wrap `connect_async` in a hard timeout. A hung TLS
    // handshake (rustls refusing renegotiation against an LB that
    // requests it mid-stream is one observed mode) would otherwise
    // sit here indefinitely, never giving the outer backoff loop a
    // chance to fire. The timeout becomes another `Transient` so the
    // backoff handles it like any other connection failure.
    // #2187 — the server's address comes from `ctl_dns`: a name resolved
    // before never waits on a resolver that has stopped answering (an exit
    // whose DNS died kept a dropped control WS from ever reconnecting).
    let (mut ws, response) =
        match tokio::time::timeout(WS_CONNECT_TIMEOUT, crate::ws_connect::connect(&url)).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                if let tokio_tungstenite::tungstenite::Error::Http(ref resp) = e
                    && resp.status().as_u16() == 401
                {
                    // #2512 — the server refuses this token: say so on the
                    // slot, so the DERP dialer and the log uploader stop
                    // spending requests it will only 401, until a new token
                    // or the next accepted upgrade.
                    if ctx.token.mark_refused(&token) {
                        info!(
                            org = %ctx.label,
                            "agent token refused; DERP dials and log uploads for this \
                             enrollment wait until it is accepted again or replaced"
                        );
                    }
                    return Err(ConnectError::AuthRejected);
                }
                return Err(ConnectError::Transient(
                    anyhow::Error::new(e).context("ws connect"),
                ));
            }
            Err(_elapsed) => {
                return Err(ConnectError::Transient(anyhow::anyhow!(
                    "ws connect timed out after {}s",
                    WS_CONNECT_TIMEOUT.as_secs()
                )));
            }
        };
    debug!(status = ?response.status(), "ws upgrade complete");

    // rc.58: now that the WS handshake is done, flip the watchdog's
    // `signaling` pump on for the lifetime of this connection. The
    // RAII guard ensures EVERY return path (Ok, ?-propagated Err,
    // explicit `return Err(...)`) also flips it back off, so the next
    // backoff-reconnect cycle isn't counted against the 90 s stall
    // threshold. See the type-level comment on `SignalingPumpGuard`.
    let _pump_guard = SignalingPumpGuard::activate(ctx.pump);
    // #2551 — the setup below awaits too (the hello, the overlay start) while
    // the pump already counts: name it, so a stall here is not blamed on the
    // select loop. Dropped where the loop starts; its arms name their own.
    let setup_stage = watchdog::enter(ctx.pump, "setup");
    // Unification P1 — mark the daemon connected for the LocalAPI; the guard
    // clears it on every return path (like `_pump_guard`). Sentinel clearing
    // is primary-only (see `ConnectedGuard::mark`).
    let _connected_guard = ConnectedGuard::mark(connected, ctx.is_primary);

    // Fleet RPC — teach the redactor THIS org's agent token before any exec
    // can run. Registered per-org (the registry is process-wide) so a command
    // asked for by org A can never leak org B's token in its output.
    crate::exec::register_secret(&token);
    // FR-103 — the server accepted this token: the renewal task looks now.
    ctx.renewal_connected.notify_one();
    // #2512 — and the loops that held their requests on its refusal resume.
    if ctx.token.mark_accepted(&token) {
        info!(
            org = %ctx.label,
            "agent token accepted again; DERP dials and log uploads resume"
        );
    }

    // Say hello.
    let mut hello_caps = stub_caps(cfg.overlay_multi_org, ctx.is_primary);
    // FR-90 P2c-3 — copies are held for the primary organization only: a
    // secondary org's connection never offers them, so its placement never
    // picks this device.
    if !ctx.is_primary {
        strip_replica_verbs(&mut hello_caps.rpc);
    }
    // FR-90 P3-4a — `vault` exactly where the hello carries the key.
    crate::vault::apply_word(
        &mut hello_caps.rpc,
        crate::vault::takes_leases(cfg.vault_enabled, ctx.is_primary),
    );
    // FR-94 — `exec-system` on exactly the connection of the device this
    // machine's SYSTEM service is anchored for, and the heartbeat re-announces
    // when that changes (an anchor written or removed while connected).
    let mut last_announced_exec_system = crate::exec_service::advertised_for(&cfg.agent_id);
    crate::exec_service::apply_word(&mut hello_caps.rpc, last_announced_exec_system);
    // FR-105 — `ssh-system` the same way: the service serves SSH for exactly
    // this device, and the person's `ssh_enabled` has this worker carry its
    // port.
    let mut last_announced_ssh_system =
        crate::ssh_service::advertised_for(&cfg.agent_id, cfg.ssh_enabled);
    crate::ssh_service::apply_word(&mut hello_caps.rpc, last_announced_ssh_system);
    // FR-85 P1e-mac — a supervised Mac's hello already knows what its attached
    // worker can record. Saying the root daemon's own list (nothing) would
    // strip RECORD for the 30 s until the first heartbeat corrects it, after
    // every reconnect. Primary org only, like the heartbeat.
    if ctx.is_primary
        && let Some(record) = delegation.host().and_then(|d| d.effective_record())
    {
        hello_caps.record = record;
    }
    // FR-85 P3b — what the hello told the server about remote recording, so
    // the heartbeat re-announces the moment the owner's gate changes it.
    let mut last_announced_record: Vec<String> = hello_caps.record.clone();
    // FR-92 — and whether the hello advertised keep-busy, so a flipped
    // `keep_busy_enabled` reaches the server within a beat.
    let mut last_announced_keep_busy = hello_caps.input.iter().any(|w| w == "keep-busy");
    // FR-97 P4a — and whether it advertised the real Ctrl+Alt+Del, so a
    // policy a GPO refresh changes reaches the server within a beat, instead
    // of a viewer sending a sequence the host may no longer send.
    let mut last_announced_sas = hello_caps.input.iter().any(|w| w == "sas");
    // FR-93 P2b — and the desktop brief it carried, so a login, a logout or
    // the greeter reaches the server within a beat.
    let mut last_announced_desktop = hello_caps.desktop.clone();
    // FR-99 P1b — and the privacy words it carried, read off the hello itself
    // so a switch flipped since `stub_caps` ran is still news on the next beat.
    let mut last_announced_privacy = privacy_words_in(&hello_caps.rpc);
    // FR-101 P2b — and the owner's session-policy floor it carried, likewise.
    let mut last_announced_session_policy = hello_caps.session_policy;
    let mut last_announced_relay_server = hello_caps.rpc.iter().any(|word| word == "relay-server");
    let (arch, arch_emulated) = crate::arch::native();
    let hello = ClientMsg::AgentHello {
        machine_name: cfg.machine_name.clone(),
        os: detect_os(),
        // FR-97 P0d — the hardware's architecture, not this build's.
        arch,
        arch_emulated,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        displays: stub_displays(),
        caps: Box::new(hello_caps),
        // Tunnel mesh subnet-router: advertise the CIDRs this host offers to
        // route — explicit `advertise_routes` config unioned with auto-detected
        // local subnets. Admin-gated server-side (untrusted until an admin
        // approves them into this agent's `routes`).
        advertised_routes: crate::subnet_detect::local_advertised_routes(cfg),
        // Multi-region relay PoPs: advertise the probe capability so the
        // server may push `rc:relay.regions` (it never sends the variant to
        // an agent that didn't flag it — our deserializer would error).
        supports_relay_regions: crate::relay_probe::probing_enabled(),
        // P6 — publish the host key's PUBLIC half so a caller can verify what
        // it dialled. Empty here is meaningful ("this device cannot prove
        // itself"), never "trust anything".
        ssh_host_pubkey: ssh_host_pubkey_for(cfg),
        // FR-90 P3-3a — the vault key's public half, made on this first ask
        // and held in memory for the life of the process: the primary
        // enrollment's connection only, and only while the owner's
        // `vault_enabled` is on.
        vault_key: crate::vault::hello_key(cfg.vault_enabled, ctx.is_primary),
        // FR-100 P1a — THIS enrollment's device key, on every org's
        // connection (one key per org, never shared): made on the first
        // hello, kept beside the config, and offered only once it is on disk.
        peer_auth_key: crate::peer_auth::hello_key(remote_cfg.config_path(), &cfg.tenant_id),
    };
    send_msg(&mut ws, &hello).await.context("sending hello")?;
    // rc.58: explicit tick on hello — the 25 s keepalive timer hasn't
    // fired yet, and a slow first server response (no inbound frame
    // for 30+ s) would otherwise leave the pump's `last_tick` at the
    // gate-activation instant. Belt-and-suspenders: the gate already
    // reset the timer, so this only matters when the server stalls
    // immediately after upgrade.
    watchdog::tick(ctx.pump);
    info!("rc:agent.hello sent");
    // A5 — if this connect ended a ≥1 h outage, the fleet may have shipped a
    // fix (or a forced update push) we never saw; check now, not in ≤4 h.
    ctx.note_ws_up_and_maybe_recheck_update();

    // Outbound channel shared by all per-session peers. Peers push their
    // locally-gathered ICE candidates and state-change terminates here;
    // the main loop flushes them to the WS.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<ClientMsg>(PEER_OUTBOUND_CAP);
    // Multi-region relay probing: the server's last region push (per
    // connection) + the periodic re-prober (exits with the connection —
    // its sends fail once `outbound_rx` drops).
    let relay_regions_slot: crate::relay_probe::RegionSlot = Default::default();
    if crate::relay_probe::probing_enabled() {
        tokio::spawn(crate::relay_probe::periodic_reprobe(
            relay_regions_slot.clone(),
            outbound_tx.clone(),
        ));
    }
    // MeshHarbor #19 — the host's read-only network inventory, from the
    // primary enrollment of a single-org device only; it exits with the
    // connection, like the re-prober.
    let _ = crate::net_inventory::spawn_reporter(
        outbound_tx.clone(),
        ctx.is_primary,
        cfg.orgs.iter().filter(|o| o.enabled).count(),
    );
    // P3b-2 PR-C: publish this connection's egress so tunnel-client flow
    // supervisors can open sessions over it; the guard clears it to `None` on
    // every exit path (like `_connected_guard`), so a supervisor holding the
    // dead egress re-waits for the next connection's sink.
    // FR-40 P1c — if the PREVIOUS session of this org ended in a key
    // rotation, say so again on this healthy socket: the copy sent on the
    // dying session can be lost (it was, in the second field run).
    drain_pending_rotation_report(&cfg.tenant_id, &outbound_tx);
    // FR-99 P1d — the curtains the previous process died holding, reported as
    // `worker_exit` on the first healthy connection of the org each belonged to.
    crate::privacy::drain_leftovers(&cfg.tenant_id, &outbound_tx);
    // FR-90 P3-4a — the primary enrollment's connection carries this
    // device's lease requests: the vault answers each on the connection it
    // came from. P3-4b — set BEFORE the supervisor below is pointed here, so
    // a run it launches from now on knows whether its toolbelt offers the
    // vault tools.
    #[cfg(feature = "vault")]
    if ctx.is_primary {
        crate::vault::on_connected(
            outbound_tx.clone(),
            crate::vault::takes_leases(cfg.vault_enabled, ctx.is_primary),
            cfg.vault_activity_log,
        );
    }
    // FR-90 — and its Hive state reports: point the supervisor at THIS one,
    // which also replays the latest state of every session a dropped
    // connection may have lost.
    #[cfg(hive_host)]
    if ctx.is_primary {
        crate::hive::on_connected(outbound_tx.clone());
    }
    let _sink_guard = tunnel_hub.publish_sink(outbound_tx.clone());
    // FR-43 P2b — point the delegation channel at THIS connection's outbound
    // queue, so a worker's `SdpAnswer` / `Ice` reach the server.
    //
    // Re-set on every reconnect, deliberately: the sender belongs to the
    // connection, not the daemon. A worker reply that arrives while no WS is
    // up is dropped rather than queued, because a session without a control
    // plane is a session the server has already forgotten — queueing it would
    // deliver an answer to a question nobody is still asking.
    // Cloned FIRST so its borrow of `delegation` ends here — the worker's
    // receiver below is borrowed for the whole connection, and a process is
    // one role or the other, so only one of these is ever `Some`.
    let delegate = delegation.host().cloned();
    if let Some(delegate) = delegate.as_ref()
        && ctx.is_primary
    {
        delegate.set_outbound(outbound_tx.clone());
    }
    // FR-43 P2b-2 — the WORKER's ends. The receiver is borrowed for this
    // connection; the sender is cloned so a delegated session can hold it.
    // FR-43 P2c — what we last told the server about our permissions.
    //
    // Per CONNECTION, not per process: a reconnect sends a fresh `rc:agent.hello`
    // carrying our own caps, so the server's view resets and our memory of it
    // must reset too — otherwise a worker that attached before a reconnect would
    // never be re-announced, and the row would sit wrong until the worker
    // happened to change.
    let mut last_announced_permissions: Option<(Vec<String>, bool)> = None;
    let (mut delegated_in, delegated_out) = match delegation.worker_mut() {
        Some((rx, tx)) => (Some(rx), Some(tx.clone())),
        None => (None, None),
    };
    // Phase 3b: if overlay is enabled, start the node runtime (relay mode)
    // and capture the channel its `rc:overlay.*` events flow into. The
    // runtime sends its `ClientMsg`s back through `outbound_tx`, like any
    // peer, and tears down when this connection's `overlay_evt_tx` drops.
    // #2551 — a re-attach to a persistent runtime awaits that runtime's
    // event channel, unbounded.
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    watchdog::stage(ctx.pump, "setup.overlay");
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    let mut overlay_evt_tx = crate::overlay::maybe_start(
        cfg,
        ctx.token.clone(),
        outbound_tx.clone(),
        overlay_view_tx.clone(),
        derp_ticket_slot.clone(),
        crate::ssh::SessionServices {
            power_activity: Some(crate::power::shared_activity().clone()),
            asker: crate::ssh::Asker::Here {
                broker: consent_broker.clone(),
                indicator: indicator.clone(),
            },
            activity: crate::ssh::ActivitySink::new(cfg, outbound_tx.clone()),
        },
    )
    .await;
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    watchdog::stage(ctx.pump, "setup");
    // B1 — install THIS connection's RTT-sample sink: a hook wrapping a
    // WEAK handle to the runtime's event channel. `None` when overlay is
    // off; a stale hook is harmless (weak upgrade fails once the runtime
    // is gone).
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        *rtt_sample_slot.write().unwrap_or_else(|e| e.into_inner()) =
            overlay_evt_tx.as_ref().map(|t| {
                let weak = t.downgrade();
                let hook: crate::localapi_state::RttSampleHook =
                    Arc::new(move |node_hex: &str, rtt_ms: u32| {
                        let Ok(node_id) = bson::oid::ObjectId::parse_str(node_hex) else {
                            return;
                        };
                        if let Some(tx) = weak.upgrade() {
                            let _ = tx.try_send(
                                tunnel_core::overlay::runtime::OverlayEvent::RttSample {
                                    node_id,
                                    rtt_ms,
                                },
                            );
                        }
                    });
                hook
            });
    }
    // Without an overlay surface nothing publishes the view; keep the params
    // used so the LocalAPI wiring stays feature-agnostic in `run_cmd`.
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    let _ = (&overlay_view_tx, &rtt_sample_slot);
    let mut peers: HashMap<bson::oid::ObjectId, AgentPeer> = HashMap::new();
    let mut shared_leases = crate::shared_lease::SharedLeases::default();
    let mut shared_ssh = crate::ssh_shared_bridge::SharedSshTargets::default();
    // 2026-07-27 — this connect iteration starts with a fresh session map;
    // release any GPU-clock pin a previous iteration left engaged (its
    // sessions died with the old map).
    crate::gpu_clock::on_sessions_changed(0);
    // Codec selected for each pending session (computed from the
    // browser∩agent intersection when `rc:session.request` arrives, read
    // at `rc:sdp.offer` time to drive the track + encoder). Entries are
    // removed when the peer is built; orphaned entries (session
    // cancelled before SDP) get cleaned when the session is terminated.
    let mut pending_codecs: HashMap<bson::oid::ObjectId, String> = HashMap::new();
    // Y.3: same lifecycle as `pending_codecs` but for the negotiated
    // video transport. Inserted when `rc:session.request` arrives,
    // consumed when `rc:sdp.offer` builds the AgentPeer + media pump.
    // `Some("data-channel-vp9-444")` flips the pump into DC mode;
    // None is the legacy WebRTC track.
    let mut pending_transports: HashMap<bson::oid::ObjectId, Option<String>> = HashMap::new();
    // rc.62: same lifecycle as `pending_transports` but for the
    // per-session VP9 chroma override forwarded from the controller's
    // `rc:session.request.chroma_pref`. `None` → fall back to the
    // agent's `ROOMLERD_VP9_CHROMA` env-var default.
    let mut pending_chroma: HashMap<bson::oid::ObjectId, Option<String>> = HashMap::new();
    // FR-17 — whether THIS controller can parse the framed DataChannel wire
    // format. Same lifecycle as `pending_chroma`: stashed by the Request
    // handler, consumed when the peer is built, cleared on WS teardown.
    let mut pending_chunk_framing: HashMap<bson::oid::ObjectId, bool> = HashMap::new();
    // Same lifecycle as `pending_transports`/`pending_chroma` but for the
    // opt-in system-audio flag forwarded from the controller's
    // `rc:session.request.audio_enabled`. `false`/missing → no audio
    // track. Inserted when `rc:request` arrives, consumed at
    // `rc:sdp.offer` time where the AgentPeer + (optional) audio pump
    // are built.
    let mut pending_audio: HashMap<bson::oid::ObjectId, bool> = HashMap::new();
    // Clipboard-v2 hardening: session permission bitfield from
    // `rc:request`, consumed at `rc:sdp.offer` time so the AgentPeer's
    // DC handlers can enforce it (today: the clipboard handler).
    // Missing entry (test harness skipped rc:request) → the
    // `Permissions` default (VIEW | INPUT | CLIPBOARD), which matches
    // pre-v2 behavior.
    let mut pending_permissions: HashMap<
        bson::oid::ObjectId,
        roomler_ai_remote_control::permissions::Permissions,
    > = HashMap::new();
    // P6 — (controller display name, device-policy input mode) from
    // `rc:request`, consumed at `rc:sdp.offer` so AgentPeer can register
    // the session with the InputArbiter (participants rail + mode seed).
    let mut pending_session_meta: HashMap<bson::oid::ObjectId, SessionMeta> = HashMap::new();
    // T2.10d: one `AgentTunnelPeer` per active `roomler`
    // session. Distinct map from `peers` (remote-control sessions)
    // because the namespaces don't overlap and the lifecycles
    // differ — tunnel peers live until `TunnelTerminate` /
    // disconnect; rc peers live until session-end.
    let mut tunnel_peers: HashMap<bson::oid::ObjectId, Arc<crate::tunnel::peer::AgentTunnelPeer>> =
        HashMap::new();
    // Phase 1d (quic-v1): one `AgentQuicPeer` per active tunnel session
    // negotiated onto the QUIC transport. Separate map from
    // `tunnel_peers` (WebRTC DC) because a session uses exactly one
    // data plane — `TcpForwardForward` dispatch checks this map first
    // and falls back to the WebRTC `tunnel_peers` map. Same lifecycle:
    // live until `TunnelTerminate` / WS disconnect.
    // R3 — reclaim any QUIC peers stashed by a prior session's TRANSIENT exit
    // (empty unless `tunnel_peers_survive_reattach` is on ⇒ pre-R3 identical).
    let mut tunnel_quic_peers = reclaim_survived_quic_peers(&cfg.tenant_id);
    // #1761 — the TURN-relayed QUIC setups this connection has in flight,
    // each on its own task, with the candidates that arrived meanwhile and
    // a cancel flag. Fresh per connection like the maps above: a setup
    // that outlives the connection reports to the next one, which holds no
    // entry for it and closes what it built.
    let mut pending_quic_setups = crate::tunnel::quic_setup::PendingQuicSetups::default();

    // Keepalive. nginx + K8s ingress commonly idle-close WSes at 60-120s of
    // silence; send an application-level Ping every 25s so the connection
    // survives quiet periods between sessions.
    let mut keepalive = tokio::time::interval(Duration::from_secs(25));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await; // Swallow the immediate first tick.

    // Phase 7: heartbeat telemetry. The server uses this to refresh
    // `agents.last_seen_at` so a quiet but connected agent doesn't
    // appear "online forever" if its WS dies silently. 30 s cadence
    // pairs with a "online if last_seen_at > now - 90 s" rule on the
    // server side. active_sessions comes straight from the peer map.
    // Stats PR-5: the promised sysinfo follow-up — every heartbeat now
    // carries an `AgentSysStats` block (process rss/cpu, host net
    // counters, overlay carrier tallies + median peer RTT from the
    // published view). The legacy top-level rss/cpu fields are filled
    // too, but the server reads only the block.
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await; // Swallow the immediate first tick.
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    let mut relay_readiness = Some(crate::relay_server::readiness());
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    let mut relay_readiness: Option<watch::Receiver<Option<u16>>> = None;
    if relay_server_ready() != last_announced_relay_server {
        heartbeat.reset_immediately();
    }
    let mut sys_sampler = crate::telemetry::SysSampler::new();

    // Receive-liveness stamp: refreshed on EVERY inbound frame (the Pongs the
    // server auto-sends for our keepalive Pings count), checked against
    // `WS_RX_DEADLINE` on the keepalive tick. See the const's doc for why
    // send-success is not a liveness signal.
    let mut last_rx = std::time::Instant::now();
    // Pong-RTT detector state: pings stamp `ws_epoch`-relative millis into
    // their payload; the echoed pong yields an exact application-level RTT.
    let ws_epoch = std::time::Instant::now();
    let mut slow_pongs: u32 = 0;
    // Send time of the newest keepalive ping still awaiting its pong.
    // `None` once any stamped pong arrives (the RTT verdict then comes from
    // the stamp itself). Checked at each keepalive tick: still outstanding
    // past the degradation bound = a strike WITHOUT waiting for the late
    // pong to crawl back.
    let mut outstanding_ping: Option<std::time::Instant> = None;

    // A5 — resume detection. Every timer here runs on the MONOTONIC clock,
    // which excludes suspend on Windows/Linux — so after a sleep the RX
    // deadline picks up where it left off and a socket that died during
    // the nap stays trusted for up to ~80 more seconds. Wall-vs-monotonic
    // skew at the keepalive tick catches the nap (the overlay runtime and
    // the watchdog use the same trick) and cycles the WS immediately: a
    // fresh connect is cheap, a post-resume zombie socket is not.
    let mut skew_wall = std::time::SystemTime::now();
    let mut skew_mono = std::time::Instant::now();

    // netstate PR-2 — probe-then-cycle on Major network changes. `Some` =
    // a probe ping is out: (window start, missed windows so far); verdict
    // at the next keepalive tick (pulled forward to the deadline).
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    let mut net_rx: Option<NetDeltaRx> =
        tunnel_core::overlay::netstate::handle().map(|h| h.subscribe());
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    let mut net_rx: Option<NetDeltaRx> = None;
    let mut netchange_probe: Option<(std::time::Instant, u8)> = None;

    // #2551 — setup is done: from here each arm names its own stage.
    drop(setup_stage);
    loop {
        tokio::select! {
            changed = relay_listener_changed(&mut relay_readiness) => {
                if changed {
                    // Reuse the existing authenticated heartbeat/caps path,
                    // without waiting 30s or cycling this control connection.
                    heartbeat.reset_immediately();
                }
            }
            _ = shutdown.changed() => {
                // #2551 — every arm names its stage, so a stall says where.
                let _stage = watchdog::enter(ctx.pump, "shutdown");
                if *shutdown.borrow() {
                    info!("shutdown signalled; closing ws");
                    close_all_peers(&mut peers, &indicator).await;
                    close_all_tunnel_peers(&mut tunnel_peers).await;
                    // Terminal: a daemon shutdown must tear peers down, never
                    // stash them (the process is going away).
                    close_all_tunnel_quic_peers(&mut tunnel_quic_peers).await;
                    let _ = send_frame(&mut ws, Message::Close(None)).await;
                    return Ok(());
                }
            }
            _ = keepalive.tick() => {
                let _stage = watchdog::enter(ctx.pump, "keepalive");
                // W4(a) — TUN-death self-heal. The overlay runtime EXITS when
                // its TUN dies (a contract the runtime tests pin), and before
                // this the only respawner was the NEXT control-WS reconnect
                // discovering the closed slot — a healthy WS + a dead TUN
                // meant silently no mesh, indefinitely. A closed event sender
                // IS the death signal and `maybe_start` IS the respawner
                // (fingerprint/slot logic included); the 25 s keepalive
                // cadence is the natural retry backoff. (The B1 RTT hook
                // stays bound to the old runtime until the next reconnect —
                // harmless: its weak upgrade fails and samples drop.)
                #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
                if overlay_evt_tx.as_ref().is_some_and(|t| t.is_closed()) {
                    warn!(
                        "overlay runtime exited mid-session (TUN death?) — respawning now \
                         instead of waiting for the next reconnect"
                    );
                    overlay_evt_tx = crate::overlay::maybe_start(
                        cfg,
                        ctx.token.clone(),
                        outbound_tx.clone(),
                        overlay_view_tx.clone(),
                        derp_ticket_slot.clone(),
                        crate::ssh::SessionServices {
                            power_activity: Some(crate::power::shared_activity().clone()),
                            asker: crate::ssh::Asker::Here {
                                broker: consent_broker.clone(),
                                indicator: indicator.clone(),
                            },
                            activity: crate::ssh::ActivitySink::new(cfg, outbound_tx.clone()),
                        },
                    )
                    .await;
                }
                let wall_gap = skew_wall.elapsed().unwrap_or_default();
                let mono_gap = skew_mono.elapsed();
                skew_wall = std::time::SystemTime::now();
                skew_mono = std::time::Instant::now();
                if wall_gap > mono_gap + RESUME_SKEW_MIN {
                    warn!(
                        napped_s = (wall_gap - mono_gap).as_secs(),
                        "suspend/resume detected at keepalive — cycling the control WS"
                    );
                    close_all_peers(&mut peers, &indicator).await;
                    close_all_tunnel_peers(&mut tunnel_peers).await;
                    park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                    return Err(ConnectError::Transient(anyhow::anyhow!(
                        "resume-from-suspend (napped ~{} s)",
                        (wall_gap - mono_gap).as_secs()
                    )));
                }
                if last_rx.elapsed() > WS_RX_DEADLINE {
                    warn!(
                        silent_s = last_rx.elapsed().as_secs(),
                        "no inbound WS frames within the RX deadline — half-open socket \
                         (middlebox still ACKs our pings); reconnecting"
                    );
                    close_all_peers(&mut peers, &indicator).await;
                    close_all_tunnel_peers(&mut tunnel_peers).await;
                    park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                    return Err(ConnectError::Transient(anyhow::anyhow!(
                        "ws rx deadline: no inbound frames for {} s",
                        last_rx.elapsed().as_secs()
                    )));
                }
                // netstate PR-2 — the net-change probe verdict. Answered =
                // its pong cleared `outstanding_ping`, or ANY frame arrived
                // after the probe went out (both prove the socket survived
                // the transition). Unanswered past the tight deadline =
                // cycle NOW, single strike — the network moved under the
                // socket and every second of blind trust stalls the whole
                // grants/netmap plane behind a dead WS.
                if let Some((probed, misses)) = netchange_probe {
                    if outstanding_ping.is_none() || last_rx.elapsed() < probed.elapsed() {
                        netchange_probe = None;
                    } else if probed.elapsed() >= WS_NETCHANGE_PROBE_DEADLINE {
                        let misses = misses + 1;
                        if misses >= WS_NETCHANGE_PROBE_STRIKES {
                            warn!(
                                unanswered_s = probed.elapsed().as_secs(),
                                misses,
                                "control WS unresponsive after a MAJOR network change — cycling now"
                            );
                            close_all_peers(&mut peers, &indicator).await;
                            close_all_tunnel_peers(&mut tunnel_peers).await;
                            park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                            return Err(ConnectError::Transient(anyhow::anyhow!(
                                "net-change probe: {} windows of {} s unanswered after a \
                                 Major network change",
                                misses,
                                WS_NETCHANGE_PROBE_DEADLINE.as_secs()
                            )));
                        }
                        // One more chance: a throttled-but-alive corp path
                        // legitimately answers slower than one window.
                        warn!(
                            unanswered_s = probed.elapsed().as_secs(),
                            "net-change probe window missed once — re-probing (2-strike rule)"
                        );
                        if let Err(e) =
                            send_frame(&mut ws, Message::Ping(ping_payload(ws_epoch).into())).await
                        {
                            warn!(%e, "net-change re-probe ping failed — reconnecting");
                            close_all_peers(&mut peers, &indicator).await;
                            close_all_tunnel_peers(&mut tunnel_peers).await;
                            park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                            return Err(ConnectError::Transient(e.context("net-change re-probe")));
                        }
                        netchange_probe = Some((std::time::Instant::now(), misses));
                        keepalive.reset_after(WS_NETCHANGE_PROBE_DEADLINE);
                    }
                }
                // Missing-pong strike: a ping still unanswered past the
                // degradation bound is the SAME verdict as a late pong,
                // available one zombie round-trip sooner (field: 41 s RTT
                // priced conviction at ~90 s when every verdict waited for
                // its pong to crawl back). A ping still WITHIN its window
                // rides — sending a replacement would reset its clock and
                // the deadline could never accrue under the accelerated
                // cadence.
                let send_fresh_ping = match outstanding_ping {
                    Some(sent) if sent.elapsed() >= WS_PONG_RTT_DEGRADED => {
                        slow_pongs += 1;
                        warn!(
                            unanswered_s = sent.elapsed().as_secs(),
                            strikes = slow_pongs,
                            "control WS keepalive ping unanswered past the degradation bound"
                        );
                        if slow_pongs >= WS_PONG_RTT_STRIKES {
                            if slowness_treadmill_holds(slowness_cycles, ws_epoch.elapsed()) {
                                warn!(
                                    unanswered_s = sent.elapsed().as_secs(),
                                    treadmill_cycles = *slowness_cycles,
                                    "control WS degraded but HELD — fresh connections re-throttled repeatedly, cycling is not improving the path; keeping the alive-but-slow WS (deadness still convicts via the rx deadline)"
                                );
                                slow_pongs = 0;
                            } else {
                                close_all_peers(&mut peers, &indicator).await;
                                close_all_tunnel_peers(&mut tunnel_peers).await;
                                park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                                return Err(ConnectError::Transient(anyhow::anyhow!(
                                    "control WS degraded: keepalive ping unanswered for {} s \
                                     ({} strikes) — cycling to a fresh connection",
                                    sent.elapsed().as_secs(),
                                    slow_pongs
                                )));
                            }
                        }
                        true
                    }
                    Some(_) => false, // in flight and inside its window
                    None => true,
                };
                if send_fresh_ping {
                    if let Err(e) =
                        send_frame(&mut ws, Message::Ping(ping_payload(ws_epoch).into())).await
                    {
                        warn!(%e, "keepalive ping failed — will reconnect");
                        close_all_peers(&mut peers, &indicator).await;
                        close_all_tunnel_peers(&mut tunnel_peers).await;
                        park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                        return Err(ConnectError::Transient(e.context("ws ping")));
                    }
                    outstanding_ping = Some(std::time::Instant::now());
                }
                if slow_pongs > 0 {
                    // One strike in: check again quickly instead of waiting
                    // out the full keepalive interval (only the CADENCE
                    // accelerates; each ping keeps its full window).
                    keepalive.reset_after(WS_PING_RETRY_ACCEL);
                } else if netchange_probe.is_some() {
                    // A probe is out: pull the next tick to its deadline.
                    keepalive.reset_after(WS_NETCHANGE_PROBE_DEADLINE);
                }
                // Liveness: a successful keepalive proves the WS pump
                // is healthy even during long quiet periods between
                // sessions. Without this tick the watchdog would flag
                // a stall after 90 s of no inbound traffic.
                watchdog::tick(ctx.pump);
            }
            summary = next_major_netchange(&mut net_rx) => {
                let _stage = watchdog::enter(ctx.pump, "netchange");
                // New network = new throttle regime — the slowness treadmill
                // re-earns its hold verdict from scratch.
                *slowness_cycles = 0;
                // netstate PR-2 — the network materially moved. Probe the
                // WS immediately (one ping, 5 s verdict at the pulled-
                // forward keepalive tick) instead of trusting a socket the
                // transition may have killed for another 45-90 s. A probe
                // already in flight rides — its verdict covers this change.
                if netchange_probe.is_none() {
                    info!(change = %summary, "MAJOR network change — probing the control WS now");
                    if let Err(e) =
                        send_frame(&mut ws, Message::Ping(ping_payload(ws_epoch).into())).await
                    {
                        warn!(%e, "net-change probe ping failed — reconnecting");
                        close_all_peers(&mut peers, &indicator).await;
                        close_all_tunnel_peers(&mut tunnel_peers).await;
                        park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                        return Err(ConnectError::Transient(e.context("net-change probe ping")));
                    }
                    if outstanding_ping.is_none() {
                        outstanding_ping = Some(std::time::Instant::now());
                    }
                    netchange_probe = Some((std::time::Instant::now(), 0));
                    keepalive.reset_after(WS_NETCHANGE_PROBE_DEADLINE);
                }
            }
            _ = heartbeat.tick() => {
                let _stage = watchdog::enter(ctx.pump, "heartbeat");
                // Wave 3 — tunnel volume the server cannot see for itself
                // (the payload rides the P2P data channel). Cumulative for
                // each forward's life, so the server treats it like the
                // other byte counters: store per bucket, difference on read.
                let tunnel_bytes = tunnel_hub.flows_snapshot().iter().fold(
                    (0u64, 0u64),
                    |(rx, tx), f| {
                        (rx.saturating_add(f.bytes_in), tx.saturating_add(f.bytes_out))
                    },
                );
                // The borrow guards are dropped before the send await.
                let sys = sys_sampler.sample(&overlay_view_tx.borrow(), tunnel_bytes);
                // NAT-traversal health. `None` only while the overlay runtime
                // hasn't published a gather yet — once it has, a measured 0 is
                // reported as 0, which is the value the server actually needs
                // (it means this node can't hole-punch at all).
                let srflx_count = overlay_view_tx
                    .borrow()
                    .srflx
                    .as_ref()
                    .map(|s| s.candidates.len().min(u8::MAX as usize) as u8);
                // C4 stage 2 — advertise the live warm allocation's relayed
                // address so the server holds it pair-less: a peer whose
                // pair to this node dies can dial it WITHOUT a coordination
                // round-trip through this (possibly captured) WS.
                let warm_relay = overlay_view_tx
                    .borrow()
                    .warm_relay
                    .as_ref()
                    .filter(|w| w.state == "live")
                    .and_then(|w| w.relayed.clone());
                // FR-43 P2c — announce capabilities only when they have
                // CHANGED. Caps travel once in `rc:agent.hello`, which is too
                // early for a macOS daemon: it must say hello immediately, and
                // the GUI worker whose permissions it reports attaches later
                // (or never, when nobody is logged in).
                //
                // ⚠️ Sending them every beat would be ~200 bytes of nothing on
                // a frequent message. `None` means "no news", not "no caps".
                let caps_now = delegate.as_ref().and_then(|d| d.effective_permissions());
                // FR-85 P3b — the owner's remote-recording gate is live, so its
                // word is news too: an OFF must stop the hub granting RECORD
                // within a beat, not at the next reconnect.
                //
                // FR-85 P1e-mac — on a supervised Mac, the WORKER's word: a
                // delegated session records there, with the person's recorder
                // and gates, while this root daemon can record nothing. PRIMARY
                // ORG ONLY, like delegation itself: a secondary org's session is
                // never handed to the worker, so its row keeps our own caps.
                let record_now = ctx
                    .is_primary
                    .then(|| delegate.as_ref().and_then(|d| d.effective_record()))
                    .flatten()
                    .unwrap_or_else(record_caps);
                let keep_busy_now = crate::keep_busy::advertised();
                let sas_now = sas_advertised();
                let desktop_now = crate::desktop_brief::current();
                let exec_system_now = crate::exec_service::advertised_for(&cfg.agent_id);
                let ssh_system_now =
                    crate::ssh_service::advertised_for(&cfg.agent_id, cfg.ssh_enabled);
                // FR-99 P1b — the owner's privacy switch is live: an OFF must
                // stop the hub granting PRIVACY within a beat.
                let privacy_now: Vec<String> = crate::privacy::current_words()
                    .into_iter()
                    .map(|w| w.wire().to_string())
                    .collect();
                // FR-101 P2b — the owner's floor is live too: a new `off` must
                // reach the hub's strip (and its reason) within a beat.
                let session_policy_now = crate::session_policy::caps_policy();
                let relay_server_now = relay_server_ready();
                let caps = if relay_server_now == last_announced_relay_server
                    && caps_now == last_announced_permissions
                    && record_now == last_announced_record
                    && keep_busy_now == last_announced_keep_busy
                    && sas_now == last_announced_sas
                    && desktop_now == last_announced_desktop
                    && exec_system_now == last_announced_exec_system
                    && ssh_system_now == last_announced_ssh_system
                    && privacy_now == last_announced_privacy
                    && session_policy_now == last_announced_session_policy
                {
                    None
                } else {
                    last_announced_relay_server = relay_server_now;
                    last_announced_permissions = caps_now.clone();
                    last_announced_record = record_now.clone();
                    last_announced_keep_busy = keep_busy_now;
                    last_announced_sas = sas_now;
                    last_announced_desktop = desktop_now;
                    last_announced_exec_system = exec_system_now;
                    last_announced_ssh_system = ssh_system_now;
                    last_announced_privacy = privacy_now;
                    last_announced_session_policy = session_policy_now;
                    // Our own caps AS THE HELLO BUILT THEM — the server replaces
                    // its stored blob with this, so anything the hello carried
                    // (`multi_org` `tun`, `record`) must be here too — with the
                    // worker's permissions substituted: codecs and encoders
                    // stay OURS, because we are the half that answers
                    // `rc:session.request` (the P2b-3 lesson).
                    let mut c = stub_caps(cfg.overlay_multi_org, ctx.is_primary);
                    if !ctx.is_primary {
                        strip_replica_verbs(&mut c.rpc);
                    }
                    crate::vault::apply_word(
                        &mut c.rpc,
                        crate::vault::takes_leases(cfg.vault_enabled, ctx.is_primary),
                    );
                    crate::exec_service::apply_word(&mut c.rpc, exec_system_now);
                    crate::ssh_service::apply_word(&mut c.rpc, ssh_system_now);
                    c.record = record_now;
                    if let Some((perms, has_input)) = caps_now {
                        c.permissions = Some(perms);
                        c.has_input_permission = has_input;
                    }
                    info!(
                        permissions = ?c.permissions,
                        record = ?c.record,
                        desktop = ?c.desktop,
                        "announcing changed capabilities on the heartbeat (FR-43 P2c)"
                    );
                    Some(Box::new(c))
                };
                let hb = ClientMsg::AgentHeartbeat {
                    rss_mb: sys.rss_mb,
                    cpu_pct: sys.cpu_pct,
                    active_sessions: peers.len().min(u8::MAX as usize) as u8,
                    sys: Some(sys),
                    srflx_count,
                    warm_relay,
                    // FR-27 — cached for 10 min inside, so this is a map lookup
                    // on all but one heartbeat in twenty.
                    companion_version: crate::companion::installed_version(),
                    caps,
                    // FR-92 P5b — where keep busy runs, for the device list.
                    keep_busy: crate::keep_busy::brief(),
                };
                if let Err(e) = send_msg(&mut ws, &hb).await {
                    warn!(%e, "heartbeat send failed — will reconnect");
                    close_all_peers(&mut peers, &indicator).await;
                    close_all_tunnel_peers(&mut tunnel_peers).await;
                    park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                    return Err(ConnectError::Transient(e.context("heartbeat send")));
                }
                // Wave 2 — one `rc:session.stats` per LIVE session, on the
                // heartbeat's own 30 s tick (no extra timer, and it stops
                // by construction when the session map empties). The
                // server folds these into `remote_sessions.stats`, which
                // recorded zeros for every session before this.
                for (session_id, peer) in peers.iter() {
                    // FR-102 P9d — one helper, shared with the carrier-ready
                    // arm, and it queues on EACH PEER'S OWN sender (the FR-43
                    // seam), never on this loop's WS: a delegated session's
                    // sample must reach the server under the daemon's
                    // identity, the one its row carries. Peers may therefore
                    // hold different senders, so one peer's full or closed
                    // queue — or its telemetry timing out — skips that peer
                    // and never stops the others.
                    send_one_session_stats(*session_id, peer, ctx.pump).await;
                }
                watchdog::tick(ctx.pump);
            }
            Some(mut outbound_msg) = outbound_rx.recv() => {
                let _stage = watchdog::enter(ctx.pump, "outbound");
                // FR-52 P4 — the choke point for answers this process did not
                // build itself: a GUI worker's (FR-43), relayed up by the
                // delegation host. An external session's answer is sealed
                // here; one that cannot be sealed is replaced by the
                // session's end — never sent bare.
                if !crate::extauth::seal_outbound(remote_cfg, &mut outbound_msg)
                    && let ClientMsg::SdpAnswer { session_id, .. } = outbound_msg
                {
                    crate::extauth::end_session(remote_cfg, session_id);
                    outbound_msg = ClientMsg::Terminate {
                        session_id,
                        reason: EndReason::AgentHangup,
                        limit: None,
                    };
                }
                // FR-100 P1b — and an in-org answer is signed here, with the
                // device key the worker never holds, against the offer the
                // daemon noted before delegating it. Whatever the worker put
                // in `peer_auth` is replaced. (A Terminate passes untouched.)
                crate::peer_auth::sign_outbound(
                    remote_cfg.peer_auth_offers(),
                    remote_cfg.config_path(),
                    &cfg.tenant_id,
                    &cfg.agent_id,
                    remote_cfg.peer_auth_policy(),
                    &mut outbound_msg,
                );
                if let Err(e) = send_msg(&mut ws, &outbound_msg).await {
                    // A failed control-WS write means the connection is
                    // done — warn-and-continue only deferred the cycle to
                    // the RX deadline (~80 s of dead air), and a WEDGED
                    // send never surfaces on the read side at all. Same
                    // teardown as every other fatal arm.
                    warn!(%e, "failed to flush peer-originated message — will reconnect");
                    close_all_peers(&mut peers, &indicator).await;
                    close_all_tunnel_peers(&mut tunnel_peers).await;
                    park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                    return Err(ConnectError::Transient(e.context("outbound flush")));
                }
                watchdog::tick(ctx.pump);
            }
            Some(sid) = carrier_ready_rx.recv() => {
                let _stage = watchdog::enter(ctx.pump, "carrier_ready");
                // FR-102 P9d — the carrier observation for a LIVE session just
                // landed (`session_carrier::observe` set the OnceLock and
                // signalled). Send ONE `rc:session.stats` for it NOW, by the
                // SAME road the 30 s tick uses: this loop's `peers` to find
                // the peer, and the peer's OWN sender (the FR-43 seam) to
                // carry the sample — this loop's `outbound_tx`, which the arm
                // above flushes to the WS one hop later, or the delegation
                // channel for a delegated session, relayed by the daemon
                // under its own identity. So a session that ends before the
                // next tick still records its carrier. The 30 s tick is
                // unchanged and keeps re-sending it (the server's `$set` is
                // idempotent).
                //
                // A session already gone — ended between the signal and here —
                // is no longer in `peers`: nothing to send, which is exactly
                // the weak-handle property P9c kept. A full or closed sender
                // is logged by the shared helper, never fatal, and the next
                // tick retries.
                if let Some(peer) = peers.get(&sid) {
                    send_one_session_stats(sid, peer, ctx.pump).await;
                }
                watchdog::tick(ctx.pump);
            }
            Some((session_hex, allow)) = consent_rx.recv() => {
                let _stage = watchdog::enter(ctx.pump, "consent");
                // FR-27 — an Approve/Deny from the NATIVE panel. Routed
                // through the broker, not applied here, so it passes the same
                // live-prompt gate as a LocalAPI or CLI decision: an answer
                // only counts for a question the broker is actively asking,
                // which is what makes pre-approval unrepresentable.
                let recorded = consent_broker.record_decision(&session_hex, allow);
                info!(
                    session = %session_hex, allow, recorded,
                    "native consent panel decision"
                );
                // Take the panel down either way. If the broker refused it,
                // the prompt it belonged to is already over, and a panel left
                // on screen for a resolved session is its own bug.
                indicator.hide_prompt(&session_hex);
                watchdog::tick(ctx.pump);
            }
            Some((sid, end)) = device_end(kill_rx, idle_rx) => {
                let _stage = watchdog::enter(ctx.pump, "device_end");
                // FR-101 P4b-2 — a hand-back from an idle watcher races the
                // session's own end; one this connection no longer holds has
                // nothing left to end (a disconnect closed every peer).
                if end == DeviceEnd::Idle && !peers.contains_key(&sid) {
                    debug!(session_id = %sid, "idle limit reached for a session no longer held — nothing to end");
                    continue;
                }
                // Viewee clicked "Disconnect" in the on-screen overlay: the
                // Windows badge, or the companion banner over LocalAPI. Or
                // (P4b-2) the session sat idle past its limit: the same end,
                // said the same way, under its own reason.
                //
                // FR-27 P10 — SAY it first, then close. The hub forwards the
                // Terminate to the controller before it echoes it back here
                // (the echo handler is idempotent), so the viewer learns that
                // the person at the device ended the session BEFORE its peer
                // dies, closes as such, and does not reconnect on its own.
                // Closing first made the browser read a plain drop and come
                // back within 3 s, hanging the old session up itself — which
                // is why the audit used to say `controller_hangup` (the P10
                // field log). The peer closes after a short grace, in a task
                // of its own, so this loop is never held.
                match end {
                    DeviceEnd::HostDisconnect => {
                        info!(session_id = %sid, "viewee requested disconnect via overlay badge")
                    }
                    DeviceEnd::Idle => {
                        info!(session_id = %sid, "idle limit reached — ending the session")
                    }
                }
                // FR-85 P3b-3 — the person at the device sent the controller
                // away: a recording of this session STOPS now, rather than
                // wait for the controller to come back (a drop does wait). An
                // idle end is final in the same way: the viewer does not
                // reconnect from it.
                #[cfg(feature = "recording")]
                crate::recording::remote::host_ended(sid);
                // Control ends at the click, not after the grace: no input,
                // clipboard, files or frames from here on, while the bare
                // connection waits for the viewer to hear why.
                let peer = peers.remove(&sid);
                if let Some(peer) = &peer {
                    peer.stop_serving();
                    // FR-101 P3 — the audit's last sample, while the server
                    // still holds the session live (the terminate follows).
                    //
                    // ⚠️ Deliberately NOT the per-peer road the live samples
                    // take (`send_one_session_stats`, FR-102 P9d): this one
                    // must land BEFORE the terminate directly below it, and
                    // the server drops a sample once `ended_at` is set — on
                    // the peer's queue, the direct terminate write would
                    // overtake it. Pre-existing follow-up, out of P9d's
                    // scope: `delegated_out` is connection-wide, so on a
                    // supervised Mac a worker's OWN session (its own row)
                    // goes up the delegation channel here too, under the
                    // daemon's identity, and the server drops it as another
                    // device's. A fix needs the terminate on the same queue
                    // as the sample, or a per-session delegation marker.
                    if let Some(stats) = final_session_stats(sid, peer).await
                        && let Err(e) =
                            reply_for_session(&mut ws, delegated_out.as_ref(), &stats).await
                    {
                        debug!(session_id = %sid, %e, "final session stats send failed");
                    }
                }
                // A delegated session (a supervised Mac) speaks through the
                // daemon's WS, the way its answer and its ICE did.
                let grace = match reply_for_session(
                    &mut ws,
                    delegated_out.as_ref(),
                    &end.terminate(sid),
                )
                .await
                {
                    Ok(()) => host_disconnect_grace(),
                    Err(e) => {
                        warn!(
                            session_id = %sid, %e, reason = end.label(),
                            "host disconnect: could not tell the server — closing the peer now"
                        );
                        Duration::ZERO
                    }
                };
                // The FR-27 field logs key on the host-disconnect line as it
                // reads; the idle end says its own.
                let grace_ms = grace.as_millis() as u64;
                match end {
                    DeviceEnd::HostDisconnect => info!(
                        session_id = %sid,
                        reason = end.label(),
                        grace_ms,
                        "host disconnect: told the server; the peer closes after the grace"
                    ),
                    DeviceEnd::Idle => info!(
                        session_id = %sid,
                        reason = end.label(),
                        grace_ms,
                        "idle limit: told the server; the peer closes after the grace"
                    ),
                }
                if let Some(peer) = peer {
                    let label = end.label();
                    tokio::spawn(async move {
                        tokio::time::sleep(grace).await;
                        close_within_budget(peer.close(), sid, label).await;
                    });
                }
                crate::gpu_clock::on_sessions_changed(peers.len());
                pending_codecs.remove(&sid);
                pending_transports.remove(&sid);
                pending_audio.remove(&sid);
                pending_permissions.remove(&sid);
                pending_session_meta.remove(&sid);
                crate::extauth::end_session(remote_cfg, sid);
                indicator.hide_session(sid.to_hex());
                watchdog::tick(ctx.pump);
            }
            Some(reap) = tunnel_reap_rx.recv() => {
                let _stage = watchdog::enter(ctx.pump, "tunnel_reap");
                // #1754 — a tunnel peer reports its client gone (a pool DC
                // closed, the peer connection Failed, the QUIC connection
                // ended). Until now only `rc:tunnel.terminate` and the WS
                // ending removed a peer, so a client that never sent its
                // terminate left its sockets in these maps for the life of
                // the connection.
                //
                // Both maps at once: a session is on exactly one data plane,
                // and the helper says which. A report for a session neither
                // map holds is the ordinary case, not an error — a peer
                // closed by the terminate arm reports its OWN close (the
                // DCs' EOF, then `Closed`), and a parked QUIC peer's report
                // can arrive after the reclaim already dropped it.
                let sid = reap.session_id;
                let Some(held) = take_reaped_tunnel_peer(sid, &mut tunnel_peers, &mut tunnel_quic_peers) else {
                    debug!(session_id = %sid, signal = %reap.signal, "tunnel reap for a session no map holds — already gone");
                    continue;
                };
                info!(
                    session_id = %sid,
                    signal = %reap.signal,
                    transport = held.transport(),
                    "tunnel peer's client is gone — reaping the session (#1754)"
                );
                match held {
                    ReapedTunnelPeer::WebRtc(peer) => {
                        // Same bound as every other close site: a webrtc
                        // close on a captured network must not stall this
                        // loop into the watchdog.
                        close_within_budget(peer.close(), sid, "tunnel_remote_gone").await;
                    }
                    ReapedTunnelPeer::Quic(peer) => peer.close(),
                }
                // Tell the server, which relays it to the client if one is
                // somehow still registered (the server does not clean the
                // session up on our word — the client's own terminate does
                // that, and its echo back to us finds an empty map).
                let _ = send_msg(
                    &mut ws,
                    &ClientMsg::TunnelTerminate {
                        session_id: sid,
                        reason: CloseReason::IoError,
                    },
                )
                .await;
                watchdog::tick(ctx.pump);
            }
            Some(outcome) = quic_setup_rx.recv() => {
                let _stage = watchdog::enter(ctx.pump, "quic_setup");
                // #1761 — a TURN-relayed QUIC setup finished on its task.
                // `settle` decides against this connection's in-flight
                // entries: the attempt still held and not cancelled is
                // inserted; a cancelled or late one (a terminate arrived
                // meanwhile, or the setup outlived the connection that
                // started it) has been closed inside `settle` — never
                // inserted, never merely dropped (#1754). The candidates
                // that arrived while the peer was being built are
                // permitted BEFORE the ready goes out, so the client's
                // opening Initials meet their TURN permission.
                let sid = outcome.session_id;
                match pending_quic_setups.settle(outcome) {
                    Settled::Ready { peer, candidates } => {
                        crate::tunnel::quic_setup::permit_candidates(&peer, sid, &candidates).await;
                        let ready = ClientMsg::TunnelQuicReady {
                            session_id: sid,
                            cert_fingerprint: peer.cert_fingerprint().to_string(),
                            addrs: peer.addrs(),
                            derp_pubkey: None,
                        };
                        if let Some(displaced) = tunnel_quic_peers.insert(sid, peer) {
                            // Only an R3-reclaimed peer could already sit
                            // here. One peer per session: closed, so its
                            // accept task cannot later reap the new one.
                            warn!(session_id = %sid, "tunnel quic: a peer already held this session — closing the displaced one");
                            displaced.close();
                        }
                        let _ = outbound_tx.send(ready).await;
                        info!(session_id = %sid, buffered_candidates = candidates.len(), "agent QUIC peer ready; rc:tunnel.quic.ready sent");
                    }
                    Settled::Failed(QuicSetupError::Allocate(e)) => {
                        warn!(session_id = %sid, %e, "tunnel quic: TURN allocate failed — no QUIC relay this session");
                    }
                    Settled::Failed(QuicSetupError::Setup(e)) => {
                        warn!(session_id = %sid, %e, "tunnel quic: AgentQuicPeer setup failed");
                    }
                    Settled::Closed { verdict, had_peer } => {
                        info!(session_id = %sid, ?verdict, had_peer, "tunnel quic: setup result not inserted — closed (#1761)");
                    }
                }
                watchdog::tick(ctx.pump);
            }
            // FR-43 P2b-2 — an rc message the root daemon delegated to us.
            //
            // It runs through the SAME `handle_server_msg` with the SAME
            // session state as our own sessions: the session ids come from the
            // daemon's device row and cannot collide with ours, and everything
            // downstream differs only in the sender the peer is built with.
            //
            // The argument list is duplicated from the `ws.next()` arm below
            // rather than hoisted, because hoisting it would mean restructuring
            // that arm's nested parse/intercept chain — a bigger change than
            // this feature. Divergence is a compile error, so the duplication
            // cannot rot silently.
            Some(inbound) = next_delegated(&mut delegated_in) => {
                let _stage = watchdog::enter(ctx.pump, "delegated");
                watchdog::tick(ctx.pump);
                let delegated_msg = match inbound {
                    // The parameters the daemon resolved, arriving ahead of the
                    // offer that consumes them. Populating the SAME maps the
                    // `Request` arm would have means the `SdpOffer` handler
                    // needs no delegation-specific branch at all.
                    crate::delegate::WorkerInbound::Params(p) => {
                        match bson::oid::ObjectId::parse_str(&p.session_id) {
                            Ok(sid) => {
                                if !shared_leases.note_optional(sid, p.shared_lease.as_ref()) {
                                    continue;
                                }
                                pending_codecs.insert(sid, p.codec);
                                pending_transports.insert(sid, p.transport);
                                pending_chroma.insert(sid, p.chroma);
                                pending_chunk_framing.insert(sid, p.chunk_framing);
                                pending_audio.insert(sid, p.audio);
                                pending_permissions.insert(sid, p.permissions);
                                // FR-85 P1e-mac — the record context the daemon
                                // resolved. This worker is the half that records:
                                // it owns the peer, and its recorder runs as the
                                // person, in their GUI session. None from an older
                                // daemon (or an unparseable id): the channel then
                                // refuses `unavailable`, as before.
                                let record = p.record.and_then(|r| {
                                    Some(RecordMeta {
                                        controller_user_id: bson::oid::ObjectId::parse_str(
                                            &r.controller_user_id,
                                        )
                                        .ok()?,
                                        prompt_window: r.prompt_window_ms.map(Duration::from_millis),
                                    })
                                });
                                // #1882 — the daemon's overlay decision, with its
                                // overlay blocks: this worker runs no overlay to
                                // read them from. An older daemon sends none,
                                // which is the default — off.
                                pending_session_meta.insert(
                                    sid,
                                    (
                                        p.controller_name,
                                        p.input_mode,
                                        p.asking_org,
                                        record,
                                        p.rc_overlay.unwrap_or_default(),
                                        // FR-101 P4b-2 — the idle limit is
                                        // this worker's to keep: it owns the
                                        // peer, the input and the screen. An
                                        // older daemon sends none.
                                        p.idle_secs,
                                        // FR-99 P3b — and so is the lock ask.
                                        p.lock_on_end,
                                    ),
                                );
                                info!(session_id = %sid, "delegation: session params received");
                            }
                            Err(e) => {
                                warn!(%e, sid = %p.session_id, "delegation: unparseable session id");
                            }
                        }
                        continue;
                    }
                    crate::delegate::WorkerInbound::Msg(m) => *m,
                };
                info!(
                    kind = crate::delegate::server_msg_kind(&delegated_msg),
                    "delegation: serving a delegated rc message"
                );
                handle_server_msg(
                    ctx,
                    &cfg.tenant_id,
                    &mut ws,
                    delegated_msg,
                    &mut shared_leases,
                    &mut shared_ssh,
                    &mut peers,
                    &mut pending_codecs,
                    &mut pending_transports,
                    &mut pending_chroma,
                    &mut pending_chunk_framing,
                    &mut pending_audio,
                    &mut pending_permissions,
                    &mut pending_session_meta,
                    &mut tunnel_peers,
                    &mut tunnel_quic_peers,
                    &outbound_tx,
                    tunnel_reap_tx,
                    &mut pending_quic_setups,
                    quic_setup_tx,
                    idle_tx,
                    encoder_preference,
                    &indicator,
                    &consent_broker,
                    &cfg.forward_acl,
                    &relay_regions_slot,
                    &derp_ticket_slot,
                    cfg,
                    remote_cfg,
                    delegate.as_ref(),
                    delegated_out.as_ref(),
                    carrier_ready_tx,
                )
                .await?;
            }
            maybe_msg = ws.next() => match maybe_msg {
                Some(Ok(Message::Text(text))) => {
                    let _stage = watchdog::enter(ctx.pump, "ws.text");
                    last_rx = std::time::Instant::now();
                    watchdog::tick(ctx.pump);
                    match serde_json::from_str::<ServerMsg>(&text) {
                        Ok(parsed) => {
                            // #2551 — which message this arm is handling: the
                            // dispatch below awaits per message.
                            watchdog::stage(
                                ctx.pump,
                                format!("ws.text:{}", server_msg_tag(&text).unwrap_or("?")),
                            );
                            // Phase 3b: route `rc:overlay.*` to the node
                            // runtime; everything else falls through to the
                            // normal dispatch below.
                            #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
                            let parsed = match &overlay_evt_tx {
                                Some(tx) => match crate::overlay::intercept(tx, parsed, ctx.is_primary) {
                                    Some(p) => p,
                                    None => continue,
                                },
                                None => parsed,
                            };
                            // P3b-2 PR-C: route client-bound tunnel replies to
                            // this daemon's originated flows; everything else
                            // (incl. the target-side tunnel messages) falls
                            // through to `handle_server_msg` unchanged.
                            let parsed = match crate::tunnel::client_mgr::intercept_server_msg(
                                &tunnel_hub,
                                parsed,
                            ) {
                                Some(p) => p,
                                None => continue,
                            };
                            handle_server_msg(
                                ctx,
                                &cfg.tenant_id,
                                &mut ws,
                                parsed,
                                &mut shared_leases,
                                &mut shared_ssh,
                                &mut peers,
                                &mut pending_codecs,
                                &mut pending_transports,
                                &mut pending_chroma,
                                &mut pending_chunk_framing,
                                &mut pending_audio,
                                &mut pending_permissions,
                                &mut pending_session_meta,
                                &mut tunnel_peers,
                                &mut tunnel_quic_peers,
                                &outbound_tx,
                                tunnel_reap_tx,
                                &mut pending_quic_setups,
                                quic_setup_tx,
                                idle_tx,
                                encoder_preference,
                                &indicator,
                                &consent_broker,
                                &cfg.forward_acl,
                                &relay_regions_slot,
                                &derp_ticket_slot,
                                cfg,
                                remote_cfg,
                                delegate.as_ref(),
                                // A message off our OWN control WS is never a
                                // delegated one — its replies belong here.
                                None,
                                carrier_ready_tx,
                            )
                            .await?;
                        }
                        // A parse failure has TWO causes that this arm used to
                        // report as one, and the difference is the difference
                        // between noise and an outage.
                        //
                        // Something that is not ours at all (a proxy's keepalive,
                        // a future frame family) is genuinely ignorable — debug.
                        //
                        // But a frame whose `t` starts with `rc:` IS ours and
                        // failed to decode, which means the server sent
                        // something this build cannot read and the frame is
                        // being dropped whole. For an `rc:overlay.netmap` that
                        // is the entire mesh: no address, no peers, and — at
                        // debug — no sign of it. That is not hypothetical: a
                        // REQUIRED field the client never reads (`epoch`) is
                        // enough to trigger it, and the message would have
                        // claimed the frame was "non-rc:*" while naming an
                        // `rc:` tag in its own payload.
                        //
                        // Deliberately not fatal: dropping one frame is still
                        // better than exiting, and an old agent meeting a new
                        // frame family must keep running. It just has to SAY so.
                        Err(e) => {
                            let tag = serde_json::from_str::<serde_json::Value>(&text)
                                .ok()
                                .and_then(|v| v.get("t")?.as_str().map(str::to_string));
                            match tag {
                                Some(t) if t.starts_with("rc:") => warn!(
                                    %e, %t,
                                    "DROPPED a roomler frame this build cannot decode — the \
                                     server sent a shape we do not understand; anything it \
                                     carried (a netmap, a session) did not arrive"
                                ),
                                _ => debug!(%e, text = %text.as_str(), "ignoring non-rc:* frame"),
                            }
                        }
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    let _stage = watchdog::enter(ctx.pump, "ws.ping");
                    last_rx = std::time::Instant::now();
                    if let Err(e) = send_frame(&mut ws, Message::Pong(data)).await {
                        warn!(%e, "pong reply failed — will reconnect");
                        close_all_peers(&mut peers, &indicator).await;
                        close_all_tunnel_peers(&mut tunnel_peers).await;
                        park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                        return Err(ConnectError::Transient(e.context("ws pong")));
                    }
                    watchdog::tick(ctx.pump);
                }
                Some(Ok(Message::Close(_))) | None => {
                    let _stage = watchdog::enter(ctx.pump, "ws.close");
                    info!("ws closed by peer");
                    close_all_peers(&mut peers, &indicator).await;
                    close_all_tunnel_peers(&mut tunnel_peers).await;
                    park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                    return Ok(());
                }
                Some(Err(e)) => {
                    let _stage = watchdog::enter(ctx.pump, "ws.error");
                    close_all_peers(&mut peers, &indicator).await;
                    close_all_tunnel_peers(&mut tunnel_peers).await;
                    park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                    return Err(ConnectError::Transient(anyhow::Error::new(e).context("ws read")));
                }
                Some(Ok(Message::Pong(payload))) => {
                    let _stage = watchdog::enter(ctx.pump, "ws.pong");
                    last_rx = std::time::Instant::now();
                    outstanding_ping = None;
                    // Zombie-slow WS detector (see [`WS_PONG_RTT_DEGRADED`]):
                    // a pong echoing one of OUR stamped pings measures the
                    // true application round trip. Two consecutive verdicts
                    // over the bound mean the path is unusable for the
                    // request/reply traffic that rides it (relay grants,
                    // exec) — cycle to a fresh connection; the persistent
                    // overlay runtime rides through WS reconnects untouched.
                    if let Some(rtt) = pong_rtt(&payload, ws_epoch) {
                        if rtt >= WS_PONG_RTT_DEGRADED {
                            slow_pongs += 1;
                            warn!(
                                rtt_s = rtt.as_secs(),
                                strikes = slow_pongs,
                                "control WS pong RTT degraded"
                            );
                            if slow_pongs >= WS_PONG_RTT_STRIKES {
                                if slowness_treadmill_holds(slowness_cycles, ws_epoch.elapsed()) {
                                    warn!(
                                        rtt_s = rtt.as_secs(),
                                        treadmill_cycles = *slowness_cycles,
                                        "control WS degraded but HELD — fresh connections re-throttled repeatedly, cycling is not improving the path; keeping the alive-but-slow WS (deadness still convicts via the rx deadline)"
                                    );
                                    slow_pongs = 0;
                                } else {
                                    close_all_peers(&mut peers, &indicator).await;
                                    close_all_tunnel_peers(&mut tunnel_peers).await;
                                    park_survived_quic_peers(&mut tunnel_quic_peers, &cfg.tenant_id).await;
                                    return Err(ConnectError::Transient(anyhow::anyhow!(
                                        "control WS degraded: pong rtt {} s ({} consecutive over \
                                         the {} s bound) — cycling to a fresh connection",
                                        rtt.as_secs(),
                                        slow_pongs,
                                        WS_PONG_RTT_DEGRADED.as_secs()
                                    )));
                                }
                            }
                        } else {
                            slow_pongs = 0;
                        }
                    }
                    watchdog::tick(ctx.pump);
                }
                // Binary / raw frames — any inbound frame proves the link
                // is alive.
                Some(Ok(_)) => {
                    let _stage = watchdog::enter(ctx.pump, "ws.other");
                    last_rx = std::time::Instant::now();
                }
            }
        }
    }
}

/// Tell the server what this device did with a pushed desired-config
/// (`docs/remote-config.md`).
///
/// Fire-and-forget, mirroring `ssh::ActivitySink::report` and for the same
/// reason: a full outbound queue means the connection is already struggling,
/// and losing a status line must never be allowed to stall the WS receive path
/// that produced it. The daemon log always has the same information.
///
/// `detail` is redacted and capped BEFORE it leaves the host — it is an error
/// string we did not compose, so it gets the same treatment as any other text
/// this daemon ships off the machine.
fn report_config_status(
    outbound_tx: &mpsc::Sender<ClientMsg>,
    revision: u64,
    outcome: roomler_ai_remote_control::models::ConfigOutcome,
    detail: Option<&str>,
) {
    use roomler_ai_remote_control::models::ConfigReport;

    let detail = detail.map(|d| {
        let mut s = crate::exec::redactor().apply(d);
        if s.chars().count() > ConfigReport::MAX_DETAIL {
            s = s.chars().take(ConfigReport::MAX_DETAIL).collect();
            s.push('…');
        }
        s
    });
    let msg = ClientMsg::ConfigStatus {
        revision,
        outcome,
        live: Vec::new(),
        needs_restart: Vec::new(),
        detail,
    };
    if outbound_tx.try_send(msg).is_err() {
        debug!("rc:agent.config_status dropped (outbound queue full or closed)");
    }
}

/// FR-40 — the device's answer to `rc:agent.key_rotate`, on every outcome.
/// Same fire-and-forget rule as [`report_config_status`]; `detail` is
/// redacted and capped before it leaves the host. Only PUBLIC keys are ever
/// passed here — the frame has no field for anything else, by construction.
fn report_key_rotated(
    outbound_tx: &mpsc::Sender<ClientMsg>,
    request_id: &str,
    outcome: roomler_ai_remote_control::models::KeyRotationOutcome,
    old_public_key: Option<&str>,
    new_public_key: Option<&str>,
    key_epoch: u32,
    detail: Option<&str>,
) {
    use roomler_ai_remote_control::models::KeyRotationReport;

    let detail = detail.map(|d| {
        let mut s = crate::exec::redactor().apply(d);
        if s.chars().count() > KeyRotationReport::MAX_DETAIL {
            s = s.chars().take(KeyRotationReport::MAX_DETAIL).collect();
            s.push('…');
        }
        s
    });
    let msg = ClientMsg::KeyRotated {
        request_id: request_id.to_string(),
        outcome,
        old_public_key: old_public_key.map(str::to_string),
        new_public_key: new_public_key.map(str::to_string),
        key_epoch,
        detail,
    };
    if outbound_tx.try_send(msg).is_err() {
        debug!("rc:agent.key_rotated dropped (outbound queue full or closed)");
    }
}

/// FR-40 P1c — a `rotated` report to re-send on the NEXT session of the org
/// that rotated. The first copy rides the session that is about to end and
/// can be lost — in the second field run the server never received it and
/// resolved `delivered` for a rotation it had itself verified at the join.
/// The re-send rides a healthy socket; the server's conditional write makes
/// the duplicate harmless.
struct PendingRotationReport {
    request_id: String,
    old_public_key: Option<String>,
    new_public_key: String,
    key_epoch: u32,
}

/// Keyed per org (tenant id): every org loop lives in this one daemon and
/// must only re-send its OWN rotation.
fn pending_rotation_reports() -> &'static std::sync::Mutex<HashMap<String, PendingRotationReport>> {
    static SLOT: std::sync::OnceLock<std::sync::Mutex<HashMap<String, PendingRotationReport>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn drain_pending_rotation_report(tenant_id: &str, outbound_tx: &mpsc::Sender<ClientMsg>) {
    let pending = pending_rotation_reports()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(tenant_id);
    if let Some(p) = pending {
        info!(
            request_id = %p.request_id,
            key_epoch = p.key_epoch,
            "rc:agent.key_rotated — re-sending the rotation report on the new session"
        );
        report_key_rotated(
            outbound_tx,
            &p.request_id,
            roomler_ai_remote_control::models::KeyRotationOutcome::Rotated,
            p.old_public_key.as_deref(),
            Some(&p.new_public_key),
            p.key_epoch,
            None,
        );
    }
}

/// FR-40 — the device's own floor between two rotations of ONE org's key.
/// The server enforces the same ceiling; this one survives a server that
/// does not.
const KEY_ROTATION_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// `true` (and stamps now) when no rotation for `tenant_id` ran inside
/// [`KEY_ROTATION_MIN_INTERVAL`]. Process-wide, keyed per org, since every
/// org loop lives in this one daemon.
fn key_rotation_ceiling_ok(tenant_id: &str) -> bool {
    static LAST: std::sync::OnceLock<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
        std::sync::OnceLock::new();
    let m = LAST.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut last = m.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    if let Some(prev) = last.get(tenant_id)
        && now.duration_since(*prev) < KEY_ROTATION_MIN_INTERVAL
    {
        return false;
    }
    last.insert(tenant_id.to_string(), now);
    true
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_msg(
    ctx: &OrgCtx,
    // R4 — this org's tenant id (OrgCtx carries only the label); the
    // quic-derp-v1 setup arm resolves its DERP mux by tenant.
    tenant_id: &str,
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: ServerMsg,
    shared_leases: &mut crate::shared_lease::SharedLeases,
    shared_ssh: &mut crate::ssh_shared_bridge::SharedSshTargets,
    peers: &mut HashMap<bson::oid::ObjectId, AgentPeer>,
    pending_codecs: &mut HashMap<bson::oid::ObjectId, String>,
    pending_transports: &mut HashMap<bson::oid::ObjectId, Option<String>>,
    pending_chroma: &mut HashMap<bson::oid::ObjectId, Option<String>>,
    pending_chunk_framing: &mut HashMap<bson::oid::ObjectId, bool>,
    pending_audio: &mut HashMap<bson::oid::ObjectId, bool>,
    pending_permissions: &mut HashMap<
        bson::oid::ObjectId,
        roomler_ai_remote_control::permissions::Permissions,
    >,
    pending_session_meta: &mut HashMap<bson::oid::ObjectId, SessionMeta>,
    tunnel_peers: &mut HashMap<bson::oid::ObjectId, Arc<crate::tunnel::peer::AgentTunnelPeer>>,
    tunnel_quic_peers: &mut HashMap<
        bson::oid::ObjectId,
        Arc<crate::tunnel::quic_peer::AgentQuicPeer>,
    >,
    outbound_tx: &mpsc::Sender<ClientMsg>,
    // #1754 — handed (cloned) to every tunnel peer built here, so it can
    // report its client gone to the reap arm.
    tunnel_reap_tx: &crate::tunnel::reap::ReapSender,
    // #1761 — this connection's TURN-relayed QUIC setups in flight, and the
    // per-org channel their tasks report on.
    pending_quic_setups: &mut crate::tunnel::quic_setup::PendingQuicSetups,
    quic_setup_tx: &crate::tunnel::quic_setup::QuicSetupSender,
    // FR-101 P4b-2 — handed (cloned) to every live session with an idle
    // limit, so its watcher can hand the session back to this org loop's
    // `idle_rx` arm to be ended.
    idle_tx: &mpsc::Sender<bson::oid::ObjectId>,
    encoder_preference: crate::encode::EncoderPreference,
    indicator: &ViewerIndicator,
    consent_broker: &crate::consent::ConsentBroker,
    forward_acl: &crate::tunnel::acl::AgentForwardAcl,
    relay_regions_slot: &crate::relay_probe::RegionSlot,
    derp_ticket_slot: &crate::relay_probe::DerpTicketSlot,
    // Multi-org: this loop's OWN enrollment — the server_url + machine
    // identity a pushed `rc:agent.join_org` enrolls with. Never a value
    // taken off the wire.
    agent_cfg: &AgentConfig,
    remote_cfg: &crate::remote_config::RemoteConfigServices,
    // FR-43 P2b — the macOS GUI-worker channel, when one is attached. `None`
    // on every other platform and whenever no worker has attached, and the
    // delegation branch below is then unreachable.
    delegate: Option<&crate::delegate::DelegateHost>,
    // FR-43 P2b-2 — set when THIS message was delegated to us by the root
    // daemon, in which case the session's replies belong on the delegation
    // channel and not on our own control WS. `None` is every ordinary session.
    delegated: Option<&mpsc::Sender<ClientMsg>>,
    // FR-102 P9d — handed to every peer built here so its carrier observation
    // can signal this loop (the `carrier_ready_rx` arm) to send one
    // `rc:session.stats` the moment the carrier is known. This is THIS loop's
    // sender, so the signal reaches the loop whose `peers` map holds the peer
    // — the daemon's, a standalone agent's, or the GUI worker's for a
    // delegated session. The sample itself then leaves through the PEER's
    // own sender, the seam chosen at `AgentPeer::new` below (`delegated` or
    // `outbound_tx`), never through this loop's WS: on a worker that would be
    // the wrong identity for a delegated session, and `delegated` is
    // per-message, not per-connection, because the worker serves its own
    // sessions under its own row as well.
    carrier_ready_tx: &mpsc::Sender<bson::oid::ObjectId>,
) -> Result<(), ConnectError> {
    if let ServerMsg::TunnelTerminate { session_id, .. } = &msg {
        shared_leases.end(*session_id);
        shared_ssh.end(*session_id);
    }
    let shared_sid = match &msg {
        ServerMsg::SdpOffer { session_id, .. }
        | ServerMsg::SharedLeaseRenewal { session_id, .. }
        | ServerMsg::Terminate { session_id, .. }
        | ServerMsg::Ice { session_id, .. }
        | ServerMsg::SdpAnswer { session_id, .. }
        | ServerMsg::SessionCreated { session_id, .. } => Some(*session_id),
        _ => None,
    };
    let shared_message = shared_sid.is_some_and(|sid| shared_leases.contains(sid))
        || matches!(
            &msg,
            ServerMsg::SdpOffer {
                shared_lease: Some(_),
                ..
            }
        );
    // #1632 — a Terminate takes any consent prompt still standing for its
    // session down with it, and does so AHEAD of the delegation gate below:
    // the prompt is this daemon's (`Request` is never delegated — consent is
    // the enrolled identity's decision), so on a host whose session media was
    // handed to the GUI worker the local `Terminate` arm never runs here, and
    // the prompt would stand for its full window. Not in the arm, then.
    //
    // The broker resolves the prompt task `Cancelled` (which sends no
    // `rc:consent` — the server has already forgotten the session) and its
    // guard removes the `.pending` marker the companion polls. The native
    // panel is hidden here directly rather than waiting for that task to be
    // scheduled; both calls are idempotent and the task hides again anyway.
    if let ServerMsg::Terminate { session_id, .. } = &msg {
        let session_hex = session_id.to_hex();
        if consent_broker.cancel(&session_hex) {
            info!(%session_id, "consent prompt withdrawn — the session was terminated while awaiting consent");
        }
        indicator.hide_prompt(&session_hex);
    }
    // FR-52 P4 — an EXTERNAL session's offer is judged HERE, ahead of the
    // delegation below: its binding lives in this process, and a GUI worker
    // that received the offer would have nothing to check it against. An
    // ordinary session's offer passes untouched. A refused one ends the
    // session rather than being dropped — a controller left waiting for an
    // answer that never comes learns nothing, and neither does the audit.
    if let ServerMsg::SdpOffer {
        session_id,
        sdp,
        extauth_mac,
        ..
    } = &msg
        && let Err(why) =
            crate::extauth::check_offer(remote_cfg, *session_id, sdp, extauth_mac.as_deref())
    {
        warn!(%session_id, why, "external session: offer refused; ending the session");
        crate::extauth::end_session(remote_cfg, *session_id);
        let _ = reply_for_session(
            ws,
            delegated,
            &ClientMsg::Terminate {
                session_id: *session_id,
                reason: EndReason::AgentHangup,
                limit: None,
            },
        )
        .await;
        return Ok(());
    }
    // FR-100 P1b — every offer's ask (a nonce) is noted HERE too, ahead of
    // the delegation below: the daemon signs the answer, whichever process
    // builds it, against the offer that passed through the daemon. Not in a
    // GUI worker handling a delegated offer: it holds no key, and the daemon
    // has already noted this one.
    if delegated.is_none()
        && let ServerMsg::SdpOffer {
            session_id,
            sdp,
            peer_auth,
            ..
        } = &msg
    {
        remote_cfg
            .peer_auth_offers()
            .note_offer(*session_id, sdp, peer_auth.as_ref());
        // FR-100 P1c — and the browser behind it is judged HERE, for the same
        // reason: the pins are the daemon's, and a GUI worker holds none.
        remote_cfg.peer_auth_offers().judge_offer(
            *session_id,
            sdp,
            peer_auth.as_ref(),
            &crate::peer_auth::OfferCheck {
                policy: remote_cfg.peer_auth_policy(),
                config_path: remote_cfg.config_path(),
                tenant_id,
                agent_id: &agent_cfg.agent_id,
            },
        );
    }
    // …and a session's end ends its binding HERE, for the same reason: a
    // delegated `Terminate` never reaches the arm below. (A no-op for every
    // session that was not external.) FR-100 P1b's notes end with it.
    if let ServerMsg::Terminate { session_id, .. } = &msg {
        shared_leases.end(*session_id);
        crate::extauth::end_session(remote_cfg, *session_id);
        remote_cfg.peer_auth_offers().forget(*session_id);
    }

    // FR-43 P2b — hand a remote-desktop session to the GUI worker, if there is
    // one. This sits ahead of the whole dispatch rather than inside each of
    // the five handlers: one place to read, one place to audit, and no way for
    // a handler to be added later that quietly forgets to check.
    //
    // ⚠️ `send_to_worker` returning false is NOT an error — it means no worker
    // is attached (or its queue is full), and the message then falls through
    // to the local handlers exactly as before. On a root macOS daemon that
    // local path cannot serve pixels, which is the whole reason P2 exists; but
    // failing SOFT is still right, because the alternative is a session that
    // vanishes rather than one that fails the way it always has.
    //
    // ⚠️ PRIMARY ORG ONLY. The GUI worker is host-global — one screen, one
    // keyboard — while the server models policy per org, so a secondary org's
    // admin must not be able to drive it. Same rule, and the same reason, as
    // `rc:agent.update`, exec and the FR-19 relay: a host-global resource
    // belongs to the enrollment that owns the host.
    if shared_message
        && ctx.is_primary
        && delegated.is_none()
        && let Some(delegate) = delegate
        && shared_sid.is_some_and(|sid| delegate.has_shared_params(sid))
    {
        // No fallback after handing a scoped session over: a queue failure may
        // lose a renewal but can never create a second unscoped peer owner.
        let _ = delegate.send_to_worker(&msg);
        return Ok(());
    }
    if let Some(delegate) = delegate
        && ctx.is_primary
        && !shared_message
        && crate::delegate::delegable_inbound(&msg)
        && delegate.send_to_worker(&msg)
    {
        tracing::debug!(
            kind = crate::delegate::server_msg_kind(&msg),
            "delegated an rc message to the GUI worker"
        );
        return Ok(());
    }

    // Service-typed ACKs cannot renew another service even with a matching SID.
    let msg = match msg {
        ServerMsg::SharedLeaseRenewal {
            session_id,
            grant_id,
            lease_epoch,
            challenge_id,
        } => match shared_leases.renew(session_id, grant_id, &lease_epoch, challenge_id) {
            Some(offer) => offer,
            None => return Ok(()),
        },
        ServerMsg::SharedSshLeaseRenewal {
            session_id,
            grant_id,
            lease_epoch,
            challenge_id,
        } => match shared_leases.renew_ssh(session_id, grant_id, &lease_epoch, challenge_id) {
            Some(offer) => offer,
            None => return Ok(()),
        },
        other => other,
    };
    if let ServerMsg::TunnelSdpOffer { session_id, .. } = &msg
        && !shared_leases.offer(*session_id, &msg, outbound_tx)
    {
        return Ok(());
    }
    if let ServerMsg::TunnelIce {
        session_id,
        candidate,
    } = &msg
        && shared_leases.hold_ice(*session_id, candidate)
    {
        return Ok(());
    }
    if let ServerMsg::SdpOffer { session_id, .. } = &msg
        && !shared_leases.offer(*session_id, &msg, delegated.unwrap_or(outbound_tx))
    {
        return Ok(());
    }
    if let ServerMsg::Ice {
        session_id,
        candidate,
    } = &msg
        && shared_leases.hold_ice(*session_id, candidate)
    {
        return Ok(());
    }
    match msg {
        ServerMsg::SharedSshSetup { session_id, setup } => {
            let accepted = {
            #[cfg(feature = "ssh-server")]
            {
            let descriptor = setup.shared_lease.clone();
            let services = crate::ssh::SessionServices {
                power_activity: Some(crate::power::shared_activity().clone()),
                asker: crate::ssh::Asker::Here {
                    broker: consent_broker.clone(),
                    indicator: indicator.clone(),
                },
                activity: crate::ssh::ActivitySink::new(agent_cfg, outbound_tx.clone()),
            };
            shared_ssh.note(session_id, setup, agent_cfg, services)
                && shared_leases.note_ssh(session_id, descriptor)
            }
            #[cfg(not(feature = "ssh-server"))]
            { let _ = setup; false }
            };
            if !accepted {
                shared_ssh.end(session_id);
                shared_leases.end(session_id);
            }
            let _ = outbound_tx.try_send(ClientMsg::SharedSshPrepared {
                session_id,
                accepted,
            });
        }
        ServerMsg::SharedSshForward {
            session_id,
            flow_id,
        } => {
            if let Some(peer) = tunnel_peers.get(&session_id).cloned() {
                shared_ssh.forward(session_id, flow_id, peer, outbound_tx.clone());
            } else {
                let _ = outbound_tx.try_send(ClientMsg::TcpForwardReject {
                    session_id,
                    flow_id,
                    kind: roomler_ai_remote_control::signaling::RejectKind::AclDenied,
                    reason: "Scoped SSH peer is not available".into(),
                });
            }
        }
        ServerMsg::Request {
            shared_lease,
            session_id,
            controller_user_id,
            controller_name,
            permissions,
            consent_timeout_secs,
            browser_caps,
            preferred_transport,
            chroma_pref,
            chunk_framing,
            audio_enabled,
            consent_mode,
            host_prompt_timeout_secs,
            input_mode,
            tenant_name,
            rc_overlay,
            // FR-101 P2b — the org's policy; applied below with the device's
            // own floor, once the consent mode is resolved.
            session_policy,
            // FR-101 P4b-2 — the idle limit, kept here once the session is live.
            idle_secs,
            // FR-99 P3b — the device's lock ask, taken into the decision at
            // the session's start.
            lock_on_end,
            external,
        } => {
            if !shared_leases.note_optional(session_id, shared_lease.as_ref()) {
                let _ = reply_for_session(
                    ws,
                    delegated,
                    &ClientMsg::Terminate {
                        session_id,
                        reason: EndReason::AdminTerminated,
                        limit: None,
                    },
                )
                .await;
                return Ok(());
            }
            // #1882 — the device's overlay decision, resolved HERE, by the
            // daemon: it is the process whose overlay knows the blocks, and a
            // delegated session's worker gets this same value.
            let rc_overlay = crate::rc_overlay::RcOverlay::resolve(rc_overlay);
            // FR-52 P4 — a controller from OUTSIDE the organization. Admitted
            // by THIS device or not at all: bound to a login it verified, under
            // its own ceiling and its own consent mode, never the server's. A
            // refusal ends the session as the device's own act (`AgentHangup`)
            // — reported as "a human refused you", it would be a lie.
            let (permissions, external_consent) = match &external {
                None => (permissions, None),
                Some(grant) => match crate::extauth::admit_session(
                    ctx.is_primary,
                    remote_cfg,
                    grant,
                    controller_user_id,
                    session_id,
                    permissions,
                )
                .await
                {
                    Ok(admitted) => (admitted.permissions, Some(admitted.consent)),
                    Err(why) => {
                        info!(%session_id, %controller_user_id, why, "external session refused by this device");
                        let _ = outbound_tx.try_send(ClientMsg::Terminate {
                            session_id,
                            reason: EndReason::AgentHangup,
                            limit: None,
                        });
                        return Ok(());
                    }
                },
            };
            // FR-100 P1b — an in-org session's controller, for the device's
            // signature over the answer. Noted here, in the daemon, because a
            // request is never delegated: whichever process builds the
            // answer, the daemon signs it. An outsider's session is bound by
            // FR-52's MAC instead, and is not noted.
            if external_consent.is_none() {
                remote_cfg
                    .peer_auth_offers()
                    .note_request(session_id, controller_user_id);
            }
            // Multi-org — WHICH organization is asking. The server's display
            // name when it sent one; otherwise this loop's own org label,
            // which at least distinguishes secondaries.
            //
            // Shown ONLY on a daemon that actually serves more than one
            // enrollment. The line exists to disambiguate, and on a
            // single-org device there is nothing to disambiguate — every
            // request necessarily comes from the one org, so an "On behalf
            // of …" row would be pure chrome on the majority of installs.
            // A secondary loop is multi-org by definition; the primary
            // checks whether any `[[orgs]]` entry rides alongside it (its
            // config keeps them — only the SYNTHESIZED per-org config has
            // `orgs` cleared).
            //
            // FR-52 P4 — an external controller is ALWAYS labelled, single-org
            // device or not: "which org" has an answer everywhere, and it is
            // "none of yours".
            let multi_org = !ctx.is_primary || !agent_cfg.orgs.is_empty();
            let asking_org: Option<String> = if external_consent.is_some() {
                Some(crate::extauth::OUTSIDE_THE_ORG.to_string())
            } else {
                multi_org
                    .then(|| {
                        tenant_name
                            .clone()
                            .or_else(|| (!ctx.is_primary).then(|| ctx.label.clone()))
                    })
                    .flatten()
            };
            // Pick the best codec for this session from the
            // intersection of (browser-advertised, agent-supported).
            // Stashed per session_id so the rc:sdp.offer handler can
            // read it back when building the peer: that's where the
            // track codec + encoder backend are actually bound.
            let our_caps = crate::encode::caps::detect();
            let chosen = crate::encode::caps::pick_best_codec(&browser_caps, &our_caps.codecs);
            pending_codecs.insert(session_id, chosen.clone());

            // Phase Y.3: figure out which video transport this
            // session will use. Honour `preferred_transport` only if
            // the agent's own AgentCaps.transports advertises it
            // (browser × agent intersection). Otherwise fall back to
            // the WebRTC video track silently — older agents had no
            // transports field at all.
            let negotiated_transport = preferred_transport.as_deref().and_then(|t| {
                if our_caps.transports.iter().any(|s| s == t) {
                    Some(t.to_string())
                } else {
                    None
                }
            });
            // Stash for the upcoming SdpOffer handler — that's where
            // AgentPeer::new is called and the media pump is built.
            // Without this stash the negotiation result was logged but
            // not actually applied (the bug Y.3's media-pump branch
            // surfaces).
            pending_transports.insert(session_id, negotiated_transport.clone());
            // rc.62 — stash per-session chroma override so the
            // SdpOffer handler can pass it into `AgentPeer::new` and
            // ultimately into the VP9-444 media pump. Only meaningful
            // when negotiated_transport == data-channel-vp9-444;
            // ignored otherwise.
            pending_chroma.insert(session_id, chroma_pref.clone());
            pending_chunk_framing.insert(session_id, chunk_framing.unwrap_or(false));
            // Opt-in system audio. Only honour the controller's request
            // when the agent actually advertises an audio codec
            // (`AgentCaps.audio` non-empty ⇒ the `audio` feature is
            // compiled in and cpal/opus are available). Otherwise store
            // `false` so the SdpOffer handler never tries to add a track
            // this build can't feed — matches the transport intersection
            // above.
            //
            // FR-52 P4 — and an EXTERNAL session hears the machine only when
            // its grant carries AUDIO. A ceiling the org or this device set has
            // to bound everything that leaves the host, and system audio does;
            // an ordinary session keeps the historical opt-in unchanged.
            let audio_negotiated = audio_enabled
                && !our_caps.audio.is_empty()
                && (external_consent.is_none()
                    || permissions
                        .contains(roomler_ai_remote_control::permissions::Permissions::AUDIO));
            pending_audio.insert(session_id, audio_negotiated);
            // Clipboard-v2 hardening — stash the session's permission
            // bitfield so the SdpOffer handler can hand it to the
            // AgentPeer's DC handlers for enforcement.
            pending_permissions.insert(session_id, permissions);
            // P6 — controller name (participants rail / ghost labels) +
            // the device policy's input arbitration mode.
            pending_session_meta.insert(
                session_id,
                (
                    controller_name.clone(),
                    input_mode,
                    asking_org.clone(),
                    None,
                    rc_overlay.clone(),
                    // FR-101 P4b-2 — `None` from an older server: no limit.
                    idle_secs,
                    // FR-99 P3b — `None` from an older server: no ask.
                    lock_on_end,
                ),
            );
            info!(
                %session_id, %controller_user_id, %controller_name,
                ?permissions, consent_timeout_secs,
                browser_caps = ?browser_caps,
                chosen_codec = %chosen,
                requested_transport = ?preferred_transport,
                negotiated_transport = ?negotiated_transport,
                chroma_pref = ?chroma_pref,
                audio_requested = audio_enabled,
                audio_negotiated,
                consent_mode = ?consent_broker.mode(),
                org = ?asking_org,
                rc_overlay = rc_overlay.allow,
                "incoming session request — running consent broker"
            );
            // FR-27 follow-up (field, 2026-08-30) — the "Being viewed by …"
            // banner + LocalAPI session registry publish are NO LONGER raised
            // here, at request time. They used to go up alongside the consent
            // prompt as defence-in-depth, but "Being viewed by X" is FALSE
            // while consent is still pending — nobody is viewing yet — and next
            // to a "Remote control request" it reads as a contradiction. The
            // `show_session_full` call now fires at PEER-BUILD (`rc:sdp.offer`
            // handler, below), so the banner + registry entry appear only once
            // the session is actually established and pixels flow. That covers
            // every mode uniformly: auto-grant reaches peer-build within ~1 ms
            // (the banner still appears at once, its only defence-in-depth
            // case), while prompt / email / push reach it only after approval.
            // `asking_org` is stashed in `pending_session_meta` for that call.
            // Spawn a task to run the broker decision in the
            // background; auto-grant resolves <1ms, prompt mode can
            // take up to 30s — we MUST NOT block the WS read loop.
            // Decision flows back via outbound_tx as a ClientMsg::Consent.
            // Phase 2 — obey the server's per-session consent directive when
            // present; fall back to the broker's startup mode (local
            // `auto_grant_session`) for an older server that sends none.
            //
            // FR-27 — the ON-HOST window is `host_prompt_timeout_secs`, not
            // `consent_timeout_secs`. They coincide for a plain attended
            // prompt and diverge for `prompt_then_email`, whose session waits
            // minutes for the owner's emailed link while the modal on this
            // screen has no business standing there that long. An older server
            // sends no split, and then the two are the same thing — the
            // pre-FR-27 behaviour, byte for byte.
            let host_window = std::time::Duration::from_secs(
                host_prompt_timeout_secs.unwrap_or(consent_timeout_secs) as u64,
            );
            let directed_mode: Option<crate::consent::Mode> = match external_consent {
                // FR-52 P4 — for an EXTERNAL session the server's directive is
                // not consulted at all: gate 5 is this device's, and
                // `external_consent_mode` is its answer. The local floor below
                // still applies — a device that asks about everyone asks about
                // strangers too.
                Some(crate::extauth::ExternalConsent::Auto) => {
                    Some(crate::consent::Mode::AutoGrant)
                }
                Some(crate::extauth::ExternalConsent::Prompt) => {
                    Some(crate::consent::Mode::Prompt {
                        timeout: host_window,
                    })
                }
                None => consent_mode.map(|m| match m {
                    roomler_ai_remote_control::models::ConsentMode::Auto => {
                        crate::consent::Mode::AutoGrant
                    }
                    // Prompt + the async owner-side channels (Email / Push /
                    // PromptThenEmail) all resolve to an on-host prompt at the
                    // agent: the server drives the owner channels itself
                    // (Phase 4) and asks the agent to prompt as the on-console
                    // path/fallback.
                    _ => crate::consent::Mode::Prompt {
                        timeout: host_window,
                    },
                }),
            };
            // FR-27 — resolve directive AGAINST the local setting, taking the
            // stricter. This used to be `directed_mode.unwrap_or(local)`, i.e.
            // the directive simply won — so a device that had set
            // `auto_grant_session = false` was silently overridden by a server
            // `Auto`, inverting the gate-4 property exec and SSH are built on.
            let effective_mode =
                crate::consent::strictest_of(directed_mode, consent_broker.mode(), host_window);
            // FR-101 P2b — the session policy, the org's (on the request) and
            // the device owner's floor, applied to the grant BEFORE anything
            // below reads it: the stash the channels enforce, the worker's
            // params, the prompt. The stricter wins, and `ask` survives only a
            // prompt the person here answers, which then names it. The hub has
            // stripped what the org refuses already; this is the half that
            // holds when it did not.
            let masked = crate::session_policy::mask(
                permissions,
                audio_enabled,
                session_policy,
                crate::session_policy::device_policy(),
                crate::session_policy::person_asked(
                    consent_mode,
                    matches!(effective_mode, crate::consent::Mode::Prompt { .. }),
                ),
            );
            if !masked.refused.is_empty() || !masked.ask.is_empty() {
                info!(
                    %session_id,
                    refused = ?masked.refused,
                    ask = ?masked.ask,
                    "session policy applied to the grant"
                );
            }
            let permissions = masked.permissions;
            let audio_negotiated = masked.audio_enabled && audio_negotiated;
            pending_permissions.insert(session_id, permissions);
            pending_audio.insert(session_id, audio_negotiated);
            let features_line =
                crate::session_policy::consent_line(&masked.ask).unwrap_or_default();
            // FR-85 P3b — a recording's prompt follows the session's own: a
            // session consented ON THE HOST asks the host again (same window)
            // before it may record; an auto-granted one does not ask, its
            // owner having opted into remote recording on the device.
            let record_prompt_window = match effective_mode {
                crate::consent::Mode::AutoGrant => None,
                crate::consent::Mode::Prompt { timeout } => Some(timeout),
            };
            if let Some(meta) = pending_session_meta.get_mut(&session_id) {
                meta.3 = Some(RecordMeta {
                    controller_user_id,
                    prompt_window: record_prompt_window,
                });
            }
            // FR-43 P2b-3 — hand the SAME resolved values to the GUI worker, if
            // one is attached. `Request` is not delegated (consent and the
            // upstream reply belong to the daemon, which is the enrolled
            // identity), but everything it resolves here is consumed by the
            // `SdpOffer` handler — which IS delegated. Without this the worker
            // defaults all seven, and the one that matters silently is
            // `transport`: `None` means the legacy RTP track, so a browser that
            // negotiated `data-channel-h264` gets a black screen while the
            // agent happily encodes into a pipe nobody reads.
            //
            // FR-85 P1e-mac — sent HERE, after the consent mode is resolved, so
            // the record context travels with the rest: a supervised Mac's
            // worker is the half that records, and without it every delegated
            // session's `record` channel refused `unavailable`. Still ahead of
            // the offer that consumes it (the server sends that only after this
            // request is answered), on the same ordered channel.
            if let Some(delegate) = delegate
                && ctx.is_primary
            {
                let sent = delegate.send_params(crate::delegate::DelegateFrame::SessionParams(
                    Box::new(crate::delegate::SessionParams {
                        session_id: session_id.to_hex(),
                        shared_lease: shared_lease.clone(),
                        codec: chosen.clone(),
                        transport: negotiated_transport.clone(),
                        chroma: chroma_pref.clone(),
                        chunk_framing: chunk_framing.unwrap_or(false),
                        audio: audio_negotiated,
                        permissions,
                        controller_name: controller_name.clone(),
                        input_mode,
                        asking_org: asking_org.clone(),
                        record: Some(crate::delegate::DelegatedRecord {
                            controller_user_id: controller_user_id.to_hex(),
                            prompt_window_ms: record_prompt_window
                                .map(|w| u64::try_from(w.as_millis()).unwrap_or(u64::MAX)),
                        }),
                        rc_overlay: Some(rc_overlay.clone()),
                        // FR-101 P4b-2 — the worker keeps the idle limit.
                        idle_secs,
                        // FR-99 P3b — and takes the lock ask into the lock:
                        // the session goes live in its process.
                        lock_on_end,
                    }),
                ));
                if !sent {
                    // No worker, or its queue is full. Not fatal — the daemon
                    // still serves the session itself, which on macOS means a
                    // blank screen but a working, terminable session.
                    tracing::debug!(%session_id, "no worker to hand session params to");
                }
            }
            let session_hex = session_id.to_hex();
            // Phase 4 — Email/Push are OWNER-side modes: the SERVER obtains
            // consent from the device owner (email link / push), so the agent
            // must NOT decide — no prompt, no `.pending`, no `rc:consent`. It
            // just waits; when the owner approves, the server sends `rc:ready`,
            // the controller offers, and the agent builds the peer from the
            // media context stashed above.
            //
            // ⚠️ FR-52 P4 — never for an external session, whatever the server
            // says: the device decides that one itself, and an offer it did
            // not consent to is refused at `check_offer`.
            let owner_side_consent = external_consent.is_none()
                && matches!(
                    consent_mode,
                    Some(roomler_ai_remote_control::models::ConsentMode::Email)
                        | Some(roomler_ai_remote_control::models::ConsentMode::Push)
                );
            // Phase 3 — when this session will PROMPT on the host, drop a
            // `.pending` marker so the tray can pop a rich Approve/Deny modal
            // (the agent→tray signal). Auto grants + owner-side modes write
            // nothing. The broker's poll loop removes it when the decision
            // resolves. Best-effort; a failure falls back to the CLI path.
            //
            // FR-27 — whether the marker landed is REMEMBERED. It is the only
            // prompt surface this daemon has besides the CLI, so a failure to
            // write it means no human can ever be asked, and that has to reach
            // the controller as "nobody could be asked" rather than as a deny.
            let will_prompt = !owner_side_consent
                && matches!(effective_mode, crate::consent::Mode::Prompt { .. });
            let mut have_surface = true;
            if will_prompt {
                // FR-27 — NATIVE surface first, companion as the fallback.
                //
                // The native panel is drawn by the daemon itself, so it needs
                // no second process running, no login-session plumbing and no
                // IPC. It exists on Windows (capture-excluded), on X11, and on
                // macOS; it does NOT exist on a headless host, under GNOME/KDE
                // Wayland (neither exposes `wlr-layer-shell` to arbitrary
                // clients), or in a build without the per-OS feature — and
                // `show_prompt` says which by returning false.
                //
                // FR-52 P4 — an external request says so in its TITLE, not
                // only in the org line: the controller's name is whatever
                // they chose to call themselves, and the one fact the person
                // at the machine must not miss is that they are not a
                // colleague.
                let (prompt_title, prompt_detail) = if external_consent.is_some() {
                    (
                        crate::extauth::EXTERNAL_PROMPT_TITLE,
                        crate::extauth::EXTERNAL_PROMPT_DETAIL,
                    )
                } else {
                    ("Remote control request", "")
                };
                // FR-99 — a grant that may cover the screen says so, on every
                // surface, in the line the person reads before deciding; and
                // only when this device would act on it.
                let privacy_line = crate::privacy::consent_line(
                    permissions,
                    crate::privacy::device_allowed(),
                    crate::privacy::curtain_possible(),
                )
                .unwrap_or_default()
                .to_string();
                // FR-101 P2b — and the features the person is asked about, by
                // name: approving the session is what grants them. One line
                // each; the native panel's detail box holds two.
                //
                // FR-52 P4 — an outsider's line comes LAST: the title already
                // says they are from outside the organization, while the lines
                // above it name what approving grants, which a two-line box
                // must not be the one to cut.
                let privacy_line = [privacy_line.as_str(), features_line.as_str(), prompt_detail]
                    .into_iter()
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                let view = crate::indicator::PromptView {
                    session_hex: session_hex.clone(),
                    title: prompt_title.into(),
                    lead: format!("{controller_name} is requesting to control this device."),
                    detail: privacy_line.clone(),
                    permissions: permissions.wire_names(),
                    org: asking_org.clone().unwrap_or_default(),
                    expires_at: std::time::Instant::now() + host_window,
                };
                let native = indicator.show_prompt(view.clone());
                let mut prompt = crate::consent::PendingPrompt {
                    kind: crate::consent::PromptKind::RemoteControl,
                    asked_by: &controller_name,
                    permissions: permissions.wire_names(),
                    detail: privacy_line,
                    // The marker is written EITHER WAY — it is the
                    // machine-readable record that a decision is outstanding,
                    // and `roomlerd consent --list` must show a
                    // natively-prompted session too. This field is what stops
                    // the companion from ALSO popping a panel and asking the
                    // same question twice.
                    surface: if native {
                        crate::consent::PromptSurface::Native
                    } else {
                        crate::consent::PromptSurface::Companion
                    },
                    // Multi-org — the desktop modal renders this so the
                    // operator can tell WHICH organization is asking. On a
                    // device enrolled in two orgs, "Alice wants to control
                    // this machine" is not enough to decide on. Absent for a
                    // single-org device (nothing useful to add).
                    org: asking_org.clone().unwrap_or_default(),
                    timeout: host_window,
                };

                let mut marker = true;
                if let Err(e) = consent_broker.write_prompt(&session_hex, &prompt) {
                    // Only fatal to the SURFACE when the companion was the
                    // plan: with a native panel already up, a human can still
                    // answer — the marker's loss costs the CLI listing, not
                    // the prompt.
                    if !native {
                        have_surface = false;
                    }
                    marker = false;
                    tracing::warn!(session = %session_hex, %e, native, "could not write the .pending consent marker");
                }

                let mut notified = false;
                if !native {
                    // FR-27 — the marker only helps if something is READING it.
                    // Nothing used to start the companion, so a device set to
                    // "Prompt on host" whose operator had quit the menu-bar app
                    // showed nothing, waited out its window, and reported a deny.
                    //
                    // AWAITED, not spawned: its verdict is what separates
                    // "nobody answered" from "there is nobody to ask, and there
                    // never was" — two outcomes with different fixes, and the
                    // caller cannot tell them apart afterwards. Bounded so a
                    // wedged `launchctl` / `systemd-run` cannot eat the prompt
                    // window; a timeout means we could not confirm a surface,
                    // which is the same answer as not having one.
                    let companion_up = tokio::time::timeout(
                        COMPANION_START_BUDGET,
                        crate::companion::ensure_running(),
                    )
                    .await
                    .unwrap_or(false);
                    if !companion_up {
                        have_surface = false;
                    }
                    // FR-93 P6f — the last on-screen surface: a desktop
                    // notification with Approve and Deny, where the companion
                    // cannot show the question (none installed: a system
                    // daemon on Fedora, openSUSE, Arch, aarch64; or no marker
                    // for it to read).
                    if !(companion_up && marker) {
                        notified = indicator.show_notification_prompt(view).await;
                    }
                    if notified {
                        have_surface = true;
                        if marker {
                            prompt.surface = crate::consent::PromptSurface::Notification;
                            if let Err(e) = consent_broker.write_prompt(&session_hex, &prompt) {
                                tracing::warn!(session = %session_hex, %e, "could not mark the consent prompt as shown by a notification");
                            }
                        }
                    }
                }
                info!(
                    session = %session_hex, native, notified, have_surface,
                    "consent prompt surface"
                );
                // FR-34 — a LOCKED host has the panel on the (currently
                // invisible) secure desktop, so the operator must UNLOCK the
                // machine before they can see and approve it. That is the
                // sound flow (unlock proves presence, then approve; 5-minute
                // window since P4) — but the controller has no way to know it
                // is locked, so its "awaiting consent" wait looks like a hang.
                // Tell it. Advisory + best-effort; `probe_lock_state()` is
                // Unlocked on every non-Windows host, so this only fires where
                // a lock screen exists.
                // FR-34 P3b — detect the lock from the SERVICE context.
                // This consent code runs on the SCM service window
                // station (the daemon only switches to WinSta0
                // per-session, when input is wired, AFTER consent), so
                // the `OpenInputDesktop`-based `probe_lock_state()` reads
                // the service station's own `Default` and ALWAYS reports
                // Unlocked here — the emit could never fire on a
                // perMachine/SYSTEM host (field-confirmed on CORPLAP-1,
                // 0.4.22). `probe_lock_state_service()` asks WTS about the
                // console session directly, from any station; fall back to
                // the desktop probe (correct for a perUser/attended daemon
                // already on WinSta0) when WTS is unavailable / UNKNOWN.
                let host_locked = crate::lock_state::probe_lock_state_service()
                    .unwrap_or_else(crate::lock_state::probe_lock_state)
                    == crate::lock_state::LockState::Locked;
                if host_locked {
                    info!(
                        session = %session_hex,
                        "consent prompt on a LOCKED host — signalling the controller to unlock + approve"
                    );
                    let _ = outbound_tx.try_send(ClientMsg::ConsentPending {
                        session_id,
                        host_locked: true,
                    });
                }
            }
            if owner_side_consent {
                info!(
                    %session_id, ?consent_mode,
                    "owner-side consent (email/push) — agent waits for the server to resolve"
                );
            } else {
                let outbound = outbound_tx.clone();
                let ind = indicator.clone();
                // #1632 — armed HERE, on the WS loop, not inside the task:
                // `request_with_mode` registers the session as pending
                // synchronously, so a `Terminate` that is the very next frame
                // this loop reads finds the prompt whether or not the task
                // below has been polled yet. (A spawned task has no ordering
                // guarantee against the loop that spawned it.)
                let prompt = consent_broker.request_with_mode(&session_hex, effective_mode);
                // FR-52 P4 — only an external session carries the config in.
                let external_cfg = external_consent.map(|_| remote_cfg.clone());
                tokio::spawn(async move {
                    let decision =
                        await_prompt_or_socket_end(prompt, &outbound, &session_hex).await;
                    // FR-27 — take the native panel down however the question
                    // was answered: the click here, the CLI, the companion,
                    // the window simply expiring, or the session ending first.
                    // This is the ONE place every one of those paths
                    // converges, so it is the only place that cannot miss one
                    // — a panel still on screen for a resolved session is its
                    // own bug, and a stale Approve button is a dangerous one.
                    ind.hide_prompt(&session_hex);
                    let Some(mut reply) = consent_reply(decision, have_surface) else {
                        // #1632 — the session was terminated while the
                        // question stood. The server forgot it when it sent
                        // the Terminate; there is nobody to answer to. (An
                        // external binding ended with that Terminate, ahead
                        // of the delegation gate.)
                        tracing::info!(
                            session = %session_hex,
                            ?decision,
                            ?effective_mode,
                            "consent prompt withdrawn — the session ended before an answer; no rc:consent sent"
                        );
                        return;
                    };
                    // FR-52 P4 — an external grant is recorded BEFORE it leaves:
                    // the offer it unlocks must never overtake it to
                    // `check_offer`. A binding that ended while the question
                    // stood cannot be granted any more; anything but a grant
                    // ends the binding here.
                    if let Some(cfg) = &external_cfg {
                        if reply.granted {
                            reply.granted = crate::extauth::grant_consent(cfg, session_id);
                        } else {
                            crate::extauth::end_session(cfg, session_id);
                        }
                    }
                    tracing::info!(
                        session = %session_hex,
                        ?decision,
                        ?effective_mode,
                        granted = reply.granted,
                        reason = reply.reason.map(|r| r.wire()),
                        "consent decision → sending rc:consent"
                    );
                    if let Err(e) = outbound
                        .send(ClientMsg::Consent {
                            session_id,
                            granted: reply.granted,
                            reason: reply.reason.map(|r| r.wire().to_string()),
                        })
                        .await
                    {
                        tracing::warn!(session = %session_hex, %e, "outbound consent send failed (channel closed)");
                    }
                });
            }
        }

        ServerMsg::SdpOffer {
            shared_lease,
            session_id,
            sdp,
            ice_servers,
            // FR-52 P4 — already judged, ahead of the delegation branch.
            extauth_mac: _,
            // FR-100 P1b — already noted there too, for the answer's signature.
            peer_auth: _,
        } => {
            info!(%session_id, sdp_len = sdp.len(), "rc:sdp.offer — creating peer");

            // Build a fresh peer for this session. If an old one somehow
            // exists (controller retry?), close it first so the browser sees
            // a clean answer.
            if let Some(old) = peers.remove(&session_id) {
                // FR-101 P3 — the session goes on under a new peer, and the
                // old one's drop forgets its counters: carry the transfer
                // readings across, so the cumulative tallies never go back.
                let carried = crate::session_telemetry::counters(session_id).take_transfers();
                close_within_budget(old.close(), session_id, "replaced_by_offer").await;
                drop(old);
                crate::session_telemetry::counters(session_id).carry_transfers(carried);
            }

            // Read back the codec picked by `rc:session.request`. If
            // the session skipped request (some test harnesses do) or
            // the message order is broken, default to "h264" so the
            // peer still works — that's the universal fallback the
            // browser understands.
            let chosen_codec = pending_codecs
                .remove(&session_id)
                .unwrap_or_else(|| "h264".to_string());
            // Y.3: pull the transport stashed in the request handler.
            // `None` (legacy WebRTC track) is the silent default for
            // older controllers / sessions that arrived without
            // preferred_transport.
            let negotiated_transport = pending_transports.remove(&session_id).unwrap_or(None);
            // #2231 — the RTP video track's codec, read from this offer: on a
            // DataChannel transport it moves to VP8 when the browser cannot
            // take the pump's codec, so the answer does not fail on a track
            // that will never carry a frame.
            let track_codec =
                crate::peer::rtp_track_codec(&chosen_codec, negotiated_transport.as_deref(), &sdp);
            // rc.62 — pull the per-session chroma override stashed by
            // the Request handler. `None` → AgentPeer falls back to
            // `ROOMLERD_VP9_CHROMA` env-var default.
            let chroma_pref = pending_chroma.remove(&session_id).unwrap_or(None);
            // FR-17 — absent (older controller, or a test harness that skipped
            // rc:request) means the legacy unframed format, which is the only
            // safe default: framing bytes a peer cannot parse is unrecoverable.
            let chunk_framing = pending_chunk_framing.remove(&session_id).unwrap_or(false);
            // Pull the opt-in audio flag stashed by the Request handler.
            // Missing (session skipped rc:request in a test harness) →
            // no audio track, the safe default.
            let audio_enabled = pending_audio.remove(&session_id).unwrap_or(false);
            // Pull the session permissions stashed by the Request
            // handler. Missing (harness skipped rc:request) → the
            // Permissions default (VIEW | INPUT | CLIPBOARD) so those
            // flows behave exactly as pre-v2.
            let permissions = pending_permissions.remove(&session_id).unwrap_or_default();
            // P6 — controller name + policy input mode for the arbiter
            // registration. Missing (harness skipped rc:request) → an
            // anonymous label + the agent-default (free) mode.
            // #1882 — and the overlay decision; missing means off, with this
            // process's own overlay blocks.
            // FR-101 P4b-2 — and the idle limit; missing means none.
            // FR-99 P3b — and the lock ask; missing means none.
            #[cfg_attr(not(feature = "recording"), allow(unused_variables))]
            let (
                controller_name,
                input_mode,
                asking_org,
                record_meta,
                rc_overlay,
                idle_secs,
                lock_ask,
            ) = pending_session_meta.remove(&session_id).unwrap_or_else(|| {
                (
                    "Controller".to_string(),
                    None,
                    None,
                    None,
                    crate::rc_overlay::RcOverlay::resolve(false),
                    None,
                    None,
                )
            });
            // FR-27 follow-up — capture what the "Being viewed by" banner needs
            // BEFORE `controller_name` is moved into `AgentPeer::new` below.
            // The banner is raised once the peer is established (after
            // `handle_offer`), not at request time. `permissions` is Copy.
            let banner_name = controller_name.clone();
            let banner_org = asking_org.unwrap_or_default();

            // #2251 — on the RTP transport the track IS the picture, so an
            // offer that carries none of its codec cannot be answered: that
            // `create_answer` failed below, the session ended as a bare
            // `Error`, and the viewer asked again into the same failure.
            // Refuse before building the peer, naming the cause the viewer
            // reads as final. Every stash above is already taken.
            if crate::peer::rtp_track_unanswerable(
                &track_codec,
                negotiated_transport.as_deref(),
                &sdp,
            ) {
                warn!(
                    %session_id,
                    codec = %track_codec,
                    offered = ?crate::peer::offered_video_codecs(&sdp),
                    "rc:sdp.offer — the browser offers no codec the RTP track can send; refusing"
                );
                let _ = reply_for_session(
                    ws,
                    delegated,
                    &ClientMsg::Terminate {
                        session_id,
                        reason: EndReason::Error,
                        limit: Some(LIMIT_NO_COMMON_CODEC.to_string()),
                    },
                )
                .await;
                return Ok(());
            }

            let peer = match AgentPeer::new(
                session_id,
                &ice_servers,
                // FR-43 P2b-2 — THE seam. Everything this peer later emits
                // (ICE, `SessionStats`, its own `Terminate`) leaves through
                // the sender it is constructed with, so a delegated session
                // needs exactly one decision, taken once, here. Nothing
                // downstream has to know it is delegated.
                delegated.unwrap_or(outbound_tx).clone(),
                encoder_preference,
                chosen_codec,
                track_codec,
                negotiated_transport,
                chroma_pref,
                chunk_framing,
                audio_enabled,
                permissions,
                controller_name,
                input_mode.map(|m| {
                    match m {
                        roomler_ai_remote_control::models::InputMode::Free => "free",
                        roomler_ai_remote_control::models::InputMode::Exclusive => "exclusive",
                    }
                    .to_string()
                }),
                rc_overlay,
                // FR-93 P6c — where the media pump ends this session when the
                // person at the screen stops the share with the desktop's own
                // control: the same kill path as their Disconnect.
                indicator.sessions().clone(),
                // FR-102 P9d — so this peer's carrier observation signals the
                // loop that holds it (the clone drops with the peer).
                carrier_ready_tx.clone(),
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!(%session_id, %e, "AgentPeer::new failed; terminating");
                    let _ = reply_for_session(
                        ws,
                        delegated,
                        &ClientMsg::Terminate {
                            session_id,
                            reason: EndReason::Error,
                            limit: None,
                        },
                    )
                    .await;
                    return Ok(());
                }
            };

            if !shared_leases.attach(session_id, shared_lease.as_ref(), peer.shared_lease_stop()) {
                close_within_budget(peer.close(), session_id, "shared_lease_expired").await;
                return Ok(());
            }
            // FR-85 P3b — the `record` channel's context, BEFORE the answer:
            // a channel cannot open until the offer is answered, so it can
            // never see this unset. P1e-mac: on a supervised Mac's worker, a
            // delegated session's context came from the daemon
            // (`SessionParams.record`), and the consent broker, indicator and
            // companion are THIS process's — the person's own, in their GUI
            // session. Only a daemon older than P1e-mac sends none, and the
            // channel then refuses `unavailable`.
            #[cfg(feature = "recording")]
            if let Some(meta) = record_meta {
                peer.set_record_ctx(crate::recording::remote::SessionCtx {
                    session_id,
                    controller_user_id: meta.controller_user_id,
                    controller_name: banner_name.clone(),
                    org: banner_org.clone(),
                    prompt_window: meta.prompt_window,
                    consent: consent_broker.clone(),
                    indicator: indicator.clone(),
                    outbound: delegated.unwrap_or(outbound_tx).clone(),
                    companion: crate::recording::remote::Companion::System,
                });
            }

            // FR-99 P1b — the `privacy` channel's context, BEFORE the answer
            // for the same reason. The curtain is THIS process's overlay: the
            // one in the console session, whose screen it covers.
            peer.set_privacy_ctx(crate::privacy::PrivacyCtx {
                session_id,
                controller_name: banner_name.clone(),
                host: std::sync::Arc::new(indicator.clone()),
                possible: crate::privacy::curtain_possible,
                // P1d — reported on THIS connection: the session belongs to
                // the org that asked, and the server looks it up there.
                report: crate::privacy::Reporter {
                    outbound: delegated.unwrap_or(outbound_tx).clone(),
                    tenant_id: tenant_id.to_string(),
                    ledger: crate::privacy::ledger(),
                },
                // P4 — the host's speakers, muted while the curtain is up.
                mute: crate::host_mute::host_mute(),
            });

            let answer_sdp = match peer.handle_offer(sdp).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%session_id, chain = ?e, "handle_offer failed; terminating");
                    close_within_budget(peer.close(), session_id, "offer_failed").await;
                    let _ = reply_for_session(
                        ws,
                        delegated,
                        &ClientMsg::Terminate {
                            session_id,
                            reason: EndReason::Error,
                            limit: None,
                        },
                    )
                    .await;
                    return Ok(());
                }
            };

            // FR-52 P4 — an external session's answer carries a MAC over THIS
            // device's DTLS certificate, which the browser checks before it
            // trusts the transport: whoever relays the signalling cannot stand
            // in for the device. Sealed before the banner goes up, because an
            // answer that cannot be sealed ends the session instead. (A GUI
            // worker holds no binding, so its answers go up unsealed and the
            // root daemon seals them on the way out — `seal_outbound`.)
            let extauth_mac = match crate::extauth::seal_answer(remote_cfg, session_id, &answer_sdp)
            {
                crate::extauth::Seal::Ordinary => None,
                crate::extauth::Seal::Sealed(mac) => Some(mac),
                crate::extauth::Seal::Refused(why) => {
                    warn!(%session_id, why, "external session: answer withheld; ending the session");
                    let _ = tokio::time::timeout(PEER_CLOSE_BUDGET, peer.close()).await;
                    crate::extauth::end_session(remote_cfg, session_id);
                    let _ = reply_for_session(
                        ws,
                        delegated,
                        &ClientMsg::Terminate {
                            session_id,
                            reason: EndReason::AgentHangup,
                            limit: None,
                        },
                    )
                    .await;
                    return Ok(());
                }
            };
            // FR-100 P1b — and an in-org session's answer is signed with this
            // enrollment's device key when its offer asked (a nonce). Unsigned
            // otherwise: nothing to sign against, or no key kept. A GUI worker
            // finds nothing noted here and holds no key, so its answer goes up
            // unsigned and the daemon signs it on the way out
            // (`peer_auth::sign_outbound`).
            let peer_auth = crate::peer_auth::sign_answer(
                remote_cfg.peer_auth_offers(),
                remote_cfg.config_path(),
                tenant_id,
                &agent_cfg.agent_id,
                session_id,
                &answer_sdp,
            );
            // FR-100 P1c — and what the device concluded about the browser
            // that offered it, for the hub to record: an outsider's session
            // (sealed above) by FR-52's MAC, an in-org one by its offer.
            let peer_auth_verdict = crate::peer_auth::answer_verdict(
                remote_cfg.peer_auth_offers(),
                remote_cfg.peer_auth_policy(),
                session_id,
                extauth_mac.is_some(),
            );

            // FR-27 follow-up — the session is now established (peer built,
            // answer ready): raise the "Being viewed by …" banner and publish
            // to the LocalAPI session registry. Deferred to here from request
            // time so it never shows while consent is still pending — "Being
            // viewed by X" is only true once pixels actually flow. Harmless
            // no-op on non-Windows / when the indicator feature is disabled.
            // FR-99 P3b — the device's lock ask first: `show_session_full`
            // takes the lock decision, and the ask is part of it.
            crate::lock_on_end::set_session_ask(session_id, lock_ask);
            indicator.show_session_full(
                session_id,
                banner_name,
                permissions.wire_names(),
                banner_org,
            );

            if let Err(e) = reply_for_session(
                ws,
                delegated,
                &ClientMsg::SdpAnswer {
                    session_id,
                    sdp: answer_sdp,
                    extauth_mac,
                    peer_auth,
                    peer_auth_verdict,
                },
            )
            .await
            {
                // The answer never left, so nobody will connect to this peer,
                // and it is in no map `close_all_peers` walks: close it here
                // (dropping a WebRTC peer frees none of its sockets) and take
                // down the banner just raised for it (found in review).
                // FR-99 P3: a session that never went live has no say in
                // locking the screen.
                crate::lock_on_end::session_aborted(session_id);
                indicator.hide_session(session_id.to_hex());
                close_within_budget(peer.close(), session_id, "answer_send_failed").await;
                return Err(ConnectError::Transient(e.context("sending answer")));
            }
            // FR-101 P4b-2 — the session is live: its idle limit runs from
            // here, not from the request (consent can take minutes). The
            // watcher stops with the peer; at the limit it hands the session
            // to this loop's `idle_rx`, which ends it as the host's
            // Disconnect does. A re-offer for the session builds a new peer
            // and arms a new watcher; the old one stopped with the old peer.
            if let Some(secs) = idle_secs.filter(|s| *s > 0) {
                let (session_end, control) = peer.idle_handles();
                crate::session_idle::arm(
                    session_id,
                    Duration::from_secs(u64::from(secs)),
                    session_end,
                    control,
                    idle_tx.clone(),
                );
            }
            for candidate in shared_leases.take_ice(session_id) {
                let _ = peer.add_remote_candidate(candidate).await;
            }
            peers.insert(session_id, peer);
            // 2026-07-27 — first live session engages the GPU-clock pin
            // (opt-in, `ROOMLERD_GPU_CLOCK_PIN`; no-op otherwise).
            crate::gpu_clock::on_sessions_changed(peers.len());
            info!(%session_id, "rc:sdp.answer sent; peer is live");
        }

        ServerMsg::Ice {
            session_id,
            candidate,
        } => {
            if let Some(peer) = peers.get(&session_id) {
                if let Err(e) = peer.add_remote_candidate(candidate).await {
                    debug!(%session_id, %e, "add_remote_candidate failed");
                }
            } else {
                debug!(%session_id, "ICE for unknown session; buffering not yet supported");
            }
        }

        // ⚠️ `WARN [] failed to handle_inbound: ErrChunk` immediately BEFORE
        // this line is EXPECTED and benign — it is the teardown, not a fault.
        // The controller hangs up, DTLS goes away, and a final in-flight SCTP
        // packet fails to parse on the way out. Measured on a macOS host
        // 2026-08-24: 14/14 occurrences were followed by this `Terminate`
        // (`reason=ControllerHangup`) within ~25 ms, and NO session ended
        // without one. It is emitted by `webrtc_sctp::association` with an
        // EMPTY name (`[]`), so it carries no `session_id` and reads as
        // unattributable — which is exactly why it invites a wrong story.
        // (It cost one: "sessions die at ~7 s" — they did not; those sessions
        // were disconnected by hand while a healthy one in the same log ran to
        // 8160 frames / 75 MB.)
        //
        // ⚠️ Do NOT "fix" it by filtering `webrtc_sctp::association` — a
        // grep for ErrChunk otherwise lands only on the CHUNKING story
        // (`clipboard.rs` rc.44, `useRemoteControl.ts` rc.23: a single SCTP
        // message ≥ the 65536 `max_message_size` default), and that same warn
        // was the ONLY signal for both of those real bugs, which dropped data
        // silently otherwise. Mid-session it means something; here it does not.
        // Distinguish by what follows: a teardown line, or nothing.
        ServerMsg::Terminate {
            session_id,
            reason,
            limit,
        } => {
            info!(%session_id, ?reason, ?limit, "session terminated by server");
            // A consent prompt still standing for this session was already
            // withdrawn above, ahead of the delegation gate (#1632) — this arm
            // does not run on a delegated session, and the prompt is ours
            // either way.
            //
            // FR-85 P3b-3 — said BEFORE the close: a close that overruns its
            // budget never reaches the `record` channel, which would then
            // stay open and its recording undetached for good. (On a supervised
            // Mac this arm runs in the WORKER for a delegated session, where
            // its recording lives — P1e-mac.)
            #[cfg(feature = "recording")]
            crate::recording::remote::session_ended(session_id);
            if let Some(peer) = peers.remove(&session_id) {
                // FR-101 P3 — the audit's last sample, before the close.
                if let Some(stats) = final_session_stats(session_id, &peer).await
                    && let Err(e) = reply_for_session(ws, delegated, &stats).await
                {
                    debug!(%session_id, %e, "final session stats send failed");
                }
                close_within_budget(peer.close(), session_id, "terminate").await;
            }
            // 2026-07-27 — last session gone → release the GPU-clock pin
            // (Drop resets the locked clocks).
            crate::gpu_clock::on_sessions_changed(peers.len());
            // Drop any orphaned pending-codec / transport entry for
            // this session so the maps don't accumulate under long-
            // running agents (e.g. sessions cancelled before SDP is
            // exchanged).
            pending_codecs.remove(&session_id);
            pending_transports.remove(&session_id);
            pending_audio.remove(&session_id);
            pending_permissions.remove(&session_id);
            pending_session_meta.remove(&session_id);
            // (FR-52 P4 — an external session's binding already ended ahead
            // of the delegation branch, which a delegated Terminate never
            // gets past.)
            indicator.hide_session(session_id.to_hex());
        }

        ServerMsg::Error {
            session_id,
            code,
            message,
            open_nonce: _,
        } => {
            warn!(?session_id, %code, %message, "server-side rc error");
        }

        // rc.53: server has decided this WS is over. Tear down every
        // peer cleanly (so the controller side gets clean ICE-restart
        // hints rather than a 10-30 s silence-detect) and surface the
        // reason via a typed ConnectError so the outer `run()` loop
        // can decide between fatal exit (`AgentDeleted` /
        // `PolicyRejected`) and back-off-with-escalation
        // (`ReplacedByNewerConnection`).
        //
        // The teardown invariant lives HERE — not in `run()` — because
        // the existing `connect_once` exit paths only run cleanup at
        // explicit `return` sites and the `?` propagation of this
        // arm's Err would otherwise SKIP `close_all_peers`. SM-1b
        // (delete-agent-with-active-session) checks this invariant
        // explicitly.
        ServerMsg::Goodbye { reason, message } => {
            // #1750 — a secondary org's `run()` arm reports every goodbye
            // reason itself (one WARN), so here it is DEBUG; the primary is
            // unchanged.
            if ctx.is_primary {
                tracing::error!(
                    ?reason,
                    %message,
                    "server-side rc:goodbye received — stopping current session loop"
                );
            } else {
                tracing::debug!(
                    org = %ctx.label,
                    ?reason,
                    %message,
                    "server-side rc:goodbye received — stopping this org's session loop"
                );
            }
            close_all_peers(peers, indicator).await;
            close_all_tunnel_peers(tunnel_peers).await;
            close_all_tunnel_quic_peers(tunnel_quic_peers).await;
            // Drop pending codec / transport entries too; they're tied
            // to in-flight session_ids that no longer have peers.
            pending_codecs.clear();
            pending_transports.clear();
            pending_chroma.clear();
            pending_chunk_framing.clear();
            pending_audio.clear();
            pending_permissions.clear();
            return match reason {
                AgentCloseReason::AgentDeleted | AgentCloseReason::PolicyRejected => {
                    Err(ConnectError::FatalGoodbye { reason, message })
                }
                AgentCloseReason::ReplacedByNewerConnection => {
                    Err(ConnectError::ReplacedByNewer { message })
                }
            };
        }

        // Controller-oriented messages shouldn't reach us.
        ServerMsg::Ready { session_id, .. }
        | ServerMsg::SessionCreated { session_id, .. }
        | ServerMsg::SdpAnswer { session_id, .. } => {
            debug!(%session_id, "unexpected controller-side msg on agent socket");
        }
        ServerMsg::Pong { .. } => {}

        // Multi-region relay PoPs: stash the pushed region list; probe now
        // when the set actually changed (rev), else let the periodic
        // re-prober use the stored copy.
        ServerMsg::RelayRegions { regions, rev } => {
            // Multi-region DERP: any region carrying a derp_url ⇒ fetch an
            // admission ticket (once; the reply arm schedules refreshes).
            // Only when this build can actually dial regional relays.
            #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
            if regions.iter().any(|r| r.derp_url.is_some())
                && tunnel_core::overlay::direct::derp_enabled()
                && derp_ticket_slot
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_none()
            {
                let _ = outbound_tx.try_send(ClientMsg::DerpTicketRequest {});
            }
            if crate::relay_probe::probing_enabled() {
                let changed = {
                    let mut slot = relay_regions_slot.lock().unwrap_or_else(|e| e.into_inner());
                    let changed = slot.as_ref().map(|(_, r)| *r != rev).unwrap_or(true);
                    *slot = Some((regions.clone(), rev));
                    changed
                };
                if changed {
                    debug!(count = regions.len(), rev, "relay regions pushed; probing");
                    tokio::spawn(crate::relay_probe::probe_and_report(
                        regions,
                        outbound_tx.clone(),
                    ));
                }
            }
        }

        // Multi-region DERP: cache the admission ticket + schedule a refresh
        // at ~90 % of its remaining validity (the refresher dies with the
        // connection — its send fails once the outbound channel closes).
        ServerMsg::DerpTicket { ticket, exp } => {
            *derp_ticket_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((ticket, exp));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let refresh_in =
                std::time::Duration::from_secs(exp.saturating_sub(now).saturating_mul(9) / 10)
                    .max(std::time::Duration::from_secs(60));
            let tx = outbound_tx.clone();
            debug!(
                exp,
                refresh_in_s = refresh_in.as_secs(),
                "derp ticket cached"
            );
            tokio::spawn(async move {
                tokio::time::sleep(refresh_in).await;
                let _ = tx.send(ClientMsg::DerpTicketRequest {}).await;
            });
        }

        // rc:tunnel.tcp.forward — server has gated the request, asks
        // the agent to dial dst + reply with Accept/Reject via the
        // outbound channel. The acceptor handles ACL + dial in an
        // async task so the WS read loop is never blocked. Owner is
        // recorded in the audit log but not consulted here (server
        // is authoritative for policy).
        ServerMsg::TcpForwardForward {
            session_id,
            flow_id,
            dst_host,
            dst_port,
            owner_user_id: _,
        } => {
            if shared_ssh.contains(session_id) {
                let _ = outbound_tx.try_send(ClientMsg::TcpForwardReject {
                    session_id,
                    flow_id,
                    kind: roomler_ai_remote_control::signaling::RejectKind::AclDenied,
                    reason: "A shared SSH peer has no arbitrary TCP destination".into(),
                });
                return Ok(());
            }
            // Dispatch on the session's negotiated data plane: a QUIC
            // session has an entry in `tunnel_quic_peers`, otherwise
            // it's a WebRTC-DC session in `tunnel_peers`. The server
            // negotiates exactly one transport per session, so at most
            // one map matches; QUIC is checked first.
            if let Some(quic_peer) = tunnel_quic_peers.get(&session_id).cloned() {
                let outbound = outbound_tx.clone();
                let acl = forward_acl.clone();
                tokio::spawn(async move {
                    crate::tunnel::acceptor::handle_forward_request_quic(
                        session_id,
                        flow_id,
                        &dst_host,
                        dst_port,
                        &acl,
                        TUNNEL_DIAL_TIMEOUT,
                        &quic_peer,
                        outbound,
                    )
                    .await;
                });
                return Ok(());
            }
            // Look up the WebRTC tunnel peer for this session — must
            // exist before the server is allowed to relay a forward
            // request for it. If absent (race / bad server), synthesise
            // an AgentError reject so the client doesn't hang.
            let Some(tunnel_peer) = tunnel_peers.get(&session_id).cloned() else {
                warn!(%session_id, %flow_id, "TcpForwardForward for unknown tunnel session — rejecting");
                let reply = ClientMsg::TcpForwardReject {
                    session_id,
                    flow_id,
                    kind: roomler_ai_remote_control::signaling::RejectKind::AgentError,
                    reason: roomler_ai_remote_control::signaling::REJECT_REASON_SESSION_GONE.into(),
                };
                let _ = outbound_tx.send(reply).await;
                return Ok(());
            };
            let outbound = outbound_tx.clone();
            let acl = forward_acl.clone();
            tokio::spawn(async move {
                crate::tunnel::acceptor::handle_forward_request(
                    session_id,
                    flow_id,
                    &dst_host,
                    dst_port,
                    &acl,
                    TUNNEL_DIAL_TIMEOUT,
                    &tunnel_peer,
                    outbound,
                )
                .await;
            });
        }

        // rc:tunnel.udp.forward — UDP ASSOCIATE analogue of
        // TcpForwardForward. Same dispatch: a QUIC session dials over
        // its quinn peer, a WebRTC-DC session over its DC pool. The
        // acceptor binds a target UDP socket, replies Accept/Reject,
        // and pumps datagrams.
        ServerMsg::UdpForwardForward {
            session_id,
            flow_id,
            dst_host,
            dst_port,
            owner_user_id: _,
        } => {
            if shared_ssh.contains(session_id) {
                return Ok(());
            }

            if let Some(quic_peer) = tunnel_quic_peers.get(&session_id).cloned() {
                let outbound = outbound_tx.clone();
                let acl = forward_acl.clone();
                tokio::spawn(async move {
                    crate::tunnel::acceptor::handle_udp_forward_request_quic(
                        session_id,
                        flow_id,
                        &dst_host,
                        dst_port,
                        &acl,
                        TUNNEL_DIAL_TIMEOUT,
                        &quic_peer,
                        outbound,
                    )
                    .await;
                });
                return Ok(());
            }
            let Some(tunnel_peer) = tunnel_peers.get(&session_id).cloned() else {
                warn!(%session_id, %flow_id, "UdpForwardForward for unknown tunnel session — rejecting");
                let reply = ClientMsg::UdpForwardReject {
                    session_id,
                    flow_id,
                    kind: roomler_ai_remote_control::signaling::RejectKind::AgentError,
                    reason: roomler_ai_remote_control::signaling::REJECT_REASON_SESSION_GONE.into(),
                };
                let _ = outbound_tx.send(reply).await;
                return Ok(());
            };
            let outbound = outbound_tx.clone();
            let acl = forward_acl.clone();
            tokio::spawn(async move {
                crate::tunnel::acceptor::handle_udp_forward_request(
                    session_id,
                    flow_id,
                    &dst_host,
                    dst_port,
                    &acl,
                    TUNNEL_DIAL_TIMEOUT,
                    &tunnel_peer,
                    outbound,
                )
                .await;
            });
        }

        // rc:tunnel.sdp.offer — controller's offer for the WebRTC
        // peer. Build an AgentTunnelPeer, accept the offer, ship the
        // answer back as `rc:tunnel.sdp.answer`. The peer takes care
        // of its own ICE trickle via the outbound channel.
        ServerMsg::TunnelSdpOffer {
            session_id,
            sdp,
            shared_lease,
        } => {
            match crate::tunnel::peer::AgentTunnelPeer::accept_offer(
                session_id,
                &sdp,
                Vec::new(),
                outbound_tx.clone(),
                tunnel_reap_tx.clone(),
            )
            .await
            {
                Ok((peer, answer_sdp)) => {
                    let peer = Arc::new(peer);
                    if shared_lease.is_some() && !shared_ssh.contains(session_id) {
                        peer.stop_serving();
                        return Ok(());
                    }
                    if !shared_leases.attach(
                        session_id,
                        shared_lease.as_ref(),
                        shared_ssh.stop(session_id, peer.clone()),
                    ) {
                        return Ok(());
                    }
                    for candidate in shared_leases.take_ice(session_id) {
                        let _ = peer.add_remote_ice(candidate).await;
                    }
                    tunnel_peers.insert(session_id, peer);
                    let _ = outbound_tx
                        .send(ClientMsg::TunnelSdpAnswer {
                            session_id,
                            sdp: answer_sdp,
                        })
                        .await;
                    info!(%session_id, "agent tunnel peer constructed; SDP answer sent");
                }
                Err(e) => {
                    warn!(%session_id, %e, "tunnel accept_offer failed");
                }
            }
        }

        // rc:tunnel.quic.setup — QUIC analogue of TunnelSdpOffer. The
        // server's trigger to stand up a quinn server endpoint for this
        // session and authorize the client bearing `quic_auth_token`.
        // We mint an ephemeral cert + bind the endpoint, then reply
        // `rc:tunnel.quic.ready` with the cert fingerprint (for the
        // client to pin — there's no CA) + dialable addrs.
        ServerMsg::TunnelQuicSetup {
            session_id,
            quic_auth_token,
            ice_servers,
            transport,
            client_derp_pubkey,
        } => {
            if shared_ssh.contains(session_id) {
                return Ok(());
            }

            // R4 — quic-derp-v1: the quinn server rides this node's
            // ESTABLISHED `/derp` WS toward the client's pubkey. No TURN
            // allocation, no permission dance. Any missing precondition
            // logs + sends no ready — the client times out and soft-falls
            // back to webrtc-dc, exactly the TURN-alloc-failure shape.
            if transport.as_deref() == Some(tunnel_core::transport::TRANSPORT_QUIC_DERP_V1) {
                let Some(handle) = crate::tunnel::netwatch::derp_tunnel_handle(tenant_id) else {
                    warn!(%session_id, "tunnel quic-derp: no live derp mux for this tenant — no ready");
                    return Ok(());
                };
                let Some(client_pk) = client_derp_pubkey
                    .as_deref()
                    .and_then(tunnel_core::transport::derp::parse_pubkey_hex)
                else {
                    warn!(%session_id, "tunnel quic-derp: missing/unparseable client_derp_pubkey — no ready");
                    return Ok(());
                };
                let conn = handle.mux.tunnel_conn_for(client_pk);
                let relay_conn: Arc<dyn relay::RelayConn> = Arc::new(conn);
                match crate::tunnel::quic_peer::AgentQuicPeer::setup_over_derp(
                    session_id,
                    quic_auth_token,
                    relay_conn,
                    handle.self_pubkey_hex.clone(),
                    tunnel_reap_tx.clone(),
                ) {
                    Ok(peer) => {
                        let ready = ClientMsg::TunnelQuicReady {
                            session_id,
                            cert_fingerprint: peer.cert_fingerprint().to_string(),
                            addrs: peer.addrs(),
                            derp_pubkey: peer.derp_pubkey_hex().map(str::to_string),
                        };
                        tunnel_quic_peers.insert(session_id, Arc::new(peer));
                        let _ = outbound_tx.send(ready).await;
                        info!(%session_id, "agent QUIC-over-DERP peer ready; rc:tunnel.quic.ready sent");
                    }
                    Err(e) => {
                        warn!(%session_id, %e, "tunnel quic-derp: AgentQuicPeer setup failed");
                    }
                }
                return Ok(());
            }
            // Phase 3d: if the server minted coturn creds, ride QUIC over
            // a TURN relay (QUIC-over-TURN) so symmetric-NAT /
            // UDP-restricted hosts are reachable; the relay peer
            // advertises its coturn relayed address. Otherwise bind a
            // direct 0.0.0.0:0 UDP endpoint (same-LAN / directly-
            // reachable; Phase 2a host candidates). A relay allocation
            // failure is non-fatal — we simply don't reply
            // `rc:tunnel.quic.ready`, and the client soft-falls back to
            // webrtc-dc-v1.
            let turn_creds = ice_servers
                .iter()
                .find_map(|s| match (&s.username, &s.credential) {
                    (Some(u), Some(c)) if relay::turn_udp_server(&s.urls).is_some() => {
                        Some((s.urls.clone(), u.clone(), c.clone()))
                    }
                    _ => None,
                });

            if let Some((urls, username, credential)) = turn_creds {
                // #1761 — NOT awaited here. The allocation walks the relay
                // ladder, ~20 s per setup on a UDP-hostile network, and
                // awaiting it on this loop stalled everything behind it —
                // pings, other sessions' setups, ICE, terminates, RC
                // signaling — for that long, per setup. It runs on its own
                // task; the outcome arm in `connect_once` inserts the peer
                // and sends the ready, applying the candidates buffered
                // meanwhile. A refusal spawns nothing and sends no ready:
                // the client soft-falls back exactly as after a failed
                // allocation.
                let req = crate::tunnel::quic_setup::QuicTurnSetup {
                    session_id,
                    quic_auth_token,
                    urls,
                    username,
                    credential,
                };
                match crate::tunnel::quic_setup::begin_quic_turn_setup(
                    pending_quic_setups,
                    req,
                    tunnel_reap_tx.clone(),
                    quic_setup_tx.clone(),
                    crate::tunnel::quic_setup::allocate_turn_relay,
                )
                .await
                {
                    Begin::Started { attempt } => {
                        info!(
                            %session_id,
                            attempt,
                            in_flight = pending_quic_setups.len(),
                            "tunnel quic: TURN-relayed setup started off the signaling loop (#1761)"
                        );
                    }
                    Begin::AlreadyPending => {
                        warn!(%session_id, "tunnel quic: a setup for this session is already in flight — ignoring the duplicate (#1761)");
                    }
                    Begin::AtCapacity => {
                        warn!(
                            %session_id,
                            cap = crate::tunnel::quic_setup::QUIC_SETUP_IN_FLIGHT_CAP,
                            "tunnel quic: too many TURN-relayed setups in flight — refusing this one; the client falls back (#1761)"
                        );
                    }
                }
                return Ok(());
            }

            // Direct bind: synchronous and instant, so it stays inline.
            let peer_result = {
                let bind = match "0.0.0.0:0".parse() {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(%session_id, %e, "tunnel quic: bad bind addr — skipping setup");
                        return Ok(());
                    }
                };
                crate::tunnel::quic_peer::AgentQuicPeer::setup(
                    session_id,
                    quic_auth_token,
                    bind,
                    tunnel_reap_tx.clone(),
                )
            };

            match peer_result {
                Ok(peer) => {
                    let ready = ClientMsg::TunnelQuicReady {
                        session_id,
                        cert_fingerprint: peer.cert_fingerprint().to_string(),
                        addrs: peer.addrs(),
                        derp_pubkey: None,
                    };
                    tunnel_quic_peers.insert(session_id, Arc::new(peer));
                    let _ = outbound_tx.send(ready).await;
                    info!(%session_id, "agent QUIC peer ready; rc:tunnel.quic.ready sent");
                }
                Err(e) => {
                    warn!(%session_id, %e, "tunnel quic: AgentQuicPeer setup failed");
                }
            }
        }

        // rc:tunnel.quic.candidate — the tunnel-client's relay
        // address(es), relayed by the server. The agent is the QUIC
        // *server* and never sends first, so for each candidate we
        // install a TURN permission (one bootstrap datagram through our
        // own allocation) — without it coturn drops the client's opening
        // QUIC Initials. No-op for a direct (non-relay) peer. Phase 3d.
        ServerMsg::TunnelQuicCandidate { session_id, addrs } => {
            let parsed = crate::tunnel::quic_setup::parse_candidate_addrs(session_id, &addrs);
            if pending_quic_setups.is_pending(session_id) {
                // #1761 — the peer is still being built on its task. Hold
                // the addresses; the outcome arm permits them the moment
                // the peer lands, before the ready goes out. Dropping them
                // here would be a session that never connects: the client's
                // opening Initials meet no TURN permission.
                for sa in &parsed {
                    pending_quic_setups.buffer_candidate(session_id, *sa);
                }
                debug!(%session_id, count = parsed.len(), "tunnel quic: candidates buffered for a setup in flight (#1761)");
            } else if let Some(peer) = tunnel_quic_peers.get(&session_id) {
                crate::tunnel::quic_setup::permit_candidates(peer, session_id, &parsed).await;
            } else {
                debug!(%session_id, "tunnel quic candidate for unknown session — dropping");
            }
        }

        // rc:tunnel.ice — trickle one ICE candidate into the agent's
        // tunnel peer. Drop silently if the peer is gone (e.g. peer
        // already torn down by a `TunnelTerminate`).
        ServerMsg::TunnelIce {
            session_id,
            candidate,
        } => {
            if let Some(peer) = tunnel_peers.get(&session_id) {
                if let Err(e) = peer.add_remote_ice(candidate).await {
                    debug!(%session_id, %e, "tunnel add_remote_ice failed");
                }
            } else {
                debug!(%session_id, "tunnel ICE for unknown session — dropping");
            }
        }

        // rc:tunnel.terminate from the server (relayed from the
        // client or admin-side teardown). Tear down our peer state.
        ServerMsg::TunnelTerminate { session_id, reason } => {
            info!(%session_id, ?reason, "rc:tunnel.terminate — closing peer");
            // #1761 — a setup still in flight for this session: its result,
            // when it lands, is closed rather than inserted.
            if pending_quic_setups.cancel(session_id) {
                info!(%session_id, "rc:tunnel.terminate for a QUIC setup still in flight — its result will be closed (#1761)");
            }
            if let Some(peer) = tunnel_peers.remove(&session_id) {
                close_within_budget(peer.close(), session_id, "tunnel_terminate").await;
            }
            // The session may instead be on the QUIC data plane.
            // `AgentQuicPeer::close` is synchronous (aborts the accept
            // task; the endpoint drops with the last Arc).
            if let Some(quic_peer) = tunnel_quic_peers.remove(&session_id) {
                quic_peer.close();
            }
        }

        // S1a — operator-triggered forced self-update from the web UI.
        // Hand the request to the updater loop's trigger channel; the
        // actual check/download/install runs there (same gates as the
        // periodic path: 5-min install-storm cooldown; transfer-defer
        // is bypassed with a warn because the operator asked NOW).
        ServerMsg::UpdateNow { pin } => {
            // Multi-org P1: the self-updater is machine-wide, so only the
            // PRIMARY enrollment may drive it — a secondary org's admin
            // must not force-update a binary shared with every other org.
            // The ignore is surfaced (log + LocalAPI OrgStatus counter)
            // rather than silently swallowed.
            if !ctx.is_primary {
                let total = ctx
                    .updates_ignored
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                warn!(
                    org = %ctx.label,
                    ?pin,
                    ignored_total = total,
                    "rc:agent.update ignored — only the primary enrollment drives the \
                     machine-wide self-updater"
                );
                return Ok(());
            }
            info!(?pin, "rc:agent.update — operator-triggered self-update");
            if !crate::updater::request_update_now(pin) {
                // Name the config key as well as the env var: the field case
                // (#1689) was `auto_update = false` in config.toml, and an
                // operator greps for the key they set.
                warn!(
                    "update trigger dropped — auto-update is off on this device \
                     (auto_update = false / ROOMLERD_AUTO_UPDATE=0), or 4 triggers \
                     are already queued"
                );
            }
        }

        // FR-92 — this org's keep-busy policy (on every connect, and on
        // change). Honoured from EVERY org, not just the primary: a deny is
        // the safe direction, and the device applies the strictest of all its
        // orgs — any one org's deny stops keep busy here and refuses it until
        // that org allows it again. Persisted, so it holds at boot.
        ServerMsg::KeepBusyPolicy { denied } => {
            info!(org = %ctx.label, denied, "keep-busy: org policy received");
            crate::keep_busy::set_org_policy(tenant_id, denied);
            // P3 — on a supervised Mac keep busy runs in the GUI worker,
            // which hears no org itself: hand it every org's word (the
            // strictest), now and on each attach. Deliberately NOT through
            // `delegable_inbound`: that path is primary-only, and a
            // secondary org's deny must reach the worker too.
            if let Some(delegate) = delegate {
                delegate.note_keep_busy_policy(tenant_id, denied);
            }
        }

        // Remote config (docs/remote-config.md) — reconcile against a pushed
        // desired state, then SAY what happened.
        //
        // Every branch below reports, including both refusals. That is the
        // point of the report rather than a completeness reflex: an operator
        // watching the dashboard cannot otherwise tell a device that declined
        // from one that never received the frame, and the two refusals here
        // are the ones they will actually hit — each with a concrete next
        // action they can only take if somebody tells them.
        ServerMsg::ConfigPush { revision, desired } => {
            use roomler_ai_remote_control::models::ConfigOutcome;

            // Machine-wide keys, so only the PRIMARY enrollment may drive
            // them — the identical rule `UpdateNow` applies to the
            // machine-wide self-updater. `AgentConfig::for_org` scopes none
            // of exec_enabled/ssh_*, so a secondary org's push would change
            // what EVERY org on this host can reach.
            if !ctx.is_primary {
                warn!(
                    org = %ctx.label,
                    revision,
                    "rc:agent.config ignored — only the primary enrollment may \
                     change machine-wide config"
                );
                report_config_status(outbound_tx, revision, ConfigOutcome::NotPrimary, None);
                return Ok(());
            }
            // Gate 4, and the reason this feature does not erode it: the
            // device decides whether it accepts pushed config at all, and the
            // server can never set this key.
            //
            // Read LIVE, not from the startup snapshot: this is how the person
            // holding the machine REVOKES the delegation, and a revocation
            // that waited for a service restart — while the control plane's
            // assertions took effect immediately — would be the slower half of
            // a rule that exists to be the last word.
            if !remote_cfg.remote_config_enabled() {
                info!(
                    revision,
                    "rc:agent.config ignored — this device has not opted in \
                     (set remote_config_enabled=true locally to accept pushed config)"
                );
                // Reporting a refusal is NOT a leak of gate 4's protection:
                // the server already knows it pushed and got nothing. What it
                // does not know is WHY, and that difference is the whole gap
                // between "update this device" and "go set one key on it".
                report_config_status(outbound_tx, revision, ConfigOutcome::NotOptedIn, None);
                return Ok(());
            }
            // Opted in and primary: reconcile against the file on DISK.
            // Idempotent — an already-matching desired state writes nothing,
            // which matters because this runs on every single reconnect.
            match remote_cfg.apply(&desired).await {
                Ok(applied) if applied.is_noop() => {
                    debug!(revision, "rc:agent.config — already matches; nothing to do");
                    // Still reported. A converged device and a device that has
                    // not answered look identical otherwise, and the steady
                    // state of this feature is "everything already matches" —
                    // so the common case would be the one with no evidence.
                    report_config_status(outbound_tx, revision, ConfigOutcome::Noop, None);
                }
                Ok(applied) => {
                    // Two lists, deliberately never one: `exec_enabled` is in
                    // force NOW, while the ssh_* keys are only WRITTEN until
                    // the daemon restarts (the SSH server is spliced into the
                    // packet path at overlay-runtime build). Reporting them
                    // together would tell an operator SSH is on when it isn't.
                    info!(
                        revision,
                        live = ?applied.live,
                        needs_restart = ?applied.needs_restart,
                        "rc:agent.config applied"
                    );
                    if !applied.needs_restart.is_empty() {
                        warn!(
                            keys = ?applied.needs_restart,
                            "rc:agent.config — saved, but these need a daemon restart \
                             to take effect"
                        );
                    }
                    let msg = ClientMsg::ConfigStatus {
                        revision,
                        outcome: ConfigOutcome::Applied,
                        live: applied.live.iter().map(|k| k.to_string()).collect(),
                        needs_restart: applied
                            .needs_restart
                            .iter()
                            .map(|k| k.to_string())
                            .collect(),
                        detail: None,
                    };
                    if outbound_tx.try_send(msg).is_err() {
                        debug!("rc:agent.config_status dropped (outbound queue full or closed)");
                    }
                }
                Err(e) => {
                    warn!(revision, %e, "rc:agent.config apply failed");
                    report_config_status(
                        outbound_tx,
                        revision,
                        ConfigOutcome::Failed,
                        Some(e.as_str()),
                    );
                }
            }
        }

        // Fleet RPC — run one bounded command and answer with rc:rpc.result.
        //
        // The server has already cleared gates 1–3 (org kill-switch, caller
        // permission, the device's ExecPolicy). Gate 4 is ours: `exec_enabled`
        // belongs to whoever holds this box and is the only refusal that
        // survives a compromised control plane.
        //
        // Everything after the gate runs on a SPAWNED task: a command may take
        // up to 300 s and this handler is on the WS receive path — blocking
        // here would stall every other message on this org's socket, including
        // the heartbeat that keeps the device marked online.
        ServerMsg::RpcExec {
            request_id,
            shell,
            command,
            timeout_ms,
            max_output_bytes,
            cwd,
            caller,
            consent_mode,
            via_service,
            run_as,
        } => {
            // FR-94 — a command meant for the SYSTEM service. Only a Windows
            // build advertises `exec-system`, so a server should never send
            // this anywhere else; if one does, refuse it here, before anyone
            // is asked to approve it. It never runs in THIS process: that
            // would be an identity nobody asked for (see `exec::RunAs`).
            if via_service && !cfg!(windows) {
                warn!(
                    %request_id, %caller,
                    "rc:rpc.exec via the SYSTEM service refused — not a Windows device"
                );
                let _ = outbound_tx
                    .send(ClientMsg::RpcResult {
                        request_id,
                        exit_code: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        truncated: false,
                        duration_ms: 0,
                        error: Some(
                            "this device cannot run commands through its SYSTEM service \
                             (update the agent)"
                                .to_string(),
                        ),
                    })
                    .await;
                return Ok(());
            }
            // FR-97 P5a — who runs it: the daemon, as Fleet RPC always has,
            // unless the device's policy names the person at the screen,
            // which the server sends only to a build advertising
            // `console-user`. A word this build does not know is refused,
            // before anyone is asked to approve it, never run as the daemon.
            let run_as = match run_as.as_deref().map(crate::exec_service::run_as_of) {
                None => crate::exec::RunAs::Daemon,
                Some(Ok((who, _))) => who,
                Some(Err(why)) => {
                    warn!(%request_id, %caller, %why, "rc:rpc.exec refused — unknown run_as");
                    let _ = outbound_tx
                        .send(ClientMsg::RpcResult {
                            request_id,
                            exit_code: None,
                            stdout: String::new(),
                            stderr: String::new(),
                            truncated: false,
                            duration_ms: 0,
                            error: Some(why),
                        })
                        .await;
                    return Ok(());
                }
            };
            // Gate 4, read LIVE (docs/remote-config.md): a pushed change takes
            // effect on the next command, with no restart — which is why
            // this is the atomic and not the startup snapshot.
            if !remote_cfg.exec_enabled() {
                warn!(
                    %request_id, %caller,
                    "rc:rpc.exec refused — exec_enabled is off on this device"
                );
                // Always answer. A caller is blocked on this; silence would
                // read as a hang rather than a refusal.
                let _ = outbound_tx
                    .send(ClientMsg::RpcResult {
                        request_id,
                        exit_code: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        truncated: false,
                        duration_ms: 0,
                        error: Some(
                            "remote execution is disabled on this device \
                             (`roomler config set exec_enabled true` to allow it)"
                                .to_string(),
                        ),
                    })
                    .await;
                return Ok(());
            }

            // Absent directive ⇒ prompt. Fail-safe for a gate that grants root.
            let auto = matches!(
                consent_mode,
                Some(roomler_ai_remote_control::models::ConsentMode::Auto)
            );
            let directive = if auto {
                crate::consent::Mode::AutoGrant
            } else {
                crate::consent::Mode::Prompt {
                    timeout: crate::consent::DEFAULT_PROMPT_TIMEOUT,
                }
            };
            // FR-27 — same floor as the RC path: a device that set
            // `auto_grant_session = false` is not overridden into auto-granting
            // a command that runs as SYSTEM/root.
            let consent_mode = crate::consent::strictest_of(
                Some(directive),
                consent_broker.mode(),
                crate::consent::DEFAULT_PROMPT_TIMEOUT,
            );

            // FR-27 — exec has ALWAYS prompted through this broker and NEVER
            // written a marker, so its prompt reached no UI: the only way to
            // answer one was to find the request id in the daemon log and run
            // the CLI inside 30 s. In practice that made a non-`auto`
            // `exec_policy` unusable rather than strict.
            //
            // ⚠️ The command is redacted BEFORE it goes anywhere near a marker
            // file that a GUI will render — same redactor that scrubs exec
            // output leaving the host, for the same reason.
            if matches!(consent_mode, crate::consent::Mode::Prompt { .. }) {
                let shown = crate::exec::redactor().apply(&command);
                let detail: String = shown.chars().take(512).collect();
                // Same multi-org rule as the RC prompt: name the asking org
                // only on a device that serves more than one, since on a
                // single-org device there is nothing to disambiguate.
                // `rc:rpc.exec` carries no tenant display name, so this
                // loop's own label is the best available.
                let org = if !ctx.is_primary || !agent_cfg.orgs.is_empty() {
                    ctx.label.clone()
                } else {
                    String::new()
                };
                // Native panel first, exactly as for a screen-control request
                // — and with the command in front of whoever is deciding,
                // because "approve SSH-ish access" and "approve `rm -rf`
                // running as SYSTEM" are not the same question.
                let view = crate::indicator::PromptView {
                    session_hex: request_id.clone(),
                    title: "Command execution request".into(),
                    lead: format!("{caller} wants to run a command on this device."),
                    detail: detail.clone(),
                    permissions: String::new(),
                    org: org.clone(),
                    expires_at: std::time::Instant::now() + crate::consent::DEFAULT_PROMPT_TIMEOUT,
                };
                let native = indicator.show_prompt(view.clone());
                let prompt = crate::consent::PendingPrompt {
                    kind: crate::consent::PromptKind::Exec,
                    asked_by: &caller,
                    permissions: String::new(),
                    detail,
                    org,
                    timeout: crate::consent::DEFAULT_PROMPT_TIMEOUT,
                    surface: if native {
                        crate::consent::PromptSurface::Native
                    } else {
                        crate::consent::PromptSurface::Companion
                    },
                };
                if let Err(e) = consent_broker.write_prompt(&request_id, &prompt) {
                    tracing::warn!(%request_id, %e, native, "could not write the .pending consent marker for this command");
                }
                if !native {
                    // FR-93 P6f — and where the companion cannot show it, a
                    // desktop notification. In the background, as the
                    // companion's start always was here: the command waits on
                    // the broker below, not on its surfaces. The marker is not
                    // rewritten for it, because by the time the notification
                    // is up the question may be over, and a marker written
                    // then would outlive it.
                    let ind = indicator.clone();
                    tokio::spawn(async move {
                        if !crate::companion::ensure_running().await {
                            ind.show_notification_prompt(view).await;
                        }
                    });
                }
            }

            let broker = consent_broker.clone();
            let outbound = outbound_tx.clone();
            let req = crate::exec::ExecRequest {
                request_id: request_id.clone(),
                shell,
                command,
                timeout_ms,
                max_output_bytes,
                cwd,
                caller: caller.clone(),
                // Fleet RPC is privileged diagnostics by design — the whole
                // point is `netsh`, route tables and service state. It runs
                // as the daemon unless the policy named the person at the
                // screen (FR-97 P5a, above).
                run_as,
                // Where it always started, or its `cwd` (FR-97 P5b is SSH's).
                start_in_home: false,
            };
            let ind = indicator.clone();
            tokio::spawn(async move {
                // #2416 — as on the RC path: a question whose control socket
                // closed is withdrawn. Here it matters more, since an Approve
                // given to a stale panel would run the command for a caller
                // no longer waiting for it, and twice if that caller retried.
                let decision = await_prompt_or_socket_end(
                    broker.request_with_mode(&request_id, consent_mode),
                    &outbound,
                    &request_id,
                )
                .await;
                // FR-27 — same convergence point as the RC path: take the
                // native panel down however the question was answered.
                ind.hide_prompt(&request_id);
                let outcome = if !decision.granted() {
                    warn!(%request_id, %caller, ?decision, "rc:rpc.exec denied at the device");
                    crate::exec::ExecOutcome {
                        error: Some(format!(
                            "the operator at this device did not approve the command ({decision:?})"
                        )),
                        ..Default::default()
                    }
                } else if via_service {
                    // FR-94 — approved: ring the SYSTEM service with the
                    // request id alone. It claims the command from the server
                    // and posts the result there itself, so once it has taken
                    // it nothing more is said from here. If it has not, the
                    // reason is this command's answer, and the server
                    // withdraws the command so a late claim cannot run it.
                    match crate::exec_service::ring(&request_id).await {
                        Ok(()) => {
                            info!(%request_id, %caller, "rc:rpc.exec handed to the SYSTEM service");
                            return;
                        }
                        Err(e) => {
                            warn!(%request_id, %caller, %e, "rc:rpc.exec: the SYSTEM service did not take it");
                            crate::exec::ExecOutcome {
                                error: Some(e),
                                ..Default::default()
                            }
                        }
                    }
                } else {
                    crate::exec::shared()
                        .run(req, &crate::exec::redactor())
                        .await
                };
                if let Err(e) = outbound
                    .send(ClientMsg::RpcResult {
                        request_id: request_id.clone(),
                        exit_code: outcome.exit_code,
                        stdout: outcome.stdout,
                        stderr: outcome.stderr,
                        truncated: outcome.truncated,
                        duration_ms: outcome.duration_ms,
                        error: outcome.error,
                    })
                    .await
                {
                    warn!(%request_id, %e, "rc:rpc.result send failed (channel closed)");
                }
            });
        }

        // Fleet RPC — kill an in-flight command. The run itself still answers
        // with an rc:rpc.result carrying `error`, so the caller isn't left
        // waiting on a request nobody will finish.
        ServerMsg::RpcCancel { request_id } => {
            tokio::spawn(async move {
                let found = crate::exec::shared().cancel(&request_id).await;
                // FR-94 — a command the SYSTEM service runs is killed there.
                let in_service = !found && crate::exec_service::cancel(&request_id).await;
                info!(%request_id, found, in_service, "rc:rpc.cancel");
            });
        }

        // Roomler SSH — the server authorized ONE inbound session against this
        // device. Recording it is all that happens here; the grant is redeemed
        // (and consumed) when a connection authenticates with the named key.
        //
        // Gate 4 is re-checked locally: a device with `ssh_enabled` off must
        // not accumulate grants it would never honour, and refusing loudly
        // beats a caller timing out against a port that answers nothing.
        //
        // FR-83 — and every outcome is ANSWERED (`rc:ssh.grant_ack`). The
        // server holds the caller until it arrives, so the refusals above now
        // reach the person who asked instead of only this log.
        ServerMsg::SshGrant {
            grant_id,
            public_key,
            caller,
            account_mode,
            account,
            expires_at_ms,
            session_secs,
            consent_mode,
            via_service,
            // FR-90 P3-8-2a — an agent session's grant, held to ONE command by
            // this device's SSH server (`ssh::Grant::one_command`), whichever
            // of the two serves it: the worker's below, or the SYSTEM
            // service's, which takes it from its own claim.
            one_command,
        } => {
            #[cfg(feature = "ssh-server")]
            if via_service {
                // FR-105 — a grant for this device's SYSTEM service never
                // lands in the worker's table, where the worker's own server
                // would honour it as the signed-in user. The service claims
                // it with its own credential, and that claim is the server's
                // acknowledgement; the worker only rings, and can refuse.
                use roomler_ai_remote_control::models::SshGrantRefusal;
                let refusal = if !agent_cfg.ssh_enabled {
                    // The person's half: their worker carries the port.
                    Some((
                        SshGrantRefusal::SshDisabled,
                        "ssh_enabled is off on this device",
                    ))
                } else if crate::ssh_service::disabled() {
                    Some((
                        SshGrantRefusal::Other,
                        "SSH through the SYSTEM service is switched off on this device",
                    ))
                } else if account_mode == "daemon"
                    && agent_cfg.ssh_max_privilege.as_deref() == Some("console_user")
                {
                    // The person's own ceiling (M5), honoured as a refusal on
                    // this path too.
                    Some((
                        SshGrantRefusal::Other,
                        "ssh_max_privilege refuses sessions as SYSTEM on this device",
                    ))
                } else {
                    None
                };
                if let Some((refused, why)) = refusal {
                    warn!(%grant_id, %caller, why, "rc:ssh.grant for the SYSTEM service refused");
                    let _ = outbound_tx
                        .send(ClientMsg::SshGrantAck {
                            grant_id,
                            refused: Some(refused),
                        })
                        .await;
                } else {
                    // Off this loop: the service's claim is an HTTPS round trip.
                    let tx = outbound_tx.clone();
                    tokio::spawn(async move {
                        match crate::exec_service::ring_ssh(&grant_id).await {
                            Ok(()) => info!(
                                %grant_id, %caller,
                                "rc:ssh.grant handed to the SYSTEM service"
                            ),
                            Err(e) => {
                                warn!(
                                    %grant_id, %caller, %e,
                                    "rc:ssh.grant refused — the SYSTEM service did not take it"
                                );
                                let _ = tx
                                    .send(ClientMsg::SshGrantAck {
                                        grant_id,
                                        refused: Some(SshGrantRefusal::Other),
                                    })
                                    .await;
                            }
                        }
                    });
                }
                // The service pulled what it needs from the server, its claim
                // carrying `one_command` too; nothing here is the worker's to
                // hold.
                let _ = (
                    public_key,
                    account,
                    consent_mode,
                    expires_at_ms,
                    session_secs,
                    one_command,
                );
            } else {
                use roomler_ai_remote_control::models::SshGrantRefusal;
                let refused = if !agent_cfg.ssh_enabled {
                    warn!(
                        %grant_id, %caller,
                        "rc:ssh.grant refused — ssh_enabled is off on this device"
                    );
                    Some(SshGrantRefusal::SshDisabled)
                } else {
                    match crate::ssh::record_grant(
                        grant_id.clone(),
                        public_key,
                        caller.clone(),
                        account_mode,
                        account,
                        consent_mode,
                        expires_at_ms,
                        session_secs,
                        one_command,
                    ) {
                        Ok(()) => None,
                        Err(e) => {
                            warn!(%grant_id, %caller, %e, "rc:ssh.grant rejected");
                            Some(e.refusal())
                        }
                    }
                };
                // Only NOW: on `None` the grant is already in the table the
                // auth path reads, so "acknowledged" means "redeemable". Sent
                // unconditionally — an older server cannot parse the frame and
                // drops it at `debug!`, which costs one small frame per grant.
                let _ = outbound_tx
                    .send(ClientMsg::SshGrantAck { grant_id, refused })
                    .await;
            }
            // No ack from this build: it advertises neither `ssh` nor
            // `ssh-grant-ack`, so no server pushes it a grant or waits on one.
            #[cfg(not(feature = "ssh-server"))]
            {
                let _ = (
                    &public_key,
                    &account_mode,
                    &account,
                    consent_mode,
                    expires_at_ms,
                    session_secs,
                    via_service,
                    one_command,
                );
                warn!(
                    %grant_id, %caller,
                    "rc:ssh.grant ignored — this build lacks the `ssh-server` feature"
                );
            }
        }

        // FR-90 — start an agent session. Answered with `rc:hive.start_ack`
        // on THIS connection, from a task of its own (launching is I/O this
        // loop must not wait on), after the device's own gates.
        ServerMsg::HiveStart {
            session_id,
            harness,
            harness_session,
            fence,
            folder,
            user_id,
            user_email,
            caller,
            resume,
            replicated,
            lease,
            fork_of,
            from_terminal,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_start(
                crate::hive::StartOrder {
                    session_id,
                    harness,
                    harness_session,
                    fence,
                    folder,
                    user_id,
                    user_email,
                    caller,
                    resume,
                    // P2c-3 — the server placed members besides this device:
                    // checkpoint each turn's end (P2b-3b).
                    replicated,
                    // P2e-2 — and hold it to the server's word on each
                    // connection from now on.
                    lease,
                    // P2f-3a — a fork: started from its parent's copy here.
                    fork_of,
                    // P2f-4a — a terminal session this device adopted, made a
                    // managed one: started from the terminal's own history.
                    from_terminal,
                },
                ctx.is_primary,
                outbound_tx.clone(),
            );
            // No ack from this build: it does not advertise `hive`, so no
            // server sends it a start or waits on one.
            #[cfg(not(hive_host))]
            {
                let _ = (
                    &harness,
                    &harness_session,
                    fence,
                    &folder,
                    user_id,
                    &user_email,
                    resume,
                    replicated,
                    lease,
                    &fork_of,
                    from_terminal,
                );
                warn!(
                    session = %session_id, %caller,
                    "rc:hive.start ignored — this build does not run agent sessions"
                );
            }
        }

        // FR-90 — stop an agent session; its `ended` arrives as
        // `rc:hive.state` once the harness is gone.
        ServerMsg::HiveStop {
            session_id,
            fence,
            reason,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_stop(session_id, fence, reason, ctx.is_primary);
            #[cfg(not(hive_host))]
            {
                let _ = (fence, &reason);
                debug!(session = %session_id, "rc:hive.stop ignored — this build does not run agent sessions");
            }
        }

        // FR-90 P2g-1 — the session purged from this device, its own copy and
        // what its account holds of it, answered per part on this connection.
        ServerMsg::HivePurge {
            purge_id,
            session_id,
            leaving,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_purge(
                purge_id,
                session_id,
                leaving,
                ctx.is_primary,
                outbound_tx.clone(),
            );
            #[cfg(not(hive_host))]
            {
                let _ = (purge_id, leaving);
                debug!(session = %session_id, "rc:hive.purge ignored — this build does not run agent sessions");
            }
        }

        // FR-90 P2g-4a — this device's enrollment is being removed: every
        // session it holds is purged.
        ServerMsg::HivePurgeAll { purge_id } => {
            #[cfg(hive_host)]
            crate::hive::handle_purge_all(purge_id, ctx.is_primary);
            #[cfg(not(hive_host))]
            debug!(purge = %purge_id, "rc:hive.purge_all ignored — this build does not run agent sessions");
        }

        // FR-90 P2g-3d — what keeps each copy this device asked about: the
        // device's own clock counts from it.
        ServerMsg::HiveRetain { words } => {
            #[cfg(hive_host)]
            crate::hive::handle_retain(words, ctx.is_primary);
            #[cfg(not(hive_host))]
            debug!(
                words = words.len(),
                "rc:hive.retain ignored — this build does not run agent sessions"
            );
        }

        // FR-90 P2e-2 — the server's word, on THIS connection, that this
        // device holds the session at that fence: a leased run calls the model
        // again, and a leased session it hosted launches.
        ServerMsg::HiveLease { session_id, fence } => {
            #[cfg(hive_host)]
            crate::hive::handle_lease(session_id, fence, ctx.is_primary, outbound_tx.clone());
            #[cfg(not(hive_host))]
            {
                let _ = fence;
                debug!(session = %session_id, "rc:hive.lease ignored — this build does not run agent sessions");
            }
        }

        // FR-90 P2e-1 — the session's lease moved past this device: what runs
        // here at an older fence ends, and nothing here resumes it.
        ServerMsg::HiveDemote {
            session_id,
            fence,
            reason,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_demote(session_id, fence, reason, ctx.is_primary);
            #[cfg(not(hive_host))]
            {
                let _ = (fence, &reason);
                debug!(session = %session_id, "rc:hive.demote ignored — this build does not run agent sessions");
            }
        }

        // FR-90 P2e-4 — the session's lease is about to leave this device: no
        // new prompt, the running turn ends or is cut, a last checkpoint, and
        // `rc:hive.drained` back on THIS connection with where the copy ends.
        // Taken up before the next frame is read, so a lease word right
        // behind it lifts it.
        ServerMsg::HiveDrain { session_id, fence } => {
            #[cfg(hive_host)]
            crate::hive::handle_drain(session_id, fence, ctx.is_primary, outbound_tx.clone());
            #[cfg(not(hive_host))]
            {
                let _ = fence;
                debug!(session = %session_id, "rc:hive.drain ignored — this build does not run agent sessions");
            }
        }

        // FR-90 P2e-5 — could this device take the session over? A start's
        // every gate, as configured now, and none of its side effects; the
        // answer goes back on THIS connection. P2f-1a — a teleport's asks
        // every gate but the copy, which the device takes after it.
        ServerMsg::HivePrepare {
            session_id,
            fence,
            harness,
            harness_session,
            folder,
            user_id,
            user_email,
            caller,
            teleport,
            have_want,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_prepare(
                crate::hive::StartOrder {
                    session_id,
                    harness,
                    harness_session,
                    fence,
                    folder,
                    user_id,
                    user_email,
                    caller,
                    resume: true,
                    replicated: true,
                    lease: true,
                    // P2f-3a — a prepare launches nothing; the moved start
                    // that follows says whether the session is a fork.
                    fork_of: None,
                    from_terminal: false,
                },
                teleport,
                have_want,
                ctx.is_primary,
                outbound_tx.clone(),
            );
            #[cfg(not(hive_host))]
            {
                let _ = (
                    fence,
                    &harness,
                    &harness_session,
                    &folder,
                    user_id,
                    &user_email,
                    &caller,
                    teleport,
                    have_want,
                );
                debug!(session = %session_id, "rc:hive.prepare ignored — this build does not run agent sessions");
            }
        }

        // FR-90 P2e-5 — the record's word for the start right behind it: the
        // turns the session has had, and where it ran. Kept for that start,
        // which takes the session over from its copy when it ran elsewhere.
        ServerMsg::HiveMove {
            session_id,
            fence,
            turns,
            from_device_id,
            from_device_name,
            from_folder,
            moved_by: _,
            moved_by_name,
            moved_at_ms,
            earlier,
        } => {
            info!(
                session = %session_id, fence, from = %from_device_name,
                by = %moved_by_name, earlier = earlier.len(), "the session moves to this device"
            );
            // P2e-7 — where it came from and who moved it, for the resume
            // note; P2f-5 — and every place before. A build without Hive keeps
            // none of it.
            #[cfg(not(hive_host))]
            let _ = (&from_folder, moved_at_ms, &earlier);
            #[cfg(hive_host)]
            crate::hive::handle_move(
                crate::hive::Moved {
                    session_id,
                    fence,
                    turns,
                    from_device_id,
                    from_device_name,
                    from_folder,
                    moved_by_name,
                    moved_at_ms,
                    earlier,
                },
                ctx.is_primary,
            );
            #[cfg(not(hive_host))]
            let _ = (turns, from_device_id);
        }

        // FR-90 P1e — a session's core memory, just ahead of its start. Kept
        // for that start's launch; whether the session sees it is the
        // device's own `hive_core_memory`.
        ServerMsg::HiveMemory {
            session_id,
            fence,
            brain_rev,
            claude_md,
            memory_md,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_memory(
                crate::hive::CoreMemory {
                    session_id,
                    fence,
                    brain_rev,
                    claude_md,
                    memory_md,
                },
                ctx.is_primary,
            );
            #[cfg(not(hive_host))]
            {
                let _ = (fence, brain_rev, &claude_md, &memory_md);
                debug!(session = %session_id, "rc:hive.memory ignored — this build does not run agent sessions");
            }
        }

        // FR-90 P1j — the server's word on a terminal session this device
        // offered. Only a build that adopts sends offers.
        ServerMsg::HiveAdoptAck {
            adopt_id,
            session_id,
            fence,
            refused,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_adopt_ack(&adopt_id, session_id, fence, refused, ctx.is_primary);
            #[cfg(not(hive_host))]
            {
                let _ = (session_id, fence, refused);
                debug!(
                    adopt_id,
                    "rc:hive.adopt_ack ignored — this build does not adopt"
                );
            }
        }

        // FR-90 P0d-2 — the viewer peer. A grant is answered with
        // `rc:hive.view.grant_ack` on THIS connection, from a task (it reads
        // the replica store); the rest feeds the grant's own actor. A build
        // without `hive` does not advertise `hive-view`, so no server sends
        // it any of these.
        ServerMsg::HiveViewGrant {
            grant_id,
            session_id,
            user_id,
            user_name,
            may_prompt,
            user_email,
            ttl_secs,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_view_grant(
                crate::hive::ViewGrant {
                    grant_id,
                    session_id,
                    user_id,
                    user_name,
                    may_prompt,
                    user_email,
                    driving_refused: None,
                    copy: false,
                    ttl_secs,
                    search: None,
                },
                ctx.is_primary,
                outbound_tx.clone(),
            );
            #[cfg(not(hive_host))]
            {
                let _ = (
                    session_id,
                    user_id,
                    &user_name,
                    may_prompt,
                    &user_email,
                    ttl_secs,
                );
                debug!(grant = %grant_id, "rc:hive.view.grant ignored — this build does not serve agent sessions");
            }
        }
        // FR-90 P2i-1 — a search over this device's copies: answered as a view
        // grant is, and served by the same actor, so the rest rides the view's
        // frames. Only a connection advertising `hive-search` is sent one.
        ServerMsg::HiveSearchGrant {
            grant_id,
            user_id,
            sessions,
            ttl_secs,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_search_grant(
                crate::hive::SearchGrant {
                    grant_id,
                    user_id,
                    sessions,
                    ttl_secs,
                },
                ctx.is_primary,
                outbound_tx.clone(),
            );
            #[cfg(not(hive_host))]
            {
                let _ = (user_id, &sessions, ttl_secs);
                debug!(grant = %grant_id, "rc:hive.search.grant ignored — this build does not serve agent sessions");
            }
        }
        ServerMsg::HiveViewOffer {
            grant_id,
            sdp,
            ice_servers,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_view_offer(grant_id, sdp, ice_servers, ctx.is_primary);
            #[cfg(not(hive_host))]
            {
                let _ = (&sdp, &ice_servers);
                debug!(grant = %grant_id, "rc:hive.view.offer ignored");
            }
        }
        ServerMsg::HiveViewIce {
            grant_id,
            candidate,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_view_ice(grant_id, candidate, ctx.is_primary);
            #[cfg(not(hive_host))]
            {
                let _ = &candidate;
                debug!(grant = %grant_id, "rc:hive.view.ice ignored");
            }
        }
        ServerMsg::HiveViewRenew { grant_id, ttl_secs } => {
            #[cfg(hive_host)]
            crate::hive::handle_view_renew(grant_id, ttl_secs, ctx.is_primary);
            #[cfg(not(hive_host))]
            {
                let _ = ttl_secs;
                debug!(grant = %grant_id, "rc:hive.view.renew ignored");
            }
        }
        ServerMsg::HiveViewClose { grant_id, reason } => {
            #[cfg(hive_host)]
            crate::hive::handle_view_close(grant_id, reason, ctx.is_primary);
            #[cfg(not(hive_host))]
            {
                let _ = &reason;
                debug!(grant = %grant_id, "rc:hive.view.close ignored");
            }
        }
        // FR-90 P2c-3 — hold a copy of a session. Answered with
        // `rc:hive.replica.join_ack` on THIS connection, after the device's
        // own gates; a secondary org's connection is refused there.
        ServerMsg::HiveReplicaJoin {
            session_id,
            fence,
            role,
            fences,
        } => {
            #[cfg(hive_host)]
            crate::hive::handle_replica_join(
                session_id,
                fence,
                role,
                fences,
                ctx.is_primary,
                outbound_tx.clone(),
            );
            // No answer from this build: it does not advertise
            // `hive-replica`, so no server sends it a join.
            #[cfg(not(hive_host))]
            {
                let _ = fences;
                debug!(
                    session = %session_id, fence, ?role,
                    "rc:hive.replica.join ignored — this build holds no copies"
                );
            }
        }

        // FR-90 P2d — serve a stream of a session this device holds to one
        // of its members. Answered with `rc:hive.replica.ready` on THIS
        // connection; a secondary org's is refused there.
        ServerMsg::HiveReplicaGrant {
            grant_id,
            session_id,
            fence,
            member_id,
            path,
            token,
            ice_servers,
            ttl_secs,
            member_derp_pubkey,
        } => {
            #[cfg(hive_host)]
            {
                crate::hive::handle_replica_grant(
                    grant_id,
                    session_id,
                    fence,
                    member_id,
                    path,
                    token,
                    ice_servers,
                    member_derp_pubkey,
                    ttl_secs,
                    ctx.is_primary,
                    outbound_tx.clone(),
                );
            }
            // No answer from this build: it does not advertise
            // `hive-stream`, so no server grants it a stream to serve.
            #[cfg(not(hive_host))]
            {
                let _ = (
                    session_id,
                    fence,
                    member_id,
                    path,
                    token,
                    ice_servers,
                    ttl_secs,
                    member_derp_pubkey,
                );
                debug!(grant = %grant_id, "rc:hive.replica.grant ignored — this build carries no streams");
            }
        }

        // FR-90 P2d — the source this device asked for is ready: dial it.
        ServerMsg::HiveReplicaDial {
            grant_id,
            session_id,
            fence,
            source_id,
            path,
            token,
            cert_fingerprint,
            addrs,
            derp_pubkey,
            ice_servers,
            ttl_secs,
        } => {
            #[cfg(hive_host)]
            {
                crate::hive::handle_replica_dial(
                    grant_id,
                    session_id,
                    fence,
                    source_id,
                    path,
                    token,
                    cert_fingerprint,
                    addrs,
                    ice_servers,
                    derp_pubkey,
                    ttl_secs,
                    ctx.is_primary,
                );
            }
            #[cfg(not(hive_host))]
            {
                let _ = (
                    session_id,
                    fence,
                    source_id,
                    path,
                    token,
                    cert_fingerprint,
                    addrs,
                    derp_pubkey,
                    ice_servers,
                    ttl_secs,
                );
                debug!(grant = %grant_id, "rc:hive.replica.dial ignored — this build carries no streams");
            }
        }

        // FR-90 P2d-2b — the member's relayed address, for the `relay` rung's
        // TURN permission on this source's allocation; and a want the server
        // refused, which the member's ladder acts on (P2d-3b).
        ServerMsg::HiveReplicaCandidate { grant_id, addr } => {
            #[cfg(hive_host)]
            crate::hive::handle_replica_candidate(grant_id, addr, ctx.is_primary);
            #[cfg(not(hive_host))]
            debug!(grant = %grant_id, %addr, "rc:hive.replica.candidate ignored — this build carries no streams");
        }
        ServerMsg::HiveReplicaRefused {
            session_id,
            fence,
            path,
            reason,
            detail,
        } => {
            info!(
                session = %session_id, fence, path = ?path, reason = ?reason, detail = ?detail,
                "rc:hive.replica.refused"
            );
            // FR-90 P2d-3b — the answer to this device's ask: the ladder acts
            // on it.
            #[cfg(hive_host)]
            crate::hive::handle_replica_refused(session_id, fence, path, reason, ctx.is_primary);
        }

        // FR-90 P2d — the server ended a stream this device is a side of.
        ServerMsg::HiveReplicaClose { grant_id, reason } => {
            #[cfg(hive_host)]
            crate::hive::handle_replica_close(grant_id, reason);
            #[cfg(not(hive_host))]
            debug!(grant = %grant_id, %reason, "rc:hive.replica.close ignored — this build carries no streams");
        }

        // Roomler SSH — the answer to a session THIS device asked for
        // (`roomler ssh`). Handed to whichever LocalAPI call is parked on it;
        // an unknown id means that caller already gave up.
        ServerMsg::SshResponse {
            request_id,
            address,
            port,
            grant_id,
            host_pubkey,
            expires_at_ms,
            error,
            // FR-90 P3-8-2b — the echo of an agent session's ticket: its
            // daemon dials only on an answer that echoes the ticket it sent.
            ssh_ticket_id,
        } => {
            // The key itself is never logged — only whether one arrived. It is
            // public, but a log line is the wrong place to start treating key
            // material as printable, and "did the server have one for this
            // device" is the whole diagnostic value anyway.
            info!(
                %request_id,
                address = ?address, port = ?port, grant_id = ?grant_id,
                verifiable = host_pubkey.is_some(), error = ?error,
                ssh_ticket_id = ?ssh_ticket_id,
                "rc:ssh.response"
            );
            crate::ssh_origin::deliver(
                &request_id,
                crate::ssh_origin::SshGrantAnswer {
                    address,
                    port,
                    host_pubkey,
                    grant_id,
                    expires_at_ms,
                    error,
                    ssh_ticket_id,
                },
            );
        }

        // Fleet RPC — the answer to a command THIS device asked another device
        // to run (`roomler exec`). Handed to whichever LocalAPI call is parked
        // on it; an unknown id means that caller already gave up.
        ServerMsg::RpcExecResponse {
            request_id,
            exit_code,
            stdout,
            stderr,
            truncated,
            duration_ms,
            error,
        } => {
            let delivered = crate::exec::deliver_response(
                &request_id,
                crate::exec::ExecOutcome {
                    exit_code,
                    // The wire carried text; the byte views are that text.
                    stdout_bytes: stdout.as_bytes().to_vec(),
                    stderr_bytes: stderr.as_bytes().to_vec(),
                    stdout,
                    stderr,
                    truncated,
                    duration_ms,
                    error,
                },
            );
            if !delivered {
                debug!(%request_id, "rc:rpc.response for an unknown request — caller gave up");
            }
        }

        // FR-40 — retire THIS org's overlay key: mint → persist → report →
        // reconnect under the new identity
        // (`docs/fr/FR-40-overlay-key-rotation.md`).
        //
        // Deliberately NOT primary-only: the key is per enrollment
        // (`AgentConfig::for_org` scopes it), so org B's admin rotating org B's
        // key on a shared host touches nothing of org A's — the opposite of
        // `rc:agent.update` / `rc:agent.config`, which drive machine-wide
        // state. Every branch reports, refusals included: the operator is
        // looking at a security action "in flight" and each refusal has a
        // different fix.
        ServerMsg::KeyRotate { request_id } => {
            use roomler_ai_remote_control::models::KeyRotationOutcome;

            if agent_cfg.overlay_key_rotation == Some(false) {
                warn!(
                    %request_id,
                    "rc:agent.key_rotate refused — overlay_key_rotation=false on this device"
                );
                report_key_rotated(
                    outbound_tx,
                    &request_id,
                    KeyRotationOutcome::Disabled,
                    None,
                    None,
                    agent_cfg.overlay_wg_key_epoch,
                    Some("overlay_key_rotation=false on the device"),
                );
                return Ok(());
            }
            // The device's OWN ceiling. The server has one too, but a bound
            // that exists only on the ordering side is not a bound.
            if !key_rotation_ceiling_ok(tenant_id) {
                warn!(
                    %request_id,
                    "rc:agent.key_rotate refused — a rotation ran less than a minute ago"
                );
                report_key_rotated(
                    outbound_tx,
                    &request_id,
                    KeyRotationOutcome::RateLimited,
                    None,
                    None,
                    agent_cfg.overlay_wg_key_epoch,
                    Some("rotated less than 60 s ago"),
                );
                return Ok(());
            }
            // A build with no overlay surface has nothing to rotate. The mint
            // lives in `crate::key_rotation`, which carries the feature split,
            // so this arm — and `ConnectError::KeyRotated` — compiles the same
            // in every feature set (see that module's doc for why that is not
            // merely tidy).
            let Some((new_secret, new_public)) = crate::key_rotation::mint_wg_identity() else {
                warn!(
                    %request_id,
                    "rc:agent.key_rotate refused — this build has no overlay surface"
                );
                report_key_rotated(
                    outbound_tx,
                    &request_id,
                    KeyRotationOutcome::Unsupported,
                    None,
                    None,
                    0,
                    Some("no overlay surface in this build"),
                );
                return Ok(());
            };
            {
                let old_public = agent_cfg
                    .overlay_wg_secret_key
                    .as_deref()
                    .and_then(crate::key_rotation::wg_public_of);
                // Persist FIRST. If this fails the identity stays and the
                // device says so: a key that is not written down would be
                // lost at the next restart, and the device would come back as
                // the key it just retired.
                let key_epoch = match remote_cfg
                    .rotate_overlay_key(ctx.is_primary, tenant_id, new_secret.clone())
                    .await
                {
                    Ok(epoch) => epoch,
                    Err(e) => {
                        warn!(
                            %request_id,
                            error = %e,
                            "rc:agent.key_rotate failed — identity unchanged"
                        );
                        report_key_rotated(
                            outbound_tx,
                            &request_id,
                            KeyRotationOutcome::Failed,
                            old_public.as_deref(),
                            None,
                            agent_cfg.overlay_wg_key_epoch,
                            Some(&e),
                        );
                        return Ok(());
                    }
                };
                info!(
                    org = %ctx.label,
                    %request_id,
                    old_public_key = old_public.as_deref().unwrap_or("-"),
                    new_public_key = %new_public,
                    key_epoch,
                    "rc:agent.key_rotate — new overlay key persisted; reconnecting under it"
                );
                // P1c — queue the same report for the NEXT session first
                // (the copy below rides a socket that is about to close).
                pending_rotation_reports()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        tenant_id.to_string(),
                        PendingRotationReport {
                            request_id: request_id.clone(),
                            old_public_key: old_public.clone(),
                            new_public_key: new_public.clone(),
                            key_epoch,
                        },
                    );
                report_key_rotated(
                    outbound_tx,
                    &request_id,
                    KeyRotationOutcome::Rotated,
                    old_public.as_deref(),
                    Some(&new_public),
                    key_epoch,
                    None,
                );
                // Let the report leave on this session before it ends — the
                // pump drains the outbound queue concurrently. Even if it is
                // lost, the join under the new key is what the server verifies.
                tokio::time::sleep(Duration::from_millis(300)).await;
                // Same teardown as `Goodbye`: the `?`-propagated Err below
                // would otherwise skip it and leave peers to a 10–30 s
                // silence-detect instead of a clean close.
                close_all_peers(peers, indicator).await;
                close_all_tunnel_peers(tunnel_peers).await;
                close_all_tunnel_quic_peers(tunnel_quic_peers).await;
                pending_codecs.clear();
                pending_transports.clear();
                pending_chroma.clear();
                pending_chunk_framing.clear();
                pending_audio.clear();
                pending_permissions.clear();
                return Err(ConnectError::KeyRotated {
                    secret_base64: new_secret,
                    key_epoch,
                });
            }
        }

        // Multi-org — "Add to another organization" from the admin UI: enroll
        // this machine into a SECOND org on the same server, from a pushed
        // single-use token, and bring that org's loop up without a restart.
        ServerMsg::JoinOrg {
            enrollment_token,
            label,
            overlay_mode,
        } => {
            // Same escalation guard as `rc:agent.update`: only the PRIMARY
            // enrollment may add orgs. A secondary org's admin borrows this
            // device — it must not be able to hand it to further orgs.
            if !ctx.is_primary {
                warn!(
                    org = %ctx.label,
                    "rc:agent.join_org ignored — only the primary enrollment may \
                     add organizations"
                );
                return Ok(());
            }
            // Off-loop: the join makes an HTTP round-trip and takes the
            // config write lock. The message loop must keep pumping (a
            // blocked loop trips the watchdog + the receive-liveness
            // deadline).
            let cfg = agent_cfg.clone();
            tokio::spawn(async move {
                match crate::org_join::join_from_push(
                    &cfg,
                    &enrollment_token,
                    label.as_deref(),
                    overlay_mode.as_deref(),
                )
                .await
                {
                    Ok(outcome) => info!(?outcome, "rc:agent.join_org applied"),
                    Err(e) => {
                        warn!(error = %format!("{e:#}"), "rc:agent.join_org failed")
                    }
                }
            });
        }

        // FR-90 P3-4a — the vault's answers to this daemon's lease requests,
        // and its revocations. Leases are the primary enrollment's only: a
        // secondary org's connection never asks, so what arrives there is
        // dropped unopened. Never logged with the frame: `sealed` is a value,
        // if a sealed one.
        ServerMsg::VaultLeased {
            req_id,
            lease_id,
            n,
            sealed,
            expires_at_ms,
            provider,
        } => {
            #[cfg(feature = "vault")]
            if ctx.is_primary {
                // P3-6b — with a dynamic secret's provider, if it names one.
                crate::vault::on_leased(
                    &req_id,
                    &lease_id,
                    n,
                    &sealed,
                    expires_at_ms,
                    provider.as_deref(),
                );
            } else {
                debug!(%lease_id, "rc:vault.leased on a secondary org's connection — dropped unopened");
            }
            #[cfg(not(feature = "vault"))]
            {
                let _ = (req_id, n, sealed, expires_at_ms, provider);
                debug!(%lease_id, "rc:vault.leased ignored — this build takes no leases");
            }
        }
        ServerMsg::VaultRefused {
            req_id,
            reason,
            approval_id,
        } => {
            #[cfg(feature = "vault")]
            if ctx.is_primary {
                crate::vault::on_refused(&req_id, &reason, approval_id.as_deref());
            }
            #[cfg(not(feature = "vault"))]
            let _ = (req_id, reason, approval_id);
        }
        // FR-90 P3-4b — a session's listing and description: metadata.
        ServerMsg::VaultListed {
            req_id,
            secrets,
            more,
        } => {
            #[cfg(feature = "vault")]
            if ctx.is_primary {
                crate::vault::on_listed(&req_id, secrets, more);
            }
            #[cfg(not(feature = "vault"))]
            let _ = (req_id, secrets, more);
        }
        ServerMsg::VaultDescribed { req_id, secret } => {
            #[cfg(feature = "vault")]
            if ctx.is_primary {
                crate::vault::on_described(&req_id, secret);
            }
            #[cfg(not(feature = "vault"))]
            let _ = (req_id, secret);
        }
        ServerMsg::VaultRevoke { lease_ids, reason } => {
            #[cfg(feature = "vault")]
            if ctx.is_primary {
                crate::vault::on_revoke(&lease_ids, &reason);
            }
            #[cfg(not(feature = "vault"))]
            let _ = (lease_ids, reason);
        }
        // FR-90 P3-7-3a — the vault's grant of a session's own egress, the
        // answer to this daemon's `rc:vault.net`: the primary's only, as a
        // lease is. Never logged with the frame (nor by the catch-all below,
        // which would): `grant` is a credential until its end.
        ServerMsg::VaultNetGranted {
            req_id,
            grant_id,
            grant,
            expires_at_ms,
            host,
            port,
        } => {
            #[cfg(feature = "vault")]
            if ctx.is_primary {
                crate::vault::on_net_granted(
                    &req_id,
                    &grant_id,
                    &grant,
                    expires_at_ms,
                    &host,
                    port,
                );
            } else {
                debug!(%grant_id, "rc:vault.net.granted on a secondary org's connection — dropped");
            }
            #[cfg(not(feature = "vault"))]
            {
                let _ = (req_id, grant, expires_at_ms, host, port);
                debug!(%grant_id, "rc:vault.net.granted ignored — this build asks for none");
            }
        }
        // FR-90 P3-8-2b — the vault's ticket for a session's command on
        // another device, the answer to this daemon's `rc:vault.ssh`: the
        // primary's only, as a lease is. Never logged with the frame (nor by
        // the catch-all below, which would): `ticket` is a credential until
        // its end.
        ServerMsg::VaultSshGranted {
            req_id,
            ticket_id,
            ticket,
            expires_at_ms,
            os,
            account,
        } => {
            #[cfg(feature = "vault")]
            if ctx.is_primary {
                crate::vault::on_ssh_granted(
                    &req_id,
                    &ticket_id,
                    &ticket,
                    expires_at_ms,
                    &os,
                    &account,
                );
            } else {
                debug!(%ticket_id, "rc:vault.ssh.granted on a secondary org's connection — dropped");
            }
            #[cfg(not(feature = "vault"))]
            {
                let _ = (req_id, ticket, expires_at_ms, os, account);
                debug!(%ticket_id, "rc:vault.ssh.granted ignored — this build asks for none");
            }
        }
        // FR-52 P3c — an outsider's login, relayed by the server. Answered in
        // a task, not inline: the live config read waits on the config lock,
        // which `rc password set` holds across an Argon2 derivation, and the
        // control loop must not stall behind it. Answered in EVERY build —
        // this one included when it has no credential stack — because every
        // build advertises `external-access` and a silent device would make
        // the server wait out its bound.
        ServerMsg::ExtauthKe1 {
            attempt_id,
            principal,
            ke1,
        } => {
            let (is_primary, remote_cfg, tx) =
                (ctx.is_primary, remote_cfg.clone(), outbound_tx.clone());
            tokio::spawn(async move {
                let reply =
                    crate::extauth::on_ke1(is_primary, &remote_cfg, attempt_id, principal, &ke1)
                        .await;
                let _ = tx.send(reply).await;
            });
        }
        ServerMsg::ExtauthKe3 {
            attempt_id,
            principal,
            ke3,
        } => {
            let (is_primary, remote_cfg, tx) =
                (ctx.is_primary, remote_cfg.clone(), outbound_tx.clone());
            tokio::spawn(async move {
                let reply =
                    crate::extauth::on_ke3(is_primary, &remote_cfg, attempt_id, principal, &ke3)
                        .await;
                let _ = tx.send(reply).await;
            });
        }

        // Remaining tunnel-flow `ServerMsg` variants
        // (TunnelOpened / TcpForwardAccept / TcpForwardReject /
        // TcpHalfClose / TcpClosed / TunnelRevoked) target the
        // browser-side tunnel-client, not the agent. Catch-all +
        // debug log so a misrouted message is visible but doesn't
        // trip a "non-exhaustive match" build error if the variants
        // change shape later.
        //
        // `#[allow(unreachable_patterns)]` because in a checkout where
        // the tunnel `ServerMsg` variants haven't landed yet (e.g.
        // master before the T2 wire types merge), the explicit arms
        // above already cover every variant and clippy flags this
        // arm as dead. The allow makes the same source compile both
        // before and after the variants land. See CLAUDE.md
        // "Defensive enum catch-alls" rule.
        #[allow(unreachable_patterns)]
        other => {
            debug!(
                ?other,
                "tunnel-side ServerMsg routed to agent signaling — ignoring"
            );
        }
    }
    Ok(())
}

async fn close_all_peers(
    peers: &mut HashMap<bson::oid::ObjectId, AgentPeer>,
    indicator: &ViewerIndicator,
) {
    // rc.24 — also hide the viewer-indicator overlay for every
    // session being torn down. Previously the indicator only
    // hid on receipt of `rc:terminate`, which never fires when
    // the WS itself drops (e.g. server pod recreate, network
    // blip). Field repro 2026-05-13 on the field-test host: after a roomler.ai
    // web deploy, the red "Being viewed by gjovanov" frame stayed
    // painted on the host indefinitely + the operator couldn't
    // reconnect ("agent capacity exceeded") until the agent
    // service was restarted manually. By hiding the overlay here
    // the next session can reconnect with a clean slate.
    if peers.is_empty() {
        return;
    }
    let count = peers.len();
    for (session_id, peer) in peers.drain() {
        // FR-85 P3b-3 — the session is over whether or not its close
        // finishes (see the `Terminate` arm).
        #[cfg(feature = "recording")]
        crate::recording::remote::session_ended(session_id);
        indicator.hide_session(session_id.to_hex());
        // Bounded ([`PEER_CLOSE_BUDGET`]): `pc.close()` hangs on webrtc
        // internals when the network was captured mid-session — the
        // stalled=signaling suicide class. Dropping `peer` right after
        // runs the P6 Drop teardown either way.
        close_within_budget(peer.close(), session_id, "ws_disconnect").await;
    }
    info!(
        count,
        "torn down peers + hid indicator overlays on ws disconnect"
    );
}

/// #2551 — the `t` tag of a server message, read from its raw JSON without
/// building the message a second time: the stage a `ws.text` arm is refined
/// to, so a stall in the dispatch names the message it was handling.
fn server_msg_tag(text: &str) -> Option<&str> {
    #[derive(serde::Deserialize)]
    struct Tag<'a> {
        #[serde(borrow)]
        t: &'a str,
    }
    serde_json::from_str::<Tag<'_>>(text).ok().map(|tag| tag.t)
}

/// T2.10d: tear down every tunnel peer on WS disconnect. Cheap
/// no-op when the map is empty (normal for agents that never serve
/// a tunnel).
async fn close_all_tunnel_peers(
    tunnel_peers: &mut HashMap<bson::oid::ObjectId, Arc<crate::tunnel::peer::AgentTunnelPeer>>,
) {
    if tunnel_peers.is_empty() {
        return;
    }
    let count = tunnel_peers.len();
    for (session_id, peer) in tunnel_peers.drain() {
        // Same bound as `close_all_peers` — a webrtc close on a captured
        // network must not stall the signaling loop into the watchdog.
        close_within_budget(peer.close(), session_id, "tunnel_ws_disconnect").await;
    }
    info!(count, "torn down agent tunnel peers on ws disconnect");
}

/// #1754 — what the reap arm took out of the session maps for a session
/// whose client is gone.
enum ReapedTunnelPeer {
    WebRtc(Arc<crate::tunnel::peer::AgentTunnelPeer>),
    Quic(Arc<crate::tunnel::quic_peer::AgentQuicPeer>),
}

impl ReapedTunnelPeer {
    fn transport(&self) -> &'static str {
        match self {
            ReapedTunnelPeer::WebRtc(_) => "webrtc-dc",
            ReapedTunnelPeer::Quic(_) => "quic",
        }
    }
}

/// #1754 — the reap arm's decision, kept pure so it can be locked by a test:
/// remove `session_id` from BOTH maps and hand back what was held, or `None`
/// when neither held it — in which case the arm does nothing at all, and in
/// particular sends no `rc:tunnel.terminate`. A session lives on one data
/// plane, but both maps are cleared regardless so a stale entry can never
/// survive its twin. Removing (not reading) is what makes a second report
/// for the same session — a peer's own close fires the same handlers — a
/// no-op rather than a second close and a second terminate.
fn take_reaped_tunnel_peer(
    session_id: bson::oid::ObjectId,
    tunnel_peers: &mut HashMap<bson::oid::ObjectId, Arc<crate::tunnel::peer::AgentTunnelPeer>>,
    tunnel_quic_peers: &mut TunnelQuicPeers,
) -> Option<ReapedTunnelPeer> {
    let webrtc = tunnel_peers.remove(&session_id);
    let quic = tunnel_quic_peers.remove(&session_id);
    match (webrtc, quic) {
        (Some(peer), _) => Some(ReapedTunnelPeer::WebRtc(peer)),
        (None, Some(peer)) => Some(ReapedTunnelPeer::Quic(peer)),
        (None, None) => None,
    }
}

/// Phase 1d (quic-v1): tear down every QUIC tunnel peer on WS
/// disconnect. `AgentQuicPeer::close` is synchronous (aborts the
/// accept task; the quinn endpoint drops with the last `Arc`), so
/// unlike [`close_all_tunnel_peers`] there's no per-peer `.await`.
/// Cheap no-op when the map is empty (normal for non-QUIC agents).
async fn close_all_tunnel_quic_peers(tunnel_quic_peers: &mut TunnelQuicPeers) {
    if tunnel_quic_peers.is_empty() {
        return;
    }
    let count = tunnel_quic_peers.len();
    for (_, peer) in tunnel_quic_peers.drain() {
        peer.close();
    }
    info!(count, "torn down agent QUIC tunnel peers on ws disconnect");
}

/// R3 — per-tenant stash of QUIC tunnel peers that SURVIVE a transient
/// control-WS reattach. QUIC flows self-signal over their own streams (no
/// welded control-WS sender — see `tunnel_core::forward::run_flow_quic`), so
/// an established QUIC/derp data plane keeps flowing while the control WS
/// re-establishes; the server-side grace (`ROOMLER__RC__TUNNEL_GRACE_SECS`)
/// keeps the session from being terminated meanwhile. Gated on
/// `tunnel_peers_survive_reattach` (default off ⇒ pre-R3 byte-identical).
/// Size-capped so a long agent outage (client re-opened elsewhere ⇒ orphaned
/// peers) can't leak sockets without bound; a dropped peer self-closes via
/// its #602 Drop.
/// A control-WS session's live QUIC tunnel peers, keyed by tunnel session id.
type TunnelQuicPeers = HashMap<bson::oid::ObjectId, Arc<crate::tunnel::quic_peer::AgentQuicPeer>>;

static TUNNEL_QUIC_SURVIVAL: std::sync::LazyLock<
    std::sync::Mutex<std::collections::BTreeMap<String, TunnelQuicPeers>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));

/// Max surviving QUIC sessions stashed per tenant (orphan-leak bound).
const TUNNEL_QUIC_SURVIVAL_CAP: usize = 32;

/// The R3 agent gate (`ROOMLERD_TUNNEL_PEERS_SURVIVE_REATTACH`, default
/// off). Read per exit so a live `roomler config set` + restart flips it.
fn tunnel_peers_survive_enabled() -> bool {
    tunnel_core::env::flag("TUNNEL_PEERS_SURVIVE_REATTACH", false)
}

/// Reclaim the tenant's stashed QUIC peers at the start of a control-WS
/// session. Empty when the flag is off — pre-R3 behaviour byte-identical.
fn reclaim_survived_quic_peers(tenant: &str) -> TunnelQuicPeers {
    if !tunnel_peers_survive_enabled() {
        return HashMap::new();
    }
    let mut map = TUNNEL_QUIC_SURVIVAL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(tenant)
        .unwrap_or_default();
    drop_parked_quic_corpses(&mut map);
    if !map.is_empty() {
        info!(
            count = map.len(),
            "R3: reclaimed surviving QUIC tunnel peers across control-WS reattach"
        );
    }
    map
}

/// #1754 — drop from a reclaimed R3 stash every peer whose one connection
/// already ended while it was parked (the client gave up during the
/// outage). Such a peer is a corpse: re-adopted into the new session's map,
/// its endpoint socket and, on the relayed flavours, its TURN allocation
/// would live until a terminate that a client already gone never sends.
/// Its own report on the reap channel is answered by an empty map. Returns
/// how many were dropped.
fn drop_parked_quic_corpses(map: &mut TunnelQuicPeers) -> usize {
    let before = map.len();
    map.retain(|sid, peer| {
        if peer.accept_ended() {
            info!(session_id = %sid, "R3: dropping a parked QUIC tunnel peer whose client left during the reattach (#1754)");
            peer.close();
            false
        } else {
            true
        }
    });
    before - map.len()
}

/// On a TRANSIENT control-WS exit (RX deadline, resume-skew, netstate probe,
/// pong-RTT, read/write/pong error): STASH the QUIC peers so they survive to
/// the next session (flag on), or close them as today (flag off). TERMINAL
/// exits — shutdown and `Goodbye` — call [`close_all_tunnel_quic_peers`]
/// directly instead (a re-registration or a delete must not keep peers).
async fn park_survived_quic_peers(tunnel_quic_peers: &mut TunnelQuicPeers, tenant: &str) {
    if !tunnel_peers_survive_enabled() {
        close_all_tunnel_quic_peers(tunnel_quic_peers).await;
        return;
    }
    if tunnel_quic_peers.is_empty() {
        return;
    }
    let count = tunnel_quic_peers.len();
    let mut stash = TUNNEL_QUIC_SURVIVAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let slot = stash.entry(tenant.to_string()).or_default();
    for (sid, peer) in tunnel_quic_peers.drain() {
        slot.insert(sid, peer);
    }
    while slot.len() > TUNNEL_QUIC_SURVIVAL_CAP {
        let Some(k) = slot.keys().next().cloned() else {
            break;
        };
        slot.remove(&k); // dropped peer self-closes (#602 Drop)
    }
    let stashed = slot.len();
    drop(stash);
    info!(
        count,
        stashed, "R3: parked QUIC tunnel peers to survive the control-WS reattach"
    );
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Single choke point for every frame written to the control WS, bounded
/// by `WS_SEND_TIMEOUT` (see its doc for the field failure this exists
/// for). A timeout is reported as an ordinary send error so every caller
/// takes its existing failed-send path — which for all of them means
/// cycling the connection. Cancelling a tungstenite send mid-flush is
/// safe here because no caller reuses the stream after an error.
async fn send_frame(ws: &mut Ws, frame: Message) -> Result<()> {
    match tokio::time::timeout(WS_SEND_TIMEOUT, ws.send(frame)).await {
        Ok(res) => res.context("ws send"),
        Err(_elapsed) => Err(anyhow::anyhow!(
            "ws send wedged for {} s (route captured mid-flight?) — cycling the connection",
            WS_SEND_TIMEOUT.as_secs()
        )),
    }
}

/// The next rc message the daemon delegated to us, or never if this process is
/// not a supervised worker.
///
/// `pending()` rather than an `Option` arm with a guard: a `select!` branch
/// that is simply never ready is the honest encoding of "this process is not a
/// worker", and it keeps the arm's body identical in both cases.
async fn next_delegated(
    rx: &mut Option<&mut mpsc::Receiver<crate::delegate::WorkerInbound>>,
) -> Option<crate::delegate::WorkerInbound> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Send one reply for a session, to wherever that session's replies go.
///
/// The WS path keeps its DIRECT write. That is not incidental: the outbound
/// queue is drained by an arm of the same `select!` that calls
/// `handle_server_msg`, so while that function runs — holding `&mut ws` — no
/// queued message can be written, and the SDP answer has therefore always
/// preceded the peer's first ICE candidate. A queued answer would lose that.
///
/// A DELEGATED session has one ordered queue for everything, so the answer may
/// follow the first candidates. Safe, and verified rather than assumed: the
/// controller buffers early ICE in `pendingRemoteIce` (`useRemoteControl.ts`)
/// exactly because `addIceCandidate` throws before `setRemoteDescription`, and
/// flushes it when the answer lands.
/// One `rc:session.stats` for `session_id`.
fn session_stats_msg(
    session_id: bson::oid::ObjectId,
    t: &crate::peer::SessionTelemetry,
    transfers: roomler_ai_remote_control::signaling::Transfers,
) -> ClientMsg {
    ClientMsg::SessionStats {
        session_id: session_id.to_hex(),
        bytes_sent: t.bytes_sent,
        bytes_recv: t.bytes_recv,
        fps: t.fps,
        rtt_ms: t.rtt_ms,
        keyframe_requests: t.keyframe_requests,
        input_events: t.input_events,
        shared_seconds: t.shared_seconds,
        mixed_dial_seconds: t.mixed_dial_seconds,
        transfers,
        // FR-102 P9c — absent until the carrier was observed, so an older
        // server never sees the key and a sample before `Connected` carries
        // nothing to misread.
        carrier: t.carrier.map(|c| c.as_str().to_string()),
    }
}

/// Queue ONE `rc:session.stats` for a live session on THE PEER'S OWN SENDER —
/// the FR-43 P2b-2 seam every message about a session leaves through — with
/// the sample Wave 2 built inline. Shared by the 30 s heartbeat tick and the
/// FR-102 P9d carrier-ready trigger so the two cannot drift.
///
/// Why the peer's sender and not this connection's WS: on a supervised Mac
/// (FR-43) the GUI worker that holds a delegated session's peer is its OWN
/// enrollment with its own WS, while the session row carries the DAEMON's
/// `agent_id`. A sample written up the worker's WS matches nothing in
/// `merge_live_stats` (`{_id, agent_id: <the socket's>, ended_at: null}`) and
/// is dropped without a word — with the file notes it carried. The peer's
/// sender is the loop's `outbound_tx` for an own session (the `outbound_rx`
/// arm writes it to the WS one hop later) and the delegation channel for a
/// delegated one (`delegable_outbound` passes `SessionStats`; the daemon
/// relays it under its own identity). The worker also serves its OWN sessions
/// under its own row, which is why this is decided per peer, never
/// connection-wide.
///
/// - Real telemetry within [`SESSION_STATS_BUDGET`]. ⚠️ Never a zeros sample:
///   `merge_live_stats` `$set`s every counter, so a sample of zeros would
///   overwrite the server's live totals (the hazard [`final_session_stats`]'s
///   doc spells out). A telemetry timeout therefore SKIPS this peer — it takes
///   nothing and sends nothing.
/// - FR-101 P3 — the session's clipboard and file traffic ride along; the file
///   notes are TAKEN, so a sample that could not be queued hands them back
///   with [`crate::session_telemetry::SessionCounters::restore_file_notes`].
/// - FR-102 P9c — the recorded carrier rides it, once observed.
///
/// ⚠️ `try_send`, never `.send().await`: the loop that calls this is the loop
/// that drains `outbound_rx`, so awaiting a full queue would wait on itself. A
/// `Full` or `Closed` queue sends nothing this round — logged, the notes
/// restored, and the next tick retries. Best-effort either way: telemetry must
/// never tear down a working session, and the heartbeat frame is what proves
/// liveness. Returns whether a sample was queued.
async fn send_one_session_stats(
    session_id: bson::oid::ObjectId,
    peer: &AgentPeer,
    pump: &'static str,
) -> bool {
    let t = match tokio::time::timeout(SESSION_STATS_BUDGET, peer.telemetry()).await {
        Ok(t) => t,
        Err(_elapsed) => {
            warn!(
                %session_id,
                "session telemetry timed out — skipping its stats this round \
                 (wedged ICE after a network transition?)"
            );
            watchdog::tick(pump);
            return false;
        }
    };
    let transfers = crate::session_telemetry::counters(session_id).take_transfers();
    let msg = session_stats_msg(session_id, &t, transfers);
    match peer.outbound().try_send(msg) {
        Ok(()) => true,
        Err(e) => {
            let why = match &e {
                mpsc::error::TrySendError::Full(_) => "queue full",
                mpsc::error::TrySendError::Closed(_) => "queue closed",
            };
            debug!(%session_id, why, "session stats not queued this round — the next tick retries");
            if let ClientMsg::SessionStats { transfers, .. } = e.into_inner() {
                crate::session_telemetry::counters(session_id).restore_file_notes(transfers.files);
            }
            false
        }
    }
}

/// FR-101 P3 — the last `rc:session.stats` of a session that is ending, so
/// the clipboard and file traffic since the previous 30 s sample still
/// reaches the audit. A session shorter than one sample would otherwise
/// report nothing at all.
///
/// Taken before the peer closes: its telemetry needs the live connection,
/// and its counters are forgotten when it drops. `None` when the session
/// moved nothing worth auditing, or when its telemetry did not answer within
/// [`SESSION_STATS_BUDGET`]: a sample of zeros could overwrite the live
/// totals of a session the server has not ended yet.
async fn final_session_stats(
    session_id: bson::oid::ObjectId,
    peer: &AgentPeer,
) -> Option<ClientMsg> {
    let transfers = crate::session_telemetry::counters(session_id).take_transfers();
    if transfers.is_empty() {
        return None;
    }
    match tokio::time::timeout(SESSION_STATS_BUDGET, peer.telemetry()).await {
        Ok(t) => Some(session_stats_msg(session_id, &t, transfers)),
        Err(_elapsed) => {
            warn!(
                %session_id,
                files = transfers.files.len(),
                "final session stats: telemetry timed out — this session's last transfers go unreported"
            );
            None
        }
    }
}

async fn reply_for_session(
    ws: &mut Ws,
    delegated: Option<&mpsc::Sender<ClientMsg>>,
    msg: &ClientMsg,
) -> Result<()> {
    match delegated {
        Some(tx) => tx
            .send(msg.clone())
            .await
            .map_err(|_| anyhow::anyhow!("delegation queue closed")),
        None => send_msg(ws, msg).await,
    }
}

async fn send_msg(ws: &mut Ws, msg: &ClientMsg) -> Result<()> {
    let json = serde_json::to_string(msg).context("serialising ClientMsg")?;
    send_frame(ws, Message::text(json)).await
}

/// Keepalive ping payload: `ws_epoch`-relative send time in millis, 8 bytes
/// BE. RFC 6455 §5.5.3 makes the peer echo it verbatim in the pong, turning
/// every keepalive into an application-level RTT probe for free.
fn ping_payload(epoch: std::time::Instant) -> Vec<u8> {
    (epoch.elapsed().as_millis() as u64).to_be_bytes().to_vec()
}

/// Decode a pong payload stamped by [`ping_payload`] into the measured
/// round trip. `None` for foreign shapes (an unsolicited server pong, or a
/// pre-upgrade peer that strips payloads) — those simply don't vote.
fn pong_rtt(payload: &[u8], epoch: std::time::Instant) -> Option<Duration> {
    let ms = u64::from_be_bytes(payload.try_into().ok()?);
    let now = epoch.elapsed().as_millis() as u64;
    Some(Duration::from_millis(now.saturating_sub(ms)))
}

/// The device's SSH host public key for the hello, or empty.
///
/// Two cfg'd items rather than one function with an inner `#[cfg]` expression:
/// the `ssh` module is gated on the OVERLAY features (no overlay ⇒ no address
/// to serve SSH on ⇒ the module does not exist), so the call itself has to
/// disappear, not just its result. `ssh.rs` then applies the SECOND gate —
/// `ssh-server` — on top.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn ssh_host_pubkey_for(cfg: &crate::config::AgentConfig) -> String {
    crate::ssh::host_public_key(cfg)
}

#[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
fn ssh_host_pubkey_for(_cfg: &crate::config::AgentConfig) -> String {
    String::new()
}

fn detect_os() -> OsKind {
    match std::env::consts::OS {
        "linux" => OsKind::Linux,
        "macos" => OsKind::Macos,
        "windows" => OsKind::Windows,
        _ => OsKind::Linux,
    }
}

fn stub_displays() -> Vec<DisplayInfo> {
    // Real enumeration via `crate::displays::enumerate` (scrap-backed on
    // Windows / Linux / macOS). Falls back to a single 1920×1080 entry
    // on builds without `scrap-capture` or hosts where enumeration
    // fails. Kept named `stub_displays` for continuity with the
    // pre-0.1.31 call site; can be renamed once the rest of the
    // hello-preamble stubs are audited.
    crate::displays::enumerate()
}

fn stub_caps(multi_org_tun: bool, is_primary: bool) -> AgentCaps {
    // Real probe via encode::caps; replaces the empty-vec stub. The
    // resulting AgentCaps populates the rc:agent.hello payload, which
    // the server persists into the agents collection and surfaces in
    // the admin UI (2A.2).
    let mut caps = crate::encode::caps::detect();
    // FR-67 P7 — whether this enrollment acts on a pushed `rc:agent.update`
    // (`self`), ignores it (`primary_org`, a secondary enrollment) or drops it
    // (`off`, auto-update off), so the server refuses the push, and says why,
    // rather than counting a frame the `UpdateNow` arm will not act on as an
    // update delivered. Stamped HERE, at every announcement: a heartbeat's
    // re-announce REPLACES the stored caps, so a hello-only word would be gone
    // at the first login.
    caps.update_mode = Some(crate::updater::update_mode(is_primary).to_string());
    // `detect()` is memoized and config-blind, so the one capability that
    // depends on the host's config gets appended here: `tun` says "this
    // daemon's TUN is already muxed — a second org can join the mesh
    // live". The flag is read from the config the PROCESS started with
    // (the reconnect loop lives inside `run`, which owns `cfg`), which is
    // precisely the honest answer: flipping `overlay_multi_org` at runtime
    // does not mux a TUN the primary loop already opened un-muxed, so the
    // server keeps being told "no" until a real daemon restart. That's
    // what lets `join-org` answer `restart_required` instead of promising
    // a mesh that would fail its bring-up (field 2026-08-07, WINHOST-A).
    if multi_org_tun {
        caps.multi_org.push("tun".into());
    }
    caps.record = record_caps();
    // FR-92 — `keep-busy` follows the owner's LIVE `keep_busy_enabled`, so,
    // like the record words, it is appended at every announcement and never
    // inside the memoized, config-blind `detect()`.
    if crate::keep_busy::advertised() {
        caps.input.push("keep-busy".into());
    }
    // FR-109 — `mouse-rel` where this build's injector carries relative
    // motion and `ROOMLERD_INPUT_MOUSE_REL` has not switched it off. A viewer
    // sends `mouse_rel` only to an agent that says so: an older one cannot
    // parse it.
    if crate::input::advertises_mouse_rel() {
        caps.input.push("mouse-rel".into());
    }
    // FR-97 P4a — the real Ctrl+Alt+Del where this process may send it: it
    // runs as SYSTEM (the SystemContext worker) and the policy lets services.
    // Live like the words above, and the heartbeat compares it
    // (`sas_advertised`), so a GPO refresh that changes the policy is news
    // within a beat. Elsewhere the button keeps typing keys, and the reason
    // says which half is missing.
    #[cfg(target_os = "windows")]
    match crate::input::sas::availability() {
        Ok(()) => {
            caps.input.push("sas".into());
            caps.unavailable.remove("sas");
        }
        Err(refusal) => {
            if let Some(entry) = caps.unavailable.get_mut("sas") {
                entry.reason = refusal.reason().into();
            }
        }
    }
    // FR-93 P2b — the desktop a controller would see now, read from the
    // refresher's cache (never logind on this path). Live, like the words
    // above: the heartbeat re-announces when it changes.
    caps.desktop = crate::desktop_brief::current();
    // FR-99 P1b — `privacy-available` where a curtain is possible here, and
    // `privacy-mode` only while the owner allows it too. Live like the record
    // words: the owner's switch moves the second, and the overlay coming up
    // after `detect()` ran moves both. The heartbeat re-announces a change.
    caps.rpc.extend(
        crate::privacy::current_words()
            .into_iter()
            .map(|w| w.wire().to_string()),
    );
    // FR-101 P2b — this build enforces the session policy (it masks every
    // grant by the org's policy and its owner's floor, and its prompt names
    // what it asks about), so the hub may keep an `ask` feature for it. And
    // the floor itself, when it restricts anything, so the hub can say why it
    // strips what this device will refuse. Live: the heartbeat re-announces it.
    caps.rpc.push(RpcCap::SessionPolicy.wire().to_string());
    caps.session_policy = crate::session_policy::caps_policy();
    // FR-101 P4b-2 — and it keeps an idle limit (`session_idle`), so the hub
    // may tell the viewer the limit this session runs under.
    caps.rpc.push(RpcCap::IdleTimeout.wire().to_string());
    // FR-99 P3b — and it takes the device policy's lock ask into the lock at
    // a session's end, where the lock can also be lifted remotely afterwards
    // (the Windows service, the Linux root daemon; never a per-user install).
    if crate::lock_on_end::can_honour_ask() {
        caps.rpc.push(RpcCap::LockOnEnd.wire().to_string());
    }
    caps
}

/// FR-97 P4a — whether this process may send the real Ctrl+Alt+Del now, the
/// `sas` word `stub_caps` puts in the hello. The heartbeat compares it, so a
/// changed policy is news within a beat.
fn relay_server_ready() -> bool {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        crate::relay_server::listening_port().is_some()
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        false
    }
}

/// A bounded watch subscription, disabled permanently if its publisher exits.
async fn relay_listener_changed(rx: &mut Option<watch::Receiver<Option<u16>>>) -> bool {
    match rx.as_mut() {
        Some(receiver) => match receiver.changed().await {
            Ok(()) => true,
            Err(_) => {
                *rx = None;
                false
            }
        },
        None => std::future::pending().await,
    }
}

fn sas_advertised() -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::input::sas::availability().is_ok()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// FR-99 P1b — the `privacy-*` words in an `rpc` list, in order: what the
/// heartbeat compares to decide whether the owner's switch is news.
fn privacy_words_in(rpc: &[String]) -> Vec<String> {
    rpc.iter()
        .filter(|w| *w == RpcCap::PrivacyMode.wire() || *w == RpcCap::PrivacyAvailable.wire())
        .cloned()
        .collect()
}

/// FR-90 P2c-3 — take the replica words out of a secondary org's caps: a
/// device holds copies for its primary organization only, so another org's
/// placement must never see it offer them. Equality, never a prefix: `hive`
/// is a prefix of each, and stays. P2d: nor does it carry another org's
/// streams (`hive-stream`). P2i-1: nor does it answer a search over them
/// (`hive-search`).
fn strip_replica_verbs(rpc: &mut Vec<String>) {
    rpc.retain(|v| {
        v != RpcCap::HiveReplica.wire()
            && v != RpcCap::HiveArchive.wire()
            && v != RpcCap::HiveStream.wire()
            && v != RpcCap::HiveSearch.wire()
    });
}

/// FR-85 P3b — `AgentCaps.record` as it stands NOW: the owner's live gate
/// and whether a recorder can run here. Config-dependent and live, so it is
/// filled at every announcement (the hello, a heartbeat that re-announces),
/// never inside the memoized `detect()`.
fn record_caps() -> Vec<String> {
    #[cfg(feature = "recording")]
    {
        crate::recording::remote::advertised()
    }
    #[cfg(not(feature = "recording"))]
    {
        Vec::new()
    }
}

pub(crate) fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2551 — a `ws.text` stage is refined to the message's wire tag, read
    /// straight from the JSON. Anything without a plain `t` gives `None`, and
    /// the arm then names `?` rather than failing.
    #[test]
    fn a_server_message_tag_is_read_from_its_json() {
        assert_eq!(
            server_msg_tag(r#"{"t":"rc:ssh.response","request_id":"x","port":2222}"#),
            Some("rc:ssh.response")
        );
        assert_eq!(
            server_msg_tag(r#"{"port":2222,"t":"rc:goodbye"}"#),
            Some("rc:goodbye")
        );
        assert_eq!(server_msg_tag(r#"{"request_id":"x"}"#), None);
        assert_eq!(server_msg_tag("not json"), None);
        // Every real tag parses: one the dispatch handles, serialised here.
        let msg = ServerMsg::Goodbye {
            reason: AgentCloseReason::AgentDeleted,
            message: "x".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(server_msg_tag(&json), Some("rc:goodbye"));
    }

    /// #2221 — a dropped session that lived restarts the reconnect ladder. A
    /// quick drop, or a failure inside an outage, keeps climbing it.
    #[test]
    fn a_session_that_lived_restarts_the_ladder() {
        let climbed = Duration::from_secs(8);
        assert_eq!(
            ladder_after_drop(climbed, true, LADDER_PROVEN_AFTER),
            Duration::from_secs(1),
            "a session past the bar starts its outage at 1 s"
        );
        assert_eq!(
            ladder_after_drop(
                climbed,
                true,
                LADDER_PROVEN_AFTER - Duration::from_millis(1)
            ),
            climbed,
            "a server that accepts and drops at once must not reset the ladder"
        );
        assert_eq!(
            ladder_after_drop(climbed, false, LADDER_PROVEN_AFTER + Duration::from_secs(1)),
            climbed,
            "an attempt that never sent its hello keeps climbing, however long it hung"
        );
    }

    /// FR-102 P9d — the sample `send_one_session_stats` builds (via the shared
    /// `session_stats_msg`, for both the 30 s tick and the carrier-ready
    /// trigger) carries REAL telemetry and the recorded carrier. ⚠️ Never a
    /// zeros sample: `merge_live_stats` `$set`s every counter, so a zeros
    /// sample would overwrite the server's live totals. This locks that the
    /// builder copies the telemetry through rather than defaulting it.
    #[test]
    fn a_session_stats_sample_carries_real_telemetry_and_the_carrier() {
        let sid = bson::oid::ObjectId::new();
        let t = crate::peer::SessionTelemetry {
            bytes_sent: 1_234,
            bytes_recv: 5_678,
            rtt_ms: 42.0,
            fps: 30.0,
            keyframe_requests: 3,
            input_events: 7,
            shared_seconds: 0,
            mixed_dial_seconds: 0,
            carrier: Some(crate::session_carrier::SessionCarrier::OverlayTurn),
        };
        match session_stats_msg(sid, &t, Default::default()) {
            ClientMsg::SessionStats {
                session_id,
                bytes_sent,
                bytes_recv,
                rtt_ms,
                keyframe_requests,
                input_events,
                carrier,
                ..
            } => {
                assert_eq!(session_id, sid.to_hex());
                assert_eq!(bytes_sent, 1_234);
                assert_eq!(bytes_recv, 5_678);
                assert_eq!(rtt_ms, 42.0);
                assert_eq!(keyframe_requests, 3);
                assert_eq!(input_events, 7);
                // The whole point of P9d: the carrier rides the early sample.
                assert_eq!(carrier.as_deref(), Some("overlay_turn"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-102 P9d — a carrier the observation could not name still rides the
    /// sample: `unknown` recorded beats absent (P9c's "never direct for an
    /// unknown tier"), and the trigger sends it regardless. A session that
    /// never recorded one carries `None`, which the server reads as unknown.
    #[test]
    fn an_unknown_carrier_rides_the_sample_but_none_is_absent() {
        let unknown = crate::peer::SessionTelemetry {
            carrier: Some(crate::session_carrier::SessionCarrier::Unknown),
            ..Default::default()
        };
        match session_stats_msg(bson::oid::ObjectId::new(), &unknown, Default::default()) {
            ClientMsg::SessionStats { carrier, .. } => {
                assert_eq!(carrier.as_deref(), Some("unknown"))
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let none = crate::peer::SessionTelemetry::default();
        match session_stats_msg(bson::oid::ObjectId::new(), &none, Default::default()) {
            ClientMsg::SessionStats { carrier, .. } => assert_eq!(carrier, None),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-102 P9d — a peer for `send_one_session_stats`: the production
    /// `AgentPeer`, built as `handle_server_msg` builds one, with `tx` as the
    /// sender it is constructed with (the FR-43 P2b-2 seam). Never offered
    /// anything, so it gathers no ICE and its telemetry answers at once.
    async fn peer_with_sender(
        session_id: bson::oid::ObjectId,
        tx: mpsc::Sender<ClientMsg>,
    ) -> AgentPeer {
        AgentPeer::new(
            session_id,
            &[],
            tx,
            crate::encode::EncoderPreference::Software,
            "h264".into(),
            "h264".into(),
            None,
            None,
            false,
            false,
            roomler_ai_remote_control::permissions::Permissions::VIEW,
            "p9d-unit".into(),
            None,
            crate::rc_overlay::RcOverlay::default(),
            crate::rc_sessions::RcSessionRegistry::new(),
            // The carrier-ready signal: nothing reads it here, the test calls
            // the helper the arm would call.
            mpsc::channel(1).0,
        )
        .await
        .expect("AgentPeer::new")
    }

    /// FR-102 P9d — a session's stats follow THE PEER'S OWN SENDER (the FR-43
    /// seam), not the loop's WS. Without a supervised Mac this is the only
    /// proof of the delegated road: a peer built with sender `A` — on a
    /// worker, the delegation channel to the daemon — puts its sample, the
    /// carrier riding it, on `A` and nowhere else. The helper is the real one
    /// both the 30 s tick and the carrier-ready arm call.
    #[tokio::test]
    async fn a_session_stats_sample_leaves_through_the_peers_own_sender() {
        let sid = bson::oid::ObjectId::new();
        let (a_tx, mut a_rx) = mpsc::channel::<ClientMsg>(8);
        let peer = peer_with_sender(sid, a_tx).await;
        peer.record_carrier_for_test(crate::session_carrier::SessionCarrier::OverlayTurn);

        let queued = send_one_session_stats(sid, &peer, "p9d-test").await;
        let first = a_rx.try_recv();
        let second = a_rx.try_recv();
        // A WebRTC peer frees nothing on drop: close it before any assertion
        // can panic.
        peer.close().await;

        assert!(queued, "the sample is queued on the peer's sender");
        match first.expect("one message on the peer's sender") {
            ClientMsg::SessionStats {
                session_id,
                carrier,
                ..
            } => {
                assert_eq!(session_id, sid.to_hex());
                assert_eq!(
                    carrier.as_deref(),
                    Some("overlay_turn"),
                    "the recorded carrier rides the sample"
                );
            }
            other => panic!("not a session stats sample: {other:?}"),
        }
        assert!(
            second.is_err(),
            "exactly one sample, nothing else: {second:?}"
        );
    }

    /// FR-102 P9d — `try_send`, never an await: a sender whose queue is full
    /// (the loop that calls this drains it, so awaiting would wait on itself)
    /// or closed queues nothing this round, hands the FR-101 P3 file notes
    /// back for the next tick, and panics on nothing.
    #[tokio::test]
    async fn a_full_or_closed_sender_restores_the_file_notes_and_sends_nothing() {
        use roomler_ai_remote_control::signaling::TransferDirection;
        let sid = bson::oid::ObjectId::new();
        // Capacity one: the first sample fills it.
        let (a_tx, mut a_rx) = mpsc::channel::<ClientMsg>(1);
        let peer = peer_with_sender(sid, a_tx).await;
        let filled = send_one_session_stats(sid, &peer, "p9d-test").await;

        // Full: the note the sample took comes back for the next tick.
        crate::session_telemetry::counters(sid).note_file(
            TransferDirection::ToHost,
            "report.pdf",
            1234,
        );
        let queued_full = send_one_session_stats(sid, &peer, "p9d-test").await;
        let after_full = crate::session_telemetry::counters(sid).take_transfers();
        let still_queued = a_rx.try_recv();

        // Closed: the receiver is gone.
        drop(a_rx);
        crate::session_telemetry::counters(sid).note_file(
            TransferDirection::FromHost,
            "salaries.xlsx",
            99,
        );
        let queued_closed = send_one_session_stats(sid, &peer, "p9d-test").await;
        let after_closed = crate::session_telemetry::counters(sid).take_transfers();
        peer.close().await;

        assert!(filled, "the first sample fills the one-slot queue");
        assert!(!queued_full, "a full queue takes no sample");
        assert_eq!(after_full.files.len(), 1, "the file note is handed back");
        assert_eq!(after_full.files[0].bytes, 1234);
        assert!(
            matches!(still_queued, Ok(ClientMsg::SessionStats { .. })),
            "the first sample is still the only thing queued: {still_queued:?}"
        );
        assert!(!queued_closed, "a closed queue takes no sample");
        assert_eq!(after_closed.files.len(), 1, "… and hands its note back too");
        assert_eq!(after_closed.files[0].bytes, 99);
    }

    /// #2221 — `note_ws_down` says whether a failure STARTED an outage: the
    /// first failure after a hello does, every later one in that outage does
    /// not.
    #[test]
    fn only_the_first_failure_after_a_hello_starts_an_outage() {
        let ctx = OrgCtx::primary(crate::token_slot::TokenSlot::new("t"));
        assert!(ctx.note_ws_down(), "the first failure starts an outage");
        assert!(!ctx.note_ws_down(), "the next one is inside it");
        ctx.note_ws_up_and_maybe_recheck_update();
        assert!(
            ctx.note_ws_down(),
            "after a hello, the next failure starts a new one"
        );
    }

    /// FR-90 P2c-3 — a secondary org's caps lose the replica words, by
    /// equality: `hive` and every other `hive-*` word stays. P2d: and
    /// `hive-stream`, so it carries no other org's streams. P2i-1: and
    /// `hive-search`, so it answers no other org's search.
    #[test]
    fn a_secondary_connection_never_offers_copies() {
        let mut rpc: Vec<String> = [
            "exec",
            "hive",
            "hive-replica",
            "hive-archive",
            "hive-stream",
            "hive-search",
            "hive-view",
            "hive-adopt",
        ]
        .map(String::from)
        .to_vec();
        strip_replica_verbs(&mut rpc);
        assert_eq!(rpc, ["exec", "hive", "hive-view", "hive-adopt"]);
    }

    /// FR-27 P10 — the host's Disconnect names itself on the wire. The
    /// viewer's "the person at the device ended the session" notice and the
    /// audit both key on this spelling; `agent_hangup` would read as the
    /// daemon giving the session up, which is a different story.
    #[test]
    fn a_host_disconnect_terminates_as_host_disconnect() {
        let sid = bson::oid::ObjectId::new();
        let msg = host_disconnect_terminate(sid);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""t":"rc:terminate""#), "{json}");
        assert!(json.contains(r#""reason":"host_disconnect""#), "{json}");
        match msg {
            ClientMsg::Terminate {
                session_id,
                reason,
                limit,
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(reason, EndReason::HostDisconnect);
                assert_eq!(limit, None, "a host disconnect is no limit");
            }
            other => panic!("wrong message: {other:?}"),
        }
    }

    /// FR-101 P4b-2 — the idle end on the wire: `idle_timeout`, the reason
    /// every server knows, naming `limit: "idle"`, which the hub honours from
    /// the agent. The host's Disconnect is untouched by it.
    #[test]
    fn an_idle_end_terminates_as_idle_timeout_naming_the_limit() {
        let sid = bson::oid::ObjectId::new();
        let json = serde_json::to_string(&DeviceEnd::Idle.terminate(sid)).unwrap();
        assert!(json.contains(r#""t":"rc:terminate""#), "{json}");
        assert!(json.contains(r#""reason":"idle_timeout""#), "{json}");
        assert!(json.contains(r#""limit":"idle""#), "{json}");
        let json = serde_json::to_string(&DeviceEnd::HostDisconnect.terminate(sid)).unwrap();
        assert!(json.contains(r#""reason":"host_disconnect""#), "{json}");
        assert!(!json.contains("limit"), "{json}");
        assert_eq!(DeviceEnd::Idle.label(), "idle_timeout");
        assert_eq!(DeviceEnd::HostDisconnect.label(), "host_disconnect");
    }

    /// FR-101 P4b-2 — either channel ends a session, each under its own
    /// reason: the overlay's Disconnect and an idle watcher's hand-back.
    #[tokio::test]
    async fn either_channel_ends_a_session() {
        let (kill_tx, mut kill_rx) = mpsc::channel(1);
        let (idle_tx, mut idle_rx) = mpsc::channel(1);
        let (a, b) = (bson::oid::ObjectId::new(), bson::oid::ObjectId::new());
        idle_tx.send(a).await.unwrap();
        assert_eq!(
            device_end(&mut kill_rx, &mut idle_rx).await,
            Some((a, DeviceEnd::Idle))
        );
        kill_tx.send(b).await.unwrap();
        assert_eq!(
            device_end(&mut kill_rx, &mut idle_rx).await,
            Some((b, DeviceEnd::HostDisconnect))
        );
    }

    /// The grace is a field knob with a kill switch (`0`), never longer than
    /// the close budget, and anything unparseable falls back to the default.
    /// Tested on the parser, not the environment: a test that sets a process
    /// variable races every other test in this binary (#1787).
    #[test]
    fn host_disconnect_grace_is_bounded_and_switchable() {
        assert_eq!(
            host_disconnect_grace_from(None),
            HOST_DISCONNECT_GRACE_DEFAULT
        );
        assert_eq!(host_disconnect_grace_from(Some("0")), Duration::ZERO);
        assert_eq!(
            host_disconnect_grace_from(Some(" 250 ")),
            Duration::from_millis(250)
        );
        assert_eq!(host_disconnect_grace_from(Some("99999")), PEER_CLOSE_BUDGET);
        assert_eq!(
            host_disconnect_grace_from(Some("soon")),
            HOST_DISCONNECT_GRACE_DEFAULT
        );
        assert_eq!(
            host_disconnect_grace_from(Some("")),
            HOST_DISCONNECT_GRACE_DEFAULT
        );
    }

    fn gone(label: &str, reason: AgentCloseReason) -> SecondaryGoodbye {
        SecondaryGoodbye {
            label: label.into(),
            reason,
            message: "agent has been deleted".into(),
        }
    }

    /// #1750 — what `roomler status` shows for a refused secondary org names
    /// every way out, with THAT org's label, and keeps the `server goodbye
    /// (<reason>)` prefix operators and docs already search for.
    #[test]
    fn a_secondary_goodbye_names_every_way_out() {
        let text = gone("demo", AgentCloseReason::AgentDeleted).to_string();
        for want in [
            "server goodbye (AgentDeleted): agent has been deleted",
            "roomlerd re-enroll --org demo --token <new-jwt>",
            "roomlerd org disable demo",
            "roomlerd org enable demo",
            "roomlerd org rm demo",
        ] {
            assert!(text.contains(want), "{want:?} missing from: {text}");
        }
    }

    /// The supervisors choose the log level by TYPE, which must survive
    /// `anyhow` and a `.context()` layer. The same words without the type — the
    /// pre-#1750 error, or any other text — must not pass for one: a fault
    /// quietly demoted to DEBUG is the one outcome worse than the noise.
    #[test]
    fn a_secondary_goodbye_is_recognised_by_type_not_text() {
        let e = anyhow::Error::from(gone("demo", AgentCloseReason::PolicyRejected));
        assert!(is_secondary_goodbye(&e));
        assert!(is_secondary_goodbye(&e.context("org loop")));

        let lookalike = anyhow::anyhow!("{}", gone("demo", AgentCloseReason::AgentDeleted));
        assert!(
            !is_secondary_goodbye(&lookalike),
            "text alone never classifies"
        );
        assert!(!is_secondary_goodbye(&anyhow::anyhow!(
            "duplicate-instance duel: displaced 3× in the window"
        )));
    }

    /// A QUIC tunnel peer on loopback, as the `TunnelQuicSetup` arm builds
    /// one, for the map helpers below.
    fn quic_peer_for(
        sid: bson::oid::ObjectId,
        reap_tx: &crate::tunnel::reap::ReapSender,
    ) -> Arc<crate::tunnel::quic_peer::AgentQuicPeer> {
        Arc::new(
            crate::tunnel::quic_peer::AgentQuicPeer::setup(
                sid,
                "tok".to_string(),
                "127.0.0.1:0".parse().unwrap(),
                reap_tx.clone(),
            )
            .expect("quic peer on loopback"),
        )
    }

    /// #1754 — the reap arm's decision. A report for a session no map holds
    /// is `None`, so the arm sends nothing; a held session comes back once
    /// and is gone from BOTH maps, so its own close's echo (the same
    /// handlers fire again) is `None` too.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reap_for_an_unknown_or_already_reaped_session_takes_nothing() {
        let mut tunnel_peers = HashMap::new();
        let mut quic_peers: TunnelQuicPeers = HashMap::new();
        let (reap_tx, _reap_rx) = mpsc::channel(8);

        let unknown = bson::oid::ObjectId::new();
        assert!(
            take_reaped_tunnel_peer(unknown, &mut tunnel_peers, &mut quic_peers).is_none(),
            "a session no map holds takes nothing"
        );

        let sid = bson::oid::ObjectId::new();
        quic_peers.insert(sid, quic_peer_for(sid, &reap_tx));
        let first = take_reaped_tunnel_peer(sid, &mut tunnel_peers, &mut quic_peers)
            .expect("the held session is taken");
        assert_eq!(first.transport(), "quic");
        assert!(
            tunnel_peers.is_empty() && quic_peers.is_empty(),
            "taken out of both maps"
        );
        assert!(
            take_reaped_tunnel_peer(sid, &mut tunnel_peers, &mut quic_peers).is_none(),
            "a second report for the same session is a no-op"
        );
        if let ReapedTunnelPeer::Quic(peer) = first {
            peer.close();
        }
    }

    /// #1754 — the R3 reclaim re-adopts only parked peers whose connection
    /// is still open; one whose accept task ended while parked is closed and
    /// dropped instead of living on until a terminate that never comes.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_reclaim_drops_a_parked_quic_peer_whose_connection_ended() {
        let (reap_tx, _reap_rx) = mpsc::channel(8);
        let live_sid = bson::oid::ObjectId::new();
        let dead_sid = bson::oid::ObjectId::new();
        let live = quic_peer_for(live_sid, &reap_tx);
        let dead = quic_peer_for(dead_sid, &reap_tx);
        // End the dead one's accept task the way a client's departure
        // does from the task's point of view: it is over.
        dead.close();
        for _ in 0..100 {
            if dead.accept_ended() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(dead.accept_ended(), "the aborted accept task has ended");
        assert!(!live.accept_ended(), "the live one has not");

        let mut map: TunnelQuicPeers = HashMap::from([(live_sid, live), (dead_sid, dead)]);
        assert_eq!(drop_parked_quic_corpses(&mut map), 1, "one corpse dropped");
        assert!(map.contains_key(&live_sid), "the live peer is re-adopted");
        assert!(!map.contains_key(&dead_sid), "the corpse is not");
        map[&live_sid].close();
    }

    /// #2416 — a prompt whose control socket closes before an answer is
    /// withdrawn. The waiting task gets `Cancelled` (nothing goes on the wire),
    /// and dropping the prompt clears the broker's entry and the companion's
    /// `.pending` marker. On 0.4.141 it stood, answerable, beside the redialled
    /// session's own question.
    #[tokio::test]
    async fn a_prompt_whose_socket_closes_is_withdrawn() {
        use crate::consent::{ConsentBroker, Decision, Mode};
        let dir = tempfile::tempdir().unwrap();
        let mode = Mode::Prompt {
            timeout: std::time::Duration::from_secs(300),
        };
        let broker = ConsentBroker::new(mode, dir.path().to_path_buf()).unwrap();
        let hex = "6ad3d602aabbccddeeff0011";
        let prompt = broker.request_with_mode(hex, mode);
        let marker = broker.write_pending(hex, "{}").unwrap();
        assert!(marker.exists());
        let (outbound, rx) = mpsc::channel::<ClientMsg>(1);
        drop(rx); // the connection's loop ended with it
        let decision = await_prompt_or_socket_end(prompt, &outbound, hex).await;
        assert_eq!(decision, Decision::Cancelled);
        assert_eq!(
            consent_reply(decision, true),
            None,
            "nothing goes on the wire"
        );
        assert!(!broker.cancel(hex), "the broker no longer holds the prompt");
        assert!(!marker.exists(), "the companion's marker is gone");
    }

    /// #2416 — while the socket lives the prompt's own answer stands, and an
    /// answer ready as the socket closes still wins.
    #[tokio::test]
    async fn a_prompt_on_a_live_socket_keeps_its_answer() {
        use crate::consent::Decision;
        let (live, _rx) = mpsc::channel::<ClientMsg>(1);
        assert_eq!(
            await_prompt_or_socket_end(async { Decision::Granted }, &live, "a").await,
            Decision::Granted
        );
        let (closed, rx) = mpsc::channel::<ClientMsg>(1);
        drop(rx);
        assert_eq!(
            await_prompt_or_socket_end(async { Decision::Denied }, &closed, "b").await,
            Decision::Denied
        );
    }

    /// #2416 — a socket that lives never withdraws a standing prompt.
    #[tokio::test(start_paused = true)]
    async fn a_live_socket_leaves_a_standing_prompt_alone() {
        let (live, _rx) = mpsc::channel::<ClientMsg>(1);
        let waited = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            await_prompt_or_socket_end(std::future::pending(), &live, "c"),
        )
        .await;
        assert!(waited.is_err(), "still standing after ten minutes");
    }

    /// #1632 — `Cancelled` is the ONE decision that puts nothing on the wire:
    /// the session was terminated while the prompt stood, so no verdict is
    /// owed. Every other decision still answers, and the FR-27 shape holds —
    /// a timeout is never a bare `granted:false` (that reads as "the user
    /// denied you"); it carries `timeout`, or `no_prompt_surface` when nobody
    /// could have been asked.
    #[test]
    fn a_cancelled_prompt_sends_no_consent_and_the_others_keep_their_reason() {
        use crate::consent::Decision;
        use roomler_ai_remote_control::consent::ConsentDenyReason;

        for have_surface in [true, false] {
            assert_eq!(
                consent_reply(Decision::Cancelled, have_surface),
                None,
                "cancelled (surface={have_surface}): nothing is sent"
            );
            assert_eq!(
                consent_reply(Decision::Granted, have_surface),
                Some(ConsentReply {
                    granted: true,
                    reason: None
                })
            );
            assert_eq!(
                consent_reply(Decision::Denied, have_surface),
                Some(ConsentReply {
                    granted: false,
                    reason: None
                })
            );
        }
        assert_eq!(
            consent_reply(Decision::Timeout, true),
            Some(ConsentReply {
                granted: false,
                reason: Some(ConsentDenyReason::HostTimeout)
            }),
            "an unanswered prompt says so"
        );
        assert_eq!(
            consent_reply(Decision::Timeout, false),
            Some(ConsentReply {
                granted: false,
                reason: Some(ConsentDenyReason::NoPromptSurface)
            }),
            "a prompt nobody could see says THAT, not timeout"
        );
    }

    /// Slowness-cycle treadmill (field winhost-a 2026-08-17): cycling on RTT
    /// degradation is allowed twice; a THIRD young-connection conviction
    /// holds instead — but a connection that ran healthy past the fresh
    /// window re-arms the counter (the 2026-08-15 escape-the-zombie regime
    /// must keep working).
    #[test]
    fn slowness_treadmill_caps_young_reconvictions_and_rearms_on_aged_connections() {
        let young = Duration::from_secs(120);
        let aged = WS_TREADMILL_FRESH_WINDOW + Duration::from_secs(1);
        let mut cycles = 0u32;

        // First two young convictions cycle (the proven-useful regime).
        assert!(!slowness_treadmill_holds(&mut cycles, young));
        assert_eq!(cycles, 1);
        assert!(!slowness_treadmill_holds(&mut cycles, young));
        assert_eq!(cycles, 2);
        // Third young conviction: the fresh connections ALSO went slow —
        // cycling is a treadmill; hold.
        assert!(slowness_treadmill_holds(&mut cycles, young));
        // Further convictions on the same held connection keep holding.
        assert!(slowness_treadmill_holds(&mut cycles, young));

        // A connection that stayed healthy past the window before
        // degrading is a NEW episode: counter re-arms at 1 and the cycle
        // fires again.
        assert!(!slowness_treadmill_holds(&mut cycles, aged));
        assert_eq!(cycles, 1);
        // And the treadmill can re-latch from there.
        assert!(!slowness_treadmill_holds(&mut cycles, young));
        assert!(slowness_treadmill_holds(&mut cycles, young));

        // The outer loop's resets (clean close / netstate Major) restore
        // full cycling credit.
        cycles = 0;
        assert!(!slowness_treadmill_holds(&mut cycles, young));
    }

    /// The keepalive ping payload must round-trip through [`pong_rtt`] as a
    /// near-zero RTT, and foreign pong shapes must abstain rather than
    /// vote — the zombie-slow-WS detector (field winhost-a 2026-08-15) only
    /// ever acts on pongs that echo OUR stamp.
    #[test]
    fn pong_rtt_round_trips_and_rejects_foreign_payloads() {
        let epoch = std::time::Instant::now();
        let p = ping_payload(epoch);
        assert_eq!(p.len(), 8);
        let rtt = pong_rtt(&p, epoch).expect("own stamp decodes");
        assert!(
            rtt < WS_PONG_RTT_DEGRADED,
            "an immediate echo must read healthy, got {rtt:?}"
        );
        assert_eq!(
            pong_rtt(&[], epoch),
            None,
            "empty (unsolicited) pong abstains"
        );
        assert_eq!(
            pong_rtt(&[1, 2, 3], epoch),
            None,
            "short foreign payload abstains"
        );
        // A stamp from 25 s ago reads as a degraded round trip. Use an
        // epoch shifted into the past so "now" is ~30 s along it — a fresh
        // epoch's elapsed() is ~0 and the stale stamp would saturate to 0.
        let old_epoch = std::time::Instant::now()
            .checked_sub(Duration::from_secs(30))
            .expect("30 s before now is representable");
        let stale = ((old_epoch.elapsed().as_millis() as u64) - 25_000)
            .to_be_bytes()
            .to_vec();
        let slow = pong_rtt(&stale, old_epoch).expect("stamped payload decodes");
        assert!(
            slow >= WS_PONG_RTT_DEGRADED,
            "a 25 s echo must read degraded, got {slow:?}"
        );
    }

    #[test]
    fn auth_backoff_ladder_pins_each_step() {
        // Step 1 covers both 0 and 1 because the counter is bumped
        // *before* the lookup; first failure passes 1 in.
        assert_eq!(auth_backoff_for(0), Duration::from_secs(30));
        assert_eq!(auth_backoff_for(1), Duration::from_secs(30));
        assert_eq!(auth_backoff_for(2), Duration::from_secs(60));
        assert_eq!(auth_backoff_for(3), Duration::from_secs(5 * 60));
        assert_eq!(auth_backoff_for(4), Duration::from_secs(60 * 60));
        assert_eq!(auth_backoff_for(99), Duration::from_secs(60 * 60));
    }

    #[test]
    fn auth_backoff_is_monotonic_non_decreasing() {
        // Fleet stability: a regression that swapped two ladder
        // entries (e.g. 5min + 1h) would silently flap agents.
        let mut last = Duration::ZERO;
        for n in 1..=10u32 {
            let d = auth_backoff_for(n);
            assert!(
                d >= last,
                "ladder must be monotonic non-decreasing; failed at n={n}"
            );
            last = d;
        }
    }

    /// W4(d) — the displacement ladder pins each rung, stays monotonic and
    /// PARKS at 15 min: a sustained duel must never re-accelerate, and the
    /// default path never escalates to a process exit at any count.
    #[test]
    fn replaced_ladder_parks_at_fifteen_minutes() {
        assert_eq!(replaced_backoff_for(1), Duration::from_secs(60));
        assert_eq!(replaced_backoff_for(2), Duration::from_secs(60));
        assert_eq!(replaced_backoff_for(3), Duration::from_secs(120));
        assert_eq!(replaced_backoff_for(4), Duration::from_secs(240));
        assert_eq!(replaced_backoff_for(5), Duration::from_secs(480));
        assert_eq!(replaced_backoff_for(6), Duration::from_secs(900));
        assert_eq!(replaced_backoff_for(500), Duration::from_secs(900));
        let mut last = Duration::ZERO;
        for n in 1..=20usize {
            let d = replaced_backoff_for(n);
            assert!(d >= last, "ladder must be monotonic; failed at n={n}");
            last = d;
        }
    }

    // ─── rc.58 regression tests ──────────────────────────────────────────────

    #[test]
    fn ws_connect_timeout_is_long_enough_for_healthy_handshake() {
        // A healthy WSS handshake is <1 s typical; the bound exists
        // to catch hangs, not to clip latency. 30 s gives 30× headroom
        // and matches the field-tested value from the rc.58 fix.
        // A regression dropping this below ~5 s would start clipping
        // legitimate slow handshakes (e.g. cold-cache TLS to a far-
        // geo LB) and produce a fresh round of false-positive ws-
        // connect-timeout warnings.
        assert!(
            WS_CONNECT_TIMEOUT >= Duration::from_secs(10),
            "WS_CONNECT_TIMEOUT must give legitimate handshakes room; \
             current={WS_CONNECT_TIMEOUT:?}"
        );
    }

    #[test]
    fn ws_send_timeout_fits_inside_the_watchdog_budget() {
        // The signaling pump's stall threshold is 90 s (main.rs
        // registration). The worst un-ticked dwell in one select arm was
        // TWO bounded sends back-to-back (heartbeat + first session-stats
        // frame). Since FR-102 P9d a session's stats are `try_send`-queued
        // on the peer's own sender, so the heartbeat arm writes ONE frame
        // (plus a ticked 3 s telemetry budget per peer) and the new
        // carrier-ready arm's worst dwell is that 3 s telemetry budget with
        // no WS write in it at all; 2×WS_SEND_TIMEOUT stays the bound, now
        // with margin. It must leave the watchdog real headroom, or
        // the WINHOST-A 2026-08-15 failure comes back: wedged send →
        // stalled=signaling → exit(2) → full overlay teardown on a mere
        // VPN route capture. The lower bound keeps a slow-but-alive
        // link (a few missed RTOs) from being cycled spuriously.
        assert!(
            WS_SEND_TIMEOUT >= Duration::from_secs(5),
            "WS_SEND_TIMEOUT too aggressive — would cycle slow-but-alive \
             links; current={WS_SEND_TIMEOUT:?}"
        );
        assert!(
            2 * WS_SEND_TIMEOUT <= Duration::from_secs(45),
            "2×WS_SEND_TIMEOUT must stay well inside the 90 s signaling \
             stall budget; current={WS_SEND_TIMEOUT:?}"
        );
    }

    #[test]
    fn error_chain_walks_anyhow_context_layers() {
        // The whole point of this helper is to surface root causes
        // that `Display` hides. Pin the format so a future refactor
        // (e.g. swap colon-join for newline-join) doesn't silently
        // change field log shape that operators grep.
        let inner = std::io::Error::other("ECONNREFUSED");
        let middle = anyhow::Error::new(inner).context("tls handshake");
        let outer = middle.context("ws connect");
        let chain = error_chain(outer.as_ref());
        // Each layer present and ordered outer→inner.
        assert!(
            chain.starts_with("ws connect"),
            "outer must lead the chain; got: {chain}"
        );
        assert!(
            chain.contains("tls handshake"),
            "middle layer missing; got: {chain}"
        );
        assert!(
            chain.contains("ECONNREFUSED"),
            "root cause missing; got: {chain}"
        );
        assert!(
            chain.matches(": ").count() >= 2,
            "expected at least two layer separators; got: {chain}"
        );
    }

    #[test]
    fn error_chain_handles_single_layer_error() {
        // A bare error with no `.source()` chain must round-trip its
        // own message — the helper shouldn't panic or emit empty.
        let bare = std::io::Error::other("simple");
        let chain = error_chain(&bare);
        assert_eq!(chain, "simple");
    }

    #[tokio::test]
    async fn listener_watch_wakes_heartbeat_and_closed_publisher_does_not_spin() {
        let (tx, rx) = watch::channel(Some(3478));
        let mut rx = Some(rx);
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(30));
        heartbeat.tick().await;
        tx.send_replace(None);
        assert!(relay_listener_changed(&mut rx).await);
        heartbeat.reset_immediately();
        tokio::time::timeout(std::time::Duration::from_secs(1), heartbeat.tick())
            .await
            .unwrap();
        drop(tx);
        assert!(!relay_listener_changed(&mut rx).await);
        assert!(rx.is_none());
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                relay_listener_changed(&mut rx)
            )
            .await
            .is_err()
        );
    }
}
