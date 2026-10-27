// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Daemon-originated tunnel-**client** flows (unification P3b-2 PR-C).
//!
//! Lets the roomler daemon act as a tunnel *client* — `meshharbor forward` /
//! `roomler socks5` over the LocalAPI — by driving
//! [`tunnel_core::driver::run_tunnel_session`] over the daemon's **existing
//! agent WebSocket** (agent JWT, `Principal::Agent` server-side) instead of a
//! second `TunnelClient` identity + second WS. The server half (accepting an
//! agent-WS as a tunnel originator) shipped in PR-B2; this is the consumer.
//!
//! ## Multiplexing N flows over one WS
//!
//! The daemon runs many client sessions over its ONE agent WS, so it needs to
//! demux the server's replies. Two seams make that work:
//!
//! * **egress** — every session's [`DaemonSink`] funnels its `ClientMsg`s onto
//!   the SAME `outbound_tx` the signaling loop drains onto the WS. The sink
//!   stamps this session's **`open_nonce`** onto the `TunnelOpen` (the driver
//!   hardcodes `None` — a single-session CLI matches the reply positionally; we
//!   can't).
//! * **ingress** — [`intercept_server_msg`] (called from the signaling loop's
//!   read arm, mirroring `overlay::intercept`) routes each client-bound
//!   `ServerMsg` into its session's per-session [`ChannelSource`]: pre-`opened`
//!   by `open_nonce`, post-`opened` by `session_id`. Everything else passes
//!   through to the target-side `handle_server_msg`.
//!
//! The demux maps + the flow registry live in [`TunnelClientHub`], created once
//! in `run_cmd` and shared (it's `Clone` over an `Arc`) between the signaling
//! loop (publish the live sink + intercept) and `DaemonState` (the LocalAPI
//! create/kill/flows verbs) — so flows survive WS reconnects.
//!
//! ## The flow owns its listener (FR-86 P1)
//!
//! A flow binds `127.0.0.1:<local>` **once**, when its supervisor starts, and
//! keeps it for its whole life ([`tunnel_core::flow_listener::FlowListener`]).
//! Each session the ladder establishes is a [`Carrier`] installed behind that
//! listener; when the carrier dies the listener stays bound and holds new
//! connections (bounded: [`HoldPolicy`]) until the next carrier is ready,
//! instead of the kernel refusing them for the whole re-establishment. Before
//! this the session bound the port itself, which also made it impossible to
//! establish a second session beside the first — P2's make-before-break
//! re-upgrade needs exactly that.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bson::oid::ObjectId;
use roomler_ai_remote_control::signaling::{ClientMsg, CloseReason, ServerMsg};
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tracing::{debug, info, warn};
use tunnel_core::driver::{
    Carrier, Establishment, GrantError, SessionGrantRef, SessionParams, Target, TransportPref,
    establish_tunnel_session,
};
use tunnel_core::flow_listener::{Admit, FlowListener, HoldPolicy};
use tunnel_core::forward::SessionThroughput;
use tunnel_core::localapi::{FlowInfo, FlowKind};
use tunnel_core::signaling_link::{TunnelSignalingSink, TunnelSignalingSource};
use tunnel_core::transport::{TRANSPORT_QUIC_DERP_V1, TRANSPORT_QUIC_V1, TRANSPORT_WEBRTC_DC_V1};

/// Per-session control-channel buffer. Sized to absorb an ICE-trickle burst at
/// session open without blocking the shared WS-read loop — control-plane only
/// (SDP / ICE / per-flow accept / close), never the byte pumps.
const SESSION_SOURCE_DEPTH: usize = 256;

/// Reconnect backoff bounds for a supervised flow, mirroring the CLI's
/// `run_forward`: near-instant re-open after a session that ran then dropped;
/// capped so a persistently-unreachable target isn't hammered.
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// How long a session must last before its end counts as "it ran, then
/// dropped" and earns the near-instant re-open.
///
/// Field 2026-08-22 (devbox): several flows were opening successfully and
/// ending almost at once. `Ok(())` reset the backoff unconditionally, so the
/// ladder could never climb — the supervisor sat at the 1 s floor
/// indefinitely, re-establishing a full WebRTC peer every cycle. The escalating
/// ladder was already there; what was missing is the condition the comment
/// above already assumes, that the session actually **ran**. A flow that dies
/// on arrival is indistinguishable from an unreachable target and belongs on
/// the same ladder.
const SESSION_RAN_THRESHOLD: Duration = Duration::from_secs(30);

/// Did a cleanly-ended session last long enough to earn a backoff reset?
///
/// Split out so the rule is stated once and can be tested without standing up
/// a hub, a WS and a peer — the loop it guards is a 60-line async supervisor.
fn session_ran(elapsed: Duration) -> bool {
    elapsed >= SESSION_RAN_THRESHOLD
}

// ---------------------------------------------------------------------------
// The hub — shared demux + flow registry
// ---------------------------------------------------------------------------

/// FR-90 P3-7-3c — the primary enrollment's hub ([`TunnelClientHub::set_primary`]).
static PRIMARY: std::sync::OnceLock<TunnelClientHub> = std::sync::OnceLock::new();

/// FR-90 P3-7-3c — the primary enrollment's hub, once the daemon built it:
/// where an agent session's tools open its own egress.
pub fn primary() -> Option<TunnelClientHub> {
    PRIMARY.get().cloned()
}

/// Shared tunnel-client state: the reply demux + the supervised-flow registry +
/// the live agent-WS egress handle. Cheap to clone (an `Arc` inside).
#[derive(Clone)]
pub struct TunnelClientHub {
    inner: Arc<HubInner>,
}

struct HubInner {
    /// The live agent-WS egress (`ClientMsg` ↑), or `None` while the WS is down.
    /// Published by the signaling loop on each (re)connect; flow supervisors
    /// wait for `Some` before opening a session.
    sink_tx: watch::Sender<Option<mpsc::Sender<ClientMsg>>>,
    /// Reply demux, pre-`opened`: `open_nonce` → the session's Source sender.
    pending_opens: Mutex<HashMap<String, mpsc::Sender<ServerMsg>>>,
    /// Reply demux, post-`opened`: `session_id` → the session's Source sender.
    client_sessions: Mutex<HashMap<ObjectId, mpsc::Sender<ServerMsg>>>,
    /// Flow registry: flow id → supervisor handle + display cells.
    flows: Mutex<HashMap<String, FlowHandle>>,
    /// This daemon's version, advertised in `rc:tunnel.hello`.
    client_version: String,
    /// Monotonic source for flow ids + open nonces (unique, deterministic — no
    /// RNG needed: a flow id is unique, and `nonce = <flow-id>.<attempt>`).
    seq: AtomicU64,
}

/// A registered flow: the supervisor's abort handle + the immutable display
/// fields + the shared live cells (`flows()` reads them; the supervisor +
/// Source write them).
struct FlowHandle {
    abort: AbortHandle,
    kind: FlowKind,
    local: u16,
    /// `host:port` for a static forward; `None` for a SOCKS5 listener.
    target: Option<String>,
    /// Target node — the hex agent id being reached.
    node: String,
    /// Requested transport word (`auto` / `quic` / `webrtc`) — shown until a
    /// session negotiates a concrete one.
    requested: String,
    live: Arc<FlowLive>,
}

/// Live per-flow cells, shared between the supervisor (writes `status` +
/// `nonce`, and `Up` when a carrier is installed — #1685 / FR-86 P1), the
/// per-session Source (writes `transport` + `session_id` when it sees
/// `TunnelOpened`) and `flows()` (reads). `kill_flow` reads `nonce` +
/// `session_id` to reap the demux maps when it aborts the supervisor
/// mid-flight.
#[derive(Default)]
pub(crate) struct FlowLive {
    /// `Up` ONLY once an established carrier is installed behind the flow's
    /// listener (#1685, FR-86 P1) — never on `rc:tunnel.opened`, which the
    /// server also answers for a node whose data plane then fails to come up.
    /// The port itself is bound for the flow's whole life; `Up` is "it
    /// serves", not "it is bound".
    status: Mutex<FlowStatus>,
    /// Negotiated transport, learned from the pass-through `TunnelOpened`.
    transport: Mutex<Option<String>>,
    /// Current session id, once opened.
    session_id: Mutex<Option<ObjectId>>,
    /// Current in-flight open nonce.
    nonce: Mutex<Option<String>>,
    /// Cumulative throughput for this forward (P3b-3). One `Arc`, created
    /// with the flow and cloned into every `run_tunnel_session` attempt, so
    /// `bytes_in`/`bytes_out` accumulate across WS reconnects; `active_flows`
    /// is the live connection gauge. Read by [`TunnelClientHub::flows_snapshot`].
    throughput: Arc<SessionThroughput>,
    /// P6: set when the supervisor hit a PERMANENT open-failure (enrollment
    /// revoked, cross-tenant) and exited its retry loop — retrying would
    /// hammer the server with a doomed TunnelOpen every backoff tick
    /// forever. Read by `flows_snapshot` (transport column shows `failed`)
    /// and by the route reconciler, which turns it into the terminal
    /// `RouteState::Failed` for a declared route.
    fatal: Mutex<Option<String>>,
    /// #1685 — consecutive session attempts that failed (or died on arrival)
    /// since the flow last served; reset when a carrier comes up. Read by
    /// the route reconciler as `RouteState::Backoff::attempts`.
    failures: std::sync::atomic::AtomicU32,
    /// #1685 — the last failed attempt's error; cleared when a carrier comes
    /// up. Read as `RouteState::Backoff::last_error`.
    last_error: Mutex<Option<String>>,
    /// #1685 — when the supervisor's current backoff sleep ends; `None`
    /// while an attempt is in flight. Read as `next_retry_secs`.
    retry_at: Mutex<Option<std::time::Instant>>,
    /// FR-90 P3-7-3a — the agent session's grant this flow's tunnels are
    /// opened under, every attempt and every re-upgrade candidate alike: the
    /// tunnel carries the session's flows or none. `None` for the daemon's
    /// own flows (declared routes, LocalAPI forwards).
    net_grant: Option<SessionGrantRef>,
}

impl FlowLive {
    /// #1685 — an established carrier is installed behind the flow's listener:
    /// the flow SERVES. The only transition to `Up` (the supervisor calls it
    /// the moment `FlowListener::install` hands the carrier the held
    /// connections — FR-86 P1; before that it was the driver's bind hook); it
    /// forgets the failures that preceded it.
    pub(crate) fn mark_listening(&self) {
        *self.status.lock().unwrap() = FlowStatus::Up;
        self.failures.store(0, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = None;
        *self.retry_at.lock().unwrap() = None;
    }

    /// #1685 — a session attempt failed (or died on arrival) with `error`.
    pub(crate) fn note_failure(&self, error: String) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = Some(error);
    }

    /// #1685 — the supervisor sleeps `backoff` before its next attempt.
    pub(crate) fn note_backoff(&self, backoff: Duration) {
        *self.retry_at.lock().unwrap() = Some(std::time::Instant::now() + backoff);
    }
}

/// #1685 — a flow's liveness as the route reconciler reads it
/// ([`TunnelClientHub::flow_report`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowReport {
    /// A carrier is ready behind the flow's listener: the port serves. (Since
    /// FR-86 P1 the port itself stays bound for the flow's whole life and
    /// connections arriving before a carrier are held; this is still the
    /// "it serves" bit the reconciler maps to `active`.)
    pub listening: bool,
    /// The supervisor stopped on a permanent failure (terminal).
    pub fatal: Option<String>,
    /// Consecutive session attempts that failed since the flow last served.
    pub failures: u32,
    /// The last failed attempt's error.
    pub last_error: Option<String>,
    /// Time left until the supervisor's next attempt; `None` while one is in
    /// flight.
    pub next_retry_in: Option<Duration>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum FlowStatus {
    /// Waiting for a live WS / mid-handshake.
    #[default]
    Connecting,
    /// A session is established (the listener is serving).
    Up,
    /// The session dropped; the supervisor is backing off before a retry.
    Down,
}

fn status_word(s: FlowStatus) -> &'static str {
    match s {
        FlowStatus::Connecting => "connecting",
        FlowStatus::Up => "up",
        FlowStatus::Down => "down",
    }
}

impl TunnelClientHub {
    /// Build an idle hub. The sink starts `None`; the signaling loop publishes
    /// it on connect via [`TunnelClientHub::publish_sink`].
    pub fn new(client_version: String) -> Self {
        let (sink_tx, _sink_rx) = watch::channel(None);
        Self {
            inner: Arc::new(HubInner {
                sink_tx,
                pending_opens: Mutex::new(HashMap::new()),
                client_sessions: Mutex::new(HashMap::new()),
                flows: Mutex::new(HashMap::new()),
                client_version,
                seq: AtomicU64::new(1),
            }),
        }
    }

    /// FR-90 P3-7-3c — make this the primary enrollment's hub, where an agent
    /// session's own egress opens its flows: sessions run on the primary
    /// alone, as leases do. The daemon calls it once, as it builds the hub;
    /// a later call is ignored.
    pub fn set_primary(&self) {
        let _ = PRIMARY.set(self.clone());
    }

    /// Publish the live agent-WS egress so flow supervisors can open sessions.
    /// Returns a guard that clears it back to `None` on drop — so a supervisor
    /// that holds a clone of the dead `outbound_tx` fails its next send and
    /// re-waits for the next connection's sink (mirrors `ConnectedGuard`).
    ///
    /// Uses `send_replace`, NOT `send`: at publish time there may be no live
    /// receiver (a flow supervisor subscribes only when its flow is created,
    /// which can be AFTER the first WS connect), and `watch::Sender::send`
    /// silently fails + drops the value when there are no receivers — the value
    /// would stay `None` and every later-subscribing supervisor would hang.
    /// `send_replace` always updates the stored value, so a supervisor that
    /// subscribes afterward sees the live sink.
    pub fn publish_sink(&self, tx: mpsc::Sender<ClientMsg>) -> SinkGuard {
        self.inner.sink_tx.send_replace(Some(tx));
        SinkGuard { hub: self.clone() }
    }

    /// The live agent-WS egress, or `None` while disconnected.
    ///
    /// Flow supervisors `subscribe()` and wait; the Fleet-RPC LocalAPI verb
    /// instead needs a one-shot answer, because "the daemon isn't connected to
    /// the server right now" is a real result for `meshharbor exec` and telling
    /// the operator that beats blocking until it reconnects.
    pub fn sink_now(&self) -> Option<mpsc::Sender<ClientMsg>> {
        self.inner.sink_tx.borrow().clone()
    }

    /// Snapshot the registry as LocalAPI [`FlowInfo`]. Live throughput
    /// (`bytes_in`/`bytes_out`/`active_flows`) is read from each flow's shared
    /// [`SessionThroughput`] aggregate (P3b-3): `bytes_*` are cumulative for
    /// the forward's life (across WS reconnects); `active_flows` is the live
    /// connection gauge. TCP payload only — SOCKS5 UDP-ASSOCIATE bytes are not
    /// counted (they run on `FlowStats` with no session aggregate). The
    /// `transport` column doubles as a liveness signal: `connecting` / `down`
    /// until a carrier is ready behind the flow's listener (#1685, FR-86 P1).
    /// A transport the server negotiated is not yet a serving flow — setup
    /// after `rc:tunnel.opened` can still fail — so it shows only once a
    /// carrier is up; [`Self::negotiated_transport`] reads it before that.
    pub fn flows_snapshot(&self) -> Vec<FlowInfo> {
        let flows = self.inner.flows.lock().unwrap();
        let mut out: Vec<FlowInfo> = flows
            .iter()
            .map(|(id, h)| {
                let status = *h.live.status.lock().unwrap();
                let transport = if h.live.fatal.lock().unwrap().is_some() {
                    // P6: supervisor stopped on a permanent failure — the
                    // liveness column says so instead of a perpetual "down".
                    "failed".to_string()
                } else if status == FlowStatus::Up {
                    h.live
                        .transport
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| h.requested.clone())
                } else {
                    status_word(status).to_string()
                };
                let (bytes_in, bytes_out, active) = h.live.throughput.snapshot();
                FlowInfo {
                    id: id.clone(),
                    kind: h.kind,
                    local_addr: format!("127.0.0.1:{}", h.local),
                    target: h.target.clone(),
                    node: Some(h.node.clone()),
                    transport,
                    active_flows: active.min(u32::MAX as u64) as u32,
                    bytes_in,
                    bytes_out,
                }
            })
            .collect();
        // Stable order for a readable table + deterministic tests.
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// The set of target node ids (hex agent ids) reached by a live (`Up`)
    /// daemon tunnel flow (P3b-3). `DaemonState::peers()` overlays these as
    /// [`tunnel_core::localapi::ConnectionType::Tunnel`] when the overlay
    /// carrier is Blocked/Offline — the "reachable via the userspace forward
    /// even though the WG carrier is down" signal. Only `Up` flows count, so a
    /// connecting/backing-off flow doesn't prematurely claim Tunnel.
    pub fn active_flow_agent_ids(&self) -> std::collections::HashSet<String> {
        let flows = self.inner.flows.lock().unwrap();
        flows
            .values()
            .filter(|h| *h.live.status.lock().unwrap() == FlowStatus::Up)
            .map(|h| h.node.clone())
            .collect()
    }

    /// Create a supervised static forward. Validates the node id + remote +
    /// that `local` is bindable, then spawns the supervisor and returns the
    /// assigned flow id. `Err` is a user-facing message for the LocalAPI.
    pub async fn create_forward(
        &self,
        node: &str,
        local: u16,
        remote: &str,
        transport: &str,
        start_transport: &str,
    ) -> std::result::Result<String, String> {
        let agent_id = parse_node(node)?;
        let (host, port) = parse_host_port(remote).map_err(|e| e.to_string())?;
        let pref = parse_transport(transport);
        // FR-86 P2 test lever — a first-session transport override (a word).
        let start = start_request_transport(start_transport);
        probe_local_port(local).await?;
        let id = self.spawn_flow(
            FlowKind::Forward,
            agent_id,
            node.to_string(),
            local,
            Some(remote.to_string()),
            Target::Static { host, port },
            pref,
            start,
            // The daemon's own forward: no session's grant, its port bound by
            // the supervisor.
            None,
            None,
        );
        info!(flow = %id, %node, local, %remote, ?pref, start, "created daemon forward");
        Ok(id)
    }

    /// Create a supervised SOCKS5 listener (userspace mode; per-connection
    /// CONNECT target). Same validation as [`create_forward`] minus the remote.
    pub async fn create_socks5(
        &self,
        node: &str,
        local: u16,
        transport: &str,
    ) -> std::result::Result<String, String> {
        let agent_id = parse_node(node)?;
        let pref = parse_transport(transport);
        probe_local_port(local).await?;
        let id = self.spawn_flow(
            FlowKind::Socks5,
            agent_id,
            node.to_string(),
            local,
            None,
            Target::Socks5,
            pref,
            // SOCKS5 has no start-transport lever (the FR-86 P2 field test drives
            // a static forward); it always starts on the normal ladder.
            None,
            // The daemon's own listener: no session's grant, its port bound by
            // the supervisor.
            None,
            None,
        );
        info!(flow = %id, %node, local, ?pref, "created daemon socks5 listener");
        Ok(id)
    }

    /// FR-90 P3-7-3b — a flow for an agent session's own egress through
    /// `exit`:
    /// - a listener on loopback at a port the system picks, each connection
    ///   first admitted by `admit` (the session's account alone);
    /// - its tunnels opened under `grant` (P3-7-3a);
    /// - ended at `until`, the grant's end: the listener closes, and every
    ///   connection ends with the carrier, both halves (#2129).
    ///
    /// `target` is a forward's one destination, or [`Target::SessionSocks5`]
    /// with the listener's credential. Answers the flow's id and the address
    /// it serves on.
    pub async fn create_session_flow(
        &self,
        exit: ObjectId,
        target: Target,
        grant: SessionGrantRef,
        until: std::time::Instant,
        admit: Admit,
    ) -> std::result::Result<(String, std::net::SocketAddr), String> {
        let (kind, shown) = match &target {
            Target::Static { host, port } => (FlowKind::Forward, Some(format!("{host}:{port}"))),
            Target::Socks5 | Target::SessionSocks5(_) => (FlowKind::Socks5, None),
        };
        let listener = FlowListener::bind_admitting(0, HoldPolicy::default(), Some(admit))
            .await
            .map_err(|e| format!("a loopback port: {e:#}"))?;
        let addr = listener.local_addr();
        let grant_id = grant.grant_id.clone();
        let id = self.spawn_flow(
            kind,
            exit,
            exit.to_hex(),
            addr.port(),
            shown,
            target,
            TransportPref::Auto,
            None,
            Some(grant),
            Some(listener),
        );
        let hub = self.clone();
        let flow = id.clone();
        let grant_for_log = grant_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
            if hub.kill_flow(&flow) {
                info!(%flow, grant = %grant_for_log, "a session's flow ended with its grant");
            }
        });
        info!(flow = %id, %exit, %addr, grant = %grant_id, "created a session's flow");
        Ok((id, addr))
    }

    /// Whether a flow with this id is registered (P6 — the route
    /// reconciler's liveness check for its route→flow mapping).
    pub fn has_flow(&self, id: &str) -> bool {
        self.inner.flows.lock().unwrap().contains_key(id)
    }

    /// The flow's permanent-failure reason, if its supervisor stopped on
    /// one (P6). `None` for a healthy/retrying flow or an unknown id.
    pub fn flow_fatal(&self, id: &str) -> Option<String> {
        self.inner
            .flows
            .lock()
            .unwrap()
            .get(id)
            .and_then(|h| h.live.fatal.lock().unwrap().clone())
    }

    /// #1685 — what the route reconciler needs to tell the truth about a
    /// declared route's flow, read in one lock walk. `None` for an unknown
    /// id. `listening` is a carrier serving behind the flow's listener and
    /// nothing less: before this the reconciler mapped "a flow exists"
    /// straight to `active`, and a route to an offline node read `active`
    /// while every connect was refused. (Since FR-86 P1 such a connect is
    /// held rather than refused, and the route still reads `backoff`.)
    pub fn flow_report(&self, id: &str) -> Option<FlowReport> {
        let flows = self.inner.flows.lock().unwrap();
        let live = &flows.get(id)?.live;
        Some(FlowReport {
            listening: *live.status.lock().unwrap() == FlowStatus::Up,
            fatal: live.fatal.lock().unwrap().clone(),
            failures: live.failures.load(Ordering::Relaxed),
            last_error: live.last_error.lock().unwrap().clone(),
            next_retry_in: live
                .retry_at
                .lock()
                .unwrap()
                .map(|t| t.saturating_duration_since(std::time::Instant::now())),
        })
    }

    /// The transport the server negotiated for this flow, as recorded from
    /// its most recent `rc:tunnel.opened` — whether or not that session has
    /// come up since. `None` for an unknown id, or before any open was
    /// answered. Proves the open was demuxed back to the flow by its nonce;
    /// it says nothing about the port serving, which is `flow_report`'s
    /// `listening`.
    pub fn negotiated_transport(&self, id: &str) -> Option<String> {
        let flows = self.inner.flows.lock().unwrap();
        flows.get(id)?.live.transport.lock().unwrap().clone()
    }

    /// Test seam: the live cells of a registered flow, so a sibling module's
    /// tests can play the supervisor (a failed attempt, the listener bind)
    /// without a server.
    #[cfg(test)]
    pub(crate) fn flow_live_for_test(&self, id: &str) -> Option<Arc<FlowLive>> {
        self.inner
            .flows
            .lock()
            .unwrap()
            .get(id)
            .map(|h| h.live.clone())
    }

    /// Abort + deregister a flow by id. Reaps the flow's demux entries (in case
    /// it was aborted mid-open / mid-session, where the supervisor's own
    /// cleanup won't run). Returns whether a flow was found.
    pub fn kill_flow(&self, id: &str) -> bool {
        let Some(handle) = self.inner.flows.lock().unwrap().remove(id) else {
            return false;
        };
        handle.abort.abort();
        if let Some(nonce) = handle.live.nonce.lock().unwrap().take() {
            self.inner.pending_opens.lock().unwrap().remove(&nonce);
        }
        if let Some(sid) = handle.live.session_id.lock().unwrap().take() {
            // #1754 — the abort above fires the driver's `TerminateOnDrop`, but
            // that runs whenever the aborted future is next dropped, which is
            // best-effort timing. Tell the server NOW, synchronously, while we
            // still hold the session id: it relays `rc:tunnel.terminate` on to
            // the exit agent so the agent reaps its per-session peer (ICE
            // sockets + DC pool / quinn endpoint) instead of leaking it. A
            // duplicate with the guard's own send is harmless — the server's
            // terminate handling is idempotent. `try_send` never blocks the
            // caller (a LocalAPI verb / the route reconciler); a full or closed
            // egress just means the server will reap on the WS drop / grace
            // instead.
            if let Some(sink) = self.sink_now() {
                let _ = sink.try_send(ClientMsg::TunnelTerminate {
                    session_id: sid,
                    reason: CloseReason::ClientShutdown,
                });
            }
            self.inner.client_sessions.lock().unwrap().remove(&sid);
        }
        info!(flow = %id, "killed daemon flow");
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_flow(
        &self,
        kind: FlowKind,
        agent_id: ObjectId,
        node: String,
        local: u16,
        target_disp: Option<String>,
        target: Target,
        pref: TransportPref,
        // FR-86 P2 — force the FIRST session's transport (a below-best carrier
        // for the field test); `None` = the normal ladder.
        start_transport: Option<&'static str>,
        // FR-90 P3-7-3a — an agent session's grant: the flow is the session's.
        net_grant: Option<SessionGrantRef>,
        // FR-90 P3-7-3b — the session's listener, bound by the caller.
        prebound: Option<FlowListener<Carrier>>,
    ) -> String {
        let id = format!("fl-{}", self.inner.seq.fetch_add(1, Ordering::Relaxed));
        let live = Arc::new(FlowLive {
            net_grant,
            ..FlowLive::default()
        });
        let handle = tokio::spawn(run_flow_supervisor(
            self.clone(),
            id.clone(),
            agent_id,
            local,
            target,
            pref,
            live.clone(),
            start_transport,
            prebound,
        ));
        self.inner.flows.lock().unwrap().insert(
            id.clone(),
            FlowHandle {
                abort: handle.abort_handle(),
                kind,
                local,
                target: target_disp,
                node,
                requested: transport_word(pref).to_string(),
                live,
            },
        );
        id
    }

    // ---- the ingress demux ------------------------------------------------

    /// Route one client-bound `ServerMsg` into its per-session Source. Returns
    /// `None` when consumed (it belonged to a daemon-originated flow), or
    /// `Some(msg)` to pass through to the target-side `handle_server_msg`.
    /// Sync — a bounded `try_send` never blocks the WS-read loop.
    fn intercept(&self, msg: ServerMsg) -> Option<ServerMsg> {
        // 1) Pre-session: `TunnelOpened` (and an open-FAILURE `Error`) carry the
        //    `open_nonce` we stamped. `TunnelOpened` promotes the pending entry
        //    to a session entry; the `Error` fails that flow's open fast.
        match &msg {
            ServerMsg::TunnelOpened {
                open_nonce: Some(nonce),
                session_id,
                ..
            } => {
                let sender = self.inner.pending_opens.lock().unwrap().remove(nonce);
                let Some(tx) = sender else {
                    // Unknown nonce (stale / not ours) — let it fall through.
                    return Some(msg);
                };
                let sid = *session_id;
                // Deliver the `opened` so the driver's open-wait sees it, THEN
                // register the session (the send moves `msg`). If the driver
                // already gave up (receiver dropped), don't register a dead
                // sender.
                match tx.try_send(msg) {
                    Ok(()) => {
                        self.inner.client_sessions.lock().unwrap().insert(sid, tx);
                    }
                    Err(_) => debug!(%sid, "opened arrived after the opener gave up; dropping"),
                }
                return None;
            }
            ServerMsg::Error {
                open_nonce: Some(nonce),
                ..
            } => {
                if let Some(tx) = self.inner.pending_opens.lock().unwrap().remove(nonce) {
                    let _ = tx.try_send(msg); // deliver the failure; the driver bails
                    return None;
                }
                // No matching nonce → fall through to the session_id routing
                // (an `Error` can also carry a live `session_id`).
            }
            _ => {}
        }

        // 2) Post-session: route the session-scoped client-bound variants by
        //    `session_id ∈ client_sessions`. A `session_id` we don't own is a
        //    target-side session — pass it through unchanged.
        let Some(sid) = client_bound_session_id(&msg) else {
            return Some(msg);
        };
        let sender = self
            .inner
            .client_sessions
            .lock()
            .unwrap()
            .get(&sid)
            .cloned();
        let Some(tx) = sender else {
            return Some(msg);
        };
        match tx.try_send(msg) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Full(m)) => {
                warn!(%sid, kind = server_msg_kind(&m), "client session source full; dropping");
                None
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The session ended between the lookup and the send — reap it.
                self.inner.client_sessions.lock().unwrap().remove(&sid);
                None
            }
        }
    }
}

/// RAII guard: clears the hub's published sink to `None` on drop (every
/// `connect_once` exit path), so a supervisor holding the dead egress re-waits.
pub struct SinkGuard {
    hub: TunnelClientHub,
}

impl Drop for SinkGuard {
    fn drop(&mut self) {
        // `send_replace` (not `send`): clear the value even if no supervisor is
        // currently subscribed, so a supervisor created later doesn't see a
        // stale sink from a dead connection.
        self.hub.inner.sink_tx.send_replace(None);
    }
}

/// The signaling-loop hook (mirrors `overlay::intercept`): consume a
/// client-bound `ServerMsg` (→ `None`) or pass it through (→ `Some`).
pub fn intercept_server_msg(hub: &TunnelClientHub, msg: ServerMsg) -> Option<ServerMsg> {
    hub.intercept(msg)
}

// ---------------------------------------------------------------------------
// Signaling seam impls — the daemon's Sink (nonce-stamping) + Source (channel)
// ---------------------------------------------------------------------------

/// The daemon's [`TunnelSignalingSink`]: funnels a session's `ClientMsg`s onto
/// the shared agent-WS egress, stamping this session's `open_nonce` onto the
/// `TunnelOpen` so the reply demux can match its `TunnelOpened` / `Error`.
struct DaemonSink {
    tx: mpsc::Sender<ClientMsg>,
    nonce: String,
}

#[async_trait]
impl TunnelSignalingSink for DaemonSink {
    async fn send(&self, msg: ClientMsg) -> anyhow::Result<()> {
        let msg = match msg {
            ClientMsg::TunnelOpen {
                agent_id,
                transport,
                open_nonce: _,
                derp_pubkey,
                net_grant,
            } => ClientMsg::TunnelOpen {
                agent_id,
                transport,
                open_nonce: Some(self.nonce.clone()),
                derp_pubkey,
                // FR-90 P3-7-2a — carried as given: the daemon's own tunnels
                // send none until P3-7-3.
                net_grant,
            },
            other => other,
        };
        self.tx
            .send(msg)
            .await
            .map_err(|e| anyhow::anyhow!("agent WS egress closed: {e}"))
    }
}

/// The daemon's [`TunnelSignalingSource`]: a per-session mpsc fed by the hub's
/// demux. Sniffs the pass-through `TunnelOpened` to record the negotiated
/// transport + session id into the flow's live cells, then yields it to the
/// driver. `None` = the session's demux entry was removed (WS drop / kill).
///
/// It does NOT mark the flow `Up` (#1685). `rc:tunnel.opened` is the server
/// accepting the open; the QUIC / DC-pool setup comes after it and can still
/// fail — toward an offline node it did, every cycle, and the flow read
/// `webrtc-dc-v1` in the Flows table for most of each cycle. Only the
/// supervisor sets `Up`, when the established carrier is installed behind the
/// flow's listener ([`run_flow_cycle`]).
struct ChannelSource {
    rx: mpsc::Receiver<ServerMsg>,
    live: Arc<FlowLive>,
}

#[async_trait]
impl TunnelSignalingSource for ChannelSource {
    async fn recv(&mut self) -> Option<ServerMsg> {
        let msg = self.rx.recv().await?;
        if let ServerMsg::TunnelOpened {
            session_id,
            transport,
            ..
        } = &msg
        {
            *self.live.transport.lock().unwrap() = Some(transport.clone());
            *self.live.session_id.lock().unwrap() = Some(*session_id);
        }
        Some(msg)
    }
}

// ---------------------------------------------------------------------------
// The supervised flow loop
// ---------------------------------------------------------------------------

/// How one supervisor cycle ended ([`run_flow_cycle`]).
enum Cycle {
    /// The hub's sink sender is gone — the daemon is shutting down.
    Shutdown,
    /// A carrier was established, served behind the flow's listener, and died.
    /// `ran` is the whole cycle (establishment + service), the same clock
    /// `session_ran` always read.
    Carried {
        ran: Duration,
        transport: &'static str,
    },
    /// The listener could not be bound, or no carrier came out of the ladder.
    Failed(anyhow::Error),
}

// ---------------------------------------------------------------------------
// FR-86 P2 — make-before-break re-upgrade: probe schedule, ranking, candidate
// establishment, promotion and drain.
// ---------------------------------------------------------------------------

/// The first re-upgrade probe fires this long after a below-best carrier is
/// installed. Short enough that a route that fell back at open recovers within
/// a minute once the better transport works; long enough not to probe a churn.
const REUPGRADE_FIRST_PROBE: Duration = Duration::from_secs(60);

/// Backoff after each FAILED probe, capped at the last entry. Applied in order:
/// the 1st failure waits `[0]`, the 2nd `[1]`, … the Nth `[len-1]`. Relentless
/// (it never gives up — the "never ratchet" rule) but cheap when a path simply
/// can't do better (a corp net with no QUIC).
const REUPGRADE_BACKOFFS: [Duration; 4] = [
    Duration::from_secs(2 * 60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
];

/// The re-upgrade probe schedule as a pure value: how long until the next probe,
/// given how many have failed since the last reset. No clock inside — the caller
/// turns a [`ReupgradeBackoff::delay`] into a deadline — so it is fully
/// deterministic to test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReupgradeBackoff {
    /// Failed probes since the last reset. 0 ⇒ the first probe is pending.
    failures: u32,
}

impl ReupgradeBackoff {
    fn new() -> Self {
        Self { failures: 0 }
    }

    /// Delay until the next probe: [`REUPGRADE_FIRST_PROBE`] while nothing has
    /// failed, then the backoff ladder, capped at its last entry.
    fn delay(&self) -> Duration {
        match self.failures {
            0 => REUPGRADE_FIRST_PROBE,
            n => {
                let i = ((n - 1) as usize).min(REUPGRADE_BACKOFFS.len() - 1);
                REUPGRADE_BACKOFFS[i]
            }
        }
    }

    /// A probe failed: the next one waits one rung further down the ladder.
    fn on_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    /// Back to the first-probe delay — after a promotion (a fresh below-best
    /// carrier) or a network change (the old path's failures no longer apply).
    fn reset(&mut self) {
        self.failures = 0;
    }
}

/// [`ReupgradeBackoff`] plus the concrete deadline it maps to, so the serving
/// loop can `sleep_until` it. Time is injected via `now`, so the deadline math
/// is testable without a real clock.
struct ProbeTimer {
    backoff: ReupgradeBackoff,
    deadline: tokio::time::Instant,
}

impl ProbeTimer {
    /// Arm the FIRST probe relative to `now`.
    fn armed(now: tokio::time::Instant) -> Self {
        let backoff = ReupgradeBackoff::new();
        Self {
            deadline: now + backoff.delay(),
            backoff,
        }
    }

    fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    /// A probe failed: back off and recompute the deadline from `now`.
    fn on_failure(&mut self, now: tokio::time::Instant) {
        self.backoff.on_failure();
        self.deadline = now + self.backoff.delay();
    }

    /// Reset to the first-probe delay from `now` (promotion / network change).
    fn reset(&mut self, now: tokio::time::Instant) {
        self.backoff.reset();
        self.deadline = now + self.backoff.delay();
    }
}

/// FR-86 P2 kill switch. `ROOMLERD_TUNNEL_REUPGRADE=0` (or the `tunnel_reupgrade`
/// config key via the env bridge) turns off all probing — behaviour is exactly
/// P1. Default ON. Read once per serving epoch, so the env var flips it live on
/// the next cycle.
fn reupgrade_enabled() -> bool {
    tunnel_core::env::flag("TUNNEL_REUPGRADE", true)
}

/// Whether re-upgrade probing runs for this flow at all: only for `auto` flows
/// (a pinned `--transport` is a decision — it NEVER probes) and only with the
/// kill switch on. Pure, so the pinned + kill-switch gates are unit-tested.
fn reupgrade_active(pref: TransportPref, kill_switch_on: bool) -> bool {
    pref == TransportPref::Auto && kill_switch_on
}

/// Rank of a negotiated transport, best highest: `quic-v1` > `quic-derp-v1` >
/// `webrtc-dc-v1`. Unknown transports rank 0 (never promoted TO, never a reason
/// to probe FROM — an old/newer server word is left alone).
fn transport_rank(t: &str) -> u8 {
    match t {
        TRANSPORT_QUIC_V1 => 3,
        TRANSPORT_QUIC_DERP_V1 => 2,
        TRANSPORT_WEBRTC_DC_V1 => 1,
        _ => 0,
    }
}

/// Transports strictly better than the active one, best first, restricted to
/// what a re-upgrade may REQUEST: `quic-derp-v1` is offered only where derp
/// fallback is enabled. Empty ⇒ the active transport is already the best allowed
/// (no probe). This doubles as the "below best?" test.
fn better_transports(active: &str, derp_enabled: bool) -> Vec<&'static str> {
    match active {
        TRANSPORT_WEBRTC_DC_V1 => {
            let mut v = vec![TRANSPORT_QUIC_V1];
            if derp_enabled {
                v.push(TRANSPORT_QUIC_DERP_V1);
            }
            v
        }
        TRANSPORT_QUIC_DERP_V1 => vec![TRANSPORT_QUIC_V1],
        // quic-v1 (the best) or an unrecognised word: nothing better to try.
        _ => vec![],
    }
}

/// Whether the active transport is below the best the flow may use — the gate on
/// whether a probe is scheduled at all.
fn below_best(active: &str, derp_enabled: bool) -> bool {
    !better_transports(active, derp_enabled).is_empty()
}

/// Map the CLI/LocalAPI start-transport WORD (the FR-86 P2 test lever) to the
/// concrete transport the daemon's first session requests. `auto`/empty/unknown
/// ⇒ `None` (the normal ladder).
fn start_request_transport(word: &str) -> Option<&'static str> {
    match word.trim().to_ascii_lowercase().as_str() {
        "webrtc" | "webrtc-dc-v1" => Some(TRANSPORT_WEBRTC_DC_V1),
        "quic" | "quic-v1" => Some(TRANSPORT_QUIC_V1),
        _ => None,
    }
}

/// Outcome of a re-upgrade probe, sent from the spawned candidate task back to
/// the flow supervisor.
enum CandidateOutcome {
    /// A better transport was established and is ready to promote. Its session
    /// is registered in the hub's demux (`client_sessions[session_id]`), so the
    /// supervisor keeps it registered and adopts the id as the flow's.
    Established {
        carrier: Box<Carrier>,
        session_id: ObjectId,
        transport: &'static str,
    },
    /// No better transport this round (setup failed / errored). Nothing to clean
    /// up — the candidate task already reaped its own demux entries.
    Failed,
}

/// Aborts a spawned task when dropped (the flow supervisor holds these for its
/// in-flight probe and its draining carriers, so `kill_flow` — which aborts the
/// supervisor — tears them ALL down, each carrier's drop telling the exit).
/// `tunnel_core::driver::AbortOnDrop` is `pub(crate)` to that crate, so the
/// daemon keeps its own one-liner.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What the drain reaper needs from a carrier — a seam so the promote/drain rule
/// is testable with a fake, without a live session (`tunnel_core::driver::Carrier`
/// implements it below; the tests use a fake). Boxed futures keep it object-safe
/// and trait-method simple; a drain reaper is not a hot path.
trait DrainableCarrier: Send + Sync + 'static {
    fn dead(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
    fn drained(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

impl DrainableCarrier for Carrier {
    fn dead(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(Carrier::dead(self))
    }
    fn drained(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(Carrier::drained(self))
    }
}

/// The end of a draining carrier, as a guard so it runs on EVERY exit of its
/// reaper — the normal ones (drained / dead) and the ABORT (#1816): `kill_flow`
/// aborts the flow supervisor, whose `drains` drop and abort each reaper
/// mid-`select!`, and the supervisor's own returns (a permanent error, the
/// hub's shutdown) drop them the same way. Before this the demux reap was the
/// reaper's last line: an aborted reaper still dropped the carrier (the future
/// owned it, so the exit was told) but left `client_sessions[old_sid]` behind
/// for the life of the daemon — `kill_flow` reaps only the ACTIVE session's id,
/// and nothing reaps it lazily, because the server forgets a session the client
/// terminated and never sends for it again.
///
/// The order is the one the body had, made explicit instead of left to how an
/// aborted `async fn` drops its parameters against its locals: the carrier
/// FIRST — its drop sends the `rc:tunnel.terminate` the exit acts on (#1754),
/// while the entry still routes — THEN the entry.
struct DrainGuard<C: ?Sized> {
    hub: TunnelClientHub,
    old_sid: ObjectId,
    /// The carrier, until `Drop` takes it: `take()`n and dropped as a statement
    /// before the reap, so the order is not a field order.
    old: Option<Arc<C>>,
}

impl<C: ?Sized> Drop for DrainGuard<C> {
    fn drop(&mut self) {
        // Dropping the carrier ends its session (TerminateOnDrop → the exit
        // frees its peer) ...
        drop(self.old.take());
        // ... then reap the demux entry the promotion left registered for it.
        self.hub
            .inner
            .client_sessions
            .lock()
            .unwrap()
            .remove(&self.old_sid);
    }
}

/// Drain a carrier the flow re-upgraded away from: keep it carrying its
/// established connections until its last one ends ([`Carrier::drained`]) — or
/// until it dies on its own — then drop it, which sends the `rc:tunnel.terminate`
/// the exit acts on (#1754) and reaps its demux entry. **No maximum drain time:
/// an established connection is never cut** — the make-before-break guarantee.
/// The end is a [`DrainGuard`], so an aborted reaper ends the same way (#1816).
async fn drain_carrier<C: DrainableCarrier + ?Sized>(
    hub: TunnelClientHub,
    old_sid: ObjectId,
    old: Arc<C>,
) {
    let guard = DrainGuard {
        hub,
        old_sid,
        old: Some(old),
    };
    let old: &C = guard
        .old
        .as_deref()
        .expect("the guard holds the carrier until it drops");
    tokio::select! {
        _ = old.drained() => {
            info!(session = %old_sid, "re-upgrade: draining carrier reached 0 connections; closing");
        }
        _ = old.dead() => {
            info!(session = %old_sid, "re-upgrade: draining carrier died before it drained; closing");
        }
    }
    // `guard` drops here — or at the `select!` above when the reaper is aborted
    // — ending the carrier (→ terminate) and then reaping its demux entry.
}

/// Spawn a [`drain_carrier`] reaper, returning its abort guard (held by the
/// supervisor so `kill_flow` tears it down).
fn spawn_drain(hub: &TunnelClientHub, old_sid: ObjectId, old: Arc<Carrier>) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(drain_carrier(hub.clone(), old_sid, old)))
}

/// A re-upgrade candidate's demux cleanup guard. On the FAILURE and (crucially)
/// the ABORT paths — where the candidate task's own cleanup did not run — it
/// removes the pending-open nonce and, if the candidate got as far as
/// `rc:tunnel.opened`, its `client_sessions` entry. Disarmed on success, because
/// the promoted carrier needs that entry to keep dispatching.
struct CandidateGuard {
    hub: TunnelClientHub,
    nonce: String,
    live: Arc<FlowLive>,
    disarmed: bool,
}

impl CandidateGuard {
    fn disarm(mut self) {
        self.disarmed = true;
    }
}

impl Drop for CandidateGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        self.hub
            .inner
            .pending_opens
            .lock()
            .unwrap()
            .remove(&self.nonce);
        if let Some(sid) = *self.live.session_id.lock().unwrap() {
            self.hub.inner.client_sessions.lock().unwrap().remove(&sid);
        }
    }
}

/// Spawn a background probe for a transport better than `active_transport`.
/// It never touches the flow's live carrier or its `FlowLive` — a private
/// throwaway `FlowLive` holds the candidate's demux bookkeeping — so a failed or
/// aborted probe cannot disturb the live route. The outcome is sent on
/// `result_tx`.
#[allow(clippy::too_many_arguments)]
fn spawn_candidate(
    hub: &TunnelClientHub,
    flow_id: &str,
    sink_tx: &mpsc::Sender<ClientMsg>,
    agent_id: ObjectId,
    target: &Target,
    active_transport: &'static str,
    derp: Option<tunnel_core::transport::derp::DerpTunnelHandle>,
    derp_enabled: bool,
    result_tx: mpsc::Sender<CandidateOutcome>,
) -> AbortOnDrop {
    let hub = hub.clone();
    let flow_id = flow_id.to_string();
    let sink_tx = sink_tx.clone();
    let target = target.clone();
    // A candidate nonce namespace disjoint from the active flow's `{flow}.{n}`.
    let seq = hub.inner.seq.fetch_add(1, Ordering::Relaxed);
    AbortOnDrop(tokio::spawn(async move {
        let outcome = establish_candidate(
            &hub,
            &flow_id,
            seq,
            &sink_tx,
            agent_id,
            &target,
            active_transport,
            derp,
            derp_enabled,
        )
        .await;
        let _ = result_tx.send(outcome).await;
    }))
}

/// Run the restricted ladder for a re-upgrade candidate: each transport strictly
/// better than `active_transport`, best first, until one is established.
#[allow(clippy::too_many_arguments)]
async fn establish_candidate(
    hub: &TunnelClientHub,
    flow_id: &str,
    seq: u64,
    sink_tx: &mpsc::Sender<ClientMsg>,
    agent_id: ObjectId,
    target: &Target,
    active_transport: &'static str,
    derp: Option<tunnel_core::transport::derp::DerpTunnelHandle>,
    derp_enabled: bool,
) -> CandidateOutcome {
    let betters = better_transports(active_transport, derp_enabled);
    // Private bookkeeping — never the flow's own FlowLive, so the live route's
    // Flows-table cells and demux state are untouched by the probe.
    let cand_live = Arc::new(FlowLive::default());
    for (i, &t) in betters.iter().enumerate() {
        let this_derp = if t == TRANSPORT_QUIC_DERP_V1 {
            if derp.is_none() {
                continue; // derp flavor wanted but no /derp handle right now
            }
            derp.clone()
        } else {
            None
        };
        let nonce = format!("{flow_id}.c{seq}.{i}");
        let guard = CandidateGuard {
            hub: hub.clone(),
            nonce: nonce.clone(),
            live: cand_live.clone(),
            disarmed: false,
        };
        match drive_attempt(
            hub,
            flow_id,
            nonce,
            sink_tx,
            agent_id,
            target,
            vec![t.to_string()],
            t,
            &cand_live,
            this_derp,
        )
        .await
        {
            Ok(Establishment::Established(carrier)) => {
                let carrier = *carrier;
                let transport = carrier.transport();
                let session_id = carrier.session_id();
                if transport_rank(transport) > transport_rank(active_transport) {
                    // Keep the session registered for the promoted carrier.
                    guard.disarm();
                    info!(flow = %flow_id, transport, "re-upgrade candidate established");
                    return CandidateOutcome::Established {
                        carrier: Box::new(carrier),
                        session_id,
                        transport,
                    };
                }
                // The server negotiated something not actually better than the
                // active carrier (defensive — we only advertised better ones):
                // drop it (terminate) and let the guard reap, then try the next.
                warn!(flow = %flow_id, transport, "re-upgrade candidate came back no better than the active carrier; dropping");
                drop(carrier);
            }
            Ok(Establishment::QuicSetupFailed) => {
                debug!(flow = %flow_id, transport = t, "re-upgrade candidate: QUIC setup failed");
            }
            Err(e) => {
                debug!(flow = %flow_id, transport = t, %e, "re-upgrade candidate errored");
            }
        }
        // Failure/no-better: the guard drops here and reaps this attempt.
    }
    CandidateOutcome::Failed
}

/// Sleep until `at`, or pend forever when `None` — the disabled-probe-timer arm.
async fn sleep_until_opt(at: Option<tokio::time::Instant>) {
    match at {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// Supervise one flow: bind its listener once, then (re)establish a tunnel
/// session over the live agent WS and serve `local` through it until the
/// session drops, then back off + retry with the listener still bound. Owns
/// the local-port intent across WS reconnects (the CLI's `run_forward` shape,
/// relocated + sharing the daemon's ONE WS instead of dialing its own).
#[allow(clippy::too_many_arguments)]
async fn run_flow_supervisor(
    hub: TunnelClientHub,
    flow_id: String,
    agent_id: ObjectId,
    local: u16,
    target: Target,
    pref: TransportPref,
    live: Arc<FlowLive>,
    // FR-86 P2 — force the FIRST session's transport (the test lever). Applied
    // on the first cycle only, then cleared so later sessions behave as `pref`.
    start_transport: Option<&'static str>,
    // FR-90 P3-7-3b — a listener the caller bound already (a session's, on a
    // port the system picked, with its admit hook); `None` binds `local` here.
    prebound: Option<FlowListener<Carrier>>,
) {
    info!(flow = %flow_id, "flow supervisor started");
    let mut sink_rx = hub.inner.sink_tx.subscribe();
    let mut backoff = RECONNECT_BACKOFF_MIN;
    let mut attempt: u64 = 0;
    // FR-86 P2 — cross-cycle re-upgrade state, owned here so `kill_flow`
    // (which aborts this task) tears it ALL down: `drains` holds the reaper of
    // each carrier a promotion left behind (dropping one terminates its
    // session), and `cand_task` the one in-flight probe. `cand_rx` carries a
    // probe's outcome, and — because it survives a cycle — a probe still running
    // when the active carrier dies is picked up by the NEXT cycle's serving
    // loop rather than wasted (spec §6).
    let mut drains: Vec<AbortOnDrop> = Vec::new();
    let mut cand_task: Option<AbortOnDrop> = None;
    let (cand_tx, mut cand_rx) = mpsc::channel::<CandidateOutcome>(2);
    let mut start_override = start_transport;
    // R1: a netstate Major during the backoff sleep invalidates the failures
    // that earned it (the old path is gone; the new one is untested) — cut
    // the wait and retry at the floor, exactly the control-WS reconnect
    // ladder's shape (`signaling.rs`). Guards against a flap pinning the
    // floor: netstate damps to ≤1 material Major / 120 s (#506), and the
    // `session_ran` threshold (#602) still governs post-session resets.
    let mut net_rx = super::netwatch::subscribe();
    // R4 — is QUIC-over-TURN failing on this path? Set from what actually
    // RAN each session (below): quic-v1 = healthy; webrtc-dc-v1 = quic fell
    // back (a capture window, or a genuinely QUIC-hostile path); quic-derp-v1
    // = the derp leg is carrying it (quic still failing underneath). While
    // true and the flavor is enabled, LEAD with quic-derp-v1 to skip the
    // doomed quic attempt. The old quick-death counter never fired in the
    // field: webrtc-dc kept sessions alive ~30-60s (> SESSION_RAN_THRESHOLD)
    // even while carrying no data (2026-08-25). The transport that ran is the
    // honest signal.
    let mut quic_over_turn_failing = false;
    // FR-86 P1 — the flow's listener: bound on the first cycle (or retried on
    // the ladder if the bind fails), kept across every session after that.
    let mut listener: Option<FlowListener<Carrier>> = prebound;
    loop {
        *live.status.lock().unwrap() = FlowStatus::Connecting;
        // #1685 — an attempt is in flight (or waiting for the WS): no countdown.
        *live.retry_at.lock().unwrap() = None;
        // Drop the handles of drain reapers that have finished (their carriers
        // are already closed) so the Vec can't grow across a long-lived flow.
        drains.retain(|d| !d.0.is_finished());

        let cycle = run_flow_cycle(
            &hub,
            &flow_id,
            agent_id,
            local,
            &target,
            pref,
            &live,
            &mut listener,
            &mut sink_rx,
            &mut attempt,
            quic_over_turn_failing,
            &mut drains,
            &mut cand_task,
            &cand_tx,
            &mut cand_rx,
            &mut net_rx,
            start_override.take(),
        )
        .await;

        *live.status.lock().unwrap() = FlowStatus::Down;
        let result = match cycle {
            Cycle::Shutdown => return, // hub dropped — the daemon is shutting down
            Cycle::Carried { ran, transport } => {
                // Update the derp-lead signal from the transport that actually
                // ran — the carrier's own word for it.
                if transport == tunnel_core::transport::TRANSPORT_QUIC_V1 {
                    quic_over_turn_failing = false;
                } else if transport == TRANSPORT_WEBRTC_DC_V1
                    || transport == tunnel_core::transport::TRANSPORT_QUIC_DERP_V1
                {
                    quic_over_turn_failing = true;
                }
                Ok(ran)
            }
            Cycle::Failed(e) => Err(e),
        };
        match result {
            Ok(ran) => {
                if session_ran(ran) {
                    info!(flow = %flow_id, ran_s = ran.as_secs(), "tunnel session ended; reconnecting");
                    backoff = RECONNECT_BACKOFF_MIN;
                } else {
                    // Opened, then died on arrival. Reported at WARN because
                    // it is indistinguishable from a broken target and used to
                    // be invisible: the old code logged this at INFO as a
                    // normal reconnect while silently pinning the ladder to
                    // its floor. See `SESSION_RAN_THRESHOLD`.
                    warn!(
                        flow = %flow_id, ran_ms = ran.as_millis(),
                        backoff_s = backoff.as_secs(),
                        "tunnel session ended immediately; backing off rather than re-opening at once"
                    );
                    live.note_failure(format!(
                        "session ended {} ms after opening",
                        ran.as_millis()
                    ));
                }
            }
            Err(e) => {
                // P6: a PERMANENT failure (enrollment revoked, cross-tenant)
                // can't heal by retrying — every retry is a doomed TunnelOpen
                // against the server, forever (and reboot-surviving for a
                // declared route). Record it and stop supervising; the
                // operator re-creates the flow / re-enables the route after
                // fixing the cause. Retryable errors keep today's backoff.
                if let Some(reason) = permanent_session_error(&e) {
                    warn!(flow = %flow_id, %reason, "tunnel session failed PERMANENTLY; supervisor stopping");
                    *live.fatal.lock().unwrap() = Some(reason);
                    return;
                }
                warn!(flow = %flow_id, %e, backoff_s = backoff.as_secs(), "tunnel session failed; retrying");
                live.note_failure(session_error_summary(&e));
            }
        }
        // #1685 — publish the countdown the route's `next_retry_secs` shows.
        live.note_backoff(backoff);
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
            }
            summary = super::netwatch::next_major(&mut net_rx) => {
                // Per-flow jitter (0–2 s, stable per flow+attempt) so N
                // supervisors woken by ONE Major don't re-open through a
                // just-transitioned corp path in the same instant.
                let jitter = flow_retry_jitter(&flow_id, attempt);
                info!(
                    flow = %flow_id, %summary, jitter_ms = jitter.as_millis(),
                    "network changed during retry backoff — retrying now"
                );
                tokio::time::sleep(jitter).await;
                backoff = RECONNECT_BACKOFF_MIN;
            }
        }
    }
}

/// One supervisor cycle: make sure the flow's listener is bound (FR-86 P1 —
/// once; a failed bind is a retryable failure exactly like a failed session
/// used to be), wait for a live agent WS, run the transport ladder to a
/// [`Carrier`], install it behind the listener (this is the ONE event that
/// makes the flow `Up`, #1685 — the held connections are handed over in the
/// same call), then wait for the carrier to die. The listener stays bound
/// throughout, so a connection arriving during the next cycle's ladder is
/// held rather than refused.
#[allow(clippy::too_many_arguments)]
async fn run_flow_cycle(
    hub: &TunnelClientHub,
    flow_id: &str,
    agent_id: ObjectId,
    local: u16,
    target: &Target,
    pref: TransportPref,
    live: &Arc<FlowLive>,
    listener: &mut Option<FlowListener<Carrier>>,
    sink_rx: &mut watch::Receiver<Option<mpsc::Sender<ClientMsg>>>,
    attempt: &mut u64,
    lead_derp: bool,
    // FR-86 P2 — cross-cycle re-upgrade state (see `run_flow_supervisor`).
    drains: &mut Vec<AbortOnDrop>,
    cand_task: &mut Option<AbortOnDrop>,
    cand_tx: &mpsc::Sender<CandidateOutcome>,
    cand_rx: &mut mpsc::Receiver<CandidateOutcome>,
    net_rx: &mut Option<super::netwatch::NetRx>,
    // FR-86 P2 — force this (first) session's transport; `None` = normal ladder.
    start_override: Option<&'static str>,
) -> Cycle {
    if listener.is_none() {
        match FlowListener::bind(local, HoldPolicy::default()).await {
            Ok(l) => {
                info!(
                    flow = %flow_id, local = %l.local_addr(),
                    "flow listener bound — connections are held until a carrier is ready"
                );
                *listener = Some(l);
            }
            // The same error shape a per-session bind failure had, so the
            // route's `last_error` reads as before (`session_error_summary`).
            Err(e) => return Cycle::Failed(e.context(format!("tunnel session (flow {flow_id})"))),
        }
    }
    let Some(listener) = listener.as_ref() else {
        return Cycle::Failed(anyhow::anyhow!("flow listener missing after bind"));
    };

    // Wait for a live agent WS.
    let Some(sink_tx) = wait_for_sink(sink_rx).await else {
        return Cycle::Shutdown;
    };

    let derp_enabled = pref == TransportPref::Auto && derp_fallback_enabled();
    // Resolve the /derp handle whenever the flavor is enabled — the
    // fallback ladder inside `run_session_with_fallback` uses it on a
    // quic-over-TURN failure even before we start LEADING with it.
    let derp = if derp_enabled {
        let h = super::netwatch::primary_derp_tunnel_handle();
        if h.is_none() && lead_derp {
            debug!(flow = %flow_id, "quic-derp-v1 wanted but no /derp handle yet (overlay derp starting?)");
        }
        h
    } else {
        None
    };

    let started = std::time::Instant::now();
    // Establish the active carrier: the FR-86 P2 test lever forces this first
    // session onto a chosen transport (falling back to the ladder if that
    // fails so the route still serves); otherwise the normal ladder runs.
    let mut active = if let Some(t) = start_override {
        info!(flow = %flow_id, transport = t, "FR-86 P2 test lever: forcing the first session's transport");
        match drive_one(
            hub,
            flow_id,
            attempt,
            &sink_tx,
            agent_id,
            target,
            vec![t.to_string()],
            t,
            live,
            None,
        )
        .await
        {
            Ok(Establishment::Established(c)) => Arc::new(*c),
            _ => {
                warn!(flow = %flow_id, "forced first-session transport did not establish; falling back to the ladder");
                match run_session_with_fallback(
                    hub, flow_id, attempt, &sink_tx, agent_id, target, pref, live, derp, lead_derp,
                )
                .await
                {
                    Ok(carrier) => Arc::new(carrier),
                    Err(e) => return Cycle::Failed(e),
                }
            }
        }
    } else {
        match run_session_with_fallback(
            hub, flow_id, attempt, &sink_tx, agent_id, target, pref, live, derp, lead_derp,
        )
        .await
        {
            Ok(carrier) => Arc::new(carrier),
            Err(e) => return Cycle::Failed(e),
        }
    };

    // #1685 / FR-86 P1 — the carrier is behind the listener: the flow SERVES.
    let handed = listener.install(Arc::clone(&active));
    live.mark_listening();
    info!(
        flow = %flow_id, transport = active.transport(), local = %listener.local_addr(),
        held_handed = handed, "carrier ready behind the flow listener — the route is serving"
    );

    // The transport that actually RAN this cycle (updated on each promotion) —
    // the derp-lead signal the supervisor reads.
    let mut transport_ran = active.transport();

    // FR-86 P2 serving phase. With the kill switch off (or a pinned transport)
    // this is exactly P1: wait for the carrier to die. Otherwise probe for a
    // better transport, promote make-before-break, and drain the old carrier.
    if !reupgrade_active(pref, reupgrade_enabled()) {
        // Abort any stale probe (kill switch flipped off mid-flight) and drain
        // its buffered outcome so nothing lingers.
        if cand_task.take().is_some() {
            while cand_rx.try_recv().is_ok() {}
        }
        active.dead().await;
    } else {
        // Arm the first probe if the active carrier is below the best allowed —
        // unless a probe is ALREADY in flight (carried over from a previous
        // cycle whose active carrier died, spec §6): its result will arrive on
        // `cand_rx` and be promoted if it beats this cycle's active carrier.
        let mut timer: Option<ProbeTimer> =
            if cand_task.is_none() && below_best(active.transport(), derp_enabled) {
                Some(ProbeTimer::armed(tokio::time::Instant::now()))
            } else {
                None
            };
        loop {
            drains.retain(|d| !d.0.is_finished());
            let active_dead = Arc::clone(&active);
            // Fire a probe only when a timer is armed AND none is in flight.
            let probe_deadline = if cand_task.is_none() {
                timer.as_ref().map(|t| t.deadline())
            } else {
                None
            };
            tokio::select! {
                _ = active_dead.dead() => {
                    // The active carrier died. Leave any in-flight probe alone —
                    // the next cycle's serving loop adopts its result. End here.
                    break;
                }
                _ = sleep_until_opt(probe_deadline), if probe_deadline.is_some() => {
                    let derp_handle = if derp_enabled {
                        super::netwatch::primary_derp_tunnel_handle()
                    } else {
                        None
                    };
                    info!(
                        flow = %flow_id, from = active.transport(),
                        "re-upgrade: probing for a better transport"
                    );
                    *cand_task = Some(spawn_candidate(
                        hub, flow_id, &sink_tx, agent_id, target,
                        active.transport(), derp_handle, derp_enabled, cand_tx.clone(),
                    ));
                }
                res = cand_rx.recv(), if cand_task.is_some() => {
                    *cand_task = None;
                    let now = tokio::time::Instant::now();
                    match res {
                        Some(CandidateOutcome::Established { carrier, session_id, transport })
                            if transport_rank(transport) > transport_rank(active.transport()) =>
                        {
                            let old_t = active.transport();
                            let new = Arc::new(*carrier);
                            // Promote: new connections go to the candidate at once
                            // (atomic swap); the old carrier keeps its established
                            // ones and becomes draining.
                            listener.install(Arc::clone(&new));
                            *live.transport.lock().unwrap() = Some(transport.to_string());
                            *live.session_id.lock().unwrap() = Some(session_id);
                            info!(flow = %flow_id, "flow re-upgraded {old_t} → {transport}");
                            let old = std::mem::replace(&mut active, new);
                            let old_sid = old.session_id();
                            drains.push(spawn_drain(hub, old_sid, old));
                            transport_ran = transport;
                            // Reset the schedule after a promotion; keep probing
                            // only if the new carrier is still below the best.
                            timer = if below_best(active.transport(), derp_enabled) {
                                Some(ProbeTimer::armed(now))
                            } else {
                                None
                            };
                        }
                        Some(CandidateOutcome::Established { carrier, transport, .. }) => {
                            // A candidate that is not better than the CURRENT
                            // active carrier (the active changed under it, or a
                            // stale carry-over): drop it (terminate) and back off.
                            debug!(flow = %flow_id, transport, active = active.transport(),
                                "re-upgrade candidate no better than the current carrier; dropping");
                            drop(carrier);
                            if let Some(t) = timer.as_mut() { t.on_failure(now); }
                        }
                        _ => {
                            // Failed probe (or the channel hiccupped): back off.
                            if let Some(t) = timer.as_mut() {
                                t.on_failure(now);
                                debug!(flow = %flow_id, "re-upgrade probe failed; backing off");
                            }
                        }
                    }
                }
                summary = super::netwatch::next_major(net_rx) => {
                    // A network change invalidates the probe schedule: retry from
                    // the first-probe delay (the old path's failures no longer apply).
                    if let Some(t) = timer.as_mut() {
                        t.reset(tokio::time::Instant::now());
                        debug!(flow = %flow_id, %summary, "network changed — re-upgrade probe schedule reset");
                    }
                }
            }
        }
    }

    // No carrier: hold from here until the next cycle installs one.
    listener.clear();
    end_session(hub, live);
    // The old end of the session function — the dispatcher aborted, the peer
    // closed, the exit told (#1754) — is this drop. Draining carriers (if any)
    // persist in `drains`, owned by the supervisor, and close on their own.
    drop(active);
    Cycle::Carried {
        ran: started.elapsed(),
        transport: transport_ran,
    }
}

/// A session is over (its carrier died, or its attempt produced none): reap
/// its demux entry + the cells the Source filled from `rc:tunnel.opened`, so
/// nothing leaks across attempts. `kill_flow` does the same from the outside.
fn end_session(hub: &TunnelClientHub, live: &FlowLive) {
    if let Some(sid) = live.session_id.lock().unwrap().take() {
        hub.inner.client_sessions.lock().unwrap().remove(&sid);
    }
    *live.transport.lock().unwrap() = None;
}

/// R4 — the client-side gate for the derp tunnel flavor
/// (`tunnel_derp_fallback` config key via the env bridge; default OFF while
/// the leg is field-proven).
fn derp_fallback_enabled() -> bool {
    tunnel_core::env::flag("TUNNEL_DERP_FALLBACK", false)
}

/// Deterministic 0–2 s spread for Major-triggered re-dials: hash of
/// (flow id, attempt) — stable per flow so the herd spreads the same way
/// every time, no RNG dependency. The exact distribution is irrelevant;
/// only "not all at once" matters.
fn flow_retry_jitter(flow_id: &str, attempt: u64) -> Duration {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    flow_id.hash(&mut h);
    attempt.hash(&mut h);
    Duration::from_millis(h.finish() % 2000)
}

/// Classify a session error as PERMANENT (`Some(reason)`) or retryable
/// (`None`). Conservative by design: only failure shapes that provably
/// cannot heal without operator action match — `rc:tunnel.revoked` (admin
/// revoked this daemon's enrollment; the driver bails with "tunnel
/// revoked …") and the server's cross-tenant open rejection (the driver
/// bails "server error during tunnel.open: cross_tenant: …"). Per-flow
/// ACL denies are NOT here: they arrive as `TcpForwardReject` per
/// connection while the session stays up, and a policy edit heals them
/// live. Anything unrecognised stays retryable (the pre-P6 behaviour).
///
/// FR-90 P3-7-3a — a session's grant the server refused or did not bind is
/// permanent too, by its type: opening again would present the same grant to
/// the same server. The session asks the vault for another.
fn permanent_session_error(e: &anyhow::Error) -> Option<String> {
    if e.downcast_ref::<GrantError>().is_some() {
        return Some(format!("{e:#}"));
    }
    let msg = format!("{e:#}");
    let lower = msg.to_ascii_lowercase();
    if lower.contains("revoked") || lower.contains("cross_tenant") {
        Some(msg)
    } else {
        None
    }
}

/// #1685 — the error a reader sees in `route ls` / the Routes page for a
/// retrying route. `{e:#}` prints the whole context chain; its outermost link
/// is `drive_one`'s `tunnel session (flow fl-N): `, which the row already
/// names, so it is dropped when present. Anything else passes through whole.
fn session_error_summary(e: &anyhow::Error) -> String {
    let full = format!("{e:#}");
    if let Some(rest) = full.strip_prefix("tunnel session (flow ")
        && let Some((_, tail)) = rest.split_once("): ")
    {
        return tail.to_string();
    }
    full
}

/// Return the current live sink, or wait for one. `None` once the hub's sink
/// sender is dropped (daemon shutdown).
async fn wait_for_sink(
    sink_rx: &mut watch::Receiver<Option<mpsc::Sender<ClientMsg>>>,
) -> Option<mpsc::Sender<ClientMsg>> {
    loop {
        if let Some(tx) = sink_rx.borrow_and_update().clone() {
            return Some(tx);
        }
        if sink_rx.changed().await.is_err() {
            return None;
        }
    }
}

/// One session with the Auto→WebRTC transport fallback, up to an established
/// [`Carrier`] (FR-86 P1: the listener is the flow's, so the ladder ends at
/// "ready to carry"). Mirrors the CLI's `run_one_session`, but each attempt
/// gets a fresh nonce + Source (the daemon re-opens over the shared WS rather
/// than dialing a new one).
#[allow(clippy::too_many_arguments)]
async fn run_session_with_fallback(
    hub: &TunnelClientHub,
    flow_id: &str,
    attempt: &mut u64,
    sink_tx: &mpsc::Sender<ClientMsg>,
    agent_id: ObjectId,
    target: &Target,
    pref: TransportPref,
    live: &Arc<FlowLive>,
    // R4 — the live `/derp` tunnel handle when the flavor is enabled + the
    // overlay's `/derp` mux is up. `None` disables the derp rungs below
    // (classic quic → webrtc-dc ladder).
    derp: Option<tunnel_core::transport::derp::DerpTunnelHandle>,
    // R4 — LEAD with quic-derp-v1 (skip the doomed quic-over-TURN attempt)
    // once the supervisor has seen quic-over-TURN fail on this path. Ignored
    // when `derp` is `None` or `pref != Auto`.
    lead_derp: bool,
) -> Result<Carrier> {
    // An explicit `--transport` is honored verbatim (no derp, no fallback).
    if pref != TransportPref::Auto {
        return match drive_one(
            hub,
            flow_id,
            attempt,
            sink_tx,
            agent_id,
            target,
            pref.supported_transports(),
            pref.request_transport(),
            live,
            None,
        )
        .await?
        {
            Establishment::Established(carrier) => Ok(*carrier),
            Establishment::QuicSetupFailed => {
                bail!("QUIC setup failed and transport={pref:?} forbids fallback")
            }
        };
    }

    // Auto. When leading with derp, request quic-derp first (still advertising
    // quic + webrtc so the server can pick a working one if derp is somehow
    // unavailable this session). Otherwise start on quic-over-TURN.
    let (supported, request, first_derp) = if lead_derp && derp.is_some() {
        info!(flow = %flow_id, "leading with quic-derp-v1 (QUIC-over-TURN failing on this path)");
        (
            vec![
                tunnel_core::transport::TRANSPORT_QUIC_DERP_V1.to_string(),
                tunnel_core::transport::TRANSPORT_QUIC_V1.to_string(),
                TRANSPORT_WEBRTC_DC_V1.to_string(),
            ],
            tunnel_core::transport::TRANSPORT_QUIC_DERP_V1,
            derp.clone(),
        )
    } else {
        (
            TransportPref::Auto.supported_transports(),
            TransportPref::Auto.request_transport(),
            None,
        )
    };
    if let Establishment::Established(carrier) = drive_one(
        hub, flow_id, attempt, sink_tx, agent_id, target, supported, request, live, first_derp,
    )
    .await?
    {
        return Ok(*carrier);
    }

    // QUIC-over-TURN failed. Try quic-derp over the ESTABLISHED /derp WS
    // BEFORE webrtc-dc — in a corp capture window webrtc-dc rides the same
    // TURN/ICE and dies identically (field 2026-08-25: webrtc-dc sessions
    // "ran" but carried no data), while the derp leg rides the wss:443 floor
    // that survives capture. Skipped if we already led with derp above.
    if !lead_derp {
        if let Some(handle) = derp {
            info!(flow = %flow_id, "QUIC-over-TURN setup failed; trying quic-derp-v1 over the established /derp WS before webrtc-dc");
            if let Establishment::Established(carrier) = drive_one(
                hub,
                flow_id,
                attempt,
                sink_tx,
                agent_id,
                target,
                vec![tunnel_core::transport::TRANSPORT_QUIC_DERP_V1.to_string()],
                tunnel_core::transport::TRANSPORT_QUIC_DERP_V1,
                live,
                Some(handle),
            )
            .await?
            {
                return Ok(*carrier);
            }
            warn!(flow = %flow_id, "quic-derp-v1 setup also failed; re-opening over webrtc-dc-v1");
        }
    } else {
        warn!(flow = %flow_id, "quic-derp-v1 lead failed; re-opening over webrtc-dc-v1");
    }

    match drive_one(
        hub,
        flow_id,
        attempt,
        sink_tx,
        agent_id,
        target,
        vec![TRANSPORT_WEBRTC_DC_V1.to_string()],
        TRANSPORT_WEBRTC_DC_V1,
        live,
        None,
    )
    .await?
    {
        Establishment::Established(carrier) => Ok(*carrier),
        Establishment::QuicSetupFailed => {
            bail!("webrtc-dc-v1 fallback unexpectedly reported QUIC-setup-failed")
        }
    }
}

/// Bump the flow's attempt counter and drive one session on a fresh
/// `{flow}.{attempt}` nonce. The active-flow path; the re-upgrade candidate
/// path calls [`drive_attempt`] directly with its own `c`-prefixed nonce.
#[allow(clippy::too_many_arguments)]
async fn drive_one(
    hub: &TunnelClientHub,
    flow_id: &str,
    attempt: &mut u64,
    sink_tx: &mpsc::Sender<ClientMsg>,
    agent_id: ObjectId,
    target: &Target,
    supported: Vec<String>,
    request: &str,
    live: &Arc<FlowLive>,
    derp: Option<tunnel_core::transport::derp::DerpTunnelHandle>,
) -> Result<Establishment> {
    *attempt += 1;
    let nonce = format!("{flow_id}.{attempt}");
    drive_attempt(
        hub, flow_id, nonce, sink_tx, agent_id, target, supported, request, live, derp,
    )
    .await
}

/// Register this attempt's demux nonce + seam, drive one
/// `establish_tunnel_session`, then reap the attempt's demux entries — the
/// pending nonce either way, the session too unless a carrier came out of it
/// (that session lives on until the supervisor ends it, `end_session`). The
/// nonce is the caller's, so both the active flow (`{flow}.{n}`) and a
/// re-upgrade candidate (`{flow}.c{seq}.{i}`) share this one body.
#[allow(clippy::too_many_arguments)]
async fn drive_attempt(
    hub: &TunnelClientHub,
    flow_id: &str,
    nonce: String,
    sink_tx: &mpsc::Sender<ClientMsg>,
    agent_id: ObjectId,
    target: &Target,
    supported: Vec<String>,
    request: &str,
    live: &Arc<FlowLive>,
    derp: Option<tunnel_core::transport::derp::DerpTunnelHandle>,
) -> Result<Establishment> {
    let (src_tx, src_rx) = mpsc::channel::<ServerMsg>(SESSION_SOURCE_DEPTH);

    // Register the pending open BEFORE the driver sends `TunnelOpen`, so a fast
    // `TunnelOpened` can't race the insert (critique U3).
    hub.inner
        .pending_opens
        .lock()
        .unwrap()
        .insert(nonce.clone(), src_tx);
    *live.nonce.lock().unwrap() = Some(nonce.clone());

    let sink: Arc<dyn TunnelSignalingSink> = Arc::new(DaemonSink {
        tx: sink_tx.clone(),
        nonce: nonce.clone(),
    });
    let source: Box<dyn TunnelSignalingSource> = Box::new(ChannelSource {
        rx: src_rx,
        live: live.clone(),
    });

    info!(flow = %flow_id, %nonce, request, "flow: driving establish_tunnel_session (hello+open)");
    let result = establish_tunnel_session(
        sink,
        source,
        SessionParams {
            agent_id,
            target: target.clone(),
            client_version: hub.inner.client_version.clone(),
            derp,
            // FR-86 P1 — the flow owns the listener, so there is no per-session
            // bind to be told about: the supervisor flips `Up` itself when it
            // installs the carrier (#1685's ONE event, one step later).
            on_listening: None,
            // FR-90 P3-7-3a — a session's flow presents its grant at every
            // open; the daemon's own flows present none.
            net_grant: live.net_grant.clone(),
        },
        supported,
        request,
        // Same Arc every attempt → cumulative bytes across reconnects (P3b-3).
        live.throughput.clone(),
    )
    .await;

    // The open is answered or abandoned either way: its nonce is spent.
    hub.inner.pending_opens.lock().unwrap().remove(&nonce);
    *live.nonce.lock().unwrap() = None;
    // No carrier out of this attempt ⇒ whatever session it opened is already
    // over (the driver's guard told the exit): reap its demux entry + cells
    // now so nothing leaks across attempts. A carrier's session stays
    // registered until the supervisor ends it (`end_session`).
    if !matches!(result, Ok(Establishment::Established(_))) {
        end_session(hub, live);
    }

    result.with_context(|| format!("tunnel session (flow {flow_id})"))
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// The `session_id` of a **client-bound** session-scoped `ServerMsg` — the set a
/// tunnel-client session consumes (driver `dispatch_loop` + QUIC path). `None`
/// for target-only / non-session variants (they pass through). `TunnelOpened` is
/// routed by nonce upstream, so it's `None` here.
fn client_bound_session_id(msg: &ServerMsg) -> Option<ObjectId> {
    match msg {
        ServerMsg::TunnelSdpAnswer { session_id, .. }
        | ServerMsg::TunnelIce { session_id, .. }
        | ServerMsg::TcpForwardAccept { session_id, .. }
        | ServerMsg::TcpForwardReject { session_id, .. }
        | ServerMsg::TcpHalfClose { session_id, .. }
        | ServerMsg::TcpClosed { session_id, .. }
        | ServerMsg::UdpForwardAccept { session_id, .. }
        | ServerMsg::UdpForwardReject { session_id, .. }
        | ServerMsg::UdpClosed { session_id, .. }
        | ServerMsg::TunnelTerminate { session_id, .. }
        | ServerMsg::TunnelQuicReady { session_id, .. } => Some(*session_id),
        // An `Error` may carry a live session id (post-open failures).
        ServerMsg::Error {
            session_id: Some(sid),
            ..
        } => Some(*sid),
        _ => None,
    }
}

/// Short kind label for diagnostics on a dropped/overflowed frame.
fn server_msg_kind(msg: &ServerMsg) -> &'static str {
    match msg {
        ServerMsg::TunnelSdpAnswer { .. } => "tunnel.sdp.answer",
        ServerMsg::TunnelIce { .. } => "tunnel.ice",
        ServerMsg::TcpForwardAccept { .. } => "tunnel.tcp.accept",
        ServerMsg::TcpForwardReject { .. } => "tunnel.tcp.reject",
        ServerMsg::TcpHalfClose { .. } => "tunnel.tcp.half_close",
        ServerMsg::TcpClosed { .. } => "tunnel.tcp.closed",
        ServerMsg::UdpForwardAccept { .. } => "tunnel.udp.accept",
        ServerMsg::UdpForwardReject { .. } => "tunnel.udp.reject",
        ServerMsg::UdpClosed { .. } => "tunnel.udp.closed",
        ServerMsg::TunnelTerminate { .. } => "tunnel.terminate",
        ServerMsg::TunnelQuicReady { .. } => "tunnel.quic.ready",
        _ => "other",
    }
}

/// Parse + validate a target node (a 24-hex agent id). `pub(crate)` so the
/// route reconciler validates a RouteAdd with the SAME rule the hub will
/// apply at create time.
pub(crate) fn parse_node(node: &str) -> std::result::Result<ObjectId, String> {
    ObjectId::parse_str(node).map_err(|_| format!("node must be a 24-hex agent id, got '{node}'"))
}

/// `auto` (default / empty / unknown) | `quic` | `webrtc`.
fn parse_transport(s: &str) -> TransportPref {
    match s.trim().to_ascii_lowercase().as_str() {
        "quic" | "quic-v1" => TransportPref::Quic,
        "webrtc" | "webrtc-dc-v1" => TransportPref::Webrtc,
        _ => TransportPref::Auto,
    }
}

/// The display word for a preference (inverse of [`parse_transport`]).
fn transport_word(p: TransportPref) -> &'static str {
    match p {
        TransportPref::Auto => "auto",
        TransportPref::Quic => "quic",
        TransportPref::Webrtc => "webrtc",
    }
}

/// Parse a `host:port` (robust to bracketed IPv6 `[::1]:80`). Mirrors the CLI's
/// `forward::parse_remote` — kept local so the daemon doesn't depend on the CLI
/// crate. `pub(crate)` for the route reconciler's RouteAdd validation.
pub(crate) fn parse_host_port(s: &str) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest
            .find(']')
            .with_context(|| format!("remote with `[` must close with `]:port`: {s}"))?;
        let host = &rest[..close];
        let port_str = rest[close + 1..]
            .strip_prefix(':')
            .with_context(|| format!("missing `:port` after `]`: {s}"))?;
        let port = port_str
            .parse()
            .with_context(|| format!("invalid port {port_str}"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port_str) = s
        .rsplit_once(':')
        .with_context(|| format!("remote must be host:port, got {s}"))?;
    if host.is_empty() {
        bail!("remote host must not be empty");
    }
    let port = port_str
        .parse()
        .with_context(|| format!("invalid port {port_str}"))?;
    Ok((host.to_string(), port))
}

/// Fail fast at create time if `local` can't be bound (the common "port already
/// in use" misconfig), with a clean message. The listener is dropped
/// immediately; the flow supervisor binds the port for real when it starts
/// (once, for the flow's life — FR-86 P1), so this is only a validation probe
/// — the tiny TOCTOU window before the supervisor's bind is a non-issue for an
/// operator-paced create.
async fn probe_local_port(local: u16) -> std::result::Result<(), String> {
    if local == 0 {
        return Err("local port must not be 0".into());
    }
    match tokio::net::TcpListener::bind(("127.0.0.1", local)).await {
        Ok(l) => {
            drop(l);
            Ok(())
        }
        Err(e) => Err(format!("local port {local} is not available: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roomler_ai_remote_control::signaling::CloseReason;
    use serde_json::json;

    fn oid(byte: u8) -> ObjectId {
        ObjectId::from_bytes([byte; 12])
    }

    #[test]
    fn parse_transport_maps_words_and_defaults() {
        assert_eq!(parse_transport("quic"), TransportPref::Quic);
        assert_eq!(parse_transport("QUIC-V1"), TransportPref::Quic);
        assert_eq!(parse_transport("webrtc"), TransportPref::Webrtc);
        assert_eq!(parse_transport("auto"), TransportPref::Auto);
        assert_eq!(parse_transport(""), TransportPref::Auto);
        assert_eq!(parse_transport("garbage"), TransportPref::Auto);
        assert_eq!(transport_word(TransportPref::Auto), "auto");
        assert_eq!(transport_word(TransportPref::Quic), "quic");
        assert_eq!(transport_word(TransportPref::Webrtc), "webrtc");
    }

    #[test]
    fn parse_host_port_variants() {
        assert_eq!(parse_host_port("db:5432").unwrap(), ("db".into(), 5432));
        assert_eq!(parse_host_port("[::1]:80").unwrap(), ("::1".into(), 80));
        assert!(parse_host_port("noport").is_err());
        assert!(parse_host_port(":5432").is_err());
        assert!(parse_host_port("h:99999").is_err());
    }

    #[test]
    fn parse_node_rejects_non_object_id() {
        assert!(parse_node("nope").is_err());
        assert!(parse_node("0123456789abcdef01234567").is_ok());
    }

    /// The demux is the crux (Risk 1). Lock each routing decision: pre-session
    /// nonce, post-session id, bidirectional pass-through, target-only
    /// pass-through, and open-failure.
    #[tokio::test]
    async fn demux_routes_by_nonce_then_session_id() {
        let hub = TunnelClientHub::new("test".into());
        let sid = oid(7);
        let (tx, mut rx) = mpsc::channel::<ServerMsg>(16);
        hub.inner
            .pending_opens
            .lock()
            .unwrap()
            .insert("n1".into(), tx);

        // (a) TunnelOpened with our nonce is consumed, promoted, and delivered.
        let opened = ServerMsg::TunnelOpened {
            session_id: sid,
            transport: "quic-v1".into(),
            dc_pool_size: 4,
            sctp_rwnd_bytes: 0,
            ice_servers: vec![],
            quic_auth_token: None,
            open_nonce: Some("n1".into()),
            net_grant_id: None,
        };
        assert!(hub.intercept(opened).is_none(), "opened consumed by nonce");
        assert!(matches!(rx.try_recv(), Ok(ServerMsg::TunnelOpened { .. })));
        assert!(hub.inner.pending_opens.lock().unwrap().is_empty());
        assert!(hub.inner.client_sessions.lock().unwrap().contains_key(&sid));

        // (b) A post-open client-bound variant for that session is consumed.
        let accept = ServerMsg::TcpForwardAccept {
            session_id: sid,
            flow_id: 1,
            dc_index: 0,
        };
        assert!(hub.intercept(accept).is_none(), "accept routed by session");
        assert!(matches!(
            rx.try_recv(),
            Ok(ServerMsg::TcpForwardAccept { .. })
        ));

        // (c) The SAME variant for an UNKNOWN session passes through (target).
        let other = ServerMsg::TcpForwardAccept {
            session_id: oid(9),
            flow_id: 2,
            dc_index: 0,
        };
        assert!(
            hub.intercept(other).is_some(),
            "unknown session passes through"
        );

        // (d) A bidirectional variant (TunnelIce) for our session is consumed…
        let ice_ours = ServerMsg::TunnelIce {
            session_id: sid,
            candidate: json!({}),
        };
        assert!(hub.intercept(ice_ours).is_none());
        // …but for an unknown session passes through to the target side.
        let ice_target = ServerMsg::TunnelIce {
            session_id: oid(9),
            candidate: json!({}),
        };
        assert!(hub.intercept(ice_target).is_some());

        // (e) A target-only variant (TunnelSdpOffer) always passes through.
        let offer = ServerMsg::TunnelSdpOffer {
            shared_lease: None,
            session_id: sid,
            sdp: "x".into(),
        };
        assert!(hub.intercept(offer).is_some(), "target-only passes through");
    }

    #[tokio::test]
    async fn demux_open_failure_error_resolves_pending_nonce() {
        let hub = TunnelClientHub::new("test".into());
        let (tx, mut rx) = mpsc::channel::<ServerMsg>(16);
        hub.inner
            .pending_opens
            .lock()
            .unwrap()
            .insert("n2".into(), tx);

        let err = ServerMsg::Error {
            session_id: None,
            code: "cross_tenant".into(),
            message: "nope".into(),
            open_nonce: Some("n2".into()),
        };
        assert!(
            hub.intercept(err).is_none(),
            "open-failure Error consumed by nonce"
        );
        assert!(matches!(rx.try_recv(), Ok(ServerMsg::Error { .. })));
        assert!(hub.inner.pending_opens.lock().unwrap().is_empty());

        // A nonceless Error (old server / target-side) passes through.
        let bare = ServerMsg::Error {
            session_id: None,
            code: "x".into(),
            message: "y".into(),
            open_nonce: None,
        };
        assert!(hub.intercept(bare).is_some());
    }

    #[tokio::test]
    async fn demux_terminate_is_bidirectional() {
        let hub = TunnelClientHub::new("test".into());
        let sid = oid(3);
        let (tx, _rx) = mpsc::channel::<ServerMsg>(16);
        hub.inner.client_sessions.lock().unwrap().insert(sid, tx);

        // Our session → consumed.
        let ours = ServerMsg::TunnelTerminate {
            session_id: sid,
            reason: CloseReason::ServerTerminated,
        };
        assert!(hub.intercept(ours).is_none());
        // Someone else's → passes through to the target-side handler.
        let target = ServerMsg::TunnelTerminate {
            session_id: oid(4),
            reason: CloseReason::ServerTerminated,
        };
        assert!(hub.intercept(target).is_some());
    }

    #[test]
    fn flows_snapshot_reflects_registered_flows() {
        let hub = TunnelClientHub::new("test".into());
        // No live sink, so the supervisor just parks in Connecting — but the
        // registry + snapshot are exercised without a running session.
        let live = Arc::new(FlowLive::default());
        let handle = tokio::runtime::Runtime::new().unwrap();
        let abort = handle.spawn(async {}).abort_handle();
        hub.inner.flows.lock().unwrap().insert(
            "fl-1".into(),
            FlowHandle {
                abort,
                kind: FlowKind::Forward,
                local: 5432,
                target: Some("db:5432".into()),
                node: "0123456789abcdef01234567".into(),
                requested: "auto".into(),
                live: live.clone(),
            },
        );
        let snap = hub.flows_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, "fl-1");
        assert_eq!(snap[0].local_addr, "127.0.0.1:5432");
        assert_eq!(snap[0].target.as_deref(), Some("db:5432"));
        // Not yet up → the transport column shows the liveness word.
        assert_eq!(snap[0].transport, "connecting");

        // Once a session negotiates, the concrete transport shows.
        *live.status.lock().unwrap() = FlowStatus::Up;
        *live.transport.lock().unwrap() = Some("quic-v1".into());
        assert_eq!(hub.flows_snapshot()[0].transport, "quic-v1");

        // P3b-3: throughput surfaces from the flow's shared SessionThroughput.
        live.throughput.bytes_in.fetch_add(1234, Ordering::Relaxed);
        live.throughput.bytes_out.fetch_add(5678, Ordering::Relaxed);
        live.throughput.active_flows.fetch_add(2, Ordering::Relaxed);
        let snap = hub.flows_snapshot();
        assert_eq!(snap[0].bytes_in, 1234);
        assert_eq!(snap[0].bytes_out, 5678);
        assert_eq!(snap[0].active_flows, 2);

        // kill removes it from the registry.
        assert!(hub.kill_flow("fl-1"));
        assert!(hub.flows_snapshot().is_empty());
        assert!(!hub.kill_flow("fl-1"), "second kill is a no-op false");
    }

    /// #1685 — `rc:tunnel.opened` is the SERVER accepting the open. The data
    /// plane (QUIC / DC pool) and the local listener come after it and can
    /// still fail — in the field the opens toward an offline laptop were
    /// accepted and then died in setup, every cycle — so seeing it must not
    /// mark the flow `Up`. `Up` is what the reconciler and the peers overlay
    /// read as "this port serves"; only the bound listener may set it.
    #[tokio::test]
    async fn tunnel_opened_alone_does_not_mark_the_flow_up() {
        let live = Arc::new(FlowLive::default());
        let (tx, rx) = mpsc::channel::<ServerMsg>(4);
        let mut source = ChannelSource {
            rx,
            live: live.clone(),
        };
        tx.send(ServerMsg::TunnelOpened {
            session_id: oid(9),
            transport: "webrtc-dc-v1".into(),
            dc_pool_size: 4,
            sctp_rwnd_bytes: 0,
            ice_servers: vec![],
            quic_auth_token: None,
            open_nonce: Some("fl-9.1".into()),
            net_grant_id: None,
        })
        .await
        .unwrap();
        assert!(matches!(
            source.recv().await,
            Some(ServerMsg::TunnelOpened { .. })
        ));
        // The informational cells ARE recorded from the frame…
        assert_eq!(
            live.transport.lock().unwrap().as_deref(),
            Some("webrtc-dc-v1")
        );
        assert_eq!(*live.session_id.lock().unwrap(), Some(oid(9)));
        // …but liveness is not: no listener has been bound.
        assert_ne!(
            *live.status.lock().unwrap(),
            FlowStatus::Up,
            "rc:tunnel.opened must not read as a serving listener"
        );
    }

    /// #1685 — the cells the route reconciler reads: a failed attempt counts
    /// and carries its error plus the countdown; the bind hook is what flips
    /// the flow to `Up`, and it forgets the failures before it.
    #[tokio::test]
    async fn flow_report_follows_failures_and_the_listener_bind() {
        let hub = TunnelClientHub::new("test".into());
        let live = Arc::new(FlowLive::default());
        let abort = tokio::spawn(async {}).abort_handle();
        hub.inner.flows.lock().unwrap().insert(
            "fl-7".into(),
            FlowHandle {
                abort,
                kind: FlowKind::Socks5,
                local: 1081,
                target: None,
                node: "0123456789abcdef01234567".into(),
                requested: "auto".into(),
                live: live.clone(),
            },
        );
        assert_eq!(hub.flow_report("ghost"), None);

        // Fresh: dialing, nothing failed yet.
        let fresh = hub.flow_report("fl-7").unwrap();
        assert!(!fresh.listening);
        assert_eq!(fresh.failures, 0);
        assert_eq!(fresh.last_error, None);
        assert_eq!(fresh.next_retry_in, None);

        // Two failed cycles, the supervisor now sleeping 4 s.
        live.note_failure("first".into());
        live.note_failure(
            "server error during tunnel.open: agent_unavailable: agent is offline".into(),
        );
        live.note_backoff(Duration::from_secs(4));
        let retrying = hub.flow_report("fl-7").unwrap();
        assert!(!retrying.listening, "a retrying flow does not serve");
        assert_eq!(retrying.failures, 2);
        assert_eq!(
            retrying.last_error.as_deref(),
            Some("server error during tunnel.open: agent_unavailable: agent is offline"),
            "the LAST error is what the reader acts on"
        );
        let left = retrying.next_retry_in.expect("sleeping ⇒ a countdown");
        assert!(
            left <= Duration::from_secs(4) && left > Duration::from_secs(2),
            "{left:?}"
        );
        // The Flows table shows the liveness word, not a negotiated transport…
        assert_eq!(
            hub.negotiated_transport("fl-7"),
            None,
            "no open answered yet"
        );
        *live.transport.lock().unwrap() = Some("webrtc-dc-v1".into());
        assert_eq!(hub.flows_snapshot()[0].transport, "connecting");
        // …while the transport the open negotiated is still readable.
        assert_eq!(
            hub.negotiated_transport("fl-7").as_deref(),
            Some("webrtc-dc-v1")
        );
        assert_eq!(hub.negotiated_transport("ghost"), None);

        // The node came back: the supervisor installed a carrier behind the
        // flow's listener (FR-86 P1 — the port itself was bound all along).
        live.mark_listening();
        let serving = hub.flow_report("fl-7").unwrap();
        assert_eq!(
            serving,
            FlowReport {
                listening: true,
                fatal: None,
                failures: 0,
                last_error: None,
                next_retry_in: None,
            }
        );
        assert_eq!(hub.flows_snapshot()[0].transport, "webrtc-dc-v1");
        assert!(
            hub.active_flow_agent_ids()
                .contains("0123456789abcdef01234567")
        );
    }

    /// FR-86 P1 (AC3, the daemon path): the flow's listener is bound by the
    /// supervisor BEFORE any session exists, so a client that connects while
    /// no carrier is ready is accepted and held — never refused — while the
    /// flow still reads `connecting` (a held connection is not a serving
    /// route). `kill_flow` during that gap releases the held connection (the
    /// client sees EOF) and unbinds the port. With no agent WS published the
    /// supervisor parks in `wait_for_sink`, which is exactly the gap. NC86B
    /// (no hold: closed on arrival) turns the first half red; NC86E (the
    /// accept task outlives the listener) the second.
    #[tokio::test]
    async fn a_client_connecting_before_any_carrier_is_held_and_released_by_kill_flow() {
        use tokio::io::AsyncReadExt;
        let hub = TunnelClientHub::new("test".into());
        let port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let id = hub
            .create_forward("0123456789abcdef01234567", port, "db:5432", "webrtc", "")
            .await
            .expect("create_forward");

        // The supervisor binds asynchronously; a client connecting right after
        // create must be ACCEPTED (held), not refused — poll the bind briefly.
        let mut client = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(s) => {
                    client = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let mut client =
            client.expect("the flow's listener must be bound before any carrier exists");
        // Held: open and quiet, and the flow does NOT claim to serve.
        let mut buf = [0u8; 4];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf))
                .await
                .is_err(),
            "a connection arriving before a carrier must be held open, not closed"
        );
        let report = hub.flow_report(&id).expect("registered");
        assert!(
            !report.listening,
            "a held connection is not a serving route"
        );
        assert_eq!(hub.flows_snapshot()[0].transport, "connecting");

        // kill_flow in the gap: the held client is released, the port freed.
        assert!(hub.kill_flow(&id));
        match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("expected the held connection to close, read {n} bytes"),
            Err(_) => panic!("the held connection must be released when the flow is killed"),
        }
        let mut rebound = false;
        for _ in 0..40 {
            if tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .is_ok()
            {
                rebound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(rebound, "kill_flow must unbind the flow's port");
    }

    /// #1685 — the route row already names the flow, so the supervisor's
    /// `tunnel session (flow fl-N): ` context is dropped from the error it
    /// publishes; an error without that prefix is kept whole.
    #[test]
    fn session_error_summary_drops_the_flow_context_only() {
        let inner = "server error during tunnel.open: agent_unavailable: agent is offline";
        let wrapped = anyhow::anyhow!("{inner}").context("tunnel session (flow fl-2)");
        assert_eq!(session_error_summary(&wrapped), inner);
        let chained = anyhow::anyhow!("deadline has elapsed")
            .context("waiting for DC pool to open")
            .context("tunnel session (flow fl-12)");
        assert_eq!(
            session_error_summary(&chained),
            "waiting for DC pool to open: deadline has elapsed"
        );
        let bare = anyhow::anyhow!("agent WS egress closed");
        assert_eq!(session_error_summary(&bare), "agent WS egress closed");
    }

    #[test]
    fn active_flow_agent_ids_returns_only_up_flow_nodes() {
        // P3b-3: the Tunnel-override join reads this — only `Up` flows count, so
        // a connecting / backing-off flow doesn't prematurely claim Tunnel.
        let hub = TunnelClientHub::new("test".into());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mk = |node: &str, status: FlowStatus| {
            let live = Arc::new(FlowLive::default());
            *live.status.lock().unwrap() = status;
            FlowHandle {
                abort: rt.spawn(async {}).abort_handle(),
                kind: FlowKind::Forward,
                local: 1,
                target: None,
                node: node.into(),
                requested: "auto".into(),
                live,
            }
        };
        {
            let mut flows = hub.inner.flows.lock().unwrap();
            flows.insert("fl-1".into(), mk("aid-up", FlowStatus::Up));
            flows.insert("fl-2".into(), mk("aid-connecting", FlowStatus::Connecting));
            flows.insert("fl-3".into(), mk("aid-down", FlowStatus::Down));
        }
        let ids = hub.active_flow_agent_ids();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains("aid-up"));
        assert!(!ids.contains("aid-connecting"));
        assert!(!ids.contains("aid-down"));
    }

    #[tokio::test]
    async fn publish_sink_is_visible_to_a_later_subscriber() {
        // Regression (found via the E2E test): a flow supervisor subscribes only
        // when its flow is created, which can be AFTER the first WS connect
        // published the sink. `watch::Sender::send` silently drops the value when
        // there are no receivers yet, so a plain `send` left the value `None` and
        // the supervisor hung at wait_for_sink forever. `publish_sink` must use
        // `send_replace` so a LATER subscriber still sees the live sink.
        let hub = TunnelClientHub::new("t".into());
        let (tx, _rx) = mpsc::channel::<ClientMsg>(1);
        let _guard = hub.publish_sink(tx); // published with NO subscriber yet
        let mut sink_rx = hub.inner.sink_tx.subscribe();
        assert!(
            sink_rx.borrow_and_update().is_some(),
            "a subscriber created after publish_sink must see the live egress"
        );
        // Dropping the guard clears it (also visible to the existing subscriber).
        drop(_guard);
        assert!(
            sink_rx.borrow_and_update().is_none(),
            "the guard clears the sink on drop"
        );
    }

    /// Field 2026-08-22: a flow that opened and died at once reset the
    /// backoff every cycle, pinning the supervisor to its 1 s floor forever
    /// and rebuilding a full WebRTC peer each time. The ladder existed; the
    /// missing part was requiring that the session actually ran.
    #[test]
    fn a_session_that_dies_on_arrival_does_not_earn_a_backoff_reset() {
        assert!(
            !super::session_ran(Duration::from_millis(200)),
            "a 200 ms session is a failure, not a healthy reconnect"
        );
        assert!(
            !super::session_ran(super::SESSION_RAN_THRESHOLD - Duration::from_millis(1)),
            "just under the threshold must still back off"
        );
        assert!(
            super::session_ran(super::SESSION_RAN_THRESHOLD),
            "at the threshold the session ran"
        );
        assert!(
            super::session_ran(Duration::from_secs(3600)),
            "a long-lived session that drops earns the near-instant re-open"
        );
    }

    /// The floor must stay below the threshold, or a session could never both
    /// fail fast AND be retried promptly — the ladder would be all-or-nothing.
    #[test]
    fn the_backoff_ladder_is_ordered() {
        assert!(super::RECONNECT_BACKOFF_MIN < super::RECONNECT_BACKOFF_MAX);
        assert!(super::RECONNECT_BACKOFF_MIN < super::SESSION_RAN_THRESHOLD);
    }

    // ─────────────────────── FR-86 P2 ───────────────────────

    /// The probe schedule: first probe at 60 s, then 2 → 5 → 15 → 60 min, capped,
    /// and reset returns to the first-probe delay. NC86P2N (on_failure a no-op)
    /// turns this red.
    #[test]
    fn reupgrade_backoff_ladder_and_reset() {
        let m = 60;
        let mut b = ReupgradeBackoff::new();
        assert_eq!(b.delay(), Duration::from_secs(60), "first probe at 60 s");
        b.on_failure();
        assert_eq!(b.delay(), Duration::from_secs(2 * m));
        b.on_failure();
        assert_eq!(b.delay(), Duration::from_secs(5 * m));
        b.on_failure();
        assert_eq!(b.delay(), Duration::from_secs(15 * m));
        b.on_failure();
        assert_eq!(b.delay(), Duration::from_secs(60 * m), "capped at 60 min");
        b.on_failure();
        assert_eq!(b.delay(), Duration::from_secs(60 * m), "stays capped");
        b.reset();
        assert_eq!(
            b.delay(),
            Duration::from_secs(60),
            "reset returns to the first-probe delay"
        );
    }

    /// The probe timer maps the ladder onto concrete deadlines relative to an
    /// injected `now`.
    #[tokio::test]
    async fn probe_timer_deadlines_follow_the_ladder() {
        let base = tokio::time::Instant::now();
        let mut t = ProbeTimer::armed(base);
        assert_eq!(t.deadline().duration_since(base), Duration::from_secs(60));
        t.on_failure(base);
        assert_eq!(t.deadline().duration_since(base), Duration::from_secs(120));
        t.on_failure(base);
        assert_eq!(t.deadline().duration_since(base), Duration::from_secs(300));
        t.reset(base);
        assert_eq!(t.deadline().duration_since(base), Duration::from_secs(60));
    }

    /// Ranking + "below best": webrtc-dc and quic-derp are below quic-v1 (so they
    /// probe); quic-v1 is the ceiling (no probe). quic-derp is only OFFERED as a
    /// candidate where derp fallback is enabled.
    #[test]
    fn transport_ranking_and_better_set() {
        assert!(transport_rank(TRANSPORT_QUIC_V1) > transport_rank(TRANSPORT_QUIC_DERP_V1));
        assert!(transport_rank(TRANSPORT_QUIC_DERP_V1) > transport_rank(TRANSPORT_WEBRTC_DC_V1));
        assert_eq!(transport_rank("something-newer"), 0);

        // active webrtc-dc, derp off: only quic-v1 is a candidate.
        assert_eq!(
            better_transports(TRANSPORT_WEBRTC_DC_V1, false),
            vec![TRANSPORT_QUIC_V1]
        );
        // active webrtc-dc, derp on: quic-v1 then quic-derp-v1.
        assert_eq!(
            better_transports(TRANSPORT_WEBRTC_DC_V1, true),
            vec![TRANSPORT_QUIC_V1, TRANSPORT_QUIC_DERP_V1]
        );
        // active quic-derp: only quic-v1 (never webrtc, never itself).
        assert_eq!(
            better_transports(TRANSPORT_QUIC_DERP_V1, true),
            vec![TRANSPORT_QUIC_V1]
        );
        // active quic-v1: nothing better → not below best.
        assert!(better_transports(TRANSPORT_QUIC_V1, true).is_empty());

        assert!(below_best(TRANSPORT_WEBRTC_DC_V1, false));
        assert!(below_best(TRANSPORT_QUIC_DERP_V1, true));
        assert!(!below_best(TRANSPORT_QUIC_V1, true));
    }

    /// A pinned `--transport` never probes, and the kill switch (off) disables
    /// probing for an `auto` flow. NC86P2K (reupgrade_active ignores `pref`)
    /// turns the pinned asserts red; NC86P2S (it ignores the kill switch) the
    /// kill-switch assert.
    #[test]
    fn reupgrade_gate_respects_pinned_and_kill_switch() {
        assert!(
            reupgrade_active(TransportPref::Auto, true),
            "auto + on ⇒ probes"
        );
        assert!(
            !reupgrade_active(TransportPref::Auto, false),
            "kill switch off ⇒ no probe"
        );
        assert!(
            !reupgrade_active(TransportPref::Quic, true),
            "pinned quic ⇒ never probes"
        );
        assert!(
            !reupgrade_active(TransportPref::Webrtc, true),
            "pinned webrtc ⇒ never probes"
        );
    }

    /// The kill switch is wired to the env flag: default ON, `0` turns it off,
    /// `1` back on. NC86P2E (`reupgrade_enabled` hardcoded `true`) turns the
    /// `=0` assert red. Serialised via the env `Saved` guard so it restores
    /// whatever the host had.
    #[test]
    fn kill_switch_reads_the_env() {
        let _saved = tunnel_core::env::test_env::Saved::cleared("TUNNEL_REUPGRADE");
        assert!(reupgrade_enabled(), "default is ON");
        unsafe { tunnel_core::env::test_env::set("TUNNEL_REUPGRADE", "0") };
        assert!(
            !reupgrade_enabled(),
            "ROOMLERD_TUNNEL_REUPGRADE=0 turns it off"
        );
        unsafe { tunnel_core::env::test_env::set("TUNNEL_REUPGRADE", "1") };
        assert!(reupgrade_enabled(), "=1 turns it back on");
    }

    /// The start-transport test lever maps its word to a concrete first-session
    /// request; `auto`/empty/unknown ⇒ no override.
    #[test]
    fn start_request_transport_maps_the_lever_word() {
        assert_eq!(
            start_request_transport("webrtc"),
            Some(TRANSPORT_WEBRTC_DC_V1)
        );
        assert_eq!(start_request_transport("quic"), Some(TRANSPORT_QUIC_V1));
        assert_eq!(start_request_transport("auto"), None);
        assert_eq!(start_request_transport(""), None);
        assert_eq!(start_request_transport("nonsense"), None);
    }

    /// A fake carrier for the drain reaper: a settable in-flight count, a signal
    /// to fire when it reaches 0, and a flag set on Drop so the test can see when
    /// the reaper actually released it.
    struct FakeDrain {
        active: Arc<AtomicU64>,
        idle: Arc<tokio::sync::Notify>,
        dead: Arc<tokio::sync::Notify>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
        /// #1816 — when set, Drop records whether the hub still routed the
        /// session at that moment: the reaper's order of ends, observed.
        entry_at_drop: Option<EntryAtDrop>,
    }

    /// What `FakeDrain`'s Drop looks at (#1816): is `sid` still in the hub's
    /// `client_sessions` as the carrier drops? `present` gets the answer.
    struct EntryAtDrop {
        hub: TunnelClientHub,
        sid: ObjectId,
        present: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for FakeDrain {
        fn drop(&mut self) {
            if let Some(e) = self.entry_at_drop.take() {
                // `try_lock`: a reaper that dropped the carrier while HOLDING
                // the demux lock would deadlock a `lock()` here — it fails the
                // order assertion instead.
                let present = e
                    .hub
                    .inner
                    .client_sessions
                    .try_lock()
                    .map(|m| m.contains_key(&e.sid))
                    .unwrap_or(false);
                e.present
                    .store(present, std::sync::atomic::Ordering::SeqCst);
            }
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl DrainableCarrier for FakeDrain {
        fn dead(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            let dead = self.dead.clone();
            Box::pin(async move { dead.notified().await })
        }
        fn drained(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            let active = self.active.clone();
            let idle = self.idle.clone();
            Box::pin(async move {
                loop {
                    let n = idle.notified();
                    tokio::pin!(n);
                    n.as_mut().enable();
                    if active.load(Ordering::SeqCst) == 0 {
                        return;
                    }
                    n.await;
                }
            })
        }
    }

    /// FR-86 P2 drain (the make-before-break guarantee at the supervisor's drop
    /// decision): a carrier the flow re-upgraded away from is NOT dropped while
    /// it still has a connection in flight — its established connections run to
    /// their natural end — and IS dropped (→ terminate) once its active count
    /// reaches 0. NC86P2P (drop the old carrier at once instead of draining)
    /// turns the "not dropped while active" assertion red — the "promote-by-cut".
    #[tokio::test]
    async fn drain_carrier_keeps_the_old_carrier_until_active_reaches_zero() {
        let active = Arc::new(AtomicU64::new(1));
        let idle = Arc::new(tokio::sync::Notify::new());
        let dead = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fake = Arc::new(FakeDrain {
            active: active.clone(),
            idle: idle.clone(),
            dead,
            dropped: dropped.clone(),
            entry_at_drop: None,
        });
        let hub = TunnelClientHub::new("t".into());
        let sid = oid(9);
        // Move the ONLY strong ref to the FakeDrain into the reaper.
        let reaper = tokio::spawn(drain_carrier(hub, sid, fake));

        // While a connection is in flight the reaper holds the carrier open.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !dropped.load(std::sync::atomic::Ordering::SeqCst),
            "a draining carrier is NOT dropped while it still carries a connection"
        );

        // The last connection ends: the reaper drops the carrier (→ terminate).
        active.store(0, Ordering::SeqCst);
        idle.notify_waiters();
        tokio::time::timeout(Duration::from_secs(2), reaper)
            .await
            .expect("reaper finishes once drained")
            .unwrap();
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "a drained carrier is dropped once its active count reaches 0"
        );
    }

    /// The dead-first path: if a draining carrier dies before it drains, the
    /// reaper drops it at once (no leak).
    #[tokio::test]
    async fn drain_carrier_drops_on_death_before_it_drains() {
        let active = Arc::new(AtomicU64::new(1)); // never reaches 0
        let idle = Arc::new(tokio::sync::Notify::new());
        let dead = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fake = Arc::new(FakeDrain {
            active,
            idle,
            dead: dead.clone(),
            dropped: dropped.clone(),
            entry_at_drop: None,
        });
        let hub = TunnelClientHub::new("t".into());
        let reaper = tokio::spawn(drain_carrier(hub, oid(10), fake));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        dead.notify_waiters();
        tokio::time::timeout(Duration::from_secs(2), reaper)
            .await
            .expect("reaper finishes on death")
            .unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// #1816 — the reaper is ABORTED mid-drain (`kill_flow` aborts the flow
    /// supervisor, whose `drains` drop; a supervisor return does the same): it
    /// still ends the carrier (→ terminate) AND reaps the demux entry the
    /// promotion left registered for the old session — the carrier first, while
    /// the entry still routes. Before the guard the reap was the reaper's last
    /// line, so an abort dropped the carrier and leaked the entry for the life
    /// of the daemon. NC1816-1 (the reap back on the reaper's last line) turns
    /// the "reaped its demux entry" assertion red; NC1816-1b (the entry reaped
    /// before the carrier drops) the order assertion.
    #[tokio::test]
    async fn an_aborted_drain_reaper_still_reaps_its_demux_entry_carrier_first() {
        let hub = TunnelClientHub::new("t".into());
        let sid = oid(11);
        // What a promotion leaves behind: the old session's demux entry, now
        // the reaper's to reap.
        let (tx, _rx) = mpsc::channel::<ServerMsg>(1);
        hub.inner.client_sessions.lock().unwrap().insert(sid, tx);

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let entry_present_at_drop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fake = Arc::new(FakeDrain {
            active: Arc::new(AtomicU64::new(1)), // never drains
            idle: Arc::new(tokio::sync::Notify::new()),
            dead: Arc::new(tokio::sync::Notify::new()), // never dies
            dropped: dropped.clone(),
            entry_at_drop: Some(EntryAtDrop {
                hub: hub.clone(),
                sid,
                present: entry_present_at_drop.clone(),
            }),
        });
        let reaper = tokio::spawn(drain_carrier(hub.clone(), sid, fake));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !dropped.load(Ordering::SeqCst),
            "parked in its select!, the reaper holds the carrier"
        );
        assert!(hub.inner.client_sessions.lock().unwrap().contains_key(&sid));

        // What `kill_flow` does to a reaper: abort it, mid-select!.
        reaper.abort();
        let err = tokio::time::timeout(Duration::from_secs(2), reaper)
            .await
            .expect("an aborted reaper finishes")
            .expect_err("aborted, not completed");
        assert!(err.is_cancelled());

        assert!(
            dropped.load(Ordering::SeqCst),
            "the aborted reaper dropped the carrier (→ terminate)"
        );
        assert!(
            !hub.inner.client_sessions.lock().unwrap().contains_key(&sid),
            "the aborted reaper reaped its demux entry"
        );
        assert!(
            entry_present_at_drop.load(Ordering::SeqCst),
            "the carrier is dropped BEFORE the entry is removed (and never under the demux lock)"
        );
    }

    /// FR-90 P3-7-3a — a session's grant the server refused or did not bind
    /// ends the flow: opening again would present the same grant to the same
    /// server. Known by its type through the context the supervisor wraps it
    /// in, while an ordinary open failure stays retryable.
    #[test]
    fn a_refused_or_unbound_grant_ends_the_flow() {
        for e in [
            GrantError::NotBound,
            GrantError::Refused("a grant for another exit".into()),
        ] {
            let wrapped = anyhow::Error::from(e.clone()).context("tunnel session (flow fl-1)");
            assert!(permanent_session_error(&wrapped).is_some(), "{e}");
        }
        let ordinary = anyhow::anyhow!("server error during tunnel.open: agent_offline: gone");
        assert!(permanent_session_error(&ordinary).is_none());
    }

    /// FR-90 P3-7-3b — a session's flow listens on a port the system picks,
    /// bound before `create_session_flow` returns; holds a connection its hook
    /// admits and closes one it does not; and ends at its grant's end,
    /// releasing what it held and unbinding its port. With no agent WS the
    /// supervisor parks in `wait_for_sink`, so nothing else ends it.
    #[tokio::test]
    async fn a_session_flow_serves_whom_it_admits_and_ends_with_its_grant() {
        use std::sync::atomic::AtomicBool;
        use tokio::io::AsyncReadExt;
        let hub = TunnelClientHub::new("test".into());
        let allow = Arc::new(AtomicBool::new(true));
        let gate = Arc::clone(&allow);
        let admit: Admit = Arc::new(move |_tcp: &tokio::net::TcpStream, _local| {
            if gate.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err("another account".into())
            }
        });
        let until = std::time::Instant::now() + Duration::from_secs(3);
        let grant = SessionGrantRef {
            token: "a.b.c".into(),
            grant_id: "g1".into(),
        };
        let target = Target::Static {
            host: "db.internal".into(),
            port: 5432,
        };
        let (id, addr) = hub
            .create_session_flow(ObjectId::new(), target, grant, until, admit)
            .await
            .expect("created");
        assert_ne!(addr.port(), 0, "a port the system picked");
        assert!(hub.has_flow(&id));

        // Bound already: an admitted connection is held, open and quiet.
        let mut held = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 4];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), held.read(&mut buf))
                .await
                .is_err(),
            "held open"
        );
        // One the hook does not admit is closed at once, while the flow lives
        // on: the hook closed it, not the grant's end.
        allow.store(false, Ordering::SeqCst);
        let mut refused = tokio::net::TcpStream::connect(addr).await.unwrap();
        match tokio::time::timeout(Duration::from_millis(500), refused.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("a connection not admitted must be closed at once: {other:?}"),
        }
        assert!(
            hub.has_flow(&id),
            "closed by the hook, not by the grant's end"
        );

        // At the grant's end: the flow is gone, what it held released, its
        // port unbound.
        match tokio::time::timeout(Duration::from_secs(5), held.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("the held connection outlived its grant: {other:?}"),
        }
        assert!(!hub.has_flow(&id), "the flow ended with its grant");
        let mut rebound = false;
        for _ in 0..40 {
            if tokio::net::TcpListener::bind(addr).await.is_ok() {
                rebound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(rebound, "its port is unbound");
    }
}
