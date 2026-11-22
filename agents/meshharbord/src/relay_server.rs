// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-19 — start the org-relay server, if this device opted in.
//!
//! Process-wide and started once: the relay owns a single UDP socket, so it is
//! deliberately **not** per-org like [`crate::overlay::maybe_start`].
//!
//! # The default path costs nothing
//!
//! `relay_server_enabled` is FR-19's gate 4 — the refusal that survives a
//! compromised server — and it is opt-in, so a device that has not explicitly
//! turned this on binds no socket, spawns no task and logs nothing.
//!
//! # A failed bind is loud, and a successful one is not a promise
//!
//! If the port cannot be bound the daemon says so at `error!` with the reason,
//! rather than starting a relay that silently never answers. And the success
//! line states plainly that **binding is not reachability**: on a host with a
//! coturn DNAT the port is consumed in `PREROUTING` while `ss -ulnp` shows it
//! free and the socket receives nothing. That is not hypothetical — it is what
//! mars does, and it is why FR-19's E2E-3 nearly reached the opposite
//! conclusion about which port corporate egresses permit.
//!
//! # P2c: it forwards now
//!
//! Since P2c the socket is served by [`RelayServer`], which answers probes,
//! runs the authenticated bind, and forwards ciphertext between bound
//! members. Sessions still enter only through [`handle`] — P3 wires that to
//! the control-WS mint. Until then a relay serves probes and holds no sessions,
//! which is exactly P1's behaviour.

use bson::oid::ObjectId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use tokio::sync::watch;
use tunnel_core::overlay::orgrelay::backbone::{self, AuthorizedBridgeGrant, BridgeLeg};

use tunnel_core::overlay::orgrelay;
use tunnel_core::overlay::orgrelay::bind::CookieKey;
use tunnel_core::overlay::orgrelay::responder::ResponderCounts;
use tunnel_core::overlay::orgrelay::server::{RelayCounts, RelayHandle, RelayServer, RelayStats};

/// Process-wide listener snapshot populated while bound and cleared on stop.
static RUNNING: OnceLock<RwLock<Option<Running>>> = OnceLock::new();
static CONTROLLER: OnceLock<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>> =
    OnceLock::new();

fn running_slot() -> &'static RwLock<Option<Running>> {
    RUNNING.get_or_init(|| RwLock::new(None))
}

fn controller_lock() -> &'static tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>> {
    CONTROLLER.get_or_init(|| tokio::sync::Mutex::new(None))
}

#[derive(Clone)]
struct Running {
    listening: String,
    stats: Arc<RelayStats>,
    handle: RelayHandle,
    readiness: watch::Receiver<Option<u16>>,
    bridges: Arc<Mutex<HashMap<ObjectId, NativeBridge>>>,
}
struct NativeBridge {
    generation: u64,
    task: tokio::task::JoinHandle<()>,
    // Observability only: no authorization or forwarding behavior differs.
    // Linux-only because every reader (the backbone tests and
    // `backbone_test_support`) is Linux-only.
    #[cfg(all(any(test, feature = "backbone-test-support"), target_os = "linux"))]
    sockets: watch::Receiver<Option<[std::net::SocketAddr; 2]>>,
}
#[cfg(all(any(test, feature = "backbone-test-support"), target_os = "linux"))]
struct BridgeSocketEvidence(watch::Sender<Option<[std::net::SocketAddr; 2]>>);
#[cfg(all(any(test, feature = "backbone-test-support"), target_os = "linux"))]
impl Drop for BridgeSocketEvidence {
    fn drop(&mut self) {
        self.0.send_replace(None);
    }
}
impl Drop for NativeBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// A listener's lifetime, not config intent. Overlay joins subscribe to this
// process-wide channel; no tunnel-core dependency on the daemon is needed.
static READINESS: OnceLock<watch::Sender<Option<u16>>> = OnceLock::new();

fn readiness_sender() -> &'static watch::Sender<Option<u16>> {
    READINESS.get_or_init(|| watch::channel(None).0)
}

/// Subscribe to actual listener lifetime for overlay join/rejoin advertisement.
pub fn readiness() -> watch::Receiver<Option<u16>> {
    readiness_sender().subscribe()
}

/// Actual bound port; None before bind, after failure, or after task teardown.
pub fn listening_port() -> Option<u16> {
    *readiness_sender().borrow()
}

fn active_running() -> Option<Running> {
    running_slot()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .filter(|r| r.readiness.borrow().is_some())
}

struct ServingGuard {
    bridges: Arc<Mutex<HashMap<ObjectId, NativeBridge>>>,
    readiness: watch::Sender<Option<u16>>,
    reporter: tokio::task::JoinHandle<()>,
}

impl Drop for ServingGuard {
    fn drop(&mut self) {
        self.readiness.send_replace(None);
        self.bridges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.reporter.abort();
    }
}

/// Probe counters, or `None` when this node is not serving. Feeds the P1
/// `NodeStatus::org_relay` field.
pub fn stats() -> Option<ResponderCounts> {
    active_running().map(|r| r.stats.snapshot().probe)
}

/// The full relay counters, or `None` when not serving.
pub fn relay_stats() -> Option<RelayCounts> {
    active_running().map(|r| r.stats.snapshot())
}

/// The bound address and probe counters, or `None` when not serving. Feeds
/// `NodeStatus::org_relay`, so `mh status` answers "is it working?"
/// immediately instead of waiting out the report loop's 300 s window.
pub fn status() -> Option<(String, ResponderCounts)> {
    active_running().map(|r| (r.listening.clone(), r.stats.snapshot().probe))
}

/// The session-install handle, or `None` when not serving. P3 uses this to
/// install and revoke sessions from the control-WS mint messages.
pub fn handle() -> Option<RelayHandle> {
    active_running().map(|r| r.handle.clone())
}

/// How often the counters are summarised into the log. `mh status` is
/// the immediate reader; this is the historical one.
const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// Bind before the daemon constructs its first hello or overlay join. A
/// configured but occupied listener remains a normal client. Still opt-in.
pub async fn maybe_start() {
    if !orgrelay::relay_server_enabled() {
        return;
    }
    set_serving(true).await;
}

/// Dynamically start or stop the process-wide UDP org-relay listener.
/// Starting publishes `Some(port)` on [`READINESS`], waking `signaling` to
/// re-advertise `RpcCap::RelayServer` and `OverlayRuntime` to rejoin with
/// `relay_port` & backbone readiness. Stopping aborts the listener & bridges
/// and publishes `None` on [`READINESS`].
pub async fn set_serving(serve: bool) -> bool {
    set_serving_on_port(serve, orgrelay::relay_server_port()).await
}

async fn set_serving_on_port(serve: bool, port: u16) -> bool {
    // FR-127 — the one place a listener is bound: a protected device refuses here, whoever
    // asked (startup config, env, or the control plane's serve push).
    let serve = if serve && orgrelay::device_protected() {
        tracing::warn!("org-relay: refused to serve as a relay: this device is protected");
        false
    } else {
        serve
    };
    let mut task_guard = controller_lock().lock().await;
    if serve {
        if listening_port().is_some() {
            return true;
        }
        match start_listener(port, readiness_sender().clone()).await {
            Ok((running, task)) => {
                tracing::info!(
                    listening = %running.listening,
                    "org-relay server dynamically started (binding is local; reachability still depends on firewall/NAT)"
                );
                *running_slot().write().unwrap_or_else(|e| e.into_inner()) = Some(running);
                *task_guard = Some(task);
                true
            }
            Err(e) => {
                tracing::error!(
                    port, error = %e,
                    "org-relay server NOT started: could not bind UDP listener; remaining a client"
                );
                false
            }
        }
    } else {
        *running_slot().write().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(task) = task_guard.take() {
            task.abort();
            let _ = task.await;
            tracing::info!("org-relay server dynamically stopped");
        }
        readiness_sender().send_replace(None);
        false
    }
}

static LAST_APPLIED_REVISION: OnceLock<tokio::sync::Mutex<Option<u64>>> = OnceLock::new();
static RUNTIME_SERVE: OnceLock<RwLock<Option<bool>>> = OnceLock::new();
static SERVER_BACKBONE_ENDPOINTS: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

fn last_applied_revision() -> &'static tokio::sync::Mutex<Option<u64>> {
    LAST_APPLIED_REVISION.get_or_init(|| tokio::sync::Mutex::new(None))
}

fn runtime_serve_slot() -> &'static RwLock<Option<bool>> {
    RUNTIME_SERVE.get_or_init(|| RwLock::new(None))
}

fn server_backbone_endpoints_slot() -> &'static RwLock<Vec<String>> {
    SERVER_BACKBONE_ENDPOINTS.get_or_init(|| RwLock::new(Vec::new()))
}

pub fn runtime_server_backbone_endpoints() -> Vec<String> {
    server_backbone_endpoints_slot()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyRevisionDecision {
    RejectStale,
    IdempotentReconnect(bool),
    ApplyNew,
}

fn classify_policy_revision(
    last_applied: &mut Option<u64>,
    runtime_serve: Option<bool>,
    revision: Option<u64>,
) -> PolicyRevisionDecision {
    match (revision, *last_applied, runtime_serve) {
        (Some(rev), Some(last), _) if rev < last => PolicyRevisionDecision::RejectStale,
        (None, Some(_), _) => PolicyRevisionDecision::RejectStale,
        (Some(rev), Some(last), Some(applied_serve)) if rev == last => {
            PolicyRevisionDecision::IdempotentReconnect(applied_serve)
        }
        (Some(rev), _, _) => {
            *last_applied = Some(rev);
            PolicyRevisionDecision::ApplyNew
        }
        (None, None, _) => PolicyRevisionDecision::ApplyNew,
    }
}

#[cfg(test)]
fn accept_policy_revision(last_applied: &mut Option<u64>, revision: Option<u64>) -> bool {
    !matches!(
        classify_policy_revision(last_applied, None, revision),
        PolicyRevisionDecision::RejectStale
    )
}

/// Reconcile against an authoritative `rc:overlay.peer_relay_serve` directive
/// from the primary organization's server: ignore stale revisions
/// (`revision < last_applied`), treat duplicate-equal revisions
/// (`Some(rev) == *last_applied` once `RUNTIME_SERVE` is initialized) as
/// idempotent reconnect deliveries without overwriting `RUNTIME_SERVE` or
/// `SERVER_BACKBONE_ENDPOINTS`, and on strictly newer revisions update the
/// runtime flag and server-authorized backbone endpoints, persist
/// `relay_server_enabled = Some(serve)` to `config.toml`, and start/stop
/// (or re-announce readiness on) the UDP relay listener.
pub async fn apply_server_policy(
    serve: bool,
    revision: Option<u64>,
    backbone_endpoints: &[String],
    remote_cfg: &crate::remote_config::RemoteConfigServices,
) -> bool {
    apply_server_policy_on_port(
        serve,
        revision,
        backbone_endpoints,
        remote_cfg,
        orgrelay::relay_server_port(),
    )
    .await
}

async fn apply_server_policy_on_port(
    serve: bool,
    revision: Option<u64>,
    backbone_endpoints: &[String],
    remote_cfg: &crate::remote_config::RemoteConfigServices,
    port: u16,
) -> bool {
    let mut last_applied = last_applied_revision().lock().await;
    let current_serve = *runtime_serve_slot()
        .read()
        .unwrap_or_else(|e| e.into_inner());
    match classify_policy_revision(&mut last_applied, current_serve, revision) {
        PolicyRevisionDecision::RejectStale => {
            tracing::debug!(
                serve,
                ?revision,
                last_applied = ?*last_applied,
                "org-relay: ignoring stale peer-relay policy directive"
            );
            return false;
        }
        PolicyRevisionDecision::IdempotentReconnect(applied_serve) => {
            if applied_serve {
                if listening_port().is_none() {
                    set_serving_on_port(true, port).await;
                }
                if let Some(bound_port) = listening_port() {
                    readiness_sender().send_replace(Some(bound_port));
                }
            } else if listening_port().is_some() {
                set_serving_on_port(false, port).await;
            }
            return true;
        }
        PolicyRevisionDecision::ApplyNew => {}
    }

    let next_endpoints = if serve {
        backbone_endpoints.to_vec()
    } else {
        Vec::new()
    };
    let endpoints_changed = {
        let mut slot = server_backbone_endpoints_slot()
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let changed = *slot != next_endpoints;
        *slot = next_endpoints;
        changed
    };
    *runtime_serve_slot()
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(serve);
    let backbone_changed =
        backbone::set_runtime_server_backbone_endpoints(serve, backbone_endpoints);
    orgrelay::set_runtime_relay_server_enabled(Some(serve));
    if let Err(e) = remote_cfg.persist_relay_server_enabled(serve).await {
        tracing::debug!(serve, error = %e, "org-relay: config persistence skipped");
    }
    let was_listening = listening_port();
    set_serving_on_port(serve, port).await;
    if serve
        && (backbone_changed || endpoints_changed)
        && was_listening.is_some()
        && listening_port() == was_listening
    {
        // Re-fire the readiness watch so `OverlayRuntime` immediately rejoins
        // with the updated `relay_backbone_ready` and refreshes probe targets.
        readiness_sender().send_replace(was_listening);
    }
    true
}

/// Separate per-instance seam so real bind/failure/teardown tests never change
/// process globals or environment and can run concurrently.
async fn start_listener(
    port: u16,
    readiness: watch::Sender<Option<u16>>,
) -> std::io::Result<(Running, tokio::task::JoinHandle<()>)> {
    let sock = Arc::new(tokio::net::UdpSocket::bind(("0.0.0.0", port)).await?);
    let addr = sock.local_addr()?;
    let mut key = [0u8; 32];
    {
        use rand::RngCore;
        rand::rng().fill_bytes(&mut key);
    }
    let stats = Arc::new(RelayStats::default());
    let (server, handle) = RelayServer::new(CookieKey::from_bytes(key), stats.clone());
    let bridges = Arc::new(Mutex::new(HashMap::new()));
    let running = Running {
        listening: addr.to_string(),
        stats: stats.clone(),
        handle,
        readiness: readiness.subscribe(),
        bridges: bridges.clone(),
    };
    let guard = ServingGuard {
        bridges,
        reporter: tokio::spawn(report_loop(stats)),
        readiness: readiness.clone(),
    };
    // Published only once the socket and server exist. The captured guard
    // clears it even if the task is cancelled before its first poll.
    readiness.send_replace(Some(addr.port()));
    let task = tokio::spawn(async move {
        let _guard = guard;
        server.serve(sock).await;
    });
    Ok((running, task))
}

/// Summarise the counters whenever they change. Silent while nothing happens,
/// so an idle relay does not fill the log.
async fn report_loop(stats: Arc<RelayStats>) {
    let mut last = RelayCounts::default();
    loop {
        tokio::time::sleep(REPORT_EVERY).await;
        let now = stats.snapshot();
        if now == last {
            continue;
        }
        tracing::info!(
            probes_answered = now.probe.answered,
            forwarded = now.forwarded,
            bound = now.bound,
            sessions_installed = now.sessions_installed,
            sessions_revoked = now.sessions_revoked,
            sessions_reaped = now.sessions_reaped,
            drop_unbound_source = now.drop_unbound_source,
            drop_unknown_vni = now.drop_unknown_vni,
            drop_bad_tag1 = now.drop_bad_tag1,
            drop_bad_cookie = now.drop_bad_cookie,
            drop_bad_tag2 = now.drop_bad_tag2,
            refused_rate_limited = now.refused_rate_limited,
            panics_caught = now.panics_caught,
            "org-relay server counters"
        );
        last = now;
    }
}

/// FR-19 P4b — install a server-minted session into the running relay
/// (`rc:overlay.relay_serve`). Every lifetime is RE-CLAMPED against this
/// node's own ceilings and its own clock — server values only ever shorten
/// (the MeshHarbor SSH rule). A malformed member (bad base64, wrong length)
/// drops the whole frame: a session with one unverifiable member is a
/// session nobody can bind to safely. A node that is not serving ignores it
/// with a warning: the server mints only onto nodes advertising
/// `relay-server`, so reaching here without a listener means a stale
/// capability, not a fault worth more than a log line.
pub fn install_from_wire(
    vni: u32,
    generation: u64,
    members: &[meshharbor_remote_control::signaling::RelayMemberWire],
    bind_secs: u32,
    idle_secs: u32,
    max_lifetime_secs: u32,
) {
    let Some(h) = handle() else {
        tracing::warn!(
            vni,
            "org-relay: relay_serve received but this node is not serving; ignored"
        );
        return;
    };
    install_session_for(
        &h,
        vni,
        generation,
        members,
        bind_secs,
        idle_secs,
        max_lifetime_secs,
    );
}

fn install_session_for(
    h: &RelayHandle,
    vni: u32,
    generation: u64,
    members: &[meshharbor_remote_control::signaling::RelayMemberWire],
    bind_secs: u32,
    idle_secs: u32,
    max_lifetime_secs: u32,
) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use tunnel_core::overlay::orgrelay::{
        bind::BindSecret,
        member::{MAX_BIND_BUDGET, MAX_LIFETIME},
        session::{IDLE_REFRESH, Member, Session},
    };
    if members.len() != 2 {
        tracing::warn!(
            vni,
            n = members.len(),
            "org-relay: relay_serve must name exactly two members; ignored"
        );
        return;
    }
    let parse = |m: &meshharbor_remote_control::signaling::RelayMemberWire| -> Option<Member> {
        let pk = BASE64.decode(&m.wg_public_key).ok()?;
        let sk = BASE64.decode(&m.bind_secret).ok()?;
        Some(Member {
            wg_public: <[u8; 32]>::try_from(pk.as_slice()).ok()?,
            secret: BindSecret::from_bytes(<[u8; 32]>::try_from(sk.as_slice()).ok()?),
        })
    };
    let (Some(a), Some(b)) = (parse(&members[0]), parse(&members[1])) else {
        tracing::warn!(
            vni,
            "org-relay: relay_serve carried a malformed member; ignored"
        );
        return;
    };
    let now = std::time::Instant::now();
    let secs = |s: u32| std::time::Duration::from_secs(u64::from(s));
    let session = Session {
        vni,
        generation,
        members: [a, b],
        bound: [None, None],
        max_lifetime: now + secs(max_lifetime_secs).min(MAX_LIFETIME),
        idle_deadline: now + secs(idle_secs).min(IDLE_REFRESH),
        bind_deadline: now + secs(bind_secs).min(MAX_BIND_BUDGET),
    };
    if h.install(session) {
        tracing::info!(vni, generation, "org-relay: session installed");
    } else {
        tracing::warn!(
            vni,
            "org-relay: session refused (table at capacity, or the relay stopped)"
        );
    }
}

/// The center authenticates/authorizes this grant; the native process still
/// refuses without its own opt-in, exact actual listener and CIDR exclusions.
/// Only the primary org dispatcher may call this function.
pub fn install_bridge_from_wire(grant: meshharbor_remote_control::signaling::RelayBridgeWire) {
    let Some(running) = active_running() else {
        return;
    };
    let Some(policy) = backbone::configured_local_policy() else {
        return;
    };
    install_bridge_for(&running, grant, policy);
}

// Same production manager path, with per-instance dependencies so tests never
// modify the process-wide OnceLock or configuration/environment of other tests.
fn install_bridge_for(
    running: &Running,
    grant: meshharbor_remote_control::signaling::RelayBridgeWire,
    policy: backbone::LocalBackbonePolicy,
) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let Some(port) = *running.readiness.borrow() else {
        return;
    };
    let Ok(remote) = grant.remote_endpoint.parse() else {
        return;
    };
    if !policy.permits(remote) {
        return;
    }
    let secret = |s: &str| {
        BASE64
            .decode(s)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .map(orgrelay::bind::BindSecret::from_bytes)
    };
    let (Some(local_secret), Some(remote_secret)) = (
        secret(&grant.local_bind_secret),
        secret(&grant.remote_bind_secret),
    ) else {
        return;
    };
    let mut entries = running.bridges.lock().unwrap_or_else(|e| e.into_inner());
    if !bridge_slot_allows(&entries, grant.trial_id, grant.generation) {
        return;
    }
    let registry = Arc::downgrade(&running.bridges);
    let id = grant.trial_id;
    let generation = grant.generation;
    let local = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let received = std::time::Instant::now();
    #[cfg(all(any(test, feature = "backbone-test-support"), target_os = "linux"))]
    let (socket_tx, socket_rx) = watch::channel(None);
    let task = tokio::spawn(async move {
        #[cfg(all(any(test, feature = "backbone-test-support"), target_os = "linux"))]
        let _evidence = BridgeSocketEvidence(socket_tx.clone());
        let lifetime = std::time::Duration::from_secs(u64::from(grant.max_lifetime_secs))
            .saturating_sub(received.elapsed());
        let grant = AuthorizedBridgeGrant {
            source_relay_id: grant.source_agent_id.to_hex(),
            target_relay_id: grant.target_agent_id.to_hex(),
            local: BridgeLeg {
                relay: local,
                vni: grant.local_vni,
                generation: grant.local_generation,
                secret: local_secret,
            },
            remote: BridgeLeg {
                relay: remote,
                vni: grant.remote_vni,
                generation: grant.remote_generation,
                secret: remote_secret,
            },
            lifetime,
        };
        match backbone::start_authorized_bridge(grant, local, &policy).await {
            Ok(mut bridge) => {
                #[cfg(all(any(test, feature = "backbone-test-support"), target_os = "linux"))]
                socket_tx.send_replace(Some(bridge.local_addrs()));
                let _ = bridge.wait().await;
            }
            Err(error) => {
                tracing::warn!(%error,"backbone bridge refused/failed; active direct remains unchanged")
            }
        }
        if let Some(registry) = registry.upgrade() {
            let mut entries = registry.lock().unwrap_or_else(|e| e.into_inner());
            if entries.get(&id).is_some_and(|e| e.generation == generation) {
                entries.remove(&id);
            }
        }
    });
    entries.insert(
        id,
        NativeBridge {
            generation,
            task,
            #[cfg(all(any(test, feature = "backbone-test-support"), target_os = "linux"))]
            sockets: socket_rx,
        },
    );
}

fn bridge_slot_allows(
    entries: &HashMap<ObjectId, NativeBridge>,
    id: ObjectId,
    generation: u64,
) -> bool {
    if let Some(existing) = entries.get(&id) {
        return generation > existing.generation;
    }
    entries.len() < meshharbor_remote_control::models::peer_relay_limits::MAX_SESSIONS_PER_RELAY
}

pub fn revoke_bridge_from_wire(id: ObjectId, generation: u64) {
    let Some(running) = active_running() else {
        return;
    };
    revoke_bridge_for(&running, id, generation);
}

fn revoke_bridge_for(running: &Running, id: ObjectId, generation: u64) {
    let mut entries = running.bridges.lock().unwrap_or_else(|e| e.into_inner());
    if entries.get(&id).is_some_and(|e| e.generation == generation) {
        entries.remove(&id);
    }
}

/// FR-19 P4b — drop a session on `rc:overlay.relay_revoke`, if this node
/// holds it. Silent when it does not: the same frame reaches members too.
pub fn revoke_from_wire(vni: u32, generation: u64) {
    if let Some(h) = handle()
        && h.revoke(vni, generation)
    {
        tracing::info!(vni, "org-relay: session revoked by the server");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global_state_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// FR-127 — a protected device binds no relay listener, even when the control plane
    /// pushes `serve` and the runtime override says yes.
    #[tokio::test]
    async fn a_protected_device_never_serves_as_a_relay() {
        let _guard = global_state_test_lock().lock().await;
        orgrelay::set_device_protected(true);
        orgrelay::set_runtime_relay_server_enabled(Some(true));
        assert!(
            !orgrelay::relay_server_enabled(),
            "protected beats the serve push"
        );
        set_serving_on_port(true, 0).await;
        assert_eq!(listening_port(), None, "no listener bound");
        assert!(stats().is_none() && handle().is_none());
        orgrelay::set_device_protected(false);
        orgrelay::set_runtime_relay_server_enabled(None);
    }

    /// The default is off, and "off" must mean nothing was created — not a
    /// relay sitting on a socket with zeroed counters. `stats()` returning
    /// `None` is how a reader tells those apart.
    #[tokio::test]
    async fn a_device_that_did_not_opt_in_reports_no_relay() {
        let _guard = global_state_test_lock().lock().await;
        orgrelay::set_runtime_relay_server_enabled(None);
        // No env set in this test process, so the gate is closed.
        assert!(!orgrelay::relay_server_enabled());
        maybe_start().await;
        assert!(
            stats().is_none() && handle().is_none(),
            "opting out must leave no relay, not an idle one"
        );
    }

    #[tokio::test]
    async fn dynamic_server_policy_starts_stops_persists_and_toggles_relay_cap() {
        use meshharbor_remote_control::models::RpcCap;
        use tunnel_core::overlay::orgrelay::{PROBE_TOKEN_LEN, build_probe};

        let _guard = global_state_test_lock().lock().await;
        set_serving(false).await;
        orgrelay::set_runtime_relay_server_enabled(None);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            r#"server_url = "http://127.0.0.1:1"
agent_token = "tok"
agent_id = "000000000000000000000001"
tenant_id = "000000000000000000000002"
machine_id = "m1"
machine_name = "box"
"#,
        )
        .unwrap();
        let remote_cfg = crate::remote_config::RemoteConfigServices::new(
            cfg_path.clone(),
            std::sync::Arc::new(tokio::sync::Mutex::new(())),
            false,
            false,
        );

        let mut readiness_rx = readiness();
        assert_eq!(*readiness_rx.borrow_and_update(), None);

        // 1. Server pushes serve = true: runtime flag flips, config persists
        //    `relay_server_enabled = Some(true)`, listener binds & answers probe,
        //    READINESS publishes `Some(port)`, and `detect()` advertises
        //    `RelayServer` + `RelayControl`.
        orgrelay::set_runtime_relay_server_enabled(Some(true));
        remote_cfg.persist_relay_server_enabled(true).await.unwrap();
        assert!(orgrelay::relay_server_enabled());
        assert_eq!(
            crate::config::load(&cfg_path)
                .unwrap()
                .relay_server_enabled,
            Some(true)
        );
        assert!(set_serving_on_port(true, 0).await);
        let port = readiness_rx.borrow_and_update().expect("ready port");
        assert_eq!(listening_port(), Some(port));
        assert!(stats().is_some() && handle().is_some());

        let caps_on = crate::encode::caps::detect();
        assert!(caps_on.rpc.iter().any(|c| c == RpcCap::RelayControl.wire()));
        assert!(caps_on.rpc.iter().any(|c| c == RpcCap::RelayServer.wire()));

        let client = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let probe = build_probe(42, &[9; PROBE_TOKEN_LEN]);
        client.send_to(&probe, ("127.0.0.1", port)).await.unwrap();
        let mut reply = [0u8; 256];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&reply[..n], &probe);

        // 2. Server pushes serve = false: listener shuts down, socket releases,
        //    READINESS publishes `None`, config persists `Some(false)`, and
        //    `detect()` drops `RelayServer` while keeping `RelayControl`.
        orgrelay::set_runtime_relay_server_enabled(Some(false));
        remote_cfg
            .persist_relay_server_enabled(false)
            .await
            .unwrap();
        assert!(!set_serving(false).await);
        assert_eq!(*readiness_rx.borrow_and_update(), None);
        assert_eq!(listening_port(), None);
        assert!(stats().is_none() && handle().is_none());
        assert_eq!(
            crate::config::load(&cfg_path)
                .unwrap()
                .relay_server_enabled,
            Some(false)
        );
        let caps_off = crate::encode::caps::detect();
        assert!(caps_off.rpc.iter().any(|c| c == RpcCap::RelayControl.wire()));
        assert!(!caps_off.rpc.iter().any(|c| c == RpcCap::RelayServer.wire()));

        // 3. Re-enabling starts cleanly again without restarting the daemon.
        assert!(set_serving_on_port(true, 0).await);
        assert!(listening_port().is_some());
        set_serving(false).await;
        orgrelay::set_runtime_relay_server_enabled(None);
    }

    #[tokio::test]
    async fn readiness_occupied_port_does_not_publish_a_relay() {
        let occupied = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await.unwrap();
        let (tx, rx) = watch::channel(None);
        let result = start_listener(occupied.local_addr().unwrap().port(), tx).await;
        assert!(result.is_err());
        assert_eq!(*rx.borrow(), None);
    }

    #[tokio::test]
    async fn readiness_bound_listener_answers_real_probe_and_clears_on_shutdown() {
        use tunnel_core::overlay::orgrelay::{PROBE_TOKEN_LEN, build_probe};
        let (tx, mut rx) = watch::channel(None);
        let (running, task) = start_listener(0, tx).await.unwrap();
        let port = rx.borrow_and_update().unwrap();
        assert_ne!(port, 0);
        assert_eq!(
            running
                .listening
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .port(),
            port
        );
        let client = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let probe = build_probe(1, &[7; PROBE_TOKEN_LEN]);
        client.send_to(&probe, ("127.0.0.1", port)).await.unwrap();
        let mut reply = [0u8; 256];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&reply[..n], &probe);
        assert_eq!(from.port(), port);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(1), rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*rx.borrow_and_update(), None);
        assert_eq!(*running.readiness.borrow(), None);
        // The real socket was released, not just hidden by a status boolean.
        let rebound = tokio::net::UdpSocket::bind(("0.0.0.0", port))
            .await
            .unwrap();
        assert_eq!(rebound.local_addr().unwrap().port(), port);
    }
    #[tokio::test]
    async fn backbone_native_registry_is_bounded_and_duplicate_generation_does_not_spawn() {
        let cap = meshharbor_remote_control::models::peer_relay_limits::MAX_SESSIONS_PER_RELAY;
        let mut entries = HashMap::new();
        for _ in 0..cap {
            entries.insert(
                ObjectId::new(),
                NativeBridge {
                    generation: 5,
                    task: tokio::spawn(std::future::pending()),
                    #[cfg(target_os = "linux")]
                    sockets: watch::channel(None).1,
                },
            );
        }
        let id = *entries.keys().next().unwrap();
        assert!(!bridge_slot_allows(&entries, ObjectId::new(), 1));
        assert!(!bridge_slot_allows(&entries, id, 5));
        assert!(!bridge_slot_allows(&entries, id, 4));
        assert!(bridge_slot_allows(&entries, id, 6));
        assert_eq!(entries.len(), cap);
        entries.clear(); // Drop aborts every pending task.
    }
    // Only the Linux-only backbone tests below observe bridge sockets.
    #[cfg(target_os = "linux")]
    async fn manager_evidence(
        mut rx: watch::Receiver<Option<[std::net::SocketAddr; 2]>>,
        live: bool,
    ) -> Option<[std::net::SocketAddr; 2]> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let current = *rx.borrow_and_update();
                if current.is_some() == live {
                    return current;
                }
                rx.changed()
                    .await
                    .expect("manager evidence channel remains live until observed teardown");
            }
        })
        .await
        .expect("manager must reach requested actual socket state")
    }
    // Only the Linux-only backbone tests below observe bridge sockets.
    #[cfg(target_os = "linux")]
    async fn manager_ports_released(addrs: [std::net::SocketAddr; 2]) {
        for addr in addrs {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                loop {
                    if let Ok(sock) = tokio::net::UdpSocket::bind(addr).await {
                        assert_eq!(sock.local_addr().unwrap(), addr);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("manager cancellation must release its actual UDP sockets");
        }
    }
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn backbone_manager_real_dual_relay_data_revoke_and_listener_withdrawal_cleanup() {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        use orgrelay::{
            bind::BindSecret,
            build_data, client, parse_data,
            session::{Member, Session},
        };
        use std::{
            net::{IpAddr, SocketAddr},
            time::{Duration, Instant},
        };
        let overlay: ipnet::IpNet = "100.64.0.0/10".parse().unwrap();
        let (interface, host) = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .map(|i| {
                let ip = i.ip();
                (i.name, ip)
            })
            .find(|(name,ip)| {
                let IpAddr::V4(_)=ip else{return false};
                // Some hosts put non-127 addresses on `lo`; address-only
                // filtering is not a valid underlay NIC check. Reuse the
                // EXACT production interface + unicast + overlay refusal.
                backbone::LocalBackbonePolicy {
                    enabled:true,interface:name.clone(),
                    allowed_cidrs:vec![format!("{ip}/32").parse().unwrap()],
                    overlay_cidrs:vec![overlay],
                }.permits(SocketAddr::new(*ip,1))
            })
            .expect(
                "local manager integration fixture requires a production-permitted underlay IPv4 NIC",
            );
        let (one, mut one_ready) = watch::channel(None);
        let (source, source_task) = start_listener(0, one).await.unwrap();
        let source_port = one_ready.borrow_and_update().unwrap();
        let (two, _two_ready) = watch::channel(None);
        let (target, target_task) = start_listener(0, two).await.unwrap();
        let target_port = target.readiness.borrow().unwrap();
        let source_addr = SocketAddr::from(([127, 0, 0, 1], source_port));
        let target_addr = SocketAddr::from(([127, 0, 0, 1], target_port));
        let target_underlay = SocketAddr::new(host, target_port);
        let policy = || backbone::LocalBackbonePolicy {
            enabled: true,
            interface: interface.clone(),
            allowed_cidrs: vec![format!("{host}/32").parse().unwrap()],
            overlay_cidrs: vec![overlay],
        };
        assert!(policy().permits(target_underlay));
        for (running, vni, secrets) in [
            (&source, 41, [[11; 32], [12; 32]]),
            (&target, 83, [[21; 32], [22; 32]]),
        ] {
            let now = Instant::now();
            assert!(running.handle.install(Session {
                vni,
                generation: 1,
                members: [
                    Member {
                        wg_public: [1; 32],
                        secret: BindSecret::from_bytes(secrets[0])
                    },
                    Member {
                        wg_public: [2; 32],
                        secret: BindSecret::from_bytes(secrets[1])
                    }
                ],
                bound: [None, None],
                max_lifetime: now + Duration::from_secs(30),
                idle_deadline: now + Duration::from_secs(30),
                bind_deadline: now + Duration::from_secs(10)
            }));
        }
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client::bind(
            &a,
            source_addr,
            41,
            1,
            &BindSecret::from_bytes([11; 32]),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        client::bind(
            &b,
            target_addr,
            83,
            1,
            &BindSecret::from_bytes([22; 32]),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let id = ObjectId::new();
        let source_id = ObjectId::new();
        let target_id = ObjectId::new();
        let grant = |generation| meshharbor_remote_control::signaling::RelayBridgeWire {
            trial_id: id,
            generation,
            source_agent_id: source_id,
            target_agent_id: target_id,
            local_vni: 41,
            local_generation: 1,
            local_bind_secret: BASE64.encode([12; 32]),
            remote_endpoint: target_underlay.to_string(),
            remote_vni: 83,
            remote_generation: 1,
            remote_bind_secret: BASE64.encode([21; 32]),
            max_lifetime_secs: 30,
        };
        install_bridge_for(&source, grant(7), policy());
        let evidence = source
            .bridges
            .lock()
            .unwrap()
            .get(&id)
            .unwrap()
            .sockets
            .clone();
        let sockets = manager_evidence(evidence.clone(), true).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while source.stats.snapshot().bound < 2 || target.stats.snapshot().bound < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Duplicate/older grants must not replace active production tasks.
        install_bridge_for(&source, grant(7), policy());
        install_bridge_for(&source, grant(6), policy());
        assert_eq!(source.bridges.lock().unwrap().len(), 1);
        assert_eq!(
            *source
                .bridges
                .lock()
                .unwrap()
                .get(&id)
                .unwrap()
                .sockets
                .borrow(),
            Some(sockets)
        );
        let payload = vec![0xa7; 1312];
        let mut buffer = [0u8; 2048];
        for (send, recv, relay, vni, expected) in
            [(&a, &b, source_addr, 41, 83), (&b, &a, target_addr, 83, 41)]
        {
            send.send_to(&build_data(vni, &payload), relay)
                .await
                .unwrap();
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), recv.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let (received, bytes) = parse_data(&buffer[..n]).unwrap();
            assert_eq!(received, expected);
            assert_eq!(bytes, payload);
        }
        revoke_bridge_for(&source, id, 6);
        assert_eq!(
            source.bridges.lock().unwrap().len(),
            1,
            "stale revoke cannot close current bridge"
        );
        revoke_bridge_for(&source, id, 7);
        assert!(source.bridges.lock().unwrap().is_empty());
        manager_evidence(evidence, false).await;
        manager_ports_released(sockets).await;
        // Reinstall through the same manager, then REAL listener task teardown
        // must clear its native task table and release both bridge sockets.
        install_bridge_for(&source, grant(8), policy());
        let evidence = source
            .bridges
            .lock()
            .unwrap()
            .get(&id)
            .unwrap()
            .sockets
            .clone();
        let sockets = manager_evidence(evidence.clone(), true).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while source.stats.snapshot().bound < 3 || target.stats.snapshot().bound < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for (send, recv, relay, vni, expected) in
            [(&a, &b, source_addr, 41, 83), (&b, &a, target_addr, 83, 41)]
        {
            send.send_to(&build_data(vni, &payload), relay)
                .await
                .unwrap();
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), recv.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let (received, bytes) = parse_data(&buffer[..n]).unwrap();
            assert_eq!(received, expected);
            assert_eq!(bytes, payload);
        }
        source_task.abort();
        assert!(source_task.await.unwrap_err().is_cancelled());
        assert_eq!(*source.readiness.borrow(), None);
        assert!(source.bridges.lock().unwrap().is_empty());
        manager_evidence(evidence, false).await;
        manager_ports_released(sockets).await;
        let source_rebound = tokio::net::UdpSocket::bind(("0.0.0.0", source_port))
            .await
            .unwrap();
        assert_eq!(source_rebound.local_addr().unwrap().port(), source_port);
        install_bridge_for(&source, grant(9), policy());
        assert!(
            source.bridges.lock().unwrap().is_empty(),
            "withdrawn listener cannot accept another bridge"
        );
        // The other relay is unrelated to source lifecycle and stays healthy.
        let probe = orgrelay::build_probe(1, &[5; orgrelay::PROBE_TOKEN_LEN]);
        b.send_to(&probe, target_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], &probe);
        target_task.abort();
        let _ = target_task.await;
    }

    #[tokio::test]
    async fn apply_server_policy_ignores_out_of_order_stale_revision() {
        let _guard = global_state_test_lock().lock().await;
        set_serving(false).await;
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let mut init_cfg = crate::config::test_fixture();
        init_cfg.relay_server_port = Some(0);
        crate::config::save(&cfg_path, &init_cfg).unwrap();
        let remote_cfg = crate::remote_config::RemoteConfigServices::new(
            cfg_path.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            false,
            true,
        );

        // Reset process-level revision state for deterministic test isolation.
        *last_applied_revision().lock().await = None;
        *runtime_serve_slot().write().unwrap() = None;
        server_backbone_endpoints_slot().write().unwrap().clear();

        // Live admin PUT (false, rev=2) arrives first.
        assert!(apply_server_policy(false, Some(2), &[], &remote_cfg).await);
        assert!(!orgrelay::relay_server_enabled());
        assert_eq!(
            crate::config::load(&cfg_path).unwrap().relay_server_enabled,
            Some(false)
        );
        assert!(listening_port().is_none());

        // Stale connect snapshot (true, rev=1) arrives out-of-order AFTER rev=2 -> ignored!
        assert!(!apply_server_policy(true, Some(1), &[], &remote_cfg).await);
        assert!(!orgrelay::relay_server_enabled());
        assert_eq!(
            crate::config::load(&cfg_path).unwrap().relay_server_enabled,
            Some(false)
        );
        assert!(listening_port().is_none());

        // Unversioned directive after versioned state is also ignored.
        assert!(!apply_server_policy(true, None, &[], &remote_cfg).await);
        assert!(!orgrelay::relay_server_enabled());

        // Same revision (reconnect with unchanged policy) and strictly higher revision apply.
        assert!(apply_server_policy(false, Some(2), &[], &remote_cfg).await);
        let mut next = None;
        assert!(accept_policy_revision(&mut next, Some(2)));
        assert!(!accept_policy_revision(&mut next, Some(1)));
        assert!(accept_policy_revision(&mut next, Some(3)));
        assert_eq!(next, Some(3));

        *last_applied_revision().lock().await = None;
        *runtime_serve_slot().write().unwrap() = None;
        server_backbone_endpoints_slot().write().unwrap().clear();
        orgrelay::set_runtime_relay_server_enabled(None);
    }

    #[tokio::test]
    async fn apply_server_policy_protects_backbone_endpoints_against_stale_and_duplicate_equal_revisions()
    {
        let _guard = global_state_test_lock().lock().await;
        set_serving(false).await;
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let mut init_cfg = crate::config::test_fixture();
        init_cfg.relay_server_port = Some(0);
        crate::config::save(&cfg_path, &init_cfg).unwrap();
        let remote_cfg = crate::remote_config::RemoteConfigServices::new(
            cfg_path.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            false,
            true,
        );

        *last_applied_revision().lock().await = None;
        *runtime_serve_slot().write().unwrap() = None;
        server_backbone_endpoints_slot().write().unwrap().clear();

        let rev_v1 = (2_u64 << 24) | 1;
        let rev_stale = (1_u64 << 24) | 99;
        let rev_v2 = (3_u64 << 24) | 1;
        let ep_initial = vec!["202.181.7.6:3478".to_string()];
        let ep_obsolete = vec!["198.51.100.99:3478".to_string()];
        let ep_updated = vec!["202.181.7.6:3478".to_string(), "8.8.4.4:3478".to_string()];

        // 1. Initial composite revision applies `serve = true` and `ep_initial`.
        assert!(apply_server_policy_on_port(true, Some(rev_v1), &ep_initial, &remote_cfg, 0).await);
        let bound_port = listening_port().expect("ephemeral relay listener bound");
        assert!(orgrelay::relay_server_enabled());
        assert_eq!(*runtime_serve_slot().read().unwrap(), Some(true));
        assert_eq!(runtime_server_backbone_endpoints(), ep_initial);

        // 2. Stale composite revision (`rev_stale < rev_v1`) is rejected (`false`) and preserves endpoints.
        assert!(!apply_server_policy_on_port(true, Some(rev_stale), &ep_obsolete, &remote_cfg, 0).await);
        assert!(orgrelay::relay_server_enabled());
        assert_eq!(runtime_server_backbone_endpoints(), ep_initial);

        // 3. Duplicate-equal revision (`rev_v1 == last_applied`) is treated as idempotent reconnect:
        //    re-emits readiness for the running listener WITHOUT overwriting `RUNTIME_SERVE`
        //    or `SERVER_BACKBONE_ENDPOINTS` even if a racing payload carried obsolete endpoints or serve=false!
        let mut readiness_rx = readiness();
        let _ = readiness_rx.borrow_and_update();
        assert!(apply_server_policy_on_port(false, Some(rev_v1), &ep_obsolete, &remote_cfg, 0).await);
        assert!(readiness_rx.has_changed().unwrap());
        assert_eq!(*readiness_rx.borrow_and_update(), Some(bound_port));
        assert!(orgrelay::relay_server_enabled());
        assert_eq!(*runtime_serve_slot().read().unwrap(), Some(true));
        assert_eq!(runtime_server_backbone_endpoints(), ep_initial);
        assert_eq!(
            crate::config::load(&cfg_path).unwrap().relay_server_enabled,
            Some(true)
        );

        // 4. Strictly newer composite revision (`rev_v2 > rev_v1`) updates backbone endpoints and fires readiness.
        let _ = readiness_rx.borrow_and_update();
        assert!(apply_server_policy_on_port(true, Some(rev_v2), &ep_updated, &remote_cfg, 0).await);
        assert!(readiness_rx.has_changed().unwrap());
        assert_eq!(runtime_server_backbone_endpoints(), ep_updated);

        // 5. Failed initial bind followed by unchanged-revision reconnect recovers the listener
        //    once the port frees, while preserving the accepted policy & endpoints.
        set_serving(false).await;
        let occupied = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await.unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let rev_v3 = (4_u64 << 24) | 1;
        let ep_v3 = vec!["10.42.2.114:3478".to_string()];
        assert!(
            apply_server_policy_on_port(true, Some(rev_v3), &ep_v3, &remote_cfg, occupied_port)
                .await
        );
        assert_eq!(listening_port(), None, "port conflict prevented initial bind");
        assert_eq!(runtime_server_backbone_endpoints(), ep_v3);

        drop(occupied);
        let _ = readiness_rx.borrow_and_update();
        assert!(
            apply_server_policy_on_port(false, Some(rev_v3), &ep_obsolete, &remote_cfg, occupied_port)
                .await
        );
        assert_eq!(
            listening_port(),
            Some(occupied_port),
            "unchanged-revision reconnect must retry and recover the failed listener bind"
        );
        assert!(readiness_rx.has_changed().unwrap());
        assert_eq!(*readiness_rx.borrow_and_update(), Some(occupied_port));
        assert_eq!(*runtime_serve_slot().read().unwrap(), Some(true));
        assert_eq!(runtime_server_backbone_endpoints(), ep_v3);

        // Cleanup globals.
        set_serving(false).await;
        *last_applied_revision().lock().await = None;
        *runtime_serve_slot().write().unwrap() = None;
        server_backbone_endpoints_slot().write().unwrap().clear();
        backbone::set_runtime_server_backbone_endpoints(false, &[]);
        orgrelay::set_runtime_relay_server_enabled(None);
    }
}

#[cfg(all(feature = "backbone-test-support", target_os = "linux"))]
#[doc(hidden)]
pub mod backbone_test_support {
    use super::*;
    use std::{
        io,
        net::{IpAddr, SocketAddr},
        time::Duration,
    };
    pub use tunnel_core::localapi::{
        ConnectionType, OverlayView, PathTrialEvent, PathTrialPhase, PathTrialStatus,
    };
    pub use tunnel_core::overlay::netstack::{Netstack, NetstackHandle};
    pub use tunnel_core::overlay::orgrelay::{
        bind::BindSecret,
        build_data,
        client::{OrgRelayConn, bind as bind_member},
        parse_data, prober,
    };
    pub use tunnel_core::overlay::runtime::{
        OverlayEvent, OverlayRuntime, RelayProbeUpdates, TunFactory,
    };
    pub use tunnel_core::overlay::tun::TunIo;
    pub use tunnel_core::overlay::wg::{Carrier, WgDevice};
    pub use tunnel_core::overlay::{
        WgKeypair,
        runtime::{PathTrialTestHarness, PathTrialTestSnapshot},
    };
    pub struct NativeRelay {
        running: Running,
        task: tokio::task::JoinHandle<()>,
        interface: String,
        ip: IpAddr,
    }
    impl Drop for NativeRelay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl NativeRelay {
        pub async fn start() -> io::Result<Self> {
            let overlay: ipnet::IpNet = "100.64.0.0/10".parse().unwrap();
            let (interface, ip) = if_addrs::get_if_addrs()?
                .into_iter()
                .map(|i| {
                    let ip = i.ip();
                    (i.name, ip)
                })
                .find(|(name, ip)| {
                    ip.is_ipv4()
                        && backbone::LocalBackbonePolicy {
                            enabled: true,
                            interface: name.clone(),
                            allowed_cidrs: vec![format!("{ip}/32").parse().unwrap()],
                            overlay_cidrs: vec![overlay],
                        }
                        .permits(SocketAddr::new(*ip, 1))
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "no production-permitted native fixture NIC",
                    )
                })?;
            let (tx, _) = watch::channel(None);
            let (running, task) = start_listener(0, tx).await?;
            Ok(Self {
                running,
                task,
                interface,
                ip,
            })
        }
        pub fn endpoint(&self) -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], self.port()))
        }
        pub fn underlay_endpoint(&self) -> SocketAddr {
            SocketAddr::new(self.ip, self.port())
        }
        /// Kill the actual listener and prove it released its bound UDP port.
        pub async fn stop_listener(&mut self) -> io::Result<u16> {
            let port = self.port();
            self.task.abort();
            if let Err(error) = (&mut self.task).await
                && !error.is_cancelled()
            {
                return Err(io::Error::other(error));
            }
            if self.running.readiness.borrow().is_some() {
                return Err(io::Error::other("stopped listener still ready"));
            }
            let released = tokio::net::UdpSocket::bind(("0.0.0.0", port)).await?;
            drop(released);
            Ok(port)
        }
        /// Rejoin on the same endpoint with fresh session and bridge state.
        pub async fn restart_listener(&mut self, port: u16) -> io::Result<()> {
            let original = self
                .running
                .listening
                .parse::<SocketAddr>()
                .map_err(io::Error::other)?
                .port();
            if !self.task.is_finished()
                || self.running.readiness.borrow().is_some()
                || port != original
            {
                return Err(io::Error::other(
                    "restart requires the stopped original listener",
                ));
            }
            let (tx, _) = watch::channel(None);
            let (running, task) = start_listener(port, tx).await?;
            self.running = running;
            self.task = task;
            Ok(())
        }
        pub fn port(&self) -> u16 {
            self.running
                .readiness
                .borrow()
                .expect("listener remains ready")
        }
        pub fn policy_to(&self, target: &Self) -> backbone::LocalBackbonePolicy {
            backbone::LocalBackbonePolicy {
                enabled: true,
                interface: self.interface.clone(),
                allowed_cidrs: vec![format!("{}/32", target.ip).parse().unwrap()],
                overlay_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
            }
        }
        pub fn session_counts(&self) -> RelayCounts {
            self.running.stats.snapshot()
        }
        pub fn watch_rejected_wg_data(&self, source: SocketAddr, vni: u32, wg_len: usize) {
            self.running
                .stats
                .fixture_watch_rejected_data(source, vni, wg_len);
        }
        pub fn rejected_wg_data_count(&self) -> u64 {
            self.running.stats.fixture_rejected_data_count()
        }
        // One fixture snapshot couples the lifetime watch with its current sockets.
        #[allow(clippy::type_complexity)]
        pub fn bridge_evidence(
            &self,
            id: ObjectId,
            generation: u64,
        ) -> io::Result<(watch::Receiver<Option<[SocketAddr; 2]>>, [SocketAddr; 2])> {
            let entries = self.running.bridges.lock().unwrap();
            let entry = entries
                .get(&id)
                .ok_or_else(|| io::Error::other("bridge missing"))?;
            if entry.generation != generation {
                return Err(io::Error::other("bridge generation mismatch"));
            }
            let evidence = entry.sockets.clone();
            let sockets = (*evidence.borrow())
                .ok_or_else(|| io::Error::other("bridge sockets not active"))?;
            Ok((evidence, sockets))
        }
        pub async fn assert_bridge_retired(
            &self,
            id: ObjectId,
            mut evidence: watch::Receiver<Option<[SocketAddr; 2]>>,
            sockets: [SocketAddr; 2],
        ) -> io::Result<()> {
            if self.running.bridges.lock().unwrap().contains_key(&id) {
                return Err(io::Error::other("bridge remains registered"));
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while evidence.borrow_and_update().is_some() {
                    if evidence.changed().await.is_err() {
                        break;
                    }
                }
                for addr in sockets {
                    loop {
                        if tokio::net::UdpSocket::bind(addr).await.is_ok() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                }
            })
            .await
            .map_err(|_| io::Error::other("bridge sockets did not close"))?;
            Ok(())
        }
        pub fn serve(
            &self,
            msg: meshharbor_remote_control::signaling::ServerMsg,
            policy: Option<backbone::LocalBackbonePolicy>,
        ) {
            use meshharbor_remote_control::signaling::ServerMsg;
            match msg {
                ServerMsg::OverlayRelayServe {
                    vni,
                    generation,
                    members,
                    bind_secs,
                    idle_secs,
                    max_lifetime_secs,
                } => install_session_for(
                    &self.running.handle,
                    vni,
                    generation,
                    &members,
                    bind_secs,
                    idle_secs,
                    max_lifetime_secs,
                ),
                ServerMsg::OverlayRelayBridgeServe { bridge } => {
                    install_bridge_for(&self.running, bridge, policy.expect("local native policy"))
                }
                ServerMsg::OverlayRelayBridgeRevoke {
                    trial_id,
                    generation,
                } => revoke_bridge_for(&self.running, trial_id, generation),
                ServerMsg::OverlayRelayRevoke { vni, scope } => {
                    assert!(scope.peer_node_id.is_none());
                    self.running.handle.revoke(vni, scope.generation);
                }
                _ => panic!("unexpected native fixture control frame"),
            }
        }
        pub async fn fail_owned_bridge(&self, id: ObjectId, generation: u64) -> io::Result<()> {
            let mut evidence = {
                let entries = self.running.bridges.lock().unwrap();
                let entry = entries.get(&id).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "expected live task-owned bridge")
                })?;
                if entry.generation != generation {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "wrong generation",
                    ));
                }
                entry.sockets.clone()
            };
            let sockets = (*evidence.borrow())
                .ok_or_else(|| io::Error::other("bridge must actually be running before fault"))?;
            revoke_bridge_for(&self.running, id, generation);
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if evidence.borrow_and_update().is_none() {
                        break;
                    }
                    let _ = evidence.changed().await;
                }
            })
            .await
            .map_err(|_| io::Error::other("bridge fault did not retire actual sockets"))?;
            for addr in sockets {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if let Ok(sock) = tokio::net::UdpSocket::bind(addr).await {
                            drop(sock);
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(|_| io::Error::other("bridge socket still in use"))?;
            }
            Ok(())
        }
        pub async fn probe_healthy(&self) -> io::Result<()> {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let frame = orgrelay::build_probe(1, &[0x55; orgrelay::PROBE_TOKEN_LEN]);
            sock.send_to(&frame, self.endpoint()).await?;
            let mut bytes = [0u8; 256];
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut bytes))
                .await
                .map_err(|_| io::Error::other("listener probe timed out"))??;
            if bytes[..n] != frame {
                return Err(io::Error::other("listener echo mismatch"));
            }
            Ok(())
        }
    }
}
