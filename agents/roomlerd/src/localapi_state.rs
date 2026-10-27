// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The agent daemon's [`LocalApiState`] — the live data the LocalAPI serves.
//!
//! Thin adapter (unification P1): turns the agent's enrolled identity + a
//! "connected" flag + the overlay runtime's published [`OverlayView`] into the
//! read-only `status` / `peers` / `flows` that the CLI (`roomler`) and the
//! desktop app read over the local pipe/socket (`tunnel_core::localapi::serve`).
//!
//! Wired in `run_cmd`: the connected flag and the overlay `watch` channel are
//! created there (stable across WS reconnects), the signaling loop updates them,
//! and the listener reads this state.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::watch;
use tunnel_core::localapi::{
    ConnectionType, ConsentRequest, DaemonMode, ExternalPasswordState, FlowInfo, LocalApiState,
    NodeStatus, OverlayView, PeerInfo, Response, Secret,
};

/// How often the RTT prober ICMP-pings each carrier-reachable peer (P3b-3).
pub const RTT_PROBE_INTERVAL: Duration = Duration::from_secs(15);
/// A cached RTT older than this is dropped from the peer view (the peer stopped
/// answering) so the column fades to "—" rather than showing a stale number.
/// ~3 missed probes.
pub const RTT_STALE: Duration = Duration::from_secs(45);
/// Per-peer ICMP probe timeout — short so one unreachable peer can't stretch the
/// sequential cycle past [`RTT_PROBE_INTERVAL`].
const RTT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared RTT cache: overlay-ip → (last measured RTT ms, when measured). Written
/// by the prober task, read by [`DaemonState::peers`].
pub type RttCache = Arc<Mutex<HashMap<String, (u32, Instant)>>>;

/// The netstack ICMP backend behind the `ping` verb, abstracted so
/// [`DaemonState`] never names the feature-gated `NetstackHandle` type. The
/// concrete impl lives in `crate::overlay` (feature `overlay-netstack`); `None`
/// on any node not running the userspace stack.
#[async_trait]
pub trait NetstackPinger: Send + Sync {
    /// ICMP-ping `dst` (already resolved, either family) over the netstack;
    /// `Ok(rtt)` on reply.
    async fn ping(&self, dst: IpAddr, timeout: Duration) -> Result<Duration, String>;
}

/// P8-cosmetics — OS-level ICMP pinger for OS-TUN nodes, so the `peers` RTT
/// column is populated everywhere (it was netstack-only before — "— by-design
/// on OS-TUN"). Shells the platform `ping` once per probe and parses ping's
/// OWN reported round-trip (subprocess spawn cost never pollutes the number).
/// The overlay ICMP path is exactly what a user's own `ping 100.64.x.y`
/// exercises, so the column now shows the same truth they'd measure.
pub struct OsPinger;

#[async_trait]
impl NetstackPinger for OsPinger {
    async fn ping(&self, dst: IpAddr, timeout: Duration) -> Result<Duration, String> {
        let target = dst.to_string();
        let mut cmd = tokio::process::Command::new("ping");
        #[cfg(windows)]
        {
            let ms = timeout.as_millis().max(100).to_string();
            cmd.args(["-n", "1", "-w", &ms, &target]);
            // CREATE_NO_WINDOW — never flash a console under an interactive
            // session (the prober runs every 15 s).
            cmd.creation_flags(0x0800_0000);
        }
        #[cfg(target_os = "linux")]
        {
            let secs = timeout.as_secs().max(1).to_string();
            cmd.args(["-c", "1", "-W", &secs, &target]);
        }
        #[cfg(target_os = "macos")]
        {
            let ms = timeout.as_millis().max(1000).to_string();
            cmd.args(["-c", "1", "-W", &ms, &target]);
        }
        cmd.stdin(std::process::Stdio::null());
        let out = tokio::time::timeout(timeout + Duration::from_secs(2), cmd.output())
            .await
            .map_err(|_| "ping subprocess timed out".to_string())?
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err("no reply".into());
        }
        parse_ping_ms(&String::from_utf8_lossy(&out.stdout))
            .map(Duration::from_millis)
            .ok_or_else(|| "no rtt in ping output".into())
    }
}

/// Locale-tolerant extraction of the round-trip from `ping` output: the
/// integer immediately before the first standalone-ish "ms" ("time=4ms",
/// "Zeit=4ms", "time<1ms", "time=0.523 ms" ⇒ 4 / 4 / 1 / 0). Pure.
pub(crate) fn parse_ping_ms(s: &str) -> Option<u64> {
    for (idx, _) in s.match_indices("ms") {
        let head = s[..idx].trim_end();
        let num: String = head
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if num.is_empty() {
            continue; // "ms" inside a word ("streams") — keep scanning
        }
        if let Ok(v) = num.split('.').next().unwrap_or("").parse::<u64>() {
            return Some(v);
        }
    }
    None
}

/// FR-85 — the answer when this daemon has no recorder attached.
#[cfg(feature = "recording")]
fn recording_unavailable() -> Response {
    Response::Error {
        message: "screen recording is not available on this daemon".into(),
    }
}

/// Live daemon state behind the LocalAPI. Built once in `run_cmd`, wrapped in an
/// `Arc<dyn LocalApiState>` for the listener; reads are cheap clones off a
/// `watch` borrow + an atomic load.
pub struct DaemonState {
    node_id: String,
    /// Mutable so a LocalAPI rename is reflected in `status()` immediately
    /// (the server-side name still updates on the next reconnect's hello).
    name: Mutex<String>,
    version: String,
    mode: DaemonMode,
    /// Root or LocalSystem, read once at construction (a daemon never changes
    /// account). `status` reports it beside `mode`, which names the kind of
    /// node, not the account.
    privileged: bool,
    tenant_id: Option<String>,
    /// Set while a signaling WS connection is live (updated by the signaling
    /// loop's per-connection guard). `peers()` reports none when this is false,
    /// since the overlay carriers are torn down on WS drop and the last view is
    /// stale.
    connected: Arc<AtomicBool>,
    /// The overlay runtime's latest view. An empty `Default` when overlay is
    /// disabled or this build lacks `overlay-l3` (nothing publishes) — so
    /// `peers()` is simply empty there.
    overlay: watch::Receiver<OverlayView>,
    /// The SAME consent broker the signaling loop prompts on (injected from
    /// `run_cmd`) — so `consent_decide` gates on the LIVE pending set and reads
    /// the broker's own sentinel dir, rather than a throwaway broker over a
    /// re-resolved path.
    consent: crate::consent::ConsentBroker,
    /// FR-51 P4 — the primary enrollment is ephemeral (from the loaded
    /// config). Surfaces in `status()` so `meshharbor status` can say the device
    /// removes itself.
    ephemeral: bool,
    /// FR-27 — live remote-control sessions, written by every signalling
    /// loop through its `ViewerIndicator`. `None` in tests and in any daemon
    /// shape that never runs signalling.
    rc_sessions: Option<crate::rc_sessions::RcSessionRegistry>,
    /// The netstack ICMP backend for the `ping` verb. `None` on a node not
    /// running the userspace stack (OS-TUN or non-overlay build).
    pinger: Option<Arc<dyn NetstackPinger>>,
    /// The tunnel-client hub (P3b-2 PR-C) — the same instance the signaling loop
    /// publishes its egress into. Backs the `flows` / `create_forward` /
    /// `create_socks5` / `kill_flow` verbs; the daemon originates tunnels over
    /// its own agent WS.
    tunnel_hub: crate::tunnel::client_mgr::TunnelClientHub,
    /// Per-peer RTT cache filled by the ICMP prober task (P3b-3), read by
    /// `peers()` to populate `rtt_ms`. Empty on a node without the netstack
    /// pinger (no prober runs) → `rtt_ms` stays `None`.
    rtt_cache: RttCache,
    /// P6: the declared-route reconciler backing the `Route*` verbs.
    /// `None` in unit tests / states built without one — the verbs then
    /// report empty/unsupported via the trait defaults' semantics.
    routes: Option<crate::tunnel::route_reconciler::RouteReconciler>,
    /// The daemon's resolved config path + the daemon-wide write lock, backing
    /// the `SetDeviceName` verb. `None` in unit tests / states built without a
    /// persist target — the verb then reports unsupported.
    config_persist: Option<(std::path::PathBuf, crate::config::WriteLock)>,
    /// Multi-org P1: live per-enrollment rows surfaced as `NodeStatus.orgs`.
    /// `None` in unit tests / states built without one → the field is empty
    /// (old-daemon shape).
    orgs: Option<OrgStatusRegistry>,
    /// Multi-org — every SECONDARY org's live overlay view, labelled (see
    /// [`OrgViewRegistry`]). `None`/empty ⇒ single-org: `peers` returns the
    /// primary's flat list exactly as before.
    org_views: Option<OrgViewRegistry>,
    /// The daemon's live gate-4 flags, so a `ConfigSet` here takes effect at
    /// the same moment a pushed change would (`docs/remote-config.md`).
    /// `None` in unit tests → the save still lands, only the live re-seed is
    /// skipped.
    remote_config: Option<crate::remote_config::RemoteConfigServices>,
    /// FR-85 — the recorder's supervisor behind the recording verbs. `None`
    /// in unit tests and daemon shapes built without one → the verbs answer
    /// "not available". (The console-user gate is the LocalAPI listener's,
    /// applied before any of them reaches this state.)
    #[cfg(feature = "recording")]
    recorder: Option<Arc<crate::recording::manager::RecordingManager>>,
    /// FR-84 D5b — the org device list + mesh proxy behind the `Devices` /
    /// `Mesh` verbs (per-org server + agent token, a short cache). `None` in
    /// unit tests / states built without one → the trait default
    /// (`Upstream { code: "unsupported" }`).
    self_view: Option<Arc<crate::self_view::SelfView>>,
    /// FR-84 D3 — the `RestartDaemon` verb's handle into `run_cmd`. `None` in
    /// unit tests and daemon shapes built without one → the verb answers
    /// "not available", which is also what an older daemon's clients expect.
    restart: Option<RestartHandle>,
    /// FR-84 D3 — when this daemon process started (unix ms), reported with
    /// its pid so a client can tell the relaunched daemon from the one that
    /// left even when Windows hands the new process the old PID.
    started_at_ms: u64,
    /// FR-92 — on a supervised Mac the GUI WORKER runs keep busy, not this
    /// root daemon, so the keep-busy verbs ask it over the delegation channel.
    /// `None` everywhere else, and in the worker itself: there this process's
    /// own engine is the one that runs.
    keep_busy_worker: Option<crate::delegate::DelegateHost>,
}

/// FR-84 D3 — what the `RestartDaemon` verb needs from `run_cmd`: who
/// supervises this process, the internal-shutdown sender the auto-updater
/// already uses, when the process started, and where the last accepted
/// restart is recorded. `run_cmd` keeps a clone and reads
/// [`Self::accepted_exit_code`] back once the graceful shutdown is done.
///
/// The verb ARMS a restart (records it, answers `DaemonRestarting`); only
/// [`Self::commit`] — called by the LocalAPI connection loop once that
/// answer has been written — starts the shutdown, so a caller never loses its
/// connection before it knows the restart was accepted. A restart the daemon
/// decides itself (FR-96 P2b, [`Self::arm_from_within`]) has no answer to
/// write, and its caller commits at once.
#[derive(Clone)]
pub struct RestartHandle {
    inner: Arc<RestartInner>,
}

struct RestartInner {
    supervision: crate::supervision::Supervision,
    shutdown: watch::Sender<bool>,
    started: Instant,
    record_path: std::path::PathBuf,
    /// One decision at a time: two requests racing must not both pass the
    /// rate limit before either has recorded itself.
    decide: tokio::sync::Mutex<()>,
    /// The accepted restart's exit code — set once, when a restart is armed.
    accepted: std::sync::OnceLock<i32>,
    /// The shutdown has been started (idempotence for [`RestartHandle::commit`]).
    committed: AtomicBool,
}

/// If the connection loop never gets to [`RestartHandle::commit`] (its task
/// was torn down between the answer and the write), an accepted restart
/// still happens this long after it was armed. The answer is ~100 bytes into
/// a pipe buffer, so on the normal path the commit comes first by orders of
/// magnitude; this only makes "accepted ⇒ restarted" unconditional.
const RESTART_COMMIT_FALLBACK: Duration = Duration::from_secs(5);

impl RestartHandle {
    pub fn new(
        supervision: crate::supervision::Supervision,
        shutdown: watch::Sender<bool>,
        started: Instant,
        record_path: std::path::PathBuf,
    ) -> Self {
        Self {
            inner: Arc::new(RestartInner {
                supervision,
                shutdown,
                started,
                record_path,
                decide: tokio::sync::Mutex::new(()),
                accepted: std::sync::OnceLock::new(),
                committed: AtomicBool::new(false),
            }),
        }
    }

    /// The exit code of the restart this process accepted, if it accepted
    /// one. `run_cmd` leaves with it after the graceful shutdown.
    pub fn accepted_exit_code(&self) -> Option<i32> {
        self.inner.accepted.get().copied()
    }

    /// Start the graceful shutdown of an ACCEPTED restart. Idempotent, and a
    /// no-op when nothing was accepted.
    pub fn commit(&self) {
        if self.inner.accepted.get().is_none() || self.inner.committed.swap(true, Ordering::SeqCst)
        {
            return;
        }
        tracing::info!(
            supervisor = self.inner.supervision.wire(),
            "restart: committed — starting the graceful shutdown"
        );
        let _ = self.inner.shutdown.send(true);
    }

    /// The daemon's shutdown signal, for work that must end with the daemon:
    /// an update hold (FR-90 P1h-2) stops waiting when the daemon stops.
    pub fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.inner.shutdown.subscribe()
    }

    /// Who supervises this process (FR-84 D3), decided once at startup.
    pub fn supervision(&self) -> crate::supervision::Supervision {
        self.inner.supervision
    }

    /// FR-96 P2b — arm a restart this daemon decided on ITSELF: its binary
    /// was replaced, and nothing it serves would be cut. The same gates as
    /// the LocalAPI verb, in the same order, through the same shared
    /// functions: a supervisor that will relaunch it, the persisted record
    /// that makes a restart loop impossible, and systemd's own read-back of
    /// the unit's policy. Two inputs differ, on purpose. `local_restart_enabled`
    /// is the owner's switch for restarts LOCAL CLIENTS ask for, and nobody is
    /// asking here. A recording is the caller's to weigh (its idle gate, and
    /// its ceiling).
    ///
    /// On `Ok` the restart is armed and recorded; the caller then
    /// [`Self::commit`]s it — there is no answer to write first.
    pub async fn arm_from_within(
        &self,
        reason: &str,
    ) -> Result<crate::supervision::RestartPlan, String> {
        use crate::supervision as sup;
        let reason = sup::sanitize_reason(reason);
        let inner = &self.inner;
        let _one_at_a_time = inner.decide.lock().await;
        let record_path = inner.record_path.clone();
        let last = match tokio::task::spawn_blocking(move || sup::read_last_request(&record_path))
            .await
        {
            Ok(Ok(last)) => last,
            Ok(Err(e)) => {
                return Err(format!(
                    "could not read the last restart's record ({e}) — that record is what keeps \
                     a restart loop impossible"
                ));
            }
            Err(e) => return Err(format!("restart record task: {e}")),
        };
        let now_ms = unix_now_ms();
        let plan = sup::decide_restart(&sup::RestartInputs {
            supervision: inner.supervision,
            enabled: true,
            last_request_ms: last,
            now_ms,
            uptime: inner.started.elapsed(),
            recording: false,
            already_accepted: inner.accepted.get().is_some(),
        })?;
        if let sup::Supervision::Systemd(unit) = inner.supervision {
            sup::confirm_systemd(unit, plan.exit_code).await?;
        }
        let record = sup::RestartRecord {
            at_ms: now_ms,
            pid: std::process::id(),
            supervisor: plan.supervisor.to_string(),
            reason: reason.clone(),
        };
        let record_path = inner.record_path.clone();
        match tokio::task::spawn_blocking(move || sup::write_record(&record_path, &record)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(format!(
                    "could not record this restart ({e}) — that record is what keeps a restart \
                     loop impossible"
                ));
            }
            Err(e) => return Err(format!("restart record task: {e}")),
        }
        let _ = inner.accepted.set(plan.exit_code);
        tracing::info!(
            %reason,
            supervisor = plan.supervisor,
            exit_code = plan.exit_code,
            "restart decided by this daemon: armed"
        );
        Ok(plan)
    }
}

/// Wall-clock ms since the epoch — the restart record is compared across
/// process lifetimes, so it cannot be a monotonic clock.
fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Does this process run as root (unix) or LocalSystem (Windows)? This is what
/// `meshharbor status` names beside the mode. Without it, the CLI printed
/// "service (SYSTEM)" for a per-user daemon too, because `mode` reads
/// `Service` for every full node, whatever account it runs as.
fn process_is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` reads the caller's own credentials; it cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        crate::win_identity::process_is_local_system()
    }
}

/// Multi-org P1 — one enrollment's live handles, seeded by `run_cmd` and
/// read by `status()`. The `connected` flag is the SAME per-connection
/// `AtomicBool` the org's signaling guard flips; `terminal_error` is written
/// by the org supervisor when its loop stops permanently.
pub struct OrgRuntime {
    pub label: String,
    pub server_url: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub primary: bool,
    pub enabled: bool,
    pub connected: Arc<AtomicBool>,
    pub terminal_error: Arc<Mutex<Option<String>>>,
    pub updates_ignored: Arc<std::sync::atomic::AtomicU32>,
    /// FR-49 — this enrollment's overlay participation (`OrgOverlayMode::wire`).
    ///
    /// A config-level decision rather than a live handle, so it needs no `Arc`;
    /// it is re-seeded whenever a row is, which is also when the config that
    /// decides it was last read.
    pub overlay_mode: &'static str,
    /// FR-103 — the enrollment's LIVE token slot (shared with its loop), so
    /// `OrgStatus.token_expires_at` moves the moment a renewal lands.
    pub token: crate::token_slot::TokenSlot,
}

/// Shared registry of [`OrgRuntime`] rows (primary first).
pub type OrgStatusRegistry = Arc<Mutex<Vec<OrgRuntime>>>;

/// Multi-org — one SECONDARY org's live overlay view, labelled.
///
/// Each org runs its own [`OverlayRuntime`] publishing to its own `watch`
/// channel; before this registry the secondaries' receivers were dropped on
/// the floor (`main.rs`, `let (tx, _rx) = watch::channel(...)`), so `peers`
/// could only ever show the primary's mesh. Registered at boot for every
/// `[[orgs]]` entry and on a live `rc:agent.join_org`.
pub type OrgViewRegistry = Arc<Mutex<Vec<(String, watch::Receiver<OverlayView>)>>>;

impl DaemonState {
    /// Build from the enrolled config identity + the live handles. `mode` is the
    /// kind of node (today's agent is always the full "be accessed" node →
    /// [`DaemonMode::Service`]; the reach-only user-mode daemon arrives with the
    /// binary unification at P3). The account it runs as is read here, not
    /// passed in: see [`process_is_privileged`].
    #[allow(clippy::too_many_arguments)] // a daemon-state constructor; grouping would obscure
    pub fn new(
        node_id: String,
        name: String,
        mode: DaemonMode,
        tenant_id: Option<String>,
        connected: Arc<AtomicBool>,
        overlay: watch::Receiver<OverlayView>,
        consent: crate::consent::ConsentBroker,
        pinger: Option<Arc<dyn NetstackPinger>>,
        tunnel_hub: crate::tunnel::client_mgr::TunnelClientHub,
        rtt_cache: RttCache,
    ) -> Self {
        Self {
            node_id,
            name: Mutex::new(name),
            version: env!("CARGO_PKG_VERSION").to_string(),
            mode,
            privileged: process_is_privileged(),
            tenant_id,
            connected,
            overlay,
            consent,
            rc_sessions: None,
            pinger,
            tunnel_hub,
            rtt_cache,
            routes: None,
            config_persist: None,
            orgs: None,
            org_views: None,
            remote_config: None,
            self_view: None,
            ephemeral: false,
            #[cfg(feature = "recording")]
            recorder: None,
            restart: None,
            // Built once, in `run_cmd`, seconds into the process's life.
            started_at_ms: unix_now_ms(),
            keep_busy_worker: None,
        }
    }

    /// FR-92 — answer the keep-busy verbs from the attached GUI worker of a
    /// supervised Mac. ⚠️ A root caller (`meshharbor exec <mac> roomler keep-busy
    /// off`) reaches THIS daemon, never the worker's per-user socket, and the
    /// daemon's own engine never runs there: before this, a root `off` stopped
    /// nothing and answered "off" while the worker kept moving the pointer
    /// (field, 0.4.126). With no worker attached, the verbs answer for this
    /// process as before.
    pub fn with_keep_busy_worker(mut self, host: crate::delegate::DelegateHost) -> Self {
        self.keep_busy_worker = Some(host);
        self
    }

    /// FR-92 — a keep-busy verb, answered by the engine that runs keep busy:
    /// a supervised Mac's attached worker, else this process's own.
    async fn keep_busy_answer(&self, off: bool) -> tunnel_core::localapi::KeepBusyInfo {
        if let Some(host) = &self.keep_busy_worker
            && let Some(info) = host
                .ask_worker_keep_busy(off, crate::delegate::KEEP_BUSY_ASK_WAIT)
                .await
        {
            return info;
        }
        crate::keep_busy::answer_local(off).await
    }

    /// FR-84 D3 — attach the restart verb's handle (see [`RestartHandle`]).
    /// The verb reads `local_restart_enabled` through [`Self::with_config_persist`]'s
    /// path, so both must be attached for it to accept anything.
    pub fn with_restart(mut self, restart: RestartHandle) -> Self {
        self.restart = Some(restart);
        self
    }

    /// FR-85 — attach the recorder's supervisor so the recording verbs are
    /// live.
    #[cfg(feature = "recording")]
    pub fn with_recorder(
        mut self,
        recorder: Arc<crate::recording::manager::RecordingManager>,
    ) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// FR-84 D5b — attach the per-org HTTP registry (server URL + agent
    /// token per enrollment, seeded next to the `OrgRuntime` rows) so the
    /// `Devices` / `Mesh` verbs can ask the org's server. Builder style like
    /// the rest, so `new()`'s call sites stay put.
    pub fn with_org_http(mut self, registry: crate::self_view::OrgHttpRegistry) -> Self {
        self.self_view = Some(Arc::new(crate::self_view::SelfView::new(registry)));
        self
    }

    /// FR-51 P4 — stamp the primary enrollment's ephemeral nature (builder
    /// style like `with_config_persist`, so `new()`'s arg list stays put).
    pub fn with_ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }

    /// FR-27 — attach the live remote-control session registry, so a thin
    /// client can render "Being viewed by …" and offer a Disconnect. Absent
    /// (tests, and any daemon shape that never runs signalling) ⇒ an empty
    /// list and a `false` disconnect, which is the honest answer there.
    pub fn with_rc_sessions(mut self, sessions: crate::rc_sessions::RcSessionRegistry) -> Self {
        self.rc_sessions = Some(sessions);
        self
    }

    /// Attach the multi-org status registry so `NodeStatus.orgs` is live.
    /// Separate from `new` to keep the constructor's existing call sites
    /// (incl. tests) unchanged.
    pub fn with_orgs(mut self, orgs: OrgStatusRegistry) -> Self {
        self.orgs = Some(orgs);
        self
    }

    /// Multi-org — attach the per-secondary-org overlay views so `peers`
    /// reports EVERY org's mesh, not just the primary's. Absent (or empty) ⇒
    /// single-org behaviour, byte-identical.
    pub fn with_org_views(mut self, views: OrgViewRegistry) -> Self {
        self.org_views = Some(views);
        self
    }

    /// Attach the declared-route reconciler (P6) so the `Route*` verbs are
    /// live. Separate from `new` to keep the constructor's existing call
    /// sites (incl. tests) unchanged.
    pub fn with_routes(mut self, routes: crate::tunnel::route_reconciler::RouteReconciler) -> Self {
        self.routes = Some(routes);
        self
    }

    /// Attach the config write path + the daemon-wide write lock so the
    /// `SetDeviceName` verb can persist — the daemon writes ITS OWN config
    /// (profile-correct under SYSTEM, where an unelevated desktop app's direct
    /// file write is denied). Same load→mutate→save-under-lock discipline as
    /// the route reconciler (P6).
    pub fn with_config_persist(
        mut self,
        path: std::path::PathBuf,
        lock: crate::config::WriteLock,
    ) -> Self {
        self.config_persist = Some((path, lock));
        self
    }

    /// Attach the daemon's live gate-4 flags so a `ConfigSet` through this
    /// LocalAPI takes effect at the same moment a SERVER push would.
    ///
    /// Without it, `exec_enabled` had an inversion: a pushed change was live
    /// immediately while the owner's own edit sat in the file until the daemon
    /// restarted. Gate 4 is the refusal that belongs to whoever holds the
    /// machine; it cannot be the slower of the two.
    pub fn with_remote_config(
        mut self,
        remote_config: crate::remote_config::RemoteConfigServices,
    ) -> Self {
        self.remote_config = Some(remote_config);
        self
    }

    /// Resolve a `ping` target — a literal overlay IP (either family) or a peer
    /// **name** — against the live mesh view. Mirrors the netstack SOCKS
    /// front's resolver (bare label / first DNS label), but reads the view
    /// `DaemonState` holds. A name resolves to the peer's IPv4 by default, or
    /// its *derived* overlay IPv6 (published by the runtime) with `prefer_v6`;
    /// a literal is used as-is (an unroutable v6 fails cleanly at the send).
    fn resolve_overlay(&self, target: &str, prefer_v6: bool) -> Option<IpAddr> {
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Some(ip);
        }
        let tl = target.to_ascii_lowercase();
        let bare = tl.split('.').next().unwrap_or(&tl).to_string();
        self.overlay.borrow().peers.iter().find_map(|p| {
            let n = p.name.to_ascii_lowercase();
            if !p.name.is_empty() && (n == tl || n == bare) {
                let v4 = p.overlay_ip.as_deref();
                let pick = if prefer_v6 {
                    // Fall back to v4 if no published v6 (shouldn't happen —
                    // the runtime derives one whenever the v4 exists).
                    p.overlay_ip6.as_deref().or(v4)
                } else {
                    v4
                };
                pick.and_then(|s| s.parse::<IpAddr>().ok())
            } else {
                None
            }
        })
    }
}

#[async_trait]
impl LocalApiState for DaemonState {
    fn status(&self) -> NodeStatus {
        let connected = self.connected.load(Ordering::Relaxed);
        NodeStatus {
            path_trials: connected
                .then(|| self.overlay.borrow().path_trials.clone())
                .flatten(),
            node_id: self.node_id.clone(),
            name: self.name.lock().map(|n| n.clone()).unwrap_or_default(),
            version: self.version.clone(),
            mode: self.mode,
            privileged: Some(self.privileged),
            tenant_id: self.tenant_id.clone(),
            // The overlay IP the runtime last assigned us — a stable identity,
            // so it's kept even across a brief disconnect.
            overlay_ip: self.overlay.borrow().self_ip.clone(),
            overlay_ip6: self.overlay.borrow().self_ip6.clone(),
            connected,
            // FR-51 P4 — the primary enrollment's nature, stamped at startup.
            ephemeral: self.ephemeral,
            // P5/S4 — exit-node routing status the overlay runtime published.
            exit_node: self.overlay.borrow().exit_node.clone(),
            // FR-97 P0b — why this node offers no routes it was configured to.
            route_offer_withheld: self.overlay.borrow().route_offer_withheld.clone(),
            host_firewall: self.overlay.borrow().host_firewall.clone(),
            // S1b — the config file this daemon actually loaded, so the
            // desktop stops guessing which copy is live.
            config_path: self
                .config_persist
                .as_ref()
                .map(|(p, _)| p.display().to_string()),
            // S2 — MagicDNS status the overlay runtime published.
            dns: self.overlay.borrow().dns.clone(),
            // NAT-traversal — the srflx gather outcome. Empty candidates means
            // this node can't hole-punch and reads as UDP-blocked to every peer.
            srflx: self.overlay.borrow().srflx.clone(),
            // FR-33 — captured LAN prefixes, from the process-wide netstate
            // snapshot (a HOST property, like netcheck). `None` when the
            // monitor is not running — and, since 2026-09-06, also when the
            // operator switched the probe OFF: an empty list read as `clear`
            // in the field (CORPLAP-3, kill-switch cycle), the same word as a
            // genuinely clear host. The probe flag travels separately so a
            // new CLI can say "probe OFF" instead of going silent.
            #[cfg(feature = "overlay-l3")]
            lan_captures: if tunnel_core::env::flag("OVERLAY_LAN_CAPTURE_PROBE", true) {
                tunnel_core::overlay::netstate::handle().map(|h| {
                    h.snapshot()
                        .lan_captures
                        .iter()
                        .map(|c| tunnel_core::localapi::LanCaptureStatus {
                            prefix: c.prefix.clone(),
                            owner: c.owner.clone(),
                            via: c.via_ifref.clone(),
                            via_name: c.via_name.clone(),
                        })
                        .collect()
                })
            } else {
                None
            },
            #[cfg(feature = "overlay-l3")]
            lan_capture_probe: tunnel_core::overlay::netstate::handle()
                .map(|_| tunnel_core::env::flag("OVERLAY_LAN_CAPTURE_PROBE", true)),
            #[cfg(not(feature = "overlay-l3"))]
            lan_captures: None,
            #[cfg(not(feature = "overlay-l3"))]
            lan_capture_probe: None,
            // FR-47 — the last join the server refused, if any. Read from the
            // process-wide slot rather than the overlay view: a refusal means
            // the runtime never came up, so there is no view to carry it.
            //
            // Feature-gated like `lan_captures` above, because `crate::overlay`
            // itself is: a signalling-only build has no overlay module and can
            // never be refused a join it does not attempt, so `None` there is
            // the truth rather than a stub.
            #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
            join_refusal: crate::overlay::last_join_refusal(),
            #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
            join_refusal: None,
            // C4 stage 1 — the warm TURN/UDP allocation's state.
            warm_relay: self.overlay.borrow().warm_relay.clone(),
            // B4 — the measured capability vector, read straight from the
            // process-wide netcheck slot (a HOST property; no runtime
            // threading needed). The slot lives behind tunnel-core's
            // `overlay-l3` feature; a signalling-only build reports None
            // exactly like a pre-B4 daemon.
            #[cfg(feature = "overlay-l3")]
            netcheck: tunnel_core::overlay::netcheck::current().map(|(v, age)| {
                tunnel_core::localapi::NetcheckStatus {
                    stun_udp: v.stun_udp,
                    relay_band_udp: v.relay_band_udp,
                    derp_ws_ok: v.derp_ws_ok,
                    nat: v.nat,
                    age_s: age.as_secs(),
                }
            }),
            #[cfg(not(feature = "overlay-l3"))]
            netcheck: None,
            // Multi-org P1 — one row per enrollment; empty (and omitted on
            // the wire) for a single-org daemon or a state built without
            // the registry.
            orgs: self
                .orgs
                .as_ref()
                .map(|reg| {
                    reg.lock()
                        .map(|rows| {
                            rows.iter()
                                .map(|o| tunnel_core::localapi::OrgStatus {
                                    label: o.label.clone(),
                                    server_url: o.server_url.clone(),
                                    tenant_id: (!o.tenant_id.is_empty())
                                        .then(|| o.tenant_id.clone()),
                                    agent_id: (!o.agent_id.is_empty()).then(|| o.agent_id.clone()),
                                    primary: o.primary,
                                    enabled: o.enabled,
                                    connected: o.connected.load(Ordering::Relaxed),
                                    terminal_error: o
                                        .terminal_error
                                        .lock()
                                        .ok()
                                        .and_then(|t| t.clone()),
                                    updates_ignored: o.updates_ignored.load(Ordering::Relaxed),
                                    overlay_mode: o.overlay_mode.to_string(),
                                    token_expires_at: crate::token_renewal::expires_at(
                                        &o.token.get(),
                                    ),
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
            // PR-B1 — per-socket receive liveness + band-walk tripwire.
            direct_socks: self.overlay.borrow().direct_socks.clone(),
            // #32 — the `/derp` inbound-drop counters, verbatim from the
            // overlay view. `None` when the overlay is not running.
            derp_inbound_drops: self.overlay.borrow().derp_inbound_drops,
            direct_bind_walks: Some(
                tunnel_core::evidence::DIRECT_BIND_WALKS.load(Ordering::Relaxed),
            ),
            roam_adoptions: Some(tunnel_core::evidence::ROAM_ADOPTIONS.load(Ordering::Relaxed)),
            // FR-68 — route-guard evidence, read together so two snapshots can
            // be diffed as one reading. Always Some: a zero here is a real
            // measurement (a quiet host, or a platform whose guard is a no-op),
            // not an absence.
            route_guard: Some((
                tunnel_core::evidence::ROUTE_EVICTIONS.load(Ordering::Relaxed),
                tunnel_core::evidence::ROUTE_SIBLING_SPARES.load(Ordering::Relaxed),
                tunnel_core::evidence::ROUTE_WAVES.load(Ordering::Relaxed),
                tunnel_core::evidence::FORCED_REVALIDATIONS.load(Ordering::Relaxed),
            )),
            // #1282 — read alongside route_guard so one snapshot is internally
            // consistent: tick + event should equal route_guard's wave total.
            route_wave_arms: Some((
                tunnel_core::evidence::ROUTE_WAVES_TICK.load(Ordering::Relaxed),
                tunnel_core::evidence::ROUTE_WAVES_EVENT.load(Ordering::Relaxed),
            )),
            // #1328 — same snapshot, because the number only means something
            // next to the eviction count it is supposed to be bounding.
            route_yields: Some(tunnel_core::evidence::ROUTE_YIELDS.load(Ordering::Relaxed)),
            // #1282 — read next to route_wave_arms: pulled ≈ tick is a guard
            // that keeps re-arming itself.
            route_wave_pulls: Some(
                tunnel_core::evidence::ROUTE_WAVES_PULLED.load(Ordering::Relaxed),
            ),
            disco_answered: Some(tunnel_core::evidence::DISCO_ANSWERED.load(Ordering::Relaxed)),
            // FR-19 — present ONLY when the responder actually bound, so a
            // failed bind reads as "no relay here" rather than a phantom one.
            //
            // Gated to match `relay_server` itself: a build without the overlay
            // features has no responder to report, and this file DOES compile
            // in those lanes (ffmpeg-encoder, vp9-444), which a local check run
            // only with `--features overlay-l3` will not reveal.
            #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
            org_relay: crate::relay_server::status().map(|(listening, c)| {
                tunnel_core::localapi::OrgRelayStatus {
                    listening,
                    answered: c.answered,
                    refused_not_shaped: c.refused_not_shaped,
                    refused_not_probe: c.refused_not_probe,
                    refused_rate_limited: c.refused_rate_limited,
                }
            }),
            #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
            org_relay: None,
            // FR-46 — what this daemon has actually READ through a retired
            // prefix. Always `Some`, never `None`, on a daemon new enough to
            // have the field: `None` is reserved for "this daemon predates the
            // field", and reporting it for an empty set would make an answered
            // question indistinguishable from an unanswerable one.
            legacy_env_uses: Some(tunnel_core::env::legacy_env_uses()),
            retired_env_present: Some(tunnel_core::env::retired_env_present()),
            // FR-84 D3 — which process answered, so a client waiting out a
            // restart knows the relaunched daemon from the one that is leaving.
            pid: Some(std::process::id()),
            started_at_ms: Some(self.started_at_ms),
            // FR-84 D4 — where a drop would land right now: the configured
            // folder when it passes for THIS writer and the user logged in
            // at this moment, else the default ladder. From a cache that is
            // refreshed off this thread — this is a sync read on the async
            // dispatch, and the honest answer needs the disk.
            files_dir: crate::files::effective_files_dir(),
        }
    }

    fn encoder_caps(&self) -> Option<tunnel_core::localapi::EncoderCapsSummary> {
        // FR-84 D4 — the probe's CACHED result and nothing else. This answers
        // every Overview poll; `caps::detect()` here would spawn the probe
        // children — vendor driver code — from a control-surface read on any
        // host that has not reached its server yet.
        Some(crate::encode::caps::summarize_cached())
    }

    fn peers(&self) -> Vec<PeerInfo> {
        // A peer list from a dropped connection is misleading — the carriers are
        // gone. Report none until reconnected + re-synced.
        if !self.connected.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let mut peers = self.overlay.borrow().peers.clone();
        // Multi-org — append every SECONDARY org's mesh, labelled. Each org
        // runs its own overlay engine with a DISJOINT peer set and address
        // space, so without the label a merged list is ambiguous (the same
        // host can appear once per shared org under different overlay IPs).
        // Only stamp when there IS more than one org, so a single-org daemon's
        // output stays byte-identical.
        if let Some(views) = &self.org_views
            && let Ok(views) = views.lock()
            && !views.is_empty()
        {
            let primary_label = self
                .orgs
                .as_ref()
                .and_then(|o| o.lock().ok())
                .and_then(|rows| rows.iter().find(|r| r.primary).map(|r| r.label.clone()))
                .unwrap_or_else(|| "primary".to_string());
            for p in &mut peers {
                p.org = primary_label.clone();
            }
            for (label, rx) in views.iter() {
                let mut org_peers = rx.borrow().peers.clone();
                for p in &mut org_peers {
                    p.org = label.clone();
                }
                peers.extend(org_peers);
            }
        }
        // P3b-3: overlay a peer as `Tunnel` when its WG carrier is down and the
        // daemon reaches its backing agent via a live tunnel flow.
        apply_tunnel_override(&mut peers, &self.tunnel_hub.active_flow_agent_ids());
        // P3b-3: fill `rtt_ms` from the ICMP prober cache (netstack nodes via
        // the userspace pinger; OS-TUN nodes via `OsPinger` since P8-cosmetics).
        // A stale entry (peer stopped answering) is dropped so the column fades
        // to "—" rather than lying. Empty cache (prober warming up) → `None`.
        if let Ok(cache) = self.rtt_cache.lock()
            && !cache.is_empty()
        {
            for p in &mut peers {
                if let Some(ip) = p.overlay_ip.as_deref()
                    && let Some((ms, at)) = cache.get(ip)
                    && at.elapsed() < RTT_STALE
                {
                    p.rtt_ms = Some(*ms);
                }
            }
        }
        peers
    }

    fn flows(&self) -> Vec<FlowInfo> {
        // P3b-2 PR-C: the tunnel data plane folded into the daemon — report the
        // supervised forwards / SOCKS5 listeners it originates over its agent WS.
        self.tunnel_hub.flows_snapshot()
    }

    fn consent_pending(&self) -> Vec<ConsentRequest> {
        // Read the broker's OWN sentinel dir — resolved in-process, so it's the
        // daemon's real profile even under SystemContext, where the interactive-
        // user tray reading the dir directly would look in the WRONG profile (the
        // P2b bug fix). Same parse the tray's cmd_get_pending_consents used to do.
        //
        // P2b review L2: the scan is bounded. Only the daemon writes here, so
        // dozens of pendings would already be a bug — but this fn runs on every
        // tray/CLI poll (~750 ms cadence), and an unbounded read-parse loop over
        // a corrupted / adversarially stuffed directory must not turn the
        // LocalAPI thread into an I/O grinder.
        const MAX_PENDING_SCAN: usize = 64;
        let Ok(entries) = std::fs::read_dir(self.consent.sentinel_dir()) else {
            return Vec::new(); // dir not created yet ⇒ nothing pending
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            if out.len() >= MAX_PENDING_SCAN {
                tracing::warn!(
                    cap = MAX_PENDING_SCAN,
                    "localapi: consent_pending hit the scan cap — sentinel dir has \
                     implausibly many pending entries, truncating the listing"
                );
                break;
            }
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pending") {
                continue;
            }
            if let Ok(body) = std::fs::read_to_string(&path)
                && let Ok(pc) = serde_json::from_str::<ConsentRequest>(&body)
            {
                out.push(pc);
            }
        }
        out
    }

    fn consent_decide(&self, session_id: &str, allow: bool) -> bool {
        // SECURITY: the session id becomes a sentinel FILE NAME, so reject
        // anything that isn't a 24-char hex ObjectId before it's used (path-
        // traversal / injection guard). The pipe SDDL already limits WHO can call
        // this (SYSTEM + Administrators + interactive user, ≥ medium integrity).
        if !is_hex_object_id(session_id) {
            tracing::warn!(
                session = %session_id,
                "localapi: rejecting consent decision — session id is not a 24-char hex ObjectId"
            );
            return false;
        }
        // Record via the LIVE broker: honored ONLY if the session is actively
        // being prompted (no pre-approval / confused-deputy — the decision is an
        // answer to a question the broker is currently asking).
        self.consent.record_decision(session_id, allow)
    }

    fn rc_sessions(&self) -> Vec<tunnel_core::localapi::RcSessionInfo> {
        self.rc_sessions
            .as_ref()
            .map(|r| r.list())
            .unwrap_or_default()
    }

    fn rc_disconnect(&self, session_id: &str) -> bool {
        // Same guard as `consent_decide`, and for the same reason: the id
        // reaches a lookup keyed by `ObjectId`, and refusing a malformed one up
        // front keeps the failure legible instead of an opaque "no such
        // session". The pipe SDDL already limits WHO may call this.
        if !is_hex_object_id(session_id) {
            tracing::warn!(
                session = %session_id,
                "localapi: rejecting rc disconnect — session id is not a 24-char hex ObjectId"
            );
            return false;
        }
        let Ok(oid) = bson::oid::ObjectId::parse_str(session_id) else {
            return false;
        };
        match &self.rc_sessions {
            Some(reg) => reg.disconnect(&oid),
            None => false,
        }
    }

    async fn ping(&self, target: &str, timeout_ms: u64, prefer_v6: bool) -> Response {
        let Some(pinger) = self.pinger.clone() else {
            // rc.204 — say what to do in BOTH non-netstack shapes: an OS-TUN
            // node pings peers with the system `ping` (the old message sent
            // operators chasing netstack when the overlay was simply off).
            return Response::Error {
                message: "meshharbor ping uses the userspace netstack, which this node isn't \
                          running. On an OS-TUN node, use the system `ping <overlay-ip>` \
                          instead (check `meshharbor status` / `meshharbor peers` for the IPs). If \
                          the overlay isn't up at all, set `overlay_enabled = true` in the \
                          node's config.toml and restart the daemon; for netstack mode, set \
                          ROOMLERD_OVERLAY_NETSTACK_SOCKS=<port>."
                    .into(),
            };
        };
        let Some(ip) = self.resolve_overlay(target, prefer_v6) else {
            return Response::Error {
                message: format!("no overlay peer named '{target}' — try an overlay IP or `peers`"),
            };
        };
        let timeout = Duration::from_millis(if timeout_ms == 0 { 3000 } else { timeout_ms });
        match pinger.ping(ip, timeout).await {
            Ok(rtt) => Response::Pong {
                target: target.to_string(),
                overlay_ip: ip.to_string(),
                rtt_micros: rtt.as_micros() as u64,
            },
            Err(message) => Response::Error { message },
        }
    }

    async fn create_forward(
        &self,
        node: &str,
        local: u16,
        remote: &str,
        transport: &str,
        start_transport: &str,
    ) -> Response {
        match self
            .tunnel_hub
            .create_forward(node, local, remote, transport, start_transport)
            .await
        {
            Ok(id) => Response::FlowCreated { id },
            Err(message) => Response::Error { message },
        }
    }

    async fn create_socks5(&self, node: &str, local: u16, transport: &str) -> Response {
        match self.tunnel_hub.create_socks5(node, local, transport).await {
            Ok(id) => Response::FlowCreated { id },
            Err(message) => Response::Error { message },
        }
    }

    fn kill_flow(&self, id: &str) -> bool {
        self.tunnel_hub.kill_flow(id)
    }

    fn route_list(&self) -> Vec<tunnel_core::localapi::RouteInfo> {
        self.routes.as_ref().map(|r| r.list()).unwrap_or_default()
    }

    async fn route_add(&self, route: tunnel_core::localapi::RouteDescriptor) -> Response {
        let Some(routes) = self.routes.as_ref() else {
            return Response::Error {
                message: "declared routes are not available on this daemon".into(),
            };
        };
        match routes.add(route).await {
            Ok(route) => Response::RouteAdded { route },
            Err(message) => Response::Error { message },
        }
    }

    async fn set_device_name(&self, name: &str) -> Response {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Response::Error {
                message: "device name is empty".into(),
            };
        }
        if trimmed.len() > 64 {
            return Response::Error {
                message: "device name is too long (max 64 characters)".into(),
            };
        }
        let Some((path, lock)) = self.config_persist.as_ref() else {
            return Response::Error {
                message: "renaming is not supported on this node".into(),
            };
        };
        // Same discipline as the route reconciler: hold the daemon-wide write
        // lock across load→mutate→save so a concurrent config writer (route
        // add, graceful shutdown) can't have its field dropped by our
        // full-struct save. Load FRESH — the boot-time snapshot may be stale.
        let _guard = lock.lock().await;
        let path = path.clone();
        let new_name = trimmed.to_string();
        let saved = tokio::task::spawn_blocking(move || {
            let mut cfg = crate::config::load(&path)
                .map_err(|e| format!("loading config for rename: {e:#}"))?;
            cfg.machine_name = new_name.clone();
            crate::config::save(&path, &cfg)
                .map_err(|e| format!("saving renamed config: {e:#}"))?;
            Ok::<String, String>(new_name)
        })
        .await
        .unwrap_or_else(|e| Err(format!("rename task join: {e}")));
        match saved {
            Ok(name) => {
                if let Ok(mut live) = self.name.lock() {
                    live.clone_from(&name);
                }
                tracing::info!(%name, "localapi: device renamed (announced on next reconnect)");
                Response::DeviceNameSet { name }
            }
            Err(message) => Response::Error { message },
        }
    }

    async fn route_remove(&self, id: &str) -> Response {
        let Some(routes) = self.routes.as_ref() else {
            return Response::Error {
                message: "declared routes are not available on this daemon".into(),
            };
        };
        match routes.remove(id).await {
            Ok(ok) => Response::RouteRemoved { ok },
            Err(message) => Response::Error { message },
        }
    }

    async fn route_set_enabled(&self, id: &str, enabled: bool) -> Response {
        let Some(routes) = self.routes.as_ref() else {
            return Response::Error {
                message: "declared routes are not available on this daemon".into(),
            };
        };
        match routes.set_enabled(id, enabled).await {
            Ok(ok) => Response::RouteUpdated { ok },
            Err(message) => Response::Error { message },
        }
    }

    /// FR-84 D1 — the atomic route edit; the reconciler's `replace` owns the
    /// validation and the one-write persistence.
    async fn route_update(&self, route: tunnel_core::localapi::RouteDescriptor) -> Response {
        let Some(routes) = self.routes.as_ref() else {
            return Response::Error {
                message: "declared routes are not available on this daemon".into(),
            };
        };
        match routes.replace(route).await {
            Ok(route) => Response::RouteReplaced { route },
            Err(message) => Response::Error { message },
        }
    }

    /// S2 — the editable config surface. Values come from a FRESH load of
    /// the daemon's own config file, so pending not-yet-restarted edits
    /// show (the boot-time snapshot would lie after a `ConfigSet`).
    async fn config_entries(&self) -> Response {
        let Some((path, lock)) = self.config_persist.as_ref() else {
            return Response::Error {
                message: "config editing is not available on this daemon".into(),
            };
        };
        let _guard = lock.lock().await;
        let path = path.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))
        })
        .await
        .unwrap_or_else(|e| Err(format!("config load task join: {e}")));
        match loaded {
            Ok(cfg) => Response::ConfigEntries(crate::config_surface::entries(&cfg)),
            Err(message) => Response::Error { message },
        }
    }

    /// S2 — set/clear one editable key. Same write discipline as
    /// [`set_device_name`](Self::set_device_name): daemon-wide write lock
    /// across load→validate→save so a concurrent config writer can't have
    /// its field dropped by our full-struct save. Validation is
    /// per-key in [`crate::config_surface::apply`]; a validation error
    /// leaves the file untouched.
    async fn config_set(&self, key: &str, value: Option<&str>) -> Response {
        let Some((path, lock)) = self.config_persist.as_ref() else {
            return Response::Error {
                message: "config editing is not available on this daemon".into(),
            };
        };
        let _guard = lock.lock().await;
        let path = path.clone();
        let key = key.to_string();
        let value = value.map(str::to_string);
        let saved = tokio::task::spawn_blocking(move || {
            let mut cfg =
                crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))?;
            // FR-84 D4 — `files_dir` names a folder this daemon will WRITE
            // remote-supplied files into, as the identity it runs under. The
            // surface's `apply` checks the shape; placement (a SYSTEM/root
            // writer stays inside the active user's profile — the pipe admits
            // interactive non-admins) and creatable-and-writable need THIS
            // process's identity and its disk, so they run here, before
            // anything is persisted: a refused value is never saved to be
            // silently ignored at use time, and the reason goes back verbatim.
            if key == "files_dir"
                && let Some(v) = value.as_deref().map(str::trim).filter(|s| !s.is_empty())
            {
                crate::files::validate_files_dir_setting(v)?;
            }
            crate::config_surface::apply(&mut cfg, &key, value.as_deref())?;
            crate::config::save(&path, &cfg).map_err(|e| format!("saving config: {e:#}"))?;
            // FR-84 D4 — `files_dir` is LIVE: every transfer reads the
            // process-global this re-seeds, so the next drop already uses
            // the new folder. The status answer is recomputed HERE, on the
            // blocking thread, so the read right after the set shows it.
            crate::files::set_files_dir(cfg.files_dir.clone());
            if key == "files_dir" {
                crate::files::refresh_effective_files_dir();
            }
            let entry = crate::config_surface::entry_for(&cfg, &key)
                .ok_or_else(|| format!("unknown config key {key:?}"))?;
            Ok((entry, cfg))
        })
        .await
        .unwrap_or_else(|e| Err(format!("config set task join: {e}")));
        match saved {
            Ok((entry, cfg)) => {
                // Re-seed the LIVE gate-4 flags from what was just written,
                // still under the write lock. Everything else on this surface
                // genuinely is restart-required; `exec_enabled` and
                // `remote_config_enabled` are not, and leaving them stale here
                // would mean a SERVER push took effect faster than the owner's
                // own decision (docs/remote-config.md).
                if let Some(rc) = self.remote_config.as_ref() {
                    rc.adopt_local(&cfg);
                }
                // (`files_dir` was re-seeded on the blocking thread above.)
                // FR-85 P3b — the remote-recording gates are live the same
                // way, and an OFF stops a remote recording in progress. The
                // console gate on `record_*` keys has already run.
                #[cfg(feature = "recording")]
                crate::recording::remote::adopt(&cfg);
                // FR-92 — keep busy's owner gate is live too: off stops a
                // keep-busy in progress and refuses a new one, and the cap
                // word follows on the next heartbeat.
                crate::keep_busy::set_device_enabled(cfg.keep_busy_enabled);
                // FR-99 P1b — and privacy mode's: off takes every curtain that
                // is up down (the viewer is told why), and `privacy-mode`
                // leaves the caps on the next heartbeat. The console gate on
                // the key has already run.
                crate::privacy::set_device_allowed(cfg.privacy_mode_allowed);
                // FR-99 P3 — and the lock-on-end policy: the next session's
                // start reads it. The console gate on the key has already run.
                crate::lock_on_end::set_device_policy(cfg.lock_on_end);
                // FR-108 — and display match's: the next request reads it.
                // The console gate on the key has already run.
                crate::display_match::set_device_policy(cfg.display_match);
                // FR-101 P2b — and the session-policy floor: the next session
                // is masked by it, and the hub hears it on the next heartbeat.
                crate::session_policy::set_device_policy(crate::session_policy::from_config(&cfg));
                // The surface says per key whether that re-seed made the
                // change live (FR-84 D2) — log the same truth the client
                // shows, never a blanket "on restart".
                tracing::info!(key = %entry.key, value = ?entry.value,
                    applies = if entry.restart_required { "restart" } else { "live" },
                    "localapi: config key updated");
                Response::ConfigUpdated { entry }
            }
            Err(message) => Response::Error { message },
        }
    }

    /// FR-52 gate 4 — register a password and persist the record.
    ///
    /// Same write discipline as [`config_set`](Self::config_set): the daemon-wide
    /// lock is held across load → derive → save, so a concurrent writer cannot
    /// have its field dropped by our full-struct save, and a failure anywhere
    /// leaves the file untouched (`config::save` is temp + fsync + rename).
    ///
    /// ⚠️ **What is logged here is the whole point of the method's shape**: the
    /// outcome and nothing else. Not the password, not its length, not the
    /// record. The neighbouring `config_set` logs `value = ?entry.value` — which
    /// is right for it and would be a credential in the daemon's rolling log
    /// here, a log `meshharbor logs` uploads to the server this gate exists to keep
    /// out.
    ///
    /// ⚠️ Deliberately does **not** touch `external_access_enabled`. Setting a
    /// password and opening gate 3 are two decisions; doing the second one on
    /// the operator's behalf would admit outsiders at the moment they were
    /// preparing to.
    ///
    /// Scope of the plaintext, stated because "never leaves the device" invites
    /// a stronger reading than is true: the password exists in the calling CLI's
    /// memory, in this process's memory for the duration of the call (the
    /// request line buffer, serde's scratch, and the argument below), and
    /// nowhere else — no file, no log, no server. It is not zeroized; doing so
    /// for this argument alone while the line buffer in `serve_connection`
    /// holds the same bytes would claim a property the code does not have.
    async fn external_password_set(&self, password: &Secret) -> Response {
        let Some((path, lock)) = self.config_persist.as_ref() else {
            return Response::Error {
                message: "config editing is not available on this daemon".into(),
            };
        };
        #[cfg(not(feature = "external-access"))]
        {
            let _ = (path, lock, password);
            // Distinct from "no password is set" on purpose — the fix is a
            // different one (a build/update, not a command), and the two
            // rendering alike is the failure `RpcCap::ExternalAccess` is
            // unconditional to avoid.
            Response::Error {
                message: "this daemon was built without external-access support, so it cannot \
                          hold a password"
                    .into(),
            }
        }
        #[cfg(feature = "external-access")]
        {
            let _guard = lock.lock().await;
            let path = path.clone();
            let password = password.expose().to_string();
            // Argon2id by design — hundreds of ms, and this is a blocking KDF,
            // so it must not run on a reactor thread. `spawn_blocking` also
            // keeps the (already blocking) config load/save with it.
            let saved = tokio::task::spawn_blocking(move || {
                let mut cfg =
                    crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))?;
                let (cred, origin) = crate::external_access::set_password(
                    cfg.external_access_setup.as_deref(),
                    &password,
                )
                .map_err(|e| e.to_string())?;
                cfg.external_access_setup = Some(cred.setup);
                cfg.external_access_verifier = Some(cred.verifier);
                crate::config::save(&path, &cfg).map_err(|e| format!("saving config: {e:#}"))?;
                Ok((origin, external_password_state(&cfg)))
            })
            .await
            .unwrap_or_else(|e| Err(format!("external password task join: {e}")));
            match saved {
                Ok((origin, state)) => {
                    tracing::info!(
                        ?origin,
                        gate3_enabled = state.enabled,
                        "localapi: external-access password set"
                    );
                    Response::ExternalPassword(state)
                }
                Err(message) => Response::Error { message },
            }
        }
    }

    /// FR-52 gate 4 — drop the stored record, closing gate 4.
    ///
    /// Ungated by the feature: a device that held a password and was later
    /// downgraded to a build without the credential stack must still be able to
    /// forget it. Clearing is two `None`s and a save — no crypto is involved, so
    /// there is nothing for the feature to gate.
    ///
    /// Both halves go together. A clear that dropped only the verifier would
    /// leave a device that reports "no password set" (correct) next to a stored
    /// setup that a later set would silently reuse — reviving the OPAQUE
    /// identity of a credential the operator believed they had destroyed.
    async fn external_password_clear(&self) -> Response {
        let Some((path, lock)) = self.config_persist.as_ref() else {
            return Response::Error {
                message: "config editing is not available on this daemon".into(),
            };
        };
        let _guard = lock.lock().await;
        let path = path.clone();
        let saved = tokio::task::spawn_blocking(move || {
            let mut cfg =
                crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))?;
            let had = cfg.external_access_setup.is_some() || cfg.external_access_verifier.is_some();
            cfg.external_access_setup = None;
            cfg.external_access_verifier = None;
            // Saved even when nothing was stored: a half-written pair also
            // reaches here, and an unconditional write is how a clear stays
            // idempotent rather than depending on what it found.
            crate::config::save(&path, &cfg).map_err(|e| format!("saving config: {e:#}"))?;
            Ok((had, external_password_state(&cfg)))
        })
        .await
        .unwrap_or_else(|e| Err(format!("external password task join: {e}")));
        match saved {
            Ok((had, state)) => {
                tracing::info!(had, "localapi: external-access password cleared");
                Response::ExternalPassword(state)
            }
            Err(message) => Response::Error { message },
        }
    }

    /// FR-52 — report gates 3 and 4 as this device sees them.
    ///
    /// Reads the config FILE rather than a boot-time snapshot, for the same
    /// reason [`config_entries`](Self::config_entries) does: an edit made since
    /// startup is exactly what the operator is checking for, and a snapshot
    /// would answer with the state they are trying to change.
    async fn external_password_status(&self) -> Response {
        let Some((path, lock)) = self.config_persist.as_ref() else {
            // No config path: report the build's capability truthfully and the
            // rest as unknown-but-closed. An `Error` here would make "is this
            // supported?" unanswerable, which is the one thing the caller came
            // to ask.
            return Response::ExternalPassword(ExternalPasswordState {
                supported: cfg!(feature = "external-access"),
                ..Default::default()
            });
        };
        let _guard = lock.lock().await;
        let path = path.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            crate::config::load(&path).map_err(|e| format!("loading config: {e:#}"))
        })
        .await
        .unwrap_or_else(|e| Err(format!("config load task join: {e}")));
        match loaded {
            Ok(cfg) => Response::ExternalPassword(external_password_state(&cfg)),
            Err(message) => Response::Error { message },
        }
    }

    /// S2 — bounded log tail for the desktop's log viewer. The daemon
    /// resolves the source from ITS OWN perspective (role-correct dirs,
    /// SYSTEM-profile paths the desktop can't even read), caps the
    /// response, and the client polls `size` for follow.
    async fn tail_log(&self, source: &str, max_bytes: Option<u64>) -> Response {
        const CAP_MAX: u64 = 64 * 1024;
        const CAP_DEFAULT: u64 = 32 * 1024;
        let cap = max_bytes.unwrap_or(CAP_DEFAULT).clamp(512, CAP_MAX);
        let source = source.to_string();
        tokio::task::spawn_blocking(move || {
            let Some(path) = crate::logging::tail_source_path(&source) else {
                return Response::Error {
                    message: format!(
                        "no log file for source {source:?} (expected daemon | service | panic)"
                    ),
                };
            };
            match crate::logging::read_tail(&path, cap) {
                Ok((size, content)) => Response::LogTail {
                    path: path.display().to_string(),
                    size,
                    content,
                },
                Err(e) => Response::Error {
                    message: format!("reading {}: {e}", path.display()),
                },
            }
        })
        .await
        .unwrap_or_else(|e| Response::Error {
            message: format!("log tail task join: {e}"),
        })
    }

    #[cfg(feature = "recording")]
    async fn record_start(&self, opts: tunnel_core::localapi::RecordStartOpts) -> Response {
        match &self.recorder {
            Some(r) => r.start(opts).await,
            None => recording_unavailable(),
        }
    }

    #[cfg(feature = "recording")]
    async fn record_stop(&self) -> Response {
        match &self.recorder {
            Some(r) => r.stop().await,
            None => recording_unavailable(),
        }
    }

    #[cfg(feature = "recording")]
    async fn record_status(&self) -> Response {
        match &self.recorder {
            Some(r) => r.status(),
            None => Response::Recording(tunnel_core::localapi::RecordingState::unavailable(
                tunnel_core::localapi::NO_RECORDER,
            )),
        }
    }

    /// FR-92 — keep busy's state, for the tray and `roomler keep-busy`.
    async fn keep_busy_status(&self) -> Response {
        Response::KeepBusy(self.keep_busy_answer(false).await)
    }

    /// FR-92 — the person at the machine stops keep busy. Waits (briefly)
    /// for the engine, so the answer usually already reads "off".
    async fn keep_busy_off(&self) -> Response {
        let info = self.keep_busy_answer(true).await;
        tracing::info!(on = info.on, "localapi: keep busy stopped at this computer");
        Response::KeepBusy(info)
    }

    /// FR-92 P10 — the person at the console turns keep busy on. The
    /// dispatcher has already refused root, services and other sessions —
    /// but not a `meshharbor exec` on Windows, which runs in the console session
    /// (FR-92 §3g).
    ///
    /// ⚠️ Never relayed to a supervised Mac's GUI worker: the person's own
    /// clients reach the worker's socket directly, and nothing that can only
    /// reach the root daemon may start synthetic input. That daemon's own
    /// engine never runs, so it says where to turn it on instead.
    async fn keep_busy_on(&self, opts: tunnel_core::localapi::KeepBusyStartOpts) -> Response {
        if self.keep_busy_worker.is_some() {
            return Response::Error {
                message: "keep busy runs in this Mac's GUI session: turn it on from the Roomler \
                          menu-bar app, or with `roomler keep-busy on` as yourself"
                    .into(),
            };
        }
        match crate::keep_busy::start_locally_and_wait(&opts, crate::keep_busy::LOCAL_OFF_WAIT)
            .await
        {
            Ok(s) => {
                tracing::info!(
                    on = s.on,
                    reason = s.reason.map(|r| r.wire()).unwrap_or("-"),
                    "localapi: keep busy turned on at this computer"
                );
                Response::KeepBusy(crate::keep_busy::local_info(&s))
            }
            Err(message) => Response::Error { message },
        }
    }

    #[cfg(feature = "recording")]
    async fn recordings_list(&self) -> Response {
        match &self.recorder {
            Some(r) => r.list().await,
            None => recording_unavailable(),
        }
    }

    #[cfg(feature = "recording")]
    async fn recording_delete(&self, name: &str) -> Response {
        match &self.recorder {
            Some(r) => r.delete(name).await,
            None => recording_unavailable(),
        }
    }

    /// FR-84 D3 — "Apply now": restart this daemon through its supervisor.
    ///
    /// LocalAPI-only by construction: no server message reaches this, and
    /// remote configuration never restarts a daemon (docs/remote-config.md
    /// §7b). Refused unless a supervisor was PROVEN at startup, the device
    /// allows it (`local_restart_enabled`, read from the file for this
    /// request), nothing would be lost (a recording), and the last accepted
    /// restart — recorded on disk, so it binds the relaunched process too —
    /// is at least `RESTART_MIN_INTERVAL` old. Under systemd the unit's
    /// effective policy is read back before anything is promised.
    ///
    /// Accepting records the request durably FIRST (a restart that could not
    /// be recorded must not happen — the record is the loop bound), then arms
    /// the exit code and answers. The shutdown itself starts in
    /// [`Self::restart_commit`], after the answer is written.
    async fn restart_daemon(&self, reason: &str) -> Response {
        use crate::supervision as sup;
        let refuse = |message: String| Response::Error { message };
        let Some(restart) = self.restart.as_ref() else {
            return refuse("restarting is not available on this daemon".into());
        };
        let Some((config_path, lock)) = self.config_persist.as_ref() else {
            return refuse("restarting is not available on this daemon (no config)".into());
        };
        let reason = sup::sanitize_reason(reason);
        let inner = &restart.inner;
        let _one_at_a_time = inner.decide.lock().await;

        // The kill switch, from the FILE — the key is live, so an owner's
        // edit is in force for the very next request.
        let enabled = {
            let _guard = lock.lock().await;
            let path = config_path.clone();
            match tokio::task::spawn_blocking(move || crate::config::load(&path)).await {
                Ok(Ok(cfg)) => cfg.local_restart_enabled,
                Ok(Err(e)) => {
                    return refuse(format!(
                        "could not read local_restart_enabled from {}: {e:#}",
                        config_path.display()
                    ));
                }
                Err(e) => return refuse(format!("config read task: {e}")),
            }
        };
        let record_path = inner.record_path.clone();
        let last =
            match tokio::task::spawn_blocking(move || sup::read_last_request(&record_path)).await {
                Ok(Ok(last)) => last,
                Ok(Err(e)) => {
                    return refuse(format!(
                        "could not read the last restart's record ({e}) — refusing, because that \
                     record is what keeps a restart loop impossible"
                    ));
                }
                Err(e) => return refuse(format!("restart record task: {e}")),
            };
        #[cfg(feature = "recording")]
        let recording = crate::recording::manager::is_recording();
        #[cfg(not(feature = "recording"))]
        let recording = false;
        let now_ms = unix_now_ms();
        let inputs = sup::RestartInputs {
            supervision: inner.supervision,
            enabled,
            last_request_ms: last,
            now_ms,
            uptime: inner.started.elapsed(),
            recording,
            already_accepted: inner.accepted.get().is_some(),
        };
        let supervisor = inner.supervision.wire();
        let refused = |why: String| {
            tracing::info!(%reason, supervisor, refusal = %why, "restart requested through the LocalAPI: refused");
            refuse(why)
        };
        let plan = match sup::decide_restart(&inputs) {
            Ok(plan) => plan,
            Err(why) => return refused(why),
        };
        // #1684 — a systemd unit also tells us how long a stop+relaunch may
        // take (`TimeoutStopSec + RestartSec`), so the caller can wait that
        // long instead of a fixed guess. `None` for every other supervisor and
        // when systemd did not report the timers — the caller keeps its
        // default. Additive on the wire.
        let mut restart_within_s: Option<u64> = None;
        if let sup::Supervision::Systemd(unit) = inner.supervision {
            match sup::confirm_systemd(unit, plan.exit_code).await {
                Ok(within) => restart_within_s = within,
                Err(why) => return refused(why),
            }
        }
        let record = sup::RestartRecord {
            at_ms: now_ms,
            pid: std::process::id(),
            supervisor: plan.supervisor.to_string(),
            reason: reason.clone(),
        };
        let record_path = inner.record_path.clone();
        match tokio::task::spawn_blocking(move || sup::write_record(&record_path, &record)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return refused(format!(
                    "could not record this restart ({e}) — refusing, because that record is \
                     what keeps a restart loop impossible"
                ));
            }
            Err(e) => return refused(format!("restart record task: {e}")),
        }
        // Armed. From here the process WILL restart: `restart_commit` starts
        // the shutdown once this answer is written, and the fallback below
        // covers a connection that never gets that far.
        let _ = inner.accepted.set(plan.exit_code);
        tracing::info!(
            %reason,
            supervisor,
            restart_by = plan.restart_by,
            exit_code = plan.exit_code,
            "restart requested through the LocalAPI: accepted — leaving once the answer is written"
        );
        let fallback = restart.clone();
        tokio::spawn(async move {
            tokio::time::sleep(RESTART_COMMIT_FALLBACK).await;
            fallback.commit();
        });
        Response::DaemonRestarting {
            supervisor: plan.supervisor.to_string(),
            restart_by: plan.restart_by.to_string(),
            exit_code: plan.exit_code,
            pid: std::process::id(),
            started_at_ms: self.started_at_ms,
            restart_within_s,
        }
    }

    /// FR-84 D3 — the `DaemonRestarting` answer is written: start the
    /// graceful shutdown (no-op unless a restart was accepted).
    fn restart_commit(&self) {
        if let Some(restart) = self.restart.as_ref() {
            restart.commit();
        }
    }

    /// FR-90 P1h-2 — the root update helper (macOS) holds this daemon before
    /// `installer(8)` restarts it: the same wait the in-process updater runs
    /// (P1d-1), ended early only by the daemon stopping.
    async fn hive_update_hold(&self) -> Response {
        // Without a restart handle (tests, a daemon built without one) the
        // sender lives here, for as long as the wait does.
        let (_keep, idle) = watch::channel(false);
        let shutdown = self
            .restart
            .as_ref()
            .map(RestartHandle::shutdown_rx)
            .unwrap_or(idle);
        crate::updater::hold_for_install(shutdown).await
    }

    fn hive_update_release(&self) {
        crate::updater::release_install_hold();
    }

    /// FR-90 P3-9-2b — `meshharbor connect`: a person's endpoint, served to the
    /// account the LocalAPI listener read, its leases asked for the device's
    /// owner and renewed while the asking connection stays open.
    #[cfg(all(hive_host, feature = "vault"))]
    async fn connect(
        &self,
        asker: &tunnel_core::localapi::Asker,
        args: &tunnel_core::localapi::ConnectArgs,
    ) -> Response {
        match crate::hive::person_connect::open(asker, args).await {
            Ok((id, endpoint)) => Response::Connected { id, endpoint },
            Err(message) => Response::Error { message },
        }
    }

    #[cfg(all(hive_host, feature = "vault"))]
    fn connect_status(&self, id: u64) -> Response {
        match crate::hive::person_connect::state(id) {
            Some(state) => Response::ConnectState(state),
            None => Response::Error {
                message: format!("no endpoint {id} is held"),
            },
        }
    }

    #[cfg(all(hive_host, feature = "vault"))]
    fn connect_release(&self, id: u64) {
        crate::hive::person_connect::release(id);
    }

    /// Fleet RPC — relay an exec to another device over this daemon's own
    /// agent WS and wait for the answer.
    ///
    /// The daemon is the right actor for three reasons: it already holds an
    /// authenticated server connection (so the CLI needs no credentials of its
    /// own), the server can resolve THIS device's owner as the acting
    /// principal, and the answer arrives asynchronously on the WS receive path
    /// where only the daemon can catch it.
    ///
    /// Note the trust boundary here is deliberately NOT just the pipe ACL,
    /// unlike every other mutating verb: being on this box is not by itself
    /// authority to run commands on a different one. The server applies all
    /// four gates and additionally requires this device to be blessed with
    /// `ExecPolicy::can_originate`.
    async fn exec_remote(
        &self,
        node: &str,
        shell: &str,
        command: &str,
        timeout_ms: u64,
    ) -> Response {
        let Some(sink) = self.tunnel_hub.sink_now() else {
            return Response::Error {
                message: "not connected to the server — remote commands need the control \
                          connection (check `meshharbor status`)"
                    .into(),
            };
        };

        let request_id = bson::oid::ObjectId::new().to_hex();
        // Register the waiter BEFORE sending, or a fast answer could arrive
        // with nowhere to go.
        let (_guard, rx) = crate::exec::expect_response(&request_id);

        if sink
            .send(roomler_ai_remote_control::ClientMsg::RpcExecRequest {
                request_id: request_id.clone(),
                target: node.to_string(),
                shell: shell.to_string(),
                command: command.to_string(),
                timeout_ms,
            })
            .await
            .is_err()
        {
            return Response::Error {
                message: "the server connection dropped while sending the command".into(),
            };
        }

        // Our own patience: the command's budget, the server's grace, plus
        // slack for the two extra WS hops this leg adds over the HTTP path.
        let budget = roomler_ai_remote_control::models::exec_limits::clamp_timeout_ms(timeout_ms);
        let deadline = Duration::from_millis(budget) + Duration::from_secs(30);
        let outcome = match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(o)) => o,
            // The waiter was dropped without a value — only happens if the
            // signalling loop tore down mid-flight.
            Ok(Err(_)) => crate::exec::ExecOutcome {
                error: Some("the server connection dropped while awaiting the result".into()),
                ..Default::default()
            },
            Err(_) => crate::exec::ExecOutcome {
                error: Some(format!(
                    "no answer from {node} within {}s",
                    deadline.as_secs()
                )),
                ..Default::default()
            },
        };

        Response::ExecResult {
            request_id,
            node: node.to_string(),
            exit_code: outcome.exit_code,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            truncated: outcome.truncated,
            duration_ms: outcome.duration_ms,
            error: outcome.error,
        }
    }

    /// Roomler SSH (P6b) — relay a grant request over this device's control
    /// WS and hand the answer back to the local caller.
    ///
    /// The public key is the CALLER's; the daemon never sees the private half,
    /// so a grant observed anywhere along this path is useless on its own.
    async fn ssh_session(&self, node: &str, public_key: &str, session_secs: u64) -> Response {
        let Some(sink) = self.tunnel_hub.sink_now() else {
            return Response::Error {
                message: "not connected to the server — SSH grants need the control \
                          connection (check `meshharbor status`)"
                    .into(),
            };
        };

        let request_id = bson::oid::ObjectId::new().to_hex();
        // Register the waiter BEFORE sending, or a fast answer could arrive
        // with nowhere to go.
        let (_guard, rx) = crate::ssh_origin::expect_response(&request_id);

        if sink
            .send(roomler_ai_remote_control::ClientMsg::SshRequest {
                request_id: request_id.clone(),
                target: node.to_string(),
                public_key: public_key.to_string(),
                session_secs,
                // A person's request: no agent session's ticket (FR-90 P3-8).
                ssh_ticket: None,
            })
            .await
            .is_err()
        {
            return Response::Error {
                message: "the server connection dropped while requesting the session".into(),
            };
        }

        // Short on purpose: this is a gate decision plus one push to the
        // target, not a command that runs. A grant also expires in ~60 s, so
        // waiting minutes for one would hand back something already dead.
        let deadline = std::time::Duration::from_secs(30);
        let answer = match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(a)) => a,
            Ok(Err(_)) => crate::ssh_origin::SshGrantAnswer {
                error: Some("the server connection dropped while awaiting the grant".into()),
                ..Default::default()
            },
            Err(_) => crate::ssh_origin::SshGrantAnswer {
                error: Some(format!(
                    "no answer about {node} within {}s",
                    deadline.as_secs()
                )),
                ..Default::default()
            },
        };

        Response::SshSession {
            request_id,
            node: node.to_string(),
            address: answer.address,
            port: answer.port,
            host_pubkey: answer.host_pubkey,
            grant_id: answer.grant_id,
            expires_at_ms: answer.expires_at_ms,
            error: answer.error,
        }
    }

    /// FR-84 D5b — the devices this device may see, asked of the org's
    /// server with the org's agent token (`self_view.rs`). Read-only; the
    /// token never crosses the pipe.
    ///
    /// FR-97 P2g — on a Mac's per-user half, which has no overlay node, the
    /// server's answer is this device alone (`no_node`); the machine's view is
    /// the root half's, asked over its person socket
    /// ([`crate::person_socket::or_machine_view`]).
    async fn devices(&self, org: &str, query: &tunnel_core::localapi::DevicesQuery) -> Response {
        let own = match &self.self_view {
            Some(view) => view.devices(org, query).await,
            None => Response::Upstream {
                code: "unsupported".into(),
                message: "this daemon was started without a server identity to ask".into(),
                status: None,
            },
        };
        let req = tunnel_core::localapi::Request::Devices {
            org: org.to_string(),
            page: query.page,
            per_page: query.per_page,
            q: query.q.clone(),
            sort: query.sort.clone(),
            dir: query.dir.clone(),
        };
        crate::person_socket::or_machine_view(own, req).await
    }

    /// FR-84 D5b — the mesh graph for the same set (and, FR-97 P2g, the
    /// machine's on a Mac's per-user half, as [`Self::devices`]).
    async fn mesh(&self, org: &str) -> Response {
        let own = match &self.self_view {
            Some(view) => view.mesh(org).await,
            None => Response::Upstream {
                code: "unsupported".into(),
                message: "this daemon was started without a server identity to ask".into(),
                status: None,
            },
        };
        let req = tunnel_core::localapi::Request::Mesh {
            org: org.to_string(),
        };
        crate::person_socket::or_machine_view(own, req).await
    }

    /// FR-97 P2h — on a Mac's per-user half, which runs no overlay node, the
    /// network fields of the status (overlay addresses, exit, MagicDNS) are the
    /// root half's ([`crate::person_socket::or_machine_status`]). Everywhere
    /// else, and on a half with a node of its own, the status is its own.
    async fn status_view(&self) -> NodeStatus {
        #[cfg(target_os = "macos")]
        {
            crate::person_socket::or_machine_status(self.status()).await
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.status()
        }
    }

    /// FR-97 P2h — and so are its peers, the live links the companion's
    /// Connection column and Overview count read.
    async fn peers_view(&self) -> Vec<PeerInfo> {
        #[cfg(target_os = "macos")]
        {
            // Cloned out first: no borrow of the overlay state across the await.
            let own_ip = self.overlay.borrow().self_ip.clone();
            crate::person_socket::or_machine_peers(self.peers(), own_ip.as_deref()).await
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.peers()
        }
    }

    /// S1b — archive the STALE config copy on a split-config host (the
    /// desktop's "Two configurations found" banner finally gets a button).
    /// The daemon is the only safe actor: it knows which copy it LOADED and
    /// has the rights to touch `%PROGRAMDATA%`. Guards:
    ///   * a second copy must actually exist,
    ///   * the daemon must be connected (proves the live copy's token works),
    ///   * both copies must parse and carry the SAME `agent_id` (a different
    ///     id = a second enrollment — refused, an operator must decide),
    ///   * the stale copy is renamed aside (`config.toml.stale-<ts>`), never
    ///     deleted.
    async fn config_cleanup_stale(&self) -> Response {
        let Some((live_path, lock)) = self.config_persist.as_ref() else {
            return Response::Error {
                message: "config cleanup is not available on this daemon".into(),
            };
        };
        // Candidate copies: the per-user default + (Windows) machine-global.
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(p) = crate::config::default_config_path() {
            candidates.push(p);
        }
        #[cfg(target_os = "windows")]
        candidates.push(crate::config::machine_global_config_path());
        let stale: Vec<_> = candidates
            .into_iter()
            .filter(|p| p != live_path && p.exists())
            .collect();
        let Some(stale_path) = stale.first().cloned() else {
            return Response::ConfigCleaned {
                ok: false,
                detail: "no stale config copy present".into(),
            };
        };
        if !self.connected.load(Ordering::Relaxed) {
            return Response::Error {
                message: "refusing cleanup while disconnected — the live config's \
                          token isn't proven working"
                    .into(),
            };
        }
        let _guard = lock.lock().await;
        let live = match crate::config::load(live_path) {
            Ok(c) => c,
            Err(e) => {
                return Response::Error {
                    message: format!("live config unreadable: {e:#}"),
                };
            }
        };
        let stale_cfg = match crate::config::load(&stale_path) {
            Ok(c) => c,
            Err(e) => {
                return Response::Error {
                    message: format!("stale config unreadable ({}): {e:#}", stale_path.display()),
                };
            }
        };
        if live.agent_id.is_empty() || live.agent_id != stale_cfg.agent_id {
            return Response::Error {
                message: format!(
                    "refusing cleanup: the copies carry different identities \
                     (live agent_id {} vs {} in {}) — that's a second enrollment, \
                     not a stale duplicate",
                    live.agent_id,
                    stale_cfg.agent_id,
                    stale_path.display()
                ),
            };
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let archived = stale_path.with_extension(format!("toml.stale-{ts}"));
        match std::fs::rename(&stale_path, &archived) {
            Ok(()) => {
                tracing::info!(
                    stale = %stale_path.display(),
                    archived = %archived.display(),
                    "localapi: archived stale config copy"
                );
                Response::ConfigCleaned {
                    ok: true,
                    detail: format!(
                        "archived {} -> {}",
                        stale_path.display(),
                        archived.display()
                    ),
                }
            }
            Err(e) => Response::Error {
                message: format!("archiving {} failed: {e}", stale_path.display()),
            },
        }
    }
}

/// Overlay [`ConnectionType::Tunnel`] onto every peer whose WG carrier is down
/// (`Blocked`/`Offline`) but whose backing `agent_id` is in `tunneled` — the set
/// of agent ids reached by a live daemon tunnel flow (P3b-3). Pure so the
/// precedence (Direct > Relay > **Tunnel** > Blocked > Offline — Tunnel never
/// masks a live WG carrier) is unit-tested without a hub. No-op on empty
/// `tunneled`.
fn apply_tunnel_override(peers: &mut [PeerInfo], tunneled: &HashSet<String>) {
    if tunneled.is_empty() {
        return;
    }
    for p in peers.iter_mut() {
        let gap = matches!(
            p.connection,
            ConnectionType::Blocked | ConnectionType::Offline
        );
        if gap && p.agent_id.as_deref().is_some_and(|a| tunneled.contains(a)) {
            p.connection = ConnectionType::Tunnel;
        }
    }
}

/// Spawn the RTT prober (P3b-3): every [`RTT_PROBE_INTERVAL`], ICMP-ping each
/// carrier-reachable peer over the userspace netstack and cache the round-trip
/// so `peers()` can surface `rtt_ms`. Only meaningful on a netstack node (the
/// caller spawns it only when a `pinger` exists); the cache stays empty
/// otherwise and every peer's `rtt_ms` is `None`.
///
/// Probes **only** `Direct`/`Relay` peers — a `Blocked`/`Offline` peer has no
/// working carrier, so a ping just burns the full timeout and would stretch the
/// sequential cycle. Pings sequentially so a burst of ICMP never hits the wire
/// at once; the worst-case cycle is (live-peer-count × [`RTT_PROBE_TIMEOUT`]),
/// comfortably under the interval for realistic meshes. Exits on `shutdown`.
pub fn spawn_rtt_prober(
    pinger: Arc<dyn NetstackPinger>,
    overlay: watch::Receiver<OverlayView>,
    cache: RttCache,
    mut shutdown: watch::Receiver<bool>,
    on_sample: Option<RttSampleHook>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RTT_PROBE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
                _ = tick.tick() => {}
            }
            // Snapshot the peers to probe, then release the watch borrow before
            // any await (the borrow is not held across the ping).
            let targets: Vec<(String, String, IpAddr)> = overlay
                .borrow()
                .peers
                .iter()
                .filter(|p| matches!(p.connection, ConnectionType::Direct | ConnectionType::Relay))
                .filter_map(|p| {
                    let ip = p.overlay_ip.as_deref()?;
                    ip.parse::<IpAddr>()
                        .ok()
                        .map(|addr| (p.node_id.clone(), ip.to_string(), addr))
                })
                .collect();
            for (node_id, key, ip) in targets {
                if let Ok(rtt) = pinger.ping(ip, RTT_PROBE_TIMEOUT).await {
                    let ms = rtt.as_millis().min(u32::MAX as u128) as u32;
                    if let Ok(mut c) = cache.lock() {
                        c.insert(key, (ms, Instant::now()));
                    }
                    // B1 — hand the sample to the overlay runtime's quality
                    // plane (a timeout deliberately hands over NOTHING —
                    // loss is the death path's business).
                    if let Some(hook) = &on_sample {
                        hook(&node_id, ms);
                    }
                }
            }
        }
    });
}

/// B1 — optional per-sample prober callback: `(node_id_hex, rtt_ms)` for
/// every SUCCESSFUL probe. Feature-agnostic — the overlay-enabled caller
/// (main.rs) bridges it into the runtime's `OverlayEvent` channel via a
/// weak sender, so this module never grows an overlay-feature dependency.
pub type RttSampleHook = Arc<dyn Fn(&str, u32) + Send + Sync>;

/// A 24-char hex ObjectId — the only shape a session id may take before it's
/// used as a sentinel filename. Guards [`DaemonState::consent_decide`] against a
/// caller smuggling path separators / traversal into the filename.
/// FR-52 — build the device's gate-3 / gate-4 view from its config.
///
/// ⚠️ `password_set` requires **both** halves. A config holding one without the
/// other authenticates nobody, so reporting it as "set" would tell an operator
/// their device is ready when the next connection attempt will fail to parse the
/// record — and the fix for both states is the same command, so there is nothing
/// lost by calling the broken one "not set".
///
/// ⚠️ `supported` is `cfg!`, not a runtime probe: it answers "was this binary
/// built with the credential stack", which is the question whose fix is a
/// different build rather than a different command.
fn external_password_state(cfg: &crate::config::AgentConfig) -> ExternalPasswordState {
    ExternalPasswordState {
        supported: cfg!(feature = "external-access"),
        password_set: cfg.external_access_setup.is_some() && cfg.external_access_verifier.is_some(),
        enabled: cfg.external_access_enabled,
        consent_mode: cfg.external_consent_mode.clone(),
        max_permissions: cfg.external_max_permissions.clone(),
    }
}

fn is_hex_object_id(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tunnel_core::localapi::ConnectionType;

    /// P8-cosmetics — the locale-tolerant ping-output parse: English, German,
    /// sub-millisecond, and Linux fractional forms all yield the right integer;
    /// output without a real measurement yields None.
    #[test]
    fn parse_ping_ms_is_locale_tolerant() {
        assert_eq!(
            parse_ping_ms("Reply from 100.64.0.1: bytes=32 time=4ms TTL=128"),
            Some(4)
        );
        assert_eq!(
            parse_ping_ms("Antwort von 100.64.0.1: Bytes=32 Zeit=101ms TTL=128"),
            Some(101)
        );
        assert_eq!(
            parse_ping_ms("Reply from 100.64.0.1: bytes=32 time<1ms TTL=128"),
            Some(1)
        );
        assert_eq!(
            parse_ping_ms("64 bytes from 100.64.0.14: icmp_seq=1 ttl=64 time=0.523 ms"),
            Some(0)
        );
        assert_eq!(parse_ping_ms("Request timed out."), None);
        assert_eq!(parse_ping_ms("streams and other ms-free words"), None);
    }

    fn view() -> OverlayView {
        OverlayView {
            path_trials: None,
            self_ip: Some("100.64.0.2".into()),
            self_ip6: Some("fd72:6f6f:6d6c::6440:2".into()),
            peers: vec![PeerInfo {
                node_id: "n2".into(),
                name: "peer".into(),
                org: String::new(),
                overlay_ip: Some("100.64.0.1".into()),
                overlay_ip6: Some("fd72:6f6f:6d6c::6440:1".into()),
                online: true,
                connection: ConnectionType::Relay,
                upgrading: false,
                stalled: false,
                rtt_ms: None,
                last_seen_ms: None,
                agent_id: None,
                relay_local: Some("94.130.141.74:10850".into()),
                relay_dst: Some("5.9.157.226:12728".into()),
                relay_kind: None,
                relay_transport: None,
                relay_server: None,
                why: None,
                probes: Vec::new(),
                debug: None,
            }],
            exit_node: None,
            route_offer_withheld: None,
            host_firewall: None,
            dns: None,
            derp_inbound_drops: None,
            srflx: None,
            warm_relay: None,
            direct_socks: Vec::new(),
        }
    }

    fn consent_broker(tag: &str) -> crate::consent::ConsentBroker {
        crate::consent::ConsentBroker::new(
            crate::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("roomler-las-consent-{tag}-{}", std::process::id())),
        )
        .unwrap()
    }

    fn empty_rtt_cache() -> RttCache {
        Arc::new(Mutex::new(HashMap::new()))
    }

    /// `status` always names the account, and names the real one. Before
    /// this, `meshharbor status` printed "service (SYSTEM)" for every daemon: a
    /// per-user Fedora install read as a system one (FR-93's lab, 0.4.128).
    /// The test process is the daemon's stand-in: unprivileged in CI's lib
    /// lane, root under its sudo step.
    #[tokio::test]
    async fn status_names_the_account_the_daemon_runs_as() {
        let (_tx, rx) = watch::channel(view());
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("privileged"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        );
        let s = st.status();
        #[cfg(unix)]
        // SAFETY: `geteuid` reads the caller's own credentials; it cannot fail.
        let expected = unsafe { libc::geteuid() == 0 };
        #[cfg(windows)]
        let expected = crate::win_identity::process_is_local_system();
        assert_eq!(s.privileged, Some(expected));
        // The kind of node does not follow the account.
        assert_eq!(s.mode, DaemonMode::Service);
    }

    #[tokio::test]
    async fn resolve_targets_and_ping_without_pinger_errors() {
        let (_tx, rx) = watch::channel(view());
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("ping"),
            None, // no netstack pinger
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        );
        // Resolve by peer name (from `view`), by first label, and by literal IP.
        assert_eq!(
            st.resolve_overlay("peer", false),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))
        );
        assert_eq!(
            st.resolve_overlay("PEER.myorg.roomler.net", false),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))
        );
        assert_eq!(
            st.resolve_overlay("100.64.0.9", false),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)))
        );
        // prefer_v6 picks the runtime-published derived v6 for a NAME target…
        assert_eq!(
            st.resolve_overlay("peer", true),
            Some("fd72:6f6f:6d6c::6440:1".parse().unwrap())
        );
        // …and a literal v6 target is accepted as-is.
        assert_eq!(
            st.resolve_overlay("fd72:6f6f:6d6c::6440:9", false),
            Some("fd72:6f6f:6d6c::6440:9".parse().unwrap())
        );
        assert_eq!(st.resolve_overlay("ghost", false), None);
        // With no pinger (not a netstack node) `ping` is a clean Error, not a Pong.
        assert!(matches!(
            st.ping("peer", 0, false).await,
            Response::Error { .. }
        ));
    }

    #[test]
    fn consent_pending_scan_is_bounded() {
        let (_tx, rx) = watch::channel(view());
        let broker = consent_broker("cap");
        let dir = broker.sentinel_dir().to_path_buf();
        // Stuff the dir well past the cap with well-formed pending sentinels
        // (only the daemon writes here in production — this simulates a
        // corrupted / adversarially stuffed directory).
        for i in 0..80u32 {
            let req = tunnel_core::localapi::ConsentRequest {
                session_id: format!("{i:024x}"),
                controller_name: "x".into(),
                permissions: "VIEW_SCREEN".into(),
                timeout_secs: 30,
                kind: "rc".into(),
                detail: String::new(),
                expires_at_ms: 0,
                surface: String::new(),
                org: String::new(),
            };
            std::fs::write(
                dir.join(format!("{i:024x}.pending")),
                serde_json::to_string(&req).unwrap(),
            )
            .unwrap();
        }
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            broker,
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        );
        let pending = st.consent_pending();
        assert!(
            pending.len() <= 64,
            "consent_pending scan must be capped at 64, got {}",
            pending.len()
        );
        assert!(
            pending.len() >= 60,
            "the cap should still return a full page, got {}",
            pending.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_device_name_persists_and_updates_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut cfg = crate::config::test_fixture();
        cfg.machine_name = "old-name".into();
        crate::config::save(&path, &cfg).unwrap();

        let (_tx, rx) = watch::channel(view());
        let st = DaemonState::new(
            "aid".into(),
            "old-name".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("rename"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        )
        .with_config_persist(path.clone(), Arc::new(tokio::sync::Mutex::new(())));

        // Rejections: empty + oversized names never touch the config.
        assert!(matches!(
            st.set_device_name("   ").await,
            Response::Error { .. }
        ));
        assert!(matches!(
            st.set_device_name(&"x".repeat(80)).await,
            Response::Error { .. }
        ));
        assert_eq!(crate::config::load(&path).unwrap().machine_name, "old-name");

        // Happy path: trimmed, persisted, and live in status() immediately.
        match st.set_device_name("  new-name  ").await {
            Response::DeviceNameSet { name } => assert_eq!(name, "new-name"),
            other => panic!("expected DeviceNameSet, got {other:?}"),
        }
        assert_eq!(st.status().name, "new-name");
        assert_eq!(crate::config::load(&path).unwrap().machine_name, "new-name");

        // Without a persist target the verb is a clean unsupported error.
        let (_tx2, rx2) = watch::channel(view());
        let bare = DaemonState::new(
            "aid".into(),
            "n".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx2,
            consent_broker("rename2"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        );
        assert!(matches!(
            bare.set_device_name("x").await,
            Response::Error { .. }
        ));
    }

    /// FR-84 D5b — the verbs reach the self-view only when a registry was
    /// attached; without one the answer is the named `unsupported`, never a
    /// bare error a client could mistake for "no devices".
    #[tokio::test]
    async fn devices_and_mesh_route_through_the_attached_registry() {
        fn state(tag: &str) -> DaemonState {
            let (_tx, rx) = watch::channel(view());
            DaemonState::new(
                "aid".into(),
                "host".into(),
                DaemonMode::Service,
                None,
                Arc::new(AtomicBool::new(true)),
                rx,
                consent_broker(tag),
                None,
                crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
                empty_rtt_cache(),
            )
        }
        let q = tunnel_core::localapi::DevicesQuery::default();

        let bare = state("dv-bare");
        assert!(matches!(
            bare.devices("", &q).await,
            Response::Upstream { ref code, .. } if code == "unsupported"
        ));
        assert!(matches!(
            bare.mesh("").await,
            Response::Upstream { ref code, .. } if code == "unsupported"
        ));

        // With a registry, the org is resolved BEFORE any request: an unknown
        // label is named as such (no server is contacted — none exists here).
        let registry: crate::self_view::OrgHttpRegistry =
            Arc::new(Mutex::new(vec![crate::self_view::OrgHttp {
                label: "primary".into(),
                server_url: "https://example.invalid".into(),
                token: crate::token_slot::TokenSlot::new("tok"),
                primary: true,
                enabled: true,
            }]));
        let wired = state("dv-wired").with_org_http(registry);
        assert!(matches!(
            wired.devices("ghost", &q).await,
            Response::Upstream { ref code, .. } if code == "unknown_org"
        ));
    }

    /// FR-84 D4 — `files_dir` is gated in the daemon's `ConfigSet` BEFORE
    /// the save: a folder this writer would refuse at use time (a system
    /// root; a path that is a file) never reaches the config, the refusal
    /// travels verbatim, and nothing is re-seeded. An accepted folder is
    /// created, persisted, live for the next drop at once — which is why
    /// the surface reports the key `restart_required = false` — and shown
    /// on `status()`.
    #[tokio::test]
    async fn config_set_files_dir_is_gated_before_the_save_and_live_after_it() {
        let _lock = crate::files::FILES_DIR_TEST_LOCK.lock().await;
        crate::files::set_files_dir(None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        crate::config::save(&path, &crate::config::test_fixture()).unwrap();
        let (_tx, rx) = watch::channel(view());
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("files-dir"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        )
        .with_config_persist(path.clone(), Arc::new(tokio::sync::Mutex::new(())));

        // Refused by placement: a system root. The surface would refuse this
        // too; the daemon refuses it first and persists nothing.
        let system_dir = if cfg!(windows) {
            r"C:\Windows\Temp\roomler-drops"
        } else {
            "/usr/roomler-drops"
        };
        match st.config_set("files_dir", Some(system_dir)).await {
            Response::Error { message } => {
                assert!(message.contains("must not be under"), "{message}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(crate::config::load(&path).unwrap().files_dir, None);
        assert_eq!(crate::files::configured_files_dir(), None);

        // Refused by reality — something only the daemon's disk can tell:
        // the path exists and is a FILE.
        let blocker = dir.path().join("not-a-folder");
        std::fs::write(&blocker, b"x").unwrap();
        match st
            .config_set("files_dir", Some(&blocker.to_string_lossy()))
            .await
        {
            Response::Error { message } => assert!(message.contains("not a folder"), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(crate::config::load(&path).unwrap().files_dir, None);

        // Accepted: created, persisted, live, on status.
        let good = dir.path().join("drops");
        let spelled = good.to_string_lossy().into_owned();
        match st.config_set("files_dir", Some(&spelled)).await {
            Response::ConfigUpdated { entry } => {
                assert!(!entry.restart_required, "files_dir is live");
                assert_eq!(entry.value.as_deref(), Some(spelled.as_str()));
            }
            other => panic!("expected ConfigUpdated, got {other:?}"),
        }
        assert!(good.is_dir(), "created at set time");
        assert_eq!(
            crate::config::load(&path).unwrap().files_dir.as_deref(),
            Some(spelled.as_str())
        );
        assert_eq!(
            crate::files::configured_files_dir().as_deref(),
            Some(spelled.as_str()),
            "re-seeded for the next drop without a restart"
        );
        assert_eq!(st.status().files_dir.as_deref(), Some(spelled.as_str()));

        // Cleared: back to the ladder, also live, and status still names
        // a folder.
        match st.config_set("files_dir", None).await {
            Response::ConfigUpdated { entry } => assert_eq!(entry.value, None),
            other => panic!("expected ConfigUpdated, got {other:?}"),
        }
        assert_eq!(crate::files::configured_files_dir(), None);
        let after = st.status().files_dir;
        assert!(after.is_some(), "the default ladder names a folder");
        assert_ne!(after.as_deref(), Some(spelled.as_str()));
    }

    #[test]
    fn consent_decide_hex_guard_rejects_unsafe_session_ids() {
        // The guard fires BEFORE any filesystem write, so a bad id is a pure
        // no-op — traversal / separators / wrong-length are all rejected.
        assert!(is_hex_object_id("0123456789abcdef01234567"));
        assert!(is_hex_object_id("6A11682E804368D30EDF57C6")); // upper-case hex ok
        assert!(!is_hex_object_id("6a11682e804368d30edf57c")); // 23 chars
        assert!(!is_hex_object_id("6a11682e804368d30edf57c6z")); // 25 / non-hex
        assert!(!is_hex_object_id("../../etc/passwd"));
        assert!(!is_hex_object_id("6a11682e804368d30edf57c6.approve"));
        assert!(!is_hex_object_id(""));
    }

    #[test]
    fn status_and_peers_track_connected_flag() {
        let connected = Arc::new(AtomicBool::new(false));
        let (_tx, rx) = watch::channel(view());
        let consent = crate::consent::ConsentBroker::new(
            crate::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("roomler-las-consent-{}", std::process::id())),
        )
        .unwrap();
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            Some("tid".into()),
            connected.clone(),
            rx,
            consent,
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        );

        // Identity + overlay IP are always reported; connected reflects the flag.
        let s = st.status();
        assert_eq!(s.node_id, "aid");
        assert_eq!(s.name, "host");
        assert_eq!(s.tenant_id.as_deref(), Some("tid"));
        assert_eq!(s.overlay_ip.as_deref(), Some("100.64.0.2"));
        assert!(!s.connected);

        // Peers hidden while disconnected…
        assert!(st.peers().is_empty(), "no peers reported while WS is down");

        // …shown once connected.
        connected.store(true, Ordering::Relaxed);
        assert!(st.status().connected);
        let peers = st.peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].connection, ConnectionType::Relay);

        // Flows are empty on the agent side in P1.
        assert!(st.flows().is_empty());
    }

    #[test]
    fn peers_fill_rtt_from_fresh_cache_and_drop_stale() {
        // The `view()` peer is a Relay with overlay_ip 100.64.0.1.
        let (_tx, rx) = watch::channel(view());
        let cache = empty_rtt_cache();
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("rtt"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            cache.clone(),
        );

        // Fresh cache entry → surfaced as rtt_ms.
        cache
            .lock()
            .unwrap()
            .insert("100.64.0.1".into(), (52, Instant::now()));
        assert_eq!(st.peers()[0].rtt_ms, Some(52));

        // Stale entry (older than RTT_STALE) → dropped to None (fade to "—").
        let stale_at = Instant::now()
            .checked_sub(RTT_STALE + Duration::from_secs(1))
            .unwrap();
        cache
            .lock()
            .unwrap()
            .insert("100.64.0.1".into(), (52, stale_at));
        assert_eq!(st.peers()[0].rtt_ms, None);

        // Empty cache → None.
        cache.lock().unwrap().clear();
        assert_eq!(st.peers()[0].rtt_ms, None);
    }

    #[test]
    fn tunnel_override_only_fills_carrier_gaps_and_respects_precedence() {
        fn peer(agent: Option<&str>, conn: ConnectionType) -> PeerInfo {
            PeerInfo {
                node_id: "n".into(),
                name: "p".into(),
                org: String::new(),
                overlay_ip: None,
                overlay_ip6: None,
                online: true,
                connection: conn,
                upgrading: false,
                stalled: false,
                rtt_ms: None,
                last_seen_ms: None,
                agent_id: agent.map(|s| s.into()),
                relay_local: None,
                relay_dst: None,
                relay_kind: None,
                relay_transport: None,
                relay_server: None,
                why: None,
                probes: Vec::new(),
                debug: None,
            }
        }
        let tunneled: HashSet<String> = ["aid-1".to_string()].into_iter().collect();
        let mut peers = vec![
            peer(Some("aid-1"), ConnectionType::Blocked), // → Tunnel (gap + live flow)
            peer(Some("aid-1"), ConnectionType::Offline), // → Tunnel (gap + live flow)
            peer(Some("aid-1"), ConnectionType::Direct),  // stays Direct (carrier wins)
            peer(Some("aid-1"), ConnectionType::Relay),   // stays Relay (carrier wins)
            peer(Some("aid-2"), ConnectionType::Blocked), // stays Blocked (no flow)
            peer(None, ConnectionType::Blocked),          // stays Blocked (no agent_id)
        ];
        apply_tunnel_override(&mut peers, &tunneled);
        assert_eq!(peers[0].connection, ConnectionType::Tunnel);
        assert_eq!(peers[1].connection, ConnectionType::Tunnel);
        assert_eq!(peers[2].connection, ConnectionType::Direct);
        assert_eq!(peers[3].connection, ConnectionType::Relay);
        assert_eq!(peers[4].connection, ConnectionType::Blocked);
        assert_eq!(peers[5].connection, ConnectionType::Blocked);

        // Empty tunneled set → untouched.
        let mut p2 = vec![peer(Some("aid-1"), ConnectionType::Blocked)];
        apply_tunnel_override(&mut p2, &HashSet::new());
        assert_eq!(p2[0].connection, ConnectionType::Blocked);
    }

    // ── FR-84 D3: the restart verb, end to end on the daemon side ──────────

    use crate::supervision::{RESTART_RECORD_FILE, Supervision, SystemdUnit};

    /// A fresh config directory holding a real `config.toml` (the verb reads
    /// `local_restart_enabled` from the FILE), unique per test.
    fn restart_dir(tag: &str, enabled: bool) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("roomler-las-restart-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = crate::config::test_fixture();
        cfg.local_restart_enabled = enabled;
        crate::config::save(&dir.join("config.toml"), &cfg).unwrap();
        dir
    }

    /// A `DaemonState` wired the way `run_cmd` wires it for the verb — as a
    /// freshly started process would be (its own handle, its own shutdown
    /// channel), over the config in `dir`.
    fn restart_state(
        dir: &std::path::Path,
        supervision: Supervision,
    ) -> (DaemonState, RestartHandle, watch::Receiver<bool>) {
        let (_ov_tx, ov_rx) = watch::channel(view());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let config = dir.join("config.toml");
        let restart = RestartHandle::new(
            supervision,
            shutdown_tx,
            // Just started — which only FR-43's worker minds, and it has its
            // own test (`a_young_macos_worker_waits_out_the_fr43_threshold`).
            // Not `now - 1h`: that panics on a runner booted under an hour ago.
            Instant::now(),
            crate::supervision::restart_record_path(&config),
        );
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            ov_rx,
            consent_broker("restart"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        )
        .with_config_persist(config, Arc::new(tokio::sync::Mutex::new(())))
        .with_restart(restart.clone());
        (st, restart, shutdown_rx)
    }

    fn refusal(resp: Response) -> String {
        match resp {
            Response::Error { message } => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The orphan `meshharbord run`: refused, nothing recorded, and even an
    /// explicit commit starts no shutdown — nothing was accepted.
    #[tokio::test]
    async fn restart_refused_when_unsupervised() {
        let dir = restart_dir("orphan", true);
        let (st, restart, shutdown) = restart_state(&dir, Supervision::None);
        let why = refusal(st.restart_daemon("apply").await);
        assert!(why.contains("not running under a service manager"), "{why}");
        assert!(
            !dir.join(RESTART_RECORD_FILE).exists(),
            "a refusal records nothing"
        );
        st.restart_commit();
        assert!(
            !*shutdown.borrow(),
            "a refused restart never shuts the daemon down"
        );
        assert_eq!(restart.accepted_exit_code(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `local_restart_enabled = false` in the file refuses — and the key is
    /// LIVE: turning it back on in the file is in force for the next request,
    /// no restart needed (which would be circular).
    #[tokio::test]
    async fn restart_refused_when_disabled_and_the_switch_is_live() {
        let dir = restart_dir("disabled", false);
        let (st, _restart, shutdown) = restart_state(&dir, Supervision::WindowsScm);
        let why = refusal(st.restart_daemon("apply").await);
        assert!(why.contains("local_restart_enabled = false"), "{why}");
        assert!(!*shutdown.borrow());
        // Same process, the file flipped back on through the LocalAPI.
        assert!(matches!(
            st.config_set("local_restart_enabled", Some("true")).await,
            Response::ConfigUpdated { .. }
        ));
        assert!(matches!(
            st.restart_daemon("apply").await,
            Response::DaemonRestarting { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Accepted: the answer names the supervisor's own exit code, the request
    /// is on disk BEFORE the answer, and the shutdown starts only at the
    /// commit — the LocalAPI loop's cue that the answer is out. A second ask
    /// in the same process is refused.
    #[tokio::test]
    async fn restart_accepted_records_first_and_shuts_down_only_on_commit() {
        let dir = restart_dir("accept", true);
        let (st, restart, shutdown) = restart_state(&dir, Supervision::WindowsScm);
        match st.restart_daemon("settings: overlay_enabled").await {
            Response::DaemonRestarting {
                supervisor,
                restart_by,
                exit_code,
                pid,
                started_at_ms,
                restart_within_s,
            } => {
                assert_eq!(supervisor, "scm");
                assert_eq!(restart_by, "supervisor");
                assert_eq!(exit_code, 0, "decide_exit_reaction(0) is Respawn");
                // #1684 — the SCM supervisor reports no stop+relaunch bound;
                // only systemd does. The caller keeps its fixed wait.
                assert_eq!(restart_within_s, None);
                // The same process identity `status` reports, so a waiting
                // caller can recognise the one that is leaving.
                let status = st.status();
                assert_eq!(Some(pid), status.pid);
                assert_eq!(Some(started_at_ms), status.started_at_ms);
            }
            other => panic!("expected DaemonRestarting, got {other:?}"),
        }
        let record = std::fs::read_to_string(dir.join(RESTART_RECORD_FILE)).unwrap();
        assert!(record.contains("settings: overlay_enabled"), "{record}");
        assert!(!*shutdown.borrow(), "armed, not yet committed");
        assert_eq!(restart.accepted_exit_code(), Some(0));
        st.restart_commit();
        assert!(
            *shutdown.borrow(),
            "the commit starts the internal shutdown"
        );
        let why = refusal(st.restart_daemon("again").await);
        assert!(why.contains("already under way"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The loop bound survives the restart it bounds: the relaunched process
    /// (a new handle, nothing in memory) reads the record and refuses a
    /// second restart inside the window.
    #[tokio::test]
    async fn restart_rate_limit_binds_the_relaunched_process() {
        let dir = restart_dir("ratelimit", true);
        let (st, _restart, _shutdown) = restart_state(&dir, Supervision::WindowsTask);
        match st.restart_daemon("first").await {
            Response::DaemonRestarting {
                restart_by,
                exit_code,
                ..
            } => {
                assert_eq!(restart_by, "caller", "the task's restart is the caller's");
                assert_eq!(exit_code, crate::watchdog::RESTART_REQUESTED_EXIT_CODE);
            }
            other => panic!("expected DaemonRestarting, got {other:?}"),
        }
        drop(st);
        let (next, next_restart, next_shutdown) = restart_state(&dir, Supervision::WindowsTask);
        let why = refusal(next.restart_daemon("second").await);
        assert!(
            why.contains("s ago") && why.contains("try again in"),
            "{why}"
        );
        assert!(!*next_shutdown.borrow());
        assert_eq!(next_restart.accepted_exit_code(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Under systemd nothing is promised until systemd itself confirms it
    /// will restart THIS process. A test process is never a unit's main
    /// process (and on a host without systemd there is nobody to ask), so
    /// the answer here is always a refusal — the fail-closed direction.
    #[tokio::test]
    async fn systemd_restart_is_refused_unless_systemd_confirms() {
        let dir = restart_dir("systemd", true);
        let unit = SystemdUnit {
            name: "meshharbord.service",
            user: false,
        };
        let (st, restart, shutdown) = restart_state(&dir, Supervision::Systemd(unit));
        let why = refusal(st.restart_daemon("apply").await);
        assert!(why.contains("meshharbord.service"), "{why}");
        assert!(!dir.join(RESTART_RECORD_FILE).exists());
        assert!(!*shutdown.borrow());
        assert_eq!(restart.accepted_exit_code(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FR-96 P2b — a restart the daemon decides itself (its binary was
    /// replaced) goes through the verb's own gates: never an orphan, and
    /// under systemd only once systemd confirms. Nothing is recorded or
    /// armed by a refusal.
    #[tokio::test]
    async fn a_self_decided_restart_passes_the_verbs_gates() {
        let unit = SystemdUnit {
            name: "meshharbor.service",
            user: true,
        };
        for (name, supervision, needle) in [
            (
                "self-orphan",
                Supervision::None,
                "not running under a service manager",
            ),
            (
                "self-systemd",
                Supervision::Systemd(unit),
                "meshharbor.service",
            ),
        ] {
            let dir = restart_dir(name, true);
            let (_st, restart, shutdown) = restart_state(&dir, supervision);
            let why = restart
                .arm_from_within("FR-96 P2b: replaced")
                .await
                .expect_err("refused");
            assert!(why.contains(needle), "{name}: {why}");
            assert!(!dir.join(RESTART_RECORD_FILE).exists(), "{name}");
            restart.commit();
            assert!(
                !*shutdown.borrow(),
                "{name}: nothing armed, nothing shut down"
            );
            assert_eq!(restart.accepted_exit_code(), None, "{name}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The one gate it does not share: `local_restart_enabled` is the owner's
    /// switch for restarts LOCAL CLIENTS ask for, and nobody is asking. It is
    /// recorded before it is armed, and shuts down only on the commit.
    #[tokio::test]
    async fn a_self_decided_restart_ignores_the_local_clients_switch() {
        let dir = restart_dir("self-switch", false);
        let (st, restart, shutdown) = restart_state(&dir, Supervision::WindowsScm);
        // The verb itself refuses on that switch…
        let why = refusal(st.restart_daemon("apply").await);
        assert!(why.contains("local_restart_enabled = false"), "{why}");
        // …the daemon's own restart does not.
        let plan = restart
            .arm_from_within("FR-96 P2b: replaced (0.4.1 -> 0.4.2)")
            .await
            .expect("armed");
        assert_eq!(plan.exit_code, 0, "the SCM's own respawn code");
        let record = std::fs::read_to_string(dir.join(RESTART_RECORD_FILE)).unwrap();
        assert!(record.contains("FR-96 P2b: replaced"), "{record}");
        assert_eq!(restart.accepted_exit_code(), Some(0));
        assert!(!*shutdown.borrow(), "armed, not yet committed");
        restart.commit();
        assert!(
            *shutdown.borrow(),
            "the commit starts the internal shutdown"
        );
        let why = restart.arm_from_within("again").await.expect_err("once");
        assert!(why.contains("already under way"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The loop bound is SHARED: a restart "Apply now" made binds the
    /// relaunched process's own restart too, through the one record.
    #[tokio::test]
    async fn a_self_decided_restart_shares_the_rate_limit_record() {
        let dir = restart_dir("self-ratelimit", true);
        let (st, _restart, _shutdown) = restart_state(&dir, Supervision::WindowsTask);
        assert!(matches!(
            st.restart_daemon("apply").await,
            Response::DaemonRestarting { .. }
        ));
        drop(st);
        let (_next, next_restart, next_shutdown) = restart_state(&dir, Supervision::WindowsTask);
        let why = next_restart
            .arm_from_within("FR-96 P2b: replaced")
            .await
            .expect_err("inside the window");
        assert!(
            why.contains("s ago") && why.contains("try again in"),
            "{why}"
        );
        assert!(!*next_shutdown.borrow());
        assert_eq!(next_restart.accepted_exit_code(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A daemon built without the handle (older shapes, other tests) says it
    /// cannot restart, and `status` names the answering process.
    #[tokio::test]
    async fn restart_without_a_handle_is_unavailable_and_status_names_the_pid() {
        let (_tx, rx) = watch::channel(view());
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("nohandle"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        );
        assert!(refusal(st.restart_daemon("x").await).contains("not available"));
        st.restart_commit(); // no handle: a no-op, not a panic
        let status = st.status();
        assert_eq!(status.pid, Some(std::process::id()));
        assert!(status.started_at_ms.is_some_and(|t| t > 0));
    }

    /// FR-92 — a supervised Mac's root daemon answers the keep-busy verbs with
    /// its GUI WORKER's state. The worker here says "running", which this
    /// process's own engine (never started in a test) cannot say: an answer
    /// from the daemon's own engine reads `on: false` and fails this. Field,
    /// 0.4.126: a root `roomler keep-busy off` answered "off" from the
    /// daemon's idle engine while the worker kept moving the pointer.
    #[tokio::test]
    async fn a_supervised_macs_daemon_answers_keep_busy_from_its_worker() {
        use crate::delegate::{DelegateFrame, DelegateHost, write_frame};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let host = DelegateHost::new();
        let secret = host.mint();
        let (client, server) = tokio::io::duplex(4096);
        let (rd, wr) = tokio::io::split(server);
        let h = host.clone();
        let serving =
            tokio::spawn(async move { h.serve(&secret, Box::new(rd), Box::new(wr)).await });
        let (crd, mut cwr) = tokio::io::split(client);
        let mut lines = BufReader::new(crd).lines();
        let greeting = lines.next_line().await.unwrap().expect("attached");
        assert!(greeting.contains("\"attached\""), "got {greeting}");
        // A ping answered: the daemon's frame loop, and its queue toward the
        // worker, are up.
        cwr.write_all(b"{\"t\":\"ping\"}\n").await.unwrap();
        assert!(
            lines
                .next_line()
                .await
                .unwrap()
                .unwrap()
                .contains("\"pong\"")
        );

        let worker = tokio::spawn(async move {
            loop {
                let line = lines.next_line().await.unwrap().expect("a question");
                if let Ok(DelegateFrame::KeepBusyAsk { id, off }) = serde_json::from_str(&line) {
                    let info = tunnel_core::localapi::KeepBusyInfo {
                        available: true,
                        on: !off,
                        phase: if off { "off" } else { "running" }.into(),
                        pattern: "wander".into(),
                        set_by: Some("Alice".into()),
                        ..Default::default()
                    };
                    let told = DelegateFrame::KeepBusyTold {
                        id,
                        info: Box::new(info),
                    };
                    write_frame(&mut cwr, &told).await.unwrap();
                    if off {
                        return (lines, cwr);
                    }
                }
            }
        });

        let (_tx, rx) = watch::channel(view());
        let st = DaemonState::new(
            "aid".into(),
            "host".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("keepbusy"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        )
        .with_keep_busy_worker(host.clone());

        match st.keep_busy_status().await {
            Response::KeepBusy(i) => assert_eq!(
                (i.on, i.phase.as_str(), i.set_by.as_deref()),
                (true, "running", Some("Alice")),
                "the status is the worker's"
            ),
            other => panic!("expected KeepBusy, got {other:?}"),
        }
        match st.keep_busy_off().await {
            Response::KeepBusy(i) => assert_eq!(
                (i.on, i.phase.as_str()),
                (false, "off"),
                "the worker was asked to stop, and said so"
            ),
            other => panic!("expected KeepBusy, got {other:?}"),
        }

        let (lines, cwr) = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("the fake worker answered both")
            .unwrap();
        drop(cwr);
        drop(lines);
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("the daemon loop ends with its channel")
            .unwrap();
    }

    /// FR-52 P2c — set → persist → reload → clear, against a real config file,
    /// and **the password is never on disk**.
    ///
    /// The last assertion is the one worth the test. Everything else here would
    /// still pass if `set_password` stored the plaintext beside the record, or
    /// if a future "cache the password to avoid re-deriving" optimisation landed
    /// — and a config file is exactly what gets copied into a support ticket,
    /// a backup, or a crash bundle. The gate's entire claim is that the password
    /// exists nowhere the server or a file copy can reach, so it is asserted
    /// here rather than trusted. (Falsified: leaking the plaintext into any
    /// other config field turns this red.)
    ///
    /// Only compiled with the credential stack: without it `set` is a refusal,
    /// which the wire test already covers.
    #[cfg(feature = "external-access")]
    #[tokio::test]
    async fn an_external_password_persists_and_never_lands_in_the_config_file() {
        // Built, not written — a scanner cannot tell a KDF input in a test from
        // a leaked credential, and it is right to stop the ones it sees.
        let password = format!("fr52-{}-not-a-credential-p2c", "roundtrip");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        crate::config::save(&path, &crate::config::test_fixture()).unwrap();

        let (_tx, rx) = watch::channel(view());
        let st = DaemonState::new(
            "aid".into(),
            "dev".into(),
            DaemonMode::Service,
            None,
            Arc::new(AtomicBool::new(true)),
            rx,
            consent_broker("extpw"),
            None,
            crate::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            empty_rtt_cache(),
        )
        .with_config_persist(path.clone(), Arc::new(tokio::sync::Mutex::new(())));

        // Nothing set yet.
        match st.external_password_status().await {
            Response::ExternalPassword(s) => {
                assert!(s.supported);
                assert!(!s.password_set);
                assert!(!s.enabled, "gate 3 is off by default");
            }
            other => panic!("expected ExternalPassword, got {other:?}"),
        }

        // A refused password must not touch the file — the same discipline
        // `set_device_name` has, and the reason the floor lives in the daemon.
        assert!(matches!(
            st.external_password_set(&Secret("short".into())).await,
            Response::Error { .. }
        ));
        assert!(
            crate::config::load(&path)
                .unwrap()
                .external_access_setup
                .is_none()
        );

        // Set it.
        match st.external_password_set(&Secret(password.clone())).await {
            Response::ExternalPassword(s) => assert!(s.password_set),
            other => panic!("expected ExternalPassword, got {other:?}"),
        }

        // It survives a reload — the daemon reads this file, not a snapshot.
        let stored = crate::config::load(&path).unwrap();
        let cred = crate::external_access::Credential {
            setup: stored.external_access_setup.clone().expect("setup"),
            verifier: stored.external_access_verifier.clone().expect("verifier"),
        };
        crate::external_access::parse(&cred).expect("the stored record must be readable back");
        assert!(
            !stored.external_access_enabled,
            "setting a password must not open gate 3"
        );

        // ⚠️ The plaintext is nowhere in the file. Checked against the RAW bytes,
        // not the parsed struct: a leak would most plausibly arrive as a new
        // field nobody thought to look at.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains(&password),
            "the password reached the config file on disk"
        );

        // Clear drops BOTH halves.
        match st.external_password_clear().await {
            Response::ExternalPassword(s) => assert!(!s.password_set),
            other => panic!("expected ExternalPassword, got {other:?}"),
        }
        let cleared = crate::config::load(&path).unwrap();
        assert!(cleared.external_access_setup.is_none(), "setup cleared");
        assert!(
            cleared.external_access_verifier.is_none(),
            "a surviving setup would be silently reused by the next set, reviving the OPAQUE \
             identity of a credential the operator believed destroyed"
        );
    }

    /// FR-52 — a half-written record reports NOT set, and gate 4 never reports
    /// gate 3.
    ///
    /// The half-written case is not hypothetical bookkeeping: it is what a
    /// hand-edited config, a partial merge or a future writer that forgets one
    /// field produces. Reporting it as "set" would tell an operator the device
    /// is ready, and the failure would surface as an unexplained refusal at the
    /// moment someone outside the org is waiting on the phone.
    ///
    /// The last assertion is the one that would catch a "helpful" change: a set
    /// that also flipped `external_access_enabled` would admit outsiders at the
    /// instant the owner was still preparing to.
    #[test]
    fn a_half_written_password_record_reports_not_set() {
        let mut cfg = crate::config::test_fixture();
        assert!(!external_password_state(&cfg).password_set, "neither half");

        cfg.external_access_setup = Some("setup".into());
        assert!(
            !external_password_state(&cfg).password_set,
            "a setup without a verifier authenticates nobody"
        );

        cfg.external_access_setup = None;
        cfg.external_access_verifier = Some("verifier".into());
        assert!(
            !external_password_state(&cfg).password_set,
            "a verifier without its setup cannot be read back"
        );

        cfg.external_access_setup = Some("setup".into());
        let state = external_password_state(&cfg);
        assert!(state.password_set, "both halves");
        assert!(
            !state.enabled,
            "gate 4 must not report gate 3 — a stored password opens nothing on its own"
        );
    }
}
