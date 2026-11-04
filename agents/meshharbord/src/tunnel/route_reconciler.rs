// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P6: the declared-route RECONCILER.
//!
//! A route (`tunnel_core::localapi::RouteDescriptor`, persisted as
//! `[[tunnel_routes]]` in the daemon config) is INTENT: "keep a
//! forward/SOCKS5 listener up toward this node". This module maps that
//! intent onto the hub's ephemeral flows and nothing more:
//!
//! - it does NOT supervise sessions — every hub flow already runs under
//!   `client_mgr::run_flow_supervisor` (1 s→30 s backoff, WS-reconnect
//!   aware). Building a second retry loop here would double-supervise.
//! - the ONLY net-new retry is around **flow creation** (`create_forward`
//!   fails fast on a taken port / bad input) — a transiently-taken port at
//!   boot must not permanently skip a declared route.
//! - a flow whose supervisor stopped on a PERMANENT failure
//!   (`FlowLive.fatal`: enrollment revoked, cross-tenant) becomes the
//!   terminal [`RouteState::Failed`] — cleared only by an operator
//!   `route enable` (or remove). Without the terminal state, a revoked
//!   route would hammer the server with a doomed TunnelOpen every 30 s,
//!   across reboots, forever.
//!
//! Persistence: the reconciler is the daemon-side writer of the
//! `tunnel_routes` config field. Every load-modify-save runs under the
//! daemon-wide config-write lock shared with main.rs's other runtime
//! writers (clean-run promotion, graceful shutdown) — see
//! `config::WriteLock`. Cross-PROCESS writers (tray enroll/device-name,
//! CLI, wizard) remain last-writer-wins on the whole file; `config::save`
//! is atomic (temp+rename) so a torn file is impossible either way.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, watch};
use tracing::{info, warn};
use tunnel_core::localapi::{FlowKind, RouteDescriptor, RouteInfo, RouteState};

use super::client_mgr::{FlowReport, TunnelClientHub};

/// Steady-state reconcile cadence. Every pass is cheap (in-memory diff +
/// a few hub map reads); creates only happen when something is out of
/// shape, so a short tick keeps `route add` → live latency low without
/// meaningful idle cost. A `kick` (route CRUD) reconciles immediately.
const RECONCILE_TICK: Duration = Duration::from_secs(5);

/// Create-retry backoff bounds (mirrors the hub's session backoff feel:
/// quick first retries, capped).
const CREATE_BACKOFF_MIN: Duration = Duration::from_secs(1);
const CREATE_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Runtime state the reconciler tracks per declared route id. Routes with
/// no entry are simply not-yet-considered (next pass picks them up).
enum RouteRuntime {
    /// Awaiting (re)creation; carries the create-retry bookkeeping.
    Pending {
        consecutive_failures: u32,
        next_retry: Option<Instant>,
        last_error: Option<String>,
    },
    /// The route's flow exists in the hub (hub supervises the session).
    Live { flow_id: String },
    /// Terminal — supervisor hit a permanent failure. Operator re-enable
    /// (or remove) clears it.
    Failed { reason: String },
}

impl RouteRuntime {
    fn fresh() -> Self {
        RouteRuntime::Pending {
            consecutive_failures: 0,
            next_retry: None,
            last_error: None,
        }
    }
}

/// The reconciler handle: cheap to clone; the reconcile task and the
/// LocalAPI verbs share one inner.
#[derive(Clone)]
pub struct RouteReconciler {
    inner: Arc<Inner>,
}

struct Inner {
    hub: TunnelClientHub,
    /// The SAME config file the daemon loaded (resolution ladder already
    /// applied by `run_cmd`) — never re-derived here.
    config_path: PathBuf,
    /// Daemon-wide config write lock (shared with main.rs's writers).
    cfg_lock: crate::config::WriteLock,
    /// Declared routes — in-memory mirror of `config.tunnel_routes`.
    routes: StdMutex<Vec<RouteDescriptor>>,
    /// Per-route runtime state, keyed by route id.
    runtime: StdMutex<HashMap<String, RouteRuntime>>,
    /// Wakes the reconcile task immediately after a CRUD change.
    kick: Notify,
    /// Monotonic source for generated route ids (`route-N`).
    seq: std::sync::atomic::AtomicU64,
}

impl RouteReconciler {
    /// Build from the routes the daemon just loaded. Call
    /// [`RouteReconciler::spawn`] to start reconciling.
    pub fn new(
        hub: TunnelClientHub,
        config_path: PathBuf,
        cfg_lock: crate::config::WriteLock,
        declared: Vec<RouteDescriptor>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                hub,
                config_path,
                cfg_lock,
                routes: StdMutex::new(declared),
                runtime: StdMutex::new(HashMap::new()),
                kick: Notify::new(),
                seq: std::sync::atomic::AtomicU64::new(1),
            }),
        }
    }

    /// Spawn the reconcile task: a pass on every tick / kick, until
    /// `shutdown`. Route flows die with the daemon (hub tasks are aborted
    /// on shutdown like every ephemeral flow) and come back on the next
    /// start from the persisted descriptors.
    pub fn spawn(&self, mut shutdown: watch::Receiver<bool>) {
        let this = self.clone();
        tokio::spawn(async move {
            info!(
                declared = this.inner.routes.lock().unwrap().len(),
                "route reconciler started"
            );
            // R1: a netstate Major clears every Pending route's backoff and
            // reconciles immediately — the failures that earned the backoff
            // described a network that no longer exists. The clear is what
            // makes the wake-up effective: `reconcile_pass` gates creation
            // on `now >= next_retry`, so a bare kick would still see the
            // route as not-due. Damped upstream (≤1 material Major/120 s).
            let mut net_rx = super::netwatch::subscribe();
            loop {
                this.reconcile_pass().await;
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                    _ = this.inner.kick.notified() => {}
                    summary = super::netwatch::next_major(&mut net_rx) => {
                        let cleared = this.clear_pending_backoffs();
                        info!(%summary, cleared, "network changed — reconciling routes now");
                    }
                    _ = tokio::time::sleep(RECONCILE_TICK) => {}
                }
            }
        });
    }

    /// Clear the `next_retry` gate on every `Pending` route so the next
    /// `reconcile_pass` re-creates them immediately. Returns how many were
    /// cleared. Deliberately does NOT touch `consecutive_failures` (the
    /// ladder resumes where it was if the new network fails too) and never
    /// touches terminal `Failed` (operator-owned).
    fn clear_pending_backoffs(&self) -> usize {
        let mut runtime = self.inner.runtime.lock().unwrap();
        let mut cleared = 0;
        for rt in runtime.values_mut() {
            if let RouteRuntime::Pending {
                next_retry: next_retry @ Some(_),
                ..
            } = rt
            {
                *next_retry = None;
                cleared += 1;
            }
        }
        cleared
    }

    /// One reconcile pass: converge hub flows toward the declared set.
    async fn reconcile_pass(&self) {
        let declared = self.inner.routes.lock().unwrap().clone();

        // 1) Tear down runtime for routes that are gone or disabled.
        let (to_kill, to_drop): (Vec<String>, Vec<String>) = {
            let runtime = self.inner.runtime.lock().unwrap();
            let mut kill = Vec::new();
            let mut drop_keys = Vec::new();
            for (id, rt) in runtime.iter() {
                let still_wanted = declared.iter().any(|r| &r.id == id && r.enabled);
                if !still_wanted {
                    if let RouteRuntime::Live { flow_id } = rt {
                        kill.push(flow_id.clone());
                    }
                    drop_keys.push(id.clone());
                }
            }
            (kill, drop_keys)
        };
        for flow_id in to_kill {
            self.inner.hub.kill_flow(&flow_id);
        }
        {
            let mut runtime = self.inner.runtime.lock().unwrap();
            for id in to_drop {
                runtime.remove(&id);
            }
        }

        // 2) Converge each enabled route. Creates await the hub, so state
        //    reads/writes are scoped to keep the mutexes un-held across
        //    awaits.
        for route in declared.iter().filter(|r| r.enabled) {
            // Multi-org P1: only primary-org routes are supervised. A
            // secondary label is legal in the schema (clients may write it
            // ahead of the P2/P3 supervision slice) but parks as terminal
            // Failed so a mislabeled route can't hammer the WRONG org's WS
            // with doomed opens.
            if let Some(org) = route.org.as_deref()
                && org != crate::config::PRIMARY_ORG_LABEL
            {
                let mut runtime = self.inner.runtime.lock().unwrap();
                if !matches!(runtime.get(&route.id), Some(RouteRuntime::Failed { .. })) {
                    warn!(
                        route = %route.id,
                        %org,
                        "declared route names a secondary org — parked (org route \
                         supervision lands with multi-org P2/P3)"
                    );
                    runtime.insert(
                        route.id.clone(),
                        RouteRuntime::Failed {
                            reason: format!(
                                "org {org:?} routes are not supervised yet (P1: primary only)"
                            ),
                        },
                    );
                }
                continue;
            }
            enum Action {
                Create,
                MarkFailed(String, String), // (flow_id to kill, reason)
                Nothing,
            }
            let action = {
                let mut runtime = self.inner.runtime.lock().unwrap();
                match runtime.get(&route.id) {
                    None => {
                        runtime.insert(route.id.clone(), RouteRuntime::fresh());
                        Action::Create
                    }
                    Some(RouteRuntime::Failed { .. }) => Action::Nothing,
                    Some(RouteRuntime::Live { flow_id }) => {
                        if let Some(reason) = self.inner.hub.flow_fatal(flow_id) {
                            Action::MarkFailed(flow_id.clone(), reason)
                        } else if !self.inner.hub.has_flow(flow_id) {
                            // Externally killed (operator `kill <flow>` on a
                            // route-owned flow). Declared intent wins —
                            // recreate; `route rm/disable` is the way to stop
                            // a declared route.
                            runtime.insert(route.id.clone(), RouteRuntime::fresh());
                            Action::Create
                        } else {
                            Action::Nothing
                        }
                    }
                    Some(RouteRuntime::Pending { next_retry, .. }) => {
                        let due = next_retry.map(|t| Instant::now() >= t).unwrap_or(true);
                        if due { Action::Create } else { Action::Nothing }
                    }
                }
            };

            match action {
                Action::Nothing => {}
                Action::MarkFailed(flow_id, reason) => {
                    warn!(route = %route.id, %reason, "route flow failed permanently; marking route Failed");
                    self.inner.hub.kill_flow(&flow_id);
                    self.inner
                        .runtime
                        .lock()
                        .unwrap()
                        .insert(route.id.clone(), RouteRuntime::Failed { reason });
                }
                Action::Create => {
                    let result = match route.kind {
                        FlowKind::Forward => {
                            let remote = route.remote.clone().unwrap_or_default();
                            self.inner
                                .hub
                                .create_forward(
                                    &route.node,
                                    route.local,
                                    &remote,
                                    &route.transport,
                                    "",
                                )
                                .await
                        }
                        FlowKind::Socks5 => {
                            self.inner
                                .hub
                                .create_socks5(&route.node, route.local, &route.transport)
                                .await
                        }
                    };
                    let mut runtime = self.inner.runtime.lock().unwrap();
                    match result {
                        Ok(flow_id) => {
                            info!(route = %route.id, flow = %flow_id, "route reconciled into a live flow");
                            super::port_holder::note_ok(&route.id);
                            runtime.insert(route.id.clone(), RouteRuntime::Live { flow_id });
                        }
                        Err(message) => {
                            // FR-84 D6 / #1035 — refused its port for two
                            // minutes: say WHO holds it (off the reconcile
                            // pass; the lookup reads tables and /proc).
                            if super::port_holder::note_failure(&route.id, &message) {
                                let (route_id, port) = (route.id.clone(), route.local);
                                tokio::spawn(async move {
                                    if let Ok(holder) = tokio::task::spawn_blocking(move || {
                                        super::port_holder::lookup(port)
                                    })
                                    .await
                                    {
                                        warn!(
                                            route = %route_id,
                                            port,
                                            holder = %super::port_holder::describe(&holder),
                                            "route still cannot bind its local port"
                                        );
                                    }
                                });
                            }
                            let failures = match runtime.get(&route.id) {
                                Some(RouteRuntime::Pending {
                                    consecutive_failures,
                                    ..
                                }) => consecutive_failures + 1,
                                _ => 1,
                            };
                            let backoff = create_backoff(failures);
                            warn!(
                                route = %route.id, %message, failures,
                                backoff_s = backoff.as_secs(),
                                "route flow creation failed; retrying"
                            );
                            runtime.insert(
                                route.id.clone(),
                                RouteRuntime::Pending {
                                    consecutive_failures: failures,
                                    next_retry: Some(Instant::now() + backoff),
                                    last_error: Some(message),
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    // ---- LocalAPI verb backs ---------------------------------------------

    /// The `RouteList` rows: declared descriptors joined with runtime state.
    ///
    /// #1685 — a `Live` runtime entry means the hub HAS a flow for the route,
    /// not that the route serves; the state a reader gets comes from the
    /// flow's own report ([`route_state_for_flow`]). Before this, `Live` was
    /// mapped straight to `Active`, and a route to an offline node read
    /// `active` with nothing listening on its port.
    pub fn list(&self) -> Vec<RouteInfo> {
        let routes = self.inner.routes.lock().unwrap().clone();
        let runtime = self.inner.runtime.lock().unwrap();
        let mut out: Vec<RouteInfo> = routes
            .into_iter()
            .map(|route| {
                let state = if !route.enabled {
                    RouteState::Disabled
                } else {
                    match runtime.get(&route.id) {
                        Some(RouteRuntime::Live { flow_id }) => {
                            match self.inner.hub.flow_report(flow_id) {
                                Some(report) => route_state_for_flow(flow_id, &report),
                                // Killed by hand; the next pass recreates it.
                                None => RouteState::Pending { flow_id: None },
                            }
                        }
                        Some(RouteRuntime::Failed { reason }) => RouteState::Failed {
                            reason: reason.clone(),
                        },
                        Some(RouteRuntime::Pending {
                            consecutive_failures,
                            next_retry: Some(t),
                            last_error: Some(e),
                        }) if *t > Instant::now() => RouteState::Backoff {
                            next_retry_secs: t.saturating_duration_since(Instant::now()).as_secs(),
                            last_error: e.clone(),
                            // No flow: creating one is what keeps failing.
                            flow_id: None,
                            attempts: *consecutive_failures,
                        },
                        _ => RouteState::Pending { flow_id: None },
                    }
                };
                RouteInfo { route, state }
            })
            .collect();
        out.sort_by(|a, b| a.route.id.cmp(&b.route.id));
        out
    }

    /// Validate + persist + reconcile a new route. Returns the effective
    /// descriptor (id generated when empty). `Err` is a user-facing
    /// message for the LocalAPI.
    pub async fn add(&self, mut route: RouteDescriptor) -> Result<RouteDescriptor, String> {
        validate_shape(&route)?;

        let effective = {
            let mut routes = self.inner.routes.lock().unwrap();
            if route.id.is_empty() {
                route.id = loop {
                    let candidate = format!(
                        "route-{}",
                        self.inner
                            .seq
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    );
                    if !routes.iter().any(|r| r.id == candidate) {
                        break candidate;
                    }
                };
            } else if routes.iter().any(|r| r.id == route.id) {
                return Err(format!("a route with id '{}' already exists", route.id));
            }
            if route.enabled && routes.iter().any(|r| r.enabled && r.local == route.local) {
                return Err(format!(
                    "local port {} is already used by another enabled route",
                    route.local
                ));
            }
            routes.push(route.clone());
            routes.clone()
        };

        if let Err(e) = self.persist(&effective).await {
            // Roll the in-memory add back so memory matches disk.
            self.inner
                .routes
                .lock()
                .unwrap()
                .retain(|r| r.id != route.id);
            return Err(e);
        }
        self.inner.kick.notify_one();
        Ok(route)
    }

    /// FR-84 D1 — replace a declared route IN ONE STEP, keyed by `route.id`
    /// (the `RouteUpdate` verb).
    ///
    /// Validated exactly like [`Self::add`], with the route being replaced
    /// excepted from the local-port clash check. An invalid descriptor is
    /// refused before anything changes, so the OLD route keeps running and
    /// stays persisted. A valid one is written to config in ONE save, then
    /// its old flow is stopped and the new descriptor is reconciled. The
    /// obvious alternative — `remove` then `add` — loses the route entirely
    /// when the add fails: the removal is already on disk by then.
    ///
    /// `Ok` carries the effective descriptor. A replacement identical to what
    /// is declared is a no-op (nothing is restarted).
    pub async fn replace(&self, route: RouteDescriptor) -> Result<RouteDescriptor, String> {
        if route.id.trim().is_empty() {
            return Err("a route update needs the id of the route to replace".to_string());
        }
        validate_shape(&route)?;

        // Swap the descriptor in memory (remembering the old one), then
        // persist; on a failed save put the old one back so memory matches
        // disk — the same rollback discipline as `add`.
        let (previous, snapshot) = {
            let mut routes = self.inner.routes.lock().unwrap();
            let Some(idx) = routes.iter().position(|r| r.id == route.id) else {
                return Err(format!("no declared route with id '{}'", route.id));
            };
            if routes[idx] == route {
                return Ok(route);
            }
            if route.enabled
                && routes
                    .iter()
                    .enumerate()
                    .any(|(i, r)| i != idx && r.enabled && r.local == route.local)
            {
                return Err(format!(
                    "local port {} is already used by another enabled route",
                    route.local
                ));
            }
            let previous = std::mem::replace(&mut routes[idx], route.clone());
            (previous, routes.clone())
        };
        if let Err(e) = self.persist(&snapshot).await {
            let mut routes = self.inner.routes.lock().unwrap();
            if let Some(slot) = routes.iter_mut().find(|r| r.id == route.id) {
                *slot = previous;
            }
            return Err(e);
        }

        // Persisted. Retire the old flow and let the next pass build the new
        // one — both under the runtime lock, so a concurrent pass cannot
        // create the replacement while the old listener still holds the
        // port. A disabled replacement simply has no runtime.
        {
            let mut runtime = self.inner.runtime.lock().unwrap();
            if let Some(RouteRuntime::Live { flow_id }) = runtime.remove(&route.id) {
                self.inner.hub.kill_flow(&flow_id);
            }
            if route.enabled {
                runtime.insert(route.id.clone(), RouteRuntime::fresh());
            }
        }
        self.inner.kick.notify_one();
        info!(route = %route.id, local = route.local, enabled = route.enabled, "route replaced");
        Ok(route)
    }

    /// Remove a declared route: kill its live flow, persist the removal.
    /// `Ok(false)` when the id was unknown.
    pub async fn remove(&self, id: &str) -> Result<bool, String> {
        let (found, snapshot) = {
            let mut routes = self.inner.routes.lock().unwrap();
            let before = routes.len();
            routes.retain(|r| r.id != id);
            (routes.len() != before, routes.clone())
        };
        if !found {
            return Ok(false);
        }
        self.persist(&snapshot).await?;
        // Tear down runtime + flow now (the next pass would too, but the
        // response should reflect the world).
        let live_flow = {
            let mut runtime = self.inner.runtime.lock().unwrap();
            match runtime.remove(id) {
                Some(RouteRuntime::Live { flow_id }) => Some(flow_id),
                _ => None,
            }
        };
        if let Some(flow_id) = live_flow {
            self.inner.hub.kill_flow(&flow_id);
        }
        info!(route = %id, "route removed");
        Ok(true)
    }

    /// Enable/disable a declared route. Enabling clears a terminal
    /// `Failed`. `Ok(false)` when the id was unknown.
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<bool, String> {
        let snapshot = {
            let mut routes = self.inner.routes.lock().unwrap();
            let Some(r) = routes.iter_mut().find(|r| r.id == id) else {
                return Ok(false);
            };
            r.enabled = enabled;
            routes.clone()
            // NB a re-enable that now clashes on `local` with another
            // enabled route isn't rejected here — the reconcile pass
            // surfaces it as Backoff{"port … in use"} against whichever
            // route loses the bind, which is honest about the runtime
            // reality (the add-time check prevents the common case).
        };
        self.persist(&snapshot).await?;
        {
            let mut runtime = self.inner.runtime.lock().unwrap();
            if enabled {
                // A re-enable resets Failed/backoff to a fresh Pending.
                runtime.insert(id.to_string(), RouteRuntime::fresh());
            } else if let Some(RouteRuntime::Live { flow_id }) = runtime.remove(id) {
                self.inner.hub.kill_flow(&flow_id);
            }
        }
        self.inner.kick.notify_one();
        info!(route = %id, enabled, "route enabled-state changed");
        Ok(true)
    }

    /// Persist `routes` as the config's `tunnel_routes` under the
    /// daemon-wide write lock (reload-modify-save so concurrent writers'
    /// OTHER fields are preserved).
    async fn persist(&self, routes: &[RouteDescriptor]) -> Result<(), String> {
        let _guard = self.inner.cfg_lock.lock().await;
        let mut cfg = crate::config::load(&self.inner.config_path)
            .map_err(|e| format!("could not reload config to persist routes: {e:#}"))?;
        cfg.tunnel_routes = routes.to_vec();
        crate::config::save(&self.inner.config_path, &cfg)
            .map_err(|e| format!("could not persist routes: {e:#}"))?;
        Ok(())
    }
}

/// #1685 — the state a declared route reports for the flow the hub holds for
/// it. `active` is the bound listener and nothing less. A flow whose session
/// failed reads `backoff` WITH its flow id (the tunnel session, not flow
/// creation, is what is being retried), carrying the last error, the
/// consecutive failures and the countdown to the next attempt; a flow still
/// on its first attempt — or between a healthy session's end and its
/// re-open — reads `pending` with its flow id ("connecting").
fn route_state_for_flow(flow_id: &str, report: &FlowReport) -> RouteState {
    if let Some(reason) = &report.fatal {
        return RouteState::Failed {
            reason: reason.clone(),
        };
    }
    if report.listening {
        return RouteState::Active {
            flow_id: flow_id.to_string(),
        };
    }
    if report.failures > 0 || report.last_error.is_some() {
        return RouteState::Backoff {
            next_retry_secs: report.next_retry_in.map(|d| d.as_secs()).unwrap_or(0),
            last_error: report.last_error.clone().unwrap_or_default(),
            flow_id: Some(flow_id.to_string()),
            attempts: report.failures,
        };
    }
    RouteState::Pending {
        flow_id: Some(flow_id.to_string()),
    }
}

/// The shape checks shared by `add` and `replace`. They mirror what the hub
/// enforces at create time, so a bad route fails HERE (once, with a clear
/// message) instead of silently backing off forever.
fn validate_shape(route: &RouteDescriptor) -> Result<(), String> {
    super::client_mgr::parse_node(&route.node)?;
    match route.kind {
        FlowKind::Forward => {
            let remote = route
                .remote
                .as_deref()
                .ok_or_else(|| "a forward route requires `remote` (host:port)".to_string())?;
            super::client_mgr::parse_host_port(remote).map_err(|e| e.to_string())?;
        }
        FlowKind::Socks5 => {
            if route.remote.is_some() {
                return Err("a socks5 route must not set `remote`".to_string());
            }
        }
    }
    if route.local == 0 {
        return Err("`local` must be a non-zero port".to_string());
    }
    Ok(())
}

/// Exponential create-retry backoff: 1 s, 2 s, 4 s, … capped at 30 s.
fn create_backoff(consecutive_failures: u32) -> Duration {
    let exp = consecutive_failures.saturating_sub(1).min(5);
    (CREATE_BACKOFF_MIN * 2u32.pow(exp)).min(CREATE_BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(id: &str, local: u16, enabled: bool) -> RouteDescriptor {
        RouteDescriptor {
            id: id.into(),
            kind: FlowKind::Forward,
            node: "aabbccddeeff001122334455".into(),
            local,
            remote: Some("db:5432".into()),
            transport: String::new(),
            enabled,
            org: None,
        }
    }

    fn reconciler(declared: Vec<RouteDescriptor>) -> (RouteReconciler, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Persist targets need a loadable config on disk.
        let mut cfg = crate::config::test_fixture();
        cfg.tunnel_routes = declared.clone();
        crate::config::save(&path, &cfg).unwrap();
        let r = RouteReconciler::new(
            TunnelClientHub::new("test".into()),
            path,
            Arc::new(tokio::sync::Mutex::new(())),
            declared,
        );
        (r, dir)
    }

    #[test]
    fn create_backoff_grows_and_caps() {
        assert_eq!(create_backoff(1), Duration::from_secs(1));
        assert_eq!(create_backoff(2), Duration::from_secs(2));
        assert_eq!(create_backoff(3), Duration::from_secs(4));
        assert_eq!(create_backoff(6), Duration::from_secs(30)); // 2^5=32 → cap
        assert_eq!(create_backoff(60), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn secondary_org_route_parks_as_failed() {
        let mut acme = desc("acme-pg", 41051, true);
        acme.org = Some("acme".into());
        let mut prim = desc("prim", 41052, true);
        prim.org = Some("primary".into()); // explicit primary is supervised normally
        let (r, _dir) = reconciler(vec![acme, prim]);
        r.reconcile_pass().await;
        let rows = r.list();
        let acme_row = rows.iter().find(|i| i.route.id == "acme-pg").unwrap();
        assert!(
            matches!(&acme_row.state, RouteState::Failed { reason }
                if reason.contains("acme") && reason.contains("primary only")),
            "got {:?}",
            acme_row.state
        );
        let prim_row = rows.iter().find(|i| i.route.id == "prim").unwrap();
        assert!(
            !matches!(&prim_row.state, RouteState::Failed { .. }),
            "explicit-primary route must not park: {:?}",
            prim_row.state
        );
    }

    #[tokio::test]
    async fn list_maps_disabled_and_pending() {
        let (r, _dir) = reconciler(vec![desc("a", 1001, true), desc("b", 1002, false)]);
        let rows = r.list();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].route.id, "a");
        assert_eq!(rows[0].state, RouteState::Pending { flow_id: None });
        assert_eq!(rows[1].state, RouteState::Disabled);
    }

    #[tokio::test]
    async fn add_validates_and_persists_and_generates_ids() {
        let (r, _dir) = reconciler(vec![]);

        // Bad node.
        let mut bad = desc("x", 1010, true);
        bad.node = "nope".into();
        assert!(r.add(bad).await.is_err());

        // Forward without remote.
        let mut bad = desc("x", 1010, true);
        bad.remote = None;
        assert!(r.add(bad).await.is_err());

        // Socks5 with a remote.
        let mut bad = desc("x", 1010, true);
        bad.kind = FlowKind::Socks5;
        assert!(r.add(bad).await.is_err());

        // Good — empty id gets generated; persisted to the config file.
        let mut ok = desc("", 1010, true);
        ok.id = String::new();
        let eff = r.add(ok).await.unwrap();
        assert!(eff.id.starts_with("route-"), "generated id, got {}", eff.id);
        let on_disk = crate::config::load(&r.inner.config_path).unwrap();
        assert_eq!(on_disk.tunnel_routes.len(), 1);
        assert_eq!(on_disk.tunnel_routes[0].id, eff.id);

        // Duplicate id rejected.
        let dup = desc(&eff.id, 1011, true);
        assert!(r.add(dup).await.is_err());

        // Duplicate enabled local port rejected.
        let clash = desc("other", 1010, true);
        let err = r.add(clash).await.unwrap_err();
        assert!(err.contains("already used"), "got {err}");
    }

    #[tokio::test]
    async fn remove_and_set_enabled_round_trip_config() {
        let (r, _dir) = reconciler(vec![desc("a", 1001, true)]);

        assert!(r.set_enabled("a", false).await.unwrap());
        assert!(
            !crate::config::load(&r.inner.config_path)
                .unwrap()
                .tunnel_routes[0]
                .enabled
        );
        assert_eq!(r.list()[0].state, RouteState::Disabled);

        assert!(r.set_enabled("a", true).await.unwrap());
        assert_eq!(r.list()[0].state, RouteState::Pending { flow_id: None });

        assert!(!r.set_enabled("ghost", true).await.unwrap());

        assert!(r.remove("a").await.unwrap());
        assert!(
            crate::config::load(&r.inner.config_path)
                .unwrap()
                .tunnel_routes
                .is_empty()
        );
        assert!(!r.remove("a").await.unwrap());
    }

    /// `N` distinct free loopback ports, for routes that must really bind.
    /// The listeners are held together and dropped together, so no two
    /// answers can be the same port.
    fn free_ports<const N: usize>() -> [u16; N] {
        let held: Vec<std::net::TcpListener> = (0..N)
            .map(|_| std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap())
            .collect();
        let ports: Vec<u16> = held
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();
        ports.try_into().unwrap()
    }

    /// The flow id behind a route that HAS one, or a panic naming its state.
    /// These tests run without an agent WS, so a route's flow never comes
    /// up: it reads `pending` WITH its flow id ("connecting", #1685), never
    /// `active` — that word is reserved for a bound listener.
    fn route_flow(r: &RouteReconciler, id: &str) -> String {
        let rows = r.list();
        let row = rows.iter().find(|i| i.route.id == id).unwrap();
        assert!(
            !matches!(row.state, RouteState::Active { .. }),
            "no listener can be bound without a WS: {:?}",
            row.state
        );
        match row.state.flow_id() {
            Some(flow_id) => flow_id.to_string(),
            None => panic!("route {id} has no flow: {:?}", row.state),
        }
    }

    /// FR-84 D1 — editing a live route's port: the old flow is gone the
    /// moment the replacement is persisted, the replacement is ONE config
    /// write, and the next pass brings the route back on a flow toward the
    /// new port with exactly one flow in the hub.
    #[tokio::test]
    async fn replace_while_live_moves_the_flow_to_the_new_port() {
        let [p1, p2] = free_ports();
        let (r, _dir) = reconciler(vec![desc("a", p1, true)]);
        r.reconcile_pass().await;
        let f1 = route_flow(&r, "a");
        assert!(r.inner.hub.has_flow(&f1));
        assert_eq!(
            r.inner.hub.flows_snapshot()[0].local_addr,
            format!("127.0.0.1:{p1}")
        );

        let eff = r.replace(desc("a", p2, true)).await.unwrap();
        assert_eq!(eff.local, p2);
        assert!(
            !r.inner.hub.has_flow(&f1),
            "the old flow is retired the moment the replacement is persisted"
        );
        let on_disk = crate::config::load(&r.inner.config_path)
            .unwrap()
            .tunnel_routes;
        assert_eq!(
            on_disk.len(),
            1,
            "a replace is not a remove+add: {on_disk:?}"
        );
        assert_eq!(
            on_disk[0].local, p2,
            "the replacement is what got persisted"
        );
        assert_eq!(r.list()[0].state, RouteState::Pending { flow_id: None });

        r.reconcile_pass().await;
        let f2 = route_flow(&r, "a");
        assert_ne!(f1, f2, "a new flow, not the old one revived");
        let flows = r.inner.hub.flows_snapshot();
        assert_eq!(
            flows.len(),
            1,
            "exactly one flow — the old listener did not survive: {flows:?}"
        );
        assert_eq!(flows[0].local_addr, format!("127.0.0.1:{p2}"));
    }

    /// FR-84 D1 — every way a replacement can be invalid leaves the OLD
    /// route running on its old flow and persisted on its old port. This is
    /// the property that rules out implementing the edit as remove+add.
    #[tokio::test]
    async fn replace_with_invalid_keeps_the_old_route_running_and_persisted() {
        let [p1, p2, p3] = free_ports();
        let (r, _dir) = reconciler(vec![desc("a", p1, true), desc("b", p2, true)]);
        r.reconcile_pass().await;
        let f1 = route_flow(&r, "a");

        let mut bad_node = desc("a", p3, true);
        bad_node.node = "nope".into();
        let mut no_remote = desc("a", p3, true);
        no_remote.remote = None;
        let mut socks_with_remote = desc("a", p3, true);
        socks_with_remote.kind = FlowKind::Socks5;
        let clash = desc("a", p2, true); // b's port
        let zero = desc("a", 0, true);
        let cases = [
            ("bad node", bad_node),
            ("forward without remote", no_remote),
            ("socks5 with remote", socks_with_remote),
            ("port clash with another enabled route", clash),
            ("port 0", zero),
        ];
        for (what, bad) in cases {
            let err = r.replace(bad).await.expect_err(what);
            assert!(!err.is_empty(), "{what}: the refusal names a reason");
            assert_eq!(
                route_flow(&r, "a"),
                f1,
                "{what}: the old flow must keep running"
            );
            assert!(
                r.inner.hub.has_flow(&f1),
                "{what}: old flow still in the hub"
            );
            let on_disk = crate::config::load(&r.inner.config_path)
                .unwrap()
                .tunnel_routes;
            assert_eq!(on_disk.len(), 2, "{what}: nothing removed from disk");
            assert_eq!(
                on_disk.iter().find(|x| x.id == "a").unwrap().local,
                p1,
                "{what}: still persisted on the old port"
            );
        }

        // A route's OWN port is not a clash with itself: changing only the
        // remote is a valid edit.
        let mut same_port = desc("a", p1, true);
        same_port.remote = Some("db:6543".into());
        let eff = r.replace(same_port).await.unwrap();
        assert_eq!(eff.remote.as_deref(), Some("db:6543"));
        assert_eq!(
            crate::config::load(&r.inner.config_path)
                .unwrap()
                .tunnel_routes
                .iter()
                .find(|x| x.id == "a")
                .unwrap()
                .remote
                .as_deref(),
            Some("db:6543")
        );
    }

    /// FR-84 D1 — an unknown (or empty) id is an error, and the declared set
    /// is untouched on disk and in memory.
    #[tokio::test]
    async fn replace_unknown_id_errors_and_changes_nothing() {
        let (r, _dir) = reconciler(vec![desc("a", 1001, true)]);
        let err = r.replace(desc("ghost", 1002, true)).await.unwrap_err();
        assert!(err.contains("ghost"), "the refusal names the id: {err}");
        let err = r.replace(desc("", 1002, true)).await.unwrap_err();
        assert!(
            err.contains("id"),
            "an empty id cannot address a route: {err}"
        );
        let on_disk = crate::config::load(&r.inner.config_path)
            .unwrap()
            .tunnel_routes;
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].id, "a");
        assert_eq!(on_disk[0].local, 1001);
        let rows = r.list();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].route.local, 1001);
    }

    /// #1685 — a route whose flow is REGISTERED but whose tunnel session is
    /// not up must not read `active`: nothing listens on its port. In this
    /// test there is no agent WS, so the flow's supervisor parks waiting for
    /// one — the same "flow exists, no listener" shape as a route to an
    /// offline node whose session keeps failing. Before the fix `Live` was
    /// mapped straight to `Active` and the port refused every connection.
    #[tokio::test]
    async fn a_route_whose_session_is_not_up_does_not_read_active() {
        let [p] = free_ports();
        let (r, _dir) = reconciler(vec![desc("a", p, true)]);
        r.reconcile_pass().await;
        let flow_id = {
            let flows = r.inner.hub.flows_snapshot();
            assert_eq!(flows.len(), 1, "the flow was created: {flows:?}");
            flows[0].id.clone()
        };
        assert!(
            std::net::TcpStream::connect(("127.0.0.1", p)).is_err(),
            "nothing listens on the route's port in this test"
        );
        let state = r.list()[0].state.clone();
        assert!(
            !matches!(state, RouteState::Active { .. }),
            "a route with no listener must not read active (flow {flow_id}): {state:?}"
        );
        // The reader still sees WHICH flow is dialing: "connecting (fl-N)".
        assert_eq!(
            state,
            RouteState::Pending {
                flow_id: Some(flow_id)
            }
        );
    }

    /// #1685 — the field shape: a route to an OFFLINE node. Its flow exists,
    /// every session attempt fails (`agent_unavailable`) and the supervisor
    /// backs off; the route reads `backoff` WITH the flow, the attempt count
    /// and the last error — never `active`. When the node comes back the
    /// driver binds the listener, and only then does the route read `active`.
    #[tokio::test]
    async fn a_retrying_session_reads_backoff_with_its_error_then_active_once_bound() {
        let [p] = free_ports();
        let mut route = desc("corp-socks", p, true);
        route.kind = FlowKind::Socks5;
        route.remote = None;
        let (r, _dir) = reconciler(vec![route]);
        r.reconcile_pass().await;
        let flow_id = route_flow(&r, "corp-socks");
        let live = r.inner.hub.flow_live_for_test(&flow_id).unwrap();

        // Two doomed cycles; the supervisor is now sleeping 8 s.
        let offline = "server error during tunnel.open: agent_unavailable: agent is offline";
        live.note_failure("waiting for DC pool to open: deadline has elapsed".into());
        live.note_failure(offline.into());
        live.note_backoff(Duration::from_secs(8));
        let state = r.list()[0].state.clone();
        match &state {
            RouteState::Backoff {
                next_retry_secs,
                last_error,
                flow_id: Some(f),
                attempts,
            } => {
                assert_eq!(f, &flow_id, "the reader can join the Flows table");
                assert_eq!(*attempts, 2);
                assert_eq!(last_error, offline, "the LAST error, not the first");
                assert!(
                    (6..=8).contains(next_retry_secs),
                    "countdown: {next_retry_secs}"
                );
            }
            other => panic!("expected backoff with the flow: {other:?}"),
        }
        // A pre-#1685 reader sees `backoff` too — a true statement — because
        // the tag set did not change; only fields were added.
        let wire = serde_json::to_value(&state).unwrap();
        assert_eq!(wire["state"], "backoff");
        assert_eq!(wire["flow_id"], flow_id);
        assert_eq!(wire["attempts"], 2);

        // The node came online: the driver bound the listener.
        live.mark_listening();
        assert_eq!(r.list()[0].state, RouteState::Active { flow_id });
    }

    /// #1685 — the pure mapping, every branch: fatal wins, then listening,
    /// then a recorded failure, else connecting.
    #[test]
    fn route_state_for_flow_orders_fatal_listening_failure_connecting() {
        let base = FlowReport {
            listening: false,
            fatal: None,
            failures: 0,
            last_error: None,
            next_retry_in: None,
        };
        assert_eq!(
            route_state_for_flow("fl-1", &base),
            RouteState::Pending {
                flow_id: Some("fl-1".into())
            }
        );
        assert_eq!(
            route_state_for_flow(
                "fl-1",
                &FlowReport {
                    listening: true,
                    ..base.clone()
                }
            ),
            RouteState::Active {
                flow_id: "fl-1".into()
            }
        );
        // In flight after a failure: no countdown ⇒ 0, still not active.
        assert_eq!(
            route_state_for_flow(
                "fl-1",
                &FlowReport {
                    failures: 3,
                    last_error: Some("x".into()),
                    ..base.clone()
                }
            ),
            RouteState::Backoff {
                next_retry_secs: 0,
                last_error: "x".into(),
                flow_id: Some("fl-1".into()),
                attempts: 3,
            }
        );
        // Terminal beats everything, even a stale `listening`.
        assert_eq!(
            route_state_for_flow(
                "fl-1",
                &FlowReport {
                    listening: true,
                    fatal: Some("revoked".into()),
                    ..base
                }
            ),
            RouteState::Failed {
                reason: "revoked".into()
            }
        );
    }

    #[tokio::test]
    async fn reenable_clears_terminal_failed() {
        let (r, _dir) = reconciler(vec![desc("a", 1001, true)]);
        r.inner.runtime.lock().unwrap().insert(
            "a".into(),
            RouteRuntime::Failed {
                reason: "revoked".into(),
            },
        );
        assert!(matches!(r.list()[0].state, RouteState::Failed { .. }));
        // Disable → Disabled wins over Failed…
        assert!(r.set_enabled("a", false).await.unwrap());
        assert_eq!(r.list()[0].state, RouteState::Disabled);
        // …re-enable → fresh Pending (Failed cleared).
        assert!(r.set_enabled("a", true).await.unwrap());
        assert_eq!(r.list()[0].state, RouteState::Pending { flow_id: None });
    }
}
