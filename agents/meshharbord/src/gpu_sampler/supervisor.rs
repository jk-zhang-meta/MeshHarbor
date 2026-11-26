// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Host-wide `gpu-sampler` child supervisor and multi-org fan-out (FR-139 §5.2).
//!
//! Design invariants:
//! - **ONE** `gpu-sampler` child process per host, shared across all org
//!   connections (primary + secondary + invited orgs). The child runs at the
//!   minimum active lease interval across all connected orgs, and fans out
//!   `rc:agent.gpu_inventory` and `rc:agent.gpu_report` per org at each org's
//!   own leased cadence.
//! - **Local kill switch (`gpu_telemetry = false`)**: never spawns a child;
//!   tears down any running child via the async reaper and answers active
//!   leases with `GpuHostStatus::OffLocal`.
//! - **Hung-driver safety**: enforces a per-frame deadline of
//!   `max(3 * interval, min_deadline)` (10 s in production). On deadline miss,
//!   calls `start_kill()` and hands the child handle to a detached background
//!   reaper task — **NEVER** awaits `child.wait()` inline on the supervisor
//!   task! While an earlier child remains unreaped (e.g. stuck in kernel D
//!   state), refuses to spawn a second child and emits `GpuHostStatus::DriverHung`.
//! - **Bounded backoff**: `30 s -> 60 s -> 120 s -> 240 s -> 300 s`, emitting
//!   `GpuHostStatus::SamplerStalled` while backing off and
//!   `GpuHostStatus::Unavailable` after 5 consecutive failures.
//! - **Parent `HostLoad`**: merges CPU / load / RAM / swap / root disk / net
//!   via `sysinfo` in the parent (no driver calls in parent).
//! - **Alert ring**: retains the last 50 `rc:gpu.alert` frames so the desktop
//!   companion can poll LocalAPI `GpuAlerts` and display OS notifications.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use meshharbor_remote_control::gpu::{
    GpuAlertWire, GpuHostStatus, GpuInventory, GpuReport, HostLoad,
};
use meshharbor_remote_control::signaling::ClientMsg;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Notify, mpsc, watch};

use super::{CHILD_ENV, ChildFrame, ControlLine, FAKE_ENV, FRAME_PREFIX};

const MAX_ALERT_RING: usize = 50;

/// Tunable supervisor timings (production defaults in `Default`, shortened in unit tests).
#[derive(Debug, Clone, Copy)]
pub struct SupervisorTimings {
    pub min_deadline: Duration,
    pub backoff_initial: Duration,
    pub backoff_cap: Duration,
    pub max_consecutive_failures: u32,
}

impl Default for SupervisorTimings {
    fn default() -> Self {
        Self {
            min_deadline: Duration::from_secs(10),
            backoff_initial: Duration::from_secs(30),
            backoff_cap: Duration::from_secs(300),
            max_consecutive_failures: 5,
        }
    }
}

#[derive(Debug, Clone)]
struct OrgLease {
    interval_ms: u32,
    expires_at: Option<Instant>,
    standing: bool,
}

impl OrgLease {
    fn effective_interval(&self, now: Instant) -> Option<u32> {
        let live_active = self.expires_at.is_some_and(|exp| exp > now);
        if live_active {
            Some(self.interval_ms.max(250))
        } else if self.standing {
            Some(30_000)
        } else {
            None
        }
    }
}

struct OrgEntry {
    tx: mpsc::Sender<ClientMsg>,
    lease: Option<OrgLease>,
    last_sent_report: Option<Instant>,
    inventory_sent: bool,
}

struct InnerState {
    orgs: HashMap<String, OrgEntry>,
}

/// Host-wide GPU telemetry supervisor handle, cheaply clonable into every org
/// signaling loop and into LocalAPI state.
#[derive(Clone)]
pub struct GpuSupervisor {
    inner: Arc<Mutex<InnerState>>,
    notify: Arc<Notify>,
    gpu_telemetry: Arc<AtomicBool>,
    gpu_processes: Arc<AtomicBool>,
    latest_inventory: Arc<RwLock<Option<GpuInventory>>>,
    latest_report: Arc<RwLock<Option<GpuReport>>>,
    alerts: Arc<Mutex<VecDeque<(u64, GpuAlertWire)>>>,
    local_alert_seq: Arc<AtomicU64>,
    unreaped_child: Arc<AtomicBool>,
    timings: SupervisorTimings,
    child_exe_override: Option<PathBuf>,
    extra_env: Vec<(String, String)>,
}

/// RAII guard returned by [`GpuSupervisor::register_org_guard`] that unregisters
/// an org WS automatically when the connection drops.
pub struct GpuOrgGuard {
    sup: GpuSupervisor,
    tenant_id: String,
}

impl Drop for GpuOrgGuard {
    fn drop(&mut self) {
        self.sup.unregister_org(&self.tenant_id);
    }
}

impl GpuSupervisor {
    pub fn from_flags(gpu_telemetry: Arc<AtomicBool>, gpu_processes: Arc<AtomicBool>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerState {
                orgs: HashMap::new(),
            })),
            notify: Arc::new(Notify::new()),
            gpu_telemetry,
            gpu_processes,
            latest_inventory: Arc::new(RwLock::new(None)),
            latest_report: Arc::new(RwLock::new(None)),
            alerts: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_ALERT_RING))),
            local_alert_seq: Arc::new(AtomicU64::new(0)),
            unreaped_child: Arc::new(AtomicBool::new(false)),
            timings: SupervisorTimings::default(),
            child_exe_override: None,
            extra_env: Vec::new(),
        }
    }

    /// Wake the supervisor after local config flags (`gpu_telemetry` /
    /// `gpu_processes`) change. Clears cached inventory/report immediately when
    /// local telemetry is disabled so no stale GPU/host metrics leak.
    pub fn notify_config_changed(&self) {
        if !self.gpu_telemetry.load(Ordering::Relaxed) {
            if let Ok(mut slot) = self.latest_inventory.write() {
                *slot = None;
            }
            if let Ok(mut slot) = self.latest_report.write() {
                *slot = None;
            }
        }
        self.notify.notify_one();
    }

    /// Register an org WS and return a drop guard that unregisters it on disconnect.
    pub fn register_org_guard(&self, tenant_id: &str, tx: mpsc::Sender<ClientMsg>) -> GpuOrgGuard {
        self.register_org(tenant_id, tx);
        GpuOrgGuard {
            sup: self.clone(),
            tenant_id: tenant_id.to_string(),
        }
    }

    /// Test helper: override timings, child executable path, and extra env vars.
    #[cfg(test)]
    pub fn with_test_overrides(
        mut self,
        timings: SupervisorTimings,
        child_exe: Option<PathBuf>,
        extra_env: Vec<(String, String)>,
    ) -> Self {
        self.timings = timings;
        self.child_exe_override = child_exe;
        self.extra_env = extra_env;
        self
    }

    /// Register an org's connected outbound WS sender so it receives initial
    /// `rc:agent.gpu_inventory` and leased `rc:agent.gpu_report` frames.
    pub fn register_org(&self, tenant_id: &str, tx: mpsc::Sender<ClientMsg>) {
        let cached_inv = self.latest_inventory.read().ok().and_then(|g| g.clone());
        let mut sent = false;
        if let Some(inv) = cached_inv {
            let _ = tx.try_send(ClientMsg::AgentGpuInventory {
                inventory: Box::new(inv),
            });
            sent = true;
        }
        if let Ok(mut g) = self.inner.lock() {
            g.orgs.insert(
                tenant_id.to_string(),
                OrgEntry {
                    tx,
                    lease: None,
                    last_sent_report: None,
                    inventory_sent: sent,
                },
            );
        }
        self.notify.notify_one();
    }

    /// Unregister an org's WS when its connection closes.
    pub fn unregister_org(&self, tenant_id: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.orgs.remove(tenant_id);
        }
        self.notify.notify_one();
    }

    /// Apply an inbound `ServerMsg::GpuLease` for `tenant_id`.
    pub fn apply_lease(&self, tenant_id: &str, interval_ms: u32, ttl_ms: u32, standing: bool) {
        let now = Instant::now();
        let expires_at = (ttl_ms > 0).then(|| now + Duration::from_millis(u64::from(ttl_ms)));
        if let Ok(mut g) = self.inner.lock()
            && let Some(entry) = g.orgs.get_mut(tenant_id)
        {
            if !standing && expires_at.is_none() {
                entry.lease = None;
            } else {
                entry.lease = Some(OrgLease {
                    interval_ms,
                    expires_at,
                    standing,
                });
            }
        }
        self.notify.notify_one();
    }

    /// Record an inbound `ServerMsg::GpuAlert` into the ring buffer for LocalAPI,
    /// assigning a daemon-local monotonic sequence cursor so server restarts,
    /// replica changes, or multi-org alert streams never stall or suppress tray
    /// notifications.
    pub fn record_alert(&self, mut alert: GpuAlertWire) {
        let remote_seq = alert.seq;
        if let Ok(mut ring) = self.alerts.lock() {
            // Avoid duplicates if delivered across multiple orgs or retries.
            if ring.iter().any(|(rseq, a)| {
                *rseq == remote_seq && a.at == alert.at && a.title == alert.title && a.body == alert.body
            }) {
                return;
            }
            let local_seq = self.local_alert_seq.fetch_add(1, Ordering::Relaxed) + 1;
            alert.seq = local_seq;
            if ring.len() >= MAX_ALERT_RING {
                ring.pop_front();
            }
            ring.push_back((remote_seq, alert));
        }
    }

    /// Read alerts strictly newer than `after_seq` for LocalAPI `GpuAlerts`.
    /// If the caller's cursor exceeds this daemon's current local counter (e.g.
    /// after a daemon restart), returns the full ring so clients self-recover.
    pub fn alerts_after(&self, after_seq: u64) -> Vec<GpuAlertWire> {
        let current = self.local_alert_seq.load(Ordering::Relaxed);
        let eff_after = if after_seq > current { 0 } else { after_seq };
        self.alerts
            .lock()
            .map(|ring| {
                ring.iter()
                    .filter(|(_, a)| a.seq > eff_after)
                    .map(|(_, a)| a.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Latest cached GPU inventory (if probed).
    pub fn latest_inventory(&self) -> Option<GpuInventory> {
        self.latest_inventory.read().ok().and_then(|g| g.clone())
    }

    /// Latest cached GPU report (if sampled).
    pub fn latest_report(&self) -> Option<GpuReport> {
        self.latest_report.read().ok().and_then(|g| g.clone())
    }

    /// Shared handle for the optional loopback Prometheus `/metrics` listener.
    pub fn report_slot(&self) -> Arc<RwLock<Option<GpuReport>>> {
        self.latest_report.clone()
    }

    /// Spawn the background supervisor loop and optional Prometheus listener.
    pub fn spawn(&self, metrics_listen: Option<&str>, shutdown_rx: watch::Receiver<bool>) {
        super::metrics::spawn_if_configured(
            metrics_listen,
            self.latest_report.clone(),
            shutdown_rx.clone(),
        );
        let sup = self.clone();
        tokio::spawn(async move {
            sup.run_loop(shutdown_rx).await;
        });
    }

    /// Compute `(need_inventory, min_active_interval_ms)` across all registered orgs.
    fn demand(&self, now: Instant) -> (bool, Option<u32>) {
        let Ok(g) = self.inner.lock() else {
            return (false, None);
        };
        let mut need_inv = false;
        let mut min_iv: Option<u32> = None;
        for entry in g.orgs.values() {
            if !entry.inventory_sent {
                need_inv = true;
            }
            if let Some(lease) = &entry.lease
                && let Some(iv) = lease.effective_interval(now)
            {
                min_iv = Some(min_iv.map_or(iv, |cur| cur.min(iv)));
            }
        }
        (need_inv, min_iv)
    }

    fn fanout_inventory(&self, inv: GpuInventory) {
        if let Ok(mut slot) = self.latest_inventory.write() {
            *slot = Some(inv.clone());
        }
        if let Ok(mut g) = self.inner.lock() {
            for entry in g.orgs.values_mut() {
                if entry
                    .tx
                    .try_send(ClientMsg::AgentGpuInventory {
                        inventory: Box::new(inv.clone()),
                    })
                    .is_ok()
                {
                    entry.inventory_sent = true;
                }
            }
        }
    }

    fn fanout_report(&self, report: GpuReport, force_all_leased: bool) {
        if let Ok(mut slot) = self.latest_report.write() {
            *slot = Some(report.clone());
        }
        let now = Instant::now();
        if let Ok(mut g) = self.inner.lock() {
            for entry in g.orgs.values_mut() {
                let Some(iv_ms) = entry.lease.as_ref().and_then(|l| l.effective_interval(now))
                else {
                    continue;
                };
                // Respect each org's own cadence (with a 15% jitter tolerance
                // so a 2 s child frame hits a 2 s org lease cleanly).
                let due = force_all_leased
                    || entry.last_sent_report.is_none_or(|last| {
                        now.duration_since(last).as_millis() + (u128::from(iv_ms) / 6)
                            >= u128::from(iv_ms)
                    });
                if due {
                    let mut org_rep = report.clone();
                    org_rep.interval_ms = iv_ms;
                    if entry
                        .tx
                        .try_send(ClientMsg::AgentGpuReport {
                            report: Box::new(org_rep),
                        })
                        .is_ok()
                    {
                        entry.last_sent_report = Some(now);
                    }
                }
            }
        }
    }

    async fn run_loop(&self, mut shutdown_rx: watch::Receiver<bool>) {
        let mut host_sampler: Option<Arc<Mutex<HostLoadSampler>>> = None;
        let mut consecutive_failures: u32 = 0;
        let mut backoff_until: Option<Instant> = None;
        let mut synthetic_seq: u64 = 0;
        let mut announced_hung = false;

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            let now = Instant::now();
            let (need_inv, active_iv) = self.demand(now);

            // Nothing connected that needs inventory or a lease -> sleep until notified.
            if !need_inv && active_iv.is_none() {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                continue;
            }

            // Local kill switch (`gpu_telemetry = false`): NEVER spawn a child
            // and NEVER sample or transmit host CPU/RAM/disk/net metrics.
            if !self.gpu_telemetry.load(Ordering::Relaxed) {
                let off_inv = GpuInventory {
                    backend: None,
                    driver_version: None,
                    gpus: Vec::new(),
                    status: GpuHostStatus::OffLocal,
                    status_detail: Some("GPU telemetry disabled locally on this host".into()),
                };
                let stale_inv = self
                    .latest_inventory
                    .read()
                    .ok()
                    .is_some_and(|g| g.as_ref().is_some_and(|i| i.status != GpuHostStatus::OffLocal));
                if need_inv || stale_inv {
                    self.fanout_inventory(off_inv);
                }
                if let Some(iv) = active_iv {
                    synthetic_seq += 1;
                    let rep = GpuReport {
                        seq: synthetic_seq,
                        interval_ms: iv,
                        status: GpuHostStatus::OffLocal,
                        status_detail: Some("GPU telemetry disabled locally on this host".into()),
                        backend: None,
                        driver_version: None,
                        host: HostLoad::default(),
                        gpus: Vec::new(),
                    };
                    self.fanout_report(rep, false);
                } else if let Ok(mut slot) = self.latest_report.write() {
                    *slot = None;
                }
                let sleep_for = Duration::from_millis(u64::from(active_iv.unwrap_or(5_000)));
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(sleep_for) => {}
                }
                continue;
            }

            // If an earlier hung child is still unreaped (e.g. stuck in kernel D
            // state), NEVER spawn a second child; report `DriverHung` instead.
            // Force immediate fanout ONLY on initial entry into DriverHung; subsequent
            // ticks respect each org's own lease cadence.
            if self.unreaped_child.load(Ordering::Acquire) {
                if let Some(iv) = active_iv {
                    synthetic_seq += 1;
                    let cached_inv = self.latest_inventory();
                    let rep = GpuReport {
                        seq: synthetic_seq,
                        interval_ms: iv,
                        status: GpuHostStatus::DriverHung,
                        status_detail: Some(
                            "GPU sampler child unreaped (driver call hung in kernel)".into(),
                        ),
                        backend: cached_inv.as_ref().and_then(|i| i.backend.clone()),
                        driver_version: cached_inv.as_ref().and_then(|i| i.driver_version.clone()),
                        host: sample_host_load_nonblocking(&mut host_sampler).await,
                        gpus: Vec::new(),
                    };
                    self.fanout_report(rep, !announced_hung);
                    announced_hung = true;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(u64::from(active_iv.unwrap_or(2_000)).min(2_000))) => {}
                }
                continue;
            }
            announced_hung = false;

            // Respect exponential backoff (capped at `backoff_cap` = 300 s); even
            // after `max_consecutive_failures` we keep reporting `Unavailable` and
            // periodically retry at `backoff_cap` so a recovered driver self-heals
            // without requiring a daemon restart.
            if let Some(until) = backoff_until
                && now < until
            {
                let status = if consecutive_failures >= self.timings.max_consecutive_failures {
                    GpuHostStatus::Unavailable
                } else {
                    GpuHostStatus::SamplerStalled
                };
                if let Some(iv) = active_iv {
                    synthetic_seq += 1;
                    let cached_inv = self.latest_inventory();
                    let rep = GpuReport {
                        seq: synthetic_seq,
                        interval_ms: iv,
                        status,
                        status_detail: Some(if status == GpuHostStatus::Unavailable {
                            "GPU sampler unavailable after repeated failures — retrying periodically"
                                .into()
                        } else {
                            "GPU sampler missed deadline or exited — backing off before retry"
                                .into()
                        }),
                        backend: cached_inv.as_ref().and_then(|i| i.backend.clone()),
                        driver_version: cached_inv.as_ref().and_then(|i| i.driver_version.clone()),
                        host: sample_host_load_nonblocking(&mut host_sampler).await,
                        gpus: Vec::new(),
                    };
                    self.fanout_report(rep, false);
                }
                let wait = (until - now).min(Duration::from_secs(2));
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(wait) => {}
                }
                continue;
            }

            // Spawn one `meshharbord gpu-sampler` child.
            let (outcome, saw_healthy_frame) = self
                .run_child_session(&mut host_sampler, &mut shutdown_rx, &mut synthetic_seq)
                .await;

            if saw_healthy_frame {
                consecutive_failures = 0;
            }

            match outcome {
                ChildOutcome::CleanIdle | ChildOutcome::Shutdown => {
                    consecutive_failures = 0;
                    backoff_until = None;
                }
                ChildOutcome::Hung => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let delay = compute_backoff(self.timings, consecutive_failures);
                    backoff_until = Some(Instant::now() + delay);
                    let status = if consecutive_failures >= self.timings.max_consecutive_failures {
                        GpuHostStatus::Unavailable
                    } else {
                        GpuHostStatus::SamplerStalled
                    };
                    synthetic_seq += 1;
                    let cached_inv = self.latest_inventory();
                    let rep = GpuReport {
                        seq: synthetic_seq,
                        interval_ms: active_iv.unwrap_or(30_000),
                        status,
                        status_detail: Some("GPU sampler exceeded frame deadline".into()),
                        backend: cached_inv.as_ref().and_then(|i| i.backend.clone()),
                        driver_version: cached_inv.as_ref().and_then(|i| i.driver_version.clone()),
                        host: sample_host_load_nonblocking(&mut host_sampler).await,
                        gpus: Vec::new(),
                    };
                    self.fanout_report(rep, true);
                }
                ChildOutcome::Failed => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let delay = compute_backoff(self.timings, consecutive_failures);
                    backoff_until = Some(Instant::now() + delay);
                    let status = if consecutive_failures >= self.timings.max_consecutive_failures {
                        GpuHostStatus::Unavailable
                    } else {
                        GpuHostStatus::SamplerStalled
                    };
                    let cached_inv = self.latest_inventory();
                    if need_inv {
                        let mut inv = cached_inv.clone().unwrap_or_default();
                        inv.status = status;
                        inv.status_detail =
                            Some("GPU sampler child exited unexpectedly".into());
                        self.fanout_inventory(inv);
                    }
                    synthetic_seq += 1;
                    let rep = GpuReport {
                        seq: synthetic_seq,
                        interval_ms: active_iv.unwrap_or(30_000),
                        status,
                        status_detail: Some("GPU sampler child exited unexpectedly".into()),
                        backend: cached_inv.as_ref().and_then(|i| i.backend.clone()),
                        driver_version: cached_inv.as_ref().and_then(|i| i.driver_version.clone()),
                        host: sample_host_load_nonblocking(&mut host_sampler).await,
                        gpus: Vec::new(),
                    };
                    self.fanout_report(rep, true);
                }
            }
        }
    }

    async fn run_child_session(
        &self,
        host_sampler: &mut Option<Arc<Mutex<HostLoadSampler>>>,
        shutdown_rx: &mut watch::Receiver<bool>,
        synthetic_seq: &mut u64,
    ) -> (ChildOutcome, bool) {
        let exe = match &self.child_exe_override {
            Some(p) => p.clone(),
            None => match own_executable() {
                Some(p) => p,
                None => {
                    tracing::warn!("gpu-sampler: cannot resolve current executable path");
                    return (ChildOutcome::Failed, false);
                }
            },
        };

        let mut cmd = Command::new(exe);
        cmd.arg("gpu-sampler")
            .env(CHILD_ENV, "1")
            .envs(tunnel_core::env::config_fallbacks_for_child())
            .envs(self.extra_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Ok(fake) = std::env::var(FAKE_ENV) {
            cmd.env(FAKE_ENV, fake);
        }
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(%e, "gpu-sampler: spawn failed");
                return (ChildOutcome::Failed, false);
            }
        };

        let Some(mut stdin) = child.stdin.take() else {
            reap_in_background(child, self.unreaped_child.clone(), true);
            return (ChildOutcome::Failed, false);
        };
        let Some(stdout) = child.stdout.take() else {
            reap_in_background(child, self.unreaped_child.clone(), true);
            return (ChildOutcome::Failed, false);
        };
        let mut lines = BufReader::new(stdout).lines();

        let mut last_ctrl: Option<(u32, bool)> = None;
        let mut last_frame_at = Instant::now();
        let mut saw_inventory = false;
        let mut saw_healthy_frame = false;

        loop {
            if *shutdown_rx.borrow() {
                let _ = write_control(&mut stdin, 0, false, true).await;
                reap_in_background(child, self.unreaped_child.clone(), false);
                return (ChildOutcome::Shutdown, saw_healthy_frame);
            }

            if !self.gpu_telemetry.load(Ordering::Relaxed) {
                let _ = write_control(&mut stdin, 0, false, true).await;
                reap_in_background(child, self.unreaped_child.clone(), false);
                return (ChildOutcome::CleanIdle, saw_healthy_frame);
            }

            let now = Instant::now();
            let (need_inv, active_iv) = self.demand(now);
            let include_procs = self.gpu_processes.load(Ordering::Relaxed);
            let desired_iv = active_iv.unwrap_or(0);

            // Push updated control line whenever interval or procs switch changed.
            if last_ctrl != Some((desired_iv, include_procs)) {
                if write_control(&mut stdin, desired_iv, include_procs, false)
                    .await
                    .is_err()
                {
                    reap_in_background(child, self.unreaped_child.clone(), true);
                    return (ChildOutcome::Failed, saw_healthy_frame);
                }
                last_ctrl = Some((desired_iv, include_procs));
                last_frame_at = Instant::now();
            }

            // If we already got inventory and nobody has an active lease, exit cleanly!
            if saw_inventory && !need_inv && desired_iv == 0 {
                let _ = write_control(&mut stdin, 0, include_procs, true).await;
                reap_in_background(child, self.unreaped_child.clone(), false);
                return (ChildOutcome::CleanIdle, saw_healthy_frame);
            }

            // Frame deadline: max(3 * interval, min_deadline), plus a generous
            // 30 s first-frame grace in production so large multi-card hosts
            // never get killed during initial probe.
            let mut deadline = Duration::from_millis(u64::from(desired_iv).saturating_mul(3))
                .max(self.timings.min_deadline);
            if !saw_inventory && self.timings.min_deadline >= Duration::from_secs(5) {
                deadline = deadline.max(Duration::from_secs(30));
            }
            let remaining = deadline.saturating_sub(last_frame_at.elapsed());
            let wake_in = remaining.min(Duration::from_millis(50));

            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        let _ = write_control(&mut stdin, 0, false, true).await;
                        reap_in_background(child, self.unreaped_child.clone(), false);
                        return (ChildOutcome::Shutdown, saw_healthy_frame);
                    }
                }
                _ = self.notify.notified() => {
                    // Re-evaluate lease demand / telemetry switch on next loop turn.
                }
                _ = tokio::time::sleep(wake_in) => {
                    if last_frame_at.elapsed() >= deadline {
                        tracing::warn!(
                            deadline_ms = deadline.as_millis() as u64,
                            "gpu-sampler: frame deadline exceeded — killing child without blocking wait"
                        );
                        reap_in_background(child, self.unreaped_child.clone(), true);
                        return (ChildOutcome::Hung, saw_healthy_frame);
                    }
                }
                line_res = lines.next_line() => {
                    match line_res {
                        Ok(Some(line)) => {
                            let Some(json) = line.strip_prefix(FRAME_PREFIX) else {
                                continue;
                            };
                            match serde_json::from_str::<ChildFrame>(json) {
                                Ok(ChildFrame::Inventory { inventory }) => {
                                    saw_inventory = true;
                                    last_frame_at = Instant::now();
                                    self.fanout_inventory(inventory);
                                }
                                Ok(ChildFrame::Report { mut report }) => {
                                    last_frame_at = Instant::now();
                                    if matches!(
                                        report.status,
                                        GpuHostStatus::Ok
                                            | GpuHostStatus::Limited
                                            | GpuHostStatus::NoGpu
                                            | GpuHostStatus::DriverMissing
                                    ) {
                                        saw_healthy_frame = true;
                                    }
                                    *synthetic_seq = (*synthetic_seq).max(report.seq);
                                    report.host = sample_host_load_nonblocking(host_sampler).await;
                                    self.fanout_report(report, false);
                                }
                                Err(e) => {
                                    tracing::debug!(%e, "gpu-sampler: ignoring malformed frame");
                                }
                            }
                        }
                        Ok(None) | Err(_) => {
                            // Child stdout closed (crashed or exited unexpectedly).
                            reap_in_background(child, self.unreaped_child.clone(), false);
                            return (ChildOutcome::Failed, saw_healthy_frame);
                        }
                    }
                }
            }
        }
    }
}

enum ChildOutcome {
    CleanIdle,
    Shutdown,
    Hung,
    Failed,
}

async fn write_control(
    stdin: &mut tokio::process::ChildStdin,
    interval_ms: u32,
    include_procs: bool,
    stop: bool,
) -> std::io::Result<()> {
    let line = serde_json::to_string(&ControlLine {
        interval_ms,
        include_procs,
        stop,
    })
    .map_err(std::io::Error::other)?;
    stdin.write_all(line.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await
}

/// Kill (if requested) and reap the child asynchronously on a detached task.
/// NEVER blocks the supervisor task even if the child is stuck in kernel D state!
fn reap_in_background(
    mut child: tokio::process::Child,
    unreaped: Arc<AtomicBool>,
    kill_immediately: bool,
) {
    unreaped.store(true, Ordering::Release);
    if kill_immediately {
        let _ = child.start_kill();
    }
    tokio::spawn(async move {
        if !kill_immediately {
            // Give a clean-stop child 1 s to exit before escalating to kill.
            if tokio::time::timeout(Duration::from_secs(1), child.wait())
                .await
                .is_ok()
            {
                unreaped.store(false, Ordering::Release);
                return;
            }
            let _ = child.start_kill();
        }
        let _ = child.wait().await;
        unreaped.store(false, Ordering::Release);
    });
}

fn compute_backoff(timings: SupervisorTimings, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(8);
    let mult = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
    timings
        .backoff_initial
        .saturating_mul(mult)
        .min(timings.backoff_cap)
}

/// This daemon's binary on disk. An in-place upgrade replaces the binary while
/// the daemon is running, causing Linux `/proc/self/exe` to report
/// `<path> (deleted)`; stripping that suffix resolves the newly installed file.
fn own_executable() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    if exe.is_file() {
        return Some(exe);
    }
    let s = exe.to_str()?;
    let installed = PathBuf::from(s.strip_suffix(" (deleted)")?);
    installed.is_file().then_some(installed)
}

/// Sample host CPU/RAM/root-disk/network load lazily on a blocking worker with
/// a bounded 2 s timeout so slow `/proc` or filesystem calls never block tokio
/// workers or daemon shutdown.
async fn sample_host_load_nonblocking(
    slot: &mut Option<Arc<Mutex<HostLoadSampler>>>,
) -> HostLoad {
    let sampler = slot
        .get_or_insert_with(|| Arc::new(Mutex::new(HostLoadSampler::new())))
        .clone();
    match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            let mut guard = sampler.lock().unwrap_or_else(|e| e.into_inner());
            guard.sample()
        }),
    )
    .await
    {
        Ok(Ok(load)) => load,
        _ => HostLoad::default(),
    }
}

/// Stat ONLY the root filesystem (`/` on Unix, `C:\` on Windows) instead of
/// enumerating all mounted filesystems via `sysinfo::Disks`, which would hang
/// on unresponsive NFS, Lustre, GPFS, or FUSE mounts.
fn sample_root_disk_gb() -> (Option<f32>, Option<f32>) {
    #[cfg(unix)]
    {
        // SAFETY: `statvfs` writes into a zero-initialized `libc::statvfs` for `"/"`.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c"/".as_ptr(), &mut st) };
        if rc == 0 {
            let frsize = if st.f_frsize > 0 {
                st.f_frsize as u64
            } else {
                st.f_bsize as u64
            };
            let total_bytes = (st.f_blocks as u64).saturating_mul(frsize);
            let avail_bytes = (st.f_bavail as u64).saturating_mul(frsize);
            if total_bytes > 0 {
                let total = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                let used =
                    total_bytes.saturating_sub(avail_bytes) as f64 / (1024.0 * 1024.0 * 1024.0);
                return (Some(used as f32), Some(total as f32));
            }
        }
        (None, None)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let root_w: Vec<u16> = "C:\\\0".encode_utf16().collect();
        let mut free_avail: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;
        // SAFETY: valid NUL-terminated UTF-16 path and writable u64 pointers.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                root_w.as_ptr(),
                &mut free_avail,
                &mut total_bytes,
                &mut total_free,
            )
        };
        if ok != 0 && total_bytes > 0 {
            let total = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let used = total_bytes.saturating_sub(free_avail) as f64 / (1024.0 * 1024.0 * 1024.0);
            return (Some(used as f32), Some(total as f32));
        }
        (None, None)
    }
    #[cfg(not(any(unix, windows)))]
    {
        (None, None)
    }
}

/// Parent-side `sysinfo` host-load collector (no GPU driver calls, no all-mount
/// `statvfs` scans).
struct HostLoadSampler {
    sys: sysinfo::System,
    networks: sysinfo::Networks,
    last_net_at: Instant,
}

impl HostLoadSampler {
    fn new() -> Self {
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        let networks = sysinfo::Networks::new_with_refreshed_list();
        Self {
            sys,
            networks,
            last_net_at: Instant::now(),
        }
    }

    fn sample(&mut self) -> HostLoad {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.networks.refresh(true);

        let dt = self.last_net_at.elapsed().as_secs_f64().max(0.1);
        self.last_net_at = Instant::now();

        let cpu_pct = Some(self.sys.global_cpu_usage());
        let cpu_count = u16::try_from(self.sys.cpus().len()).ok();
        let load = sysinfo::System::load_average();
        let (load1, load5, load15) = if cfg!(unix) {
            (Some(load.one as f32), Some(load.five as f32), Some(load.fifteen as f32))
        } else {
            (None, None, None)
        };
        let mem_total_mb = (self.sys.total_memory() > 0)
            .then(|| self.sys.total_memory() / (1024 * 1024));
        let mem_used_mb = mem_total_mb.map(|_| self.sys.used_memory() / (1024 * 1024));
        let swap_total_mb = Some(self.sys.total_swap() / (1024 * 1024));
        let swap_used_mb = Some(self.sys.used_swap() / (1024 * 1024));

        let (disk_root_used_gb, disk_root_total_gb) = sample_root_disk_gb();

        let mut rx_bytes: u64 = 0;
        let mut tx_bytes: u64 = 0;
        for (name, data) in self.networks.list() {
            if name == "lo" || name.starts_with("lo") {
                continue;
            }
            rx_bytes = rx_bytes.saturating_add(data.received());
            tx_bytes = tx_bytes.saturating_add(data.transmitted());
        }
        let net_rx_bps = Some((rx_bytes as f64 / dt) as u64);
        let net_tx_bps = Some((tx_bytes as f64 / dt) as u64);

        HostLoad {
            cpu_pct,
            load1,
            load5,
            load15,
            cpu_count,
            mem_used_mb,
            mem_total_mb,
            swap_used_mb,
            swap_total_mb,
            disk_root_used_gb,
            disk_root_total_gb,
            net_rx_bps,
            net_tx_bps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::gpu::{GpuSample, ProcsState};

    fn test_supervisor(gpu_telemetry: bool, gpu_processes: bool) -> GpuSupervisor {
        GpuSupervisor::from_flags(
            Arc::new(AtomicBool::new(gpu_telemetry)),
            Arc::new(AtomicBool::new(gpu_processes)),
        )
    }

    #[tokio::test]
    async fn fr139_supervisor_respects_local_off_switch_without_spawning() {
        let sup = test_supervisor(false, true).with_test_overrides(
            SupervisorTimings {
                min_deadline: Duration::from_millis(200),
                backoff_initial: Duration::from_millis(50),
                backoff_cap: Duration::from_millis(200),
                max_consecutive_failures: 3,
            },
            // Non-existent binary proves the child is NEVER spawned when off_local.
            Some(PathBuf::from("/nonexistent-meshharbord-gpu-sampler")),
            Vec::new(),
        );
        let (shut_tx, shut_rx) = watch::channel(false);
        sup.spawn(None, shut_rx);

        let (tx, mut rx) = mpsc::channel(16);
        sup.register_org("org-a", tx);
        sup.apply_lease("org-a", 200, 5_000, true);

        let mut saw_inv = false;
        let mut saw_off_report = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline && (!saw_inv || !saw_off_report) {
            if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                match msg {
                    ClientMsg::AgentGpuInventory { inventory } => {
                        assert_eq!(inventory.status, GpuHostStatus::OffLocal);
                        saw_inv = true;
                    }
                    ClientMsg::AgentGpuReport { report } => {
                        assert_eq!(report.status, GpuHostStatus::OffLocal);
                        assert!(report.gpus.is_empty());
                        saw_off_report = true;
                    }
                    _ => {}
                }
            }
        }
        let _ = shut_tx.send(true);
        assert!(saw_inv && saw_off_report);
    }

    #[tokio::test]
    async fn fr139_supervisor_stuck_child_reports_stalled_and_never_blocks_and_reaches_unavailable() {
        // Use `/bin/sleep` (ignores stdin and prints nothing) to simulate a hung
        // driver child; `gpu-sampler` arg is passed but sleep fails or sleeps.
        // Better: a tiny python/sh script that ignores stdin and sleeps forever!
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let script = dir.path().join("hung-sampler.sh");
            std::fs::write(&script, "#!/bin/sh\nexec sleep 60\n").unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

            let sup = test_supervisor(true, true).with_test_overrides(
                SupervisorTimings {
                    min_deadline: Duration::from_millis(120),
                    backoff_initial: Duration::from_millis(40),
                    backoff_cap: Duration::from_millis(80),
                    max_consecutive_failures: 2,
                },
                Some(script),
                Vec::new(),
            );
            let (shut_tx, shut_rx) = watch::channel(false);
            sup.spawn(None, shut_rx);

            let (tx, mut rx) = mpsc::channel(32);
            sup.register_org("org-a", tx);
            sup.apply_lease("org-a", 100, 10_000, true);

            let mut statuses = Vec::new();
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(3) {
                if let Ok(Some(ClientMsg::AgentGpuReport { report })) =
                    tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
                {
                    statuses.push(report.status);
                    if statuses.contains(&GpuHostStatus::Unavailable) {
                        break;
                    }
                }
            }
            let _ = shut_tx.send(true);
            assert!(
                statuses.iter().any(|s| matches!(
                    s,
                    GpuHostStatus::DriverHung | GpuHostStatus::SamplerStalled
                )),
                "expected hung/stalled report, got {statuses:?}"
            );
            assert!(
                statuses.contains(&GpuHostStatus::Unavailable),
                "expected Unavailable after repeated failures, got {statuses:?}"
            );
        }
    }

    #[tokio::test]
    async fn fr139_supervisor_multi_org_fanout_and_alert_ring() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let sample_inv = ChildFrame::Inventory {
                inventory: GpuInventory {
                    backend: Some("fake".into()),
                    driver_version: Some("550.90".into()),
                    gpus: vec![],
                    status: GpuHostStatus::Ok,
                    status_detail: None,
                },
            };
            let sample_rep = ChildFrame::Report {
                report: GpuReport {
                    seq: 1,
                    interval_ms: 200,
                    status: GpuHostStatus::Ok,
                    status_detail: None,
                    backend: Some("fake".into()),
                    driver_version: Some("550.90".into()),
                    host: HostLoad::default(),
                    gpus: vec![GpuSample {
                        uuid: "GPU-FAKE-0".into(),
                        idx: 0,
                        name: Some("RTX 4090".into()),
                        util_pct: Some(12),
                        mem_used_mb: Some(512),
                        mem_total_mb: Some(24_576),
                        procs_state: ProcsState::Ok,
                        procs: Some(vec![]),
                        ..Default::default()
                    }],
                },
            };
            let inv_line = format!("{FRAME_PREFIX}{}", serde_json::to_string(&sample_inv).unwrap());
            let rep_line = format!("{FRAME_PREFIX}{}", serde_json::to_string(&sample_rep).unwrap());
            let script = dir.path().join("fake-sampler.sh");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' '{}'\nwhile true; do\n  printf '%s\\n' '{}'\n  sleep 0.1\ndone\n",
                    inv_line.replace('\'', "'\\''"),
                    rep_line.replace('\'', "'\\''"),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

            let sup = test_supervisor(true, true).with_test_overrides(
                SupervisorTimings {
                    min_deadline: Duration::from_secs(2),
                    backoff_initial: Duration::from_millis(50),
                    backoff_cap: Duration::from_millis(100),
                    max_consecutive_failures: 3,
                },
                Some(script),
                Vec::new(),
            );
            let (shut_tx, shut_rx) = watch::channel(false);
            sup.spawn(None, shut_rx);

            let (tx_a, mut rx_a) = mpsc::channel(32);
            let (tx_b, mut rx_b) = mpsc::channel(32);
            sup.register_org("org-a", tx_a);
            sup.register_org("org-b", tx_b);
            sup.apply_lease("org-a", 250, 5_000, true);
            sup.apply_lease("org-b", 30_000, 0, true);

            let mut got_a_rep = false;
            let mut got_b_rep = false;
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(2) && (!got_a_rep || !got_b_rep) {
                if let Ok(Some(ClientMsg::AgentGpuReport { report })) =
                    tokio::time::timeout(Duration::from_millis(150), rx_a.recv()).await
                {
                    assert_eq!(report.gpus[0].uuid, "GPU-FAKE-0");
                    assert!(report.host.cpu_pct.is_some());
                    got_a_rep = true;
                }
                if let Ok(Some(ClientMsg::AgentGpuReport { report })) =
                    tokio::time::timeout(Duration::from_millis(150), rx_b.recv()).await
                {
                    assert_eq!(report.interval_ms, 30_000);
                    got_b_rep = true;
                }
            }
            let _ = shut_tx.send(true);
            assert!(got_a_rep && got_b_rep, "both orgs must receive reports from single child");

            // Alert ring deduplication & ordering
            sup.record_alert(GpuAlertWire {
                seq: 1,
                at: 100,
                severity: "info".into(),
                title: "t1".into(),
                body: "b1".into(),
                link: "/gpu".into(),
            });
            sup.record_alert(GpuAlertWire {
                seq: 1,
                at: 100,
                severity: "info".into(),
                title: "t1".into(),
                body: "b1".into(),
                link: "/gpu".into(),
            });
            sup.record_alert(GpuAlertWire {
                seq: 2,
                at: 101,
                severity: "warning".into(),
                title: "t2".into(),
                body: "b2".into(),
                link: "/gpu".into(),
            });
            assert_eq!(sup.alerts_after(0).len(), 2);
            assert_eq!(sup.alerts_after(1).len(), 1);
            assert_eq!(sup.alerts_after(1)[0].seq, 2);
        }
    }
}
