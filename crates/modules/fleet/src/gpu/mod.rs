// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Server-side GPU fleet manager: lease controller, `gpu_snapshot`
//! persistence, `wait_ms` freshness barrier, rollup & alert orchestration.

pub mod alerts;
pub mod bots;
pub mod history;
pub mod routes;
pub mod ws;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bson::{DateTime, doc, oid::ObjectId};
use dashmap::DashMap;
use futures::TryStreamExt as _;
use meshharbor_config::GpuSettings;
use meshharbor_core::notify::{NotifyParams, PushTo, notify_users};
use meshharbor_db::models::notification::{NotificationSource, NotificationType};
use meshharbor_remote_control::gpu::{
    GpuAlertWire, GpuHostStatus, GpuInventory, GpuReport, GpuStateThresholds,
};
use meshharbor_remote_control::models::{AgentStatus, RpcCap};
use meshharbor_remote_control::signaling::ServerMsg;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::FleetState;

pub const SNAPSHOT_COLLECTION: &str = "gpu_snapshot";
pub const MIN_LIVE_INTERVAL_MS: u32 = 500;
pub const MAX_LIVE_INTERVAL_MS: u32 = 10_000;
const STANDING_INTERVAL_MS: u32 = 30_000;
const LIVE_LEASE_TTL_MS: u32 = 30_000;

/// Persisted latest telemetry snapshot per marked GPU server (`gpu_snapshot`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSnapshotDoc {
    #[serde(rename = "_id")]
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub received_at: DateTime,
    pub report: GpuReport,
    /// Cross-replica claim timestamp for the current offline outage alert.
    /// Cleared automatically whenever a fresh report is persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_alerted_at: Option<DateTime>,
}

#[derive(Debug, Clone)]
struct LeaseSlot {
    standing: bool,
    /// Active HTTP live-viewer lease requests as `(interval_ms, expires_at)`.
    /// Always kept compact by deduplicating on `interval_ms`.
    live_requests: Vec<(u32, Instant)>,
    last_sent_interval_ms: u32,
    /// Deadline of the agent's currently dispatched live `GpuLease` (`None`
    /// when standing-only or no lease has been sent yet).
    last_sent_until: Option<Instant>,
}

impl LeaseSlot {
    fn record_sent(&mut self, eff_iv: u32, eff_ttl: u32, now: Instant) {
        self.last_sent_interval_ms = eff_iv;
        self.last_sent_until = if eff_iv > 0 && eff_iv < STANDING_INTERVAL_MS && eff_ttl > 0 {
            Some(now + Duration::from_millis(u64::from(eff_ttl)))
        } else {
            None
        };
    }

    fn needs_live_refresh(&self, eff_iv: u32, now: Instant) -> bool {
        if eff_iv == 0 || eff_iv >= STANDING_INTERVAL_MS {
            return false;
        }
        match self.last_sent_until {
            None => true,
            Some(until) => {
                until.saturating_duration_since(now)
                    <= Duration::from_millis(u64::from(LIVE_LEASE_TTL_MS / 2))
            }
        }
    }

    fn upsert_live(&mut self, interval_ms: u32, until: Instant, now: Instant) {
        self.live_requests.retain(|(_, exp)| *exp > now);
        if let Some(existing) = self
            .live_requests
            .iter_mut()
            .find(|(iv, _)| *iv == interval_ms)
        {
            if until > existing.1 {
                existing.1 = until;
            }
        } else {
            self.live_requests.push((interval_ms, until));
        }
    }

    fn effective(
        &self,
        server_live_interval_ms: u32,
        ws_min: Option<(u32, Instant)>,
        now: Instant,
    ) -> (u32, u32, bool) {
        if server_live_interval_ms > 0 {
            let mut best: Option<(u32, Instant)> = None;
            for &(iv, until) in &self.live_requests {
                if until <= now {
                    continue;
                }
                let clamped = iv.clamp(MIN_LIVE_INTERVAL_MS, MAX_LIVE_INTERVAL_MS);
                best = match best {
                    None => Some((clamped, until)),
                    Some((cur_iv, _)) if clamped < cur_iv => Some((clamped, until)),
                    Some((cur_iv, cur_until)) if clamped == cur_iv && until > cur_until => {
                        Some((cur_iv, until))
                    }
                    other => other,
                };
            }
            if let Some((iv, until)) = ws_min
                && until > now
                && iv > 0
            {
                let clamped = iv.clamp(MIN_LIVE_INTERVAL_MS, MAX_LIVE_INTERVAL_MS);
                best = match best {
                    None => Some((clamped, until)),
                    Some((cur_iv, _)) if clamped < cur_iv => Some((clamped, until)),
                    Some((cur_iv, cur_until)) if clamped == cur_iv && until > cur_until => {
                        Some((cur_iv, until))
                    }
                    other => other,
                };
            }
            if let Some((iv, until)) = best {
                let rem_ms = until.saturating_duration_since(now).as_millis() as u32;
                return (iv, rem_ms.clamp(1000, LIVE_LEASE_TTL_MS), self.standing);
            }
        }
        if self.standing {
            (STANDING_INTERVAL_MS, 0, true)
        } else {
            (0, 0, false)
        }
    }
}

/// Process-wide GPU telemetry coordinator mounted on [`FleetState`].
pub struct GpuManager {
    pub settings: GpuSettings,
    leases: DashMap<ObjectId, LeaseSlot>,
    waiters: DashMap<ObjectId, Arc<Notify>>,
    ws_subs: DashMap<String, ws::GpuWsSubscription>,
    history_credit_ms: DashMap<ObjectId, u32>,
    last_history_ms: DashMap<ObjectId, i64>,
    evaluator: Mutex<alerts::AlertEvaluator>,
    bots: bots::BotDispatcher,
    alert_seq: AtomicU64,
}

impl GpuManager {
    pub fn new(settings: GpuSettings) -> Self {
        Self {
            settings,
            leases: DashMap::new(),
            waiters: DashMap::new(),
            ws_subs: DashMap::new(),
            history_credit_ms: DashMap::new(),
            last_history_ms: DashMap::new(),
            evaluator: Mutex::new(alerts::AlertEvaluator::default()),
            bots: bots::BotDispatcher::default(),
            alert_seq: AtomicU64::new(1),
        }
    }

    /// Resolve a viewer's effective live cadence in milliseconds (`0` when live
    /// sampling is disabled by server config, otherwise `500..=10_000` ms).
    pub fn effective_viewer_interval_ms(&self, requested_ms: Option<u32>) -> u32 {
        if self.settings.live_interval_ms == 0 {
            return 0;
        }
        requested_ms
            .unwrap_or(self.settings.live_interval_ms)
            .clamp(MIN_LIVE_INTERVAL_MS, MAX_LIVE_INTERVAL_MS)
    }

    fn ws_min_for_agent(&self, agent_id: ObjectId, now: Instant) -> Option<(u32, Instant)> {
        let mut best: Option<(u32, Instant)> = None;
        for entry in self.ws_subs.iter() {
            let sub = entry.value();
            if sub.expires_at <= now || sub.interval_ms == 0 {
                continue;
            }
            if !sub.visible_agents.contains_key(&agent_id) {
                continue;
            }
            best = match best {
                None => Some((sub.interval_ms, sub.expires_at)),
                Some((iv, _)) if sub.interval_ms < iv => Some((sub.interval_ms, sub.expires_at)),
                Some((iv, exp)) if sub.interval_ms == iv && sub.expires_at > exp => {
                    Some((iv, sub.expires_at))
                }
                other => other,
            };
        }
        best
    }

    /// Accumulate sub-second report intervals into whole seconds for `stats_gpu`,
    /// bounded by actual elapsed server wall time so 500 ms cadence and jitter
    /// bursts never over-credit GPU·hours.
    fn credit_history_secs(&self, agent_id: ObjectId, interval_ms: u32, now_ms: i64) -> u64 {
        let declared = interval_ms.clamp(250, 60_000);
        let prev_ms = self.last_history_ms.insert(agent_id, now_ms);
        let add = match prev_ms {
            Some(prev) if now_ms <= prev => return 0,
            Some(prev) => {
                let elapsed = (now_ms - prev) as u64;
                elapsed.min(u64::from(declared).saturating_add(2_000)) as u32
            }
            None => declared,
        };
        let mut entry = self.history_credit_ms.entry(agent_id).or_insert(0);
        let total = entry.saturating_add(add);
        let secs = u64::from(total / 1000);
        *entry = total % 1000;
        secs
    }

    pub fn thresholds(&self) -> GpuStateThresholds {
        GpuStateThresholds {
            free_mem_max_mb: self.settings.free_mem_max_mb,
            idle_util_pct: self.settings.idle_util_pct,
            held_idle_secs: self.settings.held_idle_secs,
        }
    }

    /// Called when an agent completes `rc:agent.hello` on this pod.
    /// Grants a standing 30 s lease (or preserves active viewer live leases)
    /// iff the agent is marked `gpu_server = true` and advertises `RpcCap::Gpu`.
    pub fn on_agent_connected(
        &self,
        hub: &crate::Hub,
        agent_id: ObjectId,
        gpu_server: bool,
        supports_gpu: bool,
    ) {
        if !self.settings.enabled || !supports_gpu {
            return;
        }
        if !gpu_server {
            self.leases.remove(&agent_id);
            return;
        }
        let now = Instant::now();
        let ws_min = self.ws_min_for_agent(agent_id, now);
        let preserved_live: Vec<(u32, Instant)> = self
            .leases
            .get(&agent_id)
            .map(|existing| {
                existing
                    .live_requests
                    .iter()
                    .copied()
                    .filter(|(_, exp)| *exp > now)
                    .collect()
            })
            .unwrap_or_default();
        let mut slot = LeaseSlot {
            standing: true,
            live_requests: preserved_live,
            last_sent_interval_ms: STANDING_INTERVAL_MS,
            last_sent_until: None,
        };
        let (eff_iv, eff_ttl, standing) =
            slot.effective(self.settings.live_interval_ms, ws_min, now);
        slot.record_sent(eff_iv, eff_ttl, now);
        self.leases.insert(agent_id, slot);
        let _ = hub.send_to_agent(
            agent_id,
            ServerMsg::GpuLease {
                interval_ms: eff_iv,
                ttl_ms: eff_ttl,
                standing,
            },
        );
    }

    /// Called when an operator toggles `gpu_server` on an agent.
    pub fn on_gpu_server_toggled(
        &self,
        hub: &crate::Hub,
        agent_id: ObjectId,
        gpu_server: bool,
        supports_gpu: bool,
    ) {
        if !self.settings.enabled {
            return;
        }
        if gpu_server {
            if supports_gpu {
                self.on_agent_connected(hub, agent_id, true, true);
            }
        } else {
            self.leases.remove(&agent_id);
            self.history_credit_ms.remove(&agent_id);
            self.last_history_ms.remove(&agent_id);
            for mut sub in self.ws_subs.iter_mut() {
                sub.visible_agents.remove(&agent_id);
            }
            if let Ok(mut eval) = self.evaluator.try_lock() {
                eval.remove_host(agent_id);
            }
            if supports_gpu {
                let _ = hub.send_to_agent(
                    agent_id,
                    ServerMsg::GpuLease {
                        interval_ms: 0,
                        ttl_ms: 0,
                        standing: false,
                    },
                );
            }
        }
    }

    /// Drop any active browser WebSocket GPU subscriptions held by a removed
    /// member in `tenant_id` and immediately reconcile affected agent leases.
    pub fn revoke_ws_for_member(
        &self,
        hub: &crate::Hub,
        tenant_id: ObjectId,
        user_id: ObjectId,
    ) {
        let conn_ids: Vec<String> = self
            .ws_subs
            .iter()
            .filter(|e| e.value().tenant_id == tenant_id && e.value().user_id == user_id)
            .map(|e| e.key().clone())
            .collect();
        for cid in conn_ids {
            self.remove_ws_subscription(hub, &cid);
        }
    }

    /// Drop all active browser WebSocket GPU subscriptions scoped to `tenant_id`
    /// (called on tenant archive).
    pub fn revoke_ws_for_tenant(&self, hub: &crate::Hub, tenant_id: ObjectId) {
        let conn_ids: Vec<String> = self
            .ws_subs
            .iter()
            .filter(|e| e.value().tenant_id == tenant_id)
            .map(|e| e.key().clone())
            .collect();
        for cid in conn_ids {
            self.remove_ws_subscription(hub, &cid);
        }
    }

    /// Merge a 30 s live viewer lease across all listed online marked agents
    /// using the server's default live interval.
    pub fn request_live_leases(&self, hub: &crate::Hub, agents: &[(ObjectId, bool)]) {
        self.request_live_leases_at(hub, agents, None);
    }

    /// Merge a 30 s live viewer lease at an optional viewer-requested cadence
    /// (`500..=10_000` ms) across all listed online marked agents.
    /// Emits `rc:gpu.lease` immediately when the effective interval changes
    /// (e.g. `2s -> 0.5s`) or the agent's dispatched lease is past half-TTL.
    pub fn request_live_leases_at(
        &self,
        hub: &crate::Hub,
        agents: &[(ObjectId, bool)],
        requested_interval_ms: Option<u32>,
    ) {
        if !self.settings.enabled || self.settings.live_interval_ms == 0 {
            return;
        }
        let now = Instant::now();
        let target_iv = self.effective_viewer_interval_ms(requested_interval_ms);
        if target_iv == 0 {
            return;
        }
        let new_until = now + Duration::from_millis(u64::from(LIVE_LEASE_TTL_MS));

        for &(agent_id, supports_gpu) in agents {
            if !supports_gpu || !hub.is_agent_online(agent_id) {
                continue;
            }
            let ws_min = self.ws_min_for_agent(agent_id, now);
            let mut send_params: Option<(u32, u32, bool)> = None;
            self.leases
                .entry(agent_id)
                .and_modify(|slot| {
                    let prev_iv = slot.last_sent_interval_ms;
                    slot.standing = true;
                    slot.upsert_live(target_iv, new_until, now);
                    let (eff_iv, eff_ttl, standing) =
                        slot.effective(self.settings.live_interval_ms, ws_min, now);
                    if prev_iv != eff_iv || slot.needs_live_refresh(eff_iv, now) {
                        slot.record_sent(eff_iv, eff_ttl, now);
                        send_params = Some((eff_iv, eff_ttl, standing));
                    }
                })
                .or_insert_with(|| {
                    let mut slot = LeaseSlot {
                        standing: true,
                        live_requests: vec![(target_iv, new_until)],
                        last_sent_interval_ms: target_iv,
                        last_sent_until: None,
                    };
                    let (eff_iv, eff_ttl, standing) =
                        slot.effective(self.settings.live_interval_ms, ws_min, now);
                    slot.record_sent(eff_iv, eff_ttl, now);
                    send_params = Some((eff_iv, eff_ttl, standing));
                    slot
                });
            if let Some((iv, ttl, standing)) = send_params {
                let _ = hub.send_to_agent(
                    agent_id,
                    ServerMsg::GpuLease {
                        interval_ms: iv,
                        ttl_ms: ttl,
                        standing,
                    },
                );
            }
        }
    }

    fn upsert_ws_subscription(
        &self,
        hub: &crate::Hub,
        sub: ws::GpuWsSubscription,
        lease_targets: &[(ObjectId, bool)],
    ) {
        let prev_agents: Vec<ObjectId> = self
            .ws_subs
            .insert(sub.connection_id.clone(), sub)
            .map(|old| old.visible_agents.into_keys().collect())
            .unwrap_or_default();
        let now = Instant::now();
        let mut to_reconcile: HashSet<ObjectId> = prev_agents.into_iter().collect();
        for &(aid, supports_gpu) in lease_targets {
            if supports_gpu && hub.is_agent_online(aid) {
                to_reconcile.insert(aid);
                self.leases.entry(aid).or_insert_with(|| LeaseSlot {
                    standing: true,
                    live_requests: Vec::new(),
                    last_sent_interval_ms: STANDING_INTERVAL_MS,
                    last_sent_until: None,
                });
            }
        }
        for aid in to_reconcile {
            self.reconcile_agent_lease(hub, aid, now, true);
        }
    }

    pub(super) fn remove_ws_subscription(&self, hub: &crate::Hub, connection_id: &str) {
        let Some((_, old)) = self.ws_subs.remove(connection_id) else {
            return;
        };
        let now = Instant::now();
        for aid in old.visible_agents.into_keys() {
            self.reconcile_agent_lease(hub, aid, now, false);
        }
    }

    fn reconcile_agent_lease(
        &self,
        hub: &crate::Hub,
        agent_id: ObjectId,
        now: Instant,
        refresh_if_stale: bool,
    ) {
        if !hub.is_agent_online(agent_id) {
            return;
        }
        let ws_min = self.ws_min_for_agent(agent_id, now);
        let mut send_params: Option<(u32, u32, bool)> = None;
        if let Some(mut entry) = self.leases.get_mut(&agent_id) {
            entry.live_requests.retain(|(_, exp)| *exp > now);
            let (eff_iv, eff_ttl, standing) =
                entry.effective(self.settings.live_interval_ms, ws_min, now);
            let needs_refresh = refresh_if_stale && entry.needs_live_refresh(eff_iv, now);
            if eff_iv != entry.last_sent_interval_ms || needs_refresh {
                entry.record_sent(eff_iv, eff_ttl, now);
                send_params = Some((eff_iv, eff_ttl, standing));
            }
        }
        if let Some((iv, ttl, standing)) = send_params {
            let _ = hub.send_to_agent(
                agent_id,
                ServerMsg::GpuLease {
                    interval_ms: iv,
                    ttl_ms: ttl,
                    standing,
                },
            );
        }
    }

    /// Wait up to `wait_ms` (clamped to `0..=3000`) for fresh reports from at
    /// least one online target agent (used by `mh nvitop` one-shot `wait_ms`
    /// and Desktop manual refresh).
    pub async fn wait_for_fresh(&self, agent_ids: &[ObjectId], wait_ms: u32) {
        let clamped = wait_ms.min(3_000);
        if clamped == 0 || agent_ids.is_empty() {
            return;
        }
        // Register every Notified waiter eagerly BEFORE awaiting so a report
        // arriving right after lease dispatch cannot race ahead and be lost.
        let mut waiters = Vec::with_capacity(agent_ids.len());
        for &aid in agent_ids {
            let n = self
                .waiters
                .entry(aid)
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone();
            let mut owned = Box::pin(n.notified_owned());
            owned.as_mut().enable();
            waiters.push(owned);
        }
        let _ = tokio::time::timeout(
            Duration::from_millis(u64::from(clamped)),
            futures::future::select_all(waiters),
        )
        .await;
    }

    /// Persist static `rc:agent.gpu_inventory` onto `Agent.gpu_inventory`.
    /// Refuses unmarked or deleted devices and pushes a stop lease so multi-replica
    /// unmarks always converge on the connection-owning pod.
    ///
    /// Never overwrites a non-empty persisted inventory with an empty error
    /// frame (`sampler_stalled`, `driver_hung`, `unavailable`, `driver_missing`)
    /// so known accelerator cards stay visible during outages.
    pub async fn handle_inventory(
        &self,
        state: &FleetState,
        agent_id: ObjectId,
        mut inventory: GpuInventory,
    ) {
        if !self.settings.enabled {
            return;
        }
        let Ok(agent) = state.agents.base.find_by_id(agent_id).await else {
            return;
        };
        if agent.deleted_at.is_some() || !agent.gpu_server {
            self.on_gpu_server_toggled(&state.rc_hub, agent_id, false, true);
            return;
        }
        sanitize_inventory(&mut inventory);
        if inventory.gpus.is_empty()
            && matches!(
                inventory.status,
                meshharbor_remote_control::gpu::GpuHostStatus::SamplerStalled
                    | meshharbor_remote_control::gpu::GpuHostStatus::DriverHung
                    | meshharbor_remote_control::gpu::GpuHostStatus::Unavailable
                    | meshharbor_remote_control::gpu::GpuHostStatus::DriverMissing
            )
            && let Some(prev) = agent.gpu_inventory.as_ref()
            && !prev.gpus.is_empty()
        {
            inventory.gpus = prev.gpus.clone();
            if inventory.backend.is_none() {
                inventory.backend = prev.backend.clone();
            }
            if inventory.driver_version.is_none() {
                inventory.driver_version = prev.driver_version.clone();
            }
        }
        if let Err(e) = state.agents.set_gpu_inventory(agent_id, &inventory).await {
            tracing::debug!(%agent_id, %e, "gpu_inventory persist failed");
        }
    }

    /// Handle an inbound `rc:agent.gpu_report`:
    /// 0. Enforce live `agent.gpu_server == true` (pushes stop lease if unmarked
    ///    on another replica so collection never continues after unmark)
    /// 1. Sanitize device-supplied strings & UUIDs at ingest
    /// 2. Stamp server receive time & upsert `gpu_snapshot`
    /// 3. Wake `wait_ms` waiters
    /// 4. Feed 1-min history bucket (`stats_gpu`)
    /// 5. Evaluate owner-only alerts & deliver (in-app, companion `rc:gpu.alert`, bots)
    pub async fn handle_report(
        &self,
        state: &FleetState,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        mut report: GpuReport,
    ) {
        if !self.settings.enabled {
            return;
        }
        let Ok(agent) = state.agents.find_live_in_tenant(tenant_id, agent_id).await else {
            self.on_gpu_server_toggled(&state.rc_hub, agent_id, false, true);
            return;
        };
        if !agent.gpu_server || agent.status == AgentStatus::Quarantined {
            self.on_gpu_server_toggled(&state.rc_hub, agent_id, false, true);
            return;
        }
        sanitize_report(&mut report);
        let now = DateTime::now();
        let now_ms = now.timestamp_millis();
        let now_s = now_ms / 1000;
        let snap = GpuSnapshotDoc {
            agent_id,
            tenant_id,
            received_at: now,
            report: report.clone(),
            offline_alerted_at: None,
        };
        if let Err(e) = state
            .core
            .db
            .collection::<GpuSnapshotDoc>(SNAPSHOT_COLLECTION)
            .replace_one(doc! { "_id": agent_id }, &snap)
            .upsert(true)
            .await
        {
            tracing::debug!(%agent_id, %e, "gpu_snapshot upsert failed");
        }

        if let Some(n) = self.waiters.get(&agent_id) {
            n.notify_waiters();
        }

        // Push live host snapshot directly over WebSocket to authorized active
        // GPU-page viewers (zero polling phase lag).
        self.push_ws_report(state, agent_id, &agent, &snap, now_ms, now_s)
            .await;

        let synthetic_fault = matches!(
            report.status,
            GpuHostStatus::SamplerStalled | GpuHostStatus::Unavailable | GpuHostStatus::OffLocal
        );
        if !synthetic_fault {
            let step_secs = self.credit_history_secs(agent_id, report.interval_ms, now_ms);
            if step_secs > 0 {
                history::record_report_to_1m_bucket_with_step(
                    &state.core.db,
                    tenant_id,
                    agent_id,
                    &report,
                    now_s,
                    self.thresholds(),
                    step_secs,
                )
                .await;
            }
        }

        if self.settings.alerts {
            self.evaluate_and_deliver_report(state, tenant_id, agent_id, &agent, &report, now_s)
                .await;
        }
    }

    async fn push_ws_report(
        &self,
        state: &FleetState,
        agent_id: ObjectId,
        agent: &meshharbor_remote_control::models::Agent,
        snap: &GpuSnapshotDoc,
        now_ms: i64,
        now_s: i64,
    ) {
        if self.ws_subs.is_empty() {
            return;
        }
        let now_inst = Instant::now();
        let targets: Vec<(String, ObjectId, ObjectId, &'static str, bool, u32)> = self
            .ws_subs
            .iter()
            .filter_map(|entry| {
                let sub = entry.value();
                if sub.expires_at <= now_inst {
                    return None;
                }
                let &(source, read_only) = sub.visible_agents.get(&agent_id)?;
                Some((
                    sub.connection_id.clone(),
                    sub.user_id,
                    sub.tenant_id,
                    source,
                    read_only,
                    sub.interval_ms,
                ))
            })
            .collect();
        if targets.is_empty() {
            return;
        }

        let thresholds = self.thresholds();
        let mut projected: HashMap<(&'static str, bool, bool), routes::GpuHostFleetView> =
            HashMap::new();
        let mut revoked_any = false;
        for (conn_id, user_id, tid, source, read_only, sub_iv) in targets {
            if !routes::is_agent_visible_to_subscriber(state, tid, user_id, agent, source).await {
                let mut drop_conn = false;
                if let Some(mut sub) = self.ws_subs.get_mut(&conn_id) {
                    sub.visible_agents.remove(&agent_id);
                    drop_conn = sub.visible_agents.is_empty();
                }
                if drop_conn {
                    self.ws_subs.remove(&conn_id);
                }
                revoked_any = true;
                continue;
            }
            let live_requested = sub_iv > 0;
            let host_view = projected
                .entry((source, read_only, live_requested))
                .or_insert_with(|| {
                    routes::project_host_view(
                        agent,
                        source,
                        read_only,
                        true,
                        Some(snap),
                        now_ms,
                        now_s,
                        live_requested,
                        thresholds,
                        false,
                    )
                });
            let msg = serde_json::json!({
                "type": "gpu:update",
                "data": {
                    "tenant_id": tid.to_hex(),
                    "host": host_view,
                    "server_time_ms": now_ms,
                    "live_interval_ms": sub_iv,
                }
            });
            meshharbor_core::ws::dispatcher::send_to_connection_routed(
                &state.core.ws_storage,
                &state.core.redis_pubsub,
                &conn_id,
                &msg,
            )
            .await;
        }
        if revoked_any {
            self.reconcile_agent_lease(&state.rc_hub, agent_id, Instant::now(), false);
        }
    }

    async fn evaluate_and_deliver_report(
        &self,
        state: &FleetState,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        agent: &meshharbor_remote_control::models::Agent,
        report: &GpuReport,
        now_s: i64,
    ) {
        let owner_id = agent.owner_user_id;
        // Owner-only invariant (D4): owner must STILL be a tenant member!
        if !state.tenants.is_member(tenant_id, owner_id).await.unwrap_or(false) {
            return;
        }
        let rule = load_rule(&state.core.db, tenant_id, owner_id).await;
        let host_name = agent
            .display_name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&agent.name);

        let fired = {
            let mut eval = self.evaluator.lock().await;
            eval.evaluate_report(tenant_id, agent_id, host_name, report, now_s, &self.settings, &rule)
        };
        if !fired.is_empty() {
            self.deliver_alerts(state, tenant_id, agent_id, owner_id, &rule.lang, fired)
                .await;
        }
    }

    async fn deliver_alerts(
        &self,
        state: &FleetState,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        owner_id: ObjectId,
        lang: &str,
        fired: Vec<alerts::FiredAlert>,
    ) {
        let now_s = chrono::Utc::now().timestamp();
        let is_zh = lang.eq_ignore_ascii_case("zh");

        // Load owner's enabled bot channels once if bots are enabled.
        let channels: Vec<bots::GpuAlertChannel> = if self.settings.bots {
            match state
                .core
                .db
                .collection::<bots::GpuAlertChannel>(bots::COLLECTION)
                .find(doc! {
                    "tenant_id": tenant_id,
                    "user_id": owner_id,
                    "enabled": true,
                })
                .await
            {
                Ok(cur) => cur.try_collect().await.unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        // Find owner's online PERMANENT agents in this tenant that support
        // `RpcCap::GpuAlerts` AND have a live desktop companion. Temporary /
        // invited devices are enrolled under the inviter's `owner_user_id` and
        // MUST be excluded (fail closed if the lookup fails).
        let owner_companion_agents: Vec<ObjectId> =
            match crate::device_invite::temporary_agent_ids_in_tenant(state, tenant_id).await {
                Ok(temp_ids) => state
                    .agents
                    .base
                    .find_many(
                        doc! {
                            "tenant_id": tenant_id,
                            "owner_user_id": owner_id,
                            "deleted_at": null,
                            "ephemeral": { "$ne": true },
                            "companion_version": { "$exists": true, "$ne": bson::Bson::Null },
                        },
                        None,
                    )
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|a| a.capabilities.has_rpc(RpcCap::GpuAlerts))
                    .filter_map(|a| a.id)
                    .filter(|id| !temp_ids.contains(id) && state.rc_hub.is_agent_online(*id))
                    .collect(),
                Err(_) => Vec::new(),
            };

        for alert in fired {
            let title = if is_zh {
                alert.item.title_zh.clone()
            } else {
                alert.item.title_en.clone()
            };
            let body = if is_zh {
                alert.item.body_zh.clone()
            } else {
                alert.item.body_en.clone()
            };

            // 1. In-app + web push (`NotificationType::GpuAlert`), owner only!
            notify_users(
                &state.core,
                &NotifyParams {
                    tenant_id,
                    notification_type: NotificationType::GpuAlert,
                    title: title.clone(),
                    body: body.clone(),
                    link: alert.item.link.clone(),
                    source: NotificationSource {
                        entity_type: "agent".to_string(),
                        entity_id: agent_id,
                        actor_id: None,
                    },
                    ws_type_label: "gpu_alert",
                },
                &[owner_id],
                PushTo::Everyone,
            )
            .await;

            // 2. Desktop companion relay (`rc:gpu.alert`) to owner's online companion agents!
            let seq = self.alert_seq.fetch_add(1, Ordering::Relaxed);
            let wire = GpuAlertWire {
                seq,
                at: now_s,
                severity: alert.item.severity.clone(),
                title,
                body,
                link: alert.item.link.clone(),
            };
            for target_aid in &owner_companion_agents {
                let _ = state.rc_hub.send_to_agent(
                    *target_aid,
                    ServerMsg::GpuAlert {
                        alert: Box::new(wire.clone()),
                    },
                );
            }

            // 3. Bot channels (10 s coalescing + retries, re-loaded per attempt).
            for ch in &channels {
                if let Some(cid) = ch.id {
                    self.bots.enqueue(
                        state.core.db.clone(),
                        cid,
                        tenant_id,
                        owner_id,
                        alert.item.clone(),
                    );
                }
            }
        }
    }

    /// Spawn periodic background tasks:
    /// - Every 60 s: expire live leases back to standing 30 s & check offline > 5 min alerts.
    /// - Every 15 min: roll up `stats_gpu` -> `stats_gpu_1h` and `stats_gpu_1h` -> `stats_gpu_1d`.
    pub fn spawn_background_tasks(&self, state: FleetState) {
        if !self.settings.enabled {
            return;
        }
        // Lease sweep (every 10 s so active live leases never starve across
        // viewer step-downs or half-TTL jitter) + offline alerts (every 60 s).
        let st1 = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // skip immediate tick at startup
            let mut cycle: u64 = 0;
            loop {
                tick.tick().await;
                cycle = cycle.wrapping_add(1);
                st1.gpu.sweep_leases(&st1.rc_hub);
                if cycle.is_multiple_of(6) && st1.gpu.settings.alerts {
                    st1.gpu.sweep_offline_alerts(&st1).await;
                }
            }
        });

        // Hourly/daily rollup task
        let db = state.core.db.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15 * 60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let now_s = chrono::Utc::now().timestamp();
                let _ = history::rollup_buckets(
                    &db,
                    history::COLL_1M,
                    history::COLL_1H,
                    3600,
                    now_s - 3 * 3600,
                    now_s,
                )
                .await;
                let _ = history::rollup_buckets(
                    &db,
                    history::COLL_1H,
                    history::COLL_1D,
                    86_400,
                    now_s - 3 * 86_400,
                    now_s,
                )
                .await;
            }
        });
    }

    fn sweep_leases(&self, hub: &crate::Hub) {
        let now = Instant::now();
        self.ws_subs.retain(|_, sub| sub.expires_at > now);
        let aids: Vec<ObjectId> = self.leases.iter().map(|e| *e.key()).collect();
        for aid in aids {
            self.reconcile_agent_lease(hub, aid, now, true);
        }
    }

    async fn sweep_offline_alerts(&self, state: &FleetState) {
        let now_dt = DateTime::now();
        let now_s = now_dt.timestamp_millis() / 1000;
        let cutoff = DateTime::from_millis(now_s.saturating_sub(300).saturating_mul(1000));
        let Ok(agents) = state
            .agents
            .base
            .find_many(doc! { "gpu_server": true, "deleted_at": null }, None)
            .await
        else {
            return;
        };
        let active_ids: HashSet<ObjectId> = agents.iter().filter_map(|a| a.id).collect();
        {
            let mut eval = self.evaluator.lock().await;
            eval.prune_stale_hosts(&active_ids);
        }
        let fresh = crate::agent::agent_presence_batch(state, &agents).await;
        let snap_coll = state
            .core
            .db
            .collection::<GpuSnapshotDoc>(SNAPSHOT_COLLECTION);
        for a in agents {
            let Some(aid) = a.id else { continue };
            let redis_fresh = fresh.contains(&aid);
            let (_, is_online) = crate::agent::derive_agent_presence(state, &a, redis_fresh);
            if is_online {
                continue;
            }
            let owner_id = a.owner_user_id;
            if !state
                .tenants
                .is_member(a.tenant_id, owner_id)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            let rule = load_rule(&state.core.db, a.tenant_id, owner_id).await;
            let host_name = a
                .display_name
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(&a.name);
            let fired = {
                let mut eval = self.evaluator.lock().await;
                eval.evaluate_offline(a.tenant_id, aid, host_name, now_s, &self.settings, &rule)
            };
            if let Some(alert) = fired {
                // Atomically claim this offline transition across replicas on
                // `gpu_snapshot` so at most one pod delivers the outage alert.
                let claimed = snap_coll
                    .find_one_and_update(
                        doc! {
                            "_id": aid,
                            "offline_alerted_at": null,
                            "received_at": { "$lte": cutoff },
                        },
                        doc! { "$set": { "offline_alerted_at": now_dt } },
                    )
                    .await
                    .ok()
                    .flatten();
                if claimed.is_some() {
                    self.deliver_alerts(state, a.tenant_id, aid, owner_id, &rule.lang, vec![alert])
                        .await;
                }
            }
        }
    }
}

pub async fn load_rule(
    db: &mongodb::Database,
    tenant_id: ObjectId,
    user_id: ObjectId,
) -> alerts::GpuAlertRule {
    db.collection::<alerts::GpuAlertRule>(alerts::RULES_COLLECTION)
        .find_one(doc! { "tenant_id": tenant_id, "user_id": user_id })
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| alerts::GpuAlertRule::default_for(tenant_id, user_id))
}

/// Strip ASCII/Unicode control characters and cap length on device-reported strings.
fn sanitize_text(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect()
}

fn sanitize_opt_text(opt: &mut Option<String>, max_chars: usize) {
    if let Some(s) = opt.as_mut() {
        *s = sanitize_text(s, max_chars);
    }
}

/// Validate a GPU UUID to a safe identifier charset `[A-Za-z0-9._:-]{1..=128}`
/// so shell/clipboard exports and terminal tables can never receive injections.
fn sanitize_gpu_uuid(raw: &str, idx: u16) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'))
        .take(128)
        .collect();
    if clean.is_empty() {
        format!("gpu-{idx}")
    } else {
        clean
    }
}

fn sanitize_inventory(inv: &mut GpuInventory) {
    sanitize_opt_text(&mut inv.backend, 64);
    sanitize_opt_text(&mut inv.driver_version, 64);
    sanitize_opt_text(&mut inv.status_detail, 256);
    inv.gpus.truncate(64);
    for g in &mut inv.gpus {
        g.uuid = sanitize_gpu_uuid(&g.uuid, g.idx);
        g.name = sanitize_text(&g.name, 128);
        sanitize_opt_text(&mut g.pci_bus, 32);
    }
}

fn sanitize_report(rep: &mut GpuReport) {
    sanitize_opt_text(&mut rep.backend, 64);
    sanitize_opt_text(&mut rep.driver_version, 64);
    sanitize_opt_text(&mut rep.status_detail, 256);
    rep.gpus.truncate(64);
    for g in &mut rep.gpus {
        g.uuid = sanitize_gpu_uuid(&g.uuid, g.idx);
        sanitize_opt_text(&mut g.name, 128);
        sanitize_opt_text(&mut g.pci_bus, 32);
        sanitize_opt_text(&mut g.vendor_health, 64);
        sanitize_opt_text(&mut g.backend, 32);
        if let Some(th) = g.throttle.as_mut() {
            th.truncate(16);
            for item in th.iter_mut() {
                *item = sanitize_text(item, 32);
            }
        }
        if let Some(procs) = g.procs.as_mut() {
            procs.truncate(64);
            for p in procs.iter_mut() {
                sanitize_opt_text(&mut p.user, 64);
                sanitize_opt_text(&mut p.name, 64);
                sanitize_opt_text(&mut p.container, 32);
            }
        }
    }
}

/// Load latest `gpu_snapshot` documents for a batch of agent IDs.
pub async fn load_snapshots(
    db: &mongodb::Database,
    agent_ids: &[ObjectId],
) -> HashMap<ObjectId, GpuSnapshotDoc> {
    if agent_ids.is_empty() {
        return HashMap::new();
    }
    let Ok(mut cur) = db
        .collection::<GpuSnapshotDoc>(SNAPSHOT_COLLECTION)
        .find(doc! { "_id": { "$in": agent_ids } })
        .await
    else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    while let Ok(Some(snap)) = cur.try_next().await {
        map.insert(snap.agent_id, snap);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr139_lease_slot_merges_multi_viewer_intervals_and_falls_back_to_standing_30s() {
        let now = Instant::now();
        let mut slot = LeaseSlot {
            standing: true,
            live_requests: Vec::new(),
            last_sent_interval_ms: 30_000,
            last_sent_until: None,
        };
        slot.upsert_live(2000, now + Duration::from_secs(20), now);
        slot.upsert_live(500, now + Duration::from_secs(10), now);
        let (iv, ttl, standing) = slot.effective(1000, None, now);
        assert_eq!(iv, 500, "fastest viewer cadence must win");
        assert!(ttl > 0);
        assert!(standing);
        slot.record_sent(iv, ttl, now);
        assert!(
            slot.needs_live_refresh(iv, now),
            "10 s short-lived lease must be eligible for refresh (< 15 s half-TTL)"
        );

        // After the 500 ms viewer expires, fall back smoothly to the 2000 ms viewer.
        let (iv_mid, _, _) = slot.effective(1000, None, now + Duration::from_secs(12));
        assert_eq!(iv_mid, 2000);

        // An active WS subscriber overrides with its faster 500 ms cadence.
        let (iv_ws, _, _) = slot.effective(
            1000,
            Some((500, now + Duration::from_secs(30))),
            now + Duration::from_secs(12),
        );
        assert_eq!(iv_ws, 500);

        // After all viewers expire, fall back to 30 s standing.
        let (iv2, ttl2, standing2) = slot.effective(1000, None, now + Duration::from_secs(31));
        assert_eq!(iv2, 30_000);
        assert_eq!(ttl2, 0);
        assert!(standing2);

        // Server live_interval_ms == 0 disables live leases completely.
        assert_eq!(
            slot.effective(0, Some((500, now + Duration::from_secs(30))), now),
            (30_000, 0, true)
        );

        let unmarked = LeaseSlot {
            standing: false,
            live_requests: Vec::new(),
            last_sent_interval_ms: 0,
            last_sent_until: None,
        };
        assert_eq!(unmarked.effective(1000, None, now), (0, 0, false));
    }

    #[test]
    fn fr139_subsecond_history_credit_is_wall_clock_bounded_and_does_not_double_count() {
        let mgr = GpuManager::new(GpuSettings::default());
        let aid = ObjectId::new();
        let mut t = 1_000_000i64;
        // First 500 ms frame credits 500 ms -> 0 whole secs yet.
        assert_eq!(mgr.credit_history_secs(aid, 500, t), 0);
        // Duplicate same-ms burst must credit 0.
        assert_eq!(mgr.credit_history_secs(aid, 500, t), 0);
        // Early jitter frame at +400 ms credits 400 ms (total 900 ms) -> still 0, not 1!
        t += 400;
        assert_eq!(mgr.credit_history_secs(aid, 500, t), 0);
        // Next +400 ms frame brings total to 1300 ms -> emits 1 sec, carries 300 ms.
        t += 400;
        assert_eq!(mgr.credit_history_secs(aid, 500, t), 1);
        // Normal 1000 ms step -> 1300 ms -> emits 1 sec.
        t += 1_000;
        assert_eq!(mgr.credit_history_secs(aid, 1_000, t), 1);
        // Standing 30 s step -> emits 30 secs.
        t += 30_000;
        assert_eq!(mgr.credit_history_secs(aid, 30_000, t), 30);
    }
}
