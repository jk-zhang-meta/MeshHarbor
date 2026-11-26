// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Server-side GPU fleet manager: lease controller, `gpu_snapshot`
//! persistence, `wait_ms` freshness barrier, rollup & alert orchestration.

pub mod alerts;
pub mod bots;
pub mod history;
pub mod routes;

use std::collections::HashMap;
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
    GpuAlertWire, GpuInventory, GpuReport, GpuStateThresholds,
};
use meshharbor_remote_control::models::RpcCap;
use meshharbor_remote_control::signaling::ServerMsg;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::FleetState;

pub const SNAPSHOT_COLLECTION: &str = "gpu_snapshot";
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
}

#[derive(Debug, Clone)]
struct LeaseSlot {
    standing: bool,
    live_until: Option<Instant>,
    last_sent_interval_ms: u32,
    last_sent_at: Instant,
}

impl LeaseSlot {
    fn effective(&self, live_interval_ms: u32, now: Instant) -> (u32, u32, bool) {
        if let Some(until) = self.live_until
            && until > now
        {
            let rem_ms = until.saturating_duration_since(now).as_millis() as u32;
            (live_interval_ms.max(500), rem_ms.max(1000), self.standing)
        } else if self.standing {
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
            evaluator: Mutex::new(alerts::AlertEvaluator::default()),
            bots: bots::BotDispatcher::default(),
            alert_seq: AtomicU64::new(1),
        }
    }

    pub fn thresholds(&self) -> GpuStateThresholds {
        GpuStateThresholds {
            free_mem_max_mb: self.settings.free_mem_max_mb,
            idle_util_pct: self.settings.idle_util_pct,
            held_idle_secs: self.settings.held_idle_secs,
        }
    }

    /// Called when an agent completes `rc:agent.hello` on this pod.
    /// Grants a standing 30 s lease iff the agent is marked `gpu_server = true`
    /// and advertises `RpcCap::Gpu`.
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
        self.leases.insert(
            agent_id,
            LeaseSlot {
                standing: true,
                live_until: None,
                last_sent_interval_ms: STANDING_INTERVAL_MS,
                last_sent_at: now,
            },
        );
        let _ = hub.send_to_agent(
            agent_id,
            ServerMsg::GpuLease {
                interval_ms: STANDING_INTERVAL_MS,
                ttl_ms: 0,
                standing: true,
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
        if !self.settings.enabled || !supports_gpu {
            return;
        }
        if gpu_server {
            self.on_agent_connected(hub, agent_id, true, true);
        } else {
            self.leases.remove(&agent_id);
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

    /// Merge a 30 s live viewer lease across all listed online marked agents.
    /// Emits `rc:gpu.lease` ONLY when the effective interval changes or the
    /// live lease is within 10 s of expiry (no frame spam across N viewers).
    pub fn request_live_leases(&self, hub: &crate::Hub, agents: &[(ObjectId, bool)]) {
        if !self.settings.enabled {
            return;
        }
        let now = Instant::now();
        let target_iv = self.settings.live_interval_ms.max(500);
        let new_until = now + Duration::from_millis(u64::from(LIVE_LEASE_TTL_MS));

        for &(agent_id, supports_gpu) in agents {
            if !supports_gpu || !hub.is_agent_online(agent_id) {
                continue;
            }
            let mut should_send = false;
            self.leases
                .entry(agent_id)
                .and_modify(|slot| {
                    let prev_iv = slot.last_sent_interval_ms;
                    let needs_refresh =
                        now.duration_since(slot.last_sent_at) >= Duration::from_secs(15);
                    slot.standing = true;
                    slot.live_until = Some(new_until);
                    if prev_iv != target_iv || needs_refresh {
                        slot.last_sent_interval_ms = target_iv;
                        slot.last_sent_at = now;
                        should_send = true;
                    }
                })
                .or_insert_with(|| {
                    should_send = true;
                    LeaseSlot {
                        standing: true,
                        live_until: Some(new_until),
                        last_sent_interval_ms: target_iv,
                        last_sent_at: now,
                    }
                });
            if should_send {
                let _ = hub.send_to_agent(
                    agent_id,
                    ServerMsg::GpuLease {
                        interval_ms: target_iv,
                        ttl_ms: LIVE_LEASE_TTL_MS,
                        standing: true,
                    },
                );
            }
        }
    }

    /// Wait up to `wait_ms` (clamped to `0..=3000`) for fresh reports from at
    /// least one online target agent (used by `mh nvitop` one-shot `wait_ms`).
    pub async fn wait_for_fresh(&self, agent_ids: &[ObjectId], wait_ms: u32) {
        let clamped = wait_ms.min(3_000);
        if clamped == 0 || agent_ids.is_empty() {
            return;
        }
        let mut futs = Vec::with_capacity(agent_ids.len());
        for &aid in agent_ids {
            let n = self
                .waiters
                .entry(aid)
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone();
            futs.push(async move {
                n.notified().await;
            });
        }
        let _ = tokio::time::timeout(
            Duration::from_millis(u64::from(clamped)),
            futures::future::join_all(futs),
        )
        .await;
    }

    /// Persist static `rc:agent.gpu_inventory` onto `Agent.gpu_inventory`.
    pub async fn handle_inventory(
        &self,
        state: &FleetState,
        agent_id: ObjectId,
        inventory: GpuInventory,
    ) {
        if !self.settings.enabled {
            return;
        }
        if let Err(e) = state.agents.set_gpu_inventory(agent_id, &inventory).await {
            tracing::debug!(%agent_id, %e, "gpu_inventory persist failed");
        }
    }

    /// Handle an inbound `rc:agent.gpu_report`:
    /// 1. Stamp server receive time & upsert `gpu_snapshot`
    /// 2. Wake `wait_ms` waiters
    /// 3. Feed 1-min history bucket (`stats_gpu`)
    /// 4. Evaluate owner-only alerts & deliver (in-app, companion `rc:gpu.alert`, bots)
    pub async fn handle_report(
        &self,
        state: &FleetState,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        report: GpuReport,
    ) {
        if !self.settings.enabled {
            return;
        }
        let now = DateTime::now();
        let now_s = now.timestamp_millis() / 1000;
        let snap = GpuSnapshotDoc {
            agent_id,
            tenant_id,
            received_at: now,
            report: report.clone(),
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

        history::record_report_to_1m_bucket(
            &state.core.db,
            tenant_id,
            agent_id,
            &report,
            now_s,
            self.thresholds(),
        )
        .await;

        if self.settings.alerts {
            self.evaluate_and_deliver_report(state, tenant_id, agent_id, &report, now_s)
                .await;
        }
    }

    async fn evaluate_and_deliver_report(
        &self,
        state: &FleetState,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        report: &GpuReport,
        now_s: i64,
    ) {
        let Ok(agent) = state.agents.find_live_in_tenant(tenant_id, agent_id).await else {
            return;
        };
        if !agent.gpu_server {
            return;
        }
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
            eval.evaluate_report(agent_id, host_name, report, now_s, &self.settings, &rule)
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

        // Find owner's online agents in this tenant that support `RpcCap::GpuAlerts`
        // AND have a live desktop companion (`companion_version.is_some()`).
        let owner_companion_agents: Vec<ObjectId> = state
            .agents
            .base
            .find_many(
                doc! {
                    "tenant_id": tenant_id,
                    "owner_user_id": owner_id,
                    "deleted_at": null,
                    "companion_version": { "$exists": true, "$ne": bson::Bson::Null },
                },
                None,
            )
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.capabilities.has_rpc(RpcCap::GpuAlerts))
            .filter_map(|a| a.id)
            .filter(|id| state.rc_hub.is_agent_online(*id))
            .collect();

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

            // 3. Bot channels (10 s coalescing + retries).
            for ch in &channels {
                self.bots
                    .enqueue(state.core.db.clone(), ch.clone(), alert.item.clone());
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
        // Lease & offline-alert sweep
        let st1 = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // skip immediate tick at startup
            loop {
                tick.tick().await;
                st1.gpu.sweep_leases(&st1.rc_hub);
                if st1.gpu.settings.alerts {
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
        for mut entry in self.leases.iter_mut() {
            let aid = *entry.key();
            if !hub.is_agent_online(aid) {
                continue;
            }
            let (eff_iv, eff_ttl, standing) = entry.effective(self.settings.live_interval_ms, now);
            if eff_iv != entry.last_sent_interval_ms {
                entry.last_sent_interval_ms = eff_iv;
                entry.last_sent_at = now;
                let _ = hub.send_to_agent(
                    aid,
                    ServerMsg::GpuLease {
                        interval_ms: eff_iv,
                        ttl_ms: eff_ttl,
                        standing,
                    },
                );
            }
        }
    }

    async fn sweep_offline_alerts(&self, state: &FleetState) {
        let now_s = chrono::Utc::now().timestamp();
        let Ok(agents) = state
            .agents
            .base
            .find_many(doc! { "gpu_server": true, "deleted_at": null }, None)
            .await
        else {
            return;
        };
        let fresh = crate::agent::agent_presence_batch(state, &agents).await;
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
                eval.evaluate_offline(aid, host_name, now_s, &self.settings, &rule)
            };
            if let Some(alert) = fired {
                self.deliver_alerts(state, a.tenant_id, aid, owner_id, &rule.lang, vec![alert])
                    .await;
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
    fn fr139_lease_slot_falls_back_from_live_to_standing_30s() {
        let now = Instant::now();
        let slot = LeaseSlot {
            standing: true,
            live_until: Some(now + Duration::from_secs(20)),
            last_sent_interval_ms: 2000,
            last_sent_at: now,
        };
        let (iv, ttl, standing) = slot.effective(2000, now);
        assert_eq!(iv, 2000);
        assert!(ttl > 0);
        assert!(standing);

        let (iv2, ttl2, standing2) = slot.effective(2000, now + Duration::from_secs(31));
        assert_eq!(iv2, 30_000);
        assert_eq!(ttl2, 0);
        assert!(standing2);

        let unmarked = LeaseSlot {
            standing: false,
            live_until: None,
            last_sent_interval_ms: 0,
            last_sent_at: now,
        };
        assert_eq!(unmarked.effective(2000, now), (0, 0, false));
    }
}
