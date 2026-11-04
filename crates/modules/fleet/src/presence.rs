// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P4 — cross-org realtime device presence (`device:presence` WS events).
//!
//! Before this module, agent presence was READ-derived only: the listing
//! route computed online/stale/offline on each poll, so a user parked on
//! another org (or between polls) never learned a device changed state.
//! This module makes transitions PUSH events with three producers:
//!
//!   * agent WS register  → `online`  (ws::remote_control)
//!   * agent WS teardown  → `offline` (tx-gated + foreign-claim-suppressed —
//!     a re-homed agent's late teardown on the old pod must stay silent)
//!   * the cluster-singleton staleness sweep → `stale` / `offline` for the
//!     transitions that have NO socket moment (half-open legs, dead pods)
//!
//! Exactly-once across pods comes from the `agents.last_presence` ledger:
//! every producer runs a Mongo CAS (`set_presence_if_changed`) and only the
//! writer that actually moved the field fans out. Per-tenant batching
//! (`rc.presence_batch_ms`, default 2 s) turns a fleet-wide reconnect storm
//! into one event per tenant. Recipients are the tenant's members — the
//! same audience the device listing is visible to.
//!
//! Wire shape (additive, `{type, data}` envelope like every chat event):
//!
//! ```json
//! { "type": "device:presence",
//!   "data": { "tenant_id": "<hex>",
//!             "agents": [ { "agent_id": "<hex>", "name": "…",
//!                           "presence": "online"|"stale"|"offline" } ] } }
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use dashmap::DashMap;

use crate::FleetState;

pub const ONLINE: &str = "online";
pub const STALE: &str = "stale";
pub const OFFLINE: &str = "offline";

/// Heartbeat-freshness window separating `stale` from `offline` — the same
/// 3×-heartbeat headroom `to_agent_response` and the Redis directory TTL use.
const STALE_AFTER_MS: i64 = 90_000;

/// Member-list cache TTL. Presence bursts (pod roll = the whole fleet
/// reconnecting) must not become a per-event `tenant_members` scan; 30 s of
/// staleness on the recipient set is invisible next to the batch window.
const MEMBERS_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct PresenceUpdate {
    pub agent_id: ObjectId,
    pub name: String,
    pub presence: &'static str,
}

/// FleetState-held fan-out state: per-tenant pending batches + the member-list
/// cache. One instance per pod.
#[derive(Default)]
pub struct PresenceFanout {
    pending: DashMap<ObjectId, Vec<PresenceUpdate>>,
    members: DashMap<ObjectId, (Instant, Arc<Vec<ObjectId>>)>,
}

/// Record a presence transition and (if this caller won the ledger CAS)
/// queue it for the batched fan-out. Returns whether the transition was
/// actually queued — the sweeper uses this to gate its status-heal write.
///
/// Fail-soft: a Mongo error here loses one badge event, never a session.
pub async fn note_transition(
    state: &FleetState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    name: &str,
    presence: &'static str,
) -> bool {
    match state
        .agents
        .set_presence_if_changed(agent_id, presence)
        .await
    {
        Ok(true) => {}
        Ok(false) => return false, // someone (possibly on another pod) already announced this
        Err(e) => {
            tracing::debug!(%agent_id, %presence, %e, "presence ledger CAS failed; skipping event");
            return false;
        }
    }

    // Stats PR-1: the transition ledger behind the uptime strips. Appended
    // HERE (after the CAS win) rather than at the call sites so the
    // sweeper's stale/offline heals are captured too, and exactly-once
    // across pods comes free from the CAS. Fail-soft like the fan-out.
    if state.settings.stats.enabled
        && let Err(e) = state
            .stats
            .append_presence_event(tenant_id, agent_id, presence)
            .await
    {
        tracing::debug!(%agent_id, %presence, %e, "presence event persist failed");
    }

    let update = PresenceUpdate {
        agent_id,
        name: name.to_string(),
        presence,
    };
    let spawn_flusher = {
        let mut entry = state.presence_fanout.pending.entry(tenant_id).or_default();
        let was_empty = entry.is_empty();
        entry.push(update);
        was_empty
    };
    if spawn_flusher {
        let state = state.clone();
        let delay = Duration::from_millis(state.settings.rc.presence_batch_ms.max(1));
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            flush_tenant(&state, tenant_id).await;
        });
    }
    true
}

/// Drain one tenant's pending batch and broadcast it to the tenant's
/// members (cross-pod via the Redis fan-out — recipients' sockets may live
/// anywhere, and multi-org users are usually affine to a DIFFERENT tenant).
async fn flush_tenant(state: &FleetState, tenant_id: ObjectId) {
    let Some((_, updates)) = state.presence_fanout.pending.remove(&tenant_id) else {
        return;
    };
    if updates.is_empty() {
        return;
    }

    let latest = coalesce(updates);

    let members = match member_ids_cached(state, tenant_id).await {
        Some(m) if !m.is_empty() => m,
        _ => return,
    };

    let agents: Vec<serde_json::Value> = latest
        .iter()
        .map(|u| {
            serde_json::json!({
                "agent_id": u.agent_id.to_hex(),
                "name": u.name,
                "presence": u.presence,
            })
        })
        .collect();
    let event = serde_json::json!({
        "type": "device:presence",
        "data": {
            "tenant_id": tenant_id.to_hex(),
            "agents": agents,
        }
    });
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &members,
        &event,
    )
    .await;
}

/// Collapse one window's transitions to a single row per agent, LAST write
/// wins, first-seen order preserved.
///
/// This is the storm valve. A pod roll reconnects a whole fleet inside one
/// batch window, and an agent that flaps (`online` → `offline` → `online`
/// while its socket settles) must not ship two contradicting rows in the same
/// event — the client applies them in array order and would latch whichever
/// happened to be last in the queue, not last in TIME.
///
/// Indexed rather than a linear scan per update: the storm case is exactly
/// the one where the batch is largest (P7 scale item), and the quadratic form
/// grows with the square of the fleet.
fn coalesce(updates: Vec<PresenceUpdate>) -> Vec<PresenceUpdate> {
    let mut at: std::collections::HashMap<ObjectId, usize> =
        std::collections::HashMap::with_capacity(updates.len());
    let mut latest: Vec<PresenceUpdate> = Vec::with_capacity(updates.len());
    for u in updates {
        match at.get(&u.agent_id) {
            Some(&i) => latest[i] = u,
            None => {
                at.insert(u.agent_id, latest.len());
                latest.push(u);
            }
        }
    }
    latest
}

async fn member_ids_cached(state: &FleetState, tenant_id: ObjectId) -> Option<Arc<Vec<ObjectId>>> {
    if let Some(entry) = state.presence_fanout.members.get(&tenant_id)
        && entry.0.elapsed() < MEMBERS_CACHE_TTL
    {
        return Some(entry.1.clone());
    }
    match state.tenants.member_user_ids(tenant_id).await {
        Ok(ids) => {
            let ids = Arc::new(ids);
            state
                .presence_fanout
                .members
                .insert(tenant_id, (Instant::now(), ids.clone()));
            Some(ids)
        }
        Err(e) => {
            tracing::debug!(%tenant_id, %e, "presence member resolve failed; dropping batch");
            None
        }
    }
}

/// One staleness sweep over the scan set. Pub so integration tests can run
/// it deterministically instead of waiting out the timer. Returns how many
/// transitions were queued.
///
/// Presence derivation mirrors `to_agent_response` exactly: a locally-held
/// hub socket OR a fresh Redis directory record ⇒ online; else a fresh
/// heartbeat trail with `status: Online` ⇒ stale; else offline. With Redis
/// configured but unreachable the sweep ABORTS — an unreadable directory
/// must not demote agents that are alive on another pod. With no Redis at
/// all (single-pod deployments and most tests) the local hub IS the whole
/// truth, so the sweep proceeds on it alone.
pub async fn run_presence_sweep(state: &FleetState) -> usize {
    let rows = match state.agents.find_presence_scan_set().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::debug!(%e, "presence sweep scan failed");
            return 0;
        }
    };
    if rows.is_empty() {
        return 0;
    }

    let ids: Vec<ObjectId> = rows.iter().filter_map(|a| a.id).collect();
    let hexes: Vec<String> = ids.iter().map(|i| i.to_hex()).collect();
    let mut redis_fresh: std::collections::HashSet<ObjectId> = Default::default();
    if let Some(redis) = &state.redis_pubsub {
        match redis.agent_presence_get_many(&hexes).await {
            Ok(vals) => {
                for (id, v) in ids.iter().zip(vals) {
                    if v.is_some() {
                        redis_fresh.insert(*id);
                    }
                }
            }
            Err(e) => {
                tracing::debug!(%e, "presence sweep: directory unreadable; skipping cycle");
                return 0;
            }
        }
    }

    let now_ms = bson::DateTime::now().timestamp_millis();
    let mut queued = 0usize;
    for row in rows {
        let Some(agent_id) = row.id else { continue };
        let online = state.rc_hub.is_agent_online(agent_id) || redis_fresh.contains(&agent_id);
        let recently_seen = matches!(
            row.status,
            meshharbor_remote_control::models::AgentStatus::Online
        ) && now_ms - row.last_seen_at.timestamp_millis() < STALE_AFTER_MS;
        let computed = if online {
            ONLINE
        } else if recently_seen {
            STALE
        } else {
            OFFLINE
        };
        if row.last_presence.as_deref() == Some(computed) {
            continue;
        }
        if note_transition(state, row.tenant_id, agent_id, &row.name, computed).await {
            queued += 1;
            // Heal the green-but-dead row: a hard-killed pod leaves
            // `status: Online` behind, and only the sweep ever notices.
            if computed == OFFLINE
                && matches!(
                    row.status,
                    meshharbor_remote_control::models::AgentStatus::Online
                )
                && let Err(e) = state
                    .agents
                    .mark_status(
                        agent_id,
                        meshharbor_remote_control::models::AgentStatus::Offline,
                    )
                    .await
            {
                tracing::debug!(%agent_id, %e, "presence sweep status heal failed");
            }
        }
    }
    queued
}

/// Spawn the periodic sweep loop. Cluster-singleton per cycle via a Redis
/// NX claim keyed by DATABASE name (prod pods share a DB ⇒ one sweeper per
/// deployment; each test's UUID database gets its own isolated claim). No
/// Redis ⇒ single pod ⇒ it just runs locally every interval. The first
/// tick is a full interval out, so short-lived TestApps never race a test
/// that drives [`run_presence_sweep`] directly.
pub fn spawn_sweeper(state: FleetState) {
    let interval = Duration::from_secs(state.settings.rc.presence_sweep_secs.max(5));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Some(redis) = &state.redis_pubsub {
                let key = format!("meshharbor:presence-sweep:{}", state.db.name());
                let ttl = state
                    .settings
                    .rc
                    .presence_sweep_secs
                    .saturating_sub(5)
                    .max(5);
                match redis.try_claim(&key, ttl).await {
                    Ok(true) => {}
                    Ok(false) => continue, // another pod swept this cycle
                    Err(e) => {
                        tracing::debug!(%e, "presence sweep claim failed; skipping cycle");
                        continue;
                    }
                }
            }
            let n = run_presence_sweep(&state).await;
            if n > 0 {
                tracing::info!(transitions = n, "presence sweep announced transitions");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upd(agent: u8, presence: &'static str) -> PresenceUpdate {
        let mut raw = [0u8; 12];
        raw[11] = agent;
        PresenceUpdate {
            agent_id: ObjectId::from_bytes(raw),
            name: format!("box-{agent}"),
            presence,
        }
    }

    /// A flapping agent must contribute exactly ONE row, carrying its LAST
    /// state — the client applies the array in order, so two rows for one
    /// agent would latch whichever landed last in the queue.
    #[test]
    fn a_flapping_agent_collapses_to_its_last_state() {
        let out = coalesce(vec![
            upd(1, ONLINE),
            upd(2, ONLINE),
            upd(1, OFFLINE),
            upd(1, ONLINE),
        ]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].presence, ONLINE, "agent 1 ends online");
        assert_eq!(out[1].presence, ONLINE);
        // First-seen order is preserved, so the event reads chronologically.
        assert_eq!(out[0].agent_id, upd(1, ONLINE).agent_id);
        assert_eq!(out[1].agent_id, upd(2, ONLINE).agent_id);
    }

    /// P7 scale: a pod roll reconnects the whole fleet inside one window.
    /// The batch must collapse to one row per DEVICE, not per transition.
    #[test]
    fn a_fleet_wide_storm_collapses_to_one_row_per_device() {
        let mut storm = Vec::new();
        for round in 0..5 {
            for agent in 1..=50u8 {
                storm.push(upd(agent, if round % 2 == 0 { OFFLINE } else { ONLINE }));
            }
        }
        // 250 transitions in…
        assert_eq!(storm.len(), 250);
        let out = coalesce(storm);
        // …50 rows out, each holding the final round's state.
        assert_eq!(out.len(), 50);
        assert!(out.iter().all(|u| u.presence == OFFLINE));
        let ids: std::collections::HashSet<_> = out.iter().map(|u| u.agent_id).collect();
        assert_eq!(ids.len(), 50, "no duplicate agents survive");
    }

    #[test]
    fn coalesce_of_nothing_is_nothing() {
        assert!(coalesce(Vec::new()).is_empty());
    }
}
