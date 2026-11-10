// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-51 — ephemeral nodes: the reaper, and the one removal sequence it
//! shares with the admin DELETE.
//!
//! A device enrolled `ephemeral: true` has declared, at enrollment, that it is
//! temporary: once it has been silent past its TTL the deployment removes it —
//! device row, overlay lease, address, MagicDNS name — with no admin action.
//!
//! Three design constraints, each measured against the tree rather than
//! assumed (`docs/fr/FR-51-ephemeral-nodes.md` §3):
//!
//! * **Own query, never the presence sweep's scan set.** `run_presence_sweep`
//!   settles an absent row to `last_presence: "offline"`, after which the row
//!   matches neither branch of `find_presence_scan_set` and is never scanned
//!   again — a reaper hung off that loop would see each row exactly once, so
//!   any deadline longer than one sweep interval would silently never fire
//!   (and a test written with a short deadline would pass).
//! * **One removal sequence.** [`remove_agent_device`] is `delete_agent`
//!   minus the HTTP layer and minus the permission check; the reaper calls
//!   the same function the route does. `release_overlay_node`'s four-step
//!   order (peers-while-live → CAS-tombstone → pool → fan `removes`) is
//!   load-bearing, and a second, subtly different teardown path is the main
//!   way this feature could do harm.
//! * **Hard delete.** The `(tenant_id, machine_id)` unique index is not
//!   partial on `deleted_at`, so a tombstoned ephemeral row would reserve its
//!   random, never-reused machine_id forever. The DAO's
//!   `hard_delete_ephemeral` filters on `ephemeral: true`, so a permanent row
//!   structurally cannot take this path.
//!
//! Kill switch: `rc.ephemeral_reaper_enabled`, default **false** — zero
//! queries, zero deletes. Even enabled, the predicate (`ephemeral: true`)
//! cannot match any pre-FR-51 row: they all deserialise permanent.

use bson::oid::ObjectId;
use meshharbor_remote_control::models::Agent;
use meshharbor_services::dao::base::DaoResult;
use std::time::Duration;

use crate::NetworkState;

/// Floor on every effective TTL, applied at READ time so a bad stored value
/// can never disable it. Below this, an ordinary network blip or a pod roll
/// (the fleet reconnect takes seconds, the heartbeat cadence is 30 s) would
/// read as "the device left" and delete it.
pub const MIN_TTL_SECS: u64 = 60;

/// The inactivity deadline this row is actually held to: the per-device
/// override from its enrollment key, else the server default — both clamped
/// to the floor.
fn effective_ttl_secs(agent: &Agent, state: &NetworkState) -> u64 {
    agent
        .ephemeral_ttl_secs
        .unwrap_or(state.settings.rc.ephemeral_default_ttl_secs)
        .max(MIN_TTL_SECS)
}

/// The ONE device-removal sequence behind the admin delete, the ephemeral
/// self-unenroll and the reaper (FR-51 F3) — the fleet module's since FR-69
/// P5a (`meshharbor_mod_fleet::removal`), where the overlay release runs
/// through the core hooks. The reaper reaches it through this wrapper.
pub async fn remove_agent_device(
    state: &NetworkState,
    agent: &Agent,
    reason: &str,
) -> DaoResult<Option<meshharbor_core::hooks::ReleasedLease>> {
    meshharbor_mod_fleet::removal::remove_agent_device(&state.fleet, agent, reason).await
}

/// One reap cycle. Pub so integration tests can drive it deterministically
/// instead of waiting out the timer (the `run_presence_sweep` pattern).
/// Returns how many devices were removed.
///
/// Presence guards mirror the sweep's, because the hazard is the same: a
/// device whose heartbeat writes are failing while its socket is alive must
/// not be judged absent. A row is skipped when the local hub holds its
/// socket OR the Redis directory says another pod does — and with Redis
/// configured but unreachable the cycle ABORTS, since an unreadable
/// directory must not let this pod reap agents that are alive elsewhere.
pub async fn run_ephemeral_reap(state: &NetworkState) -> usize {
    let rows = match state
        .fleet
        .agents
        .find_ephemeral_reap_candidates(MIN_TTL_SECS as i64 * 1000)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::debug!(%e, "ephemeral reap: candidate scan failed");
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
                tracing::debug!(%e, "ephemeral reap: directory unreadable; skipping cycle");
                return 0;
            }
        }
    }

    let now_ms = bson::DateTime::now().timestamp_millis();
    let mut reaped = 0usize;
    for row in rows {
        let Some(agent_id) = row.id else { continue };
        if state.fleet.rc_hub.is_agent_online(agent_id) || redis_fresh.contains(&agent_id) {
            continue; // live somewhere — its heartbeat trail is the stale thing, not it
        }
        let ttl_ms = effective_ttl_secs(&row, state) as i64 * 1000;
        let silent_ms = now_ms - row.last_seen_at.timestamp_millis();
        if silent_ms < ttl_ms {
            continue; // candidate by the floor, but this row's own deadline is longer
        }
        match remove_agent_device(state, &row, "ephemeral_expired").await {
            Ok(released) => {
                reaped += 1;
                // The operator never clicked anything, so the log line is the
                // record that this removal happened and why (the P4 surface
                // adds it to `audit_logs`).
                tracing::info!(
                    tenant_id = %row.tenant_id, agent_id = %agent_id, name = %row.name,
                    silent_secs = silent_ms / 1000, ttl_secs = ttl_ms / 1000,
                    overlay_ip = released.as_ref().map(|r| r.overlay_ip.as_str()).unwrap_or(""),
                    "ephemeral device reaped"
                );
            }
            Err(e) => {
                tracing::warn!(%agent_id, %e, "ephemeral reap: removal failed; will retry next cycle");
            }
        }
    }
    reaped
}

/// Spawn the periodic reap loop — cluster-singleton per cycle via the same
/// DB-name-scoped Redis NX claim the presence sweep uses (prod pods share a
/// DB ⇒ one reaper per deployment; each test's UUID database gets its own
/// isolated claim; no Redis ⇒ single pod ⇒ run locally). The first tick is a
/// full interval out so short-lived TestApps never race a test driving
/// [`run_ephemeral_reap`] directly.
///
/// No-op (nothing spawned) unless `rc.ephemeral_reaper_enabled` — the FR-51
/// P1 kill switch: default off means zero queries and zero deletes.
pub fn spawn_reaper(state: NetworkState) {
    if !state.settings.rc.ephemeral_reaper_enabled {
        return;
    }
    let interval = Duration::from_secs(state.settings.rc.ephemeral_reap_interval_secs.max(5));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Some(redis) = &state.redis_pubsub {
                let key = format!("meshharbor:ephemeral-reap:{}", state.db.name());
                let ttl = state
                    .settings
                    .rc
                    .ephemeral_reap_interval_secs
                    .saturating_sub(5)
                    .max(5);
                match redis.try_claim(&key, ttl).await {
                    Ok(true) => {}
                    Ok(false) => continue, // another pod reaped this cycle
                    Err(e) => {
                        tracing::debug!(%e, "ephemeral reap claim failed; skipping cycle");
                        continue;
                    }
                }
            }
            let n = run_ephemeral_reap(&state).await;
            if n > 0 {
                tracing::info!(reaped = n, "ephemeral reap cycle removed devices");
            }
        }
    });
}
