// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Stats PR-3 — observability query APIs.
//!
//! Two families:
//!
//! - `/api/admin/stats/*` — platform-operator dashboards (relay fleet,
//!   cross-org). Gated by the `platform_admins` ObjectId allowlist and
//!   answering **404** (never 403) on missing authority: the allowlist is
//!   itself the thing being hidden, and a hidden surface beats an
//!   acknowledged one.
//! - `/api/tenant/{tid}/stats/*` — org dashboards. `overview` is
//!   member-visible (powers the dashboard Insights panel); the queryable
//!   series (`machines`/`calls`/`tunnels`) require `MANAGE_AGENTS` (the
//!   fleet bit seeded Admin roles hold) — permission failures are also
//!   404, so a polled panel degrades to empty instead of erroring on
//!   every tick.
//!
//! ⚠️ Both 404s were once justified as "the web client force-logs-out on any
//! 403". It does not any more (FR-82) — a 403 is an answer, not an expired
//! credential. The 404s stay; their real reasons are the ones above.
//!
//! Series contract: every pipeline projects `t` (unix SECONDS) plus plain
//! numbers/strings only — no BSON dates or ObjectIds leak into the JSON
//! (bson's serde would render them as `{"$date":…}`/`{"$oid":…}`).
//! Range → source tier: `24h` = raw grouped to 5 min, `7d`/`30d` = `_1h`,
//! `1y` = `_1d`.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use serde::Deserialize;
use std::collections::HashMap;

use crate::{core_state::Core, error::ApiError, extractors::auth::AuthUser};

// ── Guards ──────────────────────────────────────────────────────────────
//
// FR-69 P2 — the platform-admin and tenant-stats gates moved into
// `meshharbor_core::guards` (the `saas` module gates its admin surface on the
// first one, and a module cannot reach into this crate). Re-exported so the
// `super::stats::require_platform_admin` paths in this crate read as before.
pub(crate) use meshharbor_core::guards::{parse_tid, require_platform_admin, require_tenant_stats};

// ── Range plumbing ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RangeQuery {
    #[serde(default)]
    pub range: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// (window secs, tier). Tier picks the source collection suffix.
pub(crate) fn range_spec(range: Option<&str>) -> Result<(i64, Tier), ApiError> {
    match range.unwrap_or("24h") {
        "24h" => Ok((86_400, Tier::Raw)),
        "7d" => Ok((7 * 86_400, Tier::Hour)),
        "30d" => Ok((30 * 86_400, Tier::Hour)),
        "1y" => Ok((365 * 86_400, Tier::Day)),
        other => Err(ApiError::BadRequest(format!(
            "invalid range '{other}' (24h|7d|30d|1y)"
        ))),
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Tier {
    Raw,
    Hour,
    Day,
}

pub(crate) fn floor_dt(window_secs: i64) -> DateTime {
    DateTime::from_millis(DateTime::now().timestamp_millis() - window_secs * 1000)
}

/// Group key for the raw tier: 5-minute bins; rollup tiers are already
/// bucketed, group by their own ts.
fn bucket_expr(tier: Tier) -> Document {
    match tier {
        Tier::Raw => doc! { "$dateTrunc": { "date": "$ts", "unit": "minute", "binSize": 5 } },
        Tier::Hour | Tier::Day => doc! { "$dateTrunc": { "date": "$ts", "unit": "hour" } },
    }
}

/// `_id` (a date) → `t` unix seconds.
pub(crate) fn t_secs() -> Document {
    doc! { "$toLong": { "$divide": [ { "$toLong": "$_id" }, 1000 ] } }
}

pub(crate) async fn agg(
    state: &Core,
    coll: &str,
    pipeline: Vec<Document>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let mut cur = state
        .db
        .collection::<Document>(coll)
        .aggregate(pipeline)
        .await
        .map_err(|e| ApiError::Internal(format!("stats query failed: {e}")))?;
    let mut out = Vec::new();
    while let Some(d) = cur
        .try_next()
        .await
        .map_err(|e| ApiError::Internal(format!("stats cursor failed: {e}")))?
    {
        out.push(serde_json::to_value(&d).unwrap_or(serde_json::Value::Null));
    }
    Ok(out)
}

pub(crate) fn disabled_payload() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}

// ── Series pipelines ────────────────────────────────────────────────────

fn machine_series_pipeline(tenant: ObjectId, floor: DateTime, tier: Tier) -> Vec<Document> {
    let group = match tier {
        Tier::Raw => doc! {
            "_id": bucket_expr(tier),
            "online_set": { "$addToSet": "$agent_id" },
            "active_sessions": { "$avg": "$active_sessions" },
            "cpu_pct": { "$avg": "$sys.cpu_pct" },
            "rss_mb": { "$avg": "$sys.rss_mb" },
            "peer_rtt_ms": { "$avg": "$sys.peer_rtt_ms" },
            "direct": { "$avg": "$sys.transports.direct" },
            "relay": { "$avg": "$sys.transports.relay" },
            "derp": { "$avg": "$sys.transports.derp" },
            "tunnel_flows": { "$avg": "$sys.tunnel_flows" },
            "rc_sessions": { "$avg": "$sys.rc_sessions" },
        },
        _ => doc! {
            "_id": "$ts",
            "online": { "$sum": { "$cond": [ { "$gt": [ "$online_minutes", 0 ] }, 1, 0 ] } },
            "online_minutes": { "$sum": "$online_minutes" },
            "active_sessions": { "$avg": "$active_sessions_max" },
            "cpu_pct": { "$avg": "$cpu_pct" },
            "rss_mb": { "$avg": "$rss_mb" },
            "peer_rtt_ms": { "$avg": "$peer_rtt_ms" },
            "direct": { "$avg": "$direct" },
            "relay": { "$avg": "$relay" },
            "derp": { "$avg": "$derp" },
            "tunnel_flows": { "$avg": "$tunnel_flows" },
            "rc_sessions": { "$avg": "$rc_sessions" },
        },
    };
    let mut set = doc! { "t": t_secs() };
    if tier == Tier::Raw {
        set.insert("online", doc! { "$size": "$online_set" });
    }
    vec![
        doc! { "$match": { "tenant_id": tenant, "ts": { "$gte": floor } } },
        doc! { "$group": group },
        doc! { "$set": set },
        doc! { "$unset": [ "_id", "online_set" ] },
        doc! { "$sort": { "t": 1 } },
    ]
}

/// Wave 3 — overlay + tunnel BYTES moved per bucket.
///
/// Its own pipeline rather than more columns on `machine_series_pipeline`,
/// because volume needs a different shape: the agent reports cumulative
/// counters, so the per-bucket delta is `max - min` **per agent** before
/// anything is summed across the fleet. Folding that into the existing
/// single-stage group would have changed how the shipped cpu/rss averages
/// are weighted, which is not a change worth making by accident.
///
/// A carrier rebuild (or an agent restart) resets its counters mid-bucket,
/// so that bucket under-reports rather than going negative — the same
/// trade the host-total `net_*_bytes` columns already make.
fn machine_volume_pipeline(tenant: Option<ObjectId>, floor: DateTime, tier: Tier) -> Vec<Document> {
    let mut match_doc = doc! { "ts": { "$gte": floor } };
    if let Some(t) = tenant {
        match_doc.insert("tenant_id", t);
    }
    // Only rows that actually CARRY the counter. Without this, a fleet with
    // no reporting agent yields a full set of buckets whose `$ifNull` deltas
    // are all zero — and a flat zero line reads as "no traffic" when the
    // truth is "nobody is measuring yet". No rows ⇒ empty series ⇒ the chart
    // says so. Once agents report, a genuinely idle bucket still shows 0.
    let counter_field = if tier == Tier::Raw {
        "sys.overlay_rx_bytes"
    } else {
        "overlay_rx_bytes_max"
    };
    match_doc.insert(counter_field, doc! { "$exists": true });
    let delta = |max: &str, min: &str| {
        doc! { "$max": [ 0, { "$subtract": [
            { "$ifNull": [ format!("${max}"), 0 ] },
            { "$ifNull": [ format!("${min}"), 0 ] },
        ]}]}
    };
    // Raw samples hold the counter itself; rollup rows already hold the
    // per-agent min/max for their bucket.
    let per_agent = if tier == Tier::Raw {
        doc! { "$group": {
            "_id": { "a": "$agent_id", "b": bucket_expr(tier) },
            "orx_max": { "$max": "$sys.overlay_rx_bytes" },
            "orx_min": { "$min": "$sys.overlay_rx_bytes" },
            "otx_max": { "$max": "$sys.overlay_tx_bytes" },
            "otx_min": { "$min": "$sys.overlay_tx_bytes" },
            "trx_max": { "$max": "$sys.tunnel_rx_bytes" },
            "trx_min": { "$min": "$sys.tunnel_rx_bytes" },
            "ttx_max": { "$max": "$sys.tunnel_tx_bytes" },
            "ttx_min": { "$min": "$sys.tunnel_tx_bytes" },
        }}
    } else {
        doc! { "$group": {
            "_id": { "a": "$agent_id", "b": "$ts" },
            "orx_max": { "$max": "$overlay_rx_bytes_max" },
            "orx_min": { "$min": "$overlay_rx_bytes_min" },
            "otx_max": { "$max": "$overlay_tx_bytes_max" },
            "otx_min": { "$min": "$overlay_tx_bytes_min" },
            "trx_max": { "$max": "$tunnel_rx_bytes_max" },
            "trx_min": { "$min": "$tunnel_rx_bytes_min" },
            "ttx_max": { "$max": "$tunnel_tx_bytes_max" },
            "ttx_min": { "$min": "$tunnel_tx_bytes_min" },
        }}
    };
    vec![
        doc! { "$match": match_doc },
        per_agent,
        doc! { "$group": {
            "_id": "$_id.b",
            "overlay_rx": { "$sum": delta("orx_max", "orx_min") },
            "overlay_tx": { "$sum": delta("otx_max", "otx_min") },
            "tunnel_rx": { "$sum": delta("trx_max", "trx_min") },
            "tunnel_tx": { "$sum": delta("ttx_max", "ttx_min") },
        }},
        doc! { "$set": { "t": t_secs() } },
        doc! { "$unset": "_id" },
        doc! { "$sort": { "t": 1 } },
    ]
}

fn call_series_pipeline(tenant: Option<ObjectId>, floor: DateTime, tier: Tier) -> Vec<Document> {
    let mut match_doc = doc! { "ts": { "$gte": floor } };
    if let Some(t) = tenant {
        match_doc.insert("tenant_id", t);
    }
    let group = match tier {
        Tier::Raw => doc! {
            "_id": bucket_expr(tier),
            "participant_seconds": { "$sum": { "$multiply": [ "$participants", 30 ] } },
            "relayed_seconds": { "$sum": { "$multiply": [ "$relayed", 30 ] } },
            "direct_seconds": { "$sum": { "$multiply": [ "$direct", 30 ] } },
            "call_seconds": { "$sum": 30 },
            "peak_participants": { "$max": "$participants" },
            "send_bps": { "$avg": "$send_bps" },
            "recv_bps": { "$avg": "$recv_bps" },
            "loss_pct": { "$avg": "$loss_pct" },
            "rooms": { "$addToSet": "$room_id" },
        },
        _ => doc! {
            "_id": "$ts",
            "participant_seconds": { "$sum": "$participant_seconds" },
            "relayed_seconds": { "$sum": "$relayed_seconds" },
            "direct_seconds": { "$sum": "$direct_seconds" },
            "call_seconds": { "$sum": "$call_seconds" },
            "peak_participants": { "$max": "$peak_participants" },
            "send_bps": { "$avg": "$send_bps" },
            "recv_bps": { "$avg": "$recv_bps" },
            "loss_pct": { "$avg": "$loss_pct" },
        },
    };
    let mut set = doc! { "t": t_secs() };
    if tier == Tier::Raw {
        set.insert("distinct_rooms", doc! { "$size": "$rooms" });
    }
    vec![
        doc! { "$match": match_doc },
        doc! { "$group": group },
        doc! { "$set": set },
        doc! { "$unset": [ "_id", "rooms" ] },
        doc! { "$sort": { "t": 1 } },
    ]
}

fn relay_series_pipeline(region: &str, floor: DateTime, tier: Tier) -> Vec<Document> {
    let group = match tier {
        Tier::Raw => doc! {
            "_id": bucket_expr(tier),
            "sample_count": { "$sum": 1 },
            "healthy_count": { "$sum": { "$cond": [ "$healthy", 1, 0 ] } },
            "poll_rtt_ms": { "$avg": "$poll_rtt_ms" },
            "load1": { "$avg": "$load1" },
            "cpus": { "$max": "$cpus" },
            "mem_available_pct": { "$avg": { "$cond": [
                { "$gt": [ "$mem_total_kb", 0 ] },
                { "$divide": [ "$mem_available_kb", "$mem_total_kb" ] },
                Bson::Null,
            ] } },
            "rx_mbps": { "$avg": "$rx_mbps" },
            "tx_mbps": { "$avg": "$tx_mbps" },
            "tx_mbps_max": { "$max": "$tx_mbps" },
            "allocations": { "$avg": "$allocations" },
            "coturn_sessions": { "$avg": "$coturn_sessions" },
            "derp_registrations": { "$avg": "$derp_registrations" },
        },
        _ => doc! {
            "_id": "$ts",
            "sample_count": { "$sum": "$sample_count" },
            "healthy_count": { "$sum": "$healthy_count" },
            "poll_rtt_ms": { "$avg": "$poll_rtt_ms" },
            "load1": { "$avg": "$load1" },
            "cpus": { "$max": "$cpus" },
            "mem_available_pct": { "$avg": "$mem_available_pct" },
            "rx_mbps": { "$avg": "$rx_mbps" },
            "tx_mbps": { "$avg": "$tx_mbps" },
            "tx_mbps_max": { "$max": "$tx_mbps_max" },
            "allocations": { "$avg": "$allocations" },
            "coturn_sessions": { "$avg": "$coturn_sessions" },
            "derp_registrations": { "$avg": "$derp_registrations" },
        },
    };
    vec![
        doc! { "$match": { "region": region, "ts": { "$gte": floor } } },
        doc! { "$group": group },
        doc! { "$set": {
            "t": t_secs(),
            "healthy_pct": { "$cond": [
                { "$gt": [ "$sample_count", 0 ] },
                { "$multiply": [ { "$divide": [ "$healthy_count", "$sample_count" ] }, 100.0 ] },
                Bson::Null,
            ] },
        }},
        doc! { "$unset": "_id" },
        doc! { "$sort": { "t": 1 } },
    ]
}

/// Suffix for the tier's source collection.
pub(crate) fn tier_coll(base: &str, tier: Tier) -> String {
    match tier {
        Tier::Raw => base.to_string(),
        Tier::Hour => format!("{base}_1h"),
        Tier::Day => format!("{base}_1d"),
    }
}

/// FR-93 P2b (AC13) — devices by desktop type and the capture arm that would
/// serve them, from each device's own `capabilities.desktop` (its hello and
/// heartbeat). A device that never sent one (Windows, macOS, an agent older
/// than P2b) is not counted, so this is what the fleet SAYS. `machines.total`
/// beside it says how many devices there are. `extra` narrows the match (a
/// tenant), and the rest of the match is fixed.
pub(crate) fn desktop_breakdown_pipeline(extra: Document) -> Vec<Document> {
    let mut filter = extra;
    filter.insert("deleted_at", Bson::Null);
    filter.insert("capabilities.desktop", doc! { "$type": "object" });
    vec![
        doc! { "$match": filter },
        doc! { "$group": {
            "_id": {
                "type": "$capabilities.desktop.type",
                "capture_arm": "$capabilities.desktop.capture_arm",
            },
            "total": { "$sum": 1 },
            "online": { "$sum": { "$cond": [ { "$eq": [ "$last_presence", "online" ] }, 1, 0 ] } },
        }},
        doc! { "$project": {
            "_id": 0,
            "type": "$_id.type",
            "capture_arm": "$_id.capture_arm",
            "total": 1,
            "online": 1,
        }},
        doc! { "$sort": { "type": 1, "capture_arm": 1 } },
    ]
}

// ── Tenant endpoints ────────────────────────────────────────────────────

/// GET /api/tenant/{tid}/stats/overview — ANY member. Powers the org
/// dashboard Insights panel: current counts + two small sparklines.
pub async fn tenant_overview(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    require_tenant_stats(&state, tid, auth.user_id, false).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }

    let machines_total = state
        .db
        .collection::<Document>("agents")
        .count_documents(doc! { "tenant_id": tid, "deleted_at": Bson::Null })
        .await
        .unwrap_or(0);
    let machines_online = state
        .db
        .collection::<Document>("agents")
        .count_documents(
            doc! { "tenant_id": tid, "deleted_at": Bson::Null, "last_presence": "online" },
        )
        .await
        .unwrap_or(0);
    let calls_active = state
        .db
        .collection::<Document>("rooms")
        .count_documents(doc! { "tenant_id": tid, "conference_status": "in_progress" })
        .await
        .unwrap_or(0);

    // Minutes today + 7d daily sparkline from call_sessions (live calls
    // count up to now).
    let day_floor = floor_dt(7 * 86_400);
    let today_floor = {
        let now = DateTime::now().timestamp_millis() / 1000;
        DateTime::from_millis((now - now.rem_euclid(86_400)) * 1000)
    };
    let minutes_rows = agg(
        &state,
        "call_sessions",
        vec![
            doc! { "$match": { "tenant_id": tid, "started_at": { "$gte": day_floor } } },
            doc! { "$set": {
                "end_eff": { "$ifNull": [ "$ended_at", "$$NOW" ] },
            }},
            doc! { "$group": {
                "_id": { "$dateTrunc": { "date": "$started_at", "unit": "day" } },
                "minutes": { "$sum": { "$divide": [
                    { "$subtract": [ "$end_eff", "$started_at" ] },
                    60_000,
                ] } },
                "calls": { "$sum": 1 },
            }},
            doc! { "$set": { "t": t_secs() } },
            doc! { "$unset": "_id" },
            doc! { "$sort": { "t": 1 } },
        ],
    )
    .await?;
    let minutes_today = agg(
        &state,
        "call_sessions",
        vec![
            doc! { "$match": { "tenant_id": tid, "started_at": { "$gte": today_floor } } },
            doc! { "$set": { "end_eff": { "$ifNull": [ "$ended_at", "$$NOW" ] } } },
            doc! { "$group": {
                "_id": Bson::Null,
                "minutes": { "$sum": { "$divide": [
                    { "$subtract": [ "$end_eff", "$started_at" ] },
                    60_000,
                ] } },
            }},
            doc! { "$unset": "_id" },
        ],
    )
    .await?
    .first()
    .and_then(|v| v.get("minutes").and_then(|m| m.as_f64()))
    .unwrap_or(0.0);

    // 24 h machines-online sparkline from the hourly rollup.
    let spark_machines = agg(
        &state,
        "stats_machine_1h",
        machine_series_pipeline(tid, floor_dt(86_400), Tier::Hour),
    )
    .await?;
    // FR-93 P2b — the org's Linux desktops and the arm serving each.
    let desktops = agg(
        &state,
        "agents",
        desktop_breakdown_pipeline(doc! { "tenant_id": tid }),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "machines": { "online": machines_online, "total": machines_total },
        "calls": { "active": calls_active, "minutes_today": minutes_today },
        "spark_machines": spark_machines,
        "spark_minutes": minutes_rows,
        "desktops": desktops,
    })))
}

/// GET /api/tenant/{tid}/stats/machines?range= — MANAGE_AGENTS.
pub async fn tenant_machines(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    require_tenant_stats(&state, tid, auth.user_id, true).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    machines_payload(&state, tid, q.range.as_deref()).await
}

async fn machines_payload(
    state: &Core,
    tid: ObjectId,
    range: Option<&str>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (window, tier) = range_spec(range)?;
    let floor = floor_dt(window);
    let series = agg(
        state,
        &tier_coll("stats_machine", tier),
        machine_series_pipeline(tid, floor, tier),
    )
    .await?;
    // Per-agent totals over the window (names resolve client-side from
    // the agents store the UI already holds).
    let per_agent = agg(
        state,
        &tier_coll("stats_machine", tier),
        vec![
            doc! { "$match": { "tenant_id": tid, "ts": { "$gte": floor } } },
            doc! { "$group": {
                "_id": "$agent_id",
                "online_minutes": { "$sum": if tier == Tier::Raw {
                    doc! { "$cond": [ "$online", 1, 0 ] }.into()
                } else {
                    Bson::String("$online_minutes".to_string())
                } },
                "cpu_pct": { "$avg": if tier == Tier::Raw { "$sys.cpu_pct" } else { "$cpu_pct" } },
                "peer_rtt_ms": { "$avg": if tier == Tier::Raw { "$sys.peer_rtt_ms" } else { "$peer_rtt_ms" } },
            }},
            doc! { "$set": { "agent_id": { "$toString": "$_id" } } },
            doc! { "$unset": "_id" },
            doc! { "$sort": { "online_minutes": -1 } },
            doc! { "$limit": 100 },
        ],
    )
    .await?;
    let uptime = uptime_intervals(state, tid, floor).await?;
    let volume = agg(
        state,
        &tier_coll("stats_machine", tier),
        machine_volume_pipeline(Some(tid), floor, tier),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "enabled": true,
        "range": range.unwrap_or("24h"),
        "series": series,
        "agents": per_agent,
        "uptime": uptime,
        // Wave 3 — mesh + tunnel bytes moved. Empty until the fleet ships
        // the reporting agent; an empty series reads as "no data", which is
        // the truth, where a zero line would read as "no traffic".
        "volume": volume,
    })))
}

/// Cap on agents/intervals returned by the uptime view — a fleet-wide
/// year query must not turn into an unbounded payload.
const UPTIME_MAX_AGENTS: usize = 100;
const UPTIME_MAX_INTERVALS: usize = 500;

/// Per-agent presence intervals over the window, reconstructed from the
/// `stats_events` transition ledger.
///
/// The ledger records CHANGES, so three pieces are needed to render a
/// continuous strip: the state the agent was already in when the window
/// opened (its last transition BEFORE the floor), the transitions inside
/// the window, and the live tail (`agents.last_presence`) closing the
/// final interval at "now". An agent with no prior transition starts as
/// `unknown` — honest about "we weren't recording yet" rather than
/// back-filling a state we never observed.
async fn uptime_intervals(
    state: &Core,
    tid: ObjectId,
    floor: DateTime,
) -> Result<Vec<serde_json::Value>, ApiError> {
    // Live tail + display names, and the agent set we report on.
    let agents = agg(
        state,
        "agents",
        vec![
            doc! { "$match": { "tenant_id": tid, "deleted_at": Bson::Null } },
            doc! { "$set": { "id": { "$toString": "$_id" } } },
            doc! { "$project": { "_id": 0, "id": 1, "name": 1, "display_name": 1, "last_presence": 1 } },
            doc! { "$limit": UPTIME_MAX_AGENTS as i64 },
        ],
    )
    .await?;
    if agents.is_empty() {
        return Ok(Vec::new());
    }

    // State at window open: the newest transition strictly before floor.
    let mut prior: HashMap<String, String> = HashMap::new();
    for d in agg(
        state,
        meshharbor_services::dao::stats::STATS_EVENTS,
        vec![
            doc! { "$match": { "tenant_id": tid, "ts": { "$lt": floor } } },
            doc! { "$sort": { "ts": -1 } },
            doc! { "$group": { "_id": "$agent_id", "presence": { "$first": "$presence" } } },
            doc! { "$set": { "agent_id": { "$toString": "$_id" } } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?
    {
        if let (Some(a), Some(p)) = (
            d.get("agent_id").and_then(|v| v.as_str()),
            d.get("presence").and_then(|v| v.as_str()),
        ) {
            prior.insert(a.to_string(), p.to_string());
        }
    }

    // Transitions inside the window, oldest first per agent.
    let mut events: HashMap<String, Vec<(i64, String)>> = HashMap::new();
    for d in agg(
        state,
        meshharbor_services::dao::stats::STATS_EVENTS,
        vec![
            doc! { "$match": { "tenant_id": tid, "ts": { "$gte": floor } } },
            doc! { "$sort": { "ts": 1 } },
            doc! { "$set": {
                "agent_id": { "$toString": "$agent_id" },
                "t": { "$toLong": { "$divide": [ { "$toLong": "$ts" }, 1000 ] } },
            }},
            doc! { "$project": { "_id": 0, "agent_id": 1, "t": 1, "presence": 1 } },
        ],
    )
    .await?
    {
        if let (Some(a), Some(t), Some(p)) = (
            d.get("agent_id").and_then(|v| v.as_str()),
            d.get("t").and_then(|v| v.as_i64()),
            d.get("presence").and_then(|v| v.as_str()),
        ) {
            events
                .entry(a.to_string())
                .or_default()
                .push((t, p.to_string()));
        }
    }

    // When the ledger itself starts. Before this instant we recorded
    // nothing, so no agent's state can be claimed for that stretch — it
    // renders `unknown` rather than back-filling today's state across
    // history that predates the feature. AFTER it, silence is real
    // information: `note_transition` records every change, so an agent
    // with no events simply never changed state.
    let ledger_start = agg(
        state,
        meshharbor_services::dao::stats::STATS_EVENTS,
        vec![
            doc! { "$match": { "tenant_id": tid } },
            doc! { "$group": { "_id": Bson::Null, "first": { "$min": "$ts" } } },
            doc! { "$set": { "t": { "$toLong": { "$divide": [ { "$toLong": "$first" }, 1000 ] } } } },
            doc! { "$project": { "_id": 0, "t": 1 } },
        ],
    )
    .await?
    .first()
    .and_then(|d| d.get("t").and_then(|v| v.as_i64()));

    let from = floor.timestamp_millis() / 1000;
    let now = DateTime::now().timestamp_millis() / 1000;
    let mut out = Vec::with_capacity(agents.len());
    for a in &agents {
        let Some(id) = a.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let has_prior = prior.contains_key(id);
        let mut cursor = from;
        let mut state_now = prior
            .get(id)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let mut intervals: Vec<serde_json::Value> = Vec::new();
        // No transition before the window ⇒ the state at window-open is
        // only knowable from when the ledger began recording.
        if !has_prior
            && let Some(start) = ledger_start
            && start > from
        {
            let start = start.min(now);
            intervals.push(serde_json::json!({
                "from": from, "to": start, "presence": "unknown",
            }));
            cursor = start;
        }
        for (t, presence) in events.get(id).map(Vec::as_slice).unwrap_or(&[]) {
            let t = (*t).clamp(from, now);
            if t > cursor {
                intervals.push(serde_json::json!({
                    "from": cursor, "to": t, "presence": state_now,
                }));
                cursor = t;
            }
            state_now = presence.clone();
            if intervals.len() >= UPTIME_MAX_INTERVALS {
                break;
            }
        }
        // Live tail: the ledger's last word is authoritative for history,
        // but the CURRENT state comes from the agents row (the sweeper
        // heals stale/offline there even when no event was queued).
        let tail = a
            .get("last_presence")
            .and_then(|v| v.as_str())
            .unwrap_or(&state_now)
            .to_string();
        if now > cursor {
            intervals.push(serde_json::json!({
                "from": cursor, "to": now, "presence": tail,
            }));
        }
        out.push(serde_json::json!({
            "agent_id": id,
            "name": a.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            // FR-116 D4 — additive: the admin's friendly name, null when the
            // device has none. `name` stays the machine's name for every
            // reader that already parses it; the web shows this first (the
            // `HeartbeatBefore::label` rule), as the device list does.
            "display_name": a
                .get("display_name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty()),
            "intervals": intervals,
        }));
    }
    Ok(out)
}

/// Carrier ranking for the pessimistic edge merge: when the two ends
/// disagree about how they reach each other, the WORSE opinion wins.
/// One end believing it has a direct carrier while the other is still
/// relaying means the pair is, in practice, relaying.
fn carrier_rank(c: &str) -> u8 {
    match c {
        "direct" => 0,
        "relay" => 1,
        "derp" => 2,
        "tunnel" => 3,
        "blocked" => 4,
        _ => 5, // offline / unknown
    }
}

/// GET /api/tenant/{tid}/stats/mesh — the org's overlay topology as a
/// graph: the control plane at the centre, one node per device, and
/// edges for both the control-plane WS and the peer-to-peer carriers.
///
/// Member-visible (read-only, no addresses or secrets — carrier kind and
/// latency only), because the dashboard panel it feeds is.
pub async fn tenant_mesh(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    require_tenant_stats(&state, tid, auth.user_id, false).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    // FR-84 D5a — the same graph a device gets of ITS visible set through
    // `/api/agent/self/mesh`; unfiltered here, and byte-identical to what
    // this route answered before the split (`web_mesh_payload_is_unchanged`).
    Ok(Json(to_payload(build_mesh(&state, tid).await?, None, None)))
}

/// The org's mesh, built and merged but not yet shaped for a consumer: the
/// three lists [`tenant_mesh`] has always answered with.
#[derive(Debug, Default)]
pub(crate) struct BuiltMesh {
    /// One per live overlay node: `id`, `agent_id_hex`, `name`, `overlay_ip`,
    /// `relay_home`, `status`, `last_seen_at`.
    pub nodes: Vec<serde_json::Value>,
    /// One per live agent: `id`, `name`, `display_name`, `last_presence`,
    /// `agent_version`, `relay_home`, `os`.
    pub agents: Vec<serde_json::Value>,
    /// Undirected peer edges, `from`/`to` in NODE id space, the two ends'
    /// snapshots merged pessimistically.
    pub edges: Vec<serde_json::Value>,
}

/// The mesh payload for a consumer.
///
/// `filter = None` is the web dashboard's unshaped org view — exactly the
/// pre-FR-84 payload. `filter = Some(visible)` (the device's own view, keyed
/// by overlay node id) keeps only the visible nodes, the agents that back
/// them and the edges whose BOTH ends are visible — an edge to a withheld
/// node would name it — and adds a server-computed `label` per node
/// (display_name > agent name > node name > overlay ip > id tail, the web
/// dashboard's rule) because the companion has no agent list to join
/// against. `self_node_id` is added when given.
pub(crate) fn to_payload(
    built: BuiltMesh,
    filter: Option<&std::collections::HashSet<String>>,
    self_node_id: Option<&str>,
) -> serde_json::Value {
    let BuiltMesh {
        mut nodes,
        mut agents,
        mut edges,
    } = built;
    if let Some(visible) = filter {
        let id_of = |v: &serde_json::Value, key: &str| -> Option<String> {
            v.get(key).and_then(|s| s.as_str()).map(str::to_string)
        };
        nodes.retain(|n| id_of(n, "id").is_some_and(|id| visible.contains(&id)));
        let backing: std::collections::HashSet<String> = nodes
            .iter()
            .filter_map(|n| id_of(n, "agent_id_hex"))
            .collect();
        agents.retain(|a| id_of(a, "id").is_some_and(|id| backing.contains(&id)));
        edges.retain(|e| {
            id_of(e, "from").is_some_and(|f| visible.contains(&f))
                && id_of(e, "to").is_some_and(|t| visible.contains(&t))
        });
        let agent_by_id: HashMap<String, &serde_json::Value> = agents
            .iter()
            .filter_map(|a| Some((id_of(a, "id")?, a)))
            .collect();
        let non_empty = |v: Option<&serde_json::Value>| -> Option<String> {
            v.and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let labels: Vec<String> = nodes
            .iter()
            .map(|n| {
                let agent = id_of(n, "agent_id_hex").and_then(|a| agent_by_id.get(&a).copied());
                non_empty(agent.and_then(|a| a.get("display_name")))
                    .or_else(|| non_empty(agent.and_then(|a| a.get("name"))))
                    .or_else(|| non_empty(n.get("name")))
                    .or_else(|| non_empty(n.get("overlay_ip")))
                    .or_else(|| {
                        id_of(n, "id").map(|id| id[id.len().saturating_sub(6)..].to_string())
                    })
                    .unwrap_or_default()
            })
            .collect();
        for (n, label) in nodes.iter_mut().zip(labels) {
            n["label"] = serde_json::Value::String(label);
        }
    }
    let mut out = serde_json::json!({
        "enabled": true,
        "center": { "id": "control-plane", "name": "roomler.ai" },
        "nodes": nodes,
        "agents": agents,
        "edges": edges,
    });
    if let Some(id) = self_node_id {
        out["self_node_id"] = serde_json::Value::String(id.to_string());
    }
    out
}

/// The org's overlay topology, merged: every live node, every live agent,
/// and one undirected edge per reported pair (the worse carrier, the lower
/// RTT, both ends' own views).
pub(crate) async fn build_mesh(state: &Core, tid: ObjectId) -> Result<BuiltMesh, ApiError> {
    // Nodes: every live device, with the overlay identity the mesh
    // edges are keyed by.
    let nodes = agg(
        state,
        "overlay_nodes",
        vec![
            doc! { "$match": { "tenant_id": tid, "deleted_at": Bson::Null } },
            doc! { "$set": {
                "id": { "$toString": "$_id" },
                // An overlay node points at its owner through
                // `node_ref: {kind, id}` — there is NO flat `agent_id`.
                // Reading the wrong field yielded nulls, which silently
                // emptied the agent→node map and drew a graph with no
                // edges at all. Tunnel-client nodes have no agent, so
                // they resolve to null here by design.
                "agent_id_hex": { "$cond": [
                    { "$eq": [ "$node_ref.kind", "agent" ] },
                    { "$toString": "$node_ref.id" },
                    Bson::Null,
                ]},
            }},
            doc! { "$project": {
                "_id": 0, "id": 1, "agent_id_hex": 1, "name": 1,
                "overlay_ip": 1, "relay_home": 1, "status": 1, "last_seen_at": 1,
            }},
            doc! { "$limit": 500 },
        ],
    )
    .await?;

    // Agents carry presence + version; joined client-side by hex id so
    // the graph can grey out a device that is enrolled but offline.
    let agents = agg(
        state,
        "agents",
        vec![
            doc! { "$match": { "tenant_id": tid, "deleted_at": Bson::Null } },
            doc! { "$set": { "id": { "$toString": "$_id" } } },
            doc! { "$project": {
                "_id": 0, "id": 1, "name": 1, "display_name": 1, "last_presence": 1,
                "agent_version": 1, "relay_home": 1, "os": 1,
            }},
            doc! { "$limit": 500 },
        ],
    )
    .await?;

    // Edges: merge the two ends' snapshots. Both report the same pair,
    // and they can legitimately disagree — take the worse carrier and
    // the lower RTT, and remember whether both ends actually agreed.
    // Freshness gate (wave 4): a snapshot is one heartbeat old at most
    // while its agent lives, and FROZEN forever once it dies — a dead
    // agent's last "direct to X" claim would otherwise keep outvoting the
    // live end's "offline" for up to the 7-day TTL. Letting per-direction
    // `ends` through without this turned 40 of 62 prod edges "asymmetric"
    // on first render: stale-vs-live disagreements wearing the costume of
    // routing asymmetry. Six missed heartbeats = no vote.
    let fresh_floor = DateTime::from_millis(DateTime::now().timestamp_millis() - 180 * 1000);
    let snapshots = agg(
        state,
        meshharbor_services::dao::stats::STATS_MESH,
        vec![
            doc! { "$match": { "tenant_id": tid, "ts": { "$gte": fresh_floor } } },
            doc! { "$set": { "from": { "$toString": "$agent_id" } } },
            doc! { "$project": { "_id": 0, "from": 1, "links": 1 } },
        ],
    )
    .await?;

    #[derive(Default)]
    struct Edge {
        carrier: String,
        rtt_ms: Option<i64>,
        stalled: bool,
        reports: u8,
        // Wave 4 — each end's OWN view of the pair (`node` = the reporter,
        // `carrier`/`relay`/`rtt_ms` = how it reaches the other end). The
        // merged fields above stay for the class toggle and colour, but an
        // asymmetric pair — direct one way, relayed the other — is real
        // routing information the pessimistic merge was erasing.
        ends: Vec<serde_json::Value>,
    }
    // The two ends of an edge arrive in DIFFERENT id spaces: a snapshot
    // is keyed by the reporting AGENT, while the links inside it name
    // peers by their OVERLAY NODE id (that's what the overlay runtime
    // knows). Translate the reporter into node-space first, or every
    // edge silently fails to match a node and the graph draws nothing.
    let node_of_agent: HashMap<String, String> = nodes
        .iter()
        .filter_map(|n| {
            Some((
                n.get("agent_id_hex")?.as_str()?.to_string(),
                n.get("id")?.as_str()?.to_string(),
            ))
        })
        .collect();

    let mut edges: HashMap<(String, String), Edge> = HashMap::new();
    for snap in &snapshots {
        let Some(from) = snap
            .get("from")
            .and_then(|v| v.as_str())
            .and_then(|a| node_of_agent.get(a))
            .map(String::as_str)
        else {
            // A snapshot from an agent with no live overlay node (left
            // the mesh, or reported before joining) has nothing to
            // anchor its edges to.
            continue;
        };
        let Some(links) = snap.get("links").and_then(|v| v.as_array()) else {
            continue;
        };
        for l in links {
            let (Some(node), Some(carrier)) = (
                l.get("node").and_then(|v| v.as_str()),
                l.get("carrier").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            // Undirected: key on the sorted pair so both ends land on
            // the same entry.
            let key = if from <= node {
                (from.to_string(), node.to_string())
            } else {
                (node.to_string(), from.to_string())
            };
            let rtt = l.get("rtt_ms").and_then(|v| v.as_i64());
            let stalled = l.get("stalled").and_then(|v| v.as_bool()).unwrap_or(false);
            let e = edges.entry(key).or_default();
            e.reports += 1;
            e.stalled |= stalled;
            e.ends.push(serde_json::json!({
                "node": from,
                "carrier": carrier,
                "relay": l.get("relay").and_then(|v| v.as_str()),
                "rtt_ms": rtt,
                "stalled": stalled,
            }));
            if e.carrier.is_empty() || carrier_rank(carrier) > carrier_rank(&e.carrier) {
                e.carrier = carrier.to_string();
            }
            e.rtt_ms = match (e.rtt_ms, rtt) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
    }
    let peer_edges: Vec<serde_json::Value> = edges
        .into_iter()
        .map(|((a, b), e)| {
            serde_json::json!({
                "kind": "peer",
                "from": a,
                "to": b,
                "carrier": e.carrier,
                "rtt_ms": e.rtt_ms,
                "stalled": e.stalled,
                // 1 = only one end reported this pair (the other is
                // offline, or pre-mesh). Worth surfacing: a one-sided
                // edge is a weaker claim than a corroborated one.
                "reports": e.reports,
                "ends": e.ends,
            })
        })
        .collect();

    Ok(BuiltMesh {
        nodes,
        agents,
        edges: peer_edges,
    })
}

/// GET /api/tenant/{tid}/stats/calls?range= — MANAGE_AGENTS.
pub async fn tenant_calls(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    require_tenant_stats(&state, tid, auth.user_id, true).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    calls_payload(&state, Some(tid), q.range.as_deref()).await
}

async fn calls_payload(
    state: &Core,
    tid: Option<ObjectId>,
    range: Option<&str>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (window, tier) = range_spec(range)?;
    let floor = floor_dt(window);
    let series = agg(
        state,
        &tier_coll("stats_call", tier),
        call_series_pipeline(tid, floor, tier),
    )
    .await?;
    // Totals from the call ledger (exact regardless of tier).
    let mut match_doc = doc! { "started_at": { "$gte": floor } };
    if let Some(t) = tid {
        match_doc.insert("tenant_id", t);
    }
    let totals = agg(
        state,
        "call_sessions",
        vec![
            doc! { "$match": match_doc },
            doc! { "$set": { "end_eff": { "$ifNull": [ "$ended_at", "$$NOW" ] } } },
            doc! { "$group": {
                "_id": Bson::Null,
                "calls": { "$sum": 1 },
                "minutes": { "$sum": { "$divide": [
                    { "$subtract": [ "$end_eff", "$started_at" ] },
                    60_000,
                ] } },
                "participant_minutes": { "$sum": { "$divide": [ "$participant_seconds", 60 ] } },
                "peak_participants": { "$max": "$peak_participants" },
            }},
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    Ok(Json(serde_json::json!({
        "enabled": true,
        "range": range.unwrap_or("24h"),
        "series": series,
        "totals": totals.into_iter().next().unwrap_or(serde_json::json!({
            "calls": 0, "minutes": 0.0, "participant_minutes": 0.0,
        })),
    })))
}

/// GET /api/tenant/{tid}/stats/tunnels?range= — MANAGE_AGENTS. Aggregates
/// the existing tunnel_audit ledger (bytes + RelayMode per closed flow;
/// 90 d TTL bounds `1y` to what exists).
pub async fn tenant_tunnels(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    require_tenant_stats(&state, tid, auth.user_id, true).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let (window, tier) = range_spec(q.range.as_deref())?;
    let floor = floor_dt(window);
    let unit = match tier {
        Tier::Raw => doc! { "$dateTrunc": { "date": "$at", "unit": "minute", "binSize": 5 } },
        Tier::Hour => doc! { "$dateTrunc": { "date": "$at", "unit": "hour" } },
        Tier::Day => doc! { "$dateTrunc": { "date": "$at", "unit": "day" } },
    };
    let series = agg(
        &state,
        "tunnel_audit",
        vec![
            doc! { "$match": { "tenant_id": tid, "at": { "$gte": floor } } },
            doc! { "$group": {
                "_id": unit,
                "bytes_in": { "$sum": "$bytes_in" },
                "bytes_out": { "$sum": "$bytes_out" },
                "events": { "$sum": 1 },
                // RelayMode serializes snake_case ("direct"|"turn_udp"|"turn_tcp").
                "direct": { "$sum": { "$cond": [ { "$eq": [ "$relay", "direct" ] }, 1, 0 ] } },
                "relayed": { "$sum": { "$cond": [ { "$in": [ "$relay", [ "turn_udp", "turn_tcp" ] ] }, 1, 0 ] } },
            }},
            doc! { "$set": { "t": t_secs() } },
            doc! { "$unset": "_id" },
            doc! { "$sort": { "t": 1 } },
        ],
    )
    .await?;
    Ok(Json(serde_json::json!({
        "enabled": true,
        "range": q.range.as_deref().unwrap_or("24h"),
        "series": series,
    })))
}

// ── Page-view beacon ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PageViewBody {
    /// Client route paths, batched. NORMALISED server-side — ids never
    /// reach an analytics row (see `user_analytics::normalize_path`).
    pub paths: Vec<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// POST /api/stats/pageview — the SPA's route-change beacon.
///
/// Authenticated (so a view is attributable to a user without any
/// cookie of our own) and deliberately dumb: it records the normalised
/// route and the timestamp, nothing else. Batches are capped so a
/// misbehaving client can't turn this into a write amplifier.
pub async fn page_view(
    State(state): State<Core>,
    auth: AuthUser,
    Json(body): Json<PageViewBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.settings.stats.enabled {
        return Ok(Json(serde_json::json!({ "enabled": false })));
    }
    const MAX_BATCH: usize = 50;
    let tenant = body.tenant_id.as_deref().and_then(|t| parse_tid(t).ok());
    let now = DateTime::now();
    let docs: Vec<Document> = body
        .paths
        .iter()
        .take(MAX_BATCH)
        .map(|p| {
            doc! {
                "user_id": auth.user_id,
                "tenant_id": tenant,
                "path": crate::user_analytics::normalize_path(p),
                "ts": now,
            }
        })
        .collect();
    if docs.is_empty() {
        return Ok(Json(serde_json::json!({ "recorded": 0 })));
    }
    let n = docs.len();
    if let Err(e) = state
        .db
        .collection::<Document>(crate::user_analytics::PAGE_VIEWS)
        .insert_many(docs)
        .await
    {
        // Analytics must never fail a user's navigation.
        tracing::debug!(%e, "page view persist failed");
        return Ok(Json(serde_json::json!({ "recorded": 0 })));
    }
    Ok(Json(serde_json::json!({ "recorded": n })))
}

/// GET /api/admin/stats/users?range= — platform user analytics: WS
/// sessions over time, durations, browsers, platforms, countries, pages,
/// and the per-org split.
pub async fn admin_users(
    State(state): State<Core>,
    auth: AuthUser,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let (window, tier) = range_spec(q.range.as_deref())?;
    let floor = floor_dt(window);
    let unit = match tier {
        Tier::Raw => doc! { "$dateTrunc": { "date": "$started_at", "unit": "hour" } },
        Tier::Hour => doc! { "$dateTrunc": { "date": "$started_at", "unit": "hour" } },
        Tier::Day => doc! { "$dateTrunc": { "date": "$started_at", "unit": "day" } },
    };
    let ws = crate::user_analytics::WS_SESSIONS;

    // Sessions + distinct users per bucket. A still-open session counts
    // toward "now" via $$NOW so a live connection isn't invisible.
    let series = agg(
        &state,
        ws,
        vec![
            doc! { "$match": { "started_at": { "$gte": floor } } },
            doc! { "$set": { "end_eff": { "$ifNull": [ "$ended_at", "$$NOW" ] } } },
            doc! { "$group": {
                "_id": unit,
                "sessions": { "$sum": 1 },
                "users": { "$addToSet": "$user_id" },
                "avg_duration_s": { "$avg": { "$divide": [
                    { "$subtract": [ "$end_eff", "$started_at" ] }, 1000,
                ] } },
            }},
            doc! { "$set": { "t": t_secs(), "users": { "$size": "$users" } } },
            doc! { "$unset": "_id" },
            doc! { "$sort": { "t": 1 } },
        ],
    )
    .await?;

    // One breakdown shape, three fields.
    let breakdown = |field: &str| {
        vec![
            doc! { "$match": { "started_at": { "$gte": floor } } },
            doc! { "$group": { "_id": format!("${field}"), "sessions": { "$sum": 1 } } },
            doc! { "$set": { "key": { "$ifNull": [ "$_id", "unknown" ] } } },
            doc! { "$unset": "_id" },
            doc! { "$sort": { "sessions": -1 } },
            doc! { "$limit": 25 },
        ]
    };
    let browsers = agg(&state, ws, breakdown("browser")).await?;
    let platforms = agg(&state, ws, breakdown("platform")).await?;
    let countries = agg(&state, ws, breakdown("country")).await?;

    // Per-org: sessions, distinct users, total connected time.
    let orgs = agg(
        &state,
        ws,
        vec![
            doc! { "$match": { "started_at": { "$gte": floor }, "tenant_id": { "$ne": Bson::Null } } },
            doc! { "$set": { "end_eff": { "$ifNull": [ "$ended_at", "$$NOW" ] } } },
            doc! { "$group": {
                "_id": "$tenant_id",
                "sessions": { "$sum": 1 },
                "users": { "$addToSet": "$user_id" },
                "connected_minutes": { "$sum": { "$divide": [
                    { "$subtract": [ "$end_eff", "$started_at" ] }, 60_000,
                ] } },
            }},
            doc! { "$set": { "tenant_id": { "$toString": "$_id" }, "users": { "$size": "$users" } } },
            doc! { "$unset": "_id" },
            doc! { "$sort": { "connected_minutes": -1 } },
            doc! { "$limit": 100 },
        ],
    )
    .await?;

    let pages = agg(
        &state,
        crate::user_analytics::PAGE_VIEWS,
        vec![
            doc! { "$match": { "ts": { "$gte": floor } } },
            doc! { "$group": {
                "_id": "$path",
                "views": { "$sum": 1 },
                "users": { "$addToSet": "$user_id" },
            }},
            doc! { "$set": { "path": "$_id", "users": { "$size": "$users" } } },
            doc! { "$unset": "_id" },
            doc! { "$sort": { "views": -1 } },
            doc! { "$limit": 25 },
        ],
    )
    .await?;

    // Duration histogram — the shape of a session, not just its mean.
    let durations = agg(
        &state,
        ws,
        vec![
            doc! { "$match": { "started_at": { "$gte": floor } } },
            doc! { "$set": { "end_eff": { "$ifNull": [ "$ended_at", "$$NOW" ] } } },
            doc! { "$set": { "secs": { "$divide": [
                { "$subtract": [ "$end_eff", "$started_at" ] }, 1000,
            ] } } },
            doc! { "$bucket": {
                "groupBy": "$secs",
                "boundaries": [0, 60, 300, 900, 3600, 14400, 86_400],
                "default": "86400+",
                "output": { "sessions": { "$sum": 1 } },
            }},
            doc! { "$set": { "bucket": { "$toString": "$_id" } } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "range": q.range.as_deref().unwrap_or("24h"),
        "geoip": state.geoip.enabled(),
        // #1896 — WHOSE country data this is (the database's own type), so
        // the dashboard shows the credit its licence asks for, and no other.
        "geoip_database": state.geoip.database(),
        "series": series,
        "browsers": browsers,
        "platforms": platforms,
        "countries": countries,
        "orgs": orgs,
        "pages": pages,
        "durations": durations,
    })))
}

// ── Admin endpoints ─────────────────────────────────────────────────────

/// GET /api/admin/stats/relay/current — realtime cluster view: newest
/// persisted bucket per region (cluster-wide truth — the in-memory map is
/// per-pod), busy from this pod's load map, and the fleet-eye latency
/// (avg of agents' probe RTTs per region).
pub async fn admin_relay_current(
    State(state): State<Core>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }

    // Newest sample per region (any region seen in the last 10 min).
    let latest = agg(
        &state,
        "stats_relay",
        vec![
            doc! { "$match": { "ts": { "$gte": floor_dt(600) } } },
            doc! { "$sort": { "ts": -1 } },
            doc! { "$group": { "_id": "$region", "doc": { "$first": "$$ROOT" } } },
            doc! { "$replaceRoot": { "newRoot": "$doc" } },
            doc! { "$set": { "t": { "$toLong": { "$divide": [ { "$toLong": "$ts" }, 1000 ] } } } },
            doc! { "$unset": [ "_id", "ts" ] },
        ],
    )
    .await?;

    // Fleet-eye RTT per region from persisted agent probe tables.
    let agent_rtt = agg(
        &state,
        "agents",
        vec![
            doc! { "$match": { "deleted_at": Bson::Null, "relay_rtt": { "$type": "array" } } },
            doc! { "$unwind": "$relay_rtt" },
            doc! { "$match": { "relay_rtt.rtt_ms": { "$ne": Bson::Null } } },
            doc! { "$group": {
                "_id": "$relay_rtt.region",
                "rtt_avg_ms": { "$avg": "$relay_rtt.rtt_ms" },
                "agents": { "$sum": 1 },
            }},
            doc! { "$set": { "region": "$_id" } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;

    // Region roster from config, with busy from the live map.
    let regions: Vec<serde_json::Value> = state
        .turn_map
        .specs
        .iter()
        .map(|s| {
            let busy = meshharbor_remote_control::turn_creds::region_busy(&state.relay_load, &s.id);
            serde_json::json!({
                "id": s.id,
                "enabled": s.enabled,
                // Monitored = the poller has somewhere to fetch: a
                // regional DERP host, or the explicit `stats_urls`
                // override (multi-worker regions like the central fleet).
                "monitored": s.derp_url.is_some() || !s.stats_urls.is_empty(),
                "workers": (s.stats_urls.len().max(1)) as i64,
                "busy": busy,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "enabled": true,
        "regions_enabled": state.turn_map.enabled,
        "regions": regions,
        "latest": latest,
        "agent_rtt": agent_rtt,
    })))
}

/// GET /api/admin/stats/relay/history?region&range
pub async fn admin_relay_history(
    State(state): State<Core>,
    auth: AuthUser,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let region = q
        .region
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("region is required".into()))?;
    let (window, tier) = range_spec(q.range.as_deref())?;
    let series = agg(
        &state,
        &tier_coll("stats_relay", tier),
        relay_series_pipeline(region, floor_dt(window), tier),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "enabled": true,
        "region": region,
        "range": q.range.as_deref().unwrap_or("24h"),
        "series": series,
    })))
}

/// GET /api/admin/stats/orgs — per-tenant machine + call rollup.
pub async fn admin_orgs(
    State(state): State<Core>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }

    let tenants = agg(
        &state,
        "tenants",
        vec![
            doc! { "$match": { "deleted_at": Bson::Null } },
            doc! { "$set": { "id": { "$toString": "$_id" }, "created": "$created_at" } },
            doc! { "$project": { "_id": 0, "id": 1, "name": 1, "slug": 1, "created": 1 } },
            doc! { "$limit": 500 },
        ],
    )
    .await?;
    // Members per org — the third activity signal (an org with one
    // member, no devices and no calls is almost always a test artifact;
    // this deployment carries ~60 of them from integration runs).
    let members = agg(
        &state,
        "tenant_members",
        vec![
            doc! { "$group": { "_id": "$tenant_id", "members": { "$sum": 1 } } },
            doc! { "$set": { "tenant_id": { "$toString": "$_id" } } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    let machines = agg(
        &state,
        "agents",
        vec![
            doc! { "$match": { "deleted_at": Bson::Null } },
            doc! { "$group": {
                "_id": "$tenant_id",
                "total": { "$sum": 1 },
                "online": { "$sum": { "$cond": [ { "$eq": [ "$last_presence", "online" ] }, 1, 0 ] } },
            }},
            doc! { "$set": { "tenant_id": { "$toString": "$_id" } } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    let calls = agg(
        &state,
        "call_sessions",
        vec![
            doc! { "$match": { "started_at": { "$gte": floor_dt(30 * 86_400) } } },
            doc! { "$set": { "end_eff": { "$ifNull": [ "$ended_at", "$$NOW" ] } } },
            doc! { "$group": {
                "_id": "$tenant_id",
                "calls_30d": { "$sum": 1 },
                "minutes_30d": { "$sum": { "$divide": [
                    { "$subtract": [ "$end_eff", "$started_at" ] },
                    60_000,
                ] } },
            }},
            doc! { "$set": { "tenant_id": { "$toString": "$_id" } } },
            doc! { "$unset": "_id" },
        ],
    )
    .await?;
    // FR-93 P2b — the whole fleet's Linux desktops: the denominator a field
    // check after a roll needs, which an exec sweep (online only) cannot give.
    let desktops = agg(&state, "agents", desktop_breakdown_pipeline(doc! {})).await?;
    Ok(Json(serde_json::json!({
        "enabled": true,
        "tenants": tenants,
        "machines": machines,
        "members": members,
        "calls": calls,
        "desktops": desktops,
    })))
}

/// GET /api/admin/stats/machines?tenant_id&range — cross-org machine
/// series for a chosen tenant.
pub async fn admin_machines(
    State(state): State<Core>,
    auth: AuthUser,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let tid = q
        .tenant_id
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("tenant_id is required".into()))
        .and_then(parse_tid)?;
    machines_payload(&state, tid, q.range.as_deref()).await
}

/// GET /api/admin/stats/calls?tenant_id&range — tenant_id optional
/// (omitted ⇒ platform-wide).
pub async fn admin_calls(
    State(state): State<Core>,
    auth: AuthUser,
    Query(q): Query<RangeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let tid = match q.tenant_id.as_deref() {
        Some(t) => Some(parse_tid(t)?),
        None => None,
    };
    calls_payload(&state, tid, q.range.as_deref()).await
}

#[cfg(test)]
mod mesh_payload_tests {
    use super::*;
    use serde_json::json;

    /// Three nodes (A, B, C backed by agents a, b, c) and the three edges
    /// between them, in the shape `build_mesh` produces.
    fn built() -> BuiltMesh {
        let node = |id: &str, agent: &str, name: &str, ip: &str| {
            json!({
                "id": id, "agent_id_hex": agent, "name": name, "overlay_ip": ip,
                "relay_home": null, "status": "online", "last_seen_at": null,
            })
        };
        let agent = |id: &str, name: &str, display: Option<&str>| {
            json!({
                "id": id, "name": name, "display_name": display, "last_presence": "online",
                "agent_version": "0.4.103", "relay_home": null, "os": "linux",
            })
        };
        let edge = |from: &str, to: &str| {
            json!({
                "kind": "peer", "from": from, "to": to, "carrier": "direct",
                "rtt_ms": 5, "stalled": false, "reports": 2, "ends": [],
            })
        };
        BuiltMesh {
            nodes: vec![
                node("nodeA", "agentA", "alpha", "100.64.0.1"),
                node("nodeB", "agentB", "bravo", "100.64.0.2"),
                node("nodeC", "agentC", "charlie", "100.64.0.3"),
            ],
            agents: vec![
                agent("agentA", "alpha-box", None),
                agent("agentB", "bravo-box", Some("Kilo")),
                agent("agentC", "charlie-box", Some("")),
            ],
            edges: vec![
                edge("nodeA", "nodeB"),
                edge("nodeA", "nodeC"),
                edge("nodeB", "nodeC"),
            ],
        }
    }

    /// The web route's payload is exactly what `tenant_mesh` built inline
    /// before FR-84 split it: the same five keys, the lists untouched, no
    /// `label`, no `self_node_id`.
    #[test]
    fn web_mesh_payload_is_unchanged() {
        let b = built();
        let expected = json!({
            "enabled": true,
            "center": { "id": "control-plane", "name": "roomler.ai" },
            "nodes": b.nodes.clone(),
            "agents": b.agents.clone(),
            "edges": b.edges.clone(),
        });
        let actual = to_payload(b, None, None);
        assert_eq!(actual, expected);
        assert_eq!(
            serde_json::to_string(&actual).unwrap(),
            serde_json::to_string(&expected).unwrap(),
            "byte-identical, not merely equal"
        );
        assert!(actual.get("self_node_id").is_none());
        assert!(
            actual["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|n| n.get("label").is_none())
        );
    }

    /// The device view: nodes ∈ visible, agents whose node is visible, edges
    /// only when BOTH ends are visible, labels by the dashboard's rule, and
    /// the caller named.
    #[test]
    fn device_mesh_payload_is_restricted_to_the_visible_set() {
        let visible: std::collections::HashSet<String> =
            ["nodeA", "nodeB"].iter().map(|s| s.to_string()).collect();
        let out = to_payload(built(), Some(&visible), Some("nodeA"));
        assert_eq!(out["enabled"], json!(true));
        assert_eq!(out["self_node_id"], json!("nodeA"));

        let node_ids: Vec<&str> = out["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap())
            .collect();
        assert_eq!(node_ids, vec!["nodeA", "nodeB"]);
        let agent_ids: Vec<&str> = out["agents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap())
            .collect();
        assert_eq!(agent_ids, vec!["agentA", "agentB"]);
        let edges = out["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1, "only the A–B edge survives: {edges:?}");
        assert_eq!(edges[0]["from"], json!("nodeA"));
        assert_eq!(edges[0]["to"], json!("nodeB"));

        // display_name > agent name > node name > overlay ip > id tail.
        let labels: Vec<&str> = out["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["label"].as_str().unwrap())
            .collect();
        assert_eq!(labels, vec!["alpha-box", "Kilo"]);
    }

    /// Every rung of the label ladder, including the empty-string skips.
    #[test]
    fn label_falls_through_empty_values() {
        let visible: std::collections::HashSet<String> =
            ["n1", "n2", "n3"].iter().map(|s| s.to_string()).collect();
        let b = BuiltMesh {
            nodes: vec![
                json!({ "id": "n1", "agent_id_hex": "a1", "name": "", "overlay_ip": "100.64.0.9" }),
                json!({ "id": "n2", "agent_id_hex": null, "name": "tunnel-laptop", "overlay_ip": "100.64.0.10" }),
                json!({ "id": "n3", "agent_id_hex": null, "name": "", "overlay_ip": "" }),
            ],
            agents: vec![json!({ "id": "a1", "name": "", "display_name": null })],
            edges: vec![],
        };
        let out = to_payload(b, Some(&visible), None);
        let labels: Vec<&str> = out["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["label"].as_str().unwrap())
            .collect();
        assert_eq!(labels, vec!["100.64.0.9", "tunnel-laptop", "n3"]);
        assert!(out.get("self_node_id").is_none());
    }
}
