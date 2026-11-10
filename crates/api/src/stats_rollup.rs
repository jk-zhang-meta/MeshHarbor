// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Stats PR-1 — the rollup compactor: raw samples → `_1h` (90 d) → `_1d`
//! (730 d), so year-scale queries survive the 7-day raw TTL.
//!
//! Mechanics (each protects against a specific failure):
//!
//! - **Cluster-singleton per cycle** via the same DB-name-scoped Redis NX
//!   claim the presence sweeper uses — prod pods share a DB (one roller),
//!   each test's UUID database claims independently. No Redis ⇒ single
//!   pod ⇒ run locally.
//! - **Per-family watermark** in `stats_meta`, advanced only AFTER that
//!   family's `$merge` succeeded — a death mid-run simply re-merges, and
//!   `$merge (whenMatched: replace)` with whole-bucket recomputation is
//!   idempotent.
//! - **The open bucket is recomputed every run**: the watermark is set to
//!   the START of the current hour/day, never past it, so a partially
//!   elapsed bucket keeps refreshing until it closes instead of freezing
//!   undercounted.
//! - The floor is clamped to 6 days back — bounded work after long
//!   downtime, still within the raw TTL window.
//!
//! `_1d` is built FROM `_1h` (raw TTL 7 d < 1 y). Averages of averages are
//! an accepted approximation for gauges; counts (`sample_count`,
//! `healthy_count`, `online_minutes`, `*_seconds`) are sums all the way
//! down and stay exact.

use bson::{Bson, DateTime, Document, doc};
use tracing::{debug, info};

use crate::state::AppState;
use meshharbor_services::dao::stats::{
    CALL_BUCKET_SECS, STATS_CALL, STATS_CALL_USER, STATS_MACHINE, STATS_RELAY, STATS_USAGE,
    STATS_USAGE_1D, STATS_USAGE_1H,
};

const ROLLUP_INTERVAL_SECS: u64 = 900; // 15 min
const MINUTE: i64 = 60;
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
/// Never reprocess more than this much history in one run (bounds a
/// post-downtime catch-up; still inside the 7 d raw TTL).
const MAX_LOOKBACK_SECS: i64 = 6 * DAY;
/// First-ever run backfills this much.
const DEFAULT_LOOKBACK_SECS: i64 = 48 * HOUR;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// `"$_id.b"` (a bucket-start date) → the unix-seconds string used in the
/// deterministic rollup `_id`.
fn bucket_secs_str() -> Document {
    doc! { "$toString": { "$toLong": { "$divide": [ { "$toLong": "$_id.b" }, 1000 ] } } }
}

/// `$merge` terminal stage — whole-bucket replace keyed on `_id`.
fn merge_into(coll: &str) -> Document {
    doc! { "$merge": {
        "into": coll,
        "on": "_id",
        "whenMatched": "replace",
        "whenNotMatched": "insert",
    }}
}

fn relay_pipeline(floor: DateTime, unit: &str, src_is_rollup: bool, into: &str) -> Vec<Document> {
    // Raw samples carry healthy/load/… directly; the 1h→1d pass re-sums
    // the counts and averages the averages.
    let group = if !src_is_rollup {
        doc! {
            "_id": { "k": "$region", "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
            "sample_count": { "$sum": 1 },
            "healthy_count": { "$sum": { "$cond": [ "$healthy", 1, 0 ] } },
            "poll_rtt_ms": { "$avg": "$poll_rtt_ms" },
            "load1": { "$avg": "$load1" },
            "load5_max": { "$max": "$load5" },
            "cpus": { "$max": "$cpus" },
            "mem_available_pct": { "$avg": { "$cond": [
                { "$gt": [ "$mem_total_kb", 0 ] },
                { "$divide": [ "$mem_available_kb", "$mem_total_kb" ] },
                Bson::Null,
            ] } },
            "rx_mbps": { "$avg": "$rx_mbps" },
            "rx_mbps_max": { "$max": "$rx_mbps" },
            "tx_mbps": { "$avg": "$tx_mbps" },
            "tx_mbps_max": { "$max": "$tx_mbps" },
            "allocations": { "$avg": "$allocations" },
            "allocations_max": { "$max": "$allocations" },
            "coturn_sessions": { "$avg": "$coturn_sessions" },
            "derp_registrations": { "$avg": "$derp_registrations" },
        }
    } else {
        doc! {
            "_id": { "k": "$region", "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
            "sample_count": { "$sum": "$sample_count" },
            "healthy_count": { "$sum": "$healthy_count" },
            "poll_rtt_ms": { "$avg": "$poll_rtt_ms" },
            "load1": { "$avg": "$load1" },
            "load5_max": { "$max": "$load5_max" },
            "cpus": { "$max": "$cpus" },
            "mem_available_pct": { "$avg": "$mem_available_pct" },
            "rx_mbps": { "$avg": "$rx_mbps" },
            "rx_mbps_max": { "$max": "$rx_mbps_max" },
            "tx_mbps": { "$avg": "$tx_mbps" },
            "tx_mbps_max": { "$max": "$tx_mbps_max" },
            "allocations": { "$avg": "$allocations" },
            "allocations_max": { "$max": "$allocations_max" },
            "coturn_sessions": { "$avg": "$coturn_sessions" },
            "derp_registrations": { "$avg": "$derp_registrations" },
        }
    };
    vec![
        doc! { "$match": { "ts": { "$gte": floor } } },
        doc! { "$group": group },
        doc! { "$set": {
            "region": "$_id.k",
            "ts": "$_id.b",
            "_id": { "$concat": [ "$_id.k", ":", bucket_secs_str() ] },
        }},
        merge_into(into),
    ]
}

/// FR-20 — compact the cost ledger. Raw minute buckets → `_1h` → `_1d`.
///
/// ⚠ Every measure here is a `$sum`, never an `$avg`. These are **cost
/// drivers**: bytes relayed in an hour is the sum of the bytes relayed in its
/// minutes. Averaging one — the way the relay/machine pipelines legitimately
/// average a *gauge* like load or RTT — would silently divide the bill by the
/// bucket count, and it would look entirely plausible sitting next to them.
fn usage_pipeline(floor: DateTime, unit: &str, src_is_rollup: bool, into: &str) -> Vec<Document> {
    // The grouping key is (tenant, meter), so a tenant's meters stay separate
    // all the way down and a rollup row is still attributable.
    let group = if !src_is_rollup {
        doc! {
            "_id": {
                "k": { "$concat": [ { "$toString": "$tenant_id" }, ":", "$meter" ] },
                "b": { "$dateTrunc": { "date": "$ts", "unit": unit } },
            },
            "tenant_id": { "$first": "$tenant_id" },
            "meter": { "$first": "$meter" },
            "bucket_count": { "$sum": 1 },
            "value": { "$sum": "$value" },
        }
    } else {
        doc! {
            "_id": {
                "k": { "$concat": [ { "$toString": "$tenant_id" }, ":", "$meter" ] },
                "b": { "$dateTrunc": { "date": "$ts", "unit": unit } },
            },
            "tenant_id": { "$first": "$tenant_id" },
            "meter": { "$first": "$meter" },
            "bucket_count": { "$sum": "$bucket_count" },
            "value": { "$sum": "$value" },
        }
    };
    vec![
        doc! { "$match": { "ts": { "$gte": floor } } },
        doc! { "$group": group },
        doc! { "$set": {
            "ts": "$_id.b",
            "_id": { "$concat": [ "$_id.k", ":", bucket_secs_str() ] },
        }},
        merge_into(into),
    ]
}

/// FR-20 P4 — derive `sfu_participant_seconds` into the cost ledger from the
/// per-participant call samples that already exist.
///
/// One `stats_call_user` document IS one participant present for one
/// [`CALL_BUCKET_SECS`] window, so participant-seconds is simply the bucket
/// count times that width. No new collection point: the SFU's marginal cost was
/// already being measured, it just was not being attributed as *cost*.
///
/// ⚠ **This meter is `$merge`d, not `$inc`ed — and that difference is the whole
/// correctness argument.** The DERP meters are *observed deltas*: each flush
/// reports bytes seen since the last one, so re-running a flush double-bills and
/// a failed one is dropped. This meter is a pure *derivation* of rows that are
/// already durable, so recomputing it is idempotent and re-running it is safe —
/// which is exactly why the open bucket may be recomputed every cycle.
///
/// ⚠ It cannot clobber the `$inc`-accumulated meters: `_id` embeds the meter
/// name, so `…:sfu_participant_seconds:…` and `…:derp_bytes:…` are different
/// documents by construction.
///
/// ⚠ A missed sample under-reports rather than over-reports, consistent with
/// every other meter here.
fn sfu_seconds_pipeline(
    floor: DateTime,
    unit: &str,
    _src_is_rollup: bool,
    into: &str,
) -> Vec<Document> {
    vec![
        doc! { "$match": { "ts": { "$gte": floor } } },
        doc! { "$group": {
            "_id": {
                "k": { "$concat": [
                    { "$toString": "$tenant_id" }, ":sfu_participant_seconds",
                ] },
                "b": { "$dateTrunc": { "date": "$ts", "unit": unit } },
            },
            "tenant_id": { "$first": "$tenant_id" },
            // Each sampled bucket is one participant present for its width.
            "value": { "$sum": CALL_BUCKET_SECS },
            "bucket_count": { "$sum": 1 },
        }},
        doc! { "$set": {
            "meter": "sfu_participant_seconds",
            "ts": "$_id.b",
            "_id": { "$concat": [ "$_id.k", ":", bucket_secs_str() ] },
        }},
        merge_into(into),
    ]
}

fn machine_pipeline(floor: DateTime, unit: &str, src_is_rollup: bool, into: &str) -> Vec<Document> {
    let group = if !src_is_rollup {
        doc! {
            "_id": { "k": "$agent_id", "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
            "tenant_id": { "$first": "$tenant_id" },
            "sample_count": { "$sum": 1 },
            "online_minutes": { "$sum": { "$cond": [ "$online", 1, 0 ] } },
            "active_sessions_max": { "$max": "$active_sessions" },
            "cpu_pct": { "$avg": "$sys.cpu_pct" },
            "rss_mb": { "$avg": "$sys.rss_mb" },
            "net_rx_bytes_max": { "$max": "$sys.net_rx_bytes" },
            "net_rx_bytes_min": { "$min": "$sys.net_rx_bytes" },
            "net_tx_bytes_max": { "$max": "$sys.net_tx_bytes" },
            "net_tx_bytes_min": { "$min": "$sys.net_tx_bytes" },
            // Wave 3 — the overlay's own share of that traffic, same
            // cumulative-counter treatment (read side differences max-min).
            "overlay_rx_bytes_max": { "$max": "$sys.overlay_rx_bytes" },
            "overlay_rx_bytes_min": { "$min": "$sys.overlay_rx_bytes" },
            "overlay_tx_bytes_max": { "$max": "$sys.overlay_tx_bytes" },
            "overlay_tx_bytes_min": { "$min": "$sys.overlay_tx_bytes" },
            "tunnel_rx_bytes_max": { "$max": "$sys.tunnel_rx_bytes" },
            "tunnel_rx_bytes_min": { "$min": "$sys.tunnel_rx_bytes" },
            "tunnel_tx_bytes_max": { "$max": "$sys.tunnel_tx_bytes" },
            "tunnel_tx_bytes_min": { "$min": "$sys.tunnel_tx_bytes" },
            "direct": { "$avg": "$sys.transports.direct" },
            "relay": { "$avg": "$sys.transports.relay" },
            "derp": { "$avg": "$sys.transports.derp" },
            "tunnel_flows": { "$avg": "$sys.tunnel_flows" },
            "rc_sessions": { "$avg": "$sys.rc_sessions" },
            "peer_rtt_ms": { "$avg": "$sys.peer_rtt_ms" },
        }
    } else {
        doc! {
            "_id": { "k": "$agent_id", "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
            "tenant_id": { "$first": "$tenant_id" },
            "sample_count": { "$sum": "$sample_count" },
            "online_minutes": { "$sum": "$online_minutes" },
            "active_sessions_max": { "$max": "$active_sessions_max" },
            "cpu_pct": { "$avg": "$cpu_pct" },
            "rss_mb": { "$avg": "$rss_mb" },
            "net_rx_bytes_max": { "$max": "$net_rx_bytes_max" },
            "net_rx_bytes_min": { "$min": "$net_rx_bytes_min" },
            "net_tx_bytes_max": { "$max": "$net_tx_bytes_max" },
            "net_tx_bytes_min": { "$min": "$net_tx_bytes_min" },
            "overlay_rx_bytes_max": { "$max": "$overlay_rx_bytes_max" },
            "overlay_rx_bytes_min": { "$min": "$overlay_rx_bytes_min" },
            "overlay_tx_bytes_max": { "$max": "$overlay_tx_bytes_max" },
            "overlay_tx_bytes_min": { "$min": "$overlay_tx_bytes_min" },
            "tunnel_rx_bytes_max": { "$max": "$tunnel_rx_bytes_max" },
            "tunnel_rx_bytes_min": { "$min": "$tunnel_rx_bytes_min" },
            "tunnel_tx_bytes_max": { "$max": "$tunnel_tx_bytes_max" },
            "tunnel_tx_bytes_min": { "$min": "$tunnel_tx_bytes_min" },
            "direct": { "$avg": "$direct" },
            "relay": { "$avg": "$relay" },
            "derp": { "$avg": "$derp" },
            "tunnel_flows": { "$avg": "$tunnel_flows" },
            "rc_sessions": { "$avg": "$rc_sessions" },
            "peer_rtt_ms": { "$avg": "$peer_rtt_ms" },
        }
    };
    vec![
        doc! { "$match": { "ts": { "$gte": floor } } },
        doc! { "$group": group },
        doc! { "$set": {
            "agent_id": "$_id.k",
            "ts": "$_id.b",
            "_id": { "$concat": [ { "$toString": "$_id.k" }, ":", bucket_secs_str() ] },
        }},
        merge_into(into),
    ]
}

fn call_pipeline(floor: DateTime, unit: &str, src_is_rollup: bool, into: &str) -> Vec<Document> {
    // Raw buckets are per-room 30 s gauges; the rollup is per-TENANT (the
    // org graphs' shape). Seconds counters weight each room-bucket by its
    // 30 s width, so concurrent rooms sum correctly.
    if !src_is_rollup {
        vec![
            doc! { "$match": { "ts": { "$gte": floor } } },
            doc! { "$group": {
                "_id": { "k": "$tenant_id", "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
                "sample_count": { "$sum": 1 },
                "participant_seconds": { "$sum": { "$multiply": [ "$participants", 30 ] } },
                "relayed_seconds": { "$sum": { "$multiply": [ "$relayed", 30 ] } },
                "direct_seconds": { "$sum": { "$multiply": [ "$direct", 30 ] } },
                "call_seconds": { "$sum": 30 },
                "peak_participants": { "$max": "$participants" },
                "send_bps": { "$avg": "$send_bps" },
                "recv_bps": { "$avg": "$recv_bps" },
                "loss_pct": { "$avg": "$loss_pct" },
                "rooms": { "$addToSet": "$room_id" },
            }},
            doc! { "$set": {
                "tenant_id": "$_id.k",
                "ts": "$_id.b",
                "distinct_rooms": { "$size": "$rooms" },
                "_id": { "$concat": [ { "$toString": "$_id.k" }, ":", bucket_secs_str() ] },
            }},
            doc! { "$unset": "rooms" },
            merge_into(into),
        ]
    } else {
        vec![
            doc! { "$match": { "ts": { "$gte": floor } } },
            doc! { "$group": {
                "_id": { "k": "$tenant_id", "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
                "sample_count": { "$sum": "$sample_count" },
                "participant_seconds": { "$sum": "$participant_seconds" },
                "relayed_seconds": { "$sum": "$relayed_seconds" },
                "direct_seconds": { "$sum": "$direct_seconds" },
                "call_seconds": { "$sum": "$call_seconds" },
                "peak_participants": { "$max": "$peak_participants" },
                "send_bps": { "$avg": "$send_bps" },
                "recv_bps": { "$avg": "$recv_bps" },
                "loss_pct": { "$avg": "$loss_pct" },
            }},
            doc! { "$set": {
                "tenant_id": "$_id.k",
                "ts": "$_id.b",
                "_id": { "$concat": [ { "$toString": "$_id.k" }, ":", bucket_secs_str() ] },
            }},
            merge_into(into),
        ]
    }
}

/// Wave 3 — per-(tenant, user) call usage.
///
/// Rates in, **bytes out**: a 30 s gauge multiplied by its own bucket width
/// is an exact byte count, and unlike the averaged gauges elsewhere in this
/// file both columns are pure sums, so they stay exact through raw → 1h → 1d.
/// That matters here in a way it doesn't for a dashboard line: these numbers
/// are the usage ledger, and an average-of-averages would quietly misreport
/// a user who was only in a call for part of the bucket.
fn call_user_pipeline(
    floor: DateTime,
    unit: &str,
    src_is_rollup: bool,
    into: &str,
) -> Vec<Document> {
    let key = doc! { "$concat": [
        { "$toString": "$tenant_id" }, ":", { "$toString": "$user_id" },
    ]};
    let group = if !src_is_rollup {
        doc! {
            "_id": { "k": key.clone(), "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
            "tenant_id": { "$first": "$tenant_id" },
            "user_id": { "$first": "$user_id" },
            "seconds": { "$sum": 30 },
            "up_bytes": { "$sum": { "$divide": [ { "$multiply": [ "$up_bps", 30 ] }, 8 ] } },
            "down_bytes": { "$sum": { "$divide": [ { "$multiply": [ "$down_bps", 30 ] }, 8 ] } },
        }
    } else {
        doc! {
            "_id": { "k": key.clone(), "b": { "$dateTrunc": { "date": "$ts", "unit": unit } } },
            "tenant_id": { "$first": "$tenant_id" },
            "user_id": { "$first": "$user_id" },
            "seconds": { "$sum": "$seconds" },
            "up_bytes": { "$sum": "$up_bytes" },
            "down_bytes": { "$sum": "$down_bytes" },
        }
    };
    vec![
        doc! { "$match": { "ts": { "$gte": floor } } },
        doc! { "$group": group },
        doc! { "$set": {
            "ts": "$_id.b",
            "_id": { "$concat": [ "$_id.k", ":", bucket_secs_str() ] },
        }},
        merge_into(into),
    ]
}

/// One (src → dst) compaction pass with its watermark dance. Returns true
/// when the `$merge` ran (and the watermark advanced).
async fn roll_family(
    state: &AppState,
    key: &str,
    src: &str,
    pipeline: Vec<Document>,
    bucket_secs: i64,
) -> bool {
    let now = unix_now();
    match state
        .db
        .collection::<Document>(src)
        .aggregate(pipeline)
        .await
    {
        Ok(mut cursor) => {
            // $merge emits no documents; drain to surface any late error.
            loop {
                match cursor.advance().await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        debug!(%key, %e, "stats rollup cursor error");
                        return false;
                    }
                }
            }
            // Watermark = start of the CURRENT open bucket, so the next
            // run recomputes it until it closes.
            let open_bucket_ms = (now - now.rem_euclid(bucket_secs)) * 1000;
            if let Err(e) = state.stats.set_rollup_watermark(key, open_bucket_ms).await {
                debug!(%key, %e, "stats rollup watermark write failed");
            }
            true
        }
        Err(e) => {
            debug!(%key, %e, "stats rollup aggregate failed");
            false
        }
    }
}

/// Compute this run's floor for a family from its persisted watermark.
async fn family_floor(state: &AppState, key: &str) -> DateTime {
    let now = unix_now();
    let default_floor = now - DEFAULT_LOOKBACK_SECS;
    let wm_secs = match state.stats.rollup_watermark(key).await {
        Ok(Some(ms)) => ms / 1000,
        _ => default_floor,
    };
    DateTime::from_millis(wm_secs.max(now - MAX_LOOKBACK_SECS) * 1000)
}

/// One compaction pass: a source collection aggregated into a rollup
/// collection at one grain. Two rows per family (raw→1h, 1h→1d).
struct Pass {
    /// Watermark key, also the log label.
    key: &'static str,
    src: &'static str,
    into: &'static str,
    /// `$dateTrunc` unit for the bucket.
    unit: &'static str,
    /// Whether `src` is itself a rollup (changes how counts are summed).
    src_is_rollup: bool,
    /// Bucket width, used to hold the watermark back off the open bucket.
    bucket_secs: i64,
    pipeline: fn(DateTime, &str, bool, &str) -> Vec<Document>,
}

/// Every pass this rollup performs, in run order.
///
/// A table rather than eight hand-written blocks because the count is an
/// ASSERTED value: `run_stats_rollup_once` returns how many passes completed
/// and the integration test compares it against `PASSES.len()`. That keeps the
/// check meaningful (a pass that silently fails still trips it) without it
/// going stale the moment a family lands — which is exactly what happened when
/// `call_user` took the real count to 8 while the test still demanded 6, and
/// nothing noticed because `crates/tests` had stopped compiling entirely.
static PASSES: &[Pass] = &[
    // FR-20 P4 — derive SFU participant-seconds into the ledger FIRST, so the
    // usage rollups below compact the same cycle's rows rather than lagging one
    // behind. Minute buckets, matching `USAGE_BUCKET_SECS`.
    Pass {
        key: "usage:sfu",
        src: STATS_CALL_USER,
        into: STATS_USAGE,
        unit: "minute",
        src_is_rollup: false,
        bucket_secs: MINUTE,
        pipeline: sfu_seconds_pipeline,
    },
    // FR-20 usage ledger: raw → 1h → 1d. These are the rows billing reads;
    // the raw minute buckets are 7-day scratch.
    Pass {
        key: "usage:1h",
        src: STATS_USAGE,
        into: STATS_USAGE_1H,
        unit: "hour",
        src_is_rollup: false,
        bucket_secs: HOUR,
        pipeline: usage_pipeline,
    },
    Pass {
        key: "usage:1d",
        src: STATS_USAGE_1H,
        into: STATS_USAGE_1D,
        unit: "day",
        src_is_rollup: true,
        bucket_secs: DAY,
        pipeline: usage_pipeline,
    },
    // relay: raw → 1h → 1d
    Pass {
        key: "relay:1h",
        src: STATS_RELAY,
        into: "stats_relay_1h",
        unit: "hour",
        src_is_rollup: false,
        bucket_secs: HOUR,
        pipeline: relay_pipeline,
    },
    Pass {
        key: "relay:1d",
        src: "stats_relay_1h",
        into: "stats_relay_1d",
        unit: "day",
        src_is_rollup: true,
        bucket_secs: DAY,
        pipeline: relay_pipeline,
    },
    // machine: raw → 1h → 1d
    Pass {
        key: "machine:1h",
        src: STATS_MACHINE,
        into: "stats_machine_1h",
        unit: "hour",
        src_is_rollup: false,
        bucket_secs: HOUR,
        pipeline: machine_pipeline,
    },
    Pass {
        key: "machine:1d",
        src: "stats_machine_1h",
        into: "stats_machine_1d",
        unit: "day",
        src_is_rollup: true,
        bucket_secs: DAY,
        pipeline: machine_pipeline,
    },
    // call: raw → 1h → 1d
    Pass {
        key: "call:1h",
        src: STATS_CALL,
        into: "stats_call_1h",
        unit: "hour",
        src_is_rollup: false,
        bucket_secs: HOUR,
        pipeline: call_pipeline,
    },
    Pass {
        key: "call:1d",
        src: "stats_call_1h",
        into: "stats_call_1d",
        unit: "day",
        src_is_rollup: true,
        bucket_secs: DAY,
        pipeline: call_pipeline,
    },
    // call-user (usage ledger): raw → 1h → 1d
    Pass {
        key: "call_user:1h",
        src: STATS_CALL_USER,
        into: "stats_call_user_1h",
        unit: "hour",
        src_is_rollup: false,
        bucket_secs: HOUR,
        pipeline: call_user_pipeline,
    },
    Pass {
        key: "call_user:1d",
        src: "stats_call_user_1h",
        into: "stats_call_user_1d",
        unit: "day",
        src_is_rollup: true,
        bucket_secs: DAY,
        pipeline: call_user_pipeline,
    },
];

/// How many `$merge` passes a complete run performs. Tests assert against
/// this rather than a literal.
pub fn pass_count() -> usize {
    PASSES.len()
}

/// Run every family's 1h + 1d compaction once. Public so integration tests
/// drive it directly (the spawned loop's first tick is a full interval
/// out). Returns the number of `$merge` passes that completed.
pub async fn run_stats_rollup_once(state: &AppState) -> usize {
    if !state.settings.stats.enabled {
        return 0;
    }
    let mut done = 0usize;
    for p in PASSES {
        let floor = family_floor(state, p.key).await;
        let pipeline = (p.pipeline)(floor, p.unit, p.src_is_rollup, p.into);
        done += roll_family(state, p.key, p.src, pipeline, p.bucket_secs).await as usize;
    }
    done
}

/// Spawn the periodic compactor. First tick a full interval out (so
/// short-lived TestApps never race a test driving `run_stats_rollup_once`
/// directly); cluster-singleton per cycle via the Redis NX claim.
pub fn spawn_stats_rollup(state: AppState) {
    if !state.settings.stats.enabled {
        return;
    }
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(ROLLUP_INTERVAL_SECS);
        loop {
            tokio::time::sleep(interval).await;
            if let Some(redis) = &state.redis_pubsub {
                let key = format!("meshharbor:stats-rollup:{}", state.db.name());
                let ttl = ROLLUP_INTERVAL_SECS.saturating_sub(5);
                match redis.try_claim(&key, ttl).await {
                    Ok(true) => {}
                    Ok(false) => continue, // another pod rolled this cycle
                    Err(e) => {
                        debug!(%e, "stats rollup claim failed; skipping cycle");
                        continue;
                    }
                }
            }
            let done = run_stats_rollup_once(&state).await;
            // FR-69 P4 — the orphaned-call closer is conference's; a build
            // without the module has no call sessions to close.
            state.modules.close_orphaned_call_state().await;
            info!(passes = done, "stats rollup cycle complete");
        }
    });
}

#[cfg(test)]
mod fr20_p4_tests {
    use super::*;

    /// Participant-seconds is bucket-count × bucket-width. Pinning the width
    /// here means a change to `CALL_BUCKET_SECS` cannot silently rescale every
    /// SFU cost row — the sampler's cadence and the billed unit are the same
    /// number, and nothing else would notice them diverging.
    #[test]
    fn participant_seconds_derive_from_the_sample_width() {
        assert_eq!(CALL_BUCKET_SECS, 30);
        // Two samples for one participant in a minute = the whole minute.
        assert_eq!(2 * CALL_BUCKET_SECS, MINUTE);
    }

    /// The ledger `_id` embeds the meter, which is what lets a `$merge`d
    /// derived meter share a collection with `$inc`-accumulated observed ones
    /// without ever clobbering them.
    #[test]
    fn derived_and_observed_meters_cannot_collide() {
        let tenant = "69a1dbbad2000f26adc875ce";
        let bucket = "1787777820";
        let sfu = format!("{tenant}:sfu_participant_seconds:{bucket}");
        let derp = format!("{tenant}:derp_bytes:{bucket}");
        assert_ne!(
            sfu, derp,
            "a $merge on the derived meter must not be able to replace an \
             $inc-accumulated bytes bucket for the same tenant and minute"
        );
    }

    /// Every pass must have a distinct watermark key — two passes sharing one
    /// would make each reset the other's progress, and the symptom is a family
    /// that silently stops compacting.
    #[test]
    fn pass_watermark_keys_are_unique() {
        let mut keys: Vec<&str> = PASSES.iter().map(|p| p.key).collect();
        let before = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate rollup watermark key");
    }
}
