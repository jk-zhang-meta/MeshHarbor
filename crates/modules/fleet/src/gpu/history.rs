// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — GPU telemetry history buckets (`stats_gpu`, `stats_gpu_1h`,
//! `stats_gpu_1d`) and per-Linux-user GPU·h rollups (§7.5).

use std::collections::{HashMap, HashSet};

use bson::{DateTime, doc, oid::ObjectId};
use futures::TryStreamExt as _;
use meshharbor_remote_control::gpu::{
    GpuReport, GpuState, GpuStateThresholds, classify_gpu_state,
};
use mongodb::Database;
use serde::{Deserialize, Serialize};

pub const COLL_1M: &str = "stats_gpu";
pub const COLL_1H: &str = "stats_gpu_1h";
pub const COLL_1D: &str = "stats_gpu_1d";

pub const TTL_1M_SECS: u64 = 7 * 24 * 60 * 60;
pub const TTL_1H_SECS: u64 = 90 * 24 * 60 * 60;
pub const TTL_1D_SECS: u64 = 730 * 24 * 60 * 60;

/// Per-Linux-user accumulation inside a GPU time bucket.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserGpuRollup {
    /// GPU-seconds where this user held VRAM (>0 MiB or active process) on this card.
    #[serde(default)]
    pub held_secs: u64,
    /// GPU-seconds where this user's card had active utilization (`util >= idle_util_pct`).
    #[serde(default)]
    pub busy_secs: u64,
}

/// Persisted bucket document shared across `stats_gpu`, `stats_gpu_1h`, `stats_gpu_1d`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuBucketDoc {
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub uuid: String,
    pub ts: DateTime,
    #[serde(default)]
    pub samples: u32,
    #[serde(default)]
    pub util_samples: u32,
    #[serde(default)]
    pub util_sum: f64,
    #[serde(default)]
    pub util_wsum: f64,
    #[serde(default)]
    pub util_secs: u64,
    #[serde(default)]
    pub util_max: u8,
    #[serde(default)]
    pub mem_samples: u32,
    #[serde(default)]
    pub mem_used_sum: f64,
    #[serde(default)]
    pub mem_used_max: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_max: Option<i16>,
    #[serde(default)]
    pub power_samples: u32,
    #[serde(default)]
    pub power_sum: f64,
    #[serde(default)]
    pub free_samples: u32,
    #[serde(default)]
    pub held_idle_samples: u32,
    #[serde(default)]
    pub free_secs: u64,
    #[serde(default)]
    pub held_idle_secs: u64,
    #[serde(default)]
    pub sample_secs: u64,
    #[serde(default)]
    pub users: HashMap<String, UserGpuRollup>,
}

/// One point returned by `GET /api/tenant/{tid}/gpu/history`.
#[derive(Debug, Clone, Serialize)]
pub struct GpuHistoryPoint {
    pub ts_ms: i64,
    pub samples: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub util_avg: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub util_max: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_avg_mb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_max_mb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temp_max_c: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_avg_w: Option<f32>,
    pub free_ratio: f32,
    pub held_idle_ratio: f32,
}

/// One row returned by `GET /api/tenant/{tid}/gpu/users` & `/api/agent/self/gpu/users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuUserSummary {
    pub user: String,
    pub held_gpu_hours: f64,
    pub busy_gpu_hours: f64,
    pub live_gpus: u32,
    pub live_mem_mb: u64,
    pub hosts: Vec<String>,
}

/// Floor Unix seconds to a bucket boundary (`60`, `3600`, or `86400`).
pub fn floor_bucket_ms(now_s: i64, step_s: i64) -> i64 {
    let floored = now_s.div_euclid(step_s) * step_s;
    floored.saturating_mul(1000)
}

/// Sanitize a Linux username for Mongo dot-notation field keys.
fn safe_user_key(user: &str) -> String {
    let cleaned: String = user
        .chars()
        .map(|c| match c {
            '.' | '$' | '\0' => '_',
            other => other,
        })
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// Record one inbound `GpuReport` into 1-minute `stats_gpu` buckets.
pub async fn record_report_to_1m_bucket(
    db: &Database,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    report: &GpuReport,
    now_s: i64,
    thresholds: GpuStateThresholds,
) {
    let bucket_ts = DateTime::from_millis(floor_bucket_ms(now_s, 60));
    let step_secs = (u64::from(report.interval_ms) / 1000).clamp(1, 60);
    let coll = db.collection::<bson::Document>(COLL_1M);

    for g in &report.gpus {
        let state = classify_gpu_state(report.status, g, now_s, thresholds);
        let mut inc = doc! {
            "samples": 1i32,
            "sample_secs": step_secs as i64,
        };
        if let Some(u) = g.util_pct {
            inc.insert("util_samples", 1i32);
            inc.insert("util_sum", f64::from(u));
            inc.insert("util_wsum", f64::from(u) * step_secs as f64);
            inc.insert("util_secs", step_secs as i64);
        }
        if let Some(m) = g.mem_used_mb {
            inc.insert("mem_samples", 1i32);
            inc.insert("mem_used_sum", f64::from(m));
        }
        if let Some(p) = g.power_w {
            inc.insert("power_samples", 1i32);
            inc.insert("power_sum", f64::from(p));
        }
        if state == GpuState::Free {
            inc.insert("free_samples", 1i32);
            inc.insert("free_secs", step_secs as i64);
        }
        if state == GpuState::HeldIdle {
            inc.insert("held_idle_samples", 1i32);
            inc.insert("held_idle_secs", step_secs as i64);
        }

        // Attribute GPU-seconds to each distinct Linux user holding processes on this card.
        if let Some(procs) = &g.procs {
            let mut distinct_users: HashSet<String> = HashSet::new();
            for p in procs {
                if let Some(u) = p.user.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    distinct_users.insert(safe_user_key(u));
                }
            }
            let card_busy = g.util_pct.is_some_and(|u| u >= thresholds.idle_util_pct);
            for u in distinct_users {
                inc.insert(format!("users.{u}.held_secs"), step_secs as i64);
                if card_busy {
                    inc.insert(format!("users.{u}.busy_secs"), step_secs as i64);
                }
            }
        }

        let mut max_doc = doc! {};
        if let Some(u) = g.util_pct {
            max_doc.insert("util_max", i32::from(u));
        }
        if let Some(m) = g.mem_used_mb {
            max_doc.insert("mem_used_max", i64::from(m));
        }
        if let Some(t) = g.temp_c {
            max_doc.insert("temp_max", i32::from(t));
        }

        let mut set_doc = doc! {};
        if let Some(mt) = g.mem_total_mb {
            set_doc.insert("mem_total_mb", i64::from(mt));
        }

        let mut update = doc! {
            "$inc": inc,
            "$setOnInsert": {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "uuid": &g.uuid,
                "ts": bucket_ts,
            },
        };
        if !max_doc.is_empty() {
            update.insert("$max", max_doc);
        }
        if !set_doc.is_empty() {
            update.insert("$set", set_doc);
        }

        let filter = doc! {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "uuid": &g.uuid,
            "ts": bucket_ts,
        };
        if let Err(e) = coll.update_one(filter, update).upsert(true).await {
            tracing::debug!(%agent_id, uuid = %g.uuid, %e, "gpu history 1m upsert failed");
        }
    }
}

/// Roll up completed source buckets into coarser destination buckets (`1m -> 1h`
/// or `1h -> 1d`). Scans ONLY complete, boundary-aligned destination windows so
/// partial slices never overwrite historical totals.
pub async fn rollup_buckets(
    db: &Database,
    src_coll: &str,
    dst_coll: &str,
    dst_step_s: i64,
    since_s: i64,
    until_s: i64,
) -> Result<usize, mongodb::error::Error> {
    let start_s = if since_s.rem_euclid(dst_step_s) == 0 {
        since_s
    } else {
        (since_s.div_euclid(dst_step_s) + 1) * dst_step_s
    };
    let end_s = until_s.div_euclid(dst_step_s) * dst_step_s;
    if end_s <= start_s {
        return Ok(0);
    }
    let src = db.collection::<GpuBucketDoc>(src_coll);
    let mut cur = src
        .find(doc! {
            "ts": {
                "$gte": DateTime::from_millis(start_s * 1000),
                "$lt": DateTime::from_millis(end_s * 1000),
            }
        })
        .await?;

    let mut grouped: HashMap<(ObjectId, ObjectId, String, i64), GpuBucketDoc> = HashMap::new();
    while let Some(b) = cur.try_next().await? {
        let ts_s = b.ts.timestamp_millis() / 1000;
        let dst_ms = floor_bucket_ms(ts_s, dst_step_s);
        let key = (b.tenant_id, b.agent_id, b.uuid.clone(), dst_ms);
        let entry = grouped.entry(key).or_insert_with(|| GpuBucketDoc {
            tenant_id: b.tenant_id,
            agent_id: b.agent_id,
            uuid: b.uuid.clone(),
            ts: DateTime::from_millis(dst_ms),
            samples: 0,
            util_samples: 0,
            util_sum: 0.0,
            util_wsum: 0.0,
            util_secs: 0,
            util_max: 0,
            mem_samples: 0,
            mem_used_sum: 0.0,
            mem_used_max: 0,
            mem_total_mb: b.mem_total_mb,
            temp_max: b.temp_max,
            power_samples: 0,
            power_sum: 0.0,
            free_samples: 0,
            held_idle_samples: 0,
            free_secs: 0,
            held_idle_secs: 0,
            sample_secs: 0,
            users: HashMap::new(),
        });
        entry.samples = entry.samples.saturating_add(b.samples);
        entry.util_samples = entry.util_samples.saturating_add(b.util_samples);
        entry.util_sum += b.util_sum;
        entry.util_wsum += b.util_wsum;
        entry.util_secs = entry.util_secs.saturating_add(b.util_secs);
        entry.util_max = entry.util_max.max(b.util_max);
        entry.mem_samples = entry.mem_samples.saturating_add(b.mem_samples);
        entry.mem_used_sum += b.mem_used_sum;
        entry.mem_used_max = entry.mem_used_max.max(b.mem_used_max);
        if entry.mem_total_mb.is_none() {
            entry.mem_total_mb = b.mem_total_mb;
        }
        entry.temp_max = match (entry.temp_max, b.temp_max) {
            (Some(a), Some(c)) => Some(a.max(c)),
            (a, c) => a.or(c),
        };
        entry.power_samples = entry.power_samples.saturating_add(b.power_samples);
        entry.power_sum += b.power_sum;
        entry.free_samples = entry.free_samples.saturating_add(b.free_samples);
        entry.held_idle_samples = entry.held_idle_samples.saturating_add(b.held_idle_samples);
        entry.free_secs = entry.free_secs.saturating_add(b.free_secs);
        entry.held_idle_secs = entry.held_idle_secs.saturating_add(b.held_idle_secs);
        entry.sample_secs = entry.sample_secs.saturating_add(b.sample_secs);
        for (u, r) in b.users {
            let ur = entry.users.entry(u).or_default();
            ur.held_secs = ur.held_secs.saturating_add(r.held_secs);
            ur.busy_secs = ur.busy_secs.saturating_add(r.busy_secs);
        }
    }

    let dst = db.collection::<GpuBucketDoc>(dst_coll);
    let count = grouped.len();
    for doc_val in grouped.into_values() {
        let filter = doc! {
            "tenant_id": doc_val.tenant_id,
            "agent_id": doc_val.agent_id,
            "uuid": &doc_val.uuid,
            "ts": doc_val.ts,
        };
        dst.replace_one(filter, &doc_val).upsert(true).await?;
    }
    Ok(count)
}

/// Query time-series history for one `(agent_id, uuid)` over `1h | 24h | 7d | 30d`.
/// When `uuid` is `None`, aggregates cards by timestamp into one host-wide series.
pub async fn query_history(
    db: &Database,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    uuid: Option<&str>,
    range: &str,
) -> Result<Vec<GpuHistoryPoint>, mongodb::error::Error> {
    let now_s = chrono::Utc::now().timestamp();
    let (coll_name, since_s) = match range {
        "1h" => (COLL_1M, now_s - 3600),
        "24h" => (COLL_1M, now_s - 24 * 3600),
        "7d" => (COLL_1H, now_s - 7 * 86_400),
        "30d" => (COLL_1D, now_s - 30 * 86_400),
        _ => (COLL_1M, now_s - 24 * 3600),
    };

    let uuid_filter = uuid.map(str::trim).filter(|s| !s.is_empty());
    let mut filter = doc! {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "ts": { "$gte": DateTime::from_millis(since_s * 1000) },
    };
    if let Some(u) = uuid_filter {
        filter.insert("uuid", u);
    }

    let mut cur = db
        .collection::<GpuBucketDoc>(coll_name)
        .find(filter)
        .sort(doc! { "ts": 1 })
        .await?;

    if uuid_filter.is_some() {
        let mut out = Vec::new();
        while let Some(b) = cur.try_next().await? {
            let n = f64::from(b.samples.max(1));
            let util_avg = if b.util_secs > 0 {
                Some((b.util_wsum / b.util_secs as f64) as f32)
            } else if b.util_samples > 0 {
                Some((b.util_sum / f64::from(b.util_samples)) as f32)
            } else {
                None
            };
            let (free_ratio, held_idle_ratio) = if b.sample_secs > 0
                && (b.free_secs > 0 || b.held_idle_secs > 0 || (b.free_samples == 0 && b.held_idle_samples == 0))
            {
                (
                    (b.free_secs as f64 / b.sample_secs as f64) as f32,
                    (b.held_idle_secs as f64 / b.sample_secs as f64) as f32,
                )
            } else {
                (
                    (f64::from(b.free_samples) / n) as f32,
                    (f64::from(b.held_idle_samples) / n) as f32,
                )
            };
            out.push(GpuHistoryPoint {
                ts_ms: b.ts.timestamp_millis(),
                samples: b.samples,
                util_avg,
                util_max: (b.util_samples > 0 || b.util_secs > 0).then_some(b.util_max),
                mem_used_avg_mb: (b.mem_samples > 0)
                    .then(|| (b.mem_used_sum / f64::from(b.mem_samples)).round() as u32),
                mem_used_max_mb: (b.mem_samples > 0).then_some(b.mem_used_max),
                mem_total_mb: b.mem_total_mb,
                temp_max_c: b.temp_max,
                power_avg_w: (b.power_samples > 0)
                    .then(|| (b.power_sum / f64::from(b.power_samples)) as f32),
                free_ratio,
                held_idle_ratio,
            });
        }
        return Ok(out);
    }

    // All-GPUs view: aggregate per-card buckets at each timestamp into one
    // host-wide series using the SAME duration-weighted numerators/denominators
    // as the single-UUID path (mean util across cards, summed VRAM/power, max temp).
    #[derive(Default)]
    struct TsAgg {
        samples: u32,
        util_samples: u32,
        util_sum: f64,
        util_wsum: f64,
        util_secs: u64,
        util_max: u8,
        mem_used_avg_sum: f64,
        has_mem_used: bool,
        mem_used_max_sum: u32,
        mem_total_sum: u32,
        has_mem_total: bool,
        temp_max: Option<i16>,
        power_avg_sum: f64,
        has_power: bool,
        free_samples: u32,
        held_idle_samples: u32,
        free_secs: u64,
        held_idle_secs: u64,
        sample_secs: u64,
    }
    let mut by_ts: std::collections::BTreeMap<i64, TsAgg> = std::collections::BTreeMap::new();
    while let Some(b) = cur.try_next().await? {
        let a = by_ts.entry(b.ts.timestamp_millis()).or_default();
        a.samples = a.samples.saturating_add(b.samples);
        a.util_samples = a.util_samples.saturating_add(b.util_samples);
        a.util_sum += b.util_sum;
        if b.util_secs > 0 {
            a.util_wsum += b.util_wsum;
            a.util_secs = a.util_secs.saturating_add(b.util_secs);
        } else if b.util_samples > 0 {
            // Normalize legacy unweighted buckets before merging.
            let est_secs = u64::from(b.util_samples);
            a.util_wsum += b.util_sum;
            a.util_secs = a.util_secs.saturating_add(est_secs);
        }
        if b.util_samples > 0 || b.util_secs > 0 {
            a.util_max = a.util_max.max(b.util_max);
        }
        if b.mem_samples > 0 {
            a.mem_used_avg_sum += b.mem_used_sum / f64::from(b.mem_samples);
            a.mem_used_max_sum = a.mem_used_max_sum.saturating_add(b.mem_used_max);
            a.has_mem_used = true;
        }
        if let Some(mt) = b.mem_total_mb {
            a.mem_total_sum = a.mem_total_sum.saturating_add(mt);
            a.has_mem_total = true;
        }
        a.temp_max = match (a.temp_max, b.temp_max) {
            (Some(x), Some(y)) => Some(x.max(y)),
            (x, y) => x.or(y),
        };
        if b.power_samples > 0 {
            a.power_avg_sum += b.power_sum / f64::from(b.power_samples);
            a.has_power = true;
        }
        a.free_samples = a.free_samples.saturating_add(b.free_samples);
        a.held_idle_samples = a.held_idle_samples.saturating_add(b.held_idle_samples);
        if b.sample_secs > 0 {
            a.free_secs = a.free_secs.saturating_add(b.free_secs);
            a.held_idle_secs = a.held_idle_secs.saturating_add(b.held_idle_secs);
            a.sample_secs = a.sample_secs.saturating_add(b.sample_secs);
        } else if b.samples > 0 {
            a.free_secs = a.free_secs.saturating_add(u64::from(b.free_samples));
            a.held_idle_secs = a.held_idle_secs.saturating_add(u64::from(b.held_idle_samples));
            a.sample_secs = a.sample_secs.saturating_add(u64::from(b.samples));
        }
    }

    let out = by_ts
        .into_iter()
        .map(|(ts_ms, a)| {
            let n = f64::from(a.samples.max(1));
            let util_avg = if a.util_secs > 0 {
                Some((a.util_wsum / a.util_secs as f64) as f32)
            } else if a.util_samples > 0 {
                Some((a.util_sum / f64::from(a.util_samples)) as f32)
            } else {
                None
            };
            let (free_ratio, held_idle_ratio) = if a.sample_secs > 0 {
                (
                    (a.free_secs as f64 / a.sample_secs as f64) as f32,
                    (a.held_idle_secs as f64 / a.sample_secs as f64) as f32,
                )
            } else {
                (
                    (f64::from(a.free_samples) / n) as f32,
                    (f64::from(a.held_idle_samples) / n) as f32,
                )
            };
            GpuHistoryPoint {
                ts_ms,
                samples: a.samples,
                util_avg,
                util_max: (a.util_samples > 0 || a.util_secs > 0).then_some(a.util_max),
                mem_used_avg_mb: a.has_mem_used.then(|| a.mem_used_avg_sum.round() as u32),
                mem_used_max_mb: a.has_mem_used.then_some(a.mem_used_max_sum),
                mem_total_mb: a.has_mem_total.then_some(a.mem_total_sum),
                temp_max_c: a.temp_max,
                power_avg_w: a.has_power.then_some(a.power_avg_sum as f32),
                free_ratio,
                held_idle_ratio,
            }
        })
        .collect();
    Ok(out)
}

/// Aggregate per-Linux-user GPU·h held/busy over `24h | 7d | 30d` plus live
/// snapshot summary across authorized `(owner_tenant_id, host_label)` agents
/// (supporting cross-tenant shared GPU servers).
pub async fn query_users(
    db: &Database,
    visible_agents: &HashMap<ObjectId, (ObjectId, String)>,
    range: &str,
    live_reports: &HashMap<ObjectId, GpuReport>,
) -> Result<Vec<GpuUserSummary>, mongodb::error::Error> {
    let now_s = chrono::Utc::now().timestamp();
    let (coll_name, since_s) = match range {
        "24h" => (COLL_1M, now_s - 24 * 3600),
        "7d" => (COLL_1H, now_s - 7 * 86_400),
        "30d" => (COLL_1D, now_s - 30 * 86_400),
        _ => (COLL_1M, now_s - 24 * 3600),
    };

    let mut by_owner_tenant: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    for (&aid, &(owner_tid, _)) in visible_agents {
        by_owner_tenant.entry(owner_tid).or_default().push(aid);
    }
    let mut acc: HashMap<String, (u64, u64, u32, u64, HashSet<String>)> = HashMap::new();

    if !by_owner_tenant.is_empty() {
        let or_clauses: Vec<bson::Document> = by_owner_tenant
            .into_iter()
            .map(|(owner_tid, ids)| {
                doc! {
                    "tenant_id": owner_tid,
                    "agent_id": { "$in": ids },
                }
            })
            .collect();
        let mut cur = db
            .collection::<GpuBucketDoc>(coll_name)
            .find(doc! {
                "$or": or_clauses,
                "ts": { "$gte": DateTime::from_millis(since_s * 1000) },
            })
            .await?;
        while let Some(b) = cur.try_next().await? {
            let host = visible_agents
                .get(&b.agent_id)
                .map(|(_, name)| name.clone())
                .unwrap_or_else(|| b.agent_id.to_hex());
            for (u, r) in b.users {
                let entry = acc.entry(u).or_default();
                entry.0 = entry.0.saturating_add(r.held_secs);
                entry.1 = entry.1.saturating_add(r.busy_secs);
                entry.4.insert(host.clone());
            }
        }
    }

    // Overlay live snapshot counts (active GPUs & VRAM per user right now).
    for (aid, rep) in live_reports {
        let Some((_, host)) = visible_agents.get(aid) else {
            continue;
        };
        for g in &rep.gpus {
            let Some(procs) = &g.procs else { continue };
            let mut card_users: HashMap<String, u64> = HashMap::new();
            for p in procs {
                if let Some(u) = p.user.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    // Use the same sanitized key as historical rollups so usernames
                    // containing `.` or `$` do not split into two separate rows.
                    *card_users.entry(safe_user_key(u)).or_insert(0) += u64::from(p.mem_mb.unwrap_or(0));
                }
            }
            for (u, mem_mb) in card_users {
                let entry = acc.entry(u).or_default();
                entry.2 = entry.2.saturating_add(1);
                entry.3 = entry.3.saturating_add(mem_mb);
                entry.4.insert(host.clone());
            }
        }
    }

    let mut rows: Vec<GpuUserSummary> = acc
        .into_iter()
        .map(|(user, (held_s, busy_s, live_gpus, live_mem_mb, hosts))| {
            let mut hosts: Vec<String> = hosts.into_iter().collect();
            hosts.sort();
            GpuUserSummary {
                user,
                held_gpu_hours: (held_s as f64 / 3600.0 * 100.0).round() / 100.0,
                busy_gpu_hours: (busy_s as f64 / 3600.0 * 100.0).round() / 100.0,
                live_gpus,
                live_mem_mb,
                hosts,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.held_gpu_hours
            .total_cmp(&a.held_gpu_hours)
            .then_with(|| b.live_gpus.cmp(&a.live_gpus))
            .then_with(|| a.user.cmp(&b.user))
    });
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Persisted-doc guard (FR-139 §9, mirroring `sys_doc_carries_every_counter`):
    /// every counter field on [`GpuBucketDoc`] must survive BSON round-trip.
    #[test]
    fn fr139_gpu_bucket_doc_carries_every_counter() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            UserGpuRollup {
                held_secs: 3600,
                busy_secs: 2400,
            },
        );
        let orig = GpuBucketDoc {
            tenant_id: ObjectId::new(),
            agent_id: ObjectId::new(),
            uuid: "GPU-0001".to_string(),
            ts: DateTime::from_millis(1_762_700_040_000),
            samples: 12,
            util_samples: 10,
            util_sum: 780.0,
            util_wsum: 23400.0,
            util_secs: 300,
            util_max: 98,
            mem_samples: 12,
            mem_used_sum: 240_000.0,
            mem_used_max: 24_000,
            mem_total_mb: Some(24_576),
            temp_max: Some(74),
            power_samples: 11,
            power_sum: 3600.0,
            free_samples: 2,
            held_idle_samples: 1,
            free_secs: 60,
            held_idle_secs: 30,
            sample_secs: 60,
            users,
        };
        let bson_doc = bson::to_document(&orig).expect("to_document");
        for field in [
            "tenant_id",
            "agent_id",
            "uuid",
            "ts",
            "samples",
            "util_samples",
            "util_sum",
            "util_max",
            "mem_samples",
            "mem_used_sum",
            "mem_used_max",
            "mem_total_mb",
            "temp_max",
            "power_samples",
            "power_sum",
            "free_samples",
            "held_idle_samples",
            "sample_secs",
            "users",
        ] {
            assert!(bson_doc.contains_key(field), "missing persisted field {field}");
        }
        let back: GpuBucketDoc = bson::from_document(bson_doc).expect("from_document");
        assert_eq!(back, orig);
    }

    #[test]
    fn fr139_floor_bucket_ms_aligns_to_minute_hour_and_day() {
        assert_eq!(floor_bucket_ms(1_700_000_099, 60), 1_700_000_040_000);
        assert_eq!(floor_bucket_ms(1_700_000_099, 3600), 1_699_999_200_000);
        assert_eq!(floor_bucket_ms(86_400 + 123, 86_400), 86_400_000);
    }
}
