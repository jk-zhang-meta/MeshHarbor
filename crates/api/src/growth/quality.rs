// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P9a — remote-desktop quality from what is already recorded (spec
//! §3f): per UTC day and per agent version, the sessions that reached Active
//! against those that did not, by `end_reason`; the duration, peak frame
//! rate and RTT distributions; FR-22's time to first frame as p50/p90; and
//! crashes per 100 device-days. **Server only** — no remote-control code path
//! changes; every number is read from rows the product already writes.
//!
//! # Why a freeze
//!
//! Three of the four sources expire. `agent_logs` — where the browser's
//! `rc.connect` record carries `ttff_ms` (FR-22 part 4) and where an agent's
//! own batches say which version it ran — live **7 days**; `agent_crashes`
//! 90; `stats_machine_1d` 730; `remote_sessions` 25 months (its TTL since
//! 2026-10-17, `RemoteSession::TTL_SECONDS`). So a nightly
//! job (under the org-day fold's claim, [`super::org_daily`]) reads the last
//! three closed days and writes one row per `(day, scope, agent_version)`
//! into `growth_quality_daily` ([`GrowthQualityDao`]). Once the logs are
//! gone, the frozen row is the only place the day's time to first frame
//! exists — that is the point.
//!
//! # The rules, each a small function with a test
//!
//! * A session is counted on the day it was **requested** (`created_at`).
//!   It *reached Active* when `started_at` is set; it *never reached Active*
//!   when it ended without one; it is *pending* when the freeze saw it
//!   neither started nor ended ([`session_quality`]).
//! * Time to first frame is the `ttff_ms` of `first_frame` records from a
//!   **foreground** tab (`hidden: false`), on a **first attempt**
//!   (`attempt: 1`, `after_drop: false`) — the FR-22 doc's own mining filter
//!   ([`ttff_quality`]). A hidden tab's paint timing is invalid by the
//!   standing rule, and a retry measures the retry.
//! * A day's TTFF is measured only while **every** record of the day still
//!   exists ([`logs_complete`]): a day whose first rows have started to
//!   expire would give a biased sample, so it reads "not measured" instead.
//! * The **agent version** a session or a device ran is read from the
//!   device's own log batches — those carrying the session's id first, then
//!   the device's batches of that day — and only then from the device row's
//!   current `agent_version` ([`VersionIndex::resolve`]). A crash carries its
//!   version in its payload (`agentVersion`). A device no source can place
//!   is `unknown`.
//! * Both scopes are frozen — `external` with the exclusion set applied,
//!   `all` with nothing excluded — so `include_internal=true` is a different
//!   row, not a different code path. The set is the one at the freeze; the
//!   recompute window and `POST …/quality/backfill` re-freeze with the
//!   current one while the sources still hold the day.
//! * `None` is **not measured** (a module not mounted, logs expired), never
//!   0; a rate appears only from n = 30 (spec principle 5).
//!
//! The Quality view ([`get_quality`]) and the weekly roll-up read the frozen
//! rows through [`compute`]; the daily digest reads them for the day's TTFF
//! and its per-version table ([`super::digest`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::NaiveDate;
use meshharbor_db::models::agent_log::AgentLogBatch;
use meshharbor_services::dao::{
    growth_digest::ExcludedCounts,
    growth_quality::{
        ALL_VERSIONS, CarrierQuality, DURATION_EDGES_MS, Dist, EndReasonCount, FPS_EDGES,
        GrowthQualityDao, Pooled, QualityDay, RTT_EDGES_MS, Scope, SessionQuality, TTFF_EDGES_MS,
        TtffQuality, UNKNOWN_VERSION,
    },
};
use meshharbor_core::growth::ExclusionSet;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::{
    GrowthError,
    digest::{
        NotMeasured, SMALL_N, aggregate, day_str, dt_ms, excluded_ids, find_docs, parse_day,
        str_of, utc_date_of,
    },
    mounted,
    org_daily::due_range,
    read_key::GrowthAuth,
};
use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

/// What the first scheduled run on an empty collection fills: the digest's
/// 28-day window. Sessions and crashes exist for those days; TTFF and the
/// log-based version only for the days the logs still cover.
pub const FIRST_FILL_DAYS: i64 = 28;
/// A backfill never starts earlier than this (the stats rollups' horizon).
pub const BACKFILL_HORIZON_DAYS: i64 = 730;
/// The longest range one read answers.
pub const MAX_RANGE_DAYS: i64 = 400;
/// The browser record's `lines.target` (FR-22 part 4).
pub const RC_CONNECT_TARGET: &str = "rc.connect";
/// The `agent_logs` TTL, the horizon TTFF can be frozen within.
pub const LOG_TTL_DAYS: i64 = (AgentLogBatch::TTL_SECONDS / 86_400) as i64;

const DAY_MS: i64 = 86_400_000;
const LOG_TTL_MS: i64 = AgentLogBatch::TTL_SECONDS as i64 * 1000;

fn day_start_ms(day: NaiveDate) -> i64 {
    day.and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
        .timestamp_millis()
}

fn between(start_ms: i64, end_ms: i64) -> Document {
    doc! { "$gte": DateTime::from_millis(start_ms), "$lt": DateTime::from_millis(end_ms) }
}

/// Whether every `agent_logs` row of `day` still exists at `now`: the
/// earliest row of the day (created at its midnight) has not reached the
/// TTL. Past that, the day's sample is biased towards its late hours and
/// is not measured at all.
pub fn logs_complete(day: NaiveDate, now_ms: i64) -> bool {
    day_start_ms(day) + LOG_TTL_MS > now_ms
}

/// A number stored as any BSON numeric, rounded to an integer.
fn num_of(d: &Document, key: &str) -> Option<i64> {
    match d.get(key) {
        Some(Bson::Int32(v)) => Some(i64::from(*v)),
        Some(Bson::Int64(v)) => Some(*v),
        Some(Bson::Double(v)) if v.is_finite() => Some(v.round() as i64),
        _ => None,
    }
}

fn f64_of(d: &Document, key: &str) -> Option<f64> {
    match d.get(key) {
        Some(Bson::Double(v)) if v.is_finite() => Some(*v),
        Some(Bson::Int32(v)) => Some(f64::from(*v)),
        Some(Bson::Int64(v)) => Some(*v as f64),
        _ => None,
    }
}

// ── Sessions ─────────────────────────────────────────────────────────────

/// The carrier label of a row with none: a session from before P9c, from an
/// agent older than the field, or one that ended before the observation
/// landed. Never `direct`.
pub const UNKNOWN_CARRIER: &str = "unknown";

/// One `remote_sessions` row, the fields the quality rules read.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRow {
    pub id: ObjectId,
    pub agent_id: Option<ObjectId>,
    pub created_ms: i64,
    pub started_ms: Option<i64>,
    pub ended_ms: Option<i64>,
    pub end_reason: Option<String>,
    pub peak_fps: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    /// P9c — as the agent recorded it; `None` reads as [`UNKNOWN_CARRIER`].
    pub carrier: Option<String>,
}

/// From a projected document; `None` without an id or a `created_at`.
pub fn session_row(d: &Document) -> Option<SessionRow> {
    let stats = d.get_document("stats").ok();
    Some(SessionRow {
        id: d.get_object_id("_id").ok()?,
        agent_id: d.get_object_id("agent_id").ok(),
        created_ms: dt_ms(d, "created_at")?,
        started_ms: dt_ms(d, "started_at"),
        ended_ms: dt_ms(d, "ended_at"),
        end_reason: str_of(d, "end_reason"),
        peak_fps: stats.and_then(|s| f64_of(s, "peak_fps")),
        avg_rtt_ms: stats.and_then(|s| f64_of(s, "avg_rtt_ms")),
        carrier: str_of(d, "carrier").filter(|c| !c.is_empty()),
    })
}

/// The projection [`session_row`] reads.
pub fn session_projection() -> Document {
    doc! {
        "tenant_id": 1, "agent_id": 1, "created_at": 1, "started_at": 1, "ended_at": 1,
        "end_reason": 1, "stats.peak_fps": 1, "stats.avg_rtt_ms": 1, "carrier": 1,
    }
}

/// The rule: what became of the sessions requested in a window.
pub fn session_quality<'a>(rows: impl IntoIterator<Item = &'a SessionRow>) -> SessionQuality {
    let mut q = SessionQuality {
        requested: 0,
        reached_active: 0,
        not_reached: 0,
        pending: 0,
        by_end_reason: Vec::new(),
        duration_ms: Dist::of(Vec::new(), DURATION_EDGES_MS),
        peak_fps: Dist::of(Vec::new(), FPS_EDGES),
        avg_rtt_ms: Dist::of(Vec::new(), RTT_EDGES_MS),
        by_carrier: Vec::new(),
    };
    let mut by: BTreeMap<(bool, String), i64> = BTreeMap::new();
    let (mut durations, mut fps, mut rtt) = (Vec::new(), Vec::new(), Vec::new());
    // P9c — per carrier: (sessions, durations, fps, rtt) of the Active ones.
    /// P9c — one carrier's accumulator over the rows: the Active sessions
    /// that rode it and their samples.
    #[derive(Default)]
    struct CarrierAcc {
        sessions: i64,
        durations: Vec<i64>,
        fps: Vec<i64>,
        rtt: Vec<i64>,
    }
    let mut carriers: BTreeMap<String, CarrierAcc> = BTreeMap::new();
    for r in rows {
        q.requested += 1;
        let active = r.started_ms.is_some();
        let duration = match (r.started_ms, r.ended_ms) {
            (Some(s), Some(e)) => {
                q.reached_active += 1;
                let d = (e - s).max(0);
                durations.push(d);
                Some(d)
            }
            (Some(_), None) => {
                q.reached_active += 1;
                None
            }
            (None, Some(_)) => {
                q.not_reached += 1;
                None
            }
            (None, None) => {
                q.pending += 1;
                None
            }
        };
        let reason = match r.ended_ms {
            Some(_) => r
                .end_reason
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".to_string()),
            None => "open".to_string(),
        };
        *by.entry((active, reason)).or_insert(0) += 1;
        if active {
            let f = r.peak_fps.filter(|f| *f > 0.0).map(|f| f.round() as i64);
            let m = r.avg_rtt_ms.filter(|m| *m > 0.0).map(|m| m.round() as i64);
            fps.extend(f);
            rtt.extend(m);
            let slot = carriers
                .entry(
                    r.carrier
                        .clone()
                        .unwrap_or_else(|| UNKNOWN_CARRIER.to_string()),
                )
                .or_default();
            slot.sessions += 1;
            slot.durations.extend(duration);
            slot.fps.extend(f);
            slot.rtt.extend(m);
        }
    }
    q.by_carrier = carriers
        .into_iter()
        .map(|(carrier, acc)| CarrierQuality {
            carrier,
            reached_active: acc.sessions,
            duration_ms: Dist::of(acc.durations, DURATION_EDGES_MS),
            peak_fps: Dist::of(acc.fps, FPS_EDGES),
            avg_rtt_ms: Dist::of(acc.rtt, RTT_EDGES_MS),
        })
        .collect();
    q.by_carrier.sort_by(|a, b| {
        b.reached_active
            .cmp(&a.reached_active)
            .then_with(|| a.carrier.cmp(&b.carrier))
    });
    q.by_end_reason = by
        .into_iter()
        .map(|((reached_active, reason), count)| EndReasonCount {
            reached_active,
            reason,
            count,
        })
        .collect();
    sort_reasons(&mut q.by_end_reason);
    q.duration_ms = Dist::of(durations, DURATION_EDGES_MS);
    q.peak_fps = Dist::of(fps, FPS_EDGES);
    q.avg_rtt_ms = Dist::of(rtt, RTT_EDGES_MS);
    q
}

fn sort_reasons(rows: &mut [EndReasonCount]) {
    rows.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| b.reached_active.cmp(&a.reached_active))
            .then_with(|| a.reason.cmp(&b.reason))
    });
}

// ── Time to first frame ──────────────────────────────────────────────────

/// One browser `rc.connect` record (FR-22 part 4), the fields the rule reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtffRecord {
    /// The batch's `session_id`, when the attempt got that far.
    pub session_id: Option<ObjectId>,
    pub agent_id: Option<ObjectId>,
    /// The device's org when it is not the page's (FR-52).
    pub agent_org_id: Option<ObjectId>,
    pub outcome: String,
    pub hidden: bool,
    pub attempt: i64,
    pub after_drop: bool,
    pub ttff_ms: Option<i64>,
}

/// From `{session_id?, f: <lines.fields>}`. A record without `hidden` is
/// read as hidden — its validity cannot be told, and the rule only ever
/// admits a record that says it was in the foreground.
pub fn ttff_record(d: &Document) -> Option<TtffRecord> {
    let f = d.get_document("f").ok()?;
    let oid = |s: Option<String>| s.and_then(|s| ObjectId::parse_str(s).ok());
    Some(TtffRecord {
        session_id: oid(str_of(d, "session_id")),
        agent_id: oid(str_of(f, "agent_id")),
        agent_org_id: oid(str_of(f, "agent_org_id")),
        outcome: str_of(f, "outcome")?,
        hidden: f.get_bool("hidden").unwrap_or(true),
        attempt: num_of(f, "attempt").unwrap_or(1),
        after_drop: f.get_bool("after_drop").unwrap_or(false),
        ttff_ms: num_of(f, "ttff_ms"),
    })
}

/// The rule: the TTFF distribution over the foreground, first-attempt
/// `first_frame` records, and what was set aside.
pub fn ttff_quality<'a>(records: impl IntoIterator<Item = &'a TtffRecord>) -> TtffQuality {
    let mut hidden = 0;
    let mut later = 0;
    let mut outcomes: BTreeMap<String, i64> = BTreeMap::new();
    let mut samples = Vec::new();
    for r in records {
        if r.hidden {
            hidden += 1;
            continue;
        }
        *outcomes.entry(r.outcome.clone()).or_insert(0) += 1;
        if r.outcome != "first_frame" {
            continue;
        }
        if r.attempt != 1 || r.after_drop {
            later += 1;
            continue;
        }
        if let Some(ms) = r.ttff_ms.filter(|m| *m >= 0) {
            samples.push(ms);
        }
    }
    TtffQuality {
        dist: Dist::of(samples, TTFF_EDGES_MS),
        hidden,
        later_attempts: later,
        outcomes,
    }
}

// ── Versions ─────────────────────────────────────────────────────────────

/// A release string as numbers, so `0.4.137` sorts after `0.4.99`.
fn version_rank(v: &str) -> (Vec<u64>, String) {
    (
        v.split(['.', '-'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect(),
        v.to_string(),
    )
}

fn latest(versions: &BTreeSet<String>) -> Option<String> {
    versions.iter().max_by_key(|v| version_rank(v)).cloned()
}

/// Which version a device ran on the day, from three sources in order.
#[derive(Debug, Default)]
pub struct VersionIndex {
    /// The versions the device's own batches reported DURING a session.
    pub by_session: HashMap<ObjectId, BTreeSet<String>>,
    /// The versions the device's batches reported that day.
    pub by_agent_day: HashMap<ObjectId, BTreeSet<String>>,
    /// The device row's current `agent_version` (tombstones included).
    pub by_agent_row: HashMap<ObjectId, String>,
}

impl VersionIndex {
    /// The session's own logs, then the device's logs of the day (the newest
    /// when it updated mid-day), then the device row; else `unknown`.
    pub fn resolve(&self, session: Option<&ObjectId>, agent: Option<&ObjectId>) -> String {
        if let Some(v) = session
            .and_then(|s| self.by_session.get(s))
            .and_then(latest)
        {
            return v;
        }
        if let Some(a) = agent {
            if let Some(v) = self.by_agent_day.get(a).and_then(latest) {
                return v;
            }
            if let Some(v) = self.by_agent_row.get(a).filter(|v| !v.is_empty()) {
                return v.clone();
            }
        }
        UNKNOWN_VERSION.to_string()
    }
}

/// Read the index for `day`: one aggregate over the agents' own log batches
/// of the day (and the next, for a session that ran past midnight), and the
/// rows of every device seen.
async fn version_index(
    state: &AppState,
    day: NaiveDate,
    agents: &HashSet<ObjectId>,
) -> Result<VersionIndex, GrowthError> {
    let start = day_start_ms(day);
    let end = start + DAY_MS;
    let mut index = VersionIndex::default();
    let groups = aggregate(
        state,
        "agent_logs",
        vec![
            doc! { "$match": {
                "source": "agent",
                "created_at": between(start, end + DAY_MS),
                "agent_version": { "$type": "string" },
            } },
            doc! { "$group": {
                "_id": { "a": "$agent_id", "v": "$agent_version", "s": "$session_id" },
                "first": { "$min": "$created_at" },
            } },
        ],
    )
    .await?;
    for g in &groups {
        let Ok(id) = g.get_document("_id") else {
            continue;
        };
        let (Ok(agent), Some(version)) = (id.get_object_id("a"), str_of(id, "v")) else {
            continue;
        };
        if version.is_empty() {
            continue;
        }
        if let Some(session) = str_of(id, "s").and_then(|s| ObjectId::parse_str(s).ok()) {
            index
                .by_session
                .entry(session)
                .or_default()
                .insert(version.clone());
        }
        if dt_ms(g, "first").is_some_and(|t| t < end) {
            index.by_agent_day.entry(agent).or_default().insert(version);
        }
    }
    if !agents.is_empty() {
        let ids: Vec<ObjectId> = agents.iter().copied().collect();
        let rows = find_docs(
            state,
            "agents",
            doc! { "_id": { "$in": ids } },
            doc! { "agent_version": 1 },
        )
        .await?;
        for d in &rows {
            if let (Ok(id), Some(v)) = (d.get_object_id("_id"), str_of(d, "agent_version")) {
                index.by_agent_row.insert(id, v);
            }
        }
    }
    Ok(index)
}

// ── The freeze ───────────────────────────────────────────────────────────

#[derive(Default)]
struct Group<'a> {
    sessions: Vec<&'a SessionRow>,
    ttff: Vec<&'a TtffRecord>,
    crashes: i64,
    devices: i64,
}

/// One day's rows for one scope, read from whichever sources are mounted.
/// Pure over the database; stores nothing.
pub async fn compute_day(
    state: &AppState,
    day: NaiveDate,
    set: &ExclusionSet,
    scope: Scope,
    now: DateTime,
) -> Result<Vec<QualityDay>, GrowthError> {
    let now_ms = now.timestamp_millis();
    let start = day_start_ms(day);
    let end = start + DAY_MS;
    let excluded = excluded_ids(&set.tenants);
    let remote = mounted(state, "remote");
    let fleet = mounted(state, "fleet");
    let mut agents: HashSet<ObjectId> = HashSet::new();

    let sessions: Vec<SessionRow> = if remote {
        find_docs(
            state,
            "remote_sessions",
            doc! { "created_at": between(start, end), "tenant_id": { "$nin": excluded.clone() } },
            session_projection(),
        )
        .await?
        .iter()
        .filter_map(session_row)
        .collect()
    } else {
        Vec::new()
    };
    agents.extend(sessions.iter().filter_map(|s| s.agent_id));

    // The version each crash payload named.
    let mut crashes: Vec<String> = Vec::new();
    let mut devices: Vec<ObjectId> = Vec::new();
    let mut ttff: Vec<TtffRecord> = Vec::new();
    let ttff_measured = fleet && logs_complete(day, now_ms);
    if fleet {
        // The payload is `camelCase` on the wire and in the row
        // (`AgentCrashPayload`, flattened); `agent_version` is read too for
        // a row written by hand.
        for d in find_docs(
            state,
            "agent_crashes",
            doc! { "reported_at": between(start, end), "tenant_id": { "$nin": excluded.clone() } },
            doc! { "agentVersion": 1, "agent_version": 1 },
        )
        .await?
        {
            crashes.push(
                str_of(&d, "agentVersion")
                    .or_else(|| str_of(&d, "agent_version"))
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| UNKNOWN_VERSION.to_string()),
            );
        }
        for d in aggregate(
            state,
            "stats_machine_1d",
            vec![
                doc! { "$match": {
                    "ts": between(start, end),
                    "online_minutes": { "$gt": 0 },
                    "tenant_id": { "$nin": excluded.clone() },
                } },
                doc! { "$group": { "_id": "$agent_id" } },
            ],
        )
        .await?
        {
            if let Ok(a) = d.get_object_id("_id") {
                devices.push(a);
                agents.insert(a);
            }
        }
        if ttff_measured {
            let docs = aggregate(
                state,
                "agent_logs",
                vec![
                    doc! { "$match": {
                        "source": "browser",
                        "lines.target": RC_CONNECT_TARGET,
                        "created_at": between(start, end),
                        "tenant_id": { "$nin": excluded.clone() },
                    } },
                    doc! { "$unwind": "$lines" },
                    doc! { "$match": { "lines.target": RC_CONNECT_TARGET } },
                    doc! { "$project": { "session_id": 1, "f": "$lines.fields" } },
                ],
            )
            .await?;
            ttff = docs
                .iter()
                .filter_map(ttff_record)
                .filter(|r| !r.agent_org_id.is_some_and(|o| set.tenants.contains(&o)))
                .collect();
            agents.extend(ttff.iter().filter_map(|r| r.agent_id));
        }
    }

    let index = if fleet {
        version_index(state, day, &agents).await?
    } else {
        VersionIndex::default()
    };

    let mut groups: BTreeMap<String, Group<'_>> = BTreeMap::new();
    let mut all = Group::default();
    for s in &sessions {
        let v = index.resolve(Some(&s.id), s.agent_id.as_ref());
        groups.entry(v).or_default().sessions.push(s);
        all.sessions.push(s);
    }
    for r in &ttff {
        let v = index.resolve(r.session_id.as_ref(), r.agent_id.as_ref());
        groups.entry(v).or_default().ttff.push(r);
        all.ttff.push(r);
    }
    for v in &crashes {
        groups.entry(v.clone()).or_default().crashes += 1;
        all.crashes += 1;
    }
    for a in &devices {
        let v = index.resolve(None, Some(a));
        groups.entry(v).or_default().devices += 1;
        all.devices += 1;
    }

    let label = day_str(day);
    let row = |version: &str, g: &Group<'_>| QualityDay {
        id: QualityDay::id_of(&label, scope, version),
        day: label.clone(),
        day_start: DateTime::from_millis(start),
        scope,
        agent_version: version.to_string(),
        sessions: remote.then(|| session_quality(g.sessions.iter().copied())),
        ttff: ttff_measured.then(|| ttff_quality(g.ttff.iter().copied())),
        crashes: fleet.then_some(g.crashes),
        device_days: fleet.then_some(g.devices),
        computed_at: now,
    };
    let mut rows = vec![row(ALL_VERSIONS, &all)];
    rows.extend(groups.iter().map(|(v, g)| row(v.as_str(), g)));
    Ok(rows)
}

/// What a freeze did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FreezeReport {
    pub since: String,
    pub until: String,
    pub days: u32,
    pub rows: u64,
}

/// Freeze `[from, to]`, both scopes, day by day: the exclusion set loaded
/// once, each day's rows replaced and pruned per scope.
pub async fn freeze_range(
    state: &AppState,
    from: NaiveDate,
    to: NaiveDate,
    now: DateTime,
) -> Result<FreezeReport, GrowthError> {
    let mut report = FreezeReport {
        since: day_str(from),
        until: day_str(to),
        days: 0,
        rows: 0,
    };
    if from > to {
        return Ok(report);
    }
    let set = ExclusionSet::load(&state.core).await?;
    let none = ExclusionSet::none();
    let dao = GrowthQualityDao::new(&state.db);
    let mut day = from;
    while day <= to {
        for (scope, s) in [(Scope::External, &set), (Scope::All, &none)] {
            let rows = compute_day(state, day, s, scope, now).await?;
            report.rows += dao.replace_day(&day_str(day), scope, &rows).await?;
        }
        report.days += 1;
        day = day.succ_opt().expect("a next day exists");
    }
    Ok(report)
}

/// Clamp a requested backfill: never before `today − 730 d`, never today.
pub fn backfill_range(
    now: DateTime,
    since: NaiveDate,
    until: Option<NaiveDate>,
) -> Result<(NaiveDate, NaiveDate), String> {
    let today = utc_date_of(now);
    let yesterday = today - chrono::Duration::days(1);
    let floor = today - chrono::Duration::days(BACKFILL_HORIZON_DAYS);
    let from = since.max(floor);
    let to = until.unwrap_or(yesterday).min(yesterday);
    if from > to {
        return Err(format!(
            "nothing to freeze: the range must hold a closed day between {} and {}",
            day_str(floor),
            day_str(yesterday)
        ));
    }
    Ok((from, to))
}

/// The scheduled body, under the org-day fold's nightly claim: an empty
/// collection is filled over [`FIRST_FILL_DAYS`] once, then the last
/// [`super::org_daily::RECOMPUTE_DAYS`] closed days are re-frozen (a session
/// open at midnight, a late crash report, the exclusion list edited).
pub async fn freeze_scheduled(
    state: &AppState,
    now: DateTime,
) -> Result<FreezeReport, GrowthError> {
    if GrowthQualityDao::new(&state.db).is_empty().await? {
        let since = utc_date_of(now) - chrono::Duration::days(FIRST_FILL_DAYS);
        if let Ok((from, to)) = backfill_range(now, since, None) {
            info!(since = %day_str(from), until = %day_str(to), "growth quality: first fill");
            let r = freeze_range(state, from, to, now).await?;
            info!(rows = r.rows, "growth quality: first fill done");
        }
    }
    let (from, to) = due_range(now);
    freeze_range(state, from, to, now).await
}

// ── Reading the frozen rows ──────────────────────────────────────────────

/// P9c — one carrier over a window: the Active sessions that rode it and
/// their pooled distributions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarrierWindow {
    pub carrier: String,
    pub reached_active: i64,
    pub duration_ms: Pooled,
    pub peak_fps: Pooled,
    pub avg_rtt_ms: Pooled,
}

/// A window's sessions, pooled from the frozen days.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionWindow {
    pub requested: i64,
    pub reached_active: i64,
    pub not_reached: i64,
    pub pending: i64,
    /// `reached_active / requested`, only from [`SMALL_N`] requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reached_share: Option<f64>,
    pub by_end_reason: Vec<EndReasonCount>,
    pub duration_ms: Pooled,
    pub peak_fps: Pooled,
    pub avg_rtt_ms: Pooled,
    /// P9c — the Active sessions by carrier, most first; `unknown` for a
    /// session with none recorded (never read as direct).
    #[serde(default)]
    pub by_carrier: Vec<CarrierWindow>,
    /// Frozen days with sessions measured.
    pub days: i64,
}

/// A window's time to first frame, pooled from the frozen days.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TtffWindow {
    pub n: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p90_ms: Option<i64>,
    /// `true` for one day's exact values; `false` for an estimate from the
    /// summed daily histograms.
    pub exact: bool,
    /// Frozen days whose TTFF was measured (logs still complete).
    pub days_measured: i64,
    pub hidden: i64,
    pub later_attempts: i64,
    pub outcomes: BTreeMap<String, i64>,
}

/// One version over a range — or every version, as [`ALL_VERSIONS`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionQuality {
    pub agent_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<SessionWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttff: Option<TtffWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crashes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_days: Option<i64>,
    /// `crashes × 100 / device_days`, only from [`SMALL_N`] device-days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crashes_per_100_device_days: Option<f64>,
    /// Frozen days this version appears on.
    pub days: i64,
}

/// One frozen day, every version — the series the chart draws.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DayQuality {
    pub day: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reached_active: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_reached: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_p50_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttff_n: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttff_p50_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttff_p90_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crashes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_days: Option<i64>,
}

/// The Quality view: a closed range of frozen days, every version pooled,
/// each version, and the day series.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityReport {
    pub enabled: bool,
    /// `YYYY-MM-DD`, inclusive.
    pub since: String,
    /// `YYYY-MM-DD`, inclusive.
    pub until: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub n_floor: i64,
    /// Days in the range.
    pub days: i64,
    /// Days of the range with a frozen row.
    pub frozen_days: i64,
    /// The `agent_logs` TTL: a day is frozen with TTFF only inside it.
    pub ttff_horizon_days: i64,
    /// Why there is nothing: no frozen day in the range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_measured: Option<NotMeasured>,
    /// Every version, pooled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<VersionQuality>,
    /// Newest release first; `unknown` last.
    pub by_agent_version: Vec<VersionQuality>,
    pub series: Vec<DayQuality>,
}

/// A rate only from the n floor, to two decimals.
pub fn rate_if_enough(num: i64, den: i64, scale: f64) -> Option<f64> {
    (den >= SMALL_N).then(|| (num as f64 * scale / den as f64 * 100.0).round() / 100.0)
}

/// Pool one version's frozen days.
pub fn fold_version(version: &str, rows: &[&QualityDay]) -> VersionQuality {
    let sess: Vec<&SessionQuality> = rows.iter().filter_map(|r| r.sessions.as_ref()).collect();
    let sessions = (!sess.is_empty()).then(|| {
        let mut by: BTreeMap<(bool, String), i64> = BTreeMap::new();
        for s in &sess {
            for c in &s.by_end_reason {
                *by.entry((c.reached_active, c.reason.clone())).or_insert(0) += c.count;
            }
        }
        let mut by_end_reason: Vec<EndReasonCount> = by
            .into_iter()
            .map(|((reached_active, reason), count)| EndReasonCount {
                reached_active,
                reason,
                count,
            })
            .collect();
        sort_reasons(&mut by_end_reason);
        let requested: i64 = sess.iter().map(|s| s.requested).sum();
        let reached_active: i64 = sess.iter().map(|s| s.reached_active).sum();
        // P9c — each carrier's days, pooled.
        let mut per_carrier: BTreeMap<&str, Vec<&CarrierQuality>> = BTreeMap::new();
        for s in &sess {
            for c in &s.by_carrier {
                per_carrier.entry(c.carrier.as_str()).or_default().push(c);
            }
        }
        let mut by_carrier: Vec<CarrierWindow> = per_carrier
            .into_iter()
            .map(|(carrier, parts)| CarrierWindow {
                carrier: carrier.to_string(),
                reached_active: parts.iter().map(|c| c.reached_active).sum(),
                duration_ms: Dist::pool(parts.iter().map(|c| &c.duration_ms)),
                peak_fps: Dist::pool(parts.iter().map(|c| &c.peak_fps)),
                avg_rtt_ms: Dist::pool(parts.iter().map(|c| &c.avg_rtt_ms)),
            })
            .collect();
        by_carrier.sort_by(|a, b| {
            b.reached_active
                .cmp(&a.reached_active)
                .then_with(|| a.carrier.cmp(&b.carrier))
        });
        SessionWindow {
            requested,
            reached_active,
            not_reached: sess.iter().map(|s| s.not_reached).sum(),
            pending: sess.iter().map(|s| s.pending).sum(),
            reached_share: rate_if_enough(reached_active, requested, 1.0),
            by_end_reason,
            duration_ms: Dist::pool(sess.iter().map(|s| &s.duration_ms)),
            peak_fps: Dist::pool(sess.iter().map(|s| &s.peak_fps)),
            avg_rtt_ms: Dist::pool(sess.iter().map(|s| &s.avg_rtt_ms)),
            by_carrier,
            days: sess.len() as i64,
        }
    });
    let measured: Vec<&TtffQuality> = rows.iter().filter_map(|r| r.ttff.as_ref()).collect();
    let ttff = (!measured.is_empty()).then(|| {
        let pooled = Dist::pool(measured.iter().map(|t| &t.dist));
        let mut outcomes: BTreeMap<String, i64> = BTreeMap::new();
        for t in &measured {
            for (k, v) in &t.outcomes {
                *outcomes.entry(k.clone()).or_insert(0) += v;
            }
        }
        TtffWindow {
            n: pooled.n,
            p50_ms: pooled.p50,
            p90_ms: pooled.p90,
            exact: pooled.exact,
            days_measured: measured.len() as i64,
            hidden: measured.iter().map(|t| t.hidden).sum(),
            later_attempts: measured.iter().map(|t| t.later_attempts).sum(),
            outcomes,
        }
    });
    let sum = |f: fn(&QualityDay) -> Option<i64>| -> Option<i64> {
        let vals: Vec<i64> = rows.iter().filter_map(|r| f(r)).collect();
        (!vals.is_empty()).then(|| vals.iter().sum())
    };
    let crashes = sum(|r| r.crashes);
    let device_days = sum(|r| r.device_days);
    VersionQuality {
        agent_version: version.to_string(),
        sessions,
        ttff,
        crashes,
        device_days,
        crashes_per_100_device_days: match (crashes, device_days) {
            (Some(c), Some(d)) => rate_if_enough(c, d, 100.0),
            _ => None,
        },
        days: rows.len() as i64,
    }
}

fn day_quality(r: &QualityDay) -> DayQuality {
    DayQuality {
        day: r.day.clone(),
        requested: r.sessions.as_ref().map(|s| s.requested),
        reached_active: r.sessions.as_ref().map(|s| s.reached_active),
        not_reached: r.sessions.as_ref().map(|s| s.not_reached),
        pending: r.sessions.as_ref().map(|s| s.pending),
        duration_p50_ms: r.sessions.as_ref().and_then(|s| s.duration_ms.p50),
        ttff_n: r.ttff.as_ref().map(|t| t.dist.n),
        ttff_p50_ms: r.ttff.as_ref().and_then(|t| t.dist.p50),
        ttff_p90_ms: r.ttff.as_ref().and_then(|t| t.dist.p90),
        crashes: r.crashes,
        device_days: r.device_days,
    }
}

/// Newest release first, `unknown` last — the order every per-version
/// table uses (the view, the digest, the weekly roll-up).
pub fn version_order(a: &str, b: &str) -> std::cmp::Ordering {
    let unk = |v: &str| v == UNKNOWN_VERSION;
    unk(a)
        .cmp(&unk(b))
        .then_with(|| version_rank(b).cmp(&version_rank(a)))
}

fn sort_versions(rows: &mut [VersionQuality]) {
    rows.sort_by(|a, b| version_order(&a.agent_version, &b.agent_version));
}

/// The report for `[since, until]` (closed days) from the frozen rows of
/// the scope `include_internal` names. `set` is reported, not applied: the
/// rows were frozen with their own.
pub async fn compute(
    state: &AppState,
    set: &ExclusionSet,
    since: NaiveDate,
    until: NaiveDate,
    include_internal: bool,
    _now: DateTime,
) -> Result<QualityReport, GrowthError> {
    let scope = Scope::of_include_internal(include_internal);
    let rows = GrowthQualityDao::new(&state.db)
        .rows_between(scope, &day_str(since), &day_str(until))
        .await?;
    let (users, tenants) = set.counts();
    let mut by_version: BTreeMap<String, Vec<&QualityDay>> = BTreeMap::new();
    for r in &rows {
        by_version
            .entry(r.agent_version.clone())
            .or_default()
            .push(r);
    }
    let all = by_version.remove(ALL_VERSIONS).unwrap_or_default();
    let totals = (!all.is_empty()).then(|| fold_version(ALL_VERSIONS, &all));
    let mut by_agent_version: Vec<VersionQuality> = by_version
        .iter()
        .map(|(v, rows)| fold_version(v, rows))
        .collect();
    sort_versions(&mut by_agent_version);
    let series: Vec<DayQuality> = all.iter().map(|r| day_quality(r)).collect();
    let days = (until - since).num_days() + 1;
    Ok(QualityReport {
        enabled: true,
        since: day_str(since),
        until: day_str(until),
        include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        n_floor: SMALL_N,
        days,
        frozen_days: all.len() as i64,
        ttff_horizon_days: LOG_TTL_DAYS,
        not_measured: rows.is_empty().then(|| {
            NotMeasured::now(
                "no frozen day in the range — the nightly quality freeze has not covered it yet \
                 (POST /api/admin/growth/quality/backfill re-freezes what the sources still hold)",
            )
        }),
        totals,
        by_agent_version,
        series,
    })
}

// ── Routes ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct QualityQuery {
    /// `YYYY-MM-DD`, inclusive. Default: 27 days before `until`.
    #[serde(default)]
    pub since: Option<String>,
    /// `YYYY-MM-DD`, inclusive; an open day is clamped to yesterday.
    /// Default: yesterday.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

/// The range a query names: closed days only, at most [`MAX_RANGE_DAYS`].
pub fn query_range(
    since: Option<&str>,
    until: Option<&str>,
    now: DateTime,
) -> Result<(NaiveDate, NaiveDate), String> {
    let yesterday = utc_date_of(now) - chrono::Duration::days(1);
    let until = match until {
        Some(s) => parse_day(s)?.min(yesterday),
        None => yesterday,
    };
    let since = match since {
        Some(s) => parse_day(s)?,
        None => until - chrono::Duration::days(27),
    };
    if since > until {
        return Err(format!(
            "since ({}) is after until ({})",
            day_str(since),
            day_str(until)
        ));
    }
    if (until - since).num_days() >= MAX_RANGE_DAYS {
        return Err(format!("the range must be under {MAX_RANGE_DAYS} days"));
    }
    Ok((since, until))
}

/// `GET /api/admin/growth/quality?since&until&include_internal` — a platform
/// admin, or a read key (P10: `GrowthAuth` is the gate).
pub async fn get_quality(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<QualityQuery>,
) -> Result<Json<QualityReport>, ApiError> {
    let now = DateTime::now();
    let (since, until) =
        query_range(q.since.as_deref(), q.until.as_deref(), now).map_err(ApiError::BadRequest)?;
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    Ok(Json(
        compute(&state, &set, since, until, q.include_internal, now).await?,
    ))
}

#[derive(Debug, Deserialize)]
pub struct BackfillQuery {
    pub since: String,
    #[serde(default)]
    pub until: Option<String>,
}

/// `POST /api/admin/growth/quality/backfill?since=YYYY-MM-DD&until=` —
/// re-freeze a closed range, both scopes, with the current exclusion set;
/// clamped to the horizon; never today. TTFF comes back only for days the
/// logs still cover.
pub async fn backfill_route(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<BackfillQuery>,
) -> Result<Json<FreezeReport>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let now = DateTime::now();
    let since = parse_day(&q.since).map_err(ApiError::BadRequest)?;
    let until = match q.until.as_deref() {
        Some(s) => Some(parse_day(s).map_err(ApiError::BadRequest)?),
        None => None,
    };
    let (from, to) = backfill_range(now, since, until).map_err(ApiError::BadRequest)?;
    let report = freeze_range(&state, from, to, now).await?;
    info!(
        admin = %auth.user_id, since = %report.since, until = %report.until, rows = report.rows,
        "growth quality backfill"
    );
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        parse_day(s).unwrap()
    }

    fn ms(s: &str) -> i64 {
        DateTime::parse_rfc3339_str(s).unwrap().timestamp_millis()
    }

    fn session(
        created: &str,
        started: Option<&str>,
        ended: Option<&str>,
        reason: Option<&str>,
    ) -> SessionRow {
        SessionRow {
            id: ObjectId::new(),
            agent_id: Some(ObjectId::new()),
            created_ms: ms(created),
            started_ms: started.map(ms),
            ended_ms: ended.map(ms),
            end_reason: reason.map(str::to_string),
            peak_fps: None,
            avg_rtt_ms: None,
            carrier: None,
        }
    }

    /// Reached Active, never reached, pending: three disjoint outcomes of
    /// the sessions requested; the duration is measured on the Active ones
    /// that ended; a frame rate or RTT of 0 is "not reported", not a sample.
    #[test]
    fn sessions_are_classed_by_what_became_of_them() {
        let mut ok = session(
            "2026-10-15T10:00:00Z",
            Some("2026-10-15T10:00:03Z"),
            Some("2026-10-15T10:30:03Z"),
            Some("controller_hangup"),
        );
        ok.peak_fps = Some(29.6);
        ok.avg_rtt_ms = Some(41.4);
        let mut dropped = session(
            "2026-10-15T11:00:00Z",
            Some("2026-10-15T11:00:02Z"),
            Some("2026-10-15T11:01:02Z"),
            Some("agent_disconnect"),
        );
        dropped.peak_fps = Some(0.0);
        let refused = session(
            "2026-10-15T12:00:00Z",
            None,
            Some("2026-10-15T12:00:30Z"),
            Some("consent_timeout"),
        );
        let gave_up = session(
            "2026-10-15T13:00:00Z",
            None,
            Some("2026-10-15T13:00:20Z"),
            Some("controller_hangup"),
        );
        let running = session(
            "2026-10-15T23:50:00Z",
            Some("2026-10-15T23:50:04Z"),
            None,
            None,
        );
        let waiting = session("2026-10-15T23:59:00Z", None, None, None);
        let q = session_quality([&ok, &dropped, &refused, &gave_up, &running, &waiting]);
        assert_eq!(
            (q.requested, q.reached_active, q.not_reached, q.pending),
            (6, 3, 2, 1)
        );
        assert_eq!(q.duration_ms.n, 2);
        assert_eq!(q.duration_ms.p50, Some(60_000));
        assert_eq!(q.duration_ms.p90, Some(1_800_000));
        assert_eq!((q.peak_fps.n, q.peak_fps.p50), (1, Some(30)));
        assert_eq!((q.avg_rtt_ms.n, q.avg_rtt_ms.p50), (1, Some(41)));
        let cell = |active: bool, reason: &str| {
            q.by_end_reason
                .iter()
                .find(|c| c.reached_active == active && c.reason == reason)
                .map(|c| c.count)
        };
        assert_eq!(cell(true, "controller_hangup"), Some(1));
        assert_eq!(cell(true, "agent_disconnect"), Some(1));
        assert_eq!(cell(false, "consent_timeout"), Some(1));
        assert_eq!(cell(false, "controller_hangup"), Some(1));
        assert_eq!(cell(true, "open"), Some(1));
        assert_eq!(cell(false, "open"), Some(1));
        assert_eq!(q.by_end_reason.len(), 6);
        let empty = session_quality(std::iter::empty());
        assert_eq!((empty.requested, empty.duration_ms.n), (0, 0));
    }

    fn record(
        outcome: &str,
        hidden: bool,
        attempt: i64,
        after_drop: bool,
        ttff: Option<i64>,
    ) -> TtffRecord {
        TtffRecord {
            session_id: None,
            agent_id: None,
            agent_org_id: None,
            outcome: outcome.into(),
            hidden,
            attempt,
            after_drop,
            ttff_ms: ttff,
        }
    }

    /// The FR-22 filter: foreground, first attempt, no drop, painted. A
    /// hidden tab is set aside whatever its outcome; a retry is counted as
    /// a retry, not as a sample.
    #[test]
    fn ttff_takes_foreground_first_attempt_paints_only() {
        let records = [
            record("first_frame", false, 1, false, Some(2736)),
            record("first_frame", false, 1, false, Some(1200)),
            record("first_frame", true, 1, false, Some(90)),
            record("first_frame", false, 2, false, Some(400)),
            record("first_frame", false, 1, true, Some(500)),
            record("abandoned", false, 1, false, None),
            record("retried", false, 1, false, None),
            record("closed", true, 1, false, None),
        ];
        let t = ttff_quality(records.iter());
        assert_eq!(t.dist.n, 2);
        assert_eq!(t.dist.p50, Some(1200));
        assert_eq!(t.dist.p90, Some(2736));
        assert_eq!(t.hidden, 2);
        assert_eq!(t.later_attempts, 2);
        assert_eq!(t.outcomes.get("first_frame"), Some(&4));
        assert_eq!(t.outcomes.get("abandoned"), Some(&1));
        assert_eq!(t.outcomes.get("retried"), Some(&1));
        assert_eq!(t.outcomes.get("closed"), None, "hidden: set aside");
    }

    /// The projected shape parses with its ids as hex strings, numbers of
    /// any BSON width, and a record that does not say it was visible is
    /// read as hidden.
    #[test]
    fn a_browser_record_parses_from_its_projection() {
        let s = ObjectId::new();
        let a = ObjectId::new();
        let r = ttff_record(&doc! {
            "session_id": s.to_hex(),
            "f": {
                "v": 1_i32, "outcome": "first_frame", "attempt": 1_i64, "after_drop": false,
                "hidden": false, "stalled_at": Bson::Null, "ttff_ms": 2736.0, "agent_id": a.to_hex(),
                "marks": { "first_frame": 2736_i64 },
            },
        })
        .unwrap();
        assert_eq!((r.session_id, r.agent_id), (Some(s), Some(a)));
        assert_eq!(
            (r.ttff_ms, r.attempt, r.hidden, r.after_drop),
            (Some(2736), 1, false, false)
        );
        let r =
            ttff_record(&doc! { "f": { "outcome": "abandoned", "agent_id": "not-hex" } }).unwrap();
        assert!(r.hidden, "no `hidden` → not admissible");
        assert_eq!(r.agent_id, None);
        assert!(
            ttff_record(&doc! { "f": { "attempt": 1 } }).is_none(),
            "no outcome"
        );
    }

    #[test]
    fn a_session_row_reads_its_stats_and_tolerates_their_absence() {
        let id = ObjectId::new();
        let r = session_row(&doc! {
            "_id": id, "agent_id": ObjectId::new(),
            "created_at": DateTime::from_millis(ms("2026-10-15T10:00:00Z")),
            "started_at": DateTime::from_millis(ms("2026-10-15T10:00:02Z")),
            "ended_at": Bson::Null, "end_reason": Bson::Null,
            "stats": { "peak_fps": 29.9, "avg_rtt_ms": 12_i32 },
        })
        .unwrap();
        assert_eq!(r.id, id);
        assert_eq!(r.ended_ms, None);
        assert_eq!(r.end_reason, None);
        assert_eq!((r.peak_fps, r.avg_rtt_ms), (Some(29.9), Some(12.0)));
        let bare =
            session_row(&doc! { "_id": ObjectId::new(), "created_at": DateTime::now() }).unwrap();
        assert_eq!((bare.peak_fps, bare.agent_id), (None, None));
        assert!(
            session_row(&doc! { "_id": ObjectId::new() }).is_none(),
            "no created_at"
        );
    }

    /// The session's own logs win, then the device's logs of the day (the
    /// newest when it updated), then the device row; releases compare as
    /// numbers, not strings.
    #[test]
    fn a_version_is_resolved_from_the_nearest_source() {
        let (s, a, b) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let mut index = VersionIndex::default();
        index
            .by_session
            .insert(s, ["0.4.136".to_string()].into_iter().collect());
        index.by_agent_day.insert(
            a,
            ["0.4.99".to_string(), "0.4.137".to_string()]
                .into_iter()
                .collect(),
        );
        index.by_agent_row.insert(a, "0.4.138".into());
        index.by_agent_row.insert(b, "0.4.120".into());
        assert_eq!(index.resolve(Some(&s), Some(&a)), "0.4.136");
        assert_eq!(
            index.resolve(None, Some(&a)),
            "0.4.137",
            "the day's newest, not the row"
        );
        assert_eq!(index.resolve(Some(&ObjectId::new()), Some(&b)), "0.4.120");
        assert_eq!(index.resolve(None, Some(&ObjectId::new())), UNKNOWN_VERSION);
        assert_eq!(index.resolve(None, None), UNKNOWN_VERSION);
        assert!(version_rank("0.4.137") > version_rank("0.4.99"));
        assert!(version_rank("0.4.137") < version_rank("0.5.0"));
    }

    /// A day is frozen with TTFF only while its earliest log row still
    /// exists: the TTL counts from each row's own `created_at`.
    #[test]
    fn ttff_is_measured_only_while_the_days_logs_are_complete() {
        let day = d("2026-10-08");
        assert!(logs_complete(day, ms("2026-10-09T00:03:00Z")));
        assert!(logs_complete(day, ms("2026-10-14T23:59:00Z")));
        assert!(!logs_complete(day, ms("2026-10-15T00:00:00Z")));
        assert!(!logs_complete(day, ms("2026-10-15T03:00:00Z")));
        assert_eq!(LOG_TTL_DAYS, 7);
    }

    #[test]
    fn a_query_range_is_closed_days_defaulting_to_the_last_twenty_eight() {
        let now = DateTime::parse_rfc3339_str("2026-10-16T10:00:00Z").unwrap();
        assert_eq!(
            query_range(None, None, now).unwrap(),
            (d("2026-09-18"), d("2026-10-15"))
        );
        assert_eq!(
            query_range(Some("2026-10-01"), Some("2026-10-20"), now).unwrap(),
            (d("2026-10-01"), d("2026-10-15")),
            "an open day is clamped to yesterday"
        );
        assert!(query_range(Some("2026-10-16"), None, now).is_err());
        assert!(query_range(Some("2025-01-01"), None, now).is_err());
        assert!(query_range(Some("yesterday"), None, now).is_err());
        assert_eq!(
            backfill_range(now, d("2026-10-01"), Some(d("2027-01-01"))).unwrap(),
            (d("2026-10-01"), d("2026-10-15"))
        );
        assert!(backfill_range(now, d("2026-10-16"), None).is_err());
    }

    fn frozen(
        day: &str,
        version: &str,
        sessions: Option<SessionQuality>,
        ttff: Option<TtffQuality>,
        crashes: Option<i64>,
        devices: Option<i64>,
    ) -> QualityDay {
        QualityDay {
            id: QualityDay::id_of(day, Scope::External, version),
            day: day.into(),
            day_start: DateTime::from_millis(day_start_ms(d(day))),
            scope: Scope::External,
            agent_version: version.into(),
            sessions,
            ttff,
            crashes,
            device_days: devices,
            computed_at: DateTime::now(),
        }
    }

    /// Pooling a version over days sums the counts, estimates the window's
    /// percentiles, keeps the rate behind the n floor, and leaves an
    /// unmeasured part `None`.
    #[test]
    fn a_version_folds_over_its_frozen_days() {
        let s1 = session_quality([&session(
            "2026-10-14T10:00:00Z",
            Some("2026-10-14T10:00:01Z"),
            Some("2026-10-14T10:10:01Z"),
            Some("controller_hangup"),
        )]);
        let s2 = session_quality([&session(
            "2026-10-15T10:00:00Z",
            None,
            Some("2026-10-15T10:00:30Z"),
            Some("consent_timeout"),
        )]);
        let t1 = ttff_quality([&record("first_frame", false, 1, false, Some(1000))]);
        let rows = [
            frozen(
                "2026-10-14",
                "0.4.137",
                Some(s1),
                Some(t1),
                Some(1),
                Some(20),
            ),
            frozen("2026-10-15", "0.4.137", Some(s2), None, Some(2), Some(25)),
        ];
        let v = fold_version("0.4.137", &rows.iter().collect::<Vec<_>>());
        let s = v.sessions.unwrap();
        assert_eq!(
            (s.requested, s.reached_active, s.not_reached, s.days),
            (2, 1, 1, 2)
        );
        assert_eq!(s.reached_share, None, "under the floor");
        assert_eq!((s.duration_ms.n, s.duration_ms.exact), (1, false));
        let t = v.ttff.unwrap();
        assert_eq!(
            (t.n, t.p50_ms, t.exact, t.days_measured),
            (1, Some(1000), true, 1)
        );
        assert_eq!((v.crashes, v.device_days), (Some(3), Some(45)));
        assert_eq!(v.crashes_per_100_device_days, Some(6.67));
        assert_eq!(v.days, 2);

        let bare = fold_version("x", &[&frozen("2026-10-15", "x", None, None, None, None)]);
        assert!(bare.sessions.is_none() && bare.ttff.is_none());
        assert_eq!(
            (
                bare.crashes,
                bare.device_days,
                bare.crashes_per_100_device_days
            ),
            (None, None, None)
        );
        assert_eq!(rate_if_enough(15, 30, 1.0), Some(0.5));
        assert_eq!(rate_if_enough(15, 29, 1.0), None);
    }

    #[test]
    fn versions_list_newest_first_and_unknown_last() {
        let mut rows: Vec<VersionQuality> = ["0.4.99", "unknown", "0.4.137", "0.4.120"]
            .iter()
            .map(|v| fold_version(v, &[]))
            .collect();
        sort_versions(&mut rows);
        let names: Vec<&str> = rows.iter().map(|r| r.agent_version.as_str()).collect();
        assert_eq!(names, ["0.4.137", "0.4.120", "0.4.99", "unknown"]);
        assert_eq!(FIRST_FILL_DAYS, 28);
        assert_eq!(super::super::org_daily::RECOMPUTE_DAYS, 3);
    }
}
