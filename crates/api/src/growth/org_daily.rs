// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P2 — `growth_org_daily`: one row per org per UTC day with any
//! activity, folded by a singleton nightly job (spec §3d).
//!
//! Four of the sources expire at 90 days (`tunnel_audit`, `ssh_audit`,
//! `exec_audit`, `ws_sessions`) while retention needs a year, so the job
//! folds every source into one row per org-day while the rows exist, and
//! the funnel, the cohorts and the org views read the fold. The fold is a
//! derivation of durable rows: recomputing it is idempotent.
//!
//! Mechanics:
//!
//! * singleton per UTC day through the DB-name-scoped Redis `NX` claim the
//!   stats rollup uses (`roomler:growth-org-daily:<db>:<day>`); without
//!   Redis a pod runs locally, once per day;
//! * the last [`RECOMPUTE_DAYS`] closed days are recomputed on every run
//!   (a session open at midnight, a late audit row); today is never written;
//! * per day, replace-then-prune ([`GrowthDao::replace_day`]): rows are
//!   upserted on `_id`, then the day's rows of orgs with no activity any
//!   more are deleted, so a reader never meets an empty day;
//! * the backfill route and the first run on an empty collection are both
//!   bounded ([`RETENTION_DAYS`], [`BACKFILL_HORIZON_DAYS`], [`CHUNK_DAYS`]);
//! * the exclusion set is applied at READ time by the views, never here, so
//!   `include_internal=true` is the same code path.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{DateTime, Document, doc, oid::ObjectId};
use chrono::NaiveDate;
use meshharbor_services::dao::growth::{GrowthDao, OrgDay};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{
    GrowthError,
    digest::{
        aggregate, day_str, dt_ms, find_docs, i64_of, minutes, overlap_ms, parse_day, utc_date_of,
    },
    mounted,
    value::{self, ValueKind},
};
use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

/// Closed days recomputed by every run.
pub const RECOMPUTE_DAYS: i64 = 3;
/// The scheduler's cadence.
pub const LOOP_INTERVAL_SECS: u64 = 60 * 60;
/// A pod that just booted waits this long before its first tick.
pub const FIRST_TICK_DELAY_SECS: u64 = 3 * 60;
/// The per-day claim's lifetime (the key names the day).
pub const CLAIM_TTL_SECS: u64 = 24 * 60 * 60;
/// The collection's retention (spec D8): a backfill never starts earlier.
pub const RETENTION_DAYS: i64 = 25 * 30;
/// What the first run on an empty collection fills: the longest source
/// horizon (`call_sessions`, `stats_events`: 730 d).
pub const BACKFILL_HORIZON_DAYS: i64 = 730;
/// Days per chunk of a backfill — one set of source reads each.
pub const CHUNK_DAYS: i64 = 31;

/// The horizon must fit the retention, or the first fill would write days the
/// TTL immediately reaps. A compile-time invariant, not a runtime assert.
const _: () = assert!(BACKFILL_HORIZON_DAYS <= RETENTION_DAYS);

const DAY_MS: i64 = 86_400_000;

fn day_start_ms(day: NaiveDate) -> i64 {
    day.and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
        .timestamp_millis()
}

fn day_of_ms(ms: i64) -> NaiveDate {
    utc_date_of(DateTime::from_millis(ms))
}

fn next_day(day: NaiveDate) -> NaiveDate {
    day.succ_opt().expect("a date in range")
}

fn between_dt(start_ms: i64, end_ms: i64) -> Document {
    doc! { "$gte": DateTime::from_millis(start_ms), "$lt": DateTime::from_millis(end_ms) }
}

/// `"%Y-%m-%d"` of a date field, for a `$group` by day.
fn day_expr(field: &str) -> Document {
    doc! { "$dateToString": { "format": "%Y-%m-%d", "date": field } }
}

/// One org-day's accumulators.
#[derive(Debug, Default)]
pub struct Accum {
    pub rc_sessions: i64,
    pub rc_ms: i64,
    pub controllers: HashSet<ObjectId>,
    pub calls: i64,
    pub call_secs: i64,
    pub tunnel_flows: i64,
    pub ssh_sessions: i64,
    pub exec_runs: i64,
    pub devices: HashSet<ObjectId>,
    pub members: HashSet<ObjectId>,
    pub kinds: BTreeSet<ValueKind>,
}

/// `(tenant, day)` → accumulators, for one range.
pub type Fold = BTreeMap<(ObjectId, NaiveDate), Accum>;

fn slot(fold: &mut Fold, tenant: ObjectId, day: NaiveDate) -> &mut Accum {
    fold.entry((tenant, day)).or_default()
}

/// Fold one remote-desktop session into the days of `[from, to]`: its
/// minutes on every day it overlaps (a session spanning midnight is
/// split), its count, controller and value on the day it STARTED. `ended`
/// is `None` for a session still open (clamped at `now`).
#[allow(clippy::too_many_arguments)]
pub fn fold_rc_session(
    fold: &mut Fold,
    from: NaiveDate,
    to: NaiveDate,
    tenant: ObjectId,
    controller: Option<ObjectId>,
    started_ms: i64,
    ended_ms: Option<i64>,
    now_ms: i64,
) {
    let s = started_ms;
    let e = ended_ms.unwrap_or(now_ms).max(s);
    let (range_start, range_end) = (day_start_ms(from), day_start_ms(to) + DAY_MS);
    let mut day = day_of_ms(s.max(range_start));
    while day <= to && day_start_ms(day) < e {
        let lo = day_start_ms(day);
        let ms = overlap_ms(s, e, lo, lo + DAY_MS);
        if ms > 0 {
            let a = slot(fold, tenant, day);
            a.rc_ms += ms;
            if let Some(c) = controller {
                a.members.insert(c);
            }
        }
        day = next_day(day);
    }
    if (range_start..range_end).contains(&s) {
        let a = slot(fold, tenant, day_of_ms(s));
        a.rc_sessions += 1;
        if let Some(c) = controller {
            a.controllers.insert(c);
            a.members.insert(c);
        }
        if value::rc_session_is_value(s, e) {
            a.kinds.insert(ValueKind::Rc);
        }
    }
}

/// The rows of a fold, stamped `computed_at`.
pub fn rows_of(fold: Fold, computed_at: DateTime) -> Vec<OrgDay> {
    fold.into_iter()
        .map(|((tenant, day), a)| {
            let day_s = day_str(day);
            OrgDay {
                id: OrgDay::id_of(&tenant, &day_s),
                tenant_id: tenant,
                day: day_s,
                day_start: DateTime::from_millis(day_start_ms(day)),
                rc_sessions: a.rc_sessions,
                rc_session_minutes: minutes(a.rc_ms),
                rc_controllers: a.controllers.len() as i64,
                calls: a.calls,
                call_participant_minutes: minutes(a.call_secs * 1000),
                tunnel_flows: a.tunnel_flows,
                ssh_sessions: a.ssh_sessions,
                exec_runs: a.exec_runs,
                devices_online: a.devices.len() as i64,
                members_active: a.members.len() as i64,
                value: !a.kinds.is_empty(),
                value_kinds: a.kinds.iter().map(|k| k.as_str().to_string()).collect(),
                computed_at,
            }
        })
        .collect()
}

/// A `$group` by `(tenant, day)` with a count: `[(tenant, day, n)]`.
fn tenant_day_counts(rows: &[Document]) -> Vec<(ObjectId, NaiveDate, i64)> {
    rows.iter()
        .filter_map(|d| {
            let id = d.get_document("_id").ok()?;
            let tenant = id.get_object_id("t").ok()?;
            let day = parse_day(id.get_str("d").ok()?).ok()?;
            Some((tenant, day, i64_of(d, "n")))
        })
        .collect()
}

/// A `$group` by `(tenant, day, member)`: `[(tenant, day, member)]`.
fn tenant_day_members(rows: &[Document], member_key: &str) -> Vec<(ObjectId, NaiveDate, ObjectId)> {
    rows.iter()
        .filter_map(|d| {
            let id = d.get_document("_id").ok()?;
            let tenant = id.get_object_id("t").ok()?;
            let day = parse_day(id.get_str("d").ok()?).ok()?;
            let member = id.get_object_id(member_key).ok()?;
            Some((tenant, day, member))
        })
        .collect()
}

/// Every org-day of `[from, to]` (inclusive), read from whichever sources
/// are mounted. Pure over the database; stores nothing.
pub async fn compute_range(
    state: &AppState,
    from: NaiveDate,
    to: NaiveDate,
    now: DateTime,
) -> Result<Vec<OrgDay>, GrowthError> {
    let now_ms = now.timestamp_millis();
    let (start_ms, end_ms) = (day_start_ms(from), day_start_ms(to) + DAY_MS);
    let range = between_dt(start_ms, end_ms);
    let mut fold = Fold::new();

    if mounted(state, "remote") {
        let docs = find_docs(
            state,
            "remote_sessions",
            doc! {
                "started_at": { "$ne": bson::Bson::Null, "$lt": DateTime::from_millis(end_ms) },
                "$or": [
                    { "ended_at": bson::Bson::Null },
                    { "ended_at": { "$gte": DateTime::from_millis(start_ms) } },
                ],
            },
            doc! { "tenant_id": 1, "started_at": 1, "ended_at": 1, "controller_user_id": 1 },
        )
        .await?;
        for d in &docs {
            let (Some(s), Ok(tenant)) = (dt_ms(d, "started_at"), d.get_object_id("tenant_id"))
            else {
                continue;
            };
            fold_rc_session(
                &mut fold,
                from,
                to,
                tenant,
                d.get_object_id("controller_user_id").ok(),
                s,
                dt_ms(d, "ended_at"),
                now_ms,
            );
        }
    }

    if mounted(state, "conference") {
        let docs = find_docs(
            state,
            "call_sessions",
            doc! { "started_at": range.clone() },
            doc! { "tenant_id": 1, "started_at": 1, "peak_participants": 1, "participant_seconds": 1 },
        )
        .await?;
        for d in &docs {
            let (Some(s), Ok(tenant)) = (dt_ms(d, "started_at"), d.get_object_id("tenant_id"))
            else {
                continue;
            };
            let a = slot(&mut fold, tenant, day_of_ms(s));
            a.calls += 1;
            a.call_secs += i64_of(d, "participant_seconds");
            if value::call_is_value(i64_of(d, "peak_participants")) {
                a.kinds.insert(ValueKind::Call);
            }
        }
    }

    let count_by_day = |filter: Document| {
        vec![
            doc! { "$match": filter },
            doc! { "$group": {
                "_id": { "t": "$tenant_id", "d": day_expr("$at") },
                "n": { "$sum": 1 },
            } },
        ]
    };
    if mounted(state, "network") {
        let flows = aggregate(
            state,
            "tunnel_audit",
            count_by_day(value::tunnel_flow_filter(range.clone())),
        )
        .await?;
        for (tenant, day, n) in tenant_day_counts(&flows) {
            let a = slot(&mut fold, tenant, day);
            a.tunnel_flows += n;
            if n > 0 {
                a.kinds.insert(ValueKind::Tunnel);
            }
        }
        let grants = aggregate(
            state,
            "ssh_audit",
            count_by_day(value::ssh_session_filter(range.clone())),
        )
        .await?;
        for (tenant, day, n) in tenant_day_counts(&grants) {
            let a = slot(&mut fold, tenant, day);
            a.ssh_sessions += n;
            if n > 0 {
                a.kinds.insert(ValueKind::Ssh);
            }
        }
    }

    if mounted(state, "fleet") {
        let runs = aggregate(
            state,
            "exec_audit",
            count_by_day(value::exec_run_filter(range.clone())),
        )
        .await?;
        for (tenant, day, n) in tenant_day_counts(&runs) {
            slot(&mut fold, tenant, day).exec_runs += n;
        }
        // Devices online: a presence transition to `online` that day, or a
        // daily machine rollup with online minutes (a device online all day
        // has no transition that day).
        let online = aggregate(
            state,
            "stats_events",
            vec![
                doc! { "$match": { "presence": "online", "ts": range.clone() } },
                doc! { "$group": { "_id": { "t": "$tenant_id", "a": "$agent_id", "d": day_expr("$ts") } } },
            ],
        )
        .await?;
        for (tenant, day, agent) in tenant_day_members(&online, "a") {
            slot(&mut fold, tenant, day).devices.insert(agent);
        }
        let rolled = aggregate(
            state,
            "stats_machine_1d",
            vec![
                doc! { "$match": { "ts": range.clone(), "online_minutes": { "$gt": 0 } } },
                doc! { "$group": { "_id": { "t": "$tenant_id", "a": "$agent_id", "d": day_expr("$ts") } } },
            ],
        )
        .await?;
        for (tenant, day, agent) in tenant_day_members(&rolled, "a") {
            slot(&mut fold, tenant, day).devices.insert(agent);
        }
    }

    // Members active: anyone who opened a socket for the org that day (the
    // controllers of the day's sessions were added above).
    let sockets = aggregate(
        state,
        "ws_sessions",
        vec![
            doc! { "$match": { "started_at": range, "tenant_id": { "$ne": bson::Bson::Null } } },
            doc! { "$group": { "_id": { "t": "$tenant_id", "u": "$user_id", "d": day_expr("$started_at") } } },
        ],
    )
    .await?;
    for (tenant, day, user) in tenant_day_members(&sockets, "u") {
        slot(&mut fold, tenant, day).members.insert(user);
    }

    Ok(rows_of(fold, now))
}

/// Write the rows of `[from, to]`, day by day, pruning what vanished.
pub async fn write_range(
    state: &AppState,
    from: NaiveDate,
    to: NaiveDate,
    rows: Vec<OrgDay>,
) -> Result<u64, GrowthError> {
    let dao = GrowthDao::new(&state.db);
    let mut by_day: BTreeMap<String, Vec<OrgDay>> = BTreeMap::new();
    for r in rows {
        by_day.entry(r.day.clone()).or_default().push(r);
    }
    let mut written = 0u64;
    let mut day = from;
    while day <= to {
        let key = day_str(day);
        let rows = by_day.remove(&key).unwrap_or_default();
        written += dao.replace_day(&key, &rows).await?;
        day = next_day(day);
    }
    Ok(written)
}

/// What a run or a backfill did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RangeReport {
    pub since: String,
    pub until: String,
    pub days: u32,
    pub rows: u64,
    pub chunks: u32,
}

/// Recompute `[from, to]` in [`CHUNK_DAYS`] chunks.
pub async fn recompute_range(
    state: &AppState,
    from: NaiveDate,
    to: NaiveDate,
    now: DateTime,
) -> Result<RangeReport, GrowthError> {
    let mut report = RangeReport {
        since: day_str(from),
        until: day_str(to),
        days: 0,
        rows: 0,
        chunks: 0,
    };
    if from > to {
        return Ok(report);
    }
    report.days = ((to - from).num_days() + 1) as u32;
    let mut chunk_from = from;
    while chunk_from <= to {
        let chunk_to = (chunk_from + chrono::Duration::days(CHUNK_DAYS - 1)).min(to);
        let rows = compute_range(state, chunk_from, chunk_to, now).await?;
        report.rows += write_range(state, chunk_from, chunk_to, rows).await?;
        report.chunks += 1;
        chunk_from = next_day(chunk_to);
    }
    Ok(report)
}

/// The UTC day an instant falls in — re-exported so a caller (and a test)
/// names days without reaching into `digest`.
pub fn parse_day_of(at: DateTime) -> NaiveDate {
    utc_date_of(at)
}

/// `YYYY-MM-DD` of a day.
pub fn day_str_of(day: NaiveDate) -> String {
    day_str(day)
}

/// The days a run at `now` owes: the last [`RECOMPUTE_DAYS`] closed days.
pub fn due_range(now: DateTime) -> (NaiveDate, NaiveDate) {
    let today = utc_date_of(now);
    (
        today - chrono::Duration::days(RECOMPUTE_DAYS),
        today - chrono::Duration::days(1),
    )
}

/// Clamp a requested backfill to what the collection can hold: never
/// before `today − RETENTION_DAYS`, never today. `until` defaults to
/// yesterday. An empty range after clamping is refused.
pub fn backfill_range(
    now: DateTime,
    since: NaiveDate,
    until: Option<NaiveDate>,
) -> Result<(NaiveDate, NaiveDate), String> {
    let today = utc_date_of(now);
    let yesterday = today - chrono::Duration::days(1);
    let floor = today - chrono::Duration::days(RETENTION_DAYS);
    let from = since.max(floor);
    let to = until.unwrap_or(yesterday).min(yesterday);
    if from > to {
        return Err(format!(
            "nothing to backfill: the range must hold a closed day between {} and {}",
            day_str(floor),
            day_str(yesterday)
        ));
    }
    Ok((from, to))
}

/// The owed days, recomputed. Public so a test drives it directly.
pub async fn run_once(state: &AppState, now: DateTime) -> Result<RangeReport, GrowthError> {
    let (from, to) = due_range(now);
    recompute_range(state, from, to, now).await
}

/// The scheduled body: an empty collection is filled over the sources'
/// horizon first (once), then the owed days.
pub async fn run_scheduled(state: &AppState, now: DateTime) -> Result<RangeReport, GrowthError> {
    if GrowthDao::new(&state.db).day_bounds().await?.is_none() {
        let since = utc_date_of(now) - chrono::Duration::days(BACKFILL_HORIZON_DAYS);
        if let Ok((from, to)) = backfill_range(now, since, None) {
            info!(since = %day_str(from), until = %day_str(to), "growth org-daily: first fill");
            let r = recompute_range(state, from, to, now).await?;
            info!(
                rows = r.rows,
                chunks = r.chunks,
                "growth org-daily: first fill done"
            );
        }
    }
    run_once(state, now).await
}

/// P4 — freeze the billed totals of every closed month not frozen yet
/// (`billing::freeze_closed_months`, internal orgs left out), so deleting
/// an org later does not rewrite last year's MRR. Without `saas` there is
/// no `billing_events` to freeze. Runs under the same nightly claim.
pub async fn freeze_billing_months(
    state: &AppState,
    now: DateTime,
) -> Result<Vec<String>, GrowthError> {
    if !mounted(state, "saas") {
        return Ok(Vec::new());
    }
    let excluded: Vec<ObjectId> = meshharbor_core::growth::ExclusionSet::load(&state.core)
        .await?
        .tenants
        .into_iter()
        .collect();
    Ok(meshharbor_services::billing::freeze_closed_months(&state.db, &excluded, now).await?)
}

/// P3b — freeze the wizard's opt-in step diagnostics of the last
/// [`RECOMPUTE_DAYS`] closed days into `growth_daily`
/// (`install:wizard_step:{step, outcome, os}`, the value the number of
/// DISTINCT runs), so the counts outlive the 90-day `setup_diagnostics`
/// rows the way the fetch counters do. Idempotent per day
/// ([`GrowthDao::replace_daily`]: an unchanged row is left alone, a day
/// with no runs ends with no rows, never zeros). The collection is the
/// `fleet` module's, so without it there is nothing to freeze. Runs under
/// the same nightly claim as the org-day fold. Returns the days whose rows
/// changed.
pub async fn freeze_setup_diagnostics(
    state: &AppState,
    now: DateTime,
) -> Result<Vec<String>, GrowthError> {
    use meshharbor_remote_control::setup_diagnostics::{Outcome, Step};
    use meshharbor_services::dao::{
        growth::{INSTALL_SOURCE, INSTALL_WIZARD_STEP_METRIC, daily_row},
        setup_diagnostics::SetupDiagnosticsDao,
    };

    if !mounted(state, "fleet") {
        return Ok(Vec::new());
    }
    let dao = SetupDiagnosticsDao::new(&state.db);
    let growth = GrowthDao::new(&state.db);
    let (from, to) = due_range(now);
    let mut changed = Vec::new();
    let mut day = from;
    while day <= to {
        let start = DateTime::from_millis(
            day.and_hms_opt(0, 0, 0)
                .expect("midnight exists")
                .and_utc()
                .timestamp_millis(),
        );
        let end = DateTime::from_millis(start.timestamp_millis() + 86_400_000);
        let rows = dao.rows_between(start, end).await?;
        // Distinct runs per (step, outcome, os): a retry re-passing a step
        // is one run, and a spelling this build does not know is skipped.
        let mut runs: BTreeMap<(String, String, String), HashSet<&str>> = BTreeMap::new();
        for r in &rows {
            if Step::parse(&r.step).is_none() || Outcome::parse(&r.outcome).is_none() {
                continue;
            }
            runs.entry((r.step.clone(), r.outcome.clone(), r.os.clone()))
                .or_default()
                .insert(r.run.as_str());
        }
        let label = day_str(day);
        let frozen: Vec<_> = runs
            .into_iter()
            .map(|((step, outcome, os), set)| {
                let dims = BTreeMap::from([
                    ("step".to_string(), step),
                    ("outcome".to_string(), outcome),
                    ("os".to_string(), os),
                ]);
                daily_row(
                    INSTALL_SOURCE,
                    INSTALL_WIZARD_STEP_METRIC,
                    dims,
                    &label,
                    set.len() as i64,
                )
            })
            .collect();
        let counts = growth
            .replace_daily(
                INSTALL_SOURCE,
                &label,
                &[INSTALL_WIZARD_STEP_METRIC],
                &frozen,
            )
            .await?;
        if counts.written > 0 || counts.pruned > 0 {
            changed.push(label);
        }
        day = day.succ_opt().expect("a next day exists");
    }
    Ok(changed)
}

/// The scheduler. Only with `growth.enabled`; one run per UTC day per
/// cluster (the Redis claim) or per pod (no Redis).
pub fn spawn_org_daily_loop(state: AppState) {
    if !state.settings.growth.enabled {
        return;
    }
    info!("growth org-daily scheduler starting");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(FIRST_TICK_DELAY_SECS)).await;
        let mut last_run: Option<NaiveDate> = None;
        loop {
            let now = DateTime::now();
            let today = utc_date_of(now);
            if last_run != Some(today) {
                let claimed = match &state.redis_pubsub {
                    Some(redis) => {
                        let key = format!(
                            "roomler:growth-org-daily:{}:{}",
                            state.db.name(),
                            day_str(today)
                        );
                        match redis.try_claim(&key, CLAIM_TTL_SECS).await {
                            Ok(c) => c,
                            Err(e) => {
                                debug!(%e, "growth org-daily claim failed; skipping tick");
                                false
                            }
                        }
                    }
                    None => true,
                };
                if claimed {
                    last_run = Some(today);
                    match run_scheduled(&state, now).await {
                        Ok(r) => info!(
                            since = %r.since, until = %r.until, rows = r.rows,
                            "growth org-daily run"
                        ),
                        Err(e) => warn!(%e, "growth org-daily run failed"),
                    }
                    match freeze_billing_months(&state, now).await {
                        Ok(months) if !months.is_empty() => {
                            info!(months = ?months, "growth billing months frozen")
                        }
                        Ok(_) => {}
                        Err(e) => warn!(%e, "growth billing freeze failed"),
                    }
                    // P3b — the wizard's opt-in step counts, per closed day.
                    match freeze_setup_diagnostics(&state, now).await {
                        Ok(days) if !days.is_empty() => {
                            info!(days = ?days, "growth wizard step counts frozen")
                        }
                        Ok(_) => {}
                        Err(e) => warn!(%e, "growth wizard step freeze failed"),
                    }
                    // P9a — remote-desktop quality per day and agent version,
                    // frozen while `agent_logs` still hold the day (7 days).
                    match super::quality::freeze_scheduled(&state, now).await {
                        Ok(r) => info!(
                            since = %r.since, until = %r.until, rows = r.rows,
                            "growth quality frozen"
                        ),
                        Err(e) => warn!(%e, "growth quality freeze failed"),
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(LOOP_INTERVAL_SECS)).await;
        }
    });
}

#[derive(Debug, Deserialize)]
pub struct BackfillQuery {
    pub since: String,
    #[serde(default)]
    pub until: Option<String>,
}

/// `POST /api/admin/growth/org-daily/backfill?since=YYYY-MM-DD&until=` —
/// recompute a closed range, clamped to the retention; never today.
pub async fn backfill_route(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<BackfillQuery>,
) -> Result<Json<RangeReport>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let now = DateTime::now();
    let since = parse_day(&q.since).map_err(ApiError::BadRequest)?;
    let until = match q.until.as_deref() {
        Some(s) => Some(parse_day(s).map_err(ApiError::BadRequest)?),
        None => None,
    };
    let (from, to) = backfill_range(now, since, until).map_err(ApiError::BadRequest)?;
    let report = recompute_range(&state, from, to, now).await?;
    info!(
        admin = %auth.user_id, since = %report.since, until = %report.until, rows = report.rows,
        "growth org-daily backfill"
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

    /// A session spanning midnight is split: its minutes land on both days,
    /// its count, controller and value on the day it started.
    #[test]
    fn a_session_spanning_midnight_is_split_and_counted_once() {
        let tenant = ObjectId::new();
        let ctl = ObjectId::new();
        let mut fold = Fold::new();
        fold_rc_session(
            &mut fold,
            d("2026-10-01"),
            d("2026-10-03"),
            tenant,
            Some(ctl),
            ms("2026-10-01T23:30:00Z"),
            Some(ms("2026-10-02T00:30:00Z")),
            ms("2026-10-10T00:00:00Z"),
        );
        let first = &fold[&(tenant, d("2026-10-01"))];
        assert_eq!(first.rc_sessions, 1);
        assert_eq!(first.rc_ms, 30 * 60_000);
        assert!(first.controllers.contains(&ctl));
        assert!(first.kinds.contains(&ValueKind::Rc));
        let second = &fold[&(tenant, d("2026-10-02"))];
        assert_eq!(second.rc_sessions, 0, "counted on its start day only");
        assert_eq!(second.rc_ms, 30 * 60_000);
        assert!(second.controllers.is_empty());
        assert!(
            second.members.contains(&ctl),
            "the controller was active that day too"
        );
        assert!(second.kinds.is_empty());
        assert!(!fold.contains_key(&(tenant, d("2026-10-03"))));
    }

    /// A 12-second session counts as a session, not as value; a session
    /// that started before the range contributes its overlap only; a
    /// still-open session is clamped at `now`.
    #[test]
    fn short_earlier_and_open_sessions_fold_as_defined() {
        let tenant = ObjectId::new();
        let mut fold = Fold::new();
        let (from, to) = (d("2026-10-02"), d("2026-10-02"));
        fold_rc_session(
            &mut fold,
            from,
            to,
            tenant,
            None,
            ms("2026-10-02T10:00:00Z"),
            Some(ms("2026-10-02T10:00:12Z")),
            0,
        );
        let a = &fold[&(tenant, from)];
        assert_eq!((a.rc_sessions, a.rc_ms), (1, 12_000));
        assert!(a.kinds.is_empty());
        // Started the day before, ended inside: minutes only.
        fold_rc_session(
            &mut fold,
            from,
            to,
            tenant,
            None,
            ms("2026-10-01T22:00:00Z"),
            Some(ms("2026-10-02T01:00:00Z")),
            0,
        );
        let a = &fold[&(tenant, from)];
        assert_eq!((a.rc_sessions, a.rc_ms), (1, 12_000 + 60 * 60_000));
        // Still open at 12:00 on the 2nd: 2 h on the day, value.
        fold_rc_session(
            &mut fold,
            from,
            to,
            tenant,
            None,
            ms("2026-10-02T10:00:00Z"),
            None,
            ms("2026-10-02T12:00:00Z"),
        );
        let a = &fold[&(tenant, from)];
        assert_eq!(a.rc_sessions, 2);
        assert_eq!(a.rc_ms, 12_000 + 60 * 60_000 + 120 * 60_000);
        assert!(a.kinds.contains(&ValueKind::Rc));
        let rows = rows_of(fold, DateTime::now());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, format!("{}:2026-10-02", tenant.to_hex()));
        assert_eq!(rows[0].rc_session_minutes, 180.2);
        assert_eq!(rows[0].value_kinds, vec!["rc"]);
        assert!(rows[0].value);
    }

    #[test]
    fn a_run_owes_the_last_three_closed_days_and_never_today() {
        let now = DateTime::parse_rfc3339_str("2026-10-14T00:20:00Z").unwrap();
        assert_eq!(due_range(now), (d("2026-10-11"), d("2026-10-13")));
    }

    #[test]
    fn a_backfill_is_clamped_to_the_retention_and_to_closed_days() {
        let now = DateTime::parse_rfc3339_str("2026-10-14T10:00:00Z").unwrap();
        assert_eq!(
            backfill_range(now, d("2026-10-01"), None).unwrap(),
            (d("2026-10-01"), d("2026-10-13"))
        );
        assert_eq!(
            backfill_range(now, d("2026-10-01"), Some(d("2026-10-05"))).unwrap(),
            (d("2026-10-01"), d("2026-10-05"))
        );
        // Today and later are not closed; an until past yesterday is clamped.
        assert_eq!(
            backfill_range(now, d("2026-10-01"), Some(d("2027-01-01"))).unwrap(),
            (d("2026-10-01"), d("2026-10-13"))
        );
        assert!(backfill_range(now, d("2026-10-14"), None).is_err());
        assert!(backfill_range(now, d("2026-10-05"), Some(d("2026-10-04"))).is_err());
        // Earlier than the retention: clamped up, never refused.
        let (from, _) = backfill_range(now, d("2000-01-01"), None).unwrap();
        assert_eq!(
            from,
            d("2026-10-14") - chrono::Duration::days(RETENTION_DAYS)
        );
    }

    #[test]
    fn group_rows_read_their_tenant_day_keys() {
        let t = ObjectId::new();
        let a = ObjectId::new();
        let counts =
            tenant_day_counts(&[doc! { "_id": { "t": t, "d": "2026-10-01" }, "n": 3_i32 }]);
        assert_eq!(counts, vec![(t, d("2026-10-01"), 3)]);
        let members = tenant_day_members(
            &[doc! { "_id": { "t": t, "a": a, "d": "2026-10-02" } }],
            "a",
        );
        assert_eq!(members, vec![(t, d("2026-10-02"), a)]);
        assert!(tenant_day_counts(&[doc! { "_id": { "t": t, "d": "bad" }, "n": 1 }]).is_empty());
    }
}
