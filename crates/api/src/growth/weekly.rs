// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P10 — the weekly roll-up (spec §3l): every closed ISO week
//! (Monday–Sunday, UTC), computed once, stored once in `growth_weekly`,
//! mailed once to the digest's recipients.
//!
//! # What a week holds
//!
//! The week's totals read against the week before and the trailing four
//! (`headline`), then the reports the Growth page already shows, computed
//! for exactly that week through the same functions the routes use —
//! the account funnel by source, the cohort lines and the weekly-active
//! series, the Campaigns table by source, the Channels table, the
//! newsletter — and the week's alerts. Every rate keeps its n (the `Rate`
//! and `StepCounts` shapes), and a cell that is not measured stays a
//! reason, never a 0. Nothing here is a second definition: a number in
//! the roll-up is the number the matching route answered that morning.
//!
//! # Once, with two pods
//!
//! The same claim as the daily digest ([`DigestStore::weekly`] — one row
//! per week, the unique `_id` decides which pod computes and mails; a
//! `failed` or stale `computing` week is re-claimed; a `sent` week is
//! never sent again; a manual `send=false` run ends `preview`, which the
//! scheduler still claims). The engine is `digest::finish`, through the
//! [`Report`] seam, so the matrix is one piece of code with one set of
//! tests behind it.
//!
//! # When
//!
//! The scheduler owes the LAST CLOSED week once the clock passes Monday
//! `00:00 + digest_hour_utc` — the hour by which purestat has closed its
//! sessions. A pod that was down on Monday computes it at its next tick
//! (one mail, not a backfill), and never an older week: the run route does
//! that on purpose.

use std::{collections::BTreeMap, future::Future, pin::Pin};

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{Bson, DateTime, Document, doc};
use chrono::{Duration, NaiveDate, Timelike, Weekday};
use meshharbor_core::{campaign::KeyDepth, growth::ExclusionSet};
use meshharbor_services::{
    dao::growth_digest::{DigestDoc, DigestStatus, DigestStore, ExcludedCounts},
    purestat::Query as PsQuery,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::{
    alerts,
    campaigns::{self, CampaignsReport, WEB_METRICS, web_client},
    channels::{self, ChannelsReport},
    cohorts::{self, CohortsReport, plus_weeks, week_label, week_start},
    digest::{
        self, AlertsSection, Computed, DigestError, DigestMailer, Measured, NotMeasured, Report,
        RunReport, day_str, dt_ms, excluded_ids, find_docs, utc_date_of,
    },
    funnel::{self, Dimension, FunnelReport},
    mounted,
    newsletter::{self, NewsletterReport},
    quality::{self, QualityReport},
    read_key::GrowthAuth,
};
use crate::{error::ApiError, state::AppState};

/// The scheduler's cadence — the digest's.
pub const LOOP_INTERVAL_SECS: u64 = digest::LOOP_INTERVAL_SECS;
/// A pod that just booted waits this long before its first tick.
pub const FIRST_TICK_DELAY_SECS: u64 = digest::FIRST_TICK_DELAY_SECS + 60;
/// The weeks the headline's trailing average rests on — the four before
/// the week.
pub const BASELINE_WEEKS: i64 = 4;
/// The cohort weeks the roll-up carries (the week and the ones before).
pub const COHORT_WEEKS: i64 = 12;
const DEFAULT_LIST_LIMIT: i64 = 26;
const MAX_LIST_LIMIT: i64 = 104;
const DAY_MS: i64 = 86_400_000;

// ── Weeks ────────────────────────────────────────────────────────────────

/// `YYYY-Www` → that ISO week's Monday. Strict: the label the row is
/// stored under, nothing else.
pub fn parse_week(raw: &str) -> Result<NaiveDate, String> {
    let raw = raw.trim();
    let bad = || format!("week must be an ISO week like 2026-W42, got {raw:?}");
    let (y, w) = raw.split_once("-W").ok_or_else(bad)?;
    if y.len() != 4 || w.len() != 2 {
        return Err(bad());
    }
    let year: i32 = y.parse().map_err(|_| bad())?;
    let week: u32 = w.parse().map_err(|_| bad())?;
    NaiveDate::from_isoywd_opt(year, week, Weekday::Mon).ok_or_else(bad)
}

/// The week's Sunday.
pub fn week_end(monday: NaiveDate) -> NaiveDate {
    monday + Duration::days(6)
}

fn midnight_ms(day: NaiveDate) -> i64 {
    day.and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
        .timestamp_millis()
}

/// `[Monday 00:00, next Monday 00:00)` in milliseconds.
pub fn week_range_ms(monday: NaiveDate) -> (i64, i64) {
    (midnight_ms(monday), midnight_ms(monday) + 7 * DAY_MS)
}

/// Whether the week of `monday` has fully closed by `today`.
pub fn is_closed(monday: NaiveDate, today: NaiveDate) -> bool {
    plus_weeks(monday, 1) <= today
}

/// The week a scheduled tick at `now` owes: the last closed week, once
/// the clock has passed this week's Monday `00:00 + hour`. Before that
/// hour on a Monday, the week that just closed is not due yet (purestat
/// is still closing its sessions); from then on, every tick of the week
/// owes the same week, which the claim answers once. Never an older week.
pub fn due_week(now: DateTime, hour: u8) -> Option<NaiveDate> {
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now.timestamp_millis())?;
    let today = now_utc.date_naive();
    let this_monday = week_start(today);
    if today == this_monday && now_utc.hour() < u32::from(hour) {
        return None;
    }
    Some(plus_weeks(this_monday, -1))
}

/// The `week` a route names, defaulting to the last closed week; refused
/// unless closed.
fn closed_week(raw: Option<&str>, now: DateTime) -> Result<NaiveDate, ApiError> {
    let today = utc_date_of(now);
    let monday = match raw {
        Some(s) => parse_week(s).map_err(ApiError::BadRequest)?,
        None => plus_weeks(week_start(today), -1),
    };
    if !is_closed(monday, today) {
        return Err(ApiError::BadRequest(format!(
            "week must be a closed ISO week (before {})",
            week_label(week_start(today))
        )));
    }
    Ok(monday)
}

// ── Sections ─────────────────────────────────────────────────────────────

/// A count of the week, of the week before, and the mean of the
/// [`BASELINE_WEEKS`] before the week (absent where the weeks are not all
/// measurable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct WeekFigure {
    pub week: i64,
    pub prev_week: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w4_avg: Option<f64>,
}

impl WeekFigure {
    /// From per-week counts keyed by Monday: the week, the one before, and
    /// the mean of the four before the week (every one of which must be
    /// in `by_week`, a zero being a measured zero only when the week is
    /// present).
    pub fn of(by_week: &BTreeMap<NaiveDate, i64>, monday: NaiveDate, all_measured: bool) -> Self {
        let get = |m: NaiveDate| by_week.get(&m).copied().unwrap_or(0);
        let w4_avg = all_measured.then(|| {
            let sum: i64 = (1..=BASELINE_WEEKS)
                .map(|k| get(plus_weeks(monday, -k)))
                .sum();
            (sum as f64 / BASELINE_WEEKS as f64 * 10.0).round() / 10.0
        });
        Self {
            week: get(monday),
            prev_week: get(plus_weeks(monday, -1)),
            w4_avg,
        }
    }
}

/// purestat's totals for the week and the week before — unique over each
/// week, never a sum of days.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebWeek {
    pub visitors: WeekFigure,
    pub visits: WeekFigure,
    pub pageviews: WeekFigure,
    pub reads: WeekFigure,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeeklyHeadline {
    /// `YYYY-Www`.
    pub week: String,
    /// The Monday, `YYYY-MM-DD`.
    pub since: String,
    /// The Sunday, `YYYY-MM-DD`.
    pub until: String,
    pub signups: WeekFigure,
    pub orgs_created: WeekFigure,
    pub devices_enrolled: Measured<WeekFigure>,
    /// Weekly active orgs — the north star, from the cohort view's series.
    pub active_orgs: Measured<WeekFigure>,
    pub website: Measured<WebWeek>,
}

/// The week, as stored and mailed. Serialised whole (never a hand-built
/// document); the GET answers the stored document as plain JSON.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WeeklySections {
    pub headline: WeeklyHeadline,
    /// The week's sign-ups through the funnel, by source.
    pub funnel: FunnelReport,
    /// The cohort lines and the WAO series as they stood the morning after.
    pub cohorts: CohortsReport,
    /// The Campaigns table by source for the week.
    pub campaigns: CampaignsReport,
    /// The Channels table for the posts published in the week.
    pub channels: ChannelsReport,
    pub newsletter: NewsletterReport,
    /// Fired or cleared in the week, and open at the compute.
    pub alerts: Measured<AlertsSection>,
    /// P9a — remote-desktop quality over the week's frozen days: sessions
    /// by outcome, time to first frame, crashes per 100 device-days, by
    /// agent version. The Quality view's own report for Mon–Sun.
    pub quality: QualityReport,
    /// P7 — the repository at Sunday's snapshot (the digest's section for
    /// that day): its 7-day changes and traffic are the week's.
    pub github: super::github::GithubSection,
    /// P7 — search for Sunday: Google's windows ending on the newest final
    /// day on or before it (its 7 days lag the week by Google's settling),
    /// Bing at its own grain.
    pub search: super::digest::Measured<super::search::SearchSection>,
}

// ── Computing ────────────────────────────────────────────────────────────

/// Created-at instants bucketed by ISO week (Monday).
fn by_week(times: impl IntoIterator<Item = i64>) -> BTreeMap<NaiveDate, i64> {
    let mut out = BTreeMap::new();
    for t in times {
        let day = utc_date_of(DateTime::from_millis(t));
        *out.entry(week_start(day)).or_insert(0) += 1;
    }
    out
}

/// `created_at` of `coll` rows in `[from, to)` ms that match `filter`.
async fn created_in(
    state: &AppState,
    coll: &str,
    mut filter: Document,
    from: i64,
    to: i64,
) -> Result<Vec<i64>, DigestError> {
    filter.insert(
        "created_at",
        doc! { "$gte": DateTime::from_millis(from), "$lt": DateTime::from_millis(to) },
    );
    let docs = find_docs(state, coll, filter, doc! { "created_at": 1 }).await?;
    Ok(docs.iter().filter_map(|d| dt_ms(d, "created_at")).collect())
}

async fn headline(
    state: &AppState,
    monday: NaiveDate,
    set: &ExclusionSet,
    cohorts: &CohortsReport,
) -> Result<WeeklyHeadline, DigestError> {
    // Five weeks of facts: the week, and the four before it.
    let (from, _) = week_range_ms(plus_weeks(monday, -BASELINE_WEEKS));
    let (_, to) = week_range_ms(monday);
    let signups = by_week(
        created_in(
            state,
            "users",
            doc! { "deleted_at": Bson::Null, "_id": { "$nin": excluded_ids(&set.users) } },
            from,
            to,
        )
        .await?,
    );
    let orgs = by_week(
        created_in(
            state,
            "tenants",
            doc! { "_id": { "$nin": excluded_ids(&set.tenants) } },
            from,
            to,
        )
        .await?,
    );
    // Devices: tombstones count — a device enrolled and removed was still
    // enrolled.
    let devices = if mounted(state, "fleet") {
        Measured::Value(WeekFigure::of(
            &by_week(
                created_in(
                    state,
                    "agents",
                    doc! { "tenant_id": { "$nin": excluded_ids(&set.tenants) } },
                    from,
                    to,
                )
                .await?,
            ),
            monday,
            true,
        ))
    } else {
        Measured::unmounted("fleet")
    };
    // WAO from the cohort view's own series: one definition of "active".
    let active_orgs = match &cohorts.wao {
        Some(series) => {
            let by: BTreeMap<NaiveDate, i64> = series
                .iter()
                .filter_map(|w| Some((digest::parse_day(&w.start).ok()?, w.active_orgs as i64)))
                .collect();
            let all_measured =
                (0..=BASELINE_WEEKS).all(|k| by.contains_key(&plus_weeks(monday, -k)));
            if by.contains_key(&monday) {
                Measured::Value(WeekFigure::of(&by, monday, all_measured))
            } else {
                Measured::NotMeasured(NotMeasured::now(
                    "the week is outside the cohort view's series",
                ))
            }
        }
        None => Measured::NotMeasured(NotMeasured::now(
            cohorts
                .not_measured
                .clone()
                .unwrap_or_else(|| "no value module mounted".into()),
        )),
    };
    let website = website_week(state, monday).await;
    Ok(WeeklyHeadline {
        week: week_label(monday),
        since: day_str(monday),
        until: day_str(week_end(monday)),
        signups: WeekFigure::of(&signups, monday, true),
        orgs_created: WeekFigure::of(&orgs, monday, true),
        devices_enrolled: devices,
        active_orgs,
        website,
    })
}

/// purestat's totals for the week and the week before: two queries with
/// no dimension, so each week's visitors are unique over that week. The
/// four-week mean is not computed (it would be four more queries for a
/// number that does not add across weeks).
async fn website_week(state: &AppState, monday: NaiveDate) -> Measured<WebWeek> {
    let client = match web_client(state) {
        Ok(c) => c,
        Err(n) => return Measured::NotMeasured(n),
    };
    let mut totals = [[0i64; 4]; 2];
    for (i, m) in [monday, plus_weeks(monday, -1)].into_iter().enumerate() {
        let q = PsQuery::range(&day_str(m), &day_str(week_end(m)), &[], &WEB_METRICS, &[]);
        match client.query(&q).await {
            Ok(rows) => {
                if let Some(r) = rows.first() {
                    for (j, metric) in WEB_METRICS.iter().enumerate() {
                        totals[i][j] = r.count(metric);
                    }
                }
            }
            Err(e) => return Measured::NotMeasured(NotMeasured::now(e.to_string())),
        }
    }
    let figure = |j: usize| WeekFigure {
        week: totals[0][j],
        prev_week: totals[1][j],
        w4_avg: None,
    };
    Measured::Value(WebWeek {
        visitors: figure(0),
        visits: figure(1),
        pageviews: figure(2),
        reads: figure(3),
    })
}

impl From<ApiError> for DigestError {
    fn from(e: ApiError) -> Self {
        Self(e.to_string())
    }
}

/// The week of `monday`, computed at `now` with the exclusion set applied.
pub async fn compute(
    state: &AppState,
    monday: NaiveDate,
    set: &ExclusionSet,
    now: DateTime,
) -> Result<WeeklySections, DigestError> {
    let sunday = week_end(monday);
    let (start_ms, end_ms) = week_range_ms(monday);
    // The roll-up is always the excluded view: the engine loads the real
    // set, and there is no `include_internal` on a mailed report.
    let include_internal = false;
    let cohorts = cohorts::compute(
        state,
        set,
        plus_weeks(monday, -(COHORT_WEEKS - 1)),
        include_internal,
        now,
    )
    .await?;
    let headline = headline(state, monday, set, &cohorts).await?;
    let funnel = funnel::compute(
        state,
        set,
        DateTime::from_millis(start_ms),
        DateTime::from_millis(end_ms),
        Some(Dimension::Source),
        include_internal,
        now,
    )
    .await?;
    let campaigns = campaigns::compute(
        state,
        set,
        monday,
        sunday,
        KeyDepth::Source,
        include_internal,
        now,
    )
    .await?;
    let channels = channels::compute(state, set, monday, sunday, include_internal, now).await?;
    let newsletter = newsletter::compute(state, set, monday, sunday, include_internal, now).await?;
    let alerts = if state.settings.growth.alerts {
        Measured::Value(alerts::window_section(state, start_ms, end_ms).await?)
    } else {
        Measured::NotMeasured(NotMeasured::now(
            "alerts are off on this server (MESHHARBOR__GROWTH__ALERTS)",
        ))
    };
    let quality = quality::compute(state, set, monday, sunday, include_internal, now).await?;
    let github = super::github::section(state, sunday).await?;
    let search = Measured::Value(super::search::section(state, sunday).await?);
    Ok(WeeklySections {
        headline,
        funnel,
        cohorts,
        campaigns,
        channels,
        newsletter,
        alerts,
        quality,
        github,
        search,
    })
}

/// The weekly roll-up of one closed week, for the digest engine.
pub(crate) struct WeeklyReport {
    pub monday: NaiveDate,
}

impl Report for WeeklyReport {
    fn compute<'a>(
        &'a self,
        state: &'a AppState,
        set: &'a ExclusionSet,
        doc: &'a DigestDoc,
        now: DateTime,
    ) -> Pin<Box<dyn Future<Output = Result<Computed, DigestError>> + Send + 'a>> {
        Box::pin(async move {
            let sections = compute(state, self.monday, set, now).await?;
            Ok(Computed {
                sections: bson::to_document(&sections)?,
                subject: super::render::weekly_subject(&sections.headline),
                html: super::render::render_weekly_html(doc, &sections),
                text: super::render::render_weekly_text(doc, &sections),
            })
        })
    }
}

// ── Runs ─────────────────────────────────────────────────────────────────

/// The scheduled path: the week of `monday`, through the claim.
pub async fn run_scheduled(
    state: &AppState,
    monday: NaiveDate,
    mailer: Option<&dyn DigestMailer>,
    now: DateTime,
) -> Result<RunReport, DigestError> {
    digest::run_scheduled_report(
        state,
        &DigestStore::weekly(&state.db),
        &week_label(monday),
        &WeeklyReport { monday },
        mailer,
        now,
    )
    .await
}

/// The manual path (`POST …/weekly/run`): the digest's manual claim
/// matrix, on the week.
pub async fn run_manual(
    state: &AppState,
    monday: NaiveDate,
    send: bool,
    mailer: Option<&dyn DigestMailer>,
    now: DateTime,
) -> Result<RunReport, digest::RunError> {
    digest::run_manual_report(
        state,
        &DigestStore::weekly(&state.db),
        &week_label(monday),
        &WeeklyReport { monday },
        send,
        mailer,
        now,
    )
    .await
}

/// The scheduler: every [`LOOP_INTERVAL_SECS`], make sure the last closed
/// week exists and was handled, once the clock has passed Monday's hour.
/// Only with `growth.weekly_enabled`; the claim in `growth_weekly` is what
/// keeps two pods from both sending.
pub fn spawn_weekly_loop(state: AppState) {
    if !state.settings.growth.enabled || !state.settings.growth.weekly_enabled {
        return;
    }
    let hour = state.settings.growth.digest_hour();
    info!(hour, "growth weekly roll-up scheduler starting");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(FIRST_TICK_DELAY_SECS)).await;
        loop {
            let now = DateTime::now();
            if let Some(monday) = due_week(now, hour) {
                let mailer = digest::service_mailer(&state);
                let mailer_ref: Option<&dyn DigestMailer> =
                    mailer.as_ref().map(|m| m as &dyn DigestMailer);
                match run_scheduled(&state, monday, mailer_ref, now).await {
                    Ok(r) if r.claimed => {
                        info!(week = %r.day, status = r.status.as_str(), sent = r.sent, "growth weekly roll-up done")
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!(week = %week_label(monday), %e, "growth weekly roll-up failed")
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(LOOP_INTERVAL_SECS)).await;
        }
    });
}

// ── The routes ───────────────────────────────────────────────────────────

/// A stored week as the routes answer it: dates as RFC 3339 strings, the
/// sections as the stored document, plain JSON.
#[derive(Debug, Clone, Serialize)]
pub struct WeeklyJson {
    pub week: String,
    pub status: DigestStatus,
    pub version: u32,
    pub claimed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub recipients: u32,
    pub excluded: ExcludedCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sections: Option<serde_json::Value>,
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

impl WeeklyJson {
    pub fn of(doc: &DigestDoc) -> Self {
        Self {
            week: doc.day.clone(),
            status: doc.status,
            version: doc.version,
            claimed_at: rfc3339(doc.claimed_at),
            computed_at: doc.computed_at.map(rfc3339),
            sent_at: doc.sent_at.map(rfc3339),
            attempts: doc.attempts,
            error: doc.error.clone(),
            recipients: doc.recipients,
            excluded: doc.excluded,
            sections: doc
                .sections
                .as_ref()
                .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null)),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WeekQuery {
    #[serde(default)]
    pub week: Option<String>,
}

/// `GET /api/admin/growth/weekly?week=` — a stored week (the latest when
/// `week` is omitted); a platform admin, or a read key.
pub async fn get_weekly(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<WeekQuery>,
) -> Result<Json<WeeklyJson>, ApiError> {
    let store = DigestStore::weekly(&state.db);
    let found = match q.week.as_deref() {
        Some(raw) => {
            let monday = parse_week(raw).map_err(ApiError::BadRequest)?;
            store.get(&week_label(monday)).await?
        }
        None => store.latest().await?,
    };
    let doc = found.ok_or_else(|| ApiError::NotFound("no roll-up for that week".into()))?;
    Ok(Json(WeeklyJson::of(&doc)))
}

#[derive(Debug, Deserialize)]
pub struct WeekListQuery {
    /// `YYYY-Www`, inclusive.
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct WeeklyListRow {
    pub week: String,
    pub status: DigestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    pub attempts: u32,
    pub recipients: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub excluded: ExcludedCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headline: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct WeeklyListResponse {
    pub enabled: bool,
    /// Whether the scheduler runs on this server (`growth.weekly_enabled`).
    pub scheduled: bool,
    pub weeks: Vec<WeeklyListRow>,
}

/// `GET /api/admin/growth/weeklies?since=&limit=`
pub async fn list_weeklies(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<WeekListQuery>,
) -> Result<Json<WeeklyListResponse>, ApiError> {
    let since = match q.since.as_deref() {
        Some(s) => Some(week_label(parse_week(s).map_err(ApiError::BadRequest)?)),
        None => None,
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let rows = DigestStore::weekly(&state.db)
        .list(since.as_deref(), limit)
        .await?;
    let weeks = rows
        .iter()
        .map(|d| WeeklyListRow {
            week: d.day.clone(),
            status: d.status,
            computed_at: d.computed_at.map(rfc3339),
            sent_at: d.sent_at.map(rfc3339),
            attempts: d.attempts,
            recipients: d.recipients,
            error: d.error.clone(),
            excluded: d.excluded,
            headline: d
                .sections
                .as_ref()
                .and_then(|s| s.get_document("headline").ok())
                .and_then(|h| serde_json::to_value(h).ok()),
        })
        .collect();
    Ok(Json(WeeklyListResponse {
        enabled: true,
        scheduled: state.settings.growth.weekly_enabled,
        weeks,
    }))
}

#[derive(Debug, Deserialize)]
pub struct WeekRunQuery {
    #[serde(default)]
    pub week: Option<String>,
    #[serde(default)]
    pub send: bool,
}

/// `POST /api/admin/growth/weekly/run?week=&send=false` — a session, never
/// a key (the gate answers a key on any POST). Recompute and overwrite a
/// closed week through the claim; mail only with `send=true` AND a week
/// not already `sent`; 409 while a run of that week is in progress.
pub async fn run_weekly(
    State(state): State<AppState>,
    auth: crate::extractors::auth::AuthUser,
    Query(q): Query<WeekRunQuery>,
) -> Result<Json<WeeklyJson>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    let now = DateTime::now();
    let monday = closed_week(q.week.as_deref(), now)?;
    let mailer = digest::service_mailer(&state);
    let mailer_ref: Option<&dyn DigestMailer> = mailer.as_ref().map(|m| m as &dyn DigestMailer);
    run_manual(&state, monday, q.send, mailer_ref, now).await?;
    let doc = DigestStore::weekly(&state.db)
        .get(&week_label(monday))
        .await?
        .ok_or_else(|| ApiError::Internal("the roll-up vanished after its run".into()))?;
    Ok(Json(WeeklyJson::of(&doc)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        digest::parse_day(s).unwrap()
    }

    fn at(s: &str) -> DateTime {
        DateTime::parse_rfc3339_str(s).unwrap()
    }

    #[test]
    fn weeks_parse_strictly_and_round_trip_their_label() {
        assert_eq!(parse_week("2026-W42").unwrap(), d("2026-10-12"));
        assert_eq!(parse_week(" 2026-W01 ").unwrap(), d("2025-12-29"));
        assert_eq!(
            week_label(parse_week("2026-W53").unwrap_or(d("2026-12-28"))),
            "2026-W53"
        );
        for bad in [
            "2026-W54",
            "2026-W00",
            "2026-42",
            "2026-W4",
            "2026-10-12",
            "W42",
            "",
            "2026-Wxx",
        ] {
            assert!(parse_week(bad).is_err(), "{bad}");
        }
        assert_eq!(week_end(d("2026-10-12")), d("2026-10-18"));
        let (from, to) = week_range_ms(d("2026-10-12"));
        assert_eq!(to - from, 7 * DAY_MS);
        assert!(is_closed(d("2026-10-05"), d("2026-10-12")));
        assert!(!is_closed(d("2026-10-12"), d("2026-10-12")));
        assert!(!is_closed(d("2026-10-12"), d("2026-10-18")));
        assert!(is_closed(d("2026-10-12"), d("2026-10-19")));
    }

    /// Monday before the hour: nothing. From the hour on, every day of the
    /// week owes the week that just closed — and never an older one.
    #[test]
    fn the_due_week_is_the_last_closed_week_from_mondays_hour() {
        // 2026-10-12 is a Monday.
        assert_eq!(due_week(at("2026-10-12T05:59:59Z"), 6), None);
        assert_eq!(
            due_week(at("2026-10-12T06:00:00Z"), 6),
            Some(d("2026-10-05"))
        );
        assert_eq!(
            due_week(at("2026-10-14T03:00:00Z"), 6),
            Some(d("2026-10-05")),
            "a pod that was down on Monday still owes last week"
        );
        assert_eq!(
            due_week(at("2026-10-18T23:59:59Z"), 6),
            Some(d("2026-10-05"))
        );
        assert_eq!(
            due_week(at("2026-10-19T06:00:00Z"), 6),
            Some(d("2026-10-12"))
        );
        assert_eq!(
            due_week(at("2026-10-12T00:00:00Z"), 0),
            Some(d("2026-10-05"))
        );
    }

    #[test]
    fn a_route_week_defaults_to_the_last_closed_week_and_refuses_an_open_one() {
        let now = at("2026-10-14T10:00:00Z");
        assert_eq!(closed_week(None, now).unwrap(), d("2026-10-05"));
        assert_eq!(closed_week(Some("2026-W41"), now).unwrap(), d("2026-10-05"));
        assert_eq!(closed_week(Some("2026-W30"), now).unwrap(), d("2026-07-20"));
        for bad in ["2026-W42", "2026-W43", "2027-W01", "2026-10-05", "last"] {
            assert!(
                matches!(closed_week(Some(bad), now), Err(ApiError::BadRequest(_))),
                "{bad}"
            );
        }
        // On a Monday the week that just closed is a closed week.
        assert_eq!(
            closed_week(None, at("2026-10-12T00:00:00Z")).unwrap(),
            d("2026-10-05")
        );
    }

    /// A week figure reads the week, the week before, and the mean of the
    /// four before — only when all four are measurable.
    #[test]
    fn a_week_figure_carries_its_baselines() {
        let monday = d("2026-10-05");
        let by: BTreeMap<NaiveDate, i64> = [
            (d("2026-09-07"), 4),
            (d("2026-09-14"), 6),
            (d("2026-09-21"), 0),
            (d("2026-09-28"), 10),
            (d("2026-10-05"), 12),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            WeekFigure::of(&by, monday, true),
            WeekFigure {
                week: 12,
                prev_week: 10,
                w4_avg: Some(5.0)
            }
        );
        assert_eq!(WeekFigure::of(&by, monday, false).w4_avg, None);
        let times = [
            at("2026-10-05T00:00:00Z").timestamp_millis(),
            at("2026-10-11T23:59:59Z").timestamp_millis(),
            at("2026-10-12T00:00:00Z").timestamp_millis(),
        ];
        let b = by_week(times);
        assert_eq!(b.get(&d("2026-10-05")), Some(&2));
        assert_eq!(b.get(&d("2026-10-12")), Some(&1));
    }

    #[test]
    fn the_json_view_carries_the_week_and_rfc3339_dates() {
        let doc = DigestDoc {
            day: "2026-W41".into(),
            status: DigestStatus::Sent,
            version: 4,
            claimed_at: at("2026-10-12T06:02:00Z"),
            computed_at: Some(at("2026-10-12T06:02:30Z")),
            sent_at: Some(at("2026-10-12T06:02:31Z")),
            attempts: 1,
            error: None,
            recipients: 2,
            excluded: ExcludedCounts {
                users: 1,
                tenants: 2,
            },
            sections: Some(doc! { "headline": { "week": "2026-W41" } }),
        };
        let v = serde_json::to_value(WeeklyJson::of(&doc)).unwrap();
        assert_eq!(v["week"], "2026-W41");
        assert_eq!(v["status"], "sent");
        assert!(v["sent_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(v["sections"]["headline"]["week"], "2026-W41");
        assert!(!v.to_string().contains("$date"));
    }
}
