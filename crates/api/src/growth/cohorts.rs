// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P2 — `GET /api/admin/growth/cohorts?unit=week&since=`: weekly
//! cohorts of orgs by creation week × weeks since (W0..W12), and beside
//! them the north star, weekly active orgs (WAO) for the last 12 weeks
//! (spec §3d, D2). Both read `growth_org_daily`'s value days.
//!
//! * A cohort is the orgs created in one ISO week; an org is ACTIVE in a
//!   week when it has ≥ 1 value day in that week.
//! * A cell `W+k` is `null` until that week has started; a cell of a week
//!   in progress carries its count so far, and `closed_through` says how
//!   many of W0..W12 have fully closed, so a reader can shade the rest.
//! * WAO lists the 12 most recent closed weeks and the current one marked
//!   `partial`, oldest first.
//! * Every number applies the exclusion set; `include_internal=true` is
//!   the raw totals. Without any value module the activity is not
//!   measured: `cohorts` and `wao` are `null` with the reason.
//!
//! The ISO-week helpers here are shared with the org views.

use std::collections::{BTreeMap, HashSet};

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use chrono::{Datelike, Duration, NaiveDate};
use meshharbor_services::dao::{growth::GrowthDao, growth_digest::ExcludedCounts};
use meshharbor_core::growth::ExclusionSet;
use serde::{Deserialize, Serialize};

use super::{
    digest::{day_str, dt_ms, excluded_ids, find_docs, parse_day, utc_date_of},
    read_key::GrowthAuth,
    value,
};
use crate::{error::ApiError, state::AppState};

/// Cells per cohort: W0..W12.
pub const WEEKS_SINCE: usize = 12;
/// The weeks the UI highlights.
pub const HIGHLIGHT: [usize; 3] = [1, 4, 12];
/// Closed weeks in the WAO series (plus the current, partial one).
pub const WAO_WEEKS: usize = 12;
/// The default `since`: 26 weeks of cohorts.
pub const DEFAULT_SINCE_WEEKS: i64 = 26;
/// The furthest `since` honoured: the collection's retention, in weeks.
pub const MAX_SINCE_WEEKS: i64 = 108;

/// The Monday of `d`'s ISO week.
pub fn week_start(d: NaiveDate) -> NaiveDate {
    d - Duration::days(i64::from(d.weekday().num_days_from_monday()))
}

/// `2026-W41` — the ISO week of a Monday.
pub fn week_label(monday: NaiveDate) -> String {
    let w = monday.iso_week();
    format!("{}-W{:02}", w.year(), w.week())
}

pub fn plus_weeks(monday: NaiveDate, k: i64) -> NaiveDate {
    monday + Duration::weeks(k)
}

/// Whole weeks from Monday `a` to Monday `b` (negative when `b` is earlier).
pub fn weeks_between(a: NaiveDate, b: NaiveDate) -> i64 {
    (b - a).num_days().div_euclid(7)
}

/// One cohort: the orgs created in `week`, and how many were active in
/// each of W0..W12 after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortRow {
    pub week: String,
    /// The cohort week's Monday, `YYYY-MM-DD`.
    pub start: String,
    pub size: u64,
    /// `active[k]` = orgs active in week `W+k`; `null` until that week
    /// has started.
    pub active: Vec<Option<u64>>,
    /// The last `k` whose week has fully closed (−1 when W0 is the current
    /// week).
    pub closed_through: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaoWeek {
    pub week: String,
    pub start: String,
    pub active_orgs: u64,
    /// The current week, still open.
    pub partial: bool,
}

/// The horizon `growth_org_daily` holds — what the views can see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OrgDailyCoverage {
    pub first_day: Option<String>,
    pub last_day: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortsReport {
    pub enabled: bool,
    pub unit: String,
    pub since: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub weeks_since: usize,
    pub highlight: [usize; 3],
    pub value_basis: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_measured: Option<String>,
    pub cohorts: Option<Vec<CohortRow>>,
    pub wao: Option<Vec<WaoWeek>>,
    pub org_daily: OrgDailyCoverage,
}

/// `(org, Monday)` pairs: the weeks each org had a value day in.
pub type ActiveWeeks = HashSet<(ObjectId, NaiveDate)>;

/// The cohort table, pure. `orgs` are `(id, created)`; cohorts earlier
/// than `since` are left out.
pub fn cohort_table(
    orgs: &[(ObjectId, NaiveDate)],
    active: &ActiveWeeks,
    since_monday: NaiveDate,
    today: NaiveDate,
) -> Vec<CohortRow> {
    let this_monday = week_start(today);
    let mut by_week: BTreeMap<NaiveDate, Vec<ObjectId>> = BTreeMap::new();
    for (id, created) in orgs {
        let w = week_start(*created);
        if w >= since_monday {
            by_week.entry(w).or_default().push(*id);
        }
    }
    by_week
        .into_iter()
        .map(|(w, members)| {
            let cells = (0..=WEEKS_SINCE)
                .map(|k| {
                    let wk = plus_weeks(w, k as i64);
                    (wk <= today).then(|| {
                        members
                            .iter()
                            .filter(|id| active.contains(&(**id, wk)))
                            .count() as u64
                    })
                })
                .collect();
            CohortRow {
                week: week_label(w),
                start: day_str(w),
                size: members.len() as u64,
                active: cells,
                closed_through: (weeks_between(w, this_monday) - 1).clamp(-1, WEEKS_SINCE as i64),
            }
        })
        .collect()
}

/// Weekly active orgs: the last [`WAO_WEEKS`] closed weeks and the current
/// one, oldest first. Pure.
pub fn wao_series(active: &ActiveWeeks, today: NaiveDate) -> Vec<WaoWeek> {
    let this_monday = week_start(today);
    let mut count: BTreeMap<NaiveDate, u64> = BTreeMap::new();
    for (_, wk) in active {
        *count.entry(*wk).or_insert(0) += 1;
    }
    (0..=WAO_WEEKS as i64)
        .rev()
        .map(|back| {
            let wk = plus_weeks(this_monday, -back);
            WaoWeek {
                week: week_label(wk),
                start: day_str(wk),
                active_orgs: count.get(&wk).copied().unwrap_or(0),
                partial: back == 0,
            }
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct CohortsQuery {
    #[serde(default)]
    pub unit: Option<String>,
    /// `YYYY-MM-DD`, snapped to its Monday. Default: 26 weeks ago.
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

/// `GET /api/admin/growth/cohorts?unit=week&since=&include_internal=`
pub async fn get_cohorts(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<CohortsQuery>,
) -> Result<Json<CohortsReport>, ApiError> {
    if let Some(u) = q.unit.as_deref()
        && u != "week"
    {
        return Err(ApiError::BadRequest("unit must be week".into()));
    }
    let now = DateTime::now();
    let this_monday = week_start(utc_date_of(now));
    let floor = plus_weeks(this_monday, -MAX_SINCE_WEEKS);
    let since = match q.since.as_deref() {
        Some(s) => week_start(parse_day(s).map_err(ApiError::BadRequest)?),
        None => plus_weeks(this_monday, -DEFAULT_SINCE_WEEKS),
    }
    .max(floor);
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    Ok(Json(
        compute(&state, &set, since, q.include_internal, now).await?,
    ))
}

/// The report from the Monday `since` at `now` — what the route answers,
/// and what P10's weekly roll-up stores (the WAO series and the cohort
/// lines as they stood the morning after the week closed).
pub async fn compute(
    state: &AppState,
    set: &ExclusionSet,
    since: NaiveDate,
    include_internal: bool,
    now: DateTime,
) -> Result<CohortsReport, ApiError> {
    let today = utc_date_of(now);
    let this_monday = week_start(today);
    let (users, tenants) = set.counts();
    let excluded = ExcludedCounts {
        users: users as u32,
        tenants: tenants as u32,
    };
    let dao = GrowthDao::new(&state.db);
    let org_daily = match dao.day_bounds().await? {
        Some((first_day, last_day)) => OrgDailyCoverage {
            first_day: Some(first_day),
            last_day: Some(last_day),
        },
        None => OrgDailyCoverage::default(),
    };
    let basis = value::value_basis(&state.modules.mounted());
    if basis.is_empty() {
        return Ok(CohortsReport {
            enabled: true,
            unit: "week".into(),
            since: day_str(since),
            include_internal,
            excluded,
            weeks_since: WEEKS_SINCE,
            highlight: HIGHLIGHT,
            not_measured: Some(value::unmounted_reason(&basis)),
            value_basis: basis,
            cohorts: None,
            wao: None,
            org_daily,
        });
    }

    let since_dt = DateTime::from_millis(
        since
            .and_hms_opt(0, 0, 0)
            .expect("midnight")
            .and_utc()
            .timestamp_millis(),
    );
    let orgs: Vec<(ObjectId, NaiveDate)> = find_docs(
        state,
        "tenants",
        doc! { "created_at": { "$gte": since_dt }, "_id": { "$nin": excluded_ids(&set.tenants) } },
        doc! { "created_at": 1 },
    )
    .await?
    .iter()
    .filter_map(|d| {
        Some((
            d.get_object_id("_id").ok()?,
            utc_date_of(DateTime::from_millis(dt_ms(d, "created_at")?)),
        ))
    })
    .collect();
    // The value days from the earlier of the cohort start and the WAO
    // window, for every org not excluded.
    let from = since.min(plus_weeks(this_monday, -(WAO_WEEKS as i64)));
    let excluded_tenants = excluded_ids(&set.tenants);
    let rows = dao
        .org_days_between(
            None,
            &excluded_tenants,
            &day_str(from),
            &day_str(today),
            true,
        )
        .await?;
    let active: ActiveWeeks = rows
        .iter()
        .filter_map(|r| Some((r.tenant_id, week_start(parse_day(&r.day).ok()?))))
        .collect();

    Ok(CohortsReport {
        enabled: true,
        unit: "week".into(),
        since: day_str(since),
        include_internal,
        excluded,
        weeks_since: WEEKS_SINCE,
        highlight: HIGHLIGHT,
        value_basis: basis,
        not_measured: None,
        cohorts: Some(cohort_table(&orgs, &active, since, today)),
        wao: Some(wao_series(&active, today)),
        org_daily,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        parse_day(s).unwrap()
    }

    #[test]
    fn iso_weeks_start_on_monday_and_label_by_iso_year() {
        assert_eq!(week_start(d("2026-10-14")), d("2026-10-12"));
        assert_eq!(week_start(d("2026-10-12")), d("2026-10-12"));
        assert_eq!(week_start(d("2026-10-18")), d("2026-10-12"));
        assert_eq!(week_label(d("2026-10-12")), "2026-W42");
        // The ISO year differs from the calendar year at the edges.
        assert_eq!(week_label(week_start(d("2027-01-01"))), "2026-W53");
        assert_eq!(week_label(week_start(d("2024-12-30"))), "2025-W01");
        assert_eq!(plus_weeks(d("2026-10-12"), 2), d("2026-10-26"));
        assert_eq!(weeks_between(d("2026-10-12"), d("2026-10-26")), 2);
        assert_eq!(weeks_between(d("2026-10-26"), d("2026-10-12")), -2);
        assert_eq!(weeks_between(d("2026-10-12"), d("2026-10-18")), 0);
    }

    /// Two cohorts, known activity: the cells, the nulls past today, and
    /// `closed_through`.
    #[test]
    fn cohorts_count_active_orgs_per_week_since_creation() {
        let (a, b, c) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        // Cohort W = 2026-09-07: a and b. Cohort 2026-09-21: c.
        let orgs = vec![
            (a, d("2026-09-08")),
            (b, d("2026-09-13")),
            (c, d("2026-09-23")),
        ];
        let mut active = ActiveWeeks::new();
        // a: W0, W1, W4; b: W1; c: W0.
        for w in [d("2026-09-07"), d("2026-09-14"), d("2026-10-05")] {
            active.insert((a, w));
        }
        active.insert((b, d("2026-09-14")));
        active.insert((c, d("2026-09-21")));
        let today = d("2026-10-14"); // in week 2026-10-12
        let rows = cohort_table(&orgs, &active, d("2026-08-31"), today);
        assert_eq!(rows.len(), 2);
        let first = &rows[0];
        assert_eq!(first.week, "2026-W37");
        assert_eq!(first.start, "2026-09-07");
        assert_eq!(first.size, 2);
        assert_eq!(first.active.len(), WEEKS_SINCE + 1);
        assert_eq!(first.active[0], Some(1));
        assert_eq!(first.active[1], Some(2));
        assert_eq!(first.active[2], Some(0));
        assert_eq!(first.active[4], Some(1));
        // W5 = 2026-10-12 is the current week: counted so far; W6 not started.
        assert_eq!(first.active[5], Some(0));
        assert_eq!(first.active[6], None);
        assert_eq!(first.closed_through, 4);
        let second = &rows[1];
        assert_eq!(second.size, 1);
        assert_eq!(second.active[0], Some(1));
        assert_eq!(second.closed_through, 2);
        // A `since` after the first cohort leaves it out.
        let later = cohort_table(&orgs, &active, d("2026-09-21"), today);
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].week, "2026-W39");
        // A cohort created this week: W0 partial, nothing closed.
        let fresh = cohort_table(&[(a, d("2026-10-13"))], &active, d("2026-10-12"), today);
        assert_eq!(fresh[0].closed_through, -1);
        assert_eq!(fresh[0].active[0], Some(0));
        assert_eq!(fresh[0].active[1], None);
    }

    #[test]
    fn wao_lists_twelve_closed_weeks_and_the_partial_current_one() {
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let mut active = ActiveWeeks::new();
        active.insert((a, d("2026-10-05")));
        active.insert((b, d("2026-10-05")));
        active.insert((a, d("2026-10-12")));
        active.insert((a, d("2026-07-20"))); // 12 weeks back from 2026-10-12
        active.insert((b, d("2026-07-13"))); // 13 weeks back: outside
        let series = wao_series(&active, d("2026-10-14"));
        assert_eq!(series.len(), WAO_WEEKS + 1);
        assert_eq!(series[0].start, "2026-07-20");
        assert_eq!(series[0].active_orgs, 1);
        assert!(!series[0].partial);
        let last = series.last().unwrap();
        assert_eq!(
            (last.start.as_str(), last.active_orgs, last.partial),
            ("2026-10-12", 1, true)
        );
        assert_eq!(series[WAO_WEEKS - 1].active_orgs, 2);
        assert!(series.iter().filter(|w| w.partial).count() == 1);
    }
}
