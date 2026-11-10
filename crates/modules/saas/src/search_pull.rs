// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the Search Console puller (spec §3k): Google's clicks,
//! impressions and position per page × query × day, frozen into
//! `growth_daily` (`source: search_console`) with one `growth_pulls` row per
//! day, through a service account added to `sc-domain:meshharbor.itachi.fans`.
//!
//! `saas`'s, like every puller (no self-host profile compiles it). Without
//! a key it pulls nothing and says so once; a key that does not parse is
//! said once too, loudly, and pulls nothing.
//!
//! # What a day holds
//!
//! | `dims.by` | other dims | from |
//! |---|---|---|
//! | `site` | — | a `date` breakdown: the property's totals (by property: one impression per results page) |
//! | `page` | `page` (the URL as Google reports it) | a `page` breakdown — the per-page totals, anonymised queries included |
//! | `query` | `query` | a `query` breakdown (by property) — anonymised queries left out by Google |
//! | `page_query` | `page`, `query` | a `page` × `query` breakdown — its sum is LOWER than the `page` rows, by exactly the anonymised queries |
//!
//! Metrics `clicks`, `impressions` and `position_x100` — the position
//! weighted by impressions, ×100, rounded (`Σ position·impressions·100`):
//! the average over any set of rows is `Σ position_x100 / Σ impressions /
//! 100`, which is how Google itself averages position. CTR is
//! `clicks / impressions` and is not stored. A zero is not stored.
//!
//! # When
//!
//! * **Only final days.** Google's data settles over 2–3 days (sometimes
//!   more). Each cycle first asks the `date` breakdown with
//!   `dataState: all`, whose `metadata.firstIncompleteDate` says where the
//!   unsettled days start; a day from there on is NOT pulled — it stays
//!   due, "pending", never a partial day stored as if it were whole. When
//!   Google omits the date, the Pacific day still running is pending all
//!   the same ([`pacific_today`]). The breakdowns of a final day are asked
//!   with `dataState: final`.
//! * **The horizon** is the last [`HORIZON_DAYS`] closed days: on its first
//!   cycle the puller fills them all (Search Console keeps 16 months, but
//!   the Content table reads 28 days), and a day older than that is frozen.
//! * **The settle window**: a day younger than [`SETTLE_DAYS`] is re-pulled
//!   once per cycle, catching a late correction; an older one is pulled
//!   until it succeeds once (`pull_schedule::due_days`).
//! * A day is Google's: Search Console dates are **Pacific-time days**.
//! * A fatal error (the key, the token, a 401/403, a quota, a timeout)
//!   stops the run and records the reason for every day it owed.

use std::collections::BTreeMap;

use bson::DateTime;
use chrono::Duration;
use meshharbor_core::Core;
use meshharbor_services::dao::{
    base::DaoResult,
    growth::{GrowthDaily, GrowthDao, PulledDay, SEARCH_CONSOLE_SOURCE, daily_row},
};
use serde::Serialize;
use tracing::{info, warn};

use crate::{
    pull_schedule::{self, date_of, day_str},
    search_console::{ScClient, ScError, ScQuery, ScResponse, ScRow},
};

pub const SOURCE: &str = SEARCH_CONSOLE_SOURCE;
/// The UTC hour a cycle starts (after the purestat puller's).
pub const CYCLE_HOUR_UTC: u32 = 2;
/// Closed days pulled at all; older ones are frozen.
pub const HORIZON_DAYS: i64 = 30;
/// Days re-pulled once per cycle after they first succeed.
pub const SETTLE_DAYS: i64 = 5;
pub const LOOP_INTERVAL_SECS: u64 = 60 * 60;
pub const FIRST_TICK_DELAY_SECS: u64 = 6 * 60;
/// Every metric a pull of one day writes.
pub const METRICS: [&str; 3] = ["clicks", "impressions", "position_x100"];
/// A stored page URL is cut to this many characters.
pub const MAX_PAGE_LEN: usize = 300;
/// A stored query is cut to this many characters.
pub const MAX_QUERY_LEN: usize = 200;

/// A dimension value as stored: control characters dropped, trimmed, cut;
/// `None` when nothing is left.
pub fn clean(raw: &str, max: usize) -> Option<String> {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(max)
        .collect();
    (!s.is_empty()).then_some(s)
}

#[derive(Default, Clone, Copy)]
struct Acc {
    clicks: f64,
    impressions: f64,
    position_x100: f64,
}

impl Acc {
    fn add(&mut self, r: &ScRow) {
        let impressions = r.impressions.unwrap_or(0.0).max(0.0);
        self.clicks += r.clicks.unwrap_or(0.0).max(0.0);
        self.impressions += impressions;
        if let Some(p) = r.position {
            self.position_x100 += p * impressions * 100.0;
        }
    }
}

type Dims = BTreeMap<String, String>;

fn dims(pairs: &[(&str, &str)]) -> Dims {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Pure: a breakdown's rows as stored. `by` names the breakdown; `keys`
/// names the request's dimensions in order (`date` keys are dropped, the
/// day is the row's own). Rows that fold into one cleaned key are summed;
/// zeros are not stored.
pub fn rows_of(day: &str, by: &str, keys: &[&str], rows: &[ScRow]) -> Vec<GrowthDaily> {
    let mut acc: BTreeMap<Dims, Acc> = BTreeMap::new();
    'row: for r in rows {
        let mut d = dims(&[("by", by)]);
        for (i, k) in keys.iter().enumerate() {
            if *k == "date" {
                continue;
            }
            let max = if *k == "page" {
                MAX_PAGE_LEN
            } else {
                MAX_QUERY_LEN
            };
            match r.keys.get(i).and_then(|v| clean(v, max)) {
                Some(v) => {
                    d.insert(k.to_string(), v);
                }
                None => continue 'row,
            }
        }
        acc.entry(d).or_default().add(r);
    }
    let mut out = Vec::new();
    for (d, a) in acc {
        for (metric, value) in [
            ("clicks", a.clicks),
            ("impressions", a.impressions),
            ("position_x100", a.position_x100),
        ] {
            let v = value.round() as i64;
            if v != 0 {
                out.push(daily_row(SOURCE, metric, d.clone(), day, v));
            }
        }
    }
    out
}

/// The days of `due` that Google calls final: before `first_incomplete`
/// (all of them when Google names no incomplete day).
pub fn final_days(due: &[String], first_incomplete: Option<&str>, now: DateTime) -> Vec<String> {
    let in_progress = pacific_today(now);
    due.iter()
        .filter(|d| first_incomplete.is_none_or(|f| d.as_str() < f))
        // Whatever Google's metadata says — or omits — the Pacific day still
        // running is never final.
        .filter(|d| d.as_str() < in_progress.as_str())
        .cloned()
        .collect()
}

/// The Pacific date at `now`, read conservatively. Google's day is
/// America/Los_Angeles — UTC−8 in winter, UTC−7 in summer — and the date at
/// `now` − 8 h is never later than the true one, so a day still running is
/// never taken for final; in summer a day is held back at most an hour past
/// its end.
pub fn pacific_today(now: DateTime) -> String {
    day_str(date_of(DateTime::from_millis(
        now.timestamp_millis() - 8 * 3_600_000,
    )))
}

/// One final day, pulled: its `site` rows come from the `date` breakdown
/// already read; the other three breakdowns are asked here.
pub async fn pull_day(
    client: &ScClient,
    day: &str,
    by_date: &ScResponse,
) -> Result<(Vec<GrowthDaily>, bool), ScError> {
    let site_rows: Vec<ScRow> = by_date
        .rows
        .iter()
        .filter(|r| r.keys.first().map(String::as_str) == Some(day))
        .cloned()
        .collect();
    let mut rows = rows_of(day, "site", &["date"], &site_rows);
    let mut truncated = false;
    for (by, keys) in [
        ("page", &["page"][..]),
        ("query", &["query"][..]),
        ("page_query", &["page", "query"][..]),
    ] {
        let (r, cut) = client
            .query_all(&ScQuery::new(day, day, keys, "final"))
            .await?;
        truncated |= cut;
        rows.extend(rows_of(day, by, keys, &r.rows));
    }
    Ok((rows, truncated))
}

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PullReport {
    pub due: Vec<String>,
    /// Due days Google does not call final yet: left due, nothing stored.
    pub pending: Vec<String>,
    pub pulled: u32,
    pub failed: u32,
    pub rows_written: u64,
    pub rows_pruned: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One run at `now`. Public so a test drives it with an injected `now` and
/// a client pointed at a fake Google; the scheduler is [`spawn_puller`].
pub async fn run_once(core: &Core, client: &ScClient, now: DateTime) -> DaoResult<PullReport> {
    let dao = GrowthDao::new(&core.db);
    let today = date_of(now);
    let from = day_str(today - Duration::days(HORIZON_DAYS));
    let to = day_str(today - Duration::days(1));
    let pulls = dao.pulls_between(SOURCE, &from, &to).await?;
    let due: Vec<String> =
        pull_schedule::due_days(now, &pulls, CYCLE_HOUR_UTC, HORIZON_DAYS, SETTLE_DAYS)
            .into_iter()
            .map(day_str)
            .collect();
    let mut report = PullReport {
        due: due.clone(),
        ..Default::default()
    };
    let (Some(first), Some(last)) = (due.first(), due.last()) else {
        return Ok(report);
    };
    // Which days are final, and their property totals, in one request.
    let by_date = client
        .query_all(&ScQuery::new(first, last, &["date"], "all"))
        .await;
    let by_date = match by_date {
        Ok((r, _)) => r,
        Err(e) => {
            let reason = e.to_string();
            for d in &due {
                dao.record_pull_failed(SOURCE, d, &reason, now).await?;
            }
            report.failed = due.len() as u32;
            report.error = Some(reason);
            return Ok(report);
        }
    };
    let first_incomplete = by_date
        .metadata
        .as_ref()
        .and_then(|m| m.first_incomplete_date.clone());
    let finals = final_days(&due, first_incomplete.as_deref(), now);
    report.pending = due
        .iter()
        .filter(|d| !finals.contains(d))
        .cloned()
        .collect();
    let mut fatal: Option<ScError> = None;
    for d in &finals {
        let outcome = match &fatal {
            Some(e) => Err(e.clone()),
            None => pull_day(client, d, &by_date).await,
        };
        match outcome {
            Ok((rows, truncated)) => {
                let c = dao.replace_daily(SOURCE, d, &METRICS, &rows).await?;
                dao.record_pull_ok(
                    SOURCE,
                    d,
                    PulledDay {
                        rows: rows.len() as u32,
                        missing_goal: None,
                        truncated,
                    },
                    now,
                )
                .await?;
                if truncated {
                    warn!(day = %d, "search console pull: a breakdown hit the page bound; the day holds the busiest rows only");
                }
                report.pulled += 1;
                report.rows_written += c.written;
                report.rows_pruned += c.pruned;
            }
            Err(e) => {
                if e.is_fatal() && fatal.is_none() {
                    fatal = Some(e.clone());
                }
                let reason = e.to_string();
                dao.record_pull_failed(SOURCE, d, &reason, now).await?;
                report.failed += 1;
                report.error.get_or_insert(reason);
            }
        }
    }
    Ok(report)
}

/// The scheduler: hourly, one pod (the Redis claim), only with
/// `growth.enabled` and a usable key — without one it says so once and
/// starts nothing; with an unusable one it says why, loudly, once.
pub fn spawn_puller(core: Core) {
    let growth = &core.settings.growth;
    if !growth.enabled {
        return;
    }
    let client = match ScClient::from_settings(growth) {
        None => {
            info!(
                "growth search console puller: no key configured (MESHHARBOR__GROWTH__SEARCH_CONSOLE_KEY) — nothing is pulled"
            );
            return;
        }
        Some(Err(e)) => {
            warn!(error = %e, "growth search console puller: the configured key is unusable — nothing is pulled");
            return;
        }
        Some(Ok(c)) => c,
    };
    info!(
        site = client.site(),
        "growth search console puller starting"
    );
    pull_schedule::spawn_hourly(
        core,
        "growth-search-console-pull",
        FIRST_TICK_DELAY_SECS,
        LOOP_INTERVAL_SECS,
        move |core| {
            let client = client.clone();
            async move {
                match run_once(&core, &client, DateTime::now()).await {
                    Ok(r) if !r.due.is_empty() => info!(
                        pulled = r.pulled,
                        pending = r.pending.len(),
                        failed = r.failed,
                        rows_written = r.rows_written,
                        error = r.error.as_deref().unwrap_or(""),
                        "growth search console pull"
                    ),
                    Ok(_) => {}
                    Err(e) => warn!(%e, "growth search console pull failed"),
                }
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(keys: &[&str], clicks: f64, impressions: f64, position: Option<f64>) -> ScRow {
        ScRow {
            keys: keys.iter().map(|k| k.to_string()).collect(),
            clicks: Some(clicks),
            impressions: Some(impressions),
            position,
        }
    }

    fn value(rows: &[GrowthDaily], extra: &[(&str, &str)], metric: &str) -> Option<i64> {
        rows.iter()
            .find(|r| {
                r.metric == metric
                    && extra
                        .iter()
                        .all(|(k, v)| r.dims.get(*k).map(String::as_str) == Some(*v))
            })
            .map(|r| r.value)
    }

    /// The shaping: the date key dropped (the day is the row's), the
    /// position weighted by impressions ×100, spellings folding into one
    /// cleaned key summed, a row with an empty key dropped, zeros not stored.
    #[test]
    fn a_breakdown_shapes_into_weighted_rows() {
        let rows = vec![
            row(
                &["https://meshharbor.itachi.fans/blog/a/", "remote desktop"],
                2.0,
                40.0,
                Some(3.5),
            ),
            row(
                &[
                    "https://meshharbor.itachi.fans/blog/a/",
                    " remote desktop\u{0}",
                ],
                1.0,
                10.0,
                Some(8.0),
            ),
            row(
                &["https://meshharbor.itachi.fans/blog/b/", ""],
                5.0,
                5.0,
                Some(1.0),
            ),
            row(
                &["https://meshharbor.itachi.fans/blog/c/", "self hosted"],
                0.0,
                3.0,
                None,
            ),
        ];
        let out = rows_of("2026-10-12", "page_query", &["page", "query"], &rows);
        let a = [
            ("page", "https://meshharbor.itachi.fans/blog/a/"),
            ("query", "remote desktop"),
        ];
        assert_eq!(value(&out, &a, "clicks"), Some(3));
        assert_eq!(value(&out, &a, "impressions"), Some(50));
        // (3.5 × 40 + 8 × 10) × 100 = 22,000 → an average of 4.4.
        assert_eq!(value(&out, &a, "position_x100"), Some(22_000));
        assert!(
            out.iter().all(|r| r.dims.get("page").map(String::as_str)
                != Some("https://meshharbor.itachi.fans/blog/b/")),
            "an empty query is no key"
        );
        let c = [("query", "self hosted")];
        assert_eq!(value(&out, &c, "clicks"), None, "a zero is not stored");
        assert_eq!(value(&out, &c, "impressions"), Some(3));
        assert_eq!(
            value(&out, &c, "position_x100"),
            None,
            "no position: not stored"
        );
        assert!(
            out.iter()
                .all(|r| r.source == SOURCE && r.day == "2026-10-12")
        );

        let site = rows_of(
            "2026-10-12",
            "site",
            &["date"],
            &[row(&["2026-10-12"], 9.0, 300.0, Some(12.0))],
        );
        assert_eq!(
            value(&site, &[("by", "site")], "position_x100"),
            Some(360_000)
        );
        assert_eq!(
            site[0].dims.len(),
            1,
            "the date is the row's day, not a dimension"
        );
    }

    /// Only the days before Google's first incomplete one are final; with no
    /// incomplete day named, every due day is.
    #[test]
    fn only_final_days_are_pulled() {
        let due: Vec<String> = ["2026-10-10", "2026-10-11", "2026-10-12", "2026-10-13"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let later = DateTime::parse_rfc3339_str("2026-10-20T12:00:00Z").unwrap();
        assert_eq!(
            final_days(&due, Some("2026-10-12"), later),
            ["2026-10-10", "2026-10-11"]
        );
        assert_eq!(final_days(&due, None, later).len(), 4);
        assert!(final_days(&due, Some("2026-10-01"), later).is_empty());
        // Google omitted `firstIncompleteDate`: the Pacific day still running
        // is not final. At 03:00 UTC on 10-14 it is 10-13 in California.
        let early = DateTime::parse_rfc3339_str("2026-10-14T03:00:00Z").unwrap();
        assert_eq!(pacific_today(early), "2026-10-13");
        assert_eq!(
            final_days(&due, None, early),
            ["2026-10-10", "2026-10-11", "2026-10-12"]
        );
        // From 08:00 UTC the 13th is over in both of Pacific's offsets.
        let after = DateTime::parse_rfc3339_str("2026-10-14T08:00:00Z").unwrap();
        assert_eq!(final_days(&due, None, after).len(), 4);
    }
}
