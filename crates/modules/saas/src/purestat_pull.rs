// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P6 — the purestat puller: purestat's breakdowns of every closed
//! UTC day still inside the freeze horizon, frozen into `growth_daily`
//! (`source: purestat`), with one `growth_pulls` row per day (spec §3i).
//!
//! It is `saas`'s because it talks to the outside world for the hosted
//! business, and no self-host profile compiles `saas` (spec principle 6).
//! Without a key it pulls nothing at all and says so once.
//!
//! # What a day holds
//!
//! Three breakdowns, each row's `dims.by` naming which:
//!
//! | `by` | dims | metrics |
//! |---|---|---|
//! | `site` | — | `visitors` `visits` `pageviews` `reads` `goal.<g>` |
//! | `campaign` | the normalised key: `source`, and `medium` / `campaign` / `content` when present | the same |
//! | `path` | `path` | `visitors` `pageviews` `reads` |
//!
//! * The campaign key is normalised exactly as a sign-up's is at ingress
//!   (`CampaignKey::normalized`); raw rows that fold into one key (`YouTub`
//!   and `youtube`) are SUMMED — an upper bound on unique visitors, since a
//!   visitor who arrived by both spellings counts twice. (purestat ≥ v0.1.9
//!   answers source and medium already normalised; ours is a fixed point on
//!   that, so the fold is right against either version.) A row with no
//!   source is organic traffic and lives in the `site` row only.
//! * `reads` (pageviews visible ≥ 30 s) is the engagement purestat's v1
//!   contract carries; it has no engaged-visitor metric.
//! * A zero is not stored. On a day whose `growth_pulls` row is `ok`, a
//!   missing row IS a measured zero; on a day with no pull row, or a
//!   `failed` one, it is "not pulled" — principle 4, null ≠ 0.
//!
//! # When
//!
//! * **The horizon** is the last [`FREEZE_DAYS`] closed days. A day older
//!   than that is FROZEN: never pulled again, never rewritten — what was
//!   stored for it is what history says.
//! * **A cycle** starts every UTC day at [`CYCLE_HOUR_UTC`] (purestat closes
//!   a visit 30 minutes after its last event, so by then yesterday is
//!   final). Each day of the horizon is pulled once per cycle — a re-pull
//!   catches the late events of a day already pulled ([`due_days`]).
//! * **A failed attempt** leaves the day due, so the next hourly tick
//!   retries it; after a fatal error (no key, 401, a timeout, an
//!   unreachable host) a run stops asking and records the same reason for
//!   the rest of the days it owed, rather than waiting out seven timeouts.
//! * **Once across pods**: each tick takes the DB-name-scoped Redis `NX`
//!   claim the stats rollup and the reapers use; without Redis the pod runs
//!   locally. The writes are idempotent anyway (`$set` on the row's own
//!   `_id`, [`GrowthDao::replace_daily`]), so a double run stores one copy.

use std::collections::{BTreeMap, HashMap};

use bson::DateTime;
use chrono::{Duration, NaiveDate};
use meshharbor_services::{
    dao::{
        base::DaoResult,
        growth::{
            GrowthDaily, GrowthDao, GrowthPull, PURESTAT_FREEZE_DAYS, PURESTAT_SOURCE, PulledDay,
            daily_row,
        },
    },
    purestat::{PurestatClient, PurestatError, Query, Row},
};
use meshharbor_core::{
    Core,
    campaign::{CampaignKey, UTM_DIMENSIONS},
};
use serde::Serialize;
use tracing::{debug, info, warn};

/// The `source` of every row this job writes.
pub const SOURCE: &str = PURESTAT_SOURCE;
/// The freeze horizon, in closed days.
pub const FREEZE_DAYS: i64 = PURESTAT_FREEZE_DAYS;
/// The UTC hour a pull cycle starts.
pub const CYCLE_HOUR_UTC: u32 = 1;
/// The scheduler's cadence — also how soon a failed day is retried.
pub const LOOP_INTERVAL_SECS: u64 = 60 * 60;
/// A pod that just booted waits this long before its first tick.
pub const FIRST_TICK_DELAY_SECS: u64 = 4 * 60;
/// FR-88's four goals.
pub const GOALS: [&str; 4] = ["signup", "subscribe", "install-copy", "github-outbound"];
/// The metrics of a visit-level breakdown (`site`, `campaign`).
pub const VISIT_METRICS: [&str; 4] = ["visitors", "visits", "pageviews", "reads"];
/// The metrics of the `path` breakdown — `visits` is null in purestat for a
/// page dimension, so it is not asked for.
pub const PATH_METRICS: [&str; 3] = ["visitors", "pageviews", "reads"];
/// A stored path is cut to this many characters.
pub const MAX_PATH_LEN: usize = 200;

/// The `growth_daily` metric a goal's conversions are stored under.
pub fn goal_metric(goal: &str) -> String {
    format!("goal.{goal}")
}

/// Every metric a pull of one day writes — the set
/// [`GrowthDao::replace_daily`] prunes within. Without goals (the site did
/// not define one) the goal metrics are left as an earlier pull stored them.
pub fn metrics(goals_measured: bool) -> Vec<String> {
    let mut out: Vec<String> = VISIT_METRICS.iter().map(|m| m.to_string()).collect();
    if goals_measured {
        out.extend(GOALS.iter().map(|g| goal_metric(g)));
    }
    out
}

fn date_of(at: DateTime) -> NaiveDate {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(at.timestamp_millis())
        .expect("a BSON date is in range")
        .date_naive()
}

fn day_str(day: NaiveDate) -> String {
    day.format("%Y-%m-%d").to_string()
}

/// The days a tick at `now` owes, oldest first: every day of the horizon
/// not yet pulled in the current cycle. Before the cycle's hour, nothing —
/// yesterday may still have visits open. A day older than the horizon is
/// never due, pulled or not: frozen.
pub fn due_days(now: DateTime, pulls: &[GrowthPull]) -> Vec<NaiveDate> {
    let today = date_of(now);
    let cycle_start = today
        .and_hms_opt(CYCLE_HOUR_UTC, 0, 0)
        .expect("the cycle hour exists")
        .and_utc()
        .timestamp_millis();
    if now.timestamp_millis() < cycle_start {
        return Vec::new();
    }
    let by_day: HashMap<&str, &GrowthPull> = pulls.iter().map(|p| (p.day.as_str(), p)).collect();
    (1..=FREEZE_DAYS)
        .rev()
        .map(|age| today - Duration::days(age))
        .filter(|d| match by_day.get(day_str(*d).as_str()) {
            None => true,
            Some(p) => p
                .pulled_at
                .is_none_or(|t| t.timestamp_millis() < cycle_start),
        })
        .collect()
}

/// A path as stored: trimmed, control characters dropped, cut to
/// [`MAX_PATH_LEN`]; `None` unless it starts with `/` (anything else is
/// not a page this site served).
pub fn clean_path(raw: &str) -> Option<String> {
    let s: String = raw.trim().chars().filter(|c| !c.is_control()).collect();
    if !s.starts_with('/') {
        return None;
    }
    Some(s.chars().take(MAX_PATH_LEN).collect())
}

type Dims = BTreeMap<String, String>;

fn dims(pairs: &[(&str, &str)]) -> Dims {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The campaign row's dimensions: the normalised key, absent fields left out.
pub fn campaign_dims(key: &CampaignKey) -> Dims {
    let mut d = dims(&[("by", "campaign"), ("source", key.source.as_str())]);
    for (k, v) in [
        ("medium", &key.medium),
        ("campaign", &key.campaign),
        ("content", &key.content),
    ] {
        if let Some(v) = v {
            d.insert(k.to_string(), v.clone());
        }
    }
    d
}

fn add_counts(slot: &mut BTreeMap<String, i64>, r: &Row, metrics: &[&str], goals: bool) {
    for m in metrics {
        *slot.entry(m.to_string()).or_insert(0) += r.count(m);
    }
    if goals {
        for g in GOALS {
            *slot.entry(goal_metric(g)).or_insert(0) += r.goal(g);
        }
    }
}

/// One day's rows from the three breakdowns. Pure, so the shaping — the key
/// normalisation, the folding of spellings, the bounds and the dropped
/// zeros — is tested without a server.
pub fn day_rows(
    day: &str,
    site: &[Row],
    campaigns: &[Row],
    paths: &[Row],
    goals_measured: bool,
) -> Vec<GrowthDaily> {
    let mut acc: BTreeMap<Dims, BTreeMap<String, i64>> = BTreeMap::new();
    // A query without a dimension answers one row: the day's totals.
    if let Some(r) = site.first() {
        add_counts(
            acc.entry(dims(&[("by", "site")])).or_default(),
            r,
            &VISIT_METRICS,
            goals_measured,
        );
    }
    for r in campaigns {
        let Some(key) = CampaignKey::normalized(
            r.dim("utm_source"),
            r.dim("utm_medium"),
            r.dim("utm_campaign"),
            r.dim("utm_content"),
        ) else {
            continue;
        };
        add_counts(
            acc.entry(campaign_dims(&key)).or_default(),
            r,
            &VISIT_METRICS,
            goals_measured,
        );
    }
    for r in paths {
        let Some(path) = r.dim("path").and_then(clean_path) else {
            continue;
        };
        add_counts(
            acc.entry(dims(&[("by", "path"), ("path", path.as_str())]))
                .or_default(),
            r,
            &PATH_METRICS,
            false,
        );
    }
    let mut rows = Vec::new();
    for (d, metrics) in acc {
        for (metric, value) in metrics {
            if value != 0 {
                rows.push(daily_row(SOURCE, &metric, d.clone(), day, value));
            }
        }
    }
    rows
}

/// One day, pulled.
#[derive(Debug, Clone, PartialEq)]
pub struct DayPull {
    pub rows: Vec<GrowthDaily>,
    /// A goal the site does not define: the day's conversions are not
    /// measured (its visitors are).
    pub missing_goal: Option<String>,
    /// A breakdown hit the client's page bound.
    pub truncated: bool,
}

/// The three breakdowns of `day`, shaped. A goal the site does not define
/// costs the conversions, not the day.
pub async fn pull_day(client: &PurestatClient, day: &str) -> Result<DayPull, PurestatError> {
    let (site, missing) = client
        .query_or_without_goals(&Query::day(day, &[], &VISIT_METRICS, &GOALS))
        .await?;
    // A goal the site lacks is lacking for every breakdown: ask without.
    let goals: &[&str] = if missing.is_some() { &[] } else { &GOALS };
    let (campaigns, missing_too) = client
        .query_or_without_goals(&Query::day(day, &UTM_DIMENSIONS, &VISIT_METRICS, goals))
        .await?;
    let paths = client
        .query_paged(&Query::day(day, &["path"], &PATH_METRICS, &[]))
        .await?;
    let missing_goal = missing.or(missing_too);
    Ok(DayPull {
        rows: day_rows(
            day,
            &site.rows,
            &campaigns.rows,
            &paths.rows,
            missing_goal.is_none(),
        ),
        missing_goal,
        truncated: site.truncated || campaigns.truncated || paths.truncated,
    })
}

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PullReport {
    /// The days the run owed, oldest first.
    pub due: Vec<String>,
    pub pulled: u32,
    pub failed: u32,
    pub rows_written: u64,
    pub rows_unchanged: u64,
    pub rows_pruned: u64,
    /// The first error met, as stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Pull every day a tick at `now` owes. Public so a test drives it with an
/// injected `now` and a client pointed at a fake server; the scheduler is
/// [`spawn_puller`]. A database error stops the run (the next tick
/// retries); a purestat error is recorded per day and is never a 0.
pub async fn run_once(
    core: &Core,
    client: &PurestatClient,
    now: DateTime,
) -> DaoResult<PullReport> {
    let dao = GrowthDao::new(&core.db);
    let today = date_of(now);
    let from = day_str(today - Duration::days(FREEZE_DAYS));
    let to = day_str(today - Duration::days(1));
    let pulls = dao.pulls_between(SOURCE, &from, &to).await?;
    let mut report = PullReport::default();
    let mut fatal: Option<PurestatError> = None;
    for day in due_days(now, &pulls) {
        let d = day_str(day);
        report.due.push(d.clone());
        let outcome = match &fatal {
            Some(e) => Err(e.clone()),
            None => pull_day(client, &d).await,
        };
        match outcome {
            Ok(p) => {
                let metrics = metrics(p.missing_goal.is_none());
                let refs: Vec<&str> = metrics.iter().map(String::as_str).collect();
                let c = dao.replace_daily(SOURCE, &d, &refs, &p.rows).await?;
                dao.record_pull_ok(
                    SOURCE,
                    &d,
                    PulledDay {
                        rows: p.rows.len() as u32,
                        missing_goal: p.missing_goal.as_deref(),
                        truncated: p.truncated,
                    },
                    now,
                )
                .await?;
                if p.truncated {
                    warn!(day = %d, "purestat pull: a breakdown hit the page bound; the day holds the busiest rows only");
                }
                report.pulled += 1;
                report.rows_written += c.written;
                report.rows_unchanged += c.unchanged;
                report.rows_pruned += c.pruned;
            }
            Err(e) => {
                if e.is_fatal() && fatal.is_none() {
                    fatal = Some(e.clone());
                }
                let reason = e.to_string();
                dao.record_pull_failed(SOURCE, &d, &reason, now).await?;
                report.failed += 1;
                report.error.get_or_insert(reason);
            }
        }
    }
    Ok(report)
}

/// The scheduler: every [`LOOP_INTERVAL_SECS`], one pod (the Redis claim)
/// runs [`run_once`]. Only with `growth.enabled` and a purestat key — with
/// no key it logs that once and starts nothing, so a server without one
/// never asks anybody anything.
pub fn spawn_puller(core: Core) {
    let growth = &core.settings.growth;
    if !growth.enabled {
        return;
    }
    let Some(client) = PurestatClient::new(&growth.purestat_url, &growth.purestat_api_key) else {
        info!(
            "growth purestat puller: no purestat key configured (ROOMLER__GROWTH__PURESTAT_API_KEY) — nothing is pulled"
        );
        return;
    };
    info!(freeze_days = FREEZE_DAYS, "growth purestat puller starting");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(FIRST_TICK_DELAY_SECS)).await;
        loop {
            let claimed = match &core.redis_pubsub {
                Some(redis) => {
                    let key = format!("roomler:growth-purestat-pull:{}", core.db.name());
                    match redis.try_claim(&key, LOOP_INTERVAL_SECS - 60).await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(%e, "growth purestat pull claim failed; skipping tick");
                            false
                        }
                    }
                }
                None => true,
            };
            if claimed {
                match run_once(&core, &client, DateTime::now()).await {
                    Ok(r) if !r.due.is_empty() => info!(
                        pulled = r.pulled,
                        failed = r.failed,
                        rows_written = r.rows_written,
                        rows_pruned = r.rows_pruned,
                        error = r.error.as_deref().unwrap_or(""),
                        "growth purestat pull"
                    ),
                    Ok(_) => {}
                    Err(e) => warn!(%e, "growth purestat pull failed"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(LOOP_INTERVAL_SECS)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn at(s: &str) -> DateTime {
        DateTime::parse_rfc3339_str(s).unwrap()
    }

    fn pull(day: &str, pulled_at: Option<&str>) -> GrowthPull {
        GrowthPull {
            id: GrowthPull::id_of(SOURCE, day),
            source: SOURCE.into(),
            day: day.into(),
            status: if pulled_at.is_some() {
                meshharbor_services::dao::growth::PullStatus::Ok
            } else {
                meshharbor_services::dao::growth::PullStatus::Failed
            },
            pulled_at: pulled_at.map(at),
            attempted_at: at("2026-10-14T01:30:00Z"),
            attempts: 1,
            rows: 0,
            error: None,
            missing_goal: None,
            truncated: false,
        }
    }

    fn row(dims: &[(&str, Option<&str>)], metrics: &[(&str, f64)], goals: &[(&str, f64)]) -> Row {
        Row {
            dimensions: dims
                .iter()
                .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
                .collect(),
            metrics: metrics
                .iter()
                .map(|(k, v)| (k.to_string(), Some(*v)))
                .collect(),
            goals: goals
                .iter()
                .map(|(k, v)| (k.to_string(), Some(*v)))
                .collect(),
        }
    }

    /// The freeze rule: the horizon is the last seven closed days, today is
    /// never one of them, and a day past the horizon is never due — pulled
    /// or not.
    #[test]
    fn only_the_seven_closed_days_inside_the_horizon_are_ever_due() {
        let now = at("2026-10-14T12:00:00Z");
        let due = due_days(now, &[]);
        assert_eq!(
            due,
            vec![
                d("2026-10-07"),
                d("2026-10-08"),
                d("2026-10-09"),
                d("2026-10-10"),
                d("2026-10-11"),
                d("2026-10-12"),
                d("2026-10-13"),
            ],
            "oldest first, today excluded"
        );
        // A never-pulled day of age 8 is frozen all the same.
        assert!(!due.contains(&d("2026-10-06")));
        // Before the cycle's hour nothing is due: yesterday may be open.
        assert!(due_days(at("2026-10-14T00:59:59Z"), &[]).is_empty());
        assert_eq!(due_days(at("2026-10-14T01:00:00Z"), &[]).len(), 7);
    }

    /// Once per cycle: a day pulled after today's cycle start is done until
    /// tomorrow's; one pulled before it (yesterday's cycle) is re-pulled to
    /// catch late events; a failed day (no `pulled_at`) is retried on the
    /// next tick.
    #[test]
    fn a_day_is_re_pulled_once_per_cycle_and_a_failed_one_until_it_succeeds() {
        let now = at("2026-10-14T05:00:00Z");
        let pulls = vec![
            pull("2026-10-13", Some("2026-10-14T01:05:00Z")), // this cycle: done
            pull("2026-10-12", Some("2026-10-13T01:05:00Z")), // last cycle: re-pull
            pull("2026-10-11", None),                         // failed: retry
            pull("2026-10-10", Some("2026-10-14T00:59:00Z")), // before the cycle: re-pull
        ];
        let due = due_days(now, &pulls);
        assert!(!due.contains(&d("2026-10-13")));
        assert!(due.contains(&d("2026-10-12")));
        assert!(due.contains(&d("2026-10-11")));
        assert!(due.contains(&d("2026-10-10")));
        assert_eq!(due.len(), 6);
    }

    /// The shaping: the key normalised as at ingress, spellings folded
    /// (summed), organic rows left to the site row, paths bounded, goals
    /// kept per row, zeros dropped, and every row's `_id` its own fact.
    #[test]
    fn a_days_rows_fold_spellings_drop_zeros_and_bound_paths() {
        let site = vec![row(
            &[],
            &[
                ("visitors", 44.0),
                ("visits", 77.0),
                ("pageviews", 241.0),
                ("reads", 0.0),
            ],
            &[("signup", 1.0)],
        )];
        let campaigns = vec![
            row(
                &[
                    ("utm_source", Some("LinkedIn")),
                    ("utm_medium", Some("post")),
                    ("utm_campaign", Some("C1")),
                    ("utm_content", None),
                ],
                &[
                    ("visitors", 52.0),
                    ("visits", 60.0),
                    ("pageviews", 265.0),
                    ("reads", 30.0),
                ],
                &[("signup", 1.0)],
            ),
            row(
                &[
                    ("utm_source", Some("linkedin")),
                    ("utm_medium", Some("Post")),
                    ("utm_campaign", Some("c1")),
                    ("utm_content", None),
                ],
                &[("visitors", 3.0), ("visits", 3.0), ("pageviews", 3.0)],
                &[],
            ),
            // Organic: no source — the site row has it.
            row(
                &[
                    ("utm_source", None),
                    ("utm_medium", None),
                    ("utm_campaign", None),
                    ("utm_content", None),
                ],
                &[("visitors", 20.0)],
                &[],
            ),
            // A source the cleaning refuses is no key.
            row(
                &[("utm_source", Some("yöutube"))],
                &[("visitors", 9.0)],
                &[],
            ),
        ];
        let long = format!("/blog/{}", "x".repeat(400));
        let paths = vec![
            row(
                &[("path", Some("/blog/a/"))],
                &[("visitors", 10.0), ("pageviews", 12.0)],
                &[],
            ),
            row(
                &[("path", Some(long.as_str()))],
                &[("visitors", 1.0), ("pageviews", 1.0)],
                &[],
            ),
            row(&[("path", Some("not-a-path"))], &[("visitors", 5.0)], &[]),
        ];
        let rows = day_rows("2026-10-13", &site, &campaigns, &paths, true);
        let get = |by: &str, extra: &[(&str, &str)], metric: &str| -> Option<i64> {
            let mut want = dims(&[("by", by)]);
            for (k, v) in extra {
                want.insert(k.to_string(), v.to_string());
            }
            rows.iter()
                .find(|r| r.dims == want && r.metric == metric)
                .map(|r| r.value)
        };
        // The site row, zeros dropped (`reads` was 0).
        assert_eq!(get("site", &[], "visitors"), Some(44));
        assert_eq!(get("site", &[], "goal.signup"), Some(1));
        assert_eq!(get("site", &[], "reads"), None, "a zero is not stored");
        assert_eq!(get("site", &[], "goal.subscribe"), None);
        // LinkedIn/post/C1 and linkedin/Post/c1 are one key, summed.
        let li = [
            ("source", "linkedin"),
            ("medium", "post"),
            ("campaign", "c1"),
        ];
        assert_eq!(get("campaign", &li, "visitors"), Some(55));
        assert_eq!(get("campaign", &li, "visits"), Some(63));
        assert_eq!(get("campaign", &li, "goal.signup"), Some(1));
        // No organic or refused-source campaign row.
        assert_eq!(
            rows.iter()
                .filter(|r| r.dims.get("by").map(String::as_str) == Some("campaign"))
                .map(|r| r.dims.get("source").cloned().unwrap_or_default())
                .collect::<std::collections::BTreeSet<_>>(),
            ["linkedin".to_string()].into_iter().collect()
        );
        // Paths: kept, bounded, the non-path dropped.
        assert_eq!(get("path", &[("path", "/blog/a/")], "pageviews"), Some(12));
        let cut: String = long.chars().take(MAX_PATH_LEN).collect();
        assert_eq!(get("path", &[("path", cut.as_str())], "visitors"), Some(1));
        assert!(
            rows.iter()
                .all(|r| r.dims.get("path").is_none_or(|p| p.starts_with('/'))),
            "a non-path is never stored"
        );
        // Every row is the day's, the source's, with its own id.
        let ids: std::collections::HashSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), rows.len());
        assert!(
            rows.iter()
                .all(|r| r.day == "2026-10-13" && r.source == SOURCE)
        );
        // Without goals measured, no goal row is written.
        let no_goals = day_rows("2026-10-13", &site, &campaigns, &paths, false);
        assert!(no_goals.iter().all(|r| !r.metric.starts_with("goal.")));
        assert_eq!(
            metrics(false),
            vec!["visitors", "visits", "pageviews", "reads"]
        );
        assert_eq!(metrics(true).len(), 8);
        assert!(metrics(true).contains(&"goal.install-copy".to_string()));
    }

    #[test]
    fn a_path_is_cleaned_or_refused() {
        assert_eq!(clean_path(" /pricing "), Some("/pricing".into()));
        assert_eq!(clean_path("/a\u{0}b"), Some("/ab".into()));
        assert_eq!(clean_path("pricing"), None);
        assert_eq!(clean_path(""), None);
        assert_eq!(
            clean_path(&format!("/{}", "é".repeat(500))).map(|p| p.chars().count()),
            Some(MAX_PATH_LEN)
        );
    }
}
