// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P10 — alerts (spec §3l): a small set of rules over this server's
//! own growth numbers, evaluated by an hourly host job, each opening a
//! `growth_alerts` row once, mailing the digest's recipients at most once
//! per rule and key per day, and closing the row when the condition goes
//! away. `ROOMLER__GROWTH__ALERTS` (default off) switches all of them.
//!
//! # The rules
//!
//! | rule | key | fires when | clears when |
//! |---|---|---|---|
//! | `digest_missing` | `daily` | the daily digest is on, the latest DUE day (yesterday from `digest_hour_utc` + 2 h, the day before until then) has no row, a `failed` one, or a `computing` one older than the stale cutoff | that day's row is `sent`, `stored` or `preview`, or the digest is off |
//! | `source_not_measured` | `purestat` | the digest's web plane read "not measured" on the two latest due days while a purestat key is configured | either day measured, or no key |
//! | `source_not_measured` | `purestat_pull` | the `saas` puller's `growth_pulls` rows for the two latest cycled days are both absent or `failed` — once the puller has any row at all | either day `ok`, or nothing pulls here |
//! | `source_not_measured` | `sendgrid` | on each of the two latest closed days ≥ 1 newsletter send was accepted and NOT ONE delivery event arrived, with the webhook key configured | either day recorded an event, or no key |
//! | `source_not_measured` | `search_console_pull` · `url_inspection_pull` · `content_pull` · `github_pull` · `github_traffic_pull` · `bing_pull` | a configured `saas` puller is **failing two days running**: it still tries (an attempt in the last 26 h), and nothing it pulled has succeeded in 48 h (never, for a puller first tried ≥ 48 h ago). Measured on the clock, not on its ledger's days, because each puller dates its rows differently (Google's final day, yesterday, today) | a pull succeeds, the puller stops trying (switched off, unmounted), or it is not configured |
//! | `spike` / `drop` | `signups` | yesterday's sign-ups against the 28 days before: baseline n ≥ 30; spike `x > m + 3√m` and `x ≥ 2m`; drop `x < m − 3√m` | yesterday is within the band |
//! | `spike` / `drop` | `visitors` | the same, over the puller's daily `visitors` rows (`by = site`); needs yesterday's row and ≥ 21 of the 28 baseline days | the same |
//!
//! Every rule has an n floor (principle 5): a spike on a baseline of 5
//! sign-ups is noise, and never fires. A rule that cannot be evaluated —
//! its source not configured, not mounted, or not yet pulled — holds
//! nothing, which clears any open row (the condition it described no
//! longer applies).
//!
//! # Once, with two pods
//!
//! The fire is an insert under the partial unique index on `(rule, key)`
//! for open rows: two pods evaluating at once open ONE row. The mail is a
//! compare-and-set on the row's `mailed_on` (`GrowthAlertDao::mark_mailed`),
//! after a check that no row of the pair was mailed today, so a clear and
//! a re-fire inside one day do not mail twice either. The hourly job also
//! takes a Redis claim when one is available, so normally one pod
//! evaluates per hour.
//!
//! Detail carries days and numbers, never a person.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{Bson, DateTime, Document, doc};
use chrono::{Duration, NaiveDate, Timelike};
use meshharbor_services::dao::{
    growth::{
        BING_SOURCE, CONTENT_SOURCE, GITHUB_SOURCE, GITHUB_TRAFFIC_SOURCE, GrowthDao, GrowthPull,
        PURESTAT_SOURCE, PullStatus, SEARCH_CONSOLE_SOURCE, URL_INSPECTION_SOURCE,
    },
    growth_alert::{GrowthAlert, GrowthAlertDao},
    growth_digest::{DigestStatus, DigestStore},
};
use meshharbor_core::growth::ExclusionSet;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{
    digest::{
        self, AlertRow, AlertsSection, DigestError, DigestMailer, SMALL_N, STALE_CLAIM_SECS,
        Windows, day_str, dt_ms, excluded_ids, find_docs, parse_day, utc_date_of,
    },
    mounted,
    read_key::GrowthAuth,
};
use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};

/// The evaluator's cadence.
pub const LOOP_INTERVAL_SECS: u64 = 60 * 60;
/// A pod that just booted waits this long before its first evaluation —
/// after the digest's and the puller's first ticks, so a fresh deploy does
/// not alert on work those are about to do.
pub const FIRST_TICK_DELAY_SECS: u64 = 5 * 60;
/// The digest is given this long past its hour before its absence counts.
pub const DIGEST_GRACE_HOURS: u32 = 2;
/// The puller's cycle hour plus this grace is when its day is expected.
pub const PULL_GRACE_HOURS: u32 = 1;
/// The puller's cycle hour (`saas::purestat_pull::CYCLE_HOUR_UTC`, not
/// imported: the host does not depend on the module crate).
pub const PULL_CYCLE_HOUR_UTC: u32 = 1;
/// Consecutive days a source must read "not measured" to fire.
pub const NOT_MEASURED_DAYS: usize = 2;
/// A puller fails "two days running" when nothing it pulled succeeded in
/// this long (§3l).
pub const PULL_FAILING_HOURS: i64 = 48;
/// … while it still tries: its newest attempt is this recent. A puller with
/// no attempt this recent was switched off or is not due, and holds nothing.
pub const PULL_TRYING_HOURS: i64 = 26;
/// The pullers the failing-pull keys watch: `(key, growth_pulls source)`.
/// purestat keeps its own day-based `purestat_pull` check.
pub const PULLERS: [(&str, &str); 6] = [
    ("search_console_pull", SEARCH_CONSOLE_SOURCE),
    ("url_inspection_pull", URL_INSPECTION_SOURCE),
    ("content_pull", CONTENT_SOURCE),
    ("github_pull", GITHUB_SOURCE),
    ("github_traffic_pull", GITHUB_TRAFFIC_SOURCE),
    ("bing_pull", BING_SOURCE),
];
/// The baseline a spike or drop is read against.
pub const BASELINE_DAYS: i64 = 28;
/// Baseline days the puller must have for the visitors rule.
pub const MIN_BASELINE_DAYS_PRESENT: i64 = 21;
/// The spike's and drop's distance from the mean, in standard deviations
/// of a Poisson count.
pub const SIGMAS: f64 = 3.0;
/// A spike must also be at least this multiple of the mean.
pub const SPIKE_MIN_RATIO: f64 = 2.0;
/// The recent window the alerts route lists cleared rows from.
pub const RECENT_DAYS: i64 = 7;

// ── Rules ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    DigestMissing,
    SourceNotMeasured,
    Spike,
    Drop,
}

impl Rule {
    pub const ALL: [Rule; 4] = [
        Rule::DigestMissing,
        Rule::SourceNotMeasured,
        Rule::Spike,
        Rule::Drop,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Rule::DigestMissing => "digest_missing",
            Rule::SourceNotMeasured => "source_not_measured",
            Rule::Spike => "spike",
            Rule::Drop => "drop",
        }
    }

    /// The keys the rule is evaluated for, in evaluation order.
    pub fn keys(self) -> &'static [&'static str] {
        match self {
            Rule::DigestMissing => &["daily"],
            Rule::SourceNotMeasured => &[
                "purestat",
                "purestat_pull",
                "sendgrid",
                "search_console_pull",
                "url_inspection_pull",
                "content_pull",
                "github_pull",
                "github_traffic_pull",
                "bing_pull",
            ],
            Rule::Spike | Rule::Drop => &["signups", "visitors"],
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Rule::DigestMissing => {
                "the daily digest failed, stalled or did not run for the latest due day"
            }
            Rule::SourceNotMeasured => {
                "a source read \"not measured\" on two consecutive days while configured"
            }
            Rule::Spike => {
                "yesterday's count is above the trailing 28-day band (n ≥ 30; > mean + 3σ and ≥ 2× mean)"
            }
            Rule::Drop => {
                "yesterday's count is below the trailing 28-day band (n ≥ 30; < mean − 3σ)"
            }
        }
    }
}

/// What the rules decided for one `(rule, key)`: `Some(detail)` when the
/// condition holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub rule: Rule,
    pub key: &'static str,
    pub holds: Option<Document>,
}

/// A verdict as the route and the evaluation report answer it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerdictJson {
    pub rule: Rule,
    pub key: String,
    pub holds: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl VerdictJson {
    fn of(v: &Verdict) -> Self {
        Self {
            rule: v.rule,
            key: v.key.to_string(),
            holds: v.holds.is_some(),
            detail: v.holds.as_ref().and_then(|d| serde_json::to_value(d).ok()),
        }
    }
}

// ── The band ─────────────────────────────────────────────────────────────

/// A spike or drop decision over a baseline: pure, so the thresholds are
/// tested without a database.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Band {
    /// The baseline's total.
    pub n: i64,
    /// The baseline days the total rests on.
    pub days: i64,
    pub mean: f64,
    pub spike_above: f64,
    pub drop_below: f64,
}

impl Band {
    /// `None` below the n floor, or without a day to rest on.
    pub fn of(n: i64, days: i64) -> Option<Self> {
        if days <= 0 || n < SMALL_N {
            return None;
        }
        let mean = n as f64 / days as f64;
        let sd = mean.sqrt();
        Some(Self {
            n,
            days,
            mean,
            spike_above: (mean + SIGMAS * sd).max(mean * SPIKE_MIN_RATIO),
            drop_below: mean - SIGMAS * sd,
        })
    }

    pub fn is_spike(&self, x: i64) -> bool {
        (x as f64) > self.spike_above
    }

    pub fn is_drop(&self, x: i64) -> bool {
        (x as f64) < self.drop_below
    }

    /// The detail a fired spike or drop carries.
    pub fn detail(&self, day: NaiveDate, x: i64, rule: Rule) -> Document {
        let r2 = |v: f64| (v * 100.0).round() / 100.0;
        doc! {
            "day": day_str(day),
            "value": x,
            "baseline_n": self.n,
            "baseline_days": self.days,
            "baseline_mean": r2(self.mean),
            "threshold": r2(match rule {
                Rule::Drop => self.drop_below,
                _ => self.spike_above,
            }),
        }
    }
}

// ── Evaluating ───────────────────────────────────────────────────────────

fn utc(now: DateTime) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now.timestamp_millis())
        .expect("a BSON date is in range")
}

/// The latest day the digest is DUE at `now`: yesterday once the clock has
/// passed `digest_hour + grace`, the day before until then.
pub fn latest_due_day(now: DateTime, digest_hour: u8, grace_hours: u32) -> NaiveDate {
    let t = utc(now);
    let today = t.date_naive();
    let due_hour = u32::from(digest_hour) + grace_hours;
    if t.hour() >= due_hour {
        today - Duration::days(1)
    } else {
        today - Duration::days(2)
    }
}

/// The two latest days a daily source is expected to have covered.
fn latest_due_days(now: DateTime, hour: u8, grace_hours: u32) -> [NaiveDate; 2] {
    let d1 = latest_due_day(now, hour, grace_hours);
    [d1 - Duration::days(1), d1]
}

/// How a stored digest day reads for the `digest_missing` rule.
fn digest_state(
    doc: Option<&meshharbor_services::dao::growth_digest::DigestDoc>,
    now: DateTime,
) -> Option<Document> {
    let Some(d) = doc else {
        return Some(doc! { "status": "missing" });
    };
    match d.status {
        DigestStatus::Sent | DigestStatus::Stored | DigestStatus::Preview => None,
        DigestStatus::Failed => Some(doc! {
            "status": "failed",
            "attempts": d.attempts as i64,
            "error": d.error.clone().unwrap_or_default(),
        }),
        DigestStatus::Computing => {
            let cutoff = now.timestamp_millis() - STALE_CLAIM_SECS * 1000;
            (d.claimed_at.timestamp_millis() < cutoff).then(|| {
                doc! { "status": "stalled", "attempts": d.attempts as i64 }
            })
        }
    }
}

async fn digest_missing(state: &AppState, now: DateTime) -> Result<Option<Document>, DigestError> {
    let g = &state.settings.growth;
    if !g.digest_enabled {
        return Ok(None);
    }
    let day = latest_due_day(now, g.digest_hour(), DIGEST_GRACE_HOURS);
    let key = day_str(day);
    let row = DigestStore::new(&state.db).get(&key).await?;
    Ok(digest_state(row.as_ref(), now).map(|mut d| {
        d.insert("day", key);
        d
    }))
}

/// Whether a stored section reads "not measured" (the serialised
/// `Measured::NotMeasured` arm), with its reason.
fn not_measured_reason(sections: Option<&Document>, section: &str) -> Option<String> {
    sections
        .and_then(|s| s.get_document(section).ok())
        .and_then(|s| s.get_str("not_measured").ok())
        .map(str::to_string)
}

async fn purestat_not_measured(
    state: &AppState,
    now: DateTime,
) -> Result<Option<Document>, DigestError> {
    let g = &state.settings.growth;
    if !g.digest_enabled || !g.purestat_configured() {
        return Ok(None);
    }
    let store = DigestStore::new(&state.db);
    let mut days = Vec::new();
    let mut reason = String::new();
    for day in latest_due_days(now, g.digest_hour(), DIGEST_GRACE_HOURS) {
        let key = day_str(day);
        let Some(row) = store.get(&key).await? else {
            // Cannot tell: the digest rule speaks for a missing day.
            return Ok(None);
        };
        let Some(r) = not_measured_reason(row.sections.as_ref(), "website") else {
            return Ok(None);
        };
        days.push(key);
        reason = r;
    }
    Ok((days.len() == NOT_MEASURED_DAYS).then(|| doc! { "days": days, "reason": reason }))
}

async fn purestat_pull_not_measured(
    state: &AppState,
    now: DateTime,
) -> Result<Option<Document>, DigestError> {
    let g = &state.settings.growth;
    if !mounted(state, "saas") || !g.purestat_configured() {
        return Ok(None);
    }
    let dao = GrowthDao::new(&state.db);
    let days = latest_due_days(now, PULL_CYCLE_HOUR_UTC as u8, PULL_GRACE_HOURS);
    // A puller that never pulled anything is not a puller that failed: a
    // fresh server's first cycle is still ahead.
    let horizon = days[0] - Duration::days(14);
    let pulls = dao
        .pulls_between(PURESTAT_SOURCE, &day_str(horizon), &day_str(days[1]))
        .await?;
    if pulls.is_empty() {
        return Ok(None);
    }
    let by_day: BTreeMap<&str, PullStatus> =
        pulls.iter().map(|p| (p.day.as_str(), p.status)).collect();
    let mut states = Document::new();
    for day in days {
        let key = day_str(day);
        let state_of = match by_day.get(key.as_str()) {
            None => "not pulled",
            Some(PullStatus::Failed) => "failed",
            Some(PullStatus::Ok) => return Ok(None),
        };
        states.insert(key, state_of);
    }
    let last_error = pulls
        .iter()
        .filter_map(|p| p.error.clone())
        .next_back()
        .unwrap_or_default();
    Ok(Some(doc! { "days": states, "last_error": last_error }))
}

/// Whether the `saas` puller writing `source` runs on this server at all —
/// each puller's own start condition, so a source nobody configured holds
/// nothing. The feed needs no credential, only the growth surface.
fn puller_configured(g: &meshharbor_config::GrowthSettings, source: &str) -> bool {
    match source {
        SEARCH_CONSOLE_SOURCE | URL_INSPECTION_SOURCE => g.search_console_configured(),
        GITHUB_SOURCE => g.github_repo().is_some(),
        GITHUB_TRAFFIC_SOURCE => g.github_repo().is_some() && g.github_traffic_configured(),
        BING_SOURCE => g.bing_configured(),
        CONTENT_SOURCE => true,
        _ => false,
    }
}

/// Pure (§3l): a puller "failing two days running", read on the clock from
/// its `growth_pulls` rows. It holds when the puller still tries (its newest
/// attempt within [`PULL_TRYING_HOURS`]) and nothing it pulled succeeded
/// within [`PULL_FAILING_HOURS`] — for a puller that never succeeded, once
/// its oldest attempt on record is that old, so a fresh key's first bad
/// hours do not alert. The clock, not the rows' days: each puller dates its
/// rows its own way (Google's final day, yesterday, today), and a row stays
/// `ok` with the newest attempt's `error` when a retry of a pulled day fails,
/// so the newest SUCCESS (`pulled_at`) is the one fact they all share.
pub fn pull_failing(pulls: &[GrowthPull], now_ms: i64) -> Option<Document> {
    let hour = 3_600_000_i64;
    let newest_attempt = pulls
        .iter()
        .map(|p| p.attempted_at.timestamp_millis())
        .max()?;
    if newest_attempt < now_ms - PULL_TRYING_HOURS * hour {
        return None;
    }
    let last_ok = pulls
        .iter()
        .filter_map(|p| p.pulled_at.map(|t| t.timestamp_millis()))
        .max();
    let failing_since = match last_ok {
        Some(t) => t,
        None => pulls
            .iter()
            .map(|p| p.attempted_at.timestamp_millis())
            .min()?,
    };
    if failing_since > now_ms - PULL_FAILING_HOURS * hour {
        return None;
    }
    let newest = pulls
        .iter()
        .max_by_key(|p| p.attempted_at.timestamp_millis())?;
    let at = |ms: i64| rfc3339(DateTime::from_millis(ms));
    Some(doc! {
        "last_ok": last_ok.map(at).map_or(Bson::Null, Bson::String),
        "last_attempt": at(newest_attempt),
        "last_error": newest.error.clone().unwrap_or_default(),
        "hours_failing": (now_ms - failing_since) / hour,
    })
}

/// The failing-pull check for one `(key, source)` of [`PULLERS`].
async fn puller_failing(
    state: &AppState,
    now: DateTime,
    source: &str,
) -> Result<Option<Document>, DigestError> {
    let g = &state.settings.growth;
    if !mounted(state, "saas") || !puller_configured(g, source) {
        return Ok(None);
    }
    // Search Console's newest final day trails the clock by days; 35 days
    // of ledger is far more than any puller's lookback.
    let from = utc_date_of(now) - Duration::days(35);
    let pulls = GrowthDao::new(&state.db)
        .pulls_between(source, &day_str(from), "9999-12-31")
        .await?;
    Ok(pull_failing(&pulls, now.timestamp_millis()))
}

async fn sendgrid_not_measured(
    state: &AppState,
    now: DateTime,
) -> Result<Option<Document>, DigestError> {
    if !mounted(state, "saas") || !super::newsletter::webhook_on(state) {
        return Ok(None);
    }
    let today = utc_date_of(now);
    let mut days = Document::new();
    for age in [2, 1] {
        let day = today - Duration::days(age);
        let w = Windows::for_day(day);
        let sends = find_docs(
            state,
            "newsletter_sends",
            doc! {
                "status": "sent",
                "sent_at": { "$gte": DateTime::from_millis(w.day_start), "$lt": DateTime::from_millis(w.day_end) },
            },
            doc! { "delivery": 1 },
        )
        .await?;
        if sends.is_empty() {
            // Nothing to measure that day: the rule needs two send-days.
            return Ok(None);
        }
        let events = sends
            .iter()
            .filter(|d| {
                d.get_document("delivery").ok().is_some_and(|dl| {
                    [
                        "delivered_at",
                        "bounced_at",
                        "dropped_at",
                        "spam_reported_at",
                    ]
                    .iter()
                    .any(|k| dt_ms(dl, k).is_some())
                })
            })
            .count();
        if events > 0 {
            return Ok(None);
        }
        days.insert(
            day_str(day),
            doc! { "sends": sends.len() as i64, "events": 0_i64 },
        );
    }
    Ok(Some(doc! { "days": days }))
}

/// Per-day counts over `[day − BASELINE_DAYS, day]` for the band rules:
/// the day's value, and the baseline's `(n, days present)`.
struct Series {
    value: i64,
    baseline_n: i64,
    baseline_days: i64,
}

async fn signups_series(state: &AppState, day: NaiveDate) -> Result<Series, DigestError> {
    let set = ExclusionSet::load(&state.core).await?;
    let from = day - Duration::days(BASELINE_DAYS);
    let day_w = Windows::for_day(day);
    let docs = find_docs(
        state,
        "users",
        doc! {
            "created_at": { "$gte": DateTime::from_millis(Windows::for_day(from).day_start), "$lt": DateTime::from_millis(day_w.day_end) },
            "deleted_at": Bson::Null,
            "_id": { "$nin": excluded_ids(&set.users) },
        },
        doc! { "created_at": 1 },
    )
    .await?;
    let (mut value, mut baseline_n) = (0, 0);
    for t in docs.iter().filter_map(|d| dt_ms(d, "created_at")) {
        if t >= day_w.day_start {
            value += 1;
        } else {
            baseline_n += 1;
        }
    }
    Ok(Series {
        value,
        baseline_n,
        baseline_days: BASELINE_DAYS,
    })
}

/// The puller's daily `visitors` rows (`by = site`); `None` without
/// yesterday's row or enough baseline days.
async fn visitors_series(state: &AppState, day: NaiveDate) -> Result<Option<Series>, DigestError> {
    let from = day - Duration::days(BASELINE_DAYS);
    let rows = GrowthDao::new(&state.db)
        .read_daily(PURESTAT_SOURCE, "visitors", &day_str(from), &day_str(day))
        .await?;
    let by_day: BTreeMap<&str, i64> = rows
        .iter()
        .filter(|r| r.dims.get("by").map(String::as_str) == Some("site"))
        .map(|r| (r.day.as_str(), r.value))
        .collect();
    let key = day_str(day);
    let Some(value) = by_day.get(key.as_str()).copied() else {
        return Ok(None);
    };
    let baseline: Vec<i64> = by_day
        .iter()
        .filter(|(d, _)| **d != key.as_str())
        .map(|(_, v)| *v)
        .collect();
    if (baseline.len() as i64) < MIN_BASELINE_DAYS_PRESENT {
        return Ok(None);
    }
    Ok(Some(Series {
        value,
        baseline_n: baseline.iter().sum(),
        baseline_days: baseline.len() as i64,
    }))
}

/// The spike and drop verdicts of one metric from its series.
fn band_verdicts(key: &'static str, day: NaiveDate, series: Option<&Series>) -> [Verdict; 2] {
    let band = series.and_then(|s| Band::of(s.baseline_n, s.baseline_days));
    let mut spike = None;
    let mut drop = None;
    if let (Some(b), Some(s)) = (band, series) {
        if b.is_spike(s.value) {
            spike = Some(b.detail(day, s.value, Rule::Spike));
        }
        if b.is_drop(s.value) {
            drop = Some(b.detail(day, s.value, Rule::Drop));
        }
    }
    [
        Verdict {
            rule: Rule::Spike,
            key,
            holds: spike,
        },
        Verdict {
            rule: Rule::Drop,
            key,
            holds: drop,
        },
    ]
}

/// Every rule's verdict at `now`, in a fixed order.
pub async fn verdicts(state: &AppState, now: DateTime) -> Result<Vec<Verdict>, DigestError> {
    let mut out = vec![
        Verdict {
            rule: Rule::DigestMissing,
            key: "daily",
            holds: digest_missing(state, now).await?,
        },
        Verdict {
            rule: Rule::SourceNotMeasured,
            key: "purestat",
            holds: purestat_not_measured(state, now).await?,
        },
        Verdict {
            rule: Rule::SourceNotMeasured,
            key: "purestat_pull",
            holds: purestat_pull_not_measured(state, now).await?,
        },
        Verdict {
            rule: Rule::SourceNotMeasured,
            key: "sendgrid",
            holds: sendgrid_not_measured(state, now).await?,
        },
    ];
    for (key, source) in PULLERS {
        out.push(Verdict {
            rule: Rule::SourceNotMeasured,
            key,
            holds: puller_failing(state, now, source).await?,
        });
    }
    let yesterday = utc_date_of(now) - Duration::days(1);
    let signups = signups_series(state, yesterday).await?;
    out.extend(band_verdicts("signups", yesterday, Some(&signups)));
    let visitors = visitors_series(state, yesterday).await?;
    out.extend(band_verdicts("visitors", yesterday, visitors.as_ref()));
    Ok(out)
}

/// What an evaluation did.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Evaluation {
    /// RFC 3339.
    pub at: String,
    pub dry_run: bool,
    pub verdicts: Vec<VerdictJson>,
    /// Rows this evaluation opened.
    pub fired: Vec<AlertRow>,
    /// Rows this evaluation closed.
    pub cleared: Vec<AlertRow>,
    /// Mails sent (one per recipient).
    pub mailed: usize,
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

pub(crate) fn row_of(a: &GrowthAlert) -> AlertRow {
    AlertRow {
        rule: a.rule.clone(),
        key: a.key.clone(),
        fired_at: rfc3339(a.fired_at),
        cleared_at: a.cleared_at.map(rfc3339),
        detail: a.detail.clone(),
    }
}

/// Evaluate every rule: fire, clear, and mail what is new — or, as a dry
/// run, only decide.
pub async fn evaluate(
    state: &AppState,
    mailer: Option<&dyn DigestMailer>,
    dry_run: bool,
    now: DateTime,
) -> Result<Evaluation, DigestError> {
    let verdicts = verdicts(state, now).await?;
    let mut out = Evaluation {
        at: rfc3339(now),
        dry_run,
        verdicts: verdicts.iter().map(VerdictJson::of).collect(),
        fired: Vec::new(),
        cleared: Vec::new(),
        mailed: 0,
    };
    if dry_run {
        return Ok(out);
    }
    let dao = GrowthAlertDao::new(&state.db);
    let today = day_str(utc_date_of(now));
    let mut recipients: Option<Vec<String>> = None;
    for v in verdicts {
        let rule = v.rule.as_str();
        match v.holds {
            Some(detail) => {
                let fired = dao.fire(rule, v.key, detail, now).await?;
                if fired.created {
                    info!(rule, key = v.key, "growth alert fired");
                    out.fired.push(row_of(&fired.alert));
                }
                // Mail a row never mailed, at most once per rule+key per
                // day across rows, and only once per row across pods.
                if fired.alert.mailed_on.is_some() || dao.mailed_on(rule, v.key, &today).await? {
                    continue;
                }
                let Some(mailer) = mailer else { continue };
                let to = match &recipients {
                    Some(r) => r.clone(),
                    None => {
                        let r = digest::recipients(state).await?;
                        recipients = Some(r.clone());
                        r
                    }
                };
                if to.is_empty() || !dao.mark_mailed(fired.alert.id, &today).await? {
                    continue;
                }
                let open = dao.list_open().await?.len();
                let (subject, html, text) = super::render::alert_mail(&fired.alert, open);
                for addr in &to {
                    match mailer.send(addr, &subject, &html, &text).await {
                        Ok(()) => out.mailed += 1,
                        // The error is the mailer's text about our request;
                        // it never carries the recipient.
                        Err(e) => warn!(rule, key = v.key, %e, "growth alert send failed"),
                    }
                }
            }
            None => {
                let Some(open) = dao.open(rule, v.key).await? else {
                    continue;
                };
                if dao.clear(rule, v.key, now).await? {
                    info!(rule, key = v.key, "growth alert cleared");
                    let mut row = row_of(&open);
                    row.cleared_at = Some(rfc3339(now));
                    out.cleared.push(row);
                }
            }
        }
    }
    Ok(out)
}

/// The evaluator: every [`LOOP_INTERVAL_SECS`], one pod (a Redis claim
/// when there is Redis; the row's own arbiters otherwise) runs
/// [`evaluate`]. Only with `growth.enabled` and `growth.alerts`.
pub fn spawn_alert_loop(state: AppState) {
    if !state.settings.growth.enabled || !state.settings.growth.alerts {
        return;
    }
    info!("growth alert evaluator starting");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(FIRST_TICK_DELAY_SECS)).await;
        loop {
            let claimed = match &state.redis_pubsub {
                Some(redis) => {
                    let key = format!("roomler:growth-alerts:{}", state.db.name());
                    match redis.try_claim(&key, LOOP_INTERVAL_SECS - 60).await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(%e, "growth alerts claim failed; skipping tick");
                            false
                        }
                    }
                }
                None => true,
            };
            if claimed {
                let mailer = digest::service_mailer(&state);
                let mailer_ref: Option<&dyn DigestMailer> =
                    mailer.as_ref().map(|m| m as &dyn DigestMailer);
                match evaluate(&state, mailer_ref, false, DateTime::now()).await {
                    Ok(r) => {
                        if !r.fired.is_empty() || !r.cleared.is_empty() {
                            info!(
                                fired = r.fired.len(),
                                cleared = r.cleared.len(),
                                mailed = r.mailed,
                                "growth alerts evaluated"
                            );
                        }
                    }
                    Err(e) => warn!(%e, "growth alerts evaluation failed"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(LOOP_INTERVAL_SECS)).await;
        }
    });
}

// ── Sections for the digest and the roll-up ──────────────────────────────

/// The rows fired or cleared in `[from, to)` ms, and the ones open now.
pub async fn window_section(
    state: &AppState,
    from: i64,
    to: i64,
) -> Result<AlertsSection, DigestError> {
    let rows = GrowthAlertDao::new(&state.db)
        .list_window(DateTime::from_millis(from), DateTime::from_millis(to))
        .await?;
    let in_window =
        |t: Option<DateTime>| t.is_some_and(|t| (from..to).contains(&t.timestamp_millis()));
    Ok(AlertsSection {
        fired: rows
            .iter()
            .filter(|a| in_window(Some(a.fired_at)))
            .map(row_of)
            .collect(),
        cleared: rows
            .iter()
            .filter(|a| in_window(a.cleared_at))
            .map(row_of)
            .collect(),
        open: rows.iter().filter(|a| a.is_open()).map(row_of).collect(),
    })
}

/// The day's alerts, for the daily digest.
pub async fn day_section(state: &AppState, w: &Windows) -> Result<AlertsSection, DigestError> {
    window_section(state, w.day_start, w.day_end).await
}

// ── The routes ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertJson {
    pub id: String,
    pub rule: String,
    pub key: String,
    pub fired_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<String>,
    pub detail: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailed_on: Option<String>,
}

impl AlertJson {
    fn of(a: &GrowthAlert) -> Self {
        Self {
            id: a.id.to_hex(),
            rule: a.rule.clone(),
            key: a.key.clone(),
            fired_at: rfc3339(a.fired_at),
            cleared_at: a.cleared_at.map(rfc3339),
            detail: serde_json::to_value(&a.detail).unwrap_or(serde_json::Value::Null),
            mailed_on: a.mailed_on.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleInfo {
    pub rule: Rule,
    pub keys: Vec<String>,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    /// Whether the evaluator runs on this server (`growth.alerts`).
    pub enabled: bool,
    pub rules: Vec<RuleInfo>,
    /// Open now, newest first.
    pub open: Vec<AlertJson>,
    /// Cleared since `since` (default: the last 7 days), newest first.
    pub recent: Vec<AlertJson>,
}

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    /// `YYYY-MM-DD`: list rows cleared from that day on.
    #[serde(default)]
    pub since: Option<String>,
}

/// `GET /api/admin/growth/alerts?since=` — a platform admin, or a read key.
pub async fn get_alerts(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<AlertsQuery>,
) -> Result<Json<AlertsResponse>, ApiError> {
    let now = DateTime::now();
    let since = match q.since.as_deref() {
        Some(s) => Windows::for_day(parse_day(s).map_err(ApiError::BadRequest)?).day_start,
        None => now.timestamp_millis() - RECENT_DAYS * 86_400_000,
    };
    let rows = GrowthAlertDao::new(&state.db)
        .list_since(DateTime::from_millis(since))
        .await?;
    let (open, recent): (Vec<_>, Vec<_>) = rows.iter().partition(|a| a.is_open());
    Ok(Json(AlertsResponse {
        enabled: state.settings.growth.alerts,
        rules: Rule::ALL
            .iter()
            .map(|r| RuleInfo {
                rule: *r,
                keys: r.keys().iter().map(|k| k.to_string()).collect(),
                description: r.description().to_string(),
            })
            .collect(),
        open: open.iter().map(|a| AlertJson::of(a)).collect(),
        recent: recent.iter().map(|a| AlertJson::of(a)).collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct EvaluateQuery {
    /// Decide only: no row, no mail.
    #[serde(default)]
    pub dry_run: bool,
}

/// `POST /api/admin/growth/alerts/evaluate?dry_run=` — a session, never a
/// key. Runs every rule now, as the hourly job would; 409 when the alerts
/// are off on this server and it is not a dry run.
pub async fn evaluate_route(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<EvaluateQuery>,
) -> Result<Json<Evaluation>, ApiError> {
    super::require_growth_admin(&state, &auth)?;
    if !q.dry_run && !state.settings.growth.alerts {
        return Err(ApiError::Conflict(
            "alerts are off on this server (ROOMLER__GROWTH__ALERTS); use dry_run=true".into(),
        ));
    }
    let mailer = digest::service_mailer(&state);
    let mailer_ref: Option<&dyn DigestMailer> = mailer.as_ref().map(|m| m as &dyn DigestMailer);
    Ok(Json(
        evaluate(&state, mailer_ref, q.dry_run, DateTime::now()).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime {
        DateTime::parse_rfc3339_str(s).unwrap()
    }

    fn d(s: &str) -> NaiveDate {
        parse_day(s).unwrap()
    }

    #[test]
    fn rule_spellings_and_keys_are_locked() {
        for (r, s) in [
            (Rule::DigestMissing, "digest_missing"),
            (Rule::SourceNotMeasured, "source_not_measured"),
            (Rule::Spike, "spike"),
            (Rule::Drop, "drop"),
        ] {
            assert_eq!(r.as_str(), s);
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{s}\""));
            assert!(!r.keys().is_empty());
        }
        assert_eq!(
            Rule::SourceNotMeasured.keys(),
            &[
                "purestat",
                "purestat_pull",
                "sendgrid",
                "search_console_pull",
                "url_inspection_pull",
                "content_pull",
                "github_pull",
                "github_traffic_pull",
                "bing_pull",
            ]
        );
        // Every failing-pull key is evaluated, and only those.
        let keys = Rule::SourceNotMeasured.keys();
        assert_eq!(&keys[3..], PULLERS.map(|(k, _)| k).as_slice());
        assert_eq!(Rule::Spike.keys(), Rule::Drop.keys());
    }

    fn pull(day: &str, ok_at: Option<&str>, attempted: &str, error: Option<&str>) -> GrowthPull {
        GrowthPull {
            id: GrowthPull::id_of(SEARCH_CONSOLE_SOURCE, day),
            source: SEARCH_CONSOLE_SOURCE.into(),
            day: day.into(),
            status: if ok_at.is_some() {
                PullStatus::Ok
            } else {
                PullStatus::Failed
            },
            pulled_at: ok_at.map(at),
            attempted_at: at(attempted),
            attempts: 1,
            rows: 0,
            error: error.map(str::to_string),
            missing_goal: None,
            truncated: false,
        }
    }

    /// §3l — "failing two days running", on the clock: a success inside 48 h
    /// clears it; an old success with a recent failed attempt fires; a puller
    /// that stopped trying holds nothing; a puller that never succeeded fires
    /// only once its first attempt on record is 48 h old.
    #[test]
    fn a_puller_fails_two_days_running_only_while_it_still_tries() {
        let now = at("2026-10-18T12:00:00Z").timestamp_millis();
        assert_eq!(
            pull_failing(&[], now),
            None,
            "nothing pulled, nothing to say"
        );

        // A good pull 10 h ago: fine, whatever failed after it.
        let fine = [
            pull(
                "2026-10-15",
                Some("2026-10-18T02:00:00Z"),
                "2026-10-18T02:00:00Z",
                None,
            ),
            pull("2026-10-16", None, "2026-10-18T11:00:00Z", Some("HTTP 503")),
        ];
        assert_eq!(pull_failing(&fine, now), None);

        // The last good pull 3 days ago, failing since — still trying an hour ago.
        let failing = [
            pull(
                "2026-10-13",
                Some("2026-10-15T09:00:00Z"),
                "2026-10-15T09:00:00Z",
                None,
            ),
            pull("2026-10-14", None, "2026-10-17T10:00:00Z", Some("HTTP 403")),
            pull("2026-10-15", None, "2026-10-18T11:00:00Z", Some("HTTP 401")),
        ];
        let d = pull_failing(&failing, now).expect("fires");
        assert_eq!(d.get_str("last_ok").unwrap(), "2026-10-15T09:00:00Z");
        assert_eq!(d.get_str("last_attempt").unwrap(), "2026-10-18T11:00:00Z");
        assert_eq!(
            d.get_str("last_error").unwrap(),
            "HTTP 401",
            "the newest attempt's"
        );
        assert_eq!(d.get_i64("hours_failing").unwrap(), 75);

        // The same, but the newest attempt is 30 h old: switched off, not failing.
        let stopped = [
            pull(
                "2026-10-13",
                Some("2026-10-14T09:00:00Z"),
                "2026-10-14T09:00:00Z",
                None,
            ),
            pull("2026-10-14", None, "2026-10-17T06:00:00Z", Some("HTTP 401")),
        ];
        assert_eq!(pull_failing(&stopped, now), None);

        // Never succeeded: quiet for the first 48 h, then it fires.
        let fresh = [pull(
            "2026-10-17",
            None,
            "2026-10-18T11:00:00Z",
            Some("bad key"),
        )];
        assert_eq!(pull_failing(&fresh, now), None);
        let stuck = [
            pull("2026-10-15", None, "2026-10-16T03:00:00Z", Some("bad key")),
            pull("2026-10-17", None, "2026-10-18T11:00:00Z", Some("bad key")),
        ];
        let d = pull_failing(&stuck, now).expect("fires after 48 h of trying");
        assert_eq!(d.get("last_ok"), Some(&Bson::Null));
        assert_eq!(d.get_i64("hours_failing").unwrap(), 57);

        // An `ok` row whose newest retry failed still counts its success.
        let retried = [pull(
            "2026-10-16",
            Some("2026-10-17T20:00:00Z"),
            "2026-10-18T11:00:00Z",
            Some("timeout"),
        )];
        assert_eq!(pull_failing(&retried, now), None);
    }

    /// Each failing-pull key runs only where its puller would: the feed
    /// always, the others behind their own credentials.
    #[test]
    fn a_puller_is_watched_only_where_it_runs() {
        let mut g = meshharbor_config::GrowthSettings {
            github_repo: String::new(),
            github_token: String::new(),
            search_console_key: String::new(),
            bing_api_key: String::new(),
            ..Default::default()
        };
        let on: Vec<&str> = PULLERS
            .iter()
            .filter(|(_, s)| puller_configured(&g, s))
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(on, ["content_pull"]);
        g.github_repo = "owner/repo".into();
        g.search_console_key = "{\"type\":\"service_account\"}".into();
        g.search_console_site = "sc-domain:example.test".into();
        let on: Vec<&str> = PULLERS
            .iter()
            .filter(|(_, s)| puller_configured(&g, s))
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(
            on,
            [
                "search_console_pull",
                "url_inspection_pull",
                "content_pull",
                "github_pull"
            ]
        );
        g.github_token = "ghp_fake".into();
        g.bing_api_key = "0123456789abcdef0123456789abcdef".into();
        assert!(PULLERS.iter().all(|(_, s)| puller_configured(&g, s)));
    }

    /// The band: nothing below n = 30; a spike needs 3σ and 2× the mean; a
    /// drop needs 3σ below, which a small mean can never reach.
    #[test]
    fn the_band_has_an_n_floor_and_poisson_edges() {
        assert_eq!(Band::of(29, 28), None);
        assert_eq!(Band::of(100, 0), None);
        let b = Band::of(30, 28).unwrap();
        assert!((b.mean - 1.0714).abs() < 0.001);
        // mean + 3√mean ≈ 4.18; 2 × mean ≈ 2.14 — the larger wins.
        assert!(!b.is_spike(4));
        assert!(b.is_spike(5));
        assert!(
            !b.is_drop(0),
            "a mean this small has no floor to drop below"
        );
        let big = Band::of(1232, 28).unwrap(); // mean 44
        assert!((big.mean - 44.0).abs() < 1e-9);
        assert!(!big.is_spike(87));
        assert!(big.is_spike(89), "≥ 2 × 44 and > 44 + 3 × 6.63");
        assert!(big.is_drop(24));
        assert!(!big.is_drop(25));
        let detail = big.detail(d("2026-10-14"), 100, Rule::Spike);
        assert_eq!(detail.get_str("day").unwrap(), "2026-10-14");
        assert_eq!(detail.get_i64("value").unwrap(), 100);
        assert_eq!(detail.get_i64("baseline_n").unwrap(), 1232);
        assert_eq!(detail.get_f64("baseline_mean").unwrap(), 44.0);
        assert_eq!(detail.get_f64("threshold").unwrap(), 88.0);
        assert_eq!(
            big.detail(d("2026-10-14"), 10, Rule::Drop)
                .get_f64("threshold")
                .unwrap(),
            24.1
        );
    }

    #[test]
    fn band_verdicts_need_a_series_and_fire_one_side_at_most() {
        let day = d("2026-10-14");
        let none = band_verdicts("visitors", day, None);
        assert!(none.iter().all(|v| v.holds.is_none()));
        let quiet = Series {
            value: 1,
            baseline_n: 30,
            baseline_days: 28,
        };
        assert!(
            band_verdicts("signups", day, Some(&quiet))
                .iter()
                .all(|v| v.holds.is_none())
        );
        let spike = Series {
            value: 9,
            baseline_n: 30,
            baseline_days: 28,
        };
        let v = band_verdicts("signups", day, Some(&spike));
        assert_eq!(v[0].rule, Rule::Spike);
        assert!(v[0].holds.is_some() && v[1].holds.is_none());
        let small = Series {
            value: 99,
            baseline_n: 29,
            baseline_days: 28,
        };
        assert!(
            band_verdicts("signups", day, Some(&small))
                .iter()
                .all(|v| v.holds.is_none()),
            "below the n floor nothing fires, however large the day"
        );
    }

    /// The digest is due for yesterday from its hour plus the grace, and
    /// for the day before until then.
    #[test]
    fn the_latest_due_day_waits_for_the_grace() {
        assert_eq!(
            latest_due_day(at("2026-10-15T07:59:00Z"), 6, 2),
            d("2026-10-13")
        );
        assert_eq!(
            latest_due_day(at("2026-10-15T08:00:00Z"), 6, 2),
            d("2026-10-14")
        );
        assert_eq!(
            latest_due_day(at("2026-10-15T23:59:00Z"), 6, 2),
            d("2026-10-14")
        );
        assert_eq!(
            latest_due_days(at("2026-10-15T09:00:00Z"), 6, 2),
            [d("2026-10-13"), d("2026-10-14")]
        );
        assert_eq!(
            latest_due_days(at("2026-10-15T01:30:00Z"), 1, 1),
            [d("2026-10-12"), d("2026-10-13")],
            "the puller's day is not expected before 02:00"
        );
        assert_eq!(
            latest_due_days(at("2026-10-15T02:00:00Z"), 1, 1),
            [d("2026-10-13"), d("2026-10-14")]
        );
    }

    #[test]
    fn a_digest_day_reads_missing_failed_stalled_or_fine() {
        use meshharbor_services::dao::growth_digest::{DIGEST_VERSION, DigestDoc, ExcludedCounts};
        let now = at("2026-10-15T09:00:00Z");
        let row = |status, claimed_at| DigestDoc {
            day: "2026-10-14".into(),
            status,
            version: DIGEST_VERSION,
            claimed_at,
            computed_at: None,
            sent_at: None,
            attempts: 2,
            error: Some("boom".into()),
            recipients: 0,
            excluded: ExcludedCounts::default(),
            sections: None,
        };
        assert_eq!(
            digest_state(None, now).unwrap().get_str("status").unwrap(),
            "missing"
        );
        let failed = digest_state(Some(&row(DigestStatus::Failed, now)), now).unwrap();
        assert_eq!(failed.get_str("status").unwrap(), "failed");
        assert_eq!(failed.get_str("error").unwrap(), "boom");
        for fine in [
            DigestStatus::Sent,
            DigestStatus::Stored,
            DigestStatus::Preview,
        ] {
            assert!(
                digest_state(Some(&row(fine, now)), now).is_none(),
                "{fine:?}"
            );
        }
        let fresh = at("2026-10-15T08:45:00Z");
        assert!(digest_state(Some(&row(DigestStatus::Computing, fresh)), now).is_none());
        let stale = at("2026-10-15T08:00:00Z");
        assert_eq!(
            digest_state(Some(&row(DigestStatus::Computing, stale)), now)
                .unwrap()
                .get_str("status")
                .unwrap(),
            "stalled"
        );
    }

    #[test]
    fn a_stored_sections_not_measured_arm_is_read_by_its_reason() {
        let s = doc! {
            "website": { "not_measured": "purestat: HTTP 401" },
            "blog": { "visitors": 1 },
        };
        assert_eq!(
            not_measured_reason(Some(&s), "website").as_deref(),
            Some("purestat: HTTP 401")
        );
        assert_eq!(not_measured_reason(Some(&s), "blog"), None);
        assert_eq!(not_measured_reason(Some(&s), "campaigns"), None);
        assert_eq!(not_measured_reason(None, "website"), None);
    }
}
