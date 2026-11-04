// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the Bing Webmaster puller (spec §3k), through an API key,
//! storing what Bing returns at the granularity Bing returns it — which is
//! NOT Search Console's.
//!
//! | Bing method | Bing's grain | stored as |
//! |---|---|---|
//! | `GetRankAndTrafficStats` | one row per **day**: the site's clicks and impressions | `source: bing`, `by: site`, `clicks` `impressions` |
//! | `GetQueryStats` | one row per query per **weekly bucket** (Bing: "updated every week"; the newest bucket is rewritten until it closes) | `source: bing_weekly`, `by: query`, dims `query`, under the bucket's date |
//! | `GetPageStats` | one row per page per weekly bucket (the page URL in Bing's `Query` field) | `source: bing_weekly`, `by: page`, dims `page` |
//!
//! * Weekly rows carry `clicks`, `impressions`, and Bing's
//!   `AvgImpressionPosition` / `AvgClickPosition` **as Bing returns them**,
//!   ×10 so a decimal survives (`avg_impression_position_x10`,
//!   `avg_click_position_x10` — integers on Bing's .NET wire; a value at or
//!   below 0, Bing's "none", is not stored). Of keys that fold into one,
//!   the busiest row's positions are kept. None of it is comparable to
//!   Search Console's 7- and 28-day windows, and every reader labels them
//!   as Bing's weeks.
//! * Every call returns Bing's whole history, so a cycle rewrites only the
//!   recent part — the last [`DAILY_HORIZON_DAYS`] daily rows and the last
//!   [`WEEKLY_HORIZON_DAYS`] days of weekly buckets — and older rows are
//!   frozen as first stored.
//! * A row's day is Bing's: `/Date(1316156400000-0700)/` is epoch
//!   milliseconds with a Pacific offset, applied before the date is taken.
//! * **A rare query's text is not stored**: a query row needs
//!   [`QUERY_MIN_IMPRESSIONS`] in its bucket. Google drops rare queries
//!   itself; Bing documents no threshold. Pages are our own URLs and are
//!   stored whatever their count; the site's daily totals hold every query.
//! * The key rides the query string, so no redirect is followed (it would
//!   carry the key on), and each answer is capped at [`MAX_BODY_BYTES`].
//! * Bing exposes no index status, and its per-URL crawl method
//!   (`GetUrlInfo`) is reported broken for verified sites, so the Content
//!   table's index column is Google's alone.
//! * Without a key nothing is asked; a refused key (Bing's `ErrorCode` 3,
//!   `InvalidApiKey`; 14, `NotAuthorized`, an unverified site) is recorded
//!   on the cycle's `growth_pulls` row `bing:<day>`, never a 0.

use std::collections::BTreeMap;

use bson::DateTime;
use chrono::{Duration, NaiveDate};
use meshharbor_config::GrowthSettings;
use meshharbor_services::dao::{
    base::DaoResult,
    growth::{BING_SOURCE, BING_WEEKLY_SOURCE, GrowthDaily, GrowthDao, PulledDay, daily_row},
};
use meshharbor_core::Core;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{info, warn};

use crate::pull_schedule::{self, date_of, day_str};

pub const CYCLE_HOUR_UTC: u32 = 3;
/// Daily rows rewritten each cycle; older ones are frozen.
pub const DAILY_HORIZON_DAYS: i64 = 30;
/// Days of weekly buckets rewritten each cycle (five weeks).
pub const WEEKLY_HORIZON_DAYS: i64 = 35;
pub const LOOP_INTERVAL_SECS: u64 = 60 * 60;
pub const FIRST_TICK_DELAY_SECS: u64 = 7 * 60;
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
pub const DAILY_METRICS: [&str; 2] = ["clicks", "impressions"];
/// The weekly rows' metrics; the two positions are Bing's own numbers ×10.
pub const WEEKLY_METRICS: [&str; 4] = [
    "clicks",
    "impressions",
    "avg_impression_position_x10",
    "avg_click_position_x10",
];
pub const MAX_KEY_LEN: usize = 300;
/// The largest answer read: every call returns Bing's whole history.
pub const MAX_BODY_BYTES: usize = 32 << 20;
/// A query's text is stored only from this many impressions in its weekly
/// bucket. Google drops rare queries itself ("anonymised"); Bing documents
/// no such threshold, and a query seen a handful of times can be one
/// person's words (a name, an address). Its clicks and impressions stay in
/// the site's daily totals, which come from another call.
pub const QUERY_MIN_IMPRESSIONS: i64 = 10;

#[derive(Debug, Clone, PartialEq)]
pub enum BingError {
    /// Bing's `ErrorCode` and message (`3 InvalidApiKey`, `14 NotAuthorized`).
    Refused(i64, String),
    Status(u16, String),
    Timeout,
    Transport(String),
    Decode(String),
}

impl std::fmt::Display for BingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(c, m) => write!(f, "bing unreachable: refused (ErrorCode {c}) {m}"),
            Self::Status(c, m) => write!(f, "bing unreachable: HTTP {c} {m}"),
            Self::Timeout => write!(f, "bing unreachable: timed out"),
            Self::Transport(e) => write!(f, "bing unreachable: {e}"),
            Self::Decode(e) => write!(f, "bing unreachable: unreadable answer ({e})"),
        }
    }
}

impl From<crate::capped::BodyError> for BingError {
    fn from(e: crate::capped::BodyError) -> Self {
        match e {
            crate::capped::BodyError::Timeout => Self::Timeout,
            other => Self::Transport(short(&other.to_string())),
        }
    }
}

fn short(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(120).collect()
}

/// A number as Bing may send it (an integer on its .NET wire; read as a
/// float so a decimal or an exponent never costs the whole answer).
fn lenient<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(match v {
        serde_json::Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        serde_json::Value::String(s) => s.parse::<f64>().ok().filter(|f| f.is_finite()),
        _ => None,
    })
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct DayStats {
    pub date: String,
    #[serde(default, deserialize_with = "lenient")]
    pub clicks: Option<f64>,
    #[serde(default, deserialize_with = "lenient")]
    pub impressions: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct KeyStats {
    /// The query — or, from `GetPageStats`, the page URL.
    #[serde(default)]
    pub query: String,
    pub date: String,
    #[serde(default, deserialize_with = "lenient")]
    pub clicks: Option<f64>,
    #[serde(default, deserialize_with = "lenient")]
    pub impressions: Option<f64>,
    #[serde(default, deserialize_with = "lenient")]
    pub avg_impression_position: Option<f64>,
    #[serde(default, deserialize_with = "lenient")]
    pub avg_click_position: Option<f64>,
}

fn count(v: Option<f64>) -> i64 {
    v.map(|f| f.round() as i64).unwrap_or(0).max(0)
}

/// A position as stored: Bing's own number ×10, rounded; Bing's negative
/// "none" is no position.
fn position_x10(v: Option<f64>) -> Option<i64> {
    v.filter(|p| *p > 0.0).map(|p| (p * 10.0).round() as i64)
}

#[derive(Deserialize)]
struct Wrapped<T> {
    d: T,
}

#[derive(Clone)]
pub struct BingClient {
    base: String,
    site: String,
    key: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for BingClient {
    /// No key, ever.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BingClient")
            .field("site", &self.site)
            .finish_non_exhaustive()
    }
}

impl BingClient {
    /// `None` without a key or a site.
    pub fn from_settings(g: &GrowthSettings) -> Option<Self> {
        let key = g.bing_api_key.trim();
        let site = g.bing_site_url.trim();
        if key.is_empty() || site.is_empty() {
            return None;
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("meshharbor-api/", env!("CARGO_PKG_VERSION")))
            .timeout(TIMEOUT)
            // The key rides the query string, and a redirect would carry it
            // to wherever the next hop points (and into reqwest's debug log
            // of the move). Bing's API does not redirect: a 3xx is an error.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Self {
            base: g.bing_api_url.trim_end_matches('/').to_string(),
            site: site.to_string(),
            key: key.to_string(),
            http,
        })
    }

    async fn call<T: DeserializeOwned>(&self, method: &str) -> Result<T, BingError> {
        let resp = self
            .http
            .get(format!("{}/{method}", self.base))
            .query(&[
                ("siteUrl", self.site.as_str()),
                ("apikey", self.key.as_str()),
            ])
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    BingError::Timeout
                } else {
                    // `without_url`: the key rides the query string.
                    BingError::Transport(short(&e.without_url().to_string()))
                }
            })?;
        let status = resp.status().as_u16();
        let body = crate::capped::read_capped(resp, MAX_BODY_BYTES).await?;
        let text = String::from_utf8_lossy(&body);
        if !(200..300).contains(&status) {
            let v = serde_json::from_str::<serde_json::Value>(&text).ok();
            let code = v
                .as_ref()
                .and_then(|v| v.get("ErrorCode"))
                .and_then(|c| c.as_i64());
            let msg = v
                .as_ref()
                .and_then(|v| v.get("Message"))
                .and_then(|m| m.as_str())
                .map(short)
                .unwrap_or_default();
            return Err(match code {
                Some(c) => BingError::Refused(c, msg),
                None => BingError::Status(status, msg),
            });
        }
        serde_json::from_str::<Wrapped<T>>(&text)
            .map(|w| w.d)
            .map_err(|e| BingError::Decode(short(&e.to_string())))
    }

    pub async fn daily(&self) -> Result<Vec<DayStats>, BingError> {
        self.call("GetRankAndTrafficStats").await
    }

    pub async fn queries(&self) -> Result<Vec<KeyStats>, BingError> {
        self.call("GetQueryStats").await
    }

    pub async fn pages(&self) -> Result<Vec<KeyStats>, BingError> {
        self.call("GetPageStats").await
    }
}

/// Bing's date: `/Date(1316156400000-0700)/` — epoch milliseconds, with the
/// offset applied before the calendar day is taken. A negative instant is
/// Bing's null.
pub fn bing_day(raw: &str) -> Option<NaiveDate> {
    let inner = raw.trim().strip_prefix("/Date(")?.strip_suffix(")/")?;
    let split = inner
        .char_indices()
        .skip(1)
        .find(|(_, c)| *c == '+' || *c == '-')
        .map(|(i, _)| i);
    let (ms, offset) = match split {
        Some(i) => (&inner[..i], Some(&inner[i..])),
        None => (inner, None),
    };
    let ms: i64 = ms.parse().ok()?;
    if ms < 0 {
        return None;
    }
    let offset_min = match offset {
        Some(o) if o.len() == 5 => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let h: i64 = o[1..3].parse().ok()?;
            let m: i64 = o[3..5].parse().ok()?;
            sign * (h * 60 + m)
        }
        Some(_) => return None,
        None => 0,
    };
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms + offset_min * 60_000)
        .map(|t| t.date_naive())
}

fn clean(raw: &str) -> Option<String> {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_KEY_LEN)
        .collect();
    (!s.is_empty()).then_some(s)
}

/// Pure: the daily site rows inside `[from, to]`, grouped by day.
pub fn daily_rows(
    stats: &[DayStats],
    from: NaiveDate,
    to: NaiveDate,
) -> BTreeMap<String, Vec<GrowthDaily>> {
    let mut out: BTreeMap<String, Vec<GrowthDaily>> = BTreeMap::new();
    for s in stats {
        let Some(day) = bing_day(&s.date).filter(|d| *d >= from && *d <= to) else {
            continue;
        };
        let d = day_str(day);
        let mut dims = BTreeMap::new();
        dims.insert("by".to_string(), "site".to_string());
        let rows = out.entry(d.clone()).or_default();
        for (metric, v) in [
            ("clicks", count(s.clicks)),
            ("impressions", count(s.impressions)),
        ] {
            if v > 0 {
                rows.push(daily_row(BING_SOURCE, metric, dims.clone(), &d, v));
            }
        }
    }
    out
}

/// One key's bucket while folding: clicks, impressions, the busiest row's
/// two positions (×10) and its impressions.
type WeekAcc = (i64, i64, Option<i64>, Option<i64>, i64);

/// Pure: the weekly rows of one kind (`query` or `page`) inside
/// `[from, to]`, grouped by bucket day; keys folding into one cleaned key
/// are summed (positions kept from the busiest row).
pub fn weekly_rows(
    by: &str,
    stats: &[KeyStats],
    from: NaiveDate,
    to: NaiveDate,
) -> BTreeMap<String, Vec<GrowthDaily>> {
    let mut acc: BTreeMap<(String, String), WeekAcc> = BTreeMap::new();
    for s in stats {
        let Some(day) = bing_day(&s.date).filter(|d| *d >= from && *d <= to) else {
            continue;
        };
        let Some(key) = clean(&s.query) else {
            continue;
        };
        let e = acc
            .entry((day_str(day), key))
            .or_insert((0, 0, None, None, -1));
        let (clicks, impressions) = (count(s.clicks), count(s.impressions));
        e.0 += clicks;
        e.1 += impressions;
        if impressions > e.4 {
            e.2 = position_x10(s.avg_impression_position);
            e.3 = position_x10(s.avg_click_position);
            e.4 = impressions;
        }
    }
    let mut out: BTreeMap<String, Vec<GrowthDaily>> = BTreeMap::new();
    for ((day, key), (clicks, impressions, imp_pos, click_pos, _)) in acc {
        // A rare query's text is not stored (QUERY_MIN_IMPRESSIONS); a page
        // is our own URL and always is.
        if by == "query" && impressions < QUERY_MIN_IMPRESSIONS {
            continue;
        }
        let mut dims = BTreeMap::new();
        dims.insert("by".to_string(), by.to_string());
        dims.insert(by.to_string(), key);
        let rows = out.entry(day.clone()).or_default();
        for (metric, v) in [
            ("clicks", Some(clicks)),
            ("impressions", Some(impressions)),
            ("avg_impression_position_x10", imp_pos),
            ("avg_click_position_x10", click_pos),
        ] {
            if let Some(v) = v.filter(|v| *v > 0) {
                rows.push(daily_row(BING_WEEKLY_SOURCE, metric, dims.clone(), &day, v));
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BingReport {
    pub due: bool,
    pub ok: bool,
    pub days_written: u32,
    pub buckets_written: u32,
    pub rows_written: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One run at `now`: once per cycle, the three reads, the recent part of
/// each rewritten, the cycle recorded under yesterday's `bing:` pull row.
pub async fn run_once(core: &Core, client: &BingClient, now: DateTime) -> DaoResult<BingReport> {
    let dao = GrowthDao::new(&core.db);
    let today = date_of(now);
    let yesterday = today - Duration::days(1);
    let y = day_str(yesterday);
    let mut report = BingReport::default();
    let pulls = dao.pulls_between(BING_SOURCE, &y, &y).await?;
    if pull_schedule::due_days(now, &pulls, CYCLE_HOUR_UTC, 1, 1).is_empty() {
        return Ok(report);
    }
    report.due = true;
    let read = async {
        Ok::<_, BingError>((
            client.daily().await?,
            client.queries().await?,
            client.pages().await?,
        ))
    }
    .await;
    let (daily, queries, pages) = match read {
        Ok(v) => v,
        Err(e) => {
            let reason = e.to_string();
            dao.record_pull_failed(BING_SOURCE, &y, &reason, now)
                .await?;
            report.error = Some(reason);
            return Ok(report);
        }
    };
    let mut total = 0u32;
    for (day, rows) in daily_rows(
        &daily,
        today - Duration::days(DAILY_HORIZON_DAYS),
        yesterday,
    ) {
        let c = dao
            .replace_daily(BING_SOURCE, &day, &DAILY_METRICS, &rows)
            .await?;
        report.days_written += 1;
        report.rows_written += c.written;
        total += rows.len() as u32;
    }
    let from = today - Duration::days(WEEKLY_HORIZON_DAYS);
    let mut weekly = weekly_rows("query", &queries, from, today);
    for (day, rows) in weekly_rows("page", &pages, from, today) {
        weekly.entry(day).or_default().extend(rows);
    }
    for (day, rows) in weekly {
        let c = dao
            .replace_daily(BING_WEEKLY_SOURCE, &day, &WEEKLY_METRICS, &rows)
            .await?;
        report.buckets_written += 1;
        report.rows_written += c.written;
        total += rows.len() as u32;
    }
    dao.record_pull_ok(
        BING_SOURCE,
        &y,
        PulledDay {
            rows: total,
            missing_goal: None,
            truncated: false,
        },
        now,
    )
    .await?;
    report.ok = true;
    Ok(report)
}

/// The scheduler: hourly, one pod (the Redis claim), only with a key.
pub fn spawn_puller(core: Core) {
    let growth = &core.settings.growth;
    if !growth.enabled {
        return;
    }
    let Some(client) = BingClient::from_settings(growth) else {
        info!(
            "growth bing puller: no Bing Webmaster API key configured (ROOMLER__GROWTH__BING_API_KEY) — nothing is pulled"
        );
        return;
    };
    info!("growth bing puller starting");
    pull_schedule::spawn_hourly(
        core,
        "growth-bing-pull",
        FIRST_TICK_DELAY_SECS,
        LOOP_INTERVAL_SECS,
        move |core| {
            let client = client.clone();
            async move {
                match run_once(&core, &client, DateTime::now()).await {
                    Ok(r) if r.due => info!(
                        ok = r.ok,
                        days = r.days_written,
                        buckets = r.buckets_written,
                        error = r.error.as_deref().unwrap_or(""),
                        "growth bing pull"
                    ),
                    Ok(_) => {}
                    Err(e) => warn!(%e, "growth bing pull failed"),
                }
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    /// Bing's date is epoch milliseconds with a Pacific offset applied
    /// before the calendar day is taken; a negative instant is null.
    #[test]
    fn bings_date_reads_with_its_offset() {
        // 2011-09-16T07:00:00Z at -0700 is midnight of the 16th, Pacific.
        assert_eq!(
            bing_day("/Date(1316156400000-0700)/"),
            Some(d("2011-09-16"))
        );
        // Taken in UTC it would be the 15th at 23:00 local for a -0800 day.
        assert_eq!(
            bing_day("/Date(1316156400000-0800)/"),
            Some(d("2011-09-15"))
        );
        assert_eq!(
            bing_day("/Date(1316156400000+0200)/"),
            Some(d("2011-09-16"))
        );
        assert_eq!(bing_day("/Date(1316156400000)/"), Some(d("2011-09-16")));
        assert_eq!(bing_day("/Date(-62135596800000)/"), None, "Bing's null");
        assert_eq!(bing_day("2011-09-16"), None);
        assert_eq!(bing_day("/Date(abc-0700)/"), None);
    }

    /// The daily site totals and the weekly buckets at Bing's own grain,
    /// inside their horizons; keys folding together summed, the busiest
    /// row's positions kept ×10, Bing's negative "none" dropped.
    #[test]
    fn daily_and_weekly_rows_keep_bings_grain() {
        let daily: Vec<DayStats> = serde_json::from_str(
            r#"[{"__type":"RankAndTrafficStats:#Microsoft.Bing.Webmaster.Api","Date":"/Date(1760252400000-0700)/","Clicks":4,"Impressions":120},
                {"Date":"/Date(1757660400000-0700)/","Clicks":9,"Impressions":300}]"#,
        )
        .unwrap();
        // 1760252400000 is 2025-10-12T07:00Z → the 12th, Pacific.
        let rows = daily_rows(&daily, d("2025-10-01"), d("2025-10-13"));
        assert_eq!(rows.len(), 1, "the other day is outside the horizon");
        let day = &rows["2025-10-12"];
        assert!(day.iter().any(|r| r.metric == "clicks" && r.value == 4));
        assert!(day.iter().all(|r| r.source == BING_SOURCE));

        let weekly: Vec<KeyStats> = serde_json::from_str(
            r#"[{"Query":"roomler","Date":"/Date(1760079600000-0700)/","Clicks":3,"Impressions":40,"AvgImpressionPosition":7,"AvgClickPosition":-1},
                {"Query":" Roomler","Date":"/Date(1760079600000-0700)/","Clicks":1,"Impressions":15,"AvgImpressionPosition":2.5,"AvgClickPosition":2},
                {"Query":"roomler","Date":"/Date(1760079600000-0700)/","Clicks":0,"Impressions":1,"AvgImpressionPosition":12,"AvgClickPosition":-1},
                {"Query":"jane doe 12 main street","Date":"/Date(1760079600000-0700)/","Clicks":1,"Impressions":3,"AvgImpressionPosition":1,"AvgClickPosition":1}]"#,
        )
        .unwrap();
        let w = weekly_rows("query", &weekly, d("2025-10-01"), d("2025-10-13"));
        let bucket = &w["2025-10-10"];
        let get = |q: &str, m: &str| {
            bucket
                .iter()
                .find(|r| r.dims.get("query").map(String::as_str) == Some(q) && r.metric == m)
                .map(|r| r.value)
        };
        assert_eq!(get("roomler", "clicks"), Some(3));
        assert_eq!(get("roomler", "impressions"), Some(41));
        assert_eq!(
            get("roomler", "avg_impression_position_x10"),
            Some(70),
            "the busiest row's"
        );
        assert_eq!(
            get("roomler", "avg_click_position_x10"),
            None,
            "-1 is Bing's none"
        );
        assert_eq!(
            get("Roomler", "avg_impression_position_x10"),
            Some(25),
            "a decimal survives"
        );
        assert!(bucket.iter().all(|r| r.source == BING_WEEKLY_SOURCE));
        // A query below the floor is not stored at all — its text could be
        // one person's words — while a page with as few is: it is our URL.
        assert!(
            bucket
                .iter()
                .all(|r| r.dims.get("query").map(String::as_str) != Some("jane doe 12 main street")),
            "{bucket:?}"
        );
        let pages: Vec<KeyStats> = serde_json::from_str(
            r#"[{"Query":"https://roomler.ai/blog/a/","Date":"/Date(1760079600000-0700)/","Clicks":0,"Impressions":2,"AvgImpressionPosition":30,"AvgClickPosition":-1}]"#,
        )
        .unwrap();
        let p = weekly_rows("page", &pages, d("2025-10-01"), d("2025-10-13"));
        assert!(
            p["2025-10-10"]
                .iter()
                .any(|r| r.metric == "impressions" && r.value == 2)
        );
    }

    #[test]
    fn a_refusal_names_bings_code_and_never_the_key() {
        let e = BingError::Refused(3, "ERROR!!! InvalidApiKey".into());
        assert_eq!(
            e.to_string(),
            "bing unreachable: refused (ErrorCode 3) ERROR!!! InvalidApiKey"
        );
        let g = GrowthSettings {
            bing_api_key: "bing-secret-key".into(),
            ..Default::default()
        };
        let c = BingClient::from_settings(&g).unwrap();
        assert!(!format!("{c:?}").contains("bing-secret-key"));
        assert!(BingClient::from_settings(&GrowthSettings::default()).is_none());
    }
}
