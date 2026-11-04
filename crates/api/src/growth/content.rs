// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — `GET /api/admin/growth/content?since&until&include_internal`:
//! the Content table, one row per blog post (spec §3k).
//!
//! | Column | Source | Window |
//! |---|---|---|
//! | post, published | `growth_content` — the blog's own feed, read daily by `saas` | — |
//! | visitors, pageviews, reads, median read time, top channels | purestat, **live** for the range, by `path` (and `path` × `referrer_host` for the channels) — unique visitors do not add across days | `[since, until]` |
//! | Google: clicks, impressions, CTR, position; top queries | `growth_daily {source: search_console}` — the `page` breakdown (anonymised queries included), the `page_query` one for the queries | the 7 and 28 days ending `google_through`, the newest FINAL day pulled; `google_days` says how many of each window were pulled |
//! | indexed | `growth_content.inspection` — Google's URL Inspection | as of `inspected_at`, the verdict's own time |
//! | sign-ups | `users.signup_attribution.landing_path` equal to the post's path | `[since, until]`, the exclusion set applied |
//!
//! * **A post is its path without the trailing slash**: `/blog/a` and
//!   `/blog/a/` are counted apart by purestat and by Google, and their rows
//!   add up here (visitors too — an upper bound when one reader opened
//!   both; the median read time is the busier form's).
//! * **Small numbers stay honest**: CTR and position only from 30
//!   impressions, a read share only from 30 pageviews; below that the
//!   counts stand alone.
//! * **Three cells**: purestat down or unset makes every web cell
//!   `not_measured` with the reason; no Search Console day pulled makes
//!   every Google cell `not_measured`; never a 0.
//! * ⚠️ **Sign-ups by landing path are a lower bound.** The site carries a
//!   `landing_path` only on a journey that began on a campaign link (FR-88's
//!   carry); an organic reader of a post who signs up carries none until
//!   FR-91 P3 builds the organic carry. The cell says so.

use std::collections::{BTreeMap, HashMap};

use axum::{
    Json,
    extract::{Query as AxumQuery, State},
};
use bson::{Bson, DateTime, doc};
use chrono::Duration;
use meshharbor_services::{
    dao::{
        growth::{GrowthDao, SEARCH_CONSOLE_SOURCE},
        growth_content::{ContentPost, GrowthContentDao},
        growth_digest::ExcludedCounts,
    },
    purestat::{Filter, Query, Row},
};
use meshharbor_core::{campaign, growth::ExclusionSet};
use serde::{Deserialize, Serialize};

use super::{
    campaigns::{range, web_client},
    digest::{
        DigestError, KeyCount, Measured, NotMeasured, SMALL_N, day_str, dt_ms, excluded_ids,
        find_docs, utc_date_of,
    },
    mounted,
    read_key::GrowthAuth,
    search::{self, PageSearch, SearchCell, SearchRow},
};
use crate::{error::ApiError, state::AppState};

/// Channels shown per post.
pub const TOP_CHANNELS: usize = 3;

#[derive(Debug, Deserialize)]
pub struct ContentQuery {
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

/// One post's web plane over the range.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebCell {
    pub visitors: i64,
    pub pageviews: i64,
    /// Pageviews visible ≥ 30 s (purestat's `reads`).
    pub reads: i64,
    /// `reads / pageviews`, only from 30 pageviews.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_share: Option<f64>,
    /// purestat's median visible time of the reads, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_read_s: Option<f64>,
    /// Visitors by organic channel (the referrer host through the §3b
    /// table), top [`TOP_CHANNELS`].
    pub channels: Vec<KeyCount>,
}

/// One post's Google cells.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleCell {
    pub d7: SearchCell,
    pub d28: SearchCell,
    pub top_queries_28d: Vec<SearchRow>,
}

/// One post's index status, as URL Inspection last said it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexCell {
    /// `PASS` · `NEUTRAL` (excluded) · `FAIL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_crawl_time: Option<String>,
    /// When the verdict above was read (RFC 3339) — never a later failed
    /// attempt's time; absent while no inspection has succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspected_at: Option<String>,
    /// The newest attempt (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_at: Option<String>,
    /// The newest attempt's error, when it failed (the fields above are
    /// then the last good one's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// How many final days of each Google window ending `google_through` were
/// pulled: a day missing from a window is a day not counted, not a 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleDays {
    pub d7: i64,
    pub d28: i64,
}

/// Sign-ups whose first touch landed on the post.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignupCell {
    pub count: i64,
    /// Why the count is a lower bound.
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentRow {
    pub path: String,
    pub url: String,
    pub title: String,
    /// RFC 3339.
    pub published_at: String,
    pub in_feed: bool,
    pub web: Measured<WebCell>,
    pub google: Measured<GoogleCell>,
    pub index: Measured<IndexCell>,
    pub signups: SignupCell,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentReport {
    pub since: String,
    pub until: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub n_floor: i64,
    /// Why there is no post list (no feed read yet; `saas` not mounted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posts_not_measured: Option<NotMeasured>,
    /// Why every web cell is `not_measured`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_not_measured: Option<NotMeasured>,
    /// The newest final Search Console day the Google cells end on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_through: Option<String>,
    /// How many final days of the 7- and 28-day windows were pulled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_days: Option<GoogleDays>,
    /// Why every Google cell is `not_measured`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_not_measured: Option<NotMeasured>,
    pub rows: Vec<ContentRow>,
}

/// The lower-bound note on every sign-up cell.
pub const LANDING_NOTE: &str = "sign-ups whose first touch carried this post as landing_path — campaign links only; an organic arrival carries none until FR-91 P3";

/// The post's path in the forms a stored value may take: with and without
/// the trailing slash.
fn path_forms(path: &str) -> [String; 2] {
    let bare = path.trim_end_matches('/');
    [bare.to_string(), format!("{bare}/")]
}

struct Web {
    by_path: HashMap<String, WebCell>,
}

async fn web(state: &AppState, since: &str, until: &str) -> Result<Web, NotMeasured> {
    let client = web_client(state)?;
    let blog = Filter::starts_with("path", "/blog/");
    let rows = client
        .query(
            &Query::range(
                since,
                until,
                &["path"],
                &["visitors", "pageviews", "reads", "median_read_s"],
                &[],
            )
            .filter(blog.clone()),
        )
        .await
        .map_err(|e| NotMeasured::now(e.to_string()))?;
    let sources = client
        .query(
            &Query::range(since, until, &["path", "referrer_host"], &["visitors"], &[])
                .filter(blog),
        )
        .await
        .map_err(|e| NotMeasured::now(e.to_string()))?;
    Ok(Web {
        by_path: fold_web(&rows, &sources),
    })
}

/// One post's web numbers while its path's forms are folded.
#[derive(Default)]
struct WebSum {
    visitors: i64,
    pageviews: i64,
    reads: i64,
    /// `(reads, median)` of the form with the most reads: medians do not add.
    median: Option<(i64, f64)>,
}

/// Pure: purestat's `path` rows and `path × referrer_host` rows, one cell
/// per post. A post's path comes in two forms, `/blog/a` and `/blog/a/`,
/// which purestat counts apart: their counts ADD (visitors too — an upper
/// bound when one reader opened both), and the median read time is the one
/// of the form with the most reads.
fn fold_web(rows: &[Row], sources: &[Row]) -> HashMap<String, WebCell> {
    let mut channels: HashMap<String, BTreeMap<String, i64>> = HashMap::new();
    for r in sources {
        let Some(path) = r.dim("path") else {
            continue;
        };
        let ch = campaign::channel_for_referrer_host(r.dim("referrer_host")).as_str();
        *channels
            .entry(path.trim_end_matches('/').to_string())
            .or_default()
            .entry(ch.to_string())
            .or_insert(0) += r.count("visitors");
    }
    let mut sums: HashMap<String, WebSum> = HashMap::new();
    for r in rows {
        let Some(path) = r.dim("path") else {
            continue;
        };
        let s = sums
            .entry(path.trim_end_matches('/').to_string())
            .or_default();
        let reads = r.count("reads");
        s.visitors += r.count("visitors");
        s.pageviews += r.count("pageviews");
        s.reads += reads;
        if let Some(m) = r.metric("median_read_s")
            && s.median.is_none_or(|(n, _)| reads > n)
        {
            s.median = Some((reads, m));
        }
    }
    sums.into_iter()
        .map(|(key, s)| {
            let mut ch: Vec<KeyCount> = channels
                .remove(&key)
                .unwrap_or_default()
                .into_iter()
                .map(|(key, count)| KeyCount { key, count })
                .collect();
            ch.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
            ch.truncate(TOP_CHANNELS);
            let cell = WebCell {
                visitors: s.visitors,
                pageviews: s.pageviews,
                reads: s.reads,
                read_share: (s.pageviews >= SMALL_N).then(|| s.reads as f64 / s.pageviews as f64),
                median_read_s: s.median.map(|(_, m)| m),
                channels: ch,
            };
            (key, cell)
        })
        .collect()
}

/// Sign-ups in `[since, until]` by landing path (the trailing slash
/// folded), the exclusion set applied.
async fn signups_by_path(
    state: &AppState,
    set: &ExclusionSet,
    paths: &[String],
    since_ms: i64,
    until_ms: i64,
) -> Result<HashMap<String, i64>, DigestError> {
    let forms: Vec<String> = paths.iter().flat_map(|p| path_forms(p)).collect();
    let docs = find_docs(
        state,
        "users",
        doc! {
            "signup_attribution.landing_path": { "$in": forms },
            "created_at": {
                "$gte": DateTime::from_millis(since_ms),
                "$lt": DateTime::from_millis(until_ms),
            },
            "deleted_at": Bson::Null,
            "_id": { "$nin": excluded_ids(&set.users) },
        },
        doc! { "signup_attribution.landing_path": 1, "created_at": 1 },
    )
    .await?;
    let mut out = HashMap::new();
    for d in &docs {
        if dt_ms(d, "created_at").is_none() {
            continue;
        }
        if let Ok(p) = d
            .get_document("signup_attribution")
            .and_then(|a| a.get_str("landing_path"))
        {
            *out.entry(p.trim_end_matches('/').to_string()).or_insert(0) += 1;
        }
    }
    Ok(out)
}

fn index_cell(p: &ContentPost) -> Measured<IndexCell> {
    let rfc = |t: Option<DateTime>| t.and_then(|t| t.try_to_rfc3339_string().ok());
    match &p.inspection {
        Some(i) => Measured::Value(IndexCell {
            verdict: i.verdict.clone(),
            coverage_state: i.coverage_state.clone(),
            last_crawl_time: rfc(i.last_crawl_time),
            inspected_at: rfc(i.inspected_at),
            attempted_at: rfc(i.attempted_at),
            error: i.error.clone(),
        }),
        None => Measured::NotMeasured(NotMeasured::now("not inspected yet")),
    }
}

/// The table for `[since, until]` at `now`.
pub async fn compute(
    state: &AppState,
    set: &ExclusionSet,
    since: chrono::NaiveDate,
    until: chrono::NaiveDate,
    include_internal: bool,
    // The other views' signature; nothing here depends on the clock.
    _now: DateTime,
) -> Result<ContentReport, DigestError> {
    let (since_s, until_s) = (day_str(since), day_str(until));
    let posts = GrowthContentDao::new(&state.db).list().await?;
    let posts_not_measured = posts.is_empty().then(|| {
        if mounted(state, "saas") {
            NotMeasured::now("no blog post read yet (the content puller reads the feed daily)")
        } else {
            NotMeasured::now("saas module not mounted (the content puller runs there)")
        }
    });

    // The web plane, live.
    let web_plane = web(state, &since_s, &until_s).await;
    let web_not_measured = web_plane.as_ref().err().cloned();

    // Google, from the stored final days: the 7 and 28 days ending on the
    // newest final day pulled on or before `until`.
    let from = day_str(until - Duration::days(search::THROUGH_LOOKBACK_DAYS + 27));
    let ok = search::ok_days(state, SEARCH_CONSOLE_SOURCE, &from, &until_s).await?;
    let through = search::through_of(until, &ok);
    // A window's days that were never pulled are uncounted, not zeros: say
    // how many of each window the cells cover.
    let google_days = through.map(|t| {
        let pulled_since = |back: i64| {
            let from = day_str(t - Duration::days(back));
            let to = day_str(t);
            ok.iter().filter(|d| **d >= from && **d <= to).count() as i64
        };
        GoogleDays {
            d7: pulled_since(6),
            d28: pulled_since(27),
        }
    });
    let (google_through, google_not_measured, per_path) = match through {
        Some(through) => {
            let r_from = day_str(through - Duration::days(27));
            let r_to = day_str(through);
            let dao = GrowthDao::new(&state.db);
            let pages = dao
                .read_daily_by(SEARCH_CONSOLE_SOURCE, "page", &r_from, &r_to)
                .await?;
            let pq = dao
                .read_daily_by(SEARCH_CONSOLE_SOURCE, "page_query", &r_from, &r_to)
                .await?;
            (
                Some(day_str(through)),
                None,
                search::per_path(through, &pages, &pq, &ok),
            )
        }
        None => (
            None,
            Some(if state.settings.growth.search_console_configured() {
                NotMeasured::now("no final Search Console day pulled yet")
            } else {
                NotMeasured::now(
                    "no Search Console key configured (ROOMLER__GROWTH__SEARCH_CONSOLE_KEY)",
                )
            }),
            BTreeMap::new(),
        ),
    };
    // Keyed by the path without its trailing slash, both forms already
    // added up by `per_path`.
    let per_path: HashMap<String, PageSearch> = per_path
        .into_iter()
        .map(|(p, s)| (p.trim_end_matches('/').to_string(), s))
        .collect();

    // Sign-ups by landing path.
    let since_ms = since
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc()
        .timestamp_millis();
    let until_ms = (until + Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .expect("midnight")
        .and_utc()
        .timestamp_millis();
    let paths: Vec<String> = posts.iter().map(|p| p.path.clone()).collect();
    let signups = if paths.is_empty() {
        HashMap::new()
    } else {
        signups_by_path(state, set, &paths, since_ms, until_ms).await?
    };

    let mut rows: Vec<ContentRow> = posts
        .iter()
        .map(|p| {
            let key = p.path.trim_end_matches('/').to_string();
            ContentRow {
                path: p.path.clone(),
                url: p.url.clone(),
                title: p.title.clone(),
                published_at: p.published_at.try_to_rfc3339_string().unwrap_or_default(),
                in_feed: p.in_feed,
                web: match &web_plane {
                    Ok(w) => Measured::Value(w.by_path.get(&key).cloned().unwrap_or(WebCell {
                        visitors: 0,
                        pageviews: 0,
                        reads: 0,
                        read_share: None,
                        median_read_s: None,
                        channels: Vec::new(),
                    })),
                    Err(n) => Measured::NotMeasured(n.clone()),
                },
                google: match (&google_not_measured, per_path.get(&key)) {
                    (Some(n), _) => Measured::NotMeasured(n.clone()),
                    (None, Some(s)) => Measured::Value(GoogleCell {
                        d7: s.d7,
                        d28: s.d28,
                        top_queries_28d: s.top_queries_28d.clone(),
                    }),
                    (None, None) => Measured::Value(GoogleCell {
                        d7: SearchCell::default(),
                        d28: SearchCell::default(),
                        top_queries_28d: Vec::new(),
                    }),
                },
                index: index_cell(p),
                signups: SignupCell {
                    count: signups.get(&key).copied().unwrap_or(0),
                    note: LANDING_NOTE.to_string(),
                },
            }
        })
        .collect();
    // In the feed first, newest first (the DAO's order within each).
    rows.sort_by_key(|r| !r.in_feed);
    let (users, tenants) = set.counts();
    Ok(ContentReport {
        since: since_s,
        until: until_s,
        include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        n_floor: SMALL_N,
        posts_not_measured,
        web_not_measured,
        google_through,
        google_days,
        google_not_measured,
        rows,
    })
}

/// `GET /api/admin/growth/content` — platform admins (and the read key), 404
/// otherwise and when `growth.enabled = false`.
pub async fn get_content(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    AxumQuery(q): AxumQuery<ContentQuery>,
) -> Result<Json<ContentReport>, ApiError> {
    let now = DateTime::now();
    let today = utc_date_of(now);
    let (since, until) =
        range(q.since.as_deref(), q.until.as_deref(), today).map_err(ApiError::BadRequest)?;
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    Ok(Json(
        compute(&state, &set, since, until, q.include_internal, now).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(v: serde_json::Value) -> Row {
        serde_json::from_value(v).unwrap()
    }

    /// `/blog/a` and `/blog/a/` are one post: their counts add up, the
    /// median is the busier form's, the read share is recomputed over the
    /// sum, and the channels of both forms land on it.
    #[test]
    fn both_forms_of_a_path_add_up() {
        let rows = [
            row(serde_json::json!({ "dimensions": { "path": "/blog/a/" },
                "metrics": { "visitors": 10, "pageviews": 20, "reads": 6, "median_read_s": 40.0 } })),
            row(serde_json::json!({ "dimensions": { "path": "/blog/a" },
                "metrics": { "visitors": 3, "pageviews": 12, "reads": 2, "median_read_s": 90.0 } })),
            row(serde_json::json!({ "dimensions": { "path": "/blog/b/" },
                "metrics": { "visitors": 1, "pageviews": 1, "reads": 0, "median_read_s": null } })),
        ];
        let sources = [
            row(
                serde_json::json!({ "dimensions": { "path": "/blog/a/", "referrer_host": "www.google.com" },
                "metrics": { "visitors": 4 } }),
            ),
            row(
                serde_json::json!({ "dimensions": { "path": "/blog/a", "referrer_host": "duckduckgo.com" },
                "metrics": { "visitors": 2 } }),
            ),
        ];
        let m = fold_web(&rows, &sources);
        assert_eq!(m.len(), 2, "{m:?}");
        let a = &m["/blog/a"];
        assert_eq!((a.visitors, a.pageviews, a.reads), (13, 32, 8));
        assert_eq!(a.median_read_s, Some(40.0), "the form with the most reads");
        assert_eq!(a.read_share, Some(8.0 / 32.0), "32 pageviews: a share");
        assert_eq!(
            a.channels.iter().map(|c| c.count).sum::<i64>(),
            6,
            "both forms' channels: {:?}",
            a.channels
        );
        let b = &m["/blog/b"];
        assert_eq!((b.median_read_s, b.read_share), (None, None));
    }
}
