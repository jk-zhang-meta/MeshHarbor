// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — search, as the `saas` pullers stored it (spec §3k, §3l):
//! the readers behind the digest's `search` section, the weekly roll-up's,
//! and the Content table's search columns.
//!
//! * **Google** (`growth_daily {source: search_console}`): only FINAL days
//!   are stored, so the newest one lags the calendar by two or three days.
//!   Every window here ends on `through` — the newest day with an `ok` pull
//!   on or before the day asked for — and says so; a window never mixes a
//!   pulled day with an unpulled one silently: `days` counts the days of
//!   each window that hold an `ok` pull.
//! * **Position** is averaged as Google averages it, weighted by
//!   impressions: `Σ position_x100 / Σ impressions / 100`.
//! * **CTR** and position appear only from [`SMALL_N`] impressions — below
//!   that the counts stand alone (principle 5).
//! * **Per page**: the `page` breakdown — the per-page totals, the
//!   anonymised queries included — never the sum of the `page_query` rows,
//!   which is lower by exactly those. A page row's URL is matched to a post
//!   by its path.
//! * **Bing** (`source: bing` daily, `bing_weekly` per query and page) is
//!   Bing's own grain: daily site totals, and weekly buckets per query and
//!   page — never relabelled as 7- or 28-day windows. It is read only while
//!   a `bing` pull succeeded in the last [`BING_PULL_LOOKBACK_DAYS`]
//!   (`pulled` says which day): a failing pull reads "not measured" with
//!   the attempt's error, never as old rows shown as current.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{Duration, NaiveDate};
use meshharbor_services::dao::growth::{
    BING_SOURCE, BING_WEEKLY_SOURCE, GrowthDaily, GrowthDao, PullStatus, SEARCH_CONSOLE_SOURCE,
};
use serde::{Deserialize, Serialize};

use super::{
    digest::{DigestError, Figure, Measured, NotMeasured, SMALL_N, day_str},
    mounted,
};
use crate::state::AppState;

/// Rows in each top list.
pub const TOP_ROWS: usize = 10;
/// How far back `through` is looked for.
pub const THROUGH_LOOKBACK_DAYS: i64 = 14;
/// How far back the newest successful Bing pull may lie. Bing's rows carry
/// their own dates, but a pull that keeps failing must read as failing, not
/// as old numbers shown as measured.
pub const BING_PULL_LOOKBACK_DAYS: i64 = 3;

/// Clicks, impressions and the derived cells of a set of rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct SearchCell {
    pub clicks: i64,
    pub impressions: i64,
    /// `clicks / impressions`, only from [`SMALL_N`] impressions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctr: Option<f64>,
    /// Impression-weighted, only from [`SMALL_N`] impressions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<f64>,
}

#[derive(Default, Clone, Copy)]
struct Sum {
    clicks: i64,
    impressions: i64,
    position_x100: i64,
}

impl Sum {
    fn add(&mut self, metric: &str, v: i64) {
        match metric {
            "clicks" => self.clicks += v,
            "impressions" => self.impressions += v,
            "position_x100" => self.position_x100 += v,
            _ => {}
        }
    }

    fn cell(self) -> SearchCell {
        let enough = self.impressions >= SMALL_N;
        SearchCell {
            clicks: self.clicks,
            impressions: self.impressions,
            ctr: enough.then(|| self.clicks as f64 / self.impressions as f64),
            position: enough.then(|| {
                ((self.position_x100 as f64 / self.impressions as f64 / 100.0) * 10.0).round()
                    / 10.0
            }),
        }
    }
}

/// One row of a top list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchRow {
    pub key: String,
    #[serde(flatten)]
    pub cell: SearchCell,
}

/// Google over the windows ending on `through`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleReport {
    /// The newest final day pulled on or before the day asked for.
    pub through: String,
    pub clicks: Figure,
    pub impressions: Figure,
    /// The 28 days ending `through`, with CTR and position from 30
    /// impressions.
    pub d28: SearchCell,
    /// How many days of each window hold an `ok` pull.
    pub days: Figure,
    /// The 7 days ending `through`, by query (Google leaves anonymised
    /// queries out of this breakdown) and by page.
    pub top_queries_7d: Vec<SearchRow>,
    pub top_pages_7d: Vec<SearchRow>,
}

/// Bing at its own grain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BingReport {
    /// The newest day of Bing's daily site totals on or before the day —
    /// or, with none stored (a zero is not stored), the day the pull covered.
    pub through: String,
    /// The day the newest SUCCESSFUL Bing pull covered (its cycle's
    /// yesterday): how fresh these numbers are. Older than
    /// [`BING_PULL_LOOKBACK_DAYS`] and the section reads "not measured".
    #[serde(default)]
    pub pulled: String,
    pub clicks: Figure,
    pub impressions: Figure,
    /// Bing's newest weekly bucket on or before the day, and its top rows —
    /// a week as Bing cuts it, not a 7-day window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub week: Option<String>,
    pub top_queries_week: Vec<SearchRow>,
    pub top_pages_week: Vec<SearchRow>,
}

/// The digest's and the weekly roll-up's `search` section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchSection {
    pub google: Measured<GoogleReport>,
    pub bing: Measured<BingReport>,
}

/// The `ok` days of a source in `[from, to]`.
pub async fn ok_days(
    state: &AppState,
    source: &str,
    from: &str,
    to: &str,
) -> Result<HashSet<String>, DigestError> {
    Ok(GrowthDao::new(&state.db)
        .pulls_between(source, from, to)
        .await?
        .into_iter()
        .filter(|p| p.status == PullStatus::Ok)
        .map(|p| p.day)
        .collect())
}

/// The path of a page URL Google reports (`https://roomler.ai/blog/x/?a` →
/// `/blog/x/`), whatever the host; a value that is already a path keeps
/// its path. `None` for anything that is neither.
pub fn path_of(page: &str) -> Option<String> {
    let rest = if page.starts_with('/') {
        page
    } else {
        let after = page.split_once("://")?.1;
        match after.find('/') {
            Some(i) => &after[i..],
            None => "/",
        }
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Pure: sums of `rows` (one breakdown) per key, over the days in `[from,
/// to]` that are in `ok`.
fn sums_by(
    rows: &[GrowthDaily],
    key: impl Fn(&GrowthDaily) -> Option<String>,
    from: &str,
    to: &str,
    ok: &HashSet<String>,
) -> HashMap<String, Sum> {
    let mut out: HashMap<String, Sum> = HashMap::new();
    for r in rows {
        if r.day.as_str() < from || r.day.as_str() > to || !ok.contains(&r.day) {
            continue;
        }
        if let Some(k) = key(r) {
            out.entry(k).or_default().add(&r.metric, r.value);
        }
    }
    out
}

fn top(map: HashMap<String, Sum>) -> Vec<SearchRow> {
    let mut v: Vec<SearchRow> = map
        .into_iter()
        .map(|(key, s)| SearchRow {
            key,
            cell: s.cell(),
        })
        .filter(|r| r.cell.impressions > 0 || r.cell.clicks > 0)
        .collect();
    v.sort_by(|a, b| {
        b.cell
            .clicks
            .cmp(&a.cell.clicks)
            .then_with(|| b.cell.impressions.cmp(&a.cell.impressions))
            .then_with(|| a.key.cmp(&b.key))
    });
    v.truncate(TOP_ROWS);
    v
}

/// Pure: Google's report over stored rows, windows ending on `through`.
pub fn google_report(
    through: NaiveDate,
    site: &[GrowthDaily],
    queries: &[GrowthDaily],
    pages: &[GrowthDaily],
    ok: &HashSet<String>,
) -> GoogleReport {
    let t = day_str(through);
    let d7 = day_str(through - Duration::days(6));
    let d28 = day_str(through - Duration::days(27));
    let window = |from: &str| {
        sums_by(site, |_| Some(String::new()), from, &t, ok)
            .remove("")
            .unwrap_or_default()
    };
    let (day, w7, w28) = (window(&t), window(&d7), window(&d28));
    let count_days = |from: &str| {
        ok.iter()
            .filter(|d| d.as_str() >= from && d.as_str() <= t.as_str())
            .count() as i64
    };
    GoogleReport {
        through: t.clone(),
        clicks: Figure {
            day: day.clicks,
            d7: w7.clicks,
            d28: w28.clicks,
        },
        impressions: Figure {
            day: day.impressions,
            d7: w7.impressions,
            d28: w28.impressions,
        },
        d28: w28.cell(),
        days: Figure {
            day: count_days(&t),
            d7: count_days(&d7),
            d28: count_days(&d28),
        },
        top_queries_7d: top(sums_by(
            queries,
            |r| r.dims.get("query").cloned(),
            &d7,
            &t,
            ok,
        )),
        top_pages_7d: top(sums_by(pages, |r| r.dims.get("page").cloned(), &d7, &t, ok)),
    }
}

/// The newest `ok` day on or before `day`, within the lookback.
pub fn through_of(day: NaiveDate, ok: &HashSet<String>) -> Option<NaiveDate> {
    (0..=THROUGH_LOOKBACK_DAYS)
        .map(|b| day - Duration::days(b))
        .find(|d| ok.contains(&day_str(*d)))
}

async fn rows_by(
    state: &AppState,
    source: &str,
    by: &str,
    from: &str,
    to: &str,
) -> Result<Vec<GrowthDaily>, DigestError> {
    Ok(GrowthDao::new(&state.db)
        .read_daily_by(source, by, from, to)
        .await?)
}

fn not_pulled(state: &AppState, what: String) -> NotMeasured {
    if mounted(state, "saas") {
        NotMeasured::now(what)
    } else {
        NotMeasured::now("saas module not mounted (the search pullers run there)")
    }
}

/// Google's part of the `search` section for `day`.
pub async fn google(
    state: &AppState,
    day: NaiveDate,
) -> Result<Measured<GoogleReport>, DigestError> {
    let from = day_str(day - Duration::days(THROUGH_LOOKBACK_DAYS + 27));
    let to = day_str(day);
    let ok = ok_days(state, SEARCH_CONSOLE_SOURCE, &from, &to).await?;
    let Some(through) = through_of(day, &ok) else {
        return Ok(Measured::NotMeasured(
            if state.settings.growth.search_console_configured() {
                not_pulled(
                    state,
                    format!(
                        "no final Search Console day pulled in the {} days to {}",
                        THROUGH_LOOKBACK_DAYS + 1,
                        day_str(day)
                    ),
                )
            } else {
                NotMeasured::now(
                    "no Search Console key configured (MESHHARBOR__GROWTH__SEARCH_CONSOLE_KEY)",
                )
            },
        ));
    };
    let r_from = day_str(through - Duration::days(27));
    let r_to = day_str(through);
    let site = rows_by(state, SEARCH_CONSOLE_SOURCE, "site", &r_from, &r_to).await?;
    let queries = rows_by(state, SEARCH_CONSOLE_SOURCE, "query", &r_from, &r_to).await?;
    let pages = rows_by(state, SEARCH_CONSOLE_SOURCE, "page", &r_from, &r_to).await?;
    Ok(Measured::Value(google_report(
        through, &site, &queries, &pages, &ok,
    )))
}

/// Pure: Bing's report — daily totals ending on the newest daily row on or
/// before `day`, and the newest weekly bucket's top rows — for a pull that
/// succeeded for the day `pulled`. With no daily row stored, the windows end
/// on `pulled` and are zero: every call returns Bing's whole history, so a
/// day without a row is a day without a click or an impression.
pub fn bing_report(
    day: NaiveDate,
    daily: &[GrowthDaily],
    weekly: &[GrowthDaily],
    pulled: &str,
) -> BingReport {
    let d = day_str(day);
    let through = daily
        .iter()
        .filter(|r| r.day <= d)
        .map(|r| r.day.clone())
        .max()
        .unwrap_or_else(|| pulled.to_string());
    let t_date = NaiveDate::parse_from_str(&through, "%Y-%m-%d").unwrap_or(day);
    let d7 = day_str(t_date - Duration::days(6));
    let d28 = day_str(t_date - Duration::days(27));
    let fig = |metric: &str| {
        let mut f = Figure::default();
        for r in daily.iter().filter(|r| r.metric == metric) {
            if r.day == through {
                f.day += r.value;
            }
            if r.day >= d7 && r.day <= through {
                f.d7 += r.value;
            }
            if r.day >= d28 && r.day <= through {
                f.d28 += r.value;
            }
        }
        f
    };
    let (clicks, impressions) = (fig("clicks"), fig("impressions"));
    let week = weekly
        .iter()
        .filter(|r| r.day <= d)
        .map(|r| r.day.clone())
        .max();
    let top_of = |by: &str| -> Vec<SearchRow> {
        let Some(w) = &week else {
            return Vec::new();
        };
        let mut m: HashMap<String, Sum> = HashMap::new();
        for r in weekly
            .iter()
            .filter(|r| r.day == *w && r.dims.get("by").map(String::as_str) == Some(by))
        {
            if let Some(k) = r.dims.get(by) {
                // Bing's positions are its own; only the counts are summed.
                m.entry(k.clone()).or_default().add(&r.metric, r.value);
            }
        }
        let mut rows = top(m);
        for r in &mut rows {
            r.cell.position = None;
        }
        rows
    };
    BingReport {
        through,
        pulled: pulled.to_string(),
        clicks,
        impressions,
        top_queries_week: top_of("query"),
        top_pages_week: top_of("page"),
        week,
    }
}

/// Bing's part of the `search` section for `day`. It reads the `bing` pull
/// rows first: without one that succeeded in the [`BING_PULL_LOOKBACK_DAYS`]
/// to `day`, the stored rows — however recent their own dates — are not
/// shown as measured, and the reason names the newest failed attempt.
pub async fn bing(state: &AppState, day: NaiveDate) -> Result<Measured<BingReport>, DigestError> {
    let to = day_str(day);
    let dao = GrowthDao::new(&state.db);
    let pulls = dao
        .pulls_between(
            BING_SOURCE,
            &day_str(day - Duration::days(BING_PULL_LOOKBACK_DAYS)),
            &to,
        )
        .await?;
    let pulled = pulls
        .iter()
        .filter(|p| p.status == PullStatus::Ok)
        .map(|p| p.day.clone())
        .max();
    let Some(pulled) = pulled else {
        return Ok(Measured::NotMeasured(
            if !state.settings.growth.bing_configured() {
                NotMeasured::now(
                    "no Bing Webmaster API key configured (MESHHARBOR__GROWTH__BING_API_KEY)",
                )
            } else {
                let days = BING_PULL_LOOKBACK_DAYS + 1;
                let newest_failure = pulls
                    .iter()
                    .filter_map(|p| p.error.as_ref().map(|e| (p.day.clone(), e.clone())))
                    .max();
                not_pulled(
                    state,
                    match newest_failure {
                        Some((d, e)) => format!(
                            "no Bing pull succeeded in the {days} days to {to}; the attempt for {d}: {e}"
                        ),
                        None => format!("no Bing pull in the {days} days to {to}"),
                    },
                )
            },
        ));
    };
    let from = day_str(day - Duration::days(THROUGH_LOOKBACK_DAYS + 27));
    let daily = dao.read_daily_by(BING_SOURCE, "site", &from, &to).await?;
    let mut weekly = dao
        .read_daily_by(BING_WEEKLY_SOURCE, "query", &from, &to)
        .await?;
    weekly.extend(
        dao.read_daily_by(BING_WEEKLY_SOURCE, "page", &from, &to)
            .await?,
    );
    Ok(Measured::Value(bing_report(day, &daily, &weekly, &pulled)))
}

/// The `search` section for `day`.
pub async fn section(state: &AppState, day: NaiveDate) -> Result<SearchSection, DigestError> {
    Ok(SearchSection {
        google: google(state, day).await?,
        bing: bing(state, day).await?,
    })
}

/// The Content table's per-path Google cells: the 7 and 28 days ending
/// `through`, from the `page` breakdown, and each path's top queries over
/// the 28 days from `page_query`.
pub struct PageSearch {
    pub d7: SearchCell,
    pub d28: SearchCell,
    pub top_queries_28d: Vec<SearchRow>,
}

/// Pure: the per-path cells over stored `page` and `page_query` rows, keyed
/// by the path WITHOUT its trailing slash: `https://roomler.ai/blog/a` and
/// `…/blog/a/` (and any host) are one post, and their rows add up.
pub fn per_path(
    through: NaiveDate,
    pages: &[GrowthDaily],
    page_queries: &[GrowthDaily],
    ok: &HashSet<String>,
) -> BTreeMap<String, PageSearch> {
    let t = day_str(through);
    let d7 = day_str(through - Duration::days(6));
    let d28 = day_str(through - Duration::days(27));
    let path_key = |r: &GrowthDaily| {
        r.dims
            .get("page")
            .and_then(|p| path_of(p))
            .map(|p| p.trim_end_matches('/').to_string())
    };
    let w7 = sums_by(pages, path_key, &d7, &t, ok);
    let w28 = sums_by(pages, path_key, &d28, &t, ok);
    let mut q: HashMap<String, HashMap<String, Sum>> = HashMap::new();
    for r in page_queries {
        if r.day.as_str() < d28.as_str() || r.day.as_str() > t.as_str() || !ok.contains(&r.day) {
            continue;
        }
        let (Some(p), Some(query)) = (path_key(r), r.dims.get("query")) else {
            continue;
        };
        q.entry(p)
            .or_default()
            .entry(query.clone())
            .or_default()
            .add(&r.metric, r.value);
    }
    let mut out = BTreeMap::new();
    let paths: HashSet<String> = w28.keys().chain(w7.keys()).cloned().collect();
    for p in paths {
        let mut top_queries = q.remove(&p).map(top).unwrap_or_default();
        top_queries.truncate(5);
        out.insert(
            p.clone(),
            PageSearch {
                d7: w7.get(&p).copied().unwrap_or_default().cell(),
                d28: w28.get(&p).copied().unwrap_or_default().cell(),
                top_queries_28d: top_queries,
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_services::dao::growth::daily_row;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn sc(
        day: &str,
        by: &str,
        dims: &[(&str, &str)],
        clicks: i64,
        impressions: i64,
        pos: f64,
    ) -> Vec<GrowthDaily> {
        let mut m = BTreeMap::new();
        m.insert("by".to_string(), by.to_string());
        for (k, v) in dims {
            m.insert(k.to_string(), v.to_string());
        }
        let mut out = vec![
            daily_row(SEARCH_CONSOLE_SOURCE, "clicks", m.clone(), day, clicks),
            daily_row(
                SEARCH_CONSOLE_SOURCE,
                "impressions",
                m.clone(),
                day,
                impressions,
            ),
        ];
        let p = (pos * impressions as f64 * 100.0).round() as i64;
        if p > 0 {
            out.push(daily_row(SEARCH_CONSOLE_SOURCE, "position_x100", m, day, p));
        }
        out
    }

    fn ok(days: &[&str]) -> HashSet<String> {
        days.iter().map(|s| s.to_string()).collect()
    }

    /// The windows end on `through`; the position averages as Google does
    /// (weighted by impressions); CTR and position only from 30
    /// impressions; a row of a day without an `ok` pull is not read.
    #[test]
    fn google_windows_weight_position_and_hide_small_rates() {
        let mut site = Vec::new();
        site.extend(sc("2026-10-14", "site", &[], 4, 100, 5.0));
        site.extend(sc("2026-10-10", "site", &[], 1, 20, 10.0));
        site.extend(sc("2026-09-20", "site", &[], 2, 10, 2.0));
        // Stored, but its pull is not ok: never read.
        site.extend(sc("2026-10-13", "site", &[], 99, 999, 1.0));
        let queries = sc(
            "2026-10-14",
            "query",
            &[("query", "remote desktop")],
            3,
            25,
            4.0,
        );
        let pages = sc(
            "2026-10-14",
            "page",
            &[("page", "https://roomler.ai/blog/a/")],
            4,
            60,
            3.0,
        );
        let okd = ok(&["2026-10-14", "2026-10-10", "2026-09-20", "2026-10-12"]);
        let g = google_report(d("2026-10-14"), &site, &queries, &pages, &okd);
        assert_eq!(g.through, "2026-10-14");
        assert_eq!(
            g.clicks,
            Figure {
                day: 4,
                d7: 5,
                d28: 7
            }
        );
        assert_eq!(
            g.impressions,
            Figure {
                day: 100,
                d7: 120,
                d28: 130
            }
        );
        // (5·100 + 10·20 + 2·10) / 130 = 5.54 → 5.5.
        assert_eq!(g.d28.position, Some(5.5));
        assert_eq!(g.d28.ctr, Some(7.0 / 130.0));
        assert_eq!(
            g.days,
            Figure {
                day: 1,
                d7: 3,
                d28: 4
            }
        );
        // 25 impressions: counts only, no CTR, no position.
        assert_eq!(g.top_queries_7d[0].key, "remote desktop");
        assert_eq!(g.top_queries_7d[0].cell.ctr, None);
        assert_eq!(g.top_queries_7d[0].cell.position, None);
        assert_eq!(g.top_pages_7d[0].cell.position, Some(3.0));
        // `through` is the newest ok day on or before the day asked for.
        assert_eq!(through_of(d("2026-10-16"), &okd), Some(d("2026-10-14")));
        assert_eq!(through_of(d("2026-12-01"), &okd), None, "past the lookback");
    }

    /// Per post: the page rows matched by path (any host, the trailing
    /// slash folded by the caller), never the page × query sum; the top
    /// queries from the page × query rows.
    #[test]
    fn per_path_reads_the_page_rows_and_the_queries() {
        let mut pages = sc(
            "2026-10-14",
            "page",
            &[("page", "https://roomler.ai/blog/a/")],
            4,
            60,
            3.0,
        );
        pages.extend(sc(
            "2026-10-02",
            "page",
            &[("page", "https://www.roomler.ai/blog/a/")],
            1,
            20,
            9.0,
        ));
        // The same post without its trailing slash: its own row, one post.
        pages.extend(sc(
            "2026-10-14",
            "page",
            &[("page", "https://roomler.ai/blog/a")],
            2,
            15,
            4.0,
        ));
        let mut pq = sc(
            "2026-10-14",
            "page_query",
            &[
                ("page", "https://roomler.ai/blog/a/"),
                ("query", "remote desktop"),
            ],
            3,
            40,
            3.0,
        );
        pq.extend(sc(
            "2026-10-14",
            "page_query",
            &[
                ("page", "https://roomler.ai/blog/a/"),
                ("query", "self hosted"),
            ],
            0,
            5,
            8.0,
        ));
        let okd = ok(&["2026-10-14", "2026-10-02"]);
        let m = per_path(d("2026-10-14"), &pages, &pq, &okd);
        assert_eq!(m.len(), 1, "one post, whatever the host or the slash");
        let a = &m["/blog/a"];
        assert_eq!(
            (a.d7.clicks, a.d7.impressions),
            (6, 75),
            "/blog/a and /blog/a/ add up"
        );
        assert_eq!(
            (a.d28.clicks, a.d28.impressions),
            (7, 95),
            "both hosts and both forms, one path"
        );
        assert_eq!(a.top_queries_28d[0].key, "remote desktop");
        assert_eq!(a.top_queries_28d.len(), 2);
        assert_eq!(
            path_of("https://roomler.ai/blog/a/?x=1").as_deref(),
            Some("/blog/a/")
        );
        assert_eq!(path_of("/blog/b/").as_deref(), Some("/blog/b/"));
    }

    /// Bing: its daily totals ending on its newest day, and the newest
    /// weekly bucket's rows — Bing's positions never averaged.
    #[test]
    fn bing_reads_its_own_grain() {
        let site = |day: &str, metric: &str, v: i64| {
            let mut m = BTreeMap::new();
            m.insert("by".to_string(), "site".to_string());
            daily_row(BING_SOURCE, metric, m, day, v)
        };
        let week = |day: &str, q: &str, metric: &str, v: i64| {
            let mut m = BTreeMap::new();
            m.insert("by".to_string(), "query".to_string());
            m.insert("query".to_string(), q.to_string());
            daily_row(BING_WEEKLY_SOURCE, metric, m, day, v)
        };
        let daily = vec![
            site("2026-10-14", "clicks", 2),
            site("2026-10-14", "impressions", 40),
            site("2026-10-09", "clicks", 1),
        ];
        let weekly = vec![
            week("2026-10-10", "meshharbor", "clicks", 3),
            week("2026-10-10", "meshharbor", "impressions", 50),
            week("2026-10-10", "meshharbor", "avg_impression_position_x10", 40),
            week("2026-10-03", "old", "clicks", 9),
        ];
        let b = bing_report(d("2026-10-16"), &daily, &weekly, "2026-10-15");
        assert_eq!(b.through, "2026-10-14");
        assert_eq!(b.pulled, "2026-10-15");
        assert_eq!(
            b.clicks,
            Figure {
                day: 2,
                d7: 3,
                d28: 3
            }
        );
        assert_eq!(b.week.as_deref(), Some("2026-10-10"));
        assert_eq!(b.top_queries_week.len(), 1);
        assert_eq!(b.top_queries_week[0].cell.impressions, 50);
        assert_eq!(b.top_queries_week[0].cell.position, None);
        // A pull that succeeded with no daily row stored: Bing returned its
        // whole history, so the windows are zero, ending on the pulled day.
        let quiet = bing_report(d("2026-10-16"), &[], &weekly, "2026-10-15");
        assert_eq!(quiet.through, "2026-10-15");
        assert_eq!(quiet.clicks, Figure::default());
        assert_eq!(quiet.week.as_deref(), Some("2026-10-10"));
    }
}
