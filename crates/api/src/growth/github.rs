// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the repository's numbers as the `saas` GitHub puller stored
//! them (spec §3k): the daily digest's `github` section and the weekly
//! roll-up's.
//!
//! * **Counters are cumulative snapshots**, one per closed day
//!   (`growth_daily {source: github}`), so a change is a DIFFERENCE of two
//!   snapshots. A delta whose snapshots are not both there is `null`, never
//!   0 and never spread across the gap: a 7-day delta needs the snapshot 7
//!   days before, whatever happened in between.
//! * **Downloads are differenced per release**: a release present later
//!   and not before started at 0 and counts fully; a release that vanished
//!   (deleted) counts nothing; and a release whose total went DOWN counts
//!   nothing either. A total goes down when an asset is re-uploaded (CI's
//!   `seed-cache` has 28, clobbered on every seed save), which restarts that
//!   asset's count, and the release's total alone cannot tell the other
//!   assets' downloads from the restart — so that day is an under-count for
//!   the release, never an over-count. The per-flavour downloads have no
//!   per-release split either, and a flavour's change is clamped at 0 the
//!   same way.
//! * **A truncated listing is a lower bound**: when the puller's release
//!   listing hit its page bound (`truncated` on the day's pull row), that
//!   snapshot's downloads are shown as a lower bound and every downloads
//!   change that needs it is `null`.
//! * **The product apart from the helpers**: a release row's `kind` says
//!   whether it is the product's (the daemon, the wizard, the tunnel CLI) or
//!   a helper our own CI downloads (vendored builds, caches) — half of the
//!   repository's downloads on 2026-10-17 — and each is differenced on its
//!   own (`downloads_delta`, `helper_downloads_delta`).
//! * **Traffic** (`growth_daily {source: github_traffic}`, the token's) is
//!   GitHub's per-day buckets, summed over the days the puller holds an
//!   `ok` row for — `measured_days` says how many of each window that is —
//!   and the referrers are GitHub's own 14-day ranking, as read after the
//!   closed day it is stored under.
//!
//! ⚠️ GitHub counts every download of a release asset — the fleet's
//! self-updates among them (their `.asc` and `.sha256` sidecars are not
//! counted). Downloads are distribution, not installs.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{Duration, NaiveDate};
use meshharbor_services::dao::growth::{
    GITHUB_SOURCE, GITHUB_TRAFFIC_SOURCE, GrowthDaily, GrowthDao, PullStatus,
};
use serde::{Deserialize, Serialize};

use super::{
    digest::{DigestError, Figure, KeyCount, Measured, NotMeasured, day_str},
    mounted,
};
use crate::state::AppState;

/// How far back a reader looks for the snapshot to read at.
pub const SNAPSHOT_LOOKBACK_DAYS: i64 = 7;
/// Rows in each top list.
pub const TOP_ROWS: usize = 10;

/// A change between two snapshots, per window ending on the snapshot read:
/// `null` when the snapshot at the window's start is missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    pub day: Option<i64>,
    pub d7: Option<i64>,
    pub d28: Option<i64>,
}

/// The public counters at one snapshot, and their changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubCounters {
    pub repo: String,
    /// The closed day whose snapshot these are (`YYYY-MM-DD`): the asked-for
    /// day, or the latest snapshot before it (at most
    /// [`SNAPSHOT_LOOKBACK_DAYS`]).
    pub at: String,
    pub stars: i64,
    pub forks: i64,
    pub watchers: i64,
    /// Every download of every published PRODUCT release asset but the
    /// sidecars, ever — the fleet's self-updates included.
    pub downloads: i64,
    /// The helper releases' downloads (vendored builds and caches our own CI
    /// fetches), counted apart so the product's number is not half CI.
    pub helper_downloads: i64,
    /// The snapshot's release listing hit the puller's page bound:
    /// `downloads` and `helper_downloads` are lower bounds, and every
    /// downloads change that needs this snapshot is `null`.
    #[serde(default)]
    pub downloads_truncated: bool,
    pub stars_delta: Delta,
    pub forks_delta: Delta,
    pub watchers_delta: Delta,
    pub downloads_delta: Delta,
    pub helper_downloads_delta: Delta,
    /// Product downloads in the 7 days ending `at`, by release tag; not
    /// measured without the snapshot 7 days before.
    pub top_releases_7d: Measured<Vec<KeyCount>>,
    /// The same, by flavour (the asset name without its version).
    pub top_flavours_7d: Measured<Vec<KeyCount>>,
}

/// One referrer of GitHub's 14-day ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferrerRow {
    pub referrer: String,
    pub views: i64,
    pub uniques: i64,
}

/// The repository's traffic, as the token reads it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubTraffic {
    pub views: Figure,
    /// Each day's unique visitors, SUMMED over the window — an upper bound
    /// on the window's own uniques, which GitHub does not give per range.
    pub views_uniques: Figure,
    pub clones: Figure,
    pub clones_uniques: Figure,
    /// How many days of each window the puller holds an `ok` row for; the
    /// sums above cover those days only.
    pub measured_days: Figure,
    /// GitHub's ranking of the 14 days before the read, stored under
    /// `referrers_as_of`; empty when nobody referred.
    pub referrers: Vec<ReferrerRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrers_as_of: Option<String>,
}

/// The digest's and the weekly roll-up's `github` section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GithubSection {
    pub counters: Measured<GithubCounters>,
    pub traffic: Measured<GithubTraffic>,
}

impl GithubSection {
    /// What a digest stored before P7 reads as.
    pub fn before_p7() -> Self {
        Self {
            counters: Measured::NotMeasured(NotMeasured::later(
                "stars, forks and release downloads",
                "P7",
            )),
            traffic: Measured::NotMeasured(NotMeasured::later("repository traffic", "P7")),
        }
    }
}

/// One snapshot: the repo counters, and downloads per release (the
/// product's and the helpers' apart) and per flavour.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub repo: BTreeMap<String, i64>,
    pub releases: BTreeMap<String, i64>,
    pub helper_releases: BTreeMap<String, i64>,
    pub flavours: BTreeMap<String, i64>,
    /// The listing hit the page bound: the downloads are a lower bound.
    pub truncated: bool,
}

impl Snapshot {
    fn counter(&self, metric: &str) -> i64 {
        self.repo.get(metric).copied().unwrap_or(0)
    }
}

/// Pure: the snapshots of the `ok` days among `rows` (one repository),
/// keyed by day, those in `truncated_days` marked. A day with an `ok` pull
/// and no row of a kind holds a zero there — zeros are not stored.
pub fn snapshots(
    rows: &[GrowthDaily],
    ok_days: &HashSet<String>,
    truncated_days: &HashSet<String>,
) -> BTreeMap<String, Snapshot> {
    let mut out: BTreeMap<String, Snapshot> = ok_days
        .iter()
        .map(|d| {
            (
                d.clone(),
                Snapshot {
                    truncated: truncated_days.contains(d),
                    ..Snapshot::default()
                },
            )
        })
        .collect();
    for r in rows {
        let Some(s) = out.get_mut(&r.day) else {
            continue;
        };
        match r.dims.get("by").map(String::as_str) {
            Some("repo") => {
                s.repo.insert(r.metric.clone(), r.value);
            }
            Some("release") => {
                if let Some(tag) = r.dims.get("release") {
                    let map = if r.dims.get("kind").map(String::as_str) == Some("helper") {
                        &mut s.helper_releases
                    } else {
                        &mut s.releases
                    };
                    *map.entry(tag.clone()).or_insert(0) += r.value;
                }
            }
            Some("flavour") => {
                if let Some(f) = r.dims.get("flavour") {
                    *s.flavours.entry(f.clone()).or_insert(0) += r.value;
                }
            }
            _ => {}
        }
    }
    out
}

/// Pure: a counter's change between two snapshots.
fn counter_delta(later: &Snapshot, earlier: Option<&Snapshot>, metric: &str) -> Option<i64> {
    earlier.map(|e| later.counter(metric) - e.counter(metric))
}

/// Pure: the downloads between two snapshots, per key (a release, or a
/// flavour) — a new key counts fully, a vanished key counts nothing, and a
/// key whose total went DOWN counts nothing: an asset re-uploaded restarted
/// its count, and the total alone cannot tell the downloads of the key's
/// other assets from the restart. An under-count of that key's day, never
/// an over-count.
pub fn per_key_downloads(
    later: &BTreeMap<String, i64>,
    earlier: &BTreeMap<String, i64>,
) -> BTreeMap<String, i64> {
    later
        .iter()
        .map(|(k, &now)| {
            let before = earlier.get(k).copied().unwrap_or(0);
            (k.clone(), (now - before).max(0))
        })
        .collect()
}

/// Pure: a downloads change between two snapshots, from the per-release
/// totals `pick` chooses: `null` when the earlier snapshot is missing or
/// either listing was truncated (a lower bound differenced is no change).
fn release_delta(
    later: &Snapshot,
    earlier: Option<&Snapshot>,
    pick: fn(&Snapshot) -> &BTreeMap<String, i64>,
) -> Option<i64> {
    earlier
        .filter(|e| !e.truncated && !later.truncated)
        .map(|e| per_key_downloads(pick(later), pick(e)).values().sum())
}

fn downloads_delta(later: &Snapshot, earlier: Option<&Snapshot>) -> Option<i64> {
    release_delta(later, earlier, |s| &s.releases)
}

fn helper_downloads_delta(later: &Snapshot, earlier: Option<&Snapshot>) -> Option<i64> {
    release_delta(later, earlier, |s| &s.helper_releases)
}

fn top(map: BTreeMap<String, i64>) -> Vec<KeyCount> {
    let mut v: Vec<KeyCount> = map
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(key, count)| KeyCount { key, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    v.truncate(TOP_ROWS);
    v
}

/// Pure: the counters at the latest snapshot on or before `day` (at most
/// [`SNAPSHOT_LOOKBACK_DAYS`] before it), with their deltas.
pub fn counters_at(
    repo: &str,
    day: NaiveDate,
    snaps: &BTreeMap<String, Snapshot>,
) -> Option<GithubCounters> {
    let at = (0..=SNAPSHOT_LOOKBACK_DAYS)
        .map(|back| day - Duration::days(back))
        .find(|d| snaps.contains_key(&day_str(*d)))?;
    let now = &snaps[&day_str(at)];
    let back = |n: i64| snaps.get(&day_str(at - Duration::days(n)));
    let delta = |f: &dyn Fn(&Snapshot, Option<&Snapshot>) -> Option<i64>| Delta {
        day: f(now, back(1)),
        d7: f(now, back(7)),
        d28: f(now, back(28)),
    };
    let week_start = day_str(at - Duration::days(7));
    let week = back(7);
    let week_list = |pick: fn(&Snapshot) -> &BTreeMap<String, i64>| match week {
        None => Measured::NotMeasured(NotMeasured::now(format!(
            "no snapshot for {week_start} to difference against"
        ))),
        Some(e) if e.truncated || now.truncated => {
            let cut = if now.truncated {
                day_str(at)
            } else {
                week_start.clone()
            };
            Measured::NotMeasured(NotMeasured::now(format!(
                "the release listing of {cut} hit the page bound"
            )))
        }
        Some(e) => Measured::Value(top(per_key_downloads(pick(now), pick(e)))),
    };
    Some(GithubCounters {
        repo: repo.to_string(),
        at: day_str(at),
        stars: now.counter("stars"),
        forks: now.counter("forks"),
        watchers: now.counter("watchers"),
        downloads: now.counter("downloads"),
        helper_downloads: now.counter("helper_downloads"),
        downloads_truncated: now.truncated,
        stars_delta: delta(&|l, e| counter_delta(l, e, "stars")),
        forks_delta: delta(&|l, e| counter_delta(l, e, "forks")),
        watchers_delta: delta(&|l, e| counter_delta(l, e, "watchers")),
        downloads_delta: delta(&downloads_delta),
        helper_downloads_delta: delta(&helper_downloads_delta),
        top_releases_7d: week_list(|s| &s.releases),
        top_flavours_7d: week_list(|s| &s.flavours),
    })
}

/// Pure: the traffic windows ending on `day` over the `ok` days.
pub fn traffic_at(
    day: NaiveDate,
    rows: &[GrowthDaily],
    ok_days: &HashSet<String>,
) -> GithubTraffic {
    let (d, d7, d28) = (
        day_str(day),
        day_str(day - Duration::days(6)),
        day_str(day - Duration::days(27)),
    );
    let mut sums: HashMap<&str, Figure> = HashMap::new();
    for r in rows.iter().filter(|r| {
        r.dims.get("by").map(String::as_str) == Some("traffic") && ok_days.contains(&r.day)
    }) {
        let f = sums.entry(r.metric.as_str()).or_default();
        if r.day == d {
            f.day += r.value;
        }
        if r.day >= d7 && r.day <= d {
            f.d7 += r.value;
        }
        if r.day >= d28 && r.day <= d {
            f.d28 += r.value;
        }
    }
    let fig = |m: &str| sums.get(m).copied().unwrap_or_default();
    let mut measured_days = Figure::default();
    for ok in ok_days {
        if *ok == d {
            measured_days.day += 1;
        }
        if *ok >= d7 && *ok <= d {
            measured_days.d7 += 1;
        }
        if *ok >= d28 && *ok <= d {
            measured_days.d28 += 1;
        }
    }
    // The newest ranking on or before the day.
    let as_of = rows
        .iter()
        .filter(|r| r.dims.get("by").map(String::as_str) == Some("referrer") && r.day <= d)
        .map(|r| r.day.clone())
        .max();
    let mut by: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    if let Some(as_of) = &as_of {
        for r in rows
            .iter()
            .filter(|r| r.dims.get("by").map(String::as_str) == Some("referrer") && r.day == *as_of)
        {
            if let Some(name) = r.dims.get("referrer") {
                let e = by.entry(name.clone()).or_insert((0, 0));
                match r.metric.as_str() {
                    "referrer_views" => e.0 += r.value,
                    "referrer_uniques" => e.1 += r.value,
                    _ => {}
                }
            }
        }
    }
    let mut referrers: Vec<ReferrerRow> = by
        .into_iter()
        .map(|(referrer, (views, uniques))| ReferrerRow {
            referrer,
            views,
            uniques,
        })
        .collect();
    referrers.sort_by(|a, b| {
        b.views
            .cmp(&a.views)
            .then_with(|| a.referrer.cmp(&b.referrer))
    });
    referrers.truncate(TOP_ROWS);
    GithubTraffic {
        views: fig("views"),
        views_uniques: fig("views_uniques"),
        clones: fig("clones"),
        clones_uniques: fig("clones_uniques"),
        measured_days,
        referrers,
        referrers_as_of: as_of,
    }
}

/// What [`read`] found for one source.
struct Read {
    rows: Vec<GrowthDaily>,
    /// The days whose pull is `ok`.
    ok: HashSet<String>,
    /// The `ok` days whose last good pull hit the client's page bound.
    truncated: HashSet<String>,
}

/// The rows of one `(source, repo)` and breakdowns for
/// `from <= day <= to`, and the days whose pull is `ok`.
async fn read(
    state: &AppState,
    source: &str,
    bys: &[&str],
    repo: &str,
    from: &str,
    to: &str,
) -> Result<Read, DigestError> {
    let dao = GrowthDao::new(&state.db);
    let mut rows = Vec::new();
    for by in bys {
        rows.extend(dao.read_daily_by(source, by, from, to).await?);
    }
    rows.retain(|r| r.dims.get("repo").map(String::as_str) == Some(repo));
    let (mut ok, mut truncated) = (HashSet::new(), HashSet::new());
    for p in dao.pulls_between(source, from, to).await? {
        if p.status == PullStatus::Ok {
            if p.truncated {
                truncated.insert(p.day.clone());
            }
            ok.insert(p.day);
        }
    }
    Ok(Read {
        rows,
        ok,
        truncated,
    })
}

fn not_pulled(state: &AppState, what: &str) -> NotMeasured {
    if mounted(state, "saas") {
        NotMeasured::now(what.to_string())
    } else {
        NotMeasured::now("saas module not mounted (the GitHub puller runs there)")
    }
}

/// The `github` section for the closed day `day`, from the stored rows.
pub async fn section(state: &AppState, day: NaiveDate) -> Result<GithubSection, DigestError> {
    let g = &state.settings.growth;
    let Some(repo) = g.github_repo() else {
        fn none<T>() -> Measured<T> {
            Measured::NotMeasured(NotMeasured::now(
                "no repository configured (MESHHARBOR__GROWTH__GITHUB_REPO)",
            ))
        }
        return Ok(GithubSection {
            counters: none(),
            traffic: none(),
        });
    };
    // A 28-day delta at the oldest snapshot the lookback allows reaches
    // 28 days behind it.
    let from = day_str(day - Duration::days(SNAPSHOT_LOOKBACK_DAYS + 28));
    let to = day_str(day);
    let r = read(
        state,
        GITHUB_SOURCE,
        &["repo", "release", "flavour"],
        repo,
        &from,
        &to,
    )
    .await?;
    let counters = match counters_at(repo, day, &snapshots(&r.rows, &r.ok, &r.truncated)) {
        Some(c) => Measured::Value(c),
        None => Measured::NotMeasured(not_pulled(
            state,
            &format!(
                "no GitHub snapshot in the {} days to {}",
                SNAPSHOT_LOOKBACK_DAYS + 1,
                day_str(day)
            ),
        )),
    };
    let t_from = day_str(day - Duration::days(27));
    // The referrer ranking may be up to 14 days older than the window's
    // newest ok day; reading the 28 days covers it.
    let t = read(
        state,
        GITHUB_TRAFFIC_SOURCE,
        &["traffic", "referrer"],
        repo,
        &t_from,
        &to,
    )
    .await?;
    let traffic = if t.ok.is_empty() {
        Measured::NotMeasured(if g.github_traffic_configured() {
            not_pulled(
                state,
                &format!(
                    "no GitHub traffic pulled in the 28 days to {}",
                    day_str(day)
                ),
            )
        } else {
            NotMeasured::now("no GitHub token configured (MESHHARBOR__GROWTH__GITHUB_TOKEN)")
        })
    } else {
        Measured::Value(traffic_at(day, &t.rows, &t.ok))
    };
    Ok(GithubSection { counters, traffic })
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_services::dao::growth::daily_row;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn row(day: &str, by: &str, key: Option<(&str, &str)>, metric: &str, v: i64) -> GrowthDaily {
        let mut dims = BTreeMap::new();
        dims.insert("by".to_string(), by.to_string());
        dims.insert("repo".to_string(), "o/r".to_string());
        if let Some((k, val)) = key {
            dims.insert(k.to_string(), val.to_string());
        }
        daily_row(GITHUB_SOURCE, metric, dims, day, v)
    }

    fn snap(day: &str, stars: i64, releases: &[(&str, i64)]) -> Vec<GrowthDaily> {
        let mut out = vec![row(day, "repo", None, "stars", stars)];
        let total: i64 = releases.iter().map(|(_, n)| n).sum();
        out.push(row(day, "repo", None, "downloads", total));
        for (tag, n) in releases {
            out.push(row(day, "release", Some(("release", tag)), "downloads", *n));
        }
        out
    }

    fn ok(days: &[&str]) -> HashSet<String> {
        days.iter().map(|s| s.to_string()).collect()
    }

    /// Consecutive snapshots difference into a day; a 7-day delta needs
    /// only its two ends; a missing end is null, never 0 and never split.
    #[test]
    fn a_delta_is_two_snapshots_or_null() {
        let mut rows = Vec::new();
        rows.extend(snap("2026-10-09", 100, &[("v1", 50)]));
        // 10-10 … 10-14 missing: a gap.
        rows.extend(snap("2026-10-15", 104, &[("v1", 60)]));
        rows.extend(snap("2026-10-16", 105, &[("v1", 61), ("v2", 4)]));
        let none = HashSet::new();
        let snaps = snapshots(
            &rows,
            &ok(&["2026-10-09", "2026-10-15", "2026-10-16"]),
            &none,
        );
        let c = counters_at("o/r", d("2026-10-16"), &snaps).unwrap();
        assert_eq!(c.at, "2026-10-16");
        assert_eq!(c.stars, 105);
        assert_eq!(c.stars_delta.day, Some(1));
        assert_eq!(c.stars_delta.d7, Some(5), "10-16 vs 10-09: both ends exist");
        assert_eq!(c.stars_delta.d28, None, "no snapshot 28 days before");
        // Downloads: v1 +1, the new v2 counts fully.
        assert_eq!(c.downloads_delta.day, Some(5));
        assert_eq!(c.downloads_delta.d7, Some(15));
        // The day after the gap has no day delta.
        let c15 = counters_at("o/r", d("2026-10-15"), &snaps).unwrap();
        assert_eq!(
            c15.stars_delta.day, None,
            "10-14 is missing: null, not split"
        );
        // A day with no snapshot reads the latest one before it.
        let later = counters_at("o/r", d("2026-10-18"), &snaps).unwrap();
        assert_eq!(later.at, "2026-10-16");
        // Past the lookback: nothing.
        assert!(counters_at("o/r", d("2026-10-30"), &snaps).is_none());
        // A row of a day whose pull is not ok is not a snapshot.
        let not_ok = snapshots(&rows, &ok(&["2026-10-16"]), &none);
        assert_eq!(not_ok.len(), 1);

        // A listing that hit the page bound: its downloads are a lower bound,
        // every downloads change that needs it is null, the stars are not.
        let cut = snapshots(
            &rows,
            &ok(&["2026-10-09", "2026-10-15", "2026-10-16"]),
            &ok(&["2026-10-09"]),
        );
        let c = counters_at("o/r", d("2026-10-16"), &cut).unwrap();
        assert!(!c.downloads_truncated, "10-16's own listing was whole");
        assert_eq!(c.downloads_delta.day, Some(5), "10-15 and 10-16 are whole");
        assert_eq!(c.downloads_delta.d7, None, "10-09 is a lower bound");
        assert_eq!(c.stars_delta.d7, Some(5), "the stars are whole");
        assert!(
            matches!(&c.top_releases_7d, Measured::NotMeasured(n)
                if n.not_measured.contains("2026-10-09 hit the page bound")),
            "{:?}",
            c.top_releases_7d
        );
        let at9 = counters_at("o/r", d("2026-10-09"), &cut).unwrap();
        assert!(at9.downloads_truncated);
        assert_eq!(at9.downloads, 50, "shown, as a lower bound");

        // A helper release (CI's vendored build) is differenced apart and
        // never reaches the product's downloads.
        let helper = |day: &str, n: i64| {
            let mut dims = BTreeMap::new();
            dims.insert("by".to_string(), "release".to_string());
            dims.insert("repo".to_string(), "o/r".to_string());
            dims.insert("release".to_string(), "vendored-ffmpeg-n7.1".to_string());
            dims.insert("kind".to_string(), "helper".to_string());
            daily_row(GITHUB_SOURCE, "downloads", dims, day, n)
        };
        let mut with_helper = rows.clone();
        with_helper.push(helper("2026-10-15", 1000));
        with_helper.push(helper("2026-10-16", 1300));
        let snaps = snapshots(
            &with_helper,
            &ok(&["2026-10-09", "2026-10-15", "2026-10-16"]),
            &none,
        );
        let c = counters_at("o/r", d("2026-10-16"), &snaps).unwrap();
        assert_eq!(c.downloads_delta.day, Some(5), "the product alone");
        assert_eq!(c.helper_downloads_delta.day, Some(300));
        assert_eq!(c.helper_downloads_delta.d7, Some(1300), "new since 10-09");
    }

    /// A total that went down (an asset re-uploaded) counts nothing — the
    /// release's other assets cannot be told from the restart — a release
    /// that vanished counts nothing, and a new one counts fully.
    #[test]
    fn a_total_that_went_down_counts_nothing() {
        let earlier: BTreeMap<String, i64> = [
            ("a".into(), 10),
            ("b".into(), 7),
            ("gone".into(), 40),
            // CI's seed cache: 28 assets, six clobbered on one save.
            ("seed-cache".into(), 5_000),
        ]
        .into();
        let later: BTreeMap<String, i64> = [
            ("a".into(), 12),
            ("b".into(), 3),
            ("new".into(), 5),
            ("seed-cache".into(), 3_900),
        ]
        .into();
        let per = per_key_downloads(&later, &earlier);
        assert_eq!(per["a"], 2);
        assert_eq!(
            per["b"], 0,
            "went down: an under-count, never the new total"
        );
        assert_eq!(
            per["seed-cache"], 0,
            "not the 3,900 the clobbered release now holds"
        );
        assert_eq!(per["new"], 5);
        assert!(!per.contains_key("gone"));
        // The top list drops the zeros and sorts by count.
        let t = top(per);
        assert_eq!(
            t.iter().map(|k| k.key.as_str()).collect::<Vec<_>>(),
            ["new", "a"]
        );
    }

    /// Traffic sums the `ok` days of each window and says how many those
    /// are; the referrers are the newest ranking on or before the day.
    #[test]
    fn traffic_sums_only_the_measured_days() {
        let t = |day: &str, metric: &str, v: i64| {
            let mut dims = BTreeMap::new();
            dims.insert("by".to_string(), "traffic".to_string());
            dims.insert("repo".to_string(), "o/r".to_string());
            daily_row(GITHUB_TRAFFIC_SOURCE, metric, dims, day, v)
        };
        let r = |day: &str, name: &str, metric: &str, v: i64| {
            let mut dims = BTreeMap::new();
            dims.insert("by".to_string(), "referrer".to_string());
            dims.insert("repo".to_string(), "o/r".to_string());
            dims.insert("referrer".to_string(), name.to_string());
            daily_row(GITHUB_TRAFFIC_SOURCE, metric, dims, day, v)
        };
        let rows = vec![
            t("2026-10-16", "views", 10),
            t("2026-10-15", "views", 5),
            t("2026-10-01", "views", 3),
            // Stored, but its pull is not ok: not summed.
            t("2026-10-14", "views", 99),
            r("2026-10-15", "Google", "referrer_views", 4),
            r("2026-10-16", "Google", "referrer_views", 6),
            r("2026-10-16", "github.com", "referrer_views", 8),
            r("2026-10-16", "github.com", "referrer_uniques", 2),
        ];
        let days = ok(&["2026-10-16", "2026-10-15", "2026-10-01"]);
        let tr = traffic_at(d("2026-10-16"), &rows, &days);
        assert_eq!(
            tr.views,
            Figure {
                day: 10,
                d7: 15,
                d28: 18
            }
        );
        assert_eq!(
            tr.measured_days,
            Figure {
                day: 1,
                d7: 2,
                d28: 3
            }
        );
        assert_eq!(tr.referrers_as_of.as_deref(), Some("2026-10-16"));
        assert_eq!(tr.referrers[0].referrer, "github.com");
        assert_eq!(tr.referrers[0].uniques, 2);
        assert_eq!(tr.referrers[1].views, 6, "the newest ranking only");
        let older = traffic_at(d("2026-10-15"), &rows, &days);
        assert_eq!(older.referrers_as_of.as_deref(), Some("2026-10-15"));
    }
}
