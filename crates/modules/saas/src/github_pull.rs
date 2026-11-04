// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the GitHub puller (spec §3k): the repository's public
//! counters, and with a token its traffic, frozen daily into `growth_daily`
//! with one `growth_pulls` row per `(source, day)`.
//!
//! It is `saas`'s because it talks to the outside world for the hosted
//! business, and no self-host profile compiles `saas` (spec principle 6).
//! Without a repository it pulls nothing and says so once.
//!
//! # The public counters — `source: github`, no token
//!
//! Stars, forks and watchers come from `GET /repos/{repo}`; every release
//! asset's `download_count` from `GET /repos/{repo}/releases`, paged 100 at
//! a time. They are **cumulative**, so the puller stores a SNAPSHOT per
//! closed UTC day and the reader differences consecutive snapshots:
//!
//! | `dims.by` | other dims | metrics |
//! |---|---|---|
//! | `repo` | `repo` | `stars` `forks` `watchers`; `downloads` (every asset but the sidecars of every published PRODUCT release) and `helper_downloads` (the rest) |
//! | `release` | `repo`, `release` (the tag), `kind` (`product` · `helper`) | `downloads` |
//! | `flavour` | `repo`, `flavour` (a product asset's name without its version: `meshharbord-x86_64-pc-windows-msvc.msi`) | `downloads` |
//!
//! A **helper** release is one our own CI downloads from — vendored builds
//! and caches ([`PRODUCT_TAG_PREFIXES`] names the product's): on
//! 2026-10-17 they held 8,032 of the repository's 16,740 downloads, so they
//! are counted apart rather than mixed into the product's number.
//!
//! * **A snapshot is the close of a day.** Day D's snapshot is the counters
//!   as read in the cycle that follows it, between [`CYCLE_HOUR_UTC`] and
//!   [`SNAPSHOT_GRACE_HOURS`] later — so two consecutive snapshots are 24 h
//!   apart give or take the grace. A cumulative counter cannot be read for
//!   the past: a day not read inside its window has no snapshot, and every
//!   delta across it is null (the reader's rule — never split, never 0).
//! * **The first good read of the window stands**: a day pulled `ok` is not
//!   re-read later in the window, which would move its snapshot's time.
//! * Drafts are left out (their assets are not public). A zero is not
//!   stored: on an `ok` day a missing release or flavour row is a zero.
//! * **Sidecars are not downloads** ([`is_sidecar`]): the updater fetches a
//!   package's `.asc` beside the package itself, so counting the `.asc`
//!   and `.sha256` files would count every update twice.
//! * **A listing past [`MAX_RELEASE_PAGES`] is a lower bound.** The pull
//!   row says `truncated`, and the reader refuses every downloads change
//!   that needs that snapshot.
//! * ⚠️ GitHub counts every download of a release asset, **the fleet's
//!   self-updates included** — the updater fetches the MSI/.deb/.pkg from
//!   GitHub directly, hosted and self-hosted devices alike, and the
//!   installer proxy fetches from GitHub on each request. A download is
//!   distribution, not an install. Nothing here tells one deployment from
//!   another: it is GitHub's own public aggregate.
//!
//! # Traffic — `source: github_traffic`, with the token
//!
//! GitHub keeps 14 days of it, so it is pulled daily: views and clones per
//! day (`by: traffic`, `views` `views_uniques` `clones` `clones_uniques`),
//! re-pulled once per cycle for the last [`TRAFFIC_HORIZON_DAYS`] closed
//! days and frozen after; and the referrers (`by: referrer`,
//! `referrer_views` `referrer_uniques`), which GitHub answers only as a
//! 14-day ranking — stored under the closed day it was read after, and
//! labelled as such by every reader. Without a token none of it is read
//! and the readers say "not measured".
//!
//! **The token rides the traffic requests only.** The counters are public;
//! a token that expired, was revoked or was sealed wrong must cost the
//! traffic and never the day's snapshot, which no later read can recover.
//!
//! # Rate
//!
//! The counters are read without a token, from the 60 requests an hour
//! GitHub allows an unauthenticated address — which the releases cache
//! (`fleet::releases`, the updater's source of truth) draws on too. A cycle
//! is one request plus one per hundred releases (8 pages on 2026-10-17);
//! the listing stops, and the snapshot is retried next tick, rather than
//! spend the hour's last [`RATE_RESERVE`] requests.

use std::collections::BTreeMap;

use bson::DateTime;
use chrono::Duration;
use meshharbor_config::GrowthSettings;
use meshharbor_services::dao::{
    base::DaoResult,
    growth::{
        GITHUB_SOURCE, GITHUB_TRAFFIC_SOURCE, GrowthDaily, GrowthDao, GrowthPull, PullStatus,
        PulledDay, daily_row,
    },
};
use meshharbor_core::Core;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{info, warn};

use crate::pull_schedule::{self, date_of, day_str};

/// The `source` of the counters' rows.
pub const SOURCE: &str = GITHUB_SOURCE;
/// The `source` of the traffic rows.
pub const TRAFFIC_SOURCE: &str = GITHUB_TRAFFIC_SOURCE;
/// The UTC hour a cycle starts — GitHub's day is UTC.
pub const CYCLE_HOUR_UTC: u32 = 1;
/// A day's snapshot may be read from the cycle's start until this many
/// hours after it; later, the day has no snapshot.
pub const SNAPSHOT_GRACE_HOURS: i64 = 6;
/// Traffic days re-pulled each cycle. GitHub answers 14 daily buckets: a
/// read on 2026-10-17 ended at the previous UTC day, and one that also
/// carries today's partial bucket ends a day later. The last 13 closed days
/// are inside either, so a day outside GitHub's window is never read as a
/// quiet one.
pub const TRAFFIC_HORIZON_DAYS: i64 = 13;
/// The scheduler's cadence — also how soon a failed read is retried.
pub const LOOP_INTERVAL_SECS: u64 = 60 * 60;
/// A pod that just booted waits this long before its first tick.
pub const FIRST_TICK_DELAY_SECS: u64 = 5 * 60;
/// Releases per page (GitHub's maximum).
pub const PER_PAGE: usize = 100;
/// Pages followed before the answer is called truncated: 3,000 releases.
/// 732 existed on 2026-10-17, and 50 to 240 are cut a month.
pub const MAX_RELEASE_PAGES: u32 = 30;
/// The unauthenticated requests of the hour the counters leave untouched
/// (GitHub's `X-RateLimit-Remaining`): the releases cache the updater
/// relies on reads from the same address.
pub const RATE_RESERVE: u32 = 10;
/// Per-request ceiling.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// The largest answer read: a page of 100 releases measured 4.96 MB.
pub const MAX_BODY_BYTES: usize = 32 << 20;
/// The counters' metrics — the set a snapshot replaces.
pub const COUNTER_METRICS: [&str; 5] = [
    "stars",
    "forks",
    "watchers",
    "downloads",
    "helper_downloads",
];
/// The traffic series' metrics.
pub const TRAFFIC_METRICS: [&str; 4] = ["views", "views_uniques", "clones", "clones_uniques"];
/// The referrer ranking's metrics, stored under the day it was read after.
pub const REFERRER_METRICS: [&str; 2] = ["referrer_views", "referrer_uniques"];
/// A stored flavour, release or referrer is cut to this many characters.
pub const MAX_DIM_LEN: usize = 120;

// ── The wire ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RepoInfo {
    #[serde(default)]
    pub stargazers_count: i64,
    #[serde(default)]
    pub forks_count: i64,
    /// GitHub's "watchers" (`watchers_count` is the stars, kept for history).
    #[serde(default)]
    pub subscribers_count: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ReleaseAsset {
    pub name: String,
    #[serde(default)]
    pub download_count: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TrafficDay {
    /// `2026-10-14T00:00:00Z` — the UTC day the bucket counts.
    pub timestamp: String,
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub uniques: i64,
}

/// `GET …/traffic/views?per=day` (`views`) or `…/clones?per=day` (`clones`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct TrafficSeries {
    #[serde(default)]
    pub views: Vec<TrafficDay>,
    #[serde(default)]
    pub clones: Vec<TrafficDay>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Referrer {
    pub referrer: String,
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub uniques: i64,
}

/// Why a read gave nothing. `Display` is the short reason a pull row
/// stores; none carries the token or a body.
#[derive(Debug, Clone, PartialEq)]
pub enum GithubError {
    /// 401: the token is wrong or expired.
    Unauthorized,
    /// 403 with the token: it lacks the permission (traffic needs
    /// "Administration: read"), or the rate limit is spent.
    Forbidden(String),
    /// 404: no such repository (or a private one the token cannot see).
    NotFound,
    /// Any other non-2xx.
    Status(u16, String),
    Timeout,
    Transport(String),
    Decode(String),
    /// An answer past [`MAX_BODY_BYTES`].
    TooLarge,
    /// The hour's unauthenticated requests are down to this many: the
    /// listing stops short of [`RATE_RESERVE`] and the day is retried.
    RateReserve(u32),
}

impl std::fmt::Display for GithubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "github unreachable: unauthorized (401)"),
            Self::Forbidden(m) => write!(f, "github unreachable: forbidden (403) {m}"),
            Self::NotFound => write!(f, "github unreachable: no such repository (404)"),
            Self::Status(c, m) => write!(f, "github unreachable: HTTP {c} {m}"),
            Self::Timeout => write!(f, "github unreachable: timed out"),
            Self::Transport(e) => write!(f, "github unreachable: {e}"),
            Self::Decode(e) => write!(f, "github unreachable: unreadable answer ({e})"),
            Self::TooLarge => write!(
                f,
                "github unreachable: answer larger than {} MiB",
                MAX_BODY_BYTES >> 20
            ),
            Self::RateReserve(left) => write!(
                f,
                "github rate limit nearly spent ({left} requests left this hour); retried next tick"
            ),
        }
    }
}

impl From<crate::capped::BodyError> for GithubError {
    fn from(e: crate::capped::BodyError) -> Self {
        match e {
            crate::capped::BodyError::TooLarge(_) => Self::TooLarge,
            crate::capped::BodyError::Timeout => Self::Timeout,
            crate::capped::BodyError::Transport(t) => Self::Transport(short(&t)),
        }
    }
}

impl GithubError {
    /// Whether a later request of the same run could succeed. A wrong
    /// token, a missing permission, a missing repository, an unreachable
    /// host or a spent rate limit will not fix itself between two requests.
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Self::Status(..) | Self::Decode(_) | Self::TooLarge)
    }
}

/// Bound a server-supplied string before it lands in a stored reason.
fn short(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect::<String>()
}

#[derive(Clone)]
pub struct GithubClient {
    base: String,
    repo: String,
    token: Option<String>,
    http: reqwest::Client,
    /// [`MAX_RELEASE_PAGES`]; a test lowers it with [`Self::with_max_pages`].
    max_pages: u32,
}

impl std::fmt::Debug for GithubClient {
    /// No token, ever.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubClient")
            .field("base", &self.base)
            .field("repo", &self.repo)
            .field("token", &self.token.as_ref().map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

impl GithubClient {
    /// `None` without a plausible `owner/name` — nothing is ever asked.
    pub fn from_settings(g: &GrowthSettings) -> Option<Self> {
        let repo = g.github_repo()?.to_string();
        let token = Some(g.github_token.trim().to_string()).filter(|t| !t.is_empty());
        let http = reqwest::Client::builder()
            .user_agent(concat!("meshharbor-api/", env!("CARGO_PKG_VERSION")))
            .timeout(TIMEOUT)
            .build()
            .ok()?;
        Some(Self {
            base: g.github_api_url.trim_end_matches('/').to_string(),
            repo,
            token,
            http,
            max_pages: MAX_RELEASE_PAGES,
        })
    }

    /// The same client with another page bound — a test's way to reach it.
    pub fn with_max_pages(mut self, pages: u32) -> Self {
        self.max_pages = pages.max(1);
        self
    }

    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Whether traffic can be read.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// One GET, and GitHub's `X-RateLimit-Remaining` with it. The token is
    /// sent only when `with_token` (the traffic): the public counters never
    /// carry it, so a bad token cannot cost a snapshot.
    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        with_token: bool,
    ) -> Result<(T, Option<u32>), GithubError> {
        let mut req = self
            .http
            .get(format!("{}/repos/{}{path}", self.base, self.repo))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if with_token && let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let sent = req.send().await.map_err(|e| {
            if e.is_timeout() {
                GithubError::Timeout
            } else {
                GithubError::Transport(short(&e.without_url().to_string()))
            }
        })?;
        let status = sent.status().as_u16();
        let remaining = sent
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u32>().ok());
        let body = crate::capped::read_capped(sent, MAX_BODY_BYTES).await?;
        if !(200..300).contains(&status) {
            let msg = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(short))
                .unwrap_or_default();
            return Err(match status {
                401 => GithubError::Unauthorized,
                403 | 429 => GithubError::Forbidden(msg),
                404 => GithubError::NotFound,
                _ => GithubError::Status(status, msg),
            });
        }
        let value = serde_json::from_slice::<T>(&body)
            .map_err(|e| GithubError::Decode(short(&e.to_string())))?;
        Ok((value, remaining))
    }

    /// The repository's public counters, and the hour's remaining requests.
    pub async fn repo_info(&self) -> Result<(RepoInfo, Option<u32>), GithubError> {
        self.get("", false).await
    }

    /// Every release, page by page; `true` when the page bound cut the list
    /// short. `remaining` is what the request before the first page left:
    /// no page is asked while GitHub says fewer than [`RATE_RESERVE`]
    /// requests are left this hour.
    pub async fn releases(
        &self,
        mut remaining: Option<u32>,
    ) -> Result<(Vec<Release>, bool), GithubError> {
        let mut out = Vec::new();
        for page in 1..=self.max_pages {
            if let Some(left) = remaining.filter(|n| *n < RATE_RESERVE) {
                return Err(GithubError::RateReserve(left));
            }
            let (batch, left): (Vec<Release>, _) = self
                .get(&format!("/releases?per_page={PER_PAGE}&page={page}"), false)
                .await?;
            remaining = left;
            let n = batch.len();
            out.extend(batch);
            if n < PER_PAGE {
                return Ok((out, false));
            }
        }
        Ok((out, true))
    }

    pub async fn views(&self) -> Result<TrafficSeries, GithubError> {
        Ok(self.get("/traffic/views?per=day", true).await?.0)
    }

    pub async fn clones(&self) -> Result<TrafficSeries, GithubError> {
        Ok(self.get("/traffic/clones?per=day", true).await?.0)
    }

    pub async fn referrers(&self) -> Result<Vec<Referrer>, GithubError> {
        Ok(self.get("/traffic/popular/referrers", true).await?.0)
    }
}

// ── Shaping ──────────────────────────────────────────────────────────────

type Dims = BTreeMap<String, String>;

fn dims(pairs: &[(&str, &str)]) -> Dims {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A dimension value as stored: control characters dropped, trimmed, cut
/// to [`MAX_DIM_LEN`]; `None` when nothing is left.
pub fn clean_dim(raw: &str) -> Option<String> {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_DIM_LEN)
        .collect();
    (!s.is_empty()).then_some(s)
}

/// A version token at `i`: `\d+(\.\d+){2}` with an optional `-rc.N`,
/// `-alpha.N` or `-beta.N`; its byte length, when there is one.
fn version_len(s: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    for part in 0..3 {
        let start = j;
        while j < s.len() && s[j].is_ascii_digit() {
            j += 1;
        }
        if j == start {
            return None;
        }
        if part < 2 {
            if j >= s.len() || s[j] != b'.' {
                return None;
            }
            j += 1;
        }
    }
    for pre in [&b"-rc."[..], b"-alpha.", b"-beta."] {
        if s[j..].starts_with(pre) {
            let k = j + pre.len();
            let mut e = k;
            while e < s.len() && s[e].is_ascii_digit() {
                e += 1;
            }
            if e > k {
                j = e;
            }
            break;
        }
    }
    Some(j - i)
}

/// An asset's FLAVOUR: its name without the version, so the same artifact
/// of every release groups together — `meshharbord-0.4.140-x86_64-pc-windows-msvc.msi`
/// is `meshharbord-x86_64-pc-windows-msvc.msi`, `meshharbord_0.4.140_amd64.deb` is
/// `meshharbord_amd64.deb`. The FIRST version token preceded by `-`, `_` or a
/// `v` after one of them is removed together with that separator; a name
/// without one is its own flavour.
pub fn flavour(asset: &str) -> String {
    let b = asset.as_bytes();
    for i in 1..b.len() {
        let sep = b[i - 1];
        let (cut_from, at) = if matches!(sep, b'-' | b'_') {
            if b[i] == b'v' {
                (i - 1, i + 1)
            } else {
                (i - 1, i)
            }
        } else {
            continue;
        };
        if at < b.len()
            && let Some(n) = version_len(b, at)
        {
            let mut out = String::with_capacity(asset.len());
            out.push_str(&asset[..cut_from]);
            out.push_str(&asset[at + n..]);
            return out;
        }
    }
    asset.to_string()
}

/// The tags of the product's own releases — what a person installs or the
/// fleet updates to: the daemon, the setup wizard, the tunnel CLI and its
/// retired wizard. Every other release is a HELPER: vendored builds and
/// caches our own CI downloads (`vendored-ffmpeg-*`, `vendored-libvpx-*`,
/// `seed-cache-*`). Measured 2026-10-17 on the live repository, helpers held
/// 8,032 of 16,740 downloads — a product total that included them would be
/// half CI.
pub const PRODUCT_TAG_PREFIXES: [&str; 4] = ["agent-v", "setup-v", "tunnel-v", "tunnel-wizard-v"];

/// Whether a release is the product's (see [`PRODUCT_TAG_PREFIXES`]).
pub fn is_product_release(tag: &str) -> bool {
    PRODUCT_TAG_PREFIXES.iter().any(|p| tag.starts_with(p))
}

/// The endings of a SIDECAR: a signature or checksum fetched beside the
/// asset it describes (`meshharbord-0.4.140-x86_64-unknown-linux-gnu.deb.asc`,
/// `….deb.sha256`), or the release key itself (`meshharbor-release-pubkey.asc`).
pub const SIDECAR_SUFFIXES: [&str; 4] = [".asc", ".sig", ".sha256", ".sha512"];

/// Whether an asset is a sidecar (see [`SIDECAR_SUFFIXES`]). The updater
/// fetches a package's `.asc` with the package, so a sidecar counted as a
/// download would count every update twice; none is counted.
pub fn is_sidecar(asset: &str) -> bool {
    let lower = asset.to_ascii_lowercase();
    SIDECAR_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// The counters' rows for the snapshot of `day`. Drafts and sidecars are
/// left out; a zero is not stored. The product's releases and the helpers
/// are kept apart: `downloads` counts the product only, `helper_downloads`
/// the rest, each release row says which it is (`kind`), and the flavours
/// are the product's.
pub fn counter_rows(
    day: &str,
    repo: &str,
    info: &RepoInfo,
    releases: &[Release],
) -> Vec<GrowthDaily> {
    let mut by_release: BTreeMap<String, (bool, i64)> = BTreeMap::new();
    let mut by_flavour: BTreeMap<String, i64> = BTreeMap::new();
    let (mut product, mut helper) = (0i64, 0i64);
    for r in releases.iter().filter(|r| !r.draft) {
        let Some(tag) = clean_dim(&r.tag_name) else {
            continue;
        };
        let is_product = is_product_release(&tag);
        for a in r.assets.iter().filter(|a| !is_sidecar(&a.name)) {
            let n = a.download_count.max(0);
            if is_product {
                product += n;
                if let Some(f) = clean_dim(&flavour(&a.name)) {
                    *by_flavour.entry(f).or_insert(0) += n;
                }
            } else {
                helper += n;
            }
            by_release.entry(tag.clone()).or_insert((is_product, 0)).1 += n;
        }
    }
    let repo_dims = dims(&[("by", "repo"), ("repo", repo)]);
    let mut rows = Vec::new();
    for (metric, value) in [
        ("stars", info.stargazers_count),
        ("forks", info.forks_count),
        ("watchers", info.subscribers_count),
        ("downloads", product),
        ("helper_downloads", helper),
    ] {
        if value != 0 {
            rows.push(daily_row(SOURCE, metric, repo_dims.clone(), day, value));
        }
    }
    for (tag, (is_product, n)) in by_release {
        if n != 0 {
            let kind = if is_product { "product" } else { "helper" };
            let d = dims(&[
                ("by", "release"),
                ("repo", repo),
                ("release", tag.as_str()),
                ("kind", kind),
            ]);
            rows.push(daily_row(SOURCE, "downloads", d, day, n));
        }
    }
    for (f, n) in by_flavour {
        if n != 0 {
            let d = dims(&[("by", "flavour"), ("repo", repo), ("flavour", f.as_str())]);
            rows.push(daily_row(SOURCE, "downloads", d, day, n));
        }
    }
    rows
}

/// The traffic rows of `day` from the two series: GitHub's bucket whose
/// timestamp falls on that UTC day, zeros not stored.
pub fn traffic_rows(
    day: &str,
    repo: &str,
    views: &TrafficSeries,
    clones: &TrafficSeries,
) -> Vec<GrowthDaily> {
    let on = |series: &[TrafficDay]| {
        series
            .iter()
            .find(|t| t.timestamp.get(..10) == Some(day))
            .map(|t| (t.count.max(0), t.uniques.max(0)))
            .unwrap_or((0, 0))
    };
    let (v, vu) = on(&views.views);
    let (c, cu) = on(&clones.clones);
    let d = dims(&[("by", "traffic"), ("repo", repo)]);
    [
        ("views", v),
        ("views_uniques", vu),
        ("clones", c),
        ("clones_uniques", cu),
    ]
    .into_iter()
    .filter(|(_, n)| *n != 0)
    .map(|(m, n)| daily_row(TRAFFIC_SOURCE, m, d.clone(), day, n))
    .collect()
}

/// The referrer ranking's rows, stored under `day` — the closed day it was
/// read after. Referrers that fold into one cleaned name are summed.
pub fn referrer_rows(day: &str, repo: &str, referrers: &[Referrer]) -> Vec<GrowthDaily> {
    let mut by: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for r in referrers {
        if let Some(name) = clean_dim(&r.referrer) {
            let e = by.entry(name).or_insert((0, 0));
            e.0 += r.count.max(0);
            e.1 += r.uniques.max(0);
        }
    }
    let mut rows = Vec::new();
    for (name, (views, uniques)) in by {
        let d = dims(&[
            ("by", "referrer"),
            ("repo", repo),
            ("referrer", name.as_str()),
        ]);
        if views != 0 {
            rows.push(daily_row(
                TRAFFIC_SOURCE,
                "referrer_views",
                d.clone(),
                day,
                views,
            ));
        }
        if uniques != 0 {
            rows.push(daily_row(
                TRAFFIC_SOURCE,
                "referrer_uniques",
                d,
                day,
                uniques,
            ));
        }
    }
    rows
}

// ── When ─────────────────────────────────────────────────────────────────

/// Whether a tick at `now` owes yesterday's snapshot: inside the window
/// that starts at the cycle's hour and lasts [`SNAPSHOT_GRACE_HOURS`], and
/// only while yesterday has no `ok` snapshot (the first good read stands).
pub fn snapshot_due(now: DateTime, yesterday_pull: Option<&GrowthPull>) -> bool {
    let start = pull_schedule::cycle_start_ms(now, CYCLE_HOUR_UTC);
    let t = now.timestamp_millis();
    let in_window = t >= start && t < start + SNAPSHOT_GRACE_HOURS * 3_600_000;
    in_window && yesterday_pull.is_none_or(|p| p.status != PullStatus::Ok)
}

// ── A run ────────────────────────────────────────────────────────────────

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PullReport {
    /// Whether yesterday's snapshot was owed, and how it went.
    pub snapshot_due: bool,
    pub snapshot_ok: bool,
    /// The traffic days owed, oldest first.
    pub traffic_due: Vec<String>,
    pub traffic_pulled: u32,
    pub rows_written: u64,
    pub rows_pruned: u64,
    /// The first error met, as stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

async fn snapshot(
    client: &GithubClient,
    day: &str,
) -> Result<(Vec<GrowthDaily>, bool), GithubError> {
    let (info, remaining) = client.repo_info().await?;
    let (releases, truncated) = client.releases(remaining).await?;
    Ok((
        counter_rows(day, client.repo(), &info, &releases),
        truncated,
    ))
}

/// One run at `now`. Public so a test drives it with an injected `now` and
/// a client pointed at a fake server; the scheduler is [`spawn_puller`]. A
/// database error stops the run (the next tick retries); a GitHub error is
/// recorded per day and is never a 0.
pub async fn run_once(core: &Core, client: &GithubClient, now: DateTime) -> DaoResult<PullReport> {
    let dao = GrowthDao::new(&core.db);
    let today = date_of(now);
    let yesterday = day_str(today - Duration::days(1));
    let mut report = PullReport::default();

    // The counters: yesterday's snapshot, inside its window, once.
    let prior = dao.pulls_between(SOURCE, &yesterday, &yesterday).await?;
    if snapshot_due(now, prior.first()) {
        report.snapshot_due = true;
        match snapshot(client, &yesterday).await {
            Ok((rows, truncated)) => {
                let c = dao
                    .replace_daily(SOURCE, &yesterday, &COUNTER_METRICS, &rows)
                    .await?;
                dao.record_pull_ok(
                    SOURCE,
                    &yesterday,
                    PulledDay {
                        rows: rows.len() as u32,
                        missing_goal: None,
                        truncated,
                    },
                    now,
                )
                .await?;
                if truncated {
                    warn!(day = %yesterday, pages = client.max_pages, "github pull: the release list hit the page bound; its downloads are a lower bound and the reader refuses their changes");
                }
                report.snapshot_ok = true;
                report.rows_written += c.written;
                report.rows_pruned += c.pruned;
            }
            Err(e) => {
                let reason = e.to_string();
                dao.record_pull_failed(SOURCE, &yesterday, &reason, now)
                    .await?;
                report.error.get_or_insert(reason);
            }
        }
    }

    // Traffic: the token's, re-pulled once per cycle inside the horizon.
    if client.has_token() {
        let from = day_str(today - Duration::days(TRAFFIC_HORIZON_DAYS));
        let pulls = dao.pulls_between(TRAFFIC_SOURCE, &from, &yesterday).await?;
        let due = pull_schedule::due_days(
            now,
            &pulls,
            CYCLE_HOUR_UTC,
            TRAFFIC_HORIZON_DAYS,
            TRAFFIC_HORIZON_DAYS,
        );
        report.traffic_due = due.iter().map(|d| day_str(*d)).collect();
        if !due.is_empty() {
            let read = async {
                Ok::<_, GithubError>((
                    client.views().await?,
                    client.clones().await?,
                    client.referrers().await?,
                ))
            }
            .await;
            match read {
                Ok((views, clones, referrers)) => {
                    for d in &report.traffic_due {
                        let mut rows = traffic_rows(d, client.repo(), &views, &clones);
                        let mut metrics: Vec<&str> = TRAFFIC_METRICS.to_vec();
                        // The ranking belongs to the latest closed day only.
                        if *d == yesterday {
                            rows.extend(referrer_rows(d, client.repo(), &referrers));
                            metrics.extend(REFERRER_METRICS);
                        }
                        let c = dao
                            .replace_daily(TRAFFIC_SOURCE, d, &metrics, &rows)
                            .await?;
                        dao.record_pull_ok(
                            TRAFFIC_SOURCE,
                            d,
                            PulledDay {
                                rows: rows.len() as u32,
                                missing_goal: None,
                                truncated: false,
                            },
                            now,
                        )
                        .await?;
                        report.traffic_pulled += 1;
                        report.rows_written += c.written;
                        report.rows_pruned += c.pruned;
                    }
                }
                Err(e) => {
                    let reason = e.to_string();
                    for d in &report.traffic_due {
                        dao.record_pull_failed(TRAFFIC_SOURCE, d, &reason, now)
                            .await?;
                    }
                    report.error.get_or_insert(reason);
                }
            }
        }
    }
    Ok(report)
}

/// The scheduler: every [`LOOP_INTERVAL_SECS`] one pod (the Redis claim)
/// runs [`run_once`]. Only with `growth.enabled` and a repository — with
/// none it logs that once and starts nothing.
pub fn spawn_puller(core: Core) {
    let growth = &core.settings.growth;
    if !growth.enabled {
        return;
    }
    let Some(client) = GithubClient::from_settings(growth) else {
        info!(
            "growth github puller: no repository configured (MESHHARBOR__GROWTH__GITHUB_REPO) — nothing is pulled"
        );
        return;
    };
    info!(
        repo = client.repo(),
        traffic = client.has_token(),
        "growth github puller starting"
    );
    pull_schedule::spawn_hourly(
        core,
        "growth-github-pull",
        FIRST_TICK_DELAY_SECS,
        LOOP_INTERVAL_SECS,
        move |core| {
            let client = client.clone();
            async move {
                match run_once(&core, &client, DateTime::now()).await {
                    Ok(r) if r.snapshot_due || !r.traffic_due.is_empty() => info!(
                        snapshot_ok = r.snapshot_ok,
                        traffic_pulled = r.traffic_pulled,
                        rows_written = r.rows_written,
                        error = r.error.as_deref().unwrap_or(""),
                        "growth github pull"
                    ),
                    Ok(_) => {}
                    Err(e) => warn!(%e, "growth github pull failed"),
                }
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime {
        DateTime::parse_rfc3339_str(s).unwrap()
    }

    fn value(
        rows: &[GrowthDaily],
        by: &str,
        key: Option<(&str, &str)>,
        metric: &str,
    ) -> Option<i64> {
        rows.iter()
            .find(|r| {
                r.metric == metric
                    && r.dims.get("by").map(String::as_str) == Some(by)
                    && key.is_none_or(|(k, v)| r.dims.get(k).map(String::as_str) == Some(v))
            })
            .map(|r| r.value)
    }

    /// The same artifact of every release groups under one flavour; the
    /// version goes with the separator before it.
    #[test]
    fn a_flavour_is_the_asset_name_without_its_version() {
        for (name, want) in [
            (
                "meshharbord-0.4.140-x86_64-pc-windows-msvc.msi",
                "meshharbord-x86_64-pc-windows-msvc.msi",
            ),
            (
                "meshharbord-0.4.140-x86_64-pc-windows-msvc.msi.asc",
                "meshharbord-x86_64-pc-windows-msvc.msi.asc",
            ),
            ("meshharbord_0.4.140_amd64.deb", "meshharbord_amd64.deb"),
            (
                "meshharbor-setup-0.4.139-universal-apple-darwin.tar.gz",
                "meshharbor-setup-universal-apple-darwin.tar.gz",
            ),
            (
                "meshharbord-0.3.0-rc.480-x86_64-unknown-linux-gnu.deb",
                "meshharbord-x86_64-unknown-linux-gnu.deb",
            ),
            ("meshharbor-v0.4.7.zip", "meshharbor.zip"),
            ("SHA256SUMS", "SHA256SUMS"),
            ("ffmpeg-n7.1-win64.zip", "ffmpeg-n7.1-win64.zip"),
        ] {
            assert_eq!(flavour(name), want, "{name}");
        }
    }

    /// A snapshot: the repo's counters, downloads summed per release and per
    /// flavour, drafts and sidecars left out, zeros not stored, and every
    /// row its own id.
    #[test]
    fn a_snapshot_sums_downloads_per_release_and_flavour_without_drafts() {
        let info = RepoInfo {
            stargazers_count: 120,
            forks_count: 9,
            subscribers_count: 0,
        };
        let asset = |name: &str, n: i64| ReleaseAsset {
            name: name.into(),
            download_count: n,
        };
        let releases = vec![
            Release {
                tag_name: "agent-v0.4.140".into(),
                draft: false,
                assets: vec![
                    asset("meshharbord-0.4.140-x86_64-pc-windows-msvc.msi", 30),
                    // Sidecars: fetched beside the package, never a download.
                    asset("meshharbord-0.4.140-x86_64-pc-windows-msvc.msi.asc", 25),
                    asset("meshharbord-0.4.140-x86_64-pc-windows-msvc.msi.sha256", 4),
                    asset("meshharbor-release-pubkey.asc", 3),
                    asset("meshharbord_0.4.140_amd64.deb", 0),
                ],
            },
            Release {
                tag_name: "agent-v0.4.139".into(),
                draft: false,
                assets: vec![asset("meshharbord-0.4.139-x86_64-pc-windows-msvc.msi", 70)],
            },
            Release {
                tag_name: "agent-v0.4.141".into(),
                draft: true,
                assets: vec![asset("meshharbord-0.4.141-x86_64-pc-windows-msvc.msi", 999)],
            },
            // A helper: a vendored build our CI downloads.
            Release {
                tag_name: "vendored-ffmpeg-n7.1".into(),
                draft: false,
                assets: vec![asset("ffmpeg-linux64-lgpl-shared-minimal.tar.xz", 4000)],
            },
        ];
        let rows = counter_rows("2026-10-16", "jk-zhang-meta/MeshHarbor", &info, &releases);
        // The helper is counted apart: its own total, its release row marked,
        // no flavour of the product's.
        assert_eq!(value(&rows, "repo", None, "helper_downloads"), Some(4000));
        assert_eq!(
            value(&rows, "release", Some(("kind", "helper")), "downloads"),
            Some(4000)
        );
        assert_eq!(
            value(
                &rows,
                "release",
                Some(("release", "agent-v0.4.139")),
                "downloads"
            ),
            Some(70)
        );
        assert!(
            rows.iter()
                .filter(|r| r.dims.get("by").map(String::as_str) == Some("flavour"))
                .all(|r| !r.dims["flavour"].starts_with("ffmpeg")),
            "a helper's assets are no product flavour"
        );
        assert!(is_product_release("setup-v0.4.139") && is_product_release("tunnel-wizard-v0.3.0"));
        assert!(
            !is_product_release("seed-cache-2026") && !is_product_release("vendored-libvpx-1.15")
        );
        assert_eq!(value(&rows, "repo", None, "stars"), Some(120));
        assert_eq!(value(&rows, "repo", None, "forks"), Some(9));
        assert_eq!(
            value(&rows, "repo", None, "watchers"),
            None,
            "a zero is not stored"
        );
        assert_eq!(
            value(&rows, "repo", None, "downloads"),
            Some(100),
            "the draft and the sidecars are out"
        );
        assert_eq!(
            value(
                &rows,
                "release",
                Some(("release", "agent-v0.4.140")),
                "downloads"
            ),
            Some(30)
        );
        assert!(
            rows.iter()
                .filter(|r| r.dims.get("by").map(String::as_str) == Some("flavour"))
                .all(|r| !r.dims["flavour"].ends_with(".asc")
                    && !r.dims["flavour"].ends_with(".sha256")),
            "no sidecar flavour"
        );
        assert!(is_sidecar(
            "meshharbord-0.4.140-x86_64-unknown-linux-gnu.deb.ASC"
        ));
        assert!(!is_sidecar("meshharbord-0.4.140-x86_64-unknown-linux-gnu.deb"));
        assert_eq!(
            value(
                &rows,
                "release",
                Some(("release", "agent-v0.4.141")),
                "downloads"
            ),
            None
        );
        assert_eq!(
            value(
                &rows,
                "flavour",
                Some(("flavour", "meshharbord-x86_64-pc-windows-msvc.msi")),
                "downloads"
            ),
            Some(100),
            "the MSI of both releases, one flavour"
        );
        assert_eq!(
            value(
                &rows,
                "flavour",
                Some(("flavour", "meshharbord_amd64.deb")),
                "downloads"
            ),
            None
        );
        assert!(
            rows.iter()
                .all(|r| r.source == SOURCE && r.day == "2026-10-16")
        );
        assert!(
            rows.iter()
                .all(|r| r.dims.get("repo").map(String::as_str) == Some("jk-zhang-meta/MeshHarbor"))
        );
        let ids: std::collections::HashSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), rows.len());
    }

    /// Traffic: the bucket of the day, by its UTC date; the referrers summed
    /// per cleaned name; zeros not stored.
    #[test]
    fn traffic_and_referrers_shape_into_rows() {
        let views: TrafficSeries = serde_json::from_str(
            r#"{"count":30,"uniques":9,"views":[
                {"timestamp":"2026-10-15T00:00:00Z","count":12,"uniques":4},
                {"timestamp":"2026-10-16T00:00:00Z","count":18,"uniques":5}]}"#,
        )
        .unwrap();
        let clones: TrafficSeries = serde_json::from_str(
            r#"{"count":2,"uniques":1,"clones":[
                {"timestamp":"2026-10-16T00:00:00Z","count":2,"uniques":1}]}"#,
        )
        .unwrap();
        let rows = traffic_rows("2026-10-16", "o/r", &views, &clones);
        assert_eq!(value(&rows, "traffic", None, "views"), Some(18));
        assert_eq!(value(&rows, "traffic", None, "views_uniques"), Some(5));
        assert_eq!(value(&rows, "traffic", None, "clones"), Some(2));
        let quiet = traffic_rows("2026-10-15", "o/r", &views, &clones);
        assert_eq!(
            value(&quiet, "traffic", None, "clones"),
            None,
            "no bucket: a zero"
        );
        assert_eq!(value(&quiet, "traffic", None, "views"), Some(12));

        let refs: Vec<Referrer> = serde_json::from_str(
            r#"[{"referrer":"Google","count":4,"uniques":3},
                {"referrer":"news.ycombinator.com","count":10,"uniques":8},
                {"referrer":" Google\u0000","count":1,"uniques":1}]"#,
        )
        .unwrap();
        let rows = referrer_rows("2026-10-16", "o/r", &refs);
        assert_eq!(
            value(
                &rows,
                "referrer",
                Some(("referrer", "Google")),
                "referrer_views"
            ),
            Some(5)
        );
        assert_eq!(
            value(
                &rows,
                "referrer",
                Some(("referrer", "news.ycombinator.com")),
                "referrer_uniques"
            ),
            Some(8)
        );
        assert!(rows.iter().all(|r| r.source == TRAFFIC_SOURCE));
    }

    /// The snapshot window: from the cycle's hour for the grace, and only
    /// while yesterday has no good snapshot.
    #[test]
    fn a_snapshot_is_owed_only_inside_its_window_and_only_once() {
        let pull = |status: PullStatus| GrowthPull {
            id: GrowthPull::id_of(SOURCE, "2026-10-16"),
            source: SOURCE.into(),
            day: "2026-10-16".into(),
            status,
            pulled_at: None,
            attempted_at: at("2026-10-17T01:05:00Z"),
            attempts: 1,
            rows: 0,
            error: None,
            missing_goal: None,
            truncated: false,
        };
        assert!(
            !snapshot_due(at("2026-10-17T00:59:59Z"), None),
            "before the cycle"
        );
        assert!(snapshot_due(at("2026-10-17T01:00:00Z"), None));
        assert!(snapshot_due(at("2026-10-17T06:59:59Z"), None));
        assert!(
            !snapshot_due(at("2026-10-17T07:00:00Z"), None),
            "past the grace"
        );
        assert!(snapshot_due(
            at("2026-10-17T02:00:00Z"),
            Some(&pull(PullStatus::Failed))
        ));
        assert!(!snapshot_due(
            at("2026-10-17T02:00:00Z"),
            Some(&pull(PullStatus::Ok))
        ));
    }

    #[test]
    fn errors_read_as_short_reasons_and_the_client_never_prints_its_token() {
        assert_eq!(
            GithubError::Unauthorized.to_string(),
            "github unreachable: unauthorized (401)"
        );
        assert!(GithubError::NotFound.is_fatal());
        assert!(!GithubError::Status(502, "bad gateway".into()).is_fatal());
        assert!(GithubError::RateReserve(4).is_fatal());
        assert_eq!(
            GithubError::RateReserve(4).to_string(),
            "github rate limit nearly spent (4 requests left this hour); retried next tick"
        );
        assert_eq!(
            GithubError::from(crate::capped::BodyError::TooLarge(1)).to_string(),
            "github unreachable: answer larger than 32 MiB"
        );
        let g = GrowthSettings {
            github_token: "ghp_secret_value".into(),
            ..Default::default()
        };
        let c = GithubClient::from_settings(&g).unwrap();
        assert!(c.has_token());
        let shown = format!("{c:?}");
        assert!(!shown.contains("ghp_secret_value"), "{shown}");
        let none = GrowthSettings {
            github_repo: "not-a-repo".into(),
            ..Default::default()
        };
        assert!(GithubClient::from_settings(&none).is_none());
    }
}
