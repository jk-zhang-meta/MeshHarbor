// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P8 — `GET /api/admin/growth/channels?since&until&include_internal`:
//! per platform and per post published in the range, the platform's own
//! numbers beside what the post's campaign key brought (spec §3j).
//!
//! * **Reach is the platform's own**: each post's metric snapshots as the
//!   promotion pipeline pushed them (`growth_posts`,
//!   `growth_post_snapshots`), raw metric names, never renamed or summed
//!   into another metric — a metric is only comparable to itself. A
//!   platform's reach is summed PER SNAPSHOT AGE (`T+1d`, `T+7d`, `T+28d`),
//!   over the posts that have that snapshot, so a three-day-old post is
//!   never added to a month-old one.
//! * **Then the key**: visitors (purestat, live for the range — the same
//!   breakdown as the Campaigns table, at the post's own depth) → sign-ups
//!   → activated → first value → paid (P2's funnel, paid from P4) by the
//!   post's normalised key.
//! * **Spend**: an optional `cost_cents` per post gives cost per visitor and
//!   per sign-up — each with its n, a value only from n = 30.
//! * **Three cells**: a platform with no post pushed in the range is
//!   `not_measured` (and says when the ingest routes are not even mounted);
//!   a post with no snapshot yet has reach `not_measured`; a purestat outage
//!   makes the web cells `not_measured`, never 0.
//!
//! A platform's visitors and sign-ups are SUMS over its posts' distinct
//! keys — an upper bound on unique visitors, since one visitor who
//! followed two posts counts twice; each post's own row is exact.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    Json,
    extract::{Query as AxumQuery, State},
};
use bson::DateTime;
use chrono::NaiveDate;
use meshharbor_services::dao::{
    growth_digest::ExcludedCounts,
    growth_social::{GrowthPost, GrowthSocialDao, MAX_POSTS, PostSnapshot, SNAPSHOTS},
};
use meshharbor_core::{
    campaign::{CampaignKey, KeyDepth, PLATFORMS, platform_retired},
    growth::ExclusionSet,
};
use serde::{Deserialize, Serialize};

use super::{
    campaigns::{
        Rate, Rates, WebBreakdown, WebCells, account_by_key, blank_counts, day_range_ms, range,
        step_rate, web_breakdown, web_client,
    },
    digest::{Measured, NotMeasured, SMALL_N, day_str, utc_date_of},
    funnel::{self, GroupCounts, StepCounts},
    mounted,
    read_key::GrowthAuth,
};
use crate::{error::ApiError, state::AppState};

/// The platform's own numbers at one snapshot age, summed over the posts
/// that have that snapshot — raw metric names, a metric only ever added to
/// itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReachAt {
    /// `T+1d` · `T+7d` · `T+28d`.
    pub snapshot: String,
    /// How many posts the sums rest on.
    pub posts: u32,
    pub metrics: BTreeMap<String, f64>,
}

/// One platform's reach for a campaign key (the Campaigns table's column).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformReach {
    pub platform: String,
    /// The posts with this key on this platform.
    pub posts: u32,
    pub at: Vec<ReachAt>,
}

/// One snapshot as pushed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotOut {
    pub snapshot: String,
    /// RFC 3339.
    pub taken_at: String,
    pub metrics: BTreeMap<String, f64>,
}

/// A cost per unit with the n it rests on: `cents` only from n = 30.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CostRate {
    pub n: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cents: Option<f64>,
}

/// What posts cost, against what they brought.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Spend {
    pub cost_cents: i64,
    pub posts_with_cost: u32,
    /// Over the visitors of the posts that declared a cost; `None` when the
    /// web plane is not measured.
    pub per_visitor: Option<CostRate>,
    /// Over the sign-ups of the posts that declared a cost.
    pub per_signup: CostRate,
}

/// One post, everything it brought.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostRow {
    pub platform: String,
    pub platform_id: String,
    /// The account it was posted from — a handle of ours, never a person.
    pub account: String,
    pub format: String,
    pub url: String,
    /// RFC 3339.
    pub published_at: String,
    /// The normalised key its link carries — client-chosen text.
    pub key: CampaignKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_cents: Option<i64>,
    /// Every snapshot pushed, youngest first.
    pub snapshots: Vec<SnapshotOut>,
    /// The oldest snapshot pushed so far — the platform's latest word.
    pub reach: Measured<SnapshotOut>,
    pub web: Measured<WebCells>,
    pub signups: u64,
    pub org_created: StepCounts,
    pub activated: Option<StepCounts>,
    pub first_value: Option<StepCounts>,
    /// P4 — `null` without `saas`.
    pub paid: Option<StepCounts>,
    pub rates: Rates,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend: Option<Spend>,
}

/// A platform's posts, summed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformSummary {
    pub posts: u32,
    pub reach: Measured<Vec<ReachAt>>,
    /// Σ over the posts' distinct keys (an upper bound on unique visitors).
    pub web: Measured<WebCells>,
    pub signups: u64,
    pub org_created: StepCounts,
    pub activated: Option<StepCounts>,
    pub first_value: Option<StepCounts>,
    /// P4 — `null` without `saas`.
    pub paid: Option<StepCounts>,
    pub rates: Rates,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend: Option<Spend>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformRow {
    pub platform: String,
    /// No longer posted to; listed only when it has data in the range.
    pub retired: bool,
    /// `not_measured` when no post was pushed for it in the range.
    pub summary: Measured<PlatformSummary>,
    pub posts: Vec<PostRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelsReport {
    pub enabled: bool,
    pub since: String,
    pub until: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub n_floor: i64,
    /// Whether this server mounts the ingest routes (`saas`) — without them
    /// no new post arrives, whatever is already stored.
    pub ingest_mounted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_not_measured: Option<NotMeasured>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversions: Option<NotMeasured>,
    pub web_truncated: bool,
    pub account_truncated: bool,
    /// More posts in the range than one read loads: the oldest only.
    pub posts_truncated: bool,
    pub value_basis: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub not_measured: BTreeMap<String, String>,
    pub platforms: Vec<PlatformRow>,
}

/// The posts published in a window, and their snapshots.
pub(crate) struct Social {
    pub(crate) posts: Vec<GrowthPost>,
    pub(crate) snapshots: Vec<PostSnapshot>,
    pub(crate) truncated: bool,
}

/// The posts published in `[start_ms, end_ms)` and every snapshot of them.
pub(crate) async fn read_posts(
    state: &AppState,
    start_ms: i64,
    end_ms: i64,
) -> Result<Social, ApiError> {
    let dao = GrowthSocialDao::new(&state.db);
    let posts = dao
        .posts_published_between(
            DateTime::from_millis(start_ms),
            DateTime::from_millis(end_ms),
        )
        .await?;
    let snapshots = dao.snapshots_of(&posts).await?;
    Ok(Social {
        truncated: posts.len() as i64 >= MAX_POSTS,
        posts,
        snapshots,
    })
}

/// Why a key (or a platform) has no reach: no post at all on a server that
/// does not mount the ingest routes, or no post with it in the range.
pub(crate) fn no_reach_reason(state: &AppState, social: &Social) -> NotMeasured {
    if social.posts.is_empty() && !mounted(state, "saas") {
        NotMeasured::now(
            "no posts pushed — the ingest routes are not mounted on this server (saas module)",
        )
    } else {
        NotMeasured::now("no post pushed with this key in the range")
    }
}

/// A post's normalised key.
pub fn post_key(p: &GrowthPost) -> CampaignKey {
    CampaignKey {
        source: p.key.source.clone(),
        medium: p.key.medium.clone(),
        campaign: p.key.campaign.clone(),
        content: p.key.content.clone(),
    }
}

/// The depth a post's key is matched at: its own — `content` when its link
/// carried one, else `campaign` (the ingest requires a campaign).
pub fn post_depth(k: &CampaignKey) -> KeyDepth {
    if k.content.is_some() {
        KeyDepth::Content
    } else {
        KeyDepth::Campaign
    }
}

fn label_rank(snapshot: &str) -> usize {
    SNAPSHOTS
        .iter()
        .position(|s| *s == snapshot)
        .unwrap_or(usize::MAX)
}

/// Snapshots summed per age, youngest age first.
pub fn reach_at(snaps: &[&PostSnapshot]) -> Vec<ReachAt> {
    let mut by: BTreeMap<usize, ReachAt> = BTreeMap::new();
    for s in snaps {
        let slot = by
            .entry(label_rank(&s.snapshot))
            .or_insert_with(|| ReachAt {
                snapshot: s.snapshot.clone(),
                posts: 0,
                metrics: BTreeMap::new(),
            });
        slot.posts += 1;
        for (name, v) in &s.metrics {
            *slot.metrics.entry(name.clone()).or_insert(0.0) += v;
        }
    }
    by.into_values().collect()
}

fn snapshots_of<'a>(p: &GrowthPost, all: &'a [PostSnapshot]) -> Vec<&'a PostSnapshot> {
    let mut out: Vec<&PostSnapshot> = all
        .iter()
        .filter(|s| s.platform == p.platform && s.platform_id == p.platform_id)
        .collect();
    out.sort_by_key(|s| label_rank(&s.snapshot));
    out
}

/// The Campaigns table's reach column: per key at `depth`, per platform,
/// the posts with that key and their snapshots summed per age.
pub fn reach_by_key(
    posts: &[GrowthPost],
    snapshots: &[PostSnapshot],
    depth: KeyDepth,
) -> BTreeMap<CampaignKey, Vec<PlatformReach>> {
    let mut grouped: BTreeMap<CampaignKey, BTreeMap<String, Vec<&GrowthPost>>> = BTreeMap::new();
    for p in posts {
        grouped
            .entry(post_key(p).at_depth(depth))
            .or_default()
            .entry(p.platform.clone())
            .or_default()
            .push(p);
    }
    grouped
        .into_iter()
        .map(|(key, by_platform)| {
            let reach = by_platform
                .into_iter()
                .map(|(platform, ps)| {
                    let snaps: Vec<&PostSnapshot> =
                        ps.iter().flat_map(|p| snapshots_of(p, snapshots)).collect();
                    PlatformReach {
                        platform,
                        posts: ps.len() as u32,
                        at: reach_at(&snaps),
                    }
                })
                .collect();
            (key, reach)
        })
        .collect()
}

/// A cost per unit: `cents` from n = 30, to the cent.
pub fn cost_rate(cost_cents: i64, n: i64) -> CostRate {
    CostRate {
        n,
        cents: (n >= SMALL_N).then(|| (cost_cents as f64 / n as f64 * 100.0).round() / 100.0),
    }
}

fn add_steps(a: StepCounts, b: StepCounts) -> StepCounts {
    StepCounts {
        count: a.count + b.count,
        pending: a.pending + b.pending,
        settled: a.settled + b.settled,
    }
}

fn add_groups(acc: &mut GroupCounts, g: &GroupCounts) {
    acc.signups += g.signups;
    acc.org_created = add_steps(acc.org_created, g.org_created);
    acc.activated = acc.activated.zip(g.activated).map(|(a, b)| add_steps(a, b));
    acc.first_value = acc
        .first_value
        .zip(g.first_value)
        .map(|(a, b)| add_steps(a, b));
    acc.paid = acc.paid.zip(g.paid).map(|(a, b)| add_steps(a, b));
}

fn add_cells(acc: &mut WebCells, w: &WebCells) {
    acc.visitors += w.visitors;
    acc.visits += w.visits;
    acc.pageviews += w.pageviews;
    acc.reads += w.reads;
    acc.spellings += w.spellings;
    acc.goals = match (&acc.goals, &w.goals) {
        (Measured::Value(a), Measured::Value(b)) => Measured::Value(super::digest::CampaignGoals {
            signup: a.signup + b.signup,
            subscribe: a.subscribe + b.subscribe,
            install_copy: a.install_copy + b.install_copy,
            github_outbound: a.github_outbound + b.github_outbound,
        }),
        (Measured::NotMeasured(n), _) | (_, Measured::NotMeasured(n)) => {
            Measured::NotMeasured(n.clone())
        }
    };
}

/// Everything the join reads — pure, so it is tested without a server.
pub struct Assemble<'a> {
    pub posts: &'a [GrowthPost],
    pub snapshots: &'a [PostSnapshot],
    /// purestat at depth `campaign` and `content`, or the reason.
    pub web_campaign: &'a Result<BTreeMap<CampaignKey, WebCells>, NotMeasured>,
    pub web_content: &'a Result<BTreeMap<CampaignKey, WebCells>, NotMeasured>,
    pub conversions: &'a Option<NotMeasured>,
    /// The funnel grouped at depth `campaign` and `content`.
    pub account_campaign: &'a BTreeMap<Option<CampaignKey>, GroupCounts>,
    pub account_content: &'a BTreeMap<Option<CampaignKey>, GroupCounts>,
    pub blank: &'a GroupCounts,
    /// Why a platform without posts is not measured.
    pub no_posts: &'a NotMeasured,
}

/// One post's numbers by its key at its own depth.
struct Brought {
    key: CampaignKey,
    web: Measured<WebCells>,
    acc: GroupCounts,
}

fn brought(a: &Assemble<'_>, p: &GrowthPost) -> Brought {
    let key = post_key(p);
    let (web_map, acc_map) = match post_depth(&key) {
        KeyDepth::Content => (a.web_content, a.account_content),
        _ => (a.web_campaign, a.account_campaign),
    };
    let web = match web_map {
        Ok(m) => Measured::Value(
            m.get(&key)
                .cloned()
                .unwrap_or_else(|| WebCells::zero(true, a.conversions)),
        ),
        Err(n) => Measured::NotMeasured(n.clone()),
    };
    let acc = acc_map
        .get(&Some(key.clone()))
        .cloned()
        .unwrap_or_else(|| a.blank.clone());
    Brought { key, web, acc }
}

fn rates_of(web: &Measured<WebCells>, acc: &GroupCounts) -> Rates {
    Rates {
        signup_per_visitor: web
            .value()
            .map(|w| Rate::of(acc.signups as i64, w.visitors)),
        activation: step_rate(acc.activated),
        first_value: step_rate(acc.first_value),
        paid: step_rate(acc.paid),
    }
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

fn snapshot_out(s: &PostSnapshot) -> SnapshotOut {
    SnapshotOut {
        snapshot: s.snapshot.clone(),
        taken_at: rfc3339(s.taken_at),
        metrics: s.metrics.clone(),
    }
}

fn post_row(a: &Assemble<'_>, p: &GrowthPost) -> PostRow {
    let b = brought(a, p);
    let snaps = snapshots_of(p, a.snapshots);
    let reach = match snaps.last() {
        Some(s) => Measured::Value(snapshot_out(s)),
        None => Measured::NotMeasured(NotMeasured::now("no snapshot pushed yet")),
    };
    let spend = p.cost_cents.map(|cost| Spend {
        cost_cents: cost,
        posts_with_cost: 1,
        per_visitor: b.web.value().map(|w| cost_rate(cost, w.visitors)),
        per_signup: cost_rate(cost, b.acc.signups as i64),
    });
    PostRow {
        platform: p.platform.clone(),
        platform_id: p.platform_id.clone(),
        account: p.account.clone(),
        format: p.format.clone(),
        url: p.url.clone(),
        published_at: rfc3339(p.published_at),
        key: b.key,
        cost_cents: p.cost_cents,
        snapshots: snaps.iter().map(|s| snapshot_out(s)).collect(),
        reach,
        rates: rates_of(&b.web, &b.acc),
        web: b.web,
        signups: b.acc.signups,
        org_created: b.acc.org_created,
        activated: b.acc.activated,
        first_value: b.acc.first_value,
        paid: b.acc.paid,
        spend,
    }
}

fn summary(a: &Assemble<'_>, posts: &[&GrowthPost]) -> PlatformSummary {
    let snaps: Vec<&PostSnapshot> = posts
        .iter()
        .flat_map(|p| snapshots_of(p, a.snapshots))
        .collect();
    let reach = if snaps.is_empty() {
        Measured::NotMeasured(NotMeasured::now("no snapshot pushed yet"))
    } else {
        Measured::Value(reach_at(&snaps))
    };
    // Each distinct key once: two posts sharing a key share its visitors.
    let mut seen: BTreeSet<CampaignKey> = BTreeSet::new();
    let mut web: Result<WebCells, NotMeasured> = Ok(WebCells::zero(true, a.conversions));
    let mut acc = a.blank.clone();
    // The same sums over the posts that declared a cost, for the spend.
    let mut costed_seen: BTreeSet<CampaignKey> = BTreeSet::new();
    let (mut cost, mut costed_posts, mut costed_visitors, mut costed_signups) =
        (0i64, 0u32, 0i64, 0i64);
    for p in posts {
        let b = brought(a, p);
        if let Some(c) = p.cost_cents {
            cost += c;
            costed_posts += 1;
            if costed_seen.insert(b.key.clone()) {
                costed_visitors += b.web.value().map(|w| w.visitors).unwrap_or(0);
                costed_signups += b.acc.signups as i64;
            }
        }
        if !seen.insert(b.key.clone()) {
            continue;
        }
        add_groups(&mut acc, &b.acc);
        match &b.web {
            Measured::Value(w) => {
                if let Ok(sum) = &mut web {
                    add_cells(sum, w);
                }
            }
            Measured::NotMeasured(n) => {
                if web.is_ok() {
                    web = Err(n.clone());
                }
            }
        }
    }
    let web = match web {
        Ok(w) => Measured::Value(w),
        Err(n) => Measured::NotMeasured(n),
    };
    let spend = (costed_posts > 0).then(|| Spend {
        cost_cents: cost,
        posts_with_cost: costed_posts,
        per_visitor: web.is_measured().then(|| cost_rate(cost, costed_visitors)),
        per_signup: cost_rate(cost, costed_signups),
    });
    PlatformSummary {
        posts: posts.len() as u32,
        reach,
        rates: rates_of(&web, &acc),
        web,
        signups: acc.signups,
        org_created: acc.org_created,
        activated: acc.activated,
        first_value: acc.first_value,
        paid: acc.paid,
        spend,
    }
}

/// The join, pure: every platform of the taxonomy (a retired one only with
/// data), its posts in publish order, each by its own key.
pub fn assemble(a: &Assemble<'_>) -> Vec<PlatformRow> {
    PLATFORMS
        .iter()
        .filter_map(|platform| {
            let posts: Vec<&GrowthPost> =
                a.posts.iter().filter(|p| p.platform == *platform).collect();
            let retired = platform_retired(platform);
            if posts.is_empty() && retired {
                return None;
            }
            let summary = if posts.is_empty() {
                Measured::NotMeasured(a.no_posts.clone())
            } else {
                Measured::Value(summary(a, &posts))
            };
            Some(PlatformRow {
                platform: platform.to_string(),
                retired,
                summary,
                posts: posts.iter().map(|p| post_row(a, p)).collect(),
            })
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct ChannelsQuery {
    /// `YYYY-MM-DD`, inclusive (posts published from that day).
    #[serde(default)]
    pub since: Option<String>,
    /// `YYYY-MM-DD`, inclusive. Default: yesterday (UTC).
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

fn empty_breakdown() -> WebBreakdown {
    WebBreakdown {
        by_key: Ok(BTreeMap::new()),
        conversions: None,
        truncated: false,
    }
}

/// `GET /api/admin/growth/channels?since&until&include_internal`
pub async fn get_channels(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    AxumQuery(q): AxumQuery<ChannelsQuery>,
) -> Result<Json<ChannelsReport>, ApiError> {
    let now = DateTime::now();
    let (since, until) = range(q.since.as_deref(), q.until.as_deref(), utc_date_of(now))
        .map_err(ApiError::BadRequest)?;
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    Ok(Json(
        compute(&state, &set, since, until, q.include_internal, now).await?,
    ))
}

/// The table for the closed days `[since, until]` (inclusive) at `now` —
/// what the route answers, and what P10's weekly roll-up stores for its
/// week.
pub async fn compute(
    state: &AppState,
    set: &ExclusionSet,
    since: NaiveDate,
    until: NaiveDate,
    include_internal: bool,
    now: DateTime,
) -> Result<ChannelsReport, ApiError> {
    let (start_ms, end_ms) = day_range_ms(since, until);
    let social = read_posts(state, start_ms, end_ms).await?;

    // The account plane, grouped at both depths a post's key can have.
    let read = funnel::read(
        state,
        set,
        DateTime::from_millis(start_ms),
        DateTime::from_millis(end_ms),
    )
    .await?;
    let facts = read.facts(now.timestamp_millis());
    let account_campaign = account_by_key(&facts, KeyDepth::Campaign);
    let account_content = account_by_key(&facts, KeyDepth::Content);
    let blank = blank_counts(&read);

    // The web plane, live — asked only when there is a post to join.
    let (since_s, until_s) = (day_str(since), day_str(until));
    let client = web_client(state);
    let web_campaign = if social.posts.is_empty() {
        empty_breakdown()
    } else {
        web_breakdown(&client, &since_s, &until_s, KeyDepth::Campaign).await
    };
    let web_content = if social.posts.iter().any(|p| p.key.content.is_some()) {
        web_breakdown(&client, &since_s, &until_s, KeyDepth::Content).await
    } else {
        empty_breakdown()
    };
    let conversions = web_campaign
        .conversions
        .clone()
        .or_else(|| web_content.conversions.clone());
    let no_posts = if mounted(state, "saas") {
        NotMeasured::now("no posts pushed for this platform in the range")
    } else {
        NotMeasured::now(
            "no posts pushed — the ingest routes are not mounted on this server (saas module)",
        )
    };
    let platforms = assemble(&Assemble {
        posts: &social.posts,
        snapshots: &social.snapshots,
        web_campaign: &web_campaign.by_key,
        web_content: &web_content.by_key,
        conversions: &conversions,
        account_campaign: &account_campaign,
        account_content: &account_content,
        blank: &blank,
        no_posts: &no_posts,
    });
    let web_not_measured = web_campaign
        .by_key
        .as_ref()
        .err()
        .or_else(|| web_content.by_key.as_ref().err())
        .cloned();
    let (users, tenants) = set.counts();
    Ok(ChannelsReport {
        enabled: true,
        since: since_s,
        until: until_s,
        include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        n_floor: SMALL_N,
        ingest_mounted: mounted(state, "saas"),
        web_not_measured,
        conversions,
        web_truncated: web_campaign.truncated || web_content.truncated,
        account_truncated: read.truncated,
        posts_truncated: social.truncated,
        value_basis: read.basis.clone(),
        not_measured: read.step_reasons(),
        platforms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_services::dao::growth_social::PostKey;

    fn at(s: &str) -> DateTime {
        DateTime::parse_rfc3339_str(s).unwrap()
    }

    fn post(
        platform: &str,
        id: &str,
        campaign: &str,
        content: Option<&str>,
        cost: Option<i64>,
    ) -> GrowthPost {
        GrowthPost {
            id: None,
            platform: platform.into(),
            platform_id: id.into(),
            account: "roomler-ai".into(),
            format: "post".into(),
            url: format!("https://{platform}.example/{id}"),
            published_at: at("2026-10-12T09:00:00Z"),
            key: PostKey {
                source: platform.into(),
                medium: Some("post".into()),
                campaign: Some(campaign.into()),
                content: content.map(str::to_string),
            },
            cost_cents: cost,
            created_at: at("2026-10-12T09:05:00Z"),
            updated_at: at("2026-10-12T09:05:00Z"),
        }
    }

    fn snap(platform: &str, id: &str, label: &str, metrics: &[(&str, f64)]) -> PostSnapshot {
        PostSnapshot {
            id: None,
            platform: platform.into(),
            platform_id: id.into(),
            snapshot: label.into(),
            taken_at: at("2026-10-13T09:00:00Z"),
            metrics: metrics.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            received_at: at("2026-10-13T09:01:00Z"),
        }
    }

    fn cells(visitors: i64) -> WebCells {
        let mut w = WebCells::zero(true, &None);
        w.visitors = visitors;
        w.visits = visitors;
        w.spellings = 1;
        w
    }

    fn group(signups: u64) -> GroupCounts {
        GroupCounts {
            signups,
            org_created: StepCounts {
                count: signups,
                pending: 0,
                settled: signups,
            },
            activated: Some(StepCounts {
                count: 0,
                pending: 0,
                settled: signups,
            }),
            first_value: Some(StepCounts {
                count: 0,
                pending: 0,
                settled: signups,
            }),
            paid: Some(StepCounts {
                count: signups.min(1),
                pending: 0,
                settled: signups,
            }),
        }
    }

    fn key(platform: &str, campaign: &str, content: Option<&str>) -> CampaignKey {
        CampaignKey::normalized(Some(platform), Some("post"), Some(campaign), content).unwrap()
    }

    /// A metric is only ever added to itself, and only at the same age.
    #[test]
    fn reach_sums_raw_metrics_per_snapshot_age() {
        let a = snap(
            "linkedin",
            "1",
            "T+7d",
            &[("impressions", 3000.0), ("clicks", 80.0)],
        );
        let b = snap("linkedin", "2", "T+7d", &[("impressions", 500.0)]);
        let c = snap(
            "linkedin",
            "1",
            "T+1d",
            &[("impressions", 1000.0), ("clicks", 50.0)],
        );
        let r = reach_at(&[&a, &b, &c]);
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].snapshot.as_str(), r[0].posts),
            ("T+1d", 1),
            "youngest first"
        );
        assert_eq!((r[1].snapshot.as_str(), r[1].posts), ("T+7d", 2));
        assert_eq!(r[1].metrics["impressions"], 3500.0);
        assert_eq!(r[1].metrics["clicks"], 80.0);
        assert!(reach_at(&[]).is_empty());
    }

    #[test]
    fn a_cost_per_unit_needs_its_n() {
        assert_eq!(
            cost_rate(5000, 55),
            CostRate {
                n: 55,
                cents: Some(90.91)
            }
        );
        assert_eq!(cost_rate(5000, 29), CostRate { n: 29, cents: None });
        assert_eq!(cost_rate(5000, 0).cents, None);
    }

    /// The join: every platform listed, the one without posts not measured;
    /// a post by its own depth's key; reach latest; spend with its n; the
    /// platform's sums over distinct keys.
    #[test]
    fn platforms_and_posts_join_reach_visits_signups_and_spend() {
        let posts = vec![
            post("linkedin", "1", "c1", None, Some(5000)),
            // A second LinkedIn post with the SAME key: counted once.
            post("linkedin", "2", "c1", None, None),
            post("youtube", "v1", "20261019-ssh", Some("desc-top"), None),
            post("instagram", "old", "c0", None, None),
        ];
        let snapshots = vec![
            snap("linkedin", "1", "T+1d", &[("impressions", 1000.0)]),
            snap("linkedin", "1", "T+7d", &[("impressions", 3000.0)]),
            snap("youtube", "v1", "T+1d", &[("views", 120.0)]),
        ];
        let web_campaign: Result<_, NotMeasured> = Ok([(key("linkedin", "c1", None), cells(55))]
            .into_iter()
            .collect());
        let web_content: Result<_, NotMeasured> = Ok([(
            key("youtube", "20261019-ssh", Some("desc-top")),
            cells(7),
        )]
        .into_iter()
        .collect());
        let account_campaign: BTreeMap<Option<CampaignKey>, GroupCounts> =
            [(Some(key("linkedin", "c1", None)), group(2))]
                .into_iter()
                .collect();
        let account_content = BTreeMap::new();
        let blank = group(0);
        let no_posts = NotMeasured::now("no posts pushed for this platform in the range");
        let rows = assemble(&Assemble {
            posts: &posts,
            snapshots: &snapshots,
            web_campaign: &web_campaign,
            web_content: &web_content,
            conversions: &None,
            account_campaign: &account_campaign,
            account_content: &account_content,
            blank: &blank,
            no_posts: &no_posts,
        });
        let names: Vec<&str> = rows.iter().map(|r| r.platform.as_str()).collect();
        assert_eq!(
            names,
            [
                "youtube",
                "x",
                "linkedin",
                "facebook",
                "tiktok",
                "instagram"
            ],
            "instagram listed because it has data"
        );
        let li = rows.iter().find(|r| r.platform == "linkedin").unwrap();
        let s = li.summary.value().unwrap();
        assert_eq!(s.posts, 2);
        assert_eq!(s.web.value().unwrap().visitors, 55, "the shared key once");
        assert_eq!(s.signups, 2);
        let reach = s.reach.value().unwrap();
        assert_eq!(reach.len(), 2);
        assert_eq!(reach[1].metrics["impressions"], 3000.0);
        let spend = s.spend.as_ref().unwrap();
        assert_eq!((spend.cost_cents, spend.posts_with_cost), (5000, 1));
        assert_eq!(
            spend.per_visitor,
            Some(CostRate {
                n: 55,
                cents: Some(90.91)
            })
        );
        assert_eq!(spend.per_signup, CostRate { n: 2, cents: None });
        // The post: its latest snapshot is its reach; both snapshots listed.
        let p1 = &li.posts[0];
        assert_eq!(p1.snapshots.len(), 2);
        assert_eq!(p1.reach.value().unwrap().snapshot, "T+7d");
        assert_eq!(p1.web.value().unwrap().visitors, 55);
        assert_eq!(p1.signups, 2);
        // P4 — the key's paid orgs (the fixture: one per non-empty group).
        assert_eq!(p1.paid.map(|p| p.count), Some(1));
        assert_eq!(s.paid.map(|p| p.count), Some(1), "the shared key once");
        // The second post has no snapshot: reach not measured, never 0.
        assert!(!li.posts[1].reach.is_measured());
        assert!(li.posts[1].spend.is_none());
        // YouTube's post matches at its own depth (content).
        let yt = rows.iter().find(|r| r.platform == "youtube").unwrap();
        assert_eq!(yt.posts[0].web.value().unwrap().visitors, 7);
        assert_eq!(yt.posts[0].signups, 0, "a measured zero");
        // A platform with nothing pushed: not measured, with the reason.
        let x = rows.iter().find(|r| r.platform == "x").unwrap();
        assert_eq!(
            serde_json::to_value(&x.summary).unwrap(),
            serde_json::json!({ "not_measured": "no posts pushed for this platform in the range" })
        );
        assert!(x.posts.is_empty());
        let ig = rows.iter().find(|r| r.platform == "instagram").unwrap();
        assert!(ig.retired);

        // The web plane down: web cells say why, the reach and the account
        // plane stand; spend per visitor is not computed.
        let down: Result<BTreeMap<CampaignKey, WebCells>, NotMeasured> =
            Err(NotMeasured::now("purestat unreachable: unauthorized (401)"));
        let rows = assemble(&Assemble {
            posts: &posts,
            snapshots: &snapshots,
            web_campaign: &down,
            web_content: &down,
            conversions: &None,
            account_campaign: &account_campaign,
            account_content: &account_content,
            blank: &blank,
            no_posts: &no_posts,
        });
        let li = rows.iter().find(|r| r.platform == "linkedin").unwrap();
        let s = li.summary.value().unwrap();
        assert!(!s.web.is_measured());
        assert!(s.reach.is_measured());
        assert_eq!(s.signups, 2);
        assert_eq!(s.spend.as_ref().unwrap().per_visitor, None);
        assert!(!li.posts[0].web.is_measured());

        // Without instagram data it is not listed at all.
        let rows = assemble(&Assemble {
            posts: &posts[..3],
            snapshots: &snapshots,
            web_campaign: &web_campaign,
            web_content: &web_content,
            conversions: &None,
            account_campaign: &account_campaign,
            account_content: &account_content,
            blank: &blank,
            no_posts: &no_posts,
        });
        assert!(rows.iter().all(|r| r.platform != "instagram"));
    }

    /// The Campaigns table's reach column groups posts by the key at the
    /// table's depth, then by platform.
    #[test]
    fn reach_by_key_groups_at_the_depth_then_by_platform() {
        let posts = vec![
            post("linkedin", "1", "c1", None, None),
            post("linkedin", "2", "c2", None, None),
            post("youtube", "v1", "c1", Some("desc-top"), None),
        ];
        let snapshots = vec![
            snap("linkedin", "1", "T+1d", &[("impressions", 1000.0)]),
            snap("linkedin", "2", "T+1d", &[("impressions", 10.0)]),
        ];
        let by_campaign = reach_by_key(&posts, &snapshots, KeyDepth::Campaign);
        let li1 = &by_campaign[&key("linkedin", "c1", None)];
        assert_eq!(li1.len(), 1);
        assert_eq!((li1[0].platform.as_str(), li1[0].posts), ("linkedin", 1));
        assert_eq!(li1[0].at[0].metrics["impressions"], 1000.0);
        let by_source = reach_by_key(&posts, &snapshots, KeyDepth::Source);
        let li = &by_source[&CampaignKey::normalized(Some("linkedin"), None, None, None).unwrap()];
        assert_eq!(li[0].posts, 2);
        assert_eq!(li[0].at[0].metrics["impressions"], 1010.0);
        // A post with no snapshot still counts as a post, with no ages.
        let yt = &by_campaign[&key("youtube", "c1", None)];
        assert_eq!((yt[0].posts, yt[0].at.len()), (1, 0));
    }
}
