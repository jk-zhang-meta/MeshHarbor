// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P6 — `GET /api/admin/growth/campaigns`: per campaign key, the
//! web plane beside the account plane, joined in code by the normalised key
//! and by counts — never by a person (spec §3a, §3i).
//!
//! * **The web plane is queried LIVE** from purestat for the exact range:
//!   unique visitors do not add across days, so the frozen daily rows the
//!   `saas` puller keeps cannot answer a range. At a depth
//!   (`by=source|medium|campaign|content`) a row is purestat's breakdown by
//!   exactly those UTM dimensions, so its visitors are purestat's own number
//!   for the key (AC16) — unless several raw spellings normalise into it
//!   (`YouTub`, `youtube`), when they are summed and `spellings` says so.
//! * **The account plane is P2's funnel** (`funnel::read` + `group_by`),
//!   grouped by the same normalised key ([`CampaignKey::normalized`], the
//!   rule a sign-up was cleaned by at ingress). The exclusion set applies
//!   to it; `include_internal=true` is the raw totals.
//! * **Measured, not measured and zero are three cells.** No key, a 401, a
//!   timeout or an unreachable purestat make every web cell
//!   `not_measured` with the reason — never 0; a key purestat answered for
//!   and saw no visitor of IS a zero. A step whose module is not mounted is
//!   `null` with the module named — `paid` (P4) included, which needs
//!   `saas`.
//! * **Reach** (P8) is each platform's own numbers for the posts published
//!   in the range with the key, as the promotion pipeline pushed them
//!   (`channels::reach_by_key`) — `not_measured` when no such post exists.
//! * **Every rate carries its n**; below [`SMALL_N`] it has no value.
//!
//! ⚠️ Every key field is client-chosen text: render it as TEXT.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Query as AxumQuery, State},
};
use bson::DateTime;
use chrono::NaiveDate;
use meshharbor_services::{
    dao::{
        growth::{GrowthDao, GrowthPull, PURESTAT_FREEZE_DAYS, PURESTAT_SOURCE, PullStatus},
        growth_digest::ExcludedCounts,
    },
    purestat::{PurestatClient, PurestatError, Query, Row},
};
use meshharbor_core::{
    campaign::{CampaignKey, KeyDepth},
    growth::ExclusionSet,
};
use serde::{Deserialize, Serialize};

use super::{
    channels::PlatformReach,
    digest::{
        CampaignGoals, Coverage, Measured, NotMeasured, SMALL_N, day_str, parse_day, utc_date_of,
    },
    funnel::{self, GroupCounts, StepCounts},
    mounted,
    read_key::GrowthAuth,
};
use crate::{error::ApiError, state::AppState};

/// The default range: the 28 closed days ending yesterday.
pub const DEFAULT_RANGE_DAYS: i64 = 28;
/// purestat's own bound on one query's range.
pub const MAX_RANGE_DAYS: i64 = 366;
/// The web metrics asked for every key.
pub const WEB_METRICS: [&str; 4] = ["visitors", "visits", "pageviews", "reads"];
/// FR-88's four goals.
pub const GOALS: [&str; 4] = ["signup", "subscribe", "install-copy", "github-outbound"];
/// The most rows answered — busiest first; a ceiling, not a page.
pub const MAX_ROWS: usize = 500;
const DAY_MS: i64 = 86_400_000;

/// A rate and the n it rests on: `value` only once `n` reaches
/// [`SMALL_N`], to 0.001 — below it a reader shows counts (principle 5).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rate {
    pub n: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
}

impl Rate {
    pub fn of(count: i64, n: i64) -> Self {
        Self {
            n,
            value: (n >= SMALL_N).then(|| (count as f64 / n as f64 * 1000.0).round() / 1000.0),
        }
    }
}

/// One key's web plane, as purestat counted it over the range.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebCells {
    pub visitors: i64,
    pub visits: i64,
    pub pageviews: i64,
    /// Pageviews visible ≥ 30 s — the engagement purestat's v1 contract
    /// carries (it has no engaged-visitor metric).
    pub reads: i64,
    /// Goal conversions, as unique visitors — `not_measured` when the site
    /// does not define a goal (the visitors are still real).
    pub goals: Measured<CampaignGoals>,
    /// How many of purestat's rows normalised into this key. Above 1 the
    /// counts are SUMS of the spellings' — an upper bound on unique
    /// visitors, since a visitor who came by two spellings counts twice.
    /// 0 for a key purestat saw no visit of.
    pub spellings: u32,
}

impl WebCells {
    /// A measured zero (a key purestat saw no visit of).
    pub(crate) fn zero(goals_measured: bool, conversions: &Option<NotMeasured>) -> Self {
        Self {
            visitors: 0,
            visits: 0,
            pageviews: 0,
            reads: 0,
            goals: goals_cell(CampaignGoals::default(), goals_measured, conversions),
            spellings: 0,
        }
    }

    fn add(&mut self, r: &Row) {
        self.visitors += r.count("visitors");
        self.visits += r.count("visits");
        self.pageviews += r.count("pageviews");
        self.reads += r.count("reads");
        if let Measured::Value(g) = &mut self.goals {
            g.signup += r.goal("signup");
            g.subscribe += r.goal("subscribe");
            g.install_copy += r.goal("install-copy");
            g.github_outbound += r.goal("github-outbound");
        }
        self.spellings += 1;
    }
}

fn goals_cell(
    goals: CampaignGoals,
    measured: bool,
    conversions: &Option<NotMeasured>,
) -> Measured<CampaignGoals> {
    match (measured, conversions) {
        (true, None) => Measured::Value(goals),
        (_, Some(n)) => Measured::NotMeasured(n.clone()),
        (false, None) => Measured::NotMeasured(NotMeasured::now("goals not measured")),
    }
}

/// A key's rates, each with its n; `None` where a side is not measured.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rates {
    /// The server's sign-ups ÷ purestat's visitors (n = visitors) — two
    /// planes, joined by the key and by counts.
    pub signup_per_visitor: Option<Rate>,
    /// Activated ÷ the sign-ups settled at that step.
    pub activation: Option<Rate>,
    /// First value ÷ the sign-ups settled at that step.
    pub first_value: Option<Rate>,
    /// P4 — paid (so far) ÷ the sign-ups settled at the org step.
    pub paid: Option<Rate>,
}

/// One row of the table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignRow {
    /// The normalised key, cut to the depth — client-chosen text.
    pub key: CampaignKey,
    /// The taxonomy's group of the source: canonical, or `other`.
    pub group: String,
    pub web: Measured<WebCells>,
    pub signups: u64,
    pub org_created: StepCounts,
    pub activated: Option<StepCounts>,
    pub first_value: Option<StepCounts>,
    /// P4 — the org's first invoice paid above 0 (no window: as of now);
    /// `null` without `saas`.
    pub paid: Option<StepCounts>,
    /// P8 — each platform's own numbers for the posts published in the
    /// range with this key, per snapshot age (raw metric names);
    /// `not_measured` when no such post was pushed.
    pub reach: Measured<Vec<PlatformReach>>,
    /// purestat's `signup` conversions against the server's sign-ups for
    /// the key — what share of them the browser saw.
    pub coverage: Measured<Coverage>,
    pub rates: Rates,
}

/// The range's totals, keyed or not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    /// purestat's totals for the range — one query with no dimension, so
    /// these visitors ARE unique over the range.
    pub web: Measured<WebCells>,
    /// The range's sign-ups, exclusions applied.
    pub signups: u64,
    /// Those that carried a campaign key.
    pub keyed_signups: u64,
    pub coverage: Measured<Coverage>,
}

/// The daily puller's state over the range (`growth_pulls`): the live
/// table does not read the frozen rows, but a reader of them must be able
/// to tell a day that was not pulled, or failed, from a quiet one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PullSummary {
    pub source: String,
    pub days: u32,
    pub pulled: u32,
    pub failed: u32,
    pub not_pulled: u32,
    /// A pulled day older than this is frozen.
    pub freeze_days: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pulled_at: Option<String>,
    /// The newest attempt's error, when it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Why nothing pulls on this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_measured: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignsReport {
    pub enabled: bool,
    /// `YYYY-MM-DD`, inclusive.
    pub since: String,
    /// `YYYY-MM-DD`, inclusive.
    pub until: String,
    pub by: KeyDepth,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub windows: funnel::Windows,
    pub n_floor: i64,
    /// Why every web cell is `not_measured`; absent when purestat answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_not_measured: Option<NotMeasured>,
    /// Why no web cell carries conversions (a goal the site lacks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversions: Option<NotMeasured>,
    /// purestat's breakdown hit the page bound: the busiest keys only.
    pub web_truncated: bool,
    /// More sign-ups than one read loads: the oldest only.
    pub account_truncated: bool,
    /// More keys than [`MAX_ROWS`]: the busiest only.
    pub rows_truncated: bool,
    pub value_basis: Vec<String>,
    /// Step → why it is `null` (the module not mounted).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub not_measured: BTreeMap<String, String>,
    pub totals: Totals,
    pub rows: Vec<CampaignRow>,
    pub pulls: PullSummary,
}

#[derive(Debug, Deserialize)]
pub struct CampaignsQuery {
    /// `YYYY-MM-DD`, inclusive. Default: 27 days before `until`.
    #[serde(default)]
    pub since: Option<String>,
    /// `YYYY-MM-DD`, inclusive. Default: yesterday (UTC).
    #[serde(default)]
    pub until: Option<String>,
    /// `source` · `medium` · `campaign` (default) · `content`.
    #[serde(default)]
    pub by: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

/// The range, parsed: UTC days, both ends inclusive, at most
/// [`MAX_RANGE_DAYS`]; `until` never after today. Defaults to the 28 closed
/// days ending yesterday.
pub fn range(
    since: Option<&str>,
    until: Option<&str>,
    today: NaiveDate,
) -> Result<(NaiveDate, NaiveDate), String> {
    let until = match until {
        Some(s) => parse_day(s)?,
        None => today.pred_opt().ok_or("no yesterday")?,
    };
    if until > today {
        return Err(format!(
            "until must not be after today ({})",
            day_str(today)
        ));
    }
    let since = match since {
        Some(s) => parse_day(s)?,
        None => until - chrono::Duration::days(DEFAULT_RANGE_DAYS - 1),
    };
    if since > until {
        return Err("since must not be after until".into());
    }
    if (until - since).num_days() + 1 > MAX_RANGE_DAYS {
        return Err(format!("the range spans at most {MAX_RANGE_DAYS} days"));
    }
    Ok((since, until))
}

/// purestat's web rows folded by the normalised key at `depth`. Rows with
/// no source (organic visits) are not a key.
pub fn web_by_key(
    rows: &[Row],
    depth: KeyDepth,
    conversions: &Option<NotMeasured>,
) -> BTreeMap<CampaignKey, WebCells> {
    let mut out: BTreeMap<CampaignKey, WebCells> = BTreeMap::new();
    for r in rows {
        let Some(key) = CampaignKey::normalized(
            r.dim("utm_source"),
            r.dim("utm_medium"),
            r.dim("utm_campaign"),
            r.dim("utm_content"),
        ) else {
            continue;
        };
        out.entry(key.at_depth(depth))
            .or_insert_with(|| WebCells::zero(true, conversions))
            .add(r);
    }
    out
}

fn coverage(goals: &Measured<CampaignGoals>, server_signups: u64) -> Measured<Coverage> {
    match goals {
        Measured::Value(g) => {
            let n = server_signups as i64;
            Measured::Value(Coverage {
                purestat_signup_goals: g.signup,
                server_signups: n,
                ratio: Rate::of(g.signup, n).value,
                n_floor: SMALL_N,
            })
        }
        Measured::NotMeasured(n) => Measured::NotMeasured(n.clone()),
    }
}

pub(crate) fn step_rate(step: Option<StepCounts>) -> Option<Rate> {
    step.map(|s| Rate::of(s.count as i64, s.settled as i64))
}

/// `[since 00:00, until+1 00:00)` in milliseconds — the account plane's
/// window for a range of UTC days, both inclusive.
pub(crate) fn day_range_ms(since: NaiveDate, until: NaiveDate) -> (i64, i64) {
    let start = |d: NaiveDate| {
        d.and_hms_opt(0, 0, 0)
            .expect("midnight exists")
            .and_utc()
            .timestamp_millis()
    };
    (start(since), start(until) + DAY_MS)
}

/// The sign-up's normalised key, cut to `depth`; `None` = organic.
pub(crate) fn signup_key(s: &funnel::SignupFact, depth: KeyDepth) -> Option<CampaignKey> {
    let a = s.attribution.as_ref()?;
    CampaignKey::normalized(
        a.source.as_deref(),
        a.medium.as_deref(),
        a.campaign.as_deref(),
        a.content.as_deref(),
    )
    .map(|k| k.at_depth(depth))
}

/// The account plane grouped by the normalised key at `depth`.
pub(crate) fn account_by_key(
    facts: &funnel::Facts<'_>,
    depth: KeyDepth,
) -> BTreeMap<Option<CampaignKey>, GroupCounts> {
    funnel::group_by(facts, |s| signup_key(s, depth))
}

/// A key with no sign-up: zeros where the step's module is mounted (a
/// measured zero), `null` where it is not.
pub(crate) fn blank_counts(read: &funnel::Read) -> GroupCounts {
    GroupCounts {
        signups: 0,
        org_created: StepCounts::default(),
        activated: read.first_device.as_ref().map(|_| StepCounts::default()),
        first_value: (read.first_device.is_some() && read.first_value.is_some())
            .then(StepCounts::default),
        paid: read.first_paid.as_ref().map(|_| StepCounts::default()),
    }
}

/// The join, pure: the web plane (a value, or the reason it has none) and
/// the account plane's groups, by the same key. A key on one side only is
/// still a row — a measured zero on the other (when that side measured).
/// Sorted busiest first (visitors, then sign-ups), then by key; bounded by
/// [`MAX_ROWS`] (the bool says whether it cut).
pub fn join(
    web: &Result<BTreeMap<CampaignKey, WebCells>, NotMeasured>,
    conversions: &Option<NotMeasured>,
    account: &BTreeMap<Option<CampaignKey>, GroupCounts>,
    blank: &GroupCounts,
    reach: &BTreeMap<CampaignKey, Vec<PlatformReach>>,
    reach_absent: &NotMeasured,
) -> (Vec<CampaignRow>, bool) {
    let mut keys: Vec<&CampaignKey> = account.keys().flatten().collect();
    if let Ok(w) = web {
        keys.extend(w.keys());
    }
    keys.sort();
    keys.dedup();
    let mut rows: Vec<CampaignRow> = keys
        .into_iter()
        .map(|key| {
            let acc = account.get(&Some(key.clone())).unwrap_or(blank);
            let web_cell = match web {
                Ok(w) => Measured::Value(
                    w.get(key)
                        .cloned()
                        .unwrap_or_else(|| WebCells::zero(true, conversions)),
                ),
                Err(n) => Measured::NotMeasured(n.clone()),
            };
            let (coverage, signup_per_visitor) = match &web_cell {
                Measured::Value(c) => (
                    coverage(&c.goals, acc.signups),
                    Some(Rate::of(acc.signups as i64, c.visitors)),
                ),
                Measured::NotMeasured(n) => (Measured::NotMeasured(n.clone()), None),
            };
            CampaignRow {
                key: key.clone(),
                group: key.group().to_string(),
                web: web_cell,
                signups: acc.signups,
                org_created: acc.org_created,
                activated: acc.activated,
                first_value: acc.first_value,
                paid: acc.paid,
                reach: match reach.get(key) {
                    Some(r) => Measured::Value(r.clone()),
                    None => Measured::NotMeasured(reach_absent.clone()),
                },
                coverage,
                rates: Rates {
                    signup_per_visitor,
                    activation: step_rate(acc.activated),
                    first_value: step_rate(acc.first_value),
                    paid: step_rate(acc.paid),
                },
            }
        })
        .collect();
    let visitors = |r: &CampaignRow| r.web.value().map(|w| w.visitors).unwrap_or(0);
    rows.sort_by(|a, b| {
        visitors(b)
            .cmp(&visitors(a))
            .then_with(|| b.signups.cmp(&a.signups))
            .then_with(|| a.key.cmp(&b.key))
    });
    let cut = rows.len() > MAX_ROWS;
    rows.truncate(MAX_ROWS);
    (rows, cut)
}

/// The pull rows over the range, summarised.
pub fn pull_summary(pulls: &[GrowthPull], days: u32, saas_mounted: bool) -> PullSummary {
    let pulled = pulls.iter().filter(|p| p.status == PullStatus::Ok).count() as u32;
    let failed = pulls
        .iter()
        .filter(|p| p.status == PullStatus::Failed)
        .count() as u32;
    let newest = pulls
        .iter()
        .max_by_key(|p| p.attempted_at.timestamp_millis());
    PullSummary {
        source: PURESTAT_SOURCE.to_string(),
        days,
        pulled,
        failed,
        not_pulled: days.saturating_sub(pulled + failed),
        freeze_days: PURESTAT_FREEZE_DAYS,
        last_pulled_at: pulls
            .iter()
            .filter_map(|p| p.pulled_at)
            .max_by_key(|t| t.timestamp_millis())
            .and_then(|t| t.try_to_rfc3339_string().ok()),
        last_error: newest.and_then(|p| p.error.clone()),
        not_measured: (!saas_mounted)
            .then(|| "saas module not mounted (the puller runs there)".to_string()),
    }
}

/// One breakdown of the web plane: by the key at a depth, or the reason
/// there is none. A goal the site lacks costs the conversions only.
pub(crate) struct WebBreakdown {
    pub(crate) by_key: Result<BTreeMap<CampaignKey, WebCells>, NotMeasured>,
    pub(crate) conversions: Option<NotMeasured>,
    pub(crate) truncated: bool,
}

fn not_measured_of(e: &PurestatError) -> NotMeasured {
    NotMeasured::now(e.to_string())
}

/// This server's purestat client, or why there is none (no key — and then
/// nothing is ever asked).
pub(crate) fn web_client(state: &AppState) -> Result<PurestatClient, NotMeasured> {
    let g = &state.settings.growth;
    PurestatClient::new(&g.purestat_url, &g.purestat_api_key)
        .ok_or_else(|| not_measured_of(&PurestatError::NotConfigured))
}

/// purestat's breakdown of `[since, until]` by exactly the UTM dimensions
/// of `depth`, folded by the normalised key.
pub(crate) async fn web_breakdown(
    client: &Result<PurestatClient, NotMeasured>,
    since: &str,
    until: &str,
    depth: KeyDepth,
) -> WebBreakdown {
    let client = match client {
        Ok(c) => c,
        Err(n) => {
            return WebBreakdown {
                by_key: Err(n.clone()),
                conversions: None,
                truncated: false,
            };
        }
    };
    let breakdown = client
        .query_or_without_goals(&Query::range(
            since,
            until,
            depth.utm_dimensions(),
            &WEB_METRICS,
            &GOALS,
        ))
        .await;
    match breakdown {
        Ok((paged, missing)) => {
            let conversions = missing.map(|goal| {
                NotMeasured::now(format!("{goal} is not defined on the purestat site"))
            });
            WebBreakdown {
                by_key: Ok(web_by_key(&paged.rows, depth, &conversions)),
                conversions,
                truncated: paged.truncated,
            }
        }
        Err(e) => WebBreakdown {
            by_key: Err(not_measured_of(&e)),
            conversions: None,
            truncated: false,
        },
    }
}

/// purestat's totals for `[since, until]` — one query with no dimension, so
/// its visitors are unique over the range.
pub(crate) async fn web_totals(
    client: &Result<PurestatClient, NotMeasured>,
    since: &str,
    until: &str,
    breakdown: &WebBreakdown,
) -> Measured<WebCells> {
    let client = match (client, &breakdown.by_key) {
        (Err(n), _) | (_, Err(n)) => return Measured::NotMeasured(n.clone()),
        (Ok(c), Ok(_)) => c,
    };
    let goals: &[&str] = if breakdown.conversions.is_some() {
        &[]
    } else {
        &GOALS
    };
    match client
        .query(&Query::range(since, until, &[], &WEB_METRICS, goals))
        .await
    {
        Ok(rows) => {
            let conversions = &breakdown.conversions;
            let mut t = WebCells::zero(conversions.is_none(), conversions);
            if let Some(r) = rows.first() {
                t.add(r);
            }
            Measured::Value(t)
        }
        Err(e) => Measured::NotMeasured(not_measured_of(&e)),
    }
}

/// `GET /api/admin/growth/campaigns?since&until&by&include_internal`
pub async fn get_campaigns(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    AxumQuery(q): AxumQuery<CampaignsQuery>,
) -> Result<Json<CampaignsReport>, ApiError> {
    let now = DateTime::now();
    let today = utc_date_of(now);
    let (since, until) =
        range(q.since.as_deref(), q.until.as_deref(), today).map_err(ApiError::BadRequest)?;
    let depth = match q.by.as_deref() {
        None => KeyDepth::Campaign,
        Some(raw) => KeyDepth::parse(raw).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "by must be one of {}",
                KeyDepth::ALL
                    .iter()
                    .map(|d| d.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?,
    };
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    Ok(Json(
        compute(&state, &set, since, until, depth, q.include_internal, now).await?,
    ))
}

/// The table for the closed days `[since, until]` (inclusive) at `now` —
/// what the route answers, and what P10's weekly roll-up stores by source
/// for its week.
pub async fn compute(
    state: &AppState,
    set: &ExclusionSet,
    since: NaiveDate,
    until: NaiveDate,
    depth: KeyDepth,
    include_internal: bool,
    now: DateTime,
) -> Result<CampaignsReport, ApiError> {
    // The account plane: the range's sign-ups, `[since 00:00, until+1 00:00)`.
    let (start_ms, end_ms) = day_range_ms(since, until);
    let read = funnel::read(
        state,
        set,
        DateTime::from_millis(start_ms),
        DateTime::from_millis(end_ms),
    )
    .await?;
    let facts = read.facts(now.timestamp_millis());
    let account = account_by_key(&facts, depth);
    let signups = facts.signups.len() as u64;
    let keyed_signups: u64 = account
        .iter()
        .filter(|(k, _)| k.is_some())
        .map(|(_, g)| g.signups)
        .sum();
    let blank = blank_counts(&read);

    // The web plane, live, for the same days.
    let (since_s, until_s) = (day_str(since), day_str(until));
    let client = web_client(state);
    let web = web_breakdown(&client, &since_s, &until_s, depth).await;
    let totals_web = web_totals(&client, &since_s, &until_s, &web).await;

    // P8 — the platforms' own numbers for the posts published in the range,
    // by the same key.
    let social = super::channels::read_posts(state, start_ms, end_ms).await?;
    let reach = super::channels::reach_by_key(&social.posts, &social.snapshots, depth);
    let reach_absent = super::channels::no_reach_reason(state, &social);

    let (rows, rows_truncated) = join(
        &web.by_key,
        &web.conversions,
        &account,
        &blank,
        &reach,
        &reach_absent,
    );
    let totals_coverage = match &totals_web {
        Measured::Value(t) => coverage(&t.goals, signups),
        Measured::NotMeasured(n) => Measured::NotMeasured(n.clone()),
    };

    let pulls = GrowthDao::new(&state.db)
        .pulls_between(PURESTAT_SOURCE, &since_s, &until_s)
        .await?;
    let days = ((until - since).num_days() + 1) as u32;
    let (users, tenants) = set.counts();
    Ok(CampaignsReport {
        enabled: true,
        since: since_s,
        until: until_s,
        by: depth,
        include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        windows: funnel::Windows {
            org_days: funnel::ORG_WINDOW_DAYS,
            activation_days: funnel::ACTIVATION_WINDOW_DAYS,
            value_days: funnel::VALUE_WINDOW_DAYS,
        },
        n_floor: SMALL_N,
        web_not_measured: web.by_key.as_ref().err().cloned(),
        conversions: web.conversions.clone(),
        web_truncated: web.truncated,
        account_truncated: read.truncated,
        rows_truncated,
        value_basis: read.basis.clone(),
        not_measured: read.step_reasons(),
        totals: Totals {
            web: totals_web,
            signups,
            keyed_signups,
            coverage: totals_coverage,
        },
        rows,
        pulls: pull_summary(&pulls, days, mounted(state, "saas")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        parse_day(s).unwrap()
    }

    fn row(dims: &[(&str, &str)], visitors: f64, signup_goals: f64) -> Row {
        Row {
            dimensions: dims
                .iter()
                .map(|(k, v)| (k.to_string(), Some(v.to_string())))
                .collect(),
            metrics: [
                ("visitors".to_string(), Some(visitors)),
                ("visits".to_string(), Some(visitors + 1.0)),
                ("pageviews".to_string(), Some(visitors * 2.0)),
            ]
            .into_iter()
            .collect(),
            goals: [("signup".to_string(), Some(signup_goals))]
                .into_iter()
                .collect(),
        }
    }

    fn key(source: &str, medium: Option<&str>, campaign: Option<&str>) -> CampaignKey {
        CampaignKey::normalized(Some(source), medium, campaign, None).unwrap()
    }

    fn group(signups: u64, activated: u64, settled: u64) -> GroupCounts {
        GroupCounts {
            signups,
            org_created: StepCounts {
                count: activated,
                pending: 0,
                settled: signups,
            },
            activated: Some(StepCounts {
                count: activated,
                pending: signups - settled,
                settled,
            }),
            first_value: None,
            // P4 — one paid org per activated org, settled like the org step.
            paid: Some(StepCounts {
                count: activated,
                pending: 0,
                settled: signups,
            }),
        }
    }

    #[test]
    fn the_range_defaults_to_28_closed_days_and_is_bounded() {
        let today = d("2026-10-15");
        assert_eq!(
            range(None, None, today).unwrap(),
            (d("2026-09-17"), d("2026-10-14"))
        );
        assert_eq!(
            range(Some("2026-10-13"), Some("2026-10-13"), today).unwrap(),
            (d("2026-10-13"), d("2026-10-13"))
        );
        // Today may be read (live), tomorrow not.
        assert!(range(None, Some("2026-10-15"), today).is_ok());
        assert!(range(None, Some("2026-10-16"), today).is_err());
        assert!(range(Some("2026-10-14"), Some("2026-10-13"), today).is_err());
        assert!(range(Some("2025-01-01"), Some("2026-10-13"), today).is_err());
        assert!(range(Some("2025-10-13"), Some("2026-10-13"), today).is_ok());
        assert!(range(Some("yesterday"), None, today).is_err());
    }

    #[test]
    fn a_rate_has_a_value_only_from_the_n_floor() {
        assert_eq!(Rate::of(5, 29), Rate { n: 29, value: None });
        assert_eq!(
            Rate::of(15, 30),
            Rate {
                n: 30,
                value: Some(0.5)
            }
        );
        assert_eq!(Rate::of(0, 0).value, None);
        assert_eq!(Rate::of(1, 300).value, Some(0.003));
    }

    /// The join: spellings fold into one key (summed, counted), a key on
    /// one plane only is a measured zero on the other, the rows sort
    /// busiest first, and a depth cuts the key.
    #[test]
    fn the_planes_join_by_the_normalised_key() {
        let rows = vec![
            row(
                &[
                    ("utm_source", "LinkedIn"),
                    ("utm_medium", "post"),
                    ("utm_campaign", "C1"),
                ],
                52.0,
                1.0,
            ),
            row(
                &[
                    ("utm_source", "linkedin"),
                    ("utm_medium", "Post"),
                    ("utm_campaign", "c1"),
                ],
                3.0,
                0.0,
            ),
            row(
                &[("utm_source", "youtub"), ("utm_medium", "video")],
                7.0,
                0.0,
            ),
            // Organic — no key.
            row(&[("utm_medium", "post")], 20.0, 0.0),
        ];
        let web = Ok(web_by_key(&rows, KeyDepth::Campaign, &None));
        let li = key("linkedin", Some("post"), Some("c1"));
        let x = key("x", Some("post"), Some("c9"));
        let account: BTreeMap<Option<CampaignKey>, GroupCounts> = [
            (Some(li.clone()), group(1, 1, 1)),
            (Some(x.clone()), group(2, 0, 1)),
            (None, group(4, 0, 4)),
        ]
        .into_iter()
        .collect();
        let blank = group(0, 0, 0);
        // P8 — one LinkedIn post carries the li key; nothing else has reach.
        let reach: BTreeMap<CampaignKey, Vec<PlatformReach>> = [(
            li.clone(),
            vec![PlatformReach {
                platform: "linkedin".into(),
                posts: 1,
                at: vec![super::super::channels::ReachAt {
                    snapshot: "T+1d".into(),
                    posts: 1,
                    metrics: [("impressions".to_string(), 1000.0)].into_iter().collect(),
                }],
            }],
        )]
        .into_iter()
        .collect();
        let absent = NotMeasured::now("no post pushed with this key in the range");
        let (out, cut) = join(&web, &None, &account, &blank, &reach, &absent);
        assert!(!cut);
        assert_eq!(out.len(), 3, "linkedin, youtube, x — no organic row");
        let li_row = &out[0];
        assert_eq!(li_row.key, li);
        let w = li_row.web.value().unwrap();
        assert_eq!((w.visitors, w.spellings), (55, 2), "two spellings, summed");
        assert_eq!(w.goals.value().unwrap().signup, 1);
        assert_eq!(li_row.signups, 1);
        let cov = li_row.coverage.value().unwrap();
        assert_eq!(
            (cov.purestat_signup_goals, cov.server_signups, cov.ratio),
            (1, 1, None)
        );
        assert_eq!(
            li_row.rates.signup_per_visitor,
            Some(Rate {
                n: 55,
                value: Some(0.018)
            })
        );
        // P4 — the key's paid orgs, and the rate held back below the floor.
        assert_eq!(li_row.paid.map(|p| p.count), Some(1));
        assert_eq!(li_row.rates.paid, Some(Rate { n: 1, value: None }));
        let r = li_row.reach.value().expect("the post's reach");
        assert_eq!((r[0].platform.as_str(), r[0].posts), ("linkedin", 1));
        assert_eq!(r[0].at[0].metrics["impressions"], 1000.0);
        // youtube from `youtub`, on the web plane only: zero sign-ups, and
        // no post pushed with its key — reach not measured, never 0.
        assert_eq!(out[1].key.source, "youtube");
        assert_eq!(out[1].signups, 0);
        assert_eq!(out[1].group, "youtube");
        assert_eq!(
            serde_json::to_value(&out[1].reach).unwrap(),
            serde_json::json!({ "not_measured": "no post pushed with this key in the range" })
        );
        // x on the account plane only: a measured zero on the web.
        let x_row = out.iter().find(|r| r.key == x).unwrap();
        assert_eq!(x_row.web.value().unwrap().visitors, 0);
        assert_eq!(x_row.web.value().unwrap().spellings, 0);
        assert_eq!(x_row.signups, 2);
        assert_eq!(
            x_row.rates.signup_per_visitor,
            Some(Rate { n: 0, value: None })
        );

        // The web plane down: every web cell and coverage is the reason,
        // never 0; the account plane is untouched.
        let down: Result<BTreeMap<CampaignKey, WebCells>, NotMeasured> =
            Err(NotMeasured::now("purestat unreachable: unauthorized (401)"));
        let (out, _) = join(&down, &None, &account, &blank, &reach, &absent);
        assert_eq!(out.len(), 2, "the account plane's keys still list");
        for r in &out {
            assert!(!r.web.is_measured());
            assert!(!r.coverage.is_measured());
            assert_eq!(r.rates.signup_per_visitor, None);
            let json = serde_json::to_value(r).unwrap();
            assert_eq!(
                json["web"]["not_measured"],
                "purestat unreachable: unauthorized (401)"
            );
        }
        assert_eq!(out.iter().map(|r| r.signups).sum::<u64>(), 3);

        // A depth cuts the key: by source, LinkedIn's rows are one.
        let by_source = web_by_key(&rows, KeyDepth::Source, &None);
        assert_eq!(by_source.len(), 2);
        assert_eq!(by_source[&key("linkedin", None, None)].visitors, 55);
    }

    /// A goal the site lacks: the visitors stand, the conversions and the
    /// coverage say which goal.
    #[test]
    fn a_missing_goal_costs_the_conversions_only() {
        let conversions = Some(NotMeasured::now(
            "signup is not defined on the purestat site",
        ));
        let rows = vec![row(
            &[("utm_source", "x"), ("utm_campaign", "c1")],
            40.0,
            0.0,
        )];
        let web = Ok(web_by_key(&rows, KeyDepth::Campaign, &conversions));
        let blank = group(0, 0, 0);
        let (out, _) = join(
            &web,
            &conversions,
            &BTreeMap::new(),
            &blank,
            &BTreeMap::new(),
            &NotMeasured::now("no post"),
        );
        let w = out[0].web.value().unwrap();
        assert_eq!(w.visitors, 40);
        assert!(!w.goals.is_measured());
        assert!(!out[0].coverage.is_measured());
    }

    #[test]
    fn the_pull_summary_tells_not_pulled_and_failed_from_pulled() {
        let at = |s: &str| DateTime::parse_rfc3339_str(s).unwrap();
        let p = |day: &str, ok: bool, attempted: &str, error: Option<&str>| GrowthPull {
            id: GrowthPull::id_of(PURESTAT_SOURCE, day),
            source: PURESTAT_SOURCE.into(),
            day: day.into(),
            status: if ok {
                PullStatus::Ok
            } else {
                PullStatus::Failed
            },
            pulled_at: ok.then(|| at(attempted)),
            attempted_at: at(attempted),
            attempts: 1,
            rows: 3,
            error: error.map(str::to_string),
            missing_goal: None,
            truncated: false,
        };
        let pulls = vec![
            p("2026-10-12", true, "2026-10-14T01:10:00Z", None),
            p(
                "2026-10-13",
                false,
                "2026-10-14T02:10:00Z",
                Some("purestat unreachable: timed out"),
            ),
        ];
        let s = pull_summary(&pulls, 7, true);
        assert_eq!((s.days, s.pulled, s.failed, s.not_pulled), (7, 1, 1, 5));
        assert_eq!(
            s.last_error.as_deref(),
            Some("purestat unreachable: timed out")
        );
        assert_eq!(s.last_pulled_at.as_deref(), Some("2026-10-14T01:10:00Z"));
        assert_eq!(s.not_measured, None);
        let s = pull_summary(&[], 3, false);
        assert_eq!(s.not_pulled, 3);
        assert!(s.not_measured.unwrap().contains("saas"));
    }
}
