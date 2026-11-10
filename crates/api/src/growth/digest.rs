// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1d — the daily digest: every closed UTC day, computed once,
//! stored once, mailed once (spec §3l).
//!
//! # The shape
//!
//! Each section answers one of the operator's questions (spec §1), and every
//! count comes as a [`Figure`] — the day, and the trailing 7 and 28 days
//! ending on it — so a quiet day is read against a baseline, not alone. A
//! section whose source is not built, not mounted or not reachable is
//! [`Measured::NotMeasured`] with a reason (and the phase that brings it),
//! and is NEVER rendered as 0: *measured*, *not measured* and *zero* are
//! three cells (spec principle 4). Every number applies the
//! [`ExclusionSet`] (spec §3c.4); the footer says how many users and orgs
//! were left out, so nothing vanishes silently.
//!
//! # Once, with two pods (AC23)
//!
//! A scheduled run first claims the day: an INSERT of
//! `growth_digests {_id: "YYYY-MM-DD", status: computing}` whose unique
//! `_id` decides which pod goes on ([`DigestStore::claim`]). A `failed` day
//! or a stale `computing` one (a pod that died mid-run, past
//! [`STALE_CLAIM_SECS`]) is re-claimed with a compare-and-set; a `sent` day
//! is never sent again. The manual route (`POST …/digest/run`) recomputes
//! and overwrites a day's sections and mails only when asked AND the day
//! was not already `sent`.
//!
//! # What it never carries
//!
//! No address, name or IP: the sign-up rows list provider and campaign key,
//! the recipients are a COUNT, org names appear (as `/observability` shows
//! them) and nothing else about a person. A test asserts no seeded address
//! survives into the stored JSON or the rendered mail.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::{NaiveDate, Timelike};
use futures::TryStreamExt;
use meshharbor_core::{campaign, growth::ExclusionSet};
use meshharbor_db::models::tenant::Plan;
use meshharbor_remote_control::setup_diagnostics::{Outcome, Step};
use meshharbor_services::{
    EmailService,
    dao::{
        base::DaoError,
        growth::GrowthDao,
        growth_digest::{
            ClaimMode, ClaimOutcome, DigestDoc, DigestStatus, DigestStore, ExcludedCounts,
        },
        growth_quality::{
            ALL_VERSIONS, Dist, GrowthQualityDao, QualityDay, Scope, SessionQuality, TtffQuality,
        },
        growth_social::{GROWTH_POST_SNAPSHOTS, GROWTH_POSTS, SNAPSHOTS},
        setup_diagnostics::SetupDiagnosticsDao,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::purestat::{Filter, PurestatClient, PurestatError, Query, Row};
use super::quality::{
    SessionRow, rate_if_enough, session_projection, session_quality, session_row, version_order,
};
use crate::{error::ApiError, state::AppState};

/// A `computing` claim older than this is a dead pod's, and is re-claimed.
pub const STALE_CLAIM_SECS: i64 = 30 * 60;
/// The scheduler's cadence; a tick that finds the day done costs one read.
pub const LOOP_INTERVAL_SECS: u64 = 10 * 60;
/// A pod that just booted waits this long before its first tick, so a
/// rolling restart does not race its own predecessor's claim.
pub const FIRST_TICK_DELAY_SECS: u64 = 2 * 60;
/// A remote-desktop session is a VALUE event once it reached Active and
/// lasted this long (spec §3d). The definition lives in `value.rs` with its
/// three siblings (P2); re-exported so the path stays.
pub use super::value::VALUE_SESSION_SECS;
/// Sign-ups listed individually; past this they are aggregated by source.
pub const MAX_LISTED_SIGNUPS: usize = 20;
pub const TOP_ORGS: usize = 10;
pub const TOP_WEB_ROWS: usize = 10;
pub const TOP_BLOG_POSTS: usize = 20;
/// P8 — the most of the day's social snapshots listed (by platform, then
/// age); a bound for the mail, not a page.
pub const TOP_SOCIAL_SNAPSHOTS: usize = 20;
/// Below this n a rate is not shown — counts only (spec principle 5).
pub const SMALL_N: i64 = 30;
/// A ceiling on the rows one source query loads — far above this
/// deployment's volume; a bound, not a page.
pub(crate) const MAX_ROWS: i64 = 200_000;

// ── Errors ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct DigestError(pub String);

impl std::fmt::Display for DigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DigestError {}

impl From<DaoError> for DigestError {
    fn from(e: DaoError) -> Self {
        Self(e.to_string())
    }
}

impl From<mongodb::error::Error> for DigestError {
    fn from(e: mongodb::error::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<bson::ser::Error> for DigestError {
    fn from(e: bson::ser::Error) -> Self {
        Self(format!("sections did not serialise: {e}"))
    }
}

impl From<DigestError> for ApiError {
    fn from(e: DigestError) -> Self {
        ApiError::Internal(format!("digest: {e}"))
    }
}

// ── Days and windows ─────────────────────────────────────────────────────

/// `YYYY-MM-DD`, nothing else.
pub fn parse_day(raw: &str) -> Result<NaiveDate, String> {
    let raw = raw.trim();
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .map_err(|_| format!("day must be YYYY-MM-DD, got {raw:?}"))
}

pub fn day_str(day: NaiveDate) -> String {
    day.format("%Y-%m-%d").to_string()
}

fn midnight_ms(day: NaiveDate) -> i64 {
    day.and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
        .timestamp_millis()
}

/// The UTC calendar day an instant falls in.
pub fn utc_date_of(at: DateTime) -> NaiveDate {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(at.timestamp_millis())
        .expect("a BSON date is in range")
        .date_naive()
}

/// The day a scheduled tick at `now` owes: yesterday (UTC), once the clock
/// has passed `today 00:00 + hour`. Never an older day — there is no
/// auto-backfill; the manual route does that on purpose.
pub fn due_day(now: DateTime, hour: u8) -> Option<NaiveDate> {
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now.timestamp_millis())?;
    if now_utc.hour() < u32::from(hour) {
        return None;
    }
    now_utc.date_naive().pred_opt()
}

/// The three windows every figure is counted over, as `[start, end)`
/// millisecond ranges; all three end at the day's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Windows {
    pub day_start: i64,
    pub day_end: i64,
    pub d7_start: i64,
    pub d28_start: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Span {
    Day,
    D7,
    D28,
}

impl Windows {
    pub fn for_day(day: NaiveDate) -> Self {
        let day_start = midnight_ms(day);
        let one = 86_400_000;
        Self {
            day_start,
            day_end: day_start + one,
            d7_start: day_start - 6 * one,
            d28_start: day_start - 27 * one,
        }
    }

    pub fn range(&self, span: Span) -> (i64, i64) {
        match span {
            Span::Day => (self.day_start, self.day_end),
            Span::D7 => (self.d7_start, self.day_end),
            Span::D28 => (self.d28_start, self.day_end),
        }
    }

    pub fn contains(&self, span: Span, t: i64) -> bool {
        let (lo, hi) = self.range(span);
        (lo..hi).contains(&t)
    }

    /// Count the instants falling in each window.
    pub fn count<I: IntoIterator<Item = i64>>(&self, times: I) -> Figure {
        let mut f = Figure::default();
        for t in times {
            if self.contains(Span::Day, t) {
                f.day += 1;
            }
            if self.contains(Span::D7, t) {
                f.d7 += 1;
            }
            if self.contains(Span::D28, t) {
                f.d28 += 1;
            }
        }
        f
    }

    /// The day's date, and the first day of each window, for purestat.
    pub fn dates(&self) -> (String, String, String) {
        let day = |ms: i64| {
            chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
                .expect("in range")
                .format("%Y-%m-%d")
                .to_string()
        };
        (day(self.day_start), day(self.d7_start), day(self.d28_start))
    }

    fn start_dt(&self, span: Span) -> DateTime {
        DateTime::from_millis(self.range(span).0)
    }

    fn end_dt(&self) -> DateTime {
        DateTime::from_millis(self.day_end)
    }

    /// `{$gte: window start, $lt: day end}` for a date field.
    fn between(&self, span: Span) -> Document {
        doc! { "$gte": self.start_dt(span), "$lt": self.end_dt() }
    }
}

/// Milliseconds of `[start, end)` inside `[lo, hi)`.
pub fn overlap_ms(start: i64, end: i64, lo: i64, hi: i64) -> i64 {
    (end.min(hi) - start.max(lo)).max(0)
}

pub(crate) fn minutes(ms: i64) -> f64 {
    (ms as f64 / 60_000.0 * 10.0).round() / 10.0
}

// ── Figures ──────────────────────────────────────────────────────────────

/// A count of the day, and of the trailing 7 and 28 days ending that day.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Figure {
    pub day: i64,
    pub d7: i64,
    pub d28: i64,
}

/// Minutes, to one decimal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct FigureF {
    pub day: f64,
    pub d7: f64,
    pub d28: f64,
}

/// Why a figure is not there, and when it will be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotMeasured {
    pub not_measured: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrives_with: Option<String>,
}

impl NotMeasured {
    /// Not built yet: the phase that brings it.
    pub fn later(reason: &str, phase: &str) -> Self {
        Self {
            not_measured: reason.to_string(),
            arrives_with: Some(phase.to_string()),
        }
    }

    /// Built, but unavailable on this server or this run.
    pub fn now(reason: impl Into<String>) -> Self {
        Self {
            not_measured: reason.into(),
            arrives_with: None,
        }
    }
}

/// A value, or the reason there is none. Serialises as the value itself or
/// as `{"not_measured": …, "arrives_with": …}` — a reader can always tell
/// the two apart, and a zero is only ever a measured zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Measured<T> {
    NotMeasured(NotMeasured),
    Value(T),
}

impl<T> Measured<T> {
    pub fn unmounted(module: &str) -> Self {
        Measured::NotMeasured(NotMeasured::now(format!("{module} module not mounted")))
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Measured::Value(v) => Some(v),
            Measured::NotMeasured(_) => None,
        }
    }

    pub fn is_measured(&self) -> bool {
        matches!(self, Measured::Value(_))
    }
}

impl<T> From<Result<T, PurestatError>> for Measured<T> {
    fn from(r: Result<T, PurestatError>) -> Self {
        match r {
            Ok(v) => Measured::Value(v),
            Err(e) => Measured::NotMeasured(NotMeasured::now(match unknown_goal(&e) {
                Some(goal) => format!("{goal} is not defined on the purestat site"),
                None => e.to_string(),
            })),
        }
    }
}

/// The goal a purestat 400 names as undefined (`unknown goal: "signup"`).
/// A site with no goal definitions is a configuration gap on the web plane,
/// not an outage: the sections that need the goal say which one, and the
/// ones that do not still measure. Defined beside the client since P6 (the
/// `saas` puller reads it too); re-exported so the path stays.
pub use meshharbor_services::purestat::unknown_goal;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCount {
    pub key: String,
    pub count: i64,
}

fn key_counts(map: BTreeMap<String, i64>) -> Vec<KeyCount> {
    let mut out: Vec<KeyCount> = map
        .into_iter()
        .map(|(key, count)| KeyCount { key, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out
}

// ── Sections ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveOrgs {
    pub day: i64,
    pub d7: i64,
    pub d28: i64,
    /// Which value modules were mounted: `remote`, `conference`, `network`
    /// (P2 — the same four events `growth_org_daily` folds).
    pub basis: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    /// purestat's `signup` goal conversions for the day.
    pub purestat_signup_goals: i64,
    /// The server's sign-ups for the day, exclusions applied.
    pub server_signups: i64,
    /// `goals / signups`, only once the denominator reaches [`SMALL_N`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratio: Option<f64>,
    pub n_floor: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Headline {
    pub signups: Figure,
    pub orgs_created: Figure,
    pub devices_enrolled: Measured<Figure>,
    pub active_orgs: Measured<ActiveOrgs>,
    pub coverage: Measured<Coverage>,
}

/// One sign-up of the day: the provider and the campaign key — never the
/// address, the username or the name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupRow {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landing_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_reported: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signups {
    pub total: Figure,
    /// Sign-ups that recorded any attribution field.
    pub attributed: Figure,
    pub by_provider: Vec<KeyCount>,
    pub by_source: Vec<KeyCount>,
    /// The day's sign-ups, one each, when there are at most
    /// [`MAX_LISTED_SIGNUPS`]; otherwise absent and `by_source` carries them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<SignupRow>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgsDevices {
    pub orgs_created: Figure,
    pub devices_enrolled: Measured<Figure>,
    pub devices_by_os: Measured<Vec<KeyCount>>,
    /// Orgs whose FIRST device was enrolled in the window.
    pub orgs_first_device: Measured<Figure>,
    /// The day's devices by `install.method` (P3); a row from before the
    /// install trace, or an agent that did not say, is `unknown`.
    pub by_install_method: Measured<Vec<KeyCount>>,
}

/// P3 — fetches of one asset by one client class on one OS, as the fleet
/// module counted them into `growth_daily` (`install_trace`). Approximate by
/// construction: a class is read off a User-Agent, and a self-hoster who
/// downloads our build to enroll elsewhere fetches like anyone else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRow {
    pub asset: String,
    pub client: String,
    pub os: String,
    pub fetches: Figure,
}

/// P3 — standard enrollment tokens minted in the window, and how many of
/// those were redeemed (by `enroll_token_issued`). Exclusions apply by the
/// token's tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub issued: Figure,
    /// Of the tokens issued in the window, the ones an enroll redeemed.
    pub redeemed: Figure,
}

/// P3 — devices enrolled in the window by install method and OS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodRow {
    pub method: String,
    pub os: String,
    pub enrolled: Figure,
}

/// P3b — one wizard step over the opted-in runs of the windows: how many
/// DISTINCT runs ended it, and with which outcome. A run that retried a
/// step counts once under `reached` and once under each outcome it had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardStepRow {
    pub step: String,
    pub reached: Figure,
    pub ok: Figure,
    pub failed: Figure,
    pub cancelled: Figure,
}

/// P3b — a step's failures by error code (distinct runs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardErrorRow {
    pub step: String,
    pub error_code: String,
    pub failures: Figure,
}

/// P3b — the wizard's opt-in step diagnostics (`setup_diagnostics`): the
/// opted-in runs seen in the windows, which step each reached and how it
/// ended, and the failures by code. **Opted-in runs only**, labelled with
/// their n (`runs`): a run that did not tick the box is not here, so these
/// numbers say nothing about the runs that did not. A share appears only
/// once `runs.d28` clears `n_floor`; below it the counts stand alone. The
/// rows carry no tenant, so the exclusion set cannot apply, like the fetch
/// counters. Not measured while the server's switch is off, never 0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WizardSteps {
    /// Distinct opted-in runs with any boundary in each window — the n.
    pub runs: Figure,
    pub n_floor: i64,
    /// Of the runs in the 28-day window, the share that reached `done`;
    /// only at `runs.d28 >= n_floor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done_share_28d: Option<f64>,
    /// In run order, the steps at least one run reached in 28 days.
    pub steps: Vec<WizardStepRow>,
    /// By failures in 28 days, then run order, then the code.
    pub errors: Vec<WizardErrorRow>,
}

/// P3 — the install trace (spec §3e item 6): fetches by client class,
/// tokens issued → redeemed, enrollments by method and OS. The fetch rows
/// carry no tenant, so the exclusion set cannot apply to them; the other
/// two exclude by tenant. Since P3c the operator's internal networks stand
/// in for the exclusion set on the fetches (`internal_fetches`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Install {
    /// The counted fetches by `(asset, client, os)` — never the `internal`
    /// rows (P3c), which are summed into `internal_fetches` instead.
    pub fetches: Measured<Vec<FetchRow>>,
    /// P3c — fetches from the operator's internal networks
    /// (`growth.internal_networks`), left out of `fetches` and reported here
    /// so nothing vanishes silently. Not measured while no network is
    /// configured and none was counted in the 28 days, never a 0 claiming
    /// that no lab fetch happened. A digest stored before P3c reads as
    /// `{not_measured, arrives_with: P3c}`.
    #[serde(default = "internal_fetches_before_p3c")]
    pub internal_fetches: Measured<Figure>,
    pub tokens: Measured<Tokens>,
    pub enrollments_by_method: Measured<Vec<MethodRow>>,
    /// P3b — the wizard's opt-in step diagnostics; not measured while
    /// `growth.setup_diagnostics` is off on this server. A digest stored
    /// before P3b holds the old `{not_measured, arrives_with: P3b}` here,
    /// which still reads as this type's other arm.
    pub wizard_steps: Measured<WizardSteps>,
}

/// A digest stored before P3c has no `internal_fetches`: it reads as not
/// measured (its `fetches` still hold every class, the lab's included).
fn internal_fetches_before_p3c() -> Measured<Figure> {
    Measured::NotMeasured(NotMeasured::later("fetches from internal networks", "P3c"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteUsage {
    /// Sessions that reached Active in the window.
    pub sessions_started: Figure,
    /// Each session's overlap with the window, summed.
    pub session_minutes: FigureF,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallUsage {
    pub calls: Figure,
    /// Participant-minutes of the calls that started in the window.
    pub participant_minutes: FigureF,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopOrg {
    pub tenant_id: String,
    /// The org's name as `/observability` shows it — client-chosen text.
    pub name: String,
    pub minutes: f64,
    pub sessions: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub remote: Measured<RemoteUsage>,
    pub calls: Measured<CallUsage>,
    pub active_orgs: Measured<ActiveOrgs>,
    /// The day's top orgs by remote-desktop minutes.
    pub top_orgs: Measured<Vec<TopOrg>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferrerRow {
    pub host: String,
    pub channel: String,
    pub visitors: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRow {
    pub path: String,
    pub visitors: i64,
    pub pageviews: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Website {
    pub visitors: Figure,
    pub visits: Figure,
    pub pageviews: Figure,
    /// The day's visitors by organic channel (`campaign::Channel`).
    pub channels: Vec<KeyCount>,
    pub top_referrers: Vec<ReferrerRow>,
    pub top_paths: Vec<PathRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlogPost {
    pub path: String,
    pub visitors: i64,
    pub pageviews: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reads: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_read_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blog {
    pub posts: Vec<BlogPost>,
    pub top_sources: Vec<KeyCount>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignGoals {
    pub signup: i64,
    pub subscribe: i64,
    pub install_copy: i64,
    pub github_outbound: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignRow {
    pub source: String,
    pub medium: String,
    pub campaign: String,
    pub visitors: i64,
    pub pageviews: i64,
    /// Goal conversions — `not_measured` when the purestat site has no
    /// definition for a goal (the row's visitors are still real).
    pub goals: Measured<CampaignGoals>,
    /// MeshHarbor's own sign-ups of the day with the same key.
    pub signups: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Campaigns {
    pub rows: Vec<CampaignRow>,
    /// Why no row carries conversions: a goal the purestat site does not
    /// define (2026-10-14: the site had no goals at all, and the whole
    /// section read "not measured" for one missing definition).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversions: Option<NotMeasured>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRow {
    pub source: String,
    pub new: i64,
    pub confirmed: i64,
    pub unsubscribed: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueCountsOut {
    pub total: i64,
    pub sent: i64,
    pub failed: i64,
    pub suppressed: i64,
    pub stale: i64,
}

/// P5 — what SendGrid's signed Event Webhook reported for one issue's
/// messages so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueDelivery {
    pub delivered: i64,
    /// Every bounce, hard and blocked.
    pub bounced: i64,
    /// Hard bounces — each suppressed its address.
    pub hard_bounced: i64,
    pub dropped: i64,
    /// Spam reports — each suppressed its address.
    pub complaints: i64,
}

impl From<meshharbor_services::dao::newsletter_send::DeliveryCounts> for IssueDelivery {
    fn from(c: meshharbor_services::dao::newsletter_send::DeliveryCounts) -> Self {
        Self {
            delivered: c.delivered,
            bounced: c.bounced,
            hard_bounced: c.hard_bounced,
            dropped: c.dropped,
            complaints: c.complaints,
        }
    }
}

/// A stored issue row from before P5 had no delivery: not recorded.
fn delivery_unrecorded() -> Measured<IssueDelivery> {
    Measured::NotMeasured(NotMeasured::now(super::newsletter::SENT_UNRECORDED))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssueRow {
    pub slug: String,
    pub subject: String,
    pub sent_at: String,
    pub counts: IssueCountsOut,
    /// P5 — the issue's delivery so far (the webhook's events), or why it
    /// is not measured.
    #[serde(default = "delivery_unrecorded")]
    pub delivery: Measured<IssueDelivery>,
    /// P5 — subscribers whose current unsubscription came through this
    /// issue's own link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsubscribed_via: Option<i64>,
    /// P5 — the `utm_campaign` its links carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
}

/// P5 — SendGrid's events in the windows, each by the event's own time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryFigures {
    pub delivered: Figure,
    pub bounced: Figure,
    pub hard_bounced: Figure,
    pub dropped: Figure,
    /// Spam reports.
    pub complaints: Figure,
    /// Addresses suppressed (a hard bounce or a spam report).
    pub suppressed: Figure,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Newsletter {
    pub new: Figure,
    pub confirmed: Figure,
    pub unsubscribed: Figure,
    /// P5 — of the unsubscribes, those through an issue's own link
    /// (`subscribers.unsubscribed_via`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsubscribed_via_issue: Option<Figure>,
    pub by_source: Vec<SourceRow>,
    pub issues: Vec<IssueRow>,
    /// P5 — SendGrid's events in the windows; `not_measured` while this
    /// server does not verify the Event Webhook.
    pub delivery: Measured<DeliveryFigures>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStatusRow {
    pub plan: String,
    pub status: String,
    pub orgs: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MrrEstimate {
    pub cents: f64,
    /// Always true: list price × seats, never billed revenue.
    pub estimate: bool,
    pub basis: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revenue {
    pub orgs_by_plan_status: Vec<PlanStatusRow>,
    pub mrr: MrrEstimate,
    /// P4 — what Stripe billed (`billing_events`); `not_measured` without
    /// the `saas` module. A digest stored before P4 says "arrives with P4".
    pub billed: Measured<BilledFigures>,
    /// P4 — the plan-limit collisions in the windows: the orgs that keep
    /// hitting the ceiling. Absent from a digest stored before P4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_intent: Option<UpgradeIntent>,
}

/// P4 — billed MRR at the day's end in one currency, normalised to a month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrencyMrr {
    /// Lowercase ISO 4217, as Stripe spells it.
    pub currency: String,
    pub mrr_cents: i64,
    pub paying_orgs: i64,
}

/// P4 — what the windows' paid invoices billed, in one currency (every
/// line, prorations included, after coupons, before tax).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrencyBilled {
    pub currency: String,
    pub cents: Figure,
}

/// P4 — billed revenue: MRR at the day's end, and the windows' invoices,
/// failed payments, first payments, cancellations and trials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BilledFigures {
    /// The first day on record (`YYYY-MM-DD`, any org): nothing was
    /// recorded before it, so a window reaching back past it is partial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_since: Option<String>,
    /// Whether the operator's backfill has read Stripe's history; until it
    /// has, the figures cover only what the webhook delivered since it was
    /// wired (an existing subscriber counts from their next invoice).
    #[serde(default)]
    pub backfilled: bool,
    pub mrr: Vec<CurrencyMrr>,
    pub invoices_paid: Figure,
    pub billed: Vec<CurrencyBilled>,
    pub payment_failures: Figure,
    /// Orgs whose first invoice above 0 was paid in the window.
    pub new_paying_orgs: Figure,
    /// Subscriptions deleted.
    pub cancellations: Figure,
    pub trials_started: Figure,
}

/// P4 — one org's collisions with one limit in the 28-day window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollisionOrg {
    pub tenant_id: String,
    /// Client-chosen text.
    pub name: String,
    /// The limit's wire spelling (`max_members`, `max_devices`, …).
    pub limit: String,
    pub count: i64,
}

/// P4 — quota collisions (`growth_daily {source: quota}`), the
/// upgrade-intent signal: how many, in how many orgs, and the orgs that hit
/// hardest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpgradeIntent {
    pub collisions: Figure,
    pub orgs: Figure,
    /// At most [`TOP_ORGS`] (org, limit) pairs, by their 28-day count.
    pub top: Vec<CollisionOrg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndReasonRow {
    pub reason: String,
    /// `hangup` · `refusal` · `failure` · `other`.
    pub class: String,
    pub count: i64,
}

/// P9a — one window's distribution: the sample size and the exact p50 /
/// p90 (live from `remote_sessions`, which are kept).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistSummary {
    pub n: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p90: Option<i64>,
}

/// P9a — a [`DistSummary`] of the day, and of the trailing 7 and 28 days.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistFigure {
    pub day: DistSummary,
    pub d7: DistSummary,
    pub d28: DistSummary,
}

/// P9a — a percentile per window, `None` where there was no sample.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptFigure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d7: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d28: Option<i64>,
}

/// P9a — a rate per window, each only from the n floor ([`SMALL_N`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct RateFigure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d7: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d28: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteQuality {
    /// Sessions ENDED in the window (`ended_at`), and their reasons.
    pub ended: Figure,
    pub hangups: Figure,
    pub refusals: Figure,
    pub failures: Figure,
    pub by_end_reason: Vec<EndReasonRow>,
    /// P9a — sessions REQUESTED in the window (`created_at`) …
    #[serde(default)]
    pub requested: Figure,
    /// … of which reached Active (`started_at` set), …
    #[serde(default)]
    pub reached_active: Figure,
    /// … and of which ended without ever reaching it.
    #[serde(default)]
    pub not_reached: Figure,
    /// `reached_active / requested`, only from 30 requested.
    #[serde(default)]
    pub reached_share: RateFigure,
    /// Active sessions that ended: `ended_at − started_at`, milliseconds.
    #[serde(default)]
    pub duration_ms: DistFigure,
    /// `stats.peak_fps` of the Active sessions that reported one.
    #[serde(default)]
    pub peak_fps: DistFigure,
    /// `stats.avg_rtt_ms` of the Active sessions that reported one.
    #[serde(default)]
    pub avg_rtt_ms: DistFigure,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Crashes {
    pub total: Figure,
    /// By the version the crash payload named (`agentVersion`).
    pub by_agent_version: Vec<KeyCount>,
    /// P9a — devices online per day, summed (`stats_machine_1d`).
    #[serde(default)]
    pub device_days: Figure,
    /// P9a — `total × 100 / device_days`, only from 30 device-days.
    #[serde(default)]
    pub per_100_device_days: RateFigure,
}

/// P9a — FR-22's time to first frame, from the frozen daily rows
/// (`growth_quality_daily`): foreground tabs, first attempts, no drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtffFigures {
    /// Records in the distribution.
    pub n: Figure,
    /// Frozen days of the window whose TTFF was measured.
    pub days_measured: Figure,
    pub p50_ms: OptFigure,
    pub p90_ms: OptFigure,
    /// `d7` and `d28` are estimates from the daily histograms; `day` is
    /// exact.
    pub windows_estimated: bool,
    /// Records set aside: a hidden tab, and later attempts or a retry
    /// after a drop.
    pub hidden: Figure,
    pub later_attempts: Figure,
}

/// P9a — one agent version on the day, from its frozen row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionDayRow {
    pub agent_version: String,
    pub requested: i64,
    pub reached_active: i64,
    pub not_reached: i64,
    /// Sessions that ended on a failure-class reason, Active or not.
    pub failures: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttff_n: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttff_p50_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttff_p90_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crashes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_days: Option<i64>,
}

/// A row stored before P9a has neither field: both read as not measured.
fn quality_before_p9a<T>() -> Measured<T> {
    Measured::NotMeasured(NotMeasured::later(
        "time to first frame and the per-version table",
        "P9a",
    ))
}

/// P9b — what people answered the viewer's post-session prompt (spec §3f,
/// D10): thumbs per window, and the reason chips over 28 days. Counts of
/// **answers** — one person's rating of one session; a session with two
/// parties can carry two — never of sessions and never who answered; a
/// share only from [`SMALL_N`] answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ratings {
    pub up: Figure,
    pub down: Figure,
    /// `up + down`: answers, not sessions.
    pub rated: Figure,
    /// `up / rated` over 28 days, only from [`SMALL_N`] answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_share_28d: Option<f64>,
    pub n_floor: i64,
    /// The reason chips ticked in 28 days, most often first.
    pub reasons_28d: Vec<KeyCount>,
}

/// A row stored before P9b has no `ratings`: it reads as not measured.
fn quality_before_p9b<T>() -> Measured<T> {
    Measured::NotMeasured(NotMeasured::later("the post-session ratings", "P9b"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Quality {
    pub remote: Measured<RemoteQuality>,
    pub crashes: Measured<Crashes>,
    /// P9a — from the frozen rows; `not_measured` until the day is frozen.
    #[serde(default = "quality_before_p9a")]
    pub ttff: Measured<TtffFigures>,
    /// P9a — the day by agent version, from the frozen rows; newest first.
    #[serde(default = "quality_before_p9a")]
    pub by_agent_version: Measured<Vec<VersionDayRow>>,
    /// P9b — the viewer's post-session ratings; `not_measured` while the
    /// prompt is off on this server (`MESHHARBOR__GROWTH__FEEDBACK`).
    #[serde(default = "quality_before_p9b")]
    pub ratings: Measured<Ratings>,
}

/// P8 — the posts one platform published in the windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialPlatform {
    pub platform: String,
    pub posts: Figure,
}

/// P8 — one snapshot taken on the day: the platform's own numbers, raw
/// metric names, for the post its campaign names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SocialSnapshot {
    pub platform: String,
    pub platform_id: String,
    /// `T+1d` · `T+7d` · `T+28d`.
    pub snapshot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    pub metrics: BTreeMap<String, f64>,
}

/// P8 — social reach (spec §3l): posts published per platform, and the
/// snapshots the pipeline took on the day.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Social {
    pub posts_by_platform: Vec<SocialPlatform>,
    /// At most [`TOP_SOCIAL_SNAPSHOTS`].
    pub snapshots: Vec<SocialSnapshot>,
}

/// P10 — one alert as the digest lists it: the rule, its key, when it
/// fired and cleared, and the numbers behind it. Never a person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRow {
    pub rule: String,
    pub key: String,
    /// RFC 3339.
    pub fired_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<String>,
    #[serde(default)]
    pub detail: Document,
}

/// P10 — the day's alerts: the rows that fired or cleared during the day,
/// and the ones still open when the digest was computed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertsSection {
    pub fired: Vec<AlertRow>,
    pub cleared: Vec<AlertRow>,
    pub open: Vec<AlertRow>,
}

/// A row stored before P10 has no `alerts` field: it reads as not measured.
fn alerts_before_p10() -> Measured<AlertsSection> {
    Measured::NotMeasured(NotMeasured::later("alerts", "P10"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sections {
    pub headline: Headline,
    pub signups: Signups,
    pub orgs_devices: OrgsDevices,
    pub usage: Usage,
    pub website: Measured<Website>,
    pub blog: Measured<Blog>,
    pub campaigns: Measured<Campaigns>,
    pub newsletter: Measured<Newsletter>,
    pub revenue: Revenue,
    pub quality: Quality,
    pub install: Install,
    /// P8 — each platform's own numbers, as the promotion pipeline pushed
    /// them; `not_measured` when nothing was pushed in the 28-day window.
    pub social: Measured<Social>,
    /// P7 — the repository's public counters (cumulative snapshots and
    /// their deltas) and, with a token, its traffic. A row stored before P7
    /// reads both halves as not measured.
    #[serde(default = "super::github::GithubSection::before_p7")]
    pub github: super::github::GithubSection,
    /// P7 — Google over its final days and Bing at its own grain, from the
    /// `saas` pullers' rows. A digest stored before P7 holds
    /// `{not_measured, arrives_with: P7}` here, which still reads as this
    /// type's other arm.
    pub search: Measured<super::search::SearchSection>,
    /// P10 — the alerts that fired or cleared that day and the ones open at
    /// the compute; `not_measured` while `growth.alerts` is off.
    #[serde(default = "alerts_before_p10")]
    pub alerts: Measured<AlertsSection>,
}

/// How an `end_reason` reads in the quality section: a normal hang-up, a
/// refusal at the device, or a failure of the session itself.
pub fn end_reason_class(reason: &str) -> &'static str {
    match reason {
        "controller_hangup" | "agent_hangup" | "host_disconnect" | "admin_terminated"
        | "idle_timeout" => "hangup",
        "user_denied" | "consent_timeout" | "no_prompt_surface" => "refusal",
        "agent_disconnect" | "error" => "failure",
        _ => "other",
    }
}

// ── Reading the sources ──────────────────────────────────────────────────

use super::mounted;

pub(crate) fn excluded_ids(set: &HashSet<ObjectId>) -> Vec<ObjectId> {
    set.iter().copied().collect()
}

pub(crate) fn dt_ms(d: &Document, key: &str) -> Option<i64> {
    d.get_datetime(key).ok().map(|t| t.timestamp_millis())
}

pub(crate) fn str_of(d: &Document, key: &str) -> Option<String> {
    d.get_str(key).ok().map(str::to_string)
}

pub(crate) fn i64_of(d: &Document, key: &str) -> i64 {
    match d.get(key) {
        Some(Bson::Int32(v)) => i64::from(*v),
        Some(Bson::Int64(v)) => *v,
        Some(Bson::Double(v)) => *v as i64,
        _ => 0,
    }
}

pub(crate) async fn find_docs(
    state: &AppState,
    coll: &str,
    filter: Document,
    projection: Document,
) -> Result<Vec<Document>, DigestError> {
    let rows: Vec<Document> = state
        .db
        .collection::<Document>(coll)
        .find(filter)
        .projection(projection)
        .limit(MAX_ROWS)
        .await?
        .try_collect()
        .await?;
    Ok(rows)
}

pub(crate) async fn aggregate(
    state: &AppState,
    coll: &str,
    pipeline: Vec<Document>,
) -> Result<Vec<Document>, DigestError> {
    let rows: Vec<Document> = state
        .db
        .collection::<Document>(coll)
        .aggregate(pipeline)
        .await?
        .try_collect()
        .await?;
    Ok(rows)
}

/// One run's purestat reads. After a fatal error (no key, 401, timeout,
/// unreachable) no further query is sent: the reason is the same and the
/// run should not wait out three more timeouts to learn it.
struct Purestat {
    client: Option<PurestatClient>,
    fatal: Option<PurestatError>,
}

impl Purestat {
    fn from_settings(state: &AppState) -> Self {
        let g = &state.settings.growth;
        Self {
            client: PurestatClient::new(&g.purestat_url, &g.purestat_api_key),
            fatal: None,
        }
    }

    async fn rows(&mut self, q: &Query) -> Result<Vec<Row>, PurestatError> {
        if let Some(e) = &self.fatal {
            return Err(e.clone());
        }
        let Some(client) = &self.client else {
            self.fatal = Some(PurestatError::NotConfigured);
            return Err(PurestatError::NotConfigured);
        };
        match client.query(q).await {
            Ok(rows) => Ok(rows),
            Err(e) => {
                if e.is_fatal() {
                    self.fatal = Some(e.clone());
                }
                Err(e)
            }
        }
    }

    /// [`Self::rows`], retried ONCE without goals when the server answers
    /// that a goal is not defined (a 400 naming it): the breakdown's
    /// visitors are still real, and the missing goal comes back beside
    /// them so the section can say which conversions are not measured.
    async fn rows_or_without_goals(
        &mut self,
        q: &Query,
    ) -> Result<(Vec<Row>, Option<String>), PurestatError> {
        match self.rows(q).await {
            Ok(rows) => Ok((rows, None)),
            Err(e) => match unknown_goal(&e) {
                Some(goal) if !q.goals.is_empty() => {
                    let mut without = q.clone();
                    without.goals.clear();
                    Ok((self.rows(&without).await?, Some(goal)))
                }
                _ => Err(e),
            },
        }
    }
}

/// The sign-up rows of the 28-day window, as read: everything the sections
/// derive from users.
struct UserRows {
    created: Vec<i64>,
    attributed: Vec<i64>,
    day_rows: Vec<SignupRow>,
}

async fn read_users(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<UserRows, DigestError> {
    let docs = find_docs(
        state,
        "users",
        doc! {
            "created_at": w.between(Span::D28),
            "deleted_at": Bson::Null,
            "_id": { "$nin": excluded_ids(&set.users) },
        },
        doc! { "created_at": 1, "signup_attribution": 1, "oauth_providers.provider": 1 },
    )
    .await?;
    let mut out = UserRows {
        created: Vec::with_capacity(docs.len()),
        attributed: Vec::new(),
        day_rows: Vec::new(),
    };
    for d in &docs {
        let Some(t) = dt_ms(d, "created_at") else {
            continue;
        };
        out.created.push(t);
        let attr = d.get_document("signup_attribution").ok();
        if attr.is_some_and(|a| !a.is_empty()) {
            out.attributed.push(t);
        }
        if w.contains(Span::Day, t) {
            let provider = d
                .get_array("oauth_providers")
                .ok()
                .and_then(|a| a.first())
                .and_then(|p| p.as_document())
                .and_then(|p| str_of(p, "provider"))
                .unwrap_or_else(|| "email".to_string());
            let field = |k: &str| attr.and_then(|a| str_of(a, k));
            out.day_rows.push(SignupRow {
                provider,
                source: field("source"),
                medium: field("medium"),
                campaign: field("campaign"),
                content: field("content"),
                landing_path: field("landing_path"),
                referrer_host: field("referrer_host"),
                self_reported: field("self_reported"),
            });
        }
    }
    Ok(out)
}

fn signups_section(w: &Windows, users: &UserRows) -> Signups {
    let mut by_provider: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_source: BTreeMap<String, i64> = BTreeMap::new();
    for r in &users.day_rows {
        *by_provider.entry(r.provider.clone()).or_insert(0) += 1;
        let source = r.source.clone().unwrap_or_else(|| "(none)".to_string());
        *by_source.entry(source).or_insert(0) += 1;
    }
    let rows = (users.day_rows.len() <= MAX_LISTED_SIGNUPS).then(|| users.day_rows.clone());
    Signups {
        total: w.count(users.created.iter().copied()),
        attributed: w.count(users.attributed.iter().copied()),
        by_provider: key_counts(by_provider),
        by_source: key_counts(by_source),
        rows,
    }
}

async fn orgs_created(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<Figure, DigestError> {
    let docs = find_docs(
        state,
        "tenants",
        doc! {
            "created_at": w.between(Span::D28),
            "_id": { "$nin": excluded_ids(&set.tenants) },
        },
        doc! { "created_at": 1 },
    )
    .await?;
    Ok(w.count(docs.iter().filter_map(|d| dt_ms(d, "created_at"))))
}

struct DeviceFacts {
    enrolled: Figure,
    by_os: Vec<KeyCount>,
    first_device: Figure,
    /// P3 — the day's devices by install method.
    by_method: Vec<KeyCount>,
    /// P3 — every window, by (method, OS).
    by_method_os: Vec<MethodRow>,
}

/// P3 — the method a device row says it was installed by: `unknown` for a
/// row from before the install trace and for an agent that did not say.
fn install_method_of(d: &Document) -> String {
    d.get_document("install")
        .ok()
        .and_then(|i| str_of(i, "method"))
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn read_devices(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<DeviceFacts, DigestError> {
    let nin = excluded_ids(&set.tenants);
    // Tombstoned rows count: a device enrolled and removed the same day was
    // still enrolled.
    let docs = find_docs(
        state,
        "agents",
        doc! { "created_at": w.between(Span::D28), "tenant_id": { "$nin": &nin } },
        doc! { "created_at": 1, "os": 1, "install.method": 1 },
    )
    .await?;
    let mut by_os: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_method: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_method_os: BTreeMap<(String, String), Vec<i64>> = BTreeMap::new();
    for d in &docs {
        let Some(t) = dt_ms(d, "created_at") else {
            continue;
        };
        let os = str_of(d, "os").unwrap_or_else(|| "unknown".into());
        let method = install_method_of(d);
        if w.contains(Span::Day, t) {
            *by_os.entry(os.clone()).or_insert(0) += 1;
            *by_method.entry(method.clone()).or_insert(0) += 1;
        }
        by_method_os.entry((method, os)).or_default().push(t);
    }
    let mut by_method_os: Vec<MethodRow> = by_method_os
        .into_iter()
        .map(|((method, os), times)| MethodRow {
            method,
            os,
            enrolled: w.count(times),
        })
        .collect();
    by_method_os.sort_by(|a, b| {
        b.enrolled
            .d28
            .cmp(&a.enrolled.d28)
            .then_with(|| a.method.cmp(&b.method))
            .then_with(|| a.os.cmp(&b.os))
    });
    let firsts = aggregate(
        state,
        "agents",
        vec![
            doc! { "$match": { "tenant_id": { "$nin": &nin } } },
            doc! { "$group": { "_id": "$tenant_id", "first": { "$min": "$created_at" } } },
            doc! { "$match": { "first": w.between(Span::D28) } },
        ],
    )
    .await?;
    Ok(DeviceFacts {
        enrolled: w.count(docs.iter().filter_map(|d| dt_ms(d, "created_at"))),
        by_os: key_counts(by_os),
        first_device: w.count(firsts.iter().filter_map(|d| dt_ms(d, "first"))),
        by_method: key_counts(by_method),
        by_method_os,
    })
}

/// P3 — standard enrollment tokens issued in the 28-day window (by
/// `enroll_token_issued`), and which of them were redeemed. A token's
/// tenant is what the exclusion set filters on.
async fn read_tokens(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<Tokens, DigestError> {
    let docs = find_docs(
        state,
        meshharbor_services::dao::enroll_token_issued::ENROLL_TOKEN_ISSUED,
        doc! {
            "issued_at": w.between(Span::D28),
            "tenant_id": { "$nin": excluded_ids(&set.tenants) },
        },
        doc! { "issued_at": 1, "redeemed_at": 1 },
    )
    .await?;
    let issued: Vec<i64> = docs.iter().filter_map(|d| dt_ms(d, "issued_at")).collect();
    let redeemed: Vec<i64> = docs
        .iter()
        .filter(|d| d.get_datetime("redeemed_at").is_ok())
        .filter_map(|d| dt_ms(d, "issued_at"))
        .collect();
    Ok(Tokens {
        issued: w.count(issued),
        redeemed: w.count(redeemed),
    })
}

/// P3 — the fetch counters of the 28-day window, as `growth_daily` holds
/// them (`install:fetch:{asset, client, os}` per day), summed into the three
/// windows. A row's day is a `YYYY-MM-DD` string, so the windows are string
/// comparisons against the dates the windows start on.
///
/// P3c — the `internal` rows (fetches from the operator's internal
/// networks) never reach the table: they are summed into the second value,
/// whatever their asset. It is `not_measured` only while this server names
/// no internal network AND the window holds no internal row — rows counted
/// while a network was configured are a measurement whatever the setting
/// says today.
async fn read_fetches(
    state: &AppState,
    w: &Windows,
) -> Result<(Vec<FetchRow>, Measured<Figure>), DigestError> {
    use meshharbor_services::dao::growth::{
        INSTALL_FETCH_METRIC, INSTALL_INTERNAL_CLIENT, INSTALL_SOURCE,
    };
    let (day, d7, d28) = w.dates();
    let rows = GrowthDao::new(&state.db)
        .read_daily(INSTALL_SOURCE, INSTALL_FETCH_METRIC, &d28, &day)
        .await?;
    let mut by: BTreeMap<(String, String, String), Figure> = BTreeMap::new();
    let mut internal = Figure::default();
    let mut internal_rows = 0usize;
    for r in rows {
        let dim = |k: &str| r.dims.get(k).cloned().unwrap_or_else(|| "unknown".into());
        let f = if dim("client") == INSTALL_INTERNAL_CLIENT {
            internal_rows += 1;
            &mut internal
        } else {
            by.entry((dim("asset"), dim("client"), dim("os")))
                .or_default()
        };
        if r.day == day {
            f.day += r.value;
        }
        if r.day >= d7 {
            f.d7 += r.value;
        }
        f.d28 += r.value;
    }
    let (networks, refused) =
        meshharbor_core::growth::InternalNetworks::parse(&state.settings.growth.internal_networks);
    let internal = if networks.is_empty() && internal_rows == 0 {
        // Two reasons for one state, said apart: nothing written, or nothing
        // usable written (the boot warning names each entry and why).
        Measured::NotMeasured(NotMeasured::now(if refused.is_empty() {
            "no internal network configured on this server (growth.internal_networks)"
        } else {
            "no usable entry in growth.internal_networks (see the boot warning)"
        }))
    } else {
        Measured::Value(internal)
    };
    let mut out: Vec<FetchRow> = by
        .into_iter()
        .map(|((asset, client, os), fetches)| FetchRow {
            asset,
            client,
            os,
            fetches,
        })
        .collect();
    out.sort_by(|a, b| {
        b.fetches
            .d28
            .cmp(&a.fetches.d28)
            .then_with(|| a.asset.cmp(&b.asset))
            .then_with(|| a.client.cmp(&b.client))
            .then_with(|| a.os.cmp(&b.os))
    });
    Ok((out, internal))
}

/// Per-span sets of distinct run ids — the P3b counting unit.
#[derive(Default)]
struct RunSets {
    day: HashSet<String>,
    d7: HashSet<String>,
    d28: HashSet<String>,
}

impl RunSets {
    fn add(&mut self, w: &Windows, t: i64, run: &str) {
        if w.contains(Span::Day, t) {
            self.day.insert(run.to_string());
        }
        if w.contains(Span::D7, t) {
            self.d7.insert(run.to_string());
        }
        if w.contains(Span::D28, t) {
            self.d28.insert(run.to_string());
        }
    }

    fn figure(&self) -> Figure {
        Figure {
            day: self.day.len() as i64,
            d7: self.d7.len() as i64,
            d28: self.d28.len() as i64,
        }
    }
}

/// P3b — the wizard's opt-in step diagnostics of the 28-day window, as
/// `setup_diagnostics` holds them: distinct runs per step and outcome, and
/// per failing code. The rows outlive nothing (90 days) but cover every
/// window the digest reads; the nightly freeze keeps the daily counts.
async fn read_wizard_steps(state: &AppState, w: &Windows) -> Result<WizardSteps, DigestError> {
    let rows = SetupDiagnosticsDao::new(&state.db)
        .rows_between(w.start_dt(Span::D28), w.end_dt())
        .await?;
    if rows.len() as i64 >= meshharbor_services::dao::setup_diagnostics::MAX_READ_ROWS {
        warn!(
            rows = rows.len(),
            "setup_diagnostics: the digest's read hit its row bound; the counts are a floor"
        );
    }
    let mut runs = RunSets::default();
    let mut reached: BTreeMap<usize, RunSets> = BTreeMap::new();
    let mut by_outcome: BTreeMap<(usize, Outcome), RunSets> = BTreeMap::new();
    let mut errors: BTreeMap<(usize, String), RunSets> = BTreeMap::new();
    for r in &rows {
        let (Some(step), Some(outcome)) = (Step::parse(&r.step), Outcome::parse(&r.outcome)) else {
            // A spelling this build does not know (a newer wizard's): it is
            // not a row of any step we can name, so it costs itself only.
            continue;
        };
        let t = r.ts.timestamp_millis();
        runs.add(w, t, &r.run);
        reached.entry(step.index()).or_default().add(w, t, &r.run);
        by_outcome
            .entry((step.index(), outcome))
            .or_default()
            .add(w, t, &r.run);
        if outcome == Outcome::Failed
            && let Some(code) = &r.error_code
        {
            errors
                .entry((step.index(), code.clone()))
                .or_default()
                .add(w, t, &r.run);
        }
    }
    let outcome_figure = |idx: usize, o: Outcome| {
        by_outcome
            .get(&(idx, o))
            .map(RunSets::figure)
            .unwrap_or_default()
    };
    let steps: Vec<WizardStepRow> = Step::ALL
        .iter()
        .filter_map(|s| {
            let sets = reached.get(&s.index())?;
            Some(WizardStepRow {
                step: s.wire().to_string(),
                reached: sets.figure(),
                ok: outcome_figure(s.index(), Outcome::Ok),
                failed: outcome_figure(s.index(), Outcome::Failed),
                cancelled: outcome_figure(s.index(), Outcome::Cancelled),
            })
        })
        .collect();
    let mut errors: Vec<WizardErrorRow> = errors
        .into_iter()
        .map(|((idx, code), sets)| WizardErrorRow {
            step: Step::ALL[idx].wire().to_string(),
            error_code: code,
            failures: sets.figure(),
        })
        .collect();
    errors.sort_by(|a, b| {
        b.failures
            .d28
            .cmp(&a.failures.d28)
            .then_with(|| {
                Step::parse(&a.step)
                    .map(Step::index)
                    .cmp(&Step::parse(&b.step).map(Step::index))
            })
            .then_with(|| a.error_code.cmp(&b.error_code))
    });
    let runs = runs.figure();
    let done_28d = reached
        .get(&Step::Done.index())
        .map(|s| s.figure().d28)
        .unwrap_or(0);
    Ok(WizardSteps {
        runs,
        n_floor: SMALL_N,
        done_share_28d: (runs.d28 >= SMALL_N).then(|| done_28d as f64 / runs.d28 as f64),
        steps,
        errors,
    })
}

/// Per-span tenant sets with a value event.
#[derive(Default)]
struct ValueOrgs {
    day: HashSet<ObjectId>,
    d7: HashSet<ObjectId>,
    d28: HashSet<ObjectId>,
}

impl ValueOrgs {
    fn add(&mut self, w: &Windows, t: i64, tenant: ObjectId) {
        if w.contains(Span::Day, t) {
            self.day.insert(tenant);
        }
        if w.contains(Span::D7, t) {
            self.d7.insert(tenant);
        }
        if w.contains(Span::D28, t) {
            self.d28.insert(tenant);
        }
    }

    fn union(&mut self, other: &ValueOrgs) {
        self.day.extend(&other.day);
        self.d7.extend(&other.d7);
        self.d28.extend(&other.d28);
    }
}

struct RemoteFacts {
    usage: RemoteUsage,
    value: ValueOrgs,
    /// tenant → (day minutes, day sessions started)
    per_org_day: HashMap<ObjectId, (i64, i64)>,
}

async fn read_remote_usage(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
    now_ms: i64,
) -> Result<RemoteFacts, DigestError> {
    let docs = find_docs(
        state,
        "remote_sessions",
        doc! {
            "started_at": { "$ne": Bson::Null, "$lt": w.end_dt() },
            "$or": [ { "ended_at": Bson::Null }, { "ended_at": { "$gte": w.start_dt(Span::D28) } } ],
            "tenant_id": { "$nin": excluded_ids(&set.tenants) },
        },
        doc! { "tenant_id": 1, "started_at": 1, "ended_at": 1 },
    )
    .await?;
    let mut started = Vec::new();
    let mut ms = [0i64; 3];
    let mut value = ValueOrgs::default();
    let mut per_org_day: HashMap<ObjectId, (i64, i64)> = HashMap::new();
    for d in &docs {
        let (Some(s), Ok(tenant)) = (dt_ms(d, "started_at"), d.get_object_id("tenant_id")) else {
            continue;
        };
        let e = dt_ms(d, "ended_at").unwrap_or(now_ms).max(s);
        started.push(s);
        for (i, span) in [Span::Day, Span::D7, Span::D28].into_iter().enumerate() {
            let (lo, hi) = w.range(span);
            ms[i] += overlap_ms(s, e, lo, hi);
        }
        if super::value::rc_session_is_value(s, e) {
            value.add(w, s, tenant);
        }
        let (lo, hi) = w.range(Span::Day);
        let day_ms = overlap_ms(s, e, lo, hi);
        if day_ms > 0 || w.contains(Span::Day, s) {
            let entry = per_org_day.entry(tenant).or_insert((0, 0));
            entry.0 += day_ms;
            if w.contains(Span::Day, s) {
                entry.1 += 1;
            }
        }
    }
    Ok(RemoteFacts {
        usage: RemoteUsage {
            sessions_started: w.count(started),
            session_minutes: FigureF {
                day: minutes(ms[0]),
                d7: minutes(ms[1]),
                d28: minutes(ms[2]),
            },
        },
        value,
        per_org_day,
    })
}

struct CallFacts {
    usage: CallUsage,
    value: ValueOrgs,
}

async fn read_calls(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<CallFacts, DigestError> {
    let docs = find_docs(
        state,
        "call_sessions",
        doc! {
            "started_at": w.between(Span::D28),
            "tenant_id": { "$nin": excluded_ids(&set.tenants) },
        },
        doc! { "tenant_id": 1, "started_at": 1, "peak_participants": 1, "participant_seconds": 1 },
    )
    .await?;
    let mut started = Vec::new();
    let mut secs = [0i64; 3];
    let mut value = ValueOrgs::default();
    for d in &docs {
        let (Some(s), Ok(tenant)) = (dt_ms(d, "started_at"), d.get_object_id("tenant_id")) else {
            continue;
        };
        started.push(s);
        let ps = i64_of(d, "participant_seconds");
        for (i, span) in [Span::Day, Span::D7, Span::D28].into_iter().enumerate() {
            if w.contains(span, s) {
                secs[i] += ps;
            }
        }
        if super::value::call_is_value(i64_of(d, "peak_participants")) {
            value.add(w, s, tenant);
        }
    }
    Ok(CallFacts {
        usage: CallUsage {
            calls: w.count(started),
            participant_minutes: FigureF {
                day: minutes(secs[0] * 1000),
                d7: minutes(secs[1] * 1000),
                d28: minutes(secs[2] * 1000),
            },
        },
        value,
    })
}

/// P2 — the network pillar's value events in the 28-day window: tunnel
/// flows accepted and SSH grants issued (`value.rs`), from audit rows that
/// still exist at 28 days. With them, the digest's "active orgs" is the
/// same set `growth_org_daily` marks `value`.
async fn read_network_value(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<ValueOrgs, DigestError> {
    let mut value = ValueOrgs::default();
    let nin = excluded_ids(&set.tenants);
    for (coll, mut filter) in [
        (
            "tunnel_audit",
            super::value::tunnel_flow_filter(w.between(Span::D28)),
        ),
        (
            "ssh_audit",
            super::value::ssh_session_filter(w.between(Span::D28)),
        ),
    ] {
        filter.insert("tenant_id", doc! { "$nin": &nin });
        let docs = find_docs(state, coll, filter, doc! { "tenant_id": 1, "at": 1 }).await?;
        for d in &docs {
            if let (Some(t), Ok(tenant)) = (dt_ms(d, "at"), d.get_object_id("tenant_id")) {
                value.add(w, t, tenant);
            }
        }
    }
    Ok(value)
}

async fn org_names(
    state: &AppState,
    ids: &[ObjectId],
) -> Result<HashMap<ObjectId, String>, DigestError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let docs = find_docs(
        state,
        "tenants",
        doc! { "_id": { "$in": ids } },
        doc! { "name": 1 },
    )
    .await?;
    Ok(docs
        .iter()
        .filter_map(|d| {
            Some((
                d.get_object_id("_id").ok()?,
                str_of(d, "name").unwrap_or_default(),
            ))
        })
        .collect())
}

/// P5 — SendGrid's events in the 28-day window, by each event's own time
/// (`newsletter_sends.delivery`), and the addresses suppressed in it.
async fn delivery_figures(
    state: &AppState,
    w: &Windows,
    suppressed: Vec<i64>,
) -> Result<DeliveryFigures, DigestError> {
    let rows = find_docs(
        state,
        "newsletter_sends",
        doc! { "$or": [
            { "delivery.delivered_at": w.between(Span::D28) },
            { "delivery.bounced_at": w.between(Span::D28) },
            { "delivery.dropped_at": w.between(Span::D28) },
            { "delivery.spam_reported_at": w.between(Span::D28) },
        ] },
        doc! { "delivery": 1 },
    )
    .await?;
    let (mut delivered, mut bounced, mut hard, mut dropped, mut complaints) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for d in rows.iter().filter_map(|r| r.get_document("delivery").ok()) {
        delivered.extend(dt_ms(d, "delivered_at"));
        dropped.extend(dt_ms(d, "dropped_at"));
        complaints.extend(dt_ms(d, "spam_reported_at"));
        if let Some(t) = dt_ms(d, "bounced_at") {
            bounced.push(t);
            if str_of(d, "bounce_type").as_deref() == Some("bounce") {
                hard.push(t);
            }
        }
    }
    Ok(DeliveryFigures {
        delivered: w.count(delivered),
        bounced: w.count(bounced),
        hard_bounced: w.count(hard),
        dropped: w.count(dropped),
        complaints: w.count(complaints),
        suppressed: w.count(suppressed),
    })
}

async fn newsletter_section(state: &AppState, w: &Windows) -> Result<Newsletter, DigestError> {
    let subs = find_docs(
        state,
        "subscribers",
        doc! { "$or": [
            { "created_at": w.between(Span::D28) },
            { "confirmed_at": w.between(Span::D28) },
            { "unsubscribed_at": w.between(Span::D28) },
            { "suppressed_at": w.between(Span::D28) },
        ] },
        doc! {
            "source": 1, "created_at": 1, "confirmed_at": 1, "unsubscribed_at": 1,
            "unsubscribed_via": 1, "suppressed_at": 1,
        },
    )
    .await?;
    let mut by_source: BTreeMap<String, SourceRow> = BTreeMap::new();
    let (mut new, mut confirmed, mut unsubscribed) = (Vec::new(), Vec::new(), Vec::new());
    let (mut via_issue, mut suppressed) = (Vec::new(), Vec::new());
    for d in &subs {
        suppressed.extend(dt_ms(d, "suppressed_at"));
        if let Some(t) = dt_ms(d, "unsubscribed_at")
            && str_of(d, "unsubscribed_via").is_some()
        {
            via_issue.push(t);
        }
        let source = str_of(d, "source").unwrap_or_else(|| "(none)".into());
        let row = by_source
            .entry(source.clone())
            .or_insert_with(|| SourceRow {
                source,
                new: 0,
                confirmed: 0,
                unsubscribed: 0,
            });
        if let Some(t) = dt_ms(d, "created_at") {
            new.push(t);
            if w.contains(Span::Day, t) {
                row.new += 1;
            }
        }
        if let Some(t) = dt_ms(d, "confirmed_at") {
            confirmed.push(t);
            if w.contains(Span::Day, t) {
                row.confirmed += 1;
            }
        }
        if let Some(t) = dt_ms(d, "unsubscribed_at") {
            unsubscribed.push(t);
            if w.contains(Span::Day, t) {
                row.unsubscribed += 1;
            }
        }
    }
    let issues = find_docs(
        state,
        "newsletter_issues",
        doc! { "sent_at": w.between(Span::Day) },
        doc! {
            "slug": 1, "subject": 1, "sent_at": 1, "counts": 1, "status": 1,
            "campaign": 1, "delivery_events": 1,
        },
    )
    .await?;
    // P5 — each issue's delivery so far and its unsubscribes, by the same
    // reads (and the same three cells) as the per-issue table.
    let webhook = super::newsletter::webhook_on(state);
    let facts: Vec<(Document, Option<super::newsletter::IssueFacts>)> = issues
        .into_iter()
        .map(|d| {
            let f = super::newsletter::issue_facts_of(&d);
            (d, f)
        })
        .collect();
    let ids: Vec<ObjectId> = facts
        .iter()
        .filter_map(|(_, f)| f.as_ref().map(|f| f.id))
        .collect();
    let slugs: Vec<String> = facts
        .iter()
        .filter_map(|(_, f)| f.as_ref().map(|f| f.slug.clone()))
        .collect();
    let delivery = meshharbor_services::dao::newsletter_send::NewsletterSendDao::new(&state.db)
        .delivery_counts(&ids)
        .await?;
    let via = super::newsletter::unsubscribed_via(state, &slugs).await?;
    let issues = facts
        .iter()
        .map(|(d, f)| {
            let c = d.get_document("counts").ok();
            let n = |k: &str| c.map(|c| i64_of(c, k)).unwrap_or(0);
            IssueRow {
                slug: str_of(d, "slug").unwrap_or_default(),
                subject: str_of(d, "subject").unwrap_or_default(),
                sent_at: d
                    .get_datetime("sent_at")
                    .ok()
                    .and_then(|t| t.try_to_rfc3339_string().ok())
                    .unwrap_or_default(),
                counts: IssueCountsOut {
                    total: n("total"),
                    sent: n("sent"),
                    failed: n("failed"),
                    suppressed: n("suppressed"),
                    stale: n("stale"),
                },
                delivery: match f {
                    Some(f) => match super::newsletter::delivery_cell(
                        webhook,
                        f,
                        delivery.get(&f.id).copied(),
                    ) {
                        Measured::Value(c) => Measured::Value(c.into()),
                        Measured::NotMeasured(n) => Measured::NotMeasured(n),
                    },
                    None => delivery_unrecorded(),
                },
                unsubscribed_via: f.as_ref().map(|f| via.get(&f.slug).copied().unwrap_or(0)),
                campaign: f.as_ref().and_then(|f| f.campaign.clone()),
            }
        })
        .collect();
    let mut by_source: Vec<SourceRow> = by_source
        .into_values()
        .filter(|r| r.new + r.confirmed + r.unsubscribed > 0)
        .collect();
    by_source.sort_by(|a, b| b.new.cmp(&a.new).then_with(|| a.source.cmp(&b.source)));
    let delivery = if webhook {
        Measured::Value(delivery_figures(state, w, suppressed).await?)
    } else {
        Measured::NotMeasured(NotMeasured::now(super::newsletter::WEBHOOK_OFF))
    };
    Ok(Newsletter {
        new: w.count(new),
        confirmed: w.count(confirmed),
        unsubscribed: w.count(unsubscribed),
        unsubscribed_via_issue: Some(w.count(via_issue)),
        by_source,
        issues,
        delivery,
    })
}

/// P4 — why billed revenue is not measured while nothing is on record, as
/// the operator's newest backfill (its `growth_pulls` row) says: not run,
/// run and recording nothing — no paid invoice it read names an org on
/// this server — or run and recording rows that have since gone with their
/// org. Read, never assumed: a fixed "the backfill has not run" went on
/// saying so after a real one (2026-10-17: one paid invoice read, naming no
/// org here).
pub fn no_billing_record(
    backfill: Option<&meshharbor_services::dao::growth::GrowthPull>,
) -> String {
    match backfill {
        None => "no billing event on record yet: none from Stripe's webhook, and the backfill \
                 has not run"
            .to_string(),
        Some(p) if p.rows == 0 => format!(
            "no billing event on record yet: none from Stripe's webhook, and the backfill on {} \
             recorded no paid invoice — none it read names an org on this server",
            p.day
        ),
        Some(p) => format!(
            "no billing event on record: none from Stripe's webhook, and the {} the backfill on \
             {} recorded have since been deleted with their org",
            p.rows, p.day
        ),
    }
}

/// P4 — the billed figures of the windows, pure over `billing_events`
/// rows (exclusions already applied): MRR at the day's end per currency,
/// and every count by the instant it happened. `record_since` and
/// `backfilled` are the caller's (they read the whole record).
pub fn billed_figures(
    rows: &[meshharbor_services::dao::billing_event::BillingEvent],
    w: &Windows,
    record_since: Option<String>,
    backfilled: bool,
) -> BilledFigures {
    use meshharbor_services::{billing, dao::billing_event::BillingKind};
    let orgs = billing::fold(rows);
    let at = w.day_end - 1;
    let mut mrr: BTreeMap<String, CurrencyMrr> = BTreeMap::new();
    for o in orgs.values() {
        let cents = o.mrr_at(at);
        if cents <= 0 {
            continue;
        }
        let currency = o.currency.clone().unwrap_or_else(|| "unknown".into());
        let e = mrr.entry(currency.clone()).or_insert(CurrencyMrr {
            currency,
            mrr_cents: 0,
            paying_orgs: 0,
        });
        e.mrr_cents += cents;
        e.paying_orgs += 1;
    }
    let times = |kind: BillingKind| -> Vec<i64> {
        rows.iter()
            .filter(|r| r.kind == kind)
            .map(|r| r.ts.timestamp_millis())
            .collect()
    };
    let mut billed: BTreeMap<String, Figure> = BTreeMap::new();
    for r in rows.iter().filter(|r| r.kind == BillingKind::InvoicePaid) {
        let t = r.ts.timestamp_millis();
        let cents = r.amount_cents.unwrap_or(0);
        let f = billed
            .entry(r.currency.clone().unwrap_or_else(|| "unknown".into()))
            .or_default();
        if w.contains(Span::Day, t) {
            f.day += cents;
        }
        if w.contains(Span::D7, t) {
            f.d7 += cents;
        }
        if w.contains(Span::D28, t) {
            f.d28 += cents;
        }
    }
    BilledFigures {
        record_since,
        backfilled,
        mrr: mrr.into_values().collect(),
        invoices_paid: w.count(times(BillingKind::InvoicePaid)),
        billed: billed
            .into_iter()
            .filter(|(_, f)| *f != Figure::default())
            .map(|(currency, cents)| CurrencyBilled { currency, cents })
            .collect(),
        payment_failures: w.count(times(BillingKind::InvoicePaymentFailed)),
        new_paying_orgs: w.count(orgs.values().filter_map(|o| o.paid_since)),
        cancellations: w.count(times(BillingKind::SubscriptionDeleted)),
        trials_started: w.count(orgs.values().filter_map(|o| o.trial_started)),
    }
}

/// P4 — `billing_events` (internal orgs left out), as [`billed_figures`];
/// `not_measured` while nothing at all is on record — "no paying org" is
/// a claim only a record can make.
async fn billed_section(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<Measured<BilledFigures>, DigestError> {
    use meshharbor_services::billing;
    let Some(first) = billing::record_start(&state.db).await? else {
        let backfill = billing::last_backfill(&state.db).await?;
        return Ok(Measured::NotMeasured(NotMeasured::now(no_billing_record(
            backfill.as_ref(),
        ))));
    };
    let rows = meshharbor_services::dao::billing_event::BillingEventDao::new(&state.db)
        .list(None, &excluded_ids(&set.tenants))
        .await?;
    let backfilled = billing::last_backfill(&state.db).await?.is_some();
    Ok(Measured::Value(billed_figures(
        &rows,
        w,
        Some(day_str(utc_date_of(DateTime::from_millis(first)))),
        backfilled,
    )))
}

/// P4 — the quota collisions of the windows, from the per-day counters
/// `meshharbor_core::quota` bumps (core: read whatever modules are mounted).
/// The org is the `tenant` dimension, so an excluded org's rows are left
/// out here, at read time.
async fn upgrade_intent_section(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<UpgradeIntent, DigestError> {
    use meshharbor_services::dao::growth::{QUOTA_COLLISION_METRIC, QUOTA_SOURCE};
    let (day, _, d28) = w.dates();
    let rows = GrowthDao::new(&state.db)
        .read_daily(QUOTA_SOURCE, QUOTA_COLLISION_METRIC, &d28, &day)
        .await?;
    let mut collisions = Figure::default();
    let (mut orgs_day, mut orgs_d7, mut orgs_d28) =
        (HashSet::new(), HashSet::new(), HashSet::new());
    let mut per_pair: BTreeMap<(ObjectId, String), i64> = BTreeMap::new();
    for r in &rows {
        let (Some(tenant), Ok(d)) = (
            r.dims
                .get("tenant")
                .and_then(|t| ObjectId::parse_str(t).ok()),
            parse_day(&r.day),
        ) else {
            continue;
        };
        if set.tenant_excluded(&tenant) {
            continue;
        }
        let t = midnight_ms(d);
        if w.contains(Span::Day, t) {
            collisions.day += r.value;
            orgs_day.insert(tenant);
        }
        if w.contains(Span::D7, t) {
            collisions.d7 += r.value;
            orgs_d7.insert(tenant);
        }
        if w.contains(Span::D28, t) {
            collisions.d28 += r.value;
            orgs_d28.insert(tenant);
            let limit = r.dims.get("limit").cloned().unwrap_or_default();
            *per_pair.entry((tenant, limit)).or_insert(0) += r.value;
        }
    }
    let mut top: Vec<((ObjectId, String), i64)> = per_pair.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(TOP_ORGS);
    let ids: Vec<ObjectId> = top.iter().map(|((t, _), _)| *t).collect();
    let names = org_names(state, &ids).await?;
    Ok(UpgradeIntent {
        collisions,
        orgs: Figure {
            day: orgs_day.len() as i64,
            d7: orgs_d7.len() as i64,
            d28: orgs_d28.len() as i64,
        },
        top: top
            .into_iter()
            .map(|((tenant, limit), count)| CollisionOrg {
                tenant_id: tenant.to_hex(),
                name: names.get(&tenant).cloned().unwrap_or_default(),
                limit,
                count,
            })
            .collect(),
    })
}

async fn revenue_section(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<Revenue, DigestError> {
    let nin = excluded_ids(&set.tenants);
    let tenants = find_docs(
        state,
        "tenants",
        doc! { "deleted_at": Bson::Null, "_id": { "$nin": &nin } },
        doc! { "plan": 1, "billing.status": 1 },
    )
    .await?;
    let seats = aggregate(
        state,
        "tenant_members",
        vec![
            doc! { "$match": { "tenant_id": { "$nin": &nin } } },
            doc! { "$group": { "_id": "$tenant_id", "seats": { "$sum": 1 } } },
        ],
    )
    .await?;
    let seats: HashMap<ObjectId, i64> = seats
        .iter()
        .filter_map(|d| Some((d.get_object_id("_id").ok()?, i64_of(d, "seats"))))
        .collect();
    let mut by: BTreeMap<(String, String), i64> = BTreeMap::new();
    let mut cents = 0.0;
    for t in &tenants {
        let plan_raw = str_of(t, "plan").unwrap_or_else(|| "free".into());
        let plan: Plan = bson::from_bson(Bson::String(plan_raw.clone())).unwrap_or(Plan::Free);
        let status = t
            .get_document("billing")
            .ok()
            .and_then(|b| str_of(b, "status"))
            .unwrap_or_else(|| "none".into());
        *by.entry((plan_raw, status)).or_insert(0) += 1;
        let n = t
            .get_object_id("_id")
            .ok()
            .and_then(|id| seats.get(&id).copied())
            .unwrap_or(0);
        cents += crate::routes::cost::mrr_estimate_cents(&plan, n as f64);
    }
    Ok(Revenue {
        orgs_by_plan_status: by
            .into_iter()
            .map(|((plan, status), orgs)| PlanStatusRow { plan, status, orgs })
            .collect(),
        mrr: MrrEstimate {
            cents,
            estimate: true,
            basis: "list price × seats (plan.price_monthly_cents), not billed revenue".into(),
        },
        // P4 — billed revenue is the `saas` module's (`billing_events`);
        // the collisions are core's and read on every server.
        billed: if mounted(state, "saas") {
            billed_section(state, w, set).await?
        } else {
            Measured::unmounted("saas")
        },
        upgrade_intent: Some(upgrade_intent_section(state, w, set).await?),
    })
}

fn summary(d: &Dist) -> DistSummary {
    DistSummary {
        n: d.n,
        p50: d.p50,
        p90: d.p90,
    }
}

async fn remote_quality(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<RemoteQuality, DigestError> {
    let excluded = excluded_ids(&set.tenants);
    let docs = find_docs(
        state,
        "remote_sessions",
        doc! {
            "ended_at": w.between(Span::D28),
            "tenant_id": { "$nin": excluded.clone() },
        },
        doc! { "ended_at": 1, "end_reason": 1 },
    )
    .await?;
    let mut ended = Vec::new();
    let mut by_class: HashMap<&'static str, Vec<i64>> = HashMap::new();
    let mut day_reasons: BTreeMap<String, i64> = BTreeMap::new();
    for d in &docs {
        let Some(t) = dt_ms(d, "ended_at") else {
            continue;
        };
        ended.push(t);
        let reason = str_of(d, "end_reason").unwrap_or_else(|| "unknown".into());
        by_class
            .entry(end_reason_class(&reason))
            .or_default()
            .push(t);
        if w.contains(Span::Day, t) {
            *day_reasons.entry(reason).or_insert(0) += 1;
        }
    }
    let class_figure = |c: &str| w.count(by_class.get(c).into_iter().flatten().copied());
    let mut by_end_reason: Vec<EndReasonRow> = day_reasons
        .into_iter()
        .map(|(reason, count)| EndReasonRow {
            class: end_reason_class(&reason).to_string(),
            reason,
            count,
        })
        .collect();
    by_end_reason.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));

    // P9a — the sessions REQUESTED in the windows, by what became of them,
    // and the duration, frame-rate and RTT distributions of the Active ones:
    // the rule the nightly freeze applies (`quality::session_quality`), live
    // here because `remote_sessions` are kept.
    let rows: Vec<SessionRow> = find_docs(
        state,
        "remote_sessions",
        doc! { "created_at": w.between(Span::D28), "tenant_id": { "$nin": excluded } },
        session_projection(),
    )
    .await?
    .iter()
    .filter_map(session_row)
    .collect();
    let per = |span: Span| session_quality(rows.iter().filter(|r| w.contains(span, r.created_ms)));
    let (qd, q7, q28) = (per(Span::Day), per(Span::D7), per(Span::D28));
    let count = |f: fn(&SessionQuality) -> i64| Figure {
        day: f(&qd),
        d7: f(&q7),
        d28: f(&q28),
    };
    let dist = |f: fn(&SessionQuality) -> &Dist| DistFigure {
        day: summary(f(&qd)),
        d7: summary(f(&q7)),
        d28: summary(f(&q28)),
    };
    Ok(RemoteQuality {
        ended: w.count(ended),
        hangups: class_figure("hangup"),
        refusals: class_figure("refusal"),
        failures: class_figure("failure"),
        by_end_reason,
        requested: count(|q| q.requested),
        reached_active: count(|q| q.reached_active),
        not_reached: count(|q| q.not_reached),
        reached_share: RateFigure {
            day: rate_if_enough(qd.reached_active, qd.requested, 1.0),
            d7: rate_if_enough(q7.reached_active, q7.requested, 1.0),
            d28: rate_if_enough(q28.reached_active, q28.requested, 1.0),
        },
        duration_ms: dist(|q| &q.duration_ms),
        peak_fps: dist(|q| &q.peak_fps),
        avg_rtt_ms: dist(|q| &q.avg_rtt_ms),
    })
}

async fn crashes_section(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<Crashes, DigestError> {
    let excluded = excluded_ids(&set.tenants);
    let docs = find_docs(
        state,
        "agent_crashes",
        doc! {
            "reported_at": w.between(Span::D28),
            "tenant_id": { "$nin": excluded.clone() },
        },
        doc! { "reported_at": 1, "agentVersion": 1, "agent_version": 1 },
    )
    .await?;
    let mut by_version: BTreeMap<String, i64> = BTreeMap::new();
    for d in &docs {
        if dt_ms(d, "reported_at").is_some_and(|t| w.contains(Span::Day, t)) {
            // The payload is camelCase in the row (`AgentCrashPayload`,
            // flattened): `agentVersion`. `agent_version` is read too, for
            // a row written by hand. Before P9a only the latter was read,
            // and every production crash was "unknown".
            let version = str_of(d, "agentVersion")
                .or_else(|| str_of(d, "agent_version"))
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "unknown".into());
            *by_version.entry(version).or_insert(0) += 1;
        }
    }
    let total = w.count(docs.iter().filter_map(|d| dt_ms(d, "reported_at")));
    // P9a — device-days: one per device per day with online minutes
    // (`stats_machine_1d` holds one row per device per day bucket).
    let online = aggregate(
        state,
        "stats_machine_1d",
        vec![
            doc! { "$match": {
                "ts": w.between(Span::D28),
                "online_minutes": { "$gt": 0 },
                "tenant_id": { "$nin": excluded },
            } },
            doc! { "$group": { "_id": { "a": "$agent_id", "t": "$ts" } } },
        ],
    )
    .await?;
    let device_days = w.count(
        online
            .iter()
            .filter_map(|d| d.get_document("_id").ok().and_then(|id| dt_ms(id, "t"))),
    );
    let rate = |c: i64, d: i64| rate_if_enough(c, d, 100.0);
    Ok(Crashes {
        total,
        by_agent_version: key_counts(by_version),
        device_days,
        per_100_device_days: RateFigure {
            day: rate(total.day, device_days.day),
            d7: rate(total.d7, device_days.d7),
            d28: rate(total.d28, device_days.d28),
        },
    })
}

/// P9b — the ratings people gave from the viewer, in the windows: by the
/// answer's `ts`, the exclusion set applied to the org AND to the person
/// (a platform admin's own thumbs are not the product's).
async fn ratings_section(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<Ratings, DigestError> {
    let docs = find_docs(
        state,
        "session_feedback",
        doc! {
            "ts": w.between(Span::D28),
            "tenant_id": { "$nin": excluded_ids(&set.tenants) },
            "user_id": { "$nin": excluded_ids(&set.users) },
        },
        doc! { "ts": 1, "rating": 1, "reasons": 1 },
    )
    .await?;
    let (mut up, mut down) = (Vec::new(), Vec::new());
    let mut reasons: BTreeMap<String, i64> = BTreeMap::new();
    for d in &docs {
        let Some(t) = dt_ms(d, "ts") else {
            continue;
        };
        match str_of(d, "rating").as_deref() {
            Some("up") => up.push(t),
            Some("down") => down.push(t),
            _ => continue,
        }
        if let Ok(list) = d.get_array("reasons") {
            for r in list.iter().filter_map(|r| r.as_str()) {
                *reasons.entry(r.to_string()).or_insert(0) += 1;
            }
        }
    }
    let (up, down) = (w.count(up), w.count(down));
    let rated = Figure {
        day: up.day + down.day,
        d7: up.d7 + down.d7,
        d28: up.d28 + down.d28,
    };
    Ok(Ratings {
        up,
        down,
        rated,
        up_share_28d: rate_if_enough(up.d28, rated.d28, 1.0),
        n_floor: SMALL_N,
        reasons_28d: key_counts(reasons),
    })
}

/// P9a — why a day has no frozen row yet.
const NOT_FROZEN: &str = "the day is not frozen yet — the nightly quality freeze runs after \
                          midnight UTC; POST /api/admin/growth/quality/backfill re-freezes it";

/// P9a — what the frozen daily rows (`growth_quality_daily`) say: the day's
/// time to first frame with its 7- and 28-day context, and the day's
/// per-version table. Read from the rows rather than recomputed because the
/// records behind TTFF expire after 7 days — the freeze is what keeps them.
/// The scope follows the exclusion set: an empty set (`include_internal`)
/// reads the `all` rows, any other the `external` rows.
async fn frozen_quality(
    state: &AppState,
    w: &Windows,
    set: &ExclusionSet,
) -> Result<(Measured<TtffFigures>, Measured<Vec<VersionDayRow>>), DigestError> {
    if !mounted(state, "fleet") {
        return Ok((Measured::unmounted("fleet"), Measured::unmounted("fleet")));
    }
    let scope = if set.users.is_empty() && set.tenants.is_empty() {
        Scope::All
    } else {
        Scope::External
    };
    let (day_s, d7_s, d28_s) = w.dates();
    let rows = GrowthQualityDao::new(&state.db)
        .rows_between(scope, &d28_s, &day_s)
        .await?;
    let all: Vec<&QualityDay> = rows
        .iter()
        .filter(|r| r.agent_version == ALL_VERSIONS)
        .collect();
    if !all.iter().any(|r| r.day == day_s) {
        let n = NotMeasured::now(NOT_FROZEN);
        return Ok((Measured::NotMeasured(n.clone()), Measured::NotMeasured(n)));
    }
    let measured = |from: &str| -> Vec<&TtffQuality> {
        all.iter()
            .filter(|r| r.day.as_str() >= from)
            .filter_map(|r| r.ttff.as_ref())
            .collect()
    };
    let (td, t7, t28) = (measured(&day_s), measured(&d7_s), measured(&d28_s));
    let ttff = if td.is_empty() {
        Measured::NotMeasured(NotMeasured::now(
            "the day's connect records (agent_logs, 7-day TTL) had expired before it was frozen",
        ))
    } else {
        let pool = |v: &[&TtffQuality]| Dist::pool(v.iter().map(|t| &t.dist));
        let (pd, p7, p28) = (pool(&td), pool(&t7), pool(&t28));
        let sum = |v: &[&TtffQuality], f: fn(&TtffQuality) -> i64| -> i64 {
            v.iter().map(|t| f(t)).sum()
        };
        Measured::Value(TtffFigures {
            n: Figure {
                day: pd.n,
                d7: p7.n,
                d28: p28.n,
            },
            days_measured: Figure {
                day: td.len() as i64,
                d7: t7.len() as i64,
                d28: t28.len() as i64,
            },
            p50_ms: OptFigure {
                day: pd.p50,
                d7: p7.p50,
                d28: p28.p50,
            },
            p90_ms: OptFigure {
                day: pd.p90,
                d7: p7.p90,
                d28: p28.p90,
            },
            windows_estimated: true,
            hidden: Figure {
                day: sum(&td, |t| t.hidden),
                d7: sum(&t7, |t| t.hidden),
                d28: sum(&t28, |t| t.hidden),
            },
            later_attempts: Figure {
                day: sum(&td, |t| t.later_attempts),
                d7: sum(&t7, |t| t.later_attempts),
                d28: sum(&t28, |t| t.later_attempts),
            },
        })
    };
    let mut versions: Vec<VersionDayRow> = rows
        .iter()
        .filter(|r| r.day == day_s && r.agent_version != ALL_VERSIONS)
        .map(|r| {
            let s = r.sessions.as_ref();
            VersionDayRow {
                agent_version: r.agent_version.clone(),
                requested: s.map_or(0, |s| s.requested),
                reached_active: s.map_or(0, |s| s.reached_active),
                not_reached: s.map_or(0, |s| s.not_reached),
                failures: s.map_or(0, |s| {
                    s.by_end_reason
                        .iter()
                        .filter(|c| end_reason_class(&c.reason) == "failure")
                        .map(|c| c.count)
                        .sum()
                }),
                ttff_n: r.ttff.as_ref().map(|t| t.dist.n),
                ttff_p50_ms: r.ttff.as_ref().and_then(|t| t.dist.p50),
                ttff_p90_ms: r.ttff.as_ref().and_then(|t| t.dist.p90),
                crashes: r.crashes,
                device_days: r.device_days,
            }
        })
        .collect();
    versions.sort_by(|a, b| version_order(&a.agent_version, &b.agent_version));
    Ok((ttff, Measured::Value(versions)))
}

/// P8 — the posts published per platform in the 28-day window, and the
/// snapshots taken on the day (their post's campaign beside them). Nothing
/// pushed in the window is `not_measured` — the pipeline being quiet and the
/// pipeline not running look the same from here, so neither is a 0.
async fn social_section(state: &AppState, w: &Windows) -> Result<Measured<Social>, DigestError> {
    let posts = find_docs(
        state,
        GROWTH_POSTS,
        doc! { "published_at": w.between(Span::D28) },
        doc! { "platform": 1, "published_at": 1 },
    )
    .await?;
    let snaps = find_docs(
        state,
        GROWTH_POST_SNAPSHOTS,
        doc! { "taken_at": w.between(Span::Day) },
        doc! { "platform": 1, "platform_id": 1, "snapshot": 1, "metrics": 1 },
    )
    .await?;
    if posts.is_empty() && snaps.is_empty() {
        return Ok(Measured::NotMeasured(NotMeasured::now(
            if mounted(state, "saas") {
                "no posts pushed in the last 28 days"
            } else {
                "saas module not mounted (the ingest routes run there)"
            },
        )));
    }
    let mut by: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for d in &posts {
        if let (Some(p), Some(t)) = (str_of(d, "platform"), dt_ms(d, "published_at")) {
            by.entry(p).or_default().push(t);
        }
    }
    let mut posts_by_platform: Vec<SocialPlatform> = by
        .into_iter()
        .map(|(platform, times)| SocialPlatform {
            platform,
            posts: w.count(times),
        })
        .collect();
    posts_by_platform.sort_by(|a, b| {
        b.posts
            .d28
            .cmp(&a.posts.d28)
            .then_with(|| a.platform.cmp(&b.platform))
    });
    let mut snapshots: Vec<SocialSnapshot> = snaps
        .iter()
        .filter_map(|d| {
            let metrics = d
                .get_document("metrics")
                .ok()?
                .iter()
                .filter_map(|(k, v)| v.as_f64().map(|v| (k.clone(), v)))
                .collect();
            Some(SocialSnapshot {
                platform: str_of(d, "platform")?,
                platform_id: str_of(d, "platform_id")?,
                snapshot: str_of(d, "snapshot")?,
                campaign: None,
                metrics,
            })
        })
        .collect();
    let rank = |s: &str| SNAPSHOTS.iter().position(|x| *x == s).unwrap_or(usize::MAX);
    snapshots.sort_by(|a, b| {
        a.platform
            .cmp(&b.platform)
            .then_with(|| rank(&a.snapshot).cmp(&rank(&b.snapshot)))
            .then_with(|| a.platform_id.cmp(&b.platform_id))
    });
    snapshots.truncate(TOP_SOCIAL_SNAPSHOTS);
    // The campaign of each listed snapshot's post — which post it is, in the
    // operator's own words (the platform id is opaque).
    if !snapshots.is_empty() {
        let or: Vec<Document> = snapshots
            .iter()
            .map(|s| doc! { "platform": &s.platform, "platform_id": &s.platform_id })
            .collect();
        let keyed = find_docs(
            state,
            GROWTH_POSTS,
            doc! { "$or": or },
            doc! { "platform": 1, "platform_id": 1, "key.campaign": 1 },
        )
        .await?;
        let campaigns: HashMap<(String, String), String> = keyed
            .iter()
            .filter_map(|d| {
                let campaign = d
                    .get_document("key")
                    .ok()
                    .and_then(|k| str_of(k, "campaign"))?;
                Some((
                    (str_of(d, "platform")?, str_of(d, "platform_id")?),
                    campaign,
                ))
            })
            .collect();
        for s in &mut snapshots {
            s.campaign = campaigns
                .get(&(s.platform.clone(), s.platform_id.clone()))
                .cloned();
        }
    }
    Ok(Measured::Value(Social {
        posts_by_platform,
        snapshots,
    }))
}

// ── The web plane ────────────────────────────────────────────────────────

const WEB_TOTALS: [&str; 3] = ["visitors", "visits", "pageviews"];

async fn website_section(ps: &mut Purestat, w: &Windows) -> Result<Website, PurestatError> {
    let (day, d7, d28) = w.dates();
    let mut totals = [[0i64; 3]; 3];
    for (i, from) in [day.as_str(), d7.as_str(), d28.as_str()]
        .into_iter()
        .enumerate()
    {
        let rows = ps
            .rows(&Query::range(from, &day, &[], &WEB_TOTALS, &[]))
            .await?;
        if let Some(r) = rows.first() {
            for (j, m) in WEB_TOTALS.iter().enumerate() {
                totals[j][i] = r.count(m);
            }
        }
    }
    let figure = |j: usize| Figure {
        day: totals[j][0],
        d7: totals[j][1],
        d28: totals[j][2],
    };
    let referrers = ps
        .rows(&Query::day(&day, &["referrer_host"], &["visitors"], &[]))
        .await?;
    let mut channels: BTreeMap<String, i64> = BTreeMap::new();
    let mut top_referrers: Vec<ReferrerRow> = referrers
        .iter()
        .map(|r| {
            let host = r.dim("referrer_host");
            let channel = campaign::channel_for_referrer_host(host).as_str();
            *channels.entry(channel.to_string()).or_insert(0) += r.count("visitors");
            ReferrerRow {
                host: host.unwrap_or("(direct)").to_string(),
                channel: channel.to_string(),
                visitors: r.count("visitors"),
            }
        })
        .collect();
    top_referrers.sort_by(|a, b| {
        b.visitors
            .cmp(&a.visitors)
            .then_with(|| a.host.cmp(&b.host))
    });
    top_referrers.truncate(TOP_WEB_ROWS);
    let paths = ps
        .rows(&Query::day(
            &day,
            &["path"],
            &["visitors", "pageviews"],
            &[],
        ))
        .await?;
    let mut top_paths: Vec<PathRow> = paths
        .iter()
        .map(|r| PathRow {
            path: r.dim("path").unwrap_or("(none)").to_string(),
            visitors: r.count("visitors"),
            pageviews: r.count("pageviews"),
        })
        .collect();
    top_paths.sort_by(|a, b| {
        b.visitors
            .cmp(&a.visitors)
            .then_with(|| a.path.cmp(&b.path))
    });
    top_paths.truncate(TOP_WEB_ROWS);
    Ok(Website {
        visitors: figure(0),
        visits: figure(1),
        pageviews: figure(2),
        channels: key_counts(channels),
        top_referrers,
        top_paths,
    })
}

async fn blog_section(ps: &mut Purestat, w: &Windows) -> Result<Blog, PurestatError> {
    let (day, _, _) = w.dates();
    let blog = Filter::starts_with("path", "/blog/");
    let rows = ps
        .rows(
            &Query::day(
                &day,
                &["path"],
                &["visitors", "pageviews", "reads", "median_read_s"],
                &[],
            )
            .filter(blog.clone()),
        )
        .await?;
    let mut posts: Vec<BlogPost> = rows
        .iter()
        .map(|r| BlogPost {
            path: r.dim("path").unwrap_or("(none)").to_string(),
            visitors: r.count("visitors"),
            pageviews: r.count("pageviews"),
            reads: r.metric("reads").map(|v| v.round() as i64),
            median_read_s: r.metric("median_read_s"),
        })
        .collect();
    posts.sort_by(|a, b| {
        b.visitors
            .cmp(&a.visitors)
            .then_with(|| a.path.cmp(&b.path))
    });
    posts.truncate(TOP_BLOG_POSTS);
    let sources = ps
        .rows(&Query::day(&day, &["referrer_host"], &["visitors"], &[]).filter(blog))
        .await?;
    let mut by: BTreeMap<String, i64> = BTreeMap::new();
    for r in &sources {
        *by.entry(r.dim("referrer_host").unwrap_or("(direct)").to_string())
            .or_insert(0) += r.count("visitors");
    }
    let mut top_sources = key_counts(by);
    top_sources.truncate(TOP_WEB_ROWS);
    Ok(Blog { posts, top_sources })
}

const CAMPAIGN_GOALS: [&str; 4] = ["signup", "subscribe", "install-copy", "github-outbound"];

/// The join key: the taxonomy's spelling of source and medium (purestat's
/// rows are normalised here, meshharbor's were at ingress), the campaign
/// trimmed and lowercased.
fn campaign_key(
    source: &str,
    medium: Option<&str>,
    campaign: Option<&str>,
) -> (String, String, String) {
    (
        campaign::normalize_source(source),
        campaign::normalize_medium(medium.unwrap_or("")),
        campaign.unwrap_or("").trim().to_lowercase(),
    )
}

async fn campaigns_section(
    ps: &mut Purestat,
    w: &Windows,
    signups: &[SignupRow],
) -> Result<Campaigns, PurestatError> {
    let (day, _, _) = w.dates();
    // A goal the site does not define costs the conversions, not the
    // section: the query is retried without goals and the row's `goals`
    // read "not measured" with the goal's name.
    let (rows, missing_goal) = ps
        .rows_or_without_goals(&Query::day(
            &day,
            &["utm_source", "utm_medium", "utm_campaign"],
            &["visitors", "pageviews"],
            &CAMPAIGN_GOALS,
        ))
        .await?;
    let conversions = missing_goal
        .map(|goal| NotMeasured::now(format!("{goal} is not defined on the purestat site")));
    #[derive(Default)]
    struct Tally {
        visitors: i64,
        pageviews: i64,
        goals: CampaignGoals,
        signups: i64,
    }
    let mut by: BTreeMap<(String, String, String), Tally> = BTreeMap::new();
    for r in &rows {
        let Some(source) = r.dim("utm_source") else {
            continue;
        };
        let key = campaign_key(source, r.dim("utm_medium"), r.dim("utm_campaign"));
        let t = by.entry(key).or_default();
        t.visitors += r.count("visitors");
        t.pageviews += r.count("pageviews");
        t.goals.signup += r.goal("signup");
        t.goals.subscribe += r.goal("subscribe");
        t.goals.install_copy += r.goal("install-copy");
        t.goals.github_outbound += r.goal("github-outbound");
    }
    for s in signups {
        let Some(source) = s.source.as_deref() else {
            continue;
        };
        let key = campaign_key(source, s.medium.as_deref(), s.campaign.as_deref());
        by.entry(key).or_default().signups += 1;
    }
    let mut rows: Vec<CampaignRow> = by
        .into_iter()
        .map(|((source, medium, campaign), t)| CampaignRow {
            source,
            medium,
            campaign,
            visitors: t.visitors,
            pageviews: t.pageviews,
            goals: match &conversions {
                Some(n) => Measured::NotMeasured(n.clone()),
                None => Measured::Value(t.goals),
            },
            signups: t.signups,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.visitors
            .cmp(&a.visitors)
            .then_with(|| b.signups.cmp(&a.signups))
            .then_with(|| a.source.cmp(&b.source))
    });
    Ok(Campaigns { rows, conversions })
}

async fn coverage_section(
    ps: &mut Purestat,
    w: &Windows,
    server_signups: i64,
) -> Result<Coverage, PurestatError> {
    let (day, _, _) = w.dates();
    let rows = ps
        .rows(&Query::day(&day, &[], &["visitors"], &["signup"]))
        .await?;
    let goals = rows.first().map(|r| r.goal("signup")).unwrap_or(0);
    Ok(Coverage {
        purestat_signup_goals: goals,
        server_signups,
        ratio: (server_signups >= SMALL_N).then(|| goals as f64 / server_signups as f64),
        n_floor: SMALL_N,
    })
}

// ── The compute ──────────────────────────────────────────────────────────

/// Every section for `day`, with `set` applied. Pure over the database and
/// purestat; stores nothing.
pub async fn compute(
    state: &AppState,
    day: NaiveDate,
    set: &ExclusionSet,
    now: DateTime,
) -> Result<Sections, DigestError> {
    let w = Windows::for_day(day);
    let now_ms = now.timestamp_millis();

    let users = read_users(state, &w, set).await?;
    let signups = signups_section(&w, &users);
    let orgs = orgs_created(state, &w, set).await?;

    let devices = if mounted(state, "fleet") {
        Some(read_devices(state, &w, set).await?)
    } else {
        None
    };
    // P3 — the install trace is fleet's: the counters, the token ledger and
    // the enroll's claim all come from that module, so without it every
    // part reads "not mounted" rather than 0.
    let install = match &devices {
        Some(d) => {
            let (fetches, internal_fetches) = read_fetches(state, &w).await?;
            // P3c review — the counters off is "not measured" for both fetch
            // fields, never a measured zero: with them off nothing is counted,
            // so an empty table or a 0 would claim nobody fetched anything.
            const COUNTERS_OFF: &str =
                "install counters are off on this server (growth.install_counters)";
            let counting = state.settings.growth.install_counters;
            Install {
                fetches: if counting {
                    Measured::Value(fetches)
                } else {
                    Measured::NotMeasured(NotMeasured::now(COUNTERS_OFF))
                },
                internal_fetches: if counting {
                    internal_fetches
                } else {
                    Measured::NotMeasured(NotMeasured::now(COUNTERS_OFF))
                },
                tokens: Measured::Value(read_tokens(state, &w, set).await?),
                enrollments_by_method: Measured::Value(d.by_method_os.clone()),
                // P3b — the switch off is "not measured", never a measured zero:
                // with it off the route refuses every record, so a 0 here would
                // claim nobody opted in when nobody could.
                wizard_steps: if state.settings.growth.setup_diagnostics {
                    Measured::Value(read_wizard_steps(state, &w).await?)
                } else {
                    Measured::NotMeasured(NotMeasured::now(
                        "setup diagnostics are off on this server (growth.setup_diagnostics)",
                    ))
                },
            }
        }
        None => Install {
            fetches: Measured::unmounted("fleet"),
            internal_fetches: Measured::unmounted("fleet"),
            tokens: Measured::unmounted("fleet"),
            enrollments_by_method: Measured::unmounted("fleet"),
            wizard_steps: Measured::unmounted("fleet"),
        },
    };
    let remote = if mounted(state, "remote") {
        Some(read_remote_usage(state, &w, set, now_ms).await?)
    } else {
        None
    };
    let calls = if mounted(state, "conference") {
        Some(read_calls(state, &w, set).await?)
    } else {
        None
    };
    // P2 — the network pillar's value events, so "active orgs" here is the
    // set `growth_org_daily` marks `value` (one definition, `value.rs`).
    let network = if mounted(state, "network") {
        Some(read_network_value(state, &w, set).await?)
    } else {
        None
    };

    let active_orgs = match (&remote, &calls, &network) {
        (None, None, None) => {
            Measured::NotMeasured(NotMeasured::now(super::value::unmounted_reason(&[])))
        }
        _ => {
            let mut v = ValueOrgs::default();
            let mut basis = Vec::new();
            if let Some(r) = &remote {
                v.union(&r.value);
                basis.push("remote".to_string());
            }
            if let Some(c) = &calls {
                v.union(&c.value);
                basis.push("conference".to_string());
            }
            if let Some(n) = &network {
                v.union(n);
                basis.push("network".to_string());
            }
            Measured::Value(ActiveOrgs {
                day: v.day.len() as i64,
                d7: v.d7.len() as i64,
                d28: v.d28.len() as i64,
                basis,
            })
        }
    };

    let top_orgs = match &remote {
        None => Measured::unmounted("remote"),
        Some(r) => {
            let mut ranked: Vec<(ObjectId, i64, i64)> = r
                .per_org_day
                .iter()
                .map(|(t, (ms, n))| (*t, *ms, *n))
                .collect();
            ranked.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| b.2.cmp(&a.2))
                    .then_with(|| a.0.cmp(&b.0))
            });
            ranked.truncate(TOP_ORGS);
            let ids: Vec<ObjectId> = ranked.iter().map(|r| r.0).collect();
            let names = org_names(state, &ids).await?;
            Measured::Value(
                ranked
                    .into_iter()
                    .map(|(t, ms, n)| TopOrg {
                        tenant_id: t.to_hex(),
                        name: names.get(&t).cloned().unwrap_or_default(),
                        minutes: minutes(ms),
                        sessions: n,
                    })
                    .collect(),
            )
        }
    };

    let newsletter = if mounted(state, "saas") {
        Measured::Value(newsletter_section(state, &w).await?)
    } else {
        Measured::unmounted("saas")
    };
    let revenue = revenue_section(state, &w, set).await?;
    // P8 — core-level collections, read whether or not `saas` is mounted.
    let social = social_section(state, &w).await?;
    // P9a — the day's TTFF and per-version table come from the frozen rows.
    let (ttff, by_agent_version) = frozen_quality(state, &w, set).await?;
    // P9b — the ratings: the prompt off is "not measured", never a zero —
    // with it off nobody could answer, so a 0 would claim nobody did.
    let ratings = match &remote {
        None => Measured::unmounted("remote"),
        Some(_) if !state.settings.growth.feedback => Measured::NotMeasured(NotMeasured::now(
            "the rating prompt is off on this server (MESHHARBOR__GROWTH__FEEDBACK)",
        )),
        Some(_) => Measured::Value(ratings_section(state, &w, set).await?),
    };
    let quality = Quality {
        remote: match &remote {
            Some(_) => Measured::Value(remote_quality(state, &w, set).await?),
            None => Measured::unmounted("remote"),
        },
        crashes: match &devices {
            Some(_) => Measured::Value(crashes_section(state, &w, set).await?),
            None => Measured::unmounted("fleet"),
        },
        ttff,
        by_agent_version,
        ratings,
    };

    // The web plane last, and each piece on its own: a purestat failure
    // costs the web sections and nothing else.
    let mut ps = Purestat::from_settings(state);
    let website: Measured<Website> = website_section(&mut ps, &w).await.into();
    let blog: Measured<Blog> = blog_section(&mut ps, &w).await.into();
    let campaigns: Measured<Campaigns> =
        campaigns_section(&mut ps, &w, &users.day_rows).await.into();
    let coverage: Measured<Coverage> = coverage_section(&mut ps, &w, signups.total.day)
        .await
        .into();

    // P10 — the day's alerts, when the rules run on this server.
    let alerts = if state.settings.growth.alerts {
        Measured::Value(super::alerts::day_section(state, &w).await?)
    } else {
        Measured::NotMeasured(NotMeasured::now(
            "alerts are off on this server (MESHHARBOR__GROWTH__ALERTS)",
        ))
    };
    // P7 — the repository's counters and traffic, as the `saas` puller
    // stored them: snapshots differenced, never a 0 for a missing day.
    let github = super::github::section(state, day).await?;
    // P7 — search, from the stored rows: each engine says why it is not
    // measured (no key, nothing pulled yet, `saas` not mounted).
    let search = Measured::Value(super::search::section(state, day).await?);

    Ok(Sections {
        headline: Headline {
            signups: signups.total,
            orgs_created: orgs,
            devices_enrolled: devices
                .as_ref()
                .map(|d| Measured::Value(d.enrolled))
                .unwrap_or_else(|| Measured::unmounted("fleet")),
            active_orgs: active_orgs.clone(),
            coverage,
        },
        signups,
        orgs_devices: OrgsDevices {
            orgs_created: orgs,
            devices_enrolled: devices
                .as_ref()
                .map(|d| Measured::Value(d.enrolled))
                .unwrap_or_else(|| Measured::unmounted("fleet")),
            devices_by_os: devices
                .as_ref()
                .map(|d| Measured::Value(d.by_os.clone()))
                .unwrap_or_else(|| Measured::unmounted("fleet")),
            orgs_first_device: devices
                .as_ref()
                .map(|d| Measured::Value(d.first_device))
                .unwrap_or_else(|| Measured::unmounted("fleet")),
            by_install_method: devices
                .as_ref()
                .map(|d| Measured::Value(d.by_method.clone()))
                .unwrap_or_else(|| Measured::unmounted("fleet")),
        },
        usage: Usage {
            remote: remote
                .as_ref()
                .map(|r| Measured::Value(r.usage.clone()))
                .unwrap_or_else(|| Measured::unmounted("remote")),
            calls: calls
                .as_ref()
                .map(|c| Measured::Value(c.usage.clone()))
                .unwrap_or_else(|| Measured::unmounted("conference")),
            active_orgs,
            top_orgs,
        },
        website,
        blog,
        campaigns,
        newsletter,
        revenue,
        quality,
        install,
        social,
        github,
        search,
        alerts,
    })
}

// ── Delivery ─────────────────────────────────────────────────────────────

/// The one send a digest makes, behind a trait so a test can count attempts
/// without a mail backend.
pub trait DigestMailer: Send + Sync {
    fn send<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        html: &'a str,
        text: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// The production mailer: the server's email service. It carries HTML
/// only (the service has no multipart send), so the plain text is the
/// stored twin for a reader without HTML, not an alternative part.
pub struct ServiceMailer(pub Arc<EmailService>);

impl DigestMailer for ServiceMailer {
    fn send<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        html: &'a str,
        _text: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .send(to, subject, html)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// `Some` when the server has a mail backend configured.
pub fn service_mailer(state: &AppState) -> Option<ServiceMailer> {
    state.email.clone().map(ServiceMailer)
}

/// `digest_to` when set, else the platform admins' proven addresses
/// (`users.email` holds only those; a `.invalid` placeholder is an unproven
/// claim and is skipped).
pub async fn recipients(state: &AppState) -> Result<Vec<String>, DigestError> {
    let configured = state.settings.growth.digest_recipients();
    if !configured.is_empty() {
        return Ok(configured);
    }
    let admins: Vec<ObjectId> = state.platform_admins.iter().copied().collect();
    if admins.is_empty() {
        return Ok(Vec::new());
    }
    let docs = find_docs(
        state,
        "users",
        doc! { "_id": { "$in": admins }, "deleted_at": Bson::Null },
        doc! { "email": 1 },
    )
    .await?;
    let mut out: Vec<String> = docs
        .iter()
        .filter_map(|d| str_of(d, "email"))
        .filter(|e| e.contains('@') && !e.ends_with(".invalid"))
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReport {
    /// The row's key: the day — or, for the weekly roll-up, the ISO week.
    pub day: String,
    /// False when another pod held the day, or it was already done.
    pub claimed: bool,
    pub status: DigestStatus,
    pub attempts: u32,
    pub recipients: usize,
    pub send_attempts: usize,
    pub sent: usize,
}

/// Why a manual run did not run.
#[derive(Debug, Clone, PartialEq)]
pub enum RunError {
    /// A fresh `computing` claim: a run of this day is in progress on some
    /// pod. The route answers 409; the caller tries again later.
    Busy,
    Failed(DigestError),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("a run of this day is in progress"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<DigestError> for RunError {
    fn from(e: DigestError) -> Self {
        Self::Failed(e)
    }
}

impl From<DaoError> for RunError {
    fn from(e: DaoError) -> Self {
        Self::Failed(e.into())
    }
}

impl From<RunError> for ApiError {
    fn from(e: RunError) -> Self {
        match e {
            RunError::Busy => ApiError::Conflict("a run of this day is in progress".into()),
            RunError::Failed(e) => e.into(),
        }
    }
}

/// How a run holds the day: through the claim (`claimed`), or in place on
/// a terminal day whose status it must not touch (`prior` says which).
struct Hold {
    mode: ClaimMode,
    claimed: bool,
    prior: Option<DigestStatus>,
}

fn not_run(day: String, status: DigestStatus) -> RunReport {
    RunReport {
        day,
        claimed: false,
        status,
        attempts: 0,
        recipients: 0,
        send_attempts: 0,
        sent: 0,
    }
}

/// What a run computed: the sections to store, and the mail rendered from
/// them (what was mailed is what the GET answers).
pub(crate) struct Computed {
    pub sections: Document,
    pub subject: String,
    pub html: String,
    pub text: String,
}

/// A report the engine below runs: the daily digest, and from P10 the
/// weekly roll-up — one claim, one store, one delivery for both, each
/// contributing only what it computes and how it reads.
pub(crate) trait Report: Send + Sync {
    /// Compute and render. `doc` is the row the mail describes — its key,
    /// attempts, recipient count and excluded counts; the sections are not
    /// on it yet.
    fn compute<'a>(
        &'a self,
        state: &'a AppState,
        set: &'a ExclusionSet,
        doc: &'a DigestDoc,
        now: DateTime,
    ) -> Pin<Box<dyn Future<Output = Result<Computed, DigestError>> + Send + 'a>>;
}

/// The daily digest of one closed day.
pub(crate) struct DailyReport {
    pub day: NaiveDate,
}

impl Report for DailyReport {
    fn compute<'a>(
        &'a self,
        state: &'a AppState,
        set: &'a ExclusionSet,
        doc: &'a DigestDoc,
        now: DateTime,
    ) -> Pin<Box<dyn Future<Output = Result<Computed, DigestError>> + Send + 'a>> {
        Box::pin(async move {
            let sections = compute(state, self.day, set, now).await?;
            Ok(Computed {
                sections: bson::to_document(&sections)?,
                subject: super::render::subject(&doc.day),
                html: super::render::render_html(doc, &sections),
                text: super::render::render_text(doc, &sections),
            })
        })
    }
}

/// The scheduled path: claim-first, then compute, store and deliver. A
/// finished day (`sent`, `stored`) and a fresh claim are left alone.
pub async fn run_scheduled(
    state: &AppState,
    day: NaiveDate,
    mailer: Option<&dyn DigestMailer>,
    now: DateTime,
) -> Result<RunReport, DigestError> {
    run_scheduled_report(
        state,
        &DigestStore::new(&state.db),
        &day_str(day),
        &DailyReport { day },
        mailer,
        now,
    )
    .await
}

/// The scheduled path for any report (the daily digest, the weekly
/// roll-up): claim `key` in `store`, then [`finish`].
pub(crate) async fn run_scheduled_report(
    state: &AppState,
    store: &DigestStore,
    key: &str,
    report: &dyn Report,
    mailer: Option<&dyn DigestMailer>,
    now: DateTime,
) -> Result<RunReport, DigestError> {
    let attempts = match store
        .claim(key, now, STALE_CLAIM_SECS, ClaimMode::Scheduled)
        .await?
    {
        ClaimOutcome::Claimed { attempts, .. } => attempts,
        ClaimOutcome::Busy => return Ok(not_run(key.to_string(), DigestStatus::Computing)),
        ClaimOutcome::Done(status) | ClaimOutcome::InPlace(status) => {
            return Ok(not_run(key.to_string(), status));
        }
    };
    let hold = Hold {
        mode: ClaimMode::Scheduled,
        claimed: true,
        prior: None,
    };
    finish(state, store, key, attempts, hold, mailer, now, report).await
}

/// The manual path (`POST …/digest/run`): recompute and overwrite the
/// day's sections, through the SAME claim the scheduler uses.
///
/// * `send=false` — a day the scheduler still owes ends `preview`, which
///   the scheduler re-claims like `failed`: a look at a day never cancels
///   its email. A `sent` or `stored` day is refreshed in place and keeps
///   its status.
/// * `send=true` — the day is claimed as the scheduler would claim it (a
///   `stored` day was never mailed and is re-claimed too), so the two can
///   never both mail it. A `sent` day is refreshed in place and never
///   re-sent.
/// * A fresh `computing` claim refuses the run ([`RunError::Busy`], 409).
pub async fn run_manual(
    state: &AppState,
    day: NaiveDate,
    send: bool,
    mailer: Option<&dyn DigestMailer>,
    now: DateTime,
) -> Result<RunReport, RunError> {
    run_manual_report(
        state,
        &DigestStore::new(&state.db),
        &day_str(day),
        &DailyReport { day },
        send,
        mailer,
        now,
    )
    .await
}

/// The manual path for any report: the claim in its manual mode, then
/// [`finish`].
pub(crate) async fn run_manual_report(
    state: &AppState,
    store: &DigestStore,
    key: &str,
    report: &dyn Report,
    send: bool,
    mailer: Option<&dyn DigestMailer>,
    now: DateTime,
) -> Result<RunReport, RunError> {
    let mode = if send {
        ClaimMode::ManualSend
    } else {
        ClaimMode::ManualPreview
    };
    let (attempts, hold) = match store.claim(key, now, STALE_CLAIM_SECS, mode).await? {
        ClaimOutcome::Claimed { attempts, prior } => (
            attempts,
            Hold {
                mode,
                claimed: true,
                prior,
            },
        ),
        ClaimOutcome::Busy => return Err(RunError::Busy),
        ClaimOutcome::InPlace(status) | ClaimOutcome::Done(status) => (
            0,
            Hold {
                mode,
                claimed: false,
                prior: Some(status),
            },
        ),
    };
    Ok(finish(state, store, key, attempts, hold, mailer, now, report).await?)
}

/// The engine: compute and render through the report, store the sections,
/// then deliver or not as the hold allows — the same for the daily digest
/// and the weekly roll-up.
#[allow(clippy::too_many_arguments)]
async fn finish(
    state: &AppState,
    store: &DigestStore,
    key: &str,
    attempts: u32,
    hold: Hold,
    mailer: Option<&dyn DigestMailer>,
    now: DateTime,
    report: &dyn Report,
) -> Result<RunReport, DigestError> {
    let set = ExclusionSet::load(&state.core).await?;
    let recipients = recipients(state).await?;
    let (users, tenants) = set.counts();
    let excluded = ExcludedCounts {
        users: users as u32,
        tenants: tenants as u32,
    };
    let doc = DigestDoc {
        day: key.to_string(),
        status: DigestStatus::Computing,
        version: meshharbor_services::dao::growth_digest::DIGEST_VERSION,
        claimed_at: now,
        computed_at: Some(now),
        sent_at: None,
        attempts,
        error: None,
        recipients: recipients.len() as u32,
        excluded,
        sections: None,
    };
    let computed = match report.compute(state, &set, &doc, now).await {
        Ok(c) => c,
        Err(e) => {
            // Only a held day may be marked failed: an in-place refresh of
            // a `sent` day that fails must not hand that day back to the
            // scheduler, which would mail it again.
            if hold.claimed {
                store
                    .set_status(key, DigestStatus::Failed, None, Some(e.to_string()))
                    .await?;
            }
            return Err(e);
        }
    };
    store
        .store_sections(
            key,
            computed.sections,
            excluded,
            recipients.len() as u32,
            now,
        )
        .await?;

    // What this run may do now:
    //  * scheduled, or a manual send, holding the claim: deliver, then
    //    `sent` / `failed` / `stored`;
    //  * a manual preview holding the claim: `preview` — the status the
    //    scheduler re-claims, so a look at a day never cancels its mail;
    //  * in place (a `sent` day; a `stored` one for a preview): the sections
    //    are refreshed and the status is not touched.
    let deliver = hold.claimed && matches!(hold.mode, ClaimMode::Scheduled | ClaimMode::ManualSend);
    let mut report = RunReport {
        day: key.to_string(),
        claimed: hold.claimed,
        status: hold.prior.unwrap_or(DigestStatus::Stored),
        attempts,
        recipients: recipients.len(),
        send_attempts: 0,
        sent: 0,
    };
    match (hold.claimed, deliver, mailer, recipients.is_empty()) {
        (false, _, _, _) => {}
        (true, false, _, _) => {
            store
                .set_status(key, DigestStatus::Preview, None, None)
                .await?;
            report.status = DigestStatus::Preview;
        }
        (true, true, Some(mailer), false) => {
            let mut first_error: Option<String> = None;
            for to in &recipients {
                report.send_attempts += 1;
                match mailer
                    .send(to, &computed.subject, &computed.html, &computed.text)
                    .await
                {
                    Ok(()) => report.sent += 1,
                    Err(e) => {
                        // The error is the mailer's text about our request;
                        // it never carries the recipient.
                        warn!(key = %key, collection = store.collection_name(), %e, "growth report send failed");
                        first_error.get_or_insert(e);
                    }
                }
            }
            if report.sent > 0 {
                let note = first_error.map(|e| {
                    format!(
                        "{} of {} sends failed: {e}",
                        report.send_attempts - report.sent,
                        report.send_attempts
                    )
                });
                store
                    .set_status(key, DigestStatus::Sent, Some(now), note)
                    .await?;
                report.status = DigestStatus::Sent;
            } else {
                let e = first_error.unwrap_or_else(|| "every send failed".into());
                store
                    .set_status(key, DigestStatus::Failed, None, Some(e))
                    .await?;
                report.status = DigestStatus::Failed;
            }
        }
        (true, true, _, _) => {
            // Delivering, with nobody to deliver to (no recipients, or no
            // mail service): the digest exists, and the day is done.
            store
                .set_status(key, DigestStatus::Stored, None, None)
                .await?;
            report.status = DigestStatus::Stored;
        }
    }
    info!(
        key = %key,
        collection = store.collection_name(),
        status = report.status.as_str(),
        recipients = report.recipients,
        sent = report.sent,
        excluded_users = excluded.users,
        excluded_tenants = excluded.tenants,
        "growth report run"
    );
    Ok(report)
}

/// The scheduler: every [`LOOP_INTERVAL_SECS`], once the clock has passed
/// `digest_hour_utc`, make sure yesterday's digest exists and was handled.
/// Only with `growth.digest_enabled`; the claim in `growth_digests` is what
/// keeps two pods from both sending.
pub fn spawn_digest_loop(state: AppState) {
    if !state.settings.growth.digest_enabled {
        return;
    }
    let hour = state.settings.growth.digest_hour();
    info!(hour, "growth digest scheduler starting");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(FIRST_TICK_DELAY_SECS)).await;
        loop {
            let now = DateTime::now();
            if let Some(day) = due_day(now, hour) {
                let mailer = service_mailer(&state);
                let mailer_ref: Option<&dyn DigestMailer> =
                    mailer.as_ref().map(|m| m as &dyn DigestMailer);
                match run_scheduled(&state, day, mailer_ref, now).await {
                    Ok(r) if r.claimed => {
                        info!(day = %r.day, status = r.status.as_str(), sent = r.sent, "growth digest done")
                    }
                    Ok(_) => {}
                    Err(e) => warn!(day = %day_str(day), %e, "growth digest run failed"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(LOOP_INTERVAL_SECS)).await;
        }
    });
}

// ── The JSON view ────────────────────────────────────────────────────────

/// A stored digest as the routes answer it: dates as RFC 3339 strings (a
/// raw `bson::DateTime` would serialise as a truthy `{"$date": …}`), the
/// sections as plain JSON.
#[derive(Debug, Clone, Serialize)]
pub struct DigestJson {
    pub day: String,
    pub status: DigestStatus,
    pub version: u32,
    pub claimed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub recipients: u32,
    pub excluded: ExcludedCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sections: Option<serde_json::Value>,
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

/// The stored sections, typed when they parse (every row this build wrote)
/// and as plain JSON otherwise (a row from a later shape version).
pub fn sections_json(doc: &Document) -> serde_json::Value {
    match bson::from_document::<Sections>(doc.clone()) {
        Ok(s) => serde_json::to_value(s).unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::to_value(doc).unwrap_or(serde_json::Value::Null),
    }
}

impl DigestJson {
    pub fn of(doc: &DigestDoc) -> Self {
        Self {
            day: doc.day.clone(),
            status: doc.status,
            version: doc.version,
            claimed_at: rfc3339(doc.claimed_at),
            computed_at: doc.computed_at.map(rfc3339),
            sent_at: doc.sent_at.map(rfc3339),
            attempts: doc.attempts,
            error: doc.error.clone(),
            recipients: doc.recipients,
            excluded: doc.excluded,
            sections: doc.sections.as_ref().map(sections_json),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        parse_day(s).unwrap()
    }

    #[test]
    fn days_parse_strictly() {
        assert_eq!(day_str(d("2026-10-13")), "2026-10-13");
        for bad in [
            "2026-13-01",
            "20261013",
            "2026-10-13T00:00:00Z",
            "yesterday",
            "",
        ] {
            assert!(parse_day(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_windows_end_at_the_days_end_and_count_inclusively_from_their_start() {
        let w = Windows::for_day(d("2026-10-13"));
        let one = 86_400_000;
        assert_eq!(w.day_end - w.day_start, one);
        assert_eq!(w.day_start - w.d7_start, 6 * one);
        assert_eq!(w.day_start - w.d28_start, 27 * one);
        let f = w.count([
            w.day_start,     // in all three
            w.day_end - 1,   // last ms of the day
            w.day_end,       // the next day: in none
            w.d7_start,      // first ms of the 7-day window
            w.d7_start - 1,  // the day before: 28-day only
            w.d28_start,     // first ms of the 28-day window
            w.d28_start - 1, // out
        ]);
        assert_eq!(
            f,
            Figure {
                day: 2,
                d7: 3,
                d28: 5
            }
        );
        assert_eq!(
            w.dates(),
            (
                "2026-10-13".to_string(),
                "2026-10-07".to_string(),
                "2026-09-16".to_string()
            )
        );
    }

    #[test]
    fn a_session_counts_only_its_overlap_with_the_window() {
        assert_eq!(overlap_ms(0, 100, 50, 200), 50);
        assert_eq!(overlap_ms(0, 100, 150, 200), 0);
        assert_eq!(overlap_ms(60, 80, 0, 100), 20);
        assert_eq!(overlap_ms(0, 1000, 100, 200), 100);
        assert_eq!(minutes(90_000), 1.5);
        assert_eq!(minutes(0), 0.0);
    }

    /// The scheduler owes yesterday once the hour has passed, and never an
    /// older day.
    #[test]
    fn the_due_day_is_yesterday_after_the_hour_and_nothing_before() {
        let at = |s: &str| DateTime::parse_rfc3339_str(s).unwrap();
        assert_eq!(due_day(at("2026-10-14T05:59:59Z"), 6), None);
        assert_eq!(
            due_day(at("2026-10-14T06:00:00Z"), 6),
            Some(d("2026-10-13"))
        );
        assert_eq!(
            due_day(at("2026-10-14T23:30:00Z"), 6),
            Some(d("2026-10-13"))
        );
        assert_eq!(
            due_day(at("2026-10-14T00:10:00Z"), 0),
            Some(d("2026-10-13"))
        );
        assert_eq!(utc_date_of(at("2026-10-14T23:59:59Z")), d("2026-10-14"));
    }

    /// `Measured` tells a value from its absence on the wire, and a stored
    /// section round-trips through BSON typed — the shape the GET answers.
    #[test]
    fn measured_serialises_as_the_value_or_the_reason() {
        let v: Measured<Figure> = Measured::Value(Figure {
            day: 1,
            d7: 2,
            d28: 3,
        });
        assert_eq!(
            serde_json::to_value(&v).unwrap(),
            serde_json::json!({ "day": 1, "d7": 2, "d28": 3 })
        );
        let n: Measured<Figure> = Measured::NotMeasured(NotMeasured::later("install", "P3"));
        assert_eq!(
            serde_json::to_value(&n).unwrap(),
            serde_json::json!({ "not_measured": "install", "arrives_with": "P3" })
        );
        let u: Measured<Figure> = Measured::unmounted("fleet");
        assert_eq!(
            serde_json::to_value(&u).unwrap(),
            serde_json::json!({ "not_measured": "fleet module not mounted" })
        );
        // Through BSON and back, both arms.
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Both {
            a: Measured<Figure>,
            b: Measured<Vec<KeyCount>>,
            c: Measured<Figure>,
        }
        let both = Both {
            a: v,
            b: Measured::Value(vec![KeyCount {
                key: "linux".into(),
                count: 2,
            }]),
            c: n,
        };
        let doc = bson::to_document(&both).unwrap();
        let back: Both = bson::from_document(doc).unwrap();
        assert_eq!(back, both);
        assert!(back.a.is_measured() && !back.c.is_measured());
    }

    /// P3c — an install section stored before P3c has no
    /// `internal_fetches`: it still parses typed (through BSON, as the GET
    /// reads it), and the field reads as not measured, arriving with P3c.
    #[test]
    fn an_install_section_from_before_p3c_reads_internal_as_not_measured() {
        let zero = serde_json::json!({ "day": 0, "d7": 0, "d28": 0 });
        let old = serde_json::json!({
            "fetches": [],
            "tokens": { "issued": zero, "redeemed": zero },
            "enrollments_by_method": [],
            "wizard_steps": { "not_measured": "wizard steps", "arrives_with": "P3b" },
        });
        let i: Install = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(i.internal_fetches, internal_fetches_before_p3c());
        assert!(!i.internal_fetches.is_measured());
        let doc = bson::to_document(&old).unwrap();
        let back: Install = bson::from_document(doc).unwrap();
        assert_eq!(back, i);
    }

    #[test]
    fn end_reasons_classify_into_hangup_refusal_failure() {
        assert_eq!(end_reason_class("controller_hangup"), "hangup");
        assert_eq!(end_reason_class("host_disconnect"), "hangup");
        assert_eq!(end_reason_class("user_denied"), "refusal");
        assert_eq!(end_reason_class("no_prompt_surface"), "refusal");
        assert_eq!(end_reason_class("error"), "failure");
        assert_eq!(end_reason_class("agent_disconnect"), "failure");
        assert_eq!(end_reason_class("something_new"), "other");
    }

    /// P2 — a purestat 400 naming an undefined goal is a configuration gap
    /// the sections name; any other error reads as before.
    #[test]
    fn an_unknown_goal_is_named_and_everything_else_is_not() {
        let e = PurestatError::Status(400, "unknown goal: \"signup\"".into());
        assert_eq!(unknown_goal(&e).as_deref(), Some("signup"));
        let m: Measured<i64> = Err::<i64, _>(e).into();
        assert_eq!(
            m,
            Measured::NotMeasured(NotMeasured::now(
                "signup is not defined on the purestat site"
            ))
        );
        assert_eq!(
            unknown_goal(&PurestatError::Status(
                400,
                "Unknown goal: subscribe".into()
            ))
            .as_deref(),
            Some("subscribe")
        );
        assert_eq!(
            unknown_goal(&PurestatError::Status(400, "unknown goal".into())).as_deref(),
            Some("the goal")
        );
        for other in [
            PurestatError::Status(400, "unknown dimension".into()),
            PurestatError::Status(500, "unknown goal: \"x\"".into()),
            PurestatError::Unauthorized,
            PurestatError::Timeout,
        ] {
            assert_eq!(unknown_goal(&other), None, "{other:?}");
            let m: Measured<i64> = Err::<i64, _>(other.clone()).into();
            assert_eq!(
                m,
                Measured::NotMeasured(NotMeasured::now(other.to_string()))
            );
        }
    }

    #[test]
    fn the_campaign_join_key_is_the_taxonomys_spelling() {
        assert_eq!(
            campaign_key("YouTub", Some("Video"), Some(" 20261019-Slug ")),
            ("youtube".into(), "video".into(), "20261019-slug".into())
        );
        assert_eq!(
            campaign_key("twitter", None, None),
            ("x".into(), "".into(), "".into())
        );
    }

    #[test]
    fn the_json_view_carries_rfc3339_dates_and_no_bson() {
        let doc = DigestDoc {
            day: "2026-10-13".into(),
            status: DigestStatus::Stored,
            version: 1,
            claimed_at: DateTime::parse_rfc3339_str("2026-10-14T06:00:00Z").unwrap(),
            computed_at: Some(DateTime::parse_rfc3339_str("2026-10-14T06:00:05Z").unwrap()),
            sent_at: None,
            attempts: 1,
            error: None,
            recipients: 0,
            excluded: ExcludedCounts {
                users: 1,
                tenants: 2,
            },
            sections: Some(doc! { "headline": { "signups": { "day": 1, "d7": 2, "d28": 3 } } }),
        };
        let json = serde_json::to_value(DigestJson::of(&doc)).unwrap();
        assert_eq!(json["claimed_at"], "2026-10-14T06:00:00Z");
        assert_eq!(json["computed_at"], "2026-10-14T06:00:05Z");
        assert!(json.get("sent_at").is_none());
        assert_eq!(json["sections"]["headline"]["signups"]["d28"], 3);
        let text = json.to_string();
        assert!(
            !text.contains("$date") && !text.contains("$numberLong"),
            "{text}"
        );
    }

    /// P4 — with nothing on record, the reason reads the backfill's ledger
    /// row: "has not run" only while no run is on record; a run that
    /// recorded nothing says so and names its day; rows a run recorded and
    /// that are gone now went with their org.
    #[test]
    fn the_no_billing_reason_says_whether_the_backfill_ran() {
        use meshharbor_services::dao::growth::{BILLING_BACKFILL_SOURCE, GrowthPull, PullStatus};
        let run = |rows: u32| GrowthPull {
            id: GrowthPull::id_of(BILLING_BACKFILL_SOURCE, "2026-10-17"),
            source: BILLING_BACKFILL_SOURCE.into(),
            day: "2026-10-17".into(),
            status: PullStatus::Ok,
            pulled_at: None,
            attempted_at: DateTime::parse_rfc3339_str("2026-10-17T21:18:25Z").unwrap(),
            attempts: 1,
            rows,
            error: None,
            missing_goal: None,
            truncated: false,
        };
        let never = no_billing_record(None);
        assert!(never.contains("the backfill has not run"), "{never}");

        let empty = no_billing_record(Some(&run(0)));
        assert!(!empty.contains("has not run"), "{empty}");
        assert!(empty.contains("the backfill on 2026-10-17"), "{empty}");
        assert!(empty.contains("names an org on this server"), "{empty}");

        let gone = no_billing_record(Some(&run(3)));
        assert!(!gone.contains("has not run"), "{gone}");
        assert!(gone.contains("the 3 the backfill on 2026-10-17"), "{gone}");
        assert!(gone.contains("deleted with their org"), "{gone}");
    }
}
