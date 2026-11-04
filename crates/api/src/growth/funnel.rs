// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P2 — `GET /api/admin/growth/funnel`: sign-up → org created →
//! activated → first value → paid, as COUNTS (spec §3d).
//!
//! * **Grain.** Acquisition belongs to the USER (the owner's
//!   `signup_attribution`, normalised through `campaign.rs`); value belongs
//!   to the ORG. A sign-up's org is the earliest org that user owns, created
//!   at or after the sign-up.
//! * **Sequential.** A sign-up reaches step k only through step k−1: an org
//!   within [`ORG_WINDOW_DAYS`] of the sign-up, a device within
//!   [`ACTIVATION_WINDOW_DAYS`] of the org (tombstoned devices count), a
//!   value event within [`VALUE_WINDOW_DAYS`] of the org. Each step's count
//!   is a subset of the one before.
//! * **`pending` and `settled`** on every windowed step, as FR-88 §3c: a
//!   sign-up whose window is still open and has no event yet is pending,
//!   not a failure; `settled = signups − pending` is the only denominator a
//!   rate may use. A sign-up that failed an earlier step is settled (its
//!   outcome is known) at every later step.
//! * **First value** is read from `growth_org_daily` — the one record that
//!   outlives the 90-day audit rows — at day grain: a value on the day the
//!   window closes counts. Today's events arrive with the next nightly run,
//!   which the open window covers as `pending`.
//! * **Unmounted = `null`, with the module's name.** Without `fleet` the
//!   server cannot see devices, so `activated` (and, sequentially,
//!   `first_value`) answer `null` and `not_measured` names the module;
//!   without every value module, `first_value` does the same. Never `0`.
//! * **Paid** (P4) is the org's first invoice paid with an amount above 0
//!   (`billing_events`, the `saas` module's — `null` without it). It has NO
//!   window (§3d), so it hangs off the org step, not the value steps: an
//!   org that pays is counted whatever its path to value (a late device
//!   still pays), and an org that has not paid is counted as not paid AS OF
//!   NOW — a cohort's paid count can still grow. Its `pending` is only the
//!   sign-ups still pending at the org step. So `paid` is a subset of
//!   `org_created`, not necessarily of `first_value`.
//!
//! ⚠️ Every bucket `key` is client-chosen text (a UTM value, a landing
//! path): an admin UI renders it as TEXT, never as markup.

use std::collections::{BTreeMap, HashMap};

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{Bson, DateTime, doc, oid::ObjectId};
use meshharbor_db::models::SignupAttribution;
use meshharbor_services::dao::{growth::GrowthDao, growth_digest::ExcludedCounts};
use meshharbor_core::{campaign, growth::ExclusionSet};
use serde::{Deserialize, Serialize};

use super::{
    digest::{MAX_ROWS, aggregate, dt_ms, excluded_ids, find_docs, parse_day},
    mounted,
    read_key::GrowthAuth,
    value,
};
use crate::{error::ApiError, routes::attribution::parse_instant, state::AppState};

/// An org counts when created within this many days of the sign-up.
pub const ORG_WINDOW_DAYS: i64 = 7;
/// A device counts when enrolled within this many days of the org.
pub const ACTIVATION_WINDOW_DAYS: i64 = 7;
/// A value event counts within this many days of the org.
pub const VALUE_WINDOW_DAYS: i64 = 14;
/// The default `since` when the query names none.
const DEFAULT_WINDOW_DAYS: i64 = 90;
/// Buckets kept per dimension, most sign-ups first.
pub const MAX_BUCKETS: usize = 100;
const DAY_MS: i64 = 86_400_000;

/// The dimensions a funnel can be broken down by — the campaign key, the
/// organic channel, the self-reported answer and the landing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Source,
    Medium,
    Campaign,
    Content,
    Channel,
    SelfReported,
    LandingPath,
}

impl Dimension {
    pub const ALL: [Dimension; 7] = [
        Dimension::Source,
        Dimension::Medium,
        Dimension::Campaign,
        Dimension::Content,
        Dimension::Channel,
        Dimension::SelfReported,
        Dimension::LandingPath,
    ];

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "source" => Some(Dimension::Source),
            "medium" => Some(Dimension::Medium),
            "campaign" => Some(Dimension::Campaign),
            "content" => Some(Dimension::Content),
            "channel" => Some(Dimension::Channel),
            "self_reported" => Some(Dimension::SelfReported),
            "landing_path" => Some(Dimension::LandingPath),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::Source => "source",
            Dimension::Medium => "medium",
            Dimension::Campaign => "campaign",
            Dimension::Content => "content",
            Dimension::Channel => "channel",
            Dimension::SelfReported => "self_reported",
            Dimension::LandingPath => "landing_path",
        }
    }

    /// A sign-up's bucket on this dimension; `None` = it recorded nothing.
    /// Source and medium go through the taxonomy (older rows predate the
    /// normalisation at ingress); the channel comes from the referrer host.
    pub fn key_of(self, attr: Option<&SignupAttribution>) -> Option<String> {
        let a = attr?;
        match self {
            Dimension::Source => a.source.as_deref().map(campaign::normalize_source),
            Dimension::Medium => a.medium.as_deref().map(campaign::normalize_medium),
            Dimension::Campaign => a.campaign.clone(),
            Dimension::Content => a.content.clone(),
            Dimension::Channel => Some(
                campaign::channel_for_referrer_host(a.referrer_host.as_deref())
                    .as_str()
                    .to_string(),
            ),
            Dimension::SelfReported => a.self_reported.clone(),
            Dimension::LandingPath => a.landing_path.clone(),
        }
    }
}

/// One sign-up, as read: never a name or an address.
#[derive(Debug, Clone)]
pub struct SignupFact {
    pub id: ObjectId,
    pub created_ms: i64,
    pub attribution: Option<SignupAttribution>,
}

/// One org owned by a sign-up of the window.
#[derive(Debug, Clone, Copy)]
pub struct OrgFact {
    pub tenant_id: ObjectId,
    pub owner_id: ObjectId,
    pub created_ms: i64,
}

/// Everything the tally needs, read once.
pub struct Facts<'a> {
    pub signups: &'a [SignupFact],
    pub orgs: &'a [OrgFact],
    /// tenant → its first device's enrollment (ms); `None` = no `fleet`.
    pub first_device: Option<&'a HashMap<ObjectId, i64>>,
    /// tenant → the start of its first value day (ms); `None` = no value
    /// module mounted.
    pub first_value: Option<&'a HashMap<ObjectId, i64>>,
    /// P4 — tenant → its first invoice paid above 0 (ms); `None` = no
    /// `saas` module.
    pub first_paid: Option<&'a HashMap<ObjectId, i64>>,
    pub now_ms: i64,
}

/// What one sign-up amounts to at one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Reached, at this instant. Final.
    Reached(i64),
    /// No event yet, window still open at `now`.
    Pending,
    /// The window closed without the event, or an earlier step failed.
    Cold,
    /// The server cannot see this step's source.
    Unmeasured,
}

#[derive(Debug, Clone, Copy)]
struct Outcome {
    org: Fate,
    activated: Fate,
    value: Fate,
    paid: Fate,
}

/// One windowed step: the event at `reached_at` (if any) against the
/// window `[window_start, window_start + window_days]`, both edges
/// inclusive; `now` exactly at the end is still open.
fn step(reached_at: Option<i64>, window_start: i64, window_days: i64, now_ms: i64) -> Fate {
    let end = window_start + window_days * DAY_MS;
    match reached_at {
        Some(at) if at <= end => Fate::Reached(at),
        Some(_) => Fate::Cold,
        None if now_ms <= end => Fate::Pending,
        None => Fate::Cold,
    }
}

fn outcome(s: &SignupFact, orgs_of_owner: &[OrgFact], facts: &Facts<'_>) -> Outcome {
    let first_org = orgs_of_owner
        .iter()
        .filter(|o| o.created_ms >= s.created_ms)
        .min_by_key(|o| o.created_ms);
    let org = step(
        first_org.map(|o| o.created_ms),
        s.created_ms,
        ORG_WINDOW_DAYS,
        facts.now_ms,
    );
    let org_fact = match org {
        Fate::Reached(_) => first_org,
        _ => None,
    };
    let activated = match (org, org_fact, facts.first_device) {
        (Fate::Reached(org_at), Some(o), Some(devices)) => step(
            devices.get(&o.tenant_id).copied(),
            org_at,
            ACTIVATION_WINDOW_DAYS,
            facts.now_ms,
        ),
        (Fate::Reached(_), _, None) => Fate::Unmeasured,
        (other, _, _) => other,
    };
    let value = match (activated, org_fact, facts.first_value) {
        (Fate::Reached(_), Some(o), Some(values)) => step(
            values.get(&o.tenant_id).copied(),
            o.created_ms,
            VALUE_WINDOW_DAYS,
            facts.now_ms,
        ),
        (Fate::Reached(_), _, None) => Fate::Unmeasured,
        (other, _, _) => other,
    };
    // P4 — no window: off the org step, paid or not paid as of now.
    let paid = match (org, org_fact, facts.first_paid) {
        (Fate::Reached(_), Some(o), Some(paid)) => match paid.get(&o.tenant_id) {
            Some(at) => Fate::Reached(*at),
            None => Fate::Cold,
        },
        (Fate::Reached(_), _, None) => Fate::Unmeasured,
        (other, _, _) => other,
    };
    Outcome {
        org,
        activated,
        value,
        paid,
    }
}

/// A windowed step's counts. `settled = signups − pending`: the sign-ups
/// whose outcome at this step is known — the denominator for a rate,
/// never `signups`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepCounts {
    pub count: u64,
    pub pending: u64,
    pub settled: u64,
}

#[derive(Debug, Default)]
struct StepTally {
    count: u64,
    pending: u64,
}

impl StepTally {
    fn add(&mut self, f: Fate) {
        match f {
            Fate::Reached(_) => self.count += 1,
            Fate::Pending => self.pending += 1,
            Fate::Cold | Fate::Unmeasured => {}
        }
    }

    fn counts(&self, signups: u64) -> StepCounts {
        StepCounts {
            count: self.count,
            pending: self.pending,
            settled: signups.saturating_sub(self.pending),
        }
    }
}

#[derive(Debug, Default)]
struct Tallies {
    signups: u64,
    org: StepTally,
    activated: StepTally,
    value: StepTally,
    paid: StepTally,
}

impl Tallies {
    fn add(&mut self, o: &Outcome) {
        self.signups += 1;
        self.org.add(o.org);
        self.activated.add(o.activated);
        self.value.add(o.value);
        self.paid.add(o.paid);
    }
}

/// The five steps. `activated`, `first_value` and `paid` are `null` when
/// their source is not mounted (see `FunnelReport::not_measured`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Steps {
    pub signup: u64,
    pub org_created: StepCounts,
    pub activated: Option<StepCounts>,
    pub first_value: Option<StepCounts>,
    /// P4 — no window: paid as of now (see the module docs).
    pub paid: Option<StepCounts>,
}

/// Median and p75 in hours, with the n they rest on; `None` below n = 1.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Percentiles {
    pub median_h: Option<f64>,
    pub p75_h: Option<f64>,
    pub n: u64,
}

impl Percentiles {
    pub fn of(mut hours: Vec<f64>) -> Self {
        hours.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self {
            median_h: percentile(&hours, 0.5),
            p75_h: percentile(&hours, 0.75),
            n: hours.len() as u64,
        }
    }
}

/// The p-th percentile of a SORTED sample, linearly interpolated between
/// the two nearest ranks (R-7), to 0.1; `None` of an empty sample.
pub fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = p.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let v = sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo as f64);
    Some((v * 10.0).round() / 10.0)
}

fn hours(ms: i64) -> f64 {
    (ms.max(0) as f64 / 3_600_000.0 * 10.0).round() / 10.0
}

/// Sign-up → first device and sign-up → first value, over the sign-ups
/// that reached each; `None` where the step is not measured.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TimeToValue {
    pub first_device: Option<Percentiles>,
    pub first_value: Option<Percentiles>,
}

/// One bucket of a breakdown. `key` is client-chosen text; `null` is the
/// sign-ups that recorded nothing for the dimension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bucket {
    pub key: Option<String>,
    pub signups: u64,
    pub org_created: StepCounts,
    pub activated: Option<StepCounts>,
    pub first_value: Option<StepCounts>,
    pub paid: Option<StepCounts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Windows {
    pub org_days: i64,
    pub activation_days: i64,
    pub value_days: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunnelReport {
    pub enabled: bool,
    pub since: String,
    pub until: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub windows: Windows,
    /// True when the window held more sign-ups than one query loads; the
    /// counts then cover the oldest rows only.
    pub truncated: bool,
    /// The value modules the first-value step rests on.
    pub value_basis: Vec<String>,
    /// Step → why it is `null`: the module(s) not mounted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub not_measured: BTreeMap<String, String>,
    pub steps: Steps,
    pub time_to_value: TimeToValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<Dimension>,
    #[serde(default)]
    pub buckets: Vec<Bucket>,
}

fn orgs_by_owner(orgs: &[OrgFact]) -> HashMap<ObjectId, Vec<OrgFact>> {
    let mut orgs_of: HashMap<ObjectId, Vec<OrgFact>> = HashMap::new();
    for o in orgs {
        orgs_of.entry(o.owner_id).or_default().push(*o);
    }
    orgs_of
}

/// One group's counts — a [`Bucket`] without its key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupCounts {
    pub signups: u64,
    pub org_created: StepCounts,
    pub activated: Option<StepCounts>,
    pub first_value: Option<StepCounts>,
    pub paid: Option<StepCounts>,
}

/// P6 — every sign-up's outcome, grouped by `key_of` (`None` = the
/// sign-ups it gives no key). The SAME [`outcome`] the funnel tallies with,
/// so a group's counts and the funnel's cannot disagree on what a step
/// means; the campaigns view groups by the normalised campaign key.
pub fn group_by<K: Ord>(
    facts: &Facts<'_>,
    key_of: impl Fn(&SignupFact) -> Option<K>,
) -> BTreeMap<Option<K>, GroupCounts> {
    let orgs_of = orgs_by_owner(facts.orgs);
    let can_see_devices = facts.first_device.is_some();
    let can_see_value = can_see_devices && facts.first_value.is_some();
    let can_see_paid = facts.first_paid.is_some();
    let mut groups: BTreeMap<Option<K>, Tallies> = BTreeMap::new();
    for s in facts.signups {
        let o = outcome(
            s,
            orgs_of.get(&s.id).map(Vec::as_slice).unwrap_or(&[]),
            facts,
        );
        groups.entry(key_of(s)).or_default().add(&o);
    }
    groups
        .into_iter()
        .map(|(k, t)| {
            (
                k,
                GroupCounts {
                    signups: t.signups,
                    org_created: t.org.counts(t.signups),
                    activated: can_see_devices.then(|| t.activated.counts(t.signups)),
                    first_value: can_see_value.then(|| t.value.counts(t.signups)),
                    paid: can_see_paid.then(|| t.paid.counts(t.signups)),
                },
            )
        })
        .collect()
}

/// The join and the counting, pure so it is testable without a database.
pub fn tally(facts: &Facts<'_>, by: Option<Dimension>) -> (Steps, TimeToValue, Vec<Bucket>) {
    let orgs_of = orgs_by_owner(facts.orgs);
    let can_see_devices = facts.first_device.is_some();
    let can_see_value = can_see_devices && facts.first_value.is_some();
    let can_see_paid = facts.first_paid.is_some();

    let mut total = Tallies::default();
    let mut buckets: BTreeMap<Option<String>, Tallies> = BTreeMap::new();
    let (mut to_device, mut to_value) = (Vec::new(), Vec::new());
    for s in facts.signups {
        let o = outcome(
            s,
            orgs_of.get(&s.id).map(Vec::as_slice).unwrap_or(&[]),
            facts,
        );
        total.add(&o);
        if let Some(dim) = by {
            buckets
                .entry(dim.key_of(s.attribution.as_ref()))
                .or_default()
                .add(&o);
        }
        if let Fate::Reached(at) = o.activated {
            to_device.push(hours(at - s.created_ms));
        }
        if let Fate::Reached(at) = o.value {
            to_value.push(hours(at - s.created_ms));
        }
    }

    let steps = Steps {
        signup: total.signups,
        org_created: total.org.counts(total.signups),
        activated: can_see_devices.then(|| total.activated.counts(total.signups)),
        first_value: can_see_value.then(|| total.value.counts(total.signups)),
        paid: can_see_paid.then(|| total.paid.counts(total.signups)),
    };
    let ttv = TimeToValue {
        first_device: can_see_devices.then(|| Percentiles::of(to_device)),
        first_value: can_see_value.then(|| Percentiles::of(to_value)),
    };
    let mut rows: Vec<Bucket> = buckets
        .into_iter()
        .map(|(key, t)| Bucket {
            key,
            signups: t.signups,
            org_created: t.org.counts(t.signups),
            activated: can_see_devices.then(|| t.activated.counts(t.signups)),
            first_value: can_see_value.then(|| t.value.counts(t.signups)),
            paid: can_see_paid.then(|| t.paid.counts(t.signups)),
        })
        .collect();
    rows.sort_by(|a, b| b.signups.cmp(&a.signups).then_with(|| a.key.cmp(&b.key)));
    rows.truncate(MAX_BUCKETS);
    (steps, ttv, rows)
}

#[derive(Debug, Deserialize)]
pub struct FunnelQuery {
    /// Inclusive: RFC 3339, `YYYY-MM-DD` or unix seconds. Default: 90 days
    /// before `until`.
    #[serde(default)]
    pub since: Option<String>,
    /// An instant (RFC 3339 or unix seconds) is the exclusive end. A bare
    /// `YYYY-MM-DD` is the WHOLE day, as on every other growth route
    /// (`parse_until`). Default: now.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub by: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

/// What the handler read, before the tally. P6's campaigns view reads the
/// account plane through the same function.
pub(crate) struct Read {
    pub(crate) signups: Vec<SignupFact>,
    pub(crate) orgs: Vec<OrgFact>,
    pub(crate) first_device: Option<HashMap<ObjectId, i64>>,
    pub(crate) first_value: Option<HashMap<ObjectId, i64>>,
    /// P4 — `None` without the `saas` module.
    pub(crate) first_paid: Option<HashMap<ObjectId, i64>>,
    pub(crate) truncated: bool,
    pub(crate) basis: Vec<String>,
}

impl Read {
    /// The facts the tally (or a grouping) counts over, at `now_ms`.
    pub(crate) fn facts(&self, now_ms: i64) -> Facts<'_> {
        Facts {
            signups: &self.signups,
            orgs: &self.orgs,
            first_device: self.first_device.as_ref(),
            first_value: self.first_value.as_ref(),
            first_paid: self.first_paid.as_ref(),
            now_ms,
        }
    }

    /// Step → why it is `null`: the module(s) this server does not mount.
    pub(crate) fn step_reasons(&self) -> BTreeMap<String, String> {
        let mut not_measured = BTreeMap::new();
        if self.first_device.is_none() {
            not_measured.insert(
                "activated".to_string(),
                "fleet module not mounted".to_string(),
            );
            not_measured.insert(
                "first_value".to_string(),
                "fleet module not mounted (activation precedes value)".to_string(),
            );
        } else if self.first_value.is_none() {
            not_measured.insert(
                "first_value".to_string(),
                value::unmounted_reason(&self.basis),
            );
        }
        if self.first_paid.is_none() {
            not_measured.insert("paid".to_string(), "saas module not mounted".to_string());
        }
        not_measured
    }
}

/// The sign-ups created in `[since, until)` (exclusions applied), the orgs
/// they own, and — where their modules are mounted — each org's first
/// device and first value day.
pub(crate) async fn read(
    state: &AppState,
    set: &ExclusionSet,
    since: DateTime,
    until: DateTime,
) -> Result<Read, ApiError> {
    let users = find_docs(
        state,
        "users",
        doc! {
            "created_at": { "$gte": since, "$lt": until },
            "deleted_at": Bson::Null,
            "_id": { "$nin": excluded_ids(&set.users) },
        },
        doc! { "created_at": 1, "signup_attribution": 1 },
    )
    .await?;
    let truncated = users.len() as i64 >= MAX_ROWS;
    let signups: Vec<SignupFact> = users
        .iter()
        .filter_map(|d| {
            Some(SignupFact {
                id: d.get_object_id("_id").ok()?,
                created_ms: dt_ms(d, "created_at")?,
                attribution: d
                    .get("signup_attribution")
                    .and_then(|b| bson::from_bson::<SignupAttribution>(b.clone()).ok()),
            })
        })
        .collect();
    let owners: Vec<ObjectId> = signups.iter().map(|s| s.id).collect();
    let orgs: Vec<OrgFact> = if owners.is_empty() {
        Vec::new()
    } else {
        find_docs(
            state,
            "tenants",
            doc! { "owner_id": { "$in": &owners }, "_id": { "$nin": excluded_ids(&set.tenants) } },
            doc! { "owner_id": 1, "created_at": 1 },
        )
        .await?
        .iter()
        .filter_map(|d| {
            Some(OrgFact {
                tenant_id: d.get_object_id("_id").ok()?,
                owner_id: d.get_object_id("owner_id").ok()?,
                created_ms: dt_ms(d, "created_at")?,
            })
        })
        .collect()
    };
    let tenant_ids: Vec<ObjectId> = orgs.iter().map(|o| o.tenant_id).collect();

    // Devices: tombstones count — a device enrolled and removed was still
    // enrolled.
    let first_device = if mounted(state, "fleet") {
        let firsts = if tenant_ids.is_empty() {
            Vec::new()
        } else {
            aggregate(
                state,
                "agents",
                vec![
                    doc! { "$match": { "tenant_id": { "$in": &tenant_ids } } },
                    doc! { "$group": { "_id": "$tenant_id", "first": { "$min": "$created_at" } } },
                ],
            )
            .await?
        };
        Some(
            firsts
                .iter()
                .filter_map(|d| Some((d.get_object_id("_id").ok()?, dt_ms(d, "first")?)))
                .collect::<HashMap<_, _>>(),
        )
    } else {
        None
    };

    let basis = value::value_basis(&state.modules.mounted());
    let first_value = if basis.is_empty() {
        None
    } else {
        let days = GrowthDao::new(&state.db)
            .first_value_days(&tenant_ids)
            .await?;
        Some(
            days.into_iter()
                .filter_map(|(tenant, (day, _))| {
                    let d = parse_day(&day).ok()?;
                    Some((tenant, d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis()))
                })
                .collect::<HashMap<_, _>>(),
        )
    };

    // P4 — each org's first invoice paid above 0 (`billing_events`, the
    // `saas` module's collection).
    let first_paid = if mounted(state, "saas") {
        Some(
            meshharbor_services::dao::billing_event::BillingEventDao::new(&state.db)
                .first_paid(&tenant_ids)
                .await?,
        )
    } else {
        None
    };

    Ok(Read {
        signups,
        orgs,
        first_device,
        first_value,
        first_paid,
        truncated,
        basis,
    })
}

/// The funnel's `until`, read the way every other growth route reads a day.
/// A bare `YYYY-MM-DD` is the WHOLE day, so the window ends at the next
/// midnight (exclusive); an instant (RFC 3339 or unix seconds) stays the
/// exclusive end it names. Before this, `until=2026-10-18` meant "before the
/// 18th" here and "through the 18th" on the Campaigns, Channels, Newsletter
/// and Quality routes, so one range read two different sets of days (FR-102
/// AC7's follow-up). `since` needs no such rule: a day's start is the day.
fn parse_until(raw: &str) -> Result<DateTime, ApiError> {
    let at = parse_instant(raw, "until")?;
    if !is_bare_day(raw) {
        return Ok(at);
    }
    at.timestamp_millis()
        .checked_add(DAY_MS)
        .map(DateTime::from_millis)
        .ok_or_else(|| ApiError::BadRequest(format!("until is out of range, got {raw:?}")))
}

/// `YYYY-MM-DD` and nothing else: the shape `parse_instant` reads as a day.
fn is_bare_day(raw: &str) -> bool {
    let b = raw.trim().as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-'
}

/// `GET /api/admin/growth/funnel?since&until&by&include_internal`
pub async fn get_funnel(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<FunnelQuery>,
) -> Result<Json<FunnelReport>, ApiError> {
    let now = DateTime::now();
    let until = match q.until.as_deref() {
        Some(s) => parse_until(s)?,
        None => now,
    };
    let since = match q.since.as_deref() {
        Some(s) => parse_instant(s, "since")?,
        None => DateTime::from_millis(until.timestamp_millis() - DEFAULT_WINDOW_DAYS * DAY_MS),
    };
    if since >= until {
        return Err(ApiError::BadRequest("since must be before until".into()));
    }
    let by = match q.by.as_deref() {
        Some(raw) => Some(Dimension::parse(raw).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "by must be one of {}",
                Dimension::ALL
                    .iter()
                    .map(|d| d.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?),
        None => None,
    };
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    Ok(Json(
        compute(&state, &set, since, until, by, q.include_internal, now).await?,
    ))
}

/// The report for `[since, until)` at `now` — what the route answers, and
/// what P10's weekly roll-up stores for its week.
pub async fn compute(
    state: &AppState,
    set: &ExclusionSet,
    since: DateTime,
    until: DateTime,
    by: Option<Dimension>,
    include_internal: bool,
    now: DateTime,
) -> Result<FunnelReport, ApiError> {
    let r = read(state, set, since, until).await?;
    let (steps, time_to_value, buckets) = tally(&r.facts(now.timestamp_millis()), by);
    let not_measured = r.step_reasons();
    let (users, tenants) = set.counts();
    Ok(FunnelReport {
        enabled: true,
        since: since.try_to_rfc3339_string().unwrap_or_default(),
        until: until.try_to_rfc3339_string().unwrap_or_default(),
        include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        windows: Windows {
            org_days: ORG_WINDOW_DAYS,
            activation_days: ACTIVATION_WINDOW_DAYS,
            value_days: VALUE_WINDOW_DAYS,
        },
        truncated: r.truncated,
        value_basis: r.basis,
        not_measured,
        steps,
        time_to_value,
        by,
        buckets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_000_000_000;

    fn signup(created_ms: i64, source: Option<&str>, referrer: Option<&str>) -> SignupFact {
        SignupFact {
            id: ObjectId::new(),
            created_ms,
            attribution: (source.is_some() || referrer.is_some()).then(|| SignupAttribution {
                source: source.map(str::to_string),
                referrer_host: referrer.map(str::to_string),
                ..Default::default()
            }),
        }
    }

    fn org(owner: &SignupFact, created_ms: i64) -> OrgFact {
        OrgFact {
            tenant_id: ObjectId::new(),
            owner_id: owner.id,
            created_ms,
        }
    }

    /// Six sign-ups through the four windows, every fate represented.
    #[test]
    fn the_funnel_is_sequential_with_pending_and_settled_per_step() {
        let now = T0 + 40 * DAY_MS;
        // A: org day 1, device day 3, value day 5 — reached everything.
        let a = signup(T0, Some("YouTub"), Some("youtube.com"));
        let org_a = org(&a, T0 + DAY_MS);
        // B: org day 1, device day 19 (late) — activation cold, value cold.
        let b = signup(T0 + 10 * DAY_MS, None, Some("google.com"));
        let org_b = org(&b, T0 + 11 * DAY_MS);
        // C: org 1 day ago, no device yet — activation pending, value pending.
        let c = signup(now - 2 * DAY_MS, Some("linkedin"), None);
        let org_c = org(&c, now - DAY_MS);
        // D: no org, window closed — org cold, the rest settled-failed.
        let d = signup(T0 + 20 * DAY_MS, Some("youtube"), None);
        // E: signed up yesterday, no org — org pending, the rest pending.
        let e = signup(now - DAY_MS, None, None);
        // F: org on day 9 (too late) — org cold.
        let f = signup(T0 + 5 * DAY_MS, None, None);
        let org_f = org(&f, T0 + 14 * DAY_MS);
        let signups = vec![a.clone(), b.clone(), c.clone(), d, e, f];
        let orgs = vec![org_a, org_b, org_c, org_f];
        let first_device: HashMap<ObjectId, i64> = [
            (org_a.tenant_id, T0 + 3 * DAY_MS),
            (org_b.tenant_id, T0 + 11 * DAY_MS + 19 * DAY_MS),
        ]
        .into_iter()
        .collect();
        let first_value: HashMap<ObjectId, i64> =
            [(org_a.tenant_id, T0 + 5 * DAY_MS)].into_iter().collect();
        // P4 — A's org paid on day 20 (no window); F's org paid too, but F
        // never reached the org step (its org came too late).
        let first_paid: HashMap<ObjectId, i64> = [
            (org_a.tenant_id, T0 + 20 * DAY_MS),
            (org_f.tenant_id, T0 + 15 * DAY_MS),
        ]
        .into_iter()
        .collect();
        let facts = Facts {
            signups: &signups,
            orgs: &orgs,
            first_device: Some(&first_device),
            first_value: Some(&first_value),
            first_paid: Some(&first_paid),
            now_ms: now,
        };
        let (steps, ttv, buckets) = tally(&facts, Some(Dimension::Source));
        assert_eq!(steps.signup, 6);
        assert_eq!(
            steps.org_created,
            StepCounts {
                count: 3,
                pending: 1,
                settled: 5
            }
        );
        assert_eq!(
            steps.activated,
            Some(StepCounts {
                count: 1,
                pending: 2,
                settled: 4
            })
        );
        assert_eq!(
            steps.first_value,
            Some(StepCounts {
                count: 1,
                pending: 2,
                settled: 4
            })
        );
        // P4 — paid: A; pending only E (still pending at the org step); B
        // and C reached their org and have not paid — not paid AS OF NOW.
        assert_eq!(
            steps.paid,
            Some(StepCounts {
                count: 1,
                pending: 1,
                settled: 5
            })
        );
        assert_eq!(
            ttv.first_device,
            Some(Percentiles {
                median_h: Some(72.0),
                p75_h: Some(72.0),
                n: 1
            })
        );
        assert_eq!(ttv.first_value.unwrap().n, 1);
        assert_eq!(ttv.first_value.unwrap().median_h, Some(120.0));
        // Buckets: youtube (A normalised from YouTub, D), linkedin (C), none (B, E, F).
        let key = |k: Option<&str>| {
            buckets
                .iter()
                .find(|b| b.key.as_deref() == k)
                .unwrap_or_else(|| panic!("{k:?} in {buckets:?}"))
                .clone()
        };
        let yt = key(Some("youtube"));
        assert_eq!(yt.signups, 2);
        assert_eq!(yt.org_created.count, 1);
        assert_eq!(yt.activated.unwrap().count, 1);
        assert_eq!(yt.first_value.unwrap().count, 1);
        assert_eq!(yt.paid.unwrap().count, 1);
        let li = key(Some("linkedin"));
        assert_eq!((li.signups, li.activated.unwrap().pending), (1, 1));
        let none = key(None);
        assert_eq!(none.signups, 3);
        assert_eq!(none.org_created.pending, 1);
        assert_eq!(buckets[0].key.as_deref(), None, "most sign-ups first");

        // The channel dimension reads the referrer host.
        let (_, _, by_channel) = tally(&facts, Some(Dimension::Channel));
        let social = by_channel
            .iter()
            .find(|b| b.key.as_deref() == Some("social"))
            .unwrap();
        assert_eq!(social.signups, 1);
        assert!(
            by_channel
                .iter()
                .any(|b| b.key.as_deref() == Some("search"))
        );
        // No attribution at all is `null`, a referrer-less attribution is direct.
        assert!(by_channel.iter().any(|b| b.key.is_none()));
        assert!(
            by_channel
                .iter()
                .any(|b| b.key.as_deref() == Some("direct"))
        );
    }

    /// Without `fleet`, activation and value are `null`; with `fleet` but no
    /// value module, only value is; with both and nothing enrolled, zeros.
    #[test]
    fn unmounted_steps_are_null_never_zero() {
        let a = signup(T0, Some("x"), None);
        let org_a = org(&a, T0 + DAY_MS);
        let signups = vec![a];
        let orgs = vec![org_a];
        let now = T0 + 40 * DAY_MS;
        let (steps, ttv, _) = tally(
            &Facts {
                signups: &signups,
                orgs: &orgs,
                first_device: None,
                first_value: None,
                first_paid: None,
                now_ms: now,
            },
            None,
        );
        assert_eq!(steps.org_created.count, 1);
        assert_eq!((steps.activated, steps.first_value), (None, None));
        assert_eq!((ttv.first_device, ttv.first_value), (None, None));
        assert_eq!(steps.paid, None, "no saas: paid is null, never 0");
        let empty = HashMap::new();
        let (steps, _, _) = tally(
            &Facts {
                signups: &signups,
                orgs: &orgs,
                first_device: Some(&empty),
                first_value: None,
                first_paid: Some(&empty),
                now_ms: now,
            },
            None,
        );
        // P4 — paid hangs off the org step, so it measures without fleet's
        // or the value modules' help: a measured zero here.
        assert_eq!(
            steps.paid,
            Some(StepCounts {
                count: 0,
                pending: 0,
                settled: 1
            })
        );
        assert_eq!(
            steps.activated,
            Some(StepCounts {
                count: 0,
                pending: 0,
                settled: 1
            })
        );
        assert_eq!(steps.first_value, None);
        let (steps, ttv, _) = tally(
            &Facts {
                signups: &signups,
                orgs: &orgs,
                first_device: Some(&empty),
                first_value: Some(&empty),
                first_paid: None,
                now_ms: now,
            },
            None,
        );
        assert_eq!(steps.first_value.unwrap().settled, 1);
        assert_eq!(ttv.first_device.unwrap().n, 0);
        assert_eq!(ttv.first_device.unwrap().median_h, None);
    }

    /// The window edges are inclusive, and `now` exactly at the end is open.
    #[test]
    fn window_edges_are_inclusive() {
        let a = signup(T0, None, None);
        let orgs = vec![org(&a, T0 + ORG_WINDOW_DAYS * DAY_MS)];
        let signups = vec![a.clone()];
        let late = vec![org(&a, T0 + ORG_WINDOW_DAYS * DAY_MS + 1)];
        let empty = HashMap::new();
        let facts = |orgs: &[OrgFact], now: i64| {
            let (s, _, _) = tally(
                &Facts {
                    signups: &signups,
                    orgs,
                    first_device: Some(&empty),
                    first_value: Some(&empty),
                    first_paid: Some(&empty),
                    now_ms: now,
                },
                None,
            );
            s
        };
        assert_eq!(facts(&orgs, T0 + 30 * DAY_MS).org_created.count, 1);
        assert_eq!(facts(&late, T0 + 30 * DAY_MS).org_created.count, 0);
        assert_eq!(
            facts(&[], T0 + ORG_WINDOW_DAYS * DAY_MS)
                .org_created
                .pending,
            1
        );
        assert_eq!(
            facts(&[], T0 + ORG_WINDOW_DAYS * DAY_MS + 1)
                .org_created
                .pending,
            0
        );
    }

    /// AC7's follow-up: a bare-day `until` is the whole day, as on every other
    /// growth route; an instant keeps naming the exclusive end it says.
    #[test]
    fn a_bare_day_until_is_the_whole_day_and_an_instant_is_exact() {
        let ms = |raw: &str| parse_until(raw).unwrap().timestamp_millis();
        let day = parse_instant("2026-10-18", "until")
            .unwrap()
            .timestamp_millis();
        // The whole of the 18th: the window ends at the 19th's midnight.
        assert_eq!(ms("2026-10-18"), day + DAY_MS);
        assert_eq!(
            ms(" 2026-10-18 "),
            day + DAY_MS,
            "trimmed as parse_instant trims"
        );
        // Instants are exact, whichever spelling.
        assert_eq!(ms("2026-10-18T00:00:00Z"), day);
        assert_eq!(
            ms("2026-10-18T13:30:00Z"),
            day + 13 * 3_600_000 + 30 * 60_000
        );
        assert_eq!(ms(&(day / 1000).to_string()), day);
        // A day is not a prefix match: anything else is still a 400.
        assert!(parse_until("2026-10-18X").is_err());
        assert!(parse_until("yesterday").is_err());
        assert!(!is_bare_day("2026-10-18T00:00:00Z"));
        assert!(!is_bare_day("1760745600"));
    }

    /// P6 — a grouping by any key counts exactly what the funnel's own
    /// breakdown counts for the same key: one `outcome`, two callers.
    #[test]
    fn a_grouping_by_key_agrees_with_the_funnels_breakdown() {
        let now = T0 + 40 * DAY_MS;
        let a = signup(T0, Some("YouTub"), None);
        let b = signup(T0 + DAY_MS, Some("youtube"), None);
        let c = signup(now - DAY_MS, Some("linkedin"), None);
        let e = signup(T0, None, None);
        let org_a = org(&a, T0 + DAY_MS);
        let org_c = org(&c, now - DAY_MS + 1);
        let signups = vec![a, b, c, e];
        let orgs = vec![org_a, org_c];
        let devices: HashMap<ObjectId, i64> =
            [(org_a.tenant_id, T0 + 2 * DAY_MS)].into_iter().collect();
        let values = HashMap::new();
        let paid: HashMap<ObjectId, i64> =
            [(org_a.tenant_id, T0 + 9 * DAY_MS)].into_iter().collect();
        let facts = Facts {
            signups: &signups,
            orgs: &orgs,
            first_device: Some(&devices),
            first_value: Some(&values),
            first_paid: Some(&paid),
            now_ms: now,
        };
        let (_, _, buckets) = tally(&facts, Some(Dimension::Source));
        let groups = group_by(&facts, |s| Dimension::Source.key_of(s.attribution.as_ref()));
        assert_eq!(groups.len(), buckets.len());
        for b in &buckets {
            let g = &groups[&b.key];
            assert_eq!(
                (g.signups, g.org_created, g.activated, g.first_value, g.paid),
                (b.signups, b.org_created, b.activated, b.first_value, b.paid),
                "{:?}",
                b.key
            );
        }
        assert_eq!(groups[&Some("youtube".to_string())].paid.unwrap().count, 1);
        // Without fleet, the grouping is as blind as the funnel.
        let blind = group_by(
            &Facts {
                first_device: None,
                ..facts
            },
            |_| Some(()),
        );
        let all = &blind[&Some(())];
        assert_eq!(
            (all.signups, all.activated, all.first_value),
            (4, None, None)
        );
    }

    #[test]
    fn percentiles_interpolate_between_ranks() {
        assert_eq!(percentile(&[], 0.5), None);
        assert_eq!(percentile(&[4.0], 0.5), Some(4.0));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 0.5), Some(2.5));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 0.75), Some(3.3));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0, 5.0], 0.75), Some(4.0));
        assert_eq!(percentile(&[1.0, 2.0], 1.0), Some(2.0));
        assert_eq!(percentile(&[1.0, 2.0], 0.0), Some(1.0));
        let p = Percentiles::of(vec![3.0, 1.0, 2.0]);
        assert_eq!((p.median_h, p.p75_h, p.n), (Some(2.0), Some(2.5), 3));
        assert_eq!(hours(-5), 0.0);
        assert_eq!(hours(90 * 60_000), 1.5);
    }

    #[test]
    fn dimensions_parse_and_spell_their_names() {
        for d in Dimension::ALL {
            assert_eq!(Dimension::parse(d.as_str()), Some(d));
            assert_eq!(
                serde_json::to_string(&d).unwrap(),
                format!("\"{}\"", d.as_str())
            );
        }
        assert_eq!(Dimension::parse("Source"), None);
        assert_eq!(Dimension::parse("email"), None);
        let attr = SignupAttribution {
            source: Some("Twitter".into()),
            medium: Some("POST".into()),
            landing_path: Some("/blog/x/".into()),
            ..Default::default()
        };
        assert_eq!(Dimension::Source.key_of(Some(&attr)).as_deref(), Some("x"));
        assert_eq!(
            Dimension::Medium.key_of(Some(&attr)).as_deref(),
            Some("post")
        );
        assert_eq!(
            Dimension::Channel.key_of(Some(&attr)).as_deref(),
            Some("direct")
        );
        assert_eq!(Dimension::Channel.key_of(None), None);
        assert_eq!(
            Dimension::LandingPath.key_of(Some(&attr)).as_deref(),
            Some("/blog/x/")
        );
    }

    #[test]
    fn the_report_never_carries_a_user() {
        let a = signup(T0, Some("youtube"), None);
        let orgs = vec![org(&a, T0 + DAY_MS)];
        let signups = vec![a.clone()];
        let empty = HashMap::new();
        let (steps, ttv, buckets) = tally(
            &Facts {
                signups: &signups,
                orgs: &orgs,
                first_device: Some(&empty),
                first_value: Some(&empty),
                first_paid: Some(&empty),
                now_ms: T0 + 40 * DAY_MS,
            },
            Some(Dimension::Source),
        );
        let json = serde_json::to_string(&(steps, ttv, buckets)).unwrap();
        assert!(!json.contains(&a.id.to_hex()), "a user id leaked: {json}");
        for key in ["email", "username", "user_id", "users"] {
            assert!(!json.contains(key), "{key} in {json}");
        }
    }
}
