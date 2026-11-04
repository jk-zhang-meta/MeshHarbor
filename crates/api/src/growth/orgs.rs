// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P2 — the per-org views (spec §3d):
//!
//! * `GET /api/admin/growth/orgs` — every org as a row: created, the
//!   owner's acquisition (channel and campaign key, never the address),
//!   devices, the last value day, the active weeks of the last 12, plan and
//!   billing status, and `at_risk`;
//! * `GET /api/admin/growth/org/{tenant_id}/timeline` — one org's
//!   milestones from its owner's sign-up to its last value day: the trace
//!   view; from P4 also its first payment and its billing history (plan
//!   changes and invoices from `billing_events`, `null` without `saas`).
//!
//! **At risk** ([`at_risk`]): active in at least [`AT_RISK_MIN_ACTIVE`] of
//! the [`AT_RISK_LOOKBACK`] weeks before the last [`AT_RISK_QUIET`], and in
//! none of those last weeks — an org that had a habit and lost it, the
//! one worth a call. The current week counts as the last one, so the flag
//! rises as soon as two weeks have passed quietly.
//!
//! Weekly activity comes from `growth_org_daily`'s value days; without a
//! value module it is not measured and says so. Names are client-chosen
//! text: an admin UI renders them as text.

use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, Document, doc, oid::ObjectId};
use chrono::NaiveDate;
use meshharbor_db::models::SignupAttribution;
use meshharbor_services::dao::{growth::GrowthDao, growth_digest::ExcludedCounts};
use meshharbor_core::{campaign, growth::ExclusionSet};
use serde::{Deserialize, Serialize};

use super::{
    cohorts::{plus_weeks, week_label, week_start},
    digest::{
        Measured, aggregate, day_str, dt_ms, excluded_ids, find_docs, parse_day, str_of,
        utc_date_of,
    },
    mounted,
    read_key::GrowthAuth,
    value,
};
use crate::{error::ApiError, state::AppState};

pub const DEFAULT_LIMIT: i64 = 500;
pub const MAX_LIMIT: i64 = 2_000;
/// The weeks the org list reports activity over (the current one last).
pub const ACTIVE_WEEKS: usize = 12;
/// The weeks the timeline's activity strip spans.
pub const STRIP_WEEKS: usize = 26;
pub const AT_RISK_LOOKBACK: usize = 4;
pub const AT_RISK_MIN_ACTIVE: usize = 3;
pub const AT_RISK_QUIET: usize = 2;

/// `weeks` oldest first, the last entry the current week.
pub fn at_risk(weeks: &[bool]) -> bool {
    let n = weeks.len();
    if n < AT_RISK_LOOKBACK + AT_RISK_QUIET {
        return false;
    }
    let quiet = &weeks[n - AT_RISK_QUIET..];
    let before = &weeks[n - AT_RISK_QUIET - AT_RISK_LOOKBACK..n - AT_RISK_QUIET];
    quiet.iter().all(|w| !*w) && before.iter().filter(|w| **w).count() >= AT_RISK_MIN_ACTIVE
}

/// How the owner arrived: the organic channel and the campaign key —
/// never the address, the name or the id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Acquisition {
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_reported: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landing_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_host: Option<String>,
}

/// `unknown` when the account recorded no attribution at all (it predates
/// FR-88), else the referrer's channel (`direct` without one).
pub fn acquisition_of(attr: Option<&SignupAttribution>) -> Acquisition {
    let Some(a) = attr else {
        return Acquisition {
            channel: "unknown".into(),
            ..Acquisition::default()
        };
    };
    Acquisition {
        channel: campaign::channel_for_referrer_host(a.referrer_host.as_deref())
            .as_str()
            .to_string(),
        source: a.source.as_deref().map(campaign::normalize_source),
        medium: a.medium.as_deref().map(campaign::normalize_medium),
        campaign: a.campaign.clone(),
        content: a.content.clone(),
        self_reported: a.self_reported.clone(),
        landing_path: a.landing_path.clone(),
        referrer_host: a.referrer_host.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DeviceCounts {
    /// Every device ever enrolled, tombstones included.
    pub enrolled: u64,
    /// Devices not tombstoned.
    pub live: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgRow {
    pub tenant_id: String,
    /// Client-chosen text.
    pub name: String,
    pub slug: String,
    pub created: String,
    pub archived: bool,
    pub plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_status: Option<String>,
    /// `null` when the owner's account is gone.
    pub owner: Option<Acquisition>,
    /// `null` without `fleet`.
    pub devices: Option<DeviceCounts>,
    pub last_value_day: Option<String>,
    /// Of the last [`ACTIVE_WEEKS`], oldest first, the current week last;
    /// empty when activity is not measured.
    pub weeks: Vec<bool>,
    pub active_weeks: u64,
    pub at_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgsReport {
    pub enabled: bool,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    pub limit: i64,
    pub truncated: bool,
    pub value_basis: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_measured: Option<String>,
    pub weeks: Vec<String>,
    pub orgs: Vec<OrgRow>,
}

#[derive(Debug, Deserialize)]
pub struct OrgsQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub include_internal: bool,
}

fn rfc3339(d: &Document, key: &str) -> String {
    d.get_datetime(key)
        .ok()
        .and_then(|t| t.try_to_rfc3339_string().ok())
        .unwrap_or_default()
}

fn billing_status(d: &Document) -> Option<String> {
    d.get_document("billing")
        .ok()
        .and_then(|b| str_of(b, "status"))
}

pub(crate) async fn owner_attributions(
    state: &AppState,
    owners: &[ObjectId],
) -> Result<HashMap<ObjectId, Option<SignupAttribution>>, ApiError> {
    if owners.is_empty() {
        return Ok(HashMap::new());
    }
    let docs = find_docs(
        state,
        "users",
        doc! { "_id": { "$in": owners } },
        doc! { "signup_attribution": 1 },
    )
    .await?;
    Ok(docs
        .iter()
        .filter_map(|d| {
            Some((
                d.get_object_id("_id").ok()?,
                d.get("signup_attribution")
                    .and_then(|b| bson::from_bson::<SignupAttribution>(b.clone()).ok()),
            ))
        })
        .collect())
}

/// Per-tenant device counts; `None` without `fleet`.
async fn device_counts(
    state: &AppState,
    tenants: &[ObjectId],
) -> Result<Option<HashMap<ObjectId, DeviceCounts>>, ApiError> {
    if !mounted(state, "fleet") {
        return Ok(None);
    }
    if tenants.is_empty() {
        return Ok(Some(HashMap::new()));
    }
    let rows = aggregate(
        state,
        "agents",
        vec![
            doc! { "$match": { "tenant_id": { "$in": tenants } } },
            doc! { "$group": {
                "_id": "$tenant_id",
                "enrolled": { "$sum": 1 },
                "live": { "$sum": { "$cond": [
                    { "$in": [ { "$type": "$deleted_at" }, [ "null", "missing" ] ] }, 1, 0,
                ] } },
            } },
        ],
    )
    .await?;
    Ok(Some(
        rows.iter()
            .filter_map(|d| {
                Some((
                    d.get_object_id("_id").ok()?,
                    DeviceCounts {
                        enrolled: super::digest::i64_of(d, "enrolled").max(0) as u64,
                        live: super::digest::i64_of(d, "live").max(0) as u64,
                    },
                ))
            })
            .collect(),
    ))
}

/// The Mondays of the last `n` weeks, oldest first, the current week last.
pub fn recent_weeks(today: NaiveDate, n: usize) -> Vec<NaiveDate> {
    let this_monday = week_start(today);
    (0..n as i64)
        .rev()
        .map(|back| plus_weeks(this_monday, -back))
        .collect()
}

/// `GET /api/admin/growth/orgs?limit=&include_internal=`
pub async fn list_orgs(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<OrgsQuery>,
) -> Result<Json<OrgsReport>, ApiError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let now = DateTime::now();
    let today = utc_date_of(now);
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    let (users, tenants) = set.counts();
    let excluded_tenants = excluded_ids(&set.tenants);

    let cursor = state
        .db
        .collection::<Document>("tenants")
        .find(doc! { "_id": { "$nin": &excluded_tenants } })
        .projection(doc! {
            "name": 1, "slug": 1, "owner_id": 1, "plan": 1, "billing.status": 1,
            "is_archived": 1, "created_at": 1,
        })
        .sort(doc! { "created_at": -1, "_id": -1 })
        .limit(limit + 1)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let mut docs = collect_docs(cursor).await?;
    let truncated = docs.len() as i64 > limit;
    docs.truncate(limit as usize);

    let tenant_ids: Vec<ObjectId> = docs
        .iter()
        .filter_map(|d| d.get_object_id("_id").ok())
        .collect();
    let owner_ids: Vec<ObjectId> = docs
        .iter()
        .filter_map(|d| d.get_object_id("owner_id").ok())
        .collect();
    let owners = owner_attributions(&state, &owner_ids).await?;
    let devices = device_counts(&state, &tenant_ids).await?;

    let basis = value::value_basis(&state.modules.mounted());
    let weeks = recent_weeks(today, ACTIVE_WEEKS);
    let dao = GrowthDao::new(&state.db);
    let (active, last_value) = if basis.is_empty() {
        (HashSet::new(), HashMap::new())
    } else {
        let rows = dao
            .org_days_between(
                Some(&tenant_ids),
                &excluded_tenants,
                &day_str(weeks[0]),
                &day_str(today),
                true,
            )
            .await?;
        let active: HashSet<(ObjectId, NaiveDate)> = rows
            .iter()
            .filter_map(|r| Some((r.tenant_id, week_start(parse_day(&r.day).ok()?))))
            .collect();
        (active, dao.last_value_days(&excluded_tenants).await?)
    };

    let orgs = docs
        .iter()
        .filter_map(|d| {
            let id = d.get_object_id("_id").ok()?;
            let flags: Vec<bool> = if basis.is_empty() {
                Vec::new()
            } else {
                weeks.iter().map(|w| active.contains(&(id, *w))).collect()
            };
            Some(OrgRow {
                tenant_id: id.to_hex(),
                name: str_of(d, "name").unwrap_or_default(),
                slug: str_of(d, "slug").unwrap_or_default(),
                created: rfc3339(d, "created_at"),
                archived: d.get_bool("is_archived").unwrap_or(false),
                plan: str_of(d, "plan").unwrap_or_else(|| "free".into()),
                billing_status: billing_status(d),
                owner: d
                    .get_object_id("owner_id")
                    .ok()
                    .and_then(|o| owners.get(&o))
                    .map(|a| acquisition_of(a.as_ref())),
                devices: devices
                    .as_ref()
                    .map(|m| m.get(&id).copied().unwrap_or_default()),
                last_value_day: last_value.get(&id).cloned(),
                active_weeks: flags.iter().filter(|w| **w).count() as u64,
                at_risk: at_risk(&flags),
                weeks: flags,
            })
        })
        .collect();

    Ok(Json(OrgsReport {
        enabled: true,
        include_internal: q.include_internal,
        excluded: ExcludedCounts {
            users: users as u32,
            tenants: tenants as u32,
        },
        limit,
        truncated,
        not_measured: basis.is_empty().then(|| value::unmounted_reason(&basis)),
        value_basis: basis,
        weeks: weeks.iter().map(|w| week_label(*w)).collect(),
        orgs,
    }))
}

// ── The timeline ─────────────────────────────────────────────────────────

/// One milestone. `at` is RFC 3339, or a `YYYY-MM-DD` day for the
/// day-grained first value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub at: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Acquisition>,
    /// `member_joined`: the owner's own membership row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<bool>,
    /// `first_device`: its OS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// `first_value`: which events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_kinds: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeekCell {
    pub week: String,
    pub start: String,
    pub active: bool,
}

/// The org's totals over every `growth_org_daily` row it has.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Totals {
    pub days: u64,
    pub value_days: u64,
    pub first_day: Option<String>,
    pub last_day: Option<String>,
    pub rc_sessions: i64,
    pub rc_session_minutes: f64,
    pub calls: i64,
    pub call_participant_minutes: f64,
    pub tunnel_flows: i64,
    pub ssh_sessions: i64,
    pub exec_runs: i64,
}

/// P4 — one row of the org's billing history (`billing_events`): what
/// Stripe said, never who paid.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanChange {
    /// RFC 3339.
    pub at: String,
    /// `subscription_created` · `subscription_updated` ·
    /// `subscription_deleted` · `invoice_paid` · `invoice_payment_failed` ·
    /// `trial_will_end`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seats: Option<i64>,
    /// Invoices: what was billed (cents). Absent on a subscription event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// The newest billing rows the timeline lists.
pub const MAX_PLAN_HISTORY: usize = 200;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineReport {
    pub enabled: bool,
    pub tenant_id: String,
    pub name: String,
    pub slug: String,
    pub created: String,
    pub archived: bool,
    pub plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_status: Option<String>,
    /// P4 — plan changes and invoices, oldest first (the newest
    /// [`MAX_PLAN_HISTORY`]); `not_measured` without `saas`.
    pub plan_history: Measured<Vec<PlanChange>>,
    pub members: u64,
    pub devices: Option<DeviceCounts>,
    pub events: Vec<TimelineEvent>,
    pub value_basis: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_measured: Option<String>,
    pub weeks: Vec<WeekCell>,
    pub totals: Option<Totals>,
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    #[serde(default)]
    pub include_internal: bool,
}

/// `GET /api/admin/growth/org/{tenant_id}/timeline?include_internal=`
pub async fn org_timeline(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Path(tenant_id): Path<String>,
    Query(q): Query<TimelineQuery>,
) -> Result<Json<TimelineReport>, ApiError> {
    let tid = ObjectId::parse_str(tenant_id.trim())
        .map_err(|_| ApiError::BadRequest("tenant_id must be a 24-hex ObjectId".into()))?;
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    // An excluded org is hidden like a missing one: the view does not
    // count it, so it does not show it either.
    let tenant = find_docs(
        &state,
        "tenants",
        doc! { "_id": tid },
        doc! {
            "name": 1, "slug": 1, "owner_id": 1, "plan": 1, "billing.status": 1,
            "is_archived": 1, "created_at": 1,
        },
    )
    .await?
    .into_iter()
    .next()
    .filter(|_| !set.tenant_excluded(&tid))
    .ok_or_else(|| ApiError::NotFound("no such org".into()))?;
    let now = DateTime::now();
    let today = utc_date_of(now);
    let mut events: Vec<(i64, TimelineEvent)> = Vec::new();

    // The owner's sign-up: when, and how they arrived. Never the address.
    if let Ok(owner) = tenant.get_object_id("owner_id") {
        let owner_doc = find_docs(
            &state,
            "users",
            doc! { "_id": owner },
            doc! { "created_at": 1, "signup_attribution": 1 },
        )
        .await?;
        if let Some(u) = owner_doc.first()
            && let Some(t) = dt_ms(u, "created_at")
        {
            let attr = u
                .get("signup_attribution")
                .and_then(|b| bson::from_bson::<SignupAttribution>(b.clone()).ok());
            events.push((
                t,
                TimelineEvent {
                    at: rfc3339(u, "created_at"),
                    kind: "signup".into(),
                    attribution: Some(acquisition_of(attr.as_ref())),
                    owner: None,
                    os: None,
                    value_kinds: None,
                },
            ));
        }
    }
    if let Some(t) = dt_ms(&tenant, "created_at") {
        events.push((
            t,
            TimelineEvent {
                at: rfc3339(&tenant, "created_at"),
                kind: "org_created".into(),
                attribution: None,
                owner: None,
                os: None,
                value_kinds: None,
            },
        ));
    }

    // Members, as they joined (the owner's own row marked).
    let owner_id = tenant.get_object_id("owner_id").ok();
    let members = find_docs(
        &state,
        "tenant_members",
        doc! { "tenant_id": tid },
        doc! { "user_id": 1, "joined_at": 1 },
    )
    .await?;
    for m in &members {
        if let Some(t) = dt_ms(m, "joined_at") {
            events.push((
                t,
                TimelineEvent {
                    at: rfc3339(m, "joined_at"),
                    kind: "member_joined".into(),
                    attribution: None,
                    owner: Some(m.get_object_id("user_id").ok() == owner_id),
                    os: None,
                    value_kinds: None,
                },
            ));
        }
    }

    // The first device, tombstones included.
    let devices = device_counts(&state, &[tid]).await?;
    if devices.is_some() {
        let cursor = state
            .db
            .collection::<Document>("agents")
            .find(doc! { "tenant_id": tid })
            .projection(doc! { "created_at": 1, "os": 1 })
            .sort(doc! { "created_at": 1 })
            .limit(1)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let first = collect_docs(cursor).await?;
        if let Some(a) = first.first()
            && let Some(t) = dt_ms(a, "created_at")
        {
            events.push((
                t,
                TimelineEvent {
                    at: rfc3339(a, "created_at"),
                    kind: "first_device".into(),
                    attribution: None,
                    owner: None,
                    os: str_of(a, "os"),
                    value_kinds: None,
                },
            ));
        }
    }

    // Activity, from the fold.
    let basis = value::value_basis(&state.modules.mounted());
    let dao = GrowthDao::new(&state.db);
    let strip_weeks = recent_weeks(today, STRIP_WEEKS);
    let (weeks, totals) = if basis.is_empty() {
        (Vec::new(), None)
    } else {
        if let Some((day, kinds)) = dao.first_value_days(&[tid]).await?.remove(&tid)
            && let Ok(d) = parse_day(&day)
        {
            let t = d
                .and_hms_opt(0, 0, 0)
                .expect("midnight")
                .and_utc()
                .timestamp_millis();
            events.push((
                t,
                TimelineEvent {
                    at: day,
                    kind: "first_value".into(),
                    attribution: None,
                    owner: None,
                    os: None,
                    value_kinds: Some(kinds),
                },
            ));
        }
        let rows = dao
            .org_days_between(Some(&[tid]), &[], "0000-01-01", &day_str(today), false)
            .await?;
        let active: HashSet<NaiveDate> = rows
            .iter()
            .filter(|r| r.value)
            .filter_map(|r| Some(week_start(parse_day(&r.day).ok()?)))
            .collect();
        let weeks = strip_weeks
            .iter()
            .map(|w| WeekCell {
                week: week_label(*w),
                start: day_str(*w),
                active: active.contains(w),
            })
            .collect();
        let mut t = Totals {
            days: rows.len() as u64,
            value_days: rows.iter().filter(|r| r.value).count() as u64,
            first_day: rows.first().map(|r| r.day.clone()),
            last_day: rows.last().map(|r| r.day.clone()),
            ..Totals::default()
        };
        for r in &rows {
            t.rc_sessions += r.rc_sessions;
            t.rc_session_minutes += r.rc_session_minutes;
            t.calls += r.calls;
            t.call_participant_minutes += r.call_participant_minutes;
            t.tunnel_flows += r.tunnel_flows;
            t.ssh_sessions += r.ssh_sessions;
            t.exec_runs += r.exec_runs;
        }
        t.rc_session_minutes = (t.rc_session_minutes * 10.0).round() / 10.0;
        t.call_participant_minutes = (t.call_participant_minutes * 10.0).round() / 10.0;
        (weeks, Some(t))
    };

    // P4 — the billing history, and the first payment as a milestone.
    let plan_history = if mounted(&state, "saas") {
        let rows = meshharbor_services::dao::billing_event::BillingEventDao::new(&state.db)
            .list(Some(&[tid]), &[])
            .await?;
        if let Some(t) =
            meshharbor_services::billing::OrgBilling::of(&rows.iter().collect::<Vec<_>>())
                .paid_since
        {
            events.push((
                t,
                TimelineEvent {
                    at: DateTime::from_millis(t)
                        .try_to_rfc3339_string()
                        .unwrap_or_default(),
                    kind: "first_paid".into(),
                    attribution: None,
                    owner: None,
                    os: None,
                    value_kinds: None,
                },
            ));
        }
        let skip = rows.len().saturating_sub(MAX_PLAN_HISTORY);
        Measured::Value(
            rows.iter()
                .skip(skip)
                .map(|r| PlanChange {
                    at: r.ts.try_to_rfc3339_string().unwrap_or_default(),
                    kind: r.kind.as_str().to_string(),
                    plan: r.plan.clone(),
                    seats: r.seats,
                    amount_cents: r.amount_cents,
                    currency: r.currency.clone(),
                    status: r.status.clone(),
                })
                .collect(),
        )
    } else {
        Measured::unmounted("saas")
    };

    events.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.kind.cmp(&b.1.kind)));
    Ok(Json(TimelineReport {
        enabled: true,
        tenant_id: tid.to_hex(),
        name: str_of(&tenant, "name").unwrap_or_default(),
        slug: str_of(&tenant, "slug").unwrap_or_default(),
        created: rfc3339(&tenant, "created_at"),
        archived: tenant.get_bool("is_archived").unwrap_or(false),
        plan: str_of(&tenant, "plan").unwrap_or_else(|| "free".into()),
        billing_status: billing_status(&tenant),
        plan_history,
        members: members.len() as u64,
        devices: devices.map(|m| m.get(&tid).copied().unwrap_or_default()),
        events: events.into_iter().map(|(_, e)| e).collect(),
        not_measured: basis.is_empty().then(|| value::unmounted_reason(&basis)),
        value_basis: basis,
        weeks,
        totals,
    }))
}

/// Drain a cursor, with the driver's error mapped.
async fn collect_docs(cursor: mongodb::Cursor<Document>) -> Result<Vec<Document>, ApiError> {
    use futures::TryStreamExt;
    cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule, week by week: three of the four before the last two, none
    /// in the last two.
    #[test]
    fn at_risk_is_a_lost_habit() {
        // oldest … newest (current week last)
        let habit_lost = [
            false, false, false, false, false, false, true, true, true, false, false, false,
        ];
        assert!(at_risk(&habit_lost));
        let still_active = [
            false, false, false, false, false, false, true, true, true, false, true, false,
        ];
        assert!(!at_risk(&still_active));
        let active_this_week = [
            false, false, false, false, false, false, true, true, true, true, false, true,
        ];
        assert!(!at_risk(&active_this_week));
        let only_two = [
            false, false, false, false, false, false, true, true, false, false, false, false,
        ];
        assert!(!at_risk(&only_two), "two of four is not a habit");
        let four_of_four = [
            false, false, false, false, false, false, true, true, true, true, false, false,
        ];
        assert!(at_risk(&four_of_four));
        let never = [false; 12];
        assert!(!at_risk(&never));
        assert!(!at_risk(&[]), "nothing measured is not at risk");
        assert!(
            !at_risk(&[true, true, true, false, false]),
            "too short to judge"
        );
        assert!(
            at_risk(&[true, true, true, true, false, false]),
            "exactly six weeks"
        );
    }

    #[test]
    fn the_acquisition_carries_the_channel_and_the_key_never_a_person() {
        let a = SignupAttribution {
            source: Some("Twitter".into()),
            medium: Some("Post".into()),
            campaign: Some("20261019-slug".into()),
            referrer_host: Some("t.co".into()),
            ..Default::default()
        };
        let acq = acquisition_of(Some(&a));
        assert_eq!(acq.channel, "social");
        assert_eq!(acq.source.as_deref(), Some("x"));
        assert_eq!(acq.medium.as_deref(), Some("post"));
        assert_eq!(acq.campaign.as_deref(), Some("20261019-slug"));
        let none = acquisition_of(None);
        assert_eq!(none.channel, "unknown");
        let bare = acquisition_of(Some(&SignupAttribution::default()));
        assert_eq!(bare.channel, "direct");
        let json = serde_json::to_string(&acq).unwrap();
        for key in ["email", "username", "user_id", "name"] {
            assert!(!json.contains(key), "{key} in {json}");
        }
    }

    #[test]
    fn recent_weeks_end_with_the_current_one() {
        let weeks = recent_weeks(parse_day("2026-10-14").unwrap(), 3);
        assert_eq!(
            weeks,
            vec![
                parse_day("2026-09-28").unwrap(),
                parse_day("2026-10-05").unwrap(),
                parse_day("2026-10-12").unwrap(),
            ]
        );
    }
}
