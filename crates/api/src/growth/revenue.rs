// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P4 — `GET /api/admin/growth/revenue?since&until&include_internal`:
//! billed revenue (spec §3g), beside the list-price estimate, the cost to
//! serve and the plan-limit collisions.
//!
//! * **Billed, not listed.** Every billed figure comes from what Stripe
//!   billed (`billing_events`, the `saas` module's — `not_measured` without
//!   it): an org's MRR at an instant is the recurring part of its newest
//!   paid invoice whose period covers that instant, normalised to a month
//!   (`meshharbor_services::billing`). The list-price figure
//!   (`Plan::price_monthly_cents` × seats) stays, labelled an ESTIMATE —
//!   for an org with no invoice yet it is the only figure there is.
//! * **Months.** New, expansion, contraction and churned MRR per month per
//!   currency. A closed month past its grace is read FROZEN from
//!   `growth_daily` (as the nightly freeze wrote it, internal orgs left
//!   out), so deleting an org later does not rewrite it; the open month and
//!   any month not frozen yet are computed live. `include_internal=true`
//!   computes every month live — the frozen totals have no internal orgs.
//! * **The record.** Nothing was recorded before the first billing row
//!   (any org): a month that ended before it is `on_record: false`, never a
//!   month of zero revenue; with no row at all, billed is `not_measured`.
//!   Until the operator's backfill has run (`record.backfilled_at`), the
//!   figures cover only what the webhook delivered since it was wired.
//! * **Margin** per org: billed MRR − the cost to serve over the last 30
//!   days (FR-20's ledger, priced by `routes/cost.rs`), only where both
//!   exist in the same currency. A 30-day cost against a month's MRR — a
//!   month is 30.4 days, and the difference is noise beside the prices.
//! * **Upgrade intent**: the range's plan-limit collisions per org and
//!   limit (`growth_daily {source: quota}`, core's — read on every server).
//!
//! Org names are client-chosen text: an admin UI renders them as text.
//! Nothing here names a person; the channel is the owner's acquisition
//! channel, never the owner.

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::{
    Json,
    extract::{Query, State},
};
use bson::{Bson, DateTime, doc, oid::ObjectId};
use meshharbor_core::growth::ExclusionSet;
use meshharbor_db::models::tenant::Plan;
use meshharbor_services::{
    billing::{self, MonthMovements, OrgBilling},
    dao::{
        billing_event::{BillingEvent, BillingEventDao, BillingKind},
        growth::{GrowthDao, QUOTA_COLLISION_METRIC, QUOTA_SOURCE},
        growth_digest::ExcludedCounts,
    },
};
use serde::{Deserialize, Serialize};

use super::{
    campaigns::Rate,
    digest::{
        Measured, MrrEstimate, NotMeasured, aggregate, day_str, excluded_ids, find_docs, i64_of,
        no_billing_record, str_of, utc_date_of,
    },
    mounted,
    orgs::{acquisition_of, owner_attributions},
    read_key::GrowthAuth,
};
use crate::{error::ApiError, state::AppState};

/// Months the view spans when the query names none (the current one last).
pub const DEFAULT_MONTHS: usize = 12;
pub const MAX_MONTHS: usize = 36;
/// The earliest month a range may start at.
pub const FLOOR_MONTH: &str = "2020-01";
/// Per-org rows listed, highest billed MRR first.
pub const MAX_ORG_ROWS: usize = 500;
/// Orgs listed under the upgrade intent, most collisions first.
pub const TOP_COLLISION_ORGS: usize = 50;
/// The cost window the margin reads (`routes/cost.rs`'s ranges).
pub const COST_RANGE: &str = "30d";

/// Why the cost cells are not measured when the usage ledger is off.
const COST_OFF: &str = "the usage ledger is off (stats.enabled = false)";

// ── The range ────────────────────────────────────────────────────────────

fn valid_month(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.len() == 7
        && b[4] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || c.is_ascii_digit())
        && billing::month_bounds(raw).is_some()
}

/// The months of `[since, until]` (`YYYY-MM`, both inclusive), oldest
/// first, as `(label, start_ms, end_ms)` — the open month's end is
/// `now + 1` (its "end of month" is now). `until` defaults to the current
/// month and may not be after it; `since` to [`DEFAULT_MONTHS`] months
/// ending with `until`. At most [`MAX_MONTHS`]; never before
/// [`FLOOR_MONTH`].
pub fn month_range(
    since: Option<&str>,
    until: Option<&str>,
    now_ms: i64,
) -> Result<Vec<(String, i64, i64)>, String> {
    let current = billing::month_of(now_ms);
    let parse = |raw: &str, name: &str| -> Result<String, String> {
        let raw = raw.trim();
        if valid_month(raw) {
            Ok(raw.to_string())
        } else {
            Err(format!("{name} must be YYYY-MM"))
        }
    };
    let until = match until {
        Some(u) => parse(u, "until")?,
        None => current.clone(),
    };
    if until > current {
        return Err(format!(
            "until must not be after the current month ({current})"
        ));
    }
    let since = match since {
        Some(s) => parse(s, "since")?,
        None => {
            let mut label = until.clone();
            for _ in 1..DEFAULT_MONTHS {
                let (start, _) = billing::month_bounds(&label).ok_or("a month in range")?;
                label = billing::month_of(start - 1);
            }
            label.max(FLOOR_MONTH.to_string())
        }
    };
    if since.as_str() < FLOOR_MONTH {
        return Err(format!("since must be {FLOOR_MONTH} or later"));
    }
    if since > until {
        return Err("since must not be after until".into());
    }
    let mut out = Vec::new();
    let mut label = since;
    loop {
        if out.len() == MAX_MONTHS {
            return Err(format!("the range spans at most {MAX_MONTHS} months"));
        }
        let (start, end) = billing::month_bounds(&label).ok_or("a month in range")?;
        out.push((label.clone(), start, end.min(now_ms + 1)));
        if label == until {
            break;
        }
        label = billing::month_of(end);
    }
    Ok(out)
}

// ── The report ───────────────────────────────────────────────────────────

/// Billed MRR now, in one currency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrencyNow {
    /// Lowercase ISO 4217, as Stripe spells it.
    pub currency: String,
    /// Normalised to a month.
    pub mrr_cents: i64,
    pub paying_orgs: i64,
}

/// One currency's movements in one month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrencyMonth {
    /// Lowercase ISO 4217.
    pub currency: String,
    #[serde(flatten)]
    pub movements: MonthMovements,
}

/// One month, every currency's movements in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonthBlock {
    /// `YYYY-MM`.
    pub month: String,
    /// Read from the frozen totals (`growth_daily`), not computed live.
    pub frozen: bool,
    /// The open month: its "end" is now.
    pub partial: bool,
    /// `false` = the month ended before the first billing row: NOT
    /// MEASURED, never zero.
    pub on_record: bool,
    /// Per currency, largest MRR first; empty = nothing billed and nothing
    /// moved (when `on_record`).
    pub currencies: Vec<CurrencyMonth>,
}

/// Cents in one currency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrencyCents {
    pub currency: String,
    pub cents: i64,
}

/// The range as a whole.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RangeTotals {
    pub invoices_paid: i64,
    /// What those invoices billed (every line, prorations included, after
    /// coupons, before tax).
    pub billed: Vec<CurrencyCents>,
    pub payment_failures: i64,
    /// Orgs whose first invoice above 0 was paid in the range.
    pub new_paying_orgs: i64,
    pub cancellations: i64,
}

/// Trials started in the range and how many of them have paid since.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TrialToPaid {
    pub trials: i64,
    pub converted: i64,
    /// `converted ÷ trials`, a value only from the n-floor.
    pub rate: Rate,
}

/// The billed figures by the owner's acquisition channel, per currency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRevenue {
    /// `unknown` when the owner's account is gone or predates FR-88.
    pub channel: String,
    pub currency: String,
    /// Now.
    pub paying_orgs: i64,
    pub mrr_cents: i64,
    /// In the range.
    pub new_paying_orgs: i64,
    pub churned_orgs: i64,
    pub trials: i64,
    pub converted: i64,
}

/// What the record holds, so a reader can tell "no revenue" from "not
/// recorded".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// RFC 3339 — the first billing row, any org.
    pub since: String,
    /// RFC 3339 — the newest row read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<String>,
    /// RFC 3339 — the operator's newest backfill; absent = never run, so
    /// the figures cover only what the webhook delivered since it was wired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfilled_at: Option<String>,
    pub rows: u64,
    /// More rows than one read loads: the oldest only.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Billed {
    pub record: Record,
    pub now: Vec<CurrencyNow>,
    pub months: Vec<MonthBlock>,
    pub totals: RangeTotals,
    pub trial_to_paid: TrialToPaid,
    pub by_channel: Vec<ChannelRevenue>,
}

/// The cost-to-serve basis the margin reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostBasis {
    pub range: String,
    /// The unit costs are in (`relay_costs.currency`, major units).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Whether any metered resource carries a price; without one every
    /// org's cost is `null`, never 0.00.
    pub priced: bool,
}

/// One org.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgRevenue {
    pub tenant_id: String,
    /// Client-chosen text.
    pub name: String,
    pub deleted: bool,
    pub plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_status: Option<String>,
    pub seats: i64,
    /// The owner's acquisition channel; `None` when the owner is gone.
    pub channel: Option<String>,
    /// RFC 3339 — the first invoice paid above 0; `None` = never paid.
    pub paid_since: Option<String>,
    /// Billed MRR now (cents, monthly); `None` = no paid invoice on record.
    pub billed_mrr_cents: Option<i64>,
    pub currency: Option<String>,
    /// The list-price ESTIMATE (plan price × seats) — for an org with no
    /// invoice yet, the only figure there is.
    pub list_price_mrr_cents: f64,
    /// The cost to serve over [`COST_RANGE`], in `cost.currency`; `None`
    /// when nothing is priced or the ledger is off.
    pub cost_30d: Option<f64>,
    /// `billed_mrr − cost_30d`, in cents, only where both exist in the same
    /// currency.
    pub margin_cents: Option<i64>,
    /// Plan-limit collisions in the range.
    pub collisions: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitCount {
    /// The limit's wire spelling (`max_members`, `max_devices`, …).
    pub limit: String,
    pub count: i64,
}

/// One org's collisions in the range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollisionRow {
    pub tenant_id: String,
    /// Client-chosen text.
    pub name: String,
    pub plan: String,
    pub total: i64,
    /// Days with a collision.
    pub days: i64,
    /// `YYYY-MM-DD`.
    pub last_day: String,
    pub limits: Vec<LimitCount>,
}

/// The upgrade-intent signal over the range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeIntentView {
    pub collisions: i64,
    pub orgs: i64,
    pub by_limit: Vec<LimitCount>,
    /// At most [`TOP_COLLISION_ORGS`].
    pub top: Vec<CollisionRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevenueReport {
    pub enabled: bool,
    /// `YYYY-MM`, inclusive.
    pub since: String,
    /// `YYYY-MM`, inclusive.
    pub until: String,
    pub include_internal: bool,
    pub excluded: ExcludedCounts,
    /// RFC 3339 — "now" for the MRR and the open month.
    pub as_of: String,
    /// What Stripe billed; `not_measured` without `saas` or with nothing
    /// on record.
    pub billed: Measured<Billed>,
    /// The list-price ESTIMATE over every live org, labelled as such.
    pub estimate: MrrEstimate,
    pub cost: Measured<CostBasis>,
    pub upgrade_intent: UpgradeIntentView,
    pub orgs: Vec<OrgRevenue>,
    pub orgs_truncated: bool,
}

#[derive(Debug, Deserialize)]
pub struct RevenueQuery {
    /// `YYYY-MM`, inclusive. Default: 11 months before `until`.
    #[serde(default)]
    pub since: Option<String>,
    /// `YYYY-MM`, inclusive. Default: the current month.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub include_internal: bool,
}

// ── Pure pieces ──────────────────────────────────────────────────────────

/// Whether an org's MRR fell to zero in any of the months.
pub fn churned_in(o: &OrgBilling, months: &[(String, i64, i64)]) -> bool {
    months
        .iter()
        .any(|(_, start, end)| o.mrr_at(start - 1) > 0 && o.mrr_at(end - 1) == 0)
}

/// The margin, in cents: billed MRR less the cost to serve, only where
/// both exist and the cost's currency is the invoice's.
pub fn margin_cents(
    billed_mrr: Option<i64>,
    currency: Option<&str>,
    cost: Option<f64>,
    cost_currency: Option<&str>,
) -> Option<i64> {
    let (mrr, cur, cost, cost_cur) = (billed_mrr?, currency?, cost?, cost_currency?);
    cur.eq_ignore_ascii_case(cost_cur)
        .then(|| mrr - (cost * 100.0).round() as i64)
}

/// The billed figures by channel and currency (rows with anything in them),
/// busiest first.
pub fn channel_rows(
    orgs: &HashMap<ObjectId, OrgBilling>,
    channel_of: &HashMap<ObjectId, String>,
    months: &[(String, i64, i64)],
    now_ms: i64,
) -> Vec<ChannelRevenue> {
    let (Some(first), Some(last)) = (months.first(), months.last()) else {
        return Vec::new();
    };
    let (start, end) = (first.1, last.2);
    let mut by: BTreeMap<(String, String), ChannelRevenue> = BTreeMap::new();
    for (tenant, o) in orgs {
        let channel = channel_of
            .get(tenant)
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        let currency = o.currency.clone().unwrap_or_else(|| "unknown".into());
        let row = by
            .entry((channel.clone(), currency.clone()))
            .or_insert_with(|| ChannelRevenue {
                channel,
                currency,
                paying_orgs: 0,
                mrr_cents: 0,
                new_paying_orgs: 0,
                churned_orgs: 0,
                trials: 0,
                converted: 0,
            });
        let mrr = o.mrr_at(now_ms);
        if mrr > 0 {
            row.paying_orgs += 1;
            row.mrr_cents += mrr;
        }
        if o.paid_since.is_some_and(|t| (start..end).contains(&t)) {
            row.new_paying_orgs += 1;
        }
        if churned_in(o, months) {
            row.churned_orgs += 1;
        }
        if let Some(t) = o.trial_started.filter(|t| (start..end).contains(t)) {
            row.trials += 1;
            if o.paid_since.is_some_and(|p| p >= t) {
                row.converted += 1;
            }
        }
    }
    let mut rows: Vec<ChannelRevenue> = by
        .into_values()
        .filter(|r| {
            r.paying_orgs + r.new_paying_orgs + r.churned_orgs + r.trials > 0 || r.mrr_cents > 0
        })
        .collect();
    rows.sort_by(|a, b| {
        b.mrr_cents
            .cmp(&a.mrr_cents)
            .then_with(|| b.paying_orgs.cmp(&a.paying_orgs))
            .then_with(|| (&a.channel, &a.currency).cmp(&(&b.channel, &b.currency)))
    });
    rows
}

/// The range's invoices, failures, first payments and cancellations.
pub fn range_totals(
    rows: &[BillingEvent],
    orgs: &HashMap<ObjectId, OrgBilling>,
    start: i64,
    end: i64,
) -> RangeTotals {
    let inside = |r: &&BillingEvent| (start..end).contains(&r.ts.timestamp_millis());
    let mut billed: BTreeMap<String, i64> = BTreeMap::new();
    let mut totals = RangeTotals {
        invoices_paid: 0,
        billed: Vec::new(),
        payment_failures: 0,
        new_paying_orgs: orgs
            .values()
            .filter(|o| o.paid_since.is_some_and(|t| (start..end).contains(&t)))
            .count() as i64,
        cancellations: 0,
    };
    for r in rows.iter().filter(inside) {
        match r.kind {
            BillingKind::InvoicePaid => {
                totals.invoices_paid += 1;
                *billed
                    .entry(r.currency.clone().unwrap_or_else(|| "unknown".into()))
                    .or_insert(0) += r.amount_cents.unwrap_or(0);
            }
            BillingKind::InvoicePaymentFailed => totals.payment_failures += 1,
            BillingKind::SubscriptionDeleted => totals.cancellations += 1,
            _ => {}
        }
    }
    totals.billed = billed
        .into_iter()
        .map(|(currency, cents)| CurrencyCents { currency, cents })
        .collect();
    totals
}

/// Each month of the range: frozen when the frozen totals hold it (only
/// read when exclusions apply), else live; `on_record` against the first
/// billing row.
pub fn month_blocks(
    months: &[(String, i64, i64)],
    live: &BTreeMap<String, Vec<MonthMovements>>,
    frozen: &BTreeMap<String, BTreeMap<String, MonthMovements>>,
    record_start: Option<i64>,
    now_ms: i64,
) -> Vec<MonthBlock> {
    // currency → months, regrouped as month → currencies.
    let mut live_by_month: BTreeMap<&str, Vec<CurrencyMonth>> = BTreeMap::new();
    for (currency, moves) in live {
        for m in moves {
            live_by_month
                .entry(m.month.as_str())
                .or_default()
                .push(CurrencyMonth {
                    currency: currency.clone(),
                    movements: m.clone(),
                });
        }
    }
    let ordered = |mut v: Vec<CurrencyMonth>| {
        v.sort_by(|a, b| {
            b.movements
                .mrr_cents
                .cmp(&a.movements.mrr_cents)
                .then_with(|| a.currency.cmp(&b.currency))
        });
        v
    };
    months
        .iter()
        .map(|(label, _, end)| {
            if let Some(f) = frozen.get(label) {
                return MonthBlock {
                    month: label.clone(),
                    frozen: true,
                    partial: false,
                    on_record: true,
                    currencies: ordered(
                        f.iter()
                            .map(|(currency, m)| CurrencyMonth {
                                currency: currency.clone(),
                                movements: m.clone(),
                            })
                            .collect(),
                    ),
                };
            }
            let on_record = billing::on_record(record_start, *end);
            MonthBlock {
                month: label.clone(),
                frozen: false,
                partial: *end > now_ms,
                on_record,
                currencies: if on_record {
                    ordered(live_by_month.remove(label.as_str()).unwrap_or_default())
                } else {
                    Vec::new()
                },
            }
        })
        .collect()
}

// ── Reading ──────────────────────────────────────────────────────────────

/// One org, as the view reads it.
struct TenantFact {
    name: String,
    plan_raw: String,
    plan: Plan,
    status: Option<String>,
    owner: Option<ObjectId>,
    deleted: bool,
    seats: i64,
}

async fn tenant_facts(
    state: &AppState,
    excluded: &[ObjectId],
) -> Result<HashMap<ObjectId, TenantFact>, ApiError> {
    let docs = find_docs(
        state,
        "tenants",
        doc! { "_id": { "$nin": excluded } },
        doc! { "name": 1, "plan": 1, "billing.status": 1, "owner_id": 1, "deleted_at": 1 },
    )
    .await?;
    let seats = aggregate(
        state,
        "tenant_members",
        vec![
            doc! { "$match": { "tenant_id": { "$nin": excluded } } },
            doc! { "$group": { "_id": "$tenant_id", "seats": { "$sum": 1 } } },
        ],
    )
    .await?;
    let seats: HashMap<ObjectId, i64> = seats
        .iter()
        .filter_map(|d| Some((d.get_object_id("_id").ok()?, i64_of(d, "seats"))))
        .collect();
    Ok(docs
        .iter()
        .filter_map(|d| {
            let id = d.get_object_id("_id").ok()?;
            let plan_raw = str_of(d, "plan").unwrap_or_else(|| "free".into());
            Some((
                id,
                TenantFact {
                    name: str_of(d, "name").unwrap_or_default(),
                    plan: bson::from_bson(Bson::String(plan_raw.clone())).unwrap_or(Plan::Free),
                    plan_raw,
                    status: d
                        .get_document("billing")
                        .ok()
                        .and_then(|b| str_of(b, "status")),
                    owner: d.get_object_id("owner_id").ok(),
                    deleted: !matches!(d.get("deleted_at"), None | Some(Bson::Null)),
                    seats: seats.get(&id).copied().unwrap_or(0),
                },
            ))
        })
        .collect())
}

/// The range's collisions, per org (excluded orgs left out).
struct Collisions {
    view: UpgradeIntentView,
    per_org: HashMap<ObjectId, i64>,
}

async fn collisions(
    state: &AppState,
    set: &ExclusionSet,
    from_day: &str,
    to_day: &str,
    facts: &HashMap<ObjectId, TenantFact>,
) -> Result<Collisions, ApiError> {
    let rows = GrowthDao::new(&state.db)
        .read_daily(QUOTA_SOURCE, QUOTA_COLLISION_METRIC, from_day, to_day)
        .await?;
    /// One org's collisions in the range.
    #[derive(Default)]
    struct OrgHits {
        total: i64,
        days: HashSet<String>,
        last_day: String,
        limits: BTreeMap<String, i64>,
    }
    let mut total = 0;
    let mut by_limit: BTreeMap<String, i64> = BTreeMap::new();
    let mut per: HashMap<ObjectId, OrgHits> = HashMap::new();
    for r in &rows {
        let Some(tenant) = r
            .dims
            .get("tenant")
            .and_then(|t| ObjectId::parse_str(t).ok())
        else {
            continue;
        };
        if set.tenant_excluded(&tenant) {
            continue;
        }
        let limit = r.dims.get("limit").cloned().unwrap_or_default();
        total += r.value;
        *by_limit.entry(limit.clone()).or_insert(0) += r.value;
        let e = per.entry(tenant).or_default();
        e.total += r.value;
        e.days.insert(r.day.clone());
        if r.day > e.last_day {
            e.last_day = r.day.clone();
        }
        *e.limits.entry(limit).or_insert(0) += r.value;
    }
    let per_org: HashMap<ObjectId, i64> = per.iter().map(|(t, e)| (*t, e.total)).collect();
    let mut top: Vec<(ObjectId, OrgHits)> = per.into_iter().collect();
    top.sort_by(|a, b| b.1.total.cmp(&a.1.total).then_with(|| a.0.cmp(&b.0)));
    let orgs = top.len() as i64;
    top.truncate(TOP_COLLISION_ORGS);
    let limit_counts = |m: BTreeMap<String, i64>| {
        let mut v: Vec<LimitCount> = m
            .into_iter()
            .map(|(limit, count)| LimitCount { limit, count })
            .collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.limit.cmp(&b.limit)));
        v
    };
    Ok(Collisions {
        view: UpgradeIntentView {
            collisions: total,
            orgs,
            by_limit: limit_counts(by_limit),
            top: top
                .into_iter()
                .map(|(tenant, hits)| {
                    let fact = facts.get(&tenant);
                    CollisionRow {
                        tenant_id: tenant.to_hex(),
                        name: fact.map(|f| f.name.clone()).unwrap_or_default(),
                        plan: fact
                            .map(|f| f.plan_raw.clone())
                            .unwrap_or_else(|| "free".into()),
                        total: hits.total,
                        days: hits.days.len() as i64,
                        last_day: hits.last_day,
                        limits: limit_counts(hits.limits),
                    }
                })
                .collect(),
        },
        per_org,
    })
}

fn rfc3339_ms(ms: i64) -> String {
    DateTime::from_millis(ms)
        .try_to_rfc3339_string()
        .unwrap_or_default()
}

/// `GET /api/admin/growth/revenue?since=YYYY-MM&until=YYYY-MM&include_internal=`
pub async fn get_revenue(
    State(state): State<AppState>,
    _auth: GrowthAuth,
    Query(q): Query<RevenueQuery>,
) -> Result<Json<RevenueReport>, ApiError> {
    let now = DateTime::now();
    let now_ms = now.timestamp_millis();
    let months = month_range(q.since.as_deref(), q.until.as_deref(), now_ms)
        .map_err(ApiError::BadRequest)?;
    let (Some(first_month), Some(last_month)) = (months.first(), months.last()) else {
        return Err(ApiError::BadRequest("an empty range".into()));
    };
    let (range_start, range_end) = (first_month.1, last_month.2);
    let set = if q.include_internal {
        ExclusionSet::none()
    } else {
        ExclusionSet::load(&state.core).await?
    };
    let (users_excluded, tenants_excluded) = set.counts();
    let excluded = excluded_ids(&set.tenants);
    let facts = tenant_facts(&state, &excluded).await?;

    // The list-price ESTIMATE, as the digest and `/observability` read it.
    let list_price = |f: &TenantFact| {
        if f.deleted {
            0.0
        } else {
            crate::routes::cost::mrr_estimate_cents(&f.plan, f.seats as f64)
        }
    };
    let estimate = MrrEstimate {
        cents: facts.values().map(list_price).sum(),
        estimate: true,
        basis: "list price × seats (plan.price_monthly_cents), not billed revenue".into(),
    };

    // Billed — the `saas` module's record.
    let (billed, org_billing) = if mounted(&state, "saas") {
        match billing::record_start(&state.db).await? {
            None => {
                let backfill = billing::last_backfill(&state.db).await?;
                (
                    Measured::NotMeasured(NotMeasured::now(no_billing_record(backfill.as_ref()))),
                    HashMap::new(),
                )
            }
            Some(first) => {
                let rows = BillingEventDao::new(&state.db)
                    .list(None, &excluded)
                    .await?;
                let orgs = billing::fold(&rows);
                let live = billing::movements(&orgs, &rows, &months);
                let frozen = if q.include_internal {
                    BTreeMap::new()
                } else {
                    billing::read_frozen(&state.db, &first_month.0, &last_month.0).await?
                };
                let backfill = billing::last_backfill(&state.db).await?;
                let mut now_by: BTreeMap<String, CurrencyNow> = BTreeMap::new();
                for o in orgs.values() {
                    let mrr = o.mrr_at(now_ms);
                    if mrr <= 0 {
                        continue;
                    }
                    let currency = o.currency.clone().unwrap_or_else(|| "unknown".into());
                    let e = now_by.entry(currency.clone()).or_insert(CurrencyNow {
                        currency,
                        mrr_cents: 0,
                        paying_orgs: 0,
                    });
                    e.mrr_cents += mrr;
                    e.paying_orgs += 1;
                }
                let owners: Vec<ObjectId> = orgs
                    .keys()
                    .filter_map(|t| facts.get(t).and_then(|f| f.owner))
                    .collect();
                let attributions = owner_attributions(&state, &owners).await?;
                let channel_of: HashMap<ObjectId, String> = orgs
                    .keys()
                    .filter_map(|t| {
                        let owner = facts.get(t)?.owner?;
                        let attr = attributions.get(&owner)?;
                        Some((*t, acquisition_of(attr.as_ref()).channel))
                    })
                    .collect();
                let (trials, converted) = billing::trial_to_paid(&orgs, range_start, range_end);
                let billed = Billed {
                    record: Record {
                        since: rfc3339_ms(first),
                        last_event_at: rows.last().map(|r| rfc3339_ms(r.ts.timestamp_millis())),
                        backfilled_at: backfill
                            .map(|p| rfc3339_ms(p.attempted_at.timestamp_millis())),
                        rows: rows.len() as u64,
                        truncated: rows.len() as i64
                            >= meshharbor_services::dao::billing_event::MAX_ROWS,
                    },
                    now: now_by.into_values().collect(),
                    months: month_blocks(&months, &live, &frozen, Some(first), now_ms),
                    totals: range_totals(&rows, &orgs, range_start, range_end),
                    trial_to_paid: TrialToPaid {
                        trials,
                        converted,
                        rate: Rate::of(converted, trials),
                    },
                    by_channel: channel_rows(&orgs, &channel_of, &months, now_ms),
                };
                (Measured::Value(billed), orgs)
            }
        }
    } else {
        (Measured::unmounted("saas"), HashMap::new())
    };

    // The cost to serve (FR-20's ledger), for the margin.
    let (cost, costs) = if state.settings.stats.enabled {
        let c = crate::routes::cost::org_costs(&state.core, COST_RANGE).await?;
        (
            Measured::Value(CostBasis {
                range: COST_RANGE.to_string(),
                currency: c.currency.clone(),
                priced: c.priced,
            }),
            Some(c),
        )
    } else {
        (Measured::NotMeasured(NotMeasured::now(COST_OFF)), None)
    };

    // The collisions of the range's days.
    let from_day = format!("{}-01", first_month.0);
    let to_day = day_str(utc_date_of(DateTime::from_millis(range_end - 1)));
    let collided = collisions(&state, &set, &from_day, &to_day, &facts).await?;

    // The orgs worth a row: any billing history, a paid plan, or a
    // collision in the range.
    let mut ids: HashSet<ObjectId> = org_billing.keys().copied().collect();
    ids.extend(
        facts
            .iter()
            .filter(|(_, f)| !f.deleted && !matches!(f.plan, Plan::Free))
            .map(|(t, _)| *t),
    );
    ids.extend(collided.per_org.keys().copied());
    let owners: Vec<ObjectId> = ids
        .iter()
        .filter_map(|t| facts.get(t).and_then(|f| f.owner))
        .collect();
    let attributions = owner_attributions(&state, &owners).await?;
    let mut orgs: Vec<OrgRevenue> = ids
        .into_iter()
        .map(|t| {
            let fact = facts.get(&t);
            let ob = org_billing.get(&t);
            let billed_mrr = ob.filter(|o| !o.paid.is_empty()).map(|o| o.mrr_at(now_ms));
            let currency = ob.and_then(|o| o.currency.clone());
            let cost_30d = costs.as_ref().and_then(|c| c.of(&t.to_hex()));
            OrgRevenue {
                tenant_id: t.to_hex(),
                name: fact.map(|f| f.name.clone()).unwrap_or_default(),
                deleted: fact.is_none_or(|f| f.deleted),
                plan: fact
                    .map(|f| f.plan_raw.clone())
                    .unwrap_or_else(|| "free".into()),
                billing_status: fact.and_then(|f| f.status.clone()),
                seats: fact.map(|f| f.seats).unwrap_or(0),
                channel: fact
                    .and_then(|f| f.owner)
                    .and_then(|o| attributions.get(&o))
                    .map(|a| acquisition_of(a.as_ref()).channel),
                paid_since: ob.and_then(|o| o.paid_since).map(rfc3339_ms),
                billed_mrr_cents: billed_mrr,
                list_price_mrr_cents: fact.map(list_price).unwrap_or(0.0),
                margin_cents: margin_cents(
                    billed_mrr,
                    currency.as_deref(),
                    cost_30d,
                    costs.as_ref().and_then(|c| c.currency.as_deref()),
                ),
                currency,
                cost_30d,
                collisions: collided.per_org.get(&t).copied().unwrap_or(0),
            }
        })
        .collect();
    orgs.sort_by(|a, b| {
        b.billed_mrr_cents
            .unwrap_or(-1)
            .cmp(&a.billed_mrr_cents.unwrap_or(-1))
            .then_with(|| {
                b.list_price_mrr_cents
                    .partial_cmp(&a.list_price_mrr_cents)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| b.collisions.cmp(&a.collisions))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.tenant_id.cmp(&b.tenant_id))
    });
    let orgs_truncated = orgs.len() > MAX_ORG_ROWS;
    orgs.truncate(MAX_ORG_ROWS);

    Ok(Json(RevenueReport {
        enabled: true,
        since: first_month.0.clone(),
        until: last_month.0.clone(),
        include_internal: q.include_internal,
        excluded: ExcludedCounts {
            users: users_excluded as u32,
            tenants: tenants_excluded as u32,
        },
        as_of: rfc3339_ms(now_ms),
        billed,
        estimate,
        cost,
        upgrade_intent: collided.view,
        orgs,
        orgs_truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_services::billing::Paid;

    fn ms(s: &str) -> i64 {
        DateTime::parse_rfc3339_str(s).unwrap().timestamp_millis()
    }

    #[test]
    fn the_range_defaults_to_twelve_months_and_is_bounded() {
        let now = ms("2026-10-15T12:00:00Z");
        let r = month_range(None, None, now).unwrap();
        assert_eq!(r.len(), 12);
        assert_eq!(r[0].0, "2025-11");
        assert_eq!(r[11].0, "2026-10");
        assert_eq!(r[11].2, now + 1, "the open month ends now");
        assert_eq!(r[10].2, ms("2026-10-01T00:00:00Z"));
        let one = month_range(Some("2026-01"), Some("2026-01"), now).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(
            (one[0].1, one[0].2),
            (ms("2026-01-01T00:00:00Z"), ms("2026-02-01T00:00:00Z"))
        );
        // A year boundary.
        let y = month_range(Some("2025-12"), Some("2026-01"), now).unwrap();
        assert_eq!(
            y.iter().map(|m| m.0.as_str()).collect::<Vec<_>>(),
            ["2025-12", "2026-01"]
        );
        assert!(
            month_range(None, Some("2026-11"), now).is_err(),
            "the future"
        );
        assert!(month_range(Some("2026-05"), Some("2026-04"), now).is_err());
        assert!(month_range(Some("2019-12"), None, now).is_err());
        assert!(
            month_range(Some("2023-01"), Some("2026-01"), now).is_err(),
            "37 months"
        );
        assert!(
            month_range(Some("2023-02"), Some("2026-01"), now).is_ok(),
            "36 months"
        );
        assert!(
            month_range(Some("2026-1"), None, now).is_err(),
            "not padded"
        );
        assert!(month_range(Some("2026-13"), None, now).is_err());
        assert!(month_range(Some("26-10-01"), None, now).is_err());
    }

    fn org(paid: &[(&str, &str, i64)], ended: &[&str]) -> OrgBilling {
        OrgBilling {
            currency: Some("eur".into()),
            paid: paid
                .iter()
                .map(|(s, e, c)| Paid {
                    start_ms: ms(s),
                    end_ms: ms(e),
                    monthly_cents: *c,
                })
                .collect(),
            ended: ended.iter().map(|e| ms(e)).collect(),
            paid_since: paid.first().map(|(s, _, _)| ms(s)),
            ..OrgBilling::default()
        }
    }

    #[test]
    fn a_churn_is_a_month_whose_mrr_fell_to_zero() {
        let now = ms("2026-10-15T12:00:00Z");
        let months = month_range(Some("2026-08"), Some("2026-10"), now).unwrap();
        let stayed = org(
            &[
                ("2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z", 2000),
                ("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", 2000),
                ("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", 2000),
            ],
            &[],
        );
        assert!(!churned_in(&stayed, &months));
        let left = org(
            &[("2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z", 2000)],
            &["2026-09-01T00:00:00Z"],
        );
        assert!(churned_in(&left, &months));
    }

    #[test]
    fn a_margin_needs_both_figures_in_one_currency() {
        assert_eq!(
            margin_cents(Some(1920), Some("eur"), Some(0.58), Some("EUR")),
            Some(1862)
        );
        assert_eq!(
            margin_cents(Some(0), Some("eur"), Some(1.0), Some("EUR")),
            Some(-100),
            "a churned org still costs"
        );
        assert_eq!(
            margin_cents(Some(1920), Some("usd"), Some(0.58), Some("EUR")),
            None
        );
        assert_eq!(
            margin_cents(None, Some("eur"), Some(0.58), Some("EUR")),
            None
        );
        assert_eq!(
            margin_cents(Some(1920), Some("eur"), None, Some("EUR")),
            None
        );
        assert_eq!(
            margin_cents(Some(1920), Some("eur"), Some(0.58), None),
            None
        );
    }

    #[test]
    fn channels_group_paying_new_churned_and_trials() {
        let now = ms("2026-10-15T12:00:00Z");
        let months = month_range(Some("2026-08"), Some("2026-10"), now).unwrap();
        let (a, b, c) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let mut paying = org(
            &[("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", 1920)],
            &[],
        );
        paying.trial_started = Some(ms("2026-09-20T00:00:00Z"));
        let churned = org(
            &[("2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z", 2400)],
            &["2026-09-01T00:00:00Z"],
        );
        let mut trialing = OrgBilling {
            currency: Some("eur".into()),
            ..OrgBilling::default()
        };
        trialing.trial_started = Some(ms("2026-10-10T00:00:00Z"));
        let orgs: HashMap<ObjectId, OrgBilling> = [(a, paying), (b, churned), (c, trialing)]
            .into_iter()
            .collect();
        let channel_of: HashMap<ObjectId, String> = [
            (a, "social".to_string()),
            (b, "social".to_string()),
            (c, "search".to_string()),
        ]
        .into_iter()
        .collect();
        let rows = channel_rows(&orgs, &channel_of, &months, now);
        assert_eq!(rows.len(), 2);
        let social = &rows[0];
        assert_eq!(social.channel, "social");
        assert_eq!(
            (
                social.paying_orgs,
                social.mrr_cents,
                social.new_paying_orgs,
                social.churned_orgs,
                social.trials,
                social.converted
            ),
            (1, 1920, 2, 1, 1, 1)
        );
        let search = &rows[1];
        assert_eq!(
            (search.channel.as_str(), search.trials, search.converted),
            ("search", 1, 0)
        );
        // An org whose owner is gone reads `unknown`, never a person.
        let rows = channel_rows(&orgs, &HashMap::new(), &months, now);
        assert!(rows.iter().all(|r| r.channel == "unknown"));
    }

    #[test]
    fn a_month_before_the_record_is_not_measured_and_a_frozen_one_is_read_as_frozen() {
        let now = ms("2026-10-15T12:00:00Z");
        let months = month_range(Some("2026-07"), Some("2026-10"), now).unwrap();
        let mv = |month: &str, mrr: i64| MonthMovements {
            month: month.into(),
            mrr_cents: mrr,
            ..MonthMovements::default()
        };
        let live: BTreeMap<String, Vec<MonthMovements>> = [(
            "eur".to_string(),
            vec![mv("2026-08", 100), mv("2026-09", 200), mv("2026-10", 300)],
        )]
        .into_iter()
        .collect();
        let frozen: BTreeMap<String, BTreeMap<String, MonthMovements>> = [(
            "2026-08".to_string(),
            [("eur".to_string(), mv("2026-08", 90))]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect();
        let blocks = month_blocks(
            &months,
            &live,
            &frozen,
            Some(ms("2026-08-10T00:00:00Z")),
            now,
        );
        assert_eq!(blocks.len(), 4);
        assert!(!blocks[0].on_record, "July ended before the record");
        assert!(blocks[0].currencies.is_empty());
        assert!(blocks[1].frozen && blocks[1].currencies[0].movements.mrr_cents == 90);
        assert_eq!(blocks[1].currencies[0].currency, "eur");
        assert!(!blocks[2].frozen && blocks[2].on_record);
        assert_eq!(blocks[2].currencies[0].movements.mrr_cents, 200);
        assert!(blocks[3].partial, "October is open");
        // The wire: the currency beside the flattened movements.
        let json = serde_json::to_value(&blocks[2]).unwrap();
        assert_eq!(json["currencies"][0]["currency"], "eur");
        assert_eq!(json["currencies"][0]["mrr_cents"], 200);
        assert_eq!(json["currencies"][0]["month"], "2026-09");
    }
}
