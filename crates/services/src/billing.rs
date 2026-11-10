// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P4 — billed revenue, from what Stripe says was billed (spec §3g).
//!
//! Two halves, both pure so they are testable without a network or a
//! database:
//!
//! * **Reading Stripe's objects** into a [`BillingEvent`] row — the six
//!   event kinds of §3g. The amounts come from the INVOICE (what was billed,
//!   after any coupon, before tax), never from the price list. Stripe moved
//!   fields between API versions (the 2025-03-31 "basil" release took
//!   `invoice.subscription` into `invoice.parent.subscription_details`, a
//!   line's `proration` into `line.parent.subscription_item_details` and the
//!   subscription's `current_period_*` onto its items), so every reader here
//!   tries the classic path and then the new one: a webhook endpoint pinned
//!   to either version reads the same.
//! * **The MRR model** over those rows: an org's billed MRR at an instant is
//!   the recurring part of its newest paid invoice whose period covers that
//!   instant, normalised to a month — and nothing once the subscription was
//!   deleted. Month by month that gives new, expansion, contraction and
//!   churned MRR, paying orgs, trial → paid and each org's `paid_since`.
//!
//! The list-price figure (`Plan::price_monthly_cents` × seats) stays where
//! it was (`routes/cost.rs`), labelled an estimate; nothing here reads it.

use std::collections::{BTreeMap, HashMap};

use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use meshharbor_db::models::tenant::BillingInterval;

use crate::dao::billing_event::{BillingEvent, BillingKind, BillingSource};

/// A day in milliseconds.
const DAY_MS: i64 = 86_400_000;
/// The mean month the normalisation divides by: 365.25 / 12 days.
const MONTH_DAYS: f64 = 30.4375;

// ── Reading Stripe's objects ─────────────────────────────────────────────

fn s<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    (!cur.is_null()).then_some(cur)
}

fn s_str(v: &Value, path: &[&str]) -> Option<String> {
    s(v, path)
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}

fn s_i64(v: &Value, path: &[&str]) -> Option<i64> {
    s(v, path).and_then(Value::as_i64)
}

/// An id field that is either the id itself or an expanded object.
fn id_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(x) if !x.is_empty() => Some(x.clone()),
        Value::Object(o) => o
            .get("id")
            .and_then(Value::as_str)
            .filter(|x| !x.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn unix_ms(secs: i64) -> DateTime {
    DateTime::from_millis(secs.saturating_mul(1000))
}

/// The invoice's subscription: classic `subscription`, or basil's
/// `parent.subscription_details.subscription`.
pub fn invoice_subscription(invoice: &Value) -> Option<String> {
    id_of(invoice.get("subscription")).or_else(|| {
        id_of(s(
            invoice,
            &["parent", "subscription_details", "subscription"],
        ))
    })
}

/// The `tenant_id` the checkout stamped on the subscription's metadata, as
/// an invoice or a subscription carries it.
pub fn metadata_tenant(obj: &Value) -> Option<ObjectId> {
    [
        &["metadata", "tenant_id"][..],
        &["subscription_details", "metadata", "tenant_id"][..],
        &["parent", "subscription_details", "metadata", "tenant_id"][..],
    ]
    .iter()
    .find_map(|p| s_str(obj, p))
    .and_then(|hex| ObjectId::parse_str(hex).ok())
}

/// One invoice line, as the revenue reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct LineFact {
    /// `amount` less every `discount_amounts` entry: what this line billed
    /// after coupons, before tax.
    pub net_cents: i64,
    pub quantity: Option<i64>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub proration: bool,
    pub subscription: bool,
    pub price_id: Option<String>,
    /// The price's billing interval in months (1 monthly, 12 yearly), when
    /// the line names it.
    pub interval_months: Option<f64>,
}

fn interval_months(interval: &str, count: i64) -> Option<f64> {
    let count = count.max(1) as f64;
    match interval {
        "month" => Some(count),
        "year" => Some(12.0 * count),
        "week" => Some(7.0 * count / MONTH_DAYS),
        "day" => Some(count / MONTH_DAYS),
        _ => None,
    }
}

/// Read one invoice line, classic or basil.
pub fn line_fact(line: &Value) -> LineFact {
    let amount = s_i64(line, &["amount"]).unwrap_or(0);
    let discounts: i64 = line
        .get("discount_amounts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|d| d.get("amount").and_then(Value::as_i64))
                .sum()
        })
        .unwrap_or(0);
    let proration = s(line, &["proration"])
        .and_then(Value::as_bool)
        .or_else(|| {
            s(line, &["parent", "subscription_item_details", "proration"]).and_then(Value::as_bool)
        })
        .unwrap_or(false);
    let subscription = s_str(line, &["type"]).as_deref() == Some("subscription")
        || s_str(line, &["parent", "type"]).as_deref() == Some("subscription_item_details")
        || s(line, &["subscription"]).is_some();
    let price_id = id_of(line.get("price"))
        .or_else(|| s_str(line, &["pricing", "price_details", "price"]))
        .or_else(|| id_of(line.get("plan")));
    let interval = s_str(line, &["price", "recurring", "interval"])
        .map(|i| {
            (
                i,
                s_i64(line, &["price", "recurring", "interval_count"]).unwrap_or(1),
            )
        })
        .or_else(|| {
            s_str(line, &["plan", "interval"])
                .map(|i| (i, s_i64(line, &["plan", "interval_count"]).unwrap_or(1)))
        });
    LineFact {
        net_cents: amount - discounts,
        quantity: s_i64(line, &["quantity"]),
        period_start: s_i64(line, &["period", "start"]),
        period_end: s_i64(line, &["period", "end"]),
        proration,
        subscription,
        price_id,
        interval_months: interval.and_then(|(i, c)| interval_months(&i, c)),
    }
}

/// The recurring part of an invoice: its subscription lines that are not
/// prorations. Its amount (after discounts), seats, period and interval.
#[derive(Debug, Clone, PartialEq)]
pub struct Recurring {
    pub cents: i64,
    pub seats: Option<i64>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub price_id: Option<String>,
    pub interval_months: Option<f64>,
}

pub fn recurring_of(invoice: &Value) -> Option<Recurring> {
    let lines: Vec<LineFact> = s(invoice, &["lines", "data"])
        .and_then(Value::as_array)
        .map(|a| a.iter().map(line_fact).collect())
        .unwrap_or_default();
    let recurring: Vec<&LineFact> = lines
        .iter()
        .filter(|l| l.subscription && !l.proration)
        .collect();
    if recurring.is_empty() {
        return None;
    }
    Some(Recurring {
        cents: recurring.iter().map(|l| l.net_cents).sum(),
        seats: recurring
            .iter()
            .filter_map(|l| l.quantity)
            .reduce(|a, b| a + b),
        period_start: recurring.iter().filter_map(|l| l.period_start).min(),
        period_end: recurring.iter().filter_map(|l| l.period_end).max(),
        price_id: recurring.iter().find_map(|l| l.price_id.clone()),
        interval_months: recurring.iter().find_map(|l| l.interval_months),
    })
}

/// The subscription's current period: classic top level, or (basil) its
/// first item's.
pub fn subscription_period(sub: &Value) -> (Option<i64>, Option<i64>) {
    let item = |k: &str| {
        s(sub, &["items", "data"])
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|i| s_i64(i, &[k]))
    };
    (
        s_i64(sub, &["current_period_start"]).or_else(|| item("current_period_start")),
        s_i64(sub, &["current_period_end"]).or_else(|| item("current_period_end")),
    )
}

/// The subscription's seats: its items' quantities summed (classic
/// subscriptions also carry a top-level `quantity`).
pub fn subscription_seats(sub: &Value) -> Option<i64> {
    let items: Vec<i64> = s(sub, &["items", "data"])
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|i| i.get("quantity").and_then(Value::as_i64))
                .collect()
        })
        .unwrap_or_default();
    if items.is_empty() {
        s_i64(sub, &["quantity"])
    } else {
        Some(items.iter().sum())
    }
}

/// The subscription's (first) price id.
pub fn subscription_price(sub: &Value) -> Option<String> {
    s(sub, &["items", "data"])
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|i| id_of(i.get("price")).or_else(|| id_of(i.get("plan"))))
}

/// FR-115 — the Stripe Price ids this server sells, per plan and interval.
/// An empty id is a price it does not sell (annual is off until its Prices
/// are configured). Each Price carries both currencies (`currency_options`),
/// so the currency is not part of the key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PriceIds<'a> {
    pub pro: &'a str,
    pub business: &'a str,
    pub pro_annual: &'a str,
    pub business_annual: &'a str,
}

impl<'a> PriceIds<'a> {
    pub fn of(s: &'a meshharbor_config::StripeSettings) -> Self {
        Self {
            pro: s.price_pro.trim(),
            business: s.price_business.trim(),
            pro_annual: s.price_pro_annual.trim(),
            business_annual: s.price_business_annual.trim(),
        }
    }

    fn table(&self) -> [(&'a str, &'static str, BillingInterval); 4] {
        [
            (self.pro, "pro", BillingInterval::Month),
            (self.business, "business", BillingInterval::Month),
            (self.pro_annual, "pro", BillingInterval::Year),
            (self.business_annual, "business", BillingInterval::Year),
        ]
    }

    /// The plan id and interval of a price this server sells.
    pub fn lookup(&self, price: &str) -> Option<(&'static str, BillingInterval)> {
        let price = price.trim();
        if price.is_empty() {
            return None;
        }
        self.table()
            .into_iter()
            .find(|(id, _, _)| !id.is_empty() && *id == price)
            .map(|(_, plan, interval)| (plan, interval))
    }

    /// The price for a plan id and interval, when this server sells it.
    pub fn price_for(&self, plan: &str, interval: BillingInterval) -> Option<&'a str> {
        self.table()
            .into_iter()
            .find(|(id, p, i)| *p == plan && *i == interval && !id.is_empty())
            .map(|(id, _, _)| id)
    }
}

/// Our plan for a Stripe price id: one of the configured prices (monthly or
/// annual), else `None` (a price this server does not sell).
pub fn plan_for_price(price: Option<&str>, prices: &PriceIds) -> Option<String> {
    prices.lookup(price?).map(|(plan, _)| plan.to_string())
}

/// The six Stripe event types §3g records, and the kind each becomes.
pub fn kind_of(event_type: &str) -> Option<BillingKind> {
    Some(match event_type {
        "customer.subscription.created" => BillingKind::SubscriptionCreated,
        "customer.subscription.updated" => BillingKind::SubscriptionUpdated,
        "customer.subscription.deleted" => BillingKind::SubscriptionDeleted,
        "invoice.paid" => BillingKind::InvoicePaid,
        "invoice.payment_failed" => BillingKind::InvoicePaymentFailed,
        "customer.subscription.trial_will_end" => BillingKind::TrialWillEnd,
        _ => return None,
    })
}

/// What one Stripe object says, before the tenant is known.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub kind: BillingKind,
    pub customer: Option<String>,
    pub subscription: Option<String>,
    pub metadata_tenant: Option<ObjectId>,
    pub row: BillingEvent,
}

/// Read one of the six event kinds into a row (its `tenant_id` still the
/// placeholder — [`Parsed::with_tenant`] fills it). `event_created` is the
/// event's `created` (Unix seconds), the fallback time.
pub fn parse(
    kind: BillingKind,
    obj: &Value,
    event_id: Option<&str>,
    event_created: Option<i64>,
    prices: &PriceIds,
    now: DateTime,
) -> Option<Parsed> {
    let stripe_id = s_str(obj, &["id"])?;
    let customer = id_of(obj.get("customer"));
    let currency = s_str(obj, &["currency"]).map(|c| c.to_ascii_lowercase());
    let at = |secs: Option<i64>| secs.map(unix_ms);
    let fallback_ts = at(event_created).unwrap_or(now);
    let mut row = BillingEvent {
        id: ObjectId::new(),
        tenant_id: ObjectId::from_bytes([0; 12]),
        kind,
        plan: None,
        seats: None,
        amount_cents: None,
        recurring_cents: None,
        interval_months: None,
        currency,
        period_start: None,
        period_end: None,
        stripe_id,
        subscription_id: None,
        status: None,
        reason: None,
        cancel_at_period_end: None,
        event_id: event_id.filter(|e| !e.is_empty()).map(str::to_string),
        source: BillingSource::Webhook,
        ts: fallback_ts,
        recorded_at: now,
    };
    let subscription = match kind {
        BillingKind::InvoicePaid | BillingKind::InvoicePaymentFailed => {
            let sub = invoice_subscription(obj);
            row.amount_cents = if kind == BillingKind::InvoicePaid {
                s_i64(obj, &["amount_paid"])
            } else {
                s_i64(obj, &["amount_due"])
            };
            if let Some(r) = recurring_of(obj) {
                row.recurring_cents = Some(r.cents);
                row.seats = r.seats;
                row.period_start = at(r.period_start);
                row.period_end = at(r.period_end);
                row.interval_months = r.interval_months;
                row.plan = plan_for_price(r.price_id.as_deref(), prices);
            }
            row.reason = s_str(obj, &["billing_reason"]);
            row.status = s_str(obj, &["status"]);
            if kind == BillingKind::InvoicePaid {
                row.ts = at(s_i64(obj, &["status_transitions", "paid_at"])).unwrap_or(fallback_ts);
            }
            sub
        }
        BillingKind::SubscriptionCreated
        | BillingKind::SubscriptionUpdated
        | BillingKind::SubscriptionDeleted
        | BillingKind::TrialWillEnd => {
            let (start, end) = subscription_period(obj);
            row.period_start = at(start);
            row.period_end = at(end);
            row.seats = subscription_seats(obj);
            row.plan = plan_for_price(subscription_price(obj).as_deref(), prices)
                .or_else(|| s_str(obj, &["metadata", "plan"]));
            row.status = s_str(obj, &["status"]);
            row.cancel_at_period_end = s(obj, &["cancel_at_period_end"]).and_then(Value::as_bool);
            if kind == BillingKind::TrialWillEnd {
                row.period_end = at(s_i64(obj, &["trial_end"])).or(row.period_end);
            }
            if kind == BillingKind::SubscriptionDeleted {
                row.ts = at(s_i64(obj, &["ended_at"]))
                    .or_else(|| at(s_i64(obj, &["canceled_at"])))
                    .unwrap_or(fallback_ts);
            }
            Some(row.stripe_id.clone())
        }
    };
    row.subscription_id = subscription.clone();
    Some(Parsed {
        kind,
        customer,
        subscription,
        metadata_tenant: metadata_tenant(obj),
        row,
    })
}

impl Parsed {
    pub fn with_tenant(mut self, tenant_id: ObjectId) -> BillingEvent {
        self.row.tenant_id = tenant_id;
        self.row
    }
}

// ── The MRR model ────────────────────────────────────────────────────────

/// The months an invoice's recurring part pays for: the price's interval
/// when the invoice named it, else the period's length (a month is 30.4375
/// days; a period of 25 days or more rounds to whole months).
pub fn months_of(row: &BillingEvent) -> Option<f64> {
    if let Some(m) = row.interval_months.filter(|m| *m > 0.0) {
        return Some(m);
    }
    let (start, end) = (row.period_start?, row.period_end?);
    let days = (end.timestamp_millis() - start.timestamp_millis()) as f64 / DAY_MS as f64;
    if days <= 0.0 {
        return None;
    }
    Some(if days >= 25.0 {
        (days / MONTH_DAYS).round().max(1.0)
    } else {
        days / MONTH_DAYS
    })
}

/// One paid invoice's contribution to MRR: its recurring cents per month,
/// over its period.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Paid {
    pub start_ms: i64,
    pub end_ms: i64,
    pub monthly_cents: i64,
}

/// What one org's billing history amounts to.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OrgBilling {
    pub currency: Option<String>,
    /// Paid invoices with a recurring part above 0, oldest first.
    pub paid: Vec<Paid>,
    /// When a subscription was deleted.
    pub ended: Vec<i64>,
    /// The first invoice paid with an amount above 0 (the funnel's "paid").
    pub paid_since: Option<i64>,
    /// The first moment the org was seen trialing.
    pub trial_started: Option<i64>,
    pub plan: Option<String>,
    pub seats: Option<i64>,
}

impl OrgBilling {
    /// Fold one org's rows (any order).
    pub fn of(rows: &[&BillingEvent]) -> Self {
        let mut rows: Vec<&&BillingEvent> = rows.iter().collect();
        rows.sort_by_key(|r| r.ts.timestamp_millis());
        let mut out = OrgBilling::default();
        for r in rows {
            let ts = r.ts.timestamp_millis();
            if out.currency.is_none() {
                out.currency.clone_from(&r.currency);
            }
            match r.kind {
                BillingKind::InvoicePaid => {
                    if r.amount_cents.unwrap_or(0) > 0 && out.paid_since.is_none() {
                        out.paid_since = Some(ts);
                    }
                    let recurring = r.recurring_cents.unwrap_or(0);
                    if let (true, Some(months), Some(s), Some(e)) =
                        (recurring > 0, months_of(r), r.period_start, r.period_end)
                    {
                        out.paid.push(Paid {
                            start_ms: s.timestamp_millis(),
                            end_ms: e.timestamp_millis(),
                            monthly_cents: (recurring as f64 / months).round() as i64,
                        });
                        if r.plan.is_some() {
                            out.plan.clone_from(&r.plan);
                        }
                        if r.seats.is_some() {
                            out.seats = r.seats;
                        }
                    }
                }
                BillingKind::SubscriptionDeleted => out.ended.push(ts),
                BillingKind::SubscriptionCreated
                | BillingKind::SubscriptionUpdated
                | BillingKind::TrialWillEnd => {
                    let trialing = r.kind == BillingKind::TrialWillEnd
                        || r.status.as_deref() == Some("trialing");
                    if trialing && out.trial_started.is_none() {
                        out.trial_started = Some(ts);
                    }
                }
                BillingKind::InvoicePaymentFailed => {}
            }
        }
        out.paid.sort_by_key(|p| p.start_ms);
        out
    }

    /// Billed MRR at `t` (ms): the newest paid period covering `t`, unless
    /// a deletion at or before `t` came after that period began.
    pub fn mrr_at(&self, t: i64) -> i64 {
        let Some(p) = self
            .paid
            .iter()
            .filter(|p| p.start_ms <= t && t < p.end_ms)
            .max_by_key(|p| p.start_ms)
        else {
            return 0;
        };
        if self.ended.iter().any(|&e| e <= t && e >= p.start_ms) {
            return 0;
        }
        p.monthly_cents
    }
}

/// One month's movements for one currency.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonthMovements {
    /// `YYYY-MM`.
    pub month: String,
    /// Billed MRR at the month's end.
    pub mrr_cents: i64,
    pub paying_orgs: i64,
    /// From zero the month before.
    pub new_cents: i64,
    pub new_orgs: i64,
    pub expansion_cents: i64,
    pub contraction_cents: i64,
    /// To zero.
    pub churned_cents: i64,
    pub churned_orgs: i64,
    /// `new + expansion − contraction − churned`.
    pub net_new_cents: i64,
    /// Invoices paid in the month, and what they billed (every line,
    /// prorations included, after coupons) — cash, beside the MRR.
    pub invoices_paid: i64,
    pub billed_cents: i64,
}

/// The last instant of a month that ends at `end_ms` (exclusive).
fn last_instant(end_ms: i64) -> i64 {
    end_ms - 1
}

/// Each month's movements, per currency: MRR at the end of the month
/// against the end of the month before, org by org, and the invoices the
/// month saw. `months` are `(label, start_ms, end_ms)`, oldest first; the
/// first one's "before" is its own start. A currency with nothing in a month
/// has no entry for it.
pub fn movements(
    orgs: &HashMap<ObjectId, OrgBilling>,
    rows: &[BillingEvent],
    months: &[(String, i64, i64)],
) -> BTreeMap<String, Vec<MonthMovements>> {
    let mut out: BTreeMap<String, Vec<MonthMovements>> = BTreeMap::new();
    for (label, start, end) in months {
        let mut per: BTreeMap<String, MonthMovements> = BTreeMap::new();
        for (currency, (n, cents)) in invoices_in(rows, *start, *end) {
            let m = per.entry(currency).or_insert_with(|| MonthMovements {
                month: label.clone(),
                ..MonthMovements::default()
            });
            m.invoices_paid = n;
            m.billed_cents = cents;
        }
        for org in orgs.values() {
            let currency = org.currency.clone().unwrap_or_else(|| "unknown".into());
            let prev = org.mrr_at(start - 1);
            let cur = org.mrr_at(last_instant(*end));
            if prev == 0 && cur == 0 {
                continue;
            }
            let m = per.entry(currency).or_insert_with(|| MonthMovements {
                month: label.clone(),
                ..MonthMovements::default()
            });
            m.mrr_cents += cur;
            if cur > 0 {
                m.paying_orgs += 1;
            }
            match (prev, cur) {
                (0, c) => {
                    m.new_cents += c;
                    m.new_orgs += 1;
                }
                (p, 0) => {
                    m.churned_cents += p;
                    m.churned_orgs += 1;
                }
                (p, c) if c > p => m.expansion_cents += c - p,
                (p, c) if c < p => m.contraction_cents += p - c,
                _ => {}
            }
        }
        for (currency, mut m) in per {
            m.net_new_cents =
                m.new_cents + m.expansion_cents - m.contraction_cents - m.churned_cents;
            out.entry(currency).or_default().push(m);
        }
    }
    out
}

/// Group rows by org and fold each.
pub fn fold(rows: &[BillingEvent]) -> HashMap<ObjectId, OrgBilling> {
    let mut by: HashMap<ObjectId, Vec<&BillingEvent>> = HashMap::new();
    for r in rows {
        by.entry(r.tenant_id).or_default().push(r);
    }
    by.into_iter()
        .map(|(t, rows)| (t, OrgBilling::of(&rows)))
        .collect()
}

// ── Months, and the monthly freeze ───────────────────────────────────────

/// `YYYY-MM` of an instant (UTC).
pub fn month_of(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m").to_string())
        .unwrap_or_default()
}

/// A month's `[start, end)` in ms, from its `YYYY-MM`.
pub fn month_bounds(label: &str) -> Option<(i64, i64)> {
    use chrono::Datelike;
    let start = chrono::NaiveDate::parse_from_str(&format!("{label}-01"), "%Y-%m-%d").ok()?;
    let end = if start.month() == 12 {
        chrono::NaiveDate::from_ymd_opt(start.year() + 1, 1, 1)?
    } else {
        chrono::NaiveDate::from_ymd_opt(start.year(), start.month() + 1, 1)?
    };
    let ms = |d: chrono::NaiveDate| {
        d.and_hms_opt(0, 0, 0)
            .map(|t| t.and_utc().timestamp_millis())
    };
    Some((ms(start)?, ms(end)?))
}

/// The `n` months ending with the one containing `now_ms`, oldest first, as
/// `(YYYY-MM, start, end)`.
pub fn months_back(now_ms: i64, n: usize) -> Vec<(String, i64, i64)> {
    let mut out = Vec::with_capacity(n);
    let mut label = month_of(now_ms);
    for _ in 0..n {
        let Some((start, end)) = month_bounds(&label) else {
            break;
        };
        out.push((label.clone(), start, end));
        label = month_of(start - 1);
    }
    out.reverse();
    out
}

/// What a frozen month holds, per currency (`growth_daily`, source
/// `billing`, `day` the month's first day, `dims {currency, period: month}`).
pub const FROZEN_METRICS: [&str; 11] = [
    "mrr_cents",
    "paying_orgs",
    "new_cents",
    "new_orgs",
    "expansion_cents",
    "contraction_cents",
    "churned_cents",
    "churned_orgs",
    "net_new_cents",
    "invoices_paid",
    "billed_cents",
];

/// A closed month is frozen this long after it ends: a late webhook (Stripe
/// retries for three days) still lands first.
pub const FREEZE_GRACE_DAYS: i64 = 3;
/// How far back the nightly freeze looks for a closed month not yet frozen.
pub const FREEZE_LOOKBACK_MONTHS: usize = 13;

/// One month's invoices paid and what they billed, per currency.
pub fn invoices_in(rows: &[BillingEvent], start: i64, end: i64) -> BTreeMap<String, (i64, i64)> {
    let mut out: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    for r in rows {
        let ts = r.ts.timestamp_millis();
        if r.kind == BillingKind::InvoicePaid && (start..end).contains(&ts) {
            let e = out
                .entry(r.currency.clone().unwrap_or_else(|| "unknown".into()))
                .or_default();
            e.0 += 1;
            e.1 += r.amount_cents.unwrap_or(0);
        }
    }
    out
}

/// The `growth_daily` rows that freeze one month: its movements and its
/// invoices, per currency. A currency with nothing that month has no rows.
pub fn frozen_rows(
    month: &(String, i64, i64),
    orgs: &HashMap<ObjectId, OrgBilling>,
    rows: &[BillingEvent],
) -> Vec<crate::dao::growth::GrowthDaily> {
    use crate::dao::growth::{BILLING_SOURCE, daily_row};
    let (label, _, _) = month;
    let day = format!("{label}-01");
    let moves = movements(orgs, rows, std::slice::from_ref(month));
    let mut out = Vec::new();
    for (currency, months) in moves {
        let Some(m) = months.into_iter().next() else {
            continue;
        };
        let dims = || {
            BTreeMap::from([
                ("currency".to_string(), currency.clone()),
                ("period".to_string(), "month".to_string()),
            ])
        };
        for (metric, value) in [
            ("mrr_cents", m.mrr_cents),
            ("paying_orgs", m.paying_orgs),
            ("new_cents", m.new_cents),
            ("new_orgs", m.new_orgs),
            ("expansion_cents", m.expansion_cents),
            ("contraction_cents", m.contraction_cents),
            ("churned_cents", m.churned_cents),
            ("churned_orgs", m.churned_orgs),
            ("net_new_cents", m.net_new_cents),
            ("invoices_paid", m.invoices_paid),
            ("billed_cents", m.billed_cents),
        ] {
            out.push(daily_row(BILLING_SOURCE, metric, dims(), &day, value));
        }
    }
    out
}

/// Whether a month is frozen: its `growth_pulls` row (`billing:YYYY-MM-01`)
/// says `ok`.
pub async fn is_frozen(db: &mongodb::Database, label: &str) -> crate::dao::base::DaoResult<bool> {
    use crate::dao::growth::{BILLING_SOURCE, GrowthDao, PullStatus};
    let day = format!("{label}-01");
    Ok(GrowthDao::new(db)
        .pulls_between(BILLING_SOURCE, &day, &day)
        .await?
        .iter()
        .any(|p| p.status == PullStatus::Ok))
}

/// Whether a month ending at `end_ms` lies on the record, which begins at
/// the oldest row of any org (`BillingEventDao::first_ts`, ms). Before it
/// nothing was recorded — the webhook was not wired yet and the backfill
/// had not reached that far — so a month that ended before it is NOT
/// MEASURED, never a month of zero revenue.
pub fn on_record(record_start: Option<i64>, end_ms: i64) -> bool {
    record_start.is_some_and(|start| start < end_ms)
}

/// When the record begins (ms): the oldest billing row of any org, or the
/// first frozen month if that is older — an org purged since leaves its
/// frozen months behind, and they are still the record. `None` = nothing
/// has ever been recorded, so every billed figure is not measured.
pub async fn record_start(db: &mongodb::Database) -> crate::dao::base::DaoResult<Option<i64>> {
    use crate::dao::growth::{BILLING_SOURCE, GrowthDao, PullStatus};
    let first_row = crate::dao::billing_event::BillingEventDao::new(db)
        .first_ts()
        .await?
        .map(|t| t.timestamp_millis());
    let first_frozen = GrowthDao::new(db)
        .pulls_between(BILLING_SOURCE, "0000-01-01", "9999-12-31")
        .await?
        .into_iter()
        .filter(|p| p.status == PullStatus::Ok)
        .filter_map(|p| month_bounds(p.day.get(..7)?).map(|(start, _)| start))
        .min();
    Ok(match (first_row, first_frozen) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    })
}

/// Write one month's frozen rows and mark it frozen.
async fn write_month(
    db: &mongodb::Database,
    month: &(String, i64, i64),
    orgs: &HashMap<ObjectId, OrgBilling>,
    rows: &[BillingEvent],
    now: DateTime,
) -> crate::dao::base::DaoResult<()> {
    use crate::dao::growth::{BILLING_SOURCE, GrowthDao, PulledDay};
    let frozen = frozen_rows(month, orgs, rows);
    let day = format!("{}-01", month.0);
    let growth = GrowthDao::new(db);
    growth
        .replace_daily(BILLING_SOURCE, &day, &FROZEN_METRICS, &frozen)
        .await?;
    growth
        .record_pull_ok(
            BILLING_SOURCE,
            &day,
            PulledDay {
                rows: frozen.len() as u32,
                missing_goal: None,
                truncated: false,
            },
            now,
        )
        .await?;
    Ok(())
}

/// Freeze one month from `billing_events` into `growth_daily` (internal
/// orgs left out — the frozen totals are the business's own), and mark it
/// frozen. Without `overwrite` a month already frozen is left exactly as it
/// was; the operator's backfill overwrites the months it touched, which is
/// the only thing that ever rewrites a frozen month. A month before the
/// record ([`on_record`]) is never frozen: it stays "not measured" rather
/// than becoming a frozen zero. `Ok(true)` when written.
pub async fn freeze_month(
    db: &mongodb::Database,
    label: &str,
    excluded: &[ObjectId],
    overwrite: bool,
    now: DateTime,
) -> crate::dao::base::DaoResult<bool> {
    use crate::dao::billing_event::BillingEventDao;
    if !overwrite && is_frozen(db, label).await? {
        return Ok(false);
    }
    let Some((start, end)) = month_bounds(label) else {
        return Ok(false);
    };
    if !on_record(record_start(db).await?, end) {
        return Ok(false);
    }
    let rows = BillingEventDao::new(db).list(None, excluded).await?;
    let orgs = fold(&rows);
    write_month(db, &(label.to_string(), start, end), &orgs, &rows, now).await?;
    Ok(true)
}

/// The nightly freeze: every closed month of the last
/// [`FREEZE_LOOKBACK_MONTHS`] that ended at least [`FREEZE_GRACE_DAYS`]
/// ago, lies on the record, and is not frozen yet. The months it froze.
pub async fn freeze_closed_months(
    db: &mongodb::Database,
    excluded: &[ObjectId],
    now: DateTime,
) -> crate::dao::base::DaoResult<Vec<String>> {
    use crate::dao::billing_event::BillingEventDao;
    let now_ms = now.timestamp_millis();
    let due: Vec<(String, i64, i64)> = months_back(now_ms, FREEZE_LOOKBACK_MONTHS + 1)
        .into_iter()
        .filter(|(_, _, end)| end + FREEZE_GRACE_DAYS * DAY_MS <= now_ms)
        .collect();
    let start = record_start(db).await?;
    if due.is_empty() || start.is_none() {
        return Ok(Vec::new());
    }
    let rows = BillingEventDao::new(db).list(None, excluded).await?;
    let orgs = fold(&rows);
    let mut frozen = Vec::new();
    for month in due {
        if !on_record(start, month.2) || is_frozen(db, &month.0).await? {
            continue;
        }
        write_month(db, &month, &orgs, &rows, now).await?;
        frozen.push(month.0);
    }
    Ok(frozen)
}

/// The newest successful run of the operator's backfill, as its
/// `growth_pulls` row (`billing_backfill:YYYY-MM-DD`): until one exists,
/// billed figures cover only what the webhook delivered since it was wired.
pub async fn last_backfill(
    db: &mongodb::Database,
) -> crate::dao::base::DaoResult<Option<crate::dao::growth::GrowthPull>> {
    use crate::dao::growth::{BILLING_BACKFILL_SOURCE, GrowthDao, PullStatus};
    Ok(GrowthDao::new(db)
        .pulls_between(BILLING_BACKFILL_SOURCE, "0000-01-01", "9999-12-31")
        .await?
        .into_iter()
        .filter(|p| p.status == PullStatus::Ok)
        .max_by_key(|p| p.attempted_at.timestamp_millis()))
}

/// The frozen months between two labels (inclusive), per currency.
pub async fn read_frozen(
    db: &mongodb::Database,
    from_label: &str,
    to_label: &str,
) -> crate::dao::base::DaoResult<BTreeMap<String, BTreeMap<String, MonthMovements>>> {
    use crate::dao::growth::{BILLING_SOURCE, GrowthDao, PullStatus};
    let growth = GrowthDao::new(db);
    let (from, to) = (format!("{from_label}-01"), format!("{to_label}-01"));
    let frozen_days: Vec<String> = growth
        .pulls_between(BILLING_SOURCE, &from, &to)
        .await?
        .into_iter()
        .filter(|p| p.status == PullStatus::Ok)
        .map(|p| p.day)
        .collect();
    // month → currency → movements
    let mut out: BTreeMap<String, BTreeMap<String, MonthMovements>> = BTreeMap::new();
    for day in &frozen_days {
        out.entry(day[..7].to_string()).or_default();
    }
    for metric in FROZEN_METRICS {
        for row in growth
            .read_daily(BILLING_SOURCE, metric, &from, &to)
            .await?
        {
            if !frozen_days.contains(&row.day) {
                continue;
            }
            let month = row.day[..7].to_string();
            let currency = row
                .dims
                .get("currency")
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            let m = out
                .entry(month.clone())
                .or_default()
                .entry(currency)
                .or_insert_with(|| MonthMovements {
                    month,
                    ..MonthMovements::default()
                });
            let v = row.value;
            match metric {
                "mrr_cents" => m.mrr_cents = v,
                "paying_orgs" => m.paying_orgs = v,
                "new_cents" => m.new_cents = v,
                "new_orgs" => m.new_orgs = v,
                "expansion_cents" => m.expansion_cents = v,
                "contraction_cents" => m.contraction_cents = v,
                "churned_cents" => m.churned_cents = v,
                "churned_orgs" => m.churned_orgs = v,
                "net_new_cents" => m.net_new_cents = v,
                "invoices_paid" => m.invoices_paid = v,
                "billed_cents" => m.billed_cents = v,
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Trials started in `[start, end)` and how many of them paid (an invoice
/// above 0 after the trial began).
pub fn trial_to_paid(orgs: &HashMap<ObjectId, OrgBilling>, start: i64, end: i64) -> (i64, i64) {
    let mut trials = 0;
    let mut converted = 0;
    for o in orgs.values() {
        if let Some(t) = o.trial_started.filter(|t| (start..end).contains(t)) {
            trials += 1;
            if o.paid_since.is_some_and(|p| p >= t) {
                converted += 1;
            }
        }
    }
    (trials, converted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PRO: &str = "price_pro_test";
    const BIZ: &str = "price_biz_test";
    const MONTH: i64 = 2_629_800; // 30.4375 days in seconds

    fn now() -> DateTime {
        DateTime::parse_rfc3339_str("2026-10-15T12:00:00Z").unwrap()
    }

    /// A classic (pre-basil) paid invoice: three Pro seats, a 20 % coupon.
    fn classic_invoice() -> Value {
        json!({
            "id": "in_1", "object": "invoice", "customer": "cus_1", "subscription": "sub_1",
            "status": "paid", "amount_paid": 1920, "amount_due": 1920, "currency": "usd",
            "billing_reason": "subscription_create",
            "status_transitions": { "paid_at": 1_760_000_100 },
            "subscription_details": { "metadata": { "tenant_id": "65f000000000000000000001" } },
            "lines": { "data": [{
                "id": "il_1", "amount": 2400, "currency": "usd", "quantity": 3,
                "period": { "start": 1_760_000_000, "end": 1_760_000_000 + MONTH },
                "proration": false, "type": "subscription",
                "price": { "id": PRO, "recurring": { "interval": "month", "interval_count": 1 } },
                "discount_amounts": [{ "amount": 480, "discount": "di_1" }],
            }] },
        })
    }

    /// The same invoice as the 2025-03-31 ("basil") API shapes it.
    fn basil_invoice() -> Value {
        json!({
            "id": "in_1", "object": "invoice", "customer": "cus_1",
            "status": "paid", "amount_paid": 1920, "amount_due": 1920, "currency": "USD",
            "billing_reason": "subscription_create",
            "status_transitions": { "paid_at": 1_760_000_100 },
            "parent": { "type": "subscription_details", "subscription_details": {
                "subscription": "sub_1",
                "metadata": { "tenant_id": "65f000000000000000000001" },
            } },
            "lines": { "data": [{
                "id": "il_1", "amount": 2400, "currency": "usd", "quantity": 3,
                "period": { "start": 1_760_000_000, "end": 1_760_000_000 + MONTH },
                "parent": { "type": "subscription_item_details", "subscription_item_details": {
                    "proration": false, "subscription": "sub_1", "subscription_item": "si_1",
                } },
                "pricing": { "type": "price_details", "price_details": { "price": PRO, "product": "prod_1" } },
                "discount_amounts": [{ "amount": 480, "discount": "di_1" }],
            }] },
        })
    }

    fn parsed(kind: BillingKind, obj: &Value) -> Parsed {
        let prices = PriceIds {
            pro: PRO,
            business: BIZ,
            pro_annual: PRO_YEAR,
            business_annual: "",
        };
        parse(
            kind,
            obj,
            Some("evt_1"),
            Some(1_760_000_050),
            &prices,
            now(),
        )
        .unwrap()
    }

    const PRO_YEAR: &str = "price_pro_year_test";

    /// FR-115 — the annual Prices map to their plan too, and a price this
    /// server does not sell (or an unconfigured, empty one) maps to none.
    #[test]
    fn annual_prices_map_to_their_plan_and_interval() {
        let prices = PriceIds {
            pro: PRO,
            business: BIZ,
            pro_annual: PRO_YEAR,
            business_annual: "",
        };
        assert_eq!(prices.lookup(PRO), Some(("pro", BillingInterval::Month)));
        assert_eq!(
            prices.lookup(PRO_YEAR),
            Some(("pro", BillingInterval::Year))
        );
        assert_eq!(
            prices.lookup(BIZ),
            Some(("business", BillingInterval::Month))
        );
        assert_eq!(prices.lookup(""), None, "an empty id never matches");
        assert_eq!(prices.lookup("price_someone_else"), None);
        assert_eq!(
            prices.price_for("pro", BillingInterval::Year),
            Some(PRO_YEAR)
        );
        assert_eq!(
            prices.price_for("business", BillingInterval::Year),
            None,
            "annual Business is not configured here"
        );
        assert_eq!(
            plan_for_price(Some(PRO_YEAR), &prices).as_deref(),
            Some("pro")
        );

        let mut sub = classic_invoice();
        sub["lines"]["data"][0]["price"]["id"] = json!(PRO_YEAR);
        assert_eq!(
            parsed(BillingKind::InvoicePaid, &sub).row.plan.as_deref(),
            Some("pro")
        );
    }

    /// Billed, not listed: the invoice's recurring line after the coupon,
    /// its seats, its period; the same row from either API version.
    #[test]
    fn an_invoice_reads_the_same_billed_figures_from_either_api_version() {
        for inv in [classic_invoice(), basil_invoice()] {
            let p = parsed(BillingKind::InvoicePaid, &inv);
            assert_eq!(p.customer.as_deref(), Some("cus_1"));
            assert_eq!(p.subscription.as_deref(), Some("sub_1"));
            assert_eq!(
                p.metadata_tenant,
                Some(ObjectId::parse_str("65f000000000000000000001").unwrap())
            );
            let r = p.row;
            assert_eq!(r.amount_cents, Some(1920), "what was billed");
            assert_eq!(
                r.recurring_cents,
                Some(1920),
                "2400 list less the 480 coupon"
            );
            assert_eq!(r.seats, Some(3));
            assert_eq!(r.plan.as_deref(), Some("pro"));
            assert_eq!(r.currency.as_deref(), Some("usd"));
            assert_eq!(r.ts, DateTime::from_millis(1_760_000_100_000), "paid at");
            assert_eq!(r.reason.as_deref(), Some("subscription_create"));
            assert_eq!(months_of(&r), Some(1.0));
        }
        // The classic shape names the interval; basil's does not, and the
        // period's length says the same.
        assert_eq!(
            parsed(BillingKind::InvoicePaid, &classic_invoice())
                .row
                .interval_months,
            Some(1.0)
        );
    }

    /// A proration line (a mid-period seat change) is billed but is not
    /// recurring: it never inflates MRR.
    #[test]
    fn a_proration_is_billed_but_not_recurring() {
        let mut inv = classic_invoice();
        inv["amount_paid"] = json!(2720);
        inv["lines"]["data"].as_array_mut().unwrap().push(json!({
            "amount": 800, "quantity": 1, "proration": true, "type": "subscription",
            "period": { "start": 1_760_500_000, "end": 1_760_000_000 + MONTH },
            "price": { "id": PRO },
        }));
        let r = parsed(BillingKind::InvoicePaid, &inv).row;
        assert_eq!(r.amount_cents, Some(2720));
        assert_eq!(r.recurring_cents, Some(1920));
    }

    #[test]
    fn a_subscription_reads_its_seats_period_and_plan_from_either_version() {
        let classic = json!({
            "id": "sub_1", "customer": "cus_1", "status": "trialing", "currency": "usd",
            "current_period_start": 1_760_000_000, "current_period_end": 1_760_000_000 + MONTH,
            "cancel_at_period_end": false, "quantity": 2, "trial_end": 1_761_000_000,
            "items": { "data": [{ "quantity": 2, "price": { "id": BIZ } }] },
            "metadata": { "tenant_id": "65f000000000000000000002", "plan": "business" },
        });
        let basil = json!({
            "id": "sub_1", "customer": { "id": "cus_1" }, "status": "trialing", "currency": "usd",
            "cancel_at_period_end": false, "trial_end": 1_761_000_000,
            "items": { "data": [{
                "quantity": 2, "price": { "id": BIZ },
                "current_period_start": 1_760_000_000, "current_period_end": 1_760_000_000 + MONTH,
            }] },
            "metadata": { "tenant_id": "65f000000000000000000002" },
        });
        for sub in [classic, basil] {
            let p = parsed(BillingKind::SubscriptionCreated, &sub);
            assert_eq!(p.customer.as_deref(), Some("cus_1"));
            assert_eq!(p.subscription.as_deref(), Some("sub_1"));
            let r = p.row;
            assert_eq!(r.seats, Some(2));
            assert_eq!(r.plan.as_deref(), Some("business"));
            assert_eq!(r.status.as_deref(), Some("trialing"));
            assert_eq!(r.amount_cents, None, "a subscription event bills nothing");
            assert_eq!(
                r.period_start,
                Some(DateTime::from_millis(1_760_000_000_000))
            );
            let t = parsed(BillingKind::TrialWillEnd, &sub).row;
            assert_eq!(t.period_end, Some(DateTime::from_millis(1_761_000_000_000)));
        }
    }

    #[test]
    fn only_the_six_kinds_are_recorded() {
        for (t, k) in [
            (
                "customer.subscription.created",
                BillingKind::SubscriptionCreated,
            ),
            (
                "customer.subscription.updated",
                BillingKind::SubscriptionUpdated,
            ),
            (
                "customer.subscription.deleted",
                BillingKind::SubscriptionDeleted,
            ),
            ("invoice.paid", BillingKind::InvoicePaid),
            ("invoice.payment_failed", BillingKind::InvoicePaymentFailed),
            (
                "customer.subscription.trial_will_end",
                BillingKind::TrialWillEnd,
            ),
        ] {
            assert_eq!(kind_of(t), Some(k), "{t}");
        }
        for t in [
            "checkout.session.completed",
            "invoice.created",
            "charge.succeeded",
            "",
        ] {
            assert_eq!(kind_of(t), None, "{t}");
        }
    }

    fn row(kind: BillingKind, tenant: ObjectId, ts: i64) -> BillingEvent {
        let mut r = parsed(BillingKind::InvoicePaid, &classic_invoice()).with_tenant(tenant);
        r.kind = kind;
        r.ts = DateTime::from_millis(ts);
        r
    }

    fn paid(tenant: ObjectId, start_ms: i64, recurring: i64, amount: i64) -> BillingEvent {
        let mut r = row(BillingKind::InvoicePaid, tenant, start_ms + 60_000);
        r.period_start = Some(DateTime::from_millis(start_ms));
        r.period_end = Some(DateTime::from_millis(start_ms + MONTH * 1000));
        r.recurring_cents = Some(recurring);
        r.amount_cents = Some(amount);
        r.interval_months = Some(1.0);
        r
    }

    fn month(label: &str) -> (String, i64, i64) {
        let start = chrono::NaiveDate::parse_from_str(&format!("{label}-01"), "%Y-%m-%d").unwrap();
        let end = if start.format("%m").to_string() == "12" {
            start
                .with_year(start.year() + 1)
                .unwrap()
                .with_month(1)
                .unwrap()
        } else {
            start.with_month(start.month() + 1).unwrap()
        };
        let ms =
            |d: chrono::NaiveDate| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis();
        (label.to_string(), ms(start), ms(end))
    }
    use chrono::Datelike;

    /// Subscribe → paid → seats up → seats down → cancel: new, expansion,
    /// contraction and churn land in the months they happened, at the billed
    /// (not list) amounts.
    #[test]
    fn a_lifecycle_moves_mrr_month_by_month() {
        let t = ObjectId::new();
        let (_, aug, _) = month("2026-08");
        let (_, sep, _) = month("2026-09");
        let (_, oct, _) = month("2026-10");
        let (_, nov, _) = month("2026-11");
        let rows = vec![
            paid(t, aug + 5 * DAY_MS, 1920, 1920), // 3 seats, coupon
            paid(t, sep + 5 * DAY_MS, 3200, 3200), // 4 seats, coupon gone
            paid(t, oct + 5 * DAY_MS, 1600, 1600), // 2 seats
            row(BillingKind::SubscriptionDeleted, t, nov + 2 * DAY_MS),
        ];
        let orgs = fold(&rows);
        let o = &orgs[&t];
        assert_eq!(o.paid_since, Some(aug + 5 * DAY_MS + 60_000));
        assert_eq!(o.mrr_at(aug + 6 * DAY_MS), 1920);
        assert_eq!(o.mrr_at(nov + 3 * DAY_MS), 0, "deleted mid-period: no MRR");
        let months: Vec<_> = ["2026-08", "2026-09", "2026-10", "2026-11"]
            .iter()
            .map(|m| month(m))
            .collect();
        let m = &movements(&orgs, &rows, &months)["usd"];
        assert_eq!(m.len(), 4);
        assert_eq!((m[0].invoices_paid, m[0].billed_cents), (1, 1920));
        assert_eq!(m[3].invoices_paid, 0, "a cancellation is no invoice");
        assert_eq!(
            (m[0].new_cents, m[0].mrr_cents, m[0].paying_orgs),
            (1920, 1920, 1)
        );
        assert_eq!((m[1].expansion_cents, m[1].mrr_cents), (1280, 3200));
        assert_eq!((m[2].contraction_cents, m[2].mrr_cents), (1600, 1600));
        assert_eq!(
            (m[3].churned_cents, m[3].churned_orgs, m[3].mrr_cents),
            (1600, 1, 0)
        );
        assert_eq!(m[1].net_new_cents, 1280);
        assert_eq!(m[3].net_new_cents, -1600);
    }

    /// A yearly invoice is a twelfth of itself a month; a $0 invoice (a
    /// trial) is not paying.
    #[test]
    fn a_yearly_invoice_is_normalised_and_a_zero_invoice_is_not_paying() {
        let t = ObjectId::new();
        let (_, start, _) = month("2026-01");
        let mut yearly = paid(t, start, 19_200, 19_200);
        yearly.interval_months = Some(12.0);
        yearly.period_end = Some(DateTime::from_millis(start + 365 * DAY_MS));
        let orgs = fold(&[yearly]);
        assert_eq!(orgs[&t].mrr_at(start + 100 * DAY_MS), 1600);

        let u = ObjectId::new();
        let trial = paid(u, start, 0, 0);
        let orgs = fold(&[trial]);
        assert_eq!(orgs[&u].mrr_at(start + DAY_MS), 0);
        assert_eq!(orgs[&u].paid_since, None);
    }

    #[test]
    fn a_trial_converts_only_when_an_invoice_above_zero_follows_it() {
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let (_, oct, nov) = month("2026-10");
        let mut trial_a = row(BillingKind::SubscriptionCreated, a, oct + DAY_MS);
        trial_a.status = Some("trialing".into());
        let mut trial_b = row(BillingKind::TrialWillEnd, b, oct + 2 * DAY_MS);
        trial_b.status = Some("trialing".into());
        let rows = vec![trial_a, paid(a, oct + 15 * DAY_MS, 800, 800), trial_b];
        assert_eq!(trial_to_paid(&fold(&rows), oct, nov), (2, 1));
    }

    #[test]
    fn the_period_alone_gives_the_months_when_the_interval_is_unnamed() {
        let t = ObjectId::new();
        let mut r = paid(t, 0, 100, 100);
        r.interval_months = None;
        assert_eq!(months_of(&r), Some(1.0));
        r.period_end = Some(DateTime::from_millis(365 * DAY_MS));
        assert_eq!(months_of(&r), Some(12.0));
        r.period_end = Some(DateTime::from_millis(7 * DAY_MS));
        assert!((months_of(&r).unwrap() - 7.0 / MONTH_DAYS).abs() < 1e-9);
        r.period_end = Some(DateTime::from_millis(0));
        assert_eq!(months_of(&r), None);
    }
}
