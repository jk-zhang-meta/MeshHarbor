// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use meshharbor_config::StripeSettings;
use meshharbor_db::models::tenant::{
    BillingCurrency, BillingInfo, BillingInterval, Plan, PlanLimits, SubscriptionStatus, Tenant,
};
use mongodb::bson::{DateTime, doc, oid::ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::billing::PriceIds;

// ---- Response / DTO types ------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CheckoutResponse {
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct PlanInfo {
    pub id: String,
    pub name: String,
    /// One seat for one month, in US cents — kept for clients that read
    /// only this. [`Self::prices`] has every interval and currency.
    pub price_cents: u32,
    /// FR-115 — one seat's price for each interval and currency on sale
    /// here. Annual appears only when its Prices are configured.
    pub prices: Vec<PlanPrice>,
    /// FR-115 — the price is per seat (every member of the org).
    pub per_seat: bool,
    /// FR-115 D3 — commercial use is allowed on this plan (every plan,
    /// Free included); published so every surface can say it.
    pub commercial_use: bool,
    pub features: Vec<String>,
    pub limits: PlanLimits,
}

/// FR-115 — one seat's price, in the currency's minor unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanPrice {
    pub interval: BillingInterval,
    pub currency: BillingCurrency,
    pub unit_amount: u32,
}

/// FR-115 — what a checkout is for: plan, interval, currency and seats.
#[derive(Debug, Clone)]
pub struct CheckoutParams<'a> {
    pub plan: &'a str,
    pub interval: BillingInterval,
    pub currency: BillingCurrency,
    /// The members who accepted, at least one ([`StripeService::count_seats`]).
    pub seats: u32,
    pub email: &'a str,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
}

/// FR-115 — an org's billing as the billing page shows it.
#[derive(Debug, Clone, Serialize)]
pub struct BillingSummary {
    pub plan: String,
    /// Seats Stripe bills for (the subscription quantity), when known.
    pub seats_billed: Option<u32>,
    /// Seats the org has now (members who accepted, at least one).
    pub seats_now: u32,
    pub interval: Option<BillingInterval>,
    pub currency: Option<BillingCurrency>,
    pub status: Option<SubscriptionStatus>,
    pub current_period_end: Option<String>,
    pub cancel_at_period_end: bool,
    /// A subscription is live (active, trialing or past due): plan changes go
    /// through `change-plan`, never a second checkout.
    pub subscribed: bool,
}

/// FR-115 — one org's seat sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeatSync {
    pub tenant_id: String,
    /// The quantity Stripe had.
    pub from: u32,
    /// The seats the org has now.
    pub to: u32,
    /// Stripe's quantity was moved (with a proration).
    pub changed: bool,
}

/// FR-115 — one reconcile pass over every subscribed org.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SeatReconcile {
    pub orgs: u32,
    pub changed: u32,
    pub failed: u32,
}

// ---- Stripe webhook event (minimal deserialization) ----------------------

#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    /// Stripe event id (`evt_…`) — the S5 dedup key. `default` so a
    /// hand-rolled test payload without an id still parses (dedup is
    /// skipped for empty ids).
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
    /// When Stripe created the event (Unix seconds) — FR-102 P4's fallback
    /// time for a billing row whose object names none.
    #[serde(default)]
    pub created: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

// ---- Error type ----------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    #[error("Tenant not found")]
    TenantNotFound,
    #[error("No billing account for tenant")]
    NoBillingAccount,
    #[error("Invalid plan: {0}")]
    InvalidPlan(String),
    #[error("Stripe price id for plan '{0}' is not configured")]
    PriceNotConfigured(String),
    /// FR-115 — a second checkout would start a second subscription and
    /// bill the org twice; a plan change goes through `change_plan`.
    #[error("This organization already has a subscription — change the plan instead")]
    AlreadySubscribed,
    /// FR-115 — a plan change or seat sync needs a live subscription.
    #[error("This organization has no active subscription")]
    NotSubscribed,
    #[error("Invalid billing interval: {0} (month or year)")]
    InvalidInterval(String),
    #[error("Invalid currency: {0} (usd or eur)")]
    InvalidCurrency(String),
    /// FR-115 — the configured Price has no amount in this currency (an EUR
    /// `currency_options` entry was never added to it). Said plainly rather
    /// than handed to Stripe, whose error names a currency, not a fix.
    #[error("This plan is not sold in {0} yet. Choose another currency.")]
    CurrencyNotOffered(String),
    #[error("Stripe API error: {0}")]
    ApiError(String),
    #[error("Invalid webhook signature")]
    InvalidSignature,
    #[error("MongoDB error: {0}")]
    Mongo(#[from] mongodb::error::Error),
    /// FR-102 P4 — a write of this server's own failed (`billing_events`,
    /// the backfill's marker): a 500, never Stripe's fault.
    #[error("storage error: {0}")]
    Storage(String),
}

// ---- FR-102 P4: the operator's backfill ------------------------------------

/// Stripe's API base — the backfill reads its invoice list; a test passes a
/// fake server's.
pub const STRIPE_API_BASE: &str = "https://api.stripe.com";
/// The most pages (of 100 invoices) one backfill reads: a bound, not a page.
pub const BACKFILL_MAX_PAGES: u32 = 100;

/// What a backfill did — counts and months, never a customer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BackfillReport {
    pub pages: u32,
    /// Paid invoices read.
    pub invoices: u32,
    /// Recorded now.
    pub recorded: u32,
    /// Already on record (the webhook, or an earlier backfill).
    pub already: u32,
    /// Naming no org on this server — not recorded.
    pub no_org: u32,
    /// More invoices than [`BACKFILL_MAX_PAGES`] pages hold.
    pub truncated: bool,
    /// The months (`YYYY-MM`) whose billed figures the recorded invoices
    /// touch — the months a refreeze must rewrite.
    pub months: Vec<String>,
}

// ---- Service -------------------------------------------------------------

pub struct StripeService {
    settings: StripeSettings,
    client: reqwest::Client,
}

impl StripeService {
    pub fn new(settings: &StripeSettings) -> Self {
        Self {
            settings: settings.clone(),
            client: reqwest::Client::new(),
        }
    }

    // ---- HTTP ------------------------------------------------------------

    /// FR-115 — a Stripe API URL on the configured base (`api_base`, else
    /// Stripe's own), so the integration tests can point every call at a
    /// fake.
    fn api_url(&self, path: &str) -> String {
        let base = self.settings.api_base.trim().trim_end_matches('/');
        let base = if base.is_empty() {
            STRIPE_API_BASE
        } else {
            base
        };
        format!("{base}{path}")
    }

    /// Send one authenticated Stripe request and read its JSON, turning
    /// Stripe's `error` object into [`StripeError::ApiError`]. Bounded: a
    /// stalled Stripe must not hold a request handler or the seat sync.
    async fn send_json(&self, req: reqwest::RequestBuilder) -> Result<Value, StripeError> {
        let resp: Value = req
            .basic_auth(&self.settings.secret_key, None::<&str>)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await
            .map_err(|e| StripeError::ApiError(e.without_url().to_string()))?
            .json()
            .await
            .map_err(|e| StripeError::ApiError(e.without_url().to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(StripeError::ApiError(
                err["message"]
                    .as_str()
                    .unwrap_or("Unknown Stripe error")
                    .to_string(),
            ));
        }
        Ok(resp)
    }

    async fn post_form(&self, path: &str, params: &[(&str, String)]) -> Result<Value, StripeError> {
        self.send_json(self.client.post(self.api_url(path)).form(params))
            .await
    }

    async fn get_json(&self, path: &str) -> Result<Value, StripeError> {
        self.send_json(self.client.get(self.api_url(path))).await
    }

    /// The Stripe price id for a plan id and interval, or the reason there
    /// is none.
    fn price_id(&self, plan: &str, interval: BillingInterval) -> Result<String, StripeError> {
        if !matches!(plan, "pro" | "business") {
            return Err(StripeError::InvalidPlan(plan.to_string()));
        }
        match PriceIds::of(&self.settings).price_for(plan, interval) {
            Some(id) => Ok(id.to_string()),
            None => {
                warn!(
                    plan,
                    interval = interval.as_str(),
                    "Stripe price id is not configured"
                );
                Err(StripeError::PriceNotConfigured(match interval {
                    BillingInterval::Month => plan.to_string(),
                    BillingInterval::Year => format!("{plan} (annual)"),
                }))
            }
        }
    }

    // ---- Checkout --------------------------------------------------------

    /// FR-115 — one checkout for a plan, an interval and a currency, at
    /// `quantity = seats`. Refused when the org already has a live
    /// subscription: a second one would bill it twice (the "Switch to
    /// Business" button did exactly that before FR-115) — a plan change goes
    /// through [`Self::change_plan`].
    pub async fn create_checkout_session(
        &self,
        db: &mongodb::Database,
        tenant_id: &ObjectId,
        p: &CheckoutParams<'_>,
    ) -> Result<CheckoutResponse, StripeError> {
        // Validate the plan and the price up front, BEFORE touching Stripe —
        // otherwise an invalid plan's return path runs after a Stripe API
        // call that can fail with its own error and mask the real problem
        // (e2e: empty STRIPE_SECRET_KEY → customer-create 401 → 500 instead
        // of 400 on `plan: "nonexistent"`). An empty price id was the live
        // "payment not working" failure (2026-07-27): refused here with an
        // actionable error rather than forwarded as `price=""`.
        let price_id = self.price_id(p.plan, p.interval)?;
        // A currency the operator has not put on sale is refused before
        // anything else, with the same words as one the Price lacks.
        if !currencies_on_sale(&self.settings).contains(&p.currency) {
            return Err(StripeError::CurrencyNotOffered(
                p.currency.as_str().to_ascii_uppercase(),
            ));
        }

        let collection = db.collection::<Tenant>(Tenant::COLLECTION);
        let tenant = collection
            .find_one(doc! { "_id": tenant_id })
            .await?
            .ok_or(StripeError::TenantNotFound)?;
        if has_live_subscription(&tenant) {
            return Err(StripeError::AlreadySubscribed);
        }

        // FR-115 — the Price must carry the currency asked for. The live
        // Prices of 2026-07-27 were USD only, so an EUR checkout would
        // otherwise surface as Stripe's own error until their EUR
        // `currency_options` are added. One read per checkout.
        let sold_in = self.price_currencies(&price_id).await?;
        if !sold_in.iter().any(|c| c == p.currency.as_str()) {
            warn!(
                price = %price_id, currency = p.currency.as_str(), ?sold_in,
                "checkout refused: the Price is not sold in this currency"
            );
            return Err(StripeError::CurrencyNotOffered(
                p.currency.as_str().to_ascii_uppercase(),
            ));
        }

        // Reuse or create Stripe customer
        let customer_id = match tenant.billing.as_ref().and_then(|b| b.customer_id.clone()) {
            Some(cid) => cid,
            None => self.create_customer(p.email, &tenant_id.to_hex()).await?,
        };

        // Persist customer_id if it was just created. Tenants that never
        // checked out carry an explicit `billing: null`, and a dotted
        // `billing.customer_id` $set fails on those with Mongo error 28
        // ("Cannot create field 'customer_id' in element {billing: null}")
        // — live repro 2026-07-27 on the first real prod checkout. Set the
        // whole subdocument in that case (mirrors the webhook path).
        if tenant
            .billing
            .as_ref()
            .and_then(|b| b.customer_id.as_ref())
            .is_none()
        {
            let update = if tenant.billing.is_some() {
                doc! { "$set": { "billing.customer_id": &customer_id } }
            } else {
                doc! { "$set": { "billing": bson::to_bson(&BillingInfo {
                    customer_id: Some(customer_id.clone()),
                    subscription_id: None,
                    current_period_end: None,
                    status: SubscriptionStatus::Active,
                    cancel_at_period_end: false,
                    seats: None,
                    interval: None,
                    currency: None,
                }).unwrap_or_default() } }
            };
            collection
                .update_one(doc! { "_id": tenant_id }, update)
                .await?;
        }

        let tenant_hex = tenant_id.to_hex();
        let seats = p.seats.max(1).to_string();
        let params: Vec<(&str, String)> = vec![
            ("customer", customer_id.clone()),
            ("mode", "subscription".into()),
            ("line_items[0][price]", price_id),
            // FR-115 — one unit per seat (it was always 1: a 20-person team
            // was quoted $160 and billed $8). The seat sync keeps it true.
            ("line_items[0][quantity]", seats.clone()),
            // FR-115 — the Price carries both currencies; this picks one.
            ("currency", p.currency.as_str().into()),
            ("success_url", p.success_url.into()),
            ("cancel_url", p.cancel_url.into()),
            ("metadata[tenant_id]", tenant_hex.clone()),
            ("metadata[plan]", p.plan.into()),
            ("metadata[interval]", p.interval.as_str().into()),
            ("metadata[currency]", p.currency.as_str().into()),
            ("metadata[seats]", seats.clone()),
            // FR-102 P4 — the SUBSCRIPTION carries the org too, so every
            // later subscription and invoice event names it directly (the
            // session's metadata stays on the session).
            ("subscription_data[metadata][tenant_id]", tenant_hex),
            ("subscription_data[metadata][plan]", p.plan.into()),
            (
                "subscription_data[metadata][interval]",
                p.interval.as_str().into(),
            ),
        ];

        let resp = self.post_form("/v1/checkout/sessions", &params).await?;
        let url = resp["url"]
            .as_str()
            .ok_or_else(|| StripeError::ApiError("No checkout URL in response".to_string()))?
            .to_string();

        info!(
            tenant_id = %tenant_id, plan = p.plan, interval = p.interval.as_str(),
            currency = p.currency.as_str(), seats = p.seats,
            "checkout session created"
        );
        Ok(CheckoutResponse { url })
    }

    /// FR-115 — the currencies a Price is sold in: its own currency plus
    /// every `currency_options` key, lower-case.
    pub async fn price_currencies(&self, price_id: &str) -> Result<Vec<String>, StripeError> {
        let price = self
            .get_json(&format!(
                "/v1/prices/{price_id}?expand%5B%5D=currency_options"
            ))
            .await?;
        let mut out: Vec<String> = Vec::new();
        if let Some(c) = price["currency"].as_str() {
            out.push(c.to_ascii_lowercase());
        }
        if let Some(opts) = price["currency_options"].as_object() {
            for k in opts.keys() {
                let k = k.to_ascii_lowercase();
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        Ok(out)
    }

    // ---- Plan change (FR-115) ---------------------------------------------

    /// Move an org's live subscription to another plan and/or interval: the
    /// subscription's one item gets the new price, at the same quantity, with
    /// a proration. The currency cannot change (Stripe fixes it at creation).
    /// The webhook confirms it; the org is updated here too so the page does
    /// not wait for it.
    pub async fn change_plan(
        &self,
        db: &mongodb::Database,
        tenant_id: &ObjectId,
        plan: &str,
        interval: BillingInterval,
    ) -> Result<BillingSummary, StripeError> {
        let price_id = self.price_id(plan, interval)?;
        let collection = db.collection::<Tenant>(Tenant::COLLECTION);
        let tenant = collection
            .find_one(doc! { "_id": tenant_id })
            .await?
            .ok_or(StripeError::TenantNotFound)?;
        if !has_live_subscription(&tenant) {
            return Err(StripeError::NotSubscribed);
        }
        let sub_id = tenant
            .billing
            .as_ref()
            .and_then(|b| b.subscription_id.clone())
            .ok_or(StripeError::NotSubscribed)?;
        let sub = self
            .get_json(&format!("/v1/subscriptions/{sub_id}"))
            .await?;
        let (item_id, quantity) = first_item(&sub)
            .ok_or_else(|| StripeError::ApiError("subscription has no item".into()))?;

        let current = crate::billing::subscription_price(&sub);
        let updated = if current.as_deref() == Some(price_id.as_str()) {
            sub
        } else {
            let params: Vec<(&str, String)> = vec![
                ("items[0][id]", item_id),
                ("items[0][price]", price_id),
                ("items[0][quantity]", quantity.max(1).to_string()),
                ("proration_behavior", "create_prorations".into()),
                ("metadata[plan]", plan.into()),
                ("metadata[interval]", interval.as_str().into()),
            ];
            self.post_form(&format!("/v1/subscriptions/{sub_id}"), &params)
                .await?
        };
        self.apply_subscription(db, &updated).await?;
        info!(tenant_id = %tenant_id, plan, interval = interval.as_str(), "plan changed");
        self.summary(db, tenant_id).await
    }

    // ---- Seats (FR-115) ----------------------------------------------------

    /// The seats an org has: its members who accepted (a pending invite is
    /// not a seat — FR-115 O2), at least one.
    pub async fn count_seats(
        db: &mongodb::Database,
        tenant_id: &ObjectId,
    ) -> Result<u32, StripeError> {
        let n = db
            .collection::<bson::Document>("tenant_members")
            .count_documents(doc! { "tenant_id": tenant_id, "is_pending": { "$ne": true } })
            .await?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX).max(1))
    }

    /// Make Stripe bill an org for the seats it has now: the subscription
    /// item's quantity moves to the seat count, with a proration. A no-op
    /// when they already agree; refused without a live subscription.
    pub async fn sync_seats(
        &self,
        db: &mongodb::Database,
        tenant: &Tenant,
    ) -> Result<SeatSync, StripeError> {
        let tenant_id = tenant.id.ok_or(StripeError::TenantNotFound)?;
        if !has_live_subscription(tenant) {
            return Err(StripeError::NotSubscribed);
        }
        let sub_id = tenant
            .billing
            .as_ref()
            .and_then(|b| b.subscription_id.clone())
            .ok_or(StripeError::NotSubscribed)?;
        let seats = Self::count_seats(db, &tenant_id).await?;
        let sub = self
            .get_json(&format!("/v1/subscriptions/{sub_id}"))
            .await?;
        let (item_id, quantity) = first_item(&sub)
            .ok_or_else(|| StripeError::ApiError("subscription has no item".into()))?;
        let changed = quantity != seats;
        if changed {
            let params: Vec<(&str, String)> = vec![
                ("quantity", seats.to_string()),
                ("proration_behavior", "create_prorations".into()),
            ];
            self.post_form(&format!("/v1/subscription_items/{item_id}"), &params)
                .await?;
            info!(tenant_id = %tenant_id, from = quantity, to = seats, "seats synced to Stripe");
        }
        db.collection::<Tenant>(Tenant::COLLECTION)
            .update_one(
                doc! { "_id": tenant_id, "billing": { "$type": "object" } },
                doc! { "$set": { "billing.seats": i64::from(seats) } },
            )
            .await?;
        Ok(SeatSync {
            tenant_id: tenant_id.to_hex(),
            from: quantity,
            to: seats,
            changed,
        })
    }

    /// One pass of the seat reconcile: every org with a live subscription.
    /// An org that fails is logged and counted, never stops the pass.
    pub async fn reconcile_seats(
        &self,
        db: &mongodb::Database,
    ) -> Result<SeatReconcile, StripeError> {
        let mut report = SeatReconcile::default();
        let mut cursor = db
            .collection::<Tenant>(Tenant::COLLECTION)
            .find(doc! {
                "deleted_at": bson::Bson::Null,
                "billing.subscription_id": { "$type": "string" },
                "billing.status": { "$in": ["active", "trialing", "past_due"] },
            })
            .await?;
        while cursor.advance().await? {
            let tenant: Tenant = match cursor.deserialize_current() {
                Ok(t) => t,
                Err(e) => {
                    warn!(%e, "seat reconcile: unreadable tenant row skipped");
                    report.failed += 1;
                    continue;
                }
            };
            report.orgs += 1;
            match self.sync_seats(db, &tenant).await {
                Ok(s) if s.changed => report.changed += 1,
                Ok(_) => {}
                Err(e) => {
                    report.failed += 1;
                    warn!(tenant_id = ?tenant.id, %e, "seat sync failed");
                }
            }
        }
        Ok(report)
    }

    /// The billing page's view of an org.
    pub async fn summary(
        &self,
        db: &mongodb::Database,
        tenant_id: &ObjectId,
    ) -> Result<BillingSummary, StripeError> {
        let tenant = db
            .collection::<Tenant>(Tenant::COLLECTION)
            .find_one(doc! { "_id": tenant_id })
            .await?
            .ok_or(StripeError::TenantNotFound)?;
        let seats_now = Self::count_seats(db, tenant_id).await?;
        let b = tenant.billing.as_ref();
        Ok(BillingSummary {
            plan: tenant.plan.id().to_string(),
            seats_billed: b.and_then(|b| b.seats),
            seats_now,
            interval: b.and_then(BillingInfo::interval),
            currency: b.and_then(BillingInfo::currency),
            status: b.map(|b| b.status.clone()),
            current_period_end: b
                .and_then(|b| b.current_period_end)
                .and_then(|d| d.try_to_rfc3339_string().ok()),
            cancel_at_period_end: b.is_some_and(|b| b.cancel_at_period_end),
            subscribed: has_live_subscription(&tenant),
        })
    }

    // ---- Customer --------------------------------------------------------

    async fn create_customer(&self, email: &str, tenant_id: &str) -> Result<String, StripeError> {
        let params: Vec<(&str, String)> = vec![
            ("email", email.into()),
            ("metadata[tenant_id]", tenant_id.into()),
        ];
        let resp = self.post_form("/v1/customers", &params).await?;
        let id = resp["id"]
            .as_str()
            .ok_or_else(|| StripeError::ApiError("No customer ID in response".to_string()))?
            .to_string();

        info!(customer_id = %id, "Created Stripe customer");
        Ok(id)
    }

    // ---- Billing portal --------------------------------------------------

    pub async fn create_portal_session(
        &self,
        db: &mongodb::Database,
        tenant_id: &ObjectId,
        return_url: &str,
    ) -> Result<PortalResponse, StripeError> {
        let collection = db.collection::<Tenant>(Tenant::COLLECTION);
        let tenant = collection
            .find_one(doc! { "_id": tenant_id })
            .await?
            .ok_or(StripeError::TenantNotFound)?;

        let customer_id = tenant
            .billing
            .as_ref()
            .and_then(|b| b.customer_id.as_ref())
            .ok_or(StripeError::NoBillingAccount)?;

        let params: Vec<(&str, String)> = vec![
            ("customer", customer_id.clone()),
            ("return_url", return_url.into()),
        ];
        let resp = self
            .post_form("/v1/billing_portal/sessions", &params)
            .await?;
        let url = resp["url"]
            .as_str()
            .ok_or_else(|| StripeError::ApiError("No portal URL in response".to_string()))?
            .to_string();

        Ok(PortalResponse { url })
    }

    // ---- Plans (static) --------------------------------------------------

    /// FR-115 — per seat, monthly or annual (two months free), USD or EUR;
    /// Free says commercial use is allowed, and the copy leads with what a
    /// plan gives rather than what it withholds. The ids stay
    /// `free`/`pro`/`business` (stored in tenant docs + matched in the
    /// webhook; renaming needs a migration — display copy is the thing to
    /// change). Annual prices appear only once their Prices are configured,
    /// and a currency only once `stripe.currencies` names it
    /// ([`currencies_on_sale`]).
    pub fn get_plans(settings: &StripeSettings) -> Vec<PlanInfo> {
        let ids = PriceIds::of(settings);
        let on_sale = currencies_on_sale(settings);
        // A `year` entry is how every page learns that annual is on sale, so
        // Free, which costs nothing either way, lists one only where a paid
        // plan is sold annually. Listing it unconditionally put an Annual
        // toggle on the billing page and "or $0 per user per year" on the
        // Free card while nothing was sold annually (prod, 2026-10-20).
        let annual_on_sale = [Plan::Pro, Plan::Business]
            .iter()
            .any(|p| ids.price_for(p.id(), BillingInterval::Year).is_some());
        let prices = |plan: Plan| -> Vec<PlanPrice> {
            let mut out = Vec::new();
            for interval in BillingInterval::ALL {
                let sold = if plan == Plan::Free {
                    interval != BillingInterval::Year || annual_on_sale
                } else {
                    ids.price_for(plan.id(), interval).is_some()
                };
                if !sold && interval == BillingInterval::Year {
                    continue;
                }
                for &currency in &on_sale {
                    out.push(PlanPrice {
                        interval,
                        currency,
                        unit_amount: plan.price_cents(interval, currency),
                    });
                }
            }
            out
        };
        let info = |plan: Plan, name: &str, features: &[&str]| PlanInfo {
            id: plan.id().into(),
            name: name.into(),
            price_cents: plan.price_monthly_cents(),
            prices: prices(plan.clone()),
            per_seat: plan.limits().per_seat,
            commercial_use: true,
            features: features.iter().map(|f| f.to_string()).collect(),
            limits: plan.limits(),
        };
        vec![
            info(
                Plan::Free,
                "Free",
                &[
                    "Free for commercial use",
                    "10 users",
                    "100 devices with remote desktop",
                    "Private network with MagicDNS",
                    "1 remote session at a time",
                    "Meetings up to 60 minutes, 10 people",
                    "Unlimited chat, 1 GB storage",
                ],
            ),
            info(
                Plan::Pro,
                "Pro",
                &[
                    "Everything in Free, priced per user",
                    "1,000 devices",
                    "1 remote session at a time per user",
                    "Exit nodes",
                    "Meetings with 50 people, no time limit",
                    "25 GB of relay traffic per user each month",
                    "10 GB storage per user",
                ],
            ),
            info(
                Plan::Business,
                "Business",
                &[
                    "Everything in Pro",
                    "5,000 devices",
                    "Unlimited remote sessions",
                    "Meetings with 100 people, and recordings",
                    "100 GB of relay traffic per user each month",
                    "50 GB storage per user",
                    "Priority support",
                ],
            ),
        ]
    }

    // ---- FR-102 P4: the operator's one-off backfill -----------------------

    /// Read Stripe's paid invoices (created since `since_unix`, newest
    /// first, 100 a page, at most [`BACKFILL_MAX_PAGES`] pages) into
    /// `billing_events` as `invoice_paid` rows with `source: backfill`. An
    /// invoice the webhook already recorded is left as it was — the two meet
    /// on `(kind, stripe_id)` — so running it twice records nothing new. An
    /// invoice whose customer is no org on this server is counted, not
    /// recorded. Reads only; it never writes to Stripe.
    pub async fn backfill_paid_invoices(
        &self,
        db: &mongodb::Database,
        api_base: &str,
        since_unix: Option<i64>,
        now: DateTime,
    ) -> Result<BackfillReport, StripeError> {
        use crate::dao::billing_event::{BillingEventDao, BillingKind, BillingSource, Recorded};
        if self.settings.secret_key.trim().is_empty() {
            return Err(StripeError::ApiError(
                "no Stripe secret key configured (MESHHARBOR__STRIPE__SECRET_KEY)".into(),
            ));
        }
        let dao = BillingEventDao::new(db);
        let mut report = BackfillReport::default();
        let mut months: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut starting_after: Option<String> = None;
        loop {
            if report.pages >= BACKFILL_MAX_PAGES {
                report.truncated = true;
                break;
            }
            let mut query: Vec<(&str, String)> =
                vec![("status", "paid".into()), ("limit", "100".into())];
            if let Some(since) = since_unix {
                query.push(("created[gte]", since.to_string()));
            }
            if let Some(after) = &starting_after {
                query.push(("starting_after", after.clone()));
            }
            let resp: serde_json::Value = self
                .client
                .get(format!("{}/v1/invoices", api_base.trim_end_matches('/')))
                .basic_auth(&self.settings.secret_key, None::<&str>)
                .query(&query)
                .timeout(std::time::Duration::from_secs(20))
                .send()
                .await
                .map_err(|e| StripeError::ApiError(e.without_url().to_string()))?
                .json()
                .await
                .map_err(|e| StripeError::ApiError(e.without_url().to_string()))?;
            if let Some(err) = resp.get("error") {
                return Err(StripeError::ApiError(
                    err["message"]
                        .as_str()
                        .unwrap_or("Unknown Stripe error")
                        .to_string(),
                ));
            }
            report.pages += 1;
            let invoices = resp["data"].as_array().cloned().unwrap_or_default();
            for inv in &invoices {
                report.invoices += 1;
                let Some(mut parsed) = crate::billing::parse(
                    BillingKind::InvoicePaid,
                    inv,
                    None,
                    inv["created"].as_i64(),
                    &PriceIds::of(&self.settings),
                    now,
                ) else {
                    continue;
                };
                parsed.row.source = BillingSource::Backfill;
                let Some(tenant) = self.tenant_for(db, &parsed).await? else {
                    report.no_org += 1;
                    continue;
                };
                let row = parsed.with_tenant(tenant);
                match dao
                    .record(&row)
                    .await
                    .map_err(|e| StripeError::Storage(format!("billing_events: {e}")))?
                {
                    Recorded::Created => {
                        report.recorded += 1;
                        months.insert(crate::billing::month_of(row.ts.timestamp_millis()));
                        if let (Some(s), Some(e)) = (row.period_start, row.period_end) {
                            let mut t = s.timestamp_millis();
                            while t < e.timestamp_millis() {
                                let label = crate::billing::month_of(t);
                                let Some((_, end)) = crate::billing::month_bounds(&label) else {
                                    break;
                                };
                                months.insert(label);
                                t = end;
                            }
                        }
                    }
                    Recorded::Duplicate => report.already += 1,
                }
            }
            if resp["has_more"].as_bool() == Some(true) {
                starting_after = invoices
                    .last()
                    .and_then(|i| i["id"].as_str())
                    .map(str::to_string);
                if starting_after.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        report.months = months.into_iter().collect();
        // The marker the views read (`billing::last_backfill`): billed
        // figures now include Stripe's history, not only what the webhook
        // delivered since it was wired.
        {
            use crate::dao::growth::{BILLING_BACKFILL_SOURCE, GrowthDao, PulledDay};
            let day: String = now
                .try_to_rfc3339_string()
                .unwrap_or_default()
                .chars()
                .take(10)
                .collect();
            GrowthDao::new(db)
                .record_pull_ok(
                    BILLING_BACKFILL_SOURCE,
                    &day,
                    PulledDay {
                        rows: report.recorded,
                        missing_goal: None,
                        truncated: report.truncated,
                    },
                    now,
                )
                .await
                .map_err(|e| StripeError::Storage(format!("growth_pulls: {e}")))?;
        }
        info!(
            pages = report.pages,
            invoices = report.invoices,
            recorded = report.recorded,
            already = report.already,
            no_org = report.no_org,
            "stripe billing backfill"
        );
        Ok(report)
    }

    // ---- Webhook processing ----------------------------------------------

    /// S5 hardening — replayed signatures older (or newer) than this are
    /// rejected even when the HMAC checks out. Stripe's own SDKs default
    /// to the same 5-minute window.
    const SIGNATURE_TOLERANCE_SECS: i64 = 300;

    /// Verify the Stripe webhook signature using HMAC-SHA256, including
    /// the replay-window check against the current clock.
    pub fn verify_signature(
        webhook_secret: &str,
        payload: &[u8],
        sig_header: &str,
    ) -> Result<(), StripeError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self::verify_signature_at(webhook_secret, payload, sig_header, now)
    }

    /// The clock-injected body of [`verify_signature`] so the replay
    /// window is unit-testable without sleeping.
    pub fn verify_signature_at(
        webhook_secret: &str,
        payload: &[u8],
        sig_header: &str,
        now_unix: i64,
    ) -> Result<(), StripeError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Parse the Stripe-Signature header: t=...,v1=...,v0=...
        let mut timestamp = None;
        let mut signatures: Vec<String> = Vec::new();

        for part in sig_header.split(',') {
            let part = part.trim();
            if let Some(t) = part.strip_prefix("t=") {
                timestamp = Some(t.to_string());
            } else if let Some(v1) = part.strip_prefix("v1=") {
                signatures.push(v1.to_string());
            }
        }

        let timestamp = timestamp.ok_or(StripeError::InvalidSignature)?;
        if signatures.is_empty() {
            return Err(StripeError::InvalidSignature);
        }

        // S5 — replay window: a valid-HMAC header from outside the
        // tolerance is a replay (or a badly skewed clock) — reject.
        let ts: i64 = timestamp
            .parse()
            .map_err(|_| StripeError::InvalidSignature)?;
        if (now_unix - ts).abs() > Self::SIGNATURE_TOLERANCE_SECS {
            warn!(ts, now_unix, "stripe webhook signature outside tolerance");
            return Err(StripeError::InvalidSignature);
        }

        // Build the signed payload: "{timestamp}.{body}"
        let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(payload));

        let mut mac = Hmac::<Sha256>::new_from_slice(webhook_secret.as_bytes())
            .map_err(|_| StripeError::InvalidSignature)?;
        mac.update(signed_payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        if signatures.iter().any(|s| s == &expected) {
            Ok(())
        } else {
            Err(StripeError::InvalidSignature)
        }
    }

    /// S5 — idempotency gate: record the Stripe event id in
    /// `stripe_events` (unique `_id`, 30-day TTL via `processed_at`). A
    /// duplicate insert means this exact event was already processed —
    /// Stripe retries deliveries, and a replayed `checkout.session.
    /// completed` must not re-run the billing writes. Empty id (hand-
    /// rolled test payloads) skips dedup. Fail-open on unexpected DB
    /// errors: dropping a live billing event is worse than double-
    /// processing one.
    async fn first_time_seeing(&self, db: &mongodb::Database, event_id: &str) -> bool {
        if event_id.is_empty() {
            return true;
        }
        let coll = db.collection::<bson::Document>("stripe_events");
        match coll
            .insert_one(doc! { "_id": event_id, "processed_at": DateTime::now() })
            .await
        {
            Ok(_) => true,
            Err(e) => {
                let dup = matches!(
                    *e.kind,
                    mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                        ref we
                    )) if we.code == 11000
                );
                if dup {
                    info!(event_id, "duplicate Stripe event skipped");
                    false
                } else {
                    warn!(event_id, error = %e, "stripe_events insert failed — processing anyway");
                    true
                }
            }
        }
    }

    /// FR-102 P4 — a processing failure must not leave the event marked as
    /// seen, or Stripe's retry would be skipped and the event lost: the
    /// marker is removed so the retry processes it again (every write it
    /// makes is idempotent). Best-effort — a failed removal is logged.
    async fn forget_event(&self, db: &mongodb::Database, event_id: &str) {
        if event_id.is_empty() {
            return;
        }
        if let Err(e) = db
            .collection::<bson::Document>("stripe_events")
            .delete_one(doc! { "_id": event_id })
            .await
        {
            warn!(event_id, error = %e, "could not un-mark a failed Stripe event");
        }
    }

    /// Handle a verified webhook event, updating tenant billing state and
    /// (FR-102 P4) recording the six billing kinds in `billing_events`.
    pub async fn handle_webhook_event(
        &self,
        db: &mongodb::Database,
        event: &StripeEvent,
    ) -> Result<(), StripeError> {
        if !self.first_time_seeing(db, &event.id).await {
            return Ok(());
        }
        match self.process(db, event).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.forget_event(db, &event.id).await;
                Err(e)
            }
        }
    }

    /// The org a billing object belongs to: the `tenant_id` the checkout
    /// stamped on the subscription's metadata (when that org exists), else
    /// the org whose `billing.customer_id` / `billing.subscription_id` it
    /// names. `None` for a customer this server never checked out.
    async fn tenant_for(
        &self,
        db: &mongodb::Database,
        parsed: &crate::billing::Parsed,
    ) -> Result<Option<ObjectId>, StripeError> {
        let tenants = db.collection::<bson::Document>(Tenant::COLLECTION);
        let id_of = |d: Option<bson::Document>| d.and_then(|d| d.get_object_id("_id").ok());
        if let Some(t) = parsed.metadata_tenant
            && let Some(id) = id_of(tenants.find_one(doc! { "_id": t }).await?)
        {
            return Ok(Some(id));
        }
        if let Some(c) = &parsed.customer
            && let Some(id) = id_of(tenants.find_one(doc! { "billing.customer_id": c }).await?)
        {
            return Ok(Some(id));
        }
        if let Some(s) = &parsed.subscription
            && let Some(id) = id_of(
                tenants
                    .find_one(doc! { "billing.subscription_id": s })
                    .await?,
            )
        {
            return Ok(Some(id));
        }
        Ok(None)
    }

    /// FR-102 P4 — record one of the six billing kinds. An object whose org
    /// cannot be found is logged (ids only) and skipped: a row with no org
    /// would count revenue nobody can be credited with.
    async fn record_billing(
        &self,
        db: &mongodb::Database,
        kind: crate::dao::billing_event::BillingKind,
        event: &StripeEvent,
    ) -> Result<(), StripeError> {
        use crate::dao::billing_event::BillingEventDao;
        let Some(parsed) = crate::billing::parse(
            kind,
            &event.data.object,
            Some(&event.id),
            event.created,
            &PriceIds::of(&self.settings),
            DateTime::now(),
        ) else {
            warn!(event_id = %event.id, kind = kind.as_str(), "billing event without an object id — not recorded");
            return Ok(());
        };
        let Some(tenant) = self.tenant_for(db, &parsed).await? else {
            warn!(
                event_id = %event.id, kind = kind.as_str(), stripe_id = %parsed.row.stripe_id,
                "billing event names no org on this server — not recorded"
            );
            return Ok(());
        };
        let row = parsed.with_tenant(tenant);
        let recorded = BillingEventDao::new(db)
            .record(&row)
            .await
            .map_err(|e| StripeError::Storage(format!("billing_events: {e}")))?;
        info!(
            tenant_id = %tenant, kind = kind.as_str(), stripe_id = %row.stripe_id,
            amount_cents = ?row.amount_cents, recorded = ?recorded,
            "billing event"
        );
        Ok(())
    }

    /// FR-115 — write what a subscription object says onto its org: status,
    /// period end, cancel flag, and the seats, interval, currency and plan
    /// its item's price names. The org is the one holding the subscription
    /// id, else the one the checkout stamped on the subscription's metadata
    /// (`subscription_data[metadata][tenant_id]`) — an update can land before
    /// `checkout.session.completed`. The plan moves only while the
    /// subscription bills (a deletion is its own event), and only to a plan a
    /// configured price names; that is what makes a plan changed in Stripe's
    /// portal reach the org, which the status-only handler never did.
    ///
    /// Read-merge-write of the whole `billing` subdocument: a dotted `$set`
    /// fails on `billing: null` (Mongo error 28, live 2026-07-27).
    async fn apply_subscription(
        &self,
        db: &mongodb::Database,
        sub: &Value,
    ) -> Result<Option<ObjectId>, StripeError> {
        let Some(sub_id) = sub["id"].as_str().filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let tenants = db.collection::<Tenant>(Tenant::COLLECTION);
        let mut tenant = tenants
            .find_one(doc! { "billing.subscription_id": sub_id })
            .await?;
        if tenant.is_none()
            && let Some(tid) = sub["metadata"]["tenant_id"]
                .as_str()
                .and_then(|h| ObjectId::parse_str(h).ok())
        {
            tenant = tenants.find_one(doc! { "_id": tid }).await?;
        }
        let Some(tenant) = tenant else {
            warn!(subscription_id = %sub_id, "subscription names no org on this server");
            return Ok(None);
        };
        let tid = tenant.id.ok_or(StripeError::TenantNotFound)?;

        let status = match sub["status"].as_str().unwrap_or_default() {
            "active" => SubscriptionStatus::Active,
            "past_due" | "unpaid" => SubscriptionStatus::PastDue,
            "canceled" | "incomplete_expired" => SubscriptionStatus::Canceled,
            "trialing" => SubscriptionStatus::Trialing,
            "incomplete" => SubscriptionStatus::Incomplete,
            _ => SubscriptionStatus::Active,
        };
        let bills = matches!(
            status,
            SubscriptionStatus::Active | SubscriptionStatus::Trialing | SubscriptionStatus::PastDue
        );
        let prices = PriceIds::of(&self.settings);
        let sold = crate::billing::subscription_price(sub)
            .as_deref()
            .and_then(|p| prices.lookup(p));
        let interval = sold.map(|(_, i)| i).or_else(|| {
            sub["items"]["data"][0]["price"]["recurring"]["interval"]
                .as_str()
                .and_then(BillingInterval::parse)
        });
        let currency = sub["currency"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .and_then(|c| BillingCurrency::parse(&c));
        let seats = crate::billing::subscription_seats(sub).and_then(|n| u32::try_from(n).ok());

        let mut b = tenant.billing.clone().unwrap_or(BillingInfo {
            customer_id: None,
            subscription_id: None,
            current_period_end: None,
            status: SubscriptionStatus::Active,
            cancel_at_period_end: false,
            seats: None,
            interval: None,
            currency: None,
        });
        b.subscription_id = Some(sub_id.to_string());
        if let Some(c) = sub["customer"].as_str().filter(|c| !c.is_empty()) {
            b.customer_id = Some(c.to_string());
        }
        b.status = status;
        b.cancel_at_period_end = sub["cancel_at_period_end"].as_bool().unwrap_or(false);
        // FR-102 P4 — the 2025-03-31 API moved the period onto the items;
        // `subscription_period` reads either.
        if let Some(end) = crate::billing::subscription_period(sub).1 {
            b.current_period_end = Some(DateTime::from_millis(end * 1000));
        }
        if seats.is_some() {
            b.seats = seats;
        }
        if let Some(i) = interval {
            b.interval = Some(i.as_str().to_string());
        }
        if let Some(c) = currency {
            b.currency = Some(c.as_str().to_string());
        }

        let mut set = doc! {
            "billing": bson::to_bson(&b).unwrap_or_default(),
            "updated_at": DateTime::now(),
        };
        if bills && let Some((plan, _)) = sold {
            set.insert("plan", plan);
        }
        tenants
            .update_one(doc! { "_id": tid }, doc! { "$set": set })
            .await?;
        Ok(Some(tid))
    }

    async fn process(
        &self,
        db: &mongodb::Database,
        event: &StripeEvent,
    ) -> Result<(), StripeError> {
        let obj = &event.data.object;

        // FR-102 P4 — the six billing kinds land in `billing_events` first;
        // the tenant-state updates below are unchanged.
        if let Some(kind) = crate::billing::kind_of(&event.event_type) {
            self.record_billing(db, kind, event).await?;
        }

        match event.event_type.as_str() {
            "checkout.session.completed" => {
                let tenant_hex = obj["metadata"]["tenant_id"].as_str().unwrap_or_default();
                let plan_str = obj["metadata"]["plan"].as_str().unwrap_or_default();
                let subscription_id = obj["subscription"].as_str().unwrap_or_default();
                let customer_id = obj["customer"].as_str().unwrap_or_default();

                if tenant_hex.is_empty() {
                    warn!("checkout.session.completed missing tenant_id metadata");
                    return Ok(());
                }

                let tenant_id = ObjectId::parse_str(tenant_hex)
                    .map_err(|_| StripeError::ApiError("Invalid tenant_id in metadata".into()))?;

                let plan = match plan_str {
                    "pro" => Plan::Pro,
                    "business" => Plan::Business,
                    _ => Plan::Free,
                };

                let collection = db.collection::<Tenant>(Tenant::COLLECTION);
                // S5 — Stripe does not guarantee event ordering: when
                // `customer.subscription.updated` (which carries
                // current_period_end) lands BEFORE this event, the old
                // whole-subdoc overwrite wiped period_end back to null.
                // Read-merge-write: keep any billing facts already
                // recorded, only fill what checkout knows. (Whole-subdoc
                // $set stays — dotted paths fail on `billing: null`
                // tenants with Mongo error 28; live repro 2026-07-27.)
                let existing_billing = collection
                    .find_one(doc! { "_id": tenant_id })
                    .await?
                    .and_then(|t| t.billing);
                // FR-115 — the seats, interval and currency the checkout
                // asked for, unless a subscription event already recorded
                // Stripe's own (it is the authority; this is the fallback).
                let meta = &obj["metadata"];
                let merged = BillingInfo {
                    customer_id: Some(customer_id.to_string()),
                    subscription_id: Some(subscription_id.to_string()),
                    current_period_end: existing_billing
                        .as_ref()
                        .and_then(|b| b.current_period_end),
                    status: SubscriptionStatus::Active,
                    cancel_at_period_end: existing_billing
                        .as_ref()
                        .map(|b| b.cancel_at_period_end)
                        .unwrap_or(false),
                    seats: existing_billing
                        .as_ref()
                        .and_then(|b| b.seats)
                        .or_else(|| meta["seats"].as_str().and_then(|s| s.parse::<u32>().ok())),
                    interval: existing_billing
                        .as_ref()
                        .and_then(|b| b.interval.clone())
                        .or_else(|| {
                            meta["interval"]
                                .as_str()
                                .and_then(BillingInterval::parse)
                                .map(|i| i.as_str().to_string())
                        }),
                    currency: existing_billing
                        .as_ref()
                        .and_then(|b| b.currency.clone())
                        .or_else(|| {
                            obj["currency"]
                                .as_str()
                                .map(str::to_ascii_lowercase)
                                .and_then(|c| BillingCurrency::parse(&c))
                                .map(|c| c.as_str().to_string())
                        }),
                };
                collection
                    .update_one(
                        doc! { "_id": tenant_id },
                        doc! {
                            "$set": {
                                "plan": bson::to_bson(&plan).unwrap_or_default(),
                                "billing": bson::to_bson(&merged).unwrap_or_default(),
                                "updated_at": DateTime::now(),
                            }
                        },
                    )
                    .await?;

                info!(
                    tenant_id = %tenant_hex,
                    plan = %plan_str,
                    "Tenant plan upgraded via checkout"
                );
            }

            // FR-115 — `created` too: it can arrive before
            // `checkout.session.completed`, and it carries the seats.
            "customer.subscription.created" | "customer.subscription.updated" => {
                let tenant = self.apply_subscription(db, obj).await?;
                info!(
                    subscription_id = %obj["id"].as_str().unwrap_or_default(),
                    status = %obj["status"].as_str().unwrap_or_default(),
                    tenant_id = ?tenant,
                    event = %event.event_type,
                    "Subscription updated"
                );
            }

            "customer.subscription.deleted" => {
                let subscription_id = obj["id"].as_str().unwrap_or_default();

                let collection = db.collection::<Tenant>(Tenant::COLLECTION);
                collection
                    .update_one(
                        doc! { "billing.subscription_id": subscription_id },
                        doc! {
                            "$set": {
                                "plan": bson::to_bson(&Plan::Free).unwrap_or_default(),
                                "billing.status": bson::to_bson(&SubscriptionStatus::Canceled).unwrap_or_default(),
                                "billing.cancel_at_period_end": false,
                                "updated_at": DateTime::now(),
                            }
                        },
                    )
                    .await?;

                info!(
                    subscription_id = %subscription_id,
                    "Subscription deleted, reverted to Free plan"
                );
            }

            "invoice.payment_failed" => {
                let subscription_id = obj["subscription"].as_str().unwrap_or_default();

                let collection = db.collection::<Tenant>(Tenant::COLLECTION);
                collection
                    .update_one(
                        doc! { "billing.subscription_id": subscription_id },
                        doc! {
                            "$set": {
                                "billing.status": bson::to_bson(&SubscriptionStatus::PastDue).unwrap_or_default(),
                                "updated_at": DateTime::now(),
                            }
                        },
                    )
                    .await?;

                warn!(
                    subscription_id = %subscription_id,
                    "Invoice payment failed"
                );
            }

            other => {
                info!(event_type = %other, "Unhandled Stripe webhook event");
            }
        }

        Ok(())
    }
}

/// FR-115 — the currencies the paid plans are offered in, from
/// `stripe.currencies` (`"usd,eur"`), in the order given; USD when nothing in
/// it is readable. A currency joins the list once every configured Price
/// carries an amount in it: the billing page starts a European browser on
/// EUR, and an EUR checkout on a Price without an EUR `currency_options`
/// entry is refused.
pub fn currencies_on_sale(settings: &StripeSettings) -> Vec<BillingCurrency> {
    let mut out = Vec::new();
    for raw in settings.currencies.split(',') {
        if let Some(c) = BillingCurrency::parse(&raw.trim().to_ascii_lowercase())
            && !out.contains(&c)
        {
            out.push(c);
        }
    }
    if out.is_empty() {
        out.push(BillingCurrency::Usd);
    }
    out
}

/// FR-115 — an org whose subscription bills (or is about to): a checkout
/// would bill it twice, so a plan change takes the change path instead.
pub fn has_live_subscription(t: &Tenant) -> bool {
    t.billing.as_ref().is_some_and(|b| {
        b.subscription_id.as_deref().is_some_and(|s| !s.is_empty())
            && matches!(
                b.status,
                SubscriptionStatus::Active
                    | SubscriptionStatus::Trialing
                    | SubscriptionStatus::PastDue
            )
    })
}

/// A subscription's first (and, for us, only) item: its id and quantity.
fn first_item(sub: &Value) -> Option<(String, u32)> {
    let item = sub["items"]["data"].as_array()?.first()?;
    let id = item["id"].as_str()?.to_string();
    let quantity = item["quantity"].as_u64().unwrap_or(1);
    Some((id, u32::try_from(quantity).unwrap_or(u32::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    /// FR-115 — the plans list publishes per-seat prices in both currencies,
    /// annual only once its Prices exist, and commercial use on Free.
    #[test]
    fn plans_publish_per_seat_prices_and_annual_only_when_configured() {
        let monthly_only = StripeSettings {
            price_pro: "price_p".into(),
            price_business: "price_b".into(),
            currencies: "usd,eur".into(),
            ..Default::default()
        };
        let plans = StripeService::get_plans(&monthly_only);
        let pro = plans.iter().find(|p| p.id == "pro").unwrap();
        assert!(pro.per_seat);
        assert!(
            pro.prices
                .iter()
                .all(|p| p.interval == BillingInterval::Month)
        );
        assert_eq!(pro.prices.len(), 2, "USD and EUR");
        assert!(pro.prices.iter().all(|p| p.unit_amount == 800));
        // No plan lists a year while nothing is sold annually, Free included:
        // a `year` entry is what puts the Annual toggle on the billing page.
        assert!(
            plans.iter().all(|p| p
                .prices
                .iter()
                .all(|x| x.interval == BillingInterval::Month)),
            "a year is listed with no annual Price configured"
        );

        let with_annual = StripeSettings {
            price_pro_annual: "price_py".into(),
            price_business_annual: "price_by".into(),
            ..monthly_only
        };
        let plans = StripeService::get_plans(&with_annual);
        let biz = plans.iter().find(|p| p.id == "business").unwrap();
        let year: Vec<_> = biz
            .prices
            .iter()
            .filter(|p| p.interval == BillingInterval::Year)
            .collect();
        assert_eq!(year.len(), 2);
        assert!(year.iter().all(|p| p.unit_amount == 16_000), "ten months");

        let free = plans.iter().find(|p| p.id == "free").unwrap();
        assert!(
            free.prices
                .iter()
                .any(|p| p.interval == BillingInterval::Year && p.unit_amount == 0),
            "once annual is sold, Free is listed at 0 in both intervals"
        );
        assert!(free.commercial_use);
        assert!(!free.per_seat);
        assert_eq!(free.features[0], "Free for commercial use");
        assert!(
            plans
                .iter()
                .all(|p| !p.features.iter().any(|f| f.contains("AI"))),
            "AI recognition was deleted in FR-32 and must not be sold"
        );
    }

    /// FR-115 — a currency is offered only once the operator names it. The
    /// default is USD alone, so a Price without an EUR amount is never
    /// offered, or sold, in EUR.
    #[test]
    fn a_currency_is_offered_only_once_named() {
        let on_sale = |raw: &str| {
            currencies_on_sale(&StripeSettings {
                currencies: raw.into(),
                ..Default::default()
            })
        };
        use BillingCurrency::{Eur, Usd};
        assert_eq!(on_sale(""), vec![Usd]);
        assert_eq!(on_sale("usd"), vec![Usd]);
        assert_eq!(on_sale("usd,eur"), vec![Usd, Eur]);
        assert_eq!(on_sale(" EUR , usd ,eur"), vec![Eur, Usd]);
        assert_eq!(on_sale("gbp"), vec![Usd], "nothing readable means USD");

        let usd_only = StripeService::get_plans(&StripeSettings {
            price_pro: "price_p".into(),
            price_business: "price_b".into(),
            ..Default::default()
        });
        assert!(
            usd_only
                .iter()
                .all(|p| p.prices.iter().all(|x| x.currency == Usd)),
            "EUR stays off the page until it is on sale"
        );
    }

    fn tenant_with(status: SubscriptionStatus, sub: Option<&str>) -> Tenant {
        Tenant {
            id: Some(ObjectId::new()),
            name: "t".into(),
            slug: "t".into(),
            description: None,
            icon: None,
            owner_id: ObjectId::new(),
            security_rev: Some(1),
            plan: Plan::Pro,
            features: vec![],
            settings: Default::default(),
            billing: Some(BillingInfo {
                customer_id: Some("cus_1".into()),
                subscription_id: sub.map(str::to_string),
                current_period_end: None,
                status,
                cancel_at_period_end: false,
                seats: None,
                interval: None,
                currency: None,
            }),
            integrations: None,
            is_archived: false,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            deleted_at: None,
        }
    }

    /// FR-115 — a live subscription blocks a second checkout; a canceled
    /// one, an incomplete one or none at all does not.
    #[test]
    fn only_a_billing_subscription_blocks_a_new_checkout() {
        assert!(has_live_subscription(&tenant_with(
            SubscriptionStatus::Active,
            Some("sub_1")
        )));
        assert!(has_live_subscription(&tenant_with(
            SubscriptionStatus::PastDue,
            Some("sub_1")
        )));
        assert!(has_live_subscription(&tenant_with(
            SubscriptionStatus::Trialing,
            Some("sub_1")
        )));
        assert!(!has_live_subscription(&tenant_with(
            SubscriptionStatus::Canceled,
            Some("sub_1")
        )));
        assert!(!has_live_subscription(&tenant_with(
            SubscriptionStatus::Incomplete,
            Some("sub_1")
        )));
        assert!(!has_live_subscription(&tenant_with(
            SubscriptionStatus::Active,
            None
        )));
        assert!(!has_live_subscription(&tenant_with(
            SubscriptionStatus::Active,
            Some("")
        )));
    }

    #[test]
    fn the_first_item_is_read_with_its_quantity() {
        let sub = serde_json::json!({ "items": { "data": [ { "id": "si_1", "quantity": 7 } ] } });
        assert_eq!(first_item(&sub), Some(("si_1".to_string(), 7)));
        let none = serde_json::json!({ "items": { "data": [] } });
        assert_eq!(first_item(&none), None);
    }

    fn header_for(secret: &str, payload: &[u8], ts: i64) -> String {
        let signed = format!("{ts}.{}", String::from_utf8_lossy(payload));
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed.as_bytes());
        format!("t={ts},v1={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn signature_replay_window_enforced() {
        let secret = "whsec_test";
        let body = br#"{"id":"evt_1","type":"noop"}"#;
        let now = 1_800_000_000i64;

        // Fresh signature: accepted.
        let h = header_for(secret, body, now - 10);
        assert!(StripeService::verify_signature_at(secret, body, &h, now).is_ok());

        // Inside the 5-minute window: accepted.
        let h = header_for(secret, body, now - 290);
        assert!(StripeService::verify_signature_at(secret, body, &h, now).is_ok());

        // Replayed from outside the window: rejected even though the
        // HMAC itself is valid.
        let h = header_for(secret, body, now - 400);
        assert!(StripeService::verify_signature_at(secret, body, &h, now).is_err());

        // Future-dated beyond tolerance (badly skewed clock): rejected.
        let h = header_for(secret, body, now + 400);
        assert!(StripeService::verify_signature_at(secret, body, &h, now).is_err());

        // Wrong secret: rejected.
        let h = header_for("other", body, now);
        assert!(StripeService::verify_signature_at(secret, body, &h, now).is_err());
    }
}
