// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use bson::oid::ObjectId;
use serde::Deserialize;

use meshharbor_core::{ApiError, Core, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use meshharbor_db::models::tenant::{BillingCurrency, BillingInterval};
use meshharbor_services::stripe::{BillingSummary, CheckoutParams, StripeEvent, StripeService};

// ---- Request types -------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CheckoutRequest {
    pub tenant_id: String,
    pub plan: String,
    /// FR-115 — `month` (the default, and what a pre-FR-115 client sends by
    /// omission) or `year`.
    #[serde(default)]
    pub interval: Option<String>,
    /// FR-115 — `usd` (the default) or `eur`.
    #[serde(default)]
    pub currency: Option<String>,
    pub success_url: String,
    pub cancel_url: String,
}

/// FR-115 — move a live subscription to another plan and/or interval.
#[derive(Debug, Deserialize)]
pub struct ChangePlanRequest {
    pub tenant_id: String,
    pub plan: String,
    #[serde(default)]
    pub interval: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SummaryQuery {
    pub tenant_id: String,
}

fn parse_interval(raw: Option<&str>) -> Result<BillingInterval, ApiError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(BillingInterval::Month),
        Some(s) => BillingInterval::parse(s).ok_or_else(|| {
            stripe_err(meshharbor_services::stripe::StripeError::InvalidInterval(
                s.to_string(),
            ))
        }),
    }
}

fn parse_currency(raw: Option<&str>) -> Result<BillingCurrency, ApiError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(BillingCurrency::Usd),
        Some(s) => BillingCurrency::parse(&s.to_ascii_lowercase()).ok_or_else(|| {
            stripe_err(meshharbor_services::stripe::StripeError::InvalidCurrency(
                s.to_string(),
            ))
        }),
    }
}

#[derive(Debug, Deserialize)]
pub struct PortalRequest {
    pub tenant_id: String,
    pub return_url: String,
}

// ---- GET /api/stripe/plans (public) --------------------------------------

pub async fn get_plans(
    State(state): State<Core>,
) -> Json<Vec<meshharbor_services::stripe::PlanInfo>> {
    Json(StripeService::get_plans(&state.settings.stripe))
}

// ---- POST /api/stripe/checkout (authenticated, MANAGE_TENANT) ------------

pub async fn create_checkout(
    State(state): State<Core>,
    auth: AuthUser,
    Json(body): Json<CheckoutRequest>,
) -> Result<Json<meshharbor_services::stripe::CheckoutResponse>, ApiError> {
    let tenant_id = parse_oid(&body.tenant_id)?;
    require_manage_tenant(&state, tenant_id, auth.user_id).await?;
    let interval = parse_interval(body.interval.as_deref())?;
    let currency = parse_currency(body.currency.as_deref())?;

    // FR-115 — one unit per seat: the members who accepted, at least one.
    let seats = StripeService::count_seats(&state.db, &tenant_id)
        .await
        .map_err(stripe_err)?;
    let stripe = StripeService::new(&state.settings.stripe);
    let result = stripe
        .create_checkout_session(
            &state.db,
            &tenant_id,
            &CheckoutParams {
                plan: &body.plan,
                interval,
                currency,
                seats,
                email: &auth.email,
                success_url: &body.success_url,
                cancel_url: &body.cancel_url,
            },
        )
        .await
        .map_err(stripe_err)?;

    Ok(Json(result))
}

// ---- POST /api/stripe/change-plan (authenticated, MANAGE_TENANT) ---------

/// FR-115 — move the org's live subscription to another plan or interval,
/// with a proration; never a second checkout (which billed an org twice).
pub async fn change_plan(
    State(state): State<Core>,
    auth: AuthUser,
    Json(body): Json<ChangePlanRequest>,
) -> Result<Json<BillingSummary>, ApiError> {
    let tenant_id = parse_oid(&body.tenant_id)?;
    require_manage_tenant(&state, tenant_id, auth.user_id).await?;
    let interval = parse_interval(body.interval.as_deref())?;
    let stripe = StripeService::new(&state.settings.stripe);
    let summary = stripe
        .change_plan(&state.db, &tenant_id, &body.plan, interval)
        .await
        .map_err(stripe_err)?;
    tracing::info!(
        user = %auth.user_id, tenant = %tenant_id, plan = %body.plan,
        interval = interval.as_str(), "plan change requested"
    );
    Ok(Json(summary))
}

// ---- GET /api/stripe/summary?tenant_id= (authenticated, MANAGE_TENANT) ---

/// FR-115 — the billing page's view: plan, billed and current seats,
/// interval, currency, status.
pub async fn summary(
    State(state): State<Core>,
    auth: AuthUser,
    axum::extract::Query(q): axum::extract::Query<SummaryQuery>,
) -> Result<Json<BillingSummary>, ApiError> {
    let tenant_id = parse_oid(&q.tenant_id)?;
    require_manage_tenant(&state, tenant_id, auth.user_id).await?;
    let stripe = StripeService::new(&state.settings.stripe);
    let summary = stripe
        .summary(&state.db, &tenant_id)
        .await
        .map_err(stripe_err)?;
    Ok(Json(summary))
}

// ---- the seat reconcile (FR-115 P2) --------------------------------------

/// How often the seat reconcile runs: membership changes reach Stripe
/// within this, with a proration from the moment Stripe is told.
pub const SEAT_SYNC_INTERVAL_SECS: u64 = 15 * 60;

/// FR-115 — keep every subscription's quantity equal to its org's seats.
/// One pod per tick (the Redis claim in `pull_schedule::spawn_hourly`), and
/// only with a secret key and `stripe.seat_sync` on (the kill switch).
pub fn spawn_seat_sync(core: Core) {
    let s = &core.settings.stripe;
    if s.secret_key.trim().is_empty() || !s.seat_sync {
        tracing::info!(
            configured = !s.secret_key.trim().is_empty(),
            seat_sync = s.seat_sync,
            "stripe seat sync not started"
        );
        return;
    }
    crate::pull_schedule::spawn_hourly(
        core,
        "billing-seat-sync",
        120,
        SEAT_SYNC_INTERVAL_SECS,
        |core| async move {
            let stripe = StripeService::new(&core.settings.stripe);
            match stripe.reconcile_seats(&core.db).await {
                Ok(r) if r.changed > 0 || r.failed > 0 => tracing::info!(
                    orgs = r.orgs,
                    changed = r.changed,
                    failed = r.failed,
                    "stripe seat sync"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(%e, "stripe seat sync failed"),
            }
        },
    );
}

// ---- POST /api/stripe/portal (authenticated, MANAGE_TENANT) --------------

pub async fn create_portal(
    State(state): State<Core>,
    auth: AuthUser,
    Json(body): Json<PortalRequest>,
) -> Result<Json<meshharbor_services::stripe::PortalResponse>, ApiError> {
    let tenant_id = parse_oid(&body.tenant_id)?;
    require_manage_tenant(&state, tenant_id, auth.user_id).await?;

    let stripe = StripeService::new(&state.settings.stripe);
    let result = stripe
        .create_portal_session(&state.db, &tenant_id, &body.return_url)
        .await
        .map_err(stripe_err)?;

    Ok(Json(result))
}

// ---- POST /api/stripe/webhook (no auth, raw body) ------------------------

pub async fn webhook(
    State(state): State<Core>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let sig_header = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("Missing Stripe-Signature header".to_string()))?;

    // Verify signature
    StripeService::verify_signature(&state.settings.stripe.webhook_secret, &body, sig_header)
        .map_err(|_| ApiError::Unauthorized("Invalid webhook signature".to_string()))?;

    // Parse event
    let event: StripeEvent = serde_json::from_slice(&body)
        .map_err(|e| ApiError::BadRequest(format!("Invalid event payload: {e}")))?;

    // Process event
    let stripe = StripeService::new(&state.settings.stripe);
    stripe
        .handle_webhook_event(&state.db, &event)
        .await
        .map_err(stripe_err)?;

    Ok(StatusCode::OK)
}

// ---- FR-102 P4: the operator's one-off backfill ------------------------------

#[derive(Debug, Deserialize)]
pub struct BackfillQuery {
    /// `YYYY-MM-DD` (UTC): read invoices created since this day. Absent =
    /// all of them (bounded by `BACKFILL_MAX_PAGES` pages of 100).
    #[serde(default)]
    pub since: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct BackfillAnswer {
    #[serde(flatten)]
    pub report: meshharbor_services::stripe::BackfillReport,
    /// The closed months refrozen from the rows now on record (`YYYY-MM`).
    pub refrozen: Vec<String>,
}

/// `POST /api/admin/growth/billing/backfill?since=YYYY-MM-DD` — FR-102 P4:
/// read Stripe's paid invoices into `billing_events` (idempotent: an
/// invoice already on record is left as it was), then refreeze the closed
/// months those invoices touch. Platform admins only — 404 otherwise and
/// when `growth.enabled = false`, like every growth route. One-off and
/// operator-run: it reads Stripe and never writes to it.
pub async fn backfill(
    State(state): State<Core>,
    auth: AuthUser,
    axum::extract::Query(q): axum::extract::Query<BackfillQuery>,
) -> Result<Json<BackfillAnswer>, ApiError> {
    meshharbor_core::guards::require_platform_admin(&state, &auth)?;
    if !state.settings.growth.enabled {
        return Err(ApiError::NotFound("Not found".to_string()));
    }
    let since_unix = match q.since.as_deref() {
        None => None,
        Some(raw) => {
            let day = chrono::NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d")
                .map_err(|_| ApiError::BadRequest("since must be YYYY-MM-DD".into()))?;
            let floor = chrono::NaiveDate::from_ymd_opt(2020, 1, 1).expect("a real day");
            if day < floor {
                return Err(ApiError::BadRequest(
                    "since must be 2020-01-01 or later".into(),
                ));
            }
            Some(
                day.and_hms_opt(0, 0, 0)
                    .expect("midnight exists")
                    .and_utc()
                    .timestamp(),
            )
        }
    };
    let now = bson::DateTime::now();
    let stripe = StripeService::new(&state.settings.stripe);
    let report = stripe
        .backfill_paid_invoices(
            &state.db,
            meshharbor_services::stripe::STRIPE_API_BASE,
            since_unix,
            now,
        )
        .await
        .map_err(|e| match e {
            meshharbor_services::stripe::StripeError::ApiError(m) => ApiError::BadRequest(m),
            other => stripe_err(other),
        })?;
    let refrozen = refreeze(&state, &report.months, now).await?;
    tracing::info!(
        admin = %auth.user_id, recorded = report.recorded, refrozen = refrozen.len(),
        "growth billing backfill"
    );
    Ok(Json(BackfillAnswer { report, refrozen }))
}

/// Rewrite the frozen totals of the CLOSED months a backfill touched (past
/// the freeze grace) — the one deliberate correction a frozen month takes.
/// The current month is never frozen; it is computed live.
pub async fn refreeze(
    state: &Core,
    months: &[String],
    now: bson::DateTime,
) -> Result<Vec<String>, ApiError> {
    use meshharbor_services::billing;
    let excluded: Vec<ObjectId> = meshharbor_core::growth::ExclusionSet::load(state)
        .await?
        .tenants
        .into_iter()
        .collect();
    let now_ms = now.timestamp_millis();
    let mut done = Vec::new();
    for label in months {
        let Some((_, end)) = billing::month_bounds(label) else {
            continue;
        };
        if end + billing::FREEZE_GRACE_DAYS * 86_400_000 > now_ms {
            continue;
        }
        if billing::freeze_month(&state.db, label, &excluded, true, now).await? {
            done.push(label.clone());
        }
    }
    Ok(done)
}

// ---- Helpers -------------------------------------------------------------

fn parse_oid(s: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(s).map_err(|_| ApiError::BadRequest(format!("Invalid ObjectId: {s}")))
}

async fn require_manage_tenant(
    state: &Core,
    tenant_id: ObjectId,
    user_id: ObjectId,
) -> Result<(), ApiError> {
    // Tenant owner always has access
    let tenant = state.tenants.base.find_by_id(tenant_id).await?;
    if tenant.owner_id == user_id {
        return Ok(());
    }

    // Otherwise check MANAGE_TENANT permission
    let perms = state
        .tenants
        .get_member_permissions(tenant_id, user_id)
        .await?;
    if !permissions::has(perms, permissions::MANAGE_TENANT) {
        return Err(ApiError::Forbidden(
            "Missing MANAGE_TENANT permission".to_string(),
        ));
    }
    Ok(())
}

fn stripe_err(e: meshharbor_services::stripe::StripeError) -> ApiError {
    use meshharbor_services::stripe::StripeError;
    match e {
        StripeError::TenantNotFound => ApiError::NotFound("Tenant not found".to_string()),
        StripeError::NoBillingAccount => {
            ApiError::BadRequest("No billing account for this tenant".to_string())
        }
        StripeError::InvalidPlan(p) => ApiError::BadRequest(format!("Invalid plan: {p}")),
        StripeError::PriceNotConfigured(p) => ApiError::ServiceUnavailable(format!(
            "Payments are not configured on this server (missing Stripe price id for plan '{p}')"
        )),
        StripeError::InvalidSignature => {
            ApiError::Unauthorized("Invalid webhook signature".to_string())
        }
        // FR-115 — a second checkout would bill the org twice.
        e @ StripeError::AlreadySubscribed => ApiError::Conflict(e.to_string()),
        e @ (StripeError::NotSubscribed
        | StripeError::InvalidInterval(_)
        | StripeError::InvalidCurrency(_)
        | StripeError::CurrencyNotOffered(_)) => ApiError::BadRequest(e.to_string()),
        StripeError::ApiError(msg) => ApiError::Internal(format!("Stripe API error: {msg}")),
        StripeError::Mongo(e) => ApiError::Internal(e.to_string()),
        StripeError::Storage(msg) => ApiError::Internal(msg),
    }
}
