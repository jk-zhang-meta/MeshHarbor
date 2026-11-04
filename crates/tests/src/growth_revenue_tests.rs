// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P4 — billed revenue against a real server, through Stripe's own
//! signature scheme (spec §3g; AC13's test half).
//!
//! * **AC13** — a signed test-mode lifecycle (subscribe → invoice paid →
//!   seat change → cancel) writes `billing_events` with the INVOICE amounts,
//!   and the panel's MRR equals the invoices, not the list price — a 20 %
//!   coupon makes the two differ (the control). Month by month it moves as
//!   new → expansion → churn; the closed months freeze, and purging the org
//!   leaves the frozen months as they were.
//! * Recorded once: Stripe's retry of an event writes nothing, and the same
//!   invoice under another event is still one row.
//! * The funnel's `paid` step, the org timeline's plan history and the
//!   digest's billed section read the same rows.
//! * Trial → paid, and a failed payment, are counted.
//! * Quota collisions become a per-org, per-limit counter beside the warn
//!   line — in `warn` and `enforce` alike — and nothing with growth off.
//! * The operator's backfill reads Stripe's paid invoices (a fake Stripe)
//!   once: an invoice the webhook already recorded, and one naming no org
//!   here, are counted and not recorded; a second run records nothing.
//! * The routes hide like every growth route; without `saas` billed revenue
//!   is `not_measured`, and with nothing on record it says so — never 0.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Router, extract::Query, http::HeaderMap, routing::get};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::{Datelike, NaiveDate};
use meshharbor_services::{
    billing,
    dao::{
        billing_event::BILLING_EVENTS,
        growth::{BILLING_SOURCE, GROWTH_DAILY, QUOTA_COLLISION_METRIC, QUOTA_SOURCE},
    },
    stripe::StripeService,
};
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

const SECRET: &str = "whsec_test_fr102_p4";
const PRICE_PRO: &str = "price_pro_test";
const PRICE_BIZ: &str = "price_biz_test";

// ── Clock ────────────────────────────────────────────────────────────────

fn now_ms() -> i64 {
    DateTime::now().timestamp_millis()
}

fn secs(ms: i64) -> i64 {
    ms / 1000
}

/// `now − days`, in ms.
fn ago_days(days: i64) -> i64 {
    now_ms() - days * 86_400_000
}

/// The first day of the month `back` months before the current one.
fn month_start(back: u32) -> NaiveDate {
    let today = chrono::Utc::now().date_naive();
    let mut y = today.year();
    let mut m = today.month() as i32 - back as i32;
    while m < 1 {
        m += 12;
        y -= 1;
    }
    NaiveDate::from_ymd_opt(y, m as u32, 1).unwrap()
}

fn label(d: NaiveDate) -> String {
    d.format("%Y-%m").to_string()
}

/// 10:00 UTC on day `day` of the month `back` months ago, in ms.
fn at(back: u32, day: u32) -> i64 {
    month_start(back)
        .with_day(day)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp_millis()
}

// ── The app ──────────────────────────────────────────────────────────────

async fn revenue_app(tweak: impl FnOnce(&mut meshharbor_config::Settings)) -> (TestApp, String) {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
        s.stripe.webhook_secret = SECRET.into();
        s.stripe.price_pro = PRICE_PRO.into();
        s.stripe.price_business = PRICE_BIZ.into();
        tweak(s);
    })
    .await;
    let token = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap()
        .access_token;
    (app, token)
}

async fn insert(app: &TestApp, coll: &str, d: Document) {
    app.db
        .collection::<Document>(coll)
        .insert_one(d)
        .await
        .unwrap_or_else(|e| panic!("insert into {coll}: {e}"));
}

/// An owner (signed up `created`, arriving from YouTube) and their org
/// with `seats` members on the Free plan; returns the org's id.
async fn org_with_owner(app: &TestApp, slug: &str, created_ms: i64, seats: u32) -> ObjectId {
    let created = DateTime::from_millis(created_ms);
    let owner = ObjectId::new();
    insert(
        app,
        "users",
        doc! {
            "_id": owner, "email": format!("{slug}@test.io"), "username": slug,
            "display_name": "An Owner", "avatar": Bson::Null, "bio": Bson::Null,
            "is_verified": true, "is_mfa_enabled": false, "last_active_at": Bson::Null,
            "oauth_providers": [], "created_at": created, "updated_at": created,
            "deleted_at": Bson::Null,
            "signup_attribution": { "source": "youtube", "referrer_host": "youtube.com" },
        },
    )
    .await;
    let tenant = ObjectId::new();
    insert(
        app,
        "tenants",
        doc! {
            "_id": tenant, "name": format!("{slug} <org>"), "slug": slug,
            "description": Bson::Null, "icon": Bson::Null, "owner_id": owner,
            "plan": "free", "features": [], "settings": { "default_locale": "en-US" },
            "billing": Bson::Null, "integrations": Bson::Null, "is_archived": false,
            "created_at": created, "updated_at": created, "deleted_at": Bson::Null,
        },
    )
    .await;
    for i in 0..seats {
        insert(
            app,
            "tenant_members",
            doc! {
                "tenant_id": tenant, "user_id": if i == 0 { owner } else { ObjectId::new() },
                "nickname": Bson::Null, "role_ids": [], "joined_at": created,
                "is_pending": false, "is_muted": false, "notification_override": Bson::Null,
                "invited_by": Bson::Null, "last_seen_at": Bson::Null,
                "created_at": created, "updated_at": created,
            },
        )
        .await;
    }
    tenant
}

// ── Stripe, signed ───────────────────────────────────────────────────────

fn hmac_hex(secret: &str, message: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// POST one event to the webhook, signed with Stripe's scheme
/// (`t=<now>,v1=HMAC-SHA256(secret, "<t>.<body>")`); the status.
async fn post_event(app: &TestApp, event: &Value) -> u16 {
    let body = serde_json::to_vec(event).unwrap();
    let t = secs(now_ms()).to_string();
    let sig = hmac_hex(SECRET, &format!("{t}.{}", String::from_utf8_lossy(&body)));
    app.client
        .post(app.url("/api/stripe/webhook"))
        .header("Content-Type", "application/json")
        .header("stripe-signature", format!("t={t},v1={sig}"))
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

fn event(id: &str, kind: &str, created_ms: i64, object: Value) -> Value {
    json!({
        "id": id, "object": "event", "type": kind, "created": secs(created_ms),
        "data": { "object": object },
    })
}

fn checkout(tenant: ObjectId, sub: &str, cus: &str) -> Value {
    event(
        &format!("evt_co_{sub}"),
        "checkout.session.completed",
        now_ms(),
        json!({
            "id": format!("cs_{sub}"), "object": "checkout.session",
            "metadata": { "tenant_id": tenant.to_hex(), "plan": "pro" },
            "subscription": sub, "customer": cus,
        }),
    )
}

/// A classic subscription: one Pro item of `qty` seats.
fn subscription(
    sub: &str,
    cus: &str,
    tenant: ObjectId,
    qty: i64,
    period: (i64, i64),
    status: &str,
) -> Value {
    json!({
        "id": sub, "object": "subscription", "customer": cus, "status": status,
        "metadata": { "tenant_id": tenant.to_hex(), "plan": "pro" },
        "current_period_start": secs(period.0), "current_period_end": secs(period.1),
        "cancel_at_period_end": false,
        "items": { "data": [{
            "id": format!("si_{sub}"), "quantity": qty,
            "price": { "id": PRICE_PRO, "recurring": { "interval": "month", "interval_count": 1 } },
        }] },
    })
}

/// One invoice line: `amount` less `discount`, `qty` Pro seats over
/// `period`; a proration or the recurring charge.
fn line(amount: i64, discount: i64, qty: i64, period: (i64, i64), proration: bool) -> Value {
    json!({
        "object": "line_item", "type": "subscription", "amount": amount,
        "discount_amounts": if discount > 0 { json!([{ "amount": discount }]) } else { json!([]) },
        "quantity": qty, "proration": proration,
        "period": { "start": secs(period.0), "end": secs(period.1) },
        "price": { "id": PRICE_PRO, "recurring": { "interval": "month", "interval_count": 1 } },
    })
}

#[allow(clippy::too_many_arguments)]
fn invoice(
    id: &str,
    sub: &str,
    cus: &str,
    tenant: ObjectId,
    paid_ms: i64,
    amount: i64,
    reason: &str,
    lines: Vec<Value>,
) -> Value {
    json!({
        "id": id, "object": "invoice", "customer": cus, "subscription": sub,
        "status": "paid", "currency": "eur", "amount_paid": amount, "amount_due": amount,
        "billing_reason": reason,
        "status_transitions": { "paid_at": secs(paid_ms) },
        "subscription_details": { "metadata": { "tenant_id": tenant.to_hex() } },
        "lines": { "data": lines },
    })
}

async fn rows_of(app: &TestApp, tenant: ObjectId) -> Vec<Document> {
    use futures::TryStreamExt;
    app.db
        .collection::<Document>(BILLING_EVENTS)
        .find(doc! { "tenant_id": tenant })
        .sort(doc! { "ts": 1, "_id": 1 })
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap()
}

async fn get_json(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let r = app.auth_get(path, token).send().await.unwrap();
    let status = r.status().as_u16();
    let text = r.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn org_row(j: &Value, tenant: ObjectId) -> &Value {
    j["orgs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tenant_id"] == tenant.to_hex())
        .unwrap_or_else(|| panic!("no row for {tenant} in {}", j["orgs"]))
}

fn month<'a>(j: &'a Value, m: &str) -> &'a Value {
    j["billed"]["months"]
        .as_array()
        .unwrap_or_else(|| panic!("no months in {}", j["billed"]))
        .iter()
        .find(|b| b["month"] == m)
        .unwrap_or_else(|| panic!("no {m} in {}", j["billed"]["months"]))
}

/// The eur movements of one month (absent = nothing moved).
fn eur(block: &Value) -> Option<&Value> {
    block["currencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["currency"] == "eur")
}

// ── AC13: the control ────────────────────────────────────────────────────

/// AC13's control — three Pro seats list at 24.00 a month; the invoice,
/// after a 20 % coupon, billed 19.20. The panel's MRR is the 19.20.
/// The same rows answer the funnel's `paid`, the timeline and the digest.
#[tokio::test]
async fn the_panel_reads_what_stripe_billed_not_the_list_price() {
    let (app, token) = revenue_app(|_| {}).await;
    let x = org_with_owner(&app, "acme", ago_days(2), 3).await;
    let period = (ago_days(1), ago_days(1) + 30 * 86_400_000);
    // Both rows land in ONE second — the subscription's `created` and the
    // invoice's `paid_at` are the same instant, as Stripe sends them — so
    // their `ts` (Stripe seconds) tie, and the order the panel reads rests
    // on the `_id` tiebreak, which must be ARRIVAL order: the row's own
    // `_id` stays on the paid invoice's upsert (`BillingEventDao::record`).
    // With mongod minting that `_id` instead, this assertion failed about
    // every second run.
    let at = ago_days(1) / 1000 * 1000;

    assert_eq!(post_event(&app, &checkout(x, "sub_a", "cus_a")).await, 200);
    let created = event(
        "evt_a1",
        "customer.subscription.created",
        at,
        subscription("sub_a", "cus_a", x, 3, period, "active"),
    );
    assert_eq!(post_event(&app, &created).await, 200);
    let paid = event(
        "evt_a2",
        "invoice.paid",
        at,
        invoice(
            "in_a1",
            "sub_a",
            "cus_a",
            x,
            at,
            1920,
            "subscription_create",
            vec![line(2400, 480, 3, period, false)],
        ),
    );
    assert_eq!(post_event(&app, &paid).await, 200);

    // The rows: what the invoice billed, from the invoice.
    let rows = rows_of(&app, x).await;
    let kinds: Vec<&str> = rows.iter().map(|r| r.get_str("kind").unwrap()).collect();
    assert_eq!(kinds, ["subscription_created", "invoice_paid"]);
    let inv = &rows[1];
    assert_eq!(inv.get_i64("amount_cents").unwrap(), 1920);
    assert_eq!(inv.get_i64("recurring_cents").unwrap(), 1920);
    assert_eq!(inv.get_i64("seats").unwrap(), 3);
    assert_eq!(inv.get_str("plan").unwrap(), "pro");
    assert_eq!(inv.get_str("currency").unwrap(), "eur");
    assert_eq!(inv.get_str("stripe_id").unwrap(), "in_a1");
    assert_eq!(inv.get_str("event_id").unwrap(), "evt_a2");
    assert_eq!(rows[0].get_i64("seats").unwrap(), 3);
    assert!(
        rows[0].get("amount_cents").is_none_or(|v| *v == Bson::Null),
        "a subscription event carries no amount: null, never 0"
    );

    // Recorded once: Stripe's retry of the event, and the same invoice
    // under another event, write nothing.
    assert_eq!(post_event(&app, &paid).await, 200);
    let mut again = paid.clone();
    again["id"] = json!("evt_a2_redelivered");
    assert_eq!(post_event(&app, &again).await, 200);
    assert_eq!(rows_of(&app, x).await.len(), 2);

    // The panel: billed MRR is the invoice's 19.20, the list price 24.00.
    let (s, j) = get_json(&app, "/api/admin/growth/revenue", &token).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(
        j["billed"]["now"],
        json!([{ "currency": "eur", "mrr_cents": 1920, "paying_orgs": 1 }])
    );
    let o = org_row(&j, x);
    assert_eq!(o["billed_mrr_cents"], 1920);
    assert_eq!(o["list_price_mrr_cents"], 2400.0, "Pro 8.00 × 3 seats");
    assert_ne!(o["billed_mrr_cents"], o["list_price_mrr_cents"]);
    assert_eq!(o["currency"], "eur");
    assert_eq!(o["plan"], "pro", "the checkout's plan");
    assert_eq!(o["channel"], "social", "the owner arrived from YouTube");
    assert!(o["paid_since"].is_string());
    assert_eq!(
        j["estimate"]["estimate"], true,
        "the estimate keeps its label"
    );
    assert_eq!(j["billed"]["record"]["rows"], 2);
    assert!(
        j["billed"]["record"].get("backfilled_at").is_none(),
        "no backfill has run"
    );
    let this_month = month(&j, &label(month_start(0)));
    assert_eq!(this_month["partial"], true);
    let json = j.to_string();
    assert!(!json.contains("acme@test.io"), "no address in the view");

    // The funnel's paid step: the owner's org paid.
    let (s, f) = get_json(&app, "/api/admin/growth/funnel", &token).await;
    assert_eq!(s, 200, "{f}");
    assert_eq!(f["steps"]["paid"]["count"], 1, "{}", f["steps"]);
    assert!(f["not_measured"].get("paid").is_none());

    // The timeline: the plan history and the first payment.
    let (s, t) = get_json(
        &app,
        &format!("/api/admin/growth/org/{}/timeline", x.to_hex()),
        &token,
    )
    .await;
    assert_eq!(s, 200, "{t}");
    let history = t["plan_history"].as_array().unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1]["kind"], "invoice_paid");
    assert_eq!(history[1]["amount_cents"], 1920);
    assert!(
        t["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "first_paid")
    );

    // The digest of yesterday: the same MRR, the invoice in the day.
    let yesterday = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
    let (s, d) = get_json(
        &app,
        &format!(
            "/api/admin/growth/digest/preview?day={}",
            yesterday.format("%Y-%m-%d")
        ),
        &token,
    )
    .await;
    assert_eq!(s, 200, "{d}");
    let billed = &d["sections"]["revenue"]["billed"];
    assert_eq!(billed["mrr"][0]["mrr_cents"], 1920, "{billed}");
    assert_eq!(billed["invoices_paid"]["day"], 1);
    assert_eq!(billed["billed"][0]["cents"]["day"], 1920);
    assert_eq!(billed["new_paying_orgs"]["day"], 1);
    assert_eq!(billed["backfilled"], false);
    assert_eq!(d["sections"]["revenue"]["mrr"]["estimate"], true);
}

// ── AC13: the lifecycle, month by month ──────────────────────────────────

/// AC13 — subscribe (3 seats, 20 % off) → invoice paid → a seat change to
/// 5 (a proration invoice: cash, not MRR) → the renewal bills 5 seats →
/// cancel at the period's end. Month by month: new 19.20, expansion 12.80,
/// churn 32.00. The closed months freeze; purging the org then rewrites
/// nothing frozen.
#[tokio::test]
async fn a_lifecycle_moves_billed_mrr_month_by_month_and_freezes() {
    let (app, token) = revenue_app(|_| {}).await;
    // M0 = four months ago … M2 = two months ago: closed well past the grace.
    let y = org_with_owner(&app, "lifecycle", at(4, 1), 3).await;
    let p1 = (at(4, 5), at(3, 5));
    let p2 = (at(3, 5), at(2, 5));

    assert_eq!(post_event(&app, &checkout(y, "sub_b", "cus_b")).await, 200);
    let events = [
        event(
            "evt_b1",
            "customer.subscription.created",
            at(4, 5),
            subscription("sub_b", "cus_b", y, 3, p1, "active"),
        ),
        event(
            "evt_b2",
            "invoice.paid",
            at(4, 5),
            invoice(
                "in_b1",
                "sub_b",
                "cus_b",
                y,
                at(4, 5),
                1920,
                "subscription_create",
                vec![line(2400, 480, 3, p1, false)],
            ),
        ),
        // The seat change: 3 → 5, prorated now — cash, not MRR.
        event(
            "evt_b3",
            "customer.subscription.updated",
            at(4, 20),
            subscription("sub_b", "cus_b", y, 5, p1, "active"),
        ),
        event(
            "evt_b4",
            "invoice.paid",
            at(4, 20),
            invoice(
                "in_b2",
                "sub_b",
                "cus_b",
                y,
                at(4, 20),
                427,
                "subscription_update",
                vec![
                    line(-640, 0, 3, (at(4, 20), p1.1), true),
                    line(1067, 0, 5, (at(4, 20), p1.1), true),
                ],
            ),
        ),
        // The renewal bills the five seats, the coupon still on.
        event(
            "evt_b5",
            "invoice.paid",
            at(3, 5),
            invoice(
                "in_b3",
                "sub_b",
                "cus_b",
                y,
                at(3, 5),
                3200,
                "subscription_cycle",
                vec![line(4000, 800, 5, p2, false)],
            ),
        ),
        // Canceled at the period's end.
        event("evt_b6", "customer.subscription.deleted", at(2, 5), {
            let mut s = subscription("sub_b", "cus_b", y, 5, p2, "canceled");
            s["ended_at"] = json!(secs(at(2, 5)));
            s
        }),
    ];
    for e in &events {
        assert_eq!(post_event(&app, e).await, 200, "{}", e["id"]);
    }

    let rows = rows_of(&app, y).await;
    let paid: Vec<(i64, Option<i64>)> = rows
        .iter()
        .filter(|r| r.get_str("kind").unwrap() == "invoice_paid")
        .map(|r| {
            (
                r.get_i64("amount_cents").unwrap(),
                r.get_i64("recurring_cents").ok(),
            )
        })
        .collect();
    assert_eq!(
        paid,
        [(1920, Some(1920)), (427, None), (3200, Some(3200))],
        "the invoice amounts; a proration-only invoice has no recurring part"
    );
    let updated = rows
        .iter()
        .find(|r| r.get_str("kind").unwrap() == "subscription_updated")
        .unwrap();
    assert_eq!(updated.get_i64("seats").unwrap(), 5);
    let deleted = rows
        .iter()
        .find(|r| r.get_str("kind").unwrap() == "subscription_deleted")
        .unwrap();
    assert_eq!(
        deleted.get_datetime("ts").unwrap().timestamp_millis(),
        at(2, 5)
    );

    let (m0, m1, m2) = (
        label(month_start(4)),
        label(month_start(3)),
        label(month_start(2)),
    );
    let path = format!("/api/admin/growth/revenue?since={}", label(month_start(5)));
    let (s, j) = get_json(&app, &path, &token).await;
    assert_eq!(s, 200, "{j}");
    // Before the first row: not on record — never a month of zero.
    let before = month(&j, &label(month_start(5)));
    assert_eq!(before["on_record"], false);
    assert!(before["currencies"].as_array().unwrap().is_empty());
    let a = eur(month(&j, &m0)).expect("M0 moved");
    assert_eq!(
        (&a["mrr_cents"], &a["new_cents"], &a["new_orgs"]),
        (&json!(1920), &json!(1920), &json!(1))
    );
    assert_eq!(
        (&a["invoices_paid"], &a["billed_cents"]),
        (&json!(2), &json!(2347))
    );
    let b = eur(month(&j, &m1)).expect("M1 moved");
    assert_eq!(
        (&b["mrr_cents"], &b["expansion_cents"], &b["net_new_cents"]),
        (&json!(3200), &json!(1280), &json!(1280))
    );
    let c = eur(month(&j, &m2)).expect("M2 moved");
    assert_eq!(
        (&c["mrr_cents"], &c["churned_cents"], &c["churned_orgs"]),
        (&json!(0), &json!(3200), &json!(1))
    );
    assert_eq!(month(&j, &m0)["frozen"], false, "not frozen yet");
    assert!(
        j["billed"]["now"].as_array().unwrap().is_empty(),
        "canceled"
    );
    let social = j["billed"]["by_channel"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["channel"] == "social")
        .expect("the owner's channel");
    assert_eq!(
        (&social["new_paying_orgs"], &social["churned_orgs"]),
        (&json!(1), &json!(1))
    );
    let o = org_row(&j, y);
    assert_eq!(o["billed_mrr_cents"], 0, "billed before, nothing now");
    assert_eq!(o["plan"], "free", "the deletion reverted the plan");

    // The nightly freeze: the closed months on record, once.
    let frozen =
        meshharbor_api::growth::org_daily::freeze_billing_months(&app.state, DateTime::now())
            .await
            .unwrap();
    for m in [&m0, &m1, &m2] {
        assert!(frozen.contains(m), "{m} frozen: {frozen:?}");
    }
    assert!(
        !frozen.contains(&label(month_start(5))),
        "a month before the record is never frozen"
    );
    let again =
        meshharbor_api::growth::org_daily::freeze_billing_months(&app.state, DateTime::now())
            .await
            .unwrap();
    assert!(again.is_empty(), "frozen once: {again:?}");
    let stored = app
        .db
        .collection::<Document>(GROWTH_DAILY)
        .find_one(doc! {
            "source": BILLING_SOURCE, "metric": "mrr_cents", "day": format!("{m1}-01"),
            "dims.currency": "eur", "dims.period": "month",
        })
        .await
        .unwrap()
        .expect("M1's frozen MRR");
    assert_eq!(stored.get_i64("value").unwrap(), 3200);
    assert!(stored.get_document("dims").unwrap().get("tenant").is_none());

    // Purge the org: its rows go, the frozen months stay as they were.
    let purged = meshharbor_core::growth::purge_tenant(&app.state.core, y)
        .await
        .unwrap();
    assert_eq!(purged.billing_events, rows.len() as u64);
    assert!(rows_of(&app, y).await.is_empty());
    let (s, j) = get_json(&app, &path, &token).await;
    assert_eq!(s, 200, "{j}");
    assert!(
        j["billed"].get("not_measured").is_none(),
        "the frozen months are the record"
    );
    for (m, mrr) in [(&m0, 1920), (&m1, 3200), (&m2, 0)] {
        let block = month(&j, m);
        assert_eq!(block["frozen"], true, "{m}");
        assert_eq!(eur(block).unwrap()["mrr_cents"], mrr, "{m}");
    }
    assert_eq!(eur(month(&j, &m1)).unwrap()["expansion_cents"], 1280);
    // `include_internal` computes live — and live, the purged rows are gone.
    let (_, live) = get_json(&app, &format!("{path}&include_internal=true"), &token).await;
    assert_eq!(month(&live, &m1)["frozen"], false);
    assert!(eur(month(&live, &m1)).is_none());
}

// ── Trial → paid, and a failed payment ───────────────────────────────────

#[tokio::test]
async fn a_trial_that_pays_converts_and_a_failed_payment_is_counted() {
    let (app, token) = revenue_app(|_| {}).await;
    let z = org_with_owner(&app, "trialco", ago_days(12), 1).await;
    let trial = (ago_days(10), ago_days(10) + 14 * 86_400_000);
    assert_eq!(post_event(&app, &checkout(z, "sub_t", "cus_t")).await, 200);
    for e in [
        event(
            "evt_t1",
            "customer.subscription.created",
            ago_days(10),
            subscription("sub_t", "cus_t", z, 1, trial, "trialing"),
        ),
        event(
            "evt_t2",
            "customer.subscription.trial_will_end",
            ago_days(3),
            subscription("sub_t", "cus_t", z, 1, trial, "trialing"),
        ),
        event("evt_t3", "invoice.payment_failed", ago_days(2), {
            let mut i = invoice(
                "in_t0",
                "sub_t",
                "cus_t",
                z,
                ago_days(2),
                800,
                "subscription_cycle",
                vec![line(
                    800,
                    0,
                    1,
                    (ago_days(2), ago_days(2) + 30 * 86_400_000),
                    false,
                )],
            );
            i["status"] = json!("open");
            i["amount_paid"] = json!(0);
            i
        }),
        event(
            "evt_t4",
            "invoice.paid",
            ago_days(1),
            invoice(
                "in_t1",
                "sub_t",
                "cus_t",
                z,
                ago_days(1),
                800,
                "subscription_cycle",
                vec![line(
                    800,
                    0,
                    1,
                    (ago_days(2), ago_days(2) + 30 * 86_400_000),
                    false,
                )],
            ),
        ),
    ] {
        assert_eq!(post_event(&app, &e).await, 200, "{}", e["id"]);
    }
    let rows = rows_of(&app, z).await;
    let failed = rows
        .iter()
        .find(|r| r.get_str("kind").unwrap() == "invoice_payment_failed")
        .expect("the failed payment");
    assert_eq!(failed.get_i64("amount_cents").unwrap(), 800, "what was due");
    assert!(
        rows.iter()
            .any(|r| r.get_str("kind").unwrap() == "trial_will_end")
    );

    let (s, j) = get_json(&app, "/api/admin/growth/revenue", &token).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(j["billed"]["trial_to_paid"]["trials"], 1);
    assert_eq!(j["billed"]["trial_to_paid"]["converted"], 1);
    assert!(
        j["billed"]["trial_to_paid"]["rate"].get("value").is_none(),
        "no rate below n = 30"
    );
    assert_eq!(j["billed"]["totals"]["payment_failures"], 1);
    assert_eq!(j["billed"]["totals"]["invoices_paid"], 1);
    assert_eq!(org_row(&j, z)["billed_mrr_cents"], 800);
}

// ── Upgrade intent ───────────────────────────────────────────────────────

async fn set_plan(app: &TestApp, tenant_id: &str, plan: &str, mode: &str) {
    app.db
        .collection::<Document>("tenants")
        .update_one(
            doc! { "_id": ObjectId::parse_str(tenant_id).unwrap() },
            doc! { "$set": { "plan": plan, "settings.plan_enforcement": mode } },
        )
        .await
        .unwrap();
}

/// FR-115 made chat unlimited on every plan, so the channel cap these tests
/// used to collide with is gone; storage (1 GiB on Free, a mode-subject
/// count gate) collides instead. Sit the org `headroom` bytes under the
/// quota, the way the gate measures it (`FileDao::sum_storage_for_tenant`).
async fn fill_storage(app: &TestApp, tenant_id: &str, headroom: u64) {
    const GIB: u64 = 1024 * 1024 * 1024;
    app.db
        .collection::<Document>("files")
        .insert_one(doc! {
            "tenant_id": ObjectId::parse_str(tenant_id).unwrap(),
            "filename": "fill.bin",
            "size": (GIB - headroom) as i64,
            "deleted_at": Bson::Null,
        })
        .await
        .unwrap();
}

/// Upload a 13-byte file into the org's first room; the status.
async fn upload_small_file(app: &TestApp, t: &crate::fixtures::seed::SeededTenant) -> u16 {
    let part = reqwest::multipart::Part::bytes(b"Hello, World!".to_vec())
        .file_name("hello.txt")
        .mime_str("text/plain")
        .unwrap();
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("room_id", t.rooms[0].id.clone());
    app.client
        .post(app.url(&format!("/api/tenant/{}/file/upload", t.tenant_id)))
        .header("Authorization", format!("Bearer {}", t.admin.access_token))
        .multipart(form)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// The counter's value for one org and limit, waiting for the spawned write.
async fn collisions(app: &TestApp, tenant: &str, want: i64) -> i64 {
    let filter = doc! {
        "source": QUOTA_SOURCE, "metric": QUOTA_COLLISION_METRIC,
        "dims.tenant": tenant, "dims.limit": "storage_bytes",
    };
    let mut last = 0;
    for _ in 0..50 {
        last = app
            .db
            .collection::<Document>(GROWTH_DAILY)
            .find_one(filter.clone())
            .await
            .unwrap()
            .and_then(|d| d.get_i64("value").ok())
            .unwrap_or(0);
        if last >= want {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    last
}

/// A plan-limit collision is counted per org and limit beside the warn
/// line — let through in `warn`, refused in `enforce`, counted in both —
/// and the revenue view lists the org under the upgrade intent.
#[tokio::test]
async fn quota_collisions_count_per_org_and_limit() {
    let (app, token) = revenue_app(|_| {}).await;
    let t = app.seed_tenant("p4quota").await;
    set_plan(&app, &t.tenant_id, "free", "warn").await;
    // Twenty bytes under Free's 1 GiB: one 13-byte file fits, the next not.
    fill_storage(&app, &t.tenant_id, 20).await;
    let fits = upload_small_file(&app, &t).await;
    assert!((200..300).contains(&fits), "under the cap: {fits}");
    assert_eq!(collisions(&app, &t.tenant_id, 0).await, 0, "under the cap");
    let warn = upload_small_file(&app, &t).await;
    assert!((200..300).contains(&warn), "warn lets it through: {warn}");
    assert_eq!(collisions(&app, &t.tenant_id, 1).await, 1);
    set_plan(&app, &t.tenant_id, "free", "enforce").await;
    let refused = upload_small_file(&app, &t).await;
    assert!(refused >= 400, "enforce refuses: {refused}");
    assert_eq!(collisions(&app, &t.tenant_id, 2).await, 2);

    let row = app
        .db
        .collection::<Document>(GROWTH_DAILY)
        .find_one(doc! { "source": QUOTA_SOURCE, "dims.tenant": &t.tenant_id })
        .await
        .unwrap()
        .unwrap();
    let dims = row.get_document("dims").unwrap();
    assert_eq!(
        dims.len(),
        2,
        "the org and the limit, never a person: {dims}"
    );

    let (s, j) = get_json(&app, "/api/admin/growth/revenue", &token).await;
    assert_eq!(s, 200, "{j}");
    let u = &j["upgrade_intent"];
    assert_eq!((&u["collisions"], &u["orgs"]), (&json!(2), &json!(1)));
    assert_eq!(
        u["by_limit"],
        json!([{ "limit": "storage_bytes", "count": 2 }])
    );
    assert_eq!(u["top"][0]["tenant_id"], t.tenant_id);
    assert_eq!(u["top"][0]["days"], 1);
    assert_eq!(u["top"][0]["plan"], "free");
    let o = org_row(&j, ObjectId::parse_str(&t.tenant_id).unwrap());
    assert_eq!(o["collisions"], 2);
    assert!(o["billed_mrr_cents"].is_null(), "no invoice: null, not 0");
    // Nothing billed anywhere: billed revenue says so, never "0 MRR".
    assert!(
        j["billed"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("no billing event on record"),
        "{}",
        j["billed"]
    );
}

/// With the growth surface off, a collision still refuses or warns as
/// FR-32 decides — and nothing is counted.
#[tokio::test]
async fn no_collision_is_counted_with_growth_off() {
    let (app, _token) = revenue_app(|s| s.growth.enabled = false).await;
    let t = app.seed_tenant("p4quotaoff").await;
    set_plan(&app, &t.tenant_id, "free", "warn").await;
    // Over the storage cap, so every upload collides (the same collision
    // the test above counts with growth on) — and with growth off, none is
    // counted. Without a real collision this absence would prove nothing.
    fill_storage(&app, &t.tenant_id, 5).await;
    for _ in 0..2 {
        let s = upload_small_file(&app, &t).await;
        assert!((200..300).contains(&s), "warn lets it through: {s}");
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let n = app
        .db
        .collection::<Document>(GROWTH_DAILY)
        .count_documents(doc! { "source": QUOTA_SOURCE })
        .await
        .unwrap();
    assert_eq!(n, 0);
}

// ── The backfill ─────────────────────────────────────────────────────────

/// A fake Stripe: `GET /v1/invoices`, two pages, basic-auth checked.
async fn fake_stripe(pages: Vec<Value>, calls: Arc<AtomicUsize>) -> String {
    let pages = Arc::new(pages);
    let app = Router::new().route(
        "/v1/invoices",
        get(
            move |headers: HeaderMap,
                  Query(q): Query<std::collections::HashMap<String, String>>| {
                let pages = pages.clone();
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    if !auth.starts_with("Basic ")
                        || q.get("status").map(String::as_str) != Some("paid")
                    {
                        return axum::Json(json!({ "error": { "message": "bad request" } }));
                    }
                    let page = if q.contains_key("starting_after") {
                        1
                    } else {
                        0
                    };
                    axum::Json(pages[page].clone())
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// The operator's backfill reads Stripe's paid invoices into
/// `billing_events` once: one already recorded by the webhook and one
/// naming no org here are counted, not recorded; a second run records
/// nothing; the run leaves its marker; the closed months it touched
/// refreeze.
#[tokio::test]
async fn the_backfill_reads_stripe_once() {
    let (app, token) = revenue_app(|_| {}).await;
    let w = org_with_owner(&app, "backfilled", at(4, 1), 2).await;
    assert_eq!(post_event(&app, &checkout(w, "sub_w", "cus_w")).await, 200);
    let p_old = (at(3, 3), at(2, 3));
    let p_new = (at(2, 3), at(1, 3));
    let inv_old = invoice(
        "in_w_old",
        "sub_w",
        "cus_w",
        w,
        at(3, 3),
        1600,
        "subscription_create",
        vec![line(1600, 0, 2, p_old, false)],
    );
    let inv_new = invoice(
        "in_w_new",
        "sub_w",
        "cus_w",
        w,
        at(2, 3),
        1600,
        "subscription_cycle",
        vec![line(1600, 0, 2, p_new, false)],
    );
    // The webhook saw the newer one.
    assert_eq!(
        post_event(
            &app,
            &event("evt_w1", "invoice.paid", at(2, 3), inv_new.clone())
        )
        .await,
        200
    );
    let mut stranger = invoice(
        "in_nobody",
        "sub_nobody",
        "cus_nobody",
        ObjectId::new(),
        at(2, 10),
        999,
        "subscription_create",
        vec![line(999, 0, 1, p_new, false)],
    );
    stranger["subscription_details"] = json!({ "metadata": {} });
    let pages = vec![
        json!({ "object": "list", "data": [inv_new, inv_old], "has_more": true }),
        json!({ "object": "list", "data": [stranger], "has_more": false }),
    ];
    let calls = Arc::new(AtomicUsize::new(0));
    let base = fake_stripe(pages, calls.clone()).await;
    let stripe = StripeService::new(&meshharbor_config::StripeSettings {
        secret_key: "sk_test_fake".into(),
        webhook_secret: SECRET.into(),
        price_pro: PRICE_PRO.into(),
        price_business: PRICE_BIZ.into(),
        ..Default::default()
    });

    assert!(billing::last_backfill(&app.db).await.unwrap().is_none());
    let now = DateTime::now();
    let r = stripe
        .backfill_paid_invoices(&app.db, &base, None, now)
        .await
        .unwrap();
    assert_eq!(
        (
            r.pages,
            r.invoices,
            r.recorded,
            r.already,
            r.no_org,
            r.truncated
        ),
        (2, 3, 1, 1, 1, false),
        "{r:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(r.months.contains(&label(month_start(3))), "{:?}", r.months);
    let rows = rows_of(&app, w).await;
    assert_eq!(rows.len(), 2);
    let old = rows
        .iter()
        .find(|d| d.get_str("stripe_id").unwrap() == "in_w_old")
        .unwrap();
    assert_eq!(old.get_str("source").unwrap(), "backfill");
    assert!(
        old.get("event_id").is_none(),
        "a backfilled row has no event id"
    );
    assert!(
        app.db
            .collection::<Document>(BILLING_EVENTS)
            .find_one(doc! { "stripe_id": "in_nobody" })
            .await
            .unwrap()
            .is_none(),
        "an invoice naming no org here is not recorded"
    );

    let again = stripe
        .backfill_paid_invoices(&app.db, &base, None, now)
        .await
        .unwrap();
    assert_eq!((again.recorded, again.already, again.no_org), (0, 2, 1));
    assert!(billing::last_backfill(&app.db).await.unwrap().is_some());

    // The closed months it touched refreeze; the view says it ran.
    let refrozen = meshharbor_mod_saas::stripe::refreeze(&app.state.core, &r.months, now)
        .await
        .unwrap();
    assert!(refrozen.contains(&label(month_start(3))), "{refrozen:?}");
    let (s, j) = get_json(&app, "/api/admin/growth/revenue", &token).await;
    assert_eq!(s, 200, "{j}");
    assert!(j["billed"]["record"]["backfilled_at"].is_string());
    let m3 = month(&j, &label(month_start(3)));
    assert_eq!(m3["frozen"], true);
    assert_eq!(eur(m3).unwrap()["new_cents"], 1600);
}

/// Production's first backfill (2026-10-17): Stripe's only paid invoice
/// names no org on this server, so the run records nothing and billed stays
/// `not_measured` — and both the panel and the digest now say the backfill
/// RAN, on its day, where the fixed reason went on saying it "has not run".
#[tokio::test]
async fn a_backfill_that_records_nothing_says_it_ran() {
    let (app, token) = revenue_app(|_| {}).await;
    let yesterday = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
    let digest = format!(
        "/api/admin/growth/digest/preview?day={}",
        yesterday.format("%Y-%m-%d")
    );
    let reasons = |j: &Value, d: &Value| {
        (
            j["billed"]["not_measured"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            d["sections"]["revenue"]["billed"]["not_measured"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    };
    let (s, j) = get_json(&app, "/api/admin/growth/revenue", &token).await;
    assert_eq!(s, 200, "{j}");
    let (s, d) = get_json(&app, &digest, &token).await;
    assert_eq!(s, 200, "{d}");
    let (panel, daily) = reasons(&j, &d);
    for before in [panel, daily] {
        assert!(before.contains("the backfill has not run"), "{before}");
    }

    let period = (at(1, 10), at(0, 1));
    let mut stranger = invoice(
        "in_nobody",
        "sub_nobody",
        "cus_nobody",
        ObjectId::new(),
        at(1, 10),
        999,
        "subscription_create",
        vec![line(999, 0, 1, period, false)],
    );
    stranger["subscription_details"] = json!({ "metadata": {} });
    let pages = vec![json!({ "object": "list", "data": [stranger], "has_more": false })];
    let base = fake_stripe(pages, Arc::new(AtomicUsize::new(0))).await;
    let stripe = StripeService::new(&meshharbor_config::StripeSettings {
        secret_key: "sk_test_fake".into(),
        webhook_secret: SECRET.into(),
        price_pro: PRICE_PRO.into(),
        price_business: PRICE_BIZ.into(),
        ..Default::default()
    });
    let now = DateTime::now();
    let r = stripe
        .backfill_paid_invoices(&app.db, &base, None, now)
        .await
        .unwrap();
    assert_eq!((r.invoices, r.recorded, r.no_org), (1, 0, 1), "{r:?}");

    let ran_on = now.try_to_rfc3339_string().unwrap()[..10].to_string();
    let (s, j) = get_json(&app, "/api/admin/growth/revenue", &token).await;
    assert_eq!(s, 200, "{j}");
    let (s, d) = get_json(&app, &digest, &token).await;
    assert_eq!(s, 200, "{d}");
    let (panel, daily) = reasons(&j, &d);
    for after in [panel, daily] {
        assert!(!after.contains("has not run"), "{after}");
        assert!(
            after.contains(&format!(
                "the backfill on {ran_on} recorded no paid invoice"
            )),
            "{after}"
        );
    }
}

// ── The routes ───────────────────────────────────────────────────────────

/// 404 to everyone but a platform admin, and to the admin with growth off;
/// a bad range is a 400; without `saas` billed is `not_measured` with the
/// module named; the backfill route refuses without a Stripe key.
#[tokio::test]
async fn the_routes_hide_and_degrade() {
    let (app, token) = revenue_app(|_| {}).await;
    let t = app.seed_tenant("p4plain").await;
    for path in [
        "/api/admin/growth/revenue",
        "/api/admin/growth/revenue?since=2026-01",
    ] {
        let (s, _) = get_json(&app, path, &t.admin.access_token).await;
        assert_eq!(s, 404, "a tenant admin is not a platform admin: {path}");
    }
    let r = app
        .auth_post("/api/admin/growth/billing/backfill", &t.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    for bad in [
        "since=2026-13",
        "since=2026-1",
        "until=2999-01",
        "since=2019-12",
        "since=2026-05&until=2026-04",
    ] {
        let (s, j) = get_json(&app, &format!("/api/admin/growth/revenue?{bad}"), &token).await;
        assert_eq!(s, 400, "{bad}: {j}");
    }
    // No Stripe key configured: the backfill says so (never reaching Stripe).
    let r = app
        .auth_post("/api/admin/growth/billing/backfill", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    assert!(r.text().await.unwrap().contains("no Stripe secret key"));
    let r = app
        .auth_post("/api/admin/growth/billing/backfill?since=yesterday", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    let (off, off_token) = revenue_app(|s| s.growth.enabled = false).await;
    let (s, _) = get_json(&off, "/api/admin/growth/revenue", &off_token).await;
    assert_eq!(s, 404, "growth off");
    let r = off
        .auth_post("/api/admin/growth/billing/backfill", &off_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    let (bare, bare_token) = revenue_app(|s| s.modules.saas = false).await;
    let (s, j) = get_json(&bare, "/api/admin/growth/revenue", &bare_token).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(j["billed"]["not_measured"], "saas module not mounted");
    assert!(
        j["upgrade_intent"]["collisions"].is_number(),
        "core's, read anyway"
    );
    let (s, f) = get_json(&bare, "/api/admin/growth/funnel", &bare_token).await;
    assert_eq!(s, 200, "{f}");
    assert!(f["steps"]["paid"].is_null());
    assert_eq!(f["not_measured"]["paid"], "saas module not mounted");
}
