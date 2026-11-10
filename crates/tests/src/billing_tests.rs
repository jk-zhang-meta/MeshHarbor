// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use crate::fixtures::test_app::TestApp;
use serde_json::Value;

// ---------------------------------------------------------------------------
// GET /api/stripe/plans — public endpoint, no auth needed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_plans_returns_three_plans() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .get(app.url("/api/stripe/plans"))
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, 200, "GET /api/stripe/plans failed: {}", body);

    let plans: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(plans.len(), 3, "Expected 3 plans (Free, Pro, Business)");
}

#[tokio::test]
async fn get_plans_free_plan_has_correct_data() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .get(app.url("/api/stripe/plans"))
        .send()
        .await
        .unwrap();

    let plans: Vec<Value> = resp.json().await.unwrap();
    let free = plans
        .iter()
        .find(|p| p["id"] == "free")
        .expect("Free plan not found");

    assert_eq!(free["name"], "Free");
    assert_eq!(free["price_cents"], 0);
    // FR-115 — commercial use allowed, said by the plan itself.
    assert_eq!(free["commercial_use"], true);
    assert_eq!(free["per_seat"], false);
    assert_eq!(free["features"][0], "Free for commercial use");
    assert_eq!(free["limits"]["max_members"], 10);
    assert_eq!(free["limits"]["max_channels"], u64::from(u32::MAX));
    assert_eq!(free["limits"]["max_message_history"], -1);
    assert_eq!(free["limits"]["video_max_participants"], 10);
    assert_eq!(free["limits"]["meeting_max_minutes"], 60);
    assert_eq!(free["limits"]["cloud_integrations"], false);
    assert_eq!(free["limits"]["recordings"], false);
    assert_eq!(free["limits"]["storage_bytes"], 1024_u64 * 1024 * 1024);
    // FR-115 — the network is given away: 100 devices, MagicDNS.
    assert_eq!(free["limits"]["max_devices"], 100);
    assert_eq!(free["limits"]["max_tunnel_clients"], 100);
    assert_eq!(free["limits"]["overlay_mesh"], true);
    assert_eq!(free["limits"]["exit_nodes"], false);
    assert_eq!(free["limits"]["magic_dns"], true);
    assert_eq!(free["limits"]["max_concurrent_sessions"], 1);
    assert_eq!(free["limits"]["relay_bytes_per_month"], 10_000_000_000_u64);
    // Monthly only (no annual Prices configured on a test server), in the
    // currencies on sale, zero.
    let prices = free["prices"].as_array().unwrap();
    assert!(prices.iter().all(|p| p["unit_amount"] == 0));
    // Free's `year` entry alone put an Annual toggle on the billing page.
    assert!(
        prices.iter().all(|p| p["interval"] == "month"),
        "Free lists a year while nothing is sold annually: {prices:?}"
    );
}

#[tokio::test]
async fn get_plans_pro_plan_has_correct_data() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .get(app.url("/api/stripe/plans"))
        .send()
        .await
        .unwrap();

    let plans: Vec<Value> = resp.json().await.unwrap();
    let pro = plans
        .iter()
        .find(|p| p["id"] == "pro")
        .expect("Pro plan not found");

    assert_eq!(pro["name"], "Pro");
    assert_eq!(pro["price_cents"], 800);
    // FR-115 — per seat; one seat's numbers are what the plan publishes.
    assert_eq!(pro["per_seat"], true);
    assert_eq!(pro["limits"]["per_seat"], true);
    assert_eq!(pro["limits"]["video_max_participants"], 50);
    assert_eq!(pro["limits"]["meeting_max_minutes"], u64::from(u32::MAX));
    assert_eq!(pro["limits"]["cloud_integrations"], true);
    assert_eq!(pro["limits"]["recordings"], false);
    assert_eq!(pro["limits"]["max_devices"], 1000);
    assert_eq!(pro["limits"]["max_tunnel_clients"], 1000);
    assert_eq!(pro["limits"]["exit_nodes"], true);
    assert_eq!(pro["limits"]["magic_dns"], true);
    assert_eq!(pro["limits"]["max_concurrent_sessions"], 1);
    assert_eq!(pro["limits"]["relay_bytes_per_month"], 25_000_000_000_u64);
    assert_eq!(pro["limits"]["storage_bytes"], 10 * 1024_u64 * 1024 * 1024);
    let prices = pro["prices"].as_array().unwrap();
    assert!(
        prices
            .iter()
            .any(|p| p["interval"] == "month" && p["currency"] == "usd" && p["unit_amount"] == 800),
        "usd monthly price missing: {prices:?}"
    );
    // The deployed default sells USD alone (`stripe.currencies`): EUR waits
    // until the live Prices carry it. The fake-Stripe tests below put both on
    // sale, as the operator will after O1.
    assert!(
        prices.iter().all(|p| p["currency"] == "usd"),
        "EUR is not on sale by default: {prices:?}"
    );
    assert!(
        prices.iter().all(|p| p["interval"] == "month"),
        "annual is offered only once its Prices are configured: {prices:?}"
    );
}

#[tokio::test]
async fn get_plans_business_plan_has_correct_data() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .get(app.url("/api/stripe/plans"))
        .send()
        .await
        .unwrap();

    let plans: Vec<Value> = resp.json().await.unwrap();
    let biz = plans
        .iter()
        .find(|p| p["id"] == "business")
        .expect("Business plan not found");

    assert_eq!(biz["name"], "Business");
    assert_eq!(biz["price_cents"], 1600);
    assert_eq!(biz["per_seat"], true);
    assert_eq!(biz["limits"]["video_max_participants"], 100);
    assert_eq!(biz["limits"]["cloud_integrations"], true);
    assert_eq!(biz["limits"]["recordings"], true);
    assert_eq!(biz["limits"]["max_devices"], 5000);
    assert_eq!(biz["limits"]["max_tunnel_clients"], 5000);
    assert_eq!(biz["limits"]["exit_nodes"], true);
    assert_eq!(biz["limits"]["magic_dns"], true);
    assert_eq!(
        biz["limits"]["max_concurrent_sessions"],
        u64::from(u32::MAX)
    );
    assert_eq!(biz["limits"]["relay_bytes_per_month"], 100_000_000_000_u64);
    // AI recognition was deleted in FR-32 and must not be sold.
    assert!(
        biz["features"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| !f.as_str().unwrap_or_default().contains("AI"))
    );
}

// ---------------------------------------------------------------------------
// Tenant default plan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn new_tenant_defaults_to_free_plan() {
    let app = TestApp::spawn().await;

    let seeded = app.seed_tenant("billing-default").await;

    // Read the tenant directly from the database
    use bson::{doc, oid::ObjectId};
    let tenant_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let tenant: bson::Document = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! { "_id": tenant_oid })
        .await
        .unwrap()
        .expect("Tenant not found in DB");

    assert_eq!(tenant.get_str("plan").unwrap(), "free");
}

#[tokio::test]
async fn new_tenant_has_no_billing_info() {
    let app = TestApp::spawn().await;

    let seeded = app.seed_tenant("billing-none").await;

    use bson::{doc, oid::ObjectId};
    let tenant_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let tenant: bson::Document = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! { "_id": tenant_oid })
        .await
        .unwrap()
        .expect("Tenant not found in DB");

    // billing should be null/absent for new tenants on free plan
    let billing = tenant.get("billing");
    assert!(
        billing.is_none() || billing == Some(&bson::Bson::Null),
        "New tenant should have no billing info"
    );
}

// ---------------------------------------------------------------------------
// POST /api/stripe/checkout — authentication & authorization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn checkout_requires_authentication() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("checkout-auth").await;

    let resp = app
        .client
        .post(app.url("/api/stripe/checkout"))
        .json(&serde_json::json!({
            "tenant_id": seeded.tenant_id,
            "plan": "pro",
            "success_url": "http://localhost/success",
            "cancel_url": "http://localhost/cancel",
        }))
        .send()
        .await
        .unwrap();

    // Without auth, the server may return 401 or 403 depending on middleware ordering
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "Expected 401 or 403, got {status}"
    );
}

#[tokio::test]
async fn checkout_rejects_invalid_plan() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("checkout-invalid-plan").await;

    let resp = app
        .auth_post("/api/stripe/checkout", &seeded.admin.access_token)
        .json(&serde_json::json!({
            "tenant_id": seeded.tenant_id,
            "plan": "nonexistent_plan",
            "success_url": "http://localhost/success",
            "cancel_url": "http://localhost/cancel",
        }))
        .send()
        .await
        .unwrap();

    // With empty Stripe keys (test env), the customer creation call fires first
    // and returns a Stripe API error (500). With real test keys, this would be 400
    // for invalid plan. Either way, it should not succeed.
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 500,
        "Expected 400 or 500 for invalid plan, got {status}"
    );
}

#[tokio::test]
async fn checkout_rejects_non_owner() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("checkout-forbidden").await;

    // The member (non-owner) should not be able to create a checkout session
    let resp = app
        .auth_post("/api/stripe/checkout", &seeded.member.access_token)
        .json(&serde_json::json!({
            "tenant_id": seeded.tenant_id,
            "plan": "pro",
            "success_url": "http://localhost/success",
            "cancel_url": "http://localhost/cancel",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// POST /api/stripe/portal — authentication & authorization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn portal_requires_authentication() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("portal-auth").await;

    let resp = app
        .client
        .post(app.url("/api/stripe/portal"))
        .json(&serde_json::json!({
            "tenant_id": seeded.tenant_id,
            "return_url": "http://localhost/billing",
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "Expected 401 or 403, got {status}"
    );
}

#[tokio::test]
async fn portal_fails_without_billing_account() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("portal-no-billing").await;

    // Free plan tenant has no customer_id, so portal should fail
    let resp = app
        .auth_post("/api/stripe/portal", &seeded.admin.access_token)
        .json(&serde_json::json!({
            "tenant_id": seeded.tenant_id,
            "return_url": "http://localhost/billing",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// POST /api/stripe/webhook — signature verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_rejects_missing_signature_header() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .post(app.url("/api/stripe/webhook"))
        .header("Content-Type", "application/json")
        .body(r#"{"type":"checkout.session.completed","data":{"object":{}}}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn webhook_rejects_invalid_signature() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .post(app.url("/api/stripe/webhook"))
        .header("Content-Type", "application/json")
        .header("stripe-signature", "t=1234567890,v1=invalidsignature")
        .body(r#"{"type":"checkout.session.completed","data":{"object":{}}}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn webhook_with_valid_signature_processes_checkout_completed() {
    let app = TestApp::spawn_with_settings(|s| {
        s.stripe.webhook_secret = "whsec_test_secret_for_billing_tests".to_string();
    })
    .await;

    let seeded = app.seed_tenant("webhook-checkout").await;

    // Build the webhook payload
    let payload = serde_json::json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "metadata": {
                    "tenant_id": seeded.tenant_id,
                    "plan": "pro",
                },
                "subscription": "sub_test_123",
                "customer": "cus_test_456",
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Compute valid HMAC-SHA256 signature
    let timestamp = now_ts();
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&payload_bytes));
    let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);
    let sig_header = format!("t={},v1={}", timestamp, sig);

    let resp = app
        .client
        .post(app.url("/api/stripe/webhook"))
        .header("Content-Type", "application/json")
        .header("stripe-signature", &sig_header)
        .body(payload_bytes)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    // Verify tenant was upgraded to Pro in the database
    use bson::{doc, oid::ObjectId};
    let tenant_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let tenant: bson::Document = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! { "_id": tenant_oid })
        .await
        .unwrap()
        .expect("Tenant not found in DB");

    assert_eq!(tenant.get_str("plan").unwrap(), "pro");

    // Verify billing info was set
    let billing = tenant
        .get_document("billing")
        .expect("billing should exist");
    assert_eq!(billing.get_str("customer_id").unwrap(), "cus_test_456");
    assert_eq!(billing.get_str("subscription_id").unwrap(), "sub_test_123");
    assert_eq!(billing.get_str("status").unwrap(), "active");
    assert!(!billing.get_bool("cancel_at_period_end").unwrap());
}

#[tokio::test]
async fn webhook_subscription_deleted_reverts_to_free() {
    let app = TestApp::spawn_with_settings(|s| {
        s.stripe.webhook_secret = "whsec_test_secret_for_billing_tests".to_string();
    })
    .await;

    let seeded = app.seed_tenant("webhook-delete").await;

    // First, simulate a checkout.session.completed to set up billing
    {
        let payload = serde_json::json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "metadata": {
                        "tenant_id": seeded.tenant_id,
                        "plan": "business",
                    },
                    "subscription": "sub_del_123",
                    "customer": "cus_del_456",
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = now_ts();
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&payload_bytes));
        let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);
        let sig_header = format!("t={},v1={}", timestamp, sig);

        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", &sig_header)
            .body(payload_bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Now send customer.subscription.deleted
    {
        let payload = serde_json::json!({
            "type": "customer.subscription.deleted",
            "data": {
                "object": {
                    "id": "sub_del_123",
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = now_ts();
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&payload_bytes));
        let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);
        let sig_header = format!("t={},v1={}", timestamp, sig);

        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", &sig_header)
            .body(payload_bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Verify tenant was reverted to Free plan
    use bson::{doc, oid::ObjectId};
    let tenant_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let tenant: bson::Document = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! { "_id": tenant_oid })
        .await
        .unwrap()
        .expect("Tenant not found in DB");

    assert_eq!(tenant.get_str("plan").unwrap(), "free");
    let billing = tenant
        .get_document("billing")
        .expect("billing should exist");
    assert_eq!(billing.get_str("status").unwrap(), "canceled");
}

#[tokio::test]
async fn webhook_subscription_updated_sets_status() {
    let app = TestApp::spawn_with_settings(|s| {
        s.stripe.webhook_secret = "whsec_test_secret_for_billing_tests".to_string();
    })
    .await;

    let seeded = app.seed_tenant("webhook-update").await;

    // Set up billing via checkout.session.completed
    {
        let payload = serde_json::json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "metadata": {
                        "tenant_id": seeded.tenant_id,
                        "plan": "pro",
                    },
                    "subscription": "sub_upd_123",
                    "customer": "cus_upd_456",
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = now_ts();
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&payload_bytes));
        let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);
        let sig_header = format!("t={},v1={}", timestamp, sig);

        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", &sig_header)
            .body(payload_bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Send customer.subscription.updated with cancel_at_period_end = true
    {
        let payload = serde_json::json!({
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_upd_123",
                    "status": "active",
                    "cancel_at_period_end": true,
                    "current_period_end": 1700000000,
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = now_ts();
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&payload_bytes));
        let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);
        let sig_header = format!("t={},v1={}", timestamp, sig);

        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", &sig_header)
            .body(payload_bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Verify billing info was updated
    use bson::{doc, oid::ObjectId};
    let tenant_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let tenant: bson::Document = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! { "_id": tenant_oid })
        .await
        .unwrap()
        .expect("Tenant not found in DB");

    let billing = tenant
        .get_document("billing")
        .expect("billing should exist");
    assert_eq!(billing.get_str("status").unwrap(), "active");
    assert!(billing.get_bool("cancel_at_period_end").unwrap());
}

#[tokio::test]
async fn webhook_invoice_payment_failed_sets_past_due() {
    let app = TestApp::spawn_with_settings(|s| {
        s.stripe.webhook_secret = "whsec_test_secret_for_billing_tests".to_string();
    })
    .await;

    let seeded = app.seed_tenant("webhook-pastdue").await;

    // Set up billing first
    {
        let payload = serde_json::json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "metadata": {
                        "tenant_id": seeded.tenant_id,
                        "plan": "pro",
                    },
                    "subscription": "sub_pd_123",
                    "customer": "cus_pd_456",
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = now_ts();
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&payload_bytes));
        let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);
        let sig_header = format!("t={},v1={}", timestamp, sig);

        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", &sig_header)
            .body(payload_bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Send invoice.payment_failed
    {
        let payload = serde_json::json!({
            "type": "invoice.payment_failed",
            "data": {
                "object": {
                    "subscription": "sub_pd_123",
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = now_ts();
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&payload_bytes));
        let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);
        let sig_header = format!("t={},v1={}", timestamp, sig);

        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", &sig_header)
            .body(payload_bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Verify billing status is now past_due
    use bson::{doc, oid::ObjectId};
    let tenant_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let tenant: bson::Document = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! { "_id": tenant_oid })
        .await
        .unwrap()
        .expect("Tenant not found in DB");

    let billing = tenant
        .get_document("billing")
        .expect("billing should exist");
    assert_eq!(billing.get_str("status").unwrap(), "past_due");
}

// ---------------------------------------------------------------------------
// Helper: compute HMAC-SHA256 hex digest
// ---------------------------------------------------------------------------

/// Current unix seconds as a string — webhook signatures must carry a
/// timestamp inside the S5 replay window (±300 s), so the old hardcoded
/// `"1234567890"` would be rejected as a replay.
fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

fn compute_hmac_sha256(secret: &str, message: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// S5 — webhook hardening: replay window + event-id dedup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_rejects_replayed_signature_outside_tolerance() {
    let app = TestApp::spawn_with_settings(|s| {
        s.stripe.webhook_secret = "whsec_test_secret_for_billing_tests".to_string();
    })
    .await;
    let seeded = app.seed_tenant("webhook-replay").await;

    let payload = serde_json::json!({
        "type": "checkout.session.completed",
        "data": { "object": {
            "metadata": { "tenant_id": seeded.tenant_id, "plan": "pro" },
            "subscription": "sub_replay", "customer": "cus_replay",
        }}
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // A VALID HMAC over an hour-old timestamp — must be rejected as a
    // replay even though the signature itself checks out.
    let old_ts = (now_ts().parse::<i64>().unwrap() - 3600).to_string();
    let signed_payload = format!("{}.{}", old_ts, String::from_utf8_lossy(&payload_bytes));
    let sig = compute_hmac_sha256("whsec_test_secret_for_billing_tests", &signed_payload);

    let resp = app
        .client
        .post(app.url("/api/stripe/webhook"))
        .header("Content-Type", "application/json")
        .header("stripe-signature", format!("t={old_ts},v1={sig}"))
        .body(payload_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn webhook_duplicate_event_id_is_processed_once() {
    let app = TestApp::spawn_with_settings(|s| {
        s.stripe.webhook_secret = "whsec_test_secret_for_billing_tests".to_string();
    })
    .await;
    let seeded = app.seed_tenant("webhook-dedup").await;

    let send_event = |plan: &str| {
        let payload = serde_json::json!({
            "id": "evt_s5_dedup_test",
            "type": "checkout.session.completed",
            "data": { "object": {
                "metadata": { "tenant_id": seeded.tenant_id, "plan": plan },
                "subscription": "sub_dedup", "customer": "cus_dedup",
            }}
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let ts = now_ts();
        let sig = compute_hmac_sha256(
            "whsec_test_secret_for_billing_tests",
            &format!("{}.{}", ts, String::from_utf8_lossy(&bytes)),
        );
        (bytes, format!("t={ts},v1={sig}"))
    };

    // First delivery upgrades to Pro.
    let (bytes, header) = send_event("pro");
    let resp = app
        .client
        .post(app.url("/api/stripe/webhook"))
        .header("Content-Type", "application/json")
        .header("stripe-signature", header)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Second delivery reuses the SAME event id (Stripe retry) but claims
    // a different plan — it must be acknowledged (200, so Stripe stops
    // retrying) yet NOT re-processed.
    let (bytes, header) = send_event("business");
    let resp = app
        .client
        .post(app.url("/api/stripe/webhook"))
        .header("Content-Type", "application/json")
        .header("stripe-signature", header)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    use bson::{doc, oid::ObjectId};
    let tenant_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let tenant: bson::Document = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! { "_id": tenant_oid })
        .await
        .unwrap()
        .expect("tenant");
    assert_eq!(
        tenant.get_str("plan").unwrap(),
        "pro",
        "duplicate event id must not re-process (plan stayed from the first delivery)"
    );
}

// ---------------------------------------------------------------------------
// S5 — plan caps enforced at enrollment (Free: 3 devices, 3 tunnel clients)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_enroll_enforces_free_plan_device_cap() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("device-cap").await;

    let enroll = |machine: String| {
        let app = &app;
        let seeded = &seeded;
        async move {
            let et: Value = app
                .auth_post(
                    &format!("/api/tenant/{}/agent/enroll-token", seeded.tenant_id),
                    &seeded.admin.access_token,
                )
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            app.client
                .post(app.url("/api/agent/enroll"))
                .json(&serde_json::json!({
                    "enrollment_token": et["enrollment_token"],
                    "machine_id": machine,
                    "machine_name": format!("{machine}-name"),
                    "os": "linux",
                    "agent_version": "0.0.0-test",
                }))
                .send()
                .await
                .unwrap()
        }
    };

    // FR-115 — Free allows 100 devices. One real enrollment, then the tenant
    // is seeded to 99 directly (enrolling 100 for real would make this the
    // slowest test in the suite for no extra coverage), then the 100th
    // enrolls and the 101st is refused.
    let resp = enroll("cap-mach-1".to_string()).await;
    assert_eq!(resp.status().as_u16(), 200, "device 1 should enroll");
    seed_rows(&app, "agents", &seeded.tenant_id, "cap-seed", 98).await;
    let resp = enroll("cap-mach-100".to_string()).await;
    assert_eq!(resp.status().as_u16(), 200, "device 100 should enroll");

    // The 101st NEW machine is over the cap.
    let resp = enroll("cap-mach-101".to_string()).await;
    assert_eq!(resp.status().as_u16(), 403, "101st device must hit the cap");
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("Device limit"),
        "cap error should name the limit: {body}"
    );

    // Re-enrolling a KNOWN machine rehydrates in place — never capped.
    let resp = enroll("cap-mach-1".to_string()).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "re-enrolling an existing machine must not consume a slot"
    );
}

#[tokio::test]
async fn tunnel_enroll_enforces_free_plan_cap() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tunnel-cap").await;

    let enroll = |machine: String| {
        let app = &app;
        let seeded = &seeded;
        async move {
            let et: Value = app
                .auth_post(
                    &format!(
                        "/api/tenant/{}/tunnel-client/enroll-token",
                        seeded.tenant_id
                    ),
                    &seeded.admin.access_token,
                )
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            app.client
                .post(app.url("/api/tunnel-client/enroll"))
                .json(&serde_json::json!({
                    "enrollment_token": et["enrollment_token"],
                    "machine_id": machine,
                    "machine_name": format!("{machine}-name"),
                    "os": "linux",
                    "client_version": "0.0.0-test",
                }))
                .send()
                .await
                .unwrap()
        }
    };

    // FR-115 — Free allows 100 tunnel clients: two real, 98 seeded, then the
    // 101st is refused.
    for i in 1..=2 {
        let resp = enroll(format!("tcap-mach-{i}")).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "tunnel client {i} should enroll"
        );
    }
    seed_rows(&app, "tunnel_clients", &seeded.tenant_id, "tcap-seed", 98).await;
    let resp = enroll("tcap-mach-101".to_string()).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "101st tunnel client must hit the cap"
    );
    let resp = enroll("tcap-mach-2".to_string()).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "re-enroll rehydrates, never capped"
    );
}

/// Insert `n` live device-shaped rows (`agents` or `tunnel_clients`) for a
/// tenant — what a count gate reads — without enrolling each one.
async fn seed_rows(app: &TestApp, collection: &str, tenant_id: &str, prefix: &str, n: usize) {
    use bson::{Bson, doc, oid::ObjectId};
    let tid = ObjectId::parse_str(tenant_id).unwrap();
    let now = bson::DateTime::now();
    let docs: Vec<bson::Document> = (0..n)
        .map(|i| {
            doc! {
                "tenant_id": tid,
                "machine_id": format!("{prefix}-{i}"),
                "name": format!("{prefix}-{i}"),
                "created_at": now,
                "updated_at": now,
                "deleted_at": Bson::Null,
            }
        })
        .collect();
    app.db
        .collection::<bson::Document>(collection)
        .insert_many(docs)
        .await
        .expect("seeding rows failed");
}

// ---------------------------------------------------------------------------
// FR-115 — per-seat billing, against a fake Stripe that records every call
// ---------------------------------------------------------------------------

mod fr115 {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        extract::{Form, Path, State},
        routing::{get, post},
    };
    use bson::{Bson, doc, oid::ObjectId};
    use meshharbor_services::stripe::StripeService;

    const SECRET: &str = "whsec_test_secret_for_billing_tests";
    const PRICE_PRO: &str = "price_fr115_pro_month";
    const PRICE_BIZ: &str = "price_fr115_biz_month";
    const PRICE_PRO_YEAR: &str = "price_fr115_pro_year";
    const PRICE_BIZ_YEAR: &str = "price_fr115_biz_year";

    /// One request the fake received: method, path, form fields.
    #[derive(Debug, Clone)]
    struct Call {
        method: &'static str,
        path: String,
        form: Vec<(String, String)>,
    }

    impl Call {
        fn field(&self, k: &str) -> Option<&str> {
            self.form
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        }
    }

    #[derive(Clone, Default)]
    struct Fake {
        calls: Arc<Mutex<Vec<Call>>>,
        /// The subscription's item: (price, quantity).
        item: Arc<Mutex<(String, u32)>>,
        /// FR-115 — the currencies every Price is sold in; `None` = USD and
        /// EUR, the shape the live Prices take once their EUR option exists.
        currencies: Arc<Mutex<Option<Vec<String>>>>,
    }

    impl Fake {
        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
        fn record(&self, method: &'static str, path: String, form: Vec<(String, String)>) {
            self.calls.lock().unwrap().push(Call { method, path, form });
        }
        fn subscription(&self, id: &str) -> serde_json::Value {
            let (price, quantity) = self.item.lock().unwrap().clone();
            serde_json::json!({
                "id": id, "object": "subscription", "status": "active",
                "customer": "cus_fake", "currency": "eur",
                "cancel_at_period_end": false,
                "items": { "data": [ {
                    "id": "si_fake", "quantity": quantity,
                    "price": { "id": price, "recurring": { "interval": "month" } },
                    "current_period_end": 1_900_000_000,
                } ] },
            })
        }
    }

    /// A Stripe that answers the calls FR-115 makes and records each one.
    async fn fake_stripe(fake: Fake) -> String {
        let app = Router::new()
            .route(
                "/v1/prices/{id}",
                get(|State(f): State<Fake>, Path(id): Path<String>| async move {
                    f.record("GET", format!("/v1/prices/{id}"), vec![]);
                    let currencies = f
                        .currencies
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| vec!["usd".into(), "eur".into()]);
                    let options: serde_json::Map<String, serde_json::Value> = currencies
                        .iter()
                        .map(|c| (c.clone(), serde_json::json!({ "unit_amount": 800 })))
                        .collect();
                    axum::Json(serde_json::json!({
                        "id": id, "object": "price", "currency": currencies[0],
                        "currency_options": options,
                    }))
                }),
            )
            .route(
                "/v1/customers",
                post(|State(f): State<Fake>, Form(form): Form<Vec<(String, String)>>| async move {
                    f.record("POST", "/v1/customers".into(), form);
                    axum::Json(serde_json::json!({ "id": "cus_fake" }))
                }),
            )
            .route(
                "/v1/checkout/sessions",
                post(|State(f): State<Fake>, Form(form): Form<Vec<(String, String)>>| async move {
                    f.record("POST", "/v1/checkout/sessions".into(), form);
                    axum::Json(serde_json::json!({ "id": "cs_fake", "url": "https://checkout.example/cs_fake" }))
                }),
            )
            .route(
                "/v1/subscriptions/{id}",
                get(|State(f): State<Fake>, Path(id): Path<String>| async move {
                    f.record("GET", format!("/v1/subscriptions/{id}"), vec![]);
                    axum::Json(f.subscription(&id))
                })
                .post(
                    |State(f): State<Fake>,
                     Path(id): Path<String>,
                     Form(form): Form<Vec<(String, String)>>| async move {
                        if let Some(p) = form.iter().find(|(k, _)| k == "items[0][price]") {
                            f.item.lock().unwrap().0 = p.1.clone();
                        }
                        f.record("POST", format!("/v1/subscriptions/{id}"), form);
                        axum::Json(f.subscription(&id))
                    },
                ),
            )
            .route(
                "/v1/subscription_items/{id}",
                post(
                    |State(f): State<Fake>,
                     Path(id): Path<String>,
                     Form(form): Form<Vec<(String, String)>>| async move {
                        if let Some(q) = form.iter().find(|(k, _)| k == "quantity") {
                            f.item.lock().unwrap().1 = q.1.parse().unwrap_or(1);
                        }
                        f.record("POST", format!("/v1/subscription_items/{id}"), form);
                        axum::Json(serde_json::json!({ "id": id }))
                    },
                ),
            )
            .with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn configure(s: &mut meshharbor_config::Settings, base: &str, annual: bool) {
        s.stripe.secret_key = "sk_test_fr115_fake".into();
        s.stripe.webhook_secret = SECRET.into();
        s.stripe.price_pro = PRICE_PRO.into();
        s.stripe.price_business = PRICE_BIZ.into();
        if annual {
            s.stripe.price_pro_annual = PRICE_PRO_YEAR.into();
            s.stripe.price_business_annual = PRICE_BIZ_YEAR.into();
        }
        s.stripe.api_base = base.into();
        // Both currencies on sale, as after O1; the default is USD alone.
        s.stripe.currencies = "usd,eur".into();
    }

    /// Bring the tenant to exactly `seats` accepted members, plus one
    /// PENDING invite that must never count as a seat.
    pub(super) async fn set_seats(app: &TestApp, tenant_id: &str, seats: u64) {
        let tid = ObjectId::parse_str(tenant_id).unwrap();
        let members = app.db.collection::<bson::Document>("tenant_members");
        let now = bson::DateTime::now();
        let have = members
            .count_documents(doc! { "tenant_id": tid, "is_pending": { "$ne": true } })
            .await
            .unwrap();
        for i in have..seats {
            members
                .insert_one(doc! {
                    "tenant_id": tid, "user_id": ObjectId::new(), "role_ids": [],
                    "joined_at": now, "is_pending": false, "is_muted": false,
                    "created_at": now, "updated_at": now, "nickname": Bson::Null,
                    "notification_override": Bson::Null, "invited_by": Bson::Null,
                    "last_seen_at": Bson::Null, "_fr115": i as i64,
                })
                .await
                .unwrap();
        }
        members
            .insert_one(doc! {
                "tenant_id": tid, "user_id": ObjectId::new(), "role_ids": [],
                "joined_at": now, "is_pending": true, "is_muted": false,
                "created_at": now, "updated_at": now, "nickname": Bson::Null,
                "notification_override": Bson::Null, "invited_by": Bson::Null,
                "last_seen_at": Bson::Null,
            })
            .await
            .unwrap();
    }

    /// Give the tenant a live subscription on `price`, as the webhook would.
    async fn subscribe(app: &TestApp, tenant_id: &str, plan: &str) {
        let tid = ObjectId::parse_str(tenant_id).unwrap();
        app.db
            .collection::<bson::Document>("tenants")
            .update_one(
                doc! { "_id": tid },
                doc! { "$set": {
                    "plan": plan,
                    "billing": {
                        "customer_id": "cus_fake", "subscription_id": "sub_fake",
                        "current_period_end": Bson::Null, "status": "active",
                        "cancel_at_period_end": false, "seats": 1_i64,
                        "interval": "month", "currency": "eur",
                    },
                } },
            )
            .await
            .unwrap();
    }

    pub(super) async fn billing_of(app: &TestApp, tenant_id: &str) -> bson::Document {
        let tid = ObjectId::parse_str(tenant_id).unwrap();
        app.db
            .collection::<bson::Document>("tenants")
            .find_one(doc! { "_id": tid })
            .await
            .unwrap()
            .expect("tenant")
    }

    pub(super) async fn checkout(
        app: &TestApp,
        t: &crate::fixtures::seed::SeededTenant,
        body: serde_json::Value,
    ) -> reqwest::Response {
        let mut b = serde_json::json!({
            "tenant_id": t.tenant_id,
            "success_url": "http://localhost/ok",
            "cancel_url": "http://localhost/cancel",
        });
        for (k, v) in body.as_object().unwrap() {
            b[k] = v.clone();
        }
        app.auth_post("/api/stripe/checkout", &t.admin.access_token)
            .json(&b)
            .send()
            .await
            .unwrap()
    }

    async fn send_webhook(app: &TestApp, payload: serde_json::Value) {
        let bytes = serde_json::to_vec(&payload).unwrap();
        let ts = now_ts();
        let sig = compute_hmac_sha256(SECRET, &format!("{ts}.{}", String::from_utf8_lossy(&bytes)));
        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", format!("t={ts},v1={sig}"))
            .body(bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "webhook refused");
    }

    /// AC3 — one unit per seat, in the currency and interval asked for; a
    /// pending invite is not a seat. Before FR-115 the quantity was always 1.
    #[tokio::test]
    async fn checkout_bills_one_unit_per_seat_in_the_chosen_currency() {
        let fake = Fake::default();
        let base = fake_stripe(fake.clone()).await;
        let app = TestApp::spawn_with_settings(|s| configure(s, &base, true)).await;
        let t = app.seed_tenant("fr115-checkout").await;
        set_seats(&app, &t.tenant_id, 3).await;

        let resp = checkout(
            &app,
            &t,
            serde_json::json!({ "plan": "pro", "interval": "year", "currency": "eur" }),
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "{}",
            resp.text().await.unwrap_or_default()
        );

        let calls = fake.calls();
        let session = calls
            .iter()
            .find(|c| c.path == "/v1/checkout/sessions")
            .expect("no checkout session was created");
        assert_eq!(
            session.field("line_items[0][quantity]"),
            Some("3"),
            "{session:?}"
        );
        assert_eq!(session.field("line_items[0][price]"), Some(PRICE_PRO_YEAR));
        assert_eq!(session.field("currency"), Some("eur"));
        assert_eq!(session.field("metadata[seats]"), Some("3"));
        assert_eq!(session.field("metadata[interval]"), Some("year"));
        assert_eq!(
            session.field("subscription_data[metadata][tenant_id]"),
            Some(t.tenant_id.as_str())
        );
    }

    /// Annual is offered only once its Prices are configured: refused with
    /// a 503 naming it, before any Stripe call.
    #[tokio::test]
    async fn annual_checkout_is_refused_when_not_configured() {
        let fake = Fake::default();
        let base = fake_stripe(fake.clone()).await;
        let app = TestApp::spawn_with_settings(|s| configure(s, &base, false)).await;
        let t = app.seed_tenant("fr115-noannual").await;

        let resp = checkout(
            &app,
            &t,
            serde_json::json!({ "plan": "pro", "interval": "year" }),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 503);
        assert!(resp.text().await.unwrap().contains("annual"));
        assert!(fake.calls().is_empty(), "nothing may reach Stripe");
    }

    /// The live Prices of 2026-07-27 are USD only: until their EUR option
    /// is added, an EUR checkout is refused in words a person can act on,
    /// before any customer or session is created.
    #[tokio::test]
    async fn a_currency_the_price_does_not_carry_is_refused_plainly() {
        let fake = Fake::default();
        *fake.currencies.lock().unwrap() = Some(vec!["usd".into()]);
        let base = fake_stripe(fake.clone()).await;
        let app = TestApp::spawn_with_settings(|s| configure(s, &base, false)).await;
        let t = app.seed_tenant("fr115-usd-only").await;

        let resp = checkout(
            &app,
            &t,
            serde_json::json!({ "plan": "pro", "currency": "eur" }),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body = resp.text().await.unwrap_or_default();
        assert!(body.contains("not sold in EUR"), "got: {body}");
        assert!(
            fake.calls()
                .iter()
                .all(|c| c.path != "/v1/checkout/sessions" && c.path != "/v1/customers"),
            "nothing may be created for a currency the Price does not carry"
        );

        // USD still works.
        let resp = checkout(
            &app,
            &t,
            serde_json::json!({ "plan": "pro", "currency": "usd" }),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    /// `stripe.currencies` puts a currency on sale. One left out is absent
    /// from the plans the billing page reads, so a European browser is not
    /// started on it, and a checkout asking for it anyway is refused before
    /// any Stripe call: not even the Price is read.
    #[tokio::test]
    async fn a_currency_not_on_sale_is_neither_shown_nor_sold() {
        let fake = Fake::default();
        let base = fake_stripe(fake.clone()).await;
        let app = TestApp::spawn_with_settings(|s| {
            configure(s, &base, false);
            s.stripe.currencies = "usd".into();
        })
        .await;
        let t = app.seed_tenant("fr115-eur-off").await;

        let plans: serde_json::Value = app
            .client
            .get(app.url("/api/stripe/plans"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        for plan in plans.as_array().unwrap() {
            for price in plan["prices"].as_array().unwrap() {
                assert_eq!(price["currency"], "usd", "{}: {price}", plan["id"]);
            }
        }

        let resp = checkout(
            &app,
            &t,
            serde_json::json!({ "plan": "pro", "currency": "eur" }),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 400);
        let body = resp.text().await.unwrap_or_default();
        assert!(body.contains("not sold in EUR"), "got: {body}");
        assert!(
            fake.calls().is_empty(),
            "a currency not on sale never reaches Stripe: {:?}",
            fake.calls()
        );
    }

    /// The double-billing bug: "Switch to Business" used to run a second
    /// checkout and start a second subscription. A live subscription now
    /// refuses checkout with a 409; the change goes through change-plan.
    #[tokio::test]
    async fn a_second_checkout_is_refused_for_a_live_subscription() {
        let fake = Fake::default();
        let base = fake_stripe(fake.clone()).await;
        let app = TestApp::spawn_with_settings(|s| configure(s, &base, false)).await;
        let t = app.seed_tenant("fr115-twice").await;
        subscribe(&app, &t.tenant_id, "pro").await;

        let resp = checkout(&app, &t, serde_json::json!({ "plan": "business" })).await;
        assert_eq!(resp.status().as_u16(), 409);
        assert!(
            fake.calls()
                .iter()
                .all(|c| c.path != "/v1/checkout/sessions"),
            "no second subscription may be started"
        );
    }

    /// A plan change moves the ONE item to the new price, keeps its
    /// quantity, prorates, and the org's plan follows.
    #[tokio::test]
    async fn change_plan_moves_the_item_price_with_proration() {
        let fake = Fake::default();
        *fake.item.lock().unwrap() = (PRICE_PRO.into(), 2);
        let base = fake_stripe(fake.clone()).await;
        let app = TestApp::spawn_with_settings(|s| configure(s, &base, false)).await;
        let t = app.seed_tenant("fr115-change").await;
        subscribe(&app, &t.tenant_id, "pro").await;

        let resp = app
            .auth_post("/api/stripe/change-plan", &t.admin.access_token)
            .json(&serde_json::json!({ "tenant_id": t.tenant_id, "plan": "business", "interval": "month" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "{}",
            resp.text().await.unwrap_or_default()
        );

        let calls = fake.calls();
        let update = calls
            .iter()
            .find(|c| c.method == "POST" && c.path == "/v1/subscriptions/sub_fake")
            .expect("the subscription was not updated");
        assert_eq!(update.field("items[0][id]"), Some("si_fake"));
        assert_eq!(update.field("items[0][price]"), Some(PRICE_BIZ));
        assert_eq!(
            update.field("items[0][quantity]"),
            Some("2"),
            "quantity kept"
        );
        assert_eq!(
            update.field("proration_behavior"),
            Some("create_prorations")
        );
        assert_eq!(
            billing_of(&app, &t.tenant_id)
                .await
                .get_str("plan")
                .unwrap(),
            "business"
        );
    }

    /// AC4 — the seat reconcile moves Stripe's quantity to the member count
    /// with a proration, and does nothing when they already agree.
    #[tokio::test]
    async fn seat_sync_moves_the_quantity_to_the_member_count() {
        let fake = Fake::default();
        *fake.item.lock().unwrap() = (PRICE_PRO.into(), 1);
        let base = fake_stripe(fake.clone()).await;
        let mut settings = None;
        let app = TestApp::spawn_with_settings(|s| {
            configure(s, &base, false);
            settings = Some(s.stripe.clone());
        })
        .await;
        let t = app.seed_tenant("fr115-seats").await;
        subscribe(&app, &t.tenant_id, "pro").await;
        set_seats(&app, &t.tenant_id, 4).await;

        let stripe = StripeService::new(settings.as_ref().unwrap());
        let r = stripe.reconcile_seats(&app.db).await.unwrap();
        assert_eq!((r.orgs, r.changed, r.failed), (1, 1, 0));
        let calls = fake.calls();
        let set = calls
            .iter()
            .find(|c| c.path == "/v1/subscription_items/si_fake")
            .expect("the quantity was not moved");
        assert_eq!(set.field("quantity"), Some("4"));
        assert_eq!(set.field("proration_behavior"), Some("create_prorations"));
        let tenant = billing_of(&app, &t.tenant_id).await;
        assert_eq!(
            tenant
                .get_document("billing")
                .unwrap()
                .get_i64("seats")
                .unwrap(),
            4
        );

        // Again: they agree, so Stripe is read and not written.
        let r = stripe.reconcile_seats(&app.db).await.unwrap();
        assert_eq!((r.orgs, r.changed), (1, 0));
        let writes = fake
            .calls()
            .iter()
            .filter(|c| c.path == "/v1/subscription_items/si_fake")
            .count();
        assert_eq!(writes, 1, "an agreeing quantity must not be rewritten");
    }

    /// The webhook records seats, interval, currency and the plan a price
    /// names — a plan changed in Stripe's portal reaches the org, which the
    /// status-only handler never did. `created` may arrive before
    /// `checkout.session.completed`: the org is found by the metadata.
    #[tokio::test]
    async fn the_webhook_records_seats_interval_currency_and_plan() {
        let base = fake_stripe(Fake::default()).await;
        let app = TestApp::spawn_with_settings(|s| configure(s, &base, true)).await;
        let t = app.seed_tenant("fr115-webhook").await;

        // `created` first, before the checkout event: found by metadata.
        send_webhook(
            &app,
            serde_json::json!({
                "id": "evt_fr115_1", "type": "customer.subscription.created",
                "data": { "object": {
                    "id": "sub_hook", "object": "subscription", "status": "active",
                    "customer": "cus_hook", "currency": "eur",
                    "metadata": { "tenant_id": t.tenant_id },
                    "items": { "data": [ { "id": "si_hook", "quantity": 3,
                        "price": { "id": PRICE_PRO, "recurring": { "interval": "month" } } } ] },
                } },
            }),
        )
        .await;
        let doc = billing_of(&app, &t.tenant_id).await;
        assert_eq!(doc.get_str("plan").unwrap(), "pro");
        let b = doc.get_document("billing").unwrap();
        assert_eq!(b.get_str("subscription_id").unwrap(), "sub_hook");
        assert_eq!(b.get_i64("seats").unwrap(), 3);
        assert_eq!(b.get_str("interval").unwrap(), "month");
        assert_eq!(b.get_str("currency").unwrap(), "eur");

        // The portal moves it to annual Business with 5 seats.
        send_webhook(
            &app,
            serde_json::json!({
                "id": "evt_fr115_2", "type": "customer.subscription.updated",
                "data": { "object": {
                    "id": "sub_hook", "object": "subscription", "status": "active",
                    "customer": "cus_hook", "currency": "eur",
                    "items": { "data": [ { "id": "si_hook", "quantity": 5,
                        "price": { "id": PRICE_BIZ_YEAR, "recurring": { "interval": "year" } } } ] },
                } },
            }),
        )
        .await;
        let doc = billing_of(&app, &t.tenant_id).await;
        assert_eq!(doc.get_str("plan").unwrap(), "business");
        let b = doc.get_document("billing").unwrap();
        assert_eq!(b.get_i64("seats").unwrap(), 5);
        assert_eq!(b.get_str("interval").unwrap(), "year");

        // A price this server does not sell leaves the plan where it is.
        send_webhook(
            &app,
            serde_json::json!({
                "id": "evt_fr115_3", "type": "customer.subscription.updated",
                "data": { "object": {
                    "id": "sub_hook", "object": "subscription", "status": "active",
                    "items": { "data": [ { "id": "si_hook", "quantity": 5,
                        "price": { "id": "price_someone_else" } } ] },
                } },
            }),
        )
        .await;
        assert_eq!(
            billing_of(&app, &t.tenant_id)
                .await
                .get_str("plan")
                .unwrap(),
            "business"
        );
    }

    /// The summary the billing page reads: seats now (pending invites
    /// excluded), billed seats, subscribed.
    #[tokio::test]
    async fn the_summary_counts_accepted_members_only() {
        let base = fake_stripe(Fake::default()).await;
        let app = TestApp::spawn_with_settings(|s| configure(s, &base, false)).await;
        let t = app.seed_tenant("fr115-summary").await;
        set_seats(&app, &t.tenant_id, 6).await;

        let s: Value = app
            .auth_get(
                &format!("/api/stripe/summary?tenant_id={}", t.tenant_id),
                &t.admin.access_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(s["plan"], "free");
        assert_eq!(s["seats_now"], 6, "the pending invite is not a seat");
        assert_eq!(s["subscribed"], false);

        subscribe(&app, &t.tenant_id, "pro").await;
        let s: Value = app
            .auth_get(
                &format!("/api/stripe/summary?tenant_id={}", t.tenant_id),
                &t.admin.access_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(s["subscribed"], true);
        assert_eq!(s["seats_billed"], 1);
        assert_eq!(s["currency"], "eur");
    }
}

// ---------------------------------------------------------------------------
// FR-115 AC3 + AC4 — the same paths, against Stripe's TEST mode
// ---------------------------------------------------------------------------

/// What [`fr115`] proves against a recording fake, proven against Stripe's
/// real API in test mode. This catches what a fake cannot: a parameter
/// Stripe reads differently, a currency option it refuses, or a proration it
/// never creates.
///
/// The tests are `#[ignore]`d because they need a test-mode secret key and
/// four test Prices. Both come from the environment, never from the repo:
///
/// ```text
/// FR115_STRIPE_TEST_KEY        a TEST-mode secret key; a live one is refused
/// FR115_PRICE_PRO              USD Prices with an EUR currency option, at
/// FR115_PRICE_PRO_ANNUAL       $8 / $80 / $16 / $160 per seat
/// FR115_PRICE_BUSINESS
/// FR115_PRICE_BUSINESS_ANNUAL
/// cargo test -p meshharbor-tests fr115_testmode -- --ignored --nocapture
/// ```
///
/// The names are this module's own. Every TestApp reads `MESHHARBOR__STRIPE__*`,
/// so a key exported under those names would reach every test in the process.
/// Whatever a test creates in Stripe, it removes again.
mod fr115_testmode {
    use super::fr115::{billing_of, checkout, set_seats};
    use super::*;
    use bson::{doc, oid::ObjectId};
    use meshharbor_services::stripe::StripeService;
    use reqwest::Method;
    use std::time::Duration;

    const API: &str = "https://api.stripe.com";

    struct Env {
        key: String,
        pro: String,
        pro_year: String,
        biz: String,
        biz_year: String,
    }

    fn env() -> Env {
        let get = |k: &str| {
            std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set: see the module docs"))
        };
        let key = get("FR115_STRIPE_TEST_KEY");
        assert!(
            key.starts_with("sk_test_") || key.starts_with("rk_test_"),
            "FR115_STRIPE_TEST_KEY must be a TEST-mode key"
        );
        Env {
            key,
            pro: get("FR115_PRICE_PRO"),
            pro_year: get("FR115_PRICE_PRO_ANNUAL"),
            biz: get("FR115_PRICE_BUSINESS"),
            biz_year: get("FR115_PRICE_BUSINESS_ANNUAL"),
        }
    }

    fn configure(s: &mut meshharbor_config::Settings, e: &Env, webhook_secret: &str) {
        s.stripe.secret_key = e.key.clone();
        s.stripe.webhook_secret = webhook_secret.into();
        s.stripe.price_pro = e.pro.clone();
        s.stripe.price_business = e.biz.clone();
        s.stripe.price_pro_annual = e.pro_year.clone();
        s.stripe.price_business_annual = e.biz_year.clone();
        s.stripe.api_base = API.into();
        s.stripe.currencies = "usd,eur".into();
        // The test runs the reconcile itself; the background loop must not race it.
        s.stripe.seat_sync = false;
    }

    /// One Stripe API call. A non-2xx answer fails the test with Stripe's message.
    async fn stripe(
        app: &TestApp,
        e: &Env,
        method: Method,
        path: &str,
        form: &[(&str, &str)],
    ) -> Value {
        let mut req = app
            .client
            .request(method, format!("{API}{path}"))
            .basic_auth(&e.key, Some(""));
        if !form.is_empty() {
            req = req.form(form);
        }
        let resp = req.send().await.expect("Stripe is unreachable");
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        assert!(
            status.is_success(),
            "Stripe {path}: {status} {}",
            v["error"]["message"]
        );
        v
    }

    /// Deliver `event`, Stripe's own JSON, to the webhook, signed the way
    /// Stripe signs.
    async fn deliver(app: &TestApp, secret: &str, event: &Value) {
        let body = serde_json::to_string(event).unwrap();
        let ts = now_ts();
        let sig = compute_hmac_sha256(secret, &format!("{ts}.{body}"));
        let resp = app
            .client
            .post(app.url("/api/stripe/webhook"))
            .header("Content-Type", "application/json")
            .header("stripe-signature", format!("t={ts},v1={sig}"))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "webhook refused {}",
            event["type"]
        );
    }

    /// The newest event of `kind` whose object matches, as Stripe recorded it.
    async fn event_where(
        app: &TestApp,
        e: &Env,
        kind: &str,
        matches: impl Fn(&Value) -> bool,
    ) -> Value {
        for _ in 0..40 {
            let page = stripe(
                app,
                e,
                Method::GET,
                &format!("/v1/events?type={kind}&limit=25"),
                &[],
            )
            .await;
            if let Some(ev) = page["data"]
                .as_array()
                .and_then(|evs| evs.iter().find(|ev| matches(&ev["data"]["object"])))
            {
                return ev.clone();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("Stripe recorded no matching {kind} within 20 s");
    }

    /// `cs_test_…` from a Checkout URL (`…/c/pay/cs_test_…#…`).
    fn session_id(url: &str) -> String {
        let start = url
            .find("cs_test_")
            .unwrap_or_else(|| panic!("not a test-mode Checkout URL: {url}"));
        url[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect()
    }

    /// The sum of the customer's pending proration items, in minor units.
    async fn proration_total(app: &TestApp, e: &Env, customer: &str) -> i64 {
        let page = stripe(
            app,
            e,
            Method::GET,
            &format!("/v1/invoiceitems?customer={customer}&pending=true&limit=100"),
            &[],
        )
        .await;
        let items = page["data"].as_array().cloned().unwrap_or_default();
        assert!(
            items.iter().any(|i| i["proration"] == true),
            "no proration item: {page}"
        );
        items
            .iter()
            .filter(|i| i["proration"] == true)
            .filter_map(|i| i["amount"].as_i64())
            .sum()
    }

    /// AC3: in every interval and currency, Stripe's own Checkout Session
    /// holds one unit per seat, the Price and currency asked for, and an
    /// amount of seats × the unit price. A pending invite is not a seat.
    #[tokio::test]
    #[ignore = "needs a Stripe test-mode key and Prices (see the module docs)"]
    async fn checkout_bills_one_unit_per_seat_in_every_interval_and_currency() {
        let e = env();
        let secret = format!("fr115-testmode-{}", ObjectId::new());
        let app = TestApp::spawn_with_settings(|s| configure(s, &e, &secret)).await;
        let t = app.seed_tenant("fr115-tm-checkout").await;
        set_seats(&app, &t.tenant_id, 3).await;

        let mut customer = String::new();
        for (plan, interval, currency, price, unit) in [
            ("pro", "month", "usd", &e.pro, 800),
            ("pro", "year", "eur", &e.pro_year, 8_000),
            ("business", "month", "eur", &e.biz, 1_600),
            ("business", "year", "usd", &e.biz_year, 16_000),
        ] {
            let what = format!("{plan}/{interval}/{currency}");
            let resp = checkout(
                &app,
                &t,
                serde_json::json!({ "plan": plan, "interval": interval, "currency": currency }),
            )
            .await;
            let status = resp.status().as_u16();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            assert_eq!(status, 200, "{what}: {body}");
            let id = session_id(body["url"].as_str().expect("a Checkout URL"));
            let s = stripe(
                &app,
                &e,
                Method::GET,
                &format!("/v1/checkout/sessions/{id}?expand%5B%5D=line_items"),
                &[],
            )
            .await;
            assert_eq!(s["mode"], "subscription", "{what}");
            assert_eq!(s["currency"], currency, "{what}");
            let item = &s["line_items"]["data"][0];
            assert_eq!(item["quantity"], 3, "{what}: one unit per seat");
            assert_eq!(item["price"]["id"], price.as_str(), "{what}");
            assert_eq!(
                s["amount_total"],
                3 * unit,
                "{what}: seats × the unit price"
            );
            assert_eq!(s["metadata"]["seats"], "3", "{what}");
            assert_eq!(s["metadata"]["interval"], interval, "{what}");
            assert_eq!(s["metadata"]["tenant_id"], t.tenant_id.as_str(), "{what}");
            customer = s["customer"].as_str().unwrap_or_default().to_string();
            stripe(
                &app,
                &e,
                Method::POST,
                &format!("/v1/checkout/sessions/{id}/expire"),
                &[],
            )
            .await;
        }
        assert!(
            !customer.is_empty(),
            "the server created no Stripe customer"
        );
        stripe(
            &app,
            &e,
            Method::DELETE,
            &format!("/v1/customers/{customer}"),
            &[],
        )
        .await;
    }

    /// AC3, end to end: our checkout opens a real test-mode Checkout page, a
    /// browser pays it with Stripe's published test card, and Stripe's own
    /// `checkout.session.completed`, delivered as Stripe signs it, leaves the
    /// org on Pro with its seats, monthly, in EUR. The card was charged
    /// seats × the unit price.
    ///
    /// Interactive: the test writes the Checkout URL to the file named by
    /// `FR115_CHECKOUT_URL_FILE` and waits up to 15 minutes for someone to
    /// pay it with Stripe's published Visa test card (4242…), any future
    /// expiry and any CVC.
    #[tokio::test]
    #[ignore = "interactive: a browser pays the Checkout URL with Stripe's test card"]
    async fn a_test_card_checkout_puts_the_org_on_pro_with_its_seats() {
        let e = env();
        let handoff = std::env::var("FR115_CHECKOUT_URL_FILE")
            .expect("FR115_CHECKOUT_URL_FILE is not set: see the test's docs");
        let secret = format!("fr115-testmode-{}", ObjectId::new());
        let app = TestApp::spawn_with_settings(|s| configure(s, &e, &secret)).await;
        let t = app.seed_tenant("fr115-tm-e2e").await;
        set_seats(&app, &t.tenant_id, 3).await;

        let resp = checkout(
            &app,
            &t,
            serde_json::json!({ "plan": "pro", "interval": "month", "currency": "eur" }),
        )
        .await;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        assert_eq!(status, 200, "{body}");
        let url = body["url"].as_str().expect("a Checkout URL").to_string();
        let id = session_id(&url);
        std::fs::write(&handoff, &url).unwrap();
        eprintln!("fr115 e2e: pay the Checkout URL in {handoff} with Stripe's test card");

        // Stripe reports the session complete once the card is charged.
        let mut session = Value::Null;
        for _ in 0..300 {
            session = stripe(
                &app,
                &e,
                Method::GET,
                &format!("/v1/checkout/sessions/{id}"),
                &[],
            )
            .await;
            if session["status"] == "complete" {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        assert_eq!(
            session["status"], "complete",
            "nobody paid the Checkout page within 15 minutes"
        );
        assert_eq!(session["payment_status"], "paid");
        let sub_id = session["subscription"]
            .as_str()
            .expect("a subscription")
            .to_string();
        let customer = session["customer"].as_str().unwrap_or_default().to_string();

        // Stripe's own event, delivered as Stripe signs it.
        let completed = event_where(&app, &e, "checkout.session.completed", |o| {
            o["id"] == id.as_str()
        })
        .await;
        deliver(&app, &secret, &completed).await;
        let doc = billing_of(&app, &t.tenant_id).await;
        assert_eq!(doc.get_str("plan").unwrap(), "pro");
        let b = doc.get_document("billing").unwrap();
        assert_eq!(b.get_str("subscription_id").unwrap(), sub_id);
        assert_eq!(b.get_str("customer_id").unwrap(), customer);
        assert_eq!(b.get_i64("seats").unwrap(), 3);
        assert_eq!(b.get_str("interval").unwrap(), "month");
        assert_eq!(b.get_str("currency").unwrap(), "eur");

        // What the card paid: 3 seats × €8.
        let sub = stripe(
            &app,
            &e,
            Method::GET,
            &format!("/v1/subscriptions/{sub_id}?expand%5B%5D=latest_invoice"),
            &[],
        )
        .await;
        assert_eq!(sub["items"]["data"][0]["quantity"], 3);
        assert_eq!(sub["latest_invoice"]["amount_paid"], 2_400);
        assert_eq!(sub["latest_invoice"]["currency"], "eur");

        stripe(
            &app,
            &e,
            Method::DELETE,
            &format!("/v1/subscriptions/{sub_id}"),
            &[],
        )
        .await;
        stripe(
            &app,
            &e,
            Method::DELETE,
            &format!("/v1/customers/{customer}"),
            &[],
        )
        .await;
    }

    /// AC4: on a real subscription, whose first invoice Stripe's test card
    /// pays, a third member moves Stripe's quantity to 3 and charges for the
    /// rest of the period; the member leaving moves it back and credits it.
    /// On the way, AC3's webhook half: Stripe's own subscription events,
    /// delivered as Stripe signs them, leave plan, seats, interval and
    /// currency on the org.
    #[tokio::test]
    #[ignore = "needs a Stripe test-mode key and Prices (see the module docs)"]
    async fn seats_move_the_quantity_with_a_proration_and_the_webhook_records_them() {
        let e = env();
        let secret = format!("fr115-testmode-{}", ObjectId::new());
        let mut settings = None;
        let app = TestApp::spawn_with_settings(|s| {
            configure(s, &e, &secret);
            settings = Some(s.stripe.clone());
        })
        .await;
        let t = app.seed_tenant("fr115-tm-seats").await;
        set_seats(&app, &t.tenant_id, 2).await;

        let cus = stripe(
            &app,
            &e,
            Method::POST,
            "/v1/customers",
            &[
                ("payment_method", "pm_card_visa"),
                ("invoice_settings[default_payment_method]", "pm_card_visa"),
                ("description", "FR-115 test-mode seat sync"),
            ],
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let sub = stripe(
            &app,
            &e,
            Method::POST,
            "/v1/subscriptions",
            &[
                ("customer", cus.as_str()),
                ("items[0][price]", e.pro.as_str()),
                ("items[0][quantity]", "2"),
                ("currency", "eur"),
                ("metadata[tenant_id]", t.tenant_id.as_str()),
            ],
        )
        .await;
        assert_eq!(
            sub["status"], "active",
            "the test card did not pay the first invoice"
        );
        let sub_id = sub["id"].as_str().unwrap().to_string();

        // Stripe's own `created` event leaves plan, seats, interval and
        // currency on the org.
        let created = event_where(&app, &e, "customer.subscription.created", |o| {
            o["id"] == sub_id.as_str()
        })
        .await;
        deliver(&app, &secret, &created).await;
        let doc = billing_of(&app, &t.tenant_id).await;
        assert_eq!(doc.get_str("plan").unwrap(), "pro");
        let b = doc.get_document("billing").unwrap();
        assert_eq!(b.get_str("subscription_id").unwrap(), sub_id);
        assert_eq!(b.get_i64("seats").unwrap(), 2);
        assert_eq!(b.get_str("interval").unwrap(), "month");
        assert_eq!(b.get_str("currency").unwrap(), "eur");

        // A third member: the reconcile moves Stripe's quantity, with a charge.
        set_seats(&app, &t.tenant_id, 3).await;
        let sync = StripeService::new(settings.as_ref().unwrap());
        let r = sync.reconcile_seats(&app.db).await.unwrap();
        assert_eq!((r.orgs, r.changed, r.failed), (1, 1, 0));
        let s = stripe(
            &app,
            &e,
            Method::GET,
            &format!("/v1/subscriptions/{sub_id}"),
            &[],
        )
        .await;
        assert_eq!(s["items"]["data"][0]["quantity"], 3);
        let charged = proration_total(&app, &e, &cus).await;
        assert!(
            charged > 0,
            "the added seat is charged for the rest of the period: {charged}"
        );

        // Stripe's `updated` event for the move agrees with the org.
        let updated = event_where(&app, &e, "customer.subscription.updated", |o| {
            o["id"] == sub_id.as_str() && o["items"]["data"][0]["quantity"] == 3
        })
        .await;
        deliver(&app, &secret, &updated).await;
        let doc = billing_of(&app, &t.tenant_id).await;
        assert_eq!(
            doc.get_document("billing")
                .unwrap()
                .get_i64("seats")
                .unwrap(),
            3
        );

        // The member leaves: back to 2, with a credit.
        let tid = ObjectId::parse_str(&t.tenant_id).unwrap();
        app.db
            .collection::<bson::Document>("tenant_members")
            .delete_one(doc! { "tenant_id": tid, "_fr115": { "$exists": true } })
            .await
            .unwrap();
        let r = sync.reconcile_seats(&app.db).await.unwrap();
        assert_eq!((r.orgs, r.changed, r.failed), (1, 1, 0));
        let s = stripe(
            &app,
            &e,
            Method::GET,
            &format!("/v1/subscriptions/{sub_id}"),
            &[],
        )
        .await;
        assert_eq!(s["items"]["data"][0]["quantity"], 2);
        let after = proration_total(&app, &e, &cus).await;
        assert!(
            after < charged,
            "leaving credits the rest of the period: {charged} -> {after}"
        );

        stripe(
            &app,
            &e,
            Method::DELETE,
            &format!("/v1/subscriptions/{sub_id}"),
            &[],
        )
        .await;
        stripe(
            &app,
            &e,
            Method::DELETE,
            &format!("/v1/customers/{cus}"),
            &[],
        )
        .await;
    }
}
