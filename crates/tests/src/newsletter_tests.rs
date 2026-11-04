// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-58 — the newsletter admin surface (issues CRUD, preview, test-send),
//! against a real server and a real MongoDB.
//!
//! The load-bearing assertions: the platform-admin gate answers **404** for
//! both an unset allowlist and a non-listed caller (never 403 — the allowlist
//! is itself what is being hidden); a slug is claimed by the unique index (409,
//! never a second issue); an issue that left `draft` is not editable; the
//! preview is the branded send-path bytes with raw operator HTML structurally
//! absent; and test-send refuses loudly when no mailer is configured.

use crate::fixtures::test_app::TestApp;
use bson::{doc, oid::ObjectId};

fn issue_json(slug: &str) -> serde_json::Value {
    serde_json::json!({
        "slug": slug,
        "subject": "Three products, one daemon",
        "preheader": "Why one agent per machine is the whole point.",
        "body_md": "## The story\n\nOne daemon per machine.\n\n[Read more](https://roomler.ai/)\n\n<script>alert(1)</script>",
        "hero_url": "https://roomler.ai/newsletter-img/test-v1.png",
        "hero_alt": "One daemon radiating four capabilities",
        "cta_text": "Try Roomler",
        "cta_url": "https://roomler.ai/"
    })
}

/// Mint an access token for an id without creating a user row — the admin
/// endpoints never read the users collection, so the JWT is what's exercised
/// (same pattern as `stats_tests::admin_stats_gate_…`).
fn token_for(app: &TestApp, id: ObjectId) -> String {
    app.state
        .auth
        .generate_tokens(id, "who@test.io", "who")
        .unwrap()
        .access_token
}

#[tokio::test]
async fn every_admin_newsletter_route_is_404_without_authority() {
    // Arm 1: allowlist UNSET (the default) — the whole surface must not exist.
    let app = TestApp::spawn().await;
    let token = token_for(&app, ObjectId::new());

    let gets = [
        "/api/admin/newsletter/issues",
        "/api/admin/newsletter/issues/some-slug",
        "/api/admin/newsletter/issues/some-slug/preview",
    ];
    for path in gets {
        let r = app.auth_get(path, &token).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 404, "GET {path} with unset allowlist");
    }
    let r = app
        .auth_post("/api/admin/newsletter/issues", &token)
        .json(&issue_json("x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404, "POST create with unset allowlist");

    // Arm 2: allowlist SET, caller is a different authenticated id — same 404,
    // and the admin id itself passes (proving the 404 is the gate, not a
    // missing route).
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let outsider = token_for(&app, ObjectId::new());
    let r = app
        .auth_get("/api/admin/newsletter/issues", &outsider)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        404,
        "a non-listed caller must get 404, NEVER 403 — a 403 would confirm the surface exists"
    );
    let admin = token_for(&app, admin_id);
    let r = app
        .auth_get("/api/admin/newsletter/issues", &admin)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "the allowlisted id passes the gate"
    );
}

#[tokio::test]
async fn draft_crud_roundtrip_slug_conflict_and_edit_lock() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let admin = token_for(&app, admin_id);

    // Create.
    let r = app
        .auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("first-issue"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    let created: serde_json::Value = r.json().await.unwrap();
    assert_eq!(created["slug"], "first-issue");
    assert_eq!(created["status"], "draft");
    assert!(
        created["created_at"].as_str().unwrap().contains('T'),
        "timestamps must be plain RFC 3339 strings on the wire, not bson objects"
    );

    // The slug is a claim: a second create answers 409 and no second row exists.
    let r = app
        .auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("first-issue"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "the unique index arbitrates");
    let n = app
        .db
        .collection::<bson::Document>("newsletter_issues")
        .count_documents(doc! { "slug": "first-issue" })
        .await
        .unwrap();
    assert_eq!(n, 1);

    // Update while draft: change the subject, REMOVE the CTA — an omitted
    // optional field must be unset, not silently kept.
    let mut edited = issue_json("ignored");
    edited["subject"] = serde_json::json!("A better subject");
    edited.as_object_mut().unwrap().remove("cta_text");
    edited.as_object_mut().unwrap().remove("cta_url");
    edited.as_object_mut().unwrap().remove("slug");
    let r = app
        .auth_put("/api/admin/newsletter/issues/first-issue", &admin)
        .json(&edited)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let updated: serde_json::Value = r.json().await.unwrap();
    assert_eq!(updated["subject"], "A better subject");
    assert!(
        updated["cta_text"].is_null(),
        "a removed optional field must actually be gone"
    );

    // Unknown slug → 404 (an update must never upsert a new issue).
    let r = app
        .auth_put("/api/admin/newsletter/issues/typo-slug", &admin)
        .json(&edited)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // Once the issue leaves draft, edits answer 409 with the reason.
    app.db
        .collection::<bson::Document>("newsletter_issues")
        .update_one(
            doc! { "slug": "first-issue" },
            doc! { "$set": { "status": "sending" } },
        )
        .await
        .unwrap();
    let r = app
        .auth_put("/api/admin/newsletter/issues/first-issue", &admin)
        .json(&edited)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a non-draft is not editable");

    // List shows it.
    let r = app
        .auth_get("/api/admin/newsletter/issues", &admin)
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = r.json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn preview_is_the_branded_send_bytes_and_drops_raw_html() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let admin = token_for(&app, admin_id);

    app.auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("preview-me"))
        .send()
        .await
        .unwrap();

    let r = app
        .auth_get("/api/admin/newsletter/issues/preview-me/preview", &admin)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(ct.starts_with("text/html"), "content-type was {ct:?}");
    let html = r.text().await.unwrap();

    // Branded wrapper + rendered markdown.
    assert!(html.contains("Field Notes"));
    assert!(html.contains("The story"), "the md body must be rendered");
    assert!(html.contains("https://roomler.ai/newsletter-img/test-v1.png"));
    // The raw-HTML boundary: the <script> in body_md is structurally absent.
    assert!(
        !html.contains("<script"),
        "raw operator HTML must never reach the rendered email"
    );
    // Preview IS the sent artifact: the placeholder is substituted, none left.
    assert!(!html.contains("%%UNSUBSCRIBE_URL%%"));
    assert!(html.contains("/api/subscribe/unsubscribe/preview-sample-token"));
    // FR-102 P5 (D5) — the same tags the send carries: the links to this
    // site name the issue (the same for every recipient), and so does the
    // unsubscribe link.
    assert!(
        html.contains(
            "href=\"https://roomler.ai/?utm_source=newsletter&amp;utm_medium=email&amp;utm_campaign=nl-preview-me\""
        ),
        "{html}"
    );
    assert!(html.contains("/api/subscribe/unsubscribe/preview-sample-token?i=preview-me"));
}

#[tokio::test]
async fn test_send_refuses_loudly_without_a_mailer() {
    let admin_id = ObjectId::new();
    // Default test settings leave email unconfigured ⇒ state.email = None.
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let admin = token_for(&app, admin_id);

    app.auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("no-mailer"))
        .send()
        .await
        .unwrap();

    let r = app
        .auth_post("/api/admin/newsletter/issues/no-mailer/test-send", &admin)
        .json(&serde_json::json!({ "email": "operator@test.io" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "no mailer must be a loud refusal, not a silent skip"
    );

    // And the issue is untouched.
    let row = app
        .db
        .collection::<bson::Document>("newsletter_issues")
        .find_one(doc! { "slug": "no-mailer" })
        .await
        .unwrap()
        .expect("issue row exists");
    assert_eq!(row.get_str("status").unwrap(), "draft");
}

// ── P3: ledger + fan-out + status ───────────────────────────────────────
//
// Mailer for these tests: SMTP at an `.invalid` host — guaranteed NXDOMAIN,
// so every send fails FAST and deterministically. (A dead loopback PORT is
// not usable here: this WSL swallows loopback SYNs to unbound ports, which
// would turn every failure into a 30 s timeout.)

fn admin_app_settings(
    admin_id: ObjectId,
) -> impl FnOnce(&mut meshharbor_config::Settings) + Send + 'static {
    move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
        s.email.smtp_host = Some("mailer.does-not-exist.invalid".into());
        s.email.smtp_port = Some(1025);
    }
}

/// Seed a subscriber row directly. ⚠️ `unsubscribed_at` is OMITTED unless
/// set — `mailable()` filters on `unsubscribed_at: null`, and an explicit
/// null row would be unrepresentative of what the subscribe path writes.
async fn seed_subscriber(
    app: &TestApp,
    email: &str,
    confirmed: bool,
    unsubscribed: bool,
) -> ObjectId {
    let mut d = doc! {
        "email": email,
        "source": "test",
        "confirmed": confirmed,
        "unsubscribe_token": format!("tok-{email}"),
        "created_at": bson::DateTime::now(),
    };
    if unsubscribed {
        d.insert("unsubscribed_at", bson::DateTime::now());
    }
    app.db
        .collection::<bson::Document>("subscribers")
        .insert_one(d)
        .await
        .unwrap()
        .inserted_id
        .as_object_id()
        .unwrap()
}

async fn issue_object_id(app: &TestApp, slug: &str) -> ObjectId {
    app.db
        .collection::<bson::Document>("newsletter_issues")
        .find_one(doc! { "slug": slug })
        .await
        .unwrap()
        .expect("issue exists")
        .get_object_id("_id")
        .unwrap()
}

fn minutes_ago(m: i64) -> bson::DateTime {
    bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - m * 60 * 1000)
}

/// Poll until the issue completes — the fan-out is async behind a 202.
async fn wait_completed(app: &TestApp, slug: &str) {
    for _ in 0..60 {
        let row = app
            .db
            .collection::<bson::Document>("newsletter_issues")
            .find_one(doc! { "slug": slug })
            .await
            .unwrap()
            .expect("issue exists");
        if row.get_str("status").unwrap() == "completed" {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("issue `{slug}` never completed");
}

#[tokio::test]
async fn send_refuses_before_claiming_when_no_mailer() {
    let admin_id = ObjectId::new();
    // platform_admins set, email left UNCONFIGURED.
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let admin = token_for(&app, admin_id);

    app.auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("refuse-me"))
        .send()
        .await
        .unwrap();
    let r = app
        .auth_post("/api/admin/newsletter/issues/refuse-me/send", &admin)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    // The refusal happened BEFORE the claim — the issue must still be a
    // sendable draft once a mailer exists, not a stuck `sending`.
    let row = app
        .db
        .collection::<bson::Document>("newsletter_issues")
        .find_one(doc! { "slug": "refuse-me" })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get_str("status").unwrap(), "draft");
}

#[tokio::test]
async fn send_ledgers_the_snapshot_and_completes_honestly() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(admin_app_settings(admin_id)).await;
    let admin = token_for(&app, admin_id);

    seed_subscriber(&app, "a@test.io", true, false).await;
    seed_subscriber(&app, "b@test.io", true, false).await;
    seed_subscriber(&app, "c@test.io", true, false).await;
    seed_subscriber(&app, "pending@test.io", false, false).await;
    seed_subscriber(&app, "gone@test.io", true, true).await;

    app.auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("real-send"))
        .send()
        .await
        .unwrap();

    let r = app
        .auth_post("/api/admin/newsletter/issues/real-send/send", &admin)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    let accepted: serde_json::Value = r.json().await.unwrap();
    assert!(!accepted["claimed_by"].as_str().unwrap().is_empty());

    wait_completed(&app, "real-send").await;

    // Status: terminal is `completed`, and the counts carry the truth — an
    // all-failed issue must never read as "sent".
    let r = app
        .auth_get("/api/admin/newsletter/issues/real-send/status", &admin)
        .send()
        .await
        .unwrap();
    let st: serde_json::Value = r.json().await.unwrap();
    assert_eq!(st["status"], "completed");
    assert_eq!(st["counts"]["total"], 3, "only the mailable snapshot");
    assert_eq!(
        st["counts"]["failed"], 3,
        "the mailer host does not resolve"
    );
    assert_eq!(st["counts"]["sent"], 0);
    assert_eq!(st["counts"]["stale"], 0);
    assert_eq!(st["failed_sample"].as_array().unwrap().len(), 3);
    assert!(
        st["failed_sample"][0]["error"].as_str().unwrap().len() > 5,
        "failures carry the backend error"
    );

    // The ledger: exactly one row per mailable subscriber; pending and
    // unsubscribed never got one.
    let sends = app.db.collection::<bson::Document>("newsletter_sends");
    assert_eq!(sends.count_documents(doc! {}).await.unwrap(), 3);
    assert_eq!(
        sends
            .count_documents(doc! { "email": { "$in": ["pending@test.io", "gone@test.io"] } })
            .await
            .unwrap(),
        0
    );

    // Re-POSTing send never double-sends: completed is terminal.
    let r = app
        .auth_post("/api/admin/newsletter/issues/real-send/send", &admin)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "one issue, one send");
    assert_eq!(sends.count_documents(doc! {}).await.unwrap(), 3);
}

#[tokio::test]
async fn a_live_claim_is_never_usurped() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(admin_app_settings(admin_id)).await;
    let admin = token_for(&app, admin_id);

    app.auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("busy"))
        .send()
        .await
        .unwrap();
    app.db
        .collection::<bson::Document>("newsletter_issues")
        .update_one(
            doc! { "slug": "busy" },
            doc! { "$set": {
                "status": "sending",
                "claimed_by": "other-pod",
                "claimed_at": bson::DateTime::now(),
            } },
        )
        .await
        .unwrap();

    let r = app
        .auth_post("/api/admin/newsletter/issues/busy/send", &admin)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("other-pod"),
        "the refusal names the live claim holder: {body}"
    );
}

#[tokio::test]
async fn stale_rows_are_reported_live_and_retried_only_on_request() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(admin_app_settings(admin_id)).await;
    let admin = token_for(&app, admin_id);
    let sends = app.db.collection::<bson::Document>("newsletter_sends");
    let issues = app.db.collection::<bson::Document>("newsletter_issues");

    // ── Issue A: a stale row, resumed WITHOUT the flag — reported, untouched.
    let s1 = seed_subscriber(&app, "stuck@test.io", true, false).await;
    app.auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("stale-plain"))
        .send()
        .await
        .unwrap();
    let a_id = issue_object_id(&app, "stale-plain").await;
    sends
        .insert_one(doc! {
            "issue_id": a_id, "subscriber_id": s1, "email": "stuck@test.io",
            "status": "claimed", "claimed_at": minutes_ago(25), "updated_at": minutes_ago(25),
        })
        .await
        .unwrap();
    issues
        .update_one(
            doc! { "slug": "stale-plain" },
            doc! { "$set": { "status": "sending", "claimed_by": "dead-pod", "claimed_at": minutes_ago(20) } },
        )
        .await
        .unwrap();

    // Reported live, while still `sending`.
    let r = app
        .auth_get("/api/admin/newsletter/issues/stale-plain/status", &admin)
        .send()
        .await
        .unwrap();
    let st: serde_json::Value = r.json().await.unwrap();
    assert_eq!(st["status"], "sending");
    assert_eq!(st["counts"]["stale"], 1);
    assert_eq!(st["stale_addresses"][0], "stuck@test.io");

    // Plain resume: the stale issue-claim is re-claimable, the stale ROW is
    // not touched — "maybe delivered" stays a human decision.
    let r = app
        .auth_post("/api/admin/newsletter/issues/stale-plain/send", &admin)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202, "a stale claim is the resume path");
    wait_completed(&app, "stale-plain").await;
    let r = app
        .auth_get("/api/admin/newsletter/issues/stale-plain/status", &admin)
        .send()
        .await
        .unwrap();
    let st: serde_json::Value = r.json().await.unwrap();
    assert_eq!(st["counts"]["total"], 1);
    assert_eq!(
        st["counts"]["stale"], 1,
        "without retry_stale the ambiguous row survives, counted"
    );
    assert_eq!(st["counts"]["failed"], 0);

    // ── Issue B: retry_stale re-attempts — and the re-check honors a
    // withdrawal that happened while the row sat stuck.
    let s2 = seed_subscriber(&app, "left@test.io", true, false).await;
    app.auth_post("/api/admin/newsletter/issues", &admin)
        .json(&issue_json("stale-retry"))
        .send()
        .await
        .unwrap();
    let b_id = issue_object_id(&app, "stale-retry").await;
    sends
        .insert_one(doc! {
            "issue_id": b_id, "subscriber_id": s2, "email": "left@test.io",
            "status": "claimed", "claimed_at": minutes_ago(25), "updated_at": minutes_ago(25),
        })
        .await
        .unwrap();
    issues
        .update_one(
            doc! { "slug": "stale-retry" },
            doc! { "$set": { "status": "sending", "claimed_by": "dead-pod", "claimed_at": minutes_ago(20) } },
        )
        .await
        .unwrap();
    // The subscriber withdrew while the row was stuck.
    app.db
        .collection::<bson::Document>("subscribers")
        .update_one(
            doc! { "_id": s2 },
            doc! { "$set": { "unsubscribed_at": bson::DateTime::now(), "confirmed": false } },
        )
        .await
        .unwrap();

    let r = app
        .auth_post("/api/admin/newsletter/issues/stale-retry/send", &admin)
        .json(&serde_json::json!({ "retry_stale": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    wait_completed(&app, "stale-retry").await;
    let r = app
        .auth_get("/api/admin/newsletter/issues/stale-retry/status", &admin)
        .send()
        .await
        .unwrap();
    let st: serde_json::Value = r.json().await.unwrap();
    // Two rows, and each proves a different phase: the reclaimed stale row
    // (s2) was re-checked and the withdrawal honored — suppressed, never
    // mailed; and the snapshot phase correctly claimed the OTHER still-
    // mailable subscriber (s1, from the issue-A scenario) for THIS issue —
    // an issue's audience is the whole current list, not one stuck row.
    assert_eq!(st["counts"]["total"], 2);
    assert_eq!(
        st["counts"]["suppressed"], 1,
        "the reclaimed row was re-checked and the withdrawal honored — never mailed"
    );
    assert_eq!(
        st["counts"]["failed"], 1,
        "the snapshot phase mailed the still-subscribed s1 (dead-DNS ⇒ failed)"
    );
    assert_eq!(st["counts"]["stale"], 0);
}

// ── P4: the signed-in toggle — a different door into the SAME list ──────

#[tokio::test]
async fn signed_in_toggle_is_a_door_into_the_same_list() {
    let app = TestApp::spawn().await;
    let user = app
        .register_user(
            "member@test.io",
            "member",
            "Member",
            "correct-horse-battery",
            None,
            None,
        )
        .await;

    // Fresh account: not subscribed.
    let r = app
        .auth_get("/api/user/newsletter", &user.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let pref: serde_json::Value = r.json().await.unwrap();
    assert_eq!(pref["subscribed"], false);

    // An UNVERIFIED account must not pre-confirm — ownership is the whole
    // basis for skipping the confirmation mail. (register_user auto-verifies
    // for tests, so un-verify first.)
    app.db
        .collection::<bson::Document>("users")
        .update_one(
            doc! { "email": "member@test.io" },
            doc! { "$set": { "is_verified": false } },
        )
        .await
        .unwrap();
    let r = app
        .auth_put("/api/user/newsletter", &user.access_token)
        .json(&serde_json::json!({ "subscribed": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        422,
        "unverified ⇒ the public form's job"
    );
    app.db
        .collection::<bson::Document>("users")
        .update_one(
            doc! { "email": "member@test.io" },
            doc! { "$set": { "is_verified": true } },
        )
        .await
        .unwrap();

    // Verified: subscribing is pre-confirmed, source `account`, and the exit
    // is built with the entrance (an unsubscribe token exists immediately).
    let r = app
        .auth_put("/api/user/newsletter", &user.access_token)
        .json(&serde_json::json!({ "subscribed": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let row = app
        .db
        .collection::<bson::Document>("subscribers")
        .find_one(doc! { "email": "member@test.io" })
        .await
        .unwrap()
        .expect("the toggle writes the subscribers store — the same list");
    assert!(row.get_bool("confirmed").unwrap());
    assert_eq!(row.get_str("source").unwrap(), "account");
    let unsub_token = row.get_str("unsubscribe_token").unwrap().to_string();
    assert!(!unsub_token.is_empty());

    // Toggling off stamps the row like every other withdrawal…
    let r = app
        .auth_put("/api/user/newsletter", &user.access_token)
        .json(&serde_json::json!({ "subscribed": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let row = app
        .db
        .collection::<bson::Document>("subscribers")
        .find_one(doc! { "email": "member@test.io" })
        .await
        .unwrap()
        .unwrap();
    assert!(row.get("unsubscribed_at").is_some(), "kept and stamped");

    // …and toggling back on is fresh consent on proven ownership.
    let r = app
        .auth_put("/api/user/newsletter", &user.access_token)
        .json(&serde_json::json!({ "subscribed": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let r = app
        .auth_get("/api/user/newsletter", &user.access_token)
        .send()
        .await
        .unwrap();
    let pref: serde_json::Value = r.json().await.unwrap();
    assert_eq!(pref["subscribed"], true);

    // The public one-click unsubscribe still covers this row — one list,
    // every exit door works on it.
    let r = app
        .client
        .post(app.url(&format!("/api/subscribe/unsubscribe/{unsub_token}")))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("List-Unsubscribe=One-Click")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let r = app
        .auth_get("/api/user/newsletter", &user.access_token)
        .send()
        .await
        .unwrap();
    let pref: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        pref["subscribed"], false,
        "the toggle reads the same store the public unsubscribe wrote"
    );
}
