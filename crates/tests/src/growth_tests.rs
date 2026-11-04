// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 — growth observability, against a real server.
//!
//! P1b (AC5): a sign-up's `source` / `medium` are stored in the taxonomy's
//! spelling — `YouTub` / `Video` as `youtube` / `video`, an alias as its
//! canonical, an unknown source verbatim (lowercased), never dropped.
//!
//! P1c (AC4's set): `/api/admin/growth/exclusions` 404s a non-admin, lists
//! the implicit exclusions (the platform admins, the orgs they own) beside
//! the explicit rows, replaces the explicit list on PUT and refuses a bad
//! row; `ExclusionSet::load` is the union every growth number applies.

use bson::{Bson, Document, doc, oid::ObjectId};
use meshharbor_core::growth::ExclusionSet;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

async fn register(app: &TestApp, email: &str, username: &str, extra: Value) -> String {
    let mut body = json!({
        "email": email,
        "username": username,
        "display_name": username,
        "password": "Password123!",
    });
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            body[k] = v.clone();
        }
    }
    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(status, 201, "register {email}: {text}");
    app.activate_user(email).await;
    let login: Value = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({ "email": email, "password": "Password123!" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_string()
}

async fn stored_attribution(app: &TestApp, email: &str) -> Document {
    app.db
        .collection::<Document>("users")
        .find_one(doc! { "email": email })
        .await
        .expect("query")
        .expect("the account exists")
        .get_document("signup_attribution")
        .expect("stored")
        .clone()
}

/// AC5 — through the register body, the path the SPA takes.
#[tokio::test]
async fn a_signup_stores_the_taxonomys_spelling_of_source_and_medium() {
    let app = TestApp::spawn().await;
    register(
        &app,
        "yt@test.io",
        "ytuser",
        json!({ "attribution": { "source": "YouTub", "medium": "Video", "campaign": "20261019-Slug" } }),
    )
    .await;
    let attr = stored_attribution(&app, "yt@test.io").await;
    assert_eq!(attr.get_str("source").unwrap(), "youtube");
    assert_eq!(attr.get_str("medium").unwrap(), "video");
    assert_eq!(
        attr.get_str("campaign").unwrap(),
        "20261019-Slug",
        "only source and medium are normalised"
    );

    register(
        &app,
        "tw@test.io",
        "twuser",
        json!({ "attribution": { "source": "Twitter", "medium": "POST" } }),
    )
    .await;
    let attr = stored_attribution(&app, "tw@test.io").await;
    assert_eq!(attr.get_str("source").unwrap(), "x");
    assert_eq!(attr.get_str("medium").unwrap(), "post");

    // An unknown source is kept verbatim (lowercased) — reported under
    // `other`, never dropped.
    register(
        &app,
        "md@test.io",
        "mduser",
        json!({ "attribution": { "source": "Mastodon", "medium": "toot" } }),
    )
    .await;
    let attr = stored_attribution(&app, "md@test.io").await;
    assert_eq!(attr.get_str("source").unwrap(), "mastodon");
    assert_eq!(attr.get_str("medium").unwrap(), "toot");
}

/// A tenant row owned by `owner`, written directly: the exclusion set reads
/// only `owner_id`, and the admin's org needs no members or rooms.
async fn insert_tenant(app: &TestApp, owner: ObjectId, slug: &str) -> ObjectId {
    let id = ObjectId::new();
    let now = bson::DateTime::now();
    app.db
        .collection::<Document>("tenants")
        .insert_one(doc! {
            "_id": id,
            "name": slug,
            "slug": slug,
            "description": Bson::Null,
            "icon": Bson::Null,
            "owner_id": owner,
            "plan": "free",
            "features": [],
            "settings": { "default_locale": "en-US" },
            "billing": Bson::Null,
            "integrations": Bson::Null,
            "is_archived": false,
            "created_at": now,
            "updated_at": now,
            "deleted_at": Bson::Null,
        })
        .await
        .expect("insert tenant");
    id
}

#[tokio::test]
async fn exclusions_are_hidden_from_a_non_admin_and_when_growth_is_off() {
    let app = TestApp::spawn().await;
    let token = register(&app, "plain@test.io", "plain", json!({})).await;
    let r = app
        .auth_get("/api/admin/growth/exclusions", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404, "not a platform admin");
    let r = app
        .auth_put("/api/admin/growth/exclusions", &token)
        .json(&json!({ "exclusions": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    // A client with no credential at all — not `app.client`, whose cookie
    // jar still holds the session the login above set.
    let r = reqwest::Client::new()
        .get(app.url("/api/admin/growth/exclusions"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "no token at all");

    // The kill switch: a platform admin on a server with growth OFF.
    let admin_id = ObjectId::new();
    let off = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
        s.growth.enabled = false;
    })
    .await;
    let admin = off
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();
    let r = off
        .auth_get("/api/admin/growth/exclusions", &admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404, "growth.enabled = false");
}

#[tokio::test]
async fn exclusions_list_the_implicit_set_and_replace_the_explicit_one() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let admin = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();
    // The admin's own org, and an archived one: both internal.
    let admin_org = insert_tenant(&app, admin_id, "admin-org").await;
    let archived = insert_tenant(&app, admin_id, "admin-old").await;
    app.db
        .collection::<Document>("tenants")
        .update_one(
            doc! { "_id": archived },
            doc! { "$set": { "deleted_at": bson::DateTime::now() } },
        )
        .await
        .unwrap();
    // A real customer org, created the normal way.
    let cust_token = register(
        &app,
        "cust@test.io",
        "cust",
        json!({ "tenant_name": "Customer Org", "tenant_slug": "customer-org" }),
    )
    .await;
    let tenants: Vec<Value> = app
        .auth_get("/api/tenant", &cust_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cust_org = tenants[0]["id"].as_str().unwrap().to_string();
    let cust_user = app
        .db
        .collection::<Document>("users")
        .find_one(doc! { "email": "cust@test.io" })
        .await
        .unwrap()
        .unwrap()
        .get_object_id("_id")
        .unwrap();

    // GET: the implicit set alone.
    let r: Value = app
        .auth_get("/api/admin/growth/exclusions", &admin.access_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["enabled"], json!(true));
    assert_eq!(r["counts"], json!({ "users": 1, "tenants": 2 }), "{r}");
    let rows = r["exclusions"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{r}");
    assert!(rows.iter().all(|x| x["implicit"] == json!(true)));
    assert!(
        rows.iter()
            .any(|x| x["kind"] == "user" && x["id"] == admin_id.to_hex())
    );
    assert!(
        rows.iter()
            .any(|x| x["kind"] == "tenant" && x["id"] == admin_org.to_hex())
    );
    assert!(
        rows.iter()
            .any(|x| x["kind"] == "tenant" && x["id"] == archived.to_hex()),
        "an archived org an admin owns is still internal"
    );
    assert!(
        !rows.iter().any(|x| x["id"] == cust_org),
        "a customer is counted"
    );

    // PUT: exclude the customer org explicitly; the same org twice folds.
    let r: Value = app
        .auth_put("/api/admin/growth/exclusions", &admin.access_token)
        .json(&json!({ "exclusions": [
            { "kind": "tenant", "id": cust_org, "reason": " field test org " },
            { "kind": "tenant", "id": cust_org, "reason": "again" },
        ] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["counts"], json!({ "users": 1, "tenants": 3 }), "{r}");
    let explicit: Vec<&Value> = r["exclusions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["implicit"] == json!(false))
        .collect();
    assert_eq!(explicit.len(), 1, "{r}");
    assert_eq!(explicit[0]["id"], cust_org);
    assert_eq!(explicit[0]["reason"], "field test org");
    assert_eq!(explicit[0]["by"], admin_id.to_hex());
    assert!(explicit[0]["at"].as_str().unwrap().ends_with('Z'));
    let text = serde_json::to_string(&r).unwrap();
    assert!(!text.contains('@'), "no address in the view: {text}");

    // The set every growth number applies is the union.
    let set = ExclusionSet::load(&app.state.core).await.unwrap();
    assert!(set.user_excluded(&admin_id));
    assert!(set.tenant_excluded(&admin_org));
    assert!(set.tenant_excluded(&archived));
    assert!(set.tenant_excluded(&ObjectId::parse_str(&cust_org).unwrap()));
    assert!(
        !set.user_excluded(&cust_user),
        "the customer's account is not"
    );
    assert_eq!(set.counts(), (1, 3));
    assert_eq!(set.implicit_users, vec![admin_id]);
    assert_eq!(set.explicit.len(), 1);

    // Excluding the customer USER implies their org too, and the org's own
    // explicit row is not duplicated by the implication.
    let r: Value = app
        .auth_put("/api/admin/growth/exclusions", &admin.access_token)
        .json(&json!({ "exclusions": [
            { "kind": "user", "id": cust_user.to_hex(), "reason": "tester" },
        ] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["counts"], json!({ "users": 2, "tenants": 3 }), "{r}");
    let set = ExclusionSet::load(&app.state.core).await.unwrap();
    assert!(set.user_excluded(&cust_user));
    assert!(set.tenant_excluded(&ObjectId::parse_str(&cust_org).unwrap()));
    assert_eq!(
        set.implicit_tenants.len(),
        3,
        "admin's two + the tester's one"
    );

    // A PUT of nothing clears the explicit list and the implication with it.
    let r: Value = app
        .auth_put("/api/admin/growth/exclusions", &admin.access_token)
        .json(&json!({ "exclusions": [] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["counts"], json!({ "users": 1, "tenants": 2 }), "{r}");

    // A bad row is a 400 that names it, and the list is untouched.
    for bad in [
        json!({ "kind": "org", "id": cust_org, "reason": "x" }),
        json!({ "kind": "tenant", "id": "nope", "reason": "x" }),
        json!({ "kind": "tenant", "id": cust_org, "reason": "" }),
        json!({ "kind": "tenant", "id": cust_org, "reason": "r".repeat(201) }),
    ] {
        let r = app
            .auth_put("/api/admin/growth/exclusions", &admin.access_token)
            .json(&json!({ "exclusions": [bad] }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "{bad}");
        let text = r.text().await.unwrap();
        assert!(text.contains("exclusions[0]"), "{text}");
    }
    let set = ExclusionSet::load(&app.state.core).await.unwrap();
    assert!(set.explicit.is_empty());
}
