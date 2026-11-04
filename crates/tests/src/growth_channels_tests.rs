// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P8 — social reach: the ingest key, the two ingest routes and the
//! Channels table, against a real server and a fake purestat (spec §3j).
//!
//! * **AC18**, exactly: a snapshot pushed twice is stored once; an unknown
//!   platform is refused; a body carrying post text is refused; a wrong
//!   ingest key gets 404 — and so do a missing, malformed or revoked one, a
//!   platform admin's JWT, `growth.enabled = false` and an unmounted `saas`,
//!   each the same empty 404 a path that does not exist answers.
//! * The keys: minted once (the key in that answer only), stored as a hash,
//!   platform-admin only.
//! * The Channels join: each platform's own reach per snapshot age, then
//!   visitors → sign-ups → activated by each post's normalised key, spend
//!   with its n; a platform with nothing pushed reads `not_measured`; and
//!   the Campaigns table's `reach` column filled from the same posts.

use bson::{Document, doc};
use meshharbor_services::dao::{
    growth_key::GROWTH_KEYS,
    growth_social::{GROWTH_POST_SNAPSHOTS, GROWTH_POSTS},
};
use serde_json::{Value, json};

use crate::{
    fixtures::test_app::TestApp,
    growth_campaigns_tests::{
        admin_app, at_day, count, ds, fake_purestat, get_json, row, seed_signups, today,
    },
};

const POSTS: &str = "/api/admin/growth/ingest/posts";
const SNAPSHOTS: &str = "/api/admin/growth/ingest/snapshots";

/// Mint an ingest key as the admin; `(key, id)`.
async fn mint(app: &TestApp, token: &str) -> (String, String) {
    let r = app
        .auth_post("/api/admin/growth/keys", token)
        .json(&json!({ "kind": "ingest", "label": "promotion pipeline" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    let j: Value = r.json().await.unwrap();
    (
        j["key"].as_str().unwrap().to_string(),
        j["id"].as_str().unwrap().to_string(),
    )
}

/// POST `body` to an ingest route with `key` as the bearer (none when
/// `None`), from a client with no cookie jar. `(status, body text)`.
async fn push_raw(app: &TestApp, path: &str, key: Option<&str>, body: &str) -> (u16, String) {
    let mut req = reqwest::Client::new()
        .post(app.url(path))
        .header("content-type", "application/json")
        .body(body.to_string());
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

async fn push(app: &TestApp, path: &str, key: &str, body: &Value) -> (u16, Value) {
    let (status, text) = push_raw(app, path, Some(key), &body.to_string()).await;
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn post_body(platform: &str, id: &str, published: &str) -> Value {
    json!({
        "platform": platform,
        "platform_id": id,
        "account": "roomler-ai",
        "format": "post",
        "url": format!("https://www.linkedin.com/feed/update/{id}/"),
        "published_at": published,
        "utm_source": "LinkedIn",
        "utm_medium": "post",
        "utm_campaign": "C1",
        "cost_cents": 5000,
    })
}

fn snapshot_body(platform: &str, id: &str, label: &str, metrics: Value) -> Value {
    let taken = bson::DateTime::now().try_to_rfc3339_string().unwrap();
    json!({ "platform": platform, "platform_id": id, "snapshot": label,
            "taken_at": taken, "metrics": metrics })
}

fn yesterday_at(h: u32) -> String {
    at_day(today() - chrono::Duration::days(1), h)
        .try_to_rfc3339_string()
        .unwrap()
}

/// AC18 (1) — a post re-pushed is one row (unchanged, then updated); a
/// snapshot pushed twice is stored ONCE, with the first push's numbers; a
/// snapshot for a post never pushed is refused.
#[tokio::test]
async fn ac18_a_snapshot_pushed_twice_is_stored_once() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let (key, _) = mint(&app, &token).await;
    let body = post_body("linkedin", "urn:li:share:1", &yesterday_at(9));

    let (s, j) = push(&app, POSTS, &key, &body).await;
    assert_eq!((s, j["status"].as_str()), (201, Some("created")), "{j}");
    let (s, j) = push(&app, POSTS, &key, &body).await;
    assert_eq!((s, j["status"].as_str()), (200, Some("unchanged")), "{j}");
    let mut changed = body.clone();
    changed["cost_cents"] = json!(7000);
    let (s, j) = push(&app, POSTS, &key, &changed).await;
    assert_eq!((s, j["status"].as_str()), (200, Some("updated")), "{j}");
    assert_eq!(count(&app, GROWTH_POSTS, doc! {}).await, 1);
    let stored = app
        .db
        .collection::<Document>(GROWTH_POSTS)
        .find_one(doc! {})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.get_i64("cost_cents").unwrap(), 7000);
    assert_eq!(stored.get_str("platform").unwrap(), "linkedin");
    assert_eq!(
        stored
            .get_document("key")
            .unwrap()
            .get_str("campaign")
            .unwrap(),
        "c1",
        "the key is normalised as a sign-up's is"
    );

    let snap = snapshot_body(
        "linkedin",
        "urn:li:share:1",
        "T+1d",
        json!({ "impressions": 1000, "clicks": 50 }),
    );
    let (s, j) = push(&app, SNAPSHOTS, &key, &snap).await;
    assert_eq!((s, j["status"].as_str()), (201, Some("created")), "{j}");
    let again = snapshot_body(
        "linkedin",
        "urn:li:share:1",
        "T+1d",
        json!({ "impressions": 99999 }),
    );
    let (s, j) = push(&app, SNAPSHOTS, &key, &again).await;
    assert_eq!((s, j["status"].as_str()), (200, Some("duplicate")), "{j}");
    assert_eq!(
        count(&app, GROWTH_POST_SNAPSHOTS, doc! {}).await,
        1,
        "stored once"
    );
    let stored = app
        .db
        .collection::<Document>(GROWTH_POST_SNAPSHOTS)
        .find_one(doc! {})
        .await
        .unwrap()
        .unwrap();
    let metrics = stored.get_document("metrics").unwrap();
    assert_eq!(
        metrics.get_f64("impressions").unwrap(),
        1000.0,
        "the first push's numbers"
    );
    assert_eq!(metrics.get_f64("clicks").unwrap(), 50.0);
    // A later age is its own row.
    let (s, _) = push(
        &app,
        SNAPSHOTS,
        &key,
        &snapshot_body(
            "linkedin",
            "urn:li:share:1",
            "T+7d",
            json!({ "impressions": 3000 }),
        ),
    )
    .await;
    assert_eq!(s, 201);
    assert_eq!(count(&app, GROWTH_POST_SNAPSHOTS, doc! {}).await, 2);

    // A snapshot for a post never pushed.
    let (s, j) = push(
        &app,
        SNAPSHOTS,
        &key,
        &snapshot_body(
            "linkedin",
            "urn:li:share:404",
            "T+1d",
            json!({ "impressions": 1 }),
        ),
    )
    .await;
    assert_eq!((s, j["error"].as_str()), (422, Some("unknown_post")), "{j}");
    assert_eq!(count(&app, GROWTH_POST_SNAPSHOTS, doc! {}).await, 2);
}

/// AC18 (2, 3) — an unknown platform and any post text are refused, and
/// nothing is stored.
#[tokio::test]
async fn ac18_an_unknown_platform_and_a_body_with_post_text_are_refused() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let (key, _) = mint(&app, &token).await;
    let good = post_body("linkedin", "urn:li:share:2", &yesterday_at(9));

    let mut unknown = good.clone();
    unknown["platform"] = json!("mastodon");
    let (s, j) = push(&app, POSTS, &key, &unknown).await;
    assert_eq!(
        (s, j["error"].as_str()),
        (422, Some("unknown_platform")),
        "{j}"
    );

    for field in [
        "caption",
        "text",
        "title",
        "body",
        "description",
        "postText",
    ] {
        let mut with_text = good.clone();
        with_text[field] = json!("Remote desktop without port forwarding — here is how.");
        let (s, j) = push(&app, POSTS, &key, &with_text).await;
        assert_eq!(
            (s, j["error"].as_str()),
            (422, Some("post_text_refused")),
            "{field}: {j}"
        );
    }
    let mut snap = snapshot_body(
        "linkedin",
        "urn:li:share:2",
        "T+1d",
        json!({ "impressions": 1 }),
    );
    snap["caption"] = json!("hello");
    let (s, j) = push(&app, SNAPSHOTS, &key, &snap).await;
    assert_eq!(
        (s, j["error"].as_str()),
        (422, Some("post_text_refused")),
        "{j}"
    );
    let (s, j) = push(
        &app,
        SNAPSHOTS,
        &key,
        &snapshot_body(
            "linkedin",
            "urn:li:share:2",
            "T+1d",
            json!({ "impressions": "a lot" }),
        ),
    )
    .await;
    assert_eq!(
        (s, j["error"].as_str()),
        (422, Some("metric_not_numeric")),
        "{j}"
    );
    let (s, _) = push_raw(&app, POSTS, Some(&key), "{not json").await;
    assert_eq!(s, 400);
    let (s, _) = push_raw(&app, POSTS, Some(&key), &"x".repeat(20 * 1024)).await;
    assert_eq!(s, 413, "the body is bounded");

    assert_eq!(count(&app, GROWTH_POSTS, doc! {}).await, 0);
    assert_eq!(count(&app, GROWTH_POST_SNAPSHOTS, doc! {}).await, 0);
    // The control: the same body without the text is stored.
    let (s, _) = push(&app, POSTS, &key, &good).await;
    assert_eq!(s, 201);
}

/// AC18 (4) — every way of not holding a live ingest key is the same empty
/// 404 a path that does not exist answers: never 401, never 403.
#[tokio::test]
async fn ac18_a_missing_wrong_or_revoked_key_gets_404_never_401() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let (key, key_id) = mint(&app, &token).await;
    let body = post_body("linkedin", "urn:li:share:3", &yesterday_at(9)).to_string();
    let (absent_status, absent_body) = push_raw(
        &app,
        "/api/admin/growth/ingest/nothing-here",
        Some(&key),
        &body,
    )
    .await;
    assert_eq!(absent_status, 404);

    let wrong = format!("rgi_{}", "A".repeat(32));
    for (label, k) in [
        ("no key", None),
        ("malformed", Some("rgi_short")),
        ("well-formed, unknown", Some(wrong.as_str())),
        (
            "another kind's shape",
            Some("ps_0123456789abcdef0123456789abcdef"),
        ),
        ("a platform admin's JWT", Some(token.as_str())),
    ] {
        for path in [POSTS, SNAPSHOTS] {
            let (s, text) = push_raw(&app, path, k, &body).await;
            assert_eq!(s, 404, "{label} on {path}");
            assert_eq!(
                text, absent_body,
                "{label}: the body of a path that does not exist"
            );
        }
    }
    // A GET with a wrong key is a 404 too: the gate runs before the method.
    let r = reqwest::Client::new()
        .get(app.url(POSTS))
        .header("authorization", format!("Bearer {wrong}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // The live key works …
    let (s, _) = push_raw(&app, POSTS, Some(&key), &body).await;
    assert_eq!(s, 201);
    // … until it is revoked.
    let r = app
        .client
        .delete(app.url(&format!("/api/admin/growth/keys/{key_id}")))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    let (s, text) = push_raw(&app, POSTS, Some(&key), &body).await;
    assert_eq!((s, text.as_str()), (404, absent_body.as_str()), "revoked");
    let (_, list) = get_json(&app, "/api/admin/growth/keys", &token).await;
    assert_eq!(list["keys"][0]["live"], false);
    assert!(list["keys"][0]["revoked_at"].is_string());

    // The kill switch: a live key on a server whose growth surface is off.
    let (off, off_token) = admin_app(&base, "good", |s| s.growth.enabled = false).await;
    let (off_key, _) = {
        // Minting is a growth route too — off here; write a key directly.
        let (k, raw) = meshharbor_services::dao::growth_key::GrowthKeyDao::new(&off.db)
            .mint(
                meshharbor_services::dao::growth_key::GrowthKeyKind::Ingest,
                "test",
                bson::oid::ObjectId::new(),
                bson::DateTime::now(),
            )
            .await
            .unwrap();
        (raw, k)
    };
    let (s, _) = push_raw(&off, POSTS, Some(&off_key), &body).await;
    assert_eq!(s, 404, "growth.enabled = false");
    let (s, _) = get_json(&off, "/api/admin/growth/keys", &off_token).await;
    assert_eq!(s, 404);

    // Without `saas` the routes do not exist at all.
    let (bare, _) = admin_app(&base, "good", |s| s.modules.saas = false).await;
    let (raw, _) = {
        let (k, raw) = meshharbor_services::dao::growth_key::GrowthKeyDao::new(&bare.db)
            .mint(
                meshharbor_services::dao::growth_key::GrowthKeyKind::Ingest,
                "test",
                bson::oid::ObjectId::new(),
                bson::DateTime::now(),
            )
            .await
            .unwrap();
        (raw, k)
    };
    let (s, _) = push_raw(&bare, POSTS, Some(&raw), &body).await;
    assert_eq!(s, 404, "saas unmounted");
}

/// The keys: the key in the mint answer only, a hash at rest, the list
/// without either, platform-admin only, a ceiling on live keys.
#[tokio::test]
async fn ingest_keys_are_minted_once_stored_hashed_and_admin_only() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let (key, id) = mint(&app, &token).await;
    assert!(key.starts_with("rgi_") && key.len() == 36, "{key}");

    let stored = app
        .db
        .collection::<Document>(GROWTH_KEYS)
        .find_one(doc! {})
        .await
        .unwrap()
        .unwrap();
    let text = stored.to_string();
    assert!(!text.contains(&key), "the key is never stored: {text}");
    assert!(!text.contains(&key[12..]));
    assert_eq!(stored.get_str("prefix").unwrap(), &key[..12]);
    assert_eq!(stored.get_str("hash").unwrap().len(), 64);

    let (s, list) = get_json(&app, "/api/admin/growth/keys", &token).await;
    assert_eq!(s, 200);
    assert_eq!(list["ingest_mounted"], true);
    assert_eq!(list["keys"][0]["id"], id.as_str());
    assert_eq!(list["keys"][0]["prefix"], &key[..12]);
    assert!(!list.to_string().contains(&key[12..]), "{list}");
    assert!(list["keys"][0].get("hash").is_none());

    // Refusals: an unknown kind, an empty label. (P10 — `read` is the
    // second kind and mints, with its own prefix and its own ceiling.)
    let r = app
        .auth_post("/api/admin/growth/keys", &token)
        .json(&json!({ "kind": "read", "label": "pipeline results" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    let read: Value = r.json().await.unwrap();
    assert!(read["key"].as_str().unwrap().starts_with("rgr_"), "{read}");
    assert_eq!(read["kind"], "read");
    for bad in [
        json!({ "kind": "write", "label": "x" }),
        json!({ "kind": "ingest", "label": "" }),
    ] {
        let r = app
            .auth_post("/api/admin/growth/keys", &token)
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "{bad}");
    }
    // At most ten live keys of a kind.
    for _ in 1..10 {
        mint(&app, &token).await;
    }
    let r = app
        .auth_post("/api/admin/growth/keys", &token)
        .json(&json!({ "kind": "ingest", "label": "one too many" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    // The ceiling is per kind: a second read key still mints.
    let r = app
        .auth_post("/api/admin/growth/keys", &token)
        .json(&json!({ "kind": "read", "label": "a second reader" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);

    // Hidden from everyone else.
    let plain = app
        .register_user(
            "plain@test.io",
            "plain",
            "Plain",
            "Password123!",
            None,
            None,
        )
        .await;
    let (s, _) = get_json(&app, "/api/admin/growth/keys", &plain.access_token).await;
    assert_eq!(s, 404);
    let r = app
        .auth_post("/api/admin/growth/keys", &plain.access_token)
        .json(&json!({ "kind": "ingest", "label": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let r = app
        .client
        .delete(app.url(&format!("/api/admin/growth/keys/{id}")))
        .header("authorization", format!("Bearer {}", plain.access_token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let (s, _) = get_json(&app, "/api/admin/growth/channels", &plain.access_token).await;
    assert_eq!(s, 404);
}

/// The Channels join, with the Campaigns table's reach column: each
/// platform's own numbers per snapshot age, then what each post's key
/// brought, spend with its n; the platforms without posts not measured.
#[tokio::test]
async fn the_channels_view_joins_reach_visitors_signups_and_spend_by_each_posts_key() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let y = seed_signups(&app).await;
    let day = ds(y);
    let (key, _) = mint(&app, &token).await;
    let published = yesterday_at(9);

    // LinkedIn/post/C1 with a cost; the key purestat folds from two spellings.
    let (s, _) = push(
        &app,
        POSTS,
        &key,
        &post_body("linkedin", "urn:li:share:9", &published),
    )
    .await;
    assert_eq!(s, 201);
    // YouTube with a content — matched at that depth.
    let mut yt = post_body("youtube", "dQw4w9WgXcQ", &published);
    yt["url"] = json!("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
    yt["utm_source"] = json!("youtub");
    yt["utm_medium"] = json!("video");
    yt["utm_campaign"] = json!("20261019-ssh");
    yt["utm_content"] = json!("desc-top");
    yt.as_object_mut().unwrap().remove("cost_cents");
    assert_eq!(push(&app, POSTS, &key, &yt).await.0, 201);
    // X with a key purestat never saw.
    let mut x = post_body("x", "1849000000000000001", &published);
    x["url"] = json!("https://x.com/roomler_ai/status/1849000000000000001");
    x["utm_source"] = json!("x");
    x["utm_campaign"] = json!("c9");
    x.as_object_mut().unwrap().remove("cost_cents");
    assert_eq!(push(&app, POSTS, &key, &x).await.0, 201);
    for (platform, id, label, metrics) in [
        (
            "linkedin",
            "urn:li:share:9",
            "T+1d",
            json!({ "impressions": 1000, "clicks": 50 }),
        ),
        ("youtube", "dQw4w9WgXcQ", "T+1d", json!({ "views": 120 })),
    ] {
        let (s, j) = push(
            &app,
            SNAPSHOTS,
            &key,
            &snapshot_body(platform, id, label, metrics),
        )
        .await;
        assert_eq!(s, 201, "{j}");
    }

    let (s, j) = get_json(
        &app,
        &format!("/api/admin/growth/channels?since={day}&until={day}"),
        &token,
    )
    .await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(j["ingest_mounted"], true);
    let platform = |name: &str| -> Value {
        j["platforms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["platform"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name} in {}", j["platforms"]))
    };
    let li = platform("linkedin");
    let s = &li["summary"];
    assert_eq!(s["posts"], 1);
    assert_eq!(s["reach"][0]["snapshot"], "T+1d");
    assert_eq!(s["reach"][0]["metrics"]["impressions"], 1000.0);
    assert_eq!(s["reach"][0]["metrics"]["clicks"], 50.0);
    assert_eq!(s["web"]["visitors"], 55);
    assert_eq!(s["signups"], 1);
    assert_eq!(s["activated"]["count"], 1);
    // P4 — measured (saas is mounted), nobody paid: a zero.
    assert_eq!(s["paid"]["count"], 0);
    assert_eq!(s["spend"]["cost_cents"], 5000);
    assert_eq!(s["spend"]["per_visitor"]["n"], 55);
    assert_eq!(s["spend"]["per_visitor"]["cents"], 90.91);
    assert_eq!(s["spend"]["per_signup"]["n"], 1);
    assert!(
        s["spend"]["per_signup"].get("cents").is_none(),
        "n < 30: no value"
    );
    let p = &li["posts"][0];
    assert_eq!(p["platform_id"], "urn:li:share:9");
    assert_eq!(p["key"]["campaign"], "c1");
    assert_eq!(p["reach"]["snapshot"], "T+1d");
    assert_eq!(p["web"]["visitors"], 55);
    let yt = platform("youtube");
    assert_eq!(yt["posts"][0]["key"]["content"], "desc-top");
    assert_eq!(
        yt["posts"][0]["web"]["visitors"], 7,
        "matched at content depth"
    );
    assert_eq!(yt["posts"][0]["signups"], 1);
    assert_eq!(yt["summary"]["reach"][0]["metrics"]["views"], 120.0);
    let xp = platform("x");
    assert_eq!(xp["posts"][0]["web"]["visitors"], 0, "a measured zero");
    assert_eq!(xp["posts"][0]["signups"], 1);
    assert_eq!(
        xp["posts"][0]["reach"]["not_measured"],
        "no snapshot pushed yet"
    );
    for name in ["facebook", "tiktok"] {
        assert_eq!(
            platform(name)["summary"]["not_measured"],
            "no posts pushed for this platform in the range",
            "{name}"
        );
    }
    assert!(
        j["platforms"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["platform"] != "instagram"),
        "a retired platform without data is not listed"
    );
    assert!(!j.to_string().contains("@test.io"), "no person: {j}");

    // The Campaigns table's reach column, from the same posts.
    let (_, c) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}"),
        &token,
    )
    .await;
    let li_row = row(&c, "linkedin", Some("c1"));
    assert_eq!(li_row["reach"][0]["platform"], "linkedin");
    assert_eq!(li_row["reach"][0]["posts"], 1);
    assert_eq!(
        li_row["reach"][0]["at"][0]["metrics"]["impressions"],
        1000.0
    );
    assert_eq!(
        row(&c, "x", Some("c9"))["reach"][0]["at"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "a post with no snapshot: listed, no ages"
    );

    // The daily digest's social section: yesterday's posts per platform,
    // and a snapshot taken yesterday with its post's campaign.
    let mut taken_yesterday = snapshot_body(
        "linkedin",
        "urn:li:share:9",
        "T+7d",
        json!({ "impressions": 3000 }),
    );
    taken_yesterday["taken_at"] = json!(yesterday_at(20));
    assert_eq!(push(&app, SNAPSHOTS, &key, &taken_yesterday).await.0, 201);
    let sections = meshharbor_api::growth::digest::compute(
        &app.state,
        y,
        &meshharbor_core::growth::ExclusionSet::none(),
        bson::DateTime::now(),
    )
    .await
    .unwrap();
    let social = serde_json::to_value(&sections.social).unwrap();
    let li_posts = social["posts_by_platform"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["platform"] == "linkedin")
        .cloned()
        .unwrap_or_else(|| panic!("{social}"));
    assert_eq!(li_posts["posts"]["day"], 1);
    assert_eq!(social["snapshots"][0]["campaign"], "c1");
    assert_eq!(social["snapshots"][0]["snapshot"], "T+7d");
    assert_eq!(social["snapshots"][0]["metrics"]["impressions"], 3000.0);
    assert_eq!(
        social["snapshots"].as_array().unwrap().len(),
        1,
        "only the snapshot taken that day"
    );

    // A revoked purestat key: the web cells say why; reach and the account
    // plane stand; no cost per visitor without visitors.
    let (app2, token2) = admin_app(&base, "revoked", |_| {}).await;
    seed_signups(&app2).await;
    let (key2, _) = mint(&app2, &token2).await;
    assert_eq!(
        push(
            &app2,
            POSTS,
            &key2,
            &post_body("linkedin", "urn:li:share:9", &published)
        )
        .await
        .0,
        201
    );
    let (_, j2) = get_json(
        &app2,
        &format!("/api/admin/growth/channels?since={day}&until={day}"),
        &token2,
    )
    .await;
    assert!(
        j2["web_not_measured"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("unauthorized"),
        "{j2}"
    );
    let li2 = j2["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["platform"] == "linkedin")
        .unwrap();
    assert!(li2["summary"]["web"]["not_measured"].is_string());
    assert!(li2["summary"]["web"].get("visitors").is_none(), "never a 0");
    assert_eq!(li2["summary"]["signups"], 1);
    assert!(li2["summary"]["spend"]["per_visitor"].is_null());
}
