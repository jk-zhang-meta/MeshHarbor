// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-88 P1a — sign-up attribution, end to end against a real server.
//!
//! What is locked here, in the spec's words (§3a, §3c):
//!
//! * a sign-up that arrived with a campaign stores `signup_attribution`
//!   with the SANITISED values, and one without stores no key at all;
//! * a malformed attribution never fails a registration;
//! * the field reaches no user-facing response — asserted on a PLANTED
//!   value across every surface that answers with the account;
//! * it is set once: the profile and tutorial writers leave it alone;
//! * `GET /api/oauth/{provider}?utm_*` parks it in Redis under the CSRF
//!   state with the cookie's TTL and adds no cookie; the callback's collect
//!   is read-and-delete, and the DAO applies it only on CREATE;
//! * the admin view counts sign-ups and activations, 404s a non-admin, and
//!   reports `activated: null` when the fleet module is switched off.

use bson::oid::ObjectId;
use bson::{Document, doc};
use meshharbor_core::attribution::{AttributionInput, oauth_park_key, sanitize, take_for_oauth};
use meshharbor_services::dao::user::UserDao;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

/// The value planted on every attribution field that takes free text. Any
/// response body containing it has leaked the record.
const PLANTED: &str = "PLANTEDSRC";

async fn user_doc(app: &TestApp, email: &str) -> Document {
    app.db
        .collection::<Document>("users")
        .find_one(doc! { "email": email })
        .await
        .expect("query")
        .expect("the account exists")
}

/// Register with an explicit body (the fixture's `register_user` takes no
/// attribution), activate, log in; `(user id, access token, refresh token)`.
async fn register_and_login(
    app: &TestApp,
    email: &str,
    username: &str,
    extra: Value,
) -> (String, String, String) {
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
    (
        login["user"]["id"].as_str().unwrap().to_string(),
        login["access_token"].as_str().unwrap().to_string(),
        login["refresh_token"].as_str().unwrap().to_string(),
    )
}

fn assert_clean(surface: &str, text: &str) {
    // FR-102 normalises `source`/`medium` to lowercase at ingress, so the
    // stored value of those two is the lowercase form — a leak of either
    // spelling is a leak.
    assert!(
        !text.contains(PLANTED) && !text.contains(&PLANTED.to_ascii_lowercase()),
        "{surface} leaked the planted attribution value: {text}"
    );
    assert!(
        !text.to_ascii_lowercase().contains("attribution"),
        "{surface} carries an attribution field: {text}"
    );
}

#[tokio::test]
async fn register_with_attribution_stores_the_sanitised_values() {
    let app = TestApp::spawn().await;
    let over_long = "c".repeat(100);
    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&json!({
            "email": "utm@test.io",
            "username": "utm",
            "display_name": "Utm",
            "password": "Password123!",
            "attribution": {
                "source": "  youtube ",
                "medium": "video",
                "campaign": over_long,
                "content": "short-1",
                "term": "remote desktop",
                "referrer_host": "WWW.YouTube.com",
                "landing_path": "/blog/x/?utm_source=youtube#top",
                "self_reported": "tiktok",
                "bogus": "ignored",
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains("youtube") && !text.contains("attribution"),
        "{text}"
    );

    let attr = user_doc(&app, "utm@test.io").await;
    let attr = attr
        .get_document("signup_attribution")
        .expect("stored with the row by the struct insert");
    assert_eq!(attr.get_str("source").unwrap(), "youtube");
    assert_eq!(attr.get_str("medium").unwrap(), "video");
    assert_eq!(attr.get_str("campaign").unwrap().len(), 64, "clamped");
    assert_eq!(attr.get_str("content").unwrap(), "short-1");
    assert_eq!(attr.get_str("term").unwrap(), "remote desktop");
    assert_eq!(attr.get_str("referrer_host").unwrap(), "www.youtube.com");
    assert_eq!(attr.get_str("landing_path").unwrap(), "/blog/x/");
    assert_eq!(attr.get_str("self_reported").unwrap(), "tiktok");
    assert!(attr.get("bogus").is_none(), "unknown keys are dropped");
    assert!(attr.get_datetime("captured_at").is_ok());
}

/// The control: no attribution, no key — not an empty subdocument.
#[tokio::test]
async fn register_without_attribution_stores_no_key() {
    let app = TestApp::spawn().await;
    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&json!({
            "email": "plain@test.io",
            "username": "plain",
            "display_name": "Plain",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let doc = user_doc(&app, "plain@test.io").await;
    assert!(
        doc.get("signup_attribution").is_none(),
        "no key for a sign-up that carried nothing: {doc:?}"
    );
}

/// A malformed attribution is dropped, and the registration still succeeds.
#[tokio::test]
async fn a_malformed_attribution_never_fails_a_registration() {
    let app = TestApp::spawn().await;
    let cases = [
        ("str@test.io", "strattr", json!("youtube")),
        (
            "num@test.io",
            "numattr",
            json!({ "source": 5, "medium": ["x"] }),
        ),
        (
            "bad@test.io",
            "badattr",
            json!({
                "landing_path": "javascript:alert(1)",
                "referrer_host": "https://evil.example/x",
                "source": "vid\u{e9}o",
            }),
        ),
    ];
    for (email, username, attribution) in cases {
        let resp = app
            .client
            .post(app.url("/api/auth/register"))
            .json(&json!({
                "email": email,
                "username": username,
                "display_name": username,
                "password": "Password123!",
                "attribution": attribution,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201, "{email} must register");
        let doc = user_doc(&app, email).await;
        assert!(
            doc.get("signup_attribution").is_none(),
            "{email}: nothing survives sanitising, so no key: {doc:?}"
        );
    }
}

/// AC2's second half: the field is absent from every user-facing response.
/// Planted on every free-text field, then every surface that answers with
/// the account is read and searched for it.
#[tokio::test]
async fn the_attribution_reaches_no_user_facing_response() {
    let app = TestApp::spawn().await;
    let (uid, access, refresh) = register_and_login(
        &app,
        "hidden@test.io",
        "hidden",
        json!({
            "tenant_name": "Hidden Org",
            "tenant_slug": "hidden-org",
            "attribution": {
                "source": PLANTED,
                "medium": PLANTED,
                "campaign": PLANTED,
                "content": PLANTED,
                "term": PLANTED,
                "self_reported": PLANTED,
            }
        }),
    )
    .await;
    // Stored — the test would otherwise pass by not storing anything. The
    // source is the TAXONOMY's spelling (FR-102: lowercased at ingress); the
    // campaign is kept as sent.
    let doc = user_doc(&app, "hidden@test.io").await;
    let stored = doc.get_document("signup_attribution").unwrap();
    assert_eq!(
        stored.get_str("source").unwrap(),
        PLANTED.to_ascii_lowercase()
    );
    assert_eq!(stored.get_str("campaign").unwrap(), PLANTED);

    let tenants: Vec<Value> = app
        .auth_get("/api/tenant", &access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tid = tenants[0]["id"].as_str().unwrap().to_string();

    let login = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({ "email": "hidden@test.io", "password": "Password123!" }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_clean("POST /api/auth/login", &login);

    let me = app
        .auth_get("/api/auth/me", &access)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(me.contains("hidden@test.io"), "the surface answered: {me}");
    assert_clean("GET /api/auth/me", &me);

    let refreshed = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(refreshed.contains("access_token"), "{refreshed}");
    assert_clean("POST /api/auth/refresh", &refreshed);

    let profile = app
        .auth_get(&format!("/api/user/{uid}"), &access)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(profile.contains("\"hidden\""), "{profile}");
    assert_clean("GET /api/user/{id}", &profile);

    let members = app
        .auth_get(&format!("/api/tenant/{tid}/member"), &access)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(members.contains("hidden@test.io"), "{members}");
    assert_clean("GET /api/tenant/{id}/member", &members);

    let membership = app
        .auth_get(&format!("/api/tenant/{tid}/member/me"), &access)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_clean("GET /api/tenant/{id}/member/me", &membership);
}

/// Set once. The two writers a user has on their own row leave it alone.
#[tokio::test]
async fn the_attribution_is_written_once_and_survives_profile_writes() {
    let app = TestApp::spawn().await;
    let (_uid, access, _refresh) = register_and_login(
        &app,
        "once@test.io",
        "once",
        json!({ "attribution": { "source": "youtube", "campaign": "c1" } }),
    )
    .await;
    let before = user_doc(&app, "once@test.io")
        .await
        .get_document("signup_attribution")
        .unwrap()
        .clone();

    let r = app
        .auth_put("/api/user/me", &access)
        .json(&json!({ "display_name": "Renamed", "bio": "hello" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let r = app
        .auth_put("/api/user/tutorial", &access)
        .json(&json!({ "done": ["get-started"], "seen": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    let after = user_doc(&app, "once@test.io").await;
    assert_eq!(after.get_str("display_name").unwrap(), "Renamed");
    assert_eq!(after.get_document("signup_attribution").unwrap(), &before);
}

/// AC3's server half: the redirect parks the sanitised values under the
/// CSRF state it mints, with the cookie's TTL, and sets no cookie of its own.
#[tokio::test]
async fn oauth_redirect_parks_the_attribution_under_the_csrf_state_with_no_new_cookie() {
    let app = TestApp::spawn_with_oauth().await;
    let redis = app
        .state
        .redis_pubsub
        .as_ref()
        .expect("the test app has redis");

    let cookies_of = |resp: &reqwest::Response| -> Vec<String> {
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    };

    // Control first: a redirect without attribution sets exactly the CSRF
    // cookie and parks nothing.
    let plain = app
        .client
        .get(app.url("/api/oauth/google"))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status().as_u16(), 307);
    let plain_cookies = cookies_of(&plain);
    assert_eq!(plain_cookies.len(), 1, "{plain_cookies:?}");
    assert!(plain_cookies[0].starts_with("oauth_state="));
    let plain_state = plain_cookies[0]
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("oauth_state=")
        .to_string();
    assert_eq!(
        redis.ttl_secs(&oauth_park_key(&plain_state)).await.unwrap(),
        -2
    );
    assert!(take_for_oauth(redis.as_ref(), &plain_state).await.is_none());

    let resp = app
        .client
        .get(app.url(
            "/api/oauth/google?utm_source=youtube&utm_medium=video&utm_campaign=c1\
             &landing_path=%2Fblog%2Fx%2F%3Futm_source%3Dyoutube&referrer_host=youtube.com\
             &self_reported=friend&bogus=1&utm_term=vid%C3%A9o",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 307);
    let cookies = cookies_of(&resp);
    assert_eq!(cookies.len(), 1, "no new cookie: {cookies:?}");
    assert!(cookies[0].starts_with("oauth_state="), "{cookies:?}");
    let state = cookies[0]
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("oauth_state=")
        .to_string();
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    assert!(location.contains(&format!("state={state}")), "{location}");
    assert!(
        !location.contains("utm_") && !location.contains("youtube"),
        "the provider URL carries nothing of it: {location}"
    );

    // Parked with the cookie's TTL (600 s), not forever.
    let ttl = redis.ttl_secs(&oauth_park_key(&state)).await.unwrap();
    assert!((1..=600).contains(&ttl), "ttl {ttl}");

    // Collected once, sanitised, then gone.
    let taken = take_for_oauth(redis.as_ref(), &state)
        .await
        .expect("parked");
    assert_eq!(taken.source.as_deref(), Some("youtube"));
    assert_eq!(taken.medium.as_deref(), Some("video"));
    assert_eq!(taken.campaign.as_deref(), Some("c1"));
    assert_eq!(taken.landing_path.as_deref(), Some("/blog/x/"));
    assert_eq!(taken.referrer_host.as_deref(), Some("youtube.com"));
    assert_eq!(taken.self_reported.as_deref(), Some("friend"));
    assert_eq!(taken.term, None, "non-ASCII is dropped");
    assert_eq!(taken.content, None);
    assert!(taken.captured_at.is_some());
    assert!(
        take_for_oauth(redis.as_ref(), &state).await.is_none(),
        "read-and-delete: a second collect finds nothing"
    );
    assert_eq!(redis.ttl_secs(&oauth_park_key(&state)).await.unwrap(), -2);
}

/// The callback's other half, at the DAO: the parked value lands only when
/// the sign-in CREATES the account. An identity that already has one keeps
/// what it recorded, and linking into a password account writes nothing.
#[tokio::test]
async fn oauth_attribution_is_applied_only_when_the_account_is_created() {
    let app = TestApp::spawn().await;
    let dao = UserDao::new(&app.db);
    let attr = sanitize(AttributionInput::from_value(&json!({
        "source": "tiktok",
        "campaign": "c2",
    })))
    .unwrap();
    let other = sanitize(AttributionInput::from_value(&json!({ "source": "reddit" }))).unwrap();

    let created = dao
        .find_or_create_by_oauth(
            "google",
            "g-attr",
            "attr@test.io",
            "Attr",
            None,
            true,
            Some(attr.clone()),
        )
        .await
        .unwrap();
    assert!(created.created, "a fresh identity creates the account");
    let created = created.user;
    assert_eq!(created.signup_attribution, Some(attr.clone()));

    // Same identity, a different campaign on a later sign-in: unchanged.
    let again = dao
        .find_or_create_by_oauth(
            "google",
            "g-attr",
            "attr@test.io",
            "Attr",
            None,
            true,
            Some(other.clone()),
        )
        .await
        .unwrap();
    assert!(!again.created, "found, not created");
    assert_eq!(again.user.id, created.id);
    assert_eq!(
        dao.base
            .find_by_id(created.id.unwrap())
            .await
            .unwrap()
            .signup_attribution,
        Some(attr.clone())
    );

    // A proven address held by a verified password account: the sign-in
    // LINKS, and the account keeps its (absent) record.
    let pw = dao
        .create(
            "pw@test.io".into(),
            "pwuser".into(),
            "Pw".into(),
            "hash".into(),
            None,
        )
        .await
        .unwrap();
    app.activate_user("pw@test.io").await;
    let linked = dao
        .find_or_create_by_oauth(
            "github",
            "gh-1",
            "pw@test.io",
            "Pw",
            None,
            true,
            Some(other),
        )
        .await
        .unwrap();
    assert!(!linked.created, "linked, not created");
    assert_eq!(linked.user.id, pw.id);
    assert_eq!(linked.user.oauth_providers.len(), 1, "linked");
    assert_eq!(
        dao.base
            .find_by_id(pw.id.unwrap())
            .await
            .unwrap()
            .signup_attribution,
        None
    );
}

/// The callback after the provider has answered, driven without one:
/// `complete_sign_in` is everything `oauth_callback` does past the CSRF
/// check and the code exchange. Locks the redirect (`#signup=1` for a new
/// account only, never a token, the session on the cookies) and the parked
/// attribution's fate (collected once, applied only on create, an absent
/// key still signs in).
#[tokio::test]
async fn oauth_completion_redirects_with_a_signup_marker_and_no_token() {
    use axum::http::header::{LOCATION, SET_COOKIE};
    use meshharbor_api::routes::oauth::complete_sign_in;
    use meshharbor_services::oauth::OAuthUserInfo;

    let app = TestApp::spawn_with_oauth().await;
    let redis = app.state.redis_pubsub.as_ref().expect("redis");
    let identity = |provider_id: &str, email: &str| OAuthUserInfo {
        provider: "google".into(),
        provider_id: provider_id.into(),
        email: email.into(),
        name: "Callback".into(),
        avatar_url: None,
        email_verified: true,
    };
    // The state the redirect minted for this browser, with a campaign parked
    // under it.
    let park = |query: &'static str| {
        let app = &app;
        async move {
            let resp = app
                .client
                .get(app.url(&format!("/api/oauth/google?{query}")))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 307);
            resp.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .trim_start_matches("oauth_state=")
                .to_string()
        }
    };
    let cookies_of = |resp: &axum::response::Response| -> Vec<String> {
        resp.headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    };
    let location_of =
        |resp: &axum::response::Response| resp.headers()[LOCATION].to_str().unwrap().to_string();

    // 1. A new account: `#signup=1`, no token anywhere in the URL, the
    //    session on the cookies, the parked campaign on the row and gone
    //    from Redis.
    let state1 = park("utm_source=youtube&utm_campaign=c1").await;
    let resp = complete_sign_in(&app.state, identity("g-cb-1", "cb1@test.io"), &state1)
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    let location = location_of(&resp);
    assert_eq!(location, "http://localhost:5000/oauth/callback#signup=1");
    let cookies = cookies_of(&resp);
    let access = cookies
        .iter()
        .find_map(|c| c.strip_prefix("access_token="))
        .map(|rest| rest.split(';').next().unwrap().to_string())
        .expect("the session cookie is set");
    assert!(access.len() > 20, "a real JWT: {access}");
    assert!(!location.contains(&access), "the token is not in the URL");
    assert!(!location.contains("token"), "{location}");
    assert!(
        cookies.iter().any(|c| c.starts_with("refresh_token=")),
        "{cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("oauth_state=;")),
        "the one-shot state cookie is cleared: {cookies:?}"
    );
    let row = user_doc(&app, "cb1@test.io").await;
    let attr = row.get_document("signup_attribution").unwrap();
    assert_eq!(attr.get_str("source").unwrap(), "youtube");
    assert_eq!(attr.get_str("campaign").unwrap(), "c1");
    assert_eq!(redis.ttl_secs(&oauth_park_key(&state1)).await.unwrap(), -2);

    // 2. The same identity again, with a DIFFERENT campaign parked: a
    //    returning user — no marker, the key consumed, the row unchanged.
    let state2 = park("utm_source=reddit").await;
    let resp = complete_sign_in(&app.state, identity("g-cb-1", "cb1@test.io"), &state2)
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(location_of(&resp), "http://localhost:5000/oauth/callback");
    assert_eq!(redis.ttl_secs(&oauth_park_key(&state2)).await.unwrap(), -2);
    let row = user_doc(&app, "cb1@test.io").await;
    assert_eq!(
        row.get_document("signup_attribution")
            .unwrap()
            .get_str("source")
            .unwrap(),
        "youtube"
    );

    // 3. Nothing parked (a state whose key expired, or a landing without a
    //    campaign): the sign-in is unaffected, and a new account simply
    //    records nothing.
    let resp = complete_sign_in(
        &app.state,
        identity("g-cb-2", "cb2@test.io"),
        "00000000-0000-4000-8000-000000000000",
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(
        location_of(&resp),
        "http://localhost:5000/oauth/callback#signup=1"
    );
    let row = user_doc(&app, "cb2@test.io").await;
    assert!(row.get("signup_attribution").is_none(), "{row:?}");
}

/// AC5: counts by source and campaign, activation through a real enrollment,
/// a window that excludes, a malformed window, and 404 for a non-admin.
#[tokio::test]
async fn admin_attribution_view_counts_signups_and_activations() {
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

    // A: youtube / c1, creates an org and enrolls a device → activated.
    let (_a_id, a_token, _) = register_and_login(
        &app,
        "a@test.io",
        "usera",
        json!({
            "tenant_name": "Acme Attribution",
            "tenant_slug": "acme-attr",
            "attribution": { "source": "youtube", "medium": "video", "campaign": "c1", "self_reported": "youtube" }
        }),
    )
    .await;
    // B: youtube, no org, no device → not activated.
    register_and_login(
        &app,
        "b@test.io",
        "userb",
        json!({ "attribution": { "source": "youtube", "medium": "video" } }),
    )
    .await;
    // C: nothing recorded, an org, no device.
    register_and_login(
        &app,
        "c@test.io",
        "userc",
        json!({ "tenant_name": "Plain Org", "tenant_slug": "plain-org" }),
    )
    .await;

    let tenants: Vec<Value> = app
        .auth_get("/api/tenant", &a_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tid = tenants[0]["id"].as_str().unwrap().to_string();
    let et: Value = app
        .auth_post(&format!("/api/tenant/{tid}/agent/enroll-token"), &a_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": "mach-attr-1",
            "machine_name": "Attribution box",
            "os": "linux",
            "agent_version": "0.3.0",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(enrolled.status().as_u16(), 200, "enroll");

    let r = app
        .auth_get("/api/admin/stats/attribution", &admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["enabled"], json!(true));
    assert_eq!(body["signups"], json!(3), "{body}");
    assert_eq!(body["attributed"], json!(2), "{body}");
    assert_eq!(body["activated"], json!(1), "{body}");
    // B and C signed up seconds ago with no device: their windows are open,
    // so they are pending, and the denominator for a rate is the one settled
    // sign-up (A), not three.
    assert_eq!(body["pending"], json!(2), "{body}");
    assert_eq!(body["settled"], json!(1), "{body}");
    assert_eq!(body["activation_window_days"], json!(7));
    assert_eq!(body["truncated"], json!(false));
    let find = |dim: &str, key: Value| -> Value {
        body[dim]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["key"] == key)
            .cloned()
            .unwrap_or_else(|| panic!("no {key} in {dim}: {body}"))
    };
    let yt = find("by_source", json!("youtube"));
    assert_eq!(
        (
            yt["signups"].clone(),
            yt["activated"].clone(),
            yt["pending"].clone()
        ),
        (json!(2), json!(1), json!(1))
    );
    let none = find("by_source", Value::Null);
    assert_eq!(
        (
            none["signups"].clone(),
            none["activated"].clone(),
            none["pending"].clone()
        ),
        (json!(1), json!(0), json!(1))
    );
    let c1 = find("by_campaign", json!("c1"));
    assert_eq!(
        (
            c1["signups"].clone(),
            c1["activated"].clone(),
            c1["pending"].clone()
        ),
        (json!(1), json!(1), json!(0))
    );
    assert_eq!(find("by_medium", json!("video"))["signups"], json!(2));
    assert_eq!(
        find("by_self_reported", json!("youtube"))["signups"],
        json!(1)
    );
    // Counts only — no user is named.
    let text = body.to_string();
    for needle in ["a@test.io", "usera", "email", "username"] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }

    // A window in the future holds none of them.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let r = app
        .auth_get(
            &format!(
                "/api/admin/stats/attribution?since={}&until={}",
                now + 3600,
                now + 7200
            ),
            &admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let empty: Value = r.json().await.unwrap();
    assert_eq!(empty["signups"], json!(0));
    assert_eq!(
        empty["activated"],
        json!(0),
        "fleet is mounted: a real zero"
    );
    assert_eq!(empty["pending"], json!(0));
    assert_eq!(empty["settled"], json!(0));
    assert_eq!(empty["by_source"], json!([]));

    // A malformed window is a 400, an inverted one too.
    let r = app
        .auth_get(
            "/api/admin/stats/attribution?since=yesterday",
            &admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let r = app
        .auth_get(
            &format!(
                "/api/admin/stats/attribution?since={}&until={}",
                now,
                now - 10
            ),
            &admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // Anyone else: 404, never 403 — the surface itself is what is hidden.
    let r = app
        .auth_get("/api/admin/stats/attribution", &a_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}

/// AC5's last clause: without `fleet`, `activated` is `null` — "cannot see
/// devices", never "nobody enrolled one".
#[tokio::test]
async fn admin_attribution_view_reports_null_activation_without_fleet() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
        s.modules.fleet = false;
    })
    .await;
    let admin = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();
    register_and_login(
        &app,
        "nofleet@test.io",
        "nofleet",
        json!({ "attribution": { "source": "tiktok" } }),
    )
    .await;

    let r = app
        .auth_get("/api/admin/stats/attribution", &admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["signups"], json!(1));
    assert_eq!(body["attributed"], json!(1));
    assert!(body["activated"].is_null(), "{body}");
    assert!(body["pending"].is_null(), "{body}");
    assert!(body["settled"].is_null(), "{body}");
    let tiktok = &body["by_source"].as_array().unwrap()[0];
    assert_eq!(tiktok["key"], json!("tiktok"));
    assert_eq!(tiktok["signups"], json!(1));
    assert!(tiktok["activated"].is_null(), "{body}");
    assert!(tiktok["pending"].is_null(), "{body}");
}
