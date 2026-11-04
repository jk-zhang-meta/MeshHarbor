// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use crate::fixtures::test_app::TestApp;
use jsonwebtoken::{EncodingKey, Header};
use serde_json::Value;

#[tokio::test]
async fn register_creates_user_and_returns_activation_message() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "alice@test.com",
            "username": "alice",
            "display_name": "Alice",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 201);

    let json: Value = resp.json().await.unwrap();
    assert!(
        json["message"].is_string(),
        "Register should return activation message"
    );
}

#[tokio::test]
async fn register_with_tenant_creates_tenant() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "bob@test.com",
            "username": "bob",
            "display_name": "Bob",
            "password": "Password123!",
            "tenant_name": "Bob's Org",
            "tenant_slug": "bobs-org",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 201);

    // Activate and login to get token
    app.activate_user("bob@test.com").await;
    let login_resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({
            "email": "bob@test.com",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();
    let auth: Value = login_resp.json().await.unwrap();
    let token = auth["access_token"].as_str().unwrap();

    // Verify tenant was created
    let resp = app.auth_get("/api/tenant", token).send().await.unwrap();
    let tenants: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(tenants.len(), 1);
    assert_eq!(tenants[0]["slug"], "bobs-org");
    assert_eq!(tenants[0]["name"], "Bob's Org");
}

#[tokio::test]
async fn register_duplicate_email_fails() {
    let app = TestApp::spawn().await;

    let body = serde_json::json!({
        "email": "dup@test.com",
        "username": "user1",
        "display_name": "User 1",
        "password": "Password123!",
    });

    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);

    // Try same email, different username
    let body2 = serde_json::json!({
        "email": "dup@test.com",
        "username": "user2",
        "display_name": "User 2",
        "password": "Password123!",
    });

    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&body2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409); // Conflict
}

#[tokio::test]
async fn login_with_valid_credentials_succeeds() {
    let app = TestApp::spawn().await;

    // Register first
    app.client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "login@test.com",
            "username": "loginuser",
            "display_name": "Login User",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    // Activate user
    app.activate_user("login@test.com").await;

    // Login
    let resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({
            "email": "login@test.com",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    let json: Value = resp.json().await.unwrap();
    assert!(json["access_token"].is_string());
    assert_eq!(json["user"]["email"], "login@test.com");
}

#[tokio::test]
async fn login_without_activation_fails() {
    let app = TestApp::spawn().await;

    // Register but do NOT activate
    app.client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "unactivated@test.com",
            "username": "unactivated",
            "display_name": "Unactivated",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    // Login should fail with 401
    let resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({
            "email": "unactivated@test.com",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn login_with_wrong_password_fails() {
    let app = TestApp::spawn().await;

    // Register
    app.client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "wrongpw@test.com",
            "username": "wrongpw",
            "display_name": "Wrong PW",
            "password": "Correct123!",
        }))
        .send()
        .await
        .unwrap();

    app.activate_user("wrongpw@test.com").await;

    // Login with wrong password
    let resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({
            "email": "wrongpw@test.com",
            "password": "WrongPassword!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn login_with_nonexistent_email_fails() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({
            "email": "nobody@test.com",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn me_endpoint_returns_current_user() {
    let app = TestApp::spawn().await;

    let user = app
        .register_user(
            "me@test.com",
            "meuser",
            "Me User",
            "Password123!",
            None,
            None,
        )
        .await;

    let resp = app
        .auth_get("/api/auth/me", &user.access_token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["email"], "me@test.com");
    assert_eq!(json["username"], "meuser");
}

#[tokio::test]
async fn me_endpoint_rejects_no_token() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .get(app.url("/api/auth/me"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn me_endpoint_rejects_invalid_token() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .get(app.url("/api/auth/me"))
        .header("Authorization", "Bearer invalid-token-here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn refresh_token_generates_new_access_token() {
    let app = TestApp::spawn().await;

    let user = app
        .register_user(
            "refresh@test.com",
            "refreshuser",
            "Refresh User",
            "Password123!",
            None,
            None,
        )
        .await;

    let resp = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&serde_json::json!({
            "refresh_token": user.refresh_token,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    let json: Value = resp.json().await.unwrap();
    assert!(json["access_token"].is_string());
    // The new access token should be different
    let new_token = json["access_token"].as_str().unwrap();
    // Can use the new token
    let resp = app
        .auth_get("/api/auth/me", new_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn login_with_username_only_succeeds() {
    let app = TestApp::spawn().await;

    // Register first
    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "usernameonly@test.com",
            "username": "usernameonly",
            "display_name": "Username Only",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "Registration should succeed");

    app.activate_user("usernameonly@test.com").await;

    // Login with username only (no email field in the JSON body).
    let resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({
            "username": "usernameonly",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    let json: Value = resp.json().await.unwrap();
    assert!(json["access_token"].is_string());
    assert_eq!(json["user"]["username"], "usernameonly");
}

#[tokio::test]
async fn login_with_email_only_no_username_field() {
    let app = TestApp::spawn().await;

    // Register first
    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "emailonly@test.com",
            "username": "emailonly",
            "display_name": "Email Only",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "Registration should succeed");

    app.activate_user("emailonly@test.com").await;

    // Login with email only (no username field in the JSON body).
    let resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({
            "email": "emailonly@test.com",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    let json: Value = resp.json().await.unwrap();
    assert!(json["access_token"].is_string());
    assert_eq!(json["user"]["email"], "emailonly@test.com");
}

#[tokio::test]
async fn health_check_returns_ok() {
    let app = TestApp::spawn().await;

    let resp = app.client.get(app.url("/health")).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn protected_endpoint_returns_401_with_expired_token() {
    let app = TestApp::spawn().await;

    // Craft an expired JWT using the test secret
    let claims = serde_json::json!({
        "sub": "000000000000000000000000",
        "exp": 0, // epoch = long expired
        "iat": 0,
        "iss": "meshharbor",
    });
    let expired_token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(app.settings.jwt.secret.as_bytes()),
    )
    .expect("Failed to encode expired JWT");

    let resp = app
        .auth_get("/api/auth/me", &expired_token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn tenant_endpoint_returns_401_with_invalid_token() {
    let app = TestApp::spawn().await;

    let resp = app
        .client
        .get(app.url("/api/tenant"))
        .header("Authorization", "Bearer garbage-token-value")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

// ── the refresh cookie (cookie-only sessions, step 3) ──────────────────────
//
// A refresh token is the longest-lived browser credential: 30 days by default,
// and it re-mints access tokens, so it is worth far more to steal than an
// access token. These lock the server half — set it, accept it, clear it —
// which has to be live before the SPA stops keeping it in localStorage.

/// Pull one `Set-Cookie` value by name out of a response.
fn set_cookie<'a>(resp: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
}

#[tokio::test]
async fn login_sets_both_session_cookies() {
    let app = TestApp::spawn().await;
    app.register_user(
        "cookies@test.com",
        "cookieuser",
        "Cookie User",
        "Password123!",
        None,
        None,
    )
    .await;

    let resp = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({ "email": "cookies@test.com", "password": "Password123!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // ⚠️ Both, not one. `HeaderMap::insert` replaces every value for a name, so
    // a second `insert` of Set-Cookie would silently drop the access cookie —
    // this is the assertion that catches that.
    let access = set_cookie(&resp, "access_token").expect("access_token cookie");
    let refresh = set_cookie(&resp, "refresh_token").expect("refresh_token cookie");

    assert!(access.contains("HttpOnly"), "access: {access}");
    assert!(access.contains("Path=/;"), "access: {access}");

    assert!(refresh.contains("HttpOnly"), "refresh: {refresh}");
    // Scoped to the ONE endpoint that spends it, so it stops riding along on
    // every other request.
    assert!(
        refresh.contains("Path=/api/auth/refresh"),
        "the refresh cookie must be path-scoped: {refresh}"
    );
    assert!(refresh.contains("SameSite=Lax"), "refresh: {refresh}");
}

#[tokio::test]
async fn refresh_works_from_the_cookie_with_an_empty_body() {
    let app = TestApp::spawn().await;
    app.register_user(
        "cookieref@test.com",
        "cookierefuser",
        "Cookie Refresh",
        "Password123!",
        None,
        None,
    )
    .await;

    // A cookie store, so the login's Set-Cookie is replayed on the next call —
    // exactly what a browser does.
    let jar = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let login = jar
        .post(app.url("/api/auth/login"))
        .json(&serde_json::json!({ "email": "cookieref@test.com", "password": "Password123!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status().as_u16(), 200);

    // `{}` — no token in the body at all. This is what the SPA will send.
    let resp = jar
        .post(app.url("/api/auth/refresh"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the refresh cookie alone must be enough"
    );
    let json: Value = resp.json().await.unwrap();
    let minted = json["access_token"].as_str().expect("a new access token");
    let me = app.auth_get("/api/auth/me", minted).send().await.unwrap();
    assert_eq!(me.status().as_u16(), 200, "the minted token must work");
}

#[tokio::test]
async fn refresh_still_accepts_the_token_in_the_body() {
    // The compatibility guarantee the UI change depends on: during a rolling
    // deploy a cached bundle still posts the token in the body.
    let app = TestApp::spawn().await;
    let user = app
        .register_user(
            "bodyref@test.com",
            "bodyrefuser",
            "Body Refresh",
            "Password123!",
            None,
            None,
        )
        .await;

    let resp = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": user.refresh_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn refresh_with_neither_cookie_nor_body_is_401() {
    let app = TestApp::spawn().await;
    let resp = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn logout_clears_the_refresh_cookie_too() {
    // Clearing only the access cookie would leave a 30-day credential in the
    // browser that re-mints access tokens — a "logout" that does not log out.
    let app = TestApp::spawn().await;
    let resp = app
        .client
        .post(app.url("/api/auth/logout"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let access = set_cookie(&resp, "access_token").expect("access clear");
    let refresh = set_cookie(&resp, "refresh_token").expect("refresh clear");
    assert!(access.contains("Max-Age=0"), "access: {access}");
    assert!(refresh.contains("Max-Age=0"), "refresh: {refresh}");
    // The attributes must match the ones it was SET with, or the browser keeps
    // the original cookie and the clear is cosmetic.
    assert!(
        refresh.contains("Path=/api/auth/refresh"),
        "a clear on the wrong Path does not remove the cookie: {refresh}"
    );
}
