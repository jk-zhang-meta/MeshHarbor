// SPDX-License-Identifier: AGPL-3.0-only
//! Device login (`mh login`) over real HTTP + Mongo: start → browser preview
//! and decision (session + Origin + MANAGE_AGENTS) → PKCE-bound one-time
//! exchange → the unchanged `/api/agent/enroll`.
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BASE: &str = "/api/native/device-login";
const VERIFIER: &str = "device-login-test-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

fn challenge(v: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

async fn enabled_app() -> TestApp {
    TestApp::spawn_with_settings(|s| s.auth.native_device_login_enabled = true).await
}

async fn start(app: &TestApp, name: &str) -> reqwest::Response {
    app.client
        .post(app.url(BASE))
        .json(&json!({
            "device_name": name, "device_os": "linux",
            "code_challenge": challenge(VERIFIER), "code_challenge_method": "S256",
        }))
        .send()
        .await
        .unwrap()
}

async fn exchange(app: &TestApp, device_code: &str, verifier: &str) -> (u16, Value) {
    let r = app
        .client
        .post(app.url(&format!("{BASE}/exchange")))
        .json(&json!({ "device_code": device_code, "code_verifier": verifier }))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

async fn browser_post(
    app: &TestApp,
    path: &str,
    token: &str,
    origin: Option<&str>,
    body: Value,
) -> (u16, Value) {
    let mut req = app.auth_post(&format!("{BASE}/{path}"), token).json(&body);
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    let r = req.send().await.unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn device_login_enrolls_into_the_approvers_org_exactly_once() {
    let app = enabled_app().await;
    let seeded: SeededTenant = app.seed_tenant("dlogin-happy").await;
    let origin = app.settings.app.frontend_url.clone();

    let r = start(&app, "laptop-1").await;
    assert_eq!(r.status().as_u16(), 201);
    let started: Value = r.json().await.unwrap();
    let user_code = started["user_code"].as_str().unwrap().to_string();
    let device_code = started["device_code"].as_str().unwrap().to_string();
    assert_eq!(user_code.len(), 11, "XXXXX-XXXXX");
    assert!(
        started["verification_uri_complete"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/device-login?code={user_code}"))
    );

    // Not approved yet: the device keeps waiting.
    let (s, b) = exchange(&app, &device_code, VERIFIER).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (400, Some("authorization_pending"))
    );

    // The approval pair is a cookie-style browser call: no trusted Origin, no answer.
    let (s, _) = browser_post(
        &app,
        "preview",
        &seeded.admin.access_token,
        None,
        json!({ "user_code": user_code }),
    )
    .await;
    assert_eq!(s, 403, "preview without a trusted Origin is refused");
    let (s, p) = browser_post(
        &app,
        "preview",
        &seeded.admin.access_token,
        Some(&origin),
        json!({ "user_code": user_code.to_lowercase() }),
    )
    .await;
    assert_eq!(s, 200, "preview: {p}");
    assert_eq!(p["device"]["name"], "laptop-1");
    assert_eq!(p["device"]["os"], "linux");

    // A member without MANAGE_AGENTS cannot approve a device into the org.
    let (s, _) = browser_post(
        &app,
        "decision",
        &seeded.member.access_token,
        Some(&origin),
        json!({ "user_code": user_code, "approve": true, "tenant_id": seeded.tenant_id }),
    )
    .await;
    assert_eq!(s, 403, "a plain member may not approve");

    let (s, d) = browser_post(
        &app,
        "decision",
        &seeded.admin.access_token,
        Some(&origin),
        json!({ "user_code": user_code, "approve": true, "tenant_id": seeded.tenant_id }),
    )
    .await;
    assert_eq!((s, d["status"].as_str()), (200, Some("approved")), "{d}");

    // The device code alone is not enough: the PKCE verifier binds it.
    let (s, b) = exchange(&app, &device_code, &format!("{VERIFIER}x")).await;
    assert_eq!((s, b["error"].as_str()), (400, Some("access_denied")));

    let (s, b) = exchange(&app, &device_code, VERIFIER).await;
    assert_eq!(s, 200, "exchange: {b}");
    assert_eq!(b["tenant_id"].as_str(), Some(seeded.tenant_id.as_str()));
    let token = b["enrollment_token"].as_str().unwrap().to_string();

    // One time only.
    let (s, b) = exchange(&app, &device_code, VERIFIER).await;
    assert_eq!((s, b["error"].as_str()), (400, Some("expired_token")));

    // The token is a standard enrollment token: the unchanged enroll accepts it.
    let ej: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": token, "machine_id": "dlogin-machine-1",
            "machine_name": "laptop-1", "os": "linux", "agent_version": "0.4.151",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ej["tenant_id"].as_str(),
        Some(seeded.tenant_id.as_str()),
        "{ej}"
    );
    assert!(ej["agent_token"].as_str().is_some_and(|t| !t.is_empty()));
}

#[tokio::test]
async fn device_login_is_off_by_default_a_denial_is_final_and_starts_are_bounded() {
    // Default settings: the whole surface answers 503.
    let off = TestApp::spawn().await;
    assert_eq!(start(&off, "laptop-x").await.status().as_u16(), 503);

    let app = enabled_app().await;
    let seeded = app.seed_tenant("dlogin-deny").await;
    let origin = app.settings.app.frontend_url.clone();

    let started: Value = start(&app, "laptop-2").await.json().await.unwrap();
    let user_code = started["user_code"].as_str().unwrap().to_string();
    let device_code = started["device_code"].as_str().unwrap().to_string();
    let (s, d) = browser_post(
        &app,
        "decision",
        &seeded.admin.access_token,
        Some(&origin),
        json!({ "user_code": user_code, "approve": false }),
    )
    .await;
    assert_eq!((s, d["status"].as_str()), (200, Some("denied")));
    let (s, b) = exchange(&app, &device_code, VERIFIER).await;
    assert_eq!((s, b["error"].as_str()), (400, Some("access_denied")));
    // A decided request cannot be decided again (no flipping a denial).
    let (s, _) = browser_post(
        &app,
        "decision",
        &seeded.admin.access_token,
        Some(&origin),
        json!({ "user_code": user_code, "approve": true, "tenant_id": seeded.tenant_id }),
    )
    .await;
    assert_eq!(s, 404);

    // Unknown or malformed codes look the same: not found.
    let (s, _) = browser_post(
        &app,
        "preview",
        &seeded.admin.access_token,
        Some(&origin),
        json!({ "user_code": "BCDFG-HJKLM" }),
    )
    .await;
    assert_eq!(s, 404);
    let (s, _) = browser_post(
        &app,
        "preview",
        &seeded.admin.access_token,
        Some(&origin),
        json!({ "user_code": "{\"$ne\":1}" }),
    )
    .await;
    assert_eq!(s, 404);

    // At most five live requests per client: the sixth is told to slow down.
    // (`laptop-2` is already decided, so it no longer counts.)
    for i in 0..5 {
        assert_eq!(
            start(&app, &format!("bulk-{i}")).await.status().as_u16(),
            201
        );
    }
    assert_eq!(start(&app, "bulk-5").await.status().as_u16(), 429);

    // The device's claims are bounded before anything is stored.
    let r = app
        .client
        .post(app.url(BASE))
        .json(&json!({
            "device_name": "bad\nname", "device_os": "linux",
            "code_challenge": challenge(VERIFIER), "code_challenge_method": "S256",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
}
