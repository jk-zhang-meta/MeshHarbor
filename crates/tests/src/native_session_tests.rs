//! Explicit PKCE user grants, never device credentials, back native web sessions.
use crate::fixtures::test_app::TestApp;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bson::{DateTime, doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use meshharbor_db::models::{DeviceShareGrant, User};
use meshharbor_remote_control::models::{Agent, AgentCaps, OsKind};
use meshharbor_services::dao::agent::AgentDao;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

const VERIFIER: &str = "native-user-session-test-proof-0123456789abcdefghijklmnopqrstuv";

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn grant(app: &TestApp, token: &str) -> Value {
    let started = app
        .client
        .post(app.url("/api/native/device-login"))
        .json(&json!({
            "device_name": "Explicit GUI login",
            "device_os": "linux",
            "purpose": "user_session",
            "code_challenge": challenge(VERIFIER),
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(started.status().as_u16(), 201);
    let started: Value = started.json().await.unwrap();
    let parsed = reqwest::Url::parse(&app.settings.app.frontend_url).unwrap();
    let origin = match parsed.port() {
        Some(p) => format!("{}://{}:{p}", parsed.scheme(), parsed.host_str().unwrap()),
        None => format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap()),
    };
    let preview = app
        .auth_post("/api/native/device-login/preview", token)
        .header("Origin", &origin)
        .json(&json!({"user_code": started["user_code"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status().as_u16(), 200);
    let preview: Value = preview.json().await.unwrap();
    assert_eq!(preview["purpose"], "user_session");
    assert_eq!(preview["requested_scopes"], json!(["user_session"]));
    assert_eq!(preview["personal_device"], false);

    let decision = app
        .auth_post("/api/native/device-login/decision", token)
        .header("Origin", &origin)
        .json(&json!({"user_code": started["user_code"], "approve": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        decision.status().as_u16(),
        200,
        "user-only login needs no enrollment/admin role"
    );
    let exchanged = app
        .client
        .post(app.url("/api/native/device-login/exchange"))
        .json(&json!({"device_code": started["device_code"], "code_verifier": VERIFIER}))
        .send()
        .await
        .unwrap();
    assert_eq!(exchanged.status().as_u16(), 200);
    let body: Value = exchanged.json().await.unwrap();
    assert!(body.get("enrollment_token").is_none());
    body["native_session"].clone()
}

fn cookie_value(resp: &reqwest::Response, name: &str) -> Option<String> {
    for val in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        let raw = val.to_str().ok()?;
        let first = raw.split(';').next()?.trim();
        if let Some((k, v)) = first.split_once('=')
            && k == name
        {
            return Some(v.to_owned());
        }
    }
    None
}

#[tokio::test]
async fn native_user_session_is_explicit_pkce_bound_and_revocable_after_refresh() {
    let app = TestApp::spawn_with_settings(|s| s.auth.native_device_login_enabled = true).await;
    let user = app
        .register_user(
            "native-person@example.test",
            "internal",
            "Person",
            "Native.Password.",
            None,
            None,
        )
        .await;
    let session = grant(&app, &user.access_token).await;
    assert_eq!(session["user"]["id"], user.id);
    assert_eq!(session["user"]["email_verified"], true);
    assert_eq!(
        app.db
            .collection::<bson::Document>("agents")
            .count_documents(bson::doc! {})
            .await
            .unwrap(),
        0
    );
    let access = session["access_token"].as_str().unwrap();
    assert_eq!(
        app.auth_get("/api/auth/me", access)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    let refreshed = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&json!({"refresh_token": session["refresh_token"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed.status().as_u16(), 200);
    let refreshed: Value = refreshed.json().await.unwrap();
    let revoked = app
        .auth_post("/api/native/session/revoke", access)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status().as_u16(), 204);
    for token in [access, refreshed["access_token"].as_str().unwrap()] {
        assert_eq!(
            app.auth_get("/api/auth/me", token)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            401
        );
    }
    let expired = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&json!({"refresh_token": refreshed["refresh_token"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status().as_u16(), 401);
    assert_eq!(
        app.auth_get("/api/auth/me", &user.access_token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "revoking one native sid does not revoke unrelated browser sessions"
    );
}

#[tokio::test]
async fn enrollment_only_omits_session_and_pkce_deny_replay_or_unverified_email_fails() {
    let app = TestApp::spawn_with_settings(|s| s.auth.native_device_login_enabled = true).await;
    let owner = app
        .register_user(
            "enroll-owner@example.test",
            "owner_internal",
            "Owner",
            "Owner.Pass.123",
            Some("Enroll Org"),
            Some("enroll-org"),
        )
        .await;
    let tenants: Vec<Value> = app
        .auth_get("/api/tenant", &owner.access_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tid = tenants[0]["id"].as_str().unwrap();

    // 1. Default enrollment purpose never yields native_session
    let s1: Value = app
        .client
        .post(app.url("/api/native/device-login"))
        .json(&json!({
            "device_name": "Enroll Only Box",
            "device_os": "linux",
            "code_challenge": challenge(VERIFIER),
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        app.auth_post("/api/native/device-login/decision", &owner.access_token)
            .header("Origin", &app.settings.app.frontend_url)
            .json(&json!({"user_code": s1["user_code"], "approve": true, "tenant_id": tid}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    let ex1: Value = app
        .client
        .post(app.url("/api/native/device-login/exchange"))
        .json(&json!({"device_code": s1["device_code"], "code_verifier": VERIFIER}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(ex1["enrollment_token"].is_string());
    assert!(ex1.get("native_session").is_none());

    // Replay of consumed device_code fails
    assert_ne!(
        app.client
            .post(app.url("/api/native/device-login/exchange"))
            .json(&json!({"device_code": s1["device_code"], "code_verifier": VERIFIER}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // 2. Wrong PKCE verifier fails without consuming or minting session
    let s2: Value = app
        .client
        .post(app.url("/api/native/device-login"))
        .json(&json!({
            "device_name": "PKCE Check",
            "device_os": "linux",
            "purpose": "user_session",
            "code_challenge": challenge(VERIFIER),
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    app.auth_post("/api/native/device-login/decision", &owner.access_token)
        .header("Origin", &app.settings.app.frontend_url)
        .json(&json!({"user_code": s2["user_code"], "approve": true}))
        .send()
        .await
        .unwrap();
    assert_ne!(
        app.client
            .post(app.url("/api/native/device-login/exchange"))
            .json(&json!({
                "device_code": s2["device_code"],
                "code_verifier": "wrong-pkce-verifier-value-0123456789abcdefghijklmnopqrstuv"
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // 3. Denied request fails exchange
    let s3: Value = app
        .client
        .post(app.url("/api/native/device-login"))
        .json(&json!({
            "device_name": "Denied Box",
            "device_os": "linux",
            "purpose": "user_session",
            "code_challenge": challenge(VERIFIER),
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        app.auth_post("/api/native/device-login/decision", &owner.access_token)
            .header("Origin", &app.settings.app.frontend_url)
            .json(&json!({"user_code": s3["user_code"], "approve": false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_ne!(
        app.client
            .post(app.url("/api/native/device-login/exchange"))
            .json(&json!({"device_code": s3["device_code"], "code_verifier": VERIFIER}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // 4. Placeholder .invalid email cannot approve user_session
    let placeholder_user = app
        .register_user(
            "legacy@meshharbor.invalid",
            "legacy_internal",
            "Legacy",
            "Legacy.Pass.123",
            None,
            None,
        )
        .await;
    let s4: Value = app
        .client
        .post(app.url("/api/native/device-login"))
        .json(&json!({
            "device_name": "Placeholder Reject",
            "device_os": "linux",
            "purpose": "user_session",
            "code_challenge": challenge(VERIFIER),
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        app.auth_post(
            "/api/native/device-login/decision",
            &placeholder_user.access_token
        )
        .header("Origin", &app.settings.app.frontend_url)
        .json(&json!({"user_code": s4["user_code"], "approve": true}))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16(),
        403
    );
}

#[tokio::test]
async fn agent_jwt_and_sidless_jwt_cannot_handoff_or_revoke_and_ws_revokes_without_account_approval()
{
    let app = TestApp::spawn_with_settings(|s| {
        s.auth.native_device_login_enabled = true;
        s.auth.account_approval.enabled = false;
    })
    .await;
    let user = app
        .register_user(
            "ws-person@example.test",
            "ws_internal",
            "WS Person",
            "Ws.Password.123",
            None,
            None,
        )
        .await;
    let agent_jwt = app
        .state
        .auth
        .issue_agent_token(ObjectId::new(), ObjectId::new(), 0, Some(300))
        .unwrap();

    // AgentJWT rejected (401)
    assert_eq!(
        app.auth_post("/api/native/handoff", &agent_jwt)
            .json(&json!({"purpose": "dashboard", "form_origin": "http://127.0.0.1:43123"}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        app.auth_post("/api/native/session/revoke", &agent_jwt)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );

    // Sid-less user JWT rejected (403)
    assert_eq!(
        app.auth_post("/api/native/handoff", &user.access_token)
            .json(&json!({"purpose": "dashboard", "form_origin": "http://127.0.0.1:43123"}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        app.auth_post("/api/native/session/revoke", &user.access_token)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    // Active WS authenticated with native_sid closes on revoke even when account_approval is OFF
    let session = grant(&app, &user.access_token).await;
    let native_access = session["access_token"].as_str().unwrap();
    let ws_url = format!("ws://{}/ws?token={}", app.addr, native_access);
    let (mut ws, _) = connect_async(&ws_url).await.expect("native ws connects");
    let _ = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;

    assert_eq!(
        app.auth_post("/api/native/session/revoke", native_access)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        204
    );

    // Sending a frame triggers immediate per-Text admission check and closes socket
    let _ = ws.send(Message::Text(r#"{"type":"ping"}"#.into())).await;
    let closed = tokio::time::timeout(Duration::from_secs(6), async {
        while let Some(Ok(msg)) = ws.next().await {
            if matches!(msg, Message::Close(_)) {
                return true;
            }
        }
        true
    })
    .await;
    assert!(closed.is_ok(), "revoked native_sid must close active WS");
}

#[tokio::test]
async fn handoff_enforces_loopback_origin_single_use_cookie_only_complete_and_live_pdp() {
    use meshharbor_db::models::AccountApprovalState;
    let owner_oid = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.auth.native_device_login_enabled = true;
        s.auth.account_approval.enabled = true;
        s.auth.account_approval.owner_user_id = Some(owner_oid.to_hex());
        s.app.frontend_url = "https://www.itachi.fans/meshharbor".into();
    })
    .await;
    let mk_user = |email: &str, name: &str, fixed_id: Option<ObjectId>| {
        let app = &app;
        let email = email.to_owned();
        let name = name.to_owned();
        async move {
            let hash = app.state.auth.hash_password("Test.Pass.123!").unwrap();
            let mut u = app
                .state
                .users
                .create(email, name.clone(), name, hash, None)
                .await
                .unwrap();
            let gen_id = u.id.unwrap();
            let id = fixed_id.unwrap_or(gen_id);
            u.id = Some(id);
            u.is_verified = true;
            u.account_approval.state = AccountApprovalState::Approved;
            let coll = app.db.collection::<User>("users");
            if id != gen_id {
                coll.delete_one(doc! {"_id": gen_id}).await.unwrap();
                coll.insert_one(&u).await.unwrap();
            } else {
                coll.replace_one(doc! {"_id": id}, &u).await.unwrap();
            }
            let tok = app
                .state
                .auth
                .generate_tokens_at_revision(id, &u.email, &u.username, u.account_approval.revision)
                .unwrap()
                .access_token;
            (id, tok)
        }
    };
    let (_, owner_access_sidless) = mk_user("owner-sso@example.test", "owner_sso", Some(owner_oid)).await;
    let (recipient_oid, recipient_access_sidless) = mk_user("recipient-sso@example.test", "recipient_sso", None).await;
    let (_outsider_oid, outsider_access_sidless) = mk_user("outsider-sso@example.test", "outsider_sso", None).await;
    struct SimpleUser { id: String, access_token: String }
    let owner = SimpleUser { id: owner_oid.to_hex(), access_token: owner_access_sidless };
    let recipient = SimpleUser { id: recipient_oid.to_hex(), access_token: recipient_access_sidless };
    let outsider = SimpleUser { id: String::new(), access_token: outsider_access_sidless };
    let tenant_oid = app
        .state
        .tenants
        .create("SSO Org".into(), "sso-org".into(), owner_oid)
        .await
        .unwrap()
        .id
        .unwrap();

    let mut agent = AgentDao::new(&app.db)
        .create(
            tenant_oid,
            owner_oid,
            "SSO Workstation".into(),
            "sso-host".into(),
            OsKind::Linux,
            "0.4.161".into(),
            "not-a-real-token".into(),
            None,
        )
        .await
        .unwrap();
    let agent_oid = agent.id.unwrap();
    agent.capabilities = AgentCaps {
        rpc: vec!["shared-session-lease-v1".into()],
        ..Default::default()
    };
    app.db
        .collection::<Agent>("agents")
        .replace_one(doc! {"_id": agent_oid}, &agent)
        .await
        .unwrap();
    let (_tx, _cancel, _rx) = app.state.fleet().rc_hub.register_agent(
        agent_oid,
        tenant_oid,
        owner_oid,
        OsKind::Linux,
        2,
        false,
        false,
    );

    let owner_native = grant(&app, &owner.access_token).await;
    let owner_access = owner_native["access_token"].as_str().unwrap();
    let outsider_native = grant(&app, &outsider.access_token).await;
    let outsider_access = outsider_native["access_token"].as_str().unwrap();
    let recipient_native = grant(&app, &recipient.access_token).await;
    let recipient_access = recipient_native["access_token"].as_str().unwrap();

    // Bad loopback form_origin rejected at issue
    for bad_origin in [
        "https://127.0.0.1:41234",
        "http://localhost:41234",
        "http://127.0.0.1:0",
        "http://127.0.0.1:04123",
        "http://127.0.0.1:41234/open",
        "http://user@127.0.0.1:41234",
    ] {
        assert_eq!(
            app.auth_post("/api/native/handoff", owner_access)
                .json(&json!({"purpose": "dashboard", "form_origin": bad_origin}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            400,
            "bad form_origin must fail: {bad_origin}"
        );
    }

    // Outsider cannot issue remote handoff for owner's device
    assert_eq!(
        app.auth_post("/api/native/handoff", outsider_access)
            .json(&json!({
                "purpose": "remote",
                "tenant_id": tenant_oid.to_hex(),
                "agent_id": agent_oid.to_hex(),
                "form_origin": "http://127.0.0.1:45111"
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    // Owner issues remote handoff
    let issued_resp = app
        .auth_post("/api/native/handoff", owner_access)
        .json(&json!({
            "purpose": "remote",
            "tenant_id": tenant_oid.to_hex(),
            "agent_id": agent_oid.to_hex(),
            "form_origin": "http://127.0.0.1:45111"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(issued_resp.status().as_u16(), 200);
    let issued: Value = issued_resp.json().await.unwrap();
    assert_eq!(
        issued["post_url"],
        "https://www.itachi.fans/meshharbor/api/native/handoff/consume"
    );
    assert_eq!(issued["expires_in"], 60);
    let ticket = issued["ticket"].as_str().unwrap();

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Missing / null / wrong-port Origin rejected at consume without spending ticket
    for bad_consume_origin in [None, Some("null"), Some("http://127.0.0.1:45112")] {
        let mut req = no_redirect
            .post(app.url("/api/native/handoff/consume"))
            .form(&[("ticket", ticket)]);
        if let Some(o) = bad_consume_origin {
            req = req.header("Origin", o);
        }
        assert!(matches!(req.send().await.unwrap().status().as_u16(), 401 | 403));
    }

    // Valid consume returns 303 to fixed subpath landing + HttpOnly cookies preserving native_sid
    let consumed = no_redirect
        .post(app.url("/api/native/handoff/consume"))
        .header("Origin", "http://127.0.0.1:45111")
        .form(&[("ticket", ticket)])
        .send()
        .await
        .unwrap();
    assert_eq!(consumed.status().as_u16(), 303);
    let location = consumed
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        location.starts_with(
            "https://www.itachi.fans/meshharbor/native-session-complete?handoff_id="
        ),
        "unexpected location: {location}"
    );
    assert!(!location.contains(ticket));
    let handoff_id = location.split("handoff_id=").nth(1).unwrap().to_owned();
    let browser_access_cookie = cookie_value(&consumed, "access_token").expect("access cookie");
    let browser_refresh_cookie = cookie_value(&consumed, "refresh_token").expect("refresh cookie");
    let minted_claims = app
        .state
        .auth
        .verify_access_token(&browser_access_cookie)
        .unwrap();
    assert!(minted_claims.native_sid.is_some());

    // Replay of consumed ticket fails
    assert_eq!(
        no_redirect
            .post(app.url("/api/native/handoff/consume"))
            .header("Origin", "http://127.0.0.1:45111")
            .form(&[("ticket", ticket)])
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );

    // Complete rejects Authorization Bearer override
    assert_eq!(
        no_redirect
            .post(app.url("/api/native/handoff/complete"))
            .header("Origin", "https://www.itachi.fans")
            .header("Cookie", format!("access_token={browser_access_cookie}"))
            .bearer_auth(&owner.access_token)
            .json(&json!({"handoff_id": handoff_id}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    // Complete rejects sid-less cookie or wrong user's native_sid cookie
    let other_session = grant(&app, &owner.access_token).await;
    for wrong_cookie in [
        owner.access_token.as_str(),
        other_session["access_token"].as_str().unwrap(),
        outsider_access,
    ] {
        assert_eq!(
            no_redirect
                .post(app.url("/api/native/handoff/complete"))
                .header("Origin", "https://www.itachi.fans")
                .header("Cookie", format!("access_token={wrong_cookie}"))
                .json(&json!({"handoff_id": handoff_id}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            403
        );
    }

    // Complete succeeds (and is idempotent within TTL) with matching handoff cookie
    for _ in 0..2 {
        let completed = no_redirect
            .post(app.url("/api/native/handoff/complete"))
            .header("Origin", "https://www.itachi.fans")
            .header("Cookie", format!("access_token={browser_access_cookie}"))
            .json(&json!({"handoff_id": handoff_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(completed.status().as_u16(), 200);
        let body: Value = completed.json().await.unwrap();
        assert_eq!(body["user"]["id"], owner.id);
        assert_eq!(
            body["target"],
            json!({
                "purpose": "remote",
                "tenant_id": tenant_oid.to_hex(),
                "agent_id": agent_oid.to_hex(),
            })
        );
    }

    // Share remote handoff: authorized recipient succeeds; revoking share before consume blocks consume
    let share_resp: Value = app
        .auth_post("/api/device-shares", &owner.access_token)
        .json(&json!({
            "device_id": agent_oid.to_hex(),
            "recipient_user_id": recipient_oid.to_hex(),
            "permissions": {"desktop_view": true},
            "tcp_ports": [],
            "expires_in_secs": 600
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let share_id = share_resp["id"].as_str().unwrap();

    let share_handoff: Value = app
        .auth_post("/api/native/handoff", recipient_access)
        .json(&json!({
            "purpose": "device_share_remote",
            "share_id": share_id,
            "form_origin": "http://127.0.0.1:45113"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let share_consumed = no_redirect
        .post(app.url("/api/native/handoff/consume"))
        .header("Origin", "http://127.0.0.1:45113")
        .form(&[("ticket", share_handoff["ticket"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(share_consumed.status().as_u16(), 303);
    let share_hid = share_consumed
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .split("handoff_id=")
        .nth(1)
        .unwrap()
        .to_owned();
    let share_cookie = cookie_value(&share_consumed, "access_token").unwrap();
    let share_done: Value = no_redirect
        .post(app.url("/api/native/handoff/complete"))
        .header("Origin", "https://www.itachi.fans")
        .header("Cookie", format!("access_token={share_cookie}"))
        .json(&json!({"handoff_id": share_hid}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        share_done["target"],
        json!({"purpose": "device_share_remote", "share_id": share_id})
    );

    // Issue second share handoff, then revoke share BEFORE consume -> consume must fail (403/404)
    let share_handoff_2: Value = app
        .auth_post("/api/native/handoff", recipient_access)
        .json(&json!({
            "purpose": "device_share_remote",
            "share_id": share_id,
            "form_origin": "http://127.0.0.1:45114"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    app.db
        .collection::<bson::Document>(DeviceShareGrant::COLLECTION)
        .update_one(
            doc! {"_id": ObjectId::parse_str(share_id).unwrap()},
            doc! {"$set": {"revoked_at": DateTime::now()}},
        )
        .await
        .unwrap();
    let revoked_consume = no_redirect
        .post(app.url("/api/native/handoff/consume"))
        .header("Origin", "http://127.0.0.1:45114")
        .form(&[("ticket", share_handoff_2["ticket"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert!(
        matches!(revoked_consume.status().as_u16(), 403 | 404),
        "revoked share must fail at consume, got {}",
        revoked_consume.status()
    );

    // Credential security_rev bump invalidates browser handoff refresh cookie too
    app.db
        .collection::<User>("users")
        .update_one(doc! {"_id": owner_oid}, doc! {"$inc": {"security_rev": 1_i64}})
        .await
        .unwrap();
    assert_eq!(
        no_redirect
            .post(app.url("/api/auth/refresh"))
            .header("Cookie", format!("refresh_token={browser_refresh_cookie}"))
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
}
