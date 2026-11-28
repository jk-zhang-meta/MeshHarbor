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
    let (_, owner_access_sidless) =
        mk_user("owner-sso@example.test", "owner_sso", Some(owner_oid)).await;
    let (recipient_oid, recipient_access_sidless) =
        mk_user("recipient-sso@example.test", "recipient_sso", None).await;
    let (_outsider_oid, outsider_access_sidless) =
        mk_user("outsider-sso@example.test", "outsider_sso", None).await;
    struct SimpleUser {
        id: String,
        access_token: String,
    }
    let owner = SimpleUser {
        id: owner_oid.to_hex(),
        access_token: owner_access_sidless,
    };
    let recipient = SimpleUser {
        id: recipient_oid.to_hex(),
        access_token: recipient_access_sidless,
    };
    let outsider = SimpleUser {
        id: String::new(),
        access_token: outsider_access_sidless,
    };
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
        assert!(matches!(
            req.send().await.unwrap().status().as_u16(),
            401 | 403
        ));
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
        location
            .starts_with("https://www.itachi.fans/meshharbor/native-session-complete?handoff_id="),
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
        .update_one(
            doc! {"_id": owner_oid},
            doc! {"$inc": {"security_rev": 1_i64}},
        )
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

#[tokio::test]
async fn real_node_core_user_session_and_browser_handoff_roundtrip_against_test_app() {
    let edge_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_port = edge_listener.local_addr().unwrap().port();
    let edge_base = format!("http://127.0.0.1:{edge_port}/meshharbor");
    let frontend_for_settings = edge_base.clone();

    let app = TestApp::spawn_with_settings(move |s| {
        s.auth.native_device_login_enabled = true;
        s.app.frontend_url = frontend_for_settings;
    })
    .await;

    // Mount real API behind /meshharbor subpath (mirroring production reverse-proxy prefix)
    let edge_router = axum::Router::new().nest(
        "/meshharbor",
        meshharbor_api::build_router(app.state.clone()),
    );
    let edge_task = tokio::spawn(async move {
        let _ = axum::serve(
            edge_listener,
            edge_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let owner = app
        .register_user(
            "nodecore-sso@example.test",
            "internal_sso",
            "SSO Owner",
            "NativeSsoPass#2026!",
            None,
            None,
        )
        .await;

    let session = grant(&app, &owner.access_token).await;
    let init_refresh = session["refresh_token"].as_str().unwrap();

    // 1. Real meshharbor_node_core::user_session::refresh against /meshharbor subpath
    let refreshed = meshharbor_node_core::user_session::refresh(&edge_base, init_refresh)
        .await
        .expect("node_core refresh succeeded");
    assert_eq!(refreshed.user.id, owner.id);
    assert_eq!(refreshed.user.email, "nodecore-sso@example.test");
    assert!(refreshed.user.email_verified);

    // 2. Real BrowserHandoff::bind + user_session::handoff + BrowserHandoff::serve
    let listener = meshharbor_node_core::user_session::BrowserHandoff::bind()
        .await
        .unwrap();
    let port = listener.port().unwrap();
    let launch_url = listener.launch_url();
    let handoff = meshharbor_node_core::user_session::handoff(
        &edge_base,
        &refreshed.access_token,
        &meshharbor_node_core::user_session::WebTarget::MyDevices,
        port,
    )
    .await
    .expect("node_core handoff succeeded");
    assert_eq!(
        handoff.post_url,
        format!("{edge_base}/api/native/handoff/consume")
    );
    let serve_handle = listener.serve(handoff);

    // 3. Simulated local browser fetches loopback launch_url, parses form, POSTs to post_url with exact Origin
    let html_resp = reqwest::Client::new()
        .get(&launch_url)
        .send()
        .await
        .unwrap();
    assert_eq!(html_resp.status().as_u16(), 200);
    let html = html_resp.text().await.unwrap();
    serve_handle.await.unwrap().unwrap();

    let action_marker = "action=\"";
    let action_start = html.find(action_marker).unwrap() + action_marker.len();
    let action_url = &html[action_start..action_start + html[action_start..].find('"').unwrap()];
    let val_marker = "name=ticket value=\"";
    let val_start = html.find(val_marker).unwrap() + val_marker.len();
    let ticket_val = &html[val_start..val_start + html[val_start..].find('"').unwrap()];

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let consume_resp = no_redirect
        .post(action_url)
        .header("Origin", format!("http://127.0.0.1:{port}"))
        .form(&[("ticket", ticket_val)])
        .send()
        .await
        .unwrap();
    assert_eq!(consume_resp.status().as_u16(), 303);
    let location = consume_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(&format!("{edge_base}/native-session-complete?handoff_id=")));
    let handoff_id = location.split("handoff_id=").nth(1).unwrap();
    let access_cookie = cookie_value(&consume_resp, "access_token").unwrap();

    // 4. Complete browser handoff with cookie only on the same origin
    let origin_only = format!("http://127.0.0.1:{edge_port}");
    let complete_resp = no_redirect
        .post(format!("{edge_base}/api/native/handoff/complete"))
        .header("Origin", &origin_only)
        .header("Cookie", format!("access_token={access_cookie}"))
        .json(&json!({"handoff_id": handoff_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(complete_resp.status().as_u16(), 200);
    let complete_body: Value = complete_resp.json().await.unwrap();
    assert_eq!(complete_body["user"]["id"], owner.id);
    assert_eq!(complete_body["target"], json!({"purpose": "my_devices"}));

    // 5. Real meshharbor_node_core::user_session::revoke invalidates both native refresh and browser cookie
    meshharbor_node_core::user_session::revoke(&edge_base, &refreshed.access_token)
        .await
        .expect("node_core revoke succeeded");
    assert!(
        meshharbor_node_core::user_session::refresh(&edge_base, &refreshed.refresh_token)
            .await
            .is_err()
    );
    assert_eq!(
        no_redirect
            .get(format!("{edge_base}/api/auth/me"))
            .header("Cookie", format!("access_token={access_cookie}"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );

    edge_task.abort();
}

#[tokio::test]
async fn logout_propagates_db_failure_supports_refresh_before_revoke_and_rejects_empty_refresh_body()
 {
    let (app1, app2) = Box::pin(TestApp::spawn_pair(|s| {
        s.auth.native_device_login_enabled = true;
        s.app.frontend_url = "https://www.itachi.fans/meshharbor".into();
        // Fast Mongo failure detection once DbGate is severed so the test stays snappy.
        if !s.database.url.contains('?') {
            s.database
                .url
                .push_str("?serverSelectionTimeoutMS=400&connectTimeoutMS=400");
        }
    }))
    .await;

    let owner = app2
        .register_user(
            "logout-lineage@example.test",
            "internal_logout_lineage",
            "Logout Owner",
            "LogoutPass#2026!",
            None,
            None,
        )
        .await;
    let granted = grant(&app2, &owner.access_token).await;
    let native_access = granted["access_token"].as_str().unwrap();
    let native_refresh = granted["refresh_token"].as_str().unwrap();

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Browser handoff on app2 yields access + refresh cookies sharing native_sid.
    let handoff: Value = app2
        .auth_post("/api/native/handoff", native_access)
        .json(&json!({"purpose": "dashboard", "form_origin": "http://127.0.0.1:45210"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let consumed = no_redirect
        .post(app2.url("/api/native/handoff/consume"))
        .header("Origin", "http://127.0.0.1:45210")
        .form(&[("ticket", handoff["ticket"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(consumed.status().as_u16(), 303);
    let access_cookie = cookie_value(&consumed, "access_token").unwrap();
    let refresh_cookie = cookie_value(&consumed, "refresh_token").unwrap();

    // Fix #5 verification: valid refresh cookie + explicit empty refresh_token body -> 401 (no cookie fallback).
    let empty_body_refresh = no_redirect
        .post(app2.url("/api/auth/refresh"))
        .header("Cookie", format!("refresh_token={refresh_cookie}"))
        .json(&json!({"refresh_token": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(empty_body_refresh.status().as_u16(), 401);

    // Open an active WS connection carrying the native_sid browser cookie on app2.
    let ws_url = format!(
        "{}?token={}",
        app2.base_url.replacen("http://", "ws://", 1) + "/ws",
        access_cookie
    );
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connected");
    let _ = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("connected frame");

    // Fix #1a verification: sever app1's Mongo gate -> logout on app1 must return 503 and NOT clear cookies or revoke.
    app1.sever_db();
    let failed_logout = no_redirect
        .post(app1.url("/api/auth/logout"))
        .header("Cookie", format!("access_token={access_cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(failed_logout.status().as_u16(), 503);
    assert!(cookie_value(&failed_logout, "access_token").is_none());
    assert_eq!(
        no_redirect
            .get(app2.url("/api/auth/me"))
            .header("Cookie", format!("access_token={access_cookie}"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "failed logout must leave session unrevoked until confirmed"
    );

    // Fix #1b verification: browser whose access_token cookie was evicted sends X-Require-Session: 1 -> 401,
    // refreshes via refresh_token cookie, and retries /api/auth/logout -> revokes entire native_sid lineage.
    let require_sess = no_redirect
        .post(app2.url("/api/auth/logout"))
        .header("X-Require-Session", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(require_sess.status().as_u16(), 401);

    let refreshed_resp = no_redirect
        .post(app2.url("/api/auth/refresh"))
        .header("Cookie", format!("refresh_token={refresh_cookie}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed_resp.status().as_u16(), 200);
    let rotated_access = cookie_value(&refreshed_resp, "access_token").unwrap();

    let ok_logout = no_redirect
        .post(app2.url("/api/auth/logout"))
        .header("Cookie", format!("access_token={rotated_access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_logout.status().as_u16(), 200);

    // Native refresh, browser refresh, HTTP /auth/me, and existing WS connection are all invalidated!
    assert_eq!(
        app2.client
            .post(app2.url("/api/auth/refresh"))
            .json(&json!({"refresh_token": native_refresh}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        no_redirect
            .post(app2.url("/api/auth/refresh"))
            .header("Cookie", format!("refresh_token={refresh_cookie}"))
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        no_redirect
            .get(app2.url("/api/auth/me"))
            .header("Cookie", format!("access_token={access_cookie}"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    let _ = ws.send(Message::Text(r#"{"type":"ping"}"#.into())).await;
    let ws_closed = tokio::time::timeout(Duration::from_secs(7), async {
        while let Some(frame) = ws.next().await {
            if matches!(frame, Ok(Message::Close(_)) | Err(_)) {
                break;
            }
        }
    })
    .await;
    assert!(
        ws_closed.is_ok(),
        "existing WS must close after logout revokes native_sid"
    );
}

#[tokio::test]
async fn logout_with_genuinely_expired_access_token_revokes_native_sid_lineage() {
    let app = TestApp::spawn_with_settings(|s| {
        s.auth.native_device_login_enabled = true;
        s.app.frontend_url = "https://www.itachi.fans/meshharbor".into();
    })
    .await;

    let owner = app
        .register_user(
            "expired-access-logout@example.test",
            "internal_exp_logout",
            "Expired Logout",
            "ExpiredPass#2026!",
            None,
            None,
        )
        .await;
    let granted = grant(&app, &owner.access_token).await;
    let live_access = granted["access_token"].as_str().unwrap();
    let live_refresh = granted["refresh_token"].as_str().unwrap().to_owned();

    // Sign an access token carrying the exact same Claims & native_sid, expired beyond 60s leeway.
    let mut claims = app.state.auth.verify_access_token(live_access).unwrap();
    claims.iat -= 600;
    claims.exp = chrono::Utc::now().timestamp() - 180;
    let expired_access = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(app.settings.jwt.secret.as_bytes()),
    )
    .unwrap();

    assert_eq!(
        app.auth_get("/api/auth/me", &expired_access)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401,
        "access token must be genuinely expired before logout"
    );

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let logout_resp = no_redirect
        .post(app.url("/api/auth/logout"))
        .header("Cookie", format!("access_token={expired_access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(logout_resp.status().as_u16(), 200);

    // Even though refresh_token TTL was 7 days, logout via expired access_token revoked native_sid!
    assert_eq!(
        no_redirect
            .post(app.url("/api/auth/refresh"))
            .json(&json!({"refresh_token": live_refresh}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
}

#[tokio::test]
async fn ws_upgrade_preserves_403_401_and_503_admission_statuses() {
    use meshharbor_db::models::AccountApprovalState;

    let (app1, app2) = Box::pin(TestApp::spawn_pair(|s| {
        s.auth.native_device_login_enabled = true;
        s.auth.account_approval.enabled = true;
        s.auth.account_approval.owner_user_id = Some("6ad98b618c7a3357a7f9ef69".to_owned());
        s.app.frontend_url = "https://www.itachi.fans/meshharbor".into();
        if !s.database.url.contains('?') {
            s.database
                .url
                .push_str("?serverSelectionTimeoutMS=400&connectTimeoutMS=400");
        }
    }))
    .await;

    let hash = app2
        .state
        .auth
        .hash_password("WsFixturePass#2026!")
        .unwrap();

    // 1. Pending (policy-denied) user -> WS upgrade must be 403
    let mut pending = app2
        .state
        .users
        .create(
            "ws-pending@example.test".into(),
            "internal_ws_pending".into(),
            "WS Pending".into(),
            hash.clone(),
            None,
        )
        .await
        .unwrap();
    let pending_id = pending.id.unwrap();
    pending.is_verified = true;
    pending.account_approval.state = AccountApprovalState::Pending;
    app2.db
        .collection::<User>("users")
        .replace_one(doc! {"_id": pending_id}, &pending)
        .await
        .unwrap();
    let pending_tokens = app2
        .state
        .auth
        .generate_tokens_at_revision(pending_id, &pending.email, &pending.username, 0)
        .unwrap();

    let pending_ws = app2
        .client
        .get(app2.url(&format!("/ws?token={}", pending_tokens.access_token)))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(pending_ws.status().as_u16(), 403);

    // 2. Approved user -> revoked native_sid (401), DB outage/timeout (503), stale revision (401)
    let mut approved = app2
        .state
        .users
        .create(
            "ws-approved@example.test".into(),
            "internal_ws_approved".into(),
            "WS Approved".into(),
            hash,
            None,
        )
        .await
        .unwrap();
    let approved_id = approved.id.unwrap();
    approved.is_verified = true;
    approved.account_approval.state = AccountApprovalState::Approved;
    app2.db
        .collection::<User>("users")
        .replace_one(doc! {"_id": approved_id}, &approved)
        .await
        .unwrap();
    let approved_tokens = app2
        .state
        .auth
        .generate_tokens_at_revision(approved_id, &approved.email, &approved.username, 0)
        .unwrap();

    let granted = grant(&app2, &approved_tokens.access_token).await;
    let native_access = granted["access_token"].as_str().unwrap();

    // Revoke native_sid -> WS upgrade must be 401 (NOT 403!)
    assert_eq!(
        app2.auth_post("/api/native/session/revoke", native_access)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        204
    );
    let revoked_sid_ws = app2
        .client
        .get(app2.url(&format!("/ws?token={native_access}")))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(revoked_sid_ws.status().as_u16(), 401);

    // 3. Sever app1's DB gate -> WS upgrade must be 503 (NOT 403!)
    app1.sever_db();
    let outage_ws = app1
        .client
        .get(app1.url(&format!("/ws?token={}", approved_tokens.access_token)))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(outage_ws.status().as_u16(), 503);

    // 4. Bump approval_revision on approved user -> stale token WS upgrade must be 401 (NOT 403!)
    app2.db
        .collection::<bson::Document>("users")
        .update_one(
            doc! {"_id": approved_id},
            doc! {"$inc": {"account_approval.revision": 1_i32}},
        )
        .await
        .unwrap();
    let stale_rev_ws = app2
        .client
        .get(app2.url(&format!("/ws?token={}", approved_tokens.access_token)))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(stale_rev_ws.status().as_u16(), 401);
}

#[tokio::test]
async fn personal_device_login_mints_anchor_token_and_defaults_to_system_privileges() {
    let app = TestApp::spawn_with_settings(|s| {
        s.auth.native_device_login_enabled = true;
        s.auth.account_approval.enabled = false;
    })
    .await;
    let owner = app
        .register_user(
            "sys-default-owner@example.com",
            "sys_default_owner",
            "Owner",
            "Owner.Pass.123",
            Some("Sys Org"),
            Some("sys-org"),
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

    let started: Value = app
        .client
        .post(app.url("/api/native/device-login"))
        .json(&json!({
            "device_name": "Personal Workstation",
            "device_os": "windows",
            "purpose": "enrollment_and_user_session",
            "code_challenge": challenge(VERIFIER),
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let decide = app
        .auth_post("/api/native/device-login/decision", &owner.access_token)
        .header("Origin", &app.settings.app.frontend_url)
        .json(&json!({
            "user_code": started["user_code"],
            "approve": true,
            "tenant_id": tid
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(decide.status().as_u16(), 200);

    let exchanged: Value = app
        .client
        .post(app.url("/api/native/device-login/exchange"))
        .json(&json!({
            "device_code": started["device_code"],
            "code_verifier": VERIFIER
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrollment_token = exchanged["enrollment_token"]
        .as_str()
        .expect("enrollment_token minted")
        .to_string();

    let claims = app
        .state
        .auth
        .verify_enrollment_token(&enrollment_token)
        .expect("valid enrollment claims");
    assert!(claims.anchor, "personal device login must mint anchor=true");
    let first_jti = claims.jti.clone();

    let enrolled_resp = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": enrollment_token,
            "machine_id": "mid-personal-win-sys-001",
            "machine_name": "Personal Workstation",
            "os": "windows",
            "agent_version": "0.4.162"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(enrolled_resp.status().as_u16(), 200);
    let enrolled: Value = enrolled_resp.json().await.unwrap();
    let agent_id_str = enrolled["agent_id"].as_str().unwrap().to_string();
    let agent_oid = ObjectId::parse_str(&agent_id_str).unwrap();

    // Verify raw MongoDB document has explicit system/daemon defaults.
    let raw_doc = app
        .state
        .core
        .db
        .collection::<bson::Document>("agents")
        .find_one(doc! { "_id": agent_oid })
        .await
        .unwrap()
        .expect("agent row exists");
    assert_eq!(
        raw_doc
            .get_document("exec_policy")
            .unwrap()
            .get_str("run_as")
            .unwrap(),
        "system"
    );
    assert_eq!(
        raw_doc
            .get_document("ssh_policy")
            .unwrap()
            .get_str("account_mode")
            .unwrap(),
        "daemon"
    );
    assert_eq!(raw_doc.get_str("enrolled_with_jti").unwrap(), first_jti);

    // Second use: POST /api/agent/anchor with the SAME enrollment token succeeds
    // for Windows SYSTEM exec + SYSTEM SSH ceiling.
    let anchor_resp = app
        .client
        .post(app.url("/api/agent/anchor"))
        .json(&json!({
            "enrollment_token": enrollment_token,
            "agent_id": agent_id_str,
            "host_name": "Personal Workstation",
            "force": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        anchor_resp.status().as_u16(),
        200,
        "anchor second_use must succeed on personal device enrollment token"
    );

    // Admin subsequently vetoes exec_policy.mode -> "off" and run_as -> "console_user".
    app.state
        .core
        .db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": agent_oid },
            doc! { "$set": { "exec_policy.mode": "off", "exec_policy.run_as": "console_user" } },
        )
        .await
        .unwrap();

    // Re-login (`Purpose::Enrollment`, e.g. `mh login --replace` or promotion of
    // an unprivileged personal install) updates `enrolled_with_jti` for anchoring
    // while preserving the admin's explicit policy veto!
    let relogin_started: Value = app
        .client
        .post(app.url("/api/native/device-login"))
        .json(&json!({
            "device_name": "Personal Workstation",
            "device_os": "windows",
            "purpose": "enrollment",
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
        .json(&json!({
            "user_code": relogin_started["user_code"],
            "approve": true,
            "tenant_id": tid
        }))
        .send()
        .await
        .unwrap();
    let relogin_exchanged: Value = app
        .client
        .post(app.url("/api/native/device-login/exchange"))
        .json(&json!({
            "device_code": relogin_started["device_code"],
            "code_verifier": VERIFIER
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let relogin_token = relogin_exchanged["enrollment_token"].as_str().unwrap();
    let relogin_claims = app
        .state
        .auth
        .verify_enrollment_token(relogin_token)
        .unwrap();
    assert!(relogin_claims.anchor);
    assert_ne!(relogin_claims.jti, first_jti);

    let re_enrolled = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": relogin_token,
            "machine_id": "mid-personal-win-sys-001",
            "machine_name": "Personal Workstation",
            "os": "windows",
            "agent_version": "0.4.162"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(re_enrolled.status().as_u16(), 200);

    let raw_after = app
        .state
        .core
        .db
        .collection::<bson::Document>("agents")
        .find_one(doc! { "_id": agent_oid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        raw_after
            .get_document("exec_policy")
            .unwrap()
            .get_str("mode")
            .unwrap(),
        "off",
        "re-login must preserve explicit admin veto"
    );
    assert_eq!(
        raw_after
            .get_document("exec_policy")
            .unwrap()
            .get_str("run_as")
            .unwrap(),
        "console_user"
    );
    assert_eq!(
        raw_after.get_str("enrolled_with_jti").unwrap(),
        relogin_claims.jti
    );
}

/// The desktop's "Grant administrator rights": the GUI's saved native session
/// mints the single-use, anchor-capable enrollment token a device-login
/// approval would mint, under the same `MANAGE_AGENTS` gate, through the real
/// client (`mint_promotion_enrollment`) against the real route.
#[tokio::test]
async fn native_session_mints_a_promotion_token_only_with_manage_agents() {
    use meshharbor_node_core::user_session::{
        EnrollmentNotPermitted, SessionDenied, mint_promotion_enrollment,
    };
    let app = TestApp::spawn_with_settings(|s| s.auth.native_device_login_enabled = true).await;
    let seeded = app.seed_tenant("grantsys").await;
    let tenant = seeded.tenant_id.as_str();

    let admin = grant(&app, &seeded.admin.access_token).await;
    let admin_access = admin["access_token"].as_str().unwrap();
    let token = mint_promotion_enrollment(&app.base_url, admin_access, tenant)
        .await
        .expect("an admin's native session mints a promotion token");
    let claims = app
        .state
        .auth
        .verify_enrollment_token(&token)
        .expect("a standard enrollment token");
    assert_eq!(claims.tenant_id, tenant);
    assert!(claims.anchor, "Windows promotion anchors with this token");

    // A plain member's session is refused as a missing right, not a dead session.
    let member = grant(&app, &seeded.member.access_token).await;
    let err = mint_promotion_enrollment(
        &app.base_url,
        member["access_token"].as_str().unwrap(),
        tenant,
    )
    .await
    .unwrap_err();
    assert!(
        err.downcast_ref::<EnrollmentNotPermitted>().is_some(),
        "{err:#}"
    );

    // Once the session is revoked (tray sign-out) it mints nothing.
    let revoked = app
        .auth_post("/api/native/session/revoke", admin_access)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status().as_u16(), 204);
    let err = mint_promotion_enrollment(&app.base_url, admin_access, tenant)
        .await
        .unwrap_err();
    assert!(err.downcast_ref::<SessionDenied>().is_some(), "{err:#}");
}
