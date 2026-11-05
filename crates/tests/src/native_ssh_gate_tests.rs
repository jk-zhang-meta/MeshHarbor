// SPDX-License-Identifier: AGPL-3.0-only
//! Real HTTP/Mongo coverage of X17's default-off authorization gate.
//! Explicit opt-in is used only to prepare valid synthetic requests. It does
//! not establish cross-document revocation or policy-ABA safety.
use crate::fixtures::test_app::TestApp;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bson::{Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_config::AuthSettings;
use meshharbor_db::models::{AccountApprovalState, User};
use meshharbor_remote_control::models::{Agent, OsKind};
use meshharbor_services::dao::agent::AgentDao;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{future::Future, time::Duration};

const BASE: &str = "/api/native/share-ssh/authorizations";
const VERIFIER: &str = "x17-default-gate-synthetic-verifier-012345678901234567890123456789";

// These static labels contain no identities, credentials or request contents.
async fn initialized<T>(stage: &'static str, work: impl Future<Output = T>) -> T {
    eprintln!("X17_GATE stage={stage} begin");
    let value = tokio::time::timeout(Duration::from_secs(30), work)
        .await
        .unwrap_or_else(|_| panic!("X17_GATE stage={stage} initialization timeout"));
    eprintln!("X17_GATE stage={stage} complete");
    value
}

struct Actor {
    id: ObjectId,
    token: String,
}

async fn actor(app: &TestApp, name: &str, fixed: Option<ObjectId>) -> Actor {
    let hash = app
        .state
        .auth
        .hash_password("synthetic-native-gate-password")
        .unwrap();
    let mut user = app
        .state
        .users
        .create(
            format!("{name}@native-gate.example.test"),
            name.into(),
            name.into(),
            hash,
            None,
        )
        .await
        .unwrap();
    let original = user.id.unwrap();
    let id = fixed.unwrap_or(original);
    user.id = Some(id);
    user.is_verified = true;
    user.account_approval.state = AccountApprovalState::Approved;
    let users = app.db.collection::<User>("users");
    if id != original {
        users.delete_one(doc! {"_id": original}).await.unwrap();
        users.insert_one(&user).await.unwrap();
    } else {
        users.replace_one(doc! {"_id": id}, &user).await.unwrap();
    }
    let token = app
        .state
        .auth
        .generate_tokens_at_revision(
            id,
            &user.email,
            &user.username,
            user.account_approval.revision,
        )
        .unwrap()
        .access_token;
    Actor { id, token }
}

fn public_key() -> String {
    // A synthetic public-key wire fixture, never an actual device key.
    let mut bytes = vec![];
    bytes.extend_from_slice(&11u32.to_be_bytes());
    bytes.extend_from_slice(b"ssh-ed25519");
    bytes.extend_from_slice(&32u32.to_be_bytes());
    bytes.extend_from_slice(&[7u8; 32]);
    format!("ssh-ed25519 {}", STANDARD.encode(bytes))
}

async fn json_response(response: reqwest::Response, expected: u16, stage: &str) -> Value {
    assert_eq!(response.status().as_u16(), expected, "{stage} setup status");
    response.json().await.expect("JSON response")
}

async fn preview(app: &TestApp, token: &str, started: &Value) -> Value {
    let id = started["authorization_id"].as_str().unwrap();
    json_response(
        app.auth_post(&format!("{BASE}/{id}/preview"), token)
            .header("Origin", &app.settings.app.frontend_url)
            .json(&json!({"user_code": started["user_code"]}))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap(),
        200,
        "explicit-opt-in preview",
    )
    .await
}

async fn snapshot(app: &TestApp) -> Vec<Document> {
    app.db
        .collection::<Document>("native_ssh_authorizations")
        .find(doc! {})
        .sort(doc! {"_id": 1})
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap()
}

/// Valid credentials, origin and stored requests distinguish the disabled
/// feature from malformed-input, missing-row and account-admission refusals.
/// All four responses are collected before the final assertion, so the first
/// expected RED does not hide the other three routes or their state changes.
#[tokio::test]
async fn native_ssh_default_off_refuses_all_http_transitions_and_preserves_shared_ssh() {
    tokio::time::timeout(Duration::from_secs(120), gate_scenario())
        .await
        .expect("X17_GATE stage=scenario timeout");
}

async fn gate_scenario() {
    eprintln!("X17_GATE stage=config begin");
    let default_enabled = AuthSettings::default().native_share_ssh_authorization_enabled;
    assert!(
        !default_enabled,
        "new native authorization must default off"
    );
    let owner_id = ObjectId::new();
    eprintln!("X17_GATE stage=config complete");
    let app = initialized(
        "default_app",
        TestApp::spawn_with_settings(move |settings| {
            settings.auth.account_approval.enabled = true;
            settings.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            settings.auth.native_share_ssh_authorization_enabled = default_enabled;
            settings.app.frontend_url = "https://native-gate.example.test".into();
            settings.app.pod_id = Some(format!("native-gate-default-{}", ObjectId::new().to_hex()));
        }),
    )
    .await;
    eprintln!("X17_GATE stage=identities begin");
    let owner = actor(&app, "native_gate_owner", Some(owner_id)).await;
    let recipient = actor(&app, "native_gate_recipient", None).await;
    eprintln!("X17_GATE stage=identities complete");
    eprintln!("X17_GATE stage=share_fixture begin");
    let tenant = app
        .state
        .tenants
        .create(
            "Native gate fixture".into(),
            "native-gate-fixture".into(),
            owner.id,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    app.state
        .tenants
        .set_remote_ssh_enabled(tenant, true)
        .await
        .unwrap();
    let device = AgentDao::new(&app.db)
        .create(
            tenant,
            owner.id,
            "Native gate host".into(),
            "native-gate-machine".into(),
            OsKind::Linux,
            "synthetic".into(),
            "synthetic-agent-token-hash".into(),
            None,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    app.db.collection::<Agent>("agents").update_one(doc! {"_id": device}, doc! {"$set": {
        "ssh_host_pubkey": public_key(), "ssh_policy.mode": "on", "ssh_policy.consent_mode": "auto",
        "capabilities.rpc": ["ssh", "ssh-consent", "shared-session-lease-v1", "shared-ssh-stream-v1"],
    }}).await.unwrap();
    let share = json_response(app.auth_post("/api/device-shares", &owner.token)
        .json(&json!({"device_id":device.to_hex(), "recipient_user_id":recipient.id.to_hex(),
            "permissions":{"ssh":true}, "tcp_ports":[22], "expires_in_secs":300, "ssh_account":"alice"}))
        .timeout(Duration::from_secs(10)).send().await.unwrap(), 200, "existing shared-SSH grant").await;
    let share_id = share["id"].as_str().unwrap();

    eprintln!("X17_GATE stage=share_fixture complete");
    eprintln!("X17_GATE stage=shared_ssh_http_checks begin");
    // The switch must not disable the existing shared SSH routes or bypass
    // their recipient and explicit-bearer rules. No SSH payload is claimed.
    let _registration = app
        .state
        .modules
        .fleet
        .as_ref()
        .unwrap()
        .rc_hub
        .register_agent(device, tenant, owner.id, OsKind::Linux, 4, false, false);
    let metadata = format!("/api/device-shares/{share_id}/ssh");
    let _ = json_response(
        app.auth_get(&metadata, &recipient.token)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap(),
        200,
        "existing shared-SSH metadata",
    )
    .await;
    assert_eq!(
        app.auth_get(&metadata, &owner.token)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        app.client
            .get(app.url(&format!("{metadata}/ws")))
            .query(&[("public_key", public_key())])
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Cookie", format!("access_token={}", recipient.token))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );

    eprintln!("X17_GATE stage=shared_ssh_http_checks complete");
    // Same isolated database, distinct pod identity. Only this setup server
    // explicitly opts in; no production handler or fake scope is substituted.
    let mut opted_settings = app.settings.clone();
    opted_settings.auth.native_share_ssh_authorization_enabled = true;
    opted_settings.app.pod_id = Some(format!("native-gate-opt-in-{}", ObjectId::new().to_hex()));
    let opted = initialized(
        "opted_app",
        TestApp::spawn_with_settings(move |settings| *settings = opted_settings),
    )
    .await;
    assert!(opted.settings.auth.native_share_ssh_authorization_enabled);
    let start_body = json!({"share_grant_id":share_id, "public_key":public_key(),
        "code_challenge":URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        "code_challenge_method":"S256", "session_secs":60});
    eprintln!("X17_GATE stage=prepare_authorizations begin");
    let mut prepared = vec![];
    for _ in 0..3 {
        prepared.push(
            json_response(
                opted
                    .client
                    .post(opted.url(BASE))
                    .json(&start_body)
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await
                    .unwrap(),
                201,
                "explicit-opt-in start",
            )
            .await,
        );
    }
    let decision_preview = preview(&opted, &recipient.token, &prepared[1]).await;
    let exchange_preview = preview(&opted, &recipient.token, &prepared[2]).await;
    let exchange_id = prepared[2]["authorization_id"].as_str().unwrap();
    let _ = json_response(
        opted
            .auth_post(&format!("{BASE}/{exchange_id}/decision"), &recipient.token)
            .header("Origin", &opted.settings.app.frontend_url)
            .json(
                &json!({"user_code":prepared[2]["user_code"], "approve":true,
            "expected_scope_revision":exchange_preview["scope_revision"]}),
            )
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap(),
        200,
        "explicit-opt-in decision",
    )
    .await;
    eprintln!("X17_GATE stage=prepare_authorizations complete");
    let before = snapshot(&app).await;
    assert_eq!(
        before.len(),
        3,
        "HTTP setup should create three authorization records"
    );
    let requests = [
        ("start", BASE.to_owned(), start_body, false),
        (
            "preview",
            format!(
                "{BASE}/{}/preview",
                prepared[0]["authorization_id"].as_str().unwrap()
            ),
            json!({"user_code":prepared[0]["user_code"]}),
            true,
        ),
        (
            "decision",
            format!(
                "{BASE}/{}/decision",
                prepared[1]["authorization_id"].as_str().unwrap()
            ),
            json!({"user_code":prepared[1]["user_code"], "approve":true,
                "expected_scope_revision":decision_preview["scope_revision"]}),
            true,
        ),
        (
            "exchange",
            format!("{BASE}/exchange"),
            json!({"device_code":prepared[2]["device_code"], "code_verifier":VERIFIER}),
            false,
        ),
    ];
    let mut observations = vec![];
    for (name, path, body, authenticated) in requests {
        eprintln!("X17_GATE stage=disabled_{name} begin");
        let mut request = app
            .client
            .post(app.url(&path))
            .header("Origin", &app.settings.app.frontend_url)
            .json(&body);
        if authenticated {
            request = request.bearer_auth(&recipient.token);
        }
        let response = request
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let no_cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none();
        let body: Value = response.json().await.expect("gate response JSON");
        let no_authority = [
            "authorization_id",
            "user_code",
            "device_code",
            "scope_revision",
            "grant",
            "scope",
            "access_token",
            "refresh_token",
        ]
        .iter()
        .all(|field| body.get(field).is_none());
        // Do not log authorization documents, hashes, codes or bearer values.
        let unchanged = snapshot(&app).await == before;
        observations.push((name, status, unchanged, no_authority, no_cookie));
        eprintln!("X17_GATE stage=disabled_{name} complete");
    }
    eprintln!("X17_GATE stage=functional_assertion begin");
    assert!(
        observations.iter().all(
            |(_, status, unchanged, no_authority, no_cookie)| *status == 503
                && *unchanged
                && *no_authority
                && *no_cookie
        ),
        "default-off HTTP gate must refuse every transition without side effects; \
         (route, status, unchanged, no_authority, no_cookie)={observations:?}"
    );
}
