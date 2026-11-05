// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic HTTP coverage of native shared-SSH policy revision binding.
//! Opt-in is confined to this isolated TestApp; no agent or SSH session is started.
use crate::fixtures::test_app::TestApp;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bson::{doc, oid::ObjectId};
use meshharbor_db::models::{AccountApprovalState, NativeSshAuthorization, User};
use meshharbor_remote_control::models::{Agent, OsKind};
use meshharbor_services::dao::agent::AgentDao;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

const BASE: &str = "/api/native/share-ssh/authorizations";
const VERIFIER: &str = "x17-revision-synthetic-verifier-012345678901234567890123456789";

struct Actor {
    id: ObjectId,
    token: String,
}

async fn actor(app: &TestApp, name: &str, fixed: Option<ObjectId>) -> Actor {
    let hash = app
        .state
        .auth
        .hash_password("synthetic-native-revision-password")
        .unwrap();
    let mut user = app
        .state
        .users
        .create(
            format!("{name}@native-revision.example.test"),
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
    // Synthetic public wire bytes, not a device key or an authentication secret.
    let mut bytes = vec![];
    bytes.extend_from_slice(&11u32.to_be_bytes());
    bytes.extend_from_slice(b"ssh-ed25519");
    bytes.extend_from_slice(&32u32.to_be_bytes());
    bytes.extend_from_slice(&[7u8; 32]);
    format!("ssh-ed25519 {}", STANDARD.encode(bytes))
}

async fn json_response(response: reqwest::Response, expected: u16, stage: &str) -> Value {
    // Never include proof codes, bearer values or response contents in failures.
    assert_eq!(response.status().as_u16(), expected, "{stage} setup status");
    response.json().await.expect("JSON response")
}

async fn set_tenant_ssh(app: &TestApp, tenant: ObjectId, owner: &Actor, enabled: bool) {
    let body = json_response(
        app.auth_put(&format!("/api/tenant/{tenant}/ssh-settings"), &owner.token)
            .json(&json!({"remote_ssh_enabled": enabled}))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap(),
        200,
        "real tenant SSH policy management route",
    )
    .await;
    assert_eq!(body["remote_ssh_enabled"].as_bool(), Some(enabled));
}

async fn approve_request(app: &TestApp, recipient: &Actor, share: &Value) -> Value {
    let started = json_response(
        app.client
            .post(app.url(BASE))
            .json(
                &json!({"share_grant_id":share["id"], "public_key":public_key(),
                "code_challenge":URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
                "code_challenge_method":"S256", "session_secs":60}),
            )
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap(),
        201,
        "authorization start",
    )
    .await;
    let authorization_id =
        ObjectId::parse_str(started["authorization_id"].as_str().unwrap()).unwrap();
    let previewed = json_response(
        app.auth_post(
            &format!("{BASE}/{authorization_id}/preview"),
            &recipient.token,
        )
        .header("Origin", &app.settings.app.frontend_url)
        .json(&json!({"user_code":started["user_code"]}))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap(),
        200,
        "authorization preview",
    )
    .await;
    let approved = json_response(
        app.auth_post(
            &format!("{BASE}/{authorization_id}/decision"),
            &recipient.token,
        )
        .header("Origin", &app.settings.app.frontend_url)
        .json(&json!({"user_code":started["user_code"], "approve":true,
                "expected_scope_revision":previewed["scope_revision"]}))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap(),
        200,
        "authorization approval",
    )
    .await;
    assert_eq!(approved["status"].as_str(), Some("approved"));
    started
}

async fn exchange(app: &TestApp, started: &Value) -> reqwest::Response {
    app.client
        .post(app.url(&format!("{BASE}/exchange")))
        .json(&json!({"device_code":started["device_code"], "code_verifier":VERIFIER}))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap()
}

/// Both management writes finish before exchange begins. This tests completed
/// policy ABA, not the separately accepted window for an already in-flight read.
#[tokio::test]
async fn native_ssh_tenant_policy_aba_refuses_previously_approved_exchange() {
    tokio::time::timeout(Duration::from_secs(90), tenant_policy_aba())
        .await
        .expect("X17_REVISION stage=scenario timeout");
}

async fn tenant_policy_aba() {
    let owner_id = ObjectId::new();
    eprintln!("X17_REVISION stage=app begin");
    let app = tokio::time::timeout(
        Duration::from_secs(30),
        TestApp::spawn_with_settings(move |settings| {
            settings.auth.account_approval.enabled = true;
            settings.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            // Test-only opt-in while production remains default off.
            settings.auth.native_share_ssh_authorization_enabled = true;
            settings.app.frontend_url = "https://native-revision.example.test".into();
            settings.app.pod_id = Some(format!("native-revision-{}", ObjectId::new().to_hex()));
        }),
    )
    .await
    .expect("X17_REVISION stage=app initialization timeout");
    assert!(app.settings.auth.native_share_ssh_authorization_enabled);
    eprintln!("X17_REVISION stage=app complete");
    eprintln!("X17_REVISION stage=fixture begin");
    let owner = actor(&app, "native_revision_owner", Some(owner_id)).await;
    let recipient = actor(&app, "native_revision_recipient", None).await;
    let tenant = app
        .state
        .tenants
        .create(
            "Native revision fixture".into(),
            "native-revision-fixture".into(),
            owner.id,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    set_tenant_ssh(&app, tenant, &owner, true).await;
    let device = AgentDao::new(&app.db)
        .create(
            tenant,
            owner.id,
            "Native revision host".into(),
            "native-revision-machine".into(),
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
    let share = json_response(
        app.auth_post("/api/device-shares", &owner.token)
            .json(
                &json!({"device_id":device.to_hex(), "recipient_user_id":recipient.id.to_hex(),
                "permissions":{"ssh":true}, "tcp_ports":[22], "expires_in_secs":300,
                "ssh_account":"alice"}),
            )
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap(),
        200,
        "share creation",
    )
    .await;
    eprintln!("X17_REVISION stage=fixture complete");
    eprintln!("X17_REVISION stage=approval begin");
    let started = approve_request(&app, &recipient, &share).await;
    let authorization_id =
        ObjectId::parse_str(started["authorization_id"].as_str().unwrap()).unwrap();
    let authorizations = app
        .db
        .collection::<NativeSshAuthorization>(NativeSshAuthorization::COLLECTION);
    let before = authorizations
        .find_one(doc! {"authorization_id": authorization_id})
        .await
        .unwrap()
        .expect("approved authorization exists");
    assert_eq!(before.state, "approved");
    assert!(before.grant_hash.is_none() && before.grant_expires_at.is_none());
    eprintln!("X17_REVISION stage=approval complete");

    // Exercise the production management handler/DAO, not a fixture-only $set.
    eprintln!("X17_REVISION stage=policy_off begin");
    set_tenant_ssh(&app, tenant, &owner, false).await;
    eprintln!("X17_REVISION stage=policy_off complete");
    eprintln!("X17_REVISION stage=policy_on begin");
    set_tenant_ssh(&app, tenant, &owner, true).await;
    eprintln!("X17_REVISION stage=policy_on complete");

    eprintln!("X17_REVISION stage=exchange begin");
    let response = exchange(&app, &started).await;
    let status = response.status().as_u16();
    let body: Value = response.json().await.expect("exchange response JSON");
    let no_grant = body.get("grant").is_none();
    let after = authorizations
        .find_one(doc! {"authorization_id": authorization_id})
        .await
        .unwrap()
        .expect("authorization still exists after rejected exchange");
    let not_exchanged = after.state != "exchanged";
    let no_stored_grant = after.grant_hash.is_none() && after.grant_expires_at.is_none();
    eprintln!("X17_REVISION stage=exchange complete");
    eprintln!("X17_REVISION stage=functional_assertion begin");
    assert!(
        status == 403 && no_grant && not_exchanged && no_stored_grant,
        "completed tenant policy ABA must invalidate old approval; \
         status={status}, no_grant={no_grant}, not_exchanged={not_exchanged}, \
         no_stored_grant={no_stored_grant}"
    );

    // A newly approved request after the policy change remains usable. A
    // blanket refusal after ABA must not satisfy the stale-approval check.
    eprintln!("X17_REVISION stage=fresh_approval begin");
    let fresh = approve_request(&app, &recipient, &share).await;
    let fresh_body = json_response(exchange(&app, &fresh).await, 200, "fresh exchange").await;
    assert!(
        fresh_body["grant"]
            .as_str()
            .is_some_and(|grant| !grant.is_empty())
    );
    let fresh_row = authorizations
        .find_one(doc! {"authorization_id": ObjectId::parse_str(fresh["authorization_id"].as_str().unwrap()).unwrap()})
        .await.unwrap().unwrap();
    assert!(fresh_row.state == "exchanged" && fresh_row.grant_hash.is_some());
    eprintln!("X17_REVISION stage=fresh_approval complete");

    eprintln!("X17_REVISION stage=legacy_revision begin");
    let legacy = approve_request(&app, &recipient, &share).await;
    let legacy_id = ObjectId::parse_str(legacy["authorization_id"].as_str().unwrap()).unwrap();
    app.db
        .collection::<bson::Document>("tenants")
        .update_one(doc! {"_id": tenant}, doc! {"$unset": {"security_rev": ""}})
        .await
        .unwrap();
    let missing_tenant = json_response(
        exchange(&app, &legacy).await,
        403,
        "missing tenant revision refuses exchange",
    )
    .await;
    assert!(missing_tenant.get("grant").is_none());

    // A genuine management write can initialize the legacy tenant, but must
    // not make an approval without a revision binding exchangeable again.
    app.db
        .collection::<bson::Document>(NativeSshAuthorization::COLLECTION)
        .update_one(
            doc! {"authorization_id": legacy_id},
            doc! {"$unset": {"scope.binding.security.tenant_security_rev": ""}},
        )
        .await
        .unwrap();
    set_tenant_ssh(&app, tenant, &owner, true).await;
    let missing_binding = json_response(
        exchange(&app, &legacy).await,
        403,
        "missing approval revision remains refused",
    )
    .await;
    assert!(missing_binding.get("grant").is_none());
    let legacy_row = authorizations
        .find_one(doc! {"authorization_id": legacy_id})
        .await
        .unwrap()
        .unwrap();
    assert!(
        legacy_row.state == "approved"
            && legacy_row.grant_hash.is_none()
            && legacy_row.grant_expires_at.is_none()
    );
    eprintln!("X17_REVISION stage=legacy_revision complete");
}

/// The real Mongo update must reject corrupt/exhausted counters without
/// changing either policy field; no HTTP authentication shortcut can hide it.
#[tokio::test]
async fn native_ssh_tenant_revision_writes_are_atomic_and_fail_closed() {
    tokio::time::timeout(Duration::from_secs(90), tenant_revision_writes())
        .await
        .expect("X17_REVISION stage=writer_scenario timeout");
}

async fn tenant_revision_writes() {
    let app = tokio::time::timeout(Duration::from_secs(30), TestApp::spawn())
        .await
        .expect("X17_REVISION stage=writer_app initialization timeout");
    assert!(!app.settings.auth.native_share_ssh_authorization_enabled);
    let tenant = app
        .state
        .tenants
        .create(
            "Revision writer fixture".into(),
            "revision-writer-fixture".into(),
            ObjectId::new(),
        )
        .await
        .unwrap();
    let id = tenant.id.unwrap();
    assert_eq!(tenant.security_rev, Some(1));
    let first = app
        .state
        .tenants
        .set_remote_ssh_enabled(id, true)
        .await
        .unwrap();
    assert!(first.security_rev == Some(2) && first.settings.remote_ssh_enabled);
    let repeated = app
        .state
        .tenants
        .set_remote_ssh_enabled(id, true)
        .await
        .unwrap();
    assert!(repeated.security_rev == Some(3) && repeated.settings.remote_ssh_enabled);
    let archived = app.state.tenants.set_archived(id, true).await.unwrap();
    assert!(archived.security_rev == Some(4) && archived.is_archived);
    let restored = app.state.tenants.set_archived(id, false).await.unwrap();
    assert!(restored.security_rev == Some(5) && !restored.is_archived);

    let documents = app.db.collection::<bson::Document>("tenants");
    for (case, invalid) in [
        bson::Bson::Null,
        bson::Bson::Boolean(true),
        bson::Bson::String("1".into()),
        bson::Bson::Double(1.0),
        bson::Bson::Int64(0),
        bson::Bson::Int64(-1),
        bson::Bson::Int64(i64::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        documents
            .update_one(doc! {"_id": id}, doc! {"$set": {"security_rev": invalid}})
            .await
            .unwrap();
        let before = documents.find_one(doc! {"_id": id}).await.unwrap().unwrap();
        let ssh_rejected = app
            .state
            .tenants
            .set_remote_ssh_enabled(id, false)
            .await
            .is_err();
        let archive_rejected = app.state.tenants.set_archived(id, true).await.is_err();
        let after = documents.find_one(doc! {"_id": id}).await.unwrap().unwrap();
        assert!(
            ssh_rejected && archive_rejected && before == after,
            "invalid revision case {case} must reject both writers without mutation"
        );
    }

    documents
        .update_one(doc! {"_id": id}, doc! {"$unset": {"security_rev": ""}})
        .await
        .unwrap();
    let initialized = app
        .state
        .tenants
        .set_remote_ssh_enabled(id, false)
        .await
        .unwrap();
    assert!(initialized.security_rev == Some(1) && !initialized.settings.remote_ssh_enabled);
    documents
        .update_one(doc! {"_id": id}, doc! {"$unset": {"security_rev": ""}})
        .await
        .unwrap();
    let initialized = app.state.tenants.set_archived(id, true).await.unwrap();
    assert!(initialized.security_rev == Some(1) && initialized.is_archived);

    // The last representable increment succeeds once. It then leaves no
    // revision budget for another policy write; neither counter nor policy
    // may wrap, turn into a floating point number or change again.
    documents
        .update_one(
            doc! {"_id": id},
            doc! {"$set": {"security_rev": i64::MAX - 1}},
        )
        .await
        .unwrap();
    let last = app
        .state
        .tenants
        .set_remote_ssh_enabled(id, true)
        .await
        .unwrap();
    assert!(last.security_rev == Some(i64::MAX) && last.settings.remote_ssh_enabled);
    let before = documents.find_one(doc! {"_id": id}).await.unwrap().unwrap();
    assert!(app.state.tenants.set_archived(id, false).await.is_err());
    assert!(documents.find_one(doc! {"_id": id}).await.unwrap().unwrap() == before);
}
