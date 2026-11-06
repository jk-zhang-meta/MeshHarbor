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

    // Same numeric value, wrong BSON width: it must not match an Int64
    // approval or become usable through the administrative fallback.
    eprintln!("X17_REVISION stage=integer_width begin");
    let narrow = approve_request(&app, &recipient, &share).await;
    app.db
        .collection::<bson::Document>("tenants")
        .update_one(
            doc! {"_id": tenant},
            doc! {"$set": {"security_rev": bson::Bson::Int32(1)}},
        )
        .await
        .unwrap();
    let refused = json_response(
        exchange(&app, &narrow).await,
        403,
        "Int32 is not a valid revision",
    )
    .await;
    assert!(refused.get("grant").is_none());
    set_tenant_ssh(&app, tenant, &owner, false).await;
    let stored = app
        .db
        .collection::<bson::Document>("tenants")
        .find_one(doc! {"_id": tenant})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.get("security_rev"), Some(&bson::Bson::Int32(1)));
    let row = authorizations
        .find_one(doc! {"authorization_id":
        ObjectId::parse_str(narrow["authorization_id"].as_str().unwrap()).unwrap()})
        .await
        .unwrap()
        .unwrap();
    assert!(row.state == "approved" && row.grant_hash.is_none());
    eprintln!("X17_REVISION stage=integer_width complete");
}

/// Claude's 18:02 correction: corrupt counters deny native authority, while
/// existing administrative setters remain available and preserve the raw value.
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
    assert_eq!(tenant.security_revision(), Some(1));
    let first = app
        .state
        .tenants
        .set_remote_ssh_enabled(id, true)
        .await
        .unwrap();
    assert!(first.security_revision() == Some(2) && first.settings.remote_ssh_enabled);
    let repeated = app
        .state
        .tenants
        .set_remote_ssh_enabled(id, true)
        .await
        .unwrap();
    assert!(repeated.security_revision() == Some(3) && repeated.settings.remote_ssh_enabled);
    let archived = app.state.tenants.set_archived(id, true).await.unwrap();
    assert!(archived.security_revision() == Some(4) && archived.is_archived);
    let restored = app.state.tenants.set_archived(id, false).await.unwrap();
    assert!(restored.security_revision() == Some(5) && !restored.is_archived);

    let documents = app.db.collection::<bson::Document>("tenants");
    for (case, invalid) in [
        bson::Bson::Null,
        bson::Bson::Boolean(true),
        bson::Bson::String("1".into()),
        bson::Bson::Double(1.0),
        bson::Bson::Int32(1),
        bson::Bson::Int64(0),
        bson::Bson::Int64(-1),
        bson::Bson::Int64(i64::MAX),
        bson::Bson::Array(vec![bson::Bson::Int64(1)]),
        bson::Bson::Document(doc! {"value": 1_i64}),
    ]
    .into_iter()
    .enumerate()
    {
        documents
            .update_one(
                doc! {"_id": id},
                doc! {"$set": {"security_rev": invalid.clone()}},
            )
            .await
            .unwrap();
        let closed = app
            .state
            .tenants
            .set_remote_ssh_enabled(id, false)
            .await
            .unwrap();
        let archived = app.state.tenants.set_archived(id, true).await.unwrap();
        let reopened = app
            .state
            .tenants
            .set_remote_ssh_enabled(id, true)
            .await
            .unwrap();
        let restored = app.state.tenants.set_archived(id, false).await.unwrap();
        let after = documents.find_one(doc! {"_id": id}).await.unwrap().unwrap();
        assert!(
            !closed.settings.remote_ssh_enabled
                && archived.is_archived
                && reopened.settings.remote_ssh_enabled
                && !restored.is_archived
                && closed.security_revision().is_none()
                && [&closed, &archived, &reopened, &restored]
                    .iter()
                    .all(|row| row.security_rev.as_ref() == Some(&invalid))
                && after.get("security_rev") == Some(&invalid),
            "invalid revision case {case} must preserve management and deny native authority"
        );
    }

    // A recovered valid Int64 uses the incrementing path, not the invalid
    // fallback. This sequential check does not claim to exercise the CAS race.
    documents
        .update_one(doc! {"_id": id}, doc! {"$set": {"security_rev": 7_i64}})
        .await
        .unwrap();
    let recovered = app
        .state
        .tenants
        .set_remote_ssh_enabled(id, false)
        .await
        .unwrap();
    assert!(recovered.security_revision() == Some(8) && !recovered.settings.remote_ssh_enabled);

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
    assert!(initialized.security_revision() == Some(1) && !initialized.settings.remote_ssh_enabled);
    documents
        .update_one(doc! {"_id": id}, doc! {"$unset": {"security_rev": ""}})
        .await
        .unwrap();
    let initialized = app.state.tenants.set_archived(id, true).await.unwrap();
    assert!(initialized.security_revision() == Some(1) && initialized.is_archived);

    // The last representable increment exhausts native authority. Later
    // management still works without wrapping or changing the raw counter.
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
    assert!(
        last.security_rev == Some(bson::Bson::Int64(i64::MAX))
            && last.security_revision().is_none()
            && last.settings.remote_ssh_enabled
    );
    let restored = app.state.tenants.set_archived(id, false).await.unwrap();
    assert!(!restored.is_archived && restored.security_rev == Some(bson::Bson::Int64(i64::MAX)));
    let after = documents.find_one(doc! {"_id": id}).await.unwrap().unwrap();
    assert_eq!(
        after.get("security_rev"),
        Some(&bson::Bson::Int64(i64::MAX))
    );
}

/// Invalid counters must close native authorization without preventing the
/// owner's existing administrative kill switches. All identities are synthetic.
#[tokio::test]
async fn native_ssh_invalid_tenant_revision_allows_restrictions_and_preserves_missing_404() {
    tokio::time::timeout(Duration::from_secs(120), invalid_revision_restrictions())
        .await
        .expect("X17_RESTRICT stage=scenario timeout");
}

async fn restriction_fixture(
    app: &TestApp,
    owner: &Actor,
    recipient: &Actor,
    case: usize,
) -> (ObjectId, Value) {
    let tenant = app
        .state
        .tenants
        .create(
            format!("Restriction fixture {case}"),
            format!("restriction-fixture-{case}"),
            owner.id,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    set_tenant_ssh(app, tenant, owner, true).await;
    let device = AgentDao::new(&app.db)
        .create(
            tenant,
            owner.id,
            format!("Restriction host {case}"),
            format!("restriction-machine-{case}"),
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
        .timeout(Duration::from_secs(10)).send().await.unwrap(), 200, "restriction share fixture").await;
    let started = approve_request(app, recipient, &share).await;
    (tenant, started)
}

async fn invalid_revision_restrictions() {
    let owner_id = ObjectId::new();
    eprintln!("X17_RESTRICT stage=app begin");
    let app = tokio::time::timeout(
        Duration::from_secs(30),
        TestApp::spawn_with_settings(move |settings| {
            settings.auth.account_approval.enabled = true;
            settings.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            // This isolated synthetic fixture alone opts in to test refusal.
            settings.auth.native_share_ssh_authorization_enabled = true;
            settings.app.frontend_url = "https://native-restriction.example.test".into();
            settings.app.pod_id = Some(format!("native-restriction-{}", ObjectId::new().to_hex()));
        }),
    )
    .await
    .expect("X17_RESTRICT stage=app initialization timeout");
    let owner = actor(&app, "native_restriction_owner", Some(owner_id)).await;
    let recipient = actor(&app, "native_restriction_recipient", None).await;
    eprintln!("X17_RESTRICT stage=app complete");
    let documents = app.db.collection::<bson::Document>("tenants");
    let authorizations = app
        .db
        .collection::<NativeSshAuthorization>(NativeSshAuthorization::COLLECTION);
    let mut observations = vec![];
    let mut all_passed = true;
    for (index, (case, invalid)) in [
        ("null", bson::Bson::Null),
        ("string", bson::Bson::String("invalid-revision".into())),
        ("fractional", bson::Bson::Double(1.5)),
        ("zero", bson::Bson::Int64(0)),
        ("negative", bson::Bson::Int64(-1)),
        ("max", bson::Bson::Int64(i64::MAX)),
    ]
    .into_iter()
    .enumerate()
    {
        eprintln!("X17_RESTRICT stage=case_{case} begin");
        let (tenant, started) = restriction_fixture(&app, &owner, &recipient, index).await;
        let authorization_id =
            ObjectId::parse_str(started["authorization_id"].as_str().unwrap()).unwrap();
        let changed = documents
            .update_one(
                doc! {"_id": tenant},
                doc! {"$set": {"security_rev": invalid.clone()}},
            )
            .await
            .unwrap();
        assert_eq!(
            changed.matched_count, 1,
            "synthetic revision corruption fixture exists"
        );

        // Check the invalid revision itself while SSH and the tenant are still
        // otherwise enabled, before either administrative restriction is sent.
        let denied_before = exchange(&app, &started).await;
        let denied_before_status = denied_before.status().as_u16();
        let denied_before_body: Value = denied_before.json().await.expect("native refusal JSON");
        let no_grant_before = denied_before_body.get("grant").is_none();
        let close = app
            .auth_put(&format!("/api/tenant/{tenant}/ssh-settings"), &owner.token)
            .json(&json!({"remote_ssh_enabled":false}))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        let close_status = close.status().as_u16();
        let close_body: Value = close.json().await.expect("SSH management JSON");
        let after_close = documents.find_one(doc! {"_id": tenant}).await.unwrap();
        let ssh_disabled = after_close
            .as_ref()
            .and_then(|row| row.get_document("settings").ok())
            .and_then(|settings| settings.get_bool("remote_ssh_enabled").ok())
            == Some(false);
        let close_revision_kept =
            after_close.as_ref().and_then(|row| row.get("security_rev")) == Some(&invalid);
        let archive = app
            .auth_post(&format!("/api/tenant/{tenant}/archive"), &owner.token)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        let archive_status = archive.status().as_u16();
        let archive_body: Value = archive.json().await.expect("archive management JSON");
        let after_archive = documents.find_one(doc! {"_id": tenant}).await.unwrap();
        let archived = after_archive
            .as_ref()
            .and_then(|row| row.get_bool("is_archived").ok())
            == Some(true);
        let archive_revision_kept = after_archive
            .as_ref()
            .and_then(|row| row.get("security_rev"))
            == Some(&invalid);
        let denied_after = exchange(&app, &started).await;
        let denied_after_status = denied_after.status().as_u16();
        let denied_after_body: Value = denied_after
            .json()
            .await
            .expect("post-restriction native refusal JSON");
        let no_grant_after = denied_after_body.get("grant").is_none();
        let stored = authorizations
            .find_one(doc! {"authorization_id": authorization_id})
            .await
            .unwrap();
        let no_stored_grant = stored.as_ref().is_none_or(|row| {
            row.state != "exchanged" && row.grant_hash.is_none() && row.grant_expires_at.is_none()
        });
        let passed = denied_before_status == 403
            && no_grant_before
            && close_status == 200
            && close_body["remote_ssh_enabled"] == false
            && ssh_disabled
            && close_revision_kept
            && archive_status == 200
            && archive_body["is_archived"] == true
            && archived
            && archive_revision_kept
            && denied_after_status == 403
            && no_grant_after
            && no_stored_grant;
        all_passed &= passed;
        // Only static case labels, status codes and booleans enter failures.
        observations.push(json!({"case":case,"passed":passed,
            "native_before_status":denied_before_status,"no_grant_before":no_grant_before,
            "close_status":close_status,"ssh_disabled":ssh_disabled,"close_revision_kept":close_revision_kept,
            "archive_status":archive_status,"archived":archived,"archive_revision_kept":archive_revision_kept,
            "native_after_status":denied_after_status,"no_grant_after":no_grant_after,"no_stored_grant":no_stored_grant}));
        eprintln!("X17_RESTRICT stage=case_{case} complete");
    }

    eprintln!("X17_RESTRICT stage=missing_tenant begin");
    let missing = app
        .state
        .tenants
        .create(
            "Missing restriction fixture".into(),
            "missing-restriction-fixture".into(),
            owner.id,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    // Retain this synthetic owner's membership/roles so the SSH management
    // request reaches the missing-tenant lookup instead of an unrelated 403.
    assert_eq!(
        documents
            .delete_one(doc! {"_id": missing})
            .await
            .unwrap()
            .deleted_count,
        1
    );
    let missing_close_status = app
        .auth_put(&format!("/api/tenant/{missing}/ssh-settings"), &owner.token)
        .json(&json!({"remote_ssh_enabled":false}))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    let missing_archive_status = app
        .auth_post(&format!("/api/tenant/{missing}/archive"), &owner.token)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    eprintln!("X17_RESTRICT stage=missing_tenant complete");
    eprintln!("X17_RESTRICT stage=functional_assertion begin");
    assert!(
        all_passed && missing_close_status == 404 && missing_archive_status == 404,
        "invalid tenant revisions must not block administrative restrictions or change missing-tenant 404; \
         observations={observations:?}, missing_close_status={missing_close_status}, \
         missing_archive_status={missing_archive_status}"
    );
}

// This is runtime coverage of known writers, not an enumeration gate for
// arbitrary future Mongo writes, aliases, operators or collection names.
async fn stored_writer_revision(app: &TestApp, tenant: ObjectId) -> Option<i64> {
    app.state
        .tenants
        .base
        .find_by_id(tenant)
        .await
        .unwrap()
        .security_revision()
}

async fn observe_known_writer(
    app: &TestApp,
    tenant: ObjectId,
    label: &'static str,
    before: Option<i64>,
    succeeded: bool,
    policy_matches: impl FnOnce(&meshharbor_db::models::Tenant) -> bool,
) -> Value {
    let stored = app.state.tenants.base.find_by_id(tenant).await.unwrap();
    let after = stored.security_revision();
    let advanced = before.and_then(|revision| revision.checked_add(1)) == after && after.is_some();
    // Counter metadata and static labels only; no identities or credentials.
    json!({"writer":label, "write_succeeded":succeeded,
        "policy_matches":policy_matches(&stored), "before_revision":before,
        "after_revision":after, "revision_advanced":advanced})
}

#[tokio::test]
async fn native_ssh_known_tenant_security_writers_increment_revision() {
    tokio::time::timeout(Duration::from_secs(90), known_tenant_security_writers())
        .await
        .expect("X17_WRITERS stage=scenario timeout");
}

async fn known_tenant_security_writers() {
    use meshharbor_db::models::RcFeaturePolicy::{Ask, Off, On};

    let owner_id = ObjectId::new();
    eprintln!("X17_WRITERS stage=app begin");
    let app = tokio::time::timeout(
        Duration::from_secs(30),
        TestApp::spawn_with_settings(move |settings| {
            settings.auth.account_approval.enabled = true;
            settings.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            settings.auth.native_share_ssh_authorization_enabled = false;
            settings.app.frontend_url = "https://native-writers.example.test".into();
            settings.app.pod_id = Some(format!("native-writers-{}", ObjectId::new().to_hex()));
        }),
    )
    .await
    .expect("X17_WRITERS stage=app initialization timeout");
    assert!(!app.settings.auth.native_share_ssh_authorization_enabled);
    let owner = actor(&app, "native_writers_owner", Some(owner_id)).await;
    let tenant = app
        .state
        .tenants
        .create(
            "Known security writers".into(),
            "known-security-writers".into(),
            owner.id,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    assert_eq!(stored_writer_revision(&app, tenant).await, Some(1));
    eprintln!("X17_WRITERS stage=app complete");
    eprintln!("X17_WRITERS stage=known_setters begin");
    let mut observations = vec![];

    for (label, enabled) in [
        ("remote_exec_on", true),
        ("remote_exec_repeat", true),
        ("remote_exec_off", false),
    ] {
        let before = stored_writer_revision(&app, tenant).await;
        let succeeded = app
            .state
            .tenants
            .set_remote_exec_enabled(tenant, enabled)
            .await
            .is_ok();
        observations.push(
            observe_known_writer(&app, tenant, label, before, succeeded, |row| {
                row.settings.remote_exec_enabled == enabled
            })
            .await,
        );
    }
    for (label, required) in [
        ("exec_system_on", true),
        ("exec_system_repeat", true),
        ("exec_system_off", false),
    ] {
        let before = stored_writer_revision(&app, tenant).await;
        let succeeded = app
            .state
            .tenants
            .set_exec_require_system(tenant, required)
            .await
            .is_ok();
        observations.push(
            observe_known_writer(&app, tenant, label, before, succeeded, |row| {
                row.settings.exec_require_system == required
            })
            .await,
        );
    }
    for (label, max, idle) in [
        ("rc_limits_set", Some(60_u32), Some(30_u32)),
        ("rc_limits_repeat", Some(60), Some(30)),
        ("rc_limits_unset", None, None),
        ("rc_limits_unset_repeat", None, None),
    ] {
        let before = stored_writer_revision(&app, tenant).await;
        let succeeded = app
            .state
            .tenants
            .set_rc_session_limits(tenant, Some(max), Some(idle))
            .await
            .is_ok();
        observations.push(
            observe_known_writer(&app, tenant, label, before, succeeded, |row| {
                row.settings.rc_limits.max_secs == max && row.settings.rc_limits.idle_secs == idle
            })
            .await,
        );
    }
    // The production DAO builds these paths dynamically and supports partial
    // updates. Check all three fields, including fields a later call omits.
    for (label, clipboard, files, audio, expected) in [
        (
            "rc_policy_mixed",
            Some(Off),
            Some(Ask),
            Some(Off),
            (Off, Ask, Off),
        ),
        (
            "rc_policy_repeat",
            Some(Off),
            Some(Ask),
            Some(Off),
            (Off, Ask, Off),
        ),
        ("rc_policy_clipboard", Some(On), None, None, (On, Ask, Off)),
        (
            "rc_policy_files_audio",
            None,
            Some(On),
            Some(On),
            (On, On, On),
        ),
    ] {
        let before = stored_writer_revision(&app, tenant).await;
        let succeeded = app
            .state
            .tenants
            .set_rc_session_policy(tenant, clipboard, files, audio)
            .await
            .is_ok();
        observations.push(
            observe_known_writer(&app, tenant, label, before, succeeded, |row| {
                let policy = row.settings.rc_session;
                (policy.clipboard, policy.files, policy.audio) == expected
            })
            .await,
        );
    }
    for (label, enabled) in [
        ("ephemeral_on", true),
        ("ephemeral_repeat", true),
        ("ephemeral_off", false),
    ] {
        let before = stored_writer_revision(&app, tenant).await;
        let succeeded = app
            .state
            .tenants
            .set_ephemeral_keys_enabled(tenant, enabled)
            .await
            .is_ok();
        observations.push(
            observe_known_writer(&app, tenant, label, before, succeeded, |row| {
                row.settings.ephemeral_keys_enabled == enabled
            })
            .await,
        );
    }
    eprintln!("X17_WRITERS stage=known_setters complete");

    // Reach the existing fleet management route with its real owner role;
    // no external device, controller, connection code or agent is created.
    eprintln!("X17_WRITERS stage=external_access begin");
    for (label, enabled) in [
        ("external_on", true),
        ("external_repeat", true),
        ("external_off", false),
    ] {
        let before = stored_writer_revision(&app, tenant).await;
        let response = app
            .auth_put(
                &format!("/api/tenant/{tenant}/external-access"),
                &owner.token,
            )
            .json(&json!({"enabled":enabled}))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body: Value = response.json().await.expect("external management JSON");
        let succeeded = status == 200 && body["enabled"].as_bool() == Some(enabled);
        let mut observed = observe_known_writer(&app, tenant, label, before, succeeded, |row| {
            row.settings.external_rc_enabled == enabled
        })
        .await;
        observed["http_status"] = json!(status);
        observations.push(observed);
    }
    eprintln!("X17_WRITERS stage=external_access complete");
    eprintln!("X17_WRITERS stage=functional_assertion begin");
    assert!(
        observations.len() == 20
            && observations
                .iter()
                .all(|row| row["write_succeeded"] == true && row["policy_matches"] == true),
        "known tenant writer setup/operations must succeed before revision assertions; observations={observations:?}"
    );
    assert!(
        observations
            .iter()
            .all(|row| row["revision_advanced"] == true),
        "every successful known tenant security write must advance revision exactly once, including repeated values; observations={observations:?}"
    );
}

#[tokio::test]
async fn native_ssh_membership_device_and_account_revisions_are_atomic_and_fail_closed() {
    tokio::time::timeout(
        Duration::from_secs(90),
        membership_device_and_account_revisions(),
    )
    .await
    .expect("X17_UPSTREAM_WRITERS stage=scenario timeout");
}

async fn membership_device_and_account_revisions() {
    use meshharbor_remote_control::models::{
        AccessPolicy, AgentStatus, ConsentMode, ExecAnchor, SshAccountMode, SshMode, SshPolicy,
        SshServiceCeiling, SshServiceEndpoint,
    };

    let owner_id = ObjectId::new();
    let app = tokio::time::timeout(
        Duration::from_secs(30),
        TestApp::spawn_with_settings(move |settings| {
            settings.auth.account_approval.enabled = true;
            settings.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            settings.auth.native_share_ssh_authorization_enabled = false;
        }),
    )
    .await
    .expect("X17_UPSTREAM_WRITERS stage=app initialization timeout");
    assert!(!app.settings.auth.native_share_ssh_authorization_enabled);

    let owner = actor(&app, "upstream_revision_owner", Some(owner_id)).await;
    let recipient = actor(&app, "upstream_revision_recipient", None).await;
    let tenant = app
        .state
        .tenants
        .create(
            "Upstream revision writers".into(),
            "upstream-revision-writers".into(),
            owner.id,
        )
        .await
        .unwrap()
        .id
        .unwrap();

    // 1. Membership (`TenantMember`) monotonic revision + invalid fallback.
    let member_coll = app.db.collection::<bson::Document>("tenant_members");
    let member = app
        .state
        .tenants
        .members
        .find_one(doc! { "tenant_id": tenant, "user_id": owner.id })
        .await
        .unwrap()
        .unwrap();
    let original_member_id = member.id.unwrap();
    assert_eq!(member.security_revision(), Some(1));
    let extra_role = ObjectId::new();
    assert!(
        app.state
            .tenants
            .assign_role(tenant, owner.id, extra_role)
            .await
            .unwrap()
    );
    let after_assign = app
        .state
        .tenants
        .members
        .find_by_id(original_member_id)
        .await
        .unwrap();
    assert_eq!(after_assign.security_revision(), Some(2));
    assert!(after_assign.role_ids.contains(&extra_role));
    assert!(
        app.state
            .tenants
            .assign_role(tenant, owner.id, extra_role)
            .await
            .unwrap()
    );
    let after_repeat_assign = app
        .state
        .tenants
        .members
        .find_by_id(original_member_id)
        .await
        .unwrap();
    assert_eq!(after_repeat_assign.security_revision(), Some(3));
    assert!(
        app.state
            .tenants
            .remove_role(tenant, owner.id, extra_role)
            .await
            .unwrap()
    );
    let after_remove = app
        .state
        .tenants
        .members
        .find_by_id(original_member_id)
        .await
        .unwrap();
    assert_eq!(after_remove.security_revision(), Some(4));
    assert_eq!(after_remove.role_ids, member.role_ids);

    for invalid in [
        bson::Bson::Null,
        bson::Bson::String("invalid".into()),
        bson::Bson::Int32(1),
        bson::Bson::Int64(0),
        bson::Bson::Int64(-1),
        bson::Bson::Int64(i64::MAX),
    ] {
        member_coll
            .update_one(
                doc! { "_id": original_member_id },
                doc! { "$set": { "security_rev": invalid.clone() } },
            )
            .await
            .unwrap();
        assert!(
            app.state
                .tenants
                .assign_role(tenant, owner.id, extra_role)
                .await
                .unwrap()
        );
        assert!(
            app.state
                .tenants
                .remove_role(tenant, owner.id, extra_role)
                .await
                .unwrap()
        );
        let row = app
            .state
            .tenants
            .members
            .find_by_id(original_member_id)
            .await
            .unwrap();
        assert_eq!(row.security_revision(), None);
        assert_eq!(row.security_rev.as_ref(), Some(&invalid));
    }
    member_coll
        .update_one(
            doc! { "_id": original_member_id },
            doc! { "$unset": { "security_rev": "" } },
        )
        .await
        .unwrap();
    assert!(
        app.state
            .tenants
            .assign_role(tenant, owner.id, extra_role)
            .await
            .unwrap()
    );
    assert!(
        app.state
            .tenants
            .remove_role(tenant, owner.id, extra_role)
            .await
            .unwrap()
    );
    let reinitialized_member = app
        .state
        .tenants
        .members
        .find_by_id(original_member_id)
        .await
        .unwrap();
    assert_eq!(reinitialized_member.security_revision(), Some(2));

    // 2. Device (`Agent`) monotonic revision + invalid fallback.
    let agents = AgentDao::new(&app.db);
    let agent_coll = app.db.collection::<bson::Document>("agents");
    let created_agent = agents
        .create(
            tenant,
            owner.id,
            "Upstream host".into(),
            "upstream-machine".into(),
            OsKind::Windows,
            "synthetic".into(),
            "synthetic-agent-token-hash".into(),
            None,
        )
        .await
        .unwrap();
    let device = created_agent.id.unwrap();
    assert_eq!(created_agent.access_policy_revision(), Some(1));
    assert_eq!(created_agent.token_gen, 0);

    let ssh_on = SshPolicy {
        mode: SshMode::On,
        account_mode: SshAccountMode::Named,
        consent_mode: Some(ConsentMode::Auto),
        ..SshPolicy::default()
    };
    assert!(
        agents
            .update_ssh_policy(tenant, device, &ssh_on)
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(2)
    );
    assert!(
        agents
            .update_access_policy(tenant, device, &AccessPolicy::default())
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(3)
    );
    assert!(
        agents
            .rename(tenant, device, "Upstream renamed")
            .await
            .unwrap()
    );
    let renamed_agent = agents.base.find_by_id(device).await.unwrap();
    assert_eq!(renamed_agent.name, "Upstream renamed");
    assert_eq!(renamed_agent.access_policy_revision(), Some(3));
    assert!(agents.update_owner(tenant, device, owner.id).await.unwrap());
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(4)
    );
    let anchor = ExecAnchor {
        anchored_at: bson::DateTime::now(),
        anchored_by: owner.id,
        anchor_id: "anchor-rev-1".into(),
    };
    assert!(agents.set_exec_anchor(device, &anchor).await.unwrap());
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(5)
    );
    let first_published_at = bson::DateTime::from_millis(1_700_000_000_000);
    let mut endpoint = SshServiceEndpoint {
        host_pubkey: public_key(),
        ceiling: SshServiceCeiling::System,
        anchor_id: "anchor-rev-1".into(),
        published_at: first_published_at,
        one_command: false,
    };
    assert!(
        agents
            .publish_ssh_service(tenant, device, &endpoint)
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(6)
    );
    // Same-content republish (6h timer or service restart) updates published_at without advancing rev.
    let republished_at = bson::DateTime::from_millis(1_700_021_600_000);
    endpoint.published_at = republished_at;
    assert!(
        agents
            .publish_ssh_service(tenant, device, &endpoint)
            .await
            .unwrap()
    );
    let republished_agent = agents.base.find_by_id(device).await.unwrap();
    assert_eq!(republished_agent.access_policy_revision(), Some(6));
    assert_eq!(
        republished_agent.ssh_service.as_ref().unwrap().published_at,
        republished_at
    );
    // Changing ceiling advances access_policy_rev.
    endpoint.ceiling = SshServiceCeiling::ConsoleUser;
    assert!(
        agents
            .publish_ssh_service(tenant, device, &endpoint)
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(7)
    );
    // Changing host_pubkey advances access_policy_rev.
    endpoint.host_pubkey = format!("{} rotated", public_key());
    assert!(
        agents
            .publish_ssh_service(tenant, device, &endpoint)
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(8)
    );
    // Changing one_command advances access_policy_rev.
    endpoint.one_command = true;
    assert!(
        agents
            .publish_ssh_service(tenant, device, &endpoint)
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(9)
    );
    assert!(agents.clear_exec_anchor(device).await.unwrap());
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(10)
    );
    assert!(
        agents
            .mark_status(device, AgentStatus::Quarantined)
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(11)
    );
    assert!(
        agents
            .mark_status(device, AgentStatus::Online)
            .await
            .unwrap()
    );
    assert_eq!(
        agents
            .base
            .find_by_id(device)
            .await
            .unwrap()
            .access_policy_revision(),
        Some(11)
    );
    assert!(agents.soft_delete(tenant, device).await.unwrap());
    let deleted_agent = agents.base.find_by_id(device).await.unwrap();
    assert!(deleted_agent.deleted_at.is_some());
    assert_eq!(deleted_agent.token_gen, 1);
    assert_eq!(deleted_agent.access_policy_revision(), Some(12));
    let revived_agent = agents
        .rehydrate(
            device,
            "Upstream renamed",
            OsKind::Windows,
            "synthetic",
            None,
        )
        .await
        .unwrap();
    assert!(revived_agent.deleted_at.is_none());
    assert_eq!(revived_agent.token_gen, 1);
    assert_eq!(revived_agent.access_policy_revision(), Some(13));

    for invalid in [
        bson::Bson::Null,
        bson::Bson::String("invalid".into()),
        bson::Bson::Int32(1),
        bson::Bson::Int64(0),
        bson::Bson::Int64(-1),
        bson::Bson::Int64(i64::MAX),
    ] {
        agent_coll
            .update_one(
                doc! { "_id": device },
                doc! { "$set": { "access_policy_rev": invalid.clone() } },
            )
            .await
            .unwrap();
        assert!(
            agents
                .update_ssh_policy(tenant, device, &SshPolicy::default())
                .await
                .unwrap()
        );
        assert!(agents.soft_delete(tenant, device).await.unwrap());
        let revived = agents
            .rehydrate(
                device,
                "Upstream renamed",
                OsKind::Windows,
                "synthetic",
                None,
            )
            .await
            .unwrap();
        assert_eq!(revived.access_policy_revision(), None);
        assert_eq!(revived.access_policy_rev.as_ref(), Some(&invalid));
    }

    // 3. Account (`User`) monotonic revision + invalid fallback.
    let user_coll = app.db.collection::<bson::Document>("users");
    let fresh_user = app
        .state
        .users
        .create(
            "fresh_account@native-revision.example.test".into(),
            "fresh_account".into(),
            "Fresh Account".into(),
            app.state
                .auth
                .hash_password("synthetic-native-revision-password")
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    let uid = fresh_user.id.unwrap();
    assert_eq!(fresh_user.security_revision(), Some(1));
    assert!(app.state.users.mark_verified(uid).await.unwrap());
    assert_eq!(
        app.state
            .users
            .base
            .find_by_id(uid)
            .await
            .unwrap()
            .security_revision(),
        Some(2)
    );
    assert!(
        app.state
            .users
            .review_account_approval(uid, 0, AccountApprovalState::Approved, owner.id)
            .await
            .unwrap()
    );
    let reviewed_user = app.state.users.base.find_by_id(uid).await.unwrap();
    assert_eq!(reviewed_user.account_approval.revision, 1);
    assert_eq!(reviewed_user.security_revision(), Some(3));
    assert!(app.state.users.set_mfa_enabled(uid, true).await.unwrap());
    assert_eq!(
        app.state
            .users
            .base
            .find_by_id(uid)
            .await
            .unwrap()
            .security_revision(),
        Some(4)
    );
    assert!(app.state.users.set_mfa_enabled(uid, false).await.unwrap());
    assert_eq!(
        app.state
            .users
            .base
            .find_by_id(uid)
            .await
            .unwrap()
            .security_revision(),
        Some(5)
    );
    assert!(
        app.state
            .users
            .update_profile(uid, Some("Updated Display".into()), None, None, None, None)
            .await
            .unwrap()
    );
    let profile_updated_user = app.state.users.base.find_by_id(uid).await.unwrap();
    assert_eq!(profile_updated_user.display_name, "Updated Display");
    assert_eq!(profile_updated_user.security_revision(), Some(5));

    let mut expected_approval_rev = 1_u32;
    for invalid in [
        bson::Bson::Null,
        bson::Bson::String("invalid".into()),
        bson::Bson::Int32(1),
        bson::Bson::Int64(0),
        bson::Bson::Int64(-1),
        bson::Bson::Int64(i64::MAX),
    ] {
        user_coll
            .update_one(
                doc! { "_id": uid },
                doc! { "$set": { "security_rev": invalid.clone() } },
            )
            .await
            .unwrap();
        assert!(
            app.state
                .users
                .review_account_approval(
                    uid,
                    expected_approval_rev,
                    AccountApprovalState::Suspended,
                    owner.id
                )
                .await
                .unwrap()
        );
        expected_approval_rev += 1;
        assert!(
            app.state
                .users
                .review_account_approval(
                    uid,
                    expected_approval_rev,
                    AccountApprovalState::Approved,
                    owner.id
                )
                .await
                .unwrap()
        );
        expected_approval_rev += 1;
        let row = app.state.users.base.find_by_id(uid).await.unwrap();
        assert_eq!(row.security_revision(), None);
        assert_eq!(row.security_rev.as_ref(), Some(&invalid));
    }
    let _ = recipient;
}

/// Completed upstream membership, device-policy, or account-revision ABA (or
/// missing/invalid revisions on those documents) must refuse exchange of an
/// earlier approval while allowing a freshly approved request afterwards.
#[tokio::test]
async fn native_ssh_upstream_membership_device_and_account_aba_refuse_exchange() {
    tokio::time::timeout(
        Duration::from_secs(120),
        upstream_membership_device_and_account_aba(),
    )
    .await
    .expect("X17_UPSTREAM_ABA stage=scenario timeout");
}

async fn upstream_membership_device_and_account_aba() {
    use meshharbor_remote_control::models::{
        ConsentMode, ExecAnchor, SshAccountMode, SshMode, SshPolicy, SshServiceCeiling,
        SshServiceEndpoint,
    };

    let owner_id = ObjectId::new();
    let app = tokio::time::timeout(
        Duration::from_secs(30),
        TestApp::spawn_with_settings(move |settings| {
            settings.auth.account_approval.enabled = true;
            settings.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            settings.auth.native_share_ssh_authorization_enabled = true;
            settings.app.frontend_url = "https://native-upstream-aba.example.test".into();
            settings.app.pod_id = Some(format!("native-upstream-aba-{}", ObjectId::new().to_hex()));
        }),
    )
    .await
    .expect("X17_UPSTREAM_ABA stage=app initialization timeout");

    let owner = actor(&app, "native_upstream_owner", Some(owner_id)).await;
    let recipient = actor(&app, "native_upstream_recipient", None).await;
    let (tenant, started_member) = restriction_fixture(&app, &owner, &recipient, 100).await;
    let authorizations = app
        .db
        .collection::<NativeSshAuthorization>(NativeSshAuthorization::COLLECTION);
    let member_auth_id =
        ObjectId::parse_str(started_member["authorization_id"].as_str().unwrap()).unwrap();
    let member_row = authorizations
        .find_one(doc! { "authorization_id": member_auth_id })
        .await
        .unwrap()
        .unwrap();
    let share = json!({ "id": member_row.share_grant_id.to_hex() });
    let device = member_row.scope.as_ref().unwrap().device_id;

    // 1. Membership role ABA (assign + remove temporary role -> same role_ids, higher security_rev).
    let temp_role = ObjectId::new();
    assert!(
        app.state
            .tenants
            .assign_role(tenant, owner.id, temp_role)
            .await
            .unwrap()
    );
    assert!(
        app.state
            .tenants
            .remove_role(tenant, owner.id, temp_role)
            .await
            .unwrap()
    );
    let member_exchange = exchange(&app, &started_member).await;
    assert_eq!(member_exchange.status().as_u16(), 403);
    let member_body: Value = member_exchange.json().await.unwrap();
    assert!(member_body.get("grant").is_none());

    // 2. Device SSH policy ABA (off -> on -> same ssh_policy, higher access_policy_rev).
    let started_device = approve_request(&app, &recipient, &share).await;
    let agents = AgentDao::new(&app.db);
    let ssh_off = SshPolicy {
        mode: SshMode::Off,
        account_mode: SshAccountMode::Daemon,
        consent_mode: Some(ConsentMode::Auto),
        ..SshPolicy::default()
    };
    let ssh_on = SshPolicy {
        mode: SshMode::On,
        account_mode: SshAccountMode::Daemon,
        consent_mode: Some(ConsentMode::Auto),
        ..SshPolicy::default()
    };
    assert!(
        agents
            .update_ssh_policy(tenant, device, &ssh_off)
            .await
            .unwrap()
    );
    assert!(
        agents
            .update_ssh_policy(tenant, device, &ssh_on)
            .await
            .unwrap()
    );
    let device_exchange = exchange(&app, &started_device).await;
    assert_eq!(device_exchange.status().as_u16(), 403);
    let device_body: Value = device_exchange.json().await.unwrap();
    assert!(device_body.get("grant").is_none());

    // 3. Owner account security_rev ABA (MFA on -> off -> same booleans, higher security_rev).
    let started_account = approve_request(&app, &recipient, &share).await;
    assert!(
        app.state
            .users
            .set_mfa_enabled(owner.id, true)
            .await
            .unwrap()
    );
    assert!(
        app.state
            .users
            .set_mfa_enabled(owner.id, false)
            .await
            .unwrap()
    );
    let account_exchange = exchange(&app, &started_account).await;
    assert_eq!(account_exchange.status().as_u16(), 403);
    let account_body: Value = account_exchange.json().await.unwrap();
    assert!(account_body.get("grant").is_none());

    // 4. Same-content publish_ssh_service republish (6h timer / service restart) preserves
    //    approved authorization, while a host_pubkey or ceiling change refuses exchange.
    let anchor = ExecAnchor {
        anchored_at: bson::DateTime::now(),
        anchored_by: owner.id,
        anchor_id: "anchor-aba-1".into(),
    };
    assert!(agents.set_exec_anchor(device, &anchor).await.unwrap());
    let mut service_endpoint = SshServiceEndpoint {
        host_pubkey: public_key(),
        ceiling: SshServiceCeiling::System,
        anchor_id: "anchor-aba-1".into(),
        published_at: bson::DateTime::from_millis(1_700_000_000_000),
        one_command: false,
    };
    assert!(
        agents
            .publish_ssh_service(tenant, device, &service_endpoint)
            .await
            .unwrap()
    );
    let started_republish_ok = approve_request(&app, &recipient, &share).await;
    service_endpoint.published_at = bson::DateTime::from_millis(1_700_021_600_000);
    assert!(
        agents
            .publish_ssh_service(tenant, device, &service_endpoint)
            .await
            .unwrap()
    );
    let republish_ok_body = json_response(
        exchange(&app, &started_republish_ok).await,
        200,
        "same-content republish exchange",
    )
    .await;
    assert!(
        republish_ok_body["grant"]
            .as_str()
            .is_some_and(|grant| !grant.is_empty())
    );

    let started_republish_changed = approve_request(&app, &recipient, &share).await;
    service_endpoint.ceiling = SshServiceCeiling::ConsoleUser;
    assert!(
        agents
            .publish_ssh_service(tenant, device, &service_endpoint)
            .await
            .unwrap()
    );
    let republish_changed_exchange = exchange(&app, &started_republish_changed).await;
    assert_eq!(republish_changed_exchange.status().as_u16(), 403);
    let republish_changed_body: Value = republish_changed_exchange.json().await.unwrap();
    assert!(republish_changed_body.get("grant").is_none());

    // 5. Fresh approval after all completed ABA transitions succeeds.
    let fresh = approve_request(&app, &recipient, &share).await;
    let fresh_body = json_response(exchange(&app, &fresh).await, 200, "fresh exchange").await;
    assert!(
        fresh_body["grant"]
            .as_str()
            .is_some_and(|grant| !grant.is_empty())
    );
}
