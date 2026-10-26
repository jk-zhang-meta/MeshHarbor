// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P3b — the peer-relay admin surface, end to end: the org switch
//! (gate 1), per-device approval (gate 3) with its composite permission and
//! its audit rows, the audit reader's own permission, and the fail-closed ACL
//! loader the mint (P3c) stands on.
//!
//! What these lock is the WIRING. `decide_approval` is unit-tested in the api
//! crate; a handler that stops calling it, or audits only one arm, passes
//! every unit test and fails here.

use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use bson::{doc, oid::ObjectId};
use roomler_ai_db::models::role::permissions::{DEFAULT_ADMIN, EXEC_DEVICE};
use roomler_ai_mod_network::overlay::{PolicyLoad, load_acl, try_load_acl};
use roomler_ai_remote_control::models::OverlayAclMode;
use roomlerd::{config::AgentConfig, enrollment};
use serde_json::{Value, json};

fn url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

async fn get(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let resp = app.auth_get(path, token).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn put(app: &TestApp, path: &str, token: &str, body: Value) -> (u16, Value) {
    let resp = app.auth_put(path, token).json(&body).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Enrol a device so there is a row to approve. No WS on purpose: approval is
/// a row edit, and an OFFLINE device can be approved — it simply is not
/// serving until it comes up with `relay_server_enabled`.
async fn enrol(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> AgentConfig {
    let et: Value = app
        .auth_post(
            &url(seeded, "/agent/enroll-token"),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    enrollment::enroll(enrollment::EnrollInputs {
        server_url: &app.base_url,
        enrollment_token: et["enrollment_token"].as_str().unwrap(),
        machine_id,
        machine_name: "Relay test host",
        install: None,
    })
    .await
    .expect("agent enrollment")
}

async fn seeded_role_id(app: &TestApp, seeded: &SeededTenant, name: &str) -> String {
    let (_, roles) = get(app, &url(seeded, "/role"), &seeded.admin.access_token).await;
    roles
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("seeded role {name} not found"))["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The owner mints a role — allowed for any mask, because the owner holds
/// ADMINISTRATOR.
async fn create_role(app: &TestApp, seeded: &SeededTenant, name: &str, permissions: u64) -> String {
    let resp = app
        .auth_post(&url(seeded, "/role"), &seeded.admin.access_token)
        .json(&json!({ "name": name, "permissions": permissions }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "owner may mint {name}");
    let role: Value = resp.json().await.unwrap();
    role["id"].as_str().unwrap().to_string()
}

async fn assign_role(app: &TestApp, seeded: &SeededTenant, role_id: &str, user_id: &str) {
    let resp = app
        .auth_post(
            &url(seeded, &format!("/role/{role_id}/assign/{user_id}")),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "owner may assign a role");
}

/// Gate 1. `off` on every tenant that existed before the feature; flipping it
/// is `MANAGE_TENANT` (an org-owner decision, like `exec-settings`), while
/// reading the settings is `MANAGE_AGENTS` like every other fleet view.
#[tokio::test]
async fn org_mode_defaults_off_and_flipping_it_is_an_owner_decision() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("relaymode").await;
    let owner = &seeded.admin.access_token;
    let settings = url(&seeded, "/peer-relay");

    let (s, body) = get(&app, &settings, owner).await;
    assert_eq!(s, 200);
    assert_eq!(body["mode"], json!("off"), "closed by default");
    assert_eq!(body["relays"], json!([]));

    // A plain member can neither read nor flip it.
    let (s, _) = get(&app, &settings, &seeded.member.access_token).await;
    assert_eq!(s, 403);
    let (s, _) = put(
        &app,
        &settings,
        &seeded.member.access_token,
        json!({ "mode": "on" }),
    )
    .await;
    assert_eq!(s, 403);
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["mode"], json!("off"), "a refused flip changes nothing");

    // The owner flips it; the read reflects it.
    let (s, body) = put(&app, &settings, owner, json!({ "mode": "on" })).await;
    assert_eq!(s, 200);
    assert_eq!(body["mode"], json!("on"));
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["mode"], json!("on"));

    // An admin (DEFAULT_ADMIN: MANAGE_AGENTS, not MANAGE_TENANT) can read the
    // settings but cannot flip the org switch.
    let admin_role = seeded_role_id(&app, &seeded, "admin").await;
    assign_role(&app, &seeded, &admin_role, &seeded.member.id).await;
    let (s, body) = get(&app, &settings, &seeded.member.access_token).await;
    assert_eq!(s, 200);
    assert_eq!(body["mode"], json!("on"));
    let (s, _) = put(
        &app,
        &settings,
        &seeded.member.access_token,
        json!({ "mode": "warn" }),
    )
    .await;
    assert_eq!(s, 403, "MANAGE_AGENTS alone must not flip the org switch");
}

/// Gate 3 and its audit. `DEFAULT_ADMIN` carries `MANAGE_AGENTS` but
/// deliberately not `EXEC_DEVICE`; approving a relay needs both, clearing one
/// needs only the first, and EVERY attempt — granted or refused — is a row.
#[tokio::test]
async fn approval_needs_manage_agents_and_exec_device_and_audits_both_arms() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("relayappr").await;
    let owner = &seeded.admin.access_token;
    let member = &seeded.member.access_token;
    let cfg = enrol(&app, &seeded, "mach-relay-1").await;
    let policy = url(
        &seeded,
        &format!("/agent/{}/peer-relay-policy", cfg.agent_id),
    );
    let settings = url(&seeded, "/peer-relay");
    let audit = url(&seeded, "/peer-relay-audit");

    // 0. The audit reader is behind VIEW_EXEC_AUDIT, which a member lacks.
    let (s, _) = get(&app, &audit, member).await;
    assert_eq!(s, 403);

    // 1. A plain member is not a device admin.
    let (s, body) = put(&app, &policy, member, json!({ "serve": true })).await;
    assert_eq!(s, 403, "{body}");

    // 2. Promoted to `admin`: MANAGE_AGENTS, still no EXEC_DEVICE.
    let admin_role = seeded_role_id(&app, &seeded, "admin").await;
    assign_role(&app, &seeded, &admin_role, &seeded.member.id).await;
    let (s, body) = put(&app, &policy, member, json!({ "serve": true })).await;
    assert_eq!(s, 403);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("EXEC_DEVICE"),
        "the refusal must name the missing permission, got {body}"
    );
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(
        body["relays"],
        json!([]),
        "a refused approval changes nothing"
    );

    // 3. The owner approves (ADMINISTRATOR bypass). The device is listed —
    //    and listed as NOT serving, because this row never advertised
    //    `relay-server`: gate 3 is not gate 4.
    let (s, body) = put(&app, &policy, owner, json!({ "serve": true })).await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["serve"], json!(true));
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["relays"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["relays"][0]["id"], json!(cfg.agent_id));
    assert_eq!(body["relays"][0]["serving"], json!(false));

    // 4. Clearing is not a grant: the EXEC_DEVICE-less admin may revoke.
    let (s, _) = put(&app, &policy, member, json!({ "serve": false })).await;
    assert_eq!(s, 200);
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["relays"], json!([]));

    // 5. ...and still may not re-approve.
    let (s, _) = put(&app, &policy, member, json!({ "serve": true })).await;
    assert_eq!(s, 403);

    // 6. With EXEC_DEVICE added to the same person (roles union), it works.
    let relay_admin = create_role(&app, &seeded, "relay-admin", DEFAULT_ADMIN | EXEC_DEVICE).await;
    assign_role(&app, &seeded, &relay_admin, &seeded.member.id).await;
    let (s, body) = put(&app, &policy, member, json!({ "serve": true })).await;
    assert_eq!(s, 200, "{body}");
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["relays"][0]["id"], json!(cfg.agent_id));

    // 7. Six attempts, six rows — the refused ones included — all naming the
    //    device and who asked, newest first.
    let (s, body) = get(&app, &audit, owner).await;
    assert_eq!(s, 200);
    assert_eq!(body["total"], json!(6));
    let items = body["items"].as_array().unwrap();
    assert!(items.iter().all(|r| r["action"] == json!("approve")));
    assert!(items.iter().all(|r| r["agent_id"] == json!(cfg.agent_id)));
    let denied: Vec<&str> = items.iter().filter_map(|r| r["denied"].as_str()).collect();
    assert_eq!(
        denied.iter().filter(|d| **d == "not_device_admin").count(),
        1
    );
    assert_eq!(
        denied
            .iter()
            .filter(|d| **d == "cannot_grant_relay")
            .count(),
        2
    );
    assert_eq!(items.iter().filter(|r| r["denied"].is_null()).count(), 3);
    assert_eq!(items[0]["serve"], json!(true));
    assert_eq!(items[0]["user_id"], json!(seeded.member.id));
    assert!(
        items[0].get("vni").is_none(),
        "an approve row carries no mint fields"
    );

    // The per-device filter and the (now admin) member's own read.
    let (s, body) = get(&app, &format!("{audit}?agent_id={}", cfg.agent_id), member).await;
    assert_eq!(s, 200, "DEFAULT_ADMIN carries VIEW_EXEC_AUDIT");
    assert_eq!(body["total"], json!(6));
}

/// The loader the P3c mint will stand on. A relay grant must be REFUSED and
/// audited when the rules cannot be read, which needs an error the caller can
/// see. The netmap loader `load_acl` never opens up on a read failure either:
/// it keeps the tenant's last good ACL (so a Mongo blip neither withholds the
/// mesh nor widens it). Both postures, side by side, on the same unreadable row.
#[tokio::test]
async fn try_load_acl_errors_where_load_acl_keeps_the_last_good_acl() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("relayacl").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();

    // Readable: both agree, and `Always` reads the rows even under `off`.
    let ctx = try_load_acl(app.state.network(), tid, PolicyLoad::Always)
        .await
        .expect("a readable tenant loads");
    assert_eq!(ctx.mode, OverlayAclMode::Off);
    assert!(ctx.policies.is_empty());

    // Put the tenant in `warn` so the netmap loader really reads the rows...
    let (s, _) = put(
        &app,
        &url(&seeded, "/overlay-acl/mode"),
        &seeded.admin.access_token,
        json!({ "mode": "warn" }),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        load_acl(app.state.network(), tid).await.mode,
        OverlayAclMode::Warn
    );

    // ...then make them unreadable: a document that matches the live filter
    // but cannot deserialise into an `OverlayPolicy`.
    app.db
        .collection::<bson::Document>("overlay_policies")
        .insert_one(doc! {
            "tenant_id": tid,
            "name": "broken",
            "enabled": true,
            "sources": "not-an-array",
            "via": [],
            "destinations": [],
            "created_at": bson::DateTime::now(),
            "updated_at": bson::DateTime::now(),
            "deleted_at": null,
        })
        .await
        .unwrap();

    // The strict loader refuses to answer.
    assert!(
        try_load_acl(app.state.network(), tid, PolicyLoad::Always)
            .await
            .is_err(),
        "an unreadable policy set must be an error, not an empty ACL"
    );

    // The netmap loader keeps the last ACL it read, never `off`.
    let ctx = load_acl(app.state.network(), tid).await;
    assert_eq!(ctx.mode, OverlayAclMode::Warn);
    assert!(ctx.policies.is_empty());
}

// The enrollment credential, not a device's requested role, carries approval.
async fn relay_enrollment_token(
    app: &TestApp,
    seeded: &SeededTenant,
    user_token: &str,
    relay_server: bool,
) -> (u16, Value) {
    let response = app
        .auth_post(&url(seeded, "/agent/enroll-token"), user_token)
        .json(&json!({ "relay_server": relay_server }))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn redeem_relay_enrollment(app: &TestApp, token: &str, machine: &str) -> (u16, Value) {
    let response = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": token, "machine_id": machine,
            "machine_name": "relay enrollment test", "os": "linux", "agent_version": "0.4.151",
            // An ordinary device is allowed to send unknown fields, but they
            // must never grant it a relay role.
            "relay_server": true,
        }))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn relay_enrollment_requires_both_permissions_and_preserves_plain_policy() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("relayenroll").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let owner = &seeded.admin.access_token;
    let member = &seeded.member.access_token;
    assert_eq!(
        relay_enrollment_token(&app, &seeded, member, true).await.0,
        403
    );
    let admin_role = seeded_role_id(&app, &seeded, "admin").await;
    assign_role(&app, &seeded, &admin_role, &seeded.member.id).await;
    assert_eq!(
        relay_enrollment_token(&app, &seeded, member, true).await.0,
        403,
        "MANAGE_AGENTS without EXEC_DEVICE cannot mint a relay grant"
    );
    assert_eq!(
        relay_enrollment_token(&app, &seeded, member, false).await.0,
        200,
        "ordinary enrollment keeps its old permission contract"
    );

    let (status, token) = relay_enrollment_token(&app, &seeded, owner, true).await;
    assert_eq!(status, 200, "{token}");
    assert_eq!(token["relay_server"], json!(true));
    let (status, enrolled) = redeem_relay_enrollment(
        &app,
        token["enrollment_token"].as_str().unwrap(),
        "signed-relay",
    )
    .await;
    assert_eq!(status, 200, "{enrolled}");
    assert!(enrolled["agent_token"].is_string());
    let aid = ObjectId::parse_str(enrolled["agent_id"].as_str().unwrap()).unwrap();
    let dao = &app.state.fleet().agents;
    let row = dao.base.find_by_id(aid).await.unwrap();
    assert!(
        row.peer_relay_policy.serve,
        "no subsequent admin approval PUT needed"
    );
    // Existing endpoint configuration survives a later ordinary enrollment.
    let endpoints = vec!["8.8.8.8:3478".to_string()];
    let mut policy = row.peer_relay_policy;
    policy.static_endpoints = endpoints.clone();
    assert!(
        dao.update_peer_relay_policy(tid, aid, &policy)
            .await
            .unwrap()
    );
    let (_, plain) = relay_enrollment_token(&app, &seeded, owner, false).await;
    let (status, _) = redeem_relay_enrollment(
        &app,
        plain["enrollment_token"].as_str().unwrap(),
        "signed-relay",
    )
    .await;
    assert_eq!(status, 200);
    let row = dao.base.find_by_id(aid).await.unwrap();
    assert!(
        row.peer_relay_policy.serve,
        "plain token must not revoke existing approval"
    );
    assert_eq!(row.peer_relay_policy.static_endpoints, endpoints);
    let (_, plain) = relay_enrollment_token(&app, &seeded, owner, false).await;
    let (status, ordinary) = redeem_relay_enrollment(
        &app,
        plain["enrollment_token"].as_str().unwrap(),
        "ordinary-not-relay",
    )
    .await;
    assert_eq!(status, 200);
    let row = dao
        .base
        .find_by_id(ObjectId::parse_str(ordinary["agent_id"].as_str().unwrap()).unwrap())
        .await
        .unwrap();
    assert!(
        !row.peer_relay_policy.serve,
        "unsigned request-body role must do nothing"
    );
}

#[tokio::test]
async fn relay_enrollment_grant_matches_live_generation_and_preserves_endpoints() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("relaygrantgen").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let cfg = enrol(&app, &seeded, "relay-generation").await;
    let aid = ObjectId::parse_str(&cfg.agent_id).unwrap();
    let dao = &app.state.fleet().agents;
    let endpoints = vec!["8.8.8.8:3478".to_string()];
    let mut policy = dao.base.find_by_id(aid).await.unwrap().peer_relay_policy;
    policy.static_endpoints = endpoints.clone();
    dao.update_peer_relay_policy(tid, aid, &policy)
        .await
        .unwrap();
    assert!(
        !dao.grant_relay_server(tid, aid, 1).await.unwrap(),
        "stale generation cannot grant"
    );
    assert!(
        !dao.grant_relay_server(ObjectId::new(), aid, 0)
            .await
            .unwrap(),
        "tenant is part of atomic predicate"
    );
    assert!(dao.grant_relay_server(tid, aid, 0).await.unwrap());
    assert!(
        dao.grant_relay_server(tid, aid, 0).await.unwrap(),
        "already approved matching row is successful"
    );
    assert_eq!(
        dao.base
            .find_by_id(aid)
            .await
            .unwrap()
            .peer_relay_policy
            .static_endpoints,
        endpoints
    );
    // The enrollment read generation zero; a removal/revival advanced it.
    dao.base
        .update_by_id(
            aid,
            doc! { "$set": { "token_gen": 1, "peer_relay_policy.serve": false } },
        )
        .await
        .unwrap();
    assert!(!dao.grant_relay_server(tid, aid, 0).await.unwrap());
    assert!(
        !dao.base
            .find_by_id(aid)
            .await
            .unwrap()
            .peer_relay_policy
            .serve
    );
    assert!(dao.grant_relay_server(tid, aid, 1).await.unwrap());
    dao.base.update_by_id(aid, doc! { "$set": { "deleted_at": bson::DateTime::now(), "peer_relay_policy.serve": false } }).await.unwrap();
    assert!(
        !dao.grant_relay_server(tid, aid, 1).await.unwrap(),
        "tombstone cannot grant"
    );
}

#[tokio::test]
async fn relay_enrollment_write_failure_returns_no_credentials_and_consumes_token() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("relaygrantfail").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let (status, token) =
        relay_enrollment_token(&app, &seeded, &seeded.admin.access_token, true).await;
    assert_eq!(status, 200);
    // Isolated fixture database only: allow creating the ordinary row but
    // reject the subsequent true grant. No global mongod failpoint or race.
    app.db
        .run_command(doc! {
            "collMod": "agents",
            "validator": { "peer_relay_policy.serve": { "$ne": true } },
            "validationLevel": "strict", "validationAction": "error",
        })
        .await
        .unwrap();
    let token = token["enrollment_token"].as_str().unwrap();
    let (status, body) = redeem_relay_enrollment(&app, token, "failed-relay-grant").await;
    assert!(
        status >= 500,
        "a failed grant must not report success: {status} {body}"
    );
    assert!(
        body.get("agent_token").is_none(),
        "no agent credentials on a failed grant"
    );
    let row = app
        .state
        .fleet()
        .agents
        .find_by_tenant_and_machine(tid, "failed-relay-grant")
        .await
        .unwrap()
        .unwrap();
    assert!(
        !row.peer_relay_policy.serve,
        "partial row is ordinary, not approved"
    );
    let (status, body) = redeem_relay_enrollment(&app, token, "failed-relay-grant").await;
    assert_eq!(status, 401, "single-use claim is not rolled back: {body}");
    assert!(body.get("agent_token").is_none());
}

#[tokio::test]
async fn backbone_policy_is_same_tenant_approved_exact_and_preserved_by_plain_enrollment() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("backbone-policy").await;
    let owner = &seeded.admin.access_token;
    let source = enrol(&app, &seeded, "backbone-source").await;
    let target = enrol(&app, &seeded, "backbone-target").await;
    let source_url = url(
        &seeded,
        &format!("/agent/{}/peer-relay-policy", source.agent_id),
    );
    let target_url = url(
        &seeded,
        &format!("/agent/{}/peer-relay-policy", target.agent_id),
    );
    let edges = json!([{"relay_agent_id":target.agent_id,"endpoint":"10.20.0.2:3478"}]);
    let body = json!({"serve":true,"approved_backbone_edges":edges});
    assert_eq!(
        put(&app, &source_url, owner, body.clone()).await.0,
        400,
        "target needs its own approval"
    );
    assert_eq!(
        put(&app, &target_url, owner, json!({"serve":true})).await.0,
        200
    );
    assert_eq!(put(&app, &source_url, owner, body.clone()).await.0, 200);
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let aid = ObjectId::parse_str(&source.agent_id).unwrap();
    let dao = &app.state.network().fleet.agents;
    assert_eq!(
        dao.base
            .find_by_id(aid)
            .await
            .unwrap()
            .peer_relay_policy
            .approved_backbone_edges
            .len(),
        1
    );
    let mut bad = body.clone();
    bad["approved_backbone_edges"][0]["endpoint"] = json!("169.254.169.254:80");
    assert_eq!(put(&app, &source_url, owner, bad).await.0, 400);
    let mut self_edge = body.clone();
    self_edge["approved_backbone_edges"][0]["relay_agent_id"] = json!(source.agent_id);
    assert_eq!(put(&app, &source_url, owner, self_edge).await.0, 400);
    assert_eq!(
        dao.base
            .find_by_id(aid)
            .await
            .unwrap()
            .peer_relay_policy
            .approved_backbone_edges
            .len(),
        1,
        "failed updates retain last policy"
    );
    let other = app.seed_tenant("backbone-other").await;
    let foreign = enrol(&app, &other, "backbone-foreign").await;
    let mut foreign_edge = body.clone();
    foreign_edge["approved_backbone_edges"][0]["relay_agent_id"] = json!(foreign.agent_id);
    assert_eq!(put(&app, &source_url, owner, foreign_edge).await.0, 404);
    // Ordinary enrollment must not replace approved topology or grant a new
    // edge. The existing generation-constrained .serve grant stays narrow.
    let (_, token) = relay_enrollment_token(&app, &seeded, owner, false).await;
    let (status, _) = redeem_relay_enrollment(
        &app,
        token["enrollment_token"].as_str().unwrap(),
        "backbone-source",
    )
    .await;
    assert_eq!(status, 200);
    let row = dao.find_live_in_tenant(tid, aid).await.unwrap();
    assert_eq!(
        serde_json::to_value(row.peer_relay_policy.approved_backbone_edges).unwrap(),
        edges
    );
}
