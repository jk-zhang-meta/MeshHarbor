// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-133 — a device changes hands, over real HTTP + Mongo.
//!
//! A personal device of org A is signed in on by a person of org B, who
//! moves it: B approves a device login of the SAME machine into B, the device
//! enrolls there, and `POST /api/agent/self/move` (A's credential + B's)
//! removes A's row through the one removal sequence, with an audit row in A
//! and a notice to A's device admins that names nothing of B.
//!
//! The refusals are the point as much as the move: a plain `self/unenroll`
//! of a permanent device stays 403, and no proof that is missing, stale,
//! spent, of another machine, of the same org or not a person's approval
//! removes anything.
use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::NodeRef;
use meshharbor_services::dao::overlay_network::OverlayNetworkDao;
use meshharbor_services::dao::overlay_node::{NewOverlayNode, OverlayNodeDao};
use serde_json::{Value, json};

use crate::fixtures::{seed::SeededTenant, test_app::TestApp};

const BASE: &str = "/api/native/device-login";
const VERIFIER: &str = "device-move-test-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

fn challenge(v: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

async fn app_with_flags(move_enabled: bool, invite_enabled: bool) -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.auth.native_device_login_enabled = true;
        s.auth.native_device_move_enabled = move_enabled;
        s.auth.native_device_invite_enabled = invite_enabled;
        if let Ok(url) = std::env::var("MESHHARBOR__REDIS__URL") {
            s.redis.url = url;
        }
    })
    .await
}

async fn app_with(move_enabled: bool) -> TestApp {
    app_with_flags(move_enabled, false).await
}

/// Enroll a temporary (invitation) device into `org` through the real invite routes.
async fn temporary_device(app: &TestApp, org: &SeededTenant, machine: &str) -> (String, String) {
    let created: Value = app
        .auth_post(
            &format!("/api/tenant/{}/device-invite", org.tenant_id),
            &org.admin.access_token,
        )
        .json(&json!({ "duration_secs": 3600, "label": "guest" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = created["code"]
        .as_str()
        .unwrap_or_else(|| panic!("invite create: {created}"));
    let redeemed: Value = app
        .client
        .post(app.url("/api/native/device-invite/redeem"))
        .json(&json!({ "code": code, "device_name": "device-a", "device_os": "linux" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = redeemed["enrollment_token"]
        .as_str()
        .unwrap_or_else(|| panic!("invite redeem: {redeemed}"));
    enroll(app, token, machine).await
}

fn oid(s: &str) -> ObjectId {
    ObjectId::parse_str(s).unwrap()
}

/// A device-login approval by `approver` into `tenant`, exchanged: the
/// single-use enrollment token the device receives.
async fn device_login_token(app: &TestApp, approver: &str, tenant: &str) -> String {
    let origin = app.settings.app.frontend_url.clone();
    let started: Value = app
        .client
        .post(app.url(BASE))
        .json(&json!({
            "device_name": "laptop", "device_os": "linux",
            "code_challenge": challenge(VERIFIER), "code_challenge_method": "S256",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_code = started["user_code"].as_str().unwrap();
    let r = app
        .auth_post(&format!("{BASE}/decision"), approver)
        .header("Origin", &origin)
        .json(&json!({ "user_code": user_code, "approve": true, "tenant_id": tenant }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "decision");
    let ex: Value = app
        .client
        .post(app.url(&format!("{BASE}/exchange")))
        .json(&json!({ "device_code": started["device_code"], "code_verifier": VERIFIER }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ex["enrollment_token"]
        .as_str()
        .unwrap_or_else(|| panic!("exchange: {ex}"))
        .to_string()
}

/// An enrollment token an admin minted from the dashboard (no device login).
async fn admin_token(app: &TestApp, admin: &str, tenant: &str) -> String {
    let et: Value = app
        .auth_post(&format!("/api/tenant/{tenant}/agent/enroll-token"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    et["enrollment_token"].as_str().unwrap().to_string()
}

/// `(agent_id, agent_token)` of `machine` enrolled with `token`.
async fn enroll(app: &TestApp, token: &str, machine: &str) -> (String, String) {
    let ej: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": token, "machine_id": machine,
            "machine_name": "laptop", "os": "linux", "agent_version": "0.4.151",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        ej["agent_id"]
            .as_str()
            .unwrap_or_else(|| panic!("{ej}"))
            .to_string(),
        ej["agent_token"].as_str().unwrap().to_string(),
    )
}

/// A personal device of `org`'s admin: enrolled through a device login.
async fn personal(app: &TestApp, org: &SeededTenant, machine: &str) -> (String, String) {
    let t = device_login_token(app, &org.admin.access_token, &org.tenant_id).await;
    enroll(app, &t, machine).await
}

async fn move_out(app: &TestApp, old_token: &str, new_token: &str) -> (u16, Value) {
    let r = app
        .client
        .post(app.url("/api/agent/self/move"))
        .bearer_auth(old_token)
        .json(&json!({ "agent_token": new_token }))
        .send()
        .await
        .unwrap();
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
}

async fn row(app: &TestApp, agent_id: &str) -> bson::Document {
    app.db
        .collection::<bson::Document>("agents")
        .find_one(doc! { "_id": oid(agent_id) })
        .await
        .unwrap()
        .expect("the row (or its tombstone) is there")
}

fn is_live(d: &bson::Document) -> bool {
    matches!(d.get("deleted_at"), None | Some(bson::Bson::Null))
}

async fn listed(app: &TestApp, org: &SeededTenant, agent_id: &str) -> bool {
    let v: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent", org.tenant_id),
            &org.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v.to_string().contains(agent_id)
}

#[tokio::test]
async fn a_device_moved_by_a_person_from_another_org_leaves_with_a_record_and_a_notice() {
    let app = app_with(true).await;
    let a = app.seed_tenant("fr133-move-a").await;
    let b = app.seed_tenant("fr133-move-b").await;
    let machine = "fr133-machine-moved";
    let (a_id, a_token) = personal(&app, &a, machine).await;

    // The lease A's overlay holds for it (what `rc:overlay.join` would create).
    let networks = OverlayNetworkDao::new(&app.db);
    let nodes = OverlayNodeDao::new(&app.db);
    let net = networks.get_or_create(oid(&a.tenant_id)).await.unwrap();
    let max = meshharbor_remote_control::models::cidr_max_host(
        meshharbor_remote_control::models::OverlayNetwork::DEFAULT_CIDR,
    )
    .unwrap();
    networks.allocate_host(net.id.unwrap(), max).await.unwrap();
    let node = nodes
        .create(NewOverlayNode {
            supports_invite_deadlines: true,
            personal_access_owner_id: None,
            temporary: None,
            tenant_id: oid(&a.tenant_id),
            node_ref: NodeRef::Agent {
                agent_id: oid(&a_id),
            },
            network_id: net.id.unwrap(),
            machine_id: machine.to_string(),
            name: "laptop".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            wg_public_key: "pk-fr133".to_string(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_server_relay_strategy: false,
            supports_derp_floor: false,
            supports_overlay_echo: false,
            supports_p2pctl: false,
            supports_org_relay: false,
            advertised_routes: vec![],
            route_offer_withheld: None,
        })
        .await
        .unwrap();

    // AC4 — the plain self-removal of a permanent device is still refused.
    let r = app
        .client
        .post(app.url("/api/agent/self/unenroll"))
        .bearer_auth(&a_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "self/unenroll of a permanent device"
    );
    assert!(is_live(&row(&app, &a_id).await));

    // B's person approves the same machine into B; the device enrolls there.
    let (b_id, b_token) = personal(&app, &b, machine).await;
    assert_ne!(a_id, b_id);

    let (s, body) = move_out(&app, &a_token, &b_token).await;
    assert_eq!(s, 200, "move: {body}");
    assert_eq!(body["removed"], true);
    assert_eq!(
        body["overlay_released"], true,
        "the lease went by the normal sequence"
    );

    // AC2 — gone from A (a tombstone, never a delete), live in B.
    let a_row = row(&app, &a_id).await;
    assert!(!is_live(&a_row), "A's row is tombstoned");
    assert!(is_live(&row(&app, &b_id).await));
    assert!(!listed(&app, &a, &a_id).await, "A no longer lists it");
    assert!(listed(&app, &b, &b_id).await, "B lists it");
    let after = nodes.base.find_by_id(node.id.unwrap()).await.unwrap();
    assert!(after.deleted_at.is_some(), "the overlay node is tombstoned");
    let freed = networks.base.find_by_id(net.id.unwrap()).await.unwrap();
    assert_eq!(freed.free_hosts, vec![1], "the host went back to A's pool");

    // A's audit has the entry, naming nothing of B.
    let audits: Vec<bson::Document> = {
        use futures::TryStreamExt;
        app.db
            .collection::<bson::Document>("device_move_audit")
            .find(doc! { "tenant_id": oid(&a.tenant_id) })
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap()
    };
    assert_eq!(audits.len(), 1, "{audits:?}");
    assert_eq!(audits[0].get_str("decision").unwrap(), "moved");
    assert_eq!(audits[0].get_str("reason").unwrap(), "moved_to_other_org");
    let text = format!("{audits:?}");
    let leaks = [
        b.tenant_id.as_str(),
        b_id.as_str(),
        b.admin.id.as_str(),
        b.admin.email.as_str(),
        "fr133-move-b",
    ];
    for leak in leaks {
        assert!(!text.contains(leak), "the audit names {leak}");
    }

    // A's device admin got the notice; a plain member did not; it names no
    // one and nothing of B.
    let notes = app.db.collection::<bson::Document>("notifications");
    let admin_note = notes
        .find_one(doc! { "user_id": oid(&a.admin.id), "notification_type": "device_moved" })
        .await
        .unwrap()
        .expect("A's admin is told");
    assert_eq!(
        admin_note.get_object_id("tenant_id").unwrap(),
        oid(&a.tenant_id)
    );
    let body_text = admin_note.get_str("body").unwrap();
    assert!(
        body_text.contains("moved to another organization by a person signed in at the device"),
        "{body_text}"
    );
    let note_text = format!("{admin_note:?}");
    for leak in leaks {
        assert!(!note_text.contains(leak), "the notice names {leak}");
    }
    assert!(
        notes
            .find_one(doc! { "user_id": oid(&a.member.id), "notification_type": "device_moved" })
            .await
            .unwrap()
            .is_none(),
        "a member without MANAGE_AGENTS is not told"
    );

    // A replay: A's credential died with its row.
    let (s, _) = move_out(&app, &a_token, &b_token).await;
    assert_eq!(s, 401, "a replay after the move");
}

#[tokio::test]
async fn no_proof_that_is_missing_stale_spent_foreign_or_same_org_removes_anything() {
    let app = app_with(true).await;
    let a = app.seed_tenant("fr133-proof-a").await;
    let b = app.seed_tenant("fr133-proof-b").await;
    let c = app.seed_tenant("fr133-proof-c").await;
    let machine = "fr133-machine-proof";
    let (a_id, a_token) = personal(&app, &a, machine).await;
    let (c_id, c_token) = personal(&app, &c, machine).await;

    // An admin-minted token into B: a real enrollment of the same machine,
    // but no person approved a device login, so there is nothing to prove.
    let t = admin_token(&app, &b.admin.access_token, &b.tenant_id).await;
    let (_, b_admin_enrolled) = enroll(&app, &t, machine).await;
    let (s, body) = move_out(&app, &a_token, &b_admin_enrolled).await;
    assert_eq!(s, 403, "no device-login decision: {body}");

    // A device login of ANOTHER machine into B proves nothing about this one.
    let (_, b_other) = personal(&app, &b, "fr133-machine-other").await;
    let (s, _) = move_out(&app, &a_token, &b_other).await;
    assert_eq!(s, 403, "another machine");

    // A fresh enrollment into the SAME org is a refresh, not a move.
    let (a_again_id, a_again) = personal(&app, &a, machine).await;
    assert_eq!(a_again_id, a_id, "the same row, rehydrated");
    let (s, _) = move_out(&app, &a_token, &a_again).await;
    assert_eq!(s, 403, "same org");

    // A forged or garbage credential.
    let (s, _) = move_out(&app, &a_token, "not.a.jwt").await;
    assert_eq!(s, 403, "garbage");
    // A USER token is not an agent credential.
    let (s, _) = move_out(&app, &a_token, &b.admin.access_token).await;
    assert_eq!(s, 403, "a user token");

    // A stale decision: approved 11 minutes ago.
    let (_, b_token) = personal(&app, &b, machine).await;
    let logins = app.db.collection::<bson::Document>("device_login_requests");
    let stale = bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 11 * 60_000);
    logins
        .update_many(
            doc! { "state": "consumed" },
            doc! { "$set": { "decided_at": stale } },
        )
        .await
        .unwrap();
    let (s, _) = move_out(&app, &a_token, &b_token).await;
    assert_eq!(s, 403, "a stale approval");
    assert!(
        is_live(&row(&app, &a_id).await),
        "nothing was removed so far"
    );

    // Fresh again: it moves A's row ...
    let (_, b_token) = personal(&app, &b, machine).await;
    let (s, body) = move_out(&app, &a_token, &b_token).await;
    assert_eq!(s, 200, "{body}");
    assert!(!is_live(&row(&app, &a_id).await));
    // ... and it is spent: C's row of the same machine cannot ride it.
    let (s, _) = move_out(&app, &c_token, &b_token).await;
    assert_eq!(s, 403, "a proof removes one row");
    assert!(is_live(&row(&app, &c_id).await));

    // Every refusal is in A's or C's own audit, never B's.
    let audit = app.db.collection::<bson::Document>("device_move_audit");
    let refused_a = audit
        .count_documents(doc! { "tenant_id": oid(&a.tenant_id), "decision": "refused" })
        .await
        .unwrap();
    assert_eq!(refused_a, 6, "each refusal against A is recorded");
    assert_eq!(
        audit
            .count_documents(doc! { "tenant_id": oid(&c.tenant_id), "decision": "refused" })
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        audit
            .count_documents(doc! { "tenant_id": oid(&b.tenant_id) })
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn what_stays_an_admin_decision_is_refused() {
    let app = app_with_flags(true, true).await;
    let a = app.seed_tenant("fr133-admin-a").await;
    let b = app.seed_tenant("fr133-admin-b").await;

    // Enrolled by an admin's token: not the person's to move.
    let t = admin_token(&app, &a.admin.access_token, &a.tenant_id).await;
    let (a_id, a_token) = enroll(&app, &t, "fr133-machine-corp").await;
    let (_, b_token) = personal(&app, &b, "fr133-machine-corp").await;
    let (s, body) = move_out(&app, &a_token, &b_token).await;
    assert_eq!(s, 403, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("personal device"),
        "{body}"
    );
    assert!(is_live(&row(&app, &a_id).await));

    // A two-factor device refuses: moving it changes who controls it.
    let (tf_id, tf_token) = personal(&app, &a, "fr133-machine-2fa").await;
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": oid(&tf_id) },
            doc! { "$set": { "capabilities.two_factor": true } },
        )
        .await
        .unwrap();
    let (_, b_token) = personal(&app, &b, "fr133-machine-2fa").await;
    let (s, body) = move_out(&app, &tf_token, &b_token).await;
    assert_eq!(s, 403, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("two-factor")
    );
    assert!(is_live(&row(&app, &tf_id).await));

    // A temporary (invitation) device leaves with `mh leave`, never `self/move`.
    let (tmp_id, tmp_token) = temporary_device(&app, &a, "fr133-machine-temp").await;
    let (_, b_token) = personal(&app, &b, "fr133-machine-temp").await;
    let (s, body) = move_out(&app, &tmp_token, &b_token).await;
    assert_eq!(s, 403, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("mh leave"),
        "{body}"
    );
    assert!(is_live(&row(&app, &tmp_id).await));

    // An ephemeral device removes itself with `self/unenroll`, never `self/move`.
    let (eph_id, eph_token) = personal(&app, &a, "fr133-machine-eph").await;
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": oid(&eph_id) },
            doc! { "$set": { "ephemeral": true } },
        )
        .await
        .unwrap();
    let (_, b_token) = personal(&app, &b, "fr133-machine-eph").await;
    let (s, body) = move_out(&app, &eph_token, &b_token).await;
    assert_eq!(s, 403, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("self/unenroll"),
        "{body}"
    );
    assert!(is_live(&row(&app, &eph_id).await));
}

#[tokio::test]
async fn self_devices_exposes_org_name_for_permanent_devices_and_not_temporary_guests() {
    let app = app_with_flags(true, true).await;
    let a = app.seed_tenant("fr133-orgname-a").await;
    let (_, perm_token) = personal(&app, &a, "fr133-machine-orgname-perm").await;
    let (_, temp_token) = temporary_device(&app, &a, "fr133-machine-orgname-temp").await;

    let perm_page: Value = app
        .client
        .get(app.url("/api/agent/self/devices?page=1&per_page=1"))
        .bearer_auth(&perm_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(perm_page["org_name"].as_str(), Some("fr133-orgname-a Corp"));

    let temp_page: Value = app
        .client
        .get(app.url("/api/agent/self/devices?page=1&per_page=1"))
        .bearer_auth(&temp_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        temp_page.get("org_name").is_none(),
        "temporary guests must not receive org_name: {temp_page}"
    );
}

#[tokio::test]
async fn cross_org_replace_preserves_secondary_orgs_and_handles_older_server_fallback() {
    use meshharbor_node_core::{
        config::{AgentConfig, OrgEntry, OrgOverlayMode},
        device_move::{MoveOut, leaving_primary, remove_old_row},
        enrollment::{EnrollOutcome, apply_enrollment},
    };

    let app_on = app_with(true).await;
    let a = app_on.seed_tenant("fr133-replace-a").await;
    let b = app_on.seed_tenant("fr133-replace-b").await;
    let machine = "fr133-machine-replace";
    let (a_id, a_token) = personal(&app_on, &a, machine).await;
    let (b_id, b_token) = personal(&app_on, &b, machine).await;

    let make_cfg = |server: &str, tenant: &str, agent_id: &str, token: &str| -> AgentConfig {
        serde_json::from_value(json!({
            "server_url": server,
            "tenant_id": tenant,
            "agent_id": agent_id,
            "agent_token": token,
            "machine_id": machine,
            "machine_name": "device-a",
        }))
        .unwrap()
    };

    // Existing config has Primary = Org A and Secondary = Org C (`[[orgs]]`).
    let mut existing = make_cfg(&app_on.base_url, &a.tenant_id, &a_id, &a_token);
    existing.orgs.push(OrgEntry {
        label: "secondary-c".into(),
        server_url: app_on.base_url.clone(),
        ws_url: None,
        agent_token: "tok-c".into(),
        agent_id: "0000000000000000000000cc".into(),
        tenant_id: "00000000000000000000000c".into(),
        enabled: true,
        overlay_mode: OrgOverlayMode::Netstack,
        overlay_wg_secret_key: None,
        overlay_wg_key_epoch: 0,
        overlay_advertised_routes: Vec::new(),
        overlay_exit_node_enabled: false,
        advertise_routes: Vec::new(),
        netstack_socks_port: None,
    });
    let fresh = make_cfg(&app_on.base_url, &b.tenant_id, &b_id, &b_token);

    let leaving = leaving_primary(&existing, &fresh, false).expect("cross-org replace leaves A");
    let (merged, outcome) = apply_enrollment(Some(existing), fresh, None, true).unwrap();
    assert_eq!(outcome, EnrollOutcome::ReplacedPrimary);
    assert_eq!(merged.tenant_id, b.tenant_id);
    assert_eq!(merged.agent_id, b_id);
    assert_eq!(
        merged.orgs.len(),
        1,
        "secondary [[orgs]] enrollment must stay intact across a primary move"
    );
    assert_eq!(merged.orgs[0].label, "secondary-c");

    // 1. Live server with moves enabled: removes Org A's row.
    let out = remove_old_row(&leaving, &merged.agent_token).await;
    assert_eq!(out, MoveOut::Removed);
    assert_eq!(out.notice(), None);
    assert!(!is_live(&row(&app_on, &a_id).await), "Org A row tombstoned");
    assert!(is_live(&row(&app_on, &b_id).await), "Org B row stays live");

    // 2. Kill switch off (403): keeps Org A's row and tells the person an admin must remove it.
    let app_off = app_with(false).await;
    let a_off = app_off.seed_tenant("fr133-replace-off-a").await;
    let b_off = app_off.seed_tenant("fr133-replace-off-b").await;
    let (a_off_id, a_off_tok) = personal(&app_off, &a_off, "fr133-machine-replace-off").await;
    let (b_off_id, b_off_tok) = personal(&app_off, &b_off, "fr133-machine-replace-off").await;
    let leaving_off = leaving_primary(
        &make_cfg(&app_off.base_url, &a_off.tenant_id, &a_off_id, &a_off_tok),
        &make_cfg(&app_off.base_url, &b_off.tenant_id, &b_off_id, &b_off_tok),
        false,
    )
    .unwrap();
    let out_off = remove_old_row(&leaving_off, &b_off_tok).await;
    assert!(matches!(out_off, MoveOut::Kept(_)), "{out_off:?}");
    assert!(
        out_off
            .notice()
            .unwrap()
            .contains("an admin there must remove it")
    );
    assert!(is_live(&row(&app_off, &a_off_id).await));

    // 3. Older server without `/api/agent/self/move` (404): keeps behaviour and tells the person.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stub_task = tokio::spawn(async move {
        let _ = axum::serve(listener, axum::Router::new()).await;
    });
    let stub_url = format!("http://{addr}");
    let leaving_old = leaving_primary(
        &make_cfg(&stub_url, &a.tenant_id, &a_id, &a_token),
        &make_cfg(&stub_url, &b.tenant_id, &b_id, &b_token),
        false,
    )
    .unwrap();
    let out_404 = remove_old_row(&leaving_old, &b_token).await;
    stub_task.abort();
    assert_eq!(
        out_404,
        MoveOut::Kept("its server does not support moving devices yet".into())
    );
    assert!(
        out_404
            .notice()
            .unwrap()
            .contains("an admin there must remove it")
    );
}

#[tokio::test]
async fn the_kill_switch_answers_exactly_todays_refusal() {
    let app = app_with(false).await;
    let a = app.seed_tenant("fr133-off-a").await;
    let b = app.seed_tenant("fr133-off-b").await;
    let (a_id, a_token) = personal(&app, &a, "fr133-machine-off").await;
    let (_, b_token) = personal(&app, &b, "fr133-machine-off").await;

    let (s, moved) = move_out(&app, &a_token, &b_token).await;
    let r = app
        .client
        .post(app.url("/api/agent/self/unenroll"))
        .bearer_auth(&a_token)
        .send()
        .await
        .unwrap();
    let today = (r.status().as_u16(), r.json::<Value>().await.unwrap());
    assert_eq!(
        (s, &moved),
        (today.0, &today.1),
        "off = self/unenroll's answer"
    );
    assert_eq!(s, 403);
    assert_eq!(
        moved["message"].as_str(),
        Some(meshharbor_mod_fleet::agent::PERMANENT_SELF_REMOVAL_REFUSAL)
    );
    assert!(is_live(&row(&app, &a_id).await));
}
