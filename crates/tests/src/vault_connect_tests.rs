// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-9-1 — a person's `meshharbor connect`, the vault's half:
//! `rc:vault.connect`, answered with one field sealed to the device's key.
//!
//! Driven through the RAW agent socket the lease tests use. What these lock
//! is the SERVER:
//!
//! - a person's request is decided by Cedar's `secret:connect` for the
//!   device's OWNER as its row names them, in the roles they hold, and its
//!   lease names that owner, the device and no session;
//! - no policy written for sessions admits a person, and neither does a
//!   permit whose scope names no action;
//! - the guardrails seeded for it hold: only an upstream the secret names,
//!   never a dynamic secret's field, never a production secret;
//! - a policy that asks for someone's yes is refused `approval_unavailable`,
//!   since nobody can give one yet;
//! - `vault.people` lends only to the organizations it lists, and to none by
//!   default;
//! - an owner who is no member is nobody's principal, and a person's lease
//!   is taken back when the device's owner changes or leaves.

use std::time::Duration;

use bson::{Document, doc, oid::ObjectId};
use futures::StreamExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::vault_dynamic_tests::{Issuer, dynamic_secret, put};
use crate::vault_lease_tests::{
    Device, TAKES_LEASES, device, fresh_kek, opened, post, refused, rows, send,
};

/// The vault on with a KEK, lending to the people `people` lists
/// (`vault.people`), each pod sweeping every `sweep` s.
async fn connect_app(people: &str, sweep: u64) -> TestApp {
    let kek = fresh_kek();
    let people = people.to_string();
    TestApp::spawn_with_settings(move |s| {
        s.modules.hive = true;
        s.modules.vault = true;
        s.vault.kek = kek;
        s.vault.people = people;
        s.vault.revoke_sweep_secs = sweep;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// A sweep this long never runs in a test.
const NEVER: u64 = 3_600;

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

/// A structured secret at `path` toward the one upstream `audience`, its
/// `user` and `password` written; its id and the password, made here and
/// never written down.
async fn upstream_secret(
    app: &TestApp,
    t: &SeededTenant,
    path: &str,
    audience: &str,
) -> (String, String) {
    let (code, body) = post(
        app,
        t,
        "/vault/secret",
        json!({ "path": path, "kind": "structured", "audiences": [audience] }),
    )
    .await;
    assert_eq!(code, 201, "{body}");
    let id = body["id"].as_str().unwrap().to_string();
    let password = format!("connect-canary-{}", ObjectId::new().to_hex());
    assert_eq!(put(app, t, &id, "user", "orders_app").await, 200);
    assert_eq!(put(app, t, &id, "password", &password).await, 200);
    (id, password)
}

/// Policies, each checked and stored as an administrator writes them.
async fn policies(app: &TestApp, t: &SeededTenant, named: &[(&str, String)]) {
    for (name, text) in named {
        let (code, body) = post(
            app,
            t,
            "/vault/policy",
            json!({ "name": name, "text": text }),
        )
        .await;
        assert_eq!(code, 201, "{name}: {body}");
    }
}

/// The owner the device's row names, as the fleet's own route would leave
/// it.
async fn set_owner(app: &TestApp, device_id: &str, owner: &str) {
    let r = app
        .db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": oid(device_id) },
            doc! { "$set": { "owner_user_id": oid(owner) } },
        )
        .await
        .unwrap();
    assert_eq!(r.matched_count, 1);
}

/// `user` is no member of the organization any more, as removing them
/// leaves it.
async fn remove_member(app: &TestApp, t: &SeededTenant, user: &str) {
    let r = app
        .db
        .collection::<Document>("tenant_members")
        .delete_one(doc! { "tenant_id": oid(&t.tenant_id), "user_id": oid(user) })
        .await
        .unwrap();
    assert_eq!(r.deleted_count, 1);
}

/// Ask as the device's owner; the vault's answer to that request.
async fn ask_connect(dev: &mut Device, req_id: &str, mut frame: Value) -> Value {
    frame["t"] = json!("rc:vault.connect");
    frame["req_id"] = json!(req_id);
    if frame.get("ttl_secs").is_none() {
        frame["ttl_secs"] = json!(60);
    }
    send(&mut dev.ws, frame).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = tokio::time::timeout(left, dev.ws.next())
            .await
            .expect("no answer to the connect within 10 s")
            .expect("agent socket closed")
            .expect("agent socket error");
        if let Message::Text(text) = next {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let t = v["t"].as_str().unwrap_or_default();
            if (t == "rc:vault.leased" || t == "rc:vault.refused") && v["req_id"] == req_id {
                return v;
            }
        }
    }
}

/// The next `rc:vault.revoke` within `within`, skipping other frames.
async fn revoked(dev: &mut Device, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = match tokio::time::timeout(left, dev.ws.next()).await {
            Err(_) => return None,
            Ok(None | Some(Err(_))) => return None,
            Ok(Some(Ok(m))) => m,
        };
        if let Message::Text(text) = next {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            if v["t"] == "rc:vault.revoke" {
                return Some(v);
            }
        }
    }
}

fn names_lease(frame: &Value, lease: &str) -> bool {
    frame["lease_ids"]
        .as_array()
        .is_some_and(|ids| ids.iter().any(|id| id == lease))
}

/// The organization's people may connect to what is under `db/`, and a
/// policy that would admit them to production too.
fn members_connect(slug: &str) -> [(&'static str, String); 2] {
    [
        (
            "members-connect-to-db",
            format!(
                r#"permit (principal in MeshHarbor::Group::"member", action == MeshHarbor::Action::"secret:connect", resource in MeshHarbor::SecretFolder::"rrn:{slug}:secret:db");"#
            ),
        ),
        (
            "members-connect-to-prod",
            format!(
                r#"permit (principal in MeshHarbor::Group::"member", action == MeshHarbor::Action::"secret:connect", resource in MeshHarbor::SecretFolder::"rrn:{slug}:secret:prod");"#
            ),
        ),
    ]
}

/// FR-90 P3-9-1 — a person connects as the device's OWNER, as its row names
/// them, to what a policy names for them: one field sealed to the device's
/// key, its lease naming the owner and no session, its allow recorded with
/// the request before it was sent. A policy written for sessions and one
/// whose scope names no action admit nobody; the seeded guardrails hold;
/// every other refusal is one word.
#[tokio::test]
async fn a_person_connects_as_the_devices_owner_to_what_a_policy_names_for_them() {
    let app = connect_app("*", NEVER).await;
    let t = app.seed_tenant("vaultconn").await;
    let slug = t.tenant_slug.clone();
    let (_, password) = upstream_secret(&app, &t, "db/orders", "db.internal:5432").await;
    upstream_secret(&app, &t, "api/billing", "billing.internal:443").await;
    upstream_secret(&app, &t, "prod/db", "prod-db.internal:5432").await;
    dynamic_secret(&app, &t, &Issuer::made(), true).await;
    let mut written = members_connect(&slug).to_vec();
    written.extend([
        // A policy written for sessions, its principal unconstrained.
        (
            "any-session-uses-anything",
            r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource);"#.into(),
        ),
        // A permit whose scope names no action, as one written before a
        // person's action existed would.
        (
            "members-do-anything",
            r#"permit (principal in MeshHarbor::Group::"member", action, resource);"#.into(),
        ),
    ]);
    policies(&app, &t, &written).await;
    let mut dev = device(&app, &t, "conn-host", "linux", TAKES_LEASES, true).await;
    set_owner(&app, &dev.agent_id, &t.member.id).await;

    // Leased for the device's owner, sealed to the device's key.
    let before = bson::DateTime::now().timestamp_millis();
    let answer = ask_connect(
        &mut dev,
        "c1",
        json!({ "secret": "db/orders", "field": "password", "audience": "db.internal:5432" }),
    )
    .await;
    assert_eq!(opened(&dev, &answer), password);
    assert!(answer.get("provider").is_none(), "{answer}");
    let expires = answer["expires_at_ms"].as_i64().unwrap();
    assert!(
        (before + 59_000..=bson::DateTime::now().timestamp_millis() + 61_000).contains(&expires),
        "{answer}"
    );
    let lease_id = answer["lease_id"].as_str().unwrap().to_string();

    // Its lease: the owner, the device, no session, a proxy toward the
    // upstream.
    let lease = rows(&app, "vault_leases", doc! { "_id": oid(&lease_id) })
        .await
        .pop()
        .expect("the lease's row");
    assert!(!lease.contains_key("session_id"), "{lease:?}");
    assert_eq!(lease.get_i64("fence").unwrap(), 0);
    assert_eq!(
        lease.get_object_id("owner_id").unwrap().to_hex(),
        t.member.id
    );
    assert_eq!(
        lease.get_object_id("device_id").unwrap().to_hex(),
        dev.agent_id
    );
    assert_eq!(lease.get_str("mode").unwrap(), "proxy");
    assert_eq!(lease.get_str("audience").unwrap(), "db.internal:5432");
    assert_eq!(lease.get_str("field").unwrap(), "password");

    // Its allow: a user, the owner, the device and no session, with the
    // request as it was decided.
    let allows = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:connect", "decision": "allow" },
    )
    .await;
    assert_eq!(allows.len(), 1);
    let allow = &allows[0];
    assert_eq!(allow.get_str("principal").unwrap(), "user");
    assert_eq!(allow.get_str("op").unwrap(), "connect");
    assert_eq!(
        allow.get_object_id("user_id").unwrap().to_hex(),
        t.member.id
    );
    assert_eq!(
        allow.get_object_id("device_id").unwrap().to_hex(),
        dev.agent_id
    );
    assert!(!allow.contains_key("session_id"), "{allow:?}");
    assert_eq!(
        allow.get_str("target").unwrap(),
        format!("lease:{lease_id}")
    );
    // Decided by the permit written for people alone: the action-less one
    // is no part of it.
    let by = policy_id(&app, "members-connect-to-db").await;
    assert_eq!(allow.get_str("reason").unwrap(), format!("policy:{by}"));
    let request = allow.get_document("request").unwrap();
    assert_eq!(request.get_str("action").unwrap(), "secret:connect");
    assert_eq!(request.get_object_id("user").unwrap().to_hex(), t.member.id);
    assert_eq!(request.get_str("audience").unwrap(), "db.internal:5432");
    assert_eq!(request.get_i64("ttl_s").unwrap(), 60);
    let groups = request.get_array("groups").unwrap();
    assert!(
        groups.iter().any(|g| g.as_str() == Some("member")),
        "{request:?}"
    );
    assert_eq!(
        request
            .get_document("device")
            .unwrap()
            .get_object_id("owner")
            .unwrap()
            .to_hex(),
        t.member.id,
        "the device's facts are its row's"
    );

    // By this organization's RRN too, and the TTL clamped.
    let user = ask_connect(
        &mut dev,
        "c2",
        json!({ "secret": format!("rrn:{slug}:secret:db/orders"), "field": "user",
                "audience": "db.internal:5432", "ttl_secs": 999_999 }),
    )
    .await;
    assert_eq!(opened(&dev, &user), "orders_app");
    assert!(
        user["expires_at_ms"].as_i64().unwrap()
            <= bson::DateTime::now().timestamp_millis() + 901_000,
        "{user}"
    );

    // Refusals, one word each.
    for (req_id, frame, word) in [
        (
            "x1",
            json!({ "secret": "db/orders", "field": "password", "audience": "evil.example:5432" }),
            "denied",
        ),
        (
            "x2",
            json!({ "secret": "prod/db", "field": "password", "audience": "prod-db.internal:5432" }),
            "denied",
        ),
        (
            "x3",
            json!({ "secret": "api/billing", "field": "password", "audience": "billing.internal:443" }),
            "denied",
        ),
        (
            "x4",
            json!({ "secret": "db/dyn", "field": "admin_password", "audience": "db.internal:5432" }),
            "denied",
        ),
        (
            "x5",
            json!({ "secret": "db/none", "field": "password", "audience": "db.internal:5432" }),
            "no_secret",
        ),
        (
            "x6",
            json!({ "secret": "db/orders", "field": "token", "audience": "db.internal:5432" }),
            "no_value",
        ),
        (
            "x7",
            json!({ "secret": "rrn:another:secret:db/orders", "field": "password",
                    "audience": "db.internal:5432" }),
            "no_secret",
        ),
        (
            "x8",
            json!({ "secret": "db/orders", "field": "password", "audience": "" }),
            "bad_request",
        ),
        (
            "x9",
            json!({ "secret": "db/orders", "field": "password" }),
            "bad_request",
        ),
    ] {
        let answer = ask_connect(&mut dev, req_id, frame).await;
        assert_eq!(refused(&answer), word, "{req_id}: {answer}");
    }
    // The denies, with what decided them and the request to replay.
    let denied = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:connect", "decision": "deny", "request": { "$exists": true } },
    )
    .await;
    let mut reasons: Vec<&str> = denied
        .iter()
        .map(|r| r.get_str("reason").unwrap())
        .collect();
    reasons.sort_unstable();
    assert_eq!(
        reasons,
        [
            "default_deny",
            "guardrail:connect-never-dynamic",
            "guardrail:connect-never-prod",
            "guardrail:connect-only-named-audiences",
        ],
        "a session's policy and an action-less permit admit no person; each guardrail holds"
    );
    for row in &denied {
        assert_eq!(row.get_str("principal").unwrap(), "user", "{row:?}");
        assert!(!row.contains_key("session_id"), "{row:?}");
    }

    // A device whose hello carried no key takes no person's lease either.
    let mut keyless = device(&app, &t, "conn-keyless", "linux", TAKES_LEASES, false).await;
    set_owner(&app, &keyless.agent_id, &t.member.id).await;
    let answer = ask_connect(
        &mut keyless,
        "k1",
        json!({ "secret": "db/orders", "field": "password", "audience": "db.internal:5432" }),
    )
    .await;
    assert_eq!(refused(&answer), "unsupported", "{answer}");
}

/// A stored policy's id, by its name.
async fn policy_id(app: &TestApp, name: &str) -> String {
    rows(app, "vault_policies", doc! { "name": name })
        .await
        .pop()
        .expect("the policy")
        .get_object_id("_id")
        .unwrap()
        .to_hex()
}

/// FR-90 P3-9-1 — `vault.people` is opt-in: empty by default, it lends to
/// no organization's people, whatever its policies say, and a list lends to
/// the organizations it names alone. Nothing is recorded for a refusal the
/// switch makes.
#[tokio::test]
async fn the_vault_lends_to_no_people_unless_vault_people_lists_the_organization() {
    let another = ObjectId::new().to_hex();
    for people in ["", another.as_str()] {
        let app = connect_app(people, NEVER).await;
        let t = app.seed_tenant("vaultnopeople").await;
        upstream_secret(&app, &t, "db/orders", "db.internal:5432").await;
        policies(&app, &t, &members_connect(&t.tenant_slug)).await;
        let mut dev = device(&app, &t, "conn-off", "linux", TAKES_LEASES, true).await;
        set_owner(&app, &dev.agent_id, &t.member.id).await;
        let answer = ask_connect(
            &mut dev,
            "n1",
            json!({ "secret": "db/orders", "field": "password", "audience": "db.internal:5432" }),
        )
        .await;
        assert_eq!(refused(&answer), "not_served", "{people:?}: {answer}");
        let recorded = rows(&app, "vault_audit", doc! { "action": "secret:connect" }).await;
        assert!(recorded.is_empty(), "{people:?}: {recorded:?}");
    }
}

/// FR-90 P3-9-1, decision 24 — a policy that would allow a person only with
/// someone's yes refuses them `approval_unavailable`, recorded with the
/// request as it was decided (no approver): a person's request has nobody
/// to say yes. `simulate` answers what a yes would change, and that a
/// person's own yes changes nothing.
#[tokio::test]
async fn a_policy_that_asks_for_a_yes_is_refused_approval_unavailable() {
    let app = connect_app("*", NEVER).await;
    let t = app.seed_tenant("vaultconnyes").await;
    let (secret_id, _) = upstream_secret(&app, &t, "db/orders", "db.internal:5432").await;
    policies(
        &app,
        &t,
        &[(
            "members-connect-with-a-yes",
            format!(
                r#"permit (principal in MeshHarbor::Group::"member", action == MeshHarbor::Action::"secret:connect", resource in MeshHarbor::SecretFolder::"rrn:{}:secret:db") when {{ context has approval && context.approval.approver != principal }};"#,
                t.tenant_slug
            ),
        )],
    )
    .await;
    let mut dev = device(&app, &t, "conn-yes", "linux", TAKES_LEASES, true).await;
    set_owner(&app, &dev.agent_id, &t.member.id).await;
    let answer = ask_connect(
        &mut dev,
        "y1",
        json!({ "secret": "db/orders", "field": "password", "audience": "db.internal:5432" }),
    )
    .await;
    assert_eq!(refused(&answer), "approval_unavailable", "{answer}");
    assert!(
        answer["approval_id"].is_null(),
        "no card to wait on: {answer}"
    );
    let denied = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:connect", "decision": "deny" },
    )
    .await;
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].get_str("reason").unwrap(), "approval_unavailable");
    let request = denied[0].get_document("request").unwrap();
    assert!(
        !request.contains_key("approver"),
        "decided as asked: {request:?}"
    );
    assert!(
        rows(&app, "vault_approvals", doc! {}).await.is_empty(),
        "no card is posted for a person"
    );

    // What a yes would change, and that a person's own changes nothing.
    let simulate = |approver: &str| {
        json!({
            "action": "secret:connect",
            "principal": { "user_id": t.member.id },
            "resource": { "secret_id": secret_id },
            "device": { "os": "linux", "tags": [], "owner_id": t.member.id },
            "audience": "db.internal:5432",
            "ttl_s": 60,
            "approver_id": approver,
        })
    };
    let (code, body) = post(&app, &t, "/vault/simulate", simulate(&t.admin.id)).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["decision"], "allow", "{body}");
    let (code, body) = post(&app, &t, "/vault/simulate", simulate(&t.member.id)).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["decision"], "deny", "{body}");
    // A person's use acts as the device's owner, and has no mode.
    let mut as_other = simulate(&t.admin.id);
    as_other["device"]["owner_id"] = json!(t.admin.id);
    let (code, body) = post(&app, &t, "/vault/simulate", as_other).await;
    assert_eq!(code, 400, "{body}");
    let mut with_mode = simulate(&t.admin.id);
    with_mode["mode"] = json!("env");
    let (code, body) = post(&app, &t, "/vault/simulate", with_mode).await;
    assert_eq!(code, 400, "{body}");
}

/// FR-90 P3-9-1 — an owner who is no member of the organization is nobody's
/// principal in it: a device that outlived its owner's place is refused, the
/// refusal recorded, whatever a policy says.
#[tokio::test]
async fn an_owner_who_is_no_member_is_nobodys_principal() {
    let app = connect_app("*", NEVER).await;
    let t = app.seed_tenant("vaultconnleft").await;
    upstream_secret(&app, &t, "db/orders", "db.internal:5432").await;
    policies(
        &app,
        &t,
        &[(
            "anyone-connects",
            r#"permit (principal, action == MeshHarbor::Action::"secret:connect", resource);"#
                .into(),
        )],
    )
    .await;
    let mut dev = device(&app, &t, "conn-left", "linux", TAKES_LEASES, true).await;
    set_owner(&app, &dev.agent_id, &t.member.id).await;
    remove_member(&app, &t, &t.member.id).await;
    let answer = ask_connect(
        &mut dev,
        "l1",
        json!({ "secret": "db/orders", "field": "password", "audience": "db.internal:5432" }),
    )
    .await;
    assert_eq!(refused(&answer), "denied", "{answer}");
    let denied = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:connect", "decision": "deny" },
    )
    .await;
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].get_str("reason").unwrap(), "owner_not_member");
    assert_eq!(
        denied[0].get_object_id("user_id").unwrap().to_hex(),
        t.member.id
    );
    assert!(rows(&app, "vault_leases", doc! {}).await.is_empty());
}

/// FR-90 P3-9-1 — a person's lease stands on its owner: taken back at the
/// device's pod's next sweep when the device's row names another owner, or
/// when its owner leaves the organization, and at once when its value
/// changes, as a session's is. The row first, then the frame, and the audit
/// says why, under the person's action.
#[tokio::test]
async fn a_persons_lease_is_taken_back_when_the_owner_changes_or_leaves() {
    let app = connect_app("*", 1).await;
    let t = app.seed_tenant("vaultconnrevoke").await;
    let (secret_id, _) = upstream_secret(&app, &t, "db/orders", "db.internal:5432").await;
    policies(
        &app,
        &t,
        &[(
            "anyone-connects",
            r#"permit (principal, action == MeshHarbor::Action::"secret:connect", resource);"#
                .into(),
        )],
    )
    .await;
    let mut dev = device(&app, &t, "conn-revoke", "linux", TAKES_LEASES, true).await;
    let frame =
        || json!({ "secret": "db/orders", "field": "password", "audience": "db.internal:5432" });
    let lease = |answer: &Value| -> String {
        assert_eq!(answer["t"], "rc:vault.leased", "{answer}");
        answer["lease_id"].as_str().unwrap().to_string()
    };

    // The owner changes.
    set_owner(&app, &dev.agent_id, &t.member.id).await;
    let first = lease(&ask_connect(&mut dev, "r1", frame()).await);
    set_owner(&app, &dev.agent_id, &t.admin.id).await;
    let told = revoked(&mut dev, Duration::from_secs(10))
        .await
        .expect("a changed owner takes the lease back");
    assert_eq!(told["reason"], "owner_changed", "{told}");
    assert!(names_lease(&told, &first), "{told}");
    let row = rows(&app, "vault_leases", doc! { "_id": oid(&first) })
        .await
        .pop()
        .unwrap();
    assert_eq!(row.get_str("revoked_why").unwrap(), "owner_changed");
    let audit = rows(
        &app,
        "vault_audit",
        doc! { "op": "revoke", "target": format!("lease:{first}") },
    )
    .await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].get_str("action").unwrap(), "secret:connect");
    assert_eq!(audit[0].get_str("reason").unwrap(), "owner_changed");
    assert!(!audit[0].contains_key("session_id"), "{:?}", audit[0]);

    // The owner leaves the organization.
    set_owner(&app, &dev.agent_id, &t.member.id).await;
    let second = lease(&ask_connect(&mut dev, "r2", frame()).await);
    remove_member(&app, &t, &t.member.id).await;
    let told = revoked(&mut dev, Duration::from_secs(10))
        .await
        .expect("an owner who left takes the lease back");
    assert_eq!(told["reason"], "owner_not_member", "{told}");
    assert!(names_lease(&told, &second), "{told}");

    // A new value, as for any lease: at once.
    set_owner(&app, &dev.agent_id, &t.admin.id).await;
    let third = lease(&ask_connect(&mut dev, "r3", frame()).await);
    assert_eq!(
        put(
            &app,
            &t,
            &secret_id,
            "password",
            &format!("rotated-{}", ObjectId::new().to_hex())
        )
        .await,
        200
    );
    let told = revoked(&mut dev, Duration::from_secs(10))
        .await
        .expect("a new value takes the lease back");
    assert_eq!(told["reason"], "value_changed", "{told}");
    assert!(names_lease(&told, &third), "{told}");
}

/// FR-90 P3-9-1 — a device asks for its owner at most
/// `CONNECT_PER_MINUTE` times a minute; past it the answer is `busy` and
/// nothing is recorded, so a flood is no flood of audit rows.
#[tokio::test]
async fn a_devices_requests_for_its_owner_are_held_to_a_ceiling() {
    let app = connect_app("*", NEVER).await;
    let t = app.seed_tenant("vaultconnbusy").await;
    let mut dev = device(&app, &t, "conn-busy", "linux", TAKES_LEASES, true).await;
    set_owner(&app, &dev.agent_id, &t.member.id).await;
    let ceiling = meshharbor_remote_control::vault::lease_limits::CONNECT_PER_MINUTE;
    for i in 0..ceiling {
        let answer = ask_connect(
            &mut dev,
            &format!("b{i}"),
            json!({ "secret": "db/none", "audience": "db.internal:5432" }),
        )
        .await;
        assert_eq!(refused(&answer), "no_secret", "{i}: {answer}");
    }
    let answer = ask_connect(
        &mut dev,
        "over",
        json!({ "secret": "db/none", "audience": "db.internal:5432" }),
    )
    .await;
    assert_eq!(refused(&answer), "busy", "{answer}");
    let recorded = rows(&app, "vault_audit", doc! { "action": "secret:connect" }).await;
    assert_eq!(recorded.len() as u32, ceiling);
}
