// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-4e — the approval a policy may ask for (`context has approval`):
//! a card in the session's room, a driver's answer, and the one lease a yes
//! allows.
//!
//! Driven through the lease tests' raw agent socket, with the real start
//! route and the real answer routes. What these lock:
//!
//! - where only a yes could allow a lease, the vault posts ONE card into the
//!   session's room and refuses `awaiting_approval`, naming it, however often
//!   the session asks;
//! - a driver's yes allows exactly one lease of that very request — the
//!   secret, the mode, the audience, no longer than the card named — and
//!   the allow records who said yes; a no refuses the request `denied`;
//! - only a driver who reads the session answers, and only one whose yes
//!   the policy accepts (`approver in MeshHarbor::Group::…`); no card is posted
//!   where no driver could give one;
//! - a card nobody answered in time expires, and one for a session that
//!   moved is withdrawn: neither can be answered, and neither keeps the
//!   session from asking again.

use bson::{DateTime, doc, oid::ObjectId};
use serde_json::{Value, json};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::vault_lease_tests::{
    Device, TAKES_LEASES, ask, device, lease_app, opened, post, refused, rows, secret, start,
};

/// A role `dev` anyone may assume, which may use what is under `db/` only
/// `when { <cond> }`; and `db/main`, whose value is answered.
async fn seed(app: &TestApp, t: &SeededTenant, cond: &str) -> String {
    let (code, body) = post(app, t, "/vault/role", json!({ "name": "dev" })).await;
    assert_eq!(code, 201, "{body}");
    for (name, text) in [
        (
            "anyone-may-be-dev",
            r#"permit (principal, action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev");"#
                .to_string(),
        ),
        (
            "dev-uses-db-with-a-yes",
            format!(
                r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"secret:use", resource in MeshHarbor::SecretFolder::"rrn:{}:secret:db") when {{ {cond} }};"#,
                t.tenant_slug
            ),
        ),
    ] {
        let (code, body) = post(app, t, "/vault/policy", json!({ "name": name, "text": text })).await;
        assert_eq!(code, 201, "{body}");
    }
    // A value made here, never written down.
    let value = format!("approval-canary-{}", ObjectId::new().to_hex());
    secret(app, t, "db/main", &value).await;
    value
}

/// A lease of `db/main` in `env` mode toward `audience`, for `ttl` seconds.
fn lease(sid: &str, fence: u64, audience: &str, ttl: u64) -> Value {
    json!({ "session_id": sid, "fence": fence, "secret": "db/main", "mode": "env",
            "audience": audience, "ttl_secs": ttl })
}

/// The approval an `awaiting_approval` refusal names.
fn awaiting(answer: &Value) -> String {
    assert_eq!(refused(answer), "awaiting_approval", "{answer}");
    answer["approval_id"]
        .as_str()
        .expect("awaiting_approval names its approval")
        .to_string()
}

fn approval_path(t: &SeededTenant, id: &str) -> String {
    format!("/api/tenant/{}/vault/approval/{id}", t.tenant_id)
}

async fn get_as(app: &TestApp, token: &str, path: &str) -> (u16, Value) {
    let resp = app.auth_get(path, token).send().await.unwrap();
    let code = resp.status().as_u16();
    (code, resp.json().await.unwrap_or(Value::Null))
}

async fn answer_as(app: &TestApp, token: &str, path: &str, answer: &str) -> (u16, Value) {
    let resp = app
        .auth_post(path, token)
        .json(&json!({ "answer": answer }))
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    (code, resp.json().await.unwrap_or(Value::Null))
}

/// The card bound to approval `id`: its text.
async fn card(app: &TestApp, id: &str) -> String {
    let cards = rows(
        app,
        "messages",
        doc! { "binding.module": "vault", "binding.ref": id },
    )
    .await;
    assert_eq!(cards.len(), 1, "one card per approval: {cards:?}");
    cards[0].get_str("content").unwrap().to_string()
}

async fn approval_row(app: &TestApp, id: &str) -> bson::Document {
    let id = ObjectId::parse_str(id).unwrap();
    rows(app, "vault_approvals", doc! { "_id": id })
        .await
        .pop()
        .expect("the approval's row")
}

/// Name `user` a driver or a reader of the session, as its owner.
async fn participant(app: &TestApp, t: &SeededTenant, sid: &str, user: &str, role: &str) {
    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/hive/session/{sid}/participant/{user}",
                t.tenant_id
            ),
            &t.admin.access_token,
        )
        .json(&json!({ "role": role }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the owner names a {role}");
}

/// A meshharbor role `name` that runs agent sessions (HIVE_RUN), given to the
/// seeded member.
async fn member_role(app: &TestApp, t: &SeededTenant, name: &str) {
    let tid = &t.tenant_id;
    let role: Value = app
        .auth_post(&format!("/api/tenant/{tid}/role"), &t.admin.access_token)
        .json(
            &json!({ "name": name, "description": "answers vault approvals",
                       "permissions": 1_u64 << 32, "position": 60 }),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let assigned = app
        .auth_post(
            &format!(
                "/api/tenant/{tid}/role/{}/assign/{}",
                role["id"].as_str().expect("the role is made"),
                t.member.id
            ),
            &t.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(assigned.status().is_success(), "{:?}", assigned.status());
}

async fn running(app: &TestApp, t: &SeededTenant, machine: &str) -> (Device, String, u64) {
    let mut dev = device(app, t, machine, "linux", TAKES_LEASES, true).await;
    let (sid, fence) = start(app, t, &mut dev, "/work/approve", Some("dev")).await;
    (dev, sid, fence)
}

/// FR-90 P3-4e — the whole round: a policy that asks for a yes gets ONE card
/// however often the session asks; the card names what was asked; a
/// driver's yes allows one lease, recorded with who said yes; the next ask
/// needs a new yes; a no refuses `denied`.
#[tokio::test]
async fn a_yes_a_policy_asks_for_allows_one_lease_and_a_no_refuses() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultyes").await;
    let value = seed(&app, &t, "context has approval").await;
    let (mut dev, sid, fence) = running(&app, &t, "yes-host").await;
    let owner = t.admin.access_token.clone();

    // ── One card, however often the session asks ──────────────────────────
    let first = ask(&mut dev, "y1", lease(&sid, fence, "psql", 60)).await;
    let a1 = awaiting(&first);
    let again = ask(&mut dev, "y2", lease(&sid, fence, "psql", 60)).await;
    assert_eq!(awaiting(&again), a1, "the same card: {again}");
    let sid_oid = ObjectId::parse_str(&sid).unwrap();
    assert_eq!(
        rows(&app, "vault_approvals", doc! { "session_id": sid_oid })
            .await
            .len(),
        1,
        "one approval"
    );
    let text = card(&app, &a1).await;
    assert!(text.contains("Approval needed"), "{text}");
    assert!(
        text.contains("`db/main` in `env` mode toward psql, for up to 1 min"),
        "{text}"
    );
    assert!(!text.contains(&value), "a card never carries a value");
    // Both asks were recorded as denies waiting on it.
    let waits = rows(
        &app,
        "vault_audit",
        doc! { "session_id": sid_oid, "reason": "awaiting_approval" },
    )
    .await;
    assert_eq!(waits.len(), 2, "{waits:?}");
    assert_eq!(
        waits[0].get_str("target").unwrap(),
        format!("approval:{a1}")
    );

    // ── Who sees it ───────────────────────────────────────────────────────
    let path = approval_path(&t, &a1);
    let (code, view) = get_as(&app, &owner, &path).await;
    assert_eq!(code, 200, "{view}");
    assert_eq!(view["status"], "pending");
    assert_eq!(view["may_answer"], true, "{view}");
    assert_eq!(view["may_approve"], true, "{view}");
    assert_eq!(view["mode"], "env");
    assert_eq!(view["ttl_s"], 60);
    assert_eq!(view["rrn"], format!("rrn:{}:secret:db/main", t.tenant_slug));
    // A member outside the session's room: nothing to see, nothing to answer.
    let (code, _) = get_as(&app, &t.member.access_token, &path).await;
    assert_eq!(code, 404);
    let (code, _) = answer_as(&app, &t.member.access_token, &path, "approve").await;
    assert_eq!(code, 404);
    let (code, _) = answer_as(&app, &owner, &path, "maybe").await;
    assert_eq!(code, 400);

    // ── A yes allows ONE lease ────────────────────────────────────────────
    let (code, view) = answer_as(&app, &owner, &path, "approve").await;
    assert_eq!(code, 200, "{view}");
    assert_eq!(view["status"], "approved");
    assert_eq!(view["answered_by"], t.admin.id);
    assert!(card(&app, &a1).await.contains("✅ approved by"));
    let leased = ask(&mut dev, "y3", lease(&sid, fence, "psql", 60)).await;
    assert_eq!(opened(&dev, &leased), value);
    let row = approval_row(&app, &a1).await;
    assert_eq!(row.get_str("status").unwrap(), "used");
    assert_eq!(
        row.get_object_id("lease_id").unwrap().to_hex(),
        leased["lease_id"].as_str().unwrap()
    );
    assert!(card(&app, &a1).await.ends_with(", and used"));
    // The allow names who said yes, in the groups they hold.
    let allow = rows(
        &app,
        "vault_audit",
        doc! { "target": format!("lease:{}", leased["lease_id"].as_str().unwrap()) },
    )
    .await;
    assert_eq!(allow.len(), 1, "{allow:?}");
    let request = allow[0].get_document("request").unwrap();
    assert_eq!(
        request.get_object_id("approver").unwrap().to_hex(),
        t.admin.id
    );
    assert!(
        !request.get_array("approver_groups").unwrap().is_empty(),
        "{request}"
    );
    let (code, _) = answer_as(&app, &owner, &path, "approve").await;
    assert_eq!(code, 409, "a used yes is answered already");

    // ── The next ask needs a new yes; a no refuses it ─────────────────────
    let next = ask(&mut dev, "y4", lease(&sid, fence, "psql", 60)).await;
    let a2 = awaiting(&next);
    assert_ne!(a2, a1, "a yes is spent by its one lease");
    let (code, view) = answer_as(&app, &owner, &approval_path(&t, &a2), "deny").await;
    assert_eq!(code, 200, "{view}");
    assert_eq!(view["status"], "denied");
    assert!(card(&app, &a2).await.contains("⛔ denied by"));
    let no = ask(&mut dev, "y5", lease(&sid, fence, "psql", 60)).await;
    assert_eq!(refused(&no), "denied");
    assert!(
        no.get("approval_id").is_none(),
        "only a wait names one: {no}"
    );
    let denied = rows(
        &app,
        "vault_audit",
        doc! { "session_id": sid_oid, "reason": "approval_denied" },
    )
    .await;
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(
        denied[0].get_str("target").unwrap(),
        format!("approval:{a2}")
    );
    // The answers are recorded too, by who gave them.
    let answers = rows(&app, "vault_audit", doc! { "op": "approval" }).await;
    let reasons: Vec<&str> = answers
        .iter()
        .map(|r| r.get_str("reason").unwrap())
        .collect();
    assert_eq!(reasons, ["approved", "denied"], "{answers:?}");
}

/// FR-90 P3-4e — a policy may name whose yes counts. A card is posted only
/// where one of the session's drivers could give it — never for a reader —
/// and a driver whose yes the policy does not accept is refused, while the
/// card waits on for one it does.
#[tokio::test]
async fn a_yes_counts_only_from_a_driver_the_policy_names() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultwho").await;
    // The group exists before a policy may name it.
    member_role(&app, &t, "approvers").await;
    let value = seed(
        &app,
        &t,
        r#"context has approval && context.approval.approver in MeshHarbor::Group::"approvers""#,
    )
    .await;
    let (mut dev, sid, fence) = running(&app, &t, "who-host").await;
    let sid_oid = ObjectId::parse_str(&sid).unwrap();

    // Only the owner drives, and the owner is no approver: no card at all.
    let none = ask(&mut dev, "w1", lease(&sid, fence, "psql", 60)).await;
    assert_eq!(refused(&none), "denied", "{none}");
    // A reader is no candidate either.
    participant(&app, &t, &sid, &t.member.id, "reader").await;
    let reader = ask(&mut dev, "w2", lease(&sid, fence, "psql", 60)).await;
    assert_eq!(refused(&reader), "denied", "{reader}");
    assert!(
        rows(&app, "vault_approvals", doc! { "session_id": sid_oid })
            .await
            .is_empty(),
        "no card where no driver could answer it"
    );

    // Named a driver, the approver makes a card worth posting.
    participant(&app, &t, &sid, &t.member.id, "driver").await;
    let wait = ask(&mut dev, "w3", lease(&sid, fence, "psql", 60)).await;
    let id = awaiting(&wait);
    let path = approval_path(&t, &id);

    // The owner drives but is no approver: its GET says so, its yes is
    // refused, and the card waits on.
    let (_, view) = get_as(&app, &t.admin.access_token, &path).await;
    assert_eq!(view["may_answer"], true, "{view}");
    assert_eq!(view["may_approve"], false, "{view}");
    let (code, body) = answer_as(&app, &t.admin.access_token, &path, "approve").await;
    assert_eq!(code, 403, "{body}");
    let (_, view) = get_as(&app, &t.admin.access_token, &path).await;
    assert_eq!(view["status"], "pending", "{view}");
    let refusal = rows(&app, "vault_audit", doc! { "op": "approval" }).await;
    assert_eq!(refusal.len(), 1, "{refusal:?}");
    assert!(
        refusal[0]
            .get_str("reason")
            .unwrap()
            .starts_with("approver_refused"),
        "{refusal:?}"
    );

    // Only while they drive it: a reader sees the card and answers nothing.
    participant(&app, &t, &sid, &t.member.id, "reader").await;
    let (code, view) = get_as(&app, &t.member.access_token, &path).await;
    assert_eq!(code, 200, "a reader sees it: {view}");
    assert_eq!(view["may_answer"], false, "{view}");
    assert_eq!(view["may_approve"], false, "{view}");
    let (code, body) = answer_as(&app, &t.member.access_token, &path, "approve").await;
    assert_eq!(code, 403, "{body}");
    let refusals = rows(&app, "vault_audit", doc! { "op": "approval" }).await;
    assert_eq!(
        refusals.last().unwrap().get_str("reason").unwrap(),
        "not_a_driver"
    );

    // The approver's yes counts.
    participant(&app, &t, &sid, &t.member.id, "driver").await;
    let (code, view) = get_as(&app, &t.member.access_token, &path).await;
    assert_eq!(code, 200);
    assert_eq!(view["may_answer"], true, "{view}");
    assert_eq!(view["may_approve"], true, "{view}");
    let (code, view) = answer_as(&app, &t.member.access_token, &path, "approve").await;
    assert_eq!(code, 200, "{view}");
    let leased = ask(&mut dev, "w4", lease(&sid, fence, "psql", 60)).await;
    assert_eq!(opened(&dev, &leased), value);
}

/// FR-90 P3-4e — a yes is for that very request: no other audience, no
/// longer TTL. A card nobody answered in time expires — and neither holds
/// the request's place nor takes an answer — and a session that moved has
/// its card withdrawn.
#[tokio::test]
async fn a_yes_is_for_that_request_and_a_card_ends_when_nobody_can_act_on_it() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultkey").await;
    let value = seed(&app, &t, "context has approval").await;
    let (mut dev, sid, fence) = running(&app, &t, "key-host").await;
    let owner = t.admin.access_token.clone();

    let yes = awaiting(&ask(&mut dev, "k1", lease(&sid, fence, "psql", 60)).await);
    let (code, _) = answer_as(&app, &owner, &approval_path(&t, &yes), "approve").await;
    assert_eq!(code, 200);
    // Longer than the card named: a new card.
    let longer = awaiting(&ask(&mut dev, "k2", lease(&sid, fence, "psql", 120)).await);
    assert_ne!(longer, yes);
    // Toward another audience: a new card.
    let other = awaiting(&ask(&mut dev, "k3", lease(&sid, fence, "pg_dump", 60)).await);
    assert_ne!(other, yes);
    assert_ne!(other, longer);
    // No longer than it named: the yes allows it.
    let leased = ask(&mut dev, "k4", lease(&sid, fence, "psql", 30)).await;
    assert_eq!(opened(&dev, &leased), value);
    assert_eq!(
        approval_row(&app, &yes).await.get_str("status").unwrap(),
        "used"
    );

    // Nobody answered `longer` in time: the next ask gets a fresh card, and
    // the stale one says it ended.
    let past = DateTime::from_millis(DateTime::now().timestamp_millis() - 1000);
    let expire = |id: &str| {
        let id = ObjectId::parse_str(id).unwrap();
        let db = app.db.clone();
        async move {
            db.collection::<bson::Document>("vault_approvals")
                .update_one(doc! { "_id": id }, doc! { "$set": { "expires_at": past } })
                .await
                .unwrap();
        }
    };
    expire(&longer).await;
    let fresh = awaiting(&ask(&mut dev, "k5", lease(&sid, fence, "psql", 120)).await);
    assert_ne!(fresh, longer, "a stale card holds no place");
    assert_eq!(
        approval_row(&app, &longer).await.get_str("status").unwrap(),
        "expired"
    );
    assert!(
        card(&app, &longer)
            .await
            .ends_with("⌛ nobody answered in time")
    );
    // Nor does one take an answer.
    expire(&other).await;
    let (code, body) = answer_as(&app, &owner, &approval_path(&t, &other), "approve").await;
    assert_eq!(code, 409, "{body}");
    assert_eq!(
        approval_row(&app, &other).await.get_str("status").unwrap(),
        "expired"
    );

    // The session moves on (a newer fence): its open card is withdrawn.
    let sid_oid = ObjectId::parse_str(&sid).unwrap();
    app.db
        .collection::<bson::Document>("agent_sessions")
        .update_one(doc! { "_id": sid_oid }, doc! { "$inc": { "fence": 1_i64 } })
        .await
        .unwrap();
    let path = approval_path(&t, &fresh);
    let (code, body) = answer_as(&app, &owner, &path, "approve").await;
    assert_eq!(code, 409, "{body}");
    let (_, view) = get_as(&app, &owner, &path).await;
    assert_eq!(view["status"], "withdrawn", "{view}");
    assert_eq!(view["may_answer"], false);
    assert!(
        card(&app, &fresh)
            .await
            .ends_with("⏹ withdrawn: the session moved or ended")
    );
}
