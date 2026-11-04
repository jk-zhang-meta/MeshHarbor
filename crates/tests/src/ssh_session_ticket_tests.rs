// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-8-1b — an agent session's SSH request is the session's own:
//! `rc:ssh.request` carries the vault's ticket, and the network module holds
//! the request to it.
//!
//! Driven through RAW agent sockets, as FR-83's tests are (whose helpers these
//! share): the origin device asks, the target device is only watched. The
//! tickets are minted with the server's own auth service, so what these lock
//! is the network module's half alone (the vault's is `vault_ssh_tests`):
//!
//! - the device owner's own request from the same device is granted, so a
//!   session's refusal is the session's, never the owner's rights at work;
//! - a session's request is refused at gate 3 until decision 22, echoes its
//!   ticket, pushes nothing to the target, and is audited as the session's;
//! - a ticket that does not hold (another target, not this server's, an
//!   account the target no longer maps) is refused, never answered as the
//!   owner's, and so is a session's request to a target that cannot hold a
//!   grant to one command.

use std::time::{Duration, Instant};

use bson::{doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::models::SshAccountMode;
use meshharbor_services::auth::SshTicket;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::ssh_grant_ack_tests::{
    AgentWs, Device, SESSION_KEY, device, enable_org_ssh, next_grant, send_ack,
};

/// A current device, which says hello as Linux: it acknowledges grants
/// (FR-83) and runs `console_user` as the person at its screen (FR-97 P5a),
/// without which its `console_user` policy is refused 400.
const CURRENT: &[&str] = &[
    "exec",
    "ssh",
    "ssh-consent",
    "ssh-grant-ack",
    "console-user",
];

/// A current target that can also hold a grant to one command.
const ONE_COMMAND: &[&str] = &[
    "exec",
    "ssh",
    "ssh-consent",
    "ssh-grant-ack",
    "console-user",
    "ssh-one-command",
];

/// Wait until this server's hub holds the device. Its row reads online a
/// moment before the hub records its capabilities, and a request to it in
/// that window is refused as unsupported.
async fn held(app: &TestApp, agent_id: &str) {
    let aid = ObjectId::parse_str(agent_id).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !app.state.fleet().rc_hub.is_agent_online(aid) {
        assert!(Instant::now() < deadline, "the hub never held {agent_id}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Replace the device's SSH policy (the route is a full replace): on, as
/// `account_mode`, and able to originate.
async fn policy(app: &TestApp, seeded: &SeededTenant, agent_id: &str, account_mode: &str) {
    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/agent/{agent_id}/ssh-policy",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({ "mode": "on", "account_mode": account_mode, "can_originate": true }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "policy: {:?}", resp.status());
}

/// A ticket for `origin` → `target` as `account`, from this server, for a
/// session acting for `acts_for`.
fn ticket(
    app: &TestApp,
    seeded: &SeededTenant,
    acts_for: ObjectId,
    origin: &str,
    target: &str,
    account: SshAccountMode,
) -> (String, ObjectId, ObjectId) {
    let (session_id, ticket_id) = (ObjectId::new(), ObjectId::new());
    let token = app
        .state
        .auth
        .issue_ssh_ticket(&SshTicket {
            session_id,
            tenant_id: ObjectId::parse_str(&seeded.tenant_id).unwrap(),
            fence: 1,
            owner_user_id: acts_for,
            origin_agent_id: ObjectId::parse_str(origin).unwrap(),
            target_agent_id: ObjectId::parse_str(target).unwrap(),
            account,
            ticket_id,
            exp: bson::DateTime::now().timestamp_millis() / 1000 + 120,
        })
        .unwrap();
    (token, session_id, ticket_id)
}

/// Send `rc:ssh.request` on the origin's socket; the server's answer to it.
async fn ask(dev: &mut Device, request_id: &str, target: &str, ticket: Option<&str>) -> Value {
    let mut frame = json!({
        "t": "rc:ssh.request",
        "request_id": request_id,
        "target": target,
        "public_key": SESSION_KEY,
        "session_secs": 60,
    });
    if let Some(t) = ticket {
        frame["ssh_ticket"] = json!(t);
    }
    dev.ws
        .send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let next = tokio::time::timeout(left, dev.ws.next())
            .await
            .expect("no rc:ssh.response within 20 s")
            .expect("agent socket closed")
            .expect("agent socket error");
        if let Message::Text(t) = next {
            let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
            if v["t"] == "rc:ssh.response" && v["request_id"] == request_id {
                return v;
            }
        }
    }
}

/// No `rc:ssh.grant` reaches the target within `wait`.
async fn no_grant_within(ws: &mut AgentWs, wait: Duration) {
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        match tokio::time::timeout(left, ws.next()).await {
            Err(_) => return,
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                assert_ne!(v["t"], "rc:ssh.grant", "a grant reached the target: {v}");
            }
            Ok(_) => {}
        }
    }
}

/// The `ssh_audit` rows aimed at `target`, oldest first.
async fn audit_rows(app: &TestApp, target: &str) -> Vec<bson::Document> {
    let mut cur = app
        .db
        .collection::<bson::Document>("ssh_audit")
        .find(doc! { "agent_id": ObjectId::parse_str(target).unwrap() })
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(row) = cur.next().await {
        out.push(row.unwrap());
    }
    out
}

/// FR-90 P3-8-1b — the device owner's own request from the origin is granted,
/// so the owner WOULD be let in; the session's request from the same device,
/// with a ticket that holds, is refused at gate 3 (no policy names sessions
/// before decision 22), echoes its ticket, pushes no grant to the target, and
/// is audited as the session's: never served as the owner's.
#[tokio::test]
async fn a_sessions_request_is_its_own_and_none_is_admitted_yet() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("sshsession").await;
    enable_org_ssh(&app, &seeded).await;
    let mut origin = device(&app, &seeded, "ssh-origin", "100.64.0.21", CURRENT).await;
    let mut target = device(&app, &seeded, "ssh-target", "100.64.0.22", ONE_COMMAND).await;
    policy(&app, &seeded, &origin.agent_id, "console_user").await;
    policy(&app, &seeded, &target.agent_id, "console_user").await;
    held(&app, &origin.agent_id).await;
    held(&app, &target.agent_id).await;
    let target_id = target.agent_id.clone();

    // The owner's own request, from the same device: granted once the target
    // confirms (FR-83).
    let ask_owner = ask(&mut origin, "own", &target_id, None);
    let confirm = async {
        let grant = next_grant(&mut target.ws).await;
        send_ack(&mut target.ws, &grant, None).await;
    };
    let (owner_answer, ()) = tokio::join!(ask_owner, confirm);
    assert!(owner_answer["error"].is_null(), "{owner_answer}");
    assert!(owner_answer["address"].is_string(), "{owner_answer}");
    assert!(
        owner_answer.get("ssh_ticket_id").is_none(),
        "{owner_answer}"
    );

    // The session's, under a ticket that holds: refused at gate 3, echoed,
    // and nothing reaches the target. It acts for someone who does NOT own
    // the device it runs on, so the audit must name that person, not the
    // device's owner.
    let acts_for = ObjectId::new();
    let (token, session_id, ticket_id) = ticket(
        &app,
        &seeded,
        acts_for,
        &origin.agent_id,
        &target_id,
        SshAccountMode::ConsoleUser,
    );
    let answer = ask(&mut origin, "session", &target_id, Some(&token)).await;
    assert!(
        answer["error"]
            .as_str()
            .is_some_and(|e| e.contains("admits agent sessions")),
        "{answer}"
    );
    assert!(answer["address"].is_null(), "{answer}");
    assert_eq!(answer["ssh_ticket_id"], ticket_id.to_hex(), "the echo");
    no_grant_within(&mut target.ws, Duration::from_millis(1500)).await;

    // Audited as the session's, and the owner's row as the owner's.
    let rows = audit_rows(&app, &target_id).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let (owner_row, session_row) = (&rows[0], &rows[1]);
    assert_eq!(owner_row.get_str("source").unwrap(), "cli");
    assert!(owner_row.get("session_id").is_none());
    assert!(owner_row.get("denied").is_none(), "the owner's was granted");
    assert_eq!(session_row.get_str("source").unwrap(), "session");
    assert_eq!(session_row.get_object_id("session_id").unwrap(), session_id);
    assert_eq!(
        session_row.get_str("ssh_ticket_id").unwrap(),
        ticket_id.to_hex()
    );
    assert_eq!(
        session_row.get_str("denied").unwrap(),
        "session_not_allowed"
    );
    assert_eq!(
        session_row.get_object_id("user_id").unwrap(),
        acts_for,
        "the person the session acts for, not the device's owner"
    );
    assert_ne!(acts_for.to_hex(), seeded.admin.id, "the device's owner");
    let caller = session_row.get_str("caller").unwrap();
    assert!(
        caller.contains(&session_id.to_hex()),
        "the caller names the session: {caller}"
    );
    assert!(
        caller.contains(&acts_for.to_hex()),
        "and the person it acts for (no display name: the id): {caller}"
    );
}

/// FR-90 P3-8-1b — a ticket that does not hold refuses the request in words,
/// audited as a session's that names no session, and the owner's path is
/// never taken instead: a ticket for another target, one this server did not
/// sign, one for an account the target no longer maps; and a session's
/// request to a target that cannot hold a grant to one command.
#[tokio::test]
async fn a_ticket_that_does_not_hold_refuses_the_request() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("sshticket").await;
    enable_org_ssh(&app, &seeded).await;
    let mut origin = device(&app, &seeded, "tk-origin", "100.64.0.31", CURRENT).await;
    let mut target = device(&app, &seeded, "tk-target", "100.64.0.32", ONE_COMMAND).await;
    let mut old = device(&app, &seeded, "tk-old", "100.64.0.33", CURRENT).await;
    policy(&app, &seeded, &origin.agent_id, "console_user").await;
    policy(&app, &seeded, &target.agent_id, "console_user").await;
    policy(&app, &seeded, &old.agent_id, "console_user").await;
    for d in [&origin, &target, &old] {
        held(&app, &d.agent_id).await;
    }
    let (target_id, old_id) = (target.agent_id.clone(), old.agent_id.clone());
    let refused_ticket = "does not hold";
    let admin = ObjectId::parse_str(&seeded.admin.id).unwrap();

    // A ticket for another target: refused, not echoed (nothing it claims
    // was verified), and the target hears nothing.
    let (for_old, _, _) = ticket(
        &app,
        &seeded,
        admin,
        &origin.agent_id,
        &old_id,
        SshAccountMode::ConsoleUser,
    );
    let a = ask(&mut origin, "other-target", &target_id, Some(&for_old)).await;
    assert!(
        a["error"]
            .as_str()
            .is_some_and(|e| e.contains(refused_ticket)),
        "{a}"
    );
    assert!(a.get("ssh_ticket_id").is_none(), "{a}");

    // Not a ticket this server signed: refused alike.
    let garbage = ["not", "a", "ticket"].join(".");
    let a = ask(&mut origin, "garbage", &target_id, Some(&garbage)).await;
    assert!(
        a["error"]
            .as_str()
            .is_some_and(|e| e.contains(refused_ticket)),
        "{a}"
    );
    no_grant_within(&mut target.ws, Duration::from_millis(1000)).await;

    // Decided for `daemon` while the target now maps `console_user`: the
    // ticket held, so it is echoed, and refused as one that no longer does.
    let (stale, _, stale_id) = ticket(
        &app,
        &seeded,
        admin,
        &origin.agent_id,
        &target_id,
        SshAccountMode::Daemon,
    );
    let a = ask(&mut origin, "account", &target_id, Some(&stale)).await;
    assert!(
        a["error"]
            .as_str()
            .is_some_and(|e| e.contains(refused_ticket)),
        "{a}"
    );
    assert_eq!(a["ssh_ticket_id"], stale_id.to_hex(), "{a}");

    // A target that cannot hold a grant to one command.
    let (for_old, _, old_ticket_id) = ticket(
        &app,
        &seeded,
        admin,
        &origin.agent_id,
        &old_id,
        SshAccountMode::ConsoleUser,
    );
    let a = ask(&mut origin, "too-old", &old_id, Some(&for_old)).await;
    assert!(
        a["error"]
            .as_str()
            .is_some_and(|e| e.contains("ssh-one-command")),
        "{a}"
    );
    assert_eq!(a["ssh_ticket_id"], old_ticket_id.to_hex(), "{a}");
    no_grant_within(&mut old.ws, Duration::from_millis(1000)).await;

    // Audited: the three refusals at the target, each a session's; the two
    // whose ticket never held name no session.
    let rows = audit_rows(&app, &target_id).await;
    let words: Vec<(&str, &str, bool)> = rows
        .iter()
        .map(|r| {
            (
                r.get_str("source").unwrap(),
                r.get_str("denied").unwrap(),
                r.get("session_id").is_some(),
            )
        })
        .collect();
    assert_eq!(
        words,
        [
            ("session", "ticket_refused", false),
            ("session", "ticket_refused", false),
            ("session", "ticket_refused", true),
        ]
    );
    let old_rows = audit_rows(&app, &old_id).await;
    assert_eq!(old_rows.len(), 1, "{old_rows:?}");
    assert_eq!(old_rows[0].get_str("denied").unwrap(), "target_too_old");
    assert!(old_rows[0].get("session_id").is_some());
}
