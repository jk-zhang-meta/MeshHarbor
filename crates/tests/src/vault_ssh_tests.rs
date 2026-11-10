// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-8-1a — a session's command on another device: `rc:vault.ssh`,
//! answered with a ticket signed under its own audience (`ssh_ticket`).
//!
//! Driven through the RAW agent socket the lease tests use. What these lock
//! is the SERVER:
//!
//! - a ticket is decided by Cedar's `ssh:run`, the target's facts and the
//!   account its SSH policy maps read from ITS row, and names exactly what was
//!   decided: the session at its fence, its owner, the device it runs on, the
//!   target, the account, an end within the lease ceiling;
//! - the allow is recorded, naming the ticket, before the ticket is sent;
//! - it is believed only from the device the session's record places it on,
//!   at the record's fence, toward a live device of the organization that is
//!   NOT that device;
//! - every refusal is one word, and only the ticket's own verifier takes it.

use std::time::Duration;

use bson::{Document, doc, oid::ObjectId};
use futures::StreamExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::vault_lease_tests::{
    Device, TAKES_LEASES, device, enroll, lease_app, post, refused, rows, send, start,
};
use meshharbor_services::auth::SshTicketClaims;

/// Ask for a command on `target`; the vault's answer to that request.
async fn ask_ssh(dev: &mut Device, req_id: &str, mut frame: Value) -> Value {
    frame["t"] = json!("rc:vault.ssh");
    frame["req_id"] = json!(req_id);
    if frame.get("ttl_secs").is_none() {
        frame["ttl_secs"] = json!(120);
    }
    send(&mut dev.ws, frame).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = tokio::time::timeout(left, dev.ws.next())
            .await
            .expect("no answer to the SSH request within 10 s")
            .expect("agent socket closed")
            .expect("agent socket error");
        if let Message::Text(text) = next {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let t = v["t"].as_str().unwrap_or_default();
            if (t == "rc:vault.ssh.granted" || t == "rc:vault.refused") && v["req_id"] == req_id {
                return v;
            }
        }
    }
}

/// The ticket an answer carries, as its own verifier reads it.
fn ticketed(app: &TestApp, answer: &Value) -> SshTicketClaims {
    assert_eq!(answer["t"], "rc:vault.ssh.granted", "{answer}");
    let claims = app
        .state
        .auth
        .verify_ssh_ticket(answer["ticket"].as_str().unwrap())
        .expect("the ticket verifies as an SSH ticket");
    assert_eq!(answer["ticket_id"], claims.jti.as_str(), "{answer}");
    assert_eq!(answer["account"], claims.account.as_str(), "{answer}");
    assert_eq!(
        answer["expires_at_ms"].as_i64(),
        Some(claims.exp * 1000),
        "the answer's end is the ticket's, in whole seconds"
    );
    claims
}

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

/// A device's tags and the account its SSH policy maps, as its row holds
/// them.
async fn set_row(app: &TestApp, device_id: &str, tags: &[&str], account: &str) {
    let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": oid(device_id) },
            doc! { "$set": { "tags": tags, "ssh_policy.account_mode": account } },
        )
        .await
        .unwrap();
}

/// A role `dev` anyone may assume, which may run a command on a node tagged
/// `build`, and a guardrail that no session runs one as the daemon.
async fn seed_ssh(app: &TestApp, t: &SeededTenant) {
    let (code, body) = post(app, t, "/vault/role", json!({ "name": "dev" })).await;
    assert_eq!(code, 201, "{body}");
    for (name, text) in [
        (
            "anyone-may-be-dev",
            r#"permit (principal, action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev");"#,
        ),
        (
            "dev-runs-on-build",
            r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"ssh:run", resource) when { resource.tags.contains("build") };"#,
        ),
        (
            "never-as-the-daemon",
            r#"forbid (principal, action == MeshHarbor::Action::"ssh:run", resource) when { context.account == "daemon" };"#,
        ),
    ] {
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

/// FR-90 P3-8-1a — a session holding a role is ticketed for the commands
/// its role is allowed, and the ticket names exactly what was decided: a
/// target whose ROW carries the tag, as the account its ROW's SSH policy
/// maps, recorded before it was sent. A node no policy names, an account a
/// guardrail forbids, the session's own device, a target that is no device
/// of the organization, and a request past its bounds are each refused in
/// one word.
#[tokio::test]
async fn a_session_is_ticketed_for_the_commands_its_role_is_allowed() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultssh").await;
    let other = app.seed_tenant("vaultssh2").await;
    seed_ssh(&app, &t).await;
    let mut dev = device(&app, &t, "ssh-host", "linux", TAKES_LEASES, true).await;
    let (build, _) = enroll(&app, &t, "ssh-build", "windows").await;
    let (rooted, _) = enroll(&app, &t, "ssh-rooted", "linux").await;
    let (lab, _) = enroll(&app, &t, "ssh-lab", "linux").await;
    let (foreign, _) = enroll(&app, &other, "ssh-foreign", "linux").await;
    // The tag and the account are the ROW's: a request names neither.
    set_row(&app, &build, &["Build"], "console_user").await;
    set_row(&app, &rooted, &["build"], "daemon").await;
    set_row(&app, &lab, &["lab"], "console_user").await;
    set_row(&app, &foreign, &["build"], "console_user").await;
    // The asker's own row would be allowed, were it ever a target.
    set_row(&app, &dev.agent_id, &["build"], "console_user").await;
    let (sid, fence) = start(&app, &t, &mut dev, "/srv/s", Some("dev")).await;
    let base = |target: &str| json!({ "session_id": sid, "fence": fence, "target": target });

    // On the build box: ticketed, naming the session, its places, the account.
    let before = bson::DateTime::now().timestamp_millis() / 1000;
    let answer = ask_ssh(&mut dev, "s1", base(&build)).await;
    let k = ticketed(&app, &answer);
    assert_eq!((k.sub.as_str(), k.fence), (sid.as_str(), fence));
    assert_eq!(k.tenant_id, t.tenant_id);
    assert_eq!(k.owner_user_id, t.admin.id, "the session's owner");
    assert_eq!(k.origin_agent_id, dev.agent_id, "the device that asked");
    assert_eq!(k.target_agent_id, build);
    assert_eq!(k.account, "console_user", "the target's account");
    assert_eq!(answer["os"], "windows", "the target's system: {answer}");
    assert!(
        (before + 120..=before + 130).contains(&k.exp),
        "two minutes, as asked: {} from {before}",
        k.exp
    );

    // Recorded before it was sent: the allow, naming the ticket.
    let allows = rows(
        &app,
        "vault_audit",
        doc! { "action": "ssh:run", "decision": "allow" },
    )
    .await;
    assert_eq!(allows.len(), 1);
    let allow = &allows[0];
    assert_eq!(
        allow.get_str("target").unwrap(),
        format!("ticket:{}", k.jti)
    );
    assert_eq!(allow.get_str("op").unwrap(), "ticket");
    assert_eq!(allow.get_str("principal").unwrap(), "session");
    assert_eq!(allow.get_object_id("session_id").unwrap().to_hex(), sid);
    assert_eq!(
        allow.get_object_id("device_id").unwrap().to_hex(),
        dev.agent_id
    );
    let request = allow.get_document("request").unwrap();
    assert_eq!(request.get_str("action").unwrap(), "ssh:run");
    assert_eq!(request.get_str("account").unwrap(), "console_user");
    assert_eq!(
        request
            .get_document("node")
            .unwrap()
            .get_object_id("id")
            .unwrap()
            .to_hex(),
        build,
        "the request names its target"
    );
    assert_eq!(
        rows(&app, "vault_leases", doc! {}).await.len(),
        0,
        "a ticket is no lease"
    );

    // A node no policy names, and one the guardrail forbids: denied, recorded.
    assert_eq!(
        refused(&ask_ssh(&mut dev, "s2", base(&lab)).await),
        "denied"
    );
    assert_eq!(
        refused(&ask_ssh(&mut dev, "s3", base(&rooted)).await),
        "denied",
        "a session never runs as the daemon here"
    );
    let denies = rows(
        &app,
        "vault_audit",
        doc! { "action": "ssh:run", "decision": "deny" },
    )
    .await;
    assert_eq!(denies.len(), 2);
    let rooted_deny = denies
        .iter()
        .find(|d| d.get_str("target").ok() == Some(format!("asked:{rooted}").as_str()))
        .expect("the daemon's deny names its target");
    assert_eq!(
        rooted_deny
            .get_document("request")
            .unwrap()
            .get_str("account")
            .unwrap(),
        "daemon"
    );

    // The session's own device: refused, and recorded as such.
    let own = dev.agent_id.clone();
    assert_eq!(
        refused(&ask_ssh(&mut dev, "o1", base(&own)).await),
        "bad_request"
    );
    let own = rows(&app, "vault_audit", doc! { "reason": "own_device" }).await;
    assert_eq!(own.len(), 1, "the own-device refusal is recorded");
    assert_eq!(own[0].get_str("decision").unwrap(), "deny");

    // The lease ceiling bounds a ticket's life.
    let long = ask_ssh(
        &mut dev,
        "c1",
        json!({ "session_id": sid, "fence": fence, "target": build, "ttl_secs": 999_999 }),
    )
    .await;
    let k = ticketed(&app, &long);
    assert!(
        k.exp - k.iat <= 900,
        "clamped to the lease ceiling: {}",
        k.exp - k.iat
    );

    // `simulate` decides `ssh:run` as the vault decides a request: the
    // account the node maps, or one the simulation names.
    let sim = |account: Option<&str>| {
        let mut body = json!({
            "action": "ssh:run",
            "principal": { "role": "dev", "owner_id": t.admin.id },
            "resource": { "node_id": build },
            "device": { "os": "linux", "tags": [], "owner_id": t.admin.id },
        });
        if let Some(a) = account {
            body["account"] = json!(a);
        }
        post(&app, &t, "/vault/simulate", body)
    };
    let (code, v) = sim(None).await;
    assert_eq!((code, v["decision"].as_str()), (200, Some("allow")), "{v}");
    let (code, v) = sim(Some("daemon")).await;
    assert_eq!((code, v["decision"].as_str()), (200, Some("deny")), "{v}");
    let (code, v) = sim(Some("root")).await;
    assert_eq!(code, 400, "{v}");

    // No target: another organization's device, or no device at all.
    for (i, target) in [foreign.clone(), ObjectId::new().to_hex()]
        .iter()
        .enumerate()
    {
        let a = ask_ssh(&mut dev, &format!("x{i}"), base(target)).await;
        assert_eq!(refused(&a), "no_target", "{target}");
    }

    // Past its bounds, before anything is read: ids a refusal echoes as they
    // came (a longer one comes back clipped, so no asker could match it).
    for req_id in ["", "a\nb"] {
        let a = ask_ssh(&mut dev, req_id, base(&build)).await;
        assert_eq!(refused(&a), "bad_request", "{req_id:?}");
    }
    assert_eq!(
        rows(&app, "vault_audit", doc! { "op": "ticket" })
            .await
            .len(),
        7,
        "two allows, two denies, the own device, two targets that are none; \
         nothing past a bound"
    );
}

/// FR-90 P3-8-1a — a ticket is believed only from the device the session's
/// record places it on, at the record's fence, for a session holding a role
/// that is not over; no other gate takes it as its credential, and it takes
/// no other.
#[tokio::test]
async fn a_ticket_is_believed_only_from_the_device_that_runs_the_session() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaulttktwho").await;
    seed_ssh(&app, &t).await;
    let mut a = device(&app, &t, "ssh-a", "linux", TAKES_LEASES, true).await;
    let mut b = device(&app, &t, "ssh-b", "linux", TAKES_LEASES, true).await;
    let (target, _) = enroll(&app, &t, "ssh-target", "linux").await;
    set_row(&app, &target, &["build"], "named").await;
    let (sid, fence) = start(&app, &t, &mut a, "/srv/a", Some("dev")).await;
    let frame = json!({ "session_id": sid, "fence": fence, "target": target });

    // Another device of the organization, asking for a's session.
    assert_eq!(
        refused(&ask_ssh(&mut b, "b1", frame.clone()).await),
        "not_located"
    );
    // A fence the record does not hold.
    let mut stale = frame.clone();
    stale["fence"] = json!(fence + 1);
    assert_eq!(refused(&ask_ssh(&mut a, "a0", stale).await), "stale_fence");
    // A session that took no role.
    let (nsid, nfence) = start(&app, &t, &mut a, "/srv/n", None).await;
    let none = json!({ "session_id": nsid, "fence": nfence, "target": target });
    assert_eq!(refused(&ask_ssh(&mut a, "n1", none).await), "no_role");

    // The role's session is ticketed, until it is over.
    let answer = ask_ssh(&mut a, "a1", frame.clone()).await;
    let k = ticketed(&app, &answer);
    assert_eq!(
        (k.origin_agent_id.as_str(), k.account.as_str()),
        (a.agent_id.as_str(), "named")
    );
    let token = answer["ticket"].as_str().unwrap();
    let auth = &app.state.auth;
    assert!(
        auth.verify_agent_token(token).is_err(),
        "no agent's credential"
    );
    assert!(auth.verify_access_token(token).is_err(), "no person's");
    assert!(
        auth.verify_tunnel_client_token(token).is_err(),
        "no tunnel client's"
    );
    assert!(auth.verify_net_grant(token).is_err(), "no egress grant");
    assert!(
        auth.verify_ssh_ticket(&a.token).is_err(),
        "and an agent's token is no ticket"
    );
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": oid(&sid) },
            doc! { "$set": { "status": "ended" } },
        )
        .await
        .unwrap();
    assert_eq!(refused(&ask_ssh(&mut a, "a2", frame).await), "ended");
}
