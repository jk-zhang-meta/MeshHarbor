// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-7-1b — a session's own egress: `rc:vault.net`, answered with a
//! grant signed under its own audience (`net_grant`).
//!
//! Driven through the RAW agent socket the lease tests use. What these lock
//! is the SERVER:
//!
//! - a grant is decided by Cedar's `net:socks` or `net:forward`, the exit's
//!   facts read from ITS row, and names exactly what was decided: the session
//!   at its fence, its owner, the device it runs on, the exit, a forward's
//!   destination in its one spelling, an end within the lease ceiling;
//! - the allow is recorded, naming the grant, before the grant is sent;
//! - it is believed only from the device the session's record places it on,
//!   at the record's fence, toward a live device of the organization;
//! - every refusal is one word, and only the grant's own verifier takes it.

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
use meshharbor_services::auth::NetGrantClaims;

/// Ask for egress; the vault's answer to that request.
async fn ask_net(dev: &mut Device, req_id: &str, mut frame: Value) -> Value {
    frame["t"] = json!("rc:vault.net");
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
            .expect("no answer to the egress request within 10 s")
            .expect("agent socket closed")
            .expect("agent socket error");
        if let Message::Text(text) = next {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let t = v["t"].as_str().unwrap_or_default();
            if (t == "rc:vault.net.granted" || t == "rc:vault.refused") && v["req_id"] == req_id {
                return v;
            }
        }
    }
}

/// The grant an answer carries, as its own verifier reads it.
fn granted(app: &TestApp, answer: &Value) -> NetGrantClaims {
    assert_eq!(answer["t"], "rc:vault.net.granted", "{answer}");
    let claims = app
        .state
        .auth
        .verify_net_grant(answer["grant"].as_str().unwrap())
        .expect("the grant verifies as a net grant");
    assert_eq!(answer["grant_id"], claims.jti.as_str(), "{answer}");
    assert_eq!(
        answer["expires_at_ms"].as_i64(),
        Some(claims.exp * 1000),
        "the answer's end is the grant's, in whole seconds"
    );
    claims
}

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

async fn tag(app: &TestApp, device_id: &str, tags: &[&str]) {
    let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": oid(device_id) },
            doc! { "$set": { "tags": tags } },
        )
        .await
        .unwrap();
}

/// A role `dev` anyone may assume, which may open SOCKS through an exit
/// tagged `office` and forward to Postgres on `db.internal` through any.
async fn seed_net(app: &TestApp, t: &SeededTenant) {
    let (code, body) = post(app, t, "/vault/role", json!({ "name": "dev" })).await;
    assert_eq!(code, 201, "{body}");
    for (name, text) in [
        (
            "anyone-may-be-dev",
            r#"permit (principal, action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev");"#,
        ),
        (
            "dev-socks-via-the-office",
            r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"net:socks", resource) when { resource.tags.contains("office") };"#,
        ),
        (
            "dev-forwards-to-postgres",
            r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"net:forward", resource) when { context.host == "db.internal" && context.port == 5432 };"#,
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

/// FR-90 P3-7-1b — a session holding a role is granted the egress its role
/// is allowed, and the grant names exactly what was decided: SOCKS through
/// an exit whose ROW carries the tag, a forward toward its destination in
/// its one spelling, each recorded before it was sent. What the role is not
/// allowed, an exit that is no device of the organization, and a request
/// past its bounds are each refused in one word.
#[tokio::test]
async fn a_session_is_granted_the_egress_its_role_is_allowed() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultnet").await;
    let other = app.seed_tenant("vaultnet2").await;
    seed_net(&app, &t).await;
    let mut dev = device(&app, &t, "net-host", "linux", TAKES_LEASES, true).await;
    let (office, _) = enroll(&app, &t, "net-office", "linux").await;
    let (lab, _) = enroll(&app, &t, "net-lab", "windows").await;
    let (foreign, _) = enroll(&app, &other, "net-foreign", "linux").await;
    // The tag is the ROW's, in any case: a request names no tag at all.
    tag(&app, &office, &["Office"]).await;
    tag(&app, &foreign, &["office"]).await;
    let (sid, fence) = start(&app, &t, &mut dev, "/srv/n", Some("dev")).await;
    let base = |exit: &str, extra: Value| {
        let mut f = json!({ "session_id": sid, "fence": fence, "exit": exit });
        if let (Some(f), Some(e)) = (f.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                f.insert(k.clone(), v.clone());
            }
        }
        f
    };

    // SOCKS through the office: granted, naming the session and its places.
    let before = bson::DateTime::now().timestamp_millis() / 1000;
    let answer = ask_net(
        &mut dev,
        "s1",
        base(&office, json!({ "kind": "socks", "ttl_secs": 120 })),
    )
    .await;
    let g = granted(&app, &answer);
    assert_eq!((g.sub.as_str(), g.fence), (sid.as_str(), fence));
    assert_eq!(g.tenant_id, t.tenant_id);
    assert_eq!(g.owner_user_id, t.admin.id, "the session's owner");
    assert_eq!(g.origin_agent_id, dev.agent_id, "the device that asked");
    assert_eq!(g.exit_agent_id, office);
    assert_eq!(
        (g.net.as_str(), g.dst_host.as_str(), g.dst_port),
        ("socks", "", 0)
    );
    assert!(
        (before + 120..=before + 130).contains(&g.exp),
        "two minutes, as asked: {} from {before}",
        g.exp
    );
    assert!(
        answer.get("host").is_none() && answer.get("port").is_none(),
        "SOCKS names no destination: {answer}"
    );

    // Recorded before it was sent: the allow, naming the grant.
    let allows = rows(
        &app,
        "vault_audit",
        doc! { "action": "net:socks", "decision": "allow" },
    )
    .await;
    assert_eq!(allows.len(), 1);
    let allow = &allows[0];
    assert_eq!(allow.get_str("target").unwrap(), format!("grant:{}", g.jti));
    assert_eq!(allow.get_str("op").unwrap(), "grant");
    assert_eq!(allow.get_str("principal").unwrap(), "session");
    assert_eq!(allow.get_object_id("session_id").unwrap().to_hex(), sid);
    assert_eq!(
        allow.get_object_id("device_id").unwrap().to_hex(),
        dev.agent_id
    );
    let request = allow.get_document("request").unwrap();
    assert_eq!(request.get_str("action").unwrap(), "net:socks");
    assert_eq!(
        request
            .get_document("node")
            .unwrap()
            .get_object_id("id")
            .unwrap()
            .to_hex(),
        office,
        "the request names its exit"
    );
    assert_eq!(
        rows(&app, "vault_leases", doc! {}).await.len(),
        0,
        "a grant is no lease"
    );

    // Through an exit no policy names: denied, and recorded.
    let lab_answer = ask_net(&mut dev, "s2", base(&lab, json!({ "kind": "socks" }))).await;
    assert_eq!(refused(&lab_answer), "denied");
    let denies = rows(
        &app,
        "vault_audit",
        doc! { "action": "net:socks", "decision": "deny" },
    )
    .await;
    assert_eq!(denies.len(), 1);
    assert_eq!(denies[0].get_str("target").unwrap(), format!("asked:{lab}"));

    // A forward, in any spelling of its host: decided and granted as one.
    let fwd = ask_net(
        &mut dev,
        "f1",
        base(
            &lab,
            json!({ "kind": "forward", "host": "DB.Internal.", "port": 5432, "ttl_secs": 999_999 }),
        ),
    )
    .await;
    let g = granted(&app, &fwd);
    assert_eq!(
        (g.net.as_str(), g.dst_host.as_str(), g.dst_port),
        ("forward", "db.internal", 5432)
    );
    assert_eq!(
        (fwd["host"].as_str(), fwd["port"].as_u64()),
        (Some("db.internal"), Some(5432))
    );
    assert!(
        g.exp - g.iat <= 900,
        "clamped to the lease ceiling: {}",
        g.exp - g.iat
    );
    assert_eq!(
        refused(
            &ask_net(
                &mut dev,
                "f2",
                base(
                    &lab,
                    json!({ "kind": "forward", "host": "db.internal", "port": 22 })
                ),
            )
            .await
        ),
        "denied",
        "another port"
    );

    // `simulate` decides a forward's host as the vault decides a request's.
    let sim = |host: &str, port: u16| {
        post(
            &app,
            &t,
            "/vault/simulate",
            json!({
                "action": "net:forward",
                "principal": { "role": "dev", "owner_id": t.admin.id },
                "resource": { "node_id": lab },
                "device": { "os": "linux", "tags": [], "owner_id": t.admin.id },
                "host": host,
                "port": port,
            }),
        )
    };
    let (code, v) = sim("DB.Internal.", 5432).await;
    assert_eq!((code, v["decision"].as_str()), (200, Some("allow")), "{v}");
    for (host, port) in [
        ("010.0.0.5", 5432),
        ("db.internal:5432", 5432),
        ("db.internal", 0),
    ] {
        let (code, v) = sim(host, port).await;
        assert_eq!(code, 400, "{host}:{port} {v}");
    }

    // No exit: another organization's device, or no device at all.
    for (i, exit) in [foreign.clone(), ObjectId::new().to_hex()]
        .iter()
        .enumerate()
    {
        let a = ask_net(
            &mut dev,
            &format!("x{i}"),
            base(exit, json!({ "kind": "socks" })),
        )
        .await;
        assert_eq!(refused(&a), "no_exit", "{exit}");
    }

    // Past its bounds, before anything is read.
    for (i, extra) in [
        json!({ "kind": "udp" }),
        json!({ "kind": "socks", "host": "db.internal" }),
        json!({ "kind": "socks", "port": 5432 }),
        json!({ "kind": "forward", "host": "db.internal" }),
        json!({ "kind": "forward", "port": 5432 }),
        json!({ "kind": "forward", "host": "db.internal:5432", "port": 5432 }),
        json!({ "kind": "forward", "host": "010.0.0.5", "port": 5432 }),
    ]
    .into_iter()
    .enumerate()
    {
        let a = ask_net(&mut dev, &format!("b{i}"), base(&office, extra.clone())).await;
        assert_eq!(refused(&a), "bad_request", "{extra}");
    }
    assert_eq!(
        rows(&app, "vault_audit", doc! { "op": "grant" })
            .await
            .len(),
        6,
        "two allows, two denies, two exits that are none; nothing past a bound"
    );
}

/// FR-90 P3-7-1b — a grant is believed only from the device the session's
/// record places it on, at the record's fence, for a session holding a role
/// that is not over; and no other gate takes it as its credential.
#[tokio::test]
async fn a_grant_is_believed_only_from_the_device_that_runs_the_session() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultnetwho").await;
    seed_net(&app, &t).await;
    let mut a = device(&app, &t, "net-a", "linux", TAKES_LEASES, true).await;
    let mut b = device(&app, &t, "net-b", "linux", TAKES_LEASES, true).await;
    let (exit, _) = enroll(&app, &t, "net-exit", "linux").await;
    tag(&app, &exit, &["office"]).await;
    let (sid, fence) = start(&app, &t, &mut a, "/srv/a", Some("dev")).await;
    let frame = json!({ "session_id": sid, "fence": fence, "exit": exit, "kind": "socks" });

    // Another device of the organization, asking for a's session.
    assert_eq!(
        refused(&ask_net(&mut b, "b1", frame.clone()).await),
        "not_located"
    );
    // A fence the record does not hold.
    let mut stale = frame.clone();
    stale["fence"] = json!(fence + 1);
    assert_eq!(refused(&ask_net(&mut a, "a0", stale).await), "stale_fence");
    // A session that took no role.
    let (nsid, nfence) = start(&app, &t, &mut a, "/srv/n", None).await;
    let none = json!({ "session_id": nsid, "fence": nfence, "exit": exit, "kind": "socks" });
    assert_eq!(refused(&ask_net(&mut a, "n1", none).await), "no_role");

    // The role's session is granted, until it is over.
    let answer = ask_net(&mut a, "a1", frame.clone()).await;
    let g = granted(&app, &answer);
    assert_eq!(g.origin_agent_id, a.agent_id);
    let token = answer["grant"].as_str().unwrap();
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
    assert!(
        auth.verify_net_grant(&a.token).is_err(),
        "and an agent's token is no grant"
    );
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": oid(&sid) },
            doc! { "$set": { "status": "ended" } },
        )
        .await
        .unwrap();
    assert_eq!(refused(&ask_net(&mut a, "a2", frame).await), "ended");
}
