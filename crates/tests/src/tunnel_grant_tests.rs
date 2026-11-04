// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-7-2a — an agent session's own egress, the network module's half.
//! A grant the vault signed (P3-7-1b) rides `rc:tunnel.open` from the
//! session's device, is bound to that tunnel, and its flows are decided for
//! the SESSION, never for the device that carries them.
//!
//! What these lock:
//! - a grant is bound only where it holds: from the device it names, toward
//!   the exit it names, in its organization, before its end, and only on an
//!   agent's own connection. `rc:tunnel.opened` echoes its id. An open whose
//!   grant does not hold is refused, never opened as the device's;
//! - a session matches no tunnel-policy subject before decision 20: the
//!   `all_users` policy that admits its device's own flow refuses the
//!   session's;
//! - a flow is held to its grant before any policy: TCP only, before its
//!   end, a forward toward its one destination;
//! - the audit rows name the session, its grant, and the session's owner.

use std::time::Duration;

use bson::{Document, doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::vault::NetKind;
use meshharbor_services::auth::NetGrant;
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::tunnel_tests::{connect_agent_ws, enroll_agent, read_until, wait_agent_online};
use crate::vault_lease_tests::AgentWs;

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

fn now_s() -> i64 {
    bson::DateTime::now().timestamp_millis() / 1000
}

/// A grant as the vault signs one (P3-7-1b), made here with the server's
/// own auth service: the session `session` on `origin`, through `exit`.
/// Its token and its id.
#[allow(clippy::too_many_arguments)]
fn mint(
    app: &TestApp,
    tenant: &str,
    owner: &str,
    session: ObjectId,
    origin: &str,
    exit: &str,
    dst: Option<(&str, u16)>,
    life_s: i64,
) -> (String, String) {
    let grant_id = ObjectId::new();
    let token = app
        .state
        .auth
        .issue_net_grant(&NetGrant {
            session_id: session,
            tenant_id: oid(tenant),
            fence: 1,
            owner_user_id: oid(owner),
            origin_agent_id: oid(origin),
            exit_agent_id: oid(exit),
            net: if dst.is_some() {
                NetKind::Forward
            } else {
                NetKind::Socks
            },
            dst,
            grant_id,
            exp: now_s() + life_s,
        })
        .expect("the server signs the grant");
    (token, grant_id.to_hex())
}

/// Any principal a policy names may reach 127.0.0.1:9000-9999 on any agent:
/// what admits a device's own flow.
async fn allow_loopback(app: &TestApp, t: &SeededTenant) {
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/tunnel-policy", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({
            "name": "allow-loopback",
            "subjects": [{ "kind": "all_users" }],
            "targets": [{ "kind": "all_agents" }],
            "allowlist": [{
                "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
                "port_range": { "low": 9000, "high": 9999 }
            }],
            "max_concurrent_flows": 32,
            "max_bytes_per_session": 1048576
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
}

async fn send(ws: &mut AgentWs, frame: Value) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

async fn hello(ws: &mut AgentWs) {
    send(
        ws,
        json!({
            "t": "rc:tunnel.hello", "role": "client", "version": "0.3.0",
            "supported_transports": ["webrtc-dc-v1"],
        }),
    )
    .await;
}

/// Open a tunnel to `exit`, under `grant` when given; the answer to THIS
/// open, `rc:tunnel.opened` or `rc:error`, matched by its nonce.
async fn open(ws: &mut AgentWs, exit: &str, grant: Option<&str>, nonce: &str) -> Value {
    let mut frame = json!({
        "t": "rc:tunnel.open", "agent_id": exit, "transport": "webrtc-dc-v1",
        "open_nonce": nonce,
    });
    if let Some(g) = grant {
        frame["net_grant"] = json!(g);
    }
    send(ws, frame).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = tokio::time::timeout(left, ws.next())
            .await
            .expect("no answer to the open within 10 s")
            .expect("socket closed")
            .expect("socket error");
        if let Message::Text(text) = next {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let t = v["t"].as_str().unwrap_or_default();
            if (t == "rc:tunnel.opened" || t == "rc:error") && v["open_nonce"] == nonce {
                return v;
            }
        }
    }
}

async fn request(
    ws: &mut AgentWs,
    kind: &str,
    session_id: &str,
    flow_id: u32,
    host: &str,
    port: u16,
) {
    send(
        ws,
        json!({
            "t": format!("rc:tunnel.{kind}.request"), "session_id": session_id,
            "flow_id": flow_id, "dst_host": host, "dst_port": port,
        }),
    )
    .await;
}

/// The reject for `flow_id`, as `rc:tunnel.{kind}.reject` carries it.
async fn rejected(ws: &mut AgentWs, kind: &str, flow_id: u32) -> Value {
    let want = format!("rc:tunnel.{kind}.reject");
    loop {
        let v = read_until(ws, &want)
            .await
            .unwrap_or_else(|| panic!("no {want} for flow {flow_id}"));
        if v["flow_id"] == flow_id {
            return v;
        }
    }
}

async fn audit(app: &TestApp, filter: Document) -> Vec<Document> {
    use futures::TryStreamExt;
    app.db
        .collection::<Document>("tunnel_audit")
        .find(filter)
        .sort(doc! { "_id": 1 })
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap()
}

/// FR-90 P3-7-2a — a grant binds its tunnel, `rc:tunnel.opened` echoes it, and
/// the tunnel's flows are the SESSION's: the `all_users` policy that admits
/// the device's own flow to the same exit refuses the session's, because a
/// session matches no subject before decision 20. The audit names the
/// session, its grant, and its owner.
#[tokio::test]
async fn a_grant_binds_its_tunnel_and_its_flows_are_the_sessions() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("p372a-bind").await;
    allow_loopback(&app, &t).await;
    let (a_id, a_tok) = enroll_agent(&app, &t, "mach-p372a-A", "origin-A").await;
    let (b_id, b_tok) = enroll_agent(&app, &t, "mach-p372a-B", "exit-B").await;
    let mut a = connect_agent_ws(&app, &a_tok, "origin-A").await;
    let mut b = connect_agent_ws(&app, &b_tok, "exit-B").await;
    wait_agent_online(&app, &t, &a_id).await;
    wait_agent_online(&app, &t, &b_id).await;
    hello(&mut a).await;

    // The device's own tunnel: the policy admits its flow, as before.
    let own = open(&mut a, &b_id, None, "own").await;
    assert_eq!(own["t"], "rc:tunnel.opened", "{own}");
    assert!(own.get("net_grant_id").is_none(), "{own}");
    let own_sid = own["session_id"].as_str().unwrap().to_string();
    request(&mut a, "tcp", &own_sid, 1, "127.0.0.1", 9000).await;
    let fwd = read_until(&mut b, "rc:tunnel.tcp.forward")
        .await
        .expect("the device's own flow reaches the exit");
    assert_eq!(fwd["session_id"].as_str(), Some(own_sid.as_str()));

    // A session's tunnel, under its grant: bound, and echoed. The session acts
    // for the member, while the admin enrolled (and owns) the device.
    let session = ObjectId::new();
    let (token, grant_id) = mint(
        &app,
        &t.tenant_id,
        &t.member.id,
        session,
        &a_id,
        &b_id,
        None,
        120,
    );
    let opened = open(&mut a, &b_id, Some(&token), "sess").await;
    assert_eq!(opened["t"], "rc:tunnel.opened", "{opened}");
    assert_eq!(opened["net_grant_id"], grant_id.as_str(), "{opened}");
    let sid = opened["session_id"].as_str().unwrap().to_string();

    // Its flow is the session's: the same policy refuses it.
    request(&mut a, "tcp", &sid, 2, "127.0.0.1", 9000).await;
    let rej = rejected(&mut a, "tcp", 2).await;
    assert_eq!(rej["kind"], "acl_denied", "{rej}");

    // The audit names the session, its grant and its owner; the device's
    // own tunnel names none of them.
    let tsid = oid(&sid);
    let rows = audit(&app, doc! { "tunnel_session_id": tsid }).await;
    assert!(rows.len() >= 2, "{rows:?}");
    for r in &rows {
        assert_eq!(r.get_object_id("session_id").unwrap(), session, "{r:?}");
        assert_eq!(r.get_str("grant_id").unwrap(), grant_id, "{r:?}");
        assert_eq!(
            r.get_object_id("user_id").unwrap().to_hex(),
            t.member.id,
            "the session's owner, not the device's: {r:?}"
        );
        assert_eq!(
            r.get_object_id("origin_agent_id").unwrap().to_hex(),
            a_id,
            "{r:?}"
        );
    }
    assert!(
        rows.iter()
            .any(|r| r.get_str("kind").ok() == Some("tcp_reject")),
        "{rows:?}"
    );
    for r in audit(&app, doc! { "tunnel_session_id": oid(&own_sid) }).await {
        assert!(
            r.get("session_id").is_none() && r.get("grant_id").is_none(),
            "{r:?}"
        );
    }
}

/// FR-90 P3-7-2a — a grant holds only from the device it names, toward the
/// exit it names, in its organization, and only on an agent's own
/// connection. Any other open that carries it is refused, never opened as
/// the device's or the person's.
#[tokio::test]
async fn a_grant_holds_only_from_its_device_toward_its_exit() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("p372a-holds").await;
    let other = app.seed_tenant("p372a-other").await;
    allow_loopback(&app, &t).await;
    let (a_id, a_tok) = enroll_agent(&app, &t, "mach-p372a-hA", "origin-A").await;
    let (b_id, b_tok) = enroll_agent(&app, &t, "mach-p372a-hB", "exit-B").await;
    let (c_id, _) = enroll_agent(&app, &t, "mach-p372a-hC", "exit-C").await;
    let (x_id, _) = enroll_agent(&app, &t, "mach-p372a-hX", "device-X").await;
    let mut a = connect_agent_ws(&app, &a_tok, "origin-A").await;
    let _b = connect_agent_ws(&app, &b_tok, "exit-B").await;
    wait_agent_online(&app, &t, &a_id).await;
    wait_agent_online(&app, &t, &b_id).await;
    hello(&mut a).await;

    let s = ObjectId::new();
    let refused = |v: &Value| v["t"] == "rc:error" && v["code"] == "net_grant_refused";
    for (nonce, token, why) in [
        (
            "exit",
            mint(&app, &t.tenant_id, &t.admin.id, s, &a_id, &c_id, None, 120).0,
            "a grant for another exit",
        ),
        (
            "device",
            mint(&app, &t.tenant_id, &t.admin.id, s, &x_id, &b_id, None, 120).0,
            "a grant for another device",
        ),
        (
            "org",
            mint(
                &app,
                &other.tenant_id,
                &other.admin.id,
                s,
                &a_id,
                &b_id,
                None,
                120,
            )
            .0,
            "a grant for another organization",
        ),
        (
            "forged",
            "a.b.c".to_string(),
            "not a grant this server signed, or it has ended",
        ),
    ] {
        let v = open(&mut a, &b_id, Some(&token), nonce).await;
        assert!(refused(&v), "{nonce}: {v}");
        assert_eq!(v["message"], why, "{nonce}: {v}");
    }

    // A person's tunnel client cannot carry a session's grant.
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{}/tunnel-client/enroll-token", t.tenant_id),
            &t.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: Value = app
        .client
        .post(format!("{}/api/tunnel-client/enroll", app.base_url))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": "mach-p372a-cli", "machine_name": "cli",
            "os": "linux", "client_version": "0.3.0-test",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cli_token = enrolled["tunnel_client_token"].as_str().unwrap();
    let url = format!(
        "ws://{}/ws?token={}&role=tunnel-client",
        app.addr,
        cli_token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut cli, _) = connect_async(&url).await.expect("tunnel-client ws");
    hello(&mut cli).await;
    let (token, _) = mint(&app, &t.tenant_id, &t.admin.id, s, &a_id, &b_id, None, 120);
    let v = open(&mut cli, &b_id, Some(&token), "cli").await;
    assert!(refused(&v), "{v}");
    assert_eq!(
        v["message"], "a session's grant rides only its own device's connection",
        "{v}"
    );

    // Nothing was opened under any of them.
    assert_eq!(
        audit(&app, doc! { "session_id": s }).await.len(),
        0,
        "no tunnel under a grant that does not hold"
    );
}

/// FR-90 P3-7-2a — a flow is held to its grant before any policy is read: a
/// forward toward its one destination only, TCP only, and nothing after the
/// grant's end.
#[tokio::test]
async fn a_flow_is_held_to_its_grant() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("p372a-flow").await;
    allow_loopback(&app, &t).await;
    let (a_id, a_tok) = enroll_agent(&app, &t, "mach-p372a-fA", "origin-A").await;
    let (b_id, b_tok) = enroll_agent(&app, &t, "mach-p372a-fB", "exit-B").await;
    let mut a = connect_agent_ws(&app, &a_tok, "origin-A").await;
    let _b = connect_agent_ws(&app, &b_tok, "exit-B").await;
    wait_agent_online(&app, &t, &a_id).await;
    wait_agent_online(&app, &t, &b_id).await;
    hello(&mut a).await;

    // A forward to 127.0.0.1:9001 only.
    let (token, _) = mint(
        &app,
        &t.tenant_id,
        &t.admin.id,
        ObjectId::new(),
        &a_id,
        &b_id,
        Some(("127.0.0.1", 9001)),
        120,
    );
    let opened = open(&mut a, &b_id, Some(&token), "fwd").await;
    assert_eq!(opened["t"], "rc:tunnel.opened", "{opened}");
    let sid = opened["session_id"].as_str().unwrap().to_string();
    request(&mut a, "tcp", &sid, 1, "127.0.0.1", 9002).await;
    let rej = rejected(&mut a, "tcp", 1).await;
    assert_eq!(rej["reason"], "outside the session's grant", "{rej}");
    request(&mut a, "udp", &sid, 2, "127.0.0.1", 9001).await;
    let rej = rejected(&mut a, "udp", 2).await;
    assert_eq!(rej["reason"], "a session's grant carries TCP only", "{rej}");
    // Its own destination passes the grant, and is then the policies' to
    // decide: none names a session yet.
    request(&mut a, "tcp", &sid, 3, "127.0.0.1", 9001).await;
    let rej = rejected(&mut a, "tcp", 3).await;
    assert_ne!(rej["reason"], "outside the session's grant", "{rej}");
    assert_eq!(rej["kind"], "acl_denied", "{rej}");

    // A grant three seconds long: nothing after its end. Its end is a whole
    // second, so the open has at least two to land in.
    let (short, _) = mint(
        &app,
        &t.tenant_id,
        &t.admin.id,
        ObjectId::new(),
        &a_id,
        &b_id,
        None,
        3,
    );
    let opened = open(&mut a, &b_id, Some(&short), "short").await;
    assert_eq!(opened["t"], "rc:tunnel.opened", "{opened}");
    let short_sid = opened["session_id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(4_200)).await;
    request(&mut a, "tcp", &short_sid, 4, "127.0.0.1", 9000).await;
    let rej = rejected(&mut a, "tcp", 4).await;
    assert_eq!(rej["reason"], "the session's grant has ended", "{rej}");
}
