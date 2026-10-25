// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor #20 slice 1 (v039 FWD-03, AUTH-01): the managed forward intent
//! and its dry-run plan. Refusals happen before any effect: no fresh
//! inventory fails closed, a reported listener or another managed forward on
//! the port is a collision, a stale revision is 409, a member may not see or
//! change forwards, and the hard regional gate fails an unknown zone under
//! `enforce` (and only warns under `warn`).

use crate::agent_presence_tests::enroll;
use crate::fixtures::test_app::TestApp;
use crate::peer_relay_mint_tests::{Ws, connect_from, recv_t};
use futures::SinkExt;
use roomler_ai_remote_control::net_inventory::{L4, Listener, NetInventory, Section};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

async fn report_listener(app: &TestApp, ws: &mut Ws, tid: &str, tok: &str, agent: &str, port: u16) {
    let inv = NetInventory {
        os: "linux".into(),
        namespaces: "host_only".into(),
        listeners: Section::capped(
            vec![Listener {
                proto: L4::Tcp,
                addr: "0.0.0.0".into(),
                port,
                process: Some("sshd".into()),
            }],
            10,
        ),
        ..Default::default()
    };
    let frame = json!({ "t": "rc:agent.net_inventory", "boot_id": "b1", "seq": 1, "page": 0, "pages": 1,
        "observed_at_ms": 1, "inventory": inv });
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
    for _ in 0..30 {
        let r = app
            .auth_get(&format!("/api/tenant/{tid}/net-inventory/{agent}"), tok)
            .send()
            .await
            .unwrap();
        if r.status() == 200 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("inventory never landed");
}

fn spec(ingress: &str, port: u16) -> Value {
    json!({
        "name": "db", "ingress_agent_id": ingress, "bind_addr": "100.64.0.2", "port": port,
        "proto": "tcp", "sources": ["100.64.0.0/10"], "dest_addr": "10.0.0.5", "dest_port": 5432,
        "nat": "masquerade", "desired": "enabled"
    })
}

async fn post(app: &TestApp, path: &str, tok: &str, body: &Value) -> (u16, Value) {
    let r = app.auth_post(path, tok).json(body).send().await.unwrap();
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
}

fn verdict(plan: &Value, name: &str) -> String {
    plan["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .map(|c| c["verdict"].as_str().unwrap().to_string())
        .unwrap_or_else(|| panic!("no {name} check: {plan}"))
}

#[tokio::test]
async fn a_plan_fails_closed_without_a_fresh_inventory() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("mf-noinv").await;
    let (a, _) = enroll(&app, &seeded, "mf-noinv-a").await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    let (s, plan) = post(
        &app,
        &format!("/api/tenant/{tid}/managed-forward/plan"),
        tok,
        &spec(&a, 15432),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(plan["ok"], json!(false), "{plan}");
    assert_eq!(verdict(&plan, "port collision"), "unknown");
    let (s, body) = post(
        &app,
        &format!("/api/tenant/{tid}/managed-forward"),
        tok,
        &spec(&a, 15432),
    )
    .await;
    assert_eq!(s, 422, "nothing is stored on a failed plan: {body}");
    let r = app
        .auth_get(&format!("/api/tenant/{tid}/managed-forward"), tok)
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn collisions_revisions_and_permissions() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("mf-flow").await;
    let (a, a_tok) = enroll(&app, &seeded, "mf-flow-a").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    report_listener(&app, &mut ws, tid, tok, &a, 22).await;
    let base = format!("/api/tenant/{tid}/managed-forward");

    // A reported listener holds 22.
    let (s, body) = post(&app, &base, tok, &spec(&a, 22)).await;
    assert_eq!(s, 422);
    assert_eq!(verdict(&body["plan"], "port collision"), "fail");
    assert!(
        body["plan"]["checks"].to_string().contains("sshd"),
        "names who holds it: {body}"
    );

    // A free port is accepted; it is desired, not applied.
    let (s, body) = post(&app, &base, tok, &spec(&a, 15432)).await;
    assert_eq!(s, 201, "{body}");
    let f = &body["forward"];
    assert_eq!(f["revision"], json!(1));
    assert_eq!(
        f["status"],
        json!({ "desired": "enabled", "applied": "pending", "verified": "unverified" })
    );
    assert_eq!(
        verdict(&body["plan"], "region"),
        "warn",
        "the default isolation only warns"
    );
    let id = f["id"].as_str().unwrap().to_string();

    // The same node, port and protocol again overlaps the managed one.
    let (s, body) = post(&app, &base, tok, &spec(&a, 15432)).await;
    assert_eq!(s, 422);
    assert_eq!(verdict(&body["plan"], "managed overlap"), "fail");

    // Revisions: a stale update and delete are refused.
    let put = |rev: u64, port: u16| json!({ "expected_revision": rev, "spec": spec(&a, port) });
    let r = app
        .client
        .put(app.url(&format!("{base}/{id}")))
        .bearer_auth(tok)
        .json(&put(0, 15433))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    let r = app
        .client
        .put(app.url(&format!("{base}/{id}")))
        .bearer_auth(tok)
        .json(&put(1, 15433))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "its own port is not a collision with itself"
    );
    let v: Value = r.json().await.unwrap();
    assert_eq!(
        (
            v["forward"]["revision"].clone(),
            v["forward"]["spec"]["port"].clone()
        ),
        (json!(2), json!(15433))
    );
    let r = app
        .client
        .delete(app.url(&format!("{base}/{id}?expected_revision=1")))
        .bearer_auth(tok)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);

    // A member may neither see nor change forwards.
    let mtok = &seeded.member.access_token;
    let r = app.auth_get(&base, mtok).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 403);
    let (s, _) = post(&app, &format!("{base}/plan"), mtok, &spec(&a, 15000)).await;
    assert_eq!(s, 403);

    let r = app
        .client
        .delete(app.url(&format!("{base}/{id}?expected_revision=2")))
        .bearer_auth(tok)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    let r = app.auth_get(&base, tok).send().await.unwrap();
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["items"].as_array().unwrap().len(), 0);
    let audit = app
        .db
        .collection::<bson::Document>("managed_forward_audit")
        .count_documents(bson::doc! {})
        .await
        .unwrap();
    assert_eq!(audit, 3, "create, update, delete");
}

#[tokio::test]
async fn enforce_fails_a_forward_whose_zones_are_unknown() {
    let app = TestApp::spawn_with_settings(|s| s.app.business_isolation = "enforce".into()).await;
    let seeded = app.seed_tenant("mf-geo").await;
    let (a, a_tok) = enroll(&app, &seeded, "mf-geo-a").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    report_listener(&app, &mut ws, tid, tok, &a, 22).await;
    let (s, body) = post(
        &app,
        &format!("/api/tenant/{tid}/managed-forward"),
        tok,
        &spec(&a, 15432),
    )
    .await;
    assert_eq!(s, 422, "{body}");
    assert_eq!(verdict(&body["plan"], "region"), "fail");
    assert_eq!(
        verdict(&body["plan"], "port collision"),
        "pass",
        "only the region fails"
    );
}

async fn status(ws: &mut Ws, id: &str, revision: u64, listening: bool) {
    let m = json!({ "t": "rc:forward.status", "statuses": [{ "id": id, "revision": revision, "listening": listening }] });
    ws.send(Message::Text(m.to_string().into())).await.unwrap();
}

async fn applied(app: &TestApp, tid: &str, tok: &str, id: &str, want: &str) -> Value {
    let mut last = Value::Null;
    for _ in 0..30 {
        let r = app
            .auth_get(&format!("/api/tenant/{tid}/managed-forward/{id}"), tok)
            .send()
            .await
            .unwrap();
        last = r.json().await.unwrap();
        if last["status"]["applied"] == json!(want) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    last
}

#[tokio::test]
async fn a_capable_agent_gets_its_set_and_only_its_own_ack_counts() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("mf-push").await;
    let (a, a_tok) = enroll(&app, &seeded, "mf-push-a").await;
    let (_b, b_tok) = enroll(&app, &seeded, "mf-push-b").await;
    let mut ws = connect_from(&app, &a_tok, &["managed-forward"], None).await;
    let mut other = connect_from(&app, &b_tok, &["managed-forward"], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    report_listener(&app, &mut ws, tid, tok, &a, 22).await;
    // The hello push (an empty set) may still be on its way: drain it.
    let _ = recv_t(&mut ws, "rc:forward.set", Duration::from_millis(1500)).await;

    let (s, body) = post(
        &app,
        &format!("/api/tenant/{tid}/managed-forward"),
        tok,
        &spec(&a, 15432),
    )
    .await;
    assert_eq!(s, 201, "{body}");
    let id = body["forward"]["id"].as_str().unwrap().to_string();
    assert_eq!(body["forward"]["status"]["applied"], json!("pending"));

    let set = recv_t(&mut ws, "rc:forward.set", Duration::from_secs(3))
        .await
        .expect("the ingress agent gets its set");
    let f = &set["forwards"][0];
    assert_eq!(
        (f["id"].as_str(), f["revision"].as_u64(), f["port"].as_u64()),
        (Some(id.as_str()), Some(1), Some(15432))
    );
    assert_eq!(f["sources"], json!(["100.64.0.0/10"]));

    // Another agent's ack, and an ack of a revision that does not exist, count for nothing.
    status(&mut other, &id, 1, true).await;
    status(&mut ws, &id, 7, true).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let v = applied(&app, tid, tok, &id, "pending").await;
    assert_eq!(v["status"]["applied"], json!("pending"), "{v}");

    // The ingress agent's own ack of revision 1.
    status(&mut ws, &id, 1, true).await;
    let v = applied(&app, tid, tok, &id, "applied").await;
    assert_eq!(v["status"]["applied"], json!("applied"), "{v}");
    assert_eq!(v["status"]["verified"], json!("unverified"));

    // A bind failure reads as failed, with the agent's reason.
    let m = json!({ "t": "rc:forward.status", "statuses": [{ "id": id, "revision": 1, "listening": false, "error": "Address in use" }] });
    ws.send(Message::Text(m.to_string().into())).await.unwrap();
    let v = applied(&app, tid, tok, &id, "failed").await;
    assert_eq!(
        (v["status"]["applied"].clone(), v["status"]["error"].clone()),
        (json!("failed"), json!("Address in use"))
    );
}

#[tokio::test]
async fn an_agent_without_the_capability_is_never_pushed() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("mf-nocap").await;
    let (a, a_tok) = enroll(&app, &seeded, "mf-nocap-a").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    report_listener(&app, &mut ws, tid, tok, &a, 22).await;
    let (s, _) = post(
        &app,
        &format!("/api/tenant/{tid}/managed-forward"),
        tok,
        &spec(&a, 15432),
    )
    .await;
    assert_eq!(s, 201);
    assert!(
        recv_t(&mut ws, "rc:forward.set", Duration::from_secs(2))
            .await
            .is_none()
    );
}
