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
    assert_eq!(
        v["status"]["verified"],
        json!("unverified"),
        "no inventory since the ack yet"
    );

    // The node's next inventory (after the ack) shows the listener: verified.
    // One that lacks it would read `drift`.
    let inv = NetInventory {
        os: "linux".into(),
        namespaces: "host_only".into(),
        listeners: Section::capped(
            vec![Listener {
                proto: L4::Tcp,
                addr: "100.64.0.2".into(),
                port: 15432,
                process: Some("roomlerd".into()),
            }],
            10,
        ),
        ..Default::default()
    };
    let frame = json!({ "t": "rc:agent.net_inventory", "boot_id": "b1", "seq": 2, "page": 0, "pages": 1,
        "observed_at_ms": 2, "inventory": inv });
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
    let mut seen = Value::Null;
    for _ in 0..30 {
        let r = app
            .auth_get(&format!("/api/tenant/{tid}/managed-forward/{id}"), tok)
            .send()
            .await
            .unwrap();
        seen = r.json().await.unwrap();
        if seen["status"]["verified"] == json!("verified") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(seen["status"]["verified"], json!("verified"), "{seen}");
    let r = app
        .auth_get(&format!("/api/tenant/{tid}/managed-forward"), tok)
        .send()
        .await
        .unwrap();
    let l: Value = r.json().await.unwrap();
    assert_eq!(
        l["items"][0]["status"]["verified"],
        json!("verified"),
        "the list agrees"
    );

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

/// Once applied, the forward's own listener shows in the next inventory as
/// roomlerd's: an update on the same port is not a collision with itself.
#[tokio::test]
async fn an_applied_forwards_own_listener_is_not_a_collision() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("mf-own").await;
    let (a, a_tok) = enroll(&app, &seeded, "mf-own-a").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    report_listener(&app, &mut ws, tid, tok, &a, 22).await;
    let base = format!("/api/tenant/{tid}/managed-forward");
    let (s, body) = post(&app, &base, tok, &spec(&a, 15432)).await;
    assert_eq!(s, 201, "{body}");
    let id = body["forward"]["id"].as_str().unwrap().to_string();
    // The node now reports roomlerd on 15432 (seq 2 of the same boot).
    let inv = NetInventory {
        os: "linux".into(),
        namespaces: "host_only".into(),
        listeners: Section::capped(
            vec![
                Listener {
                    proto: L4::Tcp,
                    addr: "100.64.0.2".into(),
                    port: 15432,
                    process: Some("roomlerd".into()),
                },
                Listener {
                    proto: L4::Tcp,
                    addr: "0.0.0.0".into(),
                    port: 22,
                    process: Some("sshd".into()),
                },
            ],
            10,
        ),
        ..Default::default()
    };
    let frame = json!({ "t": "rc:agent.net_inventory", "boot_id": "b1", "seq": 2, "page": 0, "pages": 1,
        "observed_at_ms": 2, "inventory": inv });
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut upd = spec(&a, 15432);
    upd["name"] = json!("db renamed");
    let r = app
        .client
        .put(app.url(&format!("{base}/{id}")))
        .bearer_auth(tok)
        .json(&json!({ "expected_revision": 1, "spec": upd }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{}", r.text().await.unwrap());
    // A different, unmanaged process on another port still collides.
    let (s, body) = post(&app, &format!("{base}/plan"), tok, &spec(&a, 22)).await;
    assert_eq!((s, body["ok"].clone()), (200, json!(false)), "{body}");
}

/// Slice 4b: an nft forward. The ingress must advertise the backend, its
/// fresh inventory must show forwarding on and no foreign forward chain that
/// drops by default (reported, never changed), preserve-source needs an
/// on-link destination, the push carries the backend, and a status with
/// `confirm` is answered with `rc:forward.confirm` on the same connection.
#[tokio::test]
async fn the_nft_backend_is_gated_on_the_ingress_and_its_changes_are_confirmed() {
    use roomler_ai_remote_control::net_inventory::{
        FirewallChain, FirewallOwner, Forwarding, Interface,
    };
    let inv = |fwd: Option<bool>, drop_chain: bool| NetInventory {
        os: "linux".into(),
        namespaces: "host_only".into(),
        forwarding: Forwarding {
            ipv4: fwd,
            ipv6: None,
        },
        interfaces: Section::capped(
            vec![Interface {
                name: "eth1".into(),
                index: 2,
                kind: None,
                up: true,
                mtu: Some(1500),
                addrs: vec!["10.0.0.1/24".into()],
            }],
            10,
        ),
        listeners: Section::capped(vec![], 10),
        firewall_chains: Section::capped(
            if drop_chain {
                vec![FirewallChain {
                    backend: "nftables".into(),
                    family: "ip".into(),
                    table: "filter".into(),
                    name: "FORWARD".into(),
                    hook: Some("forward".into()),
                    chain_type: Some("filter".into()),
                    priority: Some(0),
                    policy: Some("drop".into()),
                    owner: FirewallOwner::Docker,
                }]
            } else {
                vec![]
            },
            10,
        ),
        ..Default::default()
    };
    let send_inv = |seq: u64, inv: NetInventory| {
        json!({ "t": "rc:agent.net_inventory", "boot_id": "b1", "seq": seq, "page": 0, "pages": 1,
            "observed_at_ms": seq, "inventory": inv })
        .to_string()
    };
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("mf-nft").await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    let plan_path = format!("/api/tenant/{tid}/managed-forward/plan");
    let nft_spec = |ingress: &str, nat: &str, dest: &str| {
        let mut s = spec(ingress, 15432);
        s["backend"] = json!("nft");
        s["nat"] = json!(nat);
        s["dest_addr"] = json!(dest);
        s
    };
    // Poll the plan until `name` reads `want` (an inventory lands async).
    let until = |body: Value, name: &'static str, want: &'static str| {
        let (app, plan_path, tok) = (&app, plan_path.clone(), tok.clone());
        async move {
            let mut last = Value::Null;
            for _ in 0..30 {
                let (_, plan) = post(app, &plan_path, &tok, &body).await;
                if plan["checks"]
                    .as_array()
                    .is_some_and(|c| c.iter().any(|c| c["name"] == name && c["verdict"] == want))
                {
                    return plan;
                }
                last = plan;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!("{name} never read {want}: {last}");
        }
    };

    // A device without the capability: refused, not run in userspace.
    let (a, a_tok) = enroll(&app, &seeded, "mf-nft-a").await;
    let mut wa = connect_from(&app, &a_tok, &["managed-forward"], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    wa.send(Message::Text(send_inv(1, inv(Some(true), false)).into()))
        .await
        .unwrap();
    let plan = until(
        nft_spec(&a, "masquerade", "10.0.0.5"),
        "native backend",
        "fail",
    )
    .await;
    assert_eq!(plan["ok"], json!(false));
    assert_eq!(plan["backend"], json!("nft"));

    // A capable device: forwarding off, then a foreign forward chain that
    // drops, then a clean host.
    let (b, b_tok) = enroll(&app, &seeded, "mf-nft-b").await;
    let mut wb = connect_from(
        &app,
        &b_tok,
        &["managed-forward", "managed-forward-nft"],
        None,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    wb.send(Message::Text(send_inv(1, inv(Some(false), false)).into()))
        .await
        .unwrap();
    let plan = until(
        nft_spec(&b, "masquerade", "10.0.0.5"),
        "ip forwarding",
        "fail",
    )
    .await;
    assert_eq!(verdict(&plan, "native backend"), "pass");
    assert!(plan.to_string().contains("does not change it"), "{plan}");
    wb.send(Message::Text(send_inv(2, inv(Some(true), true)).into()))
        .await
        .unwrap();
    let plan = until(
        nft_spec(&b, "masquerade", "10.0.0.5"),
        "foreign forward policy",
        "fail",
    )
    .await;
    assert!(
        plan.to_string().contains("filter/FORWARD"),
        "names the chain: {plan}"
    );
    wb.send(Message::Text(send_inv(3, inv(Some(true), false)).into()))
        .await
        .unwrap();
    until(
        nft_spec(&b, "masquerade", "10.0.0.5"),
        "foreign forward policy",
        "pass",
    )
    .await;

    // Preserve-source: on-link passes, off-link fails.
    let plan = until(
        nft_spec(&b, "preserve_source", "10.0.0.5"),
        "return path",
        "pass",
    )
    .await;
    assert_eq!(plan["ok"], json!(true), "{plan}");
    until(
        nft_spec(&b, "preserve_source", "10.9.9.9"),
        "return path",
        "fail",
    )
    .await;

    // Created, pushed with its backend.
    let _ = recv_t(&mut wb, "rc:forward.set", Duration::from_millis(1500)).await;
    let (s, body) = post(
        &app,
        &format!("/api/tenant/{tid}/managed-forward"),
        tok,
        &nft_spec(&b, "preserve_source", "10.0.0.5"),
    )
    .await;
    assert_eq!(s, 201, "{body}");
    let set = recv_t(&mut wb, "rc:forward.set", Duration::from_secs(3))
        .await
        .expect("pushed");
    let f = &set["forwards"][0];
    assert_eq!(f["backend"], json!("nft"), "{set}");
    assert_eq!(f["preserve_source"], json!(true), "{set}");

    // The agent's status carries the change's generation: confirmed.
    let id = f["id"].as_str().unwrap();
    let m = json!({ "t": "rc:forward.status", "confirm": 7,
        "statuses": [{ "id": id, "revision": 1, "listening": true }] });
    wb.send(Message::Text(m.to_string().into())).await.unwrap();
    let c = recv_t(&mut wb, "rc:forward.confirm", Duration::from_secs(3))
        .await
        .expect("confirmed");
    assert_eq!(c["generation"], json!(7));
    // A status without one asks for nothing.
    let m = json!({ "t": "rc:forward.status",
        "statuses": [{ "id": id, "revision": 1, "listening": true }] });
    wb.send(Message::Text(m.to_string().into())).await.unwrap();
    assert!(
        recv_t(&mut wb, "rc:forward.confirm", Duration::from_millis(800))
            .await
            .is_none()
    );
    drop(wa);
}
