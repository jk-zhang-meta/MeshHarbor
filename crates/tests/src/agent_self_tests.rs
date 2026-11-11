// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D5a — `GET /api/agent/self/{devices,mesh}`: what ONE device may see
//! of its org, driven over real agent WebSockets against a live `TestApp`.
//!
//! The load-bearing test is the negative control
//! (`enforce_lists_exactly_the_netmap_and_never_a_withheld_peer`): under
//! `enforce` the listed set must EQUAL the netmap the device just received
//! (∪ itself) — asserted as SET EQUALITY against the captured
//! `rc:overlay.netmap`, not as "C is absent" — and it is shown to go red with
//! the visibility filter removed (the PR body carries that run). A listing
//! that drifted from the netmap would drift in exactly one direction: towards
//! showing a peer the mesh withholds.
//!
//! The other rule these lock: a GET never allocates. A node-less device on a
//! fresh tenant lists itself and leaves `overlay_networks` untouched.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::{doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::fixtures::{seed::SeededTenant, test_app::TestApp};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

fn tenant_url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

/// Enroll a device under its own machine name; `(agent_id, agent_token)`.
async fn enroll(
    app: &TestApp,
    seeded: &SeededTenant,
    machine_id: &str,
    machine_name: &str,
) -> (String, String) {
    let et: Value = app
        .auth_post(
            &tenant_url(seeded, "/agent/enroll-token"),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ej: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": machine_name,
            "os": "linux",
            "agent_version": "0.4.103",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        ej["agent_id"].as_str().expect("agent_id").to_string(),
        ej["agent_token"].as_str().expect("agent_token").to_string(),
    )
}

/// Connect an agent WS and complete the hello.
async fn connect(app: &TestApp, token: &str, machine_name: &str) -> Ws {
    let ws_url = format!("ws://{}/ws?token={}&role=agent", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connect");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": machine_name,
        "os": "linux",
        "agent_version": "0.4.103",
        "displays": [],
        "caps": {
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
            "rpc": [],
        }
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

/// The next text frame within `wait`, or `None` on silence / close.
async fn recv_any(ws: &mut Ws, wait: Duration) -> Option<Value> {
    match tokio::time::timeout(wait, ws.next()).await {
        Ok(Some(Ok(Message::Text(txt)))) => serde_json::from_str::<Value>(&txt).ok(),
        Ok(Some(Ok(_))) => Some(Value::Null),
        _ => None,
    }
}

/// Read frames until one with `t == want` arrives, or give up.
async fn recv_t(ws: &mut Ws, want: &str, wait: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        match recv_any(ws, left).await {
            Some(v) if v["t"] == want => return Some(v),
            Some(_) => {}
            None => return None,
        }
    }
}

/// Discard everything queued until the socket is quiet. A policy or mode
/// edit re-fans every node's netmap; the frame answering a JOIN must not be
/// confused with one of those.
async fn settle(ws: &mut Ws) {
    while recv_any(ws, Duration::from_millis(500)).await.is_some() {}
}

/// Join (or re-join) the overlay and return the netmap that answers it.
/// `seed` makes the WG key distinct per node.
async fn join(ws: &mut Ws, seed: u8) -> Value {
    settle(ws).await;
    let msg = json!({
        "t": "rc:overlay.join",
        "wg_public_key": BASE64.encode([seed; 32]),
        "mtu": 1280,
        "endpoints": [format!("203.0.113.{seed}:41641")],
        "supports_server_relay_strategy": true,
        "org_primary": true,
    });
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .expect("send join");
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .expect("a netmap answers the join")
}

fn netmap_peer_node_ids(netmap: &Value) -> BTreeSet<String> {
    netmap["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["node_id"].as_str().unwrap().to_string())
        .collect()
}

async fn set_acl_mode(app: &TestApp, seeded: &SeededTenant, mode: &str) {
    let resp = app
        .auth_put(
            &tenant_url(seeded, "/overlay-acl/mode"),
            &seeded.admin.access_token,
        )
        .json(&json!({ "mode": mode }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "set acl mode {mode}");
}

/// One grant: `src_node` may reach `via_node` (and nothing else says anything
/// about `src_node`).
async fn allow(app: &TestApp, seeded: &SeededTenant, src_node: &str, via_node: &str) -> String {
    let resp = app
        .auth_post(
            &tenant_url(seeded, "/overlay-acl"),
            &seeded.admin.access_token,
        )
        .json(&json!({
            "name": format!("{src_node} sees {via_node}"),
            "sources": [{ "kind": "node_id", "id": src_node }],
            "via": [{ "kind": "node_id", "id": via_node }],
            "destinations": [{ "cidr": "100.64.0.0/10" }],
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "policy create: {}",
        resp.status()
    );
    let v: Value = resp.json().await.unwrap();
    v["id"].as_str().unwrap().to_string()
}

async fn rename(app: &TestApp, seeded: &SeededTenant, agent_id: &str, display_name: &str) {
    let resp = app
        .auth_put(
            &tenant_url(seeded, &format!("/agent/{agent_id}")),
            &seeded.admin.access_token,
        )
        .json(&json!({ "display_name": display_name }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "rename {agent_id}");
}

async fn node_id_of(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> String {
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    app.state
        .network()
        .overlay_nodes
        .find_live_by_tenant_and_machine(tid, machine_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no live node for {machine_id}"))
        .id
        .unwrap()
        .to_hex()
}

async fn get_devices(app: &TestApp, token: &str, query: &str) -> (u16, Value) {
    let resp = app
        .auth_get(&format!("/api/agent/self/devices{query}"), token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn get_mesh(app: &TestApp, token: &str) -> (u16, Value) {
    let resp = app
        .auth_get("/api/agent/self/mesh", token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn items(page: &Value) -> &Vec<Value> {
    page["items"].as_array().expect("items")
}

fn item_ids(page: &Value) -> BTreeSet<String> {
    items(page)
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect()
}

fn item_node_ids(page: &Value) -> BTreeSet<String> {
    items(page)
        .iter()
        .filter_map(|r| r["overlay_node_id"].as_str().map(str::to_string))
        .collect()
}

fn order(page: &Value) -> Vec<String> {
    items(page)
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect()
}

fn item<'a>(page: &'a Value, id: &str) -> &'a Value {
    items(page)
        .iter()
        .find(|r| r["id"] == json!(id))
        .unwrap_or_else(|| panic!("no row {id} in {page}"))
}

fn mesh_node_ids(mesh: &Value) -> BTreeSet<String> {
    mesh["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_str().unwrap().to_string())
        .collect()
}

fn mesh_edge_pairs(mesh: &Value) -> BTreeSet<(String, String)> {
    mesh["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["from"].as_str().unwrap().to_string(),
                e["to"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

/// Three devices on one tenant, every one joined to the overlay. Technical
/// names sort A < B < C; the display names below are chosen so the EFFECTIVE
/// order (display name over name) differs from the technical one:
/// A = "Mike", B = "Kilo", C has none ("charlie-box") ⇒ C, B, A.
struct Rig {
    app: TestApp,
    seeded: SeededTenant,
    a: Ws,
    b: Ws,
    c: Ws,
    a_id: String,
    b_id: String,
    c_id: String,
    a_tok: String,
    b_tok: String,
    c_tok: String,
    a_node: String,
    b_node: String,
    c_node: String,
}

impl Rig {
    async fn up(slug: &str) -> Self {
        let app = TestApp::spawn().await;
        let seeded = app.seed_tenant(slug).await;
        let (a_id, a_tok) = enroll(&app, &seeded, &format!("{slug}-a"), "alpha-box").await;
        let (b_id, b_tok) = enroll(&app, &seeded, &format!("{slug}-b"), "bravo-box").await;
        let (c_id, c_tok) = enroll(&app, &seeded, &format!("{slug}-c"), "charlie-box").await;
        rename(&app, &seeded, &a_id, "Mike").await;
        rename(&app, &seeded, &b_id, "Kilo").await;
        let mut a = connect(&app, &a_tok, "alpha-box").await;
        let mut b = connect(&app, &b_tok, "bravo-box").await;
        let mut c = connect(&app, &c_tok, "charlie-box").await;
        // Let the hellos land (the hub registers, the row stores caps).
        tokio::time::sleep(Duration::from_millis(300)).await;
        join(&mut a, 1).await;
        join(&mut b, 2).await;
        join(&mut c, 3).await;
        let a_node = node_id_of(&app, &seeded, &format!("{slug}-a")).await;
        let b_node = node_id_of(&app, &seeded, &format!("{slug}-b")).await;
        let c_node = node_id_of(&app, &seeded, &format!("{slug}-c")).await;
        Self {
            app,
            seeded,
            a,
            b,
            c,
            a_id,
            b_id,
            c_id,
            a_tok,
            b_tok,
            c_tok,
            a_node,
            b_node,
            c_node,
        }
    }

    fn tid(&self) -> ObjectId {
        ObjectId::parse_str(&self.seeded.tenant_id).unwrap()
    }
}

/// ACL off: every live node is listed, with the admin's display names, sorted
/// by the EFFECTIVE name, searchable by it, paged disjointly, and an unknown
/// sort / dir / kind is a 400 — the admin grid's contract, verbatim.
#[tokio::test]
async fn acl_off_lists_every_live_node_with_display_names_sorted_and_paged() {
    let rig = Rig::up("self-off").await;

    let (s, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(s, 200, "{page}");
    assert_eq!(page["total"], json!(3));
    assert_eq!(page["overlay"], json!("ok"));
    assert_eq!(page["acl_mode"], json!("off"));
    assert_eq!(page["self_node_id"], json!(rig.a_node));
    assert_eq!(
        item_ids(&page),
        [&rig.a_id, &rig.b_id, &rig.c_id]
            .into_iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    );
    let me = item(&page, &rig.a_id);
    assert_eq!(me["is_self"], json!(true));
    assert_eq!(me["display_name"], json!("Mike"));
    assert_eq!(me["name"], json!("alpha-box"));
    assert_eq!(me["overlay_node_id"], json!(rig.a_node));
    assert_eq!(me["overlay_ip"].as_str().map(|s| s.is_empty()), Some(false));
    assert_eq!(
        me["reachable"],
        json!(true),
        "a live joined node is dialable"
    );
    assert_eq!(me["presence"], json!("online"));
    let b = item(&page, &rig.b_id);
    assert_eq!(b["is_self"], json!(false));
    assert_eq!(b["display_name"], json!("Kilo"));
    assert_eq!(b["name"], json!("bravo-box"));
    assert_eq!(b["reachable"], json!(true));
    let c = item(&page, &rig.c_id);
    assert!(c["display_name"].is_null(), "C was never renamed: {c}");
    assert_eq!(c["name"], json!("charlie-box"));

    // sort=name orders by the EFFECTIVE name: C ("charlie-box") < B ("kilo")
    // < A ("mike"), not the technical alpha < bravo < charlie.
    let (s, page) = get_devices(&rig.app, &rig.a_tok, "?sort=name").await;
    assert_eq!(s, 200);
    assert_eq!(
        order(&page),
        vec![rig.c_id.clone(), rig.b_id.clone(), rig.a_id.clone()]
    );
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "?sort=name&dir=desc").await;
    assert_eq!(
        order(&page),
        vec![rig.a_id.clone(), rig.b_id.clone(), rig.c_id.clone()]
    );
    // The default (no sort) is presence first, then the effective name —
    // all three are online, so the same order.
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(
        order(&page),
        vec![rig.c_id.clone(), rig.b_id.clone(), rig.a_id.clone()]
    );

    // The search matches the display name, case-insensitively.
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "?q=kilo").await;
    assert_eq!(page["total"], json!(1));
    assert_eq!(item_ids(&page), BTreeSet::from([rig.b_id.clone()]));
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "?q=charlie").await;
    assert_eq!(item_ids(&page), BTreeSet::from([rig.c_id.clone()]));
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "?q=no-such-device").await;
    assert_eq!(page["total"], json!(0));
    assert!(items(&page).is_empty());

    // per_page=1: three disjoint pages whose union is the whole set.
    let mut seen = BTreeSet::new();
    for p in 1..=3 {
        let (s, page) = get_devices(
            &rig.app,
            &rig.a_tok,
            &format!("?sort=name&per_page=1&page={p}"),
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(page["per_page"], json!(1));
        assert_eq!(page["page"], json!(p));
        assert_eq!(page["total"], json!(3));
        assert_eq!(page["total_pages"], json!(3));
        let ids = item_ids(&page);
        assert_eq!(ids.len(), 1, "page {p}: {page}");
        assert!(seen.is_disjoint(&ids), "page {p} repeats a row");
        seen.extend(ids);
    }
    assert_eq!(seen.len(), 3);
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "?per_page=1&page=4").await;
    assert!(
        items(&page).is_empty(),
        "past the end is empty, not an error"
    );

    // The same validation as the admin grid.
    for bad in ["?sort=bogus", "?dir=sideways", "?kind=printer"] {
        let (s, body) = get_devices(&rig.app, &rig.a_tok, bad).await;
        assert_eq!(s, 400, "{bad}: {body}");
    }
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "?kind=tunnel_client").await;
    assert_eq!(page["total"], json!(0), "no tunnel clients enrolled");

    // The same view from another device: B sees the three too, and is self.
    let (_, page) = get_devices(&rig.app, &rig.b_tok, "").await;
    assert_eq!(page["total"], json!(3));
    assert_eq!(item(&page, &rig.b_id)["is_self"], json!(true));
    assert_eq!(item(&page, &rig.a_id)["is_self"], json!(false));
    assert_eq!(page["self_node_id"], json!(rig.b_node));
}

/// The negative control. Under `enforce` with one grant (A may reach B), the
/// netmap A receives carries exactly {B}; the list A gets must be exactly
/// that set ∪ {A} — asserted as set equality against the captured netmap. C,
/// which A's netmap withholds, is absent from the list for the same reason it
/// is absent from the netmap. `off` and `warn` list C again.
///
/// With the visibility filter removed from `routes/agent_self.rs` this test
/// fails at the set-equality assertion (the PR body carries that run).
#[tokio::test]
async fn enforce_lists_exactly_the_netmap_and_never_a_withheld_peer() {
    let mut rig = Rig::up("self-enforce").await;

    set_acl_mode(&rig.app, &rig.seeded, "enforce").await;
    allow(&rig.app, &rig.seeded, &rig.a_node, &rig.b_node).await;

    // A re-joins and captures the netmap the server now ships it.
    let netmap = join(&mut rig.a, 1).await;
    let netmap_peers = netmap_peer_node_ids(&netmap);
    assert_eq!(
        netmap_peers,
        BTreeSet::from([rig.b_node.clone()]),
        "the grant lets A reach B and nothing else: {netmap}"
    );

    let (s, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(s, 200, "{page}");
    assert_eq!(page["acl_mode"], json!("enforce"));
    assert_eq!(page["overlay"], json!("ok"));
    let mut expected_nodes = netmap_peers.clone();
    expected_nodes.insert(rig.a_node.clone());
    assert_eq!(
        item_node_ids(&page),
        expected_nodes,
        "the listed nodes must be EXACTLY the netmap's peers ∪ self: {page}"
    );
    assert_eq!(
        item_ids(&page),
        BTreeSet::from([rig.a_id.clone(), rig.b_id.clone()]),
        "{page}"
    );
    assert_eq!(page["total"], json!(2));
    assert!(
        items(&page).iter().all(|r| r["id"] != json!(rig.c_id)),
        "C is withheld from A's netmap and must be withheld here: {page}"
    );
    // The search cannot reach a withheld peer either.
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "?q=charlie").await;
    assert_eq!(page["total"], json!(0), "{page}");

    // C has no grant as a source: its netmap is empty, and so is its list
    // beyond itself.
    let netmap = join(&mut rig.c, 3).await;
    assert!(netmap_peer_node_ids(&netmap).is_empty(), "{netmap}");
    let (_, page) = get_devices(&rig.app, &rig.c_tok, "").await;
    assert_eq!(page["total"], json!(1), "{page}");
    assert_eq!(item_ids(&page), BTreeSet::from([rig.c_id.clone()]));
    assert_eq!(item(&page, &rig.c_id)["is_self"], json!(true));
    assert_eq!(page["self_node_id"], json!(rig.c_node));

    // Back to `off`: everyone sees everyone, in both views.
    set_acl_mode(&rig.app, &rig.seeded, "off").await;
    let netmap = join(&mut rig.a, 1).await;
    assert_eq!(
        netmap_peer_node_ids(&netmap),
        BTreeSet::from([rig.b_node.clone(), rig.c_node.clone()])
    );
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(page["acl_mode"], json!("off"));
    assert_eq!(page["total"], json!(3));
    assert!(item_ids(&page).contains(&rig.c_id));
    let (_, page) = get_devices(&rig.app, &rig.c_tok, "").await;
    assert_eq!(page["total"], json!(3));

    // `warn` observes and never withholds: C is present although the same
    // grant would deny it under `enforce`.
    set_acl_mode(&rig.app, &rig.seeded, "warn").await;
    let netmap = join(&mut rig.a, 1).await;
    assert_eq!(
        netmap_peer_node_ids(&netmap),
        BTreeSet::from([rig.b_node.clone(), rig.c_node.clone()])
    );
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(page["acl_mode"], json!("warn"));
    assert_eq!(page["total"], json!(3));
    assert!(item_ids(&page).contains(&rig.c_id));

    // Keep the sockets alive until the assertions are done.
    drop(rig.b);
}

/// A device with no live overlay node sees itself alone, says why, and the
/// GET never conjures an overlay network — on a fresh tenant the collection
/// stays empty, and on a tenant whose network exists it stays at one row.
#[tokio::test]
async fn a_node_less_device_lists_itself_and_never_creates_a_network() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("self-nonode").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let networks = app.db.collection::<bson::Document>("overlay_networks");
    let count = || async {
        networks
            .count_documents(doc! { "tenant_id": tid })
            .await
            .unwrap()
    };

    let (a_id, a_tok) = enroll(&app, &seeded, "self-nonode-a", "alpha-box").await;
    assert_eq!(count().await, 0, "a fresh tenant has no network");

    let (s, page) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 200, "{page}");
    assert_eq!(page["overlay"], json!("no_network"));
    assert_eq!(page["acl_mode"], json!("off"));
    assert!(page.get("self_node_id").is_none(), "{page}");
    assert_eq!(page["total"], json!(1));
    let me = item(&page, &a_id);
    assert_eq!(me["is_self"], json!(true));
    assert!(me.get("overlay_ip").is_none());
    assert!(me.get("overlay_node_id").is_none());
    assert_eq!(me["reachable"], json!(false));
    assert_eq!(count().await, 0, "the GET must not create a network row");

    // The mesh, likewise: nothing to draw, and still no network.
    let (s, mesh) = get_mesh(&app, &a_tok).await;
    assert_eq!(s, 200, "{mesh}");
    assert_eq!(mesh["enabled"], json!(true));
    assert_eq!(mesh["overlay"], json!("no_network"));
    assert!(mesh["nodes"].as_array().unwrap().is_empty());
    assert!(mesh["edges"].as_array().unwrap().is_empty());
    assert_eq!(count().await, 0);

    // Another device joins: the network now exists, but A still has no node
    // — it lists itself alone, says `no_node`, and the row count holds.
    let (b_id, b_tok) = enroll(&app, &seeded, "self-nonode-b", "bravo-box").await;
    let mut b = connect(&app, &b_tok, "bravo-box").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    join(&mut b, 2).await;
    assert_eq!(count().await, 1);

    let (s, page) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 200, "{page}");
    assert_eq!(page["overlay"], json!("no_node"));
    assert_eq!(page["total"], json!(1), "{page}");
    assert_eq!(item_ids(&page), BTreeSet::from([a_id.clone()]));
    assert!(
        items(&page).iter().all(|r| r["id"] != json!(b_id)),
        "no node ⇒ no netmap ⇒ no peers: {page}"
    );
    assert_eq!(
        count().await,
        1,
        "the GET must not create a second network row"
    );

    // B, which has a node, sees itself only: A has no node to be seen by.
    let (_, page) = get_devices(&app, &b_tok, "").await;
    assert_eq!(page["overlay"], json!("ok"));
    assert_eq!(page["total"], json!(1), "{page}");
    assert_eq!(item_ids(&page), BTreeSet::from([b_id.clone()]));
}

/// The leak control: no row a device receives carries the fleet record
/// (`machine_id`, owner, keys, raw status), and the search cannot probe
/// them — while the admin listing of the same tenant DOES carry them, which
/// is what makes the absence a claim rather than a coincidence.
#[tokio::test]
async fn rows_never_carry_the_fleet_record_while_the_admin_list_does() {
    let rig = Rig::up("self-leak").await;
    const FORBIDDEN: &[&str] = &[
        "machine_id",
        "owner_user_id",
        "enrolled_by",
        "overlay_public_key",
        "overlay_key_epoch",
        "wg_public_key",
        "key_epoch",
        "access_policy",
        "capabilities",
        "status",
        "created_at",
    ];

    let (s, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(s, 200);
    assert_eq!(page["total"], json!(3));
    for row in items(&page) {
        let keys: Vec<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for f in FORBIDDEN {
            assert!(!keys.contains(f), "{f} leaked in {row}");
        }
    }

    // The control: the admin grid carries them for the very same devices.
    let admin: Value = rig
        .app
        .auth_get(
            &tenant_url(&rig.seeded, "/device"),
            &rig.seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let a_admin = items(&admin)
        .iter()
        .find(|r| r["id"] == json!(rig.a_id))
        .expect("A in the admin list");
    let machine_id = a_admin["machine_id"]
        .as_str()
        .expect("admin rows carry machine_id");
    assert_eq!(machine_id, "self-leak-a");
    assert!(a_admin["owner_user_id"].is_string());
    assert!(
        a_admin["overlay_public_key"].is_string(),
        "admin rows carry the WG public key: {a_admin}"
    );

    // The oracle is closed: searching for A's machine_id finds nothing on
    // the device's route, and one row on the admin's.
    let (_, page) = get_devices(&rig.app, &rig.a_tok, &format!("?q={machine_id}")).await;
    assert_eq!(page["total"], json!(0), "q must not see machine_id: {page}");
    let admin: Value = rig
        .app
        .auth_get(
            &tenant_url(&rig.seeded, &format!("/device?q={machine_id}")),
            &rig.seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admin["total"], json!(1), "the admin search does: {admin}");
    let wg_key = a_admin["overlay_public_key"].as_str().unwrap();
    let (_, page) = get_devices(
        &rig.app,
        &rig.a_tok,
        &format!("?q={}", urlencode(&wg_key[..8])),
    )
    .await;
    assert_eq!(page["total"], json!(0), "q must not see the key: {page}");
}

/// Insert one `stats_mesh` snapshot — what the agent socket persists from a
/// heartbeat's `links` — for `from_agent` reporting `to_nodes`.
async fn report_links(app: &TestApp, tid: ObjectId, from_agent: &str, to_nodes: &[&str]) {
    let links: Vec<bson::Document> = to_nodes
        .iter()
        .map(|n| {
            doc! {
                "node": *n,
                "carrier": "direct",
                "rtt_ms": 5_i64,
                "stalled": false,
                "tx": 0_i64,
                "rx": 0_i64,
                "relay": null,
            }
        })
        .collect();
    app.db
        .collection::<bson::Document>("stats_mesh")
        .insert_one(doc! {
            "_id": from_agent,
            "tenant_id": tid,
            "agent_id": ObjectId::parse_str(from_agent).unwrap(),
            "ts": bson::DateTime::now(),
            "links": links,
        })
        .await
        .unwrap();
}

/// The mesh over the visible set: under `enforce` A's graph has no C node
/// and no edge touching C, names A as `self_node_id`, labels nodes by the
/// display name; under `off` the whole org is back. The web route of the
/// same org is unshaped and unlabelled — the pre-FR-84 payload.
#[tokio::test]
async fn mesh_is_restricted_to_the_visible_set() {
    let mut rig = Rig::up("self-mesh").await;
    let tid = rig.tid();
    let (a_node, b_node, c_node) = (rig.a_node.clone(), rig.b_node.clone(), rig.c_node.clone());
    report_links(
        &rig.app,
        tid,
        &rig.a_id,
        &[b_node.as_str(), c_node.as_str()],
    )
    .await;
    report_links(&rig.app, tid, &rig.b_id, &[c_node.as_str()]).await;

    // The unshaped org view first: three nodes, three edges.
    let web: Value = rig
        .app
        .auth_get(
            &tenant_url(&rig.seeded, "/stats/mesh"),
            &rig.seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(web["enabled"], json!(true));
    assert_eq!(
        mesh_node_ids(&web),
        BTreeSet::from([a_node.clone(), b_node.clone(), c_node.clone()])
    );
    assert_eq!(
        mesh_edge_pairs(&web),
        BTreeSet::from([
            pair(&a_node, &b_node),
            pair(&a_node, &c_node),
            pair(&b_node, &c_node)
        ])
    );
    assert!(web.get("self_node_id").is_none(), "{web}");
    assert!(web.get("overlay").is_none());
    assert!(
        web["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n.get("label").is_none()),
        "the web payload carries no server-computed label: {web}"
    );

    set_acl_mode(&rig.app, &rig.seeded, "enforce").await;
    allow(&rig.app, &rig.seeded, &a_node, &b_node).await;
    let netmap = join(&mut rig.a, 1).await;
    assert_eq!(
        netmap_peer_node_ids(&netmap),
        BTreeSet::from([b_node.clone()])
    );

    let (s, mesh) = get_mesh(&rig.app, &rig.a_tok).await;
    assert_eq!(s, 200, "{mesh}");
    assert_eq!(mesh["enabled"], json!(true));
    assert_eq!(mesh["overlay"], json!("ok"));
    assert_eq!(mesh["acl_mode"], json!("enforce"));
    assert_eq!(mesh["self_node_id"], json!(a_node));
    assert_eq!(
        mesh_node_ids(&mesh),
        BTreeSet::from([a_node.clone(), b_node.clone()]),
        "{mesh}"
    );
    assert_eq!(
        mesh_edge_pairs(&mesh),
        BTreeSet::from([pair(&a_node, &b_node)]),
        "no edge may touch the withheld C: {mesh}"
    );
    let agent_ids: BTreeSet<String> = mesh["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        agent_ids,
        BTreeSet::from([rig.a_id.clone(), rig.b_id.clone()])
    );
    let label_of = |id: &str| -> String {
        mesh["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == json!(id))
            .and_then(|n| n["label"].as_str())
            .map(str::to_string)
            .unwrap_or_else(|| panic!("no label on {id}: {mesh}"))
    };
    assert_eq!(label_of(&a_node), "Mike");
    assert_eq!(label_of(&b_node), "Kilo");
    assert_eq!(mesh["center"]["id"], json!("control-plane"));

    // C's own view: itself only, and not one edge.
    let (_, mesh_c) = get_mesh(&rig.app, &rig.c_tok).await;
    assert_eq!(mesh_node_ids(&mesh_c), BTreeSet::from([c_node.clone()]));
    assert!(mesh_c["edges"].as_array().unwrap().is_empty(), "{mesh_c}");
    assert_eq!(mesh_c["self_node_id"], json!(c_node));

    // `off`: the whole org again, labelled, with the caller named.
    set_acl_mode(&rig.app, &rig.seeded, "off").await;
    let (_, mesh) = get_mesh(&rig.app, &rig.a_tok).await;
    assert_eq!(mesh["acl_mode"], json!("off"));
    assert_eq!(
        mesh_node_ids(&mesh),
        BTreeSet::from([a_node.clone(), b_node.clone(), c_node.clone()])
    );
    assert_eq!(mesh_edge_pairs(&mesh).len(), 3, "{mesh}");
    assert_eq!(mesh["self_node_id"], json!(a_node));

    drop(rig.b);
    drop(rig.c);
}

/// Stats off ⇒ the same `{"enabled": false}` every stats route answers; the
/// listing is unaffected.
#[tokio::test]
async fn mesh_answers_disabled_when_stats_are_off() {
    let app = TestApp::spawn_with_settings(|s| s.stats.enabled = false).await;
    let seeded = app.seed_tenant("self-nostats").await;
    let (_a_id, a_tok) = enroll(&app, &seeded, "self-nostats-a", "alpha-box").await;
    let (s, mesh) = get_mesh(&app, &a_tok).await;
    assert_eq!(s, 200);
    assert_eq!(mesh, json!({ "enabled": false }));
    let (s, page) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 200);
    assert_eq!(page["total"], json!(1));
}

/// Both routes take an AGENT credential and nothing else: no bearer, a user
/// JWT, a quarantined device and a deleted device are each a 401.
#[tokio::test]
async fn auth_refuses_everything_but_a_live_agent_token() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("self-auth").await;
    let (a_id, a_tok) = enroll(&app, &seeded, "self-auth-a", "alpha-box").await;

    for path in ["/api/agent/self/devices", "/api/agent/self/mesh"] {
        let none = app.client.get(app.url(path)).send().await.unwrap();
        assert_eq!(none.status().as_u16(), 401, "{path}: no bearer");
        let user = app
            .auth_get(path, &seeded.admin.access_token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            user.status().as_u16(),
            401,
            "{path}: a user JWT is the wrong audience"
        );
        let garbage = app.auth_get(path, "not-a-jwt").send().await.unwrap();
        assert_eq!(garbage.status().as_u16(), 401, "{path}: garbage");
    }
    let (s, _) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 200, "the control: the live token works");

    // Quarantined: the row is the revocation list.
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&a_id).unwrap() },
            doc! { "$set": { "status": "quarantined" } },
        )
        .await
        .unwrap();
    let (s, body) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 401, "quarantined: {body}");
    let (s, _) = get_mesh(&app, &a_tok).await;
    assert_eq!(s, 401);
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&a_id).unwrap() },
            doc! { "$set": { "status": "online" } },
        )
        .await
        .unwrap();
    let (s, _) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 200, "back to accepted");

    // Deleted (the admin removal, which tombstones): deletion wins.
    let resp = app
        .auth_delete(
            &tenant_url(&seeded, &format!("/agent/{a_id}")),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let (s, body) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 401, "deleted: {body}");
    let (s, _) = get_mesh(&app, &a_tok).await;
    assert_eq!(s, 401);
}

/// No fleet module ⇒ 503, not 401: the caller dialled the right place with
/// the right kind of credential, and must not read the refusal as either
/// being wrong.
#[tokio::test]
async fn without_the_fleet_module_both_routes_answer_503() {
    let app = TestApp::spawn_with_settings(|s| s.modules.fleet = false).await;
    for path in ["/api/agent/self/devices", "/api/agent/self/mesh"] {
        let resp = app.auth_get(path, "any-token").send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 503, "{path}");
    }
}

/// V0028 §4.2: top-level RDP fields (`rdp_available`, `rdp_port`,
/// `rdp_cert_sha256`) appear ONLY when an agent reports
/// `capabilities.rdp_available == true`. Rows with `rdp_available == None` or
/// `rdp_available == Some(false)` (even if stale port/cert fields exist in DB)
/// emit NONE of the three keys, and `capabilities` as a whole never leaks on
/// `GET /api/agent/self/devices`.
#[tokio::test]
async fn rdp_fields_are_omitted_unless_rdp_available_is_true_and_capabilities_never_leak() {
    let rig = Rig::up("self-rdp-fields").await;
    let fp = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

    // A: default (`rdp_available` absent / None).
    // B: `rdp_available = false`, plus port + cert_sha256 set in DB to prove
    //    `rdp_available != Some(true)` suppresses all three keys.
    rig.app
        .db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&rig.b_id).unwrap() },
            doc! { "$set": {
                "capabilities.rdp_available": false,
                "capabilities.rdp_port": 3389_i32,
                "capabilities.rdp_cert_sha256": fp,
            } },
        )
        .await
        .unwrap();

    // C: `rdp_available = true`, with explicit port and cert SHA-256.
    rig.app
        .db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&rig.c_id).unwrap() },
            doc! { "$set": {
                "capabilities.rdp_available": true,
                "capabilities.rdp_port": 13389_i32,
                "capabilities.rdp_cert_sha256": fp,
            } },
        )
        .await
        .unwrap();

    let (s, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(s, 200);
    let rows = items(&page);

    for id in [&rig.a_id, &rig.b_id] {
        let row = rows
            .iter()
            .find(|r| r["id"] == json!(id))
            .unwrap_or_else(|| panic!("{id} missing from {page}"));
        let obj = row.as_object().unwrap();
        for rdp_key in ["rdp_available", "rdp_port", "rdp_cert_sha256"] {
            assert!(
                !obj.contains_key(rdp_key),
                "{rdp_key} must be omitted when rdp_available != true: {row}"
            );
        }
        assert!(
            !obj.contains_key("capabilities"),
            "capabilities leaked: {row}"
        );
    }

    let c_row = rows
        .iter()
        .find(|r| r["id"] == json!(rig.c_id))
        .expect("C in visible list");
    let c_obj = c_row.as_object().unwrap();
    assert_eq!(c_row["rdp_available"], json!(true));
    assert_eq!(c_row["rdp_port"], json!(13389));
    assert_eq!(c_row["rdp_cert_sha256"], json!(fp));
    assert!(
        !c_obj.contains_key("capabilities"),
        "capabilities leaked: {c_row}"
    );
}
