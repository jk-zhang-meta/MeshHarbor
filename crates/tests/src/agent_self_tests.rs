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

#[allow(dead_code)]
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
async fn enforce_lists_full_permanent_inventory_with_accurate_reachability_while_temporary_stays_isolated()
 {
    let mut rig = Rig::up("self-enforce").await;

    set_acl_mode(&rig.app, &rig.seeded, "enforce").await;
    allow(&rig.app, &rig.seeded, &rig.a_node, &rig.b_node).await;

    // A re-joins and captures the netmap the server now ships it.
    let netmap = join(&mut rig.a, 1).await;
    let netmap_peers = netmap_peer_node_ids(&netmap);
    assert_eq!(
        netmap_peers,
        BTreeSet::from([rig.b_node.clone()]),
        "the grant lets A reach B and nothing else on the wire netmap: {netmap}"
    );

    // Permanent account device A still sees 100% of active permanent devices
    // in `/api/agent/self/devices`, with `reachable = false` on withheld C!
    let (s, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(s, 200, "{page}");
    assert_eq!(page["acl_mode"], json!("enforce"));
    assert_eq!(page["overlay"], json!("ok"));
    assert_eq!(
        item_ids(&page),
        BTreeSet::from([rig.a_id.clone(), rig.b_id.clone(), rig.c_id.clone()]),
        "{page}"
    );
    assert_eq!(page["total"], json!(3));
    assert_eq!(item(&page, &rig.a_id)["reachable"], json!(true));
    assert_eq!(item(&page, &rig.b_id)["reachable"], json!(true));
    assert_eq!(
        item(&page, &rig.c_id)["reachable"],
        json!(false),
        "withheld C must report reachable=false under enforce: {page}"
    );

    // C has no grant as a source: its netmap is empty, and in `/self/devices`
    // only self is reachable while permanent peers A and B show `reachable = false`.
    let netmap = join(&mut rig.c, 3).await;
    assert!(netmap_peer_node_ids(&netmap).is_empty(), "{netmap}");
    let (_, page) = get_devices(&rig.app, &rig.c_tok, "").await;
    assert_eq!(page["total"], json!(3), "{page}");
    assert_eq!(item(&page, &rig.c_id)["is_self"], json!(true));
    assert_eq!(item(&page, &rig.c_id)["reachable"], json!(true));
    assert_eq!(item(&page, &rig.a_id)["reachable"], json!(false));
    assert_eq!(item(&page, &rig.b_id)["reachable"], json!(false));
    assert_eq!(page["self_node_id"], json!(rig.c_node));

    // Back to `off`: everyone sees everyone, and all live peers report reachable=true.
    set_acl_mode(&rig.app, &rig.seeded, "off").await;
    let netmap = join(&mut rig.a, 1).await;
    assert_eq!(
        netmap_peer_node_ids(&netmap),
        BTreeSet::from([rig.b_node.clone(), rig.c_node.clone()])
    );
    let (_, page) = get_devices(&rig.app, &rig.a_tok, "").await;
    assert_eq!(page["acl_mode"], json!("off"));
    assert_eq!(page["total"], json!(3));
    assert_eq!(item(&page, &rig.c_id)["reachable"], json!(true));
    let (_, page) = get_devices(&rig.app, &rig.c_tok, "").await;
    assert_eq!(page["total"], json!(3));

    // `warn` observes and never withholds: C is present and reachable.
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

    // Another device joins: the network now exists, A still has `no_node`,
    // the row count holds at 1, and under `acl_mode == "off"` BOTH account
    // devices see 100% of the account's inventory (while `enforce` restricts
    // visibility strictly to live netmap peers).
    let (b_id, b_tok) = enroll(&app, &seeded, "self-nonode-b", "bravo-box").await;
    let mut b = connect(&app, &b_tok, "bravo-box").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    join(&mut b, 2).await;
    assert_eq!(count().await, 1);

    let (s, page) = get_devices(&app, &a_tok, "").await;
    assert_eq!(s, 200, "{page}");
    assert_eq!(page["overlay"], json!("no_node"));
    assert_eq!(page["total"], json!(2), "{page}");
    assert_eq!(
        item_ids(&page),
        BTreeSet::from([a_id.clone(), b_id.clone()])
    );
    assert_eq!(item(&page, &b_id)["reachable"], json!(false));
    assert_eq!(
        count().await,
        1,
        "the GET must not create a second network row"
    );

    // B, which has a node, also sees offline/node-less A under `acl_mode == "off"`.
    let (_, page) = get_devices(&app, &b_tok, "").await;
    assert_eq!(page["overlay"], json!("ok"));
    assert_eq!(page["total"], json!(2), "{page}");
    assert_eq!(
        item_ids(&page),
        BTreeSet::from([a_id.clone(), b_id.clone()])
    );

    // Under `acl_mode == "enforce"`, permanent account devices A and B still see
    // full permanent inventory (`total == 2`) while reporting `reachable = false`
    // for ungranted peers.
    set_acl_mode(&app, &seeded, "enforce").await;
    let (_, page) = get_devices(&app, &a_tok, "").await;
    assert_eq!(page["total"], json!(2), "{page}");
    assert_eq!(
        item_ids(&page),
        BTreeSet::from([a_id.clone(), b_id.clone()])
    );
    assert_eq!(item(&page, &b_id)["reachable"], json!(false));
    let (_, page) = get_devices(&app, &b_tok, "").await;
    assert_eq!(page["total"], json!(2), "{page}");
    assert_eq!(
        item_ids(&page),
        BTreeSet::from([a_id.clone(), b_id.clone()])
    );
    assert_eq!(item(&page, &a_id)["reachable"], json!(false));
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
                "capabilities.rdp_mesh_reachable": true,
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
                "capabilities.rdp_mesh_reachable": true,
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
        for rdp_key in [
            "rdp_available",
            "rdp_port",
            "rdp_cert_sha256",
            "rdp_mesh_reachable",
        ] {
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
    assert_eq!(c_row["rdp_mesh_reachable"], json!(true));
    assert!(
        !c_obj.contains_key("capabilities"),
        "capabilities leaked: {c_row}"
    );
}

/// Build a 2-bit-tree MaxMind City MMDB (`dbip-city-lite.mmdb`) stamped 60s ago:
/// - `0.0.0.0/1`   (`8.8.8.8`)      -> US / United States / Texas / Houston (`en` fallback)
/// - `128.0.0.0/2` (`139.199.1.1`)  -> CN / 中国 / 广东省 / 深圳市 (`zh-CN` preferred)
/// - `192.0.0.0/2` (`203.0.113.9`)  -> HK / 中国香港 / 香港 (`zh-CN` preferred, NonMainland)
pub(crate) fn city_fixture_mmdb() -> Vec<u8> {
    fn text(out: &mut Vec<u8>, v: &str) {
        let len = v.len();
        if len < 29 {
            out.push(0x40 | len as u8);
        } else {
            out.push(0x40 | 29);
            out.push((len - 29) as u8);
        }
        out.extend_from_slice(v.as_bytes());
    }
    fn map(out: &mut Vec<u8>, entries: u8) {
        out.push(0xE0 | entries);
    }
    fn array(out: &mut Vec<u8>, entries: u8) {
        out.extend_from_slice(&[entries, 11 - 7]);
    }
    fn uint16(out: &mut Vec<u8>, v: u16) {
        out.push(0xA2);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn uint32(out: &mut Vec<u8>, v: u32) {
        out.push(0xC4);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn uint64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&[0x08, 9 - 7]);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn names(out: &mut Vec<u8>, zh: Option<&str>, en: &str) {
        map(out, if zh.is_some() { 2 } else { 1 });
        if let Some(zh) = zh {
            text(out, "zh-CN");
            text(out, zh);
        }
        text(out, "en");
        text(out, en);
    }
    fn city_record(
        code: &str,
        country_zh: Option<&str>,
        country_en: &str,
        region: Option<(Option<&str>, &str)>,
        city: Option<(Option<&str>, &str)>,
    ) -> Vec<u8> {
        let mut d = Vec::new();
        let fields = 1 + u8::from(region.is_some()) + u8::from(city.is_some());
        map(&mut d, fields);
        text(&mut d, "country");
        map(&mut d, 2);
        text(&mut d, "iso_code");
        text(&mut d, code);
        text(&mut d, "names");
        names(&mut d, country_zh, country_en);
        if let Some((r_zh, r_en)) = region {
            text(&mut d, "subdivisions");
            array(&mut d, 1);
            map(&mut d, 1);
            text(&mut d, "names");
            names(&mut d, r_zh, r_en);
        }
        if let Some((c_zh, c_en)) = city {
            text(&mut d, "city");
            map(&mut d, 1);
            text(&mut d, "names");
            names(&mut d, c_zh, c_en);
        }
        d
    }

    let us = city_record(
        "US",
        None,
        "United States",
        Some((None, "Texas")),
        Some((None, "Houston")),
    );
    let cn = city_record(
        "CN",
        Some("中国"),
        "China",
        Some((Some("广东省"), "Guangdong")),
        Some((Some("深圳市"), "Shenzhen")),
    );
    let hk = city_record(
        "HK",
        Some("中国香港"),
        "Hong Kong",
        None,
        Some((Some("香港"), "Hong Kong")),
    );
    let node_count: u32 = 2;
    let to_us = node_count + 16;
    let to_cn = to_us + us.len() as u32;
    let to_hk = to_cn + cn.len() as u32;
    let built = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 60;
    let mut db = Vec::new();
    // Node 0: bit 0 == 0 -> US data; bit 0 == 1 -> Node 1
    db.extend_from_slice(&to_us.to_be_bytes()[1..]);
    db.extend_from_slice(&1_u32.to_be_bytes()[1..]);
    // Node 1: bit 1 == 0 (128.0.0.0/2) -> CN; bit 1 == 1 (192.0.0.0/2) -> HK
    db.extend_from_slice(&to_cn.to_be_bytes()[1..]);
    db.extend_from_slice(&to_hk.to_be_bytes()[1..]);
    db.extend_from_slice(&[0; 16]);
    db.extend_from_slice(&us);
    db.extend_from_slice(&cn);
    db.extend_from_slice(&hk);
    db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    map(&mut db, 9);
    text(&mut db, "binary_format_major_version");
    uint16(&mut db, 2);
    text(&mut db, "binary_format_minor_version");
    uint16(&mut db, 0);
    text(&mut db, "build_epoch");
    uint64(&mut db, built);
    text(&mut db, "database_type");
    text(&mut db, "DBIP-City-Lite");
    text(&mut db, "description");
    map(&mut db, 1);
    text(&mut db, "en");
    text(&mut db, "city geoip fixture");
    text(&mut db, "ip_version");
    uint16(&mut db, 4);
    text(&mut db, "languages");
    array(&mut db, 2);
    text(&mut db, "en");
    text(&mut db, "zh-CN");
    text(&mut db, "node_count");
    uint32(&mut db, node_count);
    text(&mut db, "record_size");
    uint16(&mut db, 24);
    db
}

#[tokio::test]
async fn account_devices_include_offline_and_cross_border_with_city_geoip_and_temporary_isolation()
{
    use crate::peer_relay_mint_tests::connect_from;

    let geo = tempfile::tempdir().unwrap();
    let mmdb_path = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb_path, city_fixture_mmdb()).unwrap();
    let mmdb_str = mmdb_path.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.auth.native_device_invite_enabled = true;
        s.stats.geoip_mmdb = Some(mmdb_str);
    })
    .await;
    let seeded = app.seed_tenant("self-geo-inv").await;
    let admin = &seeded.admin.access_token;

    let (cn_id, cn_tok) = enroll(&app, &seeded, "self-geo-cn", "siat45").await;
    let (us_id, us_tok) = enroll(&app, &seeded, "self-geo-us", "houston-host").await;
    let (hk_id, hk_tok) = enroll(&app, &seeded, "self-geo-hk", "isvoro-hk").await;
    let (guest_id, guest_tok) = enroll(&app, &seeded, "self-geo-guest", "temp-guest").await;

    // CN device connects from Shenzhen IP (139.199.1.1), joins overlay, then goes OFFLINE.
    let mut cn_ws = connect_from(&app, &cn_tok, &[], Some("139.199.1.1")).await;
    join(&mut cn_ws, 11).await;
    drop(cn_ws);

    // HK device connects from Hong Kong IP (202.181.7.9) WITHOUT ever joining overlay, then goes OFFLINE.
    let hk_ws = connect_from(&app, &hk_tok, &[], Some("202.181.7.9")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(hk_ws);

    // US device stays online on Houston IP (8.8.8.8).
    let mut us_ws = connect_from(&app, &us_tok, &[], Some("8.8.8.8")).await;
    join(&mut us_ws, 12).await;

    // FR-134 requires each zone to name at least one approved gateway router.
    let resp = app
        .auth_put(
            &tenant_url(&seeded, &format!("/agent/{us_id}/peer-relay-policy")),
            admin,
        )
        .json(&json!({ "serve": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Define Logical Network Zones and pin CN device to `"siat"`.
    let resp = app
        .auth_put(&tenant_url(&seeded, "/network-zones"), admin)
        .json(&json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "Mainland China",
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [us_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "siat",
                    "name": "SIAT Campus",
                    "auto_countries": [],
                    "is_default": false,
                    "gateway_relay_ids": [us_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "hk",
                    "name": "Hong Kong",
                    "auto_countries": ["HK"],
                    "is_default": false,
                    "gateway_relay_ids": [us_id],
                    "cross_zone_mode": "direct_preferred"
                },
                {
                    "id": "global",
                    "name": "Global",
                    "auto_countries": ["US"],
                    "is_default": true,
                    "gateway_relay_ids": [us_id],
                    "cross_zone_mode": "direct_preferred"
                }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let resp = app
        .auth_put(
            &tenant_url(&seeded, &format!("/agent/{cn_id}/zone-assignment")),
            admin,
        )
        .json(&json!({ "pinned_zone_id": "siat" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Convert `guest_id` into a temporary invitee device.
    let resp = app
        .auth_post(
            &tenant_url(&seeded, &format!("/agent/{guest_id}/temporary")),
            admin,
        )
        .json(&json!({ "duration_secs": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // 1. Account device (`houston-host`) calling GET /api/agent/self/devices sees
    //    ALL 3 permanent account devices (including offline `siat45` and node-less
    //    offline `isvoro-hk`, while excluding unjoined temporary guest `temp-guest`)
    //    with persisted public_ip + zh-CN/en City GeoIP + Logical Network Zone fields!
    let (s, self_page) = get_devices(&app, &us_tok, "").await;
    assert_eq!(s, 200, "{self_page}");
    assert_eq!(self_page["total"], json!(3), "{self_page}");
    let cn_self = item(&self_page, &cn_id);
    assert_eq!(cn_self["public_ip"], json!("139.199.1.1"));
    assert_eq!(cn_self["country_code"], json!("CN"));
    assert_eq!(cn_self["country"], json!("中国"));
    assert_eq!(cn_self["region"], json!("广东省"));
    assert_eq!(cn_self["city"], json!("深圳市"));
    assert_eq!(cn_self["pinned_zone_id"], json!("siat"));
    assert_eq!(cn_self["effective_zone_id"], json!("siat"));
    assert_eq!(cn_self["effective_zone_name"], json!("SIAT Campus"));

    let hk_self = item(&self_page, &hk_id);
    assert_eq!(hk_self["public_ip"], json!("202.181.7.9"));
    assert_eq!(hk_self["country_code"], json!("HK"));
    assert_eq!(hk_self["country"], json!("中国香港"));
    assert_eq!(hk_self["city"], json!("香港"));
    assert!(hk_self.get("pinned_zone_id").is_none(), "{hk_self}");
    assert_eq!(hk_self["effective_zone_id"], json!("hk"));
    assert_eq!(hk_self["effective_zone_name"], json!("Hong Kong"));

    let us_self = item(&self_page, &us_id);
    assert_eq!(us_self["public_ip"], json!("8.8.8.8"));
    assert_eq!(us_self["country_code"], json!("US"));
    assert_eq!(us_self["country"], json!("United States"));
    assert_eq!(us_self["region"], json!("Texas"));
    assert_eq!(us_self["city"], json!("Houston"));
    assert!(us_self.get("pinned_zone_id").is_none(), "{us_self}");
    assert_eq!(us_self["effective_zone_id"], json!("global"));
    assert_eq!(us_self["effective_zone_name"], json!("Global"));

    // 2. Web UI endpoints `GET /api/tenant/{tid}/device` (`DeviceRow`) and
    //    `GET /api/tenant/{tid}/agent` (`AgentResponse`) expose identical zone + GeoIP fields.
    let dev_resp: Value = app
        .auth_get(&tenant_url(&seeded, "/device"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cn_dev = dev_resp["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(cn_id))
        .expect("cn device row");
    assert_eq!(cn_dev["public_ip"], json!("139.199.1.1"));
    assert_eq!(cn_dev["country_code"], json!("CN"));
    assert_eq!(cn_dev["country"], json!("中国"));
    assert_eq!(cn_dev["region"], json!("广东省"));
    assert_eq!(cn_dev["city"], json!("深圳市"));
    assert_eq!(cn_dev["pinned_zone_id"], json!("siat"));
    assert_eq!(cn_dev["effective_zone_id"], json!("siat"));
    assert_eq!(cn_dev["effective_zone_name"], json!("SIAT Campus"));

    let ag_resp: Value = app
        .auth_get(&tenant_url(&seeded, "/agent"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cn_ag = ag_resp["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(cn_id))
        .expect("cn agent row");
    assert_eq!(cn_ag["public_ip"], json!("139.199.1.1"));
    assert_eq!(cn_ag["country_code"], json!("CN"));
    assert_eq!(cn_ag["country"], json!("中国"));
    assert_eq!(cn_ag["region"], json!("广东省"));
    assert_eq!(cn_ag["city"], json!("深圳市"));
    assert_eq!(cn_ag["pinned_zone_id"], json!("siat"));
    assert_eq!(cn_ag["effective_zone_id"], json!("siat"));
    assert_eq!(cn_ag["effective_zone_name"], json!("SIAT Campus"));

    // 3. Temporary guest device (`guest_tok`, node-less) retains strict isolation:
    //    it does NOT receive the full tenant inventory and public_ip/geo/zone fields are blanked!
    let guest_ws = connect_from(&app, &guest_tok, &[], Some("8.8.8.8")).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (s, guest_page) = get_devices(&app, &guest_tok, "").await;
    assert_eq!(s, 200, "{guest_page}");
    assert_eq!(guest_page["total"], json!(1), "{guest_page}");
    let g_row = item(&guest_page, &guest_id);
    for key in [
        "public_ip",
        "country_code",
        "country",
        "region",
        "city",
        "lat",
        "lon",
        "accuracy_radius_km",
        "geo_level",
        "pinned_zone_id",
        "effective_zone_id",
        "effective_zone_name",
    ] {
        assert!(
            g_row.get(key).is_none(),
            "temporary caller must not receive {key}: {g_row}"
        );
    }
    let (_, q_zone) = get_devices(&app, &guest_tok, "?q=global").await;
    assert_eq!(
        q_zone["total"],
        json!(0),
        "temporary caller search must not probe zone: {q_zone}"
    );
    drop(guest_ws);
    drop(us_ws);
}

#[tokio::test]
async fn temporary_guest_without_node_stays_isolated_when_invitations_disabled_and_fails_closed_on_corrupt_invite()
 {
    let geo_dir = tempfile::tempdir().unwrap();
    let mmdb_path = geo_dir.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb_path, city_fixture_mmdb()).unwrap();
    let mmdb_str = mmdb_path.to_str().unwrap().to_owned();

    // `native_device_invite_enabled = false`, `business_isolation = "off"`, ACL `off`!
    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.auth.native_device_invite_enabled = false;
        s.stats.geoip_mmdb = Some(mmdb_str);
    })
    .await;
    let seeded = app.seed_tenant("self-inv-disabled").await;
    let tid = bson::oid::ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let admin_uid = bson::oid::ObjectId::parse_str(&seeded.admin.id).unwrap();

    let (perm_id, perm_tok) = enroll(&app, &seeded, "perm-mach-1", "perm-host").await;
    let (guest_id, guest_tok) = enroll(&app, &seeded, "guest-mach-1", "guest-host").await;

    // Permanent device connects from Houston IP (8.8.8.8) and joins overlay.
    let mut perm_ws =
        crate::peer_relay_mint_tests::connect_from(&app, &perm_tok, &[], Some("8.8.8.8")).await;
    join(&mut perm_ws, 71).await;

    // Bind `guest_id` as an already-enrolled temporary invitee (with NO overlay node!).
    let guest_oid = bson::oid::ObjectId::parse_str(&guest_id).unwrap();
    let guest_row = app
        .state
        .fleet()
        .agents
        .base
        .find_by_id(guest_oid)
        .await
        .unwrap();
    meshharbor_mod_fleet::device_invite::create_bound(
        app.state.fleet(),
        tid,
        admin_uid,
        &guest_row,
        3600,
        Vec::new(),
    )
    .await
    .unwrap();

    // Guest connects from Shenzhen IP (139.199.1.1) WITHOUT joining overlay (`no_node`).
    let guest_ws =
        crate::peer_relay_mint_tests::connect_from(&app, &guest_tok, &[], Some("139.199.1.1"))
            .await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 1. Even with `native_device_invite_enabled = false` and no overlay node,
    //    temporary guest sees ONLY itself (never permanent `perm_id`) and has
    //    `public_ip` / GeoIP blanked!
    let (s, guest_page) = get_devices(&app, &guest_tok, "").await;
    assert_eq!(s, 200, "{guest_page}");
    assert_eq!(guest_page["overlay"], json!("no_node"));
    assert_eq!(guest_page["total"], json!(1), "{guest_page}");
    let g_row = item(&guest_page, &guest_id);
    assert!(
        guest_page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["id"] != json!(perm_id)),
        "temporary invitee must never see permanent account inventory: {guest_page}"
    );
    for key in [
        "public_ip",
        "country_code",
        "country",
        "region",
        "city",
        "lat",
        "lon",
        "accuracy_radius_km",
        "geo_level",
    ] {
        assert!(
            g_row.get(key).is_none(),
            "temporary invitee must have {key} blanked: {g_row}"
        );
    }

    // 2. Permanent caller also excludes the temporary guest even when invitations are disabled.
    let (s, perm_page) = get_devices(&app, &perm_tok, "").await;
    assert_eq!(s, 200, "{perm_page}");
    assert_eq!(perm_page["total"], json!(1), "{perm_page}");
    assert_eq!(item(&perm_page, &perm_id)["public_ip"], json!("8.8.8.8"));

    // 3. Corrupt `agent_id` in `device_invites` -> temporary lookup error MUST fail closed (5xx),
    //    never defaulting `self_temporary = false`!
    app.db
        .collection::<bson::Document>("device_invites")
        .update_many(
            bson::doc! { "tenant_id": tid },
            bson::doc! { "$set": { "agent_id": "corrupted-non-oid" } },
        )
        .await
        .unwrap();
    let (err_status, err_body) = get_devices(&app, &guest_tok, "").await;
    assert!(
        err_status >= 500,
        "failed temporary-status lookup must fail closed (got {err_status}: {err_body})"
    );

    drop(guest_ws);
    drop(perm_ws);
}

#[tokio::test]
async fn permanent_caller_lists_nodeless_tunnel_clients_while_temporary_guest_hides_them() {
    let app = TestApp::spawn_with_settings(|s| {
        s.auth.native_device_invite_enabled = true;
    })
    .await;
    let seeded = app.seed_tenant("self-nodeless-tc").await;
    let admin = &seeded.admin.access_token;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();

    let (perm_id, perm_tok) = enroll(&app, &seeded, "self-tc-perm", "perm-workstation").await;
    let (guest_id, guest_tok) = enroll(&app, &seeded, "self-tc-guest", "guest-laptop").await;

    // Enroll a permanent tunnel client WITHOUT ever creating an OverlayNode or OverlayNetwork!
    let tc_et: Value = app
        .auth_post(&tenant_url(&seeded, "/tunnel-client/enroll-token"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tc_enrolled: Value = app
        .client
        .post(app.url("/api/tunnel-client/enroll"))
        .json(&json!({
            "enrollment_token": tc_et["enrollment_token"].as_str().unwrap(),
            "machine_id": "self-tc-only-m1",
            "machine_name": "nodeless-tunnel-box",
            "os": "macos",
            "client_version": "0.4.166",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tc_id = tc_enrolled["tunnel_client_id"]
        .as_str()
        .expect("tunnel_client_id")
        .to_string();

    // Mark `guest_id` as a temporary guest device.
    let resp = app
        .auth_post(
            &tenant_url(&seeded, &format!("/agent/{guest_id}/temporary")),
            admin,
        )
        .json(&json!({ "duration_secs": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // 1. Permanent caller sees BOTH `perm_id` AND the node-less permanent `tunnel_client` (`tc_id`),
    //    even on a virgin tenant where `node_by_client` is empty (`overlay: "no_network"`),
    //    and `GET /api/agent/self/devices` creates ZERO `overlay_networks` documents!
    let (s, perm_page) = get_devices(&app, &perm_tok, "").await;
    assert_eq!(s, 200, "{perm_page}");
    assert_eq!(perm_page["overlay"], json!("no_network"));
    assert_eq!(
        item_ids(&perm_page),
        BTreeSet::from([perm_id.clone(), tc_id.clone()]),
        "permanent caller must see node-less permanent tunnel client: {perm_page}"
    );
    let tc_row = item(&perm_page, &tc_id);
    assert_eq!(tc_row["kind"], json!("tunnel_client"));
    assert_eq!(tc_row["name"], json!("nodeless-tunnel-box"));
    assert_eq!(tc_row["reachable"], json!(false));
    assert!(tc_row.get("overlay_node_id").is_none());
    assert!(tc_row.get("overlay_ip").is_none());
    assert_eq!(
        app.db
            .collection::<bson::Document>("overlay_networks")
            .count_documents(doc! { "tenant_id": tid })
            .await
            .unwrap(),
        0,
        "GET /api/agent/self/devices must not allocate an overlay_networks row"
    );

    // 2. Temporary guest caller (`guest_tok`) sees ONLY itself (`guest_id`), hiding the node-less tunnel client!
    let (s, guest_page) = get_devices(&app, &guest_tok, "").await;
    assert_eq!(s, 200, "{guest_page}");
    assert_eq!(
        item_ids(&guest_page),
        BTreeSet::from([guest_id]),
        "temporary guest must never see non-netmap permanent tunnel clients: {guest_page}"
    );
}

/// Build an IPv4 MaxMind City MMDB with RFC 5737 TEST-NET records exercising all
/// FR-136 P6 `geo_level` tiers:
/// - `192.0.2.10`    -> CN / 中国 / 广东省 / 深圳市 + coords (22.5431, 114.0579, r=50) -> `coords`
/// - `198.51.100.10` -> US / United States / Texas / Houston (no `location`)         -> `city`
/// - `198.51.100.20` -> CN / 中国 / 广东省 (province centroid `location`, no city)    -> `region` (coords suppressed)
/// - `203.0.113.10`  -> US / United States (country centroid `location`, r=1000)     -> `country` (coords suppressed)
fn city_coords_fixture_mmdb() -> Vec<u8> {
    fn text(out: &mut Vec<u8>, v: &str) {
        let len = v.len();
        if len < 29 {
            out.push(0x40 | len as u8);
        } else {
            out.push(0x40 | 29);
            out.push((len - 29) as u8);
        }
        out.extend_from_slice(v.as_bytes());
    }
    fn map(out: &mut Vec<u8>, entries: u8) {
        out.push(0xE0 | entries);
    }
    fn array(out: &mut Vec<u8>, entries: u8) {
        out.extend_from_slice(&[entries, 11 - 7]);
    }
    fn uint16(out: &mut Vec<u8>, v: u16) {
        out.push(0xA2);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn uint32(out: &mut Vec<u8>, v: u32) {
        out.push(0xC4);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn uint64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&[0x08, 9 - 7]);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn double(out: &mut Vec<u8>, v: f64) {
        out.push(0x68);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn names(out: &mut Vec<u8>, zh: Option<&str>, en: &str) {
        map(out, if zh.is_some() { 2 } else { 1 });
        if let Some(zh) = zh {
            text(out, "zh-CN");
            text(out, zh);
        }
        text(out, "en");
        text(out, en);
    }
    fn record(
        code: &str,
        country_zh: Option<&str>,
        country_en: &str,
        region: Option<(Option<&str>, &str)>,
        city: Option<(Option<&str>, &str)>,
        location: Option<(f64, f64, Option<u16>)>,
    ) -> Vec<u8> {
        let mut d = Vec::new();
        let fields = 1
            + u8::from(region.is_some())
            + u8::from(city.is_some())
            + u8::from(location.is_some());
        map(&mut d, fields);
        text(&mut d, "country");
        map(&mut d, 2);
        text(&mut d, "iso_code");
        text(&mut d, code);
        text(&mut d, "names");
        names(&mut d, country_zh, country_en);
        if let Some((r_zh, r_en)) = region {
            text(&mut d, "subdivisions");
            array(&mut d, 1);
            map(&mut d, 1);
            text(&mut d, "names");
            names(&mut d, r_zh, r_en);
        }
        if let Some((c_zh, c_en)) = city {
            text(&mut d, "city");
            map(&mut d, 1);
            text(&mut d, "names");
            names(&mut d, c_zh, c_en);
        }
        if let Some((lat, lon, acc)) = location {
            text(&mut d, "location");
            map(&mut d, 2 + u8::from(acc.is_some()));
            text(&mut d, "latitude");
            double(&mut d, lat);
            text(&mut d, "longitude");
            double(&mut d, lon);
            if let Some(r) = acc {
                text(&mut d, "accuracy_radius");
                uint16(&mut d, r);
            }
        }
        d
    }

    let entries: Vec<(std::net::Ipv4Addr, Vec<u8>)> = vec![
        (
            "192.0.2.10".parse().unwrap(),
            record(
                "CN",
                Some("中国"),
                "China",
                Some((Some("广东省"), "Guangdong")),
                Some((Some("深圳市"), "Shenzhen")),
                Some((22.5431, 114.0579, Some(50))),
            ),
        ),
        (
            "198.51.100.10".parse().unwrap(),
            record(
                "US",
                None,
                "United States",
                Some((None, "Texas")),
                Some((None, "Houston")),
                None,
            ),
        ),
        (
            "198.51.100.20".parse().unwrap(),
            record(
                "CN",
                Some("中国"),
                "China",
                Some((Some("广东省"), "Guangdong")),
                None,
                Some((23.1291, 113.2644, Some(200))),
            ),
        ),
        (
            "203.0.113.10".parse().unwrap(),
            record(
                "US",
                None,
                "United States",
                None,
                None,
                Some((37.751, -97.822, Some(1000))),
            ),
        ),
    ];

    #[derive(Clone, Copy)]
    enum NodeRef {
        Internal(usize),
        Leaf(usize),
    }
    let mut nodes: Vec<[Option<NodeRef>; 2]> = vec![[None, None]];
    for (entry_idx, (ip, _)) in entries.iter().enumerate() {
        let bits = u32::from(*ip);
        let mut cur = 0usize;
        for shift in (0..32).rev() {
            let bit = ((bits >> shift) & 1) as usize;
            if shift == 0 {
                nodes[cur][bit] = Some(NodeRef::Leaf(entry_idx));
            } else {
                match nodes[cur][bit] {
                    Some(NodeRef::Internal(next)) => cur = next,
                    _ => {
                        let next = nodes.len();
                        nodes.push([None, None]);
                        nodes[cur][bit] = Some(NodeRef::Internal(next));
                        cur = next;
                    }
                }
            }
        }
    }

    let node_count = nodes.len() as u32;
    let mut offsets = Vec::with_capacity(entries.len());
    let mut data_section = Vec::new();
    for (_, rec) in &entries {
        offsets.push(node_count + 16 + data_section.len() as u32);
        data_section.extend_from_slice(rec);
    }
    let built = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 60;
    let mut db = Vec::new();
    for pair in &nodes {
        for slot in pair {
            let val: u32 = match slot {
                None => node_count,
                Some(NodeRef::Internal(i)) => *i as u32,
                Some(NodeRef::Leaf(i)) => offsets[*i],
            };
            db.extend_from_slice(&val.to_be_bytes()[1..]);
        }
    }
    db.extend_from_slice(&[0; 16]);
    db.extend_from_slice(&data_section);
    db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    map(&mut db, 9);
    text(&mut db, "binary_format_major_version");
    uint16(&mut db, 2);
    text(&mut db, "binary_format_minor_version");
    uint16(&mut db, 0);
    text(&mut db, "build_epoch");
    uint64(&mut db, built);
    text(&mut db, "database_type");
    text(&mut db, "GeoLite2-City");
    text(&mut db, "description");
    map(&mut db, 1);
    text(&mut db, "en");
    text(&mut db, "city coords geoip fixture");
    text(&mut db, "ip_version");
    uint16(&mut db, 4);
    text(&mut db, "languages");
    array(&mut db, 2);
    text(&mut db, "en");
    text(&mut db, "zh-CN");
    text(&mut db, "node_count");
    uint32(&mut db, node_count);
    text(&mut db, "record_size");
    uint16(&mut db, 24);
    db
}

#[tokio::test]
async fn device_listings_emit_mmdb_coords_accuracy_and_geo_level_and_redact_for_temporary_caller() {
    use crate::peer_relay_mint_tests::connect_from;

    let geo = tempfile::tempdir().unwrap();
    let mmdb_path = geo.path().join("geolite2-city-coords.mmdb");
    std::fs::write(&mmdb_path, city_coords_fixture_mmdb()).unwrap();
    let mmdb_str = mmdb_path.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.auth.native_device_invite_enabled = true;
        s.stats.geoip_mmdb = Some(mmdb_str);
    })
    .await;
    let seeded = app.seed_tenant("p6-mmdb-coords").await;
    let admin = &seeded.admin.access_token;

    let (coords_id, coords_tok) = enroll(&app, &seeded, "p6-coords", "device-a").await;
    let (city_id, city_tok) = enroll(&app, &seeded, "p6-city", "device-b").await;
    let (region_id, region_tok) = enroll(&app, &seeded, "p6-region", "device-c").await;
    let (country_id, country_tok) = enroll(&app, &seeded, "p6-country", "device-d").await;
    let (guest_id, guest_tok) = enroll(&app, &seeded, "p6-guest", "guest-a").await;

    let mut coords_ws = connect_from(&app, &coords_tok, &[], Some("192.0.2.10")).await;
    join(&mut coords_ws, 21).await;
    let city_ws = connect_from(&app, &city_tok, &[], Some("198.51.100.10")).await;
    let region_ws = connect_from(&app, &region_tok, &[], Some("198.51.100.20")).await;
    let country_ws = connect_from(&app, &country_tok, &[], Some("203.0.113.10")).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(city_ws);
    drop(region_ws);
    drop(country_ws);

    let resp = app
        .auth_post(
            &tenant_url(&seeded, &format!("/agent/{guest_id}/temporary")),
            admin,
        )
        .json(&json!({ "duration_secs": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let assert_tier_rows = |items: &[Value], surface: &str| {
        let by_id = |id: &str| -> &Value {
            items
                .iter()
                .find(|r| r["id"] == json!(id))
                .unwrap_or_else(|| panic!("{surface}: missing device {id}: {items:?}"))
        };

        let r_coords = by_id(&coords_id);
        assert_eq!(r_coords["country_code"], json!("CN"), "{surface}");
        assert_eq!(r_coords["city"], json!("深圳市"), "{surface}");
        assert_eq!(r_coords["lat"], json!(22.5431), "{surface}");
        assert_eq!(r_coords["lon"], json!(114.0579), "{surface}");
        assert_eq!(r_coords["accuracy_radius_km"], json!(50), "{surface}");
        assert_eq!(r_coords["geo_level"], json!("coords"), "{surface}");

        let r_city = by_id(&city_id);
        assert_eq!(r_city["city"], json!("Houston"), "{surface}");
        assert_eq!(r_city["geo_level"], json!("city"), "{surface}");
        assert!(r_city.get("lat").is_none(), "{surface}: {r_city}");
        assert!(r_city.get("lon").is_none(), "{surface}: {r_city}");
        assert!(
            r_city.get("accuracy_radius_km").is_none(),
            "{surface}: {r_city}"
        );

        let r_region = by_id(&region_id);
        assert_eq!(r_region["region"], json!("广东省"), "{surface}");
        assert!(r_region.get("city").is_none(), "{surface}: {r_region}");
        assert_eq!(r_region["geo_level"], json!("region"), "{surface}");
        assert!(r_region.get("lat").is_none(), "{surface}: {r_region}");
        assert!(r_region.get("lon").is_none(), "{surface}: {r_region}");
        assert!(
            r_region.get("accuracy_radius_km").is_none(),
            "{surface}: {r_region}"
        );

        let r_country = by_id(&country_id);
        assert_eq!(r_country["country_code"], json!("US"), "{surface}");
        assert!(r_country.get("region").is_none(), "{surface}: {r_country}");
        assert!(r_country.get("city").is_none(), "{surface}: {r_country}");
        assert_eq!(r_country["geo_level"], json!("country"), "{surface}");
        assert!(r_country.get("lat").is_none(), "{surface}: {r_country}");
        assert!(r_country.get("lon").is_none(), "{surface}: {r_country}");
        assert!(
            r_country.get("accuracy_radius_km").is_none(),
            "{surface}: {r_country}"
        );
    };

    // 1. GET /api/tenant/{tid}/agent
    let ag_list: Value = app
        .auth_get(&tenant_url(&seeded, "/agent"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_tier_rows(ag_list["items"].as_array().unwrap(), "GET /agent");

    // 2. GET /api/tenant/{tid}/agent/{aid}
    let ag_one: Value = app
        .auth_get(&tenant_url(&seeded, &format!("/agent/{coords_id}")), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ag_one["lat"], json!(22.5431));
    assert_eq!(ag_one["lon"], json!(114.0579));
    assert_eq!(ag_one["accuracy_radius_km"], json!(50));
    assert_eq!(ag_one["geo_level"], json!("coords"));

    // 3. GET /api/tenant/{tid}/device
    let dev_list: Value = app
        .auth_get(&tenant_url(&seeded, "/device"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_tier_rows(dev_list["items"].as_array().unwrap(), "GET /device");

    // 4. GET /api/agent/self/devices (permanent caller)
    let (status, self_page) = get_devices(&app, &coords_tok, "").await;
    assert_eq!(status, 200, "{self_page}");
    assert_tier_rows(
        self_page["items"].as_array().unwrap(),
        "GET /agent/self/devices",
    );

    // 5. GET /api/account/devices
    let acct_list: Value = app
        .auth_get("/api/account/devices?page=1&per_page=25", admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_tier_rows(
        acct_list["items"].as_array().unwrap(),
        "GET /account/devices",
    );

    // 6. Temporary caller MUST NOT receive MMDB coords or geo_level even from a coords IP.
    let guest_ws = connect_from(&app, &guest_tok, &[], Some("192.0.2.10")).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (status, guest_page) = get_devices(&app, &guest_tok, "").await;
    assert_eq!(status, 200, "{guest_page}");
    let g_row = item(&guest_page, &guest_id);
    for key in [
        "public_ip",
        "country_code",
        "country",
        "region",
        "city",
        "lat",
        "lon",
        "accuracy_radius_km",
        "geo_level",
    ] {
        assert!(
            g_row.get(key).is_none(),
            "temporary caller must not receive {key}: {g_row}"
        );
    }

    drop(guest_ws);
    drop(coords_ws);
}
