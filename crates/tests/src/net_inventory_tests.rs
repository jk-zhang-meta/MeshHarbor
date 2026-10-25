// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor #19 (v039 OBS-02): the read-only network inventory an agent
//! reports over its authenticated socket (`rc:agent.net_inventory`). The row
//! is the socket's agent, never the frame's; a replay, a stale or retired
//! boot, a snapshot that fails validation and an incomplete page set are all
//! dropped; reading needs `MANAGE_AGENTS` in that tenant; freshness is the
//! server's clock.

use crate::agent_presence_tests::enroll;
use crate::fixtures::test_app::TestApp;
use crate::peer_relay_mint_tests::{Ws, connect_from};
use futures::SinkExt;
use roomler_ai_remote_control::net_inventory::{Family, NetInventory, Route, Section};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

fn inventory(routes: usize) -> NetInventory {
    NetInventory {
        os: "linux".into(),
        namespaces: "host_only".into(),
        routes: Section::capped(
            (0..routes)
                .map(|i| Route {
                    family: Family::V4,
                    table: "main".into(),
                    dst: format!("10.{i}.0.0/16"),
                    kind: "unicast".into(),
                    gateway: None,
                    dev: Some("eth0".into()),
                    protocol: None,
                    metric: None,
                })
                .collect(),
            4096,
        ),
        ..Default::default()
    }
}

async fn send(ws: &mut Ws, boot: &str, seq: u64, page: u16, pages: u16, inv: &NetInventory) {
    let frame = json!({
        "t": "rc:agent.net_inventory",
        "boot_id": boot,
        "seq": seq,
        "page": page,
        "pages": pages,
        "observed_at_ms": 1_700_000_000_000i64,
        "inventory": inv,
    });
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .expect("send inventory");
}

async fn get(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let r = app.auth_get(path, token).send().await.unwrap();
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
}

/// The routes total stored for `agent`, waiting up to 3 s for `want`.
async fn routes_total(
    app: &TestApp,
    tid: &str,
    token: &str,
    agent: &str,
    want: Option<u64>,
) -> Option<u64> {
    let path = format!("/api/tenant/{tid}/net-inventory/{agent}");
    let mut last = None;
    for _ in 0..30 {
        let (s, v) = get(app, &path, token).await;
        last = (s == 200).then(|| v["routes"]["total"].as_u64().unwrap());
        if last == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    last
}

/// Long enough for a frame that should NOT land to have landed.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

#[tokio::test]
async fn a_reported_inventory_is_stored_against_the_socket_identity() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("inv-id").await;
    let (a, a_tok) = enroll(&app, &seeded, "inv-id-a").await;
    let (b, _) = enroll(&app, &seeded, "inv-id-b").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(&mut ws, "boot-a", 1, 0, 1, &inventory(3)).await;
    let tok = &seeded.admin.access_token;
    let tid = &seeded.tenant_id;
    assert_eq!(routes_total(&app, tid, tok, &a, Some(3)).await, Some(3));

    let (s, list) = get(&app, &format!("/api/tenant/{tid}/net-inventory"), tok).await;
    assert_eq!(s, 200);
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only the reporting agent: {list}");
    assert_eq!(items[0]["agent_id"], json!(a));
    assert_eq!(items[0]["fresh"], json!(true));
    assert_eq!(items[0]["routes"]["state"], json!("complete"));
    assert_eq!(items[0]["namespaces"], json!("host_only"));

    let (s, detail) = get(&app, &format!("/api/tenant/{tid}/net-inventory/{a}"), tok).await;
    assert_eq!(s, 200);
    assert_eq!(
        detail["inventory"]["routes"]["items"][2]["dst"],
        json!("10.2.0.0/16")
    );
    let (s, _) = get(&app, &format!("/api/tenant/{tid}/net-inventory/{b}"), tok).await;
    assert_eq!(
        s, 404,
        "agent b reported nothing; a's socket cannot speak for it"
    );
}

#[tokio::test]
async fn replays_stale_boots_and_bad_snapshots_are_dropped() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("inv-order").await;
    let (a, a_tok) = enroll(&app, &seeded, "inv-order-a").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);

    send(&mut ws, "boot-1", 2, 0, 1, &inventory(3)).await;
    assert_eq!(routes_total(&app, tid, tok, &a, Some(3)).await, Some(3));

    // The same seq again, and an older one: a replay and a stale frame.
    send(&mut ws, "boot-1", 2, 0, 1, &inventory(4)).await;
    send(&mut ws, "boot-1", 1, 0, 1, &inventory(5)).await;
    settle().await;
    assert_eq!(routes_total(&app, tid, tok, &a, Some(3)).await, Some(3));

    // A new process starts over at seq 1.
    send(&mut ws, "boot-2", 1, 0, 1, &inventory(6)).await;
    assert_eq!(routes_total(&app, tid, tok, &a, Some(6)).await, Some(6));

    // A late frame from the retired boot, whatever its seq.
    send(&mut ws, "boot-1", 99, 0, 1, &inventory(7)).await;
    settle().await;
    assert_eq!(routes_total(&app, tid, tok, &a, Some(6)).await, Some(6));

    // A truncated section that still claims `complete`.
    let mut bad = inventory(8);
    bad.routes.items.pop();
    send(&mut ws, "boot-2", 2, 0, 1, &bad).await;
    // Half a page set.
    let pages = inventory(9).split(5);
    assert_eq!(pages.len(), 2);
    send(&mut ws, "boot-2", 3, 0, 2, &pages[0]).await;
    // A frame naming an oversized page count.
    send(&mut ws, "boot-2", 4, 0, 99, &inventory(10)).await;
    settle().await;
    assert_eq!(routes_total(&app, tid, tok, &a, Some(6)).await, Some(6));

    // The full page set lands as one snapshot.
    let pages = inventory(11).split(5);
    let n = pages.len() as u16;
    for (i, p) in pages.iter().enumerate().rev() {
        send(&mut ws, "boot-2", 5, i as u16, n, p).await;
    }
    assert_eq!(routes_total(&app, tid, tok, &a, Some(11)).await, Some(11));
    let (_, detail) = get(&app, &format!("/api/tenant/{tid}/net-inventory/{a}"), tok).await;
    assert_eq!(
        detail["inventory"]["routes"]["items"]
            .as_array()
            .unwrap()
            .len(),
        11
    );
}

#[tokio::test]
async fn viewing_needs_manage_agents_in_that_tenant() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("inv-perm").await;
    let other = app.seed_tenant("inv-perm-other").await;
    let (a, a_tok) = enroll(&app, &seeded, "inv-perm-a").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(&mut ws, "boot-1", 1, 0, 1, &inventory(2)).await;
    let tid = &seeded.tenant_id;
    assert_eq!(
        routes_total(&app, tid, &seeded.admin.access_token, &a, Some(2)).await,
        Some(2)
    );

    for (who, tok) in [
        ("a member", &seeded.member.access_token),
        ("another tenant's admin", &other.admin.access_token),
    ] {
        let (s, _) = get(&app, &format!("/api/tenant/{tid}/net-inventory"), tok).await;
        assert_eq!(s, 403, "{who}: list");
        let (s, _) = get(&app, &format!("/api/tenant/{tid}/net-inventory/{a}"), tok).await;
        assert_eq!(s, 403, "{who}: detail");
    }
    // Another tenant's admin, asking through their own tenant, finds nothing.
    let (s, v) = get(
        &app,
        &format!("/api/tenant/{}/net-inventory", other.tenant_id),
        &other.admin.access_token,
    )
    .await;
    assert_eq!((s, v["items"].as_array().map(Vec::len)), (200, Some(0)));
}

#[tokio::test]
async fn freshness_is_the_servers_and_a_heartbeat_does_not_extend_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("inv-fresh").await;
    let (a, a_tok) = enroll(&app, &seeded, "inv-fresh-a").await;
    let mut ws = connect_from(&app, &a_tok, &[], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(&mut ws, "boot-1", 1, 0, 1, &inventory(1)).await;
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    assert_eq!(routes_total(&app, tid, tok, &a, Some(1)).await, Some(1));

    // Age the row past the window, then heartbeat.
    let aid = bson::oid::ObjectId::parse_str(&a).unwrap();
    let old =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 16 * 60 * 1000);
    app.db
        .collection::<bson::Document>("node_net_inventory")
        .update_one(
            bson::doc! { "_id": aid },
            bson::doc! { "$set": { "received_at": old } },
        )
        .await
        .unwrap();
    let hb =
        json!({ "t": "rc:agent.heartbeat", "rss_mb": 0, "cpu_pct": 0.0, "active_sessions": 0 });
    ws.send(Message::Text(hb.to_string().into())).await.unwrap();
    settle().await;
    let (_, v) = get(&app, &format!("/api/tenant/{tid}/net-inventory/{a}"), tok).await;
    assert_eq!(v["fresh"], json!(false), "{v}");
}
