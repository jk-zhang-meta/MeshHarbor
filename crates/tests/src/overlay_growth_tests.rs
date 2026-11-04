// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-47 P5c/P5d — an org that outgrows its block, end to end over a real
//! agent WebSocket.
//!
//! The DAO-level growth test (`overlay_tests`) proves the allocator appends a
//! block and moves no ordinal. It does NOT exercise the half that actually
//! reaches a device: the netmap. P5d makes `OverlayNetworkInfo.cidr`
//! **per-recipient** — the block containing *that node's own* address — because
//! a fielded agent derives its TUN netmask and its subnet-router NAT scope from
//! that one string, and block 0 is wrong for a node addressed in block 1. A
//! mistake there mis-sizes the netmask fleet-wide, which is why it is worth a
//! real join rather than a decoder test.
//!
//! **The faking, stated plainly.** Standing up 1 022 devices through 1 022
//! WebSocket joins would take minutes and prove nothing the allocator's own
//! tests do not. So the *scale* is faked — the IPAM cursor is advanced to the
//! block ceiling — while everything that matters is real: real node rows at
//! both ends of block 0, a real enrolled agent, a real `rc:overlay.join`, and
//! the real netmap the server sends back. What is being tested is the boundary
//! crossing, and the boundary crossing is not faked.

use crate::agent_presence_tests::enroll;
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::{doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::models::{OverlayNetwork, overlay_host};
use meshharbor_services::dao::overlay_network::OverlayNetworkDao;
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

async fn connect(app: &TestApp, token: &str) -> Ws {
    let ws_url = format!("ws://{}/ws?token={}&role=agent", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connect");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "growth box",
        "os": "linux",
        "agent_version": "0.4.41",
        "displays": [],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"],
            "has_input_permission": false, "supports_clipboard": false,
            "supports_file_transfer": false, "max_simultaneous_sessions": 1,
            "rpc": [],
        }
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

async fn recv_t(ws: &mut Ws, want: &str, wait: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(Message::Text(txt)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&txt)
                    && v["t"] == want
                {
                    return Some(v);
                }
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) | Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

/// A real `rc:overlay.join`, returning the netmap the server answers with.
async fn join(ws: &mut Ws, seed: u8) -> Value {
    let msg = json!({
        "t": "rc:overlay.join",
        "wg_public_key": BASE64.encode([seed; 32]),
        "mtu": 1280,
        "endpoints": ["203.0.113.9:51820"],
    });
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .expect("send join");
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(10))
        .await
        .expect("a netmap answers the join")
}

/// Drive the tenant's IPAM cursor to `next`, faking the devices between.
async fn set_cursor(app: &TestApp, network_id: ObjectId, next: u32) {
    OverlayNetworkDao::new(&app.db)
        .base
        .update_one(
            doc! { "_id": network_id },
            doc! { "$set": { "next_host": next as i64 } },
        )
        .await
        .unwrap();
}

/// FR-47 — the 1 023rd device in an org lands in a SECOND block, is told that
/// block as its own `cidr`, and costs the first 1 022 nothing.
#[tokio::test]
async fn a_device_past_the_block_ceiling_joins_into_an_appended_block() {
    let app = TestApp::spawn_with_settings(|s| {
        s.overlay.blocks_enabled = true;
        s.overlay.block_prefix = 22;
        s.overlay.multi_block_enabled = true;
    })
    .await;
    let seeded: SeededTenant = app.seed_tenant("ovgrow-e2e").await;
    let dao = OverlayNetworkDao::new(&app.db);
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();

    // The network is deliberately NOT pre-created here: the SERVER creates and
    // carves it on the first join, using its own DAO with the deployment's
    // block prefix. A test-owned `OverlayNetworkDao::new` has no prefix and
    // would create the network on the legacy /10 before the server ever saw
    // it — which is exactly what the precondition below caught the first time.
    let (first_agent, first_token) = enroll(&app, &seeded, "growth-first").await;
    let mut ws1 = connect(&app, &first_token).await;
    let nm1 = join(&mut ws1, 1).await;
    let first_ip = nm1["self_ip"].as_str().unwrap().to_string();

    let net = dao.get_or_create(tid).await.unwrap();
    let network_id = net.id.unwrap();
    let block0 = net.cidr.clone();
    assert_ne!(
        block0,
        OverlayNetwork::DEFAULT_CIDR,
        "the org must be carved for this test to mean anything"
    );
    assert_eq!(
        nm1["network"]["cidr"].as_str(),
        Some(block0.as_str()),
        "a node in the only block is told that block"
    );
    assert_eq!(
        nm1["network"]["cidrs"],
        json!([block0]),
        "an un-grown org publishes a one-element space equal to its cidr"
    );
    assert_eq!(
        overlay_host(&block0, &first_ip),
        Some(1),
        "the first device takes ordinal 1"
    );

    // Fake the other 1 021 devices: jump the cursor to the block ceiling, so
    // the NEXT allocation is the one that must grow.
    set_cursor(&app, network_id, 1023).await;

    // A REAL device crossing the boundary.
    let (_second_agent, second_token) = enroll(&app, &seeded, "growth-crosser").await;
    let mut ws2 = connect(&app, &second_token).await;
    let nm2 = join(&mut ws2, 2).await;
    let crosser_ip = nm2["self_ip"].as_str().unwrap().to_string();

    // The org grew.
    let grown = dao.base.find_by_id(network_id).await.unwrap();
    let blocks = dao.block_list(&grown).await;
    assert_eq!(
        blocks.cidrs().len(),
        2,
        "the boundary join must APPEND a block, not be refused"
    );
    assert_eq!(blocks.cidrs()[0], block0, "the first block did not move");
    let block1 = blocks.cidrs()[1].clone();
    assert_ne!(block1, block0);

    // P5d — the crosser is told ITS OWN block, not the org's first one. This
    // is the assertion the whole phase exists for: an agent sizes its TUN
    // netmask and its NAT scope from this string.
    assert_eq!(
        nm2["network"]["cidr"].as_str(),
        Some(block1.as_str()),
        "a node addressed in block 1 must be told block 1, or its netmask is wrong"
    );
    assert_eq!(
        nm2["network"]["cidrs"],
        json!([block0, block1]),
        "and the full space, in allocation order"
    );
    assert!(
        overlay_host(&block1, &crosser_ip).is_some(),
        "{crosser_ip} must fall inside the appended block {block1}"
    );
    assert!(
        overlay_host(&block0, &crosser_ip).is_none(),
        "{crosser_ip} must NOT fall inside the first block"
    );

    // FR-68 — the P5d compatibility claim, against a netmap the SERVER actually
    // produced rather than one a test hand-built. `PinnedNetworkInfo` is copied
    // verbatim from `agent-v0.4.42`, the last release before P5d: no `cidrs`, no
    // `deny_unknown_fields`. ⚠️ Do not add fields to it — it is frozen on
    // purpose, and its whole value is being the decoder a fielded agent has.
    #[derive(serde::Deserialize)]
    struct PinnedNetworkInfo {
        cidr: String,
        #[allow(dead_code)]
        mtu: u16,
    }
    let pinned: PinnedNetworkInfo = serde_json::from_value(nm2["network"].clone()).expect(
        "a pre-P5d agent must decode the netmap a grown org sends it; if this \
         fails, every agent below 0.4.43 is stranded the moment an org grows",
    );

    // The netmask that agent derives is computed HERE, the way the agent does
    // it (`prefix_of_cidr` -> `netmask_for_prefix`), and must put the crosser
    // on-link while excluding block 0. This is the property that makes growth
    // safe for the installed base; nothing else in the suite checks it.
    let (base, plen) = pinned.cidr.split_once('/').expect("cidr has a prefix");
    let base: std::net::Ipv4Addr = base.parse().expect("cidr base parses");
    let plen: u32 = plen.parse().expect("cidr prefix parses");
    let mask = u32::MAX << (32 - plen);
    let on_link = |ip: &str| {
        let ip: std::net::Ipv4Addr = ip.parse().expect("ip parses");
        u32::from(ip) & mask == u32::from(base) & mask
    };
    assert!(
        on_link(&crosser_ip),
        "a pre-P5d agent at {crosser_ip} would size its TUN from {}, which must \
         contain its own address",
        pinned.cidr
    );
    assert!(
        !on_link(&first_ip),
        "block 0's device ({first_ip}) must NOT be on-link for the block-1 node \
         — it is reached by its per-peer /32, and an on-link claim here would \
         mean the old agent black-holes it"
    );

    // The point of growth: the first device did not move.
    let still = app
        .db
        .collection::<bson::Document>("overlay_nodes")
        .find_one(doc! { "_id": first_agent_node_id(&app, &first_agent).await })
        .await
        .unwrap()
        .expect("the first node still exists");
    assert_eq!(
        still.get_str("overlay_ip").unwrap(),
        first_ip,
        "growth must not move an existing device's address"
    );

    // And a rejoin still reports block 0 to the node that lives there — the
    // per-recipient value is per NODE, not per netmap generation.
    let nm1b = join(&mut ws1, 1).await;
    assert_eq!(nm1b["self_ip"].as_str(), Some(first_ip.as_str()));
    assert_eq!(nm1b["network"]["cidr"].as_str(), Some(block0.as_str()));
    assert_eq!(nm1b["network"]["cidrs"], json!([block0, block1]));
}

/// The overlay node row id backing an agent.
async fn first_agent_node_id(app: &TestApp, agent_id: &str) -> ObjectId {
    let aid = ObjectId::parse_str(agent_id).unwrap();
    app.db
        .collection::<bson::Document>("overlay_nodes")
        .find_one(doc! { "node_ref.id": aid, "deleted_at": null })
        .await
        .unwrap()
        .expect("the agent has an overlay node")
        .get_object_id("_id")
        .unwrap()
}
