//! MeshHarbor items #18/#21 — `/derp` load-before-serve (2026-11-11).
//!
//! A missing relay table now DROPS the frame. It used to fail open, so after
//! every restart, until the network's next join or policy change, an
//! enforcing tenant's ACL and the cross-zone rule were both off on the DERP
//! tier. What keeps the floor up is that a network's first registration
//! builds its table before the node is served (`derp_acl::ensure_built`).
use crate::fixtures::test_app::TestApp;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::models::NodeRef;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[allow(clippy::too_many_arguments)]
async fn seed_node(
    app: &TestApp,
    tid: ObjectId,
    network_id: ObjectId,
    aid: &str,
    machine_id: &str,
    overlay_ip: &str,
    pk: [u8; 32],
) {
    meshharbor_services::dao::overlay_node::OverlayNodeDao::new(&app.db)
        .create(meshharbor_services::dao::overlay_node::NewOverlayNode {
            tenant_id: tid,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::parse_str(aid).unwrap(),
            },
            network_id,
            machine_id: machine_id.into(),
            name: format!("{machine_id}-node"),
            overlay_ip: overlay_ip.into(),
            wg_public_key: B64.encode(pk),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: true,
            supports_forced_derp: false,
            supports_server_relay_strategy: false,
            supports_derp_floor: false,
            supports_overlay_echo: false,
            supports_org_relay: false,
            advertised_routes: vec![],
            route_offer_withheld: None,
        })
        .await
        .unwrap();
}

async fn register(app: &TestApp, tok: &str, pk: [u8; 32]) -> Ws {
    let (mut ws, _) = connect_async(&format!("ws://{}/derp?token={}", app.addr, tok))
        .await
        .expect("derp WS");
    ws.send(Message::Binary(pk.to_vec().into())).await.unwrap();
    ws
}

/// The next binary frame within `within`, skipping pings and text.
async fn recv_binary(ws: &mut Ws, within: Duration) -> Option<Vec<u8>> {
    tokio::time::timeout(within, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => return Some(b.to_vec()),
                Some(Ok(_)) => continue,
                _ => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for: {what}"));
}

#[tokio::test]
async fn derp_builds_the_table_before_serving_and_a_missing_table_relays_nothing() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("derplbs").await;
    let tid = ObjectId::parse_str(&tenant.tenant_id).unwrap();
    let (aid_a, tok_a) = crate::agent_presence_tests::enroll(&app, &tenant, "lbs-a").await;
    let (aid_b, tok_b) = crate::agent_presence_tests::enroll(&app, &tenant, "lbs-b").await;
    let network_id = meshharbor_services::dao::overlay_network::OverlayNetworkDao::new(&app.db)
        .get_or_create(tid)
        .await
        .unwrap()
        .id
        .unwrap();
    let (pa, pb) = ([0xa1u8; 32], [0xb2u8; 32]);
    seed_node(&app, tid, network_id, &aid_a, "lbs-a", "100.64.0.21", pa).await;
    seed_node(&app, tid, network_id, &aid_b, "lbs-b", "100.64.0.22", pb).await;
    let net = app.state.network();

    // The restart shape: this process has built nothing for the network.
    assert!(
        !net.derp_acl.contains_key(&network_id),
        "precondition: no table built yet"
    );

    let mut ws_a = register(&app, &tok_a, pa).await;
    let mut ws_b = register(&app, &tok_b, pb).await;
    wait_until("both registered", || {
        net.derp_registry.contains_key(&(network_id, pa))
            && net.derp_registry.contains_key(&(network_id, pb))
    })
    .await;
    assert!(
        net.derp_acl.contains_key(&network_id),
        "a registration must build its network's table before it is served"
    );

    // A → B relays, with the src prefix rewritten to A.
    let mut frame = pb.to_vec();
    frame.extend_from_slice(&[4, 0, 0, 0, 9, 9]);
    ws_a.send(Message::Binary(frame.clone().into()))
        .await
        .unwrap();
    let got = recv_binary(&mut ws_b, Duration::from_secs(3))
        .await
        .expect("B receives A's frame on a built network");
    assert_eq!(&got[..32], &pa);
    assert_eq!(&got[32..], &[4, 0, 0, 0, 9, 9]);

    // The table disappears under live nodes: fail CLOSED, nothing relays.
    net.derp_acl.remove(&network_id);
    ws_a.send(Message::Binary(frame.clone().into()))
        .await
        .unwrap();
    assert!(
        recv_binary(&mut ws_b, Duration::from_millis(700))
            .await
            .is_none(),
        "with no table, a frame must be dropped, never forwarded"
    );

    // A reconnect builds it again before serving, and the floor is back.
    ws_a.close(None).await.ok();
    wait_until("A deregistered", || {
        !net.derp_registry.contains_key(&(network_id, pa))
    })
    .await;
    let mut ws_a = register(&app, &tok_a, pa).await;
    wait_until("A re-registered", || {
        net.derp_registry.contains_key(&(network_id, pa))
    })
    .await;
    assert!(
        net.derp_acl.contains_key(&network_id),
        "rebuilt on register"
    );
    ws_a.send(Message::Binary(frame.into())).await.unwrap();
    assert!(
        recv_binary(&mut ws_b, Duration::from_secs(3))
            .await
            .is_some(),
        "relaying resumes once the table is built again"
    );
    ws_a.close(None).await.ok();
    ws_b.close(None).await.ok();
}
