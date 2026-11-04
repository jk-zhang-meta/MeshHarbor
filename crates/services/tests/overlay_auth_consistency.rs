// SPDX-License-Identifier: AGPL-3.0-only
//! B3 MongoDB integration tests: control-plane multi-instance authority
//! revision monotonicity (`OverlayNetwork.auth_revision`) and node-level
//! CAS acknowledgement watermarks (`OverlayNodeDao::record_applied_auth_revision`).

use bson::oid::ObjectId;
use mongodb::Client;
use meshharbor_remote_control::models::{NodeRef, OverlayAclMode, PeerRelayMode};
use meshharbor_services::dao::{
    overlay_network::OverlayNetworkDao,
    overlay_node::{NewOverlayNode, OverlayNodeDao},
};

async fn test_db(name: &str) -> mongodb::Database {
    let uri = std::env::var("ROOMLER_TEST_MONGO_URL")
        .or_else(|_| std::env::var("MESHHARBOR_KEY_FENCE_MONGO"))
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27017".to_string());
    let client = Client::with_uri_str(&uri).await.unwrap();
    let db_name = format!("mh_b3_{}_{}", name, ObjectId::new().to_hex());
    let db = client.database(&db_name);
    db.drop().await.unwrap();
    db
}

#[tokio::test]
async fn b3_overlay_network_auth_revision_monotonic_across_authority_mutations() {
    let db = test_db("net_rev").await;
    let networks = OverlayNetworkDao::new(&db);
    let tenant_id = ObjectId::new();

    let net = networks.get_or_create(tenant_id).await.unwrap();
    assert_eq!(
        net.auth_revision, 1,
        "freshly created network starts at auth_revision=1"
    );
    assert_eq!(networks.current_auth_revision(tenant_id).await.unwrap(), 1);

    networks
        .set_acl_mode(tenant_id, OverlayAclMode::Enforce)
        .await
        .unwrap();
    assert_eq!(
        networks.current_auth_revision(tenant_id).await.unwrap(),
        2,
        "set_acl_mode must atomically increment auth_revision"
    );

    networks
        .set_peer_relay_mode(tenant_id, PeerRelayMode::On)
        .await
        .unwrap();
    assert_eq!(
        networks.current_auth_revision(tenant_id).await.unwrap(),
        3,
        "set_peer_relay_mode must atomically increment auth_revision"
    );

    let srv_a = ObjectId::new();
    let srv_b = ObjectId::new();
    networks
        .set_server_link(tenant_id, srv_a, srv_b, Some(true))
        .await
        .unwrap();
    assert_eq!(
        networks.current_auth_revision(tenant_id).await.unwrap(),
        4,
        "set_server_link must atomically increment auth_revision"
    );

    let bumped = networks.bump_auth_revision(tenant_id).await.unwrap();
    assert_eq!(bumped, 5);
    assert_eq!(networks.current_auth_revision(tenant_id).await.unwrap(), 5);

    // Simulate a legacy pre-B3 document where `auth_revision` is 0 / missing in MongoDB:
    // `get_or_create` must backfill it to 1 so the very first mutation advances 1 -> 2.
    let legacy_tid = ObjectId::new();
    let _ = networks.get_or_create(legacy_tid).await.unwrap();
    networks
        .base
        .collection()
        .update_one(
            bson::doc! { "tenant_id": legacy_tid },
            bson::doc! { "$unset": { "auth_revision": "" } },
        )
        .await
        .unwrap();
    let backfilled = networks.get_or_create(legacy_tid).await.unwrap();
    assert_eq!(backfilled.auth_revision, 1);
    networks
        .set_acl_mode(legacy_tid, OverlayAclMode::Enforce)
        .await
        .unwrap();
    assert_eq!(
        networks.current_auth_revision(legacy_tid).await.unwrap(),
        2,
        "first mutation on a legacy network must advance auth_revision from 1 to 2"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn b3_overlay_node_record_applied_auth_revision_is_cas_monotonic() {
    let db = test_db("node_ack").await;
    let nodes = OverlayNodeDao::new(&db);
    let tenant_id = ObjectId::new();
    let network_id = ObjectId::new();

    let created = nodes
        .create(NewOverlayNode {
            tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id,
            machine_id: "m-b3".into(),
            name: "node-b3".into(),
            overlay_ip: "100.64.0.10".into(),
            wg_public_key: "cHVia2V5".into(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: true,
            supports_relay_single: true,
            supports_derp: true,
            supports_forced_derp: true,
            supports_server_relay_strategy: true,
            supports_derp_floor: true,
            supports_overlay_echo: true,
            supports_org_relay: true,
            advertised_routes: vec![],
            route_offer_withheld: None,
        })
        .await
        .unwrap();
    let node_id = created.id.unwrap();
    assert_eq!(created.applied_auth_revision, 0);
    assert_eq!(created.applied_netmap_epoch, 0);
    assert!(created.applied_auth_at.is_none());

    // First ack (epoch=100, auth_revision=2) advances both fields.
    assert!(
        nodes
            .record_applied_auth_revision(node_id, 100, 2)
            .await
            .unwrap()
    );
    let row = nodes.base.find_by_id(node_id).await.unwrap();
    assert_eq!(row.applied_auth_revision, 2);
    assert_eq!(row.applied_netmap_epoch, 100);
    assert!(row.applied_auth_at.is_some());

    // Stale auth_revision (epoch=500, auth_revision=1) is rejected by CAS.
    assert!(
        !nodes
            .record_applied_auth_revision(node_id, 500, 1)
            .await
            .unwrap()
    );
    let row = nodes.base.find_by_id(node_id).await.unwrap();
    assert_eq!(row.applied_auth_revision, 2);
    assert_eq!(row.applied_netmap_epoch, 100);

    // Stale epoch within the same auth_revision (epoch=90, auth_revision=2) is rejected.
    assert!(
        !nodes
            .record_applied_auth_revision(node_id, 90, 2)
            .await
            .unwrap()
    );

    // Newer epoch within the same auth_revision (epoch=150, auth_revision=2) advances.
    assert!(
        nodes
            .record_applied_auth_revision(node_id, 150, 2)
            .await
            .unwrap()
    );
    let row = nodes.base.find_by_id(node_id).await.unwrap();
    assert_eq!(row.applied_auth_revision, 2);
    assert_eq!(row.applied_netmap_epoch, 150);

    // Strictly newer auth_revision (epoch=120, auth_revision=3) advances even with lower epoch.
    assert!(
        nodes
            .record_applied_auth_revision(node_id, 120, 3)
            .await
            .unwrap()
    );
    let row = nodes.base.find_by_id(node_id).await.unwrap();
    assert_eq!(row.applied_auth_revision, 3);
    assert_eq!(row.applied_netmap_epoch, 120);

    db.drop().await.unwrap();
}
