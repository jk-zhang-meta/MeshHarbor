//! Real standalone Mongo admission regressions. No mock database or transactions.
use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::{NodeRef, OverlayNode};
use meshharbor_services::dao::overlay_node::{NewOverlayNode, OverlayNodeDao};
use mongodb::{Client, Database};

async fn fixture() -> (Database, OverlayNodeDao, OverlayNode) {
    let uri =
        std::env::var("MESHHARBOR_KEY_FENCE_MONGO").expect("explicit owned Mongo fixture required");
    let client = Client::with_uri_str(uri).await.unwrap();
    let db = client.database(&format!("b4_key_fence_{}", ObjectId::new().to_hex()));
    let dao = OverlayNodeDao::new(&db);
    let node = dao
        .create(NewOverlayNode {
            tenant_id: ObjectId::new(),
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: ObjectId::new(),
            machine_id: "owned-machine".into(),
            name: "node".into(),
            overlay_ip: "100.64.0.1".into(),
            wg_public_key: "old-key".into(),
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
    (db, dao, node)
}

async fn join(
    dao: &OverlayNodeDao,
    node: &OverlayNode,
    key: &str,
    epoch: u32,
) -> meshharbor_services::dao::base::DaoResult<OverlayNode> {
    dao.rehydrate(
        node.id.unwrap(),
        &node.node_ref,
        "node",
        key,
        epoch,
        &[],
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        &[],
        None,
    )
    .await
}

#[tokio::test]
async fn persisted_rotation_refuses_old_config_after_dao_restart() {
    let (db, dao, node) = fixture().await;
    join(&dao, &node, "new-key", 1).await.unwrap();
    drop(dao);
    let restarted = OverlayNodeDao::new(&db);
    assert!(
        join(&restarted, &node, "old-key", 0).await.is_err(),
        "a persisted new identity must not admit the old config after restart"
    );
    assert_eq!(
        restarted
            .base
            .find_by_id(node.id.unwrap())
            .await
            .unwrap()
            .wg_public_key,
        "new-key"
    );
    assert!(
        !restarted
            .accepts_current_key(node.id.unwrap(), "old-key", 0)
            .await
            .unwrap()
    );
    assert!(
        restarted
            .accepts_current_key(node.id.unwrap(), "new-key", 1)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn current_reconnect_is_idempotent_and_retired_key_cannot_aba_at_a_higher_epoch() {
    let (db, dao, node) = fixture().await;
    join(&dao, &node, "old-key", 0).await.unwrap();
    join(&dao, &node, "new-key", 1).await.unwrap();
    join(&dao, &node, "new-key", 1).await.unwrap();
    let reread = OverlayNodeDao::new(&db);
    assert!(join(&reread, &node, "old-key", 2).await.is_err());
    assert!(join(&reread, &node, "new-key", 0).await.is_err());
    assert!(join(&reread, &node, "other-key", 1).await.is_err());
    join(&reread, &node, "third-key", 2).await.unwrap();
    assert!(join(&reread, &node, "new-key", 3).await.is_err());
    assert!(
        reread
            .accepts_current_key(node.id.unwrap(), "third-key", 2)
            .await
            .unwrap()
    );
    assert!(
        !reread
            .accepts_current_key(node.id.unwrap(), "third-key", 1)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn concurrent_distinct_keys_cannot_both_win_the_same_generation() {
    let (_db, dao, node) = fixture().await;
    let (a, b) = tokio::join!(join(&dao, &node, "a-key", 1), join(&dao, &node, "b-key", 1));
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "one atomic identity winner per generation"
    );
    let winner = if a.is_ok() { "a-key" } else { "b-key" };
    let loser = if a.is_ok() { "b-key" } else { "a-key" };
    assert!(
        dao.accepts_current_key(node.id.unwrap(), winner, 1)
            .await
            .unwrap()
    );
    assert!(
        !dao.accepts_current_key(node.id.unwrap(), loser, 1)
            .await
            .unwrap()
    );
    assert!(join(&dao, &node, "old-key", 2).await.is_err());
}

#[tokio::test]
async fn tombstone_is_never_reanimated_by_a_stale_join() {
    let (_db, dao, node) = fixture().await;
    dao.release(node.id.unwrap()).await.unwrap().unwrap();
    assert!(join(&dao, &node, "new-key", 1).await.is_err());
    assert!(
        dao.base
            .find_by_id(node.id.unwrap())
            .await
            .unwrap()
            .deleted_at
            .is_some()
    );
    assert!(
        !dao.accepts_current_key(node.id.unwrap(), "old-key", 0)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn failed_atomic_rotation_does_not_retire_the_still_current_key() {
    let (db, dao, node) = fixture().await;
    db.run_command(doc! { "collMod": OverlayNode::COLLECTION,
    "validator": { "wg_public_key": { "$ne": "write-rejected-key" } },
    "validationLevel": "strict", "validationAction": "error" })
        .await
        .unwrap();
    assert!(join(&dao, &node, "write-rejected-key", 1).await.is_err());
    let reread = OverlayNodeDao::new(&db);
    assert!(
        reread
            .accepts_current_key(node.id.unwrap(), "old-key", 0)
            .await
            .unwrap()
    );
    join(&reread, &node, "old-key", 0).await.unwrap();
    join(&reread, &node, "good-key", 1).await.unwrap();
    assert!(join(&reread, &node, "old-key", 2).await.is_err());
}

#[tokio::test]
async fn a_legacy_row_missing_epoch_is_a_zero_baseline_not_an_unknown_history_guess() {
    let (_db, dao, node) = fixture().await;
    dao.base
        .collection()
        .update_one(
            doc! { "_id": node.id.unwrap() },
            doc! { "$unset": { "key_epoch": "" } },
        )
        .await
        .unwrap();
    assert!(
        dao.accepts_current_key(node.id.unwrap(), "old-key", 0)
            .await
            .unwrap()
    );
    join(&dao, &node, "old-key", 0).await.unwrap();
    join(&dao, &node, "new-key", 1).await.unwrap();
    assert!(join(&dao, &node, "old-key", 2).await.is_err());
}

#[tokio::test]
async fn known_gap_retired_key_reuse_by_new_row_is_not_yet_fenced() {
    let (_db, dao, node) = fixture().await;
    join(&dao, &node, "new-key", 1).await.unwrap();
    dao.release(node.id.unwrap()).await.unwrap().unwrap();
    let reused = dao
        .create(NewOverlayNode {
            tenant_id: node.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: node.network_id,
            machine_id: "another-machine".into(),
            name: "replacement".into(),
            overlay_ip: "100.64.0.2".into(),
            wg_public_key: "old-key".into(),
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
        .await;
    assert!(
        reused.is_err(),
        "a new row must reject a network's retired key"
    );
    // Also verify the tombstoned node's final active key ("new-key") cannot be claimed by a new row.
    let reused_tombstone_key = dao
        .create(NewOverlayNode {
            tenant_id: node.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: node.network_id,
            machine_id: "third-machine".into(),
            name: "third".into(),
            overlay_ip: "100.64.0.3".into(),
            wg_public_key: "new-key".into(),
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
        .await;
    assert!(
        reused_tombstone_key.is_err(),
        "a new row must also reject a tombstoned node's final key in the same network"
    );

    // CLAUDE.md free-pool invariant: eviction (`release`) forces a new lease,
    // NOT a permanent ban. The SAME `machine_id` ("owned-machine") re-enrolling
    // with its un-revoked active key ("new-key") must succeed and obtain a new
    // overlay lease, whereas reusing its rotated/retired key ("old-key") must
    // still be rejected even for the same `machine_id`.
    let same_machine_retired = dao
        .create(NewOverlayNode {
            tenant_id: node.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: node.network_id,
            machine_id: "owned-machine".into(),
            name: "reenrolled-retired".into(),
            overlay_ip: "100.64.0.4".into(),
            wg_public_key: "old-key".into(),
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
        .await;
    assert!(
        same_machine_retired.is_err(),
        "same machine_id must still be blocked from reusing a key in retired_wg_keys"
    );

    let same_machine_rejoined = dao
        .create(NewOverlayNode {
            tenant_id: node.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: node.network_id,
            machine_id: "owned-machine".into(),
            name: "reenrolled-active".into(),
            overlay_ip: "100.64.0.4".into(),
            wg_public_key: "new-key".into(),
            key_epoch: 1,
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
        .expect("evicted machine_id must be able to re-join with its un-revoked wg_public_key");
    assert_ne!(same_machine_rejoined.id, node.id);
    assert!(
        dao.accepts_current_key(same_machine_rejoined.id.unwrap(), "new-key", 1)
            .await
            .unwrap(),
        "re-enrolled node must pass accepts_current_key despite prior tombstone of same machine_id"
    );
}

#[tokio::test]
async fn b4_key_expiration_refuses_admission_and_same_key_rejoin_without_sliding_ttl() {
    let (_db, dao, node) = fixture().await;
    let node_id = node.id.unwrap();

    // Configure a 120s TTL on the live node.
    let with_ttl = dao.set_key_ttl(node_id, Some(120)).await.unwrap();
    let initial_expiry = with_ttl.key_expires_at.expect("key_expires_at must be set");
    assert_eq!(with_ttl.key_ttl_secs, Some(120));
    assert!(
        dao.accepts_current_key(node_id, "old-key", 0)
            .await
            .unwrap()
    );

    // Reconnecting with the SAME key must NOT slide key_expires_at.
    let reconnected = join(&dao, &node, "old-key", 0).await.unwrap();
    assert_eq!(
        reconnected.key_expires_at,
        Some(initial_expiry),
        "same-key rejoin must not extend or slide key_expires_at"
    );

    // Expire the key in the past.
    let past = bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 5_000);
    dao.set_key_expires_at(node_id, Some(past)).await.unwrap();
    assert!(
        !dao.accepts_current_key(node_id, "old-key", 0)
            .await
            .unwrap(),
        "expired key must be rejected by accepts_current_key"
    );
    assert!(
        join(&dao, &node, "old-key", 0).await.is_err(),
        "expired key must not rehydrate with the same key"
    );
    assert!(
        join(&dao, &node, "old-key", 1).await.is_err(),
        "expired key must not fake-rotate by bumping epoch with the same key"
    );

    // Sweeping due expirations marks reauth_required = true and retires the expired key.
    let swept = dao
        .expire_keys_due(node.network_id, bson::DateTime::now())
        .await
        .unwrap();
    assert_eq!(swept.len(), 1);
    assert!(swept[0].reauth_required);

    // Increasing or clearing key_ttl_secs on an already-expired key must NOT
    // resurrect the expired key; it only stages the TTL for the next rotation.
    let staged_ttl = dao.set_key_ttl(node_id, Some(300)).await.unwrap();
    assert!(staged_ttl.reauth_required);
    assert_eq!(staged_ttl.key_ttl_secs, Some(300));
    assert!(!staged_ttl.is_key_authorized_at(bson::DateTime::now()));
    assert!(
        !dao.accepts_current_key(node_id, "old-key", 0)
            .await
            .unwrap()
    );

    // Rotating to a fresh key at epoch 1 clears reauth_required and mints a fresh expiry window.
    let rotated = join(&dao, &node, "rotated-after-expiry", 1).await.unwrap();
    assert!(!rotated.reauth_required);
    assert!(rotated.key_revoked_at.is_none());
    assert_eq!(
        rotated
            .retired_wg_keys
            .iter()
            .filter(|r| r.public_key == "old-key")
            .count(),
        1,
        "retired_wg_keys must not contain duplicate entries for old-key"
    );
    assert!(
        rotated
            .key_expires_at
            .expect("fresh expiry")
            .timestamp_millis()
            > initial_expiry.timestamp_millis()
    );
    assert!(
        dao.accepts_current_key(node_id, "rotated-after-expiry", 1)
            .await
            .unwrap()
    );
    assert!(
        !dao.accepts_current_key(node_id, "old-key", 0)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn b4_immediate_key_revocation_fences_current_key_and_requires_fresh_rotation() {
    let (_db, dao, node) = fixture().await;
    let node_id = node.id.unwrap();

    let peer_node = dao
        .create(NewOverlayNode {
            tenant_id: node.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: node.network_id,
            machine_id: "peer-machine".into(),
            name: "peer".into(),
            overlay_ip: "100.64.0.2".into(),
            wg_public_key: "peer-initial-key".into(),
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

    let revoked = dao
        .revoke_current_key(node_id, "admin_revoke")
        .await
        .unwrap();
    assert!(revoked.reauth_required);
    assert!(revoked.key_revoked_at.is_some());
    assert!(
        !revoked.is_key_authorized_at(bson::DateTime::now()),
        "revoked node must not be authorized"
    );
    assert!(
        !dao.accepts_current_key(node_id, "old-key", 0)
            .await
            .unwrap(),
        "revoked key must be rejected immediately"
    );
    assert!(join(&dao, &node, "old-key", 0).await.is_err());
    assert!(join(&dao, &node, "old-key", 1).await.is_err());
    assert!(
        join(&dao, &peer_node, "old-key", 1).await.is_err(),
        "another live node in the same network must not claim a revoked/retired key"
    );

    // Rotating to a brand-new key at epoch 1 restores admission.
    let recovered = join(&dao, &node, "fresh-post-revoke-key", 1).await.unwrap();
    assert!(!recovered.reauth_required);
    assert!(recovered.key_revoked_at.is_none());
    assert!(recovered.is_key_authorized_at(bson::DateTime::now()));
    assert!(
        dao.accepts_current_key(node_id, "fresh-post-revoke-key", 1)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn b4_retired_wg_keys_bounded_slice_and_default_ttl_floor_and_pre_expiry_window() {
    use meshharbor_services::dao::overlay_node::{
        MAX_RETIRED_WG_KEYS, MIN_KEY_TTL_SECS, clamp_default_key_ttl_secs,
    };

    // 1. Default TTL env helper enforces MIN_KEY_TTL_SECS = 60.
    assert_eq!(clamp_default_key_ttl_secs(0), None);
    assert_eq!(clamp_default_key_ttl_secs(1), Some(MIN_KEY_TTL_SECS));
    assert_eq!(clamp_default_key_ttl_secs(59), Some(MIN_KEY_TTL_SECS));
    assert_eq!(clamp_default_key_ttl_secs(60), Some(60));
    assert_eq!(clamp_default_key_ttl_secs(3600), Some(3600));

    let (_db, dao, node) = fixture().await;
    let node_id = node.id.unwrap();

    // 2. Rotating more than MAX_RETIRED_WG_KEYS (64) times keeps retired_wg_keys bounded at 64.
    let total_rotations = (MAX_RETIRED_WG_KEYS as u32) + 10;
    let mut latest = node.clone();
    for epoch in 1..=total_rotations {
        let key = format!("rot-key-{epoch}");
        latest = join(&dao, &node, &key, epoch).await.unwrap();
    }
    assert_eq!(
        latest.retired_wg_keys.len(),
        MAX_RETIRED_WG_KEYS,
        "retired_wg_keys must be bounded by MAX_RETIRED_WG_KEYS ($slice: -64)"
    );
    assert_eq!(
        latest.retired_wg_keys.last().unwrap().public_key,
        format!("rot-key-{}", total_rotations - 1)
    );

    // 3. Pre-expiry lead window (`list_keys_expiring_soon`):
    // Configure 60s TTL (lead window = 15s). Initially (~60s remaining), not yet due for pre-rotation.
    let with_ttl = dao.set_key_ttl(node_id, Some(60)).await.unwrap();
    let now = bson::DateTime::now();
    assert!(!with_ttl.should_pre_rotate_key_at(now));
    assert!(
        dao.list_keys_expiring_soon(node.network_id, now)
            .await
            .unwrap()
            .is_empty()
    );

    // Move key_expires_at to now + 10s (inside the 15s pre-expiry lead window, still authorized).
    let soon = bson::DateTime::from_millis(now.timestamp_millis() + 10_000);
    let updated = dao.set_key_expires_at(node_id, Some(soon)).await.unwrap();
    assert!(updated.is_key_authorized_at(now));
    assert!(updated.should_pre_rotate_key_at(now));
    let expiring_soon = dao
        .list_keys_expiring_soon(node.network_id, now)
        .await
        .unwrap();
    assert_eq!(expiring_soon.len(), 1);
    assert_eq!(expiring_soon[0].id, Some(node_id));
    assert!(
        dao.expire_keys_due(node.network_id, now)
            .await
            .unwrap()
            .is_empty(),
        "node in pre-expiry lead window must not be hard-expired before key_expires_at"
    );

    // 4. `find_same_machine_rejected_key_node` identifies same-machine tombstones with expired TTL
    //    while returning `None` when a different machine presents that key.
    let past = bson::DateTime::from_millis(now.timestamp_millis() - 5_000);
    dao.set_key_expires_at(node_id, Some(past)).await.unwrap();
    let _ = dao.release(node_id).await.unwrap();
    assert!(
        dao.wg_key_taken_by_other(node.network_id, &latest.wg_public_key, &node.machine_id)
            .await
            .unwrap(),
        "expired key on tombstone is rejected by wg_key_taken_by_other"
    );
    let same_match = dao
        .find_same_machine_rejected_key_node(
            node.network_id,
            &node.machine_id,
            &latest.wg_public_key,
        )
        .await
        .unwrap();
    assert!(
        same_match.is_some(),
        "same machine_id must match its own expired tombstone for auto-rotation recovery"
    );
    let other_match = dao
        .find_same_machine_rejected_key_node(
            node.network_id,
            "different-machine-id",
            &latest.wg_public_key,
        )
        .await
        .unwrap();
    assert!(
        other_match.is_none(),
        "another machine_id must never match a foreign machine's tombstone"
    );
}
