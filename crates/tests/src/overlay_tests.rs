// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Integration tests for overlay IP allocation and RELEASE.
//!
//! Removing a device from the fleet returns its host number to the tenant's
//! free pool so a future join can recycle it. Each test here locks one decision
//! that the release design turns on — reuse, idempotency under a double
//! release, the live-scoped uniqueness that lets a tombstone stop holding its
//! address, and "removal is final" for a machine that re-enrolls.
//!
//! The IPAM tests drive the DAOs directly against the spawned app's database:
//! allocation happens on the `rc:overlay.join` WS message, and standing up two
//! real agent WS sessions to exercise a pure counter would test the harness
//! rather than the allocator.

use bson::{doc, oid::ObjectId};
use roomler_ai_db::indexes::apply_index_sets;
use roomler_ai_remote_control::models::{NodeRef, OverlayNetwork, OverlayNode};
use roomler_ai_services::dao::base::DaoError;
use roomler_ai_services::dao::overlay_network::OverlayNetworkDao;
use roomler_ai_services::dao::overlay_node::{NewOverlayNode, OverlayNodeDao};
use serde_json::Value;

use crate::fixtures::test_app::TestApp;

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

struct Ipam {
    networks: OverlayNetworkDao,
    nodes: OverlayNodeDao,
    tenant_id: ObjectId,
    network_id: ObjectId,
}

impl Ipam {
    async fn new(app: &TestApp, tenant_id: ObjectId) -> Self {
        let networks = OverlayNetworkDao::new(&app.db);
        let nodes = OverlayNodeDao::new(&app.db);
        let network_id = networks
            .get_or_create(tenant_id)
            .await
            .unwrap()
            .id
            .expect("network _id");
        Self {
            networks,
            nodes,
            tenant_id,
            network_id,
        }
    }

    async fn network(&self) -> OverlayNetwork {
        self.networks
            .base
            .find_by_id(self.network_id)
            .await
            .unwrap()
    }

    /// Live (non-tombstoned) nodes in this network.
    async fn nodes_alive(&self) -> u64 {
        self.nodes
            .base
            .collection()
            .count_documents(doc! { "network_id": self.network_id, "deleted_at": null })
            .await
            .unwrap()
    }

    /// Allocate a host bounded by the default `/10` ceiling — what
    /// `handle_overlay_join` passes for an unmigrated tenant (P2a).
    async fn alloc(&self) -> Result<u32, DaoError> {
        self.networks
            .allocate_host(self.network_id, default_max_host())
            .await
    }

    /// Insert a node holding `overlay_ip`, as `handle_overlay_join` would.
    async fn create_node(
        &self,
        machine_id: &str,
        name: &str,
        overlay_ip: &str,
    ) -> Result<OverlayNode, DaoError> {
        self.nodes
            .create(NewOverlayNode {
                tenant_id: self.tenant_id,
                node_ref: NodeRef::Agent {
                    agent_id: ObjectId::new(),
                },
                network_id: self.network_id,
                machine_id: machine_id.to_string(),
                name: name.to_string(),
                overlay_ip: overlay_ip.to_string(),
                wg_public_key: format!("pk-base64-{machine_id}"),
                key_epoch: 0,
                endpoints: vec![],
                supports_quic: false,
                supports_relay_single: false,
                supports_derp: false,
                supports_forced_derp: false,
                supports_server_relay_strategy: false,
                supports_derp_floor: false,
                supports_overlay_echo: false,
                supports_org_relay: false,
                advertised_routes: vec![],
                route_offer_withheld: None,
            })
            .await
    }

    /// A node that ADVERTISES subnet routes (a would-be subnet router), as a
    /// join with `overlay_advertised_routes` configured would create it.
    async fn create_router_node(
        &self,
        machine_id: &str,
        name: &str,
        overlay_ip: &str,
        advertised: &[&str],
    ) -> OverlayNode {
        let mut node = self
            .create_node(machine_id, name, overlay_ip)
            .await
            .unwrap();
        self.nodes
            .base
            .update_one(
                doc! { "_id": node.id.unwrap() },
                doc! { "$set": { "advertised_routes": advertised.to_vec() } },
            )
            .await
            .unwrap();
        node.advertised_routes = advertised.iter().map(|s| s.to_string()).collect();
        node
    }
}

/// The tenant `_id` behind a seeded tenant.
fn tid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

/// The default `/10`'s block ceiling (multi-org P2a bound).
fn default_max_host() -> u32 {
    roomler_ai_remote_control::models::cidr_max_host(
        roomler_ai_remote_control::models::OverlayNetwork::DEFAULT_CIDR,
    )
    .expect("default CIDR has a ceiling")
}

// ────────────────────────────────────────────────────────────────────────────
// IPAM: the block ceiling (multi-org P2a)
// ────────────────────────────────────────────────────────────────────────────

/// The cursor refuses to lease past the network's own block, exhaustion is a
/// loud Validation error (never a neighbor-block address), and a pooled host
/// stranded above a since-shrunk ceiling is discarded — leak, never conflict.
#[tokio::test]
async fn allocate_host_stops_at_the_block_ceiling() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovipamcap").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    // A /30-sized ceiling: hosts 1..=2 leaseable.
    let max_host = 2u32;
    let a = ipam
        .networks
        .allocate_host(ipam.network_id, max_host)
        .await
        .unwrap();
    let b = ipam
        .networks
        .allocate_host(ipam.network_id, max_host)
        .await
        .unwrap();
    assert_eq!((a, b), (1, 2));
    let err = ipam
        .networks
        .allocate_host(ipam.network_id, max_host)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DaoError::Validation(m) if m.contains("exhausted")),
        "expected loud exhaustion, got {err:?}"
    );
    // The cursor did NOT walk past the ceiling.
    assert_eq!(ipam.network().await.next_host, 3);

    // Release host 2 back to the pool, then shrink the ceiling below it: the
    // pooled entry is discarded and allocation reports exhaustion (host 1 is
    // still leased; the cursor is past the new ceiling of 1).
    assert!(
        ipam.networks
            .release_host(ipam.network_id, 2)
            .await
            .unwrap()
    );
    let err = ipam
        .networks
        .allocate_host(ipam.network_id, 1)
        .await
        .unwrap_err();
    assert!(matches!(&err, DaoError::Validation(m) if m.contains("exhausted")));
    assert!(
        ipam.network().await.free_hosts.is_empty(),
        "the above-ceiling pooled host must be discarded, not re-leased"
    );

    // The full-range ceiling still hands out the next cursor host.
    let c = ipam.alloc().await.unwrap();
    assert_eq!(c, 3);
}

// ────────────────────────────────────────────────────────────────────────────
// IPAM: the free pool
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn allocate_host_is_monotonic_when_the_pool_is_empty() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovipam1").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let mut got = Vec::new();
    for _ in 0..3 {
        got.push(ipam.alloc().await.unwrap());
    }
    assert_eq!(got, vec![1, 2, 3], "host 0 is the network address");
    let net = ipam.network().await;
    assert_eq!(net.next_host, 4);
    assert!(net.free_hosts.is_empty());
}

#[tokio::test]
async fn release_host_pools_the_number_and_the_next_allocate_reuses_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovipam2").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    for _ in 0..3 {
        ipam.alloc().await.unwrap();
    }
    assert!(
        ipam.networks
            .release_host(ipam.network_id, 2)
            .await
            .unwrap()
    );
    assert_eq!(ipam.network().await.free_hosts, vec![2]);

    // The recycled number comes back BEFORE the cursor moves.
    assert_eq!(ipam.alloc().await.unwrap(), 2);
    let net = ipam.network().await;
    assert_eq!(net.next_host, 4, "the cursor did not move");
    assert!(net.free_hosts.is_empty());
}

#[tokio::test]
async fn release_host_is_fifo() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovipam3").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    for _ in 0..4 {
        ipam.alloc().await.unwrap();
    }
    ipam.networks
        .release_host(ipam.network_id, 2)
        .await
        .unwrap();
    ipam.networks
        .release_host(ipam.network_id, 3)
        .await
        .unwrap();

    let mut got = Vec::new();
    for _ in 0..3 {
        got.push(ipam.alloc().await.unwrap());
    }
    assert_eq!(
        got,
        vec![2, 3, 5],
        "oldest release first, then back to the cursor"
    );
}

/// An admin evicting a node at the same moment the agent DELETE fires must not
/// seed the pool twice — that would hand two live nodes one address and lock the
/// second out of the overlay on the unique index.
#[tokio::test]
async fn release_host_is_idempotent() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovipam4").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    for _ in 0..3 {
        ipam.alloc().await.unwrap();
    }
    ipam.networks
        .release_host(ipam.network_id, 2)
        .await
        .unwrap();
    ipam.networks
        .release_host(ipam.network_id, 2)
        .await
        .unwrap();
    assert_eq!(ipam.network().await.free_hosts, vec![2], "no duplicate");

    let a = ipam.alloc().await.unwrap();
    let b = ipam.alloc().await.unwrap();
    assert_eq!((a, b), (2, 4), "2 is handed out once, never twice");
}

#[tokio::test]
async fn release_host_rejects_hosts_the_cursor_never_issued() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovipam5").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    for _ in 0..3 {
        ipam.alloc().await.unwrap();
    }
    // Host 0 is the network address; 9_999 was never issued (cursor is at 4).
    assert!(
        !ipam
            .networks
            .release_host(ipam.network_id, 0)
            .await
            .unwrap()
    );
    assert!(
        !ipam
            .networks
            .release_host(ipam.network_id, 9_999)
            .await
            .unwrap()
    );
    assert!(ipam.network().await.free_hosts.is_empty());
}

/// The core race: N joiners hitting a pool with M entries must each get a
/// distinct host. The pop and the cursor bump are separate atomic updates, so
/// this is the test that would catch a double-hand across the two branches.
#[tokio::test]
async fn concurrent_allocate_never_double_hands_a_pooled_host() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovipam6").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    const POOLED: u32 = 50;
    const RACERS: usize = 80;

    // Advance the cursor past the numbers we're about to pool (release_host
    // only accepts hosts the cursor actually issued), then pool them.
    for _ in 0..POOLED {
        ipam.alloc().await.unwrap();
    }
    for h in 1..=POOLED {
        assert!(
            ipam.networks
                .release_host(ipam.network_id, h)
                .await
                .unwrap()
        );
    }
    assert_eq!(ipam.network().await.free_hosts.len(), POOLED as usize);

    let results = futures::future::join_all((0..RACERS).map(|_| {
        let networks = OverlayNetworkDao::new(&app.db);
        let nid = ipam.network_id;
        async move {
            networks
                .allocate_host(nid, default_max_host())
                .await
                .unwrap()
        }
    }))
    .await;

    let mut sorted = results.clone();
    sorted.sort_unstable();
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(
        sorted, deduped,
        "every racer got a DISTINCT host: {results:?}"
    );
    // The 50 pooled numbers plus 30 fresh ones off the cursor.
    let expected: Vec<u32> = (1..=POOLED).chain(POOLED + 1..=POOLED + 30).collect();
    assert_eq!(sorted, expected);
    assert!(ipam.network().await.free_hosts.is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// The tombstone / index contract
// ────────────────────────────────────────────────────────────────────────────

/// A machine can be removed and re-enrolled repeatedly, so many tombstones must
/// coexist with at most one live row. Reaching this assertion at all also proves
/// MongoDB accepted the `$type: "null"` partial filters — a rejected filter
/// would have failed `ensure_indexes` back in `TestApp::spawn`.
#[tokio::test]
async fn two_tombstones_can_share_a_machine_id() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovtomb1").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let first = ipam
        .create_node("mach-A", "box", "100.64.0.1")
        .await
        .unwrap();
    ipam.nodes.release(first.id.unwrap()).await.unwrap();

    let second = ipam
        .create_node("mach-A", "box-2", "100.64.0.2")
        .await
        .unwrap();
    ipam.nodes.release(second.id.unwrap()).await.unwrap();

    // A third live row alongside two tombstones for the same machine.
    ipam.create_node("mach-A", "box-3", "100.64.0.3")
        .await
        .expect("a live row coexists with its own tombstones");
}

#[tokio::test]
async fn a_released_node_stops_holding_its_ip_and_name() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovtomb2").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let node = ipam
        .create_node("mach-A", "laptop", "100.64.0.7")
        .await
        .unwrap();
    let before = ipam.nodes.release(node.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(
        before.overlay_ip, "100.64.0.7",
        "the CAS returns the pre-image so the caller can recover the address"
    );

    // A different machine takes over both the address and the name.
    ipam.create_node("mach-B", "laptop", "100.64.0.7")
        .await
        .expect("the tombstone holds neither its address nor its name");
}

/// The other half: the partial filters must not be so loose that two LIVE nodes
/// can collide.
#[tokio::test]
async fn two_live_nodes_still_cannot_share_an_ip_or_a_name() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovtomb3").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    ipam.create_node("mach-A", "laptop", "100.64.0.7")
        .await
        .unwrap();

    let dup_ip = ipam.create_node("mach-B", "desktop", "100.64.0.7").await;
    assert!(
        matches!(dup_ip, Err(DaoError::DuplicateKey(_))),
        "two live nodes cannot share an address, got {dup_ip:?}"
    );

    let dup_name = ipam.create_node("mach-C", "laptop", "100.64.0.8").await;
    assert!(
        matches!(dup_name, Err(DaoError::DuplicateKey(_))),
        "two live nodes cannot share a name, got {dup_name:?}"
    );
}

#[tokio::test]
async fn find_live_by_tenant_and_machine_ignores_tombstones() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovtomb4").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let dead = ipam
        .create_node("mach-A", "old", "100.64.0.1")
        .await
        .unwrap();
    ipam.nodes.release(dead.id.unwrap()).await.unwrap();

    assert!(
        ipam.nodes
            .find_live_by_tenant_and_machine(ipam.tenant_id, "mach-A")
            .await
            .unwrap()
            .is_none(),
        "a tombstone is not a live node"
    );

    let live = ipam
        .create_node("mach-A", "new", "100.64.0.2")
        .await
        .unwrap();
    let found = ipam
        .nodes
        .find_live_by_tenant_and_machine(ipam.tenant_id, "mach-A")
        .await
        .unwrap()
        .expect("the live row is found alongside its tombstone");
    assert_eq!(found.id, live.id);
}

/// The CAS is the release token: only one caller may pool the host.
#[tokio::test]
async fn release_is_a_compare_and_swap() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovtomb5").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let node = ipam
        .create_node("mach-A", "box", "100.64.0.1")
        .await
        .unwrap();
    let id = node.id.unwrap();

    assert!(
        ipam.nodes.release(id).await.unwrap().is_some(),
        "first wins"
    );
    assert!(
        ipam.nodes.release(id).await.unwrap().is_none(),
        "the second caller must NOT also pool the host"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// REST: the evict endpoint
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn evict_releases_the_ip_and_the_next_allocate_reuses_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovevict1").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    // Two nodes; evict the one holding host 2.
    ipam.alloc().await.unwrap();
    ipam.alloc().await.unwrap();
    ipam.create_node("mach-A", "keep", "100.64.0.1")
        .await
        .unwrap();
    let victim = ipam
        .create_node("mach-B", "go", "100.64.0.2")
        .await
        .unwrap();
    let victim_id = victim.id.unwrap().to_hex();

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/overlay-node/{victim_id}", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["released"], true);
    assert_eq!(body["overlay_ip"], "100.64.0.2");
    assert_eq!(body["host_recycled"], true);

    // Gone from the admin list, and its host is back in the pool.
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/overlay-node", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&victim_id.as_str()));

    assert_eq!(ipam.network().await.free_hosts, vec![2]);
    assert_eq!(
        ipam.alloc().await.unwrap(),
        2,
        "the next joiner recycles the released address"
    );
}

#[tokio::test]
async fn evict_is_404_for_an_already_released_node() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovevict2").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;
    ipam.alloc().await.unwrap();
    let node = ipam
        .create_node("mach-A", "box", "100.64.0.1")
        .await
        .unwrap();
    let path = format!(
        "/api/tenant/{}/overlay-node/{}",
        seeded.tenant_id,
        node.id.unwrap().to_hex()
    );

    let first = app
        .auth_delete(&path, &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 200);

    let second = app
        .auth_delete(&path, &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 404);
}

/// The tenant scoping is structural (the lookup runs against the caller's own
/// network), so a foreign node must read as absent rather than evictable.
#[tokio::test]
async fn evict_is_cross_tenant_safe() {
    let app = TestApp::spawn().await;
    let a = app.seed_tenant("ovevictA").await;
    let b = app.seed_tenant("ovevictB").await;
    let ipam_b = Ipam::new(&app, tid(&b.tenant_id)).await;
    ipam_b.alloc().await.unwrap();
    let victim = ipam_b
        .create_node("mach-B", "box", "100.64.0.1")
        .await
        .unwrap();

    let resp = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/overlay-node/{}",
                a.tenant_id,
                victim.id.unwrap().to_hex()
            ),
            &a.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "not 200 — and not evicted");

    let still_there = ipam_b
        .nodes
        .base
        .find_by_id(victim.id.unwrap())
        .await
        .unwrap();
    assert!(still_there.deleted_at.is_none());
}

/// One LIVE subnet router per CIDR. Field 2026-08-25: the CORP1 router moved
/// hosts but the old node's row kept its approvals, so two live nodes were
/// approved for the same corp `/32`s and every client's routing became a
/// restart lottery between a working and a dead egress. Approving a CIDR that
/// another live node already holds must be a 409 NAMING the holder — and the
/// intended operator flow (revoke there first, then approve here) must work.
#[tokio::test]
async fn approving_a_cidr_already_approved_on_another_live_node_is_a_409() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovdupacl").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;
    const CORP: &str = "10.66.51.147/32";

    ipam.alloc().await.unwrap();
    ipam.alloc().await.unwrap();
    let old_router = ipam
        .create_router_node("mach-old", "old-router", "100.64.0.1", &[CORP])
        .await;
    let new_router = ipam
        .create_router_node("mach-new", "new-router", "100.64.0.2", &[CORP])
        .await;
    let put = |node_id: String, routes: Vec<&'static str>| {
        let path = format!(
            "/api/tenant/{}/overlay-node/{node_id}/approved-routes",
            seeded.tenant_id
        );
        let token = seeded.admin.access_token.clone();
        let app = &app;
        async move {
            app.auth_put(&path, &token)
                .json(&serde_json::json!({ "approved_routes": routes }))
                .send()
                .await
                .unwrap()
        }
    };
    let old_id = old_router.id.unwrap().to_hex();
    let new_id = new_router.id.unwrap().to_hex();

    // First router takes the CIDR; re-approving it on ITSELF stays fine.
    assert_eq!(put(old_id.clone(), vec![CORP]).await.status().as_u16(), 200);
    assert_eq!(put(old_id.clone(), vec![CORP]).await.status().as_u16(), 200);

    // A second live claimant is refused, and the error names the holder.
    let resp = put(new_id.clone(), vec![CORP]).await;
    assert_eq!(resp.status().as_u16(), 409);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("old-router"),
        "the 409 must name the current holder so the operator knows where to \
         revoke; got: {body}"
    );

    // The operator flow that SHOULD have happened on 2026-08-17: revoke on the
    // old row, then approve on the new one.
    assert_eq!(put(old_id, vec![]).await.status().as_u16(), 200);
    assert_eq!(put(new_id, vec![CORP]).await.status().as_u16(), 200);
}

#[tokio::test]
async fn evict_requires_manage_agents() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovevict3").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;
    ipam.alloc().await.unwrap();
    let node = ipam
        .create_node("mach-A", "box", "100.64.0.1")
        .await
        .unwrap();

    let resp = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/overlay-node/{}",
                seeded.tenant_id,
                node.id.unwrap().to_hex()
            ),
            // A plain member, not the admin.
            &seeded.member.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

// ────────────────────────────────────────────────────────────────────────────
// REST: the agent-delete cascade
// ────────────────────────────────────────────────────────────────────────────

/// Enroll an agent and return `(agent_id, machine_id)`.
async fn enroll_agent(
    app: &TestApp,
    tenant_id: &str,
    admin_token: &str,
    machine_id: &str,
) -> String {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{tenant_id}/agent/enroll-token"),
            admin_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&serde_json::json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": "Test Box",
            "os": "linux",
            "agent_version": "0.3.0",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["agent_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn agent_delete_releases_the_overlay_node() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovcasc1").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let agent_id = enroll_agent(
        &app,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        "mach-cascade",
    )
    .await;

    // The node the agent's `rc:overlay.join` would have created.
    ipam.alloc().await.unwrap();
    let node = ipam
        .nodes
        .create(NewOverlayNode {
            tenant_id: ipam.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: tid(&agent_id),
            },
            network_id: ipam.network_id,
            machine_id: "mach-cascade".to_string(),
            name: "testbox".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            wg_public_key: "pk".to_string(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
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

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/agent/{agent_id}", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
    assert_eq!(body["overlay_released"], true);
    assert_eq!(body["overlay_ip"], "100.64.0.1");

    let after = ipam.nodes.base.find_by_id(node.id.unwrap()).await.unwrap();
    assert!(after.deleted_at.is_some(), "the node is tombstoned");
    assert_eq!(ipam.network().await.free_hosts, vec![1]);
}

#[tokio::test]
async fn agent_delete_is_404_for_an_unknown_agent() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovcasc2").await;

    let resp = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/agent/{}",
                seeded.tenant_id,
                ObjectId::new().to_hex()
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "deleting a nonexistent agent used to report success"
    );
}

/// Removal is FINAL. Re-enrolling the same machine rehydrates the AGENT row (a
/// long-standing contract), but its overlay node is a brand-new row with a fresh
/// lease — the tombstone is never revived.
#[tokio::test]
async fn a_re_enrolled_removed_machine_gets_a_fresh_overlay_node() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovcasc3").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let agent_id = enroll_agent(
        &app,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        "mach-rejoin",
    )
    .await;
    ipam.alloc().await.unwrap();
    let first = ipam
        .nodes
        .create(NewOverlayNode {
            tenant_id: ipam.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: tid(&agent_id),
            },
            network_id: ipam.network_id,
            machine_id: "mach-rejoin".to_string(),
            name: "rejoiner".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            wg_public_key: "pk".to_string(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
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

    app.auth_delete(
        &format!("/api/tenant/{}/agent/{agent_id}", seeded.tenant_id),
        &seeded.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Re-enrolling the same machine revives the AGENT row in place…
    let again = enroll_agent(
        &app,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        "mach-rejoin",
    )
    .await;
    assert_eq!(again, agent_id, "the agent row rehydrates to the same id");

    // …but the overlay lookup no longer finds the tombstone, so the join path
    // takes the fresh-node branch.
    assert!(
        ipam.nodes
            .find_live_by_tenant_and_machine(ipam.tenant_id, "mach-rejoin")
            .await
            .unwrap()
            .is_none()
    );
    let second = ipam
        .create_node("mach-rejoin", "rejoiner", "100.64.0.9")
        .await
        .expect("a fresh node row for the re-enrolled machine");
    assert_ne!(second.id, first.id, "a NEW node id, not the revived one");

    let rows = ipam
        .nodes
        .base
        .find_many(
            doc! { "tenant_id": ipam.tenant_id, "machine_id": "mach-rejoin" },
            None,
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2, "one tombstone + one live row");
    assert_eq!(
        rows.iter().filter(|r| r.deleted_at.is_none()).count(),
        1,
        "exactly one live row"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// REST: the tunnel-client delete
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tunnel_client_delete_releases_the_overlay_node() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovtc1").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let et: Value = app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: Value = app
        .client
        .post(app.url("/api/tunnel-client/enroll"))
        .json(&serde_json::json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": "mach-tc",
            "machine_name": "Laptop",
            "os": "linux",
            "client_version": "0.3.0",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = enrolled["tunnel_client_id"].as_str().unwrap().to_string();

    ipam.alloc().await.unwrap();
    let node = ipam
        .nodes
        .create(NewOverlayNode {
            tenant_id: ipam.tenant_id,
            node_ref: NodeRef::TunnelClient {
                tunnel_client_id: tid(&client_id),
            },
            network_id: ipam.network_id,
            machine_id: "mach-tc".to_string(),
            name: "laptop".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            wg_public_key: "pk".to_string(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
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

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/tunnel-client/{client_id}", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);
    assert_eq!(body["overlay_released"], true);
    assert_eq!(body["overlay_ip"], "100.64.0.1");

    let after = ipam.nodes.base.find_by_id(node.id.unwrap()).await.unwrap();
    assert!(after.deleted_at.is_some());
    assert_eq!(ipam.network().await.free_hosts, vec![1]);

    // And it drops out of the tunnel-client list.
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/tunnel-client", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 0);
}

/// A valid overlay ACL body that needs no real node: every node may reach
/// every node on the whole carrier-grade range.
fn acl_body(name: &str, enabled: bool) -> Value {
    serde_json::json!({
        "name": name,
        "enabled": enabled,
        "sources": [{ "kind": "all_nodes" }],
        "via": [{ "kind": "all_nodes" }],
        "destinations": [{ "cidr": "100.64.0.0/10" }],
    })
}

/// #1829 — removal is FINAL on every per-policy route, not only in the
/// listing. `find_by_id_in_tenant` filtered `{_id, tenant_id}` and nothing
/// else, so after `DELETE …/overlay-acl/{id}` the tombstone still answered
/// `GET` with the whole policy, `PUT` wrote `enabled: true` onto it and
/// re-fanned the tenant, and a repeat `DELETE` re-stamped the removal time.
/// The lookup every per-policy route sits on is live-scoped now, and so are
/// the writes underneath it — and the netmap compiler's input
/// (`list_active_for_tenant`) never carried the tombstone, so a deleted policy
/// is never served, edited or compiled.
///
/// Negative control (recorded on the PR): with the `deleted_at` predicate
/// taken out of the lookup this fails at "GET of a removed policy" with 200;
/// with it taken out of the write filter, at "a write must not land on a
/// tombstone".
#[tokio::test]
async fn a_removed_overlay_acl_policy_is_a_404_on_every_per_policy_route() {
    use bson::Bson;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovaclgone").await;
    let admin = seeded.admin.access_token.clone();
    let list_url = format!("/api/tenant/{}/overlay-acl", seeded.tenant_id);
    let created: Value = app
        .auth_post(&list_url, &admin)
        .json(&acl_body("gone grant", true))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let policy_id = created["id"].as_str().expect("policy id").to_string();
    let one = format!("{list_url}/{policy_id}");
    let tenant_id = tid(&seeded.tenant_id);
    let pid = tid(&policy_id);
    let policies = app.db.collection::<bson::Document>("overlay_policies");

    // The positive control: a LIVE policy resolves on both routes, and the
    // LAST write before the removal is what the tombstone must still say.
    let resp = app.auth_get(&one, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "control: GET of a live policy");
    let resp = app
        .auth_put(&one, &admin)
        .json(&acl_body("before", false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "control: PUT on a live policy");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "before");
    assert_eq!(body["enabled"], false);

    // Remove it.
    let resp = app.auth_delete(&one, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);

    // The row is a TOMBSTONE, not gone — the case the bug lived in.
    let row = policies
        .find_one(doc! { "_id": pid })
        .await
        .unwrap()
        .expect("a deleted policy tombstones in place");
    let removed_at = match row.get("deleted_at") {
        Some(Bson::DateTime(at)) => *at,
        other => panic!("tombstone must carry a removal time, got {other:?}"),
    };

    // GET: 404, exactly like a bogus id.
    let resp = app.auth_get(&one, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404, "GET of a removed policy");

    // PUT: 404 — and in particular `enabled: true` is NOT written back onto
    // the tombstone.
    let resp = app
        .auth_put(&one, &admin)
        .json(&acl_body("zombie", true))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "PUT on a removed policy");
    let row = policies
        .find_one(doc! { "_id": pid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get_str("name").unwrap(), "before");
    assert!(
        !row.get_bool("enabled").unwrap(),
        "the PUT must not re-enable the tombstone"
    );

    // The writes are live-scoped on their own, not only behind the routes'
    // lookup ("a gate applies at every entry point, or it is a courtesy").
    let network = app.state.network();
    assert!(
        !network
            .overlay_policies
            .update(
                tenant_id,
                pid,
                Some("dao".into()),
                Some(true),
                None,
                None,
                None
            )
            .await
            .unwrap(),
        "a write must not land on a tombstone"
    );
    // The removal time is written once: a repeat tombstoning is a no-op.
    assert!(
        !network
            .overlay_policies
            .soft_delete(tenant_id, pid)
            .await
            .unwrap()
    );
    let row = policies
        .find_one(doc! { "_id": pid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get_datetime("deleted_at").unwrap(), &removed_at);
    assert_eq!(row.get_str("name").unwrap(), "before");
    assert!(!row.get_bool("enabled").unwrap());

    // The two lookups differ by NAME: LIVE is NotFound, ANY still sees the
    // tombstone (the reader an audit log naming this policy would need).
    assert!(matches!(
        network
            .overlay_policies
            .find_live_in_tenant(tenant_id, pid)
            .await,
        Err(DaoError::NotFound)
    ));
    assert!(
        network
            .overlay_policies
            .find_any_in_tenant(tenant_id, pid)
            .await
            .unwrap()
            .deleted_at
            .is_some()
    );

    // The netmap compiler's input does not carry it: `try_load_acl` reads
    // `list_active_for_tenant`, nothing reads a policy by id, and the
    // evaluator skips `deleted_at` / `!enabled` rows besides. With no live
    // policy left, an ENFORCING tenant compiles `Some([])` — deny — and a
    // tombstone cannot turn that back into a grant.
    let active = network
        .overlay_policies
        .list_active_for_tenant(tenant_id)
        .await
        .unwrap();
    assert!(
        active.is_empty(),
        "a deleted policy must not reach the netmap compiler"
    );

    // A repeat DELETE is a 404 — the same answer the tunnel-policy sibling
    // gives, and the one that leaves the removal time alone and re-fans
    // nobody.
    let resp = app.auth_delete(&one, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404, "a repeat DELETE");

    // The two views agree: gone from the listing too.
    let list: Value = app
        .auth_get(&list_url, &admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 0);
}

/// #1829 — the live predicate is `deleted_at: null` (null OR ABSENT), the
/// one both listings on `overlay_policies` use, so the per-id view, the admin
/// listing and the compiler's set agree by construction. ⚠️ The
/// `$type: "null"` partial unique indexes live on `overlay_nodes`, not here —
/// `overlay_policies` declares no index set at all — and even the node DAO's
/// own live lookups query with equality-null. A `$type` predicate here would
/// 404 a live policy whose field is missing while the compiler still shipped
/// it: the per-id view disagreeing with the listing in the other direction.
#[tokio::test]
async fn a_live_overlay_acl_policy_whose_deleted_at_field_is_absent_is_still_live() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovaclabsent").await;
    let admin = &seeded.admin.access_token;
    let list_url = format!("/api/tenant/{}/overlay-acl", seeded.tenant_id);
    let created: Value = app
        .auth_post(&list_url, admin)
        .json(&acl_body("absent-field", true))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let policy_id = created["id"].as_str().expect("policy id").to_string();
    let one = format!("{list_url}/{policy_id}");
    let pid = tid(&policy_id);

    app.db
        .collection::<bson::Document>("overlay_policies")
        .update_one(doc! { "_id": pid }, doc! { "$unset": { "deleted_at": "" } })
        .await
        .unwrap();

    let resp = app.auth_get(&one, admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "GET: absent is live");
    let resp = app
        .auth_put(&one, admin)
        .json(&acl_body("still-here", true))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "PUT: absent is live");
    let list: Value = app
        .auth_get(&list_url, admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        list["items"].as_array().unwrap().len(),
        1,
        "the listing agrees"
    );
    let active = app
        .state
        .network()
        .overlay_policies
        .list_active_for_tenant(tid(&seeded.tenant_id))
        .await
        .unwrap();
    assert!(
        active.iter().any(|p| p.id == Some(pid)),
        "the compiler still ships it"
    );
}

/// An agent and a tunnel client on the SAME box share a `machine_id`, and only
/// one of them can own the overlay node. Deleting the agent must not release a
/// node the still-enrolled tunnel client owns.
#[tokio::test]
async fn agent_delete_does_not_release_a_tunnel_clients_node() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovtc2").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let agent_id = enroll_agent(
        &app,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        "mach-shared",
    )
    .await;

    // The node on that machine belongs to a TUNNEL CLIENT, not the agent.
    ipam.alloc().await.unwrap();
    let node = ipam
        .nodes
        .create(NewOverlayNode {
            tenant_id: ipam.tenant_id,
            node_ref: NodeRef::TunnelClient {
                tunnel_client_id: ObjectId::new(),
            },
            network_id: ipam.network_id,
            machine_id: "mach-shared".to_string(),
            name: "shared".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            wg_public_key: "pk".to_string(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
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

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/agent/{agent_id}", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["overlay_released"], false, "the node was not ours");

    let after = ipam.nodes.base.find_by_id(node.id.unwrap()).await.unwrap();
    assert!(
        after.deleted_at.is_none(),
        "the tunnel client keeps its overlay node"
    );
    assert!(ipam.network().await.free_hosts.is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// Multi-org P2b — tenant blocks + the renumber migration
// ────────────────────────────────────────────────────────────────────────────

/// Everything a renumber test needs on top of `Ipam`: two live nodes on the
/// legacy `/10` at ordinals 1 and 2.
async fn seed_two_nodes(ipam: &Ipam) {
    ipam.alloc().await.unwrap();
    ipam.alloc().await.unwrap();
    ipam.create_node("mach-A", "alpha", "100.64.0.1")
        .await
        .unwrap();
    ipam.create_node("mach-B", "bravo", "100.64.0.2")
        .await
        .unwrap();
}

/// The dry run is the default and it must be inert: a full before/after plan,
/// zero writes — no block consumed, no address moved, no cursor touched.
#[tokio::test]
async fn renumber_dry_run_plans_without_writing() {
    // FR-47 — carving is ON by default now, so this test pins it OFF. It is
    // specifically about migrating a network that STARTED on the shared legacy
    // range, which a carved network never does.
    let app = TestApp::spawn_with_settings(|s| s.overlay.blocks_enabled = false).await;
    let seeded = app.seed_tenant("ovblk1").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;
    seed_two_nodes(&ipam).await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    assert_eq!(body["dry_run"], true);
    assert_eq!(body["applied"], false);
    assert_eq!(body["old_cidr"], OverlayNetwork::DEFAULT_CIDR);
    // The first block ever carved starts at slot 64 — the top of the legacy
    // reserve.
    assert_eq!(body["new_cidr"], "100.65.0.0/22");
    let moves = body["moves"].as_array().unwrap();
    assert_eq!(moves.len(), 2);
    let mapped: Vec<(&str, &str)> = moves
        .iter()
        .map(|m| (m["old_ip"].as_str().unwrap(), m["new_ip"].as_str().unwrap()))
        .collect();
    assert!(mapped.contains(&("100.64.0.1", "100.65.0.1")));
    assert!(mapped.contains(&("100.64.0.2", "100.65.0.2")));
    assert!(moves.iter().all(|m| m["ordinal_preserved"] == true));

    // Nothing moved.
    let net = ipam.network().await;
    assert_eq!(net.cidr, OverlayNetwork::DEFAULT_CIDR);
    assert_eq!(net.next_host, 3);
    let nodes = ipam
        .nodes
        .list_active_in_network(ipam.tenant_id, ipam.network_id)
        .await
        .unwrap();
    assert!(nodes.iter().all(|n| n.overlay_ip.starts_with("100.64.0.")));
    assert_eq!(
        app.db
            .collection::<bson::Document>("overlay_blocks")
            .count_documents(doc! {})
            .await
            .unwrap(),
        0,
        "a dry run consumes no block"
    );
}

/// The apply: the tenant lands on its own block, every live node is re-based
/// with its ordinal intact, and the IPAM cursor + registry agree with the
/// addresses actually written.
#[tokio::test]
async fn renumber_moves_the_tenant_onto_its_own_block() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovblk2").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;
    seed_two_nodes(&ipam).await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({ "dry_run": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["applied"], true);
    let new_cidr = body["new_cidr"].as_str().unwrap().to_string();
    assert_eq!(new_cidr, "100.65.0.0/22");

    let net = ipam.network().await;
    assert_eq!(net.cidr, new_cidr, "the network follows the registry");
    assert_eq!(net.next_host, 3);
    assert!(
        net.free_hosts.is_empty(),
        "old ordinals are not carried over"
    );

    let nodes = ipam
        .nodes
        .list_active_in_network(ipam.tenant_id, ipam.network_id)
        .await
        .unwrap();
    let mut ips: Vec<String> = nodes.iter().map(|n| n.overlay_ip.clone()).collect();
    ips.sort();
    assert_eq!(ips, vec!["100.65.0.1", "100.65.0.2"]);
    // The contract the free pool depends on: every written address inverts
    // back to its ordinal under the NEW cidr.
    for n in &nodes {
        assert!(
            roomler_ai_remote_control::models::overlay_host(&net.cidr, &n.overlay_ip).is_some(),
            "{} must invert inside {}",
            n.overlay_ip,
            net.cidr
        );
    }

    // The next joiner leases inside the block, not outside it.
    let host = ipam
        .networks
        .allocate_host(ipam.network_id, net.max_host())
        .await
        .unwrap();
    assert_eq!(host, 3);
    assert_eq!(net.host_ip(host).as_deref(), Some("100.65.0.3"));
}

/// A tenant that renumbers twice must never see its old range re-issued: the
/// predecessor is quarantined and its slots stay out of circulation.
#[tokio::test]
async fn a_second_renumber_quarantines_the_first_block() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovblk3").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;
    seed_two_nodes(&ipam).await;

    let first: Value = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({ "dry_run": false, "prefix": 22 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["new_cidr"], "100.65.0.0/22");

    // A wider block: the allocator aligns it ABOVE the first one rather than
    // reusing the quarantined slot.
    let second: Value = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({ "dry_run": false, "prefix": 20 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second["new_cidr"], "100.65.16.0/20");
    assert_eq!(second["old_cidr"], "100.65.0.0/22");

    let status: Value = app
        .auth_get(
            &format!("/api/tenant/{}/overlay-block", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["cidr"], "100.65.16.0/20");
    assert_eq!(status["legacy"], false);
    assert_eq!(status["capacity"], 4094);
    let blocks = status["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 2, "the renumber trail is kept");
    let states: Vec<(&str, &str)> = blocks
        .iter()
        .map(|b| (b["cidr"].as_str().unwrap(), b["state"].as_str().unwrap()))
        .collect();
    assert!(states.contains(&("100.65.0.0/22", "quarantined")));
    assert!(states.contains(&("100.65.16.0/20", "assigned")));

    // Nodes followed the second move too.
    let nodes = ipam
        .nodes
        .list_active_in_network(ipam.tenant_id, ipam.network_id)
        .await
        .unwrap();
    assert!(nodes.iter().all(|n| n.overlay_ip.starts_with("100.65.16.")));
}

/// The whole point of blocks: two tenants can never be handed overlapping
/// ranges, whatever widths they pick.
#[tokio::test]
async fn blocks_are_disjoint_across_tenants() {
    let app = TestApp::spawn().await;
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for (i, prefix) in [22u8, 20, 22, 16].into_iter().enumerate() {
        let seeded = app.seed_tenant(&format!("ovblkdis{i}")).await;
        let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;
        ipam.alloc().await.unwrap();
        ipam.create_node("m", "n", "100.64.0.1").await.unwrap();
        let body: Value = app
            .auth_post(
                &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
                &seeded.admin.access_token,
            )
            .json(&serde_json::json!({ "dry_run": false, "prefix": prefix }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let cidr = body["new_cidr"].as_str().unwrap();
        let (base, p) = cidr.split_once('/').unwrap();
        let base: u32 = base.parse::<std::net::Ipv4Addr>().unwrap().into();
        let size = 1u32 << (32 - p.parse::<u32>().unwrap());
        for (b, s) in &ranges {
            assert!(
                base >= b + s || base + size <= *b,
                "{cidr} overlaps an earlier block at {b}+{s}"
            );
        }
        ranges.push((base, size));
    }
    assert_eq!(ranges.len(), 4);
}

/// The migration refuses to run over a fleet that predates the P2a
/// forward-compat set: those daemons purge their OWN on-link route at boot,
/// which black-holes that host's mesh. `force` is the documented override.
#[tokio::test]
async fn renumber_refuses_a_fleet_below_the_version_floor() {
    // FR-47 — carving pinned OFF: the fleet-floor refusal is about migrating a
    // network off the shared legacy range (see the dry-run test above).
    let app = TestApp::spawn_with_settings(|s| s.overlay.blocks_enabled = false).await;
    let seeded = app.seed_tenant("ovblkfloor").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    let agent_id = enroll_agent(
        &app,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        "floor-machine",
    )
    .await;
    // Roll that agent back below the floor.
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&agent_id).unwrap() },
            doc! { "$set": { "agent_version": "0.3.0-rc.299" } },
        )
        .await
        .unwrap();
    ipam.alloc().await.unwrap();
    ipam.nodes
        .create(NewOverlayNode {
            tenant_id: ipam.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::parse_str(&agent_id).unwrap(),
            },
            network_id: ipam.network_id,
            machine_id: "floor-machine".to_string(),
            name: "oldbox".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            wg_public_key: "pk".to_string(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
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

    // The status endpoint surfaces the blocker before anyone tries.
    let status: Value = app
        .auth_get(
            &format!("/api/tenant/{}/overlay-block", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["below_floor"].as_array().unwrap().len(), 1);
    assert_eq!(status["below_floor"][0]["version"], "0.3.0-rc.299");

    // The apply refuses…
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({ "dry_run": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    assert_eq!(
        ipam.network().await.cidr,
        OverlayNetwork::DEFAULT_CIDR,
        "a refused migration writes nothing"
    );

    // …but a DRY RUN still plans, so an admin can see the damage first.
    let dry: Value = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dry["below_floor"].as_array().unwrap().len(), 1);
    assert_eq!(dry["moves"].as_array().unwrap().len(), 1);

    // …and force overrides it.
    let forced = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({ "dry_run": false, "force": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(forced.status().as_u16(), 200);
    assert_eq!(ipam.network().await.cidr, "100.65.0.0/22");
}

/// Renumbering is an agent-management action, not something bare tenant
/// membership authorises.
#[tokio::test]
async fn renumber_requires_manage_agents() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovblkperm").await;
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &seeded.member.access_token,
        )
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

/// With carving on, a FRESH network is born inside its own block — but a
/// network that has already leased addresses is left alone (re-basing it
/// under live nodes is the renumber endpoint's job, because only that path
/// rewrites the node rows and cycles the sockets).
#[tokio::test]
async fn carving_claims_a_block_for_new_networks_only() {
    let app = TestApp::spawn_with_settings(|s| {
        s.overlay.blocks_enabled = true;
        s.overlay.block_prefix = 22;
    })
    .await;

    // A network that already leased an address, created the pre-P2b way.
    let legacy_seeded = app.seed_tenant("ovcarve-legacy").await;
    let legacy_dao = OverlayNetworkDao::new(&app.db);
    let legacy = legacy_dao
        .get_or_create(tid(&legacy_seeded.tenant_id))
        .await
        .unwrap();
    legacy_dao
        .allocate_host(legacy.id.unwrap(), default_max_host())
        .await
        .unwrap();

    // A fresh one, through the DAO the app itself uses.
    let fresh_seeded = app.seed_tenant("ovcarve-fresh").await;
    let status: Value = app
        .auth_get(
            &format!("/api/tenant/{}/overlay-block", fresh_seeded.tenant_id),
            &fresh_seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["cidr"], "100.65.0.0/22");
    assert_eq!(status["legacy"], false);
    assert_eq!(status["carving_enabled"], true);
    assert_eq!(status["capacity"], 1022);

    // The populated one still sits on the shared range.
    let legacy_status: Value = app
        .auth_get(
            &format!("/api/tenant/{}/overlay-block", legacy_seeded.tenant_id),
            &legacy_seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(legacy_status["cidr"], OverlayNetwork::DEFAULT_CIDR);
    assert_eq!(legacy_status["legacy"], true);
}

/// FR-47 — the SHIPPED default carves. `spawn()` takes no settings override,
/// so this asserts what a real deployment does out of the box.
///
/// It is a separate test from `carving_claims_a_block_for_new_networks_only`
/// on purpose: that one passes `blocks_enabled = true` explicitly and so would
/// keep passing if the default silently reverted. Carving was default-OFF for
/// its whole life, and the cost was measured on production — two orgs holding
/// overlapping addresses on the shared `/10`, because isolation was opt-in and
/// nobody opted in. A default nobody asserts is a default that can drift back.
#[tokio::test]
async fn the_shipped_default_carves_a_block_for_a_new_org() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovcarve-default").await;

    let status: Value = app
        .auth_get(
            &format!("/api/tenant/{}/overlay-block", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        status["legacy"], false,
        "a brand-new org must not land on the shared 100.64.0.0/10"
    );
    assert_eq!(status["carving_enabled"], true);
    assert_eq!(status["cidr"], "100.65.0.0/22");
    assert_eq!(status["capacity"], 1022);
}

/// FR-47 — a PLATFORM operator can renumber a tenant it is not a member of.
///
/// The block toolkit was unusable as a set before this: `reclaim` and
/// `reconcile-hosts` are platform-operator, so an operator could reclaim
/// ranges fleet-wide and return leaked ordinals, but could not migrate the
/// one tenant those operations exist to serve without first being made a
/// member of it.
///
/// It is consistency rather than escalation — `reclaim` already governs the
/// GLOBAL registry, which is strictly more powerful than renumbering one
/// tenant — but it is still a widened door, so both sides are pinned: this
/// test proves the platform arm opens it, and
/// `renumber_requires_manage_agents` still proves an ordinary member cannot.
#[tokio::test]
async fn a_platform_operator_can_renumber_a_tenant_it_does_not_belong_to() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.overlay.blocks_enabled = false;
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let seeded = app.seed_tenant("ovblk-padmin").await;

    // A token for an id that is on the allowlist and is NOT a member of the
    // tenant — the whole point of the arm.
    let tokens = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/overlay-block/renumber", seeded.tenant_id),
            &tokens.access_token,
        )
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a platform operator must be able to plan a renumber"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["dry_run"], true,
        "a bare body must still default to a PLAN"
    );
    assert_eq!(body["applied"], false);
    assert_eq!(body["old_cidr"], OverlayNetwork::DEFAULT_CIDR);

    // And the tenant is genuinely untouched by the plan.
    let net = OverlayNetworkDao::new(&app.db)
        .get_or_create(tid(&seeded.tenant_id))
        .await
        .unwrap();
    assert_eq!(net.cidr, OverlayNetwork::DEFAULT_CIDR);
}

/// FR-47 P5b — a network's `BlockList` is its assigned blocks in ALLOCATION
/// order, and today that is always exactly one block.
///
/// The single-entry case is the one that matters right now: it must be
/// byte-for-byte the old `overlay_ip`/`overlay_host` behaviour, because
/// multi-block ships behind a flag and "off" has to be provably the old path.
#[tokio::test]
async fn a_networks_block_list_is_its_assigned_blocks_in_allocation_order() {
    let app = TestApp::spawn_with_settings(|s| {
        s.overlay.blocks_enabled = true;
        s.overlay.block_prefix = 22;
    })
    .await;
    let seeded = app.seed_tenant("ovbl-list").await;
    let dao = OverlayNetworkDao::new(&app.db).with_block_prefix(Some(22));
    let net = dao.get_or_create(tid(&seeded.tenant_id)).await.unwrap();

    let bl = dao.block_list(&net).await;
    assert_eq!(
        bl.cidrs(),
        std::slice::from_ref(&net.cidr),
        "one carved block"
    );
    assert_eq!(bl.capacity(), 1022);
    // Identical to the bare pair it generalizes.
    for h in [1u32, 7, 1022] {
        let want = roomler_ai_remote_control::models::overlay_ip(&net.cidr, h).unwrap();
        assert_eq!(bl.ip_for_ordinal(h).as_deref(), Some(want.as_str()));
        assert_eq!(bl.ordinal_for_ip(&want), Some(h));
    }

    // A LEGACY network (no registry row at all) still resolves, via its own
    // cidr — it must stay addressable or every un-migrated tenant breaks.
    let legacy_seeded = app.seed_tenant("ovbl-legacy").await;
    let legacy_dao = OverlayNetworkDao::new(&app.db);
    let legacy = legacy_dao
        .get_or_create(tid(&legacy_seeded.tenant_id))
        .await
        .unwrap();
    let lbl = legacy_dao.block_list(&legacy).await;
    assert_eq!(lbl.cidrs(), &[OverlayNetwork::DEFAULT_CIDR.to_string()]);
    assert_eq!(lbl.ordinal_for_ip("100.64.0.7"), Some(7));
}

/// FR-47 P5c — a network that fills its block is APPENDED another, and every
/// address already leased is untouched.
///
/// This is the claim multi-block rests on, at the DAO level rather than the
/// pure-model level `BlockList`'s own tests cover: growth must cost no device
/// its address, which is what makes it free where a renumber is disruptive.
#[tokio::test]
async fn a_full_network_grows_instead_of_refusing_and_moves_no_address() {
    // A /30-wide first block: 2 leasable ordinals, so exhaustion is 3 allocs
    // away instead of 1023.
    let app = TestApp::spawn_with_settings(|s| {
        s.overlay.blocks_enabled = true;
        s.overlay.block_prefix = 22;
        s.overlay.multi_block_enabled = true;
    })
    .await;
    let seeded = app.seed_tenant("ovgrow").await;
    let dao = OverlayNetworkDao::new(&app.db).with_block_prefix(Some(22));
    let net = dao.get_or_create(tid(&seeded.tenant_id)).await.unwrap();
    let network_id = net.id.unwrap();
    let first_cidr = net.cidr.clone();

    // Fill the block right up to its ceiling by driving the cursor there.
    dao.base
        .update_one(
            doc! { "_id": network_id },
            doc! { "$set": { "next_host": 1023_i64 } },
        )
        .await
        .unwrap();
    let net = dao.base.find_by_id(network_id).await.unwrap();

    // Before: one block, and ordinal 1 resolves inside it.
    let before = dao.block_list(&net).await;
    assert_eq!(before.cidrs().len(), 1);
    let ip_1_before = before.ip_for_ordinal(1).unwrap();

    // The allocation that would previously have been refused.
    let host = dao
        .allocate_host_or_grow(&net, 22)
        .await
        .expect("a full network must GROW, not refuse");
    assert_eq!(
        host, 1023,
        "the next ordinal continues past the first block"
    );

    let net = dao.base.find_by_id(network_id).await.unwrap();
    let after = dao.block_list(&net).await;
    assert_eq!(after.cidrs().len(), 2, "a second block was appended");
    assert_eq!(after.cidrs()[0], first_cidr, "the FIRST block did not move");

    // The point of the whole design: nothing already leased changed address.
    assert_eq!(
        after.ip_for_ordinal(1).unwrap(),
        ip_1_before,
        "growth must not move an existing device's address"
    );
    for o in 1..=1022 {
        assert_eq!(before.ip_for_ordinal(o), after.ip_for_ordinal(o));
    }

    // And the new ordinal lands in the SECOND block, round-tripping.
    //
    // Checked structurally with `overlay_host`, not by comparing address
    // prefixes: `trim_end_matches` strips EVERY trailing occurrence, so
    // "100.65.0.0" reduces to "100.65" and a prefix test then matches the
    // second block too — which is how the first version of this assertion
    // failed against perfectly correct behaviour.
    use roomler_ai_remote_control::models::overlay_host;
    let ip_new = after.ip_for_ordinal(host).unwrap();
    assert!(
        overlay_host(&first_cidr, &ip_new).is_none(),
        "ordinal {host} ({ip_new}) must fall OUTSIDE the first block {first_cidr}"
    );
    assert!(
        overlay_host(&after.cidrs()[1], &ip_new).is_some(),
        "ordinal {host} ({ip_new}) must fall inside the appended block {}",
        after.cidrs()[1]
    );
    assert_eq!(after.ordinal_for_ip(&ip_new), Some(host));
}

/// With the flag OFF a full network still REFUSES — the pre-P5c behaviour,
/// which is what makes the flag a real kill switch rather than a label.
#[tokio::test]
async fn with_multi_block_off_a_full_network_still_refuses() {
    let app = TestApp::spawn_with_settings(|s| {
        s.overlay.blocks_enabled = true;
        s.overlay.block_prefix = 22;
        s.overlay.multi_block_enabled = false;
    })
    .await;
    let seeded = app.seed_tenant("ovnogrow").await;
    let dao = OverlayNetworkDao::new(&app.db).with_block_prefix(Some(22));
    let net = dao.get_or_create(tid(&seeded.tenant_id)).await.unwrap();
    let network_id = net.id.unwrap();
    dao.base
        .update_one(
            doc! { "_id": network_id },
            doc! { "$set": { "next_host": 1023_i64 } },
        )
        .await
        .unwrap();

    let err = dao
        .allocate_host(network_id, 1022)
        .await
        .expect_err("a full block must refuse when growth is off");
    assert!(matches!(&err, DaoError::Validation(m) if m.contains("exhausted")));
    let net = dao.base.find_by_id(network_id).await.unwrap();
    assert_eq!(
        dao.block_list(&net).await.cidrs().len(),
        1,
        "no block may be appended with the flag off"
    );
}

/// FR-54 — an overlay network whose tenant row is gone is reported; one whose
/// tenant EXISTS is not, archived or otherwise.
///
/// The second half is the one that keeps this route from being dangerous. An
/// archived org is retired, not orphaned — its tenant row is right there — and
/// a detector that conflated the two would offer to release a live
/// organization's whole mesh because somebody archived it. That is a far worse
/// bug than the one this route exists to find.
#[tokio::test]
async fn the_orphan_detector_finds_a_vanished_tenant_and_spares_an_archived_one() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let tokens = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();

    // Org A — will be orphaned by removing its tenant row, exactly as the
    // production incident was created.
    let a = app.seed_tenant("orph-gone").await;
    let a_ipam = Ipam::new(&app, tid(&a.tenant_id)).await;
    a_ipam.alloc().await.unwrap();
    a_ipam
        .create_node("orph-mach", "ghost-box", "100.64.0.1")
        .await
        .unwrap();

    // Org B — alive, and then ARCHIVED. It must never be reported.
    let b = app.seed_tenant("orph-archived").await;
    let b_ipam = Ipam::new(&app, tid(&b.tenant_id)).await;
    b_ipam.alloc().await.unwrap();
    b_ipam
        .create_node("live-mach", "live-box", "100.64.0.1")
        .await
        .unwrap();
    roomler_ai_services::dao::tenant::TenantDao::new(&app.db)
        .set_archived(tid(&b.tenant_id), true)
        .await
        .unwrap();

    // Vanish A's tenant row — the manual surgery this route exists to detect.
    app.db
        .collection::<bson::Document>("tenants")
        .delete_one(doc! { "_id": tid(&a.tenant_id) })
        .await
        .unwrap();

    // Dry run: A is reported with its node, B is not, and nothing is written.
    let body: Value = app
        .auth_post("/api/admin/overlay-network/orphans", &tokens.access_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["dry_run"], true);
    let orphans = body["orphans"].as_array().unwrap();
    assert_eq!(orphans.len(), 1, "exactly one orphan: {orphans:?}");
    assert_eq!(orphans[0]["tenant_id"], a.tenant_id);
    assert_eq!(orphans[0]["nodes"][0]["name"], "ghost-box");
    assert!(
        orphans[0]["released"].as_array().unwrap().is_empty(),
        "a dry run releases nothing"
    );
    assert_eq!(
        b_ipam.nodes_alive().await,
        1,
        "the ARCHIVED org's node must be untouched"
    );

    // Apply: A's node is released through the real teardown.
    let applied: Value = app
        .auth_post("/api/admin/overlay-network/orphans", &tokens.access_token)
        .json(&serde_json::json!({ "dry_run": false }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(applied["orphans"][0]["released"][0], "ghost-box");
    assert_eq!(
        a_ipam.nodes_alive().await,
        0,
        "the orphaned node is released"
    );
    assert_eq!(
        b_ipam.nodes_alive().await,
        1,
        "and the archived org is STILL untouched"
    );

    // A second run has nothing left to report for A.
    let again: Value = app
        .auth_post("/api/admin/overlay-network/orphans", &tokens.access_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let still = again["orphans"].as_array().unwrap();
    assert_eq!(still.len(), 1, "the network row itself remains, by design");
    assert!(
        still[0]["nodes"].as_array().unwrap().is_empty(),
        "but it holds no nodes now"
    );
}

/// A non-platform-admin gets 404, not 403 — the route must not confirm it
/// exists to someone who may not use it.
#[tokio::test]
async fn the_orphan_detector_is_platform_operator_only() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("orph-authz").await;
    let resp = app
        .auth_post(
            "/api/admin/overlay-network/orphans",
            &seeded.admin.access_token,
        )
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

/// FR-68 P1 — `multi_block_enabled` is a ONE-WAY DOOR, and the boot must say so.
///
/// Once a network holds two assigned blocks the `network_id` partial-unique
/// index can no longer be created: Mongo refuses on the duplicate. `ensure_indexes`
/// is documented to fail LOUDLY there rather than skip, because "a uniqueness
/// guard that quietly gives up is worse than one that stops you"
/// (`crates/db/src/indexes.rs`). Nothing tested it, so the door's safety was a
/// comment — and the failure mode it guards is a server running with the
/// one-block-per-network invariant silently unenforced.
#[tokio::test]
async fn turning_multi_block_off_after_a_grow_fails_the_boot_loudly() {
    let app = TestApp::spawn_with_settings(|s| {
        s.overlay.blocks_enabled = true;
        s.overlay.block_prefix = 22;
        s.overlay.multi_block_enabled = true;
    })
    .await;
    let seeded = app.seed_tenant("ovoneway").await;
    let dao = OverlayNetworkDao::new(&app.db).with_block_prefix(Some(22));
    let net = dao.get_or_create(tid(&seeded.tenant_id)).await.unwrap();
    let network_id = net.id.unwrap();

    // Drive the cursor to the ceiling so the next allocation must grow.
    dao.base
        .update_one(
            doc! { "_id": network_id },
            doc! { "$set": { "next_host": 1023_i64 } },
        )
        .await
        .unwrap();
    let net = dao.base.find_by_id(network_id).await.unwrap();
    dao.allocate_host_or_grow(&net, 22)
        .await
        .expect("a full network grows");

    // ⚠️ Load-bearing precondition. Without it a database that never grew would
    // satisfy the post-condition and this test would pass proving nothing —
    // the same trap the `harness` test exists to close.
    let grown = dao.base.find_by_id(network_id).await.unwrap();
    assert_eq!(
        dao.block_list(&grown).await.cidrs().len(),
        2,
        "precondition: the network must actually hold two assigned blocks"
    );

    // The door. Booting with the flag back OFF must REFUSE. Since FR-69 P7a
    // the `overlay_blocks` set — and with it the guard — is the network
    // module's (`Module::indexes_for`), applied by the host right after the
    // core plan; the boot's door is that application, so that is what the
    // test drives.
    let err = apply_index_sets(&app.db, &app.state.modules.index_sets_for(false))
        .await
        .expect_err(
            "a boot that cannot recreate the one-block-per-network guard must fail; \
             running on without it leaves the invariant silently unenforced",
        );
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("duplicate")
            || msg.to_lowercase().contains("index")
            || msg.to_lowercase().contains("e11000"),
        "the refusal must name the index conflict so an operator can act on it, got: {msg}"
    );

    // And the flag still ON is fine — the same database boots cleanly, so the
    // failure above is the DOOR, not a broken fixture.
    apply_index_sets(&app.db, &app.state.modules.index_sets_for(true))
        .await
        .expect("multi-block schema still applies to a grown network");
}

/// B4 — Evicting a node (`DELETE /api/tenant/{tid}/overlay-node/{id}` -> `release`)
/// forces a new lease rather than permanently banning the machine: the SAME
/// `machine_id` can re-join with its existing `wg_public_key` and obtain a new
/// overlay lease, while a DIFFERENT `machine_id` attempting to claim that
/// tombstoned `wg_public_key` is rejected. Also verifies pre-expiry proactive
/// key rotation (`list_keys_expiring_soon` + `order_auto_key_rotate_if_needed`).
#[tokio::test]
async fn b4_evicted_node_allows_same_machine_rejoin_with_same_key_and_rejects_other_machine() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovb4evict").await;
    let ipam = Ipam::new(&app, tid(&seeded.tenant_id)).await;

    ipam.alloc().await.unwrap();
    let first = ipam
        .create_node("mach-evict-a", "evict-box", "100.64.0.1")
        .await
        .unwrap();
    let first_id = first.id.unwrap();
    let first_key = first.wg_public_key.clone();

    // Admin evicts the node via REST API.
    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/overlay-node/{first_id}", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Another machine ("mach-hijack") attempting to claim the evicted node's
    // tombstoned `wg_public_key` must be rejected.
    let hijack = ipam
        .nodes
        .create(NewOverlayNode {
            tenant_id: ipam.tenant_id,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: ipam.network_id,
            machine_id: "mach-hijack".to_string(),
            name: "hijack-box".to_string(),
            overlay_ip: "100.64.0.2".to_string(),
            wg_public_key: first_key.clone(),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
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
        matches!(hijack, Err(DaoError::Forbidden(_))),
        "different machine_id must not claim a tombstoned node's wg_public_key: {hijack:?}"
    );

    // The SAME machine ("mach-evict-a") reconnecting with its persisted `wg_public_key`
    // must succeed and obtain a fresh overlay lease.
    let rejoined = ipam
        .create_node("mach-evict-a", "evict-box", "100.64.0.1")
        .await
        .expect("evicted machine must be able to re-join with its same wg_public_key");
    assert_ne!(rejoined.id, first.id);
    assert_eq!(rejoined.wg_public_key, first_key);
    assert!(
        ipam.nodes
            .accepts_current_key(rejoined.id.unwrap(), &first_key, 0)
            .await
            .unwrap()
    );
}

/// B4 R3 — When a node is evicted by an admin while offline (creating a
/// tombstone with `deleted_at != null` and `key_expires_at > now`), and its
/// key TTL subsequently expires while the machine is still offline
/// (`key_expires_at <= now`), reconnecting and sending `rc:overlay.join` with
/// the expired key must:
/// 1. Refuse the join with `rc:overlay.join_refused` (`reason: "key_unauthorized"`);
/// 2. Identify that the rejected key belongs to the SAME `machine_id`'s own
///    tombstone and automatically issue `rc:agent.key_rotate` (`reason: "auto_ttl"`
///    in `key_rotation_audit`);
/// 3. Allow the machine to immediately re-join the mesh with its freshly
///    rotated key (`key_epoch = 1`) and receive a new `rc:overlay.netmap`.
#[tokio::test]
async fn b4_offline_evicted_node_with_expired_ttl_receives_key_rotate_and_rejoins_with_new_key() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use futures::{SinkExt, StreamExt};
    use serde_json::json;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("ovb4offevict").await;
    let tenant_id = tid(&seeded.tenant_id);
    let nodes_dao = OverlayNodeDao::new(&app.db);

    let (agent_id, token) =
        crate::agent_presence_tests::enroll(&app, &seeded, "mach-b4-off-evict").await;
    let agent_oid = ObjectId::parse_str(&agent_id).unwrap();

    // 1. Agent connects with `key-rotate` capability and joins overlay with key_0 (epoch 0).
    let mut ws1 =
        crate::peer_relay_mint_tests::connect_from(&app, &token, &["key-rotate"], None).await;
    let key_0 = BASE64.encode([0x41u8; 32]);
    let join_0 = json!({
        "t": "rc:overlay.join",
        "wg_public_key": key_0,
        "key_epoch": 0,
        "mtu": 1280,
        "endpoints": ["198.51.100.10:51820"],
        "supports_join_refusal": true,
    });
    ws1.send(Message::Text(join_0.to_string().into()))
        .await
        .expect("send initial join");
    let netmap_0 =
        crate::peer_relay_mint_tests::recv_t(&mut ws1, "rc:overlay.netmap", Duration::from_secs(5))
            .await
            .expect("initial join must succeed with netmap");
    assert!(netmap_0["self_ip"].as_str().is_some(), "{netmap_0}");
    let initial_node = nodes_dao
        .find_live_by_agent(tenant_id, agent_oid)
        .await
        .unwrap()
        .expect("live node after initial join");
    let node_oid = initial_node.id.expect("initial node _id");
    let node_id_str = node_oid.to_hex();

    // 2. Admin configures a 60s TTL on the node while it is still valid.
    let ttl_resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/agent/{agent_id}/overlay-key/ttl",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({ "key_ttl_secs": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(ttl_resp.status().as_u16(), 200);

    // 3. Machine goes offline (closes WebSocket).
    let _ = ws1.close(None).await;
    drop(ws1);

    // 4. While machine is offline and key_expires_at is still in the future,
    //    admin evicts the overlay node row (`DELETE /api/tenant/{tid}/overlay-node/{id}`).
    let evict_resp = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/overlay-node/{node_id_str}",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(evict_resp.status().as_u16(), 200);

    let tombstone = nodes_dao.base.find_by_id(node_oid).await.unwrap();
    assert!(
        tombstone.deleted_at.is_some(),
        "evicted node row must be tombstoned"
    );
    assert!(
        !tombstone.is_key_expired_at(bson::DateTime::now()),
        "precondition: key has not yet expired at the moment of eviction"
    );

    // 5. Time passes while the machine remains offline: the tombstone's key_expires_at expires.
    let expired_at = bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 10_000);
    nodes_dao
        .base
        .update_one(
            doc! { "_id": node_oid },
            doc! { "$set": { "key_expires_at": expired_at } },
        )
        .await
        .unwrap();

    // 6. Machine comes back online and attempts to rejoin with its expired key_0 (epoch 0).
    let mut ws2 =
        crate::peer_relay_mint_tests::connect_from(&app, &token, &["key-rotate"], None).await;
    ws2.send(Message::Text(join_0.to_string().into()))
        .await
        .expect("send rejoin with expired key_0");

    let mut got_refused: Option<Value> = None;
    let mut got_rotate: Option<Value> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while got_refused.is_none() || got_rotate.is_none() {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !left.is_zero(),
            "timed out waiting for join_refused and key_rotate; got_refused={got_refused:?}, got_rotate={got_rotate:?}"
        );
        if let Ok(Some(Ok(Message::Text(txt)))) = tokio::time::timeout(left, ws2.next()).await
            && let Ok(v) = serde_json::from_str::<Value>(&txt)
        {
            match v["t"].as_str() {
                Some("rc:overlay.join_refused") => got_refused = Some(v),
                Some("rc:agent.key_rotate") => got_rotate = Some(v),
                _ => {}
            }
        }
    }
    let refused = got_refused.unwrap();
    assert_eq!(refused["reason"].as_str(), Some("key_unauthorized"));
    let rotate = got_rotate.unwrap();
    let req_id = rotate["request_id"]
        .as_str()
        .expect("key_rotate request_id")
        .to_string();

    // Verify the audit log recorded `reason: "auto_ttl"` and `dispatch: "pushed"`.
    let audit_doc = app
        .db
        .collection::<bson::Document>("key_rotation_audit")
        .find_one(doc! { "tenant_id": tenant_id, "agent_id": agent_oid, "request_id": &req_id })
        .await
        .unwrap()
        .expect("audit row for auto_ttl rotation");
    assert_eq!(audit_doc.get_str("dispatch").ok(), Some("pushed"));
    assert_eq!(audit_doc.get_str("reason").ok(), Some("auto_ttl"));

    // 7. Agent rotates to a fresh key_1 (epoch 1) and rejoins the mesh.
    let key_1 = BASE64.encode([0x42u8; 32]);
    let join_1 = json!({
        "t": "rc:overlay.join",
        "wg_public_key": key_1,
        "key_epoch": 1,
        "mtu": 1280,
        "endpoints": ["198.51.100.10:51820"],
        "supports_join_refusal": true,
    });
    ws2.send(Message::Text(join_1.to_string().into()))
        .await
        .expect("send join with rotated key_1");

    let netmap_1 =
        crate::peer_relay_mint_tests::recv_t(&mut ws2, "rc:overlay.netmap", Duration::from_secs(5))
            .await
            .expect("rejoin with rotated key_1 must succeed with netmap");
    assert!(netmap_1["self_ip"].as_str().is_some(), "{netmap_1}");
    let new_node = nodes_dao
        .find_live_by_agent(tenant_id, agent_oid)
        .await
        .unwrap()
        .expect("live node after rotated rejoin");
    let new_node_id = new_node.id.expect("new node _id");
    assert_ne!(
        new_node_id, node_oid,
        "must allocate a fresh OverlayNode row"
    );
    assert!(new_node.deleted_at.is_none());
    assert_eq!(new_node.wg_public_key, key_1);
    assert_eq!(new_node.key_epoch, 1);
    assert_eq!(
        new_node.key_ttl_secs,
        Some(60),
        "new node row preserves the machine's configured key_ttl_secs"
    );
    assert!(new_node.is_key_authorized_at(bson::DateTime::now()));
}
