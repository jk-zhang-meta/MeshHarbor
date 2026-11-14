// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The unified device list (`GET /tenant/{tid}/device`) — agents + tunnel
//! clients as one server-paginated/searched/sorted feed, joined in memory to
//! overlay nodes + the tenant's MagicDNS domain.
//!
//! The virgin-tenant test is the load-bearing one: the list must resolve the
//! overlay network with `find_for_tenant`, never `get_or_create` — the create
//! half allocates a global P2b block slot that is quarantined forever once
//! freed, and a GET must not be able to spend one.

use bson::oid::ObjectId;
use meshharbor_remote_control::models::NodeRef;
use meshharbor_services::dao::overlay_network::OverlayNetworkDao;
use meshharbor_services::dao::overlay_node::{NewOverlayNode, OverlayNodeDao};
use meshharbor_services::dao::tenant::TenantDao;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

async fn enroll_agent(
    app: &TestApp,
    tenant_id: &str,
    admin_token: &str,
    machine_id: &str,
    machine_name: &str,
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
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": machine_name,
            "os": "linux",
            "agent_version": "0.3.0",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["agent_id"].as_str().expect("agent_id").to_string()
}

async fn enroll_tunnel_client(
    app: &TestApp,
    tenant_id: &str,
    admin_token: &str,
    machine_id: &str,
    machine_name: &str,
) -> String {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{tenant_id}/tunnel-client/enroll-token"),
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
        .post(app.url("/api/tunnel-client/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": machine_name,
            "os": "macos",
            "client_version": "0.3.0-test",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["tunnel_client_id"]
        .as_str()
        .expect("tunnel_client_id")
        .to_string()
}

/// Seed an overlay node for an already-enrolled device, as
/// `handle_overlay_join` would (driving two real agent WS joins here would
/// test the harness, not the list — the overlay_tests module owns join).
async fn seed_node(
    app: &TestApp,
    tenant_id: &str,
    node_ref: NodeRef,
    machine_id: &str,
    name: &str,
    ip: &str,
) {
    let tid = ObjectId::parse_str(tenant_id).unwrap();
    let networks = OverlayNetworkDao::new(&app.db);
    let nodes = OverlayNodeDao::new(&app.db);
    let network_id = networks.get_or_create(tid).await.unwrap().id.unwrap();
    nodes
        .create(NewOverlayNode {
            temporary: None,
            tenant_id: tid,
            node_ref,
            network_id,
            machine_id: machine_id.to_string(),
            name: name.to_string(),
            overlay_ip: ip.to_string(),
            wg_public_key: format!("pk-{machine_id}"),
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
}

async fn list_devices(app: &TestApp, tenant_id: &str, token: &str, qs: &str) -> Value {
    app.auth_get(&format!("/api/tenant/{tenant_id}/device{qs}"), token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn device_list_merges_kinds_and_joins_overlay_and_magicdns() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devlist1").await;

    let aid = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "dl1-a", "Box A").await;
    enroll_tunnel_client(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "dl1-t",
        "Laptop T",
    )
    .await;
    seed_node(
        &app,
        &t.tenant_id,
        NodeRef::Agent {
            agent_id: ObjectId::parse_str(&aid).unwrap(),
        },
        "dl1-a",
        "box-a",
        "100.64.0.7",
    )
    .await;
    // Set the tenant's MagicDNS domain via the DAO — the PUT route is
    // plan-gated and the plan matrix is not what this test is about.
    TenantDao::new(&app.db)
        .set_magic_dns(
            ObjectId::parse_str(&t.tenant_id).unwrap(),
            Some("grox.internal".to_string()),
            vec![],
        )
        .await
        .unwrap();

    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "").await;
    assert_eq!(body["total"].as_u64(), Some(2));
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);

    let agent = items
        .iter()
        .find(|r| r["kind"] == "agent")
        .expect("agent row");
    assert_eq!(agent["name"].as_str(), Some("Box A"));
    assert_eq!(agent["overlay_ip"].as_str(), Some("100.64.0.7"));
    assert_eq!(agent["magic_dns_name"].as_str(), Some("box-a"));
    assert_eq!(
        agent["magic_dns_fqdn"].as_str(),
        Some("box-a.grox.internal")
    );
    assert!(agent["overlay_node_id"].as_str().is_some());

    let client = items
        .iter()
        .find(|r| r["kind"] == "tunnel_client")
        .expect("tunnel row");
    assert_eq!(client["name"].as_str(), Some("Laptop T"));
    assert!(client["overlay_ip"].is_null());
    assert!(client["magic_dns_fqdn"].is_null());
}

#[tokio::test]
async fn device_list_q_matches_across_joined_fields() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devlist2").await;

    let aid = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "dl2-a", "Alpha").await;
    enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "dl2-b", "Beta").await;
    seed_node(
        &app,
        &t.tenant_id,
        NodeRef::Agent {
            agent_id: ObjectId::parse_str(&aid).unwrap(),
        },
        "dl2-a",
        "alpha-node",
        "100.64.9.33",
    )
    .await;
    // Tag Alpha so tag-search has something to find.
    app.auth_put(
        &format!("/api/tenant/{}/agent/{aid}", t.tenant_id),
        &t.admin.access_token,
    )
    .json(&json!({ "tags": ["vienna", "prod"] }))
    .send()
    .await
    .unwrap();

    // By overlay-ip substring — only the node-backed device matches.
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "?q=64.9.33").await;
    assert_eq!(body["total"].as_u64(), Some(1));
    assert_eq!(body["items"][0]["name"].as_str(), Some("Alpha"));

    // By tag.
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "?q=vienna").await;
    assert_eq!(body["total"].as_u64(), Some(1));

    // By MagicDNS label (domain unset — the bare label still matches).
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "?q=alpha-node").await;
    assert_eq!(body["total"].as_u64(), Some(1));

    // Case-insensitive name.
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "?q=BETA").await;
    assert_eq!(body["total"].as_u64(), Some(1));
    assert_eq!(body["items"][0]["name"].as_str(), Some("Beta"));

    // No match.
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "?q=nosuch").await;
    assert_eq!(body["total"].as_u64(), Some(0));
    assert_eq!(body["total_pages"].as_u64(), Some(1));
}

#[tokio::test]
async fn device_list_sorts_and_paginates() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devlist3").await;

    let a1 = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "dl3-a", "Cherry").await;
    enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "dl3-b", "apple").await;
    enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "dl3-c", "Banana").await;
    seed_node(
        &app,
        &t.tenant_id,
        NodeRef::Agent {
            agent_id: ObjectId::parse_str(&a1).unwrap(),
        },
        "dl3-a",
        "cherry",
        "100.64.0.5",
    )
    .await;

    // Default sort (FR-11): presence bucket then effective name. All three
    // fixture agents share one presence bucket (never connected), so the
    // observable order here is the name half of the compound.
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "").await;
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["apple", "Banana", "Cherry"]);

    // display_name participates in the effective-name sort.
    let b_id = body["items"][1]["id"].as_str().unwrap().to_string();
    app.auth_put(
        &format!("/api/tenant/{}/agent/{b_id}", t.tenant_id),
        &t.admin.access_token,
    )
    .json(&json!({ "display_name": "zzz-last" }))
    .send()
    .await
    .unwrap();
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "?sort=name").await;
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["apple", "Cherry", "Banana"]);

    // Desc flips it.
    let body = list_devices(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "?sort=name&dir=desc",
    )
    .await;
    assert_eq!(body["items"][0]["name"].as_str(), Some("Banana"));

    // overlay_ip sort: the one node-backed device leads asc, node-less LAST.
    let body = list_devices(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "?sort=overlay_ip",
    )
    .await;
    assert_eq!(body["items"][0]["name"].as_str(), Some("Cherry"));
    assert!(body["items"][2]["overlay_ip"].is_null());

    // Pagination: per_page=2 ⇒ 2 + 1, disjoint, correct envelope.
    let p1 = list_devices(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "?per_page=2&page=1&sort=name",
    )
    .await;
    let p2 = list_devices(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "?per_page=2&page=2&sort=name",
    )
    .await;
    assert_eq!(p1["items"].as_array().unwrap().len(), 2);
    assert_eq!(p2["items"].as_array().unwrap().len(), 1);
    assert_eq!(p1["total"].as_u64(), Some(3));
    assert_eq!(p1["total_pages"].as_u64(), Some(2));
    let mut seen: Vec<String> = p1["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(p2["items"].as_array().unwrap())
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "pages overlap or drop rows");
}

#[tokio::test]
async fn device_list_gates_and_validates() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devlist4").await;
    let stranger = app.seed_tenant("devlist4b").await;

    enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "dl4-a", "Solo").await;
    enroll_tunnel_client(&app, &t.tenant_id, &t.admin.access_token, "dl4-t", "Tun").await;

    // A member of ANOTHER org is refused.
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/device", t.tenant_id),
            &stranger.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // A plain member of THIS org may read (mutations stay MANAGE_AGENTS).
    let body = list_devices(&app, &t.tenant_id, &t.member.access_token, "").await;
    assert_eq!(body["total"].as_u64(), Some(2));

    // kind filter.
    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "?kind=agent").await;
    assert_eq!(body["total"].as_u64(), Some(1));
    assert_eq!(body["items"][0]["kind"].as_str(), Some("agent"));

    // Unknown sort / dir / kind are 400s, not silent fallbacks.
    for qs in ["?sort=bogus", "?dir=sideways", "?kind=toaster"] {
        let resp = app
            .auth_get(
                &format!("/api/tenant/{}/device{qs}", t.tenant_id),
                &t.admin.access_token,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "{qs} must 400");
    }
}

/// The M1 guard: listing devices for a tenant that has never touched the
/// overlay must not CREATE its overlay network (get_or_create would, and
/// with blocks enabled that permanently consumes a global /22 slot).
#[tokio::test]
async fn device_list_on_virgin_tenant_creates_no_overlay_network() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devlist5").await;
    let tid = ObjectId::parse_str(&t.tenant_id).unwrap();

    enroll_agent(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "dl5-a",
        "Lone Box",
    )
    .await;

    let body = list_devices(&app, &t.tenant_id, &t.admin.access_token, "").await;
    assert_eq!(body["total"].as_u64(), Some(1));
    assert!(body["items"][0]["overlay_ip"].is_null());

    let networks = OverlayNetworkDao::new(&app.db);
    assert!(
        networks.find_for_tenant(tid).await.unwrap().is_none(),
        "GET /device allocated an overlay network for a virgin tenant"
    );
}
