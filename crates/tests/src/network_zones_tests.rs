// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Comprehensive contract & end-to-end tests for Logical Network Zones
//! (`OverlayNetwork::zones` + `Agent::pinned_zone_id`), same-zone router
//! auto-mesh vs explicit-only cross-zone links, Codex residual P1/P2 closures,
//! and SOTA scale / continuous bound-relay upgrade invariants.

use crate::agent_presence_tests::enroll;
use crate::agent_self_tests::city_fixture_mmdb;
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use crate::peer_relay_mint_tests::{
    Ws, approve, audit_rows, connect_from, grant_relay, node_id, put, recv_t, set_mode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::{doc, oid::ObjectId};
use futures::SinkExt;
use meshharbor_db::models::role::permissions::{DEFAULT_ADMIN, MANAGE_TENANT};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

fn tenant_url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

async fn get_json(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let resp = app.auth_get(path, token).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn join_node(ws: &mut Ws, seed: u8, endpoint: &str, extra: Value) -> Value {
    let mut msg = json!({
        "t": "rc:overlay.join",
        "wg_public_key": BASE64.encode([seed; 32]),
        "mtu": 1280,
        "endpoints": [endpoint],
        "srflx_endpoints": [endpoint],
        "supports_org_relay": true,
        "supports_org_relay_multi_candidate": true,
        "supports_org_relay_discovery_cursor": true,
        "supports_path_trial_v1": true,
        "supports_path_backbone_v1": true,
        "supports_server_relay_strategy": true,
        "supports_backbone_only_v1": true,
        "org_primary": true,
        "relay_port": 3478,
    });
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            msg[k] = v.clone();
        }
    }
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .expect("send join");
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .expect("netmap after join")
}

fn find_peer_in<'a>(arr: &'a Value, peer_node_id: &str) -> &'a Value {
    arr.as_array()
        .unwrap()
        .iter()
        .find(|p| p["node_id"] == json!(peer_node_id))
        .unwrap_or_else(|| panic!("peer {peer_node_id} missing from {arr}"))
}

fn find_peer<'a>(netmap: &'a Value, peer_node_id: &str) -> &'a Value {
    find_peer_in(&netmap["peers"], peer_node_id)
}

fn assert_backbone_only_stripped(peer: &Value, label: &str) {
    assert_eq!(peer["backbone_only"], json!(true), "{label}: {peer}");
    for key in ["endpoints", "lan_endpoints", "srflx_endpoints"] {
        assert!(
            peer[key].as_array().is_none_or(Vec::is_empty),
            "{label}: {key} must be stripped on cross-zone RouterOnly peer: {peer}"
        );
    }
    assert!(
        peer.get("warm_relay_endpoint").is_none_or(Value::is_null),
        "{label}: warm_relay_endpoint must be stripped: {peer}"
    );
}

#[tokio::test]
async fn network_zones_crud_permissions_gateway_redaction_and_validation_invariants() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("nz-crud").await;
    let other = app.seed_tenant("nz-crud-other").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let admin = &seeded.admin.access_token;
    let member = &seeded.member.access_token;
    let nz_path = tenant_url(&seeded, "/network-zones");

    // 1. Fresh tenant GET returns `{ revision: 0, zones: [] }` without creating `overlay_networks`.
    let (s, init) = get_json(&app, &nz_path, admin).await;
    assert_eq!(s, 200, "{init}");
    assert_eq!(init, json!({ "revision": 0, "zones": [] }));
    assert_eq!(
        app.db
            .collection::<bson::Document>("overlay_networks")
            .count_documents(doc! { "tenant_id": tid })
            .await
            .unwrap(),
        0,
        "GET /network-zones must never allocate an overlay_networks document"
    );

    // Non-member rejected on GET and PUT.
    assert_eq!(get_json(&app, &nz_path, &other.admin.access_token).await.0, 403);
    assert_eq!(
        put(&app, &nz_path, &other.admin.access_token, json!({ "zones": [] }))
            .await
            .0,
        403
    );

    // 2. PUT /network-zones is strictly ADMINISTRATOR-only: Member, MANAGE_AGENTS, and MANAGE_TENANT get 403.
    let (s, _) = put(&app, &nz_path, member, json!({ "zones": [] })).await;
    assert_eq!(s, 403);
    let mgr_role: Value = app
        .auth_post(&tenant_url(&seeded, "/role"), admin)
        .json(&json!({ "name": "ops-mgr", "permissions": DEFAULT_ADMIN | MANAGE_TENANT }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mgr_role_id = mgr_role["id"].as_str().unwrap();
    assert_eq!(
        app.auth_post(
            &tenant_url(&seeded, &format!("/role/{mgr_role_id}/assign/{}", seeded.member.id)),
            admin,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16(),
        200
    );
    assert_eq!(
        put(&app, &nz_path, member, json!({ "zones": [] })).await.0,
        403,
        "MANAGE_AGENTS | MANAGE_TENANT without ADMINISTRATOR must be refused"
    );

    // Enroll devices: `relay_ok` (approved relay), `unapproved_dev`, `member_dev` (owned by member), `admin_dev`.
    let (relay_id, _) = enroll(&app, &seeded, "nz-crud-relay").await;
    let (unapproved_id, _) = enroll(&app, &seeded, "nz-crud-unapproved").await;
    let (member_dev_id, _) = enroll(&app, &seeded, "nz-crud-member-dev").await;
    let (admin_dev_id, _) = enroll(&app, &seeded, "nz-crud-admin-dev").await;
    let (foreign_relay_id, _) = enroll(&app, &other, "nz-crud-foreign-relay").await;
    assert_eq!(approve(&app, &seeded, &relay_id, true).await, 200);
    assert_eq!(approve(&app, &other, &foreign_relay_id, true).await, 200);

    // Transfer ownership of `member_dev_id` to `seeded.member`, and drop `ops-mgr` role
    // from `seeded.member` so `seeded.member` is an ordinary Member again!
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&member_dev_id).unwrap() },
            doc! { "$set": { "owner_user_id": ObjectId::parse_str(&seeded.member.id).unwrap() } },
        )
        .await
        .unwrap();
    assert_eq!(
        app.auth_delete(
            &tenant_url(&seeded, &format!("/role/{mgr_role_id}/assign/{}", seeded.member.id)),
            admin,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16(),
        200
    );

    // 3. Validation checks on PUT /network-zones.
    // > 32 zones rejected:
    let too_many: Vec<Value> = (0..33)
        .map(|i| json!({ "id": format!("z{i}"), "name": format!("Zone {i}") }))
        .collect();
    assert_eq!(put(&app, &nz_path, admin, json!({ "zones": too_many })).await.0, 400);

    // Duplicate normalized slugs (`"CN"` vs `"cn"`) rejected:
    assert_eq!(
        put(
            &app,
            &nz_path,
            admin,
            json!({
                "zones": [
                    { "id": "CN", "name": "A" },
                    { "id": "cn", "name": "B" }
                ]
            }),
        )
        .await
        .0,
        400
    );

    // Invalid slug (`"-bad"`) rejected:
    assert_eq!(
        put(
            &app,
            &nz_path,
            admin,
            json!({ "zones": [{ "id": "-bad", "name": "Bad" }] }),
        )
        .await
        .0,
        400
    );

    // Overlapping `auto_countries` across zones rejected:
    assert_eq!(
        put(
            &app,
            &nz_path,
            admin,
            json!({
                "zones": [
                    { "id": "z1", "name": "Z1", "auto_countries": ["CN", "HK"] },
                    { "id": "z2", "name": "Z2", "auto_countries": ["hk", "US"] }
                ]
            }),
        )
        .await
        .0,
        400
    );

    // Invalid ISO country code (`"USA"` / `"C1"`) rejected:
    assert_eq!(
        put(
            &app,
            &nz_path,
            admin,
            json!({ "zones": [{ "id": "z1", "name": "Z1", "auto_countries": ["USA"] }] }),
        )
        .await
        .0,
        400
    );

    // > 1 `is_default: true` rejected:
    assert_eq!(
        put(
            &app,
            &nz_path,
            admin,
            json!({
                "zones": [
                    { "id": "z1", "name": "Z1", "is_default": true },
                    { "id": "z2", "name": "Z2", "is_default": true }
                ]
            }),
        )
        .await
        .0,
        400
    );

    // Unapproved or foreign `gateway_relay_ids` rejected:
    assert_eq!(
        put(
            &app,
            &nz_path,
            admin,
            json!({ "zones": [{ "id": "z1", "name": "Z1", "gateway_relay_ids": [unapproved_id] }] }),
        )
        .await
        .0,
        400
    );
    assert_eq!(
        put(
            &app,
            &nz_path,
            admin,
            json!({ "zones": [{ "id": "z1", "name": "Z1", "gateway_relay_ids": [foreign_relay_id] }] }),
        )
        .await
        .0,
        400
    );

    // Unknown field (`deny_unknown_fields`) rejected:
    let unknown_status = put(
        &app,
        &nz_path,
        admin,
        json!({ "zones": [], "unexpected": true }),
    )
    .await
    .0;
    assert!(matches!(unknown_status, 400 | 422), "{unknown_status}");

    // 4. Valid PUT normalizes slugs/countries, bumps `revision`, and returns full `gateway_relay_ids` to ADMINISTRATOR.
    let (s, saved) = put(
        &app,
        &nz_path,
        admin,
        json!({
            "zones": [
                {
                    "id": "CN",
                    "name": "Mainland China",
                    "auto_countries": ["cn"],
                    "is_default": false,
                    "gateway_relay_ids": [relay_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "siat",
                    "name": "SIAT Campus",
                    "auto_countries": [],
                    "is_default": false,
                    "gateway_relay_ids": [relay_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "non-cn",
                    "name": "Global",
                    "auto_countries": ["HK", "US"],
                    "is_default": true,
                    "gateway_relay_ids": [],
                    "cross_zone_mode": "direct_preferred"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "{saved}");
    let rev1 = saved["revision"].as_u64().expect("revision");
    assert!(rev1 >= 1);
    assert_eq!(saved["zones"][0]["id"], json!("cn"));
    assert_eq!(saved["zones"][0]["auto_countries"], json!(["CN"]));
    assert_eq!(saved["zones"][0]["gateway_relay_ids"], json!([relay_id]));

    // 5. Ordinary org member can GET /network-zones to populate the zone picker,
    //    with `gateway_relay_ids` redacted to `[]` while ADMINISTRATOR receives full IDs!
    let (s, member_view) = get_json(&app, &nz_path, member).await;
    assert_eq!(s, 200, "{member_view}");
    assert_eq!(member_view["revision"], json!(rev1));
    assert_eq!(member_view["zones"].as_array().unwrap().len(), 3);
    for z in member_view["zones"].as_array().unwrap() {
        assert_eq!(
            z["gateway_relay_ids"],
            json!([]),
            "non-ADMINISTRATOR GET /network-zones must blank gateway_relay_ids: {z}"
        );
    }
    let (_, admin_view) = get_json(&app, &nz_path, admin).await;
    assert_eq!(admin_view["zones"][0]["gateway_relay_ids"], json!([relay_id]));

    // 6. Zone assignment permissions + deletion protection:
    //    - Ordinary member CAN pin their own device (`member_dev_id`), CANNOT pin `admin_dev_id` (`403`).
    let member_assign_path = tenant_url(&seeded, &format!("/agent/{member_dev_id}/zone-assignment"));
    let admin_assign_path = tenant_url(&seeded, &format!("/agent/{admin_dev_id}/zone-assignment"));
    assert_eq!(
        put(&app, &admin_assign_path, member, json!({ "pinned_zone_id": "siat" }))
            .await
            .0,
        403
    );
    assert_eq!(
        put(&app, &member_assign_path, member, json!({ "pinned_zone_id": "missing-zone" }))
            .await
            .0,
        400
    );
    let (s, assigned) = put(
        &app,
        &member_assign_path,
        member,
        json!({ "pinned_zone_id": "SIAT" }),
    )
    .await;
    assert_eq!(s, 200, "{assigned}");
    assert_eq!(assigned["pinned_zone_id"], json!("siat"));
    assert_eq!(assigned["effective_zone_id"], json!("siat"));
    assert_eq!(assigned["effective_zone_name"], json!("SIAT Campus"));

    // Deleting `"siat"` while `member_dev_id` is pinned to it is rejected with 400 naming `"siat"`!
    let (s, err_body) = put(
        &app,
        &nz_path,
        admin,
        json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "Mainland China",
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [relay_id],
                    "cross_zone_mode": "router_only"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 400, "{err_body}");
    assert!(
        err_body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("siat"),
        "deletion refusal must name referenced zone 'siat': {err_body}"
    );

    // Unpin `member_dev_id` (`null` = Auto) -> deleting `"siat"` now succeeds with monotonic revision!
    let (s, cleared) = put(
        &app,
        &member_assign_path,
        member,
        json!({ "pinned_zone_id": null }),
    )
    .await;
    assert_eq!(s, 200, "{cleared}");
    assert!(cleared["pinned_zone_id"].is_null());
    assert_eq!(cleared["effective_zone_id"], json!("non-cn"));

    let (s, saved2) = put(
        &app,
        &nz_path,
        admin,
        json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "Mainland China",
                    "auto_countries": ["CN"],
                    "is_default": true,
                    "gateway_relay_ids": [relay_id],
                    "cross_zone_mode": "router_only"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "{saved2}");
    assert!(saved2["revision"].as_u64().unwrap() > rev1);
}

#[tokio::test]
async fn three_plus_zones_symmetric_router_only_direct_preferred_shared_gateway_and_fail_closed() {
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.turn.url = Some("turn:139.199.9.9:3478".into());
        s.turn.worker_urls = Some("turn:139.199.9.9:3478,turn:202.181.7.9:3478,turn:8.8.4.4:3478".into());
        s.turn.shared_secret = Some("nz-fixture-secret".into());
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-3plus").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);

    // Leaves: `cn_a`, `cn_b` (Auto CN), `siat_pin` (Pinned "siat" from HK IP!),
    // `hk_a` (Auto HK), `us_a` (Auto US), `unknown_leaf` (private-only IP, no default zone).
    // Gateways: `gz_relay` (CN), `dual_relay` (CN, shared in BOTH cn and hk gateway_relay_ids!).
    let (_cn_a_id, cn_a_tok) = enroll(&app, &seeded, "nz3-cn-a").await;
    let (_cn_b_id, cn_b_tok) = enroll(&app, &seeded, "nz3-cn-b").await;
    let (siat_id, siat_tok) = enroll(&app, &seeded, "nz3-siat-pin").await;
    let (_hk_a_id, hk_a_tok) = enroll(&app, &seeded, "nz3-hk-a").await;
    let (_us_a_id, us_a_tok) = enroll(&app, &seeded, "nz3-us-a").await;
    let (_unk_id, unk_tok) = enroll(&app, &seeded, "nz3-unk").await;
    let (gz_id, gz_tok) = enroll(&app, &seeded, "nz3-gz-relay").await;
    let (dual_id, dual_tok) = enroll(&app, &seeded, "nz3-dual-relay").await;

    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &gz_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &dual_id, true).await, 200);

    let mut cn_a_ws = connect_from(&app, &cn_a_tok, &[], Some("139.199.1.10")).await;
    let mut cn_b_ws = connect_from(&app, &cn_b_tok, &[], Some("139.199.1.11")).await;
    // `siat_pin` connects from HK IP, proving Pinned overrides GeoIP!
    let mut siat_ws = connect_from(&app, &siat_tok, &[], Some("202.181.7.50")).await;
    let mut hk_a_ws = connect_from(&app, &hk_a_tok, &[], Some("202.181.7.10")).await;
    let mut us_a_ws = connect_from(&app, &us_a_tok, &[], Some("8.8.8.8")).await;
    let mut unk_ws = connect_from(&app, &unk_tok, &[], None).await;
    let mut gz_ws = connect_from(&app, &gz_tok, &["relay-server"], Some("139.199.6.6")).await;
    let mut dual_ws = connect_from(&app, &dual_tok, &["relay-server"], Some("139.199.6.7")).await;

    join_node(&mut cn_a_ws, 11, "139.199.1.10:41641", json!({})).await;
    join_node(&mut cn_b_ws, 12, "139.199.1.11:41641", json!({})).await;
    join_node(&mut siat_ws, 13, "202.181.7.50:41641", json!({})).await;
    join_node(&mut hk_a_ws, 14, "202.181.7.10:41641", json!({})).await;
    join_node(&mut us_a_ws, 15, "8.8.8.8:41641", json!({})).await;
    join_node(&mut unk_ws, 16, "192.168.10.5:41641", json!({})).await;
    join_node(&mut gz_ws, 17, "139.199.6.6:41641", json!({ "relay_backbone_ready": true })).await;
    join_node(&mut dual_ws, 18, "139.199.6.7:41641", json!({ "relay_backbone_ready": true })).await;

    let cn_a_node = node_id(&app, &seeded, "nz3-cn-a").await;
    let cn_b_node = node_id(&app, &seeded, "nz3-cn-b").await;
    let siat_node = node_id(&app, &seeded, "nz3-siat-pin").await;
    let hk_a_node = node_id(&app, &seeded, "nz3-hk-a").await;
    let us_a_node = node_id(&app, &seeded, "nz3-us-a").await;
    let unk_node = node_id(&app, &seeded, "nz3-unk").await;
    let gz_node = node_id(&app, &seeded, "nz3-gz-relay").await;
    let dual_node = node_id(&app, &seeded, "nz3-dual-relay").await;
    grant_relay(&app, &seeded, &gz_node).await;
    grant_relay(&app, &seeded, &dual_node).await;

    // Configure 4 zones (NO `is_default: true` so `unk` resolves to `UnresolvedStrict`!).
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "Mainland China",
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [gz_id, dual_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "siat",
                    "name": "SIAT Campus",
                    "auto_countries": [],
                    "is_default": false,
                    "gateway_relay_ids": [gz_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "hk",
                    "name": "Hong Kong",
                    "auto_countries": ["HK"],
                    "is_default": false,
                    "gateway_relay_ids": [dual_id],
                    "cross_zone_mode": "direct_preferred"
                },
                {
                    "id": "us",
                    "name": "United States",
                    "auto_countries": ["US"],
                    "is_default": false,
                    "gateway_relay_ids": [],
                    "cross_zone_mode": "direct_preferred"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "{body}");

    // Drain the live full netmap pushed by `PUT /network-zones` to each online node.
    let _ = recv_t(&mut cn_a_ws, "rc:overlay.netmap", wait).await.unwrap();
    let _ = recv_t(&mut siat_ws, "rc:overlay.netmap", wait).await.unwrap();
    let _ = recv_t(&mut hk_a_ws, "rc:overlay.netmap", wait).await.unwrap();
    let unk_nm = recv_t(&mut unk_ws, "rc:overlay.netmap", wait).await.unwrap();

    // Pin `siat_id` to `"siat"` (`auto_countries: []`, gateway `[gz_id]` in CN!) ->
    // `siat_ws` immediately receives a live-pushed full netmap!
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, &format!("/agent/{siat_id}/zone-assignment")),
        admin,
        json!({ "pinned_zone_id": "siat" }),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let siat_nm = recv_t(&mut siat_ws, "rc:overlay.netmap", wait)
        .await
        .expect("live full netmap push after zone-assignment");

    // Re-join `cn_a` and `hk_a` to capture their fresh full netmaps too.
    let cn_nm = join_node(&mut cn_a_ws, 11, "139.199.1.10:41641", json!({})).await;
    let hk_nm = join_node(&mut hk_a_ws, 14, "202.181.7.10:41641", json!({})).await;

    // 1. Same-zone `cn_a <-> cn_b` keeps direct P2P (`backbone_only != true`).
    assert!(
        !find_peer(&cn_nm, &cn_b_node)
            .get("backbone_only")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    // 2. Cross-zone `DirectPreferred <-> DirectPreferred` (`hk_a <-> us_a`) keeps direct P2P!
    assert!(
        !find_peer(&hk_nm, &us_a_node)
            .get("backbone_only")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    assert!(
        !hk_nm["network"]
            .get("strict_stun")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "DirectPreferred zone omits/clears strict_stun: {}",
        hk_nm["network"]
    );

    // 3. Cross-zone `RouterOnly <-> DirectPreferred` (`cn_a <-> hk_a` AND `hk_a <-> cn_a`,
    //    plus `cn_a <-> siat` across two different RouterOnly zones!) are SYMMETRICALLY
    //    `backbone_only = true` with direct/srflx/warm stripped!
    assert_backbone_only_stripped(find_peer(&cn_nm, &hk_a_node), "cn_a -> hk_a");
    assert_backbone_only_stripped(find_peer(&hk_nm, &cn_a_node), "hk_a -> cn_a");
    assert_backbone_only_stripped(find_peer(&cn_nm, &siat_node), "cn_a -> siat");
    assert_backbone_only_stripped(find_peer(&siat_nm, &hk_a_node), "siat -> hk_a");

    // 4. Pinned `"siat"` (`auto_countries: []`) inherits `"CN"` STUN eligibility from gateway `gz_id`
    //    with `strict_stun = true` (Residual P2 #2 contract)!
    assert_eq!(siat_nm["network"]["strict_stun"], json!(true));
    let siat_stun = siat_nm["network"]["stun_urls"].as_array().unwrap();
    assert!(!siat_stun.is_empty());
    assert!(
        siat_stun
            .iter()
            .all(|u| u.as_str().unwrap_or_default().contains("139.199.9.9")),
        "only CN STUN inherited from gateway po0-gz may remain on siat: {siat_stun:?}"
    );

    // 5. `unk` (unknown GeoIP, no `is_default` zone) fails closed as `UnresolvedStrict`:
    //    `strict_stun = true`, `stun_urls = []`, and `backbone_only = true` to all peers!
    assert_eq!(unk_nm["network"]["strict_stun"], json!(true));
    assert!(
        unk_nm["network"]
            .get("stun_urls")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty),
        "UnresolvedStrict device must receive zero stun_urls: {}",
        unk_nm["network"]
    );
    assert_backbone_only_stripped(find_peer(&unk_nm, &hk_a_node), "unk -> hk_a");
    assert_backbone_only_stripped(find_peer(&hk_nm, &unk_node), "hk_a -> unk");

    // 6. DERP ACL table matches symmetric strictness!
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let net_id = app
        .state
        .network()
        .overlay_networks
        .find_for_tenant(tid)
        .await
        .unwrap()
        .unwrap()
        .id
        .unwrap();
    let table = app.state.network().derp_acl.get(&net_id).unwrap();
    assert!(table.permits(&[11_u8; 32], &[12_u8; 32]), "same-zone cn <-> cn DERP allowed");
    assert!(table.permits(&[14_u8; 32], &[15_u8; 32]), "DirectPreferred hk <-> us DERP allowed");
    assert!(!table.permits(&[11_u8; 32], &[14_u8; 32]), "cn -> hk DERP denied");
    assert!(!table.permits(&[14_u8; 32], &[11_u8; 32]), "hk -> cn DERP denied");
    assert!(!table.permits(&[16_u8; 32], &[14_u8; 32]), "UnresolvedStrict unk -> hk DERP denied");

    // 7. Single shared dual-zone gateway (`dual_id` in BOTH `cn` and `hk` `gateway_relay_ids`)
    //    serves `cn_a <-> hk_a` single-hop, while `siat <-> hk_a` (disjoint gateways `[gz]` vs `[dual]`,
    //    no cross-zone backbone link) is denied!
    cn_a_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": hk_a_node,
                "reason": "direct_timeout",
                "request_id": 10,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let _ = recv_t(&mut dual_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("shared dual-zone gateway serves cn_a <-> hk_a");
    let sess = recv_t(&mut cn_a_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("cn_a receives shared gateway session");
    assert_eq!(sess["relay_node_id"], json!(dual_node));
    let _ = recv_t(&mut hk_a_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("hk_a receives shared gateway session");

    // 8. `siat -> hk_a` routes 2-hop `gz -> dual` because `gz` and `dual` both
    //    reside in `"cn"` (same-zone router auto-mesh), whereas `siat -> us_a`
    //    (`us` has `gateway_relay_ids: []`) is refused!
    siat_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": hk_a_node,
                "reason": "direct_timeout",
                "request_id": 11,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let siat_hk_sess = recv_t(&mut siat_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("siat -> hk_a routes 2-hop via gz -> dual");
    assert_eq!(siat_hk_sess["relay_node_id"], json!(gz_node));
    let hk_siat_sess = recv_t(&mut hk_a_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("hk_a receives exit leg on dual");
    assert_eq!(hk_siat_sess["relay_node_id"], json!(dual_node));

    siat_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": us_a_node,
                "reason": "direct_timeout",
                "request_id": 12,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    for _ in 0..40 {
        if audit_rows(&app, &seeded).await.iter().any(|r| {
            r["action"] == json!("mint")
                && r["requester_node_id"] == json!(siat_node)
                && r["peer_node_id"] == json!(us_a_node)
                && r["denied"].is_string()
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        audit_rows(&app, &seeded).await.iter().any(|r| {
            r["action"] == json!("mint")
                && r["requester_node_id"] == json!(siat_node)
                && r["peer_node_id"] == json!(us_a_node)
                && r["denied"].is_string()
        }),
        "empty/disjoint cross-zone gateway_relay_ids must refuse mint"
    );
}

#[tokio::test]
async fn router_topology_same_zone_auto_mesh_vs_cross_zone_explicit_private_link() {
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-router-mesh").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);

    // Leaves: `siat45` (CN), `hk_leaf` (HK -> non-cn), `houston` (US -> non-cn).
    // Routers: `po0-gz` (CN), `po0-hk` (HK -> non-cn), `hyonix-la` (US -> non-cn).
    let (_siat_id, siat_tok) = enroll(&app, &seeded, "rm-siat45").await;
    let (_hk_leaf_id, hk_leaf_tok) = enroll(&app, &seeded, "rm-hk-leaf").await;
    let (_us_id, us_tok) = enroll(&app, &seeded, "rm-houston").await;
    let (gz_id, gz_tok) = enroll(&app, &seeded, "rm-po0-gz").await;
    let (hk_id, hk_tok) = enroll(&app, &seeded, "rm-po0-hk").await;
    let (hy_id, hy_tok) = enroll(&app, &seeded, "rm-hyonix-la").await;

    let mut siat_ws = connect_from(&app, &siat_tok, &[], Some("139.199.1.45")).await;
    let mut hk_leaf_ws = connect_from(&app, &hk_leaf_tok, &[], Some("202.181.7.20")).await;
    let mut us_ws = connect_from(&app, &us_tok, &[], Some("8.8.8.8")).await;
    let mut gz_ws =
        connect_from(&app, &gz_tok, &["relay-server", "relay-control"], Some("139.199.6.6")).await;
    let mut hk_ws =
        connect_from(&app, &hk_tok, &["relay-server", "relay-control"], Some("202.181.7.6")).await;
    let mut hy_ws =
        connect_from(&app, &hy_tok, &["relay-server", "relay-control"], Some("8.8.4.4")).await;

    // Drain initial `peer_relay_serve = false` on the 3 routers.
    let _ = recv_t(&mut gz_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut hy_ws, "rc:overlay.peer_relay_serve", wait).await;

    join_node(&mut siat_ws, 31, "139.199.1.45:41641", json!({})).await;
    join_node(&mut hk_leaf_ws, 32, "202.181.7.20:41641", json!({})).await;
    join_node(&mut us_ws, 33, "8.8.8.8:41641", json!({})).await;
    join_node(&mut gz_ws, 34, "139.199.6.6:41641", json!({ "relay_backbone_ready": true })).await;
    join_node(&mut hk_ws, 35, "202.181.7.6:41641", json!({ "relay_backbone_ready": true })).await;
    join_node(&mut hy_ws, 36, "8.8.4.4:41641", json!({ "relay_backbone_ready": true })).await;

    let siat_node = node_id(&app, &seeded, "rm-siat45").await;
    let hk_leaf_node = node_id(&app, &seeded, "rm-hk-leaf").await;
    let us_node = node_id(&app, &seeded, "rm-houston").await;
    let gz_node = node_id(&app, &seeded, "rm-po0-gz").await;
    let hk_node = node_id(&app, &seeded, "rm-po0-hk").await;
    let hy_node = node_id(&app, &seeded, "rm-hyonix-la").await;

    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &gz_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &hk_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &hy_id, true).await, 200);
    grant_relay(&app, &seeded, &gz_node).await;
    grant_relay(&app, &seeded, &hk_node).await;
    grant_relay(&app, &seeded, &hy_node).await;
    let _ = recv_t(&mut gz_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut hy_ws, "rc:overlay.peer_relay_serve", wait).await;

    // Define `"cn"` (gateway `[po0-gz]`) and `"non-cn"` (gateways `[po0-hk, hyonix-la]`)
    // with ZERO `approved_backbone_edges` configured yet!
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "CN",
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [gz_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "non-cn",
                    "name": "Non-CN",
                    "auto_countries": ["HK", "US"],
                    "is_default": true,
                    "gateway_relay_ids": [hk_id, hy_id],
                    "cross_zone_mode": "direct_preferred"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "{body}");

    // 1. Same-Zone Routers Auto-Mesh: `po0-hk` and `hyonix-la` (both `"non-cn"`)
    //    automatically receive each other's public relay endpoints in `PeerRelayServe`
    //    AND `backbone_probe_targets`, while `po0-gz` (`"cn"`) receives `[]`!
    let gz_serve = recv_t(&mut gz_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .expect("gz peer_relay_serve after zones");
    let hk_serve = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .expect("hk peer_relay_serve after zones");
    let hy_serve = recv_t(&mut hy_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .expect("hy peer_relay_serve after zones");
    assert!(
        gz_serve
            .get("backbone_endpoints")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty),
        "po0-gz is alone in 'cn' with no explicit cross-zone edges yet: {gz_serve}"
    );
    assert_eq!(
        hk_serve["backbone_endpoints"],
        json!(["8.8.4.4:3478"]),
        "po0-hk must auto-synthesize same-zone hyonix-la endpoint: {hk_serve}"
    );
    assert_eq!(
        hy_serve["backbone_endpoints"],
        json!(["202.181.7.6:3478"]),
        "hyonix-la must auto-synthesize same-zone po0-hk endpoint: {hy_serve}"
    );

    let hk_nm = join_node(&mut hk_ws, 35, "202.181.7.6:41641", json!({ "relay_backbone_ready": true })).await;
    let hk_bb_targets = hk_nm["network"]["backbone_probe_targets"]
        .as_array()
        .expect("hk backbone_probe_targets");
    assert!(
        hk_bb_targets.iter().any(|t| {
            t["relay_node_id"] == json!(hy_node) && t["endpoints"] == json!(["8.8.4.4:3478"])
        }),
        "same-zone router auto-mesh must populate backbone_probe_targets: {hk_bb_targets:?}"
    );

    // 2. Cross-Zone Routers Strictly Explicit-Only: BEFORE admin configures `po0-gz <-> po0-hk`,
    //    `siat45 -> houston` CANNOT cross between `"cn"` and `"non-cn"`!
    siat_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": us_node,
                "reason": "direct_timeout",
                "request_id": 1,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    for _ in 0..40 {
        if audit_rows(&app, &seeded).await.iter().any(|r| {
            r["action"] == json!("mint")
                && r["requester_node_id"] == json!(siat_node)
                && r["denied"].is_string()
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        audit_rows(&app, &seeded).await.iter().any(|r| {
            r["action"] == json!("mint")
                && r["requester_node_id"] == json!(siat_node)
                && r["denied"].is_string()
        }),
        "cross-zone routers must NEVER auto-mesh without an explicit admin edge"
    );

    // 3. Meanwhile, same-zone `"non-cn"` pair `hk_leaf <-> houston` (where `hk_leaf` reaches
    //    only `po0-hk` and `houston` reaches only `hyonix-la`) AUTOMATICALLY routes 2-hop
    //    over the synthesized `po0-hk -> hyonix-la` intra-zone mesh without manual edges!
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    let net = app.state.network();
    let siat_oid = ObjectId::parse_str(&siat_node).unwrap();
    let hk_leaf_oid = ObjectId::parse_str(&hk_leaf_node).unwrap();
    let us_oid = ObjectId::parse_str(&us_node).unwrap();
    let gz_oid = ObjectId::parse_str(&gz_node).unwrap();
    let hk_oid = ObjectId::parse_str(&hk_node).unwrap();
    let hy_oid = ObjectId::parse_str(&hy_node).unwrap();

    assert!(support::record_member_probe_fixture(
        net,
        hk_leaf_oid,
        &[
            (hk_oid, "202.181.7.6:3478".into(), true, Some(6)),
            (hy_oid, "8.8.4.4:3478".into(), false, None),
        ],
    ));
    assert!(support::record_member_probe_fixture(
        net,
        us_oid,
        &[
            (hk_oid, "202.181.7.6:3478".into(), false, None),
            (hy_oid, "8.8.4.4:3478".into(), true, Some(10)),
        ],
    ));
    assert!(support::record_backbone_probe_fixture(
        net,
        hk_oid,
        &[(hy_oid, "8.8.4.4:3478".into(), true, Some(85))],
    ));

    hk_leaf_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": us_node,
                "reason": "direct_timeout",
                "request_id": 2,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let _ = recv_t(&mut hk_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("po0-hk serves ingress for same-zone 2-hop");
    let hk_auto_bridge = recv_t(&mut hk_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("po0-hk auto-bridges to same-zone hyonix-la");
    assert_eq!(hk_auto_bridge["bridge"]["remote_endpoint"], json!("8.8.4.4:3478"));
    let _ = recv_t(&mut hy_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("hyonix-la serves exit for same-zone 2-hop");
    let _ = recv_t(&mut hk_leaf_ws, "rc:overlay.relay_session", wait).await.unwrap();
    let _ = recv_t(&mut us_ws, "rc:overlay.relay_session", wait).await.unwrap();

    // 4. Now Admin configures ONLY the cross-zone private link `po0-gz <-> po0-hk`
    //    (`10.42.2.114:3478` / `172.31.8.41:3478`) — STILL zero manual edges on `po0-hk -> hyonix-la`!
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/peer-relays/{gz_id}")),
            admin,
            json!({
                "serve": true,
                "approved_backbone_edges": [
                    { "relay_agent_id": hk_id, "endpoint": "10.42.2.114:3478", "cross_border": false }
                ]
            }),
        )
        .await
        .0,
        200
    );
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/peer-relays/{hk_id}")),
            admin,
            json!({
                "serve": true,
                "approved_backbone_edges": [
                    { "relay_agent_id": gz_id, "endpoint": "172.31.8.41:3478", "cross_border": false }
                ]
            }),
        )
        .await
        .0,
        200
    );

    assert!(support::record_member_probe_fixture(
        net,
        siat_oid,
        &[(gz_oid, "139.199.6.6:3478".into(), true, Some(8))],
    ));
    assert!(support::record_backbone_probe_fixture(
        net,
        gz_oid,
        &[(hk_oid, "10.42.2.114:3478".into(), true, Some(12))],
    ));
    assert!(support::record_backbone_probe_fixture(
        net,
        hk_oid,
        &[(hy_oid, "8.8.4.4:3478".into(), true, Some(85))],
    ));

    // Verify `discover` offers the 3-hop path `[gz_node, hk_node, hy_node]`!
    siat_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.org_relay_discover",
                "peer_node_id": us_node,
                "request_id": 50,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let disc = recv_t(&mut siat_ws, "rc:overlay.org_relay_candidates", wait)
        .await
        .expect("discover response");
    assert!(
        disc["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["path"]["relay_node_ids"] == json!([gz_node, hk_node, hy_node])),
        "discover must include 3-hop explicit+auto-mesh path [gz, hk, hy]: {disc}"
    );

    // Verify `relay_request` mints:
    // `siat45 -> po0-gz ==(10.42.2.114:3478)==> po0-hk ==(auto-mesh 8.8.4.4:3478)==> hyonix-la -> houston`!
    siat_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": us_node,
                "reason": "direct_timeout",
                "request_id": 3,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    let _ = recv_t(&mut gz_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("po0-gz serves ingress");
    let gz_bridge = recv_t(&mut gz_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("po0-gz bridges to po0-hk over private link");
    assert_eq!(gz_bridge["bridge"]["remote_endpoint"], json!("10.42.2.114:3478"));

    let _ = recv_t(&mut hk_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("po0-hk serves middle hop");
    let hk_bridge = recv_t(&mut hk_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("po0-hk bridges to hyonix-la over auto-synthesized same-zone mesh");
    assert_eq!(hk_bridge["bridge"]["remote_endpoint"], json!("8.8.4.4:3478"));

    let _ = recv_t(&mut hy_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("hyonix-la serves exit");
    let siat_sess = recv_t(&mut siat_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("siat45 session");
    let us_sess = recv_t(&mut us_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("houston session");
    assert_eq!(siat_sess["relay_node_id"], json!(gz_node));
    assert_eq!(us_sess["relay_node_id"], json!(hy_node));
}

#[tokio::test]
async fn auto_zone_reconnect_ip_roam_vs_pinned_stability_and_revisioned_relay_regions() {
    use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();

    let regions_json = json!([
        {
            "id": "cn-gz",
            "turn_url": "turn:139.199.9.9:3478",
            "shared_secret": "cn-secret",
            "enabled": true
        },
        {
            "id": "hk-pop",
            "turn_url": "turn:202.181.7.8:3478",
            "shared_secret": "hk-secret",
            "enabled": true
        }
    ])
    .to_string();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.app.rc_ice_zone_mode = "warn".into();
        s.relay.regions_enabled = true;
        s.relay.regions = Some(regions_json);
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-roam").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (roam_id, roam_tok) = enroll(&app, &seeded, "nz-roam-laptop").await;
    let (pinned_id, pinned_tok) = enroll(&app, &seeded, "nz-pinned-hk").await;
    let (_hk_peer_id, hk_peer_tok) = enroll(&app, &seeded, "nz-roam-hk-peer").await;
    let (hk_relay_id, hk_relay_tok) = enroll(&app, &seeded, "nz-roam-hk-relay").await;

    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &hk_relay_id, true).await, 200);

    let (s, _) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "Mainland",
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "hk",
                    "name": "Hong Kong",
                    "auto_countries": ["HK"],
                    "is_default": true,
                    "gateway_relay_ids": [hk_relay_id],
                    "cross_zone_mode": "direct_preferred"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/agent/{pinned_id}/zone-assignment")),
            admin,
            json!({ "pinned_zone_id": "hk" }),
        )
        .await
        .0,
        200
    );

    let connect_with_regions = |tok: String, xff: &'static str| {
        let addr = app.addr;
        async move {
            let enc = tok.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
            let ws_url = format!("ws://{addr}/ws?token={enc}&role=agent");
            let mut req = ws_url.into_client_request().unwrap();
            req.headers_mut().insert("x-forwarded-for", xff.parse().unwrap());
            let (mut ws, _) = connect_async(req).await.unwrap();
            ws.send(Message::Text(
                json!({
                    "t": "rc:agent.hello",
                    "machine_name": "roam",
                    "os": "linux",
                    "agent_version": "0.4.166",
                    "displays": [],
                    "supports_relay_regions": true,
                    "caps": {
                        "hw_encoders": [],
                        "codecs": ["h264"],
                        "has_input_permission": true,
                        "supports_clipboard": true,
                        "supports_file_transfer": true,
                        "max_simultaneous_sessions": 1,
                        "rpc": []
                    }
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
            ws
        }
    };

    // 1. Auto `roam` connects from HK IP (`202.181.7.10`) -> resolves to `"hk"` (`DirectPreferred`),
    //    receives both regions with `policy_revision = rev1`, and mints single-hop HK session.
    let mut roam_ws = connect_with_regions(roam_tok.clone(), "202.181.7.10").await;
    let reg1 = recv_t(&mut roam_ws, "rc:relay.regions", wait).await.unwrap();
    let rev1 = reg1["policy_revision"].as_u64().expect("policy_revision on RelayRegions");
    let reg1_ids: Vec<&str> = reg1["regions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    assert_eq!(reg1_ids, vec!["cn-gz", "hk-pop"]);

    let mut hk_peer_ws = connect_from(&app, &hk_peer_tok, &[], Some("202.181.7.11")).await;
    let mut hk_relay_ws =
        connect_from(&app, &hk_relay_tok, &["relay-server"], Some("202.181.7.6")).await;
    join_node(&mut roam_ws, 71, "202.181.7.10:41641", json!({})).await;
    join_node(&mut hk_peer_ws, 72, "202.181.7.11:41641", json!({})).await;
    join_node(&mut hk_relay_ws, 73, "202.181.7.6:41641", json!({})).await;
    let hk_peer_node = node_id(&app, &seeded, "nz-roam-hk-peer").await;
    let hk_relay_node = node_id(&app, &seeded, "nz-roam-hk-relay").await;
    grant_relay(&app, &seeded, &hk_relay_node).await;

    roam_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": hk_peer_node,
                "reason": "direct_timeout",
                "request_id": 1,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let _ = recv_t(&mut hk_relay_ws, "rc:overlay.relay_serve", wait).await.unwrap();
    let s1 = recv_t(&mut roam_ws, "rc:overlay.relay_session", wait).await.unwrap();
    let _ = recv_t(&mut hk_peer_ws, "rc:overlay.relay_session", wait).await.unwrap();
    let vni = s1["vni"].as_u64().unwrap();

    // 2. Auto `roam` roams to Shenzhen IP (`139.199.1.45` -> `"cn"`, `RouterOnly`, `gateway_relay_ids: []`):
    //    - `policy_revision` bumps (`rev2 > rev1`) and `RelayRegions` filters to `["cn-gz"]`!
    //    - Netmap peer `hk_peer` flips to `backbone_only = true`!
    //    - Stale HK single-hop session `vni` is revoked!
    drop(roam_ws);
    let mut roam_cn_ws = connect_with_regions(roam_tok.clone(), "139.199.1.45").await;
    let reg2 = recv_t(&mut roam_cn_ws, "rc:relay.regions", wait).await.unwrap();
    let rev2 = reg2["policy_revision"].as_u64().expect("bumped policy_revision");
    assert!(rev2 > rev1, "IP roam must bump policy_revision: {rev2} <= {rev1}");
    let reg2_ids: Vec<&str> = reg2["regions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    assert_eq!(reg2_ids, vec!["cn-gz"]);

    let nm_roam_cn = join_node(&mut roam_cn_ws, 71, "139.199.1.45:41641", json!({})).await;
    assert_backbone_only_stripped(find_peer(&nm_roam_cn, &hk_peer_node), "roamed cn -> hk");
    let peer_rev = recv_t(&mut hk_peer_ws, "rc:overlay.relay_revoke", wait)
        .await
        .expect("stale HK session revoked on roam to CN");
    assert_eq!(peer_rev["vni"].as_u64(), Some(vni));

    let (_, ag_roam) = get_json(&app, &tenant_url(&seeded, &format!("/agent/{roam_id}")), admin).await;
    assert_eq!(ag_roam["effective_zone_id"], json!("cn"));

    // 3. Pinned `"hk"` device connecting from CN IP (`139.199.1.45`) stays in `"hk"`!
    let mut pinned_ws = connect_with_regions(pinned_tok, "139.199.1.45").await;
    let reg_pin = recv_t(&mut pinned_ws, "rc:relay.regions", wait).await.unwrap();
    let pin_ids: Vec<&str> = reg_pin["regions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    assert_eq!(pin_ids, vec!["cn-gz", "hk-pop"]);
    let nm_pin = join_node(&mut pinned_ws, 74, "139.199.1.46:41641", json!({})).await;
    assert!(
        !find_peer(&nm_pin, &hk_peer_node)
            .get("backbone_only")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "Pinned 'hk' device must not flip to 'cn' when connecting from CN IP"
    );
}

#[tokio::test]
async fn residual_p1_finalized_trial_blocks_return_to_direct_when_zone_flips_to_router_only() {
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-p1-return").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);

    let (_cn_id, cn_tok) = enroll(&app, &seeded, "p1-cn").await;
    let (_hk_id, hk_tok) = enroll(&app, &seeded, "p1-hk").await;
    let (dual_id, dual_tok) = enroll(&app, &seeded, "p1-dual-relay").await;

    let mut cn_ws = connect_from(&app, &cn_tok, &[], Some("139.199.1.45")).await;
    let mut hk_ws = connect_from(&app, &hk_tok, &[], Some("202.181.7.10")).await;
    let mut dual_ws = connect_from(&app, &dual_tok, &["relay-server"], Some("202.181.7.6")).await;

    join_node(&mut cn_ws, 81, "139.199.1.45:41641", json!({})).await;
    join_node(&mut hk_ws, 82, "202.181.7.10:41641", json!({})).await;
    join_node(&mut dual_ws, 83, "202.181.7.6:41641", json!({ "relay_backbone_ready": true })).await;

    let hk_node = node_id(&app, &seeded, "p1-hk").await;
    let dual_node = node_id(&app, &seeded, "p1-dual-relay").await;

    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &dual_id, true).await, 200);
    grant_relay(&app, &seeded, &dual_node).await;

    // Start with BOTH zones in `direct_preferred` so direct->relay PathTrial is allowed,
    // and finalize the trial on shared gateway `dual_id`.
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, "/network-zones"),
            admin,
            json!({
                "zones": [
                    {
                        "id": "cn",
                        "name": "CN",
                        "auto_countries": ["CN"],
                        "gateway_relay_ids": [dual_id],
                        "cross_zone_mode": "direct_preferred"
                    },
                    {
                        "id": "hk",
                        "name": "HK",
                        "auto_countries": ["HK"],
                        "is_default": true,
                        "gateway_relay_ids": [dual_id],
                        "cross_zone_mode": "direct_preferred"
                    }
                ]
            }),
        )
        .await
        .0,
        200
    );
    let _ = recv_t(&mut cn_ws, "rc:overlay.netmap", wait).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.netmap", wait).await;

    cn_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.path_trial_request",
                "peer_node_id": hk_node,
                "request_id": 1,
                "path": { "relay_node_ids": [dual_node] },
                "requester_at_exit": false
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let _ = recv_t(&mut dual_ws, "rc:overlay.relay_serve", wait).await.unwrap();
    let start_cn = recv_t(&mut cn_ws, "rc:overlay.path_trial_start", wait).await.unwrap();
    let _ = recv_t(&mut hk_ws, "rc:overlay.path_trial_start", wait).await.unwrap();
    let trial_id = start_cn["trial_id"].as_str().unwrap().to_string();

    for ws in [&mut cn_ws, &mut hk_ws] {
        ws.send(Message::Text(
            json!({ "t": "rc:overlay.path_trial_ready", "trial_id": trial_id })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    }
    let _ = recv_t(&mut cn_ws, "rc:overlay.path_trial_commit", wait).await.unwrap();
    let _ = recv_t(&mut hk_ws, "rc:overlay.path_trial_commit", wait).await.unwrap();
    for ws in [&mut cn_ws, &mut hk_ws] {
        ws.send(Message::Text(
            json!({ "t": "rc:overlay.path_trial_committed", "trial_id": trial_id })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    }
    let _ = recv_t(&mut cn_ws, "rc:overlay.path_trial_finalize", wait).await.unwrap();
    let _ = recv_t(&mut hk_ws, "rc:overlay.path_trial_finalize", wait).await.unwrap();

    // Now flip `"cn"` to `"router_only"` -> direct transport is forbidden, while the
    // finalized relay carrier on shared `dual_id` stays valid!
    // Attempting a return-to-direct (`rc:overlay.path_trial_return_request`) MUST be
    // immediately refused with `rc:overlay.path_trial_return_abort`!
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, "/network-zones"),
            admin,
            json!({
                "zones": [
                    {
                        "id": "cn",
                        "name": "CN",
                        "auto_countries": ["CN"],
                        "gateway_relay_ids": [dual_id],
                        "cross_zone_mode": "router_only"
                    },
                    {
                        "id": "hk",
                        "name": "HK",
                        "auto_countries": ["HK"],
                        "is_default": true,
                        "gateway_relay_ids": [dual_id],
                        "cross_zone_mode": "direct_preferred"
                    }
                ]
            }),
        )
        .await
        .0,
        200
    );
    let _ = recv_t(&mut cn_ws, "rc:overlay.netmap", wait).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.netmap", wait).await;

    let return_id = ObjectId::new().to_hex();
    cn_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.path_trial_return_request",
                "trial_id": trial_id,
                "return_id": return_id,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let abort = recv_t(&mut cn_ws, "rc:overlay.path_trial_return_abort", wait)
        .await
        .expect("server must refuse return-to-direct once pair becomes RouterOnly");
    assert_eq!(abort["trial_id"], json!(trial_id));
    assert_eq!(abort["return_id"], json!(return_id));
}

#[tokio::test]
async fn sota_bound_single_relay_continuous_upgrade_via_make_before_break_trial_and_cooldown() {
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-bound-upgrade").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);

    // Scale constants check (Upgrade 2A):
    assert_eq!(
        meshharbor_remote_control::models::peer_relay_limits::MAX_SESSIONS_PER_RELAY,
        256
    );
    assert_eq!(
        meshharbor_remote_control::models::MAX_PEER_RELAY_BACKBONE_EDGES,
        32
    );

    let (_a_id, a_tok) = enroll(&app, &seeded, "bu-leaf-a").await;
    let (_b_id, b_tok) = enroll(&app, &seeded, "bu-leaf-b").await;
    let (slow_id, slow_tok) = enroll(&app, &seeded, "bu-relay-slow").await;
    let (fast_id, fast_tok) = enroll(&app, &seeded, "bu-relay-fast").await;

    let mut a_ws = connect_from(&app, &a_tok, &[], Some("139.199.1.10")).await;
    let mut b_ws = connect_from(&app, &b_tok, &[], Some("139.199.1.11")).await;
    let mut slow_ws = connect_from(&app, &slow_tok, &["relay-server"], Some("139.199.6.1")).await;
    let mut fast_ws = connect_from(&app, &fast_tok, &["relay-server"], Some("139.199.6.2")).await;

    join_node(&mut a_ws, 91, "139.199.1.10:41641", json!({})).await;
    join_node(&mut b_ws, 92, "139.199.1.11:41641", json!({})).await;
    join_node(&mut slow_ws, 93, "139.199.6.1:41641", json!({ "relay_backbone_ready": true })).await;
    join_node(&mut fast_ws, 94, "139.199.6.2:41641", json!({ "relay_backbone_ready": true })).await;

    let a_node = node_id(&app, &seeded, "bu-leaf-a").await;
    let b_node = node_id(&app, &seeded, "bu-leaf-b").await;
    let slow_node = node_id(&app, &seeded, "bu-relay-slow").await;
    let fast_node = node_id(&app, &seeded, "bu-relay-fast").await;

    set_mode(&app, &seeded, "on").await;
    // Initially approve ONLY `slow_id` so the pair binds onto `slow_id`!
    assert_eq!(approve(&app, &seeded, &slow_id, true).await, 200);
    grant_relay(&app, &seeded, &slow_node).await;

    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, "/network-zones"),
            admin,
            json!({
                "zones": [
                    {
                        "id": "cn",
                        "name": "CN",
                        "auto_countries": ["CN"],
                        "is_default": true,
                        "gateway_relay_ids": [slow_id],
                        "cross_zone_mode": "router_only"
                    }
                ]
            }),
        )
        .await
        .0,
        200
    );
    let _ = recv_t(&mut a_ws, "rc:overlay.netmap", wait).await;
    let _ = recv_t(&mut b_ws, "rc:overlay.netmap", wait).await;

    a_ws.send(Message::Text(
        json!({
            "t": "rc:overlay.relay_request",
            "peer_node_id": b_node,
            "reason": "direct_timeout",
            "request_id": 1,
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let _ = recv_t(&mut slow_ws, "rc:overlay.relay_serve", wait).await.unwrap();
    let slow_sess = recv_t(&mut a_ws, "rc:overlay.relay_session", wait).await.unwrap();
    let _ = recv_t(&mut b_ws, "rc:overlay.relay_session", wait).await.unwrap();
    let slow_vni = slow_sess["vni"].as_u64().unwrap();
    assert_eq!(slow_sess["relay_node_id"], json!(slow_node));

    // Age `bind_by` so `slow_sess` is an established BOUND single-hop session!
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    let net = app.state.network();
    let a_oid = ObjectId::parse_str(&a_node).unwrap();
    let b_oid = ObjectId::parse_str(&b_node).unwrap();
    let slow_oid = ObjectId::parse_str(&slow_node).unwrap();
    let fast_oid = ObjectId::parse_str(&fast_node).unwrap();
    assert!(support::mark_session_bound_fixture(net, a_oid, b_oid));

    // Approve `fast_id` and add it to `"cn"` `gateway_relay_ids`.
    assert_eq!(approve(&app, &seeded, &fast_id, true).await, 200);
    grant_relay(&app, &seeded, &fast_node).await;
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, "/network-zones"),
            admin,
            json!({
                "zones": [
                    {
                        "id": "cn",
                        "name": "CN",
                        "auto_countries": ["CN"],
                        "is_default": true,
                        "gateway_relay_ids": [slow_id, fast_id],
                        "cross_zone_mode": "router_only"
                    }
                ]
            }),
        )
        .await
        .0,
        200
    );
    // Refresh netmaps so `a` and `b` receive probe offers for both `slow` and `fast`.
    let _ = join_node(&mut a_ws, 91, "139.199.1.10:41641", json!({})).await;
    let _ = join_node(&mut b_ws, 92, "139.199.1.11:41641", json!({})).await;

    // Send real `rc:overlay.relay_probe` measurements over `b_ws` and `a_ws`
    // (`slow` = 60ms + 60ms = 120ms, `fast` = 10ms + 10ms = 20ms) to trigger
    // `reoptimize_bound_sessions`! (20ms vs 120ms beats >=25% AND >=20ms!)
    let _ = (slow_oid, fast_oid);
    async fn send_probe(ws: &mut Ws, relay_id: &str, ep: &str, rtt: u32) {
        ws.send(Message::Text(
            json!({
                "t": "rc:overlay.relay_probe",
                "relay_node_id": relay_id,
                "endpoint": ep,
                "reachable": true,
                "rtt_ms": rtt
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    }
    send_probe(&mut a_ws, &slow_node, "139.199.6.1:3478", 60).await;
    send_probe(&mut b_ws, &slow_node, "139.199.6.1:3478", 60).await;
    send_probe(&mut b_ws, &fast_node, "139.199.6.2:3478", 10).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    send_probe(&mut a_ws, &fast_node, "139.199.6.2:3478", 10).await;

    // Verify bilateral make-before-break `OverlayPathTrialStart` is pushed for `fast_node`,
    // WITHOUT revoking `slow_vni` until BOTH peers commit!
    let _ = recv_t(&mut fast_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("fast relay receives trial serve");
    let start_a = recv_t(&mut a_ws, "rc:overlay.path_trial_start", wait)
        .await
        .expect("a receives bound upgrade path_trial_start");
    let _ = recv_t(&mut b_ws, "rc:overlay.path_trial_start", wait)
        .await
        .expect("b receives bound upgrade path_trial_start");
    assert_eq!(start_a["path"]["relay_node_ids"], json!([fast_node]));
    let trial_id = start_a["trial_id"].as_str().unwrap().to_string();

    // Complete bilateral Ready -> Commit -> Committed -> Finalize:
    for ws in [&mut a_ws, &mut b_ws] {
        ws.send(Message::Text(
            json!({ "t": "rc:overlay.path_trial_ready", "trial_id": trial_id })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    }
    let _ = recv_t(&mut a_ws, "rc:overlay.path_trial_commit", wait).await.unwrap();
    let _ = recv_t(&mut b_ws, "rc:overlay.path_trial_commit", wait).await.unwrap();
    for ws in [&mut a_ws, &mut b_ws] {
        ws.send(Message::Text(
            json!({ "t": "rc:overlay.path_trial_committed", "trial_id": trial_id })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    }
    let _ = recv_t(&mut a_ws, "rc:overlay.path_trial_finalize", wait).await.unwrap();
    let _ = recv_t(&mut b_ws, "rc:overlay.path_trial_finalize", wait).await.unwrap();

    // Once finalized, the superseded `slow_vni` session is cleanly retired on `slow_ws`!
    let slow_rev = recv_t(&mut slow_ws, "rc:overlay.relay_revoke", wait)
        .await
        .expect("superseded bound single-hop session retired after trial finalize");
    assert_eq!(slow_rev["vni"].as_u64(), Some(slow_vni));
}

#[tokio::test]
async fn composite_peer_relay_serve_revisions_cold_start_synthesis_and_concurrent_zone_policy_linearizability()
{
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-codex-r2").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);

    let (r_a_id, r_a_tok) = enroll(&app, &seeded, "r2-router-a").await;
    let (r_b_id, r_b_tok) = enroll(&app, &seeded, "r2-router-b").await;
    let (leaf_id, leaf_tok) = enroll(&app, &seeded, "r2-leaf").await;

    let mut r_a_ws =
        connect_from(&app, &r_a_tok, &["relay-server", "relay-control"], Some("202.181.7.6")).await;
    let mut r_b_ws =
        connect_from(&app, &r_b_tok, &["relay-server", "relay-control"], Some("8.8.4.4")).await;
    let leaf_ws = connect_from(&app, &leaf_tok, &[], Some("202.181.7.20")).await;

    // Drain initial `serve = false` frames.
    let init_a = recv_t(&mut r_a_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();
    let _ = recv_t(&mut r_b_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();
    let rev0 = init_a["revision"].as_u64().unwrap();

    // 1. Even BEFORE `zones` is configured, `peer_relay::set_policy` unconditionally
    //    bumps `zone_revision` and emits composite `(zone_revision << 24) | peer_relay_revision`.
    assert_eq!(approve(&app, &seeded, &r_a_id, true).await, 200);
    let approve_a = recv_t(&mut r_a_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();
    let rev1 = approve_a["revision"].as_u64().unwrap();
    assert!(rev1 >= (1_u64 << 24), "expected composite revision >= 1<<24, got {rev1}");
    assert!(rev1 > rev0);

    assert_eq!(approve(&app, &seeded, &r_b_id, true).await, 200);
    let _ = recv_t(&mut r_b_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();

    // 2. Configure zones putting `r_a` (HK) and `r_b` (US) in `"global"` and `"cn"` as `router_only`.
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, "/network-zones"),
            admin,
            json!({
                "zones": [
                    {
                        "id": "cn",
                        "name": "CN",
                        "auto_countries": ["CN"],
                        "is_default": false,
                        "gateway_relay_ids": [],
                        "cross_zone_mode": "router_only"
                    },
                    {
                        "id": "global",
                        "name": "Global",
                        "auto_countries": ["HK", "US"],
                        "is_default": true,
                        "gateway_relay_ids": [r_a_id, r_b_id],
                        "cross_zone_mode": "direct_preferred"
                    }
                ]
            }),
        )
        .await
        .0,
        200
    );
    let zones_a = recv_t(&mut r_a_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();
    let rev2 = zones_a["revision"].as_u64().unwrap();
    assert!(rev2 > rev1, "{rev2} <= {rev1}");
    assert_eq!(zones_a["backbone_endpoints"], json!(["8.8.4.4:3478"]));

    // 3. Cold-start reconnect of `r_a` receives synthesized `["8.8.4.4:3478"]` immediately on WS connect
    //    at the exact composite revision `rev2`!
    drop(r_a_ws);
    let mut r_a_ws =
        connect_from(&app, &r_a_tok, &["relay-server", "relay-control"], Some("202.181.7.6")).await;
    let reconn_a = recv_t(&mut r_a_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();
    assert_eq!(reconn_a["revision"].as_u64().unwrap(), rev2);
    assert_eq!(reconn_a["backbone_endpoints"], json!(["8.8.4.4:3478"]));

    // 4. Pin `r_b` cross-zone to `"cn"` -> `r_a` receives an empty `backbone_endpoints` list
    //    at a STRICTLY HIGHER composite revision `rev3 > rev2`!
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/agent/{r_b_id}/zone-assignment")),
            admin,
            json!({ "pinned_zone_id": "cn" }),
        )
        .await
        .0,
        200
    );
    let moved_a = recv_t(&mut r_a_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();
    let rev3 = moved_a["revision"].as_u64().unwrap();
    assert!(rev3 > rev2, "cross-zone router move must strictly advance revision: {rev3} <= {rev2}");
    assert!(moved_a["backbone_endpoints"].as_array().is_none_or(Vec::is_empty));

    // 5. Concurrent `set_zones` + `set_zone_assignment` moving `leaf` to `RouterOnly` `"cn"`
    //    always converges to `strict == true` in Hub `agent_zone_ice_policy`!
    let leaf_oid = ObjectId::parse_str(&leaf_id).unwrap();
    for round in 0..8 {
        assert_eq!(
            put(
                &app,
                &tenant_url(&seeded, &format!("/agent/{leaf_id}/zone-assignment")),
                admin,
                json!({ "pinned_zone_id": "global" }),
            )
            .await
            .0,
            200
        );
        let nz_url = tenant_url(&seeded, "/network-zones");
        let assign_url = tenant_url(&seeded, &format!("/agent/{leaf_id}/zone-assignment"));
        let zones_body = json!({
            "zones": [
                {
                    "id": "cn",
                    "name": format!("CN-{round}"),
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "global",
                    "name": format!("Global-{round}"),
                    "auto_countries": ["HK", "US"],
                    "is_default": true,
                    "gateway_relay_ids": [r_a_id],
                    "cross_zone_mode": "direct_preferred"
                }
            ]
        });
        let (r1, r2) = tokio::join!(
            put(&app, &nz_url, admin, zones_body),
            put(&app, &assign_url, admin, json!({ "pinned_zone_id": "cn" })),
        );
        assert_eq!(r1.0, 200);
        assert_eq!(r2.0, 200);
        let hub_pol = app
            .state
            .fleet()
            .rc_hub
            .agent_zone_ice_policy(leaf_oid)
            .expect("hub policy present");
        assert!(
            hub_pol.strict,
            "round {round}: concurrent set_zones + RouterOnly pin must never leave strict=false on Hub: {hub_pol:?}"
        );
    }

    drop(leaf_ws);
    drop(r_b_ws);
}
