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
                    "gateway_relay_ids": [relay_id],
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
    //    - FR-124: an ordinary member may NOT pin a device, not even their own
    //      (`403`). A zone is the admin's boundary; an owner who could move
    //      their device out of a strict zone would walk around it.
    //    - `MANAGE_AGENTS` pins any device.
    let member_assign_path =
        tenant_url(&seeded, &format!("/agent/{member_dev_id}/zone-assignment"));
    let admin_assign_path = tenant_url(&seeded, &format!("/agent/{admin_dev_id}/zone-assignment"));
    assert_eq!(
        put(
            &app,
            &admin_assign_path,
            member,
            json!({ "pinned_zone_id": "siat" })
        )
        .await
        .0,
        403
    );
    assert_eq!(
        put(
            &app,
            &member_assign_path,
            member,
            json!({ "pinned_zone_id": "SIAT" })
        )
        .await
        .0,
        403,
        "the owner of a device may not change its zone"
    );
    assert_eq!(
        put(
            &app,
            &member_assign_path,
            admin,
            json!({ "pinned_zone_id": "missing-zone" })
        )
        .await
        .0,
        400
    );
    let (s, assigned) = put(
        &app,
        &member_assign_path,
        admin,
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
        admin,
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
    // FR-134 requires a gateway at save time; approve a temporary US relay to save `"us"`, then
    // revoke its approval so `"us"` has no active gateway when step 8 tests `siat -> us_a` refusal.
    let (us_revoked_id, _) = enroll(&app, &seeded, "nz-us-revoked-gw").await;
    assert_eq!(approve(&app, &seeded, &us_revoked_id, true).await, 200);
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
                    "gateway_relay_ids": [us_revoked_id],
                    "cross_zone_mode": "direct_preferred"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(approve(&app, &seeded, &us_revoked_id, false).await, 200);

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
    // FR-124: the centre (this test's origin is `localhost`, no country) is
    // outside the strict `cn` zone, so even a same-zone pair may not relay
    // through it (until 0.4.189 this pair was allowed).
    assert!(
        !table.permits(&[11_u8; 32], &[12_u8; 32]),
        "same-zone cn <-> cn: the centre is outside the strict zone"
    );
    assert!(table.refuses_registration(&[11_u8; 32]));
    assert!(
        !table.refuses_registration(&[14_u8; 32]),
        "DirectPreferred hk keeps the centre"
    );
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

    // The pre-FR-125 graph, kept behind its kill switch: with
    // `relay_auto_links = false` cross-zone links exist only as approved
    // edges and a same-zone link takes the target's first endpoint.
    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.app.relay_auto_links = false;
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
    for _ in 0..3 {
        let _ = recv_t(&mut gz_ws, "rc:overlay.peer_relay_serve", wait).await;
    }
    for _ in 0..2 {
        let _ = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait).await;
    }
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

/// FR-125 — relays link freely by measurement; the zone is the only rule.
/// A mainland-zone relay `L` has two addresses: its first (what its own
/// connection shows) is an egress-only NAT abroad that admits nobody, its
/// second an entry that admits ONE source, gateway `A`. Nothing is approved
/// or declared per link. Two pairs `cn ↔ hk`, one asked for from each side,
/// must each ride `A ==(L's entry)==> L ==> B` — the measured fastest — with
/// `A` always the one that dials `L`: the link exists only in the direction
/// it was measured to work. Asked for again from the other side, a pair
/// keeps its session (the installed crossing stays authorized on reuse), and
/// a relay that reconnects is told the same dial allow-list a live push
/// gave it (the daemon ignores a same-revision update).
async fn a_one_way_line_between_zones_is_found_from_measurements_alone(auto_links: bool) -> bool {
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();
    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.app.relay_auto_links = auto_links;
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-one-way-line").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);
    let relay_caps = ["relay-server", "relay-control"];

    let (_, cn1_tok) = enroll(&app, &seeded, "ow-cn-dev1").await;
    let (_, hk1_tok) = enroll(&app, &seeded, "ow-hk-dev1").await;
    let (_, cn2_tok) = enroll(&app, &seeded, "ow-cn-dev2").await;
    let (_, hk2_tok) = enroll(&app, &seeded, "ow-hk-dev2").await;
    let (a_id, a_tok) = enroll(&app, &seeded, "ow-gw-a").await;
    let (l_id, l_tok) = enroll(&app, &seeded, "ow-line-l").await;
    let (b_id, b_tok) = enroll(&app, &seeded, "ow-gw-b").await;
    let mut cn1_ws = connect_from(&app, &cn1_tok, &[], Some("139.199.1.45")).await;
    let mut hk1_ws = connect_from(&app, &hk1_tok, &[], Some("202.181.7.20")).await;
    let mut cn2_ws = connect_from(&app, &cn2_tok, &[], Some("139.199.1.46")).await;
    let mut hk2_ws = connect_from(&app, &hk2_tok, &[], Some("202.181.7.21")).await;
    let mut a_ws = connect_from(&app, &a_tok, &relay_caps, Some("139.199.6.6")).await;
    let mut l_ws = connect_from(&app, &l_tok, &relay_caps, Some("139.199.9.1")).await;
    let mut b_ws = connect_from(&app, &b_tok, &relay_caps, Some("202.181.7.6")).await;
    for ws in [&mut a_ws, &mut l_ws, &mut b_ws] {
        let _ = recv_t(ws, "rc:overlay.peer_relay_serve", wait).await;
    }
    let ready = json!({ "relay_backbone_ready": true });
    join_node(&mut cn1_ws, 41, "139.199.1.45:41641", json!({})).await;
    join_node(&mut hk1_ws, 42, "202.181.7.20:41641", json!({})).await;
    join_node(&mut cn2_ws, 46, "139.199.1.46:41641", json!({})).await;
    join_node(&mut hk2_ws, 47, "202.181.7.21:41641", json!({})).await;
    join_node(&mut a_ws, 43, "139.199.6.6:41641", ready.clone()).await;
    // L's own connection shows its egress-only NAT abroad.
    join_node(&mut l_ws, 44, "202.181.7.50:41641", ready.clone()).await;
    join_node(&mut b_ws, 45, "202.181.7.6:41641", ready).await;
    let cn1_node = node_id(&app, &seeded, "ow-cn-dev1").await;
    let hk1_node = node_id(&app, &seeded, "ow-hk-dev1").await;
    let cn2_node = node_id(&app, &seeded, "ow-cn-dev2").await;
    let hk2_node = node_id(&app, &seeded, "ow-hk-dev2").await;
    let a_node = node_id(&app, &seeded, "ow-gw-a").await;
    let l_node = node_id(&app, &seeded, "ow-line-l").await;
    let b_node = node_id(&app, &seeded, "ow-gw-b").await;

    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &a_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &b_id, true).await, 200);
    // L: approved to serve, reachable (for whoever its entry admits) at its
    // entry. No edge, no direction, nothing about who may use it.
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/peer-relays/{l_id}")),
            admin,
            json!({ "serve": true, "static_endpoints": ["139.199.9.9:3478"] }),
        )
        .await
        .0,
        200
    );
    for n in [&a_node, &l_node, &b_node] {
        grant_relay(&app, &seeded, n).await;
    }
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({ "zones": [
            { "id": "cn", "name": "CN", "auto_countries": ["CN"], "is_default": false,
              "gateway_relay_ids": [a_id], "cross_zone_mode": "router_only" },
            { "id": "non-cn", "name": "Non-CN", "auto_countries": ["HK", "US"], "is_default": true,
              "gateway_relay_ids": [b_id], "cross_zone_mode": "direct_preferred" }
        ]}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    // A's last live directive: the allow-list a reconnect must repeat.
    let mut a_live = None;
    while let Some(m) = recv_t(
        &mut a_ws,
        "rc:overlay.peer_relay_serve",
        Duration::from_millis(1500),
    )
    .await
    {
        a_live = Some(m);
    }
    let a_live = a_live.expect("A is told its relay policy");

    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    let net = app.state.network();
    let oid = |s: &str| ObjectId::parse_str(s).unwrap();
    let (a, l, b) = (oid(&a_node), oid(&l_node), oid(&b_node));
    for (dev, gw, ep) in [
        (&cn1_node, a, "139.199.6.6:3478"),
        (&cn2_node, a, "139.199.6.6:3478"),
        (&hk1_node, b, "202.181.7.6:3478"),
        (&hk2_node, b, "202.181.7.6:3478"),
    ] {
        assert!(support::record_member_probe_fixture(
            net,
            oid(dev),
            &[(gw, ep.into(), true, Some(5))]
        ));
    }
    // A reaches L at its entry only, and B over the public path (slower).
    assert!(support::record_backbone_probe_fixture(
        net,
        a,
        &[
            (l, "202.181.7.50:3478".into(), false, None),
            (l, "139.199.9.9:3478".into(), true, Some(6)),
            (b, "202.181.7.6:3478".into(), true, Some(80)),
        ],
    ));
    // L reaches B through its egress; nothing reaches L from abroad.
    assert!(support::record_backbone_probe_fixture(
        net,
        l,
        &[(b, "202.181.7.6:3478".into(), true, Some(25))]
    ));
    assert!(support::record_backbone_probe_fixture(
        net,
        b,
        &[
            (l, "202.181.7.50:3478".into(), false, None),
            (l, "139.199.9.9:3478".into(), false, None),
        ],
    ));

    let request = |peer: &str, id: u64| {
        Message::Text(
            json!({ "t": "rc:overlay.relay_request", "peer_node_id": peer,
                    "reason": "direct_timeout", "request_id": id })
            .to_string()
            .into(),
        )
    };
    let mut carried = true;
    let mut pair1_vni = None;
    // Pair 1 asked for from the mainland side, pair 2 from abroad.
    for (from_cn, id) in [(true, 7u64), (false, 8u64)] {
        let (cn_ws, hk_ws) = if from_cn {
            (&mut cn1_ws, &mut hk1_ws)
        } else {
            (&mut cn2_ws, &mut hk2_ws)
        };
        if from_cn {
            cn_ws.send(request(&hk1_node, id)).await.unwrap();
        } else {
            hk_ws.send(request(&cn2_node, id)).await.unwrap();
        }
        let Some(_) = recv_t(&mut a_ws, "rc:overlay.relay_serve", wait).await else {
            carried = false;
            break;
        };
        let a_bridge = recv_t(&mut a_ws, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("A dials the line");
        assert_eq!(
            a_bridge["bridge"]["remote_endpoint"],
            json!("139.199.9.9:3478"),
            "A must dial L at the address it measured reachable, not L's first: {a_bridge}"
        );
        let _ = recv_t(&mut l_ws, "rc:overlay.relay_serve", wait)
            .await
            .expect("L serves");
        let l_bridge = recv_t(&mut l_ws, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("L dials B");
        assert_eq!(
            l_bridge["bridge"]["remote_endpoint"],
            json!("202.181.7.6:3478")
        );
        let _ = recv_t(&mut b_ws, "rc:overlay.relay_serve", wait)
            .await
            .expect("B serves");
        let cn_sess = recv_t(cn_ws, "rc:overlay.relay_session", wait)
            .await
            .expect("cn session");
        let hk_sess = recv_t(hk_ws, "rc:overlay.relay_session", wait)
            .await
            .expect("hk session");
        assert_eq!(cn_sess["relay_node_id"], json!(a_node));
        assert_eq!(hk_sess["relay_node_id"], json!(b_node));
        if from_cn {
            pair1_vni = Some(hk_sess["vni"].clone());
        }
        assert!(
            recv_t(
                &mut b_ws,
                "rc:overlay.relay_bridge_serve",
                Duration::from_millis(300)
            )
            .await
            .is_none(),
            "B is never asked to dial L: nothing reaches L from abroad"
        );
    }
    if carried {
        // Another of L's addresses now measures faster from A. That is a
        // preference for the NEXT mint, never a reason to tear this one down.
        // (The fixture replaces A's offers, so it names both of L's addresses.)
        assert!(support::record_backbone_probe_fixture(
            net,
            a,
            &[
                (l, "139.199.9.9:3478".into(), true, Some(6)),
                (l, "202.181.7.50:3478".into(), true, Some(3)),
            ]
        ));
        // Pair 1 again, now from abroad: the same session comes back and no
        // relay hears anything — the crossing is still authorized.
        hk1_ws.send(request(&cn1_node, 9)).await.unwrap();
        let again = recv_t(&mut hk1_ws, "rc:overlay.relay_session", wait)
            .await
            .expect("re-push to the asker");
        assert_eq!(Some(again["vni"].clone()), pair1_vni, "{again}");
        for ws in [&mut a_ws, &mut l_ws, &mut b_ws] {
            assert!(
                recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(500))
                    .await
                    .is_none(),
                "a repeat request must not re-mint the line"
            );
        }
        // P4: A measures L's entry down (a probe round, or the re-measure
        // after a bridge's remote leg failed). Both pairs ride that hop, so
        // both are revoked at once and their members ask again.
        a_ws.send(Message::Text(
            json!({ "t": "rc:overlay.relay_probe", "relay_node_id": l_node,
                    "endpoint": "139.199.9.9:3478", "reachable": false })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        for ws in [&mut cn1_ws, &mut cn2_ws] {
            assert!(
                recv_t(ws, "rc:overlay.relay_revoke", wait).await.is_some(),
                "a link measured down revokes the sessions that ride it"
            );
        }
    }

    // A reconnects: told exactly what the live push told it.
    drop(a_ws);
    let mut a_ws = connect_from(&app, &a_tok, &relay_caps, Some("139.199.6.6")).await;
    let reconnect = recv_t(&mut a_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .expect("A's policy on connect");
    assert_eq!(
        reconnect["revision"], a_live["revision"],
        "{reconnect} vs {a_live}"
    );
    assert_eq!(
        reconnect["backbone_endpoints"], a_live["backbone_endpoints"],
        "connect-time and live allow-lists must agree"
    );
    // Every address of the same-zone relay and the other zone's gateway; the
    // pre-FR-125 entry (L's first address) always comes first.
    let mut got: Vec<&str> = a_live["backbone_endpoints"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(got.first(), Some(&"202.181.7.50:3478"), "{a_live}");
    got.sort_unstable();
    let want: &[&str] = if auto_links {
        &["139.199.9.9:3478", "202.181.7.50:3478", "202.181.7.6:3478"]
    } else {
        &["202.181.7.50:3478"]
    };
    assert_eq!(got, want, "{a_live}");
    carried
}

/// FR-125 — a pair already riding a slower crossing moves to the line once
/// the line is measured: relentless re-upgrade, not "first mint wins". `A`
/// first reaches `B` directly (80 ms); `L` has not yet measured `B`. When
/// `L` reports `B` at 25 ms, the bound session is weighed again and a
/// make-before-break trial over `A ==> L ==> B` starts.
#[tokio::test]
async fn a_pair_on_a_slower_crossing_moves_to_the_line_once_it_is_measured() {
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
    let seeded = app.seed_tenant("nz-line-upgrade").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);
    let caps = ["relay-server", "relay-control"];
    let (_, cn_tok) = enroll(&app, &seeded, "up-cn-dev").await;
    let (_, hk_tok) = enroll(&app, &seeded, "up-hk-dev").await;
    let (a_id, a_tok) = enroll(&app, &seeded, "up-gw-a").await;
    let (l_id, l_tok) = enroll(&app, &seeded, "up-line-l").await;
    let (b_id, b_tok) = enroll(&app, &seeded, "up-gw-b").await;
    let mut cn_ws = connect_from(&app, &cn_tok, &[], Some("139.199.1.45")).await;
    let mut hk_ws = connect_from(&app, &hk_tok, &[], Some("202.181.7.20")).await;
    let mut a_ws = connect_from(&app, &a_tok, &caps, Some("139.199.6.6")).await;
    let mut l_ws = connect_from(&app, &l_tok, &caps, Some("139.199.9.1")).await;
    let mut b_ws = connect_from(&app, &b_tok, &caps, Some("202.181.7.6")).await;
    for ws in [&mut a_ws, &mut l_ws, &mut b_ws] {
        let _ = recv_t(ws, "rc:overlay.peer_relay_serve", wait).await;
    }
    let ready = json!({ "relay_backbone_ready": true });
    join_node(&mut cn_ws, 51, "139.199.1.45:41641", json!({})).await;
    join_node(&mut hk_ws, 52, "202.181.7.20:41641", json!({})).await;
    join_node(&mut a_ws, 53, "139.199.6.6:41641", ready.clone()).await;
    join_node(&mut l_ws, 54, "202.181.7.50:41641", ready.clone()).await;
    join_node(&mut b_ws, 55, "202.181.7.6:41641", ready).await;
    let cn_node = node_id(&app, &seeded, "up-cn-dev").await;
    let hk_node = node_id(&app, &seeded, "up-hk-dev").await;
    let a_node = node_id(&app, &seeded, "up-gw-a").await;
    let l_node = node_id(&app, &seeded, "up-line-l").await;
    let b_node = node_id(&app, &seeded, "up-gw-b").await;
    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &a_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &b_id, true).await, 200);
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/peer-relays/{l_id}")),
            admin,
            json!({ "serve": true, "static_endpoints": ["139.199.9.9:3478"] }),
        )
        .await
        .0,
        200
    );
    for n in [&a_node, &l_node, &b_node] {
        grant_relay(&app, &seeded, n).await;
    }
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({ "zones": [
            { "id": "cn", "name": "CN", "auto_countries": ["CN"], "is_default": false,
              "gateway_relay_ids": [a_id], "cross_zone_mode": "router_only" },
            { "id": "non-cn", "name": "Non-CN", "auto_countries": ["HK", "US"], "is_default": true,
              "gateway_relay_ids": [b_id], "cross_zone_mode": "direct_preferred" }
        ]}),
    )
    .await;
    assert_eq!(s, 200, "{body}");

    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    let net = app.state.network();
    let oid = |s: &str| ObjectId::parse_str(s).unwrap();
    let (cn, hk, a, l, b) = (
        oid(&cn_node),
        oid(&hk_node),
        oid(&a_node),
        oid(&l_node),
        oid(&b_node),
    );
    assert!(support::record_member_probe_fixture(
        net,
        cn,
        &[(a, "139.199.6.6:3478".into(), true, Some(5))]
    ));
    assert!(support::record_member_probe_fixture(
        net,
        hk,
        &[(b, "202.181.7.6:3478".into(), true, Some(5))]
    ));
    assert!(support::record_backbone_probe_fixture(
        net,
        a,
        &[
            (l, "139.199.9.9:3478".into(), true, Some(6)),
            (b, "202.181.7.6:3478".into(), true, Some(80)),
        ],
    ));
    // L is offered B but has nothing current that says it works.
    assert!(support::record_backbone_probe_fixture(
        net,
        l,
        &[(b, "202.181.7.6:3478".into(), false, None)]
    ));

    cn_ws
        .send(Message::Text(
            json!({ "t": "rc:overlay.relay_request", "peer_node_id": hk_node,
                    "reason": "direct_timeout", "request_id": 7 })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let a_bridge = recv_t(&mut a_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("the first mint rides the crossing A measured");
    assert_eq!(
        a_bridge["bridge"]["remote_endpoint"],
        json!("202.181.7.6:3478"),
        "{a_bridge}"
    );
    let _ = recv_t(&mut cn_ws, "rc:overlay.relay_session", wait).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.relay_session", wait).await;
    assert!(support::mark_session_bound_fixture(net, cn, hk));

    // L now measures B, through its own exit, much faster.
    l_ws.send(Message::Text(
        json!({ "t": "rc:overlay.relay_probe", "relay_node_id": b_node,
                "endpoint": "202.181.7.6:3478", "reachable": true, "rtt_ms": 25 })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let start = recv_t(&mut cn_ws, "rc:overlay.path_trial_start", wait)
        .await
        .expect("the bound pair is weighed again and moves to the line");
    assert!(
        start.to_string().contains(&l_node),
        "the trial rides L: {start}"
    );
}

#[tokio::test]
async fn a_one_way_line_between_zones_carries_the_pair_from_either_side() {
    assert!(a_one_way_line_between_zones_is_found_from_measurements_alone(true).await);
}

#[tokio::test]
async fn without_auto_links_the_same_line_carries_nothing() {
    assert!(!a_one_way_line_between_zones_is_found_from_measurements_alone(false).await);
}

/// FR-125 field case: the pair's own ends are the zones' gateways
/// (self-relay ends), the line `L` is pinned into A's zone and reached only
/// at its static entry, and B lets `L` in only on an alternate port. A
/// measures B directly at 231 ms; A -> L -> B measures 6 + 25 ms. The mint
/// takes the line.
#[tokio::test]
async fn a_gateway_pair_takes_the_line_over_a_slower_direct_crossing() {
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
    let seeded = app.seed_tenant("nz-gw-line").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);
    let caps = ["relay-server", "relay-control"];
    let (a_id, a_tok) = enroll(&app, &seeded, "gl-gw-a").await;
    let (l_id, l_tok) = enroll(&app, &seeded, "gl-line-l").await;
    let (b_id, b_tok) = enroll(&app, &seeded, "gl-gw-b").await;
    let mut a_ws = connect_from(&app, &a_tok, &caps, Some("139.199.6.6")).await;
    // L's own connection shows its egress abroad; its zone is pinned below.
    let mut l_ws = connect_from(&app, &l_tok, &caps, Some("202.181.7.50")).await;
    let mut b_ws = connect_from(&app, &b_tok, &caps, Some("202.181.7.6")).await;
    for ws in [&mut a_ws, &mut l_ws, &mut b_ws] {
        let _ = recv_t(ws, "rc:overlay.peer_relay_serve", wait).await;
    }
    let ready = json!({ "relay_backbone_ready": true });
    join_node(&mut a_ws, 61, "139.199.6.6:41641", ready.clone()).await;
    join_node(&mut l_ws, 62, "202.181.7.50:41641", ready.clone()).await;
    join_node(&mut b_ws, 63, "202.181.7.6:41641", ready).await;
    let a_node = node_id(&app, &seeded, "gl-gw-a").await;
    let l_node = node_id(&app, &seeded, "gl-line-l").await;
    let b_node = node_id(&app, &seeded, "gl-gw-b").await;
    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &a_id, true).await, 200);
    for (id, entry) in [(&l_id, "139.199.9.9:3478"), (&b_id, "202.181.7.6:3479")] {
        assert_eq!(
            put(
                &app,
                &tenant_url(&seeded, &format!("/peer-relays/{id}")),
                admin,
                json!({ "serve": true, "static_endpoints": [entry] }),
            )
            .await
            .0,
            200
        );
    }
    for n in [&a_node, &l_node, &b_node] {
        grant_relay(&app, &seeded, n).await;
    }
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({ "zones": [
            { "id": "cn", "name": "CN", "auto_countries": ["CN"], "is_default": false,
              "gateway_relay_ids": [a_id], "cross_zone_mode": "router_only" },
            { "id": "non-cn", "name": "Non-CN", "auto_countries": ["HK", "US"], "is_default": true,
              "gateway_relay_ids": [b_id], "cross_zone_mode": "direct_preferred" }
        ]}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/agent/{l_id}/zone-assignment")),
            admin,
            json!({ "pinned_zone_id": "cn" }),
        )
        .await
        .0,
        200
    );
    for ws in [&mut a_ws, &mut l_ws, &mut b_ws] {
        while recv_t(
            ws,
            "rc:overlay.peer_relay_serve",
            Duration::from_millis(800),
        )
        .await
        .is_some()
        {}
    }

    // As in the field: each relay rejoins under the final policy (that join's
    // netmap is what offers it its lines), then reports what it measured over
    // the wire — no fixture decides what the server accepts.
    let ready = json!({ "relay_backbone_ready": true });
    join_node(&mut a_ws, 61, "139.199.6.6:41641", ready.clone()).await;
    join_node(&mut l_ws, 62, "202.181.7.50:41641", ready.clone()).await;
    join_node(&mut b_ws, 63, "202.181.7.6:41641", ready).await;
    for ws in [&mut a_ws, &mut l_ws, &mut b_ws] {
        while recv_t(ws, "rc:overlay.netmap", Duration::from_millis(500))
            .await
            .is_some()
        {}
    }
    let report = |relay: &str, endpoint: &str, rtt: Option<u32>| {
        let mut m = json!({ "t": "rc:overlay.relay_probe", "relay_node_id": relay,
                            "endpoint": endpoint, "reachable": rtt.is_some() });
        if let Some(rtt) = rtt {
            m["rtt_ms"] = json!(rtt);
            m["jitter_ms"] = json!(0);
            m["loss_permille"] = json!(0);
        }
        Message::Text(m.to_string().into())
    };
    for m in [
        report(&l_node, "139.199.9.9:3478", Some(6)),
        report(&b_node, "202.181.7.6:3478", Some(231)),
        report(&b_node, "202.181.7.6:3479", Some(242)),
    ] {
        a_ws.send(m).await.unwrap();
    }
    // L's egress drops the usual port; B's alternate one lets it in.
    for m in [
        report(&a_node, "139.199.6.6:3478", None),
        report(&b_node, "202.181.7.6:3478", None),
        report(&b_node, "202.181.7.6:3479", Some(25)),
    ] {
        l_ws.send(m).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Field 2026-11-22: every relay link a node brings up re-advertises its
    // addresses (a new local port, the same address). Each one reset the
    // node's measurement cutoff, so a link into it counted only if measured
    // in the last few seconds and the line was never chosen. Re-adverts that
    // keep a node's addresses keep its measurements.
    for port in [41700, 41701] {
        b_ws.send(Message::Text(
            json!({ "t": "rc:overlay.endpoints",
                    "candidates": [format!("202.181.7.6:{port}")] })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        b_ws.send(Message::Text(
            json!({ "t": "rc:overlay.srflx",
                    "candidates": [format!("202.181.7.6:{port}")] })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    a_ws.send(Message::Text(
        json!({ "t": "rc:overlay.relay_request", "peer_node_id": b_node,
                "reason": "direct_timeout", "request_id": 9 })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let a_bridge = recv_t(&mut a_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("A bridges the pair's first leg");
    assert_eq!(
        a_bridge["bridge"]["remote_endpoint"],
        json!("139.199.9.9:3478"),
        "A's leg goes to the line, not straight across: {a_bridge}"
    );
    let l_bridge = recv_t(&mut l_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("L bridges the crossing");
    assert_eq!(
        l_bridge["bridge"]["remote_endpoint"],
        json!("202.181.7.6:3479"),
        "{l_bridge}"
    );
}

/// FR-125 — a relay that others reach at one address but that cannot dial
/// out (an entry-only forward, an egress that drops the relay port) is still
/// reachable as a device: its own pairs end at itself, the leg into it dialed
/// by the relay before it. It is not one of its zone's gateways, so the hop
/// beside it must stay in its zone — it never becomes the zone's border.
#[tokio::test]
async fn a_relay_that_cannot_dial_out_is_reached_at_its_entry() {
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
    let seeded = app.seed_tenant("nz-entry-only").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);
    let caps = ["relay-server", "relay-control"];
    let (_, d_tok) = enroll(&app, &seeded, "eo-cn-dev").await;
    let (g_id, g_tok) = enroll(&app, &seeded, "eo-gw-g").await;
    let (l_id, l_tok) = enroll(&app, &seeded, "eo-line-l").await;
    let (b_id, b_tok) = enroll(&app, &seeded, "eo-gw-b").await;
    let mut d_ws = connect_from(&app, &d_tok, &[], Some("139.199.1.45")).await;
    let mut g_ws = connect_from(&app, &g_tok, &caps, Some("139.199.6.6")).await;
    let mut l_ws = connect_from(&app, &l_tok, &caps, Some("202.181.7.50")).await;
    let mut b_ws = connect_from(&app, &b_tok, &caps, Some("202.181.7.6")).await;
    for ws in [&mut g_ws, &mut l_ws, &mut b_ws] {
        let _ = recv_t(ws, "rc:overlay.peer_relay_serve", wait).await;
    }
    let ready = json!({ "relay_backbone_ready": true });
    join_node(&mut d_ws, 71, "139.199.1.45:41641", json!({})).await;
    join_node(&mut g_ws, 72, "139.199.6.6:41641", ready.clone()).await;
    join_node(&mut l_ws, 73, "202.181.7.50:41641", ready.clone()).await;
    join_node(&mut b_ws, 74, "202.181.7.6:41641", ready.clone()).await;
    let d_node = node_id(&app, &seeded, "eo-cn-dev").await;
    let g_node = node_id(&app, &seeded, "eo-gw-g").await;
    let l_node = node_id(&app, &seeded, "eo-line-l").await;
    let b_node = node_id(&app, &seeded, "eo-gw-b").await;
    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &g_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &b_id, true).await, 200);
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/peer-relays/{l_id}")),
            admin,
            json!({ "serve": true, "static_endpoints": ["139.199.9.9:3478"] }),
        )
        .await
        .0,
        200
    );
    for n in [&g_node, &l_node, &b_node] {
        grant_relay(&app, &seeded, n).await;
    }
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({ "zones": [
            { "id": "cn", "name": "CN", "auto_countries": ["CN"], "is_default": false,
              "gateway_relay_ids": [g_id], "cross_zone_mode": "router_only" },
            { "id": "non-cn", "name": "Non-CN", "auto_countries": ["HK", "US"], "is_default": true,
              "gateway_relay_ids": [b_id], "cross_zone_mode": "router_only" }
        ]}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, &format!("/agent/{l_id}/zone-assignment")),
            admin,
            json!({ "pinned_zone_id": "cn" }),
        )
        .await
        .0,
        200
    );
    // Rejoin under the final policy (that join's netmap offers the lines),
    // then drain what the policy changes pushed.
    join_node(&mut g_ws, 72, "139.199.6.6:41641", ready.clone()).await;
    join_node(&mut l_ws, 73, "202.181.7.50:41641", ready.clone()).await;
    join_node(&mut b_ws, 74, "202.181.7.6:41641", ready).await;
    for ws in [&mut d_ws, &mut g_ws, &mut l_ws, &mut b_ws] {
        while recv_t(ws, "rc:overlay.netmap", Duration::from_millis(400))
            .await
            .is_some()
        {}
    }

    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    let net = app.state.network();
    let oid = |s: &str| ObjectId::parse_str(s).unwrap();
    let (d, g, l) = (oid(&d_node), oid(&g_node), oid(&l_node));
    // The device reaches its gateway; L reaches nothing on the relay port.
    assert!(support::record_member_probe_fixture(
        net,
        d,
        &[(g, "139.199.6.6:3478".into(), true, Some(5))]
    ));
    assert!(support::record_member_probe_fixture(
        net,
        l,
        &[(g, "139.199.6.6:3478".into(), false, None)]
    ));
    let report = |relay: &str, endpoint: &str, rtt: Option<u32>| {
        let mut m = json!({ "t": "rc:overlay.relay_probe", "relay_node_id": relay,
                            "endpoint": endpoint, "reachable": rtt.is_some() });
        if let Some(rtt) = rtt {
            m["rtt_ms"] = json!(rtt);
            m["jitter_ms"] = json!(0);
            m["loss_permille"] = json!(0);
        }
        Message::Text(m.to_string().into())
    };
    // The gateway reaches L at its entry; L dials out to nothing; the far
    // gateway reaches L's entry too (a crossing straight into L).
    g_ws.send(report(&l_node, "139.199.9.9:3478", Some(6)))
        .await
        .unwrap();
    for m in [
        report(&g_node, "139.199.6.6:3478", None),
        report(&b_node, "202.181.7.6:3478", None),
    ] {
        l_ws.send(m).await.unwrap();
    }
    b_ws.send(report(&l_node, "139.199.9.9:3478", Some(30)))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let request = |peer: &str, id: u64| {
        Message::Text(
            json!({ "t": "rc:overlay.relay_request", "peer_node_id": peer,
                    "reason": "direct_timeout", "request_id": id })
            .to_string()
            .into(),
        )
    };

    // 1. Same zone: device -> gateway -> L, L ending its own path.
    d_ws.send(request(&l_node, 1)).await.unwrap();
    let d_sess = recv_t(&mut d_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("the device rides its gateway to L");
    assert_eq!(d_sess["relay_node_id"], json!(g_node), "{d_sess}");
    let g_bridge = recv_t(&mut g_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("the gateway dials L's entry");
    assert_eq!(
        g_bridge["bridge"]["remote_endpoint"],
        json!("139.199.9.9:3478"),
        "{g_bridge}"
    );
    let l_sess = recv_t(&mut l_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("L ends the path at itself");
    assert_eq!(l_sess["relay_node_id"], json!(l_node), "{l_sess}");
    assert_eq!(l_sess["relay_endpoints"][0], json!("127.0.0.1:3478"));
    // Reuse within the bind window re-pushes; the reuse check applies the
    // same rule, so the session is not revoked.
    d_ws.send(request(&l_node, 2)).await.unwrap();
    let again = recv_t(&mut d_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("the live session is re-pushed");
    assert_eq!(again["vni"], d_sess["vni"], "{again}");
    assert!(
        recv_t(
            &mut d_ws,
            "rc:overlay.relay_revoke",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "reusing the session must not revoke it"
    );

    // 2. Across zones, with only the far gateway -> L measured: that crossing
    // would make L its zone's border, so it carries nothing.
    b_ws.send(request(&l_node, 3)).await.unwrap();
    assert!(
        recv_t(
            &mut l_ws,
            "rc:overlay.relay_session",
            Duration::from_millis(1500)
        )
        .await
        .is_none(),
        "a crossing straight into a non-gateway relay must not end its path"
    );

    // 3. Once the far gateway also measures this zone's gateway, the pair
    // crosses there and the gateway hands it to L inside the zone.
    b_ws.send(report(&g_node, "139.199.6.6:3478", Some(40)))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    b_ws.send(request(&l_node, 4)).await.unwrap();
    let b_bridge = recv_t(&mut b_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("the far gateway crosses to this zone's gateway");
    assert_eq!(
        b_bridge["bridge"]["remote_endpoint"],
        json!("139.199.6.6:3478"),
        "{b_bridge}"
    );
    let g_bridge = recv_t(&mut g_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("the gateway hands the pair to L");
    assert_eq!(
        g_bridge["bridge"]["remote_endpoint"],
        json!("139.199.9.9:3478"),
        "{g_bridge}"
    );
}

/// FR-125 — does relay `A` get the other zone's relay in its dial
/// allow-list under business isolation `isolation`? The same predicate as
/// the planner: legacy `enforce` keeps its own edge rules.
async fn an_other_zone_relay_is_dialable(isolation: &'static str) -> bool {
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();
    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = isolation.into();
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-auto-links-iso").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);
    let caps = ["relay-server", "relay-control"];
    let (a_id, a_tok) = enroll(&app, &seeded, "al-gw-hk").await;
    let (b_id, b_tok) = enroll(&app, &seeded, "al-gw-cn").await;
    let mut a_ws = connect_from(&app, &a_tok, &caps, Some("202.181.7.6")).await;
    let mut b_ws = connect_from(&app, &b_tok, &caps, Some("139.199.6.6")).await;
    let _ = recv_t(&mut a_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut b_ws, "rc:overlay.peer_relay_serve", wait).await;
    assert_eq!(approve(&app, &seeded, &a_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &b_id, true).await, 200);
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({ "zones": [
            { "id": "cn", "name": "CN", "auto_countries": ["CN"], "is_default": false,
              "gateway_relay_ids": [b_id], "cross_zone_mode": "router_only" },
            { "id": "global", "name": "Global", "auto_countries": ["HK", "US"], "is_default": true,
              "gateway_relay_ids": [a_id], "cross_zone_mode": "direct_preferred" }
        ]}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let mut last = None;
    while let Some(m) = recv_t(
        &mut a_ws,
        "rc:overlay.peer_relay_serve",
        Duration::from_millis(1500),
    )
    .await
    {
        last = Some(m);
    }
    let last = last.expect("A is told its relay policy");
    last["backbone_endpoints"]
        .as_array()
        .is_some_and(|eps| eps.contains(&json!("139.199.6.6:3478")))
}

#[tokio::test]
async fn legacy_enforce_keeps_relays_to_their_own_zone_and_off_links_across() {
    assert!(an_other_zone_relay_is_dialable("off").await);
    assert!(!an_other_zone_relay_is_dialable("enforce").await);
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
    let (cn_gw_id, _) = enroll(&app, &seeded, "nz-roam-cn-gw").await;

    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &hk_relay_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &cn_gw_id, true).await, 200);

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
                    "gateway_relay_ids": [cn_gw_id],
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
    let approve_a_after_b = recv_t(&mut r_a_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .unwrap();
    let rev1_b = approve_a_after_b["revision"].as_u64().unwrap();
    assert!(rev1_b > rev1);
    let rev1 = rev1_b;
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
                        "gateway_relay_ids": [r_b_id],
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

    // 4. Pin `r_b` cross-zone to `"cn"` -> `r_a` is re-told at a STRICTLY HIGHER
    //    composite revision `rev3 > rev2`. FR-125: relays link across zones too
    //    (the zone rule applies where a pair's path is built), so `r_b` stays in
    //    `r_a`'s list; without auto links it would leave it (the legacy test
    //    `router_topology_same_zone_auto_mesh_vs_cross_zone_explicit_private_link`).
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
    assert_eq!(moved_a["backbone_endpoints"], json!(["8.8.4.4:3478"]));

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
                    "gateway_relay_ids": [r_b_id],
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

#[tokio::test]
async fn gateway_routers_usable_as_endpoint_devices_across_zones_via_terminal_self_relay() {
    let geo = tempfile::tempdir().unwrap();
    let mmdb = geo.path().join("dbip-city-lite.mmdb");
    std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
    let mmdb = mmdb.to_str().unwrap().to_owned();

    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        // Exercise enforced business isolation (`Side` scopes) AND NAT-mapped
        // static endpoint ports (`139.199.6.6:443` while local listener is `:3478`).
        s.app.business_isolation = "enforce".into();
        s.stats.geoip_mmdb = Some(mmdb);
    })
    .await;
    let seeded = app.seed_tenant("nz-gw-endpoint").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);

    let (_siat_id, siat_tok) = enroll(&app, &seeded, "gwep-siat45").await;
    let (_hk_leaf_id, hk_leaf_tok) = enroll(&app, &seeded, "gwep-isvoro-hk").await;
    let (gz_id, gz_tok) = enroll(&app, &seeded, "gwep-po0-gz").await;
    let (hk_id, hk_tok) = enroll(&app, &seeded, "gwep-po0-hk").await;

    let mut siat_ws = connect_from(&app, &siat_tok, &[], Some("139.199.1.45")).await;
    let mut hk_leaf_ws = connect_from(&app, &hk_leaf_tok, &[], Some("202.181.7.20")).await;
    let mut gz_ws =
        connect_from(&app, &gz_tok, &["relay-server", "relay-control"], Some("139.199.6.6")).await;
    let mut hk_ws =
        connect_from(&app, &hk_tok, &["relay-server", "relay-control"], Some("202.181.7.6")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let _ = recv_t(&mut gz_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait).await;

    let full_caps = json!({
        "supports_path_trial_v1": true,
        "supports_path_backbone_v1": true,
        "supports_backbone_only_v1": true,
    });
    let gw_caps = json!({
        "relay_backbone_ready": true,
        "relay_port": 3478,
        "supports_path_trial_v1": true,
        "supports_path_backbone_v1": true,
        "supports_backbone_only_v1": true,
    });
    join_node(&mut siat_ws, 71, "139.199.1.45:41641", full_caps.clone()).await;
    join_node(&mut hk_leaf_ws, 72, "202.181.7.20:41641", full_caps).await;
    // Give `po0-gz` only a private LAN candidate on join + a NAT-mapped `:443`
    // static endpoint in policy, proving loopback bind uses listener port `:3478`!
    join_node(&mut gz_ws, 73, "10.0.0.5:41641", gw_caps.clone()).await;
    join_node(&mut hk_ws, 74, "202.181.7.6:41641", gw_caps).await;

    let siat_node = node_id(&app, &seeded, "gwep-siat45").await;
    let hk_leaf_node = node_id(&app, &seeded, "gwep-isvoro-hk").await;
    let gz_node = node_id(&app, &seeded, "gwep-po0-gz").await;
    let hk_node = node_id(&app, &seeded, "gwep-po0-hk").await;

    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &gz_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &hk_id, true).await, 200);
    grant_relay(&app, &seeded, &gz_node).await;
    grant_relay(&app, &seeded, &hk_node).await;
    let _ = recv_t(&mut gz_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait).await;

    // Configure CN (`po0-gz` sole gateway, `router_only`) <-> Non-CN (`po0-hk` gateway, `router_only`)
    // linked via Tencent private network `172.31.8.41:3478 <-> 10.42.2.114:3478`.
    assert_eq!(
        put(
            &app,
            &tenant_url(&seeded, "/network-zones"),
            admin,
            json!({
                "zones": [
                    {
                        "id": "cn",
                        "name": "CN 区",
                        "auto_countries": ["CN"],
                        "is_default": false,
                        "gateway_relay_ids": [gz_id],
                        "cross_zone_mode": "router_only"
                    },
                    {
                        "id": "non-cn",
                        "name": "非 CN 区",
                        "auto_countries": ["HK", "US"],
                        "is_default": true,
                        "gateway_relay_ids": [hk_id],
                        "cross_zone_mode": "router_only"
                    }
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
            &tenant_url(&seeded, &format!("/peer-relays/{gz_id}")),
            admin,
            json!({
                "serve": true,
                "static_endpoints": ["139.199.6.6:443"],
                "approved_backbone_edges": [
                    { "relay_agent_id": hk_id, "endpoint": "10.42.2.114:3478", "cross_border": true }
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
                    { "relay_agent_id": gz_id, "endpoint": "172.31.8.41:3478", "cross_border": true }
                ]
            }),
        )
        .await
        .0,
        200
    );

    // 1. CN leaf `siat45` -> Non-CN gateway `po0-hk` mints 2-hop `[po0-gz, po0-hk]`
    //    where `po0-hk` acts as its own terminal exit relay over `127.0.0.1:3478`!
    siat_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": hk_node,
                "reason": "direct_timeout",
                "request_id": 101,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let siat_sess = recv_t(&mut siat_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("siat45 receives ingress leg on po0-gz");
    assert_eq!(siat_sess["relay_node_id"], json!(gz_node));
    let hk_self_sess = recv_t(&mut hk_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("po0-hk receives terminal self-relay leg on po0-hk");
    assert_eq!(hk_self_sess["relay_node_id"], json!(hk_node));
    assert_eq!(
        hk_self_sess["relay_endpoints"][0],
        json!("127.0.0.1:3478"),
        "terminal self-relay must prepend 127.0.0.1:3478: {hk_self_sess}"
    );
    // Probe report from `po0-hk` on `127.0.0.1:3478` must be accepted as minted!
    let hk_oid = ObjectId::parse_str(&hk_node).unwrap();
    assert!(app.state.network().org_relay.record_probe_with_sla(
        hk_oid,
        hk_oid,
        "127.0.0.1:3478".into(),
        true,
        Some(0),
        Some(0),
        Some(0),
    ));

    // 2. CN gateway `po0-gz` -> Non-CN leaf `isvoro-hk` mints 2-hop `[po0-gz, po0-hk]`
    //    where `po0-gz` acts as its own terminal ingress relay over `127.0.0.1:3478`!
    gz_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": hk_leaf_node,
                "reason": "direct_timeout",
                "request_id": 102,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let gz_self_sess = recv_t(&mut gz_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("po0-gz receives terminal self-relay leg on po0-gz");
    assert_eq!(gz_self_sess["relay_node_id"], json!(gz_node));
    assert_eq!(
        gz_self_sess["relay_endpoints"],
        json!(["127.0.0.1:3478", "139.199.6.6:443"]),
        "loopback bind must use listener port 3478 rather than NAT-mapped static port 443"
    );
    let hk_leaf_sess = recv_t(&mut hk_leaf_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("isvoro-hk receives exit leg on po0-hk");
    assert_eq!(hk_leaf_sess["relay_node_id"], json!(hk_node));

    // 3. CN gateway `po0-gz` <-> Non-CN gateway `po0-hk` mints 2-hop `[po0-gz, po0-hk]`
    //    where BOTH gateways bind their own local `127.0.0.1:3478`!
    gz_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.org_relay_discover",
                "peer_node_id": hk_node,
                "request_id": 103,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let disc = recv_t(&mut gz_ws, "rc:overlay.org_relay_candidates", wait)
        .await
        .expect("discover candidates for po0-gz -> po0-hk");
    let cands = disc["candidates"].as_array().expect("candidates array");
    assert!(
        cands.iter().any(|c| {
            c["path"]["relay_node_ids"] == json!([gz_node, hk_node])
                && c["endpoints"][0] == json!("127.0.0.1:3478")
        }),
        "discover must offer [po0-gz, po0-hk] with 127.0.0.1:3478 first: {cands:?}"
    );

    gz_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": hk_node,
                "reason": "direct_timeout",
                "request_id": 104,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let gz_to_hk_sess = recv_t(&mut gz_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("po0-gz receives self-relay leg for po0-gz <-> po0-hk");
    assert_eq!(gz_to_hk_sess["relay_node_id"], json!(gz_node));
    assert_eq!(gz_to_hk_sess["relay_endpoints"][0], json!("127.0.0.1:3478"));
    let hk_from_gz_sess = recv_t(&mut hk_ws, "rc:overlay.relay_session", wait)
        .await
        .expect("po0-hk receives self-relay leg for po0-gz <-> po0-hk");
    assert_eq!(hk_from_gz_sess["relay_node_id"], json!(hk_node));
    assert_eq!(hk_from_gz_sess["relay_endpoints"][0], json!("127.0.0.1:3478"));

    // 4. Same-zone `po0-gz -> siat45` (where `po0-gz` is the ONLY CN gateway) MUST NOT
    //    mint a 1-hop self-relay `[po0-gz]`!
    gz_ws
        .send(Message::Text(
            json!({
                "t": "rc:overlay.relay_request",
                "peer_node_id": siat_node,
                "reason": "direct_timeout",
                "request_id": 105,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    for _ in 0..40 {
        if audit_rows(&app, &seeded).await.iter().any(|r| {
            r["action"] == json!("mint")
                && r["requester_node_id"] == json!(gz_node)
                && r["peer_node_id"] == json!(siat_node)
                && r["denied"].is_string()
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        audit_rows(&app, &seeded).await.iter().any(|r| {
            r["action"] == json!("mint")
                && r["requester_node_id"] == json!(gz_node)
                && r["peer_node_id"] == json!(siat_node)
                && r["denied"].is_string()
        }),
        "1-hop self-relay must be refused even under NetworkZones"
    );

    // 5. `reconcile_acl` preserves all 3 active multi-hop terminal self-relay sessions!
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let gz_oid = ObjectId::parse_str(&gz_node).unwrap();
    assert!(meshharbor_mod_network::org_relay::reconcile_acl(app.state.network(), tid).await);
    assert_eq!(app.state.network().org_relay.sessions_on_relay(gz_oid), 3);
    assert_eq!(app.state.network().org_relay.sessions_on_relay(hk_oid), 3);
}

#[tokio::test]
async fn twenty_concurrent_overlay_joins_serialize_cleanly_without_store_unavailable_refusal() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("nz-concurrent-join-20").await;

    let mut sockets = Vec::with_capacity(20);
    for idx in 0..20u8 {
        let (_, tok) = enroll(&app, &seeded, &format!("cj-node-{idx:02}")).await;
        let ws = connect_from(&app, &tok, &[], None).await;
        sockets.push((idx, ws));
    }

    // Fire all 20 `rc:overlay.join` frames simultaneously (with `supports_join_refusal: true`)
    // simulating a 20-node fleet reconnecting on server restart!
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(20));
    let mut handles = Vec::with_capacity(20);
    for (idx, mut ws) in sockets {
        let bar = barrier.clone();
        handles.push(tokio::spawn(async move {
            let msg = json!({
                "t": "rc:overlay.join",
                "wg_public_key": BASE64.encode([100 + idx; 32]),
                "mtu": 1280,
                "endpoints": [format!("198.51.100.{}:41641", idx + 1)],
                "srflx_endpoints": [format!("198.51.100.{}:41641", idx + 1)],
                "supports_join_refusal": true,
                "supports_org_relay": true,
                "org_primary": true,
            });
            bar.wait().await;
            ws.send(Message::Text(msg.to_string().into()))
                .await
                .expect("send concurrent join");
            let netmap = recv_t(&mut ws, "rc:overlay.netmap", Duration::from_secs(10))
                .await
                .unwrap_or_else(|| panic!("node {idx} failed to receive netmap on concurrent join"));
            (ws, netmap)
        }));
    }

    let mut ips = std::collections::HashSet::new();
    let mut initial_views = Vec::with_capacity(20);
    for h in handles {
        let (ws, netmap) = h.await.expect("join task");
        let ip = netmap["self_ip"].as_str().unwrap_or_default().to_string();
        assert!(!ip.is_empty());
        assert!(ips.insert(ip.clone()), "duplicate overlay IP allocated");
        initial_views.push((ws, ip, netmap));
    }
    assert_eq!(ips.len(), 20, "all 20 concurrent joiners must succeed on first attempt");

    // Verify full peer-table convergence across all 20 nodes under strict
    // monotonic `auth_revision` acceptance (rejecting any out-of-order delta!).
    for (idx, (mut ws, self_ip, netmap)) in initial_views.into_iter().enumerate() {
        let mut rev = netmap["network"]["auth_revision"].as_u64().unwrap_or(0);
        let mut known_peers: std::collections::HashMap<String, String> = netmap["peers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| {
                Some((
                    p["node_id"].as_str()?.to_string(),
                    p["overlay_ip"].as_str()?.to_string(),
                ))
            })
            .collect();

        while known_peers.len() < 19 {
            let Some(frame) = recv_t(&mut ws, "rc:overlay.netmap_delta", Duration::from_secs(3)).await else {
                break;
            };
            let delta_rev = frame["auth_revision"].as_u64().unwrap_or(0);
            assert!(
                delta_rev >= rev,
                "node {idx} ({self_ip}) received out-of-order delta rev {delta_rev} < {rev}"
            );
            rev = delta_rev;
            if let Some(upserts) = frame["upserts"].as_array() {
                for u in upserts {
                    if let (Some(nid), Some(pip)) =
                        (u["node_id"].as_str(), u["overlay_ip"].as_str())
                    {
                        known_peers.insert(nid.to_string(), pip.to_string());
                    }
                }
            }
        }
        let mut expected = ips.clone();
        expected.remove(&self_ip);
        let got: std::collections::HashSet<String> = known_peers.into_values().collect();
        assert_eq!(
            got, expected,
            "node {idx} ({self_ip}) failed to converge to all 19 peer IPs"
        );
    }
}

/// Field, 2026-11-17: clients re-advertise unchanged srflx candidates on a
/// timer (every NAT keepalive), and every advert from a serving relay bumped
/// the tenant's zone and auth revisions and re-pushed every relay's
/// directive — 21 a minute with seven relays, and a join spanning one was
/// refused "authority changed before join netmap". A re-advert that moves
/// none of the relay's addresses now changes nothing; one that moves them
/// still re-publishes its same-zone peer's backbone endpoints.
#[tokio::test]
async fn an_unchanged_relay_readvert_does_not_bump_the_zone_revision() {
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
    let seeded = app.seed_tenant("nz-readvert").await;
    let admin = &seeded.admin.access_token;
    let wait = Duration::from_secs(5);
    let (hk_id, hk_tok) = enroll(&app, &seeded, "ra-po0-hk").await;
    let (hy_id, hy_tok) = enroll(&app, &seeded, "ra-hyonix-la").await;
    let caps = ["relay-server", "relay-control"];
    let mut hk_ws = connect_from(&app, &hk_tok, &caps, Some("202.181.7.6")).await;
    let mut hy_ws = connect_from(&app, &hy_tok, &caps, Some("8.8.4.4")).await;
    let _ = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait).await;
    let _ = recv_t(&mut hy_ws, "rc:overlay.peer_relay_serve", wait).await;
    let ready = json!({ "relay_backbone_ready": true });
    join_node(&mut hk_ws, 35, "202.181.7.6:41641", ready.clone()).await;
    join_node(&mut hy_ws, 36, "8.8.4.4:41641", ready).await;
    let hk_node = node_id(&app, &seeded, "ra-po0-hk").await;
    let hy_node = node_id(&app, &seeded, "ra-hyonix-la").await;
    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &hk_id, true).await, 200);
    assert_eq!(approve(&app, &seeded, &hy_id, true).await, 200);
    grant_relay(&app, &seeded, &hk_node).await;
    grant_relay(&app, &seeded, &hy_node).await;
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({ "zones": [{
            "id": "non-cn", "name": "Non-CN", "auto_countries": ["HK", "US"],
            "is_default": true, "gateway_relay_ids": [hk_id, hy_id],
            "cross_zone_mode": "direct_preferred"
        }]}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let quiet = Duration::from_millis(1500);
    // Settle: drain every directive the setup produced.
    while recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", quiet)
        .await
        .is_some()
    {}
    while recv_t(&mut hy_ws, "rc:overlay.peer_relay_serve", quiet)
        .await
        .is_some()
    {}
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let before = zone_and_auth_revision(&app, tid).await;

    let srflx =
        |ip: &str| json!({ "t": "rc:overlay.srflx", "candidates": [format!("{ip}:41641")] });
    for _ in 0..3 {
        hy_ws
            .send(Message::Text(srflx("8.8.4.4").to_string().into()))
            .await
            .unwrap();
    }
    assert!(
        recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", quiet)
            .await
            .is_none(),
        "an unchanged re-advert re-pushes no directive"
    );
    assert_eq!(
        zone_and_auth_revision(&app, tid).await,
        before,
        "nor bumps the revisions"
    );

    hy_ws
        .send(Message::Text(srflx("8.8.8.8").to_string().into()))
        .await
        .unwrap();
    let moved = recv_t(&mut hk_ws, "rc:overlay.peer_relay_serve", wait)
        .await
        .expect("a moved relay address re-publishes its peer's backbone endpoints");
    // FR-125: every address the relay holds is listed, the one its NAT now
    // exposes first; the relay's measurements say which still answers.
    assert_eq!(moved["backbone_endpoints"][0], json!("8.8.8.8:3478"), "{moved}");
    assert!(zone_and_auth_revision(&app, tid).await.0 > before.0);
}

async fn zone_and_auth_revision(app: &TestApp, tid: ObjectId) -> (u64, u64) {
    let n = app
        .state
        .network()
        .overlay_networks
        .find_for_tenant(tid)
        .await
        .unwrap()
        .unwrap();
    (n.zone_revision, n.auth_revision)
}

/// FR-124 — a zone is a boundary. A strict (`router_only`) zone whose
/// countries do not hold the centre rides no relay outside it: its rows toward
/// its OWN zone's peers carry no DERP tier, its nodes are told to open no
/// `/derp`, and the relay refuses their registration. A zone that is not
/// strict keeps the floor, and so does a strict zone whose countries DO hold
/// the centre (the same config with the centre's origin in CN).
#[tokio::test]
async fn a_strict_zone_rides_no_relay_outside_it_not_even_the_centres_derp() {
    for centre_in_cn in [false, true] {
        let geo = tempfile::tempdir().unwrap();
        let mmdb = geo.path().join("dbip-city-lite.mmdb");
        std::fs::write(&mmdb, city_fixture_mmdb()).unwrap();
        let mmdb = mmdb.to_str().unwrap().to_owned();
        let app = TestApp::spawn_with_settings(move |s| {
            s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
            s.app.rate_limit_trusted_hops = 0;
            s.app.business_isolation = "off".into();
            s.stats.geoip_mmdb = Some(mmdb);
            if centre_in_cn {
                // An IP literal geolocates without DNS (the fixture puts
                // 139.199.0.0/16 in CN).
                s.app.frontend_url = "http://139.199.9.9".into();
            }
        })
        .await;
        let seeded = app.seed_tenant("fr124-zone-boundary").await;
        let admin = &seeded.admin.access_token;
        let wait = Duration::from_secs(5);
        let (cn_a_id, cn_a_tok) = enroll(&app, &seeded, "fr124-cn-a").await;
        let (_cn_b_id, cn_b_tok) = enroll(&app, &seeded, "fr124-cn-b").await;
        let (_us_a_id, us_a_tok) = enroll(&app, &seeded, "fr124-us-a").await;
        let (_us_b_id, us_b_tok) = enroll(&app, &seeded, "fr124-us-b").await;
        let mut cn_a = connect_from(&app, &cn_a_tok, &[], Some("139.199.1.10")).await;
        let mut cn_b = connect_from(&app, &cn_b_tok, &[], Some("139.199.1.11")).await;
        let mut us_a = connect_from(&app, &us_a_tok, &[], Some("8.8.8.8")).await;
        let mut us_b = connect_from(&app, &us_b_tok, &[], Some("8.8.4.4")).await;
        let derp = json!({
            "supports_derp": true,
            "supports_derp_floor": true,
            "supports_forced_derp": true,
        });
        join_node(&mut cn_a, 41, "139.199.1.10:41641", derp.clone()).await;
        join_node(&mut cn_b, 42, "139.199.1.11:41641", derp.clone()).await;
        join_node(&mut us_a, 43, "8.8.8.8:41641", derp.clone()).await;
        join_node(&mut us_b, 44, "8.8.4.4:41641", derp.clone()).await;
        let cn_b_node = node_id(&app, &seeded, "fr124-cn-b").await;
        let us_b_node = node_id(&app, &seeded, "fr124-us-b").await;

        // No zones yet: the floor is offered (the control for what follows).
        let before = join_node(&mut cn_a, 41, "139.199.1.10:41641", derp.clone()).await;
        assert_eq!(
            find_peer(&before, &cn_b_node)["supports_derp"],
            json!(true),
            "{before}"
        );
        assert!(
            before["network"].get("central_relay_denied").is_none(),
            "{}",
            before["network"]
        );

        let (gw_id, _) = enroll(&app, &seeded, "fr124-gw").await;
        assert_eq!(approve(&app, &seeded, &gw_id, true).await, 200);
        let (s, body) = put(
            &app,
            &tenant_url(&seeded, "/network-zones"),
            admin,
            json!({ "zones": [
                { "id": "cn", "name": "Mainland China", "auto_countries": ["CN"],
                  "is_default": false, "gateway_relay_ids": [gw_id], "cross_zone_mode": "router_only" },
                { "id": "non-cn", "name": "Elsewhere", "auto_countries": [],
                  "is_default": true, "gateway_relay_ids": [gw_id], "cross_zone_mode": "direct_preferred" }
            ]}),
        )
        .await;
        assert_eq!(s, 200, "{body}");
        for ws in [&mut cn_a, &mut cn_b, &mut us_a, &mut us_b] {
            let _ = recv_t(ws, "rc:overlay.netmap", wait).await;
        }

        let cn_nm = join_node(&mut cn_a, 41, "139.199.1.10:41641", derp.clone()).await;
        let us_nm = join_node(&mut us_a, 43, "8.8.8.8:41641", derp.clone()).await;
        let cn_row = find_peer(&cn_nm, &cn_b_node);
        // The non-strict zone keeps its floor in both runs.
        assert_eq!(
            find_peer(&us_nm, &us_b_node)["supports_derp"],
            json!(true),
            "{us_nm}"
        );
        assert!(
            us_nm["network"].get("central_relay_denied").is_none(),
            "{}",
            us_nm["network"]
        );

        // The relay itself: a registration from the strict zone never enters
        // the registry when the centre is outside it, and does when inside.
        let pk_a = [41u8; 32];
        let _sock = {
            use tokio_tungstenite::connect_async;
            let (mut ws, _) = connect_async(&format!("ws://{}/derp?token={}", app.addr, cn_a_tok))
                .await
                .expect("derp WS");
            ws.send(Message::Binary(pk_a.to_vec().into()))
                .await
                .unwrap();
            ws
        };
        let mut registered = false;
        for _ in 0..30 {
            if app
                .state
                .network()
                .derp_registry
                .iter()
                .any(|e| e.key().1 == pk_a)
            {
                registered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if centre_in_cn {
            assert_eq!(
                cn_row["supports_derp"],
                json!(true),
                "centre inside the zone: {cn_nm}"
            );
            assert!(
                cn_nm["network"].get("central_relay_denied").is_none(),
                "{}",
                cn_nm["network"]
            );
            assert!(
                registered,
                "the centre is inside the zone: the registration stands"
            );
        } else {
            for key in [
                "supports_derp",
                "supports_derp_floor",
                "supports_forced_derp",
            ] {
                assert!(
                    cn_row.get(key).is_none_or(|v| v == &json!(false)),
                    "{key} offered inside a strict zone the centre is outside of: {cn_row}"
                );
            }
            assert_ne!(cn_row["relay_strategy"], json!("derp"), "{cn_row}");
            assert_eq!(
                cn_nm["network"]["central_relay_denied"],
                json!(true),
                "{}",
                cn_nm["network"]
            );
            assert!(
                !registered,
                "a strict zone's node is not registered at a centre outside it"
            );
        }
        let _ = cn_a_id;
    }
}

#[tokio::test]
async fn zone_backbone_endpoint_permissions_and_empty_state() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("nz-backbone-perm").await;
    let other = app.seed_tenant("nz-backbone-other").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let admin = &seeded.admin.access_token;
    let member = &seeded.member.access_token;
    let backbone_path = tenant_url(&seeded, "/network-zones/backbone");

    // Ordinary member (no MANAGE_AGENTS) and non-member get 403.
    assert_eq!(get_json(&app, &backbone_path, member).await.0, 403);
    assert_eq!(
        get_json(&app, &backbone_path, &other.admin.access_token)
            .await
            .0,
        403
    );

    // Grant MANAGE_AGENTS to member and confirm 200 OK with empty backbone
    // and without allocating an overlay_networks document.
    let mgr_role: Value = app
        .auth_post(&tenant_url(&seeded, "/role"), admin)
        .json(&json!({
            "name": "backbone-viewer",
            "permissions": meshharbor_db::models::role::permissions::MANAGE_AGENTS
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mgr_role_id = mgr_role["id"].as_str().unwrap();
    assert_eq!(
        app.auth_post(
            &tenant_url(
                &seeded,
                &format!("/role/{mgr_role_id}/assign/{}", seeded.member.id)
            ),
            admin,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16(),
        200
    );

    let (status, body) = get_json(&app, &backbone_path, member).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({
            "revision": 0,
            "zones": [],
            "gateways": [],
            "links": [],
        })
    );
    assert_eq!(
        app.db
            .collection::<bson::Document>("overlay_networks")
            .count_documents(doc! { "tenant_id": tid })
            .await
            .unwrap(),
        0,
        "GET /network-zones/backbone must not allocate an overlay_networks document"
    );
}

#[tokio::test]
async fn zone_backbone_endpoint_returns_zones_centre_live_entries_and_gateway_links() {
    use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

    let app = TestApp::spawn_with_settings(|s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.management_entries = true;
    })
    .await;
    let seeded = app.seed_tenant("nz-backbone-live").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let admin = &seeded.admin.access_token;

    // Enroll three approved gateways (centre, cn, eu) and one regular device in cn.
    let (gw_centre_id, gw_centre_tok) = enroll(&app, &seeded, "gateway-centre").await;
    let (gw_cn_id, gw_cn_tok) = enroll(&app, &seeded, "gateway-cn").await;
    let (gw_eu_id, _gw_eu_tok) = enroll(&app, &seeded, "gateway-eu").await;
    let (dev_cn_id, dev_cn_tok) = enroll(&app, &seeded, "device-cn").await;

    set_mode(&app, &seeded, "on").await;
    for gw in [&gw_centre_id, &gw_cn_id, &gw_eu_id] {
        assert_eq!(approve(&app, &seeded, gw, true).await, 200);
    }

    // Configure three zones: centre (is_centre=true), cn (router_only), eu (default).
    let (s, zones_resp) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        admin,
        json!({
            "zones": [
                {
                    "id": "centre",
                    "name": "Centre Hub",
                    "is_centre": true,
                    "is_default": false,
                    "cross_zone_mode": "direct_preferred",
                    "auto_countries": [],
                    "gateway_relay_ids": [gw_centre_id]
                },
                {
                    "id": "cn",
                    "name": "CN Mainland",
                    "is_centre": false,
                    "is_default": false,
                    "cross_zone_mode": "router_only",
                    "auto_countries": ["CN"],
                    "gateway_relay_ids": [gw_cn_id]
                },
                {
                    "id": "eu",
                    "name": "EU Region",
                    "is_centre": false,
                    "is_default": true,
                    "cross_zone_mode": "direct_preferred",
                    "auto_countries": ["DE"],
                    "gateway_relay_ids": [gw_eu_id]
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "PUT /network-zones: {zones_resp}");

    // Pin each device to its zone so device_count is deterministic without GeoIP MMDB.
    for (aid, zone) in [
        (&gw_centre_id, "centre"),
        (&gw_cn_id, "cn"),
        (&gw_eu_id, "eu"),
        (&dev_cn_id, "cn"),
    ] {
        let (ps, pbody) = put(
            &app,
            &tenant_url(&seeded, &format!("/agent/{aid}/zone-assignment")),
            admin,
            json!({ "pinned_zone_id": zone }),
        )
        .await;
        assert_eq!(ps, 200, "pin {aid}->{zone}: {pbody}");
    }

    // Helper to open an agent WS through loopback proxy with optional entry port & token.
    async fn open_agent_ws(
        app: &TestApp,
        token: &str,
        xff: &str,
        entry_port: Option<u16>,
        entry_token: Option<&str>,
    ) -> Ws {
        let mut ws_url = format!("ws://{}/ws?token={}&role=agent", app.addr, token);
        if let Some(et) = entry_token {
            ws_url.push_str("&entry=");
            ws_url.push_str(et);
        }
        let mut req = ws_url.into_client_request().expect("ws req");
        req.headers_mut()
            .insert("x-forwarded-for", xff.parse().expect("xff"));
        let (mut ws, _) = connect_async(req).await.expect("ws connect");
        let mut caps = json!({
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
            "rpc": ["management-path", "management-entry", "relay-server"]
        });
        if let Some(port) = entry_port {
            caps["management_entry_port"] = json!(port);
        }
        let hello = json!({
            "t": "rc:agent.hello",
            "machine_name": "backbone-node",
            "os": "linux",
            "agent_version": "0.4.210",
            "displays": [],
            "caps": caps
        });
        ws.send(Message::Text(hello.to_string().into()))
            .await
            .expect("send hello");
        let _ = recv_t(&mut ws, "rc:agent.management_path", Duration::from_secs(5))
            .await
            .expect("management_path fence");
        ws
    }

    // Connect gw-centre (online, relay serving turned OFF after zone save so its
    // centre role is exercised independently from forwarder/entry serving!) and
    // gw-cn (online, serving relay + management entry listening on 18443).
    // gw-eu stays offline (and even if its DB row had a stale port, offline must report false/null).
    assert_eq!(approve(&app, &seeded, &gw_centre_id, false).await, 200);
    let mut ws_centre = open_agent_ws(&app, &gw_centre_tok, "192.0.2.10", None, None).await;
    let mut ws_cn = open_agent_ws(&app, &gw_cn_tok, "203.0.113.50", Some(18443), None).await;

    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&gw_eu_id).unwrap() },
            doc! { "$set": { "capabilities.management_entry_port": 18443 } },
        )
        .await
        .unwrap();

    // Sign a valid management-entry attestation from gw-cn for dev-cn and connect dev-cn through it.
    let gw_cn_row = app
        .db
        .collection::<bson::Document>("agents")
        .find_one(doc! { "_id": ObjectId::parse_str(&gw_cn_id).unwrap() })
        .await
        .unwrap()
        .unwrap();
    let token_gen = match gw_cn_row.get("token_gen") {
        Some(bson::Bson::Int32(v)) => *v as u32,
        Some(bson::Bson::Int64(v)) => *v as u32,
        _ => 0,
    };
    let entry_key = meshharbor_remote_control::management_entry::derive_key(
        app.settings.jwt.secret.as_bytes(),
        &gw_cn_id,
        token_gen,
    );
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let att_token = meshharbor_remote_control::management_entry::sign(
        &entry_key,
        &gw_cn_id,
        "198.51.100.77".parse().unwrap(),
        "0123456789abcdef0123456789abcdef",
        now_s,
    )
    .expect("sign attestation");
    let mut ws_dev_cn =
        open_agent_ws(&app, &dev_cn_tok, "203.0.113.50", None, Some(&att_token)).await;

    // Join overlay on gw-centre, gw-cn, and dev-cn so overlay_nodes exist.
    let _nm_centre = join_node(&mut ws_centre, 81, "192.0.2.10:41641", json!({})).await;
    let _nm_cn = join_node(&mut ws_cn, 82, "203.0.113.50:41641", json!({})).await;
    let _nm_dev = join_node(&mut ws_dev_cn, 83, "198.51.100.77:41641", json!({})).await;
    let node_centre = node_id(&app, &seeded, "gateway-centre").await;
    let node_cn = node_id(&app, &seeded, "gateway-cn").await;
    let node_dev = node_id(&app, &seeded, "device-cn").await;

    // Seed fresh stats_mesh snapshots for gw-centre and gw-cn (including a non-gateway link
    // to dev-cn that must be filtered out) plus a stale snapshot for gw-eu (> 180s old).
    let now_dt = bson::DateTime::now();
    let stale_dt = bson::DateTime::from_millis(now_dt.timestamp_millis() - 300 * 1000);
    let mesh_coll = app
        .db
        .collection::<bson::Document>(meshharbor_services::dao::stats::STATS_MESH);
    mesh_coll
        .insert_many(vec![
            doc! {
                "_id": &gw_cn_id,
                "tenant_id": tid,
                "agent_id": ObjectId::parse_str(&gw_cn_id).unwrap(),
                "ts": now_dt,
                "links": [
                    { "node": &node_centre, "carrier": "direct", "rtt_ms": 34_i64, "stalled": false },
                    { "node": &node_dev, "carrier": "direct", "rtt_ms": 7_i64, "stalled": false }
                ]
            },
            doc! {
                "_id": &gw_centre_id,
                "tenant_id": tid,
                "agent_id": ObjectId::parse_str(&gw_centre_id).unwrap(),
                "ts": now_dt,
                "links": [
                    { "node": &node_cn, "carrier": "relay", "relay": "org_relay", "rtt_ms": 46_i64, "stalled": true },
                    { "node": &node_dev, "carrier": "derp", "rtt_ms": 95_i64, "stalled": false }
                ]
            },
            doc! {
                "_id": &gw_eu_id,
                "tenant_id": tid,
                "agent_id": ObjectId::parse_str(&gw_eu_id).unwrap(),
                "ts": stale_dt,
                "links": [
                    { "node": &node_cn, "carrier": "direct", "rtt_ms": 120_i64, "stalled": false }
                ]
            },
        ])
        .await
        .unwrap();

    // Query GET /api/tenant/{tid}/network-zones/backbone.
    let (status, body) = get_json(&app, &tenant_url(&seeded, "/network-zones/backbone"), admin).await;
    assert_eq!(status, 200, "GET /network-zones/backbone: {body}");
    assert!(body["revision"].as_u64().unwrap() > 0);

    // Zones & device counts.
    let zones = body["zones"].as_array().unwrap();
    assert_eq!(zones.len(), 3, "{body}");
    let z_centre = zones.iter().find(|z| z["id"] == "centre").unwrap();
    let z_cn = zones.iter().find(|z| z["id"] == "cn").unwrap();
    let z_eu = zones.iter().find(|z| z["id"] == "eu").unwrap();
    assert_eq!(z_centre["is_centre"], json!(true));
    assert_eq!(z_centre["device_count"], json!(1));
    assert_eq!(z_cn["is_centre"], json!(false));
    assert_eq!(z_cn["device_count"], json!(2));
    assert_eq!(z_eu["device_count"], json!(1));

    // Gateways & live entry state.
    let gateways = body["gateways"].as_array().unwrap();
    assert_eq!(gateways.len(), 3, "{body}");
    let g_centre = gateways
        .iter()
        .find(|g| g["agent_id"] == gw_centre_id)
        .unwrap();
    let g_cn = gateways.iter().find(|g| g["agent_id"] == gw_cn_id).unwrap();
    let g_eu = gateways.iter().find(|g| g["agent_id"] == gw_eu_id).unwrap();

    assert_eq!(g_centre["is_centre"], json!(true));
    assert_eq!(g_centre["online"], json!(true));
    assert_eq!(g_centre["serving_relay"], json!(false));
    assert_eq!(g_centre["entry_listening"], json!(false));
    assert_eq!(g_centre["entry_port"], Value::Null);
    assert_eq!(g_centre["entry_device_count"], json!(0));

    assert_eq!(g_cn["is_centre"], json!(false));
    assert_eq!(g_cn["online"], json!(true));
    assert_eq!(g_cn["serving_relay"], json!(true));
    assert_eq!(g_cn["entry_listening"], json!(true));
    assert_eq!(g_cn["entry_port"], json!(18443));
    assert_eq!(g_cn["entry_device_count"], json!(1));

    assert_eq!(g_eu["online"], json!(false));
    assert_eq!(g_eu["entry_listening"], json!(false));
    assert_eq!(g_eu["entry_port"], Value::Null);
    assert_eq!(g_eu["entry_device_count"], json!(0));

    // Gateway↔gateway links: only gw-centre <-> gw-cn survives; non-gateway and stale links excluded.
    let links = body["links"].as_array().unwrap();
    assert_eq!(links.len(), 1, "expected 1 gateway link: {body}");
    let link = &links[0];
    let mut expected_pair = [gw_centre_id.clone(), gw_cn_id.clone()];
    expected_pair.sort();
    assert_eq!(link["from_agent_id"], json!(expected_pair[0]));
    assert_eq!(link["to_agent_id"], json!(expected_pair[1]));
    assert_eq!(link["carrier"], json!("relay"));
    assert_eq!(link["rtt_ms"], json!(34));
    assert_eq!(link["stalled"], json!(true));
    assert_eq!(link["reports"], json!(2));
    assert_eq!(link["cross_zone"], json!(true));
    let ends = link["ends"].as_array().unwrap();
    assert_eq!(ends.len(), 2);
    assert!(ends.iter().any(|e| e["node"] == gw_cn_id && e["carrier"] == "direct"));
    assert!(
        ends.iter()
            .any(|e| e["node"] == gw_centre_id && e["carrier"] == "relay" && e["relay"] == "org_relay")
    );

    // Disconnecting dev-cn drops gw-cn's live entry_device_count back to 0.
    let _ = ws_dev_cn.close(None).await;
    drop(ws_dev_cn);
    let dev_cn_oid = ObjectId::parse_str(&dev_cn_id).unwrap();
    for _ in 0..50 {
        if !app.state.fleet().rc_hub.is_agent_online(dev_cn_oid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status2, body2) =
        get_json(&app, &tenant_url(&seeded, "/network-zones/backbone"), admin).await;
    assert_eq!(status2, 200);
    let g_cn_after = body2["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["agent_id"] == gw_cn_id)
        .unwrap();
    assert_eq!(g_cn_after["entry_device_count"], json!(0));

    let _ = ws_centre.close(None).await;
    let _ = ws_cn.close(None).await;
}
