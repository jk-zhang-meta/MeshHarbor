// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-138 — VPN-resistant automatic Logical Network Zones end-to-end tests:
//!
//! 1. `fr138_vpn_resistant_auto_zones_and_hysteresis`:
//!    - CN device connects cleanly -> `cn` (`auto_egress_ip`), records `last_clean_zone_id = cn`.
//!    - Turns on VPN (US WS IP) with `default_route_vpn = true` -> stays in `cn` (`auto_vpn_held`)
//!      across `/api/tenant/{tid}/agent`, `/api/tenant/{tid}/device`, `/api/account/devices`,
//!      `/api/agent/self/devices`, and Hub ICE policy.
//!    - Without the VPN flag, with a fresh CN physical probe (`POST /api/agent/self/egress-probe`)
//!      while WS sits on the US VPN IP -> stays in `cn` (`auto_physical`), surfacing both IPs.
//!    - With neither (US probe on the same connection) -> held by 10-min hysteresis on probes
//!      within the window, then moves to `non-cn` once two probes >= 10 min apart observe US.
//! 2. `fr138_egress_probe_honours_fr134_attested_management_entry`:
//!    - Probe arriving through a gateway management entry carries `?entry=<attestation>` and
//!      records the attested physical device IP (never the gateway's IP).
//!    - Unattested probe from a gateway's IP takes no origin and cannot lend the gateway's zone.
//! 3. `fr138_vpn_flag_security_invariant_no_clean_history_and_cannot_move_zones`:
//!    - Device with no clean history behind a VPN falls back to egress IP flagged as
//!      `auto_egress_fallback`, never polluting `last_clean_zone_id`.
//!    - Toggling `default_route_vpn` can only hold an earned `last_clean_zone_id`, never move a
//!      device into another zone.

use crate::agent_presence_tests::enroll;
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use crate::peer_relay_mint_tests::{Ws, approve, put, recv_t, set_mode};
use bson::{doc, oid::ObjectId};
use futures::SinkExt;
use meshharbor_remote_control::management_entry::{derive_key, sign};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};

/// RFC 5737 TEST-NET-1 -> mapped to `CN` in [`rfc5737_fixture_mmdb`].
const CN_IP: &str = "192.0.2.10";
/// RFC 5737 TEST-NET-2 -> mapped to `US` in [`rfc5737_fixture_mmdb`].
const US_IP: &str = "198.51.100.20";
/// RFC 5737 TEST-NET-3 -> mapped to `HK` in [`rfc5737_fixture_mmdb`].
const HK_IP: &str = "203.0.113.50";

const WAIT: Duration = Duration::from_secs(5);
const NONCE: &str = "0123456789abcdef0123456789abcdef";

/// Minimal valid MaxMind DB mapping pure RFC 5737 TEST-NET prefixes:
/// - `192.0.0.0/6` (includes `192.0.2.0/24`) -> `CN`
/// - `196.0.0.0/6` (includes `198.51.100.0/24`) -> `US`
/// - `200.0.0.0/5` (includes `203.0.113.0/24`) -> `HK`
fn rfc5737_fixture_mmdb() -> Vec<u8> {
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
        out.extend_from_slice(&[entries, 4]);
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
        out.extend_from_slice(&[0x08, 2]);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn country_rec(code: &str, name: &str) -> Vec<u8> {
        let mut d = Vec::new();
        map(&mut d, 1);
        text(&mut d, "country");
        map(&mut d, 2);
        text(&mut d, "iso_code");
        text(&mut d, code);
        text(&mut d, "names");
        map(&mut d, 1);
        text(&mut d, "en");
        text(&mut d, name);
        d
    }

    let cn = country_rec("CN", "China");
    let us = country_rec("US", "United States");
    let hk = country_rec("HK", "Hong Kong");

    // 6-node binary trie on bits 0..5 of IPv4:
    // node 0 (bit 0): 0 -> empty (6), 1 -> node 1
    // node 1 (bit 1): 0 -> empty (6), 1 -> node 2   (192.0.0.0/2 = 11..)
    // node 2 (bit 2): 0 -> node 3,    1 -> empty (6) (192.0.0.0/3 = 110..)
    // node 3 (bit 3): 0 -> node 4,    1 -> empty (6) (192.0.0.0/4 = 1100..)
    // node 4 (bit 4): 0 -> node 5,    1 -> HK        (200.0.0.0/5 = 11001..)
    // node 5 (bit 5): 0 -> CN,        1 -> US        (192.0.0.0/6 = 110000.., 196.0.0.0/6 = 110001..)
    let node_count: u32 = 6;
    let empty = node_count;
    let to_cn = node_count + 16;
    let to_us = to_cn + cn.len() as u32;
    let to_hk = to_us + us.len() as u32;

    let mut db = Vec::new();
    for (left, right) in [
        (empty, 1),
        (empty, 2),
        (3, empty),
        (4, empty),
        (5, to_hk),
        (to_cn, to_us),
    ] {
        db.extend_from_slice(&left.to_be_bytes()[1..]);
        db.extend_from_slice(&right.to_be_bytes()[1..]);
    }
    db.extend_from_slice(&[0; 16]);
    db.extend_from_slice(&cn);
    db.extend_from_slice(&us);
    db.extend_from_slice(&hk);
    db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");

    let built = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 60;
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
    text(&mut db, "fr138 rfc5737 geoip fixture");
    text(&mut db, "ip_version");
    uint16(&mut db, 4);
    text(&mut db, "languages");
    array(&mut db, 1);
    text(&mut db, "en");
    text(&mut db, "node_count");
    uint32(&mut db, node_count);
    text(&mut db, "record_size");
    uint16(&mut db, 24);
    db
}

fn tenant_url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

async fn spawn_geo_app(management_entries: bool) -> (TestApp, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mmdb = dir.path().join("fr138-rfc5737.mmdb");
    std::fs::write(&mmdb, rfc5737_fixture_mmdb()).unwrap();
    let mmdb_str = mmdb.to_str().unwrap().to_owned();
    let app = TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.business_isolation = "off".into();
        s.app.management_entries = management_entries;
        s.stats.geoip_mmdb = Some(mmdb_str);
    })
    .await;
    (app, dir)
}

async fn connect_agent(
    app: &TestApp,
    token: &str,
    xff: &str,
    default_route_vpn: bool,
    rpc: &[&str],
    entry_port: Option<u16>,
) -> Ws {
    let ws_url = format!("ws://{}/ws?token={}&role=agent", app.addr, token);
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
        "rpc": rpc,
        "default_route_vpn": default_route_vpn,
    });
    if let Some(p) = entry_port {
        caps["management_entry_port"] = json!(p);
    }
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "device-a",
        "os": "linux",
        "agent_version": "0.4.212",
        "displays": [],
        "caps": caps,
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

async fn send_heartbeat_vpn(ws: &mut Ws, default_route_vpn: bool) {
    let hb = json!({
        "t": "rc:agent.heartbeat",
        "rss_mb": 0,
        "cpu_pct": 0.0,
        "active_sessions": 0,
        "caps": {
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
            "rpc": ["management-path"],
            "default_route_vpn": default_route_vpn,
        }
    });
    ws.send(Message::Text(hb.to_string().into()))
        .await
        .expect("send heartbeat");
}

async fn post_egress_probe(
    app: &TestApp,
    agent_token: &str,
    xff: &str,
    entry_token: Option<&str>,
) -> (u16, Value) {
    let mut url = reqwest::Url::parse(&format!("{}/api/agent/self/egress-probe", app.base_url))
        .expect("probe url");
    if let Some(t) = entry_token {
        url.query_pairs_mut().append_pair("entry", t);
    }
    let resp = app
        .client
        .post(url)
        .bearer_auth(agent_token)
        .header("x-forwarded-for", xff)
        .send()
        .await
        .expect("egress-probe request");
    let status = resp.status().as_u16();
    let body = resp.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

async fn setup_cn_and_non_cn_zones(
    app: &TestApp,
    seeded: &SeededTenant,
) -> (String, String, String, String) {
    let admin = &seeded.admin.access_token;
    set_mode(app, seeded, "auto").await;
    let (gw_cn_id, gw_cn_tok) = enroll(app, seeded, "gateway-a").await;
    let (gw_us_id, gw_us_tok) = enroll(app, seeded, "gateway-b").await;
    approve(app, seeded, &gw_cn_id, true).await;
    approve(app, seeded, &gw_us_id, true).await;
    let (s, body) = put(
        app,
        &tenant_url(seeded, "/network-zones"),
        admin,
        json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "CN",
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [gw_cn_id],
                    "cross_zone_mode": "router_only"
                },
                {
                    "id": "non-cn",
                    "name": "Non-CN",
                    "auto_countries": [],
                    "is_default": true,
                    "gateway_relay_ids": [gw_us_id],
                    "cross_zone_mode": "router_only"
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "set zones failed: {body}");
    (gw_cn_id, gw_cn_tok, gw_us_id, gw_us_tok)
}

#[tokio::test]
async fn fr138_vpn_resistant_auto_zones_and_hysteresis() {
    let (app, _geo_dir) = spawn_geo_app(false).await;
    let seeded = app.seed_tenant("fr138-main").await;
    let admin = &seeded.admin.access_token;
    let _gws = setup_cn_and_non_cn_zones(&app, &seeded).await;

    let (dev_id, dev_tok) = enroll(&app, &seeded, "device-a").await;
    let dev_oid = ObjectId::parse_str(&dev_id).unwrap();
    let hub = &app.state.modules.fleet.as_ref().unwrap().rc_hub;

    // 1. Clean connect from CN IP -> resolves to `cn` (`auto_egress_ip`) and stores `last_clean_zone_id = cn`.
    let ws1 = connect_agent(&app, &dev_tok, CN_IP, false, &["management-path"], None).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let agent_resp: Value = app
        .auth_get(&tenant_url(&seeded, &format!("/agent/{dev_id}")), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agent_resp["effective_zone_id"], json!("cn"), "{agent_resp}");
    assert_eq!(
        agent_resp["zone_source"],
        json!("auto_egress_ip"),
        "{agent_resp}"
    );
    assert_eq!(agent_resp["public_ip"], json!(CN_IP), "{agent_resp}");

    // 2. Device turns on VPN (reconnects from US IP with default_route_vpn=true) -> stays in `cn` (`auto_vpn_held`).
    drop(ws1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut ws2 = connect_agent(&app, &dev_tok, US_IP, true, &["management-path"], None).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let agent_vpn: Value = app
        .auth_get(&tenant_url(&seeded, &format!("/agent/{dev_id}")), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agent_vpn["effective_zone_id"], json!("cn"), "{agent_vpn}");
    assert_eq!(
        agent_vpn["zone_source"],
        json!("auto_vpn_held"),
        "{agent_vpn}"
    );
    assert_eq!(agent_vpn["default_route_vpn"], json!(true), "{agent_vpn}");
    assert_eq!(agent_vpn["public_ip"], json!(US_IP), "{agent_vpn}");
    assert_eq!(
        hub.agent_zone_ice_policy(dev_oid).and_then(|p| p.zone),
        Some("cn".to_string()),
        "Hub ICE policy must hold cn under VPN"
    );

    // Unified resolver parity across `/device`, `/account/devices`, and `/agent/self/devices`.
    let dev_list: Value = app
        .auth_get(&tenant_url(&seeded, "/device?per_page=50"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dev_row = dev_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(dev_id))
        .expect("device row");
    assert_eq!(dev_row["effective_zone_id"], json!("cn"));
    assert_eq!(dev_row["zone_source"], json!("auto_vpn_held"));

    let self_list: Value = app
        .auth_get("/api/agent/self/devices", &dev_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let self_row = self_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(dev_id))
        .expect("self row");
    assert_eq!(self_row["effective_zone_id"], json!("cn"));
    assert_eq!(self_row["zone_source"], json!("auto_vpn_held"));

    // Backbone per-zone device counts must also use the unified FR-138 resolver:
    // `dev` (auto_vpn_held on US_IP) must be counted in `cn`, NOT `non-cn`.
    let backbone: Value = app
        .auth_get(&tenant_url(&seeded, "/network-zones/backbone"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bb_zones = backbone["zones"].as_array().expect("backbone zones");
    let cn_bb = bb_zones
        .iter()
        .find(|z| z["id"] == json!("cn"))
        .expect("cn backbone zone");
    let non_cn_bb = bb_zones
        .iter()
        .find(|z| z["id"] == json!("non-cn"))
        .expect("non-cn backbone zone");
    // `gw_cn` and `gw_us` have no public IP so both fall into default `non-cn` (2),
    // while `dev` (`auto_vpn_held` on `US_IP`) is counted in `cn` (1), NOT `non-cn`!
    assert_eq!(
        cn_bb["device_count"],
        json!(1),
        "auto_vpn_held device must be counted in cn: {backbone}"
    );
    assert_eq!(
        non_cn_bb["device_count"],
        json!(2),
        "auto_vpn_held device must NOT be counted in non-cn (only the 2 unlocated gateways): {backbone}"
    );

    // 3. Without the VPN flag (default_route_vpn=false) + fresh CN physical probe -> STILL stays in `cn` (`auto_physical`),
    //    both physical + current IPs are surfaced, and display location follows the fresh physical egress (`CN`, not VPN `US`).
    let (ps, pbody) = post_egress_probe(&app, &dev_tok, CN_IP, None).await;
    assert_eq!(ps, 200, "{pbody}");
    assert_eq!(pbody["ok"], json!(true));
    assert_eq!(pbody["physical_public_ip"], json!(CN_IP));
    assert_eq!(pbody["current_public_ip"], json!(US_IP));
    assert_eq!(pbody["zone_id"], json!("cn"));
    assert_eq!(pbody["zone_source"], json!("auto_physical"));

    send_heartbeat_vpn(&mut ws2, false).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let agent_phys: Value = app
        .auth_get(&tenant_url(&seeded, &format!("/agent/{dev_id}")), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agent_phys["effective_zone_id"], json!("cn"), "{agent_phys}");
    assert_eq!(
        agent_phys["zone_source"],
        json!("auto_physical"),
        "{agent_phys}"
    );
    assert_eq!(
        agent_phys["physical_public_ip"],
        json!(CN_IP),
        "{agent_phys}"
    );
    assert_eq!(agent_phys["public_ip"], json!(US_IP), "{agent_phys}");
    assert_eq!(
        agent_phys["country_code"],
        json!("CN"),
        "agent display location must follow fresh physical egress, not VPN exit: {agent_phys}"
    );

    // Verify display location follows fresh physical egress across `/device`, `/agent/self/devices`, and `/account/devices`.
    let dev_phys_list: Value = app
        .auth_get(&tenant_url(&seeded, "/device?per_page=50"), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dev_phys_row = dev_phys_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(dev_id))
        .expect("device row with physical egress");
    assert_eq!(dev_phys_row["public_ip"], json!(US_IP));
    assert_eq!(dev_phys_row["physical_public_ip"], json!(CN_IP));
    assert_eq!(
        dev_phys_row["country_code"],
        json!("CN"),
        "/device display location must follow fresh physical egress: {dev_phys_row}"
    );

    let self_phys_list: Value = app
        .auth_get("/api/agent/self/devices", &dev_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let self_phys_row = self_phys_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(dev_id))
        .expect("self row with physical egress");
    assert_eq!(self_phys_row["public_ip"], json!(US_IP));
    assert_eq!(self_phys_row["physical_public_ip"], json!(CN_IP));
    assert_eq!(
        self_phys_row["country_code"],
        json!("CN"),
        "/agent/self/devices display location must follow fresh physical egress: {self_phys_row}"
    );

    let acct_phys_list: Value = app
        .auth_get("/api/account/devices?per_page=50", admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let acct_phys_row = acct_phys_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(dev_id))
        .expect("account devices row with physical egress");
    assert_eq!(acct_phys_row["public_ip"], json!(US_IP));
    assert_eq!(acct_phys_row["physical_public_ip"], json!(CN_IP));
    assert_eq!(
        acct_phys_row["country_code"],
        json!("CN"),
        "/account/devices display location must follow fresh physical egress: {acct_phys_row}"
    );

    // 4. Mid-connection probe from US IP (probe #1) is HELD by 10-min hysteresis -> stays in `cn`.
    let (h1_status, h1) = post_egress_probe(&app, &dev_tok, US_IP, None).await;
    assert_eq!(h1_status, 200, "{h1}");
    assert_eq!(h1["hysteresis_held"], json!(true), "{h1}");
    assert_eq!(h1["zone_id"], json!("cn"), "{h1}");
    assert_eq!(h1["physical_public_ip"], json!(CN_IP), "{h1}");

    // Probe #2 immediately (< 10 min) is STILL held.
    let (h2_status, h2) = post_egress_probe(&app, &dev_tok, US_IP, None).await;
    assert_eq!(h2_status, 200, "{h2}");
    assert_eq!(h2["hysteresis_held"], json!(true), "{h2}");
    assert_eq!(h2["zone_id"], json!("cn"), "{h2}");

    // 5. After >= 10 min (backdated via Hub test hook), next US probe COMMITS -> moves to `non-cn`.
    assert!(hub.backdate_zone_hysteresis(dev_oid, 11 * 60 * 1000));
    let (h3_status, h3) = post_egress_probe(&app, &dev_tok, US_IP, None).await;
    assert_eq!(h3_status, 200, "{h3}");
    assert!(
        h3.get("hysteresis_held").is_none_or(|v| v == &json!(false)),
        "{h3}"
    );
    assert_eq!(h3["zone_id"], json!("non-cn"), "{h3}");
    assert_eq!(h3["zone_source"], json!("auto_physical"), "{h3}");
    assert_eq!(h3["physical_public_ip"], json!(US_IP), "{h3}");
    assert_eq!(
        hub.agent_zone_ice_policy(dev_oid).and_then(|p| p.zone),
        Some("non-cn".to_string()),
        "Hub ICE policy must update after hysteresis commits"
    );
    drop(ws2);
}

#[tokio::test]
async fn fr138_egress_probe_honours_fr134_attested_management_entry() {
    let (app, _geo_dir) = spawn_geo_app(true).await;
    let seeded = app.seed_tenant("fr138-entry").await;
    let (gw_cn_id, gw_cn_tok, _gw_us_id, _gw_us_tok) = setup_cn_and_non_cn_zones(&app, &seeded).await;

    // Connect gateway-a advertising management entry on port 18443 from HK_IP so the server
    // recognises HK_IP as an active management entry address.
    let mut gw_ws = connect_agent(
        &app,
        &gw_cn_tok,
        HK_IP,
        false,
        &["management-path", "management-entry", "relay-server"],
        Some(18443),
    )
    .await;
    let _ = recv_t(&mut gw_ws, "rc:agent.management_entry", WAIT)
        .await
        .expect("gateway entry key");

    let (dev_id, dev_tok) = enroll(&app, &seeded, "device-a").await;
    let _dev_ws = connect_agent(&app, &dev_tok, US_IP, true, &["management-path"], None).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 1. Unattested probe from the entry's IP must NOT record the entry's IP as physical_public_ip.
    let (s_unatt, unatt) = post_egress_probe(&app, &dev_tok, HK_IP, None).await;
    assert_eq!(s_unatt, 200, "{unatt}");
    assert!(
        unatt.get("physical_public_ip").is_none_or(Value::is_null),
        "unattested entry IP must not be recorded as physical_public_ip: {unatt}"
    );

    // 2. Attested probe arriving via HK_IP carrying a valid entry token naming CN_IP records CN_IP!
    let key = derive_key(app.state.settings.jwt.secret.as_bytes(), &gw_cn_id, 0);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let att_token = sign(
        &key,
        &gw_cn_id,
        CN_IP.parse::<IpAddr>().unwrap(),
        NONCE,
        now_secs,
    )
    .expect("sign attestation");

    let (s_att, att) = post_egress_probe(&app, &dev_tok, HK_IP, Some(&att_token)).await;
    assert_eq!(s_att, 200, "{att}");
    assert_eq!(att["physical_public_ip"], json!(CN_IP), "{att}");
    assert_eq!(att["zone_id"], json!("cn"), "{att}");
    assert_eq!(att["zone_source"], json!("auto_physical"), "{att}");

    // Confirm persisted on the agent row in MongoDB as CN_IP, never HK_IP.
    let dev_oid = ObjectId::parse_str(&dev_id).unwrap();
    let stored = app
        .state
        .modules
        .fleet
        .as_ref()
        .unwrap()
        .agents
        .find_live_in_tenant(ObjectId::parse_str(&seeded.tenant_id).unwrap(), dev_oid)
        .await
        .unwrap();
    assert_eq!(stored.physical_public_ip.as_deref(), Some(CN_IP));
    assert_eq!(stored.last_clean_zone_id.as_deref(), Some("cn"));
    drop(gw_ws);
}

#[tokio::test]
async fn fr138_vpn_flag_security_invariant_no_clean_history_and_cannot_move_zones() {
    let (app, _geo_dir) = spawn_geo_app(false).await;
    let seeded = app.seed_tenant("fr138-sec").await;
    let admin = &seeded.admin.access_token;
    let _gws = setup_cn_and_non_cn_zones(&app, &seeded).await;

    let (dev_id, dev_tok) = enroll(&app, &seeded, "device-b").await;
    let dev_oid = ObjectId::parse_str(&dev_id).unwrap();
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();

    // First-ever connect from US IP with default_route_vpn=true and NO clean history:
    // falls back to `non-cn` explicitly flagged as `auto_egress_fallback`, and does NOT record
    // `last_clean_zone_id`.
    let _ws = connect_agent(&app, &dev_tok, US_IP, true, &["management-path"], None).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let agent_resp: Value = app
        .auth_get(&tenant_url(&seeded, &format!("/agent/{dev_id}")), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        agent_resp["effective_zone_id"],
        json!("non-cn"),
        "{agent_resp}"
    );
    assert_eq!(
        agent_resp["zone_source"],
        json!("auto_egress_fallback"),
        "{agent_resp}"
    );

    let stored = app
        .state
        .modules
        .fleet
        .as_ref()
        .unwrap()
        .agents
        .find_live_in_tenant(tid, dev_oid)
        .await
        .unwrap();
    assert_eq!(
        stored.last_clean_zone_id, None,
        "VPN fallback must never write last_clean_zone_id"
    );

    // Even if last_clean_zone_id is absent or tampered to a non-existent zone, default_route_vpn=true
    // can never move the device into `cn`.
    let _ = app
        .state
        .core
        .db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": dev_oid },
            doc! { "$set": { "last_clean_zone_id": "nonexistent" } },
        )
        .await;
    let after: Value = app
        .auth_get(&tenant_url(&seeded, &format!("/agent/{dev_id}")), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after["effective_zone_id"], json!("non-cn"), "{after}");
    assert_eq!(
        after["zone_source"],
        json!("auto_egress_fallback"),
        "{after}"
    );
}
