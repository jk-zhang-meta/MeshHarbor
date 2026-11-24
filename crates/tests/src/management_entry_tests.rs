// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-128 — the centre is a zone of its own: a management entry's key, its attestation of a
//! device's address at the `/ws?role=agent` upgrade, and the path each device is told.
//!
//! Every connection here comes through the trusted loopback proxy, so `X-Forwarded-For` is the
//! address the centre sees. A device that "comes through an entry" is one whose connection
//! carries the entry's address; whether it keeps that address, takes the attested one, or takes
//! none is what these tests lock (AC3, and the centre's kill switch of AC4).
//!
//! The fence for every `public_ip` read is the connection's `rc:agent.management_path` frame:
//! the server persists the connection's address before it computes the path it pushes.

use crate::agent_presence_tests::enroll;
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use crate::peer_relay_mint_tests::{Ws, approve, put, recv_t, set_mode};
use bson::{Document, doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::management_entry::{EntryKey, derive_key, sign};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};

/// The entry's public address: where it connects from, and so where every device that comes
/// through it appears to connect from.
const ENTRY_IP: &str = "203.0.113.50";
/// The address an entry attests for the device behind it.
const DEVICE_IP: &str = "198.51.100.77";
/// The device's own address when it dials the centre directly.
const DIRECT_IP: &str = "198.51.100.20";
/// An address that is no entry's.
const STRANGER_IP: &str = "203.0.113.99";
const ENTRY_PORT: u16 = 18443;
const NONCE: &str = "0123456789abcdef0123456789abcdef";
const WAIT: Duration = Duration::from_secs(5);
/// How long a frame that must NOT arrive is waited for, after the path frame fenced the push.
const QUIET: Duration = Duration::from_secs(2);

fn tenant_url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// The app every test runs: loopback is the only trusted proxy, so the forwarded address is the
/// connection's client address. `entries` is `app.management_entries`.
async fn spawn(entries: bool) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
        s.app.management_entries = entries;
    })
    .await
}

/// An agent WS through the trusted proxy (`xff`), with `entry=` on the URL when given, and a
/// hello that advertises `rpc` and, when given, a bound management entry port.
async fn connect(
    app: &TestApp,
    token: &str,
    rpc: &[&str],
    xff: &str,
    entry_port: Option<u16>,
    entry_token: Option<&str>,
) -> Ws {
    let mut ws_url = format!("ws://{}/ws?token={}&role=agent", app.addr, token);
    if let Some(t) = entry_token {
        ws_url.push_str("&entry=");
        ws_url.push_str(t);
    }
    let mut req = ws_url.into_client_request().expect("ws request");
    req.headers_mut()
        .insert("x-forwarded-for", xff.parse().expect("xff header"));
    let (mut ws, _) = connect_async(req).await.expect("ws connect");
    let mut caps = json!({
        "hw_encoders": ["openh264"],
        "codecs": ["h264"],
        "has_input_permission": true,
        "supports_clipboard": true,
        "supports_file_transfer": true,
        "max_simultaneous_sessions": 1,
        "rpc": rpc,
    });
    if let Some(port) = entry_port {
        caps["management_entry_port"] = json!(port);
    }
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "management entry box",
        "os": "linux",
        "agent_version": "0.4.210",
        "displays": [],
        "caps": caps,
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

/// Every text frame that arrives within `wait`.
async fn collect(ws: &mut Ws, wait: Duration) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut out = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return out;
        }
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(Message::Text(txt)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&txt) {
                    out.push(v);
                }
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) | Ok(None) | Err(_) => return out,
        }
    }
}

fn has_t(frames: &[Value], t: &str) -> bool {
    frames.iter().any(|f| f["t"] == t)
}

/// The connection's path frame: the fence after which its address is persisted.
async fn path_frame(ws: &mut Ws, label: &str) -> Value {
    recv_t(ws, "rc:agent.management_path", WAIT)
        .await
        .unwrap_or_else(|| panic!("{label}: no rc:agent.management_path after hello"))
}

async fn close(app: &TestApp, mut ws: Ws, agent_id: &str) {
    let _ = ws.close(None).await;
    drop(ws);
    let id = oid(agent_id);
    for _ in 0..50 {
        if !app.state.fleet().rc_hub.is_agent_online(id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{agent_id} still online after its socket closed");
}

async fn agent_row(app: &TestApp, agent_id: &str) -> Document {
    app.db
        .collection::<Document>("agents")
        .find_one(doc! { "_id": oid(agent_id) })
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no agents row for {agent_id}"))
}

async fn public_ip(app: &TestApp, agent_id: &str) -> Option<String> {
    agent_row(app, agent_id)
        .await
        .get_str("public_ip")
        .ok()
        .map(str::to_owned)
}

fn live_ip(app: &TestApp, agent_id: &str) -> Option<IpAddr> {
    app.state.fleet().rc_hub.agent_live_public_ip(oid(agent_id))
}

/// The key the centre derives for `entry_id`: from the test app's own server secret and the
/// entry's current token generation, read from its row.
async fn entry_key_bytes(app: &TestApp, entry_id: &str) -> Vec<u8> {
    let row = agent_row(app, entry_id).await;
    let token_gen = match row.get("token_gen") {
        Some(bson::Bson::Int32(v)) => *v as u32,
        Some(bson::Bson::Int64(v)) => *v as u32,
        _ => 0,
    };
    derive_key(app.settings.jwt.secret.as_bytes(), entry_id, token_gen)
}

fn attest(key: &[u8], entry_id: &str, ip: &str, now: i64) -> String {
    sign(key, entry_id, ip.parse().unwrap(), NONCE, now).expect("sign attestation")
}

/// `gateway_ids` approved as org relays (mode on) and made the gateways of one `RouterOnly`
/// zone `cn`, which a device without a pin or a country does not resolve into.
async fn zone_with_gateways(app: &TestApp, seeded: &SeededTenant, gateway_ids: &[&str]) {
    set_mode(app, seeded, "on").await;
    for gw in gateway_ids {
        assert_eq!(approve(app, seeded, gw, true).await, 200, "approve {gw}");
    }
    let (s, body) = put(
        app,
        &tenant_url(seeded, "/network-zones"),
        &seeded.admin.access_token,
        json!({
            "zones": [{
                "id": "cn",
                "name": "Mainland China",
                "auto_countries": ["CN"],
                "is_default": false,
                "gateway_relay_ids": gateway_ids,
                "cross_zone_mode": "router_only",
            }]
        }),
    )
    .await;
    assert_eq!(s, 200, "PUT /network-zones: {body}");
}

/// One tenant whose zone `cn` has one gateway `gw` that runs an entry, connected from
/// [`ENTRY_IP`] and holding its key; and a device `d`, no relay, that has not connected yet.
struct Rig {
    app: TestApp,
    seeded: SeededTenant,
    gw_id: String,
    /// Held open: the entry's live address is one of the two a token is checked against.
    _gw_ws: Ws,
    d_id: String,
    d_tok: String,
}

impl Rig {
    async fn up(slug: &str, entries: bool) -> Self {
        let app = spawn(entries).await;
        let seeded = app.seed_tenant(slug).await;
        let (gw_id, gw_tok) = enroll(&app, &seeded, &format!("{slug}-gw")).await;
        let (d_id, d_tok) = enroll(&app, &seeded, &format!("{slug}-d")).await;
        zone_with_gateways(&app, &seeded, &[&gw_id]).await;
        let mut gw_ws = connect(&app, &gw_tok, &[], ENTRY_IP, Some(ENTRY_PORT), None).await;
        if entries {
            // The key's arrival also fences the hello: the row holds the port and the address.
            recv_t(&mut gw_ws, "rc:agent.management_entry", WAIT)
                .await
                .expect("the entry receives its key");
        } else {
            let frames = collect(&mut gw_ws, QUIET).await;
            assert!(
                !has_t(&frames, "rc:agent.management_entry"),
                "management_entries=false delivers no key: {frames:?}"
            );
        }
        assert_eq!(public_ip(&app, &gw_id).await.as_deref(), Some(ENTRY_IP));
        Self {
            app,
            seeded,
            gw_id,
            _gw_ws: gw_ws,
            d_id,
            d_tok,
        }
    }

    /// Connect `d` from `xff`, optionally carrying `entry`, wait for its path frame, and return
    /// its socket and persisted `public_ip`.
    async fn device(&self, xff: &str, entry: Option<&str>, label: &str) -> (Ws, Option<String>) {
        let mut ws = connect(
            &self.app,
            &self.d_tok,
            &["management-path"],
            xff,
            None,
            entry,
        )
        .await;
        path_frame(&mut ws, label).await;
        (ws, public_ip(&self.app, &self.d_id).await)
    }

    /// `d` dials the centre directly from [`DIRECT_IP`], then hangs up: its address is known.
    async fn device_seen_directly(&self) {
        let (ws, ip) = self.device(DIRECT_IP, None, "direct").await;
        assert_eq!(
            ip.as_deref(),
            Some(DIRECT_IP),
            "a direct connection takes its address"
        );
        close(&self.app, ws, &self.d_id).await;
    }

    async fn valid_token(&self) -> String {
        let key = entry_key_bytes(&self.app, &self.gw_id).await;
        attest(&key, &self.gw_id, DEVICE_IP, unix_now())
    }
}

#[tokio::test]
async fn an_approved_gateway_with_an_entry_port_alone_receives_its_derived_key() {
    let app = spawn(true).await;
    let seeded = app.seed_tenant("mge-key").await;
    let (gw_id, gw_tok) = enroll(&app, &seeded, "mge-key-gw").await;
    let (np_id, np_tok) = enroll(&app, &seeded, "mge-key-gw-noport").await;
    let (_plain_id, plain_tok) = enroll(&app, &seeded, "mge-key-plain").await;
    zone_with_gateways(&app, &seeded, &[&gw_id, &np_id]).await;

    let rpc = ["management-path"];
    let mut gw = connect(&app, &gw_tok, &rpc, ENTRY_IP, Some(ENTRY_PORT), None).await;
    let frame = recv_t(&mut gw, "rc:agent.management_entry", WAIT)
        .await
        .expect("an approved gateway that runs an entry receives its key");
    let want = EntryKey::from_bytes(&entry_key_bytes(&app, &gw_id).await);
    assert_eq!(
        frame["key"],
        json!(want.0),
        "the key is derived from the server secret, the entry id and its token generation"
    );
    assert!(
        want.bytes().is_some(),
        "the delivered key decodes to a usable signing key"
    );

    // A gateway of the same zone that runs no entry, and a device that opened the port but
    // is no gateway: each gets its path (the fence), and no key.
    let mut np = connect(&app, &np_tok, &rpc, "203.0.113.51", None, None).await;
    let mut plain = connect(
        &app,
        &plain_tok,
        &rpc,
        "203.0.113.60",
        Some(ENTRY_PORT),
        None,
    )
    .await;
    for (label, ws) in [
        ("gateway without a port", &mut np),
        ("port without a gateway", &mut plain),
    ] {
        path_frame(ws, label).await;
        let frames = collect(ws, QUIET).await;
        assert!(
            !has_t(&frames, "rc:agent.management_entry"),
            "{label} must receive no entry key: {frames:?}"
        );
    }
}

#[tokio::test]
async fn a_valid_attestation_from_the_entrys_address_gives_the_device_the_attested_address() {
    let rig = Rig::up("mge-att", true).await;
    let token = rig.valid_token().await;
    let (_ws, ip) = rig.device(ENTRY_IP, Some(&token), "attested").await;
    assert_eq!(
        ip.as_deref(),
        Some(DEVICE_IP),
        "the attested address, not the entry's, is the device's public_ip"
    );
    assert_eq!(
        live_ip(&rig.app, &rig.d_id),
        Some(DEVICE_IP.parse().unwrap())
    );
}

#[tokio::test]
async fn a_connection_from_the_entrys_address_without_a_token_takes_no_address() {
    let rig = Rig::up("mge-bare", true).await;
    rig.device_seen_directly().await;
    let (_ws, ip) = rig.device(ENTRY_IP, None, "no token").await;
    assert_eq!(
        ip.as_deref(),
        Some(DIRECT_IP),
        "an entry must not lend its address: public_ip keeps the device's last own address"
    );
    assert_eq!(
        live_ip(&rig.app, &rig.d_id),
        None,
        "the live connection has no address, so no zone"
    );

    // An approved relay is the org's own infrastructure and may share the entry's egress: from
    // the same address, with no token, it keeps that address.
    let (r_id, r_tok) = enroll(&rig.app, &rig.seeded, "mge-bare-relay").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &r_id, true).await, 200);
    let mut r = connect(&rig.app, &r_tok, &["management-path"], ENTRY_IP, None, None).await;
    path_frame(&mut r, "approved relay").await;
    assert_eq!(
        public_ip(&rig.app, &r_id).await.as_deref(),
        Some(ENTRY_IP),
        "an approved relay at the entry's address keeps that address"
    );
    assert_eq!(live_ip(&rig.app, &r_id), Some(ENTRY_IP.parse().unwrap()));
}

#[tokio::test]
async fn forged_foreign_stale_or_misplaced_attestations_never_move_the_device() {
    let rig = Rig::up("mge-neg", true).await;
    let app = &rig.app;

    // An entry of ANOTHER tenant, current in its own: its key arrives, so its tokens verify.
    let other = app.seed_tenant("mge-neg-other").await;
    let (ogw_id, ogw_tok) = enroll(app, &other, "mge-neg-other-gw").await;
    zone_with_gateways(app, &other, &[&ogw_id]).await;
    let other_ip = "203.0.113.70";
    let mut ogw = connect(app, &ogw_tok, &[], other_ip, Some(ENTRY_PORT), None).await;
    recv_t(&mut ogw, "rc:agent.management_entry", WAIT)
        .await
        .expect("the other tenant's entry receives its key");

    rig.device_seen_directly().await;

    let now = unix_now();
    let key = entry_key_bytes(app, &rig.gw_id).await;
    let other_key = entry_key_bytes(app, &ogw_id).await;
    let wrong_key = derive_key(b"not-the-server-secret-not-the-server", &rig.gw_id, 0);
    let cases = [
        ("forged", attest(&wrong_key, &rig.gw_id, DEVICE_IP, now)),
        ("expired", attest(&key, &rig.gw_id, DEVICE_IP, now - 300)),
    ];
    for (label, token) in &cases {
        let (ws, ip) = rig.device(ENTRY_IP, Some(token.as_str()), label).await;
        assert_eq!(
            ip.as_deref(),
            Some(DIRECT_IP),
            "{label}: refused, and from an entry's address: no address at all"
        );
        assert_eq!(live_ip(app, &rig.d_id), None, "{label}: no live address");
        close(app, ws, &rig.d_id).await;
    }

    // Another tenant's entry, from its own address: the token is refused (not the device's
    // org), and that entry is no entry of the device's org either, so the connection takes
    // the address it comes from. Never the attested one.
    let token = attest(&other_key, &ogw_id, DEVICE_IP, now);
    let (ws, ip) = rig.device(other_ip, Some(&token), "foreign entry").await;
    assert_eq!(
        ip.as_deref(),
        Some(other_ip),
        "another tenant's entry: refused, the connection keeps its own address"
    );
    assert_eq!(live_ip(app, &rig.d_id), Some(other_ip.parse().unwrap()));
    close(app, ws, &rig.d_id).await;

    // A valid token is not a bearer credential: from an address that is no entry's, the
    // connection keeps its own address.
    let token = attest(&key, &rig.gw_id, DEVICE_IP, unix_now());
    let (ws, ip) = rig
        .device(STRANGER_IP, Some(&token), "not from the entry")
        .await;
    assert_eq!(
        ip.as_deref(),
        Some(STRANGER_IP),
        "a valid token presented from elsewhere is ignored"
    );
    close(app, ws, &rig.d_id).await;

    // Positive control on the same rig: the same entry's valid token, from its address.
    let token = attest(&key, &rig.gw_id, DEVICE_IP, unix_now());
    let (_ws, ip) = rig.device(ENTRY_IP, Some(&token), "control").await;
    assert_eq!(
        ip.as_deref(),
        Some(DEVICE_IP),
        "control: a valid attestation is accepted"
    );
    drop(ogw);
}

#[tokio::test]
async fn only_a_current_entry_of_the_devices_own_org_withholds_its_address() {
    let rig = Rig::up("mge-scope", true).await;
    let app = &rig.app;
    let rpc = ["management-path"];

    // The port is the device owner's setting: a device that opened it, approved as nothing;
    // an approved relay that opened it but is no zone's gateway; and a current entry of
    // ANOTHER org (its key arrives, so it is one there). Each sits at an address of its own.
    let (p_id, p_tok) = enroll(app, &rig.seeded, "mge-scope-port").await;
    let (q_id, q_tok) = enroll(app, &rig.seeded, "mge-scope-relay").await;
    assert_eq!(approve(app, &rig.seeded, &q_id, true).await, 200);
    let other = app.seed_tenant("mge-scope-other").await;
    let (o_id, o_tok) = enroll(app, &other, "mge-scope-other-gw").await;
    zone_with_gateways(app, &other, &[&o_id]).await;
    let mut p = connect(app, &p_tok, &rpc, "203.0.113.81", Some(ENTRY_PORT), None).await;
    path_frame(&mut p, "port without a gateway").await;
    let mut q = connect(app, &q_tok, &rpc, "203.0.113.82", Some(ENTRY_PORT), None).await;
    path_frame(&mut q, "relay without a gateway").await;
    let mut o = connect(app, &o_tok, &[], "203.0.113.83", Some(ENTRY_PORT), None).await;
    recv_t(&mut o, "rc:agent.management_entry", WAIT)
        .await
        .expect("the other org's entry receives its key");

    let cases = [
        ("a port without a gateway", p_id.as_str(), "203.0.113.81"),
        ("a relay that is no gateway", q_id.as_str(), "203.0.113.82"),
        ("another org's current entry", o_id.as_str(), "203.0.113.83"),
    ];
    let mut wrong = Vec::new();
    for (label, holder, x) in cases {
        // On the holder's row, where the upgrade's lookup reads it.
        assert_eq!(public_ip(app, holder).await.as_deref(), Some(x), "{label}");
        let (ws, ip) = rig.device(x, None, label).await;
        let live = live_ip(app, &rig.d_id);
        if ip.as_deref() != Some(x) || live != Some(x.parse().unwrap()) {
            wrong.push(format!("{label}: public_ip={ip:?} live={live:?}, want {x}"));
        }
        close(app, ws, &rig.d_id).await;
    }
    assert!(
        wrong.is_empty(),
        "none is a current entry of the device's org: a direct device keeps its address: \
         {wrong:#?}"
    );

    // Control on the same rig: the org's own current entry still withholds.
    let (_ws, ip) = rig.device(ENTRY_IP, None, "own entry").await;
    assert_eq!(
        ip.as_deref(),
        Some("203.0.113.83"),
        "control: from its org's entry, the device keeps its last own address"
    );
    assert_eq!(live_ip(app, &rig.d_id), None, "control: no live address");
    drop((p, q, o));
}

#[tokio::test]
async fn with_management_entries_off_a_valid_token_is_ignored_and_the_entrys_address_is_taken() {
    let rig = Rig::up("mge-off", false).await;
    let token = rig.valid_token().await;
    let mut ws = connect(
        &rig.app,
        &rig.d_tok,
        &["management-path"],
        ENTRY_IP,
        None,
        Some(&token),
    )
    .await;
    let path = path_frame(&mut ws, "switch off").await;
    assert_eq!(path["direct"], json!(true), "switch off: direct, {path}");
    assert_eq!(path["entries"], json!([]), "switch off: no entries, {path}");
    assert_eq!(
        public_ip(&rig.app, &rig.d_id).await.as_deref(),
        Some(ENTRY_IP),
        "switch off: the connection takes its own address, as before FR-128"
    );
}

#[tokio::test]
async fn a_device_without_zones_is_told_direct_with_no_entries() {
    let app = spawn(true).await;
    let seeded = app.seed_tenant("mge-path-open").await;
    let (_d_id, d_tok) = enroll(&app, &seeded, "mge-path-open-d").await;
    let mut ws = connect(&app, &d_tok, &["management-path"], DIRECT_IP, None, None).await;
    let path = path_frame(&mut ws, "no zones").await;
    assert_eq!(path["direct"], json!(true), "{path}");
    assert_eq!(path["entries"], json!([]), "{path}");

    // Without the verb, no frame at all (a pre-FR-128 agent).
    let (_o_id, o_tok) = enroll(&app, &seeded, "mge-path-open-old").await;
    let mut old = connect(&app, &o_tok, &[], DIRECT_IP, None, None).await;
    let frames = collect(&mut old, QUIET).await;
    assert!(
        !has_t(&frames, "rc:agent.management_path"),
        "no management-path verb, no frame: {frames:?}"
    );
}

#[tokio::test]
async fn a_device_in_a_strict_zone_without_the_centre_is_told_its_entries_and_no_direct() {
    let app = spawn(true).await;
    let seeded = app.seed_tenant("mge-path-strict").await;
    let (gw_id, gw_tok) = enroll(&app, &seeded, "mge-path-strict-gw").await;
    let (d_id, d_tok) = enroll(&app, &seeded, "mge-path-strict-d").await;
    zone_with_gateways(&app, &seeded, &[&gw_id]).await;
    // The admin's static endpoint, written straight to the row: the route refuses
    // documentation-range addresses, which the path's own public-literal rule accepts.
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": oid(&gw_id) },
            doc! { "$set": { "peer_relay_policy.static_endpoints": ["198.51.100.10:3478"] } },
        )
        .await
        .unwrap();
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, &format!("/agent/{d_id}/zone-assignment")),
        &seeded.admin.access_token,
        json!({ "pinned_zone_id": "cn" }),
    )
    .await;
    assert_eq!(s, 200, "pin to cn: {body}");

    let rpc = ["management-path"];
    let mut gw = connect(&app, &gw_tok, &rpc, ENTRY_IP, Some(ENTRY_PORT), None).await;
    let gw_path = path_frame(&mut gw, "gateway").await;
    assert_eq!(
        gw_path["direct"],
        json!(true),
        "a gateway is its zone's line to the centre: {gw_path}"
    );

    let mut d = connect(&app, &d_tok, &rpc, DIRECT_IP, None, None).await;
    let path = path_frame(&mut d, "strict zone").await;
    assert_eq!(
        path["direct"],
        json!(false),
        "a RouterOnly zone whose countries exclude the centre has no direct path: {path}"
    );
    let entries: Vec<&str> = path["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("entries is a list: {path}"))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        entries.contains(&"198.51.100.10:18443"),
        "the gateway's static endpoint IP at the entry port: {path}"
    );
}

#[tokio::test]
async fn fr134_every_non_gateway_zone_member_gets_entries_only_while_gateways_and_centre_zone_get_direct()
{
    let app = spawn(true).await;
    let seeded = app.seed_tenant("fr134-paths").await;
    let (gw_cn, gw_cn_tok) = enroll(&app, &seeded, "fr134-gw-cn").await;
    let (gw_dp, gw_dp_tok) = enroll(&app, &seeded, "fr134-gw-dp").await;
    let (gw_centre, gw_centre_tok) = enroll(&app, &seeded, "fr134-gw-centre").await;
    let (dev_cn, dev_cn_tok) = enroll(&app, &seeded, "fr134-dev-cn").await;
    let (dev_dp, dev_dp_tok) = enroll(&app, &seeded, "fr134-dev-dp").await;
    let (dev_centre, dev_centre_tok) = enroll(&app, &seeded, "fr134-dev-centre").await;
    let (_dev_unresolved, dev_unresolved_tok) =
        enroll(&app, &seeded, "fr134-dev-unresolved").await;

    set_mode(&app, &seeded, "on").await;
    for gw in [&gw_cn, &gw_dp, &gw_centre] {
        assert_eq!(approve(&app, &seeded, gw, true).await, 200);
    }
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        &seeded.admin.access_token,
        json!({
            "zones": [
                {
                    "id": "cn",
                    "name": "Zone A",
                    "auto_countries": ["CN"],
                    "is_default": false,
                    "gateway_relay_ids": [gw_cn],
                    "cross_zone_mode": "router_only",
                },
                {
                    "id": "non-cn",
                    "name": "Zone B",
                    "auto_countries": ["SG"],
                    "is_default": false,
                    "gateway_relay_ids": [gw_dp],
                    "cross_zone_mode": "direct_preferred",
                },
                {
                    "id": "centre",
                    "name": "Centre",
                    "auto_countries": [],
                    "is_default": false,
                    "gateway_relay_ids": [gw_centre],
                    "cross_zone_mode": "router_only",
                    "is_centre": true,
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 200, "PUT /network-zones: {body}");

    for (aid, zone) in [
        (&gw_cn, "cn"),
        (&dev_cn, "cn"),
        (&gw_dp, "non-cn"),
        (&dev_dp, "non-cn"),
        (&gw_centre, "centre"),
        (&dev_centre, "centre"),
    ] {
        let (st, b) = put(
            &app,
            &tenant_url(&seeded, &format!("/agent/{aid}/zone-assignment")),
            &seeded.admin.access_token,
            json!({ "pinned_zone_id": zone }),
        )
        .await;
        assert_eq!(st, 200, "pin {aid} to {zone}: {b}");
    }

    // Gateways connect advertising `management-entry` WITHOUT an already-bound entry port:
    // FR-134 delivers their attestation key immediately so they can start tcp/:18443 live.
    let gw_rpc = ["management-path", "management-entry"];
    let mut gw_cn_ws = connect(&app, &gw_cn_tok, &gw_rpc, "203.0.113.10", None, None).await;
    let mut gw_dp_ws = connect(&app, &gw_dp_tok, &gw_rpc, "203.0.113.20", None, None).await;
    let mut gw_centre_ws = connect(&app, &gw_centre_tok, &gw_rpc, "203.0.113.30", None, None).await;

    for (label, ws) in [
        ("gw_cn", &mut gw_cn_ws),
        ("gw_dp", &mut gw_dp_ws),
        ("gw_centre", &mut gw_centre_ws),
    ] {
        let p = path_frame(ws, label).await;
        assert_eq!(p["direct"], json!(true), "{label} must dial direct: {p}");
        let k = recv_t(ws, "rc:agent.management_entry", WAIT)
            .await
            .unwrap_or_else(|| panic!("{label} must receive derived entry key without manual port"));
        assert!(!k["key"].as_str().unwrap_or("").is_empty(), "{label}: {k}");
    }

    // Non-gateway devices connect BEFORE the gateways announce their bound port:
    let dev_rpc = ["management-path", "management-entry"];
    let mut dev_cn_ws = connect(&app, &dev_cn_tok, &dev_rpc, "198.51.100.11", None, None).await;
    let mut dev_dp_ws = connect(&app, &dev_dp_tok, &dev_rpc, "198.51.100.21", None, None).await;
    let mut dev_centre_ws =
        connect(&app, &dev_centre_tok, &dev_rpc, "198.51.100.31", None, None).await;
    let mut dev_unres_ws =
        connect(&app, &dev_unresolved_tok, &dev_rpc, "198.51.100.41", None, None).await;

    let p_cn_initial = path_frame(&mut dev_cn_ws, "dev_cn initial").await;
    assert_eq!(p_cn_initial["direct"], json!(false), "cn non-gw: {p_cn_initial}");
    let p_dp_initial = path_frame(&mut dev_dp_ws, "dev_dp initial").await;
    assert_eq!(
        p_dp_initial["direct"],
        json!(false),
        "FR-134: direct_preferred zone non-gateway must STILL get direct=false: {p_dp_initial}"
    );
    let p_centre = path_frame(&mut dev_centre_ws, "dev_centre").await;
    assert_eq!(
        p_centre["direct"],
        json!(true),
        "centre zone member must get direct=true: {p_centre}"
    );
    let p_unres = path_frame(&mut dev_unres_ws, "dev_unresolved").await;
    assert_eq!(
        p_unres["direct"],
        json!(true),
        "unresolved device must stay direct (never stranded): {p_unres}"
    );
    assert_eq!(p_unres["entries"], json!([]));

    // Non-gateways must NOT receive an entry key even though they advertise `management-entry`.
    let dev_cn_frames = collect(&mut dev_cn_ws, Duration::from_millis(400)).await;
    assert!(
        !has_t(&dev_cn_frames, "rc:agent.management_entry"),
        "non-gateway must not receive entry key: {dev_cn_frames:?}"
    );

    // Gateways send their immediate heartbeat announcing tcp/:18443 bound -> server live-pushes
    // updated `rc:agent.management_path` containing each gateway's public IP:18443!
    let hb_with_port = json!({
        "t": "rc:agent.heartbeat",
        "rss_mb": 10,
        "cpu_pct": 0.5,
        "active_sessions": 0,
        "caps": {
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
            "rpc": gw_rpc,
            "management_entry_port": ENTRY_PORT,
        }
    });
    gw_cn_ws
        .send(Message::Text(hb_with_port.to_string().into()))
        .await
        .unwrap();
    gw_dp_ws
        .send(Message::Text(hb_with_port.to_string().into()))
        .await
        .unwrap();

    // Receive live-pushed management paths on both non-gateway devices (filter until the entry
    // appears, since the second heartbeat triggers a second sync).
    let mut got_cn = false;
    for _ in 0..4 {
        let p = path_frame(&mut dev_cn_ws, "dev_cn live").await;
        if p["entries"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == "203.0.113.10:18443"))
        {
            assert_eq!(p["direct"], json!(false));
            got_cn = true;
            break;
        }
    }
    assert!(got_cn, "dev_cn must receive live entry 203.0.113.10:18443");

    let mut got_dp = false;
    for _ in 0..4 {
        let p = path_frame(&mut dev_dp_ws, "dev_dp live").await;
        if p["entries"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == "203.0.113.20:18443"))
        {
            assert_eq!(p["direct"], json!(false));
            got_dp = true;
            break;
        }
    }
    assert!(got_dp, "dev_dp (direct_preferred zone) must receive live entry 203.0.113.20:18443");

    drop((gw_cn_ws, gw_dp_ws, gw_centre_ws, dev_cn_ws, dev_dp_ws, dev_centre_ws, dev_unres_ws));
}

#[tokio::test]
async fn fr134_zone_without_gateway_is_refused_and_centre_zone_rejects_auto_rules() {
    let app = spawn(true).await;
    let seeded = app.seed_tenant("fr134-val").await;
    let (gw_id, _) = enroll(&app, &seeded, "fr134-val-gw").await;
    set_mode(&app, &seeded, "on").await;
    assert_eq!(approve(&app, &seeded, &gw_id, true).await, 200);

    // 1. Zone with empty gateway_relay_ids -> 400 BadRequest (AC4).
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        &seeded.admin.access_token,
        json!({
            "zones": [{
                "id": "cn",
                "name": "Zone A",
                "auto_countries": ["CN"],
                "is_default": false,
                "gateway_relay_ids": [],
                "cross_zone_mode": "router_only",
            }]
        }),
    )
    .await;
    assert_eq!(s, 400, "empty gateway_relay_ids must be refused: {body}");

    // 2. Centre zone with auto_countries -> 400.
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        &seeded.admin.access_token,
        json!({
            "zones": [{
                "id": "centre",
                "name": "Centre",
                "auto_countries": ["HK"],
                "is_default": false,
                "gateway_relay_ids": [gw_id],
                "cross_zone_mode": "router_only",
                "is_centre": true,
            }]
        }),
    )
    .await;
    assert_eq!(s, 400, "centre zone with countries must be refused: {body}");

    // 3. Centre zone with is_default -> 400.
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        &seeded.admin.access_token,
        json!({
            "zones": [{
                "id": "centre",
                "name": "Centre",
                "auto_countries": [],
                "is_default": true,
                "gateway_relay_ids": [gw_id],
                "cross_zone_mode": "router_only",
                "is_centre": true,
            }]
        }),
    )
    .await;
    assert_eq!(s, 400, "centre zone with is_default must be refused: {body}");

    // 4. Two centre zones -> 400.
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        &seeded.admin.access_token,
        json!({
            "zones": [
                {
                    "id": "c1",
                    "name": "Centre 1",
                    "auto_countries": [],
                    "is_default": false,
                    "gateway_relay_ids": [gw_id],
                    "cross_zone_mode": "router_only",
                    "is_centre": true,
                },
                {
                    "id": "c2",
                    "name": "Centre 2",
                    "auto_countries": [],
                    "is_default": false,
                    "gateway_relay_ids": [gw_id],
                    "cross_zone_mode": "router_only",
                    "is_centre": true,
                }
            ]
        }),
    )
    .await;
    assert_eq!(s, 400, "two centre zones must be refused: {body}");

    // 5. Valid centre zone saves cleanly and round-trips `is_centre: true`.
    let (s, body) = put(
        &app,
        &tenant_url(&seeded, "/network-zones"),
        &seeded.admin.access_token,
        json!({
            "zones": [{
                "id": "centre",
                "name": "Centre",
                "auto_countries": [],
                "is_default": false,
                "gateway_relay_ids": [gw_id],
                "cross_zone_mode": "router_only",
                "is_centre": true,
            }]
        }),
    )
    .await;
    assert_eq!(s, 200, "valid centre zone saves: {body}");
    assert_eq!(body["zones"][0]["is_centre"], json!(true));
}

#[tokio::test]
async fn fr134_live_gateway_demotion_revokes_entry_key_and_updates_zone_paths() {
    let app = spawn(true).await;
    let seeded = app.seed_tenant("fr134-demote").await;
    let (gw_id, gw_tok) = enroll(&app, &seeded, "fr134-demote-gw").await;
    let (dev_id, dev_tok) = enroll(&app, &seeded, "fr134-demote-dev").await;
    zone_with_gateways(&app, &seeded, &[&gw_id]).await;
    let (st, _) = put(
        &app,
        &tenant_url(&seeded, &format!("/agent/{dev_id}/zone-assignment")),
        &seeded.admin.access_token,
        json!({ "pinned_zone_id": "cn" }),
    )
    .await;
    assert_eq!(st, 200);

    let rpc = ["management-path", "management-entry"];
    let mut gw_ws = connect(&app, &gw_tok, &rpc, ENTRY_IP, Some(ENTRY_PORT), None).await;
    let _ = path_frame(&mut gw_ws, "gw").await;
    let k1 = recv_t(&mut gw_ws, "rc:agent.management_entry", WAIT)
        .await
        .expect("gateway receives initial entry key");
    assert!(!k1["key"].as_str().unwrap_or("").is_empty());

    let mut dev_ws = connect(&app, &dev_tok, &rpc, DIRECT_IP, None, None).await;
    let p1 = path_frame(&mut dev_ws, "dev initial").await;
    assert_eq!(p1["direct"], json!(false));
    assert_eq!(p1["entries"], json!([format!("{ENTRY_IP}:{ENTRY_PORT}")]));

    // Revoke gateway's relay approval -> live gateway receives empty revocation key, and zone
    // device receives updated path without the demoted gateway.
    assert_eq!(approve(&app, &seeded, &gw_id, false).await, 200);
    let revoke = recv_t(&mut gw_ws, "rc:agent.management_entry", WAIT)
        .await
        .expect("demoted gateway must receive empty revocation key");
    assert_eq!(revoke["key"], json!(""), "revocation key must be empty: {revoke}");

    let p2 = path_frame(&mut dev_ws, "dev after demotion").await;
    assert_eq!(p2["direct"], json!(false));
    assert_eq!(
        p2["entries"],
        json!([]),
        "demoted gateway must disappear from zone entries: {p2}"
    );
    drop((gw_ws, dev_ws));
}
