// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P3c — the org-relay MINT, driven end to end over real agent
//! WebSockets against a live `TestApp`: three enrolled agents join the
//! overlay, one is approved as the relay, and a `rc:overlay.relay_request`
//! from one member must produce `relay_serve` at the relay and
//! `relay_session` at both members — or an audited refusal naming its gate.
//!
//! What these lock is the WIRING of §1–§7: that the mint sits on the one path
//! a relay request takes, that every refusal reaches `peer_relay_audit` with
//! the reason the spec enumerates, that a live session flips the server
//! verdict to `org-relay`, and that all four revocation triggers push
//! `relay_revoke` to every party. The data plane — the members actually
//! binding at a relay — is `tunnel-core`'s loopback test; this crate does not
//! compile the overlay (spec §10b).

use crate::agent_presence_tests::enroll;
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::{doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};

pub(crate) type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

fn url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

/// Connect an agent WS and complete the hello with the given RPC verbs — the
/// relay's `relay-server` capability rides here, exactly as a real daemon
/// advertises it.
async fn connect(app: &TestApp, token: &str, rpc: &[&str]) -> Ws {
    connect_from(app, token, rpc, None).await
}

/// [`connect`] through a trusted loopback proxy: `xff` is the client address
/// the `X-Forwarded-For` header claims, which is what the server's business
/// observation records for this connection (`None` = a bare loopback peer).
pub(crate) async fn connect_from(app: &TestApp, token: &str, rpc: &[&str], xff: Option<&str>) -> Ws {
    let ws_url = format!("ws://{}/ws?token={}&role=agent", app.addr, urlencode(token));
    let mut req = ws_url.into_client_request().expect("ws request");
    if let Some(ip) = xff {
        req.headers_mut()
            .insert("x-forwarded-for", ip.parse().expect("xff header"));
    }
    let (mut ws, _) = connect_async(req).await.expect("ws connect");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "relay mint box",
        "os": "linux",
        "agent_version": "0.4.20",
        "displays": [],
        "caps": {
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
            "rpc": rpc,
        }
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

/// Read frames until one with `t == want` arrives, or give up.
pub(crate) async fn recv_t(ws: &mut Ws, want: &str, wait: Duration) -> Option<Value> {
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

/// Join the overlay as a node that understands org relays. `seed` makes the
/// WG key distinct per node; `endpoint` is the public address the relay
/// candidate is reachable at.
pub(crate) async fn join(ws: &mut Ws, seed: u8, org_primary: Option<bool>, endpoint: &str) -> Value {
    let key = BASE64.encode([seed; 32]);
    let mut msg = json!({
        "t": "rc:overlay.join",
        "wg_public_key": key,
        "mtu": 1280,
        "endpoints": [endpoint],
        "supports_org_relay": true,
        "supports_server_relay_strategy": true,
        "relay_port": 3478,
    });
    if let Some(p) = org_primary {
        msg["org_primary"] = json!(p);
    }
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .expect("send join");
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .expect("a netmap answers the join")
}

pub(crate) async fn put(app: &TestApp, path: &str, token: &str, body: Value) -> (u16, Value) {
    let resp = app.auth_put(path, token).json(&body).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn get(app: &TestApp, path: &str, token: &str) -> Value {
    app.auth_get(path, token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_or(Value::Null)
}

pub(crate) async fn set_mode(app: &TestApp, seeded: &SeededTenant, mode: &str) {
    let (s, _) = put(
        app,
        &url(seeded, "/peer-relay"),
        &seeded.admin.access_token,
        json!({ "mode": mode }),
    )
    .await;
    assert_eq!(s, 200, "set mode {mode}");
}

pub(crate) async fn approve(
    app: &TestApp,
    seeded: &SeededTenant,
    agent_id: &str,
    serve: bool,
) -> u16 {
    let (s, _) = put(
        app,
        &url(seeded, &format!("/agent/{agent_id}/peer-relay-policy")),
        &seeded.admin.access_token,
        json!({ "serve": serve }),
    )
    .await;
    s
}

/// The gate-2 grant: every node may reach the relay node. `via` names the
/// relay; the destination CIDR covers its overlay address.
pub(crate) async fn grant_relay(
    app: &TestApp,
    seeded: &SeededTenant,
    relay_node_id: &str,
) -> String {
    let resp = app
        .auth_post(&url(seeded, "/overlay-acl"), &seeded.admin.access_token)
        .json(&json!({
            "name": "relay grant",
            "sources": [{ "kind": "all_nodes" }],
            "via": [{ "kind": "node_id", "id": relay_node_id }],
            "destinations": [{ "cidr": "100.64.0.0/10" }],
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "policy create: {}",
        resp.status()
    );
    let v: Value = resp.json().await.unwrap();
    v["id"].as_str().unwrap().to_string()
}

pub(crate) async fn node_id(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> String {
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    app.state
        .network()
        .overlay_nodes
        .find_live_by_tenant_and_machine(tid, machine_id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no live node for {machine_id}"))
        .id
        .unwrap()
        .to_hex()
}

pub(crate) async fn audit_rows(app: &TestApp, seeded: &SeededTenant) -> Vec<Value> {
    get(
        app,
        &url(seeded, "/peer-relay-audit"),
        &seeded.admin.access_token,
    )
    .await["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// Wait for the newest audit row to be a `mint` row, then return it.
pub(crate) async fn wait_mint_row(app: &TestApp, seeded: &SeededTenant) -> Value {
    for _ in 0..40 {
        let rows = audit_rows(app, seeded).await;
        if let Some(r) = rows.first()
            && r["action"] == json!("mint")
        {
            return r.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "no mint row appeared; rows: {:?}",
        audit_rows(app, seeded).await
    );
}

/// Three nodes on one tenant: `a` asks, `b` is the peer, `r` may relay.
struct Rig {
    app: TestApp,
    seeded: SeededTenant,
    a: Ws,
    b: Ws,
    r: Ws,
    a_node: String,
    b_node: String,
    r_node: String,
    r_agent: String,
}

impl Rig {
    /// `relay_rpc` = whether the relay's hello advertises `relay-server`;
    /// `a_primary` = what `a`'s join says about its org.
    async fn up(slug: &str, relay_rpc: bool, a_primary: Option<bool>) -> Self {
        let app = TestApp::spawn().await;
        let seeded = app.seed_tenant(slug).await;
        let (a_agent, a_tok) = enroll(&app, &seeded, &format!("{slug}-a")).await;
        let (b_agent, b_tok) = enroll(&app, &seeded, &format!("{slug}-b")).await;
        let (r_agent, r_tok) = enroll(&app, &seeded, &format!("{slug}-r")).await;
        let _ = (a_agent, b_agent);
        let mut a = connect(&app, &a_tok, &[]).await;
        let mut b = connect(&app, &b_tok, &[]).await;
        let rpc: &[&str] = if relay_rpc { &["relay-server"] } else { &[] };
        let mut r = connect(&app, &r_tok, rpc).await;
        // Let the hellos land (the hub registers, the row stores caps).
        tokio::time::sleep(Duration::from_millis(300)).await;
        join(&mut r, 3, Some(true), "8.8.8.8:41641").await;
        join(&mut a, 1, a_primary, "203.0.113.10:41641").await;
        join(&mut b, 2, Some(true), "203.0.113.11:41641").await;
        let a_node = node_id(&app, &seeded, &format!("{slug}-a")).await;
        let b_node = node_id(&app, &seeded, &format!("{slug}-b")).await;
        let r_node = node_id(&app, &seeded, &format!("{slug}-r")).await;
        Self {
            app,
            seeded,
            a,
            b,
            r,
            a_node,
            b_node,
            r_node,
            r_agent,
        }
    }

    /// Everything a mint needs: org on, relay approved, gate-2 grant.
    async fn arm(&mut self) -> String {
        set_mode(&self.app, &self.seeded, "on").await;
        assert_eq!(
            approve(&self.app, &self.seeded, &self.r_agent, true).await,
            200
        );
        grant_relay(&self.app, &self.seeded, &self.r_node).await
    }

    async fn request(&mut self) {
        self.a
            .send(Message::Text(
                json!({ "t": "rc:overlay.relay_request", "peer_node_id": self.b_node })
                    .to_string()
                    .into(),
            ))
            .await
            .expect("send relay_request");
    }

    /// The three frames of a mint, in the order the server sends them.
    async fn expect_minted(&mut self) -> (Value, Value, Value) {
        let wait = Duration::from_secs(5);
        let serve = recv_t(&mut self.r, "rc:overlay.relay_serve", wait)
            .await
            .expect("the relay receives relay_serve");
        let sa = recv_t(&mut self.a, "rc:overlay.relay_session", wait)
            .await
            .expect("member a receives relay_session");
        let sb = recv_t(&mut self.b, "rc:overlay.relay_session", wait)
            .await
            .expect("member b receives relay_session");
        (serve, sa, sb)
    }

    async fn expect_revoked(&mut self, vni: u64) {
        let wait = Duration::from_secs(5);
        for (name, ws) in [("a", &mut self.a), ("b", &mut self.b), ("r", &mut self.r)] {
            let v = recv_t(ws, "rc:overlay.relay_revoke", wait)
                .await
                .unwrap_or_else(|| panic!("{name} receives relay_revoke"));
            assert_eq!(v["vni"], json!(vni), "{name}: the revoke names the session");
        }
    }

    async fn assert_nothing_pushed_to_a(&mut self) {
        assert!(
            recv_t(
                &mut self.a,
                "rc:overlay.relay_session",
                Duration::from_millis(600)
            )
            .await
            .is_none(),
            "no session must reach a"
        );
    }
}

/// MeshHarbor #5 — two approved, granted relays and two members that joined
/// after them, so each member's full netmap offers both.
struct TwoRelays {
    app: TestApp,
    seeded: SeededTenant,
    /// (node id, WS) of r1, r2.
    relays: Vec<(String, Ws)>,
    /// (WS, offered targets) of a, b.
    members: Vec<(Ws, Vec<Value>)>,
    b_node: String,
}

impl TwoRelays {
    async fn up(slug: &str) -> Self {
        let app = TestApp::spawn().await;
        let seeded = app.seed_tenant(slug).await;
        let mut relays = Vec::new();
        let mut agents = Vec::new();
        for (i, name) in ["r1", "r2"].into_iter().enumerate() {
            let (agent, tok) = enroll(&app, &seeded, &format!("{slug}-{name}")).await;
            let mut ws = connect(&app, &tok, &["relay-server"]).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            join(
                &mut ws,
                10 + i as u8,
                Some(true),
                &format!("8.8.8.{}:41641", 8 + i),
            )
            .await;
            relays.push((node_id(&app, &seeded, &format!("{slug}-{name}")).await, ws));
            agents.push(agent);
        }
        set_mode(&app, &seeded, "on").await;
        for (agent, (node, _)) in agents.iter().zip(&relays) {
            assert_eq!(approve(&app, &seeded, agent, true).await, 200);
            grant_relay(&app, &seeded, node).await;
        }
        let mut members = Vec::new();
        for (i, name) in ["a", "b"].into_iter().enumerate() {
            let (_, tok) = enroll(&app, &seeded, &format!("{slug}-{name}")).await;
            let mut ws = connect(&app, &tok, &[]).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            let map = join(
                &mut ws,
                1 + i as u8,
                Some(true),
                &format!("203.0.113.{}:41641", 10 + i),
            )
            .await;
            let targets = map["network"]["relay_probe_targets"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let named: BTreeSet<&str> = targets
                .iter()
                .filter_map(|t| t["relay_node_id"].as_str())
                .collect();
            assert_eq!(
                named,
                relays.iter().map(|(n, _)| n.as_str()).collect(),
                "{name} is offered both relays: {targets:?}"
            );
            members.push((ws, targets));
        }
        let b_node = node_id(&app, &seeded, &format!("{slug}-b")).await;
        Self {
            app,
            seeded,
            relays,
            members,
            b_node,
        }
    }

    /// Every member reports r1 slow and r2 fast, toward the endpoint it was offered.
    async fn report_r2_fastest(&mut self) {
        let r1 = json!(self.relays[0].0);
        for (ws, targets) in &mut self.members {
            for target in targets.iter() {
                let rtt = if target["relay_node_id"] == r1 {
                    180
                } else {
                    12
                };
                let probe = json!({
                    "t": "rc:overlay.relay_probe",
                    "relay_node_id": target["relay_node_id"],
                    "endpoint": target["endpoints"][0],
                    "reachable": true,
                    "rtt_ms": rtt,
                });
                ws.send(Message::Text(probe.to_string().into()))
                    .await
                    .unwrap();
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    async fn request(&mut self) {
        let msg = json!({ "t": "rc:overlay.relay_request", "peer_node_id": self.b_node });
        self.members[0]
            .0
            .send(Message::Text(msg.to_string().into()))
            .await
            .unwrap();
    }

    /// Whether relay `i` is told to serve the pair within `wait`.
    async fn serves(&mut self, i: usize, wait: Duration) -> bool {
        recv_t(&mut self.relays[i].1, "rc:overlay.relay_serve", wait)
            .await
            .is_some()
    }
}

/// MeshHarbor #5 — a member's RTT to a relay it was only OFFERED (never
/// minted) ranks the pair's first mint. Without the offer the reports were
/// refused and the tie fell to the approval order, so the slower relay won.
#[tokio::test]
async fn the_first_mint_goes_to_the_relay_both_members_measured_fastest() {
    let mut rig = TwoRelays::up("mint-probe-rank").await;
    rig.report_r2_fastest().await;
    rig.request().await;
    assert!(
        rig.serves(1, Duration::from_secs(5)).await,
        "the fast relay serves the pair"
    );
    assert!(
        !rig.serves(0, Duration::from_millis(500)).await,
        "the slow relay does not"
    );
}

/// MeshHarbor #5 — a pair minted before its members' measurements (blind,
/// so on r1) moves once they land, while its session is still unbound.
#[tokio::test]
async fn a_young_pair_moves_to_the_relay_its_first_measurements_rank_fastest() {
    let mut rig = TwoRelays::up("mint-probe-rerank").await;
    rig.request().await;
    assert!(
        rig.serves(0, Duration::from_secs(5)).await,
        "unmeasured, the tie goes to r1"
    );
    rig.report_r2_fastest().await;
    assert!(
        recv_t(
            &mut rig.relays[0].1,
            "rc:overlay.relay_revoke",
            Duration::from_secs(5)
        )
        .await
        .is_some(),
        "r1's young session is revoked"
    );
    assert!(
        rig.serves(1, Duration::from_secs(5)).await,
        "and the pair is minted on r2"
    );
    let rows = audit_rows(&rig.app, &rig.seeded).await;
    assert!(
        rows.iter()
            .any(|r| r["action"] == "revoke" && r["reason"] == "org_relay_rerank"),
        "the move is audited: {rows:?}"
    );
}

/// The happy path, and what a live session changes: three frames with one
/// VNI, a mint row naming every party, an idempotent re-request that re-pushes
/// the same session without a second row, and the server verdict flipping to
/// `org-relay` on the pair's next netmap.
#[tokio::test]
async fn mint_pushes_serve_and_sessions_flips_the_verdict_and_is_idempotent() {
    let mut rig = Rig::up("mint-ok", true, Some(true)).await;
    rig.arm().await;
    rig.request().await;
    let (serve, sa, sb) = rig.expect_minted().await;

    let vni = serve["vni"].as_u64().expect("vni");
    assert!(vni > 0 && vni <= 0xFF_FFFF, "24-bit vni, never 0: {vni}");
    assert_ne!(vni, 0x2112A4, "the STUN cookie is never minted");
    assert_eq!(sa["vni"], json!(vni));
    assert_eq!(sb["vni"], json!(vni));
    assert_eq!(serve["generation"], sa["generation"]);
    assert_eq!(serve["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(sa["peer_node_id"], json!(rig.b_node));
    assert_eq!(sb["peer_node_id"], json!(rig.a_node));
    assert_eq!(sa["relay_node_id"], json!(rig.r_node));
    assert_eq!(
        sa["relay_endpoints"],
        json!(["8.8.8.8:3478"]),
        "the relay's public address, re-paired with its relay port"
    );
    assert_ne!(
        sa["bind_secret"], sb["bind_secret"],
        "one secret per member"
    );
    let secrets: Vec<&Value> = serve["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| &m["bind_secret"])
        .collect();
    assert!(secrets.contains(&&sa["bind_secret"]) && secrets.contains(&&sb["bind_secret"]));
    assert_eq!(sa["bind_secs"], json!(30));
    assert_eq!(serve["idle_secs"], json!(300));
    assert_eq!(serve["max_lifetime_secs"], json!(3600));

    let row = wait_mint_row(&rig.app, &rig.seeded).await;
    assert!(row["denied"].is_null(), "{row}");
    assert_eq!(row["vni"], json!(vni));
    assert_eq!(row["relay_node_id"], json!(rig.r_node));
    assert_eq!(row["agent_id"], json!(rig.r_agent));
    assert_eq!(row["requester_node_id"], json!(rig.a_node));
    assert_eq!(row["peer_node_id"], json!(rig.b_node));
    assert_eq!(row["warn_only"], json!(false));
    let rows_before = audit_rows(&rig.app, &rig.seeded).await.len();

    // Idempotent: the same pair asks again → the SAME session comes back to
    // the asker, nobody else hears anything, no new row.
    rig.request().await;
    let again = recv_t(
        &mut rig.a,
        "rc:overlay.relay_session",
        Duration::from_secs(5),
    )
    .await
    .expect("re-push to the asker");
    assert_eq!(again["vni"], json!(vni));
    assert_eq!(again["bind_secret"], sa["bind_secret"]);
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_serve",
            Duration::from_millis(500)
        )
        .await
        .is_none()
    );
    assert_eq!(audit_rows(&rig.app, &rig.seeded).await.len(), rows_before);

    // The verdict: on a's next netmap, b is stamped `org-relay`.
    let netmap = join(&mut rig.a, 1, Some(true), "203.0.113.10:41641").await;
    let b_entry = netmap["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["node_id"] == json!(rig.b_node))
        .expect("b is in a's netmap");
    assert_eq!(b_entry["relay_strategy"], json!("org-relay"), "{b_entry}");
    let r_entry = netmap["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["node_id"] == json!(rig.r_node))
        .expect("r is in a's netmap");
    assert_ne!(
        r_entry["relay_strategy"],
        json!("org-relay"),
        "only the pair with a session"
    );
}

/// §7 — revocation is a push, from all four triggers. Each trigger starts
/// from a fresh mint; each revoke reaches the relay and both members and
/// leaves an audit row naming the trigger.
#[tokio::test]
async fn all_four_revocation_triggers_push_relay_revoke_to_every_party() {
    let mut rig = Rig::up("mint-revoke", true, Some(true)).await;
    let policy_id = rig.arm().await;

    // 1. Policy revoke — the relay's approval cleared.
    rig.request().await;
    let (serve, _, _) = rig.expect_minted().await;
    let vni1 = serve["vni"].as_u64().unwrap();
    assert_eq!(
        approve(&rig.app, &rig.seeded, &rig.r_agent, false).await,
        200
    );
    rig.expect_revoked(vni1).await;

    // 2. Mode off.
    assert_eq!(
        approve(&rig.app, &rig.seeded, &rig.r_agent, true).await,
        200
    );
    rig.request().await;
    let (serve, _, _) = rig.expect_minted().await;
    let vni2 = serve["vni"].as_u64().unwrap();
    assert_ne!(vni2, vni1, "a re-mint gets a fresh vni");
    assert!(
        serve["generation"].as_u64().unwrap() > 1,
        "generation is monotonic"
    );
    set_mode(&rig.app, &rig.seeded, "off").await;
    rig.expect_revoked(vni2).await;

    // 3. ACL revoke — the grant deleted.
    set_mode(&rig.app, &rig.seeded, "on").await;
    rig.request().await;
    let (serve, _, _) = rig.expect_minted().await;
    let vni3 = serve["vni"].as_u64().unwrap();
    let resp = app_delete(
        &rig.app,
        &url(&rig.seeded, &format!("/overlay-acl/{policy_id}")),
        &rig.seeded.admin.access_token,
    )
    .await;
    assert_eq!(resp, 200, "policy delete");
    rig.expect_revoked(vni3).await;

    // 4. Device removal — the relay deleted from the fleet.
    grant_relay(&rig.app, &rig.seeded, &rig.r_node).await;
    rig.request().await;
    let (serve, _, _) = rig.expect_minted().await;
    let vni4 = serve["vni"].as_u64().unwrap();
    let resp = app_delete(
        &rig.app,
        &url(&rig.seeded, &format!("/agent/{}", rig.r_agent)),
        &rig.seeded.admin.access_token,
    )
    .await;
    assert_eq!(resp, 200, "agent delete");
    let wait = Duration::from_secs(5);
    for (name, ws) in [("a", &mut rig.a), ("b", &mut rig.b)] {
        let v = recv_t(ws, "rc:overlay.relay_revoke", wait)
            .await
            .unwrap_or_else(|| panic!("{name} receives relay_revoke after the relay was removed"));
        assert_eq!(v["vni"], json!(vni4));
    }

    let reasons: Vec<String> = audit_rows(&rig.app, &rig.seeded)
        .await
        .iter()
        .filter(|r| r["action"] == json!("revoke"))
        .filter_map(|r| r["reason"].as_str().map(str::to_string))
        .collect();
    for want in [
        "policy_revoked",
        "mode_off",
        "acl_revoked",
        "device_removed",
    ] {
        assert!(
            reasons.contains(&want.to_string()),
            "missing revoke reason {want} in {reasons:?}"
        );
    }
}

async fn app_delete(app: &TestApp, path: &str, token: &str) -> u16 {
    app.client
        .delete(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Gate 1's two closed postures: `off` writes nothing at all, `warn` decides
/// and audits exactly what `on` would have and pushes nothing.
#[tokio::test]
async fn mode_off_writes_nothing_and_warn_audits_without_pushing() {
    let mut rig = Rig::up("mint-mode", true, Some(true)).await;
    assert_eq!(
        approve(&rig.app, &rig.seeded, &rig.r_agent, true).await,
        200
    );
    grant_relay(&rig.app, &rig.seeded, &rig.r_node).await;

    // off (the default): no frames, no rows.
    rig.request().await;
    rig.assert_nothing_pushed_to_a().await;
    assert!(
        audit_rows(&rig.app, &rig.seeded)
            .await
            .iter()
            .all(|r| r["action"] != json!("mint")),
        "off ⇒ zero MINT rows (the approval writes its own row, legitimately)"
    );

    // warn: the decision is recorded as a would-be mint, nothing is pushed.
    set_mode(&rig.app, &rig.seeded, "warn").await;
    rig.request().await;
    let row = wait_mint_row(&rig.app, &rig.seeded).await;
    assert_eq!(row["warn_only"], json!(true), "{row}");
    assert!(row["denied"].is_null());
    assert!(
        row["vni"].is_number(),
        "warn records the vni it would have issued"
    );
    assert_eq!(row["relay_node_id"], json!(rig.r_node));
    rig.assert_nothing_pushed_to_a().await;
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_serve",
            Duration::from_millis(300)
        )
        .await
        .is_none()
    );
}

/// Every refusal the spec enumerates for the server side, each on its own
/// rig, each audited with its reason and pushing nothing.
#[tokio::test]
async fn every_refusal_is_audited_with_its_reason() {
    // No grant at all → the ACL is an affirmative capability, so no relay.
    {
        let mut rig = Rig::up("mint-noacl", true, Some(true)).await;
        set_mode(&rig.app, &rig.seeded, "on").await;
        assert_eq!(
            approve(&rig.app, &rig.seeded, &rig.r_agent, true).await,
            200
        );
        rig.request().await;
        let row = wait_mint_row(&rig.app, &rig.seeded).await;
        assert_eq!(row["denied"], json!("acl_denied"), "{row}");
        rig.assert_nothing_pushed_to_a().await;
    }
    // Approved but not serving (no `relay-server` on its hello).
    {
        let mut rig = Rig::up("mint-nocap", false, Some(true)).await;
        rig.arm().await;
        rig.request().await;
        let row = wait_mint_row(&rig.app, &rig.seeded).await;
        assert_eq!(row["denied"], json!("no_relay"), "{row}");
        rig.assert_nothing_pushed_to_a().await;
    }
    // The asker joined from a secondary org — or did not say.
    {
        let mut rig = Rig::up("mint-secondary", true, Some(false)).await;
        rig.arm().await;
        rig.request().await;
        let row = wait_mint_row(&rig.app, &rig.seeded).await;
        assert_eq!(row["denied"], json!("secondary_org"), "{row}");
    }
    {
        let mut rig = Rig::up("mint-unsaid", true, None).await;
        rig.arm().await;
        rig.request().await;
        let row = wait_mint_row(&rig.app, &rig.seeded).await;
        assert_eq!(
            row["denied"],
            json!("secondary_org"),
            "an absent flag fails closed: {row}"
        );
    }
    // A static endpoint that is not a public address — refused by the
    // approval route, and refused at mint time when smuggled past it.
    {
        let mut rig = Rig::up("mint-ssrf", true, Some(true)).await;
        rig.arm().await;
        let (s, _) = put(
            &rig.app,
            &url(
                &rig.seeded,
                &format!("/agent/{}/peer-relay-policy", rig.r_agent),
            ),
            &rig.seeded.admin.access_token,
            json!({ "serve": true, "static_endpoints": ["169.254.169.254:80"] }),
        )
        .await;
        assert_eq!(s, 400, "the route refuses a metadata-service endpoint");
        rig.app
            .db
            .collection::<bson::Document>("agents")
            .update_one(
                doc! { "_id": ObjectId::parse_str(&rig.r_agent).unwrap() },
                doc! { "$set": { "peer_relay_policy.static_endpoints": ["10.0.0.5:3478"] } },
            )
            .await
            .unwrap();
        rig.request().await;
        let row = wait_mint_row(&rig.app, &rig.seeded).await;
        assert_eq!(row["denied"], json!("non_routable_endpoint"), "{row}");
        rig.assert_nothing_pushed_to_a().await;
    }
    // The per-(requester, relay) ceiling, pre-spent in process.
    {
        let mut rig = Rig::up("mint-rate", true, Some(true)).await;
        rig.arm().await;
        let (a, r) = (
            ObjectId::parse_str(&rig.a_node).unwrap(),
            ObjectId::parse_str(&rig.r_node).unwrap(),
        );
        for _ in 0..30 {
            assert!(rig.app.state.network().relay_rate_limiter.check(a, r, 30));
        }
        rig.request().await;
        let row = wait_mint_row(&rig.app, &rig.seeded).await;
        assert_eq!(row["denied"], json!("rate_limited"), "{row}");
        assert_eq!(
            row["relay_node_id"].as_str(),
            None,
            "no relay is named on a refusal before the mint"
        );
        rig.assert_nothing_pushed_to_a().await;
    }
    // Unreadable policies: fail CLOSED, with the reason that says so.
    {
        let mut rig = Rig::up("mint-unread", true, Some(true)).await;
        rig.arm().await;
        let tid = ObjectId::parse_str(&rig.seeded.tenant_id).unwrap();
        rig.app
            .db
            .collection::<bson::Document>("overlay_policies")
            .insert_one(doc! {
                "tenant_id": tid,
                "name": "broken",
                "enabled": true,
                "sources": "not-an-array",
                "via": [],
                "destinations": [],
                "created_at": bson::DateTime::now(),
                "updated_at": bson::DateTime::now(),
                "deleted_at": null,
            })
            .await
            .unwrap();
        rig.request().await;
        let row = wait_mint_row(&rig.app, &rig.seeded).await;
        assert_eq!(row["denied"], json!("policy_unreadable"), "{row}");
        rig.assert_nothing_pushed_to_a().await;
    }
}

async fn discover(rig: &mut Rig, peer: &str, request_id: u64) -> Value {
    rig.a.send(Message::Text(json!({
        "t": "rc:overlay.org_relay_discover", "peer_node_id": peer, "request_id": request_id,
    }).to_string().into())).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let reply = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let frame = tokio::time::timeout(remaining, rig.a.next())
            .await
            .expect("discovery deadline")
            .expect("open websocket")
            .expect("websocket frame");
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            assert!(
                !matches!(
                    value["t"].as_str(),
                    Some(
                        "rc:overlay.relay_grant"
                            | "rc:overlay.relay_session"
                            | "rc:overlay.relay_serve"
                            | "rc:overlay.force_derp"
                    )
                ),
                "discovery allocated or changed a carrier before replying: {value}"
            );
            if value["t"] == json!("rc:overlay.org_relay_candidates") {
                break value;
            }
        }
    };
    assert_eq!(reply["request_id"], json!(request_id));
    reply
}

async fn assert_no_discovery_allocation(ws: &mut Ws) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                let value: Value = serde_json::from_str(&text).unwrap();
                assert!(
                    !matches!(
                        value["t"].as_str(),
                        Some(
                            "rc:overlay.relay_grant"
                                | "rc:overlay.relay_session"
                                | "rc:overlay.relay_serve"
                                | "rc:overlay.force_derp"
                        )
                    ),
                    "discovery allocated or changed a carrier: {value}"
                );
            }
            Err(_) => return,
            Ok(Some(Ok(_))) => {}
            other => panic!("unexpected websocket termination: {other:?}"),
        }
    }
}

#[tokio::test]
async fn metadata_discovery_is_bounded_and_never_allocates_or_spends_mint_budget() {
    let mut rig = Rig::up("discovery-ok", true, Some(true)).await;
    rig.arm().await;
    let (status, _) = put(
        &rig.app,
        &url(
            &rig.seeded,
            &format!("/agent/{}/peer-relay-policy", rig.r_agent),
        ),
        &rig.seeded.admin.access_token,
        json!({ "serve": true, "static_endpoints": [
            "1.1.1.1:3478", "9.9.9.9:3478", "8.8.4.4:3478", "1.0.0.1:3478", "9.9.9.10:3478"
        ] }),
    )
    .await;
    assert_eq!(status, 200);
    let peer = rig.b_node.clone();
    for request_id in 1..=2 {
        let reply = discover(&mut rig, &peer, request_id).await;
        assert_eq!(reply["peer_node_id"], json!(peer));
        assert_eq!(reply["ttl_secs"], json!(30));
        let candidates = reply["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0]["relay_node_id"], json!(rig.r_node));
        assert_eq!(candidates[0]["endpoints"].as_array().unwrap().len(), 4);
        assert!(reply.get("vni").is_none() && reply.get("bind_secret").is_none());
    }
    let (a, b, r) = (
        ObjectId::parse_str(&rig.a_node).unwrap(),
        ObjectId::parse_str(&rig.b_node).unwrap(),
        ObjectId::parse_str(&rig.r_node).unwrap(),
    );
    let network = rig.app.state.network();
    assert!(
        network
            .org_relay
            .active_session(&roomler_ai_mod_network::overlay::pair_key(a, b))
            .is_none()
    );
    assert_eq!(network.org_relay.sessions_on_relay(r), 0);
    assert!(
        network.relay_pair_churn.is_empty(),
        "discovery is not TURN churn evidence"
    );
    for _ in 0..30 {
        assert!(
            network.relay_rate_limiter.check(a, r, 30),
            "discovery cannot spend mint budget"
        );
    }
    assert!(
        audit_rows(&rig.app, &rig.seeded)
            .await
            .iter()
            .all(|row| row["action"] != json!("mint"))
    );
    assert_no_discovery_allocation(&mut rig.a).await;
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
}

/// A new requester can cover three authorized one-hop paths; a legacy
/// requester receives exactly the previous single hint. This is metadata,
/// not a bind, route change, probe grant, or session allocation.
#[tokio::test]
async fn metadata_discovery_multi_onehop_negotiates_caps_and_preserves_all_gates() {
    let mut rig = Rig::up("discovery-multi", true, Some(true)).await;
    rig.arm().await;
    let mut relays = Vec::new();
    let mut allowed = vec![rig.r_node.clone()];
    let mut approved_agents = vec![rig.r_agent.clone()];
    // Four eligible relays prove the total cap, plus an approved but
    // ACL-denied relay which may NEVER fill a slot, even when all others go.
    for (index, endpoint) in [
        "1.1.1.1:41641",
        "8.8.4.4:41641",
        "9.9.9.9:41641",
        "1.0.0.1:41641",
    ]
    .into_iter()
    .enumerate()
    {
        let machine = format!("discovery-multi-r{index}");
        let (agent, token) = enroll(&rig.app, &rig.seeded, &machine).await;
        let mut ws = connect(&rig.app, &token, &["relay-server"]).await;
        join(&mut ws, 10 + index as u8, Some(true), endpoint).await;
        let node = node_id(&rig.app, &rig.seeded, &machine).await;
        assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
        if index < 3 {
            grant_relay(&rig.app, &rig.seeded, &node).await;
            allowed.push(node);
            approved_agents.push(agent);
        }
        relays.push(ws);
    }
    let peer = rig.b_node.clone();
    let old = discover(&mut rig, &peer, 1).await;
    assert_eq!(old["candidates"].as_array().unwrap().len(), 1);
    let rejoin = |flag| {
        json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([1;32]),
        "mtu":1280, "endpoints":["203.0.113.10:41641"], "supports_org_relay":true,
        "supports_server_relay_strategy":true, "org_primary":true, "relay_port":3478,
        "supports_org_relay_multi_candidate":flag})
    };
    rig.a
        .send(Message::Text(rejoin(false).to_string().into()))
        .await
        .unwrap();
    recv_t(&mut rig.a, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
    let explicit_false = discover(&mut rig, &peer, 2).await;
    assert_eq!(
        explicit_false["candidates"], old["candidates"],
        "missing and false retain the exact legacy hint"
    );
    rig.a
        .send(Message::Text(rejoin(true).to_string().into()))
        .await
        .unwrap();
    recv_t(&mut rig.a, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
    let new = discover(&mut rig, &peer, 3).await;
    let hints = new["candidates"].as_array().unwrap();
    assert_eq!(hints.len(), 3);
    assert_eq!(
        hints[0], old["candidates"][0],
        "preserve existing preference order"
    );
    let ids: std::collections::HashSet<_> = hints
        .iter()
        .map(|c| c["relay_node_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 3, "no duplicate candidate identities");
    assert!(
        ids.iter().all(|id| allowed.contains(id)),
        "only the shared planner's ACL-authorized relays"
    );
    assert!(hints.iter().all(|c| {
        c.get("exit_relay_node_id").is_none()
            && c["endpoints"]
                .as_array()
                .is_some_and(|e| !e.is_empty() && e.len() <= 4)
    }));
    assert_eq!(new["ttl_secs"], json!(30));
    // Remove the preferred relay through the real policy API. Discovery
    // must still expose all three remaining eligible paths, not starvation.
    let first = hints[0]["relay_node_id"].as_str().unwrap();
    let first_index = allowed.iter().position(|id| id == first).unwrap();
    assert_eq!(
        approve(&rig.app, &rig.seeded, &approved_agents[first_index], false).await,
        200
    );
    let after = discover(&mut rig, &peer, 4).await;
    let after = after["candidates"].as_array().unwrap();
    assert_eq!(after.len(), 3);
    assert!(after.iter().all(|c| c["relay_node_id"] != json!(first)));
    for agent in &approved_agents {
        assert_eq!(approve(&rig.app, &rig.seeded, agent, false).await, 200);
    }
    let empty = discover(&mut rig, &peer, 5).await;
    assert_eq!(
        empty["candidates"],
        json!([]),
        "approved but ACL-denied cannot leak as fallback"
    );
    assert_eq!(empty["ttl_secs"], json!(0));
    assert!(
        rig.app
            .state
            .network()
            .org_relay
            .active_session(&roomler_ai_mod_network::overlay::pair_key(
                ObjectId::parse_str(&rig.a_node).unwrap(),
                ObjectId::parse_str(&peer).unwrap()
            ))
            .is_none()
    );
    assert!(
        audit_rows(&rig.app, &rig.seeded)
            .await
            .iter()
            .all(|r| r["action"] != json!("mint"))
    );
    assert_no_discovery_allocation(&mut rig.a).await;
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
    for ws in &mut relays {
        assert_no_discovery_allocation(ws).await;
    }
}

#[tokio::test]
async fn metadata_discovery_respects_modes_approval_acl_and_primary() {
    let mut rig = Rig::up("discovery-gates", true, Some(true)).await;
    let grant = rig.arm().await;
    let peer = rig.b_node.clone();
    for (request_id, mode) in [(1, "off"), (2, "warn")] {
        set_mode(&rig.app, &rig.seeded, mode).await;
        let reply = discover(&mut rig, &peer, request_id).await;
        assert_eq!(reply["candidates"], json!([]));
        assert_eq!(reply["ttl_secs"], json!(0));
    }
    set_mode(&rig.app, &rig.seeded, "on").await;
    approve(&rig.app, &rig.seeded, &rig.r_agent, false).await;
    assert_eq!(discover(&mut rig, &peer, 3).await["candidates"], json!([]));
    approve(&rig.app, &rig.seeded, &rig.r_agent, true).await;
    assert_eq!(
        app_delete(
            &rig.app,
            &url(&rig.seeded, &format!("/overlay-acl/{grant}")),
            &rig.seeded.admin.access_token
        )
        .await,
        200
    );
    assert_eq!(
        discover(&mut rig, &peer, 4).await["candidates"],
        json!([]),
        "relay ACL must affirmatively authorize both endpoints"
    );
    grant_relay(&rig.app, &rig.seeded, &rig.r_node).await;
    // Rejoining as a secondary loses eligibility despite a valid agent JWT.
    join(&mut rig.a, 1, Some(false), "203.0.113.10:41641").await;
    assert_eq!(discover(&mut rig, &peer, 5).await["candidates"], json!([]));
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
}

#[tokio::test]
async fn metadata_discovery_rejects_cross_tenant_and_bounds_requester_flood() {
    let mut rig = Rig::up("discovery-flood", true, Some(true)).await;
    rig.arm().await;
    let other = rig.app.seed_tenant("discovery-other").await;
    let (_, token) = enroll(&rig.app, &other, "discovery-other-node").await;
    let mut outsider = connect(&rig.app, &token, &[]).await;
    join(&mut outsider, 9, Some(true), "203.0.113.99:41641").await;
    let outside_id = node_id(&rig.app, &other, "discovery-other-node").await;
    rig.a.send(Message::Text(json!({ "t": "rc:overlay.org_relay_discover", "peer_node_id": outside_id, "request_id": 1 }).to_string().into())).await.unwrap();
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.org_relay_candidates",
            Duration::from_millis(200)
        )
        .await
        .is_none()
    );
    let peer = rig.b_node.clone();
    // The refused cross-tenant request already consumed one requester slot.
    for request_id in 2..=6 {
        assert_eq!(
            discover(&mut rig, &peer, request_id).await["candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    rig.a
        .send(Message::Text(
            json!({ "t": "rc:overlay.org_relay_discover", "peer_node_id": peer, "request_id": 7 })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.org_relay_candidates",
            Duration::from_millis(200)
        )
        .await
        .is_none()
    );
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
}

#[tokio::test]
async fn metadata_discovery_requires_actual_relay_server_capability() {
    let mut rig = Rig::up("discovery-not-serving", false, Some(true)).await;
    rig.arm().await;
    let peer = rig.b_node.clone();
    let reply = discover(&mut rig, &peer, 1).await;
    assert_eq!(reply["candidates"], json!([]));
    assert_eq!(reply["ttl_secs"], json!(0));
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
}

#[tokio::test]
async fn live_listener_withdrawal_revokes_and_removes_discovery_without_reconnect() {
    let mut rig = Rig::up("listener-withdraw", true, Some(true)).await;
    rig.arm().await;
    let peer = rig.b_node.clone();
    assert_eq!(
        discover(&mut rig, &peer, 1).await["candidates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    rig.request().await;
    let (serve, _, _) = rig.expect_minted().await;
    let vni = serve["vni"].as_u64().unwrap();
    // Same authenticated relay WS, same WG identity and advertised carrier
    // endpoint. Only the actual org-relay listener stopped. No disconnect,
    // user/admin policy edit, or false capability blob is used to hide it.
    rig.r
        .send(Message::Text(
            json!({
                "t": "rc:overlay.join", "wg_public_key": BASE64.encode([3; 32]),
                "mtu": 1280, "endpoints": ["8.8.8.8:41641"],
                "supports_org_relay": true, "supports_server_relay_strategy": true,
                "org_primary": true
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    rig.expect_revoked(vni).await;
    let map = recv_t(&mut rig.r, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(map["org_relay_discovery"], json!(true));
    assert_eq!(discover(&mut rig, &peer, 2).await["candidates"], json!([]));
    let node = ObjectId::parse_str(&rig.r_node).unwrap();
    let agent = ObjectId::parse_str(&rig.r_agent).unwrap();
    assert!(
        rig.app
            .state
            .network()
            .org_relay
            .join_extras(node)
            .relay_withdrawn
    );
    assert!(
        rig.app.state.fleet().rc_hub.is_agent_online(agent),
        "relay control WS never disconnected"
    );
    assert!(
        rig.app
            .state
            .fleet()
            .agents
            .base
            .find_by_id(agent)
            .await
            .unwrap()
            .capabilities
            .has_rpc(roomler_ai_remote_control::models::RpcCap::RelayServer),
        "explicit port withdrawal must win even before heartbeat caps arrive"
    );
    assert_eq!(rig.app.state.network().org_relay.sessions_on_relay(node), 0);
    assert!(
        audit_rows(&rig.app, &rig.seeded)
            .await
            .iter()
            .any(|row| row["action"] == json!("revoke")
                && row["reason"] == json!("listener_changed"))
    );
    // Repeated empty advertisement does not resurrect a default-port relay.
    rig.r
        .send(Message::Text(
            json!({
                "t": "rc:overlay.join", "wg_public_key": BASE64.encode([3; 32]),
                "mtu": 1280, "endpoints": ["8.8.8.8:41641"],
                "supports_org_relay": true, "org_primary": true
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    recv_t(&mut rig.r, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(discover(&mut rig, &peer, 3).await["candidates"], json!([]));
    // Recovery uses the same WS, not a new enrollment or manual relay list.
    join(&mut rig.r, 3, Some(true), "8.8.8.8:41641").await;
    assert_eq!(
        discover(&mut rig, &peer, 4).await["candidates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_no_discovery_allocation(&mut rig.a).await;
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
}

async fn trial_join(ws: &mut Ws, seed: u8, capable: bool) {
    ws.send(Message::Text(
        json!({
            "t": "rc:overlay.join", "wg_public_key": BASE64.encode([seed; 32]),
            "mtu": 1280, "endpoints": ["203.0.113.10:41641"],
            "supports_org_relay": true, "supports_path_trial_v1": capable,
            "supports_server_relay_strategy": true, "org_primary": true, "relay_port": 3478
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let map = recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(map["path_trial_v1"], json!(true));
}

async fn trial_message(ws: &mut Ws, kind: &str, id: &Value) {
    ws.send(Message::Text(
        json!({ "t": kind, "trial_id": id }).to_string().into(),
    ))
    .await
    .unwrap();
}

async fn begin_trial(rig: &mut Rig, request_id: u64) -> (Value, Value, Value) {
    rig.a
        .send(Message::Text(
            json!({
                "t": "rc:overlay.path_trial_request", "peer_node_id": rig.b_node,
                "relay_node_id": rig.r_node, "request_id": request_id
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let relay = recv_t(&mut rig.r, "rc:overlay.relay_serve", Duration::from_secs(5))
        .await
        .unwrap();
    let a = recv_t(
        &mut rig.a,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let b = recv_t(
        &mut rig.b,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    (relay, a, b)
}

/// Two equally authorized relays: no probe result or policy change is used
/// to manufacture a different ranking. A caller may choose a fresh non-first
/// hint, but the server must still reauthorize that EXACT requested relay.
async fn alternate_onehop_fixture(slug: &str) -> (Rig, Ws, String, String, String, String) {
    let mut rig = Rig::up(slug, true, Some(true)).await;
    let original_acl = rig.arm().await;
    let machine = format!("{slug}-extra");
    let (agent, token) = enroll(&rig.app, &rig.seeded, &machine).await;
    let mut extra = connect(&rig.app, &token, &["relay-server"]).await;
    join(&mut extra, 4, Some(true), "1.1.1.1:41641").await;
    let node = node_id(&rig.app, &rig.seeded, &machine).await;
    assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
    let extra_acl = grant_relay(&rig.app, &rig.seeded, &node).await;
    for (ws, seed) in [(&mut rig.a, 1u8), (&mut rig.b, 2u8)] {
        ws.send(Message::Text(
            json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([seed;32]),
                "mtu":1280, "endpoints":["203.0.113.10:41641"], "supports_org_relay":true,
                "supports_path_trial_v1":true, "supports_org_relay_multi_candidate":true,
                "supports_server_relay_strategy":true, "org_primary":true, "relay_port":3478
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
            .await
            .unwrap();
    }
    (rig, extra, agent, node, original_acl, extra_acl)
}

async fn request_onehop(rig: &mut Rig, relay: &str, serial: u64) {
    rig.a
        .send(Message::Text(
            json!({"t":"rc:overlay.path_trial_request",
                "peer_node_id":rig.b_node, "relay_node_id":relay, "request_id":serial
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn path_trial_nonpreferred_onehop_is_fresh_authorized_and_revocation_fails_closed() {
    let (mut rig, mut extra, extra_agent, extra_node, _, _) =
        alternate_onehop_fixture("trial-alternate").await;
    let peer = rig.b_node.clone();
    let metadata = discover(&mut rig, &peer, 1).await;
    let hints = metadata["candidates"].as_array().unwrap();
    assert_eq!(hints.len(), 2);
    let preferred = hints[0]["relay_node_id"].as_str().unwrap().to_owned();
    let requested = hints[1]["relay_node_id"].as_str().unwrap().to_owned();
    assert_ne!(requested, preferred);
    assert!(requested == rig.r_node || requested == extra_node);
    request_onehop(&mut rig, &requested, 41).await;
    let a = recv_t(
        &mut rig.a,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .expect("fresh authorized nonpreferred discovery hint must be requestable");
    let b = recv_t(
        &mut rig.b,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let serve = recv_t(
        if requested == rig.r_node {
            &mut rig.r
        } else {
            &mut extra
        },
        "rc:overlay.relay_serve",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(a["relay_node_id"], json!(requested));
    assert_eq!(b["relay_node_id"], json!(requested));
    assert_eq!(a["trial_id"], b["trial_id"]);
    assert_eq!(a["vni"], serve["vni"]);
    assert_eq!(a["generation"], serve["generation"]);
    assert_eq!(a["peer_wg_public_key"], json!(BASE64.encode([2; 32])));
    assert_eq!(b["peer_wg_public_key"], json!(BASE64.encode([1; 32])));
    assert_no_discovery_allocation(if requested == rig.r_node {
        &mut extra
    } else {
        &mut rig.r
    })
    .await;
    // Do not trust a previously authorized cached hint after approval changes.
    let agent = if requested == rig.r_node {
        rig.r_agent.clone()
    } else {
        extra_agent
    };
    assert_eq!(approve(&rig.app, &rig.seeded, &agent, false).await, 200);
    for ws in [&mut rig.a, &mut rig.b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_abort", Duration::from_secs(5))
                .await
                .unwrap()["trial_id"],
            a["trial_id"]
        );
    }
    let relay = if requested == rig.r_node {
        &mut rig.r
    } else {
        &mut extra
    };
    assert_eq!(
        recv_t(relay, "rc:overlay.relay_revoke", Duration::from_secs(5))
            .await
            .unwrap()["vni"],
        serve["vni"]
    );
    request_onehop(&mut rig, &requested, 42).await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_start",
            Duration::from_millis(250)
        )
        .await
        .is_none()
    );
    assert_no_discovery_allocation(&mut rig.r).await;
    assert_no_discovery_allocation(&mut extra).await;
}

#[tokio::test]
async fn path_trial_nonpreferred_onehop_acl_removed_does_not_fall_back_to_other_relay() {
    let (mut rig, mut extra, _, extra_node, original_acl, extra_acl) =
        alternate_onehop_fixture("trial-alternate-acl").await;
    let peer = rig.b_node.clone();
    let metadata = discover(&mut rig, &peer, 1).await;
    let hints = metadata["candidates"].as_array().unwrap();
    assert_eq!(hints.len(), 2);
    let preferred = hints[0]["relay_node_id"].as_str().unwrap().to_owned();
    let requested = hints[1]["relay_node_id"].as_str().unwrap().to_owned();
    let acl = if requested == rig.r_node {
        original_acl
    } else {
        extra_acl
    };
    assert_eq!(
        app_delete(
            &rig.app,
            &url(&rig.seeded, &format!("/overlay-acl/{acl}")),
            &rig.seeded.admin.access_token
        )
        .await,
        200
    );
    request_onehop(&mut rig, &requested, 51).await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_start",
            Duration::from_millis(250)
        )
        .await
        .is_none()
    );
    assert_no_discovery_allocation(&mut rig.r).await;
    assert_no_discovery_allocation(&mut extra).await;
    let fresh = discover(&mut rig, &peer, 2).await;
    assert_eq!(fresh["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(fresh["candidates"][0]["relay_node_id"], json!(preferred));
    assert!(requested == rig.r_node || requested == extra_node);
    // Authorization still works for the other actual relay: rejection cannot
    // be a false-positive caused by missing path capability or a closed WS.
    request_onehop(&mut rig, &preferred, 52).await;
    let start = recv_t(
        &mut rig.a,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(start["relay_node_id"], json!(preferred));
}

#[tokio::test]
async fn path_trial_bilateral_ack_preserves_active_session_and_uses_independent_vni() {
    let mut rig = Rig::up("trial-commit", true, Some(true)).await;
    rig.arm().await;
    trial_join(&mut rig.a, 1, true).await;
    trial_join(&mut rig.b, 2, true).await;
    rig.request().await;
    let (old, _, _) = rig.expect_minted().await;
    let (relay, a, b) = begin_trial(&mut rig, 1).await;
    assert_ne!(
        old["vni"], relay["vni"],
        "candidate cannot overwrite active relay session"
    );
    assert_eq!(a["vni"], relay["vni"]);
    assert_eq!(a["trial_id"], b["trial_id"]);
    assert_ne!(a["bind_secret"], b["bind_secret"]);
    assert_eq!(a["peer_wg_public_key"], json!(BASE64.encode([2; 32])));
    let id = &a["trial_id"];
    trial_message(&mut rig.a, "rc:overlay.path_trial_ready", id).await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_commit",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
    trial_message(&mut rig.b, "rc:overlay.path_trial_ready", id).await;
    for ws in [&mut rig.a, &mut rig.b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_commit", Duration::from_secs(5))
                .await
                .unwrap()["trial_id"],
            *id
        );
    }
    trial_message(&mut rig.a, "rc:overlay.path_trial_committed", id).await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_finalize",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
    trial_message(&mut rig.b, "rc:overlay.path_trial_committed", id).await;
    for ws in [&mut rig.a, &mut rig.b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_finalize", Duration::from_secs(5))
                .await
                .unwrap()["trial_id"],
            *id
        );
    }
    let pair = roomler_ai_mod_network::overlay::pair_key(
        ObjectId::parse_str(&rig.a_node).unwrap(),
        ObjectId::parse_str(&rig.b_node).unwrap(),
    );
    assert_eq!(
        rig.app
            .state
            .network()
            .org_relay
            .active_session(&pair)
            .unwrap()
            .vni,
        old["vni"].as_u64().unwrap() as u32
    );
    assert_eq!(
        rig.app
            .state
            .network()
            .org_relay
            .sessions_on_relay(ObjectId::parse_str(&rig.r_node).unwrap()),
        2
    );
    // Replaying an already finalized request does not allocate another VNI.
    rig.a
        .send(Message::Text(
            json!({ "t": "rc:overlay.path_trial_request", "peer_node_id": rig.b_node,
        "relay_node_id": rig.r_node, "request_id": 1 })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_finalize",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["trial_id"],
        *id
    );
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_serve",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );

    // A late preparation failure must not roll back one finalized member.
    trial_message(&mut rig.a, "rc:overlay.path_trial_abort", id).await;
    assert!(
        recv_t(
            &mut rig.b,
            "rc:overlay.path_trial_abort",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn path_trial_legacy_peer_is_not_sent_new_variant_and_revoke_covers_trial() {
    let mut rig = Rig::up("trial-gates", true, Some(true)).await;
    rig.arm().await;
    trial_join(&mut rig.a, 1, true).await;
    // b is the legacy/default-false peer. Nothing may be installed on relay.
    rig.a
        .send(Message::Text(
            json!({ "t": "rc:overlay.path_trial_request", "peer_node_id": rig.b_node,
        "relay_node_id": rig.r_node, "request_id": 1 })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_serve",
            Duration::from_millis(150)
        )
        .await
        .is_none()
    );
    assert!(
        recv_t(
            &mut rig.b,
            "rc:overlay.path_trial_start",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
    trial_join(&mut rig.b, 2, true).await;
    let (_, a, _) = begin_trial(&mut rig, 2).await;
    assert_eq!(
        approve(&rig.app, &rig.seeded, &rig.r_agent, false).await,
        200
    );
    for ws in [&mut rig.a, &mut rig.b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_abort", Duration::from_secs(5))
                .await
                .unwrap()["trial_id"],
            a["trial_id"]
        );
    }
    assert_eq!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["vni"],
        a["vni"]
    );
    assert_eq!(
        rig.app
            .state
            .network()
            .org_relay
            .sessions_on_relay(ObjectId::parse_str(&rig.r_node).unwrap()),
        0
    );
}

async fn finalize_trial_for_return(rig: &mut Rig) -> Value {
    let (_, a, _) = begin_trial(rig, 1).await;
    let id = a["trial_id"].clone();
    for ws in [&mut rig.a, &mut rig.b] {
        trial_message(ws, "rc:overlay.path_trial_ready", &id).await;
    }
    for ws in [&mut rig.a, &mut rig.b] {
        recv_t(ws, "rc:overlay.path_trial_commit", Duration::from_secs(5))
            .await
            .unwrap();
    }
    for ws in [&mut rig.a, &mut rig.b] {
        trial_message(ws, "rc:overlay.path_trial_committed", &id).await;
    }
    for ws in [&mut rig.a, &mut rig.b] {
        recv_t(ws, "rc:overlay.path_trial_finalize", Duration::from_secs(5))
            .await
            .unwrap();
    }
    a
}

async fn return_message(ws: &mut Ws, kind: &str, id: &Value, return_id: &str) {
    ws.send(Message::Text(
        json!({"t":kind,"trial_id":id,"return_id":return_id})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
}

async fn expect_return_both(rig: &mut Rig, kind: &str, return_id: &str) {
    for ws in [&mut rig.a, &mut rig.b] {
        assert_eq!(
            recv_t(ws, kind, Duration::from_secs(5)).await.unwrap()["return_id"],
            json!(return_id)
        );
    }
}

#[tokio::test]
async fn path_trial_return_bilateral_ack_retires_vni_only_after_both_and_fences_stale_attempt() {
    let mut rig = Rig::up("trial-return", true, Some(true)).await;
    rig.arm().await;
    trial_join(&mut rig.a, 1, true).await;
    trial_join(&mut rig.b, 2, true).await;
    let trial = finalize_trial_for_return(&mut rig).await;
    let id = &trial["trial_id"];
    let stale = ObjectId::new().to_hex();
    // The relay itself is not a member and cannot ask peers to change senders.
    return_message(
        &mut rig.r,
        "rc:overlay.path_trial_return_request",
        id,
        &stale,
    )
    .await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_return_prepare",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
    return_message(
        &mut rig.a,
        "rc:overlay.path_trial_return_request",
        id,
        &stale,
    )
    .await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_prepare", &stale).await;
    return_message(&mut rig.a, "rc:overlay.path_trial_return_abort", id, &stale).await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_abort", &stale).await;
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_millis(100)
        )
        .await
        .is_none(),
        "failed healthy return keeps relay allocation"
    );

    // Recovery after a lost ReturnAbort: either phase retransmission or
    // duplicate request replays the aborted decision; no one-sided timeout.
    return_message(&mut rig.b, "rc:overlay.path_trial_returned", id, &stale).await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_abort", &stale).await;
    return_message(
        &mut rig.a,
        "rc:overlay.path_trial_return_request",
        id,
        &stale,
    )
    .await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_abort", &stale).await;
    let fresh = ObjectId::new().to_hex();
    return_message(
        &mut rig.a,
        "rc:overlay.path_trial_return_request",
        id,
        &fresh,
    )
    .await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_prepare", &fresh).await;
    // Delayed old attempt messages cannot abort or ready the new attempt.
    return_message(&mut rig.b, "rc:overlay.path_trial_return_ready", id, &stale).await;
    return_message(&mut rig.a, "rc:overlay.path_trial_return_abort", id, &stale).await;
    return_message(&mut rig.a, "rc:overlay.path_trial_return_ready", id, &fresh).await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_return_commit",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
    return_message(&mut rig.b, "rc:overlay.path_trial_return_ready", id, &fresh).await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_commit", &fresh).await;
    return_message(&mut rig.a, "rc:overlay.path_trial_returned", id, &fresh).await;
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_millis(100)
        )
        .await
        .is_none(),
        "one ACK cannot release a live receive path"
    );
    return_message(&mut rig.b, "rc:overlay.path_trial_returned", id, &fresh).await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_finalize", &fresh).await;
    assert_eq!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["vni"],
        trial["vni"]
    );
    assert_eq!(
        rig.app
            .state
            .network()
            .org_relay
            .sessions_on_relay(ObjectId::parse_str(&rig.r_node).unwrap()),
        0
    );
    return_message(&mut rig.a, "rc:overlay.path_trial_return_abort", id, &fresh).await;
    return_message(&mut rig.b, "rc:overlay.path_trial_returned", id, &fresh).await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_finalize", &fresh).await;
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_millis(100)
        )
        .await
        .is_none(),
        "duplicate ack is idempotent"
    );
}

#[tokio::test]
async fn path_trial_return_authorization_revoke_is_strict_abort_not_healthy_return() {
    let mut rig = Rig::up("return-revoke", true, Some(true)).await;
    rig.arm().await;
    trial_join(&mut rig.a, 1, true).await;
    trial_join(&mut rig.b, 2, true).await;
    let trial = finalize_trial_for_return(&mut rig).await;
    let id = &trial["trial_id"];
    let return_id = ObjectId::new().to_hex();
    return_message(
        &mut rig.a,
        "rc:overlay.path_trial_return_request",
        id,
        &return_id,
    )
    .await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_prepare", &return_id).await;
    assert_eq!(
        approve(&rig.app, &rig.seeded, &rig.r_agent, false).await,
        200
    );
    for ws in [&mut rig.a, &mut rig.b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_abort", Duration::from_secs(5))
                .await
                .unwrap()["trial_id"],
            *id
        );
    }
    assert_eq!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["vni"],
        trial["vni"]
    );
    return_message(
        &mut rig.a,
        "rc:overlay.path_trial_return_ready",
        id,
        &return_id,
    )
    .await;
    return_message(
        &mut rig.b,
        "rc:overlay.path_trial_return_ready",
        id,
        &return_id,
    )
    .await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_return_commit",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
}

async fn backbone_join(ws: &mut Ws, seed: u8, path: bool, serving: bool, endpoint: &str) {
    ws.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([seed;32]),"mtu":1280,"endpoints":[endpoint],"supports_org_relay":true,"supports_server_relay_strategy":true,"supports_path_trial_v1":true,"supports_path_backbone_v1":path,"relay_backbone_ready":serving,"org_primary":true,"relay_port":3478}).to_string().into())).await.unwrap();
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
}
async fn request_backbone(rig: &mut Rig, exit: &str, serial: u64) {
    rig.a.send(Message::Text(json!({"t":"rc:overlay.path_trial_request","peer_node_id":rig.b_node,"relay_node_id":rig.r_node,"exit_relay_node_id":exit,"request_id":serial}).to_string().into())).await.unwrap();
}

#[tokio::test]
async fn backbone_discovery_trial_dual_grants_return_and_edge_withdrawal_are_one_authorized_path() {
    let mut rig = Rig::up("backbone-path", true, Some(true)).await;
    rig.arm().await;
    let (exit_agent, exit_token) = enroll(&rig.app, &rig.seeded, "backbone-exit").await;
    let mut exit = connect(&rig.app, &exit_token, &["relay-server"]).await;
    join(&mut exit, 4, Some(true), "8.8.4.4:41641").await;
    let exit_node = node_id(&rig.app, &rig.seeded, "backbone-exit").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &exit_agent, true).await, 200);
    grant_relay(&rig.app, &rig.seeded, &exit_node).await;
    let source_policy = url(
        &rig.seeded,
        &format!("/agent/{}/peer-relay-policy", rig.r_agent),
    );
    assert_eq!(put(&rig.app,&source_policy,&rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":"10.20.0.2:3478"}]})).await.0,200);
    backbone_join(&mut rig.a, 1, true, false, "203.0.113.10:41641").await;
    backbone_join(&mut rig.b, 2, true, false, "203.0.113.11:41641").await;
    // No bridge offer from the native source: approved topology alone cannot
    // create a private dial task or even advertise a two-hop candidate.
    let peer = rig.b_node.clone();
    let metadata = discover(&mut rig, &peer, 1).await;
    assert!(
        metadata["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c.get("exit_relay_node_id").is_none())
    );
    backbone_join(&mut rig.r, 3, true, true, "8.8.8.8:41641").await;
    // Both API and fresh mint defend the tenant's real overlay range, not
    // merely the native operator's exclusion inventory or an old hint.
    // New tenants use carved /22 blocks above the legacy reserve. Derive
    // the forbidden underlay from an actually leased node in THIS tenant,
    // not a hard-coded address that may belong to another/legacy range.
    let state = rig.app.state.network();
    let tid = ObjectId::parse_str(&rig.seeded.tenant_id).unwrap();
    let network = state.overlay_networks.get_or_create(tid).await.unwrap();
    let peer_row = state
        .overlay_nodes
        .base
        .find_by_id(ObjectId::parse_str(&rig.b_node).unwrap())
        .await
        .unwrap();
    assert!(
        roomler_ai_remote_control::models::overlay_host(&network.cidr, &peer_row.overlay_ip)
            .is_some(),
        "fixture forbidden address must belong to this tenant's actual CIDR"
    );
    let overlay_endpoint = format!("{}:3478", peer_row.overlay_ip);
    assert_eq!(put(&rig.app,&source_policy,&rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":overlay_endpoint}]})).await.0,400);
    {
        let state = rig.app.state.network();
        let tid = ObjectId::parse_str(&rig.seeded.tenant_id).unwrap();
        let aid = ObjectId::parse_str(&rig.r_agent).unwrap();
        let mut policy = state
            .fleet
            .agents
            .find_live_in_tenant(tid, aid)
            .await
            .unwrap()
            .peer_relay_policy;
        policy.approved_backbone_edges[0].endpoint = overlay_endpoint.clone();
        state
            .fleet
            .agents
            .update_peer_relay_policy(tid, aid, &policy)
            .await
            .unwrap();
        // Deliberately bypass the route: fresh planner/discovery must reject
        // persisted invalid edges without relying on an eligibility nudge.
    }
    let metadata = discover(&mut rig, &peer, 2).await;
    assert!(
        metadata["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c.get("exit_relay_node_id").is_none()),
        "stored invalid edges cannot be discovered"
    );
    rig.b.send(Message::Text(json!({"t":"rc:overlay.path_trial_request","peer_node_id":rig.a_node,"relay_node_id":rig.r_node,"exit_relay_node_id":exit_node,"request_id":90}).to_string().into())).await.unwrap();
    assert!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_serve",
            Duration::from_millis(100)
        )
        .await
        .is_none(),
        "fresh trial rejects a persisted overlay-target edge"
    );
    assert_eq!(put(&rig.app,&source_policy,&rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":"10.20.0.2:3478"}]})).await.0,200);
    let metadata = discover(&mut rig, &peer, 3).await;
    assert!(
        metadata["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["relay_node_id"] == rig.r_node && c["exit_relay_node_id"] == exit_node)
    );
    assert!(
        !metadata.to_string().contains("10.20.0.2"),
        "private underlay targets never go to leaf clients"
    );
    request_backbone(&mut rig, &exit_node, 1).await;
    let first = recv_t(&mut rig.r, "rc:overlay.relay_serve", Duration::from_secs(5))
        .await
        .unwrap();
    let bridge = recv_t(
        &mut rig.r,
        "rc:overlay.relay_bridge_serve",
        Duration::from_secs(5),
    )
    .await
    .unwrap()["bridge"]
        .clone();
    let second = recv_t(&mut exit, "rc:overlay.relay_serve", Duration::from_secs(5))
        .await
        .unwrap();
    let a = recv_t(
        &mut rig.a,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let b = recv_t(
        &mut rig.b,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(a["relay_node_id"], rig.r_node);
    assert_eq!(b["relay_node_id"], exit_node);
    assert_eq!(a["vni"], first["vni"]);
    assert_eq!(b["vni"], second["vni"]);
    assert_eq!(bridge["local_vni"], first["vni"]);
    assert_eq!(bridge["remote_vni"], second["vni"]);
    assert_eq!(bridge["source_agent_id"], rig.r_agent);
    assert_eq!(bridge["target_agent_id"], exit_agent);
    assert_eq!(
        bridge["local_bind_secret"],
        first["members"][1]["bind_secret"]
    );
    assert_eq!(
        bridge["remote_bind_secret"],
        second["members"][0]["bind_secret"]
    );
    assert_eq!(a["bind_secret"], first["members"][0]["bind_secret"]);
    assert_eq!(b["bind_secret"], second["members"][1]["bind_secret"]);
    let id = &a["trial_id"];
    for ws in [&mut rig.a, &mut rig.b] {
        trial_message(ws, "rc:overlay.path_trial_ready", id).await;
    }
    for ws in [&mut rig.a, &mut rig.b] {
        recv_t(ws, "rc:overlay.path_trial_commit", Duration::from_secs(5))
            .await
            .unwrap();
    }
    for ws in [&mut rig.a, &mut rig.b] {
        trial_message(ws, "rc:overlay.path_trial_committed", id).await;
    }
    for ws in [&mut rig.a, &mut rig.b] {
        recv_t(ws, "rc:overlay.path_trial_finalize", Duration::from_secs(5))
            .await
            .unwrap();
    }
    let ret = ObjectId::new().to_hex();
    return_message(&mut rig.a, "rc:overlay.path_trial_return_request", id, &ret).await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_prepare", &ret).await;
    for ws in [&mut rig.a, &mut rig.b] {
        return_message(ws, "rc:overlay.path_trial_return_ready", id, &ret).await;
    }
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_commit", &ret).await;
    return_message(&mut rig.a, "rc:overlay.path_trial_returned", id, &ret).await;
    assert!(
        recv_t(
            &mut exit,
            "rc:overlay.relay_revoke",
            Duration::from_millis(100)
        )
        .await
        .is_none()
    );
    return_message(&mut rig.b, "rc:overlay.path_trial_returned", id, &ret).await;
    expect_return_both(&mut rig, "rc:overlay.path_trial_return_finalize", &ret).await;
    assert_eq!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["vni"],
        first["vni"]
    );
    assert_eq!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_bridge_revoke",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["trial_id"],
        *id
    );
    assert_eq!(
        recv_t(&mut exit, "rc:overlay.relay_revoke", Duration::from_secs(5))
            .await
            .unwrap()["vni"],
        second["vni"]
    );
    // A fresh trial gets independent allocations, and removing only the edge
    // (not relay approval) synchronously revokes BOTH legs and the bridge.
    request_backbone(&mut rig, &exit_node, 2).await;
    let first = recv_t(&mut rig.r, "rc:overlay.relay_serve", Duration::from_secs(5))
        .await
        .unwrap();
    let bridge = recv_t(
        &mut rig.r,
        "rc:overlay.relay_bridge_serve",
        Duration::from_secs(5),
    )
    .await
    .unwrap()["bridge"]
        .clone();
    let second = recv_t(&mut exit, "rc:overlay.relay_serve", Duration::from_secs(5))
        .await
        .unwrap();
    let a = recv_t(
        &mut rig.a,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    recv_t(
        &mut rig.b,
        "rc:overlay.path_trial_start",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(
        put(
            &rig.app,
            &source_policy,
            &rig.seeded.admin.access_token,
            json!({"serve":true})
        )
        .await
        .0,
        200
    );
    for ws in [&mut rig.a, &mut rig.b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_abort", Duration::from_secs(5))
                .await
                .unwrap()["trial_id"],
            a["trial_id"]
        );
    }
    assert_eq!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["vni"],
        first["vni"]
    );
    assert_eq!(
        recv_t(
            &mut rig.r,
            "rc:overlay.relay_bridge_revoke",
            Duration::from_secs(5)
        )
        .await
        .unwrap()["trial_id"],
        bridge["trial_id"]
    );
    assert_eq!(
        recv_t(&mut exit, "rc:overlay.relay_revoke", Duration::from_secs(5))
            .await
            .unwrap()["vni"],
        second["vni"]
    );
}

#[cfg(target_os = "linux")]
struct CompositeDirectLink {
    delay: std::sync::Arc<std::sync::atomic::AtomicU64>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    a: std::net::SocketAddr,
    b: std::net::SocketAddr,
}
#[cfg(target_os = "linux")]
impl Drop for CompositeDirectLink {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
#[cfg(target_os = "linux")]
impl CompositeDirectLink {
    async fn new(a: std::net::SocketAddr, b: std::net::SocketAddr) -> Self {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        let left = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let right = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let aa = left.local_addr().unwrap();
        let ab = right.local_addr().unwrap();
        let delay = Arc::new(AtomicU64::new(40));
        let mut tasks = Vec::new();
        for (input, output, dst) in [(left.clone(), right.clone(), b), (right, left, a)] {
            let delay = delay.clone();
            tasks.push(tokio::spawn(async move {
                let mut bytes = [0u8; 4096];
                loop {
                    let (n, _) = input.recv_from(&mut bytes).await.unwrap();
                    assert!(n < bytes.len(), "fixture must never truncate a datagram");
                    let ms = delay.load(Ordering::Relaxed);
                    if ms > 0 {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                    }
                    output.send_to(&bytes[..n], dst).await.unwrap();
                }
            }));
        }
        Self {
            delay,
            tasks,
            a: aa,
            b: ab,
        }
    }
    fn recover(&self) {
        self.delay.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
async fn composite_drive(
    label: &str,
    h: &mut roomlerd::relay_server::backbone_test_support::PathTrialTestHarness,
    output: &mut tokio::sync::mpsc::Receiver<roomler_ai_remote_control::signaling::ClientMsg>,
    ws: &mut Ws,
    trace: &mut Vec<(String, String)>,
    trial: ObjectId,
    fault: Option<std::time::Instant>,
) {
    h.tick().await;
    while let Ok(msg) = output.try_recv() {
        let value = serde_json::to_value(&msg).unwrap();
        let tag = value["t"].as_str().unwrap().to_string();
        if tag == "rc:overlay.path_trial_return_request" {
            let snap = h.snapshot(trial);
            assert_eq!(
                snap.windows.len(),
                9,
                "production hysteresis needs nine actual paired rounds"
            );
            assert!(snap.windows.iter().filter(|w| w.0.is_some()).count() >= 6);
            assert!(
                snap.windows.iter().filter(|w| w.1.is_none()).count() >= 6,
                "bridge fault must create real echo loss, not an injected score"
            );
            let fault = fault.expect("no return may be triggered before task-owned bridge fault");
            assert!(
                snap.windows.iter().filter(|w| w.2 >= fault).count() >= 6,
                "decision must use newly transmitted post-fault probes"
            );
        }
        trace.push((label.into(), tag));
        ws.send(Message::Text(value.to_string().into()))
            .await
            .unwrap();
    }
    // Bound both work and wait; unrelated netmaps/pings cannot starve ticks.
    for _ in 0..32 {
        let frame = match tokio::time::timeout(Duration::from_millis(1), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => t,
            Ok(Some(Ok(_))) => continue,
            Err(_) => break,
            other => panic!("fixture WS ended: {other:?}"),
        };
        let value: Value = serde_json::from_str(&frame).unwrap();
        let tag = value["t"].as_str().unwrap_or("");
        if tag.starts_with("rc:overlay.path_trial_") {
            trace.push((format!("server->{label}"), tag.into()));
        }
        if let Ok(msg) = serde_json::from_value(value) {
            h.control(msg).await;
        }
    }
}

#[cfg(target_os = "linux")]
fn composite_ip(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20 + payload.len()];
    packet[0] = 0x45;
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..].copy_from_slice(payload);
    packet
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn backbone_real_manager_fault_actual_echo_hysteresis_and_server_return_2pc() {
    tokio::time::timeout(Duration::from_secs(45),async {
        use roomlerd::relay_server::backbone_test_support::{NativeRelay,PathTrialTestHarness,WgKeypair};
        use roomler_ai_remote_control::signaling::{NetmapPeer,ServerMsg};
        use std::{sync::Arc,net::Ipv4Addr,time::Instant};
        let mut rig=Rig::up("backbone-real-fault",true,Some(true)).await;rig.arm().await;
        let source=NativeRelay::start().await.unwrap();let target=NativeRelay::start().await.unwrap();
        let (exit_agent,exit_token)=enroll(&rig.app,&rig.seeded,"backbone-fault-exit").await;
        let mut exit=connect(&rig.app,&exit_token,&["relay-server"]).await;
        let join_relay=|key:u8,port:u16,ready:bool|json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([key;32]),"mtu":1280,"endpoints":[format!("8.8.8.8:{port}")],"supports_org_relay":true,"supports_path_trial_v1":true,"supports_path_backbone_v1":true,"relay_backbone_ready":ready,"org_primary":true,"relay_port":port});
        rig.r.send(Message::Text(join_relay(3,source.port(),true).to_string().into())).await.unwrap();recv_t(&mut rig.r,"rc:overlay.netmap",Duration::from_secs(5)).await.unwrap();
        exit.send(Message::Text(join_relay(4,target.port(),false).to_string().into())).await.unwrap();recv_t(&mut exit,"rc:overlay.netmap",Duration::from_secs(5)).await.unwrap();
        let exit_node=node_id(&rig.app,&rig.seeded,"backbone-fault-exit").await;
        assert_eq!(approve(&rig.app,&rig.seeded,&exit_agent,true).await,200);grant_relay(&rig.app,&rig.seeded,&exit_node).await;
        let policy_url=url(&rig.seeded,&format!("/agent/{}/peer-relay-policy",rig.r_agent));
        assert_eq!(put(&rig.app,&policy_url,&rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":target.underlay_endpoint().to_string()}]})).await.0,200);
        let own_a=WgKeypair::generate();let own_b=WgKeypair::generate();
        for (ws,key) in [(&mut rig.a,own_a.public_base64()),(&mut rig.b,own_b.public_base64())] {
            ws.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":key,"mtu":1280,"endpoints":["203.0.113.10:41641"],"supports_org_relay":true,"supports_path_trial_v1":true,"supports_path_backbone_v1":true,"org_primary":true}).to_string().into())).await.unwrap();recv_t(ws,"rc:overlay.netmap",Duration::from_secs(5)).await.unwrap();
        }
        let a_id=ObjectId::parse_str(&rig.a_node).unwrap();let b_id=ObjectId::parse_str(&rig.b_node).unwrap();
        let a_ip:Ipv4Addr=rig.app.state.network().overlay_nodes.base.find_by_id(a_id).await.unwrap().overlay_ip.parse().unwrap();
        let b_ip:Ipv4Addr=rig.app.state.network().overlay_nodes.base.find_by_id(b_id).await.unwrap().overlay_ip.parse().unwrap();
        let sa=Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());let sb=Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let direct=CompositeDirectLink::new(sa.local_addr().unwrap(),sb.local_addr().unwrap()).await;
        let peer=|id:ObjectId,ip:Ipv4Addr,key:String|serde_json::from_value::<NetmapPeer>(json!({"node_id":id.to_hex(),"overlay_ip":ip.to_string(),"wg_public_key":key,"reachable":true,"supports_org_relay":true,"supports_overlay_echo":true})).unwrap();
        let (mut a,mut a_out)=PathTrialTestHarness::new(own_a.clone(),peer(b_id,b_ip,own_b.public_base64()),sa,direct.a,true).await;
        let (mut b,mut b_out)=PathTrialTestHarness::new(own_b,peer(a_id,a_ip,own_a.public_base64()),sb,direct.b,false).await;
        tokio::time::timeout(Duration::from_secs(5),async{while !a.handshake_done()||!b.handshake_done(){tokio::time::sleep(Duration::from_millis(10)).await;}}).await.unwrap();
        request_backbone(&mut rig,&exit_node,1).await;
        let s1=recv_t(&mut rig.r,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();
        let bridge=recv_t(&mut rig.r,"rc:overlay.relay_bridge_serve",Duration::from_secs(5)).await.unwrap();
        let s2=recv_t(&mut exit,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();
        let mut start_a=recv_t(&mut rig.a,"rc:overlay.path_trial_start",Duration::from_secs(5)).await.unwrap();
        let mut start_b=recv_t(&mut rig.b,"rc:overlay.path_trial_start",Duration::from_secs(5)).await.unwrap();
        let trial=ObjectId::parse_str(start_a["trial_id"].as_str().unwrap()).unwrap();let generation=bridge["bridge"]["generation"].as_u64().unwrap();
        target.serve(serde_json::from_value::<ServerMsg>(s2).unwrap(),None);source.serve(serde_json::from_value::<ServerMsg>(s1).unwrap(),None);source.serve(serde_json::from_value::<ServerMsg>(bridge).unwrap(),Some(source.policy_to(&target)));
        // Only public-address->owned-loopback endpoint resolution is mapped.
        // The authenticated CP identity, VNI, secrets, and actual private NIC
        // endpoint from the approved edge remain untouched and are exercised.
        start_a["relay_endpoints"]=json!([source.endpoint().to_string()]);start_b["relay_endpoints"]=json!([target.endpoint().to_string()]);
        a.control(serde_json::from_value(start_a).unwrap()).await;b.control(serde_json::from_value(start_b).unwrap()).await;
        let mut trace=Vec::new();
        loop {
            composite_drive("a",&mut a,&mut a_out,&mut rig.a,&mut trace,trial,None).await;
            composite_drive("b",&mut b,&mut b_out,&mut rig.b,&mut trace,trial,None).await;
            if a.snapshot(trial).phase=="finalized"&&b.snapshot(trial).phase=="finalized"{break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!a.snapshot(trial).direct_sender&&!b.snapshot(trial).direct_sender,"actual measured healthy relay must first become both senders");
        let packet=composite_ip(a_ip,b_ip,b"actual WG application payload through approved two-hop manager");assert!(a.send_packet(&packet).await);assert_eq!(b.receive_packet().await.unwrap(),packet);
        source.probe_healthy().await.unwrap();target.probe_healthy().await.unwrap();
        // Retained direct carriers have a conclusive sticky-dead verdict.
        // Only the actual Engine tick may create fresh shadow crypto sessions;
        // no data sender/relay grant is changed during this recovery.
        a.fail_retained_direct(trial);b.fail_retained_direct(trial);
        loop {
            composite_drive("a",&mut a,&mut a_out,&mut rig.a,&mut trace,trial,None).await;
            composite_drive("b",&mut b,&mut b_out,&mut rig.b,&mut trace,trial,None).await;
            assert!(!a.snapshot(trial).direct_sender&&!b.snapshot(trial).direct_sender);
            if a.snapshot(trial).direct_ready&&b.snapshot(trial).direct_ready{break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let held=composite_ip(a_ip,b_ip,b"sticky-dead shadow rebuilt with fresh WG handshake; relay remains active");assert!(a.send_packet(&held).await);assert_eq!(b.receive_packet().await.unwrap(),held);
        source.fail_owned_bridge(trial,generation).await.unwrap();direct.recover();let fault=Instant::now();
        // CP has NOT received an offline or revoke signal: listener + P2P
        // stay alive; only real candidate echo timeout can start this return.
        source.probe_healthy().await.unwrap();target.probe_healthy().await.unwrap();
        loop {
            composite_drive("a",&mut a,&mut a_out,&mut rig.a,&mut trace,trial,Some(fault)).await;
            composite_drive("b",&mut b,&mut b_out,&mut rig.b,&mut trace,trial,Some(fault)).await;
            if a.snapshot(trial).phase=="retired"&&b.snapshot(trial).phase=="retired"{break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let a_state=a.snapshot(trial);let b_state=b.snapshot(trial);assert!(a_state.direct_sender&&b_state.direct_sender&&!a_state.managed&&!b_state.managed);
        for (owner,kind) in [("a","rc:overlay.path_trial_return_ready"),("b","rc:overlay.path_trial_return_ready"),("a","rc:overlay.path_trial_returned"),("b","rc:overlay.path_trial_returned"),("server->a","rc:overlay.path_trial_return_finalize"),("server->b","rc:overlay.path_trial_return_finalize")] {assert!(trace.iter().any(|(o,k)|o==owner&&k==kind),"missing real protocol step {owner} {kind}");}
        let packet=composite_ip(a_ip,b_ip,b"after bridge fault A to B actual P2P");assert!(a.send_packet(&packet).await);assert_eq!(b.receive_packet().await.unwrap(),packet);
        let packet=composite_ip(b_ip,a_ip,b"after bridge fault B to A actual P2P");assert!(b.send_packet(&packet).await);assert_eq!(a.receive_packet().await.unwrap(),packet);
        for want in ["rc:overlay.relay_revoke","rc:overlay.relay_bridge_revoke"]{let msg=recv_t(&mut rig.r,want,Duration::from_secs(5)).await.unwrap();source.serve(serde_json::from_value(msg).unwrap(),None);}
        let msg=recv_t(&mut exit,"rc:overlay.relay_revoke",Duration::from_secs(5)).await.unwrap();target.serve(serde_json::from_value(msg).unwrap(),None);
        source.probe_healthy().await.unwrap();target.probe_healthy().await.unwrap();
        println!("real bridge manager fault -> actual authenticated echo loss/fresh hysteresis -> bilateral server Return2PC -> bidirectional WG P2P payload: PASS; listeners remained healthy; no NIC/route/WAN changes");
    }).await.expect("bounded local bridge-fault composite oracle exceeded 45 seconds");
}

/// Pump the SAME Discovery and Engine APIs as the runtime, through real agent
/// WS frames. Only public-address resolution is mapped to task loopback.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn alternate_composite_drive(
    h: &mut roomlerd::relay_server::backbone_test_support::PathTrialTestHarness,
    output: &mut tokio::sync::mpsc::Receiver<roomler_ai_remote_control::signaling::ClientMsg>,
    ws: &mut Ws,
    discover: bool,
    expected_hint_count: usize,
    first_id: &str,
    first_endpoint: std::net::SocketAddr,
    backup_endpoint: std::net::SocketAddr,
    requests: &mut Vec<(String, std::time::Instant)>,
    controls: &mut Vec<(String, ObjectId)>,
) {
    use roomler_ai_remote_control::signaling::ClientMsg;
    h.tick().await;
    if discover {
        h.request_discovery().await;
    }
    while let Ok(msg) = output.try_recv() {
        if let ClientMsg::OverlayPathTrialRequest {
            relay_node_id,
            exit_relay_node_id,
            ..
        } = &msg
        {
            assert!(
                exit_relay_node_id.is_none(),
                "this oracle covers one-hop alternatives"
            );
            requests.push((relay_node_id.to_hex(), std::time::Instant::now()));
            let role = if relay_node_id.to_hex() == first_id {
                "first"
            } else {
                "alternate"
            };
            println!(
                "ALT_REQUEST ordinal={} role={} since_first_ms={}",
                requests.len(),
                role,
                requests.first().unwrap().1.elapsed().as_millis()
            );
        }
        ws.send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
            .await
            .unwrap();
    }
    for _ in 0..32 {
        let text = match tokio::time::timeout(Duration::from_millis(1), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => text,
            Ok(Some(Ok(_))) => continue,
            Err(_) => break,
            other => panic!("composite fixture WS ended: {other:?}"),
        };
        let mut value: Value = serde_json::from_str(&text).unwrap();
        if let (Some(tag), Some(id)) = (value["t"].as_str(), value["trial_id"].as_str()) {
            if tag.starts_with("rc:overlay.path_trial_") {
                controls.push((tag.to_owned(), ObjectId::parse_str(id).unwrap()));
                let phase = match tag {
                    "rc:overlay.path_trial_start" => "start",
                    "rc:overlay.path_trial_commit" => "commit",
                    "rc:overlay.path_trial_finalize" => "finalize",
                    "rc:overlay.path_trial_abort" => "abort",
                    _ => "other_path_control",
                };
                println!("ALT_SERVER phase={phase}");
            }
        }
        if value["t"] == json!("rc:overlay.path_trial_start") {
            let endpoint = if value["relay_node_id"] == json!(first_id) {
                first_endpoint
            } else {
                backup_endpoint
            };
            value["relay_endpoints"] = json!([endpoint.to_string()]);
        }
        if value["t"] == json!("rc:overlay.org_relay_candidates") {
            assert_eq!(
                h.receive_discovery(serde_json::from_value(value).unwrap()),
                expected_hint_count
            );
        } else if let Ok(msg) = serde_json::from_value(value) {
            h.control(msg).await;
        }
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn org_relay_discovery_actual_alternate_wg_payload_and_late_bind_generation_fence() {
    run_alternate_wg_composite(false).await;
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn org_relay_discovery_five_registered_hidden_relay_actual_wg_and_late_bind_fence() {
    run_alternate_wg_composite(true).await;
}

/// Same real 100s oracle and native managers; only the registered inventory
/// and legitimate central display names vary. No score/clock/cache injection.
#[cfg(target_os = "linux")]
async fn run_alternate_wg_composite(five_registered_relays: bool) {
    tokio::time::timeout(Duration::from_secs(100), async {
        use roomlerd::relay_server::backbone_test_support::{NativeRelay, PathTrialTestHarness, WgKeypair};
        use roomler_ai_remote_control::signaling::{ClientMsg, NetmapPeer, ServerMsg};
        use std::{net::Ipv4Addr, sync::Arc, time::Instant};
        let diagnostic_started=Instant::now();
        println!("ALT_STAGE setup elapsed_ms=0");
        let slug=if five_registered_relays {"hidden-five-real-wg"} else {"alternate-real-wg"};
        let (mut rig, mut extra, extra_agent, extra_node, _, _) = alternate_onehop_fixture(slug).await;
        println!("ALT_STAGE central_fixture_ready elapsed_ms={}",diagnostic_started.elapsed().as_millis());
        let original_native = NativeRelay::start().await.unwrap();
        let extra_native = NativeRelay::start().await.unwrap();
        let hint_count=if five_registered_relays {3} else {2};
        let mut registered_ids=vec![rig.r_node.clone(),extra_node.clone()];
        let mut registered_agents=vec![rig.r_agent.clone(),extra_agent];
        // These are genuine enrolled+online+approved relay servers. Their
        // centrally stored names control only planner tie preference; their
        // ObjectIds remain assigned by actual registration, in canonical order.
        let mut standby_relays=Vec::new();
        if five_registered_relays {
            for index in 0..3u8 {
                let machine=format!("{slug}-standby-{index}");
                let(agent,token)=enroll(&rig.app,&rig.seeded,&machine).await;
                let mut ws=connect(&rig.app,&token,&["relay-server"]).await;
                let native=NativeRelay::start().await.unwrap();
                join(&mut ws,5+index,Some(true),&format!("8.8.4.4:{}",native.port())).await;
                // join's legacy port3478 is replaced with this manager's real port.
                ws.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([5+index;32]),
                    "mtu":1280,"endpoints":[format!("8.8.4.4:{}",native.port())],"supports_org_relay":true,
                    "org_primary":true,"relay_port":native.port()}).to_string().into())).await.unwrap();
                recv_t(&mut ws,"rc:overlay.netmap",Duration::from_secs(5)).await.unwrap();
                let id=node_id(&rig.app,&rig.seeded,&machine).await;
                assert_eq!(approve(&rig.app,&rig.seeded,&agent,true).await,200);
                grant_relay(&rig.app,&rig.seeded,&id).await;
                registered_ids.push(id);registered_agents.push(agent);standby_relays.push((ws,native));
            }
            assert!(registered_ids.windows(2).all(|p|ObjectId::parse_str(&p[0]).unwrap()<ObjectId::parse_str(&p[1]).unwrap()),"fixture labels1..5 must reflect real canonical node IDs");
            // AgentDao::list_relay_approved sorts persisted NAME; the planner's
            // equal unknown-probe/zero-session class is stable. Use that actual
            // admin API, not fabricated RTT or rewritten Discovery metadata.
            for (index,rank) in [1,4,2,5,3].into_iter().enumerate() {
                assert_eq!(put(&rig.app,&url(&rig.seeded,&format!("/agent/{}",registered_agents[index])),
                    &rig.seeded.admin.access_token,json!({"name":format!("coverage-preference-{rank:02}")})).await.0,200);
            }
        }
        // The real listener ports, identities, relay Serve decoder and manager
        // are used. Only their public addresses are fixture-resolved locally.
        for (ws, seed, port, public) in [(&mut rig.r, 3u8, original_native.port(), "8.8.8.8"),
            (&mut extra, 4u8, extra_native.port(), "1.1.1.1")] {
            ws.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([seed;32]),
                "mtu":1280, "endpoints":[format!("{public}:{port}")], "supports_org_relay":true,
                "org_primary":true, "relay_port":port}).to_string().into())).await.unwrap();
            recv_t(ws,"rc:overlay.netmap",Duration::from_secs(5)).await.unwrap();
        }
        let own_a=WgKeypair::generate(); let own_b=WgKeypair::generate();
        for (ws,key) in [(&mut rig.a,own_a.public_base64()),(&mut rig.b,own_b.public_base64())] {
            ws.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":key, "mtu":1280,
                "endpoints":["203.0.113.10:41641"], "supports_org_relay":true,
                "supports_path_trial_v1":true, "supports_org_relay_multi_candidate":true,
                "supports_org_relay_discovery_cursor":five_registered_relays,
                "org_primary":true}).to_string().into())).await.unwrap();
            recv_t(ws,"rc:overlay.netmap",Duration::from_secs(5)).await.unwrap();
        }
        let a_id=ObjectId::parse_str(&rig.a_node).unwrap();let b_id=ObjectId::parse_str(&rig.b_node).unwrap();
        let state=rig.app.state.network();
        let a_ip:Ipv4Addr=state.overlay_nodes.base.find_by_id(a_id).await.unwrap().overlay_ip.parse().unwrap();
        let b_ip:Ipv4Addr=state.overlay_nodes.base.find_by_id(b_id).await.unwrap().overlay_ip.parse().unwrap();
        let sa=Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sb=Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let direct=CompositeDirectLink::new(sa.local_addr().unwrap(),sb.local_addr().unwrap()).await;
        let peer=|id:ObjectId,ip:Ipv4Addr,key:String|serde_json::from_value::<NetmapPeer>(json!({
            "node_id":id.to_hex(),"overlay_ip":ip.to_string(),"wg_public_key":key,
            "reachable":true,"supports_org_relay":true,"supports_overlay_echo":true})).unwrap();
        let (mut a,mut a_out)=PathTrialTestHarness::new(own_a.clone(),peer(b_id,b_ip,own_b.public_base64()),sa,direct.a,true).await;
        let (mut b,mut b_out)=PathTrialTestHarness::new(own_b,peer(a_id,a_ip,own_a.public_base64()),sb,direct.b,false).await;
        tokio::time::timeout(Duration::from_secs(5),async {
            while !a.handshake_done()||!b.handshake_done(){tokio::time::sleep(Duration::from_millis(10)).await;}
        }).await.unwrap();
        println!("ALT_STAGE direct_handshake_ready elapsed_ms={}",diagnostic_started.elapsed().as_millis());
        let original_a=a.installed_identity().unwrap(); let original_b=b.installed_identity().unwrap();
        a.request_discovery().await;
        let discovery=a_out.recv().await.unwrap();
        assert!(matches!(discovery,ClientMsg::OverlayOrgRelayDiscover{..}));
        rig.a.send(Message::Text(serde_json::to_string(&discovery).unwrap().into())).await.unwrap();
        let metadata=recv_t(&mut rig.a,"rc:overlay.org_relay_candidates",Duration::from_secs(5)).await.unwrap();
        let hints=metadata["candidates"].as_array().unwrap();assert_eq!(hints.len(),hint_count);
        let first=hints[0]["relay_node_id"].as_str().unwrap().to_owned();
        let backup=if five_registered_relays {
            let observed:Vec<_>=hints.iter().map(|c|c["relay_node_id"].as_str().unwrap().to_owned()).collect();
            assert_eq!(observed,vec![registered_ids[0].clone(),registered_ids[2].clone(),registered_ids[4].clone()],"real central preference must yield canonical IDs[1,3,5]");
            assert!(hints.iter().all(|c|c["relay_node_id"]!=registered_ids[1]),"healthy canonical2 must be hidden from initial metadata");
            assert_eq!(first,registered_ids[0]);
            assert!(metadata.get("next_cursor").is_some(),"real WS must negotiate traversal");
            registered_ids[1].clone()
        } else {hints[1]["relay_node_id"].as_str().unwrap().to_owned()};
        assert!(first==rig.r_node||first==extra_node);assert_ne!(first,backup);
        assert_eq!(a.receive_discovery(serde_json::from_value(metadata).unwrap()),hint_count);
        println!("ALT_STAGE discovery_received candidate_count={} hidden_healthy={} elapsed_ms={}",hint_count,five_registered_relays,diagnostic_started.elapsed().as_millis());
        let first_requested_at=Instant::now(); // lower bound before the actual paced tick
        a.tick().await;
        let request=a_out.recv().await.unwrap();
        assert!(matches!(&request,ClientMsg::OverlayPathTrialRequest{relay_node_id,..} if relay_node_id.to_hex()==first));
        rig.a.send(Message::Text(serde_json::to_string(&request).unwrap().into())).await.unwrap();
        let mut start_a=recv_t(&mut rig.a,"rc:overlay.path_trial_start",Duration::from_secs(5)).await.unwrap();
        let mut start_b=recv_t(&mut rig.b,"rc:overlay.path_trial_start",Duration::from_secs(5)).await.unwrap();
        let first_trial=ObjectId::parse_str(start_a["trial_id"].as_str().unwrap()).unwrap();
        let first_generation=start_a["generation"].as_u64().unwrap();
        let (first_native,backup_native,mut first_ws,mut backup_ws)=if first==rig.r_node {
            (original_native,extra_native,rig.r,extra)
        } else {(extra_native,original_native,extra,rig.r)};
        let first_endpoint=first_native.endpoint();let backup_endpoint=backup_native.endpoint();
        let serve=recv_t(&mut first_ws,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();
        first_native.serve(serde_json::from_value::<ServerMsg>(serve).unwrap(),None);
        start_a["relay_endpoints"]=json!([first_endpoint.to_string()]);
        start_b["relay_endpoints"]=json!([first_endpoint.to_string()]);
        let late_start_a=start_a.clone();let late_start_b=start_b.clone();
        a.control(serde_json::from_value(start_a).unwrap()).await;
        let mut late=a.hold_completed_bind().await;
        assert_eq!(late.trial_id(),first_trial);assert!(late.is_alive());
        println!("ALT_STAGE first_actual_bind_held elapsed_ms={}",diagnostic_started.elapsed().as_millis());
        // Fault only the owned listener. The first REAL successful completion
        // is retained while B actually fails bind and the real server
        // withdraws it (client Abort or the existing preparation deadline).
        // No score, timeout, or generation is injected.
        drop(first_native);
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {if let Ok(sock)=tokio::net::UdpSocket::bind(("0.0.0.0",first_endpoint.port())).await {drop(sock);break;}
                tokio::time::sleep(Duration::from_millis(10)).await;}
        }).await.unwrap();
        b.control(serde_json::from_value(start_b).unwrap()).await;
        println!("ALT_STAGE first_listener_gone_responder_started elapsed_ms={}",diagnostic_started.elapsed().as_millis());
        let mut requests=vec![(first.clone(),first_requested_at)];let mut responder_requests=Vec::new();
        let mut controls_a=Vec::new();let mut controls_b=Vec::new();
        let mut backup_trial=None;let mut backup_start=None;let mut served=false;
        let mut next_diagnostic=Instant::now();
        loop {
            alternate_composite_drive(&mut a,&mut a_out,&mut rig.a,true,hint_count,&first,first_endpoint,backup_endpoint,&mut requests,&mut controls_a).await;
            alternate_composite_drive(&mut b,&mut b_out,&mut rig.b,false,hint_count,&first,first_endpoint,backup_endpoint,&mut responder_requests,&mut controls_b).await;
            assert!(responder_requests.is_empty(),"no responder-side duplicate trial");
            assert!(requests.len()<=2,"one initial attempt and one alternate, no request flood");
            if requests.len()==2 {
                assert_eq!(requests[1].0,backup);
                assert!(requests[1].1.duration_since(first_requested_at)>=Duration::from_secs(60),"real production request pacing remains intact");
            } else {
                assert_eq!(a.installed_identity(),Some(original_a));
                assert_eq!(b.installed_identity(),Some(original_b));
            }
            if !served {
                if let Some(value)=recv_t(&mut backup_ws,"rc:overlay.relay_serve",Duration::from_millis(1)).await {
                    assert_eq!(requests.len(),2);
                    let generation=value["generation"].as_u64().unwrap();assert!(generation>first_generation);
                    backup_native.serve(serde_json::from_value(value).unwrap(),None);served=true;
                    println!("ALT_STAGE alternate_manager_serve elapsed_ms={}",diagnostic_started.elapsed().as_millis());
                }
            }
            // The real Engine exposes no fabricated winner. The trial id is
            // observed from its server Start via the server's actual sessions.
            if backup_trial.is_none() && served {
                let sessions=state.org_relay.sessions_on_relay(ObjectId::parse_str(&backup).unwrap());
                assert_eq!(sessions,1,"exactly one current alternate reservation");
                // Captured on a separate read below by the helper's trace API.
            }
            if let Some((id,start))=a.active_trial_observation() {
                if id!=first_trial { backup_trial=Some(id);backup_start=Some(start); }
            }
            if Instant::now()>=next_diagnostic {
                next_diagnostic=Instant::now()+Duration::from_secs(5);
                let (at,ap,ad,ac,af,av)=a.diagnostic_counters();
                let (bt,bp,bd,bc,bf,bv)=b.diagnostic_counters();
                let aid=backup_trial.unwrap_or(first_trial);
                let aa=a.snapshot(aid);let bb=b.snapshot(aid);
                let (aq,ah,aw,adn,arn,adm,arm)=a.diagnostic_quality(aid);
                let (bq,bh,bw,bdn,brn,bdm,brm)=b.diagnostic_quality(aid);
                println!("ALT_QUALITY a_score_ready={} b_score_ready={} a_wg_initiator_ready={} b_wg_initiator_ready={} a_windows={} b_windows={} a_direct_success={} b_direct_success={} a_relay_success={} b_relay_success={} a_direct_median_ms={:?} b_direct_median_ms={:?} a_relay_median_ms={:?} b_relay_median_ms={:?}",
                    aq,bq,ah,bh,aw,bw,adn,bdn,arn,brn,adm,bdm,arm,brm);
                println!("ALT_STATE elapsed_ms={} requests={} manager_served={} a_phase={} b_phase={} a_trials={} b_trials={} a_pending={} b_pending={} a_delay_ms={} b_delay_ms={} a_candidate={} b_candidate={} a_failed={} b_failed={} a_current={} b_current={} a_direct={} b_direct={} a_managed={} b_managed={} server_abort_a={} server_abort_b={}",
                    diagnostic_started.elapsed().as_millis(),requests.len(),served,aa.phase,bb.phase,at,bt,ap,bp,ad,bd,ac,bc,af,bf,av,bv,aa.direct_sender,bb.direct_sender,aa.managed,bb.managed,
                    controls_a.iter().any(|(t,id)|t=="rc:overlay.path_trial_abort"&&*id==first_trial),
                    controls_b.iter().any(|(t,id)|t=="rc:overlay.path_trial_abort"&&*id==first_trial));
            }
            if let Some(id)=backup_trial {
                if a.snapshot(id).phase=="finalized"&&b.snapshot(id).phase=="finalized" {break;}
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        println!("ALT_STAGE alternate_bilateral_finalized elapsed_ms={}",diagnostic_started.elapsed().as_millis());
        let second_trial=backup_trial.unwrap();assert!(backup_start.unwrap()>first_requested_at);
        assert_ne!(first_trial,second_trial);assert!(served);assert_eq!(requests.len(),2);
        for controls in [&controls_a,&controls_b] {
            assert!(controls.iter().any(|(tag,id)|tag=="rc:overlay.path_trial_abort"&&*id==first_trial),"actual server withdrawal must retire the first trial");
            for kind in ["rc:overlay.path_trial_commit","rc:overlay.path_trial_finalize"] {
                assert!(controls.iter().any(|(tag,id)|tag==kind&&*id==second_trial),"both actual server 2PC decisions must be observed");
            }
        }
        // Read the actual accepted Engine phases via the SAME production
        // bounded watch publisher, after real bilateral WG/2PC (no fake state).
        let observed_controls=|status:&roomlerd::relay_server::backbone_test_support::PathTrialStatus| {
            status.transitions.iter().map(|t|(t.sequence,t.trial_id.clone(),t.peer_node_id.clone(),t.from,t.to,t.event,t.return_id.clone())).collect::<Vec<_>>()
        };
        for (h,expected_peer) in [(&a,b_id),(&b,a_id)] {
            let observed=h.local_observation();
            assert!(observed.active.len()<=4 && observed.transitions.len()<=32);
            let current=observed.active.iter().find(|t|t.trial_id==second_trial.to_hex()).expect("real current alternate trial visible");
            assert_eq!(current.peer_node_id,expected_peer.to_hex());
            assert_eq!(current.phase,roomlerd::relay_server::backbone_test_support::PathTrialPhase::Finalized);
            assert_eq!(current.return_id,None);
            assert_eq!(current.samples.len(),9);assert!(current.samples.len()<=9);
            assert_eq!(usize::from(current.direct_success),current.samples.iter().filter(|s|s.direct_rtt_ns.is_some()).count());
            assert_eq!(usize::from(current.candidate_success),current.samples.iter().filter(|s|s.candidate_rtt_ns.is_some()).count());
            for (event,from,to) in [(roomlerd::relay_server::backbone_test_support::PathTrialEvent::Commit,roomlerd::relay_server::backbone_test_support::PathTrialPhase::Ready,roomlerd::relay_server::backbone_test_support::PathTrialPhase::Committed),
                (roomlerd::relay_server::backbone_test_support::PathTrialEvent::Finalize,roomlerd::relay_server::backbone_test_support::PathTrialPhase::Committed,roomlerd::relay_server::backbone_test_support::PathTrialPhase::Finalized)] {
                let entries:Vec<_>=observed.transitions.iter().filter(|t|t.trial_id==second_trial.to_hex()&&t.event==event).collect();
                assert_eq!(entries.len(),1,"exactly one accepted actual transition");
                assert_eq!(entries[0].peer_node_id,expected_peer.to_hex());assert_eq!(entries[0].from,Some(from));assert_eq!(entries[0].to,Some(to));assert_eq!(entries[0].return_id,None);
            }
        }
        let before_rejected_a=a.local_observation();let before_rejected_b=b.local_observation();
        assert_eq!(a.trial_count(),1);assert_eq!(b.trial_count(),1);
        assert!(!a.snapshot(second_trial).direct_sender&&!b.snapshot(second_trial).direct_sender);
        let identity_a=a.installed_identity().unwrap();let identity_b=b.installed_identity().unwrap();
        assert_eq!((identity_a.0,identity_a.1),(original_a.0,original_a.1));
        assert_eq!((identity_b.0,identity_b.1),(original_b.0,original_b.1));
        assert_ne!(identity_a.2,original_a.2);assert_ne!(identity_b.2,original_b.2);
        let payload=composite_ip(a_ip,b_ip,b"actual alternate one-hop WG payload after first bind failure");
        assert!(a.send_packet(&payload).await);assert_eq!(b.receive_packet().await.unwrap(),payload);
        println!("ALT_STAGE alternate_payload_received elapsed_ms={}",diagnostic_started.elapsed().as_millis());
        // Deliver the original AUTHENTICATED bind result through the same
        // Engine queue after a newer generation finalized. It must close.
        assert!(late.is_alive());a.release_completed_bind(&mut late).await;a.tick().await;
        assert!(!late.is_alive(),"stale actual bound socket must be closed");
        println!("ALT_STAGE stale_actual_bind_closed elapsed_ms={}",diagnostic_started.elapsed().as_millis());
        for (h,start) in [(&mut a,late_start_a),(&mut b,late_start_b)] {
            h.control(serde_json::from_value(start.clone()).unwrap()).await;
            h.control(serde_json::from_value(start).unwrap()).await;
        }
        assert_eq!(a.installed_identity(),Some(identity_a));assert_eq!(b.installed_identity(),Some(identity_b));
        assert_eq!(a.trial_count(),1);assert_eq!(b.trial_count(),1);
        assert_eq!(a.snapshot(second_trial).phase,"finalized");assert_eq!(b.snapshot(second_trial).phase,"finalized");
        let after_rejected_a=a.local_observation();let after_rejected_b=b.local_observation();
        assert_eq!((after_rejected_a.runtime_id,after_rejected_a.epoch),(before_rejected_a.runtime_id,before_rejected_a.epoch));
        assert_eq!((after_rejected_b.runtime_id,after_rejected_b.epoch),(before_rejected_b.runtime_id,before_rejected_b.epoch));
        assert_eq!(observed_controls(&after_rejected_a),observed_controls(&before_rejected_a),"late actual Bound and rejected old Starts cannot forge accepted history");
        assert_eq!(observed_controls(&after_rejected_b),observed_controls(&before_rejected_b));
        println!("ACTUAL_WG_OWNER_OBSERVATION: PASS (both accepted Commit/Finalize; same production bounded watch; late rejection adds no transition)");
        let payload=composite_ip(b_ip,a_ip,b"late first bind and duplicate Start cannot overwrite newer relay generation");
        assert!(b.send_packet(&payload).await);assert_eq!(a.receive_packet().await.unwrap(),payload);
        if five_registered_relays {
            for (ws,_) in &mut standby_relays {assert_no_discovery_allocation(ws).await;}
            println!("DISCOVERY_HIDDEN_FIVE_WG: PASS (5 real registrations; initial canonical[1,3,5]; actual second canonical2; real60s; bilateral2PC; exactbytes; latefirst fenced)");
        }
        println!("DISCOVERY_ALTERNATE_WG_LATE_BIND: PASS (real 60s pacing; same WG keys/IP; real bind + manager bytes; no clock/score injection)");
    }).await.expect("bounded real-clock alternate composite exceeded 100 seconds");
}

async fn discovery_cursor_join(rig: &mut Rig, cap: Option<bool>) {
    let mut message = json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([1;32]),"mtu":1280,"endpoints":["203.0.113.10:41641"],"supports_org_relay":true,"supports_org_relay_multi_candidate":true,"supports_path_trial_v1":true,"supports_server_relay_strategy":true,"org_primary":true,"relay_port":3478});
    if let Some(cap) = cap {
        message["supports_org_relay_discovery_cursor"] = json!(cap);
    }
    rig.a
        .send(Message::Text(message.to_string().into()))
        .await
        .unwrap();
    recv_t(&mut rig.a, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
}
async fn discovery_cursor_page(rig: &mut Rig, serial: u64, cursor: Option<Value>) -> Value {
    let mut request =
        json!({"t":"rc:overlay.org_relay_discover","peer_node_id":rig.b_node,"request_id":serial});
    if let Some(cursor) = cursor {
        request["cursor"] = cursor;
    }
    rig.a
        .send(Message::Text(request.to_string().into()))
        .await
        .unwrap();
    let reply = recv_t(
        &mut rig.a,
        "rc:overlay.org_relay_candidates",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(reply["request_id"], serial);
    assert!(reply.get("vni").is_none() && reply.get("bind_secret").is_none());
    reply
}
#[tokio::test]
async fn metadata_discovery_cursor_covers_five_relays_and_rechecks_acl_between_pages() {
    let mut rig = Rig::up("discovery-cursor", true, Some(true)).await;
    let original_acl = rig.arm().await;
    let mut relays = Vec::new();
    let mut ids = vec![rig.r_node.clone()];
    let mut acls = vec![original_acl];
    for index in 0..4 {
        let machine = format!("discovery-cursor-r{index}");
        let (agent, token) = enroll(&rig.app, &rig.seeded, &machine).await;
        let mut ws = connect(&rig.app, &token, &["relay-server"]).await;
        join(&mut ws, 20 + index, Some(true), "1.1.1.1:41641").await;
        let id = node_id(&rig.app, &rig.seeded, &machine).await;
        assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
        acls.push(grant_relay(&rig.app, &rig.seeded, &id).await);
        ids.push(id);
        relays.push(ws);
    }
    // Rollout absence and explicit false preserve the complete old response shape.
    discovery_cursor_join(&mut rig, None).await;
    let old = discovery_cursor_page(&mut rig, 1, None).await;
    discovery_cursor_join(&mut rig, Some(false)).await;
    let false_page = discovery_cursor_page(
        &mut rig,
        2,
        Some(json!({"relay_node_id":ObjectId::new().to_hex()})),
    )
    .await;
    assert_eq!(old["candidates"], false_page["candidates"]);
    assert!(old.get("next_cursor").is_none() && false_page.get("next_cursor").is_none());
    discovery_cursor_join(&mut rig, Some(true)).await;
    let first = discovery_cursor_page(&mut rig, 3, None).await;
    assert_eq!(
        first["candidates"], old["candidates"],
        "preferred initial page unchanged"
    );
    let mut seen = std::collections::HashSet::new();
    let mut page = first;
    for serial in 4..=5 {
        for c in page["candidates"].as_array().unwrap() {
            assert!(ids.contains(&c["relay_node_id"].as_str().unwrap().to_owned()));
            seen.insert(c["relay_node_id"].as_str().unwrap().to_owned());
        }
        page = discovery_cursor_page(&mut rig, serial, Some(page["next_cursor"].clone())).await;
    }
    for c in page["candidates"].as_array().unwrap() {
        seen.insert(c["relay_node_id"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        seen.len(),
        5,
        "five eligible relays cannot remain hidden behind first three"
    );
    // Delete a real ACL between pages. Caller supplied/stale position cannot authorize it.
    let denied = ids[0].clone();
    assert_eq!(
        app_delete(
            &rig.app,
            &url(&rig.seeded, &format!("/overlay-acl/{}", acls[0])),
            &rig.seeded.admin.access_token
        )
        .await,
        200
    );
    let final_page = discovery_cursor_page(&mut rig, 6, Some(page["next_cursor"].clone())).await;
    assert!(
        final_page["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["relay_node_id"] != denied)
    );
    // Fresh trial mint must deny the now-unapproved ACL even with a former hint.
    trial_join(&mut rig.b, 2, true).await;
    request_onehop(&mut rig, &denied, 1).await;
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.path_trial_start",
            Duration::from_millis(150)
        )
        .await
        .is_none()
    );
    assert!(
        rig.app
            .state
            .network()
            .org_relay
            .active_session(&roomler_ai_mod_network::overlay::pair_key(
                ObjectId::parse_str(&rig.a_node).unwrap(),
                ObjectId::parse_str(&rig.b_node).unwrap()
            ))
            .is_none()
    );
    assert!(
        audit_rows(&rig.app, &rig.seeded)
            .await
            .iter()
            .all(|row| row["action"] != json!("mint"))
    );
    assert_no_discovery_allocation(&mut rig.a).await;
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
    for ws in &mut relays {
        assert_no_discovery_allocation(ws).await;
    }
}

#[tokio::test]
async fn metadata_discovery_cursor_rebuilds_backbone_after_approval_and_mode_changes() {
    let mut rig = Rig::up("discovery-cursor-backbone", true, Some(true)).await;
    rig.arm().await;
    let (agent, token) = enroll(&rig.app, &rig.seeded, "discovery-cursor-exit").await;
    let mut exit = connect(&rig.app, &token, &["relay-server"]).await;
    join(&mut exit, 4, Some(true), "1.1.1.1:41641").await;
    let exit_id = node_id(&rig.app, &rig.seeded, "discovery-cursor-exit").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
    grant_relay(&rig.app, &rig.seeded, &exit_id).await;
    let source_policy = url(
        &rig.seeded,
        &format!("/agent/{}/peer-relay-policy", rig.r_agent),
    );
    assert_eq!(put(&rig.app,&source_policy,&rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agent,"endpoint":"10.20.0.2:3478"}]})).await.0,200);
    backbone_join(&mut rig.r, 3, true, true, "8.8.8.8:41641").await;
    backbone_join(&mut rig.b, 2, true, false, "203.0.113.11:41641").await;
    rig.a.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([1;32]),"mtu":1280,"endpoints":["203.0.113.10:41641"],"supports_org_relay":true,"supports_org_relay_multi_candidate":true,"supports_org_relay_discovery_cursor":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true,"org_primary":true,"relay_port":3478}).to_string().into())).await.unwrap();
    recv_t(&mut rig.a, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .unwrap();
    let first = discovery_cursor_page(&mut rig, 1, None).await;
    assert!(
        first["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["relay_node_id"] == rig.r_node && c["exit_relay_node_id"] == exit_id)
    );
    assert_eq!(approve(&rig.app, &rig.seeded, &agent, false).await, 200);
    let second = discovery_cursor_page(&mut rig, 2, Some(first["next_cursor"].clone())).await;
    assert!(
        second["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c.get("exit_relay_node_id").is_none() && c["relay_node_id"] != exit_id)
    );
    set_mode(&rig.app, &rig.seeded, "off").await;
    let off = discovery_cursor_page(&mut rig, 3, Some(second["next_cursor"].clone())).await;
    assert_eq!(off["candidates"], json!([]));
    assert_eq!(off["ttl_secs"], 0);
    assert!(off.get("next_cursor").is_none());
    assert_no_discovery_allocation(&mut rig.a).await;
    assert_no_discovery_allocation(&mut rig.b).await;
    assert_no_discovery_allocation(&mut rig.r).await;
    assert_no_discovery_allocation(&mut exit).await;
}

/// The new purpose is a real network WS message; no legacy TURN request is
/// involved and every frame is inspected so an accidental grant cannot hide.
async fn request_org_only(rig: &mut Rig, serial: u64) {
    rig.a.send(Message::Text(json!({
        "t":"rc:overlay.org_relay_fallback_request", "peer_node_id":rig.b_node,
        "request_id":serial
    }).to_string().into())).await.unwrap();
}

async fn recv_org_only_session(ws: &mut Ws) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout_at(deadline, ws.next()).await
            .expect("ORG-only session timeout").expect("WS open").expect("WS frame");
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_ne!(value["t"], json!("rc:overlay.relay_grant"), "ORG-only must never grant TURN");
            assert_ne!(value["t"], json!("rc:overlay.force_derp"), "ORG-only is not TURN churn");
            if value["t"] == json!("rc:overlay.relay_session") { return value; }
        }
    }
}

async fn assert_org_only_quiet(ws: &mut Ws) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    while let Ok(Some(Ok(frame))) = tokio::time::timeout_at(deadline, ws.next()).await {
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            assert!(!["rc:overlay.relay_grant", "rc:overlay.force_derp", "rc:overlay.relay_session",
                "rc:overlay.relay_serve"].contains(&value["t"].as_str().unwrap_or_default()), "unexpected allocation: {}", value["t"]);
        }
    }
}

#[tokio::test]
async fn org_only_fallback_mints_without_turn_churn_and_repushes_remaining_ttl() {
    let mut rig = Rig::up("org-only-ok", true, Some(true)).await;
    rig.arm().await;
    let map = join(&mut rig.a, 1, Some(true), "203.0.113.10:41641").await;
    assert_eq!(map["network"]["org_relay_fallback_v1"], json!(true));
    request_org_only(&mut rig, 1).await;
    let sa = recv_org_only_session(&mut rig.a).await;
    let sb = recv_org_only_session(&mut rig.b).await;
    let serve = recv_t(&mut rig.r, "rc:overlay.relay_serve", Duration::from_secs(5)).await.unwrap();
    assert_eq!(sa["vni"], serve["vni"]);
    assert_eq!(sa["vni"], sb["vni"]);
    let a = ObjectId::parse_str(&rig.a_node).unwrap();
    let b = ObjectId::parse_str(&rig.b_node).unwrap();
    let r = ObjectId::parse_str(&rig.r_node).unwrap();
    let pk = roomler_ai_mod_network::overlay::pair_key(a,b);
    let first = rig.app.state.network().org_relay.active_session(&pk).unwrap();
    let rows = audit_rows(&rig.app, &rig.seeded).await.len();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    request_org_only(&mut rig, 2).await;
    let again = recv_org_only_session(&mut rig.a).await;
    let network = rig.app.state.network();
    assert_eq!(again["vni"], sa["vni"]);
    assert_eq!(again["generation"], sa["generation"]);
    assert_eq!(again["bind_secret"], sa["bind_secret"]);
    assert!(again["max_lifetime_secs"].as_u64().unwrap() < sa["max_lifetime_secs"].as_u64().unwrap());
    assert_eq!(network.org_relay.active_session(&pk).unwrap().expires_at, first.expires_at);
    assert_eq!(audit_rows(&rig.app, &rig.seeded).await.len(), rows);
    assert!(network.relay_pair_churn.is_empty(), "ORG-only cannot arm or consume TURN churn");
    for _ in 0..29 { assert!(network.relay_rate_limiter.check(a,r,30)); }
    assert!(!network.relay_rate_limiter.check(a,r,30), "one mint spent one slot; repush spent none");
    assert_org_only_quiet(&mut rig.a).await;
    assert_org_only_quiet(&mut rig.b).await;
    assert_org_only_quiet(&mut rig.r).await;
}

/// Field, 2026-10-25: a session minted while the direct path was still up
/// was never bound inside the relay's bind window, after which the relay
/// drops every Bind for it; re-pushing that same session on each fallback
/// re-request stranded the pair for 6 and 26 minutes. Within the window the
/// session is re-pushed; past it, it is revoked and a fresh one is minted.
#[tokio::test]
async fn org_only_fallback_remints_once_the_bind_window_has_passed() {
    let mut rig = Rig::up("org-only-rebind", true, Some(true)).await;
    rig.arm().await;
    join(&mut rig.a, 1, Some(true), "203.0.113.10:41641").await;
    request_org_only(&mut rig, 1).await;
    let sa = recv_org_only_session(&mut rig.a).await;
    let _ = recv_org_only_session(&mut rig.b).await;
    let serve = recv_t(&mut rig.r, "rc:overlay.relay_serve", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(sa["vni"], serve["vni"]);
    let a = ObjectId::parse_str(&rig.a_node).unwrap();
    let b = ObjectId::parse_str(&rig.b_node).unwrap();
    let pk = roomler_ai_mod_network::overlay::pair_key(a, b);
    request_org_only(&mut rig, 2).await;
    let within = recv_org_only_session(&mut rig.a).await;
    assert_eq!(
        within["generation"], sa["generation"],
        "inside the window: the same session"
    );
    rig.app.state.network().org_relay.age_past_bind_window(&pk);
    request_org_only(&mut rig, 3).await;
    let fresh = recv_org_only_session(&mut rig.a).await;
    assert_ne!(
        fresh["generation"], sa["generation"],
        "past the window: a fresh session"
    );
    assert_ne!(fresh["bind_secret"], sa["bind_secret"]);
    let peer = recv_org_only_session(&mut rig.b).await;
    assert_eq!(
        peer["generation"], fresh["generation"],
        "the peer gets it too"
    );
    let serve2 = loop {
        let s = recv_t(&mut rig.r, "rc:overlay.relay_serve", Duration::from_secs(5))
            .await
            .unwrap();
        if s["generation"] == fresh["generation"] {
            break s;
        }
    };
    assert_eq!(serve2["vni"], fresh["vni"], "and the relay installs it");
    let live = rig
        .app
        .state
        .network()
        .org_relay
        .active_session(&pk)
        .unwrap();
    assert_eq!(json!(live.generation), fresh["generation"]);
}

#[tokio::test]
async fn org_only_fallback_preserves_forced_derp_pin_without_churn_or_mint() {
    use roomler_ai_mod_network::overlay::{PairChurn,arm_grant,churn_note_request,pair_key};
    let mut rig = Rig::up("org-only-pin", true, Some(true)).await;
    rig.arm().await;
    let pk = pair_key(ObjectId::parse_str(&rig.a_node).unwrap(),ObjectId::parse_str(&rig.b_node).unwrap());
    let base = std::time::Instant::now() - Duration::from_secs(30);
    let mut churn = PairChurn::default();
    for cycle in 0..3u64 {
        let grant = base + Duration::from_secs(cycle*6);
        arm_grant(&mut churn,grant);
        assert_eq!(churn_note_request(&mut churn,grant+Duration::from_secs(6)),cycle==2);
    }
    let before = format!("{churn:?}");
    rig.app.state.network().relay_pair_churn.insert(pk.clone(),churn);
    request_org_only(&mut rig,1).await;
    assert_org_only_quiet(&mut rig.a).await;
    assert_org_only_quiet(&mut rig.b).await;
    assert_org_only_quiet(&mut rig.r).await;
    let network=rig.app.state.network();
    assert_eq!(format!("{:?}",network.relay_pair_churn.get(&pk).unwrap().value()),before);
    assert!(network.org_relay.active_session(&pk).is_none());
    assert!(audit_rows(&rig.app,&rig.seeded).await.iter().all(|r|r["action"] != "mint"));
}

/// [`join`] as a member that can ride DERP and honours the server's pin.
async fn derp_join(ws: &mut Ws, seed: u8, endpoint: &str) -> Value {
    let msg = json!({
        "t": "rc:overlay.join", "wg_public_key": BASE64.encode([seed; 32]), "mtu": 1280,
        "endpoints": [endpoint], "supports_org_relay": true,
        "supports_server_relay_strategy": true, "relay_port": 3478, "org_primary": true,
        "supports_derp": true, "supports_forced_derp": true,
    });
    ws.send(Message::Text(msg.to_string().into())).await.expect("send join");
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5)).await.expect("a netmap answers the join")
}

async fn report_loss(ws: &mut Ws, peer: &str, vni: u64, packets: u64, lost: u64) {
    ws.send(Message::Text(json!({
        "t": "rc:overlay.org_relay_loss", "peer_node_id": peer, "vni": vni,
        "packets": packets, "lost": lost,
    }).to_string().into())).await.expect("send loss report");
}

/// Nothing that would move the pair reaches `ws` for a moment.
async fn assert_pair_unmoved(ws: &mut Ws) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
    while let Ok(Some(Ok(frame))) = tokio::time::timeout_at(deadline, ws.next()).await {
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            assert!(!["rc:overlay.force_derp", "rc:overlay.relay_revoke"]
                .contains(&value["t"].as_str().unwrap_or_default()), "unexpected: {}", value["t"]);
        }
    }
}

/// Field, 2026-10-26: an org relay whose ingress lost 7–10% carried ~2 Mbit/s
/// while DERP through the same host carried 23–33, and the ladder kept the
/// pair on ORG. A member's report of a lossy window now pins the pair to DERP
/// on both ends, revokes the session on all three parties with an audited
/// reason, and the pin refuses an ORG re-mint. A report under the threshold,
/// about another VNI, or from a node that is not a member moves nothing.
#[tokio::test]
async fn org_loss_report_pins_the_pair_to_derp_and_revokes_the_session() {
    let mut rig = Rig::up("org-loss", true, Some(true)).await;
    rig.arm().await;
    let map = derp_join(&mut rig.a, 1, "203.0.113.10:41641").await;
    assert_eq!(map["network"]["org_relay_loss_v1"], json!(true));
    derp_join(&mut rig.b, 2, "203.0.113.11:41641").await;
    request_org_only(&mut rig, 1).await;
    let sa = recv_org_only_session(&mut rig.a).await;
    recv_org_only_session(&mut rig.b).await;
    recv_t(&mut rig.r, "rc:overlay.relay_serve", Duration::from_secs(5)).await.unwrap();
    let vni = sa["vni"].as_u64().unwrap();
    let pk = roomler_ai_mod_network::overlay::pair_key(
        ObjectId::parse_str(&rig.a_node).unwrap(), ObjectId::parse_str(&rig.b_node).unwrap());

    report_loss(&mut rig.a, &rig.b_node, vni, 3000, 60).await; // 2%
    report_loss(&mut rig.a, &rig.b_node, vni + 1, 3000, 240).await; // another VNI
    report_loss(&mut rig.r, &rig.b_node, vni, 3000, 240).await; // not a member
    assert_pair_unmoved(&mut rig.a).await;
    assert_pair_unmoved(&mut rig.b).await;
    assert_pair_unmoved(&mut rig.r).await;
    assert!(rig.app.state.network().org_relay.active_session(&pk).is_some());

    // One member's report is enough: 8% of the stream b receives from a.
    report_loss(&mut rig.b, &rig.a_node, vni, 3000, 240).await;
    let wait = Duration::from_secs(5);
    let fa = recv_t(&mut rig.a, "rc:overlay.force_derp", wait).await.expect("a is pinned");
    let fb = recv_t(&mut rig.b, "rc:overlay.force_derp", wait).await.expect("b is pinned");
    assert_eq!(fa["peer_node_id"], json!(rig.b_node));
    assert_eq!(fb["peer_node_id"], json!(rig.a_node));
    let ttl = fa["ttl_ms"].as_u64().unwrap();
    assert!((590_000..=600_000).contains(&ttl), "a 10-minute pin: {ttl}");
    assert_eq!(fb["ttl_ms"], fa["ttl_ms"]);
    rig.expect_revoked(vni).await;
    let mut audited = false;
    for _ in 0..40 {
        audited = audit_rows(&rig.app, &rig.seeded).await.iter().any(|r| {
            r["action"] == "revoke" && r["vni"] == json!(vni) && r["reason"] == "org_relay_lossy"
        });
        if audited { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(audited, "the revoke is audited with its reason");

    assert!(rig.app.state.network().org_relay.active_session(&pk).is_none());
    request_org_only(&mut rig, 2).await;
    assert!(
        recv_t(&mut rig.a, "rc:overlay.relay_session", Duration::from_millis(600)).await.is_none(),
        "the pin refuses an ORG re-mint"
    );
    // Nor does a ladder climb mint one; it gets the pin again, with what is left of it.
    rig.request().await;
    let again = recv_t(&mut rig.a, "rc:overlay.force_derp", wait).await.expect("the pin is re-pushed");
    assert!(again["ttl_ms"].as_u64().unwrap() <= ttl);
    assert!(
        recv_t(&mut rig.a, "rc:overlay.relay_session", Duration::from_millis(600)).await.is_none(),
        "a relay_request under the pin mints no ORG session"
    );
    assert!(rig.app.state.network().org_relay.active_session(&pk).is_none());
}

/// With a second relay in the zone, a lossy relay moves the pair there, not
/// to DERP: the lossy session is revoked (audited), a new one is minted on
/// the other relay at once, nothing is pinned, and the lossy relay sits out
/// for this pair: the next fallback request mints on the other relay again.
#[tokio::test]
async fn a_lossy_relay_moves_the_pair_to_another_relay_in_the_zone() {
    let (mut rig, extra, _extra_agent, extra_node, _, _) =
        alternate_onehop_fixture("org-loss-move").await;
    request_org_only(&mut rig, 1).await;
    let old = recv_org_only_session(&mut rig.a).await;
    recv_org_only_session(&mut rig.b).await;
    let (old_relay, other) = if old["relay_node_id"] == json!(rig.r_node) {
        (rig.r_node.clone(), extra_node.clone())
    } else {
        (extra_node.clone(), rig.r_node.clone())
    };
    let vni = old["vni"].as_u64().unwrap();
    let pk = roomler_ai_mod_network::overlay::pair_key(
        ObjectId::parse_str(&rig.a_node).unwrap(),
        ObjectId::parse_str(&rig.b_node).unwrap(),
    );

    report_loss(&mut rig.b, &rig.a_node, vni, 3000, 240).await; // 8%
    // recv_org_only_session fails on any force_derp: the pair is not pinned.
    let fresh = recv_org_only_session(&mut rig.a).await;
    recv_org_only_session(&mut rig.b).await;
    assert_eq!(
        fresh["relay_node_id"],
        json!(other),
        "minted on the other relay"
    );
    // VNIs are per relay; the generation is the server-wide clock.
    assert!(fresh["generation"].as_u64().unwrap() > old["generation"].as_u64().unwrap());
    let mut audited = false;
    for _ in 0..40 {
        audited = audit_rows(&rig.app, &rig.seeded).await.iter().any(|r| {
            r["action"] == "revoke" && r["vni"] == json!(vni) && r["reason"] == "org_relay_lossy"
        });
        if audited {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        audited,
        "the lossy session's revoke is audited with its reason"
    );
    assert!(
        rig.app.state.network().relay_pair_churn.is_empty(),
        "no DERP pin"
    );
    let live = rig
        .app
        .state
        .network()
        .org_relay
        .active_session(&pk)
        .expect("a live session");
    assert_eq!(live.relay.node_id.to_hex(), other);
    assert!(rig.app.state.network().org_relay.is_lossy(
        &pk,
        ObjectId::parse_str(&old_relay).unwrap(),
        std::time::Instant::now()
    ));
    drop(extra);
}

#[tokio::test]
async fn org_only_fallback_reauthorizes_stale_cached_relay_and_mints_alternate() {
    let (mut rig,mut extra,extra_agent,extra_node,_,_)=alternate_onehop_fixture("org-only-stale").await;
    request_org_only(&mut rig,1).await;
    let old=recv_org_only_session(&mut rig.a).await;
    recv_org_only_session(&mut rig.b).await;
    let original=old["relay_node_id"]==json!(rig.r_node);
    let (old_agent,new_node)=if original {(rig.r_agent.clone(),extra_node.clone())}else{(extra_agent.clone(),rig.r_node.clone())};
    if original {recv_t(&mut rig.r,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();}
    else {recv_t(&mut extra,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();}
    // Simulate an out-of-band policy update: no route revoker removes the
    // cached lease. The next request itself must reauthorize and retire it.
    rig.app.db.collection::<bson::Document>("agents").update_one(
        doc!{"_id":ObjectId::parse_str(&old_agent).unwrap()},
        doc!{"$set":{"peer_relay_policy.serve":false}}
    ).await.unwrap();
    request_org_only(&mut rig,2).await;
    let fresh=recv_org_only_session(&mut rig.a).await;
    recv_org_only_session(&mut rig.b).await;
    assert_eq!(fresh["relay_node_id"],json!(new_node));
    assert!(fresh["generation"].as_u64().unwrap()>old["generation"].as_u64().unwrap());
    assert_ne!(fresh["bind_secret"],old["bind_secret"]);
    if original {recv_t(&mut extra,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();}
    else {recv_t(&mut rig.r,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();}
    let rows=audit_rows(&rig.app,&rig.seeded).await;
    assert!(rows.iter().any(|r|r["action"]=="revoke" && r["vni"]==old["vni"] && r["reason"]=="org-fallback-reauthorization"));
    assert_eq!(rows.iter().filter(|r|r["action"]=="mint" && r["denied"].is_null()).count(),2);
    assert!(rig.app.state.network().relay_pair_churn.is_empty());
    assert_org_only_quiet(&mut rig.a).await;
}

#[tokio::test]
async fn org_only_fallback_mode_acl_primary_and_mint_rate_gates_fail_closed() {
    for (slug,mode,primary,acl,deny) in [
        ("org-only-off","off",Some(true),true,None),
        ("org-only-warn","warn",Some(true),true,None),
        ("org-only-noacl","on",Some(true),false,Some("acl_denied")),
        ("org-only-secondary","on",Some(false),true,Some("secondary_org")),
        ("org-only-rate","on",Some(true),true,Some("rate_limited")),
    ] {
        let mut rig=Rig::up(slug,true,primary).await;
        set_mode(&rig.app,&rig.seeded,mode).await;
        assert_eq!(approve(&rig.app,&rig.seeded,&rig.r_agent,true).await,200);
        if acl {grant_relay(&rig.app,&rig.seeded,&rig.r_node).await;}
        if deny==Some("rate_limited") {
            let network=rig.app.state.network();
            for _ in 0..30 {assert!(network.relay_rate_limiter.check(ObjectId::parse_str(&rig.a_node).unwrap(),ObjectId::parse_str(&rig.r_node).unwrap(),30));}
        }
        request_org_only(&mut rig,1).await;
        if mode!="off" {
            let row=wait_mint_row(&rig.app,&rig.seeded).await;
            assert_eq!(row["denied"],deny.map(|d|json!(d)).unwrap_or(Value::Null));
            assert_eq!(row["warn_only"],json!(mode=="warn"));
        }
        assert_org_only_quiet(&mut rig.a).await;
        assert_org_only_quiet(&mut rig.b).await;
        assert_org_only_quiet(&mut rig.r).await;
        assert!(rig.app.state.network().relay_pair_churn.is_empty());
    }
}

#[tokio::test]
async fn org_only_fallback_rejects_cross_tenant_self_and_unjoined_requesters() {
    let mut rig=Rig::up("org-only-identity",true,Some(true)).await;
    rig.arm().await;
    let foreign=rig.app.seed_tenant("org-only-foreign").await;
    let (_,tok)=enroll(&rig.app,&foreign,"org-only-foreign-node").await;
    let mut ws=connect(&rig.app,&tok,&[]).await;
    join(&mut ws,9,Some(true),"203.0.113.99:41641").await;
    let foreign_id=node_id(&rig.app,&foreign,"org-only-foreign-node").await;
    for (serial,peer) in [(1,foreign_id),(2,rig.a_node.clone())] {
        rig.a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request","peer_node_id":peer,"request_id":serial}).to_string().into())).await.unwrap();
    }
    let (_,tok)=enroll(&rig.app,&rig.seeded,"org-only-unjoined").await;
    let mut unjoined=connect(&rig.app,&tok,&[]).await;
    unjoined.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request","peer_node_id":rig.b_node,"request_id":3}).to_string().into())).await.unwrap();
    assert_org_only_quiet(&mut unjoined).await;
    assert_org_only_quiet(&mut rig.a).await;
    assert_org_only_quiet(&mut rig.b).await;
    assert_org_only_quiet(&mut rig.r).await;
    assert!(rig.app.state.network().relay_pair_churn.is_empty());
    assert!(audit_rows(&rig.app,&rig.seeded).await.iter().all(|r|r["action"]!="mint"));
}

#[tokio::test]
async fn org_only_fallback_simultaneous_members_claim_one_live_generation() {
    let mut rig=Rig::up("org-only-concurrent",true,Some(true)).await;
    rig.arm().await;
    let a_msg=Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request","peer_node_id":rig.b_node,"request_id":1}).to_string().into());
    let b_msg=Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request","peer_node_id":rig.a_node,"request_id":2}).to_string().into());
    let (a,b)=tokio::join!(rig.a.send(a_msg),rig.b.send(b_msg));a.unwrap();b.unwrap();
    let sa=recv_org_only_session(&mut rig.a).await;
    let sb=recv_org_only_session(&mut rig.b).await;
    let serve=recv_t(&mut rig.r,"rc:overlay.relay_serve",Duration::from_secs(5)).await.unwrap();
    assert_eq!(sa["vni"],sb["vni"]);assert_eq!(sa["generation"],sb["generation"]);
    assert_eq!(sa["vni"],serve["vni"]);assert_eq!(sa["generation"],serve["generation"]);
    // A losing query may repush the canonical lease to its asker. It may
    // never send a different live generation, a TURN grant, or another Serve.
    for ws in [&mut rig.a,&mut rig.b] {
        let deadline=tokio::time::Instant::now()+Duration::from_millis(300);
        while let Ok(Some(Ok(frame)))=tokio::time::timeout_at(deadline,ws.next()).await {
            if let Message::Text(text)=frame {
                let value:Value=serde_json::from_str(&text).unwrap();
                assert_ne!(value["t"],json!("rc:overlay.relay_grant"));
                assert_ne!(value["t"],json!("rc:overlay.force_derp"));
                if value["t"]=="rc:overlay.relay_session" {
                    assert_eq!(value["vni"],serve["vni"]);
                    assert_eq!(value["generation"],serve["generation"]);
                }
            }
        }
    }
    assert_org_only_quiet(&mut rig.r).await;
    let rows=audit_rows(&rig.app,&rig.seeded).await;
    assert_eq!(rows.iter().filter(|row|row["action"]=="mint" && row["denied"].is_null()).count(),1);
    let network=rig.app.state.network();
    let r=ObjectId::parse_str(&rig.r_node).unwrap();
    assert_eq!(network.org_relay.sessions_on_relay(r),1);
    assert!(network.relay_pair_churn.is_empty());
    let mut slots_left=0;
    for member in [&rig.a_node,&rig.b_node] {
        let member=ObjectId::parse_str(member).unwrap();
        while network.relay_rate_limiter.check(member,r,30) {slots_left+=1;}
    }
    assert_eq!(slots_left,59,"only the winning mint consumes a requester->relay slot");
}

#[tokio::test]
async fn org_only_fallback_multi_peer_query_budget_allows_128_and_bounds_129() {
    let mut rig=Rig::up("org-only-query-budget",true,Some(true)).await;
    rig.arm().await;
    let (_,c_token)=enroll(&rig.app,&rig.seeded,"org-only-query-c").await;
    let (_,d_token)=enroll(&rig.app,&rig.seeded,"org-only-query-d").await;
    let mut c=connect(&rig.app,&c_token,&[]).await;
    let mut d=connect(&rig.app,&d_token,&[]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    join(&mut c,6,Some(true),"203.0.113.16:41641").await;
    join(&mut d,7,Some(true),"203.0.113.17:41641").await;
    let peers=[rig.b_node.clone(),node_id(&rig.app,&rig.seeded,"org-only-query-c").await,
        node_id(&rig.app,&rig.seeded,"org-only-query-d").await];
    let mut leases=std::collections::HashMap::new();
    for serial in 1..=128u64 {
        let peer=&peers[((serial-1)%3)as usize];
        rig.a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request",
            "peer_node_id":peer,"request_id":serial}).to_string().into())).await.unwrap();
        let session=recv_org_only_session(&mut rig.a).await;
        assert_eq!(session["peer_node_id"],json!(peer));
        let identity=(session["vni"].clone(),session["generation"].clone());
        if let Some(previous)=leases.insert(peer.clone(),identity.clone()) {assert_eq!(identity,previous);}
    }
    assert_eq!(leases.len(),3,"queries genuinely cover multiple peer pairs");
    rig.a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request",
        "peer_node_id":peers[0],"request_id":129}).to_string().into())).await.unwrap();
    assert_org_only_quiet(&mut rig.a).await;
    let network=rig.app.state.network();
    let a=ObjectId::parse_str(&rig.a_node).unwrap();
    let relay=ObjectId::parse_str(&rig.r_node).unwrap();
    let mut remaining=0;
    while network.relay_rate_limiter.check(a,relay,30) {remaining+=1;}
    assert_eq!(remaining,27,"3 fresh peer leases spent 3 mint slots; 125 healthy repushes spent none");
    assert_eq!(network.org_relay.sessions_on_relay(relay),3);
    assert!(network.relay_pair_churn.is_empty());
    let rows=audit_rows(&rig.app,&rig.seeded).await;
    assert_eq!(rows.iter().filter(|r|r["action"]=="mint" && r["denied"].is_null()).count(),3);
}

/// `join` from `a`'s socket under a given process instance (`None` = an
/// older node that sends none).
async fn rejoin_as(ws: &mut Ws, seed: u8, instance: Option<&str>) {
    let mut msg = json!({
        "t": "rc:overlay.join",
        "wg_public_key": BASE64.encode([seed; 32]),
        "mtu": 1280,
        "endpoints": ["203.0.113.10:41641"],
        "supports_org_relay": true,
        "supports_server_relay_strategy": true,
        "relay_port": 3478,
        "org_primary": true,
    });
    if let Some(i) = instance {
        msg["instance"] = json!(i);
    }
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .expect("send join");
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .expect("a netmap answers the join");
}

/// Field 2026-10-27 (rf-e17c20cfdb71): a relay restarted twice, its fresh
/// requests counted against the grants from before each restart, and its
/// three pairs were pinned to DERP for 30 min. A join under a new process
/// instance forgets the node's armed grants and counted cycles, keeping a
/// standing pin; a reconnect under the same instance, or a join without
/// one, changes nothing.
#[tokio::test]
async fn a_restarted_node_starts_its_churn_count_afresh() {
    use roomler_ai_mod_network::overlay::{
        PairChurn, arm_grant, churn_note_request, org_loss_pin, pair_key,
    };
    let mut rig = Rig::up("restart-churn", true, Some(true)).await;
    let pk = pair_key(
        ObjectId::parse_str(&rig.a_node).unwrap(),
        ObjectId::parse_str(&rig.b_node).unwrap(),
    );
    let now = std::time::Instant::now();
    let t = now - Duration::from_secs(60);
    let mut churn = PairChurn::default();
    arm_grant(&mut churn, t);
    assert!(!churn_note_request(&mut churn, t + Duration::from_secs(10)));
    arm_grant(&mut churn, t + Duration::from_secs(20));
    org_loss_pin(&mut churn, now);
    let before = format!("{churn:?}");
    let mut fresh = PairChurn::default();
    org_loss_pin(&mut fresh, now);
    let forgotten = format!("{fresh:?}");
    assert_ne!(before, forgotten);
    rig.app
        .state
        .network()
        .relay_pair_churn
        .insert(pk.clone(), churn);
    let state = |rig: &Rig| {
        format!(
            "{:?}",
            rig.app
                .state
                .network()
                .relay_pair_churn
                .get(&pk)
                .unwrap()
                .value()
        )
    };

    rejoin_as(&mut rig.a, 1, Some("one")).await;
    assert_eq!(state(&rig), before, "a first-seen instance is no restart");
    rejoin_as(&mut rig.a, 1, Some("one")).await;
    assert_eq!(state(&rig), before, "a reconnect keeps the count");
    rejoin_as(&mut rig.a, 1, None).await;
    assert_eq!(state(&rig), before, "an older node keeps the count");
    rejoin_as(&mut rig.a, 1, Some("two")).await;
    assert_eq!(
        state(&rig),
        forgotten,
        "a restart forgets grants, keeps the pin"
    );
}
