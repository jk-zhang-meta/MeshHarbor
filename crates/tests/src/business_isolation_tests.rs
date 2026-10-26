// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor #21 — hard mainland/non-mainland isolation in netmap shaping
//! (`app.business_isolation`). Under `enforce`, a node is shown only the
//! peers whose live connection was observed in its own business zone; a
//! peer across the line, or with no zone at all, is withheld from the full
//! netmap and sent as a `removes` in every delta. Under `warn` nothing is
//! withheld.
//!
//! Zones come from the auto-relay fixture: each agent WebSocket places
//! itself with `X-Forwarded-For` through the trusted loopback proxy, and a
//! two-record GeoIP database maps 0.0.0.0/1 to US and 128.0.0.0/1 to CN.

use crate::agent_presence_tests::enroll;
use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::peer_relay_auto_tests::{
    CN_A, US_A, US_B, approved_user, assert_observed, fixture_mmdb,
};
use crate::peer_relay_mint_tests::{
    Ws, approve, audit_rows, connect_from, grant_relay, join, node_id, put, recv_t, set_mode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::oid::ObjectId;
use futures::SinkExt;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

struct Rig {
    app: TestApp,
    seeded: SeededTenant,
    _geo: tempfile::TempDir,
}

impl Rig {
    async fn up(slug: &str, isolation: &'static str) -> Self {
        let geo = tempfile::tempdir().unwrap();
        let mmdb = geo.path().join("dbip-country-lite.mmdb");
        std::fs::write(&mmdb, fixture_mmdb()).unwrap();
        let mmdb = mmdb.to_str().unwrap().to_owned();
        let owner_id = ObjectId::new();
        let app = TestApp::spawn_with_settings(move |s| {
            s.auth.account_approval.enabled = true;
            s.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
            s.app.rate_limit_trusted_hops = 0;
            s.app.business_isolation = isolation.into();
            s.stats.geoip_mmdb = Some(mmdb);
        })
        .await;
        approved_user(&app, &format!("{slug}_owner"), Some(owner_id)).await;
        let admin = approved_user(&app, &format!("{slug}_admin"), None).await;
        let member = approved_user(&app, &format!("{slug}_member"), None).await;
        let tenant_id = app
            .state
            .tenants
            .create(
                format!("{slug} Corp"),
                slug.to_owned(),
                ObjectId::parse_str(&admin.id).unwrap(),
            )
            .await
            .unwrap()
            .id
            .unwrap()
            .to_hex();
        let seeded = SeededTenant {
            tenant_id,
            tenant_slug: slug.to_owned(),
            admin,
            member,
            rooms: Vec::new(),
        };
        Self {
            app,
            seeded,
            _geo: geo,
        }
    }

    /// Enroll and connect `name` from `from` (`None`: a bare connection, no
    /// zone), and check the server recorded that placement.
    async fn device(&self, name: &str, from: Option<&str>) -> Ws {
        let (agent, tok) = enroll(&self.app, &self.seeded, name).await;
        let ws = connect_from(&self.app, &tok, &[], from).await;
        assert_observed(&self.app, &agent, from).await;
        ws
    }

    async fn node(&self, name: &str) -> String {
        node_id(&self.app, &self.seeded, name).await
    }
}

fn peer_ids(netmap: &Value) -> BTreeSet<String> {
    netmap["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["node_id"].as_str().unwrap().to_owned())
        .collect()
}

/// Every delta `ws` receives within `wait`: (upserted ids, removed ids).
async fn deltas(ws: &mut Ws, wait: Duration) -> (BTreeSet<String>, BTreeSet<String>) {
    let (mut up, mut rm) = (BTreeSet::new(), BTreeSet::new());
    while let Some(d) = recv_t(ws, "rc:overlay.netmap_delta", wait).await {
        for u in d["upserts"].as_array().unwrap() {
            up.insert(u["node_id"].as_str().unwrap().to_owned());
        }
        for r in d["removes"].as_array().unwrap() {
            rm.insert(r.as_str().unwrap().to_owned());
        }
    }
    (up, rm)
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn enforce_shows_only_peers_in_the_same_zone() {
    let rig = Rig::up("iso-enforce", "enforce").await;
    let mut us_a = rig.device("iso-us-a", Some(US_A)).await;
    let mut cn_a = rig.device("iso-cn-a", Some(CN_A)).await;
    let mut us_b = rig.device("iso-us-b", Some(US_B)).await;

    assert!(peer_ids(&join(&mut us_a, 1, Some(true), "203.0.113.10:41641").await).is_empty());
    let us_a_id = rig.node("iso-us-a").await;

    // The mainland joiner sees no non-mainland peer, and the non-mainland
    // node is told to REMOVE it, never offered it.
    assert!(peer_ids(&join(&mut cn_a, 2, Some(true), "203.0.113.11:41641").await).is_empty());
    let cn_a_id = rig.node("iso-cn-a").await;
    let (up, rm) = deltas(&mut us_a, Duration::from_millis(600)).await;
    assert!(!up.contains(&cn_a_id), "us-a was offered cn-a: {up:?}");
    assert!(
        rm.contains(&cn_a_id),
        "us-a was not told to remove cn-a: {rm:?}"
    );

    // Same zone: the second non-mainland node sees the first, and the first
    // is offered it; the mainland node is not.
    let b_map = join(&mut us_b, 3, Some(true), "203.0.113.12:41641").await;
    assert_eq!(peer_ids(&b_map), set(&[&us_a_id]));
    let us_b_id = rig.node("iso-us-b").await;
    let (up, _) = deltas(&mut us_a, Duration::from_millis(600)).await;
    assert!(up.contains(&us_b_id), "us-a was not offered us-b: {up:?}");
    let (up, rm) = deltas(&mut cn_a, Duration::from_millis(600)).await;
    assert!(
        !up.contains(&us_b_id) && rm.contains(&us_b_id),
        "cn-a: up {up:?} rm {rm:?}"
    );

    // A rejoin's full netmap agrees with the deltas.
    assert_eq!(
        peer_ids(&join(&mut us_a, 1, Some(true), "203.0.113.10:41641").await),
        set(&[&us_b_id])
    );
    assert!(peer_ids(&join(&mut cn_a, 2, Some(true), "203.0.113.11:41641").await).is_empty());
}

#[tokio::test]
async fn enforce_withholds_a_node_without_a_zone_from_everyone() {
    let rig = Rig::up("iso-unknown", "enforce").await;
    let mut us_a = rig.device("iso-u-us-a", Some(US_A)).await;
    let mut bare = rig.device("iso-u-bare", None).await;
    join(&mut us_a, 1, Some(true), "203.0.113.10:41641").await;
    let us_a_id = rig.node("iso-u-us-a").await;
    // Fail closed both ways: the zoneless node sees nobody, and nobody is
    // offered it.
    assert!(peer_ids(&join(&mut bare, 4, Some(true), "203.0.113.13:41641").await).is_empty());
    let bare_id = rig.node("iso-u-bare").await;
    let (up, rm) = deltas(&mut us_a, Duration::from_millis(600)).await;
    assert!(
        !up.contains(&bare_id) && rm.contains(&bare_id),
        "us-a: up {up:?} rm {rm:?}"
    );
    assert!(
        !peer_ids(&join(&mut us_a, 1, Some(true), "203.0.113.10:41641").await).contains(&bare_id)
    );
    assert_ne!(us_a_id, bare_id);
}

#[tokio::test]
async fn warn_withholds_nothing() {
    let rig = Rig::up("iso-warn", "warn").await;
    let mut us_a = rig.device("iso-w-us-a", Some(US_A)).await;
    let mut cn_a = rig.device("iso-w-cn-a", Some(CN_A)).await;
    join(&mut us_a, 1, Some(true), "203.0.113.10:41641").await;
    let us_a_id = rig.node("iso-w-us-a").await;
    let cn_map = join(&mut cn_a, 2, Some(true), "203.0.113.11:41641").await;
    assert_eq!(peer_ids(&cn_map), set(&[&us_a_id]), "warn only logs");
    let cn_a_id = rig.node("iso-w-cn-a").await;
    let (up, _) = deltas(&mut us_a, Duration::from_millis(600)).await;
    assert!(up.contains(&cn_a_id), "{up:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// The cross-border line (#21 rules 1–5)
// ─────────────────────────────────────────────────────────────────────────────

/// Mainland and non-mainland relay addresses in the fixture database.
const CN_R: &str = "223.6.6.6";
const US_R: &str = "1.1.1.1";
/// The exit relay's address on the private line (the approved edge's).
const LINE: &str = "10.42.2.114:3478";

/// A mainland member `cn`, a non-mainland member `us`, a mainland relay `gz`
/// and a non-mainland relay `hk`, with `gz → hk` approved as a backbone
/// edge (`cross_border` as given). Both relays serve and are granted to
/// every node; `gz` is backbone-ready; both members ride line-only peers.
struct LineRig {
    rig: Rig,
    cn: Ws,
    us: Ws,
    gz: Ws,
    hk: Ws,
    cn_node: String,
    us_node: String,
    gz_node: String,
    hk_node: String,
    gz_agent: String,
    hk_agent: String,
    /// `us`'s agent token, to reconnect it.
    us_tok: String,
}

async fn line_join(ws: &mut Ws, seed: u8, endpoint: &str, extra: Value) -> Value {
    let mut msg = json!({
        "t": "rc:overlay.join", "wg_public_key": BASE64.encode([seed; 32]), "mtu": 1280,
        "endpoints": [endpoint], "supports_org_relay": true,
        "supports_server_relay_strategy": true, "relay_port": 3478, "org_primary": true,
        "supports_derp": true, "supports_forced_derp": true,
    });
    for (k, v) in extra.as_object().unwrap() {
        msg[k] = v.clone();
    }
    ws.send(Message::Text(msg.to_string().into())).await.unwrap();
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .expect("a netmap answers the join")
}

async fn relay_request(ws: &mut Ws, peer: &str) {
    ws.send(Message::Text(
        json!({ "t": "rc:overlay.relay_request", "peer_node_id": peer })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
}

impl LineRig {
    async fn up(slug: &str, cross_border: bool) -> Self {
        let rig = Rig::up(slug, "enforce").await;
        let relay = |name: String, from: &'static str| {
            let rig = &rig;
            async move {
                let (agent, tok) = enroll(&rig.app, &rig.seeded, &name).await;
                let ws = connect_from(&rig.app, &tok, &["relay-server"], Some(from)).await;
                assert_observed(&rig.app, &agent, Some(from)).await;
                (agent, ws)
            }
        };
        let (gz_agent, mut gz) = relay(format!("{slug}-gz"), CN_R).await;
        let (hk_agent, mut hk) = relay(format!("{slug}-hk"), US_R).await;
        let mut cn = rig.device(&format!("{slug}-cn"), Some(CN_A)).await;
        let (us_agent, us_tok) = enroll(&rig.app, &rig.seeded, &format!("{slug}-us")).await;
        let mut us = connect_from(&rig.app, &us_tok, &[], Some(US_A)).await;
        assert_observed(&rig.app, &us_agent, Some(US_A)).await;
        line_join(&mut gz, 3, "223.6.6.6:41641", json!({ "relay_backbone_ready": true })).await;
        line_join(&mut hk, 4, "1.1.1.1:41641", json!({})).await;
        let flag = json!({ "supports_backbone_only_v1": true });
        line_join(&mut cn, 1, "223.5.5.5:41641", flag.clone()).await;
        line_join(&mut us, 2, "8.8.8.8:41641", flag).await;
        let (app, seeded) = (&rig.app, &rig.seeded);
        set_mode(app, seeded, "on").await;
        assert_eq!(approve(app, seeded, &gz_agent, true).await, 200);
        assert_eq!(approve(app, seeded, &hk_agent, true).await, 200);
        let gz_node = rig.node(&format!("{slug}-gz")).await;
        let hk_node = rig.node(&format!("{slug}-hk")).await;
        grant_relay(app, seeded, &gz_node).await;
        grant_relay(app, seeded, &hk_node).await;
        let mut line = Self {
            cn_node: rig.node(&format!("{slug}-cn")).await,
            us_node: rig.node(&format!("{slug}-us")).await,
            rig,
            cn,
            us,
            gz,
            hk,
            gz_node,
            hk_node,
            gz_agent,
            hk_agent,
            us_tok,
        };
        line.set_edge(cross_border).await;
        line
    }

    async fn set_edge(&mut self, cross_border: bool) {
        let path = format!(
            "/api/tenant/{}/agent/{}/peer-relay-policy",
            self.rig.seeded.tenant_id, self.gz_agent
        );
        let body = json!({ "serve": true, "approved_backbone_edges": [
            { "relay_agent_id": self.hk_agent, "endpoint": LINE, "cross_border": cross_border },
        ]});
        let (status, v) = put(&self.rig.app, &path, &self.rig.seeded.admin.access_token, body).await;
        assert_eq!(status, 200, "{v}");
    }

    /// Every frame of a line mint: (gz serve, bridge, hk serve, cn session,
    /// us session).
    async fn expect_line(&mut self) -> (Value, Value, Value, Value, Value) {
        let wait = Duration::from_secs(5);
        let gz = recv_t(&mut self.gz, "rc:overlay.relay_serve", wait).await.expect("gz serves");
        let bridge = recv_t(&mut self.gz, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("gz bridges")["bridge"]
            .clone();
        let hk = recv_t(&mut self.hk, "rc:overlay.relay_serve", wait).await.expect("hk serves");
        let cn = recv_t(&mut self.cn, "rc:overlay.relay_session", wait).await.expect("cn session");
        let us = recv_t(&mut self.us, "rc:overlay.relay_session", wait).await.expect("us session");
        (gz, bridge, hk, cn, us)
    }

    async fn expect_line_revoked(&mut self, cn_vni: &Value, us_vni: &Value) {
        let wait = Duration::from_secs(5);
        for (name, ws, vni) in [
            ("gz", &mut self.gz, cn_vni),
            ("cn", &mut self.cn, cn_vni),
            ("hk", &mut self.hk, us_vni),
            ("us", &mut self.us, us_vni),
        ] {
            let v = recv_t(ws, "rc:overlay.relay_revoke", wait)
                .await
                .unwrap_or_else(|| panic!("{name} receives relay_revoke"));
            assert_eq!(&v["vni"], vni, "{name}: its own leg's VNI");
        }
        recv_t(&mut self.gz, "rc:overlay.relay_bridge_revoke", wait)
            .await
            .expect("gz's bridge is revoked");
    }

    async fn audit_reasons(&self, action: &str) -> Vec<(String, String)> {
        audit_rows(&self.rig.app, &self.rig.seeded)
            .await
            .iter()
            .filter(|r| r["action"] == action)
            .map(|r| {
                let s = |k: &str| r[k].as_str().unwrap_or_default().to_owned();
                (s("reason"), s("relay_node_id"))
            })
            .collect()
    }
}

/// Rules 1–5 end to end. Without a `cross_border` edge the cross-zone peer
/// stays withheld and a relay request mints nothing. With one, a member that
/// rides line-only peers is shown the other side `backbone_only` and bare,
/// and a relay request mints one org-relay session per side: each member
/// binds a relay in its own zone, and the mainland relay's bridge joins the
/// two over the private line, which no member is told. No TURN grant is
/// issued, both legs are audited `cross_border_line`, a re-request re-pushes
/// the asker's own leg, and a lossy line is kept rather than pinned to DERP.
#[tokio::test]
async fn a_cross_border_pair_rides_only_its_approved_line() {
    let mut l = LineRig::up("iso-line", false).await;
    let flag = json!({ "supports_backbone_only_v1": true });

    // An ordinary edge is not a line.
    let map = line_join(&mut l.cn, 1, "223.5.5.5:41641", flag.clone()).await;
    assert!(!peer_ids(&map).contains(&l.us_node), "withheld without a line");
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(600)).await.is_none(),
        "no line, no mint"
    );

    l.set_edge(true).await;
    // A member without the flag still sees nothing across the line.
    let mut old = l.rig.device("iso-line-old", Some(CN_A)).await;
    let old_map = line_join(&mut old, 5, "223.5.5.7:41641", json!({})).await;
    assert!(!peer_ids(&old_map).contains(&l.us_node), "rule 4: an old client sees nothing");
    let map = line_join(&mut l.cn, 1, "223.5.5.5:41641", flag.clone()).await;
    let us = map["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["node_id"] == json!(l.us_node))
        .expect("the line shows the cross-zone peer")
        .clone();
    assert_eq!(us["backbone_only"], json!(true), "{us}");
    assert!(us["endpoints"].as_array().is_none_or(|e| e.is_empty()), "{us}");
    assert_ne!(us["supports_derp"], json!(true), "{us}");
    assert_ne!(us["supports_derp_floor"], json!(true), "{us}");

    relay_request(&mut l.cn, &l.us_node).await;
    let (gz, bridge, hk, cn, us) = l.expect_line().await;
    assert_eq!(cn["relay_node_id"], json!(l.gz_node), "cn binds the mainland relay");
    assert_eq!(us["relay_node_id"], json!(l.hk_node), "us binds the non-mainland relay");
    assert_eq!(cn["peer_node_id"], json!(l.us_node));
    assert_eq!(us["peer_node_id"], json!(l.cn_node));
    assert_eq!(gz["vni"], cn["vni"]);
    assert_eq!(hk["vni"], us["vni"]);
    let secret = |v: &Value, i: usize| v["members"][i]["bind_secret"].clone();
    assert_eq!(secret(&gz, 0), cn["bind_secret"]);
    assert_eq!(secret(&hk, 1), us["bind_secret"]);
    assert_eq!(bridge["local_vni"], gz["vni"]);
    assert_eq!(bridge["local_bind_secret"], secret(&gz, 1), "the bridge holds us's slot on gz");
    assert_eq!(bridge["remote_vni"], hk["vni"]);
    assert_eq!(bridge["remote_bind_secret"], secret(&hk, 0), "and cn's on hk");
    assert_eq!(bridge["remote_endpoint"], json!(LINE));
    for (name, s) in [("cn", &cn), ("us", &us)] {
        assert!(!s.to_string().contains("10.42.2.114"), "{name} is never told the line: {s}");
    }
    assert!(
        recv_t(&mut l.cn, "rc:overlay.relay_grant", Duration::from_millis(400)).await.is_none(),
        "rule 3: no TURN across the line"
    );
    let mut minted = Vec::new();
    for _ in 0..40 {
        minted = l.audit_reasons("mint").await;
        if minted.iter().filter(|(r, _)| r == "cross_border_line").count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for relay in [&l.gz_node, &l.hk_node] {
        assert!(
            minted.contains(&("cross_border_line".into(), relay.clone())),
            "rule 5: both legs audited: {minted:?}"
        );
    }

    // The other member asking re-pushes its own leg; nothing new is minted.
    relay_request(&mut l.us, &l.cn_node).await;
    let again = recv_t(&mut l.us, "rc:overlay.relay_session", Duration::from_secs(5))
        .await
        .expect("us's leg is re-pushed");
    assert_eq!(again["vni"], us["vni"]);
    assert_eq!(again["relay_node_id"], json!(l.hk_node));
    assert!(
        recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(400)).await.is_none(),
        "no second mint"
    );

    // 8% loss on the line: both ends could ride DERP, but nothing else may
    // carry this pair, so the line stays.
    l.us.send(Message::Text(
        json!({ "t": "rc:overlay.org_relay_loss", "peer_node_id": l.cn_node,
            "vni": us["vni"], "packets": 3000, "lost": 240 })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    for (name, ws) in [("cn", &mut l.cn), ("us", &mut l.us)] {
        assert!(
            recv_t(ws, "rc:overlay.force_derp", Duration::from_millis(600)).await.is_none(),
            "{name}: a lossy line is not pinned to DERP"
        );
    }
    let pk = roomler_ai_mod_network::overlay::pair_key(
        ObjectId::parse_str(&l.cn_node).unwrap(),
        ObjectId::parse_str(&l.us_node).unwrap(),
    );
    assert!(l.rig.app.state.network().org_relay.active_session(&pk).is_some());
}

/// A line ends with its edge's `cross_border` flag and with either relay's
/// approval, on all four parties, each told its own VNI, and the bridge with
/// it. Whichever member asks, the mainland member binds the mainland relay.
#[tokio::test]
async fn a_line_ends_with_its_edge_and_with_either_relay() {
    let mut l = LineRig::up("iso-line-end", true).await;
    relay_request(&mut l.cn, &l.us_node).await;
    let (_, _, _, cn, us) = l.expect_line().await;
    l.set_edge(false).await;
    l.expect_line_revoked(&cn["vni"], &us["vni"]).await;
    let mut revoked = Vec::new();
    for _ in 0..40 {
        revoked = l.audit_reasons("revoke").await;
        if revoked.iter().any(|(r, _)| r == "backbone_edge_revoked") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(revoked.iter().any(|(r, _)| r == "backbone_edge_revoked"), "{revoked:?}");

    // The non-mainland member asks this time; the line keeps its sides.
    l.set_edge(true).await;
    relay_request(&mut l.us, &l.cn_node).await;
    let (_, _, _, cn, us) = l.expect_line().await;
    assert_eq!(cn["relay_node_id"], json!(l.gz_node));
    assert_eq!(us["relay_node_id"], json!(l.hk_node));
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &l.hk_agent, false).await, 200);
    l.expect_line_revoked(&cn["vni"], &us["vni"]).await;
}

/// A line outlives a party's displaced control connection for
/// `LINE_RECONNECT_GRACE`, since it carries traffic without the control
/// plane: a member that reconnects from its own zone keeps the line, and one
/// that reconnects from the other zone loses it once the grace has passed.
/// (A member that goes offline loses it at once, as `device_left`.) Field,
/// 2026-10-26: revoking at every closed connection tore a line down on one
/// relay only while a restarting center closed its connections.
#[tokio::test]
async fn a_line_outlives_a_reconnect_from_its_zone_only() {
    use roomler_ai_mod_network::org_relay::LINE_RECONNECT_GRACE;
    let mut l = LineRig::up("iso-line-reconnect", true).await;
    relay_request(&mut l.cn, &l.us_node).await;
    let (_, _, _, cn, us) = l.expect_line().await;
    let flag = json!({ "supports_backbone_only_v1": true });

    let mut again = connect_from(&l.rig.app, &l.us_tok, &[], Some(US_B)).await;
    line_join(&mut again, 2, "8.8.8.8:41641", flag.clone()).await;
    let past = LINE_RECONNECT_GRACE + Duration::from_secs(3);
    assert!(
        recv_t(&mut l.hk, "rc:overlay.relay_revoke", past)
            .await
            .is_none(),
        "a reconnect from the same zone keeps the line"
    );

    let mut moved = connect_from(&l.rig.app, &l.us_tok, &[], Some(CN_A)).await;
    line_join(&mut moved, 2, "8.8.8.8:41641", flag).await;
    let wait = LINE_RECONNECT_GRACE + Duration::from_secs(5);
    for (name, ws, vni) in [
        ("hk", &mut l.hk, &us["vni"]),
        ("gz", &mut l.gz, &cn["vni"]),
        ("cn", &mut l.cn, &cn["vni"]),
    ] {
        let v = recv_t(ws, "rc:overlay.relay_revoke", wait)
            .await
            .unwrap_or_else(|| panic!("{name}: a member that moved zones ends the line"));
        assert_eq!(&v["vni"], vni, "{name}: its own leg's VNI");
    }
    drop((again, moved));
}

/// Open a center-brokered tunnel from `ws` (an agent driving the tunnel-client
/// role) to `target`, and return the server's answer: `rc:tunnel.opened` or
/// the `rc:error` code.
async fn tunnel_open(ws: &mut Ws, target: &str) -> String {
    for m in [
        json!({ "t": "rc:tunnel.hello", "role": "client", "version": "0.3.0",
                "supported_transports": ["webrtc-dc-v1"] }),
        json!({ "t": "rc:tunnel.open", "agent_id": target, "transport": "webrtc-dc-v1" }),
    ] {
        ws.send(Message::Text(m.to_string().into())).await.unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Some(left) = deadline.checked_duration_since(tokio::time::Instant::now()) {
        let Ok(Some(Ok(Message::Text(txt)))) =
            tokio::time::timeout(left, futures::StreamExt::next(ws)).await
        else {
            continue;
        };
        let v: Value = serde_json::from_str(&txt).unwrap_or_default();
        match v["t"].as_str() {
            Some("rc:tunnel.opened") => return "opened".into(),
            Some("rc:error") => return v["code"].as_str().unwrap_or("?").into(),
            _ => {}
        }
    }
    "no answer".into()
}

/// #22 — a tunnel the center brokers carries business bytes, so it obeys the
/// zones too; the devices' own management connections (the hello the zones
/// were observed on) are never refused.
#[tokio::test]
async fn a_center_brokered_tunnel_stays_in_one_zone() {
    for (mode, across) in [("enforce", "business_isolation"), ("warn", "opened")] {
        let rig = Rig::up(&format!("iso-tunnel-{mode}"), mode).await;
        let mut devices = Vec::new();
        for (name, from) in [
            ("iso-tun-us-a", US_A),
            ("iso-tun-cn-a", CN_A),
            ("iso-tun-us-b", US_B),
        ] {
            let (id, tok) = enroll(&rig.app, &rig.seeded, name).await;
            let ws = connect_from(&rig.app, &tok, &[], Some(from)).await;
            assert_observed(&rig.app, &id, Some(from)).await;
            devices.push((id, ws));
        }
        let [(_, mut us_a), (cn_id, _cn_a), (us_b_id, _us_b)] =
            <[_; 3]>::try_from(devices).ok().unwrap();
        assert_eq!(
            tunnel_open(&mut us_a, &cn_id).await,
            across,
            "{mode}: across the zones"
        );
        assert_eq!(
            tunnel_open(&mut us_a, &us_b_id).await,
            "opened",
            "{mode}: within one zone"
        );
    }
}
