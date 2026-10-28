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
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

struct Rig {
    app: TestApp,
    seeded: SeededTenant,
    owner_token: String,
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
        let owner = approved_user(&app, &format!("{slug}_owner"), Some(owner_id)).await;
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
            owner_token: owner.access_token,
            _geo: geo,
        }
    }

    /// The central owner approves `agent`'s business role (`server`).
    async fn set_role(&self, agent: &str, role: &str) {
        let path = format!(
            "/api/admin/business-authority/agent/{}/{agent}",
            self.seeded.tenant_id
        );
        let (s, v) = put(
            &self.app,
            &path,
            &self.owner_token,
            json!({ "role": role, "reason": "server topology fixture" }),
        )
        .await;
        assert_eq!(s, 200, "set role {role}: {v}");
    }

    /// The admin enables or disables the server link `a`—`b`.
    async fn link(&self, a: &str, b: &str, enabled: bool) {
        let (s, v) = put(
            &self.app,
            &format!("/api/tenant/{}/server-link", self.seeded.tenant_id),
            &self.seeded.admin.access_token,
            json!({ "a": a, "b": b, "enabled": enabled }),
        )
        .await;
        assert_eq!(s, 200, "link: {v}");
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

/// ACL-02 — the tenant's ACL posture never lifts the isolation: with the ACL
/// in `warn` (which only logs) the cross-zone peer is still withheld.
#[tokio::test]
async fn an_acl_in_warn_does_not_lift_the_isolation() {
    let rig = Rig::up("iso-acl-warn", "enforce").await;
    let (s, v) = put(
        &rig.app,
        &format!("/api/tenant/{}/overlay-acl/mode", rig.seeded.tenant_id),
        &rig.seeded.admin.access_token,
        json!({ "mode": "warn" }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let mut us_a = rig.device("iso-aw-us-a", Some(US_A)).await;
    let mut cn_a = rig.device("iso-aw-cn-a", Some(CN_A)).await;
    join(&mut us_a, 1, Some(true), "203.0.113.10:41641").await;
    assert!(peer_ids(&join(&mut cn_a, 2, Some(true), "203.0.113.11:41641").await).is_empty());
    let cn_a_id = rig.node("iso-aw-cn-a").await;
    let (up, rm) = deltas(&mut us_a, Duration::from_millis(600)).await;
    assert!(
        !up.contains(&cn_a_id) && rm.contains(&cn_a_id),
        "us-a: up {up:?} rm {rm:?}"
    );
}

/// GEO-04 — a node whose control connection was observed in one zone but
/// whose traffic leaves from the other (its trickled srflx address) has no
/// zone, and under `enforce` is withdrawn from its peers; an address in its
/// own zone changes nothing.
#[tokio::test]
async fn an_address_in_the_other_zone_withdraws_the_nodes_zone() {
    let rig = Rig::up("iso-conflict", "enforce").await;
    let mut us_a = rig.device("iso-c-us-a", Some(US_A)).await;
    let mut us_b = rig.device("iso-c-us-b", Some(US_B)).await;
    join(&mut us_a, 1, Some(true), "203.0.113.10:41641").await;
    let a_sees = peer_ids(&join(&mut us_b, 2, Some(true), "203.0.113.11:41641").await);
    let us_b_id = rig.node("iso-c-us-b").await;
    assert_eq!(a_sees.len(), 1, "the control: one zone, visible");
    let _ = deltas(&mut us_a, Duration::from_millis(600)).await;

    let srflx =
        |ip: &str| json!({ "t": "rc:overlay.srflx", "candidates": [format!("{ip}:41641")] });
    us_b.send(Message::Text(srflx(US_B).to_string().into()))
        .await
        .unwrap();
    let (_, rm) = deltas(&mut us_a, Duration::from_millis(800)).await;
    assert!(
        !rm.contains(&us_b_id),
        "an address in its own zone keeps it: rm {rm:?}"
    );

    us_b.send(Message::Text(srflx(CN_A).to_string().into()))
        .await
        .unwrap();
    let (up, rm) = deltas(&mut us_a, Duration::from_millis(800)).await;
    assert!(
        !up.contains(&us_b_id) && rm.contains(&us_b_id),
        "a CN address withdraws it: up {up:?} rm {rm:?}"
    );
}

/// The server topology: two servers meet exactly when an enabled link names
/// them, across the zones or inside one; a client keeps the zone rule.
#[tokio::test]
async fn servers_meet_by_link_alone_whatever_their_zones() {
    let rig = Rig::up("iso-links", "enforce").await;
    let mut devs = Vec::new();
    for (name, from) in [
        ("iso-l-us-s", US_A),
        ("iso-l-cn-s", CN_A),
        ("iso-l-us-s2", US_B),
        ("iso-l-us-c", US_R),
    ] {
        let (agent, tok) = enroll(&rig.app, &rig.seeded, name).await;
        let ws = connect_from(&rig.app, &tok, &[], Some(from)).await;
        assert_observed(&rig.app, &agent, Some(from)).await;
        devs.push((agent, ws));
    }
    for (agent, _) in &devs[..3] {
        rig.set_role(agent, "server").await;
    }
    for (i, (_, ws)) in devs.iter_mut().enumerate() {
        join(
            ws,
            60 + i as u8,
            Some(true),
            &format!("203.0.113.{}:41641", 60 + i),
        )
        .await;
    }
    let ids: Vec<String> = futures::future::join_all(
        ["iso-l-us-s", "iso-l-cn-s", "iso-l-us-s2", "iso-l-us-c"].map(|n| rig.node(n)),
    )
    .await;
    let (us_s, cn_s, us_s2, us_c) = (&ids[0], &ids[1], &ids[2], &ids[3]);
    // No links: a server sees no other server, not even in its own zone, and
    // still sees the client in its zone.
    let full = peer_ids(&join(&mut devs[0].1, 60, Some(true), "203.0.113.60:41641").await);
    assert_eq!(
        full,
        set(&[us_c]),
        "unlinked servers are separate: {full:?}"
    );

    // A link across the line connects the two servers, and only them.
    let _ = deltas(&mut devs[0].1, Duration::from_millis(600)).await;
    rig.link(&devs[0].0, &devs[1].0, true).await;
    let (up, _) = deltas(&mut devs[0].1, Duration::from_millis(800)).await;
    assert!(up.contains(cn_s), "linked: us-s is offered cn-s: {up:?}");
    let full = peer_ids(&join(&mut devs[1].1, 61, Some(true), "203.0.113.61:41641").await);
    assert_eq!(
        full,
        set(&[us_s]),
        "cn-s sees exactly its linked server: {full:?}"
    );
    assert!(!full.contains(us_s2.as_str()));

    // Disabled, the edge separates them again.
    rig.link(&devs[0].0, &devs[1].0, false).await;
    let (_, rm) = deltas(&mut devs[0].1, Duration::from_millis(800)).await;
    assert!(
        rm.contains(cn_s),
        "disabled: us-s is told to remove cn-s: {rm:?}"
    );

    // The topology the map draws: every server with where it was seen, and
    // the (now disabled) edge.
    let topo: Value = rig
        .app
        .auth_get(
            &format!("/api/tenant/{}/server-link", rig.seeded.tenant_id),
            &rig.seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let servers = topo["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 3, "{topo}");
    let cn = servers
        .iter()
        .find(|s| s["agent_id"] == devs[1].0.as_str())
        .unwrap();
    assert_eq!(
        (cn["country"].as_str(), cn["zone"].as_str()),
        (Some("CN"), Some("mainland")),
        "{topo}"
    );
    assert_eq!(topo["links"].as_array().unwrap().len(), 1, "{topo}");
    assert_eq!(topo["links"][0]["enabled"], false, "{topo}");
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
        Self::up_with_isolation(slug, cross_border, "enforce").await
    }

    async fn up_with_isolation(slug: &str, cross_border: bool, isolation: &'static str) -> Self {
        let rig = Rig::up(slug, isolation).await;
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

/// Exercise the staged graph builder against real live joins, ACLs and policy
/// updates, without sending any relay session or touching production.
#[tokio::test]
async fn staged_graph_uses_live_gates_and_revoked_crossing_is_not_offered() {
    let mut l = LineRig::up("iso-graph-stage", true).await;
    let net = l.rig.app.state.network();
    let cn = ObjectId::parse_str(&l.cn_node).unwrap();
    let us = ObjectId::parse_str(&l.us_node).unwrap();
    let gz = ObjectId::parse_str(&l.gz_agent).unwrap();
    let hk = ObjectId::parse_str(&l.hk_agent).unwrap();
    let edges = roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(net, cn, us, false).await.unwrap();
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(net, cn, us, true).await.is_err(), "trial capability is required");
    assert_eq!(edges, vec![(gz, hk, LINE.to_string(), true)]);
    l.set_edge(false).await;
    let edges = roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(l.rig.app.state.network(), cn, us, false).await.unwrap();
    assert!(edges.is_empty(), "a non-cross-border edge must not carry this pair");
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &l.hk_agent, false).await, 200);
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(l.rig.app.state.network(), cn, us, false).await.is_err());
}

#[tokio::test]
async fn staged_graph_tracks_three_relay_chain_and_each_acl() {
    let l = LineRig::up("iso-graph-chain", true).await;
    let (mid_agent, mid_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-graph-chain-mid").await;
    let mut mid = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(&mut mid, 6, "223.6.6.7:41641", json!({ "relay_backbone_ready": true })).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await, 200);
    let mid_node = l.rig.node("iso-graph-chain-mid").await;
    let mid_acl = grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    for (source, target, endpoint, cross) in [
        (&l.gz_agent, &mid_agent, "10.42.2.113:3478", false),
        (&mid_agent, &l.hk_agent, LINE, true),
    ] {
        let path = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, source);
        let body = json!({ "serve": true, "approved_backbone_edges": [
            { "relay_agent_id": target, "endpoint": endpoint, "cross_border": cross }
        ]});
        let (status, value) = put(&l.rig.app, &path, &l.rig.seeded.admin.access_token, body).await;
        assert_eq!(status, 200, "{value}");
    }
    let cn = ObjectId::parse_str(&l.cn_node).unwrap();
    let us = ObjectId::parse_str(&l.us_node).unwrap();
    let gz = ObjectId::parse_str(&l.gz_agent).unwrap();
    let mid_id = ObjectId::parse_str(&mid_agent).unwrap();
    let hk = ObjectId::parse_str(&l.hk_agent).unwrap();
    let edges = roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(l.rig.app.state.network(), cn, us, false).await.unwrap();
    let actual: BTreeSet<_> = edges.into_iter().collect();
    let expected: BTreeSet<_> = [(gz, mid_id, "10.42.2.113:3478".into(), false),
                                (mid_id, hk, LINE.into(), true)].into_iter().collect();
    assert_eq!(actual, expected);
    // Simulate the documented offered-probe path: the member can reach GZ,
    // not the same-zone middle relay; the remote member can reach HK.
    let gz_node = ObjectId::parse_str(&l.gz_node).unwrap();
    let mid_node_id = ObjectId::parse_str(&mid_node).unwrap();
    let hk_node = ObjectId::parse_str(&l.hk_node).unwrap();
    let net = l.rig.app.state.network();
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(net, cn, &[
        (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
        (mid_node_id, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(net, us, &[
        (hk_node, "1.1.1.1:3478".into(), true, Some(10)),
    ]));
    let chosen = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(l.rig.app.state.network(), cn, us, false).await.unwrap().unwrap();
    assert_eq!(chosen, (vec![gz, mid_id, hk], false));
    // A real endpoint update away and back must not resurrect an old probe.
    async fn endpoint_update(ws: &mut Ws, endpoint: &str) {
        ws.send(Message::Text(json!({"t":"rc:overlay.endpoints", "candidates":[endpoint]}).to_string().into())).await.unwrap();
        ws.send(Message::Ping(b"endpoint-barrier".to_vec().into())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(frame) = ws.next().await {
                if matches!(frame, Ok(Message::Pong(ref p)) if p.as_ref() == b"endpoint-barrier") { return; }
            }
            panic!("socket closed before endpoint barrier");
        }).await.expect("endpoint barrier timed out");
    }
    endpoint_update(&mut mid, "223.6.6.8:41641").await;
    endpoint_update(&mut mid, "223.6.6.7:41641").await;
    let after_endpoint_revert = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false).await.unwrap().unwrap();
    assert_eq!(after_endpoint_revert, (vec![mid_id, hk], false));
    let negative = [(mid_node_id, "223.6.6.7:3478".into(), false, None)];
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(net, cn, &negative));
    assert_eq!(roomler_ai_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false).await.unwrap().unwrap(), (vec![gz, mid_id, hk], false));
    // The actual policy route also invalidates a probe across A→B→A.
    let mid_policy_path = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, mid_agent);
    for edges in [json!([]), json!([{ "relay_agent_id": l.hk_agent, "endpoint": LINE, "cross_border": true }])] {
        let (status, value) = put(&l.rig.app, &mid_policy_path, &l.rig.seeded.admin.access_token,
            json!({ "serve": true, "approved_backbone_edges": edges })).await;
        assert_eq!(status, 200, "{value}");
    }
    assert_eq!(roomler_ai_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false).await.unwrap().unwrap(), (vec![mid_id, hk], false));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(net, cn, &negative));
    assert_eq!(roomler_ai_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false).await.unwrap().unwrap(), (vec![gz, mid_id, hk], false));
    // A rejoin invalidates the old direct-to-middle measurement even when
    // its endpoint string happens to stay unchanged.
    line_join(&mut mid, 6, "223.6.6.7:41641", json!({ "relay_backbone_ready": true })).await;
    let after_rejoin = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(l.rig.app.state.network(), cn, us, false).await.unwrap().unwrap();
    assert_eq!(after_rejoin, (vec![mid_id, hk], false));
    let path = format!("/api/tenant/{}/overlay-acl/{}", l.rig.seeded.tenant_id, mid_acl);
    let status = l.rig.app.client.delete(l.rig.app.url(&path)).bearer_auth(&l.rig.seeded.admin.access_token)
        .send().await.unwrap().status().as_u16();
    assert_eq!(status, 200);
    let edges = roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(l.rig.app.state.network(), cn, us, false).await.unwrap();
    assert!(edges.is_empty(), "no edge may use the no-longer-granted middle relay");
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::select_path(l.rig.app.state.network(), cn, us, false).await.unwrap().is_none());
}

/// A displaced agent WS can stay open. Its late report must not be accepted
/// after a replacement has bound; the replacement's own report still works.
#[tokio::test]
async fn staged_graph_rejects_probe_from_displaced_agent_socket() {
    let mut l = LineRig::up("iso-probe-owner", true).await;
    let us = ObjectId::parse_str(&l.us_node).unwrap();
    let hk = ObjectId::parse_str(&l.hk_node).unwrap();
    let endpoint = "1.1.1.1:3478";
    let net = l.rig.app.state.network();
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
        net, us, &[(hk, endpoint.into(), true, Some(30))]));
    let node = net.overlay_nodes.base.find_by_id(us).await.unwrap();
    let identity = match node.node_ref {
        roomler_ai_remote_control::models::NodeRef::Agent { agent_id } => agent_id,
        _ => panic!("fixture must be an agent"),
    };
    let old_connection = roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).unwrap();
    let (reached, release, finished) = roomler_ai_mod_network::org_relay::candidate_test_support::pause_next_probe(identity);
    let report = |rtt| Message::Text(json!({"t":"rc:overlay.relay_probe", "relay_node_id":hk.to_hex(),
        "endpoint":endpoint, "reachable":true, "rtt_ms":rtt}).to_string().into());
    l.us.send(report(1)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reached).await.unwrap().unwrap();
    let mut replacement = connect_from(&l.rig.app, &l.us_tok, &[], Some(US_A)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity)
                .is_some_and(|id| id != old_connection) { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("replacement was not bound");
    release.send(()).unwrap();
    assert!(!tokio::time::timeout(Duration::from_secs(5), finished).await.unwrap().unwrap());
    assert_eq!(roomler_ai_mod_network::org_relay::candidate_test_support::probe_rtts(net, us, hk), vec![Some(30)]);
    async fn barrier(ws: &mut Ws, nonce: &'static [u8]) {
        ws.send(Message::Ping(nonce.to_vec().into())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(frame) = ws.next().await {
                if matches!(frame, Ok(Message::Pong(ref payload)) if payload.as_ref() == nonce) { return; }
            }
            panic!("socket closed before ping barrier");
        }).await.expect("ping barrier timed out");
    }
    replacement.send(report(20)).await.unwrap();
    barrier(&mut replacement, b"new-probe-barrier").await;
    assert_eq!(roomler_ai_mod_network::org_relay::candidate_test_support::probe_rtts(net, us, hk), vec![Some(30), Some(20)]);
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

/// MeshHarbor #5 step B: of two lines a cross-border pair could ride, the
/// planner takes the one whose whole path is fastest, the line's own RTT
/// included. gz (mainland) has a line to hk and one to hk2. Measured: cn→gz
/// 5 ms; the gz→hk line 150 ms and gz→hk2 30 ms (gz's own reports, on the
/// private endpoints its netmap offered it); us→hk 10 ms, us→hk2 20 ms. By
/// the members alone hk wins (15 vs 25); by the path, hk2 does (55 vs 165).
#[tokio::test]
async fn a_cross_border_pair_rides_its_fastest_line() {
    const LINE2: &str = "10.42.2.115:3478";
    let mut l = LineRig::up("iso-fast", true).await;
    let (hk2_agent, hk2_tok) = enroll(&l.rig.app, &l.rig.seeded, "iso-fast-hk2").await;
    let mut hk2 = connect_from(&l.rig.app, &hk2_tok, &["relay-server"], Some("1.0.0.1")).await;
    assert_observed(&l.rig.app, &hk2_agent, Some("1.0.0.1")).await;
    line_join(&mut hk2, 6, "1.0.0.1:41641", json!({})).await;
    let (app, seeded) = (&l.rig.app, &l.rig.seeded);
    assert_eq!(approve(app, seeded, &hk2_agent, true).await, 200);
    let hk2_node = l.rig.node("iso-fast-hk2").await;
    grant_relay(app, seeded, &hk2_node).await;
    let path = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        seeded.tenant_id, l.gz_agent
    );
    let body = json!({ "serve": true, "approved_backbone_edges": [
        { "relay_agent_id": l.hk_agent, "endpoint": LINE, "cross_border": true },
        { "relay_agent_id": hk2_agent, "endpoint": LINE2, "cross_border": true },
    ]});
    let (status, v) = put(app, &path, &seeded.admin.access_token, body).await;
    assert_eq!(status, 200, "{v}");

    // gz is offered both lines to measure, at their private endpoints; the
    // members are offered no line at all.
    let gz_map = line_join(
        &mut l.gz,
        3,
        "223.6.6.6:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    let lines = gz_map["network"]["backbone_probe_targets"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let offered: BTreeSet<(String, String)> = lines
        .iter()
        .map(|t| {
            (
                t["relay_node_id"].as_str().unwrap().to_owned(),
                t["endpoints"][0].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        offered,
        BTreeSet::from([
            (l.hk_node.clone(), LINE.to_owned()),
            (hk2_node.clone(), LINE2.to_owned())
        ]),
        "{gz_map}"
    );
    let flag = json!({ "supports_backbone_only_v1": true });
    let cn_map = line_join(&mut l.cn, 1, "223.5.5.5:41641", flag.clone()).await;
    let us_map = line_join(&mut l.us, 2, "8.8.8.8:41641", flag).await;
    for m in [&cn_map, &us_map] {
        assert!(
            m["network"]["backbone_probe_targets"]
                .as_array()
                .is_none_or(|t| t.is_empty()),
            "{m}"
        );
    }

    let report = |relay: &str, endpoint: &Value, rtt: u32| {
        json!({ "t": "rc:overlay.relay_probe", "relay_node_id": relay,
            "endpoint": endpoint, "reachable": true, "rtt_ms": rtt })
        .to_string()
    };
    let offered_endpoint = |map: &Value, relay: &str| {
        map["network"]["relay_probe_targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["relay_node_id"] == json!(relay))
            .unwrap_or_else(|| panic!("{relay} offered: {map}"))["endpoints"][0]
            .clone()
    };
    for (relay, endpoint, rtt) in [(&l.hk_node, LINE, 150), (&hk2_node, LINE2, 30)] {
        l.gz.send(Message::Text(report(relay, &json!(endpoint), rtt).into()))
            .await
            .unwrap();
    }
    let gz_ep = offered_endpoint(&cn_map, &l.gz_node);
    l.cn.send(Message::Text(report(&l.gz_node, &gz_ep, 5).into()))
        .await
        .unwrap();
    for (relay, rtt) in [(&l.hk_node, 10), (&hk2_node, 20)] {
        let ep = offered_endpoint(&us_map, relay);
        l.us.send(Message::Text(report(relay, &ep, rtt).into()))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    relay_request(&mut l.cn, &l.us_node).await;
    let wait = Duration::from_secs(5);
    let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("gz bridges")["bridge"]
        .clone();
    assert_eq!(
        bridge["remote_endpoint"],
        json!(LINE2),
        "the faster line: {bridge}"
    );
    recv_t(&mut hk2, "rc:overlay.relay_serve", wait)
        .await
        .expect("hk2 serves");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("us session");
    assert_eq!(
        us["relay_node_id"],
        json!(hk2_node),
        "us binds the faster line's exit"
    );
    assert!(
        recv_t(
            &mut l.hk,
            "rc:overlay.relay_serve",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "the slower line's exit serves nothing"
    );
}

/// v039 GEO-03: a subnet route rides its router peer, so under `enforce` a
/// mainland router's approved LAN reaches a mainland client and never a
/// non-mainland one: no peer, no route, no `allowed_ips` for it. (An exit
/// node is the same peer carrying `0.0.0.0/0`.)
#[tokio::test]
async fn a_subnet_route_stays_in_its_routers_zone() {
    const LAN: &str = "10.77.0.0/24";
    let rig = Rig::up("iso-route", "enforce").await;
    let mut router = rig.device("iso-route-r", Some(CN_A)).await;
    let mut cn = rig.device("iso-route-cn", Some("223.5.5.6")).await;
    let mut us = rig.device("iso-route-us", Some(US_A)).await;
    line_join(
        &mut router,
        70,
        "223.5.5.5:41641",
        json!({ "advertised_routes": [LAN] }),
    )
    .await;
    let r_node = rig.node("iso-route-r").await;
    let (status, v) = put(
        &rig.app,
        &format!(
            "/api/tenant/{}/overlay-node/{r_node}/approved-routes",
            rig.seeded.tenant_id
        ),
        &rig.seeded.admin.access_token,
        json!({ "approved_routes": [LAN] }),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    let routes_of = |map: &Value| -> Vec<String> {
        map["peers"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|p| p["routes"].as_array().cloned().unwrap_or_default())
            .filter_map(|r| r.as_str().map(str::to_owned))
            .collect()
    };
    let cn_map = line_join(&mut cn, 71, "223.5.5.6:41641", json!({})).await;
    assert!(peer_ids(&cn_map).contains(&r_node), "{cn_map}");
    assert_eq!(
        routes_of(&cn_map),
        vec![LAN.to_owned()],
        "same zone: the LAN is routed"
    );
    let us_map = line_join(&mut us, 72, "8.8.8.8:41641", json!({})).await;
    assert!(!peer_ids(&us_map).contains(&r_node), "{us_map}");
    assert!(
        routes_of(&us_map).is_empty(),
        "other zone: no route at all: {us_map}"
    );
    assert!(
        !us_map.to_string().contains(LAN),
        "not even named: {us_map}"
    );
}

/// v039 GEO-03: a managed forward must not launder an origin. Ingress and
/// destination are both mainland, so "region" passes; but a non-mainland
/// node among its sources would reach the mainland destination behind the
/// ingress's address, so "source region" fails it under `enforce`, while a
/// mainland source passes.
#[tokio::test]
async fn a_forward_cannot_carry_a_source_across_zones() {
    use crate::managed_forward_tests::{post as mf_post, report_listener, spec, verdict};
    let rig = Rig::up("iso-fwd", "enforce").await;
    let (app, seeded) = (&rig.app, &rig.seeded);
    let (tid, tok) = (&seeded.tenant_id, &seeded.admin.access_token);
    let (a, a_tok) = enroll(app, seeded, "iso-fwd-a").await;
    let mut wa = connect_from(app, &a_tok, &["managed-forward"], Some(CN_A)).await;
    assert_observed(app, &a, Some(CN_A)).await;
    let mut wb = rig.device("iso-fwd-b", Some("223.5.5.6")).await;
    let mut wd = rig.device("iso-fwd-d", Some("223.5.5.7")).await;
    let mut wc = rig.device("iso-fwd-c", Some(US_A)).await;
    line_join(&mut wa, 80, "223.5.5.5:41641", json!({})).await;
    line_join(&mut wb, 81, "223.5.5.6:41641", json!({})).await;
    line_join(&mut wd, 82, "223.5.5.7:41641", json!({})).await;
    line_join(&mut wc, 83, "8.8.8.8:41641", json!({})).await;
    report_listener(app, &mut wa, tid, tok, &a, 22).await;
    let ip = |name: &'static str| {
        let app = &rig.app;
        let tid = ObjectId::parse_str(tid).unwrap();
        async move {
            app.state
                .network()
                .overlay_nodes
                .find_live_by_tenant_and_machine(tid, name)
                .await
                .unwrap()
                .unwrap()
                .overlay_ip
        }
    };
    let (ip_b, ip_c, ip_d) = (
        ip("iso-fwd-b").await,
        ip("iso-fwd-c").await,
        ip("iso-fwd-d").await,
    );
    let plan_path = format!("/api/tenant/{tid}/managed-forward/plan");
    let body = |source: &str| {
        let mut s = spec(&a, 15432);
        s["dest_addr"] = json!(ip_b);
        s["sources"] = json!([format!("{source}/32")]);
        s
    };

    let (_, plan) = mf_post(app, &plan_path, tok, &body(&ip_c)).await;
    assert_eq!(
        verdict(&plan, "region"),
        "pass",
        "ingress and destination share a zone: {plan}"
    );
    assert_eq!(verdict(&plan, "source region"), "fail", "{plan}");
    assert!(plan.to_string().contains(&ip_c), "names the source: {plan}");

    let (_, plan) = mf_post(app, &plan_path, tok, &body(&ip_d)).await;
    assert_eq!(verdict(&plan, "source region"), "pass", "{plan}");
}

/// v039 GEO-06: identical private prefixes in two zones stay distinct. Under
/// `enforce` a mainland and a non-mainland router may hold the same approved
/// LAN, each client seeing only its own zone's. The approval binds to the
/// router's zone, so a router that roams into the other zone keeps its peer
/// entry there but offers none of its routes: it cannot claim that zone's
/// site of the same CIDR.
#[tokio::test]
async fn identical_private_prefixes_in_two_zones_stay_distinct() {
    use std::collections::BTreeMap;
    const LAN: &str = "10.78.0.0/24";
    let rig = Rig::up("iso-geo6", "enforce").await;
    let tid = rig.seeded.tenant_id.clone();
    let (cn_agent, cn_tok) = enroll(&rig.app, &rig.seeded, "iso-geo6-cn").await;
    let mut cn_r = connect_from(&rig.app, &cn_tok, &[], Some(CN_A)).await;
    assert_observed(&rig.app, &cn_agent, Some(CN_A)).await;
    let mut us_r = rig.device("iso-geo6-us", Some(US_A)).await;
    let lan = json!({ "advertised_routes": [LAN] });
    line_join(&mut cn_r, 100, "223.5.5.5:41641", lan.clone()).await;
    line_join(&mut us_r, 101, "8.8.8.8:41641", lan.clone()).await;
    let cn_node = rig.node("iso-geo6-cn").await;
    let us_node = rig.node("iso-geo6-us").await;
    for node in [&cn_node, &us_node] {
        let (status, v) = put(
            &rig.app,
            &format!("/api/tenant/{tid}/overlay-node/{node}/approved-routes"),
            &rig.seeded.admin.access_token,
            json!({ "approved_routes": [LAN] }),
        )
        .await;
        assert_eq!(status, 200, "one CIDR per zone: {v}");
    }
    let routes_by = |map: &Value| -> BTreeMap<String, Vec<String>> {
        map["peers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| {
                let routes: Vec<String> = p["routes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|r| r.as_str().map(str::to_owned))
                    .collect();
                (!routes.is_empty()).then(|| (p["node_id"].as_str().unwrap().to_owned(), routes))
            })
            .collect()
    };
    let only = |node: &str| BTreeMap::from([(node.to_owned(), vec![LAN.to_owned()])]);
    let mut cn_c = rig.device("iso-geo6-cnc", Some("223.5.5.6")).await;
    let cn_map = line_join(&mut cn_c, 102, "223.5.5.6:41641", json!({})).await;
    assert_eq!(routes_by(&cn_map), only(&cn_node), "{cn_map}");
    let mut us_c = rig.device("iso-geo6-usc", Some(US_B)).await;
    let us_map = line_join(&mut us_c, 103, "8.8.4.4:41641", json!({})).await;
    assert_eq!(routes_by(&us_map), only(&us_node), "{us_map}");

    // The mainland router roams: it reconnects from a non-mainland address.
    drop(cn_r);
    let mut cn_r = connect_from(&rig.app, &cn_tok, &[], Some("8.8.8.9")).await;
    assert_observed(&rig.app, &cn_agent, Some("8.8.8.9")).await;
    line_join(&mut cn_r, 100, "8.8.8.9:41641", lan).await;
    let mut us_c2 = rig.device("iso-geo6-usc2", Some("8.8.4.5")).await;
    let us_map = line_join(&mut us_c2, 104, "8.8.4.5:41641", json!({})).await;
    assert!(
        peer_ids(&us_map).contains(&cn_node),
        "a same-zone peer now: {us_map}"
    );
    assert_eq!(
        routes_by(&us_map),
        only(&us_node),
        "outside its bound zone it offers no route: {us_map}"
    );
}

#[tokio::test]
async fn staged_graph_tunnel_displaced_probe_is_rejected() {
    let rig = Rig::up("iso-tunnel-probe-owner", "enforce").await;
    let et: Value = rig.app.auth_post(
        &format!("/api/tenant/{}/tunnel-client/enroll-token", rig.seeded.tenant_id),
        &rig.seeded.admin.access_token,
    ).send().await.unwrap().json().await.unwrap();
    let enrolled: Value = rig.app.client.post(rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({"enrollment_token":et["enrollment_token"], "machine_id":"mach-tunnel-probe-owner",
            "machine_name":"tunnel-probe-owner", "os":"linux", "client_version":"0.3.0-test"}))
        .send().await.unwrap().json().await.unwrap();
    let identity = ObjectId::parse_str(enrolled["tunnel_client_id"].as_str().unwrap()).unwrap();
    let token = enrolled["tunnel_client_token"].as_str().unwrap();
    let url = format!("ws://{}/ws?token={}&role=tunnel-client", rig.app.addr,
        token.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"));
    let (mut old, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    line_join(&mut old, 31, "223.6.6.6:41641", json!({})).await;
    let net = rig.app.state.network();
    let node = roomler_ai_mod_network::overlay::current_node(net,
        roomler_ai_mod_network::overlay::NodeIdentity::TunnelClient(identity)).await.unwrap().id.unwrap();
    let relay = ObjectId::new();
    let endpoint = "1.1.1.1:3478";
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
        net, node, &[(relay, endpoint.into(), true, Some(30))]));
    let old_conn = roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).unwrap();
    let (reached, release, finished) = roomler_ai_mod_network::org_relay::candidate_test_support::pause_next_probe(identity);
    let report = |rtt| Message::Text(json!({"t":"rc:overlay.relay_probe", "relay_node_id":relay.to_hex(),
        "endpoint":endpoint, "reachable":true, "rtt_ms":rtt}).to_string().into());
    old.send(report(1)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reached).await.unwrap().unwrap();
    let (mut replacement, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    line_join(&mut replacement, 31, "223.6.6.6:41641", json!({})).await;
    assert_ne!(roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).unwrap(), old_conn);
    // Re-offer the same endpoint before the old report resumes, so offer
    // withdrawal cannot accidentally hide a missing ownership check.
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
        net, node, &[(relay, endpoint.into(), true, Some(30))]));
    release.send(()).unwrap();
    assert!(!tokio::time::timeout(Duration::from_secs(5), finished).await.unwrap().unwrap());
    assert_eq!(roomler_ai_mod_network::org_relay::candidate_test_support::probe_rtts(net, node, relay), vec![Some(30), Some(30)]);
    replacement.send(report(20)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let rtts = roomler_ai_mod_network::org_relay::candidate_test_support::probe_rtts(net, node, relay);
            if rtts == vec![Some(30), Some(30), Some(20)] { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("current tunnel report must be accepted");
}

/// A displaced client cannot leave or tear down its replacement's live path.
#[tokio::test]
async fn staged_graph_tunnel_old_close_preserves_replacement_session() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut l = LineRig::up("iso-tunnel-revoke", true).await;
    let et: Value = l.rig.app.auth_post(
        &format!("/api/tenant/{}/tunnel-client/enroll-token", l.rig.seeded.tenant_id),
        &l.rig.seeded.admin.access_token,
    ).send().await.unwrap().json().await.unwrap();
    let enrolled: Value = l.rig.app.client.post(l.rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({"enrollment_token":et["enrollment_token"], "machine_id":"mach-tunnel-revoke",
            "machine_name":"tunnel-revoke", "os":"linux", "client_version":"0.3.0-test"}))
        .send().await.unwrap().json().await.unwrap();
    let identity = ObjectId::parse_str(enrolled["tunnel_client_id"].as_str().unwrap()).unwrap();
    let token = enrolled["tunnel_client_token"].as_str().unwrap();
    let url = format!("ws://{}/ws?token={}&role=tunnel-client", l.rig.app.addr,
        token.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"));
    let request = || {
        let mut req = url.as_str().into_client_request().unwrap();
        req.headers_mut().insert("x-forwarded-for", US_A.parse().unwrap());
        req
    };
    let (mut old, _) = tokio_tungstenite::connect_async(request()).await.unwrap();
    line_join(&mut old, 31, "8.8.8.9:41641", json!({ "supports_backbone_only_v1": true })).await;
    let old_conn = roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(l.rig.app.state.network(), identity).unwrap();
    let cleanup = roomler_ai_mod_network::org_relay::candidate_test_support::observe_tunnel_cleanup(&old_conn);
    let (mut replacement, _) = tokio_tungstenite::connect_async(request()).await.unwrap();
    line_join(&mut replacement, 31, "8.8.8.9:41641", json!({ "supports_backbone_only_v1": true })).await;
    let net = l.rig.app.state.network();
    let ident = roomler_ai_mod_network::overlay::NodeIdentity::TunnelClient(identity);
    let tunnel_node = roomler_ai_mod_network::overlay::current_node(net, ident).await.unwrap().id.unwrap();
    let cn_node = ObjectId::parse_str(&l.cn_node).unwrap();
    let key = roomler_ai_mod_network::overlay::pair_key(cn_node, tunnel_node);
    let current = roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).unwrap();
    relay_request(&mut l.cn, &tunnel_node.to_hex()).await;
    let wait = Duration::from_secs(5);
    let gz = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("GZ serves line");
    let hk = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("HK serves line");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("CN session");
    let tc = recv_t(&mut replacement, "rc:overlay.relay_session", wait).await.expect("tunnel session");
    assert_eq!(gz["vni"], cn["vni"]);
    assert_eq!(hk["vni"], tc["vni"]);
    assert!(net.org_relay.active_session(&key).is_some());
    // Old socket stays open: even an explicit leave from it must not remove
    // the new client's node or revoke the established cross-zone line.
    old.send(Message::Text(json!({"t":"rc:overlay.leave"}).to_string().into())).await.unwrap();
    old.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(wait, cleanup).await.expect("old cleanup did not finish").unwrap();
    assert!(net.overlay_nodes_by_id.contains_key(&identity));
    assert_eq!(roomler_ai_mod_network::overlay::current_node(net, ident).await.unwrap().status,
        roomler_ai_remote_control::models::AgentStatus::Online);
    assert!(net.org_relay.active_session(&key).is_some());
    assert!(recv_t(&mut l.cn, "rc:overlay.relay_revoke", Duration::from_millis(600)).await.is_none());
    assert_eq!(roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity), Some(current));
}

/// A new bind waits for the old connection's async overlay cleanup, then the
/// new join wins after the old leave completes.
#[tokio::test]
async fn staged_graph_tunnel_bind_waits_for_old_async_leave() {
    let rig = Rig::up("iso-tunnel-leave-race", "enforce").await;
    let et: Value = rig.app.auth_post(
        &format!("/api/tenant/{}/tunnel-client/enroll-token", rig.seeded.tenant_id),
        &rig.seeded.admin.access_token,
    ).send().await.unwrap().json().await.unwrap();
    let enrolled: Value = rig.app.client.post(rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({"enrollment_token":et["enrollment_token"], "machine_id":"mach-tunnel-leave-race",
            "machine_name":"tunnel-leave-race", "os":"linux", "client_version":"0.3.0-test"}))
        .send().await.unwrap().json().await.unwrap();
    let identity = ObjectId::parse_str(enrolled["tunnel_client_id"].as_str().unwrap()).unwrap();
    let token = enrolled["tunnel_client_token"].as_str().unwrap();
    let url = format!("ws://{}/ws?token={}&role=tunnel-client", rig.app.addr,
        token.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"));
    let (mut old, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    line_join(&mut old, 31, "223.6.6.6:41641", json!({})).await;
    let net = rig.app.state.network();
    let old_id = roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).unwrap();
    let (reached, resume) = roomler_ai_mod_network::org_relay::candidate_test_support::pause_tunnel_leave(&old_id);
    old.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reached).await.unwrap().unwrap();
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).is_none());
    let bind_attempt = roomler_ai_mod_network::org_relay::candidate_test_support::observe_tunnel_bind_attempt(identity);
    let mut bound = roomler_ai_mod_network::org_relay::candidate_test_support::observe_tunnel_bound(identity);
    let (mut replacement, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), bind_attempt).await.unwrap().unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(300), &mut bound).await.is_err(), "new bind must wait for old async leave");
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).is_none());
    resume.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), bound).await.unwrap().unwrap();
    line_join(&mut replacement, 31, "223.6.6.6:41641", json!({})).await;
    assert!(net.overlay_nodes_by_id.contains_key(&identity));
    let new_id = roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).unwrap();
    assert_ne!(new_id, old_id);
    let node = roomler_ai_mod_network::overlay::current_node(net,
        roomler_ai_mod_network::overlay::NodeIdentity::TunnelClient(identity)).await.unwrap();
    assert_eq!(node.status, roomler_ai_remote_control::models::AgentStatus::Online);
    // Closing the current owner must still perform ordinary cleanup.
    let current_cleanup = roomler_ai_mod_network::org_relay::candidate_test_support::observe_tunnel_cleanup(&new_id);
    replacement.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), current_cleanup).await.unwrap().unwrap();
    assert!(!net.overlay_nodes_by_id.contains_key(&identity));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::current_connection_id(net, identity).is_none());
    let offline = roomler_ai_mod_network::overlay::current_node(net,
        roomler_ai_mod_network::overlay::NodeIdentity::TunnelClient(identity)).await.unwrap();
    assert_eq!(offline.status, roomler_ai_remote_control::models::AgentStatus::Offline);
}

/// Staged N-hop planning must preserve the current authorized single-relay
/// behavior when isolation only logs or is off and zones are unknown.
async fn staged_graph_unknown_zone_parity(mode: &'static str, slug: &str) {
    let rig = Rig::up(slug, mode).await;
    let (relay_id, token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-relay")).await;
    let mut relay = connect_from(&rig.app, &token, &["relay-server"], None).await;
    let mut a = rig.device(&format!("{slug}-a"), None).await;
    let mut b = rig.device(&format!("{slug}-b"), None).await;
    line_join(&mut relay, 31, "1.1.1.1:41641", json!({})).await;
    line_join(&mut a, 32, "8.8.8.8:41641", json!({})).await;
    line_join(&mut b, 33, "8.8.4.4:41641", json!({})).await;
    set_mode(&rig.app, &rig.seeded, "on").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &relay_id, true).await, 200);
    let relay_node = rig.node(&format!("{slug}-relay")).await;
    grant_relay(&rig.app, &rig.seeded, &relay_node).await;
    let a_node = rig.node(&format!("{slug}-a")).await;
    let b_node = rig.node(&format!("{slug}-b")).await;
    relay_request(&mut a, &b_node).await;
    let wait = Duration::from_secs(5);
    if mode == "enforce" {
        assert!(recv_t(&mut relay, "rc:overlay.relay_serve", Duration::from_millis(600)).await.is_none());
        let a_id = ObjectId::parse_str(&a_node).unwrap();
        let b_id = ObjectId::parse_str(&b_node).unwrap();
        let result = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(
            rig.app.state.network(), a_id, b_id, false).await;
        assert!(matches!(result, Err(roomler_ai_remote_control::models::PeerRelayDenyReason::ZoneDenied)));
        return;
    }
    recv_t(&mut relay, "rc:overlay.relay_serve", wait).await.expect("existing relay gate should authorize");
    recv_t(&mut a, "rc:overlay.relay_session", wait).await.expect("member a has session");
    recv_t(&mut b, "rc:overlay.relay_session", wait).await.expect("member b has session");
    let a_id = ObjectId::parse_str(&a_node).unwrap();
    let b_id = ObjectId::parse_str(&b_node).unwrap();
    let relay_agent_id = ObjectId::parse_str(&relay_id).unwrap();
    let path = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(
        rig.app.state.network(), a_id, b_id, false).await.expect("staged gate should honor same isolation mode").expect("a relay path exists");
    assert_eq!(path.0, vec![relay_agent_id]);
}

#[tokio::test]
async fn staged_graph_unknown_zone_parity_off() { staged_graph_unknown_zone_parity("off", "iso-zone-none-off").await; }

#[tokio::test]
async fn staged_graph_unknown_zone_parity_warn() { staged_graph_unknown_zone_parity("warn", "iso-zone-none-warn").await; }

#[tokio::test]
async fn staged_graph_unknown_zone_parity_enforce() { staged_graph_unknown_zone_parity("enforce", "iso-zone-none-enforce").await; }

/// Enforced isolation already permits a linked server pair when at least one
/// server has zone evidence; a relay in that known zone can serve both.
#[tokio::test]
async fn staged_graph_unknown_zone_parity_linked_servers_enforce() {
    let rig = Rig::up("iso-linked-zone-unknown", "enforce").await;
    let (r_id, r_token) = enroll(&rig.app, &rig.seeded, "iso-linked-zone-relay").await;
    let (a_id, a_token) = enroll(&rig.app, &rig.seeded, "iso-linked-zone-a").await;
    let (b_id, b_token) = enroll(&rig.app, &rig.seeded, "iso-linked-zone-b").await;
    let mut relay = connect_from(&rig.app, &r_token, &["relay-server"], Some(CN_R)).await;
    let mut a = connect_from(&rig.app, &a_token, &[], Some(CN_A)).await;
    let mut b = connect_from(&rig.app, &b_token, &[], None).await;
    assert_observed(&rig.app, &r_id, Some(CN_R)).await;
    assert_observed(&rig.app, &a_id, Some(CN_A)).await;
    assert_observed(&rig.app, &b_id, None).await;
    rig.set_role(&a_id, "server").await;
    rig.set_role(&b_id, "server").await;
    rig.link(&a_id, &b_id, true).await;
    line_join(&mut relay, 31, "223.6.6.6:41641", json!({})).await;
    line_join(&mut a, 32, "223.5.5.5:41641", json!({})).await;
    line_join(&mut b, 33, "223.5.5.6:41641", json!({})).await;
    set_mode(&rig.app, &rig.seeded, "on").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &r_id, true).await, 200);
    let relay_node = rig.node("iso-linked-zone-relay").await;
    grant_relay(&rig.app, &rig.seeded, &relay_node).await;
    let a_node = rig.node("iso-linked-zone-a").await;
    let b_node = rig.node("iso-linked-zone-b").await;
    relay_request(&mut a, &b_node).await;
    let wait = Duration::from_secs(5);
    recv_t(&mut relay, "rc:overlay.relay_serve", wait).await.expect("existing linked-server gate should authorize");
    recv_t(&mut a, "rc:overlay.relay_session", wait).await.expect("server a session");
    recv_t(&mut b, "rc:overlay.relay_session", wait).await.expect("server b session");
    let selected = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(
        rig.app.state.network(), ObjectId::parse_str(&a_node).unwrap(), ObjectId::parse_str(&b_node).unwrap(), false,
    ).await.expect("staged gate should honor linked-server topology").expect("a relay path exists");
    assert_eq!(selected.0, vec![ObjectId::parse_str(&r_id).unwrap()]);
}

async fn staged_graph_unknown_backbone(mode: &'static str, slug: &str) {
    let rig = Rig::up(slug, mode).await;
    let (r1_id, r1_token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-r1")).await;
    let (r2_id, r2_token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-r2")).await;
    let mut r1 = connect_from(&rig.app, &r1_token, &["relay-server"], None).await;
    let mut r2 = connect_from(&rig.app, &r2_token, &["relay-server"], None).await;
    let mut a = rig.device(&format!("{slug}-a"), None).await;
    let mut b = rig.device(&format!("{slug}-b"), None).await;
    line_join(&mut r1, 41, "1.1.1.1:41641", json!({ "relay_backbone_ready": true })).await;
    line_join(&mut r2, 42, "1.0.0.1:41641", json!({ "relay_backbone_ready": true })).await;
    line_join(&mut a, 43, "8.8.8.8:41641", json!({})).await;
    line_join(&mut b, 44, "8.8.4.4:41641", json!({})).await;
    set_mode(&rig.app, &rig.seeded, "on").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &r1_id, true).await, 200);
    assert_eq!(approve(&rig.app, &rig.seeded, &r2_id, true).await, 200);
    let r1_node = rig.node(&format!("{slug}-r1")).await;
    let r2_node = rig.node(&format!("{slug}-r2")).await;
    grant_relay(&rig.app, &rig.seeded, &r1_node).await;
    grant_relay(&rig.app, &rig.seeded, &r2_node).await;
    let a_node = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
    let b_node = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
    let source = ObjectId::parse_str(&r1_id).unwrap();
    let target = ObjectId::parse_str(&r2_id).unwrap();
    let r1_node = ObjectId::parse_str(r1_node).unwrap();
    let r2_node = ObjectId::parse_str(r2_node).unwrap();
    let policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", rig.seeded.tenant_id, r1_id);
    let net = rig.app.state.network();
    for cross in [false, true] {
        let (status, response) = put(&rig.app, &policy, &rig.seeded.admin.access_token, json!({
            "serve": true, "approved_backbone_edges": [{"relay_agent_id":r2_id,
                "endpoint":"10.42.2.113:3478", "cross_border":cross}]
        })).await;
        assert_eq!(status, 200, "{response}");
        let edges = roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(
            rig.app.state.network(), a_node, b_node, false).await.unwrap();
        assert!(edges.iter().any(|(a,b,_,flag)| *a==source && *b==target && *flag == cross),
            "Off/Warn keep an approved edge and preserve its original cross-border bit");
        assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(net, a_node, &[
            (r1_node, "1.1.1.1:3478".into(), true, Some(10)),
            (r2_node, "1.0.0.1:3478".into(), false, None),
        ]));
        assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(net, b_node, &[
            (r1_node, "1.1.1.1:3478".into(), false, None),
            (r2_node, "1.0.0.1:3478".into(), true, Some(10)),
        ]));
        let selected = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(net, a_node, b_node, false)
            .await.unwrap().expect("approved two-relay path exists");
        assert_eq!(selected, (vec![source, target], false));
    }
}

#[tokio::test]
async fn staged_graph_unknown_zone_parity_backbone_off() { staged_graph_unknown_backbone("off", "iso-zone-backbone-off").await; }
#[tokio::test]
async fn staged_graph_unknown_zone_parity_backbone_warn() { staged_graph_unknown_backbone("warn", "iso-zone-backbone-warn").await; }

/// Even topology-linked servers in different known zones need a cross-border line.
#[tokio::test]
async fn staged_graph_unknown_zone_parity_linked_servers_known_cross_zone() {
    let rig = Rig::up("iso-linked-cross-unknown", "enforce").await;
    let (r_id, r_token) = enroll(&rig.app, &rig.seeded, "iso-linked-cross-relay").await;
    let (a_id, a_token) = enroll(&rig.app, &rig.seeded, "iso-linked-cross-a").await;
    let (b_id, b_token) = enroll(&rig.app, &rig.seeded, "iso-linked-cross-b").await;
    let mut relay = connect_from(&rig.app, &r_token, &["relay-server"], Some(CN_R)).await;
    let mut a = connect_from(&rig.app, &a_token, &[], Some(CN_A)).await;
    let mut b = connect_from(&rig.app, &b_token, &[], Some(US_A)).await;
    assert_observed(&rig.app, &r_id, Some(CN_R)).await;
    assert_observed(&rig.app, &a_id, Some(CN_A)).await;
    assert_observed(&rig.app, &b_id, Some(US_A)).await;
    rig.set_role(&a_id, "server").await;
    rig.set_role(&b_id, "server").await;
    rig.link(&a_id, &b_id, true).await;
    line_join(&mut relay, 31, "223.6.6.6:41641", json!({})).await;
    line_join(&mut a, 32, "223.5.5.5:41641", json!({})).await;
    line_join(&mut b, 33, "8.8.8.8:41641", json!({})).await;
    set_mode(&rig.app, &rig.seeded, "on").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &r_id, true).await, 200);
    let relay_node = rig.node("iso-linked-cross-relay").await;
    grant_relay(&rig.app, &rig.seeded, &relay_node).await;
    let a_node = rig.node("iso-linked-cross-a").await;
    let b_node = rig.node("iso-linked-cross-b").await;
    relay_request(&mut a, &b_node).await;
    let wait = Duration::from_secs(5);
    assert!(recv_t(&mut relay, "rc:overlay.relay_serve", wait).await.is_none(), "no cross-border line may be minted");
    let selected = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(
        rig.app.state.network(), ObjectId::parse_str(&a_node).unwrap(), ObjectId::parse_str(&b_node).unwrap(), false,
    ).await;
    assert!(matches!(selected, Err(roomler_ai_remote_control::models::PeerRelayDenyReason::ZoneDenied)));

}

/// Two server-role members without their topology link must not obtain a
/// staged cross-zone path even if a relay-to-relay edge itself is approved.
#[tokio::test]
async fn staged_graph_unknown_zone_parity_unlinked_servers_fail_closed() {
    let l = LineRig::up("iso-zone-unlinked-servers", true).await;
    let net = l.rig.app.state.network();
    let cn = ObjectId::parse_str(&l.cn_node).unwrap();
    let us = ObjectId::parse_str(&l.us_node).unwrap();
    let agent_id = |node: &roomler_ai_remote_control::models::OverlayNode| match node.node_ref {
        roomler_ai_remote_control::models::NodeRef::Agent { agent_id } => agent_id.to_hex(),
        _ => panic!("fixture member must be an agent"),
    };
    let cn_agent = agent_id(&net.overlay_nodes.base.find_by_id(cn).await.unwrap());
    let us_agent = agent_id(&net.overlay_nodes.base.find_by_id(us).await.unwrap());
    l.rig.set_role(&cn_agent, "server").await;
    l.rig.set_role(&us_agent, "server").await;
    l.rig.link(&cn_agent, &us_agent, false).await;
    let result = roomler_ai_mod_network::org_relay::candidate_test_support::prepare_edges(net, cn, us, false).await;
    assert!(matches!(result, Err(roomler_ai_remote_control::models::PeerRelayDenyReason::ZoneDenied)));
}

/// The server's real edge-withdrawal entry point must retain an approved
/// ordinary edge, but revoke the full path when a required crossing loses its
/// approval or when an ordinary edge disappears. The fixture inserts state
/// only; it does not grant a live path or prove remote revoke delivery.
#[tokio::test]
async fn staged_graph_mixed_edge_approval_revokes_only_when_the_edge_requires_it() {
    use roomler_ai_mod_network::org_relay::{
        LineLeg, OrgRelaySession, SessionMember, SessionParty,
        candidate_test_support::insert_session_fixture, revoke_removed_backbone_edges_sync,
    };
    use roomler_ai_remote_control::models::{NodeRef, PeerRelayBackboneEdge};
    use std::time::Instant;
    let app = TestApp::spawn().await;
    let state = app.state.network();
    let tenant = ObjectId::new();
    let agents = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
    let party = |id| SessionParty { node_id: ObjectId::new(), node_ref: NodeRef::Agent { agent_id: id } };
    let member = |id| SessionMember { party: party(id), wg_public_key: "fixture".into(), bind_secret: "fixture".into() };
    let line = |index, required, endpoint: &str| LineLeg {
        relay: party(agents[index]), relay_agent_id: agents[index], vni: index as u32 + 10,
        generation: index as u64 + 20, endpoints: vec!["relay".into()],
        private_endpoint: endpoint.into(), requires_cross_border_approval: required,
        bridge_id: ObjectId::new(), bridge_secrets: ["a".into(), "b".into()],
    };
    let session = OrgRelaySession {
        tenant_id: tenant, pair_key: "mixed-fixture".into(), vni: 9, generation: 19,
        relay: party(agents[0]), relay_agent_id: agents[0], implicit: false,
        members: [member(ObjectId::new()), member(ObjectId::new())], endpoints: vec!["relay".into()],
        expires_at: Instant::now() + Duration::from_secs(60), bind_by: Instant::now() + Duration::from_secs(30),
        hops: vec![line(1, false, "10.0.0.2:3478"), line(2, true, "10.0.0.3:3478")],
    };
    let edge = |target: ObjectId, endpoint: &str, cross_border| PeerRelayBackboneEdge {
        relay_agent_id: target.to_hex(), endpoint: endpoint.into(), cross_border,
    };
    assert!(insert_session_fixture(state, session.clone()));
    assert!(revoke_removed_backbone_edges_sync(state, tenant, agents[0], &[edge(agents[1], "10.0.0.2:3478", false)]).is_empty());
    assert!(state.org_relay.active_session("mixed-fixture").is_some());
    assert!(revoke_removed_backbone_edges_sync(state, tenant, agents[1], &[edge(agents[2], "10.0.0.3:3478", true)]).is_empty());
    assert_eq!(revoke_removed_backbone_edges_sync(state, tenant, agents[1], &[edge(agents[2], "10.0.0.3:3478", false)]).len(), 1);
    assert!(state.org_relay.active_session("mixed-fixture").is_none());
    let mut another = session;
    another.pair_key = "ordinary-edge-removed".into();
    assert!(insert_session_fixture(state, another));
    assert!(revoke_removed_backbone_edges_sync(state, ObjectId::new(), agents[0], &[]).is_empty());
    assert_eq!(revoke_removed_backbone_edges_sync(state, tenant, agents[0], &[]).len(), 1);
    assert!(state.org_relay.active_session("ordinary-edge-removed").is_none());
}

/// The real zone recheck sees three live relay identities. The inserted
/// three-relay records are fixtures, not grants to those relay processes.
#[tokio::test]
async fn staged_graph_three_relay_zone_recheck_preserves_valid_and_revokes_changed_edges() {
    use roomler_ai_mod_network::org_relay::{
        LineLeg, SessionParty,
        candidate_test_support::{insert_session_fixture, line_zones_fit_fixture, recheck_zones_fixture},
    };
    use roomler_ai_remote_control::models::NodeRef;
    let mut l = LineRig::up("iso-three-relay-zone", true).await;
    let (extra_agent, extra_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-three-relay-zone-extra").await;
    let mut extra = connect_from(&l.rig.app, &extra_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &extra_agent, Some(CN_R)).await;
    line_join(&mut extra, 5, "223.6.6.7:41641", json!({ "relay_backbone_ready": true })).await;
    let extra_node = l.rig.node("iso-three-relay-zone-extra").await;
    relay_request(&mut l.cn, &l.us_node).await;
    let _ = l.expect_line().await;
    let state = l.rig.app.state.network();
    let pair = roomler_ai_mod_network::overlay::pair_key(
        ObjectId::parse_str(&l.cn_node).unwrap(), ObjectId::parse_str(&l.us_node).unwrap());
    let original = state.org_relay.active_session(&pair).unwrap();
    assert!(line_zones_fit_fixture(state, &original).await, "the original approved crossing remains valid");
    let extra_id = ObjectId::parse_str(&extra_agent).unwrap();
    let mut valid = original.clone();
    valid.pair_key = "three-zone-valid".into();
    valid.hops.insert(0, LineLeg {
        relay: SessionParty { node_id: ObjectId::parse_str(&extra_node).unwrap(), node_ref: NodeRef::Agent { agent_id: extra_id } },
        relay_agent_id: extra_id, vni: 100, generation: 101, endpoints: vec!["relay".into()],
        private_endpoint: "10.1.2.3:3478".into(), requires_cross_border_approval: false,
        bridge_id: ObjectId::new(), bridge_secrets: ["a".into(), "b".into()],
    });
    assert!(line_zones_fit_fixture(state, &valid).await, "same-zone edge then approved crossing");
    let mut ordinary_changed = valid.clone();
    ordinary_changed.pair_key = "three-zone-ordinary-changed".into();
    ordinary_changed.hops[0].requires_cross_border_approval = true;
    let mut crossing_changed = valid.clone();
    crossing_changed.pair_key = "three-zone-crossing-changed".into();
    crossing_changed.hops[1].requires_cross_border_approval = false;
    let mut unknown = valid.clone();
    unknown.pair_key = "three-zone-unknown".into();
    unknown.hops[1].relay.node_ref = NodeRef::Agent { agent_id: ObjectId::new() };
    assert!(!line_zones_fit_fixture(state, &ordinary_changed).await);
    assert!(!line_zones_fit_fixture(state, &crossing_changed).await);
    assert!(!line_zones_fit_fixture(state, &unknown).await);
    for session in [valid, ordinary_changed, crossing_changed, unknown] {
        assert!(insert_session_fixture(state, session));
    }
    recheck_zones_fixture(state, extra_id).await;
    assert!(state.org_relay.active_session("three-zone-valid").is_some());
    for key in ["three-zone-ordinary-changed", "three-zone-crossing-changed", "three-zone-unknown"] {
        assert!(state.org_relay.active_session(key).is_none(), "{key} must be revoked");
    }
}

/// Drive the real cross-zone request handler through a three-relay chain with
/// one same-zone edge and one approved crossing. This checks control messages,
/// per-crossing audit, actual WireGuard data, and policy withdrawal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_actual_three_relay_mint_audits_and_revokes_each_edge() {
    use roomler_ai_remote_control::signaling::ServerMsg;
    use roomlerd::relay_server::backbone_test_support::{BindSecret, Carrier, NativeRelay, OrgRelayConn, WgDevice, WgKeypair, bind_member};
    use std::{net::Ipv4Addr, sync::{Arc, atomic::AtomicBool}};
    let source_native = NativeRelay::start().await.unwrap();
    let middle_native = NativeRelay::start().await.unwrap();
    let exit_native = NativeRelay::start().await.unwrap();
    let key_a = WgKeypair::generate();
    let key_b = WgKeypair::generate();
    let mut l = LineRig::up("iso-actual-three", true).await;
    let (middle_agent, middle_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-actual-three-middle").await;
    let mut middle = connect_from(&l.rig.app, &middle_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &middle_agent, Some(CN_R)).await;
    line_join(&mut middle, 5, "223.6.6.7:41641", json!({ "relay_backbone_ready": true })).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &middle_agent, true).await, 200);
    let middle_node = l.rig.node("iso-actual-three-middle").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &middle_node).await;
    for (ws, key, endpoint) in [(&mut l.cn, key_a.public_base64(), "223.5.5.5:41641"), (&mut l.us, key_b.public_base64(), "8.8.8.8:41641")] {
        ws.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":key, "mtu":1280,
            "endpoints":[endpoint], "supports_org_relay":true, "supports_backbone_only_v1":true,
            "supports_server_relay_strategy":true, "org_primary":true}).to_string().into())).await.unwrap();
        recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5)).await.expect("member rejoin");
    }
    let policy_path = |agent: &str| format!("/api/tenant/{}/agent/{agent}/peer-relay-policy", l.rig.seeded.tenant_id);
    let gz_policy = policy_path(&l.gz_agent);
    let middle_policy = policy_path(&middle_agent);
    let policy = |target: &str, endpoint: &str, cross_border| json!({ "serve": true, "approved_backbone_edges": [
        { "relay_agent_id": target, "endpoint": endpoint, "cross_border": cross_border },
    ]});
    let admin = &l.rig.seeded.admin.access_token;
    let middle_endpoint = middle_native.underlay_endpoint().to_string();
    let exit_endpoint = exit_native.underlay_endpoint().to_string();
    let (status, body) = put(&l.rig.app, &gz_policy, admin, policy(&middle_agent, &middle_endpoint, false)).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, false)).await;
    assert_eq!(status, 200, "{body}");
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(700)).await.is_none(), "crossing without approval must not mint");
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, true)).await;
    assert_eq!(status, 200, "{body}");
    let network = l.rig.app.state.network();
    let a = ObjectId::parse_str(&l.cn_node).unwrap();
    let b = ObjectId::parse_str(&l.us_node).unwrap();
    let gz_node = ObjectId::parse_str(&l.gz_node).unwrap();
    let mid_node = ObjectId::parse_str(&middle_node).unwrap();
    let hk_node = ObjectId::parse_str(&l.hk_node).unwrap();
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, a, &[
        (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
        (mid_node, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, b, &[
        (hk_node, "1.1.1.1:3478".into(), true, Some(10)),
    ]));
    let selected = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(network, a, b, false).await.unwrap().unwrap();
    assert_eq!(selected, (vec![ObjectId::parse_str(&l.gz_agent).unwrap(), ObjectId::parse_str(&middle_agent).unwrap(), ObjectId::parse_str(&l.hk_agent).unwrap()], false));
    relay_request(&mut l.cn, &l.us_node).await;
    let wait = Duration::from_secs(8);
    let gz = match recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await {
        Some(msg) => msg,
        None => panic!("ingress serve absent; audits={:?}", l.audit_reasons("mint").await),
    };
    let first_bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("first bridge");
    let mid = recv_t(&mut middle, "rc:overlay.relay_serve", wait).await.expect("middle serve");
    let second_bridge = recv_t(&mut middle, "rc:overlay.relay_bridge_serve", wait).await.expect("second bridge");
    let hk = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("exit serve");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("requester session");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("peer session");
    assert_eq!(cn["vni"], gz["vni"]);
    assert_eq!(us["vni"], hk["vni"]);
    assert_eq!(cn["relay_node_id"], json!(l.gz_node));
    assert_eq!(us["relay_node_id"], json!(l.hk_node));
    assert_eq!(first_bridge["bridge"]["local_vni"], gz["vni"]);
    assert_eq!(first_bridge["bridge"]["remote_vni"], mid["vni"]);
    assert_eq!(second_bridge["bridge"]["local_vni"], mid["vni"]);
    assert_eq!(second_bridge["bridge"]["remote_vni"], hk["vni"]);
    let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
    let live = network.org_relay.active_session(&pair).expect("real multi-hop session");
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    assert!(support::reauthorize_nhop_fixture(network, a, b, &live).await);
    let mut bad_endpoint = live.clone();
    bad_endpoint.hops[0].private_endpoint = "10.77.0.9:3478".into();
    assert!(!support::reauthorize_nhop_fixture(network, a, b, &bad_endpoint).await);
    let mut bad_crossing = live.clone();
    bad_crossing.hops[1].requires_cross_border_approval = false;
    assert!(!support::reauthorize_nhop_fixture(network, a, b, &bad_crossing).await);
    let mut bad_member = live.clone();
    bad_member.members[0].wg_public_key = BASE64.encode([99u8; 32]);
    assert!(!support::reauthorize_nhop_fixture(network, a, b, &bad_member).await);
    // Fill the middle relay to the hard limit; the existing path's own slot
    // must be reusable instead of being mistaken for a new allocation.
    let middle_party = live.hops[0].relay.clone();
    let middle_agent_id = live.hops[0].relay_agent_id;
    let mut fixture_keys = Vec::new();
    for i in 0..roomler_ai_remote_control::models::peer_relay_limits::MAX_SESSIONS_PER_RELAY - 1 {
        let mut held = live.clone();
        held.pair_key = format!("nhop-reuse-capacity-{i}");
        held.relay = middle_party.clone(); held.relay_agent_id = middle_agent_id;
        held.vni = 1000 + i as u32; held.generation = 1000 + i as u64;
        held.hops.clear();
        fixture_keys.push(held.pair_key.clone());
        assert!(support::insert_session_fixture(network, held));
    }
    assert!(support::reauthorize_nhop_fixture(network, a, b, &live).await, "own occupied slots must be reusable");
    relay_request(&mut l.cn, &l.us_node).await;
    let repushed = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("reauthorized re-push");
    assert_eq!(repushed["vni"], cn["vni"]);
    assert!(recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(500)).await.is_none(), "re-push must not mint another relay session");
    for key in fixture_keys { assert!(support::remove_session_fixture(network, &key)); }
    support::fail_next_nhop_reauth_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(recv_t(&mut l.cn, "rc:overlay.relay_session", Duration::from_millis(800)).await.is_none(), "transient read failure must not re-push");
    assert_eq!(network.org_relay.active_session(&pair).unwrap().generation, live.generation, "transient failure must not tear down an established path");
    for (relay, frame) in [(&source_native, gz.clone()), (&middle_native, mid.clone()), (&exit_native, hk.clone())] {
        relay.serve(serde_json::from_value::<ServerMsg>(frame).unwrap(), None);
    }
    source_native.serve(serde_json::from_value(first_bridge.clone()).unwrap(), Some(source_native.policy_to(&middle_native)));
    middle_native.serve(serde_json::from_value(second_bridge.clone()).unwrap(), Some(middle_native.policy_to(&exit_native)));
    let socket_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let secret = |frame: &Value| BindSecret::from_bytes(BASE64.decode(frame["bind_secret"].as_str().unwrap()).unwrap().try_into().unwrap());
    let vni = |frame: &Value| frame["vni"].as_u64().unwrap() as u32;
    let generation = |frame: &Value| frame["generation"].as_u64().unwrap();
    bind_member(&socket_a, source_native.endpoint(), vni(&cn), generation(&cn), &secret(&cn), Duration::from_secs(5)).await.unwrap();
    bind_member(&socket_b, exit_native.endpoint(), vni(&us), generation(&us), &secret(&us), Duration::from_secs(5)).await.unwrap();
    let conn_a = Arc::new(OrgRelayConn::new(socket_a, source_native.endpoint(), vni(&cn), "test-ingress".into()));
    let conn_b = Arc::new(OrgRelayConn::new(socket_b, exit_native.endpoint(), vni(&us), "test-exit".into()));
    let carrier_a = Arc::new(Carrier::Relay { dst: conn_a.synth_peer(), conn: conn_a, dead: AtomicBool::new(false) });
    let carrier_b = Arc::new(Carrier::Relay { dst: conn_b.synth_peer(), conn: conn_b, dead: AtomicBool::new(false) });
    let ip_a: Ipv4Addr = network.overlay_nodes.base.find_by_id(a).await.unwrap().overlay_ip.parse().unwrap();
    let ip_b: Ipv4Addr = network.overlay_nodes.base.find_by_id(b).await.unwrap().overlay_ip.parse().unwrap();
    let (mut wg_a, mut received_a) = WgDevice::new(key_a.secret.clone());
    let (mut wg_b, mut received_b) = WgDevice::new(key_b.secret.clone());
    wg_a.add_peer(key_b.public.to_bytes(), ip_b, carrier_a, true);
    wg_b.add_peer(key_a.public.to_bytes(), ip_a, carrier_b, false);
    let packet = |source: Ipv4Addr, target: Ipv4Addr, payload: &[u8]| {
        let mut bytes = vec![0u8; 20 + payload.len()];
        bytes[0] = 0x45; let len = bytes.len() as u16; bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[8] = 64; bytes[9] = 17; bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&target.octets()); bytes[20..].copy_from_slice(payload); bytes
    };
    let forward = packet(ip_a, ip_b, b"three relay actual WireGuard forward");
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            wg_a.send_ip_packet(&forward).await;
            if let Ok(Some(got)) = tokio::time::timeout(Duration::from_millis(150), received_b.recv()).await {
                if got == forward { break; }
            }
        }
    }).await.expect("actual forward WG packet across three native relays");
    let backward = packet(ip_b, ip_a, b"three relay actual WireGuard reverse");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_b.send_ip_packet(&backward).await;
            if let Ok(Some(got)) = tokio::time::timeout(Duration::from_millis(150), received_a.recv()).await {
                if got == backward { break; }
            }
        }
    }).await.expect("actual reverse WG packet across three native relays");
    let crossing_reason = format!("cross_border_edge:{}", l.hk_agent);
    let audits = l.audit_reasons("mint").await;
    assert!(audits.iter().any(|(reason, node)| reason == &crossing_reason && node == &middle_node), "per-edge crossing audit missing: {audits:?}");
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, false)).await;
    assert_eq!(status, 200, "{body}");
    for (name, ws, vni) in [("ingress", &mut l.gz, &gz["vni"]), ("middle", &mut middle, &mid["vni"]),
        ("exit", &mut l.hk, &hk["vni"]), ("requester", &mut l.cn, &cn["vni"]), ("peer", &mut l.us, &us["vni"])] {
        let revoke = recv_t(ws, "rc:overlay.relay_revoke", wait).await.unwrap_or_else(|| panic!("{name} revoke"));
        assert_eq!(&revoke["vni"], vni, "{name} vni");
        match name {
            "ingress" => source_native.serve(serde_json::from_value(revoke).unwrap(), None),
            "middle" => middle_native.serve(serde_json::from_value(revoke).unwrap(), None),
            "exit" => exit_native.serve(serde_json::from_value(revoke).unwrap(), None),
            _ => {},
        }
    }
    let first_revoke = recv_t(&mut l.gz, "rc:overlay.relay_bridge_revoke", wait).await.expect("first bridge revoke");
    let second_revoke = recv_t(&mut middle, "rc:overlay.relay_bridge_revoke", wait).await.expect("second bridge revoke");
    source_native.serve(serde_json::from_value(first_revoke).unwrap(), None);
    middle_native.serve(serde_json::from_value(second_revoke).unwrap(), None);
    while received_b.try_recv().is_ok() {}
    let after = packet(ip_a, ip_b, b"must not traverse revoked bridge");
    wg_a.send_ip_packet(&after).await;
    assert!(tokio::time::timeout(Duration::from_millis(500), received_b.recv()).await.is_err(), "revoked path must not deliver new WG traffic");

    // Force the actual policy update between the server claim and delivery.
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, true)).await;
    assert_eq!(status, 200, "{body}");
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, a, &[
        (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
        (mid_node, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, b, &[
        (hk_node, "1.1.1.1:3478".into(), true, Some(10)),
    ]));
    let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
    let (reached, resume) = roomler_ai_mod_network::org_relay::candidate_test_support::pause_nhop_delivery_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached).await.expect("claim pause").unwrap();
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, false)).await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    assert!(recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(700)).await.is_none(), "revoked candidate must not deliver a relay grant");
    assert!(recv_t(&mut l.cn, "rc:overlay.relay_session", Duration::from_millis(700)).await.is_none(), "revoked candidate must not deliver a member grant");
    assert!(network.org_relay.active_session(&pair).is_none());

    // Force a policy withdrawal after the first eligibility check but before
    // its send. The delivery guard keeps the revoke ordered after the grant.
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, true)).await;
    assert_eq!(status, 200, "{body}");
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, a, &[
        (gz_node, "223.6.6.6:3478".into(), true, Some(10)), (mid_node, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, b, &[
        (hk_node, "1.1.1.1:3478".into(), true, Some(10)),
    ]));
    let (reached, release) = roomler_ai_mod_network::org_relay::candidate_test_support::pause_nhop_before_first_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached).await.expect("first delivery pause").unwrap();
    let withdrawal = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, false));
    let release_after_update_starts = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        release.send(()).unwrap();
    };
    let ((status, body), ()) = tokio::join!(withdrawal, release_after_update_starts);
    assert_eq!(status, 200, "{body}");
    let sent = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("first grant was queued");
    let revoked = recv_t(&mut l.gz, "rc:overlay.relay_revoke", wait).await.expect("revoke follows first grant");
    assert_eq!(sent["vni"], revoked["vni"]);
    assert!(network.org_relay.active_session(&pair).is_none());

    // Re-establish a real multi-hop session. Pause its reauthorization just
    // before re-push, revoke an edge, and prove the old member grant does not
    // get queued after revocation.
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, true)).await;
    assert_eq!(status, 200, "{body}");
    assert!(support::record_member_probe_fixture(network, a, &[
        (gz_node, "223.6.6.6:3478".into(), true, Some(10)), (mid_node, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(support::record_member_probe_fixture(network, b, &[(hk_node, "1.1.1.1:3478".into(), true, Some(10))]));
    relay_request(&mut l.cn, &l.us_node).await;
    recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("new ingress");
    recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("new first bridge");
    recv_t(&mut middle, "rc:overlay.relay_serve", wait).await.expect("new middle");
    recv_t(&mut middle, "rc:overlay.relay_bridge_serve", wait).await.expect("new second bridge");
    recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("new exit");
    recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("new member");
    recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("new peer");
    let (reached, resume) = support::pause_nhop_repush_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached).await.expect("repush pause").unwrap();
    let (status, body) = put(&l.rig.app, &middle_policy, admin, policy(&l.hk_agent, &exit_endpoint, false)).await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    assert!(recv_t(&mut l.cn, "rc:overlay.relay_session", Duration::from_millis(800)).await.is_none(), "revoked path must not be re-pushed");
    assert!(network.org_relay.active_session(&pair).is_none());
}

/// Four relays alternate between zones. The real handler must emit every
/// bridge and a distinct audit for each of the three approved crossings.
#[tokio::test]
async fn staged_graph_actual_four_relay_mint_uses_every_bridge() {
    let mut l = LineRig::up("iso-actual-four", true).await;
    let (m1_agent, m1_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-actual-four-mid1").await;
    let (m2_agent, m2_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-actual-four-mid2").await;
    let mut m1 = connect_from(&l.rig.app, &m1_token, &["relay-server"], Some(US_R)).await;
    let mut m2 = connect_from(&l.rig.app, &m2_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &m1_agent, Some(US_R)).await;
    assert_observed(&l.rig.app, &m2_agent, Some(CN_R)).await;
    line_join(&mut m1, 5, "1.1.1.2:41641", json!({ "relay_backbone_ready": true })).await;
    line_join(&mut m2, 6, "223.6.6.8:41641", json!({ "relay_backbone_ready": true })).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &m1_agent, true).await, 200);
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &m2_agent, true).await, 200);
    let m1_node = l.rig.node("iso-actual-four-mid1").await;
    let m2_node = l.rig.node("iso-actual-four-mid2").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &m1_node).await;
    grant_relay(&l.rig.app, &l.rig.seeded, &m2_node).await;
    let admin = &l.rig.seeded.admin.access_token;
    let policy = |target: &str, endpoint: &str, cross_border| json!({ "serve": true, "approved_backbone_edges": [
        { "relay_agent_id": target, "endpoint": endpoint, "cross_border": cross_border },
    ]});
    for (source, target, endpoint, crossing) in [
        (&l.gz_agent, &m1_agent, "10.44.0.1:3478", true),
        (&m1_agent, &m2_agent, "10.44.0.2:3478", true),
        (&m2_agent, &l.hk_agent, "10.44.0.3:3478", true),
    ] {
        let path = format!("/api/tenant/{}/agent/{source}/peer-relay-policy", l.rig.seeded.tenant_id);
        let (status, body) = put(&l.rig.app, &path, admin, policy(target, endpoint, crossing)).await;
        assert_eq!(status, 200, "{body}");
    }
    let network = l.rig.app.state.network();
    let a = ObjectId::parse_str(&l.cn_node).unwrap();
    let b = ObjectId::parse_str(&l.us_node).unwrap();
    let gz = ObjectId::parse_str(&l.gz_node).unwrap();
    let mid1 = ObjectId::parse_str(&m1_node).unwrap();
    let mid2 = ObjectId::parse_str(&m2_node).unwrap();
    let hk = ObjectId::parse_str(&l.hk_node).unwrap();
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, a, &[
        (gz, "223.6.6.6:3478".into(), true, Some(10)),
        (mid2, "223.6.6.8:3478".into(), false, None),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, b, &[
        (hk, "1.1.1.1:3478".into(), true, Some(10)),
        (mid1, "1.1.1.2:3478".into(), false, None),
    ]));
    let chosen = roomler_ai_mod_network::org_relay::candidate_test_support::select_path(network, a, b, false).await.unwrap().unwrap();
    assert_eq!(chosen, (vec![ObjectId::parse_str(&l.gz_agent).unwrap(), ObjectId::parse_str(&m1_agent).unwrap(),
        ObjectId::parse_str(&m2_agent).unwrap(), ObjectId::parse_str(&l.hk_agent).unwrap()], false));
    relay_request(&mut l.cn, &l.us_node).await;
    let wait = Duration::from_secs(8);
    let first = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("first serve");
    let bridge1 = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("first bridge");
    let second = recv_t(&mut m1, "rc:overlay.relay_serve", wait).await.expect("second serve");
    let bridge2 = recv_t(&mut m1, "rc:overlay.relay_bridge_serve", wait).await.expect("second bridge");
    let third = recv_t(&mut m2, "rc:overlay.relay_serve", wait).await.expect("third serve");
    let bridge3 = recv_t(&mut m2, "rc:overlay.relay_bridge_serve", wait).await.expect("third bridge");
    let last = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("last serve");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("requester grant");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("peer grant");
    for (bridge, source, target) in [(&bridge1, &first, &second), (&bridge2, &second, &third), (&bridge3, &third, &last)] {
        assert_eq!(bridge["bridge"]["local_vni"], source["vni"]);
        assert_eq!(bridge["bridge"]["remote_vni"], target["vni"]);
    }
    assert_eq!(cn["vni"], first["vni"]);
    assert_eq!(us["vni"], last["vni"]);
    let audits = l.audit_reasons("mint").await;
    for (source_node, target_agent) in [(&l.gz_node, &m1_agent), (&m1_node, &m2_agent), (&m2_node, &l.hk_agent)] {
        let reason = format!("cross_border_edge:{target_agent}");
        assert!(audits.iter().any(|(r, node)| r == &reason && node == source_node), "missing crossing audit: {audits:?}");
    }
    // Withdraw the active path, restore it, and exhaust the real requester /
    // ingress limiter. A refused request must not write crossing-mint rows.
    let gz_policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
    let (status, body) = put(&l.rig.app, &gz_policy, admin, json!({"serve": true, "approved_backbone_edges": []})).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(&l.rig.app, &gz_policy, admin, policy(&m1_agent, "10.44.0.1:3478", true)).await;
    assert_eq!(status, 200, "{body}");
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, a, &[
        (gz, "223.6.6.6:3478".into(), true, Some(10)), (mid2, "223.6.6.8:3478".into(), false, None),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(network, b, &[
        (hk, "1.1.1.1:3478".into(), true, Some(10)), (mid1, "1.1.1.2:3478".into(), false, None),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_backbone_probe_fixture(network, gz, &[
        (mid1, "10.44.0.1:3478".into(), true, Some(100)),
    ]));
    assert!(roomler_ai_mod_network::org_relay::candidate_test_support::record_backbone_probe_fixture(network, mid2, &[
        (hk, "10.44.0.3:3478".into(), true, Some(5)),
    ]));
    let limit = roomler_ai_remote_control::models::peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE;
    for _ in 0..limit { network.relay_rate_limiter.check(a, gz, limit); }
    let crossing_count = |rows: &[(String, String)]| rows.iter().filter(|(r, _)| r.starts_with("cross_border_edge:")).count();
    let before = crossing_count(&l.audit_reasons("mint").await);
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(800)).await.is_none(), "rate-limited path must not be served");
    let after = crossing_count(&l.audit_reasons("mint").await);
    assert_eq!(after, before, "rate-limit denial must precede crossing audit rows");
    let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
    let fallback = network.org_relay.active_session(&pair).expect("an available alternate ingress is replanned");
    assert_eq!(fallback.hops.len(), 1);
    // Either directed approved crossing may win; its orientation determines
    // which member binds the ingress. The rate-limited GZ cannot be chosen.
    let (ingress, bridge, exit, flipped) = if fallback.relay.node_id == mid1 {
        (recv_t(&mut m1, "rc:overlay.relay_serve", wait).await.expect("alternate ingress"),
         recv_t(&mut m1, "rc:overlay.relay_bridge_serve", wait).await.expect("alternate bridge"),
         recv_t(&mut m2, "rc:overlay.relay_serve", wait).await.expect("alternate exit"), true)
    } else {
        assert_eq!(fallback.relay.node_id, mid2);
        (recv_t(&mut m2, "rc:overlay.relay_serve", wait).await.expect("alternate ingress"),
         recv_t(&mut m2, "rc:overlay.relay_bridge_serve", wait).await.expect("alternate bridge"),
         recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("alternate exit"), false)
    };
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("fallback requester");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("fallback peer");
    assert_eq!(bridge["bridge"]["local_vni"], ingress["vni"]);
    assert_eq!(bridge["bridge"]["remote_vni"], exit["vni"]);
    assert_eq!(if flipped { &us["vni"] } else { &cn["vni"] }, &ingress["vni"]);
    assert_eq!(if flipped { &cn["vni"] } else { &us["vni"] }, &exit["vni"]);
}

/// A selected multi-hop attempt whose crossing audit fails must still replan a
/// safe direct line. Also force an authorization epoch change before claim.
/// The same ingress has exactly one token left for the second attempt, which
/// the multi-hop attempt consumes; fallback must not spend it twice.
#[tokio::test]
async fn staged_graph_long_path_audit_failure_falls_back_without_double_rate_charge() {
    let mut l = LineRig::up("iso-multi-audit-fallback", true).await;
    let (mid_agent, mid_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-multi-audit-fallback-mid").await;
    let mut mid_ws = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(&mut mid_ws, 5, "223.6.6.7:41641", json!({ "relay_backbone_ready": true })).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await, 200);
    let mid_node = l.rig.node("iso-multi-audit-fallback-mid").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let admin = &l.rig.seeded.admin.access_token;
    let gz_policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
    let mid_policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, mid_agent);
    let (status, body) = put(&l.rig.app, &gz_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":mid_agent,"endpoint":"10.55.0.2:3478","cross_border":false},
        {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.3:3478","cross_border":true},
    ]})).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(&l.rig.app, &mid_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.4:3478","cross_border":true},
    ]})).await;
    assert_eq!(status, 200, "{body}");
    let network = l.rig.app.state.network();
    let (a, b, gz, mid, hk) = (
        ObjectId::parse_str(&l.cn_node).unwrap(), ObjectId::parse_str(&l.us_node).unwrap(),
        ObjectId::parse_str(&l.gz_node).unwrap(), ObjectId::parse_str(&mid_node).unwrap(), ObjectId::parse_str(&l.hk_node).unwrap(),
    );
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    assert!(support::record_member_probe_fixture(network, a, &[
        (gz, "223.6.6.6:3478".into(), true, Some(10)), (mid, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(support::record_member_probe_fixture(network, b, &[(hk, "1.1.1.1:3478".into(), true, Some(10))]));
    assert!(support::record_backbone_probe_fixture(network, gz, &[
        (mid, "10.55.0.2:3478".into(), true, Some(5)), (hk, "10.55.0.3:3478".into(), true, Some(100)),
    ]));
    assert!(support::record_backbone_probe_fixture(network, mid, &[(hk, "10.55.0.4:3478".into(), true, Some(5))]));
    let selected = support::select_path(network, a, b, false).await.unwrap().unwrap();
    assert_eq!(selected, (vec![ObjectId::parse_str(&l.gz_agent).unwrap(), ObjectId::parse_str(&mid_agent).unwrap(), ObjectId::parse_str(&l.hk_agent).unwrap()], false));
    let limit = roomler_ai_remote_control::models::peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE;
    let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
    // If both audits fail, fallback must still fail closed and send no grant.
    support::fail_next_nhop_audit_fixture(pair.clone());
    support::fail_next_line_audit_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(800)).await.is_none(), "failed line audit must not serve");
    assert!(recv_t(&mut l.cn, "rc:overlay.relay_session", Duration::from_millis(800)).await.is_none(), "failed line audit must not grant");
    assert!(network.org_relay.active_session(&pair).is_none());
    // Remove only the long path after its audit/selection but before claim.
    // The direct edge stays approved; the new policy epoch must trigger a
    // fresh, successful direct-line replan.
    let (reached, resume) = support::pause_nhop_preclaim_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached).await.expect("preclaim pause").unwrap();
    let (status, body) = put(&l.rig.app, &gz_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.3:3478","cross_border":true},
    ]})).await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    let wait = Duration::from_secs(8);
    recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("direct ingress after epoch change");
    recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("direct bridge after epoch change");
    recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("direct exit after epoch change");
    recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("requester after epoch change");
    recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("peer after epoch change");
    // Remove the direct session, restore both edges, and re-establish the
    // measurements invalidated by policy edits.
    let (status, body) = put(&l.rig.app, &gz_policy, admin, json!({"serve":true,"approved_backbone_edges":[]})).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(&l.rig.app, &gz_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":mid_agent,"endpoint":"10.55.0.2:3478","cross_border":false},
        {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.3:3478","cross_border":true},
    ]})).await;
    assert_eq!(status, 200, "{body}");
    assert!(support::record_member_probe_fixture(network, a, &[
        (gz, "223.6.6.6:3478".into(), true, Some(10)), (mid, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(support::record_member_probe_fixture(network, b, &[(hk, "1.1.1.1:3478".into(), true, Some(10))]));
    assert!(support::record_backbone_probe_fixture(network, gz, &[
        (mid, "10.55.0.2:3478".into(), true, Some(5)), (hk, "10.55.0.3:3478".into(), true, Some(100)),
    ]));
    assert!(support::record_backbone_probe_fixture(network, mid, &[(hk, "10.55.0.4:3478".into(), true, Some(5))]));
    assert_eq!(support::select_path(network, a, b, false).await.unwrap().unwrap().0.len(), 3);
    // The first two attempts each consumed one token; leave exactly one more.
    for _ in 0..limit - 3 { assert!(network.relay_rate_limiter.check(a, gz, limit)); }
    support::fail_next_nhop_audit_fixture(pair);
    relay_request(&mut l.cn, &l.us_node).await;
    let wait = Duration::from_secs(8);
    let first = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("fresh direct-line ingress");
    let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("fresh direct-line bridge");
    let last = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("fresh direct-line exit");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("requester grant");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("peer grant");
    assert_eq!(bridge["bridge"]["remote_vni"], last["vni"]);
    assert_eq!(cn["vni"], first["vni"]);
    assert_eq!(us["vni"], last["vni"]);
    assert!(recv_t(&mut mid_ws, "rc:overlay.relay_serve", Duration::from_millis(500)).await.is_none(), "failed multi-hop candidate must not be sent");
    assert!(!network.relay_rate_limiter.check(a, gz, limit), "the one remaining token was consumed once");
}

/// Saturate the selected ingress after multi-hop reauthorization but before
/// claim. The direct fallback must be freshly planned on the other ingress.
#[tokio::test]
async fn staged_graph_long_path_capacity_race_falls_back_to_available_line() {
    use roomler_ai_mod_network::org_relay::{OrgRelaySession, SessionMember, SessionParty, candidate_test_support as support};
    use roomler_ai_remote_control::models::{NodeRef, peer_relay_limits as limits};
    use std::time::Instant;
    let mut l = LineRig::up("iso-multi-cap-fallback", true).await;
    let (mid_agent, mid_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-multi-cap-fallback-mid").await;
    let mut mid_ws = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(&mut mid_ws, 5, "223.6.6.7:41641", json!({ "relay_backbone_ready": true })).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await, 200);
    let mid_node = l.rig.node("iso-multi-cap-fallback-mid").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let admin = &l.rig.seeded.admin.access_token;
    let gz_policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
    let mid_policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, mid_agent);
    let (status, body) = put(&l.rig.app, &gz_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":mid_agent,"endpoint":"10.56.0.2:3478","cross_border":false},
    ]})).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(&l.rig.app, &mid_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":l.hk_agent,"endpoint":"10.56.0.3:3478","cross_border":true},
    ]})).await;
    assert_eq!(status, 200, "{body}");
    let network = l.rig.app.state.network();
    let (a, b, gz, mid, hk) = (
        ObjectId::parse_str(&l.cn_node).unwrap(), ObjectId::parse_str(&l.us_node).unwrap(),
        ObjectId::parse_str(&l.gz_node).unwrap(), ObjectId::parse_str(&mid_node).unwrap(), ObjectId::parse_str(&l.hk_node).unwrap(),
    );
    assert!(support::record_member_probe_fixture(network, a, &[
        (gz, "223.6.6.6:3478".into(), true, Some(10)), (mid, "223.6.6.7:3478".into(), false, None),
    ]));
    assert!(support::record_member_probe_fixture(network, b, &[(hk, "1.1.1.1:3478".into(), true, Some(10))]));
    let selected = support::select_path(network, a, b, false).await.unwrap().unwrap();
    assert_eq!(selected.0.len(), 3);
    let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
    let (reached, resume) = support::pause_nhop_preclaim_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached).await.expect("preclaim pause").unwrap();
    let gz_agent = ObjectId::parse_str(&l.gz_agent).unwrap();
    let tenant = ObjectId::parse_str(&l.rig.seeded.tenant_id).unwrap();
    let party = |id| SessionParty { node_id: id, node_ref: NodeRef::Agent { agent_id: id } };
    let member = |id| SessionMember { party: party(id), wg_public_key: "fixture".into(), bind_secret: "fixture".into() };
    for i in 0..limits::MAX_SESSIONS_PER_RELAY {
        let fixture = OrgRelaySession {
            tenant_id: tenant, pair_key: format!("capacity-fixture-{i}"), vni: i as u32 + 1000,
            generation: i as u64 + 1000, relay: SessionParty { node_id: gz, node_ref: NodeRef::Agent { agent_id: gz_agent } },
            relay_agent_id: gz_agent, implicit: false, members: [member(ObjectId::new()), member(ObjectId::new())],
            endpoints: vec!["fixture".into()], expires_at: Instant::now() + Duration::from_secs(90),
            bind_by: Instant::now() + Duration::from_secs(30), hops: Vec::new(),
        };
        assert!(support::insert_session_fixture(network, fixture));
    }
    resume.send(()).unwrap();
    let wait = Duration::from_secs(8);
    let first = recv_t(&mut mid_ws, "rc:overlay.relay_serve", wait).await.expect("alternate ingress after capacity race");
    let bridge = recv_t(&mut mid_ws, "rc:overlay.relay_bridge_serve", wait).await.expect("alternate bridge");
    let last = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("alternate exit");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("requester grant");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("peer grant");
    assert_eq!(cn["relay_node_id"], json!(mid_node));
    assert_eq!(cn["vni"], first["vni"]);
    assert_eq!(bridge["bridge"]["remote_vni"], last["vni"]);
    assert_eq!(us["vni"], last["vni"]);
    assert!(recv_t(&mut l.gz, "rc:overlay.relay_serve", Duration::from_millis(500)).await.is_none());
}

/// Same-zone real requests should mint, reauthorize and revoke all relay legs
/// in each isolation mode, including the org-only fallback entry point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_same_zone_actual_mint_and_fallback() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    for (isolation, fallback) in [("enforce", false), ("enforce", true), ("warn", false), ("warn", true), ("off", false), ("off", true)] {
        let slug = format!("iso-same-{isolation}-{}", if fallback { "fallback" } else { "normal" });
        let rig = Rig::up(&slug, isolation).await;
        let mut relays = Vec::new();
        let mut agents = Vec::new();
        let mut nodes = Vec::new();
        for i in 0..3 {
            let name = format!("{slug}-r{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(CN_R)).await;
            assert_observed(&rig.app, &agent, Some(CN_R)).await;
            line_join(&mut ws, 10 + i, &format!("223.6.6.{}:41641", 6 + i), json!({"relay_backbone_ready":true})).await;
            assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
            let node = rig.node(&name).await;
            grant_relay(&rig.app, &rig.seeded, &node).await;
            relays.push(ws); agents.push(agent); nodes.push(node);
        }
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig.device(&format!("{slug}-b"), Some(CN_A)).await;
        let flag = json!({"supports_backbone_only_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flag.clone()).await;
        line_join(&mut b, 2, "223.5.5.6:41641", flag).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        set_mode(&rig.app, &rig.seeded, "on").await;
        let policy_path = |agent: &str| format!("/api/tenant/{}/agent/{agent}/peer-relay-policy", rig.seeded.tenant_id);
        for i in 0..2 {
            let (status, body) = put(&rig.app, &policy_path(&agents[i]), &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],"endpoint":format!("10.44.0.{}:3478",i+2),"cross_border":false}]})).await;
            assert_eq!(status, 200, "{body}");
        }
        let network = rig.app.state.network();
        let ids: Vec<_> = nodes.iter().map(|n| ObjectId::parse_str(n).unwrap()).collect();
        assert!(support::record_member_probe_fixture(network, a_id, &[
            (ids[0], "223.6.6.6:3478".into(), true, Some(10)),
            (ids[1], "223.6.6.7:3478".into(), false, None),
            (ids[2], "223.6.6.8:3478".into(), false, None),
        ]));
        assert!(support::record_member_probe_fixture(network, b_id, &[
            (ids[0], "223.6.6.6:3478".into(), false, None),
            (ids[1], "223.6.6.7:3478".into(), false, None),
            (ids[2], "223.6.6.8:3478".into(), true, Some(10)),
        ]));
        if fallback {
            a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request", "peer_node_id":b_id.to_hex(), "request_id":1}).to_string().into())).await.unwrap();
        } else { relay_request(&mut a, &b_id.to_hex()).await; }
        let wait = Duration::from_secs(8);
        let mut serves = Vec::new();
        for ws in &mut relays {
            serves.push(recv_t(ws, "rc:overlay.relay_serve", wait).await.unwrap_or_else(|| panic!("{slug}: relay serve absent")));
        }
        let bridge0 = recv_t(&mut relays[0], "rc:overlay.relay_bridge_serve", wait).await.expect("first bridge");
        let bridge1 = recv_t(&mut relays[1], "rc:overlay.relay_bridge_serve", wait).await.expect("second bridge");
        let sa = recv_t(&mut a, "rc:overlay.relay_session", wait).await.expect("requester session");
        let sb = recv_t(&mut b, "rc:overlay.relay_session", wait).await.expect("peer session");
        assert_eq!(sa["vni"], serves[0]["vni"]); assert_eq!(sb["vni"], serves[2]["vni"]);
        assert_eq!(bridge0["bridge"]["local_vni"], serves[0]["vni"]);
        assert_eq!(bridge0["bridge"]["remote_vni"], serves[1]["vni"]);
        assert_eq!(bridge1["bridge"]["local_vni"], serves[1]["vni"]);
        assert_eq!(bridge1["bridge"]["remote_vni"], serves[2]["vni"]);
        assert!(audit_rows(&rig.app, &rig.seeded).await.iter().any(|row| row["reason"] == "multi_hop_same_zone_attempt"), "{slug}: audit missing");
        relay_request(&mut a, &b_id.to_hex()).await;
        let again = recv_t(&mut a, "rc:overlay.relay_session", wait).await.expect("reauthorized repush");
        assert_eq!(again["vni"], sa["vni"]);
        let (status, body) = put(&rig.app, &policy_path(&agents[0]), &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[]})).await;
        assert_eq!(status, 200, "{body}");
        for (i, ws) in relays.iter_mut().enumerate() {
            let revoked = recv_t(ws, "rc:overlay.relay_revoke", wait).await.expect("relay revoked");
            assert_eq!(revoked["vni"], serves[i]["vni"]);
        }
        for ws in relays.iter_mut().take(2) { recv_t(ws, "rc:overlay.relay_bridge_revoke", wait).await.expect("bridge revoked"); }
        assert!(recv_t(&mut a, "rc:overlay.relay_revoke", wait).await.is_some());
        assert!(recv_t(&mut b, "rc:overlay.relay_revoke", wait).await.is_some());
        if isolation == "enforce" {
            // Make the long path fast but keep r0 as the best single relay.
            // Its first successful mint spent one token; leave just one more.
            let (status, body) = put(&rig.app, &policy_path(&agents[0]), &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[1],"endpoint":"10.44.0.2:3478","cross_border":false}]})).await;
            assert_eq!(status, 200, "{body}");
            assert!(support::record_member_probe_fixture(network, a_id, &[
                (ids[0], "223.6.6.6:3478".into(), true, Some(10)),
                (ids[1], "223.6.6.7:3478".into(), false, None),
                (ids[2], "223.6.6.8:3478".into(), false, None),
            ]));
            assert!(support::record_member_probe_fixture(network, b_id, &[
                (ids[0], "223.6.6.6:3478".into(), true, Some(1000)),
                (ids[1], "223.6.6.7:3478".into(), false, None),
                (ids[2], "223.6.6.8:3478".into(), true, Some(10)),
            ]));
            assert!(support::record_backbone_probe_fixture(network, ids[0], &[(ids[1], "10.44.0.2:3478".into(), true, Some(5))]));
            assert!(support::record_backbone_probe_fixture(network, ids[1], &[(ids[2], "10.44.0.3:3478".into(), true, Some(5))]));
            let selected = support::select_path(network, a_id, b_id, false).await.unwrap().unwrap();
            assert_eq!(selected, (agents.iter().map(|id| ObjectId::parse_str(id).unwrap()).collect(), false));
            let limit = roomler_ai_remote_control::models::peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE;
            for _ in 0..limit - 2 { assert!(network.relay_rate_limiter.check(a_id, ids[0], limit)); }
            let pair = roomler_ai_mod_network::overlay::pair_key(a_id, b_id);
            support::fail_next_nhop_audit_fixture(pair.clone());
            if fallback {
                a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request", "peer_node_id":b_id.to_hex(), "request_id":2}).to_string().into())).await.unwrap();
            } else { relay_request(&mut a, &b_id.to_hex()).await; }
            let old = recv_t(&mut relays[0], "rc:overlay.relay_serve", wait).await.expect("single relay fallback after audit failure");
            let grant_a = recv_t(&mut a, "rc:overlay.relay_session", wait).await.expect("single requester grant");
            let grant_b = recv_t(&mut b, "rc:overlay.relay_session", wait).await.expect("single peer grant");
            assert_eq!(grant_a["vni"], old["vni"]); assert_eq!(grant_b["vni"], old["vni"]);
            assert!(network.org_relay.active_session(&pair).unwrap().hops.is_empty(), "failed audit must not mint long path");
            assert!(!network.relay_rate_limiter.check(a_id, ids[0], limit), "attempt spent its final token exactly once");
        }
    }
}

/// A direct-line claim that loses to a concurrent N-hop winner must not
/// bypass that winner's complete reauthorization when repushing it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_line_claim_race_reauthorizes_multihop_winner() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    for invalid_key in [false, true] {
    let slug = if invalid_key { "iso-line-claim-race-denied" } else { "iso-line-claim-race-unavailable" };
    let mut l = LineRig::up(slug, true).await;
    let (middle_agent, token) = enroll(&l.rig.app, &l.rig.seeded, "iso-line-claim-race-mid").await;
    let mut middle = connect_from(&l.rig.app, &token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &middle_agent, Some(CN_R)).await;
    line_join(&mut middle, 5, "223.6.6.7:41641", json!({"relay_backbone_ready":true})).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &middle_agent, true).await, 200);
    let middle_node = l.rig.node("iso-line-claim-race-mid").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &middle_node).await;
    let network = l.rig.app.state.network();
    let (a, b, gz, mid, hk) = (ObjectId::parse_str(&l.cn_node).unwrap(), ObjectId::parse_str(&l.us_node).unwrap(),
        ObjectId::parse_str(&l.gz_node).unwrap(), ObjectId::parse_str(&middle_node).unwrap(), ObjectId::parse_str(&l.hk_node).unwrap());
    let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
    let (reached, resume) = support::pause_line_preclaim_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached).await.expect("direct line reached claim").unwrap();
    // Keep the original direct line, but introduce a faster authorized chain
    // while its first request is paused just before the shared claim.
    let admin = &l.rig.seeded.admin.access_token;
    let gz_policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
    let mid_policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, middle_agent);
    let (status, body) = put(&l.rig.app, &gz_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":middle_agent,"endpoint":"10.59.0.2:3478","cross_border":false},
        {"relay_agent_id":l.hk_agent,"endpoint":"10.59.0.3:3478","cross_border":true}]})).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(&l.rig.app, &mid_policy, admin, json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":l.hk_agent,"endpoint":"10.59.0.4:3478","cross_border":true}]})).await;
    assert_eq!(status, 200, "{body}");
    assert!(support::record_member_probe_fixture(network, a, &[
        (gz, "223.6.6.6:3478".into(), true, Some(10)), (mid, "223.6.6.7:3478".into(), false, None)]));
    assert!(support::record_member_probe_fixture(network, b, &[(hk, "1.1.1.1:3478".into(), true, Some(10))]));
    assert!(support::record_backbone_probe_fixture(network, gz, &[
        (mid, "10.59.0.2:3478".into(), true, Some(5)), (hk, "10.59.0.3:3478".into(), true, Some(100))]));
    assert!(support::record_backbone_probe_fixture(network, mid, &[(hk, "10.59.0.4:3478".into(), true, Some(5))]));
    assert_eq!(support::select_path(network, a, b, false).await.unwrap().unwrap().0,
        vec![ObjectId::parse_str(&l.gz_agent).unwrap(), ObjectId::parse_str(&middle_agent).unwrap(), ObjectId::parse_str(&l.hk_agent).unwrap()]);
    // A different connection can issue the competing request while CN's
    // original WebSocket handler is paused.
    relay_request(&mut l.us, &l.cn_node).await;
    let wait = Duration::from_secs(8);
    let gz_serve = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("winning ingress serve");
    recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("winning first bridge");
    recv_t(&mut middle, "rc:overlay.relay_serve", wait).await.expect("winning middle serve");
    recv_t(&mut middle, "rc:overlay.relay_bridge_serve", wait).await.expect("winning second bridge");
    recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("winning exit serve");
    let first = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("winning CN grant");
    recv_t(&mut l.us, "rc:overlay.relay_session", wait).await.expect("winning US grant");
    assert_eq!(first["vni"], gz_serve["vni"]);
    let winner = network.org_relay.active_session(&pair).expect("winning session");
    assert_eq!(winner.hops.len(), 2);
    // A transient read failure must not send a stale grant, nor tear down the
    // healthy winning path. The old shortcut incorrectly sent the grant.
    if invalid_key {
        assert!(support::invalidate_session_member_key_fixture(network, &pair));
        resume.send(()).unwrap();
        recv_t(&mut l.cn, "rc:overlay.relay_revoke", wait).await.expect("definitely invalid winner revoked");
        assert!(network.org_relay.active_session(&pair).is_none(), "invalid winner remains active");
        assert!(recv_t(&mut l.cn, "rc:overlay.relay_session", Duration::from_millis(500)).await.is_none(), "invalid winner was re-pushed");
    } else {
        support::fail_next_nhop_reauth_fixture(pair.clone());
        resume.send(()).unwrap();
        assert!(recv_t(&mut l.cn, "rc:overlay.relay_session", Duration::from_millis(1500)).await.is_none(), "losing line bypassed multi-hop reauthorization");
        let retained = network.org_relay.active_session(&pair).expect("transient reauthorization retains winner");
        assert_eq!((retained.vni, retained.generation), (winner.vni, winner.generation));
        relay_request(&mut l.cn, &l.us_node).await;
        let retry = recv_t(&mut l.cn, "rc:overlay.relay_session", wait).await.expect("healthy reauthorization repushes winner");
        assert_eq!(retry["vni"], first["vni"]);
    }
    }
}

/// Cross-zone trial authorization must record the crossing attempt before it
/// reserves a trial slot or emits relay, bridge, and member grants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_cross_border_trial_audit_failure_and_timeout_fail_closed() {
    use roomler_ai_mod_network::org_relay::candidate_test_support::{self as support, TrialCrossingAuditFault};
    for (slug, fault) in [("iso-trial-audit-error", TrialCrossingAuditFault::Error), ("iso-trial-audit-timeout", TrialCrossingAuditFault::Timeout)] {
        let mut l = LineRig::up(slug, true).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,
            "supports_path_trial_v1":true,"supports_org_relay_multi_candidate":true,
            "supports_org_relay_discovery_cursor":true});
        line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
        let (a, b, gz, hk) = (ObjectId::parse_str(&l.cn_node).unwrap(), ObjectId::parse_str(&l.us_node).unwrap(),
            ObjectId::parse_str(&l.gz_node).unwrap(), ObjectId::parse_str(&l.hk_node).unwrap());
        let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
        let network = l.rig.app.state.network();
        support::fail_next_trial_crossing_audit(pair, fault);
        let request = |request_id| Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
            "path":{"relay_node_ids":[l.gz_node,l.hk_node]}, "requester_at_exit":false, "request_id":request_id}).to_string().into());
        l.cn.send(request(1)).await.unwrap();
        async fn assert_no_trial_frames(ws: &mut Ws, label: &str) {
            let until = tokio::time::Instant::now() + Duration::from_millis(3800);
            while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                if let Message::Text(text) = message {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    assert!(!["rc:overlay.relay_serve", "rc:overlay.relay_bridge_serve", "rc:overlay.path_trial_start"].contains(&v["t"].as_str().unwrap_or_default()), "{label}: failed audit emitted a trial grant");
                }
            }
        }
        tokio::join!(assert_no_trial_frames(&mut l.gz, &slug), assert_no_trial_frames(&mut l.hk, &slug),
            assert_no_trial_frames(&mut l.cn, &slug), assert_no_trial_frames(&mut l.us, &slug));
        assert_eq!(support::trial_slots_on_relay(network, gz), 0, "{slug}: ingress capacity leak");
        assert_eq!(support::trial_slots_on_relay(network, hk), 0, "{slug}: exit capacity leak");
        assert!(l.audit_reasons("mint").await.is_empty(), "{slug}: simulated failed audit cannot be successful");
        // Discovery is metadata only; it must remain available without any
        // audit write or trial/session allocation after the failed attempt.
        l.cn.send(Message::Text(json!({"t":"rc:overlay.org_relay_discover", "peer_node_id":l.us_node, "request_id":1}).to_string().into())).await.unwrap();
        let hint = recv_t(&mut l.cn, "rc:overlay.org_relay_candidates", Duration::from_secs(5)).await.expect("discovery unaffected");
        assert!(hint["candidates"].as_array().unwrap().iter().any(|c| c["path"]["relay_node_ids"] == json!([l.gz_node, l.hk_node]) && c["requester_at_exit"] == false));
        assert!(l.audit_reasons("mint").await.is_empty());
        l.cn.send(request(2)).await.unwrap();
        let wait = Duration::from_secs(8);
        let a = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("success ingress serve");
        let b = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("success exit serve");
        let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("success bridge");
        let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait).await.expect("success requester trial");
        let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait).await.expect("success peer trial");
        assert_eq!(cn["vni"], a["vni"]); assert_eq!(us["vni"], b["vni"]);
        assert_eq!(bridge["bridge"]["local_vni"], a["vni"]); assert_eq!(bridge["bridge"]["remote_vni"], b["vni"]);
        assert_eq!(support::trial_slots_on_relay(network, gz), 1); assert_eq!(support::trial_slots_on_relay(network, hk), 1);
        assert!(l.audit_reasons("mint").await.iter().any(|(reason, node)| reason == &format!("cross_border_edge:{}", l.hk_agent) && node == &l.gz_node));
    }
}

/// Off/Warn isolation does not waive approval or audit for an actual crossing;
/// unknown relay placement cannot prove that the backbone edge is local.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_actual_edge_zone_gates_apply_in_off_and_warn() {
    use roomler_ai_mod_network::org_relay::candidate_test_support::{self as support, TrialCrossingAuditFault};
    for mode in ["off", "warn"] {
        for case in ["unapproved", "audit_error", "audit_timeout", "unknown", "same_zone"] {
            let slug = format!("iso-trial-zone-{mode}-{case}");
            let mut l = LineRig::up_with_isolation(&slug, case != "unapproved", mode).await;
            let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
            line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
            line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
            let pair = roomler_ai_mod_network::overlay::pair_key(ObjectId::parse_str(&l.cn_node).unwrap(), ObjectId::parse_str(&l.us_node).unwrap());
            let gz = ObjectId::parse_str(&l.gz_node).unwrap();
            let hk = ObjectId::parse_str(&l.hk_node).unwrap();
            let network = l.rig.app.state.network();
            let mut alternate = None;
            let mut exit_node = l.hk_node.clone();
            if case == "unknown" || case == "same_zone" {
                let name = format!("{slug}-alternate");
                let (agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
                let from = if case == "unknown" { None } else { Some(CN_R) };
                let mut ws = connect_from(&l.rig.app, &token, &["relay-server"], from).await;
                assert_observed(&l.rig.app, &agent, from).await;
                let endpoint = if case == "unknown" { "1.1.1.9:41641" } else { "223.6.6.9:41641" };
                line_join(&mut ws, 10, endpoint, json!({})).await;
                assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
                exit_node = l.rig.node(&name).await;
                grant_relay(&l.rig.app, &l.rig.seeded, &exit_node).await;
                let policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
                let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
                    json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agent,"endpoint":"10.67.0.2:3478","cross_border":case == "unknown"}]})).await;
                assert_eq!(status, 200, "{body}");
                alternate = Some(ws);
            }
            if case == "audit_error" { support::fail_next_trial_crossing_audit(pair.clone(), TrialCrossingAuditFault::Error); }
            if case == "audit_timeout" { support::fail_next_trial_crossing_audit(pair.clone(), TrialCrossingAuditFault::Timeout); }
            async fn request(ws: &mut Ws, peer: &str, ingress: &str, exit: &str, serial: u64) {
                ws.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":peer,
                    "path":{"relay_node_ids":[ingress,exit]}, "requester_at_exit":false, "request_id":serial}).to_string().into())).await.unwrap();
            }
            request(&mut l.cn, &l.us_node, &l.gz_node, &exit_node, 1).await;
            let wait = Duration::from_secs(8);
            if case == "same_zone" {
                let serve = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("same-zone ingress serve");
                let other = recv_t(alternate.as_mut().unwrap(), "rc:overlay.relay_serve", wait).await.expect("same-zone exit serve");
                let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("same-zone bridge");
                let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait).await.expect("same-zone requester start");
                let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait).await.expect("same-zone peer start");
                assert_eq!(cn["vni"], serve["vni"]); assert_eq!(us["vni"], other["vni"]);
                assert_eq!(bridge["bridge"]["local_vni"], serve["vni"]); assert_eq!(bridge["bridge"]["remote_vni"], other["vni"]);
                assert!(l.audit_reasons("mint").await.is_empty(), "same-zone edge must not claim a crossing");
                continue;
            }
            async fn assert_quiet(ws: &mut Ws, label: &str) {
                let until = tokio::time::Instant::now() + Duration::from_millis(3600);
                while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                    if let Message::Text(text) = message {
                        let v: Value = serde_json::from_str(&text).unwrap();
                        assert!(!["rc:overlay.relay_serve", "rc:overlay.relay_bridge_serve", "rc:overlay.path_trial_start"].contains(&v["t"].as_str().unwrap_or_default()), "{label}: forbidden/unaudited edge emitted a trial grant");
                    }
                }
            }
            if let Some(ws) = alternate.as_mut() {
                tokio::join!(assert_quiet(&mut l.gz, &slug), assert_quiet(&mut l.hk, &slug), assert_quiet(ws, &slug),
                    assert_quiet(&mut l.cn, &slug), assert_quiet(&mut l.us, &slug));
            } else {
                tokio::join!(assert_quiet(&mut l.gz, &slug), assert_quiet(&mut l.hk, &slug),
                    assert_quiet(&mut l.cn, &slug), assert_quiet(&mut l.us, &slug));
            }
            assert_eq!(support::trial_slots_on_relay(network, gz), 0); assert_eq!(support::trial_slots_on_relay(network, hk), 0);
            assert!(l.audit_reasons("mint").await.is_empty());
            if case == "unapproved" || case == "unknown" { l.set_edge(true).await; }
            request(&mut l.cn, &l.us_node, &l.gz_node, &l.hk_node, 2).await;
            let a = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("approved, audited ingress");
            let b = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait).await.expect("approved, audited exit");
            let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("approved bridge");
            let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait).await.expect("approved requester trial");
            let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait).await.expect("approved peer trial");
            assert_eq!(cn["vni"], a["vni"]); assert_eq!(us["vni"], b["vni"]);
            assert_eq!(bridge["bridge"]["local_vni"], a["vni"]); assert_eq!(bridge["bridge"]["remote_vni"], b["vni"]);
            assert!(l.audit_reasons("mint").await.iter().any(|(reason,node)| reason == &format!("cross_border_edge:{}", l.hk_agent) && node == &l.gz_node));
        }
    }
}

/// Losing a required crossing approval must retire the whole actual trial;
/// the same policy edit must preserve an ordinary same-zone trial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_edge_approval_downgrade_revokes_only_actual_crossing() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    for (slug, mode, same_zone) in [("iso-trial-edge-enforce", "enforce", false),
        ("iso-trial-edge-off", "off", false), ("iso-trial-edge-local", "off", true)] {
        let mut l = LineRig::up_with_isolation(slug, true, mode).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
        let mut alternate = None;
        let mut target_agent = l.hk_agent.clone();
        let mut target_node = l.hk_node.clone();
        let mut endpoint = LINE.to_owned();
        if same_zone {
            let name = format!("{slug}-local");
            let (agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
            let mut ws = connect_from(&l.rig.app, &token, &["relay-server"], Some(CN_R)).await;
            assert_observed(&l.rig.app, &agent, Some(CN_R)).await;
            line_join(&mut ws, 12, "223.6.6.9:41641", json!({})).await;
            assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
            target_node = l.rig.node(&name).await;
            grant_relay(&l.rig.app, &l.rig.seeded, &target_node).await;
            target_agent = agent;
            endpoint = "10.69.0.2:3478".into();
            alternate = Some(ws);
        }
        let policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
        let set_edge = |cross: bool| json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":target_agent,"endpoint":endpoint,"cross_border":cross}]} );
        let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token, set_edge(true)).await;
        assert_eq!(status, 200, "{body}");
        l.cn.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
            "path":{"relay_node_ids":[l.gz_node,target_node]}, "requester_at_exit":false,"request_id":1}).to_string().into())).await.unwrap();
        let wait = Duration::from_secs(8);
        let source = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("trial ingress serve");
        let exit_ws = if same_zone { alternate.as_mut().unwrap() } else { &mut l.hk };
        let exit = recv_t(exit_ws, "rc:overlay.relay_serve", wait).await.expect("trial exit serve");
        let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("trial bridge");
        let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait).await.expect("requester start");
        let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait).await.expect("peer start");
        assert_eq!(cn["trial_id"], us["trial_id"]); assert_eq!(cn["vni"], source["vni"]); assert_eq!(us["vni"], exit["vni"]);
        assert_eq!(bridge["bridge"]["local_vni"], source["vni"]); assert_eq!(bridge["bridge"]["remote_vni"], exit["vni"]);
        let network = l.rig.app.state.network();
        let source_node = ObjectId::parse_str(&l.gz_node).unwrap();
        let exit_id = ObjectId::parse_str(&target_node).unwrap();
        assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
        assert_eq!(support::trial_slots_on_relay(network, exit_id), 1);
        let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token, set_edge(false)).await;
        assert_eq!(status, 200, "{body}");
        if same_zone {
            async fn no_retirement(ws: &mut Ws, label: &str) {
                let until = tokio::time::Instant::now() + Duration::from_millis(650);
                while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                    if let Message::Text(text) = message {
                        let v: Value = serde_json::from_str(&text).unwrap();
                        assert!(!["rc:overlay.path_trial_abort","rc:overlay.relay_revoke","rc:overlay.relay_bridge_revoke"].contains(&v["t"].as_str().unwrap_or_default()), "{label}: same-zone trial wrongly revoked");
                    }
                }
            }
            tokio::join!(no_retirement(&mut l.gz, slug), no_retirement(alternate.as_mut().unwrap(), slug),
                no_retirement(&mut l.cn, slug), no_retirement(&mut l.us, slug));
            assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
            assert_eq!(support::trial_slots_on_relay(network, exit_id), 1);
            // Removing the edge itself must still revoke the same-zone trial.
            let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[]})).await;
            assert_eq!(status, 200, "{body}");
        }
        let gz = recv_t(&mut l.gz, "rc:overlay.relay_revoke", wait).await.expect("ingress revoke");
        let exit_ws = if same_zone { alternate.as_mut().unwrap() } else { &mut l.hk };
        let end = recv_t(exit_ws, "rc:overlay.relay_revoke", wait).await.expect("exit revoke");
        let br = recv_t(&mut l.gz, "rc:overlay.relay_bridge_revoke", wait).await.expect("bridge revoke");
        let a = recv_t(&mut l.cn, "rc:overlay.path_trial_abort", wait).await.expect("requester abort");
        let b = recv_t(&mut l.us, "rc:overlay.path_trial_abort", wait).await.expect("peer abort");
        assert_eq!(gz["vni"], source["vni"]); assert_eq!(end["vni"], exit["vni"]);
        assert_eq!(br["trial_id"], cn["trial_id"]); assert_eq!(br["generation"], source["generation"]);
        assert_eq!(a["trial_id"], cn["trial_id"]); assert_eq!(b["trial_id"], cn["trial_id"]);
        assert_eq!(support::trial_slots_on_relay(network, source_node), 0); assert_eq!(support::trial_slots_on_relay(network, exit_id), 0);
    }
}

/// Trial relay-zone changes must be rechecked for Off as well as Enforce;
/// unchanged or restored zones must not tear down a healthy trial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_live_relay_zone_recheck_revokes_changes_not_stale_reads() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    for case in ["cross_to_same", "same_to_cross", "unknown", "stable", "race_restore", "read_healthy", "read_retry"] {
        let slug = format!("iso-trial-zone-live-{case}");
        let mut l = LineRig::up_with_isolation(&slug, true, "off").await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
        let originally_same = matches!(case, "same_to_cross" | "stable" | "race_restore" | "read_healthy" | "read_retry");
        let initial_ip = if originally_same { CN_R } else { US_R };
        let initial_endpoint = if originally_same { "223.6.6.9:41641" } else { "1.1.1.9:41641" };
        let name = format!("{slug}-exit");
        let (exit_agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
        let mut old_exit = connect_from(&l.rig.app, &token, &["relay-server"], Some(initial_ip)).await;
        assert_observed(&l.rig.app, &exit_agent, Some(initial_ip)).await;
        line_join(&mut old_exit, 12, initial_endpoint, json!({})).await;
        assert_eq!(approve(&l.rig.app, &l.rig.seeded, &exit_agent, true).await, 200);
        let exit_node = l.rig.node(&name).await;
        grant_relay(&l.rig.app, &l.rig.seeded, &exit_node).await;
        let policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
        let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":"10.70.0.2:3478","cross_border":!originally_same}]})).await;
        assert_eq!(status, 200, "{body}");
        l.cn.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
            "path":{"relay_node_ids":[l.gz_node,exit_node]}, "requester_at_exit":false,"request_id":1}).to_string().into())).await.unwrap();
        let wait = Duration::from_secs(8);
        let source = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await.expect("trial ingress serve");
        let exit = recv_t(&mut old_exit, "rc:overlay.relay_serve", wait).await.expect("trial exit serve");
        recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait).await.expect("trial bridge");
        let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait).await.expect("requester start");
        recv_t(&mut l.us, "rc:overlay.path_trial_start", wait).await.expect("peer start");
        let trial_id = ObjectId::parse_str(cn["trial_id"].as_str().unwrap()).unwrap();
        let network = l.rig.app.state.network();
        let source_node = ObjectId::parse_str(&l.gz_node).unwrap();
        let exit_node_id = ObjectId::parse_str(&exit_node).unwrap();
        assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
        let changed = match case { "cross_to_same" | "stable" | "read_healthy" => Some(CN_R), "same_to_cross" | "race_restore" | "read_retry" => Some(US_R), _ => None };
        let endpoint = if changed == Some(CN_R) { "223.6.6.9:41641" } else { "1.1.1.9:41641" };
        if matches!(case, "read_healthy" | "read_retry") { support::fail_next_trial_zone_read(trial_id); }
        let mut fresh = connect_from(&l.rig.app, &token, &["relay-server"], changed).await;
        async fn join_capture_revoke(ws: &mut Ws, endpoint: &str) -> Option<Value> {
            ws.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([12;32]), "mtu":1280,
                "endpoints":[endpoint], "supports_org_relay":true, "supports_server_relay_strategy":true,
                "relay_port":3478, "org_primary":true, "supports_derp":true, "supports_forced_derp":true}).to_string().into())).await.unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            let mut revoke = None;
            loop {
                let frame = tokio::time::timeout_at(deadline, ws.next()).await.expect("netmap after rejoin").expect("WS open").expect("WS message");
                if let Message::Text(text) = frame {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    if v["t"] == "rc:overlay.relay_revoke" { revoke = Some(v); }
                    else if v["t"] == "rc:overlay.netmap" { return revoke; }
                }
            }
        }
        let mut during_join = None;
        if case == "race_restore" {
            let (reached, resume) = support::pause_trial_zone_revoke(trial_id);
            fresh.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([12;32]), "mtu":1280,
                "endpoints":[endpoint], "supports_org_relay":true, "supports_server_relay_strategy":true,
                "relay_port":3478, "org_primary":true, "supports_derp":true, "supports_forced_derp":true}).to_string().into())).await.unwrap();
            tokio::time::timeout(wait, reached).await.expect("recheck paused before revoke").unwrap();
            // Restore the original zone on a replacement connection while the
            // previous mismatching snapshot is still paused.
            let mut restored = connect_from(&l.rig.app, &token, &["relay-server"], Some(CN_R)).await;
            line_join(&mut restored, 12, "223.6.6.9:41641", json!({})).await;
            resume.send(()).unwrap();
            fresh = restored;
        } else {
            during_join = join_capture_revoke(&mut fresh, endpoint).await;
        }
        if matches!(case, "stable" | "race_restore" | "read_healthy") {
            assert!(during_join.is_none(), "stable rejoin already received a revoke");
            async fn no_retirement(ws: &mut Ws, label: &str) {
                let until = tokio::time::Instant::now() + Duration::from_millis(800);
                while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                    if let Message::Text(text) = message {
                        let v: Value = serde_json::from_str(&text).unwrap();
                        assert!(!["rc:overlay.path_trial_abort","rc:overlay.relay_revoke","rc:overlay.relay_bridge_revoke"].contains(&v["t"].as_str().unwrap_or_default()), "{label}: healthy trial wrongly revoked");
                    }
                }
            }
            tokio::join!(no_retirement(&mut l.gz, &slug), no_retirement(&mut fresh, &slug),
                no_retirement(&mut l.cn, &slug), no_retirement(&mut l.us, &slug));
            assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
            assert_eq!(support::trial_slots_on_relay(network, exit_node_id), 1);
        } else {
            let source_revoke = recv_t(&mut l.gz, "rc:overlay.relay_revoke", wait).await.expect("ingress revoke");
            let exit_revoke = match during_join { Some(v) => v, None => recv_t(&mut fresh, "rc:overlay.relay_revoke", wait).await.expect("rejoined exit revoke") };
            let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_revoke", wait).await.expect("bridge revoke");
            let a = recv_t(&mut l.cn, "rc:overlay.path_trial_abort", wait).await.expect("requester abort");
            let b = recv_t(&mut l.us, "rc:overlay.path_trial_abort", wait).await.expect("peer abort");
            assert_eq!(source_revoke["vni"], source["vni"]); assert_eq!(exit_revoke["vni"], exit["vni"]);
            assert_eq!(bridge["trial_id"], cn["trial_id"]); assert_eq!(bridge["generation"], source["generation"]);
            assert_eq!(a["trial_id"], cn["trial_id"]); assert_eq!(b["trial_id"], cn["trial_id"]);
            assert_eq!(support::trial_slots_on_relay(network, source_node), 0);
            assert_eq!(support::trial_slots_on_relay(network, exit_node_id), 0);
        }
    }
}

/// Both relays can move while one asynchronous check is paused. A same-zone
/// relation alone is insufficient: each relay must retain its issued zone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_live_relay_zone_recheck_retires_two_relays_moving_together() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    let mut l = LineRig::up_with_isolation("iso-trial-both-move", true, "off").await;
    let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
    line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
    line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
    let (source_agent, source_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-trial-both-move-source").await;
    let (exit_agent, exit_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-trial-both-move-exit").await;
    let mut source = connect_from(&l.rig.app, &source_token, &["relay-server"], Some(CN_R)).await;
    let mut exit = connect_from(&l.rig.app, &exit_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &source_agent, Some(CN_R)).await;
    assert_observed(&l.rig.app, &exit_agent, Some(CN_R)).await;
    line_join(&mut source, 15, "223.6.6.10:41641", json!({"relay_backbone_ready":true})).await;
    line_join(&mut exit, 16, "223.6.6.11:41641", json!({})).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &source_agent, true).await, 200);
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &exit_agent, true).await, 200);
    let source_node = l.rig.node("iso-trial-both-move-source").await;
    let exit_node = l.rig.node("iso-trial-both-move-exit").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &source_node).await;
    grant_relay(&l.rig.app, &l.rig.seeded, &exit_node).await;
    let policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, source_agent);
    let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":"10.71.0.2:3478","cross_border":false}]})).await;
    assert_eq!(status, 200, "{body}");
    l.cn.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
        "path":{"relay_node_ids":[source_node,exit_node]}, "requester_at_exit":false,"request_id":1}).to_string().into())).await.unwrap();
    let wait = Duration::from_secs(8);
    let s = recv_t(&mut source, "rc:overlay.relay_serve", wait).await.expect("source serve");
    let e = recv_t(&mut exit, "rc:overlay.relay_serve", wait).await.expect("exit serve");
    recv_t(&mut source, "rc:overlay.relay_bridge_serve", wait).await.expect("bridge serve");
    let a = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait).await.expect("requester start");
    recv_t(&mut l.us, "rc:overlay.path_trial_start", wait).await.expect("peer start");
    let trial_id = ObjectId::parse_str(a["trial_id"].as_str().unwrap()).unwrap();
    let (reached, resume) = support::pause_trial_zone_revoke(trial_id);
    let mut exit_new = connect_from(&l.rig.app, &exit_token, &["relay-server"], Some(US_R)).await;
    exit_new.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([16;32]),"mtu":1280,
        "endpoints":["1.1.1.11:41641"],"supports_org_relay":true,"supports_server_relay_strategy":true,"relay_port":3478,"org_primary":true}).to_string().into())).await.unwrap();
    tokio::time::timeout(wait, reached).await.expect("exit-zone recheck paused").unwrap();
    let mut source_new = connect_from(&l.rig.app, &source_token, &["relay-server"], Some(US_R)).await;
    source_new.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([15;32]),"mtu":1280,
        "endpoints":["1.1.1.10:41641"],"supports_org_relay":true,"supports_server_relay_strategy":true,
        "relay_backbone_ready":true,"relay_port":3478,"org_primary":true}).to_string().into())).await.unwrap();
    let mut source_revoke = None; let mut bridge_revoke = None;
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let frame = tokio::time::timeout_at(deadline, source_new.next()).await.expect("source rejoin netmap").expect("source open").expect("source frame");
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["t"] == "rc:overlay.relay_revoke" { source_revoke = Some(value); }
            else if value["t"] == "rc:overlay.relay_bridge_revoke" { bridge_revoke = Some(value); }
            else if value["t"] == "rc:overlay.netmap" { break; }
        }
    }
    resume.send(()).unwrap();
    let source_revoke = match source_revoke { Some(v) => v, None => recv_t(&mut source_new, "rc:overlay.relay_revoke", wait).await.expect("both-moved source revoke") };
    let bridge_revoke = match bridge_revoke { Some(v) => v, None => recv_t(&mut source_new, "rc:overlay.relay_bridge_revoke", wait).await.expect("both-moved bridge revoke") };
    let exit_revoke = recv_t(&mut exit_new, "rc:overlay.relay_revoke", wait).await.expect("both-moved exit revoke");
    let ca = recv_t(&mut l.cn, "rc:overlay.path_trial_abort", wait).await.expect("requester abort");
    let cb = recv_t(&mut l.us, "rc:overlay.path_trial_abort", wait).await.expect("peer abort");
    assert_eq!(source_revoke["vni"], s["vni"]); assert_eq!(exit_revoke["vni"], e["vni"]);
    assert_eq!(bridge_revoke["trial_id"], a["trial_id"]); assert_eq!(bridge_revoke["generation"], s["generation"]);
    assert_eq!(ca["trial_id"], a["trial_id"]); assert_eq!(cb["trial_id"], a["trial_id"]);
    let network = l.rig.app.state.network();
    assert_eq!(support::trial_slots_on_relay(network, ObjectId::parse_str(source_node).unwrap()), 0);
    assert_eq!(support::trial_slots_on_relay(network, ObjectId::parse_str(exit_node).unwrap()), 0);
}

/// An explicit future trial path is independently reauthorized from live
/// members, relay gates and directed current policy; it sends no grants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_specified_trial_path_rechecks_all_nodes_and_edges() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    use roomler_ai_mod_network::org_relay::{OrgRelaySession, SessionMember, SessionParty};
    use roomler_ai_remote_control::models::{NodeRef, peer_relay_limits as limits};
    use std::time::Instant;

    let mut l = LineRig::up("iso-trial-path", true).await;
    let caps = json!({"supports_backbone_only_v1":true, "supports_path_trial_v1":true,
        "supports_path_backbone_v1":true});
    line_join(&mut l.cn, 1, "223.5.5.5:41641", caps.clone()).await;
    line_join(&mut l.us, 2, "8.8.8.8:41641", caps.clone()).await;
    let (mid_agent, mid_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-trial-path-mid").await;
    let mut mid = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(&mut mid, 5, "223.6.6.7:41641", json!({"relay_backbone_ready":true})).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await, 200);
    let mid_node = l.rig.node("iso-trial-path-mid").await;
    let mid_acl = grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let (transit_agent, transit_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-trial-path-transit").await;
    let mut transit = connect_from(&l.rig.app, &transit_token, &["relay-server"], Some(US_R)).await;
    assert_observed(&l.rig.app, &transit_agent, Some(US_R)).await;
    line_join(&mut transit, 6, "1.1.1.2:41641", json!({"relay_backbone_ready":true})).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &transit_agent, true).await, 200);
    let transit_node = l.rig.node("iso-trial-path-transit").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &transit_node).await;
    let policy_path = |agent: &str| format!("/api/tenant/{}/agent/{agent}/peer-relay-policy", l.rig.seeded.tenant_id);
    let set_edge = |target: &str, endpoint: &str, cross_border| json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":target,"endpoint":endpoint,"cross_border":cross_border} ]});
    for (agent, target, endpoint, cross) in [
        (&l.gz_agent, &mid_agent, "10.71.0.2:3478", false),
        (&mid_agent, &transit_agent, "10.71.0.3:3478", true),
        (&transit_agent, &l.hk_agent, "10.71.0.4:3478", false),
    ] {
        let (status, body) = put(&l.rig.app, &policy_path(agent), &l.rig.seeded.admin.access_token,
            set_edge(target, endpoint, cross)).await;
        assert_eq!(status, 200, "{body}");
    }
    let network = l.rig.app.state.network();
    let a = ObjectId::parse_str(&l.cn_node).unwrap();
    let b = ObjectId::parse_str(&l.us_node).unwrap();
    let nodes: Vec<_> = [&l.gz_node, &mid_node, &transit_node, &l.hk_node].into_iter()
        .map(|id| ObjectId::parse_str(id).unwrap()).collect();
    let snapshot = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.expect("approved four-relay path");
    assert!(snapshot.locally_current(network));
    assert_eq!(snapshot.edges(), vec![
        (nodes[0], nodes[1], "10.71.0.2:3478".into(), false),
        (nodes[1], nodes[2], "10.71.0.3:3478".into(), true),
        (nodes[2], nodes[3], "10.71.0.4:3478".into(), false),
    ]);
    assert!(support::reauthorize_trial_path_fixture(network, a, b, &snapshot).await.is_ok());
    assert!(support::plan_trial_path_fixture(network, b, a, nodes.clone(), true).await.is_ok(), "requester at exit");
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), true).await.is_err(), "member zone orientation");
    assert!(support::plan_trial_path_fixture(network, a, b, vec![nodes[0], nodes[2], nodes[1], nodes[3]], false).await.is_err(), "missing directed edges");
    assert!(support::plan_trial_path_fixture(network, a, b, vec![nodes[0], nodes[1], nodes[1], nodes[3]], false).await.is_err(), "repeated node");
    assert!(support::plan_trial_path_fixture(network, a, b, vec![nodes[0], ObjectId::new(), nodes[3]], false).await.is_err(), "unregistered middle node");

    // A real member rejoin with a different public key cannot inherit the
    // previous snapshot, even if the same relay identities remain approved.
    line_join(&mut l.us, 9, "8.8.8.8:41641", caps.clone()).await;
    assert!(support::reauthorize_trial_path_fixture(network, a, b, &snapshot).await.is_err(), "changed member key");
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_ok(), "current member identity can plan");
    line_join(&mut l.us, 2, "8.8.8.8:41641", caps.clone()).await;
    let snapshot = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.expect("original member key restored");

    // A current approved edge change must invalidate its old endpoint, while a
    // fresh plan may use only the newly approved endpoint.
    let (status, body) = put(&l.rig.app, &policy_path(&mid_agent), &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.33:3478", true)).await;
    assert_eq!(status, 200, "{body}");
    assert!(!snapshot.locally_current(network), "policy update changes epoch");
    assert!(support::reauthorize_trial_path_fixture(network, a, b, &snapshot).await.is_err(), "stale private edge endpoint");
    let fresh = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.expect("new endpoint approved");
    assert_eq!(fresh.edges()[1].2, "10.71.0.33:3478");
    let (status, body) = put(&l.rig.app, &policy_path(&mid_agent), &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.3:3478", false)).await;
    assert_eq!(status, 200, "{body}");
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_err(), "unapproved crossing");
    let (status, body) = put(&l.rig.app, &policy_path(&mid_agent), &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.3:3478", true)).await;
    assert_eq!(status, 200, "{body}");

    line_join(&mut mid, 5, "223.6.6.7:41641", json!({"relay_backbone_ready":false})).await;
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_err(), "middle bridge readiness withdrawn");
    line_join(&mut mid, 5, "223.6.6.7:41641", json!({"relay_backbone_ready":true})).await;
    line_join(&mut l.us, 2, "8.8.8.8:41641", json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true})).await;
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_err(), "peer trial capability withdrawn");
    line_join(&mut l.us, 2, "8.8.8.8:41641", caps).await;
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &mid_agent, false).await, 200);
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_err(), "middle approval withdrawn");
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await, 200);
    let (status, body) = put(&l.rig.app, &policy_path(&mid_agent), &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.3:3478", true)).await;
    assert_eq!(status, 200, "{body}");
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_ok(), "approval and edge restored");

    // Remove the middle relay's both-member grant, then grant only A.
    let acl_path = format!("/api/tenant/{}/overlay-acl/{mid_acl}", l.rig.seeded.tenant_id);
    let status = l.rig.app.client.delete(l.rig.app.url(&acl_path)).bearer_auth(&l.rig.seeded.admin.access_token)
        .send().await.unwrap().status().as_u16();
    assert_eq!(status, 200);
    let acl_collection = format!("/api/tenant/{}/overlay-acl", l.rig.seeded.tenant_id);
    let only_a = l.rig.app.auth_post(&acl_collection, &l.rig.seeded.admin.access_token).json(&json!({
        "name":"trial middle requester only", "sources":[{"kind":"node_id","id":l.cn_node}],
        "via":[{"kind":"node_id","id":mid_node}], "destinations":[{"cidr":"100.64.0.0/10"}]
    })).send().await.unwrap();
    assert!(only_a.status().is_success());
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_err(), "peer lacks middle relay ACL");
    grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let before_capacity = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.expect("restored path");
    let tenant = ObjectId::parse_str(&l.rig.seeded.tenant_id).unwrap();
    let mid_agent_id = ObjectId::parse_str(&mid_agent).unwrap();
    let party = |id| SessionParty { node_id:id, node_ref:NodeRef::Agent { agent_id:id } };
    let member = |id| SessionMember { party:party(id), wg_public_key:"fixture".into(), bind_secret:"fixture".into() };
    let mut keys = Vec::new();
    for i in 0..limits::MAX_SESSIONS_PER_RELAY {
        let key = format!("specified-trial-capacity-{i}");
        let fixture = OrgRelaySession {
            tenant_id:tenant, pair_key:key.clone(), vni:i as u32+1000, generation:i as u64+1000,
            relay:SessionParty { node_id:nodes[1], node_ref:NodeRef::Agent { agent_id:mid_agent_id } },
            relay_agent_id:mid_agent_id, implicit:false, members:[member(ObjectId::new()), member(ObjectId::new())],
            endpoints:vec!["fixture".into()], expires_at:Instant::now()+Duration::from_secs(90),
            bind_by:Instant::now()+Duration::from_secs(30), hops:Vec::new(),
        };
        assert!(support::insert_session_fixture(network, fixture)); keys.push(key);
    }
    assert!(!before_capacity.locally_current(network), "capacity is rechecked separately from epoch");
    assert!(support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.is_err(), "middle relay full");
    for key in keys { assert!(support::remove_session_fixture(network, &key)); }
    let before_delete = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false).await.expect("capacity restored");
    assert!(network.overlay_nodes.base.soft_delete(b).await.unwrap());
    assert!(support::plan_trial_path_fixture(network, a, b, nodes, false).await.is_err(), "tombstoned peer must not be accepted");
    assert!(support::reauthorize_trial_path_fixture(network, a, b, &before_delete).await.is_err(), "tombstoned peer cannot reauthorize");
    let pair = roomler_ai_mod_network::overlay::pair_key(a, b);
    assert!(network.org_relay.active_session(&pair).is_none(), "planning must not mint a session");
    assert!(l.audit_reasons("mint").await.is_empty());
    for ws in [&mut l.gz, &mut mid, &mut transit, &mut l.hk] {
        assert!(recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(250)).await.is_none(), "planning must not send grants");
    }
}

/// Warn/Off isolation graph construction may retain crossing metadata. The
/// trial planner itself must still require explicit approval of every crossing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_specified_trial_path_denies_unapproved_crossing_outside_enforce() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    for mode in ["off", "warn"] {
        let slug = format!("iso-trial-cross-{mode}");
        let rig = Rig::up(&slug, mode).await;
        let (left_agent, left_token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-left")).await;
        let mut left = connect_from(&rig.app, &left_token, &["relay-server"], Some(CN_R)).await;
        assert_observed(&rig.app, &left_agent, Some(CN_R)).await;
        line_join(&mut left, 3, "223.6.6.6:41641", json!({"relay_backbone_ready":true})).await;
        let (right_agent, right_token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-right")).await;
        let mut right = connect_from(&rig.app, &right_token, &["relay-server"], Some(US_R)).await;
        assert_observed(&rig.app, &right_agent, Some(US_R)).await;
        line_join(&mut right, 4, "1.1.1.1:41641", json!({})).await;
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig.device(&format!("{slug}-b"), Some(US_A)).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_trial_v1":true,"supports_path_backbone_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut b, 2, "8.8.8.8:41641", flags).await;
        set_mode(&rig.app, &rig.seeded, "on").await;
        assert_eq!(approve(&rig.app, &rig.seeded, &left_agent, true).await, 200);
        assert_eq!(approve(&rig.app, &rig.seeded, &right_agent, true).await, 200);
        let left_node = rig.node(&format!("{slug}-left")).await;
        let right_node = rig.node(&format!("{slug}-right")).await;
        grant_relay(&rig.app, &rig.seeded, &left_node).await;
        grant_relay(&rig.app, &rig.seeded, &right_node).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        let nodes = vec![ObjectId::parse_str(left_node).unwrap(), ObjectId::parse_str(right_node).unwrap()];
        let policy = format!("/api/tenant/{}/agent/{left_agent}/peer-relay-policy", rig.seeded.tenant_id);
        let net = rig.app.state.network();
        for cross in [false, true] {
            let (status, body) = put(&rig.app, &policy, &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":right_agent,"endpoint":"10.72.0.2:3478","cross_border":cross}]})).await;
            assert_eq!(status, 200, "{body}");
            let planned = support::plan_trial_path_fixture(net, a_id, b_id, nodes.clone(), false).await;
            assert_eq!(planned.is_ok(), cross, "{mode}: crossing approval required");
        }
    }
}

/// Exercise the actual WS trial endpoint with an exact, directed multi-hop
/// path, both member orientations, bilateral commit/return, and revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_nhop_trial_actual_lifecycle_and_rollback() {
    use roomler_ai_mod_network::org_relay::candidate_test_support::{self as support, TrialCrossingAuditFault};
    async fn control(ws: &mut Ws, kind: &str, trial: &Value, return_id: Option<&str>) {
        let mut msg = json!({"t":kind,"trial_id":trial});
        if let Some(id) = return_id { msg["return_id"] = json!(id); }
        ws.send(Message::Text(msg.to_string().into())).await.unwrap();
    }
    for (length, flipped, outcome) in [(3, false, "abort"), (4, true, "return"),
        (4, false, "edge"), (4, false, "audit"), (4, false, "approval"), (4, false, "zone")] {
        let slug = format!("iso-nhop-trial-{length}-{outcome}");
        let mut l = LineRig::up(&slug, true).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
        let mut extras = Vec::new(); let mut extra_agents = Vec::new(); let mut extra_nodes = Vec::new(); let mut extra_tokens = Vec::new();
        for i in 0..length-2 {
            let name = format!("{slug}-middle-{i}");
            let (agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
            let from = if length == 3 || i % 2 == 1 { CN_R } else { US_R };
            let mut ws = connect_from(&l.rig.app, &token, &["relay-server"], Some(from)).await;
            assert_observed(&l.rig.app, &agent, Some(from)).await;
            let endpoint = if from == CN_R { format!("223.6.6.{}:41641", 7+i) } else { format!("1.1.1.{}:41641",2+i) };
            line_join(&mut ws, 10+i as u8, &endpoint, json!({"relay_backbone_ready":true})).await;
            assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
            let node = l.rig.node(&name).await; grant_relay(&l.rig.app, &l.rig.seeded, &node).await;
            extras.push(ws); extra_agents.push(agent); extra_nodes.push(node); extra_tokens.push(token);
        }
        let mut agents = vec![l.gz_agent.clone()]; agents.extend(extra_agents); agents.push(l.hk_agent.clone());
        let mut nodes = vec![l.gz_node.clone()]; nodes.extend(extra_nodes); nodes.push(l.hk_node.clone());
        let mut relays = vec![l.gz]; relays.extend(extras); relays.push(l.hk);
        let endpoints: Vec<_> = (0..length-1).map(|i| format!("10.73.0.{}:3478",i+2)).collect();
        let crosses: Vec<_> = (0..length-1).map(|i| length == 4 || i == 1).collect();
        let policy = |source: &str| format!("/api/tenant/{}/agent/{source}/peer-relay-policy", l.rig.seeded.tenant_id);
        for i in 0..length-1 {
            let approved = crosses[i] && !(outcome == "approval" && i == 1);
            let (status, body) = put(&l.rig.app, &policy(&agents[i]), &l.rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],"endpoint":endpoints[i],"cross_border":approved}]})).await;
            assert_eq!(status, 200, "{body}");
        }
        let network = l.rig.app.state.network();
        let cn = ObjectId::parse_str(&l.cn_node).unwrap(); let us = ObjectId::parse_str(&l.us_node).unwrap();
        let pair = roomler_ai_mod_network::overlay::pair_key(cn, us);
        let ids: Vec<_> = nodes.iter().map(|id| ObjectId::parse_str(id).unwrap()).collect();
        if outcome == "audit" { support::fail_next_trial_crossing_audit(pair, TrialCrossingAuditFault::Error); }
        let request = json!({"t":"rc:overlay.path_trial_request", "peer_node_id":if flipped {&l.cn_node} else {&l.us_node},
            "request_id":1, "path":{"relay_node_ids":nodes}, "requester_at_exit":flipped});
        if flipped { l.us.send(Message::Text(request.to_string().into())).await.unwrap(); }
        else { l.cn.send(Message::Text(request.to_string().into())).await.unwrap(); }
        let wait = Duration::from_secs(8);
        if outcome == "audit" || outcome == "approval" {
            for ws in &mut relays { assert!(recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(500)).await.is_none(), "{slug}: rejected path emitted serve"); }
            assert!(recv_t(&mut l.cn, "rc:overlay.path_trial_start", Duration::from_millis(500)).await.is_none());
            assert!(recv_t(&mut l.us, "rc:overlay.path_trial_start", Duration::from_millis(500)).await.is_none());
            for id in &ids { assert_eq!(support::trial_slots_on_relay(network, *id), 0, "{slug}: leaked trial slot"); }
            continue;
        }
        let mut serves = Vec::new();
        for ws in &mut relays { serves.push(recv_t(ws, "rc:overlay.relay_serve", wait).await.expect("trial relay serve")); }
        let mut bridges = Vec::new();
        for ws in relays.iter_mut().take(length-1) { bridges.push(recv_t(ws, "rc:overlay.relay_bridge_serve", wait).await.expect("trial bridge")); }
        let a = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait).await.expect("CN trial start");
        let b = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait).await.expect("US trial start");
        assert_eq!(a["trial_id"], b["trial_id"]); assert_eq!(a["path"]["relay_node_ids"], json!(nodes)); assert_eq!(b["path"], a["path"]);
        assert_eq!(a["requester_at_exit"], json!(flipped)); assert_eq!(b["requester_at_exit"], json!(flipped));
        assert_eq!(a["vni"], serves[0]["vni"]); assert_eq!(b["vni"], serves[length-1]["vni"]);
        for i in 0..length-1 {
            assert_eq!(bridges[i]["bridge"]["local_vni"], serves[i]["vni"]);
            assert_eq!(bridges[i]["bridge"]["remote_vni"], serves[i+1]["vni"]);
        }
        for id in &ids { assert_eq!(support::trial_slots_on_relay(network, *id), 1); }
        let audits = audit_rows(&l.rig.app, &l.rig.seeded).await;
        for i in 0..length-1 { if crosses[i] {
            let reason = format!("cross_border_edge:{}", agents[i+1]);
            assert!(audits.iter().any(|row| row["reason"] == reason && row["relay_node_id"] == nodes[i]), "{slug}: missing crossing audit {i}");
        }}
        let mut rejoin_controls = Vec::new();
        if outcome == "abort" {
            control(&mut l.cn, "rc:overlay.path_trial_abort", &a["trial_id"], None).await;
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_abort", wait).await.expect("member abort"); }
        } else if outcome == "zone" {
            // The first middle relay was US; reconnect the same identity in
            // CN. The actual four-relay trial must be retired on every leg.
            let mut moved = connect_from(&l.rig.app, &extra_tokens[0], &["relay-server"], Some(CN_R)).await;
            moved.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([10;32]), "mtu":1280,
                "endpoints":["223.6.6.7:41641"], "supports_org_relay":true, "supports_server_relay_strategy":true,
                "relay_port":3478, "org_primary":true, "relay_backbone_ready":true}).to_string().into())).await.unwrap();
            let until = tokio::time::Instant::now()+wait;
            loop {
                let frame = tokio::time::timeout_at(until, moved.next()).await.expect("middle netmap").expect("middle open").expect("middle frame");
                if let Message::Text(text) = frame {
                    let value:Value=serde_json::from_str(&text).unwrap();
                    if value["t"]=="rc:overlay.netmap" {break;}
                    if value["t"]=="rc:overlay.relay_revoke" || value["t"]=="rc:overlay.relay_bridge_revoke" {rejoin_controls.push(value);}
                }
            }
            relays[1]=moved;
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_abort", wait).await.expect("zone change abort"); }
        } else if outcome == "edge" {
            let i=1;
            let (status, body) = put(&l.rig.app, &policy(&agents[i]), &l.rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],"endpoint":endpoints[i],"cross_border":false}]})).await;
            assert_eq!(status, 200, "{body}");
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_abort", wait).await.expect("edge withdrawal abort"); }
        } else {
            for ws in [&mut l.cn, &mut l.us] { control(ws, "rc:overlay.path_trial_ready", &a["trial_id"], None).await; }
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_commit", wait).await.expect("bilateral commit"); }
            for ws in [&mut l.cn, &mut l.us] { control(ws, "rc:overlay.path_trial_committed", &a["trial_id"], None).await; }
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_finalize", wait).await.expect("bilateral finalize"); }
            let return_id = ObjectId::new().to_hex();
            control(&mut l.cn, "rc:overlay.path_trial_return_request", &a["trial_id"], Some(&return_id)).await;
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_return_prepare", wait).await.expect("return prepare"); }
            for ws in [&mut l.cn, &mut l.us] { control(ws, "rc:overlay.path_trial_return_ready", &a["trial_id"], Some(&return_id)).await; }
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_return_commit", wait).await.expect("return commit"); }
            control(&mut l.cn, "rc:overlay.path_trial_returned", &a["trial_id"], Some(&return_id)).await;
            for id in &ids { assert_eq!(support::trial_slots_on_relay(network, *id), 1, "one member cannot retire relays"); }
            control(&mut l.us, "rc:overlay.path_trial_returned", &a["trial_id"], Some(&return_id)).await;
            for ws in [&mut l.cn, &mut l.us] { recv_t(ws, "rc:overlay.path_trial_return_finalize", wait).await.expect("return finalize"); }
        }
        for (i, ws) in relays.iter_mut().enumerate() {
            let captured=if i==1 && outcome=="zone" {rejoin_controls.iter().find(|v|v["t"]=="rc:overlay.relay_revoke").cloned()}else{None};
            let revoke=match captured {Some(v)=>v,None=>recv_t(ws, "rc:overlay.relay_revoke", wait).await.expect("every relay retired")};
            assert_eq!(revoke["vni"], serves[i]["vni"]);
        }
        for (i, ws) in relays.iter_mut().take(length-1).enumerate() {
            let captured=if i==1 && outcome=="zone" {rejoin_controls.iter().find(|v|v["t"]=="rc:overlay.relay_bridge_revoke").cloned()}else{None};
            let revoke=match captured {Some(v)=>v,None=>recv_t(ws, "rc:overlay.relay_bridge_revoke", wait).await.expect("every bridge retired")};
            assert_eq!(revoke["trial_id"], bridges[i]["bridge"]["trial_id"]);
            assert_eq!(revoke["generation"], serves[i]["generation"]);
        }
        for id in &ids { assert_eq!(support::trial_slots_on_relay(network, *id), 0, "every trial slot released"); }
    }
}

/// Cross-zone cursor pages must traverse freshly authorized lines, not the
/// Pair-scope one-relay planner that rejects cross-zone endpoints.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_cross_zone_discovery_paginates_and_rechecks_approvals() {
    let mut l = LineRig::up("iso-cross-page", true).await;
    let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,
        "supports_path_trial_v1":true,"supports_org_relay_multi_candidate":true,
        "supports_org_relay_discovery_cursor":true});
    line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
    line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
    let mut agents = vec![l.hk_agent.clone()];
    let mut ids = vec![l.hk_node.clone()];
    let mut relays = Vec::new();
    for i in 0..4 {
        let name = format!("iso-cross-page-exit-{i}");
        let (agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
        let mut ws = connect_from(&l.rig.app, &token, &["relay-server"], Some(US_R)).await;
        assert_observed(&l.rig.app, &agent, Some(US_R)).await;
        line_join(&mut ws, 10 + i, &format!("1.1.1.{}:41641", i + 2), json!({})).await;
        assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
        let id = l.rig.node(&name).await;
        grant_relay(&l.rig.app, &l.rig.seeded, &id).await;
        agents.push(agent); ids.push(id); relays.push(ws);
    }
    let policy = format!("/api/tenant/{}/agent/{}/peer-relay-policy", l.rig.seeded.tenant_id, l.gz_agent);
    let make_edges = |agents: &[String]| agents.iter().enumerate().map(|(i, id)|
        json!({"relay_agent_id":id,"endpoint":format!("10.61.0.{}:3478",i+2),"cross_border":true})).collect::<Vec<_>>();
    let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":make_edges(&agents)})).await;
    assert_eq!(status, 200, "{body}");
    async fn page(ws: &mut Ws, peer: &str, serial: u64, cursor: Option<Value>) -> Value {
        let mut req = json!({"t":"rc:overlay.org_relay_discover", "peer_node_id":peer, "request_id":serial});
        if let Some(c) = cursor { req["cursor"] = c; }
        ws.send(Message::Text(req.to_string().into())).await.unwrap();
        let result = recv_t(ws, "rc:overlay.org_relay_candidates", Duration::from_secs(8)).await.expect("discovery response");
        assert_eq!(result["request_id"], serial); result
    }
    let mut result = page(&mut l.cn, &l.us_node, 1, None).await;
    assert_eq!(result["candidates"].as_array().unwrap().len(), 2, "preferred first page");
    let mut seen = BTreeSet::new();
    for serial in 2..=3 {
        for c in result["candidates"].as_array().unwrap() {
            assert_eq!(c["path"]["relay_node_ids"][0], l.gz_node);
            seen.insert(c["path"]["relay_node_ids"][1].as_str().unwrap().to_owned());
        }
        let cursor = result["next_cursor"].clone();
        assert!(cursor.is_object(), "cross-zone cursor missing: {result}");
        result = page(&mut l.cn, &l.us_node, serial, Some(cursor)).await;
        assert!(result["candidates"].as_array().unwrap().len() <= 3);
    }
    for c in result["candidates"].as_array().unwrap() { seen.insert(c["path"]["relay_node_ids"][1].as_str().unwrap().to_owned()); }
    assert_eq!(seen, ids.iter().cloned().collect(), "all five approved exits should be discoverable");
    let removed = ids[0].clone();
    let pair = roomler_ai_mod_network::overlay::pair_key(ObjectId::parse_str(&l.cn_node).unwrap(), ObjectId::parse_str(&l.us_node).unwrap());
    let (reached, resume) = roomler_ai_mod_network::org_relay::candidate_test_support::pause_cross_discovery_fixture(pair.clone());
    l.cn.send(Message::Text(json!({"t":"rc:overlay.org_relay_discover", "peer_node_id":l.us_node,
        "request_id":4, "cursor":result["next_cursor"]}).to_string().into())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), reached).await.expect("discovery page reached final fence").unwrap();
    let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":make_edges(&agents[1..])})).await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    let stale = recv_t(&mut l.cn, "rc:overlay.org_relay_candidates", Duration::from_secs(8)).await.expect("fenced page response");
    assert_eq!(stale["request_id"], 4);
    assert!(stale["candidates"].as_array().unwrap().is_empty(), "concurrent withdrawal must discard the old snapshot");
    let after = page(&mut l.cn, &l.us_node, 5, Some(result["next_cursor"].clone())).await;
    assert!(after["candidates"].as_array().unwrap().iter().all(|c| c["path"]["relay_node_ids"][1] != removed), "withdrawn edge remains in page");
    assert!(!after["candidates"].as_array().unwrap().is_empty(), "other approved lines remain available");
    assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agents[1], false).await, 200);
    let after_approval = page(&mut l.cn, &l.us_node, 6, Some(after["next_cursor"].clone())).await;
    assert!(after_approval["candidates"].as_array().unwrap().iter().all(|c| c["path"]["relay_node_ids"][1] != ids[1]), "unapproved relay remains in page");
    assert!(l.rig.app.state.network().org_relay.active_session(&pair).is_none(), "discovery must not mint");
    assert!(l.audit_reasons("mint").await.is_empty(), "discovery must not audit a mint");
    for ws in [&mut l.gz, &mut l.hk] { assert!(recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(250)).await.is_none()); }
    for ws in &mut relays { assert!(recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(250)).await.is_none()); }
}

/// Off/Warn must not add a member-to-endpoint zone gate at either path length.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_nhop_trial_off_warn_endpoint_zone_parity_two_and_three() {
    use roomler_ai_mod_network::org_relay::candidate_test_support as support;
    for isolation in ["off", "warn"] {
        let slug = format!("iso-trial-endpoint-parity-{isolation}");
        let rig = Rig::up(&slug, isolation).await;
        let mut relays = Vec::new(); let mut agents = Vec::new(); let mut nodes = Vec::new();
        for i in 0..3 {
            let name = format!("{slug}-r{i}"); let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(US_R)).await;
            assert_observed(&rig.app, &agent, Some(US_R)).await;
            line_join(&mut ws, 10+i, &format!("1.1.1.{}:41641", i+1), json!({"relay_backbone_ready":true})).await;
            assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
            let node = rig.node(&name).await; grant_relay(&rig.app, &rig.seeded, &node).await;
            relays.push(ws); agents.push(agent); nodes.push(node);
        }
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig.device(&format!("{slug}-b"), if isolation == "warn" { None } else { Some(CN_A) }).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut b, 2, "223.5.5.6:41641", flags).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        set_mode(&rig.app, &rig.seeded, "on").await;
        let path = |agent: &str| format!("/api/tenant/{}/agent/{agent}/peer-relay-policy", rig.seeded.tenant_id);
        let (status, body) = put(&rig.app, &path(&agents[0]), &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[
                {"relay_agent_id":agents[1],"endpoint":"10.74.0.2:3478","cross_border":false},
                {"relay_agent_id":agents[2],"endpoint":"10.74.0.3:3478","cross_border":false}]})).await;
        assert_eq!(status, 200, "{body}");
        let (status, body) = put(&rig.app, &path(&agents[1]), &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[2],"endpoint":"10.74.0.4:3478","cross_border":false}]})).await;
        assert_eq!(status, 200, "{body}");
        let network = rig.app.state.network(); let ids: Vec<_> = nodes.iter().map(|n| ObjectId::parse_str(n).unwrap()).collect();
        for (serial, indexes, flipped) in [(1, vec![0,2], false), (2, vec![0,1,2], true)] {
            let path_nodes: Vec<_> = indexes.iter().map(|&i| nodes[i].clone()).collect();
            let request = json!({"t":"rc:overlay.path_trial_request", "peer_node_id":if flipped {a_id.to_hex()} else {b_id.to_hex()},
                "request_id":serial,"path":{"relay_node_ids":path_nodes},"requester_at_exit":flipped});
            if flipped { b.send(Message::Text(request.to_string().into())).await.unwrap(); }
            else { a.send(Message::Text(request.to_string().into())).await.unwrap(); }
            let wait = Duration::from_secs(8); let mut serves = Vec::new();
            for &i in &indexes { serves.push(recv_t(&mut relays[i], "rc:overlay.relay_serve", wait).await.expect("off/warn endpoint-mismatch serve")); }
            let mut bridges = Vec::new();
            for &i in indexes.iter().take(indexes.len()-1) { bridges.push(recv_t(&mut relays[i], "rc:overlay.relay_bridge_serve", wait).await.expect("endpoint-mismatch bridge")); }
            let sa = recv_t(&mut a, "rc:overlay.path_trial_start", wait).await.expect("a start");
            let sb = recv_t(&mut b, "rc:overlay.path_trial_start", wait).await.expect("b start");
            assert_eq!(sa["trial_id"], sb["trial_id"]); assert_eq!(sa["vni"], serves[0]["vni"]); assert_eq!(sb["vni"], serves.last().unwrap()["vni"]);
            for &i in &indexes { assert_eq!(support::trial_slots_on_relay(network, ids[i]), 1); }
            a.send(Message::Text(json!({"t":"rc:overlay.path_trial_abort","trial_id":sa["trial_id"]}).to_string().into())).await.unwrap();
            for ws in [&mut a, &mut b] { recv_t(ws, "rc:overlay.path_trial_abort", wait).await.expect("abort"); }
            for (position, &i) in indexes.iter().enumerate() { let revoke=recv_t(&mut relays[i], "rc:overlay.relay_revoke", wait).await.expect("relay revoke"); assert_eq!(revoke["vni"], serves[position]["vni"]); }
            for (position, &i) in indexes.iter().take(indexes.len()-1).enumerate() { let revoke=recv_t(&mut relays[i], "rc:overlay.relay_bridge_revoke", wait).await.expect("bridge revoke"); assert_eq!(revoke["trial_id"], bridges[position]["bridge"]["trial_id"]); }
            for &i in &indexes { assert_eq!(support::trial_slots_on_relay(network, ids[i]), 0); }
        }
    }
}
/// Fixture-owned four-relay trial: recheck every middle relay and member on
/// real WebSocket rejoin, and inspect all generated revocation frames. This
/// inserts trial state without issuing grants; real trial admission is separate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_nhop_trial_zone_fixture_rechecks_middle_and_members() {
    use roomler_ai_mod_network::org_relay::{candidate_test_support as support, LineLeg, OrgRelaySession, SessionMember, SessionParty};
    use roomler_ai_remote_control::models::NodeRef;
    use roomler_core::business_authority::BusinessZone::Mainland;
    use std::time::Instant;
    for case in ["changed", "unknown", "stable", "race_restore", "member_changed", "unconstrained_member"] {
        let slug = format!("iso-nhop-zone-{case}");
        let rig = Rig::up(&slug, "off").await;
        let mut relays = Vec::new(); let mut relay_tokens = Vec::new();
        let mut agent_ids = Vec::new(); let mut node_ids = Vec::new();
        for i in 0..4 {
            let name = format!("{slug}-r{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(CN_R)).await;
            assert_observed(&rig.app, &agent, Some(CN_R)).await;
            line_join(&mut ws, 10 + i, &format!("223.6.6.{}:41641",10 + i), json!({"relay_backbone_ready":true})).await;
            assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
            let node = rig.node(&name).await; grant_relay(&rig.app, &rig.seeded, &node).await;
            agent_ids.push(ObjectId::parse_str(agent).unwrap()); node_ids.push(ObjectId::parse_str(node).unwrap());
            relay_tokens.push(token); relays.push(ws);
        }
        let (a_agent, a_token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-a")).await;
        let (b_agent, b_token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-b")).await;
        let mut a = connect_from(&rig.app, &a_token, &[], Some(CN_A)).await;
        let mut b = connect_from(&rig.app, &b_token, &[], Some(CN_A)).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut b, 2, "223.5.5.6:41641", flags.clone()).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        let now = Instant::now();
        let member = |node_id, agent: &str, seed| SessionMember {
            party: SessionParty { node_id, node_ref: NodeRef::Agent { agent_id:ObjectId::parse_str(agent).unwrap() } },
            wg_public_key:BASE64.encode([seed;32]), bind_secret:"fixture-secret".into(),
        };
        let mut session = OrgRelaySession {
            tenant_id:ObjectId::parse_str(&rig.seeded.tenant_id).unwrap(),
            pair_key:roomler_ai_mod_network::overlay::pair_key(a_id,b_id),
            vni:101, generation:201, relay:SessionParty { node_id:node_ids[0], node_ref:NodeRef::Agent{agent_id:agent_ids[0]} },
            relay_agent_id:agent_ids[0], implicit:false,
            members:[member(a_id,&a_agent,1),member(b_id,&b_agent,2)],
            endpoints:vec!["223.6.6.10:3478".into()], expires_at:now+Duration::from_secs(600),
            bind_by:now+Duration::from_secs(60), hops:Vec::new(),
        };
        for i in 1..4 {
            session.hops.push(LineLeg {
                relay:SessionParty { node_id:node_ids[i], node_ref:NodeRef::Agent{agent_id:agent_ids[i]} },
                relay_agent_id:agent_ids[i], vni:101+i as u32, generation:201+i as u64,
                endpoints:vec![format!("223.6.6.{}:3478",10+i)], private_endpoint:format!("10.72.0.{}:3478",i+1),
                requires_cross_border_approval:false, bridge_id:ObjectId::new(), bridge_secrets:["fixture-a".into(),"fixture-b".into()],
            });
        }
        let network = rig.app.state.network();
        let constrained = if case == "unconstrained_member" { None } else { Some([Mainland;2]) };
        let trial_id = support::insert_nhop_zone_trial_fixture(network, session.clone(), vec![Mainland;4], constrained);
        for id in &node_ids { assert_eq!(support::trial_slots_on_relay(network,*id),1); }
        async fn join_collect(ws:&mut Ws, seed:u8, endpoint:&str, ready:bool, path:bool)->Vec<Value> {
            ws.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([seed;32]),"mtu":1280,
                "endpoints":[endpoint],"supports_org_relay":true,"supports_server_relay_strategy":true,"relay_port":3478,"org_primary":true,
                "relay_backbone_ready":ready,"supports_backbone_only_v1":path,"supports_path_backbone_v1":path,"supports_path_trial_v1":path}).to_string().into())).await.unwrap();
            let until=tokio::time::Instant::now()+Duration::from_secs(8);let mut controls=Vec::new();
            loop {let msg=tokio::time::timeout_at(until,ws.next()).await.expect("join netmap").expect("connection").expect("frame");
                if let Message::Text(text)=msg {let value:Value=serde_json::from_str(&text).unwrap();
                    if value["t"]=="rc:overlay.netmap" {return controls;}
                    if ["rc:overlay.relay_revoke","rc:overlay.relay_bridge_revoke","rc:overlay.path_trial_abort"].contains(&value["t"].as_str().unwrap_or_default()) {controls.push(value);}
                }}
        }
        let mut before_netmap = Vec::new();
        if matches!(case, "member_changed" | "unconstrained_member") {
            let mut replacement=connect_from(&rig.app,&a_token,&[],Some(US_A)).await;
            before_netmap=join_collect(&mut replacement,1,"8.8.8.9:41641",false,true).await; a=replacement;
        } else {
            let changed = match case { "stable" => Some(CN_R), "unknown" => None, _ => Some(US_R) };
            let endpoint=if changed==Some(CN_R){"223.6.6.11:41641"}else{"1.1.1.11:41641"};
            let mut replacement=connect_from(&rig.app,&relay_tokens[1],&["relay-server"],changed).await;
            if case == "race_restore" {
                let (reached,resume)=support::pause_trial_zone_revoke(trial_id);
                replacement.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([11;32]),"mtu":1280,
                    "endpoints":[endpoint],"supports_org_relay":true,"supports_server_relay_strategy":true,"relay_port":3478,"org_primary":true,"relay_backbone_ready":true}).to_string().into())).await.unwrap();
                tokio::time::timeout(Duration::from_secs(8),reached).await.expect("middle recheck paused").unwrap();
                let mut restored=connect_from(&rig.app,&relay_tokens[1],&["relay-server"],Some(CN_R)).await;
                before_netmap=join_collect(&mut restored,11,"223.6.6.11:41641",true,false).await;
                resume.send(()).unwrap(); relays[1]=restored;
            } else { before_netmap=join_collect(&mut replacement,11,endpoint,true,false).await; relays[1]=replacement; }
        }
        if matches!(case,"stable"|"race_restore"|"unconstrained_member") {
            assert!(before_netmap.is_empty(),"{slug}: healthy path retired during join");
            for id in &node_ids {assert_eq!(support::trial_slots_on_relay(network,*id),1,"{slug}: healthy path lost");}
            async fn quiet(ws:&mut Ws,label:&str){let until=tokio::time::Instant::now()+Duration::from_millis(300);
                while let Ok(Some(Ok(Message::Text(text))))=tokio::time::timeout_at(until,ws.next()).await {
                    let v:Value=serde_json::from_str(&text).unwrap();assert!(!["rc:overlay.relay_revoke","rc:overlay.relay_bridge_revoke","rc:overlay.path_trial_abort"].contains(&v["t"].as_str().unwrap_or_default()),"{label}: healthy trial wrongly revoked");}}
            for ws in &mut relays {quiet(ws,&slug).await;} quiet(&mut a,&slug).await; quiet(&mut b,&slug).await;
        } else {
            let wait=Duration::from_secs(8);
            for i in 0..4 {
                let expected=if i==0 {session.vni}else{session.hops[i-1].vni};
                let revoke=if i==1 && case!="member_changed" {before_netmap.iter().find(|v|v["t"]=="rc:overlay.relay_revoke").cloned()}else{None};
                let revoke=match revoke {Some(v)=>v,None=>recv_t(&mut relays[i],"rc:overlay.relay_revoke",wait).await.expect("relay revoke")};
                assert_eq!(revoke["vni"],expected,"{slug} relay {i}");
                if i<3 {
                    let bridge=if i==1 && case!="member_changed" {before_netmap.iter().find(|v|v["t"]=="rc:overlay.relay_bridge_revoke").cloned()}else{None};
                    let bridge=match bridge {Some(v)=>v,None=>recv_t(&mut relays[i],"rc:overlay.relay_bridge_revoke",wait).await.expect("bridge revoke")};
                    assert_eq!(bridge["trial_id"],session.hops[i].bridge_id.to_hex());
                    let generation=if i==0{session.generation}else{session.hops[i-1].generation};assert_eq!(bridge["generation"],generation);
                }
            }
            let first=if case=="member_changed" {before_netmap.iter().find(|v|v["t"]=="rc:overlay.path_trial_abort").cloned()}else{None};
            let first=match first {Some(v)=>v,None=>recv_t(&mut a,"rc:overlay.path_trial_abort",wait).await.expect("first abort")};
            let second=recv_t(&mut b,"rc:overlay.path_trial_abort",wait).await.expect("second abort");
            assert_eq!(first["trial_id"],trial_id.to_hex());assert_eq!(second["trial_id"],trial_id.to_hex());
            for id in &node_ids {assert_eq!(support::trial_slots_on_relay(network,*id),0,"{slug}: trial slot leaked");}
        }
    }
}
