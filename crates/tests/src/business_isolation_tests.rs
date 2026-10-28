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
