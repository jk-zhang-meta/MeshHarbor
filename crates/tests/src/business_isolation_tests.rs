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
        Self::up_with_unknown_role(slug, isolation, "warn").await
    }

    async fn up_with_unknown_role(
        slug: &str,
        isolation: &'static str,
        unknown_role: &'static str,
    ) -> Self {
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
            s.app.business_unknown_role = unknown_role.into();
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
        self.set_device_role("agent", agent, role).await;
    }

    async fn set_device_role(&self, kind: &str, id: &str, role: &str) {
        let path = format!(
            "/api/admin/business-authority/{kind}/{}/{id}",
            self.seeded.tenant_id
        );
        let (s, v) = put(
            &self.app,
            &path,
            &self.owner_token,
            json!({ "role": role, "reason": "business role fixture" }),
        )
        .await;
        assert_eq!(s, 200, "set {kind} role {role}: {v}");
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
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .unwrap();
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
        line_join(
            &mut gz,
            3,
            "223.6.6.6:41641",
            json!({ "relay_backbone_ready": true }),
        )
        .await;
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
        let (status, v) = put(
            &self.rig.app,
            &path,
            &self.rig.seeded.admin.access_token,
            body,
        )
        .await;
        assert_eq!(status, 200, "{v}");
    }

    /// Every frame of a line mint: (gz serve, bridge, hk serve, cn session,
    /// us session).
    async fn expect_line(&mut self) -> (Value, Value, Value, Value, Value) {
        let wait = Duration::from_secs(5);
        let gz = recv_t(&mut self.gz, "rc:overlay.relay_serve", wait)
            .await
            .expect("gz serves");
        let bridge = recv_t(&mut self.gz, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("gz bridges")["bridge"]
            .clone();
        let hk = recv_t(&mut self.hk, "rc:overlay.relay_serve", wait)
            .await
            .expect("hk serves");
        let cn = recv_t(&mut self.cn, "rc:overlay.relay_session", wait)
            .await
            .expect("cn session");
        let us = recv_t(&mut self.us, "rc:overlay.relay_session", wait)
            .await
            .expect("us session");
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
    assert!(
        !peer_ids(&map).contains(&l.us_node),
        "withheld without a line"
    );
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(600)
        )
        .await
        .is_none(),
        "no line, no mint"
    );

    l.set_edge(true).await;
    // A member without the flag still sees nothing across the line.
    let mut old = l.rig.device("iso-line-old", Some(CN_A)).await;
    let old_map = line_join(&mut old, 5, "223.5.5.7:41641", json!({})).await;
    assert!(
        !peer_ids(&old_map).contains(&l.us_node),
        "rule 4: an old client sees nothing"
    );
    let map = line_join(&mut l.cn, 1, "223.5.5.5:41641", flag.clone()).await;
    let us = map["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["node_id"] == json!(l.us_node))
        .expect("the line shows the cross-zone peer")
        .clone();
    assert_eq!(us["backbone_only"], json!(true), "{us}");
    assert!(
        us["endpoints"].as_array().is_none_or(|e| e.is_empty()),
        "{us}"
    );
    assert_ne!(us["supports_derp"], json!(true), "{us}");
    assert_ne!(us["supports_derp_floor"], json!(true), "{us}");

    relay_request(&mut l.cn, &l.us_node).await;
    let (gz, bridge, hk, cn, us) = l.expect_line().await;
    assert_eq!(
        cn["relay_node_id"],
        json!(l.gz_node),
        "cn binds the mainland relay"
    );
    assert_eq!(
        us["relay_node_id"],
        json!(l.hk_node),
        "us binds the non-mainland relay"
    );
    assert_eq!(cn["peer_node_id"], json!(l.us_node));
    assert_eq!(us["peer_node_id"], json!(l.cn_node));
    assert_eq!(gz["vni"], cn["vni"]);
    assert_eq!(hk["vni"], us["vni"]);
    let secret = |v: &Value, i: usize| v["members"][i]["bind_secret"].clone();
    assert_eq!(secret(&gz, 0), cn["bind_secret"]);
    assert_eq!(secret(&hk, 1), us["bind_secret"]);
    assert_eq!(bridge["local_vni"], gz["vni"]);
    assert_eq!(
        bridge["local_bind_secret"],
        secret(&gz, 1),
        "the bridge holds us's slot on gz"
    );
    assert_eq!(bridge["remote_vni"], hk["vni"]);
    assert_eq!(
        bridge["remote_bind_secret"],
        secret(&hk, 0),
        "and cn's on hk"
    );
    assert_eq!(bridge["remote_endpoint"], json!(LINE));
    for (name, s) in [("cn", &cn), ("us", &us)] {
        assert!(
            !s.to_string().contains("10.42.2.114"),
            "{name} is never told the line: {s}"
        );
    }
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_grant",
            Duration::from_millis(400)
        )
        .await
        .is_none(),
        "rule 3: no TURN across the line"
    );
    let mut minted = Vec::new();
    for _ in 0..40 {
        minted = l.audit_reasons("mint").await;
        if minted
            .iter()
            .filter(|(r, _)| r == "cross_border_line")
            .count()
            >= 2
        {
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
    let again = recv_t(
        &mut l.us,
        "rc:overlay.relay_session",
        Duration::from_secs(5),
    )
    .await
    .expect("us's leg is re-pushed");
    assert_eq!(again["vni"], us["vni"]);
    assert_eq!(again["relay_node_id"], json!(l.hk_node));
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(400)
        )
        .await
        .is_none(),
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
            recv_t(ws, "rc:overlay.force_derp", Duration::from_millis(600))
                .await
                .is_none(),
            "{name}: a lossy line is not pinned to DERP"
        );
    }
    let pk = meshharbor_mod_network::overlay::pair_key(
        ObjectId::parse_str(&l.cn_node).unwrap(),
        ObjectId::parse_str(&l.us_node).unwrap(),
    );
    assert!(
        l.rig
            .app
            .state
            .network()
            .org_relay
            .active_session(&pk)
            .is_some()
    );
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
    let edges = meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
        net, cn, us, false,
    )
    .await
    .unwrap();
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(net, cn, us, true)
            .await
            .is_err(),
        "trial capability is required"
    );
    assert_eq!(edges, vec![(gz, hk, LINE.to_string(), true)]);
    l.set_edge(false).await;
    let edges = meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
        l.rig.app.state.network(),
        cn,
        us,
        false,
    )
    .await
    .unwrap();
    assert!(
        edges.is_empty(),
        "a non-cross-border edge must not carry this pair"
    );
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &l.hk_agent, false).await,
        200
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
            l.rig.app.state.network(),
            cn,
            us,
            false
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn staged_graph_tracks_three_relay_chain_and_each_acl() {
    let l = LineRig::up("iso-graph-chain", true).await;
    let (mid_agent, mid_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-graph-chain-mid").await;
    let mut mid = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(
        &mut mid,
        6,
        "223.6.6.7:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await,
        200
    );
    let mid_node = l.rig.node("iso-graph-chain-mid").await;
    let mid_acl = grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    for (source, target, endpoint, cross) in [
        (&l.gz_agent, &mid_agent, "10.42.2.113:3478", false),
        (&mid_agent, &l.hk_agent, LINE, true),
    ] {
        let path = format!(
            "/api/tenant/{}/agent/{}/peer-relay-policy",
            l.rig.seeded.tenant_id, source
        );
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
    let edges = meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
        l.rig.app.state.network(),
        cn,
        us,
        false,
    )
    .await
    .unwrap();
    let actual: BTreeSet<_> = edges.into_iter().collect();
    let expected: BTreeSet<_> = [
        (gz, mid_id, "10.42.2.113:3478".into(), false),
        (mid_id, hk, LINE.into(), true),
    ]
    .into_iter()
    .collect();
    assert_eq!(actual, expected);
    // Simulate the documented offered-probe path: the member can reach GZ,
    // not the same-zone middle relay; the remote member can reach HK.
    let gz_node = ObjectId::parse_str(&l.gz_node).unwrap();
    let mid_node_id = ObjectId::parse_str(&mid_node).unwrap();
    let hk_node = ObjectId::parse_str(&l.hk_node).unwrap();
    let net = l.rig.app.state.network();
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            net,
            cn,
            &[
                (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
                (mid_node_id, "223.6.6.7:3478".into(), false, None),
            ]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            net,
            us,
            &[(hk_node, "1.1.1.1:3478".into(), true, Some(10)),]
        )
    );
    let chosen = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
        l.rig.app.state.network(),
        cn,
        us,
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(chosen, (vec![gz, mid_id, hk], false));
    // A real endpoint update away and back must not resurrect an old probe.
    async fn endpoint_update(ws: &mut Ws, endpoint: &str) {
        ws.send(Message::Text(
            json!({"t":"rc:overlay.endpoints", "candidates":[endpoint]})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        ws.send(Message::Ping(b"endpoint-barrier".to_vec().into()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(frame) = ws.next().await {
                if matches!(frame, Ok(Message::Pong(ref p)) if p.as_ref() == b"endpoint-barrier") {
                    return;
                }
            }
            panic!("socket closed before endpoint barrier");
        })
        .await
        .expect("endpoint barrier timed out");
    }
    endpoint_update(&mut mid, "223.6.6.8:41641").await;
    endpoint_update(&mut mid, "223.6.6.7:41641").await;
    let after_endpoint_revert =
        meshharbor_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(after_endpoint_revert, (vec![mid_id, hk], false));
    let negative = [(mid_node_id, "223.6.6.7:3478".into(), false, None)];
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            net, cn, &negative
        )
    );
    assert_eq!(
        meshharbor_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false)
            .await
            .unwrap()
            .unwrap(),
        (vec![gz, mid_id, hk], false)
    );
    // The actual policy route also invalidates a probe across A→B→A.
    let mid_policy_path = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, mid_agent
    );
    for edges in [
        json!([]),
        json!([{ "relay_agent_id": l.hk_agent, "endpoint": LINE, "cross_border": true }]),
    ] {
        let (status, value) = put(
            &l.rig.app,
            &mid_policy_path,
            &l.rig.seeded.admin.access_token,
            json!({ "serve": true, "approved_backbone_edges": edges }),
        )
        .await;
        assert_eq!(status, 200, "{value}");
    }
    assert_eq!(
        meshharbor_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false)
            .await
            .unwrap()
            .unwrap(),
        (vec![mid_id, hk], false)
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            net, cn, &negative
        )
    );
    assert_eq!(
        meshharbor_mod_network::org_relay::candidate_test_support::select_path(net, cn, us, false)
            .await
            .unwrap()
            .unwrap(),
        (vec![gz, mid_id, hk], false)
    );
    // A rejoin invalidates the old direct-to-middle measurement even when
    // its endpoint string happens to stay unchanged.
    line_join(
        &mut mid,
        6,
        "223.6.6.7:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    let after_rejoin = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
        l.rig.app.state.network(),
        cn,
        us,
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(after_rejoin, (vec![mid_id, hk], false));
    let path = format!(
        "/api/tenant/{}/overlay-acl/{}",
        l.rig.seeded.tenant_id, mid_acl
    );
    let status = l
        .rig
        .app
        .client
        .delete(l.rig.app.url(&path))
        .bearer_auth(&l.rig.seeded.admin.access_token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 200);
    let edges = meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
        l.rig.app.state.network(),
        cn,
        us,
        false,
    )
    .await
    .unwrap();
    assert!(
        edges.is_empty(),
        "no edge may use the no-longer-granted middle relay"
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::select_path(
            l.rig.app.state.network(),
            cn,
            us,
            false
        )
        .await
        .unwrap()
        .is_none()
    );
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
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            net,
            us,
            &[(hk, endpoint.into(), true, Some(30))]
        )
    );
    let node = net.overlay_nodes.base.find_by_id(us).await.unwrap();
    let identity = match node.node_ref {
        meshharbor_remote_control::models::NodeRef::Agent { agent_id } => agent_id,
        _ => panic!("fixture must be an agent"),
    };
    let old_connection =
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            net, identity,
        )
        .unwrap();
    let (reached, release, finished) =
        meshharbor_mod_network::org_relay::candidate_test_support::pause_next_probe(identity);
    let report = |rtt| {
        Message::Text(
            json!({"t":"rc:overlay.relay_probe", "relay_node_id":hk.to_hex(),
        "endpoint":endpoint, "reachable":true, "rtt_ms":rtt})
            .to_string()
            .into(),
        )
    };
    l.us.send(report(1)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reached)
        .await
        .unwrap()
        .unwrap();
    let mut replacement = connect_from(&l.rig.app, &l.us_tok, &[], Some(US_A)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
                net, identity,
            )
            .is_some_and(|id| id != old_connection)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement was not bound");
    release.send(()).unwrap();
    assert!(
        !tokio::time::timeout(Duration::from_secs(5), finished)
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        meshharbor_mod_network::org_relay::candidate_test_support::probe_rtts(net, us, hk),
        vec![Some(30)]
    );
    async fn barrier(ws: &mut Ws, nonce: &'static [u8]) {
        ws.send(Message::Ping(nonce.to_vec().into())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(frame) = ws.next().await {
                if matches!(frame, Ok(Message::Pong(ref payload)) if payload.as_ref() == nonce) {
                    return;
                }
            }
            panic!("socket closed before ping barrier");
        })
        .await
        .expect("ping barrier timed out");
    }
    replacement.send(report(20)).await.unwrap();
    barrier(&mut replacement, b"new-probe-barrier").await;
    assert_eq!(
        meshharbor_mod_network::org_relay::candidate_test_support::probe_rtts(net, us, hk),
        vec![Some(30), Some(20)]
    );
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
    assert!(
        revoked.iter().any(|(r, _)| r == "backbone_edge_revoked"),
        "{revoked:?}"
    );

    // The non-mainland member asks this time; the line keeps its sides.
    l.set_edge(true).await;
    relay_request(&mut l.us, &l.cn_node).await;
    let (_, _, _, cn, us) = l.expect_line().await;
    assert_eq!(cn["relay_node_id"], json!(l.gz_node));
    assert_eq!(us["relay_node_id"], json!(l.hk_node));
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &l.hk_agent, false).await,
        200
    );
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
    use meshharbor_mod_network::org_relay::LINE_RECONNECT_GRACE;
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
    let et: Value = rig
        .app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                rig.seeded.tenant_id
            ),
            &rig.seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: Value = rig.app.client.post(rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({"enrollment_token":et["enrollment_token"], "machine_id":"mach-tunnel-probe-owner",
            "machine_name":"tunnel-probe-owner", "os":"linux", "client_version":"0.3.0-test"}))
        .send().await.unwrap().json().await.unwrap();
    let identity = ObjectId::parse_str(enrolled["tunnel_client_id"].as_str().unwrap()).unwrap();
    let token = enrolled["tunnel_client_token"].as_str().unwrap();
    let url = format!(
        "ws://{}/ws?token={}&role=tunnel-client",
        rig.app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut old, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    line_join(&mut old, 31, "223.6.6.6:41641", json!({})).await;
    let net = rig.app.state.network();
    let node = meshharbor_mod_network::overlay::current_node(
        net,
        meshharbor_mod_network::overlay::NodeIdentity::TunnelClient(identity),
    )
    .await
    .unwrap()
    .id
    .unwrap();
    let relay = ObjectId::new();
    let endpoint = "1.1.1.1:3478";
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            net,
            node,
            &[(relay, endpoint.into(), true, Some(30))]
        )
    );
    let old_conn =
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            net, identity,
        )
        .unwrap();
    let (reached, release, finished) =
        meshharbor_mod_network::org_relay::candidate_test_support::pause_next_probe(identity);
    let report = |rtt| {
        Message::Text(
            json!({"t":"rc:overlay.relay_probe", "relay_node_id":relay.to_hex(),
        "endpoint":endpoint, "reachable":true, "rtt_ms":rtt})
            .to_string()
            .into(),
        )
    };
    old.send(report(1)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reached)
        .await
        .unwrap()
        .unwrap();
    let (mut replacement, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    line_join(&mut replacement, 31, "223.6.6.6:41641", json!({})).await;
    assert_ne!(
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            net, identity
        )
        .unwrap(),
        old_conn
    );
    // Re-offer the same endpoint before the old report resumes, so offer
    // withdrawal cannot accidentally hide a missing ownership check.
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            net,
            node,
            &[(relay, endpoint.into(), true, Some(30))]
        )
    );
    release.send(()).unwrap();
    assert!(
        !tokio::time::timeout(Duration::from_secs(5), finished)
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        meshharbor_mod_network::org_relay::candidate_test_support::probe_rtts(net, node, relay),
        vec![Some(30), Some(30)]
    );
    replacement.send(report(20)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let rtts = meshharbor_mod_network::org_relay::candidate_test_support::probe_rtts(
                net, node, relay,
            );
            if rtts == vec![Some(30), Some(30), Some(20)] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("current tunnel report must be accepted");
}

/// A displaced client cannot leave or tear down its replacement's live path.
#[tokio::test]
async fn staged_graph_tunnel_old_close_preserves_replacement_session() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut l = LineRig::up("iso-tunnel-revoke", true).await;
    let et: Value = l
        .rig
        .app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                l.rig.seeded.tenant_id
            ),
            &l.rig.seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: Value = l
        .rig
        .app
        .client
        .post(l.rig.app.url("/api/tunnel-client/enroll"))
        .json(
            &json!({"enrollment_token":et["enrollment_token"], "machine_id":"mach-tunnel-revoke",
            "machine_name":"tunnel-revoke", "os":"linux", "client_version":"0.3.0-test"}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let identity = ObjectId::parse_str(enrolled["tunnel_client_id"].as_str().unwrap()).unwrap();
    let token = enrolled["tunnel_client_token"].as_str().unwrap();
    let url = format!(
        "ws://{}/ws?token={}&role=tunnel-client",
        l.rig.app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let request = || {
        let mut req = url.as_str().into_client_request().unwrap();
        req.headers_mut()
            .insert("x-forwarded-for", US_A.parse().unwrap());
        req
    };
    let (mut old, _) = tokio_tungstenite::connect_async(request()).await.unwrap();
    line_join(
        &mut old,
        31,
        "8.8.8.9:41641",
        json!({ "supports_backbone_only_v1": true }),
    )
    .await;
    let old_conn =
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            l.rig.app.state.network(),
            identity,
        )
        .unwrap();
    let cleanup = meshharbor_mod_network::org_relay::candidate_test_support::observe_tunnel_cleanup(
        &old_conn,
    );
    let (mut replacement, _) = tokio_tungstenite::connect_async(request()).await.unwrap();
    line_join(
        &mut replacement,
        31,
        "8.8.8.9:41641",
        json!({ "supports_backbone_only_v1": true }),
    )
    .await;
    let net = l.rig.app.state.network();
    let ident = meshharbor_mod_network::overlay::NodeIdentity::TunnelClient(identity);
    let tunnel_node = meshharbor_mod_network::overlay::current_node(net, ident)
        .await
        .unwrap()
        .id
        .unwrap();
    let cn_node = ObjectId::parse_str(&l.cn_node).unwrap();
    let key = meshharbor_mod_network::overlay::pair_key(cn_node, tunnel_node);
    let current = meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
        net, identity,
    )
    .unwrap();
    relay_request(&mut l.cn, &tunnel_node.to_hex()).await;
    let wait = Duration::from_secs(5);
    let gz = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
        .await
        .expect("GZ serves line");
    let hk = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
        .await
        .expect("HK serves line");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("CN session");
    let tc = recv_t(&mut replacement, "rc:overlay.relay_session", wait)
        .await
        .expect("tunnel session");
    assert_eq!(gz["vni"], cn["vni"]);
    assert_eq!(hk["vni"], tc["vni"]);
    assert!(net.org_relay.active_session(&key).is_some());
    // Old socket stays open: even an explicit leave from it must not remove
    // the new client's node or revoke the established cross-zone line.
    old.send(Message::Text(
        json!({"t":"rc:overlay.leave"}).to_string().into(),
    ))
    .await
    .unwrap();
    old.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(wait, cleanup)
        .await
        .expect("old cleanup did not finish")
        .unwrap();
    assert!(net.overlay_nodes_by_id.contains_key(&identity));
    assert_eq!(
        meshharbor_mod_network::overlay::current_node(net, ident)
            .await
            .unwrap()
            .status,
        meshharbor_remote_control::models::AgentStatus::Online
    );
    assert!(net.org_relay.active_session(&key).is_some());
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_revoke",
            Duration::from_millis(600)
        )
        .await
        .is_none()
    );
    assert_eq!(
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            net, identity
        ),
        Some(current)
    );
}

/// A new bind waits for the old connection's async overlay cleanup, then the
/// new join wins after the old leave completes.
#[tokio::test]
async fn staged_graph_tunnel_bind_waits_for_old_async_leave() {
    let rig = Rig::up("iso-tunnel-leave-race", "enforce").await;
    let et: Value = rig
        .app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                rig.seeded.tenant_id
            ),
            &rig.seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: Value = rig.app.client.post(rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({"enrollment_token":et["enrollment_token"], "machine_id":"mach-tunnel-leave-race",
            "machine_name":"tunnel-leave-race", "os":"linux", "client_version":"0.3.0-test"}))
        .send().await.unwrap().json().await.unwrap();
    let identity = ObjectId::parse_str(enrolled["tunnel_client_id"].as_str().unwrap()).unwrap();
    let token = enrolled["tunnel_client_token"].as_str().unwrap();
    let url = format!(
        "ws://{}/ws?token={}&role=tunnel-client",
        rig.app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut old, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    line_join(&mut old, 31, "223.6.6.6:41641", json!({})).await;
    let net = rig.app.state.network();
    let old_id = meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
        net, identity,
    )
    .unwrap();
    let (reached, resume) =
        meshharbor_mod_network::org_relay::candidate_test_support::pause_tunnel_leave(&old_id);
    old.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reached)
        .await
        .unwrap()
        .unwrap();
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            net, identity
        )
        .is_none()
    );
    let bind_attempt =
        meshharbor_mod_network::org_relay::candidate_test_support::observe_tunnel_bind_attempt(
            identity,
        );
    let mut bound =
        meshharbor_mod_network::org_relay::candidate_test_support::observe_tunnel_bound(identity);
    let (mut replacement, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), bind_attempt)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut bound)
            .await
            .is_err(),
        "new bind must wait for old async leave"
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            net, identity
        )
        .is_none()
    );
    resume.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), bound)
        .await
        .unwrap()
        .unwrap();
    line_join(&mut replacement, 31, "223.6.6.6:41641", json!({})).await;
    assert!(net.overlay_nodes_by_id.contains_key(&identity));
    let new_id = meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
        net, identity,
    )
    .unwrap();
    assert_ne!(new_id, old_id);
    let node = meshharbor_mod_network::overlay::current_node(
        net,
        meshharbor_mod_network::overlay::NodeIdentity::TunnelClient(identity),
    )
    .await
    .unwrap();
    assert_eq!(
        node.status,
        meshharbor_remote_control::models::AgentStatus::Online
    );
    // Closing the current owner must still perform ordinary cleanup.
    let current_cleanup =
        meshharbor_mod_network::org_relay::candidate_test_support::observe_tunnel_cleanup(&new_id);
    replacement.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), current_cleanup)
        .await
        .unwrap()
        .unwrap();
    assert!(!net.overlay_nodes_by_id.contains_key(&identity));
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
            net, identity
        )
        .is_none()
    );
    let offline = meshharbor_mod_network::overlay::current_node(
        net,
        meshharbor_mod_network::overlay::NodeIdentity::TunnelClient(identity),
    )
    .await
    .unwrap();
    assert_eq!(
        offline.status,
        meshharbor_remote_control::models::AgentStatus::Offline
    );
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
        assert!(
            recv_t(
                &mut relay,
                "rc:overlay.relay_serve",
                Duration::from_millis(600)
            )
            .await
            .is_none()
        );
        let a_id = ObjectId::parse_str(&a_node).unwrap();
        let b_id = ObjectId::parse_str(&b_node).unwrap();
        let result = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
            rig.app.state.network(),
            a_id,
            b_id,
            false,
        )
        .await;
        assert!(matches!(
            result,
            Err(meshharbor_remote_control::models::PeerRelayDenyReason::ZoneDenied)
        ));
        return;
    }
    recv_t(&mut relay, "rc:overlay.relay_serve", wait)
        .await
        .expect("existing relay gate should authorize");
    recv_t(&mut a, "rc:overlay.relay_session", wait)
        .await
        .expect("member a has session");
    recv_t(&mut b, "rc:overlay.relay_session", wait)
        .await
        .expect("member b has session");
    let a_id = ObjectId::parse_str(&a_node).unwrap();
    let b_id = ObjectId::parse_str(&b_node).unwrap();
    let relay_agent_id = ObjectId::parse_str(&relay_id).unwrap();
    let path = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
        rig.app.state.network(),
        a_id,
        b_id,
        false,
    )
    .await
    .expect("staged gate should honor same isolation mode")
    .expect("a relay path exists");
    assert_eq!(path.0, vec![relay_agent_id]);
}

#[tokio::test]
async fn staged_graph_unknown_zone_parity_off() {
    staged_graph_unknown_zone_parity("off", "iso-zone-none-off").await;
}

#[tokio::test]
async fn staged_graph_unknown_zone_parity_warn() {
    staged_graph_unknown_zone_parity("warn", "iso-zone-none-warn").await;
}

#[tokio::test]
async fn staged_graph_unknown_zone_parity_enforce() {
    staged_graph_unknown_zone_parity("enforce", "iso-zone-none-enforce").await;
}

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
    recv_t(&mut relay, "rc:overlay.relay_serve", wait)
        .await
        .expect("existing linked-server gate should authorize");
    recv_t(&mut a, "rc:overlay.relay_session", wait)
        .await
        .expect("server a session");
    recv_t(&mut b, "rc:overlay.relay_session", wait)
        .await
        .expect("server b session");
    let selected = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
        rig.app.state.network(),
        ObjectId::parse_str(&a_node).unwrap(),
        ObjectId::parse_str(&b_node).unwrap(),
        false,
    )
    .await
    .expect("staged gate should honor linked-server topology")
    .expect("a relay path exists");
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
    line_join(
        &mut r1,
        41,
        "1.1.1.1:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    line_join(
        &mut r2,
        42,
        "1.0.0.1:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
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
    let policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        rig.seeded.tenant_id, r1_id
    );
    let net = rig.app.state.network();
    for cross in [false, true] {
        let (status, response) = put(
            &rig.app,
            &policy,
            &rig.seeded.admin.access_token,
            json!({
                "serve": true, "approved_backbone_edges": [{"relay_agent_id":r2_id,
                    "endpoint":"10.42.2.113:3478", "cross_border":cross}]
            }),
        )
        .await;
        assert_eq!(status, 200, "{response}");
        let edges = meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
            rig.app.state.network(),
            a_node,
            b_node,
            false,
        )
        .await
        .unwrap();
        assert!(
            edges
                .iter()
                .any(|(a, b, _, flag)| *a == source && *b == target && *flag == cross),
            "Off/Warn keep an approved edge and preserve its original cross-border bit"
        );
        assert!(
            meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
                net,
                a_node,
                &[
                    (r1_node, "1.1.1.1:3478".into(), true, Some(10)),
                    (r2_node, "1.0.0.1:3478".into(), false, None),
                ]
            )
        );
        assert!(
            meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
                net,
                b_node,
                &[
                    (r1_node, "1.1.1.1:3478".into(), false, None),
                    (r2_node, "1.0.0.1:3478".into(), true, Some(10)),
                ]
            )
        );
        let selected = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
            net, a_node, b_node, false,
        )
        .await
        .unwrap()
        .expect("approved two-relay path exists");
        assert_eq!(selected, (vec![source, target], false));
    }
}

#[tokio::test]
async fn staged_graph_unknown_zone_parity_backbone_off() {
    staged_graph_unknown_backbone("off", "iso-zone-backbone-off").await;
}
#[tokio::test]
async fn staged_graph_unknown_zone_parity_backbone_warn() {
    staged_graph_unknown_backbone("warn", "iso-zone-backbone-warn").await;
}

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
    assert!(
        recv_t(&mut relay, "rc:overlay.relay_serve", wait)
            .await
            .is_none(),
        "no cross-border line may be minted"
    );
    let selected = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
        rig.app.state.network(),
        ObjectId::parse_str(&a_node).unwrap(),
        ObjectId::parse_str(&b_node).unwrap(),
        false,
    )
    .await;
    assert!(matches!(
        selected,
        Err(meshharbor_remote_control::models::PeerRelayDenyReason::ZoneDenied)
    ));
}

/// Two server-role members without their topology link must not obtain a
/// staged cross-zone path even if a relay-to-relay edge itself is approved.
#[tokio::test]
async fn staged_graph_unknown_zone_parity_unlinked_servers_fail_closed() {
    let l = LineRig::up("iso-zone-unlinked-servers", true).await;
    let net = l.rig.app.state.network();
    let cn = ObjectId::parse_str(&l.cn_node).unwrap();
    let us = ObjectId::parse_str(&l.us_node).unwrap();
    let agent_id = |node: &meshharbor_remote_control::models::OverlayNode| match node.node_ref {
        meshharbor_remote_control::models::NodeRef::Agent { agent_id } => agent_id.to_hex(),
        _ => panic!("fixture member must be an agent"),
    };
    let cn_agent = agent_id(&net.overlay_nodes.base.find_by_id(cn).await.unwrap());
    let us_agent = agent_id(&net.overlay_nodes.base.find_by_id(us).await.unwrap());
    l.rig.set_role(&cn_agent, "server").await;
    l.rig.set_role(&us_agent, "server").await;
    l.rig.link(&cn_agent, &us_agent, false).await;
    let result = meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
        net, cn, us, false,
    )
    .await;
    assert!(matches!(
        result,
        Err(meshharbor_remote_control::models::PeerRelayDenyReason::ZoneDenied)
    ));
}

/// The server's real edge-withdrawal entry point must retain an approved
/// ordinary edge, but revoke the full path when a required crossing loses its
/// approval or when an ordinary edge disappears. The fixture inserts state
/// only; it does not grant a live path or prove remote revoke delivery.
#[tokio::test]
async fn staged_graph_mixed_edge_approval_revokes_only_when_the_edge_requires_it() {
    use meshharbor_mod_network::org_relay::{
        LineLeg, OrgRelaySession, SessionMember, SessionParty,
        candidate_test_support::insert_session_fixture, revoke_removed_backbone_edges_sync,
    };
    use meshharbor_remote_control::models::{NodeRef, PeerRelayBackboneEdge};
    use std::time::Instant;
    let app = TestApp::spawn().await;
    let state = app.state.network();
    let tenant = ObjectId::new();
    let agents = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
    let party = |id| SessionParty {
        node_id: ObjectId::new(),
        node_ref: NodeRef::Agent { agent_id: id },
    };
    let member = |id| SessionMember {
        party: party(id),
        wg_public_key: "fixture".into(),
        bind_secret: "fixture".into(),
    };
    let line = |index, required, endpoint: &str| LineLeg {
        relay: party(agents[index]),
        relay_agent_id: agents[index],
        vni: index as u32 + 10,
        generation: index as u64 + 20,
        endpoints: vec!["relay".into()],
        private_endpoint: endpoint.into(),
        requires_cross_border_approval: required,
        bridge_id: ObjectId::new(),
        bridge_secrets: ["a".into(), "b".into()],
    };
    let session = OrgRelaySession {
        tenant_id: tenant,
        pair_key: "mixed-fixture".into(),
        vni: 9,
        generation: 19,
        relay: party(agents[0]),
        relay_agent_id: agents[0],
        implicit: false,
        members: [member(ObjectId::new()), member(ObjectId::new())],
        endpoints: vec!["relay".into()],
        expires_at: Instant::now() + Duration::from_secs(60),
        bind_by: Instant::now() + Duration::from_secs(30),
        hops: vec![
            line(1, false, "10.0.0.2:3478"),
            line(2, true, "10.0.0.3:3478"),
        ],
    };
    let edge = |target: ObjectId, endpoint: &str, cross_border| PeerRelayBackboneEdge {
        relay_agent_id: target.to_hex(),
        endpoint: endpoint.into(),
        cross_border,
    };
    assert!(insert_session_fixture(state, session.clone()));
    assert!(
        revoke_removed_backbone_edges_sync(
            state,
            tenant,
            agents[0],
            &[edge(agents[1], "10.0.0.2:3478", false)]
        )
        .is_empty()
    );
    assert!(state.org_relay.active_session("mixed-fixture").is_some());
    assert!(
        revoke_removed_backbone_edges_sync(
            state,
            tenant,
            agents[1],
            &[edge(agents[2], "10.0.0.3:3478", true)]
        )
        .is_empty()
    );
    assert_eq!(
        revoke_removed_backbone_edges_sync(
            state,
            tenant,
            agents[1],
            &[edge(agents[2], "10.0.0.3:3478", false)]
        )
        .len(),
        1
    );
    assert!(state.org_relay.active_session("mixed-fixture").is_none());
    let mut another = session;
    another.pair_key = "ordinary-edge-removed".into();
    assert!(insert_session_fixture(state, another));
    assert!(revoke_removed_backbone_edges_sync(state, ObjectId::new(), agents[0], &[]).is_empty());
    assert_eq!(
        revoke_removed_backbone_edges_sync(state, tenant, agents[0], &[]).len(),
        1
    );
    assert!(
        state
            .org_relay
            .active_session("ordinary-edge-removed")
            .is_none()
    );
}

/// The real zone recheck sees three live relay identities. The inserted
/// three-relay records are fixtures, not grants to those relay processes.
#[tokio::test]
async fn staged_graph_three_relay_zone_recheck_preserves_valid_and_revokes_changed_edges() {
    use meshharbor_mod_network::org_relay::{
        LineLeg, SessionParty,
        candidate_test_support::{
            insert_session_fixture, line_zones_fit_fixture, recheck_zones_fixture,
        },
    };
    use meshharbor_remote_control::models::NodeRef;
    let mut l = LineRig::up("iso-three-relay-zone", true).await;
    let (extra_agent, extra_token) =
        enroll(&l.rig.app, &l.rig.seeded, "iso-three-relay-zone-extra").await;
    let mut extra = connect_from(&l.rig.app, &extra_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &extra_agent, Some(CN_R)).await;
    line_join(
        &mut extra,
        5,
        "223.6.6.7:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    let extra_node = l.rig.node("iso-three-relay-zone-extra").await;
    relay_request(&mut l.cn, &l.us_node).await;
    let _ = l.expect_line().await;
    let state = l.rig.app.state.network();
    let pair = meshharbor_mod_network::overlay::pair_key(
        ObjectId::parse_str(&l.cn_node).unwrap(),
        ObjectId::parse_str(&l.us_node).unwrap(),
    );
    let original = state.org_relay.active_session(&pair).unwrap();
    assert!(
        line_zones_fit_fixture(state, &original).await,
        "the original approved crossing remains valid"
    );
    // Loss of region evidence is not proof that the existing data path is invalid.
    let gz_id = ObjectId::parse_str(&l.gz_agent).unwrap();
    let gz_conn = meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
        state, gz_id,
    )
    .unwrap();
    assert!(state.org_relay.unbind_live_conn(gz_id, &gz_conn));
    recheck_zones_fixture(state, gz_id).await;
    assert_eq!(
        state
            .org_relay
            .active_session(&pair)
            .expect("unknown relay region must preserve a healthy formal session")
            .generation,
        original.generation
    );
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_millis(600)
        )
        .await
        .is_none(),
        "unknown relay region must withhold a line re-push"
    );
    state.org_relay.bind_live_conn(gz_id, &gz_conn);
    let extra_id = ObjectId::parse_str(&extra_agent).unwrap();
    let mut valid = original.clone();
    valid.pair_key = "three-zone-valid".into();
    valid.hops.insert(
        0,
        LineLeg {
            relay: SessionParty {
                node_id: ObjectId::parse_str(&extra_node).unwrap(),
                node_ref: NodeRef::Agent { agent_id: extra_id },
            },
            relay_agent_id: extra_id,
            vni: 100,
            generation: 101,
            endpoints: vec!["relay".into()],
            private_endpoint: "10.1.2.3:3478".into(),
            requires_cross_border_approval: false,
            bridge_id: ObjectId::new(),
            bridge_secrets: ["a".into(), "b".into()],
        },
    );
    assert!(
        line_zones_fit_fixture(state, &valid).await,
        "same-zone edge then approved crossing"
    );
    let mut ordinary_changed = valid.clone();
    ordinary_changed.pair_key = "three-zone-ordinary-changed".into();
    ordinary_changed.hops[0].requires_cross_border_approval = true;
    let mut crossing_changed = valid.clone();
    crossing_changed.pair_key = "three-zone-crossing-changed".into();
    crossing_changed.hops[1].requires_cross_border_approval = false;
    let mut unknown = valid.clone();
    unknown.pair_key = "three-zone-unknown".into();
    unknown.hops[1].relay.node_ref = NodeRef::Agent {
        agent_id: ObjectId::new(),
    };
    assert!(!line_zones_fit_fixture(state, &ordinary_changed).await);
    assert!(!line_zones_fit_fixture(state, &crossing_changed).await);
    assert!(!line_zones_fit_fixture(state, &unknown).await);
    for session in [valid, ordinary_changed, crossing_changed, unknown] {
        assert!(insert_session_fixture(state, session));
    }
    recheck_zones_fixture(state, extra_id).await;
    assert!(state.org_relay.active_session("three-zone-valid").is_some());
    for key in [
        "three-zone-ordinary-changed",
        "three-zone-crossing-changed",
        "three-zone-unknown",
    ] {
        assert!(
            state.org_relay.active_session(key).is_none(),
            "{key} must be revoked"
        );
    }
}

/// A concurrent zero-hit revocation still changes the eligibility epoch. It
/// cannot hide an already-confirmed bad edge, or revoke its newer replacement.
#[tokio::test]
async fn staged_session_zone_epoch_change_revokes_invalid_snapshot_not_new_generation() {
    use meshharbor_mod_network::org_relay::{self, candidate_test_support as support};
    let mut l = LineRig::up("iso-session-zone-epoch", true).await;
    relay_request(&mut l.cn, &l.us_node).await;
    let _ = l.expect_line().await;
    let state = l.rig.app.state.network();
    let pair = meshharbor_mod_network::overlay::pair_key(
        ObjectId::parse_str(&l.cn_node).unwrap(),
        ObjectId::parse_str(&l.us_node).unwrap(),
    );
    let original = state.org_relay.active_session(&pair).unwrap();
    let gz_id = ObjectId::parse_str(&l.gz_agent).unwrap();
    for replace in [false, true] {
        let mut invalid = original.clone();
        invalid.pair_key = format!("session-zone-epoch-replacement-{replace}");
        invalid.hops[0].requires_cross_border_approval = false;
        assert!(support::insert_session_fixture(state, invalid.clone()));
        let (reached, resume) = support::pause_session_zone_fixture(invalid.pair_key.clone());
        let checking = state.clone();
        let task = tokio::spawn(async move {
            support::recheck_zones_fixture(&checking, gz_id).await;
        });
        tokio::time::timeout(Duration::from_secs(5), reached)
            .await
            .expect("region decision pause")
            .unwrap();
        assert_eq!(
            org_relay::revoke_relay_agent(state, original.tenant_id, ObjectId::new(), "epoch-only")
                .await,
            0
        );
        if replace {
            assert!(support::remove_session_fixture(state, &invalid.pair_key));
            let mut replacement = original.clone();
            replacement.pair_key = invalid.pair_key.clone();
            replacement.generation = invalid.generation + 1;
            assert!(support::insert_session_fixture(state, replacement));
        }
        resume.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("zone recheck finished")
            .unwrap();
        if replace {
            assert_eq!(
                state
                    .org_relay
                    .active_session(&invalid.pair_key)
                    .expect("the same pair/VNI with a new generation must survive")
                    .generation,
                invalid.generation + 1
            );
            assert!(support::remove_session_fixture(state, &invalid.pair_key));
        } else {
            assert!(
                state.org_relay.active_session(&invalid.pair_key).is_none(),
                "an epoch change must not hide a confirmed invalid region relationship"
            );
        }
    }
}

/// The actual scheduler owns its recovery guard from spawn through completion.
#[tokio::test]
async fn staged_trial_zone_worker_keeps_its_guard_until_the_worker_finishes() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    let rig = Rig::up("iso-trial-zone-guard", "enforce").await;
    let state = rig.app.state.network();
    // No await between spawn and this observation: on this current-thread
    // runtime the worker has not been polled, so only premature Drop can clear it.
    support::schedule_trial_zone_retry_fixture(state, ObjectId::new());
    assert_eq!(
        support::trial_zone_retry_state_fixture(state),
        (true, false),
        "the recovery guard must be owned by the unpolled worker"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while support::trial_zone_retry_state_fixture(state).0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("missing trial completes its normal recheck");
    assert_eq!(
        support::trial_zone_retry_state_fixture(state),
        (false, false),
        "normal completion must not request an abnormal-exit rescan"
    );
}

/// Drive the real cross-zone request handler through a three-relay chain with
/// one same-zone edge and one approved crossing. This checks control messages,
/// per-crossing audit, actual WireGuard data, and policy withdrawal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_actual_three_relay_mint_audits_and_revokes_each_edge() {
    use meshharbor_remote_control::signaling::ServerMsg;
    use meshharbord::relay_server::backbone_test_support::{
        BindSecret, Carrier, NativeRelay, OrgRelayConn, WgDevice, WgKeypair, bind_member,
    };
    use std::{
        net::Ipv4Addr,
        sync::{Arc, atomic::AtomicBool},
    };
    let source_native = NativeRelay::start().await.unwrap();
    let middle_native = NativeRelay::start().await.unwrap();
    let exit_native = NativeRelay::start().await.unwrap();
    let key_a = WgKeypair::generate();
    let key_b = WgKeypair::generate();
    let mut l = LineRig::up("iso-actual-three", true).await;
    let (middle_agent, middle_token) =
        enroll(&l.rig.app, &l.rig.seeded, "iso-actual-three-middle").await;
    let mut middle = connect_from(&l.rig.app, &middle_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &middle_agent, Some(CN_R)).await;
    line_join(
        &mut middle,
        5,
        "223.6.6.7:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &middle_agent, true).await,
        200
    );
    let middle_node = l.rig.node("iso-actual-three-middle").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &middle_node).await;
    for (ws, key, endpoint) in [
        (&mut l.cn, key_a.public_base64(), "223.5.5.5:41641"),
        (&mut l.us, key_b.public_base64(), "8.8.8.8:41641"),
    ] {
        ws.send(Message::Text(
            json!({"t":"rc:overlay.join", "wg_public_key":key, "mtu":1280,
            "endpoints":[endpoint], "supports_org_relay":true, "supports_backbone_only_v1":true,
            "supports_server_relay_strategy":true, "org_primary":true})
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
            .await
            .expect("member rejoin");
    }
    let policy_path = |agent: &str| {
        format!(
            "/api/tenant/{}/agent/{agent}/peer-relay-policy",
            l.rig.seeded.tenant_id
        )
    };
    let gz_policy = policy_path(&l.gz_agent);
    let middle_policy = policy_path(&middle_agent);
    let policy = |target: &str, endpoint: &str, cross_border| {
        json!({ "serve": true, "approved_backbone_edges": [
            { "relay_agent_id": target, "endpoint": endpoint, "cross_border": cross_border },
        ]})
    };
    let admin = &l.rig.seeded.admin.access_token;
    let middle_endpoint = middle_native.underlay_endpoint().to_string();
    let exit_endpoint = exit_native.underlay_endpoint().to_string();
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        policy(&middle_agent, &middle_endpoint, false),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, false),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(700)
        )
        .await
        .is_none(),
        "crossing without approval must not mint"
    );
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, true),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let network = l.rig.app.state.network();
    let a = ObjectId::parse_str(&l.cn_node).unwrap();
    let b = ObjectId::parse_str(&l.us_node).unwrap();
    let gz_node = ObjectId::parse_str(&l.gz_node).unwrap();
    let mid_node = ObjectId::parse_str(&middle_node).unwrap();
    let hk_node = ObjectId::parse_str(&l.hk_node).unwrap();
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            a,
            &[
                (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
                (mid_node, "223.6.6.7:3478".into(), false, None),
            ]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            b,
            &[(hk_node, "1.1.1.1:3478".into(), true, Some(10)),]
        )
    );
    let selected = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
        network, a, b, false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        selected,
        (
            vec![
                ObjectId::parse_str(&l.gz_agent).unwrap(),
                ObjectId::parse_str(&middle_agent).unwrap(),
                ObjectId::parse_str(&l.hk_agent).unwrap()
            ],
            false
        )
    );
    relay_request(&mut l.cn, &l.us_node).await;
    let wait = Duration::from_secs(8);
    let gz = match recv_t(&mut l.gz, "rc:overlay.relay_serve", wait).await {
        Some(msg) => msg,
        None => panic!(
            "ingress serve absent; audits={:?}",
            l.audit_reasons("mint").await
        ),
    };
    let first_bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("first bridge");
    let mid = recv_t(&mut middle, "rc:overlay.relay_serve", wait)
        .await
        .expect("middle serve");
    let second_bridge = recv_t(&mut middle, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("second bridge");
    let hk = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
        .await
        .expect("exit serve");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("requester session");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("peer session");
    assert_eq!(cn["vni"], gz["vni"]);
    assert_eq!(us["vni"], hk["vni"]);
    assert_eq!(cn["relay_node_id"], json!(l.gz_node));
    assert_eq!(us["relay_node_id"], json!(l.hk_node));
    assert_eq!(first_bridge["bridge"]["local_vni"], gz["vni"]);
    assert_eq!(first_bridge["bridge"]["remote_vni"], mid["vni"]);
    assert_eq!(second_bridge["bridge"]["local_vni"], mid["vni"]);
    assert_eq!(second_bridge["bridge"]["remote_vni"], hk["vni"]);
    let pair = meshharbor_mod_network::overlay::pair_key(a, b);
    let live = network
        .org_relay
        .active_session(&pair)
        .expect("real multi-hop session");
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
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
    for i in 0..meshharbor_remote_control::models::peer_relay_limits::MAX_SESSIONS_PER_RELAY - 1 {
        let mut held = live.clone();
        held.pair_key = format!("nhop-reuse-capacity-{i}");
        held.relay = middle_party.clone();
        held.relay_agent_id = middle_agent_id;
        held.vni = 1000 + i as u32;
        held.generation = 1000 + i as u64;
        held.hops.clear();
        fixture_keys.push(held.pair_key.clone());
        assert!(support::insert_session_fixture(network, held));
    }
    assert!(
        support::reauthorize_nhop_fixture(network, a, b, &live).await,
        "own occupied slots must be reusable"
    );
    relay_request(&mut l.cn, &l.us_node).await;
    let repushed = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("reauthorized re-push");
    assert_eq!(repushed["vni"], cn["vni"]);
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(500)
        )
        .await
        .is_none(),
        "re-push must not mint another relay session"
    );
    for key in fixture_keys {
        assert!(support::remove_session_fixture(network, &key));
    }
    support::fail_next_nhop_reauth_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "transient read failure must not re-push"
    );
    assert_eq!(
        network.org_relay.active_session(&pair).unwrap().generation,
        live.generation,
        "transient failure must not tear down an established path"
    );
    for (relay, frame) in [
        (&source_native, gz.clone()),
        (&middle_native, mid.clone()),
        (&exit_native, hk.clone()),
    ] {
        relay.serve(serde_json::from_value::<ServerMsg>(frame).unwrap(), None);
    }
    source_native.serve(
        serde_json::from_value(first_bridge.clone()).unwrap(),
        Some(source_native.policy_to(&middle_native)),
    );
    middle_native.serve(
        serde_json::from_value(second_bridge.clone()).unwrap(),
        Some(middle_native.policy_to(&exit_native)),
    );
    let socket_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let secret = |frame: &Value| {
        BindSecret::from_bytes(
            BASE64
                .decode(frame["bind_secret"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    let vni = |frame: &Value| frame["vni"].as_u64().unwrap() as u32;
    let generation = |frame: &Value| frame["generation"].as_u64().unwrap();
    bind_member(
        &socket_a,
        source_native.endpoint(),
        vni(&cn),
        generation(&cn),
        &secret(&cn),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    bind_member(
        &socket_b,
        exit_native.endpoint(),
        vni(&us),
        generation(&us),
        &secret(&us),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let conn_a = Arc::new(OrgRelayConn::new(
        socket_a,
        source_native.endpoint(),
        vni(&cn),
        "test-ingress".into(),
    ));
    let conn_b = Arc::new(OrgRelayConn::new(
        socket_b,
        exit_native.endpoint(),
        vni(&us),
        "test-exit".into(),
    ));
    let carrier_a = Arc::new(Carrier::Relay {
        dst: conn_a.synth_peer(),
        conn: conn_a,
        dead: AtomicBool::new(false),
    });
    let carrier_b = Arc::new(Carrier::Relay {
        dst: conn_b.synth_peer(),
        conn: conn_b,
        dead: AtomicBool::new(false),
    });
    let ip_a: Ipv4Addr = network
        .overlay_nodes
        .base
        .find_by_id(a)
        .await
        .unwrap()
        .overlay_ip
        .parse()
        .unwrap();
    let ip_b: Ipv4Addr = network
        .overlay_nodes
        .base
        .find_by_id(b)
        .await
        .unwrap()
        .overlay_ip
        .parse()
        .unwrap();
    let (mut wg_a, mut received_a) = WgDevice::new(key_a.secret.clone());
    let (mut wg_b, mut received_b) = WgDevice::new(key_b.secret.clone());
    wg_a.add_peer(key_b.public.to_bytes(), ip_b, carrier_a, true);
    wg_b.add_peer(key_a.public.to_bytes(), ip_a, carrier_b, false);
    let packet = |source: Ipv4Addr, target: Ipv4Addr, payload: &[u8]| {
        let mut bytes = vec![0u8; 20 + payload.len()];
        bytes[0] = 0x45;
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&target.octets());
        bytes[20..].copy_from_slice(payload);
        bytes
    };
    let forward = packet(ip_a, ip_b, b"three relay actual WireGuard forward");
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            wg_a.send_ip_packet(&forward).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(150), received_b.recv()).await
                && got == forward
            {
                break;
            }
        }
    })
    .await
    .expect("actual forward WG packet across three native relays");
    let backward = packet(ip_b, ip_a, b"three relay actual WireGuard reverse");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_b.send_ip_packet(&backward).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(150), received_a.recv()).await
                && got == backward
            {
                break;
            }
        }
    })
    .await
    .expect("actual reverse WG packet across three native relays");
    let middle_conn = support::current_connection_id(network, middle_agent_id).unwrap();
    assert!(
        network
            .org_relay
            .unbind_live_conn(middle_agent_id, &middle_conn)
    );
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_millis(700)
        )
        .await
        .is_none(),
        "unknown middle relay must not receive a fresh re-push"
    );
    assert_eq!(
        network
            .org_relay
            .active_session(&pair)
            .expect("unknown middle relay must not revoke the established path")
            .generation,
        live.generation
    );
    support::recheck_zones_fixture(network, middle_agent_id).await;
    assert_eq!(
        network
            .org_relay
            .active_session(&pair)
            .expect("unknown middle relay must also survive the active zone recheck")
            .generation,
        live.generation
    );
    let during_unknown = packet(
        ip_a,
        ip_b,
        b"healthy WireGuard path while middle region is unknown",
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            wg_a.send_ip_packet(&during_unknown).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(150), received_b.recv()).await
                && got == during_unknown
            {
                break;
            }
        }
    })
    .await
    .expect("uncertain geography must not interrupt established encrypted data");
    network
        .org_relay
        .bind_live_conn(middle_agent_id, &middle_conn);
    line_join(
        &mut middle,
        5,
        "223.6.6.7:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    let crossing_reason = format!("cross_border_edge:{}", l.hk_agent);
    let audits = l.audit_reasons("mint").await;
    assert!(
        audits
            .iter()
            .any(|(reason, node)| reason == &crossing_reason && node == &middle_node),
        "per-edge crossing audit missing: {audits:?}"
    );
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, false),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    for (name, ws, vni) in [
        ("ingress", &mut l.gz, &gz["vni"]),
        ("middle", &mut middle, &mid["vni"]),
        ("exit", &mut l.hk, &hk["vni"]),
        ("requester", &mut l.cn, &cn["vni"]),
        ("peer", &mut l.us, &us["vni"]),
    ] {
        let revoke = recv_t(ws, "rc:overlay.relay_revoke", wait)
            .await
            .unwrap_or_else(|| panic!("{name} revoke"));
        assert_eq!(&revoke["vni"], vni, "{name} vni");
        match name {
            "ingress" => source_native.serve(serde_json::from_value(revoke).unwrap(), None),
            "middle" => middle_native.serve(serde_json::from_value(revoke).unwrap(), None),
            "exit" => exit_native.serve(serde_json::from_value(revoke).unwrap(), None),
            _ => {}
        }
    }
    let first_revoke = recv_t(&mut l.gz, "rc:overlay.relay_bridge_revoke", wait)
        .await
        .expect("first bridge revoke");
    let second_revoke = recv_t(&mut middle, "rc:overlay.relay_bridge_revoke", wait)
        .await
        .expect("second bridge revoke");
    source_native.serve(serde_json::from_value(first_revoke).unwrap(), None);
    middle_native.serve(serde_json::from_value(second_revoke).unwrap(), None);
    while received_b.try_recv().is_ok() {}
    let after = packet(ip_a, ip_b, b"must not traverse revoked bridge");
    wg_a.send_ip_packet(&after).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), received_b.recv())
            .await
            .is_err(),
        "revoked path must not deliver new WG traffic"
    );

    // Force the actual policy update between the server claim and delivery.
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, true),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            a,
            &[
                (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
                (mid_node, "223.6.6.7:3478".into(), false, None),
            ]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            b,
            &[(hk_node, "1.1.1.1:3478".into(), true, Some(10)),]
        )
    );
    let pair = meshharbor_mod_network::overlay::pair_key(a, b);
    let (reached, resume) =
        meshharbor_mod_network::org_relay::candidate_test_support::pause_nhop_delivery_fixture(
            pair.clone(),
        );
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached)
        .await
        .expect("claim pause")
        .unwrap();
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, false),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(700)
        )
        .await
        .is_none(),
        "revoked candidate must not deliver a relay grant"
    );
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_millis(700)
        )
        .await
        .is_none(),
        "revoked candidate must not deliver a member grant"
    );
    assert!(network.org_relay.active_session(&pair).is_none());

    // Force a policy withdrawal after the first eligibility check but before
    // its send. The delivery guard keeps the revoke ordered after the grant.
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, true),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            a,
            &[
                (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
                (mid_node, "223.6.6.7:3478".into(), false, None),
            ]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            b,
            &[(hk_node, "1.1.1.1:3478".into(), true, Some(10)),]
        )
    );
    let (reached, release) =
        meshharbor_mod_network::org_relay::candidate_test_support::pause_nhop_before_first_fixture(
            pair.clone(),
        );
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached)
        .await
        .expect("first delivery pause")
        .unwrap();
    let withdrawal = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, false),
    );
    let release_after_update_starts = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        release.send(()).unwrap();
    };
    let ((status, body), ()) = tokio::join!(withdrawal, release_after_update_starts);
    assert_eq!(status, 200, "{body}");
    let sent = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
        .await
        .expect("first grant was queued");
    let revoked = recv_t(&mut l.gz, "rc:overlay.relay_revoke", wait)
        .await
        .expect("revoke follows first grant");
    assert_eq!(sent["vni"], revoked["vni"]);
    assert!(network.org_relay.active_session(&pair).is_none());

    // Re-establish a real multi-hop session. Pause its reauthorization just
    // before re-push, revoke an edge, and prove the old member grant does not
    // get queued after revocation.
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, true),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(support::record_member_probe_fixture(
        network,
        a,
        &[
            (gz_node, "223.6.6.6:3478".into(), true, Some(10)),
            (mid_node, "223.6.6.7:3478".into(), false, None),
        ]
    ));
    assert!(support::record_member_probe_fixture(
        network,
        b,
        &[(hk_node, "1.1.1.1:3478".into(), true, Some(10))]
    ));
    relay_request(&mut l.cn, &l.us_node).await;
    recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
        .await
        .expect("new ingress");
    recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("new first bridge");
    recv_t(&mut middle, "rc:overlay.relay_serve", wait)
        .await
        .expect("new middle");
    recv_t(&mut middle, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("new second bridge");
    recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
        .await
        .expect("new exit");
    recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("new member");
    recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("new peer");
    let (reached, resume) = support::pause_nhop_repush_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached)
        .await
        .expect("repush pause")
        .unwrap();
    let (status, body) = put(
        &l.rig.app,
        &middle_policy,
        admin,
        policy(&l.hk_agent, &exit_endpoint, false),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "revoked path must not be re-pushed"
    );
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
    line_join(
        &mut m1,
        5,
        "1.1.1.2:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    line_join(
        &mut m2,
        6,
        "223.6.6.8:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &m1_agent, true).await,
        200
    );
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &m2_agent, true).await,
        200
    );
    let m1_node = l.rig.node("iso-actual-four-mid1").await;
    let m2_node = l.rig.node("iso-actual-four-mid2").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &m1_node).await;
    grant_relay(&l.rig.app, &l.rig.seeded, &m2_node).await;
    let admin = &l.rig.seeded.admin.access_token;
    let policy = |target: &str, endpoint: &str, cross_border| {
        json!({ "serve": true, "approved_backbone_edges": [
            { "relay_agent_id": target, "endpoint": endpoint, "cross_border": cross_border },
        ]})
    };
    for (source, target, endpoint, crossing) in [
        (&l.gz_agent, &m1_agent, "10.44.0.1:3478", true),
        (&m1_agent, &m2_agent, "10.44.0.2:3478", true),
        (&m2_agent, &l.hk_agent, "10.44.0.3:3478", true),
    ] {
        let path = format!(
            "/api/tenant/{}/agent/{source}/peer-relay-policy",
            l.rig.seeded.tenant_id
        );
        let (status, body) =
            put(&l.rig.app, &path, admin, policy(target, endpoint, crossing)).await;
        assert_eq!(status, 200, "{body}");
    }
    let network = l.rig.app.state.network();
    let a = ObjectId::parse_str(&l.cn_node).unwrap();
    let b = ObjectId::parse_str(&l.us_node).unwrap();
    let gz = ObjectId::parse_str(&l.gz_node).unwrap();
    let mid1 = ObjectId::parse_str(&m1_node).unwrap();
    let mid2 = ObjectId::parse_str(&m2_node).unwrap();
    let hk = ObjectId::parse_str(&l.hk_node).unwrap();
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            a,
            &[
                (gz, "223.6.6.6:3478".into(), true, Some(10)),
                (mid2, "223.6.6.8:3478".into(), false, None),
            ]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            b,
            &[
                (hk, "1.1.1.1:3478".into(), true, Some(10)),
                (mid1, "1.1.1.2:3478".into(), false, None),
            ]
        )
    );
    let chosen = meshharbor_mod_network::org_relay::candidate_test_support::select_path(
        network, a, b, false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        chosen,
        (
            vec![
                ObjectId::parse_str(&l.gz_agent).unwrap(),
                ObjectId::parse_str(&m1_agent).unwrap(),
                ObjectId::parse_str(&m2_agent).unwrap(),
                ObjectId::parse_str(&l.hk_agent).unwrap()
            ],
            false
        )
    );
    relay_request(&mut l.cn, &l.us_node).await;
    let wait = Duration::from_secs(8);
    let first = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
        .await
        .expect("first serve");
    let bridge1 = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("first bridge");
    let second = recv_t(&mut m1, "rc:overlay.relay_serve", wait)
        .await
        .expect("second serve");
    let bridge2 = recv_t(&mut m1, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("second bridge");
    let third = recv_t(&mut m2, "rc:overlay.relay_serve", wait)
        .await
        .expect("third serve");
    let bridge3 = recv_t(&mut m2, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("third bridge");
    let last = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
        .await
        .expect("last serve");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("requester grant");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("peer grant");
    for (bridge, source, target) in [
        (&bridge1, &first, &second),
        (&bridge2, &second, &third),
        (&bridge3, &third, &last),
    ] {
        assert_eq!(bridge["bridge"]["local_vni"], source["vni"]);
        assert_eq!(bridge["bridge"]["remote_vni"], target["vni"]);
    }
    assert_eq!(cn["vni"], first["vni"]);
    assert_eq!(us["vni"], last["vni"]);
    let audits = l.audit_reasons("mint").await;
    for (source_node, target_agent) in [
        (&l.gz_node, &m1_agent),
        (&m1_node, &m2_agent),
        (&m2_node, &l.hk_agent),
    ] {
        let reason = format!("cross_border_edge:{target_agent}");
        assert!(
            audits
                .iter()
                .any(|(r, node)| r == &reason && node == source_node),
            "missing crossing audit: {audits:?}"
        );
    }
    // Withdraw the active path, restore it, and exhaust the real requester /
    // ingress limiter. A refused request must not write crossing-mint rows.
    let gz_policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, l.gz_agent
    );
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        json!({"serve": true, "approved_backbone_edges": []}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        policy(&m1_agent, "10.44.0.1:3478", true),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            a,
            &[
                (gz, "223.6.6.6:3478".into(), true, Some(10)),
                (mid2, "223.6.6.8:3478".into(), false, None),
            ]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_member_probe_fixture(
            network,
            b,
            &[
                (hk, "1.1.1.1:3478".into(), true, Some(10)),
                (mid1, "1.1.1.2:3478".into(), false, None),
            ]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_backbone_probe_fixture(
            network,
            gz,
            &[(mid1, "10.44.0.1:3478".into(), true, Some(100)),]
        )
    );
    assert!(
        meshharbor_mod_network::org_relay::candidate_test_support::record_backbone_probe_fixture(
            network,
            mid2,
            &[(hk, "10.44.0.3:3478".into(), true, Some(5)),]
        )
    );
    let limit = meshharbor_remote_control::models::peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE;
    for _ in 0..limit {
        network.relay_rate_limiter.check(a, gz, limit);
    }
    let crossing_count = |rows: &[(String, String)]| {
        rows.iter()
            .filter(|(r, _)| r.starts_with("cross_border_edge:"))
            .count()
    };
    let before = crossing_count(&l.audit_reasons("mint").await);
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "rate-limited path must not be served"
    );
    let after = crossing_count(&l.audit_reasons("mint").await);
    assert_eq!(
        after, before,
        "rate-limit denial must precede crossing audit rows"
    );
    let pair = meshharbor_mod_network::overlay::pair_key(a, b);
    let fallback = network
        .org_relay
        .active_session(&pair)
        .expect("an available alternate ingress is replanned");
    assert_eq!(fallback.hops.len(), 1);
    // Either directed approved crossing may win; its orientation determines
    // which member binds the ingress. The rate-limited GZ cannot be chosen.
    let (ingress, bridge, exit, flipped) = if fallback.relay.node_id == mid1 {
        (
            recv_t(&mut m1, "rc:overlay.relay_serve", wait)
                .await
                .expect("alternate ingress"),
            recv_t(&mut m1, "rc:overlay.relay_bridge_serve", wait)
                .await
                .expect("alternate bridge"),
            recv_t(&mut m2, "rc:overlay.relay_serve", wait)
                .await
                .expect("alternate exit"),
            true,
        )
    } else {
        assert_eq!(fallback.relay.node_id, mid2);
        (
            recv_t(&mut m2, "rc:overlay.relay_serve", wait)
                .await
                .expect("alternate ingress"),
            recv_t(&mut m2, "rc:overlay.relay_bridge_serve", wait)
                .await
                .expect("alternate bridge"),
            recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
                .await
                .expect("alternate exit"),
            false,
        )
    };
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("fallback requester");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("fallback peer");
    assert_eq!(bridge["bridge"]["local_vni"], ingress["vni"]);
    assert_eq!(bridge["bridge"]["remote_vni"], exit["vni"]);
    assert_eq!(
        if flipped { &us["vni"] } else { &cn["vni"] },
        &ingress["vni"]
    );
    assert_eq!(if flipped { &cn["vni"] } else { &us["vni"] }, &exit["vni"]);
}

/// A selected multi-hop attempt whose crossing audit fails must still replan a
/// safe direct line. Also force an authorization epoch change before claim.
/// The same ingress has exactly one token left for the second attempt, which
/// the multi-hop attempt consumes; fallback must not spend it twice.
#[tokio::test]
async fn staged_graph_long_path_audit_failure_falls_back_without_double_rate_charge() {
    let mut l = LineRig::up("iso-multi-audit-fallback", true).await;
    let (mid_agent, mid_token) =
        enroll(&l.rig.app, &l.rig.seeded, "iso-multi-audit-fallback-mid").await;
    let mut mid_ws = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(
        &mut mid_ws,
        5,
        "223.6.6.7:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await,
        200
    );
    let mid_node = l.rig.node("iso-multi-audit-fallback-mid").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let admin = &l.rig.seeded.admin.access_token;
    let gz_policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, l.gz_agent
    );
    let mid_policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, mid_agent
    );
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":mid_agent,"endpoint":"10.55.0.2:3478","cross_border":false},
            {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.3:3478","cross_border":true},
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(
        &l.rig.app,
        &mid_policy,
        admin,
        json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.4:3478","cross_border":true},
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let network = l.rig.app.state.network();
    let (a, b, gz, mid, hk) = (
        ObjectId::parse_str(&l.cn_node).unwrap(),
        ObjectId::parse_str(&l.us_node).unwrap(),
        ObjectId::parse_str(&l.gz_node).unwrap(),
        ObjectId::parse_str(&mid_node).unwrap(),
        ObjectId::parse_str(&l.hk_node).unwrap(),
    );
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    assert!(support::record_member_probe_fixture(
        network,
        a,
        &[
            (gz, "223.6.6.6:3478".into(), true, Some(10)),
            (mid, "223.6.6.7:3478".into(), false, None),
        ]
    ));
    assert!(support::record_member_probe_fixture(
        network,
        b,
        &[(hk, "1.1.1.1:3478".into(), true, Some(10))]
    ));
    assert!(support::record_backbone_probe_fixture(
        network,
        gz,
        &[
            (mid, "10.55.0.2:3478".into(), true, Some(5)),
            (hk, "10.55.0.3:3478".into(), true, Some(100)),
        ]
    ));
    assert!(support::record_backbone_probe_fixture(
        network,
        mid,
        &[(hk, "10.55.0.4:3478".into(), true, Some(5))]
    ));
    let selected = support::select_path(network, a, b, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        selected,
        (
            vec![
                ObjectId::parse_str(&l.gz_agent).unwrap(),
                ObjectId::parse_str(&mid_agent).unwrap(),
                ObjectId::parse_str(&l.hk_agent).unwrap()
            ],
            false
        )
    );
    let limit = meshharbor_remote_control::models::peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE;
    let pair = meshharbor_mod_network::overlay::pair_key(a, b);
    // If both audits fail, fallback must still fail closed and send no grant.
    support::fail_next_nhop_audit_fixture(pair.clone());
    support::fail_next_line_audit_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "failed line audit must not serve"
    );
    assert!(
        recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "failed line audit must not grant"
    );
    assert!(network.org_relay.active_session(&pair).is_none());
    // Remove only the long path after its audit/selection but before claim.
    // The direct edge stays approved; the new policy epoch must trigger a
    // fresh, successful direct-line replan.
    let (reached, resume) = support::pause_nhop_preclaim_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached)
        .await
        .expect("preclaim pause")
        .unwrap();
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.3:3478","cross_border":true},
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    let wait = Duration::from_secs(8);
    recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
        .await
        .expect("direct ingress after epoch change");
    recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("direct bridge after epoch change");
    recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
        .await
        .expect("direct exit after epoch change");
    recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("requester after epoch change");
    recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("peer after epoch change");
    // Remove the direct session, restore both edges, and re-establish the
    // measurements invalidated by policy edits.
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        json!({"serve":true,"approved_backbone_edges":[]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":mid_agent,"endpoint":"10.55.0.2:3478","cross_border":false},
            {"relay_agent_id":l.hk_agent,"endpoint":"10.55.0.3:3478","cross_border":true},
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(support::record_member_probe_fixture(
        network,
        a,
        &[
            (gz, "223.6.6.6:3478".into(), true, Some(10)),
            (mid, "223.6.6.7:3478".into(), false, None),
        ]
    ));
    assert!(support::record_member_probe_fixture(
        network,
        b,
        &[(hk, "1.1.1.1:3478".into(), true, Some(10))]
    ));
    assert!(support::record_backbone_probe_fixture(
        network,
        gz,
        &[
            (mid, "10.55.0.2:3478".into(), true, Some(5)),
            (hk, "10.55.0.3:3478".into(), true, Some(100)),
        ]
    ));
    assert!(support::record_backbone_probe_fixture(
        network,
        mid,
        &[(hk, "10.55.0.4:3478".into(), true, Some(5))]
    ));
    assert_eq!(
        support::select_path(network, a, b, false)
            .await
            .unwrap()
            .unwrap()
            .0
            .len(),
        3
    );
    // The first two attempts each consumed one token; leave exactly one more.
    for _ in 0..limit - 3 {
        assert!(network.relay_rate_limiter.check(a, gz, limit));
    }
    support::fail_next_nhop_audit_fixture(pair);
    relay_request(&mut l.cn, &l.us_node).await;
    let wait = Duration::from_secs(8);
    let first = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
        .await
        .expect("fresh direct-line ingress");
    let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("fresh direct-line bridge");
    let last = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
        .await
        .expect("fresh direct-line exit");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("requester grant");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("peer grant");
    assert_eq!(bridge["bridge"]["remote_vni"], last["vni"]);
    assert_eq!(cn["vni"], first["vni"]);
    assert_eq!(us["vni"], last["vni"]);
    assert!(
        recv_t(
            &mut mid_ws,
            "rc:overlay.relay_serve",
            Duration::from_millis(500)
        )
        .await
        .is_none(),
        "failed multi-hop candidate must not be sent"
    );
    assert!(
        !network.relay_rate_limiter.check(a, gz, limit),
        "the one remaining token was consumed once"
    );
}

/// Saturate the selected ingress after multi-hop reauthorization but before
/// claim. The direct fallback must be freshly planned on the other ingress.
#[tokio::test]
async fn staged_graph_long_path_capacity_race_falls_back_to_available_line() {
    use meshharbor_mod_network::org_relay::{
        OrgRelaySession, SessionMember, SessionParty, candidate_test_support as support,
    };
    use meshharbor_remote_control::models::{NodeRef, peer_relay_limits as limits};
    use std::time::Instant;
    let mut l = LineRig::up("iso-multi-cap-fallback", true).await;
    let (mid_agent, mid_token) =
        enroll(&l.rig.app, &l.rig.seeded, "iso-multi-cap-fallback-mid").await;
    let mut mid_ws = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(
        &mut mid_ws,
        5,
        "223.6.6.7:41641",
        json!({ "relay_backbone_ready": true }),
    )
    .await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await,
        200
    );
    let mid_node = l.rig.node("iso-multi-cap-fallback-mid").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let admin = &l.rig.seeded.admin.access_token;
    let gz_policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, l.gz_agent
    );
    let mid_policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, mid_agent
    );
    let (status, body) = put(
        &l.rig.app,
        &gz_policy,
        admin,
        json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":mid_agent,"endpoint":"10.56.0.2:3478","cross_border":false},
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = put(
        &l.rig.app,
        &mid_policy,
        admin,
        json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":l.hk_agent,"endpoint":"10.56.0.3:3478","cross_border":true},
        ]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let network = l.rig.app.state.network();
    let (a, b, gz, mid, hk) = (
        ObjectId::parse_str(&l.cn_node).unwrap(),
        ObjectId::parse_str(&l.us_node).unwrap(),
        ObjectId::parse_str(&l.gz_node).unwrap(),
        ObjectId::parse_str(&mid_node).unwrap(),
        ObjectId::parse_str(&l.hk_node).unwrap(),
    );
    assert!(support::record_member_probe_fixture(
        network,
        a,
        &[
            (gz, "223.6.6.6:3478".into(), true, Some(10)),
            (mid, "223.6.6.7:3478".into(), false, None),
        ]
    ));
    assert!(support::record_member_probe_fixture(
        network,
        b,
        &[(hk, "1.1.1.1:3478".into(), true, Some(10))]
    ));
    let selected = support::select_path(network, a, b, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.0.len(), 3);
    let pair = meshharbor_mod_network::overlay::pair_key(a, b);
    let (reached, resume) = support::pause_nhop_preclaim_fixture(pair.clone());
    relay_request(&mut l.cn, &l.us_node).await;
    tokio::time::timeout(Duration::from_secs(10), reached)
        .await
        .expect("preclaim pause")
        .unwrap();
    let gz_agent = ObjectId::parse_str(&l.gz_agent).unwrap();
    let tenant = ObjectId::parse_str(&l.rig.seeded.tenant_id).unwrap();
    let party = |id| SessionParty {
        node_id: id,
        node_ref: NodeRef::Agent { agent_id: id },
    };
    let member = |id| SessionMember {
        party: party(id),
        wg_public_key: "fixture".into(),
        bind_secret: "fixture".into(),
    };
    for i in 0..limits::MAX_SESSIONS_PER_RELAY {
        let fixture = OrgRelaySession {
            tenant_id: tenant,
            pair_key: format!("capacity-fixture-{i}"),
            vni: i as u32 + 1000,
            generation: i as u64 + 1000,
            relay: SessionParty {
                node_id: gz,
                node_ref: NodeRef::Agent { agent_id: gz_agent },
            },
            relay_agent_id: gz_agent,
            implicit: false,
            members: [member(ObjectId::new()), member(ObjectId::new())],
            endpoints: vec!["fixture".into()],
            expires_at: Instant::now() + Duration::from_secs(90),
            bind_by: Instant::now() + Duration::from_secs(30),
            hops: Vec::new(),
        };
        assert!(support::insert_session_fixture(network, fixture));
    }
    resume.send(()).unwrap();
    let wait = Duration::from_secs(8);
    let first = recv_t(&mut mid_ws, "rc:overlay.relay_serve", wait)
        .await
        .expect("alternate ingress after capacity race");
    let bridge = recv_t(&mut mid_ws, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("alternate bridge");
    let last = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
        .await
        .expect("alternate exit");
    let cn = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
        .await
        .expect("requester grant");
    let us = recv_t(&mut l.us, "rc:overlay.relay_session", wait)
        .await
        .expect("peer grant");
    assert_eq!(cn["relay_node_id"], json!(mid_node));
    assert_eq!(cn["vni"], first["vni"]);
    assert_eq!(bridge["bridge"]["remote_vni"], last["vni"]);
    assert_eq!(us["vni"], last["vni"]);
    assert!(
        recv_t(
            &mut l.gz,
            "rc:overlay.relay_serve",
            Duration::from_millis(500)
        )
        .await
        .is_none()
    );
}

/// Two-relay lines, including a concurrent claim winner, must go through the
/// same complete, guarded reauthorization as longer multi-hop sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_two_relay_repush_and_claim_reauthorize_every_edge() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    async fn request(ws: &mut Ws, peer: &str, fallback: bool, serial: u64) {
        if fallback {
            ws.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request", "peer_node_id":peer, "request_id":serial}).to_string().into())).await.unwrap();
        } else {
            relay_request(ws, peer).await;
        }
    }
    for fallback in [false, true] {
        let slug = format!(
            "iso-two-reauth-{}",
            if fallback { "fallback" } else { "normal" }
        );
        let mut l = LineRig::up(&slug, true).await;
        let a = ObjectId::parse_str(&l.cn_node).unwrap();
        let b = ObjectId::parse_str(&l.us_node).unwrap();
        let pair = meshharbor_mod_network::overlay::pair_key(a, b);
        request(&mut l.cn, &l.us_node, fallback, 1).await;
        let (_, _, _, cn, _) = l.expect_line().await;
        let network = l.rig.app.state.network();
        let original = network
            .org_relay
            .active_session(&pair)
            .expect("two-relay session");
        assert_eq!(original.hops.len(), 1);
        assert!(
            support::reauthorize_nhop_fixture(network, a, b, &original).await,
            "current line must pass full authorization"
        );
        let mut bad_edge = original.clone();
        bad_edge.hops[0].private_endpoint = "10.77.1.9:3478".into();
        assert!(
            !support::reauthorize_nhop_fixture(network, a, b, &bad_edge).await,
            "changed edge address must fail"
        );
        let mut bad_cross = original.clone();
        bad_cross.hops[0].requires_cross_border_approval = false;
        assert!(
            !support::reauthorize_nhop_fixture(network, a, b, &bad_cross).await,
            "crossing bit cannot be cleared"
        );
        support::fail_next_nhop_reauth_fixture(pair.clone());
        request(&mut l.cn, &l.us_node, fallback, 2).await;
        assert!(
            recv_t(
                &mut l.cn,
                "rc:overlay.relay_session",
                Duration::from_millis(800)
            )
            .await
            .is_none(),
            "unreadable line was re-pushed"
        );
        assert_eq!(
            network.org_relay.active_session(&pair).unwrap().generation,
            original.generation,
            "transient read failure should preserve current line"
        );
        request(&mut l.cn, &l.us_node, fallback, 3).await;
        let retry = recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_secs(8),
        )
        .await
        .expect("healthy line re-push");
        assert_eq!(retry["vni"], cn["vni"]);
        // A stale key is a definite denial, not a read failure. The old
        // generation must be revoked before any replacement is sent.
        assert!(support::invalidate_session_member_key_fixture(
            network, &pair
        ));
        request(&mut l.cn, &l.us_node, fallback, 4).await;
        let revoke = recv_t(&mut l.cn, "rc:overlay.relay_revoke", Duration::from_secs(8))
            .await
            .expect("invalid line revoked");
        assert_eq!(revoke["vni"], cn["vni"]);
        let replacement = recv_t(
            &mut l.cn,
            "rc:overlay.relay_session",
            Duration::from_secs(8),
        )
        .await
        .expect("fresh line planned");
        assert_ne!(
            replacement["vni"], cn["vni"],
            "old line key must never be re-pushed"
        );
    }
    for unavailable in [false, true] {
        let slug = format!(
            "iso-two-claim-{}",
            if unavailable {
                "unavailable"
            } else {
                "invalid"
            }
        );
        let mut l = LineRig::up(&slug, true).await;
        let a = ObjectId::parse_str(&l.cn_node).unwrap();
        let b = ObjectId::parse_str(&l.us_node).unwrap();
        let pair = meshharbor_mod_network::overlay::pair_key(a, b);
        let (reached, resume) = support::pause_line_preclaim_fixture(pair.clone());
        relay_request(&mut l.cn, &l.us_node).await;
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .expect("losing line claim paused")
            .unwrap();
        relay_request(&mut l.us, &l.cn_node).await;
        let (_, _, _, cn, _) = l.expect_line().await;
        let network = l.rig.app.state.network();
        let winner = network
            .org_relay
            .active_session(&pair)
            .expect("winning two-relay line");
        assert_eq!(winner.hops.len(), 1);
        if unavailable {
            support::fail_next_nhop_reauth_fixture(pair.clone());
            resume.send(()).unwrap();
            assert!(
                recv_t(
                    &mut l.cn,
                    "rc:overlay.relay_session",
                    Duration::from_millis(800)
                )
                .await
                .is_none(),
                "losing claim bypassed unreadable two-relay authorization"
            );
            assert_eq!(
                network.org_relay.active_session(&pair).unwrap().generation,
                winner.generation
            );
            relay_request(&mut l.cn, &l.us_node).await;
            let retry = recv_t(
                &mut l.cn,
                "rc:overlay.relay_session",
                Duration::from_secs(8),
            )
            .await
            .expect("winning line re-push");
            assert_eq!(retry["vni"], cn["vni"]);
        } else {
            assert!(support::invalidate_session_member_key_fixture(
                network, &pair
            ));
            resume.send(()).unwrap();
            let revoke = recv_t(&mut l.cn, "rc:overlay.relay_revoke", Duration::from_secs(8))
                .await
                .expect("invalid concurrent winner revoked");
            assert_eq!(revoke["vni"], cn["vni"]);
            assert!(network.org_relay.active_session(&pair).is_none());
            assert!(
                recv_t(
                    &mut l.cn,
                    "rc:overlay.relay_session",
                    Duration::from_millis(500)
                )
                .await
                .is_none(),
                "invalid concurrent winner re-pushed"
            );
        }
    }
}

/// Off/Warn business isolation permits explicitly approved cross-zone paths.
/// Peer-relay Warn remains audit-only; actual On grants carry WG until revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_off_warn_cross_zone_actual_wg_and_warn_only() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    use meshharbor_remote_control::signaling::ServerMsg;
    use meshharbord::relay_server::backbone_test_support::{
        BindSecret, Carrier, NativeRelay, OrgRelayConn, WgDevice, WgKeypair, bind_member,
    };
    use std::{
        net::Ipv4Addr,
        sync::{Arc, atomic::AtomicBool},
    };
    for (isolation, fallback) in [
        ("off", false),
        ("off", true),
        ("warn", false),
        ("warn", true),
    ] {
        let slug = format!(
            "iso-cross-wg-{isolation}-{}",
            if fallback { "fallback" } else { "normal" }
        );
        let native = [
            NativeRelay::start().await.unwrap(),
            NativeRelay::start().await.unwrap(),
            NativeRelay::start().await.unwrap(),
        ];
        let key_a = WgKeypair::generate();
        let key_b = WgKeypair::generate();
        let rig = Rig::up(&slug, isolation).await;
        let mut relays = Vec::new();
        let mut agents = Vec::new();
        let mut nodes = Vec::new();
        let endpoints = ["223.6.6.6:41641", "223.6.6.7:41641", "1.1.1.1:41641"];
        let public = ["223.6.6.6:3478", "223.6.6.7:3478", "1.1.1.1:3478"];
        for i in 0..3 {
            let name = format!("{slug}-r{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let from = if i < 2 { CN_R } else { US_R };
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(from)).await;
            assert_observed(&rig.app, &agent, Some(from)).await;
            line_join(
                &mut ws,
                10 + i,
                endpoints[i as usize],
                json!({"relay_backbone_ready":true}),
            )
            .await;
            assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
            let node = rig.node(&name).await;
            grant_relay(&rig.app, &rig.seeded, &node).await;
            relays.push(ws);
            agents.push(agent);
            nodes.push(node);
        }
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig.device(&format!("{slug}-b"), Some(US_A)).await;
        for (ws, key, endpoint) in [
            (&mut a, key_a.public_base64(), "223.5.5.5:41641"),
            (&mut b, key_b.public_base64(), "8.8.8.8:41641"),
        ] {
            ws.send(Message::Text(
                json!({"t":"rc:overlay.join", "wg_public_key":key, "mtu":1280,
                "endpoints":[endpoint], "supports_org_relay":true, "supports_backbone_only_v1":true,
                "supports_server_relay_strategy":true, "org_primary":true})
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
            recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
                .await
                .expect("member join");
        }
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        let path = |agent: &str| {
            format!(
                "/api/tenant/{}/agent/{agent}/peer-relay-policy",
                rig.seeded.tenant_id
            )
        };
        for i in 0..2 {
            let (status, body) = put(&rig.app, &path(&agents[i]), &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],
                    "endpoint":native[i+1].underlay_endpoint().to_string(),"cross_border":i == 1}]})).await;
            assert_eq!(status, 200, "{body}");
        }
        let network = rig.app.state.network();
        let ids: Vec<_> = nodes
            .iter()
            .map(|n| ObjectId::parse_str(n).unwrap())
            .collect();
        let record = || {
            let ar: Vec<_> = (0..3)
                .map(|i| (ids[i], public[i].into(), i == 0, (i == 0).then_some(10)))
                .collect();
            let br: Vec<_> = (0..3)
                .map(|i| (ids[i], public[i].into(), i == 2, (i == 2).then_some(10)))
                .collect();
            assert!(support::record_member_probe_fixture(network, a_id, &ar));
            assert!(support::record_member_probe_fixture(network, b_id, &br));
            for i in 0..2 {
                assert!(support::record_backbone_probe_fixture(
                    network,
                    ids[i],
                    &[(
                        ids[i + 1],
                        native[i + 1].underlay_endpoint().to_string(),
                        true,
                        Some(5)
                    )]
                ));
            }
        };
        async fn request(ws: &mut Ws, peer: ObjectId, fallback: bool, serial: u64) {
            if fallback {
                ws.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request","peer_node_id":peer.to_hex(),"request_id":serial}).to_string().into())).await.unwrap();
            } else {
                relay_request(ws, &peer.to_hex()).await;
            }
        }
        let pair = meshharbor_mod_network::overlay::pair_key(a_id, b_id);
        let reason = format!("cross_border_edge:{}", agents[2]);
        set_mode(&rig.app, &rig.seeded, "warn").await;
        record();
        request(&mut a, b_id, fallback, 1).await;
        assert!(
            recv_t(
                &mut a,
                "rc:overlay.relay_session",
                Duration::from_millis(600)
            )
            .await
            .is_none(),
            "{slug}: warn emitted a grant"
        );
        for ws in &mut relays {
            assert!(
                recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(150))
                    .await
                    .is_none()
            );
        }
        assert!(
            network.org_relay.active_session(&pair).is_none(),
            "warn allocated a session"
        );
        assert!(
            audit_rows(&rig.app, &rig.seeded)
                .await
                .iter()
                .any(|row| row["reason"] == reason && row["warn_only"] == true),
            "warn crossing audit missing: {slug}"
        );
        set_mode(&rig.app, &rig.seeded, "on").await;
        record();
        request(&mut a, b_id, fallback, 2).await;
        let wait = Duration::from_secs(8);
        let mut serves = Vec::new();
        for ws in &mut relays {
            serves.push(
                recv_t(ws, "rc:overlay.relay_serve", wait)
                    .await
                    .expect("relay serve"),
            );
        }
        let bridge0 = recv_t(&mut relays[0], "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("first bridge");
        let bridge1 = recv_t(&mut relays[1], "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("crossing bridge");
        let sa = recv_t(&mut a, "rc:overlay.relay_session", wait)
            .await
            .expect("requester grant");
        let sb = recv_t(&mut b, "rc:overlay.relay_session", wait)
            .await
            .expect("peer grant");
        assert_eq!(sa["vni"], serves[0]["vni"]);
        assert_eq!(sb["vni"], serves[2]["vni"]);
        assert_eq!(bridge0["bridge"]["local_vni"], serves[0]["vni"]);
        assert_eq!(bridge0["bridge"]["remote_vni"], serves[1]["vni"]);
        assert_eq!(bridge1["bridge"]["local_vni"], serves[1]["vni"]);
        assert_eq!(bridge1["bridge"]["remote_vni"], serves[2]["vni"]);
        assert!(
            audit_rows(&rig.app, &rig.seeded)
                .await
                .iter()
                .any(|row| row["reason"] == reason && row["warn_only"] == false),
            "actual crossing audit missing: {slug}"
        );
        for (relay, frame) in native.iter().zip(serves.iter()) {
            relay.serve(
                serde_json::from_value::<ServerMsg>(frame.clone()).unwrap(),
                None,
            );
        }
        native[0].serve(
            serde_json::from_value(bridge0).unwrap(),
            Some(native[0].policy_to(&native[1])),
        );
        native[1].serve(
            serde_json::from_value(bridge1).unwrap(),
            Some(native[1].policy_to(&native[2])),
        );
        let socket_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let secret = |frame: &Value| {
            BindSecret::from_bytes(
                BASE64
                    .decode(frame["bind_secret"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        };
        let vni = |frame: &Value| frame["vni"].as_u64().unwrap() as u32;
        let generation = |frame: &Value| frame["generation"].as_u64().unwrap();
        bind_member(
            &socket_a,
            native[0].endpoint(),
            vni(&sa),
            generation(&sa),
            &secret(&sa),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        bind_member(
            &socket_b,
            native[2].endpoint(),
            vni(&sb),
            generation(&sb),
            &secret(&sb),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let conn_a = Arc::new(OrgRelayConn::new(
            socket_a,
            native[0].endpoint(),
            vni(&sa),
            "off-warn-ingress".into(),
        ));
        let conn_b = Arc::new(OrgRelayConn::new(
            socket_b,
            native[2].endpoint(),
            vni(&sb),
            "off-warn-exit".into(),
        ));
        let ca = Arc::new(Carrier::Relay {
            dst: conn_a.synth_peer(),
            conn: conn_a,
            dead: AtomicBool::new(false),
        });
        let cb = Arc::new(Carrier::Relay {
            dst: conn_b.synth_peer(),
            conn: conn_b,
            dead: AtomicBool::new(false),
        });
        let ip_a: Ipv4Addr = network
            .overlay_nodes
            .base
            .find_by_id(a_id)
            .await
            .unwrap()
            .overlay_ip
            .parse()
            .unwrap();
        let ip_b: Ipv4Addr = network
            .overlay_nodes
            .base
            .find_by_id(b_id)
            .await
            .unwrap()
            .overlay_ip
            .parse()
            .unwrap();
        let (mut wg_a, mut received_a) = WgDevice::new(key_a.secret.clone());
        let (mut wg_b, mut received_b) = WgDevice::new(key_b.secret.clone());
        wg_a.add_peer(key_b.public.to_bytes(), ip_b, ca, true);
        wg_b.add_peer(key_a.public.to_bytes(), ip_a, cb, false);
        let packet = |source: Ipv4Addr, target: Ipv4Addr, payload: &[u8]| {
            let mut bytes = vec![0u8; 20 + payload.len()];
            bytes[0] = 0x45;
            let len = bytes.len() as u16;
            bytes[2..4].copy_from_slice(&len.to_be_bytes());
            bytes[8] = 64;
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&target.octets());
            bytes[20..].copy_from_slice(payload);
            bytes
        };
        let forward = packet(ip_a, ip_b, b"off-warn cross-zone WG forward");
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                wg_a.send_ip_packet(&forward).await;
                if let Ok(Some(got)) =
                    tokio::time::timeout(Duration::from_millis(150), received_b.recv()).await
                    && got == forward
                {
                    break;
                }
            }
        })
        .await
        .expect("cross-zone forward WG");
        let backward = packet(ip_b, ip_a, b"off-warn cross-zone WG reverse");
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                wg_b.send_ip_packet(&backward).await;
                if let Ok(Some(got)) =
                    tokio::time::timeout(Duration::from_millis(150), received_a.recv()).await
                    && got == backward
                {
                    break;
                }
            }
        })
        .await
        .expect("cross-zone reverse WG");
        let (status, body) = put(&rig.app, &path(&agents[1]), &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[2], "endpoint":native[2].underlay_endpoint().to_string(), "cross_border":false}]})).await;
        assert_eq!(status, 200, "{body}");
        assert!(network.org_relay.active_session(&pair).is_none());
        let mut revokes = Vec::new();
        for (i, ws) in relays.iter_mut().enumerate() {
            let revoke = recv_t(ws, "rc:overlay.relay_revoke", wait)
                .await
                .expect("relay revoke");
            assert_eq!(revoke["vni"], serves[i]["vni"]);
            revokes.push(revoke);
        }
        let revoke0 = recv_t(&mut relays[0], "rc:overlay.relay_bridge_revoke", wait)
            .await
            .expect("first bridge revoke");
        let revoke1 = recv_t(&mut relays[1], "rc:overlay.relay_bridge_revoke", wait)
            .await
            .expect("crossing bridge revoke");
        assert!(
            recv_t(&mut a, "rc:overlay.relay_revoke", wait)
                .await
                .is_some()
        );
        assert!(
            recv_t(&mut b, "rc:overlay.relay_revoke", wait)
                .await
                .is_some()
        );
        // Apply only the crossing bridge's server-issued revoke first.
        native[1].serve(serde_json::from_value(revoke1).unwrap(), None);
        while received_a.try_recv().is_ok() {}
        while received_b.try_recv().is_ok() {}
        let blocked_a = packet(ip_a, ip_b, b"off-warn revoked crossing forward");
        let blocked_b = packet(ip_b, ip_a, b"off-warn revoked crossing reverse");
        for _ in 0..5 {
            wg_a.send_ip_packet(&blocked_a).await;
            wg_b.send_ip_packet(&blocked_b).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(120), received_b.recv()).await
            {
                assert_ne!(got, blocked_a, "forward passed revoked crossing");
            }
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(120), received_a.recv()).await
            {
                assert_ne!(got, blocked_b, "reverse passed revoked crossing");
            }
        }
        for (relay, frame) in native.iter().zip(revokes) {
            relay.serve(serde_json::from_value(frame).unwrap(), None);
        }
        native[0].serve(serde_json::from_value(revoke0).unwrap(), None);
    }
}

/// Off/Warn cross-zone paths require every crossing approval and audit, while
/// an invalid long path still falls back through the established one-hop gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_off_warn_cross_zone_mint_rechecks_every_edge_and_audit() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    async fn policy(rig: &Rig, source: &str, target: &str, endpoint: &str, crossing: bool) {
        let path = format!(
            "/api/tenant/{}/agent/{source}/peer-relay-policy",
            rig.seeded.tenant_id
        );
        let (status, value) = put(&rig.app, &path, &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":target,"endpoint":endpoint,"cross_border":crossing}]})).await;
        assert_eq!(status, 200, "{value}");
    }
    async fn request(ws: &mut Ws, peer: ObjectId, fallback: bool, serial: u64) {
        if fallback {
            ws.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request", "peer_node_id":peer.to_hex(), "request_id":serial}).to_string().into())).await.unwrap();
        } else {
            relay_request(ws, &peer.to_hex()).await;
        }
    }
    for (isolation, fallback, fault) in [
        ("off", false, "none"),
        ("off", true, "none"),
        ("warn", false, "none"),
        ("warn", true, "none"),
        ("off", false, "unknown"),
        ("warn", true, "implicit"),
    ] {
        let slug = format!(
            "iso-cross-mint-{isolation}-{}-{fault}",
            if fallback { "fallback" } else { "normal" }
        );
        let rig = Rig::up(&slug, isolation).await;
        let mut relays = Vec::new();
        let mut agents = Vec::new();
        let mut nodes = Vec::new();
        let endpoints = [
            "223.6.6.6:41641",
            "1.1.1.1:41641",
            "223.6.6.8:41641",
            "1.1.1.3:41641",
        ];
        let public = [
            "223.6.6.6:3478",
            "1.1.1.1:3478",
            "223.6.6.8:3478",
            "1.1.1.3:3478",
        ];
        let private = ["10.69.0.2:3478", "10.69.0.3:3478", "10.69.0.4:3478"];
        for i in 0..4 {
            let name = format!("{slug}-r{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let from = if i == 2 && fault == "unknown" {
                None
            } else if i % 2 == 0 {
                Some(CN_R)
            } else {
                Some(US_R)
            };
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], from).await;
            assert_observed(&rig.app, &agent, from).await;
            line_join(
                &mut ws,
                10 + i,
                endpoints[i as usize],
                json!({"relay_backbone_ready":true}),
            )
            .await;
            let node = rig.node(&name).await;
            if i == 2 && fault == "implicit" {
                rig.set_role(&agent, "server").await;
            } else {
                assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
                grant_relay(&rig.app, &rig.seeded, &node).await;
            }
            relays.push(ws);
            agents.push(agent);
            nodes.push(node);
        }
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig.device(&format!("{slug}-b"), Some(US_A)).await;
        let flag = json!({"supports_backbone_only_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flag.clone()).await;
        line_join(&mut b, 2, "8.8.8.8:41641", flag).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        set_mode(
            &rig.app,
            &rig.seeded,
            if fault == "implicit" { "auto" } else { "on" },
        )
        .await;
        // Configure from the exit backwards; a backbone target must already
        // be relay-approved, including the Auto/ACL-negative fixture.
        for i in (0..3).rev() {
            policy(&rig, &agents[i], &agents[i + 1], private[i], true).await;
        }
        let network = rig.app.state.network();
        let ids: Vec<_> = nodes
            .iter()
            .map(|n| ObjectId::parse_str(n).unwrap())
            .collect();
        let pair = meshharbor_mod_network::overlay::pair_key(a_id, b_id);
        let record = || {
            let ar: Vec<_> = (0..4)
                .map(|i| (ids[i], public[i].into(), i == 0, (i == 0).then_some(10)))
                .collect();
            let br: Vec<_> = (0..4)
                .map(|i| (ids[i], public[i].into(), i == 3, (i == 3).then_some(10)))
                .collect();
            assert!(support::record_member_probe_fixture(network, a_id, &ar));
            assert!(support::record_member_probe_fixture(network, b_id, &br));
            for i in 0..3 {
                assert!(support::record_backbone_probe_fixture(
                    network,
                    ids[i],
                    &[(ids[i + 1], private[i].into(), true, Some(5))]
                ));
            }
        };
        if fault != "none" {
            record();
            request(&mut a, b_id, fallback, 1).await;
            recv_t(&mut a, "rc:overlay.relay_session", Duration::from_secs(8))
                .await
                .expect("legacy fallback grant");
            let session = network
                .org_relay
                .active_session(&pair)
                .expect("legacy fallback session");
            assert!(
                session.hops.is_empty(),
                "{slug}: unknown or implicit relay entered multi-hop"
            );
            assert!(
                recv_t(
                    &mut relays[2],
                    "rc:overlay.relay_bridge_serve",
                    Duration::from_millis(300)
                )
                .await
                .is_none()
            );
            continue;
        }
        let mut serial = 1;
        // Fail each individual crossing independently. Revoke the resulting
        // single-relay fallback between attempts so no cached session masks a
        // later mint decision.
        for withheld in 0..3 {
            policy(
                &rig,
                &agents[withheld],
                &agents[withheld + 1],
                private[withheld],
                false,
            )
            .await;
            record();
            request(&mut a, b_id, fallback, serial).await;
            serial += 1;
            recv_t(&mut a, "rc:overlay.relay_session", Duration::from_secs(8))
                .await
                .expect("legacy fallback grant");
            let session = network
                .org_relay
                .active_session(&pair)
                .expect("legacy fallback session");
            assert!(
                session.hops.is_empty(),
                "{slug}: crossing {withheld} without approval minted multi-hop"
            );
            assert!(
                audit_rows(&rig.app, &rig.seeded)
                    .await
                    .iter()
                    .all(|row| !row["reason"]
                        .as_str()
                        .unwrap_or_default()
                        .starts_with("cross_border_edge:")),
                "unapproved path wrote crossing audit"
            );
            let relay_index = ids
                .iter()
                .position(|id| *id == session.relay.node_id)
                .unwrap();
            assert_eq!(
                approve(&rig.app, &rig.seeded, &agents[relay_index], false).await,
                200
            );
            assert!(network.org_relay.active_session(&pair).is_none());
            assert_eq!(
                approve(&rig.app, &rig.seeded, &agents[relay_index], true).await,
                200
            );
            for ws in &mut relays {
                while recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(100))
                    .await
                    .is_some()
                {}
            }
            while recv_t(
                &mut b,
                "rc:overlay.relay_session",
                Duration::from_millis(100),
            )
            .await
            .is_some()
            {}
            for i in 0..3 {
                policy(&rig, &agents[i], &agents[i + 1], private[i], true).await;
            }
        }
        record();
        assert_eq!(
            support::select_path(network, a_id, b_id, false)
                .await
                .unwrap()
                .unwrap()
                .0,
            agents
                .iter()
                .map(|id| ObjectId::parse_str(id).unwrap())
                .collect::<Vec<_>>()
        );
        support::fail_next_nhop_audit_fixture(pair.clone());
        request(&mut a, b_id, fallback, serial).await;
        serial += 1;
        recv_t(&mut a, "rc:overlay.relay_session", Duration::from_secs(8))
            .await
            .expect("fallback after audit failure");
        let session = network
            .org_relay
            .active_session(&pair)
            .expect("fallback after failed audit");
        assert!(
            session.hops.is_empty(),
            "failed crossing audit minted multi-hop"
        );
        let relay_index = ids
            .iter()
            .position(|id| *id == session.relay.node_id)
            .unwrap();
        assert_eq!(
            approve(&rig.app, &rig.seeded, &agents[relay_index], false).await,
            200
        );
        assert!(network.org_relay.active_session(&pair).is_none());
        assert_eq!(
            approve(&rig.app, &rig.seeded, &agents[relay_index], true).await,
            200
        );
        for ws in &mut relays {
            while recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(100))
                .await
                .is_some()
            {}
        }
        while recv_t(
            &mut b,
            "rc:overlay.relay_session",
            Duration::from_millis(100),
        )
        .await
        .is_some()
        {}
        for i in 0..3 {
            policy(&rig, &agents[i], &agents[i + 1], private[i], true).await;
        }
        record();
        request(&mut a, b_id, fallback, serial).await;
        let wait = Duration::from_secs(8);
        let mut serves = Vec::new();
        for ws in &mut relays {
            serves.push(
                recv_t(ws, "rc:overlay.relay_serve", wait)
                    .await
                    .unwrap_or_else(|| panic!("{slug}: actual relay serve missing")),
            );
        }
        let mut bridges = Vec::new();
        for ws in relays.iter_mut().take(3) {
            bridges.push(
                recv_t(ws, "rc:overlay.relay_bridge_serve", wait)
                    .await
                    .expect("actual bridge"),
            );
        }
        let sa = recv_t(&mut a, "rc:overlay.relay_session", wait)
            .await
            .expect("requester session");
        let sb = recv_t(&mut b, "rc:overlay.relay_session", wait)
            .await
            .expect("peer session");
        assert_eq!(sa["vni"], serves[0]["vni"]);
        assert_eq!(sb["vni"], serves[3]["vni"]);
        for i in 0..3 {
            assert_eq!(bridges[i]["bridge"]["local_vni"], serves[i]["vni"]);
            assert_eq!(bridges[i]["bridge"]["remote_vni"], serves[i + 1]["vni"]);
        }
        let session = network
            .org_relay
            .active_session(&pair)
            .expect("cross-zone multi-hop session");
        assert!(!session.implicit);
        assert_eq!(session.hops.len(), 3);
        assert!(
            session
                .hops
                .iter()
                .all(|h| h.requires_cross_border_approval)
        );
        assert!(support::reauthorize_nhop_fixture(network, a_id, b_id, &session).await);
        let audits = audit_rows(&rig.app, &rig.seeded).await;
        for i in 0..3 {
            let reason = format!("cross_border_edge:{}", agents[i + 1]);
            assert!(
                audits
                    .iter()
                    .any(|row| row["reason"] == reason && row["relay_node_id"] == nodes[i]),
                "missing distinct crossing audit: {slug} {i}"
            );
        }
        policy(&rig, &agents[1], &agents[2], private[1], false).await;
        assert!(
            network.org_relay.active_session(&pair).is_none(),
            "approval withdrawal must revoke all hops"
        );
        for (i, ws) in relays.iter_mut().enumerate() {
            let revoked = recv_t(ws, "rc:overlay.relay_revoke", wait)
                .await
                .expect("relay revoke");
            assert_eq!(revoked["vni"], serves[i]["vni"]);
        }
        for ws in relays.iter_mut().take(3) {
            recv_t(ws, "rc:overlay.relay_bridge_revoke", wait)
                .await
                .expect("bridge revoke");
        }
        assert!(
            recv_t(&mut a, "rc:overlay.relay_revoke", wait)
                .await
                .is_some()
        );
        assert!(
            recv_t(&mut b, "rc:overlay.relay_revoke", wait)
                .await
                .is_some()
        );
    }
}

/// An unusable shortcut must not hide an explicit, same-zone multi-hop path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_same_zone_filters_unusable_relays_before_mint_selection() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    for (scenario, isolation, fallback, best_single, probe_case) in [
        ("foreign", "off", false, false, "measured"),
        ("foreign", "off", true, false, "measured"),
        ("foreign", "warn", false, false, "measured"),
        ("foreign", "warn", true, false, "measured"),
        ("unknown", "off", false, false, "measured"),
        ("implicit", "enforce", false, true, "measured"),
        ("implicit", "enforce", true, true, "measured"),
        ("implicit", "off", true, true, "measured"),
        ("foreign", "off", false, true, "measured"),
        ("foreign", "warn", true, true, "measured"),
        ("unknown", "off", false, true, "measured"),
        ("unknown", "warn", true, true, "measured"),
        ("foreign", "off", false, true, "no-rtt"),
        ("unknown", "warn", true, true, "old-endpoint"),
    ] {
        let slug = format!(
            "iso-filter-{scenario}-{isolation}-{}-{best_single}-{probe_case}",
            if fallback { "fallback" } else { "normal" }
        );
        let rig = Rig::up(&slug, isolation).await;
        let mut relays = Vec::new();
        let mut agents = Vec::new();
        let mut nodes = Vec::new();
        for i in 0..4 {
            let name = format!("{slug}-relay-{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let location = if i != 3 || scenario == "implicit" {
                Some(CN_R)
            } else if scenario == "foreign" {
                Some(US_R)
            } else {
                None
            };
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], location).await;
            assert_observed(&rig.app, &agent, location).await;
            let endpoint = if i == 3 && scenario != "implicit" {
                "1.1.1.2:41641".to_string()
            } else {
                format!("223.6.6.{}:41641", 6 + i)
            };
            line_join(
                &mut ws,
                10 + i,
                &endpoint,
                json!({"relay_backbone_ready":true}),
            )
            .await;
            let node = rig.node(&name).await;
            if i == 3 && scenario == "implicit" {
                rig.set_role(&agent, "server").await;
            } else {
                assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
                grant_relay(&rig.app, &rig.seeded, &node).await;
            }
            relays.push(ws);
            agents.push(agent);
            nodes.push(node);
        }
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig.device(&format!("{slug}-b"), Some(CN_A)).await;
        let flag = json!({"supports_backbone_only_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flag.clone()).await;
        line_join(&mut b, 2, "223.5.5.6:41641", flag).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        set_mode(
            &rig.app,
            &rig.seeded,
            if scenario == "implicit" { "auto" } else { "on" },
        )
        .await;
        let path = |agent: &str| {
            format!(
                "/api/tenant/{}/agent/{agent}/peer-relay-policy",
                rig.seeded.tenant_id
            )
        };
        let mut source_edges = vec![
            json!({"relay_agent_id":agents[1],"endpoint":"10.68.0.2:3478","cross_border":false}),
        ];
        if scenario != "implicit" {
            source_edges.push(
                json!({"relay_agent_id":agents[3],"endpoint":"10.68.0.4:3478","cross_border":true}),
            );
            let (status, body) = put(&rig.app, &path(&agents[3]), &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[2],"endpoint":"10.68.0.5:3478","cross_border":true}]})).await;
            assert_eq!(status, 200, "{body}");
        }
        let (status, body) = put(
            &rig.app,
            &path(&agents[0]),
            &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":source_edges}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, body) = put(&rig.app, &path(&agents[1]), &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[2],"endpoint":"10.68.0.3:3478","cross_border":false}]})).await;
        assert_eq!(status, 200, "{body}");
        let network = rig.app.state.network();
        let ids: Vec<_> = nodes
            .iter()
            .map(|id| ObjectId::parse_str(id).unwrap())
            .collect();
        let bad_endpoint = if scenario == "implicit" {
            "223.6.6.9:3478"
        } else {
            "1.1.1.2:3478"
        };
        let probe_endpoint = if probe_case == "old-endpoint" {
            "8.8.4.4:3478"
        } else {
            bad_endpoint
        };
        let probe_rtt = if best_single && probe_case != "no-rtt" {
            Some(1)
        } else {
            None
        };
        assert!(support::record_member_probe_fixture(
            network,
            a_id,
            &[
                (ids[0], "223.6.6.6:3478".into(), true, Some(10)),
                (ids[1], "223.6.6.7:3478".into(), false, None),
                (ids[2], "223.6.6.8:3478".into(), false, None),
                (ids[3], probe_endpoint.into(), best_single, probe_rtt)
            ]
        ));
        assert!(support::record_member_probe_fixture(
            network,
            b_id,
            &[
                (ids[0], "223.6.6.6:3478".into(), false, None),
                (ids[1], "223.6.6.7:3478".into(), false, None),
                (ids[2], "223.6.6.8:3478".into(), true, Some(10)),
                (ids[3], probe_endpoint.into(), best_single, probe_rtt)
            ]
        ));
        let mut source_probes = vec![(ids[1], "10.68.0.2:3478".into(), true, Some(50))];
        if scenario != "implicit" {
            source_probes.push((ids[3], "10.68.0.4:3478".into(), true, Some(1)));
        }
        assert!(support::record_backbone_probe_fixture(
            network,
            ids[0],
            &source_probes
        ));
        assert!(support::record_backbone_probe_fixture(
            network,
            ids[1],
            &[(ids[2], "10.68.0.3:3478".into(), true, Some(50))]
        ));
        if scenario != "implicit" {
            assert!(support::record_backbone_probe_fixture(
                network,
                ids[3],
                &[(ids[2], "10.68.0.5:3478".into(), true, Some(1))]
            ));
        }
        let selected = support::select_path(network, a_id, b_id, false)
            .await
            .unwrap()
            .unwrap();
        let bad_agent = ObjectId::parse_str(&agents[3]).unwrap();
        assert!(
            selected.0.contains(&bad_agent),
            "unfiltered ranking must prefer the ineligible relay: {slug} {selected:?}"
        );
        if fallback {
            a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request", "peer_node_id":b_id.to_hex(), "request_id":1}).to_string().into())).await.unwrap();
        } else {
            relay_request(&mut a, &b_id.to_hex()).await;
        }
        let wait = Duration::from_secs(8);
        if best_single {
            recv_t(&mut a, "rc:overlay.relay_session", wait)
                .await
                .expect("single-relay fallback");
            let pair = meshharbor_mod_network::overlay::pair_key(a_id, b_id);
            let session = network
                .org_relay
                .active_session(&pair)
                .expect("single-relay session");
            assert!(
                session.hops.is_empty(),
                "{slug}: faster single relay was ignored"
            );
            assert_eq!(session.relay.node_id, ids[3], "{slug}: wrong single relay");
            continue;
        }
        let mut serves = Vec::new();
        for ws in relays.iter_mut().take(3) {
            serves.push(
                recv_t(ws, "rc:overlay.relay_serve", wait)
                    .await
                    .unwrap_or_else(|| panic!("{slug}: explicit relay serve missing")),
            );
        }
        recv_t(&mut relays[0], "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("first bridge");
        recv_t(&mut relays[1], "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("second bridge");
        let member_a = recv_t(&mut a, "rc:overlay.relay_session", wait)
            .await
            .expect("requester grant");
        let member_b = recv_t(&mut b, "rc:overlay.relay_session", wait)
            .await
            .expect("peer grant");
        assert_eq!(member_a["vni"], serves[0]["vni"]);
        assert_eq!(member_b["vni"], serves[2]["vni"]);
        assert!(
            recv_t(
                &mut relays[3],
                "rc:overlay.relay_serve",
                Duration::from_millis(250)
            )
            .await
            .is_none(),
            "ineligible relay received a multi-hop serve"
        );
        let pair = meshharbor_mod_network::overlay::pair_key(a_id, b_id);
        let session = network
            .org_relay
            .active_session(&pair)
            .expect("actual same-zone multi-hop");
        assert!(!session.implicit);
        assert_eq!(session.relay.node_id, ids[0]);
        assert_eq!(session.hops.len(), 2);
        assert_eq!(session.hops[0].relay.node_id, ids[1]);
        assert_eq!(session.hops[1].relay.node_id, ids[2]);
        assert!(
            session
                .hops
                .iter()
                .all(|h| !h.requires_cross_border_approval)
        );
        // Remove the only valid first edge. No route using the ineligible
        // shortcut may be minted; the established single-relay fallback is OK.
        let replacement = if scenario == "implicit" {
            json!([])
        } else {
            json!([
            {"relay_agent_id":agents[3],"endpoint":"10.68.0.4:3478","cross_border":true}])
        };
        let (status, body) = put(
            &rig.app,
            &path(&agents[0]),
            &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":replacement}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(
            network.org_relay.active_session(&pair).is_none(),
            "removed ordinary edge must revoke path"
        );
        relay_request(&mut a, &b_id.to_hex()).await;
        recv_t(&mut a, "rc:overlay.relay_session", wait)
            .await
            .expect("single-relay fallback");
        let fallback_session = network
            .org_relay
            .active_session(&pair)
            .expect("fallback session");
        assert!(
            fallback_session.hops.is_empty(),
            "ineligible multi-hop path was minted"
        );
    }
}

/// Same-zone real requests should mint, reauthorize and revoke all relay legs
/// in each isolation mode, including the org-only fallback entry point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_same_zone_actual_mint_and_fallback() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    for (isolation, fallback) in [
        ("enforce", false),
        ("enforce", true),
        ("warn", false),
        ("warn", true),
        ("off", false),
        ("off", true),
    ] {
        let slug = format!(
            "iso-same-{isolation}-{}",
            if fallback { "fallback" } else { "normal" }
        );
        let rig = Rig::up(&slug, isolation).await;
        let mut relays = Vec::new();
        let mut agents = Vec::new();
        let mut nodes = Vec::new();
        for i in 0..3 {
            let name = format!("{slug}-r{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(CN_R)).await;
            assert_observed(&rig.app, &agent, Some(CN_R)).await;
            line_join(
                &mut ws,
                10 + i,
                &format!("223.6.6.{}:41641", 6 + i),
                json!({"relay_backbone_ready":true}),
            )
            .await;
            assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
            let node = rig.node(&name).await;
            grant_relay(&rig.app, &rig.seeded, &node).await;
            relays.push(ws);
            agents.push(agent);
            nodes.push(node);
        }
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig.device(&format!("{slug}-b"), Some(CN_A)).await;
        let flag = json!({"supports_backbone_only_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flag.clone()).await;
        line_join(&mut b, 2, "223.5.5.6:41641", flag).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        set_mode(&rig.app, &rig.seeded, "on").await;
        let policy_path = |agent: &str| {
            format!(
                "/api/tenant/{}/agent/{agent}/peer-relay-policy",
                rig.seeded.tenant_id
            )
        };
        for i in 0..2 {
            let (status, body) = put(&rig.app, &policy_path(&agents[i]), &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],"endpoint":format!("10.44.0.{}:3478",i+2),"cross_border":false}]})).await;
            assert_eq!(status, 200, "{body}");
        }
        let network = rig.app.state.network();
        let ids: Vec<_> = nodes
            .iter()
            .map(|n| ObjectId::parse_str(n).unwrap())
            .collect();
        assert!(support::record_member_probe_fixture(
            network,
            a_id,
            &[
                (ids[0], "223.6.6.6:3478".into(), true, Some(10)),
                (ids[1], "223.6.6.7:3478".into(), false, None),
                (ids[2], "223.6.6.8:3478".into(), false, None),
            ]
        ));
        assert!(support::record_member_probe_fixture(
            network,
            b_id,
            &[
                (ids[0], "223.6.6.6:3478".into(), false, None),
                (ids[1], "223.6.6.7:3478".into(), false, None),
                (ids[2], "223.6.6.8:3478".into(), true, Some(10)),
            ]
        ));
        if fallback {
            a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request", "peer_node_id":b_id.to_hex(), "request_id":1}).to_string().into())).await.unwrap();
        } else {
            relay_request(&mut a, &b_id.to_hex()).await;
        }
        let wait = Duration::from_secs(8);
        let mut serves = Vec::new();
        for ws in &mut relays {
            serves.push(
                recv_t(ws, "rc:overlay.relay_serve", wait)
                    .await
                    .unwrap_or_else(|| panic!("{slug}: relay serve absent")),
            );
        }
        let bridge0 = recv_t(&mut relays[0], "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("first bridge");
        let bridge1 = recv_t(&mut relays[1], "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("second bridge");
        let sa = recv_t(&mut a, "rc:overlay.relay_session", wait)
            .await
            .expect("requester session");
        let sb = recv_t(&mut b, "rc:overlay.relay_session", wait)
            .await
            .expect("peer session");
        assert_eq!(sa["vni"], serves[0]["vni"]);
        assert_eq!(sb["vni"], serves[2]["vni"]);
        assert_eq!(bridge0["bridge"]["local_vni"], serves[0]["vni"]);
        assert_eq!(bridge0["bridge"]["remote_vni"], serves[1]["vni"]);
        assert_eq!(bridge1["bridge"]["local_vni"], serves[1]["vni"]);
        assert_eq!(bridge1["bridge"]["remote_vni"], serves[2]["vni"]);
        assert!(
            audit_rows(&rig.app, &rig.seeded)
                .await
                .iter()
                .any(|row| row["reason"] == "multi_hop_same_zone_attempt"),
            "{slug}: audit missing"
        );
        relay_request(&mut a, &b_id.to_hex()).await;
        let again = recv_t(&mut a, "rc:overlay.relay_session", wait)
            .await
            .expect("reauthorized repush");
        assert_eq!(again["vni"], sa["vni"]);
        let (status, body) = put(
            &rig.app,
            &policy_path(&agents[0]),
            &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[]}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        for (i, ws) in relays.iter_mut().enumerate() {
            let revoked = recv_t(ws, "rc:overlay.relay_revoke", wait)
                .await
                .expect("relay revoked");
            assert_eq!(revoked["vni"], serves[i]["vni"]);
        }
        for ws in relays.iter_mut().take(2) {
            recv_t(ws, "rc:overlay.relay_bridge_revoke", wait)
                .await
                .expect("bridge revoked");
        }
        assert!(
            recv_t(&mut a, "rc:overlay.relay_revoke", wait)
                .await
                .is_some()
        );
        assert!(
            recv_t(&mut b, "rc:overlay.relay_revoke", wait)
                .await
                .is_some()
        );
        if isolation == "enforce" {
            // Make the long path fast but keep r0 as the best single relay.
            // Its first successful mint spent one token; leave just one more.
            let (status, body) = put(&rig.app, &policy_path(&agents[0]), &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[1],"endpoint":"10.44.0.2:3478","cross_border":false}]})).await;
            assert_eq!(status, 200, "{body}");
            assert!(support::record_member_probe_fixture(
                network,
                a_id,
                &[
                    (ids[0], "223.6.6.6:3478".into(), true, Some(10)),
                    (ids[1], "223.6.6.7:3478".into(), false, None),
                    (ids[2], "223.6.6.8:3478".into(), false, None),
                ]
            ));
            assert!(support::record_member_probe_fixture(
                network,
                b_id,
                &[
                    (ids[0], "223.6.6.6:3478".into(), true, Some(1000)),
                    (ids[1], "223.6.6.7:3478".into(), false, None),
                    (ids[2], "223.6.6.8:3478".into(), true, Some(10)),
                ]
            ));
            assert!(support::record_backbone_probe_fixture(
                network,
                ids[0],
                &[(ids[1], "10.44.0.2:3478".into(), true, Some(5))]
            ));
            assert!(support::record_backbone_probe_fixture(
                network,
                ids[1],
                &[(ids[2], "10.44.0.3:3478".into(), true, Some(5))]
            ));
            let selected = support::select_path(network, a_id, b_id, false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                selected,
                (
                    agents
                        .iter()
                        .map(|id| ObjectId::parse_str(id).unwrap())
                        .collect(),
                    false
                )
            );
            let limit =
                meshharbor_remote_control::models::peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE;
            for _ in 0..limit - 2 {
                assert!(network.relay_rate_limiter.check(a_id, ids[0], limit));
            }
            let pair = meshharbor_mod_network::overlay::pair_key(a_id, b_id);
            support::fail_next_nhop_audit_fixture(pair.clone());
            if fallback {
                a.send(Message::Text(json!({"t":"rc:overlay.org_relay_fallback_request", "peer_node_id":b_id.to_hex(), "request_id":2}).to_string().into())).await.unwrap();
            } else {
                relay_request(&mut a, &b_id.to_hex()).await;
            }
            let old = recv_t(&mut relays[0], "rc:overlay.relay_serve", wait)
                .await
                .expect("single relay fallback after audit failure");
            let grant_a = recv_t(&mut a, "rc:overlay.relay_session", wait)
                .await
                .expect("single requester grant");
            let grant_b = recv_t(&mut b, "rc:overlay.relay_session", wait)
                .await
                .expect("single peer grant");
            assert_eq!(grant_a["vni"], old["vni"]);
            assert_eq!(grant_b["vni"], old["vni"]);
            assert!(
                network
                    .org_relay
                    .active_session(&pair)
                    .unwrap()
                    .hops
                    .is_empty(),
                "failed audit must not mint long path"
            );
            assert!(
                !network.relay_rate_limiter.check(a_id, ids[0], limit),
                "attempt spent its final token exactly once"
            );
        }
    }
}

/// A direct-line claim that loses to a concurrent N-hop winner must not
/// bypass that winner's complete reauthorization when repushing it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_line_claim_race_reauthorizes_multihop_winner() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    for invalid_key in [false, true] {
        let slug = if invalid_key {
            "iso-line-claim-race-denied"
        } else {
            "iso-line-claim-race-unavailable"
        };
        let mut l = LineRig::up(slug, true).await;
        let (middle_agent, token) =
            enroll(&l.rig.app, &l.rig.seeded, "iso-line-claim-race-mid").await;
        let mut middle = connect_from(&l.rig.app, &token, &["relay-server"], Some(CN_R)).await;
        assert_observed(&l.rig.app, &middle_agent, Some(CN_R)).await;
        line_join(
            &mut middle,
            5,
            "223.6.6.7:41641",
            json!({"relay_backbone_ready":true}),
        )
        .await;
        assert_eq!(
            approve(&l.rig.app, &l.rig.seeded, &middle_agent, true).await,
            200
        );
        let middle_node = l.rig.node("iso-line-claim-race-mid").await;
        grant_relay(&l.rig.app, &l.rig.seeded, &middle_node).await;
        let network = l.rig.app.state.network();
        let (a, b, gz, mid, hk) = (
            ObjectId::parse_str(&l.cn_node).unwrap(),
            ObjectId::parse_str(&l.us_node).unwrap(),
            ObjectId::parse_str(&l.gz_node).unwrap(),
            ObjectId::parse_str(&middle_node).unwrap(),
            ObjectId::parse_str(&l.hk_node).unwrap(),
        );
        let pair = meshharbor_mod_network::overlay::pair_key(a, b);
        let (reached, resume) = support::pause_line_preclaim_fixture(pair.clone());
        relay_request(&mut l.cn, &l.us_node).await;
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .expect("direct line reached claim")
            .unwrap();
        // Keep the original direct line, but introduce a faster authorized chain
        // while its first request is paused just before the shared claim.
        let admin = &l.rig.seeded.admin.access_token;
        let gz_policy = format!(
            "/api/tenant/{}/agent/{}/peer-relay-policy",
            l.rig.seeded.tenant_id, l.gz_agent
        );
        let mid_policy = format!(
            "/api/tenant/{}/agent/{}/peer-relay-policy",
            l.rig.seeded.tenant_id, middle_agent
        );
        let (status, body) = put(
            &l.rig.app,
            &gz_policy,
            admin,
            json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":middle_agent,"endpoint":"10.59.0.2:3478","cross_border":false},
        {"relay_agent_id":l.hk_agent,"endpoint":"10.59.0.3:3478","cross_border":true}]}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, body) = put(
            &l.rig.app,
            &mid_policy,
            admin,
            json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":l.hk_agent,"endpoint":"10.59.0.4:3478","cross_border":true}]}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(support::record_member_probe_fixture(
            network,
            a,
            &[
                (gz, "223.6.6.6:3478".into(), true, Some(10)),
                (mid, "223.6.6.7:3478".into(), false, None)
            ]
        ));
        assert!(support::record_member_probe_fixture(
            network,
            b,
            &[(hk, "1.1.1.1:3478".into(), true, Some(10))]
        ));
        assert!(support::record_backbone_probe_fixture(
            network,
            gz,
            &[
                (mid, "10.59.0.2:3478".into(), true, Some(5)),
                (hk, "10.59.0.3:3478".into(), true, Some(100))
            ]
        ));
        assert!(support::record_backbone_probe_fixture(
            network,
            mid,
            &[(hk, "10.59.0.4:3478".into(), true, Some(5))]
        ));
        assert_eq!(
            support::select_path(network, a, b, false)
                .await
                .unwrap()
                .unwrap()
                .0,
            vec![
                ObjectId::parse_str(&l.gz_agent).unwrap(),
                ObjectId::parse_str(&middle_agent).unwrap(),
                ObjectId::parse_str(&l.hk_agent).unwrap()
            ]
        );
        // A different connection can issue the competing request while CN's
        // original WebSocket handler is paused.
        relay_request(&mut l.us, &l.cn_node).await;
        let wait = Duration::from_secs(8);
        let gz_serve = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
            .await
            .expect("winning ingress serve");
        recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("winning first bridge");
        recv_t(&mut middle, "rc:overlay.relay_serve", wait)
            .await
            .expect("winning middle serve");
        recv_t(&mut middle, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("winning second bridge");
        recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
            .await
            .expect("winning exit serve");
        let first = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
            .await
            .expect("winning CN grant");
        recv_t(&mut l.us, "rc:overlay.relay_session", wait)
            .await
            .expect("winning US grant");
        assert_eq!(first["vni"], gz_serve["vni"]);
        let winner = network
            .org_relay
            .active_session(&pair)
            .expect("winning session");
        assert_eq!(winner.hops.len(), 2);
        // A transient read failure must not send a stale grant, nor tear down the
        // healthy winning path. The old shortcut incorrectly sent the grant.
        if invalid_key {
            assert!(support::invalidate_session_member_key_fixture(
                network, &pair
            ));
            resume.send(()).unwrap();
            recv_t(&mut l.cn, "rc:overlay.relay_revoke", wait)
                .await
                .expect("definitely invalid winner revoked");
            assert!(
                network.org_relay.active_session(&pair).is_none(),
                "invalid winner remains active"
            );
            assert!(
                recv_t(
                    &mut l.cn,
                    "rc:overlay.relay_session",
                    Duration::from_millis(500)
                )
                .await
                .is_none(),
                "invalid winner was re-pushed"
            );
        } else {
            support::fail_next_nhop_reauth_fixture(pair.clone());
            resume.send(()).unwrap();
            assert!(
                recv_t(
                    &mut l.cn,
                    "rc:overlay.relay_session",
                    Duration::from_millis(1500)
                )
                .await
                .is_none(),
                "losing line bypassed multi-hop reauthorization"
            );
            let retained = network
                .org_relay
                .active_session(&pair)
                .expect("transient reauthorization retains winner");
            assert_eq!(
                (retained.vni, retained.generation),
                (winner.vni, winner.generation)
            );
            relay_request(&mut l.cn, &l.us_node).await;
            let retry = recv_t(&mut l.cn, "rc:overlay.relay_session", wait)
                .await
                .expect("healthy reauthorization repushes winner");
            assert_eq!(retry["vni"], first["vni"]);
        }
    }
}

/// Cross-zone trial authorization must record the crossing attempt before it
/// reserves a trial slot or emits relay, bridge, and member grants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_cross_border_trial_audit_failure_and_timeout_fail_closed() {
    use meshharbor_mod_network::org_relay::candidate_test_support::{
        self as support, TrialCrossingAuditFault,
    };
    for (slug, fault) in [
        ("iso-trial-audit-error", TrialCrossingAuditFault::Error),
        ("iso-trial-audit-timeout", TrialCrossingAuditFault::Timeout),
    ] {
        let mut l = LineRig::up(slug, true).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,
            "supports_path_trial_v1":true,"supports_org_relay_multi_candidate":true,
            "supports_org_relay_discovery_cursor":true});
        line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
        let (a, b, gz, hk) = (
            ObjectId::parse_str(&l.cn_node).unwrap(),
            ObjectId::parse_str(&l.us_node).unwrap(),
            ObjectId::parse_str(&l.gz_node).unwrap(),
            ObjectId::parse_str(&l.hk_node).unwrap(),
        );
        let pair = meshharbor_mod_network::overlay::pair_key(a, b);
        let network = l.rig.app.state.network();
        support::fail_next_trial_crossing_audit(pair, fault);
        let request = |request_id| {
            Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
            "path":{"relay_node_ids":[l.gz_node,l.hk_node]}, "requester_at_exit":false, "request_id":request_id}).to_string().into())
        };
        l.cn.send(request(1)).await.unwrap();
        async fn assert_no_trial_frames(ws: &mut Ws, label: &str) {
            let until = tokio::time::Instant::now() + Duration::from_millis(3800);
            while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                if let Message::Text(text) = message {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    assert!(
                        ![
                            "rc:overlay.relay_serve",
                            "rc:overlay.relay_bridge_serve",
                            "rc:overlay.path_trial_start"
                        ]
                        .contains(&v["t"].as_str().unwrap_or_default()),
                        "{label}: failed audit emitted a trial grant"
                    );
                }
            }
        }
        tokio::join!(
            assert_no_trial_frames(&mut l.gz, slug),
            assert_no_trial_frames(&mut l.hk, slug),
            assert_no_trial_frames(&mut l.cn, slug),
            assert_no_trial_frames(&mut l.us, slug)
        );
        assert_eq!(
            support::trial_slots_on_relay(network, gz),
            0,
            "{slug}: ingress capacity leak"
        );
        assert_eq!(
            support::trial_slots_on_relay(network, hk),
            0,
            "{slug}: exit capacity leak"
        );
        assert!(
            l.audit_reasons("mint").await.is_empty(),
            "{slug}: simulated failed audit cannot be successful"
        );
        // Discovery is metadata only; it must remain available without any
        // audit write or trial/session allocation after the failed attempt.
        l.cn.send(Message::Text(
            json!({"t":"rc:overlay.org_relay_discover", "peer_node_id":l.us_node, "request_id":1})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let hint = recv_t(
            &mut l.cn,
            "rc:overlay.org_relay_candidates",
            Duration::from_secs(5),
        )
        .await
        .expect("discovery unaffected");
        assert!(
            hint["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(
                    |c| c["path"]["relay_node_ids"] == json!([l.gz_node, l.hk_node])
                        && c["requester_at_exit"] == false
                )
        );
        assert!(l.audit_reasons("mint").await.is_empty());
        l.cn.send(request(2)).await.unwrap();
        let wait = Duration::from_secs(8);
        let a = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
            .await
            .expect("success ingress serve");
        let b = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
            .await
            .expect("success exit serve");
        let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("success bridge");
        let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
            .await
            .expect("success requester trial");
        let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait)
            .await
            .expect("success peer trial");
        assert_eq!(cn["vni"], a["vni"]);
        assert_eq!(us["vni"], b["vni"]);
        assert_eq!(bridge["bridge"]["local_vni"], a["vni"]);
        assert_eq!(bridge["bridge"]["remote_vni"], b["vni"]);
        assert_eq!(support::trial_slots_on_relay(network, gz), 1);
        assert_eq!(support::trial_slots_on_relay(network, hk), 1);
        assert!(
            l.audit_reasons("mint")
                .await
                .iter()
                .any(
                    |(reason, node)| reason == &format!("cross_border_edge:{}", l.hk_agent)
                        && node == &l.gz_node
                )
        );
    }
}

/// Off/Warn isolation does not waive approval or audit for an actual crossing;
/// unknown relay placement cannot prove that the backbone edge is local.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_actual_edge_zone_gates_apply_in_off_and_warn() {
    use meshharbor_mod_network::org_relay::candidate_test_support::{
        self as support, TrialCrossingAuditFault,
    };
    for mode in ["off", "warn"] {
        for case in [
            "unapproved",
            "audit_error",
            "audit_timeout",
            "unknown",
            "same_zone",
        ] {
            let slug = format!("iso-trial-zone-{mode}-{case}");
            let mut l = LineRig::up_with_isolation(&slug, case != "unapproved", mode).await;
            let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
            line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
            line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
            let pair = meshharbor_mod_network::overlay::pair_key(
                ObjectId::parse_str(&l.cn_node).unwrap(),
                ObjectId::parse_str(&l.us_node).unwrap(),
            );
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
                let endpoint = if case == "unknown" {
                    "1.1.1.9:41641"
                } else {
                    "223.6.6.9:41641"
                };
                line_join(&mut ws, 10, endpoint, json!({})).await;
                assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
                exit_node = l.rig.node(&name).await;
                grant_relay(&l.rig.app, &l.rig.seeded, &exit_node).await;
                let policy = format!(
                    "/api/tenant/{}/agent/{}/peer-relay-policy",
                    l.rig.seeded.tenant_id, l.gz_agent
                );
                let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
                    json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agent,"endpoint":"10.67.0.2:3478","cross_border":case == "unknown"}]})).await;
                assert_eq!(status, 200, "{body}");
                alternate = Some(ws);
            }
            if case == "audit_error" {
                support::fail_next_trial_crossing_audit(
                    pair.clone(),
                    TrialCrossingAuditFault::Error,
                );
            }
            if case == "audit_timeout" {
                support::fail_next_trial_crossing_audit(
                    pair.clone(),
                    TrialCrossingAuditFault::Timeout,
                );
            }
            async fn request(ws: &mut Ws, peer: &str, ingress: &str, exit: &str, serial: u64) {
                ws.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":peer,
                    "path":{"relay_node_ids":[ingress,exit]}, "requester_at_exit":false, "request_id":serial}).to_string().into())).await.unwrap();
            }
            request(&mut l.cn, &l.us_node, &l.gz_node, &exit_node, 1).await;
            let wait = Duration::from_secs(8);
            if case == "same_zone" {
                let serve = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
                    .await
                    .expect("same-zone ingress serve");
                let other = recv_t(alternate.as_mut().unwrap(), "rc:overlay.relay_serve", wait)
                    .await
                    .expect("same-zone exit serve");
                let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
                    .await
                    .expect("same-zone bridge");
                let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
                    .await
                    .expect("same-zone requester start");
                let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait)
                    .await
                    .expect("same-zone peer start");
                assert_eq!(cn["vni"], serve["vni"]);
                assert_eq!(us["vni"], other["vni"]);
                assert_eq!(bridge["bridge"]["local_vni"], serve["vni"]);
                assert_eq!(bridge["bridge"]["remote_vni"], other["vni"]);
                assert!(
                    l.audit_reasons("mint").await.is_empty(),
                    "same-zone edge must not claim a crossing"
                );
                continue;
            }
            async fn assert_quiet(ws: &mut Ws, label: &str) {
                let until = tokio::time::Instant::now() + Duration::from_millis(3600);
                while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                    if let Message::Text(text) = message {
                        let v: Value = serde_json::from_str(&text).unwrap();
                        assert!(
                            ![
                                "rc:overlay.relay_serve",
                                "rc:overlay.relay_bridge_serve",
                                "rc:overlay.path_trial_start"
                            ]
                            .contains(&v["t"].as_str().unwrap_or_default()),
                            "{label}: forbidden/unaudited edge emitted a trial grant"
                        );
                    }
                }
            }
            if let Some(ws) = alternate.as_mut() {
                tokio::join!(
                    assert_quiet(&mut l.gz, &slug),
                    assert_quiet(&mut l.hk, &slug),
                    assert_quiet(ws, &slug),
                    assert_quiet(&mut l.cn, &slug),
                    assert_quiet(&mut l.us, &slug)
                );
            } else {
                tokio::join!(
                    assert_quiet(&mut l.gz, &slug),
                    assert_quiet(&mut l.hk, &slug),
                    assert_quiet(&mut l.cn, &slug),
                    assert_quiet(&mut l.us, &slug)
                );
            }
            assert_eq!(support::trial_slots_on_relay(network, gz), 0);
            assert_eq!(support::trial_slots_on_relay(network, hk), 0);
            assert!(l.audit_reasons("mint").await.is_empty());
            if case == "unapproved" || case == "unknown" {
                l.set_edge(true).await;
            }
            request(&mut l.cn, &l.us_node, &l.gz_node, &l.hk_node, 2).await;
            let a = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
                .await
                .expect("approved, audited ingress");
            let b = recv_t(&mut l.hk, "rc:overlay.relay_serve", wait)
                .await
                .expect("approved, audited exit");
            let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
                .await
                .expect("approved bridge");
            let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
                .await
                .expect("approved requester trial");
            let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait)
                .await
                .expect("approved peer trial");
            assert_eq!(cn["vni"], a["vni"]);
            assert_eq!(us["vni"], b["vni"]);
            assert_eq!(bridge["bridge"]["local_vni"], a["vni"]);
            assert_eq!(bridge["bridge"]["remote_vni"], b["vni"]);
            assert!(
                l.audit_reasons("mint")
                    .await
                    .iter()
                    .any(
                        |(reason, node)| reason == &format!("cross_border_edge:{}", l.hk_agent)
                            && node == &l.gz_node
                    )
            );
        }
    }
}

/// Losing a required crossing approval must retire the whole actual trial;
/// the same policy edit must preserve an ordinary same-zone trial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_edge_approval_downgrade_revokes_only_actual_crossing() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    for (slug, mode, same_zone) in [
        ("iso-trial-edge-enforce", "enforce", false),
        ("iso-trial-edge-off", "off", false),
        ("iso-trial-edge-local", "off", true),
    ] {
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
        let policy = format!(
            "/api/tenant/{}/agent/{}/peer-relay-policy",
            l.rig.seeded.tenant_id, l.gz_agent
        );
        let set_edge = |cross: bool| {
            json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":target_agent,"endpoint":endpoint,"cross_border":cross}]} )
        };
        let (status, body) = put(
            &l.rig.app,
            &policy,
            &l.rig.seeded.admin.access_token,
            set_edge(true),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        l.cn.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
            "path":{"relay_node_ids":[l.gz_node,target_node]}, "requester_at_exit":false,"request_id":1}).to_string().into())).await.unwrap();
        let wait = Duration::from_secs(8);
        let source = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
            .await
            .expect("trial ingress serve");
        let exit_ws = if same_zone {
            alternate.as_mut().unwrap()
        } else {
            &mut l.hk
        };
        let exit = recv_t(exit_ws, "rc:overlay.relay_serve", wait)
            .await
            .expect("trial exit serve");
        let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("trial bridge");
        let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
            .await
            .expect("requester start");
        let us = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait)
            .await
            .expect("peer start");
        assert_eq!(cn["trial_id"], us["trial_id"]);
        assert_eq!(cn["vni"], source["vni"]);
        assert_eq!(us["vni"], exit["vni"]);
        assert_eq!(bridge["bridge"]["local_vni"], source["vni"]);
        assert_eq!(bridge["bridge"]["remote_vni"], exit["vni"]);
        let network = l.rig.app.state.network();
        let source_node = ObjectId::parse_str(&l.gz_node).unwrap();
        let exit_id = ObjectId::parse_str(&target_node).unwrap();
        assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
        assert_eq!(support::trial_slots_on_relay(network, exit_id), 1);
        let (status, body) = put(
            &l.rig.app,
            &policy,
            &l.rig.seeded.admin.access_token,
            set_edge(false),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        if same_zone {
            async fn no_retirement(ws: &mut Ws, label: &str) {
                let until = tokio::time::Instant::now() + Duration::from_millis(650);
                while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                    if let Message::Text(text) = message {
                        let v: Value = serde_json::from_str(&text).unwrap();
                        assert!(
                            ![
                                "rc:overlay.path_trial_abort",
                                "rc:overlay.relay_revoke",
                                "rc:overlay.relay_bridge_revoke"
                            ]
                            .contains(&v["t"].as_str().unwrap_or_default()),
                            "{label}: same-zone trial wrongly revoked"
                        );
                    }
                }
            }
            tokio::join!(
                no_retirement(&mut l.gz, slug),
                no_retirement(alternate.as_mut().unwrap(), slug),
                no_retirement(&mut l.cn, slug),
                no_retirement(&mut l.us, slug)
            );
            assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
            assert_eq!(support::trial_slots_on_relay(network, exit_id), 1);
            // Removing the edge itself must still revoke the same-zone trial.
            let (status, body) = put(
                &l.rig.app,
                &policy,
                &l.rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[]}),
            )
            .await;
            assert_eq!(status, 200, "{body}");
        }
        let gz = recv_t(&mut l.gz, "rc:overlay.relay_revoke", wait)
            .await
            .expect("ingress revoke");
        let exit_ws = if same_zone {
            alternate.as_mut().unwrap()
        } else {
            &mut l.hk
        };
        let end = recv_t(exit_ws, "rc:overlay.relay_revoke", wait)
            .await
            .expect("exit revoke");
        let br = recv_t(&mut l.gz, "rc:overlay.relay_bridge_revoke", wait)
            .await
            .expect("bridge revoke");
        let a = recv_t(&mut l.cn, "rc:overlay.path_trial_abort", wait)
            .await
            .expect("requester abort");
        let b = recv_t(&mut l.us, "rc:overlay.path_trial_abort", wait)
            .await
            .expect("peer abort");
        assert_eq!(gz["vni"], source["vni"]);
        assert_eq!(end["vni"], exit["vni"]);
        assert_eq!(br["trial_id"], cn["trial_id"]);
        assert_eq!(br["generation"], source["generation"]);
        assert_eq!(a["trial_id"], cn["trial_id"]);
        assert_eq!(b["trial_id"], cn["trial_id"]);
        assert_eq!(support::trial_slots_on_relay(network, source_node), 0);
        assert_eq!(support::trial_slots_on_relay(network, exit_id), 0);
    }
}

/// Trial relay-zone changes must be rechecked for Off as well as Enforce;
/// unchanged or restored zones must not tear down a healthy trial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_live_relay_zone_recheck_revokes_changes_not_stale_reads() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    for case in [
        "cross_to_same",
        "same_to_cross",
        "unknown",
        "stable",
        "race_restore",
        "read_healthy",
        "read_retry",
    ] {
        let slug = format!("iso-trial-zone-live-{case}");
        let mut l = LineRig::up_with_isolation(&slug, true, "off").await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
        let originally_same = matches!(
            case,
            "same_to_cross" | "stable" | "race_restore" | "read_healthy" | "read_retry"
        );
        let initial_ip = if originally_same { CN_R } else { US_R };
        let initial_endpoint = if originally_same {
            "223.6.6.9:41641"
        } else {
            "1.1.1.9:41641"
        };
        let name = format!("{slug}-exit");
        let (exit_agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
        let mut old_exit =
            connect_from(&l.rig.app, &token, &["relay-server"], Some(initial_ip)).await;
        assert_observed(&l.rig.app, &exit_agent, Some(initial_ip)).await;
        line_join(&mut old_exit, 12, initial_endpoint, json!({})).await;
        assert_eq!(
            approve(&l.rig.app, &l.rig.seeded, &exit_agent, true).await,
            200
        );
        let exit_node = l.rig.node(&name).await;
        grant_relay(&l.rig.app, &l.rig.seeded, &exit_node).await;
        let policy = format!(
            "/api/tenant/{}/agent/{}/peer-relay-policy",
            l.rig.seeded.tenant_id, l.gz_agent
        );
        let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":"10.70.0.2:3478","cross_border":!originally_same}]})).await;
        assert_eq!(status, 200, "{body}");
        l.cn.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
            "path":{"relay_node_ids":[l.gz_node,exit_node]}, "requester_at_exit":false,"request_id":1}).to_string().into())).await.unwrap();
        let wait = Duration::from_secs(8);
        let source = recv_t(&mut l.gz, "rc:overlay.relay_serve", wait)
            .await
            .expect("trial ingress serve");
        let exit = recv_t(&mut old_exit, "rc:overlay.relay_serve", wait)
            .await
            .expect("trial exit serve");
        recv_t(&mut l.gz, "rc:overlay.relay_bridge_serve", wait)
            .await
            .expect("trial bridge");
        let cn = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
            .await
            .expect("requester start");
        recv_t(&mut l.us, "rc:overlay.path_trial_start", wait)
            .await
            .expect("peer start");
        let trial_id = ObjectId::parse_str(cn["trial_id"].as_str().unwrap()).unwrap();
        let network = l.rig.app.state.network();
        let source_node = ObjectId::parse_str(&l.gz_node).unwrap();
        let exit_node_id = ObjectId::parse_str(&exit_node).unwrap();
        assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
        let changed = match case {
            "cross_to_same" | "stable" | "read_healthy" => Some(CN_R),
            "same_to_cross" | "race_restore" | "read_retry" => Some(US_R),
            _ => None,
        };
        let endpoint = if changed == Some(CN_R) {
            "223.6.6.9:41641"
        } else {
            "1.1.1.9:41641"
        };
        if matches!(case, "read_healthy" | "read_retry") {
            support::fail_next_trial_zone_read(trial_id);
        }
        let mut fresh = connect_from(&l.rig.app, &token, &["relay-server"], changed).await;
        async fn join_capture_revoke(ws: &mut Ws, endpoint: &str) -> Option<Value> {
            ws.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([12;32]), "mtu":1280,
                "endpoints":[endpoint], "supports_org_relay":true, "supports_server_relay_strategy":true,
                "relay_port":3478, "org_primary":true, "supports_derp":true, "supports_forced_derp":true}).to_string().into())).await.unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            let mut revoke = None;
            loop {
                let frame = tokio::time::timeout_at(deadline, ws.next())
                    .await
                    .expect("netmap after rejoin")
                    .expect("WS open")
                    .expect("WS message");
                if let Message::Text(text) = frame {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    if v["t"] == "rc:overlay.relay_revoke" {
                        revoke = Some(v);
                    } else if v["t"] == "rc:overlay.netmap" {
                        return revoke;
                    }
                }
            }
        }
        let mut during_join = None;
        if case == "race_restore" {
            let (reached, resume) = support::pause_trial_zone_revoke(trial_id);
            fresh.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([12;32]), "mtu":1280,
                "endpoints":[endpoint], "supports_org_relay":true, "supports_server_relay_strategy":true,
                "relay_port":3478, "org_primary":true, "supports_derp":true, "supports_forced_derp":true}).to_string().into())).await.unwrap();
            tokio::time::timeout(wait, reached)
                .await
                .expect("recheck paused before revoke")
                .unwrap();
            // Restore the original zone on a replacement connection while the
            // previous mismatching snapshot is still paused.
            let mut restored =
                connect_from(&l.rig.app, &token, &["relay-server"], Some(CN_R)).await;
            line_join(&mut restored, 12, "223.6.6.9:41641", json!({})).await;
            resume.send(()).unwrap();
            fresh = restored;
        } else {
            during_join = join_capture_revoke(&mut fresh, endpoint).await;
        }
        if matches!(case, "unknown" | "stable" | "race_restore" | "read_healthy") {
            if case == "unknown" {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            assert!(
                during_join.is_none(),
                "stable rejoin already received a revoke"
            );
            async fn no_retirement(ws: &mut Ws, label: &str) {
                let until = tokio::time::Instant::now() + Duration::from_millis(800);
                while let Ok(Some(Ok(message))) = tokio::time::timeout_at(until, ws.next()).await {
                    if let Message::Text(text) = message {
                        let v: Value = serde_json::from_str(&text).unwrap();
                        assert!(
                            ![
                                "rc:overlay.path_trial_abort",
                                "rc:overlay.relay_revoke",
                                "rc:overlay.relay_bridge_revoke"
                            ]
                            .contains(&v["t"].as_str().unwrap_or_default()),
                            "{label}: healthy trial wrongly revoked"
                        );
                    }
                }
            }
            tokio::join!(
                no_retirement(&mut l.gz, &slug),
                no_retirement(&mut fresh, &slug),
                no_retirement(&mut l.cn, &slug),
                no_retirement(&mut l.us, &slug)
            );
            assert_eq!(support::trial_slots_on_relay(network, source_node), 1);
            assert_eq!(support::trial_slots_on_relay(network, exit_node_id), 1);
        } else {
            let source_revoke = recv_t(&mut l.gz, "rc:overlay.relay_revoke", wait)
                .await
                .expect("ingress revoke");
            let exit_revoke = match during_join {
                Some(v) => v,
                None => recv_t(&mut fresh, "rc:overlay.relay_revoke", wait)
                    .await
                    .expect("rejoined exit revoke"),
            };
            let bridge = recv_t(&mut l.gz, "rc:overlay.relay_bridge_revoke", wait)
                .await
                .expect("bridge revoke");
            let a = recv_t(&mut l.cn, "rc:overlay.path_trial_abort", wait)
                .await
                .expect("requester abort");
            let b = recv_t(&mut l.us, "rc:overlay.path_trial_abort", wait)
                .await
                .expect("peer abort");
            assert_eq!(source_revoke["vni"], source["vni"]);
            assert_eq!(exit_revoke["vni"], exit["vni"]);
            assert_eq!(bridge["trial_id"], cn["trial_id"]);
            assert_eq!(bridge["generation"], source["generation"]);
            assert_eq!(a["trial_id"], cn["trial_id"]);
            assert_eq!(b["trial_id"], cn["trial_id"]);
            assert_eq!(support::trial_slots_on_relay(network, source_node), 0);
            assert_eq!(support::trial_slots_on_relay(network, exit_node_id), 0);
        }
    }
}

/// Both relays can move while one asynchronous check is paused. A same-zone
/// relation alone is insufficient: each relay must retain its issued zone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_trial_live_relay_zone_recheck_retires_two_relays_moving_together() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    let mut l = LineRig::up_with_isolation("iso-trial-both-move", true, "off").await;
    let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
    line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
    line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
    let (source_agent, source_token) =
        enroll(&l.rig.app, &l.rig.seeded, "iso-trial-both-move-source").await;
    let (exit_agent, exit_token) =
        enroll(&l.rig.app, &l.rig.seeded, "iso-trial-both-move-exit").await;
    let mut source = connect_from(&l.rig.app, &source_token, &["relay-server"], Some(CN_R)).await;
    let mut exit = connect_from(&l.rig.app, &exit_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &source_agent, Some(CN_R)).await;
    assert_observed(&l.rig.app, &exit_agent, Some(CN_R)).await;
    line_join(
        &mut source,
        15,
        "223.6.6.10:41641",
        json!({"relay_backbone_ready":true}),
    )
    .await;
    line_join(&mut exit, 16, "223.6.6.11:41641", json!({})).await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &source_agent, true).await,
        200
    );
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &exit_agent, true).await,
        200
    );
    let source_node = l.rig.node("iso-trial-both-move-source").await;
    let exit_node = l.rig.node("iso-trial-both-move-exit").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &source_node).await;
    grant_relay(&l.rig.app, &l.rig.seeded, &exit_node).await;
    let policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, source_agent
    );
    let (status, body) = put(&l.rig.app, &policy, &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":exit_agent,"endpoint":"10.71.0.2:3478","cross_border":false}]})).await;
    assert_eq!(status, 200, "{body}");
    l.cn.send(Message::Text(json!({"t":"rc:overlay.path_trial_request", "peer_node_id":l.us_node,
        "path":{"relay_node_ids":[source_node,exit_node]}, "requester_at_exit":false,"request_id":1}).to_string().into())).await.unwrap();
    let wait = Duration::from_secs(8);
    let s = recv_t(&mut source, "rc:overlay.relay_serve", wait)
        .await
        .expect("source serve");
    let e = recv_t(&mut exit, "rc:overlay.relay_serve", wait)
        .await
        .expect("exit serve");
    recv_t(&mut source, "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("bridge serve");
    let a = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
        .await
        .expect("requester start");
    recv_t(&mut l.us, "rc:overlay.path_trial_start", wait)
        .await
        .expect("peer start");
    let trial_id = ObjectId::parse_str(a["trial_id"].as_str().unwrap()).unwrap();
    let (reached, resume) = support::pause_trial_zone_revoke(trial_id);
    let mut exit_new = connect_from(&l.rig.app, &exit_token, &["relay-server"], Some(US_R)).await;
    exit_new.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([16;32]),"mtu":1280,
        "endpoints":["1.1.1.11:41641"],"supports_org_relay":true,"supports_server_relay_strategy":true,"relay_port":3478,"org_primary":true}).to_string().into())).await.unwrap();
    tokio::time::timeout(wait, reached)
        .await
        .expect("exit-zone recheck paused")
        .unwrap();
    let mut source_new =
        connect_from(&l.rig.app, &source_token, &["relay-server"], Some(US_R)).await;
    source_new.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([15;32]),"mtu":1280,
        "endpoints":["1.1.1.10:41641"],"supports_org_relay":true,"supports_server_relay_strategy":true,
        "relay_backbone_ready":true,"relay_port":3478,"org_primary":true}).to_string().into())).await.unwrap();
    let mut source_revoke = None;
    let mut bridge_revoke = None;
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let frame = tokio::time::timeout_at(deadline, source_new.next())
            .await
            .expect("source rejoin netmap")
            .expect("source open")
            .expect("source frame");
        if let Message::Text(text) = frame {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["t"] == "rc:overlay.relay_revoke" {
                source_revoke = Some(value);
            } else if value["t"] == "rc:overlay.relay_bridge_revoke" {
                bridge_revoke = Some(value);
            } else if value["t"] == "rc:overlay.netmap" {
                break;
            }
        }
    }
    resume.send(()).unwrap();
    let source_revoke = match source_revoke {
        Some(v) => v,
        None => recv_t(&mut source_new, "rc:overlay.relay_revoke", wait)
            .await
            .expect("both-moved source revoke"),
    };
    let bridge_revoke = match bridge_revoke {
        Some(v) => v,
        None => recv_t(&mut source_new, "rc:overlay.relay_bridge_revoke", wait)
            .await
            .expect("both-moved bridge revoke"),
    };
    let exit_revoke = recv_t(&mut exit_new, "rc:overlay.relay_revoke", wait)
        .await
        .expect("both-moved exit revoke");
    let ca = recv_t(&mut l.cn, "rc:overlay.path_trial_abort", wait)
        .await
        .expect("requester abort");
    let cb = recv_t(&mut l.us, "rc:overlay.path_trial_abort", wait)
        .await
        .expect("peer abort");
    assert_eq!(source_revoke["vni"], s["vni"]);
    assert_eq!(exit_revoke["vni"], e["vni"]);
    assert_eq!(bridge_revoke["trial_id"], a["trial_id"]);
    assert_eq!(bridge_revoke["generation"], s["generation"]);
    assert_eq!(ca["trial_id"], a["trial_id"]);
    assert_eq!(cb["trial_id"], a["trial_id"]);
    let network = l.rig.app.state.network();
    assert_eq!(
        support::trial_slots_on_relay(network, ObjectId::parse_str(source_node).unwrap()),
        0
    );
    assert_eq!(
        support::trial_slots_on_relay(network, ObjectId::parse_str(exit_node).unwrap()),
        0
    );
}

/// The authenticated production discovery endpoint feeds the real Discovery
/// and Engine request path; an incorrect middle hop must not consume its Start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_multihop_discovery_actual_client_request_and_middle_fence() {
    use meshharbor_remote_control::signaling::{ClientMsg, NetmapPeer, ServerMsg};
    use meshharbord::relay_server::backbone_test_support::{PathTrialTestHarness, WgKeypair};
    use std::sync::Arc;
    let mut l = LineRig::up("iso-discovery-nhop-client", true).await;
    let caps = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,
        "supports_path_trial_v1":true,"supports_org_relay_multi_candidate":true,"supports_org_relay_discovery_cursor":true});
    line_join(&mut l.cn, 1, "223.5.5.5:41641", caps.clone()).await;
    line_join(&mut l.us, 2, "8.8.8.8:41641", caps).await;
    let mut middles = Vec::new();
    let mut agents = Vec::new();
    let mut nodes = Vec::new();
    for index in 0..2 {
        let name = format!("iso-discovery-nhop-middle-{index}");
        let (agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
        let mut ws = connect_from(&l.rig.app, &token, &["relay-server"], Some(CN_R)).await;
        assert_observed(&l.rig.app, &agent, Some(CN_R)).await;
        line_join(
            &mut ws,
            8 + index,
            &format!("223.6.6.{}:41641", 8 + index),
            json!({"relay_backbone_ready":true}),
        )
        .await;
        assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
        let node = l.rig.node(&name).await;
        grant_relay(&l.rig.app, &l.rig.seeded, &node).await;
        middles.push(ws);
        agents.push(agent);
        nodes.push(node);
    }
    let policy = |source: &str| {
        format!(
            "/api/tenant/{}/agent/{source}/peer-relay-policy",
            l.rig.seeded.tenant_id
        )
    };
    let (status, body) = put(
        &l.rig.app,
        &policy(&l.gz_agent),
        &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":l.hk_agent,"endpoint":"10.79.0.2:3478","cross_border":true},
            {"relay_agent_id":agents[0],"endpoint":"10.79.0.3:3478","cross_border":false},
            {"relay_agent_id":agents[1],"endpoint":"10.79.0.4:3478","cross_border":false}]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    for index in 0..2 {
        let mut edges = vec![
            json!({"relay_agent_id":l.hk_agent,"endpoint":"10.79.0.2:3478","cross_border":true}),
        ];
        if index == 0 {
            edges.push(json!({"relay_agent_id":agents[1],"endpoint":"10.79.0.4:3478","cross_border":false}));
        }
        let (status, body) = put(
            &l.rig.app,
            &policy(&agents[index]),
            &l.rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":edges}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }
    let id = ObjectId::parse_str(&l.us_node).unwrap();
    let row = l
        .rig
        .app
        .state
        .network()
        .overlay_nodes
        .base
        .find_by_id(id)
        .await
        .unwrap();
    let peer: NetmapPeer =
        serde_json::from_value(json!({"node_id":l.us_node,"overlay_ip":row.overlay_ip,
        "wg_public_key":row.wg_public_key,"reachable":true,"supports_org_relay":true}))
        .unwrap();
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let dst = socket.local_addr().unwrap();
    let (client, mut out) =
        PathTrialTestHarness::new(WgKeypair::generate(), peer, socket, dst, true).await;
    let mut client = client.with_backbone_enabled(true);
    let now = std::time::Instant::now();
    let wait = Duration::from_secs(8);
    let mut received_paths = Vec::new();
    for page in 0..2 {
        client
            .request_discovery_at(now + Duration::from_secs(page * 61))
            .await;
        let request = out.recv().await.expect("production Discovery request");
        assert!(matches!(request, ClientMsg::OverlayOrgRelayDiscover { .. }));
        l.cn.send(Message::Text(
            serde_json::to_string(&request).unwrap().into(),
        ))
        .await
        .unwrap();
        let response = recv_t(&mut l.cn, "rc:overlay.org_relay_candidates", wait)
            .await
            .expect("actual discovery reply");
        if page == 1 {
            received_paths = response["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c["path"]["relay_node_ids"].clone())
                .collect();
            assert!(
                received_paths.contains(&json!([l.gz_node, nodes[0], l.hk_node])),
                "first same-end alternate missing: {response}"
            );
            assert!(
                received_paths.contains(&json!([l.gz_node, nodes[1], l.hk_node])),
                "second same-end alternate missing: {response}"
            );
            assert!(
                received_paths.contains(&json!([l.gz_node, nodes[0], nodes[1], l.hk_node])),
                "four-relay candidate missing: {response}"
            );
        }
        client.receive_discovery(serde_json::from_value(response).unwrap());
    }
    client.tick().await;
    let request = tokio::time::timeout(wait, out.recv())
        .await
        .expect("actual Engine request deadline")
        .expect("actual Engine trial request");
    let ClientMsg::OverlayPathTrialRequest { ref path, .. } = request else {
        panic!("actual Engine did not request a trial")
    };
    assert!(path.relay_node_ids().len() >= 3);
    assert!(received_paths.contains(&serde_json::to_value(path).unwrap()["relay_node_ids"]));
    l.cn.send(Message::Text(
        serde_json::to_string(&request).unwrap().into(),
    ))
    .await
    .unwrap();
    let start = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
        .await
        .expect("real unified engine Start");
    let mut wrong = start.clone();
    wrong["path"]["relay_node_ids"][1] = json!(ObjectId::new().to_hex());
    client
        .control(serde_json::from_value::<ServerMsg>(wrong).unwrap())
        .await;
    assert_eq!(
        client.trial_count(),
        0,
        "wrong middle node consumed pending request"
    );
    assert!(
        client.diagnostic_counters().1,
        "correct pending request was discarded"
    );
    let abort = out.recv().await.expect("wrong full path rejected");
    assert!(matches!(abort, ClientMsg::OverlayPathTrialAbort { .. }));
    l.cn.send(Message::Text(serde_json::to_string(&abort).unwrap().into()))
        .await
        .unwrap();
    recv_t(&mut l.cn, "rc:overlay.path_trial_abort", wait)
        .await
        .expect("trial abort acknowledged");
    // Remove one actual edge and rescan from scratch. No stale path may survive.
    let (status, body) = put(
        &l.rig.app,
        &policy(&agents[0]),
        &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":[]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    l.cn.send(Message::Text(
        json!({"t":"rc:overlay.org_relay_discover","peer_node_id":l.us_node,"request_id":99,
        "scan":{"state":"progress","scan_next":true,"checkpoint":null,"after":null}})
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let refreshed = recv_t(&mut l.cn, "rc:overlay.org_relay_candidates", wait)
        .await
        .expect("fresh scan after edge removal");
    assert!(
        refreshed["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| !c["path"]["relay_node_ids"]
                .as_array()
                .unwrap()
                .contains(&json!(nodes[0]))),
        "withdrawn middle path leaked: {refreshed}"
    );
}

/// An explicit future trial path is independently reauthorized from live
/// members, relay gates and directed current policy; it sends no grants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_specified_trial_path_rechecks_all_nodes_and_edges() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    use meshharbor_mod_network::org_relay::{OrgRelaySession, SessionMember, SessionParty};
    use meshharbor_remote_control::models::{NodeRef, peer_relay_limits as limits};
    use std::time::Instant;

    let mut l = LineRig::up("iso-trial-path", true).await;
    let caps = json!({"supports_backbone_only_v1":true, "supports_path_trial_v1":true,
        "supports_path_backbone_v1":true});
    line_join(&mut l.cn, 1, "223.5.5.5:41641", caps.clone()).await;
    line_join(&mut l.us, 2, "8.8.8.8:41641", caps.clone()).await;
    let (mid_agent, mid_token) = enroll(&l.rig.app, &l.rig.seeded, "iso-trial-path-mid").await;
    let mut mid = connect_from(&l.rig.app, &mid_token, &["relay-server"], Some(CN_R)).await;
    assert_observed(&l.rig.app, &mid_agent, Some(CN_R)).await;
    line_join(
        &mut mid,
        5,
        "223.6.6.7:41641",
        json!({"relay_backbone_ready":true}),
    )
    .await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await,
        200
    );
    let mid_node = l.rig.node("iso-trial-path-mid").await;
    let mid_acl = grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let (transit_agent, transit_token) =
        enroll(&l.rig.app, &l.rig.seeded, "iso-trial-path-transit").await;
    let mut transit = connect_from(&l.rig.app, &transit_token, &["relay-server"], Some(US_R)).await;
    assert_observed(&l.rig.app, &transit_agent, Some(US_R)).await;
    line_join(
        &mut transit,
        6,
        "1.1.1.2:41641",
        json!({"relay_backbone_ready":true}),
    )
    .await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &transit_agent, true).await,
        200
    );
    let transit_node = l.rig.node("iso-trial-path-transit").await;
    grant_relay(&l.rig.app, &l.rig.seeded, &transit_node).await;
    let policy_path = |agent: &str| {
        format!(
            "/api/tenant/{}/agent/{agent}/peer-relay-policy",
            l.rig.seeded.tenant_id
        )
    };
    let set_edge = |target: &str, endpoint: &str, cross_border| {
        json!({"serve":true,"approved_backbone_edges":[
        {"relay_agent_id":target,"endpoint":endpoint,"cross_border":cross_border} ]})
    };
    for (agent, target, endpoint, cross) in [
        (&l.gz_agent, &mid_agent, "10.71.0.2:3478", false),
        (&mid_agent, &transit_agent, "10.71.0.3:3478", true),
        (&transit_agent, &l.hk_agent, "10.71.0.4:3478", false),
    ] {
        let (status, body) = put(
            &l.rig.app,
            &policy_path(agent),
            &l.rig.seeded.admin.access_token,
            set_edge(target, endpoint, cross),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }
    let network = l.rig.app.state.network();
    let a = ObjectId::parse_str(&l.cn_node).unwrap();
    let b = ObjectId::parse_str(&l.us_node).unwrap();
    let nodes: Vec<_> = [&l.gz_node, &mid_node, &transit_node, &l.hk_node]
        .into_iter()
        .map(|id| ObjectId::parse_str(id).unwrap())
        .collect();
    let snapshot = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
        .await
        .expect("approved four-relay path");
    assert!(snapshot.locally_current(network));
    assert_eq!(
        snapshot.edges(),
        vec![
            (nodes[0], nodes[1], "10.71.0.2:3478".into(), false),
            (nodes[1], nodes[2], "10.71.0.3:3478".into(), true),
            (nodes[2], nodes[3], "10.71.0.4:3478".into(), false),
        ]
    );
    assert!(
        support::reauthorize_trial_path_fixture(network, a, b, &snapshot)
            .await
            .is_ok()
    );
    assert!(
        support::plan_trial_path_fixture(network, b, a, nodes.clone(), true)
            .await
            .is_ok(),
        "requester at exit"
    );
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), true)
            .await
            .is_err(),
        "member zone orientation"
    );
    assert!(
        support::plan_trial_path_fixture(
            network,
            a,
            b,
            vec![nodes[0], nodes[2], nodes[1], nodes[3]],
            false
        )
        .await
        .is_err(),
        "missing directed edges"
    );
    assert!(
        support::plan_trial_path_fixture(
            network,
            a,
            b,
            vec![nodes[0], nodes[1], nodes[1], nodes[3]],
            false
        )
        .await
        .is_err(),
        "repeated node"
    );
    assert!(
        support::plan_trial_path_fixture(
            network,
            a,
            b,
            vec![nodes[0], ObjectId::new(), nodes[3]],
            false
        )
        .await
        .is_err(),
        "unregistered middle node"
    );

    // A real member rejoin with a different public key cannot inherit the
    // previous snapshot, even if the same relay identities remain approved.
    line_join(&mut l.us, 9, "8.8.8.8:41641", caps.clone()).await;
    assert!(
        support::reauthorize_trial_path_fixture(network, a, b, &snapshot)
            .await
            .is_err(),
        "changed member key"
    );
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_ok(),
        "current member identity can plan"
    );
    line_join(&mut l.us, 2, "8.8.8.8:41641", caps.clone()).await;
    let snapshot = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
        .await
        .expect("original member key restored");

    // A current approved edge change must invalidate its old endpoint, while a
    // fresh plan may use only the newly approved endpoint.
    let (status, body) = put(
        &l.rig.app,
        &policy_path(&mid_agent),
        &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.33:3478", true),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !snapshot.locally_current(network),
        "policy update changes epoch"
    );
    assert!(
        support::reauthorize_trial_path_fixture(network, a, b, &snapshot)
            .await
            .is_err(),
        "stale private edge endpoint"
    );
    let fresh = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
        .await
        .expect("new endpoint approved");
    assert_eq!(fresh.edges()[1].2, "10.71.0.33:3478");
    let (status, body) = put(
        &l.rig.app,
        &policy_path(&mid_agent),
        &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.3:3478", false),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_err(),
        "unapproved crossing"
    );
    let (status, body) = put(
        &l.rig.app,
        &policy_path(&mid_agent),
        &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.3:3478", true),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    line_join(
        &mut mid,
        5,
        "223.6.6.7:41641",
        json!({"relay_backbone_ready":false}),
    )
    .await;
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_err(),
        "middle bridge readiness withdrawn"
    );
    line_join(
        &mut mid,
        5,
        "223.6.6.7:41641",
        json!({"relay_backbone_ready":true}),
    )
    .await;
    line_join(
        &mut l.us,
        2,
        "8.8.8.8:41641",
        json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true}),
    )
    .await;
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_err(),
        "peer trial capability withdrawn"
    );
    line_join(&mut l.us, 2, "8.8.8.8:41641", caps).await;
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &mid_agent, false).await,
        200
    );
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_err(),
        "middle approval withdrawn"
    );
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &mid_agent, true).await,
        200
    );
    let (status, body) = put(
        &l.rig.app,
        &policy_path(&mid_agent),
        &l.rig.seeded.admin.access_token,
        set_edge(&transit_agent, "10.71.0.3:3478", true),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_ok(),
        "approval and edge restored"
    );

    // Remove the middle relay's both-member grant, then grant only A.
    let acl_path = format!(
        "/api/tenant/{}/overlay-acl/{mid_acl}",
        l.rig.seeded.tenant_id
    );
    let status = l
        .rig
        .app
        .client
        .delete(l.rig.app.url(&acl_path))
        .bearer_auth(&l.rig.seeded.admin.access_token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 200);
    let acl_collection = format!("/api/tenant/{}/overlay-acl", l.rig.seeded.tenant_id);
    let only_a = l
        .rig
        .app
        .auth_post(&acl_collection, &l.rig.seeded.admin.access_token)
        .json(&json!({
            "name":"trial middle requester only", "sources":[{"kind":"node_id","id":l.cn_node}],
            "via":[{"kind":"node_id","id":mid_node}], "destinations":[{"cidr":"100.64.0.0/10"}]
        }))
        .send()
        .await
        .unwrap();
    assert!(only_a.status().is_success());
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_err(),
        "peer lacks middle relay ACL"
    );
    grant_relay(&l.rig.app, &l.rig.seeded, &mid_node).await;
    let before_capacity = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
        .await
        .expect("restored path");
    let tenant = ObjectId::parse_str(&l.rig.seeded.tenant_id).unwrap();
    let mid_agent_id = ObjectId::parse_str(&mid_agent).unwrap();
    let party = |id| SessionParty {
        node_id: id,
        node_ref: NodeRef::Agent { agent_id: id },
    };
    let member = |id| SessionMember {
        party: party(id),
        wg_public_key: "fixture".into(),
        bind_secret: "fixture".into(),
    };
    let mut keys = Vec::new();
    for i in 0..limits::MAX_SESSIONS_PER_RELAY {
        let key = format!("specified-trial-capacity-{i}");
        let fixture = OrgRelaySession {
            tenant_id: tenant,
            pair_key: key.clone(),
            vni: i as u32 + 1000,
            generation: i as u64 + 1000,
            relay: SessionParty {
                node_id: nodes[1],
                node_ref: NodeRef::Agent {
                    agent_id: mid_agent_id,
                },
            },
            relay_agent_id: mid_agent_id,
            implicit: false,
            members: [member(ObjectId::new()), member(ObjectId::new())],
            endpoints: vec!["fixture".into()],
            expires_at: Instant::now() + Duration::from_secs(90),
            bind_by: Instant::now() + Duration::from_secs(30),
            hops: Vec::new(),
        };
        assert!(support::insert_session_fixture(network, fixture));
        keys.push(key);
    }
    assert!(
        !before_capacity.locally_current(network),
        "capacity is rechecked separately from epoch"
    );
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
            .await
            .is_err(),
        "middle relay full"
    );
    for key in keys {
        assert!(support::remove_session_fixture(network, &key));
    }
    let before_delete = support::plan_trial_path_fixture(network, a, b, nodes.clone(), false)
        .await
        .expect("capacity restored");
    assert!(network.overlay_nodes.base.soft_delete(b).await.unwrap());
    assert!(
        support::plan_trial_path_fixture(network, a, b, nodes, false)
            .await
            .is_err(),
        "tombstoned peer must not be accepted"
    );
    assert!(
        support::reauthorize_trial_path_fixture(network, a, b, &before_delete)
            .await
            .is_err(),
        "tombstoned peer cannot reauthorize"
    );
    let pair = meshharbor_mod_network::overlay::pair_key(a, b);
    assert!(
        network.org_relay.active_session(&pair).is_none(),
        "planning must not mint a session"
    );
    assert!(l.audit_reasons("mint").await.is_empty());
    for ws in [&mut l.gz, &mut mid, &mut transit, &mut l.hk] {
        assert!(
            recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(250))
                .await
                .is_none(),
            "planning must not send grants"
        );
    }
}

/// Warn/Off isolation graph construction may retain crossing metadata. The
/// trial planner itself must still require explicit approval of every crossing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_specified_trial_path_denies_unapproved_crossing_outside_enforce() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    for mode in ["off", "warn"] {
        let slug = format!("iso-trial-cross-{mode}");
        let rig = Rig::up(&slug, mode).await;
        let (left_agent, left_token) = enroll(&rig.app, &rig.seeded, &format!("{slug}-left")).await;
        let mut left = connect_from(&rig.app, &left_token, &["relay-server"], Some(CN_R)).await;
        assert_observed(&rig.app, &left_agent, Some(CN_R)).await;
        line_join(
            &mut left,
            3,
            "223.6.6.6:41641",
            json!({"relay_backbone_ready":true}),
        )
        .await;
        let (right_agent, right_token) =
            enroll(&rig.app, &rig.seeded, &format!("{slug}-right")).await;
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
        assert_eq!(
            approve(&rig.app, &rig.seeded, &right_agent, true).await,
            200
        );
        let left_node = rig.node(&format!("{slug}-left")).await;
        let right_node = rig.node(&format!("{slug}-right")).await;
        grant_relay(&rig.app, &rig.seeded, &left_node).await;
        grant_relay(&rig.app, &rig.seeded, &right_node).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        let nodes = vec![
            ObjectId::parse_str(left_node).unwrap(),
            ObjectId::parse_str(right_node).unwrap(),
        ];
        let policy = format!(
            "/api/tenant/{}/agent/{left_agent}/peer-relay-policy",
            rig.seeded.tenant_id
        );
        let net = rig.app.state.network();
        for cross in [false, true] {
            let (status, body) = put(&rig.app, &policy, &rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":right_agent,"endpoint":"10.72.0.2:3478","cross_border":cross}]})).await;
            assert_eq!(status, 200, "{body}");
            let planned =
                support::plan_trial_path_fixture(net, a_id, b_id, nodes.clone(), false).await;
            assert_eq!(planned.is_ok(), cross, "{mode}: crossing approval required");
        }
    }
}

/// Exercise the actual WS trial endpoint with an exact, directed multi-hop
/// path, both member orientations, bilateral commit/return, and revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_nhop_trial_actual_lifecycle_and_rollback() {
    use meshharbor_mod_network::org_relay::candidate_test_support::{
        self as support, TrialCrossingAuditFault,
    };
    async fn control(ws: &mut Ws, kind: &str, trial: &Value, return_id: Option<&str>) {
        let mut msg = json!({"t":kind,"trial_id":trial});
        if let Some(id) = return_id {
            msg["return_id"] = json!(id);
        }
        ws.send(Message::Text(msg.to_string().into()))
            .await
            .unwrap();
    }
    for (length, flipped, outcome) in [
        (3, false, "abort"),
        (4, true, "return"),
        (4, false, "edge"),
        (4, false, "audit"),
        (4, false, "approval"),
        (4, false, "zone"),
    ] {
        let slug = format!("iso-nhop-trial-{length}-{outcome}");
        let mut l = LineRig::up(&slug, true).await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut l.cn, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut l.us, 2, "8.8.8.8:41641", flags).await;
        let mut extras = Vec::new();
        let mut extra_agents = Vec::new();
        let mut extra_nodes = Vec::new();
        let mut extra_tokens = Vec::new();
        for i in 0..length - 2 {
            let name = format!("{slug}-middle-{i}");
            let (agent, token) = enroll(&l.rig.app, &l.rig.seeded, &name).await;
            let from = if length == 3 || i % 2 == 1 {
                CN_R
            } else {
                US_R
            };
            let mut ws = connect_from(&l.rig.app, &token, &["relay-server"], Some(from)).await;
            assert_observed(&l.rig.app, &agent, Some(from)).await;
            let endpoint = if from == CN_R {
                format!("223.6.6.{}:41641", 7 + i)
            } else {
                format!("1.1.1.{}:41641", 2 + i)
            };
            line_join(
                &mut ws,
                10 + i as u8,
                &endpoint,
                json!({"relay_backbone_ready":true}),
            )
            .await;
            assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
            let node = l.rig.node(&name).await;
            grant_relay(&l.rig.app, &l.rig.seeded, &node).await;
            extras.push(ws);
            extra_agents.push(agent);
            extra_nodes.push(node);
            extra_tokens.push(token);
        }
        let mut agents = vec![l.gz_agent.clone()];
        agents.extend(extra_agents);
        agents.push(l.hk_agent.clone());
        let mut nodes = vec![l.gz_node.clone()];
        nodes.extend(extra_nodes);
        nodes.push(l.hk_node.clone());
        let mut relays = vec![l.gz];
        relays.extend(extras);
        relays.push(l.hk);
        let endpoints: Vec<_> = (0..length - 1)
            .map(|i| format!("10.73.0.{}:3478", i + 2))
            .collect();
        let crosses: Vec<_> = (0..length - 1).map(|i| length == 4 || i == 1).collect();
        let policy = |source: &str| {
            format!(
                "/api/tenant/{}/agent/{source}/peer-relay-policy",
                l.rig.seeded.tenant_id
            )
        };
        for i in 0..length - 1 {
            let approved = crosses[i] && !(outcome == "approval" && i == 1);
            let (status, body) = put(&l.rig.app, &policy(&agents[i]), &l.rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],"endpoint":endpoints[i],"cross_border":approved}]})).await;
            assert_eq!(status, 200, "{body}");
        }
        let network = l.rig.app.state.network();
        let cn = ObjectId::parse_str(&l.cn_node).unwrap();
        let us = ObjectId::parse_str(&l.us_node).unwrap();
        let pair = meshharbor_mod_network::overlay::pair_key(cn, us);
        let ids: Vec<_> = nodes
            .iter()
            .map(|id| ObjectId::parse_str(id).unwrap())
            .collect();
        if outcome == "audit" {
            support::fail_next_trial_crossing_audit(pair, TrialCrossingAuditFault::Error);
        }
        let request = json!({"t":"rc:overlay.path_trial_request", "peer_node_id":if flipped {&l.cn_node} else {&l.us_node},
            "request_id":1, "path":{"relay_node_ids":nodes}, "requester_at_exit":flipped});
        if flipped {
            l.us.send(Message::Text(request.to_string().into()))
                .await
                .unwrap();
        } else {
            l.cn.send(Message::Text(request.to_string().into()))
                .await
                .unwrap();
        }
        let wait = Duration::from_secs(8);
        if outcome == "audit" || outcome == "approval" {
            for ws in &mut relays {
                assert!(
                    recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(500))
                        .await
                        .is_none(),
                    "{slug}: rejected path emitted serve"
                );
            }
            assert!(
                recv_t(
                    &mut l.cn,
                    "rc:overlay.path_trial_start",
                    Duration::from_millis(500)
                )
                .await
                .is_none()
            );
            assert!(
                recv_t(
                    &mut l.us,
                    "rc:overlay.path_trial_start",
                    Duration::from_millis(500)
                )
                .await
                .is_none()
            );
            for id in &ids {
                assert_eq!(
                    support::trial_slots_on_relay(network, *id),
                    0,
                    "{slug}: leaked trial slot"
                );
            }
            continue;
        }
        let mut serves = Vec::new();
        for ws in &mut relays {
            serves.push(
                recv_t(ws, "rc:overlay.relay_serve", wait)
                    .await
                    .expect("trial relay serve"),
            );
        }
        let mut bridges = Vec::new();
        for ws in relays.iter_mut().take(length - 1) {
            bridges.push(
                recv_t(ws, "rc:overlay.relay_bridge_serve", wait)
                    .await
                    .expect("trial bridge"),
            );
        }
        let a = recv_t(&mut l.cn, "rc:overlay.path_trial_start", wait)
            .await
            .expect("CN trial start");
        let b = recv_t(&mut l.us, "rc:overlay.path_trial_start", wait)
            .await
            .expect("US trial start");
        assert_eq!(a["trial_id"], b["trial_id"]);
        assert_eq!(a["path"]["relay_node_ids"], json!(nodes));
        assert_eq!(b["path"], a["path"]);
        assert_eq!(a["requester_at_exit"], json!(flipped));
        assert_eq!(b["requester_at_exit"], json!(flipped));
        assert_eq!(a["vni"], serves[0]["vni"]);
        assert_eq!(b["vni"], serves[length - 1]["vni"]);
        for i in 0..length - 1 {
            assert_eq!(bridges[i]["bridge"]["local_vni"], serves[i]["vni"]);
            assert_eq!(bridges[i]["bridge"]["remote_vni"], serves[i + 1]["vni"]);
        }
        for id in &ids {
            assert_eq!(support::trial_slots_on_relay(network, *id), 1);
        }
        let audits = audit_rows(&l.rig.app, &l.rig.seeded).await;
        for i in 0..length - 1 {
            if crosses[i] {
                let reason = format!("cross_border_edge:{}", agents[i + 1]);
                assert!(
                    audits
                        .iter()
                        .any(|row| row["reason"] == reason && row["relay_node_id"] == nodes[i]),
                    "{slug}: missing crossing audit {i}"
                );
            }
        }
        let mut rejoin_controls = Vec::new();
        if outcome == "abort" {
            control(
                &mut l.cn,
                "rc:overlay.path_trial_abort",
                &a["trial_id"],
                None,
            )
            .await;
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_abort", wait)
                    .await
                    .expect("member abort");
            }
        } else if outcome == "zone" {
            // The first middle relay was US; reconnect the same identity in
            // CN. The actual four-relay trial must be retired on every leg.
            let mut moved =
                connect_from(&l.rig.app, &extra_tokens[0], &["relay-server"], Some(CN_R)).await;
            moved.send(Message::Text(json!({"t":"rc:overlay.join", "wg_public_key":BASE64.encode([10;32]), "mtu":1280,
                "endpoints":["223.6.6.7:41641"], "supports_org_relay":true, "supports_server_relay_strategy":true,
                "relay_port":3478, "org_primary":true, "relay_backbone_ready":true}).to_string().into())).await.unwrap();
            let until = tokio::time::Instant::now() + wait;
            loop {
                let frame = tokio::time::timeout_at(until, moved.next())
                    .await
                    .expect("middle netmap")
                    .expect("middle open")
                    .expect("middle frame");
                if let Message::Text(text) = frame {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value["t"] == "rc:overlay.netmap" {
                        break;
                    }
                    if value["t"] == "rc:overlay.relay_revoke"
                        || value["t"] == "rc:overlay.relay_bridge_revoke"
                    {
                        rejoin_controls.push(value);
                    }
                }
            }
            relays[1] = moved;
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_abort", wait)
                    .await
                    .expect("zone change abort");
            }
        } else if outcome == "edge" {
            let i = 1;
            let (status, body) = put(&l.rig.app, &policy(&agents[i]), &l.rig.seeded.admin.access_token,
                json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],"endpoint":endpoints[i],"cross_border":false}]})).await;
            assert_eq!(status, 200, "{body}");
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_abort", wait)
                    .await
                    .expect("edge withdrawal abort");
            }
        } else {
            for ws in [&mut l.cn, &mut l.us] {
                control(ws, "rc:overlay.path_trial_ready", &a["trial_id"], None).await;
            }
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_commit", wait)
                    .await
                    .expect("bilateral commit");
            }
            for ws in [&mut l.cn, &mut l.us] {
                control(ws, "rc:overlay.path_trial_committed", &a["trial_id"], None).await;
            }
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_finalize", wait)
                    .await
                    .expect("bilateral finalize");
            }
            let return_id = ObjectId::new().to_hex();
            control(
                &mut l.cn,
                "rc:overlay.path_trial_return_request",
                &a["trial_id"],
                Some(&return_id),
            )
            .await;
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_return_prepare", wait)
                    .await
                    .expect("return prepare");
            }
            for ws in [&mut l.cn, &mut l.us] {
                control(
                    ws,
                    "rc:overlay.path_trial_return_ready",
                    &a["trial_id"],
                    Some(&return_id),
                )
                .await;
            }
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_return_commit", wait)
                    .await
                    .expect("return commit");
            }
            control(
                &mut l.cn,
                "rc:overlay.path_trial_returned",
                &a["trial_id"],
                Some(&return_id),
            )
            .await;
            for id in &ids {
                assert_eq!(
                    support::trial_slots_on_relay(network, *id),
                    1,
                    "one member cannot retire relays"
                );
            }
            control(
                &mut l.us,
                "rc:overlay.path_trial_returned",
                &a["trial_id"],
                Some(&return_id),
            )
            .await;
            for ws in [&mut l.cn, &mut l.us] {
                recv_t(ws, "rc:overlay.path_trial_return_finalize", wait)
                    .await
                    .expect("return finalize");
            }
        }
        for (i, ws) in relays.iter_mut().enumerate() {
            let captured = if i == 1 && outcome == "zone" {
                rejoin_controls
                    .iter()
                    .find(|v| v["t"] == "rc:overlay.relay_revoke")
                    .cloned()
            } else {
                None
            };
            let revoke = match captured {
                Some(v) => v,
                None => recv_t(ws, "rc:overlay.relay_revoke", wait)
                    .await
                    .expect("every relay retired"),
            };
            assert_eq!(revoke["vni"], serves[i]["vni"]);
        }
        for (i, ws) in relays.iter_mut().take(length - 1).enumerate() {
            let captured = if i == 1 && outcome == "zone" {
                rejoin_controls
                    .iter()
                    .find(|v| v["t"] == "rc:overlay.relay_bridge_revoke")
                    .cloned()
            } else {
                None
            };
            let revoke = match captured {
                Some(v) => v,
                None => recv_t(ws, "rc:overlay.relay_bridge_revoke", wait)
                    .await
                    .expect("every bridge retired"),
            };
            assert_eq!(revoke["trial_id"], bridges[i]["bridge"]["trial_id"]);
            assert_eq!(revoke["generation"], serves[i]["generation"]);
        }
        for id in &ids {
            assert_eq!(
                support::trial_slots_on_relay(network, *id),
                0,
                "every trial slot released"
            );
        }
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
        line_join(
            &mut ws,
            10 + i,
            &format!("1.1.1.{}:41641", i + 2),
            json!({}),
        )
        .await;
        assert_eq!(approve(&l.rig.app, &l.rig.seeded, &agent, true).await, 200);
        let id = l.rig.node(&name).await;
        grant_relay(&l.rig.app, &l.rig.seeded, &id).await;
        agents.push(agent);
        ids.push(id);
        relays.push(ws);
    }
    let policy = format!(
        "/api/tenant/{}/agent/{}/peer-relay-policy",
        l.rig.seeded.tenant_id, l.gz_agent
    );
    let make_edges = |agents: &[String]| {
        agents.iter().enumerate().map(|(i, id)|
        json!({"relay_agent_id":id,"endpoint":format!("10.61.0.{}:3478",i+2),"cross_border":true})).collect::<Vec<_>>()
    };
    let (status, body) = put(
        &l.rig.app,
        &policy,
        &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":make_edges(&agents)}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    async fn page(ws: &mut Ws, peer: &str, serial: u64, cursor: Option<Value>) -> Value {
        let mut req =
            json!({"t":"rc:overlay.org_relay_discover", "peer_node_id":peer, "request_id":serial});
        if let Some(c) = cursor {
            req["cursor"] = c;
        }
        ws.send(Message::Text(req.to_string().into()))
            .await
            .unwrap();
        let result = recv_t(
            ws,
            "rc:overlay.org_relay_candidates",
            Duration::from_secs(8),
        )
        .await
        .expect("discovery response");
        assert_eq!(result["request_id"], serial);
        result
    }
    let mut result = page(&mut l.cn, &l.us_node, 1, None).await;
    assert_eq!(
        result["candidates"].as_array().unwrap().len(),
        2,
        "preferred first page"
    );
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
    for c in result["candidates"].as_array().unwrap() {
        seen.insert(c["path"]["relay_node_ids"][1].as_str().unwrap().to_owned());
    }
    assert_eq!(
        seen,
        ids.iter().cloned().collect(),
        "all five approved exits should be discoverable"
    );
    let removed = ids[0].clone();
    let pair = meshharbor_mod_network::overlay::pair_key(
        ObjectId::parse_str(&l.cn_node).unwrap(),
        ObjectId::parse_str(&l.us_node).unwrap(),
    );
    let (reached, resume) =
        meshharbor_mod_network::org_relay::candidate_test_support::pause_cross_discovery_fixture(
            pair.clone(),
        );
    l.cn.send(Message::Text(
        json!({"t":"rc:overlay.org_relay_discover", "peer_node_id":l.us_node,
        "request_id":4, "cursor":result["next_cursor"]})
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), reached)
        .await
        .expect("discovery page reached final fence")
        .unwrap();
    let (status, body) = put(
        &l.rig.app,
        &policy,
        &l.rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":make_edges(&agents[1..])}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    resume.send(()).unwrap();
    let stale = recv_t(
        &mut l.cn,
        "rc:overlay.org_relay_candidates",
        Duration::from_secs(8),
    )
    .await
    .expect("fenced page response");
    assert_eq!(stale["request_id"], 4);
    assert!(
        stale["candidates"].as_array().unwrap().is_empty(),
        "concurrent withdrawal must discard the old snapshot"
    );
    let after = page(
        &mut l.cn,
        &l.us_node,
        5,
        Some(result["next_cursor"].clone()),
    )
    .await;
    assert!(
        after["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["path"]["relay_node_ids"][1] != removed),
        "withdrawn edge remains in page"
    );
    assert!(
        !after["candidates"].as_array().unwrap().is_empty(),
        "other approved lines remain available"
    );
    assert_eq!(
        approve(&l.rig.app, &l.rig.seeded, &agents[1], false).await,
        200
    );
    let after_approval = page(&mut l.cn, &l.us_node, 6, Some(after["next_cursor"].clone())).await;
    assert!(
        after_approval["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["path"]["relay_node_ids"][1] != ids[1]),
        "unapproved relay remains in page"
    );
    assert!(
        l.rig
            .app
            .state
            .network()
            .org_relay
            .active_session(&pair)
            .is_none(),
        "discovery must not mint"
    );
    assert!(
        l.audit_reasons("mint").await.is_empty(),
        "discovery must not audit a mint"
    );
    for ws in [&mut l.gz, &mut l.hk] {
        assert!(
            recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(250))
                .await
                .is_none()
        );
    }
    for ws in &mut relays {
        assert!(
            recv_t(ws, "rc:overlay.relay_serve", Duration::from_millis(250))
                .await
                .is_none()
        );
    }
}

/// Off/Warn must not add a member-to-endpoint zone gate at either path length.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_nhop_trial_off_warn_endpoint_zone_parity_two_and_three() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    for isolation in ["off", "warn"] {
        let slug = format!("iso-trial-endpoint-parity-{isolation}");
        let rig = Rig::up(&slug, isolation).await;
        let mut relays = Vec::new();
        let mut agents = Vec::new();
        let mut nodes = Vec::new();
        for i in 0..3 {
            let name = format!("{slug}-r{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(US_R)).await;
            assert_observed(&rig.app, &agent, Some(US_R)).await;
            line_join(
                &mut ws,
                10 + i,
                &format!("1.1.1.{}:41641", i + 1),
                json!({"relay_backbone_ready":true}),
            )
            .await;
            assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
            let node = rig.node(&name).await;
            grant_relay(&rig.app, &rig.seeded, &node).await;
            relays.push(ws);
            agents.push(agent);
            nodes.push(node);
        }
        let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
        let mut b = rig
            .device(
                &format!("{slug}-b"),
                if isolation == "warn" {
                    None
                } else {
                    Some(CN_A)
                },
            )
            .await;
        let flags = json!({"supports_backbone_only_v1":true,"supports_path_backbone_v1":true,"supports_path_trial_v1":true});
        line_join(&mut a, 1, "223.5.5.5:41641", flags.clone()).await;
        line_join(&mut b, 2, "223.5.5.6:41641", flags).await;
        let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        set_mode(&rig.app, &rig.seeded, "on").await;
        let path = |agent: &str| {
            format!(
                "/api/tenant/{}/agent/{agent}/peer-relay-policy",
                rig.seeded.tenant_id
            )
        };
        let (status, body) = put(
            &rig.app,
            &path(&agents[0]),
            &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[
                {"relay_agent_id":agents[1],"endpoint":"10.74.0.2:3478","cross_border":false},
                {"relay_agent_id":agents[2],"endpoint":"10.74.0.3:3478","cross_border":false}]}),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, body) = put(&rig.app, &path(&agents[1]), &rig.seeded.admin.access_token,
            json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[2],"endpoint":"10.74.0.4:3478","cross_border":false}]})).await;
        assert_eq!(status, 200, "{body}");
        let network = rig.app.state.network();
        let ids: Vec<_> = nodes
            .iter()
            .map(|n| ObjectId::parse_str(n).unwrap())
            .collect();
        for (serial, indexes, flipped) in [(1, vec![0, 2], false), (2, vec![0, 1, 2], true)] {
            let path_nodes: Vec<_> = indexes.iter().map(|&i| nodes[i].clone()).collect();
            let request = json!({"t":"rc:overlay.path_trial_request", "peer_node_id":if flipped {a_id.to_hex()} else {b_id.to_hex()},
                "request_id":serial,"path":{"relay_node_ids":path_nodes},"requester_at_exit":flipped});
            if flipped {
                b.send(Message::Text(request.to_string().into()))
                    .await
                    .unwrap();
            } else {
                a.send(Message::Text(request.to_string().into()))
                    .await
                    .unwrap();
            }
            let wait = Duration::from_secs(8);
            let mut serves = Vec::new();
            for &i in &indexes {
                serves.push(
                    recv_t(&mut relays[i], "rc:overlay.relay_serve", wait)
                        .await
                        .expect("off/warn endpoint-mismatch serve"),
                );
            }
            let mut bridges = Vec::new();
            for &i in indexes.iter().take(indexes.len() - 1) {
                bridges.push(
                    recv_t(&mut relays[i], "rc:overlay.relay_bridge_serve", wait)
                        .await
                        .expect("endpoint-mismatch bridge"),
                );
            }
            let sa = recv_t(&mut a, "rc:overlay.path_trial_start", wait)
                .await
                .expect("a start");
            let sb = recv_t(&mut b, "rc:overlay.path_trial_start", wait)
                .await
                .expect("b start");
            assert_eq!(sa["trial_id"], sb["trial_id"]);
            assert_eq!(sa["vni"], serves[0]["vni"]);
            assert_eq!(sb["vni"], serves.last().unwrap()["vni"]);
            for &i in &indexes {
                assert_eq!(support::trial_slots_on_relay(network, ids[i]), 1);
            }
            a.send(Message::Text(
                json!({"t":"rc:overlay.path_trial_abort","trial_id":sa["trial_id"]})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            for ws in [&mut a, &mut b] {
                recv_t(ws, "rc:overlay.path_trial_abort", wait)
                    .await
                    .expect("abort");
            }
            for (position, &i) in indexes.iter().enumerate() {
                let revoke = recv_t(&mut relays[i], "rc:overlay.relay_revoke", wait)
                    .await
                    .expect("relay revoke");
                assert_eq!(revoke["vni"], serves[position]["vni"]);
            }
            for (position, &i) in indexes.iter().take(indexes.len() - 1).enumerate() {
                let revoke = recv_t(&mut relays[i], "rc:overlay.relay_bridge_revoke", wait)
                    .await
                    .expect("bridge revoke");
                assert_eq!(revoke["trial_id"], bridges[position]["bridge"]["trial_id"]);
            }
            for &i in &indexes {
                assert_eq!(support::trial_slots_on_relay(network, ids[i]), 0);
            }
        }
    }
}
/// Fixture-owned four-relay trial: recheck every middle relay and member on
/// real WebSocket rejoin, and inspect all generated revocation frames. This
/// inserts trial state without issuing grants; real trial admission is separate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_nhop_trial_zone_fixture_rechecks_middle_and_members() {
    use meshharbor_core::business_authority::BusinessZone::Mainland;
    use meshharbor_mod_network::org_relay::{
        LineLeg, OrgRelaySession, SessionMember, SessionParty, candidate_test_support as support,
    };
    use meshharbor_remote_control::models::NodeRef;
    use std::time::Instant;
    for case in [
        "changed",
        "unknown",
        "stable",
        "race_restore",
        "member_changed",
        "unconstrained_member",
        "unconstrained_member_deleted",
        "unconstrained_member_wrong",
        "node_missing",
        "node_deleted",
        "agent_deleted",
        "read_error",
        "slow_vs_invalid",
        "same_trial_race",
    ] {
        let slug = format!("iso-nhop-zone-{case}");
        let rig = Rig::up(&slug, "off").await;
        let mut relays = Vec::new();
        let mut relay_tokens = Vec::new();
        let mut agent_ids = Vec::new();
        let mut node_ids = Vec::new();
        for i in 0..4 {
            let name = format!("{slug}-r{i}");
            let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
            let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(CN_R)).await;
            assert_observed(&rig.app, &agent, Some(CN_R)).await;
            line_join(
                &mut ws,
                10 + i,
                &format!("223.6.6.{}:41641", 10 + i),
                json!({"relay_backbone_ready":true}),
            )
            .await;
            assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
            let node = rig.node(&name).await;
            grant_relay(&rig.app, &rig.seeded, &node).await;
            agent_ids.push(ObjectId::parse_str(agent).unwrap());
            node_ids.push(ObjectId::parse_str(node).unwrap());
            relay_tokens.push(token);
            relays.push(ws);
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
            party: SessionParty {
                node_id,
                node_ref: NodeRef::Agent {
                    agent_id: ObjectId::parse_str(agent).unwrap(),
                },
            },
            wg_public_key: BASE64.encode([seed; 32]),
            bind_secret: "fixture-secret".into(),
        };
        let mut session = OrgRelaySession {
            tenant_id: ObjectId::parse_str(&rig.seeded.tenant_id).unwrap(),
            pair_key: meshharbor_mod_network::overlay::pair_key(a_id, b_id),
            vni: 101,
            generation: 201,
            relay: SessionParty {
                node_id: node_ids[0],
                node_ref: NodeRef::Agent {
                    agent_id: agent_ids[0],
                },
            },
            relay_agent_id: agent_ids[0],
            implicit: false,
            members: [member(a_id, &a_agent, 1), member(b_id, &b_agent, 2)],
            endpoints: vec!["223.6.6.10:3478".into()],
            expires_at: now + Duration::from_secs(600),
            bind_by: now + Duration::from_secs(60),
            hops: Vec::new(),
        };
        for i in 1..4 {
            session.hops.push(LineLeg {
                relay: SessionParty {
                    node_id: node_ids[i],
                    node_ref: NodeRef::Agent {
                        agent_id: agent_ids[i],
                    },
                },
                relay_agent_id: agent_ids[i],
                vni: 101 + i as u32,
                generation: 201 + i as u64,
                endpoints: vec![format!("223.6.6.{}:3478", 10 + i)],
                private_endpoint: format!("10.72.0.{}:3478", i + 1),
                requires_cross_border_approval: false,
                bridge_id: ObjectId::new(),
                bridge_secrets: ["fixture-a".into(), "fixture-b".into()],
            });
        }
        if case == "node_missing" {
            node_ids[1] = ObjectId::new();
            session.hops[0].relay.node_id = node_ids[1];
        }
        if case == "unconstrained_member_wrong" {
            session.members[0].party.node_id = node_ids[2];
        }
        if case == "same_trial_race" {
            session.relay.node_id = ObjectId::new();
        }
        let network = rig.app.state.network();
        let constrained = if case.starts_with("unconstrained_member") {
            None
        } else {
            Some([Mainland; 2])
        };
        let trial_id = support::insert_nhop_zone_trial_fixture(
            network,
            session.clone(),
            vec![Mainland; 4],
            constrained,
        );
        if case == "same_trial_race" {
            let (reached, resume) = support::pause_trial_zone_revoke(trial_id);
            let owned_state = (*network).clone();
            let first = tokio::spawn(async move {
                support::run_one_trial_slice_fixture(&owned_state, trial_id).await
            });
            tokio::time::timeout(Duration::from_secs(8), reached)
                .await
                .expect("first path reached the revoke hook")
                .unwrap();
            assert!(
                support::run_one_trial_slice_fixture(network, trial_id).await,
                "second path coalesces while first is in flight"
            );
            assert!(support::trial_exists_fixture(network, trial_id));
            resume.send(()).unwrap();
            assert!(!first.await.unwrap(), "first path retires the trial");
            assert!(!support::trial_exists_fixture(network, trial_id));
            for ws in [&mut a, &mut b] {
                recv_t(ws, "rc:overlay.path_trial_abort", Duration::from_secs(8))
                    .await
                    .expect("single abort");
                assert!(
                    recv_t(
                        ws,
                        "rc:overlay.path_trial_abort",
                        Duration::from_millis(300)
                    )
                    .await
                    .is_none(),
                    "duplicate abort"
                );
            }
            for ws in &mut relays {
                recv_t(ws, "rc:overlay.relay_revoke", Duration::from_secs(8))
                    .await
                    .expect("single relay revoke");
                assert!(
                    recv_t(ws, "rc:overlay.relay_revoke", Duration::from_millis(300))
                        .await
                        .is_none(),
                    "duplicate relay revoke"
                );
            }
            continue;
        }
        if case == "slow_vs_invalid" {
            let mut invalid = session.clone();
            invalid.relay.node_id = ObjectId::new(); // no DAO row for this relay
            let invalid_id = support::insert_nhop_zone_trial_fixture(
                network,
                invalid,
                vec![Mainland; 4],
                Some([Mainland; 2]),
            );
            support::stall_next_trial_zone_read(trial_id);
            let started = tokio::time::Instant::now();
            let (slow_pending, invalid_pending) =
                support::run_two_trial_slices_fixture(network, trial_id, invalid_id).await;
            assert!(slow_pending && !invalid_pending);
            assert!(support::trial_exists_fixture(network, trial_id));
            assert!(!support::trial_exists_fixture(network, invalid_id));
            assert!(
                started.elapsed() < Duration::from_secs(8),
                "the stalled read must not block the next slice indefinitely"
            );
            continue;
        }
        for id in &node_ids {
            assert_eq!(support::trial_slots_on_relay(network, *id), 1);
        }
        async fn join_collect(
            ws: &mut Ws,
            seed: u8,
            endpoint: &str,
            ready: bool,
            path: bool,
        ) -> Vec<Value> {
            ws.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([seed;32]),"mtu":1280,
                "endpoints":[endpoint],"supports_org_relay":true,"supports_server_relay_strategy":true,"relay_port":3478,"org_primary":true,
                "relay_backbone_ready":ready,"supports_backbone_only_v1":path,"supports_path_backbone_v1":path,"supports_path_trial_v1":path}).to_string().into())).await.unwrap();
            let until = tokio::time::Instant::now() + Duration::from_secs(8);
            let mut controls = Vec::new();
            loop {
                let msg = tokio::time::timeout_at(until, ws.next())
                    .await
                    .expect("join netmap")
                    .expect("connection")
                    .expect("frame");
                if let Message::Text(text) = msg {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value["t"] == "rc:overlay.netmap" {
                        return controls;
                    }
                    if [
                        "rc:overlay.relay_revoke",
                        "rc:overlay.relay_bridge_revoke",
                        "rc:overlay.path_trial_abort",
                    ]
                    .contains(&value["t"].as_str().unwrap_or_default())
                    {
                        controls.push(value);
                    }
                }
            }
        }
        let mut before_netmap = Vec::new();
        if matches!(
            case,
            "node_missing"
                | "node_deleted"
                | "agent_deleted"
                | "read_error"
                | "unconstrained_member_deleted"
                | "unconstrained_member_wrong"
        ) {
            if case == "node_deleted" {
                assert!(
                    network
                        .overlay_nodes
                        .base
                        .soft_delete(node_ids[1])
                        .await
                        .unwrap()
                );
            }
            if case == "agent_deleted" {
                assert!(
                    network
                        .fleet
                        .agents
                        .base
                        .soft_delete(agent_ids[1])
                        .await
                        .unwrap()
                );
            }
            if case == "read_error" {
                support::fail_next_trial_zone_read(trial_id);
            }
            if case == "unconstrained_member_deleted" {
                assert!(
                    network
                        .fleet
                        .agents
                        .base
                        .soft_delete(ObjectId::parse_str(&a_agent).unwrap())
                        .await
                        .unwrap()
                );
            }
            let changed = if case.starts_with("unconstrained_member") {
                ObjectId::parse_str(&a_agent).unwrap()
            } else {
                agent_ids[1]
            };
            support::recheck_zones_fixture(network, changed).await;
        } else if matches!(case, "member_changed" | "unconstrained_member") {
            let mut replacement = connect_from(&rig.app, &a_token, &[], Some(US_A)).await;
            before_netmap = join_collect(&mut replacement, 1, "8.8.8.9:41641", false, true).await;
            a = replacement;
        } else {
            let changed = match case {
                "stable" => Some(CN_R),
                "unknown" => None,
                _ => Some(US_R),
            };
            let endpoint = if changed == Some(CN_R) {
                "223.6.6.11:41641"
            } else {
                "1.1.1.11:41641"
            };
            let mut replacement =
                connect_from(&rig.app, &relay_tokens[1], &["relay-server"], changed).await;
            if case == "race_restore" {
                let (reached, resume) = support::pause_trial_zone_revoke(trial_id);
                replacement.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":BASE64.encode([11;32]),"mtu":1280,
                    "endpoints":[endpoint],"supports_org_relay":true,"supports_server_relay_strategy":true,"relay_port":3478,"org_primary":true,"relay_backbone_ready":true}).to_string().into())).await.unwrap();
                tokio::time::timeout(Duration::from_secs(8), reached)
                    .await
                    .expect("middle recheck paused")
                    .unwrap();
                let mut restored =
                    connect_from(&rig.app, &relay_tokens[1], &["relay-server"], Some(CN_R)).await;
                before_netmap =
                    join_collect(&mut restored, 11, "223.6.6.11:41641", true, false).await;
                resume.send(()).unwrap();
                relays[1] = restored;
            } else {
                before_netmap = join_collect(&mut replacement, 11, endpoint, true, false).await;
                relays[1] = replacement;
            }
        }
        if matches!(
            case,
            "stable" | "race_restore" | "unconstrained_member" | "unknown" | "read_error"
        ) {
            if matches!(case, "unknown" | "read_error") {
                tokio::time::sleep(Duration::from_secs(7)).await;
            }
            assert!(
                before_netmap.is_empty(),
                "{slug}: healthy path retired during join"
            );
            for id in &node_ids {
                assert_eq!(
                    support::trial_slots_on_relay(network, *id),
                    1,
                    "{slug}: healthy path lost"
                );
            }
            async fn quiet(ws: &mut Ws, label: &str) {
                let until = tokio::time::Instant::now() + Duration::from_millis(300);
                while let Ok(Some(Ok(Message::Text(text)))) =
                    tokio::time::timeout_at(until, ws.next()).await
                {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    assert!(
                        ![
                            "rc:overlay.relay_revoke",
                            "rc:overlay.relay_bridge_revoke",
                            "rc:overlay.path_trial_abort"
                        ]
                        .contains(&v["t"].as_str().unwrap_or_default()),
                        "{label}: healthy trial wrongly revoked"
                    );
                }
            }
            for ws in &mut relays {
                quiet(ws, &slug).await;
            }
            quiet(&mut a, &slug).await;
            quiet(&mut b, &slug).await;
        } else {
            let wait = Duration::from_secs(8);
            for (i, relay) in relays.iter_mut().enumerate().take(4) {
                let expected = if i == 0 {
                    session.vni
                } else {
                    session.hops[i - 1].vni
                };
                let revoke = if i == 1 && case != "member_changed" {
                    before_netmap
                        .iter()
                        .find(|v| v["t"] == "rc:overlay.relay_revoke")
                        .cloned()
                } else {
                    None
                };
                let revoke = match revoke {
                    Some(v) => v,
                    None => recv_t(relay, "rc:overlay.relay_revoke", wait)
                        .await
                        .expect("relay revoke"),
                };
                assert_eq!(revoke["vni"], expected, "{slug} relay {i}");
                if i < 3 {
                    let bridge = if i == 1 && case != "member_changed" {
                        before_netmap
                            .iter()
                            .find(|v| v["t"] == "rc:overlay.relay_bridge_revoke")
                            .cloned()
                    } else {
                        None
                    };
                    let bridge = match bridge {
                        Some(v) => v,
                        None => recv_t(relay, "rc:overlay.relay_bridge_revoke", wait)
                            .await
                            .expect("bridge revoke"),
                    };
                    assert_eq!(bridge["trial_id"], session.hops[i].bridge_id.to_hex());
                    let generation = if i == 0 {
                        session.generation
                    } else {
                        session.hops[i - 1].generation
                    };
                    assert_eq!(bridge["generation"], generation);
                }
            }
            let first = if case == "member_changed" {
                before_netmap
                    .iter()
                    .find(|v| v["t"] == "rc:overlay.path_trial_abort")
                    .cloned()
            } else {
                None
            };
            let first = match first {
                Some(v) => v,
                None => recv_t(&mut a, "rc:overlay.path_trial_abort", wait)
                    .await
                    .expect("first abort"),
            };
            let second = recv_t(&mut b, "rc:overlay.path_trial_abort", wait)
                .await
                .expect("second abort");
            assert_eq!(first["trial_id"], trial_id.to_hex());
            assert_eq!(second["trial_id"], trial_id.to_hex());
            for id in &node_ids {
                assert_eq!(
                    support::trial_slots_on_relay(network, *id),
                    0,
                    "{slug}: trial slot leaked"
                );
            }
        }
    }
}

/// Both real client owners discover and run a four-relay native WG trial,
/// then return through measured bridge failure and the server's bilateral 2PC.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(target_os = "linux")]
async fn staged_graph_multihop_discovery_bilateral_client_wg_commit_return() {
    run_multihop_discovery_bilateral_client_wg(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(target_os = "linux")]
async fn staged_graph_multihop_discovery_bilateral_client_wg_commit_return_at_exit() {
    run_multihop_discovery_bilateral_client_wg(true, false).await;
}

/// Kill the active middle listener, complete the measured return, then rejoin
/// the same endpoint and carry fresh WG payload through a newly minted path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(target_os = "linux")]
async fn staged_graph_multihop_middle_listener_restart_remints_and_carries_wg() {
    run_multihop_discovery_bilateral_client_wg(false, true).await;
}

#[cfg(target_os = "linux")]
async fn run_multihop_discovery_bilateral_client_wg(flipped: bool, restart_listener: bool) {
    tokio::time::timeout(Duration::from_secs(if restart_listener {240}else{180}), async {
        use crate::peer_relay_mint_tests::{CompositeDirectLink, composite_ip};
        use meshharbor_mod_network::org_relay::candidate_test_support as support;
        use meshharbor_remote_control::signaling::{ClientMsg, NetmapPeer, ServerMsg};
        use meshharbord::relay_server::backbone_test_support::{NativeRelay, PathTrialTestHarness, WgKeypair};
        use std::{net::Ipv4Addr, sync::Arc, time::Instant};
        #[allow(clippy::too_many_arguments)]
        async fn pump(label: &str, owner: &mut PathTrialTestHarness,
            output: &mut tokio::sync::mpsc::Receiver<ClientMsg>, ws: &mut Ws,
            trace: &mut Vec<(String,String)>, trial: ObjectId,
            fault: Option<Instant>, hold_returned: bool, held: &mut Option<ClientMsg>) {
            owner.tick().await;
            while let Ok(message)=output.try_recv() {
                let value=serde_json::to_value(&message).unwrap(); let tag=value["t"].as_str().unwrap();
                if tag=="rc:overlay.path_trial_return_request" {
                    let snapshot=owner.snapshot(trial); let fault=fault.expect("return before actual middle-bridge failure");
                    assert_eq!(snapshot.windows.len(),9);
                    assert!(snapshot.windows.iter().filter(|w|w.0.is_some()).count()>=6,"direct path lacks real successful echoes");
                    assert!(snapshot.windows.iter().filter(|w|w.1.is_none()&&w.2>=fault).count()>=6,"return lacks fresh post-fault relay loss");
                }
                if hold_returned && matches!(&message,ClientMsg::OverlayPathTrialReturned{..}) {
                    assert!(held.replace(message).is_none(),"unexpected duplicate held Return ACK"); continue;
                }
                trace.push((label.into(),tag.into()));
                ws.send(Message::Text(value.to_string().into())).await.unwrap();
            }
            for _ in 0..32 {
                let text=match tokio::time::timeout(Duration::from_millis(1),ws.next()).await {
                    Ok(Some(Ok(Message::Text(text))))=>text, Ok(Some(Ok(_)))=>continue, Err(_)=>break,
                    other=>panic!("client fixture control ended: {other:?}"),
                };
                let value:Value=serde_json::from_str(&text).unwrap();
                if let Some(tag)=value["t"].as_str().filter(|tag|tag.starts_with("rc:overlay.path_trial_")) {
                    trace.push((format!("server->{label}"),tag.into()));
                }
                if let Ok(message)=serde_json::from_value(value) { owner.control(message).await; }
            }
        }
        let slug=if restart_listener {"iso-nhop-client-listener-restart"}else if flipped {"iso-nhop-client-native-exit"}else{"iso-nhop-client-native"}; let rig=Rig::up(slug,"enforce").await;
        let mut native=Vec::new(); let mut relays=Vec::new(); let mut agents=Vec::new(); let mut nodes=Vec::new();
        for index in 0..4u8 {
            let relay=NativeRelay::start().await.unwrap(); let name=format!("{slug}-r{index}");
            let (agent,token)=enroll(&rig.app,&rig.seeded,&name).await;
            let from=if index==3 {US_R}else{CN_R};
            let mut ws=connect_from(&rig.app,&token,&["relay-server"],Some(from)).await;
            assert_observed(&rig.app,&agent,Some(from)).await;
            let public=if index==3 {"1.1.1.1".to_string()}else{format!("223.6.6.{}",6+index)};
            line_join(&mut ws,10+index,&format!("{public}:{}",relay.port()),
                json!({"relay_backbone_ready":true,"relay_port":relay.port()})).await;
            assert_eq!(approve(&rig.app,&rig.seeded,&agent,true).await,200);
            let node=rig.node(&name).await; grant_relay(&rig.app,&rig.seeded,&node).await;
            native.push(relay);relays.push(ws);agents.push(agent);nodes.push(node);
        }
        let key_a=WgKeypair::generate();let key_b=WgKeypair::generate();
        let mut a_ws=rig.device(&format!("{slug}-a"),Some(CN_A)).await;
        let mut b_ws=rig.device(&format!("{slug}-b"),Some(US_A)).await;
        for (ws,key,endpoint) in [(&mut a_ws,key_a.public_base64(),"223.5.5.5:41641"),(&mut b_ws,key_b.public_base64(),"8.8.8.8:41641")] {
            ws.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":key,"mtu":1280,"endpoints":[endpoint],
                "supports_org_relay":true,"supports_path_trial_v1":true,"supports_path_backbone_v1":true,
                "supports_backbone_only_v1":true,"supports_server_relay_strategy":true,"supports_overlay_echo":true,
                "supports_org_relay_multi_candidate":true,"supports_org_relay_discovery_cursor":true,"org_primary":true}).to_string().into())).await.unwrap();
            recv_t(ws,"rc:overlay.netmap",Duration::from_secs(5)).await.expect("real-key member join");
        }
        let a_id=ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
        let b_id=ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
        let network=rig.app.state.network();set_mode(&rig.app,&rig.seeded,"on").await;
        for index in 0..3 {
            let path=format!("/api/tenant/{}/agent/{}/peer-relay-policy",rig.seeded.tenant_id,agents[index]);
            let (status,body)=put(&rig.app,&path,&rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[
                {"relay_agent_id":agents[index+1],"endpoint":native[index+1].underlay_endpoint().to_string(),"cross_border":index==2}]})).await;
            assert_eq!(status,200,"{body}");
        }
        let a_ip:Ipv4Addr=network.overlay_nodes.base.find_by_id(a_id).await.unwrap().overlay_ip.parse().unwrap();
        let b_ip:Ipv4Addr=network.overlay_nodes.base.find_by_id(b_id).await.unwrap().overlay_ip.parse().unwrap();
        let socket_a=Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_b=Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let direct=CompositeDirectLink::new(socket_a.local_addr().unwrap(),socket_b.local_addr().unwrap()).await;
        let peer=|id:ObjectId,ip:Ipv4Addr,key:String|serde_json::from_value::<NetmapPeer>(json!({
            "node_id":id.to_hex(),"overlay_ip":ip.to_string(),"wg_public_key":key,"reachable":true,
            "supports_org_relay":true,"supports_overlay_echo":true})).unwrap();
        let (a, mut a_out) = PathTrialTestHarness::new(
            key_a.clone(),
            peer(b_id, b_ip, key_b.public_base64()),
            socket_a,
            direct.a,
            true,
        )
        .await;
        let mut a = a.with_backbone_enabled(true);
        let (b, mut b_out) = PathTrialTestHarness::new(
            key_b,
            peer(a_id, a_ip, key_a.public_base64()),
            socket_b,
            direct.b,
            false,
        )
        .await;
        let mut b = b.with_backbone_enabled(true);
        tokio::time::timeout(Duration::from_secs(8),async {while !a.handshake_done()||!b.handshake_done(){tokio::time::sleep(Duration::from_millis(10)).await;}}).await.expect("real incumbent bilateral WG handshake");
        let direct_packet=composite_ip(a_ip,b_ip,b"native client incumbent WG before discovery");
        assert!(a.send_packet(&direct_packet).await);assert_eq!(b.receive_packet().await.unwrap(),direct_packet);
        let direct_reverse=composite_ip(b_ip,a_ip,b"native client reverse incumbent WG before discovery");
        assert!(b.send_packet(&direct_reverse).await);assert_eq!(a.receive_packet().await.unwrap(),direct_reverse);
        let asked=Instant::now();
        for page in 0..2 {
            if page==1 {tokio::time::sleep_until(tokio::time::Instant::from_std(asked+Duration::from_secs(61))).await;}
            let (requester,output,ws)=if flipped {(&mut b,&mut b_out,&mut b_ws)}else{(&mut a,&mut a_out,&mut a_ws)};
            requester.request_discovery().await;
            let request=tokio::time::timeout(Duration::from_secs(2),output.recv()).await.unwrap().expect("actual paced discovery request");
            assert!(matches!(request,ClientMsg::OverlayOrgRelayDiscover{..}));
            ws.send(Message::Text(serde_json::to_string(&request).unwrap().into())).await.unwrap();
            let metadata=recv_t(ws,"rc:overlay.org_relay_candidates",Duration::from_secs(8)).await.expect("production discovery response");
            if page==1 {assert_eq!(metadata["candidates"][0]["path"]["relay_node_ids"],json!(nodes),"actual first graph candidate must carry all four relays");assert_eq!(metadata["candidates"][0]["requester_at_exit"],json!(flipped));}
            requester.receive_discovery(serde_json::from_value(metadata).unwrap());
        }
        let original_request;
        {
            let (requester,output,ws)=if flipped {(&mut b,&mut b_out,&mut b_ws)}else{(&mut a,&mut a_out,&mut a_ws)};
            requester.tick().await;
            let request=tokio::time::timeout(Duration::from_secs(2),output.recv()).await.unwrap().expect("actual four-relay client request");
            assert!(matches!(&request,ClientMsg::OverlayPathTrialRequest{path,requester_at_exit,..} if *requester_at_exit==flipped && path.relay_node_ids().iter().map(|id|id.to_hex()).collect::<Vec<_>>()==nodes));
            original_request=serde_json::to_value(&request).unwrap();
            ws.send(Message::Text(serde_json::to_string(&request).unwrap().into())).await.unwrap();
        }
        let wait=Duration::from_secs(8);let mut serves=Vec::new();let mut bridges=Vec::new();
        for ws in &mut relays {serves.push(recv_t(ws,"rc:overlay.relay_serve",wait).await.expect("all four actual relay grants"));}
        for ws in relays.iter_mut().take(3) {bridges.push(recv_t(ws,"rc:overlay.relay_bridge_serve",wait).await.expect("all three actual bridge grants"));}
        for (relay,serve) in native.iter().zip(&serves) {relay.serve(serde_json::from_value::<ServerMsg>(serve.clone()).unwrap(),None);}
        for index in 0..3 {native[index].serve(serde_json::from_value(bridges[index].clone()).unwrap(),Some(native[index].policy_to(&native[index+1])));}
        let mut start_a=recv_t(&mut a_ws,"rc:overlay.path_trial_start",wait).await.expect("requester Start");
        let mut start_b=recv_t(&mut b_ws,"rc:overlay.path_trial_start",wait).await.expect("responder Start");
        let trial=ObjectId::parse_str(start_a["trial_id"].as_str().unwrap()).unwrap();
        assert_eq!(start_a["path"]["relay_node_ids"],json!(nodes));assert_eq!(start_a["trial_id"],start_b["trial_id"]);
        assert_eq!(start_a["requester_at_exit"],json!(flipped));assert_eq!(start_b["requester_at_exit"],json!(flipped));
        assert_eq!(start_a["relay_node_id"],nodes[0]);assert_eq!(start_b["relay_node_id"],nodes[3]);
        start_a["relay_endpoints"]=json!([native[0].endpoint().to_string()]);
        start_b["relay_endpoints"]=json!([native[3].endpoint().to_string()]);
        a.control(serde_json::from_value(start_a).unwrap()).await;b.control(serde_json::from_value(start_b).unwrap()).await;
        let mut trace=Vec::new();let mut held=None;
        loop {
            pump("a",&mut a,&mut a_out,&mut a_ws,&mut trace,trial,None,false,&mut held).await;
            pump("b",&mut b,&mut b_out,&mut b_ws,&mut trace,trial,None,false,&mut held).await;
            if a.snapshot(trial).phase=="finalized"&&b.snapshot(trial).phase=="finalized" {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!a.snapshot(trial).direct_sender&&!b.snapshot(trial).direct_sender,"real measured four-relay path did not become both senders");
        for (owner,tag) in [("a","rc:overlay.path_trial_ready"),("b","rc:overlay.path_trial_ready"),("a","rc:overlay.path_trial_committed"),("b","rc:overlay.path_trial_committed"),("server->a","rc:overlay.path_trial_finalize"),("server->b","rc:overlay.path_trial_finalize")] {
            assert!(trace.iter().any(|(observed,kind)|observed==owner&&kind==tag),"missing actual client/server phase {owner} {tag}");
        }
        for sequence in 0..if restart_listener {64}else{1} {
            let forward=composite_ip(a_ip,b_ip,format!("bilateral real client four relay WG forward {sequence}").as_bytes());
            assert!(a.send_packet(&forward).await);assert_eq!(b.receive_packet().await.unwrap(),forward);
            let reverse=composite_ip(b_ip,a_ip,format!("bilateral real client four relay WG reverse {sequence}").as_bytes());
            assert!(b.send_packet(&reverse).await);assert_eq!(a.receive_packet().await.unwrap(),reverse);
        }
        let mut evidence=Vec::new();
        for index in 0..3 {let id=ObjectId::parse_str(bridges[index]["bridge"]["trial_id"].as_str().unwrap()).unwrap();
            let generation=bridges[index]["bridge"]["generation"].as_u64().unwrap();
            let (watch,sockets)=native[index].bridge_evidence(id,generation).expect("exact active manager");evidence.push((id,watch,sockets));}
        for node in &nodes {assert_eq!(support::trial_slots_on_relay(network,ObjectId::parse_str(node).unwrap()),1);}
        let bridge=ObjectId::parse_str(bridges[1]["bridge"]["trial_id"].as_str().unwrap()).unwrap();
        let generation=bridges[1]["bridge"]["generation"].as_u64().unwrap();
        let stopped_port=if restart_listener {
            Some(native[1].stop_listener().await.expect("actual active middle listener stopped"))
        } else {
            native[1].fail_owned_bridge(bridge,generation).await.expect("actual middle manager failure");
            None
        };
        direct.recover();let fault=Instant::now();
        for (index,relay) in native.iter().enumerate() {
            if restart_listener&&index==1 {continue;}
            relay.probe_healthy().await.expect("unrelated listener remains healthy during the fault");
        }
        loop {
            pump("a",&mut a,&mut a_out,&mut a_ws,&mut trace,trial,Some(fault),false,&mut held).await;
            pump("b",&mut b,&mut b_out,&mut b_ws,&mut trace,trial,Some(fault),true,&mut held).await;
            if held.is_some()&&a.snapshot(trial).phase=="returned"&&b.snapshot(trial).phase=="returned" {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Hold B's REAL generated ACK at the fixture transport. A socket ping
        // barrier proves A's earlier ACK was processed before inspecting slots.
        let nonce=b"actual-return-first-ack-barrier";
        a_ws.send(Message::Ping(nonce.to_vec().into())).await.unwrap();
        tokio::time::timeout(wait,async {loop {let frame=a_ws.next().await.expect("live barrier WS").unwrap();
            if matches!(frame,Message::Pong(ref data) if data.as_ref()==nonce) {break;}
            if let Message::Text(text)=frame {let value:Value=serde_json::from_str(&text).unwrap();assert_ne!(value["t"],"rc:overlay.path_trial_return_finalize","server finalized before both ACKs");}
        }}).await.expect("first real returned ACK barrier");
        for node in &nodes {assert_eq!(support::trial_slots_on_relay(network,ObjectId::parse_str(node).unwrap()),1,"one ACK released a relay slot");}
        for relay in &native {assert_eq!(relay.session_counts().sessions_revoked,0,"one ACK retired a native session");}
        let message=held.take().unwrap();trace.push(("b".into(),"rc:overlay.path_trial_returned".into()));
        b_ws.send(Message::Text(serde_json::to_string(&message).unwrap().into())).await.unwrap();
        loop {
            pump("a",&mut a,&mut a_out,&mut a_ws,&mut trace,trial,Some(fault),false,&mut held).await;
            pump("b",&mut b,&mut b_out,&mut b_ws,&mut trace,trial,Some(fault),false,&mut held).await;
            if a.snapshot(trial).phase=="retired"&&b.snapshot(trial).phase=="retired" {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(a.snapshot(trial).direct_sender&&b.snapshot(trial).direct_sender);
        assert!(!a.snapshot(trial).managed&&!b.snapshot(trial).managed);
        for (index,ws) in relays.iter_mut().enumerate() {
            let revoke=recv_t(ws,"rc:overlay.relay_revoke",wait).await.expect("all four relay revokes");
            assert_eq!(revoke["vni"],serves[index]["vni"]);native[index].serve(serde_json::from_value(revoke).unwrap(),None);
        }
        for (index,ws) in relays.iter_mut().take(3).enumerate() {
            let revoke=recv_t(ws,"rc:overlay.relay_bridge_revoke",wait).await.expect("all three bridge revokes");
            assert_eq!(revoke["trial_id"],bridges[index]["bridge"]["trial_id"]);assert_eq!(revoke["generation"],bridges[index]["bridge"]["generation"]);
            native[index].serve(serde_json::from_value(revoke).unwrap(),None);
        }
        for (index,(id,watch,sockets)) in evidence.into_iter().enumerate() {native[index].assert_bridge_retired(id,watch,sockets).await.expect("all manager registrations and sockets retired");}
        for (owner,tag) in [("a","rc:overlay.path_trial_return_ready"),("b","rc:overlay.path_trial_return_ready"),("a","rc:overlay.path_trial_returned"),("b","rc:overlay.path_trial_returned"),("server->a","rc:overlay.path_trial_return_finalize"),("server->b","rc:overlay.path_trial_return_finalize")] {
            assert!(trace.iter().any(|(observed,kind)|observed==owner&&kind==tag),"missing real return phase {owner} {tag}");
        }
        for node in &nodes {assert_eq!(support::trial_slots_on_relay(network,ObjectId::parse_str(node).unwrap()),0);}
        for (index,relay) in native.iter().enumerate() {
            if restart_listener&&index==1 {continue;}
            tokio::time::timeout(Duration::from_secs(2),async {
                while relay.session_counts().sessions_revoked!=1 {tokio::time::sleep(Duration::from_millis(10)).await;}
            }).await.expect("native session revoke applied");
            relay.probe_healthy().await.unwrap();
        }
        if let Some(port)=stopped_port {
            // A same-port fresh listener is an actual process-state loss: none
            // of its old grants or manager tasks survives. The API receives a
            // fresh join before it is asked to mint the next directed path.
            native[1].restart_listener(port).await.expect("same middle endpoint restored");
            native[1].probe_healthy().await.expect("restored middle listener responds");
            assert_eq!(native[1].session_counts().sessions_installed,0);
            line_join(&mut relays[1],11,&format!("223.6.6.7:{port}"),
                json!({"relay_backbone_ready":true,"relay_port":port})).await;
            assert_observed(&rig.app,&agents[1],Some(CN_R)).await;
            assert_eq!(rig.node(&format!("{slug}-r1")).await,nodes[1]);

            // Keep the SAME live member owners, WG state and authenticated WS.
            // Restore the incumbent's original measured latency so the new
            // relay trial has to prove itself again; no score is fabricated.
            // The control re-request is explicit, not an automatic retry claim.
            direct.degrade();
            assert!(a.handshake_done()&&b.handshake_done(),"member WG state survived relay restart");
            let mut request=original_request;
            request["request_id"]=json!(request["request_id"].as_u64().unwrap().checked_add(1).unwrap());
            a_ws.send(Message::Text(request.to_string().into())).await.unwrap();
            let mut recovered_serves=Vec::new();let mut recovered_bridges=Vec::new();
            for (index,ws) in relays.iter_mut().enumerate() {
                let serve=recv_t(ws,"rc:overlay.relay_serve",wait).await.expect("fresh grant after middle rejoin");
                assert!(serve["generation"].as_u64().unwrap()>serves[index]["generation"].as_u64().unwrap(),"recovery must mint fresh generations");
                native[index].serve(serde_json::from_value(serve.clone()).unwrap(),None);
                recovered_serves.push(serve);
            }
            for (index,ws) in relays.iter_mut().take(3).enumerate() {
                let bridge=recv_t(ws,"rc:overlay.relay_bridge_serve",wait).await.expect("fresh bridge after middle rejoin");
                native[index].serve(serde_json::from_value(bridge.clone()).unwrap(),Some(native[index].policy_to(&native[index+1])));
                recovered_bridges.push(bridge);
            }
            let mut start_a=recv_t(&mut a_ws,"rc:overlay.path_trial_start",wait).await.expect("recovery requester Start");
            let mut start_b=recv_t(&mut b_ws,"rc:overlay.path_trial_start",wait).await.expect("recovery responder Start");
            let recovered_trial=ObjectId::parse_str(start_a["trial_id"].as_str().unwrap()).unwrap();
            assert_ne!(recovered_trial,trial,"restore reused the retired trial");
            assert_eq!(start_a["path"]["relay_node_ids"],json!(nodes));
            assert_eq!(start_a["trial_id"],start_b["trial_id"]);
            start_a["relay_endpoints"]=json!([native[0].endpoint().to_string()]);
            start_b["relay_endpoints"]=json!([native[3].endpoint().to_string()]);
            a.control(serde_json::from_value(start_a).unwrap()).await;
            b.control(serde_json::from_value(start_b).unwrap()).await;
            loop {
                pump("recovered-a",&mut a,&mut a_out,&mut a_ws,&mut trace,recovered_trial,None,false,&mut held).await;
                pump("recovered-b",&mut b,&mut b_out,&mut b_ws,&mut trace,recovered_trial,None,false,&mut held).await;
                if a.snapshot(recovered_trial).phase=="finalized"&&b.snapshot(recovered_trial).phase=="finalized" {break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(!a.snapshot(recovered_trial).direct_sender&&!b.snapshot(recovered_trial).direct_sender,"recovered payload must use the freshly minted four-relay path");
            for sequence in 0..64 {
                let packet=composite_ip(a_ip,b_ip,format!("restored middle fresh WG forward {sequence}").as_bytes());
                assert!(a.send_packet(&packet).await);assert_eq!(b.receive_packet().await.unwrap(),packet);
                let packet=composite_ip(b_ip,a_ip,format!("restored middle fresh WG reverse {sequence}").as_bytes());
                assert!(b.send_packet(&packet).await);assert_eq!(a.receive_packet().await.unwrap(),packet);
            }
            let mut recovered_evidence=Vec::new();
            for index in 0..3 {
                let id=ObjectId::parse_str(recovered_bridges[index]["bridge"]["trial_id"].as_str().unwrap()).unwrap();
                let generation=recovered_bridges[index]["bridge"]["generation"].as_u64().unwrap();
                let (watch,sockets)=native[index].bridge_evidence(id,generation).unwrap();
                recovered_evidence.push((id,watch,sockets));
            }
            // An authenticated mode-off is also the recovery round's negative
            // control: all actual relay grants and native managers must retire.
            let revoked_before:Vec<_>=native.iter().map(|relay|relay.session_counts().sessions_revoked).collect();
            set_mode(&rig.app,&rig.seeded,"off").await;
            async fn next_cleanup(ws:&mut Ws)->Value {
                loop {
                    match ws.next().await {
                        Some(Ok(Message::Text(text)))=>{
                            let value:Value=serde_json::from_str(&text).unwrap();
                            match value["t"].as_str().expect("cleanup frame tag") {
                                "rc:overlay.path_trial_abort"|"rc:overlay.relay_revoke"|"rc:overlay.relay_bridge_revoke"=>return value,
                                // Mode changes also republish peer metadata;
                                // these are explicitly not cleanup commands.
                                "rc:overlay.netmap"|"rc:overlay.netmap_delta"=>{},
                                other=>panic!("unexpected mode-off control frame: {other}"),
                            }
                        }
                        Some(Ok(Message::Ping(data)))=>ws.send(Message::Pong(data)).await.unwrap(),
                        Some(Ok(Message::Pong(_)))=>{},
                        other=>panic!("mode-off control stream ended: {other:?}"),
                    }
                }
            }
            for (owner,ws) in [(&mut a,&mut a_ws),(&mut b,&mut b_ws)] {
                let (old,fresh)=tokio::time::timeout(wait,async {
                    let mut old=None;let mut fresh=None;
                    while old.is_none()||fresh.is_none() {
                        let abort=next_cleanup(ws).await;
                        assert_eq!(abort["t"],"rc:overlay.path_trial_abort");
                        if abort["trial_id"]==trial.to_hex() {assert!(old.replace(abort).is_none(),"duplicate old abort");}
                        else {assert_eq!(abort["trial_id"],recovered_trial.to_hex(),"unknown aborted trial");assert!(fresh.replace(abort).is_none(),"duplicate fresh abort");}
                    }
                    (old.unwrap(),fresh.unwrap())
                }).await.expect("mode-off must abort both exact retained and recovered trials");
                // Deliver the actual stale frame first even if the transport
                // presented the fresh one first, so this fence is exercised.
                owner.control(serde_json::from_value(old).unwrap()).await;
                assert_eq!(owner.snapshot(recovered_trial).phase,"finalized","old abort retired the recovered trial");
                owner.control(serde_json::from_value(fresh).unwrap()).await;
                assert_eq!(owner.snapshot(recovered_trial).phase,"retired");
            }
            for (index,ws) in relays.iter_mut().enumerate() {
                tokio::time::timeout(wait,async {
                    let mut seen=[false,false,index==3,index==3];
                    while !seen.iter().all(|v|*v) {
                        let revoke=next_cleanup(ws).await;
                        let slot=match revoke["t"].as_str().unwrap() {
                            "rc:overlay.relay_revoke"=>{
                                assert_eq!(revoke["scope"]["relay_node_id"],nodes[index]);
                                assert!(revoke["scope"]["peer_node_id"].is_null(),"relay revoke addressed a member");
                                let matches=|serve:&Value|revoke["vni"]==serve["vni"]&&revoke["scope"]["generation"]==serve["generation"];
                                if matches(&serves[index]) {0}else{assert!(matches(&recovered_serves[index]),"unknown relay generation revoke");1}
                            }
                            "rc:overlay.relay_bridge_revoke"=>{
                                assert!(index<3,"exit relay has no outgoing bridge");
                                let matches=|bridge:&Value|revoke["trial_id"]==bridge["bridge"]["trial_id"]&&revoke["generation"]==bridge["bridge"]["generation"];
                                if matches(&bridges[index]) {2}else{assert!(matches(&recovered_bridges[index]),"unknown bridge generation revoke");3}
                            }
                            other=>panic!("unexpected relay cleanup command: {other}"),
                        };
                        assert!(!std::mem::replace(&mut seen[slot],true),"duplicate exact relay cleanup command");
                        native[index].serve(serde_json::from_value(revoke).unwrap(),None);
                    }
                }).await.expect("mode-off must revoke every exact old/fresh relay session and bridge");
            }
            for (index,(id,watch,sockets)) in recovered_evidence.into_iter().enumerate() {
                native[index].assert_bridge_retired(id,watch,sockets).await.expect("recovered manager sockets released");
            }
            for (index,relay) in native.iter().enumerate() {
                tokio::time::timeout(Duration::from_secs(2),async {
                    while relay.session_counts().sessions_revoked!=revoked_before[index]+1 {tokio::time::sleep(Duration::from_millis(10)).await;}
                }).await.expect("fresh native revoke applied");
                assert_eq!(support::trial_slots_on_relay(network,ObjectId::parse_str(&nodes[index]).unwrap()),0);
            }
        }
        drop(native); // Post-return payload cannot be secretly carried by any relay.
        let packet=composite_ip(a_ip,b_ip,b"after real bilateral return client P2P forward");
        if restart_listener {
            assert!(!a.send_packet(&packet).await,"mode-off must leave no recovered sender");
            let packet=composite_ip(b_ip,a_ip,b"mode-off recovered reverse must be refused");
            assert!(!b.send_packet(&packet).await,"mode-off must leave no reverse recovered sender");
        } else {
            assert!(a.send_packet(&packet).await);assert_eq!(b.receive_packet().await.unwrap(),packet);
            let packet=composite_ip(b_ip,a_ip,b"after real bilateral return client P2P reverse");
            assert!(b.send_packet(&packet).await);assert_eq!(a.receive_packet().await.unwrap(),packet);
        }
    }).await.expect("bounded four-relay actual-client lifecycle exceeded its deadline");
}

/// The complete four-relay trial carries real encrypted packets before and
/// after bilateral commit; only the second return ACK retires all resources.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_nhop_trial_actual_wg_commit_and_bilateral_return() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    use meshharbor_remote_control::signaling::ServerMsg;
    use meshharbord::relay_server::backbone_test_support::{
        BindSecret, Carrier, NativeRelay, OrgRelayConn, WgDevice, WgKeypair, bind_member,
    };
    use std::{
        net::Ipv4Addr,
        sync::{Arc, atomic::AtomicBool},
    };
    let mut native = Vec::new();
    for _ in 0..4 {
        native.push(NativeRelay::start().await.unwrap());
    }
    let key_a = WgKeypair::generate();
    let key_b = WgKeypair::generate();
    let slug = "iso-nhop-trial-wg";
    let rig = Rig::up(slug, "enforce").await;
    let mut relays = Vec::new();
    let mut agents = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..4u8 {
        let name = format!("{slug}-r{i}");
        let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
        let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(CN_R)).await;
        assert_observed(&rig.app, &agent, Some(CN_R)).await;
        line_join(
            &mut ws,
            10 + i,
            &format!("223.6.6.{}:41641", 6 + i),
            json!({"relay_backbone_ready":true}),
        )
        .await;
        assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
        let node = rig.node(&name).await;
        grant_relay(&rig.app, &rig.seeded, &node).await;
        relays.push(ws);
        agents.push(agent);
        nodes.push(node);
    }
    let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
    let mut b = rig.device(&format!("{slug}-b"), Some(CN_A)).await;
    for (ws, key, endpoint) in [
        (&mut a, key_a.public_base64(), "223.5.5.5:41641"),
        (&mut b, key_b.public_base64(), "223.5.5.6:41641"),
    ] {
        ws.send(Message::Text(json!({"t":"rc:overlay.join","wg_public_key":key,"mtu":1280,"endpoints":[endpoint],
            "supports_org_relay":true,"supports_path_trial_v1":true,"supports_path_backbone_v1":true,
            "supports_backbone_only_v1":true,"supports_server_relay_strategy":true,"org_primary":true}).to_string().into())).await.unwrap();
        recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
            .await
            .expect("member joined");
    }
    let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
    let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
    let network = rig.app.state.network();
    set_mode(&rig.app, &rig.seeded, "on").await;
    for i in 0..3 {
        let path = format!(
            "/api/tenant/{}/agent/{}/peer-relay-policy",
            rig.seeded.tenant_id, agents[i]
        );
        let (status,body)=put(&rig.app,&path,&rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[
            {"relay_agent_id":agents[i+1],"endpoint":native[i+1].underlay_endpoint().to_string(),"cross_border":false}]})).await;
        assert_eq!(status, 200, "{body}");
    }
    a.send(Message::Text(
        json!({"t":"rc:overlay.path_trial_request","peer_node_id":b_id.to_hex(),"request_id":1,
        "path":{"relay_node_ids":nodes},"requester_at_exit":false})
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let wait = Duration::from_secs(8);
    let mut serves = Vec::new();
    let mut bridges = Vec::new();
    for ws in &mut relays {
        serves.push(
            recv_t(ws, "rc:overlay.relay_serve", wait)
                .await
                .expect("trial relay serve"),
        );
    }
    for ws in relays.iter_mut().take(3) {
        bridges.push(
            recv_t(ws, "rc:overlay.relay_bridge_serve", wait)
                .await
                .expect("trial bridge serve"),
        );
    }
    let sa = recv_t(&mut a, "rc:overlay.path_trial_start", wait)
        .await
        .expect("requester Start");
    let sb = recv_t(&mut b, "rc:overlay.path_trial_start", wait)
        .await
        .expect("peer Start");
    assert_eq!(sa["trial_id"], sb["trial_id"]);
    assert_eq!(sa["path"]["relay_node_ids"], json!(nodes));
    assert_eq!(sa["vni"], serves[0]["vni"]);
    assert_eq!(sb["vni"], serves[3]["vni"]);
    for i in 0..3 {
        assert_eq!(bridges[i]["bridge"]["local_vni"], serves[i]["vni"]);
        assert_eq!(bridges[i]["bridge"]["remote_vni"], serves[i + 1]["vni"]);
    }
    for (r, s) in native.iter().zip(&serves) {
        r.serve(
            serde_json::from_value::<ServerMsg>(s.clone()).unwrap(),
            None,
        );
    }
    for i in 0..3 {
        native[i].serve(
            serde_json::from_value(bridges[i].clone()).unwrap(),
            Some(native[i].policy_to(&native[i + 1])),
        );
    }
    let socket_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let source_a = socket_a.local_addr().unwrap();
    let source_b = socket_b.local_addr().unwrap();
    let secret = |f: &Value| {
        BindSecret::from_bytes(
            BASE64
                .decode(f["bind_secret"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    let vni = |f: &Value| f["vni"].as_u64().unwrap() as u32;
    let generation = |f: &Value| f["generation"].as_u64().unwrap();
    bind_member(
        &socket_a,
        native[0].endpoint(),
        vni(&sa),
        generation(&sa),
        &secret(&sa),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    bind_member(
        &socket_b,
        native[3].endpoint(),
        vni(&sb),
        generation(&sb),
        &secret(&sb),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let ca = Arc::new(OrgRelayConn::new(
        socket_a,
        native[0].endpoint(),
        vni(&sa),
        "nhop-trial-ingress".into(),
    ));
    let cb = Arc::new(OrgRelayConn::new(
        socket_b,
        native[3].endpoint(),
        vni(&sb),
        "nhop-trial-exit".into(),
    ));
    let carrier_a = Arc::new(Carrier::Relay {
        dst: ca.synth_peer(),
        conn: ca,
        dead: AtomicBool::new(false),
    });
    let carrier_b = Arc::new(Carrier::Relay {
        dst: cb.synth_peer(),
        conn: cb,
        dead: AtomicBool::new(false),
    });
    let ip_a: Ipv4Addr = network
        .overlay_nodes
        .base
        .find_by_id(a_id)
        .await
        .unwrap()
        .overlay_ip
        .parse()
        .unwrap();
    let ip_b: Ipv4Addr = network
        .overlay_nodes
        .base
        .find_by_id(b_id)
        .await
        .unwrap()
        .overlay_ip
        .parse()
        .unwrap();
    let (mut wg_a, mut received_a) = WgDevice::new(key_a.secret.clone());
    let (mut wg_b, mut received_b) = WgDevice::new(key_b.secret.clone());
    wg_a.add_peer(key_b.public.to_bytes(), ip_b, carrier_a, true);
    wg_b.add_peer(key_a.public.to_bytes(), ip_a, carrier_b, false);
    let packet = |source: Ipv4Addr, target: Ipv4Addr, payload: &[u8]| {
        let mut bytes = vec![0u8; 20 + payload.len()];
        bytes[0] = 0x45;
        let n = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&n.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&target.octets());
        bytes[20..].copy_from_slice(payload);
        bytes
    };
    let forward = packet(ip_a, ip_b, b"four relay trial WG forward");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            wg_a.send_ip_packet(&forward).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(100), received_b.recv()).await
                && got == forward
            {
                break;
            }
        }
    })
    .await
    .expect("real four relay forward data");
    let reverse = packet(ip_b, ip_a, b"four relay trial WG reverse");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_b.send_ip_packet(&reverse).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(100), received_a.recv()).await
                && got == reverse
            {
                break;
            }
        }
    })
    .await
    .expect("real four relay reverse data");
    async fn signal(ws: &mut Ws, t: &str, id: &Value, return_id: Option<&str>) {
        let mut v = json!({"t":t,"trial_id":id});
        if let Some(r) = return_id {
            v["return_id"] = json!(r);
        }
        ws.send(Message::Text(v.to_string().into())).await.unwrap();
    }
    async fn assert_no_control(ws: &mut Ws, forbidden: &[&str]) {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        loop {
            match tokio::time::timeout_at(deadline, ws.next()).await {
                Err(_) => break,
                Ok(Some(Ok(Message::Text(txt)))) => {
                    let msg: Value = serde_json::from_str(&txt).unwrap();
                    assert!(
                        !forbidden.contains(&msg["t"].as_str().unwrap_or_default()),
                        "premature control frame: {msg}"
                    );
                }
                Ok(Some(Ok(_))) => {}
                _ => panic!("member control socket closed during barrier check"),
            }
        }
    }
    let id = sa["trial_id"].clone();
    let trial_oid = ObjectId::parse_str(id.as_str().unwrap()).unwrap();
    signal(&mut a, "rc:overlay.path_trial_ready", &id, None).await;
    tokio::time::timeout(wait, async {
        while support::trial_member_progress(network, trial_oid, a_id) != Some((0, true)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first Ready processed without committing");
    assert_eq!(
        support::trial_member_progress(network, trial_oid, b_id),
        Some((0, false))
    );
    for ws in [&mut a, &mut b] {
        assert_no_control(
            ws,
            &[
                "rc:overlay.path_trial_commit",
                "rc:overlay.path_trial_finalize",
            ],
        )
        .await;
    }
    signal(&mut b, "rc:overlay.path_trial_ready", &id, None).await;
    for ws in [&mut a, &mut b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_commit", wait)
                .await
                .unwrap()["trial_id"],
            id
        );
    }
    signal(&mut a, "rc:overlay.path_trial_committed", &id, None).await;
    tokio::time::timeout(wait, async {
        while support::trial_member_progress(network, trial_oid, a_id) != Some((1, true)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first Committed processed without finalizing");
    assert_eq!(
        support::trial_member_progress(network, trial_oid, b_id),
        Some((1, false))
    );
    for ws in [&mut a, &mut b] {
        assert_no_control(ws, &["rc:overlay.path_trial_finalize"]).await;
    }
    signal(&mut b, "rc:overlay.path_trial_committed", &id, None).await;
    for ws in [&mut a, &mut b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_finalize", wait)
                .await
                .unwrap()["trial_id"],
            id
        );
    }
    let committed_forward = packet(ip_a, ip_b, b"committed four relay WG forward");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_a.send_ip_packet(&committed_forward).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(100), received_b.recv()).await
                && got == committed_forward
            {
                break;
            }
        }
    })
    .await
    .expect("committed four relay forward data");
    let committed_reverse = packet(ip_b, ip_a, b"committed four relay WG reverse");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_b.send_ip_packet(&committed_reverse).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(100), received_a.recv()).await
                && got == committed_reverse
            {
                break;
            }
        }
    })
    .await
    .expect("committed four relay reverse data");
    let mut bridge_evidence = Vec::new();
    for i in 0..3 {
        let bridge_id =
            ObjectId::parse_str(bridges[i]["bridge"]["trial_id"].as_str().unwrap()).unwrap();
        let generation = bridges[i]["bridge"]["generation"].as_u64().unwrap();
        let (watch, sockets) = native[i]
            .bridge_evidence(bridge_id, generation)
            .expect("bridge active with correct generation");
        bridge_evidence.push((bridge_id, watch, sockets));
    }
    for relay in &native {
        let counts = relay.session_counts();
        assert_eq!(
            counts.sessions_installed, 1,
            "trial relay session not installed"
        );
        assert_eq!(
            counts.sessions_revoked, 0,
            "trial relay session revoked early"
        );
    }
    for node in &nodes {
        assert_eq!(
            support::trial_slots_on_relay(network, ObjectId::parse_str(node).unwrap()),
            1
        );
    }
    let return_id = ObjectId::new().to_hex();
    signal(
        &mut a,
        "rc:overlay.path_trial_return_request",
        &id,
        Some(&return_id),
    )
    .await;
    for ws in [&mut a, &mut b] {
        assert_eq!(
            recv_t(ws, "rc:overlay.path_trial_return_prepare", wait)
                .await
                .unwrap()["return_id"],
            return_id
        );
    }
    signal(
        &mut a,
        "rc:overlay.path_trial_return_ready",
        &id,
        Some(&return_id),
    )
    .await;
    signal(
        &mut b,
        "rc:overlay.path_trial_return_ready",
        &id,
        Some(&return_id),
    )
    .await;
    for ws in [&mut a, &mut b] {
        recv_t(ws, "rc:overlay.path_trial_return_commit", wait)
            .await
            .expect("bilateral return commit");
    }
    signal(
        &mut a,
        "rc:overlay.path_trial_returned",
        &id,
        Some(&return_id),
    )
    .await;
    signal(
        &mut a,
        "rc:overlay.path_trial_return_request",
        &id,
        Some(&return_id),
    )
    .await;
    for ws in [&mut a, &mut b] {
        recv_t(ws, "rc:overlay.path_trial_return_commit", wait)
            .await
            .expect("one-ACK return replay");
    }
    for node in &nodes {
        assert_eq!(
            support::trial_slots_on_relay(network, ObjectId::parse_str(node).unwrap()),
            1,
            "one return ACK released a relay"
        );
    }
    for ws in &mut relays {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        loop {
            match tokio::time::timeout_at(deadline, ws.next()).await {
                Err(_) => break,
                Ok(Some(Ok(Message::Text(txt)))) => {
                    let msg: Value = serde_json::from_str(&txt).unwrap();
                    assert!(
                        !["rc:overlay.relay_revoke", "rc:overlay.relay_bridge_revoke"]
                            .contains(&msg["t"].as_str().unwrap_or_default()),
                        "one return ACK revoked a relay or bridge: {msg}"
                    );
                }
                Ok(Some(Ok(_))) => {}
                _ => panic!("relay control socket closed while waiting for second return ACK"),
            }
        }
    }
    let pending_forward = packet(ip_a, ip_b, b"one return ACK four relay forward");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_a.send_ip_packet(&pending_forward).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(100), received_b.recv()).await
                && got == pending_forward
            {
                break;
            }
        }
    })
    .await
    .expect("one return ACK preserves forward data");
    let pending_reverse = packet(ip_b, ip_a, b"one return ACK four relay reverse");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_b.send_ip_packet(&pending_reverse).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(100), received_a.recv()).await
                && got == pending_reverse
            {
                break;
            }
        }
    })
    .await
    .expect("one return ACK preserves reverse data");
    for relay in &native {
        assert_eq!(
            relay.session_counts().sessions_revoked,
            0,
            "one ACK retired a native session"
        );
    }
    for (i, (bridge_id, _, _)) in bridge_evidence.iter().enumerate() {
        native[i]
            .bridge_evidence(
                *bridge_id,
                bridges[i]["bridge"]["generation"].as_u64().unwrap(),
            )
            .expect("one ACK retired a native bridge");
    }
    signal(
        &mut b,
        "rc:overlay.path_trial_returned",
        &id,
        Some(&return_id),
    )
    .await;
    for ws in [&mut a, &mut b] {
        recv_t(ws, "rc:overlay.path_trial_return_finalize", wait)
            .await
            .expect("bilateral return finalize");
    }
    for (i, ws) in relays.iter_mut().enumerate() {
        let revoke = recv_t(ws, "rc:overlay.relay_revoke", wait)
            .await
            .expect("all trial relays retired");
        assert_eq!(revoke["vni"], serves[i]["vni"]);
        native[i].serve(serde_json::from_value(revoke).unwrap(), None);
    }
    for (i, ws) in relays.iter_mut().enumerate().take(3) {
        let revoke = recv_t(ws, "rc:overlay.relay_bridge_revoke", wait)
            .await
            .expect("all trial bridges retired");
        assert_eq!(revoke["trial_id"], bridges[i]["bridge"]["trial_id"]);
        assert_eq!(revoke["generation"], bridges[i]["bridge"]["generation"]);
        native[i].serve(serde_json::from_value(revoke).unwrap(), None);
    }
    for (i, (bridge_id, watch, sockets)) in bridge_evidence.into_iter().enumerate() {
        native[i]
            .assert_bridge_retired(bridge_id, watch, sockets)
            .await
            .expect("bridge registry and sockets retired");
    }
    for relay in &native {
        tokio::time::timeout(Duration::from_secs(2), async {
            while relay.session_counts().sessions_revoked != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("native session revoke applied");
        relay
            .probe_healthy()
            .await
            .expect("native relay listener remains healthy");
    }
    for node in &nodes {
        assert_eq!(
            support::trial_slots_on_relay(network, ObjectId::parse_str(node).unwrap()),
            0
        );
    }
    while received_a.try_recv().is_ok() {}
    while received_b.try_recv().is_ok() {}
    assert_eq!(
        wg_a.fixture_relay_receive_task_live(&key_b.public.to_bytes()),
        Some(true)
    );
    assert_eq!(
        wg_b.fixture_relay_receive_task_live(&key_a.public.to_bytes()),
        Some(true)
    );
    // Unique lengths distinguish these data packets from fixture control,
    // keepalive and earlier packets. BoringTun adds 32 WG bytes without padding.
    let stopped_forward = packet(ip_a, ip_b, &[0x6d; 173]);
    let stopped_reverse = packet(ip_b, ip_a, &[0x79; 181]);
    native[0].watch_rejected_wg_data(source_a, vni(&sa), stopped_forward.len() + 32);
    native[3].watch_rejected_wg_data(source_b, vni(&sb), stopped_reverse.len() + 32);
    for _ in 0..4 {
        assert!(
            wg_a.send_ip_packet(&stopped_forward).await,
            "forward test packet was not locally accepted"
        );
        assert!(
            wg_b.send_ip_packet(&stopped_reverse).await,
            "reverse test packet was not locally accepted"
        );
    }
    async fn assert_blocked(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>, forbidden: &[u8]) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(got)) => assert_ne!(
                    got.as_slice(),
                    forbidden,
                    "returned trial still carried data"
                ),
                Ok(None) => panic!("receiver closed during blocking check"),
                Err(_) => break,
            }
        }
    }
    tokio::join!(
        assert_blocked(&mut received_b, &stopped_forward),
        assert_blocked(&mut received_a, &stopped_reverse)
    );
    assert!(
        native[0].rejected_wg_data_count() > 0,
        "ingress relay did not reject matching WG data for the retired VNI"
    );
    assert!(
        native[3].rejected_wg_data_count() > 0,
        "exit relay did not reject matching WG data for the retired VNI"
    );
    assert_eq!(
        wg_a.fixture_relay_receive_task_live(&key_b.public.to_bytes()),
        Some(true),
        "forward WG receive task stopped"
    );
    assert_eq!(
        wg_b.fixture_relay_receive_task_live(&key_a.public.to_bytes()),
        Some(true),
        "reverse WG receive task stopped"
    );
}

/// Exercise a same-zone, explicitly authorized three-relay session with the
/// real server messages, native relays, and actual WireGuard packet crypto.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_graph_same_zone_actual_wg_and_bridge_revocation() {
    use meshharbor_mod_network::org_relay::candidate_test_support as support;
    use meshharbor_remote_control::signaling::ServerMsg;
    use meshharbord::relay_server::backbone_test_support::{
        BindSecret, Carrier, NativeRelay, OrgRelayConn, WgDevice, WgKeypair, bind_member,
    };
    use std::{
        net::Ipv4Addr,
        sync::{Arc, atomic::AtomicBool},
    };
    let native = [
        NativeRelay::start().await.unwrap(),
        NativeRelay::start().await.unwrap(),
        NativeRelay::start().await.unwrap(),
    ];
    let key_a = WgKeypair::generate();
    let key_b = WgKeypair::generate();
    let slug = "iso-same-wg-e2e";
    let rig = Rig::up(slug, "enforce").await;
    let mut relays = Vec::new();
    let mut agents = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..3 {
        let name = format!("{slug}-relay-{i}");
        let (agent, token) = enroll(&rig.app, &rig.seeded, &name).await;
        let mut ws = connect_from(&rig.app, &token, &["relay-server"], Some(CN_R)).await;
        assert_observed(&rig.app, &agent, Some(CN_R)).await;
        line_join(
            &mut ws,
            10 + i,
            &format!("223.6.6.{}:41641", 6 + i),
            json!({"relay_backbone_ready":true}),
        )
        .await;
        assert_eq!(approve(&rig.app, &rig.seeded, &agent, true).await, 200);
        let node = rig.node(&name).await;
        grant_relay(&rig.app, &rig.seeded, &node).await;
        relays.push(ws);
        agents.push(agent);
        nodes.push(node);
    }
    let mut a = rig.device(&format!("{slug}-a"), Some(CN_A)).await;
    let mut b = rig.device(&format!("{slug}-b"), Some(CN_A)).await;
    for (ws, key, endpoint) in [
        (&mut a, key_a.public_base64(), "223.5.5.5:41641"),
        (&mut b, key_b.public_base64(), "223.5.5.6:41641"),
    ] {
        ws.send(Message::Text(
            json!({"t":"rc:overlay.join", "wg_public_key":key, "mtu":1280,
            "endpoints":[endpoint], "supports_org_relay":true, "supports_backbone_only_v1":true,
            "supports_server_relay_strategy":true, "org_primary":true})
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
            .await
            .expect("member join");
    }
    let a_id = ObjectId::parse_str(rig.node(&format!("{slug}-a")).await).unwrap();
    let b_id = ObjectId::parse_str(rig.node(&format!("{slug}-b")).await).unwrap();
    set_mode(&rig.app, &rig.seeded, "on").await;
    let policy_path = |agent: &str| {
        format!(
            "/api/tenant/{}/agent/{agent}/peer-relay-policy",
            rig.seeded.tenant_id
        )
    };
    for i in 0..2 {
        let body = json!({"serve":true,"approved_backbone_edges":[{"relay_agent_id":agents[i+1],
            "endpoint":native[i+1].underlay_endpoint().to_string(),"cross_border":false}]});
        let (status, value) = put(
            &rig.app,
            &policy_path(&agents[i]),
            &rig.seeded.admin.access_token,
            body,
        )
        .await;
        assert_eq!(status, 200, "{value}");
    }
    let network = rig.app.state.network();
    let ids: Vec<_> = nodes
        .iter()
        .map(|id| ObjectId::parse_str(id).unwrap())
        .collect();
    assert!(support::record_member_probe_fixture(
        network,
        a_id,
        &[
            (ids[0], "223.6.6.6:3478".into(), true, Some(10)),
            (ids[1], "223.6.6.7:3478".into(), false, None),
            (ids[2], "223.6.6.8:3478".into(), false, None)
        ]
    ));
    assert!(support::record_member_probe_fixture(
        network,
        b_id,
        &[
            (ids[0], "223.6.6.6:3478".into(), false, None),
            (ids[1], "223.6.6.7:3478".into(), false, None),
            (ids[2], "223.6.6.8:3478".into(), true, Some(10))
        ]
    ));
    let selected = support::select_path(network, a_id, b_id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        selected,
        (
            agents
                .iter()
                .map(|id| ObjectId::parse_str(id).unwrap())
                .collect(),
            false
        )
    );
    relay_request(&mut a, &b_id.to_hex()).await;
    let wait = Duration::from_secs(8);
    let mut serves = Vec::new();
    for ws in &mut relays {
        serves.push(
            recv_t(ws, "rc:overlay.relay_serve", wait)
                .await
                .expect("relay serve"),
        );
    }
    let bridge0 = recv_t(&mut relays[0], "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("first bridge");
    let bridge1 = recv_t(&mut relays[1], "rc:overlay.relay_bridge_serve", wait)
        .await
        .expect("second bridge");
    let sa = recv_t(&mut a, "rc:overlay.relay_session", wait)
        .await
        .expect("requester grant");
    let sb = recv_t(&mut b, "rc:overlay.relay_session", wait)
        .await
        .expect("peer grant");
    assert_eq!(sa["vni"], serves[0]["vni"]);
    assert_eq!(sb["vni"], serves[2]["vni"]);
    assert_eq!(bridge0["bridge"]["local_vni"], serves[0]["vni"]);
    assert_eq!(bridge0["bridge"]["remote_vni"], serves[1]["vni"]);
    assert_eq!(bridge1["bridge"]["local_vni"], serves[1]["vni"]);
    assert_eq!(bridge1["bridge"]["remote_vni"], serves[2]["vni"]);
    assert!(
        audit_rows(&rig.app, &rig.seeded)
            .await
            .iter()
            .any(|r| r["reason"] == "multi_hop_same_zone_attempt")
    );
    for (relay, frame) in native.iter().zip(serves.iter()) {
        relay.serve(
            serde_json::from_value::<ServerMsg>(frame.clone()).unwrap(),
            None,
        );
    }
    native[0].serve(
        serde_json::from_value(bridge0).unwrap(),
        Some(native[0].policy_to(&native[1])),
    );
    native[1].serve(
        serde_json::from_value(bridge1).unwrap(),
        Some(native[1].policy_to(&native[2])),
    );
    let socket_a = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let secret = |frame: &Value| {
        BindSecret::from_bytes(
            BASE64
                .decode(frame["bind_secret"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    let vni = |frame: &Value| frame["vni"].as_u64().unwrap() as u32;
    let generation = |frame: &Value| frame["generation"].as_u64().unwrap();
    bind_member(
        &socket_a,
        native[0].endpoint(),
        vni(&sa),
        generation(&sa),
        &secret(&sa),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    bind_member(
        &socket_b,
        native[2].endpoint(),
        vni(&sb),
        generation(&sb),
        &secret(&sb),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let conn_a = Arc::new(OrgRelayConn::new(
        socket_a,
        native[0].endpoint(),
        vni(&sa),
        "same-zone-ingress".into(),
    ));
    let conn_b = Arc::new(OrgRelayConn::new(
        socket_b,
        native[2].endpoint(),
        vni(&sb),
        "same-zone-exit".into(),
    ));
    let carrier_a = Arc::new(Carrier::Relay {
        dst: conn_a.synth_peer(),
        conn: conn_a,
        dead: AtomicBool::new(false),
    });
    let carrier_b = Arc::new(Carrier::Relay {
        dst: conn_b.synth_peer(),
        conn: conn_b,
        dead: AtomicBool::new(false),
    });
    let ip_a: Ipv4Addr = network
        .overlay_nodes
        .base
        .find_by_id(a_id)
        .await
        .unwrap()
        .overlay_ip
        .parse()
        .unwrap();
    let ip_b: Ipv4Addr = network
        .overlay_nodes
        .base
        .find_by_id(b_id)
        .await
        .unwrap()
        .overlay_ip
        .parse()
        .unwrap();
    let (mut wg_a, mut received_a) = WgDevice::new(key_a.secret.clone());
    let (mut wg_b, mut received_b) = WgDevice::new(key_b.secret.clone());
    wg_a.add_peer(key_b.public.to_bytes(), ip_b, carrier_a, true);
    wg_b.add_peer(key_a.public.to_bytes(), ip_a, carrier_b, false);
    let packet = |source: Ipv4Addr, target: Ipv4Addr, payload: &[u8]| {
        let mut bytes = vec![0u8; 20 + payload.len()];
        bytes[0] = 0x45;
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&target.octets());
        bytes[20..].copy_from_slice(payload);
        bytes
    };
    let forward = packet(ip_a, ip_b, b"same zone three relay WG forward");
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            wg_a.send_ip_packet(&forward).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(150), received_b.recv()).await
                && got == forward
            {
                break;
            }
        }
    })
    .await
    .expect("actual forward WG packet across three same-zone native relays");
    let backward = packet(ip_b, ip_a, b"same zone three relay WG reverse");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            wg_b.send_ip_packet(&backward).await;
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(150), received_a.recv()).await
                && got == backward
            {
                break;
            }
        }
    })
    .await
    .expect("actual reverse WG packet across three same-zone native relays");
    let (status, body) = put(
        &rig.app,
        &policy_path(&agents[0]),
        &rig.seeded.admin.access_token,
        json!({"serve":true,"approved_backbone_edges":[]}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let pair = meshharbor_mod_network::overlay::pair_key(a_id, b_id);
    assert!(
        network.org_relay.active_session(&pair).is_none(),
        "withdrawn edge must remove session"
    );
    // Save the other server revocations, but first apply only the revoked
    // source bridge. This tests that the bridge itself stops both directions.
    let mut revokes = Vec::new();
    for (i, ws) in relays.iter_mut().enumerate() {
        let revoke = recv_t(ws, "rc:overlay.relay_revoke", wait)
            .await
            .expect("relay revoke");
        assert_eq!(revoke["vni"], serves[i]["vni"]);
        revokes.push(revoke);
    }
    let revoke0 = recv_t(&mut relays[0], "rc:overlay.relay_bridge_revoke", wait)
        .await
        .expect("first bridge revoke");
    let revoke1 = recv_t(&mut relays[1], "rc:overlay.relay_bridge_revoke", wait)
        .await
        .expect("second bridge revoke");
    assert!(
        recv_t(&mut a, "rc:overlay.relay_revoke", wait)
            .await
            .is_some()
    );
    assert!(
        recv_t(&mut b, "rc:overlay.relay_revoke", wait)
            .await
            .is_some()
    );
    let bridge_id = ObjectId::parse_str(revoke0["trial_id"].as_str().unwrap()).unwrap();
    let bridge_generation = revoke0["generation"].as_u64().unwrap();
    let (bridge_retirement, bridge_sockets) = native[0]
        .bridge_evidence(bridge_id, bridge_generation)
        .expect("revocation names the running source bridge generation");
    native[0].serve(serde_json::from_value(revoke0).unwrap(), None);
    // Revocation requests asynchronous cancellation in the production manager.
    // Observe both bridge sockets close before testing post-retirement traffic.
    native[0]
        .assert_bridge_retired(bridge_id, bridge_retirement, bridge_sockets)
        .await
        .expect("revoked source bridge must unregister and close both sockets");
    while received_a.try_recv().is_ok() {}
    while received_b.try_recv().is_ok() {}
    let blocked_a = packet(ip_a, ip_b, b"revoked same zone bridge blocks forward");
    let blocked_b = packet(ip_b, ip_a, b"revoked same zone bridge blocks reverse");
    for _ in 0..6 {
        wg_a.send_ip_packet(&blocked_a).await;
        wg_b.send_ip_packet(&blocked_b).await;
        if let Ok(Some(got)) =
            tokio::time::timeout(Duration::from_millis(120), received_b.recv()).await
        {
            assert_ne!(got, blocked_a, "forward passed revoked bridge");
        }
        if let Ok(Some(got)) =
            tokio::time::timeout(Duration::from_millis(120), received_a.recv()).await
        {
            assert_ne!(got, blocked_b, "reverse passed revoked bridge");
        }
    }
    for (relay, frame) in native.iter().zip(revokes.into_iter()) {
        relay.serve(serde_json::from_value(frame).unwrap(), None);
    }
    native[1].serve(serde_json::from_value(revoke1).unwrap(), None);
}

/// Item #96 — Under `app.business_isolation = "enforce"` and
/// `app.business_unknown_role = "enforce"`, any `Agent` or `TunnelClient`
/// whose effective role is `Unknown` (including revoked) is denied all
/// business connectivity across discovery, full/delta netmaps, TURN grants,
/// org relay planning, DERP allow table, managed forward admission, and
/// center-brokered tunnels (both open and mid-session forward requests),
/// regardless of `overlay_acl` (`off`/`warn`/`enforce`), while management
/// traffic remains unaffected.
#[tokio::test]
async fn unknown_role_enforce_denies_all_business_connectivity_until_approved_and_revokes_on_reset()
{
    use crate::managed_forward_tests::{post as mf_post, report_listener, spec, verdict};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let rig = Rig::up_with_unknown_role("iso-unknown-role", "enforce", "enforce").await;
    let tid = rig.seeded.tenant_id.clone();
    let tid_oid = ObjectId::parse_str(&tid).unwrap();
    let admin = rig.seeded.admin.access_token.clone();

    // Allow all_users -> all_agents on loopback 9000-9999 for center-brokered tunnel tests.
    let policy_resp = rig
        .app
        .auth_post(&format!("/api/tenant/{tid}/tunnel-policy"), &admin)
        .json(&json!({
            "name": "allow-loopback-9000",
            "subjects": [{ "kind": "all_users" }],
            "targets": [{ "kind": "all_agents" }],
            "allowlist": [{
                "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
                "port_range": { "low": 9000, "high": 9999 }
            }],
            "max_concurrent_flows": 32,
            "max_bytes_per_session": 1048576
        }))
        .send()
        .await
        .unwrap();
    assert!(policy_resp.status().is_success());

    // Enroll two same-zone agents (US_A, US_B), one cross-zone agent (CN_A),
    // one same-zone relay agent (US_R), and one same-zone TunnelClient (US_A).
    let (us_a_id, us_a_tok) = enroll(&rig.app, &rig.seeded, "ur-us-a").await;
    let (us_b_id, us_b_tok) = enroll(&rig.app, &rig.seeded, "ur-us-b").await;
    let (cn_a_id, cn_a_tok) = enroll(&rig.app, &rig.seeded, "ur-cn-a").await;
    let (us_r_id, us_r_tok) = enroll(&rig.app, &rig.seeded, "ur-us-r").await;

    let mut us_a = connect_from(&rig.app, &us_a_tok, &["managed-forward"], Some(US_A)).await;
    let mut us_b = connect_from(&rig.app, &us_b_tok, &[], Some(US_B)).await;
    let mut cn_a = connect_from(&rig.app, &cn_a_tok, &[], Some(CN_A)).await;
    let mut us_r = connect_from(&rig.app, &us_r_tok, &["relay-server"], Some(US_R)).await;
    assert_observed(&rig.app, &us_a_id, Some(US_A)).await;
    assert_observed(&rig.app, &us_b_id, Some(US_B)).await;
    assert_observed(&rig.app, &cn_a_id, Some(CN_A)).await;
    assert_observed(&rig.app, &us_r_id, Some(US_R)).await;

    let et: Value = rig
        .app
        .auth_post(
            &format!("/api/tenant/{tid}/tunnel-client/enroll-token"),
            &admin,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled_tc: Value = rig
        .app
        .client
        .post(rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"],
            "machine_id": "ur-tc-us",
            "machine_name": "ur-tc-us",
            "os": "linux",
            "client_version": "0.4.151"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tc_id = enrolled_tc["tunnel_client_id"].as_str().unwrap().to_owned();
    let tc_tok = enrolled_tc["tunnel_client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let tc_url = format!(
        "ws://{}/ws?token={}&role=tunnel-client",
        rig.app.addr,
        tc_tok
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let mut tc_req = tc_url.as_str().into_client_request().unwrap();
    tc_req
        .headers_mut()
        .insert("x-forwarded-for", US_A.parse().unwrap());
    let (mut tc_ws, _) = tokio_tungstenite::connect_async(tc_req).await.unwrap();

    // Management endpoints work while effective_role is Unknown.
    for (kind, id) in [
        ("agent", us_a_id.as_str()),
        ("tunnel-client", tc_id.as_str()),
    ] {
        let auth_view: Value = rig
            .app
            .auth_get(
                &format!("/api/admin/business-authority/{kind}/{tid}/{id}"),
                &rig.owner_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(auth_view["effective_role"], json!("unknown"), "{auth_view}");
    }

    // Join overlay on all 5 devices (seeds 1..=5).
    assert!(peer_ids(&line_join(&mut us_a, 1, "8.8.8.1:41641", json!({})).await).is_empty());
    assert!(peer_ids(&line_join(&mut us_b, 2, "8.8.8.2:41641", json!({})).await).is_empty());
    assert!(peer_ids(&line_join(&mut cn_a, 3, "223.5.5.1:41641", json!({})).await).is_empty());
    assert!(peer_ids(&line_join(&mut us_r, 4, "1.1.1.1:41641", json!({})).await).is_empty());
    assert!(peer_ids(&line_join(&mut tc_ws, 5, "8.8.8.5:41641", json!({})).await).is_empty());

    let us_a_node = rig.node("ur-us-a").await;
    let us_b_node = rig.node("ur-us-b").await;
    let cn_a_node = rig.node("ur-cn-a").await;
    let us_r_node = rig.node("ur-us-r").await;
    let net = rig.app.state.network();
    let tc_oid = ObjectId::parse_str(&tc_id).unwrap();
    let tc_node = meshharbor_mod_network::overlay::current_node(
        net,
        meshharbor_mod_network::overlay::NodeIdentity::TunnelClient(tc_oid),
    )
    .await
    .unwrap()
    .id
    .unwrap()
    .to_hex();

    // Approve us_r as an org-relay server (both peer-relay + business role "server")
    // so the relay itself is ready while the members are still Unknown.
    set_mode(&rig.app, &rig.seeded, "on").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &us_r_id, true).await, 200);
    grant_relay(&rig.app, &rig.seeded, &us_r_node).await;
    rig.set_role(&us_r_id, "server").await;
    let _ = deltas(&mut us_a, Duration::from_millis(400)).await;

    // Seed a mesh link row between us_a and us_b so `/api/agent/self/mesh` has an edge to filter.
    rig.app
        .db
        .collection::<bson::Document>("stats_mesh")
        .insert_one(bson::doc! {
            "_id": &us_a_id,
            "tenant_id": tid_oid,
            "agent_id": ObjectId::parse_str(&us_a_id).unwrap(),
            "ts": bson::DateTime::now(),
            "links": [{
                "node": &us_b_node,
                "carrier": "direct",
                "rtt_ms": 4_i64,
                "stalled": false,
                "tx": 0_i64,
                "rx": 0_i64,
                "relay": null,
            }],
        })
        .await
        .unwrap();

    // Report listener on us_a for managed-forward checks.
    report_listener(&rig.app, &mut us_a, &tid, &admin, &us_a_id, 22).await;
    let ip_a = net
        .overlay_nodes
        .base
        .find_by_id(ObjectId::parse_str(&us_a_node).unwrap())
        .await
        .unwrap()
        .overlay_ip;
    let ip_b = net
        .overlay_nodes
        .base
        .find_by_id(ObjectId::parse_str(&us_b_node).unwrap())
        .await
        .unwrap()
        .overlay_ip;
    let ip_tc = net
        .overlay_nodes
        .base
        .find_by_id(ObjectId::parse_str(&tc_node).unwrap())
        .await
        .unwrap()
        .overlay_ip;
    let plan_path = format!("/api/tenant/{tid}/managed-forward/plan");

    // Verify across all three overlay_acl modes ("off", "warn", "enforce") that
    // Unknown role is denied on every business connectivity surface.
    for acl_mode in ["off", "warn", "enforce"] {
        let (s, v) = put(
            &rig.app,
            &format!("/api/tenant/{tid}/overlay-acl/mode"),
            &admin,
            json!({ "mode": acl_mode }),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        let map_a = line_join(&mut us_a, 1, "8.8.8.1:41641", json!({})).await;
        assert!(
            peer_ids(&map_a).is_empty(),
            "acl={acl_mode}: Unknown us_a must see no peers: {map_a}"
        );
        assert!(
            map_a["network"]["relay_probe_targets"]
                .as_array()
                .is_none_or(|t| t.is_empty()),
            "acl={acl_mode}: Unknown us_a must not receive relay_probe_targets: {map_a}"
        );
        let (up, rm) = deltas(&mut us_b, Duration::from_millis(400)).await;
        assert!(
            !up.contains(&us_a_node) && rm.contains(&us_a_node),
            "acl={acl_mode}: us_b must receive explicit remove for Unknown us_a: up={up:?} rm={rm:?}"
        );

        // Discovery: /api/agent/self/devices, /api/agent/self/mesh, /api/tunnel-client/agents
        let devs: Value = rig
            .app
            .auth_get("/api/agent/self/devices", &us_a_tok)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            devs["total"],
            json!(1),
            "acl={acl_mode}: only self in devices: {devs}"
        );
        assert_eq!(devs["items"][0]["id"], json!(us_a_id));

        let mesh: Value = rig
            .app
            .auth_get("/api/agent/self/mesh", &us_a_tok)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            mesh["nodes"].as_array().unwrap().len(),
            1,
            "acl={acl_mode}: {mesh}"
        );
        assert!(
            mesh["edges"].as_array().unwrap().is_empty(),
            "acl={acl_mode}: {mesh}"
        );

        let tc_agents: Value = rig
            .app
            .auth_get("/api/tunnel-client/agents", &tc_tok)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            tc_agents.as_array().unwrap().is_empty(),
            "acl={acl_mode}: Unknown tunnel-client must see no agents: {tc_agents}"
        );
    }

    // Restore overlay_acl to "off" so only business_isolation + business_unknown_role gate.
    let (s, _) = put(
        &rig.app,
        &format!("/api/tenant/{tid}/overlay-acl/mode"),
        &admin,
        json!({ "mode": "off" }),
    )
    .await;
    assert_eq!(s, 200);

    // TURN grant & org relay denied while Unknown.
    relay_request(&mut us_a, &us_b_node).await;
    assert!(
        recv_t(
            &mut us_r,
            "rc:overlay.relay_serve",
            Duration::from_millis(500)
        )
        .await
        .is_none(),
        "Unknown pair must not mint org-relay session"
    );
    assert!(
        recv_t(
            &mut us_a,
            "rc:overlay.relay_grant",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "Unknown pair must not receive TURN grant"
    );
    let us_a_oid = ObjectId::parse_str(&us_a_node).unwrap();
    let us_b_oid = ObjectId::parse_str(&us_b_node).unwrap();
    assert!(matches!(
        meshharbor_mod_network::org_relay::candidate_test_support::select_path(
            net, us_a_oid, us_b_oid, false
        )
        .await,
        Err(meshharbor_remote_control::models::PeerRelayDenyReason::ZoneDenied)
    ));
    assert!(matches!(
        meshharbor_mod_network::org_relay::candidate_test_support::prepare_edges(
            net, us_a_oid, us_b_oid, false
        )
        .await,
        Err(meshharbor_remote_control::models::PeerRelayDenyReason::ZoneDenied)
    ));

    // DERP allow table denies Unknown pubkeys even in the same zone.
    assert!(
        !net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[1u8; 32], &[2u8; 32])
    );
    assert!(
        !net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[5u8; 32], &[1u8; 32])
    );

    // Managed forward admission denies both cross-node and same-node while Unknown.
    let mut fwd_spec = spec(&us_a_id, 15432);
    fwd_spec["dest_addr"] = json!(ip_b);
    fwd_spec["sources"] = json!([format!("{ip_tc}/32")]);
    let (_, plan) = mf_post(&rig.app, &plan_path, &admin, &fwd_spec).await;
    assert_eq!(verdict(&plan, "region"), "fail", "{plan}");
    assert_eq!(verdict(&plan, "source region"), "fail", "{plan}");

    let mut self_spec = spec(&us_a_id, 15433);
    self_spec["dest_addr"] = json!(ip_a);
    self_spec["sources"] = json!([format!("{ip_a}/32")]);
    let (_, self_plan) = mf_post(&rig.app, &plan_path, &admin, &self_spec).await;
    assert_eq!(
        verdict(&self_plan, "region"),
        "fail",
        "same-node Unknown must also fail: {self_plan}"
    );

    // Center-brokered tunnel open is refused for both Agent and TunnelClient while Unknown.
    assert_eq!(tunnel_open(&mut us_a, &us_b_id).await, "business_isolation");
    assert_eq!(
        tunnel_open(&mut tc_ws, &us_b_id).await,
        "business_isolation"
    );

    // ── Approve us_a, us_b, tc_us as "client" (and cn_a as "client" in CN) ──
    let _ = deltas(&mut us_a, Duration::from_millis(200)).await;
    rig.set_device_role("agent", &us_a_id, "client").await;
    rig.set_device_role("agent", &us_b_id, "client").await;
    rig.set_device_role("agent", &cn_a_id, "client").await;
    rig.set_device_role("tunnel-client", &tc_id, "client").await;

    let (up, _) = deltas(&mut us_a, Duration::from_millis(800)).await;
    assert!(
        up.contains(&us_b_node) && up.contains(&tc_node) && up.contains(&us_r_node),
        "approved same-zone peers must be upserted: {up:?}"
    );
    assert!(
        !up.contains(&cn_a_node),
        "approved cross-zone client must stay withheld: {up:?}"
    );

    // Discovery now includes approved same-zone peers and excludes cross-zone cn_a.
    let devs: Value = rig
        .app
        .auth_get("/api/agent/self/devices", &us_a_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(devs["total"], json!(4), "{devs}");
    let mesh: Value = rig
        .app
        .auth_get("/api/agent/self/mesh", &us_a_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mesh["edges"].as_array().unwrap().len(), 1, "{mesh}");
    let tc_agents: Value = rig
        .app
        .auth_get("/api/tunnel-client/agents", &tc_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tc_agent_ids: BTreeSet<String> = tc_agents
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["agent_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        tc_agent_ids,
        BTreeSet::from([us_a_id.clone(), us_b_id.clone(), us_r_id.clone()])
    );

    // DERP allow table permits approved same-zone peers and denies cross-zone cn_a.
    assert!(
        net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[1u8; 32], &[2u8; 32])
    );
    assert!(
        net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[5u8; 32], &[1u8; 32])
    );
    assert!(
        !net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[1u8; 32], &[3u8; 32])
    );

    // Managed forward plan now passes AND live managed forward is created and pushed.
    let (_, plan) = mf_post(&rig.app, &plan_path, &admin, &fwd_spec).await;
    assert_eq!(verdict(&plan, "region"), "pass", "{plan}");
    assert_eq!(verdict(&plan, "source region"), "pass", "{plan}");
    let wait = Duration::from_secs(5);
    let _ = recv_t(&mut us_a, "rc:forward.set", Duration::from_millis(300)).await;
    let (create_status, created_fwd) = mf_post(
        &rig.app,
        &format!("/api/tenant/{tid}/managed-forward"),
        &admin,
        &fwd_spec,
    )
    .await;
    assert_eq!(create_status, 201, "{created_fwd}");
    let pushed_fwd = recv_t(&mut us_a, "rc:forward.set", wait)
        .await
        .expect("ingress us_a receives ManagedForwardSet on create");
    assert_eq!(
        pushed_fwd["forwards"].as_array().unwrap().len(),
        1,
        "{pushed_fwd}"
    );

    // Org relay now mints for approved same-zone peers.
    relay_request(&mut us_a, &us_b_node).await;
    let serve = recv_t(&mut us_r, "rc:overlay.relay_serve", wait)
        .await
        .expect("approved pair mints org relay");
    let sess_a = recv_t(&mut us_a, "rc:overlay.relay_session", wait)
        .await
        .expect("us_a receives relay_session");
    let _sess_b = recv_t(&mut us_b, "rc:overlay.relay_session", wait)
        .await
        .expect("us_b receives relay_session");
    assert_eq!(serve["vni"], sess_a["vni"]);
    let pair = meshharbor_mod_network::overlay::pair_key(us_a_oid, us_b_oid);
    assert!(net.org_relay.active_session(&pair).is_some());

    // Center-brokered tunnel now opens for both Agent and TunnelClient, and forwards TCP.
    assert_eq!(tunnel_open(&mut us_a, &us_b_id).await, "opened");
    tc_ws
        .send(Message::Text(
            json!({
                "t": "rc:tunnel.open",
                "agent_id": us_a_id,
                "transport": "webrtc-dc-v1"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let tc_opened = recv_t(&mut tc_ws, "rc:tunnel.opened", wait)
        .await
        .expect("approved tunnel-client opens tunnel");
    let tc_session_id = tc_opened["session_id"].as_str().unwrap().to_owned();
    tc_ws
        .send(Message::Text(
            json!({
                "t": "rc:tunnel.tcp.request",
                "session_id": tc_session_id,
                "flow_id": 1,
                "dst_host": "127.0.0.1",
                "dst_port": 9000
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let forwarded = recv_t(&mut us_a, "rc:tunnel.tcp.forward", wait)
        .await
        .expect("us_a receives forwarded TCP request from approved tunnel-client");
    assert_eq!(forwarded["flow_id"], json!(1));

    // ── Revoke tc_us back to "unknown": immediate tunnel termination on BOTH legs,
    // managed-forward withdrawal on us_a, netmap remove on BOTH us_a and tc_ws,
    // DERP deny, and mid-session forward rejection at tunnel.rs:1424 ──
    let _ = deltas(&mut us_a, Duration::from_millis(200)).await;
    let _ = deltas(&mut tc_ws, Duration::from_millis(200)).await;
    rig.set_device_role("tunnel-client", &tc_id, "unknown")
        .await;
    let tc_term = recv_t(&mut tc_ws, "rc:tunnel.terminate", wait)
        .await
        .expect("revoked tunnel-client receives rc:tunnel.terminate");
    assert_eq!(tc_term["session_id"], json!(tc_session_id));
    let target_term = recv_t(&mut us_a, "rc:tunnel.terminate", wait)
        .await
        .expect("target agent us_a receives rc:tunnel.terminate when tunnel-client is revoked");
    assert_eq!(target_term["session_id"], json!(tc_session_id));
    let withdrawn_fwd = recv_t(&mut us_a, "rc:forward.set", wait)
        .await
        .expect("ingress us_a receives ManagedForwardSet withdrawal when source tc_us is revoked");
    assert!(
        withdrawn_fwd["forwards"].as_array().unwrap().is_empty(),
        "managed forward admitting revoked source must be withdrawn: {withdrawn_fwd}"
    );
    let (_, rm_a) = deltas(&mut us_a, Duration::from_millis(800)).await;
    assert!(
        rm_a.contains(&tc_node),
        "revoking tunnel-client to unknown must fan explicit remove to us_a: {rm_a:?}"
    );
    let (_, rm_tc) = deltas(&mut tc_ws, Duration::from_millis(800)).await;
    assert!(
        rm_tc.contains(&us_a_node) && rm_tc.contains(&us_b_node) && rm_tc.contains(&us_r_node),
        "revoked tunnel-client itself must receive explicit removes for its peers: {rm_tc:?}"
    );
    assert!(
        !net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[5u8; 32], &[1u8; 32])
    );
    tc_ws
        .send(Message::Text(
            json!({
                "t": "rc:tunnel.tcp.request",
                "session_id": tc_session_id,
                "flow_id": 2,
                "dst_host": "127.0.0.1",
                "dst_port": 9000
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let rejected = recv_t(&mut tc_ws, "rc:tunnel.tcp.reject", wait)
        .await
        .expect("revoked tunnel-client mid-session forward must be rejected at tunnel.rs:1424");
    assert_eq!(rejected["flow_id"], json!(2));
    assert_eq!(rejected["kind"], json!("acl_denied"));
    assert_eq!(rejected["reason"], json!("business_isolation"));

    // ── Revoke originating agent us_a back to "unknown": immediate org-relay
    // revocation, tunnel termination on BOTH originating us_a AND target us_b,
    // netmap remove on BOTH us_b and us_a, and DERP deny ──
    let _ = deltas(&mut us_a, Duration::from_millis(200)).await;
    let _ = deltas(&mut us_b, Duration::from_millis(200)).await;
    rig.set_device_role("agent", &us_a_id, "unknown").await;
    assert!(
        net.org_relay.active_session(&pair).is_none(),
        "revoking member to unknown must immediately revoke org-relay session"
    );
    let rev_r = recv_t(&mut us_r, "rc:overlay.relay_revoke", wait)
        .await
        .expect("relay receives relay_revoke");
    let rev_a = recv_t(&mut us_a, "rc:overlay.relay_revoke", wait)
        .await
        .expect("us_a receives relay_revoke");
    let rev_b = recv_t(&mut us_b, "rc:overlay.relay_revoke", wait)
        .await
        .expect("us_b receives relay_revoke");
    assert_eq!(rev_r["vni"], serve["vni"]);
    assert_eq!(rev_a["vni"], serve["vni"]);
    assert_eq!(rev_b["vni"], serve["vni"]);
    let _ = recv_t(&mut us_a, "rc:tunnel.terminate", wait)
        .await
        .expect("originating us_a receives rc:tunnel.terminate when its role is revoked");
    let _ = recv_t(&mut us_b, "rc:tunnel.terminate", wait)
        .await
        .expect("target us_b receives rc:tunnel.terminate when originating us_a role is revoked");
    let (_, rm_b) = deltas(&mut us_b, Duration::from_millis(800)).await;
    assert!(
        rm_b.contains(&us_a_node),
        "revoking us_a to unknown must fan explicit remove to us_b: {rm_b:?}"
    );
    let (_, rm_a2) = deltas(&mut us_a, Duration::from_millis(800)).await;
    assert!(
        rm_a2.contains(&us_b_node) && rm_a2.contains(&us_r_node),
        "revoked us_a itself must receive explicit removes for its peers: {rm_a2:?}"
    );
    assert!(
        !net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[1u8; 32], &[2u8; 32])
    );
}

/// Item #96 (b) — under `app.business_isolation = enforce` and
/// `app.business_unknown_role = warn`, `Unknown` devices in the same zone
/// remain permitted across all connectivity surfaces (netmap, DERP, tunnel
/// roster/open/forward, 1-hop org-relay mint, cross-border line, and managed
/// forward) while identifying the `Unknown` devices for `would refuse: unknown_role`
/// logging, and cross-zone `Unknown` devices without a line remain strictly
/// blocked by regional `enforce`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_role_warn_logs_without_blocking_same_zone_or_relaxing_zone_enforce() {
    use crate::managed_forward_tests::{post as mf_post, report_listener, spec, verdict};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let rig = Rig::up_with_unknown_role("iso-unknown-warn", "enforce", "warn").await;
    let tid = rig.seeded.tenant_id.clone();
    let tid_oid = ObjectId::parse_str(&tid).unwrap();
    let admin = rig.seeded.admin.access_token.clone();
    let wait = Duration::from_secs(5);

    let policy_resp = rig
        .app
        .auth_post(&format!("/api/tenant/{tid}/tunnel-policy"), &admin)
        .json(&json!({
            "name": "allow-loopback-9000",
            "subjects": [{ "kind": "all_users" }],
            "targets": [{ "kind": "all_agents" }],
            "allowlist": [{
                "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
                "port_range": { "low": 9000, "high": 9999 }
            }],
            "max_concurrent_flows": 32,
            "max_bytes_per_session": 1048576
        }))
        .send()
        .await
        .unwrap();
    assert!(policy_resp.status().is_success());

    let (us_a_id, us_a_tok) = enroll(&rig.app, &rig.seeded, "uw-us-a").await;
    let (us_b_id, us_b_tok) = enroll(&rig.app, &rig.seeded, "uw-us-b").await;
    let (cn_a_id, cn_a_tok) = enroll(&rig.app, &rig.seeded, "uw-cn-a").await;
    let (us_r_id, us_r_tok) = enroll(&rig.app, &rig.seeded, "uw-us-r").await;

    let mut us_a = connect_from(&rig.app, &us_a_tok, &["managed-forward"], Some(US_A)).await;
    let mut us_b = connect_from(&rig.app, &us_b_tok, &[], Some(US_B)).await;
    let mut cn_a = connect_from(&rig.app, &cn_a_tok, &[], Some(CN_A)).await;
    let mut us_r = connect_from(&rig.app, &us_r_tok, &["relay-server"], Some(US_R)).await;
    assert_observed(&rig.app, &us_a_id, Some(US_A)).await;
    assert_observed(&rig.app, &us_b_id, Some(US_B)).await;
    assert_observed(&rig.app, &cn_a_id, Some(CN_A)).await;
    assert_observed(&rig.app, &us_r_id, Some(US_R)).await;

    // 1. Netmap: same-zone Unknown peers see each other; cross-zone Unknown peer is withheld.
    line_join(&mut us_a, 1, "8.8.8.1:41641", json!({})).await;
    let us_a_node = rig.node("uw-us-a").await;
    let b_map = line_join(&mut us_b, 2, "8.8.8.2:41641", json!({})).await;
    let us_b_node = rig.node("uw-us-b").await;
    assert_eq!(
        peer_ids(&b_map),
        set(&[&us_a_node]),
        "warn mode permits same-zone Unknown peers"
    );
    let cn_map = line_join(&mut cn_a, 3, "223.5.5.1:41641", json!({})).await;
    assert!(
        peer_ids(&cn_map).is_empty(),
        "warn mode never relaxes cross-zone regional enforce"
    );
    line_join(
        &mut us_r,
        4,
        "1.1.1.1:41641",
        json!({"relay_backbone_ready": true}),
    )
    .await;
    let us_r_node = rig.node("uw-us-r").await;

    // 2. DERP allow table: permits same-zone Unknown peers, denies cross-zone Unknown peers.
    let net = rig.app.state.network();
    assert!(
        net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[1u8; 32], &[2u8; 32]),
        "warn mode DERP permits same-zone Unknown peers"
    );
    assert!(
        !net.derp_acl
            .iter()
            .next()
            .unwrap()
            .value()
            .permits(&[1u8; 32], &[3u8; 32]),
        "warn mode DERP still denies cross-zone Unknown peers"
    );

    // Verify `Lines` under warn mode identifies Unknown devices for `would refuse: unknown_role`.
    let topo = meshharbor_mod_network::business_isolation::lines(
        net,
        meshharbor_mod_network::business_isolation::Mode::Enforce,
        tid_oid,
    )
    .await;
    assert_eq!(
        topo.unknown_role,
        meshharbor_mod_network::business_isolation::Mode::Warn
    );
    assert!(topo.approved_roles.is_empty());

    // 3. Center-brokered Tunnel (roster + open + TCP forward) with Unknown roles in warn mode.
    let et: Value = rig
        .app
        .auth_post(
            &format!("/api/tenant/{tid}/tunnel-client/enroll-token"),
            &admin,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled_tc: Value = rig
        .app
        .client
        .post(rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"],
            "machine_id": "uw-tc-us",
            "machine_name": "uw-tc-us",
            "os": "linux",
            "client_version": "0.4.151"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tc_tok = enrolled_tc["tunnel_client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let tc_url = format!(
        "ws://{}/ws?token={}&role=tunnel-client",
        rig.app.addr,
        tc_tok
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let mut tc_req = tc_url.as_str().into_client_request().unwrap();
    tc_req
        .headers_mut()
        .insert("x-forwarded-for", US_A.parse().unwrap());
    let (mut tc_ws, _) = tokio_tungstenite::connect_async(tc_req).await.unwrap();
    line_join(&mut tc_ws, 5, "8.8.8.5:41641", json!({})).await;

    let tc_agents: Value = rig
        .app
        .auth_get("/api/tunnel-client/agents", &tc_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tc_agent_ids: BTreeSet<String> = tc_agents
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["agent_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        tc_agent_ids.contains(&us_a_id) && !tc_agent_ids.contains(&cn_a_id),
        "warn mode tunnel roster includes same-zone Unknown agent and excludes cross-zone: {tc_agent_ids:?}"
    );
    tc_ws
        .send(Message::Text(
            json!({
                "t": "rc:tunnel.open",
                "agent_id": us_a_id,
                "transport": "webrtc-dc-v1"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let tc_opened = recv_t(&mut tc_ws, "rc:tunnel.opened", wait)
        .await
        .expect("warn mode permits tunnel open between Unknown devices");
    let tc_session_id = tc_opened["session_id"].as_str().unwrap().to_owned();
    tc_ws
        .send(Message::Text(
            json!({
                "t": "rc:tunnel.tcp.request",
                "session_id": tc_session_id,
                "flow_id": 1,
                "dst_host": "127.0.0.1",
                "dst_port": 9000
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let forwarded = recv_t(&mut us_a, "rc:tunnel.tcp.forward", wait)
        .await
        .expect("warn mode permits tunnel TCP forward between Unknown devices");
    assert_eq!(forwarded["flow_id"], json!(1));

    // 4. 1-hop org-relay mint with Unknown roles in warn mode.
    set_mode(&rig.app, &rig.seeded, "on").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &us_r_id, true).await, 200);
    grant_relay(&rig.app, &rig.seeded, &us_r_node).await;
    relay_request(&mut us_a, &us_b_node).await;
    let _ = recv_t(&mut us_r, "rc:overlay.relay_serve", wait)
        .await
        .expect("warn mode permits 1-hop org-relay serve with Unknown roles");
    let _ = recv_t(&mut us_a, "rc:overlay.relay_session", wait)
        .await
        .expect("warn mode permits 1-hop org-relay session with Unknown roles");

    // 5. Cross-border line formation with Unknown relay roles in warn mode.
    let (cn_r_id, cn_r_tok) = enroll(&rig.app, &rig.seeded, "uw-cn-r").await;
    let mut cn_r = connect_from(&rig.app, &cn_r_tok, &["relay-server"], Some(CN_R)).await;
    assert_observed(&rig.app, &cn_r_id, Some(CN_R)).await;
    line_join(
        &mut cn_r,
        6,
        "223.6.6.6:41641",
        json!({"relay_backbone_ready": true}),
    )
    .await;
    assert_eq!(approve(&rig.app, &rig.seeded, &cn_r_id, true).await, 200);
    let edge_path = format!("/api/tenant/{tid}/agent/{us_r_id}/peer-relay-policy");
    let (st, _) = put(
        &rig.app,
        &edge_path,
        &admin,
        json!({
            "serve": true,
            "approved_backbone_edges": [{
                "relay_agent_id": cn_r_id,
                "endpoint": "10.88.0.2:3478",
                "cross_border": true
            }]
        }),
    )
    .await;
    assert_eq!(st, 200);
    let topo_after_line = meshharbor_mod_network::business_isolation::lines(
        net,
        meshharbor_mod_network::business_isolation::Mode::Enforce,
        tid_oid,
    )
    .await;
    assert!(
        !topo_after_line.lines.is_empty(),
        "warn mode permits cross-border line between Unknown-role relays"
    );

    // 6. Managed forward between Unknown-role agents in warn mode.
    report_listener(&rig.app, &mut us_a, &tid, &admin, &us_a_id, 22).await;
    let ip_b = net
        .overlay_nodes
        .base
        .find_by_id(ObjectId::parse_str(&us_b_node).unwrap())
        .await
        .unwrap()
        .overlay_ip;
    let mut fwd_spec = spec(&us_a_id, 15432);
    fwd_spec["dest_addr"] = json!(ip_b);
    fwd_spec["dest_port"] = json!(80);
    fwd_spec["sources"] = json!([format!("{ip_b}/32")]);
    let plan_path = format!("/api/tenant/{tid}/managed-forward/plan");
    let (_, plan) = mf_post(&rig.app, &plan_path, &admin, &fwd_spec).await;
    assert_eq!(
        verdict(&plan, "region"),
        "pass",
        "warn mode region check passes: {plan}"
    );
    assert_eq!(
        verdict(&plan, "source region"),
        "pass",
        "warn mode source region check passes: {plan}"
    );

    // 7. Role-read outage under `business_isolation = enforce` + `business_unknown_role = warn`:
    //    because `topo.servers` is derived from `current_approved_roles`, an unreadable
    //    role table under `business_isolation = enforce` must fail closed for new admissions
    //    (preventing unlinked same-zone servers from failing open) while preserving live
    //    netmaps, DERP tables, tunnel sessions, and managed forwards.
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, true);
    let (_, warn_outage_plan) = mf_post(&rig.app, &plan_path, &admin, &fwd_spec).await;
    assert_eq!(
        verdict(&warn_outage_plan, "region"),
        "unknown",
        "warn mode under enforce isolation returns unknown when role read fails: {warn_outage_plan}"
    );
    assert_eq!(
        verdict(&warn_outage_plan, "source region"),
        "unknown",
        "warn mode under enforce isolation returns unknown source region when role read fails: {warn_outage_plan}"
    );
    let us_a_ref = meshharbor_remote_control::models::NodeRef::Agent {
        agent_id: ObjectId::parse_str(&us_a_id).unwrap(),
    };
    let us_b_ref = meshharbor_remote_control::models::NodeRef::Agent {
        agent_id: ObjectId::parse_str(&us_b_id).unwrap(),
    };
    assert_eq!(
        meshharbor_mod_network::business_isolation::permit_refs(
            net,
            meshharbor_mod_network::business_isolation::Mode::Enforce,
            tid_oid,
            &us_a_ref,
            &us_b_ref,
        )
        .await,
        meshharbor_mod_network::business_isolation::Permit::Denied,
        "new admission permit_refs fails closed when role read fails under enforce isolation"
    );
    assert!(
        meshharbor_mod_network::business_isolation::refuses_parties(
            net,
            (tid_oid, &us_a_ref),
            (tid_oid, &us_b_ref),
            "test_warn_outage",
        )
        .await,
        "new admission refuses_parties fails closed when role read fails under enforce isolation"
    );
    assert!(
        !meshharbor_mod_network::tunnel::reconcile_tunnel_sessions(net, tid_oid).await,
        "reconcile_tunnel_sessions preserves live tunnel sessions on role read failure in warn mode"
    );
    let us_a_row = net
        .overlay_nodes
        .base
        .find_by_id(ObjectId::parse_str(&us_a_node).unwrap())
        .await
        .unwrap();
    assert!(
        !meshharbor_mod_network::overlay::refan_node(net, &us_a_row).await,
        "refan_node preserves live peer netmaps on role read failure in warn mode"
    );
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, false);
}

/// Mandatory Item 1 & 3 — under `app.business_isolation = enforce` and
/// `app.business_unknown_role = enforce`, a transient storage failure when
/// reading `current_approved_roles` must NOT be treated as mass revocation by
/// reconcile/teardown paths (zero `removes`, zero `rc:tunnel.terminate`, zero
/// `rc:overlay.relay_revoke`, unchanged `DerpAllowTable`, and no managed-forward
/// withdrawal), while new admissions fail closed, and post-revocation background
/// retry automatically completes once storage recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_role_enforce_transient_role_read_failure_preserves_live_state_and_retries() {
    use crate::managed_forward_tests::{post as mf_post, report_listener, spec, verdict};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let rig = Rig::up_with_unknown_role("iso-unknown-transient-err", "enforce", "enforce").await;
    let tid = rig.seeded.tenant_id.clone();
    let tid_oid = ObjectId::parse_str(&tid).unwrap();
    let admin = rig.seeded.admin.access_token.clone();
    let wait = Duration::from_secs(5);

    let policy_resp = rig
        .app
        .auth_post(&format!("/api/tenant/{tid}/tunnel-policy"), &admin)
        .json(&json!({
            "name": "allow-loopback-9000",
            "subjects": [{ "kind": "all_users" }],
            "targets": [{ "kind": "all_agents" }],
            "allowlist": [{
                "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
                "port_range": { "low": 9000, "high": 9999 }
            }],
            "max_concurrent_flows": 32,
            "max_bytes_per_session": 1048576
        }))
        .send()
        .await
        .unwrap();
    assert!(policy_resp.status().is_success());

    let (us_a_id, us_a_tok) = enroll(&rig.app, &rig.seeded, "te-us-a").await;
    let (us_b_id, us_b_tok) = enroll(&rig.app, &rig.seeded, "te-us-b").await;
    let (us_r_id, us_r_tok) = enroll(&rig.app, &rig.seeded, "te-us-r").await;

    let mut us_a = connect_from(&rig.app, &us_a_tok, &["managed-forward"], Some(US_A)).await;
    let mut us_b = connect_from(&rig.app, &us_b_tok, &[], Some(US_B)).await;
    let mut us_r = connect_from(&rig.app, &us_r_tok, &["relay-server"], Some(US_R)).await;
    assert_observed(&rig.app, &us_a_id, Some(US_A)).await;
    assert_observed(&rig.app, &us_b_id, Some(US_B)).await;
    assert_observed(&rig.app, &us_r_id, Some(US_R)).await;

    let et: Value = rig
        .app
        .auth_post(
            &format!("/api/tenant/{tid}/tunnel-client/enroll-token"),
            &admin,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled_tc: Value = rig
        .app
        .client
        .post(rig.app.url("/api/tunnel-client/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"],
            "machine_id": "te-tc-us",
            "machine_name": "te-tc-us",
            "os": "linux",
            "client_version": "0.4.151"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tc_id = enrolled_tc["tunnel_client_id"].as_str().unwrap().to_owned();
    let tc_tok = enrolled_tc["tunnel_client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let tc_url = format!(
        "ws://{}/ws?token={}&role=tunnel-client",
        rig.app.addr,
        tc_tok
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let mut tc_req = tc_url.as_str().into_client_request().unwrap();
    tc_req
        .headers_mut()
        .insert("x-forwarded-for", US_A.parse().unwrap());
    let (mut tc_ws, _) = tokio_tungstenite::connect_async(tc_req).await.unwrap();

    // Approve all devices as Client and join overlay.
    rig.set_device_role("agent", &us_a_id, "client").await;
    rig.set_device_role("agent", &us_b_id, "client").await;
    rig.set_device_role("agent", &us_r_id, "client").await;
    rig.set_device_role("tunnel-client", &tc_id, "client").await;

    line_join(&mut us_a, 1, "8.8.8.1:41641", json!({})).await;
    let us_a_node = rig.node("te-us-a").await;
    line_join(&mut us_b, 2, "8.8.8.2:41641", json!({})).await;
    let us_b_node = rig.node("te-us-b").await;
    line_join(&mut us_r, 4, "1.1.1.1:41641", json!({})).await;
    let us_r_node = rig.node("te-us-r").await;
    line_join(&mut tc_ws, 5, "8.8.8.5:41641", json!({})).await;

    let net = rig.app.state.network();
    let tc_oid = ObjectId::parse_str(&tc_id).unwrap();
    let tc_node = meshharbor_mod_network::overlay::current_node(
        net,
        meshharbor_mod_network::overlay::NodeIdentity::TunnelClient(tc_oid),
    )
    .await
    .unwrap()
    .id
    .unwrap()
    .to_hex();

    set_mode(&rig.app, &rig.seeded, "on").await;
    assert_eq!(approve(&rig.app, &rig.seeded, &us_r_id, true).await, 200);
    grant_relay(&rig.app, &rig.seeded, &us_r_node).await;

    // Drain initial join deltas.
    let _ = deltas(&mut us_a, Duration::from_millis(300)).await;
    let _ = deltas(&mut us_b, Duration::from_millis(300)).await;
    let _ = deltas(&mut tc_ws, Duration::from_millis(300)).await;

    let net_id = net
        .overlay_networks
        .get_or_create(tid_oid)
        .await
        .unwrap()
        .id
        .unwrap();
    assert!(meshharbor_mod_network::derp_acl::rebuild(net, tid_oid, net_id).await);
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[1u8; 32], &[2u8; 32])
    );
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[5u8; 32], &[1u8; 32])
    );

    // Open tunnel session tc_ws -> us_a.
    tc_ws
        .send(Message::Text(
            json!({
                "t": "rc:tunnel.open",
                "agent_id": us_a_id,
                "transport": "webrtc-dc-v1"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let tc_opened = recv_t(&mut tc_ws, "rc:tunnel.opened", wait).await.unwrap();
    let tc_session_id = tc_opened["session_id"].as_str().unwrap().to_owned();

    // Mint 1-hop org-relay session us_a <-> us_b via us_r.
    let us_a_oid = ObjectId::parse_str(&us_a_node).unwrap();
    let us_b_oid = ObjectId::parse_str(&us_b_node).unwrap();
    let pair = meshharbor_mod_network::overlay::pair_key(us_a_oid, us_b_oid);
    relay_request(&mut us_a, &us_b_node).await;
    let _ = recv_t(&mut us_r, "rc:overlay.relay_serve", wait)
        .await
        .unwrap();
    let _ = recv_t(&mut us_a, "rc:overlay.relay_session", wait)
        .await
        .unwrap();
    let _ = recv_t(&mut us_b, "rc:overlay.relay_session", wait)
        .await
        .unwrap();
    assert!(net.org_relay.active_session(&pair).is_some());

    // Create managed forward on us_a admitting tc_ip -> ip_b.
    report_listener(&rig.app, &mut us_a, &tid, &admin, &us_a_id, 22).await;
    let ip_b = net
        .overlay_nodes
        .base
        .find_by_id(us_b_oid)
        .await
        .unwrap()
        .overlay_ip;
    let ip_tc = net
        .overlay_nodes
        .base
        .find_by_id(ObjectId::parse_str(&tc_node).unwrap())
        .await
        .unwrap()
        .overlay_ip;
    let mut fwd_spec = spec(&us_a_id, 15432);
    fwd_spec["dest_addr"] = json!(ip_b);
    fwd_spec["dest_port"] = json!(80);
    fwd_spec["sources"] = json!([format!("{ip_tc}/32")]);
    let _ = recv_t(&mut us_a, "rc:forward.set", Duration::from_millis(300)).await;
    let (create_status, created_fwd) = mf_post(
        &rig.app,
        &format!("/api/tenant/{tid}/managed-forward"),
        &admin,
        &fwd_spec,
    )
    .await;
    assert_eq!(create_status, 201, "{created_fwd}");
    let init_fwd = recv_t(&mut us_a, "rc:forward.set", wait).await.unwrap();
    assert_eq!(init_fwd["forwards"].as_array().unwrap().len(), 1);

    // ── Inject simulated transient role-read storage failure ──
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, true);

    // New managed-forward plan during outage fails closed with Verdict::Unknown.
    let plan_path = format!("/api/tenant/{tid}/managed-forward/plan");
    let (_, outage_plan) = mf_post(&rig.app, &plan_path, &admin, &fwd_spec).await;
    assert_eq!(verdict(&outage_plan, "region"), "unknown", "{outage_plan}");
    assert_eq!(
        verdict(&outage_plan, "source region"),
        "unknown",
        "{outage_plan}"
    );

    // 1. Direct reconcile calls during outage must return false and preserve ALL live state.
    assert!(
        !meshharbor_mod_network::org_relay::recheck_zones(
            net,
            ObjectId::parse_str(&us_a_id).unwrap(),
            "test_role_read_outage",
        )
        .await,
        "org_relay::recheck_zones must return false on role read failure"
    );
    assert!(
        !meshharbor_mod_network::derp_acl::rebuild(net, tid_oid, net_id).await,
        "derp_acl::rebuild must return false on role read failure"
    );
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[1u8; 32], &[2u8; 32]),
        "DERP table must remain intact on role read failure"
    );
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[5u8; 32], &[1u8; 32]),
        "DERP table must remain intact for tc_us on role read failure"
    );
    assert!(
        !meshharbor_mod_network::tunnel::reconcile_tunnel_sessions(net, tid_oid).await,
        "reconcile_tunnel_sessions must return false on role read failure"
    );
    assert!(
        !meshharbor_mod_network::managed_forward::reconcile_tenant_forwards(net, tid_oid).await,
        "reconcile_tenant_forwards must return false on role read failure"
    );
    let us_a_row = net.overlay_nodes.base.find_by_id(us_a_oid).await.unwrap();
    assert!(
        !meshharbor_mod_network::overlay::refan_node(net, &us_a_row).await,
        "refan_node must return false on role read failure"
    );

    // Verify zero removes, zero TunnelTerminate, zero forward withdrawals, and active org-relay kept during outage.
    let (_, rm_b_during) = deltas(&mut us_b, Duration::from_millis(300)).await;
    assert!(
        rm_b_during.is_empty(),
        "role read failure must NOT emit netmap removes to us_b: {rm_b_during:?}"
    );
    assert!(
        recv_t(
            &mut tc_ws,
            "rc:tunnel.terminate",
            Duration::from_millis(200)
        )
        .await
        .is_none(),
        "role read failure must NOT emit TunnelTerminate"
    );
    assert!(
        recv_t(&mut us_a, "rc:forward.set", Duration::from_millis(200))
            .await
            .is_none(),
        "role read failure must NOT push a managed-forward withdrawal"
    );
    assert!(
        net.org_relay.active_session(&pair).is_some(),
        "role read failure must NOT tear down active org-relay session"
    );

    // 1b. Re-joining (`rc:overlay.join`) on `us_a` during `roles_read_failed` must NOT
    //     emit a degraded empty `rc:overlay.netmap` (which would wipe `us_a`'s established
    //     peers) and must NOT emit `removes` to `us_b`; once role reads recover, the
    //     scheduled join retry delivers the full netmap to `us_a`.
    us_a.send(Message::Text(
        json!({
            "t": "rc:overlay.join",
            "wg_public_key": BASE64.encode([1u8; 32]),
            "mtu": 1280,
            "key_epoch": 0,
            "endpoints": ["8.8.8.1:41641"],
            "supports_derp": true,
            "supports_org_relay": true,
            "supports_server_relay_strategy": true,
            "relay_port": 3478,
            "org_primary": true,
            "supports_forced_derp": true,
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    assert!(
        recv_t(&mut us_a, "rc:overlay.netmap", Duration::from_millis(250))
            .await
            .is_none(),
        "handle_overlay_join during role read failure must withhold degraded empty full netmap"
    );
    let (_, rm_b_on_rejoin) = deltas(&mut us_b, Duration::from_millis(150)).await;
    assert!(
        rm_b_on_rejoin.is_empty(),
        "handle_overlay_join during role read failure must not emit removes to us_b: {rm_b_on_rejoin:?}"
    );
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, false);
    let recovered_netmap = recv_t(&mut us_a, "rc:overlay.netmap", wait)
        .await
        .expect("scheduled join netmap retry delivers full netmap to us_a once role read recovers");
    assert!(
        peer_ids(&recovered_netmap).contains(&us_b_node),
        "recovered join netmap must include healthy peer us_b: {recovered_netmap}"
    );
    let _ = deltas(&mut us_b, Duration::from_millis(200)).await;
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, true);

    // 2. Superseding a failed `unknown` approval with a `client` re-approval before retry
    //    fires must cancel the stale `unknown` retry and keep tc_us's session + DERP alive.
    let tc_sid_oid = ObjectId::parse_str(&tc_session_id).unwrap();
    rig.set_device_role("tunnel-client", &tc_id, "unknown")
        .await;
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[5u8; 32], &[1u8; 32]),
        "during role-read outage, DERP entry for tc_us is preserved until storage recovers"
    );
    assert!(
        net.tunnel_clients_by_session.contains_key(&tc_sid_oid),
        "during role-read outage, tunnel session for tc_us is preserved until storage recovers"
    );
    rig.set_device_role("tunnel-client", &tc_id, "client").await;
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, false);
    assert!(
        recv_t(
            &mut tc_ws,
            "rc:tunnel.terminate",
            Duration::from_millis(350)
        )
        .await
        .is_none(),
        "superseded unknown -> client approval must not terminate tc_us on retry"
    );
    assert!(
        net.tunnel_clients_by_session.contains_key(&tc_sid_oid),
        "superseded unknown -> client approval keeps tunnel session in map"
    );
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[5u8; 32], &[1u8; 32]),
        "superseded unknown -> client approval keeps tc_us permitted in DERP"
    );

    // 3. Revoke tc_us to "unknown" while role reads are failing again:
    //    `approve` writes the revocation to DB, runs the first pass (which sees
    //    the read failure and preserves live DERP/tunnel/forward state during the
    //    outage), and spawns the background retry task.
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, true);
    rig.set_device_role("tunnel-client", &tc_id, "unknown")
        .await;
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[5u8; 32], &[1u8; 32]),
        "before storage recovers, tc_us DERP entry is still preserved"
    );
    assert!(
        net.tunnel_clients_by_session.contains_key(&tc_sid_oid),
        "before storage recovers, tc_us tunnel session is still preserved"
    );
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[1u8; 32], &[2u8; 32]),
        "unaffected pair us_a <-> us_b stays permitted in DERP during read outage"
    );
    assert!(
        net.org_relay.active_session(&pair).is_some(),
        "unaffected org-relay session us_a <-> us_b stays alive during read outage"
    );

    // Now clear the simulated storage failure so the spawned retry task succeeds.
    meshharbor_core::business_authority::set_test_force_role_read_fail(tid_oid, false);

    let tc_term = recv_t(&mut tc_ws, "rc:tunnel.terminate", wait)
        .await
        .expect("background retry terminates revoked tunnel-client session once storage recovers");
    assert_eq!(tc_term["session_id"], json!(tc_session_id));
    let _ = recv_t(&mut us_a, "rc:tunnel.terminate", wait)
        .await
        .expect("background retry terminates target agent side once storage recovers");
    let withdrawn = recv_t(&mut us_a, "rc:forward.set", wait)
        .await
        .expect("background retry withdraws managed forward admitting revoked tc_us");
    assert!(withdrawn["forwards"].as_array().unwrap().is_empty());
    let (_, rm_a_after) = deltas(&mut us_a, Duration::from_millis(1200)).await;
    assert!(
        rm_a_after.contains(&tc_node),
        "background retry fans remove for revoked tc_node to us_a: {rm_a_after:?}"
    );
    assert!(
        !net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[5u8; 32], &[1u8; 32]),
        "background retry rebuilds DERP table denying revoked tc_us"
    );
    assert!(
        net.derp_acl
            .get(&net_id)
            .unwrap()
            .permits(&[1u8; 32], &[2u8; 32]),
        "healthy approved pair us_a <-> us_b remains permitted in DERP"
    );
    assert!(
        net.org_relay.active_session(&pair).is_some(),
        "healthy approved org-relay session us_a <-> us_b remains active"
    );
}

/// Full legacy member runtimes own discovery, WG, carrier health and retries.
/// The enclosing disposable network namespace supplies only the ingress/exit
/// public aliases; the middle's advertised member endpoint is unreachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(target_os = "linux")]
async fn legacy_three_relay_runtime_recovers_automatically_after_middle_restart() {
    use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
    use meshharbord::relay_server::backbone_test_support::{
        ConnectionType, NativeRelay, Netstack, NetstackHandle, OverlayEvent, OverlayRuntime,
        OverlayView, RelayProbeUpdates, TunFactory, TunIo, WgKeypair, prober,
    };
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
        sync::{
            Arc, Mutex as StdMutex,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::{Mutex, mpsc, watch},
        task::JoinHandle,
    };

    struct Tasks(Vec<JoinHandle<()>>);
    impl Drop for Tasks {
        fn drop(&mut self) {
            for task in &self.0 {
                task.abort();
            }
        }
    }
    struct TraceState {
        started: std::time::Instant,
        inner: StdMutex<(Vec<Value>, std::collections::HashMap<&'static str, String>)>,
    }
    impl TraceState {
        fn record(&self, role: &'static str, event: &str, data: Value) {
            let mut inner = self.inner.lock().unwrap();
            let seq = inner.0.len() + 1;
            inner.0.push(
                json!({"seq":seq,"relative_ms":self.started.elapsed().as_millis(),
                "context_role":role,"event":event,"data":data}),
            );
        }
        fn bind(&self, role: &'static str, node: &str) {
            self.inner.lock().unwrap().1.insert(role, node.into());
        }
        fn phase(&self, name: &str) {
            self.record("test", "phase", json!({"phase":name}));
        }
        fn wire(&self, role: &'static str, message: &ServerMsg) {
            // Full serialization is ephemeral. Only the explicit identity
            // whitelist below enters the retained trace or its printed log.
            let raw = serde_json::to_value(message).unwrap();
            let tag = raw["t"].as_str().unwrap_or("");
            if !(tag.starts_with("rc:overlay.path_trial_")
                || matches!(
                    tag,
                    "rc:overlay.relay_grant"
                        | "rc:overlay.relay_session"
                        | "rc:overlay.relay_serve"
                        | "rc:overlay.relay_revoke"
                        | "rc:overlay.relay_bridge_serve"
                        | "rc:overlay.relay_bridge_revoke"
                ))
            {
                return;
            }
            let mut safe = serde_json::Map::new();
            for key in [
                "t",
                "vni",
                "generation",
                "peer_node_id",
                "relay_node_id",
                "trial_id",
            ] {
                if let Some(value) = raw.get(key) {
                    safe.insert(key.into(), value.clone());
                }
            }
            for (nested, keys) in [
                (
                    "scope",
                    &["relay_node_id", "generation", "peer_node_id"][..],
                ),
                (
                    "bridge",
                    &[
                        "trial_id",
                        "generation",
                        "local_vni",
                        "local_generation",
                        "remote_vni",
                        "remote_generation",
                        "source_agent_id",
                        "target_agent_id",
                    ][..],
                ),
            ] {
                if let Some(object) = raw.get(nested).and_then(Value::as_object) {
                    let mut fields = serde_json::Map::new();
                    for key in keys {
                        if let Some(value) = object.get(*key) {
                            fields.insert((*key).into(), value.clone());
                        }
                    }
                    safe.insert(nested.into(), Value::Object(fields));
                }
            }
            self.record(role, "received_wire", Value::Object(safe));
        }
    }
    struct TraceGuard(Arc<TraceState>);
    impl Drop for TraceGuard {
        fn drop(&mut self) {
            let inner = self.0.inner.lock().unwrap();
            for event in &inner.0 {
                let mut safe = event.clone();
                let role = event["context_role"].as_str().unwrap();
                safe["context_node_id"] =
                    inner.1.get(role).map(|id| json!(id)).unwrap_or(Value::Null);
                println!("X4_LEGACY_TRACE {safe}");
            }
        }
    }
    struct Member {
        handle: NetstackHandle,
        view: watch::Receiver<OverlayView>,
        requests: Arc<StdMutex<Vec<ObjectId>>>,
        join_caps: Arc<StdMutex<Vec<Value>>>,
        probes: Arc<StdMutex<Vec<(ObjectId, bool, Option<u32>)>>>,
        metadata_seen: Arc<AtomicBool>,
        forbidden_carrier: Arc<AtomicBool>,
        runtime: usize,
        pump: usize,
        _events: mpsc::Sender<OverlayEvent>,
    }
    impl Member {
        fn healthy(&self, peer: &str) -> bool {
            self.view.borrow().peers.iter().any(|p| {
                p.node_id == peer
                    && p.connection == ConnectionType::Relay
                    && p.relay_kind.as_deref() == Some("org")
                    && !p.stalled
                    && p.debug.as_ref().is_some_and(|d| d.hs_done)
            })
        }
        fn requests_for(&self, peer: ObjectId) -> usize {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|p| **p == peer)
                .count()
        }
        fn assert_live(&self, tasks: &Tasks) {
            assert!(
                !tasks.0[self.runtime].is_finished(),
                "member runtime stopped"
            );
            assert!(
                !tasks.0[self.pump].is_finished(),
                "member control pump stopped"
            );
            assert!(
                !self.forbidden_carrier.load(Ordering::SeqCst),
                "backbone-only peer used Direct/TURN/DERP"
            );
        }
    }
    async fn member(
        mut ws: Ws,
        agent: String,
        other_agent: ObjectId,
        endpoint: String,
        key: WgKeypair,
        tasks: &mut Tasks,
        context: (&'static str, Arc<TraceState>),
    ) -> Member {
        let (role, trace) = context;
        let mainland = endpoint.starts_with("223.");
        let (out, mut outbound) = mpsc::channel::<ClientMsg>(256);
        let (events, event_rx) = mpsc::channel(256);
        let (handle_tx, mut handle_rx) = mpsc::unbounded_channel();
        let factory: TunFactory = Box::new(move |ip, nm, mtu| {
            let stack = Netstack::start(ip, u32::from(nm).count_ones() as u8, mtu);
            handle_tx
                .send(stack.handle)
                .map_err(|_| io::Error::other("member handle receiver gone"))?;
            Ok(stack.tun as Arc<dyn TunIo>)
        });
        let (view_tx, view) = watch::channel(OverlayView::default());
        let runtime = OverlayRuntime::new_relay(key, out, factory, 1280)
            .with_org_primary(true)
            .with_backbone_enabled(true)
            .with_netstack_socks(Some(0))
            .with_peer_view(view_tx);
        let runtime_index = tasks.0.len();
        tasks
            .0
            .push(tokio::spawn(runtime.run(event_rx, vec![endpoint])));
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let join_caps = Arc::new(StdMutex::new(Vec::new()));
        let probes = Arc::new(StdMutex::new(Vec::new()));
        let metadata_seen = Arc::new(AtomicBool::new(false));
        let expected_peer = Arc::new(StdMutex::new(None::<ObjectId>));
        let pump_index = tasks.0.len();
        let pump_events = events.clone();
        let pump_requests = requests.clone();
        let seen = metadata_seen.clone();
        let caps = join_caps.clone();
        let reported = probes.clone();
        tasks.0.push(tokio::spawn(async move {
            let mut heartbeat=tokio::time::interval(Duration::from_secs(25));heartbeat.tick().await;
            loop { tokio::select! {
                _=heartbeat.tick()=>ws.send(Message::Ping(Vec::new().into())).await.unwrap(),
                message=outbound.recv()=>{
                    let message=message.expect("member runtime control remains live");
                    if let ClientMsg::OverlayJoin{supports_org_relay,supports_backbone_only_v1,
                        supports_path_backbone_v1,org_primary,endpoints,..}=&message {
                        caps.lock().unwrap().push(json!({"org_relay":supports_org_relay,
                            "backbone_only":supports_backbone_only_v1,"path_backbone":supports_path_backbone_v1,
                            "primary":org_primary}));
                        assert!(*supports_org_relay&&*supports_backbone_only_v1&&*supports_path_backbone_v1
                            &&*org_primary==Some(true),"three-relay fixture needs primary/org/backbone capabilities and MESHHARBORD_PATH_TRIAL=1");
                        assert!(!endpoints.iter().any(|e|e.starts_with(if mainland {"1.1.1.1:"}else{"223.6.6.6:"})),
                            "mixed-zone fixture NIC aliases were advertised: run with MESHHARBORD_OVERLAY_DIRECT=0; never bypass GEO-04");
                    }
                    if let ClientMsg::OverlayRelayRequest{peer_node_id,..}
                        |ClientMsg::OverlayOrgRelayFallbackRequest{peer_node_id,..}=&message {
                        pump_requests.lock().unwrap().push(*peer_node_id);
                        let kind=if matches!(&message,ClientMsg::OverlayRelayRequest{..}) {
                            "OverlayRelayRequest"
                        }else{"OverlayOrgRelayFallbackRequest"};
                        trace.record(role,"member_request",json!({"kind":kind,"peer_node_id":peer_node_id.to_hex()}));
                    }
                    if let ClientMsg::OverlayRelayProbe{relay_node_id,reachable,rtt_ms,..}=&message {
                        reported.lock().unwrap().push((*relay_node_id,*reachable,*rtt_ms));
                    }
                    ws.send(Message::Text(serde_json::to_string(&message).unwrap().into())).await.unwrap();
                }
                message=ws.next()=>match message {
                    Some(Ok(Message::Text(text)))=>{
                        let message:ServerMsg=serde_json::from_str(&text).expect("real member server frame");
                        trace.wire(role,&message);
                        let peers=match &message {
                            ServerMsg::OverlayNetmap{peers,..}=>peers.as_slice(),
                            ServerMsg::OverlayNetmapDelta{upserts,..}=>upserts.as_slice(),
                            _=>&[],
                        };
                        for peer in peers.iter().filter(|p|p.agent_id==Some(other_agent)) {
                            assert!(peer.backbone_only,"authoritative cross-zone peer must be backbone-only");
                            *expected_peer.lock().unwrap()=Some(peer.node_id);
                            seen.store(true,Ordering::SeqCst);
                        }
                        if let ServerMsg::OverlayRelayGrant{peer_node_id,..}|ServerMsg::OverlayForceDerp{peer_node_id,..}=&message {
                            assert_ne!(Some(*peer_node_id),*expected_peer.lock().unwrap(),"server offered forbidden fallback for cross-zone pair");
                        }
                        let _=meshharbord::overlay::intercept(&pump_events,message,true,&agent);
                    }
                    Some(Ok(Message::Ping(data)))=>ws.send(Message::Pong(data)).await.unwrap(),
                    Some(Ok(Message::Pong(_)))=>{},
                    other=>panic!("member control ended: {other:?}"),
                }
            }}
        }));
        let forbidden_carrier = Arc::new(AtomicBool::new(false));
        let violation = forbidden_carrier.clone();
        let mut observed = view.clone();
        let other = other_agent.to_hex();
        tasks.0.push(tokio::spawn(async move {
            while observed.changed().await.is_ok() {
                let snapshot = observed.borrow().clone();
                for peer in snapshot
                    .peers
                    .iter()
                    .filter(|p| p.agent_id.as_deref() == Some(other.as_str()))
                {
                    if matches!(
                        peer.connection,
                        ConnectionType::Direct | ConnectionType::Tunnel
                    ) || (peer.connection == ConnectionType::Relay
                        && peer.relay_kind.as_deref() != Some("org"))
                    {
                        violation.store(true, Ordering::SeqCst);
                    }
                }
            }
        }));
        let handle = tokio::time::timeout(Duration::from_secs(20), handle_rx.recv())
            .await
            .expect("runtime initial netmap/TunFactory")
            .expect("netstack handle");
        Member {
            handle,
            view,
            requests,
            join_caps,
            probes,
            metadata_seen,
            forbidden_carrier,
            runtime: runtime_index,
            pump: pump_index,
            _events: events,
        }
    }
    async fn relay_probe_targets(
        message: &ServerMsg,
        native: &Arc<Mutex<NativeRelay>>,
        target: Option<&Arc<Mutex<NativeRelay>>>,
        context: (&'static str, &TraceState),
        targets: &watch::Sender<Vec<prober::Target>>,
        updates: &mut RelayProbeUpdates,
    ) {
        let ServerMsg::OverlayNetmap { network, peers, .. } = message else {
            return;
        };
        let policy = if let Some(target) = target {
            let next = target.lock().await;
            Some(native.lock().await.policy_to(&next))
        } else {
            None
        };
        let accepted = prober::targets_from_wire(
            &network.relay_probe_targets,
            &network.backbone_probe_targets,
            policy.as_ref(),
        );
        let safe = |offered: &[meshharbor_remote_control::signaling::RelayProbeTargetWire]| {
            offered
                .iter()
                .map(|t| json!({"relay_node_id":t.relay_node_id.to_hex(),"endpoints":t.endpoints}))
                .collect::<Vec<_>>()
        };
        context.1.record(context.0,"received_probe_targets",json!({
            "public":safe(&network.relay_probe_targets),"backbone":safe(&network.backbone_probe_targets),
            "accepted":accepted.iter().map(|t|json!({"relay_node_id":t.relay_node_id.to_hex(),
                "endpoints":t.endpoints.iter().map(ToString::to_string).collect::<Vec<_>>(),"via":t.via})).collect::<Vec<_>>()}));
        // Production runtime replaces this watch on every full netmap,
        // including identical values. The production prober owns round timing.
        updates.reset_full(&accepted, peers, network.auth_revision);
        targets.send_replace(accepted);
    }
    async fn relay_pump(
        mut ws: Ws,
        native: Arc<Mutex<NativeRelay>>,
        target: Option<Arc<Mutex<NativeRelay>>>,
        context: (&'static str, Arc<TraceState>),
        initial: ServerMsg,
        probe_control: (watch::Sender<Vec<prober::Target>>, prober::ReactiveProbes),
        mut outcomes: mpsc::Receiver<Vec<prober::Outcome>>,
    ) {
        let (role, trace) = context;
        let (targets, reactive) = probe_control;
        let mut updates = RelayProbeUpdates::default();
        relay_probe_targets(
            &initial,
            &native,
            target.as_ref(),
            (role, &trace),
            &targets,
            &mut updates,
        )
        .await;
        // The production agent initiates pings; the server deliberately never
        // does. A silent fixture otherwise loses its WS receive-liveness lease.
        let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
        heartbeat.tick().await;
        loop {
            let frame = tokio::select! {
                _=heartbeat.tick()=>{ws.send(Message::Ping(Vec::new().into())).await.unwrap();continue;}
                round=outcomes.recv()=>{
                    let Some(round)=round else {break;};
                    let mut relay_ids=round.iter().map(|o|o.relay_node_id.to_hex()).collect::<Vec<_>>();
                    relay_ids.sort();relay_ids.dedup();
                    trace.record(role,"measured_probe_round",json!({"relay_node_ids":relay_ids,"outcome_count":round.len()}));
                    for outcome in round {
                        let rtt_ms=outcome.rtt.map(|d|u32::try_from(d.as_millis()).unwrap_or(u32::MAX));
                        trace.record(role,"measured_probe",json!({"relay_node_id":outcome.relay_node_id.to_hex(),
                            "endpoint":outcome.endpoint.to_string(),"reachable":outcome.rtt.is_some(),"rtt_ms":rtt_ms}));
                        let report=ClientMsg::OverlayRelayProbe{relay_node_id:outcome.relay_node_id,
                            endpoint:outcome.endpoint.to_string(),reachable:outcome.rtt.is_some(),rtt_ms};
                        ws.send(Message::Text(serde_json::to_string(&report).unwrap().into())).await.unwrap();
                    }
                    continue;
                }
                frame=ws.next()=>frame,
            };
            let Some(frame) = frame else {
                break;
            };
            match frame.expect("relay control frame") {
                Message::Text(text) => {
                    let message: ServerMsg =
                        serde_json::from_str(&text).expect("relay server message");
                    trace.wire(role, &message);
                    relay_probe_targets(
                        &message,
                        &native,
                        target.as_ref(),
                        (role, &trace),
                        &targets,
                        &mut updates,
                    )
                    .await;
                    match &message {
                        ServerMsg::OverlayNetmapDelta {
                            epoch,
                            auth_revision,
                            upserts,
                            removes,
                        } => {
                            for (id, serial) in
                                updates.delta(*epoch, *auth_revision, upserts, removes)
                            {
                                let queued = reactive.request(id, serial);
                                trace.record(
                                    role,
                                    "accepted_probe_hint",
                                    json!({"relay_node_id":id.to_hex(),
                                    "local_event_serial":serial,"queued":queued}),
                                );
                            }
                        }
                        ServerMsg::OverlayRelayServe { .. }
                        | ServerMsg::OverlayRelayRevoke { .. }
                        | ServerMsg::OverlayRelayBridgeServe { .. }
                        | ServerMsg::OverlayRelayBridgeRevoke { .. } => {
                            let policy =
                                if matches!(&message, ServerMsg::OverlayRelayBridgeServe { .. }) {
                                    let next = target
                                        .as_ref()
                                        .expect("bridge requires next relay")
                                        .lock()
                                        .await;
                                    Some(native.lock().await.policy_to(&next))
                                } else {
                                    None
                                };
                            native.lock().await.serve(message, policy);
                        }
                        // These relay fixtures serve production listener/bridge
                        // control only; their member metadata is not installed.
                        _ => {}
                    }
                }
                Message::Ping(data) => ws.send(Message::Pong(data)).await.unwrap(),
                Message::Pong(_) => {}
                other => panic!("relay control ended: {other:?}"),
            }
        }
    }
    fn start_relay(
        ws: Ws,
        native: Arc<Mutex<NativeRelay>>,
        target: Option<Arc<Mutex<NativeRelay>>>,
        context: (&'static str, Arc<TraceState>),
        initial: ServerMsg,
        tasks: &mut Tasks,
    ) -> usize {
        let (targets, target_rx) = watch::channel(Vec::<prober::Target>::new());
        let (outcomes, outcome_rx) = mpsc::channel(8);
        let (prober_task, reactive) = prober::spawn_reactive(target_rx, outcomes);
        tasks.0.push(prober_task);
        let index = tasks.0.len();
        tasks.0.push(tokio::spawn(relay_pump(
            ws,
            native,
            target,
            context,
            initial,
            (targets, reactive),
            outcome_rx,
        )));
        index
    }
    async fn tcp64(
        from: &NetstackHandle,
        to: &NetstackHandle,
        target: Ipv4Addr,
        port: u16,
    ) -> io::Result<()> {
        fn stage(
            error: io::Error,
            side: &str,
            sequence: usize,
            operation: &str,
            port: u16,
        ) -> io::Error {
            io::Error::new(
                error.kind(),
                format!("TCP echo port={port} {side} completed={sequence}/64 {operation}: {error}"),
            )
        }
        let mut listener = to
            .listen(port)
            .await
            .map_err(|e| stage(e, "server", 0, "listen", port))?;
        let echo = async {
            let mut stream = listener
                .accept()
                .await
                .ok_or_else(|| io::Error::other("echo listener closed"))?;
            for sequence in 0..64 {
                let mut bytes = [0; 512];
                stream
                    .read_exact(&mut bytes)
                    .await
                    .map_err(|e| stage(e, "server", sequence, "read request", port))?;
                stream
                    .write_all(&bytes)
                    .await
                    .map_err(|e| stage(e, "server", sequence, "write echo", port))?;
            }
            // NsTcpStream writes enqueue; dropping the stream aborts its
            // smoltcp socket. Keep this owner alive until the client has read
            // the 64th echo and half-closes, rather than dropping queued data.
            let mut extra = [0; 1];
            if stream
                .read(&mut extra)
                .await
                .map_err(|e| stage(e, "server", 64, "await client EOF", port))?
                != 0
            {
                return Err(io::Error::other(
                    "TCP echo server received more than 64*512 bytes",
                ));
            }
            stream
                .shutdown()
                .await
                .map_err(|e| stage(e, "server", 64, "shutdown", port))
        };
        let send = async {
            let mut stream = from
                .connect(SocketAddr::from((target, port)))
                .await
                .map_err(|e| stage(e, "client", 0, "connect", port))?;
            for sequence in 0..64u8 {
                let bytes = [sequence; 512];
                stream.write_all(&bytes).await.map_err(|e| {
                    stage(e, "client", usize::from(sequence), "write request", port)
                })?;
                let mut reply = [0; 512];
                stream
                    .read_exact(&mut reply)
                    .await
                    .map_err(|e| stage(e, "client", usize::from(sequence), "read echo", port))?;
                if reply != bytes {
                    return Err(io::Error::other(format!(
                        "TCP echo port={port} sequence={sequence} payload mismatch"
                    )));
                }
            }
            stream
                .shutdown()
                .await
                .map_err(|e| stage(e, "client", 64, "shutdown after all replies", port))?;
            let mut extra = [0; 1];
            if stream
                .read(&mut extra)
                .await
                .map_err(|e| stage(e, "client", 64, "await server EOF", port))?
                != 0
            {
                return Err(io::Error::other(
                    "TCP echo client received more than 64*512 bytes",
                ));
            }
            Ok(())
        };
        tokio::try_join!(echo, send)?;
        Ok(())
    }

    // Cover the unchanged 240-second periodic fallback plus ordinary setup,
    // automatic member retry and resource teardown. Events may react earlier.
    tokio::time::timeout(Duration::from_secs(480),async {
        let slug="iso-legacy-runtime-restart";let rig=Rig::up(slug,"enforce").await;
        // Declared after Rig: both success and panic unwinding print the
        // sanitized trace before TestApp's database teardown runs.
        let trace=TraceGuard(Arc::new(TraceState{started:std::time::Instant::now(),inner:StdMutex::new((Vec::new(),std::collections::HashMap::new()))}));
        let mut tasks=Tasks(Vec::new());let mut native=Vec::new();let mut relay_ws=Vec::new();let mut relay_maps=Vec::new();
        let mut agents=Vec::new();let mut nodes=Vec::new();let mut tokens=Vec::new();
        for index in 0..3u8 {
            let relay=NativeRelay::start().await.unwrap();let port=relay.port();
            let name=format!("{slug}-r{index}");let (agent,token)=enroll(&rig.app,&rig.seeded,&name).await;
            let origin=if index==2 {US_R}else{CN_R};
            let mut ws=connect_from(&rig.app,&token,&["relay-server"],Some(origin)).await;
            assert_observed(&rig.app,&agent,Some(origin)).await;
            let public=["223.6.6.6","223.6.6.7","1.1.1.1"][usize::from(index)];
            let initial=line_join(&mut ws,10+index,&format!("{public}:{port}"),json!({"relay_backbone_ready":index<2,"relay_port":port})).await;
            assert_eq!(approve(&rig.app,&rig.seeded,&agent,true).await,200);
            let node=rig.node(&name).await;grant_relay(&rig.app,&rig.seeded,&node).await;
            trace.0.bind(["relay0","relay1","relay2"][usize::from(index)],&node);
            native.push(Arc::new(Mutex::new(relay)));relay_ws.push(ws);relay_maps.push(initial);agents.push(agent);tokens.push(token);nodes.push(node);
        }
        for index in 0..2 {
            let endpoint=native[index+1].lock().await.underlay_endpoint().to_string();
            let (status,body)=put(&rig.app,&format!("/api/tenant/{}/agent/{}/peer-relay-policy",rig.seeded.tenant_id,agents[index]),
                &rig.seeded.admin.access_token,json!({"serve":true,"approved_backbone_edges":[
                    {"relay_agent_id":agents[index+1],"endpoint":endpoint,"cross_border":index==1}]})).await;
            assert_eq!(status,200,"{body}");
        }
        set_mode(&rig.app,&rig.seeded,"on").await;
        // The earlier joins predated approval/ACL/edge configuration. Those
        // HTTP edits send deltas, not replacement network probe targets. Get
        // genuine configured full maps for ALL relays before starting probes.
        for (index,ws) in relay_ws.iter_mut().enumerate() {
            let port=native[index].lock().await.port();
            let public=["223.6.6.6","223.6.6.7","1.1.1.1"][index];
            let fresh=line_join(ws,10+index as u8,&format!("{public}:{port}"),
                json!({"relay_backbone_ready":index<2,"relay_port":port})).await;
            if index<2 {
                let expected=native[index+1].lock().await.underlay_endpoint().to_string();
                assert!(fresh["network"]["backbone_probe_targets"].as_array().is_some_and(|targets|
                    targets.iter().any(|target|target["relay_node_id"]==nodes[index+1]
                        &&target["endpoints"].as_array().is_some_and(|endpoints|endpoints.iter().any(|endpoint|endpoint==&expected)))),
                    "configured full map must offer its actual approved private edge");
            }
            relay_maps[index]=fresh;
        }
        trace.0.phase("configured_relay_joins_complete");
        let mut relay_task_indices=Vec::new();
        for (index,(ws,initial)) in relay_ws.into_iter().zip(relay_maps).enumerate() {
            relay_task_indices.push(start_relay(ws,native[index].clone(),native.get(index+1).cloned(),
                (["relay0","relay1","relay2"][index],trace.0.clone()),serde_json::from_value(initial).unwrap(),&mut tasks));
        }
        for (index,relay) in native.iter().cloned().enumerate() {
            let observed=trace.0.clone();let role=["relay0","relay1","relay2"][index];
            tasks.0.push(tokio::spawn(async move {
                let mut tick=tokio::time::interval(Duration::from_millis(250));let mut previous=(0,0);
                loop {tick.tick().await;if let Ok(relay)=relay.try_lock() {
                    let counts=relay.session_counts();let current=(counts.sessions_installed,counts.sessions_revoked);
                    if current!=previous {observed.record(role,"applied_native_counts",json!({
                        "sessions_installed":current.0,"sessions_revoked":current.1}));previous=current;}
                }}
            }));
        }
        let (a_agent,a_token)=enroll(&rig.app,&rig.seeded,&format!("{slug}-a")).await;
        let (b_agent,b_token)=enroll(&rig.app,&rig.seeded,&format!("{slug}-b")).await;
        let a_ws=connect_from(&rig.app,&a_token,&[],Some(CN_A)).await;
        let b_ws=connect_from(&rig.app,&b_token,&[],Some(US_A)).await;
        assert_observed(&rig.app,&a_agent,Some(CN_A)).await;
        assert_observed(&rig.app,&b_agent,Some(US_A)).await;
        let a_agent_id=ObjectId::parse_str(&a_agent).unwrap();let b_agent_id=ObjectId::parse_str(&b_agent).unwrap();
        let a=member(a_ws,a_agent,b_agent_id,"223.5.5.5:41641".into(),WgKeypair::generate(),&mut tasks,("memberA",trace.0.clone())).await;
        let b=member(b_ws,b_agent,a_agent_id,"8.8.8.8:41641".into(),WgKeypair::generate(),&mut tasks,("memberB",trace.0.clone())).await;
        let a_node=rig.node(&format!("{slug}-a")).await;let b_node=rig.node(&format!("{slug}-b")).await;
        trace.0.bind("memberA",&a_node);trace.0.bind("memberB",&b_node);
        let a_id=ObjectId::parse_str(&a_node).unwrap();let b_id=ObjectId::parse_str(&b_node).unwrap();
        let network=rig.app.state.network();let pair=meshharbor_mod_network::overlay::pair_key(a_id,b_id);
        let initial=tokio::time::timeout(Duration::from_secs(90),async {
            loop {a.assert_live(&tasks);b.assert_live(&tasks);if a.healthy(&b_node)&&b.healthy(&a_node){break;}
                tokio::time::sleep(Duration::from_millis(50)).await;}
        }).await;
        if initial.is_err() {
            let view=|member:&Member|member.view.borrow().peers.iter().map(|p|json!({
                "node":p.node_id,"connection":p.connection,"relay_kind":p.relay_kind,
                "stalled":p.stalled,"hs_done":p.debug.as_ref().map(|d|d.hs_done)})).collect::<Vec<_>>();
            let extras=|node|{let e=network.org_relay.join_extras(node);json!({"primary":e.org_primary,
                "backbone_only":e.supports_backbone_only_v1,"path_backbone":e.supports_path_backbone_v1})};
            let mut counts=Vec::new();for relay in &native {let c=relay.lock().await.session_counts();
                counts.push(json!({"installed":c.sessions_installed,"revoked":c.sessions_revoked}));}
            let session=network.org_relay.active_session(&pair).map(|s|json!({"vni":s.vni,"generation":s.generation,"hops":s.hops.len()}));
            eprintln!("legacy initial diagnostic {}",json!({"views":[view(&a),view(&b)],
                "requests":[a.requests_for(b_id),b.requests_for(a_id)],
                "metadata":[a.metadata_seen.load(Ordering::SeqCst),b.metadata_seen.load(Ordering::SeqCst)],
                "join_caps":[a.join_caps.lock().unwrap().clone(),b.join_caps.lock().unwrap().clone()],
                "probes":[a.probes.lock().unwrap().iter().map(|(n,r,t)|json!({"relay":n.to_hex(),"reachable":r,"rtt":t})).collect::<Vec<_>>(),
                    b.probes.lock().unwrap().iter().map(|(n,r,t)|json!({"relay":n.to_hex(),"reachable":r,"rtt":t})).collect::<Vec<_>>()],
                "server_extras":[extras(a_id),extras(b_id)],"native":counts,"active":session}));
            panic!("full runtimes must establish org line automatically");
        }
        assert!(a.metadata_seen.load(Ordering::SeqCst)&&b.metadata_seen.load(Ordering::SeqCst));
        trace.0.phase("initialhealthy");
        let original=network.org_relay.active_session(&pair).expect("actual legacy line");
        assert_eq!(std::iter::once(original.relay.node_id).chain(original.hops.iter().map(|h|h.relay.node_id)).map(|id|id.to_hex()).collect::<Vec<_>>(),nodes);
        let a_ip:Ipv4Addr=a.view.borrow().self_ip.as_ref().unwrap().parse().unwrap();
        let b_ip:Ipv4Addr=b.view.borrow().self_ip.as_ref().unwrap().parse().unwrap();
        tokio::time::timeout(Duration::from_secs(20),tcp64(&a.handle,&b.handle,b_ip,35101)).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(20),tcp64(&b.handle,&a.handle,a_ip,35102)).await.unwrap().unwrap();
        let requests_before_each=[a.requests_for(b_id),b.requests_for(a_id)];
        let requests_before=requests_before_each.iter().sum::<usize>();
        let port=native[1].lock().await.stop_listener().await.expect("kill active middle listener");
        trace.0.phase("middlestopped");
        tasks.0[relay_task_indices[1]].abort(); // actual relay control disconnect
        tokio::time::timeout(Duration::from_secs(45),async {
            while a.healthy(&b_node)&&b.healthy(&a_node) {a.assert_live(&tasks);b.assert_live(&tasks);tokio::time::sleep(Duration::from_millis(100)).await;}
        }).await.expect("real runtime must observe middle failure");
        native[1].lock().await.restart_listener(port).await.unwrap();
        trace.0.phase("listenerrestarted");
        let rejoin_started=std::time::Instant::now();
        let mut ws=connect_from(&rig.app,&tokens[1],&["relay-server"],Some(CN_R)).await;
        assert_observed(&rig.app,&agents[1],Some(CN_R)).await;
        let rejoin_map=line_join(&mut ws,11,&format!("223.6.6.7:{port}"),json!({"relay_backbone_ready":true,"relay_port":port})).await;
        trace.0.phase("rejoincompleted");
        assert_eq!(rig.node(&format!("{slug}-r1")).await,nodes[1]);
        start_relay(ws,native[1].clone(),Some(native[2].clone()),("relay1",trace.0.clone()),serde_json::from_value(rejoin_map).unwrap(),&mut tasks);
        // Rejoin invalidates old incoming-edge observations. This 300-second
        // window also covers the unchanged 240-second periodic fallback and
        // normal retries without forcing another source join; events may react earlier.
        let recovery=tokio::time::timeout(Duration::from_secs(300),async {
            loop {a.assert_live(&tasks);b.assert_live(&tasks);
                let reminted=network.org_relay.active_session(&pair).is_some_and(|s|s.generation!=original.generation);
                if reminted&&a.healthy(&b_node)&&b.healthy(&a_node){break;}
                tokio::time::sleep(Duration::from_millis(50)).await;}
        }).await;
        if recovery.is_err() {
            let view=|member:&Member|member.view.borrow().peers.iter().map(|p|json!({
                "node":p.node_id,"connection":p.connection,"relay_kind":p.relay_kind,
                "stalled":p.stalled,"hs_done":p.debug.as_ref().map(|d|d.hs_done)})).collect::<Vec<_>>();
            let extras=|node|{let e=network.org_relay.join_extras(node);json!({"primary":e.org_primary,
                "backbone_only":e.supports_backbone_only_v1,"path_backbone":e.supports_path_backbone_v1,
                "backbone_ready":e.relay_backbone_ready,"relay_port":e.relay_port})};
            let mut roles=Vec::new();let mut counts=Vec::new();
            for (index,relay) in native.iter().enumerate() {
                let agent=ObjectId::parse_str(&agents[index]).unwrap();
                let c=relay.lock().await.session_counts();
                counts.push(json!({"installed":c.sessions_installed,"revoked":c.sessions_revoked}));
                roles.push(json!({"node":nodes[index],"online":network.fleet.rc_hub.is_agent_online(agent),
                    "has_live_conn":meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(network,agent).is_some(),
                    "extras":extras(ObjectId::parse_str(&nodes[index]).unwrap())}));
            }
            let session=network.org_relay.active_session(&pair).map(|s|json!({"vni":s.vni,"generation":s.generation,"hops":s.hops.len()}));
            use meshharbor_mod_network::org_relay::candidate_test_support as diagnostics;
            let latest_denial=diagnostics::last_mint_for_fixture(network,a_id,b_id);
            let zone_graph=tokio::time::timeout(Duration::from_secs(10),async {
                let mut zones=Vec::new();
                let ids=std::iter::once(a_id).chain(std::iter::once(b_id))
                    .chain(nodes.iter().map(|id|ObjectId::parse_str(id).unwrap()));
                for node in ids {
                    zones.push(match diagnostics::zone_snapshot_for_fixture(network,node).await {
                        Ok(snapshot)=>snapshot,
                        Err(error)=>json!({"node":node.to_hex(),"error":error}),
                    });
                }
                let mut orientations=Vec::new();
                for (requester,peer) in [(a_id,b_id),(b_id,a_id)] {
                    let edges=match diagnostics::prepare_edges(network,requester,peer,false).await {
                        Ok(edges)=>json!({"ok":edges.into_iter().map(|(from,to,endpoint,cross_border)|
                            json!({"from_agent":from.to_hex(),"to_agent":to.to_hex(),"endpoint":endpoint,"cross_border":cross_border})).collect::<Vec<_>>()}),
                        Err(error)=>json!({"error":format!("{error:?}")}),
                    };
                    let selected=match diagnostics::select_path(network,requester,peer,false).await {
                        Ok(Some((relays,flipped)))=>json!({"ok":{"relay_agents":relays.into_iter().map(|id|id.to_hex()).collect::<Vec<_>>(),"flipped":flipped}}),
                        Ok(None)=>json!({"ok":null}),
                        Err(error)=>json!({"error":format!("{error:?}")}),
                    };
                    orientations.push(json!({"requester":requester.to_hex(),"peer":peer.to_hex(),"prepared_edges":edges,"selected_path":selected}));
                }
                json!({"zones":zones,"orientations":orientations})
            }).await.unwrap_or_else(|_|json!({"diagnostic_timeout_seconds":10}));
            eprintln!("legacy recovery diagnostic {}",json!({"views":[view(&a),view(&b)],
                "requests_before":requests_before,"requests":[a.requests_for(b_id),b.requests_for(a_id)],
                "metadata":[a.metadata_seen.load(Ordering::SeqCst),b.metadata_seen.load(Ordering::SeqCst)],
                "join_caps":[a.join_caps.lock().unwrap().clone(),b.join_caps.lock().unwrap().clone()],
                "probes":[a.probes.lock().unwrap().iter().map(|(n,r,t)|json!({"relay":n.to_hex(),"reachable":r,"rtt":t})).collect::<Vec<_>>(),
                    b.probes.lock().unwrap().iter().map(|(n,r,t)|json!({"relay":n.to_hex(),"reachable":r,"rtt":t})).collect::<Vec<_>>()],
                "server_member_extras":[extras(a_id),extras(b_id)],"relays":roles,
                "native":counts,"active":session,"original_generation":original.generation,
                "latest_denial":latest_denial,"zone_graph":zone_graph}));
            panic!("same full runtimes must recover with automatic requests");
        }
        let recovery_elapsed_ms=rejoin_started.elapsed().as_millis();
        trace.0.phase("recovered");
        assert!(a.requests_for(b_id)+b.requests_for(a_id)>requests_before,"no runtime-generated post-fault request");
        let requests_after_each=[a.requests_for(b_id),b.requests_for(a_id)];
        let recovered=network.org_relay.active_session(&pair).unwrap();
        assert_eq!(std::iter::once(recovered.relay.node_id).chain(recovered.hops.iter().map(|h|h.relay.node_id)).map(|id|id.to_hex()).collect::<Vec<_>>(),nodes);
        tokio::time::timeout(Duration::from_secs(20),tcp64(&a.handle,&b.handle,b_ip,35201)).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(20),tcp64(&b.handle,&a.handle,a_ip,35202)).await.unwrap().unwrap();
        let mut evidence=Vec::new();
        for index in 0..2 {
            let hop=&recovered.hops[index];let generation=if index==0 {recovered.generation}else{recovered.hops[index-1].generation};
            let (watch,sockets)=native[index].lock().await.bridge_evidence(hop.bridge_id,generation).unwrap();
            evidence.push((hop.bridge_id,watch,sockets));
        }
        trace.0.phase("modeoff");
        set_mode(&rig.app,&rig.seeded,"off").await;
        tokio::time::timeout(Duration::from_secs(15),async {
            while network.org_relay.active_session(&pair).is_some()||a.healthy(&b_node)||b.healthy(&a_node) {
                a.assert_live(&tasks);b.assert_live(&tasks);tokio::time::sleep(Duration::from_millis(50)).await;}
        }).await.expect("mode-off withdraws legacy line");
        for (index,(id,watch,sockets)) in evidence.into_iter().enumerate() {
            native[index].lock().await.assert_bridge_retired(id,watch,sockets).await.unwrap();
        }
        let _listener_a=a.handle.listen(35301).await.unwrap();let _listener_b=b.handle.listen(35302).await.unwrap();
        assert!(!matches!(tokio::time::timeout(Duration::from_secs(3),a.handle.connect(SocketAddr::from((b_ip,35302)))).await,Ok(Ok(_))),"mode-off bypassed line A→B");
        assert!(!matches!(tokio::time::timeout(Duration::from_secs(3),b.handle.connect(SocketAddr::from((a_ip,35301)))).await,Ok(Ok(_))),"mode-off bypassed line B→A");
        a.assert_live(&tasks);b.assert_live(&tasks);
        for relay in &native {relay.lock().await.stop_listener().await.unwrap();}
        drop((_listener_a,_listener_b));drop(a);drop(b);
        for task in &tasks.0 {task.abort();}
        for task in tasks.0.drain(..) {if let Err(error)=task.await {assert!(error.is_cancelled(),"fixture task panicked: {error}");}}
        // Client tasks ending is not server teardown. Keep this TestApp and its
        // Mongo runtime alive until all five authenticated sockets have left
        // both the Hub and network's exact-connection registry.
        let mut identities=agents.iter().map(|id|ObjectId::parse_str(id).unwrap()).collect::<Vec<_>>();
        identities.extend([a_agent_id,b_agent_id]);
        tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                let gone=identities.iter().all(|id|!network.fleet.rc_hub.is_agent_online(*id)
                    &&meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(network,*id).is_none());
                // socket.rs closes its observation LAST, after the Mongo
                // Offline/presence writes. Hub removal alone precedes those
                // awaits and cannot certify that DB cleanup has finished.
                let open_observations=rig.app.db.collection::<bson::Document>(
                    meshharbor_core::business_authority::OBSERVATIONS_COLLECTION)
                    .count_documents(bson::doc!{"identity.device_id":{"$in":identities.clone()},"closed_at":bson::Bson::Null})
                    .await.expect("read owned socket cleanup observations");
                if gone&&open_observations==0 {break;}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("owned authenticated sockets did not complete server disconnect");
        tokio::time::timeout(Duration::from_secs(15),meshharbor_api::state::shutdown_cleanup(&rig.app.state))
            .await.expect("owned test API module shutdown did not finish");
        println!("legacy recovery success {}",json!({
            "chain_relays":1+recovered.hops.len(),"old_generation":original.generation,
            "new_generation":recovered.generation,"automatic_requests_before":requests_before_each,
            "automatic_requests_after":requests_after_each,
            "recovery_elapsed_ms_from_rejoin_start":recovery_elapsed_ms,
            "tcp_echo":{"before":{"a_to_b":64,"b_to_a":64},"after":{"a_to_b":64,"b_to_a":64},"bytes_each":512},
            "same_member_owners":true,"mode_off_denied_both_directions":true,
            "bridge_sockets_released":true,"all_listeners_released":true,
            "owned_tasks_joined":true,"authenticated_connections_gone":identities.len(),"api_shutdown_complete":true}));
    }).await.expect("bounded full-runtime legacy recovery exceeded480 seconds");
}

/// Without a persistent `/ws?role=tunnel-client` connection (e.g. `mh socks5`
/// mesh mode fetching `/api/tunnel-client/agents` before opening its WS),
/// `list_tenant_agents` evaluates the caller's zone from the HTTP request's
/// `ConnectionOrigin` using the same trusted-proxy rules as `/ws`, without
/// mutating persistent connection tables:
/// 1. Same-zone, no WS -> returns only same-zone devices;
/// 2. Cross-zone, no WS -> filtered out;
/// 3. Unknown zone, no WS -> returns empty under `enforce`, returns devices as usual under `warn`;
/// 4. With a live WS -> existing behavior unchanged (live WS zone governs).
#[test]
fn tunnel_roster_without_ws_uses_request_origin_and_keeps_live_ws_precedence() {
    std::thread::Builder::new()
        .name("tunnel-roster-no-ws".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(tunnel_roster_without_ws_uses_request_origin_inner());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn tunnel_roster_without_ws_uses_request_origin_inner() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let fetch_roster = |app: &TestApp, tok: &str, xff: Option<&str>| {
        let mut req = app.auth_get("/api/tunnel-client/agents", tok);
        if let Some(ip) = xff {
            req = req.header("x-forwarded-for", ip);
        }
        async move {
            let v: Value = req.send().await.unwrap().json().await.unwrap();
            v.as_array()
                .unwrap()
                .iter()
                .map(|a| a["agent_id"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<String>>()
        }
    };

    // ── Enforce mode ──
    {
        let rig = Box::pin(Rig::up_with_unknown_role(
            "iso-roster-no-ws-enforce",
            "enforce",
            "enforce",
        ))
        .await;
        let tid = rig.seeded.tenant_id.clone();
        let admin = rig.seeded.admin.access_token.clone();

        let (us_a_id, us_a_tok) = enroll(&rig.app, &rig.seeded, "roster-us-a").await;
        let (cn_a_id, cn_a_tok) = enroll(&rig.app, &rig.seeded, "roster-cn-a").await;
        let _us_a_ws = connect_from(&rig.app, &us_a_tok, &[], Some(US_A)).await;
        let _cn_a_ws = connect_from(&rig.app, &cn_a_tok, &[], Some(CN_A)).await;
        assert_observed(&rig.app, &us_a_id, Some(US_A)).await;
        assert_observed(&rig.app, &cn_a_id, Some(CN_A)).await;

        let et: Value = rig
            .app
            .auth_post(
                &format!("/api/tenant/{tid}/tunnel-client/enroll-token"),
                &admin,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let enrolled_tc: Value = rig
            .app
            .client
            .post(rig.app.url("/api/tunnel-client/enroll"))
            .json(&json!({
                "enrollment_token": et["enrollment_token"],
                "machine_id": "roster-tc-stateless",
                "machine_name": "roster-tc-stateless",
                "os": "linux",
                "client_version": "0.4.151"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let tc_id = enrolled_tc["tunnel_client_id"].as_str().unwrap().to_owned();
        let tc_oid = ObjectId::parse_str(&tc_id).unwrap();
        let tc_tok = enrolled_tc["tunnel_client_token"]
            .as_str()
            .unwrap()
            .to_owned();

        rig.set_device_role("agent", &us_a_id, "client").await;
        rig.set_device_role("agent", &cn_a_id, "client").await;
        rig.set_device_role("tunnel-client", &tc_id, "client").await;

        let net = rig.app.state.network();
        assert!(
            meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
                net, tc_oid
            )
            .is_none(),
            "precondition: tunnel-client has no live WS connection"
        );
        let zones_gen_before = rig.app.state.business_zones.generation();

        // 1 & 2. No WS: Mainland origin returns only Mainland agent; Non-Mainland returns only Non-Mainland agent.
        assert_eq!(
            fetch_roster(&rig.app, &tc_tok, Some(CN_A)).await,
            BTreeSet::from([cn_a_id.clone()]),
            "no-WS Mainland request must return only Mainland agent and filter cross-zone"
        );
        assert_eq!(
            fetch_roster(&rig.app, &tc_tok, Some(US_A)).await,
            BTreeSet::from([us_a_id.clone()]),
            "no-WS Non-Mainland request must return only Non-Mainland agent and filter cross-zone"
        );

        // 3a. Unknown zone, no WS under enforce -> fail-closed empty roster.
        assert!(
            fetch_roster(&rig.app, &tc_tok, None).await.is_empty(),
            "no-WS unknown zone must fail closed and return empty under enforce"
        );

        // Verify stateless HTTP requests did NOT mutate persistent connection tables or DB observations.
        assert!(
            meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
                net, tc_oid
            )
            .is_none(),
            "stateless roster check must not register a live connection"
        );
        assert_eq!(
            rig.app.state.business_zones.generation(),
            zones_gen_before,
            "stateless roster check must not mutate LiveZones"
        );
        let tc_obs_count = rig
            .app
            .db
            .collection::<bson::Document>(
                meshharbor_core::business_authority::OBSERVATIONS_COLLECTION,
            )
            .count_documents(bson::doc! { "identity.device_id": tc_oid })
            .await
            .unwrap();
        assert_eq!(
            tc_obs_count, 0,
            "stateless roster check must not persist a connection observation row"
        );

        // 4. With a live WS connection -> existing behavior unchanged (live WS zone governs
        //    even if the HTTP request has no X-Forwarded-For or a different X-Forwarded-For).
        let tc_url = format!(
            "ws://{}/ws?token={}&role=tunnel-client",
            rig.app.addr,
            tc_tok
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        );
        let mut tc_req = tc_url.as_str().into_client_request().unwrap();
        tc_req
            .headers_mut()
            .insert("x-forwarded-for", US_A.parse().unwrap());
        let (mut tc_ws, _) = tokio_tungstenite::connect_async(tc_req).await.unwrap();
        let _ = line_join(&mut tc_ws, 5, "203.0.113.15:41641", json!({})).await;

        assert_eq!(
            fetch_roster(&rig.app, &tc_tok, None).await,
            BTreeSet::from([us_a_id.clone()]),
            "with live WS in NonMainland, HTTP request without XFF still uses live WS zone"
        );
        assert_eq!(
            fetch_roster(&rig.app, &tc_tok, Some(CN_A)).await,
            BTreeSet::from([us_a_id.clone()]),
            "with live WS in NonMainland, HTTP request with conflicting XFF cannot override live WS zone"
        );
        let _ = tc_ws.close(None).await;
    }

    // 3b. Unknown zone, no WS under warn -> returns devices as usual.
    {
        let warn_rig = Box::pin(Rig::up("iso-roster-no-ws-warn", "warn")).await;
        let warn_tid = warn_rig.seeded.tenant_id.clone();
        let warn_admin = warn_rig.seeded.admin.access_token.clone();
        let (w_us_id, w_us_tok) = enroll(&warn_rig.app, &warn_rig.seeded, "roster-w-us").await;
        let (w_cn_id, w_cn_tok) = enroll(&warn_rig.app, &warn_rig.seeded, "roster-w-cn").await;
        let _w_us_ws = connect_from(&warn_rig.app, &w_us_tok, &[], Some(US_A)).await;
        let _w_cn_ws = connect_from(&warn_rig.app, &w_cn_tok, &[], Some(CN_A)).await;
        assert_observed(&warn_rig.app, &w_us_id, Some(US_A)).await;
        assert_observed(&warn_rig.app, &w_cn_id, Some(CN_A)).await;

        let w_et: Value = warn_rig
            .app
            .auth_post(
                &format!("/api/tenant/{warn_tid}/tunnel-client/enroll-token"),
                &warn_admin,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let w_tc: Value = warn_rig
            .app
            .client
            .post(warn_rig.app.url("/api/tunnel-client/enroll"))
            .json(&json!({
                "enrollment_token": w_et["enrollment_token"],
                "machine_id": "roster-w-tc",
                "machine_name": "roster-w-tc",
                "os": "linux",
                "client_version": "0.4.151"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let w_tc_tok = w_tc["tunnel_client_token"].as_str().unwrap().to_owned();
        assert_eq!(
            fetch_roster(&warn_rig.app, &w_tc_tok, None).await,
            BTreeSet::from([w_us_id, w_cn_id]),
            "no-WS unknown zone under warn must return devices as usual"
        );
    }
}
