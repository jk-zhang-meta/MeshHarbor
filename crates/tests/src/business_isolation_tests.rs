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
use crate::peer_relay_mint_tests::{Ws, connect_from, join, node_id, recv_t};
use bson::oid::ObjectId;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;

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
