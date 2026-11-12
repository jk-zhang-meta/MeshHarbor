// SPDX-License-Identifier: AGPL-3.0-only
//! Org-relay takeover (field, 2026-11-11: item 6 with two relays under `auto`
//! and `enforce`). A pair must leave a relay that failed it even when an older
//! probe still says the relay was fine, must not be re-minted onto a relay
//! whose session for it never bound, and must get back onto a loss-pinned
//! relay once that relay is the only one left, instead of riding DERP for the
//! rest of the pin.
//!
//! The rig is `peer_relay_auto_tests`' with a second relay: members `a` and
//! `b`, relays `r1` and `r2`, every connection placed in the same zone through
//! the trusted loopback proxy. Both relays hold the central Server role, so
//! every grant here is implicit.

use crate::agent_presence_tests::enroll;
use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::peer_relay_auto_tests::{US_A, US_B, approved_user, assert_observed, fixture_mmdb};
use crate::peer_relay_mint_tests::{Ws, connect_from, join, node_id, put, recv_t, set_mode};
use bson::oid::ObjectId;
use futures::SinkExt;
use meshharbor_mod_network::org_relay::candidate_test_support::{
    eligibility_generation, record_member_probe_fixture,
};
use serde_json::json;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

const US_R1: &str = "1.1.1.1";
const US_R2: &str = "1.0.0.1";
const R1_EP: &str = "8.8.8.8:3478";
const R2_EP: &str = "9.9.9.9:3478";

struct Rig {
    app: TestApp,
    _geo: tempfile::TempDir,
    a: Ws,
    _b: Ws,
    _r1: Ws,
    r2: Option<Ws>,
    a_node: ObjectId,
    b_node: ObjectId,
    r1_node: ObjectId,
    r2_node: ObjectId,
    serial: u64,
}

impl Rig {
    async fn up(slug: &str) -> Self {
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
            s.app.business_isolation = "enforce".into();
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
        let (a_agent, a_tok) = enroll(&app, &seeded, &format!("{slug}-a")).await;
        let (b_agent, b_tok) = enroll(&app, &seeded, &format!("{slug}-b")).await;
        let (r1_agent, r1_tok) = enroll(&app, &seeded, &format!("{slug}-r1")).await;
        let (r2_agent, r2_tok) = enroll(&app, &seeded, &format!("{slug}-r2")).await;
        let mut a = connect_from(&app, &a_tok, &[], Some(US_A)).await;
        let mut b = connect_from(&app, &b_tok, &[], Some(US_B)).await;
        let mut r1 = connect_from(&app, &r1_tok, &["relay-server"], Some(US_R1)).await;
        let mut r2 = connect_from(&app, &r2_tok, &["relay-server"], Some(US_R2)).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        for (agent, ip) in [
            (&a_agent, Some(US_A)),
            (&b_agent, Some(US_B)),
            (&r1_agent, Some(US_R1)),
            (&r2_agent, Some(US_R2)),
        ] {
            assert_observed(&app, agent, ip).await;
        }
        join(&mut r1, 3, Some(true), "8.8.8.8:41641").await;
        join(&mut r2, 4, Some(true), "9.9.9.9:41641").await;
        join(&mut a, 1, Some(true), "203.0.113.10:41641").await;
        join(&mut b, 2, Some(true), "203.0.113.11:41641").await;
        for agent in [&r1_agent, &r2_agent] {
            let path = format!(
                "/api/admin/business-authority/agent/{}/{}",
                seeded.tenant_id, agent
            );
            let (s, v) = put(
                &app,
                &path,
                &owner.access_token,
                json!({ "role": "server", "reason": "takeover fixture" }),
            )
            .await;
            assert_eq!(s, 200, "set server role: {v}");
        }
        set_mode(&app, &seeded, "auto").await;
        let oid = |hex: String| ObjectId::parse_str(&hex).unwrap();
        let a_node = oid(node_id(&app, &seeded, &format!("{slug}-a")).await);
        let b_node = oid(node_id(&app, &seeded, &format!("{slug}-b")).await);
        let r1_node = oid(node_id(&app, &seeded, &format!("{slug}-r1")).await);
        let r2_node = oid(node_id(&app, &seeded, &format!("{slug}-r2")).await);
        Self {
            app,
            _geo: geo,
            a,
            _b: b,
            _r1: r1,
            r2: Some(r2),
            a_node,
            b_node,
            r1_node,
            r2_node,
            serial: 0,
        }
    }

    fn pair_key(&self) -> String {
        meshharbor_mod_network::overlay::pair_key(self.a_node, self.b_node)
    }

    /// Both members report the same measurement of each relay, through the
    /// same offer/report checks a real report takes.
    fn both_measure(&self, results: &[(ObjectId, bool, Option<u32>)]) {
        let reports: Vec<(ObjectId, String, bool, Option<u32>)> = results
            .iter()
            .map(|(relay, ok, rtt)| {
                let ep = if *relay == self.r1_node { R1_EP } else { R2_EP };
                (*relay, ep.to_string(), *ok, *rtt)
            })
            .collect();
        let net = self.app.state.network();
        for member in [self.a_node, self.b_node] {
            assert!(record_member_probe_fixture(net, member, &reports));
        }
    }

    /// `a` asks for an ORG link to `b`, as a member on DERP does each gap.
    async fn ask(&mut self) {
        self.serial += 1;
        self.a
            .send(Message::Text(
                json!({
                    "t": "rc:overlay.org_relay_fallback_request",
                    "peer_node_id": self.b_node.to_hex(),
                    "request_id": self.serial,
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send org fallback request");
    }

    /// The relay of the session the mint pushed to `a`, if one came.
    async fn minted_relay(&mut self, wait: Duration) -> Option<ObjectId> {
        let v = recv_t(&mut self.a, "rc:overlay.relay_session", wait).await?;
        Some(ObjectId::parse_str(v["relay_node_id"].as_str().expect("relay id")).unwrap())
    }
}

/// D1 — both members measured r1 the better relay, then unreachable. The
/// newer failure decides: the pair goes to r2. Before, the best probe of the
/// whole 10-minute window decided, and a frozen relay was re-minted twice.
#[tokio::test]
async fn a_relay_measured_unreachable_after_a_success_is_not_minted() {
    let mut rig = Rig::up("orgtk-neg").await;
    rig.both_measure(&[(rig.r1_node, true, Some(5)), (rig.r2_node, true, Some(50))]);
    rig.both_measure(&[(rig.r1_node, false, None)]);
    rig.ask().await;
    assert_eq!(
        rig.minted_relay(Duration::from_secs(5)).await,
        Some(rig.r2_node),
        "the pair must not be minted onto a relay both members just failed to reach"
    );
}

/// D1 — r1 is still measured best, but its session for the pair passed the
/// bind window while `a` was still asking for a link: the re-mint goes to r2.
#[tokio::test]
async fn a_relay_whose_session_never_bound_is_not_reminted_first() {
    let mut rig = Rig::up("orgtk-unbound").await;
    rig.both_measure(&[(rig.r1_node, true, Some(5)), (rig.r2_node, true, Some(50))]);
    rig.ask().await;
    assert_eq!(
        rig.minted_relay(Duration::from_secs(5)).await,
        Some(rig.r1_node),
        "the first mint goes to the better-measured relay"
    );
    rig.app
        .state
        .network()
        .org_relay
        .age_past_bind_window(&rig.pair_key());
    rig.ask().await;
    assert_eq!(
        rig.minted_relay(Duration::from_secs(5)).await,
        Some(rig.r2_node),
        "a relay that did not carry the pair is ranked last for it"
    );
}

/// D2 — r1 is loss-pinned for the pair and the pair is on r2. r2 goes away:
/// while the pin is young the pair stays on DERP, and once the sole-retry
/// wait has passed r1 serves it again rather than DERP for the whole pin.
#[tokio::test]
async fn a_loss_pinned_relay_serves_its_pair_once_it_is_the_only_one_left() {
    let mut rig = Rig::up("orgtk-sole").await;
    rig.both_measure(&[(rig.r1_node, true, Some(5)), (rig.r2_node, true, Some(50))]);
    let pk = rig.pair_key();
    let net = rig.app.state.network();
    net.org_relay.mark_lossy(
        &pk,
        rig.r1_node,
        std::time::Instant::now() + Duration::from_secs(600),
    );
    rig.ask().await;
    assert_eq!(
        rig.minted_relay(Duration::from_secs(5)).await,
        Some(rig.r2_node),
        "the pin moves the pair to the other relay"
    );
    drop(rig.r2.take());
    // r2's connection ends: its implicit session for the pair is revoked.
    assert!(
        recv_t(
            &mut rig.a,
            "rc:overlay.relay_revoke",
            Duration::from_secs(5)
        )
        .await
        .is_some(),
        "the session on the departed relay is revoked"
    );
    // Let the hub unregister the departed relay's connection.
    tokio::time::sleep(Duration::from_millis(500)).await;
    rig.ask().await;
    assert_eq!(
        rig.minted_relay(Duration::from_millis(800)).await,
        None,
        "a fresh pin still keeps its relay out"
    );
    rig.app.state.network().org_relay.age_loss_pin(
        &pk,
        rig.r1_node,
        meshharbor_mod_network::org_relay::LOSS_PIN_SOLE_RETRY,
    );
    rig.ask().await;
    assert_eq!(
        rig.minted_relay(Duration::from_secs(5)).await,
        Some(rig.r1_node),
        "the only relay left serves the pair again after the sole-retry wait"
    );
}

/// Regression for V0037 §2.2: every `TestApp` shares one local Redis pub/sub
/// channel (`rc_ctrl`). An `overlay_policy_sync` published without `"db"`
/// (from `business_authority` or `server_link`) bypasses `apply_policy_sync_ctrl`'s
/// DB filter on sibling `TestApp`s and calls `invalidate_eligibility()`,
/// aborting concurrent `maybe_mint_fallback` calls with `None` under load.
#[tokio::test]
async fn foreign_db_authority_sync_does_not_bump_eligibility_generation() {
    let app_a = TestApp::spawn().await;
    assert!(
        app_a.state.redis_pubsub.is_some(),
        "test requires local Redis pub/sub to exercise cross-DB rc_ctrl isolation"
    );
    let owner_id = ObjectId::new();
    let app_b = TestApp::spawn_with_settings(move |s| {
        s.auth.account_approval.enabled = true;
        s.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
    })
    .await;
    assert_ne!(app_a.db.name(), app_b.db.name());

    // Give both Redis subscribers a moment to finish subscribing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = eligibility_generation(app_a.state.network());

    let owner_b = approved_user(&app_b, "orgtk_xdb_owner", Some(owner_id)).await;
    let admin_b = approved_user(&app_b, "orgtk_xdb_admin", None).await;
    let member_b = approved_user(&app_b, "orgtk_xdb_member", None).await;
    let tid_b = app_b
        .state
        .tenants
        .create(
            "XDB Corp".into(),
            "orgtk-xdb".into(),
            ObjectId::parse_str(&admin_b.id).unwrap(),
        )
        .await
        .unwrap()
        .id
        .unwrap()
        .to_hex();
    let seeded_b = SeededTenant {
        tenant_id: tid_b,
        tenant_slug: "orgtk-xdb".into(),
        admin: admin_b,
        member: member_b,
        rooms: Vec::new(),
    };
    let (agent_b, _) = enroll(&app_b, &seeded_b, "orgtk-xdb-r1").await;
    let path = format!(
        "/api/admin/business-authority/agent/{}/{}",
        seeded_b.tenant_id, agent_b
    );
    let (s, v) = put(
        &app_b,
        &path,
        &owner_b.access_token,
        json!({ "role": "server", "reason": "cross-db check" }),
    )
    .await;
    assert_eq!(s, 200, "set server role on foreign db: {v}");

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        eligibility_generation(app_a.state.network()),
        before,
        "foreign-DB overlay_policy_sync must not bump app_a's eligibility_generation"
    );
}
