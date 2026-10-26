// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor §6 item 4 — `peer_relay_mode = auto`. A device whose CENTRAL
//! `server` role is current serves as an org relay with no per-device `serve`
//! approval and no per-relay ACL grant, but only between two members whose
//! LIVE connections were observed in the same business zone as its own. An
//! unknown zone on any of the three refuses, and an implicit session ends with
//! the role, with `auto`, and with any party's connection.
//!
//! The TestApp trusts its own loopback as a proxy, so each agent WebSocket
//! places itself with `X-Forwarded-For`. The GeoIP database is a two-record
//! fixture written at test time with a current build date: a checked-in or
//! downloaded database would age past the 120-day evidence rule
//! (`MAX_GEOIP_DATASET_AGE_SECS`) and turn these tests red on a calendar date.

use crate::agent_presence_tests::enroll;
use crate::fixtures::seed::{SeededTenant, SeededUser};
use crate::fixtures::test_app::TestApp;
use crate::peer_relay_mint_tests::{
    Ws, approve, audit_rows, connect_from, grant_relay, join, node_id, put, recv_t, set_mode,
    wait_mint_row,
};
use bson::{doc, oid::ObjectId};
use futures::SinkExt;
use roomler_ai_db::models::{AccountApprovalState, User};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// Non-mainland in the fixture database (it maps 0.0.0.0/1 to US) and in DB-IP.
pub(crate) const US_A: &str = "8.8.8.8";
pub(crate) const US_B: &str = "8.8.4.4";
const US_R: &str = "1.1.1.1";
/// Mainland in the fixture database (it maps 128.0.0.0/1 to CN) and in DB-IP.
pub(crate) const CN_A: &str = "223.5.5.5";

/// A MaxMind DB (format 2.0) with ONE search-tree node: 0.0.0.0/1 →
/// `{country: {iso_code: "US"}}` and 128.0.0.0/1 → `{country: {iso_code:
/// "CN"}}`, laid out byte for byte as `user_analytics`'s own fixture, but
/// stamped a minute ago so the zone evidence is never stale.
pub(crate) fn fixture_mmdb() -> Vec<u8> {
    fn text(out: &mut Vec<u8>, v: &str) {
        out.push(0x40 | v.len() as u8);
        out.extend_from_slice(v.as_bytes());
    }
    fn map(out: &mut Vec<u8>, entries: u8) {
        out.push(0xE0 | entries);
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
        out.extend_from_slice(&[0x08, 9 - 7]);
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn country(code: &str) -> Vec<u8> {
        let mut d = Vec::new();
        map(&mut d, 1);
        text(&mut d, "country");
        map(&mut d, 1);
        text(&mut d, "iso_code");
        text(&mut d, code);
        d
    }
    let (us, cn) = (country("US"), country("CN"));
    let node_count: u32 = 1;
    let to_us = node_count + 16;
    let to_cn = to_us + us.len() as u32;
    let built = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 60;
    let mut db = Vec::new();
    db.extend_from_slice(&to_us.to_be_bytes()[1..]);
    db.extend_from_slice(&to_cn.to_be_bytes()[1..]);
    db.extend_from_slice(&[0; 16]);
    db.extend_from_slice(&us);
    db.extend_from_slice(&cn);
    db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    map(&mut db, 9);
    text(&mut db, "binary_format_major_version");
    uint16(&mut db, 2);
    text(&mut db, "binary_format_minor_version");
    uint16(&mut db, 0);
    text(&mut db, "build_epoch");
    uint64(&mut db, built);
    text(&mut db, "database_type");
    text(&mut db, "DBIP-Country-Lite");
    text(&mut db, "description");
    map(&mut db, 1);
    text(&mut db, "en");
    text(&mut db, "auto relay fixture");
    text(&mut db, "ip_version");
    uint16(&mut db, 4);
    text(&mut db, "languages");
    db.extend_from_slice(&[0x01, 11 - 7]);
    text(&mut db, "en");
    text(&mut db, "node_count");
    uint32(&mut db, node_count);
    text(&mut db, "record_size");
    uint16(&mut db, 24);
    db
}

/// The zone the fixture database places `ip` in, as the observation stores it
/// (128.0.0.0/1 is CN).
fn zone_of(ip: &str) -> &'static str {
    let first = ip.split('.').next().and_then(|o| o.parse::<u8>().ok());
    if first.is_some_and(|o| o >= 128) { "mainland" } else { "non_mainland" }
}

/// The fixture must actually place each connection, or every refusal test
/// passes vacuously: assert the observation the server recorded for
/// `agent_id` names `from` and its zone (a bare connection: no zone at all).
pub(crate) async fn assert_observed(app: &TestApp, agent_id: &str, from: Option<&str>) {
    let id = ObjectId::parse_str(agent_id).unwrap();
    let rows = app
        .db
        .collection::<bson::Document>(roomler_core::business_authority::OBSERVATIONS_COLLECTION);
    let mut row = None;
    for _ in 0..30 {
        row = rows.find_one(doc! { "identity.device_id": id }).await.unwrap();
        if row.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let row = row.unwrap_or_else(|| panic!("no observation recorded for {agent_id}"));
    match from {
        Some(ip) => {
            assert_eq!(row.get_str("client_ip").ok(), Some(ip), "{row}");
            assert_eq!(row.get_str("zone").ok(), Some(zone_of(ip)), "{row}");
        }
        None => assert!(row.get_str("zone").is_err(), "{row}"),
    }
}

/// Admission is on for EVERY user once a central owner exists, so fixture
/// users are written approved rather than registered (`register_user` cannot
/// log a pending account in).
pub(crate) async fn approved_user(
    app: &TestApp,
    name: &str,
    fixed: Option<ObjectId>,
) -> SeededUser {
    let hash = app
        .state
        .auth
        .hash_password("fixture-only-not-a-real-password")
        .unwrap();
    let mut u = app
        .state
        .users
        .create(
            format!("{name}@auto-relay.example.test"),
            name.into(),
            name.into(),
            hash,
            None,
        )
        .await
        .unwrap();
    let generated = u.id.unwrap();
    let id = fixed.unwrap_or(generated);
    u.id = Some(id);
    u.is_verified = true;
    u.account_approval.state = AccountApprovalState::Approved;
    let users = app.db.collection::<User>("users");
    if id != generated {
        users.delete_one(doc! { "_id": generated }).await.unwrap();
        users.insert_one(&u).await.unwrap();
    } else {
        users.replace_one(doc! { "_id": id }, &u).await.unwrap();
    }
    let tokens = app
        .state
        .auth
        .generate_tokens_at_revision(id, &u.email, &u.username, 0)
        .unwrap();
    SeededUser {
        id: id.to_hex(),
        email: u.email.clone(),
        username: u.username.clone(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }
}

/// Three nodes on one tenant: `a` asks, `b` is the peer, `r` may relay. None
/// is approved to `serve`, and no overlay policy names `r`.
struct AutoRig {
    app: TestApp,
    seeded: SeededTenant,
    owner_token: String,
    _geo: tempfile::TempDir,
    a: Ws,
    b: Ws,
    r: Ws,
    b_tok: String,
    b_node: String,
    r_node: String,
    r_agent: String,
}

impl AutoRig {
    /// `from` = the address a, b and r each connect from through the trusted
    /// loopback proxy; `None` connects bare, which observes no zone at all.
    async fn up(slug: &str, from: [Option<&str>; 3]) -> Self {
        Self::up_isolated(slug, from, "warn").await
    }

    /// [`Self::up`] under `app.business_isolation = isolation` (#21).
    async fn up_isolated(slug: &str, from: [Option<&str>; 3], isolation: &'static str) -> Self {
        let geo = tempfile::tempdir().unwrap();
        let mmdb = geo.path().join("dbip-country-lite.mmdb");
        std::fs::write(&mmdb, fixture_mmdb()).unwrap();
        let mmdb = mmdb.to_str().unwrap().to_owned();
        let owner_id = ObjectId::new();
        let app = TestApp::spawn_with_settings(move |s| {
            s.auth.account_approval.enabled = true;
            s.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
            s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
            // Loopback is the ONLY proxy, so the last forwarded entry is the
            // client. `Settings::load()` defaults to one further hop, under
            // which a single-entry header is a too-short (refused) chain.
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
        let (a_agent, a_tok) = enroll(&app, &seeded, &format!("{slug}-a")).await;
        let (b_agent, b_tok) = enroll(&app, &seeded, &format!("{slug}-b")).await;
        let (r_agent, r_tok) = enroll(&app, &seeded, &format!("{slug}-r")).await;
        let mut a = connect_from(&app, &a_tok, &[], from[0]).await;
        let mut b = connect_from(&app, &b_tok, &[], from[1]).await;
        let mut r = connect_from(&app, &r_tok, &["relay-server"], from[2]).await;
        // Let the hellos, and each connection's observation, land.
        tokio::time::sleep(Duration::from_millis(300)).await;
        for (agent, ip) in [(&a_agent, from[0]), (&b_agent, from[1]), (&r_agent, from[2])] {
            assert_observed(&app, agent, ip).await;
        }
        join(&mut r, 3, Some(true), "8.8.8.8:41641").await;
        join(&mut a, 1, Some(true), "203.0.113.10:41641").await;
        join(&mut b, 2, Some(true), "203.0.113.11:41641").await;
        let b_node = node_id(&app, &seeded, &format!("{slug}-b")).await;
        let r_node = node_id(&app, &seeded, &format!("{slug}-r")).await;
        Self {
            app,
            seeded,
            owner_token: owner.access_token,
            _geo: geo,
            a,
            b,
            r,
            b_tok,
            b_node,
            r_node,
            r_agent,
        }
    }

    /// The central owner sets r's business role (`server`, or `unknown` to
    /// revoke it).
    async fn set_relay_role(&self, role: &str) {
        let path = format!(
            "/api/admin/business-authority/agent/{}/{}",
            self.seeded.tenant_id, self.r_agent
        );
        let (s, v) = put(
            &self.app,
            &path,
            &self.owner_token,
            json!({ "role": role, "reason": "auto relay fixture" }),
        )
        .await;
        assert_eq!(s, 200, "set role {role}: {v}");
    }

    /// Everything an implicit grant needs: r is a server, the org is `auto`.
    async fn arm(&self) {
        self.set_relay_role("server").await;
        set_mode(&self.app, &self.seeded, "auto").await;
    }

    /// An explicit grant instead: `on`, r approved to serve, and a policy
    /// granting every node the relay.
    async fn explicit(&self) {
        set_mode(&self.app, &self.seeded, "on").await;
        assert_eq!(
            approve(&self.app, &self.seeded, &self.r_agent, true).await,
            200
        );
        grant_relay(&self.app, &self.seeded, &self.r_node).await;
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

    /// The three frames of a mint; returns the session's VNI.
    async fn expect_minted(&mut self) -> u64 {
        let wait = Duration::from_secs(5);
        let Some(serve) = recv_t(&mut self.r, "rc:overlay.relay_serve", wait).await else {
            panic!(
                "the relay receives relay_serve; audit: {:?}",
                audit_rows(&self.app, &self.seeded).await
            );
        };
        let sa = recv_t(&mut self.a, "rc:overlay.relay_session", wait)
            .await
            .expect("member a receives relay_session");
        let sb = recv_t(&mut self.b, "rc:overlay.relay_session", wait)
            .await
            .expect("member b receives relay_session");
        let vni = serve["vni"].as_u64().expect("a vni");
        assert_eq!(sa["vni"], json!(vni));
        assert_eq!(sb["vni"], json!(vni));
        assert_eq!(sa["relay_node_id"], json!(self.r_node));
        vni
    }

    /// The newest audit row is a refused mint naming `reason`, and no session
    /// reached the asker.
    async fn expect_refused(&mut self, reason: &str) {
        let row = wait_mint_row(&self.app, &self.seeded).await;
        assert_eq!(row["denied"], json!(reason), "{row}");
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

    /// `relay_revoke` naming `vni` reaches a and r, and b too unless it is
    /// the party that left.
    async fn expect_revoked(&mut self, vni: u64, b_too: bool) {
        let wait = Duration::from_secs(5);
        let mut parties: Vec<(&str, &mut Ws)> = vec![("a", &mut self.a), ("r", &mut self.r)];
        if b_too {
            parties.push(("b", &mut self.b));
        }
        for (name, ws) in parties {
            let v: Value = recv_t(ws, "rc:overlay.relay_revoke", wait)
                .await
                .unwrap_or_else(|| panic!("{name} receives relay_revoke"));
            assert_eq!(v["vni"], json!(vni), "{name}: the revoke names the session");
        }
    }
}

/// The point of `auto`: a Server-role relay serves a same-zone pair with
/// neither a `serve` approval nor an overlay policy naming it.
#[tokio::test]
async fn auto_server_role_relay_serves_a_same_zone_pair_without_serve_or_acl() {
    let mut rig = AutoRig::up("auto-same", [Some(US_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    let vni = rig.expect_minted().await;
    let row = wait_mint_row(&rig.app, &rig.seeded).await;
    assert!(row["denied"].is_null(), "{row}");
    assert_eq!(row["vni"], json!(vni));
    assert_eq!(row["agent_id"], json!(rig.r_agent));
}

/// The zone evidence is the connection's, not the observation row's: the row
/// expires 60 s after the connection opens (TTL index on `expires_at`), and a
/// grant that read it would refuse every pair older than a minute.
#[tokio::test]
async fn auto_zone_evidence_outlives_the_expiring_observation_row() {
    let mut rig = AutoRig::up("auto-ttl", [Some(US_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.app
        .db
        .collection::<bson::Document>(roomler_core::business_authority::OBSERVATIONS_COLLECTION)
        .delete_many(doc! {})
        .await
        .unwrap();
    rig.request().await;
    rig.expect_minted().await;
}

/// Hard isolation: one member observed in the other zone ⇒ no implicit grant.
#[tokio::test]
async fn auto_refuses_a_pair_that_crosses_zones() {
    let mut rig = AutoRig::up("auto-cross", [Some(CN_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    rig.expect_refused("zone_denied").await;
}

/// The same refusal again is not written again: a member on DERP asks
/// every minute, and the first row stands for the repeats.
#[tokio::test]
async fn a_repeated_identical_refusal_is_audited_once() {
    let mut rig = AutoRig::up("auto-cross-repeat", [Some(CN_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    rig.expect_refused("zone_denied").await;
    rig.request().await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let mints = audit_rows(&rig.app, &rig.seeded)
        .await
        .into_iter()
        .filter(|r| r["action"] == json!("mint"))
        .count();
    assert_eq!(mints, 1, "one row for two identical refusals");
}

/// Fail closed: a connection with no observed zone grants nothing.
#[tokio::test]
async fn auto_refuses_a_member_whose_zone_is_unknown() {
    let mut rig = AutoRig::up("auto-unknown", [None, Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    rig.expect_refused("zone_denied").await;
}

/// `on` is unchanged: a role is not a `serve` approval, so r is no candidate.
#[tokio::test]
async fn on_mode_does_not_grant_by_role() {
    let mut rig = AutoRig::up("auto-on", [Some(US_A), Some(US_B), Some(US_R)]).await;
    rig.set_relay_role("server").await;
    set_mode(&rig.app, &rig.seeded, "on").await;
    rig.request().await;
    rig.expect_refused("no_relay").await;
}

/// The role is the grant: withdrawing it withdraws what it minted.
#[tokio::test]
async fn revoking_the_server_role_revokes_its_implicit_sessions() {
    let mut rig = AutoRig::up("auto-role", [Some(US_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    let vni = rig.expect_minted().await;
    rig.set_relay_role("unknown").await;
    rig.expect_revoked(vni, true).await;
}

/// So is the mode: `on` keeps only what an overlay policy grants.
#[tokio::test]
async fn leaving_auto_revokes_implicit_sessions() {
    let mut rig = AutoRig::up("auto-leave", [Some(US_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    let vni = rig.expect_minted().await;
    set_mode(&rig.app, &rig.seeded, "on").await;
    rig.expect_revoked(vni, true).await;
}

/// A connection that displaces the first (the old socket still open, so no
/// overlay leave runs) carries its OWN zone evidence: what the first vouched
/// for is revoked at the new hello, and the next mint reads the new zone.
#[tokio::test]
async fn a_displacing_connection_revokes_and_brings_its_own_zone() {
    let mut rig = AutoRig::up("auto-swap", [Some(US_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    let vni = rig.expect_minted().await;
    let b_tok = rig.b_tok.clone();
    let mut b2 = connect_from(&rig.app, &b_tok, &[], Some(CN_A)).await;
    rig.expect_revoked(vni, false).await;
    join(&mut b2, 2, Some(true), "203.0.113.11:41641").await;
    rig.request().await;
    rig.expect_refused("zone_denied").await;
}

/// And the evidence: each zone was observed on ONE connection, and what that
/// connection vouched for ends with it.
#[tokio::test]
async fn a_party_disconnecting_revokes_implicit_sessions() {
    let mut rig = AutoRig::up("auto-gone", [Some(US_A), Some(US_B), Some(US_R)]).await;
    rig.arm().await;
    rig.request().await;
    let vni = rig.expect_minted().await;
    rig.b.close(None).await.expect("close b");
    rig.expect_revoked(vni, false).await;
}

/// GEO-05 — a member that roams into the other zone (it reconnects from
/// there) ends its explicitly granted session on its rejoin, not at the
/// session's expiry; a reconnect from the same zone keeps it, and `warn` only
/// logs.
#[tokio::test]
async fn a_member_roaming_into_the_other_zone_ends_its_session_on_rejoin() {
    for (mode, ends) in [("enforce", true), ("warn", false)] {
        let mut rig = AutoRig::up_isolated(
            &format!("geo05-{mode}"),
            [Some(US_A), Some(US_B), Some(US_R)],
            mode,
        )
        .await;
        rig.explicit().await;
        rig.request().await;
        let vni = rig.expect_minted().await;
        let b_tok = rig.b_tok.clone();

        let mut same = connect_from(&rig.app, &b_tok, &[], Some(US_B)).await;
        join(&mut same, 2, Some(true), "203.0.113.11:41641").await;
        assert!(
            recv_t(
                &mut rig.r,
                "rc:overlay.relay_revoke",
                Duration::from_secs(2)
            )
            .await
            .is_none(),
            "{mode}: a reconnect from the same zone keeps the session"
        );

        let mut roamed = connect_from(&rig.app, &b_tok, &[], Some(CN_A)).await;
        join(&mut roamed, 2, Some(true), "203.0.113.11:41641").await;
        let revoke = recv_t(
            &mut rig.r,
            "rc:overlay.relay_revoke",
            Duration::from_secs(3),
        )
        .await;
        assert_eq!(revoke.is_some(), ends, "{mode}: {revoke:?}");
        if ends {
            assert_eq!(revoke.unwrap()["vni"], json!(vni));
            let rows = audit_rows(&rig.app, &rig.seeded).await;
            assert!(
                rows.iter()
                    .any(|r| r["action"] == "revoke" && r["reason"] == "zone_changed"),
                "{rows:?}"
            );
        }
    }
}

/// #21 control: under `warn` an explicit grant still carries a cross-zone
/// pair (the rule only logs), so the refusals below are the rule's.
#[tokio::test]
async fn isolation_warn_leaves_an_explicit_cross_zone_grant_alone() {
    let mut rig =
        AutoRig::up_isolated("iso-x-warn", [Some(CN_A), Some(US_B), Some(US_R)], "warn").await;
    rig.explicit().await;
    rig.request().await;
    rig.expect_minted().await;
}

/// #21 `enforce`: no explicit grant (`serve` plus a policy naming the relay)
/// carries a pair across the mainland line.
#[tokio::test]
async fn isolation_enforce_refuses_an_explicit_cross_zone_grant() {
    let mut rig =
        AutoRig::up_isolated("iso-x-enf", [Some(CN_A), Some(US_B), Some(US_R)], "enforce").await;
    rig.explicit().await;
    rig.request().await;
    rig.expect_refused("zone_denied").await;
}

/// ACL-02 — an explicit grant under an ACL in `warn` (which only logs) still
/// does not carry a pair across the line.
#[tokio::test]
async fn isolation_enforce_refuses_a_cross_zone_grant_under_a_warn_acl() {
    let mut rig = AutoRig::up_isolated(
        "iso-x-aclw",
        [Some(CN_A), Some(US_B), Some(US_R)],
        "enforce",
    )
    .await;
    rig.explicit().await;
    let (s, v) = put(
        &rig.app,
        &format!("/api/tenant/{}/overlay-acl/mode", rig.seeded.tenant_id),
        &rig.seeded.admin.access_token,
        json!({ "mode": "warn" }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    rig.request().await;
    rig.expect_refused("zone_denied").await;
}

/// #21 `enforce`: a same-zone pair is not carried through a relay in the
/// other zone either.
#[tokio::test]
async fn isolation_enforce_skips_a_relay_outside_the_pairs_zone() {
    let mut rig =
        AutoRig::up_isolated("iso-r-enf", [Some(US_A), Some(US_B), Some(CN_A)], "enforce").await;
    rig.explicit().await;
    rig.request().await;
    rig.expect_refused("zone_denied").await;
}

/// #21: the TURN grant is a carrier too. `warn` grants a cross-zone pair,
/// `enforce` sends nothing.
#[tokio::test]
async fn isolation_enforce_refuses_a_cross_zone_turn_grant() {
    for (isolation, granted) in [("warn", true), ("enforce", false)] {
        let mut rig = AutoRig::up_isolated(
            &format!("iso-turn-{isolation}"),
            [Some(CN_A), Some(US_B), Some(US_R)],
            isolation,
        )
        .await;
        rig.request().await;
        let grant = recv_t(&mut rig.a, "rc:overlay.relay_grant", Duration::from_secs(2)).await;
        assert_eq!(grant.is_some(), granted, "{isolation}: {grant:?}");
    }
}
