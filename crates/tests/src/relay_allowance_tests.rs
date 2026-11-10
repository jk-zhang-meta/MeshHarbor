// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P4a — the relay allowance's job, through a real server and a real
//! MongoDB. An org past its plan's monthly relay has every overlay network
//! in the over-allowance set, at its plan's rate. Inside the allowance, last
//! month, with the kill switch off, or on a server that sells no plans,
//! nothing is.
//!
//! The process-wide map `forward_frame` reads is the unit tests'
//! (`relay_allowance::tests`): these tests read what the job COMPUTES and
//! PUBLISHES, which is scoped to each test's own database.

use bson::{DateTime, Document, doc, oid::ObjectId};
use meshharbor_mod_network::{NetworkState, relay_allowance};
use meshharbor_services::dao::overlay_network::OverlayNetworkDao;

use crate::fixtures::test_app::TestApp;

const GB: i64 = 1_000_000_000;

fn net(app: &TestApp) -> &NetworkState {
    app.state
        .modules
        .network
        .as_ref()
        .expect("the network module is mounted in tests")
}

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

fn enable(s: &mut meshharbor_config::Settings) {
    s.relay_allowance.enabled = true;
}

/// `bytes` of DERP relay for `tenant` this month, as FR-20 records them: in
/// the hourly tier for a completed hour when the month has one, the rest in
/// the raw tier's open hour.
async fn relayed_this_month(app: &TestApp, tenant: ObjectId, bytes: i64) {
    let now = DateTime::now();
    let start = relay_allowance::month_start(now);
    let hour = DateTime::from_millis(now.timestamp_millis() / 3_600_000 * 3_600_000);
    let (hourly, raw) = if hour.timestamp_millis() > start.timestamp_millis() {
        (bytes / 2, bytes - bytes / 2)
    } else {
        (0, bytes)
    };
    if hourly > 0 {
        usage_row(app, "stats_usage_1h", tenant, start, hourly).await;
    }
    usage_row(app, "stats_usage", tenant, now, raw).await;
}

async fn usage_row(app: &TestApp, coll: &str, tenant: ObjectId, ts: DateTime, value: i64) {
    app.db
        .collection::<Document>(coll)
        .insert_one(doc! {
            "_id": format!("{}:derp_bytes:{}:{}", tenant.to_hex(), ts.timestamp_millis() / 1000, ObjectId::new().to_hex()),
            "tenant_id": tenant,
            "meter": "derp_bytes",
            "ts": ts,
            "value": value,
        })
        .await
        .unwrap();
}

async fn network_of(app: &TestApp, tenant: ObjectId) -> ObjectId {
    OverlayNetworkDao::new(&app.db)
        .get_or_create(tenant)
        .await
        .unwrap()
        .id
        .expect("network _id")
}

async fn set_plan(app: &TestApp, tenant: ObjectId, plan: &str, seats: i64) {
    app.db
        .collection::<Document>("tenants")
        .update_one(
            doc! { "_id": tenant },
            doc! { "$set": { "plan": plan, "billing": { "seats": seats } } },
        )
        .await
        .unwrap();
}

/// A Free org past its 10 GB has its network in the set at the Free rate
/// (1 Mbit/s = 125,000 B/s), and the job publishes exactly that.
#[tokio::test]
async fn a_free_org_past_its_allowance_is_throttled_at_the_free_rate() {
    let app = TestApp::spawn_with_settings(enable).await;
    let t = app.seed_tenant("fr115relay1").await;
    let tid = oid(&t.tenant_id);
    let network = network_of(&app, tid).await;

    relayed_this_month(&app, tid, 9 * GB).await;
    let set = relay_allowance::compute(net(&app), DateTime::now())
        .await
        .unwrap();
    assert!(set.is_empty(), "inside its allowance: {set:?}");

    relayed_this_month(&app, tid, 2 * GB).await;
    let set = relay_allowance::compute(net(&app), DateTime::now())
        .await
        .unwrap();
    assert_eq!(set.get(&network), Some(&125_000), "{set:?}");

    // Published for every pod to read, scoped to this database. `publish` is
    // the job's body: the module's own loop claimed this tick at startup, so
    // `run_job_once` here would lose the claim and publish nothing.
    assert_eq!(
        relay_allowance::publish(net(&app), DateTime::now()).await,
        Some(1)
    );
    if let Some(redis) = &net(&app).redis_pubsub {
        let raw = redis
            .kv_get(&relay_allowance::set_key(app.db.name()))
            .await
            .unwrap()
            .expect("the set is published");
        let published: std::collections::HashMap<String, u64> = serde_json::from_str(&raw).unwrap();
        assert_eq!(published.get(&network.to_hex()), Some(&125_000), "{raw}");
    }
}

/// Pro's allowance is 25 GB per billed seat, and its rate is the paid one
/// (4 Mbit/s = 500,000 B/s).
#[tokio::test]
async fn a_pro_orgs_allowance_grows_with_its_seats() {
    let app = TestApp::spawn_with_settings(enable).await;
    let t = app.seed_tenant("fr115relay2").await;
    let tid = oid(&t.tenant_id);
    let network = network_of(&app, tid).await;
    set_plan(&app, tid, "pro", 3).await;

    relayed_this_month(&app, tid, 60 * GB).await;
    let set = relay_allowance::compute(net(&app), DateTime::now())
        .await
        .unwrap();
    assert!(
        set.is_empty(),
        "60 GB is inside three seats' 75 GB: {set:?}"
    );

    relayed_this_month(&app, tid, 20 * GB).await;
    let set = relay_allowance::compute(net(&app), DateTime::now())
        .await
        .unwrap();
    assert_eq!(set.get(&network), Some(&500_000), "{set:?}");
}

/// The allowance is monthly: last month's relay does not count.
#[tokio::test]
async fn last_months_relay_does_not_count() {
    let app = TestApp::spawn_with_settings(enable).await;
    let t = app.seed_tenant("fr115relay3").await;
    let tid = oid(&t.tenant_id);
    network_of(&app, tid).await;
    let start = relay_allowance::month_start(DateTime::now());
    let last_month = DateTime::from_millis(start.timestamp_millis() - 86_400_000);
    usage_row(&app, "stats_usage_1h", tid, last_month, 50 * GB).await;

    let set = relay_allowance::compute(net(&app), DateTime::now())
        .await
        .unwrap();
    assert!(set.is_empty(), "{set:?}");
}

/// The kill switch: the job publishes nothing, whoever is over.
#[tokio::test]
async fn the_kill_switch_publishes_nothing() {
    let app = TestApp::spawn().await; // `relay_allowance.enabled` defaults off
    let t = app.seed_tenant("fr115relay4").await;
    let tid = oid(&t.tenant_id);
    network_of(&app, tid).await;
    relayed_this_month(&app, tid, 20 * GB).await;

    assert_eq!(
        relay_allowance::publish(net(&app), DateTime::now()).await,
        Some(0)
    );
    if let Some(redis) = &net(&app).redis_pubsub {
        let raw = redis
            .kv_get(&relay_allowance::set_key(app.db.name()))
            .await
            .unwrap();
        assert!(
            raw.is_none(),
            "nothing is published with the switch off: {raw:?}"
        );
    }
}

/// A server that sells no plans throttles nobody: self-hosting is
/// unlimited (`Core::plans_sold`).
#[tokio::test]
async fn a_server_that_sells_no_plans_throttles_nobody() {
    let app = TestApp::spawn_with_settings(|s| {
        enable(s);
        s.modules.saas = false;
    })
    .await;
    let t = app.seed_tenant("fr115relay5").await;
    let tid = oid(&t.tenant_id);
    network_of(&app, tid).await;
    relayed_this_month(&app, tid, 20 * GB).await;

    assert_eq!(
        relay_allowance::publish(net(&app), DateTime::now()).await,
        Some(0)
    );
}

/// The org's analytics page (`/stats/resources`): its `quota.relay`.
async fn relay_quota(app: &TestApp, t: &crate::fixtures::seed::SeededTenant) -> serde_json::Value {
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/stats/resources?range=24h", t.tenant_id),
            &t.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["quota"]["relay"].clone()
}

/// AC7's surface: the org's analytics page shows the month's relay against
/// its plan's allowance, by the throttle's own arithmetic. With the switch
/// off (the default) it is shown and not applied: never throttled.
#[tokio::test]
async fn the_org_page_shows_its_relay_against_the_allowance() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("fr115relay6").await;
    let tid = oid(&t.tenant_id);

    relayed_this_month(&app, tid, 2 * GB).await;
    let q = relay_quota(&app, &t).await;
    assert_eq!(q["used_bytes"], 2 * GB, "{q}");
    assert_eq!(q["allowance_bytes"], 10 * GB, "Free's flat 10 GB: {q}");
    assert_eq!(q["rate_kbps"], 1_000, "{q}");
    assert_eq!(q["enforced"], false, "{q}");
    assert_eq!(q["throttled"], false, "{q}");
    assert!(
        q["resets_at"]
            .as_str()
            .is_some_and(|s| s.contains("-01T00:00:00")),
        "{q}"
    );

    // Past the allowance with the switch off: shown over, not throttled.
    relayed_this_month(&app, tid, 9 * GB).await;
    let q = relay_quota(&app, &t).await;
    assert_eq!(q["used_bytes"], 11 * GB, "{q}");
    assert_eq!(q["throttled"], false, "not enforced: {q}");

    // A paid plan: 25 GB per billed seat, at the paid rate.
    set_plan(&app, tid, "pro", 3).await;
    let q = relay_quota(&app, &t).await;
    assert_eq!(q["allowance_bytes"], 75 * GB, "{q}");
    assert_eq!(q["rate_kbps"], 4_000, "{q}");
}

/// With the throttle on, an org past its allowance reads as throttled; a
/// server that sells no plans shows no allowance at all.
#[tokio::test]
async fn the_org_page_says_when_the_throttle_is_on() {
    let app = TestApp::spawn_with_settings(enable).await;
    let t = app.seed_tenant("fr115relay7").await;
    let tid = oid(&t.tenant_id);
    relayed_this_month(&app, tid, 11 * GB).await;
    let q = relay_quota(&app, &t).await;
    assert_eq!(q["enforced"], true, "{q}");
    assert_eq!(q["throttled"], true, "{q}");

    let selfhost = TestApp::spawn_with_settings(|s| {
        enable(s);
        s.modules.saas = false;
    })
    .await;
    let t = selfhost.seed_tenant("fr115relay8").await;
    relayed_this_month(&selfhost, oid(&t.tenant_id), 11 * GB).await;
    assert!(
        relay_quota(&selfhost, &t).await.is_null(),
        "self-hosting has no allowance"
    );
}

/// FR-115 P4a-2 — the API half of the push to the PoPs. On its `/stats`
/// poll, the pod signs the over-allowance set the job published and POSTs it
/// to every endpoint; a fake PoP records what arrives. What it receives must
/// verify with the ticket key's PUBLIC half (all a PoP holds) and carry the
/// published set, with a lifetime of three polls; an absent set is pushed
/// as an empty one, which is how the kill switch reaches a PoP.
#[tokio::test]
async fn the_poller_pushes_the_signed_set_to_the_pops() {
    use base64::Engine as _;
    use meshharbor_remote_control::derp_ticket::{self, DerpTicketSigner};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    // A fake PoP: the GET answers a minimal snapshot, the POST is recorded.
    let pushed: Arc<Mutex<Vec<String>>> = Arc::default();
    let pop = {
        let pushed = pushed.clone();
        axum::Router::new().route(
            "/stats",
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "cpus": 1 })) }).post(
                move |body: String| {
                    let pushed = pushed.clone();
                    async move {
                        pushed.lock().unwrap().push(body);
                        axum::http::StatusCode::NO_CONTENT
                    }
                },
            ),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pop_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, pop).await.unwrap() });

    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let private_b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
    let configured = private_b64.clone();
    let app = TestApp::spawn_with_settings(move |s| {
        s.turn.url = Some("turn:coturn.example:3478".into());
        s.turn.shared_secret = Some(ObjectId::new().to_hex());
        s.relay.regions_enabled = true;
        s.relay.regions = Some(format!(
            r#"[{{"id":"pop-test","turn_url":"turn:coturn-pop.example:3478","stats_urls":["http://{pop_addr}/stats"]}}]"#
        ));
        s.relay.stats_poll_secs = 1;
        s.relay.derp_ticket_private_key = Some(configured);
    })
    .await;
    let Some(redis) = net(&app).redis_pubsub.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let key = relay_allowance::set_key(app.db.name());
    let network = ObjectId::new().to_hex();

    // The PoP's half: the public key, exactly as a PoP is configured.
    let signer = DerpTicketSigner::from_pkcs8_b64(&private_b64).unwrap();
    let public = derp_ticket::decoding_key_from_public_b64(signer.public_key_b64()).unwrap();
    let newest = |want_network: bool| {
        pushed.lock().unwrap().iter().rev().find_map(|t| {
            derp_ticket::verify_allowance_set(t, &public)
                .ok()
                .filter(|c| c.set.contains_key(&network) == want_network)
        })
    };

    // The module's own job runs at startup and, with the switch off, deletes
    // the set: write it again on every wait.
    let deadline = Instant::now() + Duration::from_secs(15);
    let claims = loop {
        redis
            .kv_set_ex(&key, &format!(r#"{{"{network}":125000}}"#), 900)
            .await
            .unwrap();
        if let Some(c) = newest(true) {
            break c;
        }
        assert!(Instant::now() < deadline, "no signed set reached the PoP");
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(claims.set.get(&network), Some(&125_000));
    assert_eq!(claims.ttl, 3, "a PoP keeps it three polls of 1 s");

    // No set published: an empty one is pushed, and the PoP lets go.
    pushed.lock().unwrap().clear();
    redis.kv_del(&key).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let empty = loop {
        if let Some(c) = newest(false) {
            break c;
        }
        assert!(Instant::now() < deadline, "no empty set reached the PoP");
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert!(empty.set.is_empty(), "{empty:?}");
}
