// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P4b (AC8) — coturn's statistics DB into `turn_bytes` per org,
//! through real servers, a real Redis and a real MongoDB. The test plays
//! coturn: it publishes an allocation's totals on coturn's channels, in
//! coturn's format, under usernames issued the way the server issues them
//! (`turn_creds::charged`).
//!
//! ⚠️ Every TestApp with `turn_attribution` on subscribes to the same Redis,
//! so tests running at once hear each other's messages (and record them in
//! their own databases). Each test asserts only on its own ids.

use std::time::{Duration, Instant};

use bson::{Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_remote_control::turn_creds::{charged, org_of_username};
use serde_json::{Value, json};

use crate::fixtures::{seed::SeededTenant, test_app::TestApp};

fn attribution_on(s: &mut meshharbor_config::Settings) {
    s.relay_allowance.turn_attribution = true;
}

/// The database's `turn_bytes` for `tenant`, summed over its buckets.
async fn turn_bytes(app: &TestApp, tenant: ObjectId) -> i64 {
    let mut cursor = app
        .db
        .collection::<Document>("stats_usage")
        .find(doc! { "tenant_id": tenant, "meter": "turn_bytes" })
        .await
        .unwrap();
    let mut total = 0i64;
    while let Some(row) = cursor.try_next().await.unwrap() {
        total += row.get_i64("value").unwrap_or(0);
    }
    total
}

/// coturn's two total channels for one allocation: the client leg, and the
/// relay ↔ peer leg.
fn channels(username: &str, allocation: u64) -> (String, String) {
    let client =
        format!("turn/realm/roomler.ai/user/{username}/allocation/{allocation:018}/total_traffic");
    let peer = format!("{client}/peer");
    (client, peer)
}

/// One allocation's two legs, charged to an org, are counted once for that
/// org as what coturn SENT: toward the client plus toward the peer, though
/// both pods hear every message. The subscriptions are asynchronous, so the
/// test publishes until the total lands, then publishes the same allocation
/// again: a repeat is the same allocation leg, and must not count twice.
#[tokio::test]
async fn a_charged_allocation_is_counted_once_across_pods() {
    let (app1, _app2) = TestApp::spawn_pair(attribution_on).await;
    let Some(redis) = app1.state.redis_pubsub.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let t = app1.seed_tenant("fr115turn1").await;
    let org = ObjectId::parse_str(&t.tenant_id).unwrap();
    let principal = charged(&ObjectId::new().to_hex(), &org.to_hex());
    let (client, peer) = channels(&format!("1792000000:{principal}"), 4242);

    // Publish until both legs have landed, and keep publishing the same
    // allocation for two more rounds after that.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut rounds_since_counted = 0;
    while rounds_since_counted < 3 && Instant::now() < deadline {
        redis
            .publish_to(&client, "rcvp=10, rcvb=1000, sentp=20, sentb=50000")
            .await
            .unwrap();
        redis
            .publish_to(&peer, "rcvp=20, rcvb=50000, sentp=10, sentb=1000")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        if turn_bytes(&app1, org).await >= 51_000 {
            rounds_since_counted += 1;
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        turn_bytes(&app1, org).await,
        51_000,
        "each leg once: 50,000 sent toward the client plus 1,000 toward the peer"
    );
}

/// A username that names no org is counted nowhere. The case that matters
/// is an overlay pair's: its principal is `<node>:<node>`, so uncharged it
/// still ends in an ObjectId, and a parser that took the last hex part for
/// the org would book the bytes under a node. A charged control proves the
/// subscription was live.
#[tokio::test]
async fn a_username_naming_no_org_is_not_counted() {
    let app = TestApp::spawn_with_settings(attribution_on).await;
    let Some(redis) = app.state.redis_pubsub.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let t = app.seed_tenant("fr115turn2").await;
    let org = ObjectId::parse_str(&t.tenant_id).unwrap();
    let (a, b) = (ObjectId::new(), ObjectId::new());
    let pair = format!("{}:{}", a.to_hex(), b.to_hex());
    let (uncharged, _) = channels(&format!("1792000000:{pair}"), 7);
    let (control, _) = channels(&format!("1792000000:{}", charged(&pair, &org.to_hex())), 8);

    let deadline = Instant::now() + Duration::from_secs(20);
    while turn_bytes(&app, org).await < 9_000 && Instant::now() < deadline {
        redis
            .publish_to(&uncharged, "rcvp=1, rcvb=1, sentp=1, sentb=777")
            .await
            .unwrap();
        redis
            .publish_to(&control, "rcvp=1, rcvb=1, sentp=1, sentb=9000")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(turn_bytes(&app, org).await, 9_000, "the control is counted");
    assert_eq!(
        turn_bytes(&app, b).await,
        0,
        "nothing is booked under the node an uncharged pair username ends with"
    );
}

/// TURN configured, with a secret made at runtime.
fn turn_on(s: &mut meshharbor_config::Settings) {
    s.turn.url = Some("turn:coturn.example:3478".into());
    s.turn.shared_secret = Some(ObjectId::new().to_hex());
}

/// Enroll one device into `seeded`'s org; its id.
async fn enroll(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> String {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ej: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": machine_id,
            "os": "linux",
            "agent_version": "0.1.0",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ej["agent_id"].as_str().unwrap().to_string()
}

/// The TURN username a pre-fetch with `query` issues. A pre-fetch is never
/// refused over whom to charge.
async fn prefetch_username(app: &TestApp, token: &str, query: &str) -> String {
    let resp = app
        .auth_get(&format!("/api/turn/credentials{query}"), token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "pre-fetch {query:?}");
    let body: Value = resp.json().await.unwrap();
    body["ice_servers"][1]["username"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The RC viewer builds its peer connection from the session-less
/// pre-fetch, so that is where the browser leg is charged: to the device's
/// org, when the caller names it, is a member of it, and the device is live
/// there. Every other shape is the uncharged credential, as before.
#[tokio::test]
async fn the_rc_prefetch_is_charged_to_the_devices_org() {
    let app = TestApp::spawn_with_settings(turn_on).await;
    let home = app.seed_tenant("fr115turn3").await;
    let elsewhere = app.seed_tenant("fr115turn4").await;
    let device = enroll(&app, &home, "mach-fr115-turn").await;
    let home_tid = home.tenant_id.clone();
    let token = home.admin.access_token.clone();

    let named = format!("?tenant_id={home_tid}&agent_id={device}");
    let u = prefetch_username(&app, &token, &named).await;
    assert_eq!(org_of_username(&u), Some(home_tid.as_str()), "{u}");

    // Uncharged: nothing named (the pre-FR-115 viewer, an external session).
    let u = prefetch_username(&app, &token, "").await;
    assert_eq!(org_of_username(&u), None, "{u}");
    // Uncharged: an id that does not parse.
    let u = prefetch_username(
        &app,
        &token,
        &format!("?tenant_id=nothex&agent_id={device}"),
    )
    .await;
    assert_eq!(org_of_username(&u), None, "{u}");

    // Uncharged: the caller names an org they are not a member of.
    let outsider = elsewhere.admin.access_token.clone();
    let u = prefetch_username(&app, &outsider, &named).await;
    assert_eq!(org_of_username(&u), None, "a non-member: {u}");
    // Uncharged: the caller's own org, with a device that lives elsewhere.
    let u = prefetch_username(
        &app,
        &outsider,
        &format!("?tenant_id={}&agent_id={device}", elsewhere.tenant_id),
    )
    .await;
    assert_eq!(org_of_username(&u), None, "a device of another org: {u}");
}
