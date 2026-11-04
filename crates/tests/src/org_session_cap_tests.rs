// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P3 — an organization's concurrent remote-session cap, through real
//! servers, real sockets and a real MongoDB.
//!
//! Free runs one session at a time per org, Pro one per billed seat, Business
//! any number. A request over the cap is refused at start with
//! `org_session_limit`, naming who holds the slot and on which device, and the
//! session holding it is untouched. `rc.org_session_cap = false` lifts the
//! cap. A request relayed to the pod that owns the device carries the cap the
//! origin pod's gate read, or a cross-pod request would skip it.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Enroll a device owned by the seeded admin and connect it to `app`.
async fn connect_agent(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> (String, Ws) {
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
    let agent_id = ej["agent_id"].as_str().unwrap().to_string();
    let token = ej["agent_token"].as_str().unwrap().to_string();
    let url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        urlencode(&token)
    );
    let (mut ws, _) = connect_async(&url).await.expect("agent ws");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": machine_id,
        "os": "linux",
        "agent_version": "0.1.0",
        "displays": [],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"], "has_input_permission": true,
            "supports_clipboard": true, "supports_file_transfer": true,
            "max_simultaneous_sessions": 4, "input": ["arbiter"], "rpc": [],
        },
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    (agent_id, ws)
}

/// The next frame of type `t` on `ws` within `within`, or `None`.
async fn next_of(ws: &mut Ws, t: &str, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(250), ws.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v["t"] == t {
            return Some(v);
        }
    }
    None
}

/// Ask `app` for a session on `agent_id` as `token`: the controller's socket,
/// kept open so the session stays live, and its answer — `rc:session.created`
/// or `rc:error`.
async fn ask(app: &TestApp, token: &str, agent_id: &str) -> (Ws, Value) {
    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ctl, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(200), ctl.next()).await;
    ctl.send(Message::Text(
        json!({
            "t": "rc:session.request",
            "agent_id": agent_id,
            "permissions": "VIEW | INPUT",
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(250), ctl.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v["t"] == "rc:session.created" || v["t"] == "rc:error" {
            return (ctl, v);
        }
    }
    panic!("no answer to the session request within 5 s");
}

fn created(answer: &Value) -> String {
    assert_eq!(answer["t"], "rc:session.created", "{answer}");
    answer["session_id"].as_str().unwrap().to_string()
}

fn refused_by_the_cap(answer: &Value) -> String {
    assert_eq!(answer["t"], "rc:error", "{answer}");
    assert_eq!(answer["code"], "org_session_limit", "{answer}");
    answer["message"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_free_org_runs_one_session_at_a_time_and_names_the_holder() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr115cap1").await;
    let (a, _a_ws) = connect_agent(&app, &seeded, "mach-fr115-cap-a").await;
    let (b, _b_ws) = connect_agent(&app, &seeded, "mach-fr115-cap-b").await;
    let token = &seeded.admin.access_token;

    let (mut first, answer) = ask(&app, token, &a).await;
    let held = created(&answer);

    let (_second, answer) = ask(&app, token, &b).await;
    let message = refused_by_the_cap(&answer);
    assert!(
        message.contains("fr115cap1 Admin"),
        "the refusal names who holds the slot: {message}"
    );
    assert!(
        message.contains("mach-fr115-cap-a"),
        "and on which device: {message}"
    );
    assert!(
        next_of(&mut first, "rc:terminate", Duration::from_secs(1))
            .await
            .is_none(),
        "the session holding the slot is untouched by the refusal"
    );

    // Ended, the slot is free again.
    let r = app
        .auth_post(
            &format!(
                "/api/tenant/{}/session/{}/terminate",
                seeded.tenant_id, held
            ),
            token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let mut freed = None;
    for _ in 0..10 {
        let (ctl, answer) = ask(&app, token, &b).await;
        if answer["t"] == "rc:session.created" {
            freed = Some((ctl, answer));
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(freed.is_some(), "the slot frees when its session ends");
}

/// Pro is one session per billed seat: two seats run two at once, not three.
#[tokio::test]
async fn a_pro_org_runs_one_session_per_seat() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr115cap2").await;
    app.db
        .collection::<bson::Document>("tenants")
        .update_one(
            bson::doc! { "_id": bson::oid::ObjectId::parse_str(&seeded.tenant_id).unwrap() },
            bson::doc! { "$set": { "plan": "pro", "billing": { "seats": 2 } } },
        )
        .await
        .unwrap();
    let (a, _a_ws) = connect_agent(&app, &seeded, "mach-fr115-cap2-a").await;
    let (b, _b_ws) = connect_agent(&app, &seeded, "mach-fr115-cap2-b").await;
    let (c, _c_ws) = connect_agent(&app, &seeded, "mach-fr115-cap2-c").await;
    let token = &seeded.admin.access_token;

    let (_one, answer) = ask(&app, token, &a).await;
    created(&answer);
    let (_two, answer) = ask(&app, token, &b).await;
    created(&answer);
    let (_three, answer) = ask(&app, token, &c).await;
    let message = refused_by_the_cap(&answer);
    assert!(
        message.contains("runs 2 remote sessions at a time"),
        "the refusal says the cap: {message}"
    );
    assert!(
        message.contains("move to Business"),
        "and the way past it a Pro org has: {message}"
    );
}

#[tokio::test]
async fn a_business_org_runs_several_at_once() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr115cap3").await;
    app.set_plan(&seeded.tenant_id, "business").await;
    let (a, _a_ws) = connect_agent(&app, &seeded, "mach-fr115-cap3-a").await;
    let (b, _b_ws) = connect_agent(&app, &seeded, "mach-fr115-cap3-b").await;
    let token = &seeded.admin.access_token;

    let (_one, answer) = ask(&app, token, &a).await;
    created(&answer);
    let (_two, answer) = ask(&app, token, &b).await;
    created(&answer);
}

/// A server without the hosted `saas` module sells no plans (the self-hosted
/// image is built that way), so it caps nobody's sessions: a Free org runs
/// several at once.
#[tokio::test]
async fn a_server_that_sells_no_plans_caps_no_sessions() {
    let app = TestApp::spawn_with_settings(|s| s.modules.saas = false).await;
    let seeded = app.seed_tenant("fr115cap6").await;
    let (a, _a_ws) = connect_agent(&app, &seeded, "mach-fr115-cap6-a").await;
    let (b, _b_ws) = connect_agent(&app, &seeded, "mach-fr115-cap6-b").await;
    let token = &seeded.admin.access_token;

    let (_one, answer) = ask(&app, token, &a).await;
    created(&answer);
    let (_two, answer) = ask(&app, token, &b).await;
    created(&answer);
}

#[tokio::test]
async fn the_kill_switch_lifts_the_cap() {
    let app = TestApp::spawn_with_settings(|s| s.rc.org_session_cap = false).await;
    let seeded = app.seed_tenant("fr115cap4").await;
    let (a, _a_ws) = connect_agent(&app, &seeded, "mach-fr115-cap4-a").await;
    let (b, _b_ws) = connect_agent(&app, &seeded, "mach-fr115-cap4-b").await;
    let token = &seeded.admin.access_token;

    let (_one, answer) = ask(&app, token, &a).await;
    created(&answer);
    let (_two, answer) = ask(&app, token, &b).await;
    created(&answer);
}

/// ⚠️ The relay is an entry point too. The controller asks on pod 2 for
/// devices homed on pod 1: pod 2's gate reads the cap, and pod 1's hub, which
/// holds the org's sessions, must apply it.
#[tokio::test]
async fn a_cross_pod_request_carries_the_cap() {
    let (app1, app2) = TestApp::spawn_pair(|_| {}).await;
    if app1.state.cluster_bus.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    for _ in 0..40 {
        let a = app1.state.cluster_bus.as_ref().unwrap();
        let b = app2.state.cluster_bus.as_ref().unwrap();
        if a.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
            && b.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seeded = app1.seed_tenant("fr115cap5").await;
    let (a, _a_ws) = connect_agent(&app1, &seeded, "mach-fr115-cap5-a").await;
    let (b, _b_ws) = connect_agent(&app1, &seeded, "mach-fr115-cap5-b").await;
    let token = &seeded.admin.access_token;
    // Pod 2 routes by the agents' presence records, which pod 1 writes late
    // in the hello: wait until pod 2 itself reads both online.
    for agent in [&a, &b] {
        let row_url = app2.url(&format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent));
        let mut online = false;
        for _ in 0..50 {
            let row: Value = app2
                .client
                .get(&row_url)
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if row["presence"] == "online" {
                online = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(online, "pod 2 never read {agent} online");
    }

    let (_one, answer) = ask(&app2, token, &a).await;
    created(&answer);
    let (_two, answer) = ask(&app2, token, &b).await;
    let message = refused_by_the_cap(&answer);
    assert!(
        message.contains("mach-fr115-cap5-a"),
        "the owner pod names the holder: {message}"
    );
}

// ── FR-115 P3b — session slots, the cluster-wide count ──────────────────

/// Two pods whose cluster buses are up, both under `mutator`.
async fn two_pods(mutator: fn(&mut meshharbor_config::Settings)) -> Option<(TestApp, TestApp)> {
    let (app1, app2) = TestApp::spawn_pair(mutator).await;
    if app1.state.cluster_bus.is_none() || app1.state.session_slots.is_none() {
        eprintln!("skipping: no Redis available");
        return None;
    }
    for _ in 0..40 {
        let a = app1.state.cluster_bus.as_ref().unwrap();
        let b = app2.state.cluster_bus.as_ref().unwrap();
        if a.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
            && b.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Some((app1, app2))
}

fn slots_on(s: &mut meshharbor_config::Settings) {
    s.rc.session_slots = true;
}

/// With slots on, the cap is cluster-wide. A Free org's session to its device
/// on pod 1 holds its one slot, so a request on pod 2 for the org's device
/// THERE is refused, naming the first; P3's count, kept per hub, let both open
/// (`with_slots_off_each_hub_counts_its_own`). Ending the first gives the
/// slot back.
#[tokio::test]
async fn slots_count_an_orgs_sessions_across_pods() {
    let Some((app1, app2)) = two_pods(slots_on).await else {
        return;
    };
    let seeded = app1.seed_tenant("fr115slot1").await;
    let (a, _a_ws) = connect_agent(&app1, &seeded, "mach-fr115-slot1-a").await;
    let (b, _b_ws) = connect_agent(&app2, &seeded, "mach-fr115-slot1-b").await;
    let token = &seeded.admin.access_token;

    let (_one, answer) = ask(&app1, token, &a).await;
    let first = created(&answer);
    let (_two, answer) = ask(&app2, token, &b).await;
    let message = refused_by_the_cap(&answer);
    assert!(
        message.contains("mach-fr115-slot1-a"),
        "pod 2 names the holder on pod 1: {message}"
    );

    let r = app1
        .auth_post(
            &format!(
                "/api/tenant/{}/session/{}/terminate",
                seeded.tenant_id, first
            ),
            token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let mut freed = None;
    for _ in 0..15 {
        let (ctl, answer) = ask(&app2, token, &b).await;
        if answer["t"] == "rc:session.created" {
            freed = Some((ctl, answer));
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(freed.is_some(), "the slot comes back when its session ends");
}

/// The kill switch (`rc.session_slots = false`, the default): P3's count on
/// each hub, which sees only its own sessions, so the same two requests both
/// open. This is the gap the slots close.
#[tokio::test]
async fn with_slots_off_each_hub_counts_its_own() {
    let Some((app1, app2)) = two_pods(|_| {}).await else {
        return;
    };
    let seeded = app1.seed_tenant("fr115slot2").await;
    let (a, _a_ws) = connect_agent(&app1, &seeded, "mach-fr115-slot2-a").await;
    let (b, _b_ws) = connect_agent(&app2, &seeded, "mach-fr115-slot2-b").await;
    let token = &seeded.admin.access_token;
    let (_one, answer) = ask(&app1, token, &a).await;
    created(&answer);
    let (_two, answer) = ask(&app2, token, &b).await;
    created(&answer);
}

/// The claim itself, against the real Redis: a free slot is claimed, a retry
/// for the same session renews it, a full set names its holder, an expired
/// lease is dropped before counting, and a release frees the slot.
#[tokio::test]
async fn the_slot_claim_claims_renews_refuses_and_expires() {
    use bson::oid::ObjectId;
    use meshharbor_core::cluster::session_slots::{SlotClaim, SlotScope};
    let app = TestApp::spawn_with_settings(slots_on).await;
    let (Some(slots), Some(redis)) = (
        app.state.session_slots.clone(),
        app.state.redis_pubsub.clone(),
    ) else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let org = SlotScope::Org(ObjectId::new());
    let (s1, s2) = (ObjectId::new(), ObjectId::new());
    let (user, device) = (ObjectId::new(), ObjectId::new());
    let pod = "fr115-test-pod";

    assert_eq!(
        slots.claim(org, s1, user, device, 1, pod).await.unwrap(),
        SlotClaim::Claimed
    );
    assert_eq!(
        slots.claim(org, s1, user, device, 1, pod).await.unwrap(),
        SlotClaim::Renewed
    );
    match slots.claim(org, s2, user, device, 1, pod).await.unwrap() {
        SlotClaim::Full(holders) => {
            assert_eq!(holders.len(), 1, "{holders:?}");
            assert_eq!(holders[0].session, s1.to_hex());
            assert_eq!(holders[0].user, user.to_hex());
            assert_eq!(holders[0].device, device.to_hex());
            assert_eq!(holders[0].pod, pod);
        }
        other => panic!("one slot, held: {other:?}"),
    }
    // A pod that died stops renewing: age the lease into the past.
    let mut conn = redis.connection();
    redis::cmd("ZADD")
        .arg(slots.slots_key(org))
        .arg(1)
        .arg(s1.to_hex())
        .query_async::<()>(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        slots.claim(org, s2, user, device, 1, pod).await.unwrap(),
        SlotClaim::Claimed
    );
    assert_eq!(
        slots.held(org).await.unwrap(),
        1,
        "the expired lease is gone"
    );
    slots.release(org, s2).await.unwrap();
    assert_eq!(slots.held(org).await.unwrap(), 0);
    // Renewal only updates: a lease released while a round was in flight is
    // answered missing and never put back. `restore` puts back the ones the
    // hub still holds (a Redis that lost them).
    let lease = meshharbor_core::cluster::session_slots::Lease {
        scope: org,
        session: s2,
        user,
        device,
    };
    let missing = slots.renew(std::slice::from_ref(&lease)).await.unwrap();
    assert_eq!(missing, vec![lease.clone()]);
    assert_eq!(
        slots.held(org).await.unwrap(),
        0,
        "renewal never resurrects a slot"
    );
    slots.restore(&missing, pod).await.unwrap();
    assert_eq!(slots.held(org).await.unwrap(), 1, "restore puts it back");
    // Another payer's slots are its own.
    let account = SlotScope::User(ObjectId::new());
    assert_eq!(
        slots
            .claim(account, s1, user, device, 1, pod)
            .await
            .unwrap(),
        SlotClaim::Claimed
    );
}

/// A slot THIS pod claimed for a session its hub no longer holds (a release
/// that failed) does not lock the org out for a whole lease: the next request
/// drops it and claims. The same lease claimed by ANOTHER pod is never judged
/// here, and refuses as any held slot does.
#[tokio::test]
async fn a_stale_slot_this_pod_claimed_does_not_lock_the_org_out() {
    use bson::oid::ObjectId;
    use meshharbor_core::cluster::session_slots::SlotScope;
    let app = TestApp::spawn_with_settings(slots_on).await;
    let Some(slots) = app.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app.seed_tenant("fr115slot3").await;
    let org = SlotScope::Org(ObjectId::parse_str(&seeded.tenant_id).unwrap());
    let (a, _a_ws) = connect_agent(&app, &seeded, "mach-fr115-slot3-a").await;
    let token = &seeded.admin.access_token;
    let ghost = ObjectId::new();

    slots
        .claim(
            org,
            ghost,
            ObjectId::new(),
            ObjectId::new(),
            1,
            "another-pod",
        )
        .await
        .unwrap();
    let (_refused, answer) = ask(&app, token, &a).await;
    refused_by_the_cap(&answer);

    slots.release(org, ghost).await.unwrap();
    slots
        .claim(
            org,
            ghost,
            ObjectId::new(),
            ObjectId::new(),
            1,
            &app.state.pod.pod_id,
        )
        .await
        .unwrap();
    let (_live, answer) = ask(&app, token, &a).await;
    created(&answer);
}

/// O6 + O7 — whose slots an external session takes: the org the outsider
/// names when they belong to it, else their only org, else (none, or several
/// and none named) the account with Free's one. No paid org is needed, a
/// Business org is unlimited, and an org they are not in is never charged.
#[tokio::test]
async fn an_external_session_is_charged_to_the_org_it_is_for() {
    use bson::oid::ObjectId;
    use meshharbor_mod_remote::extauth::charge_scope;
    use meshharbor_core::cluster::session_slots::SlotScope;
    let app = TestApp::spawn().await;
    let remote = app
        .state
        .modules
        .remote
        .clone()
        .expect("the remote module is mounted in tests");
    let free = app.seed_tenant("fr115chg1").await;
    let free_org = ObjectId::parse_str(&free.tenant_id).unwrap();
    let outsider = ObjectId::parse_str(&free.admin.id).unwrap();

    // One org (Free): it, at Free's one, with nothing named.
    assert_eq!(
        charge_scope(&remote, outsider, None).await,
        Some((SlotScope::Org(free_org), Some(1)))
    );
    // An org they are not in is never charged: the default applies.
    let other = app.seed_tenant("fr115chg2").await;
    assert_eq!(
        charge_scope(&remote, outsider, Some(&other.tenant_id)).await,
        Some((SlotScope::Org(free_org), Some(1)))
    );
    // In no org at all: the account, at Free's one.
    let stranger = ObjectId::new();
    assert_eq!(
        charge_scope(&remote, stranger, None).await,
        Some((SlotScope::User(stranger), Some(1)))
    );
    // A Business org they name is unlimited (nothing to claim).
    let biz = ObjectId::parse_str(&other.tenant_id).unwrap();
    app.set_plan(&other.tenant_id, "business").await;
    app.state
        .tenants
        .add_member(biz, outsider, vec![], None)
        .await
        .unwrap();
    assert_eq!(
        charge_scope(&remote, outsider, Some(&other.tenant_id)).await,
        Some((SlotScope::Org(biz), None))
    );
    // Two orgs and none named: the account, at Free's one.
    assert_eq!(
        charge_scope(&remote, outsider, None).await,
        Some((SlotScope::User(outsider), Some(1)))
    );
}
