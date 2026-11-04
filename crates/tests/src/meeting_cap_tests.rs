// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P5 — the meeting-length cap against real MongoDB, Redis and a real
//! socket: a Free meeting is warned once at 55 minutes and ended at 60, a
//! paid one runs on, two pods warn and end a meeting once, a sweep never ends
//! the next meeting in the room, and the kill switch stops the cap.
//!
//! The clock moves by back-dating the room's `actual_start_time`, and the
//! sweep is driven by hand (`meeting_cap::sweep`). Every app also runs its own
//! sweep every 30 s; the writes are conditional, so the assertions read the
//! outcome (the room, the socket, the counter), never which sweep produced it.

use std::time::Duration;

use bson::{DateTime, Document, doc, oid::ObjectId};
use futures::StreamExt;
use serde_json::Value;

use crate::fixtures::test_app::TestApp;
use meshharbor_mod_conference::{ConferenceState, meeting_cap};
use meshharbor_services::dao::growth::{GROWTH_DAILY, QUOTA_COLLISION_METRIC, QUOTA_SOURCE};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn conf(app: &TestApp) -> &ConferenceState {
    app.state
        .modules
        .conference
        .as_ref()
        .expect("the conference module is mounted in tests")
}

fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).unwrap()
}

async fn socket(app: &TestApp, token: &str) -> Ws {
    let url = format!("ws://{}/ws?token={token}", app.addr);
    let (ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("the user socket opens");
    ws
}

/// The next frame of type `kind` within `within`, skipping every other frame.
async fn next_of(ws: &mut Ws, kind: &str, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.checked_duration_since(tokio::time::Instant::now())?;
        let frame = match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(frame))) => frame,
            _ => return None,
        };
        let Ok(text) = frame.to_text() else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        if v["type"] == kind {
            return Some(v);
        }
    }
}

async fn room(app: &TestApp, room: &str) -> Document {
    app.db
        .collection::<Document>("rooms")
        .find_one(doc! { "_id": oid(room) })
        .await
        .unwrap()
        .expect("the room exists")
}

async fn start_call(app: &TestApp, tenant: &str, room_id: &str, token: &str) -> ObjectId {
    let r = app
        .auth_post(
            &format!("/api/tenant/{tenant}/room/{room_id}/call/start"),
            token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    room(app, room_id)
        .await
        .get_object_id("current_call_id")
        .expect("the call is the room's")
}

/// Move the room's call start `minutes` into the past.
async fn started_ago(app: &TestApp, room_id: &str, minutes: i64) -> i64 {
    let at = DateTime::now().timestamp_millis() - minutes * 60_000;
    app.db
        .collection::<Document>("rooms")
        .update_one(
            doc! { "_id": oid(room_id) },
            doc! { "$set": { "actual_start_time": DateTime::from_millis(at) } },
        )
        .await
        .unwrap();
    at
}

/// The org's counted `meeting_max_minutes` collisions: waits up to 5 s for
/// the spawned write to reach `want`, then a little longer, so a second
/// (double) count that lands just behind the first is seen too.
async fn collisions(app: &TestApp, tenant: &str, want: i64) -> i64 {
    for _ in 0..50 {
        if collision_count(app, tenant).await >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    collision_count(app, tenant).await
}

async fn collision_count(app: &TestApp, tenant: &str) -> i64 {
    app.db
        .collection::<Document>(GROWTH_DAILY)
        .find_one(doc! {
            "source": QUOTA_SOURCE, "metric": QUOTA_COLLISION_METRIC,
            "dims.tenant": tenant, "dims.limit": "meeting_max_minutes",
        })
        .await
        .unwrap()
        .and_then(|d| d.get_i64("value").ok())
        .unwrap_or(0)
}

#[tokio::test]
async fn a_free_meeting_is_warned_once_at_55_and_ended_at_60() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("capfree").await;
    let (tid, rid, token) = (&t.tenant_id, &t.rooms[0].id, &t.admin.access_token);
    let mut ws = socket(&app, token).await;
    let call = start_call(&app, tid, rid, token).await;

    // Short of the warning line: nothing happens.
    started_ago(&app, rid, 54).await;
    let swept = meeting_cap::sweep(conf(&app), DateTime::now()).await;
    assert_eq!(swept, meeting_cap::Swept::default());
    assert!(room(&app, rid).await.get("cap_warned_call_id").is_none());

    // In the last five minutes: the participants are told when it ends.
    let started = started_ago(&app, rid, 56).await;
    meeting_cap::sweep(conf(&app), DateTime::now()).await;
    let warning = next_of(&mut ws, "room:call_ending_soon", Duration::from_secs(5))
        .await
        .expect("the meeting's members are warned");
    assert_eq!(warning["data"]["room_id"], rid.as_str());
    assert_eq!(warning["data"]["ends_at"], started + 60 * 60_000);
    assert_eq!(warning["data"]["max_minutes"], 60);
    assert_eq!(warning["data"]["plan"], "free");
    assert_eq!(
        room(&app, rid)
            .await
            .get_object_id("cap_warned_call_id")
            .unwrap(),
        call
    );

    // Once: the next sweep finds it warned.
    let again = meeting_cap::sweep(conf(&app), DateTime::now()).await;
    assert!(
        again.warned.is_empty(),
        "a warned meeting is not warned again"
    );
    assert!(
        next_of(&mut ws, "room:call_ending_soon", Duration::from_millis(500))
            .await
            .is_none()
    );

    // At sixty: ended, and the members are told why.
    started_ago(&app, rid, 61).await;
    meeting_cap::sweep(conf(&app), DateTime::now()).await;
    let ended = next_of(&mut ws, "room:call_ended", Duration::from_secs(5))
        .await
        .expect("the meeting's members are told it ended");
    assert_eq!(ended["data"]["room_id"], rid.as_str());
    assert_eq!(ended["data"]["reason"], "plan_limit");
    assert_eq!(ended["data"]["max_minutes"], 60);

    let r = room(&app, rid).await;
    assert_eq!(r.get_str("conference_status").unwrap(), "ended");
    assert!(r.get("current_call_id").is_none());
    let session = app
        .db
        .collection::<Document>("call_sessions")
        .find_one(doc! { "_id": call })
        .await
        .unwrap()
        .expect("stats are on in tests, so the call has a session");
    assert_eq!(session.get_str("end_reason").unwrap(), "plan_limit");
    assert_eq!(
        collisions(&app, tid, 1).await,
        1,
        "FR-102 counts the end once"
    );

    // A meeting started again gets its own sixty minutes.
    let next = start_call(&app, tid, rid, token).await;
    assert_ne!(next, call);
    let swept = meeting_cap::sweep(conf(&app), DateTime::now()).await;
    assert!(swept.ended.is_empty());
    assert_eq!(
        room(&app, rid).await.get_str("conference_status").unwrap(),
        "in_progress"
    );
}

#[tokio::test]
async fn a_paid_meeting_runs_past_sixty_minutes() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("cappro").await;
    let (tid, rid, token) = (&t.tenant_id, &t.rooms[0].id, &t.admin.access_token);
    app.db
        .collection::<Document>("tenants")
        .update_one(doc! { "_id": oid(tid) }, doc! { "$set": { "plan": "pro" } })
        .await
        .unwrap();
    let call = start_call(&app, tid, rid, token).await;

    started_ago(&app, rid, 180).await;
    let swept = meeting_cap::sweep(conf(&app), DateTime::now()).await;
    assert_eq!(swept, meeting_cap::Swept::default());
    let r = room(&app, rid).await;
    assert_eq!(r.get_str("conference_status").unwrap(), "in_progress");
    assert_eq!(r.get_object_id("current_call_id").unwrap(), call);
    assert!(r.get("cap_warned_call_id").is_none());
}

/// Two pods sweep the same calls at the same moment: the conditional writes
/// let exactly one of them warn, and exactly one end.
#[tokio::test]
async fn two_pods_warn_and_end_a_meeting_once() {
    let (a, b) = TestApp::spawn_pair(|_| {}).await;
    if a.state.redis_pubsub.is_none() || b.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    // Whichever pod wins the warning broadcasts it; pod b's reaches the
    // member's socket on pod a over the user pub/sub, so both subscriptions
    // must be live first.
    let live = |app: &TestApp| {
        app.state
            .redis_sub_alive
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    for _ in 0..50 {
        if live(&a) && live(&b) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(live(&a) && live(&b), "both pods' pub/sub came up");
    let t = a.seed_tenant("captwo").await;
    let (tid, rid, token) = (&t.tenant_id, &t.rooms[0].id, &t.admin.access_token);
    let mut ws = socket(&a, token).await;
    start_call(&a, tid, rid, token).await;

    started_ago(&a, rid, 56).await;
    let now = DateTime::now();
    let (sa, sb) = tokio::join!(
        meeting_cap::sweep(conf(&a), now),
        meeting_cap::sweep(conf(&b), now)
    );
    assert!(
        sa.warned.len() + sb.warned.len() <= 1,
        "one pod warns: {sa:?} {sb:?}"
    );
    assert!(
        next_of(&mut ws, "room:call_ending_soon", Duration::from_secs(10))
            .await
            .is_some(),
        "the member is warned, by whichever pod won: {sa:?} {sb:?}"
    );
    assert!(
        next_of(&mut ws, "room:call_ending_soon", Duration::from_millis(500))
            .await
            .is_none(),
        "the members are warned once"
    );

    started_ago(&a, rid, 61).await;
    let now = DateTime::now();
    let (sa, sb) = tokio::join!(
        meeting_cap::sweep(conf(&a), now),
        meeting_cap::sweep(conf(&b), now)
    );
    assert!(
        sa.ended.len() + sb.ended.len() <= 1,
        "one pod ends it: {sa:?} {sb:?}"
    );
    assert!(
        next_of(&mut ws, "room:call_ended", Duration::from_secs(10))
            .await
            .is_some(),
        "the member is told it ended, by whichever pod won: {sa:?} {sb:?}"
    );
    assert!(
        next_of(&mut ws, "room:call_ended", Duration::from_millis(500))
            .await
            .is_none(),
        "the meeting ends once"
    );
    assert_eq!(collisions(&a, tid, 1).await, 1);
}

/// A sweep reads a call, then writes. The writes name the call they read, so
/// one that lands after the meeting ended and another began touches nothing.
#[tokio::test]
async fn a_sweep_never_touches_the_next_meeting_in_the_room() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("capnext").await;
    let (tid, rid, token) = (&t.tenant_id, &t.rooms[0].id, &t.admin.access_token);
    let first = start_call(&app, tid, rid, token).await;
    let r = app
        .auth_post(&format!("/api/tenant/{tid}/room/{rid}/call/end"), token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let second = start_call(&app, tid, rid, token).await;

    let rooms = &conf(&app).rooms;
    assert!(!rooms.claim_cap_warning(oid(rid), first).await.unwrap());
    assert!(!rooms.end_call_if_current(oid(rid), first).await.unwrap());
    let r = room(&app, rid).await;
    assert_eq!(r.get_str("conference_status").unwrap(), "in_progress");
    assert_eq!(r.get_object_id("current_call_id").unwrap(), second);
    assert!(r.get("cap_warned_call_id").is_none());

    // The meeting it does name is its to warn, once, and to end.
    assert!(rooms.claim_cap_warning(oid(rid), second).await.unwrap());
    assert!(!rooms.claim_cap_warning(oid(rid), second).await.unwrap());
    assert!(rooms.end_call_if_current(oid(rid), second).await.unwrap());
    assert!(!rooms.end_call_if_current(oid(rid), second).await.unwrap());
}

/// A server without the hosted `saas` module sells no plans (the self-hosted
/// image is built that way), so no meeting on it ends on a plan's clock.
#[tokio::test]
async fn a_server_that_sells_no_plans_ends_no_meeting() {
    let app = TestApp::spawn_with_settings(|s| s.modules.saas = false).await;
    let t = app.seed_tenant("capselfhost").await;
    let (tid, rid, token) = (&t.tenant_id, &t.rooms[0].id, &t.admin.access_token);
    let call = start_call(&app, tid, rid, token).await;

    started_ago(&app, rid, 61).await;
    let swept = meeting_cap::sweep(conf(&app), DateTime::now()).await;
    assert_eq!(swept, meeting_cap::Swept::default());
    let r = room(&app, rid).await;
    assert_eq!(r.get_str("conference_status").unwrap(), "in_progress");
    assert_eq!(r.get_object_id("current_call_id").unwrap(), call);
    assert!(r.get("cap_warned_call_id").is_none());
}

#[tokio::test]
async fn the_kill_switch_lets_a_free_meeting_run() {
    let app = TestApp::spawn_with_settings(|s| s.meetings.free_cap = false).await;
    let t = app.seed_tenant("capoff").await;
    let (tid, rid, token) = (&t.tenant_id, &t.rooms[0].id, &t.admin.access_token);
    let call = start_call(&app, tid, rid, token).await;

    started_ago(&app, rid, 61).await;
    let swept = meeting_cap::sweep(conf(&app), DateTime::now()).await;
    assert_eq!(swept, meeting_cap::Swept::default());
    let r = room(&app, rid).await;
    assert_eq!(r.get_str("conference_status").unwrap(), "in_progress");
    assert_eq!(r.get_object_id("current_call_id").unwrap(), call);
}
