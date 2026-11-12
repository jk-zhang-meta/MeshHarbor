// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P0b — the server side of an agent session's lifecycle.
//!
//! Driven through a RAW agent socket, like FR-83's grant-ack tests: no
//! daemon runs sessions yet (P0c), and what these lock is the SERVER — that a
//! start reaches only a device that runs sessions, that the caller is
//! answered with the device's own words, that a frame from the wrong device
//! or an old fence changes nothing, that a device which was away is told
//! what it missed, and that removing a member or a device ends what ran for
//! it. A peer that decides exactly when — and whether — it answers is the
//! only way to observe those.

use std::time::{Duration, Instant};

use bson::{Document, doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::tunnel_tests::{enroll_agent, read_until, wait_agent_online};
use meshharbor_remote_control::hive::hive_limits;

type AgentWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// What a Hive-capable build advertises…
const RUNS_HIVE: &[&str] = &["exec", "hive"];
/// …and what every build before it does.
const NO_HIVE: &[&str] = &["exec", "ssh"];

/// `HIVE_RUN` — bit 32, the first permission above 31.
const HIVE_RUN: u64 = 1 << 32;

/// How long the device sits on a start before answering — far longer than a
/// same-host round trip, so an answer that did not wait for the device
/// cannot arrive after it by accident.
const HOLD: Duration = Duration::from_millis(1200);

struct Device {
    agent_id: String,
    token: String,
    machine: String,
    ws: AgentWs,
}

async fn hive_app() -> TestApp {
    // The module's switch defaults OFF; every test here but the first
    // turns it on. Raise the per-IP governor like `hive_app_polling` /
    // `replicaset_app`: `device()`, `start()`, `wait_status()`, and
    // `wait_offline()` all poll `/api` every 50 ms, which under loaded runs
    // exhausts `test_settings()`'s 60-request burst (1 req/s refill) and gets
    // a plain-text 429 before the awaited condition arrives.
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

async fn connect(app: &TestApp, token: &str, machine: &str, rpc: &[&str]) -> AgentWs {
    let url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut ws, _) = connect_async(&url).await.expect("agent ws connect");
    ws.send(Message::Text(
        json!({
            "t": "rc:agent.hello",
            "machine_name": machine,
            "os": "linux",
            "agent_version": "0.4.117",
            "displays": [],
            "caps": {
                "hw_encoders": [],
                "codecs": ["h264"],
                "has_input_permission": true,
                "supports_clipboard": false,
                "supports_file_transfer": false,
                "max_simultaneous_sessions": 4,
                "rpc": rpc,
            }
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    ws
}

/// Enrol a device in `seeded`'s org and connect a raw socket advertising
/// `rpc`; returns once the server holds it.
async fn device(app: &TestApp, seeded: &SeededTenant, machine: &str, rpc: &[&str]) -> Device {
    let (agent_id, token) = enroll_agent(app, seeded, machine, machine).await;
    let ws = connect(app, &token, machine, rpc).await;
    wait_agent_online(app, seeded, &agent_id).await;
    Device {
        agent_id,
        token,
        machine: machine.to_string(),
        ws,
    }
}

async fn send(ws: &mut AgentWs, frame: Value) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

/// `POST …/hive/session` once, as `token`.
async fn post_start(app: &TestApp, tid: &str, token: &str, device_id: &str, folder: &str) -> Value {
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/hive/session"), token)
        .json(&json!({ "device_id": device_id, "folder": folder }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "start");
    resp.json().await.unwrap()
}

/// `POST …/hive/session`, retrying ONLY the refusals that come from racing
/// the device's registration: the row reads online a moment before the Hub
/// has recorded the connection's capabilities (`update_hello` precedes
/// `register_agent`). Both are refused before any session is created and
/// before the ceiling spends a token, so a retry is safe.
async fn start(app: &TestApp, tid: &str, token: &str, device_id: &str, folder: &str) -> Value {
    for _ in 0..40 {
        let body = post_start(app, tid, token, device_id, folder).await;
        let racing = body["outcome"] == "refused"
            && body["session"].is_null()
            && matches!(
                body["reason"].as_str(),
                Some("device_offline" | "device_unsupported")
            );
        if !racing {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the Hub never recorded the device as running Hive sessions");
}

async fn get_session(app: &TestApp, tid: &str, token: &str, sid: &str) -> (u16, Value) {
    let resp = app
        .auth_get(&format!("/api/tenant/{tid}/hive/session/{sid}"), token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Poll a session until its status reads `want` — the device's reports are
/// applied by a per-connection task, after the frame is read.
async fn wait_status(app: &TestApp, tid: &str, token: &str, sid: &str, want: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (code, s) = get_session(app, tid, token, sid).await;
        assert_eq!(code, 200, "session read");
        if s["status"] == want {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "session {sid} never reached `{want}`: {s}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stop(app: &TestApp, tid: &str, token: &str, sid: &str) -> (u16, Value) {
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/hive/session/{sid}/stop"), token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The stored session, read past the API (for a removed member's).
async fn stored(app: &TestApp, sid: &str) -> Document {
    app.db
        .collection::<Document>("agent_sessions")
        .find_one(doc! { "_id": ObjectId::parse_str(sid).unwrap() })
        .await
        .unwrap()
        .expect("the session record")
}

async fn wait_offline(app: &TestApp, seeded: &SeededTenant, agent_id: &str) {
    for _ in 0..100 {
        let resp = app
            .auth_get(
                &format!("/api/tenant/{}/agent/{agent_id}", seeded.tenant_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "agent status read");
        let row: Value = resp.json().await.unwrap();
        if row["status"].as_str() != Some("online") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("agent {agent_id} never went offline");
}

/// Grant the seeded MEMBER a role holding `HIVE_RUN` (and nothing else).
async fn grant_hive_run_to_member(app: &TestApp, seeded: &SeededTenant) {
    let role: Value = app
        .auth_post(
            &format!("/api/tenant/{}/role", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&json!({
            "name": "hive-runner",
            "description": "starts agent sessions",
            "permissions": HIVE_RUN,
            "position": 60,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(role["permissions"], HIVE_RUN, "{role}");
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                seeded.tenant_id,
                role["id"].as_str().unwrap(),
                seeded.member.id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "assign: {:?}", resp.status());
}

/// The session room's messages as `token` reads them: (status, items).
async fn room_messages(app: &TestApp, tid: &str, token: &str, room: &str) -> (u16, Vec<Value>) {
    let resp = app
        .auth_get(
            &format!("/api/tenant/{tid}/room/{room}/message?per_page=100"),
            token,
        )
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    (status, v["items"].as_array().cloned().unwrap_or_default())
}

/// Poll the session room until `pred` holds for its messages — the device's
/// reports are applied, and their notes posted, by a task after the frame.
async fn wait_messages(
    app: &TestApp,
    tid: &str,
    token: &str,
    room: &str,
    what: &str,
    pred: impl Fn(&[Value]) -> bool,
) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (code, items) = room_messages(app, tid, token, room).await;
        assert_eq!(code, 200, "the owner reads the session's room");
        if pred(&items) {
            return items;
        }
        assert!(Instant::now() < deadline, "{what}: {items:#?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn bound_to(m: &Value, reference: &str) -> bool {
    m["binding"]["module"] == "hive" && m["binding"]["ref"] == reference
}

/// The module's switch is the one that defaults OFF: a roll that ships the
/// code serves none of it until an operator turns it on.
#[tokio::test]
async fn the_module_is_off_by_default_and_serves_nothing() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("hiveoff").await;
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/hive/session", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&json!({ "device_id": ObjectId::new().to_hex(), "folder": "/srv" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "not mounted ⇒ no route");
}

// ─── P1g — the organizations agent sessions serve (`hive.tenants`) ─────────

/// A second server over `first`'s database serving only the organizations
/// listed — as `first` restarted with `hive.tenants` set. The list alone
/// switches the module on, with no `modules.hive`: the form a hosted server
/// uses, so these tests hold the one prod runs.
async fn serving_only(first: &TestApp, tenants: &str) -> TestApp {
    let db = first.db.name().to_string();
    let tenants = tenants.to_string();
    TestApp::spawn_with_settings(move |s| {
        s.database.name = db;
        s.hive.tenants = tenants;
        // Polls, like `hive_app_polling`: the default limiter answers a
        // poll loop 429 before the condition it waits for.
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// `hive.tenants` set: its organizations get every route; any other is
/// answered as if the module were not there for it, and someone outside an
/// organization learns nothing about whether it is served.
#[tokio::test]
async fn an_organization_hive_does_not_serve_sees_none_of_it() {
    let first = hive_app().await;
    let a = first.seed_tenant("hiveserved").await;
    let b = first.seed_tenant("hiveunserved").await;
    let app = serving_only(&first, &a.tenant_id).await;
    let get = |tid: &str, path: &str, token: &str| {
        let url = format!("/api/tenant/{tid}/hive{path}");
        app.auth_get(&url, token).send()
    };

    // A — served: the question, the list, the brain.
    let (code, body) =
        status_and_json(get(&a.tenant_id, "", &a.admin.access_token).await.unwrap()).await;
    assert_eq!(
        (code, body["enabled"].clone()),
        (200, json!(true)),
        "{body}"
    );
    for path in ["/session", "/brain"] {
        let resp = get(&a.tenant_id, path, &a.admin.access_token)
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{path}");
    }

    // B — not served: every route, read or write, is not found, in words.
    let (code, body) =
        status_and_json(get(&b.tenant_id, "", &b.admin.access_token).await.unwrap()).await;
    assert_eq!(code, 404, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("not available"),
        "{body}"
    );
    for path in ["/session", "/brain"] {
        let resp = get(&b.tenant_id, path, &b.admin.access_token)
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "{path}");
    }
    let start = app
        .auth_post(
            &format!("/api/tenant/{}/hive/session", b.tenant_id),
            &b.admin.access_token,
        )
        .json(&json!({ "device_id": ObjectId::new().to_hex(), "folder": "/srv" }))
        .send()
        .await
        .unwrap();
    assert_eq!(start.status().as_u16(), 404, "no start for an unserved org");
    let keep = app
        .auth_post(
            &format!("/api/tenant/{}/hive/brain", b.tenant_id),
            &b.admin.access_token,
        )
        .json(&json!({ "scope": "org", "text": "kept nowhere" }))
        .send()
        .await
        .unwrap();
    assert_eq!(keep.status().as_u16(), 404, "no fact for an unserved org");

    // The list alone switched the module on, and the server says so.
    let caps: Value = app
        .client
        .get(app.url("/api/capabilities"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let listed = |key: &str| caps[key].as_array().unwrap().iter().any(|m| m == "hive");
    assert!(listed("modules") && !listed("switched_off"), "{caps}");

    // Outside A: the answer is about membership, never about the gate.
    let (code, body) =
        status_and_json(get(&a.tenant_id, "", &b.admin.access_token).await.unwrap()).await;
    assert_eq!(
        (code, body["error"].clone()),
        (403, json!("not_a_member")),
        "{body}"
    );
}

/// An organization taken out of `hive.tenants`: when one of its devices
/// connects, what it still runs for that organization ends — the device is
/// told to stop, the record says why, and nothing of it can be read.
#[tokio::test]
async fn a_device_of_an_organization_no_longer_served_is_told_to_stop() {
    let first = hive_app_polling().await;
    let a = first.seed_tenant("hivestays").await;
    let b = first.seed_tenant("hiveleaves").await;
    let (tid, token) = (b.tenant_id.clone(), b.admin.access_token.clone());
    let mut dev = device(&first, &b, "hive-leaves", RUNS_HIVE).await;
    let sid = started_session(&first, &tid, &token, &mut dev).await;
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
    )
    .await;
    wait_status(&first, &tid, &token, &sid, "idle").await;
    drop(dev.ws);
    wait_offline(&first, &b, &dev.agent_id).await;

    // The server restarted without B in the list; B's device comes back.
    let app = serving_only(&first, &a.tenant_id).await;
    let mut ws = connect(&app, &dev.token, &dev.machine, RUNS_HIVE).await;
    let order = read_until(&mut ws, "rc:hive.stop")
        .await
        .expect("the device is told to stop what it runs for an unserved org");
    assert_eq!(order["session_id"], sid);
    assert_eq!(order["reason"], "hive_not_enabled");

    // The stop goes before the record is written (`hooks::end_and_tell`), so
    // the device can hear it first: the record is waited for, not read once.
    let s = wait_stored(&app, &sid, "ended for the unserved org", |s| {
        s.get_str("status") == Ok("ended")
    })
    .await;
    assert_eq!(s.get_str("end_reason").unwrap(), "hive_not_enabled");
    let (code, _) = get_session(&app, &tid, &token, &sid).await;
    assert_eq!(code, 404, "an unserved org's session cannot be read");
}

/// The whole round trip. The caller is answered only after the device
/// decided (held for [`HOLD`]); the start carries metadata and names no
/// account; the device's run states move the record; a stop reaches the
/// device and its `ended` closes the session as `stopped`.
#[tokio::test]
async fn a_start_reaches_the_device_and_the_caller_hears_the_device() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveflow").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-flow", RUNS_HIVE).await;

    let caller = async {
        let body = start(&app, &tid, &token, &dev.agent_id, "/home/dev/src/app").await;
        (body, Instant::now())
    };
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives rc:hive.start");
        tokio::time::sleep(HOLD).await;
        let acked_at = Instant::now();
        send(
            &mut dev.ws,
            json!({
                "t": "rc:hive.start_ack",
                "session_id": frame["session_id"],
                "fence": frame["fence"],
                "account": "dev",
            }),
        )
        .await;
        (frame, acked_at)
    };
    let ((body, answered_at), (frame, acked_at)) = tokio::join!(caller, target);

    assert!(
        answered_at >= acked_at,
        "the caller was answered {:?} BEFORE the device decided",
        acked_at - answered_at
    );
    assert_eq!(body["outcome"], "accepted", "{body}");
    let s = &body["session"];
    assert_eq!(s["status"], "starting", "accepted, harness not up yet: {s}");
    assert_eq!(s["account"], "dev", "the device's mapping is shown: {s}");
    assert_eq!(s["title"], "app", "the folder's last component: {s}");
    let sid = s["id"].as_str().unwrap().to_string();

    // The frame: who, where, which fence — and nothing else.
    assert_eq!(frame["session_id"], sid);
    assert_eq!(frame["fence"], 1);
    assert_eq!(frame["resume"], false);
    assert_eq!(frame["harness"], "claude-code");
    assert_eq!(frame["folder"], "/home/dev/src/app");
    assert_eq!(frame["user_id"], seeded.admin.id);
    assert_eq!(frame["harness_session"], s["harness_session"]);
    assert!(
        uuid::Uuid::parse_str(frame["harness_session"].as_str().unwrap()).is_ok(),
        "the harness id is a UUID: {frame}"
    );
    for absent in ["prompt", "account", "env", "context", "settings"] {
        assert!(frame.get(absent).is_none(), "`{absent}` in {frame}");
    }

    // Run states move the record, in order.
    for state in ["idle", "running", "awaiting_approval", "running", "idle"] {
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": state}),
        )
        .await;
    }
    wait_status(&app, &tid, &token, &sid, "idle").await;

    // A state this build cannot name keeps what it knew.
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "compacting"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        get_session(&app, &tid, &token, &sid).await.1["status"],
        "idle"
    );

    // Stop: the device is told, and its `ended` closes the session.
    let (code, stopped) = stop(&app, &tid, &token, &sid).await;
    assert_eq!(code, 200);
    assert_eq!(stopped["outcome"], "stopping", "{stopped}");
    let order = read_until(&mut dev.ws, "rc:hive.stop")
        .await
        .expect("the device receives rc:hive.stop");
    assert_eq!(order["session_id"], sid);
    assert_eq!(order["fence"], 1);
    assert_eq!(order["reason"], "owner");

    // An `idle` that crossed the stop on the wire does not undo it.
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        get_session(&app, &tid, &token, &sid).await.1["status"],
        "stopping"
    );

    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended",
               "detail": "stopped by request"}),
    )
    .await;
    let s = wait_status(&app, &tid, &token, &sid, "ended").await;
    assert_eq!(s["end_reason"], "stopped", "{s}");
    assert!(s["ended_at"].is_string(), "{s}");

    // Stopping again is idempotent and touches nothing.
    let (_, again) = stop(&app, &tid, &token, &sid).await;
    assert_eq!(again["outcome"], "ended");

    // The audit holds the server's two decisions — and no content.
    let audit: Vec<Document> = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "session_id": ObjectId::parse_str(&sid).unwrap() })
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let mut actions: Vec<(String, String)> = audit
        .iter()
        .map(|d| {
            (
                d.get_str("action").unwrap().to_string(),
                d.get_str("outcome").unwrap().to_string(),
            )
        })
        .collect();
    actions.sort();
    assert!(
        actions.contains(&("start".into(), "sent".into())),
        "{actions:?}"
    );
    assert!(
        actions.contains(&("stop".into(), "sent".into())),
        "{actions:?}"
    );
}

/// The REAL daemon's order: it reports `idle` the moment its harness is up
/// and answers the start right after, so the state lands first. The answer
/// must still be heard — the caller woken by it, its account recorded, the
/// room told. Field, 2026-10-07: every start lost its answer this way; the
/// caller waited out the whole bound and the account and note never came.
#[tokio::test]
async fn a_state_that_beats_the_devices_answer_does_not_lose_it() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveorder").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-order", RUNS_HIVE).await;

    let caller = async {
        let asked = Instant::now();
        let body = start(&app, &tid, &token, &dev.agent_id, "/home/dev/src/app").await;
        (body, asked.elapsed())
    };
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives rc:hive.start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.state", "session_id": frame["session_id"],
                   "fence": frame["fence"], "state": "idle"}),
        )
        .await;
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
    };
    let ((body, waited), ()) = tokio::join!(caller, target);

    assert_eq!(body["outcome"], "accepted", "{body}");
    let s = &body["session"];
    assert_eq!(s["account"], "dev", "the device's answer was heard: {s}");
    assert!(
        waited < Duration::from_secs(hive_limits::START_ACK_TIMEOUT_SECS / 2),
        "the caller waited {waited:?}: the answer was dropped and only the bound released it"
    );
    let sid = s["id"].as_str().unwrap().to_string();
    assert!(
        matches!(
            stored(&app, &sid).await.get("accepted_at"),
            Some(bson::Bson::DateTime(_))
        ),
        "the answer is on the record"
    );
    let room = s["room_id"].as_str().unwrap().to_string();
    wait_messages(
        &app,
        &tid,
        &token,
        &room,
        "the start note, with the account",
        |items| {
            items.iter().any(|m| {
                m["content"]
                    .as_str()
                    .is_some_and(|c| c.contains("Started on") && c.contains("**dev**"))
            })
        },
    )
    .await;
}

/// The device's gate is the caller's answer: which gate, in its own word,
/// with a message saying what to change.
#[tokio::test]
async fn a_device_refusal_is_the_callers_answer_with_its_gate() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiverefuse").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-refuse", RUNS_HIVE).await;

    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv/data");
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({
                "t": "rc:hive.start_ack",
                "session_id": frame["session_id"],
                "fence": 1,
                "refused": "no_account",
                "detail": "no hive_accounts entry\nfor this user",
            }),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);

    assert_eq!(body["outcome"], "refused", "{body}");
    assert_eq!(body["reason"], "no_account");
    assert!(
        body["message"].as_str().unwrap().contains("hive_accounts"),
        "{body}"
    );
    let s = &body["session"];
    assert_eq!(s["status"], "refused");
    assert_eq!(s["refusal"], "no_account");
    assert_eq!(
        s["detail"], "no hive_accounts entry for this user",
        "kept on one line"
    );

    // P0d — and the session's room says so, in the device's own words.
    let room = s["room_id"].as_str().expect("the session has a room");
    let items = wait_messages(&app, &tid, &token, room, "a refusal note", |items| {
        items.iter().any(|m| {
            m["content"]
                .as_str()
                .is_some_and(|c| c.contains("refused the session"))
        })
    })
    .await;
    let note = items
        .iter()
        .find(|m| m["content"].as_str().unwrap().contains("refused"))
        .unwrap();
    assert!(
        note["content"].as_str().unwrap().contains("hive_accounts"),
        "{note}"
    );
    assert_eq!(note["author_type"], "bot");
}

/// P0d — a session is a `Secret` room the session itself writes into: a
/// note when it starts, one stub per turn updated in place as the turn
/// finishes, a note when it ends. Nobody else in the org can see the room,
/// and a turn report from another device writes nothing.
#[tokio::test]
async fn a_session_is_a_secret_room_its_device_writes_stubs_into() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveroom").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-room", RUNS_HIVE).await;
    let mut stranger = device(&app, &seeded, "hive-room-x", RUNS_HIVE).await;

    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv/app");
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": f["session_id"], "fence": 1, "account": "dev"}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    let sid = body["session"]["id"].as_str().unwrap().to_string();
    let room = body["session"]["room_id"]
        .as_str()
        .expect("a session has a room")
        .to_string();

    // The room is the session's: bound to it, and secret to everyone else.
    let r: Value = app
        .auth_get(&format!("/api/tenant/{tid}/room/{room}"), &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["visibility"], "secret", "{r}");
    assert!(bound_to(&r, &sid), "{r}");
    assert_eq!(r["name"], "app", "titled like the session: {r}");
    let other = &seeded.member.access_token;
    let resp = app
        .auth_get(&format!("/api/tenant/{tid}/room/{room}"), other)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "a non-member learns nothing");
    assert_eq!(room_messages(&app, &tid, other, &room).await.0, 404);

    // …and not a channel: the plan's `max_channels` gate and the compliance
    // report count with `channel_filter`, which must not see a bound room,
    // or a few sessions would lock the org out of creating channels.
    // The seeded rooms are the positive control: a filter that saw nothing
    // would pass the absence alone.
    let rooms = app.db.collection::<Document>("rooms");
    let in_org = doc! { "tenant_id": ObjectId::parse_str(&tid).unwrap() };
    let mut live = doc! { "deleted_at": null };
    live.extend(in_org.clone());
    let mut channels = meshharbor_services::dao::room::RoomDao::channel_filter();
    channels.extend(in_org);
    let seeded_rooms = seeded.rooms.len() as u64;
    assert_eq!(rooms.count_documents(live).await.unwrap(), seeded_rooms + 1);
    assert_eq!(
        rooms.count_documents(channels).await.unwrap(),
        seeded_rooms,
        "the seeded rooms are channels; the session's room is not"
    );

    // The start note, authored by the session.
    let items = wait_messages(&app, &tid, &token, &room, "the start note", |items| {
        items.iter().any(|m| {
            m["content"]
                .as_str()
                .is_some_and(|c| c.contains("Started on"))
        })
    })
    .await;
    let started = items
        .iter()
        .find(|m| m["content"].as_str().unwrap().contains("Started on"))
        .unwrap();
    assert_eq!(started["author_type"], "bot");
    assert_eq!(started["author_name"], "Claude · hive-room");
    assert_eq!(started["author_id"], sid, "the session authors it");
    assert!(
        started["content"].as_str().unwrap().contains("**dev**"),
        "as the account the device reported: {started}"
    );

    // A turn starts: one stub, bound to the session's turn 1.
    let turn_ref = format!("{sid}#1");
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.turn", "session_id": sid, "fence": 1, "turn": 1,
               "status": "running", "prompted_by": seeded.admin.id, "steps": 0}),
    )
    .await;
    let items = wait_messages(&app, &tid, &token, &room, "a running stub", |items| {
        items.iter().any(|m| bound_to(m, &turn_ref))
    })
    .await;
    let stub = items.iter().find(|m| bound_to(m, &turn_ref)).unwrap();
    let stub_id = stub["id"].as_str().unwrap().to_string();
    let content = stub["content"].as_str().unwrap();
    assert!(
        content.contains("Turn 1") && content.contains("working"),
        "{content}"
    );
    assert!(content.contains("asked by"), "attributed: {content}");

    // It finishes: the SAME message is updated, no second stub.
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.turn", "session_id": sid, "fence": 1, "turn": 1,
               "status": "ok", "prompted_by": seeded.admin.id, "steps": 3,
               "duration_ms": 42000, "cost_usd": 0.12}),
    )
    .await;
    let items = wait_messages(&app, &tid, &token, &room, "the stub updated", |items| {
        items.iter().any(|m| {
            bound_to(m, &turn_ref) && m["content"].as_str().is_some_and(|c| c.contains("done"))
        })
    })
    .await;
    let stubs: Vec<&Value> = items.iter().filter(|m| bound_to(m, &turn_ref)).collect();
    assert_eq!(stubs.len(), 1, "one stub per turn: {stubs:#?}");
    assert_eq!(stubs[0]["id"], stub_id, "updated in place");
    let content = stubs[0]["content"].as_str().unwrap();
    assert!(
        content.contains("3 steps") && content.contains("42 s") && content.contains("$0.12"),
        "{content}"
    );

    // Another device's report for this session writes nothing. Its frame is
    // applied by ITS connection's task, so give that time before looking.
    let stranger_ref = format!("{sid}#2");
    send(
        &mut stranger.ws,
        json!({"t": "rc:hive.turn", "session_id": sid, "fence": 1, "turn": 2, "status": "running"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, items) = room_messages(&app, &tid, &token, &room).await;
    assert!(
        !items.iter().any(|m| bound_to(m, &stranger_ref)),
        "another device's turn report must not write into the room: {items:#?}"
    );

    // The session's device ends it: the end note follows, and the stranger's
    // turn 2 still never appeared.
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended",
               "detail": "the harness exited"}),
    )
    .await;
    let items = wait_messages(&app, &tid, &token, &room, "the end note", |items| {
        items.iter().any(|m| {
            m["content"]
                .as_str()
                .is_some_and(|c| c.contains("Session ended"))
        })
    })
    .await;
    assert!(
        !items.iter().any(|m| bound_to(m, &stranger_ref)),
        "another device's turn report must not write into the room: {items:#?}"
    );
}

/// Gate 4 (`HIVE_RUN`) for a plain member: a 200 carrying the reason, no
/// session created, nothing sent — and an audit row, because a refusal is
/// the interesting decision.
/// P1a-2 — an approval is ONE stub in the session's room, however often its
/// opening is replayed, edited to say how it ended; who answered is named
/// only when that is a driver; the driver is notified, naming the session
/// and never the call; and a session that ends with one open withdraws it.
#[tokio::test]
async fn an_approval_is_one_stub_that_says_how_it_ended() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveappr").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-appr", RUNS_HIVE).await;
    let sid = started_session(&app, &tid, &token, &mut dev).await;
    let (_, s) = get_session(&app, &tid, &token, &sid).await;
    let room = s["room_id"].as_str().expect("a room").to_string();
    let approval = |id: &str, status: &str, by: Option<&str>| {
        let mut f = json!({"t": "rc:hive.approval", "session_id": sid, "fence": 1,
                           "approval_id": id, "turn": 1, "status": status});
        if let Some(by) = by {
            f["answered_by"] = json!(by);
        }
        f
    };
    let record = |id: &'static str| {
        let db = app.db.clone();
        async move {
            db.collection::<Document>("agent_approvals")
                .find_one(doc! { "approval_id": id })
                .await
                .unwrap()
                .expect("on the record")
        }
    };
    let content = |items: &[Value], reference: &str| -> Vec<String> {
        items
            .iter()
            .filter(|m| bound_to(m, reference))
            .map(|m| m["content"].as_str().unwrap_or_default().to_string())
            .collect()
    };

    // Opened — and said again, as a reconnect replays it.
    let a1 = format!("{sid}!a1");
    send(&mut dev.ws, approval("a1", "open", None)).await;
    send(&mut dev.ws, approval("a1", "open", None)).await;
    wait_messages(&app, &tid, &token, &room, "the approval's stub", |items| {
        items.iter().any(|m| bound_to(m, &a1))
    })
    .await;
    // Past the replay: a stub for a frame it carried would be there by now.
    send(&mut dev.ws, approval("amarker", "open", None)).await;
    let items = wait_messages(&app, &tid, &token, &room, "the marker", |items| {
        items.iter().any(|m| bound_to(m, &format!("{sid}!amarker")))
    })
    .await;
    assert_eq!(
        content(&items, &a1),
        ["🔐 **Approval needed** · turn 1 — open the session to answer"],
        "one stub, however often it is said"
    );
    assert_eq!(record("a1").await.get_str("status").unwrap(), "open");
    let notes = app.db.collection::<Document>("notifications");
    let n = notes
        .find_one(doc! { "notification_type": "approval_request" })
        .await
        .unwrap()
        .expect("the driver was notified");
    assert_eq!(
        n.get_object_id("user_id").unwrap().to_hex(),
        seeded.admin.id
    );
    assert_eq!(
        n.get_str("link").unwrap(),
        format!("/tenant/{tid}/room/{room}")
    );
    assert!(
        n.get_str("title").unwrap().ends_with("needs approval"),
        "{n}"
    );

    // Answered by someone who is not a driver: the end is taken, the name
    // is not — no stub says a person allowed what they could not have.
    send(
        &mut dev.ws,
        approval("a1", "allowed", Some(&seeded.member.id)),
    )
    .await;
    let items = wait_messages(&app, &tid, &token, &room, "a1 allowed", |items| {
        content(items, &a1).iter().any(|c| c.contains("allowed"))
    })
    .await;
    // Counted only now: the marker's stub is posted BEFORE its notification
    // is written, so right after the stub the count could still be 1. A
    // device's reports are applied one at a time, in order, so once this end
    // shows, the marker's whole frame was applied — notification included.
    assert_eq!(
        notes
            .count_documents(doc! { "notification_type": "approval_request" })
            .await
            .unwrap(),
        2,
        "one per approval (a1 and the marker), none for the replay"
    );
    assert_eq!(
        content(&items, &a1),
        ["🔐 **Approval** · turn 1 — ✅ allowed"]
    );
    let r1 = record("a1").await;
    assert_eq!(r1.get_str("status").unwrap(), "allowed");
    assert!(r1.get("answered_by").is_none(), "{r1}");
    assert!(r1.get("resolved_at").is_some(), "{r1}");

    // Denied by the driver: named. An end said again changes nothing.
    let a2 = format!("{sid}!a2");
    send(&mut dev.ws, approval("a2", "open", None)).await;
    send(
        &mut dev.ws,
        approval("a2", "denied", Some(&seeded.admin.id)),
    )
    .await;
    send(&mut dev.ws, approval("a2", "expired", None)).await;
    let items = wait_messages(&app, &tid, &token, &room, "a2 denied", |items| {
        content(items, &a2).iter().any(|c| c.contains("denied by"))
    })
    .await;
    let said = content(&items, &a2);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].starts_with("🔐 **Approval** · turn 1 — ⛔ denied by **"),
        "{said:?}"
    );
    let r2 = record("a2").await;
    assert_eq!(
        r2.get_str("status").unwrap(),
        "denied",
        "the late `expired` changed nothing"
    );
    assert_eq!(
        r2.get_object_id("answered_by").unwrap().to_hex(),
        seeded.admin.id
    );

    // An end whose opening never arrived is recorded, and stubbed, as it ended.
    let a3 = format!("{sid}!a3");
    send(&mut dev.ws, approval("a3", "expired", None)).await;
    wait_messages(&app, &tid, &token, &room, "a3 expired", |items| {
        content(items, &a3) == ["🔐 **Approval** · turn 1 — ⌛ nobody answered in time"]
    })
    .await;

    // Still open when the session ends: withdrawn, on the record and in the
    // room. (The marker is that one.)
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended",
               "detail": "the harness exited"}),
    )
    .await;
    let marker = format!("{sid}!amarker");
    wait_messages(
        &app,
        &tid,
        &token,
        &room,
        "the open one withdrawn",
        |items| content(items, &marker) == ["🔐 **Approval** · turn 1 — ⏹ withdrawn"],
    )
    .await;
    assert_eq!(
        record("amarker").await.get_str("status").unwrap(),
        "withdrawn"
    );

    // Nothing opens in a session that is over — nor ends there, unrecorded.
    send(&mut dev.ws, approval("a4", "open", None)).await;
    send(&mut dev.ws, approval("a5", "withdrawn", None)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, items) = room_messages(&app, &tid, &token, &room).await;
    assert!(content(&items, &format!("{sid}!a4")).is_empty());
    assert!(content(&items, &format!("{sid}!a5")).is_empty());
}

/// P1b — a device that says it no longer runs a session ends it (finding 7:
/// a restarted daemon runs none of what it ran, and nothing else would ever
/// say so). What its manifest names stays; a start still in flight is
/// reconcile's, not the manifest's; another device's list changes nothing
/// of this one's.
#[tokio::test]
async fn a_device_that_no_longer_runs_a_session_ends_it() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivemani").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-mani", RUNS_HIVE).await;
    let mut stranger = device(&app, &seeded, "hive-mani-x", RUNS_HIVE).await;
    let gone = started_session(&app, &tid, &token, &mut dev).await;
    let kept = started_session(&app, &tid, &token, &mut dev).await;
    for sid in [&gone, &kept] {
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
        )
        .await;
        wait_status(&app, &tid, &token, sid, "idle").await;
    }

    // Another device's empty list is about that device only.
    send(
        &mut stranger.ws,
        json!({"t": "rc:hive.manifest", "sessions": []}),
    )
    .await;

    // A start in flight: sent, not yet answered.
    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv/third");
    let device_side = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        let pending = f["session_id"].as_str().unwrap().to_string();
        // The device lists only `kept`: `gone` is over; the unanswered
        // start is not "running" yet.
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.manifest", "sessions": [{"session_id": kept, "fence": 1}]}),
        )
        .await;
        wait_status(&app, &tid, &token, &gone, "ended").await;
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": pending, "fence": 1, "account": "dev"}),
        )
        .await;
        pending
    };
    let (body, pending) = tokio::join!(caller, device_side);
    assert_eq!(
        body["outcome"], "accepted",
        "the start in flight survived: {body}"
    );

    let (_, g) = get_session(&app, &tid, &token, &gone).await;
    assert_eq!(g["end_reason"], "not_on_device", "{g}");
    let (_, k) = get_session(&app, &tid, &token, &kept).await;
    assert_eq!(k["status"], "idle", "what the list names stays: {k}");
    let (_, p) = get_session(&app, &tid, &token, &pending).await;
    assert_ne!(p["status"], "ended", "{p}");
    let room = g["room_id"].as_str().unwrap();
    wait_messages(&app, &tid, &token, room, "the ended note", |items| {
        items.iter().any(|m| {
            m["content"]
                .as_str()
                .is_some_and(|c| c.contains("its device no longer runs it"))
        })
    })
    .await;
}

/// P1b — the state usually lands BEFORE the answer (P0g), so a socket that
/// drops between the two leaves the session `idle` with no `accepted_at`.
/// Reconcile never re-sends it — it is not `starting` — so the manifest is
/// the only word that it is over: a run state is the device's own word that
/// it launched the session, as good as its answer. Field, 2026-10-08: the one
/// record the first P1b run left `idle`.
#[tokio::test]
async fn a_session_whose_answer_was_lost_still_ends() {
    // It polls the record and the device's row, past the default limiter.
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await;
    let seeded = app.seed_tenant("hivelostack").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-lostack", RUNS_HIVE).await;
    let agent_id = dev.agent_id.clone();

    // The caller is held for the answer that never comes; the device's side
    // runs meanwhile.
    let caller = start(&app, &tid, &token, &agent_id, "/srv");
    let device_side = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        let sid = f["session_id"].as_str().unwrap().to_string();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
        )
        .await;
        wait_status(&app, &tid, &token, &sid, "idle").await;
        // The socket drops before the answer, and the daemon restarts.
        drop(dev.ws);
        wait_offline(&app, &seeded, &dev.agent_id).await;
        let mut ws = connect(&app, &dev.token, &dev.machine, RUNS_HIVE).await;
        send(&mut ws, json!({"t": "rc:hive.manifest", "sessions": []})).await;
        let s = wait_status(&app, &tid, &token, &sid, "ended").await;
        assert!(
            read_until(&mut ws, "rc:hive.start").await.is_none(),
            "reconcile re-sent it: the manifest is not the only word"
        );
        (sid, s)
    };
    let (_, (sid, s)) = tokio::join!(caller, device_side);
    assert_eq!(s["end_reason"], "not_on_device", "{s}");
    assert!(s["accepted_at"].is_null(), "the answer never landed: {s}");
    let room = s["room_id"].as_str().unwrap();
    wait_messages(&app, &tid, &token, room, "the ended note", |items| {
        items.iter().any(|m| {
            bound_to(m, &sid)
                && m["content"]
                    .as_str()
                    .is_some_and(|c| c.contains("its device no longer runs it"))
        })
    })
    .await;
}

#[tokio::test]
async fn a_member_without_hive_run_is_refused_and_audited() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveperm").await;
    let mut dev = device(&app, &seeded, "hive-perm", RUNS_HIVE).await;

    let body = post_start(
        &app,
        &seeded.tenant_id,
        &seeded.member.access_token,
        &dev.agent_id,
        "/srv",
    )
    .await;
    assert_eq!(body["outcome"], "refused", "{body}");
    assert_eq!(body["reason"], "no_permission");
    assert!(
        body["session"].is_null(),
        "no session for a refusal: {body}"
    );
    assert!(
        read_until(&mut dev.ws, "rc:hive.start").await.is_none(),
        "nothing reaches the device"
    );

    let audit = app
        .db
        .collection::<Document>("hive_audit")
        .find_one(doc! { "reason": "no_permission" })
        .await
        .unwrap()
        .expect("the refusal is audited");
    assert_eq!(audit.get_str("action").unwrap(), "start");
    assert_eq!(audit.get_str("outcome").unwrap(), "refused");
    let sessions = app
        .db
        .collection::<Document>("agent_sessions")
        .count_documents(doc! {})
        .await
        .unwrap();
    assert_eq!(sessions, 0);
}

/// A connection that does not advertise `hive` is never sent a start: a
/// pre-feature agent drops the unknown tag at `debug!` and the caller would
/// wait on silence. An enrolled device that is not connected is `offline`.
#[tokio::test]
async fn a_device_that_does_not_run_sessions_is_never_sent_one() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivecaps").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut old = device(&app, &seeded, "hive-old", NO_HIVE).await;

    // Past the registration race (offline), the answer settles on
    // `device_unsupported` and stays there.
    let mut body = Value::Null;
    for _ in 0..40 {
        body = post_start(&app, &tid, &token, &old.agent_id, "/srv").await;
        if body["reason"] != "device_offline" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(body["reason"], "device_unsupported", "{body}");
    assert!(
        read_until(&mut old.ws, "rc:hive.start").await.is_none(),
        "a start was pushed to a build that would drop it"
    );

    let (never_connected, _token) = enroll_agent(&app, &seeded, "hive-away", "hive-away").await;
    let body = post_start(&app, &tid, &token, &never_connected, "/srv").await;
    assert_eq!(body["reason"], "device_offline", "{body}");
}

/// Another org's device is a 404 — the answer a bogus id gets — and a
/// folder no filesystem holds is a 400, before anything is created.
#[tokio::test]
async fn another_orgs_device_is_unknown_and_a_bad_folder_is_refused() {
    let app = hive_app().await;
    let ours = app.seed_tenant("hiveours").await;
    let theirs = app.seed_tenant("hivetheirs").await;
    let foreign = device(&app, &theirs, "hive-foreign", RUNS_HIVE).await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/hive/session", ours.tenant_id),
            &ours.admin.access_token,
        )
        .json(&json!({ "device_id": foreign.agent_id, "folder": "/srv" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "another org's device");

    let mine = device(&app, &ours, "hive-mine", RUNS_HIVE).await;
    for folder in ["", "   ", "/srv\nINFO forged"] {
        let resp = app
            .auth_post(
                &format!("/api/tenant/{}/hive/session", ours.tenant_id),
                &ours.admin.access_token,
            )
            .json(&json!({ "device_id": mine.agent_id, "folder": folder }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "folder {folder:?}");
    }
    let sessions = app
        .db
        .collection::<Document>("agent_sessions")
        .count_documents(doc! {})
        .await
        .unwrap();
    assert_eq!(sessions, 0);
}

/// In P0 a session belongs to the member who started it: anyone else's
/// read or stop is a 404, and their listing does not show it.
#[tokio::test]
async fn only_the_starter_sees_or_stops_a_session() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveown").await;
    let tid = seeded.tenant_id.clone();
    let mut dev = device(&app, &seeded, "hive-own", RUNS_HIVE).await;

    let caller = start(
        &app,
        &tid,
        &seeded.admin.access_token,
        &dev.agent_id,
        "/srv",
    );
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": f["session_id"], "fence": 1}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    let sid = body["session"]["id"].as_str().unwrap().to_string();

    let other = &seeded.member.access_token;
    assert_eq!(get_session(&app, &tid, other, &sid).await.0, 404);
    assert_eq!(stop(&app, &tid, other, &sid).await.0, 404);
    let list: Value = app
        .auth_get(&format!("/api/tenant/{tid}/hive/session"), other)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["total"], 0, "{list}");

    let mine: Value = app
        .auth_get(
            &format!("/api/tenant/{tid}/hive/session"),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mine["total"], 1, "{mine}");
    assert_eq!(mine["items"][0]["id"], sid);
    assert!(mine["items"][0]["created_at"].is_string(), "{mine}");
}

/// Session ids are ObjectIds — structured, not secret. An answer from
/// another device, or from this one at an old fence, changes nothing and
/// does not wake the caller; the right answer still does.
#[tokio::test]
async fn answers_from_another_device_or_another_fence_change_nothing() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivefence").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-target", RUNS_HIVE).await;
    let mut stranger = device(&app, &seeded, "hive-stranger", RUNS_HIVE).await;

    let caller = async {
        let body = start(&app, &tid, &token, &dev.agent_id, "/srv").await;
        (body, Instant::now())
    };
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        let sid = f["session_id"].clone();
        send(
            &mut stranger.ws,
            json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 1, "refused": "hive_disabled"}),
        )
        .await;
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2, "refused": "hive_disabled"}),
        )
        .await;
        tokio::time::sleep(HOLD).await;
        let acked_at = Instant::now();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 1, "account": "dev"}),
        )
        .await;
        acked_at
    };
    let ((body, answered_at), acked_at) = tokio::join!(caller, target);
    assert!(
        answered_at >= acked_at,
        "a wrong answer woke the caller {:?} early",
        acked_at - answered_at
    );
    assert_eq!(body["outcome"], "accepted", "{body}");
    assert_eq!(body["session"]["status"], "starting");
    assert!(body["session"]["refusal"].is_null(), "{body}");

    // And a state report from the stranger moves nothing either.
    let sid = body["session"]["id"].as_str().unwrap().to_string();
    send(
        &mut stranger.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        get_session(&app, &tid, &token, &sid).await.1["status"],
        "starting"
    );
}

/// The record is the source of truth, not the wait. A device that does not
/// answer leaves the caller with `pending` after the bound; when the device
/// reconnects it is sent the unanswered start again, and its answer lands.
#[tokio::test]
async fn a_silent_device_leaves_the_start_pending_and_is_asked_again() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivesilent").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-silent", RUNS_HIVE).await;

    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv");
    let target = async { read_until(&mut dev.ws, "rc:hive.start").await.unwrap() };
    let (body, first) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "pending", "{body}");
    assert_eq!(body["session"]["status"], "starting");
    let sid = body["session"]["id"].as_str().unwrap().to_string();
    assert_eq!(first["session_id"], sid);

    // The device drops and comes back: it is asked again, same session,
    // same fence, same harness id.
    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let mut ws = connect(&app, &dev.token, &dev.machine, RUNS_HIVE).await;
    let again = read_until(&mut ws, "rc:hive.start")
        .await
        .expect("the unanswered start is re-sent on connect");
    assert_eq!(again["session_id"], sid);
    assert_eq!(again["fence"], 1);
    assert_eq!(again["harness_session"], first["harness_session"]);

    send(
        &mut ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 1, "account": "dev"}),
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let s = get_session(&app, &tid, &token, &sid).await.1;
        if s["accepted_at"].is_string() {
            assert_eq!(s["account"], "dev");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the late answer never landed: {s}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// An unanswered start whose device comes back as a build that does not run
/// sessions is over: nothing there can launch it. The record says `lost`, and
/// the session's room says so — once — like every other way a session ends.
#[tokio::test]
async fn a_start_its_device_can_no_longer_run_is_lost_and_the_room_says_so() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivelost").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-lost", RUNS_HIVE).await;

    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv");
    let target = async { read_until(&mut dev.ws, "rc:hive.start").await.unwrap() };
    let (body, _) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "pending", "{body}");
    let sid = body["session"]["id"].as_str().unwrap().to_string();
    let room = body["session"]["room_id"]
        .as_str()
        .expect("the session has a room")
        .to_string();

    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let mut ws = connect(&app, &dev.token, &dev.machine, NO_HIVE).await;
    let s = wait_status(&app, &tid, &token, &sid, "lost").await;
    assert_eq!(s["end_reason"], "never_answered", "{s}");
    assert!(
        read_until(&mut ws, "rc:hive.start").await.is_none(),
        "a start was re-sent to a build that would drop it"
    );

    let ended = |m: &Value| {
        bound_to(m, &sid)
            && m["content"]
                .as_str()
                .is_some_and(|c| c.starts_with("⏹ Session ended"))
    };
    let items = wait_messages(&app, &tid, &token, &room, "the lost note", |items| {
        items.iter().any(ended)
    })
    .await;
    let note = items.iter().find(|m| ended(m)).unwrap();
    let text = note["content"].as_str().unwrap();
    assert!(text.contains("never answered"), "{text}");
    assert!(text.contains("does not run agent sessions"), "{text}");
    assert_eq!(note["author_type"], "bot");
    assert_eq!(items.iter().filter(|m| ended(m)).count(), 1, "{items:#?}");
}

/// P1b's other door. A build without `hive` runs no session and sends no
/// manifest, so what its device ran stayed live on the record. Field,
/// 2026-10-10: a Windows device ran an accepted session, updated itself to
/// 0.4.123, whose build has no `hive`, and the session read `idle` for ever.
/// Back without `hive`, the device runs none of what it ran: each session
/// ends (`not_on_device`, or `stopped` for one being stopped), its room is
/// told once, and its open approval is withdrawn. The control comes first:
/// the same device back WITH `hive`, its manifest naming both, keeps them.
#[tokio::test]
async fn a_device_back_without_agent_sessions_ends_the_ones_it_ran() {
    // It polls the records, the rooms and the device's row.
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("hivenohive").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-nohive", RUNS_HIVE).await;
    let ran = started_session(&app, &tid, &token, &mut dev).await;
    let stopping = started_session(&app, &tid, &token, &mut dev).await;
    for sid in [&ran, &stopping] {
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
        )
        .await;
        wait_status(&app, &tid, &token, sid, "idle").await;
    }
    let room_of = |s: Value| s["room_id"].as_str().expect("a room").to_string();
    let room = room_of(get_session(&app, &tid, &token, &ran).await.1);
    let stopping_room = room_of(get_session(&app, &tid, &token, &stopping).await.1);
    let a1 = format!("{ran}!a1");
    let approval = || {
        let db = app.db.clone();
        async move {
            db.collection::<Document>("agent_approvals")
                .find_one(doc! { "approval_id": "a1" })
                .await
                .unwrap()
                .expect("on the record")
        }
    };
    let ended = |m: &Value, sid: &str| {
        bound_to(m, sid)
            && m["content"]
                .as_str()
                .is_some_and(|c| c.starts_with("⏹ Session ended"))
    };

    // The control: back WITH `hive`, its manifest naming both. The approval
    // it opens next is applied after the manifest, from the same ordered
    // queue, so its stub says the manifest was read.
    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let mut ws = connect(&app, &dev.token, &dev.machine, RUNS_HIVE).await;
    send(
        &mut ws,
        json!({"t": "rc:hive.manifest", "sessions": [
            {"session_id": ran, "fence": 1},
            {"session_id": stopping, "fence": 1}
        ]}),
    )
    .await;
    send(
        &mut ws,
        json!({"t": "rc:hive.approval", "session_id": ran, "fence": 1,
               "approval_id": "a1", "turn": 1, "status": "open"}),
    )
    .await;
    wait_messages(&app, &tid, &token, &room, "the approval's stub", |items| {
        items.iter().any(|m| bound_to(m, &a1))
    })
    .await;
    for sid in [&ran, &stopping] {
        let (_, s) = get_session(&app, &tid, &token, sid).await;
        assert_eq!(s["status"], "idle", "what the manifest names stays: {s}");
    }
    assert_eq!(approval().await.get_str("status").unwrap(), "open");

    // Away again, and a stop is queued for one of them.
    drop(ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let (code, queued) = stop(&app, &tid, &token, &stopping).await;
    assert_eq!(code, 200);
    assert_eq!(queued["outcome"], "queued", "{queued}");

    // Back as a build WITHOUT `hive`: it sends no manifest and runs nothing.
    let mut ws = connect(&app, &dev.token, &dev.machine, NO_HIVE).await;
    let s = wait_status(&app, &tid, &token, &ran, "ended").await;
    assert_eq!(s["end_reason"], "not_on_device", "{s}");
    let s = wait_status(&app, &tid, &token, &stopping, "ended").await;
    assert_eq!(s["end_reason"], "stopped", "{s}");

    let items = wait_messages(&app, &tid, &token, &room, "the ended note", |items| {
        items.iter().any(|m| ended(m, &ran))
    })
    .await;
    let note = items.iter().find(|m| ended(m, &ran)).unwrap();
    let text = note["content"].as_str().unwrap();
    assert!(text.contains("its device no longer runs it"), "{text}");
    let withdrawn = "🔐 **Approval** · turn 1 — ⏹ withdrawn";
    wait_messages(
        &app,
        &tid,
        &token,
        &room,
        "the approval withdrawn",
        |items| {
            items
                .iter()
                .any(|m| bound_to(m, &a1) && m["content"] == withdrawn)
        },
    )
    .await;
    assert_eq!(approval().await.get_str("status").unwrap(), "withdrawn");
    wait_messages(
        &app,
        &tid,
        &token,
        &stopping_room,
        "the stopped session's note",
        |items| items.iter().any(|m| ended(m, &stopping)),
    )
    .await;

    // Nothing is pushed to a build that would drop it, and meanwhile no
    // room is told twice.
    assert!(
        !device_hears(&mut ws, "rc:hive.stop", Duration::from_millis(500)).await,
        "a stop was pushed to a build without `hive`"
    );
    for (sid, room) in [(&ran, &room), (&stopping, &stopping_room)] {
        let (_, items) = room_messages(&app, &tid, &token, room).await;
        let notes = items.iter().filter(|m| ended(m, sid)).count();
        assert_eq!(notes, 1, "{items:#?}");
    }
}

/// A stop for a device that is away is queued, and delivered when it
/// connects — the same path as an online one.
#[tokio::test]
async fn a_stop_for_an_absent_device_is_delivered_when_it_connects() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivequeue").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-queue", RUNS_HIVE).await;

    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv");
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": f["session_id"], "fence": 1}),
        )
        .await;
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.state", "session_id": f["session_id"], "fence": 1, "state": "idle"}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    let sid = body["session"]["id"].as_str().unwrap().to_string();
    wait_status(&app, &tid, &token, &sid, "idle").await;

    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let (code, queued) = stop(&app, &tid, &token, &sid).await;
    assert_eq!(code, 200);
    assert_eq!(queued["outcome"], "queued", "{queued}");
    assert_eq!(queued["session"]["status"], "stopping");

    let mut ws = connect(&app, &dev.token, &dev.machine, RUNS_HIVE).await;
    let order = read_until(&mut ws, "rc:hive.stop")
        .await
        .expect("the queued stop is delivered on connect");
    assert_eq!(order["session_id"], sid);
    send(
        &mut ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended"}),
    )
    .await;
    let s = wait_status(&app, &tid, &token, &sid, "ended").await;
    assert_eq!(s["end_reason"], "stopped");
}

/// A member who is removed stops driving agent sessions on the org's
/// devices at once: the device is told, and the record ends.
#[tokio::test]
async fn removing_a_member_ends_their_sessions_and_tells_the_device() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivemember").await;
    let tid = seeded.tenant_id.clone();
    grant_hive_run_to_member(&app, &seeded).await;
    let mut dev = device(&app, &seeded, "hive-member", RUNS_HIVE).await;

    let caller = start(
        &app,
        &tid,
        &seeded.member.access_token,
        &dev.agent_id,
        "/srv",
    );
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        assert_eq!(f["user_id"], seeded.member.id, "the starter, not the owner");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": f["session_id"], "fence": 1}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    let sid = body["session"]["id"].as_str().unwrap().to_string();

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{tid}/member/{}", seeded.member.id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {:?}", resp.status());

    let order = read_until(&mut dev.ws, "rc:hive.stop")
        .await
        .expect("the device is told to stop");
    assert_eq!(order["session_id"], sid);
    assert_eq!(order["reason"], "member_removed");
    let s = stored(&app, &sid).await;
    assert_eq!(s.get_str("status").unwrap(), "ended");
    assert_eq!(s.get_str("end_reason").unwrap(), "member_removed");
}

/// The same removal while the device is AWAY: the record ends at once, but
/// the stop cannot reach it, and nothing is pending for reconcile to re-send.
/// The device's own replay on reconnect — "I run this, idle" — is what it is
/// answered on: a stop, with the record's reason. Its `ended` reply changes
/// nothing, and draws no second stop.
#[tokio::test]
async fn a_device_that_missed_the_end_is_told_when_it_reports_the_session() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivemissed").await;
    let tid = seeded.tenant_id.clone();
    grant_hive_run_to_member(&app, &seeded).await;
    let mut dev = device(&app, &seeded, "hive-missed", RUNS_HIVE).await;

    let caller = start(
        &app,
        &tid,
        &seeded.member.access_token,
        &dev.agent_id,
        "/srv",
    );
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": f["session_id"], "fence": 1}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    let sid = body["session"]["id"].as_str().unwrap().to_string();

    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let resp = app
        .auth_delete(
            &format!("/api/tenant/{tid}/member/{}", seeded.member.id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {:?}", resp.status());
    assert_eq!(stored(&app, &sid).await.get_str("status").unwrap(), "ended");

    // Back, and still running it — as the device's replay says.
    let mut ws = connect(&app, &dev.token, &dev.machine, RUNS_HIVE).await;
    send(
        &mut ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
    )
    .await;
    let order = read_until(&mut ws, "rc:hive.stop")
        .await
        .expect("a device running a session that is over is told to stop");
    assert_eq!(order["session_id"], sid);
    assert_eq!(order["fence"], 1);
    assert_eq!(order["reason"], "member_removed");

    send(
        &mut ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended"}),
    )
    .await;
    assert!(
        read_until(&mut ws, "rc:hive.stop").await.is_none(),
        "an `ended` answer drew another stop"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(s.get_str("status").unwrap(), "ended");
    assert_eq!(s.get_str("end_reason").unwrap(), "member_removed");
}

/// Removing a device ends the sessions it ran — before its row and socket
/// go, so it is still there to be told.
#[tokio::test]
async fn removing_a_device_ends_its_sessions() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivedevice").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-device", RUNS_HIVE).await;

    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv");
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": f["session_id"], "fence": 1}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    let sid = body["session"]["id"].as_str().unwrap().to_string();

    let resp = app
        .auth_delete(&format!("/api/tenant/{tid}/agent/{}", dev.agent_id), &token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "delete: {:?}", resp.status());

    let order = read_until(&mut dev.ws, "rc:hive.stop")
        .await
        .expect("the device is told before it is removed");
    assert_eq!(order["reason"], "device_removed");
    let (_, s) = get_session(&app, &tid, &token, &sid).await;
    assert_eq!(s["status"], "ended", "{s}");
    assert_eq!(s["end_reason"], "device_removed");
}

// ─── P2e-1 — a report from a device that is no longer the location ─────────

/// Move a session's record to `device` at `fence`, as a promotion's lease
/// CAS will (P2e-3): the record alone, nobody told.
async fn move_record(app: &TestApp, sid: &str, device: &str, fence: i64) {
    let moved = app
        .db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(sid).unwrap() },
            doc! { "$set": {
                "location.device_id": ObjectId::parse_str(device).unwrap(),
                "fence": fence,
            } },
        )
        .await
        .unwrap();
    assert_eq!(moved.modified_count, 1, "the record moved");
}

/// FR-90 P2e-1 — a device that reports a session the record holds on
/// another device (its run state, a turn, an approval, its manifest, a late
/// answer to the start) is told it no longer holds it: `rc:hive.demote`, at
/// the RECORD's fence. The record does not move. The holder is told
/// nothing, even at an older fence of its own, and neither is another
/// organization's device that names the session.
#[tokio::test]
async fn a_device_that_reports_a_session_held_elsewhere_is_demoted() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivedemote").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut old = device(&app, &seeded, "hive-old", RUNS_HIVE).await;
    let mut holder = device(&app, &seeded, "hive-holder", RUNS_HIVE).await;
    let theirs = app.seed_tenant("hivedemote2").await;
    let mut foreign = device(&app, &theirs, "hive-foreign", RUNS_HIVE).await;
    let sid = started_session(&app, &tid, &token, &mut old).await;
    send(
        &mut old.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
    )
    .await;
    wait_status(&app, &tid, &token, &sid, "idle").await;

    move_record(&app, &sid, &holder.agent_id, 2).await;

    let reports = [
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "running"}),
        json!({"t": "rc:hive.turn", "session_id": sid, "fence": 1, "turn": 1, "status": "running"}),
        json!({"t": "rc:hive.approval", "session_id": sid, "fence": 1,
               "approval_id": "a1", "turn": 1, "status": "open"}),
        json!({"t": "rc:hive.manifest", "sessions": [{"session_id": sid, "fence": 1}]}),
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 1, "account": "dev"}),
    ];
    for report in reports {
        send(&mut old.ws, report.clone()).await;
        let demote = read_until(&mut old.ws, "rc:hive.demote")
            .await
            .unwrap_or_else(|| panic!("no demote for {report}"));
        assert_eq!(demote["session_id"], sid, "{report}");
        assert_eq!(demote["fence"], 2, "the record's fence: {report}");
        assert_eq!(demote["reason"], "not_location", "{report}");
    }

    // The holder, at its own fence and at an older one: nothing.
    for fence in [2, 1] {
        send(
            &mut holder.ws,
            json!({"t": "rc:hive.state", "session_id": sid, "fence": fence, "state": "idle"}),
        )
        .await;
    }
    assert!(
        !device_hears(&mut holder.ws, "rc:hive.demote", Duration::from_millis(800)).await,
        "the holder is not demoted"
    );
    // Another organization's device naming the session: nothing either.
    send(
        &mut foreign.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "running"}),
    )
    .await;
    send(
        &mut foreign.ws,
        json!({"t": "rc:hive.manifest", "sessions": [{"session_id": sid, "fence": 1}]}),
    )
    .await;
    assert!(
        !device_hears(
            &mut foreign.ws,
            "rc:hive.demote",
            Duration::from_millis(800)
        )
        .await,
        "another organization's device is told nothing"
    );

    let s = stored(&app, &sid).await;
    assert_eq!(
        s.get_document("location")
            .unwrap()
            .get_object_id("device_id")
            .unwrap()
            .to_hex(),
        holder.agent_id,
        "the record does not move"
    );
    assert_eq!(s.get_i64("fence").unwrap(), 2);
    assert_eq!(s.get_str("status").unwrap(), "idle");
}

// ─── P2e-2 — the lease word ────────────────────────────────────────────────

/// What a build that holds a leased session to the server's word
/// advertises.
const HOLDS_LEASES: &[&str] = &["exec", "hive", "hive-lease"];

/// Start a session on `dev`, which accepts it: the session as the start's
/// answer shows it, and the `rc:hive.start` frame the device received.
async fn started_frame(
    app: &TestApp,
    tid: &str,
    token: &str,
    dev: &mut Device,
    folder: &str,
) -> (Value, Value) {
    let caller = start(app, tid, token, &dev.agent_id, folder);
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives rc:hive.start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
        frame
    };
    let (body, frame) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    (body["session"].clone(), frame)
}

/// `rc:hive.manifest` naming `sid` at fence 1.
fn manifest_of(sid: &str) -> Value {
    json!({"t": "rc:hive.manifest", "sessions": [{"session_id": sid, "fence": 1}]})
}

/// FR-90 P2e-2 — a replicated session is leased on a device that holds
/// leases: its start asks for it, and every manifest of that device's is
/// answered with the server's word, at the record's fence, on the
/// connection that sent it, the next connection's included. A device that
/// does not hold leases is never asked, nor sent a word; a session alone gets
/// none; a session that is over, named in a manifest, is told to stop.
#[tokio::test]
async fn a_replicated_session_is_leased_and_each_manifest_answered_with_the_word() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivelease").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-lease-primary", HOLDS_LEASES).await;
    let _member = device(&app, &seeded, "mach-lease-member", HOLDS_COPIES).await;
    let mut older = device(&app, &seeded, "mach-lease-older", RUNS_HIVE).await;

    let (s, frame) = started_frame(&app, &tid, &admin, &mut primary, "/srv/lease").await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert_eq!(
        (frame["replicated"].clone(), frame["lease"].clone()),
        (json!(true), json!(true)),
        "the start asks for the lease: {frame}"
    );
    send(&mut primary.ws, manifest_of(&sid)).await;
    let word = read_until(&mut primary.ws, "rc:hive.lease")
        .await
        .expect("the manifest is answered with the word");
    assert_eq!(
        (word["session_id"].as_str(), word["fence"].as_u64()),
        (Some(sid.as_str()), Some(1))
    );

    // And on the next connection again: a word counts on its own one only.
    primary.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;
    let mut ws = connect(&app, &primary.token, &primary.machine, HOLDS_LEASES).await;
    wait_agent_online(&app, &seeded, &primary.agent_id).await;
    send(&mut ws, manifest_of(&sid)).await;
    let again = read_until(&mut ws, "rc:hive.lease")
        .await
        .expect("the next connection's manifest is answered too");
    assert_eq!(again["session_id"].as_str(), Some(sid.as_str()));

    // A device that does not hold leases: never asked, never sent the word.
    let (os, oframe) = started_frame(&app, &tid, &admin, &mut older, "/srv/lease-older").await;
    let osid = os["id"].as_str().unwrap().to_string();
    assert_eq!(oframe["replicated"], true, "{oframe}");
    assert!(
        oframe.get("lease").is_none(),
        "a device that does not hold leases is never asked: {oframe}"
    );
    send(&mut older.ws, manifest_of(&osid)).await;
    assert!(
        !device_hears(&mut older.ws, "rc:hive.lease", Duration::from_millis(800)).await,
        "no word for a device that does not hold leases"
    );

    // A session alone (another org, one device): no lease asked, no word.
    let lone = app.seed_tenant("hiveleaselone").await;
    on_pro(&app, &lone).await;
    let mut single = device(&app, &lone, "mach-lease-lone", HOLDS_LEASES).await;
    let (ls, lframe) = started_frame(
        &app,
        &lone.tenant_id,
        &lone.admin.access_token,
        &mut single,
        "/srv/lease-lone",
    )
    .await;
    let lsid = ls["id"].as_str().unwrap().to_string();
    assert!(lframe.get("lease").is_none(), "{lframe}");
    send(&mut single.ws, manifest_of(&lsid)).await;
    assert!(
        !device_hears(&mut single.ws, "rc:hive.lease", Duration::from_millis(800)).await,
        "no word for a session alone"
    );

    // Over on the record, and named in a manifest: told to stop, and no word.
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "status": "ended", "end_reason": "owner" } },
        )
        .await
        .unwrap();
    send(&mut ws, manifest_of(&sid)).await;
    let stop = read_until(&mut ws, "rc:hive.stop")
        .await
        .expect("a session over is told to stop");
    assert_eq!(
        (stop["session_id"].as_str(), stop["reason"].as_str()),
        (Some(sid.as_str()), Some("owner"))
    );
    assert!(
        !device_hears(&mut ws, "rc:hive.lease", Duration::from_millis(500)).await,
        "no word for a session that is over"
    );
}

/// FR-90 P2e-2 — a session that started alone is leased from its first
/// member on: the primary that holds leases hears the word at once, beside
/// its join, so it holds the session to the word from its next connection.
#[tokio::test]
async fn a_session_that_gains_its_first_member_is_leased_from_then_on() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hiveleasefirst").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let (code, p) = put_policy(&app, &tid, &admin, &policy_min(1, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut primary = device(&app, &seeded, "mach-leasefirst-primary", HOLDS_LEASES).await;
    let _b = device(&app, &seeded, "mach-leasefirst-b", HOLDS_COPIES).await;
    let (s, frame) = started_frame(&app, &tid, &admin, &mut primary, "/srv/leasefirst").await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert!(frame.get("lease").is_none(), "alone: {frame}");

    let (code, p) = put_policy(&app, &tid, &admin, &policy_min(2, 1)).await;
    assert_eq!(code, 200, "{p}");
    let word = read_until(&mut primary.ws, "rc:hive.lease")
        .await
        .expect("leased from its first member on");
    assert_eq!(
        (word["session_id"].as_str(), word["fence"].as_u64()),
        (Some(sid.as_str()), Some(1))
    );
}

// ─── P2e-3 — promotion ─────────────────────────────────────────────────────

/// What a build that takes part in a promotion advertises, at either end: it
/// runs sessions, holds copies, carries streams and holds leases.
const PROMOTES: &[&str] = &[
    "exec",
    "hive",
    "hive-replica",
    "hive-stream",
    "hive-lease",
    "hive-promote",
];

/// [`replicaset_app`] with each step of a promotion bound to 4 s, so a step
/// that runs out does so within a test, with room for a loaded runner.
async fn promote_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.hive.promote_prepare_secs = 4;
        s.hive.promote_drain_secs = 4;
        s.hive.promote_sync_secs = 4;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// A replicated session running on `a` at fence 1, whose members `b` and
/// `more` took their copies.
struct Moving {
    tid: String,
    admin: String,
    admin_id: String,
    sid: String,
    a: Device,
    b: Device,
    more: Vec<Device>,
    seeded: SeededTenant,
}

/// [`Moving`]: the primary advertises [`PROMOTES`], `b` advertises
/// `b_caps`, every other member [`PROMOTES`].
async fn promotable(app: &TestApp, tag: &str, more: usize, b_caps: &[&str]) -> Moving {
    let seeded = app.seed_tenant(tag).await;
    on_pro(app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let min = 2 + u32::try_from(more).unwrap();
    let (code, p) = put_policy(app, &tid, &admin, &policy_min(min, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut a = device(app, &seeded, &format!("mach-{tag}-a"), PROMOTES).await;
    let mut b = device(app, &seeded, &format!("mach-{tag}-b"), b_caps).await;
    let mut others = Vec::new();
    for i in 0..more {
        others.push(device(app, &seeded, &format!("mach-{tag}-m{i}"), PROMOTES).await);
    }
    let (s, frame) = started_frame(app, &tid, &admin, &mut a, &format!("/srv/{tag}")).await;
    assert_eq!(frame["replicated"], true, "{frame}");
    let sid = s["id"].as_str().unwrap().to_string();
    for m in std::iter::once(&mut b).chain(others.iter_mut()) {
        let join = read_until(&mut m.ws, "rc:hive.replica.join")
            .await
            .expect("the member's join");
        assert_eq!(join["fence"], 1, "{join}");
        send(
            &mut m.ws,
            json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
        )
        .await;
        let id = m.agent_id.clone();
        wait_member(app, &tid, &admin, &sid, &id, "joined", |m| {
            m["state"] == "joined"
        })
        .await;
    }
    Moving {
        tid,
        admin,
        admin_id: seeded.admin.id.clone(),
        sid,
        a,
        b,
        more: others,
        seeded,
    }
}

async fn post_promote(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    device: &str,
    folder: Option<&str>,
) -> (u16, Value) {
    let mut body = json!({ "device_id": device });
    if let Some(f) = folder {
        body["folder"] = json!(f);
    }
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/promote"),
            token,
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Promote `m`'s session to `b`, which answers the prepare `answer` (`None`
/// = ready): the route's answer and the prepare `b` received.
async fn promote_answered(app: &TestApp, m: &mut Moving, answer: Option<Value>) -> (Value, Value) {
    let (tid, admin, sid, to) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.b.agent_id.clone(),
    );
    let caller = post_promote(app, &tid, &admin, &sid, &to, None);
    let target = async {
        let prep = read_until(&mut m.b.ws, "rc:hive.prepare")
            .await
            .expect("the member is asked to prepare");
        let mut ack = json!({"t": "rc:hive.prepare_ack", "session_id": sid,
                             "fence": prep["fence"], "account": "dev"});
        if let Some(Value::Object(extra)) = answer {
            for (k, v) in extra {
                ack[k] = v;
            }
        }
        send(&mut m.b.ws, ack).await;
        prep
    };
    let ((code, body), prep) = tokio::join!(caller, target);
    assert_eq!(code, 200, "{body}");
    (body, prep)
}

/// [`promote_answered`], ready: the primary is draining.
async fn prepared(app: &TestApp, m: &mut Moving) -> (Value, Value) {
    let (body, prep) = promote_answered(app, m, None).await;
    assert_eq!(body["outcome"], "promoting", "{body}");
    (body, prep)
}

fn drained(sid: &str, seq: u64, fill: &str) -> Value {
    json!({"t": "rc:hive.drained", "session_id": sid, "fence": 1, "seq": seq, "hash": hash(fill)})
}

fn tip_at(sid: &str, fence: u64, seq: u64, fill: &str) -> Value {
    json!({"t": "rc:hive.replica.tip", "session_id": sid, "fence": fence, "seq": seq,
           "hash": hash(fill)})
}

fn promotion_state(s: &Document) -> Option<&str> {
    s.get_document("promotion").ok()?.get_str("state").ok()
}

/// Poll the stored session until `pred` holds.
async fn wait_stored(
    app: &TestApp,
    sid: &str,
    what: &str,
    pred: impl Fn(&Document) -> bool,
) -> Document {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let s = stored(app, sid).await;
        if pred(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "{what}: {s:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The frames `ws` receives whose `t` is among `kinds`, in the order they
/// arrive, until each kind has come once.
async fn frames_until(ws: &mut AgentWs, kinds: &[&str]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if kinds
            .iter()
            .all(|k| out.iter().any(|f| f["t"].as_str() == Some(k)))
        {
            return out;
        }
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && kinds.iter().any(|k| v["t"].as_str() == Some(k))
                {
                    out.push(v);
                }
            }
            Ok(Some(Ok(_))) | Err(_) => continue,
            Ok(Some(Err(_))) | Ok(None) => break,
        }
    }
    panic!("not every one of {kinds:?} arrived: {out:?}");
}

/// The stored member `device` of `s`: its role and its state.
fn stored_member(s: &Document, device: &str) -> (String, String) {
    let id = ObjectId::parse_str(device).unwrap();
    s.get_document("replicaset")
        .unwrap()
        .get_array("members")
        .unwrap()
        .iter()
        .filter_map(|m| m.as_document())
        .find(|m| m.get_object_id("device_id").ok() == Some(id))
        .map(|m| {
            (
                m.get_str("role").unwrap_or("").to_string(),
                m.get_str("state").unwrap_or("pending").to_string(),
            )
        })
        .unwrap_or_default()
}

/// The lease word, given back once a step ran out: longer than
/// `read_until`'s five seconds, which a bound and a loaded runner can pass.
async fn word_back(ws: &mut AgentWs) -> Option<Value> {
    arrives(ws, "rc:hive.lease", Duration::from_secs(15)).await
}

/// The `promote` audit rows of `sid`, in order: (outcome, reason).
async fn promote_audit(app: &TestApp, sid: &str) -> Vec<(String, String)> {
    let mut rows = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "session_id": ObjectId::parse_str(sid).unwrap(), "action": "promote" })
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(d) = rows.next().await {
        let d = d.unwrap();
        out.push((
            d.get_str("outcome").unwrap().to_string(),
            d.get_str("reason").unwrap_or("").to_string(),
        ));
    }
    out
}

/// The notes in `sid`'s room whose text contains `needle`.
async fn notes_with(app: &TestApp, m: &Moving, needle: &str) -> Vec<String> {
    let room = stored(app, &m.sid)
        .await
        .get_object_id("room_id")
        .unwrap()
        .to_hex();
    room_messages(app, &m.tid, &m.admin, &room)
        .await
        .1
        .iter()
        .filter_map(|i| i["content"].as_str())
        .filter(|c| c.contains(needle))
        .map(str::to_string)
        .collect()
}

/// Poll until the room holds a note containing `needle`; every such note.
async fn wait_note(app: &TestApp, m: &Moving, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let found = notes_with(app, m, needle).await;
        if !found.is_empty() {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "no note with {needle:?} in the room"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// FR-90 P2e-3 — the whole move, with fake devices at both ends. The member
/// is asked to prepare before anything moves; once it is ready the primary
/// is told to drain, and its manifest gets no lease word meanwhile; the
/// lease moves only once the member's OWN tip is the drained one. Then the
/// old primary is demoted at the new fence and joined as a member, every
/// other member is joined at the new fence, and the member hears its join as
/// the primary, the record's move and the start, as a resume, in that order.
/// Its acceptance ends the promotion; the room says who moved it where, and
/// the new primary's manifest is answered with the word at the new fence.
#[tokio::test]
async fn a_promotion_moves_the_lease_once_the_members_copy_holds_the_drained_tip() {
    let app = promote_app().await;
    let mut m = promotable(&app, "promote", 1, PROMOTES).await;
    let sid = m.sid.clone();

    let (body, prep) = prepared(&app, &mut m).await;
    assert_eq!(
        (
            prep["fence"].as_u64(),
            prep["folder"].as_str(),
            prep["user_id"].as_str()
        ),
        (Some(2), Some("/srv/promote"), Some(m.admin_id.as_str())),
        "{prep}"
    );
    assert_eq!(prep["harness_session"], body["session"]["harness_session"]);
    assert_eq!(body["session"]["promotion"]["state"], "draining", "{body}");
    assert_eq!(body["session"]["fence"], 1, "nothing moved yet");

    let drain = read_until(&mut m.a.ws, "rc:hive.drain")
        .await
        .expect("the primary is told to drain");
    assert_eq!(
        (drain["session_id"].as_str(), drain["fence"].as_u64()),
        (Some(sid.as_str()), Some(1))
    );
    send(&mut m.a.ws, manifest_of(&sid)).await;
    assert!(
        !device_hears(&mut m.a.ws, "rc:hive.lease", Duration::from_millis(600)).await,
        "no word while it drains for the move"
    );

    send(&mut m.a.ws, drained(&sid, 5, "ab")).await;
    wait_stored(&app, &sid, "syncing", |s| {
        promotion_state(s) == Some("syncing")
    })
    .await;
    // The primary's own tip at the drained one says nothing of the member's
    // copy; the member behind it moves nothing.
    send(&mut m.a.ws, tip_at(&sid, 1, 5, "ab")).await;
    send(&mut m.b.ws, tip_at(&sid, 1, 4, "cd")).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let s = stored(&app, &sid).await;
    assert_eq!(
        (s.get_i64("fence").unwrap(), promotion_state(&s)),
        (1, Some("syncing")),
        "the member is behind: the lease stays"
    );
    send(&mut m.b.ws, tip_at(&sid, 1, 5, "ab")).await;

    // Another member: joined at the new fence.
    let join = read_until(&mut m.more[0].ws, "rc:hive.replica.join")
        .await
        .expect("another member is joined at the new fence");
    assert_eq!(
        (join["fence"].as_u64(), join["role"].as_str()),
        (Some(2), Some("owner"))
    );
    // The old primary: demoted at the new fence, then — read in order, so a
    // join that came first would be passed over — joined as a member.
    let demote = read_until(&mut m.a.ws, "rc:hive.demote")
        .await
        .expect("the old primary is demoted at the new fence");
    assert_eq!(
        (demote["fence"].as_u64(), demote["reason"].as_str()),
        (Some(2), Some("promoted"))
    );
    let a_join = read_until(&mut m.a.ws, "rc:hive.replica.join")
        .await
        .expect("the owner's own device that holds copies stays a member");
    assert_eq!(
        (a_join["fence"].as_u64(), a_join["role"].as_str()),
        (Some(2), Some("owner"))
    );
    // The member: its join as the primary, the move, then the start.
    let b_frames = frames_until(
        &mut m.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    let kinds: Vec<&str> = b_frames.iter().map(|f| f["t"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
        "the floor before the move, the move before the start"
    );
    let (j, mv, st) = (&b_frames[0], &b_frames[1], &b_frames[2]);
    assert_eq!(
        (j["fence"].as_u64(), j["role"].as_str()),
        (Some(2), Some("primary"))
    );
    assert_eq!(
        (
            mv["fence"].as_u64(),
            mv["turns"].as_u64(),
            mv["from_device_id"].as_str(),
            mv["from_folder"].as_str(),
            mv["moved_by"].as_str(),
        ),
        (
            Some(2),
            Some(0),
            Some(m.a.agent_id.as_str()),
            Some("/srv/promote"),
            Some(m.admin_id.as_str()),
        ),
        "{mv}"
    );
    assert_eq!(
        (
            st["fence"].as_u64(),
            st["resume"].as_bool(),
            st["replicated"].as_bool(),
            st["lease"].as_bool(),
            st["folder"].as_str()
        ),
        (
            Some(2),
            Some(true),
            Some(true),
            Some(true),
            Some("/srv/promote")
        ),
        "a resume, leased: {st}"
    );

    let s = stored(&app, &sid).await;
    assert_eq!(s.get_i64("fence").unwrap(), 2);
    let loc = s.get_document("location").unwrap();
    assert_eq!(
        loc.get_object_id("device_id").unwrap().to_hex(),
        m.b.agent_id
    );
    assert_eq!(s.get_str("status").unwrap(), "starting");
    assert!(s.get("accepted_at").is_none(), "unanswered, as a start is");
    assert_eq!(promotion_state(&s), Some("moving"));
    let fences = s.get_array("fences").expect("where fence 1 ended");
    assert_eq!(fences.len(), 1, "{fences:?}");
    let f = fences[0].as_document().unwrap();
    assert_eq!(
        (
            f.get_i64("fence").unwrap(),
            f.get_i64("seq").unwrap(),
            f.get_str("hash").unwrap()
        ),
        (1, 5, hash("ab").as_str()),
        "the drained tip"
    );
    // P2f-5 — the path map keeps the move: where it ran, where it runs now.
    let path = s.get_array("path_map").expect("the move in the path map");
    assert_eq!(path.len(), 1, "{path:?}");
    let step = path[0].as_document().unwrap();
    let place = |end: &str| {
        let p = step.get_document(end).unwrap();
        (
            p.get_object_id("device_id").unwrap().to_hex(),
            p.get_str("folder").unwrap().to_string(),
        )
    };
    assert_eq!(
        (step.get_i64("fence").unwrap(), place("from"), place("to")),
        (
            2,
            (m.a.agent_id.clone(), "/srv/promote".to_string()),
            (m.b.agent_id.clone(), "/srv/promote".to_string()),
        ),
        "{step}"
    );
    // P2f-5 — and the move named every place the session ran before, from
    // that map: here, only the one.
    assert_eq!(
        mv["earlier"],
        json!([{"device_name": mv["from_device_name"], "folder": "/srv/promote"}]),
        "every place it ran before: {mv}"
    );
    let role = |d: &str| stored_member(&s, d);
    assert_eq!(role(&m.b.agent_id), ("primary".into(), "pending".into()));
    assert_eq!(role(&m.a.agent_id), ("owner".into(), "pending".into()));
    assert_eq!(
        role(&m.more[0].agent_id),
        ("owner".into(), "pending".into())
    );

    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2, "account": "dev"}),
    )
    .await;
    wait_stored(&app, &sid, "done", |s| {
        !s.contains_key("promotion") && s.get_datetime("accepted_at").is_ok()
    })
    .await;
    let moved = wait_note(&app, &m, "🔀 Moved from").await;
    assert_eq!(moved.len(), 1, "{moved:?}");
    assert!(moved[0].contains("as **dev**"), "{}", moved[0]);
    assert_eq!(
        notes_with(&app, &m, "is moving the session to").await.len(),
        1
    );
    assert_eq!(
        notes_with(&app, &m, "Started on").await.len(),
        1,
        "the first start's note only: a moved start's is the move's"
    );

    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.manifest", "sessions": [{"session_id": sid, "fence": 2}]}),
    )
    .await;
    let word = read_until(&mut m.b.ws, "rc:hive.lease")
        .await
        .expect("the new primary's manifest is answered with the word");
    assert_eq!(word["fence"], 2);
    assert_eq!(
        promote_audit(&app, &sid).await,
        [
            ("sent".to_string(), String::new()),
            ("moved".to_string(), String::new()),
            ("done".to_string(), String::new()),
        ]
    );
}

/// FR-90 P2e-3 — a member that cannot run the session says so to the
/// prepare, and that is the caller's answer, in the start's words: nothing
/// moves, the primary is never told to drain, and the room says why.
#[tokio::test]
async fn a_member_that_cannot_run_it_answers_the_caller_and_nothing_moves() {
    let app = promote_app().await;
    let mut m = promotable(&app, "promoterefuse", 0, PROMOTES).await;
    let sid = m.sid.clone();
    let (body, _) = promote_answered(
        &app,
        &mut m,
        Some(json!({"refused": "no_account", "detail": "no *entry*"})),
    )
    .await;
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("no_account")),
        "{body}"
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("maps no local account"),
        "{body}"
    );
    assert!(body["session"].get("promotion").is_none(), "{body}");
    assert!(
        !device_hears(&mut m.a.ws, "rc:hive.drain", Duration::from_millis(600)).await,
        "the primary is never told to drain"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(s.get_i64("fence").unwrap(), 1);
    assert!(!s.contains_key("promotion"));
    let note = wait_note(&app, &m, "did not happen").await;
    assert!(note[0].contains("maps no local account"), "{}", note[0]);
    assert!(note[0].contains(r"(no \*entry\*)"), "escaped: {}", note[0]);
    assert_eq!(
        promote_audit(&app, &sid).await,
        [
            ("sent".to_string(), String::new()),
            ("failed".to_string(), "no_account".to_string()),
        ]
    );
}

/// FR-90 P2e-3 — a primary that does not drain keeps the session, and is
/// given its lease word back, which lifts the drain: one that says it does
/// not run it, one whose answer names no readable tip, and one that never
/// answers, each in the room's own words.
#[tokio::test]
async fn a_primary_that_does_not_drain_keeps_the_session_and_its_word() {
    let app = promote_app().await;
    let mut m = promotable(&app, "promotedrain", 0, PROMOTES).await;
    let sid = m.sid.clone();
    let cases: [(Option<Value>, &str, &str); 3] = [
        (
            Some(
                json!({"t": "rc:hive.drained", "session_id": sid, "fence": 1,
                        "refused": "not_running"}),
            ),
            "drain_not_running",
            "does not run the session",
        ),
        (
            Some(
                json!({"t": "rc:hive.drained", "session_id": sid, "fence": 1,
                        "seq": 5, "hash": "AB".repeat(32)}),
            ),
            "drain_unreadable",
            "could not be read",
        ),
        (None, "drain_timeout", "did not finish its turn"),
    ];
    for (answer, reason, words) in cases {
        prepared(&app, &mut m).await;
        read_until(&mut m.a.ws, "rc:hive.drain")
            .await
            .expect("told to drain");
        if let Some(a) = answer {
            send(&mut m.a.ws, a).await;
        }
        let word = word_back(&mut m.a.ws)
            .await
            .unwrap_or_else(|| panic!("{reason}: the primary is given its word back"));
        assert_eq!(word["fence"], 1, "{reason}");
        let s = wait_stored(&app, &sid, reason, |s| !s.contains_key("promotion")).await;
        assert_eq!(s.get_i64("fence").unwrap(), 1, "{reason}");
        assert_eq!(
            s.get_document("location")
                .unwrap()
                .get_object_id("device_id")
                .unwrap()
                .to_hex(),
            m.a.agent_id,
            "{reason}"
        );
        // The note is posted after the audit row: once it is there, so is
        // the row.
        wait_note(&app, &m, words).await;
        assert_eq!(
            promote_audit(&app, &sid).await.last().cloned(),
            Some(("failed".to_string(), reason.to_string()))
        );
    }

    // A session stopped while its primary drains: the promotion fails at its
    // bound with no word, since nothing holds a lease to give back, and with
    // no note of its own: the stop's end is the room's.
    prepared(&app, &mut m).await;
    read_until(&mut m.a.ws, "rc:hive.drain")
        .await
        .expect("told to drain");
    let (code, _) = stop(&app, &m.tid, &m.admin, &sid).await;
    assert_eq!(code, 200);
    read_until(&mut m.a.ws, "rc:hive.stop")
        .await
        .expect("the stop");
    wait_stored(&app, &sid, "the drain's bound", |s| {
        !s.contains_key("promotion")
    })
    .await;
    assert!(
        !device_hears(&mut m.a.ws, "rc:hive.lease", Duration::from_millis(500)).await,
        "no word for a session being stopped"
    );
    assert_eq!(
        notes_with(&app, &m, "did not happen").await.len(),
        3,
        "the three moves above, not this one"
    );
}

/// FR-90 P2e-3 — the compare-and-sets, raced at the store, where two
/// browsers racing past the route's gate cannot be timed from outside: of two
/// promotions begun on one session the second begins nothing; the lease
/// moves once, and never for a promotion that is not the record's; a move
/// back applies once, to the fence after the member's.
#[tokio::test]
async fn the_promotions_compare_and_sets_move_the_lease_once() {
    use meshharbor_mod_hive::dao::AgentSessionDao;
    use meshharbor_mod_hive::model::{DrainedTip, MemberState, Promotion, PromotionState};
    let app = promote_app().await;
    let m = promotable(&app, "promotecas", 0, PROMOTES).await;
    let dao = AgentSessionDao::new(&app.db);
    let sid = ObjectId::parse_str(&m.sid).unwrap();
    let s = dao.find(sid).await.unwrap().unwrap();
    let to = ObjectId::parse_str(&m.b.agent_id).unwrap();
    let in_a_minute =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() + 60_000);
    let promotion = || Promotion {
        id: ObjectId::new(),
        to,
        to_name: m.b.machine.clone(),
        to_role: "owner".into(),
        folder: s.location.folder.clone(),
        from: s.location.clone(),
        from_fence: s.fence,
        by: s.owner_id,
        state: PromotionState::Syncing,
        started_at: bson::DateTime::now(),
        deadline: in_a_minute,
        drained: Some(DrainedTip {
            seq: 5,
            hash: hash("ab"),
        }),
        unreachable_from: false,
        prior: None,
        teleport: false,
        fork: None,
    };
    let (one, two) = (promotion(), promotion());
    assert!(
        dao.begin_promotion(s.tenant_id, s.owner_id, sid, &one, false)
            .await
            .unwrap(),
        "the first begins"
    );
    assert!(
        !dao.begin_promotion(s.tenant_id, s.owner_id, sid, &two, false)
            .await
            .unwrap(),
        "the second finds the first in flight"
    );
    assert!(
        !dao.move_lease(sid, &two, "owner", MemberState::Pending, in_a_minute)
            .await
            .unwrap(),
        "a promotion that is not the record's moves nothing"
    );
    assert!(
        dao.move_lease(sid, &one, "owner", MemberState::Pending, in_a_minute)
            .await
            .unwrap(),
        "the record's moves it"
    );
    assert!(
        !dao.move_lease(sid, &one, "owner", MemberState::Pending, in_a_minute)
            .await
            .unwrap(),
        "once"
    );
    let moved = dao.find(sid).await.unwrap().unwrap();
    assert_eq!((moved.fence, moved.location.device_id), (2, to));
    assert_eq!(
        moved.promotion.as_ref().map(|p| p.state),
        Some(PromotionState::Moving)
    );
    let mark = |fence| meshharbor_mod_hive::model::FenceMark {
        fence,
        seq: 5,
        hash: hash("ab"),
    };
    assert_eq!(
        moved.fences,
        [mark(1)],
        "the fence it superseded ends at the drained tip"
    );
    assert!(dao.move_lease_back(sid, &one).await.unwrap(), "back");
    assert!(!dao.move_lease_back(sid, &one).await.unwrap(), "once");
    let back = dao.find(sid).await.unwrap().unwrap();
    assert_eq!(
        (back.fence, back.location.device_id),
        (3, s.location.device_id),
        "to the fence after the member's"
    );
    assert!(back.promotion.is_none());
    assert_eq!(
        back.fences,
        [mark(1), mark(2)],
        "the member's fence ends where it began: it ran nothing"
    );
}

/// FR-90 P2e-3 — the lease moves only on the member's copy reaching the
/// drained tip exactly. Another event at its seq is a copy that is not the
/// primary's: failed at once. A copy that never catches up fails at the
/// sync's bound. Either way the primary keeps the session and its word.
#[tokio::test]
async fn a_copy_that_does_not_reach_the_drained_tip_moves_nothing() {
    let app = promote_app().await;
    let mut m = promotable(&app, "promotesync", 0, PROMOTES).await;
    let sid = m.sid.clone();
    let (tid, admin, b_id) = (m.tid.clone(), m.admin.clone(), m.b.agent_id.clone());
    for (seq, fill, reason, words) in [
        (5, "cd", "diverged", "is not the one"),
        (4, "ab", "sync_timeout", "did not catch up in time"),
    ] {
        // The member's tip first, kept, and only then the promotion and its
        // drain: the two connections' reports apply in no order between them,
        // and nothing slow may sit inside a bounded step.
        send(&mut m.b.ws, tip_at(&sid, 1, seq, fill)).await;
        wait_member(&app, &tid, &admin, &sid, &b_id, "the member's tip", |mm| {
            mm["tip"]["seq"] == seq && mm["tip"]["hash"] == hash(fill)
        })
        .await;
        prepared(&app, &mut m).await;
        read_until(&mut m.a.ws, "rc:hive.drain")
            .await
            .expect("told to drain");
        send(&mut m.a.ws, drained(&sid, 5, "ab")).await;
        let word = word_back(&mut m.a.ws)
            .await
            .unwrap_or_else(|| panic!("{reason}: the word back"));
        assert_eq!(word["fence"], 1);
        let s = wait_stored(&app, &sid, reason, |s| !s.contains_key("promotion")).await;
        assert_eq!(s.get_i64("fence").unwrap(), 1, "{reason}: nothing moved");
        // The note after the audit row, as above.
        wait_note(&app, &m, words).await;
        assert_eq!(
            promote_audit(&app, &sid).await.last().cloned(),
            Some(("failed".to_string(), reason.to_string()))
        );
        assert!(
            !device_hears(&mut m.b.ws, "rc:hive.start", Duration::from_millis(300)).await,
            "{reason}: the member is never started"
        );
    }
}

/// Run a promotion of `m` up to the move: prepared, drained at `{5, ab}`,
/// the member's tip there; then drain the frames each side hears at it.
async fn moved(app: &TestApp, m: &mut Moving) {
    let sid = m.sid.clone();
    prepared(app, m).await;
    read_until(&mut m.a.ws, "rc:hive.drain")
        .await
        .expect("told to drain");
    send(&mut m.a.ws, drained(&sid, 5, "ab")).await;
    send(&mut m.b.ws, tip_at(&sid, 1, 5, "ab")).await;
    let to = frames_until(
        &mut m.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    // Its demote, and its join as a member at the new fence.
    let from = frames_until(&mut m.a.ws, &["rc:hive.demote", "rc:hive.replica.join"]).await;
    // P2e-5b — and each join at the new fence names where fence 1 ended, the
    // drained tip: a member's floor is above every event the session had.
    let ended = json!([{"fence": 1, "seq": 5, "hash": hash("ab")}]);
    assert_eq!(
        join_of(&to)["fences"],
        ended,
        "the member's, as the primary"
    );
    assert_eq!(
        join_of(&from)["fences"],
        ended,
        "the old primary's, as a member"
    );
}

/// The join among `frames`.
fn join_of(frames: &[Value]) -> &Value {
    frames
        .iter()
        .find(|f| f["t"] == "rc:hive.replica.join")
        .expect("a join")
}

/// FR-90 P2e-3 — a start the member refuses after the lease moved moves it
/// back, to the fence after the member's: the session is NOT refused. The old
/// primary is its primary again and hears its join, the move and the start,
/// as a resume; the member is a member again, joined at the new fence; the
/// room says why. Its acceptance there posts no second start note.
#[tokio::test]
async fn a_moved_start_the_member_refuses_moves_the_lease_back() {
    let app = promote_app().await;
    let mut m = promotable(&app, "promoteback", 0, PROMOTES).await;
    let sid = m.sid.clone();
    moved(&app, &mut m).await;
    // P2e-5c — A, a member at the new fence, follows the session where it
    // moved: a stream B is asked to serve, before B has run anything.
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 2}),
    )
    .await;
    let (tid, admin, a_id) = (m.tid.clone(), m.admin.clone(), m.a.agent_id.clone());
    wait_member(
        &app,
        &tid,
        &admin,
        &sid,
        &a_id,
        "A joined at fence 2",
        |mm| mm["state"] == "joined",
    )
    .await;
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.replica.want", "session_id": sid, "fence": 2,
               "seq": 5, "hash": hash("ab"), "path": "direct"}),
    )
    .await;
    let g = read_until(&mut m.b.ws, "rc:hive.replica.grant")
        .await
        .expect("B is asked to serve A");
    let gid = g["grant_id"].as_str().unwrap().to_string();
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid,
               "cert_fingerprint": hash("ab"), "addrs": ["192.0.2.7:41641"]}),
    )
    .await;
    read_until(&mut m.a.ws, "rc:hive.replica.dial")
        .await
        .expect("A dials B");
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2,
               "refused": "launch_failed", "detail": "no claude"}),
    )
    .await;
    // P2e-5c — the stream ends at the move back, as every stream of the
    // session ends at a move: B never ran it, and A, told by it that the
    // session runs nowhere, would have parked a copy of one that runs on.
    for (who, ws) in [
        ("B, its source", &mut m.b.ws),
        ("A, its member", &mut m.a.ws),
    ] {
        let c = read_until(ws, "rc:hive.replica.close")
            .await
            .unwrap_or_else(|| panic!("{who} is told the stream ended at the move back"));
        assert_eq!(
            (c["grant_id"].as_str(), c["reason"].as_str()),
            (Some(gid.as_str()), Some("moved")),
            "{who}"
        );
    }

    let a_frames = frames_until(
        &mut m.a.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    let back: Vec<(&str, Option<u64>)> = a_frames
        .iter()
        .map(|f| (f["t"].as_str().unwrap(), f["fence"].as_u64()))
        .collect();
    assert_eq!(
        back,
        [
            ("rc:hive.replica.join", Some(3)),
            ("rc:hive.move", Some(3)),
            ("rc:hive.start", Some(3)),
        ],
        "{a_frames:?}"
    );
    assert_eq!(a_frames[0]["role"], "primary");
    // P2e-5b — fence 1 ended at the drained tip, and the member's fence 2
    // ended where it began: it ran nothing.
    let ended = json!([
        {"fence": 1, "seq": 5, "hash": hash("ab")},
        {"fence": 2, "seq": 5, "hash": hash("ab")},
    ]);
    assert_eq!(a_frames[0]["fences"], ended, "the old primary's join");
    assert_eq!(a_frames[1]["from_device_id"], m.a.agent_id.as_str());
    assert_eq!(a_frames[2]["resume"], true);
    let join = read_until(&mut m.b.ws, "rc:hive.replica.join")
        .await
        .expect("the member is joined again at the new fence");
    assert_eq!(
        (join["fence"].as_u64(), join["role"].as_str()),
        (Some(3), Some("owner"))
    );
    assert_eq!(join["fences"], ended, "and the member's");

    let s = stored(&app, &sid).await;
    assert_eq!(
        s.get_i64("fence").unwrap(),
        3,
        "never a fence handed out once"
    );
    assert_eq!(
        s.get_document("location")
            .unwrap()
            .get_object_id("device_id")
            .unwrap()
            .to_hex(),
        m.a.agent_id
    );
    assert_eq!(s.get_str("status").unwrap(), "starting", "not refused");
    assert!(!s.contains_key("promotion"));
    assert_eq!(
        stored_member(&s, &m.a.agent_id),
        ("primary".into(), "pending".into())
    );
    assert_eq!(
        stored_member(&s, &m.b.agent_id),
        ("owner".into(), "pending".into())
    );
    let note = wait_note(&app, &m, "did not happen").await;
    assert!(
        note[0].contains("could not start the agent harness"),
        "{}",
        note[0]
    );
    assert_eq!(
        promote_audit(&app, &sid).await.last().cloned(),
        Some(("moved_back".to_string(), "launch_failed".to_string()))
    );

    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 3, "account": "dev"}),
    )
    .await;
    wait_stored(&app, &sid, "accepted at fence 3", |s| {
        s.get_datetime("accepted_at").is_ok()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        notes_with(&app, &m, "Started on").await.len(),
        1,
        "a move back posts no second start note: its note is the move's"
    );
}

/// FR-90 P2e-3 — a member that reconnects before it answered the moved
/// start hears, on its new connection, its join as the primary, the move and
/// the start again, as a resume; its answer there ends the promotion.
#[tokio::test]
async fn a_member_back_before_it_answered_hears_the_join_the_move_and_the_start_again() {
    let app = promote_app().await;
    let mut m = promotable(&app, "promoteagain", 0, PROMOTES).await;
    let sid = m.sid.clone();
    moved(&app, &mut m).await;
    m.b.ws.close(None).await.unwrap();
    // P2f-5 — as if it came back an hour after the lease moved.
    let hour_ago =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 3_600_000);
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "moved.at": hour_ago } },
        )
        .await
        .unwrap();
    let mut ws = connect(&app, &m.b.token, &m.b.machine, PROMOTES).await;
    let again = frames_until(
        &mut ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    let kinds: Vec<&str> = again.iter().map(|f| f["t"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"]
    );
    assert_eq!(again[0]["role"], "primary");
    assert_eq!(again[1]["from_device_id"], m.a.agent_id.as_str());
    // P2f-5 — the move it names is the lease's, an hour ago, not the
    // re-send's; and every place it ran before comes again.
    assert_eq!(
        (
            again[1]["moved_at_ms"].as_i64(),
            again[1]["earlier"][0]["folder"].as_str()
        ),
        (Some(hour_ago.timestamp_millis()), Some("/srv/promoteagain")),
        "the lease move's time, not the re-send's: {}",
        again[1]
    );
    assert_eq!(
        (again[2]["fence"].as_u64(), again[2]["resume"].as_bool()),
        (Some(2), Some(true)),
        "the re-sent start resumes"
    );
    send(
        &mut ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2, "account": "dev"}),
    )
    .await;
    wait_stored(&app, &sid, "done", |s| !s.contains_key("promotion")).await;
    wait_note(&app, &m, "🔀 Moved from").await;
}

/// FR-90 P2e-6a — as if the server last heard from `agent_id` `secs` ago.
async fn heard_last(app: &TestApp, agent_id: &str, secs: u64) {
    let ms = i64::try_from(secs * 1000).unwrap();
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(agent_id).unwrap() },
            doc! { "$set": {
                "last_seen_at": bson::DateTime::from_millis(
                    bson::DateTime::now().timestamp_millis() - ms,
                ),
            } },
        )
        .await
        .unwrap();
}

/// A ready's `tip`: where the member's copy ends.
fn ready_at(fence: u64, seq: u64, fill: &str) -> Value {
    json!({"tip": {"fence": fence, "seq": seq, "hash": hash(fill)}})
}

/// The frames `ws` receives until one of each of `kinds` has come, every
/// one of them kept, whatever its kind.
async fn heard_until(ws: &mut AgentWs, kinds: &[&str]) -> Vec<Value> {
    let mut heard: Vec<Value> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !kinds
        .iter()
        .all(|k| heard.iter().any(|f| f["t"].as_str() == Some(k)))
    {
        assert!(
            Instant::now() < deadline,
            "not every one of {kinds:?}: {heard:?}"
        );
        heard.extend(frames_within(ws, Duration::from_millis(200)).await);
    }
    heard
}

/// FR-90 P2e-6a — a primary the server stopped hearing from is waited out,
/// then moved away from with no drain. While it may still call the model, it
/// is not (`primary_offline`); to a member that holds less of the session
/// than another, never (`not_freshest`); then to the one that holds the most,
/// at the tip its own ready names, the primary never asked. The room says
/// what the session goes on from. Back, the old primary is demoted and given
/// no word, and rejoins as a member, holding what it wrote past where its
/// fence ended. When the new primary goes too, that copy is never moved to
/// (`cut_off`), and the member behind the end yields to it (`not_freshest`):
/// the old primary holds the session up to the end.
#[tokio::test]
async fn an_unreachable_primary_is_waited_out_then_moved_away_from_with_no_drain() {
    use meshharbor_remote_control::hive::promote_limits::UNREACHABLE_SECS;
    let app = promote_app().await;
    let mut m = promotable(&app, "unreach", 1, PROMOTES).await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    let (a_id, b_id, c_id) = (
        m.a.agent_id.clone(),
        m.b.agent_id.clone(),
        m.more[0].agent_id.clone(),
    );
    // B holds the most of the session, C less; each tip kept before A goes.
    send(&mut m.b.ws, tip_at(&sid, 1, 5, "ab")).await;
    wait_member(&app, &tid, &admin, &sid, &b_id, "B's tip", |mm| {
        mm["tip"]["seq"] == 5
    })
    .await;
    send(&mut m.more[0].ws, tip_at(&sid, 1, 4, "ab")).await;
    wait_member(&app, &tid, &admin, &sid, &c_id, "C's tip", |mm| {
        mm["tip"]["seq"] == 4
    })
    .await;
    m.a.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &a_id).await;
    let try_to = |device: String| {
        let (app, tid, admin, sid) = (&app, tid.clone(), admin.clone(), sid.clone());
        async move { post_promote(app, &tid, &admin, &sid, &device, None).await.1 }
    };
    let refused = |body: &Value, why: &str| {
        assert_eq!(
            (body["outcome"].as_str(), body["reason"].as_str()),
            (Some("refused"), Some(why)),
            "{body}"
        );
    };

    // Just gone: its own clock may still let it call the model.
    let body = try_to(b_id.clone()).await;
    refused(&body, "primary_offline");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains(&format!("{UNREACHABLE_SECS} s")),
        "the refusal names the wait: {body}"
    );
    heard_last(&app, &a_id, UNREACHABLE_SECS + 1).await;
    refused(&try_to(c_id.clone()).await, "not_freshest");

    // To B, which holds the most: its ready names where its copy ends, and
    // the lease moves there before the caller hears.
    let (body, prep) = promote_answered(&app, &mut m, Some(ready_at(1, 5, "ab"))).await;
    assert_eq!(
        body["outcome"], "promoting",
        "the member's ready moves the lease: {body}"
    );
    assert_eq!(prep["fence"], 2, "{prep}");
    assert_eq!(
        (
            body["session"]["fence"].as_i64(),
            body["session"]["promotion"]["state"].as_str()
        ),
        (Some(2), Some("moving")),
        "moved, the primary never asked: {body}"
    );
    let ended = json!([{"fence": 1, "seq": 5, "hash": hash("ab")}]);
    let b_frames = frames_until(
        &mut m.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    let kinds: Vec<&str> = b_frames.iter().map(|f| f["t"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"]
    );
    assert_eq!(join_of(&b_frames)["role"], "primary");
    assert_eq!(
        join_of(&b_frames)["fences"],
        ended,
        "fence 1 ends where B's copy does"
    );
    assert_eq!(b_frames[2]["resume"], true, "{}", b_frames[2]);
    let c_join = read_until(&mut m.more[0].ws, "rc:hive.replica.join")
        .await
        .expect("C is joined at the new fence");
    assert_eq!(
        (c_join["fence"].as_u64(), &c_join["fences"]),
        (Some(2), &ended)
    );
    let s = stored(&app, &sid).await;
    let p = s.get_document("promotion").unwrap();
    assert_eq!(
        (p.get_str("state").ok(), p.get_bool("unreachable_from").ok()),
        (Some("moving"), Some(true)),
        "{p:?}"
    );
    let drained = p.get_document("drained").unwrap();
    assert_eq!(
        (drained.get_i64("seq").ok(), drained.get_str("hash").ok()),
        (Some(5), Some(hash("ab").as_str())),
        "the member's own tip"
    );
    let note = wait_note(&app, &m, "cannot be reached").await;
    assert!(
        note[0].contains("goes on from the copy"),
        "the room says what it goes on from: {}",
        note[0]
    );
    assert!(
        notes_with(&app, &m, "takes no new prompt meanwhile")
            .await
            .is_empty(),
        "no drain, so no drain's note"
    );
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2, "account": "dev"}),
    )
    .await;
    wait_stored(&app, &sid, "done", |s| !s.contains_key("promotion")).await;
    wait_note(&app, &m, "🔀 Moved from").await;
    send(
        &mut m.more[0].ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 2}),
    )
    .await;
    wait_member(&app, &tid, &admin, &sid, &c_id, "C joined at 2", |mm| {
        mm["state"] == "joined"
    })
    .await;

    // A, back: demoted at the new fence and given no word; then joined as a
    // member, the join naming where fence 1 ended. What it wrote past that
    // end, nobody heard: its tip.
    m.a.ws = connect(&app, &m.a.token, &m.a.machine, PROMOTES).await;
    send(&mut m.a.ws, manifest_of(&sid)).await;
    let mut heard = heard_until(&mut m.a.ws, &["rc:hive.demote", "rc:hive.replica.join"]).await;
    heard.extend(frames_within(&mut m.a.ws, Duration::from_millis(500)).await);
    let demote = heard.iter().find(|f| f["t"] == "rc:hive.demote").unwrap();
    assert_eq!(demote["fence"], 2, "{demote}");
    let a_join = join_of(&heard);
    assert_eq!(
        (
            a_join["fence"].as_u64(),
            a_join["role"].as_str(),
            &a_join["fences"]
        ),
        (Some(2), Some("owner"), &ended),
        "{a_join}"
    );
    assert!(
        !heard.iter().any(|f| f["t"] == "rc:hive.lease"),
        "no word for a session it no longer holds: {heard:?}"
    );
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 2}),
    )
    .await;
    send(&mut m.a.ws, tip_at(&sid, 1, 9, "ff")).await;
    wait_member(&app, &tid, &admin, &sid, &a_id, "A, a member", |mm| {
        mm["state"] == "joined" && mm["tip"]["seq"] == 9
    })
    .await;
    // P2k-5 — the room says how many of A's events did not carry over: the
    // four it wrote past where fence 1 ended. Once: the same tip again adds
    // nothing.
    let tail = wait_note(&app, &m, "did not carry over").await;
    assert!(
        tail.len() == 1 && tail[0].contains("holds 4 events it wrote after the session moved on"),
        "{tail:?}"
    );
    send(&mut m.a.ws, tip_at(&sid, 1, 9, "ff")).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        notes_with(&app, &m, "did not carry over").await.len(),
        1,
        "said once"
    );

    // B goes too, before A followed it. A holds fence 1 up to its end, more
    // than C: C yields. A's copy runs past that end: never moved to.
    m.b.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &b_id).await;
    heard_last(&app, &b_id, UNREACHABLE_SECS + 1).await;
    refused(&try_to(c_id.clone()).await, "not_freshest");
    let caller = post_promote(&app, &tid, &admin, &sid, &a_id, None);
    let target = async {
        let prep = read_until(&mut m.a.ws, "rc:hive.prepare")
            .await
            .expect("A is asked to prepare");
        let mut ack = json!({"t": "rc:hive.prepare_ack", "session_id": sid,
                             "fence": prep["fence"], "account": "dev"});
        ack["tip"] = ready_at(1, 9, "ff")["tip"].clone();
        send(&mut m.a.ws, ack).await;
    };
    let ((code, body), ()) = tokio::join!(caller, target);
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["reason"], "cut_off",
        "a copy past where its fence ended is never moved to: {body}"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(s.get_i64("fence").unwrap(), 2, "nothing moved");
    assert!(!s.contains_key("promotion"), "{s:?}");
    wait_note(&app, &m, "an earlier move left out").await;

    let audit: Vec<(String, String)> = promote_audit(&app, &sid).await;
    let want: Vec<(String, String)> = [
        ("refused", "primary_offline"),
        ("refused", "not_freshest"),
        ("sent", ""),
        ("moved", ""),
        ("done", ""),
        ("refused", "not_freshest"),
        ("sent", ""),
        ("failed", "cut_off"),
    ]
    .iter()
    .map(|(o, r)| (o.to_string(), r.to_string()))
    .collect();
    assert_eq!(audit, want);
}

/// FR-90 P2e-6a — what a move away from an unreachable primary cannot trust,
/// it refuses, each in its own word: a primary whose last build would run
/// the session again on reconnect before it hears it was demoted
/// (`primary_unsupported`); a ready that does not say where the member's
/// copy ends (`no_copy_tip`), its failure in the room. And a primary heard
/// from again before the member answers is drained after all, as any online
/// primary is.
#[tokio::test]
async fn a_move_away_from_an_unreachable_primary_refuses_what_it_cannot_trust() {
    use meshharbor_remote_control::hive::promote_limits::UNREACHABLE_SECS;
    let app = promote_app().await;
    let mut m = promotable(&app, "unreachgate", 0, PROMOTES).await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    let (a_id, b_id) = (m.a.agent_id.clone(), m.b.agent_id.clone());
    send(&mut m.b.ws, tip_at(&sid, 1, 5, "ab")).await;
    wait_member(&app, &tid, &admin, &sid, &b_id, "B's tip", |mm| {
        mm["tip"]["seq"] == 5
    })
    .await;
    m.a.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &a_id).await;
    heard_last(&app, &a_id, UNREACHABLE_SECS + 1).await;

    // A's last hello, from a build before the lease word.
    let agents = app.db.collection::<Document>("agents");
    let a_oid = ObjectId::parse_str(&a_id).unwrap();
    let set_rpc = |rpc: Vec<&'static str>| {
        let agents = agents.clone();
        async move {
            agents
                .update_one(
                    doc! { "_id": a_oid },
                    doc! { "$set": { "capabilities.rpc": rpc } },
                )
                .await
                .unwrap();
        }
    };
    set_rpc(vec!["hive", "hive-replica", "hive-stream", "hive-promote"]).await;
    let (code, body) = post_promote(&app, &tid, &admin, &sid, &b_id, None).await;
    assert_eq!(code, 200);
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("primary_unsupported")),
        "{body}"
    );
    set_rpc(PROMOTES.to_vec()).await;

    // A ready that names no tip: an older member's.
    let (body, _) = promote_answered(&app, &mut m, None).await;
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("no_copy_tip")),
        "{body}"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(s.get_i64("fence").unwrap(), 1, "nothing moved");
    assert!(!s.contains_key("promotion"), "{s:?}");
    wait_note(&app, &m, "did not say where its copy ends").await;

    // A back before B answers: drained after all.
    let caller = post_promote(&app, &tid, &admin, &sid, &b_id, None);
    let target = async {
        let prep = read_until(&mut m.b.ws, "rc:hive.prepare")
            .await
            .expect("B is asked to prepare");
        m.a.ws = connect(&app, &m.a.token, &m.a.machine, PROMOTES).await;
        wait_agent_online(&app, &m.seeded, &a_id).await;
        let mut ack = json!({"t": "rc:hive.prepare_ack", "session_id": sid,
                             "fence": prep["fence"], "account": "dev"});
        ack["tip"] = ready_at(1, 5, "ab")["tip"].clone();
        send(&mut m.b.ws, ack).await;
    };
    let ((code, body), ()) = tokio::join!(caller, target);
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        (
            body["outcome"].as_str(),
            body["session"]["promotion"]["state"].as_str()
        ),
        (Some("promoting"), Some("draining")),
        "back before the member answered, the primary drains: {body}"
    );
    let drain = read_until(&mut m.a.ws, "rc:hive.drain")
        .await
        .expect("A, back, is told to drain");
    assert_eq!(drain["fence"], 1);
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.drained", "session_id": sid, "fence": 1, "refused": "not_running"}),
    )
    .await;
    word_back(&mut m.a.ws)
        .await
        .expect("the word back: nothing moved");
    wait_stored(&app, &sid, "ended", |s| !s.contains_key("promotion")).await;
    let want: Vec<(String, String)> = [
        ("refused", "primary_unsupported"),
        ("sent", ""),
        ("failed", "no_copy_tip"),
        ("sent", ""),
        ("failed", "drain_not_running"),
    ]
    .iter()
    .map(|(o, r)| (o.to_string(), r.to_string()))
    .collect();
    // The promotion's end and its audit row are two writes: wait for the
    // row, the operation's LAST one (#2065), never the record alone.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut audit = promote_audit(&app, &sid).await;
    while audit.len() < want.len() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        audit = promote_audit(&app, &sid).await;
    }
    assert_eq!(audit, want);
}

/// FR-90 P2e-6b — the session's record as if it were made `secs` ago.
async fn made_ago(app: &TestApp, sid: &str, secs: i64) {
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(sid).unwrap() },
            doc! { "$set": {
                "created_at": bson::DateTime::from_millis(
                    bson::DateTime::now().timestamp_millis() - secs * 1000,
                ),
            } },
        )
        .await
        .unwrap();
}

/// Promote `m`'s session to its old primary, A, which answers the prepare
/// with `answer`'s fields: the caller's answer and A's prepare.
async fn promote_back_to_a(app: &TestApp, m: &mut Moving, answer: Value) -> (u16, Value, Value) {
    let (tid, admin, sid, to) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.a.agent_id.clone(),
    );
    let caller = post_promote(app, &tid, &admin, &sid, &to, None);
    // A refusal at the route asks nothing of A: no prepare, and the caller's
    // answer says why.
    let target = async {
        let Some(prep) = read_until(&mut m.a.ws, "rc:hive.prepare").await else {
            return Value::Null;
        };
        let mut ack = json!({"t": "rc:hive.prepare_ack", "session_id": sid,
                             "fence": prep["fence"], "account": "dev"});
        if let Value::Object(extra) = answer {
            for (k, v) in extra {
                ack[k] = v;
            }
        }
        send(&mut m.a.ws, ack).await;
        prep
    };
    let ((code, body), prep) = tokio::join!(caller, target);
    (code, body, prep)
}

/// The `rc:hive.move` among `frames`.
fn move_of(frames: &[Value]) -> &Value {
    frames
        .iter()
        .find(|f| f["t"] == "rc:hive.move")
        .expect("a move")
}

/// Moved to B, which hears its start and never answers it; A, demoted, takes
/// its member's copy at fence 2; B gone, and unreachable for 230 s.
async fn moved_to_a_silent_b(app: &TestApp, m: &mut Moving) {
    use meshharbor_remote_control::hive::promote_limits::UNREACHABLE_SECS;
    let (tid, admin, sid, a_id, b_id) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.a.agent_id.clone(),
        m.b.agent_id.clone(),
    );
    moved(app, m).await;
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 2}),
    )
    .await;
    wait_member(
        app,
        &tid,
        &admin,
        &sid,
        &a_id,
        "A joined at fence 2",
        |mm| mm["state"] == "joined",
    )
    .await;
    m.b.ws.close(None).await.unwrap();
    wait_offline(app, &m.seeded, &b_id).await;
    heard_last(app, &b_id, UNREACHABLE_SECS + 1).await;
}

/// FR-90 P2e-6b — a move's target that never answers its start. Back however
/// late, it is sent that start again: the redelivery window bounds a
/// session's FIRST start only, and this session was made long before its
/// move. Once it is unreachable, the owner moves the session on, as from any
/// unreachable primary, to a member at its own tip with no drain: the move
/// that sent the start is replaced. Back again, the silent device is demoted
/// and given nothing to run.
#[tokio::test]
async fn a_target_that_never_answered_is_waited_out_then_moved_on() {
    use meshharbor_remote_control::hive::promote_limits::UNREACHABLE_SECS;
    let app = promote_app().await;
    let mut m = promotable(&app, "silent", 0, PROMOTES).await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    let (a_id, b_id) = (m.a.agent_id.clone(), m.b.agent_id.clone());
    moved_to_a_silent_b(&app, &mut m).await;

    // Back, eleven minutes after the session was made: the start again.
    made_ago(&app, &sid, 11 * 60).await;
    m.b.ws = connect(&app, &m.b.token, &m.b.machine, PROMOTES).await;
    let again = frames_within(&mut m.b.ws, Duration::from_secs(3)).await;
    let of = |kind: &str| again.iter().find(|f| f["t"] == kind);
    assert_eq!(
        (
            of("rc:hive.move").and_then(|f| f["from_device_id"].as_str()),
            of("rc:hive.start").and_then(|f| f["fence"].as_u64())
        ),
        (Some(a_id.as_str()), Some(2)),
        "a moved start is sent again, however late its device comes back: {again:?}"
    );
    m.b.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &b_id).await;

    // Just gone: the move to B is still under way.
    let (_, body) = post_promote(&app, &tid, &admin, &sid, &a_id, None).await;
    assert_eq!(
        body["reason"], "primary_offline",
        "a target gone for less than 230 s is waited for: {body}"
    );
    heard_last(&app, &b_id, UNREACHABLE_SECS + 1).await;

    let (code, body, prep) = promote_back_to_a(&app, &mut m, ready_at(1, 5, "ab")).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["outcome"], "promoting",
        "the owner moves on from a target that never answered: {body}"
    );
    assert_eq!(prep["fence"], 3, "{prep}");
    let a_frames = frames_until(
        &mut m.a.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    let join = join_of(&a_frames);
    assert_eq!(
        (join["fence"].as_u64(), join["role"].as_str()),
        (Some(3), Some("primary"))
    );
    assert_eq!(
        join["fences"],
        json!([
            {"fence": 1, "seq": 5, "hash": hash("ab")},
            {"fence": 2, "seq": 5, "hash": hash("ab")},
        ]),
        "B's fence ended where it began: it ran nothing"
    );
    assert_eq!(move_of(&a_frames)["from_device_id"], b_id.as_str());
    let s = stored(&app, &sid).await;
    assert_eq!(s.get_i64("fence").unwrap(), 3);
    wait_note(&app, &m, "cannot be reached").await;
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 3, "account": "dev"}),
    )
    .await;
    wait_stored(&app, &sid, "done", |s| {
        !s.contains_key("promotion") && s.get_datetime("accepted_at").is_ok()
    })
    .await;

    // B, back once more: demoted, and nothing to run.
    m.b.ws = connect(&app, &m.b.token, &m.b.machine, PROMOTES).await;
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.manifest", "sessions": [{"session_id": sid, "fence": 2}]}),
    )
    .await;
    let mut heard = heard_until(&mut m.b.ws, &["rc:hive.demote"]).await;
    heard.extend(frames_within(&mut m.b.ws, Duration::from_millis(500)).await);
    assert!(
        !heard
            .iter()
            .any(|f| f["t"] == "rc:hive.start" || f["t"] == "rc:hive.lease"),
        "nothing to run for a session that moved on: {heard:?}"
    );
    let audit: Vec<(String, String)> = promote_audit(&app, &sid).await;
    let want: Vec<(String, String)> = [
        ("sent", ""),
        ("moved", ""),
        ("refused", "primary_offline"),
        ("sent", ""),
        ("moved", ""),
        ("done", ""),
    ]
    .iter()
    .map(|(o, r)| (o.to_string(), r.to_string()))
    .collect();
    assert_eq!(audit, want);
}

/// FR-90 P2e-6b — a move on from a target that never answered can fail: its
/// member refuses the prepare, or the start. Either way the silent device is
/// owed its start, and that start still comes from where the first move took
/// the session, so that back, the device takes it over from its own copy.
#[tokio::test]
async fn a_failed_move_on_keeps_where_the_silent_targets_start_came_from() {
    use meshharbor_remote_control::hive::promote_limits::UNREACHABLE_SECS;
    let app = promote_app().await;
    let mut m = promotable(&app, "silentkeep", 0, PROMOTES).await;
    let sid = m.sid.clone();
    let (a_id, b_id) = (m.a.agent_id.clone(), m.b.agent_id.clone());
    moved_to_a_silent_b(&app, &mut m).await;

    // A cannot run it: the move on fails, and the session waits on B.
    let (code, body, _) = promote_back_to_a(&app, &mut m, json!({"refused": "no_account"})).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("no_account")),
        "{body}"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(
        (
            s.get_i64("fence").unwrap(),
            s.get_document("location")
                .unwrap()
                .get_object_id("device_id")
                .unwrap()
                .to_hex()
        ),
        (2, b_id.clone())
    );
    m.b.ws = connect(&app, &m.b.token, &m.b.machine, PROMOTES).await;
    let again = frames_until(
        &mut m.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    assert_eq!(
        move_of(&again)["from_device_id"],
        a_id.as_str(),
        "the start a silent target is owed comes from where the first move took it: {again:?}"
    );
    m.b.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &b_id).await;
    heard_last(&app, &b_id, UNREACHABLE_SECS + 1).await;

    // A is ready, then cannot take the session over: the lease moves back to
    // B, at fence 4, B back by then.
    let (code, body, _) = promote_back_to_a(&app, &mut m, ready_at(1, 5, "ab")).await;
    assert_eq!(
        (code, body["outcome"].as_str()),
        (200, Some("promoting")),
        "{body}"
    );
    read_until(&mut m.a.ws, "rc:hive.start")
        .await
        .expect("A's moved start");
    m.b.ws = connect(&app, &m.b.token, &m.b.machine, PROMOTES).await;
    wait_agent_online(&app, &m.seeded, &b_id).await;
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 3,
               "refused": "launch_failed", "detail": "no claude"}),
    )
    .await;
    let s = wait_stored(&app, &sid, "moved back to B", |s| {
        s.get_i64("fence").ok() == Some(4) && !s.contains_key("promotion")
    })
    .await;
    assert_eq!(
        s.get_document("moved")
            .and_then(|m| m.get_document("from"))
            .and_then(|f| f.get_object_id("device_id"))
            .map(|id| id.to_hex())
            .ok(),
        Some(a_id.clone()),
        "the record keeps where the silent target's start came from: {s:?}"
    );
    let back = frames_until(
        &mut m.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    assert_eq!(
        (
            move_of(&back)["from_device_id"].as_str(),
            back.last().unwrap()["fence"].as_u64()
        ),
        (Some(a_id.as_str()), Some(4)),
        "the start back comes from where the first move took the session: {back:?}"
    );
}

/// FR-90 P2e-3 — the route's gates, each refusal in its own word and
/// audited: with the replicaset off the route is not there; a session is
/// promoted by its owner only; never to the device it runs on, nor to one
/// that holds no copy, nor between devices that do not both take part in a
/// promotion, nor to one offline; never a session that is not running; and
/// of two promotions raced, one moves on.
#[tokio::test]
async fn a_promotion_is_refused_by_the_gate_it_failed() {
    let off = hive_app().await;
    let seeded = off.seed_tenant("promoteoff").await;
    let (code, _) = post_promote(
        &off,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        &ObjectId::new().to_hex(),
        &ObjectId::new().to_hex(),
        None,
    )
    .await;
    assert_eq!(code, 404, "with the replicaset off the route is not there");

    let app = promote_app().await;
    let mut m = promotable(&app, "promotegate", 1, HOLDS_COPIES).await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    let try_to = |device: String| {
        let (app, tid, admin, sid) = (&app, tid.clone(), admin.clone(), sid.clone());
        async move { post_promote(app, &tid, &admin, &sid, &device, None).await.1 }
    };
    let refused = |body: &Value, why: &str| {
        assert_eq!(
            (body["outcome"].as_str(), body["reason"].as_str()),
            (Some("refused"), Some(why)),
            "{body}"
        );
        assert!(body["message"].as_str().is_some_and(|t| !t.is_empty()));
    };

    refused(&try_to(m.a.agent_id.clone()).await, "already_primary");
    // P2e-5b — moved as often as one join can say: one more move, and its
    // move back, would leave a join naming more ends than a device takes.
    let marks = |n: usize| -> Vec<Document> {
        (1..=n as i64)
            .map(|f| doc! { "fence": f, "seq": 1_i64, "hash": hash("ab") })
            .collect()
    };
    let set_marks = |n: usize| {
        let (app, sid) = (&app, sid.clone());
        async move {
            app.db
                .collection::<Document>("agent_sessions")
                .update_one(
                    doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
                    doc! { "$set": { "fences": marks(n) } },
                )
                .await
                .unwrap();
        }
    };
    let max = meshharbor_remote_control::hive::replica_limits::MAX_FENCE_MARKS;
    set_marks(max - 1).await;
    refused(&try_to(m.more[0].agent_id.clone()).await, "moved_too_often");
    set_marks(0).await;
    // The owner's own device that holds copies, enrolled after the start: no
    // member.
    let stranger = device(&app, &m.seeded, "mach-promotegate-x", PROMOTES).await;
    refused(&try_to(stranger.agent_id.clone()).await, "not_a_member");
    // A member whose build takes no part in a promotion.
    refused(&try_to(m.b.agent_id.clone()).await, "device_unsupported");

    // Someone else in the org: the session is not theirs to see.
    let (code, _) = post_promote(
        &app,
        &tid,
        &m.seeded.member.access_token,
        &sid,
        &m.more[0].agent_id,
        None,
    )
    .await;
    assert_eq!(code, 404, "another member's read of the id is a 404");

    // Two promotions raced: one goes on, the other is told one is under way.
    // The member never answers, so the one that went on fails at the
    // prepare's bound, and its caller hears that.
    let to = m.more[0].agent_id.clone();
    let (one, two) = tokio::join!(try_to(to.clone()), try_to(to.clone()));
    let mut reasons = [
        one["reason"].as_str().unwrap_or("").to_string(),
        two["reason"].as_str().unwrap_or("").to_string(),
    ];
    reasons.sort();
    assert_eq!(
        reasons,
        ["prepare_timeout", "promotion_in_progress"],
        "{one} {two}"
    );
    assert_eq!(
        frames_within(&mut m.more[0].ws, Duration::from_millis(500))
            .await
            .iter()
            .filter(|f| f["t"] == "rc:hive.prepare")
            .count(),
        1,
        "one prepare"
    );
    let s = stored(&app, &sid).await;
    assert!(!s.contains_key("promotion"), "{s:?}");
    assert_eq!(s.get_i64("fence").unwrap(), 1);

    // The primary offline; then the member offline too, which is the gate
    // asked first.
    m.a.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.a.agent_id).await;
    refused(&try_to(m.more[0].agent_id.clone()).await, "primary_offline");
    m.more[0].ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.more[0].agent_id).await;
    refused(&try_to(m.more[0].agent_id.clone()).await, "device_offline");

    // A session that is not running.
    let (code, _) = stop(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200);
    refused(
        &try_to(m.more[0].agent_id.clone()).await,
        "session_not_running",
    );

    let reasons: Vec<String> = promote_audit(&app, &sid)
        .await
        .into_iter()
        .filter(|(o, _)| o == "refused")
        .map(|(_, r)| r)
        .collect();
    for want in [
        "already_primary",
        "moved_too_often",
        "not_a_member",
        "device_unsupported",
        "primary_offline",
        "device_offline",
        "promotion_in_progress",
        "session_not_running",
    ] {
        assert!(reasons.iter().any(|r| r == want), "{want}: {reasons:?}");
    }
}

// ─── P2f-1 — teleport ──────────────────────────────────────────────────────

/// What a build that takes part in a teleport advertises at either end:
/// everything a promotion asks, and `hive-teleport`.
const TELEPORTS: &[&str] = &[
    "exec",
    "hive",
    "hive-replica",
    "hive-stream",
    "hive-lease",
    "hive-promote",
    "hive-teleport",
];

/// …and a target whose owner never let it hold copies: no `hive-replica`.
const TELEPORT_TARGET: &[&str] = &[
    "exec",
    "hive",
    "hive-stream",
    "hive-lease",
    "hive-promote",
    "hive-teleport",
];

/// [`promote_app`], with the teleport's joining step bound to 6 s.
async fn teleport_app() -> TestApp {
    teleport_app_joining(6).await
}

/// [`teleport_app`], the joining step bound to `join_secs`.
async fn teleport_app_joining(join_secs: u64) -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.hive.promote_prepare_secs = 4;
        s.hive.promote_join_secs = join_secs;
        s.hive.promote_drain_secs = 4;
        s.hive.promote_sync_secs = 4;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// A session running alone on `a` (the policy's `min` is 1), and `b`, which
/// holds no copy of it and advertises `b_caps`.
async fn teleportable(app: &TestApp, tag: &str, b_caps: &[&str]) -> Moving {
    let seeded = app.seed_tenant(tag).await;
    on_pro(app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let (code, p) = put_policy(app, &tid, &admin, &policy_min(1, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut a = device(app, &seeded, &format!("mach-{tag}-a"), TELEPORTS).await;
    let b = device(app, &seeded, &format!("mach-{tag}-b"), b_caps).await;
    let (s, frame) = started_frame(app, &tid, &admin, &mut a, &format!("/srv/{tag}")).await;
    assert_ne!(frame["replicated"], true, "alone: {frame}");
    Moving {
        tid,
        admin,
        admin_id: seeded.admin.id.clone(),
        sid: s["id"].as_str().unwrap().to_string(),
        a,
        b,
        more: Vec::new(),
        seeded,
    }
}

async fn post_teleport(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    device: &str,
    folder: Option<&str>,
) -> (u16, Value) {
    let mut body = json!({ "device_id": device });
    if let Some(f) = folder {
        body["folder"] = json!(f);
    }
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/teleport"),
            token,
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Teleport `m`'s session to `b` into `folder`, `b` answering its prepare
/// `answer` (`None` = ready): the route's answer and the prepare `b` got.
async fn teleport_answered(
    app: &TestApp,
    m: &mut Moving,
    folder: Option<&str>,
    answer: Option<Value>,
) -> (Value, Value) {
    let (tid, admin, sid, to) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.b.agent_id.clone(),
    );
    let caller = post_teleport(app, &tid, &admin, &sid, &to, folder);
    let target = async {
        let prep = read_until(&mut m.b.ws, "rc:hive.prepare")
            .await
            .expect("the target is asked to prepare");
        let mut ack = json!({"t": "rc:hive.prepare_ack", "session_id": sid,
                             "fence": prep["fence"], "account": "dev"});
        if let Some(Value::Object(extra)) = answer {
            for (k, v) in extra {
                ack[k] = v;
            }
        }
        send(&mut m.b.ws, ack).await;
        prep
    };
    let ((code, body), prep) = tokio::join!(caller, target);
    assert_eq!(code, 200, "{body}");
    (body, prep)
}

/// [`teleport_answered`], ready: the target is sent its join (returned), the
/// primary its own, and the record is `joining`.
async fn joining(app: &TestApp, m: &mut Moving, folder: Option<&str>) -> Value {
    let (body, prep) = teleport_answered(app, m, folder, None).await;
    assert_eq!(body["outcome"], "teleporting", "{body}");
    assert_eq!(
        prep["teleport"], true,
        "a teleport's prepare says so: {prep}"
    );
    let join = read_until(&mut m.b.ws, "rc:hive.replica.join")
        .await
        .expect("the target is sent its join");
    assert_eq!(
        (join["fence"].as_u64(), join["role"].as_str()),
        (Some(1), Some("teleport")),
        "{join}"
    );
    join
}

/// A join's answer, `joined`, from `ws` at fence 1.
async fn joined(ws: &mut AgentWs, sid: &str) {
    send(
        ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
}

/// The `teleport` audit rows of `sid`, in order: (outcome, reason).
async fn teleport_audit(app: &TestApp, sid: &str) -> Vec<(String, String)> {
    let mut rows = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "session_id": ObjectId::parse_str(sid).unwrap(), "action": "teleport" })
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(d) = rows.next().await {
        let d = d.unwrap();
        out.push((
            d.get_str("outcome").unwrap().to_string(),
            d.get_str("reason").unwrap_or("").to_string(),
        ));
    }
    out
}

/// FR-90 P2f-1 — the whole teleport, with fake devices at both ends. The
/// target, which holds no copy and does not hold copies at all, is asked a
/// teleport's prepare; ready, it joins the replicaset in the `teleport` role
/// and is sent its join, the session that ran alone is leased and its
/// primary sent its join as the primary. Nothing drains until both answered,
/// the primary said where its copy ends, and the target's copy holds that
/// much; then the drain, the sync and the move run as a promotion's, the
/// target the primary at fence 2, in the folder the teleport named. Every
/// audit row says `teleport`.
#[tokio::test]
async fn a_teleport_joins_its_target_then_moves_the_session_as_a_promotion() {
    let app = teleport_app().await;
    let mut m = teleportable(&app, "teleport", TELEPORT_TARGET).await;
    let sid = m.sid.clone();
    let (body, prep) = teleport_answered(&app, &mut m, Some("/srv/elsewhere"), None).await;
    assert_eq!(body["outcome"], "teleporting", "{body}");
    assert_eq!(
        (
            prep["teleport"].as_bool(),
            prep["fence"].as_u64(),
            prep["folder"].as_str()
        ),
        (Some(true), Some(2), Some("/srv/elsewhere")),
        "{prep}"
    );
    assert_eq!(
        (
            body["session"]["promotion"]["state"].as_str(),
            body["session"]["promotion"]["teleport"].as_bool()
        ),
        (Some("joining"), Some(true)),
        "{body}"
    );

    let b_join = read_until(&mut m.b.ws, "rc:hive.replica.join")
        .await
        .expect("the target is sent its join, though it holds no copies");
    assert_eq!(
        (b_join["fence"].as_u64(), b_join["role"].as_str()),
        (Some(1), Some("teleport")),
        "{b_join}"
    );
    // The lease word goes first, then the join: each read in its turn.
    let word = arrives(&mut m.a.ws, "rc:hive.lease", Duration::from_secs(5)).await;
    assert!(
        word.is_some_and(|w| w["fence"] == 1),
        "a session that ran alone is leased from its first member on"
    );
    let a_join = arrives(&mut m.a.ws, "rc:hive.replica.join", Duration::from_secs(5))
        .await
        .unwrap_or(Value::Null);
    assert_eq!(
        (a_join["fence"].as_u64(), a_join["role"].as_str()),
        (Some(1), Some("primary")),
        "the primary is asked to join as the primary: {a_join}"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(promotion_state(&s), Some("joining"));
    assert_eq!(
        stored_member(&s, &m.b.agent_id),
        ("teleport".into(), "pending".into())
    );
    assert_eq!(
        stored_member(&s, &m.a.agent_id),
        ("primary".into(), "pending".into()),
        "a session that ran alone: its primary is owed its join"
    );

    joined(&mut m.b.ws, &sid).await;
    joined(&mut m.a.ws, &sid).await;
    send(&mut m.a.ws, tip_at(&sid, 1, 7, "ab")).await;
    send(&mut m.b.ws, tip_at(&sid, 1, 5, "cd")).await;
    assert!(
        !device_hears(&mut m.a.ws, "rc:hive.drain", Duration::from_millis(800)).await,
        "the target's copy is behind the primary's: no drain"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(promotion_state(&s), Some("joining"));
    assert_eq!(
        (
            stored_member(&s, &m.b.agent_id),
            stored_member(&s, &m.a.agent_id)
        ),
        (
            ("teleport".into(), "joined".into()),
            ("primary".into(), "joined".into())
        )
    );
    send(&mut m.b.ws, tip_at(&sid, 1, 7, "ab")).await;
    let drain = read_until(&mut m.a.ws, "rc:hive.drain")
        .await
        .expect("caught up: the primary is told to drain");
    assert_eq!(drain["fence"], 1);

    send(&mut m.a.ws, drained(&sid, 8, "ef")).await;
    wait_stored(&app, &sid, "syncing", |s| {
        promotion_state(s) == Some("syncing")
    })
    .await;
    send(&mut m.b.ws, tip_at(&sid, 1, 8, "ef")).await;
    let b_frames = frames_until(
        &mut m.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    let kinds: Vec<&str> = b_frames.iter().map(|f| f["t"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"]
    );
    assert_eq!(
        (b_frames[0]["fence"].as_u64(), b_frames[0]["role"].as_str()),
        (Some(2), Some("primary"))
    );
    assert_eq!(
        (
            b_frames[2]["fence"].as_u64(),
            b_frames[2]["folder"].as_str()
        ),
        (Some(2), Some("/srv/elsewhere")),
        "the folder the teleport named"
    );
    let s = stored(&app, &sid).await;
    assert_eq!(s.get_i64("fence").unwrap(), 2);
    assert_eq!(
        stored_member(&s, &m.b.agent_id),
        ("primary".into(), "pending".into())
    );
    assert_eq!(
        stored_member(&s, &m.a.agent_id),
        ("owner".into(), "pending".into()),
        "the old primary, the owner's own that holds copies, stays a member"
    );
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2, "account": "dev"}),
    )
    .await;
    wait_stored(&app, &sid, "done", |s| {
        !s.contains_key("promotion") && s.get_datetime("accepted_at").is_ok()
    })
    .await;
    assert_eq!(
        notes_with(&app, &m, "which holds no copy of it yet")
            .await
            .len(),
        1
    );
    assert_eq!(wait_note(&app, &m, "🔀 Moved from").await.len(), 1);
    assert_eq!(
        teleport_audit(&app, &sid).await,
        [
            ("sent".to_string(), String::new()),
            ("moved".to_string(), String::new()),
            ("done".to_string(), String::new()),
        ]
    );
    assert!(
        promote_audit(&app, &sid).await.is_empty(),
        "no row of it reads as a promotion"
    );
}

/// FR-90 P2f-2b — a teleport's prepare tells its target it may take the
/// workspace's first pack as one against what its folder's repository holds
/// (`have_want`) only where the deployment turned that on
/// (`hive.teleport_have_want`, default off: decision 16 is the operator's);
/// a promotion's never does, its target holding a copy already. Off, the
/// prepare carries no word of it, as an older server's.
#[tokio::test]
async fn only_a_teleports_prepare_says_have_and_want_and_only_once_turned_on() {
    for on in [false, true] {
        let app = TestApp::spawn_with_settings(|s| {
            s.modules.hive = true;
            s.hive.replicaset = true;
            s.hive.promote_prepare_secs = 4;
            s.hive.promote_join_secs = 6;
            s.hive.promote_drain_secs = 4;
            s.hive.promote_sync_secs = 4;
            s.hive.teleport_have_want = on;
            s.app.rate_limit_per_sec = 100;
            s.app.rate_limit_burst = 1000;
        })
        .await;
        let mut t = teleportable(&app, &format!("havewant{on}"), TELEPORT_TARGET).await;
        let (body, prep) = teleport_answered(&app, &mut t, None, None).await;
        assert_eq!(body["outcome"], "teleporting", "{body}");
        assert_eq!(
            (prep["teleport"].as_bool(), prep.get("have_want")),
            (Some(true), on.then_some(&json!(true))),
            "a teleport's prepare, turned on {on}: {prep}"
        );
        let mut p = promotable(&app, &format!("havewantpromote{on}"), 0, PROMOTES).await;
        let (body, prep) = promote_answered(&app, &mut p, None).await;
        assert_eq!(body["outcome"], "promoting", "{body}");
        assert_eq!(
            (prep.get("teleport"), prep.get("have_want")),
            (None, None),
            "a promotion's prepare, turned on {on}: {prep}"
        );
    }
}

/// FR-90 P2f-2d — a teleport's target whose folder holds work of its own
/// refuses the prepare `folder_dirty`: the caller is answered in those words,
/// with the target's own detail (the sibling it names for the person to
/// make), and nothing moves.
#[tokio::test]
async fn a_teleport_into_a_folder_holding_work_of_its_own_is_refused_in_words() {
    let app = teleport_app().await;
    let mut m = teleportable(&app, "teleportdirty", TELEPORT_TARGET).await;
    let detail = "it is neither what its HEAD holds nor what this session last left there; \
                  make a sibling, e.g. `git worktree add /srv/clone-hive-1234abcd`, and teleport there";
    let (body, _) = teleport_answered(
        &app,
        &mut m,
        Some("/srv/clone"),
        Some(json!({"refused": "folder_dirty", "detail": detail})),
    )
    .await;
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("folder_dirty")),
        "{body}"
    );
    // The room's words, escaped for Markdown.
    let said = body["message"]
        .as_str()
        .unwrap_or_default()
        .replace('\\', "");
    assert!(
        said.contains("holds work of its own")
            && said.contains("git worktree add /srv/clone-hive-1234abcd"),
        "the room's words: {body}"
    );
    assert!(
        body["session"].get("promotion").is_none(),
        "nothing moves: {body}"
    );
}

/// FR-90 P2f-1 — a teleport is refused by the gate it failed, each in its
/// own word: the route is not there with the replicaset off; a device that
/// holds a copy already is promoted to, not teleported to; the target and the
/// primary must both advertise `hive-teleport`, and both be online: a
/// teleport copies the session from its primary.
#[tokio::test]
async fn a_teleport_is_refused_by_the_gate_it_failed() {
    let off = hive_app().await;
    let seeded = off.seed_tenant("teleportoff").await;
    let (code, _) = post_teleport(
        &off,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        &ObjectId::new().to_hex(),
        &ObjectId::new().to_hex(),
        None,
    )
    .await;
    assert_eq!(code, 404, "with the replicaset off the route is not there");

    let app = teleport_app().await;
    let refused = |body: &Value, why: &str| {
        assert_eq!(
            (body["outcome"].as_str(), body["reason"].as_str()),
            (Some("refused"), Some(why)),
            "{body}"
        );
        assert!(body["message"].as_str().is_some_and(|t| !t.is_empty()));
    };
    // A session with a member that took its copy; its primary takes no part
    // in a teleport.
    let mut p = promotable(&app, "teleportmember", 0, PROMOTES).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let try_to = |sid: String, device: String| {
        let (app, tid, admin) = (&app, tid.clone(), admin.clone());
        async move {
            post_teleport(app, &tid, &admin, &sid, &device, None)
                .await
                .1
        }
    };
    refused(
        &try_to(sid.clone(), p.b.agent_id.clone()).await,
        "already_a_member",
    );
    refused(
        &try_to(sid.clone(), p.a.agent_id.clone()).await,
        "already_primary",
    );
    let target = device(&app, &p.seeded, "mach-teleportmember-t", TELEPORT_TARGET).await;
    refused(
        &try_to(sid.clone(), target.agent_id.clone()).await,
        "primary_unsupported",
    );
    let old = device(&app, &p.seeded, "mach-teleportmember-o", PROMOTES).await;
    refused(
        &try_to(sid.clone(), old.agent_id.clone()).await,
        "device_unsupported",
    );
    p.b.ws.close(None).await.unwrap();

    // A session alone: its primary offline, then the target too.
    let mut m = teleportable(&app, "teleportgate", TELEPORT_TARGET).await;
    m.a.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.a.agent_id).await;
    let (_, body) = post_teleport(&app, &m.tid, &m.admin, &m.sid, &m.b.agent_id, None).await;
    refused(&body, "primary_offline");
    m.b.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.b.agent_id).await;
    let (_, body) = post_teleport(&app, &m.tid, &m.admin, &m.sid, &m.b.agent_id, None).await;
    refused(&body, "device_offline");

    let reasons = |rows: Vec<(String, String)>| -> Vec<String> {
        rows.into_iter()
            .filter(|(o, _)| o == "refused")
            .map(|(_, r)| r)
            .collect()
    };
    assert_eq!(
        reasons(teleport_audit(&app, &sid).await),
        [
            "already_a_member",
            "already_primary",
            "primary_unsupported",
            "device_unsupported"
        ]
    );
    assert_eq!(
        reasons(teleport_audit(&app, &m.sid).await),
        ["primary_offline", "device_offline"]
    );
}

/// FR-90 P2f-1 — a target that refuses its join fails the teleport in its
/// word: nothing drains, the target's copy is let go (`leaving`), and the
/// room says why.
#[tokio::test]
async fn a_teleport_whose_target_refuses_its_join_lets_it_go() {
    let app = teleport_app().await;
    let mut m = teleportable(&app, "teleportrefuse", TELEPORT_TARGET).await;
    let sid = m.sid.clone();
    joining(&app, &mut m, None).await;
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1,
               "refused": "not_prepared", "detail": "a restart came between"}),
    )
    .await;
    wait_stored(&app, &sid, "the teleport fails", |s| {
        !s.contains_key("promotion")
    })
    .await;
    // `fail` ends the promotion, lets the target go, audits, then tells the
    // room, each its own write: once the room is told, the rest is there.
    let why = wait_note(&app, &m, "did not take a copy of the session").await;
    assert!(why[0].contains("no longer prepared"), "{}", why[0]);
    let s = stored(&app, &sid).await;
    assert_eq!(
        teleport_audit(&app, &sid).await.last(),
        Some(&("failed".to_string(), "join_refused".to_string())),
        "failed in the device's word"
    );
    assert_eq!(
        stored_member(&s, &m.b.agent_id),
        ("teleport".into(), "leaving".into()),
        "its copy is let go"
    );
    assert_eq!(s.get_i64("fence").unwrap(), 1, "nothing moved");
    assert!(
        !device_hears(&mut m.a.ws, "rc:hive.drain", Duration::from_millis(500)).await,
        "the primary never drains"
    );
}

/// FR-90 P2f-1 — a target whose copy never catches up fails the teleport at
/// the joining step's bound: the primary was never told to drain, so it has
/// nothing to give back, and the target's copy is let go.
#[tokio::test]
async fn a_teleport_whose_target_never_catches_up_fails_at_its_bound() {
    let app = teleport_app().await;
    let mut m = teleportable(&app, "teleportslow", TELEPORT_TARGET).await;
    let sid = m.sid.clone();
    joining(&app, &mut m, None).await;
    joined(&mut m.b.ws, &sid).await;
    joined(&mut m.a.ws, &sid).await;
    send(&mut m.a.ws, tip_at(&sid, 1, 9, "ab")).await;
    send(&mut m.b.ws, tip_at(&sid, 1, 3, "cd")).await;
    wait_stored(&app, &sid, "the joining step runs out", |s| {
        !s.contains_key("promotion")
    })
    .await;
    // As above: the room is told last, after the target is let go.
    let why = wait_note(&app, &m, "did not catch up in time").await;
    assert_eq!(why.len(), 1, "{why:?}");
    assert_eq!(
        stored_member(&stored(&app, &sid).await, &m.b.agent_id),
        ("teleport".into(), "leaving".into())
    );
    assert!(
        !device_hears(&mut m.a.ws, "rc:hive.drain", Duration::from_millis(300)).await,
        "never drained"
    );
    assert_eq!(
        teleport_audit(&app, &sid).await.last(),
        Some(&("failed".to_string(), "join_timeout".to_string()))
    );
}

/// FR-90 P2f-1 — a target back before it answered its join is sent it again
/// on a connection that takes a teleport, whatever it says of holding
/// copies; never on one that does not.
#[tokio::test]
async fn a_teleports_target_back_before_it_answered_hears_its_join_again() {
    // Two disconnections fit in the joining step's bound.
    let app = teleport_app_joining(60).await;
    let mut m = teleportable(&app, "teleportback", TELEPORT_TARGET).await;
    let sid = m.sid.clone();
    joining(&app, &mut m, None).await;
    m.b.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.b.agent_id).await;

    m.b.ws = connect(&app, &m.b.token, &m.b.machine, HOLDS_COPIES).await;
    wait_agent_online(&app, &m.seeded, &m.b.agent_id).await;
    assert!(
        arrives(
            &mut m.b.ws,
            "rc:hive.replica.join",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "a connection that holds copies but takes no teleport: no join"
    );
    m.b.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.b.agent_id).await;

    m.b.ws = connect(&app, &m.b.token, &m.b.machine, TELEPORT_TARGET).await;
    let join = read_until(&mut m.b.ws, "rc:hive.replica.join")
        .await
        .expect("sent again on a connection that takes a teleport");
    assert_eq!(
        (join["fence"].as_u64(), join["role"].as_str()),
        (Some(1), Some("teleport")),
        "{join}"
    );
    joined(&mut m.b.ws, &sid).await;
    let s = wait_stored(&app, &sid, "joined", |s| {
        stored_member(s, &m.b.agent_id).1 == "joined"
    })
    .await;
    assert_eq!(promotion_state(&s), Some("joining"));
}

/// FR-90 P2f-1 — placement decided again while a teleport joins leaves its
/// target alone: no placement chose it, and it must not be let go for that.
#[tokio::test]
async fn a_placement_decided_again_leaves_a_teleports_target_alone() {
    let app = teleport_app().await;
    let mut m = teleportable(&app, "teleportplace", TELEPORT_TARGET).await;
    let sid = m.sid.clone();
    joining(&app, &mut m, None).await;
    let (code, p) = put_policy(&app, &m.tid, &m.admin, &policy_min(2, 1)).await;
    assert_eq!(code, 200, "{p}");
    // Placed again: the record names the policy the placement read.
    let s = wait_stored(&app, &sid, "placed again", |s| {
        s.get_document("replicaset")
            .is_ok_and(|r| r.get_i64("policy_revision") == Ok(2))
    })
    .await;
    assert_eq!(promotion_state(&s), Some("joining"));
    assert_eq!(
        stored_member(&s, &m.b.agent_id),
        ("teleport".into(), "pending".into()),
        "the teleport's, not placement's"
    );
}

/// FR-90 P2f-1 — a moved start its target refuses moves the lease back, as
/// a promotion's does, and lets the target's copy go: it is `leaving`, never
/// owed its join again.
#[tokio::test]
async fn a_teleports_moved_start_the_target_refuses_lets_its_copy_go() {
    let app = teleport_app().await;
    let mut m = teleportable(&app, "teleportback2", TELEPORT_TARGET).await;
    let sid = m.sid.clone();
    joining(&app, &mut m, None).await;
    joined(&mut m.b.ws, &sid).await;
    joined(&mut m.a.ws, &sid).await;
    send(&mut m.a.ws, tip_at(&sid, 1, 4, "ab")).await;
    send(&mut m.b.ws, tip_at(&sid, 1, 4, "ab")).await;
    read_until(&mut m.a.ws, "rc:hive.drain")
        .await
        .expect("the primary drains");
    send(&mut m.a.ws, drained(&sid, 4, "ab")).await;
    let start = read_until(&mut m.b.ws, "rc:hive.start")
        .await
        .expect("the moved start");
    assert_eq!(start["fence"], 2);
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2,
               "refused": "launch_failed", "detail": "the folder could not be put in place"}),
    )
    .await;
    let s = wait_stored(&app, &sid, "the lease moves back", |s| {
        s.get_i64("fence").ok() == Some(3)
    })
    .await;
    assert_eq!(
        s.get_document("location")
            .unwrap()
            .get_object_id("device_id")
            .unwrap()
            .to_hex(),
        m.a.agent_id
    );
    assert_eq!(
        stored_member(&s, &m.b.agent_id),
        ("teleport".into(), "leaving".into()),
        "let go, not owed its join again"
    );
    assert!(
        arrives(
            &mut m.b.ws,
            "rc:hive.replica.join",
            Duration::from_millis(600)
        )
        .await
        .is_none(),
        "no join at the new fence"
    );
}

// ─── FR-90 P2f-3b — a fork ─────────────────────────────────────────────────

/// What a build that starts a fork from its parent's copy advertises: a
/// promotion's words, and `hive-fork`.
const FORKS: &[&str] = &[
    "exec",
    "hive",
    "hive-replica",
    "hive-stream",
    "hive-lease",
    "hive-promote",
    "hive-fork",
];

/// [`promote_app`], a fork's wait for its device's copy bound to 2 s.
async fn fork_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.hive.promote_prepare_secs = 4;
        s.hive.promote_drain_secs = 4;
        s.hive.promote_sync_secs = 4;
        s.hive.fork_copy_secs = 2;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// A tip of `sid` at fence 1, its copy's last checkpoint at `checkpoint`.
fn tip_with_checkpoint(sid: &str, seq: u64, checkpoint: u64) -> Value {
    json!({"t": "rc:hive.replica.tip", "session_id": sid, "fence": 1, "seq": seq,
           "hash": hash("e"), "checkpoint": {"seq": checkpoint, "hash": hash("c")}})
}

/// The last checkpoint the stored member `device` of `s` reported.
fn checkpoint_seq_of(s: &Document, device: &str) -> Option<i64> {
    let id = ObjectId::parse_str(device).unwrap();
    s.get_document("replicaset")
        .ok()?
        .get_array("members")
        .ok()?
        .iter()
        .filter_map(|m| m.as_document())
        .find(|m| m.get_object_id("device_id").ok() == Some(id))?
        .get_document("tip")
        .ok()?
        .get_i64("checkpoint_seq")
        .ok()
}

/// A replicated session running on `a`, which advertises [`FORKS`], at fence
/// 1, whose member `b` (advertising `b_caps`) took its copy.
async fn forkable(app: &TestApp, tag: &str, b_caps: &[&str]) -> Moving {
    forkable_with(app, tag, FORKS, b_caps).await
}

/// [`forkable`], its primary advertising `a_caps`.
async fn forkable_with(app: &TestApp, tag: &str, a_caps: &[&str], b_caps: &[&str]) -> Moving {
    let seeded = app.seed_tenant(tag).await;
    on_pro(app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let (code, p) = put_policy(app, &tid, &admin, &policy_min(2, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut a = device(app, &seeded, &format!("mach-{tag}-a"), a_caps).await;
    let mut b = device(app, &seeded, &format!("mach-{tag}-b"), b_caps).await;
    let (s, frame) = started_frame(app, &tid, &admin, &mut a, &format!("/srv/{tag}")).await;
    assert_eq!(frame["replicated"], true, "{frame}");
    let sid = s["id"].as_str().unwrap().to_string();
    read_until(&mut b.ws, "rc:hive.replica.join")
        .await
        .expect("the member's join");
    send(
        &mut b.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
    let id = b.agent_id.clone();
    wait_member(app, &tid, &admin, &sid, &id, "joined", |m| {
        m["state"] == "joined"
    })
    .await;
    Moving {
        tid,
        admin,
        admin_id: seeded.admin.id.clone(),
        sid,
        a,
        b,
        more: Vec::new(),
        seeded,
    }
}

/// The session's first turn ends on its primary, which reports no checkpoint
/// of it yet.
async fn turn_ended(app: &TestApp, m: &mut Moving) {
    let sid = m.sid.clone();
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.turn", "session_id": sid, "fence": 1, "turn": 1,
               "status": "ok", "prompted_by": m.admin_id, "steps": 1, "duration_ms": 10}),
    )
    .await;
    wait_stored(app, &sid, "the turn", |s| {
        s.get_document("last_turn").is_ok()
    })
    .await;
}

/// The session's first turn ends on its primary, which then reports its tip
/// at its checkpoint 5; the member's copy reports `member_checkpoint`.
async fn kept_a_turn(app: &TestApp, m: &mut Moving, member_checkpoint: u64) {
    turn_ended(app, m).await;
    checkpointed(app, m, member_checkpoint).await;
}

/// The primary reports its tip at its checkpoint 5, the member's copy at
/// `member_checkpoint`.
async fn checkpointed(app: &TestApp, m: &mut Moving, member_checkpoint: u64) {
    let sid = m.sid.clone();
    send(&mut m.a.ws, tip_with_checkpoint(&sid, 6, 5)).await;
    send(&mut m.b.ws, tip_with_checkpoint(&sid, 6, member_checkpoint)).await;
    let (a, b) = (m.a.agent_id.clone(), m.b.agent_id.clone());
    wait_stored(app, &sid, "the turn, and both copies' checkpoints", |s| {
        s.get_document("last_turn").is_ok()
            && checkpoint_seq_of(s, &a) == Some(5)
            && checkpoint_seq_of(s, &b) == i64::try_from(member_checkpoint).ok()
    })
    .await;
}

async fn post_fork(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    device: &str,
    folder: &str,
) -> (u16, Value) {
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/hive/session/{sid}/fork"), token)
        .json(&json!({ "device_id": device, "folder": folder }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Fork `sid` onto `dev`, which accepts the fork's start: the route's answer
/// and the `rc:hive.start` the device received.
async fn forked(
    app: &TestApp,
    dev: &mut Device,
    tid: &str,
    token: &str,
    sid: &str,
    folder: &str,
) -> (Value, Value) {
    let caller = post_fork(app, tid, token, sid, &dev.agent_id, folder);
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives the fork's start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
        frame
    };
    let ((code, body), frame) = tokio::join!(caller, target);
    assert_eq!(code, 200, "{body}");
    (body, frame)
}

/// The notes in `sid`'s room whose text contains `needle`.
async fn notes_in(app: &TestApp, tid: &str, token: &str, sid: &str, needle: &str) -> Vec<String> {
    let room = stored(app, sid)
        .await
        .get_object_id("room_id")
        .unwrap()
        .to_hex();
    room_messages(app, tid, token, &room)
        .await
        .1
        .iter()
        .filter_map(|i| i["content"].as_str())
        .filter(|c| c.contains(needle))
        .map(str::to_string)
        .collect()
}

/// The `fork` audit rows naming `parent` as the session forked, in order:
/// (outcome, reason, the fork's id).
async fn fork_audit(app: &TestApp, parent: &str) -> Vec<(String, String, String)> {
    let mut rows = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "target_id": ObjectId::parse_str(parent).unwrap(), "action": "fork" })
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(d) = rows.next().await {
        let d = d.unwrap();
        out.push((
            d.get_str("outcome").unwrap().to_string(),
            d.get_str("reason").unwrap_or("").to_string(),
            d.get_object_id("session_id")
                .map(|o| o.to_hex())
                .unwrap_or_default(),
        ));
    }
    out
}

/// FR-90 P2f-3b — a fork on a member that holds the session's last
/// checkpoint: a new record, its owner's, with its own harness id and room,
/// naming its parent and carrying its restricted tags; its start names the
/// parent; both rooms say so, and the audit names the session it forks. The
/// parent is as it was.
#[tokio::test]
async fn a_fork_on_a_member_is_a_new_session_whose_start_names_its_parent() {
    let app = fork_app().await;
    let mut m = forkable(&app, "fork", FORKS).await;
    kept_a_turn(&app, &mut m, 5).await;
    let parent = stored(&app, &m.sid).await;
    let parent_harness = parent
        .get_document("harness")
        .unwrap()
        .get_str("session")
        .unwrap()
        .to_string();
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    // The session carries a restricted tag the policy does not name, which
    // the fork's device carries and the parent's primary does not: only the
    // parent's tags can restrict the fork to it.
    set_device(&app, &m.b.agent_id, doc! { "tags": ["secret"] }).await;
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "replicaset.restricted_tags": ["secret"] } },
        )
        .await
        .unwrap();

    let (body, frame) = forked(&app, &mut m.b, &tid, &admin, &sid, "/srv/fork-b").await;
    assert_eq!(body["outcome"], "accepted", "{body}");
    let fork = &body["session"];
    let fsid = fork["id"].as_str().unwrap().to_string();
    assert_ne!(fsid, sid);
    assert_eq!(
        fork["parent_session_id"], sid,
        "the fork names its parent: {fork}"
    );
    assert_eq!(fork["title"], "Fork of fork", "{fork}");
    assert_eq!(fork["owner_id"], m.admin_id);
    assert_eq!(fork["device_id"], m.b.agent_id);
    assert_eq!(fork["folder"], "/srv/fork-b");
    assert_ne!(
        fork["harness_session"], parent_harness,
        "a harness id of its own"
    );
    assert_eq!(
        frame["fork_of"],
        json!({"session_id": sid, "harness_session": parent_harness}),
        "the start names its parent: {frame}"
    );
    assert_eq!(frame["session_id"], fsid);
    assert_eq!(frame["fence"], 1);
    assert_eq!(frame["resume"], false);

    let stored_fork = stored(&app, &fsid).await;
    let link = stored_fork.get_document("parent").unwrap();
    assert_eq!(link.get_object_id("session_id").unwrap().to_hex(), sid);
    assert_eq!(link.get_str("harness_session").unwrap(), parent_harness);
    assert_ne!(
        stored_fork.get_object_id("room_id").unwrap(),
        parent.get_object_id("room_id").unwrap(),
        "a room of its own"
    );
    let placed = stored_fork
        .get_document("replicaset")
        .expect("placed under the rules");
    // An empty list is left out of the record: read it as empty.
    let restricted = placed
        .get_array("restricted_tags")
        .map(|a| a.to_vec())
        .unwrap_or_default();
    assert_eq!(
        restricted,
        vec![bson::Bson::String("secret".into())],
        "a fork of a restricted session is restricted: {placed}"
    );
    let a_id = ObjectId::parse_str(&m.a.agent_id).unwrap();
    assert!(
        !placed
            .get_array("members")
            .unwrap()
            .iter()
            .filter_map(|x| x.as_document())
            .any(|x| x.get_object_id("device_id").ok() == Some(a_id)),
        "the parent's primary lacks the tag, so it holds no copy of the fork: {placed}"
    );
    assert_eq!(placed.get_str("short").ok(), Some("restricted"), "{placed}");

    assert_eq!(
        notes_in(
            &app,
            &tid,
            &admin,
            &sid,
            "forked the session into **Fork of fork**"
        )
        .await
        .len(),
        1,
        "the parent's room says so, once"
    );
    assert_eq!(
        notes_in(&app, &tid, &admin, &fsid, "A fork of **fork**")
            .await
            .len(),
        1,
        "the fork's room says what it was made from"
    );
    assert_eq!(
        fork_audit(&app, &sid).await,
        [("sent".to_string(), String::new(), fsid.clone())],
        "the audit names the session forked"
    );
    let after = stored(&app, &sid).await;
    assert_eq!(
        after.get_str("status").unwrap(),
        parent.get_str("status").unwrap(),
        "the parent goes on as it was"
    );
    assert!(after.get_document("parent").is_err());
}

/// FR-90 P2f-3b — a fork on the session's own primary runs in a folder of its
/// own: there the copy is current by definition. The session's own folder is
/// refused `same_folder`.
#[tokio::test]
async fn a_fork_on_its_primary_needs_a_folder_of_its_own() {
    let app = fork_app().await;
    let mut m = forkable(&app, "forkhere", FORKS).await;
    kept_a_turn(&app, &mut m, 1).await;
    let (tid, admin, sid, a) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.a.agent_id.clone(),
    );
    let (code, body) = post_fork(&app, &tid, &admin, &sid, &a, "/srv/forkhere").await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("same_folder")),
        "{body}"
    );
    assert!(body.get("session").is_none(), "no record: {body}");

    // A fork the device refuses: its own room says so, the parent's nothing.
    let caller = post_fork(&app, &tid, &admin, &sid, &a, "/srv/forkhere-dirty");
    let target = async {
        let frame = read_until(&mut m.a.ws, "rc:hive.start")
            .await
            .expect("the device receives the fork's start");
        send(
            &mut m.a.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "refused": "folder_dirty"}),
        )
        .await;
    };
    let ((code, body), ()) = tokio::join!(caller, target);
    assert_eq!(
        (code, body["outcome"].as_str(), body["reason"].as_str()),
        (200, Some("refused"), Some("folder_dirty")),
        "{body}"
    );
    assert!(
        notes_in(&app, &tid, &admin, &sid, "forked the session into")
            .await
            .is_empty(),
        "the parent's room says nothing of a fork its device refused"
    );

    // The member's copy is behind; the primary's is not.
    let (body, frame) = forked(&app, &mut m.a, &tid, &admin, &sid, "/srv/forkhere-2").await;
    assert_eq!(body["outcome"], "accepted", "{body}");
    assert_eq!(frame["fork_of"]["session_id"], sid, "{frame}");
    assert_eq!(body["session"]["device_id"], a);
    assert_eq!(
        notes_in(&app, &tid, &admin, &sid, "forked the session into")
            .await
            .len(),
        1,
        "the parent's room tells of the fork its device took"
    );
}

/// FR-90 P2f-3b — a member's copy must reach the session's last checkpoint
/// first: a fork waits for it, and goes ahead once it does; one that never
/// does is refused `copy_behind` at the bound, and nothing is made.
#[tokio::test]
async fn a_fork_waits_for_the_members_copy_to_reach_the_last_checkpoint() {
    let app = fork_app().await;
    let mut m = forkable(&app, "forklag", FORKS).await;
    kept_a_turn(&app, &mut m, 3).await;
    let (tid, admin, sid, b) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.b.agent_id.clone(),
    );

    let started = Instant::now();
    let (code, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/forklag-b").await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("copy_behind")),
        "{body}"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "it waited out its bound"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "its bound is the setting's, not the default's: {:?}",
        started.elapsed()
    );
    assert!(
        arrives(&mut m.b.ws, "rc:hive.start", Duration::from_millis(300))
            .await
            .is_none(),
        "nothing reached the member"
    );

    // Caught up while the fork waits: it goes ahead.
    let caller = post_fork(&app, &tid, &admin, &sid, &b, "/srv/forklag-b");
    let target = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        send(&mut m.b.ws, tip_with_checkpoint(&sid, 7, 5)).await;
        let frame = read_until(&mut m.b.ws, "rc:hive.start")
            .await
            .expect("the fork's start, once the copy caught up");
        send(
            &mut m.b.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": 1, "account": "dev"}),
        )
        .await;
        frame
    };
    let ((code, body), frame) = tokio::join!(caller, target);
    assert_eq!(
        (code, body["outcome"].as_str()),
        (200, Some("accepted")),
        "{body}"
    );
    assert_eq!(frame["fork_of"]["session_id"], sid);
    let rows = fork_audit(&app, &sid).await;
    assert_eq!(
        rows.iter()
            .map(|(o, r, _)| (o.as_str(), r.as_str()))
            .collect::<Vec<_>>(),
        [("refused", "copy_behind"), ("sent", "")]
    );
}

/// FR-90 P2f-3b — each gate refuses in its own words, and audits it: a
/// session with no turn kept, or no checkpoint of one; an archived org; an
/// owner without `HIVE_RUN`; an adopted session; a device that holds no copy
/// and takes none (P2f-3c: no `hive-teleport`), or a member that has not taken
/// its copy and takes none either; one that lacks a restricted tag;
/// a session moving; one that does not start forks, or is offline; a session
/// alone has no copy to fork; another person's session, or a server with the
/// replicaset off, is not there at all.
#[tokio::test]
async fn a_fork_is_refused_by_the_gate_it_failed() {
    let app = fork_app().await;

    // No turn kept yet.
    let mut m = forkable(&app, "forkgate", FORKS).await;
    let (tid, admin, sid, b) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.b.agent_id.clone(),
    );
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/g").await;
    assert_eq!(body["reason"], "no_conversation", "{body}");
    // A turn kept, and no checkpoint of it reported by its primary.
    turn_ended(&app, &mut m).await;
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/g").await;
    assert_eq!(body["reason"], "no_conversation", "{body}");
    checkpointed(&app, &mut m, 5).await;

    let sessions = app.db.collection::<Document>("agent_sessions");
    let this = doc! { "_id": ObjectId::parse_str(&sid).unwrap() };
    // The org archived.
    let tenants = app.db.collection::<Document>("tenants");
    let org = doc! { "_id": ObjectId::parse_str(&tid).unwrap() };
    for archived in [true, false] {
        tenants
            .update_one(org.clone(), doc! { "$set": { "is_archived": archived } })
            .await
            .unwrap();
        if archived {
            let (_, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/g").await;
            assert_eq!(body["reason"], "org_archived", "{body}");
        }
    }
    // An owner who lost `HIVE_RUN` since the session started: the session
    // made the member's, who holds no role with it.
    let member = m.seeded.member.access_token.clone();
    for owner in [&m.seeded.member.id, &m.admin_id] {
        sessions
            .update_one(
                this.clone(),
                doc! { "$set": { "owner_id": ObjectId::parse_str(owner).unwrap() } },
            )
            .await
            .unwrap();
        if *owner != m.admin_id {
            let (_, body) = post_fork(&app, &tid, &member, &sid, &b, "/srv/g").await;
            assert_eq!(body["reason"], "no_permission", "{body}");
        }
    }
    // An adopted session: its terminal holds the harness, and no checkpoint
    // of it is kept.
    for origin in ["adopted", "started"] {
        sessions
            .update_one(this.clone(), doc! { "$set": { "origin": origin } })
            .await
            .unwrap();
        if origin == "adopted" {
            let (_, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/g").await;
            assert_eq!(body["reason"], "not_forkable", "{body}");
        }
    }

    // A device of the org that holds no copy, and takes none: it does not
    // advertise `hive-teleport` (P2f-3c).
    let c = device(&app, &m.seeded, "mach-forkgate-c", FORKS).await;
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &c.agent_id, "/srv/g").await;
    assert_eq!(body["reason"], "device_unsupported", "{body}");
    // A member whose copy is not taken yet holds none either, and takes none.
    let b_row = doc! {
        "_id": ObjectId::parse_str(&sid).unwrap(),
        "replicaset.members.device_id": ObjectId::parse_str(&b).unwrap(),
    };
    for state in ["pending", "joined"] {
        sessions
            .update_one(
                b_row.clone(),
                doc! { "$set": { "replicaset.members.$.state": state } },
            )
            .await
            .unwrap();
        if state == "pending" {
            let (_, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/g").await;
            assert_eq!(body["reason"], "device_unsupported", "{body}");
        }
    }

    // A member without the restricted tag the session carries.
    set_device(&app, &m.a.agent_id, doc! { "tags": ["prod"] }).await;
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "replicaset.restricted_tags": ["prod"] } },
        )
        .await
        .unwrap();
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/g").await;
    assert_eq!(body["reason"], "restricted", "{body}");
    set_device(&app, &b, doc! { "tags": ["Prod"] }).await;

    // Another person's session: not there.
    grant_hive_run_to_member(&app, &m.seeded).await;
    let member = m.seeded.member.access_token.clone();
    let (code, _) = post_fork(&app, &tid, &member, &sid, &b, "/srv/g").await;
    assert_eq!(code, 404, "only its owner forks it");

    // Moving.
    let (body, _) = prepared(&app, &mut m).await;
    assert_eq!(body["outcome"], "promoting", "{body}");
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &b, "/srv/g").await;
    assert_eq!(body["reason"], "in_progress", "{body}");

    let reasons: Vec<String> = fork_audit(&app, &sid)
        .await
        .into_iter()
        .map(|(_, r, _)| r)
        .collect();
    assert_eq!(
        reasons,
        [
            "no_conversation",
            "no_conversation",
            "org_archived",
            "no_permission",
            "not_forkable",
            "device_unsupported",
            "device_unsupported",
            "restricted",
            "in_progress"
        ],
        "every refusal audited, naming the session"
    );

    // A member that does not start forks.
    let mut old = forkable(&app, "forkold", PROMOTES).await;
    kept_a_turn(&app, &mut old, 5).await;
    let (_, body) = post_fork(
        &app,
        &old.tid,
        &old.admin,
        &old.sid,
        &old.b.agent_id,
        "/srv/g",
    )
    .await;
    assert_eq!(body["reason"], "device_unsupported", "{body}");
    assert!(
        body.get("session").is_none(),
        "refused at the gate, before any record: {body}"
    );
    // A member that holds a copy, offline.
    old.b.ws.close(None).await.unwrap();
    wait_offline(&app, &old.seeded, &old.b.agent_id).await;
    let (_, body) = post_fork(
        &app,
        &old.tid,
        &old.admin,
        &old.sid,
        &old.b.agent_id,
        "/srv/g",
    )
    .await;
    assert_eq!(body["reason"], "device_offline", "{body}");
    assert!(
        body.get("session").is_none(),
        "refused at the gate while offline, before any record: {body}"
    );

    // A session alone.
    let seeded = app.seed_tenant("forkalone").await;
    on_pro(&app, &seeded).await;
    let token = seeded.admin.access_token.clone();
    let (code, p) = put_policy(&app, &seeded.tenant_id, &token, &policy_min(1, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut alone = device(&app, &seeded, "mach-forkalone", FORKS).await;
    let (s, _) = started_frame(&app, &seeded.tenant_id, &token, &mut alone, "/srv/alone").await;
    let alone_sid = s["id"].as_str().unwrap();
    let (_, body) = post_fork(
        &app,
        &seeded.tenant_id,
        &token,
        alone_sid,
        &alone.agent_id,
        "/srv/alone-2",
    )
    .await;
    assert_eq!(body["reason"], "not_replicated", "{body}");

    // The replicaset off: no fork route at all.
    let off = hive_app().await;
    let seeded = off.seed_tenant("forkoff").await;
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&off, &seeded, "mach-forkoff", FORKS).await;
    let (s, _) = started_frame(&off, &seeded.tenant_id, &token, &mut dev, "/srv/off").await;
    let (code, _) = post_fork(
        &off,
        &seeded.tenant_id,
        &token,
        s["id"].as_str().unwrap(),
        &dev.agent_id,
        "/srv/off-2",
    )
    .await;
    assert_eq!(code, 404);
}

/// FR-90 P2f-3b — a fork's unanswered start is sent again on its device's
/// next connection, naming its parent, but only to a connection that starts
/// forks: a build that does not would start it empty, so it waits for one
/// that does.
#[tokio::test]
async fn a_forks_start_goes_again_only_to_a_connection_that_starts_forks() {
    let app = fork_app().await;
    let mut m = forkable(&app, "forkagain", FORKS).await;
    kept_a_turn(&app, &mut m, 5).await;
    let (tid, admin, sid, b) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.b.agent_id.clone(),
    );
    let caller = post_fork(&app, &tid, &admin, &sid, &b, "/srv/again-b");
    let target = async { read_until(&mut m.b.ws, "rc:hive.start").await.unwrap() };
    let ((code, body), first) = tokio::join!(caller, target);
    assert_eq!(
        (code, body["outcome"].as_str()),
        (200, Some("pending")),
        "{body}"
    );
    let fsid = body["session"]["id"].as_str().unwrap().to_string();

    // Back as a build that does not start forks: nothing is sent.
    let (token, machine) = (m.b.token.clone(), m.b.machine.clone());
    drop(m.b.ws);
    wait_offline(&app, &m.seeded, &b).await;
    let mut ws = connect(&app, &token, &machine, PROMOTES).await;
    let mut no_start = true;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if let Some(f) = arrives(&mut ws, "rc:hive.start", Duration::from_millis(200)).await
            && f["session_id"] == fsid
        {
            no_start = false;
        }
    }
    assert!(
        no_start,
        "no fork's start to a build that would start it empty"
    );
    assert_eq!(
        stored(&app, &fsid).await.get_str("status").unwrap(),
        "starting"
    );

    // Back as one that does: the start again, naming its parent.
    drop(ws);
    wait_offline(&app, &m.seeded, &b).await;
    let mut ws = connect(&app, &token, &machine, FORKS).await;
    let again = loop {
        let f = read_until(&mut ws, "rc:hive.start")
            .await
            .expect("the fork's start, again");
        if f["session_id"] == fsid {
            break f;
        }
    };
    assert_eq!(
        again["fork_of"], first["fork_of"],
        "the start again names its parent: {again}"
    );
    assert_eq!(again["harness_session"], first["harness_session"]);
}

/// FR-90 P2f-3b — a fork moves only to a device that starts forks: a member
/// of its own replicaset that took its copy, back as a build without
/// `hive-fork`, is refused `device_unsupported`, and nothing moves.
#[tokio::test]
async fn a_fork_moves_only_to_a_device_that_starts_forks() {
    let app = fork_app().await;
    let mut m = forkable(&app, "forkmove", FORKS).await;
    kept_a_turn(&app, &mut m, 5).await;
    let (tid, admin, sid, a) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.a.agent_id.clone(),
    );
    let (body, _) = forked(&app, &mut m.b, &tid, &admin, &sid, "/srv/forkmove-b").await;
    assert_eq!(body["outcome"], "accepted", "{body}");
    let fsid = body["session"]["id"].as_str().unwrap().to_string();
    // The fork's own member: `a`, the owner's other device, takes its copy.
    let join = loop {
        let j = read_until(&mut m.a.ws, "rc:hive.replica.join")
            .await
            .expect("the fork's member is joined");
        if j["session_id"] == fsid {
            break j;
        }
    };
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": fsid, "fence": join["fence"]}),
    )
    .await;
    wait_member(&app, &tid, &admin, &fsid, &a, "joined", |m| {
        m["state"] == "joined"
    })
    .await;

    // Back as a build that promotes but does not start forks.
    let (token, machine) = (m.a.token.clone(), m.a.machine.clone());
    drop(m.a.ws);
    wait_offline(&app, &m.seeded, &a).await;
    let _ws = connect(&app, &token, &machine, PROMOTES).await;
    wait_agent_online(&app, &m.seeded, &a).await;
    let (code, body) = post_promote(&app, &tid, &admin, &fsid, &a, None).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("device_unsupported")),
        "{body}"
    );
    assert!(stored(&app, &fsid).await.get_document("promotion").is_err());
}

/// FR-90 P2f-3b — a fork promoted to its own member, which starts forks: the
/// moved start names its parent, as its first start did, so the member keeps
/// the parent's history in the fork's checkpoints.
#[tokio::test]
async fn a_promoted_forks_moved_start_names_its_parent() {
    let app = fork_app().await;
    let mut m = forkable(&app, "forkmoved", FORKS).await;
    kept_a_turn(&app, &mut m, 5).await;
    let (tid, admin, sid, a) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.a.agent_id.clone(),
    );
    let (body, first) = forked(&app, &mut m.b, &tid, &admin, &sid, "/srv/forkmoved-b").await;
    assert_eq!(body["outcome"], "accepted", "{body}");
    let fsid = body["session"]["id"].as_str().unwrap().to_string();
    // The fork's own member: `a`, the owner's other device, takes its copy.
    let join = loop {
        let j = read_until(&mut m.a.ws, "rc:hive.replica.join")
            .await
            .expect("the fork's member is joined");
        if j["session_id"] == fsid {
            break j;
        }
    };
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": fsid, "fence": join["fence"]}),
    )
    .await;
    wait_member(&app, &tid, &admin, &fsid, &a, "joined", |m| {
        m["state"] == "joined"
    })
    .await;

    // The fork, run by `b`, promoted to `a`: prepared, drained, synced, moved.
    let Moving {
        tid,
        admin,
        admin_id,
        a,
        b,
        seeded,
        ..
    } = m;
    let mut f = Moving {
        tid,
        admin,
        admin_id,
        sid: fsid.clone(),
        a: b,
        b: a,
        more: Vec::new(),
        seeded,
    };
    prepared(&app, &mut f).await;
    read_until(&mut f.a.ws, "rc:hive.drain")
        .await
        .expect("the fork's primary is told to drain");
    send(&mut f.a.ws, drained(&fsid, 5, "ab")).await;
    send(&mut f.b.ws, tip_at(&fsid, 1, 5, "ab")).await;
    let to = frames_until(
        &mut f.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    let moved_start = to
        .iter()
        .find(|x| x["t"] == "rc:hive.start")
        .expect("the fork's moved start");
    assert_eq!(moved_start["fence"], 2, "{moved_start}");
    assert_eq!(
        moved_start["fork_of"], first["fork_of"],
        "the moved start names its parent: {moved_start}"
    );
}

// ─── FR-90 P2f-3c — a fork onto a device that holds no copy ───────────────

/// [`FORKS`] and `hive-teleport`: a primary that hands its copy over to a
/// teleport's target, and so to a fork's.
const FORKS_AND_COPIES: &[&str] = &[
    "exec",
    "hive",
    "hive-replica",
    "hive-stream",
    "hive-lease",
    "hive-promote",
    "hive-teleport",
    "hive-fork",
];

/// A device that holds no copies (no `hive-replica`) but takes a teleport's
/// copy, and starts forks: a fork onto it takes a copy first.
const TAKES_A_COPY_TO_FORK: &[&str] = &[
    "exec",
    "hive",
    "hive-stream",
    "hive-lease",
    "hive-promote",
    "hive-teleport",
    "hive-fork",
];

/// [`forkable`], its primary handing copies over and its first turn kept;
/// and `c`, the owner's third device, which holds no copy of it.
async fn joinable(app: &TestApp, tag: &str) -> (Moving, Device) {
    joinable_with(app, tag, TAKES_A_COPY_TO_FORK).await
}

/// [`joinable`], `c` advertising `c_caps`.
async fn joinable_with(app: &TestApp, tag: &str, c_caps: &[&str]) -> (Moving, Device) {
    let mut m = forkable_with(app, tag, FORKS_AND_COPIES, FORKS).await;
    kept_a_turn(app, &mut m, 5).await;
    let c = device(app, &m.seeded, &format!("mach-{tag}-c"), c_caps).await;
    (m, c)
}

/// Fork `m`'s session onto `c`, which holds no copy: `c` answers the
/// teleport's prepare it is sent, ready or with the `refused` word. The
/// route's answer and the prepare.
async fn fork_join_prepared(
    app: &TestApp,
    m: &Moving,
    c: &mut Device,
    folder: &str,
    refused: Option<&str>,
) -> (Value, Value) {
    let caller = post_fork(app, &m.tid, &m.admin, &m.sid, &c.agent_id, folder);
    let target = async {
        let prep = read_until(&mut c.ws, "rc:hive.prepare")
            .await
            .expect("the device is asked to prepare");
        let mut ack = json!({"t": "rc:hive.prepare_ack", "session_id": prep["session_id"],
                             "fence": prep["fence"], "account": "dev"});
        if let Some(word) = refused {
            ack["refused"] = json!(word);
        }
        send(&mut c.ws, ack).await;
        prep
    };
    let ((code, body), prep) = tokio::join!(caller, target);
    assert_eq!(code, 200, "{body}");
    (body, prep)
}

/// `dev`'s join of `sid` in `role`, read and answered `joined`.
async fn join_answered(dev: &mut Device, sid: &str, role: &str) -> Value {
    let join = loop {
        let j = read_until(&mut dev.ws, "rc:hive.replica.join")
            .await
            .unwrap_or_else(|| panic!("the {role}'s join of {sid}"));
        if j["session_id"] == sid && j["role"] == role {
            break j;
        }
    };
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": join["fence"]}),
    )
    .await;
    join
}

/// The sessions forked from `parent`.
async fn forks_of(app: &TestApp, parent: &str) -> Vec<Document> {
    let mut rows = app
        .db
        .collection::<Document>("agent_sessions")
        .find(doc! { "parent.session_id": ObjectId::parse_str(parent).unwrap() })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(d) = rows.next().await {
        out.push(d.unwrap());
    }
    out
}

/// FR-90 P2f-3c — a fork onto a device that holds no copy: the device is
/// asked to prepare as a teleport's target, for the session, in the fork's
/// folder, and the answer is `joining`; it joins in the teleport's role and
/// takes a copy from the primary while the session runs; once its copy holds
/// what the primary said it holds, the fork is made there, its start naming
/// its parent, and the device is let go from the session's replicaset. The
/// session never moves; both rooms say what happened.
#[tokio::test]
async fn a_fork_onto_a_device_with_no_copy_takes_one_first_and_is_made_there() {
    let app = fork_app().await;
    let (mut m, mut c) = joinable(&app, "forkjoin").await;
    let sid = m.sid.clone();
    let parent_harness = stored(&app, &sid)
        .await
        .get_document("harness")
        .unwrap()
        .get_str("session")
        .unwrap()
        .to_string();

    let (body, prep) = fork_join_prepared(&app, &m, &mut c, "/srv/forkjoin-c", None).await;
    assert_eq!(body["outcome"], "joining", "{body}");
    assert!(body.get("session").is_none(), "no fork yet: {body}");
    assert_eq!(
        (
            prep["session_id"].as_str(),
            prep["teleport"].as_bool(),
            prep["folder"].as_str()
        ),
        (Some(sid.as_str()), Some(true), Some("/srv/forkjoin-c")),
        "a teleport's prepare, for the session, in the fork's folder: {prep}"
    );
    wait_note(&app, &m, "is forking the session into **Fork of forkjoin**").await;
    assert!(
        forks_of(&app, &sid).await.is_empty(),
        "no fork before its device holds a copy"
    );

    // The device takes its copy as a teleport's target; the primary says where
    // its copy ends, and the device's copy reaches it.
    join_answered(&mut c, &sid, "teleport").await;
    join_answered(&mut m.a, &sid, "primary").await;
    send(&mut m.a.ws, tip_at(&sid, 1, 9, "ab")).await;
    send(&mut c.ws, tip_at(&sid, 1, 9, "ab")).await;

    // The fork's start, naming its parent, on that device, in that folder.
    let start = read_until(&mut c.ws, "rc:hive.start")
        .await
        .expect("the fork's start, once the copy caught up");
    assert_eq!(
        start["fork_of"],
        json!({"session_id": sid, "harness_session": parent_harness}),
        "the start names its parent: {start}"
    );
    assert_eq!(start["folder"], "/srv/forkjoin-c", "{start}");
    assert_eq!(start["fence"], 1, "{start}");
    let fsid = start["session_id"].as_str().unwrap().to_string();
    assert_ne!(fsid, sid, "a session of its own");
    send(
        &mut c.ws,
        json!({"t": "rc:hive.start_ack", "session_id": fsid, "fence": 1, "account": "dev"}),
    )
    .await;

    let fork = wait_stored(&app, &fsid, "the fork's device answers", |s| {
        s.get_datetime("accepted_at").is_ok()
    })
    .await;
    let link = fork
        .get_document("parent")
        .expect("the fork names its parent");
    assert_eq!(link.get_object_id("session_id").unwrap().to_hex(), sid);
    assert_eq!(
        fork.get_document("location")
            .unwrap()
            .get_object_id("device_id")
            .unwrap()
            .to_hex(),
        c.agent_id,
        "made on the device that took the copy"
    );
    assert_eq!(fork.get_str("title").unwrap(), "Fork of forkjoin");

    // The session moved nothing, and its fork's device is let go from it.
    let after = wait_stored(&app, &sid, "the fork's taking of a copy ends", |s| {
        !s.contains_key("promotion")
    })
    .await;
    assert_eq!(
        after
            .get_document("location")
            .unwrap()
            .get_object_id("device_id")
            .unwrap()
            .to_hex(),
        m.a.agent_id,
        "the session stays where it is"
    );
    assert_eq!(after.get_i64("fence").unwrap(), 1, "nothing moved");
    assert_eq!(
        stored_member(&after, &c.agent_id),
        ("teleport".into(), "leaving".into()),
        "the device took its copy only to fork: let go"
    );
    assert!(
        !device_hears(&mut m.a.ws, "rc:hive.drain", Duration::from_millis(300)).await,
        "the primary never drains"
    );
    wait_note(&app, &m, "forked the session into **Fork of forkjoin**").await;
    assert_eq!(
        notes_in(&app, &m.tid, &m.admin, &fsid, "A fork of **forkjoin**")
            .await
            .len(),
        1,
        "the fork's room says what it was made from"
    );
    assert_eq!(
        fork_audit(&app, &sid).await,
        [
            ("joining".to_string(), String::new(), String::new()),
            ("sent".to_string(), String::new(), fsid.clone())
        ],
        "the audit names the session forked, at each step"
    );
}

/// FR-90 P2f-3c — a fork whose device does not take its copy is not made: a
/// refused prepare answers in the device's words, and a refused join fails
/// the fork in the room, its device let go. No fork is made either way.
#[tokio::test]
async fn a_fork_whose_device_does_not_take_its_copy_is_not_made() {
    let app = fork_app().await;
    let (m, mut c) = joinable(&app, "forkjoinno").await;
    let sid = m.sid.clone();

    let (body, _) =
        fork_join_prepared(&app, &m, &mut c, "/srv/forkjoinno-c", Some("folder_dirty")).await;
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("folder_dirty")),
        "refused in the device's words: {body}"
    );
    wait_stored(
        &app,
        &sid,
        "the refused prepare ends the fork's move",
        |s| !s.contains_key("promotion"),
    )
    .await;

    let (body, _) = fork_join_prepared(&app, &m, &mut c, "/srv/forkjoinno-c2", None).await;
    assert_eq!(body["outcome"], "joining", "{body}");
    let join = read_until(&mut c.ws, "rc:hive.replica.join")
        .await
        .expect("the device's join");
    send(
        &mut c.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": join["fence"],
               "refused": "not_prepared", "detail": "a restart came between"}),
    )
    .await;
    // `fail` tells the room last: once it has, the rest is written.
    let why = wait_note(&app, &m, "did not take a copy of the session").await;
    assert!(
        why.iter().all(|n| n.contains("The fork onto")),
        "the fork's words, not a move's: {why:?}"
    );
    let after = stored(&app, &sid).await;
    assert!(!after.contains_key("promotion"), "{after:?}");
    assert_eq!(
        stored_member(&after, &c.agent_id),
        ("teleport".into(), "leaving".into()),
        "its copy is let go"
    );
    assert!(forks_of(&app, &sid).await.is_empty(), "no fork was made");
    assert!(
        notes_with(&app, &m, "forked the session into")
            .await
            .is_empty(),
        "the room tells of no fork"
    );
    assert_eq!(
        fork_audit(&app, &sid)
            .await
            .into_iter()
            .map(|(o, r, _)| (o, r))
            .collect::<Vec<_>>(),
        [
            ("joining".to_string(), String::new()),
            ("failed".to_string(), "folder_dirty".to_string()),
            ("joining".to_string(), String::new()),
            ("failed".to_string(), "join_refused".to_string())
        ],
        "each attempt audited, naming the session"
    );
}

/// FR-90 P2f-3c — a fork onto a device that holds no copy is refused by the
/// gate it failed, before anything is asked of it: a primary that does not
/// hand copies over, or is offline; a session that does not run; and the
/// device's own gate, and the session's, before the primary's. A fork taking
/// a copy moves nothing: a fork onto a member is not held up by it, while a
/// second fork taking a copy, or a promotion, waits for it.
#[tokio::test]
async fn a_fork_onto_a_device_with_no_copy_is_refused_by_the_gate_it_failed() {
    let app = fork_app().await;

    // A primary that does not hand copies over.
    let mut old = forkable(&app, "forkjoinold", FORKS).await;
    kept_a_turn(&app, &mut old, 5).await;
    let mut c = device(
        &app,
        &old.seeded,
        "mach-forkjoinold-c",
        TAKES_A_COPY_TO_FORK,
    )
    .await;
    let (_, body) = post_fork(&app, &old.tid, &old.admin, &old.sid, &c.agent_id, "/srv/j").await;
    assert_eq!(body["reason"], "primary_unsupported", "{body}");
    assert!(
        arrives(&mut c.ws, "rc:hive.prepare", Duration::from_millis(300))
            .await
            .is_none(),
        "nothing asked of the device"
    );
    // A device that takes no copy is told so first: its own gate comes before
    // the primary's.
    let e = device(&app, &old.seeded, "mach-forkjoinold-e", FORKS).await;
    let (_, body) = post_fork(&app, &old.tid, &old.admin, &old.sid, &e.agent_id, "/srv/j").await;
    assert_eq!(
        body["reason"], "device_unsupported",
        "the device's gate first: {body}"
    );

    // A fork taking a copy moves nothing.
    let (mut m, mut c) = joinable(&app, "forkjoingate").await;
    let (body, _) = fork_join_prepared(&app, &m, &mut c, "/srv/forkjoingate-c", None).await;
    assert_eq!(body["outcome"], "joining", "{body}");
    let (tid, admin, sid, b) = (
        m.tid.clone(),
        m.admin.clone(),
        m.sid.clone(),
        m.b.agent_id.clone(),
    );
    // A fork onto a member that holds a copy goes ahead meanwhile.
    let (body, _) = forked(&app, &mut m.b, &tid, &admin, &sid, "/srv/forkjoingate-b").await;
    assert_eq!(body["outcome"], "accepted", "not held up: {body}");
    // A second fork taking a copy, or a move, waits for it.
    let d = device(&app, &m.seeded, "mach-forkjoingate-d", TAKES_A_COPY_TO_FORK).await;
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &d.agent_id, "/srv/j").await;
    assert_eq!(body["reason"], "in_progress", "{body}");
    let (code, body) = post_promote(&app, &tid, &admin, &sid, &b, None).await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("promotion_in_progress")),
        "{body}"
    );

    // A session that does not run: no copy can be taken. Its members' copies
    // still fork it.
    let (mut m, c) = joinable(&app, "forkjoinstop").await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "status": "ended" } },
        )
        .await
        .unwrap();
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &c.agent_id, "/srv/j").await;
    assert_eq!(body["reason"], "no_copy", "{body}");
    let (body, _) = forked(&app, &mut m.b, &tid, &admin, &sid, "/srv/forkjoinstop-b").await;
    assert_eq!(
        body["outcome"], "accepted",
        "a member's copy forks it: {body}"
    );
    // A session that does not run says so first, whatever its primary: the
    // session's own gate comes before the primary's.
    m.a.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.a.agent_id).await;
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &c.agent_id, "/srv/j2").await;
    assert_eq!(
        body["reason"], "no_copy",
        "the session's gate first: {body}"
    );

    // A primary that is offline.
    let (mut m, c) = joinable(&app, "forkjoinaway").await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    m.a.ws.close(None).await.unwrap();
    wait_offline(&app, &m.seeded, &m.a.agent_id).await;
    let (_, body) = post_fork(&app, &tid, &admin, &sid, &c.agent_id, "/srv/j").await;
    assert_eq!(body["reason"], "primary_offline", "{body}");

    let reasons: Vec<String> = fork_audit(&app, &old.sid)
        .await
        .into_iter()
        .map(|(_, r, _)| r)
        .collect();
    assert_eq!(
        reasons,
        ["primary_unsupported", "device_unsupported"],
        "audited"
    );
}

// ─── P0d-2b — the viewer peer's signalling ─────────────────────────────────

/// A build that runs sessions AND serves them to a browser.
const VIEWS_HIVE: &[&str] = &["exec", "hive", "hive-view"];

type UserWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn user_ws(app: &TestApp, token: &str) -> UserWs {
    let url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (ws, _) = connect_async(&url).await.expect("user ws connect");
    ws
}

async fn user_send(ws: &mut UserWs, kind: &str, data: Value) {
    ws.send(Message::Text(
        json!({ "type": kind, "data": data }).to_string().into(),
    ))
    .await
    .unwrap();
}

/// The `data` of the next user-socket frame of `kind`, within `within`.
async fn user_read_for(ws: &mut UserWs, kind: &str, within: Duration) -> Option<Value> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && v["type"] == kind
                {
                    return Some(v["data"].clone());
                }
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) | Ok(None) => return None,
            Err(_) => {}
        }
    }
    None
}

async fn user_read(ws: &mut UserWs, kind: &str) -> Option<Value> {
    user_read_for(ws, kind, Duration::from_secs(5)).await
}

/// Whether the device receives `want` within `within` — for asserting that
/// it does NOT, without waiting `read_until`'s five seconds.
async fn device_hears(ws: &mut AgentWs, want: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && v["t"] == want
                {
                    return true;
                }
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) | Ok(None) => return false,
            Err(_) => {}
        }
    }
    false
}

/// Start a session as `token` on `dev`, which accepts it; its id.
async fn started_session(app: &TestApp, tid: &str, token: &str, dev: &mut Device) -> String {
    let caller = start(app, tid, token, &dev.agent_id, "/srv");
    let target = async {
        let f = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": f["session_id"], "fence": 1, "account": "dev"}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    body["session"]["id"].as_str().unwrap().to_string()
}

/// Open a view and have the device confirm it; the grant id.
async fn ready_view(ws: &mut UserWs, dev: &mut Device, sid: &str) -> String {
    user_send(ws, "hive:view.open", json!({"session_id": sid})).await;
    let grant = read_until(&mut dev.ws, "rc:hive.view.grant")
        .await
        .expect("the device is asked");
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": gid}),
    )
    .await;
    let ready = user_read(ws, "hive:view.ready").await.expect("ready");
    assert_eq!(ready["grant_id"], gid);
    gid
}

/// FR-83's rule for the viewer: the browser is told it may dial only once
/// the DEVICE confirmed the grant; then the handshake is relayed both ways
/// with the ICE servers minted for this one peer, and the browser's socket
/// closing tells the device.
#[tokio::test]
async fn a_view_is_ready_only_after_the_device_confirms_its_grant() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveview").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-view", VIEWS_HIVE).await;
    let sid = started_session(&app, &tid, &token, &mut dev).await;

    let mut ws = user_ws(&app, &token).await;
    user_send(
        &mut ws,
        "hive:view.open",
        json!({"session_id": sid, "ref": "r1"}),
    )
    .await;
    let grant = read_until(&mut dev.ws, "rc:hive.view.grant")
        .await
        .expect("the device is asked first");
    assert_eq!(grant["session_id"], sid);
    assert_eq!(grant["user_id"], seeded.admin.id);
    assert_eq!(
        grant["may_prompt"], true,
        "the starter drives a live session"
    );
    assert_eq!(grant["ttl_secs"], 600);
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    assert!(
        user_read_for(&mut ws, "hive:view.ready", Duration::from_millis(400))
            .await
            .is_none(),
        "the browser was told to dial before the device confirmed"
    );

    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": gid}),
    )
    .await;
    let ready = user_read(&mut ws, "hive:view.ready")
        .await
        .expect("ready once the device confirmed");
    assert_eq!(ready["grant_id"], gid);
    assert_eq!(ready["ref"], "r1");
    assert_eq!(ready["may_prompt"], true);
    assert!(!ready["ice_servers"].as_array().unwrap().is_empty());

    // The handshake, relayed — with the same ICE servers on both ends.
    user_send(
        &mut ws,
        "hive:view.offer",
        json!({"grant_id": gid, "sdp": "v=0 offer"}),
    )
    .await;
    let offer = read_until(&mut dev.ws, "rc:hive.view.offer").await.unwrap();
    assert_eq!(offer["sdp"], "v=0 offer");
    assert_eq!(offer["ice_servers"], ready["ice_servers"]);
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.answer", "grant_id": gid, "sdp": "v=0 answer"}),
    )
    .await;
    assert_eq!(
        user_read(&mut ws, "hive:view.answer").await.unwrap()["sdp"],
        "v=0 answer"
    );
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.ice", "grant_id": gid, "candidate": {"candidate": "from-device"}}),
    )
    .await;
    assert_eq!(
        user_read(&mut ws, "hive:view.ice").await.unwrap()["candidate"]["candidate"],
        "from-device"
    );
    user_send(
        &mut ws,
        "hive:view.ice",
        json!({"grant_id": gid, "candidate": {"candidate": "from-browser"}}),
    )
    .await;
    assert_eq!(
        read_until(&mut dev.ws, "rc:hive.view.ice").await.unwrap()["candidate"]["candidate"],
        "from-browser"
    );

    // A renewal re-checks the right to read and gives the device a fresh TTL.
    user_send(&mut ws, "hive:view.renew", json!({"grant_id": gid})).await;
    assert_eq!(
        read_until(&mut dev.ws, "rc:hive.view.renew").await.unwrap()["ttl_secs"],
        600
    );
    assert_eq!(
        user_read(&mut ws, "hive:view.renewed").await.unwrap()["ttl_secs"],
        600
    );

    let audited = app
        .db
        .collection::<Document>("hive_audit")
        .count_documents(doc! { "action": "view", "outcome": "sent" })
        .await
        .unwrap();
    assert_eq!(audited, 1, "the grant is the server's decision, audited");

    // The browser goes: the device closes the peer.
    drop(ws);
    let close = read_until(&mut dev.ws, "rc:hive.view.close")
        .await
        .expect("the device is told the viewer left");
    assert_eq!(close["grant_id"], gid);
    assert_eq!(close["reason"], "viewer_left");
}

/// Every refusal names who said no. A member outside the session's room
/// learns nothing — the answer a bogus id gets — and the device's own
/// refusal reaches the viewer in its words.
#[tokio::test]
async fn a_view_is_refused_in_the_servers_words_or_the_devices() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveviewno").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-view-no", VIEWS_HIVE).await;
    let sid = started_session(&app, &tid, &token, &mut dev).await;

    let mut member = user_ws(&app, &seeded.member.access_token).await;
    user_send(
        &mut member,
        "hive:view.open",
        json!({"session_id": sid, "ref": "m"}),
    )
    .await;
    let no = user_read(&mut member, "hive:view.refused").await.unwrap();
    assert_eq!(no["reason"], "not_found", "{no}");
    assert_eq!(no["ref"], "m");
    user_send(
        &mut member,
        "hive:view.open",
        json!({"session_id": ObjectId::new().to_hex()}),
    )
    .await;
    assert_eq!(
        user_read(&mut member, "hive:view.refused").await.unwrap()["reason"],
        "not_found",
        "a bogus id and a room you are not in answer alike"
    );
    assert!(
        !device_hears(
            &mut dev.ws,
            "rc:hive.view.grant",
            Duration::from_millis(300)
        )
        .await,
        "no grant was minted for a non-member"
    );

    // The device's own word.
    let mut ws = user_ws(&app, &token).await;
    user_send(&mut ws, "hive:view.open", json!({"session_id": sid})).await;
    let grant = read_until(&mut dev.ws, "rc:hive.view.grant").await.unwrap();
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": grant["grant_id"], "refused": "no_session", "detail": "store\nlost"}),
    )
    .await;
    let refused = user_read(&mut ws, "hive:view.refused").await.unwrap();
    assert_eq!(refused["reason"], "no_session");
    assert_eq!(
        refused["message"], "store lost",
        "the device's words, on one line"
    );

    // A build that runs sessions but does not serve them is never asked.
    let mut old = device(&app, &seeded, "hive-old-view", RUNS_HIVE).await;
    let old_sid = started_session(&app, &tid, &token, &mut old).await;
    user_send(&mut ws, "hive:view.open", json!({"session_id": old_sid})).await;
    assert_eq!(
        user_read(&mut ws, "hive:view.refused").await.unwrap()["reason"],
        "device_unsupported"
    );
    assert!(
        !device_hears(
            &mut old.ws,
            "rc:hive.view.grant",
            Duration::from_millis(300)
        )
        .await,
        "a grant was pushed to a build that would drop it"
    );

    // And one that is away is offline.
    drop(old.ws);
    wait_offline(&app, &seeded, &old.agent_id).await;
    user_send(&mut ws, "hive:view.open", json!({"session_id": old_sid})).await;
    assert_eq!(
        user_read(&mut ws, "hive:view.refused").await.unwrap()["reason"],
        "device_offline"
    );
}

/// A grant belongs to one connection and one device: another socket's
/// frames for it, or another device's, move nothing.
#[tokio::test]
async fn frames_for_someone_elses_grant_move_nothing() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveviewx").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-view-x", VIEWS_HIVE).await;
    let sid = started_session(&app, &tid, &token, &mut dev).await;
    let mut ws = user_ws(&app, &token).await;
    let gid = ready_view(&mut ws, &mut dev, &sid).await;

    // The same user on another tab, and another user: neither can drive it.
    let mut tab = user_ws(&app, &token).await;
    let mut stranger = user_ws(&app, &seeded.member.access_token).await;
    for other in [&mut tab, &mut stranger] {
        user_send(
            other,
            "hive:view.offer",
            json!({"grant_id": gid, "sdp": "v=0 hijack"}),
        )
        .await;
        user_send(other, "hive:view.close", json!({"grant_id": gid})).await;
    }
    assert!(
        !device_hears(
            &mut dev.ws,
            "rc:hive.view.offer",
            Duration::from_millis(500)
        )
        .await,
        "an offer from a socket that does not hold the grant reached the device"
    );

    // Another device answering for it reaches nobody.
    let mut other_dev = device(&app, &seeded, "hive-view-y", VIEWS_HIVE).await;
    send(
        &mut other_dev.ws,
        json!({"t": "rc:hive.view.answer", "grant_id": gid, "sdp": "v=0 forged"}),
    )
    .await;
    assert!(
        user_read_for(&mut ws, "hive:view.answer", Duration::from_millis(500))
            .await
            .is_none(),
        "another device's answer reached the viewer"
    );

    // The grant still works for its holder.
    user_send(
        &mut ws,
        "hive:view.offer",
        json!({"grant_id": gid, "sdp": "v=0 real"}),
    )
    .await;
    assert_eq!(
        read_until(&mut dev.ws, "rc:hive.view.offer").await.unwrap()["sdp"],
        "v=0 real"
    );
}

/// A device that never answers a grant: the viewer is told, and the device
/// told to drop it should its answer come after all.
#[tokio::test]
async fn a_silent_device_is_no_answer_for_the_viewer() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveviewq").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-view-q", VIEWS_HIVE).await;
    let sid = started_session(&app, &tid, &token, &mut dev).await;

    let mut ws = user_ws(&app, &token).await;
    user_send(&mut ws, "hive:view.open", json!({"session_id": sid})).await;
    let grant = read_until(&mut dev.ws, "rc:hive.view.grant").await.unwrap();
    let refused = user_read_for(&mut ws, "hive:view.refused", Duration::from_secs(15))
        .await
        .expect("the viewer hears no_answer");
    assert_eq!(refused["reason"], "no_answer");
    let close = read_until(&mut dev.ws, "rc:hive.view.close").await.unwrap();
    assert_eq!(close["grant_id"], grant["grant_id"]);
    assert_eq!(close["reason"], "no_answer");
}

/// A member who is removed stops READING too: their views close, on the
/// device, at once — not when the grant runs out.
#[tokio::test]
async fn removing_a_member_closes_their_views() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveviewm").await;
    let tid = seeded.tenant_id.clone();
    grant_hive_run_to_member(&app, &seeded).await;
    let mut dev = device(&app, &seeded, "hive-view-m", VIEWS_HIVE).await;
    let sid = started_session(&app, &tid, &seeded.member.access_token, &mut dev).await;
    let mut ws = user_ws(&app, &seeded.member.access_token).await;
    let gid = ready_view(&mut ws, &mut dev, &sid).await;

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{tid}/member/{}", seeded.member.id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {:?}", resp.status());

    let close = read_until(&mut dev.ws, "rc:hive.view.close")
        .await
        .expect("the device hears the view close");
    assert_eq!(close["grant_id"], gid);
    assert_eq!(close["reason"], "member_removed");
}

// ─── P1c — who takes part, and who drives ────────────────────────────────

/// A hive app that a polling test cannot run into the default limiter with.
async fn hive_app_polling() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

fn participant_url(tid: &str, sid: &str, user: Option<&str>) -> String {
    match user {
        Some(u) => format!("/api/tenant/{tid}/hive/session/{sid}/participant/{u}"),
        None => format!("/api/tenant/{tid}/hive/session/{sid}/participant"),
    }
}

async fn status_and_json(resp: reqwest::Response) -> (u16, Value) {
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// `PUT …/participant/{user}` `{role}` as `token`.
async fn set_part(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    user: &str,
    role: &str,
) -> (u16, Value) {
    let resp = app
        .auth_put(&participant_url(tid, sid, Some(user)), token)
        .json(&json!({ "role": role }))
        .send()
        .await
        .unwrap();
    status_and_json(resp).await
}

async fn remove_part(app: &TestApp, tid: &str, token: &str, sid: &str, user: &str) -> (u16, Value) {
    let resp = app
        .auth_delete(&participant_url(tid, sid, Some(user)), token)
        .send()
        .await
        .unwrap();
    status_and_json(resp).await
}

async fn parts(app: &TestApp, tid: &str, token: &str, sid: &str) -> (u16, Value) {
    let resp = app
        .auth_get(&participant_url(tid, sid, None), token)
        .send()
        .await
        .unwrap();
    status_and_json(resp).await
}

/// Whether a stored session names no driver: the field absent, or emptied.
fn no_drivers(s: &Document) -> bool {
    s.get_array("drivers").map(|d| d.is_empty()).unwrap_or(true)
}

/// Whom every `approval_request` notification went to, sorted.
async fn approval_pushes(app: &TestApp) -> Vec<String> {
    let mut to: Vec<String> = Vec::new();
    let mut cur = app
        .db
        .collection::<Document>("notifications")
        .find(doc! { "notification_type": "approval_request" })
        .await
        .unwrap();
    while cur.advance().await.unwrap() {
        let n = cur.deserialize_current().unwrap();
        to.push(n.get_object_id("user_id").unwrap().to_hex());
    }
    to.sort();
    to
}

/// `user`'s role in a participants answer, if listed.
fn role_of(body: &Value, user: &str) -> Option<String> {
    body["items"]
        .as_array()?
        .iter()
        .find(|p| p["user_id"] == user)
        .and_then(|p| p["role"].as_str().map(str::to_string))
}

/// P1c — the owner decides who takes part: a READER joins the session's
/// Secret room and reads it; a DRIVER also prompts it. Naming a driver needs
/// `HIVE_RUN` (driving runs code on the device as the session's account);
/// every change ends the person's open views, because a grant carries
/// `may_prompt` as it was minted; and nobody but the owner changes anything.
#[tokio::test]
async fn the_owner_names_who_reads_and_who_drives() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("hiveparts").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let member = seeded.member.access_token.clone();
    let mid = seeded.member.id.clone();
    let mut dev = device(&app, &seeded, "hive-parts", VIEWS_HIVE).await;
    let sid = started_session(&app, &tid, &owner, &mut dev).await;
    let room = get_session(&app, &tid, &owner, &sid).await.1["room_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Before: the member learns nothing, and changes nothing.
    assert_eq!(get_session(&app, &tid, &member, &sid).await.0, 404);
    assert_eq!(parts(&app, &tid, &member, &sid).await.0, 404);
    assert_eq!(
        set_part(&app, &tid, &member, &sid, &mid, "reader").await.0,
        404
    );

    // A reader: in the room, reading — not prompting.
    let (code, body) = set_part(&app, &tid, &owner, &sid, &mid, "reader").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(role_of(&body, &seeded.admin.id).as_deref(), Some("owner"));
    assert_eq!(role_of(&body, &mid).as_deref(), Some("reader"));
    assert_eq!(body["may_manage"], true);
    let (code, s) = get_session(&app, &tid, &member, &sid).await;
    assert_eq!(code, 200, "a reader reads the session: {s}");
    assert_eq!(s["drivers"], json!([]), "{s}");
    let (code, theirs) = parts(&app, &tid, &member, &sid).await;
    assert_eq!(code, 200);
    assert_eq!(
        theirs["may_manage"], false,
        "only the owner manages: {theirs}"
    );
    assert_eq!(
        set_part(&app, &tid, &member, &sid, &mid, "driver").await.0,
        404,
        "a reader cannot make themselves a driver"
    );
    wait_messages(&app, &tid, &owner, &room, "the room is told", |items| {
        items.iter().any(|m| {
            m["content"]
                .as_str()
                .is_some_and(|c| c.contains("Member** joined to read"))
        })
    })
    .await;

    let mut mws = user_ws(&app, &member).await;
    user_send(&mut mws, "hive:view.open", json!({"session_id": sid})).await;
    let grant = read_until(&mut dev.ws, "rc:hive.view.grant")
        .await
        .expect("a reader may view");
    assert_eq!(grant["user_id"], mid);
    assert_eq!(grant["may_prompt"], false, "a reader does not prompt");
    assert!(
        grant.get("user_email").is_none(),
        "a reader's address never leaves the server (P1c-2): {grant}"
    );
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": gid}),
    )
    .await;
    assert_eq!(
        user_read(&mut mws, "hive:view.ready").await.unwrap()["may_prompt"],
        false
    );

    // A driver needs HIVE_RUN: refused, audited, nothing changed.
    let (code, body) = set_part(&app, &tid, &owner, &sid, &mid, "driver").await;
    assert_eq!(code, 403, "{body}");
    assert!(
        body.to_string().contains("HIVE_RUN"),
        "the refusal names what is missing: {body}"
    );
    let refused = app
        .db
        .collection::<Document>("hive_audit")
        .find_one(doc! { "action": "participant", "outcome": "refused" })
        .await
        .unwrap()
        .expect("the refusal is audited");
    assert_eq!(refused.get_str("reason").unwrap(), "no_permission");
    assert_eq!(refused.get_object_id("target_id").unwrap().to_hex(), mid);
    assert!(
        !device_hears(
            &mut dev.ws,
            "rc:hive.view.close",
            Duration::from_millis(300)
        )
        .await,
        "a refused change ends no view"
    );

    // Granted it, the member is named a driver; their view says otherwise
    // now, so it ends, and the one they reopen may prompt.
    grant_hive_run_to_member(&app, &seeded).await;
    let (code, body) = set_part(&app, &tid, &owner, &sid, &mid, "driver").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(role_of(&body, &mid).as_deref(), Some("driver"));
    let close = read_until(&mut dev.ws, "rc:hive.view.close")
        .await
        .expect("the device closes the stale grant");
    assert_eq!(close["grant_id"], gid);
    assert_eq!(close["reason"], "role_changed");
    assert_eq!(
        user_read(&mut mws, "hive:view.closed").await.unwrap()["reason"],
        "role_changed"
    );
    user_send(&mut mws, "hive:view.open", json!({"session_id": sid})).await;
    let grant = read_until(&mut dev.ws, "rc:hive.view.grant")
        .await
        .expect("reopened");
    assert_eq!(grant["may_prompt"], true, "a driver prompts a live session");
    assert_eq!(
        grant["user_email"], seeded.member.email,
        "a driver's address goes with the grant, for the device's own hive_accounts"
    );
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": grant["grant_id"]}),
    )
    .await;
    assert_eq!(
        user_read(&mut mws, "hive:view.ready").await.unwrap()["may_prompt"],
        true
    );
    assert_eq!(
        get_session(&app, &tid, &owner, &sid).await.1["drivers"],
        json!([mid]),
    );
    // Saying it again changes nothing, and ends nothing.
    assert_eq!(
        set_part(&app, &tid, &owner, &sid, &mid, "driver").await.0,
        200
    );
    assert!(
        !device_hears(
            &mut dev.ws,
            "rc:hive.view.close",
            Duration::from_millis(300)
        )
        .await,
        "no change, no ended view"
    );

    // What is not a participant change.
    assert_eq!(
        set_part(&app, &tid, &owner, &sid, &seeded.admin.id, "reader")
            .await
            .0,
        400,
        "the owner always drives"
    );
    assert_eq!(
        set_part(&app, &tid, &owner, &sid, &mid, "admin").await.0,
        400
    );
    assert_eq!(
        set_part(
            &app,
            &tid,
            &owner,
            &sid,
            &ObjectId::new().to_hex(),
            "reader"
        )
        .await
        .0,
        404,
        "a stranger's id answers like a bogus one"
    );

    // Taken out: out of the room, driving nothing, reading nothing.
    let (code, body) = remove_part(&app, &tid, &owner, &sid, &mid).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(role_of(&body, &mid), None);
    assert_eq!(
        read_until(&mut dev.ws, "rc:hive.view.close").await.unwrap()["reason"],
        "removed"
    );
    assert_eq!(get_session(&app, &tid, &member, &sid).await.0, 404);
    assert!(no_drivers(&stored(&app, &sid).await));
    // Again: nothing to do, nothing said.
    assert_eq!(remove_part(&app, &tid, &owner, &sid, &mid).await.0, 200);
    let audit = app.db.collection::<Document>("hive_audit");
    for (outcome, n) in [("reader", 1), ("driver", 1), ("removed", 1)] {
        assert_eq!(
            audit
                .count_documents(doc! { "action": "participant", "outcome": outcome })
                .await
                .unwrap(),
            n,
            "{outcome}"
        );
    }
}

/// P1c — what a device says about WHO acted is believed only when it names
/// a driver: who answered an approval, who asked a turn. A device naming a
/// reader is not believed — no stub says a person did what they could not
/// have. And an approval is pushed to every driver still in the room.
#[tokio::test]
async fn a_drivers_word_is_believed_and_a_readers_is_not() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("hivewho").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let mid = seeded.member.id.clone();
    grant_hive_run_to_member(&app, &seeded).await;
    let mut dev = device(&app, &seeded, "hive-who", RUNS_HIVE).await;
    let sid = started_session(&app, &tid, &owner, &mut dev).await;
    let room = get_session(&app, &tid, &owner, &sid).await.1["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        set_part(&app, &tid, &owner, &sid, &mid, "reader").await.0,
        200
    );

    let turn = |n: u32, by: &str| {
        json!({"t": "rc:hive.turn", "session_id": sid, "fence": 1, "turn": n,
               "status": "ok", "prompted_by": by, "steps": 0})
    };
    let approval = |id: &str, status: &str, by: Option<&str>| {
        let mut f = json!({"t": "rc:hive.approval", "session_id": sid, "fence": 1,
                           "approval_id": id, "turn": 1, "status": status});
        if let Some(by) = by {
            f["answered_by"] = json!(by);
        }
        f
    };
    let stub = |items: &[Value], reference: &str| -> String {
        items
            .iter()
            .find(|m| bound_to(m, reference))
            .and_then(|m| m["content"].as_str())
            .unwrap_or_default()
            .to_string()
    };

    // As a reader: neither claim is believed.
    send(&mut dev.ws, turn(1, &mid)).await;
    send(&mut dev.ws, approval("r1", "open", None)).await;
    send(&mut dev.ws, approval("r1", "allowed", Some(&mid))).await;
    let (t1, r1) = (format!("{sid}#1"), format!("{sid}!r1"));
    let items = wait_messages(&app, &tid, &owner, &room, "the reader's claims", |items| {
        items.iter().any(|m| bound_to(m, &t1)) && stub(items, &r1).contains("allowed")
    })
    .await;
    assert!(
        !stub(&items, &t1).contains("asked by"),
        "{}",
        stub(&items, &t1)
    );
    assert_eq!(stub(&items, &r1), "🔐 **Approval** · turn 1 — ✅ allowed");
    assert_eq!(
        approval_pushes(&app).await,
        std::slice::from_ref(&seeded.admin.id),
        "a reader is not asked to answer"
    );

    // As a driver: both are, and the push reaches them too.
    assert_eq!(
        set_part(&app, &tid, &owner, &sid, &mid, "driver").await.0,
        200
    );
    send(&mut dev.ws, turn(2, &mid)).await;
    send(&mut dev.ws, approval("d1", "open", None)).await;
    send(&mut dev.ws, approval("d1", "denied", Some(&mid))).await;
    let (t2, d1) = (format!("{sid}#2"), format!("{sid}!d1"));
    let items = wait_messages(&app, &tid, &owner, &room, "the driver's claims", |items| {
        stub(items, &t2).contains("asked by") && stub(items, &d1).contains("denied by")
    })
    .await;
    assert!(
        stub(&items, &t2).contains("Member"),
        "asked by the driver: {}",
        stub(&items, &t2)
    );
    assert!(
        stub(&items, &d1).contains("denied by **hivewho Member**"),
        "{}",
        stub(&items, &d1)
    );
    let mut want = vec![
        seeded.admin.id.clone(),
        seeded.admin.id.clone(),
        mid.clone(),
    ];
    want.sort();
    assert_eq!(
        approval_pushes(&app).await,
        want,
        "r1 to the owner; d1 to the owner AND the driver"
    );
}

/// P1c — a member who leaves the org drives nobody's session any more: a
/// seat nobody re-offered must not come back if they rejoin.
#[tokio::test]
async fn a_member_who_leaves_the_org_drives_nothing() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("hivegone").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let mid = seeded.member.id.clone();
    grant_hive_run_to_member(&app, &seeded).await;
    let mut dev = device(&app, &seeded, "hive-gone", RUNS_HIVE).await;
    let sid = started_session(&app, &tid, &owner, &mut dev).await;
    assert_eq!(
        set_part(&app, &tid, &owner, &sid, &mid, "driver").await.0,
        200
    );
    assert_eq!(
        stored(&app, &sid).await.get_array("drivers").unwrap().len(),
        1
    );

    let resp = app
        .auth_delete(&format!("/api/tenant/{tid}/member/{mid}"), &owner)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {:?}", resp.status());
    let s = stored(&app, &sid).await;
    assert!(no_drivers(&s), "dropped from the drivers: {s}");
    assert_ne!(
        s.get_str("status").unwrap(),
        "ended",
        "the OWNER's session runs on — only the member's own end"
    );
}

// ─── P1e — core memory, the brain's first layer ─────────────────────────

/// What a build that understands core memory advertises.
const TAKES_MEMORY: &[&str] = &["exec", "hive", "hive-memory"];

fn brain_url(tid: &str, fact: Option<&str>) -> String {
    match fact {
        Some(f) => format!("/api/tenant/{tid}/hive/brain/{f}"),
        None => format!("/api/tenant/{tid}/hive/brain"),
    }
}

/// `POST …/hive/brain`.
async fn keep(app: &TestApp, tid: &str, token: &str, body: Value) -> (u16, Value) {
    status_and_json(
        app.auth_post(&brain_url(tid, None), token)
            .json(&body)
            .send()
            .await
            .unwrap(),
    )
    .await
}

/// `PUT …/hive/brain/{fact}`.
async fn edit_fact(app: &TestApp, tid: &str, token: &str, fact: &str, body: Value) -> (u16, Value) {
    status_and_json(
        app.auth_put(&brain_url(tid, Some(fact)), token)
            .json(&body)
            .send()
            .await
            .unwrap(),
    )
    .await
}

/// `DELETE …/hive/brain/{fact}`.
async fn archive_fact(app: &TestApp, tid: &str, token: &str, fact: &str) -> (u16, Value) {
    status_and_json(
        app.auth_delete(&brain_url(tid, Some(fact)), token)
            .send()
            .await
            .unwrap(),
    )
    .await
}

/// `GET …/hive/brain`, with a device's facts too when one is named.
async fn brain(app: &TestApp, tid: &str, token: &str, device: Option<&str>) -> Value {
    let url = match device {
        Some(d) => format!("{}?device_id={d}", brain_url(tid, None)),
        None => brain_url(tid, None),
    };
    let (code, body) = status_and_json(app.auth_get(&url, token).send().await.unwrap()).await;
    assert_eq!(code, 200, "{body}");
    body
}

fn budget_of(view: &Value, scope: &str) -> Value {
    view["budgets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["scope"] == scope)
        .cloned()
        .unwrap_or_else(|| panic!("no {scope} budget in {view}"))
}

/// The brain's audit rows, by outcome.
async fn brain_audit(app: &TestApp) -> Vec<Document> {
    let mut cursor = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "action": "brain" })
        .await
        .unwrap();
    let mut rows = Vec::new();
    while let Some(row) = cursor.next().await {
        rows.push(row.unwrap());
    }
    rows
}

/// AC8's second half: a write past its scope's budget fails VISIBLY — the
/// numbers in the answer, nothing evicted — and the budget follows every
/// add, edit and archive.
#[tokio::test]
async fn core_memory_keeps_facts_inside_their_budgets_and_says_so() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainbudget").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();

    let first = "Deploys go through the release branch.";
    let (code, f) = keep(&app, &tid, &admin, json!({"scope": "org", "text": first})).await;
    assert_eq!(code, 200, "{f}");
    assert_eq!(f["scope"], "org");
    assert_eq!(f["kind"], "convention", "the default kind");
    assert_eq!(f["version"], 1);
    assert!(f.get("owner_id").is_none(), "an org fact has no owner: {f}");
    let view = brain(&app, &tid, &admin, None).await;
    assert_eq!(view["brain_rev"], 1);
    assert_eq!(budget_of(&view, "org")["used"], first.len());
    assert_eq!(budget_of(&view, "org")["budget"], 3000);

    let big = "x".repeat(500);
    for _ in 0..5 {
        let (code, b) = keep(
            &app,
            &tid,
            &admin,
            json!({"scope": "org", "text": big, "kind": "gotcha"}),
        )
        .await;
        assert_eq!(code, 200, "{b}");
    }
    let used = first.len() as i64 + 2_500;
    let (code, refused) = keep(&app, &tid, &admin, json!({"scope": "org", "text": big})).await;
    assert_eq!(code, 409, "{refused}");
    assert_eq!(refused["error"], "over_budget");
    assert_eq!(refused["scope"], "org");
    assert_eq!(refused["used"], used);
    assert_eq!(refused["budget"], 3000);
    assert_eq!(refused["needed"], 500);
    assert!(
        refused["message"]
            .as_str()
            .unwrap()
            .contains("archive a fact"),
        "the refusal names the way out: {refused}"
    );
    let view = brain(&app, &tid, &admin, None).await;
    assert_eq!(
        view["facts"].as_array().unwrap().len(),
        6,
        "nothing evicted"
    );
    assert_eq!(budget_of(&view, "org")["used"], used);
    assert_eq!(view["brain_rev"], 6, "a refusal is no revision");

    // One character more, so growing the first fact to the longest a fact
    // may be no longer fits (without it, it would fit exactly).
    let (code, z) = keep(&app, &tid, &admin, json!({"scope": "org", "text": "z"})).await;
    assert_eq!(code, 200, "{z}");
    let others = 2_501_i64;

    // An edit that grows a fact past the budget is refused the same way;
    // one that fits is the next version; a stale one is a conflict.
    let fid = f["id"].as_str().unwrap().to_string();
    let (code, e) = edit_fact(
        &app,
        &tid,
        &admin,
        &fid,
        json!({"text": "y".repeat(500), "version": 1}),
    )
    .await;
    assert_eq!(
        (code, e["error"].as_str()),
        (409, Some("over_budget")),
        "{e}"
    );
    let shorter = "Deploys go through `release`.";
    let (code, e) = edit_fact(
        &app,
        &tid,
        &admin,
        &fid,
        json!({"text": shorter, "version": 1}),
    )
    .await;
    assert_eq!(code, 200, "{e}");
    assert_eq!(e["version"], 2);
    let (code, e) = edit_fact(
        &app,
        &tid,
        &admin,
        &fid,
        json!({"text": "again", "version": 1}),
    )
    .await;
    assert_eq!(
        (code, e["error"].as_str()),
        (409, Some("conflict")),
        "stale: {e}"
    );
    let view = brain(&app, &tid, &admin, None).await;
    assert_eq!(
        budget_of(&view, "org")["used"],
        shorter.len() as i64 + others
    );

    // Archiving gives the room back.
    let (code, a) = archive_fact(&app, &tid, &admin, &fid).await;
    assert_eq!((code, a["archived"].as_bool()), (200, Some(true)), "{a}");
    let (code, a) = archive_fact(&app, &tid, &admin, &fid).await;
    assert_eq!(
        (code, a["archived"].as_bool()),
        (200, Some(false)),
        "once: {a}"
    );
    let view = brain(&app, &tid, &admin, None).await;
    assert_eq!(budget_of(&view, "org")["used"], others);
    assert!(
        view["facts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["id"] != fid.as_str())
    );
    let fits = "w".repeat(499);
    let (code, b) = keep(&app, &tid, &admin, json!({"scope": "org", "text": fits})).await;
    assert_eq!(code, 200, "now it fits, exactly: {b}");
    let view = brain(&app, &tid, &admin, None).await;
    assert_eq!(budget_of(&view, "org")["used"], 3_000);

    let rows = brain_audit(&app).await;
    let count = |outcome: &str| {
        rows.iter()
            .filter(|r| r.get_str("outcome").ok() == Some(outcome))
            .count()
    };
    assert_eq!(
        (
            count("added"),
            count("refused"),
            count("edited"),
            count("archived")
        ),
        (8, 2, 1, 1),
        "every write audited: {rows:?}"
    );
    assert!(
        rows.iter().all(|r| !r.contains_key("device_id")),
        "an org fact concerns no device"
    );
}

/// The org's memory is its administrators'; a person's is theirs, with
/// `HIVE_RUN`; a device's is whoever manages devices'. Someone else's user
/// memory answers like a bogus id.
#[tokio::test]
async fn who_keeps_which_memory() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainwho").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let member = seeded.member.access_token.clone();
    let dev = device(&app, &seeded, "brain-who", TAKES_MEMORY).await;

    assert_eq!(
        keep(&app, &tid, &member, json!({"scope": "org", "text": "t"}))
            .await
            .0,
        403
    );
    assert_eq!(
        keep(&app, &tid, &member, json!({"scope": "user", "text": "t"}))
            .await
            .0,
        403,
        "no HIVE_RUN, no memory for agent sessions"
    );
    grant_hive_run_to_member(&app, &seeded).await;
    let (code, mine) = keep(
        &app,
        &tid,
        &member,
        json!({"scope": "user", "text": "Small commits.", "kind": "preference"}),
    )
    .await;
    assert_eq!(code, 200, "{mine}");
    assert_eq!(mine["owner_id"], seeded.member.id, "their own by default");
    assert_eq!(
        keep(
            &app,
            &tid,
            &member,
            json!({"scope": "user", "owner_id": seeded.admin.id, "text": "t"})
        )
        .await
        .0,
        403,
        "never someone else's"
    );
    assert_eq!(
        keep(
            &app,
            &tid,
            &member,
            json!({"scope": "device", "owner_id": dev.agent_id, "text": "t"})
        )
        .await
        .0,
        403
    );
    let (code, d) = keep(
        &app,
        &tid,
        &admin,
        json!({"scope": "device", "owner_id": dev.agent_id, "text": "Datasets in /data.", "kind": "path"}),
    )
    .await;
    assert_eq!(code, 200, "{d}");
    assert_eq!(
        keep(
            &app,
            &tid,
            &admin,
            json!({"scope": "device", "owner_id": ObjectId::new().to_hex(), "text": "t"})
        )
        .await
        .0,
        404,
        "a device not in this org answers like a bogus id"
    );
    assert_eq!(
        keep(
            &app,
            &tid,
            &admin,
            json!({"scope": "org", "owner_id": seeded.admin.id, "text": "t"})
        )
        .await
        .0,
        400
    );
    assert_eq!(
        keep(&app, &tid, &admin, json!({"scope": "project", "text": "t"}))
            .await
            .0,
        400
    );
    assert_eq!(
        keep(&app, &tid, &admin, json!({"scope": "org", "text": " \n "}))
            .await
            .0,
        400
    );

    let mid = mine["id"].as_str().unwrap().to_string();
    assert_eq!(
        archive_fact(&app, &tid, &admin, &mid).await.0,
        404,
        "not even an admin's"
    );
    let view = brain(&app, &tid, &admin, None).await;
    assert!(
        view["facts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["id"] != mid.as_str())
    );
    let view = brain(&app, &tid, &member, Some(&dev.agent_id)).await;
    let scopes: Vec<&str> = view["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["scope"].as_str().unwrap())
        .collect();
    assert_eq!(scopes, ["user", "device"], "{view}");
    assert_eq!(budget_of(&view, "device")["budget"], 800);

    let rows = brain_audit(&app).await;
    let device_row = rows
        .iter()
        .find(|r| r.get_str("outcome").ok() == Some("added") && r.contains_key("device_id"))
        .expect("a device fact's audit names the device");
    assert_eq!(
        device_row.get_object_id("device_id").unwrap().to_hex(),
        dev.agent_id
    );
}

/// Two writes racing for the last room: ONE conditional update decides, so
/// exactly one fits.
#[tokio::test]
async fn two_writes_racing_for_the_last_room_cannot_both_fit() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainrace").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let big = "x".repeat(500);
    for _ in 0..5 {
        assert_eq!(
            keep(&app, &tid, &admin, json!({"scope": "org", "text": big}))
                .await
                .0,
            200
        );
    }
    let (a, b) = tokio::join!(
        keep(&app, &tid, &admin, json!({"scope": "org", "text": big})),
        keep(&app, &tid, &admin, json!({"scope": "org", "text": big})),
    );
    let mut codes = [a.0, b.0];
    codes.sort_unstable();
    assert_eq!(codes, [200, 409], "{a:?} {b:?}");
    let view = brain(&app, &tid, &admin, None).await;
    assert_eq!(budget_of(&view, "org")["used"], 3_000);
    assert_eq!(view["facts"].as_array().unwrap().len(), 6);
}

fn org_counter_key(tid: &str) -> Document {
    doc! { "tenant_id": ObjectId::parse_str(tid).unwrap(), "scope": "org", "owner_id": null }
}

/// The org scope's counter, as the DAO keeps it (`brain_budgets`).
async fn org_counter(app: &TestApp, tid: &str) -> Document {
    app.db
        .collection::<Document>("brain_budgets")
        .find_one(org_counter_key(tid))
        .await
        .unwrap()
        .expect("the org's counter")
}

/// Leave the org scope's counter as a write in flight, or a crash, would.
async fn set_org_counter(app: &TestApp, tid: &str, update: Document) {
    let r = app
        .db
        .collection::<Document>("brain_budgets")
        .update_one(org_counter_key(tid), update)
        .await
        .unwrap();
    assert_eq!(r.matched_count, 1, "the org's counter");
}

/// The org's active facts, counted from the facts themselves: (how many,
/// their characters).
async fn org_active(app: &TestApp, tid: &str) -> (usize, i64) {
    let mut cursor = app
        .db
        .collection::<Document>("brain_facts")
        .find(doc! { "tenant_id": ObjectId::parse_str(tid).unwrap(), "scope": "org", "status": "active" })
        .await
        .unwrap();
    let (mut n, mut chars) = (0, 0);
    while let Some(f) = cursor.next().await {
        n += 1;
        chars += f.unwrap().get_i64("chars").unwrap();
    }
    (n, chars)
}

/// `n` org facts of 500 characters; their ids.
async fn keep_org_facts(app: &TestApp, tid: &str, admin: &str, n: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for _ in 0..n {
        let (code, f) = keep(
            app,
            tid,
            admin,
            json!({"scope": "org", "text": "x".repeat(500)}),
        )
        .await;
        assert_eq!(code, 200, "{f}");
        ids.push(f["id"].as_str().unwrap().to_string());
    }
    ids
}

fn ms_ago(ms: i64) -> bson::DateTime {
    bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - ms)
}

/// The race above, held open: a write has taken the last room and not yet
/// written its fact. A refusal must not recount over that reservation, or a
/// second write takes the same room — which is how the race test failed under
/// the whole suite's load.
#[tokio::test]
async fn a_reservation_in_flight_is_not_recounted_away() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("braininflight").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    keep_org_facts(&app, &tid, &admin, 5).await;
    let counter = org_counter(&app, &tid).await;
    assert_eq!(
        counter.get_i64("v").unwrap(),
        5,
        "each reservation is one more: {counter}"
    );
    let touched = counter
        .get_datetime("touched_at")
        .unwrap()
        .timestamp_millis();
    assert!(
        bson::DateTime::now().timestamp_millis() - touched < 60_000,
        "a reservation touches the counter: {counter}"
    );
    // What `reserve` leaves for those milliseconds: the room taken, no fact.
    set_org_counter(
        &app,
        &tid,
        doc! { "$inc": { "used": 500_i64, "v": 1_i64 }, "$set": { "touched_at": bson::DateTime::now() } },
    )
    .await;
    let (code, body) = keep(
        &app,
        &tid,
        &admin,
        json!({"scope": "org", "text": "y".repeat(500)}),
    )
    .await;
    assert_eq!(code, 409, "{body}");
    assert_eq!(
        org_counter(&app, &tid).await.get_i64("used").unwrap(),
        3_000,
        "the reservation in flight is intact"
    );
    assert_eq!(org_active(&app, &tid).await, (5, 2_500));
}

/// A reservation a crash left behind is still given back, at the next
/// refusal once the counter has been quiet for the window — and so is one on
/// a counter from before the window and its version existed.
#[tokio::test]
async fn a_reservation_a_crash_left_behind_is_recounted_once_quiet() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainleak").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let ids = keep_org_facts(&app, &tid, &admin, 5).await;
    let quiet = ms_ago((meshharbor_mod_hive::brain::RECOUNT_QUIET_SECS + 60) * 1000);
    set_org_counter(
        &app,
        &tid,
        doc! { "$inc": { "used": 500_i64, "v": 1_i64 }, "$set": { "touched_at": quiet } },
    )
    .await;
    let (code, body) = keep(
        &app,
        &tid,
        &admin,
        json!({"scope": "org", "text": "y".repeat(500)}),
    )
    .await;
    assert_eq!(code, 200, "the leaked room is recounted: {body}");
    assert_eq!(
        org_counter(&app, &tid).await.get_i64("used").unwrap(),
        3_000
    );
    assert_eq!(org_active(&app, &tid).await, (6, 3_000));

    // A counter written before `v` and `touched_at`: neither field, and a leak.
    assert_eq!(archive_fact(&app, &tid, &admin, &ids[0]).await.0, 200);
    set_org_counter(
        &app,
        &tid,
        doc! { "$unset": { "v": "", "touched_at": "" }, "$inc": { "used": 500_i64 } },
    )
    .await;
    let (code, body) = keep(
        &app,
        &tid,
        &admin,
        json!({"scope": "org", "text": "z".repeat(500)}),
    )
    .await;
    assert_eq!(code, 200, "recounted without a version: {body}");
    let counter = org_counter(&app, &tid).await;
    assert_eq!(counter.get_i64("used").unwrap(), 3_000);
    assert!(counter.get_i64("v").unwrap() >= 1, "{counter}");
    assert_eq!(org_active(&app, &tid).await, (6, 3_000));
}

/// An archive in flight: its fact has left the count, its release is still
/// to come, and the counter was touched first. A refusal must not recount
/// over it, or the release takes the room off twice and a later write
/// overspends. A real archive, and an edit that shrinks a fact, each touch
/// the counter BEFORE the fact changes, then again with the release.
#[tokio::test]
async fn an_archive_in_flight_is_not_counted_twice() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainarchive").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let ids = keep_org_facts(&app, &tid, &admin, 6).await;
    let v = |c: &Document| c.get_i64("v").unwrap();

    let before = v(&org_counter(&app, &tid).await);
    assert_eq!(archive_fact(&app, &tid, &admin, &ids[0]).await.0, 200);
    assert_eq!(
        v(&org_counter(&app, &tid).await) - before,
        2,
        "touched, then released"
    );
    let before = v(&org_counter(&app, &tid).await);
    let (code, e) = edit_fact(
        &app,
        &tid,
        &admin,
        &ids[1],
        json!({"text": "short", "version": 1}),
    )
    .await;
    assert_eq!(code, 200, "{e}");
    assert_eq!(
        v(&org_counter(&app, &tid).await) - before,
        2,
        "touched, then released"
    );
    let (code, e) = edit_fact(
        &app,
        &tid,
        &admin,
        &ids[1],
        json!({"text": "x".repeat(500), "version": 2}),
    )
    .await;
    assert_eq!(code, 200, "{e}");
    keep_org_facts(&app, &tid, &admin, 1).await;
    assert_eq!(org_active(&app, &tid).await, (6, 3_000));

    // The archive of ids[2], held open after its touch and its flip.
    set_org_counter(
        &app,
        &tid,
        doc! { "$inc": { "v": 1_i64 }, "$set": { "touched_at": bson::DateTime::now() } },
    )
    .await;
    let flipped = app
        .db
        .collection::<Document>("brain_facts")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&ids[2]).unwrap() },
            doc! { "$set": { "status": "archived" } },
        )
        .await
        .unwrap();
    assert_eq!(flipped.modified_count, 1);
    let (code, body) = keep(
        &app,
        &tid,
        &admin,
        json!({"scope": "org", "text": "y".repeat(500)}),
    )
    .await;
    assert_eq!(
        code, 409,
        "not recounted over the archive in flight: {body}"
    );
    // Its release lands; the room it gave back fits one write, and only one.
    set_org_counter(
        &app,
        &tid,
        doc! { "$inc": { "used": -500_i64, "v": 1_i64 }, "$set": { "touched_at": bson::DateTime::now() } },
    )
    .await;
    let (code, body) = keep(
        &app,
        &tid,
        &admin,
        json!({"scope": "org", "text": "y".repeat(500)}),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    let (code, body) = keep(
        &app,
        &tid,
        &admin,
        json!({"scope": "org", "text": "z".repeat(500)}),
    )
    .await;
    assert_eq!(code, 409, "{body}");
    assert_eq!(
        org_counter(&app, &tid).await.get_i64("used").unwrap(),
        3_000
    );
    assert_eq!(org_active(&app, &tid).await, (6, 3_000));
}

/// AC8's first half, on the server: a session's core memory is rendered when
/// it is created, reaches the device BEFORE its start, and is FROZEN — a fact
/// written afterwards is in the next session's snapshot and never in this one.
#[tokio::test]
async fn a_sessions_core_memory_comes_before_its_start_and_is_frozen() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainsnap").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "brain-snap", TAKES_MEMORY).await;
    for (scope, text, owner) in [
        ("org", "ORG-FACT-ONE", None),
        ("user", "MY-FACT", None),
        ("device", "DEVICE-FACT", Some(dev.agent_id.clone())),
    ] {
        let mut body = json!({"scope": scope, "text": text});
        if let Some(o) = owner {
            body["owner_id"] = json!(o);
        }
        assert_eq!(keep(&app, &tid, &admin, body).await.0, 200);
    }

    let caller = start(&app, &tid, &admin, &dev.agent_id, "/srv");
    let target = async {
        // In order: the memory, THEN the start (a start first would be
        // skipped by the first wait, and the second would time out).
        let memory = read_until(&mut dev.ws, "rc:hive.memory")
            .await
            .expect("the memory");
        let start = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("then the start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": start["session_id"], "fence": 1, "account": "dev"}),
        )
        .await;
        (memory, start)
    };
    let (body, (memory, start_frame)) = tokio::join!(caller, target);
    let sid = body["session"]["id"].as_str().unwrap().to_string();
    assert_eq!(memory["session_id"], sid.as_str());
    assert_eq!(start_frame["session_id"], sid.as_str());
    assert_eq!(memory["fence"], 1);
    assert_eq!(memory["brain_rev"], 3);
    assert_eq!(body["session"]["brain_rev"], 3, "pinned on the record");
    let claude_md = memory["claude_md"].as_str().unwrap();
    assert!(
        claude_md.contains("ORG-FACT-ONE") && claude_md.contains("MY-FACT"),
        "{claude_md}"
    );
    assert!(!claude_md.contains("DEVICE-FACT"), "{claude_md}");
    assert!(
        memory["memory_md"]
            .as_str()
            .unwrap()
            .contains("DEVICE-FACT"),
        "{memory}"
    );
    for absent in ["prompt", "transcript", "account"] {
        assert!(memory.get(absent).is_none(), "`{absent}` in {memory}");
    }

    // A fact written now is not this session's…
    assert_eq!(
        keep(
            &app,
            &tid,
            &admin,
            json!({"scope": "org", "text": "ORG-FACT-TWO"})
        )
        .await
        .0,
        200
    );
    let stored = app
        .db
        .collection::<Document>("hive_session_memory")
        .find_one(doc! { "_id": ObjectId::parse_str(&sid).unwrap() })
        .await
        .unwrap()
        .expect("the snapshot is kept for a re-send");
    assert!(
        !stored
            .get_str("claude_md")
            .unwrap()
            .contains("ORG-FACT-TWO"),
        "frozen: {stored}"
    );
    assert_eq!(stored.get_i64("brain_rev").unwrap(), 3);

    // …and is the next one's.
    let caller = start(&app, &tid, &admin, &dev.agent_id, "/srv");
    let target = async {
        let memory = read_until(&mut dev.ws, "rc:hive.memory")
            .await
            .expect("the memory");
        let start = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("then the start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": start["session_id"], "fence": 1, "account": "dev"}),
        )
        .await;
        memory
    };
    let (_, next) = tokio::join!(caller, target);
    assert_eq!(next["brain_rev"], 4);
    let claude_md = next["claude_md"].as_str().unwrap();
    assert!(
        claude_md.contains("ORG-FACT-ONE") && claude_md.contains("ORG-FACT-TWO"),
        "{claude_md}"
    );
}

/// A device that does not advertise `hive-memory` is never sent core memory
/// — and its session starts all the same.
#[tokio::test]
async fn a_device_without_hive_memory_gets_none_and_still_starts() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainnone").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "brain-none", RUNS_HIVE).await;
    assert_eq!(
        keep(
            &app,
            &tid,
            &admin,
            json!({"scope": "org", "text": "ORG-FACT"})
        )
        .await
        .0,
        200
    );

    let caller = start(&app, &tid, &admin, &dev.agent_id, "/srv");
    let target = async {
        let mut seen: Vec<String> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let Ok(Some(Ok(Message::Text(text)))) =
                tokio::time::timeout(Duration::from_millis(100), dev.ws.next()).await
            else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let t = v["t"].as_str().unwrap_or_default().to_string();
            let is_start = t == "rc:hive.start";
            seen.push(t);
            if is_start {
                send(
                    &mut dev.ws,
                    json!({"t": "rc:hive.start_ack", "session_id": v["session_id"], "fence": 1, "account": "dev"}),
                )
                .await;
                break;
            }
        }
        seen
    };
    let (body, seen) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    assert!(seen.iter().any(|t| t == "rc:hive.start"), "{seen:?}");
    assert!(!seen.iter().any(|t| t == "rc:hive.memory"), "{seen:?}");
    assert!(body["session"].get("brain_rev").is_none(), "{body}");
}

/// A start re-sent on connect carries the SAME frozen snapshot ahead of it,
/// even when the brain moved on in between.
#[tokio::test]
async fn a_re_sent_start_carries_the_same_snapshot_first() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("brainresend").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "brain-resend", TAKES_MEMORY).await;
    assert_eq!(
        keep(
            &app,
            &tid,
            &admin,
            json!({"scope": "org", "text": "ORG-FACT-ONE"})
        )
        .await
        .0,
        200
    );

    let caller = start(&app, &tid, &admin, &dev.agent_id, "/srv");
    let target = async { read_until(&mut dev.ws, "rc:hive.memory").await.unwrap() };
    let (body, first) = tokio::join!(caller, target);
    assert_eq!(
        body["outcome"], "pending",
        "the device stayed silent: {body}"
    );
    let sid = body["session"]["id"].as_str().unwrap().to_string();

    assert_eq!(
        keep(
            &app,
            &tid,
            &admin,
            json!({"scope": "org", "text": "ORG-FACT-TWO"})
        )
        .await
        .0,
        200
    );
    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let mut ws = connect(&app, &dev.token, &dev.machine, TAKES_MEMORY).await;
    let again = read_until(&mut ws, "rc:hive.memory")
        .await
        .expect("the memory again");
    let start = read_until(&mut ws, "rc:hive.start")
        .await
        .expect("then the start again");
    assert_eq!(again["session_id"], sid.as_str());
    assert_eq!(start["session_id"], sid.as_str());
    assert_eq!(again["claude_md"], first["claude_md"], "the same snapshot");
    assert_eq!(again["brain_rev"], first["brain_rev"]);
    assert!(
        !again["claude_md"]
            .as_str()
            .unwrap()
            .contains("ORG-FACT-TWO")
    );
}

// ─── P1j — terminal sessions a person adopted (`rc:hive.adopt`) ─────────────

/// The device offers a terminal session; the server's answer.
async fn adopt(ws: &mut AgentWs, adopt_id: &str, harness_session: &str, keys: &[&str]) -> Value {
    send(
        ws,
        json!({
            "t": "rc:hive.adopt",
            "adopt_id": adopt_id,
            "harness_session": harness_session,
            "keys": keys,
            "account": "alice",
            "folder": "/home/alice/client-x",
        }),
    )
    .await;
    let ack = read_until(ws, "rc:hive.adopt_ack")
        .await
        .expect("an answer to the offer");
    assert_eq!(ack["adopt_id"], adopt_id, "{ack}");
    ack
}

/// Decision 11 on the server: an adopted terminal session is attributed
/// through the device's keys, never by guess; it is its owner's alone, the
/// org's admin included; it is read-only, with readers by name and no
/// drivers; and one terminal session is one record, however often offered.
#[tokio::test]
async fn an_adopted_terminal_session_is_its_owners_alone() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("hiveadopt").await;
    let (owner, admin) = (&seeded.member, &seeded.admin);
    let tid = seeded.tenant_id.clone();
    let mut dev = device(
        &app,
        &seeded,
        "adopter",
        &["hive", "hive-view", "hive-adopt"],
    )
    .await;

    let uuid = "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70";
    let ack = adopt(&mut dev.ws, "a1", uuid, &[&owner.email]).await;
    assert!(ack.get("refused").is_none(), "{ack}");
    assert_eq!(ack["fence"], 1);
    let sid = ack["session_id"].as_str().unwrap().to_string();

    // Its owner's: read-only, named after its folder (no title is offered).
    let (code, s) = get_session(&app, &tid, &owner.access_token, &sid).await;
    assert_eq!(code, 200, "{s}");
    assert_eq!(
        (
            s["origin"].clone(),
            s["status"].clone(),
            s["title"].clone(),
            s["account"].clone()
        ),
        (
            json!("adopted"),
            json!("idle"),
            json!("client-x"),
            json!("alice")
        ),
        "{s}"
    );
    let row = stored(&app, &sid).await;
    assert_eq!(row.get_str("origin").unwrap(), "adopted");
    // Nobody else's — the org's admin included.
    let (code, _) = get_session(&app, &tid, &admin.access_token, &sid).await;
    assert_eq!(code, 404, "an admin does not read someone's terminal");

    // No drivers, even ones the org trusts; readers by name.
    let (code, body) = set_part(&app, &tid, &owner.access_token, &sid, &admin.id, "driver").await;
    assert_eq!(code, 409, "{body}");
    let (code, body) = set_part(&app, &tid, &owner.access_token, &sid, &admin.id, "reader").await;
    assert_eq!(code, 200, "{body}");
    let (code, _) = get_session(&app, &tid, &admin.access_token, &sid).await;
    assert_eq!(code, 200, "a reader the owner named reads it");

    // The same terminal offered again — a restart, a lost ack: the same record.
    let again = adopt(&mut dev.ws, "a2", uuid, &[&owner.email]).await;
    assert_eq!(again["session_id"], sid.as_str(), "{again}");

    // Attributed by the keys, never by guess.
    let two = adopt(
        &mut dev.ws,
        "a3",
        "11111111-2222-3333-4444-555555555555",
        &[&owner.email, &admin.email],
    )
    .await;
    assert_eq!(
        two["refused"], "ambiguous_account",
        "two people behind one account: {two}"
    );
    let nobody = adopt(
        &mut dev.ws,
        "a4",
        "22222222-2222-3333-4444-555555555555",
        &["nobody@example.com"],
    )
    .await;
    assert_eq!(nobody["refused"], "no_account", "{nobody}");
    let placeholder = format!("{}.invalid", owner.email);
    let unproven = adopt(
        &mut dev.ws,
        "a5",
        "33333333-2222-3333-4444-555555555555",
        &[&placeholder],
    )
    .await;
    assert_eq!(
        unproven["refused"], "no_account",
        "a placeholder names nobody: {unproven}"
    );
    let elsewhere = app.seed_tenant("hiveadopt2").await;
    let foreign = adopt(
        &mut dev.ws,
        "a6",
        "44444444-2222-3333-4444-555555555555",
        &[&elsewhere.member.email],
    )
    .await;
    assert_eq!(foreign["refused"], "not_a_member", "{foreign}");
    // By user id, and an address in another case, both name the owner.
    let by_id = adopt(
        &mut dev.ws,
        "a7",
        "55555555-2222-3333-4444-555555555555",
        &[&owner.id],
    )
    .await;
    assert!(by_id.get("refused").is_none(), "{by_id}");
    let upper = owner.email.to_ascii_uppercase();
    let by_case = adopt(
        &mut dev.ws,
        "a8",
        "66666666-2222-3333-4444-555555555555",
        &[&upper],
    )
    .await;
    assert!(by_case.get("refused").is_none(), "{by_case}");

    // The device's owner remapped the account: the same terminal session now
    // names someone else. Its record ends; nothing more is mirrored into it.
    let remapped_sid = by_id["session_id"].as_str().unwrap().to_string();
    let moved = adopt(
        &mut dev.ws,
        "a9",
        "55555555-2222-3333-4444-555555555555",
        &[&admin.email],
    )
    .await;
    assert_eq!(moved["refused"], "ambiguous_account", "{moved}");
    let row = stored(&app, &remapped_sid).await;
    assert_eq!(
        (
            row.get_str("status").unwrap(),
            row.get_str("end_reason").unwrap()
        ),
        ("ended", "attribution_changed"),
        "the record held for the old owner ends"
    );

    // The device's reports move it like any session's.
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended", "detail": "the terminal closed"}),
    )
    .await;
    let s = wait_status(&app, &tid, &owner.access_token, &sid, "ended").await;
    assert_eq!(s["origin"], "adopted", "{s}");
}

/// The gates before attribution: a device that did not say it adopts is not
/// answered at all, and an org agent sessions do not serve is refused in
/// those words.
#[tokio::test]
async fn an_adopt_offer_passes_the_device_and_org_gates_first() {
    let first = hive_app().await;
    let a = first.seed_tenant("hiveadoptgate").await;
    let b = first.seed_tenant("hiveadoptother").await;
    // Hive serves B only.
    let app = serving_only(&first, &b.tenant_id).await;

    let mut quiet = device(&app, &a, "noadopt", &["hive", "hive-view"]).await;
    send(
        &mut quiet.ws,
        json!({
            "t": "rc:hive.adopt", "adopt_id": "q1",
            "harness_session": "77777777-2222-3333-4444-555555555555",
            "keys": [a.member.email.clone()], "account": "alice", "folder": "/home/alice/x",
        }),
    )
    .await;
    assert!(
        read_until(&mut quiet.ws, "rc:hive.adopt_ack")
            .await
            .is_none(),
        "a device that did not advertise hive-adopt is not answered"
    );

    let mut unserved = device(&app, &a, "adopter2", &["hive", "hive-view", "hive-adopt"]).await;
    let ack = adopt(
        &mut unserved.ws,
        "u1",
        "88888888-2222-3333-4444-555555555555",
        &[&a.member.email],
    )
    .await;
    assert_eq!(ack["refused"], "hive_not_enabled", "{ack}");
    let none = app
        .db
        .collection::<Document>("agent_sessions")
        .count_documents(doc! { "origin": "adopted" })
        .await
        .unwrap();
    assert_eq!(none, 0, "no record for a refused or unanswered offer");
}

// ─── P2c-2a — the replica policy (`hive.replicaset`) ───────────────────────

/// [`hive_app`] with the replicaset's server switch on.
async fn replicaset_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        // Polls, like `hive_app_polling`: the default limiter answers a poll
        // loop 429 before the condition it waits for, so a wait that runs to
        // its deadline would fail on the 429, not on what it waited for.
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// FR-90 P2h-2 — the SPA's question, whether agent sessions serve the
/// organization, also says whether they are copied here at all
/// (`hive.replicaset`): its copies page is shown only then.
#[tokio::test]
async fn the_hive_question_says_whether_sessions_are_copied_here() {
    for (app, copied) in [(hive_app().await, false), (replicaset_app().await, true)] {
        let s = app
            .seed_tenant(if copied { "copieshere" } else { "nocopies" })
            .await;
        let (code, body) = status_and_json(
            app.auth_get(
                &format!("/api/tenant/{}/hive", s.tenant_id),
                &s.admin.access_token,
            )
            .send()
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(
            (code, body["enabled"].clone(), body["replicaset"].clone()),
            (200, json!(true), json!(copied)),
            "{body}"
        );
    }
}

async fn get_policy(app: &TestApp, tid: &str, token: &str) -> (u16, Value) {
    let resp = app
        .auth_get(&format!("/api/tenant/{tid}/hive/policy"), token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn put_policy(app: &TestApp, tid: &str, token: &str, body: &Value) -> (u16, Value) {
    let resp = app
        .auth_put(&format!("/api/tenant/{tid}/hive/policy"), token)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn a_policy(revision: i64) -> Value {
    json!({
        "replicaset": {
            "min": 3,
            "max": 5,
            "archive": false,
            "prefer": ["owner_devices"],
            "restricted_tags": [" pci ", "pci", ""],
        },
        "retention_days": 30,
        "archive_devices": [],
        "revision": revision,
    })
}

/// With the replicaset's switch off, the policy is not there for anyone.
#[tokio::test]
async fn the_replica_policy_is_not_there_while_its_switch_is_off() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivepolicyoff").await;
    let admin = &seeded.admin.access_token;
    assert_eq!(get_policy(&app, &seeded.tenant_id, admin).await.0, 404);
    assert_eq!(
        put_policy(&app, &seeded.tenant_id, admin, &a_policy(0))
            .await
            .0,
        404
    );
}

/// An organization starts with decision 2's defaults. Any member reads the
/// policy; only an administrator writes it, from the revision they read, an
/// archive device must be a live device of this organization, and every
/// attempt is audited.
#[tokio::test]
async fn an_administrator_sets_the_replica_policy_from_the_revision_they_read() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivepolicy").await;
    let tid = seeded.tenant_id.as_str();
    let admin = seeded.admin.access_token.as_str();
    let member = seeded.member.access_token.as_str();

    let (s, p) = get_policy(&app, tid, member).await;
    assert_eq!(s, 200, "{p}");
    assert_eq!(p["is_default"], true);
    assert_eq!(p["revision"], 0);
    assert_eq!(
        p["replicaset"],
        json!({
            "min": 2, "max": 4, "archive": true,
            "prefer": ["owner_devices"], "restricted_tags": ["prod"],
        })
    );
    assert_eq!(p["retention_days"], 90);

    assert_eq!(put_policy(&app, tid, member, &a_policy(0)).await.0, 403);

    let (s, p) = put_policy(&app, tid, admin, &a_policy(0)).await;
    assert_eq!(s, 200, "{p}");
    assert_eq!(p["revision"], 1);
    assert_eq!(p["is_default"], false);
    assert_eq!(
        p["replicaset"]["restricted_tags"],
        json!(["pci"]),
        "normalized"
    );
    assert_eq!(p["updated_by"], seeded.admin.id.as_str());
    assert_eq!(get_policy(&app, tid, member).await.1["revision"], 1);

    let (s, _) = put_policy(&app, tid, admin, &a_policy(0)).await;
    assert_eq!(s, 409, "a write from the revision before is stale");

    let mut next = a_policy(1);
    next["replicaset"]["min"] = json!(1);
    let (s, p) = put_policy(&app, tid, admin, &next).await;
    assert_eq!(s, 200, "{p}");
    assert_eq!(
        (p["revision"].as_i64(), p["replicaset"]["min"].as_i64()),
        (Some(2), Some(1))
    );
    let (s, _) = put_policy(&app, tid, admin, &next).await;
    assert_eq!(s, 409, "revision 1 is no longer the stored one");

    let mut bad = a_policy(2);
    bad["replicaset"]["max"] = json!(0);
    assert_eq!(put_policy(&app, tid, admin, &bad).await.0, 400);

    let other = app.seed_tenant("hivepolicyother").await;
    let (foreign, _) = enroll_agent(&app, &other, "mach-policy-foreign", "foreign").await;
    let mut archive = a_policy(2);
    archive["archive_devices"] = json!([foreign]);
    assert_eq!(
        put_policy(&app, tid, admin, &archive).await.0,
        400,
        "another organization's device"
    );
    let agents = app.db.collection::<Document>("agents");
    let (removed, _) = enroll_agent(&app, &seeded, "mach-policy-removed", "removed").await;
    agents
        .update_one(
            doc! { "_id": ObjectId::parse_str(&removed).unwrap() },
            doc! { "$set": { "deleted_at": bson::DateTime::now() } },
        )
        .await
        .unwrap();
    archive["archive_devices"] = json!([removed]);
    assert_eq!(
        put_policy(&app, tid, admin, &archive).await.0,
        400,
        "a removed device"
    );
    let (ephemeral, _) = enroll_agent(&app, &seeded, "mach-policy-eph", "eph").await;
    agents
        .update_one(
            doc! { "_id": ObjectId::parse_str(&ephemeral).unwrap() },
            doc! { "$set": { "ephemeral": true } },
        )
        .await
        .unwrap();
    archive["archive_devices"] = json!([ephemeral]);
    let (s, p) = put_policy(&app, tid, admin, &archive).await;
    assert_eq!(s, 400, "an ephemeral device: {p}");
    let (own, _) = enroll_agent(&app, &seeded, "mach-policy-own", "own").await;
    archive["archive_devices"] = json!([own, own]);
    let (s, p) = put_policy(&app, tid, admin, &archive).await;
    assert_eq!(s, 200, "{p}");
    assert_eq!(p["archive_devices"], json!([own]), "once");

    let tid_oid = ObjectId::parse_str(tid).unwrap();
    let mut audits = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "tenant_id": tid_oid, "action": "policy" })
        .await
        .unwrap();
    let mut seen: Vec<(String, String)> = Vec::new();
    while let Some(d) = audits.next().await {
        let d = d.unwrap();
        seen.push((
            d.get_str("outcome").unwrap().to_string(),
            d.get_str("reason").unwrap_or("").to_string(),
        ));
    }
    seen.sort();
    let want = [
        ("refused", "ephemeral"),
        ("refused", "invalid"),
        ("refused", "no_permission"),
        ("refused", "not_a_device"),
        ("refused", "not_a_device"),
        ("refused", "stale"),
        ("refused", "stale"),
        ("set", ""),
        ("set", ""),
        ("set", ""),
    ]
    .map(|(o, r)| (o.to_string(), r.to_string()));
    assert_eq!(seen, want);
}

// ─── P2c-2b — placement (`hive.replicaset`) ────────────────────────────────

/// Set fields on a device's stored row, as its hello or an admin would.
async fn set_device(app: &TestApp, id: &str, set: Document) {
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(id).unwrap() },
            doc! { "$set": set },
        )
        .await
        .unwrap();
}

/// A device of the admin's that never connected, whose stored capabilities
/// are `rpc`: placement reads the last hello, so an offline device is placed
/// too.
async fn stored_device(
    app: &TestApp,
    seeded: &SeededTenant,
    machine: &str,
    rpc: &[&str],
) -> String {
    let (id, _) = enroll_agent(app, seeded, machine, machine).await;
    let rpc: Vec<String> = rpc.iter().map(|s| s.to_string()).collect();
    set_device(app, &id, doc! { "capabilities.rpc": rpc }).await;
    id
}

/// Start a session on `dev` as `token`, answered as the device would.
async fn started(app: &TestApp, tid: &str, token: &str, dev: &mut Device, folder: &str) -> Value {
    let caller = start(app, tid, token, &dev.agent_id, folder);
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives rc:hive.start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    body["session"].clone()
}

fn members(s: &Value) -> Vec<(String, String)> {
    s["replicaset"]["members"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|m| {
            (
                m["device_id"].as_str().unwrap_or("").to_string(),
                m["role"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// With the replicaset's switch off, a session is placed nowhere: the
/// record carries no replicaset and nothing is audited.
#[tokio::test]
async fn a_session_started_with_the_switch_off_is_placed_nowhere() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveplaceoff").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-placeoff-p", RUNS_HIVE).await;
    stored_device(&app, &seeded, "mach-placeoff-r", &["hive-replica"]).await;
    let s = started(&app, &tid, &admin, &mut primary, "/srv/off").await;
    assert!(s.get("replicaset").is_none(), "{s}");
    let sid = s["id"].as_str().unwrap();
    assert!(stored(&app, sid).await.get("replicaset").is_none());
    let places = app
        .db
        .collection::<Document>("hive_audit")
        .count_documents(doc! { "action": "place" })
        .await
        .unwrap();
    assert_eq!(places, 0);
}

/// Placement at a start, from the devices' stored rows: the designated
/// archive that offers itself, then the owner's own devices that offer,
/// last seen first, until `min`. Never a device that does not offer, an
/// ephemeral one, one handed to someone else, or a removed one; and with a
/// restricted primary, only devices carrying its tag, in any case.
#[tokio::test]
async fn placement_takes_the_archive_then_the_owners_offering_devices() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hiveplace").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    // Eight devices: past the free plan's three.
    app.db
        .collection::<Document>("tenants")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&tid).unwrap() },
            doc! { "$set": { "plan": "pro" } },
        )
        .await
        .unwrap();
    let mut primary = device(&app, &seeded, "mach-place-primary", RUNS_HIVE).await;
    // Online, and its hello offers copies.
    let laptop = device(
        &app,
        &seeded,
        "mach-place-laptop",
        &["exec", "hive", "hive-replica"],
    )
    .await;
    let old = stored_device(&app, &seeded, "mach-place-old", &["hive-replica"]).await;
    let day_ago =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 86_400_000);
    set_device(&app, &old, doc! { "last_seen_at": day_ago }).await;
    let nas = stored_device(
        &app,
        &seeded,
        "mach-place-nas",
        &["hive-replica", "hive-archive"],
    )
    .await;
    let silent = stored_device(&app, &seeded, "mach-place-silent", &["exec"]).await;
    let eph = stored_device(&app, &seeded, "mach-place-eph", &["hive-replica"]).await;
    set_device(&app, &eph, doc! { "ephemeral": true }).await;
    let handed = stored_device(&app, &seeded, "mach-place-handed", &["hive-replica"]).await;
    let member_id = ObjectId::parse_str(&seeded.member.id).unwrap();
    set_device(&app, &handed, doc! { "owner_user_id": member_id }).await;
    let removed = stored_device(&app, &seeded, "mach-place-removed", &["hive-replica"]).await;
    set_device(&app, &removed, doc! { "deleted_at": bson::DateTime::now() }).await;

    let mut policy = a_policy(0);
    policy["replicaset"] = json!({
        "min": 3, "max": 4, "archive": true,
        "prefer": ["owner_devices"], "restricted_tags": ["prod"],
    });
    policy["archive_devices"] = json!([nas]);
    let (code, p) = put_policy(&app, &tid, &admin, &policy).await;
    assert_eq!(code, 200, "{p}");

    let s = started(&app, &tid, &admin, &mut primary, "/srv/place").await;
    let r = &s["replicaset"];
    assert_eq!(
        (
            r["policy_revision"].as_i64(),
            r["min"].as_u64(),
            r["max"].as_u64()
        ),
        (Some(1), Some(3), Some(4)),
        "{s}"
    );
    let want = |rows: &[(&str, &str)]| -> Vec<(String, String)> {
        rows.iter()
            .map(|(d, r)| (d.to_string(), r.to_string()))
            .collect()
    };
    assert_eq!(
        members(&s),
        want(&[
            (&primary.agent_id, "primary"),
            (&nas, "archive"),
            (&laptop.agent_id, "owner"),
        ]),
        "{r}"
    );
    assert!(r.get("short").is_none(), "{r}");
    assert_eq!(r["restricted_tags"], json!([]));
    let sid = s["id"].as_str().unwrap().to_string();
    let (_, read) = get_session(&app, &tid, &admin, &sid).await;
    assert_eq!(read["replicaset"], s["replicaset"], "kept on the record");
    for never in [&silent, &eph, &handed, &removed, &old] {
        assert!(!members(&s).iter().any(|(d, _)| d == never), "{never}: {r}");
    }

    // A primary tagged `Prod` is restricted by the policy's `prod`; only the
    // device tagged `PROD` may hold a copy, and the session is short.
    set_device(&app, &primary.agent_id, doc! { "tags": ["Prod"] }).await;
    set_device(&app, &old, doc! { "tags": ["PROD"] }).await;
    let s = started(&app, &tid, &admin, &mut primary, "/srv/prod").await;
    let r = &s["replicaset"];
    assert_eq!(r["restricted_tags"], json!(["prod"]), "{r}");
    assert_eq!(
        members(&s),
        want(&[(&primary.agent_id, "primary"), (&old, "owner")]),
        "{r}"
    );
    assert_eq!(r["short"], "restricted");

    let tid_oid = ObjectId::parse_str(&tid).unwrap();
    let mut rows = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "tenant_id": tid_oid, "action": "place" })
        .await
        .unwrap();
    let mut seen: Vec<(String, String)> = Vec::new();
    while let Some(d) = rows.next().await {
        let d = d.unwrap();
        seen.push((
            d.get_str("outcome").unwrap().to_string(),
            d.get_str("reason").unwrap_or("").to_string(),
        ));
    }
    seen.sort();
    assert_eq!(
        seen,
        [
            ("placed".to_string(), String::new()),
            ("short".to_string(), "restricted".to_string()),
        ]
    );
}

// ─── P2c-3a — the join, and what a member says back ─────────────────────────

/// What a device that holds copies advertises (`hive-replica`).
const HOLDS_COPIES: &[&str] = &["exec", "hive", "hive-replica"];

/// The free plan's three devices are not enough for a replicaset test.
async fn on_pro(app: &TestApp, seeded: &SeededTenant) {
    app.db
        .collection::<Document>("tenants")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&seeded.tenant_id).unwrap() },
            doc! { "$set": { "plan": "pro" } },
        )
        .await
        .unwrap();
}

/// The member of `sid` that is `device`, as the session view reads it.
async fn member_of(app: &TestApp, tid: &str, token: &str, sid: &str, device: &str) -> Value {
    let (code, s) = get_session(app, tid, token, sid).await;
    assert_eq!(code, 200, "{s}");
    s["replicaset"]["members"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["device_id"] == device).cloned())
        .unwrap_or(Value::Null)
}

/// Poll until the member `device` of `sid` satisfies `pred`.
async fn wait_member(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    device: &str,
    what: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let m = member_of(app, tid, token, sid, device).await;
        if pred(&m) {
            return m;
        }
        assert!(Instant::now() < deadline, "{what}: {m}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether a frame `want` arrives within `within`.
async fn arrives(ws: &mut AgentWs, want: &str, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && v["t"] == want
                {
                    return Some(v);
                }
            }
            Ok(Some(Ok(_))) | Err(_) => continue,
            Ok(Some(Err(_))) | Ok(None) => return None,
        }
    }
    None
}

/// A well-formed hash, every character `fill`.
fn hash(fill: &str) -> String {
    fill.repeat(64 / fill.len())
}

/// A member that holds copies is sent its join once the primary accepts,
/// and the primary's start says the session is replicated. The member's
/// answer and its tips land on its entry; the primary's tips on the
/// primary's. A device the session does not hold as a member changes
/// nothing, and a malformed hash is dropped.
#[tokio::test]
async fn a_member_is_joined_once_the_primary_accepts_and_its_tips_are_kept() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivejoin").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-join-primary", RUNS_HIVE).await;
    let mut member = device(&app, &seeded, "mach-join-member", HOLDS_COPIES).await;
    let mut stranger = device(&app, &seeded, "mach-join-stranger", RUNS_HIVE).await;
    let other = app.seed_tenant("hivejoinother").await;
    // Someone else's device: never the admin's own, so never placed.
    let mut theirs = device(&app, &other, "mach-join-theirs", HOLDS_COPIES).await;

    let caller = start(&app, &tid, &admin, &primary.agent_id, "/srv/join");
    let target = async {
        let frame = read_until(&mut primary.ws, "rc:hive.start")
            .await
            .expect("the primary receives rc:hive.start");
        assert_eq!(frame["replicated"], true, "a member was placed: {frame}");
        send(
            &mut primary.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    let sid = body["session"]["id"].as_str().unwrap().to_string();

    let join = read_until(&mut member.ws, "rc:hive.replica.join")
        .await
        .expect("the member receives its join");
    assert_eq!(join["session_id"], sid.as_str());
    assert_eq!(
        (join["fence"].as_u64(), join["role"].as_str()),
        (Some(1), Some("owner"))
    );
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &member.agent_id).await["state"],
        "pending",
        "sent, not yet answered"
    );
    assert!(
        arrives(
            &mut theirs.ws,
            "rc:hive.replica.join",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "another organization's device is never joined"
    );

    // A stranger's answer and tip change nothing, nor an answer to another
    // fence.
    send(
        &mut stranger.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
    send(
        &mut stranger.ws,
        json!({"t": "rc:hive.replica.tip", "session_id": sid, "fence": 1, "seq": 9,
               "hash": hash("ee")}),
    )
    .await;
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 7}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &member.agent_id).await["state"],
        "pending",
        "neither the stranger's answer nor one to fence 7 counted"
    );
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
    let m = wait_member(&app, &tid, &admin, &sid, &member.agent_id, "joined", |m| {
        m["state"] == "joined"
    })
    .await;
    assert!(m["answered_at"].is_string(), "{m}");
    assert!(m.get("refusal").is_none(), "{m}");

    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.tip", "session_id": sid, "fence": 1, "seq": 3,
               "hash": hash("ab"), "checkpoint": {"seq": 2, "hash": hash("cd")}}),
    )
    .await;
    let m = wait_member(&app, &tid, &admin, &sid, &member.agent_id, "its tip", |m| {
        m["tip"]["seq"] == 3
    })
    .await;
    assert_eq!(
        (
            m["tip"]["fence"].as_i64(),
            m["tip"]["hash"].as_str(),
            m["tip"]["checkpoint_seq"].as_i64(),
            m["tip"]["checkpoint_hash"].as_str()
        ),
        (
            Some(1),
            Some(hash("ab").as_str()),
            Some(2),
            Some(hash("cd").as_str())
        )
    );
    // Malformed: dropped, and the last good tip stays. Then the primary's
    // own tip, through its manifest, which lands after it.
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.tip", "session_id": sid, "fence": 1, "seq": 5,
               "hash": "AB".repeat(32)}),
    )
    .await;
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.manifest", "sessions": [
            {"session_id": sid, "fence": 1, "seq": 4, "hash": hash("01")}
        ]}),
    )
    .await;
    wait_member(
        &app,
        &tid,
        &admin,
        &sid,
        &primary.agent_id,
        "the primary's tip",
        |m| m["tip"]["seq"] == 4,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &member.agent_id).await["tip"]["seq"],
        3,
        "the malformed tip was dropped"
    );
    let s = stored(&app, &sid).await;
    let members = s
        .get_document("replicaset")
        .unwrap()
        .get_array("members")
        .unwrap();
    assert_eq!(members.len(), 2, "nobody else was added: {members:?}");
    let stranger_got_tip = members.iter().any(|m| {
        m.as_document()
            .and_then(|d| d.get_document("tip").ok())
            .is_some_and(|t| t.get_i64("seq").ok() == Some(9))
    });
    assert!(!stranger_got_tip, "the stranger's tip landed nowhere");
}

/// A member offline at the start keeps its join pending; a connection that
/// does not hold copies gets nothing; the one that does gets the join, and
/// its refusal lands with the device's word. A member that refused holds
/// nothing, so its tips are not kept.
#[tokio::test]
async fn a_pending_join_waits_for_a_connection_that_holds_copies() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivejoinlater").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-later-primary", RUNS_HIVE).await;
    let (member_id, member_token) =
        enroll_agent(&app, &seeded, "mach-later-member", "mach-later-member").await;
    set_device(
        &app,
        &member_id,
        doc! { "capabilities.rpc": ["hive-replica"] },
    )
    .await;

    let s = started(&app, &tid, &admin, &mut primary, "/srv/later").await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert_eq!(
        members(&s),
        [
            (primary.agent_id.clone(), "primary".to_string()),
            (member_id.clone(), "owner".to_string()),
        ]
    );

    // Connected, but not holding copies: nothing is sent.
    let mut ws = connect(&app, &member_token, "mach-later-member", RUNS_HIVE).await;
    wait_agent_online(&app, &seeded, &member_id).await;
    assert!(
        arrives(&mut ws, "rc:hive.replica.join", Duration::from_millis(800))
            .await
            .is_none(),
        "no join to a connection without hive-replica"
    );
    ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &member_id).await;
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &member_id).await["state"],
        "pending"
    );

    // The connection that holds copies gets it, and refuses.
    let mut ws = connect(&app, &member_token, "mach-later-member", HOLDS_COPIES).await;
    let join = read_until(&mut ws, "rc:hive.replica.join")
        .await
        .expect("the join, on the connection that holds copies");
    assert_eq!(join["session_id"], sid.as_str());
    send(
        &mut ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1,
               "refused": "replica_disabled", "detail": "hive_replica is off"}),
    )
    .await;
    let m = wait_member(&app, &tid, &admin, &sid, &member_id, "refused", |m| {
        m["state"] == "refused"
    })
    .await;
    assert_eq!(m["refusal"], "replica_disabled");
    send(
        &mut ws,
        json!({"t": "rc:hive.replica.tip", "session_id": sid, "fence": 1, "seq": 2,
               "hash": hash("ab")}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        member_of(&app, &tid, &admin, &sid, &member_id)
            .await
            .get("tip")
            .is_none(),
        "a member that refused holds nothing"
    );
}

// ─── P2c-4a — placement decided again ───────────────────────────────────────

/// Set a device's tags through fleet's own route, as an admin does: the
/// change that makes placement decide again (core's `agent_updated`).
async fn tag(app: &TestApp, tid: &str, token: &str, device: &str, tags: &[&str]) {
    let resp = app
        .auth_put(&format!("/api/tenant/{tid}/agent/{device}"), token)
        .json(&json!({ "tags": tags }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert_eq!(
        status,
        200,
        "tags: {}",
        resp.text().await.unwrap_or_default()
    );
}

/// A policy with decision 2's rules but `min`, written from `revision`.
fn policy_min(min: u32, revision: i64) -> Value {
    json!({
        "replicaset": {
            "min": min, "max": 4, "archive": true,
            "prefer": ["owner_devices"], "restricted_tags": ["prod"],
        },
        "retention_days": 90,
        "archive_devices": [],
        "revision": revision,
    })
}

/// A device's tags change, and placement decides again. An unrelated change
/// moves nothing: a member that still qualifies is kept. A tag taken off
/// makes the member leave, and a device that now qualifies takes its place
/// and is joined; tagged again, the one that left stays leaving while its
/// replacement still qualifies.
#[tokio::test]
async fn placement_is_decided_again_when_a_devices_tags_change() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivereplace").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-re-primary", RUNS_HIVE).await;
    set_device(&app, &primary.agent_id, doc! { "tags": ["prod"] }).await;
    let mut a = device(&app, &seeded, "mach-re-a", HOLDS_COPIES).await;
    set_device(&app, &a.agent_id, doc! { "tags": ["prod"] }).await;
    let mut b = device(&app, &seeded, "mach-re-b", HOLDS_COPIES).await;

    let s = started(&app, &tid, &admin, &mut primary, "/srv/re").await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert_eq!(
        members(&s),
        [
            (primary.agent_id.clone(), "primary".to_string()),
            (a.agent_id.clone(), "owner".to_string()),
        ],
        "B lacks the restricted tag"
    );
    read_until(&mut a.ws, "rc:hive.replica.join")
        .await
        .expect("A's join");
    send(
        &mut a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
    wait_member(&app, &tid, &admin, &sid, &a.agent_id, "A joined", |m| {
        m["state"] == "joined"
    })
    .await;

    // An unrelated change: B now qualifies too, and nothing moves.
    tag(&app, &tid, &admin, &b.agent_id, &["prod"]).await;
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &a.agent_id).await["state"],
        "joined"
    );
    assert!(
        member_of(&app, &tid, &admin, &sid, &b.agent_id)
            .await
            .is_null(),
        "min holds: B is not taken"
    );
    assert!(
        arrives(
            &mut b.ws,
            "rc:hive.replica.join",
            Duration::from_millis(300)
        )
        .await
        .is_none()
    );

    // A's tag taken off: A leaves, B takes its place and is joined.
    tag(&app, &tid, &admin, &a.agent_id, &[]).await;
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &a.agent_id).await["state"],
        "leaving"
    );
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &b.agent_id).await["state"],
        "pending"
    );
    let join = read_until(&mut b.ws, "rc:hive.replica.join")
        .await
        .expect("B's join");
    assert_eq!(join["session_id"], sid.as_str());
    // A's join answer, late, does not take it back.
    send(
        &mut a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;

    // A tagged again: B still qualifies and is kept; A stays leaving.
    tag(&app, &tid, &admin, &a.agent_id, &["prod"]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &a.agent_id).await["state"],
        "leaving"
    );
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &b.agent_id).await["state"],
        "pending"
    );
    let (_, read) = get_session(&app, &tid, &admin, &sid).await;
    assert_eq!(read["replicaset"]["restricted_tags"], json!(["prod"]));

    let tid_oid = ObjectId::parse_str(&tid).unwrap();
    let replaced = app
        .db
        .collection::<Document>("hive_audit")
        .count_documents(doc! { "tenant_id": tid_oid, "action": "place", "outcome": "replaced" })
        .await
        .unwrap();
    assert_eq!(replaced, 1, "one change moved anyone: A out, B in");
}

/// A policy that asks for more copies places them on the live sessions it
/// governs, and joins them.
#[tokio::test]
async fn a_policy_that_asks_for_more_copies_places_them() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivereplacepolicy").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let (code, p) = put_policy(&app, &tid, &admin, &policy_min(1, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut primary = device(&app, &seeded, "mach-rp-primary", RUNS_HIVE).await;
    let mut b = device(&app, &seeded, "mach-rp-b", HOLDS_COPIES).await;
    let s = started(&app, &tid, &admin, &mut primary, "/srv/rp").await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert_eq!(members(&s).len(), 1, "min 1: the primary alone");

    let (code, p) = put_policy(&app, &tid, &admin, &policy_min(2, 1)).await;
    assert_eq!(code, 200, "{p}");
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &b.agent_id).await["state"],
        "pending"
    );
    read_until(&mut b.ws, "rc:hive.replica.join")
        .await
        .expect("B's join, from the policy change");
    let (_, read) = get_session(&app, &tid, &admin, &sid).await;
    assert_eq!(
        (
            read["replicaset"]["min"].as_u64(),
            read["replicaset"]["policy_revision"].as_i64()
        ),
        (Some(2), Some(2))
    );
}

/// A member removed from the fleet leaves the sessions it held copies of, and
/// another device that qualifies takes its place.
#[tokio::test]
async fn a_removed_member_leaves_and_another_takes_its_place() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivereplacegone").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-rg-primary", RUNS_HIVE).await;
    let mut b = device(&app, &seeded, "mach-rg-b", HOLDS_COPIES).await;
    let day_ago =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 86_400_000);
    set_device(&app, &b.agent_id, doc! { "last_seen_at": day_ago }).await;
    let a = device(&app, &seeded, "mach-rg-a", HOLDS_COPIES).await;
    let s = started(&app, &tid, &admin, &mut primary, "/srv/rg").await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert_eq!(
        members(&s)[1],
        (a.agent_id.clone(), "owner".to_string()),
        "A, seen last"
    );

    let resp = app
        .auth_delete(&format!("/api/tenant/{tid}/agent/{}", a.agent_id), &admin)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {}", resp.status());
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &a.agent_id).await["state"],
        "leaving"
    );
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &b.agent_id).await["state"],
        "pending"
    );
    read_until(&mut b.ws, "rc:hive.replica.join")
        .await
        .expect("B's join, in A's place");
}

// ─── P2c-4b — the primary told, and sessions from before placement ─────────

/// A session that started alone gains its first member: its primary is owed
/// its join, `role: primary`, and checkpoints once it answers. A primary that
/// refused (a build that cannot name the role) is asked again at its next
/// connection; one that answered `joined` is owed nothing more, and an answer
/// it was not owed changes nothing.
#[tokio::test]
async fn a_session_that_gains_its_first_member_tells_its_primary() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hiveprimaryjoin").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let (code, p) = put_policy(&app, &tid, &admin, &policy_min(1, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut primary = device(&app, &seeded, "mach-pj-primary", RUNS_HIVE).await;
    let mut b = device(&app, &seeded, "mach-pj-b", HOLDS_COPIES).await;
    let s = started(&app, &tid, &admin, &mut primary, "/srv/pj").await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert_eq!(members(&s).len(), 1, "min 1: the primary alone");
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &primary.agent_id).await["state"],
        "joined",
        "its start told it all there was"
    );

    let (code, p) = put_policy(&app, &tid, &admin, &policy_min(2, 1)).await;
    assert_eq!(code, 200, "{p}");
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &primary.agent_id).await["state"],
        "pending",
        "owed its join"
    );
    let join = read_until(&mut primary.ws, "rc:hive.replica.join")
        .await
        .expect("the primary's join");
    assert_eq!(
        (
            join["session_id"].as_str(),
            join["fence"].as_u64(),
            join["role"].as_str()
        ),
        (Some(sid.as_str()), Some(1), Some("primary"))
    );
    read_until(&mut b.ws, "rc:hive.replica.join")
        .await
        .expect("B's join");

    // A build that cannot name the role refuses it, in its own word.
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1,
               "refused": "other", "detail": "a role this build cannot name"}),
    )
    .await;
    let m = wait_member(
        &app,
        &tid,
        &admin,
        &sid,
        &primary.agent_id,
        "refused",
        |m| m["state"] == "refused",
    )
    .await;
    assert_eq!(m["refusal"], "other");

    // Asked again at its next connection, and this time it takes it.
    primary.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;
    let mut ws = connect(&app, &primary.token, &primary.machine, RUNS_HIVE).await;
    let again = read_until(&mut ws, "rc:hive.replica.join")
        .await
        .expect("asked again at its next connection");
    assert_eq!(again["role"], "primary");
    send(
        &mut ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
    wait_member(&app, &tid, &admin, &sid, &primary.agent_id, "joined", |m| {
        m["state"] == "joined"
    })
    .await;

    // An answer it was not owed changes nothing; nor is it asked again.
    send(
        &mut ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1,
               "refused": "other"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &primary.agent_id).await["state"],
        "joined"
    );
    ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;
    let mut ws = connect(&app, &primary.token, &primary.machine, RUNS_HIVE).await;
    assert!(
        arrives(&mut ws, "rc:hive.replica.join", Duration::from_millis(800))
            .await
            .is_none(),
        "joined: owed nothing"
    );
}

/// A session placed nowhere (one from before P2, or started while the switch
/// was off) is placed the first time its primary connects with the switch
/// on, as at a start: its primary, which runs it without `replicated`, is
/// owed its join, and its member is sent its own. A second connection places
/// nothing more.
#[tokio::test]
async fn a_session_from_before_placement_is_placed_when_its_primary_connects() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hiveunplaced").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-up-primary", RUNS_HIVE).await;
    let mut b = device(&app, &seeded, "mach-up-b", HOLDS_COPIES).await;
    let s = started(&app, &tid, &admin, &mut primary, "/srv/up").await;
    let sid = s["id"].as_str().unwrap().to_string();
    read_until(&mut b.ws, "rc:hive.replica.join")
        .await
        .expect("B's join at the start");
    // As a record from before P2 has it: no replicaset at all.
    let oid = ObjectId::parse_str(&sid).unwrap();
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(doc! { "_id": oid }, doc! { "$unset": { "replicaset": "" } })
        .await
        .unwrap();
    let places = || async {
        app.db
            .collection::<Document>("hive_audit")
            .count_documents(doc! { "session_id": oid, "action": "place" })
            .await
            .unwrap()
    };
    assert_eq!(places().await, 1, "the start's");

    primary.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;
    let mut ws = connect(&app, &primary.token, &primary.machine, RUNS_HIVE).await;
    let join = read_until(&mut ws, "rc:hive.replica.join")
        .await
        .expect("the primary's join");
    assert_eq!(
        (join["session_id"].as_str(), join["role"].as_str()),
        (Some(sid.as_str()), Some("primary"))
    );
    let bj = read_until(&mut b.ws, "rc:hive.replica.join")
        .await
        .expect("B's join, placed at the primary's connection");
    assert_eq!(bj["session_id"], sid.as_str());
    let (_, read) = get_session(&app, &tid, &admin, &sid).await;
    assert_eq!(
        members(&read),
        [
            (primary.agent_id.clone(), "primary".to_string()),
            (b.agent_id.clone(), "owner".to_string()),
        ]
    );
    assert_eq!(
        member_of(&app, &tid, &admin, &sid, &primary.agent_id).await["state"],
        "pending"
    );
    assert_eq!(places().await, 2, "placed once more, by the connection");

    ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;
    let _ws = connect(&app, &primary.token, &primary.machine, RUNS_HIVE).await;
    wait_agent_online(&app, &seeded, &primary.agent_id).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(places().await, 2, "placed already: nothing more");
}

/// `first`'s database, served by a second server with the replicaset's
/// switch off: as `first` restarted with `hive.replicaset = false`.
async fn switch_off(first: &TestApp) -> TestApp {
    let db = first.db.name().to_string();
    TestApp::spawn_with_settings(move |s| {
        s.database.name = db;
        s.modules.hive = true;
        s.hive.replicaset = false;
        // Polls, like `serving_only`: the default limiter answers a poll
        // loop 429 before the condition it waits for.
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// Every frame `ws` receives within `within`.
async fn frames_within(ws: &mut AgentWs, within: Duration) -> Vec<Value> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    out.push(v);
                }
            }
            Ok(Some(Ok(_))) | Err(_) => continue,
            Ok(Some(Err(_))) | Ok(None) => break,
        }
    }
    out
}

/// The replicaset's switch off is a session on its primary alone, as in P1,
/// for sessions placed while it was on as well: no join goes to a member or
/// to a primary owed one, at a connection or at an acceptance, and a start
/// sent again does not say `replicated`.
#[tokio::test]
async fn with_the_switch_off_no_replica_frame_is_sent() {
    let on = replicaset_app().await;
    let seeded = on.seed_tenant("hiveswitchoff").await;
    on_pro(&on, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let (code, p) = put_policy(&on, &tid, &admin, &policy_min(1, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut primary = device(&on, &seeded, "mach-so-primary", RUNS_HIVE).await;
    let (b_id, b_token) = enroll_agent(&on, &seeded, "mach-so-b", "mach-so-b").await;
    set_device(&on, &b_id, doc! { "capabilities.rpc": ["hive-replica"] }).await;

    // X starts alone, then gains B: its primary is owed its join.
    let x = started(&on, &tid, &admin, &mut primary, "/srv/so-x").await;
    let x = x["id"].as_str().unwrap().to_string();
    let (code, p) = put_policy(&on, &tid, &admin, &policy_min(2, 1)).await;
    assert_eq!(code, 200, "{p}");
    read_until(&mut primary.ws, "rc:hive.replica.join")
        .await
        .expect("X's primary join, with the switch on");
    assert_eq!(
        member_of(&on, &tid, &admin, &x, &primary.agent_id).await["state"],
        "pending"
    );
    // Y starts with B as a member, and its device does not answer yet.
    let caller = start(&on, &tid, &admin, &primary.agent_id, "/srv/so-y");
    let target = async {
        read_until(&mut primary.ws, "rc:hive.start")
            .await
            .expect("Y's start")
    };
    let (body, first) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "pending", "{body}");
    assert_eq!(first["replicated"], true, "placed with B, the switch on");
    let y = body["session"]["id"].as_str().unwrap().to_string();

    // The switch off: the same database, served again.
    let off = switch_off(&on).await;
    primary.ws.close(None).await.unwrap();
    wait_offline(&on, &seeded, &primary.agent_id).await;
    let mut ws = connect(&off, &primary.token, &primary.machine, RUNS_HIVE).await;
    let frames = frames_within(&mut ws, Duration::from_millis(1500)).await;
    let again = frames
        .iter()
        .find(|f| f["t"] == "rc:hive.start" && f["session_id"] == y.as_str())
        .expect("Y's start, sent again");
    assert!(again.get("replicated").is_none(), "not replicated: {again}");
    assert!(
        !frames.iter().any(|f| f["t"] == "rc:hive.replica.join"),
        "no primary join: {frames:?}"
    );

    let mut b = connect(&off, &b_token, "mach-so-b", HOLDS_COPIES).await;
    wait_agent_online(&off, &seeded, &b_id).await;
    send(
        &mut ws,
        json!({"t": "rc:hive.start_ack", "session_id": y, "fence": 1, "account": "dev"}),
    )
    .await;
    assert!(
        arrives(&mut b, "rc:hive.replica.join", Duration::from_millis(1200))
            .await
            .is_none(),
        "no member join, at its connection or at Y's acceptance"
    );
}

// ─── P2d-1 — the replica stream's grants ───────────────────────────────────

/// What a source advertises: it runs sessions and carries streams.
const SERVES_STREAMS: &[&str] = &["exec", "hive", "hive-stream"];
/// What a member that follows advertises: it holds copies and carries streams.
const FOLLOWS: &[&str] = &["exec", "hive", "hive-replica", "hive-stream"];

/// The replicaset on, a TURN server configured so the `relay` rung can be
/// granted, and a limiter a polling test cannot trip.
async fn stream_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.turn.url = Some("turn:turn.example.com:3478".into());
        s.turn.shared_secret = Some("stream-test-secret".into());
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// A session on `primary`, with `member` joined: it answered its join.
async fn followed(
    app: &TestApp,
    tid: &str,
    token: &str,
    primary: &mut Device,
    member: &mut Device,
    folder: &str,
) -> String {
    let s = started(app, tid, token, primary, folder).await;
    let sid = s["id"].as_str().unwrap().to_string();
    read_until(&mut member.ws, "rc:hive.replica.join")
        .await
        .expect("the member's join");
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
    wait_member(app, tid, token, &sid, &member.agent_id, "joined", |m| {
        m["state"] == "joined"
    })
    .await;
    sid
}

/// A member's want, from an empty copy, on `path`.
fn want(sid: &str, path: &str) -> Value {
    json!({
        "t": "rc:hive.replica.want", "session_id": sid, "fence": 1,
        "seq": 0, "hash": "0".repeat(64), "path": path,
    })
}

/// The member's refusal, and why. `waited` names what the caller waited
/// for, in the panic when none came: every call shares the panic's line.
async fn refused_why(ws: &mut AgentWs, waited: &str) -> Value {
    read_until(ws, "rc:hive.replica.refused")
        .await
        .unwrap_or_else(|| panic!("no refusal: {waited}"))
}

/// The member is told to dial only once the source said it is ready, with
/// the token the source was granted and the certificate it reported. A
/// candidate on the direct rung goes nowhere; a close reaches the other side.
#[tokio::test]
async fn a_member_is_told_to_dial_only_once_the_source_is_ready() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivestream").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-st-primary", SERVES_STREAMS).await;
    let mut member = device(&app, &seeded, "mach-st-member", FOLLOWS).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/st").await;

    send(&mut member.ws, want(&sid, "direct")).await;
    let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("the source's grant");
    assert_eq!(grant["session_id"], sid.as_str());
    assert_eq!(grant["member_id"], member.agent_id.as_str());
    assert_eq!(
        (grant["path"].as_str(), grant["ttl_secs"].as_u64()),
        (Some("direct"), Some(600))
    );
    let token = grant["token"].as_str().unwrap().to_string();
    assert!(token.len() >= 32, "unguessable: {token}");
    assert!(
        grant["ice_servers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s.get("username").is_none()),
        "STUN only on the direct rung: {grant}"
    );
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    // The member cannot answer for its source.
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("ee"),
               "addrs": ["192.0.2.66:1"]}),
    )
    .await;
    assert!(
        arrives(
            &mut member.ws,
            "rc:hive.replica.dial",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "no dial before the source is ready, nor on the member's own word"
    );

    let fp = hash("ab");
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": fp,
               "addrs": ["192.0.2.7:41641"]}),
    )
    .await;
    let dial = read_until(&mut member.ws, "rc:hive.replica.dial")
        .await
        .expect("the member's dial");
    assert_eq!(
        (
            dial["grant_id"].as_str(),
            dial["source_id"].as_str(),
            dial["token"].as_str(),
            dial["cert_fingerprint"].as_str(),
        ),
        (
            Some(gid.as_str()),
            Some(primary.agent_id.as_str()),
            Some(token.as_str()),
            Some(fp.as_str()),
        )
    );
    assert_eq!(dial["addrs"], json!(["192.0.2.7:41641"]));

    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.candidate", "grant_id": gid, "addr": "198.51.100.4:3478"}),
    )
    .await;
    assert!(
        arrives(
            &mut primary.ws,
            "rc:hive.replica.candidate",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "no candidate on the direct rung"
    );
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.close", "grant_id": gid, "reason": "caught_up"}),
    )
    .await;
    let close = read_until(&mut primary.ws, "rc:hive.replica.close")
        .await
        .expect("the source is told");
    assert_eq!(
        (close["grant_id"].as_str(), close["reason"].as_str()),
        (Some(gid.as_str()), Some("caught_up"))
    );
    let tid_oid = ObjectId::parse_str(&tid).unwrap();
    let rows = app
        .db
        .collection::<Document>("hive_audit")
        .count_documents(doc! { "tenant_id": tid_oid, "action": "stream" })
        .await
        .unwrap();
    assert_eq!(rows, 2, "sent, then ready");
}

/// The `relay` rung carries TURN credentials to both sides, minted for one
/// worker, and relays the member's address to the source; the `derp` rung
/// carries both devices' keys, and a ready without the source's is no ready.
#[tokio::test]
async fn the_relay_and_derp_rungs_carry_what_they_need() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivestreamrungs").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-sr-primary", SERVES_STREAMS).await;
    let mut member = device(&app, &seeded, "mach-sr-member", FOLLOWS).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/sr").await;

    let turn = |ice: &Value| {
        ice.as_array()
            .unwrap()
            .iter()
            .any(|s| s["username"].is_string() && s["credential"].is_string())
    };
    send(&mut member.ws, want(&sid, "relay")).await;
    let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a relay grant");
    assert!(turn(&grant["ice_servers"]), "the source's TURN credentials");
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("cd"),
               "addrs": ["203.0.113.9:49152"]}),
    )
    .await;
    let dial = read_until(&mut member.ws, "rc:hive.replica.dial")
        .await
        .expect("a relay dial");
    assert!(turn(&dial["ice_servers"]), "the member's TURN credentials");
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.candidate", "grant_id": gid, "addr": "198.51.100.4:3478"}),
    )
    .await;
    let c = read_until(&mut primary.ws, "rc:hive.replica.candidate")
        .await
        .expect("the member's relay address, for the source to permit");
    assert_eq!(c["addr"], "198.51.100.4:3478");
    // Not an address, or not the member's grant: nothing.
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.candidate", "grant_id": gid, "addr": "relay.example:3478"}),
    )
    .await;
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.candidate", "grant_id": gid, "addr": "198.51.100.5:3478"}),
    )
    .await;
    assert!(
        arrives(
            &mut primary.ws,
            "rc:hive.replica.candidate",
            Duration::from_millis(300)
        )
        .await
        .is_none()
    );

    let member_key = "1f".repeat(32);
    let mut w = want(&sid, "derp");
    w["derp_pubkey"] = json!(member_key);
    send(&mut member.ws, w.clone()).await;
    let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a derp grant");
    assert_eq!(grant["member_derp_pubkey"], member_key.as_str());
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("ef")}),
    )
    .await;
    let no = refused_why(&mut member.ws, "a derp ready without the source's key").await;
    assert_eq!(
        no["reason"], "other",
        "a derp ready without the source's key: {no}"
    );
    let close = read_until(&mut primary.ws, "rc:hive.replica.close")
        .await
        .expect("the source's endpoint is told to go");
    assert_eq!(close["reason"], "malformed");

    send(&mut member.ws, w).await;
    let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a second derp grant");
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    let source_key = "2e".repeat(32);
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("ef"),
               "derp_pubkey": source_key}),
    )
    .await;
    let dial = read_until(&mut member.ws, "rc:hive.replica.dial")
        .await
        .expect("a derp dial");
    assert_eq!(dial["derp_pubkey"], source_key.as_str());
    assert_eq!(dial["path"], "derp");
}

/// FR-90 P2d-2b — an address no device could be reached at is never
/// relayed: a `ready` that offers one is no ready (the member is refused
/// `other`, the source's endpoint is told to go), and such a candidate is
/// dropped. The device checks again before it dials or permits: this is the
/// server's courtesy, the device's the gate.
#[tokio::test]
async fn an_address_no_device_could_be_reached_at_is_never_relayed() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivestreamaddrs").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-sa-primary", SERVES_STREAMS).await;
    let mut member = device(&app, &seeded, "mach-sa-member", FOLLOWS).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/sa").await;

    for nowhere in [
        "224.0.0.251:5353",
        "255.255.255.255:41641",
        "0.0.0.0:41641",
        "192.0.2.7:0",
    ] {
        send(&mut member.ws, want(&sid, "direct")).await;
        let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
            .await
            .expect("a grant");
        let gid = grant["grant_id"].as_str().unwrap().to_string();
        send(
            &mut primary.ws,
            json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("ab"),
                   "addrs": [nowhere]}),
        )
        .await;
        let no = refused_why(&mut member.ws, &format!("a ready offering {nowhere}")).await;
        assert_eq!(no["reason"], "other", "{nowhere}: {no}");
        let close = read_until(&mut primary.ws, "rc:hive.replica.close")
            .await
            .expect("the source's endpoint is told to go");
        assert_eq!(close["reason"], "malformed", "{nowhere}");
    }

    send(&mut member.ws, want(&sid, "relay")).await;
    let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a relay grant");
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("cd"),
               "addrs": ["203.0.113.9:49152"]}),
    )
    .await;
    read_until(&mut member.ws, "rc:hive.replica.dial")
        .await
        .expect("a relay dial");
    send(
        &mut member.ws,
        json!({"t": "rc:hive.replica.candidate", "grant_id": gid, "addr": "224.0.0.251:5353"}),
    )
    .await;
    assert!(
        arrives(
            &mut primary.ws,
            "rc:hive.replica.candidate",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "a multicast candidate is dropped"
    );
}

/// Each of the server's gates refuses in its own word: not a member, another
/// fence, a rung that cannot be had, a source away or of an older build, and
/// the rate. A connection that does not carry streams is not heard at all.
#[tokio::test]
async fn a_want_is_refused_by_the_gate_it_failed() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivestreamgates").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-sg-primary", SERVES_STREAMS).await;
    let mut member = device(&app, &seeded, "mach-sg-member", FOLLOWS).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/sg").await;
    // Enrolled after the session was placed: no member of it.
    let mut outsider = device(&app, &seeded, "mach-sg-outsider", FOLLOWS).await;

    send(&mut outsider.ws, want(&sid, "direct")).await;
    assert_eq!(
        refused_why(&mut outsider.ws, "the outsider's not_a_member").await["reason"],
        "not_a_member"
    );
    let mut stale = want(&sid, "direct");
    stale["fence"] = json!(2);
    send(&mut member.ws, stale).await;
    assert_eq!(
        refused_why(&mut member.ws, "the stale fence").await["reason"],
        "stale_fence"
    );
    for (path, why) in [
        ("smoke_signals", "a rung this build cannot name"),
        ("derp", "derp without the member's key"),
        ("relay", "relay with no TURN server configured"),
    ] {
        send(&mut member.ws, want(&sid, path)).await;
        let no = refused_why(&mut member.ws, why).await;
        assert_eq!(no["reason"], "path_unavailable", "{why}: {no}");
    }
    assert!(
        arrives(
            &mut primary.ws,
            "rc:hive.replica.grant",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "no gate let a grant through"
    );

    // A connection that does not carry streams is not heard, though the
    // source is right there to be granted to.
    member.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &member.agent_id).await;
    let mut no_streams = connect(&app, &member.token, &member.machine, HOLDS_COPIES).await;
    wait_agent_online(&app, &seeded, &member.agent_id).await;
    send(&mut no_streams, want(&sid, "direct")).await;
    assert!(
        arrives(
            &mut primary.ws,
            "rc:hive.replica.grant",
            Duration::from_millis(600)
        )
        .await
        .is_none(),
        "no grant from a connection without hive-stream"
    );
    drop(no_streams);
    wait_offline(&app, &seeded, &member.agent_id).await;
    let mut follower = connect(&app, &member.token, &member.machine, FOLLOWS).await;
    wait_agent_online(&app, &seeded, &member.agent_id).await;

    // A primary of an older build carries no stream; one away is offline.
    primary.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;
    let older = connect(&app, &primary.token, &primary.machine, RUNS_HIVE).await;
    wait_agent_online(&app, &seeded, &primary.agent_id).await;
    send(&mut follower, want(&sid, "direct")).await;
    assert_eq!(
        refused_why(&mut follower, "an older source").await["reason"],
        "source_unsupported"
    );
    drop(older);
    wait_offline(&app, &seeded, &primary.agent_id).await;
    send(&mut follower, want(&sid, "direct")).await;
    assert_eq!(
        refused_why(&mut follower, "a source away").await["reason"],
        "source_offline"
    );

    // The rate, after the identity gates: two wants passed it above.
    let mut reasons = Vec::new();
    for _ in 0..12 {
        send(&mut follower, want(&sid, "direct")).await;
        reasons.push(refused_why(&mut follower, "the rate").await["reason"].clone());
    }
    assert_eq!(reasons.last().unwrap(), "rate_limited", "{reasons:?}");
    assert_eq!(
        reasons.iter().filter(|r| *r == "source_offline").count(),
        10,
        "twelve a minute: {reasons:?}"
    );
}

/// A source's refusal reaches the member in the source's word, and a source
/// that never answers is the member's `no_answer`, its grant dropped.
#[tokio::test]
async fn the_sources_refusal_or_silence_reaches_the_member() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivestreamsource").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-ss-primary", SERVES_STREAMS).await;
    let mut member = device(&app, &seeded, "mach-ss-member", FOLLOWS).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/ss").await;

    send(&mut member.ws, want(&sid, "direct")).await;
    let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a grant");
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": grant["grant_id"], "refused": "not_held",
               "detail": "this device lost its store"}),
    )
    .await;
    let no = refused_why(&mut member.ws, "the source's not_held").await;
    assert_eq!(
        (no["reason"].as_str(), no["detail"].as_str()),
        (Some("not_held"), Some("this device lost its store"))
    );

    send(&mut member.ws, want(&sid, "direct")).await;
    let grant = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a second grant");
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    let silent = Duration::from_secs(
        meshharbor_remote_control::hive::stream_limits::GRANT_ACK_TIMEOUT_SECS + 5,
    );
    let no = arrives(&mut member.ws, "rc:hive.replica.refused", silent)
        .await
        .expect("the member hears no_answer");
    assert_eq!(no["reason"], "no_answer");
    let close = read_until(&mut primary.ws, "rc:hive.replica.close")
        .await
        .expect("the source is told to drop it");
    assert_eq!(
        (close["grant_id"].as_str(), close["reason"].as_str()),
        (Some(gid.as_str()), Some("no_answer"))
    );
    // Its answer after all changes nothing.
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("ab"),
               "addrs": ["192.0.2.7:41641"]}),
    )
    .await;
    assert!(
        arrives(
            &mut member.ws,
            "rc:hive.replica.dial",
            Duration::from_millis(400)
        )
        .await
        .is_none()
    );
}

/// A renewal comes up beside the grant the member follows
/// (make-before-break); a third want replaces the oldest, and both sides are
/// told.
#[tokio::test]
async fn a_renewal_keeps_the_grant_it_follows_and_a_third_replaces_the_oldest() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivestreamrenew").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-sn-primary", SERVES_STREAMS).await;
    let mut member = device(&app, &seeded, "mach-sn-member", FOLLOWS).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/sn").await;

    let mut grants = Vec::new();
    for _ in 0..2 {
        send(&mut member.ws, want(&sid, "direct")).await;
        let g = read_until(&mut primary.ws, "rc:hive.replica.grant")
            .await
            .expect("a grant");
        grants.push(g["grant_id"].as_str().unwrap().to_string());
    }
    assert!(
        arrives(
            &mut primary.ws,
            "rc:hive.replica.close",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "the second comes up beside the first"
    );
    send(&mut member.ws, want(&sid, "direct")).await;
    let frames = frames_within(&mut primary.ws, Duration::from_millis(1200)).await;
    assert!(
        frames.iter().any(|f| f["t"] == "rc:hive.replica.grant"),
        "the third is granted: {frames:?}"
    );
    let closed: Vec<&Value> = frames
        .iter()
        .filter(|f| f["t"] == "rc:hive.replica.close")
        .collect();
    assert_eq!(closed.len(), 1, "one replaced: {frames:?}");
    assert_eq!(
        (closed[0]["grant_id"].as_str(), closed[0]["reason"].as_str()),
        (Some(grants[0].as_str()), Some("replaced"))
    );
    let told = read_until(&mut member.ws, "rc:hive.replica.close")
        .await
        .expect("the member is told too");
    assert_eq!(told["grant_id"], grants[0].as_str());
}

/// A member placement lets go stops following at once, and a removed
/// device's streams end with it: the other side is told each time.
#[tokio::test]
async fn a_member_let_go_or_a_device_removed_ends_its_streams() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivestreamend").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-se-primary", SERVES_STREAMS).await;
    set_device(&app, &primary.agent_id, doc! { "tags": ["prod"] }).await;
    let mut member = device(&app, &seeded, "mach-se-member", FOLLOWS).await;
    set_device(&app, &member.agent_id, doc! { "tags": ["prod"] }).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/se").await;

    let ready = |gid: &str| {
        json!({"t": "rc:hive.replica.ready", "grant_id": gid, "cert_fingerprint": hash("ab"),
               "addrs": ["192.0.2.7:41641"]})
    };
    send(&mut member.ws, want(&sid, "direct")).await;
    let g = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a grant");
    let gid = g["grant_id"].as_str().unwrap().to_string();
    send(&mut primary.ws, ready(&gid)).await;
    read_until(&mut member.ws, "rc:hive.replica.dial")
        .await
        .expect("a dial");

    // The member's tag taken off: the restricted session lets it go.
    tag(&app, &tid, &admin, &member.agent_id, &[]).await;
    for (who, ws) in [("source", &mut primary.ws), ("member", &mut member.ws)] {
        let c = read_until(ws, "rc:hive.replica.close")
            .await
            .unwrap_or_else(|| panic!("the {who} is told"));
        assert_eq!(
            (c["grant_id"].as_str(), c["reason"].as_str()),
            (Some(gid.as_str()), Some("member_left")),
            "{who}"
        );
    }

    // A second session, followed by another device carrying the tag; then
    // its source is removed.
    let mut other = device(&app, &seeded, "mach-se-other", FOLLOWS).await;
    set_device(&app, &other.agent_id, doc! { "tags": ["prod"] }).await;
    let sid2 = followed(&app, &tid, &admin, &mut primary, &mut other, "/srv/se2").await;
    send(&mut other.ws, want(&sid2, "direct")).await;
    let g = read_until(&mut primary.ws, "rc:hive.replica.grant")
        .await
        .expect("a grant for the second");
    let gid = g["grant_id"].as_str().unwrap().to_string();
    send(&mut primary.ws, ready(&gid)).await;
    read_until(&mut other.ws, "rc:hive.replica.dial")
        .await
        .expect("a dial");
    let resp = app
        .auth_delete(
            &format!("/api/tenant/{tid}/agent/{}", primary.agent_id),
            &admin,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {}", resp.status());
    let c = read_until(&mut other.ws, "rc:hive.replica.close")
        .await
        .expect("the member is told its source is gone");
    assert_eq!(
        (c["grant_id"].as_str(), c["reason"].as_str()),
        (Some(gid.as_str()), Some("device_removed"))
    );
}

/// With the replicaset's switch off, a want is answered by nothing: no grant
/// to the source, no refusal to the member.
#[tokio::test]
async fn with_the_switch_off_no_stream_is_granted() {
    let on = stream_app().await;
    let seeded = on.seed_tenant("hivestreamoff").await;
    on_pro(&on, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&on, &seeded, "mach-so2-primary", SERVES_STREAMS).await;
    let mut member = device(&on, &seeded, "mach-so2-member", FOLLOWS).await;
    let sid = followed(&on, &tid, &admin, &mut primary, &mut member, "/srv/so2").await;

    let off = switch_off(&on).await;
    primary.ws.close(None).await.unwrap();
    member.ws.close(None).await.unwrap();
    wait_offline(&on, &seeded, &primary.agent_id).await;
    wait_offline(&on, &seeded, &member.agent_id).await;
    let mut source = connect(&off, &primary.token, &primary.machine, SERVES_STREAMS).await;
    let mut follower = connect(&off, &member.token, &member.machine, FOLLOWS).await;
    wait_agent_online(&off, &seeded, &member.agent_id).await;
    send(&mut follower, want(&sid, "direct")).await;
    assert!(
        arrives(
            &mut source,
            "rc:hive.replica.grant",
            Duration::from_millis(800)
        )
        .await
        .is_none(),
        "no grant"
    );
    assert!(
        arrives(
            &mut follower,
            "rc:hive.replica.refused",
            Duration::from_millis(300)
        )
        .await
        .is_none(),
        "no refusal either"
    );
}

// ─── P2d-5 — a replica's read-only view ───────────────────────────────────

/// A primary that runs sessions, carries streams and serves views.
const SERVES_VIEWS: &[&str] = &["exec", "hive", "hive-view", "hive-stream"];
/// A member that holds copies, carries streams and serves views of them.
const COPIES_VIEWS: &[&str] = &["exec", "hive", "hive-view", "hive-replica", "hive-stream"];

/// Open a view of `sid`, have `dev` confirm the grant it is asked, and the
/// grant it was asked and the browser's `ready`. `asked` says why `dev` is
/// the one asked, in the panic when it is not.
async fn view_on(ws: &mut UserWs, dev: &mut Device, sid: &str, asked: &str) -> (Value, Value) {
    user_send(ws, "hive:view.open", json!({"session_id": sid})).await;
    let grant = read_until(&mut dev.ws, "rc:hive.view.grant")
        .await
        .unwrap_or_else(|| panic!("not asked: {asked}"));
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": gid}),
    )
    .await;
    let ready = user_read(ws, "hive:view.ready").await.expect("ready");
    assert_eq!(ready["grant_id"], gid.as_str());
    (grant, ready)
}

/// The views of `tenant` sent to `device` from a copy, as the audit counts
/// them, once they number `want` (within 5 s), or the count then.
async fn copy_views(app: &TestApp, tenant: &str, device: &str, want: u64) -> u64 {
    let filter = doc! {
        "tenant_id": ObjectId::parse_str(tenant).unwrap(),
        "device_id": ObjectId::parse_str(device).unwrap(),
        "action": "view",
        "outcome": "sent",
        "reason": "copy",
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let n = app
            .db
            .collection::<Document>("hive_audit")
            .count_documents(filter.clone())
            .await
            .unwrap();
        if n == want || Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// P2d-5 — the primary serves a view while it can, the starter driving. Once
/// it cannot, a member's copy does, read only for everyone, the starter
/// included, its grant carrying no address; and the audit row says `copy`.
#[tokio::test]
async fn a_view_reads_a_members_copy_once_the_primary_cannot_serve() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivecopy").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&app, &seeded, "mach-cp-primary", SERVES_VIEWS).await;
    let mut member = device(&app, &seeded, "mach-cp-member", COPIES_VIEWS).await;
    let sid = followed(&app, &tid, &admin, &mut primary, &mut member, "/srv/cp").await;
    let mut ws = user_ws(&app, &admin).await;

    let (grant, ready) = view_on(
        &mut ws,
        &mut primary,
        &sid,
        "the primary, while it can serve",
    )
    .await;
    assert_eq!(
        (grant["may_prompt"].as_bool(), ready["may_prompt"].as_bool()),
        (Some(true), Some(true)),
        "the primary while it can serve, the starter driving: {grant}"
    );
    assert!(
        !device_hears(
            &mut member.ws,
            "rc:hive.view.grant",
            Duration::from_millis(300)
        )
        .await,
        "no copy is asked while the primary serves"
    );
    user_send(
        &mut ws,
        "hive:view.close",
        json!({"grant_id": ready["grant_id"]}),
    )
    .await;

    primary.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;
    let (grant, ready) = view_on(
        &mut ws,
        &mut member,
        &sid,
        "the member's copy, once the primary cannot",
    )
    .await;
    assert_eq!(grant["session_id"], sid.as_str());
    assert_eq!(
        (grant["may_prompt"].as_bool(), ready["may_prompt"].as_bool()),
        (Some(false), Some(false)),
        "a copy is read only, the starter's view too: {grant}"
    );
    assert!(
        grant["user_email"].is_null(),
        "a reader's grant carries no address: {grant}"
    );
    assert_eq!(
        copy_views(&app, &tid, &member.agent_id, 1).await,
        1,
        "the audit row says the view was a copy"
    );
}

/// P2d-5 — of the members that hold a copy, the freshest by the tip it last
/// reported serves the view. One whose connection serves no copies (no
/// `hive-replica`) is passed over, and with none left the primary's word
/// refuses.
#[tokio::test]
async fn a_view_goes_to_the_freshest_copy_that_can_serve() {
    let app = stream_app().await;
    let seeded = app.seed_tenant("hivefresh").await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    // Three copies: the primary and both members (decision 2's two would
    // place one).
    let mut policy = a_policy(0);
    policy["replicaset"]["restricted_tags"] = json!([]);
    let (code, p) = put_policy(&app, &tid, &admin, &policy).await;
    assert_eq!(code, 200, "{p}");
    let mut primary = device(&app, &seeded, "mach-fr-primary", SERVES_VIEWS).await;
    let mut behind = device(&app, &seeded, "mach-fr-behind", COPIES_VIEWS).await;
    let mut ahead = device(&app, &seeded, "mach-fr-ahead", COPIES_VIEWS).await;
    let s = started(&app, &tid, &admin, &mut primary, "/srv/fr").await;
    let sid = s["id"].as_str().unwrap().to_string();
    for (m, seq) in [(&mut behind, 3), (&mut ahead, 7)] {
        read_until(&mut m.ws, "rc:hive.replica.join")
            .await
            .expect("the member's join");
        send(
            &mut m.ws,
            json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
        )
        .await;
        wait_member(&app, &tid, &admin, &sid, &m.agent_id, "joined", |v| {
            v["state"] == "joined"
        })
        .await;
        send(
            &mut m.ws,
            json!({"t": "rc:hive.replica.tip", "session_id": sid, "fence": 1, "seq": seq,
                   "hash": hash("ab")}),
        )
        .await;
        wait_member(&app, &tid, &admin, &sid, &m.agent_id, "its tip", |v| {
            v["tip"]["seq"] == seq
        })
        .await;
    }
    primary.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &primary.agent_id).await;

    let mut ws = user_ws(&app, &admin).await;
    let (grant, ready) = view_on(&mut ws, &mut ahead, &sid, "the freshest copy").await;
    assert_eq!(grant["may_prompt"], false, "{grant}");
    assert!(
        !device_hears(
            &mut behind.ws,
            "rc:hive.view.grant",
            Duration::from_millis(300)
        )
        .await,
        "the copy behind is not asked"
    );
    user_send(
        &mut ws,
        "hive:view.close",
        json!({"grant_id": ready["grant_id"]}),
    )
    .await;

    // The copy ahead comes back on a connection that serves no copies.
    ahead.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &ahead.agent_id).await;
    let mut no_copies = connect(&app, &ahead.token, &ahead.machine, VIEWS_HIVE).await;
    wait_agent_online(&app, &seeded, &ahead.agent_id).await;
    let (grant, ready) = view_on(
        &mut ws,
        &mut behind,
        &sid,
        "the copy behind, once the one ahead serves no copies",
    )
    .await;
    assert_eq!(grant["may_prompt"], false, "{grant}");
    assert!(
        !device_hears(
            &mut no_copies,
            "rc:hive.view.grant",
            Duration::from_millis(300)
        )
        .await,
        "a connection that serves no copies is passed over"
    );
    user_send(
        &mut ws,
        "hive:view.close",
        json!({"grant_id": ready["grant_id"]}),
    )
    .await;

    behind.ws.close(None).await.unwrap();
    wait_offline(&app, &seeded, &behind.agent_id).await;
    user_send(&mut ws, "hive:view.open", json!({"session_id": sid})).await;
    let refused = user_read(&mut ws, "hive:view.refused")
        .await
        .expect("with no copy left, the primary's word refuses");
    assert_eq!(
        refused["reason"], "device_offline",
        "with no copy left, the primary's word: {refused}"
    );
}

/// P2d-5 — with the replicaset's switch off, no copy serves a view, whatever
/// its members hold: the primary's word refuses.
#[tokio::test]
async fn with_the_switch_off_no_copy_serves_a_view() {
    let on = stream_app().await;
    let seeded = on.seed_tenant("hivecopyoff").await;
    on_pro(&on, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let mut primary = device(&on, &seeded, "mach-co-primary", SERVES_VIEWS).await;
    let mut member = device(&on, &seeded, "mach-co-member", COPIES_VIEWS).await;
    let sid = followed(&on, &tid, &admin, &mut primary, &mut member, "/srv/co").await;

    let off = switch_off(&on).await;
    primary.ws.close(None).await.unwrap();
    member.ws.close(None).await.unwrap();
    wait_offline(&on, &seeded, &primary.agent_id).await;
    wait_offline(&on, &seeded, &member.agent_id).await;
    let mut copier = connect(&off, &member.token, &member.machine, COPIES_VIEWS).await;
    wait_agent_online(&off, &seeded, &member.agent_id).await;

    let mut ws = user_ws(&off, &admin).await;
    user_send(&mut ws, "hive:view.open", json!({"session_id": sid})).await;
    let refused = user_read(&mut ws, "hive:view.refused")
        .await
        .expect("with the switch off, the primary's word refuses");
    assert_eq!(refused["reason"], "device_offline", "{refused}");
    assert!(
        !device_hears(
            &mut copier,
            "rc:hive.view.grant",
            Duration::from_millis(300)
        )
        .await,
        "no copy is asked"
    );
}

// ─── P2f-4b — an ended adopted session made a managed one ───────────────────

/// A device that adopts terminal sessions and makes an ended one managed.
const MANAGES: &[&str] = &["hive", "hive-view", "hive-adopt", "hive-manage"];

/// The terminal session every test here adopts.
const TERMINAL: &str = "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f71";

/// `POST …/session/{sid}/manage`, as `token`.
async fn post_manage(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    folder: Option<&str>,
) -> (u16, Value) {
    let body = match folder {
        Some(f) => json!({ "folder": f }),
        None => json!({}),
    };
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/manage"),
            token,
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// A terminal session adopted on `dev` for `email`'s person, whose terminal
/// then ended there: what the device says when it does.
async fn ended_terminal(
    app: &TestApp,
    tid: &str,
    token: &str,
    dev: &mut Device,
    email: &str,
) -> String {
    let ack = adopt(&mut dev.ws, "m1", TERMINAL, &[email]).await;
    assert!(ack.get("refused").is_none(), "{ack}");
    let sid = ack["session_id"].as_str().unwrap().to_string();
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "ended",
               "detail": "the terminal session ended (exit)"}),
    )
    .await;
    wait_status(app, tid, token, &sid, "ended").await;
    sid
}

/// The asking, `folder` as typed if any, answered by the device with
/// `answer` (merged into its `rc:hive.start_ack`): the route's answer, and
/// the start the device got.
async fn managed(
    app: &TestApp,
    dev: &mut Device,
    tid: &str,
    token: &str,
    sid: &str,
    folder: Option<&str>,
    answer: Value,
) -> (Value, Value) {
    let caller = post_manage(app, tid, token, sid, folder);
    let device = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives the start");
        let mut ack = json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                             "fence": frame["fence"]});
        for (k, v) in answer.as_object().unwrap() {
            ack[k] = v.clone();
        }
        send(&mut dev.ws, ack).await;
        frame
    };
    let ((code, body), frame) = tokio::join!(caller, device);
    assert_eq!(code, 200, "{body}");
    (body, frame)
}

/// `manage` rows of the audit for `sid`, oldest first: outcome and reason.
async fn manage_audit(app: &TestApp, sid: &str) -> Vec<(String, String)> {
    let mut rows = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "session_id": ObjectId::parse_str(sid).unwrap(), "action": "manage" })
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(d) = rows.next().await {
        let d = d.unwrap();
        out.push((
            d.get_str("outcome").unwrap().to_string(),
            d.get_str("reason").unwrap_or("").to_string(),
        ));
    }
    out
}

/// FR-90 P2f-4b — decision 11's other half on the server. The owner makes
/// their ended adopted session a managed one: the SAME record, at its fence,
/// on the device that adopted it. Its start says so, and goes there. It is a
/// started session now, placed by the policy; the room says so, and the
/// audit records it. Asked again, it is a managed one already.
#[tokio::test]
async fn an_ended_terminal_session_is_made_a_managed_one_on_its_own_device() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivemanage").await;
    let admin = &seeded.admin;
    let tid = seeded.tenant_id.clone();
    let mut dev = device(&app, &seeded, "manager", MANAGES).await;
    let sid = ended_terminal(&app, &tid, &admin.access_token, &mut dev, &admin.email).await;
    let before = stored(&app, &sid).await;
    let ended_at = before.get_datetime("ended_at").unwrap().to_owned();

    let (body, frame) = managed(
        &app,
        &mut dev,
        &tid,
        &admin.access_token,
        &sid,
        None,
        json!({"account": "alice"}),
    )
    .await;
    assert_eq!(body["outcome"], "accepted", "{body}");
    assert_eq!(
        body["session"]["id"],
        sid.as_str(),
        "the same record: {body}"
    );
    assert_eq!(body["session"]["origin"], "started", "{body}");
    assert_eq!(
        (
            frame["session_id"].clone(),
            frame["harness_session"].clone(),
            frame["fence"].clone(),
            frame["from_terminal"].clone(),
            frame["resume"].clone(),
            frame["folder"].clone(),
        ),
        (
            json!(sid),
            json!(TERMINAL),
            json!(1),
            json!(true),
            json!(false),
            json!("/home/alice/client-x"),
        ),
        "the start makes the terminal's own conversation a managed one: {frame}"
    );
    assert!(frame.get("fork_of").is_none(), "{frame}");

    let after = stored(&app, &sid).await;
    assert!(
        after.get("origin").is_none(),
        "a started session stores no origin: {after}"
    );
    assert!(after.get_datetime("accepted_at").is_ok(), "{after}");
    assert!(after.get("end_reason").is_none(), "{after}");
    let from = after.get_document("from_terminal").expect("where it began");
    assert_eq!(
        from.get_object_id("device_id").unwrap().to_hex(),
        dev.agent_id
    );
    assert_eq!(from.get_object_id("by").unwrap().to_hex(), admin.id);
    assert_eq!(from.get_datetime("ended_at").unwrap(), &ended_at);
    assert_eq!(from.get_str("end_reason").unwrap(), "exited");
    assert!(from.get("refused").is_none(), "{from}");
    assert!(
        after.get_document("replicaset").is_ok(),
        "it follows the policy now: {after}"
    );
    assert_eq!(
        notes_in(
            &app,
            &tid,
            &admin.access_token,
            &sid,
            "is making this terminal session"
        )
        .await
        .len(),
        1,
        "the room says it was asked"
    );
    assert_eq!(
        notes_in(
            &app,
            &tid,
            &admin.access_token,
            &sid,
            "Made a managed session on"
        )
        .await
        .len(),
        1,
        "and that it was made"
    );
    assert_eq!(
        manage_audit(&app, &sid).await,
        [("sent".to_string(), String::new())]
    );

    // It runs as any session does, and is a managed one already.
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 1, "state": "idle"}),
    )
    .await;
    wait_status(&app, &tid, &admin.access_token, &sid, "idle").await;
    let (code, again) = post_manage(&app, &tid, &admin.access_token, &sid, None).await;
    assert_eq!(
        (code, again["reason"].as_str()),
        (200, Some("not_adopted")),
        "{again}"
    );
}

/// FR-90 P2f-4b — a start the device refused leaves the adopted session it
/// was: its own end and folder back, the device's word kept for whoever
/// asked. It never becomes a refused managed session that nothing could
/// start again. Asked again, it is made one, where its terminal ran.
#[tokio::test]
async fn a_refused_start_leaves_the_adopted_session_it_was() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivemanagerefused").await;
    let admin = &seeded.admin;
    let tid = seeded.tenant_id.clone();
    let mut dev = device(&app, &seeded, "manager", MANAGES).await;
    let sid = ended_terminal(&app, &tid, &admin.access_token, &mut dev, &admin.email).await;

    // Asked to run it in another folder.
    let began = Instant::now();
    let (body, frame) = managed(
        &app,
        &mut dev,
        &tid,
        &admin.access_token,
        &sid,
        Some("/home/alice/client-y"),
        json!({"refused": "launch_failed",
               "detail": "this device could not put its terminal's history in place"}),
    )
    .await;
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("launch_failed")),
        "{body}"
    );
    assert_eq!(frame["folder"], "/home/alice/client-y", "{frame}");
    assert!(
        began.elapsed() < Duration::from_secs(hive_limits::START_ACK_TIMEOUT_SECS / 2),
        "the refusal wakes whoever asked, not the start's bound: {:?}",
        began.elapsed()
    );
    assert_eq!(body["session"]["origin"], "adopted", "{body}");
    let row = stored(&app, &sid).await;
    assert_eq!(
        (
            row.get_str("origin").unwrap(),
            row.get_str("status").unwrap(),
            row.get_str("end_reason").unwrap(),
        ),
        ("adopted", "ended", "exited"),
        "the adopted session it was: {row}"
    );
    assert!(row.get_datetime("ended_at").is_ok(), "{row}");
    assert!(
        row.get("replicaset").is_none(),
        "placed nowhere again: {row}"
    );
    assert_eq!(
        row.get_document("location")
            .ok()
            .and_then(|l| l.get_str("folder").ok()),
        Some("/home/alice/client-x"),
        "its own folder back: {row}"
    );
    let from = row.get_document("from_terminal").unwrap();
    assert_eq!(from.get_str("refused").unwrap(), "launch_failed");
    assert!(
        from.get_str("refused_detail")
            .unwrap()
            .contains("history in place"),
        "{from}"
    );
    assert_eq!(
        notes_in(
            &app,
            &tid,
            &admin.access_token,
            &sid,
            "did not make this terminal session a managed one"
        )
        .await
        .len(),
        1,
        "the room says why"
    );
    assert_eq!(
        manage_audit(&app, &sid).await,
        [
            ("sent".to_string(), String::new()),
            ("refused".to_string(), "launch_failed".to_string())
        ]
    );

    // Asked again, naming no folder: it is made one, where its terminal ran.
    let (body, frame) = managed(
        &app,
        &mut dev,
        &tid,
        &admin.access_token,
        &sid,
        None,
        json!({"account": "alice"}),
    )
    .await;
    assert_eq!(body["outcome"], "accepted", "{body}");
    assert_eq!(
        (frame["from_terminal"].clone(), frame["folder"].clone()),
        (json!(true), json!("/home/alice/client-x")),
        "{frame}"
    );
    let row = stored(&app, &sid).await;
    assert!(
        row.get_document("from_terminal")
            .unwrap()
            .get("refused")
            .is_none(),
        "this asking's own record: {row}"
    );
}

/// FR-90 P2f-4b — the server's gates. Only the owner learns the session
/// exists; only an ended terminal session, whose mirroring was never stopped
/// from MeshHarbor, is made a managed one; only on a device that is here and
/// makes one; and only with `HIVE_RUN`. Nothing reaches the device on any of
/// them.
#[tokio::test]
async fn only_an_ended_terminal_session_is_made_managed_and_by_its_owner() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivemanagegates").await;
    let (admin, member) = (&seeded.admin, &seeded.member);
    let tid = seeded.tenant_id.clone();
    let mut dev = device(&app, &seeded, "manager", MANAGES).await;

    // A live terminal session: not yet.
    let ack = adopt(&mut dev.ws, "g1", TERMINAL, &[&admin.email]).await;
    let live = ack["session_id"].as_str().unwrap().to_string();
    let (code, body) = post_manage(&app, &tid, &admin.access_token, &live, None).await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("not_ended")),
        "{body}"
    );
    // Someone else's: no such session.
    let (code, _) = post_manage(&app, &tid, &member.access_token, &live, None).await;
    assert_eq!(code, 404, "nobody else learns it exists");
    // Stopped from MeshHarbor: its terminal went on after the stop.
    let (code, _) = stop(&app, &tid, &admin.access_token, &live).await;
    assert_eq!(code, 200);
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": live, "fence": 1, "state": "ended",
               "detail": "mirroring stopped; the terminal session goes on"}),
    )
    .await;
    wait_status(&app, &tid, &admin.access_token, &live, "ended").await;
    let (code, body) = post_manage(&app, &tid, &admin.access_token, &live, None).await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("stopped")),
        "{body}"
    );

    // An ended one, on a device that does not make one: an older build.
    let mut old = device(&app, &seeded, "older", &["hive", "hive-view", "hive-adopt"]).await;
    let ack = adopt(
        &mut old.ws,
        "g2",
        "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f72",
        &[&admin.email],
    )
    .await;
    let on_old = ack["session_id"].as_str().unwrap().to_string();
    send(
        &mut old.ws,
        json!({"t": "rc:hive.state", "session_id": on_old, "fence": 1, "state": "ended",
               "detail": "the terminal session ended (exit)"}),
    )
    .await;
    wait_status(&app, &tid, &admin.access_token, &on_old, "ended").await;
    let (code, body) = post_manage(&app, &tid, &admin.access_token, &on_old, None).await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("device_unsupported")),
        "{body}"
    );
    assert!(
        !device_hears(&mut old.ws, "rc:hive.start", Duration::from_millis(300)).await,
        "nothing reached it"
    );
    // Offline.
    drop(old.ws);
    wait_offline(&app, &seeded, &old.agent_id).await;
    let (code, body) = post_manage(&app, &tid, &admin.access_token, &on_old, None).await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("device_offline")),
        "{body}"
    );

    // Without HIVE_RUN: a plain member's own ended terminal session.
    let ack = adopt(
        &mut dev.ws,
        "g3",
        "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f73",
        &[&member.email],
    )
    .await;
    let members = ack["session_id"].as_str().unwrap().to_string();
    send(
        &mut dev.ws,
        json!({"t": "rc:hive.state", "session_id": members, "fence": 1, "state": "ended",
               "detail": "the terminal session ended (exit)"}),
    )
    .await;
    wait_status(&app, &tid, &member.access_token, &members, "ended").await;
    let (code, body) = post_manage(&app, &tid, &member.access_token, &members, None).await;
    assert_eq!(
        (code, body["reason"].as_str()),
        (200, Some("no_permission")),
        "{body}"
    );
    assert!(
        !device_hears(&mut dev.ws, "rc:hive.start", Duration::from_millis(300)).await,
        "nothing reached the device"
    );
    let row = stored(&app, &members).await;
    assert_eq!(
        row.get_str("origin").unwrap(),
        "adopted",
        "untouched: {row}"
    );
}

/// FR-90 P2f-4b — the server is off, and so is the route: P2's switch.
#[tokio::test]
async fn making_a_terminal_session_managed_is_off_with_the_replicaset() {
    let app = hive_app_polling().await;
    let seeded = app.seed_tenant("hivemanageoff").await;
    let admin = &seeded.admin;
    let tid = seeded.tenant_id.clone();
    let mut dev = device(&app, &seeded, "manager", MANAGES).await;
    let sid = ended_terminal(&app, &tid, &admin.access_token, &mut dev, &admin.email).await;
    let (code, _) = post_manage(&app, &tid, &admin.access_token, &sid, None).await;
    assert_eq!(code, 404);
}

/// FR-90 P2f-4b — a start the device never answered is sent again on its
/// next connection, still a terminal's; past the start's redelivery window,
/// counted from the asking and not from the adoption, it is the adopted
/// session it was, never a lost one.
#[tokio::test]
async fn an_unanswered_start_is_sent_again_and_past_its_window_restored() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivemanagelate").await;
    let admin = &seeded.admin;
    let tid = seeded.tenant_id.clone();
    let mut dev = device(&app, &seeded, "manager", MANAGES).await;
    let sid = ended_terminal(&app, &tid, &admin.access_token, &mut dev, &admin.email).await;
    // The adoption was long ago: only the asking's own time counts.
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "created_at": bson::DateTime::from_millis(0) } },
        )
        .await
        .unwrap();

    // The device stays silent: pending.
    let (code, body) = post_manage(&app, &tid, &admin.access_token, &sid, None).await;
    assert_eq!(
        (code, body["outcome"].as_str()),
        (200, Some("pending")),
        "{body}"
    );
    let first = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
    assert_eq!(first["from_terminal"], true);

    // Its next connection: the start again, still a terminal's.
    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let mut ws = connect(&app, &dev.token, &dev.machine, MANAGES).await;
    let again = read_until(&mut ws, "rc:hive.start")
        .await
        .expect("the start again");
    assert_eq!(
        (again["session_id"].as_str(), again["from_terminal"].clone()),
        (Some(sid.as_str()), json!(true)),
        "{again}"
    );
    assert_eq!(
        stored(&app, &sid).await.get_str("status").unwrap(),
        "starting"
    );

    // Past the window, counted from the asking: the adopted session it was.
    drop(ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let late = bson::DateTime::from_millis(
        bson::DateTime::now().timestamp_millis()
            - (hive_limits::START_REDELIVERY_WINDOW_SECS + 60) * 1000,
    );
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "from_terminal.at": late } },
        )
        .await
        .unwrap();
    let mut ws = connect(&app, &dev.token, &dev.machine, MANAGES).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let row = loop {
        let row = stored(&app, &sid).await;
        if row.get_str("status").unwrap() != "starting" {
            break row;
        }
        assert!(Instant::now() < deadline, "never restored: {row}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // Read whole, so a record made `lost` fails here, by name.
    assert_eq!(
        (
            row.get_str("origin").ok(),
            row.get_str("status").ok(),
            row.get_document("from_terminal")
                .ok()
                .and_then(|f| f.get_str("refused").ok())
        ),
        (Some("adopted"), Some("ended"), Some("never_answered")),
        "never lost: {row}"
    );
    assert!(
        !device_hears(&mut ws, "rc:hive.start", Duration::from_millis(300)).await,
        "and not sent again"
    );
}

/// FR-90 P2f-4b — the device comes back as a build that does not make one:
/// the start is not sent to it, and the session is the adopted one it was.
#[tokio::test]
async fn a_device_back_as_an_older_build_leaves_the_adopted_session_it_was() {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant("hivemanageolder").await;
    let admin = &seeded.admin;
    let tid = seeded.tenant_id.clone();
    let mut dev = device(&app, &seeded, "manager", MANAGES).await;
    let sid = ended_terminal(&app, &tid, &admin.access_token, &mut dev, &admin.email).await;
    let (code, body) = post_manage(&app, &tid, &admin.access_token, &sid, None).await;
    assert_eq!(
        (code, body["outcome"].as_str()),
        (200, Some("pending")),
        "{body}"
    );
    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
    let mut ws = connect(
        &app,
        &dev.token,
        &dev.machine,
        &["hive", "hive-view", "hive-adopt"],
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let row = loop {
        let row = stored(&app, &sid).await;
        if row.get_str("status").unwrap() != "starting" {
            break row;
        }
        assert!(Instant::now() < deadline, "never restored: {row}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(
        (
            row.get_str("origin").unwrap(),
            row.get_document("from_terminal")
                .unwrap()
                .get_str("refused")
                .unwrap()
        ),
        ("adopted", "device_unsupported"),
        "{row}"
    );
    assert!(
        !device_hears(&mut ws, "rc:hive.start", Duration::from_millis(300)).await,
        "nothing a build before it would start afresh"
    );
}

// ─── P2f-5 — the path map across several moves ─────────────────────────────

/// FR-90 P2f-5 — `m`'s session moved from `primary`, at `fence`, to `target`
/// in `folder`: the target ready, the primary drained at `(seq, fill)` and the
/// target's copy there. What the target hears: its join, the move, the start.
#[allow(clippy::too_many_arguments)]
async fn moved_into(
    app: &TestApp,
    (tid, admin, sid): (&str, &str, &str),
    primary: &mut Device,
    target: &mut Device,
    fence: u64,
    folder: &str,
    (seq, fill): (u64, &str),
) -> Vec<Value> {
    let to = target.agent_id.clone();
    let caller = post_promote(app, tid, admin, sid, &to, Some(folder));
    let ready = async {
        let prep = read_until(&mut target.ws, "rc:hive.prepare")
            .await
            .expect("the target is asked to prepare");
        send(
            &mut target.ws,
            json!({"t": "rc:hive.prepare_ack", "session_id": sid, "fence": prep["fence"],
                   "account": "dev"}),
        )
        .await;
    };
    let ((code, body), ()) = tokio::join!(caller, ready);
    assert_eq!(
        (code, body["outcome"].as_str()),
        (200, Some("promoting")),
        "{body}"
    );
    read_until(&mut primary.ws, "rc:hive.drain")
        .await
        .expect("the primary is told to drain");
    send(
        &mut primary.ws,
        json!({"t": "rc:hive.drained", "session_id": sid, "fence": fence, "seq": seq,
               "hash": hash(fill)}),
    )
    .await;
    send(&mut target.ws, tip_at(sid, fence, seq, fill)).await;
    frames_until(
        &mut target.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await
}

/// The record's path map: each move's fence, and the folders before and
/// after it.
fn path_of(s: &Document) -> Vec<(i64, String, String)> {
    let folder = |e: &Document, end: &str| {
        e.get_document(end)
            .ok()
            .and_then(|p| p.get_str("folder").ok())
            .unwrap_or("")
            .to_string()
    };
    s.get_array("path_map")
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_document())
                .map(|e| {
                    (
                        e.get_i64("fence").unwrap_or(0),
                        folder(e, "from"),
                        folder(e, "to"),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// FR-90 P2f-5 — each lease move goes into the record's path map, and each
/// moved start names every place the session ran before, oldest first, one
/// per folder: its old turns keep the paths they had there, and the note
/// says where they live now. A move back takes out the entry of the move it
/// undoes, which started no run.
#[tokio::test]
async fn each_moved_start_names_every_folder_the_session_ran_in_before() {
    let app = promote_app().await;
    let mut m = promotable(&app, "pathmap", 0, PROMOTES).await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    let ids = (tid.as_str(), admin.as_str(), sid.as_str());
    let a_id = m.a.agent_id.clone();
    let path = |p: &[(i64, &str, &str)]| -> Vec<(i64, String, String)> {
        p.iter()
            .map(|(f, a, b)| (*f, a.to_string(), b.to_string()))
            .collect()
    };

    // A to B, into B's own folder.
    let to_b = moved_into(
        &app,
        ids,
        &mut m.a,
        &mut m.b,
        1,
        "/srv/pathmap-b",
        (5, "ab"),
    )
    .await;
    let a_name = move_of(&to_b)["from_device_name"].clone();
    assert_eq!(
        move_of(&to_b)["earlier"],
        json!([{"device_name": a_name, "folder": "/srv/pathmap"}]),
        "{to_b:?}"
    );
    frames_until(&mut m.a.ws, &["rc:hive.demote", "rc:hive.replica.join"]).await;
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 2}),
    )
    .await;
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 2, "account": "dev"}),
    )
    .await;
    send(
        &mut m.b.ws,
        json!({"t": "rc:hive.state", "session_id": sid, "fence": 2, "state": "idle"}),
    )
    .await;
    wait_stored(&app, &sid, "running on B, A a member again", |s| {
        !s.contains_key("promotion")
            && s.get_str("status") == Ok("idle")
            && stored_member(s, &a_id).1 == "joined"
    })
    .await;

    // B to A, into a third folder: both earlier folders, oldest first.
    let to_a = moved_into(
        &app,
        ids,
        &mut m.b,
        &mut m.a,
        2,
        "/srv/pathmap-c",
        (7, "cd"),
    )
    .await;
    let b_name = move_of(&to_a)["from_device_name"].clone();
    assert_eq!(
        move_of(&to_a)["earlier"],
        json!([
            {"device_name": a_name, "folder": "/srv/pathmap"},
            {"device_name": b_name, "folder": "/srv/pathmap-b"},
        ]),
        "every folder its earlier turns worked in"
    );
    assert_eq!(
        path_of(&stored(&app, &sid).await),
        path(&[
            (2, "/srv/pathmap", "/srv/pathmap-b"),
            (3, "/srv/pathmap-b", "/srv/pathmap-c"),
        ]),
        "each move in the path map"
    );

    // A refuses its moved start: the lease moves back to B, and the map is as
    // it was before the move it undid.
    send(
        &mut m.a.ws,
        json!({"t": "rc:hive.start_ack", "session_id": sid, "fence": 3,
               "refused": "launch_failed"}),
    )
    .await;
    let back = frames_until(
        &mut m.b.ws,
        &["rc:hive.replica.join", "rc:hive.move", "rc:hive.start"],
    )
    .await;
    assert_eq!(
        path_of(&stored(&app, &sid).await),
        path(&[(2, "/srv/pathmap", "/srv/pathmap-b")]),
        "a move back takes its move's entry out"
    );
    assert_eq!(
        move_of(&back)["earlier"],
        json!([{"device_name": a_name, "folder": "/srv/pathmap"}]),
        "the move undone left no earlier place"
    );
}

// ─── P2g-2 — a purge, the server's half ─────────────────────────────────────

/// What a build that purges advertises, holding copies.
const PURGES: &[&str] = &[
    "exec",
    "hive",
    "hive-replica",
    "hive-stream",
    "hive-lease",
    "hive-purge",
    "hive-purge-all",
];
/// A build of P2g-1 to P2g-3d (`agent-v0.4.136`): it purges a session, and
/// cannot decode a removal's purge of everything.
const PURGES_A_SESSION: &[&str] = &[
    "exec",
    "hive",
    "hive-replica",
    "hive-stream",
    "hive-lease",
    "hive-purge",
];
/// A build before P2g-1: it holds copies, and does not know a purge.
const KEEPS: &[&str] = &["exec", "hive", "hive-replica", "hive-stream", "hive-lease"];

/// A session running on `a` (which purges), whose members took their copies.
struct Purgeable {
    tid: String,
    admin: String,
    admin_id: String,
    sid: String,
    a: Device,
    members: Vec<Device>,
    seeded: SeededTenant,
}

/// [`Purgeable`], with a member per entry of `member_caps`, each advertising
/// those caps.
async fn purgeable(app: &TestApp, tag: &str, member_caps: &[&[&str]]) -> Purgeable {
    let seeded = app.seed_tenant(tag).await;
    on_pro(app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let min = 1 + u32::try_from(member_caps.len()).unwrap();
    let (code, p) = put_policy(app, &tid, &admin, &policy_min(min, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut a = device(app, &seeded, &format!("mach-{tag}-a"), PURGES).await;
    let mut members = Vec::new();
    for (i, caps) in member_caps.iter().enumerate() {
        members.push(device(app, &seeded, &format!("mach-{tag}-m{i}"), caps).await);
    }
    let (s, frame) = started_frame(app, &tid, &admin, &mut a, &format!("/srv/{tag}")).await;
    // Absent when false, as every start before P2c-3a.
    assert_eq!(
        frame["replicated"].as_bool().unwrap_or(false),
        !members.is_empty(),
        "{frame}"
    );
    let sid = s["id"].as_str().unwrap().to_string();
    for m in &mut members {
        read_until(&mut m.ws, "rc:hive.replica.join")
            .await
            .expect("the member's join");
        send(
            &mut m.ws,
            json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
        )
        .await;
        let id = m.agent_id.clone();
        wait_member(app, &tid, &admin, &sid, &id, "joined", |m| {
            m["state"] == "joined"
        })
        .await;
    }
    Purgeable {
        tid,
        admin,
        admin_id: seeded.admin.id.clone(),
        sid,
        a,
        members,
        seeded,
    }
}

/// `DELETE …/hive/session/{sid}` as `token`.
async fn delete_session(app: &TestApp, tid: &str, token: &str, sid: &str) -> (u16, Value) {
    let resp = app
        .auth_delete(&format!("/api/tenant/{tid}/hive/session/{sid}"), token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// `GET …/hive/session/{sid}/purge` as `token`.
async fn read_purge(app: &TestApp, tid: &str, token: &str, sid: &str) -> (u16, Value) {
    let resp = app
        .auth_get(
            &format!("/api/tenant/{tid}/hive/session/{sid}/purge"),
            token,
        )
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Poll the owner's view of the purge of `sid` until `pred` holds.
async fn wait_purge(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    what: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (code, v) = read_purge(app, tid, token, sid).await;
        assert_eq!(code, 200, "{v}");
        if pred(&v) {
            return v;
        }
        assert!(Instant::now() < deadline, "{what}: {v}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The entry of `device` in a purge's view.
fn entry_of(purge: &Value, device: &str) -> Value {
    purge["devices"]
        .as_array()
        .and_then(|d| d.iter().find(|e| e["device_id"] == device).cloned())
        .unwrap_or(Value::Null)
}

/// The stored session, when there is one.
async fn record_of(app: &TestApp, sid: &str) -> Option<Document> {
    app.db
        .collection::<Document>("agent_sessions")
        .find_one(doc! { "_id": ObjectId::parse_str(sid).unwrap() })
        .await
        .unwrap()
}

/// Poll until the stored session is gone.
async fn wait_record_gone(app: &TestApp, sid: &str, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while record_of(app, sid).await.is_some() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Answer a purge, as a device.
async fn purge_ack(ws: &mut AgentWs, purge: &str, sid: &str, store: &str, account: &str) {
    send(
        ws,
        json!({"t": "rc:hive.purge_ack", "purge_id": purge, "session_id": sid,
               "store": store, "account": account}),
    )
    .await;
}

/// The first `rc:hive.*` frame a device hears.
async fn first_hive_frame(ws: &mut AgentWs) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && v["t"].as_str().is_some_and(|t| t.starts_with("rc:hive."))
                {
                    return v;
                }
            }
            Ok(Some(Ok(_))) | Err(_) => continue,
            Ok(Some(Err(_))) | Ok(None) => break,
        }
    }
    panic!("no rc:hive.* frame arrived");
}

/// The server's `purge` decisions about `sid`, oldest first: (outcome, reason).
async fn purge_audit(app: &TestApp, sid: &str) -> Vec<(String, Option<String>)> {
    let mut cur = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "session_id": ObjectId::parse_str(sid).unwrap(), "action": "purge" })
        .sort(doc! { "at": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(row) = cur.next().await {
        let row = row.unwrap();
        out.push((
            row.get_str("outcome").unwrap().to_string(),
            row.get_str("reason").ok().map(str::to_string),
        ));
    }
    out
}

/// FR-90 P2g-2 — AC11: a purge issued while a member is offline is applied
/// and acknowledged when that member connects. The primary, online, is told
/// at once; the session and its room are gone for its owner the moment the
/// purge is issued; the member, back, hears its purge before anything else;
/// once both have answered the purge is complete, its tombstone gone, and
/// asking again answers with that purge.
#[tokio::test]
async fn a_purge_issued_while_a_member_is_offline_is_applied_when_it_connects() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-ac11", &[PURGES]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let (_, view) = get_session(&app, &tid, &admin, &sid).await;
    let room = view["room_id"].as_str().expect("its room").to_string();
    let mut b = p.members.remove(0);
    drop(b.ws);
    wait_offline(&app, &p.seeded, &b.agent_id).await;

    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["outcome"], "purging", "{body}");
    let purge = body["purge"]["id"].as_str().unwrap().to_string();
    assert_eq!(body["purge"]["session_id"], sid, "{body}");
    assert_eq!(entry_of(&body["purge"], &p.a.agent_id)["state"], "pending");
    assert_eq!(entry_of(&body["purge"], &b.agent_id)["state"], "pending");

    // The primary, online, is told at once.
    let told = read_until(&mut p.a.ws, "rc:hive.purge")
        .await
        .expect("the primary's purge");
    assert_eq!(told["purge_id"], purge, "{told}");
    assert_eq!(told["session_id"], sid, "{told}");
    assert!(
        told.get("leaving").is_none(),
        "a whole session's purge carries no leaving word (P2k-3): {told}"
    );

    // Gone for its owner at once: the session, its listing, its room.
    assert_eq!(get_session(&app, &tid, &admin, &sid).await.0, 404);
    let list: Value = app
        .auth_get(&format!("/api/tenant/{tid}/hive/session"), &admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == sid),
        "its listing: {list}"
    );
    let (code, _) = room_messages(&app, &tid, &admin, &room).await;
    assert_eq!(code, 404, "the session's room went with it");
    let tomb = record_of(&app, &sid).await.expect("the tombstone");
    assert_eq!(
        tomb.get_document("purged")
            .unwrap()
            .get_object_id("purge_id")
            .unwrap()
            .to_hex(),
        purge,
        "{tomb}"
    );
    assert_eq!(tomb.get_str("status").unwrap(), "ended");
    assert_eq!(tomb.get_str("end_reason").unwrap(), "purged");
    assert_eq!(tomb.get_str("title").unwrap(), "", "its name of the work");
    assert!(!tomb.contains_key("room_id"), "{tomb}");

    // The primary answers: its part is done, and the purge waits on the
    // member.
    purge_ack(&mut p.a.ws, &purge, &sid, "done", "done").await;
    let v = wait_purge(&app, &tid, &admin, &sid, "the primary's part", |v| {
        entry_of(v, &p.a.agent_id)["state"] == "done"
    })
    .await;
    assert!(v.get("done_at").is_none(), "the member is pending: {v}");
    assert_eq!(entry_of(&v, &b.agent_id)["state"], "pending", "{v}");
    assert!(record_of(&app, &sid).await.is_some(), "the tombstone waits");
    // A replay of the primary's answer lands on nothing: an answer is its
    // socket's own device's, never the member's still pending.
    purge_ack(&mut p.a.ws, &purge, &sid, "done", "done").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, v) = read_purge(&app, &tid, &admin, &sid).await;
    assert_eq!(
        entry_of(&v, &b.agent_id)["state"],
        "pending",
        "the primary's replay is not the member's answer: {v}"
    );

    // The member connects: its purge is the first thing it hears of Hive.
    b.ws = connect(&app, &b.token, &b.machine, PURGES).await;
    let first = first_hive_frame(&mut b.ws).await;
    assert_eq!(first["t"], "rc:hive.purge", "{first}");
    assert_eq!(first["purge_id"], purge, "{first}");
    purge_ack(&mut b.ws, &purge, &sid, "done", "not_there").await;
    let v = wait_purge(&app, &tid, &admin, &sid, "complete", |v| {
        v["done_at"].is_string()
    })
    .await;
    assert_eq!(entry_of(&v, &b.agent_id)["account"], "not_there", "{v}");
    wait_record_gone(&app, &sid, "the tombstone goes with the purge's completion").await;
    assert_eq!(
        purge_audit(&app, &sid).await,
        vec![("issued".to_string(), None), ("complete".to_string(), None)]
    );

    // Asking again answers with that purge.
    let (code, again) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{again}");
    assert_eq!(
        (again["outcome"].as_str(), again["purge"]["id"].as_str()),
        (Some("purged"), Some(purge.as_str())),
        "{again}"
    );
}

/// FR-90 P2g-2 — a part that failed stays pending, in the device's own
/// words, and the purge is sent again at the device's next connection; once
/// it answers both parts closed, the purge completes.
#[tokio::test]
async fn a_part_that_failed_stays_pending_and_is_sent_again() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-again", &[]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    let purge = body["purge"]["id"].as_str().unwrap().to_string();
    read_until(&mut p.a.ws, "rc:hive.purge")
        .await
        .expect("the device's purge");
    send(
        &mut p.a.ws,
        json!({"t": "rc:hive.purge_ack", "purge_id": purge, "session_id": sid,
               "store": "done", "account": "failed",
               "detail": "nobody is signed in\n\u{1b}[2J at the device"}),
    )
    .await;
    let v = wait_purge(&app, &tid, &admin, &sid, "the failed part", |v| {
        entry_of(v, &p.a.agent_id)["account"] == "failed"
    })
    .await;
    let e = entry_of(&v, &p.a.agent_id);
    assert_eq!(e["state"], "pending", "{v}");
    assert_eq!(e["store"], "done", "{v}");
    assert_eq!(
        e["detail"], "nobody is signed in  [2J at the device",
        "the device's words, on one line: {v}"
    );
    assert!(v.get("done_at").is_none(), "{v}");

    // Its next connection hears the purge again.
    drop(p.a.ws);
    wait_offline(&app, &p.seeded, &p.a.agent_id).await;
    p.a.ws = connect(&app, &p.a.token, &p.a.machine, PURGES).await;
    let again = read_until(&mut p.a.ws, "rc:hive.purge")
        .await
        .expect("the purge again");
    assert_eq!(again["purge_id"], purge, "{again}");
    purge_ack(&mut p.a.ws, &purge, &sid, "not_there", "done").await;
    wait_purge(&app, &tid, &admin, &sid, "complete", |v| {
        v["done_at"].is_string()
    })
    .await;
    wait_record_gone(&app, &sid, "the tombstone goes").await;
}

/// FR-90 P2g-2 — a member of a build before P2g-1 is never sent a frame it
/// does not know: its part waits, its entry saying why, and its first
/// connection as a build that purges hears the purge. A removed device can
/// never be asked: its part is closed at once.
#[tokio::test]
async fn a_build_before_purges_waits_and_a_removed_device_is_closed() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-old", &[KEEPS, PURGES]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let gone = p.members.pop().unwrap();
    let mut old = p.members.pop().unwrap();
    let resp = app
        .auth_delete(
            &format!("/api/tenant/{tid}/agent/{}", gone.agent_id),
            &admin,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {:?}", resp.status());

    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    let purge = body["purge"]["id"].as_str().unwrap().to_string();
    let e = entry_of(&body["purge"], &gone.agent_id);
    assert_eq!(
        (e["state"].as_str(), e["closed"].as_str()),
        (Some("closed"), Some("device_removed")),
        "{body}"
    );
    let e = entry_of(&body["purge"], &old.agent_id);
    assert_eq!(
        (e["state"].as_str(), e["detail"].as_str()),
        (Some("pending"), Some("device_unsupported")),
        "{body}"
    );
    assert!(
        !device_hears(&mut old.ws, "rc:hive.purge", Duration::from_millis(500)).await,
        "a build that does not know the frame is sent none"
    );
    read_until(&mut p.a.ws, "rc:hive.purge")
        .await
        .expect("the primary's purge");
    purge_ack(&mut p.a.ws, &purge, &sid, "done", "done").await;
    let v = wait_purge(&app, &tid, &admin, &sid, "the primary's part", |v| {
        entry_of(v, &p.a.agent_id)["state"] == "done"
    })
    .await;
    assert!(v.get("done_at").is_none(), "the old build waits: {v}");

    // It updates: its first connection that purges hears the purge.
    drop(old.ws);
    wait_offline(&app, &p.seeded, &old.agent_id).await;
    old.ws = connect(&app, &old.token, &old.machine, PURGES).await;
    let told = read_until(&mut old.ws, "rc:hive.purge")
        .await
        .expect("the updated build's purge");
    assert_eq!(told["purge_id"], purge, "{told}");
    purge_ack(&mut old.ws, &purge, &sid, "done", "done").await;
    wait_purge(&app, &tid, &admin, &sid, "complete", |v| {
        v["done_at"].is_string()
    })
    .await;
    wait_record_gone(&app, &sid, "the tombstone goes").await;
}

/// FR-90 P2g-2 — the purge is its owner's alone, with `HIVE_RUN` (decision
/// 12), only with the replicaset's switch on, and never while a promotion
/// moves the session: a move would leave a copy the purge could not name.
/// Each refusal is a 200 carrying the reason, audited, and changes nothing.
#[tokio::test]
async fn a_purge_is_its_owners_with_hive_run_and_never_during_a_move() {
    // The switch off: the route is not there, for a session of the caller's
    // own too.
    let off = hive_app().await;
    let seeded = off.seed_tenant("purge-off").await;
    let mut dev = device(&off, &seeded, "mach-purge-off", PURGES).await;
    let (tid, token) = (seeded.tenant_id.clone(), seeded.admin.access_token.clone());
    let own = started_session(&off, &tid, &token, &mut dev).await;
    let (code, _) = delete_session(&off, &tid, &token, &own).await;
    assert_eq!(code, 404, "the switch is off");
    assert!(
        !device_hears(&mut dev.ws, "rc:hive.purge", Duration::from_millis(300)).await,
        "nothing reached the device"
    );
    assert_eq!(get_session(&off, &tid, &token, &own).await.0, 200);

    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-gates", &[]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    // Anyone else: a 404, like a bogus id.
    let (code, _) = delete_session(&app, &tid, &p.seeded.member.access_token, &sid).await;
    assert_eq!(code, 404, "another member's purge");
    assert_eq!(
        read_purge(&app, &tid, &admin, &sid).await.0,
        404,
        "a live session has no purge"
    );

    // A promotion in flight.
    let s_oid = ObjectId::parse_str(&sid).unwrap();
    let now = bson::DateTime::now();
    let promotion = doc! {
        "id": ObjectId::new(),
        "to": ObjectId::new(),
        "to_name": "venus",
        "to_role": "owner",
        "folder": "/srv",
        "from": { "device_id": ObjectId::parse_str(&p.a.agent_id).unwrap(), "folder": "/srv" },
        "from_fence": 1_i64,
        "by": ObjectId::parse_str(&p.admin_id).unwrap(),
        "state": "preparing",
        "started_at": now,
        "deadline": bson::DateTime::from_millis(now.timestamp_millis() + 600_000),
    };
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": s_oid },
            doc! { "$set": { "promotion": promotion } },
        )
        .await
        .unwrap();
    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("in_progress")),
        "{body}"
    );
    assert!(
        !device_hears(&mut p.a.ws, "rc:hive.purge", Duration::from_millis(300)).await,
        "nothing reached the device"
    );
    assert!(
        !record_of(&app, &sid).await.unwrap().contains_key("purged"),
        "the session is untouched"
    );

    // A plain member's own session: no HIVE_RUN.
    let member = ObjectId::parse_str(&p.seeded.member.id).unwrap();
    let mine = ObjectId::new();
    app.db
        .collection::<Document>("agent_sessions")
        .insert_one(doc! {
            "_id": mine,
            "tenant_id": ObjectId::parse_str(&tid).unwrap(),
            "owner_id": member,
            "title": "mine",
            "harness": { "id": "claude-code", "session": "u" },
            "location": { "device_id": ObjectId::parse_str(&p.a.agent_id).unwrap(), "folder": "/srv" },
            "status": "ended",
            "fence": 1_i64,
            "created_at": now,
            "updated_at": now,
        })
        .await
        .unwrap();
    let (code, body) =
        delete_session(&app, &tid, &p.seeded.member.access_token, &mine.to_hex()).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("no_permission")),
        "{body}"
    );
    assert!(
        !record_of(&app, &mine.to_hex())
            .await
            .unwrap()
            .contains_key("purged"),
        "the session is untouched"
    );
    assert_eq!(
        purge_audit(&app, &sid).await,
        vec![("refused".to_string(), Some("in_progress".to_string()))]
    );
    assert_eq!(
        purge_audit(&app, &mine.to_hex()).await,
        vec![("refused".to_string(), Some("no_permission".to_string()))]
    );
}

/// FR-90 P2g-2 — a purged session is read by nobody, its owner included:
/// not its view, not its participants, not a fork of it; the purge is its
/// owner's to read, and asking again answers with it.
#[tokio::test]
async fn a_purged_session_is_read_by_nobody() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-unread", &[]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let member = p.seeded.member.access_token.clone();
    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{tid}/hive/session/{sid}/participant/{}",
                p.seeded.member.id
            ),
            &admin,
        )
        .json(&json!({ "role": "reader" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "reader: {:?}", resp.status());
    assert_eq!(get_session(&app, &tid, &member, &sid).await.0, 200);

    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    let purge = body["purge"]["id"].as_str().unwrap().to_string();
    read_until(&mut p.a.ws, "rc:hive.purge")
        .await
        .expect("the device's purge");
    for (who, token) in [("its owner", &admin), ("its reader", &member)] {
        assert_eq!(get_session(&app, &tid, token, &sid).await.0, 404, "{who}");
        let resp = app
            .auth_get(
                &format!("/api/tenant/{tid}/hive/session/{sid}/participant"),
                token,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "{who}: its participants");
    }
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/fork"),
            &admin,
        )
        .json(&json!({ "device_id": p.a.agent_id, "folder": "/srv/elsewhere" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "a fork of it");
    // Nor a viewer's grant, to its owner either: it would stream from a
    // device the purge has not reached yet.
    let mut ws = user_ws(&app, &admin).await;
    user_send(&mut ws, "hive:view.open", json!({"session_id": sid})).await;
    let refused = user_read(&mut ws, "hive:view.refused")
        .await
        .expect("the view refused");
    assert_eq!(refused["reason"], "not_found", "{refused}");

    // The purge is its owner's to read; a reader asking hears nothing.
    let (code, v) = read_purge(&app, &tid, &admin, &sid).await;
    assert_eq!((code, v["id"].as_str()), (200, Some(purge.as_str())), "{v}");
    assert_eq!(read_purge(&app, &tid, &member, &sid).await.0, 404);
    let (code, again) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{again}");
    assert_eq!(
        (again["outcome"].as_str(), again["purge"]["id"].as_str()),
        (Some("purging"), Some(purge.as_str())),
        "the same purge, not a second one: {again}"
    );
    assert_eq!(
        app.db
            .collection::<Document>("hive_purges")
            .count_documents(doc! { "session_id": ObjectId::parse_str(&sid).unwrap() })
            .await
            .unwrap(),
        1
    );
}

/// FR-90 P2g-2 — a purge is sent only while its session's tombstone names
/// it: one whose tombstone never landed (a lost race, a crash between the two
/// writes) reaches no device, and the session is still its owner's. And the
/// tombstone itself is made only over the devices its purge reaches: a
/// record naming another one is no tombstone.
#[tokio::test]
async fn a_purge_no_tombstone_names_is_never_sent() {
    use meshharbor_mod_hive::{dao::AgentSessionDao, model::PurgedMark};

    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-orphan", &[]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let (t, s, a, owner) = (
        ObjectId::parse_str(&tid).unwrap(),
        ObjectId::parse_str(&sid).unwrap(),
        ObjectId::parse_str(&p.a.agent_id).unwrap(),
        ObjectId::parse_str(&p.admin_id).unwrap(),
    );
    let now = bson::DateTime::now();
    app.db
        .collection::<Document>("hive_purges")
        .insert_one(doc! {
            "_id": ObjectId::new(),
            "tenant_id": t,
            "session_id": s,
            "owner_id": owner,
            "by": owner,
            "reason": "owner",
            "devices": [{ "device_id": a, "state": "pending" }],
            "at": now,
        })
        .await
        .unwrap();
    drop(p.a.ws);
    wait_offline(&app, &p.seeded, &p.a.agent_id).await;
    p.a.ws = connect(&app, &p.a.token, &p.a.machine, PURGES).await;
    assert!(
        !device_hears(&mut p.a.ws, "rc:hive.purge", Duration::from_millis(1500)).await,
        "a purge no tombstone names reaches no device"
    );
    assert_eq!(get_session(&app, &tid, &admin, &sid).await.0, 200);

    let dao = AgentSessionDao::new(&app.db);
    let mark = PurgedMark {
        purge_id: ObjectId::new(),
        by: owner,
        at: now,
    };
    assert!(
        dao.tombstone(t, owner, s, &mark, &[ObjectId::new()], false)
            .await
            .unwrap()
            .is_none(),
        "the record names a device the purge does not reach"
    );
    assert!(!record_of(&app, &sid).await.unwrap().contains_key("purged"));
    // Nor while a promotion is in flight: one begun after the purge read the
    // record would move the session to a device the purge may not name.
    let sessions = app.db.collection::<Document>("agent_sessions");
    let promotion = doc! {
        "id": ObjectId::new(),
        "to": a,
        "to_name": "",
        "to_role": "owner",
        "folder": "/srv",
        "from": { "device_id": a, "folder": "/srv" },
        "from_fence": 1_i64,
        "by": owner,
        "state": "preparing",
        "started_at": now,
        "deadline": bson::DateTime::from_millis(now.timestamp_millis() + 600_000),
    };
    sessions
        .update_one(
            doc! { "_id": s },
            doc! { "$set": { "promotion": promotion } },
        )
        .await
        .unwrap();
    assert!(
        dao.tombstone(t, owner, s, &mark, &[a], false)
            .await
            .unwrap()
            .is_none(),
        "a promotion in flight"
    );
    sessions
        .update_one(doc! { "_id": s }, doc! { "$unset": { "promotion": "" } })
        .await
        .unwrap();
    // P2g-3a — retention's tombstone is only of a session that is over: this
    // one runs.
    assert!(
        dao.tombstone(t, owner, s, &mark, &[a], true)
            .await
            .unwrap()
            .is_none(),
        "retention never tombstones a live session"
    );
    let before = dao
        .tombstone(t, owner, s, &mark, &[a], false)
        .await
        .unwrap()
        .expect("over every device it names");
    assert!(before.purged.is_none(), "the record as it stood before");
    assert_eq!(
        record_of(&app, &sid)
            .await
            .unwrap()
            .get_document("purged")
            .unwrap()
            .get_object_id("purge_id")
            .unwrap(),
        mark.purge_id
    );
}

// ─── P2g-3a — retention, the server's sweep ───────────────────────────────

/// [`replicaset_app`], with retention swept every second.
async fn retention_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.hive.retention_sweep_secs = 1;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// The stored session as if it had ended `days` ago.
async fn ended_days_ago(app: &TestApp, sid: &str, days: i64) {
    let then =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - days * 86_400_000);
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(sid).unwrap() },
            doc! { "$set": { "status": "ended", "end_reason": "exited", "ended_at": then } },
        )
        .await
        .unwrap();
}

/// The `rc:hive.purge` frames a device hears within `within`, by session.
async fn purges_heard(ws: &mut AgentWs, within: Duration) -> Vec<Value> {
    let mut out = Vec::new();
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && v["t"] == "rc:hive.purge"
                {
                    out.push(v);
                }
            }
            Ok(Some(Ok(_))) | Err(_) => {}
            Ok(Some(Err(_))) | Ok(None) => break,
        }
    }
    out
}

/// FR-90 P2g-3a — retention purges a session over for longer than its
/// organization keeps (the default, 90 days), from every device that held
/// it, as its owner's purge would: `reason: retention`, audited. A session
/// that ended within the days is kept, and so is a live one however old.
#[tokio::test]
async fn retention_purges_a_session_over_for_longer_than_its_org_keeps() {
    let app = retention_app().await;
    let mut p = purgeable(&app, "retention-old", &[]).await;
    let (tid, admin) = (p.tid.clone(), p.admin.clone());
    let old = p.sid.clone();
    let recent = started_frame(&app, &tid, &admin, &mut p.a, "/srv/retention-recent")
        .await
        .0["id"]
        .as_str()
        .unwrap()
        .to_string();
    let live = started_frame(&app, &tid, &admin, &mut p.a, "/srv/retention-live")
        .await
        .0["id"]
        .as_str()
        .unwrap()
        .to_string();
    ended_days_ago(&app, &old, 100).await;
    ended_days_ago(&app, &recent, 10).await;
    // A live session started long ago: its age is no end.
    let long_ago =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 200 * 86_400_000);
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&live).unwrap() },
            doc! { "$set": { "created_at": long_ago, "updated_at": long_ago } },
        )
        .await
        .unwrap();

    let heard = purges_heard(&mut p.a.ws, Duration::from_secs(4)).await;
    let named: Vec<&str> = heard
        .iter()
        .filter_map(|f| f["session_id"].as_str())
        .collect();
    assert!(
        named.contains(&old.as_str()),
        "the session past its retention is purged: {heard:?}"
    );
    assert!(
        !named.contains(&recent.as_str()) && !named.contains(&live.as_str()),
        "a session within its days, and a live one, are kept: {heard:?}"
    );
    let (code, v) = read_purge(&app, &tid, &admin, &old).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["reason"], "retention", "{v}");
    assert_eq!(get_session(&app, &tid, &admin, &old).await.0, 404);
    for kept in [&recent, &live] {
        assert_eq!(get_session(&app, &tid, &admin, kept).await.0, 200, "{kept}");
    }
    assert_eq!(
        purge_audit(&app, &old).await,
        vec![("issued".to_string(), Some("retention".to_string()))]
    );
    let purge = v["id"].as_str().unwrap().to_string();
    purge_ack(&mut p.a.ws, &purge, &old, "done", "done").await;
    wait_purge(&app, &tid, &admin, &old, "complete", |v| {
        v["done_at"].is_string()
    })
    .await;
    wait_record_gone(&app, &old, "the tombstone goes").await;
}

/// FR-90 P2g-3a — an organization whose policy keeps its sessions for ever
/// (`retention_days = 0`) is never swept, however long ago they ended.
#[tokio::test]
async fn an_org_that_keeps_its_sessions_for_ever_is_never_swept() {
    let app = retention_app().await;
    let mut p = purgeable(&app, "retention-never", &[]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let mut policy = policy_min(1, 1);
    policy["retention_days"] = json!(0);
    let (code, body) = put_policy(&app, &tid, &admin, &policy).await;
    assert_eq!(code, 200, "{body}");
    ended_days_ago(&app, &sid, 1000).await;
    assert!(
        purges_heard(&mut p.a.ws, Duration::from_secs(3))
            .await
            .is_empty(),
        "nothing is purged"
    );
    assert_eq!(get_session(&app, &tid, &admin, &sid).await.0, 200);
    assert!(purge_audit(&app, &sid).await.is_empty());
}

// ─── P2g-3b — a purge reaches its device on any pod ─────────────────────────

/// [`replicaset_app`]'s settings, for two pods sharing one database and Redis
/// ([`TestApp::spawn_pair`]).
fn replicaset_settings(s: &mut meshharbor_config::Settings) {
    s.modules.hive = true;
    s.hive.replicaset = true;
    s.app.rate_limit_per_sec = 100;
    s.app.rate_limit_burst = 1000;
}

/// FR-90 P2g-3b — a purge issued on one pod reaches a device whose socket is
/// on the other. The owner's DELETE, like the retention sweep, runs on
/// whichever pod it lands on, and the pod that holds the device's socket
/// pushes it there. Before, the device heard it only at its next connection.
#[tokio::test]
async fn a_purge_issued_on_one_pod_reaches_a_device_on_the_other() {
    let (app1, app2) = TestApp::spawn_pair(replicaset_settings).await;
    if app1.state.redis_pubsub.is_none() || app2.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    // The device's socket, and its session, are on pod 1.
    let mut p = purgeable(&app1, "purge-xpod", &[]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    // The owner's DELETE lands on pod 2, which holds no socket of it.
    let (code, body) = delete_session(&app2, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["outcome"], "purging", "{body}");
    let purge = body["purge"]["id"].as_str().unwrap().to_string();
    let told = read_until(&mut p.a.ws, "rc:hive.purge")
        .await
        .expect("the purge reaches the device on the other pod");
    assert_eq!(told["purge_id"], purge, "{told}");
    assert_eq!(told["session_id"], sid, "{told}");
    // Its answer lands where its socket is, and completes the purge.
    purge_ack(&mut p.a.ws, &purge, &sid, "done", "done").await;
    wait_purge(&app2, &tid, &admin, &sid, "complete", |v| {
        v["done_at"].is_string()
    })
    .await;
    wait_record_gone(&app1, &sid, "the tombstone goes").await;
}

// ─── P2g-3c — the retention word, the server's half ─────────────────────────

/// Ask what keeps each of `sessions`' copies, as a device: the server's
/// answer, `None` when none came within [`HOLD`].
async fn ask_retain(ws: &mut AgentWs, sessions: &[&str]) -> Option<Value> {
    send(ws, json!({"t": "rc:hive.retain_ask", "sessions": sessions})).await;
    let deadline = Instant::now() + HOLD;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && v["t"] == "rc:hive.retain"
                {
                    return Some(v);
                }
            }
            Ok(Some(Ok(_))) | Err(_) => {}
            Ok(Some(Err(_))) | Ok(None) => break,
        }
    }
    None
}

/// An answer's words.
fn words_of(answer: &Value) -> Vec<Value> {
    answer["words"].as_array().cloned().unwrap_or_default()
}

/// The stored member row of `device`.
fn member_row(s: &Document, device: &str) -> Document {
    let id = ObjectId::parse_str(device).unwrap();
    s.get_document("replicaset")
        .unwrap()
        .get_array("members")
        .unwrap()
        .iter()
        .filter_map(|r| r.as_document())
        .find(|r| r.get_object_id("device_id").ok() == Some(id))
        .cloned()
        .unwrap_or_default()
}

/// FR-90 P2g-3c — a device that asks what keeps its copies hears, for each
/// session whose record names it, its organization's days and, once the
/// session is over, its end, as the sweep counts them. A device the record
/// does not name, another organization's session, one that does not exist
/// and a tombstone have no word; an oversized ask is answered with nothing.
#[tokio::test]
async fn a_device_that_asks_hears_what_keeps_each_copy_its_record_gives_it() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "retain-word", &[PURGES]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let other = purgeable(&app, "retain-word-other", &[]).await;
    let mut m = p.members.remove(0);
    let nobody = ObjectId::new().to_hex();

    // A member of a live session: the default days, no end.
    let answer = ask_retain(&mut m.ws, &[&sid, &other.sid, &nobody])
        .await
        .expect("an answer");
    assert_eq!(
        words_of(&answer),
        vec![json!({"session_id": sid, "days": 90})],
        "a live session's word names no end, and there is none of another org's or of none: {answer}"
    );
    // Its primary: the same word.
    let answer = ask_retain(&mut p.a.ws, &[&sid]).await.expect("an answer");
    assert_eq!(
        words_of(&answer),
        vec![json!({"session_id": sid, "days": 90})]
    );
    // A device of the org the record does not name: answered, with nothing.
    let mut outsider = device(&app, &p.seeded, "mach-retain-word-out", PURGES).await;
    let answer = ask_retain(&mut outsider.ws, &[&sid])
        .await
        .expect("an answer");
    assert!(
        words_of(&answer).is_empty(),
        "a device the record does not name hears no word: {answer}"
    );

    // The organization's own days.
    let mut policy = policy_min(2, 1);
    policy["retention_days"] = json!(30);
    let (code, body) = put_policy(&app, &tid, &admin, &policy).await;
    assert_eq!(code, 200, "{body}");
    let answer = ask_retain(&mut m.ws, &[&sid]).await.expect("an answer");
    assert_eq!(
        words_of(&answer),
        vec![json!({"session_id": sid, "days": 30})],
        "the organization's days: {answer}"
    );

    // Over: its end, as the sweep counts it.
    ended_days_ago(&app, &sid, 2).await;
    let ended = record_of(&app, &sid)
        .await
        .unwrap()
        .get_datetime("ended_at")
        .unwrap()
        .timestamp_millis();
    let answer = ask_retain(&mut m.ws, &[&sid]).await.expect("an answer");
    assert_eq!(
        words_of(&answer),
        vec![json!({"session_id": sid, "days": 30, "ended_at_ms": ended})],
        "a session that is over names its end: {answer}"
    );

    // Too many to be any device's: no answer at all.
    let many: Vec<String> = (0..=meshharbor_remote_control::hive::retain_limits::MAX_RETAIN_ASK)
        .map(|_| ObjectId::new().to_hex())
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert!(
        ask_retain(&mut m.ws, &many).await.is_none(),
        "an oversized ask is answered with nothing"
    );

    // Purged: its purge is its word.
    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    let answer = ask_retain(&mut m.ws, &[&sid]).await.expect("an answer");
    assert!(
        words_of(&answer).is_empty(),
        "a purged session has no word: {answer}"
    );
}

/// FR-90 P2g-3c — with the replicaset's switch off, an ask is answered with
/// nothing, and every device keeps its last word.
#[tokio::test]
async fn the_retention_word_is_not_answered_with_the_switch_off() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("retain-off").await;
    let mut dev = device(&app, &seeded, "mach-retain-off", PURGES).await;
    let nobody = ObjectId::new().to_hex();
    assert!(
        ask_retain(&mut dev.ws, &[&nobody]).await.is_none(),
        "nothing is answered with the switch off"
    );
}

/// FR-90 P2g-3c — a member's manifest that says its own clock purged its
/// copy: its row is refused `purged` and its tip forgotten, as a join it
/// answered so would be, so placement no longer counts on it and the
/// session's purge closes its part at once. The primary's own row is left
/// alone, and so is the record when a device it does not name says so.
#[tokio::test]
async fn a_copy_its_members_own_clock_purged_is_no_longer_counted() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "retain-purged", &[PURGES]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let mut m = p.members.remove(0);
    let at = bson::DateTime::now().timestamp_millis();
    let manifest = |sid: &str| {
        json!({"t": "rc:hive.replica.manifest", "sessions": [],
               "purged": [{"session_id": sid, "at_ms": at}]})
    };
    send(&mut m.ws, tip_at(&sid, 1, 3, "ab")).await;
    wait_stored(&app, &sid, "the member's tip", |s| {
        member_row(s, &m.agent_id).contains_key("tip")
    })
    .await;

    // The primary saying so of its own session, and a device the record
    // does not name: neither changes the members. A connection's reports are
    // applied in order, so once its ask is answered the manifest before it
    // was read.
    let before = stored(&app, &sid).await;
    let mut outsider = device(&app, &p.seeded, "mach-retain-purged-out", PURGES).await;
    for ws in [&mut p.a.ws, &mut outsider.ws] {
        send(ws, manifest(&sid)).await;
        ask_retain(ws, &[&sid])
            .await
            .expect("its reports were read");
    }
    let members = |s: &Document| {
        s.get_document("replicaset")
            .unwrap()
            .get_array("members")
            .unwrap()
            .clone()
    };
    assert_eq!(
        members(&stored(&app, &sid).await),
        members(&before),
        "the primary's own row, and a device the record does not name"
    );

    // The member saying so: refused `purged`, its tip forgotten.
    send(&mut m.ws, manifest(&sid)).await;
    let s = wait_stored(&app, &sid, "the member refused purged", |s| {
        stored_member(s, &m.agent_id).1 == "refused"
    })
    .await;
    let row = member_row(&s, &m.agent_id);
    assert_eq!(row.get_str("refusal").unwrap(), "purged", "{row}");
    assert!(!row.contains_key("tip"), "its tip forgotten: {row}");

    // The session's purge closes its part at once: by its own word it holds
    // nothing.
    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        entry_of(&body["purge"], &m.agent_id)["state"],
        "closed",
        "{body}"
    );
    assert_eq!(entry_of(&body["purge"], &p.a.agent_id)["state"], "pending");
}

// ─── P2g-4a — a removed device purges what it holds ─────────────────────────

/// Remove `device` from its organization, as its admin.
async fn remove_device(app: &TestApp, tid: &str, admin: &str, device: &str) {
    let resp = app
        .auth_delete(&format!("/api/tenant/{tid}/agent/{device}"), admin)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "remove: {:?}", resp.status());
}

/// FR-90 P2g-4a — a device removed from its organization is told, while its
/// socket is still up, to purge every session it holds: a member hears
/// `rc:hive.purge_all`, an id and nothing else, and so does a primary, after
/// the stop of the session it ran. A build that purges a session but
/// predates the frame is sent none, and neither is a device that stays.
#[tokio::test]
async fn a_removed_device_is_told_to_purge_everything_it_holds() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-all", &[PURGES, PURGES_A_SESSION]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let mut old = p.members.pop().unwrap();
    let mut m = p.members.pop().unwrap();

    // A member.
    remove_device(&app, &tid, &admin, &m.agent_id).await;
    let told = read_until(&mut m.ws, "rc:hive.purge_all")
        .await
        .expect("the removed member's purge");
    assert!(
        told["purge_id"]
            .as_str()
            .is_some_and(|id| ObjectId::parse_str(id).is_ok()),
        "{told}"
    );
    assert_eq!(
        told.as_object().map(|o| o.len()),
        Some(2),
        "an id, nothing else: {told}"
    );

    // A build of P2g-1 to P2g-3d: never sent a frame it cannot decode.
    remove_device(&app, &tid, &admin, &old.agent_id).await;
    assert!(
        !device_hears(&mut old.ws, "rc:hive.purge_all", Duration::from_millis(500)).await,
        "a build that purges a session but predates the frame is sent none"
    );
    assert!(
        !device_hears(&mut p.a.ws, "rc:hive.purge_all", Duration::from_millis(500)).await,
        "the device that stays hears none"
    );

    // The primary: the stop of the session it ran, then the purge.
    remove_device(&app, &tid, &admin, &p.a.agent_id).await;
    let frames = frames_until(&mut p.a.ws, &["rc:hive.stop", "rc:hive.purge_all"]).await;
    let at = |t: &str| frames.iter().position(|f| f["t"] == t).unwrap();
    assert!(at("rc:hive.stop") < at("rc:hive.purge_all"), "{frames:?}");
    let stop = &frames[at("rc:hive.stop")];
    assert_eq!(
        (stop["session_id"].as_str(), stop["reason"].as_str()),
        (Some(sid.as_str()), Some("device_removed")),
        "{stop}"
    );
}

/// FR-90 P2g-4a — a purge waiting on offline members completes once they are
/// removed: each one's part closes `device_removed` at its own removal, as it
/// would at the issue of a purge after it, the other members' parts waiting
/// still, and the last removal completes the purge.
#[tokio::test]
async fn a_purge_waiting_on_removed_devices_completes_without_them() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "purge-gone", &[PURGES, PURGES]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    let c = p.members.pop().unwrap();
    let b = p.members.pop().unwrap();
    drop(b.ws);
    drop(c.ws);
    wait_offline(&app, &p.seeded, &b.agent_id).await;
    wait_offline(&app, &p.seeded, &c.agent_id).await;
    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    let purge = body["purge"]["id"].as_str().unwrap().to_string();
    read_until(&mut p.a.ws, "rc:hive.purge")
        .await
        .expect("the primary's purge");
    purge_ack(&mut p.a.ws, &purge, &sid, "done", "done").await;
    wait_purge(&app, &tid, &admin, &sid, "the primary's part", |v| {
        entry_of(v, &p.a.agent_id)["state"] == "done"
    })
    .await;

    // One member removed: its part closes; the other's still waits.
    remove_device(&app, &tid, &admin, &b.agent_id).await;
    let (_, v) = read_purge(&app, &tid, &admin, &sid).await;
    let e = entry_of(&v, &b.agent_id);
    assert_eq!(
        (e["state"].as_str(), e["closed"].as_str()),
        (Some("closed"), Some("device_removed")),
        "the removed member's part closes: {v}"
    );
    assert_eq!(
        entry_of(&v, &c.agent_id)["state"],
        "pending",
        "the other member's part still waits: {v}"
    );
    assert_eq!(entry_of(&v, &p.a.agent_id)["state"], "done", "{v}");
    assert!(v.get("done_at").is_none(), "{v}");

    // The last one removed: the purge completes.
    remove_device(&app, &tid, &admin, &c.agent_id).await;
    let v = wait_purge(
        &app,
        &tid,
        &admin,
        &sid,
        "the last removal completes the purge",
        |v| v["done_at"].is_string(),
    )
    .await;
    assert_eq!(entry_of(&v, &c.agent_id)["closed"], "device_removed", "{v}");
    wait_record_gone(&app, &sid, "the tombstone goes with the purge's completion").await;
    assert_eq!(
        purge_audit(&app, &sid).await,
        vec![("issued".to_string(), None), ("complete".to_string(), None)]
    );
}

/// FR-90 P2g-4a — with the replicaset's switch off, a removal tells the
/// device nothing to purge: its purges are the replicaset's, and off.
#[tokio::test]
async fn a_removal_purges_nothing_with_the_switch_off() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("purge-all-off").await;
    let mut dev = device(&app, &seeded, "mach-purge-all-off", PURGES).await;
    remove_device(
        &app,
        &seeded.tenant_id,
        &seeded.admin.access_token,
        &dev.agent_id,
    )
    .await;
    assert!(
        !device_hears(&mut dev.ws, "rc:hive.purge_all", Duration::from_millis(500)).await,
        "nothing is purged with the switch off"
    );
}

/// FR-90 P2g-4a — a removal on one pod reaches a device whose socket is on
/// the other: that pod pushes the purge, published ahead of the kick that
/// unregisters the device there.
#[tokio::test]
async fn a_removal_on_one_pod_reaches_a_device_on_the_other() {
    let (app1, app2) = TestApp::spawn_pair(replicaset_settings).await;
    if app1.state.redis_pubsub.is_none() || app2.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    // The member's socket is on pod 1; its removal lands on pod 2.
    let mut p = purgeable(&app1, "purge-all-xpod", &[PURGES]).await;
    let (tid, admin) = (p.tid.clone(), p.admin.clone());
    let mut m = p.members.remove(0);
    remove_device(&app2, &tid, &admin, &m.agent_id).await;
    read_until(&mut m.ws, "rc:hive.purge_all")
        .await
        .expect("the purge reaches the device on the other pod");
}

// ─── P2g-4b — a member that leaves is purged once min holds without it ──────

/// A live session on `a`, which carries the policy's restricted tag `prod`,
/// with `min` 2: `m`, tagged, took its copy and said where it ends; `n`
/// carries no tag yet. Every device purges.
struct Leaving {
    tid: String,
    admin: String,
    sid: String,
    seeded: SeededTenant,
    a: Device,
    m: Device,
    n: Device,
}

/// [`Leaving`], its machines named after `tag`.
async fn leaving(app: &TestApp, tag: &str) -> Leaving {
    let seeded = app.seed_tenant(tag).await;
    on_pro(app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let (code, p) = put_policy(app, &tid, &admin, &policy_min(2, 0)).await;
    assert_eq!(code, 200, "{p}");
    let mut a = device(app, &seeded, &format!("mach-{tag}-a"), PURGES).await;
    set_device(app, &a.agent_id, doc! { "tags": ["prod"] }).await;
    let mut m = device(app, &seeded, &format!("mach-{tag}-m"), PURGES).await;
    set_device(app, &m.agent_id, doc! { "tags": ["prod"] }).await;
    let n = device(app, &seeded, &format!("mach-{tag}-n"), PURGES).await;
    let (s, _) = started_frame(app, &tid, &admin, &mut a, &format!("/srv/{tag}")).await;
    let sid = s["id"].as_str().unwrap().to_string();
    took_copy(app, &tid, &admin, &sid, &mut m).await;
    Leaving {
        tid,
        admin,
        sid,
        seeded,
        a,
        m,
        n,
    }
}

/// `d` answers its join of `sid` and says where its copy ends.
async fn took_copy(app: &TestApp, tid: &str, admin: &str, sid: &str, d: &mut Device) {
    read_until(&mut d.ws, "rc:hive.replica.join")
        .await
        .expect("its join");
    answer_join(app, tid, admin, sid, d).await;
    send(&mut d.ws, tip_at(sid, 1, 3, "ab")).await;
    let id = d.agent_id.clone();
    wait_stored(app, sid, "its tip", |s| {
        member_row(s, &id).contains_key("tip")
    })
    .await;
}

/// `d` answers its join of `sid`, `joined`.
async fn answer_join(app: &TestApp, tid: &str, admin: &str, sid: &str, d: &mut Device) {
    send(
        &mut d.ws,
        json!({"t": "rc:hive.replica.join_ack", "session_id": sid, "fence": 1}),
    )
    .await;
    wait_member(app, tid, admin, sid, &d.agent_id, "joined", |m| {
        m["state"] == "joined"
    })
    .await;
}

/// The purge `device`'s row of `sid` names, when it names one.
async fn purging_of(app: &TestApp, sid: &str, device: &str) -> Option<String> {
    member_row(&stored(app, sid).await, device)
        .get_object_id("purging")
        .ok()
        .map(|o| o.to_hex())
}

/// Every purge of `sid` the server keeps, oldest first.
async fn purges_of(app: &TestApp, sid: &str) -> Vec<Document> {
    let mut cur = app
        .db
        .collection::<Document>("hive_purges")
        .find(doc! { "session_id": ObjectId::parse_str(sid).unwrap() })
        .sort(doc! { "at": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(p) = cur.next().await {
        out.push(p.unwrap());
    }
    out
}

/// FR-90 P2g-4b — a member a smaller policy lets go, while the copies
/// elsewhere are enough, is purged at once: its copy alone, the session left
/// as it is, no tombstone. Once it answers, its row goes. The member that
/// stays and the primary hear nothing, and the owner's read of the session's
/// purge is not this one.
#[tokio::test]
async fn a_member_a_smaller_policy_lets_go_is_purged_at_once() {
    let app = replicaset_app().await;
    let mut p = purgeable(&app, "leave-now", &[PURGES, PURGES]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    for m in &mut p.members {
        send(&mut m.ws, tip_at(&sid, 1, 3, "ab")).await;
    }
    for m in &p.members {
        let id = m.agent_id.clone();
        wait_stored(&app, &sid, "each member's tip", |s| {
            member_row(s, &id).contains_key("tip")
        })
        .await;
    }

    // A smaller policy: placement keeps one member and lets the other go.
    let (code, body) = put_policy(&app, &tid, &admin, &policy_min(2, 1)).await;
    assert_eq!(code, 200, "{body}");
    let s = stored(&app, &sid).await;
    let i = p
        .members
        .iter()
        .position(|m| stored_member(&s, &m.agent_id).1 == "leaving")
        .expect("one member leaves");
    let mut gone = p.members.remove(i);
    let mut kept = p.members.remove(0);
    assert_eq!(stored_member(&s, &kept.agent_id).1, "joined", "{s}");

    // Min holds without it: its purge goes at once, and only to it.
    let told = read_until(&mut gone.ws, "rc:hive.purge")
        .await
        .expect("the member that leaves hears its purge");
    assert_eq!(told["session_id"], sid, "{told}");
    assert_eq!(
        told["leaving"], true,
        "its copy alone, which is not final on the device (P2k-3): {told}"
    );
    let purge = told["purge_id"].as_str().unwrap().to_string();
    assert_eq!(
        purging_of(&app, &sid, &gone.agent_id).await.as_deref(),
        Some(purge.as_str()),
        "its row names the purge"
    );
    for (who, ws) in [
        ("the member that stays", &mut kept.ws),
        ("the primary", &mut p.a.ws),
    ] {
        assert!(
            !device_hears(ws, "rc:hive.purge", Duration::from_millis(500)).await,
            "{who} hears no purge"
        );
    }
    let all = purges_of(&app, &sid).await;
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(
        (
            all[0].get_str("reason").ok(),
            all[0].get_object_id("member").ok().map(|o| o.to_hex())
        ),
        (Some("leaving"), Some(gone.agent_id.clone())),
        "a purge of that member alone: {all:?}"
    );
    let rec = record_of(&app, &sid).await.expect("the session stays");
    assert!(!rec.contains_key("purged"), "no tombstone: {rec}");
    assert_eq!(get_session(&app, &tid, &admin, &sid).await.0, 200);

    // It answers: the purge completes, and its row goes.
    purge_ack(&mut gone.ws, &purge, &sid, "done", "not_there").await;
    wait_stored(&app, &sid, "its row goes once the purge completes", |s| {
        member_row(s, &gone.agent_id).is_empty()
    })
    .await;
    assert_eq!(
        stored_member(&stored(&app, &sid).await, &kept.agent_id).1,
        "joined"
    );
    assert_eq!(
        read_purge(&app, &tid, &admin, &sid).await.0,
        404,
        "the owner's read is the session's own purge, and there is none"
    );
    assert_eq!(
        purge_audit(&app, &sid).await,
        vec![
            ("issued".to_string(), Some("leaving".to_string())),
            ("complete".to_string(), Some("leaving".to_string())),
        ]
    );
}

/// FR-90 P2k-3 — a leaving member's purge issued on one pod reaches its
/// device on the other still saying `leaving`: the pod that holds the socket
/// builds the frame from the purge's envelope, so the device keeps no id
/// there either.
#[tokio::test]
async fn a_leaving_members_purge_from_the_other_pod_still_says_so() {
    let (app1, app2) = TestApp::spawn_pair(replicaset_settings).await;
    if app1.state.redis_pubsub.is_none() || app2.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    // The members' sockets, and the session, are on pod 1.
    let mut p = purgeable(&app1, "leave-xpod", &[PURGES, PURGES]).await;
    let (tid, admin, sid) = (p.tid.clone(), p.admin.clone(), p.sid.clone());
    for m in &mut p.members {
        send(&mut m.ws, tip_at(&sid, 1, 3, "ab")).await;
    }
    for m in &p.members {
        let id = m.agent_id.clone();
        wait_stored(&app1, &sid, "each member's tip", |s| {
            member_row(s, &id).contains_key("tip")
        })
        .await;
    }

    // The smaller policy lands on pod 2, which holds no socket of theirs.
    let (code, body) = put_policy(&app2, &tid, &admin, &policy_min(2, 1)).await;
    assert_eq!(code, 200, "{body}");
    let s = stored(&app1, &sid).await;
    let i = p
        .members
        .iter()
        .position(|m| stored_member(&s, &m.agent_id).1 == "leaving")
        .expect("one member leaves");
    let mut gone = p.members.remove(i);
    let told = read_until(&mut gone.ws, "rc:hive.purge")
        .await
        .expect("the member that leaves hears its purge, from the other pod");
    assert_eq!(told["session_id"], sid, "{told}");
    assert_eq!(
        told["leaving"], true,
        "its copy alone, from the other pod too: {told}"
    );
}

/// FR-90 P2g-4b — make-before-break: a member that leaves keeps its copy
/// while the copies elsewhere fall short, and a device that took its place
/// counts only once its copy holds as much as the leaving one's (P2k-2: not
/// at the empty tip it says when it joins). Then its purge goes.
#[tokio::test]
async fn a_member_that_leaves_keeps_its_copy_until_min_holds_without_it() {
    let app = replicaset_app().await;
    let mut l = leaving(&app, "leave-wait").await;
    let (tid, admin, sid) = (l.tid.clone(), l.admin.clone(), l.sid.clone());

    // Its tag taken off: it leaves, and min does not hold without it.
    tag(&app, &tid, &admin, &l.m.agent_id, &[]).await;
    assert_eq!(
        stored_member(&stored(&app, &sid).await, &l.m.agent_id).1,
        "leaving"
    );
    assert!(
        !device_hears(&mut l.m.ws, "rc:hive.purge", Duration::from_millis(500)).await,
        "min does not hold without it: it keeps its copy"
    );
    assert_eq!(purging_of(&app, &sid, &l.m.agent_id).await, None);

    // Another takes its place, and joins, but has said nothing yet: the
    // primary's own tip looks again, and finds it is not yet a copy.
    tag(&app, &tid, &admin, &l.n.agent_id, &["prod"]).await;
    read_until(&mut l.n.ws, "rc:hive.replica.join")
        .await
        .expect("n's join");
    answer_join(&app, &tid, &admin, &sid, &mut l.n).await;
    send(&mut l.a.ws, tip_at(&sid, 1, 3, "ab")).await;
    let a_id = l.a.agent_id.clone();
    wait_stored(&app, &sid, "the primary's tip", |s| {
        member_row(s, &a_id).contains_key("tip")
    })
    .await;
    assert!(
        !device_hears(&mut l.m.ws, "rc:hive.purge", Duration::from_millis(500)).await,
        "a copy that has said nothing is not yet one"
    );

    // P2k-2 (F1) — it says it joined, at its floor, holding nothing yet: a
    // device does so the moment it takes its copy. Still not one.
    send(&mut l.n.ws, tip_at(&sid, 1, 0, "00")).await;
    let n_id = l.n.agent_id.clone();
    wait_stored(&app, &sid, "n's empty tip", |s| {
        member_row(s, &n_id).contains_key("tip")
    })
    .await;
    assert!(
        !device_hears(&mut l.m.ws, "rc:hive.purge", Duration::from_millis(500)).await,
        "a copy that holds less than m's is not yet one"
    );

    // It says where its copy ends: min holds, and m's purge goes.
    send(&mut l.n.ws, tip_at(&sid, 1, 3, "ab")).await;
    let told = read_until(&mut l.m.ws, "rc:hive.purge")
        .await
        .expect("m's purge, now that n holds a copy");
    assert_eq!(told["session_id"], sid, "{told}");
    assert!(
        !device_hears(&mut l.n.ws, "rc:hive.purge", Duration::from_millis(300)).await,
        "n hears none"
    );
}

/// FR-90 P2g-4b — a member taken back before its purge goes is a member
/// again, as before: nothing of it is purged.
#[tokio::test]
async fn a_member_taken_back_before_its_purge_goes_is_never_purged() {
    let app = replicaset_app().await;
    let mut l = leaving(&app, "leave-back").await;
    let (tid, admin, sid) = (l.tid.clone(), l.admin.clone(), l.sid.clone());
    tag(&app, &tid, &admin, &l.m.agent_id, &[]).await;
    assert_eq!(
        stored_member(&stored(&app, &sid).await, &l.m.agent_id).1,
        "leaving"
    );
    tag(&app, &tid, &admin, &l.m.agent_id, &["prod"]).await;
    assert_eq!(
        stored_member(&stored(&app, &sid).await, &l.m.agent_id).1,
        "pending",
        "taken back before its purge went"
    );
    read_until(&mut l.m.ws, "rc:hive.replica.join")
        .await
        .expect("its join again");
    answer_join(&app, &tid, &admin, &sid, &mut l.m).await;
    send(&mut l.m.ws, tip_at(&sid, 1, 4, "cd")).await;
    assert!(
        !device_hears(&mut l.m.ws, "rc:hive.purge", Duration::from_millis(500)).await,
        "a member taken back is never purged"
    );
    assert!(purges_of(&app, &sid).await.is_empty());
}

/// FR-90 P2g-4b — once a member's purge went, placement never takes it back
/// nor chooses its device again: removal is final there, so a join would be
/// refused for ever. Offline when its purge went, it hears it at its next
/// connection, answers, and its row goes.
#[tokio::test]
async fn a_member_whose_purge_went_is_never_taken_back_and_hears_it_later() {
    let app = replicaset_app().await;
    let mut l = leaving(&app, "leave-gone").await;
    let (tid, admin, sid) = (l.tid.clone(), l.admin.clone(), l.sid.clone());
    let o = device(&app, &l.seeded, "mach-leave-gone-o", PURGES).await;

    // Let go, and offline: n takes its place and holds a copy, so m's purge
    // goes, to nobody yet.
    tag(&app, &tid, &admin, &l.m.agent_id, &[]).await;
    drop(l.m.ws);
    wait_offline(&app, &l.seeded, &l.m.agent_id).await;
    tag(&app, &tid, &admin, &l.n.agent_id, &["prod"]).await;
    took_copy(&app, &tid, &admin, &sid, &mut l.n).await;
    let purge = {
        let id = l.m.agent_id.clone();
        wait_stored(&app, &sid, "its row names its purge", |s| {
            member_row(s, &id).contains_key("purging")
        })
        .await;
        purging_of(&app, &sid, &id).await.unwrap()
    };

    // A placement that read the member before its purge took cannot take it
    // back after: the take-back holds only while no purge names the row.
    let took_back = meshharbor_mod_hive::dao::AgentSessionDao::new(&app.db)
        .rejoin(
            ObjectId::parse_str(&sid).unwrap(),
            ObjectId::parse_str(&l.m.agent_id).unwrap(),
            "owner",
        )
        .await
        .unwrap();
    assert!(
        !took_back,
        "a placement that read it before its purge cannot take it back"
    );

    // Tagged again: never taken back.
    tag(&app, &tid, &admin, &l.m.agent_id, &["prod"]).await;
    assert_eq!(
        stored_member(&stored(&app, &sid).await, &l.m.agent_id).1,
        "leaving",
        "a member whose purge went is never taken back"
    );
    // n let go too, and o tagged: o takes the place, never m.
    tag(&app, &tid, &admin, &l.n.agent_id, &[]).await;
    tag(&app, &tid, &admin, &o.agent_id, &["prod"]).await;
    let s = stored(&app, &sid).await;
    assert_eq!(
        stored_member(&s, &o.agent_id).1,
        "pending",
        "o takes the place: a member whose purge went is never chosen: {s}"
    );
    assert_eq!(stored_member(&s, &l.m.agent_id).1, "leaving", "{s}");

    // m connects: it hears its purge, answers, and its row goes.
    l.m.ws = connect(&app, &l.m.token, &l.m.machine, PURGES).await;
    let told = arrives(&mut l.m.ws, "rc:hive.purge", Duration::from_secs(5))
        .await
        .expect("m hears its purge at its next connection");
    assert_eq!(told["purge_id"], purge, "{told}");
    purge_ack(&mut l.m.ws, &purge, &sid, "done", "not_there").await;
    let id = l.m.agent_id.clone();
    wait_stored(&app, &sid, "its row goes", |s| {
        member_row(s, &id).is_empty()
    })
    .await;
}

/// FR-90 P2g-4b — the owner's read of a session that is gone answers its
/// own purge, never a leaving member's, even one that completed after it.
#[tokio::test]
async fn the_owners_read_of_a_gone_session_is_its_own_purge() {
    let app = replicaset_app().await;
    let mut l = leaving(&app, "leave-read").await;
    let (tid, admin, sid) = (l.tid.clone(), l.admin.clone(), l.sid.clone());
    tag(&app, &tid, &admin, &l.m.agent_id, &[]).await;
    drop(l.m.ws);
    wait_offline(&app, &l.seeded, &l.m.agent_id).await;
    tag(&app, &tid, &admin, &l.n.agent_id, &["prod"]).await;
    took_copy(&app, &tid, &admin, &sid, &mut l.n).await;
    let leave = {
        let id = l.m.agent_id.clone();
        wait_stored(&app, &sid, "m's purge went", |s| {
            member_row(s, &id).contains_key("purging")
        })
        .await;
        purging_of(&app, &sid, &id).await.unwrap()
    };

    // The owner purges the session; a and n answer it.
    let (code, body) = delete_session(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{body}");
    let owner = body["purge"]["id"].as_str().unwrap().to_string();
    for d in [&mut l.a, &mut l.n] {
        read_until(&mut d.ws, "rc:hive.purge")
            .await
            .expect("the session's purge");
        purge_ack(&mut d.ws, &owner, &sid, "done", "done").await;
    }

    // m answers the session's purge first, then its own: the session's
    // completes first, and the member's after it.
    l.m.ws = connect(&app, &l.m.token, &l.m.machine, PURGES).await;
    purge_ack(&mut l.m.ws, &owner, &sid, "done", "done").await;
    wait_record_gone(&app, &sid, "the session's purge completes").await;
    purge_ack(&mut l.m.ws, &leave, &sid, "done", "done").await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while purges_of(&app, &sid)
        .await
        .iter()
        .any(|p| !p.contains_key("done_at"))
    {
        assert!(Instant::now() < deadline, "the member's purge completes");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (code, v) = read_purge(&app, &tid, &admin, &sid).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        v["id"], owner,
        "the owner's read is the session's own purge, never a member's: {v}"
    );
}

/// FR-90 P2g-4b — with the replicaset's switch off, a member that leaves is
/// purged by nothing: a tip that would make min hold changes nothing.
#[tokio::test]
async fn a_member_that_leaves_is_purged_by_nothing_with_the_switch_off() {
    let app = replicaset_app().await;
    let mut l = leaving(&app, "leave-off").await;
    let (tid, admin, sid) = (l.tid.clone(), l.admin.clone(), l.sid.clone());
    tag(&app, &tid, &admin, &l.m.agent_id, &[]).await;
    tag(&app, &tid, &admin, &l.n.agent_id, &["prod"]).await;
    read_until(&mut l.n.ws, "rc:hive.replica.join")
        .await
        .expect("n's join");
    answer_join(&app, &tid, &admin, &sid, &mut l.n).await;

    // The switch goes off; n says where its copy ends there.
    let off = switch_off(&app).await;
    drop(l.n.ws);
    wait_offline(&app, &l.seeded, &l.n.agent_id).await;
    let mut n = connect(&off, &l.n.token, &l.n.machine, PURGES).await;
    send(&mut n, tip_at(&sid, 1, 3, "ab")).await;
    let id = l.n.agent_id.clone();
    wait_stored(&off, &sid, "n's tip lands", |s| {
        member_row(s, &id).contains_key("tip")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        purges_of(&off, &sid).await.is_empty(),
        "nothing is purged with the switch off"
    );
    assert!(
        !device_hears(&mut l.m.ws, "rc:hive.purge", Duration::from_millis(300)).await,
        "m hears nothing"
    );
}

/// A device that holds no copies but takes a teleport's copy, starts forks
/// and purges: a fork onto it takes a copy first, and that copy is purged
/// once it may go.
const TAKES_A_COPY_TO_FORK_AND_PURGES: &[&str] = &[
    "exec",
    "hive",
    "hive-stream",
    "hive-lease",
    "hive-promote",
    "hive-teleport",
    "hive-fork",
    "hive-purge",
];

/// [`TAKES_A_COPY_TO_FORK_AND_PURGES`] without `hive-fork`: a build that
/// takes a teleport's copy and purges, and starts no fork.
const TAKES_A_COPY_AND_PURGES: &[&str] = &[
    "exec",
    "hive",
    "hive-stream",
    "hive-lease",
    "hive-promote",
    "hive-teleport",
    "hive-purge",
];

/// `m`'s session forked onto `c`, which takes its copy as a teleport's
/// target and catches up to the primary's tip; with `catch_up` false, `c`
/// says nothing yet, and only the primary has said where its copy ends.
async fn fork_joined(app: &TestApp, m: &mut Moving, c: &mut Device, folder: &str, catch_up: bool) {
    let sid = m.sid.clone();
    let (body, _) = fork_join_prepared(app, m, c, folder, None).await;
    assert_eq!(body["outcome"], "joining", "{body}");
    join_answered(c, &sid, "teleport").await;
    join_answered(&mut m.a, &sid, "primary").await;
    send(&mut m.a.ws, tip_at(&sid, 1, 9, "ab")).await;
    let a = m.a.agent_id.clone();
    wait_stored(app, &sid, "the primary's tip", |s| {
        member_row(s, &a)
            .get_document("tip")
            .is_ok_and(|t| t.get_i64("seq") == Ok(9))
    })
    .await;
    if catch_up {
        send(&mut c.ws, tip_at(&sid, 1, 9, "ab")).await;
    }
}

/// FR-90 P2g-4b — a fork onto a device with no copy (P2f-3c) is made from
/// the copy that device takes. The device is let go as the move ends, its
/// row naming the fork, and keeps that copy while the fork's start is out:
/// though the session holds its `min` copies without it, tips land
/// meanwhile, and the server stops waiting for the answer (putting a copy in
/// place can take long). Once the device answers, however late, the copy
/// goes as any leaving member's.
#[tokio::test]
async fn a_member_a_fork_is_made_from_keeps_its_copy_until_the_forks_start_is_answered() {
    let app = fork_app().await;
    let (mut m, mut c) = joinable_with(&app, "forkhold", TAKES_A_COPY_TO_FORK_AND_PURGES).await;
    let sid = m.sid.clone();
    fork_joined(&app, &mut m, &mut c, "/srv/forkhold-c", true).await;
    let start = read_until(&mut c.ws, "rc:hive.start")
        .await
        .expect("the fork's start, once the copy caught up");
    let fsid = start["session_id"].as_str().unwrap().to_string();

    // Let go as the move ended, its row naming the fork. The primary and b
    // hold the session, so min holds without it: its copy stays anyway,
    // through the tip that caught it up and the next one.
    let s = wait_stored(&app, &sid, "the fork's move ends", |s| {
        !s.contains_key("promotion")
    })
    .await;
    assert_eq!(
        stored_member(&s, &c.agent_id),
        ("teleport".into(), "leaving".into())
    );
    assert_eq!(
        member_row(&s, &c.agent_id)
            .get_object_id("forking")
            .ok()
            .map(|o| o.to_hex()),
        Some(fsid.clone()),
        "its row names the fork: {s}"
    );
    send(&mut m.b.ws, tip_with_checkpoint(&sid, 9, 5)).await;
    let b = m.b.agent_id.clone();
    wait_stored(&app, &sid, "b's next tip", |s| {
        member_row(s, &b)
            .get_document("tip")
            .is_ok_and(|t| t.get_i64("seq") == Ok(9))
    })
    .await;
    assert!(
        !device_hears(&mut c.ws, "rc:hive.purge", Duration::from_millis(500)).await,
        "its copy stays while the fork's start is out"
    );
    assert!(purges_of(&app, &sid).await.is_empty(), "no purge is issued");
    // A purge that read the row before the fork was named cannot take it.
    let took = meshharbor_mod_hive::dao::AgentSessionDao::new(&app.db)
        .mark_purging(
            ObjectId::parse_str(&sid).unwrap(),
            ObjectId::parse_str(&c.agent_id).unwrap(),
            ObjectId::new(),
            None,
        )
        .await
        .unwrap();
    assert!(
        !took,
        "a row naming a fork is taken by no purge that read it without one"
    );

    // The server stops waiting for the answer and says the fork was made:
    // the copy stays for the answer still to come.
    wait_note(&app, &m, "forked the session into **Fork of forkhold**").await;
    assert!(
        !device_hears(&mut c.ws, "rc:hive.purge", Duration::from_millis(300)).await,
        "its copy stays while the answer may yet come"
    );

    // The device answers the start: the copy goes as any leaving member's.
    send(
        &mut c.ws,
        json!({"t": "rc:hive.start_ack", "session_id": fsid, "fence": 1, "account": "dev"}),
    )
    .await;
    let told = read_until(&mut c.ws, "rc:hive.purge")
        .await
        .expect("once the fork's start is answered, the copy it was made from is purged");
    assert_eq!(told["session_id"], sid, "{told}");
    let purge = told["purge_id"].as_str().unwrap().to_string();
    purge_ack(&mut c.ws, &purge, &sid, "done", "not_there").await;
    let c_id = c.agent_id.clone();
    wait_stored(&app, &sid, "its row goes once the purge completes", |s| {
        member_row(s, &c_id).is_empty()
    })
    .await;
    assert!(
        stored(&app, &fsid)
            .await
            .get_datetime("accepted_at")
            .is_ok(),
        "the fork runs on"
    );
}

/// FR-90 P2g-4b — a fork whose start cannot reach its device (back, once
/// its copy caught up, as a build that starts no fork) is not made, and the
/// copy it was to be made from goes then, not at the session's next tip.
#[tokio::test]
async fn a_member_a_fork_is_never_started_on_lets_its_copy_go() {
    let app = fork_app().await;
    let (mut m, mut c) = joinable_with(&app, "forknever", TAKES_A_COPY_TO_FORK_AND_PURGES).await;
    let sid = m.sid.clone();
    fork_joined(&app, &mut m, &mut c, "/srv/forknever-c", false).await;
    // b follows the primary to seq 9, as a member does: min holds without c
    // only once b holds what c is about to (P2k-2).
    send(&mut m.b.ws, tip_with_checkpoint(&sid, 9, 5)).await;
    let b = m.b.agent_id.clone();
    wait_stored(&app, &sid, "b's next tip", |s| {
        member_row(s, &b)
            .get_document("tip")
            .is_ok_and(|t| t.get_i64("seq") == Ok(9))
    })
    .await;

    // Back as a build that starts no fork, where its copy catches up.
    let (token, machine, c_id) = (c.token.clone(), c.machine.clone(), c.agent_id.clone());
    drop(c.ws);
    wait_offline(&app, &m.seeded, &c_id).await;
    let mut ws = connect(&app, &token, &machine, TAKES_A_COPY_AND_PURGES).await;
    send(&mut ws, tip_at(&sid, 1, 9, "ab")).await;

    // The fork's start could not go: the fork is lost, and the copy goes.
    let told = read_until(&mut ws, "rc:hive.purge")
        .await
        .expect("the copy no fork will be made from is purged");
    assert_eq!(told["session_id"], sid, "{told}");
    let forks = forks_of(&app, &sid).await;
    assert_eq!(forks.len(), 1, "{forks:?}");
    assert_eq!(forks[0].get_str("status").ok(), Some("lost"), "{forks:?}");
    assert_eq!(
        purging_of(&app, &sid, &c_id).await.as_deref(),
        told["purge_id"].as_str(),
        "its row names the purge"
    );
}

/// `device`'s row of `sid` names `fork` as the fork made from its copy.
async fn name_fork(app: &TestApp, sid: &str, device: &str, fork: ObjectId) {
    let r = app
        .db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! {
                "_id": ObjectId::parse_str(sid).unwrap(),
                "replicaset.members.device_id": ObjectId::parse_str(device).unwrap(),
            },
            doc! { "$set": { "replicaset.members.$.forking": fork } },
        )
        .await
        .unwrap();
    assert_eq!(r.modified_count, 1, "the row names the fork");
}

/// FR-90 P2g-4b — a fork whose record was never made (the server stopped
/// between the move's end and the fork's record) holds the copy it was to be
/// made from for a start's redelivery window, and no longer: once that has
/// passed, the session's next tip lets the member go.
#[tokio::test]
async fn a_fork_never_made_holds_its_copy_only_for_a_starts_redelivery_window() {
    let app = replicaset_app().await;
    let mut l = leaving(&app, "forkunmade").await;
    let (tid, admin, sid) = (l.tid.clone(), l.admin.clone(), l.sid.clone());
    tag(&app, &tid, &admin, &l.m.agent_id, &[]).await;
    assert_eq!(
        stored_member(&stored(&app, &sid).await, &l.m.agent_id).1,
        "leaving"
    );
    name_fork(&app, &sid, &l.m.agent_id, ObjectId::new()).await;

    // Another takes its place and says where its copy ends: min holds
    // without m, which keeps its copy for a fork that may yet be made.
    tag(&app, &tid, &admin, &l.n.agent_id, &["prod"]).await;
    read_until(&mut l.n.ws, "rc:hive.replica.join")
        .await
        .expect("n's join");
    answer_join(&app, &tid, &admin, &sid, &mut l.n).await;
    send(&mut l.n.ws, tip_at(&sid, 1, 3, "ab")).await;
    let n_id = l.n.agent_id.clone();
    wait_stored(&app, &sid, "n's tip", |s| {
        member_row(s, &n_id).contains_key("tip")
    })
    .await;
    assert!(
        !device_hears(&mut l.m.ws, "rc:hive.purge", Duration::from_millis(500)).await,
        "a fork that may yet be made keeps the copy"
    );
    assert!(purges_of(&app, &sid).await.is_empty(), "no purge is issued");

    // Named a redelivery window ago, it never will be: the next tip lets m go.
    let secs = u32::try_from(
        bson::DateTime::now().timestamp_millis() / 1000
            - hive_limits::START_REDELIVERY_WINDOW_SECS
            - 60,
    )
    .unwrap();
    let mut old = ObjectId::new().bytes();
    old[..4].copy_from_slice(&secs.to_be_bytes());
    name_fork(&app, &sid, &l.m.agent_id, ObjectId::from_bytes(old)).await;
    send(&mut l.a.ws, tip_at(&sid, 1, 4, "ac")).await;
    let told = read_until(&mut l.m.ws, "rc:hive.purge")
        .await
        .expect("past the window, the copy goes");
    assert_eq!(told["session_id"], sid, "{told}");
}

/// FR-90 P2g-4b — a device a fork is being made from, removed while the
/// fork's start is out, is let go at once: its removal ends every session
/// on it first, the fork among them, so nothing holds its copy (it was told
/// to purge everything, P2g-4a). Its row goes, its part of the purge closed
/// `device_removed`.
#[tokio::test]
async fn a_member_a_fork_is_made_from_that_is_removed_is_let_go_at_once() {
    let app = fork_app().await;
    let (mut m, mut c) = joinable_with(&app, "forkgone", TAKES_A_COPY_TO_FORK_AND_PURGES).await;
    let (tid, admin, sid) = (m.tid.clone(), m.admin.clone(), m.sid.clone());
    fork_joined(&app, &mut m, &mut c, "/srv/forkgone-c", true).await;
    read_until(&mut c.ws, "rc:hive.start")
        .await
        .expect("the fork's start, once the copy caught up");
    // b follows the primary to seq 9, as a member does: min holds without c
    // only once b holds what c holds (P2k-2).
    send(&mut m.b.ws, tip_with_checkpoint(&sid, 9, 5)).await;
    let b = m.b.agent_id.clone();
    wait_stored(&app, &sid, "b's next tip", |s| {
        member_row(s, &b)
            .get_document("tip")
            .is_ok_and(|t| t.get_i64("seq") == Ok(9))
    })
    .await;
    let c_id = c.agent_id.clone();
    wait_stored(&app, &sid, "its row names the fork", |s| {
        member_row(s, &c_id).contains_key("forking")
    })
    .await;

    remove_device(&app, &tid, &admin, &c_id).await;
    wait_stored(&app, &sid, "the removed device's row goes", |s| {
        member_row(s, &c_id).is_empty()
    })
    .await;
    let all = purges_of(&app, &sid).await;
    assert_eq!(all.len(), 1, "{all:?}");
    let part = all[0].get_array("devices").unwrap()[0]
        .as_document()
        .unwrap()
        .clone();
    assert_eq!(
        (
            all[0].get_str("reason").ok(),
            part.get_str("state").ok(),
            part.get_str("closed").ok()
        ),
        (Some("leaving"), Some("closed"), Some("device_removed")),
        "{all:?}"
    );
}

// ─── P2i-2 — a search, the server's half ────────────────────────────────────

/// What an archive replica that searches advertises: it serves views (whose
/// frames carry a search's peer), holds copies, offers itself as an archive,
/// and answers a search over what it holds.
const SEARCHES: &[&str] = &[
    "exec",
    "hive",
    "hive-view",
    "hive-replica",
    "hive-archive",
    "hive-search",
];

/// An organization on Pro with copies on: a primary that runs sessions, and
/// archive replicas the policy designates in this order, each connected with
/// its own capabilities.
struct Searchable {
    app: TestApp,
    seeded: SeededTenant,
    tid: String,
    admin: String,
    primary: Device,
    archives: Vec<Device>,
}

async fn searchable(tag: &str, archives: &[&[&str]]) -> Searchable {
    let app = replicaset_app().await;
    let seeded = app.seed_tenant(tag).await;
    on_pro(&app, &seeded).await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let primary = device(&app, &seeded, &format!("{tag}-primary"), VIEWS_HIVE).await;
    let mut devices = Vec::new();
    for (i, caps) in archives.iter().enumerate() {
        devices.push(device(&app, &seeded, &format!("{tag}-archive-{i}"), caps).await);
    }
    let mut policy = a_policy(0);
    policy["replicaset"] = json!({
        "min": 2, "max": 2 + archives.len(), "archive": true,
        "prefer": ["owner_devices"], "restricted_tags": [],
    });
    policy["archive_devices"] = json!(
        devices
            .iter()
            .map(|d| d.agent_id.clone())
            .collect::<Vec<_>>()
    );
    let (code, p) = put_policy(&app, &tid, &admin, &policy).await;
    assert_eq!(code, 200, "{p}");
    Searchable {
        app,
        seeded,
        tid,
        admin,
        primary,
        archives: devices,
    }
}

/// A session the admin starts on the primary, whose copy each archive
/// replica in `holders` (indexes into `archives`) took; its id. The others'
/// joins go unanswered: pending, they hold nothing.
async fn held_session(s: &mut Searchable, folder: &str, holders: &[usize]) -> String {
    let started = started(&s.app, &s.tid, &s.admin, &mut s.primary, folder).await;
    let sid = started["id"].as_str().unwrap().to_string();
    for &i in holders {
        let a = &mut s.archives[i];
        loop {
            let join = read_until(&mut a.ws, "rc:hive.replica.join")
                .await
                .expect("the archive replica is asked to join");
            if join["session_id"] == sid.as_str() {
                break;
            }
        }
        joined(&mut a.ws, &sid).await;
        let id = a.agent_id.clone();
        wait_stored(&s.app, &sid, "the archive replica took its copy", |d| {
            stored_member(d, &id).1 == "joined"
        })
        .await;
    }
    sid
}

/// Set a session's last activity, so the order a grant names is known.
async fn active_at(app: &TestApp, sid: &str, millis_ago: i64) {
    let at = bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - millis_ago);
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(sid).unwrap() },
            doc! { "$set": { "updated_at": at } },
        )
        .await
        .unwrap();
}

/// The `search` audit rows of `tid`, in order: (outcome, reason, sessions),
/// each row's keys checked to hold nothing a search could have said.
async fn search_audit(app: &TestApp, tid: &str) -> Vec<(String, String, Option<i64>)> {
    let mut rows = app
        .db
        .collection::<Document>("hive_audit")
        .find(doc! { "tenant_id": ObjectId::parse_str(tid).unwrap(), "action": "search" })
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap();
    let allowed = [
        "_id",
        "tenant_id",
        "user_id",
        "device_id",
        "action",
        "outcome",
        "reason",
        "sessions",
        "at",
    ];
    let mut out = Vec::new();
    while let Some(d) = rows.next().await {
        let d = d.unwrap();
        for k in d.keys() {
            assert!(
                allowed.contains(&k.as_str()),
                "a search's row holds {k}: {d:?}"
            );
        }
        out.push((
            d.get_str("outcome").unwrap().to_string(),
            d.get_str("reason").unwrap_or("").to_string(),
            d.get("sessions")
                .and_then(|b| b.as_i32().map(i64::from).or_else(|| b.as_i64())),
        ));
    }
    out
}

/// Wait until `tid` holds `want` `search` audit rows. A grant's row is
/// written once its push to the device returned, so a test that has just read
/// the grant off the device's socket can be ahead of it, and so can one that
/// read the device's refusal, which its answer's handler relays (both
/// measured on a loaded host, 2026-10-16).
async fn wait_search_audit(app: &TestApp, tid: &str, want: u64) {
    let filter = doc! { "tenant_id": ObjectId::parse_str(tid).unwrap(), "action": "search" };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let n = app
            .db
            .collection::<Document>("hive_audit")
            .count_documents(filter.clone())
            .await
            .unwrap();
        if n >= want || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// FR-90 P2i-2 — a search grant names what its asker may read and the
/// archive replica holds a copy of, and nothing else: a session the asker is
/// not in the room of, or whose copy the archive replica never took, is left
/// out; the most recently active first. The browser is told it may dial only
/// once the device confirmed it, with how many sessions it names; the audit
/// says how many, and never a word of what was searched.
#[tokio::test]
async fn a_search_names_only_what_its_asker_may_read_and_the_archive_holds() {
    let mut s = searchable("srchname", &[SEARCHES]).await;
    let (tid, admin) = (s.tid.clone(), s.admin.clone());
    let member = s.seeded.member.id.clone();
    let own = held_session(&mut s, "/srv/own", &[0]).await;
    let shared = held_session(&mut s, "/srv/shared", &[0]).await;
    let unheld = held_session(&mut s, "/srv/unheld", &[]).await;
    // A session the archive replica runs itself: its row there is the
    // primary's, no copy, and it searches only copies.
    let runs_here = started(&s.app, &tid, &admin, &mut s.archives[0], "/srv/runs-here").await;
    assert_eq!(
        members(&runs_here),
        [(s.archives[0].agent_id.clone(), "primary".to_string())],
        "{runs_here}"
    );
    for sid in [&shared, &unheld] {
        let (code, body) = set_part(&s.app, &tid, &admin, sid, &member, "reader").await;
        assert_eq!(code, 200, "{body}");
    }
    active_at(&s.app, &own, 60_000).await;
    active_at(&s.app, &shared, 1_000).await;

    // The member reads `shared` and `unheld`; the archive holds `own` and
    // `shared`: one session.
    let mut mws = user_ws(&s.app, &s.seeded.member.access_token).await;
    user_send(
        &mut mws,
        "hive:search.open",
        json!({"tenant_id": tid, "ref": "m1"}),
    )
    .await;
    let grant = read_until(&mut s.archives[0].ws, "rc:hive.search.grant")
        .await
        .expect("the archive replica is asked");
    assert_eq!(
        grant["sessions"],
        json!([shared]),
        "the member's: only what they may read and the archive holds: {grant}"
    );
    assert_eq!(grant["user_id"], member);
    assert_eq!(grant["ttl_secs"], 600);
    assert!(
        grant.get("q").is_none() && grant.get("query").is_none(),
        "{grant}"
    );
    let gid = grant["grant_id"].as_str().unwrap().to_string();
    assert!(
        user_read_for(&mut mws, "hive:search.ready", Duration::from_millis(400))
            .await
            .is_none(),
        "the browser was told to dial before the device confirmed"
    );
    send(
        &mut s.archives[0].ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": gid}),
    )
    .await;
    let ready = user_read(&mut mws, "hive:search.ready")
        .await
        .expect("ready once the device confirmed");
    assert_eq!(
        (
            ready["grant_id"].as_str(),
            ready["ref"].as_str(),
            ready["sessions"].as_u64()
        ),
        (Some(gid.as_str()), Some("m1"), Some(1)),
        "{ready}"
    );
    assert!(!ready["ice_servers"].as_array().unwrap().is_empty());
    assert!(
        ready.get("session_id").is_none(),
        "a search views no session: {ready}"
    );

    // The peer rides the view's frames, by the grant.
    user_send(
        &mut mws,
        "hive:view.offer",
        json!({"grant_id": gid, "sdp": "v=0 offer"}),
    )
    .await;
    let offer = read_until(&mut s.archives[0].ws, "rc:hive.view.offer")
        .await
        .expect("the offer reaches the archive replica");
    assert_eq!(offer["sdp"], "v=0 offer");
    assert_eq!(offer["ice_servers"], ready["ice_servers"]);

    // The owner reads both of theirs it holds, the most recently active first.
    let mut aws = user_ws(&s.app, &admin).await;
    user_send(&mut aws, "hive:search.open", json!({"tenant_id": tid})).await;
    let grant = read_until(&mut s.archives[0].ws, "rc:hive.search.grant")
        .await
        .unwrap();
    assert_eq!(
        grant["sessions"],
        json!([shared, own]),
        "the owner's copies, the most recently active first, and never one it runs: {grant}"
    );

    wait_search_audit(&s.app, &tid, 2).await;
    assert_eq!(
        search_audit(&s.app, &tid).await,
        [
            ("sent".to_string(), String::new(), Some(1)),
            ("sent".to_string(), String::new(), Some(2)),
        ],
        "the audit says how many sessions each named"
    );
}

/// FR-90 P2i-2 — every way a search is refused, each in its own word: an
/// organization the asker is not in, or where nothing is copied, answers as a
/// bogus one does; no designated archive replica that searches online here;
/// one that holds nothing the asker may read; and the device's own word,
/// with its detail.
#[tokio::test]
async fn a_search_is_refused_where_there_is_nothing_to_search() {
    async fn refused(ws: &mut UserWs, tid: &str) -> Value {
        user_send(
            ws,
            "hive:search.open",
            json!({"tenant_id": tid, "ref": "r"}),
        )
        .await;
        user_read(ws, "hive:search.refused").await.expect("refused")
    }

    // Nothing is copied on this server.
    let off = hive_app().await;
    let seeded = off.seed_tenant("srchoff").await;
    let mut ws = user_ws(&off, &seeded.admin.access_token).await;
    assert_eq!(
        refused(&mut ws, &seeded.tenant_id).await["reason"],
        "not_found",
        "nothing is copied on this server"
    );

    // An archive replica connected without `hive-search`: it holds copies
    // and offers itself, but a build before P2i-1 drops a search grant.
    let mut s = searchable("srchrefuse", &[&SEARCHES[..5]]).await;
    let tid = s.tid.clone();
    held_session(&mut s, "/srv/a", &[0]).await;
    let mut ws = user_ws(&s.app, &s.admin).await;
    assert_eq!(
        refused(&mut ws, &tid).await["reason"],
        "no_archive_replica",
        "a build without hive-search is never asked"
    );
    assert!(
        !device_hears(
            &mut s.archives[0].ws,
            "rc:hive.search.grant",
            Duration::from_millis(300)
        )
        .await
    );

    // Someone outside the organization, and a bogus organization.
    let other = s.app.seed_tenant("srchother").await;
    let mut ows = user_ws(&s.app, &other.admin.access_token).await;
    assert_eq!(
        refused(&mut ows, &tid).await["reason"],
        "not_found",
        "someone outside the organization"
    );
    assert_eq!(
        refused(&mut ows, "not-an-id").await["reason"],
        "not_found",
        "a bogus organization"
    );

    // An archive replica that searches, holding nothing the member may read.
    let mut s = searchable("srchnothing", &[SEARCHES]).await;
    let tid = s.tid.clone();
    held_session(&mut s, "/srv/b", &[0]).await;
    let mut mws = user_ws(&s.app, &s.seeded.member.access_token).await;
    assert_eq!(
        refused(&mut mws, &tid).await["reason"],
        "no_session",
        "nothing the member may read"
    );
    assert!(
        !device_hears(
            &mut s.archives[0].ws,
            "rc:hive.search.grant",
            Duration::from_millis(300)
        )
        .await,
        "nothing to search is sent to no device"
    );

    // The device's own word, with its detail, reaches the browser.
    let mut aws = user_ws(&s.app, &s.admin).await;
    user_send(
        &mut aws,
        "hive:search.open",
        json!({"tenant_id": tid, "ref": "a1"}),
    )
    .await;
    let grant = read_until(&mut s.archives[0].ws, "rc:hive.search.grant")
        .await
        .unwrap();
    send(
        &mut s.archives[0].ws,
        json!({"t": "rc:hive.view.grant_ack", "grant_id": grant["grant_id"],
               "refused": "hive_disabled", "detail": "not an archive\nreplica"}),
    )
    .await;
    let r = user_read(&mut aws, "hive:search.refused")
        .await
        .expect("the device's refusal reaches the browser as a search's");
    assert_eq!(
        (r["ref"].as_str(), r["reason"].as_str()),
        (Some("a1"), Some("hive_disabled")),
        "{r}"
    );
    assert!(
        r["message"].as_str().is_some_and(|m| !m.contains('\n')),
        "the detail, clamped to one line: {r}"
    );

    // The device's refusal reaches the browser through its answer's handler,
    // which can run before the open writes its `sent` row.
    wait_search_audit(&s.app, &tid, 2).await;
    assert_eq!(
        search_audit(&s.app, &tid).await,
        [
            ("refused".to_string(), "no_session".to_string(), Some(0)),
            ("sent".to_string(), String::new(), Some(1)),
        ],
        "each refusal audited in its own word, and the grant the device refused as sent"
    );
}

/// FR-90 P2i-2 — a search grant ends when its user no longer reads what it
/// names: taken out of a session's room, at once; out of the room by any
/// other road, at its next renewal. A change of their part that leaves them
/// reading it ends nothing, and a renewal that finds them reading renews.
#[tokio::test]
async fn a_search_grant_ends_when_its_user_no_longer_reads_what_it_names() {
    let mut s = searchable("srchends", &[SEARCHES]).await;
    let (tid, admin) = (s.tid.clone(), s.admin.clone());
    let member = s.seeded.member.id.clone();
    let shared = held_session(&mut s, "/srv/shared", &[0]).await;
    let (code, body) = set_part(&s.app, &tid, &admin, &shared, &member, "reader").await;
    assert_eq!(code, 200, "{body}");
    let mut mws = user_ws(&s.app, &s.seeded.member.access_token).await;

    /// A search the device confirmed; its grant id.
    async fn ready_search(mws: &mut UserWs, dev: &mut Device, tid: &str) -> String {
        user_send(mws, "hive:search.open", json!({"tenant_id": tid})).await;
        let grant = read_until(&mut dev.ws, "rc:hive.search.grant")
            .await
            .expect("the archive replica is asked");
        let gid = grant["grant_id"].as_str().unwrap().to_string();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.view.grant_ack", "grant_id": gid}),
        )
        .await;
        user_read(mws, "hive:search.ready").await.expect("ready");
        gid
    }

    // Driving it now, still reading it: the search goes on, and renews.
    let gid = ready_search(&mut mws, &mut s.archives[0], &tid).await;
    grant_hive_run_to_member(&s.app, &s.seeded).await;
    let (code, body) = set_part(&s.app, &tid, &admin, &shared, &member, "driver").await;
    assert_eq!(code, 200, "{body}");
    assert!(
        user_read_for(&mut mws, "hive:view.closed", Duration::from_millis(500))
            .await
            .is_none(),
        "a change of part that leaves them reading ends no search"
    );
    user_send(&mut mws, "hive:view.renew", json!({"grant_id": gid})).await;
    let renewed = user_read(&mut mws, "hive:view.renewed")
        .await
        .expect("a renewal that finds them reading renews");
    assert_eq!(renewed["grant_id"], gid);
    let renew = read_until(&mut s.archives[0].ws, "rc:hive.view.renew")
        .await
        .unwrap();
    assert_eq!(renew["grant_id"], gid);

    // Taken out of the room: the search that names it ends at once.
    let resp = s
        .app
        .auth_delete(&participant_url(&tid, &shared, Some(&member)), &admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let closed = user_read(&mut mws, "hive:view.closed")
        .await
        .expect("the removal ends the search at once");
    assert_eq!(
        (closed["grant_id"].as_str(), closed["reason"].as_str()),
        (Some(gid.as_str()), Some("removed")),
        "{closed}"
    );
    let told = read_until(&mut s.archives[0].ws, "rc:hive.view.close")
        .await
        .unwrap();
    assert_eq!(told["grant_id"], gid);

    // Back in, then out of the room by another road: the next renewal finds
    // it, closes the grant, and tells the device.
    let (code, body) = set_part(&s.app, &tid, &admin, &shared, &member, "reader").await;
    assert_eq!(code, 200, "{body}");
    let gid = ready_search(&mut mws, &mut s.archives[0], &tid).await;
    let room = stored(&s.app, &shared)
        .await
        .get_object_id("room_id")
        .unwrap();
    s.app
        .db
        .collection::<Document>("room_members")
        .delete_many(doc! { "room_id": room, "user_id": ObjectId::parse_str(&member).unwrap() })
        .await
        .unwrap();
    user_send(&mut mws, "hive:view.renew", json!({"grant_id": gid})).await;
    let closed = user_read(&mut mws, "hive:view.closed")
        .await
        .expect("a renewal finds them out of the room");
    assert_eq!(
        (closed["grant_id"].as_str(), closed["reason"].as_str()),
        (Some(gid.as_str()), Some("not_a_member")),
        "{closed}"
    );
    let told = read_until(&mut s.archives[0].ws, "rc:hive.view.close")
        .await
        .unwrap();
    assert_eq!(told["grant_id"], gid);
}

/// FR-90 P2i-2 — of several archive replicas that search, the one that holds
/// the most of what the asker may read is asked; among equals, the first in
/// the policy's order.
#[tokio::test]
async fn the_archive_replica_that_holds_the_most_is_asked() {
    let mut s = searchable("srchmost", &[SEARCHES, SEARCHES]).await;
    let tid = s.tid.clone();
    let first = held_session(&mut s, "/srv/one", &[0, 1]).await;
    let mut ws = user_ws(&s.app, &s.admin).await;

    // Equal: the first designated.
    user_send(&mut ws, "hive:search.open", json!({"tenant_id": tid})).await;
    let grant = read_until(&mut s.archives[0].ws, "rc:hive.search.grant")
        .await
        .expect("the first designated, among equals");
    assert_eq!(grant["sessions"], json!([first]));
    user_send(
        &mut ws,
        "hive:view.close",
        json!({"grant_id": grant["grant_id"]}),
    )
    .await;

    // The second holds one more.
    let second = held_session(&mut s, "/srv/two", &[1]).await;
    active_at(&s.app, &first, 60_000).await;
    user_send(&mut ws, "hive:search.open", json!({"tenant_id": tid})).await;
    let grant = read_until(&mut s.archives[1].ws, "rc:hive.search.grant")
        .await
        .expect("the one that holds the most");
    assert_eq!(grant["sessions"], json!([second, first]));
    assert!(
        !device_hears(
            &mut s.archives[0].ws,
            "rc:hive.search.grant",
            Duration::from_millis(300)
        )
        .await
    );
}

/// FR-90 P2i-2 — the SPA's question says whether the organization can be
/// searched: copies on, and a designated archive replica whose row says it
/// searches and is not offline. Its rows, so a pod without its socket answers
/// alike.
#[tokio::test]
async fn the_hive_question_says_whether_the_organization_can_be_searched() {
    async fn search_flag(app: &TestApp, tid: &str, token: &str) -> Value {
        let (code, body) = status_and_json(
            app.auth_get(&format!("/api/tenant/{tid}/hive"), token)
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(code, 200, "{body}");
        body["search"].clone()
    }

    // Nothing is copied on this server, whatever a policy left from when it
    // was says: an archive replica that searches, connected and designated.
    let off = hive_app().await;
    let seeded = off.seed_tenant("srchflagoff").await;
    let left = device(&off, &seeded, "srchflagoff-archive", SEARCHES).await;
    off.db
        .collection::<Document>("hive_policies")
        .insert_one(doc! {
            "tenant_id": ObjectId::parse_str(&seeded.tenant_id).unwrap(),
            "replicaset": { "min": 2, "max": 3, "archive": true,
                            "prefer": ["owner_devices"], "restricted_tags": [] },
            "retention_days": 30,
            "archive_devices": [ObjectId::parse_str(&left.agent_id).unwrap()],
            "revision": 1,
        })
        .await
        .unwrap();
    assert_eq!(
        search_flag(&off, &seeded.tenant_id, &seeded.admin.access_token).await,
        json!(false),
        "nothing is copied here, whatever a policy left says"
    );

    let s = searchable("srchflag", &[SEARCHES]).await;
    let token = s.seeded.member.access_token.clone();
    assert_eq!(
        search_flag(&s.app, &s.tid, &token).await,
        json!(true),
        "a designated archive replica that searches, online"
    );

    // Its row says it no longer searches: no box.
    let rpc: Vec<String> = SEARCHES[..5].iter().map(|w| w.to_string()).collect();
    set_device(
        &s.app,
        &s.archives[0].agent_id,
        doc! { "capabilities.rpc": rpc },
    )
    .await;
    assert_eq!(
        search_flag(&s.app, &s.tid, &token).await,
        json!(false),
        "its row no longer says it searches"
    );

    // A row that searches but went quiet long ago, its socket gone: no box.
    let quiet = stored_device(&s.app, &s.seeded, "srchflag-quiet", SEARCHES).await;
    let long_ago =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 3_600_000);
    set_device(
        &s.app,
        &quiet,
        doc! { "status": "offline", "last_seen_at": long_ago },
    )
    .await;
    let mut policy = a_policy(1);
    policy["replicaset"]["archive"] = json!(true);
    policy["archive_devices"] = json!([quiet]);
    let (code, p) = put_policy(&s.app, &s.tid, &s.admin, &policy).await;
    assert_eq!(code, 200, "{p}");
    assert_eq!(
        search_flag(&s.app, &s.tid, &token).await,
        json!(false),
        "a row that went quiet long ago"
    );
}

/// FR-90 P2i-2 — a search is paced after the identity gates: one browser
/// connection holds at most four grants, a search's counted with a view's;
/// and a person opens at most [`search_limits::OPEN_RATE_PER_MINUTE`]
/// searches a minute in an organization. Each refusal is audited.
#[tokio::test]
async fn a_search_is_paced_per_connection_and_per_minute() {
    let mut s = searchable("srchpace", &[SEARCHES]).await;
    let tid = s.tid.clone();
    held_session(&mut s, "/srv/p", &[0]).await;
    let mut ws = user_ws(&s.app, &s.admin).await;

    let mut grants = Vec::new();
    for _ in 0..4 {
        user_send(&mut ws, "hive:search.open", json!({"tenant_id": tid})).await;
        let g = read_until(&mut s.archives[0].ws, "rc:hive.search.grant")
            .await
            .expect("granted");
        grants.push(g["grant_id"].as_str().unwrap().to_string());
    }
    user_send(&mut ws, "hive:search.open", json!({"tenant_id": tid})).await;
    let r = user_read(&mut ws, "hive:search.refused")
        .await
        .expect("a fifth grant on one connection is refused");
    assert_eq!(r["reason"], "too_many_views", "{r}");

    // Closing them frees the connection; the minute's opens run out.
    for g in &grants {
        user_send(&mut ws, "hive:view.close", json!({"grant_id": g})).await;
    }
    let rate = meshharbor_remote_control::hive::search_limits::OPEN_RATE_PER_MINUTE;
    for _ in 4..rate {
        user_send(&mut ws, "hive:search.open", json!({"tenant_id": tid})).await;
        let g = read_until(&mut s.archives[0].ws, "rc:hive.search.grant")
            .await
            .expect("granted within the minute");
        user_send(
            &mut ws,
            "hive:view.close",
            json!({"grant_id": g["grant_id"]}),
        )
        .await;
    }
    user_send(&mut ws, "hive:search.open", json!({"tenant_id": tid})).await;
    let r = user_read(&mut ws, "hive:search.refused")
        .await
        .expect("an open past the minute's is refused");
    assert_eq!(r["reason"], "rate_limited", "{r}");

    let refusals: Vec<String> = search_audit(&s.app, &tid)
        .await
        .into_iter()
        .filter(|(o, _, _)| o == "refused")
        .map(|(_, r, _)| r)
        .collect();
    assert_eq!(refusals, ["too_many_views", "rate_limited"]);
}

// ─── FR-90 P3-2b — a session's vault role ──────────────────────────────────

/// Hive and the vault both on.
async fn role_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.modules.vault = true;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// `POST …/hive/session` naming a vault role.
async fn post_start_role(
    app: &TestApp,
    tid: &str,
    token: &str,
    device_id: &str,
    folder: &str,
    role: &str,
) -> Value {
    for _ in 0..40 {
        let resp = app
            .auth_post(&format!("/api/tenant/{tid}/hive/session"), token)
            .json(&json!({ "device_id": device_id, "folder": folder, "role": role }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "start");
        let body: Value = resp.json().await.unwrap();
        // The same registration race `start` retries past.
        let racing = body["outcome"] == "refused"
            && matches!(
                body["reason"].as_str(),
                Some("device_offline" | "device_unsupported")
            );
        if !racing {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the Hub never recorded the device as running Hive sessions");
}

/// A vault role `dev`, and one policy: `user` takes it on a device tagged
/// `build`, and nowhere else.
async fn dev_on_build_boxes(app: &TestApp, tid: &str, token: &str, user: &str) -> String {
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/vault/role"), token)
        .json(&json!({ "name": "dev" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "role");
    let text = format!(
        r#"permit (principal == MeshHarbor::User::"{user}", action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev") when {{ context.device.tags.contains("build") }};"#
    );
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/vault/policy"), token)
        .json(&json!({ "name": "dev-on-build-boxes", "text": text }))
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(code, 201, "{body}");
    body["id"].as_str().unwrap().to_string()
}

async fn tag_device(app: &TestApp, agent_id: &str, tags: &[&str]) {
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(agent_id).unwrap() },
            doc! { "$set": { "tags": tags } },
        )
        .await
        .unwrap();
}

/// The vault's `role:assume` rows, in order: (op, decision, reason).
async fn role_decisions(app: &TestApp) -> Vec<(String, String, String)> {
    use futures::TryStreamExt;
    let mut cursor = app
        .db
        .collection::<Document>("vault_audit")
        .find(doc! { "action": "role:assume" })
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(d) = cursor.try_next().await.unwrap() {
        out.push((
            d.get_str("op").unwrap().to_string(),
            d.get_str("decision").unwrap().to_string(),
            d.get_str("reason").unwrap().to_string(),
        ));
    }
    out
}

/// FR-90 P3-2b — a start that names a role gets it only as the vault's
/// policies allow it, for that person, on that device: refused on a laptop,
/// allowed on a build box (its tag lowercased), refused for a role the
/// organization has not got. A start that names none never asks. Every
/// decision is the vault's, recorded with the request it decided.
#[tokio::test]
async fn a_start_takes_a_role_only_as_the_vault_allows_it_on_that_device() {
    let app = role_app().await;
    let seeded = app.seed_tenant("hiverole").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let mut dev = device(&app, &seeded, "hive-role", RUNS_HIVE).await;
    let pid = dev_on_build_boxes(&app, &tid, &token, &seeded.admin.id).await;

    // Not a build box: refused before anything is made or sent.
    let body = post_start_role(&app, &tid, &token, &dev.agent_id, "/srv/a", "dev").await;
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("role_refused")),
        "{body}"
    );
    assert!(body["session"].is_null(), "{body}");
    assert_eq!(
        app.db
            .collection::<Document>("agent_sessions")
            .count_documents(doc! {})
            .await
            .unwrap(),
        0
    );

    // A build box: the device's tag as an admin typed it, `Build`.
    tag_device(&app, &dev.agent_id, &["Build"]).await;
    let caller = post_start_role(&app, &tid, &token, &dev.agent_id, "/srv/b", "dev");
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives rc:hive.start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
        frame
    };
    let (body, _frame) = tokio::join!(caller, target);
    assert_eq!(body["outcome"], "accepted", "{body}");
    let sid = body["session"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        stored(&app, &sid).await.get_str("vault_role").ok(),
        Some("dev")
    );

    // A role the organization has not got.
    let body = post_start_role(&app, &tid, &token, &dev.agent_id, "/srv/c", "ghost").await;
    assert_eq!(body["reason"], "role_refused", "{body}");

    // No role: the vault is not asked, and the record holds none.
    let caller = start(&app, &tid, &token, &dev.agent_id, "/srv/d");
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start").await.unwrap();
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
    };
    let (body, ()) = tokio::join!(caller, target);
    let plain = body["session"]["id"].as_str().unwrap().to_string();
    assert!(stored(&app, &plain).await.get_str("vault_role").is_err());

    assert_eq!(
        role_decisions(&app).await,
        [
            (
                "start".to_string(),
                "deny".to_string(),
                "default_deny".to_string()
            ),
            ("start".to_string(), "allow".to_string(), pid.clone()),
            (
                "start".to_string(),
                "deny".to_string(),
                "unknown_role".to_string()
            ),
        ]
    );
    // The allowed one carries the request as decided: the tag lowercased.
    let row = app
        .db
        .collection::<Document>("vault_audit")
        .find_one(doc! { "action": "role:assume", "decision": "allow" })
        .await
        .unwrap()
        .unwrap();
    let request = row.get_document("request").unwrap();
    assert_eq!(request.get_str("role").unwrap(), "dev");
    let device_facts = request.get_document("device").unwrap();
    assert_eq!(device_facts.get_str("os").unwrap(), "linux");
    assert_eq!(
        device_facts.get_array("tags").unwrap(),
        &vec![bson::Bson::String("build".into())]
    );
    assert_eq!(
        row.get_object_id("session_id").unwrap().to_hex(),
        sid,
        "the decision names the session it was for"
    );
}

/// With no vault mounted, a start that names a role is refused in words —
/// never started without the role it asked for. One that names none starts.
#[tokio::test]
async fn a_role_named_with_no_vault_is_refused() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hivenovault").await;
    let tid = seeded.tenant_id.clone();
    let token = seeded.admin.access_token.clone();
    let dev = device(&app, &seeded, "hive-novault", RUNS_HIVE).await;
    let body = post_start_role(&app, &tid, &token, &dev.agent_id, "/srv/a", "dev").await;
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("vault_unavailable")),
        "{body}"
    );
    assert!(
        body["message"].as_str().unwrap().contains("vault"),
        "{body}"
    );
}

/// A session that holds a role moves with it only as the vault allows it on
/// the device it moves TO: a teleport to a laptop is refused, to a build box
/// it goes ahead.
#[tokio::test]
async fn a_session_moves_with_its_role_only_where_the_vault_allows_it() {
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.modules.vault = true;
        s.hive.replicaset = true;
        s.hive.promote_prepare_secs = 4;
        s.hive.promote_join_secs = 6;
        s.hive.promote_drain_secs = 4;
        s.hive.promote_sync_secs = 4;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await;
    let mut m = teleportable(&app, "roleteleport", TELEPORT_TARGET).await;
    let pid = dev_on_build_boxes(&app, &m.tid, &m.admin, &m.admin_id).await;
    // The session took `dev` at its start (as the start test shows).
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&m.sid).unwrap() },
            doc! { "$set": { "vault_role": "dev" } },
        )
        .await
        .unwrap();

    let (code, body) = post_teleport(&app, &m.tid, &m.admin, &m.sid, &m.b.agent_id, None).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        (body["outcome"].as_str(), body["reason"].as_str()),
        (Some("refused"), Some("role_refused")),
        "{body}"
    );
    assert!(
        teleport_audit(&app, &m.sid)
            .await
            .contains(&("refused".to_string(), "role_refused".to_string())),
        "hive's own audit says why"
    );

    tag_device(&app, &m.b.agent_id, &["build"]).await;
    let (body, _prep) = teleport_answered(&app, &mut m, None, None).await;
    assert_eq!(body["outcome"], "teleporting", "{body}");

    assert_eq!(
        role_decisions(&app).await,
        [
            (
                "teleport".to_string(),
                "deny".to_string(),
                "default_deny".to_string()
            ),
            ("teleport".to_string(), "allow".to_string(), pid),
        ]
    );
}

/// Regression for loaded `hive_app()` runs: under CPU/DB load, `device()`,
/// `start()`, and `wait_offline()` together spend more than `test_settings()`'s
/// default 60-request burst (1 req/s refill) against one in-process server,
/// causing `tower_governor` to answer `wait_offline` with a plain-text 429 that
/// failed JSON decoding (`expected value at line 1 column 1`).
#[tokio::test]
async fn hive_app_sustains_loaded_polling_without_per_ip_429() {
    let app = hive_app().await;
    let seeded = app.seed_tenant("hiveloadpoll").await;
    let dev = device(&app, &seeded, "hive-load-poll", RUNS_HIVE).await;

    // Simulate ~2.5 s of 50 ms polling spent waiting for registration / status
    // under suite load before the disconnect poll runs.
    for _ in 0..55 {
        let resp = app
            .auth_get(
                &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, dev.agent_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    drop(dev.ws);
    wait_offline(&app, &seeded, &dev.agent_id).await;
}
