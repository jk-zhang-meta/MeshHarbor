// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-99 P1d — what a device reports about privacy mode (`rc:privacy.activity`),
//! through real servers, real WebSockets and a real MongoDB.
//!
//! A report lands in `privacy_activity` only for a session of THAT device whose
//! grant held `PRIVACY`. Another device, another org, or a session granted
//! without it is dropped. A `worker_exit` comes from the next process to start,
//! after its session ended, and the stored session row decides it the same
//! way. Every refusal has its positive control beside it, because a filter
//! that dropped everything would pass every "dropped" cell. A reason that is
//! not a short code is dropped while the row is kept.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const REMOTE_CONTROL: u64 = 1 << 25;

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Enroll a Windows device that serves privacy mode (its owner allowed it),
/// and connect it.
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
            "os": "windows",
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
        "os": "windows",
        "agent_version": "0.1.0",
        "displays": [{
            "index": 0, "name": "x", "width_px": 800, "height_px": 600,
            "scale": 1.0, "primary": true,
        }],
        "caps": {
            "hw_encoders": [],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": false,
            "supports_file_transfer": false,
            "max_simultaneous_sessions": 16,
            "input": ["arbiter"],
            "rpc": ["privacy-available", "privacy-mode"],
        },
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    (agent_id, ws)
}

/// A session for `permissions`, asked on a FRESH controller connection (a
/// second request on one socket coalesces onto its first session, #1045).
/// The connection is returned so the caller holds the session live.
async fn ask(
    app: &TestApp,
    token: &str,
    agent_id: &str,
    permissions: &str,
) -> (Ws, String, String) {
    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    let req = json!({
        "t": "rc:session.request",
        "agent_id": agent_id,
        "permissions": permissions,
    });
    ws.send(Message::Text(req.to_string().into()))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(500), ws.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match v.get("t").and_then(|t| t.as_str()) {
            Some("rc:session.created") => {
                let sid = v["session_id"].as_str().unwrap().to_string();
                let granted = v["permissions"].as_str().unwrap_or_default().to_string();
                return (ws, sid, granted);
            }
            Some("rc:error") => panic!("the request was refused outright: {v}"),
            _ => {}
        }
    }
    panic!("no rc:session.created within 5 s");
}

fn holds(granted: &str, bit: &str) -> bool {
    granted.split('|').any(|p| p.trim() == bit)
}

/// The session's row, once the audit sink has flushed its request (batched,
/// every 200 ms).
async fn session_row(app: &TestApp, seeded: &SeededTenant, session_id: &str) -> Value {
    for _ in 0..50 {
        let resp = app
            .client
            .get(app.url(&format!(
                "/api/tenant/{}/session/{}",
                seeded.tenant_id, session_id
            )))
            .bearer_auth(&seeded.admin.access_token)
            .send()
            .await
            .unwrap();
        if resp.status().is_success() {
            return resp.json().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("session {session_id} never got its row");
}

/// One `rc:privacy.activity`, as the agent sends it.
async fn report(ws: &mut Ws, session_id: &str, kind: &str, reason: Option<&str>) {
    let mut msg = json!({
        "t": "rc:privacy.activity",
        "session_id": session_id,
        "kind": kind,
    });
    if let Some(r) = reason {
        msg["reason"] = json!(r);
    }
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .unwrap();
}

async fn give_member(app: &TestApp, seeded: &SeededTenant, name: &str, mask: u64) {
    let role: Value = app
        .auth_post(
            &format!("/api/tenant/{}/role", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&json!({ "name": name, "permissions": mask }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_str().expect("a role id").to_string();
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                seeded.tenant_id, role_id, seeded.member.id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "assign {name}");
}

async fn activity(
    app: &TestApp,
    seeded: &SeededTenant,
    agent_id: &str,
    token: &str,
) -> (u16, Value) {
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/tenant/{}/privacy-activity/{}?per_page=100",
            seeded.tenant_id, agent_id
        )))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Poll until the device's trail reaches `total` rows, then give anything that
/// should have been dropped every chance to (wrongly) land.
async fn settle(app: &TestApp, seeded: &SeededTenant, agent_id: &str, total: u64) -> Value {
    for _ in 0..30 {
        let (status, body) = activity(app, seeded, agent_id, &seeded.admin.access_token).await;
        assert_eq!(status, 200, "{body}");
        if body["total"].as_u64() == Some(total) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, body) = activity(app, seeded, agent_id, &seeded.admin.access_token).await;
    assert_eq!(body["total"], total, "{body}");
    body
}

/// (kind, reason) of every row, oldest first.
fn trail(body: &Value) -> Vec<(String, Option<String>)> {
    let mut rows: Vec<(String, Option<String>)> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["kind"].as_str().unwrap().to_string(),
                r["reason"].as_str().map(str::to_string),
            )
        })
        .collect();
    rows.reverse();
    rows
}

#[tokio::test]
async fn privacy_activity_is_kept_only_for_a_session_that_could_curtain() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr99p1d").await;
    // FR-115 P3 — several sessions at once in one org: Free runs one.
    app.set_plan(&seeded.tenant_id, "business").await;
    let other = app.seed_tenant("fr99p1dx").await;
    let (a, mut a_ws) = connect_agent(&app, &seeded, "mach-fr99-p1d-a").await;
    let (b, mut b_ws) = connect_agent(&app, &seeded, "mach-fr99-p1d-b").await;
    let (_c, mut c_ws) = connect_agent(&app, &other, "mach-fr99-p1d-c").await;

    // A session granted PRIVACY, and one on the same device without it.
    let (owner_ws, with, granted) = ask(
        &app,
        &seeded.admin.access_token,
        &a,
        "VIEW | INPUT | PRIVACY",
    )
    .await;
    assert!(
        holds(&granted, "PRIVACY"),
        "the positive control needs the bit: {granted}"
    );
    give_member(&app, &seeded, "viewer", REMOTE_CONTROL).await;
    let (member_ws, without, granted) = ask(&app, &seeded.member.access_token, &a, "VIEW").await;
    assert!(!holds(&granted, "PRIVACY"), "{granted}");
    session_row(&app, &seeded, &with).await;
    session_row(&app, &seeded, &without).await;

    // Kept: four rows on the granted session.
    report(&mut a_ws, &with, "on", None).await;
    report(&mut a_ws, &with, "off", Some("controller")).await;
    report(&mut a_ws, &with, "refused", Some("unavailable")).await;
    // Not a code: a host that may be compromised tried to write text. The
    // fact is kept, the text is not.
    report(&mut a_ws, &with, "on", Some("covered by <b>IT</b>")).await;
    // Dropped: no PRIVACY in the grant, another device, another org.
    report(&mut a_ws, &without, "on", None).await;
    report(&mut b_ws, &with, "on", None).await;
    report(&mut c_ws, &with, "on", None).await;

    let body = settle(&app, &seeded, &a, 4).await;
    assert_eq!(
        trail(&body),
        [
            ("on".to_string(), None),
            ("off".to_string(), Some("controller".to_string())),
            ("refused".to_string(), Some("unavailable".to_string())),
            ("on".to_string(), None),
        ]
    );
    for row in body["items"].as_array().unwrap() {
        assert_eq!(row["session_id"].as_str(), Some(with.as_str()), "{row}");
        assert_eq!(
            row["controller_user_id"].as_str(),
            Some(seeded.admin.id.as_str()),
            "the SERVER's record of the controller: {row}"
        );
        assert!(row["at"].is_string(), "RFC 3339: {row}");
        let mut keys: Vec<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "at",
                "controller_user_id",
                "id",
                "kind",
                "reason",
                "session_id"
            ],
            "{row}"
        );
    }

    // Device B wrote nothing about A's session.
    let (_, rows_b) = activity(&app, &seeded, &b, &seeded.admin.access_token).await;
    assert_eq!(rows_b["total"], 0, "{rows_b}");
    // The trail is read under VIEW_REMOTE_AUDIT: the member, who holds only
    // REMOTE_CONTROL, is refused.
    let (status, _) = activity(&app, &seeded, &a, &seeded.member.access_token).await;
    assert_eq!(status, 403);
    drop((owner_ws, member_ws));
}

/// A worker killed with its curtain up cannot say so. The next process to
/// start reports `worker_exit`, after the session is gone, and the stored row
/// decides: kept for a session granted `PRIVACY`, dropped for one without.
#[tokio::test]
async fn a_worker_exit_is_kept_after_its_session_ended() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr99p1de").await;
    // FR-115 P3 — several sessions at once in one org: Free runs one.
    app.set_plan(&seeded.tenant_id, "business").await;
    let (a, mut a_ws) = connect_agent(&app, &seeded, "mach-fr99-p1d-e").await;

    let (owner_ws, with, granted) = ask(
        &app,
        &seeded.admin.access_token,
        &a,
        "VIEW | INPUT | PRIVACY",
    )
    .await;
    assert!(holds(&granted, "PRIVACY"), "{granted}");
    give_member(&app, &seeded, "viewer", REMOTE_CONTROL).await;
    let (member_ws, without, granted) = ask(&app, &seeded.member.access_token, &a, "VIEW").await;
    assert!(!holds(&granted, "PRIVACY"), "{granted}");
    session_row(&app, &seeded, &with).await;
    session_row(&app, &seeded, &without).await;
    report(&mut a_ws, &with, "on", None).await;
    settle(&app, &seeded, &a, 1).await;

    // Both sessions end. `terminated: true` says this pod's hub held each one
    // and removed it, so what follows is decided by the stored row, not by a
    // live grant.
    for sid in [&with, &without] {
        let resp = app
            .auth_post(
                &format!("/api/tenant/{}/session/{}/terminate", seeded.tenant_id, sid),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "terminate {sid}: {}",
            resp.status()
        );
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["terminated"], true, "{sid}: {body}");
    }
    drop((owner_ws, member_ws));
    for sid in [&with, &without] {
        let mut ended = false;
        for _ in 0..50 {
            let row = session_row(&app, &seeded, sid).await;
            if row["ended_at"].is_string() || row["phase"] == "closed" {
                ended = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ended, "session {sid} never ended");
    }

    report(&mut a_ws, &with, "off", Some("worker_exit")).await;
    report(&mut a_ws, &without, "off", Some("worker_exit")).await;
    let body = settle(&app, &seeded, &a, 2).await;
    assert_eq!(
        trail(&body),
        [
            ("on".to_string(), None),
            ("off".to_string(), Some("worker_exit".to_string())),
        ]
    );
    assert_eq!(body["items"][0]["session_id"].as_str(), Some(with.as_str()));
}

/// One millisecond of reports lists newest first, in the order the hub
/// recorded them. This pins the flake the first cell hit on #2272's
/// integration run (2026-10-15): its four reports landed in one millisecond,
/// `at` was the only sort key, and the index returned the tied rows oldest
/// first, so the trail read `refused` before the `off` it followed. These rows
/// go straight into the collection with one `at`, so the tie is certain rather
/// than a race.
#[tokio::test]
async fn one_millisecond_of_reports_lists_in_arrival_order() {
    use meshharbor_remote_control::models::{PrivacyActivityEvent, PrivacyActivityKind};

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr99p1dtie").await;
    let (a, _a_ws) = connect_agent(&app, &seeded, "mach-fr99-p1d-tie").await;
    let tenant_id = bson::oid::ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let agent_id = bson::oid::ObjectId::parse_str(&a).unwrap();
    let at = bson::DateTime::now();
    // Ids made in order rise, as the hub's inserts' do.
    let rows: Vec<PrivacyActivityEvent> = [
        PrivacyActivityKind::On,
        PrivacyActivityKind::Off,
        PrivacyActivityKind::Refused,
    ]
    .into_iter()
    .map(|kind| PrivacyActivityEvent {
        id: Some(bson::oid::ObjectId::new()),
        tenant_id,
        agent_id,
        session_id: bson::oid::ObjectId::new(),
        controller_user_id: bson::oid::ObjectId::new(),
        kind,
        reason: None,
        at,
    })
    .collect();
    app.db
        .collection::<PrivacyActivityEvent>(PrivacyActivityEvent::COLLECTION)
        .insert_many(rows)
        .await
        .unwrap();

    let body = settle(&app, &seeded, &a, 3).await;
    assert_eq!(
        trail(&body),
        [
            ("on".to_string(), None),
            ("off".to_string(), None),
            ("refused".to_string(), None),
        ],
        "{body}"
    );
}
