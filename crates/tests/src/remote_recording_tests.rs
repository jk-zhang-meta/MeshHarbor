// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P3a — the server's gates for REMOTE screen recording, through real
//! servers, real WebSockets and a real MongoDB.
//!
//! `Permissions::RECORD` survives a session request only when BOTH hold:
//!
//! 1. the controller may record — the device's owner, an ADMINISTRATOR, or a
//!    holder of `RECORD_REMOTE_SCREEN` — and ⚠️ never under break-glass;
//! 2. the device serves it — its caps advertise `record: ["remote"]` (in the
//!    hello, or re-announced in a heartbeat), which an agent does only while
//!    its owner's gate is on. P3c-2: a device with a recorder whose owner has
//!    not opted in advertises `available` alone (`device_not_opted_in`); one
//!    with no recorder advertises nothing (`device_cannot_record`, named
//!    first, whoever asks: the viewer then shows no Record control).
//!
//! Every cell is here, each with the positive control beside it, because a
//! strip that fires for every request would pass every "refused" cell. And
//! what a device then REPORTS (`rc:recording.activity`) is recorded only for
//! a session of that device whose grant held RECORD.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const ADMINISTRATOR: u64 = 1 << 23;
const REMOTE_CONTROL: u64 = 1 << 25;
const RECORD_REMOTE_SCREEN: u64 = 1 << 31;

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// An agent's capabilities, with `record` as its recording words.
fn caps(record: &[&str]) -> Value {
    json!({
        "hw_encoders": [],
        "codecs": ["h264"],
        "has_input_permission": false,
        "supports_clipboard": false,
        "supports_file_transfer": false,
        // Enough for every cell below to hold a session at once.
        "max_simultaneous_sessions": 16,
        "input": ["arbiter"],
        "record": record,
    })
}

/// Enroll a device (owned by the seeded admin, who issues the token) and
/// connect it with `record` as its recording caps.
async fn connect_agent(
    app: &TestApp,
    seeded: &SeededTenant,
    machine_id: &str,
    record: &[&str],
) -> (String, Ws) {
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
        "displays": [{
            "index": 0, "name": "x", "width_px": 800, "height_px": 600,
            "scale": 1.0, "primary": true,
        }],
        "caps": caps(record),
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    // Let the hello land before anyone asks for a session.
    tokio::time::sleep(Duration::from_millis(300)).await;
    (agent_id, ws)
}

/// The server's answer to one request for `VIEW | RECORD`.
struct Answer {
    /// The controller connection that asked. Held by the caller while the
    /// session must stay live; dropping it lets the next request reap it.
    ws: Ws,
    session_id: String,
    permissions: String,
    why: Option<String>,
}

impl Answer {
    fn records(&self) -> bool {
        self.permissions.split('|').any(|p| p.trim() == "RECORD")
    }
}

/// Ask for `VIEW | RECORD` on a FRESH controller connection.
///
/// ⚠️ Fresh on purpose. A second request on the SAME socket to a device it
/// already holds a live session with coalesces onto that session (#1045) and
/// is answered with that session's grant — so every cell after the first
/// would silently be answering the first cell's question.
async fn ask_to_record(
    app: &TestApp,
    token: &str,
    agent_id: &str,
    override_reason: Option<&str>,
) -> Answer {
    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    let mut req = json!({
        "t": "rc:session.request",
        "agent_id": agent_id,
        "permissions": "VIEW | RECORD",
    });
    if let Some(r) = override_reason {
        req["override_reason"] = json!(r);
    }
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
                return Answer {
                    session_id: v["session_id"].as_str().unwrap().to_string(),
                    permissions: v["permissions"].as_str().unwrap_or_default().to_string(),
                    why: v["record_refused"].as_str().map(str::to_string),
                    ws,
                };
            }
            Some("rc:error") => panic!("the request was refused outright: {v}"),
            _ => {}
        }
    }
    panic!("no rc:session.created within 5 s");
}

/// A role with `mask`, assigned to the seeded member.
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

#[tokio::test]
async fn record_survives_only_for_an_allowed_controller_on_an_opted_in_device() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr85rec1").await;
    // FR-115 P3 — several sessions at once in one org: Free runs one.
    app.set_plan(&seeded.tenant_id, "business").await;
    let (serves, _serves_ws) =
        connect_agent(&app, &seeded, "mach-fr85-serves", &["available", "remote"]).await;
    let (plain, _plain_ws) = connect_agent(&app, &seeded, "mach-fr85-plain", &["available"]).await;
    let (none, _none_ws) = connect_agent(&app, &seeded, "mach-fr85-none", &[]).await;
    let owner = &seeded.admin.access_token;
    let member = &seeded.member.access_token;

    // The device's OWNER (the admin enrolled it).
    let a = ask_to_record(&app, owner, &serves, None).await;
    assert!(
        a.records(),
        "owner on an opted-in device keeps RECORD: {}",
        a.permissions
    );
    assert_eq!(a.why, None);
    // …but not on a device whose owner never opted in.
    let a = ask_to_record(&app, owner, &plain, None).await;
    assert!(!a.records(), "{}", a.permissions);
    assert_eq!(a.why.as_deref(), Some("device_not_opted_in"));
    // P3c-2 — nor on one with no recorder at all, which says so.
    let a = ask_to_record(&app, owner, &none, None).await;
    assert!(!a.records(), "{}", a.permissions);
    assert_eq!(a.why.as_deref(), Some("device_cannot_record"));

    // A member who may control but NOT record.
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let a = ask_to_record(&app, member, &serves, None).await;
    assert!(!a.records(), "{}", a.permissions);
    assert_eq!(a.why.as_deref(), Some("controller_not_allowed"));
    // No recorder is named before the controller's own refusal: there is
    // nothing on that device to allow or refuse.
    let a = ask_to_record(&app, member, &none, None).await;
    assert_eq!(a.why.as_deref(), Some("device_cannot_record"));

    // The same member, now holding RECORD_REMOTE_SCREEN (the positive control
    // for the cell above: the strip is the permission, not the member).
    give_member(
        &app,
        &seeded,
        "recorder",
        REMOTE_CONTROL | RECORD_REMOTE_SCREEN,
    )
    .await;
    let a = ask_to_record(&app, member, &serves, None).await;
    assert!(a.records(), "the role bit grants it: {}", a.permissions);
    assert_eq!(a.why, None);
}

/// ⚠️ Break-glass never records: it skips the host's consent, so recording
/// under it would be covert. The same ADMINISTRATOR without an override
/// reason is the positive control.
#[tokio::test]
async fn an_administrator_may_record_but_never_under_break_glass() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr85rec2").await;
    // FR-115 P3 — several sessions at once in one org: Free runs one.
    app.set_plan(&seeded.tenant_id, "business").await;
    let (serves, _ws) = connect_agent(&app, &seeded, "mach-fr85-bg", &["remote"]).await;
    // The member becomes an ADMINISTRATOR who does not own the device.
    give_member(&app, &seeded, "admins", ADMINISTRATOR).await;
    let admin = &seeded.member.access_token;

    let a = ask_to_record(&app, admin, &serves, None).await;
    assert!(
        a.records(),
        "a non-owner ADMINISTRATOR may record: {}",
        a.permissions
    );
    assert_eq!(a.why, None);

    let a = ask_to_record(&app, admin, &serves, Some("incident 42")).await;
    assert!(
        !a.records(),
        "break-glass must not record: {}",
        a.permissions
    );
    assert_eq!(a.why.as_deref(), Some("controller_not_allowed"));
}

/// `rc:agent.heartbeat`, re-announcing the caps when `record` is given
/// (FR-43 P2c's `caps` field) and carrying no caps ("no news") otherwise.
async fn heartbeat(ws: &mut Ws, record: Option<&[&str]>) {
    let mut hb = json!({
        "t": "rc:agent.heartbeat", "rss_mb": 0, "cpu_pct": 0.0, "active_sessions": 0,
    });
    if let Some(record) = record {
        hb["caps"] = caps(record);
    }
    ws.send(Message::Text(hb.to_string().into())).await.unwrap();
}

/// Ask until the answer's `record_refused` is `want`, for up to ~4 s: the
/// heartbeat and the request travel on two different sockets, so one
/// request straight after the heartbeat could race it. Each answer's
/// connection is dropped, so its session is reaped by the next request.
async fn ask_until(
    app: &TestApp,
    token: &str,
    agent_id: &str,
    want: Option<&str>,
) -> Option<String> {
    let mut last = None;
    for _ in 0..8 {
        let a = ask_to_record(app, token, agent_id, None).await;
        if a.why.as_deref() == want {
            return a.why;
        }
        last = a.why;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    last
}

/// The owner switches remote recording on or off while the device stays
/// connected, and the agent re-announces its caps in a heartbeat. The hub
/// must follow in both directions; before, it kept the hello's answer until
/// the next reconnect. A heartbeat WITHOUT caps is "no news" and changes
/// nothing.
#[tokio::test]
async fn a_heartbeat_opts_a_device_in_and_out_without_a_reconnect() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr85rec4").await;
    let (agent, mut agent_ws) = connect_agent(&app, &seeded, "mach-fr85-hb", &["available"]).await;
    let owner = &seeded.admin.access_token;

    let a = ask_to_record(&app, owner, &agent, None).await;
    assert_eq!(a.why.as_deref(), Some("device_not_opted_in"));
    drop(a);

    heartbeat(&mut agent_ws, Some(&["available", "remote"])).await;
    assert_eq!(
        ask_until(&app, owner, &agent, None).await,
        None,
        "an ON announced in a heartbeat must reach the hub"
    );

    // No caps = no news: the device stays opted in.
    heartbeat(&mut agent_ws, None).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a = ask_to_record(&app, owner, &agent, None).await;
    assert!(
        a.records() && a.why.is_none(),
        "a caps-less heartbeat changed the answer: {:?}",
        a.why
    );
    drop(a);

    heartbeat(&mut agent_ws, Some(&["available"])).await;
    assert_eq!(
        ask_until(&app, owner, &agent, Some("device_not_opted_in"))
            .await
            .as_deref(),
        Some("device_not_opted_in"),
        "an OFF announced in a heartbeat must reach the hub"
    );

    // P3c-2 — and a recorder that goes away (`MESHHARBORD_RECORDING=0` takes
    // effect, say) announces nothing at all.
    heartbeat(&mut agent_ws, Some(&[])).await;
    assert_eq!(
        ask_until(&app, owner, &agent, Some("device_cannot_record"))
            .await
            .as_deref(),
        Some("device_cannot_record"),
        "a device that stops advertising a recorder must read as having none"
    );
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
            "/api/tenant/{}/recording-activity/{}",
            seeded.tenant_id, agent_id
        )))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn report(ws: &mut Ws, session_id: &str, kind: &str) {
    let msg = json!({
        "t": "rc:recording.activity",
        "session_id": session_id,
        "kind": kind,
        "name": "Roomler Recording 2026-09-25 14-30-12.mp4",
        "bytes": 1234,
        "duration_ms": 5000,
        "reason": "requested",
    });
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .unwrap();
}

/// What a device reports lands in `recording_activity` — for a session of
/// THAT device whose grant held RECORD, and for nothing else.
#[tokio::test]
async fn recording_activity_is_kept_only_for_a_session_that_could_record() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr85rec3").await;
    // FR-115 P3 — several sessions at once in one org: Free runs one.
    app.set_plan(&seeded.tenant_id, "business").await;
    let (a, mut a_ws) = connect_agent(&app, &seeded, "mach-fr85-a", &["remote"]).await;
    let (b, mut b_ws) = connect_agent(&app, &seeded, "mach-fr85-b", &["remote"]).await;

    // Both answers are held, so both sessions stay live while reported on.
    let with_record = ask_to_record(&app, &seeded.admin.access_token, &a, None).await;
    assert!(with_record.records());
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let without_record = ask_to_record(&app, &seeded.member.access_token, &a, None).await;
    assert!(!without_record.records());

    report(&mut a_ws, &with_record.session_id, "stopped").await; // kept
    report(&mut a_ws, &without_record.session_id, "started").await; // no RECORD: dropped
    report(&mut b_ws, &with_record.session_id, "started").await; // another device: dropped

    for _ in 0..20 {
        let (status, body) = activity(&app, &seeded, &a, &seeded.admin.access_token).await;
        assert_eq!(status, 200, "{body}");
        if body["total"].as_u64() == Some(1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Give the dropped ones every chance to (wrongly) land.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (_, rows_a) = activity(&app, &seeded, &a, &seeded.admin.access_token).await;
    assert_eq!(rows_a["total"], 1, "only the reportable one: {rows_a}");
    let item = &rows_a["items"][0];
    assert_eq!(item["kind"], "stopped");
    assert_eq!(
        item["session_id"].as_str(),
        Some(with_record.session_id.as_str())
    );
    assert_eq!(
        item["controller_user_id"].as_str(),
        Some(seeded.admin.id.as_str())
    );
    assert_eq!(item["bytes"], 1234);
    assert!(
        item["at"].is_string(),
        "RFC 3339, never a raw BSON date: {item}"
    );
    let (_, rows_b) = activity(&app, &seeded, &b, &seeded.admin.access_token).await;
    assert_eq!(
        rows_b["total"], 0,
        "device B cannot write about A's session"
    );

    // The log is read under VIEW_REMOTE_AUDIT: the member (who holds only
    // REMOTE_CONTROL) is refused.
    let (status, _) = activity(&app, &seeded, &a, &seeded.member.access_token).await;
    assert_eq!(status, 403);
    drop((with_record.ws, without_record.ws));
}
