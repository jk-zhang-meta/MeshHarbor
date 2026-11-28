// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! #2267 — a removal tells a CONNECTED device at once.
//!
//! Before, the removal's kick only took the device out of the hub: the device
//! kept its control socket, heard nothing, and learned it was removed only
//! when something else dropped that socket (a network change, a pod roll), at
//! its next connection. Now the kick queues `rc:goodbye AgentDeleted` on the
//! socket, and the daemon stops as it would at that next connection.
//!
//! The negative controls: the kill switch (`rc.removal_goodbye = false`)
//! keeps the socket open and silent, which is also the behaviour before the
//! fix, and an ephemeral device that unenrolls itself is not told (it is
//! already leaving).

use std::time::Duration;

use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

use crate::agent_presence_tests::{connect_agent, enroll};
use crate::fixtures::test_app::TestApp;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// What the socket did within `within`.
#[derive(Debug)]
enum Heard {
    /// An `rc:goodbye` frame.
    Goodbye(Value),
    /// Our ping's pong: the server's read loop is still running.
    Pong,
    /// Nothing: the socket stayed open and silent.
    Nothing,
    /// The socket closed (or failed) without a goodbye.
    Closed,
}

/// Read until a goodbye, a pong, a close, or `within` passes. Other frames
/// (the hello's replies) are skipped.
async fn listen(ws: &mut Ws, within: Duration) -> Heard {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Heard::Nothing;
        }
        match tokio::time::timeout(left, ws.next()).await {
            Err(_) => return Heard::Nothing,
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return Heard::Closed,
            Ok(Some(Ok(Message::Pong(_)))) => return Heard::Pong,
            Ok(Some(Ok(Message::Text(t)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&t)
                    && v["t"] == "rc:goodbye"
                {
                    return Heard::Goodbye(v);
                }
            }
            Ok(Some(Ok(_))) => {}
        }
    }
}

/// The socket is still served: a ping is answered.
async fn still_served(ws: &mut Ws) -> bool {
    if ws
        .send(Message::Ping(b"2267".to_vec().into()))
        .await
        .is_err()
    {
        return false;
    }
    matches!(listen(ws, Duration::from_secs(3)).await, Heard::Pong)
}

async fn wait_registered(app: &TestApp, agent_id: &str) -> ObjectId {
    let aid = ObjectId::parse_str(agent_id).unwrap();
    for _ in 0..100 {
        if app.state.fleet().rc_hub.is_agent_online(aid) {
            return aid;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the agent never registered on its pod");
}

fn assert_told(heard: Heard) {
    match heard {
        Heard::Goodbye(v) => assert_eq!(
            v["reason"], "agent_deleted",
            "the goodbye a daemon stops on (exit 7): {v}"
        ),
        other => panic!(
            "a removed, connected device must be told at once with rc:goodbye \
             AgentDeleted; heard {other:?} (before #2267 the socket stayed open \
             and silent)"
        ),
    }
}

/// The admin's `DELETE …/agent/{id}` tells the device on its socket.
#[tokio::test]
async fn a_removed_connected_device_is_told_at_once() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rmgb1").await;
    let (agent_id, agent_token) = enroll(&app, &seeded, "mach-rmgb1").await;
    let mut ws = connect_agent(&app, &agent_token).await;
    let aid = wait_registered(&app, &agent_id).await;

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the removal itself");

    assert_told(listen(&mut ws, Duration::from_secs(5)).await);
    assert!(
        !app.state.fleet().rc_hub.is_agent_online(aid),
        "nothing addresses a removed device"
    );
}

/// The kill switch, and the behaviour before #2267: out of the hub, but the
/// socket stays open and silent, and the server still answers it.
#[tokio::test]
async fn the_kill_switch_keeps_the_socket_open_and_silent() {
    let app = TestApp::spawn_with_settings(|s| s.rc.removal_goodbye = false).await;
    let seeded = app.seed_tenant("rmgb2").await;
    let (agent_id, agent_token) = enroll(&app, &seeded, "mach-rmgb2").await;
    let mut ws = connect_agent(&app, &agent_token).await;
    let aid = wait_registered(&app, &agent_id).await;

    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    match listen(&mut ws, Duration::from_secs(2)).await {
        Heard::Nothing => {}
        other => panic!("rc.removal_goodbye = false must tell nothing; heard {other:?}"),
    }
    assert!(
        !app.state.fleet().rc_hub.is_agent_online(aid),
        "the kick still takes it out of the hub"
    );
    assert!(
        still_served(&mut ws).await,
        "and the socket stays open, as before #2267"
    );
}

/// The removal runs on whichever pod the admin's request lands on; the pod
/// holding the socket applies the kick from the control channel, goodbye
/// included.
#[tokio::test]
async fn a_removal_on_another_pod_tells_the_device() {
    let (app1, app2) = TestApp::spawn_pair(|_| {}).await;
    if app1.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("rmgb3").await;
    let (agent_id, agent_token) = enroll(&app1, &seeded, "mach-rmgb3").await;
    let mut ws = connect_agent(&app1, &agent_token).await;
    let aid = wait_registered(&app1, &agent_id).await;
    assert!(
        !app2.state.fleet().rc_hub.is_agent_online(aid),
        "the socket is on pod 1 only"
    );

    let resp = app2
        .auth_delete(
            &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "removed through pod 2");

    assert_told(listen(&mut ws, Duration::from_secs(5)).await);
    assert!(!app1.state.fleet().rc_hub.is_agent_online(aid));
}

/// An archive revokes every device of the org; a connected one is told,
/// as a removal does. Before #2267 an archive did not even take it out of
/// the hub.
#[tokio::test]
async fn an_archived_orgs_connected_device_is_told() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rmgb4").await;
    let (agent_id, agent_token) = enroll(&app, &seeded, "mach-rmgb4").await;
    let mut ws = connect_agent(&app, &agent_token).await;
    let aid = wait_registered(&app, &agent_id).await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/archive", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the archive itself");

    assert_told(listen(&mut ws, Duration::from_secs(5)).await);
    assert!(!app.state.fleet().rc_hub.is_agent_online(aid));
}

/// An ephemeral device that unenrolls itself is mid-shutdown: a goodbye
/// racing its graceful exit would turn a clean stop into exit 7.
#[tokio::test]
async fn an_ephemeral_device_leaving_by_itself_is_not_told() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rmgb5").await;
    let (agent_id, agent_token) = enroll(&app, &seeded, "mach-rmgb5").await;
    let aid = ObjectId::parse_str(&agent_id).unwrap();
    app.state
        .fleet()
        .agents
        .set_ephemeral(aid, Some(60))
        .await
        .expect("mark ephemeral");
    let mut ws = connect_agent(&app, &agent_token).await;
    wait_registered(&app, &agent_id).await;

    let resp = app
        .client
        .post(app.url("/api/agent/self/unenroll"))
        .bearer_auth(&agent_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the self-unenroll itself");

    match listen(&mut ws, Duration::from_secs(2)).await {
        Heard::Nothing => {}
        other => panic!("a device leaving by itself must not be told; heard {other:?}"),
    }
    assert!(!app.state.fleet().rc_hub.is_agent_online(aid));
}
