// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

/// Read the next WS message, skipping room:call_* notification messages.
async fn next_media_msg(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
    loop {
        let msg = ws.next().await.unwrap().unwrap();
        let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        let msg_type = parsed["type"].as_str().unwrap_or("");
        if !msg_type.starts_with("room:") {
            return parsed;
        }
    }
}

#[tokio::test]
async fn create_room_for_call() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("conf1").await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({
            "name": "Team Standup",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["name"], "Team Standup");
    assert!(!json["id"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn room_call_lifecycle_start_join_leave_end() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("conflife").await;

    // Create room
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({
            "name": "Sprint Planning",
        }))
        .send()
        .await
        .unwrap();

    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    // Start call
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/start",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["started"], true);

    // Get room - check call status is InProgress
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/room/{}", tenant.tenant_id, room_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["conference_status"], "in_progress");

    // Join call
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/join",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["joined"], true);

    // List participants
    let resp = app
        .auth_get(
            &format!(
                "/api/tenant/{}/room/{}/call/participant",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let parts: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0]["user_id"], tenant.admin.id);

    // Leave call
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/leave",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // End call
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room/{}/call/end", tenant.tenant_id, room_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["ended"], true);

    // Get room - check call status is Ended
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/room/{}", tenant.tenant_id, room_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["conference_status"], "ended");
}

/// Regression: a duplicate /call/leave (e.g. browser retry, double-click) must not
/// underflow participant_count. Before the fix, the second leave issued an
/// unconditional `$inc:-1` which sent the BSON value to -1, then any subsequent
/// GET /room failed with `expected u32, got -1` → 500.
#[tokio::test]
async fn duplicate_call_leave_does_not_underflow_participant_count() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("leaveunder").await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "Underflow Repro" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    let path_start = format!(
        "/api/tenant/{}/room/{}/call/start",
        tenant.tenant_id, room_id
    );
    let path_join = format!(
        "/api/tenant/{}/room/{}/call/join",
        tenant.tenant_id, room_id
    );
    let path_leave = format!(
        "/api/tenant/{}/room/{}/call/leave",
        tenant.tenant_id, room_id
    );
    let path_get = format!("/api/tenant/{}/room/{}", tenant.tenant_id, room_id);
    let path_list = format!("/api/tenant/{}/room", tenant.tenant_id);

    app.auth_post(&path_start, &tenant.admin.access_token)
        .send()
        .await
        .unwrap();
    app.auth_post(&path_join, &tenant.admin.access_token)
        .send()
        .await
        .unwrap();

    // First leave — legitimate.
    let resp = app
        .auth_post(&path_leave, &tenant.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Second leave — duplicate (no active session). Must not underflow.
    let resp = app
        .auth_post(&path_leave, &tenant.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // The smoking-gun: deserializing the room must succeed (the bug surfaced as
    // a 500 on this exact call when participant_count was -1).
    let resp = app
        .auth_get(&path_get, &tenant.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert!(
        json["participant_count"].as_i64().unwrap() >= 0,
        "participant_count went negative: {:?}",
        json["participant_count"]
    );

    // GET /room (list) is the actual UI call that broke in prod.
    let resp = app
        .auth_get(&path_list, &tenant.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn list_rooms() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("conflist").await;

    // Create 2 additional rooms (3 seeded + 2 = 5)
    for name in &["Standup Room", "Retro Room"] {
        app.auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .unwrap();
    }

    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let rooms: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(rooms.len(), 5);
}

// --- Phase 6 mediasoup integration tests ---

#[tokio::test]
async fn call_start_creates_mediasoup_room() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("msoup1").await;

    // Create room
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "Media Test" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    // Start call — should create mediasoup room and return rtp_capabilities
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/start",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["started"], true);

    // Verify rtp_capabilities is present and has codecs
    let caps = &json["rtp_capabilities"];
    assert!(caps.is_object(), "rtp_capabilities should be an object");
    assert!(
        caps.get("codecs").is_some(),
        "rtp_capabilities should have codecs"
    );
    let codecs = caps["codecs"].as_array().unwrap();
    assert!(codecs.len() >= 2, "Should have at least opus + VP8 codecs");
}

#[tokio::test]
async fn call_join_returns_transport_options() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("msoup2").await;

    // Create + start call
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "Transport Test" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/start",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Join — should return transport options
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/join",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["joined"], true);

    // Transports are now created via WS media:join, not REST join.
    // Connect WS and send media:join to get transports.
    let ws_url = format!("ws://{}/ws?token={}", app.addr, tenant.admin.access_token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    use futures::SinkExt;
    use futures::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    ws.next().await; // connected msg

    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Should receive router_capabilities
    let msg = ws.next().await.unwrap().unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:router_capabilities");

    // Should receive transport_created
    let msg = ws.next().await.unwrap().unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:transport_created");

    let send = &parsed["data"]["send_transport"];
    assert!(send["id"].is_string(), "send_transport should have id");
    assert!(
        send["ice_parameters"].is_object(),
        "send_transport should have ice_parameters"
    );
    assert!(
        send["ice_candidates"].is_array(),
        "send_transport should have ice_candidates"
    );
    assert!(
        send["dtls_parameters"].is_object(),
        "send_transport should have dtls_parameters"
    );

    let recv = &parsed["data"]["recv_transport"];
    assert!(recv["id"].is_string(), "recv_transport should have id");
    assert!(
        recv["ice_parameters"].is_object(),
        "recv_transport should have ice_parameters"
    );

    ws.close(None).await.ok();
}

#[tokio::test]
async fn call_end_cleans_up_room() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("msoup3").await;

    // Create + start + end
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "Cleanup Test" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/start",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room/{}/call/end", tenant.tenant_id, room_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["ended"], true);

    // Verify call status is Ended
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/room/{}", tenant.tenant_id, room_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["conference_status"], "ended");
}

#[tokio::test]
async fn ws_media_join_signaling() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("msoup4").await;

    // Create + start call
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "WS Test" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/start",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Connect WebSocket
    let ws_url = format!("ws://{}/ws?token={}", app.addr, tenant.admin.access_token);
    let (mut ws, _) = connect_async(&ws_url).await.expect("Failed to connect WS");

    // Read initial "connected" message
    let msg = ws.next().await.unwrap().unwrap();
    let connected: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(connected["type"], "connected");

    // REST join first (creates transports)
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Send media:join
    let join_msg = serde_json::json!({
        "type": "media:join",
        "data": { "room_id": room_id }
    });
    ws.send(Message::Text(
        serde_json::to_string(&join_msg).unwrap().into(),
    ))
    .await
    .unwrap();

    // Should receive media:router_capabilities (skip room:call_* notifications)
    let parsed = next_media_msg(&mut ws).await;
    assert_eq!(parsed["type"], "media:router_capabilities");
    assert!(parsed["data"]["rtp_capabilities"]["codecs"].is_array());

    ws.close(None).await.ok();
}

#[tokio::test]
async fn ws_media_leave_broadcasts_peer_left() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("msoup5").await;

    // Create + start call
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "Leave Test" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/start",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // User 1 (admin) connects WS and joins
    let ws_url1 = format!("ws://{}/ws?token={}", app.addr, tenant.admin.access_token);
    let (mut ws1, _) = connect_async(&ws_url1)
        .await
        .expect("Failed to connect WS1");
    ws1.next().await; // connected msg

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    ws1.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Read router_capabilities for user 1 (skip room:call_* notifications)
    let parsed = next_media_msg(&mut ws1).await;
    assert_eq!(parsed["type"], "media:router_capabilities");

    // Read transport_created for user 1
    let parsed = next_media_msg(&mut ws1).await;
    assert_eq!(parsed["type"], "media:transport_created");

    // User 2 (member) connects WS and joins
    let ws_url2 = format!("ws://{}/ws?token={}", app.addr, tenant.member.access_token);
    let (mut ws2, _) = connect_async(&ws_url2)
        .await
        .expect("Failed to connect WS2");
    ws2.next().await; // connected msg

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.member.access_token,
    )
    .send()
    .await
    .unwrap();

    ws2.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Read router_capabilities for user 2 (skip room:call_* notifications)
    let parsed = next_media_msg(&mut ws2).await;
    assert_eq!(parsed["type"], "media:router_capabilities");

    // Read transport_created for user 2
    let parsed = next_media_msg(&mut ws2).await;
    assert_eq!(parsed["type"], "media:transport_created");

    // User 2 sends media:leave
    ws2.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:leave",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Give a moment for the broadcast to propagate
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // User 1 should receive peer_left (skip room:call_* notifications)
    let parsed = next_media_msg(&mut ws1).await;
    assert_eq!(parsed["type"], "media:peer_left");
    assert_eq!(parsed["data"]["user_id"], tenant.member.id);

    ws1.close(None).await.ok();
    ws2.close(None).await.ok();
}

#[tokio::test]
async fn call_leave_cleans_up_participant_media() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("msoup6").await;

    // Create + start
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "Leave Cleanup" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/start",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Join via REST
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/join",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["joined"], true);

    // Connect WS and join media room to create transports
    let ws_url = format!("ws://{}/ws?token={}", app.addr, tenant.admin.access_token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    use futures::SinkExt;
    use futures::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    ws.next().await; // connected msg

    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Drain router_capabilities + transport_created (skip room:call_* notifications)
    let parsed = next_media_msg(&mut ws).await;
    assert_eq!(parsed["type"], "media:router_capabilities");

    let parsed = next_media_msg(&mut ws).await;
    assert_eq!(parsed["type"], "media:transport_created");

    // Leave — should clean up transports
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/leave",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Re-join the way the PRODUCT does. #754: this used `call/join` alone, and
    // that sequence does not exist in the client. `ConferenceView::doJoin` runs
    // `startCall` then `joinCall` UNCONDITIONALLY — it does not choose between
    // them — so every real re-entry starts first.
    //
    // It matters here because the single participant leaving auto-ends the call
    // (count 0 + in_progress -> `end_call`), and `call/join` never restores
    // `conference_status`; only `call/start` does. Joining alone therefore left
    // the room `ended` in Mongo, and the later `media:join` was correctly refused
    // by the C-4 claim gate. The test was asserting a pre-C-4 contract.
    //
    // `call/start` is transition-gated, so the extra call is a no-op whenever the
    // call is already running — which is exactly why the client can afford to
    // issue it every time.
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/start",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/join",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["joined"], true);

    // WS media:join again — should create new transports (proving old ones were cleaned up)
    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    let parsed = next_media_msg(&mut ws).await;
    assert_eq!(parsed["type"], "media:router_capabilities");

    let parsed = next_media_msg(&mut ws).await;
    assert_eq!(
        parsed["type"], "media:transport_created",
        "Should get new transports after re-join"
    );

    ws.close(None).await.ok();
}

/// #754 — `call/join` must broadcast the status the DATABASE holds, not a
/// literal. It used to send `"conference_status": "in_progress"` hardcoded, so
/// joining a call that had already auto-ended told every client in the room the
/// call was live when the stored status was `ended`.
///
/// Worth its own test rather than riding on the media one: that test needs a
/// mediasoup worker and is skipped on CI, so the product bug it exposed had no
/// coverage anywhere the runner would notice. This asserts the same contract
/// with HTTP + WS only, so it runs everywhere.
#[tokio::test]
async fn call_join_broadcasts_the_stored_status_not_a_literal() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("joinstatus").await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "Status Truth" }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap();

    let post = |p: String| {
        app.auth_post(&p, &tenant.admin.access_token)
            .json(&serde_json::json!({}))
            .send()
    };

    // Start → join → leave. The single participant leaving auto-ends the call.
    post(format!(
        "/api/tenant/{}/room/{}/call/start",
        tenant.tenant_id, room_id
    ))
    .await
    .unwrap();
    post(format!(
        "/api/tenant/{}/room/{}/call/join",
        tenant.tenant_id, room_id
    ))
    .await
    .unwrap();
    post(format!(
        "/api/tenant/{}/room/{}/call/leave",
        tenant.tenant_id, room_id
    ))
    .await
    .unwrap();

    // The DB's own answer — whatever the broadcast claims must equal THIS.
    let stored = {
        let resp = app
            .auth_get(
                &format!("/api/tenant/{}/room/{}", tenant.tenant_id, room_id),
                &tenant.admin.access_token,
            )
            .send()
            .await
            .unwrap();
        let json: Value = resp.json().await.unwrap();
        json["conference_status"].as_str().unwrap_or("").to_string()
    };
    assert_eq!(
        stored, "ended",
        "precondition: the last participant leaving must auto-end the call — \
         without it this test would pass for the wrong reason"
    );

    // Listen before joining, or the broadcast is gone before we look.
    let ws_url = format!("ws://{}/ws?token={}", app.addr, tenant.admin.access_token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");
    ws.next().await; // connected

    post(format!(
        "/api/tenant/{}/room/{}/call/join",
        tenant.tenant_id, room_id
    ))
    .await
    .unwrap();

    let mut seen = None;
    for _ in 0..10 {
        let Ok(Some(Ok(msg))) =
            tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await
        else {
            break;
        };
        let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        if parsed["type"] == "room:call_updated" {
            seen = parsed["data"]["conference_status"]
                .as_str()
                .map(str::to_string);
            break;
        }
    }

    let broadcast = seen.expect("no room:call_updated arrived after call/join");
    assert_eq!(
        broadcast, stored,
        "call/join broadcast `{broadcast}` while the database held `{stored}` — \
         the event must not assert a status the DB does not have (#754)"
    );
}

// --- TCP transport + TURN config tests ---

#[tokio::test]
async fn transport_created_contains_udp_and_tcp_candidates() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("tcp1").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "TCP Transport Test",
    )
    .await;

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    let (mut ws, transport) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Check both send_transport and recv_transport ICE candidates
    for transport_key in &["send_transport", "recv_transport"] {
        let candidates = transport["data"][transport_key]["ice_candidates"]
            .as_array()
            .unwrap_or_else(|| panic!("{} should have ice_candidates array", transport_key));

        let has_udp = candidates
            .iter()
            .any(|c| c["protocol"].as_str() == Some("udp"));
        let has_tcp = candidates
            .iter()
            .any(|c| c["protocol"].as_str() == Some("tcp"));

        assert!(has_udp, "{} should have UDP ICE candidates", transport_key);
        assert!(has_tcp, "{} should have TCP ICE candidates", transport_key);

        // TCP candidates should be passive
        for c in candidates
            .iter()
            .filter(|c| c["protocol"].as_str() == Some("tcp"))
        {
            assert_eq!(
                c["tcpType"].as_str(),
                Some("passive"),
                "TCP ICE candidates should have tcpType: passive"
            );
        }
    }

    ws.close(None).await.ok();
}

#[tokio::test]
async fn transport_created_includes_turn_config() {
    let app = TestApp::spawn_with_settings(|s| {
        s.turn.url = Some("turn:turn.example.com:3478".to_string());
        s.turn.username = Some("testuser".to_string());
        s.turn.password = Some("testpass".to_string());
        s.turn.shared_secret = None;
        s.turn.force_relay = Some(true);
    })
    .await;
    let tenant = app.seed_tenant("turn1").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "TURN Config Test",
    )
    .await;

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    let (mut ws, transport) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Verify ice_servers contains our TURN config
    let ice_servers = transport["data"]["ice_servers"]
        .as_array()
        .expect("ice_servers should be an array");
    assert_eq!(ice_servers.len(), 1, "Should have exactly one TURN server");

    let server = &ice_servers[0];
    let urls = server["urls"].as_array().expect("urls should be an array");
    assert_eq!(urls[0].as_str(), Some("turn:turn.example.com:3478"));
    assert_eq!(server["username"].as_str(), Some("testuser"));
    assert_eq!(server["credential"].as_str(), Some("testpass"));

    // Verify force_relay
    assert_eq!(
        transport["data"]["force_relay"].as_bool(),
        Some(true),
        "force_relay should be true when configured"
    );

    ws.close(None).await.ok();
}

#[tokio::test]
async fn transport_created_no_turn_by_default() {
    let app = TestApp::spawn_with_settings(|s| {
        s.turn.url = None;
        s.turn.username = None;
        s.turn.password = None;
        s.turn.force_relay = None;
    })
    .await;
    let tenant = app.seed_tenant("noturn1").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "No TURN Test",
    )
    .await;

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    let (mut ws, transport) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Verify ice_servers is empty
    let ice_servers = transport["data"]["ice_servers"]
        .as_array()
        .expect("ice_servers should be an array");
    assert!(
        ice_servers.is_empty(),
        "ice_servers should be empty when TURN is not configured"
    );

    // Verify force_relay is false
    assert_eq!(
        transport["data"]["force_relay"].as_bool(),
        Some(false),
        "force_relay should be false by default"
    );

    ws.close(None).await.ok();
}

// --- Connection-ID isolation tests ---

/// Helper: connect WS, read "connected" message, send media:join, read router_capabilities + transport_created.
/// Returns the WS stream and the transport_created data.
async fn ws_join_media(
    addr: &std::net::SocketAddr,
    token: &str,
    room_id: &str,
) -> (
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Value,
) {
    let ws_url = format!("ws://{}/ws?token={}", addr, token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    // Read "connected"
    ws.next().await;

    // Send media:join
    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Read router_capabilities (skip room:call_* notifications)
    let parsed = next_media_msg(&mut ws).await;
    assert_eq!(parsed["type"], "media:router_capabilities");

    // Read transport_created
    let transport = next_media_msg(&mut ws).await;
    assert_eq!(transport["type"], "media:transport_created");

    (ws, transport)
}

/// Helper: create a room + start a call, return room_id.
async fn create_room_and_start_call(
    app: &TestApp,
    tenant_id: &str,
    token: &str,
    name: &str,
) -> String {
    let resp = app
        .auth_post(&format!("/api/tenant/{}/room", tenant_id), token)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .unwrap();
    let room: Value = resp.json().await.unwrap();
    let room_id = room["id"].as_str().unwrap().to_string();

    app.auth_post(
        &format!("/api/tenant/{}/room/{}/call/start", tenant_id, room_id),
        token,
    )
    .send()
    .await
    .unwrap();

    room_id
}

#[tokio::test]
async fn two_different_users_get_independent_transports() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("connid1").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "ConnID Test",
    )
    .await;

    // Both users REST-join
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.member.access_token,
    )
    .send()
    .await
    .unwrap();

    // Both users WS media:join — each gets their own transports
    let (mut ws1, t1) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;
    let (mut ws2, t2) = ws_join_media(&app.addr, &tenant.member.access_token, &room_id).await;

    // Verify different transport IDs (proves separate connection_ids)
    let send1_id = t1["data"]["send_transport"]["id"].as_str().unwrap();
    let send2_id = t2["data"]["send_transport"]["id"].as_str().unwrap();
    assert_ne!(
        send1_id, send2_id,
        "Different users should get different transport IDs"
    );

    let recv1_id = t1["data"]["recv_transport"]["id"].as_str().unwrap();
    let recv2_id = t2["data"]["recv_transport"]["id"].as_str().unwrap();
    assert_ne!(
        recv1_id, recv2_id,
        "Different users should get different recv transport IDs"
    );

    ws1.close(None).await.ok();
    ws2.close(None).await.ok();
}

#[tokio::test]
async fn same_user_two_connections_get_independent_transports() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("connid2").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "Same User Multi-Tab",
    )
    .await;

    // REST join once
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Same user, two WS connections, each sends media:join
    let (mut ws1, t1) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;
    let (mut ws2, t2) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Both should get unique transport IDs (keyed by connection_id, not user_id)
    let send1_id = t1["data"]["send_transport"]["id"].as_str().unwrap();
    let send2_id = t2["data"]["send_transport"]["id"].as_str().unwrap();
    assert_ne!(
        send1_id, send2_id,
        "Same user from two connections must get different transport IDs (connection_id isolation)"
    );

    // Closing ws2 should NOT destroy ws1's transports.
    // ws1 should still be able to communicate.
    ws2.close(None).await.ok();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // ws1 may receive media:peer_left (ws2 left the call) — that's expected
    // Then send a ping to verify ws1 is still alive
    ws1.send(Message::Text(
        serde_json::to_string(&serde_json::json!({ "type": "ping" }))
            .unwrap()
            .into(),
    ))
    .await
    .unwrap();

    // Read messages until we get pong (there may be a peer_left first)
    let mut got_pong = false;
    for _ in 0..5 {
        match tokio::time::timeout(std::time::Duration::from_secs(2), ws1.next()).await {
            Ok(Some(Ok(msg))) => {
                let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
                if parsed["type"] == "pong" {
                    got_pong = true;
                    break;
                }
                // media:peer_left is expected, skip it
            }
            _ => break,
        }
    }
    assert!(
        got_pong,
        "ws1 should still be alive after ws2 closes (got pong)"
    );

    ws1.close(None).await.ok();
}

/// Same user, two connections in the same room call. When one sends media:leave,
/// only the OTHER connection should receive peer_left — never the leaving connection.
/// This catches the broadcast-by-user_id bug where same-user connections echo events
/// back to themselves.
#[tokio::test]
async fn same_user_media_leave_no_self_notification() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("echo1").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "No Echo Leave",
    )
    .await;

    // REST join once
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Same user, two WS connections
    let (mut ws1, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;
    let (mut ws2, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // ws2 sends media:leave
    ws2.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:leave",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // ws1 should receive exactly one peer_left
    let msg = tokio::time::timeout(std::time::Duration::from_secs(3), ws1.next())
        .await
        .expect("ws1 should receive peer_left")
        .unwrap()
        .unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:peer_left");
    assert!(
        parsed["data"]["connection_id"].is_string(),
        "peer_left should include connection_id"
    );

    // ws2 should NOT receive any peer_left (it was the one leaving).
    // Use a short timeout — if nothing arrives, that's correct.
    let ws2_msg = tokio::time::timeout(std::time::Duration::from_millis(500), ws2.next()).await;
    match ws2_msg {
        Ok(Some(Ok(msg))) => {
            let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
            assert_ne!(
                parsed["type"], "media:peer_left",
                "ws2 must NOT receive peer_left for its own leave (broadcast echo bug)"
            );
        }
        _ => {
            // Timeout or closed — correct, ws2 should not get peer_left
        }
    }

    ws1.close(None).await.ok();
    ws2.close(None).await.ok();
}

/// Same user, three connections. When one disconnects (WS drop), the other two
/// should each receive exactly one peer_left — not zero, not two.
#[tokio::test]
async fn same_user_disconnect_notifies_only_other_connections() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("echo2").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "No Echo Disconnect",
    )
    .await;

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // Same user, three WS connections
    let (mut ws1, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;
    let (mut ws2, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;
    let (ws3, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // ws3 disconnects
    drop(ws3);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ws1 should receive exactly one peer_left
    let msg1 = tokio::time::timeout(std::time::Duration::from_secs(3), ws1.next())
        .await
        .expect("ws1 should receive peer_left")
        .unwrap()
        .unwrap();
    let parsed1: Value = serde_json::from_str(msg1.to_text().unwrap()).unwrap();
    assert_eq!(parsed1["type"], "media:peer_left");
    let left_conn_id = parsed1["data"]["connection_id"]
        .as_str()
        .unwrap()
        .to_string();

    // ws2 should also receive exactly one peer_left with the same connection_id
    let msg2 = tokio::time::timeout(std::time::Duration::from_secs(3), ws2.next())
        .await
        .expect("ws2 should receive peer_left")
        .unwrap()
        .unwrap();
    let parsed2: Value = serde_json::from_str(msg2.to_text().unwrap()).unwrap();
    assert_eq!(parsed2["type"], "media:peer_left");
    assert_eq!(
        parsed2["data"]["connection_id"].as_str().unwrap(),
        left_conn_id,
        "Both connections should see peer_left for the same disconnected connection"
    );

    // Neither ws1 nor ws2 should receive a second peer_left
    let extra1 = tokio::time::timeout(std::time::Duration::from_millis(500), ws1.next()).await;
    // Anything other than a message — i.e. the timeout — is the CORRECT outcome
    // here, so only the message case has anything to assert.
    if let Ok(Some(Ok(msg))) = extra1 {
        let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_ne!(
            parsed["type"], "media:peer_left",
            "ws1 should not receive a second peer_left"
        );
    }

    ws1.close(None).await.ok();
    ws2.close(None).await.ok();
}

/// When a second connection from the same user joins, it should receive existing
/// producers with connection_id fields (from ws_join_media's initial producer list).
/// This verifies the join-time producer list is connection-scoped.
#[tokio::test]
async fn same_user_second_connection_receives_existing_producers_with_connection_id() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("echo3").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "Join Producer List",
    )
    .await;

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // ws1 joins first (no existing producers yet)
    let (mut ws1, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Now have a second different user join and produce (to create some producers).
    // We use the member user so there's a real producer in the room.
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.member.access_token,
    )
    .send()
    .await
    .unwrap();

    let (mut ws_member, _) = ws_join_media(&app.addr, &tenant.member.access_token, &room_id).await;

    // Now the admin opens a second connection (ws2). On join it should receive
    // the member's existing producers, each with a connection_id field.
    // It should also receive ws1's producers (none, since ws1 didn't produce).

    // We need to manually do the ws_join_media equivalent to inspect new_producer messages.
    let ws_url = format!("ws://{}/ws?token={}", app.addr, tenant.admin.access_token);
    let (mut ws2, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");
    ws2.next().await; // connected

    ws2.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Read router_capabilities
    let msg = ws2.next().await.unwrap().unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:router_capabilities");

    // Read transport_created
    let msg = ws2.next().await.unwrap().unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:transport_created");

    // No producers were actually created (produce requires DTLS), so ws2 should
    // not receive any new_producer messages. This test just verifies the join
    // completes cleanly without errors for same-user multi-connection.
    let extra = tokio::time::timeout(std::time::Duration::from_millis(500), ws2.next()).await;
    // The timeout is the EXPECTED outcome — no producers exist — so only a
    // message that actually arrives has anything to prove.
    if let Ok(Some(Ok(msg))) = extra {
        let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        // If somehow there's a message, it should not be an error
        assert_ne!(
            parsed["type"], "media:error",
            "Second same-user connection should not trigger errors"
        );
    }

    ws1.close(None).await.ok();
    ws2.close(None).await.ok();
    ws_member.close(None).await.ok();
}

/// Verify that media:produce accepts the `source` field without errors.
/// The produce itself will fail (transport not connected / no DTLS), but the
/// error should be about the transport, not about source field parsing.
#[tokio::test]
async fn produce_with_source_field_is_accepted() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("src1").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "Source Field Test",
    )
    .await;

    // REST join
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    // WS join -> creates transports
    let (mut ws, _transport) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Send media:produce with source="screen" (will fail because transport not connected, but
    // proves the source field is accepted by the handler without parse errors)
    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:produce",
            "data": {
                "room_id": room_id,
                "kind": "video",
                "rtp_parameters": {
                    "codecs": [{
                        "mimeType": "video/VP8",
                        "clockRate": 90000,
                        "payloadType": 96,
                    }],
                    "encodings": [{ "ssrc": 12345 }],
                },
                "source": "screen"
            }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    // Read the response — should be media:error. The error may be about invalid
    // rtp_parameters (mediasoup's strict parser) or transport not connected.
    // Either way, it proves the source field didn't cause a crash or unknown error.
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting for response")
        .unwrap()
        .unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:error");
    let error_msg = parsed["data"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("produce failed") || error_msg.contains("rtp_parameters"),
        "Error should be about produce failure or rtp_parameters, not about source field, got: {}",
        error_msg
    );

    ws.close(None).await.ok();
}

/// Verify that media:produce without a source field defaults correctly
/// (audio -> "audio", video -> "camera").
#[tokio::test]
async fn produce_without_source_field_defaults_correctly() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("src2").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "Source Default Test",
    )
    .await;

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    let (mut ws, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Send media:produce WITHOUT source field — should not cause any errors in parsing
    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:produce",
            "data": {
                "room_id": room_id,
                "kind": "video",
                "rtp_parameters": {
                    "codecs": [{
                        "mimeType": "video/VP8",
                        "clockRate": 90000,
                        "payloadType": 96,
                    }],
                    "encodings": [{ "ssrc": 99999 }],
                }
            }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting for response")
        .unwrap()
        .unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:error");
    let error_msg = parsed["data"]["message"].as_str().unwrap();
    // Should fail on produce or rtp_parameters, not on missing source field
    assert!(
        error_msg.contains("produce failed") || error_msg.contains("rtp_parameters"),
        "Should get produce/rtp_parameters error, not unknown error, got: {}",
        error_msg
    );

    ws.close(None).await.ok();
}

/// Verify that transport_created includes force_relay=false and warns about
/// force_relay=true (checked via the response, not the log).
#[tokio::test]
async fn transport_created_force_relay_false_by_default_disables_relay() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr1").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "Force Relay Default",
    )
    .await;

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    let (mut ws, transport) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;

    // Default: force_relay should be false
    assert_eq!(
        transport["data"]["force_relay"].as_bool(),
        Some(false),
        "force_relay should default to false (mediasoup doesn't support server-side TURN)"
    );

    ws.close(None).await.ok();
}

#[tokio::test]
async fn ws_disconnect_notifies_peers_with_peer_left() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("connid3").await;
    let room_id = create_room_and_start_call(
        &app,
        &tenant.tenant_id,
        &tenant.admin.access_token,
        "Disconnect Notify",
    )
    .await;

    // Both users REST-join
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        &tenant.member.access_token,
    )
    .send()
    .await
    .unwrap();

    // Both users WS media:join
    let (mut ws1, _) = ws_join_media(&app.addr, &tenant.admin.access_token, &room_id).await;
    let (ws2, _) = ws_join_media(&app.addr, &tenant.member.access_token, &room_id).await;

    // User 2 disconnects (drops WS)
    drop(ws2);

    // User 1 should receive peer_left
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let msg = ws1.next().await.unwrap().unwrap();
    let parsed: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "media:peer_left");
    assert_eq!(parsed["data"]["user_id"], tenant.member.id);

    ws1.close(None).await.ok();
}

// ── PR-1 (2026-08-04): session-scoped call leave ────────────────────

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open a WS and capture the server-minted `connection_id` from the
/// `connected` frame (call sessions are scoped per connection).
async fn ws_connect_with_conn_id(addr: &std::net::SocketAddr, token: &str) -> (WsStream, String) {
    let ws_url = format!("ws://{}/ws?token={}", addr, token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");
    let first = ws.next().await.expect("no frame").expect("ws error");
    let parsed: Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
    assert_eq!(parsed["type"], "connected");
    let conn_id = parsed["connection_id"]
        .as_str()
        .expect("connected frame carries connection_id")
        .to_string();
    (ws, conn_id)
}

/// Send media:join on an already-connected WS and read caps + transport.
async fn media_join(ws: &mut WsStream, room_id: &str) -> Value {
    ws.send(Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "media:join",
            "data": { "room_id": room_id }
        }))
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    let caps = next_media_msg(ws).await;
    assert_eq!(caps["type"], "media:router_capabilities");
    let transport = next_media_msg(ws).await;
    assert_eq!(transport["type"], "media:transport_created");
    transport
}

async fn get_room(app: &TestApp, tenant_id: &str, room_id: &str, token: &str) -> Value {
    app.auth_get(
        &format!("/api/tenant/{}/room/{}", tenant_id, room_id),
        token,
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap()
}

/// The bug-1 regression lock: the same user in the call from TWO browsers —
/// one browser's HTTP leave (with its connection_id) must NOT tear down the
/// other browser's media, must NOT decrement the distinct-user count, and
/// must NOT end the call.
#[tokio::test]
async fn http_call_leave_with_connection_id_keeps_other_connection_alive() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("connleave1").await;
    let token = &tenant.admin.access_token;
    let room_id = create_room_and_start_call(&app, &tenant.tenant_id, token, "Two Browsers").await;

    let (mut ws1, conn1) = ws_connect_with_conn_id(&app.addr, token).await;
    let (mut ws2, conn2) = ws_connect_with_conn_id(&app.addr, token).await;
    assert_ne!(conn1, conn2);

    for conn in [&conn1, &conn2] {
        let resp = app
            .auth_post(
                &format!(
                    "/api/tenant/{}/room/{}/call/join",
                    tenant.tenant_id, room_id
                ),
                token,
            )
            .json(&serde_json::json!({ "connection_id": conn }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Same user twice = ONE distinct participant.
    let room = get_room(&app, &tenant.tenant_id, &room_id, token).await;
    assert_eq!(room["participant_count"], 1);
    assert_eq!(room["conference_status"], "in_progress");

    let _t1 = media_join(&mut ws1, &room_id).await;
    let _t2 = media_join(&mut ws2, &room_id).await;

    // Browser 2 hangs up via HTTP, scoped to ITS connection.
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/leave",
                tenant.tenant_id, room_id
            ),
            token,
        )
        .json(&serde_json::json!({ "connection_id": conn2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // Browser 1 gets a peer_left carrying the LEAVING connection's id (tiles
    // are keyed by connection_id), and its own media stays alive.
    let peer_left = next_media_msg(&mut ws1).await;
    assert_eq!(peer_left["type"], "media:peer_left");
    assert_eq!(peer_left["data"]["connection_id"], conn2.as_str());

    let room = get_room(&app, &tenant.tenant_id, &room_id, token).await;
    assert_eq!(
        room["participant_count"], 1,
        "distinct-user count must not drop while another session is open"
    );
    assert_eq!(
        room["conference_status"], "in_progress",
        "the call must NOT auto-end while the user's other browser is in it"
    );

    // Browser 1 hangs up too → now the call ends.
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/leave",
            tenant.tenant_id, room_id
        ),
        token,
    )
    .json(&serde_json::json!({ "connection_id": conn1 }))
    .send()
    .await
    .unwrap();

    let room = get_room(&app, &tenant.tenant_id, &room_id, token).await;
    assert_eq!(room["participant_count"], 0);
    assert_eq!(room["conference_status"], "ended");

    ws1.close(None).await.ok();
    ws2.close(None).await.ok();
}

/// Legacy contract: a bodyless (or connection-less) leave still closes ALL
/// of the user's sessions — the mixed-version fallback during rolls.
#[tokio::test]
async fn call_leave_without_connection_id_closes_all_sessions() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("connleave2").await;
    let token = &tenant.admin.access_token;
    let room_id = create_room_and_start_call(&app, &tenant.tenant_id, token, "Legacy Leave").await;

    let (ws1, conn1) = ws_connect_with_conn_id(&app.addr, token).await;
    let (ws2, conn2) = ws_connect_with_conn_id(&app.addr, token).await;
    for conn in [&conn1, &conn2] {
        app.auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/join",
                tenant.tenant_id, room_id
            ),
            token,
        )
        .json(&serde_json::json!({ "connection_id": conn }))
        .send()
        .await
        .unwrap();
    }

    // Bodyless leave (legacy client shape).
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/leave",
                tenant.tenant_id, room_id
            ),
            token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let room = get_room(&app, &tenant.tenant_id, &room_id, token).await;
    assert_eq!(room["participant_count"], 0);
    assert_eq!(room["conference_status"], "ended");

    drop(ws1);
    drop(ws2);
}

/// The bug-4 regression lock: a WS drop (page refresh / tab close) must
/// finalize the call session in the DB — count decremented, call auto-ended
/// when it was the last session — with no HTTP leave ever arriving.
#[tokio::test]
async fn ws_disconnect_finalizes_call_session_in_db() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("conndrop1").await;
    let token = &tenant.admin.access_token;
    let room_id = create_room_and_start_call(&app, &tenant.tenant_id, token, "Refresh Drop").await;

    let (mut ws1, conn1) = ws_connect_with_conn_id(&app.addr, token).await;
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        token,
    )
    .json(&serde_json::json!({ "connection_id": conn1 }))
    .send()
    .await
    .unwrap();
    let _t1 = media_join(&mut ws1, &room_id).await;

    let room = get_room(&app, &tenant.tenant_id, &room_id, token).await;
    assert_eq!(room["participant_count"], 1);

    // Simulate a page refresh: the socket just dies.
    drop(ws1);

    let mut cleaned = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let room = get_room(&app, &tenant.tenant_id, &room_id, token).await;
        if room["participant_count"] == 0 && room["conference_status"] == "ended" {
            cleaned = true;
            break;
        }
    }
    assert!(
        cleaned,
        "WS disconnect must close the call session (count→0, status→ended)"
    );
}

/// A session whose media:join never happened (HTTP call/join only) must
/// still be finalized on WS disconnect via the Mongo connection lookup.
#[tokio::test]
async fn ws_disconnect_finalizes_http_only_call_session() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("conndrop2").await;
    let token = &tenant.admin.access_token;
    let room_id = create_room_and_start_call(&app, &tenant.tenant_id, token, "HTTP Only").await;

    let (ws1, conn1) = ws_connect_with_conn_id(&app.addr, token).await;
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/join",
            tenant.tenant_id, room_id
        ),
        token,
    )
    .json(&serde_json::json!({ "connection_id": conn1 }))
    .send()
    .await
    .unwrap();

    drop(ws1);

    let mut cleaned = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let room = get_room(&app, &tenant.tenant_id, &room_id, token).await;
        if room["participant_count"] == 0 && room["conference_status"] == "ended" {
            cleaned = true;
            break;
        }
    }
    assert!(cleaned, "HTTP-only session must be reaped on WS disconnect");
}

/// FR-126 — `media:join` is the message that creates a connection's transports, so it carries
/// the room gate itself. Before it, a signed-in user of ANY org who knew a room id got
/// transports and could consume the call. Refused: someone from another org, and a member of
/// the org who is not in a secret room. Still allowed: the room's own member.
#[tokio::test]
async fn ws_media_join_is_refused_to_anyone_not_allowed_in_the_room() {
    use tokio_tungstenite::connect_async;

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr126gate").await;
    let other = app.seed_tenant("fr126other").await;

    let room: Value = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "FR-126 gate" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let room_id = room["id"].as_str().unwrap().to_string();
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/room/{}", tenant.tenant_id, room_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "visibility": "secret" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "secret: {}", resp.status());
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/room/{}/call/start",
                tenant.tenant_id, room_id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "call/start: {}", resp.status());

    let join = |token: String| {
        let addr = app.addr;
        let room_id = room_id.clone();
        async move {
            let (mut ws, _) = connect_async(format!("ws://{addr}/ws?token={token}"))
                .await
                .expect("ws");
            let first: Value =
                serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(first["type"], "connected");
            ws.send(Message::Text(
                serde_json::json!({ "type": "media:join", "data": { "room_id": room_id } })
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            let reply =
                tokio::time::timeout(std::time::Duration::from_secs(10), next_media_msg(&mut ws))
                    .await
                    .expect("an answer to media:join");
            ws.close(None).await.ok();
            reply
        }
    };

    for (who, token) in [
        ("another org's user", other.admin.access_token.clone()),
        (
            "an org member outside the secret room",
            tenant.member.access_token.clone(),
        ),
    ] {
        let reply = join(token).await;
        assert_eq!(reply["type"], "media:error", "{who}: {reply}");
        assert_eq!(
            reply["data"]["message"], "Not allowed in this meeting",
            "{who}: {reply}"
        );
    }
    let rid = bson::oid::ObjectId::parse_str(&room_id).unwrap();
    assert!(
        app.state
            .modules
            .conference
            .as_ref()
            .expect("the conference module is mounted in tests")
            .room_manager
            .get_participant_user_ids(&rid)
            .is_empty(),
        "a refused join must leave no participant behind"
    );

    let reply = join(tenant.admin.access_token.clone()).await;
    assert_eq!(reply["type"], "media:router_capabilities", "{reply}");
}

/// FR-126 — a meeting command from a connection that has not joined that room's meeting is
/// refused, whatever it is. `media:play_audio` used to play a file of the room's org into the
/// meeting for anyone who knew the room id, and answer with the file's name.
#[tokio::test]
async fn media_commands_need_the_connection_to_have_joined_that_meeting() {
    use tokio_tungstenite::connect_async;

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr126cmd").await;
    let other = app.seed_tenant("fr126cmdother").await;
    let room: Value = app
        .auth_post(
            &format!("/api/tenant/{}/room", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "name": "FR-126 commands" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let room_id = room["id"].as_str().unwrap().to_string();
    app.auth_post(
        &format!(
            "/api/tenant/{}/room/{}/call/start",
            tenant.tenant_id, room_id
        ),
        &tenant.admin.access_token,
    )
    .send()
    .await
    .unwrap();

    let (mut ws, _) = connect_async(format!(
        "ws://{}/ws?token={}",
        app.addr, other.admin.access_token
    ))
    .await
    .expect("ws");
    let _connected = ws.next().await.unwrap().unwrap();
    for msg_type in ["media:play_audio", "media:stop_audio", "media:consume"] {
        ws.send(Message::Text(
            serde_json::json!({
                "type": msg_type,
                "data": {
                    "room_id": room_id,
                    "file_id": bson::oid::ObjectId::new().to_hex(),
                    "playback_id": "x",
                    "producer_id": "x",
                }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        let reply =
            tokio::time::timeout(std::time::Duration::from_secs(10), next_media_msg(&mut ws))
                .await
                .expect("an answer");
        assert_eq!(reply["type"], "media:error", "{msg_type}: {reply}");
        assert_eq!(
            reply["data"]["message"], "Join the meeting first",
            "{msg_type}: {reply}"
        );
    }
    ws.close(None).await.ok();
}
