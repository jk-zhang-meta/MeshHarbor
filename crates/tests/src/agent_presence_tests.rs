// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Phase A-1 — cross-pod agent presence truth.
//!
//! Two-pod model: `TestApp::spawn_pair` runs two servers over ONE Mongo
//! database and the one shared Redis (`redis://127.0.0.1:6379`), each with
//! its own pod-local in-memory rc-hub — exactly the prod S6 topology that
//! produced the 2026-08-02 green-but-"not online" incident.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Normal authenticated hello publication must reach the ordinary Fleet DTO,
/// without treating this public identity as a capability or an SSH grant.
#[tokio::test]
async fn fleet_hostkey_registered_hello_is_public_member_metadata_and_scoped() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fleet-hostkey").await;
    let other = app.seed_tenant("fleet-hostkey-other").await;
    let (agent_id, token) = enroll(&app, &tenant, "fleet-hostkey-native-identity").await;
    let path = format!("/api/tenant/{}/agent/{agent_id}", tenant.tenant_id);
    let list_path = format!("/api/tenant/{}/agent?page=1&per_page=100", tenant.tenant_id);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&11u32.to_be_bytes());
    bytes.extend_from_slice(b"ssh-ed25519");
    bytes.extend_from_slice(&32u32.to_be_bytes());
    bytes.extend_from_slice(&[7u8; 32]);
    let first = format!("ssh-ed25519 {} fixture-first", STANDARD.encode(&bytes));
    bytes[19..].fill(9);
    let second = format!("ssh-ed25519 {} fixture-refreshed", STANDARD.encode(&bytes));
    let empty = String::new();
    for key in [&first, &second, &empty] {
        let url = format!(
            "ws://{}/ws?token={}&role=agent",
            app.addr,
            urlencode(&token)
        );
        let (mut ws, _) = connect_async(&url).await.unwrap();
        ws.send(Message::Text(
            json!({
                "t":"rc:agent.hello", "machine_name":"hostkey fixture", "os":"linux",
                "agent_version":"0.4.151", "displays":[], "ssh_host_pubkey":key,
                "caps":{"hw_encoders":[],"codecs":["h264"],"has_input_permission":true,
                        "supports_clipboard":false,"supports_file_transfer":false,
                        "max_simultaneous_sessions":1,"rpc":["ssh"]}
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let response = app
                .auth_get(&path, &tenant.member.access_token)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                200,
                "ordinary member retains read access"
            );
            let row: Value = response.json().await.unwrap();
            if row["is_online"] == true {
                assert!(
                    row["ssh_host_pubkey"].is_string(),
                    "registered host key must be an explicit top-level DTO string, even when empty"
                );
                if row["ssh_host_pubkey"] == key.as_str() {
                    assert!(row["capabilities"].get("ssh_host_pubkey").is_none());
                    for private in [
                        "agent_token",
                        "agent_token_hash",
                        "ssh_host_key",
                        "overlay_wg_secret_key",
                    ] {
                        assert!(
                            row.get(private).is_none(),
                            "private field leaked: {private}"
                        );
                    }
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "authenticated hello metadata did not refresh"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let list: Value = app
            .auth_get(&list_path, &tenant.member.access_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let row = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == agent_id)
            .unwrap();
        assert_eq!(row["ssh_host_pubkey"], key.as_str());
        let denied = app
            .client
            .put(app.url(&path))
            .bearer_auth(&tenant.member.access_token)
            .json(&json!({"tags":["no-escalation"]}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            denied.status(),
            403,
            "metadata read does not add MANAGE_AGENTS"
        );
        let changed: Value = app
            .client
            .put(app.url(&path))
            .bearer_auth(&tenant.admin.access_token)
            .json(&json!({"tags":["fixture"]}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            changed["agent"]["ssh_host_pubkey"],
            key.as_str(),
            "admin update reuses the same DTO"
        );
        ws.close(None).await.unwrap();
    }
    assert_eq!(
        reqwest::Client::new()
            .get(app.url(&path))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        app.auth_get(&path, &other.admin.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let foreign_id_path = format!("/api/tenant/{}/agent/{agent_id}", other.tenant_id);
    assert_eq!(
        app.auth_get(&foreign_id_path, &other.admin.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        app.client
            .delete(app.url(&path))
            .bearer_auth(&tenant.admin.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        app.auth_get(&path, &tenant.member.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let list: Value = app
        .auth_get(&list_path, &tenant.member.access_token)
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
            .any(|r| r["id"] == agent_id)
    );
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

pub(crate) async fn enroll(
    app: &TestApp,
    seeded: &SeededTenant,
    machine_id: &str,
) -> (String, String) {
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
            "machine_name": "presence test box",
            "os": "linux",
            "agent_version": "0.1.0",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        ej["agent_id"].as_str().unwrap().to_string(),
        ej["agent_token"].as_str().unwrap().to_string(),
    )
}

/// Connect an agent WS to `app` and complete the hello handshake.
pub(crate) async fn connect_agent(
    app: &TestApp,
    agent_token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let ws_url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        urlencode(agent_token)
    );
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connect");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "presence test box",
        "os": "linux",
        "agent_version": "0.1.0",
        "displays": [],
        "caps": {
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
        }
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

/// Fetch one agent's listing row via `app`'s HTTP API.
async fn fetch_agent_row(app: &TestApp, seeded: &SeededTenant, agent_id: &str) -> Value {
    let resp: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp
}

/// (a) Agent's WS on pod 1 → listing served by pod 2 reads `presence:
/// "online"` through the Redis directory (pod 2's local hub has no entry —
/// pre-A-1 this was the exact green-but-dead disjunction, now it is TRUE
/// reachability knowledge).
#[tokio::test]
async fn presence_online_cross_pod_via_redis() {
    let (app1, app2) = TestApp::spawn_pair(|_| {}).await;
    if app1.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("presx").await;
    let (agent_id, agent_token) = enroll(&app1, &seeded, "mach-presx-a").await;

    let mut ws = connect_agent(&app1, &agent_token).await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // Sanity: pod 2's LOCAL hub genuinely doesn't know the agent.
    let aid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();
    assert!(!app2.state.fleet().rc_hub.is_agent_online(aid));
    assert!(app1.state.fleet().rc_hub.is_agent_online(aid));

    let row = fetch_agent_row(&app2, &seeded, &agent_id).await;
    assert_eq!(row["presence"], "online", "row: {row}");
    assert_eq!(row["is_online"], true);

    let _ = ws.close(None).await;
}

/// (b) Re-home race: agent moves pod 1 → pod 2; pod 1's LATE teardown must
/// not release pod 2's fresh Redis claim, and the heartbeat self-heal
/// bounds the Mongo status clobber.
#[tokio::test]
async fn rehome_race_keeps_newest_claim() {
    let (app1, app2) = TestApp::spawn_pair(|_| {}).await;
    if app1.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("presy").await;
    let (agent_id, agent_token) = enroll(&app1, &seeded, "mach-presy-a").await;
    let aid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();

    // Old socket on pod 1, then the agent re-homes to pod 2.
    let mut ws_old = connect_agent(&app1, &agent_token).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut ws_new = connect_agent(&app2, &agent_token).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Tear the OLD socket down LAST — its compare-DEL must no-op against
    // pod 2's newer claim.
    let _ = ws_old.close(None).await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    assert!(app2.state.fleet().rc_hub.is_agent_online(aid));
    let row = fetch_agent_row(&app1, &seeded, &agent_id).await;
    assert_eq!(
        row["presence"], "online",
        "old teardown must not erase the new claim: {row}"
    );

    // The old teardown may have written status Offline (cross-pod removal
    // is not identity-gated across hubs by design); a heartbeat self-heals
    // it within one beat.
    ws_new
        .send(Message::Text(
            json!({"t": "rc:agent.heartbeat", "rss_mb": 0, "cpu_pct": 0.0, "active_sessions": 0})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let row = fetch_agent_row(&app1, &seeded, &agent_id).await;
    assert_eq!(row["status"], "online", "heartbeat self-heal: {row}");

    let _ = ws_new.close(None).await;
}

/// (c) Server receive-liveness: a silent socket (no heartbeats, no pings —
/// the half-open middlebox shape) is reaped within the shortened deadline;
/// the teardown flips presence away from "online".
#[tokio::test]
async fn rx_deadline_reaps_silent_socket() {
    let app = TestApp::spawn_with_settings(|s| {
        s.rc.ws_rx_deadline_secs = 2;
        s.rc.ws_liveness_tick_secs = 1;
    })
    .await;
    let seeded = app.seed_tenant("presz").await;
    let (agent_id, agent_token) = enroll(&app, &seeded, "mach-presz-a").await;
    let aid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();

    let ws = connect_agent(&app, &agent_token).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(app.state.fleet().rc_hub.is_agent_online(aid));

    // Go silent WITHOUT closing (a close frame would be a normal
    // disconnect, not a reap). Leaking the stream keeps the TCP socket
    // open with no traffic — the middlebox half-open shape.
    std::mem::forget(ws);

    // Deadline 2 s, tick 1 s ⇒ reaped in ≤ ~4 s.
    let mut reaped = false;
    for _ in 0..12 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if !app.state.fleet().rc_hub.is_agent_online(aid) {
            reaped = true;
            break;
        }
    }
    assert!(
        reaped,
        "silent agent socket was not reaped by the rx deadline"
    );

    let row = fetch_agent_row(&app, &seeded, &agent_id).await;
    assert_ne!(row["presence"], "online", "row: {row}");
    assert_eq!(row["is_online"], false);
}

/// (d) Graceful shutdown sweep: `shutdown_cleanup` cancels local sockets,
/// bulk-offlines their rows, and releases presence.
#[tokio::test]
async fn shutdown_cleanup_marks_local_agents_offline() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("presw").await;
    let (agent_id, agent_token) = enroll(&app, &seeded, "mach-presw-a").await;
    let aid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();

    let _ws = connect_agent(&app, &agent_token).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(app.state.fleet().rc_hub.is_agent_online(aid));

    roomler_ai_api::state::shutdown_cleanup(&app.state).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(!app.state.fleet().rc_hub.is_agent_online(aid));
    let row = fetch_agent_row(&app, &seeded, &agent_id).await;
    assert_ne!(row["presence"], "online", "row: {row}");
    assert_eq!(row["status"], "offline", "row: {row}");
}

// ─── P4 — device:presence push events ───────────────────────────────────

/// Await the next `{type: <ty>}` frame on a USER WebSocket, skipping
/// unrelated events, within `secs`.
async fn wait_for_event(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    ty: &str,
    secs: u64,
) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let msg = tokio::time::timeout(remaining, ws.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {ty}"))
            .expect("ws stream ended")
            .expect("ws frame error");
        let Ok(v) = serde_json::from_str::<Value>(msg.to_text().unwrap_or_default()) else {
            continue;
        };
        if v["type"] == ty {
            return v;
        }
    }
}

/// (f) P4 — an agent WS connect pushes `device:presence` online to a
/// tenant member's user socket; the disconnect pushes offline. The
/// payload carries tenant_id + the batched agents list.
#[tokio::test]
async fn device_presence_events_on_connect_and_disconnect() {
    let app = TestApp::spawn_with_settings(|s| {
        s.rc.presence_batch_ms = 50;
    })
    .await;
    let seeded = app.seed_tenant("presp4a").await;

    let ws_url = format!("ws://{}/ws?token={}", app.addr, seeded.member.access_token);
    let (mut user_ws, _) = connect_async(&ws_url).await.expect("user ws connect");
    user_ws.next().await; // drain the `connected` frame

    let (agent_id, agent_token) = enroll(&app, &seeded, "mach-presp4-a").await;
    let mut agent_ws = connect_agent(&app, &agent_token).await;

    let ev = wait_for_event(&mut user_ws, "device:presence", 5).await;
    assert_eq!(
        ev["data"]["tenant_id"],
        seeded.tenant_id.as_str(),
        "ev: {ev}"
    );
    let agents = ev["data"]["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1, "ev: {ev}");
    assert_eq!(agents[0]["agent_id"], agent_id.as_str());
    assert_eq!(agents[0]["presence"], "online");
    assert!(agents[0]["name"].is_string());

    let _ = agent_ws.close(None).await;
    let ev = wait_for_event(&mut user_ws, "device:presence", 5).await;
    let agents = ev["data"]["agents"].as_array().unwrap();
    assert_eq!(agents[0]["agent_id"], agent_id.as_str());
    assert_eq!(agents[0]["presence"], "offline", "ev: {ev}");
}

/// (g) P4 — the staleness sweep: a stranded row (status Online + fresh
/// heartbeat, no socket anywhere) transitions to `stale`; once the
/// heartbeat trail ages out it transitions to `offline` AND the row's
/// status is healed. The `last_presence` ledger dedupes: a repeat sweep
/// with no change announces nothing.
#[tokio::test]
async fn presence_sweep_transitions_stale_then_offline_once() {
    let app = TestApp::spawn_with_settings(|s| {
        s.rc.presence_batch_ms = 50;
    })
    .await;
    let seeded = app.seed_tenant("presp4b").await;

    let ws_url = format!("ws://{}/ws?token={}", app.addr, seeded.member.access_token);
    let (mut user_ws, _) = connect_async(&ws_url).await.expect("user ws connect");
    user_ws.next().await;

    let (agent_id, _token) = enroll(&app, &seeded, "mach-presp4-b").await;
    let aid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();

    use bson::doc;
    let agents_coll = app.db.collection::<bson::Document>("agents");
    // Fabricate the stranded shape: last broadcast said online, Mongo still
    // says Online + fresh heartbeat, but no socket ever registered.
    agents_coll
        .update_one(
            doc! { "_id": aid },
            doc! { "$set": {
                "status": "online",
                "last_seen_at": bson::DateTime::now(),
                "last_presence": "online",
            } },
        )
        .await
        .unwrap();

    let n = roomler_ai_mod_fleet::presence::run_presence_sweep(app.state.fleet()).await;
    assert_eq!(n, 1, "fresh-heartbeat stranded row must announce stale");
    let ev = wait_for_event(&mut user_ws, "device:presence", 5).await;
    assert_eq!(ev["data"]["agents"][0]["presence"], "stale", "ev: {ev}");

    // Unchanged state ⇒ the ledger CAS keeps a repeat sweep silent.
    let n = roomler_ai_mod_fleet::presence::run_presence_sweep(app.state.fleet()).await;
    assert_eq!(n, 0, "repeat sweep with no transition must be silent");

    // Age the heartbeat past the 90 s freshness window ⇒ offline + heal.
    let aged = bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 120_000);
    agents_coll
        .update_one(
            doc! { "_id": aid },
            doc! { "$set": { "last_seen_at": aged } },
        )
        .await
        .unwrap();
    let n = roomler_ai_mod_fleet::presence::run_presence_sweep(app.state.fleet()).await;
    assert_eq!(n, 1);
    let ev = wait_for_event(&mut user_ws, "device:presence", 5).await;
    assert_eq!(ev["data"]["agents"][0]["presence"], "offline", "ev: {ev}");

    let row = agents_coll
        .find_one(doc! { "_id": aid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.get_str("status").unwrap(),
        "offline",
        "row status healed"
    );
    assert_eq!(row.get_str("last_presence").unwrap(), "offline");

    // Offline rows leave the scan set entirely.
    let n = roomler_ai_mod_fleet::presence::run_presence_sweep(app.state.fleet()).await;
    assert_eq!(n, 0);
}

/// (h) P4 — re-home suppression: when the agent moves pod 1 → pod 2, the
/// OLD socket's late teardown must NOT announce offline (a foreign pod
/// owns the presence record and the device is alive). Closing the NEW
/// socket afterwards must still announce offline — proving silence came
/// from suppression, not a broken pipeline.
#[tokio::test]
async fn rehome_teardown_does_not_announce_offline() {
    let (app1, app2) = TestApp::spawn_pair(|s| {
        s.rc.presence_batch_ms = 50;
    })
    .await;
    if app1.state.redis_pubsub.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("presp4c").await;

    let ws_url = format!("ws://{}/ws?token={}", app1.addr, seeded.member.access_token);
    let (mut user_ws, _) = connect_async(&ws_url).await.expect("user ws connect");
    user_ws.next().await;

    let (_agent_id, agent_token) = enroll(&app1, &seeded, "mach-presp4-c").await;
    let mut ws_old = connect_agent(&app1, &agent_token).await;
    let ev = wait_for_event(&mut user_ws, "device:presence", 5).await;
    assert_eq!(ev["data"]["agents"][0]["presence"], "online");

    // Re-home to pod 2, then tear the OLD socket down last.
    let mut ws_new = connect_agent(&app2, &agent_token).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let _ = ws_old.close(None).await;

    // No offline may arrive: the ledger stayed "online" throughout, and the
    // old teardown saw pod 2's foreign claim. Drain the WHOLE quiet window —
    // one unrelated frame must not mask a late wrongful offline behind it.
    let quiet_deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1200);
    loop {
        let remaining = quiet_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(Some(Ok(msg))) = tokio::time::timeout(remaining, user_ws.next()).await else {
            break;
        };
        let v: Value = serde_json::from_str(msg.to_text().unwrap_or_default()).unwrap_or_default();
        assert_ne!(
            (
                v["type"].as_str(),
                v["data"]["agents"][0]["presence"].as_str()
            ),
            (Some("device:presence"), Some("offline")),
            "re-homed agent's old-socket teardown must not announce offline: {v}"
        );
    }

    // The pipeline still works: closing the LIVE socket announces offline.
    let _ = ws_new.close(None).await;
    let ev = wait_for_event(&mut user_ws, "device:presence", 5).await;
    assert_eq!(ev["data"]["agents"][0]["presence"], "offline", "ev: {ev}");
}

/// (e) The "stale" state: heartbeat trail fresh + status Online in Mongo,
/// but NO socket anywhere (the stranded-row shape a hard-killed pod
/// leaves) ⇒ amber `stale`, `is_online: false` — never a green lie.
#[tokio::test]
async fn stale_when_heartbeat_fresh_but_no_socket() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("presv").await;
    let (agent_id, _token) = enroll(&app, &seeded, "mach-presv-a").await;
    let aid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();

    // Fabricate the stranded row directly: status Online + fresh
    // last_seen_at, no WS ever connected.
    use bson::doc;
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": aid },
            doc! { "$set": { "status": "online", "last_seen_at": bson::DateTime::now() } },
        )
        .await
        .unwrap();

    let row = fetch_agent_row(&app, &seeded, &agent_id).await;
    assert_eq!(row["presence"], "stale", "row: {row}");
    assert_eq!(row["is_online"], false, "stale must not read green: {row}");
}

/// #2552 — after a fast reconnect, the displaced connection's teardown
/// writes `Offline` only while the row still names it. Each hello names its
/// connection. Once a newer hello holds the row, the old connection's late
/// write matches nothing, in whichever order the two land, and the newer
/// connection's own teardown still writes it.
#[tokio::test]
async fn a_displaced_connections_late_offline_leaves_the_newer_hello_online() {
    use roomler_ai_remote_control::models::{AgentCaps, AgentStatus};
    use roomler_ai_services::dao::agent::AgentDao;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("p2552").await;
    let (agent_id, _) = enroll(&app, &seeded, "mach-2552").await;
    let id = bson::oid::ObjectId::parse_str(&agent_id).unwrap();
    let dao = AgentDao::new(&app.db);
    for conn in ["the-old-connection", "the-new-connection"] {
        dao.update_hello(
            id,
            "0.4.147",
            &[],
            &AgentCaps::default(),
            &[],
            "",
            "",
            "",
            "",
            false,
            conn,
        )
        .await
        .unwrap();
    }
    let status = || async { dao.base.find_by_id(id).await.unwrap().status };
    assert!(
        !dao.mark_offline_if_conn(id, "the-old-connection")
            .await
            .unwrap(),
        "the displaced connection's write matches nothing"
    );
    assert!(matches!(status().await, AgentStatus::Online));
    assert!(
        dao.mark_offline_if_conn(id, "the-new-connection")
            .await
            .unwrap(),
        "the connection that holds the row writes its own offline"
    );
    assert!(matches!(status().await, AgentStatus::Offline));
}
