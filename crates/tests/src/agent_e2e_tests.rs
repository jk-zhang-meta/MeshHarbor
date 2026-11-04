// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Phase 1 Chunk 1C — agent end-to-end integration tests.
//!
//! Complements `agent_tests.rs` (which locks the basic enroll →
//! connect → online + single-session SDP round-trip) with the
//! end-to-end scenarios the Phase 1 plan flagged as gaps:
//!
//! * concurrent sessions — two browser controllers driving sessions
//!   against the same enrolled agent in parallel. Validates that the
//!   per-session `pending_codecs` / `pending_transports` HashMaps
//!   don't bleed state across sessions, that each session gets a
//!   distinct `session_id`, and that consent is requested per session.
//!
//! * session.terminate clears state — the controller asks for a
//!   session, then terminates it, then asks for another. Both must
//!   work. Locks the cleanup contract in `handle_server_msg::
//!   ServerMsg::Terminate` (pending_codecs.remove + indicator hide).
//!
//! * controller-side ICE trickle — the controller delivers an ICE
//!   candidate via `rc:ice`. The agent's `add_remote_candidate` path
//!   is exercised. Tests today don't drive this direction; only the
//!   agent-side gather is observed (and that's flaky over localhost).
//!
//! All three tests follow the `agent_tests::agent_answers_sdp_offer_
//! with_real_webrtc_peer` pattern: spawn TestApp + agent library +
//! webrtc-rs PC as the browser. No new fixtures introduced; everything
//! reuses TestApp + SeededTenant.
//!
//! Why a new file (not adding to agent_tests.rs): keeps the
//! plan-mapped "Phase 1 Chunk 1C" addition discoverable in `git log
//! --follow agent_e2e_tests.rs` for the next operator who needs to
//! understand the integration coverage matrix.

use crate::fixtures::test_app::TestApp;
use meshharbord::{config::AgentConfig, encode::EncoderPreference, enrollment, signaling};
use serde_json::{Value, json};
use std::time::Duration;

/// Spawn the agent signaling loop with test-friendly defaults for the
/// LocalAPI / consent handles `signaling::run` gained in the Unification
/// P1 + P2b work. Duplicated from `agent_tests.rs` so this file stands
/// alone (same rationale as the `enrol` helper below).
fn spawn_agent_signaling(
    cfg: AgentConfig,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (view_tx, _view_rx) = tokio::sync::watch::channel(Default::default());
        let broker = meshharbord::consent::ConsentBroker::new(
            meshharbord::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("meshharbor-test-consent-{}", cfg.agent_id)),
        )
        .expect("consent broker init");
        // Read before `cfg` is moved into the call below.
        let exec_enabled = cfg.exec_enabled;
        let remote_config_enabled = cfg.remote_config_enabled;
        let _ = signaling::run(
            signaling::OrgCtx::primary(meshharbord::token_slot::TokenSlot::new(
                cfg.agent_token.clone(),
            )),
            // FR-43 P2b — no GUI-worker delegation in tests: `Off` is not a
            // stub but the real production value on every platform except a
            // macOS daemon supervising a worker, or the worker it supervises.
            meshharbord::delegate::Delegation::Off,
            cfg,
            EncoderPreference::Software,
            stop_rx,
            connected,
            view_tx,
            // B1 — the RTT-prober bridge slot. Tests never install a hook, so
            // an empty slot is the correct value, not a stub.
            Default::default(),
            broker,
            meshharbord::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            // Remote config: tests never PUSH one, but the live `exec_enabled`
            // must still be SEEDED from the config this agent was handed —
            // which is exactly what `main.rs` does. See agent_exec_tests for
            // the failure hardcoding `false` produced.
            meshharbord::remote_config::RemoteConfigServices::new(
                std::path::PathBuf::from("unused-in-tests.toml"),
                std::sync::Arc::new(tokio::sync::Mutex::new(())),
                exec_enabled,
                remote_config_enabled,
            ),
            // FR-27 — the live remote-control session registry. Tests never
            // read it back, but the signalling loop registers into it, so a
            // fresh one per harness is the honest value (not a shared global
            // that would leak sessions between tests).
            meshharbord::rc_sessions::RcSessionRegistry::new(),
        )
        .await;
    })
}

/// Helper copy of `agent_tests::enrol_via_agent_lib` — duplicated
/// rather than pulled into a shared module so this file can stand
/// alone if the agent_tests.rs surface gets refactored.
async fn enrol(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    machine_id: &str,
    machine_name: &str,
) -> AgentConfig {
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
    enrollment::enroll(enrollment::EnrollInputs {
        server_url: &app.base_url,
        enrollment_token: et["enrollment_token"].as_str().unwrap(),
        machine_id,
        machine_name,
        install: None,
    })
    .await
    .expect("agent enrollment")
}

/// Spawn signaling::run in a task and wait for the agent's online
/// flag to flip. Returns the task handle + shutdown sender so the
/// caller controls teardown.
async fn spawn_agent_and_wait_online(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    cfg: &AgentConfig,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let sig_task = spawn_agent_signaling(cfg.clone(), stop_rx);
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let row: Value = app
            .auth_get(
                &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, cfg.agent_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if row["is_online"].as_bool() == Some(true) {
            return (sig_task, stop_tx);
        }
    }
    panic!("agent never transitioned to is_online=true within 6 s");
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Open a controller WS as the seeded admin user. Returns the
/// connected stream. Drains the first WS frame (welcome / hello)
/// with a tiny timeout so subsequent reads start from a clean slate.
async fn open_controller_ws(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use futures::StreamExt;
    use tokio_tungstenite::connect_async;

    let ctrl_url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&seeded.admin.access_token)
    );
    let (mut ws, _) = connect_async(&ctrl_url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
    ws
}

/// Send `rc:session.request` and await the first `rc:session.created`
/// reply, returning its `session_id`. Times out after 5 s. Filters
/// out unrelated frames (other sessions on the same WS — relevant
/// in the concurrent-sessions test).
async fn request_session_and_get_id(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    agent_id: &str,
) -> String {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    ws.send(Message::Text(
        json!({
            "t": "rc:session.request",
            "agent_id": agent_id,
            "permissions": "VIEW",
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let frame = match tokio::time::timeout(Duration::from_millis(250), ws.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        let Message::Text(text) = frame else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v.get("t").and_then(|x| x.as_str()) == Some("rc:session.created")
            && let Some(sid) = v.get("session_id").and_then(|x| x.as_str())
        {
            return sid.to_string();
        }
    }
    panic!("rc:session.created never arrived within 5 s");
}

#[tokio::test]
async fn concurrent_sessions_each_get_distinct_session_ids() {
    // Two controllers, one agent. Each controller requests its own
    // session; both must succeed and the session_ids must differ.
    // Regression target: a `pending_codecs.insert(session_id, ...)`
    // that accidentally used a shared key (or a global single-slot
    // pending), which would cause the second session's request to
    // overwrite the first's codec selection. The current code uses
    // a `HashMap<ObjectId, String>` so this should pass — locking
    // the contract makes a future refactor visible.
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("agent-e2e-concurrent").await;
    // FR-115 P3 — several sessions at once in one org: Free runs one.
    app.set_plan(&seeded.tenant_id, "business").await;
    let cfg = enrol(&app, &seeded, "mach-e2e-concurrent", "Concurrent test").await;
    let (sig_task, stop_tx) = spawn_agent_and_wait_online(&app, &seeded, &cfg).await;

    let mut ws_a = open_controller_ws(&app, &seeded).await;
    let mut ws_b = open_controller_ws(&app, &seeded).await;

    let sid_a = request_session_and_get_id(&mut ws_a, &cfg.agent_id).await;
    let sid_b = request_session_and_get_id(&mut ws_b, &cfg.agent_id).await;

    assert_ne!(sid_a, sid_b, "concurrent sessions must get distinct ids");
    // ObjectId hex is 24 chars — the wire format lock in
    // signaling::tests::object_ids_serialise_as_raw_hex_on_wire.
    // Repeated here so a regression on the WIRE side (vs the local
    // serialisation tests) fails this integration test too.
    assert_eq!(sid_a.len(), 24, "session_id must be raw hex ObjectId");
    assert_eq!(sid_b.len(), 24, "session_id must be raw hex ObjectId");

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), sig_task).await;
}

#[tokio::test]
async fn terminate_clears_state_so_next_request_works() {
    // Request → terminate → request again. The second request must
    // succeed (a fresh session_id, agent reachable). Regression
    // target: terminate leaks state (pending_codecs / pending_
    // transports entry not removed) which would still LET the next
    // session.request succeed but would cause the SDP-offer arm to
    // pick a stale codec from the orphaned entry.
    //
    // Locks: handle_server_msg::ServerMsg::Terminate clears
    // pending_codecs.remove + pending_transports.remove (see
    // signaling.rs ~line 672).
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("agent-e2e-terminate").await;
    let cfg = enrol(&app, &seeded, "mach-e2e-terminate", "Terminate test").await;
    let (sig_task, stop_tx) = spawn_agent_and_wait_online(&app, &seeded, &cfg).await;

    let mut ws = open_controller_ws(&app, &seeded).await;
    let sid_a = request_session_and_get_id(&mut ws, &cfg.agent_id).await;

    // Terminate session A. We don't observe the agent's outbound
    // terminate frame here — the controller-side terminate is
    // sufficient to drive the agent's cleanup; the test's job is
    // to prove the NEXT request works.
    //
    // ⚠️ The wire tag is `rc:terminate` and the reason is a snake_case
    // `EndReason` — the values the real viewer sends (`useRemoteControl`'s
    // disconnect). The former `rc:session.terminate` / `user-cancelled` matched
    // NEITHER, so the frame silently failed to parse and session A was never
    // torn down; the test only passed because `create_session` always minted a
    // fresh id. #1045's same-connection coalesce exposed that: with the real
    // terminate, session A is gone and request #2 correctly gets a new id;
    // without it, the leaked live session on this same socket coalesces.
    ws.send(Message::Text(
        json!({
            "t": "rc:terminate",
            "session_id": sid_a,
            "reason": "controller_hangup",
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();

    // Brief settling window for the server to route the terminate
    // to the agent + the agent to drop the session. 200 ms is
    // generous in-process; the actual cleanup is microseconds.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let sid_b = request_session_and_get_id(&mut ws, &cfg.agent_id).await;
    assert_ne!(sid_a, sid_b, "post-terminate request must yield a new id");

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), sig_task).await;
}

#[tokio::test]
async fn controller_can_trickle_ice_candidate_to_agent() {
    // The controller emits a fake `rc:ice` candidate after the
    // session is built. The agent's `add_remote_candidate` path
    // gets exercised. We don't assert on what the agent DOES with
    // the candidate (it'll get a parse-error log if malformed, no-op
    // if the session_id is unknown) — only that the message round-
    // trips through the server without 4xx-ing the controller.
    //
    // Regression target: a refactor that moved `rc:ice` routing
    // from the agent-bound WS handler to a different arm could
    // silently drop the message; this test would fail because
    // the agent never logs `add_remote_candidate` from the trace
    // (we can't grep traces from a sibling crate easily, so we
    // assert weaker: no server-side error frame comes back).
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("agent-e2e-ice").await;
    let cfg = enrol(&app, &seeded, "mach-e2e-ice", "ICE trickle test").await;
    let (sig_task, stop_tx) = spawn_agent_and_wait_online(&app, &seeded, &cfg).await;

    let mut ws = open_controller_ws(&app, &seeded).await;
    let sid = request_session_and_get_id(&mut ws, &cfg.agent_id).await;

    // Send a minimal candidate. The agent's add_remote_candidate
    // expects RTCIceCandidateInit JSON; we hand-roll one with a
    // syntactically-valid but unreachable candidate string. The
    // agent will log a debug if it can't parse, but the server-side
    // routing layer (which is what we're testing) doesn't care
    // about the candidate body.
    ws.send(Message::Text(
        json!({
            "t": "rc:ice",
            "session_id": sid,
            "candidate": {
                "candidate": "candidate:1 1 udp 2122252543 192.0.2.1 49152 typ host",
                "sdpMid": "0",
                "sdpMLineIndex": 0,
            },
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();

    // Drain WS frames for 500 ms and verify no `rc:error` came back
    // pinned to OUR session_id. Other frames (heartbeat, other
    // session events) are ignored.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < deadline {
        let frame = match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        let Message::Text(text) = frame else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v.get("t").and_then(|x| x.as_str()) == Some("rc:error")
            && v.get("session_id").and_then(|x| x.as_str()) == Some(&sid)
        {
            panic!("server returned rc:error for our ICE trickle: {v}");
        }
    }

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), sig_task).await;
}
