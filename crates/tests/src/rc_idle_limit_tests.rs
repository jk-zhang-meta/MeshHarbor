// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-101 P4b-2 — the idle limit, through a real server, a real MongoDB and
//! the REAL agent library (`meshharbord::signaling::run`).
//!
//! The device keeps this limit, since only it sees both halves of "idle" (the
//! controller's input rides the peer-to-peer channels, the pixels never leave
//! the device). So these cells drive the agent itself. A session that goes
//! live and then sees no input and no frames (this test build captures
//! nothing) must be ended BY THE AGENT as `IdleTimeout` with `limit: "idle"`,
//! which the hub names to the controller and in the `session_ended` audit
//! row. The route and the hub's half (what rides to whom, who may name the
//! limit) are covered with a raw agent socket in `rc_session_limits_tests`.
//! #2251's cells (`rc_no_common_codec_tests`) drive the same agent through
//! the helpers here.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use meshharbord::{config::AgentConfig, encode::EncoderPreference, enrollment, signaling};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use webrtc::peer_connection::RTCPeerConnection;

pub(crate) type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub(crate) fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Spawn the agent signalling loop with test-friendly defaults. Duplicated
/// from `agent_e2e_tests.rs` so this file stands alone, as that one is.
pub(crate) fn spawn_agent_signaling(
    cfg: AgentConfig,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (view_tx, _view_rx) = tokio::sync::watch::channel(Default::default());
        let broker = meshharbord::consent::ConsentBroker::new(
            meshharbord::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("meshharbor-test-consent-{}", cfg.agent_id)),
        )
        .expect("consent broker init");
        let exec_enabled = cfg.exec_enabled;
        let remote_config_enabled = cfg.remote_config_enabled;
        let _ = signaling::run(
            signaling::OrgCtx::primary(meshharbord::token_slot::TokenSlot::new(
                cfg.agent_token.clone(),
            )),
            meshharbord::delegate::Delegation::Off,
            cfg,
            EncoderPreference::Software,
            stop_rx,
            connected,
            view_tx,
            Default::default(),
            broker,
            meshharbord::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            meshharbord::remote_config::RemoteConfigServices::new(
                std::path::PathBuf::from("unused-in-tests.toml"),
                Arc::new(tokio::sync::Mutex::new(())),
                exec_enabled,
                remote_config_enabled,
            ),
            meshharbord::rc_sessions::RcSessionRegistry::new(),
        )
        .await;
    })
}

/// Enroll a device through the agent library, as `agent_e2e_tests` does.
pub(crate) async fn enrol(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> AgentConfig {
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
        machine_name: machine_id,
        install: None,
    })
    .await
    .expect("agent enrollment")
}

/// Wait for the agent's row to say online. Polled gently, and a refusal is a
/// reason to look again, never a panic: TestApp's per-IP limiter answers a
/// fast poll with a 429 that is not JSON, which once hid the real failure (an
/// agent that never started) behind a decode error.
pub(crate) async fn wait_online(app: &TestApp, seeded: &SeededTenant, cfg: &AgentConfig) {
    let url = format!("/api/tenant/{}/agent/{}", seeded.tenant_id, cfg.agent_id);
    for _ in 0..40 {
        if let Ok(resp) = app.auth_get(&url, &seeded.admin.access_token).send().await
            && resp.status().is_success()
            && let Ok(row) = resp.json::<Value>().await
            && row["is_online"].as_bool() == Some(true)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the agent never came online");
}

/// The next frame of type `t` on `ws` within `within`, or `None`.
pub(crate) async fn next_of(ws: &mut Ws, t: &str, within: Duration) -> Option<Value> {
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

/// Open a session to the real agent and drive it LIVE with a real webrtc-rs
/// offer: the agent auto-grants, builds its peer and answers. Returns the
/// controller's socket, the session id, the `rc:session.created` frame and the
/// browser's peer connection, which the caller closes (dropping one frees
/// none of its sockets).
async fn go_live(
    app: &TestApp,
    token: &str,
    agent_id: &str,
) -> (Ws, String, Value, Arc<RTCPeerConnection>) {
    use webrtc::api::APIBuilder;
    use webrtc::api::media_engine::MediaEngine;
    use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
    use webrtc::peer_connection::configuration::RTCConfiguration;

    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let api = APIBuilder::new().with_media_engine(me).build();
    let pc = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    let _dc = pc
        .create_data_channel("control", Some(RTCDataChannelInit::default()))
        .await
        .unwrap();
    let offer = pc.create_offer(None).await.unwrap();
    pc.set_local_description(offer.clone()).await.unwrap();

    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ctl, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(500), ctl.next()).await;
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
    let created = next_of(&mut ctl, "rc:session.created", Duration::from_secs(10))
        .await
        .expect("rc:session.created");
    let sid = created["session_id"].as_str().unwrap().to_string();
    next_of(&mut ctl, "rc:ready", Duration::from_secs(10))
        .await
        .expect("rc:ready (the agent auto-grants)");
    ctl.send(Message::Text(
        json!({ "t": "rc:sdp.offer", "session_id": sid, "sdp": offer.sdp })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    next_of(&mut ctl, "rc:sdp.answer", Duration::from_secs(10))
        .await
        .expect("the agent's answer: the session is live");
    (ctl, sid, created, pc)
}

/// Write the org's idle limit straight into its row (`None` removes it): the
/// route accepts a minute at the least, and a test should not wait one.
async fn store_idle_secs(app: &TestApp, seeded: &SeededTenant, secs: Option<i64>) {
    let tid = bson::oid::ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let update = match secs {
        Some(s) => bson::doc! { "$set": { "settings.rc_limits.idle_secs": s } },
        None => bson::doc! { "$unset": { "settings.rc_limits.idle_secs": "" } },
    };
    app.db
        .collection::<bson::Document>("tenants")
        .update_one(bson::doc! { "_id": tid }, update)
        .await
        .unwrap();
}

/// The `session_ended` audit row of a session, once it lands.
pub(crate) async fn ended_row(app: &TestApp, seeded: &SeededTenant, sid: &str) -> Option<Value> {
    let url = app.url(&format!(
        "/api/tenant/{}/session/{}/audit",
        seeded.tenant_id, sid
    ));
    for _ in 0..40 {
        let resp = app
            .client
            .get(&url)
            .bearer_auth(&seeded.admin.access_token)
            .send()
            .await
            .unwrap();
        if resp.status().is_success() {
            let body: Value = resp.json().await.unwrap();
            let row = body["items"].as_array().and_then(|items| {
                items
                    .iter()
                    .find(|i| i["event"]["kind"] == "session_ended")
                    .map(|i| i["event"].clone())
            });
            if row.is_some() {
                return row;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// The idle limit, end to end, kept by the real agent: the viewer is told the
/// limit (this agent advertises `idle-timeout`), the session lives until it,
/// and then the AGENT ends it as `idle_timeout` naming `limit: "idle"`, which
/// reaches the controller and the audit. The control is the same device and
/// controller with no idle limit: the session goes on well past it.
#[tokio::test]
async fn the_agent_ends_a_session_that_sits_idle() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr101p4b2idle").await;
    store_idle_secs(&app, &seeded, Some(2)).await;
    let cfg = enrol(&app, &seeded, "mach-fr101-idle").await;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let sig = spawn_agent_signaling(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg).await;

    let (mut ctl, sid, created, pc) =
        go_live(&app, &seeded.admin.access_token, &cfg.agent_id).await;
    let live_at = Instant::now();
    assert_eq!(
        created["idle_secs"], 2,
        "the viewer is told the limit: this agent keeps it ({created})"
    );
    let ended = next_of(&mut ctl, "rc:terminate", Duration::from_secs(10))
        .await
        .expect("the agent ends the idle session");
    let after = live_at.elapsed();
    assert_eq!(ended["session_id"], sid.as_str());
    assert_eq!(ended["reason"], "idle_timeout", "{ended}");
    assert_eq!(ended["limit"], "idle", "{ended}");
    assert!(
        after >= Duration::from_millis(1700),
        "ended {after:?} after going live: before its 2 s limit"
    );
    let ev = ended_row(&app, &seeded, &sid)
        .await
        .expect("a session_ended audit row");
    assert_eq!(ev["reason"], "idle_timeout", "{ev}");
    assert_eq!(ev["limit"], "idle", "{ev}");
    pc.close().await.unwrap();

    // The control: no idle limit, and the session outlives the old one.
    store_idle_secs(&app, &seeded, None).await;
    let (mut ctl2, _sid2, created2, pc2) =
        go_live(&app, &seeded.admin.access_token, &cfg.agent_id).await;
    assert!(created2["idle_secs"].is_null(), "{created2}");
    assert!(
        next_of(&mut ctl2, "rc:terminate", Duration::from_secs(4))
            .await
            .is_none(),
        "a session with no idle limit must not end"
    );
    pc2.close().await.unwrap();

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), sig).await;
}
