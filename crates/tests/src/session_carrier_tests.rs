// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P9c — the carrier a session rides, on the server side: the agent
//! records it on `rc:session.stats` once the session reaches Active, and the
//! server stores it on `remote_sessions.carrier`. Through a real server, a
//! real agent WebSocket and a real MongoDB.
//!
//! * a sample carrying a carrier code writes it on the session row, beside
//!   `stats`;
//! * a later sample with NO carrier never overwrites it (absent means
//!   "nothing new to say", not "direct"), and one with a non-code value is
//!   dropped (the device is the only writer; a compromised one gets no free
//!   string field);
//! * a session whose agent never recorded a carrier has none — the growth
//!   freeze reads that as `unknown`, never direct (asserted in
//!   `growth_quality_tests`).
//!
//! The row is read straight from Mongo: the carrier has no HTTP route (it is
//! not controller-facing), exactly as `transfer_totals` has none.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use bson::{Document, doc, oid::ObjectId};
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

/// Enroll a device and connect its agent WS.
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
            "agent_version": "0.4.140",
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
        "t": "rc:agent.hello", "machine_name": machine_id, "os": "linux", "agent_version": "0.4.140",
        "displays": [{ "index": 0, "name": "x", "width_px": 800, "height_px": 600, "scale": 1.0, "primary": true }],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"], "has_input_permission": false,
            "supports_clipboard": false, "supports_file_transfer": false,
            "max_simultaneous_sessions": 16, "input": ["arbiter"],
        },
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    (agent_id, ws)
}

/// Ask for a session on a fresh controller connection; returns it live.
async fn ask(app: &TestApp, token: &str, agent_id: &str) -> (Ws, String) {
    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    ws.send(Message::Text(
        json!({ "t": "rc:session.request", "agent_id": agent_id, "permissions": "VIEW" })
            .to_string()
            .into(),
    ))
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
                return (ws, v["session_id"].as_str().unwrap().to_string());
            }
            Some("rc:error") => panic!("request refused: {v}"),
            _ => {}
        }
    }
    panic!("no rc:session.created within 5 s");
}

async fn wait_for_session_row(app: &TestApp, seeded: &SeededTenant, session_id: &str) {
    for _ in 0..50 {
        let resp = app
            .client
            .get(app.url(&format!(
                "/api/tenant/{}/session/{session_id}",
                seeded.tenant_id
            )))
            .bearer_auth(&seeded.admin.access_token)
            .send()
            .await
            .unwrap();
        if resp.status().is_success() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("session {session_id} never got its row");
}

/// One `rc:session.stats`, `carrier` present only when `Some`.
async fn report(ws: &mut Ws, session_id: &str, carrier: Option<&str>) {
    let mut msg = json!({
        "t": "rc:session.stats", "session_id": session_id,
        "bytes_sent": 1, "bytes_recv": 2, "fps": 30.0, "rtt_ms": 40.0,
        "keyframe_requests": 0, "input_events": 0,
    });
    if let Some(c) = carrier {
        msg["carrier"] = json!(c);
    }
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .unwrap();
}

/// The stored `carrier`, polled until it reaches `want` (or the timeout).
async fn await_carrier(app: &TestApp, session_id: &str, want: Option<&str>) -> Option<String> {
    let sid = ObjectId::parse_str(session_id).unwrap();
    let mut last = None;
    for _ in 0..50 {
        let row = app
            .db
            .collection::<Document>("remote_sessions")
            .find_one(doc! { "_id": sid })
            .await
            .unwrap();
        last = row.and_then(|d| d.get_str("carrier").ok().map(str::to_string));
        if last.as_deref() == want {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    last
}

#[tokio::test]
async fn the_server_records_the_carrier_a_sample_names_and_never_unlearns_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("carrier").await;
    let (agent_id, mut agent) = connect_agent(&app, &seeded, "carrier-host").await;
    let (_ctl, sid) = ask(&app, &seeded.admin.access_token, &agent_id).await;
    wait_for_session_row(&app, &seeded, &sid).await;

    // A sample naming a carrier code writes it on the row.
    report(&mut agent, &sid, Some("overlay_turn")).await;
    assert_eq!(
        await_carrier(&app, &sid, Some("overlay_turn"))
            .await
            .as_deref(),
        Some("overlay_turn"),
        "the carrier the agent recorded is stored"
    );

    // A later sample with NO carrier does not erase it — absent is "nothing
    // new", not "direct".
    report(&mut agent, &sid, None).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        await_carrier(&app, &sid, Some("overlay_turn"))
            .await
            .as_deref(),
        Some("overlay_turn"),
        "an absent carrier never unlearns the stored one"
    );

    // A non-code value is dropped at the socket gate: the row is untouched.
    report(&mut agent, &sid, Some("DROP TABLE sessions")).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        await_carrier(&app, &sid, Some("overlay_turn"))
            .await
            .as_deref(),
        Some("overlay_turn"),
        "a non-code carrier is dropped, not stored"
    );
}

#[tokio::test]
async fn a_session_whose_agent_recorded_no_carrier_has_none() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("nocarrier").await;
    let (agent_id, mut agent) = connect_agent(&app, &seeded, "nocarrier-host").await;
    let (_ctl, sid) = ask(&app, &seeded.admin.access_token, &agent_id).await;
    wait_for_session_row(&app, &seeded, &sid).await;

    // An older agent (or one before the observation landed) sends stats with
    // no carrier: the field is simply absent — the freeze reads that as
    // `unknown`, never direct.
    report(&mut agent, &sid, None).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let sid_oid = ObjectId::parse_str(&sid).unwrap();
    let row = app
        .db
        .collection::<Document>("remote_sessions")
        .find_one(doc! { "_id": sid_oid })
        .await
        .unwrap()
        .expect("the session row");
    assert!(row.get("carrier").is_none(), "no carrier recorded: {row:?}");
    // But the rest of the sample landed — the merge ran.
    let stats = row.get_document("stats").unwrap();
    assert_eq!(stats.get_i64("bytes_recv").unwrap(), 2);
}

// ────────────────────────────────────────────────────────────────────────────
// FR-102 P9d — a REAL agent, a REAL session, held well under the 30 s heartbeat
// tick, records its carrier. The tests above drive the server with hand-made
// `rc:session.stats` frames; this one drives the actual agent library through a
// real webrtc-rs peer, so the genuine carrier observation
// (`meshharbord::session_carrier::observe`) and the P9d early-send trigger fire.
//
// On master this FAILS: the only carrier send is the 30 s tick (which never
// fires in a ~15 s session) and `final_session_stats` (no transfers ⇒ `None`,
// and dropped once `ended_at` is set). With P9d the agent sends one
// `rc:session.stats` the moment the observation lands, so the carrier reaches
// the row while the server still holds the session live.
// ────────────────────────────────────────────────────────────────────────────

use meshharbord::{config::AgentConfig, encode::EncoderPreference, enrollment, signaling};
use std::net::IpAddr;
use std::sync::Arc;
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

/// Spawn the real agent signalling loop, as `rc_idle_limit_tests` does: the
/// consent broker auto-grants, no GUI-worker delegation (`Off` is the real
/// production value on every platform but a supervised Mac).
fn spawn_real_agent(
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

/// Enroll a device through the agent library (a real config + token).
async fn enrol_real(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> AgentConfig {
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

/// Wait for the agent's row to say online.
async fn wait_online(app: &TestApp, seeded: &SeededTenant, cfg: &AgentConfig) {
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

/// The overlay's address ranges, as the agent's carrier observation reads them
/// (`meshharbord::peer::addr_is_overlay_range`): the CGNAT `/10` the overlay
/// lives in, and the derived-v6 ULA `fd72:6f6f:6d6c::/48`.
fn is_overlay_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd72 && s[1] == 0x6f6f && s[2] == 0x6d6c
        }
    }
}

/// The stored `carrier`, or `None` if absent/null.
async fn stored_carrier(app: &TestApp, sid: &ObjectId) -> Option<String> {
    app.db
        .collection::<Document>("remote_sessions")
        .find_one(doc! { "_id": sid })
        .await
        .unwrap()
        .and_then(|d| d.get_str("carrier").ok().map(str::to_string))
}

#[tokio::test]
async fn a_short_real_session_records_its_carrier() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("carrier-short").await;
    let cfg = enrol_real(&app, &seeded, "carrier-short-host").await;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let sig = spawn_real_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg).await;

    // A real browser peer: register codecs + a data channel so the agent builds
    // a peer and answers, and collect its ICE candidates to cross-feed.
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    // No host candidate on an overlay address: on a box with an overlay
    // interface, a pair on `100.64.0.0/10` (or the derived-v6 ULA) reads as an
    // overlay carrier — `unknown` here, where no overlay runtime answers — not
    // `direct`. CI's runner has no overlay; the filter makes a dev box read the
    // same. (The agent keeps its own overlay addresses out by interface name.)
    let mut setting = SettingEngine::default();
    setting.set_ip_filter(Box::new(|ip| !is_overlay_range(ip)));
    let api = APIBuilder::new()
        .with_media_engine(me)
        .with_setting_engine(setting)
        .build();
    let pc = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    let _dc = pc
        .create_data_channel("control", Some(RTCDataChannelInit::default()))
        .await
        .unwrap();
    let (cand_tx, mut cand_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let cand_tx = cand_tx.clone();
        Box::pin(async move {
            if let Some(c) = c
                && let Ok(init) = c.to_json()
                && let Ok(val) = serde_json::to_value(init)
            {
                let _ = cand_tx.send(val);
            }
        })
    }));
    let offer = pc.create_offer(None).await.unwrap();
    pc.set_local_description(offer.clone()).await.unwrap();

    let url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&seeded.admin.access_token)
    );
    let (mut ctl, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(300), ctl.next()).await;
    ctl.send(Message::Text(
        json!({ "t": "rc:session.request", "agent_id": cfg.agent_id, "permissions": "VIEW" })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();

    // One loop that handshakes, cross-feeds ICE BOTH ways through the server,
    // and polls the row for the carrier. It ends the moment the carrier lands
    // or at the deadline — kept comfortably under the agent's first 30 s
    // heartbeat tick (which starts at the agent's WS connect, a few seconds
    // before this loop), so the session is always short and master is red
    // because no tick can carry the carrier within the window.
    let mut sid: Option<ObjectId> = None;
    let mut sid_hex = String::new();
    let mut answered = false;
    let mut pending_agent_ice: Vec<Value> = Vec::new();
    let mut carrier: Option<String> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && carrier.is_none() {
        if let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(200), ctl.next()).await
            && let Ok(v) = serde_json::from_str::<Value>(&text)
        {
            match v.get("t").and_then(|t| t.as_str()) {
                Some("rc:session.created") => {
                    sid_hex = v["session_id"].as_str().unwrap().to_string();
                    sid = Some(ObjectId::parse_str(&sid_hex).unwrap());
                }
                Some("rc:ready") => {
                    ctl.send(Message::Text(
                        json!({ "t": "rc:sdp.offer", "session_id": sid_hex, "sdp": offer.sdp })
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                }
                Some("rc:sdp.answer") => {
                    let answer =
                        RTCSessionDescription::answer(v["sdp"].as_str().unwrap().to_string())
                            .unwrap();
                    pc.set_remote_description(answer).await.unwrap();
                    answered = true;
                    for c in pending_agent_ice.drain(..) {
                        if let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(c) {
                            let _ = pc.add_ice_candidate(init).await;
                        }
                    }
                }
                Some("rc:ice") => {
                    let cand = v["candidate"].clone();
                    if answered {
                        if let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(cand) {
                            let _ = pc.add_ice_candidate(init).await;
                        }
                    } else {
                        pending_agent_ice.push(cand);
                    }
                }
                _ => {}
            }
        }
        // Forward every browser candidate gathered so far to the agent.
        if !sid_hex.is_empty() {
            while let Ok(cand) = cand_rx.try_recv() {
                let _ = ctl
                    .send(Message::Text(
                        json!({ "t": "rc:ice", "session_id": sid_hex, "candidate": cand })
                            .to_string()
                            .into(),
                    ))
                    .await;
            }
        }
        if let Some(sid) = sid.as_ref() {
            carrier = stored_carrier(&app, sid).await;
        }
    }

    // Tear the short session down BEFORE the first heartbeat tick could fire.
    pc.close().await.ok();
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), sig).await;

    assert_eq!(
        carrier.as_deref(),
        Some("direct"),
        "a session held well under 30 s records its carrier (FR-102 P9d); \
         a loopback host↔host pair is `direct`"
    );
}
