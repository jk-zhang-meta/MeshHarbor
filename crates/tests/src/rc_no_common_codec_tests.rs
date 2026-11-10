// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! #2251 — an offer the RTP video track cannot answer is refused by the REAL
//! agent library (`meshharbord::signaling::run`) before it builds a peer, as
//! `error` naming `limit: "no_common_codec"`, which the hub names to the
//! controller and in the `session_ended` audit row.
//!
//! The browser is a webrtc-rs peer whose media engine registers VP8 alone,
//! offering a recvonly video transceiver and asking for no DataChannel
//! transport: a Firefox without OpenH264 on the WebRTC track. This build's
//! agent encodes nothing, so `pick_best_codec` falls back to H.264 for it, as
//! it did for the field's agents (0.4.136: `create_answer` failed, the session
//! ended as a bare `error`, and the viewer asked again). The control is the
//! same agent and controller with H.264 in the offer: answered.

use crate::fixtures::test_app::TestApp;
use crate::rc_idle_limit_tests::{
    Ws, ended_row, enrol, next_of, spawn_agent_signaling, urlencode, wait_online,
};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::{MIME_TYPE_VP8, MediaEngine};
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::rtp_transceiver::rtp_codec::{
    RTCRtpCodecCapability, RTCRtpCodecParameters, RTPCodecType,
};
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;

/// A browser's offer with a recvonly video transceiver and the `control`
/// DataChannel the viewer always opens: VP8 alone, or webrtc-rs's default
/// codecs (H.264 among them). Its peer is closed once the offer is written:
/// nothing here needs it to connect.
async fn browser_offer(vp8_only: bool) -> String {
    let mut engine = MediaEngine::default();
    if vp8_only {
        engine
            .register_codec(
                RTCRtpCodecParameters {
                    capability: RTCRtpCodecCapability {
                        mime_type: MIME_TYPE_VP8.to_owned(),
                        clock_rate: 90000,
                        channels: 0,
                        sdp_fmtp_line: String::new(),
                        rtcp_feedback: vec![],
                    },
                    payload_type: 96,
                    ..Default::default()
                },
                RTPCodecType::Video,
            )
            .unwrap();
    } else {
        engine.register_default_codecs().unwrap();
    }
    let api = APIBuilder::new().with_media_engine(engine).build();
    let pc = api
        .new_peer_connection(RTCConfiguration::default())
        .await
        .unwrap();
    pc.add_transceiver_from_kind(
        RTPCodecType::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            send_encodings: vec![],
        }),
    )
    .await
    .unwrap();
    pc.create_data_channel("control", None).await.unwrap();
    let offer = pc.create_offer(None).await.unwrap();
    // A WebRTC peer frees nothing on drop: close it.
    pc.close().await.unwrap();
    assert_eq!(
        offer.sdp.contains("H264"),
        !vp8_only,
        "the fixture offer carries H.264 exactly when asked to"
    );
    offer.sdp
}

/// Ask for a session on the WebRTC track as a browser that decodes `caps`,
/// wait for the agent's grant, and send `sdp`. Returns the controller's socket
/// and the session id.
async fn ask(app: &TestApp, token: &str, agent_id: &str, caps: &[&str], sdp: &str) -> (Ws, String) {
    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ctl, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(500), ctl.next()).await;
    ctl.send(Message::Text(
        json!({
            "t": "rc:session.request",
            "agent_id": agent_id,
            "permissions": "VIEW | INPUT",
            "browser_caps": caps,
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
        json!({ "t": "rc:sdp.offer", "session_id": sid, "sdp": sdp })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    (ctl, sid)
}

/// Every frame up to and including the first `rc:terminate`, within `within`.
async fn frames_until_terminate(ws: &mut Ws, within: Duration) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + within;
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(250), ws.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let done = v["t"] == "rc:terminate";
        seen.push(v);
        if done {
            break;
        }
    }
    seen
}

/// The refusal, end to end: the agent ends the session before answering, as
/// `error` naming `no_common_codec`, and the controller and the audit are told
/// so. The control: the same agent answers an offer that carries H.264.
#[tokio::test]
async fn the_agent_refuses_an_offer_its_rtp_track_cannot_answer() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("i2251codec").await;
    let cfg = enrol(&app, &seeded, "mach-2251-codec").await;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let sig = spawn_agent_signaling(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg).await;
    let token = &seeded.admin.access_token;

    // A Firefox without OpenH264, on the WebRTC track.
    let sdp = browser_offer(true).await;
    let (mut ctl, sid) = ask(&app, token, &cfg.agent_id, &["vp8", "vp9", "av1"], &sdp).await;
    let frames = frames_until_terminate(&mut ctl, Duration::from_secs(10)).await;
    let ended = frames
        .iter()
        .find(|f| f["t"] == "rc:terminate")
        .unwrap_or_else(|| panic!("the agent must end the session: {frames:?}"));
    assert!(
        !frames.iter().any(|f| f["t"] == "rc:sdp.answer"),
        "refused before a peer is built, so never answered: {frames:?}"
    );
    assert_eq!(ended["session_id"], sid.as_str());
    assert_eq!(ended["reason"], "error", "{ended}");
    assert_eq!(ended["limit"], "no_common_codec", "{ended}");
    let ev = ended_row(&app, &seeded, &sid)
        .await
        .expect("a session_ended audit row");
    assert_eq!(ev["reason"], "error", "{ev}");
    assert_eq!(ev["limit"], "no_common_codec", "{ev}");

    // The control: H.264 in the offer, and the same agent answers it.
    let sdp = browser_offer(false).await;
    let (mut ctl2, _sid2) = ask(&app, token, &cfg.agent_id, &["h264", "vp8"], &sdp).await;
    next_of(&mut ctl2, "rc:sdp.answer", Duration::from_secs(10))
        .await
        .expect("an offer carrying H.264 is answered");

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), sig).await;
}
