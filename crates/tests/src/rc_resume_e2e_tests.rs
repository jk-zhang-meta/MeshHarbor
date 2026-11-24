// SPDX-License-Identifier: AGPL-3.0-only
//! FR-130 — a live session outlives its device's control socket, end to end.
//!
//! Every other FR-130 test drives one half: `rc_resume_*_tests` play the
//! device over a bare socket against the real server, and the agent's
//! `session_table` tests play the server against the real table. Here both
//! halves are real: the agent library's signalling loop (`signaling::run`)
//! against a real server, a webrtc-rs peer as the browser, and a controller
//! socket that speaks the viewer's side of the hold.
//!
//! The device's socket is cut from the server's side (`cycle_agent_ws`, what a
//! renumber does), which is the transient exit a server restart takes on the
//! device: the device keeps the peer, redials, and claims the session back in
//! its hello. What must hold:
//!
//! - the viewer is told `rc:session.detached`, never `rc:terminate`, and its
//!   `rc:session.rejoin` is answered `rc:session.resumed`;
//! - the row is the same row: still open, `attach_seq` bumped once, nothing
//!   detached, and no second session was created;
//! - the device was asked for no new consent: the claim is its own;
//! - the rebuilt session's file child transports are revoked, the device
//!   acknowledges it (so the fail-closed deadline does not end the session),
//!   and the viewer hears it at its rejoin;
//! - a hangup after the resume still reaches the device and ends the row.

use std::time::Duration;

use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::agent_e2e_tests::{enrol, spawn_agent_and_wait_online};
use crate::fixtures::test_app::TestApp;
use crate::rc_resume_claim_tests::{
    attach_seq, audit, detached, end_reason, ended, kinds, one, open, row, scope_all, wait_row,
};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

async fn send(ws: &mut Ws, frame: Value) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

/// The next text frame on `ws`, within `within`.
async fn next_frame(ws: &mut Ws, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        let left = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    return Some(v);
                }
            }
            Ok(Some(Ok(_))) => {}
            _ => return None,
        }
    }
    None
}

fn tag(v: &Value) -> &str {
    v.get("t").and_then(Value::as_str).unwrap_or("")
}

/// One live session of the real agent library on `app`: the device, its
/// signalling task and stop switch, the viewer's socket, the session, the
/// `resume_secs` the viewer was told, and the browser's peer.
struct Live {
    agent: ObjectId,
    sig_task: tokio::task::JoinHandle<()>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    viewer: Ws,
    sid: ObjectId,
    sid_hex: String,
    resume_secs: Option<u64>,
    browser_pc: webrtc::peer_connection::RTCPeerConnection,
}

async fn live_session(app: &TestApp, slug: &str, machine_id: &str) -> Live {
    use webrtc::api::APIBuilder;
    use webrtc::api::media_engine::MediaEngine;
    use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
    use webrtc::peer_connection::configuration::RTCConfiguration;

    let seeded = app.seed_tenant(slug).await;
    // The real agent library, with the device's resume switch at its default
    // (on): nothing here sets its environment.
    let cfg = enrol(app, &seeded, machine_id, "device-a").await;
    let agent = ObjectId::parse_str(&cfg.agent_id).unwrap();
    let (sig_task, stop_tx) = spawn_agent_and_wait_online(app, &seeded, &cfg).await;

    // The browser: a peer with a control channel, and its offer.
    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let api = APIBuilder::new().with_media_engine(me).build();
    let browser_pc = api
        .new_peer_connection(RTCConfiguration::default())
        .await
        .unwrap();
    let _dc = browser_pc
        .create_data_channel("control", Some(RTCDataChannelInit::default()))
        .await
        .unwrap();
    let offer = browser_pc.create_offer(None).await.unwrap();
    browser_pc
        .set_local_description(offer.clone())
        .await
        .unwrap();

    // The viewer's socket, and the session up to its answer.
    let url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&seeded.admin.access_token)
    );
    let (mut viewer, _) = connect_async(&url).await.expect("the viewer's socket");
    send(
        &mut viewer,
        json!({ "t": "rc:session.request", "agent_id": cfg.agent_id, "permissions": "VIEW | INPUT" }),
    )
    .await;
    let mut sid_hex: Option<String> = None;
    let mut resume_secs = None;
    let mut answered = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && !answered {
        let Some(v) = next_frame(&mut viewer, Duration::from_millis(500)).await else {
            continue;
        };
        match tag(&v) {
            "rc:session.created" => {
                resume_secs = v["resume_secs"].as_u64();
                sid_hex = v["session_id"].as_str().map(str::to_owned);
            }
            "rc:ready" => {
                let sid = sid_hex.clone().expect("created before ready");
                send(
                    &mut viewer,
                    json!({ "t": "rc:sdp.offer", "session_id": sid, "sdp": offer.sdp }),
                )
                .await;
            }
            "rc:sdp.answer" => answered = true,
            _ => {}
        }
    }
    assert!(answered, "the device never answered the offer");
    let sid_hex = sid_hex.unwrap();
    let sid = ObjectId::parse_str(&sid_hex).unwrap();
    assert!(app.state.fleet().rc_hub.session_snapshot(sid).is_some());
    // The audit sink projects the row in batches: wait for it to read live.
    let before = wait_row(app, sid, "the session's row is live", open).await;
    assert_eq!(attach_seq(&before), 0, "{before:?}");
    Live {
        agent,
        sig_task,
        stop_tx,
        viewer,
        sid,
        sid_hex,
        resume_secs,
        browser_pc,
    }
}

async fn stop(live: Live) {
    let _ = live.browser_pc.close().await;
    let _ = live.stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), live.sig_task).await;
}

#[tokio::test]
async fn a_live_session_outlives_its_devices_control_socket() {
    // The server's window, and every device in its resume scope.
    let app = one(60).await;
    scope_all(&app).await;
    let mut live = live_session(&app, "fr130e2e", "mach-fr130-e2e").await;
    let hub = &app.state.fleet().rc_hub;
    let (agent, sid, sid_hex) = (live.agent, live.sid, live.sid_hex.clone());
    assert_eq!(
        hub.agent_resume_window(agent),
        Some(60),
        "the real agent says rc-resume by default, and is announced the window"
    );
    assert_eq!(
        live.resume_secs,
        Some(60),
        "the viewer is told it may hold this session"
    );
    let viewer = &mut live.viewer;

    // The cut: the server closes the device's control socket. The device
    // keeps the peer and redials at once.
    assert!(hub.cycle_agent_ws(agent));

    // The viewer: told the session is detached, never that it ended, and its
    // rejoin is answered once the device has claimed the session back.
    let mut told_detached = false;
    let mut resumed = false;
    let mut revoked_at_rejoin = false;
    let mut last_ask = tokio::time::Instant::now() - Duration::from_secs(1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline && !(resumed && revoked_at_rejoin) {
        if told_detached && !resumed && last_ask.elapsed() >= Duration::from_millis(400) {
            send(
                viewer,
                json!({ "t": "rc:session.rejoin", "session_id": sid_hex }),
            )
            .await;
            last_ask = tokio::time::Instant::now();
        }
        let Some(v) = next_frame(viewer, Duration::from_millis(200)).await else {
            continue;
        };
        match tag(&v) {
            "rc:session.detached" => {
                assert_eq!(v["session_id"].as_str(), Some(sid_hex.as_str()));
                assert!(v["resume_by"].as_u64().unwrap_or(0) > 0, "{v}");
                told_detached = true;
            }
            "rc:session.resumed" => {
                assert_eq!(v["session_id"].as_str(), Some(sid_hex.as_str()));
                resumed = true;
            }
            "rc:file.child.revoke" => {
                assert_eq!(v["session_id"].as_str(), Some(sid_hex.as_str()));
                assert_eq!(v["reason"].as_str(), Some("session_resumed"), "{v}");
                revoked_at_rejoin = true;
            }
            "rc:terminate" => panic!("the session ended at the cut: {v}"),
            "rc:session.created" => panic!("a second session was created: {v}"),
            _ => {}
        }
    }
    assert!(
        told_detached,
        "the viewer was never told rc:session.detached"
    );
    assert!(
        resumed,
        "the rejoin was never answered rc:session.resumed: the device did not claim the session back"
    );
    assert!(
        revoked_at_rejoin,
        "the viewer was not told the file child transports are gone"
    );

    // The row is the same row, resumed once; the device claimed it, and was
    // asked for nothing new.
    let after = wait_row(&app, sid, "the row is resumed once", |r| {
        open(r) && !detached(r) && attach_seq(r) == 1
    })
    .await;
    assert!(!ended(&after), "{after:?}");
    let trail = kinds(&audit(&app, sid).await);
    for kind in ["session_detached", "session_resumed"] {
        assert!(trail.iter().any(|k| k == kind), "{kind} in {trail:?}");
    }
    assert_eq!(
        trail.iter().filter(|k| *k == "consent_prompted").count(),
        1,
        "one consent, at the session's start: {trail:?}"
    );
    let sessions = app
        .db
        .collection::<bson::Document>("remote_sessions")
        .count_documents(bson::doc! { "agent_id": agent })
        .await
        .unwrap();
    assert_eq!(sessions, 1, "no new session row");

    // Past the deadline every revocation has: the real device acknowledged
    // the one a rebuilt session is born with, so the session is still there.
    tokio::time::sleep(Duration::from_millis(6_500)).await;
    assert!(
        hub.session_snapshot(sid).is_some(),
        "the session ended after its resume: the device did not acknowledge rc:file.child.revoke"
    );
    assert!(open(&row(&app, sid).await));

    // The session is the device's still: the viewer's hangup reaches it and
    // ends the row.
    send(
        viewer,
        json!({ "t": "rc:terminate", "session_id": sid_hex, "reason": "controller_hangup" }),
    )
    .await;
    let closed = wait_row(&app, sid, "the hangup ended the row", ended).await;
    assert_eq!(end_reason(&closed), Some("controller_hangup"), "{closed:?}");
    stop(live).await;
}

/// Off is today, with the same two real halves and the same cut: at the
/// server's default window (0) the device is announced none, so the viewer
/// is told no `resume_secs`, the cut ends the session `agent_disconnect`, and
/// nothing is claimed back. The test above differs from this one by the
/// window and the scope alone.
#[tokio::test]
async fn with_the_window_off_the_same_cut_ends_the_session_as_before() {
    let app = one(0).await;
    scope_all(&app).await;
    let mut live = live_session(&app, "fr130e2eoff", "mach-fr130-e2e-off").await;
    let hub = &app.state.fleet().rc_hub;
    let (agent, sid, sid_hex) = (live.agent, live.sid, live.sid_hex.clone());
    assert_eq!(hub.agent_resume_window(agent), None, "no window announced");
    assert_eq!(live.resume_secs, None, "the viewer is told nothing to hold");

    assert!(hub.cycle_agent_ws(agent));

    let mut reason = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline && reason.is_none() {
        let Some(v) = next_frame(&mut live.viewer, Duration::from_millis(200)).await else {
            continue;
        };
        match tag(&v) {
            "rc:terminate" if v["session_id"].as_str() == Some(sid_hex.as_str()) => {
                reason = v["reason"].as_str().map(str::to_owned);
            }
            "rc:session.detached" | "rc:session.resumed" => {
                panic!("nothing is held at window 0: {v}")
            }
            _ => {}
        }
    }
    assert_eq!(
        reason.as_deref(),
        Some("agent_disconnect"),
        "the cut ends the session, as it always has"
    );
    let closed = wait_row(&app, sid, "the row ended", ended).await;
    assert_eq!(end_reason(&closed), Some("agent_disconnect"), "{closed:?}");
    assert_eq!(attach_seq(&closed), 0, "nothing resumed it: {closed:?}");
    let trail = kinds(&audit(&app, sid).await);
    assert!(
        !trail
            .iter()
            .any(|k| k == "session_detached" || k == "session_resumed"),
        "{trail:?}"
    );
    stop(live).await;
}
