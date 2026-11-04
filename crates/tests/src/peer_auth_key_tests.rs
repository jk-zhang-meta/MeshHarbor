// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-100 P1a — a device's identity key, as the fleet stores it from the hello
//! and as the device list shows it.
//!
//! The key is a HINT for a browser's first pin (P2), never an authority, so
//! what matters here is that the row and the API name exactly the key the
//! device last sent, in its one shape:
//!
//! - written from EVERY hello, and cleared by a hello without one (a rollback
//!   to a build with no key must not leave browsers expecting its signature);
//! - a malformed key is stored as none, never as sent;
//! - the API shows the key with its fingerprint, both or neither.
//!
//! And one test runs the REAL agent: its hello carries a well-formed key that
//! it keeps beside its config, in one file per enrollment.
//!
//! P1b — and the real agent signs the answer an offer asked for (a nonce),
//! with the key on its row, over that session's transcript, while an offer
//! that did not ask is answered exactly as before.
//!
//! P1c — and the real agent judges the browser behind every in-org offer
//! (`absent` · `unknown` · `verified` · `mismatch`), remembering each browser
//! key beside its device key, while the hub records the verdict on the
//! session's audit row and refuses nothing.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bson::{Document, doc, oid::ObjectId};
use futures::SinkExt;
use meshharbor_remote_control::signaling::{peer_auth_fingerprint, peer_auth_key_is_well_formed};
use meshharbord::{config::AgentConfig, encode::EncoderPreference, enrollment, signaling};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::fixtures::{seed::SeededTenant, test_app::TestApp};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The P-256 generator G (FIPS 186-4 D.1.2.3) as a device key would carry a
/// point, built from its coordinates rather than written as a base64 literal
/// (a secret scanner cannot tell a public curve constant from a key).
fn p256_g() -> String {
    const GX: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    const GY: [u8; 32] = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];
    let mut point = vec![0x04];
    point.extend_from_slice(&GX);
    point.extend_from_slice(&GY);
    STANDARD.encode(point)
}
/// G's fingerprint, computed outside this code (coreutils `sha256sum`).
const P256_G_FINGERPRINT: &str = "698b ea63 dc44 a344 663f";

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

async fn enroll_token(app: &TestApp, seeded: &SeededTenant) -> String {
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
    et["enrollment_token"].as_str().unwrap().to_string()
}

/// Enroll a device over the API; `(agent_id, agent_token)`.
async fn enroll(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> (String, String) {
    let ej: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": enroll_token(app, seeded).await,
            "machine_id": machine_id,
            "machine_name": machine_id,
            "os": "linux",
            "agent_version": "0.4.145",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        ej["agent_id"].as_str().expect("agent_id").to_string(),
        ej["agent_token"].as_str().expect("agent_token").to_string(),
    )
}

/// Connect as the device and say hello, with `peer_auth_key` when given and
/// without the field otherwise (an older agent, or one that kept no key).
async fn hello(app: &TestApp, token: &str, peer_auth_key: Option<&str>) -> Ws {
    let url = format!("ws://{}/ws?token={}&role=agent", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&url).await.expect("agent ws connect");
    let mut hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "device-key-host",
        "os": "linux",
        "agent_version": "0.4.145",
        "displays": [],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"], "has_input_permission": false,
            "supports_clipboard": false, "supports_file_transfer": false,
            "max_simultaneous_sessions": 1, "rpc": [],
        }
    });
    if let Some(key) = peer_auth_key {
        hello["peer_auth_key"] = json!(key);
    }
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

/// The key on the device's row, `None` for an empty one or none at all.
async fn stored_key(app: &TestApp, agent_id: &str) -> Option<String> {
    let id = ObjectId::parse_str(agent_id).unwrap();
    let row: Document = app
        .db
        .collection::<Document>("agents")
        .find_one(doc! { "_id": id })
        .await
        .unwrap()
        .expect("the agent row");
    row.get_str("peer_auth_key")
        .ok()
        .filter(|k| !k.is_empty())
        .map(str::to_string)
}

/// Wait until the row holds `want`, failing with what it held instead.
async fn wait_for_key(app: &TestApp, agent_id: &str, want: Option<&str>) {
    let mut last = None;
    for _ in 0..100 {
        last = stored_key(app, agent_id).await;
        if last.as_deref() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the row's device key stayed {last:?}, expected {want:?}");
}

/// `(peer_auth_key, peer_auth_fingerprint)` as the device API shows them.
async fn shown(app: &TestApp, seeded: &SeededTenant, agent_id: &str) -> (Value, Value) {
    let row: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent/{agent_id}", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        row["peer_auth_key"].clone(),
        row["peer_auth_fingerprint"].clone(),
    )
}

#[tokio::test]
async fn every_hello_writes_the_device_key_and_the_api_shows_it_with_its_fingerprint() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("devicekey").await;
    let (agent_id, token) = enroll(&app, &seeded, "device-key-host").await;
    assert_eq!(
        stored_key(&app, &agent_id).await,
        None,
        "enrollment knows no key"
    );
    assert_eq!(
        shown(&app, &seeded, &agent_id).await,
        (Value::Null, Value::Null),
        "and the API shows none"
    );

    // A key: stored as sent, shown with the fingerprint every surface uses.
    let g = p256_g();
    let mut ws = hello(&app, &token, Some(&g)).await;
    wait_for_key(&app, &agent_id, Some(&g)).await;
    assert_eq!(
        shown(&app, &seeded, &agent_id).await,
        (json!(g), json!(P256_G_FINGERPRINT))
    );
    ws.close(None).await.ok();

    // A compressed point is another shape: stored as none, neither as sent
    // nor by keeping the key before it, and the API shows neither half.
    let point = STANDARD.decode(&g).unwrap();
    let mut compressed = vec![0x02];
    compressed.extend_from_slice(&point[1..33]);
    let mut ws = hello(&app, &token, Some(&STANDARD.encode(&compressed))).await;
    wait_for_key(&app, &agent_id, None).await;
    assert_eq!(
        shown(&app, &seeded, &agent_id).await,
        (Value::Null, Value::Null)
    );
    ws.close(None).await.ok();

    // A key again, then a hello without one, as from a build rolled back to
    // before the key: the stored key goes with it.
    let mut ws = hello(&app, &token, Some(&g)).await;
    wait_for_key(&app, &agent_id, Some(&g)).await;
    ws.close(None).await.ok();
    let mut ws = hello(&app, &token, None).await;
    wait_for_key(&app, &agent_id, None).await;
    ws.close(None).await.ok();
}

/// The real agent, with a config path in a directory of its own: its hello
/// carries a well-formed key, the key file sits beside the config, and the
/// API's fingerprint is that key's.
#[tokio::test]
async fn the_real_agent_says_hello_with_a_key_it_keeps_beside_its_config() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("devicekey-real").await;
    let cfg: AgentConfig = enrollment::enroll(enrollment::EnrollInputs {
        server_url: &app.base_url,
        enrollment_token: &enroll_token(&app, &seeded).await,
        machine_id: "device-key-real",
        machine_name: "Device key host",
        install: None,
    })
    .await
    .expect("agent enrollment");
    let agent_id = cfg.agent_id.clone();
    let tenant_id = cfg.tenant_id.clone();
    let dir = tempfile::tempdir().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let agent = spawn_keyed_agent(cfg, dir.path().join("config.toml"), stop_rx);

    let key = wait_for_any_key(&app, &agent_id).await;
    assert!(peer_auth_key_is_well_formed(&key), "{key}");
    let file = dir
        .path()
        .join(meshharbord::peer_auth::DIR_NAME)
        .join(format!("{tenant_id}.json"));
    assert!(
        file.exists(),
        "the key is kept beside the config: {}",
        file.display()
    );
    assert_eq!(
        shown(&app, &seeded, &agent_id).await,
        (json!(key), json!(peer_auth_fingerprint(&key).unwrap()))
    );

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}

/// The real agent's signalling loop, with a config path in a directory of its
/// own: the one thing these tests vary, because that is where its key goes.
fn spawn_keyed_agent(
    cfg: AgentConfig,
    config_path: std::path::PathBuf,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (view_tx, _view_rx) = tokio::sync::watch::channel(Default::default());
        let broker = meshharbord::consent::ConsentBroker::new(
            meshharbord::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("roomler-device-key-consent-{}", cfg.agent_id)),
        )
        .expect("consent broker init");
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
                config_path,
                std::sync::Arc::new(tokio::sync::Mutex::new(())),
                false,
                false,
            ),
            meshharbord::rc_sessions::RcSessionRegistry::new(),
        )
        .await;
    })
}

/// The key the row holds once the agent's hello lands.
async fn wait_for_any_key(app: &TestApp, agent_id: &str) -> String {
    for _ in 0..100 {
        if let Some(key) = stored_key(app, agent_id).await {
            return key;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the real agent's hello carried no device key");
}

// ─── P1b — the device signs its answer ──────────────────────────────────

/// A browser's nonce: bytes 0 to 15, base64url without padding. Built, not
/// written as a literal: a secret scanner cannot tell a counting sequence
/// from a key.
fn nonce() -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        (0u8..16).collect::<Vec<u8>>(),
    )
}

/// Ask the real agent for a session as the admin and, once it is ready, send
/// a real webrtc-rs offer, with `nonce` as its `peer_auth` when given. Returns
/// the controller's socket, the session id, the offer's SDP, the answer frame
/// and the browser's peer connection, which the caller closes (dropping one
/// frees none of its sockets).
async fn offer_and_answer(
    app: &TestApp,
    token: &str,
    agent_id: &str,
    nonce: Option<&str>,
) -> (
    Ws,
    String,
    String,
    Value,
    std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
) {
    let nonce = nonce.map(str::to_string);
    offer_and_answer_with(app, token, agent_id, move |_, _| {
        nonce.map(|n| json!({ "nonce": n }))
    })
    .await
}

/// [`offer_and_answer`], with the offer's `peer_auth` built by `ask` once the
/// session id and the offer's SDP exist: FR-100 P2b's signed offer covers both.
async fn offer_and_answer_with(
    app: &TestApp,
    token: &str,
    agent_id: &str,
    ask: impl FnOnce(&str, &str) -> Option<Value>,
) -> (
    Ws,
    String,
    String,
    Value,
    std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
) {
    use crate::rc_idle_limit_tests::next_of;
    use webrtc::api::APIBuilder;
    use webrtc::api::media_engine::MediaEngine;
    use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
    use webrtc::peer_connection::configuration::RTCConfiguration;

    let mut me = MediaEngine::default();
    me.register_default_codecs().unwrap();
    let api = APIBuilder::new().with_media_engine(me).build();
    let pc = std::sync::Arc::new(
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
    let mut frame = json!({ "t": "rc:sdp.offer", "session_id": sid, "sdp": offer.sdp });
    if let Some(peer_auth) = ask(&sid, &offer.sdp) {
        frame["peer_auth"] = peer_auth;
    }
    ctl.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
    let answer = next_of(&mut ctl, "rc:sdp.answer", Duration::from_secs(10))
        .await
        .expect("the agent's answer");
    (ctl, sid, offer.sdp, answer, pc)
}

/// An offer that asks gets an answer signed with the key on the device's
/// row, over THIS session's transcript (its id, the device, the admin who
/// asked, both DTLS fingerprints, the nonce): what a browser that pinned the
/// key will check. An offer that does not ask, the shape every browser sends
/// before P2, gets no signature and is answered exactly as before.
#[tokio::test]
async fn the_real_agent_signs_the_answer_an_offer_asked_for() {
    use meshharbor_remote_control::signaling::{
        peer_auth_transcript, peer_auth_verify, sdp_dtls_fingerprint,
    };
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("peerauth-answer").await;
    let cfg = crate::rc_idle_limit_tests::enrol(&app, &seeded, "peer-auth-answer").await;
    let agent_id = cfg.agent_id.clone();
    let dir = tempfile::tempdir().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let agent = spawn_keyed_agent(cfg.clone(), dir.path().join("config.toml"), stop_rx);
    crate::rc_idle_limit_tests::wait_online(&app, &seeded, &cfg).await;
    let key = wait_for_any_key(&app, &agent_id).await;
    let token = &seeded.admin.access_token;
    let nonce = nonce();

    let (mut ctl, sid, offer_sdp, answer, pc) =
        offer_and_answer(&app, token, &agent_id, Some(nonce.as_str())).await;
    let signed = &answer["peer_auth"];
    assert_eq!(
        signed["key"],
        json!(key),
        "signed by the key on the row: {answer}"
    );
    let transcript = peer_auth_transcript(
        "answer",
        &sid,
        &agent_id,
        &seeded.admin.id,
        &sdp_dtls_fingerprint(&offer_sdp).unwrap(),
        &sdp_dtls_fingerprint(answer["sdp"].as_str().unwrap()).unwrap(),
        &nonce,
    )
    .unwrap();
    assert!(
        peer_auth_verify(&key, &transcript, signed["sig"].as_str().unwrap()),
        "the signature verifies over this session's transcript: {answer}"
    );
    // Over this session's only: the member, who did not ask, is not who it
    // was signed for.
    let theirs = peer_auth_transcript(
        "answer",
        &sid,
        &agent_id,
        &seeded.member.id,
        &sdp_dtls_fingerprint(&offer_sdp).unwrap(),
        &sdp_dtls_fingerprint(answer["sdp"].as_str().unwrap()).unwrap(),
        &nonce,
    )
    .unwrap();
    assert!(!peer_auth_verify(
        &key,
        &theirs,
        signed["sig"].as_str().unwrap()
    ));
    ctl.send(Message::Text(
        json!({ "t": "rc:terminate", "session_id": sid, "reason": "controller_hangup" })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _ = pc.close().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (_ctl, _sid, _offer, answer, pc) = offer_and_answer(&app, token, &agent_id, None).await;
    assert!(
        answer.get("peer_auth").is_none(),
        "an offer that did not ask is answered unsigned: {answer}"
    );
    let _ = pc.close().await;

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}

// ─── P1c — the device checks the browser ────────────────────────────────

/// A browser the test holds: a P-256 key made fresh (never a literal), its
/// public half as an offer carries it.
struct TestBrowser {
    pair: ring::signature::EcdsaKeyPair,
    key: String,
}

fn test_browser() -> TestBrowser {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let key = STANDARD.encode(pair.public_key().as_ref());
    TestBrowser { pair, key }
}

/// `browser`'s `peer_auth` for an offer: signed over the transcript with role
/// `offer` and an EMPTY answer fingerprint, for `signed_sid`, which a test may
/// set to ANOTHER session's id.
fn signed_ask(
    browser: &TestBrowser,
    signed_sid: &str,
    agent_id: &str,
    user_id: &str,
    offer_sdp: &str,
    nonce: &str,
) -> Value {
    use meshharbor_remote_control::signaling::{peer_auth_transcript, sdp_dtls_fingerprint};
    let transcript = peer_auth_transcript(
        "offer",
        signed_sid,
        agent_id,
        user_id,
        &sdp_dtls_fingerprint(offer_sdp).unwrap(),
        "",
        nonce,
    )
    .unwrap();
    let sig = browser
        .pair
        .sign(&ring::rand::SystemRandom::new(), &transcript)
        .unwrap();
    json!({
        "nonce": nonce,
        "key": browser.key,
        "sig": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_ref()),
    })
}

/// The verdict on session `sid`'s `session_started` audit row, once the hub's
/// sink has flushed it (every 200 ms). `None` = recorded without one.
async fn recorded_verdict(app: &TestApp, sid: &str) -> Option<String> {
    use meshharbor_remote_control::models::RemoteAuditEvent;
    let sid = ObjectId::parse_str(sid).unwrap();
    for _ in 0..50 {
        if let Some(row) = app
            .db
            .collection::<Document>(RemoteAuditEvent::COLLECTION)
            .find_one(doc! { "session_id": sid, "event.kind": "session_started" })
            .await
            .unwrap()
        {
            return row
                .get_document("event")
                .unwrap()
                .get_str("peer_auth")
                .ok()
                .map(str::to_string);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no session_started row for {sid}");
}

/// End one session as a viewer does, and close its peer (dropping one frees
/// none of its sockets).
async fn hang_up(
    mut ctl: Ws,
    sid: &str,
    pc: std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
) {
    ctl.send(Message::Text(
        json!({ "t": "rc:terminate", "session_id": sid, "reason": "controller_hangup" })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let _ = pc.close().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// The real agent judges the browser behind every in-org offer, and the hub
/// records the verdict on the session's audit row, which is what AC4's fleet
/// week counts. An offer nobody signed is `absent`. A browser's first signed
/// offer is `unknown`, and its key is remembered beside the device key; its
/// next offer is `verified`. A signature made for another session is a
/// `mismatch`, and under `audit` the session is answered all the same.
#[tokio::test]
async fn the_device_judges_the_browser_and_the_hub_records_the_verdict() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("peerauth-verdict").await;
    let cfg = crate::rc_idle_limit_tests::enrol(&app, &seeded, "peer-auth-verdict").await;
    let agent_id = cfg.agent_id.clone();
    let pins =
        std::path::Path::new("peer-auth").join(format!("{}.controllers.json", cfg.tenant_id));
    let dir = tempfile::tempdir().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let agent = spawn_keyed_agent(cfg.clone(), dir.path().join("config.toml"), stop_rx);
    crate::rc_idle_limit_tests::wait_online(&app, &seeded, &cfg).await;
    let _ = wait_for_any_key(&app, &agent_id).await;
    let token = &seeded.admin.access_token;
    let admin = seeded.admin.id.clone();
    let chrome = test_browser();

    let (ctl, sid, _, answer, pc) =
        offer_and_answer(&app, token, &agent_id, Some(nonce().as_str())).await;
    assert_eq!(
        recorded_verdict(&app, &sid).await.as_deref(),
        Some("absent"),
        "nobody signed the offer: {answer}"
    );
    assert!(
        answer.get("peer_auth_verdict").is_none(),
        "the hub records the verdict; it never relays it: {answer}"
    );
    hang_up(ctl, &sid, pc).await;

    let (ctl, sid, _, _, pc) = offer_and_answer_with(&app, token, &agent_id, |sid, sdp| {
        Some(signed_ask(&chrome, sid, &agent_id, &admin, sdp, &nonce()))
    })
    .await;
    assert_eq!(
        recorded_verdict(&app, &sid).await.as_deref(),
        Some("unknown"),
        "a browser the device has not met"
    );
    assert!(
        dir.path().join(&pins).exists(),
        "its key is remembered beside the device key"
    );
    hang_up(ctl, &sid, pc).await;

    let (ctl, sid, _, _, pc) = offer_and_answer_with(&app, token, &agent_id, |sid, sdp| {
        Some(signed_ask(&chrome, sid, &agent_id, &admin, sdp, &nonce()))
    })
    .await;
    assert_eq!(
        recorded_verdict(&app, &sid).await.as_deref(),
        Some("verified"),
        "the same browser, met before"
    );
    hang_up(ctl, &sid, pc).await;

    let elsewhere = ObjectId::new().to_hex();
    let (ctl, sid, _, answer, pc) = offer_and_answer_with(&app, token, &agent_id, |_, sdp| {
        Some(signed_ask(
            &chrome,
            &elsewhere,
            &agent_id,
            &admin,
            sdp,
            &nonce(),
        ))
    })
    .await;
    assert!(answer["sdp"].is_string(), "audit refuses nothing: {answer}");
    assert_eq!(
        recorded_verdict(&app, &sid).await.as_deref(),
        Some("mismatch"),
        "a signature made for another session"
    );
    hang_up(ctl, &sid, pc).await;

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}
