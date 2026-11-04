// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-52 P3c — the loopback proof: an OUTSIDER logs into a device through the
//! server, and the device verifies.
//!
//! Everything real except the browser: a real API server, the REAL agent
//! signalling loop (`meshharbord`, with `external-access`) reading a real config
//! file for gate 3 and the password record, an org-less user on a real user
//! socket, and opaque-ke standing in for `@serenity-kit/opaque` — which is
//! opaque-ke compiled to WASM, and was proven to log into this agent's records
//! in P3a with the real library. The spec's bar for P3 is "proven on loopback
//! against the real agent first", as FR-19's bind handshake was.
//!
//! The server in the middle is exactly what these tests are about: it relays
//! three messages it cannot use, applies the two gates it owns, and — the
//! property the device-side tests cannot see — routes each answer back to the
//! right socket.

use std::time::{Duration, Instant};

use base64::Engine as _;
use futures::{SinkExt, StreamExt};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand_opaque::rngs::OsRng;
use meshharbord::external_access::{Suite, set_password};
use meshharbord::{config::AgentConfig, encode::EncoderPreference, enrollment, signaling};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Built, never written: a secret scanner cannot tell a KDF input in a test
/// from a leaked credential.
fn pw(tag: &str) -> String {
    format!("fr52-not-a-credential-{tag}")
}

fn b64url() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

async fn put(app: &TestApp, path: &str, token: &str, body: Value) -> u16 {
    app.auth_put(path, token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn post_json(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let resp = app.auth_post(path, token).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn enrol(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> AgentConfig {
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
    .expect("enrollment")
}

/// The real agent loop, mirroring `main.rs`'s wiring — with a REAL config path.
///
/// ⚠️ The shared harnesses hand the agent `unused-in-tests.toml`. That is fine
/// for gates read from the in-memory config, and wrong here: the device reads
/// gate 3 and the password record from its config FILE on every knock, so that
/// a revocation is live. A fake path would make every login `unavailable`.
fn spawn_agent(
    cfg: AgentConfig,
    config_path: std::path::PathBuf,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (view_tx, _view_rx) = tokio::sync::watch::channel(Default::default());
        let broker = meshharbord::consent::ConsentBroker::new(
            meshharbord::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("meshharbor-extauth-consent-{}", cfg.agent_id)),
        )
        .expect("consent broker init");
        let (exec_enabled, remote_config_enabled) = (cfg.exec_enabled, cfg.remote_config_enabled);
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
                exec_enabled,
                remote_config_enabled,
            ),
            meshharbord::rc_sessions::RcSessionRegistry::new(),
        )
        .await;
    })
}

/// A device ready for external access: enrolled, a password set on it, gate 3
/// open in its config FILE, gate 1 and gate 2 open on the server, and a connect
/// code minted. Returns the code in its dictation form.
struct Device {
    code: String,
    agent_id: String,
    _dir: tempfile::TempDir,
    stop: tokio::sync::watch::Sender<bool>,
    _task: tokio::task::JoinHandle<()>,
}

async fn device(app: &TestApp, seeded: &SeededTenant, machine: &str, password: &str) -> Device {
    device_with(app, seeded, machine, password, Terms::default()).await
}

/// P4 — the device's own terms for an external session, in its config file.
#[derive(Default, Clone, Copy)]
struct Terms {
    /// `external_consent_mode`. The tests that open a session say `auto`: the
    /// test agent has no prompt surface, and `prompt` would wait out the
    /// attended window. The ordering of consent and offer is proven where it
    /// can be made deterministic — the device's and the Hub's unit tests.
    consent: Option<&'static str>,
    /// `external_max_permissions`.
    ceiling: Option<&'static str>,
}

async fn device_with(
    app: &TestApp,
    seeded: &SeededTenant,
    machine: &str,
    password: &str,
    terms: Terms,
) -> Device {
    let mut cfg = enrol(app, seeded, machine).await;
    let (cred, _) = set_password(None, password).expect("registration");
    cfg.external_access_enabled = true;
    cfg.external_access_setup = Some(cred.setup);
    cfg.external_access_verifier = Some(cred.verifier);
    cfg.external_consent_mode = terms.consent.map(str::to_string);
    cfg.external_max_permissions = terms.ceiling.map(str::to_string);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    meshharbord::config::save(&path, &cfg).unwrap();
    let agent_id = cfg.agent_id.clone();

    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg, path, stop_rx);

    let owner = &seeded.admin.access_token;
    assert_eq!(
        put(
            app,
            &url(seeded, "/external-access"),
            owner,
            json!({ "enabled": true })
        )
        .await,
        200,
        "gate 1"
    );
    // Gate 2 can only be granted once the device's hello has recorded that it
    // advertises `external-access` — which the REAL agent does on connect.
    let policy = url(seeded, &format!("/agent/{agent_id}/external-access-policy"));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if put(app, &policy, owner, json!({ "approved": true })).await == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "gate 2 could not be granted: the agent never reported `external-access`"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (s, body) = post_json(
        app,
        &url(seeded, &format!("/agent/{agent_id}/connect-code")),
        owner,
    )
    .await;
    assert_eq!(s, 200, "{body}");
    Device {
        code: body["connect_code"].as_str().unwrap().to_string(),
        agent_id,
        _dir: dir,
        stop,
        _task: task,
    }
}

/// An org-less account on a real user socket — the outsider.
async fn outsider(app: &TestApp, tag: &str) -> (String, Ws) {
    let user = app
        .register_user(
            &format!("{tag}@outside.test"),
            tag,
            "An Outsider",
            &pw(&format!("{tag}-account")),
            None,
            None,
        )
        .await;
    let ws_url = format!("ws://{}/ws?token={}", app.addr, user.access_token);
    let (mut ws, _) = connect_async(&ws_url).await.expect("user socket");
    // Drain whatever the server greets a socket with.
    let _ = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;
    (user.id, ws)
}

async fn send(ws: &mut Ws, frame: Value) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

/// The next frame whose tag is one of `tags`, skipping unrelated traffic.
async fn next_of(ws: &mut Ws, tags: &[&str]) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let msg = tokio::time::timeout(left, ws.next())
            .await
            .unwrap_or_else(|_| panic!("no {tags:?} within 15 s"))
            .expect("socket open")
            .expect("frame");
        if let Message::Text(t) = msg
            && let Ok(v) = serde_json::from_str::<Value>(&t)
            && tags.contains(&v["t"].as_str().unwrap_or(""))
        {
            return v;
        }
    }
}

fn client_ke1(password: &str) -> (ClientLogin<Suite>, String) {
    let s = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
    (s.state, b64url().encode(s.message.serialize()))
}

/// Open KE2. `None` = the client refused it — what a wrong password looks like.
fn client_ke3(state: ClientLogin<Suite>, password: &str, ke2: &str) -> Option<String> {
    let ke2 = b64url().decode(ke2).ok()?;
    let done = state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            CredentialResponse::<Suite>::deserialize(&ke2).ok()?,
            ClientLoginFinishParameters::default(),
        )
        .ok()?;
    Some(b64url().encode(done.message.serialize()))
}

/// THE loopback proof: KE1 → the device, KE2 → the browser, KE3 → the device,
/// VERIFIED → the browser — and a `login` row in the org's audit log.
#[tokio::test]
async fn an_outsider_logs_in_through_the_server_and_the_device_verifies() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-ok").await;
    let dev = device(&app, &seeded, "mach-extauth-ok", &pw("device")).await;
    let (_outsider_id, mut ws) = outsider(&app, "extok").await;

    let (state, ke1) = client_ke1(&pw("device"));
    send(
        &mut ws,
        json!({"t": "rc:extauth.start", "connect_code": dev.code, "ke1": ke1}),
    )
    .await;
    let challenge = next_of(&mut ws, &["rc:extauth.challenge", "rc:extauth.result"]).await;
    assert_eq!(
        challenge["t"], "rc:extauth.challenge",
        "the device answered KE1: {challenge}"
    );
    let attempt_id = challenge["attempt_id"].as_str().unwrap().to_string();

    let ke3 = client_ke3(state, &pw("device"), challenge["ke2"].as_str().unwrap())
        .expect("the right password opens the device's KE2");
    send(
        &mut ws,
        json!({"t": "rc:extauth.finish", "connect_code": dev.code, "attempt_id": attempt_id, "ke3": ke3}),
    )
    .await;
    let result = next_of(&mut ws, &["rc:extauth.result"]).await;
    assert_eq!(result["attempt_id"], json!(attempt_id));
    assert!(
        result.get("refused").is_none(),
        "the device must have VERIFIED the login: {result}"
    );

    // The org sees it. Written after the reply, so allow it a moment.
    let audit = url(&seeded, "/external-rc-audit");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let body: Value = app
            .auth_get(&audit, &seeded.admin.access_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let row = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["action"] == "login" && i["attempt_id"] == json!(attempt_id))
            .cloned();
        if let Some(row) = row {
            assert!(
                row.get("login_refused").is_none(),
                "a verified login: {row}"
            );
            break;
        }
        assert!(Instant::now() < deadline, "no `login` audit row: {body}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = dev.stop.send(true);
}

/// A wrong password is decided in the BROWSER — and still costs the device a
/// guess. Five abandoned logins, then the device throttles the sixth, through
/// the real server, with the retry time the outsider needs.
///
/// This is P3a's measurement (the client learns the answer at KE2 and never
/// sends KE3) turned into an end-to-end property: if the device counted only
/// failed KE3s, the sixth knock would be answered like the first.
#[tokio::test]
async fn wrong_guesses_are_counted_at_ke1_and_the_device_throttles() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-throttle").await;
    let dev = device(&app, &seeded, "mach-extauth-throttle", &pw("device")).await;
    let (_id, mut ws) = outsider(&app, "extguess").await;

    for n in 0..5 {
        let (state, ke1) = client_ke1(&pw("guess"));
        send(
            &mut ws,
            json!({"t": "rc:extauth.start", "connect_code": dev.code, "ke1": ke1}),
        )
        .await;
        let challenge = next_of(&mut ws, &["rc:extauth.challenge", "rc:extauth.result"]).await;
        assert_eq!(
            challenge["t"], "rc:extauth.challenge",
            "guess {n} is answered: {challenge}"
        );
        assert!(
            client_ke3(state, &pw("guess"), challenge["ke2"].as_str().unwrap()).is_none(),
            "a wrong password must fail in the client, at KE2"
        );
        // …and the client stops. No finish, ever.
    }
    let (_, ke1) = client_ke1(&pw("guess"));
    send(
        &mut ws,
        json!({"t": "rc:extauth.start", "connect_code": dev.code, "ke1": ke1}),
    )
    .await;
    let result = next_of(&mut ws, &["rc:extauth.challenge", "rc:extauth.result"]).await;
    assert_eq!(
        result["t"], "rc:extauth.result",
        "the sixth guess is NOT answered: {result}"
    );
    assert_eq!(result["refused"], "throttled", "{result}");
    // Real time passes between the fifth answer and this knock (the client's
    // Argon2 plus two round trips), and the device rounds the rest of its 30 s
    // UP — measured 29 here. The exact value is the unit test's job; end to
    // end, "a real wait, never more than the backoff" is what holds.
    let retry = result["retry_after_secs"].as_u64().expect("a retry time");
    assert!((1..=30).contains(&retry), "{result}");
    let _ = dev.stop.send(true);
}

/// No such code, the org's switch off, the device not approved: the outsider
/// gets the SAME answer for each, and the org's audit log tells them apart.
#[tokio::test]
async fn every_server_refusal_looks_the_same_to_the_outsider() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-gates").await;
    let dev = device(&app, &seeded, "mach-extauth-gates", &pw("device")).await;
    let (_id, mut ws) = outsider(&app, "extgates").await;
    let owner = &seeded.admin.access_token;
    let cfg_id = dev.agent_id.clone();

    let mut answers = Vec::new();
    let knock = |code: String| {
        let (_, ke1) = client_ke1(&pw("device"));
        json!({"t": "rc:extauth.start", "connect_code": code, "ke1": ke1})
    };

    // 1. A code nobody was ever given.
    send(&mut ws, knock("0000-0000-0000".into())).await;
    answers.push(next_of(&mut ws, &["rc:extauth.challenge", "rc:extauth.result"]).await);

    // 2. The org switches external access off (gate 1).
    assert_eq!(
        put(
            &app,
            &url(&seeded, "/external-access"),
            owner,
            json!({"enabled": false})
        )
        .await,
        200
    );
    send(&mut ws, knock(dev.code.clone())).await;
    answers.push(next_of(&mut ws, &["rc:extauth.challenge", "rc:extauth.result"]).await);

    // 3. Back on, but the device's approval withdrawn (gate 2).
    assert_eq!(
        put(
            &app,
            &url(&seeded, "/external-access"),
            owner,
            json!({"enabled": true})
        )
        .await,
        200
    );
    assert_eq!(
        put(
            &app,
            &url(&seeded, &format!("/agent/{cfg_id}/external-access-policy")),
            owner,
            json!({"approved": false})
        )
        .await,
        200
    );
    send(&mut ws, knock(dev.code.clone())).await;
    answers.push(next_of(&mut ws, &["rc:extauth.challenge", "rc:extauth.result"]).await);

    for a in &answers {
        assert_eq!(
            a,
            &json!({"t": "rc:extauth.result", "refused": "unavailable"}),
            "every server refusal must be byte-identical — no attempt id, no hint"
        );
    }
    let _ = dev.stop.send(true);
}

/// Only the principal who STARTED an attempt can finish it — and a stranger's
/// try does not burn it for its owner.
#[tokio::test]
async fn only_the_starter_can_finish_an_attempt() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-owner").await;
    let dev = device(&app, &seeded, "mach-extauth-owner", &pw("device")).await;
    let (_a, mut ws_a) = outsider(&app, "extownera").await;
    let (_b, mut ws_b) = outsider(&app, "extownerb").await;

    let (state, ke1) = client_ke1(&pw("device"));
    send(
        &mut ws_a,
        json!({"t": "rc:extauth.start", "connect_code": dev.code, "ke1": ke1}),
    )
    .await;
    let challenge = next_of(&mut ws_a, &["rc:extauth.challenge", "rc:extauth.result"]).await;
    let attempt_id = challenge["attempt_id"].as_str().unwrap().to_string();
    let ke3 = client_ke3(state, &pw("device"), challenge["ke2"].as_str().unwrap()).unwrap();

    // B holds a perfectly valid KE3 for A's attempt, and is told it does not exist.
    send(
        &mut ws_b,
        json!({"t": "rc:extauth.finish", "connect_code": dev.code, "attempt_id": attempt_id, "ke3": ke3}),
    )
    .await;
    let b_result = next_of(&mut ws_b, &["rc:extauth.result"]).await;
    assert_eq!(b_result["refused"], "unknown_attempt", "{b_result}");

    // A's attempt is intact.
    send(
        &mut ws_a,
        json!({"t": "rc:extauth.finish", "connect_code": dev.code, "attempt_id": attempt_id, "ke3": ke3}),
    )
    .await;
    let a_result = next_of(&mut ws_a, &["rc:extauth.result"]).await;
    assert!(
        a_result.get("refused").is_none(),
        "A still verifies: {a_result}"
    );
    let _ = dev.stop.send(true);
}

/// P3d — the outsider lands on the OTHER pod, and still logs in.
///
/// An outsider has no tenant, so tenant affinity cannot put their socket on the
/// pod that holds the device, and `/ws` refuses a `tid` they are not a member
/// of. Before P3d this login answered `unavailable`. Now both frames are
/// forwarded over the PR-2 relay to the device's pod, handled there, and
/// answered back to THIS socket — including `finish`, whose attempt lives only
/// on the other pod.
///
/// ⚠️ Needs a cluster bus (Redis). Without one it cannot run and says so
/// loudly rather than passing on nothing.
#[tokio::test]
async fn an_outsider_on_the_other_pod_still_logs_in() {
    let (app1, app2) = TestApp::spawn_pair(|_| {}).await;
    if app1.state.cluster_bus.is_none() {
        eprintln!(
            "SKIPPED an_outsider_on_the_other_pod_still_logs_in: no Redis — P3d unproven here"
        );
        return;
    }
    for _ in 0..40 {
        let (a, b) = (
            app1.state.cluster_bus.as_ref().unwrap(),
            app2.state.cluster_bus.as_ref().unwrap(),
        );
        if a.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
            && b.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let seeded = app1.seed_tenant("extauth-xpod").await;
    // The device is homed on pod 1…
    let dev = device(&app1, &seeded, "mach-extauth-xpod", &pw("device")).await;
    // …and the outsider lands on pod 2.
    let (_id, mut ws) = outsider(&app2, "extxpod").await;

    let (state, ke1) = client_ke1(&pw("device"));
    send(
        &mut ws,
        json!({"t": "rc:extauth.start", "connect_code": dev.code, "ke1": ke1}),
    )
    .await;
    let challenge = next_of(&mut ws, &["rc:extauth.challenge", "rc:extauth.result"]).await;
    assert_eq!(
        challenge["t"], "rc:extauth.challenge",
        "the device on the OTHER pod answered KE1: {challenge}"
    );
    let attempt_id = challenge["attempt_id"].as_str().unwrap().to_string();
    let ke3 = client_ke3(state, &pw("device"), challenge["ke2"].as_str().unwrap())
        .expect("the right password opens the device's KE2");
    send(
        &mut ws,
        json!({"t": "rc:extauth.finish", "connect_code": dev.code, "attempt_id": attempt_id, "ke3": ke3}),
    )
    .await;
    let result = next_of(&mut ws, &["rc:extauth.result"]).await;
    assert!(
        result.get("refused").is_none(),
        "verified across pods — the attempt lives on pod 1, the socket on pod 2: {result}"
    );
    let _ = dev.stop.send(true);
}

// ─── P4 — the session a verified login opens ─────────────────────────────────
//
// The browser's half is written here from the SPEC, not from the device's code:
// the AppKey derivation, the MAC and the fingerprint normalisation below are an
// independent implementation (HKDF from two HMACs, per RFC 5869), so a device
// that drifted from the spec fails these tests instead of agreeing with itself.

/// `HKDF-SHA512(salt = none, ikm = the OPAQUE session key)`, expanded under the
/// label and the two length-prefixed fields — the browser's AppKey.
fn app_key(session_key: &[u8], attempt_id: &str, principal: &str) -> [u8; 32] {
    use hmac::Mac as _;
    type H = hmac::Hmac<sha2::Sha512>;
    // Extract with no salt: a hash-length block of zeros (RFC 5869 §2.2).
    let mut extract = <H as hmac::Mac>::new_from_slice(&[0u8; 64]).unwrap();
    extract.update(session_key);
    let prk = extract.finalize().into_bytes();
    // Expand, one block: T(1) = HMAC(PRK, info ‖ 0x01), truncated to 32.
    let mut info = b"meshharbor-extauth-v1 app-key".to_vec();
    for field in [attempt_id.as_bytes(), principal.as_bytes()] {
        info.extend_from_slice(&(field.len() as u16).to_be_bytes());
        info.extend_from_slice(field);
    }
    let mut expand = <H as hmac::Mac>::new_from_slice(&prk).unwrap();
    expand.update(&info);
    expand.update(&[1u8]);
    expand.finalize().into_bytes()[..32].try_into().unwrap()
}

/// `HMAC-SHA256(AppKey, label ‖ u16be ‖ role ‖ u16be ‖ fingerprint)`, base64url.
fn transport_mac(key: &[u8; 32], role: &str, fingerprint: &str) -> String {
    use hmac::Mac as _;
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
    mac.update(b"meshharbor-extauth-v1 transport");
    for field in [role.as_bytes(), fingerprint.as_bytes()] {
        mac.update(&(field.len() as u16).to_be_bytes());
        mac.update(field);
    }
    b64url().encode(mac.finalize().into_bytes())
}

/// The SDP's one certificate fingerprint: `lowercase(hash) + " " + UPPERCASE(hex)`.
fn fingerprint(sdp: &str) -> String {
    let value = sdp
        .lines()
        .find_map(|l| l.trim().strip_prefix("a=fingerprint:"))
        .expect("an SDP with a DTLS fingerprint");
    let (hash, hex) = value.trim().split_once(' ').unwrap();
    format!(
        "{} {}",
        hash.to_ascii_lowercase(),
        hex.trim().to_ascii_uppercase()
    )
}

/// A whole login as a browser runs it: the attempt, and the key the BROWSER
/// derives from its own side of the exchange.
async fn login(ws: &mut Ws, code: &str, password: &str, principal: &str) -> (String, [u8; 32]) {
    let (state, ke1) = client_ke1(password);
    send(
        ws,
        json!({"t": "rc:extauth.start", "connect_code": code, "ke1": ke1}),
    )
    .await;
    let challenge = next_of(ws, &["rc:extauth.challenge", "rc:extauth.result"]).await;
    assert_eq!(challenge["t"], "rc:extauth.challenge", "{challenge}");
    let attempt_id = challenge["attempt_id"].as_str().unwrap().to_string();
    let ke2 = b64url().decode(challenge["ke2"].as_str().unwrap()).unwrap();
    let done = state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            CredentialResponse::<Suite>::deserialize(&ke2).unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .expect("the right password opens the device's KE2");
    send(
        ws,
        json!({
            "t": "rc:extauth.finish",
            "connect_code": code,
            "attempt_id": attempt_id,
            "ke3": b64url().encode(done.message.serialize()),
        }),
    )
    .await;
    let result = next_of(ws, &["rc:extauth.result"]).await;
    assert!(result.get("refused").is_none(), "not verified: {result}");
    let key = app_key(&done.session_key, &attempt_id, principal);
    (attempt_id, key)
}

/// A browser-side peer and its offer: a data channel, so the offer has an
/// m-section, and so a DTLS fingerprint.
async fn browser_offer() -> (
    std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
    String,
) {
    use webrtc::api::APIBuilder;
    use webrtc::api::media_engine::MediaEngine;
    use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
    use webrtc::peer_connection::configuration::RTCConfiguration;
    let mut media = MediaEngine::default();
    media.register_default_codecs().unwrap();
    let api = APIBuilder::new().with_media_engine(media).build();
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
    (pc, offer.sdp)
}

/// Ask for the session a verified login earned; wait for `rc:session.created`
/// and `rc:ready` (the device consents by itself: `external_consent_mode =
/// auto`). Returns the session id.
async fn open_session(ws: &mut Ws, code: &str, attempt_id: &str, permissions: &str) -> String {
    send(
        ws,
        json!({
            "t": "rc:extauth.session",
            "connect_code": code,
            "attempt_id": attempt_id,
            "permissions": permissions,
        }),
    )
    .await;
    let created = next_of(ws, &["rc:session.created", "rc:extauth.result", "rc:error"]).await;
    assert_eq!(created["t"], "rc:session.created", "{created}");
    assert_eq!(
        created["agent_id"], "000000000000000000000000",
        "an outsider named a connect code, and is never told the internal id: {created}"
    );
    let session_id = created["session_id"].as_str().unwrap().to_string();
    let ready = next_of(ws, &["rc:ready", "rc:terminate", "rc:error"]).await;
    assert_eq!(
        ready["t"], "rc:ready",
        "the device admitted the session and consented: {ready}"
    );
    session_id
}

/// The device's terms for the tests that open a session.
fn unattended() -> Terms {
    Terms {
        consent: Some("auto"),
        ..Terms::default()
    }
}

/// THE P4 proof, end to end through the real server and the real agent: a
/// verified login opens a session; the offer carries a MAC over the browser's
/// certificate, under a key only the two ends hold; the device answers with a
/// MAC over ITS certificate under the same key; and the org's log has a
/// `session` row naming the session and the login it spent.
#[tokio::test]
async fn an_outsider_opens_a_session_bound_to_their_login() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-session").await;
    let dev = device_with(
        &app,
        &seeded,
        "mach-extauth-session",
        &pw("device"),
        unattended(),
    )
    .await;
    let (principal, mut ws) = outsider(&app, "extsession").await;

    let (attempt_id, key) = login(&mut ws, &dev.code, &pw("device"), &principal).await;
    let session_id = open_session(&mut ws, &dev.code, &attempt_id, "VIEW | INPUT").await;

    let (pc, offer) = browser_offer().await;
    send(
        &mut ws,
        json!({
            "t": "rc:sdp.offer",
            "session_id": session_id,
            "sdp": offer,
            "extauth_mac": transport_mac(&key, "offer", &fingerprint(&offer)),
        }),
    )
    .await;
    let answer = next_of(&mut ws, &["rc:sdp.answer", "rc:terminate", "rc:error"]).await;
    assert_eq!(
        answer["t"], "rc:sdp.answer",
        "the device accepted the sealed offer: {answer}"
    );
    let answer_sdp = answer["sdp"].as_str().unwrap();
    assert_eq!(
        answer["extauth_mac"].as_str(),
        Some(transport_mac(&key, "answer", &fingerprint(answer_sdp)).as_str()),
        "the answer is sealed over the DEVICE's certificate, under the login's key"
    );
    assert_ne!(
        fingerprint(answer_sdp),
        fingerprint(&offer),
        "two certificates, one per end"
    );
    pc.set_remote_description(
        webrtc::peer_connection::sdp::session_description::RTCSessionDescription::answer(
            answer_sdp.to_string(),
        )
        .unwrap(),
    )
    .await
    .expect("the browser accepts the device's answer");

    // The org sees who got in, on which login, into which session.
    let audit = url(&seeded, "/external-rc-audit");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let body: Value = app
            .auth_get(&audit, &seeded.admin.access_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let row = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["action"] == "session" && i["attempt_id"] == json!(attempt_id))
            .cloned();
        if let Some(row) = row {
            assert!(row.get("login_refused").is_none(), "admitted: {row}");
            assert_eq!(row["session_id"], json!(session_id), "{row}");
            assert_eq!(row["user_id"], json!(principal), "{row}");
            break;
        }
        assert!(Instant::now() < deadline, "no `session` audit row: {body}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = pc.close().await;
    let _ = dev.stop.send(true);
}

/// What binds every controller of a device binds an outsider too (FR-101). The
/// org says `files: off` and sets an idle limit; gate 2's ceiling allows FILES
/// and the outsider asks for it. The session opens without FILES, names the
/// org as the reason, and runs under the org's idle limit. FR-52 was built
/// before FR-101 existed. Rebased onto it, the extauth relay first handed the
/// Hub an unrestricted policy and no limits, so FILES survived and an
/// outsider's session could sit idle for ever: the outside door looser than
/// the inside one.
#[tokio::test]
async fn an_outsiders_session_is_bound_by_the_orgs_session_policy() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-policy").await;
    let dev = device_with(
        &app,
        &seeded,
        "mach-extauth-policy",
        &pw("device"),
        unattended(),
    )
    .await;
    let owner = &seeded.admin.access_token;
    // The ceiling allows FILES: what must take it out is the org's POLICY.
    let policy = url(
        &seeded,
        &format!("/agent/{}/external-access-policy", dev.agent_id),
    );
    let ceiling = json!({ "approved": true, "max_permissions": "VIEW | INPUT | FILES" });
    assert_eq!(put(&app, &policy, owner, ceiling).await, 200);
    let files_off = json!({ "files": "off" });
    assert_eq!(
        put(&app, &url(&seeded, "/rc-session-policy"), owner, files_off).await,
        200
    );
    let idle = json!({ "idle_secs": 600 });
    assert_eq!(
        put(&app, &url(&seeded, "/rc-session-limits"), owner, idle).await,
        200
    );

    let (principal, mut ws) = outsider(&app, "extpolicy").await;
    let (attempt_id, _key) = login(&mut ws, &dev.code, &pw("device"), &principal).await;
    send(
        &mut ws,
        json!({
            "t": "rc:extauth.session",
            "connect_code": dev.code,
            "attempt_id": attempt_id,
            "permissions": "VIEW | INPUT | FILES",
        }),
    )
    .await;
    let created = next_of(
        &mut ws,
        &["rc:session.created", "rc:extauth.result", "rc:error"],
    )
    .await;
    assert_eq!(created["t"], "rc:session.created", "{created}");
    let granted = created["permissions"].as_str().unwrap_or_default();
    assert!(granted.contains("VIEW"), "{created}");
    assert!(
        !granted.contains("FILES"),
        "the org's `files: off` binds an outsider: {created}"
    );
    assert_eq!(
        created["features_refused"]["files"], "org_policy_off",
        "{created}"
    );
    assert_eq!(
        created["idle_secs"], 600,
        "the org's idle limit binds an outsider: {created}"
    );
    let _ = dev.stop.send(true);
}

/// The binding is enforced BY THE DEVICE: an offer that does not carry the
/// login's MAC over its own certificate — a key from nowhere, no MAC at all, or
/// the right key over a swapped certificate — ends the session, and no answer
/// ever comes back. This is what stops a server that relays the signalling from
/// substituting its own DTLS endpoint for the browser's.
#[tokio::test]
async fn an_offer_the_login_did_not_seal_ends_the_session() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-badmac").await;
    let dev = device_with(
        &app,
        &seeded,
        "mach-extauth-badmac",
        &pw("device"),
        unattended(),
    )
    .await;
    let (principal, mut ws) = outsider(&app, "extbadmac").await;

    // A genuine tag over a certificate that is not the offer's: what an
    // interloper who saw a real offer could replay onto its own.
    const NOT_THE_OFFERS: &str = "sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:\
                                  11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00";
    for forgery in ["another key", "no mac", "swapped certificate"] {
        let (attempt_id, key) = login(&mut ws, &dev.code, &pw("device"), &principal).await;
        let session_id = open_session(&mut ws, &dev.code, &attempt_id, "VIEW").await;
        let (pc, offer) = browser_offer().await;
        let mac = match forgery {
            "another key" => Some(transport_mac(&[0x42; 32], "offer", &fingerprint(&offer))),
            "no mac" => None,
            _ => Some(transport_mac(&key, "offer", NOT_THE_OFFERS)),
        };
        let mut frame = json!({"t": "rc:sdp.offer", "session_id": session_id, "sdp": offer});
        if let Some(mac) = mac {
            frame["extauth_mac"] = json!(mac);
        }
        send(&mut ws, frame).await;
        let verdict = next_of(&mut ws, &["rc:sdp.answer", "rc:terminate", "rc:error"]).await;
        assert_eq!(
            verdict["t"], "rc:terminate",
            "{forgery}: the device must end the session, never answer it: {verdict}"
        );
        assert_eq!(
            verdict["session_id"],
            json!(session_id),
            "{forgery}: {verdict}"
        );
        assert_eq!(
            verdict["reason"], "agent_hangup",
            "{forgery}: ended by the device's own act: {verdict}"
        );
        let _ = pc.close().await;
    }
    let _ = dev.stop.send(true);
}

/// One verified login opens ONE session, and only for the principal who logged
/// in: another outsider holding the attempt id, a second ask on the same login,
/// and an attempt nobody verified are all `unknown_attempt`.
#[tokio::test]
async fn a_login_opens_one_session_for_its_own_principal() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extauth-once").await;
    let dev = device_with(
        &app,
        &seeded,
        "mach-extauth-once",
        &pw("device"),
        unattended(),
    )
    .await;
    let (principal, mut ws_a) = outsider(&app, "extoncea").await;
    let (_b, mut ws_b) = outsider(&app, "extonceb").await;

    let (attempt_id, _key) = login(&mut ws_a, &dev.code, &pw("device"), &principal).await;
    let ask = |attempt: &str| {
        json!({
            "t": "rc:extauth.session",
            "connect_code": dev.code,
            "attempt_id": attempt,
            "permissions": "VIEW",
        })
    };

    send(&mut ws_b, ask(&attempt_id)).await;
    let stolen = next_of(&mut ws_b, &["rc:extauth.result", "rc:session.created"]).await;
    assert_eq!(stolen["refused"], "unknown_attempt", "{stolen}");

    // A's login survived B's try.
    let _session = open_session(&mut ws_a, &dev.code, &attempt_id, "VIEW").await;

    send(&mut ws_a, ask(&attempt_id)).await;
    let twice = next_of(&mut ws_a, &["rc:extauth.result", "rc:session.created"]).await;
    assert_eq!(
        twice["refused"], "unknown_attempt",
        "one login, one session: {twice}"
    );

    send(&mut ws_a, ask("66f0c0ffee0000000000abcd")).await;
    let never = next_of(&mut ws_a, &["rc:extauth.result", "rc:session.created"]).await;
    assert_eq!(never["refused"], "unknown_attempt", "{never}");
    let _ = dev.stop.send(true);
}

/// P4 across pods — the outsider on pod 2, the device on pod 1. The session is
/// opened on pod 1 with the relay's proxy sender, and every later frame of it
/// (the sealed offer, the sealed answer) crosses the PR-2 relay in both
/// directions with its MAC intact: the server carries a field it cannot check
/// and must not drop.
///
/// ⚠️ Needs a cluster bus (Redis). Without one it says so loudly rather than
/// passing on nothing.
#[tokio::test]
async fn an_outsider_on_the_other_pod_opens_a_sealed_session() {
    let (app1, app2) = TestApp::spawn_pair(|_| {}).await;
    if app1.state.cluster_bus.is_none() {
        eprintln!(
            "SKIPPED an_outsider_on_the_other_pod_opens_a_sealed_session: no Redis — P4 \
             cross-pod unproven here"
        );
        return;
    }
    for _ in 0..40 {
        let (a, b) = (
            app1.state.cluster_bus.as_ref().unwrap(),
            app2.state.cluster_bus.as_ref().unwrap(),
        );
        if a.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
            && b.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let seeded = app1.seed_tenant("extauth-xpod-session").await;
    let dev = device_with(
        &app1,
        &seeded,
        "mach-extauth-xpod-session",
        &pw("device"),
        unattended(),
    )
    .await;
    let (principal, mut ws) = outsider(&app2, "extxpodsession").await;

    let (attempt_id, key) = login(&mut ws, &dev.code, &pw("device"), &principal).await;
    let session_id = open_session(&mut ws, &dev.code, &attempt_id, "VIEW | INPUT").await;
    let (pc, offer) = browser_offer().await;
    send(
        &mut ws,
        json!({
            "t": "rc:sdp.offer",
            "session_id": session_id,
            "sdp": offer,
            "extauth_mac": transport_mac(&key, "offer", &fingerprint(&offer)),
        }),
    )
    .await;
    let answer = next_of(&mut ws, &["rc:sdp.answer", "rc:terminate", "rc:error"]).await;
    assert_eq!(
        answer["t"], "rc:sdp.answer",
        "the offer crossed to pod 1 with its MAC, the answer came back: {answer}"
    );
    let answer_sdp = answer["sdp"].as_str().unwrap();
    assert_eq!(
        answer["extauth_mac"].as_str(),
        Some(transport_mac(&key, "answer", &fingerprint(answer_sdp)).as_str()),
        "the seal survived the relay"
    );
    let _ = pc.close().await;
    let _ = dev.stop.send(true);
}
