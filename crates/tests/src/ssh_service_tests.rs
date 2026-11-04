// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-105 — roomler SSH through a Windows device's SYSTEM service, the
//! server's half.
//!
//! The device is a RAW agent socket (the test crate builds the agent without
//! `ssh-server`), and the test plays the SYSTEM service with the credential
//! the anchor minted. What these lock:
//! - a grant goes to the service only with BOTH halves: the server's record
//!   (anchored, and an endpoint the service published under that anchor whose
//!   ceiling permits the account) and the device's live `ssh-system` word;
//! - the caller then dials the service's port and pins the SERVICE's key;
//! - only the service's claim confirms the grant (the worker can refuse it,
//!   never confirm it), single use, this device only, inside the wait; and a
//!   claim on the other pod still reaches the caller;
//! - only the service publishes its endpoint, and re-anchoring retires it;
//! - `ssh_audit.ran_as` records who served it; the kill switch restores the
//!   worker path.

use std::time::{Duration, Instant};

use base64::Engine as _;
use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::models::NodeRef;
use meshharbor_services::dao::overlay_network::OverlayNetworkDao;
use meshharbor_services::dao::overlay_node::{NewOverlayNode, OverlayNodeDao};
use serde_json::{Value, json};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::tunnel_tests::wait_agent_online;

type AgentWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// An OpenSSH ed25519 public key with a recognisable body. The server checks
/// the structure only; nothing here ever dials.
fn ed25519(fill: u8, comment: &str) -> String {
    let mut raw = Vec::with_capacity(51);
    raw.extend_from_slice(&11u32.to_be_bytes());
    raw.extend_from_slice(b"ssh-ed25519");
    raw.extend_from_slice(&32u32.to_be_bytes());
    raw.extend_from_slice(&[fill; 32]);
    format!(
        "ssh-ed25519 {} {comment}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn session_key() -> String {
    ed25519(1, "caller")
}
fn worker_key() -> String {
    ed25519(2, "worker")
}
fn service_key() -> String {
    ed25519(3, "service")
}

/// What an `ssh-server` build with the FR-105 service path advertises…
const SERVICE_CAPABLE: &[&str] = &["exec", "ssh", "ssh-consent", "ssh-grant-ack", "ssh-system"];
/// …and the same build whose anchor does not allow SSH.
const WORKER_ONLY: &[&str] = &["exec", "ssh", "ssh-consent", "ssh-grant-ack"];

struct Device {
    agent_id: String,
    /// The worker's agent token.
    token: String,
    /// The SYSTEM service's credential, from the anchor.
    service: String,
    ws: AgentWs,
}

async fn enable_org_ssh(app: &TestApp, seeded: &SeededTenant) {
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/ssh-settings", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&json!({ "remote_ssh_enabled": true }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "org switch: {:?}",
        resp.status()
    );
}

async fn enrollment_token(app: &TestApp, seeded: &SeededTenant) -> String {
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

async fn set_policy(app: &TestApp, seeded: &SeededTenant, agent_id: &str, account_mode: &str) {
    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/agent/{agent_id}/ssh-policy",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({ "mode": "on", "account_mode": account_mode, "consent_mode": "auto" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "policy: {:?}", resp.status());
}

async fn publish(app: &TestApp, credential: &str, body: Value) -> reqwest::Response {
    app.client
        .put(app.url("/api/agent/service/ssh-host-key"))
        .bearer_auth(credential)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn claim(app: &TestApp, service: &str, grant_id: &str) -> reqwest::Response {
    app.auth_post(&format!("/api/agent/service/ssh/{grant_id}/claim"), service)
        .send()
        .await
        .unwrap()
}

/// FR-90 P3-8-2a — a claim from a service that holds an agent session's
/// grant to one command, as its build says on every claim.
async fn claim_holding_one_command(
    app: &TestApp,
    service: &str,
    grant_id: &str,
) -> reqwest::Response {
    app.auth_post(
        &format!("/api/agent/service/ssh/{grant_id}/claim?one_command=true"),
        service,
    )
    .send()
    .await
    .unwrap()
}

/// A Windows device on the mesh: enrolled, an overlay address, SSH policy
/// `account_mode`, anchored, its service's endpoint published with
/// `ceiling`, and a raw socket advertising `rpc`.
async fn device(
    app: &TestApp,
    seeded: &SeededTenant,
    machine: &str,
    ip: &str,
    account_mode: &str,
    ceiling: &str,
    rpc: &[&str],
) -> Device {
    let ej: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": enrollment_token(app, seeded).await,
            "machine_id": machine,
            "machine_name": machine,
            "os": "windows",
            "agent_version": "0.4.135",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = ej["agent_id"].as_str().unwrap().to_string();
    let token = ej["agent_token"].as_str().unwrap().to_string();

    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let aid = ObjectId::parse_str(&agent_id).unwrap();
    let network_id = OverlayNetworkDao::new(&app.db)
        .get_or_create(tid)
        .await
        .unwrap()
        .id
        .unwrap();
    OverlayNodeDao::new(&app.db)
        .create(NewOverlayNode {
            tenant_id: tid,
            node_ref: NodeRef::Agent { agent_id: aid },
            network_id,
            machine_id: machine.to_string(),
            name: machine.to_string(),
            overlay_ip: ip.to_string(),
            wg_public_key: format!("pk-{machine}"),
            key_epoch: 0,
            endpoints: vec![],
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_server_relay_strategy: false,
            supports_derp_floor: false,
            supports_overlay_echo: false,
            supports_org_relay: false,
            advertised_routes: vec![],
            route_offer_withheld: None,
        })
        .await
        .unwrap();
    set_policy(app, seeded, &agent_id, account_mode).await;

    let anchored: Value = app
        .client
        .post(app.url("/api/agent/anchor"))
        .json(&json!({
            "enrollment_token": enrollment_token(app, seeded).await,
            "agent_id": agent_id,
            "host_name": machine,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let service = anchored["service_token"]
        .as_str()
        .expect("anchored")
        .to_string();
    let published = publish(
        app,
        &service,
        json!({ "host_pubkey": service_key(), "ceiling": ceiling }),
    )
    .await;
    assert_eq!(
        published.status(),
        200,
        "the service publishes its endpoint"
    );

    let url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut ws, _) = connect_async(&url).await.expect("agent ws connect");
    ws.send(Message::Text(
        json!({
            "t": "rc:agent.hello",
            "machine_name": machine,
            "os": "windows",
            "agent_version": "0.4.135",
            "displays": [],
            "ssh_host_pubkey": worker_key(),
            "caps": {
                "hw_encoders": [], "codecs": ["h264"], "has_input_permission": true,
                "supports_clipboard": false, "supports_file_transfer": false,
                "max_simultaneous_sessions": 4, "rpc": rpc,
            }
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    wait_agent_online(app, seeded, &agent_id).await;
    Device {
        agent_id,
        token,
        service,
        ws,
    }
}

/// `POST …/agent/{id}/ssh` as the admin. Retries only the window in which the
/// row reads online before the Hub recorded the device's words (a refusal
/// before any grant is minted, so retrying it is safe).
async fn request_session(app: &TestApp, seeded: &SeededTenant, agent_id: &str) -> Value {
    for _ in 0..10 {
        let body: Value = app
            .auth_post(
                &format!("/api/tenant/{}/agent/{agent_id}/ssh", seeded.tenant_id),
                &seeded.admin.access_token,
            )
            .json(&json!({ "public_key": session_key() }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let unsupported = body["error"]
            .as_str()
            .is_some_and(|e| e.contains("does not support roomler SSH"));
        if !unsupported {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the Hub never recorded the device's ssh words");
}

/// Read frames until the server pushes a grant; returns the frame.
async fn next_grant(ws: &mut AgentWs) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let frame = tokio::time::timeout(left, ws.next())
            .await
            .expect("no rc:ssh.grant within 10 s")
            .expect("agent socket closed")
            .expect("agent socket error");
        if let Message::Text(t) = frame {
            let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
            if v["t"] == "rc:ssh.grant" {
                return v;
            }
        }
    }
}

async fn send_ack(ws: &mut AgentWs, grant_id: &str, refused: Option<&str>) {
    let mut ack = json!({ "t": "rc:ssh.grant_ack", "grant_id": grant_id });
    if let Some(r) = refused {
        ack["refused"] = json!(r);
    }
    ws.send(Message::Text(ack.to_string().into()))
        .await
        .unwrap();
}

async fn audit_rows(app: &TestApp, seeded: &SeededTenant) -> Vec<Value> {
    let audit: Value = app
        .auth_get(
            &format!("/api/tenant/{}/ssh-audit", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    audit["items"].as_array().cloned().unwrap_or_default()
}

/// AC1's server half: an anchored device whose service published an endpoint
/// and whose worker advertises `ssh-system` gets the grant through the
/// service. The worker's own "recorded" confirms nothing; the service's claim
/// does, once. The caller dials the service port and pins the service's key.
#[tokio::test]
async fn a_grant_goes_to_the_service_and_its_claim_confirms_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr105service").await;
    enable_org_ssh(&app, &seeded).await;
    let mut dev = device(
        &app,
        &seeded,
        "HOST-S1",
        "100.64.0.51",
        "daemon",
        "system",
        SERVICE_CAPABLE,
    )
    .await;

    let target = async {
        let frame = next_grant(&mut dev.ws).await;
        assert_eq!(
            frame["via_service"],
            json!(true),
            "the worker is told it is the service's: {frame}"
        );
        let grant_id = frame["grant_id"].as_str().unwrap().to_string();
        // The worker says "recorded"; that must not answer the caller.
        send_ack(&mut dev.ws, &grant_id, None).await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let claimed = claim(&app, &dev.service, &grant_id).await;
        assert_eq!(claimed.status(), 200, "the service claims it");
        let grant: Value = claimed.json().await.unwrap();
        assert_eq!(grant["public_key"], json!(session_key()));
        assert_eq!(grant["account_mode"], json!("daemon"));
        (grant_id, Instant::now())
    };
    let caller = async {
        let body = request_session(&app, &seeded, &dev.agent_id).await;
        (body, Instant::now())
    };
    let ((grant_id, claimed_at), (body, answered_at)) = tokio::join!(target, caller);

    assert!(
        answered_at >= claimed_at,
        "the caller was answered before the service claimed: the worker's own ack confirmed it"
    );
    assert_eq!(body["address"], json!("100.64.0.51"), "{body}");
    assert_eq!(body["port"], json!(2223), "the service's port: {body}");
    assert_eq!(
        body["host_pubkey"],
        json!(service_key()),
        "the SERVICE's key, never the worker's: {body}"
    );

    // Single use, this device only.
    assert_eq!(claim(&app, &dev.service, &grant_id).await.status(), 404);
    let rows = audit_rows(&app, &seeded).await;
    assert!(
        rows.iter()
            .any(|r| r["grant_id"] == json!(grant_id) && r["ran_as"] == json!("system")),
        "the decision names who served it: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r["denied"] == json!("claim_refused")),
        "the second claim is audited: {rows:?}"
    );
}

/// Without the device's word, or with a ceiling that does not permit the
/// account, or under the kill switch, the grant goes to the worker exactly as
/// before FR-105: its port, its key, no `via_service`, and `ran_as: worker`.
#[tokio::test]
async fn without_both_halves_the_grant_goes_to_the_worker() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr105worker").await;
    enable_org_ssh(&app, &seeded).await;

    // No `ssh-system` word.
    let mut no_word = device(
        &app,
        &seeded,
        "HOST-W1",
        "100.64.0.52",
        "daemon",
        "system",
        WORKER_ONLY,
    )
    .await;
    // The word, but a ceiling of `console_user` under a `daemon` policy.
    let mut low_ceiling = device(
        &app,
        &seeded,
        "HOST-W2",
        "100.64.0.53",
        "daemon",
        "console_user",
        SERVICE_CAPABLE,
    )
    .await;

    for dev in [&mut no_word, &mut low_ceiling] {
        let agent_id = dev.agent_id.clone();
        let target = async {
            let frame = next_grant(&mut dev.ws).await;
            assert!(
                frame.get("via_service").is_none(),
                "a worker grant carries no via_service: {frame}"
            );
            let grant_id = frame["grant_id"].as_str().unwrap().to_string();
            send_ack(&mut dev.ws, &grant_id, None).await;
        };
        let (body, ()) = tokio::join!(request_session(&app, &seeded, &agent_id), target);
        assert_eq!(body["port"], json!(2222), "{body}");
        assert_eq!(body["host_pubkey"], json!(worker_key()), "{body}");
    }
    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(
        rows.iter()
            .filter(|r| r["ran_as"] == json!("worker"))
            .count(),
        2,
        "{rows:?}"
    );

    // A `console_user` policy fits the `console_user` ceiling: the service.
    set_policy(&app, &seeded, &low_ceiling.agent_id, "console_user").await;
    let target = async {
        let frame = next_grant(&mut low_ceiling.ws).await;
        assert_eq!(frame["via_service"], json!(true), "{frame}");
        let grant_id = frame["grant_id"].as_str().unwrap().to_string();
        assert_eq!(
            claim(&app, &low_ceiling.service, &grant_id).await.status(),
            200
        );
    };
    let (body, ()) = tokio::join!(
        request_session(&app, &seeded, &low_ceiling.agent_id),
        target
    );
    assert_eq!(body["port"], json!(2223), "{body}");
    let rows = audit_rows(&app, &seeded).await;
    assert!(
        rows.iter().any(|r| r["ran_as"] == json!("console_user")),
        "{rows:?}"
    );
}

/// The worker can still REFUSE a grant meant for the service (the person's
/// own `ssh_enabled` off is theirs to say), and that refusal withdraws it: a
/// claim afterwards gets nothing.
#[tokio::test]
async fn the_worker_can_refuse_a_service_grant_and_that_withdraws_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr105refuse").await;
    enable_org_ssh(&app, &seeded).await;
    let mut dev = device(
        &app,
        &seeded,
        "HOST-R1",
        "100.64.0.54",
        "daemon",
        "system",
        SERVICE_CAPABLE,
    )
    .await;

    let target = async {
        let frame = next_grant(&mut dev.ws).await;
        let grant_id = frame["grant_id"].as_str().unwrap().to_string();
        send_ack(&mut dev.ws, &grant_id, Some("ssh_disabled")).await;
        grant_id
    };
    let (body, grant_id) = tokio::join!(request_session(&app, &seeded, &dev.agent_id), target);
    assert!(body["address"].is_null(), "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("switched off on the device itself"),
        "{body}"
    );
    assert_eq!(
        claim(&app, &dev.service, &grant_id).await.status(),
        404,
        "a refused grant can no longer be claimed"
    );
}

/// Only the service publishes its endpoint: the worker's agent token is
/// refused, a malformed key is refused, and an endpoint published under an
/// anchor that was since replaced no longer routes (the grant goes to the
/// worker until the service publishes again under the new anchor).
#[tokio::test]
async fn only_the_service_publishes_and_a_re_anchor_retires_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr105publish").await;
    enable_org_ssh(&app, &seeded).await;
    let mut dev = device(
        &app,
        &seeded,
        "HOST-P1",
        "100.64.0.55",
        "daemon",
        "system",
        SERVICE_CAPABLE,
    )
    .await;

    // The worker's own token cannot publish.
    let by_worker = publish(
        &app,
        &dev.token,
        json!({ "host_pubkey": ed25519(9, "forged"), "ceiling": "system" }),
    )
    .await;
    assert_eq!(
        by_worker.status(),
        401,
        "the worker's token is not the service's"
    );
    let malformed = publish(
        &app,
        &dev.service,
        json!({ "host_pubkey": "ssh-ed25519 not-a-key", "ceiling": "system" }),
    )
    .await;
    assert_eq!(malformed.status(), 400);

    // Re-anchoring: the old credential and its publication are retired.
    let re: Value = app
        .client
        .post(app.url("/api/agent/anchor"))
        .json(&json!({
            "enrollment_token": enrollment_token(&app, &seeded).await,
            "agent_id": dev.agent_id,
            "host_name": "HOST-P1",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_service = re["service_token"].as_str().unwrap().to_string();
    assert_eq!(
        publish(
            &app,
            &dev.service,
            json!({ "host_pubkey": service_key(), "ceiling": "system" })
        )
        .await
        .status(),
        401,
        "the old anchor's credential is dead"
    );

    let target = async {
        let frame = next_grant(&mut dev.ws).await;
        assert!(
            frame.get("via_service").is_none(),
            "stale endpoint: worker path: {frame}"
        );
        let grant_id = frame["grant_id"].as_str().unwrap().to_string();
        send_ack(&mut dev.ws, &grant_id, None).await;
    };
    let (body, ()) = tokio::join!(request_session(&app, &seeded, &dev.agent_id), target);
    assert_eq!(body["port"], json!(2222), "{body}");

    // Published again under the new anchor: the service path is back.
    assert_eq!(
        publish(
            &app,
            &new_service,
            json!({ "host_pubkey": service_key(), "ceiling": "system" })
        )
        .await
        .status(),
        200
    );
    dev.service = new_service;
    let target = async {
        let frame = next_grant(&mut dev.ws).await;
        assert_eq!(frame["via_service"], json!(true), "{frame}");
        let grant_id = frame["grant_id"].as_str().unwrap().to_string();
        assert_eq!(claim(&app, &dev.service, &grant_id).await.status(), 200);
    };
    let (body, ()) = tokio::join!(request_session(&app, &seeded, &dev.agent_id), target);
    assert_eq!(body["port"], json!(2223), "{body}");
}

/// A service that never claims leaves the caller unconfirmed (never an
/// address), and a late claim is refused: once nobody waits, nothing may
/// take the grant.
#[tokio::test]
async fn silence_from_the_service_is_unconfirmed_and_a_late_claim_is_refused() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr105silent").await;
    enable_org_ssh(&app, &seeded).await;
    let mut dev = device(
        &app,
        &seeded,
        "HOST-Q1",
        "100.64.0.56",
        "daemon",
        "system",
        SERVICE_CAPABLE,
    )
    .await;

    let target = async {
        next_grant(&mut dev.ws).await["grant_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (body, grant_id) = tokio::join!(request_session(&app, &seeded, &dev.agent_id), target);
    assert!(body["address"].is_null(), "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("did not confirm"),
        "{body}"
    );
    assert_eq!(claim(&app, &dev.service, &grant_id).await.status(), 404);
}

/// AC5 — the device's socket and the caller are on pod A; the service's claim
/// lands on pod B. The caller still resolves, through the shared row.
#[tokio::test]
async fn a_claim_on_the_other_pod_still_confirms_the_grant() {
    let (a, b) = TestApp::spawn_pair(|_| {}).await;
    let seeded = a.seed_tenant("fr105pods").await;
    enable_org_ssh(&a, &seeded).await;
    let mut dev = device(
        &a,
        &seeded,
        "HOST-X1",
        "100.64.0.57",
        "daemon",
        "system",
        SERVICE_CAPABLE,
    )
    .await;

    let target = async {
        let frame = next_grant(&mut dev.ws).await;
        let grant_id = frame["grant_id"].as_str().unwrap().to_string();
        assert_eq!(
            claim(&b, &dev.service, &grant_id).await.status(),
            200,
            "claimed on pod B"
        );
    };
    let (body, ()) = tokio::join!(request_session(&a, &seeded, &dev.agent_id), target);
    assert_eq!(
        body["port"],
        json!(2223),
        "the caller on pod A resolves: {body}"
    );
}

/// The kill switch: `rc.ssh_via_service = false` sends every grant to the
/// worker, whatever the device says.
#[tokio::test]
async fn the_kill_switch_restores_the_worker_path() {
    let app = TestApp::spawn_with_settings(|s| s.rc.ssh_via_service = false).await;
    let seeded = app.seed_tenant("fr105switch").await;
    enable_org_ssh(&app, &seeded).await;
    let mut dev = device(
        &app,
        &seeded,
        "HOST-K1",
        "100.64.0.58",
        "daemon",
        "system",
        SERVICE_CAPABLE,
    )
    .await;
    let target = async {
        let frame = next_grant(&mut dev.ws).await;
        assert!(frame.get("via_service").is_none(), "{frame}");
        let grant_id = frame["grant_id"].as_str().unwrap().to_string();
        send_ack(&mut dev.ws, &grant_id, None).await;
    };
    let (body, ()) = tokio::join!(request_session(&app, &seeded, &dev.agent_id), target);
    assert_eq!(body["port"], json!(2222), "{body}");
}

/// FR-90 P3-8-2a — the claim is where an agent session's grant would reach a
/// service too old to hold it to one command, so it is the backstop:
/// - such a grant is not handed to a claim that does not say
///   `one_command=true` (the same 404 as every other refusal, audited
///   `claim_refused`), and is to one that does, the word with it;
/// - a person's grant is still handed to a claim that says nothing, which is
///   the positive control;
/// - what the service publishes of one command is what the record holds, and
///   false when it says nothing.
///
/// No policy admits a session before decision 22, so the session's grant is
/// written as `decide` would write it.
#[tokio::test]
async fn a_sessions_grant_is_claimed_only_by_a_service_that_holds_one_command() {
    use meshharbor_remote_control::models::SshPending;
    use meshharbor_services::dao::ssh_pending::SshPendingDao;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("sshonecmd").await;
    enable_org_ssh(&app, &seeded).await;
    let dev = device(
        &app,
        &seeded,
        "win-onecmd",
        "100.64.0.71",
        "daemon",
        "system",
        SERVICE_CAPABLE,
    )
    .await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let aid = ObjectId::parse_str(&dev.agent_id).unwrap();

    // The record holds what the service said of one command.
    let held = || async {
        let row = app
            .db
            .collection::<bson::Document>("agents")
            .find_one(bson::doc! { "_id": aid })
            .await
            .unwrap()
            .expect("the device's row");
        row.get_document("ssh_service")
            .expect("an endpoint")
            .get_bool("one_command")
            .unwrap_or(false)
    };
    assert!(!held().await, "published without the word");
    let republished = publish(
        &app,
        &dev.service,
        json!({ "host_pubkey": service_key(), "ceiling": "system", "one_command": true }),
    )
    .await;
    assert_eq!(republished.status(), 200);
    assert!(held().await, "published with it");

    let now = bson::DateTime::now();
    let at = |secs: i64| bson::DateTime::from_millis(now.timestamp_millis() + secs * 1000);
    let row = |grant_id: &str, one_command: bool| SshPending {
        id: None,
        grant_id: grant_id.to_string(),
        tenant_id: tid,
        agent_id: aid,
        public_key: session_key(),
        caller: "agent session 0 of someone (via a device)".to_string(),
        account_mode: "daemon".to_string(),
        expires_at_ms: (now.timestamp_millis() + 60_000) as u64,
        session_secs: 60,
        consent_mode: None,
        one_command,
        state: SshPending::PENDING.to_string(),
        created_at: now,
        claim_by: at(10),
        expires_at: at(120),
        claimed_at: None,
    };
    let dao = SshPendingDao::new(&app.db);
    let (person, session) = (ObjectId::new().to_hex(), ObjectId::new().to_hex());
    dao.insert(&row(&person, false)).await.unwrap();
    dao.insert(&row(&session, true)).await.unwrap();

    // A person's grant, to a claim that says nothing: handed over, as before.
    let claimed = claim(&app, &dev.service, &person).await;
    assert_eq!(claimed.status(), 200, "the positive control");
    let body: Value = claimed.json().await.unwrap();
    assert!(body.get("one_command").is_none(), "{body}");

    // A session's, to a claim that says nothing: refused, and audited.
    assert_eq!(claim(&app, &dev.service, &session).await.status(), 404);
    let rows = audit_rows(&app, &seeded).await;
    assert!(
        rows.iter()
            .any(|r| r["denied"] == json!("claim_refused") && r["grant_id"] == json!(session)),
        "the refused claim is audited: {rows:?}"
    );

    // …and to a claim that holds one command: handed over, with the word.
    let claimed = claim_holding_one_command(&app, &dev.service, &session).await;
    assert_eq!(claimed.status(), 200);
    let body: Value = claimed.json().await.unwrap();
    assert_eq!(body["one_command"], json!(true), "{body}");
}
