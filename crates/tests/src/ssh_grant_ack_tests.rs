// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-83 — an SSH grant is confirmed before the caller is told to dial.
//!
//! Driven through a RAW agent socket rather than the `roomlerd` library, for
//! two reasons. The test crate builds the agent without `ssh-server`, so the
//! real one could not take a grant at all; and what these lock is the
//! SERVER's ordering, which only a peer that decides exactly when — and
//! whether — it answers can observe.
//!
//! The assertions read the response JSON only, never a type FR-83 added, so
//! this file also compiles against the server as it was before FR-83. That is
//! how the ordering and gate-4 tests were shown to FAIL there: the caller was
//! answered with an address at once, before — and regardless of — anything
//! the device said.

use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use meshharbor_remote_control::models::NodeRef;
use meshharbor_services::dao::overlay_network::OverlayNetworkDao;
use meshharbor_services::dao::overlay_node::{NewOverlayNode, OverlayNodeDao};
use serde_json::{Value, json};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::tunnel_tests::{enroll_agent, wait_agent_online};

pub(crate) type AgentWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// The caller's session key. A throwaway: its private half was deleted the
/// moment it was generated, and nothing in these tests ever dials.
pub(crate) const SESSION_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHTipQcil2m8O1ZIOjcIA7lWXSa5hiqg4doutBYcFZ2F fr83-test";

/// What a current `ssh-server` build advertises…
const ACKING: &[&str] = &["exec", "ssh", "ssh-consent", "ssh-grant-ack"];
/// …and what every build before FR-83 did.
const PRE_ACK: &[&str] = &["exec", "ssh", "ssh-consent"];

/// How long the device sits on a grant before acknowledging it — far longer
/// than a same-host round trip, so an answer that did not wait for the ack
/// cannot arrive after it by accident.
const HOLD: Duration = Duration::from_millis(1500);

/// A device on the mesh with a raw control socket, SSH allowed by org and
/// policy, and everything else left to the test.
pub(crate) struct Device {
    pub(crate) agent_id: String,
    pub(crate) ws: AgentWs,
}

pub(crate) async fn enable_org_ssh(app: &TestApp, seeded: &SeededTenant) {
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

/// Enrol, give the device an overlay address, open its policy, connect a raw
/// socket advertising `rpc`, and wait until the server holds it.
pub(crate) async fn device(
    app: &TestApp,
    seeded: &SeededTenant,
    machine: &str,
    ip: &str,
    rpc: &[&str],
) -> Device {
    let (agent_id, token) = enroll_agent(app, seeded, machine, machine).await;

    // Seeded directly, as `handle_overlay_join` would: the grant needs an
    // address to answer with, and the join itself is exercised elsewhere.
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

    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/agent/{agent_id}/ssh-policy",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({ "mode": "on", "account_mode": "daemon" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "policy: {:?}", resp.status());

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
            "os": "linux",
            "agent_version": "0.4.101",
            "displays": [],
            "caps": {
                "hw_encoders": [],
                "codecs": ["h264"],
                "has_input_permission": true,
                "supports_clipboard": false,
                "supports_file_transfer": false,
                "max_simultaneous_sessions": 4,
                "rpc": rpc,
            }
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    wait_agent_online(app, seeded, &agent_id).await;
    Device { agent_id, ws }
}

/// `POST …/agent/{id}/ssh` as the org's admin.
///
/// The row reads online a moment BEFORE the Hub has recorded the agent's
/// capabilities (`update_hello` precedes `register_agent`), and a request in
/// that window is refused as unsupported. That refusal happens before any
/// grant is minted, so retrying it is safe — and it is the ONLY refusal
/// retried here.
async fn request_session(app: &TestApp, seeded: &SeededTenant, agent_id: &str) -> Value {
    for _ in 0..10 {
        let body: Value = app
            .auth_post(
                &format!("/api/tenant/{}/agent/{agent_id}/ssh", seeded.tenant_id),
                &seeded.admin.access_token,
            )
            .json(&json!({ "public_key": SESSION_KEY }))
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
    panic!("the Hub never recorded the agent's ssh capability");
}

/// Read frames until the server pushes a grant; returns its id.
pub(crate) async fn next_grant(ws: &mut AgentWs) -> String {
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
                return v["grant_id"].as_str().expect("grant_id").to_string();
            }
        }
    }
}

pub(crate) async fn send_ack(ws: &mut AgentWs, grant_id: &str, refused: Option<&str>) {
    let mut ack = json!({ "t": "rc:ssh.grant_ack", "grant_id": grant_id });
    if let Some(r) = refused {
        ack["refused"] = json!(r);
    }
    ws.send(Message::Text(ack.to_string().into()))
        .await
        .unwrap();
}

/// AC1 — the ordering itself. The device holds its ack for [`HOLD`]; the
/// caller's answer must not arrive before the ack was sent. Before FR-83 the
/// answer arrived at once, ~1.5 s ahead of it: this is #1597 in miniature, a
/// caller told to dial into a device that had not confirmed anything.
#[tokio::test]
async fn the_caller_is_answered_only_after_the_device_confirms() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr83order").await;
    enable_org_ssh(&app, &seeded).await;
    let mut dev = device(&app, &seeded, "fr83-order", "100.64.0.31", ACKING).await;

    let caller = async {
        let body = request_session(&app, &seeded, &dev.agent_id).await;
        (body, Instant::now())
    };
    let target = async {
        let grant_id = next_grant(&mut dev.ws).await;
        tokio::time::sleep(HOLD).await;
        let acked_at = Instant::now();
        send_ack(&mut dev.ws, &grant_id, None).await;
        acked_at
    };
    let ((body, answered_at), acked_at) = tokio::join!(caller, target);

    assert!(
        answered_at >= acked_at,
        "the caller was answered {:?} BEFORE the device confirmed the grant — \
         a caller told to dial into a device that may not have it yet (#1597)",
        acked_at - answered_at
    );
    assert_eq!(
        body["address"], "100.64.0.31",
        "confirmed ⇒ where to dial: {body}"
    );
    assert!(body["error"].is_null(), "{body}");
}

/// AC2 — gate 4 reaches the caller. Before FR-83 the device's refusal lived
/// only in its own log and the caller got an address — then a bare
/// `Connection refused`, since nothing intercepts the port when SSH is off:
/// the deterministic negative control.
#[tokio::test]
async fn a_device_with_ssh_switched_off_answers_the_caller_as_gate_4() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr83gate4").await;
    enable_org_ssh(&app, &seeded).await;
    let mut dev = device(&app, &seeded, "fr83-gate4", "100.64.0.32", ACKING).await;

    let target = async {
        let grant_id = next_grant(&mut dev.ws).await;
        send_ack(&mut dev.ws, &grant_id, Some("ssh_disabled")).await;
    };
    let (body, ()) = tokio::join!(request_session(&app, &seeded, &dev.agent_id), target);

    assert!(
        body["address"].is_null(),
        "a device that refused the grant must not be offered as a place to dial: {body}"
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("switched off on the device itself"),
        "the caller must be told it was gate 4, not a key problem: {body}"
    );

    // And the decision log names it too — a refusal nobody can find later is
    // the same support ticket, one step removed.
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
    let rows = audit["items"].as_array().cloned().unwrap_or_default();
    assert!(
        rows.iter().any(|r| r["denied"] == "agent_disabled"),
        "the refusal must be audited as agent_disabled: {audit}"
    );
}

/// AC3 + AC5 — silence from the target is `unconfirmed`, never an address,
/// even when ANOTHER device in the tenant acknowledges the target's grant id
/// on its own socket. Grant ids are ObjectIds, structured, not secret; if an
/// ack were honoured from any socket, the race would be back for whoever
/// bothered.
#[tokio::test]
async fn silence_from_the_target_is_unconfirmed_even_when_another_device_acks() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr83silent").await;
    enable_org_ssh(&app, &seeded).await;
    let mut target = device(&app, &seeded, "fr83-target", "100.64.0.33", ACKING).await;
    let mut stranger = device(&app, &seeded, "fr83-stranger", "100.64.0.34", ACKING).await;

    let started = Instant::now();
    let impostor = async {
        let grant_id = next_grant(&mut target.ws).await;
        // The target says nothing. A different device claims the grant.
        send_ack(&mut stranger.ws, &grant_id, None).await;
    };
    let (body, ()) = tokio::join!(request_session(&app, &seeded, &target.agent_id), impostor);
    let waited = started.elapsed();

    assert!(
        body["address"].is_null(),
        "an ack from another device's socket must confirm nothing: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("did not confirm the grant")),
        "{body}"
    );
    assert!(
        waited >= Duration::from_secs(9),
        "refused after {waited:?} — the bound is 10 s, so this was not the wait timing out"
    );
}

/// AC4 — an agent from before FR-83 never acks, and must be answered exactly
/// as before: at once, with an address. Waiting on it would add the whole
/// bound to every session on every older device, and then refuse them all.
#[tokio::test]
async fn an_agent_without_the_verb_is_answered_at_once() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr83legacy").await;
    enable_org_ssh(&app, &seeded).await;
    let dev = device(&app, &seeded, "fr83-legacy", "100.64.0.35", PRE_ACK).await;

    let started = Instant::now();
    let body = request_session(&app, &seeded, &dev.agent_id).await;
    let took = started.elapsed();

    assert_eq!(body["address"], "100.64.0.35", "{body}");
    assert!(
        took < Duration::from_secs(3),
        "a pre-FR-83 agent was made to wait {took:?} for an ack it never sends"
    );
    drop(dev);
}
