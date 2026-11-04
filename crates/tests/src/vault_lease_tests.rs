// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-3b — leases: a session's request for a value over its device's
//! control connection, answered with the value sealed to that device's key.
//!
//! Driven through a RAW agent socket that holds a vault key of its own, like
//! the hive tests' device: it starts a session through the real start route,
//! asks for values the way a daemon will, and opens what it is sent with its
//! own secret half. What these lock is the SERVER:
//!
//! - a lease is sealed to the key the device's hello carried, opens there,
//!   and is recorded (the lease row and the allow) before it is sent;
//! - it is believed only from the device the session's record places it on,
//!   at the record's fence, for a live session holding a vault role;
//! - Cedar's `secret:use` decides it, the guardrails included, with the
//!   device's facts read from its ROW;
//! - every refusal is one word, and none carries a value.

use std::time::Duration;

use age::secrecy::ExposeSecret;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bson::{Document, doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::tunnel_tests::{read_until, wait_agent_online};

pub(crate) type AgentWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A build that runs sessions and takes leases.
pub(crate) const TAKES_LEASES: &[&str] = &["exec", "hive", "vault"];
/// One that runs sessions and takes none.
pub(crate) const RUNS_HIVE: &[&str] = &["exec", "hive"];

pub(crate) struct Device {
    pub(crate) agent_id: String,
    pub(crate) ws: AgentWs,
    /// P3-3c — the agent token, to dial again as the same device.
    pub(crate) token: String,
    /// The device's vault key, as a daemon holds it.
    pub(crate) key: crypto_box::SecretKey,
}

/// A KEK made for the test, never written down.
pub(crate) fn fresh_kek() -> String {
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_string()
}

/// Hive and the vault on, with a KEK.
pub(crate) async fn lease_app() -> TestApp {
    let kek = fresh_kek();
    TestApp::spawn_with_settings(move |s| {
        s.modules.hive = true;
        s.modules.vault = true;
        s.vault.kek = kek;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

pub(crate) async fn enroll(
    app: &TestApp,
    t: &SeededTenant,
    machine: &str,
    os: &str,
) -> (String, String) {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", t.tenant_id),
            &t.admin.access_token,
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
            "machine_id": machine,
            "machine_name": machine,
            "os": os,
            "agent_version": "0.4.143",
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

/// Enroll and connect a device: `rpc` in its hello, and its vault key's
/// public half when `with_key`.
pub(crate) async fn device(
    app: &TestApp,
    t: &SeededTenant,
    machine: &str,
    os: &str,
    rpc: &[&str],
    with_key: bool,
) -> Device {
    let (agent_id, token) = enroll(app, t, machine, os).await;
    let key = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
    let url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut ws, _) = connect_async(&url).await.expect("agent ws connect");
    let mut hello = json!({
        "t": "rc:agent.hello",
        "machine_name": machine,
        "os": os,
        "agent_version": "0.4.143",
        "displays": [],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"], "has_input_permission": false,
            "supports_clipboard": false, "supports_file_transfer": false,
            "max_simultaneous_sessions": 1, "rpc": rpc,
        }
    });
    if with_key {
        hello["vault_key"] = json!(STANDARD.encode(key.public_key().as_bytes()));
    }
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    wait_agent_online(app, t, &agent_id).await;
    Device {
        agent_id,
        ws,
        token,
        key,
    }
}

pub(crate) async fn send(ws: &mut AgentWs, frame: Value) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

pub(crate) async fn post(app: &TestApp, t: &SeededTenant, path: &str, body: Value) -> (u16, Value) {
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}{path}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    (code, resp.json().await.unwrap_or(Value::Null))
}

/// A secret with one value; its id.
pub(crate) async fn secret(app: &TestApp, t: &SeededTenant, path: &str, value: &str) -> String {
    let (code, body) = post(
        app,
        t,
        "/vault/secret",
        json!({ "path": path, "kind": "static" }),
    )
    .await;
    assert_eq!(code, 201, "{body}");
    let id = body["id"].as_str().unwrap().to_string();
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/vault/secret/{id}/value", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "value": value }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    id
}

/// The organization's vault as these tests use it: a role `dev`, assumable
/// by anyone on any device, which may use what is under `db/`. Secrets
/// `db/main` (the value returned), `api/key` (outside `db/`) and `db/off`
/// (disabled).
pub(crate) async fn seed_vault(app: &TestApp, t: &SeededTenant) -> String {
    let (code, body) = post(app, t, "/vault/role", json!({ "name": "dev" })).await;
    assert_eq!(code, 201, "{body}");
    for (name, text) in [
        (
            "anyone-may-be-dev",
            r#"permit (principal, action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev");"#
                .to_string(),
        ),
        (
            "dev-uses-db",
            format!(
                r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"secret:use", resource in MeshHarbor::SecretFolder::"rrn:{}:secret:db");"#,
                t.tenant_slug
            ),
        ),
    ] {
        let (code, body) = post(app, t, "/vault/policy", json!({ "name": name, "text": text })).await;
        assert_eq!(code, 201, "{body}");
    }
    // Values made here, never written down.
    let value = format!("lease-canary-{}", ObjectId::new().to_hex());
    secret(app, t, "db/main", &value).await;
    secret(
        app,
        t,
        "api/key",
        &format!("other-{}", ObjectId::new().to_hex()),
    )
    .await;
    let off = secret(
        app,
        t,
        "db/off",
        &format!("off-{}", ObjectId::new().to_hex()),
    )
    .await;
    let resp = app
        .client
        .patch(app.url(&format!("/api/tenant/{}/vault/secret/{off}", t.tenant_id)))
        .header("Authorization", format!("Bearer {}", t.admin.access_token))
        .json(&json!({ "disabled": true }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    value
}

/// Start a session on `dev` (naming `role` when given), the device
/// answering the start; the session's id and fence.
pub(crate) async fn start(
    app: &TestApp,
    t: &SeededTenant,
    dev: &mut Device,
    folder: &str,
    role: Option<&str>,
) -> (String, u64) {
    let agent_id = dev.agent_id.clone();
    let mut body = json!({ "device_id": agent_id, "folder": folder });
    if let Some(r) = role {
        body["role"] = json!(r);
    }
    let caller = async {
        for _ in 0..40 {
            let (code, answer) = post(app, t, "/hive/session", body.clone()).await;
            assert_eq!(code, 200, "start");
            // The registration race the hive tests retry past.
            let racing = answer["outcome"] == "refused"
                && matches!(
                    answer["reason"].as_str(),
                    Some("device_offline" | "device_unsupported")
                );
            if !racing {
                return answer;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the Hub never recorded the device as running sessions");
    };
    let target = async {
        let frame = read_until(&mut dev.ws, "rc:hive.start")
            .await
            .expect("the device receives rc:hive.start");
        send(
            &mut dev.ws,
            json!({"t": "rc:hive.start_ack", "session_id": frame["session_id"],
                   "fence": frame["fence"], "account": "dev"}),
        )
        .await;
        frame
    };
    let (answer, frame) = tokio::join!(caller, target);
    assert_eq!(answer["outcome"], "accepted", "{answer}");
    (
        answer["session"]["id"].as_str().unwrap().to_string(),
        frame["fence"].as_u64().unwrap(),
    )
}

/// Ask for a lease; the vault's answer to that request.
pub(crate) async fn ask(dev: &mut Device, req_id: &str, mut frame: Value) -> Value {
    frame["t"] = json!("rc:vault.lease");
    frame["req_id"] = json!(req_id);
    if frame.get("mode").is_none() {
        frame["mode"] = json!("env");
    }
    if frame.get("ttl_secs").is_none() {
        frame["ttl_secs"] = json!(60);
    }
    send(&mut dev.ws, frame).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = tokio::time::timeout(left, dev.ws.next())
            .await
            .expect("no answer to the lease within 10 s")
            .expect("agent socket closed")
            .expect("agent socket error");
        if let Message::Text(text) = next {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let t = v["t"].as_str().unwrap_or_default();
            if (t == "rc:vault.leased" || t == "rc:vault.refused") && v["req_id"] == req_id {
                return v;
            }
        }
    }
}

pub(crate) fn refused(answer: &Value) -> &str {
    assert_eq!(answer["t"], "rc:vault.refused", "{answer}");
    answer["reason"].as_str().unwrap()
}

/// What a granted lease carries, opened with the device's own key.
pub(crate) fn opened(dev: &Device, answer: &Value) -> String {
    assert_eq!(answer["t"], "rc:vault.leased", "{answer}");
    let sealed = STANDARD.decode(answer["sealed"].as_str().unwrap()).unwrap();
    String::from_utf8(dev.key.unseal(&sealed).expect("the device opens its lease")).unwrap()
}

pub(crate) async fn rows(app: &TestApp, collection: &str, filter: Document) -> Vec<Document> {
    use futures::TryStreamExt;
    app.db
        .collection::<Document>(collection)
        .find(filter)
        .sort(doc! { "_id": 1 })
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap()
}

/// FR-90 P3-3b — a session holding a role leases a value its role is allowed:
/// sealed to the key its device's hello carried, opened there, clamped in
/// time, and recorded — the lease row and the allow — before it was sent.
/// What the role is not allowed, what is disabled, absent or valueless, and a
/// mode that releases no stored value, are each refused in one word.
#[tokio::test]
async fn a_session_leases_what_its_role_allows_sealed_to_its_device() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultlease").await;
    let value = seed_vault(&app, &t).await;
    let mut dev = device(&app, &t, "lease-host", "linux", TAKES_LEASES, true).await;
    let (sid, fence) = start(&app, &t, &mut dev, "/srv/a", Some("dev")).await;

    // Leased by path, sealed to this device's key.
    let before = bson::DateTime::now().timestamp_millis();
    let answer = ask(
        &mut dev,
        "r1",
        json!({ "session_id": sid, "fence": fence, "secret": "db/main" }),
    )
    .await;
    assert_eq!(opened(&dev, &answer), value);
    assert_eq!(answer["n"], 1, "{answer}");
    let expires = answer["expires_at_ms"].as_i64().unwrap();
    assert!(
        (before + 59_000..=bson::DateTime::now().timestamp_millis() + 61_000).contains(&expires),
        "{answer}"
    );
    let lease_id = answer["lease_id"].as_str().unwrap().to_string();
    assert!(
        !serde_json::to_string(&answer).unwrap().contains(&value),
        "the frame carries the value sealed, never in the clear"
    );

    // Recorded before it was sent: the lease row, and the allow naming it.
    let leases = rows(&app, "vault_leases", doc! {}).await;
    assert_eq!(leases.len(), 1);
    let row = &leases[0];
    assert_eq!(row.get_object_id("_id").unwrap().to_hex(), lease_id);
    assert_eq!(row.get_object_id("session_id").unwrap().to_hex(), sid);
    assert_eq!(
        row.get_object_id("device_id").unwrap().to_hex(),
        dev.agent_id
    );
    assert_eq!(
        row.get_str("sealed_to").unwrap(),
        STANDARD.encode(dev.key.public_key().as_bytes())
    );
    assert_eq!(row.get_str("mode").unwrap(), "env");
    let allows = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:use", "decision": "allow" },
    )
    .await;
    assert_eq!(allows.len(), 1);
    assert_eq!(
        allows[0].get_str("target").unwrap(),
        format!("lease:{lease_id}")
    );
    assert_eq!(allows[0].get_str("principal").unwrap(), "session");
    let request = allows[0].get_document("request").unwrap();
    assert_eq!(request.get_str("mode").unwrap(), "env");
    assert_eq!(request.get_i64("ttl_s").unwrap(), 60);
    assert_eq!(
        request
            .get_document("device")
            .unwrap()
            .get_str("os")
            .unwrap(),
        "linux",
        "the device's facts are its row's"
    );

    // Named by this organization's RRN; the TTL clamped both ways.
    let rrn = format!("rrn:{}:secret:db/main", t.tenant_slug);
    let short = ask(
        &mut dev,
        "r2",
        json!({ "session_id": sid, "fence": fence, "secret": rrn, "ttl_secs": 5 }),
    )
    .await;
    assert_eq!(opened(&dev, &short), value);
    let now = bson::DateTime::now().timestamp_millis();
    assert!(
        short["expires_at_ms"].as_i64().unwrap() <= now + 31_000,
        "{short}"
    );
    let long = ask(
        &mut dev,
        "r3",
        json!({ "session_id": sid, "fence": fence, "secret": "db/main", "ttl_secs": 999_999 }),
    )
    .await;
    assert!(
        long["expires_at_ms"].as_i64().unwrap()
            <= bson::DateTime::now().timestamp_millis() + 901_000,
        "{long}"
    );

    // Refusals, one word each.
    let base = json!({ "session_id": sid, "fence": fence });
    let with = |extra: Value| {
        let mut f = base.clone();
        for (k, v) in extra.as_object().unwrap() {
            f[k] = v.clone();
        }
        f
    };
    for (req_id, frame, word) in [
        ("x1", with(json!({ "secret": "api/key" })), "denied"),
        ("x2", with(json!({ "secret": "db/off" })), "disabled"),
        ("x3", with(json!({ "secret": "db/none" })), "no_secret"),
        (
            "x4",
            with(json!({ "secret": "rrn:someone-else:secret:db/main" })),
            "no_secret",
        ),
        (
            "x5",
            with(json!({ "secret": "db/main", "field": "password" })),
            "no_value",
        ),
        (
            "x6",
            with(json!({ "secret": "db/main", "mode": "identity" })),
            "bad_request",
        ),
        (
            "x7",
            json!({ "session_id": sid, "fence": fence + 1, "secret": "db/main" }),
            "stale_fence",
        ),
        (
            "x8",
            json!({ "session_id": ObjectId::new().to_hex(), "fence": fence, "secret": "db/main" }),
            "not_located",
        ),
    ] {
        let answer = ask(&mut dev, req_id, frame).await;
        assert_eq!(refused(&answer), word, "{req_id}: {answer}");
        assert!(answer.get("sealed").is_none(), "{answer}");
    }

    // The policy's deny is recorded with the request it decided; still the
    // one lease row per granted lease.
    let denies = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:use", "decision": "deny", "reason": "default_deny" },
    )
    .await;
    assert_eq!(denies.len(), 1, "{denies:?}");
    assert_eq!(
        denies[0]
            .get_document("request")
            .unwrap()
            .get_document("secret")
            .unwrap()
            .get_str("path")
            .unwrap(),
        "api/key"
    );
    assert_eq!(rows(&app, "vault_leases", doc! {}).await.len(), 3);
}

/// FR-90 P3-3b — a lease is believed only from the device the session runs
/// on: another device of the organization asking for it is refused, as is a
/// device that takes no leases, and a session that took no vault role holds
/// nothing in the vault. A session that is over is leased nothing.
#[tokio::test]
async fn a_lease_is_believed_only_from_the_device_that_runs_the_session() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultwho").await;
    // Four devices: past the free plan's three.
    app.db
        .collection::<Document>("tenants")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&t.tenant_id).unwrap() },
            doc! { "$set": { "plan": "pro" } },
        )
        .await
        .unwrap();
    seed_vault(&app, &t).await;
    let mut a = device(&app, &t, "lease-a", "linux", TAKES_LEASES, true).await;
    let (sid, fence) = start(&app, &t, &mut a, "/srv/a", Some("dev")).await;
    let frame = json!({ "session_id": sid, "fence": fence, "secret": "db/main" });

    // Another device of the organization, asking for a's session.
    let mut b = device(&app, &t, "lease-b", "linux", TAKES_LEASES, true).await;
    assert_eq!(
        refused(&ask(&mut b, "b1", frame.clone()).await),
        "not_located"
    );

    // Devices that take no leases: no verb, or the verb and no key.
    let mut plain = device(&app, &t, "lease-plain", "linux", RUNS_HIVE, true).await;
    let (psid, pfence) = start(&app, &t, &mut plain, "/srv/p", Some("dev")).await;
    let pframe = json!({ "session_id": psid, "fence": pfence, "secret": "db/main" });
    assert_eq!(refused(&ask(&mut plain, "p1", pframe).await), "unsupported");
    let mut keyless = device(&app, &t, "lease-keyless", "linux", TAKES_LEASES, false).await;
    let (ksid, kfence) = start(&app, &t, &mut keyless, "/srv/k", Some("dev")).await;
    let kframe = json!({ "session_id": ksid, "fence": kfence, "secret": "db/main" });
    assert_eq!(
        refused(&ask(&mut keyless, "k1", kframe).await),
        "unsupported"
    );

    // A session that took no role.
    let (nsid, nfence) = start(&app, &t, &mut a, "/srv/n", None).await;
    let nframe = json!({ "session_id": nsid, "fence": nfence, "secret": "db/main" });
    assert_eq!(refused(&ask(&mut a, "n1", nframe).await), "no_role");

    // The role's session leases, until it is over.
    assert_eq!(
        ask(&mut a, "a1", frame.clone()).await["t"],
        "rc:vault.leased"
    );
    app.db
        .collection::<Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "status": "ended" } },
        )
        .await
        .unwrap();
    assert_eq!(refused(&ask(&mut a, "a2", frame).await), "ended");

    // Exactly one lease was released, to a.
    let leases = rows(&app, "vault_leases", doc! {}).await;
    assert_eq!(leases.len(), 1);
    assert_eq!(
        leases[0].get_object_id("device_id").unwrap().to_hex(),
        a.agent_id
    );
}

/// FR-90 P3-3b — the seeded guardrails decide a lease too, from the device's
/// ROW: a Windows device's session is never handed a value to materialize,
/// and is leased the same value for a proxy.
#[tokio::test]
async fn a_windows_device_is_leased_values_only_for_a_proxy() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultwin").await;
    let value = seed_vault(&app, &t).await;
    let mut win = device(&app, &t, "lease-win", "windows", TAKES_LEASES, true).await;
    let (sid, fence) = start(&app, &t, &mut win, "C:\\src\\a", Some("dev")).await;
    for mode in ["env", "file", "exec"] {
        let answer = ask(
            &mut win,
            &format!("w-{mode}"),
            json!({ "session_id": sid, "fence": fence, "secret": "db/main", "mode": mode }),
        )
        .await;
        assert_eq!(refused(&answer), "denied", "{mode}: {answer}");
    }
    // P3-5a — toward an upstream the secret names, as every proxy is.
    name_audience(&app, &t, "db/main", "db.internal:5432").await;
    let answer = ask(
        &mut win,
        "w-proxy",
        json!({ "session_id": sid, "fence": fence, "secret": "db/main", "mode": "proxy",
                "audience": "db.internal:5432" }),
    )
    .await;
    assert_eq!(opened(&win, &answer), value);
    let guarded = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:use", "decision": "deny" },
    )
    .await;
    assert_eq!(guarded.len(), 3);
    for row in &guarded {
        assert!(
            row.get_str("reason").unwrap().contains("windows"),
            "{row:?}"
        );
    }
}

/// P3-5a — `audience` as the only upstream the secret at `path` names.
pub(crate) async fn name_audience(app: &TestApp, t: &SeededTenant, path: &str, audience: &str) {
    let found = rows(app, "vault_secrets", doc! { "path": path }).await;
    let id = found[0].get_object_id("_id").unwrap().to_hex();
    let resp = app
        .client
        .patch(app.url(&format!("/api/tenant/{}/vault/secret/{id}", t.tenant_id)))
        .header("Authorization", format!("Bearer {}", t.admin.access_token))
        .json(&json!({ "audiences": [audience] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
}

/// FR-90 P3-5a — a `proxy` lease is released only toward an upstream its
/// secret names in `audiences`, exactly: the daemon authenticates with the
/// value to whatever the lease names, so anything else is refused by the
/// `proxy-only-named-audiences` guardrail, recorded with its request.
#[tokio::test]
async fn a_proxy_lease_reaches_only_an_upstream_its_secret_names() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultproxy").await;
    let value = seed_vault(&app, &t).await;
    name_audience(&app, &t, "db/main", "db.internal:5432").await;
    let mut dev = device(&app, &t, "lease-proxy", "linux", TAKES_LEASES, true).await;
    let (sid, fence) = start(&app, &t, &mut dev, "/srv/proxy", Some("dev")).await;
    let frame = |audience: &str| {
        json!({ "session_id": sid, "fence": fence, "secret": "db/main", "mode": "proxy",
                "audience": audience })
    };
    let ok = ask(&mut dev, "p-ok", frame("db.internal:5432")).await;
    assert_eq!(opened(&dev, &ok), value);
    for (i, audience) in ["evil.example:5432", "db.internal:6432", "db.internal", ""]
        .iter()
        .enumerate()
    {
        let answer = ask(&mut dev, &format!("p-{i}"), frame(audience)).await;
        assert_eq!(refused(&answer), "denied", "{audience:?}: {answer}");
    }
    let denied = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:use", "decision": "deny" },
    )
    .await;
    assert_eq!(denied.len(), 4);
    for row in &denied {
        assert_eq!(
            row.get_str("reason").unwrap(),
            "guardrail:proxy-only-named-audiences",
            "{row:?}"
        );
        assert!(row.contains_key("request"), "replayable: {row:?}");
    }
}

/// FR-90 P3-4c-1 — an `exec` lease is released only for a program its
/// secret names in `exec_allow`, by the bare name a device asks with as the
/// lease's audience. Any other program, a path, or none is refused by the
/// `exec-only-allowed-programs` guardrail, recorded with its request.
#[tokio::test]
async fn an_exec_lease_reaches_only_a_program_its_secret_names() {
    let app = lease_app().await;
    let t = app.seed_tenant("vaultexec").await;
    let value = seed_vault(&app, &t).await;
    let main = rows(&app, "vault_secrets", doc! { "path": "db/main" }).await;
    let id = main[0].get_object_id("_id").unwrap().to_hex();
    let resp = app
        .client
        .patch(app.url(&format!("/api/tenant/{}/vault/secret/{id}", t.tenant_id)))
        .header("Authorization", format!("Bearer {}", t.admin.access_token))
        .json(&json!({ "exec_allow": ["psql", "kubectl"] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let mut dev = device(&app, &t, "lease-exec", "linux", TAKES_LEASES, true).await;
    let (sid, fence) = start(&app, &t, &mut dev, "/srv/exec", Some("dev")).await;
    let frame = |audience: &str| {
        json!({ "session_id": sid, "fence": fence, "secret": "db/main", "mode": "exec",
                "audience": audience })
    };
    let ok = ask(&mut dev, "e-psql", frame("psql")).await;
    assert_eq!(opened(&dev, &ok), value);
    for (i, audience) in ["curl", "/usr/bin/psql", ""].iter().enumerate() {
        let answer = ask(&mut dev, &format!("e-{i}"), frame(audience)).await;
        assert_eq!(refused(&answer), "denied", "{audience:?}: {answer}");
    }
    let denied = rows(
        &app,
        "vault_audit",
        doc! { "action": "secret:use", "decision": "deny" },
    )
    .await;
    assert_eq!(denied.len(), 3);
    for row in &denied {
        assert_eq!(
            row.get_str("reason").unwrap(),
            "guardrail:exec-only-allowed-programs",
            "{row:?}"
        );
        assert!(row.contains_key("request"), "replayable: {row:?}");
    }
}
