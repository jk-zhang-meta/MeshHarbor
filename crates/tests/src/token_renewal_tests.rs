// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-103 — device credentials renew themselves, and a removal ends every
//! token a device was ever given. The server's half:
//! - a device buys a fresh agent token with the one it holds, idempotently,
//!   and the old one keeps working until its own `exp` (no rotation in v1);
//! - a token up to `RENEWAL_GRACE_SECS` past its `exp` still renews, on the
//!   renew route only, so a device that slept through its anniversary
//!   recovers by itself; an older one does not;
//! - removing a device advances its `token_gen`, so after the same machine
//!   re-enrolls and revives the row, every token minted before the removal
//!   is refused, at the HTTP routes, the agent socket, DERP and the renew
//!   route alike;
//! - the same for a `mh` tunnel client;
//! - both kill switches; and the device list's "credential expires".
//!
//! And the device's half (P2), the real `meshharbord` code against this server:
//! a due token is renewed and saved before use; a device that was off across
//! its expiry renews inside the grace and comes back by itself; a token
//! re-enrolled on disk is taken up without a restart; a secondary org renews
//! against its own server and into its own `[[orgs]]` entry; and a server
//! that answers the renew route with 404 changes nothing.

use crate::fixtures::test_app::TestApp;
use crate::tunnel_tests::wait_agent_online;
use futures::{SinkExt, StreamExt};
use jsonwebtoken::{EncodingKey, Header};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

/// Enroll a device with a fresh single-use token. Returns its id and agent
/// token.
async fn enroll(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    machine_id: &str,
) -> (String, String) {
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
            "agent_version": "0.4.134",
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

async fn remove(app: &TestApp, seeded: &crate::fixtures::seed::SeededTenant, agent_id: &str) {
    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "remove the device");
}

async fn renew(app: &TestApp, token: &str) -> reqwest::Response {
    app.auth_post("/api/agent/self/renew", token)
        .send()
        .await
        .unwrap()
}

/// An `AuthAgent` route: the device's own view of its org.
async fn self_devices(app: &TestApp, token: &str) -> u16 {
    app.auth_get("/api/agent/self/devices", token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// The status an upgrade to `path` answers with this token: 101 when the
/// socket is accepted, the HTTP status when it is refused.
async fn upgrade_status(app: &TestApp, path: &str, token: &str) -> u16 {
    let url = format!(
        "ws://{}{path}?token={}&role=agent",
        app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    match connect_async(&url).await {
        Ok(_) => 101,
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => resp.status().as_u16(),
        Err(e) => panic!("{path} upgrade failed oddly: {e}"),
    }
}

/// A token signed with the test server's own secret: what an old build, or
/// the calendar, would have produced. `exp_offset` is relative to now;
/// `generation` None leaves the claim out entirely (a pre-FR-103 token).
fn forge_agent_token(
    app: &TestApp,
    agent_id: &str,
    tenant_id: &str,
    exp_offset_secs: i64,
    generation: Option<u32>,
) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "sub": agent_id,
        "tenant_id": tenant_id,
        "iat": now - 400 * 24 * 3600,
        "exp": now + exp_offset_secs,
        "iss": app.settings.jwt.issuer,
        "token_type": "agent",
    });
    if let Some(g) = generation {
        claims["gen"] = json!(g);
    }
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(app.settings.jwt.secret.as_bytes()),
    )
    .unwrap()
}

/// A device renews its own token. The new one is accepted everywhere, and the
/// old one keeps working until its own `exp`: renewal does not rotate, so a
/// lost response costs nothing.
#[tokio::test]
async fn a_device_renews_its_own_token() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103renew").await;
    let (_agent_id, token) = enroll(&app, &seeded, "m-fr103-renew").await;
    // A JWT is deterministic: minted in the same second with the same claims,
    // the renewal would be byte-identical to the enrollment's token.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let resp = renew(&app, &token).await;
    assert_eq!(resp.status(), 200, "renew");
    let body: Value = resp.json().await.unwrap();
    let fresh = body["agent_token"].as_str().unwrap().to_string();
    assert!(fresh != token, "a fresh token, minted in a later second");
    let expires = chrono::DateTime::parse_from_rfc3339(body["expires_at"].as_str().unwrap())
        .expect("expires_at is RFC 3339");
    assert!(
        expires > chrono::Utc::now() + chrono::Duration::days(300),
        "about a year out: {expires}"
    );

    assert_eq!(self_devices(&app, &fresh).await, 200, "the new token works");
    assert_eq!(upgrade_status(&app, "/ws", &fresh).await, 101);
    assert_eq!(
        self_devices(&app, &token).await,
        200,
        "and so does the old one"
    );
    // Renewing again, with either, is fine: idempotent.
    assert_eq!(renew(&app, &token).await.status(), 200);
    assert_eq!(renew(&app, &fresh).await.status(), 200);
}

/// A token up to `RENEWAL_GRACE_SECS` past its `exp` renews; every other
/// route refuses it, and a token older than the grace does not renew.
#[tokio::test]
async fn an_expired_token_renews_within_the_grace_only() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103grace").await;
    let (agent_id, _) = enroll(&app, &seeded, "m-fr103-grace").await;
    let tid = seeded.tenant_id.to_string();
    let day = 24 * 3600;

    let lapsed = forge_agent_token(&app, &agent_id, &tid, -30 * day, Some(0));
    assert_eq!(
        self_devices(&app, &lapsed).await,
        401,
        "expired everywhere else"
    );
    assert_eq!(upgrade_status(&app, "/ws", &lapsed).await, 401);
    let resp = renew(&app, &lapsed).await;
    assert_eq!(
        resp.status(),
        200,
        "but within the grace on the renew route"
    );
    let fresh: Value = resp.json().await.unwrap();
    assert_eq!(
        self_devices(&app, fresh["agent_token"].as_str().unwrap()).await,
        200
    );

    let too_old = forge_agent_token(&app, &agent_id, &tid, -91 * day, Some(0));
    assert_eq!(renew(&app, &too_old).await.status(), 401, "past the grace");
}

/// Removing a device ends every token it held. The same machine enrolling
/// again revives the row in place (the same id), and only a token minted
/// after the removal is accepted, at every place an agent token is checked.
/// Before FR-103 the revived row accepted the old token again.
#[tokio::test]
async fn a_removal_ends_every_earlier_token() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103removal").await;
    let (agent_id, old) = enroll(&app, &seeded, "m-fr103-removal").await;
    assert_eq!(self_devices(&app, &old).await, 200);

    remove(&app, &seeded, &agent_id).await;
    let (again, new) = enroll(&app, &seeded, "m-fr103-removal").await;
    assert_eq!(again, agent_id, "the same row is revived");

    // The old token: refused at every site, the renew route included.
    assert_eq!(
        self_devices(&app, &old).await,
        401,
        "an AuthAgent route must refuse a token from before the removal"
    );
    assert_eq!(
        upgrade_status(&app, "/ws", &old).await,
        401,
        "the agent socket"
    );
    assert_eq!(upgrade_status(&app, "/derp", &old).await, 401, "DERP");
    assert_eq!(renew(&app, &old).await.status(), 401, "the renew route");

    // The new one: accepted.
    assert_eq!(self_devices(&app, &new).await, 200);
    assert_eq!(upgrade_status(&app, "/ws", &new).await, 101);
    assert_eq!(renew(&app, &new).await.status(), 200);
}

/// A token minted before FR-103 carries no `gen` claim. It must keep working
/// on a device that was never removed, or deploying FR-103 would refuse the
/// whole fleet.
#[tokio::test]
async fn a_token_from_before_fr103_still_works() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103legacy").await;
    let (agent_id, _) = enroll(&app, &seeded, "m-fr103-legacy").await;
    let legacy = forge_agent_token(&app, &agent_id, &seeded.tenant_id.to_string(), 3600, None);
    assert_eq!(self_devices(&app, &legacy).await, 200);
    assert_eq!(upgrade_status(&app, "/ws", &legacy).await, 101);
    assert_eq!(renew(&app, &legacy).await.status(), 200);
}

/// A quarantined or removed device cannot renew: the renew route checks the
/// row exactly as `AuthAgent` does.
#[tokio::test]
async fn a_quarantined_or_removed_device_cannot_renew() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103refuse").await;
    let (agent_id, token) = enroll(&app, &seeded, "m-fr103-refuse").await;
    let oid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            bson::doc! { "_id": oid },
            bson::doc! { "$set": { "status": "quarantined" } },
        )
        .await
        .unwrap();
    assert_eq!(renew(&app, &token).await.status(), 401, "quarantined");
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            bson::doc! { "_id": oid },
            bson::doc! { "$set": { "status": "offline" } },
        )
        .await
        .unwrap();
    assert_eq!(renew(&app, &token).await.status(), 200, "released");
    remove(&app, &seeded, &agent_id).await;
    assert_eq!(renew(&app, &token).await.status(), 401, "removed");
}

/// #2463 — a device with NO row (FR-51's reaper hard-deletes an ephemeral
/// one) is refused at the agent socket with the 401 the HTTP routes already
/// give it, BEFORE the upgrade. It used to upgrade and drop with no frame, and
/// the daemon reconnected every minute forever. A live device still upgrades,
/// and a removed (tombstoned) one still upgrades to hear its typed goodbye.
#[tokio::test]
async fn a_device_with_no_row_is_refused_before_the_upgrade() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("i2463gone").await;
    let (agent_id, token) = enroll(&app, &seeded, "m-2463-reaped").await;
    assert_eq!(
        upgrade_status(&app, "/ws", &token).await,
        101,
        "a live device upgrades"
    );
    // The reaper's hard delete (`hard_delete_ephemeral`): no tombstone left.
    let oid = bson::oid::ObjectId::parse_str(&agent_id).unwrap();
    let gone = app
        .db
        .collection::<bson::Document>("agents")
        .delete_one(bson::doc! { "_id": oid })
        .await
        .unwrap();
    assert_eq!(gone.deleted_count, 1, "the row is gone");
    assert_eq!(
        upgrade_status(&app, "/ws", &token).await,
        401,
        "no row: refused before the upgrade"
    );
    assert_eq!(
        self_devices(&app, &token).await,
        401,
        "the HTTP routes agree"
    );

    // A removed device keeps its tombstone, upgrades, and hears its typed
    // goodbye (`rc:goodbye AgentDeleted`, exit 7): unchanged.
    let (removed_id, removed_token) = enroll(&app, &seeded, "m-2463-removed").await;
    remove(&app, &seeded, &removed_id).await;
    let url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        removed_token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut ws, _) = connect_async(&url)
        .await
        .expect("a tombstone still upgrades to its goodbye");
    let goodbye = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Text(t) = msg
                && let Ok(v) = serde_json::from_str::<Value>(&t)
                && v["t"] == "rc:goodbye"
            {
                return Some(v);
            }
        }
        None
    })
    .await
    .expect("a frame within 10 s")
    .expect("the typed goodbye, not a bare close");
    assert_eq!(goodbye["reason"], "agent_deleted", "{goodbye}");
}

/// The kill switches: `rc.token_renewal = false` answers 404 on both renew
/// routes; `rc.token_generation_check = false` accepts a pre-removal token
/// again, which is the behaviour before FR-103.
#[tokio::test]
async fn the_kill_switches() {
    let off = TestApp::spawn_with_settings(|s| s.rc.token_renewal = false).await;
    let seeded = off.seed_tenant("fr103off").await;
    let (_, token) = enroll(&off, &seeded, "m-fr103-off").await;
    assert_eq!(renew(&off, &token).await.status(), 404);
    assert_eq!(
        off.auth_post("/api/tunnel-client/renew", &token)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let lax = TestApp::spawn_with_settings(|s| s.rc.token_generation_check = false).await;
    let seeded = lax.seed_tenant("fr103lax").await;
    let (agent_id, old) = enroll(&lax, &seeded, "m-fr103-lax").await;
    remove(&lax, &seeded, &agent_id).await;
    let _ = enroll(&lax, &seeded, "m-fr103-lax").await;
    assert_eq!(
        self_devices(&lax, &old).await,
        200,
        "with the check off, a revived row accepts its old token as before"
    );
}

/// The device list shows when the token a device connected with expires.
#[tokio::test]
async fn the_device_list_shows_when_a_credential_expires() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103exp").await;
    let (agent_id, token) = enroll(&app, &seeded, "m-fr103-exp").await;

    let url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        token
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D")
    );
    let (mut ws, _) = connect_async(&url).await.expect("agent ws");
    ws.send(Message::Text(
        json!({
            "t": "rc:agent.hello",
            "machine_name": "m-fr103-exp",
            "os": "linux",
            "agent_version": "0.4.134",
            "displays": [],
            "caps": {
                "hw_encoders": [], "codecs": ["h264"], "has_input_permission": true,
                "supports_clipboard": false, "supports_file_transfer": false,
                "max_simultaneous_sessions": 1, "rpc": [],
            },
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    wait_agent_online(&app, &seeded, &agent_id).await;

    let mut expires = None;
    for _ in 0..20 {
        let row: Value = app
            .auth_get(
                &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(s) = row["token_expires_at"].as_str() {
            expires = Some(s.to_string());
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let expires = expires.expect("token_expires_at appears once the device connects");
    let expires = chrono::DateTime::parse_from_rfc3339(&expires)
        .or_else(|_| chrono::DateTime::parse_from_str(&expires, "%+"))
        .expect("a timestamp");
    assert!(expires > chrono::Utc::now() + chrono::Duration::days(300));
}

/// The device list follows a renewal at once. A device keeps its socket after
/// renewing and presents the new token only at its next connect, which on a
/// live socket can be weeks away, so the renewal itself records the expiry.
#[tokio::test]
async fn a_renewal_shows_in_the_device_list_without_a_reconnect() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103stamp").await;
    let (agent_id, token) = enroll(&app, &seeded, "m-fr103-stamp").await;

    let resp = renew(&app, &token).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let parse = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .or_else(|_| chrono::DateTime::parse_from_str(s, "%+"))
            .expect("a timestamp")
    };
    let renewed = parse(body["expires_at"].as_str().unwrap());

    let row: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let shown = parse(
        row["token_expires_at"]
            .as_str()
            .expect("the renewal is on the record before any connect"),
    );
    assert!(
        (shown - renewed).num_seconds().abs() <= 1,
        "the list shows {shown}, the renewal said {renewed}"
    );
}

/// A `mh` tunnel client renews its own token, and removing it ends every
/// earlier token, as for an agent. The roster route now checks the row too.
#[tokio::test]
async fn a_tunnel_client_renews_and_a_removal_ends_its_tokens() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103tunnel").await;

    async fn enroll_client(
        app: &TestApp,
        seeded: &crate::fixtures::seed::SeededTenant,
        machine_id: &str,
    ) -> (String, String) {
        let et: Value = app
            .auth_post(
                &format!(
                    "/api/tenant/{}/tunnel-client/enroll-token",
                    seeded.tenant_id
                ),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let e: Value = app
            .client
            .post(app.url("/api/tunnel-client/enroll"))
            .json(&json!({
                "enrollment_token": et["enrollment_token"].as_str().unwrap(),
                "machine_id": machine_id,
                "machine_name": machine_id,
                "os": "linux",
                "client_version": "0.4.134",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        (
            e["tunnel_client_id"].as_str().unwrap().to_string(),
            e["tunnel_client_token"].as_str().unwrap().to_string(),
        )
    }
    let roster = |token: String| {
        let req = app.auth_get("/api/tunnel-client/agents", &token);
        async move { req.send().await.unwrap().status().as_u16() }
    };
    let renew_client = |token: String| {
        let req = app.auth_post("/api/tunnel-client/renew", &token);
        async move { req.send().await.unwrap() }
    };

    let (client_id, old) = enroll_client(&app, &seeded, "m-fr103-cli").await;
    let resp = renew_client(old.clone()).await;
    assert_eq!(resp.status(), 200, "a client renews");
    let fresh: Value = resp.json().await.unwrap();
    assert_eq!(
        roster(fresh["tunnel_client_token"].as_str().unwrap().to_string()).await,
        200
    );
    assert_eq!(roster(old.clone()).await, 200, "no rotation");

    let removed = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/tunnel-client/{}",
                seeded.tenant_id, client_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(removed.status().is_success(), "remove the client");
    assert_eq!(
        roster(old.clone()).await,
        401,
        "the roster checks the row now"
    );

    let (again, new) = enroll_client(&app, &seeded, "m-fr103-cli").await;
    assert_eq!(again, client_id, "the same row is revived");
    assert_eq!(
        roster(old.clone()).await,
        401,
        "a token from before the removal"
    );
    assert_eq!(renew_client(old).await.status(), 401);
    assert_eq!(roster(new.clone()).await, 200);
    assert_eq!(renew_client(new).await.status(), 200);
}

// ---------------------------------------------------------------------------
// FR-103 P2 — the DEVICE's half: the real `meshharbord` renewal code against
// this server.
// ---------------------------------------------------------------------------

const DAY: i64 = 24 * 3600;

/// These tests poll; the in-process agent shares 127.0.0.1 and the default
/// limiter's one bucket with them.
async fn polling_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await
}

/// Poll the device row until it reads online. Tolerant of a read that fails:
/// that is "not yet".
async fn wait_online(app: &TestApp, seeded: &crate::fixtures::seed::SeededTenant, agent_id: &str) {
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let row: Value = match app
            .auth_get(
                &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
        {
            Ok(resp) => resp.json().await.unwrap_or(Value::Null),
            Err(_) => Value::Null,
        };
        if row["status"].as_str() == Some("online") {
            return;
        }
    }
    panic!("agent {agent_id} never came online");
}

fn config_services(path: &std::path::Path) -> meshharbord::remote_config::RemoteConfigServices {
    meshharbord::remote_config::RemoteConfigServices::new(
        path.to_path_buf(),
        std::sync::Arc::new(tokio::sync::Mutex::new(())),
        false,
        false,
    )
}

/// A device renews once its token is due, saves the new one before using it,
/// and the old one keeps working (no rotation). A fresh year-long token is
/// not due, and nothing is asked.
#[tokio::test]
async fn a_device_renews_before_its_token_expires() {
    use meshharbord::token_renewal::{self, Settings};
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr103due").await;
    let cfg = crate::agent_tests::enrol_via_agent_lib(&app, &seeded, "m-fr103-due", "due").await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    meshharbord::config::save(&path, &cfg).unwrap();
    let services = config_services(&path);
    let enrollment = token_renewal::Enrollment {
        label: "primary".into(),
        server_url: cfg.server_url.clone(),
        tenant_id: cfg.tenant_id.clone(),
        agent_id: cfg.agent_id.clone(),
        token: meshharbord::token_slot::TokenSlot::new(cfg.agent_token.clone()),
    };
    let now = chrono::Utc::now().timestamp();

    let look = token_renewal::check_once(&enrollment, &services, Settings::default(), now).await;
    assert!(
        enrollment.token.get() == cfg.agent_token,
        "a fresh token is not due"
    );
    assert_eq!(
        look,
        token_renewal::Look {
            next: Settings::default().interval,
            failed: false
        }
    );

    // A token minted in the same second as the enrollment's is byte-identical.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let due_now = Settings {
        horizon: Some(Duration::from_secs(400 * 86_400)),
        ..Settings::default()
    };
    token_renewal::check_once(&enrollment, &services, due_now, now).await;
    let renewed = enrollment.token.get();
    assert!(renewed != cfg.agent_token, "renewed once due");
    assert!(
        meshharbord::config::load(&path).unwrap().agent_token == renewed,
        "saved before it was used"
    );
    assert_eq!(self_devices(&app, &renewed).await, 200);
    assert_eq!(
        self_devices(&app, &cfg.agent_token).await,
        200,
        "no rotation: the old token keeps working"
    );
}

/// The case FR-103 exists for: a device that was off across its token's
/// expiry is refused at the socket, renews inside the server's grace, saves
/// the new token, and comes back online with no hands on the machine. Before
/// P2 it backed off for good and asked for a re-enrollment.
#[tokio::test]
async fn a_lapsed_device_renews_in_the_grace_and_comes_back() {
    let app = polling_app().await;
    let seeded = app.seed_tenant("fr103lapsed").await;
    let mut cfg =
        crate::agent_tests::enrol_via_agent_lib(&app, &seeded, "m-fr103-lapsed", "lapsed").await;
    let lapsed = forge_agent_token(&app, &cfg.agent_id, &cfg.tenant_id, -30 * DAY, Some(0));
    assert_eq!(
        upgrade_status(&app, "/ws", &lapsed).await,
        401,
        "refused as it is"
    );
    cfg.agent_token = lapsed.clone();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    meshharbord::config::save(&path, &cfg).unwrap();

    let slot = meshharbord::token_slot::TokenSlot::new(lapsed.clone());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = crate::agent_tests::spawn_agent_signaling_on(
        meshharbord::signaling::OrgCtx::primary(slot.clone()),
        cfg.clone(),
        path.clone(),
        stop_rx,
    );
    wait_online(&app, &seeded, &cfg.agent_id).await;

    let in_use = slot.get();
    assert!(in_use != lapsed, "a renewed token is in use");
    assert!(
        meshharbord::config::load(&path).unwrap().agent_token == in_use,
        "and it is the one on disk"
    );
    assert_eq!(self_devices(&app, &in_use).await, 200);
    let _ = stop_tx.send(true);
    task.abort();
}

/// A device removed and enrolled again (`meshharbord re-enroll`) while its
/// daemon kept running: the running token is now refused (the removal
/// advanced the generation), and the daemon switches to the token the
/// re-enrollment wrote to its config file, without a restart.
#[tokio::test]
async fn a_token_re_enrolled_on_disk_is_used_without_a_restart() {
    let app = polling_app().await;
    let seeded = app.seed_tenant("fr103reenrolled").await;
    let first =
        crate::agent_tests::enrol_via_agent_lib(&app, &seeded, "m-fr103-again", "again").await;
    remove(&app, &seeded, &first.agent_id).await;
    let again =
        crate::agent_tests::enrol_via_agent_lib(&app, &seeded, "m-fr103-again", "again").await;
    assert_eq!(again.agent_id, first.agent_id, "the same row is revived");
    assert_eq!(
        upgrade_status(&app, "/ws", &first.agent_token).await,
        401,
        "the token from before the removal is refused"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    meshharbord::config::save(&path, &again).unwrap();

    // The daemon still runs on the token it started with.
    let slot = meshharbord::token_slot::TokenSlot::new(first.agent_token.clone());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = crate::agent_tests::spawn_agent_signaling_on(
        meshharbord::signaling::OrgCtx::primary(slot.clone()),
        first.clone(),
        path,
        stop_rx,
    );
    wait_online(&app, &seeded, &first.agent_id).await;
    assert!(
        slot.get() == again.agent_token,
        "the re-enrolled token, adopted from the file"
    );
    let _ = stop_tx.send(true);
    task.abort();
}

/// A device in two orgs (multi-org) holds a token from each org's server. The
/// secondary org's token renews against the SECONDARY's server and is saved
/// into that org's `[[orgs]]` entry. Renewing it at the primary's server is
/// refused (that server does not know the device), and saving it over the
/// primary's token would cut the primary off at the next restart.
#[tokio::test]
async fn a_secondary_org_renews_against_its_own_server() {
    use meshharbord::token_renewal::{self, Settings};
    let primary = TestApp::spawn().await;
    let secondary = TestApp::spawn().await;
    let seeded_a = primary.seed_tenant("fr103orga").await;
    let seeded_b = secondary.seed_tenant("fr103orgb").await;
    let mut cfg =
        crate::agent_tests::enrol_via_agent_lib(&primary, &seeded_a, "m-fr103-orgs", "orgs").await;
    let org_b =
        crate::agent_tests::enrol_via_agent_lib(&secondary, &seeded_b, "m-fr103-orgs", "orgs")
            .await;
    // The control: only its own server renews the secondary's token.
    assert_ne!(
        renew(&primary, &org_b.agent_token).await.status(),
        200,
        "the primary's server must not renew a token it never issued"
    );
    cfg.orgs.push(meshharbord::config::OrgEntry {
        label: "org-b".into(),
        server_url: org_b.server_url.clone(),
        ws_url: None,
        agent_token: org_b.agent_token.clone(),
        agent_id: org_b.agent_id.clone(),
        tenant_id: org_b.tenant_id.clone(),
        enabled: true,
        overlay_mode: meshharbord::config::OrgOverlayMode::Off,
        overlay_wg_secret_key: None,
        overlay_wg_key_epoch: 0,
        overlay_advertised_routes: Vec::new(),
        overlay_exit_node_enabled: false,
        advertise_routes: Vec::new(),
        netstack_socks_port: None,
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    meshharbord::config::save(&path, &cfg).unwrap();
    let services = config_services(&path);
    // The secondary org's own enrollment, as its signalling loop builds it.
    let enrollment = token_renewal::Enrollment {
        label: "org-b".into(),
        server_url: org_b.server_url.clone(),
        tenant_id: org_b.tenant_id.clone(),
        agent_id: org_b.agent_id.clone(),
        token: meshharbord::token_slot::TokenSlot::new(org_b.agent_token.clone()),
    };
    // A token minted in the same second as the enrollment's is byte-identical.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let due_now = Settings {
        horizon: Some(Duration::from_secs(400 * 86_400)),
        ..Settings::default()
    };
    token_renewal::check_once(
        &enrollment,
        &services,
        due_now,
        chrono::Utc::now().timestamp(),
    )
    .await;
    let renewed = enrollment.token.get();
    assert!(renewed != org_b.agent_token, "renewed, by its own server");
    assert_eq!(self_devices(&secondary, &renewed).await, 200);
    let back = meshharbord::config::load(&path).unwrap();
    assert!(
        back.orgs[0].agent_token == renewed,
        "saved into its own [[orgs]] entry"
    );
    assert!(
        back.agent_token == cfg.agent_token,
        "the primary's token is untouched"
    );
    assert_eq!(
        self_devices(&primary, &back.agent_token).await,
        200,
        "and the primary still connects with it"
    );
}

/// A server older than FR-103, or one with `rc.token_renewal` off, answers the
/// renew route with 404. The device carries on exactly as before: the token it
/// has, nothing written to its config, no failure backoff (the next look is on
/// the normal schedule), and the token still accepted.
#[tokio::test]
async fn an_old_server_answering_404_changes_nothing() {
    use meshharbord::token_renewal::{self, Settings};
    let old = TestApp::spawn_with_settings(|s| s.rc.token_renewal = false).await;
    let seeded = old.seed_tenant("fr103oldsrv").await;
    let cfg =
        crate::agent_tests::enrol_via_agent_lib(&old, &seeded, "m-fr103-oldsrv", "oldsrv").await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    meshharbord::config::save(&path, &cfg).unwrap();
    let before = std::fs::read_to_string(&path).unwrap();
    let services = config_services(&path);
    let enrollment = token_renewal::Enrollment {
        label: "primary".into(),
        server_url: cfg.server_url.clone(),
        tenant_id: cfg.tenant_id.clone(),
        agent_id: cfg.agent_id.clone(),
        token: meshharbord::token_slot::TokenSlot::new(cfg.agent_token.clone()),
    };
    let due_now = Settings {
        horizon: Some(Duration::from_secs(400 * 86_400)),
        ..Settings::default()
    };
    let look = token_renewal::check_once(
        &enrollment,
        &services,
        due_now,
        chrono::Utc::now().timestamp(),
    )
    .await;
    assert_eq!(
        look,
        token_renewal::Look {
            next: Settings::default().interval,
            failed: false
        },
        "no failure backoff: the next look is on the normal schedule"
    );
    assert!(
        enrollment.token.get() == cfg.agent_token,
        "the token it had"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "nothing written to the config"
    );
    assert_eq!(
        self_devices(&old, &cfg.agent_token).await,
        200,
        "and the token is still accepted"
    );
}
