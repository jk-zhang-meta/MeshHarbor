// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Integration tests for the remote-control subsystem.
//!
//! These exercise the REST flow (enroll → list → delete), the JWT audience
//! separation (enrollment vs agent tokens), and the WS handshake that marks an
//! agent row `online` after `rc:agent.hello`.
//!
//! Full SDP/ICE round-trip tests belong in a follow-up once the native agent
//! binary exists — here we verify the surface the browser + agent talk to.

use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ────────────────────────────────────────────────────────────────────────────
// REST: enrollment flow
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn enroll_token_requires_auth() {
    let app = TestApp::spawn().await;
    let resp = app
        .client
        .post(app.url("/api/tenant/000000000000000000000000/agent/enroll-token"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn enroll_agent_full_round_trip() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcflow1").await;

    // 1. Admin issues an enrollment token.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let et: Value = resp.json().await.unwrap();
    let enrollment_token = et["enrollment_token"].as_str().unwrap().to_string();
    assert_eq!(et["expires_in"].as_u64().unwrap(), 600);
    assert!(!et["jti"].as_str().unwrap().is_empty());

    // 2. Agent exchanges it for a long-lived agent token.
    let resp = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": enrollment_token,
            "machine_id": "mach-rcflow1-A",
            "machine_name": "Goran's Laptop",
            "os": "linux",
            "agent_version": "0.1.0",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let ej: Value = resp.json().await.unwrap();
    let agent_token = ej["agent_token"].as_str().unwrap();
    let agent_id = ej["agent_id"].as_str().unwrap();
    assert_eq!(ej["tenant_id"].as_str().unwrap(), seeded.tenant_id);
    assert!(!agent_token.is_empty());
    assert_eq!(agent_id.len(), 24); // hex ObjectId

    // 3. Re-enrolling the same machine_id returns the same agent row.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    let et2: Value = resp.json().await.unwrap();
    let resp = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": et2["enrollment_token"].as_str().unwrap(),
            "machine_id": "mach-rcflow1-A",
            "machine_name": "Goran's Laptop (reinstall)",
            "os": "linux",
            "agent_version": "0.1.1",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let ej2: Value = resp.json().await.unwrap();
    assert_eq!(ej2["agent_id"].as_str().unwrap(), agent_id);
}

/// Regression: soft-deleting an agent and re-enrolling the same `machine_id`
/// must rehydrate the existing row (clearing `deleted_at`, refreshing name /
/// os / agent_version) instead of failing with E11000 against the unique
/// `(tenant_id, machine_id)` index. Pre-fix, the unfiltered index treated the
/// soft-deleted tombstone as a duplicate and the second enrollment 409'd.
#[tokio::test]
async fn enroll_revives_soft_deleted_agent() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcrevive").await;

    let (first_agent_id, _) = enroll_helper(&app, &seeded, "mach-rcrevive-A", "corp3").await;

    // Admin soft-deletes the agent.
    app.auth_delete(
        &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, first_agent_id),
        &seeded.admin.access_token,
    )
    .send()
    .await
    .unwrap()
    .error_for_status()
    .unwrap();

    // Re-enroll the same machine with a NEW name — must succeed (200) and
    // return the same _id.
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
    let resp = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": "mach-rcrevive-A",
            "machine_name": "corp3_laptop",
            "os": "windows",
            "agent_version": "0.2.7",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let revived: Value = resp.json().await.unwrap();
    assert_eq!(revived["agent_id"].as_str().unwrap(), first_agent_id);

    // Admin list now shows the revived row with the new name + version.
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"].as_str().unwrap(), first_agent_id);
    assert_eq!(items[0]["name"].as_str().unwrap(), "corp3_laptop");
    assert_eq!(items[0]["agent_version"].as_str().unwrap(), "0.2.7");
}

#[tokio::test]
async fn enroll_rejects_bogus_token() {
    let app = TestApp::spawn().await;
    let resp = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": "not-a-jwt",
            "machine_id": "mach-x",
            "machine_name": "x",
            "os": "linux",
            "agent_version": "0.1.0",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn agent_token_rejected_on_enroll_endpoint() {
    // The agent token (aud=agent) must not be usable as an enrollment token —
    // verifies JWT audience separation in AuthService.
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcflow2").await;

    // Enroll one agent to obtain a real agent_token.
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
            "machine_id": "mach-cross",
            "machine_name": "cross",
            "os": "linux",
            "agent_version": "0.1.0",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_token = ej["agent_token"].as_str().unwrap();

    // Now try to use the agent_token as an enrollment token — must fail.
    let resp = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": agent_token,
            "machine_id": "mach-cross-2",
            "machine_name": "cross2",
            "os": "linux",
            "agent_version": "0.1.0",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

// ────────────────────────────────────────────────────────────────────────────
// REST: agent CRUD
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_agents_shows_enrolled_agent() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rclist").await;

    let (_, _) = enroll_helper(&app, &seeded, "mach-rclist-A", "laptop").await;

    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/agent", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"].as_str().unwrap(), "laptop");
    // No live WS yet → is_online must be false.
    assert!(!items[0]["is_online"].as_bool().unwrap());
}

#[tokio::test]
async fn delete_agent_removes_from_list() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcdel").await;

    let (agent_id, _) = enroll_helper(&app, &seeded, "mach-rcdel-A", "A").await;

    app.auth_delete(
        &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
        &seeded.admin.access_token,
    )
    .send()
    .await
    .unwrap()
    .error_for_status()
    .unwrap();

    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 0);
}

/// #1821 — removal is FINAL on every per-device route, not only in the
/// listing. `find_by_id_in_tenant` filtered `{_id, tenant_id}` and nothing
/// else, so after `DELETE` the tombstone still answered `GET` with the whole
/// row and took every per-device WRITE — a stale page holding the id kept
/// editing a device that no longer existed. The lookup every per-device route
/// sits on is live-scoped now, and so are the admin setters underneath it.
///
/// Negative control (recorded on the PR): with the `deleted_at` predicate
/// taken back out of the lookup, this fails at "GET of a removed device"
/// with 200; with it taken out of the setters' filter, at "a setter must
/// not land on a tombstone".
#[tokio::test]
async fn a_removed_device_is_a_404_on_every_per_device_route() {
    use bson::{Bson, doc, oid::ObjectId};
    use reqwest::Method;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcgone").await;
    let admin = seeded.admin.access_token.clone();
    let (agent_id, _) = enroll_helper(&app, &seeded, "mach-rcgone-A", "Gone box").await;
    let base = format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id);
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let aid = ObjectId::parse_str(&agent_id).unwrap();
    let agents = app.db.collection::<bson::Document>("agents");

    // Every per-device route this locks, with a body each accepts: the
    // writes (settings, the three policies, the config intent, the update
    // order), a session start (exec) and a read that is about the device's
    // future (join-targets). The listing-style audit reads are NOT here —
    // `recording-activity/{aid}` deliberately still resolves a removed device.
    let routes: Vec<(&str, Method, String, Value)> = vec![
        (
            "PUT settings",
            Method::PUT,
            base.clone(),
            json!({ "tags": ["after"] }),
        ),
        (
            "PUT exec-policy",
            Method::PUT,
            format!("{base}/exec-policy"),
            json!({}),
        ),
        (
            "PUT ssh-policy",
            Method::PUT,
            format!("{base}/ssh-policy"),
            json!({}),
        ),
        (
            "PUT desired-config",
            Method::PUT,
            format!("{base}/desired-config"),
            json!({}),
        ),
        (
            "PUT peer-relay-policy",
            Method::PUT,
            format!("{base}/peer-relay-policy"),
            json!({}),
        ),
        (
            "POST update",
            Method::POST,
            format!("{base}/update"),
            json!({}),
        ),
        (
            "POST exec",
            Method::POST,
            format!("{base}/exec"),
            json!({ "command": "true" }),
        ),
        (
            "GET join-targets",
            Method::GET,
            format!("{base}/join-targets"),
            Value::Null,
        ),
    ];
    let call = |method: Method, path: &str, body: &Value| {
        let mut req = app
            .client
            .request(method, app.url(path))
            .header("Authorization", format!("Bearer {admin}"));
        if !body.is_null() {
            req = req.json(body);
        }
        req.send()
    };

    // The positive control: for a LIVE device none of these is a 404 — so a
    // 404 after the removal is the lookup's answer, not a route that never
    // existed or a body the parser refused before the lookup ran.
    for (name, method, path, body) in &routes {
        let status = call(method.clone(), path, body)
            .await
            .unwrap()
            .status()
            .as_u16();
        assert_ne!(status, 404, "control: {name} must resolve a live device");
    }
    let resp = app.auth_get(&base, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "control: GET of a live device");
    // The LAST write before the removal — what the tombstone must still say
    // after every write below it has been refused (the control loop above
    // wrote `after` while the device was live, which is why this comes last).
    let resp = app
        .auth_put(&base, &admin)
        .json(&json!({ "tags": ["before"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "control: settings write on a live device"
    );

    // Remove it.
    let resp = app.auth_delete(&base, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);

    // The row is a TOMBSTONE, not gone — the case the bug lived in.
    let row = agents
        .find_one(doc! { "_id": aid })
        .await
        .unwrap()
        .expect("a permanent device tombstones in place");
    let removed_at = match row.get("deleted_at") {
        Some(Bson::DateTime(at)) => *at,
        other => panic!("tombstone must carry a removal time, got {other:?}"),
    };

    // GET: 404, exactly like a bogus id.
    let resp = app.auth_get(&base, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404, "GET of a removed device");

    // Every other per-device route: 404.
    for (name, method, path, body) in &routes {
        let status = call(method.clone(), path, body)
            .await
            .unwrap()
            .status()
            .as_u16();
        assert_eq!(status, 404, "{name} on a removed device");
    }

    // …and none of those writes reached the tombstone.
    let row = agents.find_one(doc! { "_id": aid }).await.unwrap().unwrap();
    assert_eq!(
        row.get_array("tags").unwrap(),
        &vec![Bson::String("before".into())],
        "the settings write must not land on the tombstone"
    );

    // The setters are live-scoped on their own, not only behind the routes'
    // lookup ("a gate applies at every entry point, or it is a courtesy"):
    // reached directly, one still refuses the tombstone.
    let fleet = app.state.fleet();
    assert!(
        !fleet
            .agents
            .set_tags(tid, aid, &["dao".into()])
            .await
            .unwrap(),
        "a setter must not land on a tombstone"
    );
    // The removal time is written once: a repeat tombstoning is a no-op.
    assert!(!fleet.agents.soft_delete(tid, aid).await.unwrap());
    let row = agents.find_one(doc! { "_id": aid }).await.unwrap().unwrap();
    assert_eq!(row.get_datetime("deleted_at").unwrap(), &removed_at);
    assert_eq!(
        row.get_array("tags").unwrap(),
        &vec![Bson::String("before".into())]
    );

    // A repeat DELETE is a 404 — the same answer the listing gives, and the
    // one that leaves the state alone (re-finding the tombstone would re-run
    // the cascade and re-stamp the removal time).
    let resp = app.auth_delete(&base, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404, "a repeat DELETE");

    // The two views agree: gone from the listing too.
    let list: Value = app
        .auth_get(&format!("/api/tenant/{}/agent", seeded.tenant_id), &admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 0);
}

/// #1821 — the live predicate is `deleted_at: null`, which is null OR
/// ABSENT: a row that never carried the field was never tombstoned, and it is
/// the predicate the listing uses, so the two views agree by construction.
/// The `{ "$type": "null" }` spelling belongs to the partial unique indexes;
/// in this lookup it would 404 a live device whose field is missing, on
/// every per-device route at once. Locked so a later "tidy" cannot do that.
#[tokio::test]
async fn a_live_device_whose_deleted_at_field_is_absent_is_still_live() {
    use bson::{doc, oid::ObjectId};

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcabsent").await;
    let admin = &seeded.admin.access_token;
    let (agent_id, _) = enroll_helper(&app, &seeded, "mach-rcabsent-A", "Absent box").await;
    let aid = ObjectId::parse_str(&agent_id).unwrap();
    let base = format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id);

    app.db
        .collection::<bson::Document>("agents")
        .update_one(doc! { "_id": aid }, doc! { "$unset": { "deleted_at": "" } })
        .await
        .unwrap();

    let resp = app.auth_get(&base, admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "GET: absent is live");
    let resp = app
        .auth_put(&base, admin)
        .json(&json!({ "tags": ["still-here"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "PUT: absent is live");
    let list: Value = app
        .auth_get(&format!("/api/tenant/{}/agent", seeded.tenant_id), admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        list["items"].as_array().unwrap().len(),
        1,
        "the listing agrees"
    );
}

#[tokio::test]
async fn get_missing_agent_returns_404() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rc404").await;

    let resp = app
        .auth_get(
            &format!(
                "/api/tenant/{}/agent/000000000000000000000000",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn turn_credentials_returns_stun_fallback() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcturn").await;

    let resp = app
        .auth_get("/api/turn/credentials", &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    let servers = json["ice_servers"].as_array().unwrap();
    assert!(!servers.is_empty());
    // Default test settings have no TURN shared_secret → only STUN is returned.
    let first_url = servers[0]["urls"][0].as_str().unwrap();
    assert!(
        first_url.starts_with("stun:"),
        "first ICE server should be STUN; got {first_url}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// WebSocket: agent handshake marks row online
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agent_hello_marks_status_online() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcws").await;

    let (agent_id, agent_token) = enroll_helper(&app, &seeded, "mach-rcws-A", "WS laptop").await;

    // Connect WS as agent.
    let ws_url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        urlencode(&agent_token)
    );
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connect");

    // Send rc:agent.hello.
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "WS laptop",
        "os": "linux",
        "agent_version": "0.1.0",
        "displays": [{
            "index": 0,
            "name": "eDP-1",
            "width_px": 1920,
            "height_px": 1080,
            "scale": 1.0,
            "primary": true,
        }],
        "caps": {
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 2,
        }
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();

    // Give the server a moment to process the hello + update Mongo.
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let resp: Value = app
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
        if resp["status"].as_str() == Some("online") {
            assert!(resp["is_online"].as_bool().unwrap());
            assert_eq!(resp["agent_version"].as_str().unwrap(), "0.1.0");
            // Drain one message just to make sure we can still read — there
            // should be none queued, but the next `next()` may time out which
            // is fine.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(50), ws.next()).await;
            return;
        }
    }
    panic!("agent row never transitioned to online");
}

#[tokio::test]
async fn agent_ws_rejects_user_token() {
    // ?role=agent with a user JWT must be rejected — verifies the WS upgrade
    // honours audience checks rather than accepting any valid JWT.
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcws2").await;

    let ws_url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        urlencode(&seeded.admin.access_token)
    );
    let err = connect_async(&ws_url).await;
    assert!(
        err.is_err(),
        "user JWT must not be accepted for agent role; got Ok"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Phase Y.3: preferred_transport on rc:session.request flows controller → agent
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rc_session_request_forwards_preferred_transport_to_agent() {
    // The browser advertises `preferred_transport: data-channel-vp9-444` on
    // the rc:session.request payload (Phase Y.3 — see
    // ui/src/composables/useRemoteControl.ts). The server's Hub forwards
    // the field verbatim to the agent inside the rc:request envelope so
    // the agent can intersect it with its own AgentCaps.transports and
    // pick a video transport. This test locks the relay path: any
    // future regression that drops the field on the way through will
    // surface here.
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcprefxport").await;

    // Enroll + connect the agent so the Hub knows about it. Caps don't
    // matter for this test — the relay forwards `preferred_transport`
    // unconditionally; intersection happens on the agent side.
    let (agent_id, agent_token) =
        enroll_helper(&app, &seeded, "mach-rcprefxport-A", "Y.3 agent").await;
    let agent_ws_url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        urlencode(&agent_token)
    );
    let (mut agent_ws, _) = connect_async(&agent_ws_url).await.expect("agent ws");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "Y.3 agent",
        "os": "linux",
        "agent_version": "0.1.0",
        "displays": [{
            "index": 0, "name": "x", "width_px": 800, "height_px": 600,
            "scale": 1.0, "primary": true,
        }],
        "caps": {
            "hw_encoders": [],
            "codecs": ["h264"],
            "has_input_permission": false,
            "supports_clipboard": false,
            "supports_file_transfer": false,
            "max_simultaneous_sessions": 1,
            "transports": ["data-channel-vp9-444"],
        }
    });
    agent_ws
        .send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();

    // Controller WS — uses the admin's user JWT (no `role` query param).
    let ctrl_ws_url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&seeded.admin.access_token)
    );
    let (mut ctrl_ws, _) = connect_async(&ctrl_ws_url).await.expect("controller ws");

    // Drain any startup frames the controller WS might emit (e.g.
    // initial presence). Best-effort timeout — many tenants emit
    // nothing.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), ctrl_ws.next()).await;

    // Kick off the session with the new field set.
    let req = json!({
        "t": "rc:session.request",
        "agent_id": agent_id,
        "permissions": "VIEW",
        "preferred_transport": "data-channel-vp9-444",
    });
    ctrl_ws
        .send(Message::Text(req.to_string().into()))
        .await
        .unwrap();

    // Read agent-side messages until we see `rc:request` carrying the
    // forwarded preferred_transport, or hit the deadline.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut saw_request = false;
    while tokio::time::Instant::now() < deadline && !saw_request {
        let msg = match tokio::time::timeout(std::time::Duration::from_millis(500), agent_ws.next())
            .await
        {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        let Message::Text(text) = msg else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v.get("t").and_then(|x| x.as_str()) == Some("rc:request") {
            // Lock the field name + value: a typo or accidental rename
            // server-side would silently break the agent's negotiation
            // logic.
            assert_eq!(
                v.get("preferred_transport").and_then(|x| x.as_str()),
                Some("data-channel-vp9-444"),
                "rc:request must forward preferred_transport verbatim; got {v}"
            );
            saw_request = true;
        }
    }
    assert!(
        saw_request,
        "agent never received rc:request with preferred_transport"
    );
}

#[tokio::test]
async fn rc_session_request_omits_preferred_transport_when_unset() {
    // Older browsers (and the default code path) don't include the
    // `preferred_transport` field. The relay must NOT inject a
    // default value — the agent's negotiation logic distinguishes
    // None ("any transport") from Some("webrtc-video") and the wire
    // format uses serde `skip_serializing_if = "Option::is_none"` to
    // express that. Lock the absence on the wire so a future
    // refactor that helpfully fills in defaults regresses here.
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcprefxport2").await;

    let (agent_id, agent_token) =
        enroll_helper(&app, &seeded, "mach-rcprefxport-B", "Y.3 default agent").await;
    let agent_ws_url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        urlencode(&agent_token)
    );
    let (mut agent_ws, _) = connect_async(&agent_ws_url).await.expect("agent ws");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "Y.3 default agent",
        "os": "linux",
        "agent_version": "0.1.0",
        "displays": [{
            "index": 0, "name": "x", "width_px": 800, "height_px": 600,
            "scale": 1.0, "primary": true,
        }],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"],
            "has_input_permission": false, "supports_clipboard": false,
            "supports_file_transfer": false, "max_simultaneous_sessions": 1,
        }
    });
    agent_ws
        .send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();

    let ctrl_ws_url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&seeded.admin.access_token)
    );
    let (mut ctrl_ws, _) = connect_async(&ctrl_ws_url).await.expect("controller ws");
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), ctrl_ws.next()).await;

    // Same shape as the previous test, sans preferred_transport.
    let req = json!({
        "t": "rc:session.request",
        "agent_id": agent_id,
        "permissions": "VIEW",
    });
    ctrl_ws
        .send(Message::Text(req.to_string().into()))
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut saw_request = false;
    while tokio::time::Instant::now() < deadline && !saw_request {
        let msg = match tokio::time::timeout(std::time::Duration::from_millis(500), agent_ws.next())
            .await
        {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        let Message::Text(text) = msg else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v.get("t").and_then(|x| x.as_str()) == Some("rc:request") {
            assert!(
                v.get("preferred_transport").is_none(),
                "rc:request must omit preferred_transport when unset; got {v}"
            );
            saw_request = true;
        }
    }
    assert!(
        saw_request,
        "agent never received rc:request — server may have rejected the request"
    );
}

/// The agent listing must return the device's stored exec + SSH policies.
///
/// Regression, and the failure mode is worse than a blank field: both policy
/// dialogs PUT the WHOLE shape, and both build their draft as
/// `{...closedDefault, ...(agent.ssh_policy ?? {})}`. With the policies absent
/// from the listing, a dialog reopened after any page load shows the closed
/// default, and the next save REPLACES the stored policy with what is on
/// screen — so an admin who re-enables SSH silently drops an
/// `allowed_user_ids` restriction, widening the device from "these people" to
/// "anyone holding SSH_DEVICE", and resets `account_mode` from whatever was
/// chosen back to the default.
///
/// The hex assertions are load-bearing too: serialising the stored model
/// directly would render `allowed_user_ids` as `[{"$oid": …}]`, which no
/// client here parses (the same reason `SshAuditRow` / `ExecAuditRow` exist).
#[tokio::test]
async fn agent_listing_returns_the_stored_exec_and_ssh_policies() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcpolicy").await;
    let (agent_id, _token) = enroll_helper(&app, &seeded, "mach-rcpolicy-A", "Policy Box").await;
    let admin_id = seeded.admin.id.clone();

    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/agent/{}/exec-policy",
                seeded.tenant_id, agent_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({
            "mode": "on",
            "can_originate": true,
            "allowed_user_ids": [admin_id],
            "consent_mode": "auto",
            "shells": ["bash"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "exec-policy PUT");

    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/agent/{}/ssh-policy",
                seeded.tenant_id, agent_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({
            "mode": "on",
            "can_originate": true,
            "allowed_user_ids": [admin_id],
            "account_mode": "daemon",
            // `auto` rather than a prompt policy: a freshly enrolled row has
            // no capabilities yet, and the server rightly refuses a prompt
            // policy an agent would ignore.
            "consent_mode": "auto",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "ssh-policy PUT");

    let listing: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // ⚠️ The listing is `{"items": [...]}` — an `["agents"]` lookup silently
    // yields null and every assertion below would pass vacuously.
    let row = listing["items"]
        .as_array()
        .expect("listing must have items")
        .iter()
        .find(|a| a["id"].as_str() == Some(agent_id.as_str()))
        .expect("enrolled agent must be listed");

    let exec = &row["exec_policy"];
    assert_eq!(exec["mode"].as_str(), Some("on"), "exec mode: {row}");
    assert_eq!(exec["can_originate"].as_bool(), Some(true));
    assert_eq!(exec["consent_mode"].as_str(), Some("auto"));
    assert_eq!(
        exec["allowed_user_ids"].as_array().map(Vec::as_slice),
        Some([Value::String(admin_id.clone())].as_slice()),
        "allowed_user_ids must be hex strings, not extended JSON: {exec}"
    );
    assert_eq!(
        exec["shells"].as_array().map(Vec::as_slice),
        Some([Value::String("bash".into())].as_slice())
    );

    let ssh = &row["ssh_policy"];
    assert_eq!(ssh["mode"].as_str(), Some("on"), "ssh mode: {row}");
    assert_eq!(ssh["can_originate"].as_bool(), Some(true));
    assert_eq!(ssh["account_mode"].as_str(), Some("daemon"));
    assert_eq!(ssh["consent_mode"].as_str(), Some("auto"));
    assert_eq!(
        ssh["allowed_user_ids"].as_array().map(Vec::as_slice),
        Some([Value::String(admin_id)].as_slice()),
        "allowed_user_ids must be hex strings, not extended JSON: {ssh}"
    );
}

/// A device nobody has configured must report NO policy — not the model's
/// default one.
///
/// This is the counterpart to the test above and it is a security assertion,
/// not tidiness. `SshPolicy::default()` names `account_mode: daemon`
/// (SYSTEM / root), while the dialog's own closed default is `console_user`
/// precisely so that turning SSH on without reading the account selector
/// cannot hand out a root shell. If the listing shipped the model default,
/// the dialog would spread it over its own and pre-select `daemon` for every
/// unconfigured device in the fleet — re-creating the exact hazard the
/// dialog's default exists to remove.
///
/// The stored model genuinely cannot tell "never configured" from "explicitly
/// saved as all-defaults", so absent is the honest answer for that shape.
#[tokio::test]
async fn an_unconfigured_device_reports_no_policy_rather_than_a_root_default() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("rcpolicy2").await;
    let (agent_id, _token) = enroll_helper(&app, &seeded, "mach-rcpolicy-B", "Fresh Box").await;

    let listing: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = listing["items"]
        .as_array()
        .expect("listing must have items")
        .iter()
        .find(|a| a["id"].as_str() == Some(agent_id.as_str()))
        .expect("enrolled agent must be listed");

    assert!(
        row.get("exec_policy").is_none(),
        "an unconfigured device must not report an exec policy: {row}"
    );
    assert!(
        row.get("ssh_policy").is_none(),
        "an unconfigured device must not report an ssh policy — the model \
         default is `daemon`, and the dialog would pre-select it: {row}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

async fn enroll_helper(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    machine_id: &str,
    machine_name: &str,
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
            "machine_name": machine_name,
            "os": "linux",
            "agent_version": "0.1.0",
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

fn urlencode(s: &str) -> String {
    // Minimal URL-encoding for the JWT (only `+`, `/`, `=` need escaping).
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

// ────────────────────────────────────────────────────────────────────────────
// #1630: the session audit trail must read back through the real route
// ────────────────────────────────────────────────────────────────────────────

/// `GET /api/tenant/{tid}/session/{sid}/audit` 500'd on every session in prod
/// (0.4.101): the audit sink writes rows through the driver's typed
/// `insert_many`, whose raw serializer stores `Permissions` as `Int32` bits,
/// and the route reads them back through the typed cursor — where serde's
/// tagged-enum buffering reports the field as human-readable, so the `rc:*`
/// wire rule refused the number. A `to_document`/`from_document` round trip
/// cannot see this (#1166 learned that the hard way), so this test uses the
/// production writer (`AuditSink`) and the production reader (the HTTP route)
/// against a real MongoDB. RED before the `deserialize_stored` opt-ins, with
/// exactly the prod message in the 500 body.
#[tokio::test]
async fn session_audit_reads_back_rows_the_audit_sink_wrote() {
    use bson::oid::ObjectId;
    use meshharbor_remote_control::audit::AuditSink;
    use meshharbor_remote_control::models::{AuditKind, EndReason, RemoteAuditEvent};
    use meshharbor_remote_control::permissions::Permissions;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("audit1630").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let uid = ObjectId::parse_str(&seeded.admin.id).unwrap();
    let sid = ObjectId::new();
    let aid = ObjectId::new();

    // The production writer — the sink the Hub records through. Its
    // `SessionRequested` projection also creates the `remote_sessions` row
    // the route's tenant check reads, exactly as in prod.
    let (sink, flusher) = AuditSink::spawn(app.db.clone());
    sink.record(
        sid,
        aid,
        tid,
        AuditKind::SessionRequested {
            controller_user_id: uid,
            controller_name: "audit1630 Admin".into(),
            permissions: Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD,
            record_stripped: None,
            privacy_stripped: None,
            features_stripped: None,
            idle_secs: None,
            idle_enforced: None,
            lock_on_end: None,
            lock_enforced: None,
        },
    );
    sink.record(
        sid,
        aid,
        tid,
        AuditKind::PermissionsChanged {
            permissions: Permissions::VIEW,
        },
    );
    sink.record(
        sid,
        aid,
        tid,
        AuditKind::SessionEnded {
            reason: EndReason::ControllerHangup,
            limit: None,
        },
    );
    // Closing the channel makes the flusher drain and exit: every write
    // above has landed once it joins.
    drop(sink);
    flusher.await.expect("audit flusher");

    // Pin what is actually on disk: the driver's typed insert stores the
    // bits (every `remote_audit` row in prod holds an Int32), while the
    // `to_document` projection stores the names. Both must read, forever.
    let audit_raw = app
        .db
        .collection::<bson::Document>(RemoteAuditEvent::COLLECTION)
        .find_one(bson::doc! { "session_id": sid, "event.kind": "session_requested" })
        .await
        .unwrap()
        .expect("audit row present");
    let stored = audit_raw.get_document("event").unwrap().get("permissions");
    assert_eq!(stored, Some(&bson::Bson::Int32(7)), "audit rows hold bits");
    let session_raw = app
        .db
        .collection::<bson::Document>("remote_sessions")
        .find_one(bson::doc! { "_id": sid })
        .await
        .unwrap()
        .expect("session row projected");
    assert_eq!(
        session_raw.get_str("permissions").ok(),
        Some("VIEW"),
        "session rows hold names (the PermissionsChanged $set landed)"
    );

    // The production reader.
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/session/{}/audit", seeded.tenant_id, sid),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status, 200,
        "the audit route must read bits-shaped rows: {body}"
    );
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 3, "{body}");
    let by_kind = |kind: &str| -> &Value {
        items
            .iter()
            .find(|i| i["event"]["kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} in {body}"))
    };
    // The API keeps the name form the browser expects.
    assert_eq!(
        by_kind("session_requested")["event"]["permissions"],
        "VIEW | INPUT | CLIPBOARD"
    );
    assert_eq!(
        by_kind("permissions_changed")["event"]["permissions"],
        "VIEW"
    );
    let _ = by_kind("session_ended");

    // Positive control for the #1166 half: the name-shaped session row the
    // same flush projected (and then `$set` to "VIEW") still reads.
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/session/{}", seeded.tenant_id, sid),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let session: Value = resp.json().await.unwrap();
    assert_eq!(session["permissions"], "VIEW");
}

/// X14: the actual local HTTP upgrade + user socket + PDP creates the source.
/// Agents below are bounded in-memory sinks, never sockets or peer connections.
/// This does not enable the production child capability or attest delegation.
#[tokio::test]
async fn file_child_local_controller_source_requires_http_authentication_and_actual_pdp() {
    use bson::oid::ObjectId;
    use meshharbor_remote_control::{
        models::{EndReason, OsKind},
        permissions::Permissions,
        signaling::{ClientMsg, ServerMsg},
    };
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    async fn frame_of_type(
        socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
        expected: &str,
    ) -> Value {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let message = socket
                    .next()
                    .await
                    .expect("synthetic controller open")
                    .expect("synthetic controller frame");
                if let Message::Text(text) = message {
                    let value: Value = serde_json::from_str(&text).expect("server JSON frame");
                    if value["t"] == expected {
                        return value;
                    }
                }
            }
        })
        .await
        .expect("bounded X14 local controller response")
    }
    fn request(agent_id: ObjectId) -> String {
        serde_json::to_string(&ClientMsg::SessionRequest {
            agent_id,
            share_grant_id: None,
            permissions: Permissions::VIEW | Permissions::FILES,
            browser_caps: Vec::new(),
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            override_reason: None,
            local_relay: None,
            initial_resolution: None,
        })
        .unwrap()
    }

    let app = TestApp::spawn().await;
    let owner = app.seed_tenant("x14-local-pdp-owner").await;
    let outsider = app.seed_tenant("x14-local-pdp-outsider").await;
    let (agent_hex, _) = enroll_helper(&app, &owner, "x14-synthetic-parent", "X14 Synthetic").await;
    let agent = ObjectId::parse_str(&agent_hex).unwrap();
    let tenant = ObjectId::parse_str(&owner.tenant_id).unwrap();
    let owner_id = ObjectId::parse_str(&owner.admin.id).unwrap();
    let hub = &app.state.fleet().rc_hub;
    let (_, _cancel, mut agent_rx) =
        hub.register_agent(agent, tenant, owner_id, OsKind::Linux, 3, false, false);

    let unauthenticated = connect_async(format!("ws://{}/ws", app.addr)).await;
    match unauthenticated {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status().as_u16(), 401)
        }
        _ => panic!("X14 unauthenticated local controller must receive HTTP 401"),
    }
    assert!(agent_rx.try_recv().is_err());

    // A valid account from another tenant reaches the actual PDP, which must
    // refuse before creating a parent or enqueueing any agent Request.
    let outsider_url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&outsider.admin.access_token)
    );
    let outsider_socket = connect_async(&outsider_url).await;
    assert!(
        outsider_socket.is_ok(),
        "synthetic authenticated outsider upgrade"
    );
    let (mut outsider_socket, _) = outsider_socket.unwrap();
    outsider_socket
        .send(Message::Text(request(agent).into()))
        .await
        .unwrap();
    let denied = frame_of_type(&mut outsider_socket, "rc:error").await;
    assert_eq!(denied["code"], "permission_denied");
    assert!(
        agent_rx.try_recv().is_err(),
        "denied PDP must not reach an agent"
    );
    outsider_socket.close(None).await.unwrap();

    let owner_url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&owner.admin.access_token)
    );
    let owner_socket = connect_async(&owner_url).await;
    assert!(
        owner_socket.is_ok(),
        "synthetic authenticated owner upgrade"
    );
    let (mut owner_socket, _) = owner_socket.unwrap();
    owner_socket
        .send(Message::Text(request(agent).into()))
        .await
        .unwrap();
    let created = frame_of_type(&mut owner_socket, "rc:session.created").await;
    let sid = ObjectId::parse_str(created["session_id"].as_str().unwrap()).unwrap();
    assert_eq!(hub.file_child_local_pdp_for_tests(sid), Some(true));
    assert!(
        matches!(tokio::time::timeout(Duration::from_secs(2), agent_rx.recv()).await.expect("bounded synthetic agent Request"), Some(ServerMsg::Request { session_id, .. }) if session_id == sid)
    );
    // A real consent transition cannot stamp/upgrade the provenance later.
    hub.deliver_consent(sid, true, None).unwrap();
    frame_of_type(&mut owner_socket, "rc:ready").await;
    assert_eq!(hub.file_child_local_pdp_for_tests(sid), Some(true));
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileChildReserve {
                session_id: sid,
                transfer_id: "synthetic-download".into(),
                direction: meshharbor_remote_control::signaling::FileChildDirection::Download,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        frame_of_type(&mut owner_socket, "rc:error").await["code"],
        "file_child_error"
    );
    assert!(
        agent_rx.try_recv().is_err(),
        "default-off capability must not forward any child"
    );
    hub.terminate(sid, EndReason::ControllerHangup).unwrap();

    // A stale Hub connection with no matching Mongo agent hits the legacy
    // PDP early-out (Ok(Prompt)); that is not an actual authorization proof.
    let stale = ObjectId::new();
    let (_, _stale_cancel, mut stale_rx) =
        hub.register_agent(stale, tenant, owner_id, OsKind::Linux, 3, false, false);
    owner_socket
        .send(Message::Text(request(stale).into()))
        .await
        .unwrap();
    let created = frame_of_type(&mut owner_socket, "rc:session.created").await;
    let stale_sid = ObjectId::parse_str(created["session_id"].as_str().unwrap()).unwrap();
    assert_eq!(hub.file_child_local_pdp_for_tests(stale_sid), Some(false));
    assert!(
        matches!(tokio::time::timeout(Duration::from_secs(2), stale_rx.recv()).await.expect("bounded synthetic stale agent Request"), Some(ServerMsg::Request { session_id, .. }) if session_id == stale_sid)
    );
    hub.terminate(stale_sid, EndReason::ControllerHangup)
        .unwrap();
    owner_socket.close(None).await.unwrap();
}

/// X14 upload direction: default-off capability, isolation from download
/// capability and kill switch, direction-bound reservation/offer, and policy
/// revision revocation over the real controller WebSocket + MongoDB PDP.
#[tokio::test]
async fn file_child_upload_direction_default_off_opt_in_kill_switch_and_revocation_contract() {
    use bson::oid::ObjectId;
    use meshharbor_remote_control::{
        models::{EndReason, OsKind},
        permissions::Permissions,
        signaling::{ClientMsg, FileChildDirection, FileChildOfferProof, ServerMsg},
    };
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    async fn frame_of_type(
        socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
        expected: &str,
    ) -> Value {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let message = socket
                    .next()
                    .await
                    .expect("controller ws open")
                    .expect("controller ws frame");
                if let Message::Text(text) = message {
                    let value: Value = serde_json::from_str(&text).expect("server JSON frame");
                    if value["t"] == expected {
                        return value;
                    }
                }
            }
        })
        .await
        .expect("bounded X14 upload controller response")
    }

    let app = TestApp::spawn().await;
    let owner = app.seed_tenant("x14-upload-owner").await;
    let (agent_hex, _) = enroll_helper(&app, &owner, "x14-upload-agent", "X14 Upload Agent").await;
    let agent = ObjectId::parse_str(&agent_hex).unwrap();
    let tenant = ObjectId::parse_str(&owner.tenant_id).unwrap();
    let owner_id = ObjectId::parse_str(&owner.admin.id).unwrap();
    let hub = &app.state.fleet().rc_hub;
    let (_, _cancel, mut agent_rx) =
        hub.register_agent(agent, tenant, owner_id, OsKind::Linux, 4, false, false);

    let owner_url = format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&owner.admin.access_token)
    );
    let (mut owner_socket, _) = connect_async(&owner_url).await.expect("owner ws connect");

    // 1. Session with ONLY `file-child-download` opted in: download reserve works, upload reserve fails with `file_child_error`.
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::SessionRequest {
                agent_id: agent,
                share_grant_id: None,
                permissions: Permissions::VIEW | Permissions::FILES,
                browser_caps: vec!["file-child-download".into()],
                preferred_transport: None,
                chroma_pref: None,
                chunk_framing: None,
                audio_enabled: false,
                override_reason: None,
                local_relay: None,
                initial_resolution: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let created = frame_of_type(&mut owner_socket, "rc:session.created").await;
    let sid1 = ObjectId::parse_str(created["session_id"].as_str().unwrap()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), agent_rx.recv())
        .await
        .unwrap();
    hub.deliver_consent(sid1, true, None).unwrap();
    frame_of_type(&mut owner_socket, "rc:ready").await;
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::SdpOffer {
                session_id: sid1,
                sdp: "v=0\r\n".into(),
                extauth_mac: None,
                peer_auth: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), agent_rx.recv())
        .await
        .unwrap();
    hub.forward_answer(sid1, "v=0\r\n".into(), None, None, None)
        .unwrap();
    frame_of_type(&mut owner_socket, "rc:sdp.answer").await;

    // Upload reserve on download-only session -> `file_child_error`
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileChildReserve {
                session_id: sid1,
                transfer_id: "up-denied".into(),
                direction: FileChildDirection::Upload,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let err_frame = frame_of_type(&mut owner_socket, "rc:error").await;
    assert_eq!(err_frame["code"], "file_child_error");

    // Download reserve on the same session -> succeeds
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileChildReserve {
                session_id: sid1,
                transfer_id: "dl-ok".into(),
                direction: FileChildDirection::Download,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let dl_reserved = frame_of_type(&mut owner_socket, "rc:file.child.reserved").await;
    assert_eq!(dl_reserved["transfer_id"], "dl-ok");
    hub.terminate(sid1, EndReason::ControllerHangup).unwrap();
    while agent_rx.try_recv().is_ok() {}

    // 2. Session opting into both `file-child-upload` and `file-child-download`.
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::SessionRequest {
                agent_id: agent,
                share_grant_id: None,
                permissions: Permissions::VIEW | Permissions::FILES,
                browser_caps: vec!["file-child-upload".into(), "file-child-download".into()],
                preferred_transport: None,
                chroma_pref: None,
                chunk_framing: None,
                audio_enabled: false,
                override_reason: None,
                local_relay: None,
                initial_resolution: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let created2 = frame_of_type(&mut owner_socket, "rc:session.created").await;
    let sid2 = ObjectId::parse_str(created2["session_id"].as_str().unwrap()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), agent_rx.recv())
        .await
        .unwrap();
    hub.deliver_consent(sid2, true, None).unwrap();
    frame_of_type(&mut owner_socket, "rc:ready").await;
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::SdpOffer {
                session_id: sid2,
                sdp: "v=0\r\n".into(),
                extauth_mac: None,
                peer_auth: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), agent_rx.recv())
        .await
        .unwrap();
    hub.forward_answer(sid2, "v=0\r\n".into(), None, None, None)
        .unwrap();
    frame_of_type(&mut owner_socket, "rc:sdp.answer").await;

    // Reserve an upload child.
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileChildReserve {
                session_id: sid2,
                transfer_id: "up-1".into(),
                direction: FileChildDirection::Upload,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let up_reserved = frame_of_type(&mut owner_socket, "rc:file.child.reserved").await;
    assert_eq!(up_reserved["direction"], "upload");
    let up_cid = ObjectId::parse_str(up_reserved["child_id"].as_str().unwrap()).unwrap();

    // Cross-direction offer (Download offer for Upload reservation) -> `file_child_error`.
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileSdpOffer {
                session_id: sid2,
                child_id: up_cid,
                transfer_id: "up-1".into(),
                direction: FileChildDirection::Download,
                sdp: "v=0\r\na=fingerprint:sha-256 AA:BB\r\n".into(),
                proof: FileChildOfferProof {
                    nonce: "nonce-12345678".into(),
                    key: "key-b64".into(),
                    sig: "sig-b64".into(),
                },
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let cross_err = frame_of_type(&mut owner_socket, "rc:error").await;
    assert_eq!(cross_err["code"], "file_child_error");
    assert!(agent_rx.try_recv().is_err());

    // Matching Upload offer -> delivered to agent_rx with `direction: Upload`.
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileSdpOffer {
                session_id: sid2,
                child_id: up_cid,
                transfer_id: "up-1".into(),
                direction: FileChildDirection::Upload,
                sdp: "v=0\r\na=fingerprint:sha-256 AA:BB\r\n".into(),
                proof: FileChildOfferProof {
                    nonce: "nonce-12345678".into(),
                    key: "key-b64".into(),
                    sig: "sig-b64".into(),
                },
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(2), agent_rx.recv())
        .await
        .unwrap()
    {
        Some(ServerMsg::FileSdpOffer {
            session_id,
            child_id,
            direction: FileChildDirection::Upload,
            ..
        }) => {
            assert_eq!(session_id, sid2);
            assert_eq!(child_id, up_cid);
        }
        other => panic!("expected upload FileSdpOffer, got {other:?}"),
    }

    // 3. Disabling ONLY upload kill switch blocks upload while download still works.
    hub.set_file_child_direction_disabled(FileChildDirection::Upload, true);
    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileChildReserve {
                session_id: sid2,
                transfer_id: "up-killed".into(),
                direction: FileChildDirection::Upload,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let killed_err = frame_of_type(&mut owner_socket, "rc:error").await;
    assert_eq!(killed_err["code"], "file_child_error");

    owner_socket
        .send(Message::Text(
            serde_json::to_string(&ClientMsg::FileChildReserve {
                session_id: sid2,
                transfer_id: "dl-unaffected".into(),
                direction: FileChildDirection::Download,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let dl_still_ok = frame_of_type(&mut owner_socket, "rc:file.child.reserved").await;
    assert_eq!(dl_still_ok["transfer_id"], "dl-unaffected");
    hub.set_file_child_direction_disabled(FileChildDirection::Upload, false);

    // 4. Policy revision bump in MongoDB triggers `rc:file.child.revoke` within <= 5s.
    app.db
        .collection::<bson::Document>("tenants")
        .update_one(
            bson::doc! { "_id": tenant },
            bson::doc! { "$inc": { "security_rev": 1_i64 } },
        )
        .await
        .unwrap();
    let revoke_frame = frame_of_type(&mut owner_socket, "rc:file.child.revoke").await;
    assert_eq!(revoke_frame["session_id"], sid2.to_hex());

    hub.terminate(sid2, EndReason::ControllerHangup).unwrap();
    owner_socket.close(None).await.unwrap();
}
