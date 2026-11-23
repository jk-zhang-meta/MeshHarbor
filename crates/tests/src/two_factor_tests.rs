// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-129 — switching a device's two-factor on and off from the admin page.
//!
//! The device is a fake agent on a real `/ws?role=agent` socket: it receives each
//! `rc:agent.two_factor` step and answers `rc:agent.two_factor_result`, as the daemon does. What
//! these lock is the centre's half: it relays each step and the code to the device, answers
//! the device's verdict (a refusal is an answer, not an HTTP error), keeps no secret, and gates
//! who may ask (AC2's server side; the device's own check is
//! `meshharbor_node_core::two_factor`'s tests).

use crate::agent_presence_tests::enroll;
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use crate::peer_relay_mint_tests::{Ws, recv_t};
use bson::{Document, doc, oid::ObjectId};
use futures::SinkExt;
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

const WAIT: Duration = Duration::from_secs(5);
/// What the fake device hands out as its secret: it must never be stored by the centre.
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// An agent WS whose hello advertises `rpc`.
async fn connect(app: &TestApp, token: &str, rpc: &[&str]) -> Ws {
    let url = format!("ws://{}/ws?token={}&role=agent", app.addr, token);
    let (mut ws, _) = connect_async(url).await.expect("ws connect");
    let hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "gpu box",
        "os": "linux",
        "agent_version": "0.4.212",
        "displays": [],
        "caps": {
            "hw_encoders": ["openh264"],
            "codecs": ["h264"],
            "has_input_permission": true,
            "supports_clipboard": true,
            "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
            "rpc": rpc,
        },
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .expect("send hello");
    ws
}

async fn post(
    app: &TestApp,
    seeded: &SeededTenant,
    aid: &str,
    token: &str,
    body: Value,
) -> (u16, Value) {
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{aid}/two-factor", seeded.tenant_id),
            token,
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

/// The device's side of one step: the frame it got, then its answer.
async fn answer_once(ws: &mut Ws, reply: Value) -> Value {
    let got = recv_t(ws, "rc:agent.two_factor", WAIT)
        .await
        .expect("the step reached the device");
    let mut reply = reply;
    reply["t"] = json!("rc:agent.two_factor_result");
    reply["request_id"] = got["request_id"].clone();
    ws.send(Message::Text(reply.to_string().into()))
        .await
        .expect("send result");
    got
}

/// The hello is persisted asynchronously: wait until the row advertises `two-factor`.
async fn wait_caps(app: &TestApp, aid: &str) {
    let oid = ObjectId::parse_str(aid).unwrap();
    for _ in 0..50 {
        let row = app
            .db
            .collection::<Document>("agents")
            .find_one(doc! {"_id": oid})
            .await
            .unwrap()
            .unwrap();
        if row
            .get_document("capabilities")
            .ok()
            .and_then(|c| c.get_array("rpc").ok())
            .is_some_and(|r| r.iter().any(|v| v.as_str() == Some("two-factor")))
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the hello's caps were never stored");
}

async fn agent_row(app: &TestApp, aid: &str) -> Document {
    app.db
        .collection::<Document>("agents")
        .find_one(doc! {"_id": ObjectId::parse_str(aid).unwrap()})
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn each_step_is_relayed_to_the_device_and_the_centre_keeps_no_secret() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tfa-steps").await;
    let admin = seeded.admin.access_token.clone();
    let (aid, token) = enroll(&app, &seeded, "tfa-steps-box").await;
    let mut ws = connect(&app, &token, &["two-factor"]).await;
    wait_caps(&app, &aid).await;

    // begin: the device answers its secret and URI; the page gets them, once.
    let device = tokio::spawn(async move {
        let got = answer_once(
            &mut ws,
            json!({
                "enabled": false,
                "secret": SECRET,
                "setup_id": "setup-1",
                "otpauth_uri": format!("otpauth://totp/MeshHarbor:gpu%20box?secret={SECRET}&issuer=MeshHarbor"),
            }),
        )
        .await;
        (ws, got)
    });
    let (status, v) = post(&app, &seeded, &aid, &admin, json!({"op": "begin"})).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["secret"], SECRET);
    assert!(
        v["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/MeshHarbor:")
    );
    assert_eq!(v["enabled"], false);
    assert_eq!(v["setup_id"], "setup-1");
    let (mut ws, got) = device.await.unwrap();
    assert_eq!(got["op"]["op"], "begin");
    let account = got["op"]["account"].as_str().unwrap().to_string();
    assert!(!account.is_empty(), "the app shows the device's name");

    // confirm: the code rides to the device; the device's yes switches the stored state.
    let device = tokio::spawn(async move {
        let got = answer_once(
            &mut ws,
            json!({"enabled": true, "recovery_codes": ["abcd-efgh", "jkmn-pqrs"]}),
        )
        .await;
        (ws, got)
    });
    let (status, v) = post(
        &app,
        &seeded,
        &aid,
        &admin,
        json!({"op": "confirm", "code": "123456", "setup_id": "setup-1"}),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["enabled"], true);
    assert_eq!(v["recovery_codes"], json!(["abcd-efgh", "jkmn-pqrs"]));
    let (mut ws, got) = device.await.unwrap();
    assert_eq!(
        got["op"],
        json!({"op": "confirm", "code": "123456", "setup_id": "setup-1"})
    );
    let row = agent_row(&app, &aid).await;
    assert_eq!(
        row.get_document("capabilities")
            .unwrap()
            .get_bool("two_factor"),
        Ok(true),
        "the admin page shows it on without waiting for a reconnect"
    );
    let stored = serde_json::to_string(&row).unwrap();
    for leaked in [SECRET, "abcd-efgh", "123456"] {
        assert!(!stored.contains(leaked), "the centre stored {leaked}");
    }

    // disable with a wrong code: the device's refusal is an answer (200), and nothing changes.
    let device = tokio::spawn(async move {
        answer_once(
            &mut ws,
            json!({"enabled": true, "refused": "two_factor_invalid"}),
        )
        .await;
        ws
    });
    let (status, v) = post(
        &app,
        &seeded,
        &aid,
        &admin,
        json!({"op": "disable", "code": "000000"}),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["refused"], "two_factor_invalid");
    assert_eq!(v["enabled"], true);
    assert!(v["message"].as_str().unwrap().contains("wrong"), "{v}");
    let mut ws = device.await.unwrap();
    assert_eq!(
        agent_row(&app, &aid)
            .await
            .get_document("capabilities")
            .unwrap()
            .get_bool("two_factor"),
        Ok(true)
    );

    // disable with the device's yes: off again.
    let device = tokio::spawn(async move {
        answer_once(&mut ws, json!({"enabled": false})).await;
        ws
    });
    let (status, v) = post(
        &app,
        &seeded,
        &aid,
        &admin,
        json!({"op": "disable", "code": "654321"}),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["enabled"], false);
    let _ws = device.await.unwrap();
    assert!(
        agent_row(&app, &aid)
            .await
            .get_document("capabilities")
            .unwrap()
            .get("two_factor")
            .is_none()
    );
}

#[tokio::test]
async fn only_an_agent_manager_may_ask_and_only_a_device_that_supports_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tfa-gate").await;
    let (old_aid, old_token) = enroll(&app, &seeded, "tfa-gate-old").await;
    let _old = connect(&app, &old_token, &["exec"]).await;
    let (aid, token) = enroll(&app, &seeded, "tfa-gate-new").await;
    let _ws = connect(&app, &token, &["two-factor"]).await;
    wait_caps(&app, &aid).await;

    let (status, _) = post(
        &app,
        &seeded,
        &aid,
        &seeded.member.access_token,
        json!({"op": "begin"}),
    )
    .await;
    assert_eq!(status, 403, "a member without MANAGE_AGENTS");
    let (status, v) = post(
        &app,
        &seeded,
        &old_aid,
        &seeded.admin.access_token,
        json!({"op": "begin"}),
    )
    .await;
    assert_eq!(status, 409, "an agent without the verb: {v}");
    let (status, _) = post(
        &app,
        &seeded,
        &aid,
        &seeded.admin.access_token,
        json!({"op": "steal"}),
    )
    .await;
    assert!(
        status == 400 || status == 422,
        "an unknown step is refused: {status}"
    );

    // Another tenant's admin cannot reach this device.
    let other = app.seed_tenant("tfa-gate-other").await;
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{aid}/two-factor", other.tenant_id),
            &other.admin.access_token,
        )
        .json(&json!({"op": "begin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}

#[tokio::test]
async fn the_centres_switch_stops_new_setups_but_never_a_devices_own_switch_off() {
    let app = TestApp::spawn_with_settings(|s| s.app.device_two_factor = false).await;
    let seeded = app.seed_tenant("tfa-switch").await;
    let admin = seeded.admin.access_token.clone();
    let (aid, token) = enroll(&app, &seeded, "tfa-switch-box").await;
    let mut ws = connect(&app, &token, &["two-factor"]).await;
    wait_caps(&app, &aid).await;

    for body in [
        json!({"op": "begin"}),
        json!({"op": "confirm", "code": "123456"}),
    ] {
        let (status, _) = post(&app, &seeded, &aid, &admin, body.clone()).await;
        assert_eq!(status, 403, "{body}");
    }
    let device = tokio::spawn(async move {
        answer_once(&mut ws, json!({"enabled": false})).await;
        ws
    });
    let (status, v) = post(
        &app,
        &seeded,
        &aid,
        &admin,
        json!({"op": "disable", "code": "123456"}),
    )
    .await;
    assert_eq!(
        status, 200,
        "a device that has it can still be switched off with its code: {v}"
    );
    let _ws = device.await.unwrap();
}
