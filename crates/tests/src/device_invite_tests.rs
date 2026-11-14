// SPDX-License-Identifier: AGPL-3.0-only
//! Temporary devices over real HTTP + Mongo: an invitation's code redeemed
//! once, the enrollment bound to it (a known machine refused), the device's
//! own view, a renewal, a revocation that removes the device, the deadline
//! reaper, an enrolled device made temporary, and the history that keeps
//! every invitation.
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use serde_json::{Value, json};

async fn enabled_app() -> TestApp {
    TestApp::spawn_with_settings(|s| s.auth.native_device_invite_enabled = true).await
}

async fn create(app: &TestApp, s: &SeededTenant, token: &str, secs: i64) -> (u16, Value) {
    let r = app
        .auth_post(&format!("/api/tenant/{}/device-invite", s.tenant_id), token)
        .json(&json!({ "duration_secs": secs, "label": "helper" }))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

async fn redeem(app: &TestApp, code: &str, name: &str) -> (u16, Value) {
    let r = app
        .client
        .post(app.url("/api/native/device-invite/redeem"))
        .json(&json!({ "code": code, "device_name": name, "device_os": "windows" }))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

async fn enroll(app: &TestApp, token: &str, machine: &str) -> (u16, Value) {
    let r = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": token, "machine_id": machine,
            "machine_name": machine, "os": "windows", "agent_version": "0.4.152",
        }))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

async fn list(app: &TestApp, s: &SeededTenant) -> Vec<Value> {
    let v: Value = app
        .auth_get(
            &format!("/api/tenant/{}/device-invite", s.tenant_id),
            &s.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["items"].as_array().cloned().unwrap_or_default()
}

async fn self_view(app: &TestApp, agent_token: &str) -> Value {
    app.client
        .get(app.url("/api/agent/self/temporary"))
        .bearer_auth(agent_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn an_invite_code_enrolls_one_temporary_device_once() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-happy").await;

    // A plain member may not invite devices.
    assert_eq!(create(&app, &s, &s.member.access_token, 3600).await.0, 403);
    // Bounds: shorter than 10 minutes or longer than 5 years is refused.
    assert_eq!(create(&app, &s, &s.admin.access_token, 60).await.0, 400);
    assert_eq!(
        create(&app, &s, &s.admin.access_token, 6 * 365 * 86_400)
            .await
            .0,
        400
    );

    let (st, inv) = create(&app, &s, &s.admin.access_token, 3600).await;
    assert_eq!(st, 201, "{inv}");
    let code = inv["code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 9, "1234-5678");
    assert_eq!(inv["join_command"], format!("mh join {code}"));
    // The history never shows the code again.
    let rows = list(&app, &s).await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].get("code").is_none() && rows[0]["state"] == "open");

    // A wrong code is refused like a used one.
    assert_eq!(redeem(&app, "0000-0000", "pc").await.0, 404);

    let (st, r) = redeem(&app, &code.replace('-', " "), "helper-pc").await;
    assert_eq!(st, 200, "{r}");
    assert_eq!(r["tenant_id"].as_str(), Some(s.tenant_id.as_str()));
    let token = r["enrollment_token"].as_str().unwrap().to_string();
    // Once only.
    assert_eq!(redeem(&app, &code, "another-pc").await.0, 404);

    let (st, e) = enroll(&app, &token, "tinv-machine-1").await;
    assert_eq!(st, 200, "{e}");
    let agent_token = e["agent_token"].as_str().unwrap().to_string();
    let v = self_view(&app, &agent_token).await;
    assert_eq!(v["temporary"], true, "{v}");
    assert!(v["access_until_ms"].as_i64().unwrap() > 0);

    let rows = list(&app, &s).await;
    assert_eq!(rows[0]["state"], "enrolled");
    assert_eq!(rows[0]["device_name"], "helper-pc");
    assert_eq!(rows[0]["agent_id"].as_str(), e["agent_id"].as_str());
}

#[tokio::test]
async fn an_invite_never_binds_a_machine_the_org_already_has() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-known").await;
    // An ordinary device of the org.
    let ordinary: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", s.tenant_id),
            &s.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let t = ordinary["token"]
        .as_str()
        .or_else(|| ordinary["enrollment_token"].as_str())
        .unwrap()
        .to_string();
    assert_eq!(enroll(&app, &t, "tinv-known-machine").await.0, 200);

    let (_, inv) = create(&app, &s, &s.admin.access_token, 3600).await;
    let (_, r) = redeem(&app, inv["code"].as_str().unwrap(), "known").await;
    let (st, body) = enroll(
        &app,
        r["enrollment_token"].as_str().unwrap(),
        "tinv-known-machine",
    )
    .await;
    assert_eq!(
        st, 403,
        "a known machine is never made temporary by a code: {body}"
    );
}

#[tokio::test]
async fn renewal_extends_and_revocation_removes_the_device() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-renew").await;
    let (_, inv) = create(&app, &s, &s.admin.access_token, 3600).await;
    let id = inv["id"].as_str().unwrap().to_string();
    let until0 = inv["access_until_ms"].as_i64().unwrap();
    let (_, r) = redeem(&app, inv["code"].as_str().unwrap(), "pc").await;
    let (_, e) = enroll(
        &app,
        r["enrollment_token"].as_str().unwrap(),
        "tinv-renew-1",
    )
    .await;
    let agent_token = e["agent_token"].as_str().unwrap().to_string();

    let renewed: Value = app
        .auth_post(
            &format!("/api/tenant/{}/device-invite/{id}/renew", s.tenant_id),
            &s.admin.access_token,
        )
        .json(&json!({ "duration_secs": 86_400 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        renewed["access_until_ms"].as_i64().unwrap(),
        until0 + 86_400_000,
        "extends from the current end: {renewed}"
    );
    assert_eq!(renewed["renewals"].as_array().unwrap().len(), 1);
    let v = self_view(&app, &agent_token).await;
    assert_eq!(
        v["access_until_ms"].as_i64(),
        Some(until0 + 86_400_000),
        "the device sees it"
    );

    let st = app
        .auth_delete(
            &format!("/api/tenant/{}/device-invite/{id}", s.tenant_id),
            &s.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 200);
    let rows = list(&app, &s).await;
    assert_eq!(rows[0]["state"], "ended");
    assert_eq!(rows[0]["end_reason"], "temporary_revoked");
    assert_eq!(rows[0]["ended_by"].as_str(), Some(s.admin.id.as_str()));
    // The device's credential is dead.
    let st = app
        .client
        .get(app.url("/api/agent/self/temporary"))
        .bearer_auth(&agent_token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 401, "a removed device is refused");
    // An ended invitation cannot be renewed.
    let st = app
        .auth_post(
            &format!("/api/tenant/{}/device-invite/{id}/renew", s.tenant_id),
            &s.admin.access_token,
        )
        .json(&json!({ "duration_secs": 86_400 }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 409);
}

#[tokio::test]
async fn the_reaper_ends_access_on_time_and_history_stays() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-reap").await;
    let (_, inv) = create(&app, &s, &s.admin.access_token, 600).await;
    let id = bson::oid::ObjectId::parse_str(inv["id"].as_str().unwrap()).unwrap();
    let (_, r) = redeem(&app, inv["code"].as_str().unwrap(), "pc").await;
    let (_, e) = enroll(&app, r["enrollment_token"].as_str().unwrap(), "tinv-reap-1").await;
    let agent_token = e["agent_token"].as_str().unwrap().to_string();

    // Nothing is due yet.
    let fleet = app.state.fleet();
    assert_eq!(
        meshharbor_mod_fleet::device_invite::reap_once(fleet)
            .await
            .unwrap(),
        0
    );
    // Move the deadline into the past, as time would.
    app.db
        .collection::<bson::Document>(meshharbor_mod_fleet::device_invite::COLLECTION)
        .update_one(
            bson::doc! { "_id": id },
            bson::doc! { "$set": { "access_until": bson::DateTime::from_millis(1) } },
        )
        .await
        .unwrap();
    assert_eq!(
        meshharbor_mod_fleet::device_invite::reap_once(fleet)
            .await
            .unwrap(),
        1
    );
    let rows = list(&app, &s).await;
    assert_eq!(rows.len(), 1, "the history keeps it");
    assert_eq!(rows[0]["state"], "ended");
    assert_eq!(rows[0]["end_reason"], "temporary_expired");
    let st = app
        .client
        .get(app.url("/api/agent/self/temporary"))
        .bearer_auth(&agent_token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 401, "the device was removed at its deadline");
}

#[tokio::test]
async fn an_enrolled_device_can_be_made_temporary_and_the_feature_is_off_by_default() {
    let off = TestApp::spawn().await;
    let so = off.seed_tenant("tinv-off").await;
    let st = off
        .auth_get(
            &format!("/api/tenant/{}/device-invite", so.tenant_id),
            &so.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 503);

    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-convert").await;
    let ordinary: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", s.tenant_id),
            &s.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let t = ordinary["token"]
        .as_str()
        .or_else(|| ordinary["enrollment_token"].as_str())
        .unwrap()
        .to_string();
    let (_, e) = enroll(&app, &t, "tinv-convert-1").await;
    let aid = e["agent_id"].as_str().unwrap().to_string();
    let agent_token = e["agent_token"].as_str().unwrap().to_string();
    assert_eq!(self_view(&app, &agent_token).await["temporary"], false);

    let r = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{aid}/temporary", s.tenant_id),
            &s.admin.access_token,
        )
        .json(&json!({ "duration_secs": 365 * 86_400 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(self_view(&app, &agent_token).await["temporary"], true);
    let rows = list(&app, &s).await;
    assert_eq!(rows[0]["converted"], true);
    assert_eq!(rows[0]["state"], "enrolled");
    // Twice is refused.
    let st = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{aid}/temporary", s.tenant_id),
            &s.admin.access_token,
        )
        .json(&json!({ "duration_secs": 86_400 }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 409);

    // And back: an ordinary device again, still enrolled, history kept.
    let st = app
        .auth_delete(
            &format!("/api/tenant/{}/agent/{aid}/temporary", s.tenant_id),
            &s.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 200);
    assert_eq!(self_view(&app, &agent_token).await["temporary"], false);
    let rows = list(&app, &s).await;
    assert_eq!(rows[0]["state"], "ended");
    assert_eq!(rows[0]["end_reason"], "temporary_made_permanent");
}
