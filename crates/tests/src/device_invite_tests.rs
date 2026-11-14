// SPDX-License-Identifier: AGPL-3.0-only
//! Temporary devices over real HTTP + Mongo: an invitation's code redeemed
//! once, the enrollment bound to it (a known machine refused), the device's
//! own view, a renewal, a revocation that removes the device, the deadline
//! reaper, an enrolled device made temporary, and the history that keeps
//! every invitation; several invitations on one device, and the device
//! owner's proof-linked view.
use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use serde_json::{Value, json};

async fn enabled_app() -> TestApp {
    TestApp::spawn_with_settings(|s| {
        s.auth.native_device_invite_enabled = true;
        if let Ok(url) = std::env::var("MESHHARBOR__REDIS__URL") {
            s.redis.url = url;
        }
    })
    .await
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
    assert!(
        r["features"].is_null(),
        "legacy redemption remains without selection"
    );
    assert_eq!(e["personal_device"], false);
    let legacy_id = bson::oid::ObjectId::parse_str(e["agent_id"].as_str().unwrap()).unwrap();
    let legacy = app
        .state
        .fleet()
        .agents
        .base
        .find_by_id(legacy_id)
        .await
        .unwrap();
    assert_eq!(
        legacy.ssh_policy.mode,
        meshharbor_remote_control::models::SshMode::Off
    );
    assert_eq!(
        legacy.exec_policy.mode,
        meshharbor_remote_control::models::ExecMode::Off
    );
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
    let (ordinary_status, ordinary_device) = enroll(&app, &t, "tinv-known-machine").await;
    assert_eq!(ordinary_status, 200);
    assert_eq!(
        ordinary_device["personal_device"], false,
        "ordinary admin token is not browser-approved personal provenance"
    );
    let ordinary_id =
        bson::oid::ObjectId::parse_str(ordinary_device["agent_id"].as_str().unwrap()).unwrap();
    let ordinary_agent = app
        .state
        .fleet()
        .agents
        .base
        .find_by_id(ordinary_id)
        .await
        .unwrap();
    assert_eq!(
        ordinary_agent.ssh_policy.mode,
        meshharbor_remote_control::models::SshMode::Off
    );
    assert_eq!(
        ordinary_agent.exec_policy.mode,
        meshharbor_remote_control::models::ExecMode::Off
    );

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

// ─── several invitations per device, the owner's view ──────────────────────

async fn ordinary_device(app: &TestApp, s: &SeededTenant, machine: &str) -> Value {
    let v: Value = app
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
    let t = v["token"]
        .as_str()
        .or_else(|| v["enrollment_token"].as_str())
        .unwrap()
        .to_string();
    let (st, e) = enroll(app, &t, machine).await;
    assert_eq!(st, 200, "{e}");
    e
}

async fn post_json(app: &TestApp, path: &str, bearer: Option<&str>, body: Value) -> (u16, Value) {
    let mut rq = app.client.post(app.url(path)).json(&body);
    if let Some(b) = bearer {
        rq = rq.bearer_auth(b);
    }
    let r = rq.send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

async fn host_list(app: &TestApp, s: &SeededTenant) -> Vec<Value> {
    let v: Value = app
        .auth_get(
            &format!("/api/tenant/{}/device-grants", s.tenant_id),
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

#[tokio::test]
async fn two_invitations_from_one_org_share_one_enrollment_and_end_one_by_one() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-multi").await;
    let (_, inv1) = create(&app, &s, &s.admin.access_token, 3600).await;
    let (_, inv2) = create(&app, &s, &s.admin.access_token, 7200).await;
    let (id1, id2) = (
        inv1["id"].as_str().unwrap().to_string(),
        inv2["id"].as_str().unwrap().to_string(),
    );
    let (_, r) = redeem(&app, inv1["code"].as_str().unwrap(), "pc").await;
    assert_eq!(r["invite_id"].as_str(), Some(id1.as_str()));
    assert_eq!(r["device_proof"].as_str().map(str::len), Some(64));
    let (_, e) = enroll(
        &app,
        r["enrollment_token"].as_str().unwrap(),
        "tinv-multi-1",
    )
    .await;
    let agent_token = e["agent_token"].as_str().unwrap().to_string();

    // The preview tells who and until when, and spends nothing.
    let code2 = inv2["code"].as_str().unwrap();
    for _ in 0..2 {
        let (st, p) = post_json(
            &app,
            "/api/native/device-invite/preview",
            None,
            json!({ "code": code2 }),
        )
        .await;
        assert_eq!(st, 200, "{p}");
        assert_eq!(p["tenant_id"].as_str(), Some(s.tenant_id.as_str()));
        assert_eq!(p["access_until_ms"], inv2["access_until_ms"]);
        assert!(p.get("enrollment_token").is_none());
    }
    let (st, _) = post_json(
        &app,
        "/api/native/device-invite/preview",
        None,
        json!({ "code": "0000-0000" }),
    )
    .await;
    assert_eq!(st, 404);

    // The second code attaches to the device's enrollment there.
    let (st, a) = post_json(
        &app,
        "/api/native/device-invite/redeem",
        None,
        json!({ "code": code2, "device_name": "pc", "device_os": "windows", "attach_token": agent_token }),
    )
    .await;
    assert_eq!(st, 200, "{a}");
    assert_eq!(a["attached"], true);
    assert_eq!(a["agent_id"], e["agent_id"]);
    assert!(a.get("enrollment_token").is_none());
    let v = self_view(&app, &agent_token).await;
    assert_eq!(v["grants"].as_array().unwrap().len(), 2, "{v}");
    assert_eq!(
        v["access_until_ms"], inv2["access_until_ms"],
        "the latest deadline"
    );

    // Ending one keeps the device; the other still holds it.
    let st = app
        .auth_delete(
            &format!("/api/tenant/{}/device-invite/{id1}", s.tenant_id),
            &s.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 200);
    let v = self_view(&app, &agent_token).await;
    assert_eq!(v["temporary"], true, "{v}");
    assert_eq!(v["grants"].as_array().unwrap().len(), 1);
    assert_eq!(v["grants"][0]["invite_id"].as_str(), Some(id2.as_str()));

    // Leaving the last one from the device removes it.
    let (st, l) = post_json(
        &app,
        &format!("/api/agent/self/temporary/{id2}/leave"),
        Some(&agent_token),
        json!({}),
    )
    .await;
    assert_eq!(st, 200, "{l}");
    assert_eq!(l["device_removed"], true);
    let st = app
        .client
        .get(app.url("/api/agent/self/temporary"))
        .bearer_auth(&agent_token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 401);
    let rows = list(&app, &s).await;
    let reason = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap()["end_reason"].clone();
    assert_eq!(reason(&id1), "temporary_revoked");
    assert_eq!(reason(&id2), "temporary_left");
}

#[tokio::test]
async fn an_ordinary_device_cannot_attach_and_the_code_stays_unspent() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-noattach").await;
    let e = ordinary_device(&app, &s, "tinv-noattach-1").await;
    let (_, inv) = create(&app, &s, &s.admin.access_token, 3600).await;
    let code = inv["code"].as_str().unwrap();
    let (st, r) = post_json(
        &app,
        "/api/native/device-invite/redeem",
        None,
        json!({ "code": code, "device_name": "pc", "device_os": "windows", "attach_token": e["agent_token"] }),
    )
    .await;
    assert_eq!(st, 409, "{r}");
    assert_eq!(r["error"], "already_member");
    let (st, _) = post_json(
        &app,
        "/api/native/device-invite/preview",
        None,
        json!({ "code": code }),
    )
    .await;
    assert_eq!(st, 200, "the code is still open");
}

#[tokio::test]
async fn the_owner_sees_and_ends_what_its_device_accepted_by_proof_only() {
    let app = enabled_app().await;
    let owner = app.seed_tenant("tinv-owner").await;
    let inviter = app.seed_tenant("tinv-inviter").await;
    let other = app.seed_tenant("tinv-other").await;
    // The machine is its owner's device, and takes an invitation from elsewhere.
    let own = ordinary_device(&app, &owner, "tinv-shared-machine").await;
    let own_token = own["agent_token"].as_str().unwrap().to_string();
    let (_, inv) = create(&app, &inviter, &inviter.admin.access_token, 3600).await;
    let iid = inv["id"].as_str().unwrap().to_string();
    let (_, r) = redeem(&app, inv["code"].as_str().unwrap(), "pc").await;
    let proof = r["device_proof"].as_str().unwrap().to_string();
    let (st, e) = enroll(
        &app,
        r["enrollment_token"].as_str().unwrap(),
        "tinv-shared-machine",
    )
    .await;
    assert_eq!(st, 200, "another org's enrollment of the same machine: {e}");
    let temp_token = e["agent_token"].as_str().unwrap().to_string();

    assert!(
        host_list(&app, &owner).await.is_empty(),
        "nothing before the proof"
    );
    // A wrong proof links nothing; the temporary enrollment may not link.
    let bad = json!({ "proofs": [{ "invite_id": iid, "proof": "0".repeat(64) }] });
    let (st, v) = post_json(&app, "/api/agent/self/link", Some(&own_token), bad).await;
    assert_eq!((st, v["linked"].as_u64()), (200, Some(0)));
    let good = json!({ "proofs": [{ "invite_id": iid, "proof": proof }] });
    let (st, _) = post_json(
        &app,
        "/api/agent/self/link",
        Some(&temp_token),
        good.clone(),
    )
    .await;
    assert_eq!(st, 403);
    let (st, v) = post_json(&app, "/api/agent/self/link", Some(&own_token), good.clone()).await;
    assert_eq!((st, v["linked"].as_u64()), (200, Some(1)));
    let (_, v) = post_json(&app, "/api/agent/self/link", Some(&own_token), good).await;
    assert_eq!(v["linked"].as_u64(), Some(0), "idempotent");

    let items = host_list(&app, &owner).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["state"], "enrolled");
    assert_eq!(items[0]["host_agent_id"], own["agent_id"]);
    assert!(
        items[0].get("label").is_none(),
        "the inviter's note is private"
    );
    assert!(
        host_list(&app, &other).await.is_empty(),
        "another org sees nothing"
    );
    // The inviter's history never names the device's owner.
    let rows = list(&app, &inviter).await;
    assert!(rows[0].get("hosts").is_none());

    // Another org cannot end it; the owner can.
    let st = app
        .auth_delete(
            &format!("/api/tenant/{}/device-grants/{iid}", other.tenant_id),
            &other.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(st, 404);
    let v: Value = app
        .auth_delete(
            &format!("/api/tenant/{}/device-grants/{iid}", owner.tenant_id),
            &owner.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["device_removed"], true, "{v}");
    assert_eq!(
        list(&app, &inviter).await[0]["end_reason"],
        "temporary_ended_by_owner"
    );
    assert_eq!(
        host_list(&app, &owner).await[0]["state"],
        "ended",
        "the history stays"
    );
    // The owner's own enrollment is untouched.
    assert_eq!(self_view(&app, &own_token).await["temporary"], false);
}

#[tokio::test]
async fn only_the_inviter_and_its_roles_may_control_a_temporary_device() {
    use bson::{doc, oid::ObjectId};
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-rc").await;
    let e = ordinary_device(&app, &s, "tinv-rc-1").await;
    let aid = e["agent_id"].as_str().unwrap().to_string();
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{aid}/temporary", s.tenant_id),
            &s.admin.access_token,
        )
        .json(&json!({ "duration_secs": 86_400 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let remote = app
        .state
        .modules
        .remote
        .as_ref()
        .expect("remote is mounted");
    let admin = ObjectId::parse_str(&s.admin.id).unwrap();
    let member = ObjectId::parse_str(&s.member.id).unwrap();
    let agent = ObjectId::parse_str(&aid).unwrap();
    let req =
        json!({ "t": "rc:session.request", "agent_id": aid, "permissions": "VIEW" }).to_string();
    // The admin invited it (and owns it): past the gate.
    let ok = meshharbor_mod_remote::controller::resolve_session_authz(remote, admin, &req).await;
    assert!(ok.is_ok(), "the inviter: {:?}", ok.err());

    // Someone else invited (and owns) it: even an ADMINISTRATOR is refused.
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": agent },
            doc! { "$set": { "owner_user_id": member } },
        )
        .await
        .unwrap();
    let invites = app
        .db
        .collection::<bson::Document>(meshharbor_mod_fleet::device_invite::COLLECTION);
    invites
        .update_one(
            doc! { "agent_id": agent },
            doc! { "$set": { "inviter_user_id": member } },
        )
        .await
        .unwrap();
    let err = meshharbor_mod_remote::controller::resolve_session_authz(remote, admin, &req)
        .await
        .err()
        .expect("a non-inviter administrator is refused");
    assert!(err.contains("temporary device"), "{err}");

    // A role named on the invitation admits its members.
    let me = app
        .db
        .collection::<bson::Document>("tenant_members")
        .find_one(
            doc! { "tenant_id": ObjectId::parse_str(&s.tenant_id).unwrap(), "user_id": admin },
        )
        .await
        .unwrap()
        .expect("the admin's membership");
    let roles = me.get_array("role_ids").unwrap().clone();
    invites
        .update_one(
            doc! { "agent_id": agent },
            doc! { "$set": { "allow_role_ids": roles } },
        )
        .await
        .unwrap();
    let ok = meshharbor_mod_remote::controller::resolve_session_authz(remote, admin, &req).await;
    assert!(ok.is_ok(), "a member of an allowed role: {:?}", ok.err());
}

#[tokio::test]
async fn host_selected_features_are_saved_and_only_host_can_change_them() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-features").await;
    let (_, inv) = create(&app, &s, &s.admin.access_token, 3600).await;
    let selected = json!({ "desktop_view": true, "desktop_control": false, "clipboard": false,
        "files": true, "ssh": true, "exec": false, "rdp": false, "network": false });
    let response = app.client.post(app.url("/api/native/device-invite/redeem"))
        .json(&json!({ "code": inv["code"], "device_name": "select-host", "device_os": "linux", "features": selected }))
        .send().await.unwrap();
    assert!(response.status().is_success());
    let redeemed: Value = response.json().await.unwrap();
    assert_eq!(redeemed["features"], selected);
    assert_eq!(redeemed["features_revision"], 0);
    let (status, enrolled) = enroll(
        &app,
        redeemed["enrollment_token"].as_str().unwrap(),
        "select-host",
    )
    .await;
    assert_eq!(status, 200, "{enrolled}");
    assert_eq!(enrolled["personal_device"], false);
    let aid = bson::oid::ObjectId::parse_str(enrolled["agent_id"].as_str().unwrap()).unwrap();
    let inviter = bson::oid::ObjectId::parse_str(&s.admin.id).unwrap();
    let member = bson::oid::ObjectId::parse_str(&s.member.id).unwrap();
    let chosen: meshharbor_remote_control::models::DeviceAccessFeatures =
        serde_json::from_value(selected.clone()).unwrap();
    assert_eq!(
        meshharbor_mod_fleet::device_invite::features_for_caller(app.state.fleet(), aid, inviter)
            .await
            .unwrap(),
        Some(chosen)
    );
    assert_eq!(
        meshharbor_mod_fleet::device_invite::features_for_caller(app.state.fleet(), aid, member)
            .await
            .unwrap(),
        Some(meshharbor_remote_control::models::DeviceAccessFeatures::none())
    );
    let target = app.state.fleet().agents.base.find_by_id(aid).await.unwrap();
    let caller = meshharbor_mod_fleet::agent_exec::Caller {
        user_id: inviter,
        display: "inviter".into(),
        origin_agent_id: None,
        source: "api",
    };
    assert_eq!(
        meshharbor_mod_fleet::agent_exec::authorize(
            app.state.fleet(),
            target.tenant_id,
            &target,
            &caller,
            "sh"
        )
        .await,
        Err(meshharbor_remote_control::models::ExecDenyReason::CallerNotAllowed),
        "owner shortcut cannot enable unselected exec"
    );
    let token = enrolled["agent_token"].as_str().unwrap();
    let view = self_view(&app, token).await;
    assert_eq!(view["grants"][0]["features"], selected);
    let id = view["grants"][0]["invite_id"]
        .as_str()
        .or_else(|| view["grants"][0]["id"].as_str())
        .unwrap();
    let path = format!("/api/agent/self/temporary/{id}/features");
    let none = json!({ "desktop_view": false, "desktop_control": false, "clipboard": false,
        "files": false, "ssh": false, "exec": false, "rdp": false, "network": false });
    let denied = app
        .auth_post(&path, &s.admin.access_token)
        .json(&json!({"features": none, "expected_revision":0}))
        .send()
        .await
        .unwrap();
    assert!(
        !denied.status().is_success(),
        "org admin token is not host authority"
    );
    let old_epoch =
        meshharbor_mod_fleet::device_invite::authorization_epoch(app.state.fleet(), aid)
            .await
            .unwrap();
    let authorized_before =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 1);
    assert!(
        meshharbor_mod_fleet::device_invite::service_request_is_current(
            app.state.fleet(),
            aid,
            authorized_before
        )
        .await
        .unwrap()
    );
    for collection in ["exec_pending", "ssh_pending"] {
        app.db
            .collection::<bson::Document>(collection)
            .insert_one(bson::doc! {
                "agent_id": aid, "tenant_id": bson::oid::ObjectId::parse_str(&s.tenant_id).unwrap(),
                "state": "pending", "request_id": "obsolete-exec", "grant_id": "obsolete-ssh", "device_access_epoch": &old_epoch
            })
            .await
            .unwrap();
    }
    let updated = app
        .client
        .post(app.url(&path))
        .bearer_auth(token)
        .json(&json!({"features":none,"expected_revision":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        updated.status().as_u16(),
        202,
        "{}",
        updated.text().await.unwrap()
    );
    let stale = app
        .client
        .post(app.url(&path))
        .bearer_auth(token)
        .json(&json!({"features":selected,"expected_revision":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);
    let view = self_view(&app, token).await;
    assert_eq!(view["grants"][0]["features"], none);
    assert_eq!(view["grants"][0]["features_revision"], 1);
    assert_eq!(view["grants"][0]["revocation_pending"], true);
    // The service doorbell can validate only its own exact pending revision.
    let anchor_id = "feature-close-test-anchor";
    app.db.collection::<bson::Document>("agents").update_one(bson::doc! { "_id": aid }, bson::doc! { "$set": {
        "exec_anchor": { "anchored_at": bson::DateTime::now(), "anchored_by": inviter, "anchor_id": anchor_id }
    }}).await.unwrap();
    let tid = bson::oid::ObjectId::parse_str(&s.tenant_id).unwrap();
    let service = app
        .state
        .fleet()
        .auth
        .issue_agent_service_token(aid, tid, anchor_id)
        .unwrap();
    let pending_url = app.url(&format!(
        "/api/agent/service/temporary/{id}/features/pending?expected_revision=1"
    ));
    let response = app
        .client
        .get(&pending_url)
        .bearer_auth(&service)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let evidence: Value = response.json().await.unwrap();
    assert_eq!(evidence["agent_id"], enrolled["agent_id"]);
    assert_eq!(evidence["features_revision"], 1);
    assert_eq!(evidence["revocation_pending"], true);
    for credential in [token, s.admin.access_token.as_str()] {
        assert_eq!(
            app.client
                .get(&pending_url)
                .bearer_auth(credential)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            401
        );
    }
    assert_eq!(
        app.client
            .get(pending_url.replace("revision=1", "revision=0"))
            .bearer_auth(&service)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    let other_org = app.seed_tenant("tinv-linked-service").await;
    let other_tid = bson::oid::ObjectId::parse_str(&other_org.tenant_id).unwrap();
    let other_owner = bson::oid::ObjectId::parse_str(&other_org.admin.id).unwrap();
    let other_aid = bson::oid::ObjectId::new();
    let mut other = app
        .db
        .collection::<bson::Document>("agents")
        .find_one(bson::doc! { "_id": aid })
        .await
        .unwrap()
        .unwrap();
    other.insert("_id", other_aid);
    // Deliberately SAME machine_id: a name must never prove host identity.
    other.insert("tenant_id", other_tid);
    other.insert("owner_user_id", other_owner);
    app.db
        .collection::<bson::Document>("agents")
        .insert_one(other)
        .await
        .unwrap();
    let other_service = app
        .state
        .fleet()
        .auth
        .issue_agent_service_token(other_aid, other_tid, anchor_id)
        .unwrap();
    assert_eq!(
        app.client
            .get(&pending_url)
            .bearer_auth(&other_service)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    let host_token = app
        .state
        .fleet()
        .auth
        .issue_agent_token(other_aid, other_tid, 0, None)
        .unwrap();
    let linked: Value = app
        .client
        .post(app.url("/api/agent/self/link"))
        .bearer_auth(&host_token)
        .json(&json!({ "proofs": [{ "invite_id": id, "proof": redeemed["device_proof"] }] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(linked["linked"], 1, "{linked}");
    let (account_token, _) = app
        .state
        .fleet()
        .auth
        .issue_enrollment_token(other_owner, other_tid, 600)
        .unwrap();
    assert_eq!(
        enroll(&app, &account_token, "select-host").await.0,
        403,
        "known linked-primary machine_id plus account token is not host proof"
    );
    assert_eq!(app.client.post(app.url("/api/agent/enroll")).bearer_auth(token)
        .json(&json!({"enrollment_token":account_token,"machine_id":"select-host","machine_name":"select-host","os":"windows","agent_version":"test"}))
        .send().await.unwrap().status().as_u16(), 403,
        "another membership credential cannot re-sign the linked primary");
    let linked_response = app
        .client
        .get(&pending_url)
        .bearer_auth(&other_service)
        .send()
        .await
        .unwrap();
    assert_eq!(linked_response.status().as_u16(), 200);
    let linked_body: Value = linked_response.json().await.unwrap();
    assert_eq!(linked_body["agent_id"], enrolled["agent_id"]);
    assert_eq!(linked_body["host_agent_id"], other_aid.to_hex());
    assert!(
        meshharbor_mod_fleet::device_invite::host_revocation_pending(app.state.fleet(), other_aid)
            .await
            .unwrap()
    );
    assert!(
        !meshharbor_mod_fleet::device_invite::service_request_is_current(
            app.state.fleet(),
            other_aid,
            bson::DateTime::now()
        )
        .await
        .unwrap()
    );
    assert_eq!(
        meshharbor_mod_fleet::device_invite::features_for_caller(
            app.state.fleet(),
            other_aid,
            other_owner
        )
        .await
        .unwrap(),
        Some(meshharbor_remote_control::models::DeviceAccessFeatures::none())
    );

    app.db
        .collection::<bson::Document>(meshharbor_mod_fleet::device_invite::COLLECTION)
        .update_one(
            bson::doc! { "agent_id": aid },
            bson::doc! { "$pull": { "hosts": { "agent_id": other_aid, "tenant_id": other_tid } } },
        )
        .await
        .unwrap();
    assert_eq!(
        app.client
            .get(&pending_url)
            .bearer_auth(&other_service)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert!(
        !meshharbor_mod_fleet::device_invite::service_request_is_current(
            app.state.fleet(),
            aid,
            authorized_before
        )
        .await
        .unwrap()
    );
    for collection in ["exec_pending", "ssh_pending"] {
        let old = app
            .db
            .collection::<bson::Document>(collection)
            .find_one(bson::doc! { "agent_id": aid })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old.get_str("state").unwrap(), "cancelled");
    }

    // The inviter is the Agent owner, but the selected ceiling still wins.
    assert_eq!(
        meshharbor_mod_fleet::device_invite::features_for_caller(app.state.fleet(), aid, inviter)
            .await
            .unwrap(),
        Some(meshharbor_remote_control::models::DeviceAccessFeatures::none())
    );
    assert!(
        meshharbor_mod_fleet::device_invite::end_keeping_device(app.state.fleet(), aid, inviter)
            .await
            .is_err()
    );
    let ack_path = app.url(&format!("/api/agent/self/temporary/{id}/features/ack"));
    assert_eq!(
        app.client
            .post(&ack_path)
            .bearer_auth(token)
            .json(&json!({"expected_revision":0,"closed":true}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        409
    );
    assert_eq!(
        app.client
            .post(&ack_path)
            .bearer_auth(&s.admin.access_token)
            .json(&json!({"expected_revision":1,"closed":true}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        app.client
            .post(&ack_path)
            .bearer_auth(token)
            .json(&json!({"expected_revision":1,"closed":false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    assert_eq!(
        app.client
            .post(&ack_path)
            .bearer_auth(&host_token)
            .json(&json!({"expected_revision":1,"closed":true}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    let ack = app
        .client
        .post(&ack_path)
        .bearer_auth(token)
        .json(&json!({"expected_revision":1,"closed":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(ack.status().as_u16(), 200);
    let acked: Value = ack.json().await.unwrap();
    assert_eq!(acked["revocation_pending"], false);
    assert_eq!(acked["enrollment_removed"], false);
    assert!(
        !meshharbor_mod_fleet::device_invite::stored_service_epoch_current(
            app.state.fleet(),
            aid,
            "exec_pending",
            "request_id",
            "obsolete-exec"
        )
        .await
        .unwrap(),
        "pre-change epochs stay stale after ACK"
    );
    assert!(
        !meshharbor_mod_fleet::device_invite::stored_service_epoch_current(
            app.state.fleet(),
            aid,
            "ssh_pending",
            "grant_id",
            "obsolete-ssh"
        )
        .await
        .unwrap()
    );
    assert_eq!(
        app.client
            .post(&ack_path)
            .bearer_auth(token)
            .json(&json!({"expected_revision":1,"closed":true}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    // Restore proof and expire during a second close transaction.
    let linked: Value = app
        .client
        .post(app.url("/api/agent/self/link"))
        .bearer_auth(&host_token)
        .json(&json!({"proofs":[{"invite_id":id,"proof":redeemed["device_proof"]}]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(linked["linked"], 1);
    let next = app
        .client
        .post(app.url(&path))
        .bearer_auth(token)
        .json(&json!({"features":selected,"expected_revision":1}))
        .send()
        .await
        .unwrap();
    assert_eq!(next.status().as_u16(), 202);
    assert_eq!(
        app.client
            .post(&ack_path)
            .bearer_auth(token)
            .json(&json!({"expected_revision":1,"closed":true}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        409,
        "an old ACK cannot succeed once the next CAS revision is pending"
    );
    assert!(
        meshharbor_mod_fleet::device_invite::host_revocation_pending(app.state.fleet(), other_aid)
            .await
            .unwrap()
    );
    app.db
        .collection::<bson::Document>(meshharbor_mod_fleet::device_invite::COLLECTION)
        .update_one(
            bson::doc! { "agent_id": aid },
            bson::doc! { "$set": { "access_until": bson::DateTime::from_millis(1) } },
        )
        .await
        .unwrap();
    assert_eq!(
        app.client
            .get(pending_url.replace("revision=1", "revision=2"))
            .bearer_auth(&service)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    let expired_view = self_view(&app, token).await;
    assert_eq!(expired_view["grants"][0]["revocation_pending"], true);
    assert_eq!(
        meshharbor_mod_fleet::device_invite::reap_once(app.state.fleet())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        meshharbor_mod_fleet::device_invite::features_for_caller(app.state.fleet(), aid, inviter)
            .await
            .unwrap(),
        Some(meshharbor_remote_control::models::DeviceAccessFeatures::none())
    );
    let discovered = &expired_view["grants"][0];
    let completed = app
        .client
        .post(app.url(&format!(
            "/api/agent/self/temporary/{}/features/ack",
            discovered["invite_id"].as_str().unwrap()
        )))
        .bearer_auth(token)
        .json(&json!({"expected_revision":discovered["features_revision"],"closed":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(completed.status().as_u16(), 200);
    let completed: Value = completed.json().await.unwrap();
    assert_eq!(completed["revocation_pending"], false);
    assert_eq!(completed["enrollment_removed"], true);
    assert!(
        app.state
            .fleet()
            .agents
            .base
            .find_by_id(aid)
            .await
            .unwrap()
            .deleted_at
            .is_some()
    );
    assert!(
        !meshharbor_mod_fleet::device_invite::host_revocation_pending(app.state.fleet(), other_aid)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn organization_token_cannot_impersonate_an_invited_host_and_expiry_stays_closed() {
    let app = enabled_app().await;
    let s = app.seed_tenant("tinv-no-impersonation").await;
    let (_, inv) = create(&app, &s, &s.admin.access_token, 3600).await;
    let (_, redeemed) = redeem(&app, inv["code"].as_str().unwrap(), "held-host").await;
    let (status, enrolled) = enroll(
        &app,
        redeemed["enrollment_token"].as_str().unwrap(),
        "held-machine",
    )
    .await;
    assert_eq!(status, 200);
    let aid = bson::oid::ObjectId::parse_str(enrolled["agent_id"].as_str().unwrap()).unwrap();
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
    let (status, body) = enroll(
        &app,
        ordinary["enrollment_token"].as_str().unwrap(),
        "held-machine",
    )
    .await;
    assert_eq!(
        status, 403,
        "known-machine replay must not mint host authority: {body}"
    );
    assert!(body["agent_token"].is_null());
    app.db
        .collection::<bson::Document>(meshharbor_mod_fleet::device_invite::COLLECTION)
        .update_many(
            bson::doc! { "agent_id": aid },
            bson::doc! { "$set": { "access_until": bson::DateTime::from_millis(1) }},
        )
        .await
        .unwrap();
    let user = bson::oid::ObjectId::parse_str(&s.admin.id).unwrap();
    assert!(
        meshharbor_mod_fleet::device_invite::live_for_agent(app.state.fleet(), aid)
            .await
            .unwrap()
            .is_empty()
    );
    let expired = meshharbor_mod_fleet::device_invite::grant_for_agent(app.state.fleet(), aid)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !expired.allows(Some(user), &[]),
        "expiry is enforced before asynchronous reaping"
    );
    assert_eq!(
        meshharbor_mod_fleet::device_invite::features_for_caller(app.state.fleet(), aid, user)
            .await
            .unwrap(),
        Some(meshharbor_remote_control::models::DeviceAccessFeatures::none())
    );
}

#[tokio::test]
async fn proof_family_transitive_closure_freezes_all_four_identities_and_rotates_epochs() {
    use bson::{doc, oid::ObjectId};
    use meshharbor_mod_fleet::device_invite as invites;
    let app = enabled_app().await;
    let seed = app.seed_tenant("tinv-component").await;
    let (_, invitation) = create(&app, &seed, &seed.admin.access_token, 3600).await;
    let (_, redemption) = redeem(&app, invitation["code"].as_str().unwrap(), "component").await;
    let (_, enrollment) = enroll(
        &app,
        redemption["enrollment_token"].as_str().unwrap(),
        "component-t",
    )
    .await;
    let t = ObjectId::parse_str(enrollment["agent_id"].as_str().unwrap()).unwrap();
    let tid = ObjectId::parse_str(&seed.tenant_id).unwrap();
    let agents = app.db.collection::<bson::Document>("agents");
    let template = agents.find_one(doc! {"_id":t}).await.unwrap().unwrap();
    let (a, b, u) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    for id in [a, b, u] {
        let mut row = template.clone();
        row.insert("_id", id);
        row.insert("machine_id", id.to_hex());
        agents.insert_one(row).await.unwrap();
    }
    let rows = app.db.collection::<bson::Document>(invites::COLLECTION);
    rows.update_one(doc! {"agent_id":t}, doc! {"$set":{"hosts":[{"agent_id":a,"tenant_id":tid,"linked_at":bson::DateTime::now()},{"agent_id":b,"tenant_id":tid,"linked_at":bson::DateTime::now()}]}}).await.unwrap();
    let mut second = rows.find_one(doc! {"agent_id":t}).await.unwrap().unwrap();
    let second_id = ObjectId::new();
    second.insert("_id", second_id);
    second.insert("agent_id", u);
    second.insert(
        "hosts",
        bson::bson!([{ "agent_id":b,"tenant_id":tid,"linked_at":bson::DateTime::now() }]),
    );
    // Independent invitation uniqueness keys.
    second.insert("code_hash", second_id.to_hex());
    second.insert("enrollment_jti", second_id.to_hex());
    rows.insert_one(second).await.unwrap();
    let before = invites::authorization_epoch(app.state.fleet(), a)
        .await
        .unwrap();
    rows.update_one(
        doc! {"_id":second_id},
        doc! {"$set":{"revocation_pending":true,"features_revision":1}},
    )
    .await
    .unwrap();
    for id in [a, b, t, u] {
        assert!(
            invites::host_revocation_pending(app.state.fleet(), id)
                .await
                .unwrap(),
            "{id} must freeze"
        );
    }
    assert_ne!(
        before,
        invites::authorization_epoch(app.state.fleet(), a)
            .await
            .unwrap()
    );
    rows.update_one(
        doc! {"_id":second_id},
        doc! {"$set":{"revocation_pending":false}},
    )
    .await
    .unwrap();
    for id in [a, b, t, u] {
        assert!(
            !invites::host_revocation_pending(app.state.fleet(), id)
                .await
                .unwrap()
        );
    }
    let oversized: Vec<bson::Document> = (0..101)
        .map(|_| {
            doc! {
                "agent_id":ObjectId::new(),"tenant_id":tid,"linked_at":bson::DateTime::now()
            }
        })
        .chain(std::iter::once(
            doc! {"agent_id":b,"tenant_id":tid,"linked_at":bson::DateTime::now()},
        ))
        .collect();
    rows.update_one(doc! {"_id":second_id}, doc! {"$set":{"hosts":oversized}})
        .await
        .unwrap();
    assert!(
        invites::host_revocation_pending(app.state.fleet(), a)
            .await
            .is_err(),
        "oversized proof components fail closed"
    );
    rows.update_one(
        doc! {"_id":second_id},
        doc! {"$set":{"hosts":[{"agent_id":b,"tenant_id":tid,"linked_at":bson::DateTime::now()}]}},
    )
    .await
    .unwrap();
    let owner = ObjectId::parse_str(&seed.admin.id).unwrap();
    let (account_token, _) = app
        .state
        .fleet()
        .auth
        .issue_enrollment_token(owner, tid, 600)
        .unwrap();
    assert_eq!(enroll(&app, &account_token, &a.to_hex()).await.0, 403);
    let credential = app
        .state
        .fleet()
        .auth
        .issue_agent_token(a, tid, 0, None)
        .unwrap();
    let response=app.client.post(app.url("/api/agent/enroll")).bearer_auth(credential)
        .json(&json!({"enrollment_token":account_token,"machine_id":a.to_hex(),"machine_name":"A","os":"windows","agent_version":"test"}))
        .send().await.unwrap();
    assert_eq!(
        response.status().as_u16(),
        200,
        "{}",
        response.text().await.unwrap()
    );
    let network = app.state.modules.network.as_ref().unwrap();
    let node = access_test_node(&app, tid, a, &a.to_hex()).await;
    network
        .overlay_nodes
        .mark_status(
            node.id.unwrap(),
            meshharbor_remote_control::models::AgentStatus::Offline,
        )
        .await
        .unwrap();
    meshharbor_mod_network::overlay::sync_temporary_mark(network, tid, a)
        .await
        .unwrap();
    let (ready, resume) = meshharbor_mod_network::overlay::pause_next_access_projection(network, a);
    let st = network.clone();
    let old = tokio::spawn(async move {
        meshharbor_mod_network::overlay::sync_temporary_mark(&st, tid, a).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    rows.update_one(
        doc! {"_id":second_id},
        doc! {"$set":{"revocation_pending":true,"features_revision":2}},
    )
    .await
    .unwrap();
    meshharbor_mod_network::overlay::refresh_access_authority(network, tid, a)
        .await
        .unwrap();
    let denied = network
        .overlay_nodes
        .base
        .find_by_id(node.id.unwrap())
        .await
        .unwrap();
    assert!(
        denied.temporary.is_none(),
        "ordinary primary, not an invited target"
    );
    assert_eq!(
        denied.personal_access_owner_id,
        Some(ObjectId::from_bytes([0; 12]))
    );
    let raw_nodes = app.db.collection::<bson::Document>("overlay_nodes");
    let before = raw_nodes
        .find_one(doc! {"_id":node.id})
        .await
        .unwrap()
        .unwrap();
    resume.notify_one();
    assert!(
        old.await.unwrap().is_err(),
        "stale pre-revocation projection must not commit or fan"
    );
    let after = raw_nodes
        .find_one(doc! {"_id":node.id})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        before.get_i64("access_projection_revision"),
        after.get_i64("access_projection_revision")
    );
    assert_eq!(
        after.get_object_id("personal_access_owner_id"),
        Ok(ObjectId::from_bytes([0; 12]))
    );
}

/// Faults are injected at the actual strict refresh operation boundaries, not
/// by replacing the HTTP endpoint or acknowledging an unexecuted refresh.
#[tokio::test]
async fn capability_refresh_faults_remain_pending_and_retry_from_durable_activation() {
    use bson::{doc, oid::ObjectId};
    use meshharbor_mod_network::overlay::inject_access_refresh_fault;
    use meshharbor_remote_control::models::{DeviceAccessFeatures, NodeRef};
    use meshharbor_services::dao::overlay_node::NewOverlayNode;
    let app = enabled_app().await;
    let seed = app.seed_tenant("tinv-refresh-faults").await;
    let (_, inv) = create(&app, &seed, &seed.admin.access_token, 3600).await;
    let (_, redeemed) = redeem(&app, inv["code"].as_str().unwrap(), "refresh-host").await;
    let (_, enrolled) = enroll(
        &app,
        redeemed["enrollment_token"].as_str().unwrap(),
        "refresh-host",
    )
    .await;
    let aid = ObjectId::parse_str(enrolled["agent_id"].as_str().unwrap()).unwrap();
    let tid = ObjectId::parse_str(&seed.tenant_id).unwrap();
    let token = enrolled["agent_token"].as_str().unwrap();
    let view = self_view(&app, token).await;
    let iid = view["grants"][0]["invite_id"].as_str().unwrap();
    let oid = ObjectId::parse_str(iid).unwrap();
    let path = app.url(&format!("/api/agent/self/temporary/{iid}/features"));
    let ack = app.url(&format!("/api/agent/self/temporary/{iid}/features/ack"));
    let network = app.state.modules.network.as_ref().unwrap();
    let net = network.overlay_networks.get_or_create(tid).await.unwrap();
    let nid = net.id.unwrap();
    let node = network
        .overlay_nodes
        .create(NewOverlayNode {
            supports_invite_deadlines: true,
            personal_access_owner_id: None,
            temporary: None,
            tenant_id: tid,
            node_ref: NodeRef::Agent { agent_id: aid },
            network_id: nid,
            machine_id: "refresh-host".into(),
            name: "refresh-host".into(),
            overlay_ip: "100.64.0.77".into(),
            wg_public_key: "refresh-key".into(),
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
    network
        .overlay_nodes
        .mark_status(
            node.id.unwrap(),
            meshharbor_remote_control::models::AgentStatus::Offline,
        )
        .await
        .unwrap();
    let rows = app
        .db
        .collection::<bson::Document>(meshharbor_mod_fleet::device_invite::COLLECTION);
    for (index, stage) in ["network", "nodes", "refan", "publish"]
        .into_iter()
        .enumerate()
    {
        let revision = index as u32 + 1;
        inject_access_refresh_fault(tid, stage, 0);
        let response = app
            .client
            .post(&path)
            .bearer_auth(token)
            .json(&json!({"features":DeviceAccessFeatures::all(),"expected_revision":revision-1}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            503,
            "{stage}: selected state is not reported as synchronized"
        );
        let marked = network
            .overlay_nodes
            .base
            .find_by_id(node.id.unwrap())
            .await
            .unwrap();
        assert_eq!(
            marked.personal_access_owner_id,
            Some(ObjectId::from_bytes([0; 12])),
            "mark persisted before {stage} failed"
        );
        assert!(
            self_view(&app, token).await["grants"][0]["revocation_pending"]
                .as_bool()
                .unwrap()
        );
        // Frozen pass succeeds, activation pass fails at the same operation.
        inject_access_refresh_fault(tid, stage, 1);
        let response = app
            .client
            .post(&ack)
            .bearer_auth(token)
            .json(&json!({"expected_revision":revision,"closed":true}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            503,
            "{stage}: partial activation is not ACK success"
        );
        let pending = rows.find_one(doc! {"_id":oid}).await.unwrap().unwrap();
        assert_eq!(pending.get_bool("revocation_pending"), Ok(false));
        assert_eq!(pending.get_bool("activation_pending"), Ok(true));
        assert!(!pending.contains_key("revocation_acked_revision"));
        assert!(
            meshharbor_mod_fleet::device_invite::host_revocation_pending(app.state.fleet(), aid)
                .await
                .unwrap()
        );
        let selected = meshharbor_mod_fleet::device_invite::features_for_caller(
            app.state.fleet(),
            aid,
            ObjectId::parse_str(&seed.admin.id).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            selected,
            Some(DeviceAccessFeatures::none()),
            "applications frozen during activation"
        );
        let effective = self_view(&app, token).await;
        assert_eq!(effective["grants"][0]["revocation_pending"], true);
        assert_eq!(effective["grants"][0]["activation_pending"], true);
        let response = app
            .client
            .post(&ack)
            .bearer_auth(token)
            .json(&json!({"expected_revision":revision,"closed":true}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            200,
            "{stage}: retry must recover"
        );
        assert!(
            !meshharbor_mod_fleet::device_invite::host_revocation_pending(app.state.fleet(), aid)
                .await
                .unwrap()
        );
        let restored = network
            .overlay_nodes
            .base
            .find_by_id(node.id.unwrap())
            .await
            .unwrap();
        assert_eq!(restored.personal_access_owner_id, None);
        assert_eq!(
            restored.temporary.unwrap().feature_grants[0].features,
            Some(DeviceAccessFeatures::all())
        );
        assert!(
            network.derp_acl.contains_key(&nid),
            "relay cache rebuilt before success"
        );
    }
    // Activation is cleanup-only after expiry: retain identity until retry,
    // never restore the expired grant, then remove its enrollment normally.
    assert_eq!(
        app.client
            .post(&path)
            .bearer_auth(token)
            .json(&json!({"features":DeviceAccessFeatures::all(),"expected_revision":4}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        202
    );
    inject_access_refresh_fault(tid, "publish", 1);
    assert_eq!(
        app.client
            .post(&ack)
            .bearer_auth(token)
            .json(&json!({"expected_revision":5,"closed":true}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        503
    );
    rows.update_one(
        doc! {"_id":oid},
        doc! {"$set":{"access_until":bson::DateTime::from_millis(1)}},
    )
    .await
    .unwrap();
    assert_eq!(
        meshharbor_mod_fleet::device_invite::reap_once(app.state.fleet())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        self_view(&app, token).await["grants"][0]["activation_pending"],
        true
    );
    let (account, _) = app
        .state
        .fleet()
        .auth
        .issue_enrollment_token(ObjectId::parse_str(&seed.admin.id).unwrap(), tid, 600)
        .unwrap();
    assert_eq!(
        enroll(&app, &account, "refresh-host").await.0,
        403,
        "expired activation still requires host possession"
    );
    assert_eq!(
        app.client
            .post(&ack)
            .bearer_auth(token)
            .json(&json!({"expected_revision":4,"closed":true}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        409
    );
    let done = app
        .client
        .post(&ack)
        .bearer_auth(token)
        .json(&json!({"expected_revision":5,"closed":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(done.status().as_u16(), 200);
    let done: Value = done.json().await.unwrap();
    assert_eq!(done["enrollment_removed"], true);
}

async fn access_test_node(
    app: &TestApp,
    tid: bson::oid::ObjectId,
    aid: bson::oid::ObjectId,
    machine: &str,
) -> meshharbor_remote_control::models::OverlayNode {
    use base64::Engine;
    use meshharbor_remote_control::models::NodeRef;
    use meshharbor_services::dao::overlay_node::NewOverlayNode;
    let n = app.state.modules.network.as_ref().unwrap();
    let net = n.overlay_networks.get_or_create(tid).await.unwrap();
    let temporary = meshharbor_mod_fleet::device_invite::grant_for_agent(app.state.fleet(), aid)
        .await
        .unwrap()
        .as_ref()
        .map(meshharbor_mod_network::overlay::temporary_mark_of);
    n.overlay_nodes
        .create(NewOverlayNode {
            supports_invite_deadlines: true,
            personal_access_owner_id: None,
            temporary,
            tenant_id: tid,
            node_ref: NodeRef::Agent { agent_id: aid },
            network_id: net.id.unwrap(),
            machine_id: machine.into(),
            name: machine.into(),
            overlay_ip: "100.64.0.88".into(),
            wg_public_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
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
        .unwrap()
}

#[tokio::test]
async fn receiver_failure_and_old_connection_ack_cannot_complete_activation() {
    use bson::{doc, oid::ObjectId};
    use meshharbor_mod_network::overlay::{self, NodeIdentity};
    use meshharbor_remote_control::{
        models::{DeviceAccessFeatures, OsKind},
        signaling::{ClientMsg, ServerMsg},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let (app, receiver) = TestApp::spawn_pair(|s| {
        s.auth.native_device_invite_enabled = true;
        s.redis.url = std::env::var("MESHHARBOR__REDIS__URL").expect("isolated Redis URL required");
    })
    .await;
    let seed = app.seed_tenant("tinv-apply-barrier").await;
    let (_, inv) = create(&app, &seed, &seed.admin.access_token, 3600).await;
    let (_, redeemed) = redeem(&app, inv["code"].as_str().unwrap(), "barrier-host").await;
    let (_, enrolled) = enroll(
        &app,
        redeemed["enrollment_token"].as_str().unwrap(),
        "barrier-host",
    )
    .await;
    let aid = ObjectId::parse_str(enrolled["agent_id"].as_str().unwrap()).unwrap();
    let tid = ObjectId::parse_str(&seed.tenant_id).unwrap();
    let owner = ObjectId::parse_str(&seed.admin.id).unwrap();
    let token = enrolled["agent_token"].as_str().unwrap();
    let view = self_view(&app, token).await;
    let iid = view["grants"][0]["invite_id"].as_str().unwrap();
    let oid = ObjectId::parse_str(iid).unwrap();
    let features = app.url(&format!("/api/agent/self/temporary/{iid}/features"));
    let ack = app.url(&format!("/api/agent/self/temporary/{iid}/features/ack"));
    let node = access_test_node(&app, tid, aid, "barrier-host").await;
    let target = receiver.state.modules.network.as_ref().unwrap();
    let redis = receiver
        .state
        .redis_pubsub
        .as_ref()
        .expect("real Redis required");
    let (_tx, _cancel, mut rx) =
        target
            .fleet
            .rc_hub
            .register_agent(aid, tid, owner, OsKind::Windows, 1, false, false);
    target.org_relay.bind_live_conn(aid, "old-connection");
    redis
        .agent_presence_set(
            &aid.to_hex(),
            &redis.agent_owner_token("old-connection", bson::DateTime::now().timestamp_millis()),
        )
        .await
        .unwrap();
    let join = |instance: &str| {
        serde_json::from_value::<ClientMsg>(json!({"t":"rc:overlay.join","wg_public_key":node.wg_public_key,
        "mtu":1280,"supported":["wireguard-v1"],"supports_invite_deadlines":true,"instance":instance})).unwrap()
    };
    overlay::relay_overlay_msg_from_node(
        target,
        NodeIdentity::Agent(aid),
        "old-connection",
        join("old-process"),
    )
    .await;
    let enabled = Arc::new(AtomicBool::new(true));
    let connection = Arc::new(tokio::sync::Mutex::new("old-connection".to_string()));
    let latest = Arc::new(tokio::sync::Mutex::new((0u64, 0u64)));
    let st = target.clone();
    let flag = enabled.clone();
    let conn = connection.clone();
    let seen = latest.clone();
    let apply = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let ServerMsg::OverlayNetmap { epoch, network, .. } = msg {
                *seen.lock().await = (epoch, network.auth_revision);
                if flag.load(Ordering::SeqCst) {
                    let current = conn.lock().await.clone();
                    overlay::relay_overlay_msg_from_node(
                        &st,
                        NodeIdentity::Agent(aid),
                        &current,
                        ClientMsg::OverlayNetmapAck {
                            epoch,
                            auth_revision: network.auth_revision,
                        },
                    )
                    .await;
                }
            }
        }
    });
    for _ in 0..100 {
        if app.state.redis_sub_alive.load(Ordering::Relaxed)
            && receiver.state.redis_sub_alive.load(Ordering::Relaxed)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        app.state.redis_sub_alive.load(Ordering::Relaxed)
            && receiver.state.redis_sub_alive.load(Ordering::Relaxed)
    );
    overlay::inject_access_refresh_fault_on_pod(target, tid, "receiver", 0);
    let response = app
        .client
        .post(&features)
        .bearer_auth(token)
        .json(&json!({"features":DeviceAccessFeatures::all(),"expected_revision":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        503,
        "PUBLISH success must not substitute for receiver apply"
    );
    assert_eq!(
        self_view(&app, token).await["grants"][0]["revocation_pending"],
        true
    );
    // Frozen pass acknowledged; receiver fails only the activation pass.
    overlay::inject_access_refresh_fault_on_pod(target, tid, "receiver", 1);
    let response = app
        .client
        .post(&ack)
        .bearer_auth(token)
        .json(&json!({"expected_revision":1,"closed":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
    let rows = app
        .db
        .collection::<bson::Document>(meshharbor_mod_fleet::device_invite::COLLECTION);
    assert_eq!(
        rows.find_one(doc! {"_id":oid})
            .await
            .unwrap()
            .unwrap()
            .get_bool("activation_pending"),
        Ok(true)
    );
    let old = *latest.lock().await;
    overlay::relay_overlay_msg_from_node(
        target,
        NodeIdentity::Agent(aid),
        "old-connection",
        ClientMsg::OverlayNetmapAck {
            epoch: old.0,
            auth_revision: old.1,
        },
    )
    .await;
    assert_eq!(
        self_view(&app, token).await["grants"][0]["revocation_pending"],
        true
    );
    enabled.store(false, Ordering::SeqCst);
    let client = app.client.clone();
    let url = ack.clone();
    let credential = token.to_string();
    let waiting = tokio::spawn(async move {
        client
            .post(url)
            .bearer_auth(credential)
            .json(&json!({"expected_revision":1,"closed":true}))
            .send()
            .await
            .unwrap()
    });
    for _ in 0..100 {
        if latest.lock().await.1 > old.1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(latest.lock().await.1 > old.1);
    // A stale old connection offers deadline support=true; a newer connection
    // offers false. Suspend the old computed write until the new CAS commits.
    let (computed, resume_old) = overlay::pause_next_access_projection(target, aid);
    let old_join = join("old-process");
    let old_state = target.clone();
    let stale_join = tokio::spawn(async move {
        overlay::relay_overlay_msg_from_node(
            &old_state,
            NodeIdentity::Agent(aid),
            "old-connection",
            old_join,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), computed.notified())
        .await
        .unwrap();
    target.org_relay.bind_live_conn(aid, "new-connection");
    *connection.lock().await = "new-connection".into();
    redis
        .agent_presence_set(
            &aid.to_hex(),
            &redis.agent_owner_token("new-connection", bson::DateTime::now().timestamp_millis()),
        )
        .await
        .unwrap();
    let mut new_join = join("new-process");
    if let ClientMsg::OverlayJoin {
        supports_invite_deadlines,
        ..
    } = &mut new_join
    {
        *supports_invite_deadlines = false;
    }
    overlay::relay_overlay_msg_from_node(
        target,
        NodeIdentity::Agent(aid),
        "new-connection",
        new_join,
    )
    .await;
    let caps_after_new = app
        .db
        .collection::<bson::Document>("overlay_nodes")
        .find_one(doc! {"_id":node.id})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        caps_after_new.get_bool("supports_invite_deadlines"),
        Ok(false)
    );
    resume_old.notify_one();
    stale_join.await.unwrap();
    let caps_after_old = app
        .db
        .collection::<bson::Document>("overlay_nodes")
        .find_one(doc! {"_id":node.id})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        caps_after_old.get_bool("supports_invite_deadlines"),
        Ok(false),
        "late true capability must not overwrite the newer false connection"
    );
    assert_eq!(
        caps_after_old.get_i64("access_projection_revision"),
        caps_after_new.get_i64("access_projection_revision")
    );
    let current = *latest.lock().await;
    overlay::relay_overlay_msg_from_node(
        target,
        NodeIdentity::Agent(aid),
        "old-connection",
        ClientMsg::OverlayNetmapAck {
            epoch: current.0,
            auth_revision: current.1,
        },
    )
    .await;
    assert_eq!(
        waiting.await.unwrap().status().as_u16(),
        503,
        "reconnect invalidates the previous connection's barrier"
    );
    let raw = app
        .db
        .collection::<bson::Document>("overlay_nodes")
        .find_one(doc! {"_id":node.id})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.get_str("access_connection_id"), Ok("new-connection"));
    assert!(
        raw.get_str("access_applied_connection_id").is_err(),
        "old connection ACK cannot populate new receipt"
    );
    enabled.store(true, Ordering::SeqCst);
    let response = app
        .client
        .post(&ack)
        .bearer_auth(token)
        .json(&json!({"expected_revision":1,"closed":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        200,
        "new connection's actual matching full-map ACK completes activation"
    );
    let raw = app
        .db
        .collection::<bson::Document>("overlay_nodes")
        .find_one(doc! {"_id":node.id})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        raw.get_str("access_applied_connection_id"),
        Ok("new-connection")
    );
    assert_eq!(
        self_view(&app, token).await["grants"][0]["revocation_pending"],
        false
    );
    apply.abort();
}

#[tokio::test]
async fn live_websocket_presence_token_uses_the_exact_overlay_connection_identity() {
    use bson::oid::ObjectId;
    let app = enabled_app().await;
    let seed = app.seed_tenant("access-conn-binding").await;
    let (id, token) = crate::agent_presence_tests::enroll(&app, &seed, "access-conn-binding").await;
    let aid = ObjectId::parse_str(&id).unwrap();
    let mut ws = crate::agent_presence_tests::connect_agent(&app, &token).await;
    let network = app.state.modules.network.as_ref().unwrap();
    let redis = app
        .state
        .redis_pubsub
        .as_ref()
        .expect("isolated Redis must be live");
    let mut observed = None;
    for _ in 0..100 {
        let connection =
            meshharbor_mod_network::org_relay::candidate_test_support::current_connection_id(
                network, aid,
            );
        let token = redis
            .agent_presence_get_many(&[id.clone()])
            .await
            .unwrap()
            .pop()
            .flatten();
        if let (Some(connection), Some(token)) = (connection, token) {
            observed = Some((connection, token));
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let (connection, token) =
        observed.expect("real WebSocket registered on both overlay and presence paths");
    let owner = meshharbor_core::cluster::directory::OwnerRecord::parse(&token).unwrap();
    assert_eq!(
        owner.extra, connection,
        "presence must not generate an unrelated random UUID"
    );
    assert_eq!(
        format!("{}/{}", owner.pod_id, owner.epoch),
        app.state.pod.origin()
    );
    ws.close(None).await.unwrap();
}
