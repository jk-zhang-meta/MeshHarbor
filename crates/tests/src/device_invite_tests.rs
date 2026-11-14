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
