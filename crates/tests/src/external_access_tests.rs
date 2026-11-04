// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-52 P1 — the cross-org access admin surface, end to end: the org switch
//! (gate 1), per-device approval (gate 2) with its compound permission and its
//! audit rows, the connect code (§5), and the two leaks a careless wiring
//! would introduce.
//!
//! What these lock is the WIRING. `decide_approval` is unit-tested in the api
//! crate; a handler that stops calling it, or audits only one arm, passes every
//! unit test and fails here.
//!
//! ⚠️ P1 ships **no access path**. Nothing in this file opens a session — the
//! handshake lands in P3/P4. These tests assert the policy surface and the
//! record of it, which is all there is to assert yet.

use crate::fixtures::{seed::SeededTenant, test_app::TestApp};
use bson::{doc, oid::ObjectId};
use meshharbor_db::models::role::permissions::MANAGE_AGENTS;
use meshharbord::{config::AgentConfig, enrollment};
use serde_json::{Value, json};

fn url(seeded: &SeededTenant, tail: &str) -> String {
    format!("/api/tenant/{}{}", seeded.tenant_id, tail)
}

async fn get(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let resp = app.auth_get(path, token).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn put(app: &TestApp, path: &str, token: &str, body: Value) -> (u16, Value) {
    let resp = app.auth_put(path, token).json(&body).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn post(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let resp = app
        .auth_post(path, token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Enrol a device so there is a row to approve. No WS on purpose: approval is
/// a row edit, and an OFFLINE device is approvable — it simply cannot be
/// reached until it comes up.
async fn enrol(app: &TestApp, seeded: &SeededTenant, machine_id: &str) -> AgentConfig {
    let et: Value = app
        .auth_post(
            &url(seeded, "/agent/enroll-token"),
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
        machine_name: "External access test host",
        install: None,
    })
    .await
    .expect("agent enrollment")
}

/// Stamp the `external-access` capability onto a device row.
///
/// A freshly enrolled device has never said a hello, so it advertises nothing
/// and gate 2 refuses it — which is correct, and is itself asserted below.
/// Writing the verb directly is the cheapest way to get past that without a
/// live agent WS; the SHAPE of the value is what matters, and it is the same
/// `capabilities.rpc` list a hello writes.
async fn mark_supported(app: &TestApp, agent_id: &str) {
    let oid = ObjectId::parse_str(agent_id).unwrap();
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": oid },
            doc! { "$set": { "capabilities.rpc": ["external-access"] } },
        )
        .await
        .expect("stamp the capability");
}

async fn create_role(app: &TestApp, seeded: &SeededTenant, name: &str, permissions: u64) -> String {
    let resp = app
        .auth_post(&url(seeded, "/role"), &seeded.admin.access_token)
        .json(&json!({ "name": name, "permissions": permissions }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "owner may mint {name}");
    let role: Value = resp.json().await.unwrap();
    role["id"].as_str().unwrap().to_string()
}

async fn assign_role(app: &TestApp, seeded: &SeededTenant, role_id: &str, user_id: &str) {
    let resp = app
        .auth_post(
            &url(seeded, &format!("/role/{role_id}/assign/{user_id}")),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "owner may assign a role");
}

/// Gate 1. Off on every tenant that existed before the feature; flipping it is
/// `MANAGE_TENANT` — an org-owner decision, because it decides whether this org
/// can be reached from outside at all. Reading the settings is `MANAGE_AGENTS`,
/// like every other fleet view.
#[tokio::test]
async fn org_switch_defaults_off_and_flipping_it_is_an_owner_decision() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extmode").await;
    let owner = &seeded.admin.access_token;
    let settings = url(&seeded, "/external-access");

    let (s, body) = get(&app, &settings, owner).await;
    assert_eq!(s, 200);
    assert_eq!(body["enabled"], json!(false), "closed by default");
    assert_eq!(body["devices"], json!([]));

    // A plain member can neither read nor flip it.
    let (s, _) = get(&app, &settings, &seeded.member.access_token).await;
    assert_eq!(s, 403);
    let (s, _) = put(
        &app,
        &settings,
        &seeded.member.access_token,
        json!({ "enabled": true }),
    )
    .await;
    assert_eq!(s, 403);
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(
        body["enabled"],
        json!(false),
        "a refused flip changes nothing"
    );

    // The owner flips it; the read reflects it.
    let (s, body) = put(&app, &settings, owner, json!({ "enabled": true })).await;
    assert_eq!(s, 200);
    assert_eq!(body["enabled"], json!(true));
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["enabled"], json!(true));

    // A fleet admin (DEFAULT_ADMIN carries MANAGE_AGENTS, not MANAGE_TENANT)
    // may read the settings but must not flip the org switch.
    let admin_role = create_role(
        &app,
        &seeded,
        "fleet-admin",
        meshharbor_db::models::role::permissions::DEFAULT_ADMIN,
    )
    .await;
    assign_role(&app, &seeded, &admin_role, &seeded.member.id).await;
    let (s, body) = get(&app, &settings, &seeded.member.access_token).await;
    assert_eq!(s, 200);
    assert_eq!(body["enabled"], json!(true));
    let (s, _) = put(
        &app,
        &settings,
        &seeded.member.access_token,
        json!({ "enabled": false }),
    )
    .await;
    assert_eq!(
        s, 403,
        "MANAGE_AGENTS alone must not flip the org switch — that is gate 1"
    );
}

/// Gate 2 and its audit. A plain member is refused; a `MANAGE_AGENTS`-only
/// custom role is refused for a GRANT but allowed to CLEAR; and EVERY
/// attempt — granted or refused — leaves a row.
#[tokio::test]
async fn approval_is_compound_clearing_is_not_and_both_arms_are_audited() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extappr").await;
    let owner = &seeded.admin.access_token;
    let member = &seeded.member.access_token;
    let cfg = enrol(&app, &seeded, "mach-ext-1").await;
    mark_supported(&app, &cfg.agent_id).await;
    let policy = url(
        &seeded,
        &format!("/agent/{}/external-access-policy", cfg.agent_id),
    );
    let settings = url(&seeded, "/external-access");
    let audit = url(&seeded, "/external-rc-audit");

    // 0. The audit reader is behind VIEW_REMOTE_AUDIT, which a plain member
    //    lacks.
    let (s, _) = get(&app, &audit, member).await;
    assert_eq!(s, 403);

    // 1. A plain member is not a device admin.
    let (s, body) = put(&app, &policy, member, json!({ "approved": true })).await;
    assert_eq!(s, 403, "{body}");

    // 2. A custom role with MANAGE_AGENTS but NOT REMOTE_CONTROL: may not
    //    grant. This is the case the compound gate actually bites on — the
    //    seeded `admin` role carries both bits, so it would not.
    let device_admin = create_role(&app, &seeded, "device-admin", MANAGE_AGENTS).await;
    assign_role(&app, &seeded, &device_admin, &seeded.member.id).await;
    let (s, body) = put(&app, &policy, member, json!({ "approved": true })).await;
    assert_eq!(s, 403);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("REMOTE_CONTROL"),
        "the refusal must name the missing permission, got {body}"
    );
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(
        body["devices"],
        json!([]),
        "a refused approval changes nothing"
    );

    // 3. The owner approves (ADMINISTRATOR bypass). The device is listed, with
    //    the RESOLVED ceiling — never an unset placeholder.
    let (s, body) = put(&app, &policy, owner, json!({ "approved": true })).await;
    assert_eq!(s, 200, "{body}");
    let (_, body) = get(&app, &settings, owner).await;
    let devices = body["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["id"], json!(cfg.agent_id));
    assert_eq!(
        devices[0]["max_permissions"],
        json!("VIEW | INPUT"),
        "an unset ceiling resolves to the NARROW default, never 'unrestricted'"
    );
    assert_eq!(
        devices[0]["connect_code"],
        Value::Null,
        "a code is minted on demand — approval alone does not make a device \
         reachable, and the view must say so"
    );

    // 4. The MANAGE_AGENTS-only role may CLEAR it. Revocation is not a grant.
    let (s, body) = put(&app, &policy, member, json!({ "approved": false })).await;
    assert_eq!(s, 200, "clearing needs only MANAGE_AGENTS: {body}");
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["devices"], json!([]));

    // 5. Every attempt is a row — including the two refusals. Without the
    //    refused rows, someone probing which devices they can open leaves no
    //    trace at all.
    let (s, body) = get(&app, &audit, owner).await;
    assert_eq!(s, 200);
    let items = body["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        4,
        "2 refusals + 1 approve + 1 clear, got {items:#?}"
    );
    let denied: Vec<&str> = items.iter().filter_map(|i| i["denied"].as_str()).collect();
    assert!(
        denied.contains(&"not_device_admin") && denied.contains(&"cannot_grant_external"),
        "both refusal reasons must be recorded, got {denied:?}"
    );
    // A refusal must not carry grant-only shape it never earned.
    let refusal = items.iter().find(|i| i["denied"].is_string()).unwrap();
    assert_eq!(refusal["action"], json!("approve"));
    assert!(
        refusal["actor"].as_str().is_some(),
        "a row must stay readable after the account is renamed"
    );
}

/// The `RpcCap` gate. A device whose agent cannot tell the person at the
/// machine that the controller is an OUTSIDER must not be approvable — else
/// the consent prompt makes a promise the device does not keep. Clearing must
/// still work, so a downgraded device is never stuck approved.
#[tokio::test]
async fn an_unsupported_device_cannot_be_approved_but_can_always_be_cleared() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extcap").await;
    let owner = &seeded.admin.access_token;
    let cfg = enrol(&app, &seeded, "mach-ext-old").await;
    let policy = url(
        &seeded,
        &format!("/agent/{}/external-access-policy", cfg.agent_id),
    );

    // Never advertised the verb — even the owner is refused.
    let (s, body) = put(&app, &policy, owner, json!({ "approved": true })).await;
    assert_eq!(s, 403, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("outside"),
        "the refusal must explain WHY an old agent is unsafe here, got {body}"
    );

    // Stamp the capability and it goes through.
    mark_supported(&app, &cfg.agent_id).await;
    let (s, body) = put(&app, &policy, owner, json!({ "approved": true })).await;
    assert_eq!(s, 200, "{body}");

    // Now take the capability away, as an agent downgrade would. The approval
    // must still be clearable.
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&cfg.agent_id).unwrap() },
            doc! { "$set": { "capabilities.rpc": Vec::<String>::new() } },
        )
        .await
        .unwrap();
    let (s, body) = put(&app, &policy, owner, json!({ "approved": false })).await;
    assert_eq!(
        s, 200,
        "a downgraded device must never be stuck approved: {body}"
    );
}

/// §5 — the connect code. Minted on demand, returned in display form, stable
/// across reads, and replaced by a rotation.
///
/// ⚠️ And the leak check: the ordinary device list needs only tenant
/// MEMBERSHIP, so the code must not appear there. It is the address a stranger
/// dials, and handing it to every member is a wider audience than the admin
/// who is supposed to be handing it out.
#[tokio::test]
async fn a_connect_code_is_minted_on_demand_and_never_reaches_the_device_list() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extcode").await;
    let owner = &seeded.admin.access_token;
    let cfg = enrol(&app, &seeded, "mach-ext-code").await;
    mark_supported(&app, &cfg.agent_id).await;
    let rotate = url(&seeded, &format!("/agent/{}/connect-code", cfg.agent_id));
    let policy = url(
        &seeded,
        &format!("/agent/{}/external-access-policy", cfg.agent_id),
    );
    let settings = url(&seeded, "/external-access");

    // A plain member may not mint one.
    let (s, _) = post(&app, &rotate, &seeded.member.access_token).await;
    assert_eq!(s, 403);

    let (s, body) = post(&app, &rotate, owner).await;
    assert_eq!(s, 200, "{body}");
    let first = body["connect_code"].as_str().unwrap().to_string();
    assert_eq!(first.len(), 14, "XXXX-XXXX-XXXX, got {first:?}");
    assert_eq!(
        first.matches('-').count(),
        2,
        "the display form is grouped for dictation, got {first:?}"
    );
    assert!(
        !first.contains(['I', 'L', 'O', 'U']),
        "Crockford excludes the confusables, got {first:?}"
    );

    // Readable again from the settings view once the device is approved.
    let (s, _) = put(&app, &policy, owner, json!({ "approved": true })).await;
    assert_eq!(s, 200);
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["devices"][0]["connect_code"], json!(first));

    // Rotation replaces it. This IS the revocation story for a leaked code.
    let (s, body) = post(&app, &rotate, owner).await;
    assert_eq!(s, 200);
    let second = body["connect_code"].as_str().unwrap().to_string();
    assert_ne!(first, second, "rotation must actually rotate");
    let (_, body) = get(&app, &settings, owner).await;
    assert_eq!(body["devices"][0]["connect_code"], json!(second));

    // ⚠️ The leak check. `GET /agent` needs only membership.
    let (s, body) = get(&app, &url(&seeded, "/agent"), &seeded.member.access_token).await;
    assert_eq!(s, 200);
    let raw = serde_json::to_string(&body).unwrap();
    assert!(
        !raw.contains("connect_code"),
        "the device list must not carry connect codes — it needs only \
         membership, and the code is the address a stranger dials"
    );
    let bare = second.replace('-', "");
    assert!(!raw.contains(&bare), "nor the ungrouped form of one: {raw}");
}

/// The replace-on-save hazard, locked end to end.
///
/// The dialog PUTs the WHOLE policy, so if `AgentResponse` did not carry the
/// stored one the dialog would open on its closed default and the next save
/// would silently drop a narrowed ceiling — widening what an OUTSIDER may do.
/// Same class as the warning on `AgentResponse::exec_policy`, with worse
/// consequences.
#[tokio::test]
async fn the_stored_policy_round_trips_through_the_device_list() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extround").await;
    let owner = &seeded.admin.access_token;
    let cfg = enrol(&app, &seeded, "mach-ext-round").await;
    mark_supported(&app, &cfg.agent_id).await;
    let policy = url(
        &seeded,
        &format!("/agent/{}/external-access-policy", cfg.agent_id),
    );
    let one = url(&seeded, &format!("/agent/{}", cfg.agent_id));

    // Unconfigured: absent, so a dialog opens on its own closed default rather
    // than on a server-supplied one.
    let (s, body) = get(&app, &one, owner).await;
    assert_eq!(s, 200);
    assert!(
        body.get("external_access_policy").is_none(),
        "an untouched policy is reported absent, got {body}"
    );

    // Narrow it to view-only, then read it back intact.
    let (s, body) = put(
        &app,
        &policy,
        owner,
        json!({ "approved": true, "max_permissions": "VIEW" }),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let (_, body) = get(&app, &one, owner).await;
    let stored = &body["external_access_policy"];
    assert_eq!(stored["approved"], json!(true));
    assert_eq!(
        stored["max_permissions"],
        json!("VIEW"),
        "the narrowed ceiling must survive to the client, or the next save \
         silently widens it: {body}"
    );
}

/// An expiry already in the past is a refusal, not a policy: it would store an
/// approval that is closed the instant it is written, which reads on the grid
/// as "approved" and behaves as "denied".
#[tokio::test]
async fn an_expiry_in_the_past_is_refused_before_anything_is_written() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("extexp").await;
    let owner = &seeded.admin.access_token;
    let cfg = enrol(&app, &seeded, "mach-ext-exp").await;
    mark_supported(&app, &cfg.agent_id).await;
    let policy = url(
        &seeded,
        &format!("/agent/{}/external-access-policy", cfg.agent_id),
    );
    let audit = url(&seeded, "/external-rc-audit");

    // ⚠️ An RFC3339 STRING, because that is what `Date.toISOString()` gives
    // the dialog. A body typed as `bson::DateTime` would refuse this shape and
    // answer 4xx for the wrong reason — asserted here as well as in the unit
    // tests, so the route and the client cannot drift apart.
    let (s, _) = put(
        &app,
        &policy,
        owner,
        json!({ "approved": true, "expires_at": "1970-01-01T00:16:40Z" }),
    )
    .await;
    assert_eq!(s, 400);

    let (_, body) = get(&app, &url(&seeded, "/external-access"), owner).await;
    assert_eq!(body["devices"], json!([]), "nothing was written");
    // And it left no granted-looking row behind — the check runs BEFORE the
    // decision for exactly that reason.
    let (_, body) = get(&app, &audit, owner).await;
    assert_eq!(
        body["items"].as_array().unwrap().len(),
        0,
        "a malformed body is not a policy decision and must not be audited as one"
    );

    // A FUTURE expiry goes through, and comes back as a STRING the dialog can
    // put straight into the next PUT. A `bson::DateTime` here would serialise
    // as `{"$date":…}` — truthy, so a presence check passes and the display
    // renders `[object Object]`.
    let (s, _) = put(
        &app,
        &policy,
        owner,
        json!({ "approved": true, "expires_at": "2099-01-01T00:00:00Z" }),
    )
    .await;
    assert_eq!(s, 200);
    let (_, body) = get(&app, &url(&seeded, "/external-access"), owner).await;
    let exp = &body["devices"][0]["expires_at"];
    assert!(
        exp.is_string(),
        "the expiry must reach the client as a string, got {exp}"
    );
    assert!(exp.as_str().unwrap().starts_with("2099-01-01"), "got {exp}");

    // Same rule on the audit rows, which carry two timestamps of their own.
    let (_, body) = get(&app, &audit, owner).await;
    let row = &body["items"][0];
    assert!(row["at"].is_string(), "audit `at` must be a string: {row}");
    assert!(
        row["expires_at"].is_string(),
        "audit `expires_at` must be a string: {row}"
    );
}
