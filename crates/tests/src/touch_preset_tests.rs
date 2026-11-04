// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-111 P4a — the org's on-screen control presets (spec
//! `docs/fr/FR-111-touch-controls.md` §3d), through the real routes.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use meshharbor_remote_control::models::TouchControl;
use serde_json::{Value, json};

/// Controls compared as controls: as JSON text the server writes `12.0` for
/// a place the viewer sent as `12`, the same number to `JSON.parse`.
fn controls(v: &Value) -> Vec<TouchControl> {
    serde_json::from_value(v.clone()).expect("controls")
}

/// A preset as the viewer writes one: a row with a key and a macro, a d-pad,
/// a stick.
fn preset(name: &str) -> Value {
    json!({
        "name": name,
        "controls": [
            { "kind": "row", "id": "keys", "at": { "bottom": 12 }, "buttons": [
                { "id": "esc", "label": "Esc", "action": { "kind": "keys", "keys": [0x29] } },
                { "id": "paste", "label": "Paste", "action": { "kind": "macro", "steps": [
                    { "op": "press", "key": 0xe0 },
                    { "op": "tap", "key": 0x19, "wait_ms": 100 },
                    { "op": "release", "key": 0xe0 }
                ] } }
            ] },
            { "kind": "dpad", "id": "move", "label": "Move", "at": { "left": 16, "bottom": 16 },
              "size": 150, "up": 0x1a, "down": 0x16, "left": 0x04, "right": 0x07 },
            { "kind": "stick", "id": "look", "label": "Look", "at": { "right": 16, "bottom": 16 },
              "size": 150, "speed": 1 }
        ]
    })
}

fn base(tenant_id: &str) -> String {
    format!("/api/tenant/{tenant_id}/touch-preset")
}

async fn list(app: &TestApp, tenant_id: &str, token: &str) -> reqwest::Response {
    app.client
        .get(app.url(&base(tenant_id)))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn create(app: &TestApp, tenant_id: &str, token: &str, body: &Value) -> reqwest::Response {
    app.client
        .post(app.url(&base(tenant_id)))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap()
}

async fn put(
    app: &TestApp,
    tenant_id: &str,
    id: &str,
    token: &str,
    body: &Value,
) -> reqwest::Response {
    app.client
        .put(app.url(&format!("{}/{id}", base(tenant_id))))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap()
}

async fn delete(app: &TestApp, tenant_id: &str, id: &str, token: &str) -> reqwest::Response {
    app.client
        .delete(app.url(&format!("{}/{id}", base(tenant_id))))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn names(app: &TestApp, seeded: &SeededTenant) -> Vec<String> {
    let body: Value = list(app, &seeded.tenant_id, &seeded.member.access_token)
        .await
        .json()
        .await
        .unwrap();
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect()
}

/// Any member reads, only `MANAGE_TENANT` writes, a name is unique per org,
/// and a write answers the stored preset.
#[tokio::test]
async fn presets_read_for_members_and_write_for_admins() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr111p4route").await;
    let other = app.seed_tenant("fr111p4other").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let member = seeded.member.access_token.clone();

    // A member reads an empty list.
    let resp = list(&app, &tid, &member).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap(), json!({ "items": [] }));

    // Someone from another org is not a member, and is told so by code.
    let resp = list(&app, &tid, &other.admin.access_token).await;
    assert_eq!(resp.status().as_u16(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "not_a_member", "{body}");

    // A member without MANAGE_TENANT cannot write: a permission refusal, not
    // an eviction from the org.
    let resp = create(&app, &tid, &member, &preset("Mine")).await;
    assert_eq!(resp.status().as_u16(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_ne!(body["error"], "not_a_member", "{body}");

    // The admin creates one: 201, the name trimmed, the controls as written.
    let resp = create(&app, &tid, &admin, &preset("  Game pad  ")).await;
    assert_eq!(resp.status().as_u16(), 201);
    let stored: Value = resp.json().await.unwrap();
    assert_eq!(stored["name"], "Game pad");
    assert_eq!(
        controls(&stored["controls"]),
        controls(&preset("x")["controls"])
    );
    assert!(stored["updated_at"].is_string(), "a time as text: {stored}");
    let id = stored["id"].as_str().expect("an id").to_string();
    assert_eq!(id.len(), 24, "an id as hex");
    assert_eq!(names(&app, &seeded).await, ["Game pad"]);

    // A second preset of that name is refused by code.
    let resp = create(&app, &tid, &admin, &preset("Game pad")).await;
    assert_eq!(resp.status().as_u16(), 409);
    assert_eq!(resp.json::<Value>().await.unwrap()["error"], "name_taken");

    // A member still cannot change or delete it.
    assert_eq!(
        put(&app, &tid, &id, &member, &preset("Hijacked"))
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        delete(&app, &tid, &id, &member).await.status().as_u16(),
        403
    );

    // The admin renames it and changes its controls: 200, the stored row.
    let mut changed = preset("Game pad 2");
    changed["controls"] = json!([changed["controls"][0].clone()]);
    let resp = put(&app, &tid, &id, &admin, &changed).await;
    assert_eq!(resp.status().as_u16(), 200);
    let stored: Value = resp.json().await.unwrap();
    assert_eq!(stored["id"], id.as_str());
    assert_eq!(stored["name"], "Game pad 2");
    assert_eq!(stored["controls"].as_array().unwrap().len(), 1);
    // Saving it unchanged is still a success, not a missing preset.
    assert_eq!(
        put(&app, &tid, &id, &admin, &changed)
            .await
            .status()
            .as_u16(),
        200
    );
    // A rename onto another preset's name is refused like a create.
    let resp = create(&app, &tid, &admin, &preset("Office")).await;
    assert_eq!(resp.status().as_u16(), 201);
    let resp = put(&app, &tid, &id, &admin, &preset("Office")).await;
    assert_eq!(resp.status().as_u16(), 409);
    assert_eq!(resp.json::<Value>().await.unwrap()["error"], "name_taken");
    assert_eq!(names(&app, &seeded).await, ["Game pad 2", "Office"]);

    // Deleted: 204, then gone, then a 404 for a second delete.
    assert_eq!(delete(&app, &tid, &id, &admin).await.status().as_u16(), 204);
    assert_eq!(names(&app, &seeded).await, ["Office"]);
    assert_eq!(delete(&app, &tid, &id, &admin).await.status().as_u16(), 404);
    assert_eq!(
        put(&app, &tid, &id, &admin, &preset("Back"))
            .await
            .status()
            .as_u16(),
        404
    );
}

/// A preset is resolved within the tenant: org B's admin, holding org A's
/// preset id, gets a 404 through org B and `not_a_member` through org A, and
/// org A's preset is untouched.
#[tokio::test]
async fn a_foreign_preset_is_a_404() {
    let app = TestApp::spawn().await;
    let a = app.seed_tenant("fr111p4a").await;
    let b = app.seed_tenant("fr111p4b").await;
    let resp = create(&app, &a.tenant_id, &a.admin.access_token, &preset("A's")).await;
    assert_eq!(resp.status().as_u16(), 201);
    let id = resp.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let b_admin = &b.admin.access_token;
    assert_eq!(
        put(&app, &b.tenant_id, &id, b_admin, &preset("Taken"))
            .await
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        delete(&app, &b.tenant_id, &id, b_admin)
            .await
            .status()
            .as_u16(),
        404
    );
    let resp = delete(&app, &a.tenant_id, &id, b_admin).await;
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(resp.json::<Value>().await.unwrap()["error"], "not_a_member");
    // B sees nothing of A's.
    let body: Value = list(&app, &b.tenant_id, b_admin)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body, json!({ "items": [] }));
    assert_eq!(names(&app, &a).await, ["A's"]);
    // A malformed id is a 400, not a lookup.
    assert_eq!(
        delete(&app, &a.tenant_id, "nope", &a.admin.access_token)
            .await
            .status()
            .as_u16(),
        400
    );
}

/// What a viewer should not run is refused with a code, and nothing is
/// stored: an unknown field, a key the keyboard path cannot send, a macro
/// past its length, and a body past the limit.
#[tokio::test]
async fn invalid_presets_are_refused_with_a_code() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr111p4bad").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();

    let mut unknown = preset("Unknown");
    unknown["controls"][0]["buttons"][0]["action"]["repeat"] = json!(true);
    let mut bad_key = preset("Bad key");
    bad_key["controls"][1]["up"] = json!(0xf0);
    let mut long_macro = preset("Long macro");
    long_macro["controls"][0]["buttons"][1]["action"]["steps"] = json!(
        (0..7)
            .map(|_| json!({ "op": "tap", "key": 0x19, "wait_ms": 5000 }))
            .collect::<Vec<_>>()
    );
    let mut empty_name = preset("x");
    empty_name["name"] = json!("   ");
    for (body, code) in [
        (unknown, "invalid_json"),
        (bad_key, "key_invalid"),
        (long_macro, "macro_too_long"),
        (empty_name, "name_empty"),
    ] {
        let resp = create(&app, &tid, &admin, &body).await;
        assert_eq!(resp.status().as_u16(), 422, "{code}");
        assert_eq!(resp.json::<Value>().await.unwrap()["error"], code);
    }
    // A body past the limit never reaches the parser.
    let mut huge = preset("Huge");
    huge["controls"][0]["buttons"][0]["label"] = json!("x".repeat(40 * 1024));
    let resp = create(&app, &tid, &admin, &huge).await;
    assert_eq!(resp.status().as_u16(), 413);
    assert!(names(&app, &seeded).await.is_empty());
}

/// An org keeps at most fifty presets; the fifty-first is refused by code.
#[tokio::test]
async fn an_org_keeps_at_most_fifty() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr111p4cap").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    for i in 0..50 {
        let resp = create(&app, &tid, &admin, &preset(&format!("P{i:02}"))).await;
        assert_eq!(resp.status().as_u16(), 201, "preset {i}");
    }
    let resp = create(&app, &tid, &admin, &preset("One too many")).await;
    assert_eq!(resp.status().as_u16(), 409);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["error"],
        "too_many_presets"
    );
    assert_eq!(names(&app, &seeded).await.len(), 50);
}
