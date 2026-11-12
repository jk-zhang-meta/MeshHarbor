// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-32 — plan limits, end to end against a real server and a real MongoDB.
//!
//! The unit tests in `services::quota` pin the decision function. These pin the
//! part a pure function cannot: that the gate is actually *wired* at the route,
//! that it reads the tenant's real usage, and that the three modes produce three
//! different HTTP outcomes.
//!
//! ⚠ The most valuable test here is [`an_established_limit_ignores_the_mode`].
//! P0 re-pointed the pre-FR-32 device cap through the same helper as the new
//! gates, and the mode defaults to `Warn` — so a plausible "simplification"
//! (dropping `Limit::is_established`) would silently stop enforcing the device
//! cap fleet-wide while every other test still passed. That is a billing
//! regression inside a diff that reads as a cleanup, which is exactly the kind
//! a unit test on the helper alone would not catch at the route.

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use bson::{Bson, doc, oid::ObjectId};
use serde_json::Value;

/// Set a tenant's plan and enforcement mode directly, the way an operator
/// would during P2. Both are plain fields on the tenant document.
async fn set_plan(app: &TestApp, tenant_id: &str, plan: &str, mode: &str) {
    let tid = ObjectId::parse_str(tenant_id).unwrap();
    app.db
        .collection::<bson::Document>("tenants")
        .update_one(
            doc! { "_id": tid },
            doc! { "$set": { "plan": plan, "settings.plan_enforcement": mode } },
        )
        .await
        .expect("failed to set plan/enforcement");
}

async fn create_room(app: &TestApp, tenant_id: &str, token: &str, name: &str) -> reqwest::Response {
    app.auth_post(&format!("/api/tenant/{tenant_id}/room"), token)
        .json(&serde_json::json!({ "name": name, "is_open": true }))
        .send()
        .await
        .expect("create room request failed")
}

/// Bring the tenant to exactly `target` live channels. A seeded tenant starts
/// with three; no plan caps channels since FR-115.
async fn fill_channels(app: &TestApp, t: &SeededTenant, target: usize) {
    let tid = ObjectId::parse_str(&t.tenant_id).unwrap();
    loop {
        let n = app
            .db
            .collection::<bson::Document>("rooms")
            .count_documents(doc! { "tenant_id": tid, "deleted_at": Bson::Null })
            .await
            .unwrap() as usize;
        if n >= target {
            break;
        }
        let r = create_room(
            app,
            &t.tenant_id,
            &t.admin.access_token,
            &format!("fill-{n}"),
        )
        .await;
        assert!(r.status().is_success(), "seeding channel {n} failed");
    }
}

// ── the three modes, three outcomes ─────────────────────────────────
//
// FR-115 made chat unlimited on every plan, so the channel cap these tests
// used to exercise is gone. Recordings (off on Free, a mode-subject gate) and
// storage (1 GiB on Free, a mode-subject COUNT gate) carry the same three
// properties now.

async fn start_recording(app: &TestApp, t: &SeededTenant) -> reqwest::Response {
    let room = &t.rooms[0].id;
    app.auth_post(
        &format!("/api/tenant/{}/room/{}/recording", t.tenant_id, room),
        &t.admin.access_token,
    )
    .json(&serde_json::json!({ "recording_type": "video" }))
    .send()
    .await
    .expect("recording request failed")
}

/// Sit the tenant `headroom` bytes under its storage quota, the way the
/// gate measures it (`FileDao::sum_storage_for_tenant`).
async fn fill_storage(app: &TestApp, tenant_id: &str, quota: u64, headroom: u64) {
    let tid = ObjectId::parse_str(tenant_id).unwrap();
    app.db
        .collection::<bson::Document>("files")
        .insert_one(doc! {
            "tenant_id": tid,
            "filename": "fill.bin",
            "size": (quota - headroom) as i64,
            "deleted_at": Bson::Null,
        })
        .await
        .expect("storage seed failed");
}

async fn upload_small_file(app: &TestApp, t: &SeededTenant) -> reqwest::Response {
    let part = reqwest::multipart::Part::bytes(b"Hello, World!".to_vec())
        .file_name("hello.txt")
        .mime_str("text/plain")
        .unwrap();
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("room_id", t.rooms[0].id.clone());
    app.client
        .post(app.url(&format!("/api/tenant/{}/file/upload", t.tenant_id)))
        .header("Authorization", format!("Bearer {}", t.admin.access_token))
        .multipart(form)
        .send()
        .await
        .expect("upload failed")
}

#[tokio::test]
async fn warn_records_a_gate_but_does_not_refuse() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planwarn").await;
    set_plan(&app, &t.tenant_id, "free", "warn").await; // Free.recordings == false

    let r = start_recording(&app, &t).await;
    assert!(
        r.status().is_success(),
        "Warn must record and let the request through, got {}",
        r.status()
    );
}

#[tokio::test]
async fn enforce_refuses_at_the_storage_cap() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planenf").await;
    set_plan(&app, &t.tenant_id, "free", "enforce").await;
    // Free.storage_bytes == 1 GiB; leave five bytes, upload thirteen.
    fill_storage(&app, &t.tenant_id, 1024 * 1024 * 1024, 5).await;

    let r = upload_small_file(&app, &t).await;
    assert_eq!(r.status(), 403, "Enforce must refuse past the cap");
    let body = r.text().await.unwrap_or_default();
    assert!(
        body.contains("Bytes of storage limit reached") && body.contains("of 1073741824"),
        "refusal must name the limit and the numbers, got: {body}"
    );
}

#[tokio::test]
async fn off_disables_a_newly_wired_gate_entirely() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planoff").await;
    set_plan(&app, &t.tenant_id, "free", "off").await;
    fill_storage(&app, &t.tenant_id, 1024 * 1024 * 1024, 5).await;

    for i in 0..2 {
        let r = start_recording(&app, &t).await;
        assert!(
            r.status().is_success(),
            "Off must not check at all (iteration {i}), got {}",
            r.status()
        );
    }
    let r = upload_small_file(&app, &t).await;
    assert!(
        r.status().is_success(),
        "Off must not check storage either, got {}",
        r.status()
    );
}

// ── The regression guard ────────────────────────────────────────────

/// `max_devices` was enforced before FR-32. The staging mode must not be able
/// to weaken it — including under `Off`, which disables every *new* gate.
///
/// If `Limit::is_established` were dropped, this is the test that fails; the
/// channel tests above would all still pass, and the fleet would silently stop
/// enforcing the device cap it bills for.
#[tokio::test]
async fn an_established_limit_ignores_the_mode() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planest").await;
    // `Off` is the most permissive mode there is.
    set_plan(&app, &t.tenant_id, "free", "off").await;

    // Free.max_devices == 100 (FR-115). Seed the tenant to its cap directly.
    let tid = ObjectId::parse_str(&t.tenant_id).unwrap();
    let now = bson::DateTime::now();
    let docs: Vec<bson::Document> = (0..100)
        .map(|i| {
            doc! {
                "tenant_id": tid,
                "machine_id": format!("est-machine-{i}"),
                "name": format!("est-{i}"),
                "created_at": now,
                "updated_at": now,
                "deleted_at": Bson::Null,
            }
        })
        .collect();
    app.db
        .collection::<bson::Document>("agents")
        .insert_many(docs)
        .await
        .expect("agent seed failed");

    // Mint an enrollment token and try to enroll a 101st device.
    let tok: Value = app
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
    let enrollment_token = tok["enrollment_token"]
        .as_str()
        .expect("no token")
        .to_string();

    let r = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&serde_json::json!({
            "enrollment_token": enrollment_token,
            "machine_id": "est-machine-fourth",
            "machine_name": "fourth",
            "os": "linux",
            "agent_version": "0.0.0",
        }))
        .send()
        .await
        .expect("enroll request failed");

    assert_eq!(
        r.status(),
        403,
        "the device cap must refuse even under Off — it predates FR-32 and the \
         staging mode must never be able to turn billing off"
    );
}

// ── Feature gates read as features, not counts ──────────────────────

#[tokio::test]
async fn a_disabled_feature_is_refused_with_feature_wording() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planfeat").await;
    set_plan(&app, &t.tenant_id, "free", "enforce").await; // Free.recordings == false

    let room = &t.rooms[0].id;
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/room/{}/recording", t.tenant_id, room),
            &t.admin.access_token,
        )
        .json(&serde_json::json!({ "recording_type": "video" }))
        .send()
        .await
        .expect("recording request failed");

    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap_or_default();
    assert!(
        body.contains("not available on the Free plan"),
        "a disabled feature must not be described by counting, got: {body}"
    );
    assert!(
        !body.contains("0 of 0"),
        "feature gates must never tell a customer to remove something that does \
         not exist, got: {body}"
    );
}

#[tokio::test]
async fn a_feature_the_plan_includes_is_allowed() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planbiz").await;
    set_plan(&app, &t.tenant_id, "business", "enforce").await; // recordings == true

    let room = &t.rooms[0].id;
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/room/{}/recording", t.tenant_id, room),
            &t.admin.access_token,
        )
        .json(&serde_json::json!({ "recording_type": "video" }))
        .send()
        .await
        .expect("recording request failed");

    assert!(
        r.status().is_success(),
        "Business includes recordings, got {}",
        r.status()
    );
}

// ── The enable-only asymmetry ───────────────────────────────────────

/// Gating a toggle's *disable* path would let a plan downgrade strand a tenant
/// holding a feature they are not allowed to turn off — strictly worse than the
/// feature having been free. Only enabling is gated.
///
/// FR-115 put MagicDNS on every plan, so exit nodes (Free gets them at P4d)
/// carry the property. The gate runs before the node lookup: enabling an
/// unknown node on Free is refused BY THE PLAN (403, feature wording), while
/// disabling it gets as far as the lookup (404) — the plan never refused it.
#[tokio::test]
async fn an_exit_node_can_always_be_turned_off_but_not_on() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planexit").await;
    set_plan(&app, &t.tenant_id, "free", "enforce").await;
    let node = ObjectId::new().to_hex();
    let url = format!("/api/tenant/{}/overlay-node/{node}/exit-node", t.tenant_id);

    let on = app
        .auth_put(&url, &t.admin.access_token)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(on.status(), 403, "Free must not enable an exit node yet");
    let body = on.text().await.unwrap_or_default();
    assert!(
        body.contains("not available on the Free plan"),
        "the refusal must be the plan's, got: {body}"
    );

    let off = app
        .auth_put(&url, &t.admin.access_token)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert_ne!(
        off.status(),
        403,
        "withdrawing an exit node must never be refused by the plan"
    );
}

/// Setting MagicDNS rewrites every node's DNS upstream, so it needs
/// `MANAGE_AGENTS`: a plain member is refused and nothing changes, while
/// reading the config stays member-visible.
#[tokio::test]
async fn a_plain_member_cannot_set_magic_dns_but_can_read_it() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("dnsperm").await;
    let url = format!("/api/tenant/{}/magic-dns", t.tenant_id);
    let body = serde_json::json!({
        "magic_dns_domain": "dnsperm.example",
        "magic_dns_nameservers": ["192.0.2.53"],
    });
    let refused = app
        .auth_put(&url, &t.member.access_token)
        .json(&body)
        .send()
        .await
        .expect("member put failed");
    assert_eq!(
        refused.status(),
        403,
        "a plain member must not set MagicDNS"
    );
    let read = app
        .auth_get(&url, &t.member.access_token)
        .send()
        .await
        .expect("member get failed");
    assert_eq!(read.status(), 200, "reading MagicDNS stays member-visible");
    let v: serde_json::Value = read.json().await.unwrap();
    assert!(
        v["magic_dns_domain"].is_null(),
        "the refused write changed nothing: {v}"
    );
    let ok = app
        .auth_put(&url, &t.admin.access_token)
        .json(&body)
        .send()
        .await
        .expect("admin put failed");
    assert!(
        ok.status().is_success(),
        "the admin may set it, got {}",
        ok.status()
    );
}

/// FR-115 — MagicDNS is on every plan, Free included.
#[tokio::test]
async fn free_can_set_a_magic_dns_zone() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("plandns").await;
    set_plan(&app, &t.tenant_id, "free", "enforce").await;
    let on = app
        .auth_put(
            &format!("/api/tenant/{}/magic-dns", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&serde_json::json!({
            "magic_dns_domain": "plandns.example",
            "magic_dns_nameservers": ["1.1.1.1"],
        }))
        .send()
        .await
        .expect("set magic dns failed");
    assert!(
        on.status().is_success(),
        "Free includes MagicDNS since FR-115, got {}",
        on.status()
    );
}

/// FR-115 D2 — Free's ten users is enforced whatever the mode: `off` is the
/// most permissive mode there is, and the eleventh member is still refused.
#[tokio::test]
async fn the_free_member_cap_ignores_the_mode() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planmemoff").await;
    set_plan(&app, &t.tenant_id, "free", "off").await;
    fill_members(&app, &t.tenant_id, 10).await;

    let outsider = app
        .register_user(
            "outsider@planmemoff.test",
            "planmemoff_outsider",
            "Outsider",
            "Outsider123!",
            None,
            None,
        )
        .await;
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/member", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&serde_json::json!({ "user_id": outsider.id }))
        .send()
        .await
        .expect("add member failed");
    assert_eq!(
        r.status(),
        403,
        "the eleventh member must be refused under Off"
    );

    // A paid plan has no member cap: every user is a billed seat.
    set_plan(&app, &t.tenant_id, "pro", "enforce").await;
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/member", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&serde_json::json!({ "user_id": outsider.id }))
        .send()
        .await
        .expect("add member failed");
    assert!(
        r.status().is_success(),
        "Pro has no member cap, got {}",
        r.status()
    );
}

/// Bring the tenant to exactly `target` members (rows the gate counts).
async fn fill_members(app: &TestApp, tenant_id: &str, target: u64) {
    let tid = ObjectId::parse_str(tenant_id).unwrap();
    let now = bson::DateTime::now();
    let existing = app
        .db
        .collection::<bson::Document>("tenant_members")
        .count_documents(doc! { "tenant_id": tid })
        .await
        .unwrap();
    for i in existing..target {
        app.db
            .collection::<bson::Document>("tenant_members")
            .insert_one(doc! {
                "tenant_id": tid,
                "user_id": ObjectId::new(),
                "role_ids": [],
                "joined_at": now,
                "is_pending": false,
                "is_muted": false,
                "created_at": now,
                "updated_at": now,
                "nickname": Bson::Null,
                "notification_override": Bson::Null,
                "invited_by": Bson::Null,
                "last_seen_at": Bson::Null,
                "_filler": i as i64,
            })
            .await
            .expect("member seed failed");
    }
}

// ── The unlimited sentinel, through the route ───────────────────────

/// `Pro.max_channels` is `u32::MAX`, the codebase's "unlimited" spelling. If the
/// gate treated it as a real number the report and the refusal would both be
/// wrong; here it must simply never fire.
#[tokio::test]
async fn an_unlimited_plan_never_trips_a_count_gate() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planpro").await;
    set_plan(&app, &t.tenant_id, "pro", "enforce").await;
    fill_channels(&app, &t, 12).await; // far past the five Free had before FR-115

    let r = create_room(&app, &t.tenant_id, &t.admin.access_token, "still-fine").await;
    assert!(
        r.status().is_success(),
        "u32::MAX means unlimited, not 4294967295, got {}",
        r.status()
    );
}

// ── The member cap gates BOTH paths ─────────────────────────────────

/// `add_member` is the admin route; invite redemption is the one an invitee
/// walks. Leaving either open makes the cap a formality.
#[tokio::test]
async fn the_member_cap_gates_the_admin_add_path() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("planmem").await;
    set_plan(&app, &t.tenant_id, "free", "enforce").await;

    // Seed to Free's cap of 10 (the tenant starts with 2).
    let tid = ObjectId::parse_str(&t.tenant_id).unwrap();
    let now = bson::DateTime::now();
    let existing = app
        .db
        .collection::<bson::Document>("tenant_members")
        .count_documents(doc! { "tenant_id": tid })
        .await
        .unwrap();
    for i in existing..10 {
        app.db
            .collection::<bson::Document>("tenant_members")
            .insert_one(doc! {
                "tenant_id": tid,
                "user_id": ObjectId::new(),
                "role_ids": [],
                "joined_at": now,
                "is_pending": false,
                "is_muted": false,
                "created_at": now,
                "updated_at": now,
                "nickname": Bson::Null,
                "notification_override": Bson::Null,
                "invited_by": Bson::Null,
                "last_seen_at": Bson::Null,
                "_filler": i as i64,
            })
            .await
            .expect("member seed failed");
    }

    // A real, verified account that is not yet a member.
    let outsider = app
        .register_user(
            "outsider@planmem.test",
            "planmem_outsider",
            "Outsider",
            "Outsider123!",
            None,
            None,
        )
        .await;

    let r = app
        .auth_post(
            &format!("/api/tenant/{}/member", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&serde_json::json!({ "user_id": outsider.id }))
        .send()
        .await
        .expect("add member failed");

    assert_eq!(r.status(), 403, "the member cap must refuse the 11th seat");
    let body = r.text().await.unwrap_or_default();
    assert!(
        body.contains("10 of 10 members used"),
        "refusal must name the real counts, got: {body}"
    );
}

// ── Self-hosting: no plans sold, no limits held ─────────────────────

/// FR-115 — a server without the hosted `saas` module sells no plans, so no
/// org on it is held to one: the self-hosted image is built that way, and
/// self-hosting is free and unlimited. A Free org in the strictest mode, at
/// every cap, still enrolls its 101st device, adds its 11th member and stores
/// past 1 GiB. The control is every other test in this file, where the same
/// org on a server that sells plans is refused at each one.
#[tokio::test]
async fn a_server_that_sells_no_plans_holds_no_org_to_one() {
    let app = TestApp::spawn_with_settings(|s| s.modules.saas = false).await;
    let t = app.seed_tenant("planselfhost").await;
    set_plan(&app, &t.tenant_id, "free", "enforce").await;

    // Devices (established): 100 seeded, the 101st enrolls.
    let tid = ObjectId::parse_str(&t.tenant_id).unwrap();
    let now = bson::DateTime::now();
    let docs: Vec<bson::Document> = (0..100)
        .map(|i| {
            doc! {
                "tenant_id": tid,
                "machine_id": format!("selfhost-machine-{i}"),
                "name": format!("selfhost-{i}"),
                "created_at": now,
                "updated_at": now,
                "deleted_at": Bson::Null,
            }
        })
        .collect();
    app.db
        .collection::<bson::Document>("agents")
        .insert_many(docs)
        .await
        .expect("agent seed failed");
    let tok: Value = app
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
    let r = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&serde_json::json!({
            "enrollment_token": tok["enrollment_token"].as_str().expect("no token"),
            "machine_id": "selfhost-machine-101",
            "machine_name": "the 101st",
            "os": "linux",
            "agent_version": "0.0.0",
        }))
        .send()
        .await
        .expect("enroll request failed");
    assert!(
        r.status().is_success(),
        "a self-hosted org enrolls past Free's 100 devices, got {}",
        r.status()
    );

    // Members (established): 10 seeded, the 11th joins.
    fill_members(&app, &t.tenant_id, 10).await;
    let outsider = app
        .register_user(
            "outsider@planselfhost.test",
            "planselfhost_outsider",
            "Outsider",
            "Outsider123!",
            None,
            None,
        )
        .await;
    let r = app
        .auth_post(
            &format!("/api/tenant/{}/member", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&serde_json::json!({ "user_id": outsider.id }))
        .send()
        .await
        .expect("add member failed");
    assert!(
        r.status().is_success(),
        "a self-hosted org adds its 11th member, got {}",
        r.status()
    );

    // Storage (staged, under enforce): past 1 GiB, the upload lands.
    fill_storage(&app, &t.tenant_id, 1024 * 1024 * 1024, 5).await;
    let r = upload_small_file(&app, &t).await;
    assert!(
        r.status().is_success(),
        "a self-hosted org stores past Free's 1 GiB, got {}",
        r.status()
    );
}
