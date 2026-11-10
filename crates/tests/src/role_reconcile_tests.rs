// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-82 — the two halves of "a permission refusal is not a logout":
//!
//! 1. the wire tells a **non-member** apart from a **member without the bit**
//!    (`not_a_member` vs `forbidden`), because the SPA's behaviour forks on it
//!    and a message-string sniff would sweep `chat`'s room refusal in with it;
//! 2. `reconcile_managed_roles` raises a stale managed mask to its definition,
//!    keeps a bit the org added itself, and is a no-op on a second run.
//!
//! The field bug: an org member opened the Devices page, the unconditionally
//! mounted enrollment-keys card fetched a `MANAGE_TENANT` route, and the api
//! client turned the 403 into a logout.

use bson::{doc, oid::ObjectId};
use serde_json::Value;

use crate::fixtures::test_app::TestApp;

/// `/ephemeral-key-settings` is the exact route the Devices page fetched on
/// mount. Any `MANAGE_TENANT` GET would do; this one is the field bug.
fn org_switch(tenant_id: &str) -> String {
    format!("/api/tenant/{tenant_id}/ephemeral-key-settings")
}

#[tokio::test]
async fn a_member_without_the_bit_is_refused_as_forbidden_naming_the_permission() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr81perm").await;

    // `tenant.member` holds the seeded `member` role: no MANAGE_TENANT, and
    // no ADMINISTRATOR bypass.
    let resp = app
        .auth_get(&org_switch(&tenant.tenant_id), &tenant.member.access_token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"].as_str(),
        Some("forbidden"),
        "a permission refusal must NOT be the code the client evicts a tenant on"
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap_or("")
            .contains("MANAGE_TENANT"),
        "the refusal has to say WHICH permission: {body}"
    );
}

#[tokio::test]
async fn a_non_member_is_refused_as_not_a_member() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr81out").await;

    // Registered, signed in, and in no tenant at all — the "membership
    // revoked / tenant switched underneath" shape.
    let outsider = app
        .register_user(
            "outsider@fr81out.test",
            "fr81out_outsider",
            "FR81 Outsider",
            "Outsider123!",
            None,
            None,
        )
        .await;

    let resp = app
        .auth_get(&org_switch(&tenant.tenant_id), &outsider.access_token)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"].as_str(),
        Some("not_a_member"),
        "the ONE 403 the client navigates on has to be distinguishable: {body}"
    );
}

#[tokio::test]
async fn a_membership_gated_read_tells_a_non_member_apart_from_a_member() {
    // The same distinction on a route that needs no permission at all — the
    // devices grid. Both callers get 403; only one of them has left the org,
    // and the client does very different things about it.
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr81dev").await;
    let path = format!("/api/tenant/{}/device", tenant.tenant_id);

    let member = app
        .auth_get(&path, &tenant.member.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        member.status().as_u16(),
        200,
        "the devices grid is membership-gated, so a plain member reads it"
    );

    let outsider = app
        .register_user(
            "outsider@fr81dev.test",
            "fr81dev_outsider",
            "FR81 Dev Outsider",
            "Outsider123!",
            None,
            None,
        )
        .await;
    let resp = app
        .auth_get(&path, &outsider.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"].as_str(), Some("not_a_member"));
}

/// Read one managed role's stored mask straight from the collection.
async fn stored_mask(app: &TestApp, tenant_id: &str, name: &str) -> u64 {
    let tid = ObjectId::parse_str(tenant_id).unwrap();
    let doc = app
        .db
        .collection::<bson::Document>("roles")
        .find_one(doc! { "tenant_id": tid, "name": name })
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no `{name}` role"));
    doc.get_i64("permissions")
        .ok()
        .or_else(|| doc.get_i32("permissions").ok().map(i64::from))
        .unwrap() as u64
}

async fn set_mask(app: &TestApp, tenant_id: &str, name: &str, mask: u64) {
    let tid = ObjectId::parse_str(tenant_id).unwrap();
    app.db
        .collection::<bson::Document>("roles")
        .update_one(
            doc! { "tenant_id": tid, "name": name },
            doc! { "$set": { "permissions": mask as i64 } },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn the_reconcile_raises_a_stale_mask_and_keeps_what_the_org_added() {
    use meshharbor_db::models::role::{ManagedRole, permissions};

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr81rec").await;

    // The measured prod state, reproduced: `admin` frozen at the mask it had
    // before MANAGE_AGENTS existed, `owner` at the `ALL` of that day.
    const STALE_ADMIN: u64 = 0x7ffff7;
    const STALE_OWNER: u64 = 0xffffff;
    set_mask(&app, &tenant.tenant_id, "admin", STALE_ADMIN).await;
    set_mask(&app, &tenant.tenant_id, "owner", STALE_OWNER).await;

    // ⚠️ And one bit this org granted ITSELF, on a managed role. A replace
    // would revoke it silently; the additive rule exists for this row.
    let moderator_def = ManagedRole::by_name("moderator").unwrap().permissions;
    set_mask(
        &app,
        &tenant.tenant_id,
        "moderator",
        moderator_def | permissions::EXEC_DEVICE,
    )
    .await;

    let groups = app.state.tenants.reconcile_managed_roles().await.unwrap();
    assert!(!groups.is_empty(), "the reconcile inspected nothing");

    let admin_def = ManagedRole::by_name("admin").unwrap().permissions;
    assert_eq!(
        stored_mask(&app, &tenant.tenant_id, "admin").await,
        STALE_ADMIN | admin_def,
        "admin did not gain the fleet bits its definition carries"
    );
    assert_ne!(
        stored_mask(&app, &tenant.tenant_id, "admin").await & permissions::MANAGE_AGENTS,
        0,
        "the whole point: a frozen admin could not see the fleet"
    );
    assert_eq!(
        stored_mask(&app, &tenant.tenant_id, "owner").await,
        STALE_OWNER | permissions::ALL,
        "owner did not reach ALL"
    );
    assert_ne!(
        stored_mask(&app, &tenant.tenant_id, "moderator").await & permissions::EXEC_DEVICE,
        0,
        "ADDITIVE means additive — the org's own grant must survive the reconcile"
    );

    // `member` was already current, so it must not have been rewritten.
    let member_def = ManagedRole::by_name("member").unwrap().permissions;
    assert_eq!(
        stored_mask(&app, &tenant.tenant_id, "member").await,
        member_def
    );
}

#[tokio::test]
async fn the_reconcile_is_a_no_op_on_a_second_run() {
    // Every pod boot runs this. A second run that still reported changes
    // would mean it is rewriting rows forever — and would make the log line
    // that says "something was granted" worthless as a signal.
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr81idem").await;
    set_mask(&app, &tenant.tenant_id, "admin", 0x7ffff7).await;

    let first = app.state.tenants.reconcile_managed_roles().await.unwrap();
    assert!(
        first.iter().any(|g| g.gained() != 0),
        "the first run should have had something to do"
    );

    let second = app.state.tenants.reconcile_managed_roles().await.unwrap();
    for g in &second {
        assert_eq!(
            g.gained(),
            0,
            "`{}` still gained {:#x} on the second run",
            g.name,
            g.gained()
        );
    }
}

#[tokio::test]
async fn the_reconcile_leaves_a_role_it_does_not_define_alone() {
    // GROX's hand-made "Remote Operator" is the real case: a tenant's own
    // role, and the only non-managed role on the whole deployment. A managed
    // row whose NAME drifted lands in the same branch — reported, untouched.
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr81custom").await;
    let tid = ObjectId::parse_str(&tenant.tenant_id).unwrap();
    let now = bson::DateTime::now();

    app.db
        .collection::<bson::Document>("roles")
        .insert_one(doc! {
            "tenant_id": tid,
            "name": "Remote Operator",
            "description": bson::Bson::Null,
            "color": bson::Bson::Null,
            "position": 5_i64,
            "permissions": 0x3000000_i64,
            "is_default": false,
            // Managed, so the reconcile SEES it — and still must not guess a
            // definition for a name the table does not own.
            "is_managed": true,
            "is_mentionable": false,
            "is_hoisted": false,
            "created_at": now,
            "updated_at": now,
        })
        .await
        .unwrap();

    let groups = app.state.tenants.reconcile_managed_roles().await.unwrap();

    assert_eq!(
        stored_mask(&app, &tenant.tenant_id, "Remote Operator").await,
        0x3000000,
        "a role the table does not define must not be rewritten"
    );
    let reported = groups
        .iter()
        .find(|g| g.name == "Remote Operator")
        .expect("an untouched managed role must still be REPORTED — silent drift is the defect");
    assert_eq!(reported.gained(), 0);
}

#[tokio::test]
async fn the_grant_leaves_a_record_that_outlives_the_pod_that_made_it() {
    // FR-82 shipped with the arithmetic at INFO and a comment promising it
    // would be "readable in `kubectl logs` afterwards". Measured on the real
    // roll: ~10 minutes later it was readable nowhere — `kubectl logs` serves
    // only the current container and the emitting pod had been replaced, so
    // the sole record of a one-way grant across 63 organisations survived
    // purely because somebody was watching live. This is the durable half.
    use meshharbor_db::models::role::{ManagedRole, RoleReconcileEvent, permissions};

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("fr82audit").await;

    const STALE_ADMIN: u64 = 0x7ffff7;
    set_mask(&app, &tenant.tenant_id, "admin", STALE_ADMIN).await;

    let audit = app
        .db
        .collection::<bson::Document>(RoleReconcileEvent::COLLECTION);
    assert_eq!(
        audit.count_documents(doc! {}).await.unwrap(),
        0,
        "precondition: nothing has been reconciled yet"
    );

    app.state.tenants.reconcile_managed_roles().await.unwrap();

    let row = audit
        .find_one(doc! { "role": "admin", "stored": STALE_ADMIN as i64 })
        .await
        .unwrap()
        .expect("the admin grant left no record");

    let admin_def = ManagedRole::by_name("admin").unwrap().permissions;
    assert_eq!(
        row.get_i64("granted").unwrap() as u64,
        STALE_ADMIN | admin_def,
        "the row must say what the mask became"
    );
    assert_eq!(
        row.get_i64("gained").unwrap() as u64,
        admin_def & !STALE_ADMIN,
        "the row must say what the grant actually added"
    );
    assert!(
        row.get_i64("rows").unwrap() >= 1,
        "the row must say how many organisations it covered"
    );

    // The masks are the record; the names are the part a human reads years
    // later without re-deriving a bitfield.
    let names: Vec<String> = row
        .get_array("gained_names")
        .unwrap()
        .iter()
        .filter_map(|b| b.as_str().map(str::to_string))
        .collect();
    assert!(
        names.iter().any(|n| n == "MANAGE_AGENTS"),
        "gained_names should name the grant in words, got {names:?}"
    );

    // ⚠️ And the bit that must NEVER appear in one of these rows below the
    // ADMINISTRATOR bypass. `no_managed_role_below_administrator_seeds_a_root_shell`
    // guards the table; this guards what the migration actually handed out.
    assert!(
        !names
            .iter()
            .any(|n| n == "EXEC_DEVICE" || n == "SSH_DEVICE"),
        "the reconcile granted a root shell to every org: {names:?}"
    );
    assert_eq!(
        row.get_i64("gained").unwrap() as u64
            & (permissions::EXEC_DEVICE | permissions::SSH_DEVICE),
        0
    );

    let after_first = audit.count_documents(doc! {}).await.unwrap();

    // Every pod boot runs this. A run that changes nothing must file nothing,
    // or the collection grows on every restart and buries the one row that
    // matters.
    app.state.tenants.reconcile_managed_roles().await.unwrap();
    assert_eq!(
        audit.count_documents(doc! {}).await.unwrap(),
        after_first,
        "an idempotent run still wrote an audit row"
    );
}
