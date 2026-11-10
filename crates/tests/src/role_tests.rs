// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use crate::fixtures::test_app::TestApp;
use serde_json::Value;

#[tokio::test]
async fn list_default_roles() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("role1").await;

    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let roles: Vec<Value> = resp.json().await.unwrap();
    // Tenant creation should produce default roles (admin, member at minimum)
    assert!(
        roles.len() >= 2,
        "Expected at least 2 default roles, got {}",
        roles.len()
    );

    let role_names: Vec<&str> = roles.iter().filter_map(|r| r["name"].as_str()).collect();
    assert!(role_names.contains(&"admin"), "Expected 'admin' role");
    assert!(role_names.contains(&"member"), "Expected 'member' role");
}

#[tokio::test]
async fn create_custom_role() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("role2").await;

    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        // NOT "moderator": `roles` carries a unique index on
        // {tenant_id, name} and tenant seeding creates owner/admin/moderator/
        // member, so this test 409'd from the day `moderator` joined the
        // seeded set — the "role dedup" entry in CLAUDE.md's known-failures
        // list. It is a test-data collision, never a product bug.
        .json(&serde_json::json!({
            "name": "curator",
            "description": "Can moderate messages",
            "color": 0xFF5500,
            "permissions": 42,
            "position": 50,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let role: Value = resp.json().await.unwrap();
    assert_eq!(role["name"], "curator");
    assert_eq!(role["description"], "Can moderate messages");
    assert_eq!(role["color"], 0xFF5500);
    assert_eq!(role["permissions"], 42);
    assert_eq!(role["position"], 50);
    assert_eq!(role["is_default"], false);
    assert_eq!(role["is_managed"], false);
    assert!(role["id"].as_str().is_some(), "Role should have an id");
}

#[tokio::test]
async fn update_role() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("role3").await;

    // Create a role
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({
            "name": "editor",
        }))
        .send()
        .await
        .unwrap();

    let role: Value = resp.json().await.unwrap();
    let role_id = role["id"].as_str().unwrap();

    // Update it
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/role/{}", tenant.tenant_id, role_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({
            "name": "senior-editor",
            "description": "Can edit everything",
            "permissions": 99,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["updated"], true);

    // Verify the update via list
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    let roles: Vec<Value> = resp.json().await.unwrap();
    let updated_role = roles.iter().find(|r| r["id"].as_str() == Some(role_id));
    assert!(updated_role.is_some(), "Updated role should still exist");
    assert_eq!(updated_role.unwrap()["name"], "senior-editor");
}

#[tokio::test]
async fn delete_role() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("role4").await;

    // Create a role
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({
            "name": "temp-role",
        }))
        .send()
        .await
        .unwrap();

    let role: Value = resp.json().await.unwrap();
    let role_id = role["id"].as_str().unwrap();

    // Delete it
    let resp = app
        .auth_delete(
            &format!("/api/tenant/{}/role/{}", tenant.tenant_id, role_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["deleted"], true);

    // Verify it's gone from the list
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    let roles: Vec<Value> = resp.json().await.unwrap();
    let found = roles.iter().any(|r| r["id"].as_str() == Some(role_id));
    assert!(!found, "Deleted role should not appear in list");
}

#[tokio::test]
async fn assign_and_unassign_role_to_user() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("role5").await;

    // Create a custom role
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({
            "name": "reviewer",
        }))
        .send()
        .await
        .unwrap();

    let role: Value = resp.json().await.unwrap();
    let role_id = role["id"].as_str().unwrap();

    // Assign role to the member user
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                tenant.tenant_id, role_id, tenant.member.id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["assigned"], true);

    // Unassign the role
    let resp = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                tenant.tenant_id, role_id, tenant.member.id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["removed"], true);
}

#[tokio::test]
async fn non_member_cannot_list_roles() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("role6").await;

    // Register an outsider who is NOT a member of this tenant
    let outsider = app
        .register_user(
            "outsider@role6.test",
            "outsider_role6",
            "Outsider",
            "Outsider123!",
            None,
            None,
        )
        .await;

    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &outsider.access_token,
        )
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status().as_u16(),
        403,
        "Non-member should get 403 Forbidden when listing roles"
    );
}

/// The privilege-escalation guard, end to end.
///
/// `MANAGE_ROLES` ships inside `DEFAULT_ADMIN`, so before this guard any admin
/// could mint or assign a role carrying bits the org deliberately withheld —
/// `EXEC_DEVICE`, `SSH_DEVICE`, `ADMINISTRATOR`. The unit tests in
/// `crates/api/src/routes/role.rs` lock the bit algebra; this locks the WIRING,
/// which is the part that can silently regress: a handler that stops calling
/// `check_grant` still passes every unit test.
#[tokio::test]
async fn an_admin_cannot_grant_permissions_it_does_not_hold() {
    // Mirrors `meshharbor_db::models::role::permissions`, spelled out here so a
    // rename over there is a visible break rather than a silently skipped test.
    const ADMINISTRATOR: u64 = 1 << 23;
    const EXEC_DEVICE: u64 = 1 << 27;
    const SEND_MESSAGES: u64 = 1 << 7;

    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("roleesc").await;

    let roles: Vec<Value> = app
        .auth_get(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id_of = |name: &str| {
        roles
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("seeded role {name} not found"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (admin_role, owner_role) = (id_of("admin"), id_of("owner"));

    // The owner promotes the seeded member to `admin` — allowed, because the
    // owner holds ADMINISTRATOR. From here on we act AS that admin.
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                tenant.tenant_id, admin_role, tenant.member.id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "owner may assign admin");
    let admin_token = &tenant.member.access_token;

    // 1. Minting a role that carries a bit the admin lacks: refused.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({ "name": "sneaky", "permissions": EXEC_DEVICE }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "an admin must not be able to mint EXEC_DEVICE"
    );

    // 2. A subset of what the admin holds: allowed. The guard blocks widening,
    //    not role administration.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({ "name": "greeter", "permissions": SEND_MESSAGES }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "granting a held bit is fine");
    let created: Value = resp.json().await.unwrap();
    let greeter = created["id"].as_str().unwrap().to_string();

    // 3. Widening that role afterwards: refused. (Same bit, second door.)
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/role/{}", tenant.tenant_id, greeter),
            admin_token,
        )
        .json(&serde_json::json!({ "permissions": SEND_MESSAGES | EXEC_DEVICE }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "an admin must not be able to widen a role past its own mask"
    );

    // 4. The takeover: assigning the pre-existing `owner` role (ALL, including
    //    ADMINISTRATOR) to itself. Gating create/update alone would leave this
    //    wide open, because the powerful role already exists.
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                tenant.tenant_id, owner_role, tenant.member.id
            ),
            admin_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "an admin must not be able to assign itself owner"
    );

    // ...and prove it did not take effect: still refused afterwards.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({ "name": "after", "permissions": ADMINISTRATOR }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "the refused assign must not have granted anything"
    );
}

/// The escalation's fourth and fifth doors: `INVITE_MEMBERS`, not
/// `MANAGE_ROLES`.
///
/// Gating the three role routes is not enough. Handing someone a role is
/// handing them its permissions, and three other paths write
/// `tenant_members.role_ids` from caller-supplied ids behind the much weaker
/// `INVITE_MEMBERS` bit. Adding a FRESH account carrying the seeded `owner`
/// role — or mailing it an invite that does — is the same takeover by another
/// route.
#[tokio::test]
async fn invite_paths_cannot_grant_roles_the_caller_does_not_hold() {
    let app = TestApp::spawn().await;
    let tenant = app.seed_tenant("inviteesc").await;

    let roles: Vec<Value> = app
        .auth_get(
            &format!("/api/tenant/{}/role", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id_of = |name: &str| {
        roles
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("seeded role {name} not found"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (admin_role, owner_role, member_role) = (id_of("admin"), id_of("owner"), id_of("member"));

    // Promote the seeded member to `admin` (holds INVITE_MEMBERS, not
    // ADMINISTRATOR), then act as them.
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                tenant.tenant_id, admin_role, tenant.member.id
            ),
            &tenant.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let admin_token = &tenant.member.access_token;

    let outsider = app
        .register_user(
            "outsider@inviteesc.test",
            "outsider_inviteesc",
            "Outsider",
            "Outsider123!",
            None,
            None,
        )
        .await;

    // 1. add_member with the owner role: refused.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/member", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({ "user_id": outsider.id, "role_ids": [owner_role] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "add_member must not grant a role the caller cannot grant"
    );

    // 2. ...but adding them with a role the caller DOES hold still works.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/member", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({ "user_id": outsider.id, "role_ids": [member_role] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "inviting with a held role must keep working"
    );

    // 3. An invite carrying the owner role: refused at CREATION, because at
    //    redemption the actor is the invitee, granting themselves nothing.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/invite", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({ "assign_role_ids": [owner_role] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "an invite is a deferred grant and must answer to the same rule"
    );

    // 4. An invite with no roles at all stays unprivileged and allowed.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/invite", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({ "assign_role_ids": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "a plain invite must still work"
    );

    // 5. The owner is unaffected — ADMINISTRATOR bypasses, as everywhere else.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/invite", tenant.tenant_id),
            &tenant.admin.access_token,
        )
        .json(&serde_json::json!({ "assign_role_ids": [owner_role] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "the owner may still delegate ownership"
    );

    // 6. Batch invites report the refusal per item rather than aborting.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/invite/batch", tenant.tenant_id),
            admin_token,
        )
        .json(&serde_json::json!({
            "invites": [
                { "target_email": "ok@inviteesc.test", "assign_role_ids": [member_role] },
                { "target_email": "bad@inviteesc.test", "assign_role_ids": [owner_role] },
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["created"], 1,
        "the grantable invite is created: {body}"
    );
    assert_eq!(body["failed"], 1, "the escalating one is refused: {body}");
}
