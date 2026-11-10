// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use meshharbor_db::models::role::permissions;
use serde::{Deserialize, Serialize};

use crate::{core_state::Core, error::ApiError, extractors::auth::AuthUser};

/// Require `MANAGE_ROLES` for role administration, returning the caller's own
/// combined mask so the escalation guard below doesn't re-query it. Doubles as
/// the membership check — `get_member_permissions` returns `Forbidden` for a
/// non-member; `owner`/admin pass via the `ADMINISTRATOR` bypass in `has`.
async fn require_manage_roles(
    state: &Core,
    tenant_id: ObjectId,
    user_id: ObjectId,
) -> Result<u64, ApiError> {
    let perms = state
        .tenants
        .get_member_permissions(tenant_id, user_id)
        .await?;
    if !permissions::has(perms, permissions::MANAGE_ROLES) {
        return Err(ApiError::Forbidden(
            "Missing MANAGE_ROLES permission".to_string(),
        ));
    }
    Ok(perms)
}

/// "You cannot grant a permission you do not hold."
///
/// `MANAGE_ROLES` is part of `DEFAULT_ADMIN`, so without this every admin can
/// mint a role carrying `ADMINISTRATOR` / `EXEC_DEVICE` / `SSH_DEVICE` and
/// assign it to themselves. That would make gate 2 of the exec and SSH chains
/// decorative: those bits are deliberately withheld from `DEFAULT_ADMIN`
/// precisely so that running a root shell on a fleet device stays an explicit
/// grant, and a bit anyone can hand themselves is not a grant.
///
/// Only bits being **added** are checked. Renaming, recolouring, or narrowing a
/// role that already carries a permission the caller lacks keeps working —
/// widening is the privileged operation, not touching. `ADMINISTRATOR` holders
/// pass everything, mirroring the bypass in `permissions::has`.
///
/// Pure and synchronous on purpose: the interesting behaviour is bit algebra,
/// and it should be testable without a database.
pub(crate) fn check_grant(held: u64, current: u64, requested: u64) -> Result<(), ApiError> {
    if held & permissions::ADMINISTRATOR != 0 {
        return Ok(());
    }
    let missing = requested & !current & !held;
    if missing != 0 {
        return Err(ApiError::Forbidden(format!(
            "Cannot grant permissions you do not hold: {}",
            permissions::names(missing).join(", ")
        )));
    }
    Ok(())
}

/// The same rule, applied to a set of ROLE IDS rather than a raw mask.
///
/// Handing someone a role is handing them its permissions, so every path that
/// writes `tenant_members.role_ids` is a grant and has to answer to
/// [`check_grant`]. There are four such paths and they are NOT all behind
/// `MANAGE_ROLES`: `invite::add_member`, `invite::create_invite` and
/// `invite::batch_create_invite` sit behind `INVITE_MEMBERS`, which is a far
/// weaker bit and one an org may hand to someone who is not an admin at all.
///
/// Unknown or cross-tenant ids are refused rather than skipped — the lookup is
/// tenant-scoped, so a silent skip would let a caller reference a role the
/// check never sees.
pub(crate) async fn check_grant_roles(
    state: &Core,
    tenant_id: ObjectId,
    held: u64,
    role_ids: &[ObjectId],
) -> Result<(), ApiError> {
    if role_ids.is_empty() || held & permissions::ADMINISTRATOR != 0 {
        return Ok(());
    }
    let mut requested = 0u64;
    for rid in role_ids {
        let role = state
            .roles
            .base
            .find_by_id_in_tenant(tenant_id, *rid)
            .await?;
        requested |= role.permissions;
    }
    check_grant(held, 0, requested)
}

#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<u32>,
    pub position: u32,
    pub permissions: u64,
    pub is_default: bool,
    pub is_managed: bool,
    pub is_mentionable: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub color: Option<u32>,
    pub permissions: Option<u64>,
    pub position: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub color: Option<u32>,
    pub permissions: Option<u64>,
    pub position: Option<u32>,
}

pub async fn list(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<RoleResponse>>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let roles = state.roles.find_for_tenant(tid).await?;
    let response: Vec<RoleResponse> = roles.into_iter().map(to_response).collect();

    Ok(Json(response))
}

pub async fn create(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    let held = require_manage_roles(&state, tid, auth.user_id).await?;
    let perms = body.permissions.unwrap_or(0);
    check_grant(held, 0, perms)?;

    let role = state
        .roles
        .create(
            tid,
            body.name,
            body.description,
            body.color,
            perms,
            false,
            false,
            body.position.unwrap_or(100),
        )
        .await?;

    Ok(Json(to_response(role)))
}

pub async fn update(
    State(state): State<Core>,
    auth: AuthUser,
    Path((tenant_id, role_id)): Path<(String, String)>,
    Json(body): Json<UpdateRoleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&role_id)
        .map_err(|_| ApiError::BadRequest("Invalid role_id".to_string()))?;

    let held = require_manage_roles(&state, tid, auth.user_id).await?;

    // Read the role's CURRENT mask so only the delta is gated. Tenant-scoped,
    // so a role id from another org is a 404 rather than a cross-tenant read.
    if let Some(requested) = body.permissions {
        let existing = state.roles.base.find_by_id_in_tenant(tid, rid).await?;
        check_grant(held, existing.permissions, requested)?;
    }

    state
        .roles
        .update(
            rid,
            tid,
            body.name,
            body.description,
            body.color,
            body.permissions,
            body.position,
        )
        .await?;

    Ok(Json(serde_json::json!({ "updated": true })))
}

pub async fn delete(
    State(state): State<Core>,
    auth: AuthUser,
    Path((tenant_id, role_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&role_id)
        .map_err(|_| ApiError::BadRequest("Invalid role_id".to_string()))?;

    require_manage_roles(&state, tid, auth.user_id).await?;

    state.roles.delete(rid, tid).await?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

pub async fn assign(
    State(state): State<Core>,
    auth: AuthUser,
    Path((tenant_id, role_id, user_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&role_id)
        .map_err(|_| ApiError::BadRequest("Invalid role_id".to_string()))?;
    let uid = ObjectId::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    let held = require_manage_roles(&state, tid, auth.user_id).await?;

    // The most direct escalation: permissions are purely role-derived
    // (`get_member_permissions` ORs the member's role masks, with no owner
    // special case), so the seeded Owner role carries `ALL` including
    // `ADMINISTRATOR`. Without this, one POST assigning Owner to yourself is a
    // full tenant takeover — and gating only `create`/`update` would leave it
    // wide open, since the powerful role already exists.
    check_grant_roles(&state, tid, held, &[rid]).await?;

    state.tenants.assign_role(tid, uid, rid).await?;

    Ok(Json(serde_json::json!({ "assigned": true })))
}

pub async fn unassign(
    State(state): State<Core>,
    auth: AuthUser,
    Path((tenant_id, role_id, user_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&role_id)
        .map_err(|_| ApiError::BadRequest("Invalid role_id".to_string()))?;
    let uid = ObjectId::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    require_manage_roles(&state, tid, auth.user_id).await?;

    state.tenants.remove_role(tid, uid, rid).await?;

    Ok(Json(serde_json::json!({ "removed": true })))
}

fn to_response(r: meshharbor_db::models::Role) -> RoleResponse {
    RoleResponse {
        id: r.id.unwrap().to_hex(),
        tenant_id: r.tenant_id.to_hex(),
        name: r.name,
        description: r.description,
        color: r.color,
        position: r.position,
        permissions: r.permissions,
        is_default: r.is_default,
        is_managed: r.is_managed,
        is_mentionable: r.is_mentionable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permissions::*;

    fn err(r: Result<(), ApiError>) -> String {
        match r {
            Err(ApiError::Forbidden(m)) => m,
            Err(other) => panic!("expected Forbidden, got {other:?}"),
            Ok(()) => panic!("expected a refusal"),
        }
    }

    #[test]
    fn an_admin_cannot_hand_itself_exec_or_ssh() {
        // The whole point of the fix. `MANAGE_ROLES` is in `DEFAULT_ADMIN`;
        // `EXEC_DEVICE` and `SSH_DEVICE` deliberately are not.
        for bit in [EXEC_DEVICE, SSH_DEVICE, ADMINISTRATOR] {
            let msg = err(check_grant(DEFAULT_ADMIN, 0, DEFAULT_ADMIN | bit));
            assert!(
                msg.contains(names(bit)[0].as_str()),
                "refusal should name the bit: {msg}"
            );
        }
    }

    #[test]
    fn assigning_the_owner_role_is_refused() {
        // Permissions are role-derived with no owner special case, so the
        // seeded Owner role (`ALL`) is a full takeover in one request.
        let msg = err(check_grant(DEFAULT_ADMIN, 0, ALL));
        assert!(msg.contains("ADMINISTRATOR"), "{msg}");
    }

    #[test]
    fn administrator_may_grant_anything() {
        check_grant(ADMINISTRATOR, 0, ALL).unwrap();
        check_grant(DEFAULT_ADMIN | ADMINISTRATOR, 0, ALL).unwrap();
    }

    #[test]
    fn granting_a_subset_of_what_you_hold_is_allowed() {
        check_grant(DEFAULT_ADMIN, 0, DEFAULT_MEMBER).unwrap();
        check_grant(DEFAULT_ADMIN, 0, DEFAULT_ADMIN).unwrap();
        check_grant(DEFAULT_ADMIN | EXEC_DEVICE, 0, EXEC_DEVICE).unwrap();
    }

    #[test]
    fn touching_a_role_that_already_outranks_you_still_works() {
        // Only the delta is gated. An admin must still be able to rename or
        // recolour the Owner role, or narrow it — otherwise the guard turns
        // into "roles above you are frozen", which is a different feature.
        check_grant(DEFAULT_ADMIN, ALL, ALL).unwrap();
        check_grant(DEFAULT_ADMIN, ALL, DEFAULT_MEMBER).unwrap();
        check_grant(DEFAULT_ADMIN, EXEC_DEVICE | SSH_DEVICE, EXEC_DEVICE).unwrap();
    }

    #[test]
    fn adding_one_bit_to_a_role_that_outranks_you_is_still_refused() {
        // The role already carries SSH_DEVICE (which the caller lacks) — that
        // part is grandfathered. Adding EXEC_DEVICE on top is not.
        let msg = err(check_grant(
            DEFAULT_ADMIN,
            SSH_DEVICE,
            SSH_DEVICE | EXEC_DEVICE,
        ));
        assert!(msg.contains("EXEC_DEVICE"), "{msg}");
        assert!(
            !msg.contains("SSH_DEVICE"),
            "a pre-existing bit must not be reported as refused: {msg}"
        );
    }

    #[test]
    fn a_no_op_mask_is_never_refused() {
        check_grant(0, 0, 0).unwrap();
        check_grant(0, ALL, ALL).unwrap();
    }

    #[test]
    fn an_unnamed_bit_is_still_refused_and_still_reported() {
        // Masks arrive over the wire as an arbitrary u64. A bit above the
        // named range must not slip through unmentioned just because the
        // table has no name for it.
        let rogue = 1u64 << 40;
        let msg = err(check_grant(DEFAULT_ADMIN, 0, rogue));
        assert!(msg.contains(&format!("{rogue:#x}")), "{msg}");
    }

    // `check_grant_roles` needs a database for the role lookup, so what is
    // testable here is the part that decides WITHOUT one: a set of roles is
    // granted iff the UNION of their masks is grantable. That union is the
    // whole point — three individually-harmless roles can add up to owner.
    #[test]
    fn a_set_of_roles_is_judged_by_the_union_of_its_masks() {
        let held = DEFAULT_ADMIN;
        // Individually fine...
        check_grant(held, 0, MANAGE_CHANNELS).unwrap();
        check_grant(held, 0, KICK_MEMBERS).unwrap();
        // ...and fine together.
        check_grant(held, 0, MANAGE_CHANNELS | KICK_MEMBERS).unwrap();
        // But a role carrying something the caller lacks poisons the union,
        // which is why the invite paths OR every referenced role before asking.
        let msg = err(check_grant(held, 0, MANAGE_CHANNELS | SSH_DEVICE));
        assert!(msg.contains("SSH_DEVICE"), "{msg}");
    }

    #[test]
    fn an_empty_role_set_grants_nothing_and_is_allowed() {
        // `check_grant_roles` short-circuits on an empty list; this is the
        // mask-level statement of the same thing. Inviting someone with no
        // explicit roles must not require any permission beyond the invite bit.
        check_grant(0, 0, 0).unwrap();
    }
}
