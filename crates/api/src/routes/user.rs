// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};
// PaginationParams no longer used here — MemberListQuery is flat (FR-11).

#[derive(Debug, Serialize)]
pub struct MemberResponse {
    pub id: String,
    pub user_id: String,
    pub nickname: Option<String>,
    /// The user's display name (falls back to username), resolved from the users
    /// collection — so member pickers can show a name, not a raw id.
    pub display_name: String,
    /// FR-11: shown on the members grid — org members see each other's
    /// addresses; that is what the page is for. Empty when the user row is
    /// gone (defensive).
    pub email: String,
    pub role_ids: Vec<String>,
    pub joined_at: String,
}

/// FR-11 members-grid params. Flat on purpose — never `#[serde(flatten)]
/// PaginationParams` behind axum's `Query` (the AuditQuery postmortem).
/// All optional/defaulted: a parameterless request behaves as before.
#[derive(Debug, Deserialize)]
pub struct MemberListQuery {
    #[serde(default = "member_default_page")]
    pub page: u64,
    #[serde(default = "member_default_per_page")]
    pub per_page: u64,
    /// Case-insensitive substring over display name, username, nickname and
    /// email.
    pub q: Option<String>,
    /// `name` | `email` | `joined_at` (default). Unknown → 400.
    pub sort: Option<String>,
    /// `asc` (default) | `desc`.
    pub dir: Option<String>,
}
fn member_default_page() -> u64 {
    1
}
fn member_default_per_page() -> u64 {
    25
}

#[derive(Debug, Serialize)]
pub struct ProfileResponse {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub presence: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
}

pub async fn list_members(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<MemberListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let sort_key = params.sort.as_deref();
    if let Some(k) = sort_key
        && !matches!(k, "name" | "email" | "joined_at")
    {
        return Err(ApiError::BadRequest(format!("Unknown sort key: {k}")));
    }
    let desc = match params.dir.as_deref() {
        None | Some("asc") => false,
        Some("desc") => true,
        Some(other) => {
            return Err(ApiError::BadRequest(format!("Unknown dir: {other}")));
        }
    };
    let per_page = params.per_page.clamp(1, 100);
    let page = params.page.max(1);

    // FR-11: in-memory compose, like the devices grid — the search/sort
    // columns (name, email) live in the USERS collection while the rows are
    // tenant_members, and per-tenant membership is tens of rows.
    let members = state
        .tenants
        .members
        .find_many(doc! { "tenant_id": tid }, Some(doc! { "joined_at": 1 }))
        .await?;
    let user_ids: Vec<ObjectId> = members.iter().map(|m| m.user_id).collect();
    let facts = state
        .users
        .find_member_facts(&user_ids)
        .await
        .unwrap_or_default();

    let mut rows: Vec<MemberResponse> = members
        .into_iter()
        .map(|m| {
            let f = facts.get(&m.user_id);
            MemberResponse {
                id: m.id.unwrap().to_hex(),
                user_id: m.user_id.to_hex(),
                nickname: m.nickname,
                display_name: f.map(|f| f.display_name.clone()).unwrap_or_default(),
                email: f.map(|f| f.email.clone()).unwrap_or_default(),
                role_ids: m.role_ids.iter().map(|r| r.to_hex()).collect(),
                joined_at: m.joined_at.try_to_rfc3339_string().unwrap_or_default(),
            }
        })
        .collect();

    if let Some(q) = params.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        let needle = q.to_lowercase();
        rows.retain(|r| {
            r.display_name.to_lowercase().contains(&needle)
                || r.email.to_lowercase().contains(&needle)
                || r.nickname
                    .as_deref()
                    .is_some_and(|n| n.to_lowercase().contains(&needle))
        });
    }

    rows.sort_by(|a, b| {
        let ord = match sort_key {
            Some("name") => a
                .display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase()),
            Some("email") => a.email.to_lowercase().cmp(&b.email.to_lowercase()),
            // Default AND explicit joined_at: the pre-FR order.
            _ => a.joined_at.cmp(&b.joined_at),
        };
        let ord = if desc { ord.reverse() } else { ord };
        ord.then_with(|| a.id.cmp(&b.id))
    });

    let total = rows.len() as u64;
    let total_pages = total.div_ceil(per_page).max(1);
    let start = ((page - 1) * per_page) as usize;
    let items: Vec<MemberResponse> = if start >= rows.len() {
        Vec::new()
    } else {
        rows.into_iter()
            .skip(start)
            .take(per_page as usize)
            .collect()
    };

    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    })))
}

/// DELETE /api/tenant/{tid}/member/{user_id} — remove a member (FR-11).
///
/// First consumer of `KICK_MEMBERS`. The tenant OWNER cannot be removed
/// (409 — ownership transfer is a different operation); removing YOURSELF is
/// allowed and simply means leaving. Room-membership rows are left in place:
/// tenant `is_member` is the access gate on every read/write path, so a
/// removed user loses access structurally. What a pillar RUNS for the member
/// is different — it would outlive the access check — so every holder's
/// `member_removed` hook runs first (FR-90: their agent sessions end).
pub async fn remove_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((tenant_id, member_user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let target = ObjectId::parse_str(&member_user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    // Self-removal (leave) needs no permission; kicking someone else does.
    if target != auth.user_id {
        let perms = state
            .tenants
            .get_member_permissions(tid, auth.user_id)
            .await?;
        if !meshharbor_db::models::role::permissions::has(
            perms,
            meshharbor_db::models::role::permissions::KICK_MEMBERS,
        ) {
            return Err(ApiError::Forbidden(
                "Missing KICK_MEMBERS permission".to_string(),
            ));
        }
    }

    let tenant = state.tenants.base.find_by_id(tid).await?;
    if tenant.owner_id == target {
        return Err(ApiError::Conflict(
            "The organization owner cannot be removed".to_string(),
        ));
    }

    // The holders first, in HOOK_ORDER — FR-90: `hive` ends the member's
    // agent sessions on the org's devices. BEFORE the membership row goes, so
    // a failure refuses the removal rather than leaving sessions running for
    // someone a retry would then find already gone.
    state
        .core
        .hooks
        .member_removed(tid, target)
        .await
        .map_err(|e| ApiError::Internal(format!("member removal cascade: {e}")))?;

    let removed = state.tenants.remove_member(tid, target).await?;
    if !removed {
        return Err(ApiError::NotFound("Not a member".to_string()));
    }
    tracing::info!(admin = %auth.user_id, tenant = %tid, user = %target, "member removed");
    Ok(Json(serde_json::json!({ "removed": true })))
}

pub async fn get_profile(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<ProfileResponse>, ApiError> {
    let uid = ObjectId::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".to_string()))?;

    let user = state.users.base.find_by_id(uid).await?;

    Ok(Json(ProfileResponse {
        id: user.id.unwrap().to_hex(),
        username: user.username,
        display_name: user.display_name,
        avatar: user.avatar,
        bio: user.bio,
        presence: format!("{:?}", user.presence).to_lowercase(),
        created_at: user.created_at.try_to_rfc3339_string().unwrap_or_default(),
    }))
}

pub async fn update_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateProfileRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .users
        .update_profile(
            auth.user_id,
            body.display_name,
            body.bio,
            body.avatar,
            body.locale,
            body.timezone,
        )
        .await?;

    Ok(Json(serde_json::json!({ "updated": true })))
}

/// FR-12 P3 — PUT /api/user/tutorial.
///
/// Both fields are optional and independent: the view writes `done` when a
/// chapter is ticked and `seen: true` exactly once, on the first auto-open.
#[derive(Debug, Deserialize)]
pub struct UpdateTutorialRequest {
    /// The chapter ids this user has completed. Replaces the stored list.
    pub done: Option<Vec<String>>,
    /// `true` marks the welcome tour as shown. There is no way to unset it
    /// from here — see `set_tutorial_state`.
    pub seen: Option<bool>,
}

/// The tutorial is a convenience, never a gate: if this route is unreachable
/// the client keeps working from `localStorage` alone. It is therefore
/// authenticated but deliberately unremarkable — a user may only ever write
/// their OWN state, which is why there is no id in the path.
pub async fn update_tutorial(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateTutorialRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let updated = state
        .users
        .set_tutorial_state(auth.user_id, body.done, body.seen)
        .await?;

    Ok(Json(serde_json::json!({ "updated": updated })))
}

#[derive(Debug, Serialize)]
pub struct MyMembershipResponse {
    /// Combined permission bitmask across all the caller's roles in this
    /// tenant (`role::permissions` flags OR-ed). Value stays < 2^27, so it
    /// is safe as a plain JSON number.
    pub permissions: u64,
    /// Whether the caller is the tenant's owner. Owners may hold no explicit
    /// role, so the UI treats this as an implicit all-permissions grant.
    pub is_owner: bool,
}

/// GET /api/tenant/{tenant_id}/member/me — the caller's own effective
/// permissions in this tenant. Purely informational for the client (nav
/// gating, disabled buttons); every mutating route still enforces its own
/// permission check server-side.
pub async fn my_membership(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<MyMembershipResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    // Non-members get the DAO's Forbidden straight through.
    let permissions = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    let is_owner = state
        .tenants
        .base
        .find_by_id(tid)
        .await
        .map(|t| t.owner_id == auth.user_id)
        .unwrap_or(false);

    Ok(Json(MyMembershipResponse {
        permissions,
        is_owner,
    }))
}

// P4's `GET /api/user/unread-summary` is the `chat` module's since FR-69 P3
// (`meshharbor_mod_chat::user_unread`): it counts messages and rooms.
