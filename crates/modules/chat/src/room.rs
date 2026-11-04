// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::oid::ObjectId;
use meshharbor_services::quota;
use serde::{Deserialize, Serialize};

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::ChatState;
use meshharbor_db::models::role::permissions;
use meshharbor_db::models::{MediaSettings, RoomVisibility};
use meshharbor_services::dao::base::PaginationParams;

#[derive(Debug, Deserialize)]
pub struct CreateRoomRequest {
    pub name: String,
    pub parent_id: Option<String>,
    #[serde(default)]
    pub is_open: bool,
    pub media_settings: Option<MediaSettings>,
}

#[derive(Debug, Serialize)]
pub struct RoomResponse {
    pub id: String,
    pub name: String,
    pub path: String,
    pub parent_id: Option<String>,
    pub is_open: bool,
    /// Who may read the room. The UI padlock renders from THIS, not from
    /// `is_open` — that one is "listed in Explore" and drawing a lock for it
    /// claimed a privacy the server never enforced.
    pub visibility: RoomVisibility,
    pub member_count: u32,
    pub message_count: u64,
    pub has_media: bool,
    pub conference_status: Option<String>,
    pub meeting_code: Option<String>,
    pub participant_count: u32,
    /// FR-90 — what owns this room's meaning (an agent session), if anything:
    /// a client renders such a room as that module's surface. Chat never
    /// interprets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<meshharbor_db::models::Binding>,
}

/// Optional sidebar-search params. Flat (never `#[serde(flatten)]` behind
/// axum `Query` — the postmortem lives on `agent_exec.rs`'s AuditQuery); all
/// optional so a bare `GET /room` keeps its exact legacy behavior AND shape.
#[derive(Debug, serde::Deserialize)]
pub struct ListRoomsQuery {
    pub q: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

pub async fn list(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<ListRoomsQuery>,
) -> Result<Json<Vec<RoomResponse>>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let search_mode = params
        .q
        .as_deref()
        .map(str::trim)
        .is_some_and(|q| !q.is_empty())
        || params.page.is_some()
        || params.per_page.is_some();
    let rooms = if search_mode {
        // Server-side search/paging for the capped sidebar: the secret-room
        // visibility condition is pushed into the query so a page can't
        // under-fill (the response stays a bare array; the client infers
        // has_more from items.len() == per_page).
        state
            .rooms
            .search_for_tenant(
                tid,
                auth.user_id,
                params.q.as_deref().map(str::trim).unwrap_or(""),
                &meshharbor_services::dao::base::PaginationParams {
                    page: params.page.unwrap_or(1).max(1),
                    per_page: params.per_page.unwrap_or(20),
                    before: None,
                },
            )
            .await?
    } else {
        state.rooms.find_by_tenant(tid).await?
    };

    // A Secret room must not appear to someone who is not in it — its
    // existence is the thing being kept. Private rooms DO stay listed: that is
    // the difference between the two, and it is what lets someone ask to be
    // let in. Filtered here rather than in the query because the membership
    // test is per-room; the `any_secret` guard keeps the extra reads off the
    // common path, where every room is Public.
    let any_secret = rooms.iter().any(|r| r.visibility.hidden_from_non_members());
    let visible = if any_secret {
        let mut keep = Vec::with_capacity(rooms.len());
        for room in rooms {
            if room.visibility.hidden_from_non_members() {
                let rid = match room.id {
                    Some(id) => id,
                    None => continue,
                };
                if !state.rooms.is_member(tid, rid, auth.user_id).await? {
                    continue;
                }
            }
            keep.push(room);
        }
        keep
    } else {
        rooms
    };

    let response: Vec<RoomResponse> = visible.into_iter().map(to_response).collect();

    Ok(Json(response))
}

pub async fn create(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<CreateRoomRequest>,
) -> Result<Json<RoomResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    // FR-32 P1b — plan `max_channels` cap. Counts live rooms only, so an
    // archived channel does not hold a seat the customer is paying for.
    {
        let tenant = state.tenants.base.find_by_id(tid).await?;
        let used = state.rooms.count_for_tenant(tid).await?;
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) = meshharbor_core::quota::check(&state, &tenant, quota::Limit::MaxChannels, used)
        {
            return Err(ApiError::Forbidden(d.message()));
        }
    }

    let parent_id = body
        .parent_id
        .as_ref()
        .map(ObjectId::parse_str)
        .transpose()
        .map_err(|_| ApiError::BadRequest("Invalid parent_id".to_string()))?;

    let room = state
        .rooms
        .create(
            tid,
            body.name,
            parent_id,
            auth.user_id,
            body.is_open,
            body.media_settings,
            None,
        )
        .await?;

    Ok(Json(to_response(room)))
}

pub async fn join(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    // Previously ungated ENTIRELY: any authenticated user could join ANY room
    // in ANY tenant by id, and then received that room's live WS fan-out —
    // cross-tenant eavesdropping. Binding the room to the path tenant closes
    // that.
    //
    // Resolved WITHOUT the visibility gate, deliberately: joining is how
    // someone becomes a member, so requiring membership here would make a
    // Private room unjoinable — visible in the list, unreadable, and with no
    // way in. That is the one place `resolve_room_in_tenant` may be used.
    let room = crate::guards::resolve_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    // Still NOT gated on `is_open` — that flag means "listed in Explore", not
    // "who may enter", and rooms created through the API default to `false`,
    // so gating on it would stop members joining most channels.
    //
    // Secret IS gated. A Secret room's whole property is that a non-member
    // cannot learn it exists; letting one walk in by guessing an id would give
    // that away and hand them the contents. 404 for the same reason the read
    // path uses 404 — a 403 would confirm the room is there.
    if room.visibility.hidden_from_non_members()
        && !state.rooms.is_member(tid, rid, auth.user_id).await?
    {
        return Err(ApiError::NotFound("Resource not found".to_string()));
    }

    state.rooms.join(tid, rid, auth.user_id).await?;

    Ok(Json(serde_json::json!({ "joined": true })))
}

pub async fn leave(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    state.rooms.leave(tid, rid, auth.user_id).await?;

    Ok(Json(serde_json::json!({ "left": true })))
}

pub async fn get(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<RoomResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    // Goes through the shared guard rather than re-implementing the tenant
    // check: this is the single-room READ, so it is exactly where a
    // Private/Secret room would otherwise be handed to a non-member. The
    // hand-rolled `is_member` + `find_by_id_in_tenant` pair it used to have
    // was equivalent for tenant scope and silently blind to room scope.
    let room = crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    Ok(Json(to_response(room)))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoomRequest {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub purpose: Option<String>,
    pub is_open: Option<bool>,
    pub is_archived: Option<bool>,
    pub is_read_only: Option<bool>,
    /// Who may read the room. Absent = unchanged.
    pub visibility: Option<RoomVisibility>,
}

pub async fn update(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    Json(body): Json<UpdateRoomRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;
    meshharbor_core::guards::require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_CHANNELS,
        "MANAGE_CHANNELS",
    )
    .await?;

    // Closing a room must not lock its own admin out. Adding the actor BEFORE
    // the write means there is no window in which the room is members-only
    // with no members — and `join` is idempotent-ish here because a duplicate
    // row would only widen nothing (same user, same room).
    if let Some(v) = body.visibility
        && v.requires_membership()
        && !state.rooms.is_member(tid, rid, auth.user_id).await?
    {
        state.rooms.join(tid, rid, auth.user_id).await?;
    }

    state
        .rooms
        .update(
            tid,
            rid,
            body.name,
            body.topic,
            body.purpose,
            body.is_open,
            body.is_archived,
            body.is_read_only,
            body.visibility,
        )
        .await?;

    Ok(Json(serde_json::json!({ "updated": true })))
}

pub async fn delete(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;
    meshharbor_core::guards::require_permission(
        &state,
        tid,
        auth.user_id,
        permissions::MANAGE_CHANNELS,
        "MANAGE_CHANNELS",
    )
    .await?;

    state.rooms.cascade_delete(tid, rid).await?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

pub async fn members(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let result = state.rooms.list_members(rid, &params).await?;

    // Batch-fetch user details (username, avatar) for member user IDs
    let user_ids: Vec<ObjectId> = result.items.iter().filter_map(|m| m.user_id).collect();
    let user_map = if !user_ids.is_empty() {
        // Batch-fetch user records for username + avatar (avoids N+1)
        let users = state
            .users
            .base
            .find_by_ids(&user_ids)
            .await
            .unwrap_or_default();
        let mut map = std::collections::HashMap::new();
        for user in users {
            if let Some(uid) = user.id {
                map.insert(uid, (user.username, user.avatar, user.display_name));
            }
        }
        map
    } else {
        std::collections::HashMap::new()
    };

    let items: Vec<serde_json::Value> = result
        .items
        .iter()
        .map(|m| {
            let user_info = m.user_id.and_then(|uid| user_map.get(&uid));
            serde_json::json!({
                "id": m.id.unwrap().to_hex(),
                "user_id": m.user_id.map(|u| u.to_hex()),
                "room_id": m.room_id.to_hex(),
                "display_name": user_info.map(|u| u.2.clone()).or_else(|| m.display_name.clone()).unwrap_or_default(),
                "username": user_info.map(|u| u.0.clone()),
                "avatar": user_info.and_then(|u| u.1.clone()),
                "joined_at": m.joined_at.try_to_rfc3339_string().unwrap_or_default(),
                "unread_count": m.unread_count,
                "is_muted": m.is_muted,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
        "total_pages": result.total_pages,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ExploreQuery {
    pub q: String,
}

pub async fn explore(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(query): Query<ExploreQuery>,
) -> Result<Json<Vec<RoomResponse>>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let rooms = state.rooms.explore(tid, &query.q).await?;
    let response: Vec<RoomResponse> = rooms.into_iter().map(to_response).collect();

    Ok(Json(response))
}

fn to_response(r: meshharbor_db::models::Room) -> RoomResponse {
    // `r.id.unwrap()` previously panicked when a Mongo document
    // somehow lacked `_id` (or arrived stripped through a custom
    // projection in the future). Any panic inside Axum's handler
    // gets caught by tower_http's catch_panic and surfaces as a 500
    // with no body — exactly the symptom of the recurring 500
    // reports on /api/tenant/.../room. Fall back to an empty hex
    // string so the response still serialises; a missing id will
    // be obvious in the UI / logs without bringing the whole list
    // endpoint down.
    let id_hex = r.id.map(|i| i.to_hex()).unwrap_or_default();
    RoomResponse {
        id: id_hex,
        name: r.name,
        path: r.path,
        parent_id: r.parent_id.map(|p| p.to_hex()),
        is_open: r.is_open,
        visibility: r.visibility,
        member_count: r.member_count,
        message_count: r.message_count,
        has_media: r.media_settings.is_some(),
        conference_status: r.conference_status,
        meeting_code: r.meeting_code,
        participant_count: r.participant_count,
        binding: r.binding,
    }
}
