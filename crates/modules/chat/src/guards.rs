// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Object-level authorisation for room- and message-scoped routes.
//!
//! FR-69 P3 — moved from the api crate's `routes/helpers.rs` unchanged. P4 —
//! the room guards gained `_with` forms over the two DAOs, so `conference`
//! (which owns its own `RoomDao` handle for call state) shares ONE visibility
//! rule instead of a copy; the `ChatState` forms below bind them.

use bson::oid::ObjectId;
use meshharbor_db::models::{Message, Room};
use meshharbor_services::dao::{room::RoomDao, tenant::TenantDao};
use meshharbor_core::ApiError;

use crate::ChatState;

/// [`resolve_room_in_tenant`] over the two DAOs it needs, for a caller whose
/// state is not [`ChatState`].
pub async fn resolve_room_in_tenant_with(
    tenants: &TenantDao,
    rooms: &RoomDao,
    tenant_id: ObjectId,
    room_id: ObjectId,
    user_id: ObjectId,
) -> Result<Room, ApiError> {
    if !tenants.is_member(tenant_id, user_id).await? {
        return Err(ApiError::NotAMember);
    }
    Ok(rooms.base.find_by_id_in_tenant(tenant_id, room_id).await?)
}

/// [`require_room_in_tenant`] over the two DAOs it needs — the one room
/// visibility rule, shared with `conference`.
pub async fn require_room_in_tenant_with(
    tenants: &TenantDao,
    rooms: &RoomDao,
    tenant_id: ObjectId,
    room_id: ObjectId,
    user_id: ObjectId,
) -> Result<Room, ApiError> {
    let room = resolve_room_in_tenant_with(tenants, rooms, tenant_id, room_id, user_id).await?;

    // Room-level read authorization. Tenant membership answers "may you be
    // here at all"; this answers "may you be in THIS room" — the question that
    // previously had no answer, so every member could read every room while
    // the sidebar drew a padlock on most of them.
    //
    // `Public` (the default, and what every pre-existing room reads back as)
    // short-circuits, so this costs no query for the overwhelming majority of
    // requests and changes no behaviour on the day it ships.
    if room.visibility.requires_membership()
        && !rooms.is_member(tenant_id, room_id, user_id).await?
    {
        // NOT FOUND, not FORBIDDEN, for a `Secret` room: 403 would confirm it
        // exists to someone who is not supposed to know that, which is the
        // whole point of Secret. `Private` is listed anyway, so its existence
        // is not a secret and a 403 is the more useful answer.
        return Err(if room.visibility.hidden_from_non_members() {
            ApiError::NotFound("Resource not found".to_string())
        } else {
            ApiError::Forbidden("Not a member of this room".to_string())
        });
    }

    Ok(room)
}

/// Tenant membership + the room resolved WITHIN that tenant, and nothing else.
///
/// This is [`require_room_in_tenant`] without the room-level visibility gate,
/// and it exists for exactly one caller: `join`. Joining is how someone
/// BECOMES a member, so routing it through a check that requires membership
/// would make Private rooms unjoinable — a room you can see, cannot read, and
/// cannot ask to enter.
///
/// ⚠️ Do not reach for this to "skip the check" anywhere else. Every other
/// room-scoped route wants [`require_room_in_tenant`]; a second caller here
/// would be a visibility bypass wearing a helper's name.
pub async fn resolve_room_in_tenant(
    state: &ChatState,
    tenant_id: ObjectId,
    room_id: ObjectId,
    user_id: ObjectId,
) -> Result<Room, ApiError> {
    resolve_room_in_tenant_with(&state.tenants, &state.rooms, tenant_id, room_id, user_id).await
}

/// Object-level authorization gate for room-scoped collaboration routes.
///
/// Returns the room ONLY if it belongs to `tenant_id` AND the caller is a
/// member of that tenant. This is the invariant the older collaboration
/// handlers were missing: `is_member(tid)` alone is satisfied by any tenant
/// the caller belongs to (a user can create their own tenant for free), so it
/// does NOT stop reading or mutating ANOTHER tenant's room by id — the
/// cross-tenant IDOR. Resolving the room *within* the tenant (`{_id,
/// tenant_id}`) closes it: a foreign room resolves to nothing → 404, leaking
/// neither its content nor its existence.
pub async fn require_room_in_tenant(
    state: &ChatState,
    tenant_id: ObjectId,
    room_id: ObjectId,
    user_id: ObjectId,
) -> Result<Room, ApiError> {
    require_room_in_tenant_with(&state.tenants, &state.rooms, tenant_id, room_id, user_id).await
}

/// The message-keyed sibling of [`require_room_in_tenant`]. Handlers keyed by
/// `message_id` (reactions, thread replies, edits) cannot rely on the room
/// check because the id is decoupled from the path room: a caller can pass
/// their own tenant + room but another tenant's message id. Resolving the
/// message within the tenant (`{_id, tenant_id}`) is the binding check.
pub async fn require_message_in_tenant(
    state: &ChatState,
    tenant_id: ObjectId,
    message_id: ObjectId,
    user_id: ObjectId,
) -> Result<Message, ApiError> {
    if !state.tenants.is_member(tenant_id, user_id).await? {
        return Err(ApiError::NotAMember);
    }
    Ok(state
        .messages
        .base
        .find_by_id_in_tenant(tenant_id, message_id)
        .await?)
}
