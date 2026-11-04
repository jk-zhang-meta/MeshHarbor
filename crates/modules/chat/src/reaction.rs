// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use serde::Deserialize;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::ChatState;

#[derive(Debug, Deserialize)]
pub struct AddReactionRequest {
    pub emoji: String,
}

pub async fn add(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, _room_id, message_id)): Path<(String, String, String)>,
    Json(body): Json<AddReactionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let mid = ObjectId::parse_str(&message_id)
        .map_err(|_| ApiError::BadRequest("Invalid message_id".to_string()))?;

    // The reaction is keyed by message id, which is decoupled from the path
    // room — so the message, not the room, is the object we must bind to this
    // tenant, and its own room is the correct fan-out target.
    let message = crate::guards::require_message_in_tenant(&state, tid, mid, auth.user_id).await?;
    let rid = message.room_id;

    let reaction = state
        .reactions
        .add_and_update_summary(&state.messages, tid, rid, mid, auth.user_id, body.emoji)
        .await?;

    let member_ids = state.rooms.find_member_user_ids(rid).await?;
    let event = serde_json::json!({
        "type": "message:reaction",
        "data": {
            "action": "add",
            "message_id": message_id,
            "room_id": rid.to_hex(),
            "user_id": auth.user_id.to_hex(),
            "emoji": reaction.emoji.value,
        }
    });
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &member_ids,
        &event,
    )
    .await;

    Ok(Json(serde_json::json!({ "added": true })))
}

pub async fn remove(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, _room_id, message_id, emoji)): Path<(String, String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let mid = ObjectId::parse_str(&message_id)
        .map_err(|_| ApiError::BadRequest("Invalid message_id".to_string()))?;

    let message = crate::guards::require_message_in_tenant(&state, tid, mid, auth.user_id).await?;

    let removed = state
        .reactions
        .remove_and_update_summary(&state.messages, mid, auth.user_id, &emoji)
        .await?;

    if removed {
        let rid = message.room_id;
        let member_ids = state.rooms.find_member_user_ids(rid).await?;
        let event = serde_json::json!({
            "type": "message:reaction",
            "data": {
                "action": "remove",
                "message_id": message_id,
                "room_id": rid.to_hex(),
                "user_id": auth.user_id.to_hex(),
                "emoji": emoji,
            }
        });
        meshharbor_core::ws::dispatcher::broadcast_with_redis(
            &state.ws_storage,
            &state.redis_pubsub,
            &member_ids,
            &event,
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "removed": removed })))
}
