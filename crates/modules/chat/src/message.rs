// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::ChatState;
use meshharbor_db::models::{Mentions, MessageAttachment};
use meshharbor_services::dao::base::PaginationParams;

#[derive(Debug, Deserialize)]
pub struct MentionRequest {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub everyone: bool,
    #[serde(default)]
    pub here: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateMessageRequest {
    pub content: String,
    pub thread_id: Option<String>,
    pub referenced_message_id: Option<String>,
    pub nonce: Option<String>,
    pub mentions: Option<MentionRequest>,
    #[serde(default)]
    pub attachment_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMessageRequest {
    pub content: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct AttachmentResponse {
    pub file_id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MessageResponse {
    pub id: String,
    /// P4 — carried so a multi-org client can route a `message:create` for a
    /// NON-active org into its per-org badge store (without it, cross-org
    /// events could only inflate the wrong org's badges or be dropped).
    pub tenant_id: String,
    pub room_id: String,
    pub author_id: String,
    pub author_name: String,
    /// FR-90 — `user` | `bot` | …: a client renders an agent's turn stub
    /// differently from a person's message, and must not offer to DM a bot.
    pub author_type: &'static str,
    /// FR-90 — what owns this message's meaning (a turn stub's session), if
    /// anything. Chat never interprets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<meshharbor_db::models::Binding>,
    pub content: String,
    pub message_type: String,
    pub is_pinned: bool,
    pub is_edited: bool,
    pub is_thread_root: bool,
    pub thread_id: Option<String>,
    pub referenced_message_id: Option<String>,
    pub reaction_summary: Vec<ReactionSummaryResponse>,
    pub attachments: Vec<AttachmentResponse>,
    pub is_read: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reply_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reply_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ReactionSummaryResponse {
    pub emoji: String,
    pub count: u32,
}

pub async fn list(
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

    let result = state.messages.find_in_room(rid, &params).await?;

    let author_ids = collect_author_ids(&result.items);
    let names = state
        .users
        .find_display_names(&author_ids)
        .await
        .unwrap_or_default();
    let viewer_id = Some(auth.user_id);

    let items: Vec<MessageResponse> = result
        .items
        .into_iter()
        .map(|m| to_response(m, &names, viewer_id))
        .collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
        "total_pages": result.total_pages,
    })))
}

pub async fn create(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    Json(body): Json<CreateMessageRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let thread_id = body
        .thread_id
        .as_ref()
        .map(ObjectId::parse_str)
        .transpose()
        .map_err(|_| ApiError::BadRequest("Invalid thread_id".to_string()))?;

    let ref_msg_id = body
        .referenced_message_id
        .as_ref()
        .map(ObjectId::parse_str)
        .transpose()
        .map_err(|_| ApiError::BadRequest("Invalid referenced_message_id".to_string()))?;

    // Parse mentions from request
    let mentions = if let Some(ref mention_req) = body.mentions {
        let user_ids: Vec<ObjectId> = mention_req
            .users
            .iter()
            .filter_map(|s| ObjectId::parse_str(s).ok())
            .collect();
        Some(Mentions {
            users: user_ids,
            roles: Vec::new(),
            rooms: Vec::new(),
            everyone: mention_req.everyone,
            here: mention_req.here,
        })
    } else {
        None
    };

    // Fetch file records for attachments (tenant-scoped to prevent cross-tenant access)
    let attachments = if !body.attachment_ids.is_empty() {
        let mut att = Vec::new();
        for file_id_str in &body.attachment_ids {
            if let Ok(fid) = ObjectId::parse_str(file_id_str)
                && let Ok(file) = state.files.base.find_by_id_in_tenant(tid, fid).await
            {
                att.push(MessageAttachment {
                    file_id: file.id.unwrap(),
                    filename: file.filename,
                    content_type: file.content_type,
                    size: file.size,
                    url: file.url,
                    thumbnail_url: file.thumbnails.first().map(|t| t.url.clone()),
                    is_spoiler: false,
                });
            }
        }
        att
    } else {
        Vec::new()
    };

    let message = state
        .messages
        .create_with_attachments(
            tid,
            rid,
            auth.user_id,
            body.content.clone(),
            thread_id,
            ref_msg_id,
            body.nonce,
            mentions,
            attachments,
        )
        .await?;

    let message_id = message.id.unwrap();

    // Fetch author display name for the response
    let names = state
        .users
        .find_display_names(&[auth.user_id])
        .await
        .unwrap_or_default();

    // Fetch room member IDs once and reuse for WS broadcast, thread update, and notifications
    let all_member_ids = state.rooms.find_member_user_ids(rid).await?;
    let member_ids_excluding_sender: Vec<ObjectId> = all_member_ids
        .iter()
        .filter(|id| **id != auth.user_id)
        .copied()
        .collect();

    // Broadcast via WebSocket to ALL room members INCLUDING the sender
    // (2026-08-04): sends are fanned out per user, so excluding the sender's
    // user id starved their OTHER browsers/devices of realtime messages.
    // The client dedups by message id (the sending tab already appended the
    // POST response), and skips unread/badge work for its own messages.
    // Mentions + push below keep their own sender-excluded list.
    let response = to_response(message, &names, Some(auth.user_id));
    let event = serde_json::json!({
        "type": "message:create",
        "data": &response,
    });
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &all_member_ids,
        &event,
    )
    .await;

    // If this was a thread reply, broadcast an update for the parent message
    // so other users see the updated is_thread_root + reply_count
    if let Some(parent_id) = thread_id
        && let Ok(parent_msg) = state.messages.base.find_by_id(parent_id).await
    {
        let parent_author_ids = vec![parent_msg.author_id];
        let parent_names = state
            .users
            .find_display_names(&parent_author_ids)
            .await
            .unwrap_or_default();
        let parent_response = to_response(parent_msg, &parent_names, None);
        let parent_event = serde_json::json!({
            "type": "message:update",
            "data": &parent_response,
        });
        // Broadcast to ALL members (including sender, so sender's UI also updates)
        meshharbor_core::ws::dispatcher::broadcast_with_redis(
            &state.ws_storage,
            &state.redis_pubsub,
            &all_member_ids,
            &parent_event,
        )
        .await;
    }

    // Create notifications for mentioned users via helper
    if let Some(ref mention_req) = body.mentions {
        let mentioned_user_ids: Vec<ObjectId> = if mention_req.everyone {
            // @everyone: notify all room members except sender
            member_ids_excluding_sender.clone()
        } else {
            mention_req
                .users
                .iter()
                .filter_map(|s| ObjectId::parse_str(s).ok())
                .filter(|id| *id != auth.user_id)
                .collect()
        };

        let room_name = state
            .rooms
            .base
            .find_by_id(rid)
            .await
            .map(|r| r.name)
            .unwrap_or_default();

        let mentioner_name = names
            .get(&auth.user_id)
            .cloned()
            .unwrap_or_else(|| auth.user_id.to_hex());

        meshharbor_core::notify::notify_mentions(
            &state,
            tid,
            rid,
            message_id,
            auth.user_id,
            &mentioned_user_ids,
            &room_name,
            &body.content,
            &mentioner_name,
            &tenant_id,
            &room_id,
        )
        .await;
    }

    Ok(Json(response))
}

pub async fn update(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id, message_id)): Path<(String, String, String)>,
    Json(body): Json<UpdateMessageRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;
    let mid = ObjectId::parse_str(&message_id)
        .map_err(|_| ApiError::BadRequest("Invalid message_id".to_string()))?;

    crate::guards::require_message_in_tenant(&state, tid, mid, auth.user_id).await?;

    state
        .messages
        .update_content(tid, mid, auth.user_id, body.content.clone())
        .await?;

    // Re-fetch the updated message for the full response. MUST be
    // tenant-scoped: a bare `find_by_id(mid)` here returned ANY tenant's
    // message content in the response even though `update_content` is
    // tenant-scoped and modified nothing (cross-tenant read via edit).
    let updated = state.messages.base.find_by_id_in_tenant(tid, mid).await?;
    let names = state
        .users
        .find_display_names(&[updated.author_id])
        .await
        .unwrap_or_default();
    let response = to_response(updated, &names, Some(auth.user_id));

    // Broadcast to ALL members incl. the sender — reaches their other
    // browsers/devices; the client applies updates idempotently by id.
    let member_ids: Vec<ObjectId> = state.rooms.find_member_user_ids(rid).await?;
    let event = serde_json::json!({
        "type": "message:update",
        "data": &response,
    });
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &member_ids,
        &event,
    )
    .await;

    Ok(Json(response))
}

pub async fn delete(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id, message_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;
    let mid = ObjectId::parse_str(&message_id)
        .map_err(|_| ApiError::BadRequest("Invalid message_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    // Verify ownership: only the author can delete their message (tenant-scoped)
    let message = state.messages.base.find_by_id_in_tenant(tid, mid).await?;
    if message.author_id != auth.user_id {
        return Err(ApiError::Forbidden(
            "Only the author can delete this message".to_string(),
        ));
    }

    state.messages.base.soft_delete_in_tenant(tid, mid).await?;

    // All members incl. the sender — reaches their other browsers/devices;
    // delete-by-id is idempotent client-side.
    let member_ids: Vec<ObjectId> = state.rooms.find_member_user_ids(rid).await?;
    let event = serde_json::json!({
        "type": "message:delete",
        "data": {
            "id": message_id,
            "room_id": room_id,
        }
    });
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &member_ids,
        &event,
    )
    .await;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

pub async fn pinned(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<Vec<MessageResponse>>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let messages = state.messages.find_pinned(rid).await?;
    let author_ids = collect_author_ids(&messages);
    let names = state
        .users
        .find_display_names(&author_ids)
        .await
        .unwrap_or_default();
    let response: Vec<MessageResponse> = messages
        .into_iter()
        .map(|m| to_response(m, &names, Some(auth.user_id)))
        .collect();

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct TogglePinRequest {
    pub pinned: bool,
}

pub async fn toggle_pin(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id, message_id)): Path<(String, String, String)>,
    Json(body): Json<TogglePinRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;
    let mid = ObjectId::parse_str(&message_id)
        .map_err(|_| ApiError::BadRequest("Invalid message_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    state.messages.toggle_pin(tid, mid, body.pinned).await?;

    let member_ids = state.rooms.find_member_user_ids(rid).await?;
    let event = serde_json::json!({
        "type": if body.pinned { "message:pin" } else { "message:unpin" },
        "data": {
            "message_id": message_id,
            "room_id": room_id,
            "pinned": body.pinned,
        }
    });
    meshharbor_core::ws::dispatcher::broadcast_with_redis(
        &state.ws_storage,
        &state.redis_pubsub,
        &member_ids,
        &event,
    )
    .await;

    Ok(Json(serde_json::json!({ "pinned": body.pinned })))
}

pub async fn thread_replies(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, _room_id, message_id)): Path<(String, String, String)>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let mid = ObjectId::parse_str(&message_id)
        .map_err(|_| ApiError::BadRequest("Invalid message_id".to_string()))?;

    crate::guards::require_message_in_tenant(&state, tid, mid, auth.user_id).await?;

    let result = state.messages.find_thread_replies(mid, &params).await?;

    let author_ids = collect_author_ids(&result.items);
    let names = state
        .users
        .find_display_names(&author_ids)
        .await
        .unwrap_or_default();
    let viewer_id = Some(auth.user_id);

    let items: Vec<MessageResponse> = result
        .items
        .into_iter()
        .map(|m| to_response(m, &names, viewer_id))
        .collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
        "total_pages": result.total_pages,
    })))
}

pub(crate) fn to_response(
    m: meshharbor_db::models::Message,
    names: &HashMap<ObjectId, String>,
    viewer_id: Option<ObjectId>,
) -> MessageResponse {
    let author_name = m.author_label(names);
    let author_type = m.author_type_str();
    let is_read = viewer_id.is_some_and(|uid| m.readby.iter().any(|r| r == &uid));
    let (reply_count, last_reply_at, last_reply_user_id) = match &m.thread_metadata {
        Some(tm) => (
            Some(tm.reply_count),
            tm.last_reply_at
                .as_ref()
                .map(|d| d.try_to_rfc3339_string().unwrap_or_default()),
            tm.last_reply_user_id.map(|u| u.to_hex()),
        ),
        None => (None, None, None),
    };
    MessageResponse {
        id: m.id.unwrap().to_hex(),
        tenant_id: m.tenant_id.to_hex(),
        room_id: m.room_id.to_hex(),
        author_id: m.author_id.to_hex(),
        author_name,
        author_type,
        binding: m.binding,
        content: m.content,
        message_type: format!("{:?}", m.message_type),
        is_pinned: m.is_pinned,
        is_edited: m.is_edited,
        is_thread_root: m.is_thread_root,
        thread_id: m.thread_id.map(|t| t.to_hex()),
        referenced_message_id: m.referenced_message_id.map(|r| r.to_hex()),
        reaction_summary: m
            .reaction_summary
            .into_iter()
            .map(|r| ReactionSummaryResponse {
                emoji: r.emoji,
                count: r.count,
            })
            .collect(),
        attachments: m
            .attachments
            .into_iter()
            .map(|a| AttachmentResponse {
                file_id: a.file_id.to_hex(),
                filename: a.filename,
                content_type: a.content_type,
                size: a.size,
                url: a.url,
                thumbnail_url: a.thumbnail_url,
            })
            .collect(),
        is_read,
        reply_count,
        last_reply_at,
        last_reply_user_id,
        created_at: m.created_at.try_to_rfc3339_string().unwrap_or_default(),
        updated_at: m.updated_at.try_to_rfc3339_string().unwrap_or_default(),
    }
}

/// Collect unique author IDs from a slice of messages
fn collect_author_ids(messages: &[meshharbor_db::models::Message]) -> Vec<ObjectId> {
    let mut ids: Vec<ObjectId> = messages.iter().map(|m| m.author_id).collect();
    ids.sort();
    ids.dedup();
    ids
}

#[derive(Debug, Deserialize)]
pub struct MarkReadRequest {
    pub message_ids: Vec<String>,
}

pub async fn mark_read(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    Json(body): Json<MarkReadRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let message_ids: Vec<ObjectId> = body
        .message_ids
        .iter()
        .filter_map(|s| ObjectId::parse_str(s).ok())
        .collect();

    let modified = state
        .messages
        .mark_read(rid, auth.user_id, &message_ids)
        .await?;

    Ok(Json(serde_json::json!({ "marked": modified })))
}

/// Mark EVERY unread message in the room read for the caller (same filter
/// as `unread_count`, so the badge reliably reaches 0). Invoked when a room
/// is opened — Slack-style auto-clear (2026-08-04 user decision).
pub async fn read_all(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let modified = state.messages.mark_all_read(rid, auth.user_id).await?;

    Ok(Json(serde_json::json!({ "marked": modified })))
}

pub async fn unread_count(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let count = state.messages.unread_count(rid, auth.user_id).await?;

    Ok(Json(serde_json::json!({ "count": count })))
}
