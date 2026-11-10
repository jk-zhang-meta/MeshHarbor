// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ChatState;
use meshharbor_core::ApiError;
use meshharbor_core::extractors::auth::AuthUser;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: u64,
}

fn default_limit() -> u64 {
    20
}

#[derive(Serialize)]
pub struct SearchMessageResult {
    pub id: String,
    pub room_id: String,
    pub room_name: String,
    pub author_id: String,
    pub author_name: String,
    pub content_preview: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct SearchRoomResult {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub member_count: u32,
}

#[derive(Serialize)]
pub struct SearchUserResult {
    pub id: String,
    pub display_name: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

#[derive(Serialize)]
pub struct SearchResults {
    pub messages: Vec<SearchMessageResult>,
    pub rooms: Vec<SearchRoomResult>,
    pub users: Vec<SearchUserResult>,
}

pub async fn search(
    State(state): State<ChatState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<SearchQuery>,
    auth: AuthUser,
) -> Result<Json<SearchResults>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let q = query.q.trim();
    if q.is_empty() {
        return Ok(Json(SearchResults {
            messages: Vec::new(),
            rooms: Vec::new(),
            users: Vec::new(),
        }));
    }

    let limit = query.limit.min(50) as i64;

    // Search messages in tenant
    let msg_filter = doc! {
        "tenant_id": tid,
        "deleted_at": null,
        "thread_id": null,
    };
    let messages = state
        .messages
        .base
        .text_search(q, msg_filter, limit)
        .await
        .unwrap_or_default();

    // Collect author IDs and room IDs from messages for enrichment
    let author_ids: Vec<ObjectId> = messages.iter().map(|m| m.author_id).collect();
    let msg_room_ids: Vec<ObjectId> = messages.iter().map(|m| m.room_id).collect();

    let author_names = state
        .users
        .find_display_names(&author_ids)
        .await
        .unwrap_or_default();

    // Batch-fetch room names for message enrichment
    let room_name_map = fetch_room_names(&state, &msg_room_ids).await;

    let message_results: Vec<SearchMessageResult> = messages
        .into_iter()
        .map(|m| {
            let room_name = room_name_map.get(&m.room_id).cloned().unwrap_or_default();
            let author_name = m.author_label(&author_names);
            // Truncate the preview on a CHAR boundary. `&m.content[..200]`
            // sliced on a BYTE index and panics ("byte index 200 is not a
            // char boundary") whenever a multi-byte UTF-8 char straddles byte
            // 200 — so a single crafted message could 500 every OTHER user's
            // search of that room (there is no CatchPanicLayer wired up).
            let content_preview = if m.content.chars().count() > 200 {
                let truncated: String = m.content.chars().take(200).collect();
                format!("{}...", truncated)
            } else {
                m.content.clone()
            };
            SearchMessageResult {
                id: m.id.unwrap().to_hex(),
                room_id: m.room_id.to_hex(),
                room_name,
                author_id: m.author_id.to_hex(),
                author_name,
                content_preview,
                created_at: m.created_at.try_to_rfc3339_string().unwrap_or_default(),
            }
        })
        .collect();

    // Search rooms in tenant
    let room_filter = doc! {
        "tenant_id": tid,
        "deleted_at": null,
    };
    let rooms = state
        .rooms
        .base
        .text_search(q, room_filter, limit)
        .await
        .unwrap_or_default();

    let room_results: Vec<SearchRoomResult> = rooms
        .into_iter()
        .map(|r| SearchRoomResult {
            id: r.id.unwrap().to_hex(),
            name: r.name,
            purpose: r.purpose,
            member_count: r.member_count,
        })
        .collect();

    // Search users (tenant members) — first get member user IDs, then text search users
    let tenant_member_user_ids = get_tenant_member_user_ids(&state, tid).await;
    let user_filter = doc! {
        "_id": { "$in": &tenant_member_user_ids },
        "deleted_at": null,
    };
    let users = state
        .users
        .base
        .text_search(q, user_filter, limit)
        .await
        .unwrap_or_default();

    let user_results: Vec<SearchUserResult> = users
        .into_iter()
        .map(|u| SearchUserResult {
            id: u.id.unwrap().to_hex(),
            display_name: u.display_name,
            username: u.username,
            avatar: u.avatar,
        })
        .collect();

    Ok(Json(SearchResults {
        messages: message_results,
        rooms: room_results,
        users: user_results,
    }))
}

/// Fetch room names for a list of room IDs and return a map.
async fn fetch_room_names(state: &ChatState, room_ids: &[ObjectId]) -> HashMap<ObjectId, String> {
    use futures::TryStreamExt;

    let mut result = HashMap::new();
    if room_ids.is_empty() {
        return result;
    }

    let ids_bson: Vec<bson::Bson> = room_ids
        .iter()
        .map(|id| bson::Bson::ObjectId(*id))
        .collect();
    let filter = doc! { "_id": { "$in": ids_bson } };
    let projection = doc! { "_id": 1, "name": 1 };

    let coll = state
        .rooms
        .base
        .collection()
        .clone_with_type::<bson::Document>();
    if let Ok(mut cursor) = coll.find(filter).projection(projection).await {
        while let Ok(Some(doc)) = cursor.try_next().await {
            if let (Ok(id), Ok(name)) = (doc.get_object_id("_id"), doc.get_str("name")) {
                result.insert(id, name.to_string());
            }
        }
    }

    result
}

/// Get all user IDs that are members of a tenant.
async fn get_tenant_member_user_ids(state: &ChatState, tenant_id: ObjectId) -> Vec<ObjectId> {
    use futures::TryStreamExt;

    let filter = doc! { "tenant_id": tenant_id };
    let projection = doc! { "user_id": 1, "_id": 0 };

    let coll = state
        .tenants
        .members
        .collection()
        .clone_with_type::<bson::Document>();
    let mut user_ids = Vec::new();
    if let Ok(mut cursor) = coll.find(filter).projection(projection).await {
        while let Ok(Some(doc)) = cursor.try_next().await {
            if let Ok(uid) = doc.get_object_id("user_id") {
                user_ids.push(uid);
            }
        }
    }

    user_ids
}
