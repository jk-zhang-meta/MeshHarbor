// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::ChatState;
use meshharbor_db::models::TaskCategory;
use meshharbor_services::dao::base::PaginationParams;

#[derive(Debug, Deserialize)]
pub struct ExportConversationRequest {
    pub room_id: String,
}

pub async fn export_conversation(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<ExportConversationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&body.room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    // Create background task
    let task = state
        .tasks
        .create_task(
            tid,
            auth.user_id,
            "export_conversation".to_string(),
            TaskCategory::Export,
            serde_json::json!({ "room_id": body.room_id }),
        )
        .await?;

    let task_id = task.id.unwrap();

    // Spawn async export work
    let messages_dao = Arc::clone(&state.messages);
    let users_dao = Arc::clone(&state.users);
    let task_store = Arc::clone(state.tasks.store());
    let storage = Arc::clone(&state.storage);

    state.tasks.spawn_task(task_id, async move {
        // Fetch all messages in room (up to 10000)
        let params = PaginationParams {
            page: 1,
            per_page: 10000,
            before: None,
        };
        let result = messages_dao
            .find_in_room(rid, &params)
            .await
            .map_err(|e| format!("Failed to fetch messages: {}", e))?;

        task_store
            .update_progress(task_id, 30, Some("Fetched messages".to_string()))
            .await
            .map_err(|e| format!("Failed to update progress: {}", e))?;

        // Collect unique author IDs and fetch users
        let author_ids: Vec<ObjectId> = result
            .items
            .iter()
            .map(|m| m.author_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mut user_map = HashMap::new();
        for uid in &author_ids {
            if let Ok(user) = users_dao.base.find_by_id(*uid).await {
                user_map.insert(*uid, user);
            }
        }

        task_store
            .update_progress(task_id, 60, Some("Fetched user data".to_string()))
            .await
            .map_err(|e| format!("Failed to update progress: {}", e))?;

        // Generate Excel
        let bytes =
            meshharbor_services::export::excel::export_conversation(&result.items, &user_map)
                .map_err(|e| format!("Excel export failed: {}", e))?;

        // Persist the artifact through the storage backend; `file_path` on
        // the task record is the storage KEY (pre-S0 records hold absolute
        // local paths — the download route's Local backend resolves both).
        let file_name = format!("conversation-export-{}.xlsx", task_id.to_hex());
        let storage_key = format!("exports/{}", file_name);
        storage
            .put(&storage_key, bytes)
            .await
            .map_err(|e| format!("Failed to store export file: {}", e))?;

        task_store
            .complete(task_id, Some(storage_key), Some(file_name))
            .await
            .map_err(|e| format!("Failed to complete task: {}", e))?;

        Ok(())
    });

    Ok(Json(serde_json::json!({
        "task_id": task_id.to_hex(),
        "status": "pending",
    })))
}
