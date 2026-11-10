// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use serde::Deserialize;
use std::sync::Arc;

use crate::{error::ApiError, extractors::auth::AuthUser, state::AppState};
use meshharbor_db::models::TaskCategory;

/// POST /api/tenant/:tid/export/conversation-pdf
/// Export conversation as PDF (background task).
#[derive(Debug, Deserialize)]
pub struct ExportPdfRequest {
    pub room_id: String,
}

pub async fn export_conversation_pdf(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<ExportPdfRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&body.room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let task = state
        .tasks
        .create_task(
            tid,
            auth.user_id,
            "export_conversation_pdf".to_string(),
            TaskCategory::Export,
            serde_json::json!({ "room_id": body.room_id, "format": "pdf" }),
        )
        .await?;

    let task_id = task.id.unwrap();
    // FR-69 P3 — `messages` is the `chat` module's; a DAO is a stateless
    // handle on the collection, so this export builds its own. (The PDF
    // export itself belongs with the xlsx one in `chat`; a later move.)
    let messages_dao = Arc::new(meshharbor_services::dao::message::MessageDao::new(
        &state.db,
    ));
    let users_dao = Arc::clone(&state.users);
    let task_store = Arc::clone(state.tasks.store());
    let storage = Arc::clone(&state.storage);

    state.tasks.spawn_task(task_id, async move {
        let params = meshharbor_services::dao::base::PaginationParams {
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
            .map_err(|e| format!("{}", e))?;

        let author_ids: Vec<ObjectId> = result
            .items
            .iter()
            .map(|m| m.author_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mut user_map = std::collections::HashMap::new();
        for uid in &author_ids {
            if let Ok(user) = users_dao.base.find_by_id(*uid).await {
                user_map.insert(*uid, user);
            }
        }

        task_store
            .update_progress(task_id, 60, Some("Generating PDF".to_string()))
            .await
            .map_err(|e| format!("{}", e))?;

        let bytes =
            meshharbor_services::export::pdf::export_conversation(&result.items, &user_map)?;

        // Persist through the storage backend; `file_path` on the task record
        // is the storage KEY (see routes/export.rs for the same convention).
        let file_name = format!("conversation-export-{}.pdf", task_id.to_hex());
        let storage_key = format!("exports/{}", file_name);
        storage
            .put(&storage_key, bytes)
            .await
            .map_err(|e| format!("Failed to store PDF: {}", e))?;

        task_store
            .complete(task_id, Some(storage_key), Some(file_name))
            .await
            .map_err(|e| format!("{}", e))?;

        Ok(())
    });

    Ok(Json(serde_json::json!({
        "task_id": task_id.to_hex(),
        "status": "pending",
    })))
}
