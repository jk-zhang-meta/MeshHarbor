// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    response::Response,
};
use bson::oid::ObjectId;
use serde::Serialize;

use crate::{core_state::Core, error::ApiError, extractors::auth::AuthUser};
use meshharbor_services::dao::base::PaginationParams;

#[derive(Debug, Serialize)]
pub struct TaskResponse {
    pub id: String,
    pub task_type: String,
    pub status: String,
    pub progress: u8,
    pub logs: Vec<String>,
    pub file_name: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
}

pub async fn list(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    let result = state
        .tasks
        .list_user_tasks(tid, auth.user_id, &params)
        .await?;

    let items: Vec<TaskResponse> = result
        .items
        .into_iter()
        .map(|t| TaskResponse {
            id: t.id.unwrap().to_hex(),
            task_type: t.task_type,
            status: format!("{:?}", t.status),
            progress: t.progress,
            logs: t.logs,
            file_name: t.file_name,
            error: t.error,
            created_at: t.created_at.try_to_rfc3339_string().unwrap_or_default(),
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

pub async fn get(
    State(state): State<Core>,
    auth: AuthUser,
    Path((_tenant_id, task_id)): Path<(String, String)>,
) -> Result<Json<TaskResponse>, ApiError> {
    let task_oid = ObjectId::parse_str(&task_id)
        .map_err(|_| ApiError::BadRequest("Invalid task_id".to_string()))?;

    let task = state.tasks.get_task(task_oid).await?;

    if task.user_id != auth.user_id {
        return Err(ApiError::Forbidden("Not your task".to_string()));
    }

    Ok(Json(TaskResponse {
        id: task.id.unwrap().to_hex(),
        task_type: task.task_type,
        status: format!("{:?}", task.status),
        progress: task.progress,
        logs: task.logs,
        file_name: task.file_name,
        error: task.error,
        created_at: task.created_at.try_to_rfc3339_string().unwrap_or_default(),
    }))
}

pub async fn download(
    State(state): State<Core>,
    auth: AuthUser,
    Path((_tenant_id, task_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let task_oid = ObjectId::parse_str(&task_id)
        .map_err(|_| ApiError::BadRequest("Invalid task_id".to_string()))?;

    let task = state.tasks.get_task(task_oid).await?;

    if task.user_id != auth.user_id {
        return Err(ApiError::Forbidden("Not your task".to_string()));
    }

    let file_path = task
        .file_path
        .ok_or_else(|| ApiError::NotFound("Task has no file".to_string()))?;
    let file_name = task.file_name.unwrap_or_else(|| "download".to_string());

    // `file_path` is a storage key for post-S0 tasks and an absolute local
    // path for legacy ones; the storage backend resolves both (legacy paths
    // on the S3 backend miss → 404, the accepted answer for artifacts that
    // lived on the wiped pod-ephemeral /tmp).
    let contents = state.storage.get(&file_path).await.map_err(|e| match e {
        crate::storage::StorageError::NotFound => {
            ApiError::NotFound("Export file is no longer available".to_string())
        }
        crate::storage::StorageError::Other(msg) => {
            ApiError::Internal(format!("Failed to read file: {}", msg))
        }
    })?;

    // Determine content type from file name
    let content_type = if file_name.ends_with(".xlsx") {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    } else if file_name.ends_with(".pdf") {
        "application/pdf"
    } else {
        "application/octet-stream"
    };

    Ok(Response::builder()
        .header("Content-Type", content_type)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", file_name),
        )
        .body(Body::from(contents))
        .unwrap())
}
