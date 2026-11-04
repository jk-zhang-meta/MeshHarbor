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

use crate::ConferenceState;
use meshharbor_services::dao::base::PaginationParams;

#[derive(Debug, Serialize)]
pub struct RecordingResponse {
    pub id: String,
    pub room_id: String,
    pub recording_type: String,
    pub status: String,
    pub content_type: String,
    pub size: u64,
    pub duration: u32,
    pub created_at: String,
}

pub async fn list(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let result = state.recordings.find_by_room(rid, &params).await?;
    let items: Vec<RecordingResponse> = result.items.into_iter().map(to_response).collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
        "total_pages": result.total_pages,
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateRecordingRequest {
    pub recording_type: Option<String>,
}

pub async fn create(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    Json(body): Json<CreateRecordingRequest>,
) -> Result<Json<RecordingResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    // FR-32 P1a — `recordings` is advertised per plan and was enforced nowhere.
    // Ships in the tenant's `plan_enforcement` mode, which defaults to `Warn`:
    // this records the denial and lets the call through until an operator
    // reads the data and flips the tenant to `Enforce`.
    let tenant = state.tenants.base.find_by_id(tid).await?;
    // FR-102 P4 — through core, which also counts the collision per org.
    if let Err(d) = meshharbor_core::quota::require_feature(&state, &tenant, quota::Limit::Recordings)
    {
        return Err(ApiError::Forbidden(d.message()));
    }

    let recording_type = match body.recording_type.as_deref() {
        Some("audio") => meshharbor_db::models::recording::RecordingType::Audio,
        Some("screen_share") => meshharbor_db::models::recording::RecordingType::ScreenShare,
        _ => meshharbor_db::models::recording::RecordingType::Video,
    };

    let now = bson::DateTime::now();
    let storage_file = meshharbor_db::models::recording::StorageFile {
        storage_provider: meshharbor_db::models::recording::StorageProvider::Local,
        bucket: "recordings".to_string(),
        key: format!("{}/{}/{}", tid.to_hex(), rid.to_hex(), uuid::Uuid::new_v4()),
        url: String::new(),
        content_type: "video/webm".to_string(),
        size: 0,
        duration: 0,
        resolution: None,
    };

    let recording = state
        .recordings
        .create(tid, rid, recording_type, storage_file, now, now)
        .await?;

    Ok(Json(to_response(recording)))
}

pub async fn delete(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, _room_id, recording_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rec_id = ObjectId::parse_str(&recording_id)
        .map_err(|_| ApiError::BadRequest("Invalid recording_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    state.recordings.soft_delete(tid, rec_id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

fn to_response(r: meshharbor_db::models::Recording) -> RecordingResponse {
    RecordingResponse {
        id: r.id.unwrap().to_hex(),
        room_id: r.room_id.to_hex(),
        recording_type: format!("{:?}", r.recording_type),
        status: format!("{:?}", r.status),
        content_type: r.file.content_type,
        size: r.file.size,
        duration: r.file.duration,
        created_at: r.created_at.try_to_rfc3339_string().unwrap_or_default(),
    }
}
