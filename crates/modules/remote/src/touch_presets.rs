// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-111 P4a — the org's on-screen control presets (spec
//! `docs/fr/FR-111-touch-controls.md` §3d): the presets every member's viewer
//! offers beside the built-ins, in the `touch_presets` collection.
//!
//! - Reading is open to ANY member: every viewer in the org offers them.
//! - Writing takes `MANAGE_TENANT` (open decision 5, built to its
//!   recommendation), like the org's session policy: a stored preset runs on
//!   every member's viewer, so writing one decides for the org.
//! - A preset is resolved WITHIN the tenant on every write, so a foreign id is
//!   a 404 that leaks neither content nor existence.
//! - The body is read strictly: unknown fields, keys the keyboard path cannot
//!   send, oversized lists, long macros are each a 422 with a code
//!   (`TouchPresetRequest::validate`).
//!
//! Each write is logged naming the admin, never the content.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_permission};
use meshharbor_db::models::role::permissions;
use meshharbor_mod_fleet::agent::fmt_dt;
use meshharbor_remote_control::models::{TouchControl, TouchPreset, TouchPresetRequest};
use meshharbor_services::dao::base::DaoError;
use serde::Serialize;
use tracing::{info, warn};

use crate::{RemoteState, routes::refuse};

/// A preset as the viewer reads it: ids as hex, the time as RFC 3339 (never a
/// raw `bson::DateTime`, which serialises as an object).
#[derive(Debug, Serialize)]
pub struct TouchPresetView {
    pub id: String,
    pub name: String,
    pub controls: Vec<TouchControl>,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct TouchPresetList {
    pub items: Vec<TouchPresetView>,
}

fn view(p: TouchPreset) -> TouchPresetView {
    TouchPresetView {
        id: p.id.map(|i| i.to_hex()).unwrap_or_default(),
        name: p.name,
        controls: p.controls,
        updated_at: fmt_dt(p.updated_at),
    }
}

fn tenant_of(tenant_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(tenant_id).map_err(|_| ApiError::BadRequest("Invalid tenant_id".into()))
}

fn preset_of(preset_id: &str) -> Result<ObjectId, ApiError> {
    ObjectId::parse_str(preset_id).map_err(|_| ApiError::BadRequest("Invalid preset_id".into()))
}

/// The request, read strictly; or the code of the 422 that says why not.
fn parse(body: &Bytes) -> Result<(String, Vec<TouchControl>), &'static str> {
    let request: TouchPresetRequest = serde_json::from_slice(body).map_err(|_| "invalid_json")?;
    let name = request.validate()?;
    Ok((name, request.controls))
}

async fn may_write(state: &RemoteState, tid: ObjectId, auth: &AuthUser) -> Result<(), ApiError> {
    require_permission(
        state,
        tid,
        auth.user_id,
        permissions::MANAGE_TENANT,
        "MANAGE_TENANT",
    )
    .await
}

/// `GET /api/tenant/{tenant_id}/touch-preset` — any member.
pub async fn list(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<TouchPresetList>, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }
    let items = state
        .touch_presets
        .list(tid)
        .await?
        .into_iter()
        .map(view)
        .collect();
    Ok(Json(TouchPresetList { items }))
}

/// `POST /api/tenant/{tenant_id}/touch-preset` — `MANAGE_TENANT`. 201 with
/// the stored preset; 409 `name_taken` or `too_many_presets`.
pub async fn create(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    may_write(&state, tid, &auth).await?;
    let (name, controls) = match parse(&body) {
        Ok(v) => v,
        Err(code) => return Ok(refuse(StatusCode::UNPROCESSABLE_ENTITY, code)),
    };
    // A soft cap: two creates racing at the limit may both land, one over.
    if state.touch_presets.count(tid).await? >= TouchPreset::MAX_PER_TENANT {
        return Ok(refuse(StatusCode::CONFLICT, "too_many_presets"));
    }
    let now = DateTime::now();
    let mut preset = TouchPreset {
        id: None,
        tenant_id: tid,
        name,
        controls,
        created_by: auth.user_id,
        updated_by: auth.user_id,
        created_at: now,
        updated_at: now,
    };
    match state.touch_presets.create(&preset).await {
        Ok(id) => {
            preset.id = Some(id);
            info!(tenant = %tid, preset = %id, by = %auth.user_id, "touch preset created");
            Ok((StatusCode::CREATED, Json(view(preset))).into_response())
        }
        Err(DaoError::DuplicateKey(_)) => Ok(refuse(StatusCode::CONFLICT, "name_taken")),
        Err(e) => {
            warn!(tenant = %tid, error = %e, "touch preset: create failed");
            Err(e.into())
        }
    }
}

/// `PUT /api/tenant/{tenant_id}/touch-preset/{preset_id}` — `MANAGE_TENANT`.
/// Replaces the name and the controls; 404 for a preset not in this tenant.
pub async fn update(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path((tenant_id, preset_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    let pid = preset_of(&preset_id)?;
    may_write(&state, tid, &auth).await?;
    let (name, controls) = match parse(&body) {
        Ok(v) => v,
        Err(code) => return Ok(refuse(StatusCode::UNPROCESSABLE_ENTITY, code)),
    };
    match state
        .touch_presets
        .replace(tid, pid, &name, &controls, auth.user_id)
        .await
    {
        Ok(Some(stored)) => {
            info!(tenant = %tid, preset = %pid, by = %auth.user_id, "touch preset changed");
            Ok(Json(view(stored)).into_response())
        }
        Ok(None) => Err(ApiError::NotFound("Touch preset not found".into())),
        Err(DaoError::DuplicateKey(_)) => Ok(refuse(StatusCode::CONFLICT, "name_taken")),
        Err(e) => {
            warn!(tenant = %tid, preset = %pid, error = %e, "touch preset: change failed");
            Err(e.into())
        }
    }
}

/// `DELETE /api/tenant/{tenant_id}/touch-preset/{preset_id}` —
/// `MANAGE_TENANT`. 204; 404 for a preset not in this tenant.
pub async fn delete(
    State(state): State<RemoteState>,
    auth: AuthUser,
    Path((tenant_id, preset_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let tid = tenant_of(&tenant_id)?;
    let pid = preset_of(&preset_id)?;
    may_write(&state, tid, &auth).await?;
    if !state.touch_presets.delete(tid, pid).await? {
        return Err(ApiError::NotFound("Touch preset not found".into()));
    }
    info!(tenant = %tid, preset = %pid, by = %auth.user_id, "touch preset deleted");
    Ok(StatusCode::NO_CONTENT)
}
