// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! PUBLIC remote-control consent endpoints (Phase 4).
//!
//! A device owner who received an email link / web-push tap lands here to
//! approve or deny a pending remote-control session. There is **no auth
//! extractor** — the unguessable `token` (a `ConsentRequest.token`) IS the
//! capability. The decision resolves the session's in-memory consent slot via
//! `Hub::deliver_consent`, exactly as if the agent (on-host prompt) had replied.

use axum::{
    Json,
    extract::{Path, State},
};
use meshharbor_db::models::consent_request::ConsentRequestStatus;

use meshharbor_core::ApiError;

use crate::FleetState;

/// `POST /api/consent/{token}/approve`
pub async fn approve_consent(
    State(state): State<FleetState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    resolve(&state, &token, true).await
}

/// `POST /api/consent/{token}/deny`
pub async fn deny_consent(
    State(state): State<FleetState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    resolve(&state, &token, false).await
}

async fn resolve(
    state: &FleetState,
    token: &str,
    granted: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req = state
        .consent_requests
        .find_by_token(token)
        .await?
        .ok_or_else(|| ApiError::NotFound("Consent request not found or expired".to_string()))?;

    if req.status != ConsentRequestStatus::Pending {
        return Err(ApiError::BadRequest(
            "This request has already been handled".to_string(),
        ));
    }
    if req.expires_at < bson::DateTime::now() {
        return Err(ApiError::BadRequest("This request has expired".to_string()));
    }

    let id = req
        .id
        .ok_or_else(|| ApiError::Internal("consent request missing id".to_string()))?;
    let status = if granted {
        ConsentRequestStatus::Approved
    } else {
        ConsentRequestStatus::Denied
    };
    // Single-use: only proceed if THIS call flipped Pending → resolved. Guards
    // against a double-click / an approve+deny race replaying the same token.
    let won = state.consent_requests.resolve(id, status).await?;
    if !won {
        return Err(ApiError::BadRequest(
            "This request has already been handled".to_string(),
        ));
    }

    // Resolve the in-memory consent slot. Best-effort: the session may have
    // already timed out or closed, in which case there's nothing to grant — the
    // owner still gets a clean 200 (their decision was recorded).
    if let Err(e) = state.rc_hub.deliver_consent(req.session_id, granted, None) {
        tracing::info!(
            session = %req.session_id, %e,
            "consent slot no longer waiting (session gone / timed out)"
        );
    }
    // C-2 — the approve-link HTTP can land on a pod that doesn't hold the
    // session; broadcast the verdict so the holding pod applies it too
    // (idempotent — the local attempt above already ran here).
    crate::ctrl::publish_rc_ctrl(
        state,
        "consent",
        serde_json::json!({ "session_id": req.session_id.to_hex(), "granted": granted }),
    )
    .await;

    Ok(Json(
        serde_json::json!({ "resolved": true, "granted": granted }),
    ))
}
