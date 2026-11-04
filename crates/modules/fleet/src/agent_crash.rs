// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `/api/agent/crash` (public, agent-authed) +
//! `/api/tenant/{tenant_id}/agent/{agent_id}/crash` (protected,
//! user-authed) — agent crash report ingest + listing.
//!
//! Phase 2 of the Task 9 crash-log feature. The agent's
//! `crash_uploader` POSTs an `AgentCrashPayload` JSON body with an
//! `Authorization: Bearer <agent_jwt>` header. The ingest handler takes the
//! [`AuthAgent`](crate::auth_agent::AuthAgent) extractor — which
//! verifies the JWT *and* confirms the agent's row is still one we accept,
//! the same rule `crates/api/src/ws/handler.rs` applies on the WS upgrade —
//! validates the body shape, and persists via `AgentCrashDao::record`.
//!
//! Admin UI fetches via the protected GET endpoint which goes
//! through the standard `AuthUser` middleware + tenant-membership
//! check.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use bson::oid::ObjectId;
use meshharbor_remote_control::models::{AgentCrashPayload, AgentCrashRecord};
use serde::Serialize;
use serde_json::json;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::{FleetState, auth_agent::AuthAgent};

/// Maximum `log_tail` byte length accepted by the ingest endpoint.
/// Matches `meshharbord::crash_recorder::MAX_PAYLOAD_BYTES` so a
/// drift on either side surfaces as a 422 (server) or a serialise-
/// time failure (agent), not silent data loss.
const MAX_LOG_TAIL_BYTES: usize = 64 * 1024;

/// Plausibility window for the agent's `crashed_at_unix`. A clock-
/// skewed host (NTP not running) could legitimately report a few
/// minutes off; allowing 7 days catches both directions while
/// rejecting payloads that are obviously stale or future-dated.
const MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_FUTURE_SECS: i64 = 60 * 60; // 1h tolerance for clock skew

/// POST `/api/agent/crash` — ingest a crash report from a recently-
/// restarted agent. Auth: `Authorization: Bearer <agent_jwt>`.
///
/// Status codes:
///   201 — accepted, record persisted.
///   401 — missing / malformed / invalid agent JWT, or an agent whose row
///         has been deleted or quarantined.
///   422 — payload validation failed (log_tail too large, summary
///         empty, crashed_at_unix outside plausibility window).
///   500 — DB write failure, or the agent row could not be read.
///
/// The `AuthAgent` extractor is what makes the 401 case real: this handler
/// used to trust the claims alone, so a deleted or quarantined device kept
/// writing crash reports for the remaining life of its year-long token.
pub async fn ingest(
    State(state): State<FleetState>,
    agent: AuthAgent,
    Json(payload): Json<AgentCrashPayload>,
) -> Result<impl IntoResponse, ApiError> {
    validate_payload(&payload)?;

    let _id = state
        .agent_crashes
        .record(agent.tenant_id, agent.agent_id, payload)
        .await
        .map_err(|e| ApiError::Internal(format!("agent_crashes insert: {e}")))?;

    Ok((StatusCode::CREATED, Json(json!({ "status": "accepted" }))))
}

/// GET `/api/tenant/{tenant_id}/agent/{agent_id}/crash` — list the
/// most-recent 50 crash reports for the agent. Auth: standard user
/// JWT + tenant membership.
pub async fn list_for_agent(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> Result<Json<AgentCrashListResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let records = state
        .agent_crashes
        .list_for_agent_in_tenant(tid, aid, 50)
        .await
        .map_err(|e| ApiError::Internal(format!("agent_crashes list: {e}")))?;

    let items: Vec<AgentCrashView> = records.into_iter().map(AgentCrashView::from).collect();
    Ok(Json(AgentCrashListResponse { items }))
}

#[derive(Debug, Serialize)]
pub struct AgentCrashListResponse {
    pub items: Vec<AgentCrashView>,
}

/// View-model for an admin-UI crash row. Mirrors the payload's
/// camelCase shape PLUS the server-side `_id` (hex string) and
/// `reportedAt` (RFC 3339).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCrashView {
    pub id: String,
    pub reported_at: String,
    #[serde(flatten)]
    pub payload: AgentCrashPayload,
}

impl From<AgentCrashRecord> for AgentCrashView {
    fn from(r: AgentCrashRecord) -> Self {
        let id = r.id.map(|o| o.to_hex()).unwrap_or_default();
        let reported_at = r.reported_at.try_to_rfc3339_string().unwrap_or_default();
        AgentCrashView {
            id,
            reported_at,
            payload: r.payload,
        }
    }
}

/// Validate body invariants. Returns `Err(ApiError::Validation)` on
/// failure so the response is 422 not 400.
fn validate_payload(payload: &AgentCrashPayload) -> Result<(), ApiError> {
    if payload.summary.trim().is_empty() {
        return Err(ApiError::Validation(
            "summary must not be empty".to_string(),
        ));
    }
    if payload.log_tail.len() > MAX_LOG_TAIL_BYTES {
        return Err(ApiError::Validation(format!(
            "log_tail exceeds {MAX_LOG_TAIL_BYTES} bytes"
        )));
    }
    let now_unix = chrono::Utc::now().timestamp();
    let age = now_unix.saturating_sub(payload.crashed_at_unix);
    if age > MAX_AGE_SECS {
        return Err(ApiError::Validation(format!(
            "crashed_at_unix older than {} days",
            MAX_AGE_SECS / (24 * 60 * 60)
        )));
    }
    if -age > MAX_FUTURE_SECS {
        return Err(ApiError::Validation(
            "crashed_at_unix is in the future beyond clock-skew tolerance".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::models::CrashReason;

    fn sample_payload() -> AgentCrashPayload {
        AgentCrashPayload {
            crashed_at_unix: chrono::Utc::now().timestamp(),
            reason: CrashReason::Panic,
            summary: "test crash".to_string(),
            log_tail: String::new(),
            agent_version: "0.0.0-test".to_string(),
            os: "linux".to_string(),
            hostname: "test-host".to_string(),
            pid: 42,
            suppressed_since_last: 0,
        }
    }

    // Bearer-parsing tests moved with the behaviour, to
    // `crate::extractors::agent` — this route no longer parses the header
    // itself; the `AuthAgent` extractor does, and checks the agent row too.

    #[test]
    fn validate_payload_accepts_fresh_payload() {
        assert!(validate_payload(&sample_payload()).is_ok());
    }

    #[test]
    fn validate_payload_rejects_empty_summary() {
        let mut p = sample_payload();
        p.summary = "   ".to_string();
        let err = validate_payload(&p).expect_err("should reject");
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn validate_payload_rejects_oversized_log_tail() {
        let mut p = sample_payload();
        p.log_tail = "x".repeat(MAX_LOG_TAIL_BYTES + 1);
        let err = validate_payload(&p).expect_err("should reject");
        match err {
            ApiError::Validation(msg) => assert!(msg.contains("log_tail")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_payload_rejects_far_past_timestamp() {
        let mut p = sample_payload();
        p.crashed_at_unix = chrono::Utc::now().timestamp() - (MAX_AGE_SECS + 60);
        let err = validate_payload(&p).expect_err("should reject");
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn validate_payload_rejects_far_future_timestamp() {
        let mut p = sample_payload();
        p.crashed_at_unix = chrono::Utc::now().timestamp() + (MAX_FUTURE_SECS + 60);
        let err = validate_payload(&p).expect_err("should reject");
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn validate_payload_accepts_minor_clock_skew() {
        // ±30s drift should be fine.
        let mut p = sample_payload();
        p.crashed_at_unix = chrono::Utc::now().timestamp() - 30;
        assert!(validate_payload(&p).is_ok());
        p.crashed_at_unix = chrono::Utc::now().timestamp() + 30;
        assert!(validate_payload(&p).is_ok());
    }
}
