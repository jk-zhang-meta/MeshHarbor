// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! rc.58 — centralized log-batch ingest + listing.
//!
//! Two ingest endpoints:
//! - `POST /api/tenant/{tenant_id}/agent/{agent_id}/logs` (auth: agent
//!   JWT; sources: agent / service / installer / crash / updater).
//! - `POST /api/log/browser` (auth: user JWT; source: browser).
//!
//! Both validate the body shape, server-stamp `created_at`, then call
//! [`AgentLogDao::record_batch`].
//!
//! Listing endpoint (admin UI): `GET
//! /api/tenant/{tenant_id}/agent/{agent_id}/logs?limit=N` — standard
//! `AuthUser` + tenant-membership check.
//!
//! Server-side scrub: defense-in-depth strip of JWT-shaped tokens from
//! every `msg` field at ingest time. The agent should never leak a
//! token (per ed69c6c rc.53 PII rules) but this re-scrubs.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use bson::{DateTime, Document, oid::ObjectId};
use meshharbor_db::models::{AgentLogBatch, LogLevel, LogLine, LogSource};
use serde::{Deserialize, Serialize};
use serde_json::json;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::{FleetState, auth_agent::AuthAgent};

/// Body shape POSTed by an uploader. `source` must NOT be `Browser`
/// on the agent-authed route; route handler enforces this.
#[derive(Debug, Deserialize)]
pub struct LogBatchPayload {
    pub source: LogSource,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub host_id_hash: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    pub lines: Vec<LogLine>,
}

#[derive(Debug, Deserialize)]
pub struct ListLogsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct LogsListResponse {
    pub batches: Vec<AgentLogBatchView>,
}

/// View-model for an admin-UI log batch row. Mirrors the wire shape
/// but exposes `id` as hex string + `created_at` as RFC 3339 so the
/// SPA doesn't need to handle BSON dates.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentLogBatchView {
    pub id: String,
    pub source: String,
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub host_id_hash: Option<String>,
    pub agent_version: Option<String>,
    pub line_count: u32,
    pub created_at: String,
    pub lines: Vec<LogLineView>,
}

/// One line as the SPA reads it: `ts` as RFC 3339, like `created_at`. A bare
/// `bson::DateTime` serialises to JSON as `{"$date": …}`, which the logs dialog
/// printed verbatim in place of the time.
#[derive(Debug, Serialize)]
pub struct LogLineView {
    pub ts: String,
    pub level: LogLevel,
    pub target: String,
    pub msg: String,
    #[serde(skip_serializing_if = "Document::is_empty")]
    pub fields: Document,
}

impl From<LogLine> for LogLineView {
    fn from(l: LogLine) -> Self {
        Self {
            ts: l.ts.try_to_rfc3339_string().unwrap_or_default(),
            level: l.level,
            target: l.target,
            msg: l.msg,
            fields: l.fields,
        }
    }
}

impl From<AgentLogBatch> for AgentLogBatchView {
    fn from(b: AgentLogBatch) -> Self {
        Self {
            id: b.id.map(|o| o.to_hex()).unwrap_or_default(),
            source: b.source.as_str().to_string(),
            agent_id: b.agent_id.map(|o| o.to_hex()),
            user_id: b.user_id.map(|o| o.to_hex()),
            session_id: b.session_id,
            host_id_hash: b.host_id_hash,
            agent_version: b.agent_version,
            line_count: b.line_count,
            created_at: b.created_at.try_to_rfc3339_string().unwrap_or_default(),
            lines: b.lines.into_iter().map(Into::into).collect(),
        }
    }
}

/// POST `/api/tenant/{tenant_id}/agent/{agent_id}/logs` — ingest a
/// batch from the agent-side uploader. Auth: agent JWT. The JWT's
/// `tenant_id` + `sub` must match the route params (cross-tenant /
/// cross-agent uploads are rejected as 403).
///
/// Status codes:
///   201 — accepted, batch persisted.
///   401 — missing / malformed / invalid agent JWT, or an agent whose row
///         has been deleted or quarantined.
///   403 — agent-id or tenant-id in route doesn't match JWT claims.
///   422 — payload validation failed (too many lines, oversized msg,
///         body too large, browser source on agent route).
///   500 — DB write failure, or the agent row could not be read.
///
/// The `AuthAgent` extractor is what makes the 401 case real: this handler
/// used to trust the claims alone, so a deleted or quarantined device kept
/// uploading logs for the remaining life of its year-long token.
pub async fn ingest_agent(
    State(state): State<FleetState>,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    agent: AuthAgent,
    Json(payload): Json<LogBatchPayload>,
) -> Result<impl IntoResponse, ApiError> {
    // Route params must match JWT claims — defense-in-depth against
    // route-config mistakes that would let agent A in tenant T upload
    // batches under agent B / tenant T'. JWT validation alone doesn't
    // catch this since the agent's JWT trusts the issuer.
    //
    // Compare against the EXTRACTOR's ids, not the raw claims: those are the
    // ones that were looked up and accepted, so the check cannot pass against
    // an identity the row check never saw.
    if agent.tenant_id.to_hex() != tenant_id {
        return Err(ApiError::Forbidden(
            "tenant_id in route does not match agent JWT".to_string(),
        ));
    }
    if agent.agent_id.to_hex() != agent_id {
        return Err(ApiError::Forbidden(
            "agent_id in route does not match agent JWT".to_string(),
        ));
    }

    // Source must be agent-side. Browser source has its own user-
    // authed route below.
    if payload.source == LogSource::Browser {
        return Err(ApiError::Validation(
            "browser source not accepted on agent-authed route".to_string(),
        ));
    }

    let batch = build_batch(agent.tenant_id, Some(agent.agent_id), None, payload)?;
    state
        .agent_logs
        .record_batch(batch)
        .await
        .map_err(|e| ApiError::Internal(format!("agent_logs insert: {e}")))?;

    Ok((StatusCode::CREATED, Json(json!({ "status": "accepted" }))))
}

/// POST `/api/log/browser` — ingest a batch from the browser. Auth: user
/// JWT; the body names the `tenant_id`, and the caller must be a member of
/// it (the user JWT alone pins no tenant).
///
/// First caller, FR-22 part 4 (2026-09-25): the RC viewer's connect-timing
/// record — one batch of one `rc.connect` line per connect attempt
/// (`ui/src/composables/rcConnectTimingUpload.ts`). The route had existed
/// since rc.58 with no caller at all, so `agent_logs` held zero browser rows
/// for as long as it had a browser source. The exact JSON that caller emits
/// is locked to parse here by `browser_connect_timing_record_parses`.
pub async fn ingest_browser(
    State(state): State<FleetState>,
    auth: AuthUser,
    Json(payload): Json<BrowserLogBatchPayload>,
) -> Result<impl IntoResponse, ApiError> {
    let tid = ObjectId::parse_str(&payload.tenant_id)
        .map_err(|_| ApiError::BadRequest("invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::Forbidden("Not a tenant member".to_string()));
    }

    // Browser route only accepts Browser source.
    if payload.inner.source != LogSource::Browser {
        return Err(ApiError::Validation(
            "non-browser source not accepted on browser route".to_string(),
        ));
    }

    let batch = build_batch(tid, None, Some(auth.user_id), payload.inner)?;
    state
        .agent_logs
        .record_batch(batch)
        .await
        .map_err(|e| ApiError::Internal(format!("agent_logs insert: {e}")))?;

    Ok((StatusCode::CREATED, Json(json!({ "status": "accepted" }))))
}

/// Browser-route body — wraps a [`LogBatchPayload`] with an explicit
/// `tenant_id` since the user JWT alone doesn't pin a tenant.
#[derive(Debug, Deserialize)]
pub struct BrowserLogBatchPayload {
    pub tenant_id: String,
    #[serde(flatten)]
    pub inner: LogBatchPayload,
}

/// GET `/api/tenant/{tenant_id}/agent/{agent_id}/logs?limit=N` —
/// list the most-recent N batches. Auth: standard user JWT + tenant
/// membership. Default limit: 50.
pub async fn list_for_agent(
    State(state): State<FleetState>,
    auth: AuthUser,
    Path((tenant_id, agent_id)): Path<(String, String)>,
    Query(q): Query<ListLogsQuery>,
) -> Result<Json<LogsListResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let aid = ObjectId::parse_str(&agent_id)
        .map_err(|_| ApiError::BadRequest("Invalid agent_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let limit = q.limit.clamp(1, 500);
    let records = state
        .agent_logs
        .list_recent_for_agent(tid, aid, limit)
        .await
        .map_err(|e| ApiError::Internal(format!("agent_logs list: {e}")))?;

    let batches: Vec<AgentLogBatchView> = records.into_iter().map(Into::into).collect();
    Ok(Json(LogsListResponse { batches }))
}

/// Shared builder that validates + stamps server-side fields.
fn build_batch(
    tenant_id: ObjectId,
    agent_id: Option<ObjectId>,
    user_id: Option<ObjectId>,
    mut payload: LogBatchPayload,
) -> Result<AgentLogBatch, ApiError> {
    if payload.lines.len() > AgentLogBatch::MAX_LINES_PER_BATCH {
        return Err(ApiError::Validation(format!(
            "lines exceeds {} per batch",
            AgentLogBatch::MAX_LINES_PER_BATCH
        )));
    }
    for line in payload.lines.iter() {
        if line.msg.len() > AgentLogBatch::MAX_MSG_BYTES {
            return Err(ApiError::Validation(format!(
                "msg exceeds {} bytes",
                AgentLogBatch::MAX_MSG_BYTES
            )));
        }
    }
    // Defense-in-depth scrub for JWT-shaped tokens (agent SHOULD have
    // already scrubbed at source; this catches accidental regressions).
    for line in payload.lines.iter_mut() {
        line.msg = scrub_tokens(&line.msg);
    }
    Ok(AgentLogBatch {
        id: None,
        tenant_id,
        source: payload.source,
        agent_id,
        user_id,
        session_id: payload.session_id,
        host_id_hash: payload.host_id_hash,
        agent_version: payload.agent_version,
        line_count: payload.lines.len() as u32,
        created_at: DateTime::now(),
        lines: payload.lines,
    })
}

/// Strip JWT-shaped substrings (`xxx.yyy.zzz`) and `Bearer <token>`
/// patterns from a string. Returns a NEW String; if no match, returns
/// the original.
fn scrub_tokens(s: &str) -> String {
    // Cheap path: most lines don't look like JWTs. Skip the regex for
    // the 99.9% case.
    if !s.contains("eyJ") && !s.contains("Bearer ") && !s.contains("bearer ") {
        return s.to_string();
    }
    let mut out = s.to_string();
    // JWT: three base64url-ish segments separated by dots, starting
    // with "eyJ" (the magic byte for a JSON-encoded header).
    // Conservative: only replace tokens at least 64 chars total (real
    // JWTs are 200+ chars; below 64 is likely a false positive).
    let bytes = out.as_bytes();
    let mut i = 0;
    let mut replacements: Vec<(usize, usize)> = Vec::new();
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] == b"eyJ" {
            // Find run end: chars in [A-Za-z0-9._-].
            let mut j = i + 3;
            let mut dots = 0;
            while j < bytes.len() {
                let c = bytes[j];
                if c == b'.' {
                    dots += 1;
                } else if !c.is_ascii_alphanumeric() && c != b'_' && c != b'-' {
                    break;
                }
                j += 1;
            }
            if dots >= 2 && j - i >= 64 {
                replacements.push((i, j));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // Apply in reverse to keep indices valid.
    for (start, end) in replacements.iter().rev() {
        out.replace_range(*start..*end, "[REDACTED_JWT]");
    }
    // Handle Bearer + bearer prefixes followed by long-ish tokens.
    for prefix in &["Bearer ", "bearer "] {
        while let Some(pos) = out.find(prefix) {
            let after = pos + prefix.len();
            let bytes = out.as_bytes();
            let mut j = after;
            while j < bytes.len() {
                let c = bytes[j];
                if !c.is_ascii_alphanumeric() && c != b'.' && c != b'_' && c != b'-' {
                    break;
                }
                j += 1;
            }
            if j - after >= 8 {
                out.replace_range(pos..j, "[REDACTED_BEARER]");
            } else {
                // Short suffix; advance past prefix to avoid infinite loop.
                let mut tmp = out;
                tmp.replace_range(pos..pos + prefix.len() - 1, "_");
                out = tmp;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_lines_carry_an_rfc3339_time_not_a_bson_date() {
        let mut line = sample_line("hello");
        line.ts = DateTime::from_millis(1_793_734_833_625);
        line.fields = bson::doc! { "k": 1 };
        let batch = AgentLogBatch {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            source: LogSource::Agent,
            agent_id: Some(ObjectId::new()),
            user_id: None,
            session_id: None,
            host_id_hash: None,
            agent_version: None,
            line_count: 1,
            created_at: DateTime::now(),
            lines: vec![line],
        };
        let v = serde_json::to_value(AgentLogBatchView::from(batch)).unwrap();
        let l = &v["lines"][0];
        assert_eq!(l["ts"], "2026-11-03T19:40:33.625Z", "{l}");
        assert_eq!(l["level"], "INFO");
        assert_eq!(l["msg"], "hello");
        assert_eq!(l["fields"]["k"], 1);
    }

    fn sample_line(msg: &str) -> LogLine {
        LogLine {
            ts: DateTime::now(),
            level: LogLevel::Info,
            target: "test".to_string(),
            msg: msg.to_string(),
            fields: bson::doc! {},
        }
    }

    fn sample_payload(source: LogSource, lines: Vec<LogLine>) -> LogBatchPayload {
        LogBatchPayload {
            source,
            session_id: Some("69ab".to_string()),
            host_id_hash: Some("abc123".to_string()),
            agent_version: Some("0.3.0-rc.58".to_string()),
            lines,
        }
    }

    #[test]
    fn build_batch_stamps_server_fields() {
        let tid = ObjectId::new();
        let aid = ObjectId::new();
        let batch = build_batch(
            tid,
            Some(aid),
            None,
            sample_payload(LogSource::Agent, vec![sample_line("hello")]),
        )
        .expect("build_batch");
        assert_eq!(batch.tenant_id, tid);
        assert_eq!(batch.agent_id, Some(aid));
        assert_eq!(batch.user_id, None);
        assert_eq!(batch.line_count, 1);
        assert_eq!(batch.source, LogSource::Agent);
    }

    #[test]
    fn build_batch_rejects_oversized_batch() {
        let tid = ObjectId::new();
        let lines: Vec<LogLine> = (0..(AgentLogBatch::MAX_LINES_PER_BATCH + 1))
            .map(|_| sample_line("x"))
            .collect();
        let err = build_batch(tid, None, None, sample_payload(LogSource::Browser, lines))
            .expect_err("should reject");
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn build_batch_rejects_oversized_msg() {
        let tid = ObjectId::new();
        let big_msg = "x".repeat(AgentLogBatch::MAX_MSG_BYTES + 1);
        let payload = sample_payload(LogSource::Agent, vec![sample_line(&big_msg)]);
        let err = build_batch(tid, None, None, payload).expect_err("should reject");
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn build_batch_scrubs_jwt_in_msg() {
        let tid = ObjectId::new();
        // Realistic JWT shape — three base64url segments, ~200 chars total.
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let msg = format!("connecting with token {jwt} ok");
        let payload = sample_payload(LogSource::Agent, vec![sample_line(&msg)]);
        let batch =
            build_batch(tid, None, None, payload).expect("build_batch should succeed after scrub");
        assert!(
            !batch.lines[0].msg.contains(jwt),
            "raw JWT should not survive scrub: {}",
            batch.lines[0].msg
        );
        assert!(batch.lines[0].msg.contains("[REDACTED_JWT]"));
    }

    #[test]
    fn build_batch_scrubs_bearer_header() {
        let tid = ObjectId::new();
        let msg = "header was: Bearer somelongtokenvaluehere1234567890";
        let payload = sample_payload(LogSource::Agent, vec![sample_line(msg)]);
        let batch = build_batch(tid, None, None, payload).expect("build_batch");
        assert!(batch.lines[0].msg.contains("[REDACTED_BEARER]"));
        assert!(!batch.lines[0].msg.contains("somelongtokenvaluehere"));
    }

    /// FR-22 part 4 — the RC viewer's connect-timing record, in exactly the
    /// shape `ui/src/composables/rcConnectTimingUpload.ts` emits. The browser
    /// has no other way to learn that its `ts` (canonical extended JSON —
    /// what `bson::DateTime` round-trips through `serde_json`) and its
    /// `fields` document parse on this route: a POST that 422s is swallowed
    /// by design, so a shape drift would show up as `agent_logs` staying
    /// empty — which is indistinguishable from nobody connecting.
    #[test]
    fn browser_connect_timing_record_parses() {
        let raw = r#"{
            "tenant_id": "69f0000000000000000000a1",
            "source": "browser",
            "session_id": "69f0000000000000000000b2",
            "lines": [{
                "ts": {"$date": {"$numberLong": "1758826800000"}},
                "level": "INFO",
                "target": "rc.connect",
                "msg": "attempt 1 ttff 2736ms — ws_ready:+12 turn_ready:+64 probes_ready:+28 request_sent:+3 session_created:+43 ready:+53 offer_sent:+9 answer:+214 pc_connected:+1150 dc_open:+788 first_frame:+372",
                "fields": {
                    "v": 1,
                    "outcome": "first_frame",
                    "attempt": 1,
                    "after_drop": false,
                    "hidden": false,
                    "stalled_at": null,
                    "ttff_ms": 2736,
                    "agent_id": "69f0000000000000000000c3",
                    "marks": {"ws_ready": 12, "turn_ready": 76, "first_frame": 2736}
                }
            }]
        }"#;
        let payload: BrowserLogBatchPayload =
            serde_json::from_str(raw).expect("the viewer's record must parse");
        assert_eq!(payload.inner.source, LogSource::Browser);
        assert_eq!(
            payload.inner.session_id.as_deref(),
            Some("69f0000000000000000000b2")
        );
        let tid = ObjectId::parse_str(&payload.tenant_id).expect("tenant hex");
        let batch =
            build_batch(tid, None, Some(ObjectId::new()), payload.inner).expect("build_batch");
        assert_eq!(batch.line_count, 1);
        let line = &batch.lines[0];
        assert_eq!(line.ts.timestamp_millis(), 1_758_826_800_000);
        assert_eq!(line.level, LogLevel::Info);
        assert_eq!(line.target, "rc.connect");
        assert_eq!(line.fields.get_str("outcome"), Ok("first_frame"));
        assert_eq!(line.fields.get_bool("hidden"), Ok(false));
        assert!(matches!(
            line.fields.get("stalled_at"),
            Some(bson::Bson::Null)
        ));
        let marks = line.fields.get_document("marks").expect("marks doc");
        // serde_json hands an integer to bson as i64 or i32 depending on the
        // path; the record only promises "a number of milliseconds".
        let first_frame = match marks.get("first_frame") {
            Some(bson::Bson::Int32(v)) => i64::from(*v),
            Some(bson::Bson::Int64(v)) => *v,
            other => panic!("first_frame should be an integer, got {other:?}"),
        };
        assert_eq!(first_frame, 2736);
        // An unreached mark is ABSENT, never zero: its absence is the finding.
        assert!(marks.get("answer").is_none());
    }

    /// The abandoned shape: no `session_id` (a `requesting` stall never got
    /// one), `WARN`, and `stalled_at` naming the wait that never completed.
    #[test]
    fn browser_connect_timing_abandoned_record_parses() {
        let raw = r#"{
            "tenant_id": "69f0000000000000000000a1",
            "source": "browser",
            "lines": [{
                "ts": {"$date": {"$numberLong": "1758826804000"}},
                "level": "WARN",
                "target": "rc.connect",
                "msg": "attempt 1 INCOMPLETE (stalled waiting for session_created) — ws_ready:+12 turn_ready:+64 probes_ready:+28 request_sent:+3 session_created:— ready:— offer_sent:— answer:— pc_connected:— dc_open:— first_frame:—",
                "fields": {
                    "v": 1,
                    "outcome": "abandoned",
                    "attempt": 1,
                    "after_drop": false,
                    "hidden": true,
                    "stalled_at": "session_created",
                    "ttff_ms": null,
                    "agent_id": "69f0000000000000000000c3",
                    "marks": {"ws_ready": 12, "turn_ready": 76, "probes_ready": 104, "request_sent": 107}
                }
            }]
        }"#;
        let payload: BrowserLogBatchPayload = serde_json::from_str(raw).expect("parse");
        assert_eq!(payload.inner.session_id, None);
        let tid = ObjectId::parse_str(&payload.tenant_id).expect("tenant hex");
        let batch =
            build_batch(tid, None, Some(ObjectId::new()), payload.inner).expect("build_batch");
        let line = &batch.lines[0];
        assert_eq!(line.level, LogLevel::Warn);
        assert_eq!(line.fields.get_str("stalled_at"), Ok("session_created"));
        assert_eq!(line.fields.get_bool("hidden"), Ok(true));
        assert!(matches!(line.fields.get("ttff_ms"), Some(bson::Bson::Null)));
    }

    /// FR-16 L4 — the bench viewer's input-to-photon record, in exactly the
    /// shape `buildL4Upload` in `ui/src/composables/rcBench.ts` emits (its
    /// spec builds the same body from the same numbers). Round trips are
    /// fractional milliseconds, so they arrive as doubles; a shape drift
    /// would 422, be swallowed, and look like nobody benchmarking.
    #[test]
    fn browser_l4_bench_record_parses() {
        let raw = r#"{
            "tenant_id": "69f0000000000000000000a1",
            "source": "browser",
            "session_id": "69f0000000000000000000b2",
            "lines": [{
                "ts": {"$date": {"$numberLong": "1760364000000"}},
                "level": "INFO",
                "target": "rc.l4",
                "msg": "L4 n=3 lost=1 p50=45.6ms p95=61.2ms max=61.2ms path=video",
                "fields": {
                    "v": 1,
                    "paths": ["video"],
                    "n": 3,
                    "lost": 1,
                    "p50_ms": 45.6,
                    "p95_ms": 61.2,
                    "min_ms": 38,
                    "max_ms": 61.2,
                    "rtt_ms": [45.6, 38, 61.2],
                    "agent_id": "69f0000000000000000000c3"
                }
            }]
        }"#;
        let payload: BrowserLogBatchPayload =
            serde_json::from_str(raw).expect("the bench viewer's record must parse");
        let tid = ObjectId::parse_str(&payload.tenant_id).expect("tenant hex");
        let batch =
            build_batch(tid, None, Some(ObjectId::new()), payload.inner).expect("build_batch");
        let line = &batch.lines[0];
        assert_eq!(line.target, "rc.l4");
        assert_eq!(line.level, LogLevel::Info);
        assert_eq!(line.fields.get_f64("p50_ms"), Ok(45.6));
        let rtts = line.fields.get_array("rtt_ms").expect("rtt_ms array");
        assert_eq!(rtts.len(), 3);
        assert_eq!(
            line.fields
                .get_array("paths")
                .expect("paths")
                .first()
                .and_then(|p| p.as_str()),
            Some("video")
        );
    }

    #[test]
    fn scrub_tokens_passes_through_non_jwt() {
        let s = "just a normal log line with no secrets";
        assert_eq!(scrub_tokens(s), s);
    }

    #[test]
    fn scrub_tokens_ignores_short_eyj_prefix() {
        // "eyJ" appears in non-JWT contexts too (e.g. base64-encoded
        // text that happens to start with these chars). Don't scrub
        // unless the full JWT shape (>=64 chars + 2 dots) is present.
        let s = "saw eyJabc not a real jwt";
        assert_eq!(scrub_tokens(s), s);
    }

    // The bearer-parsing test moved with the behaviour, to
    // `crate::extractors::agent` — this route no longer parses the header
    // itself; the `AuthAgent` extractor does, and checks the agent row too.
}
