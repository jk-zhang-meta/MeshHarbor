// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Centralized log-batch model — rc.58.
//!
//! Stores tracing/console batches from:
//! - the agent worker (source = "agent"),
//! - the SCM service supervisor (source = "service"),
//! - the install wizard (source = "installer"),
//! - the crash recorder (source = "crash"),
//! - the auto-updater (source = "updater"),
//! - the browser viewer (source = "browser").
//!
//! Default-on uploader pushes batches every 5 s; backend gates by tenant
//! scope (the agent JWT's `tenant_id` claim must match the route param),
//! TTL-deletes batches older than 7 days. Indexes set in
//! [`crate::indexes`].
//!
//! See `crates/api/src/routes/agent_log.rs` for the route + validation;
//! see `agents/meshharbord/src/logs_upload.rs` for the agent-side
//! `tracing` layer that produces these batches.

use bson::{DateTime, Document, oid::ObjectId};
use serde::{Deserialize, Serialize};

/// One batch as POSTed by an uploader. Maps 1:1 to a MongoDB document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLogBatch {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// Tenant scope. Always set; matches the agent JWT `tenant_id`
    /// claim for agent-source batches, the user's active tenant for
    /// browser-source batches.
    pub tenant_id: ObjectId,
    pub source: LogSource,
    /// Set for agent-side sources (agent / service / installer / crash
    /// / updater). `None` for browser logs (route-derived from user
    /// JWT, no agent context).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<ObjectId>,
    /// Set for browser logs (the controller user). `None` for
    /// agent-side sources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<ObjectId>,
    /// `rc:*` session hex when the batch was emitted during an active
    /// remote-control session. Drilldown key in the admin UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// SHA256(hostname) — hashed before upload per PII policy
    /// (`ed69c6c` retired raw hostnames from code; same rule applies
    /// to telemetry). Allows fleet-level grouping without identifying
    /// the host directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id_hash: Option<String>,
    /// Workspace version of the agent at upload time. `None` for
    /// browser batches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// Number of lines in this batch — denormalised for fast count
    /// queries without unwinding `lines`.
    pub line_count: u32,
    /// TTL anchor (7-day expiry per the index in
    /// [`crate::indexes::ensure_indexes`]).
    pub created_at: DateTime,
    pub lines: Vec<LogLine>,
}

/// One log line. Mirrors the structured shape that
/// `tracing::Event` / `console.X` produce: timestamp + level + target
/// + a string message + arbitrary structured fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub ts: DateTime,
    pub level: LogLevel,
    /// `tracing` target on the agent side (e.g. `meshharbord::peer`)
    /// or the JS module / `console` site on the browser side.
    pub target: String,
    pub msg: String,
    /// Structured fields from the tracing macro. Unschematized BSON so
    /// future tracing keys are forward-compatible — adding a new field
    /// doesn't require a migration. Common keys for the agent worker:
    /// `session_id`, `norm_x`, `norm_y`, `px`, `py`, `mon` etc.
    #[serde(default, skip_serializing_if = "Document::is_empty")]
    pub fields: Document,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    Agent,
    Service,
    Installer,
    Crash,
    Updater,
    Browser,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl AgentLogBatch {
    pub const COLLECTION: &'static str = "agent_logs";

    /// TTL window — every batch older than this is dropped by the
    /// MongoDB background task. Kept in lockstep with the
    /// `expireAfterSeconds` argument in [`crate::indexes`]. 7 days
    /// matches the user-facing "7-day diagnostic window" decision; see
    /// the rc.58 plan in the project handover notes.
    pub const TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

    /// Server-side validation cap: max lines per batch. Uploaders must
    /// fragment larger bursts. Matches the agent-side flusher's batch
    /// size threshold in `logs_upload.rs`.
    pub const MAX_LINES_PER_BATCH: usize = 500;

    /// Server-side validation cap: max bytes per `msg` field. Lines
    /// with longer `msg` are rejected at validate time — keeps
    /// MongoDB indexes from blowing up when the agent runs out of
    /// memory and serializes a panic backtrace.
    pub const MAX_MSG_BYTES: usize = 64 * 1024;

    /// Server-side validation cap: max total request body size. Set
    /// generously so the 500-line × 64 KB pathological case still fits
    /// with overhead; in practice batches are ~50–200 KB.
    pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
}

impl LogSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Service => "service",
            Self::Installer => "installer",
            Self::Crash => "crash",
            Self::Updater => "updater",
            Self::Browser => "browser",
        }
    }
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire shape lock — uploader/route must agree on field names.
    #[test]
    fn log_level_serializes_uppercase() {
        let lvl = LogLevel::Info;
        let json = serde_json::to_string(&lvl).expect("serialize");
        assert_eq!(json, "\"INFO\"");
    }

    #[test]
    fn log_source_serializes_snake_case() {
        let src = LogSource::Agent;
        let json = serde_json::to_string(&src).expect("serialize");
        assert_eq!(json, "\"agent\"");
        let src = LogSource::Installer;
        let json = serde_json::to_string(&src).expect("serialize");
        assert_eq!(json, "\"installer\"");
    }

    #[test]
    fn log_line_roundtrips() {
        let line = LogLine {
            ts: DateTime::now(),
            level: LogLevel::Info,
            target: "meshharbord::peer".to_string(),
            msg: "input dispatch".to_string(),
            fields: bson::doc! { "norm_x": 0.615, "px": 1181 },
        };
        let json = serde_json::to_string(&line).expect("serialize");
        let back: LogLine = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.target, line.target);
        assert_eq!(back.msg, line.msg);
        assert_eq!(back.level, line.level);
    }

    #[test]
    fn batch_with_empty_lines_serializes() {
        // Edge case: a flush with zero lines (heartbeat). Route still
        // accepts it (no-op in collection).
        let batch = AgentLogBatch {
            id: None,
            tenant_id: ObjectId::new(),
            source: LogSource::Browser,
            agent_id: None,
            user_id: Some(ObjectId::new()),
            session_id: None,
            host_id_hash: None,
            agent_version: None,
            line_count: 0,
            created_at: DateTime::now(),
            lines: vec![],
        };
        let _ = serde_json::to_string(&batch).expect("serialize");
    }
}
