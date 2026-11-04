// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-40 overlay-key rotation audit log (`key_rotation_audit`).
//!
//! Every rotation ORDER lands here — dispatched to a live socket, queued for
//! the device's next connect, or refused. Both arms come through one call
//! site (`routes::overlay_key`), so a new refusal cannot forget to audit
//! itself; the same shape as `config_audit`.
//!
//! ⚠️ A row records what the SERVER decided, never what the device did. The
//! device's own account is `agents.key_rotation_report` (a claim), and the
//! key it actually joined with afterwards is `agents.overlay_identity` (what
//! the server verified). Three records, three trust levels — never fold them.
//!
//! Writes are best-effort and must never gate the request. Rows TTL out after
//! 90 days (`crates/db/src/indexes.rs`), matching the other audit logs.

use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::models::KeyRotationAuditEvent;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct KeyRotationAuditDao {
    pub base: BaseDao<KeyRotationAuditEvent>,
}

impl KeyRotationAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, KeyRotationAuditEvent::COLLECTION),
        }
    }

    /// Record one decision. Exactly one of `dispatch` (`pushed` / `queued`)
    /// and `denied` (the refusal's wire string) is `Some`.
    pub async fn record(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        user_id: ObjectId,
        request_id: &str,
        dispatch: Option<&str>,
        denied: Option<&str>,
    ) -> DaoResult<ObjectId> {
        self.record_with_reason(
            tenant_id,
            agent_id,
            user_id,
            request_id,
            dispatch,
            denied,
            Some("manual"),
        )
        .await
    }

    /// Record one decision with an explicit trigger reason (`"manual"`,
    /// `"auto_ttl"`, `"admin_revoke"`).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_with_reason(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        user_id: ObjectId,
        request_id: &str,
        dispatch: Option<&str>,
        denied: Option<&str>,
        reason: Option<&str>,
    ) -> DaoResult<ObjectId> {
        let event = KeyRotationAuditEvent {
            id: None,
            tenant_id,
            agent_id,
            user_id,
            at: DateTime::now(),
            request_id: request_id.to_string(),
            dispatch: dispatch.map(|s| s.to_string()),
            denied: denied.map(|s| s.to_string()),
            reason: reason.map(|s| s.to_string()),
        };
        self.base.insert_one(&event).await
    }

    /// "Who has been rotating this device's key?", newest first.
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        pagination: &PaginationParams,
    ) -> DaoResult<PaginatedResult<KeyRotationAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1 }),
                pagination,
            )
            .await
    }
}
