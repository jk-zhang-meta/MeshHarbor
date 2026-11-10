// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Remote-config audit log (`config_audit`).
//!
//! Every desired-config write lands here — granted or refused. The refused
//! rows are the point: an admin probing which devices they can open exec on
//! should not be able to do so without leaving a trace.
//!
//! ⚠️ A row records what was **asked for**, never what the device did. The
//! device may be offline, may not have opted in via `remote_config_enabled`,
//! and is free to refuse — so these rows cannot answer "does this device have
//! exec on?". Only the device's own heartbeat can. Same discipline as
//! `ssh_audit`, which records the decision and not the session.
//!
//! Writes are best-effort and must never gate the request; the caller logs a
//! failed insert and proceeds. Rows TTL out after 90 days
//! (`crates/db/src/indexes.rs`), matching `exec_audit` / `ssh_audit`.

use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::models::{ConfigAuditEvent, DesiredConfig};
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct ConfigAuditDao {
    pub base: BaseDao<ConfigAuditEvent>,
}

impl ConfigAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, ConfigAuditEvent::COLLECTION),
        }
    }

    /// Record one decision. `denied` carries the refusal's wire string, or
    /// `None` when the write was allowed — both arms come through here so a
    /// new refusal cannot forget to audit itself.
    pub async fn record(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        user_id: ObjectId,
        requested: &DesiredConfig,
        denied: Option<&str>,
    ) -> DaoResult<ObjectId> {
        let event = ConfigAuditEvent {
            id: None,
            tenant_id,
            agent_id,
            user_id,
            at: DateTime::now(),
            requested: requested.clone(),
            denied: denied.map(|s| s.to_string()),
        };
        self.base.insert_one(&event).await
    }

    /// Org-wide, newest first.
    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        pagination: &PaginationParams,
    ) -> DaoResult<PaginatedResult<ConfigAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                pagination,
            )
            .await
    }

    /// "Who has been changing this device's config?", newest first.
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        pagination: &PaginationParams,
    ) -> DaoResult<PaginatedResult<ConfigAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1 }),
                pagination,
            )
            .await
    }
}
