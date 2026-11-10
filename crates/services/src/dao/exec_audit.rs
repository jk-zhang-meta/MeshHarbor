// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Fleet-RPC audit log (`exec_audit`).
//!
//! Every exec ATTEMPT lands here — allowed or denied. A refused command is the
//! interesting one: without a row, someone probing which devices will run
//! things for them leaves no trace at all.
//!
//! Writes are best-effort and must never gate the command itself; the caller
//! logs a failed insert and proceeds. Rows TTL out after 90 days
//! (`crates/db/src/indexes.rs`), matching `remote_audit` / `tunnel_audit`.

use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::ExecAuditEvent;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct ExecAuditDao {
    pub base: BaseDao<ExecAuditEvent>,
}

impl ExecAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, ExecAuditEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: ExecAuditEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// Org-wide "what ran on my fleet?", newest first.
    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<ExecAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// Per-device console history, newest first.
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<ExecAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// "What did this person run?" — where an incident review actually starts.
    pub async fn list_for_user(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<ExecAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "user_id": user_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }
}
