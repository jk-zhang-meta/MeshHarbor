// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor-SSH audit log (`ssh_audit`).
//!
//! Every session REQUEST lands here — granted or refused. The refused rows are
//! the point: without them, someone probing which devices will let them in
//! leaves no trace at all.
//!
//! What this log can and cannot answer is set by the architecture, not by
//! effort. The server hands back an address and a grant and then steps out of
//! the way — the session rides the overlay directly and the server never sees
//! it. So these rows record the DECISION (who asked, for which device, as
//! which account, allowed or refused) and never the session's content,
//! duration or outcome. See [`SshAuditEvent`].
//!
//! Writes are best-effort and must never gate the request; the caller logs a
//! failed insert and proceeds. Rows TTL out after 90 days
//! (`crates/db/src/indexes.rs`), matching `exec_audit` / `remote_audit`.

use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::SshAuditEvent;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct SshAuditDao {
    pub base: BaseDao<SshAuditEvent>,
}

impl SshAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, SshAuditEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: SshAuditEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// Org-wide "who has been opening sessions on my fleet?", newest first.
    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<SshAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// Per-device history, newest first — "who has been on this machine?"
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<SshAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// "Where did this person get a shell?" — where an incident review starts.
    pub async fn list_for_user(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<SshAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "user_id": user_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }
}
