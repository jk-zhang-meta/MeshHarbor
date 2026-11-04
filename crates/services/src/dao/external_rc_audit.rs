// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-52 cross-org remote access — the decision log (`external_rc_audit`).
//!
//! Every decision the server takes about letting someone OUTSIDE the org onto
//! a device lands here, granted or refused. The refused rows are the point, as
//! in `ssh_audit`: an admin probing which devices they can open to outsiders
//! should not be able to do it silently, and an operator asking "why can my
//! contractor not connect?" has exactly one place to look.
//!
//! ⚠️ A row is the SERVER's own decision, and it is authoritative. It is not a
//! record of the session: the server's involvement ends when it says yes, and
//! the session then rides a path the server never observes. Same discipline as
//! `ssh_audit` — and the same reason there is no duration, no outcome and no
//! content here, and never will be.
//!
//! Writes are best-effort and must never gate a request; the caller logs a
//! failed insert loudly and proceeds. Rows TTL out after 90 days
//! (`crates/db/src/indexes.rs`), matching `ssh_audit` / `exec_audit`.

use bson::{doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::ExternalRcAuditEvent;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct ExternalRcAuditDao {
    pub base: BaseDao<ExternalRcAuditEvent>,
}

impl ExternalRcAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, ExternalRcAuditEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: ExternalRcAuditEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// Org-wide "who has been opening my fleet to outsiders?", newest first.
    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<ExternalRcAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// Per-device history, newest first — "when was this machine opened up,
    /// and by whom?"
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<ExternalRcAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }
}
