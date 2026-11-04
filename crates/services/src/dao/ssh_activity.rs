// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Roomler-SSH session activity (`ssh_activity`, P8).
//!
//! What a device REPORTS doing inside a session: the commands it ran, the
//! shells and SFTP subsystems it opened, the forwards it allowed or refused.
//!
//! Deliberately a different collection from `ssh_audit`, and the distinction
//! is the whole point of the design:
//!
//! | | `ssh_audit` | `ssh_activity` |
//! |---|---|---|
//! | written by | the SERVER, from its own decision | the DEVICE, reporting |
//! | authority | authoritative | a claim by a host that may be compromised |
//! | answers | who was ALLOWED in | what they did once inside |
//!
//! Folding them together would leave a reader unable to tell which rows the
//! server stands behind. Correlate across the two on `grant_id`.
//!
//! ⚠️ **No rows is not proof of no activity.** Reporting is off by default
//! (`ssh_activity_log`), and a compromised host can simply stop talking. The
//! grant record in `ssh_audit` is what survives a lying device.
//!
//! Content is deliberately absent — no pty byte stream, no command output.
//! Recording those would ship whatever the operator typed, passwords included,
//! off the host; see `SshActivityEvent`. Writes are best-effort and must never
//! gate a session. Rows TTL out after 90 days (`crates/db/src/indexes.rs`).

use bson::{doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::SshActivityEvent;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct SshActivityDao {
    pub base: BaseDao<SshActivityEvent>,
}

impl SshActivityDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, SshActivityEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: SshActivityEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// Org-wide feed, newest first.
    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<SshActivityEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// "What has been run on this machine?"
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<SshActivityEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// Everything one session did — the join back from an `ssh_audit`
    /// decision row to what followed it.
    pub async fn list_for_grant(
        &self,
        tenant_id: ObjectId,
        grant_id: &str,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<SshActivityEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "grant_id": grant_id },
                Some(doc! { "at": 1 }),
                params,
            )
            .await
    }
}
