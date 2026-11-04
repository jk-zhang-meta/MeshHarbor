// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-105 — `ssh_pending`: an SSH grant routed to a Windows device's SYSTEM
//! service, between the decision that writes it and the service's claim.
//!
//! Every transition is ONE conditional write, keyed by `grant_id` AND the
//! device AND the tenant, so the database arbitrates:
//! - **claim** `pending → claimed`, only before `claim_by`. Single use: a
//!   second claim, a stale one, or another device's fails, and no grant
//!   material leaves the server.
//! - **cancel** `pending → cancelled`. A grant the caller stopped waiting for
//!   can never be claimed afterwards.
//!
//! The index set lives with the network module (`indexes_for`): `grant_id`
//! unique, and a TTL on `expires_at`.

use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::models::SshPending;
use mongodb::Database;
use mongodb::options::ReturnDocument;

use super::base::{BaseDao, DaoResult};

pub struct SshPendingDao {
    pub base: BaseDao<SshPending>,
}

impl SshPendingDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, SshPending::COLLECTION),
        }
    }

    pub async fn insert(&self, row: &SshPending) -> DaoResult<ObjectId> {
        self.base.insert_one(row).await
    }

    /// The single-use claim. `Some` = this device's service may record the
    /// grant now. `None` = nothing is handed out: unknown, claimed already,
    /// withdrawn, past `claim_by`, or pending for a DIFFERENT device. The
    /// caller cannot tell those apart, and should not: a forged id learns
    /// nothing.
    ///
    /// FR-90 P3-8-2a — nor an agent session's grant (`one_command`) to a
    /// claimer that does not hold one command (`holds_one_command`). A row
    /// written before the field has none, and `$ne` matches it.
    pub async fn claim(
        &self,
        grant_id: &str,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        holds_one_command: bool,
    ) -> DaoResult<Option<SshPending>> {
        let now = DateTime::now();
        let mut filter = doc! {
            "grant_id": grant_id,
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "state": SshPending::PENDING,
            "claim_by": { "$gt": now },
        };
        if !holds_one_command {
            filter.insert("one_command", doc! { "$ne": true });
        }
        let row = self
            .base
            .collection()
            .find_one_and_update(
                filter,
                doc! { "$set": { "state": SshPending::CLAIMED, "claimed_at": now } },
            )
            .return_document(ReturnDocument::After)
            .await?;
        Ok(row)
    }

    /// The caller stopped waiting (a refusal, the bound). Only a row nobody
    /// claimed yet: `false` = it was claimed first, or is gone.
    pub async fn cancel(&self, grant_id: &str, tenant_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! {
                    "grant_id": grant_id,
                    "tenant_id": tenant_id,
                    "state": SshPending::PENDING,
                },
                doc! { "$set": { "state": SshPending::CANCELLED } },
            )
            .await
    }

    /// Has the device's service claimed it? Polled by the waiting caller,
    /// which sits on the pod holding the device's socket while the claim can
    /// land on any pod.
    pub async fn is_claimed(&self, grant_id: &str) -> DaoResult<bool> {
        Ok(self
            .base
            .find_one(doc! { "grant_id": grant_id, "state": SshPending::CLAIMED })
            .await?
            .is_some())
    }
}
