// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-94 — `exec_pending`: a Fleet RPC routed to a Windows device's SYSTEM
//! service, between the dispatch that writes it and the result the service
//! posts.
//!
//! Every transition is ONE conditional write, keyed by `request_id` AND the
//! device AND the tenant, so the database arbitrates:
//! - **claim** `pending → claimed`, only before `claim_by`. Single use: a
//!   second claim, a stale one, or another device's fails without running
//!   anything.
//! - **complete** `claimed → done`, only by the device that claimed it.
//! - **cancel** `pending → cancelled`. A command withdrawn before its claim
//!   can never be claimed afterwards.
//!
//! The index set lives with the fleet module (`indexes()`): `request_id`
//! unique, and a TTL on `expires_at`.

use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::models::{ExecOutcome, ExecPending};
use mongodb::Database;
use mongodb::options::ReturnDocument;

use super::base::{BaseDao, DaoResult};

pub struct ExecPendingDao {
    pub base: BaseDao<ExecPending>,
}

impl ExecPendingDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, ExecPending::COLLECTION),
        }
    }

    pub async fn insert(&self, row: &ExecPending) -> DaoResult<ObjectId> {
        self.base.insert_one(row).await
    }

    /// The single-use claim. `Some` = this device may run it now. `None` =
    /// nothing runs: unknown, claimed already, withdrawn, past `claim_by`, or
    /// pending for a DIFFERENT device. The caller cannot tell those apart,
    /// and should not: a forged id learns nothing.
    pub async fn claim(
        &self,
        request_id: &str,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> DaoResult<Option<ExecPending>> {
        let now = DateTime::now();
        let row = self
            .base
            .collection()
            .find_one_and_update(
                doc! {
                    "request_id": request_id,
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "state": ExecPending::PENDING,
                    "claim_by": { "$gt": now },
                },
                doc! { "$set": { "state": ExecPending::CLAIMED, "claimed_at": now } },
            )
            .return_document(ReturnDocument::After)
            .await?;
        Ok(row)
    }

    /// `claimed → done`, by the device that claimed it. `false` = no such
    /// claimed row for this device: a result for something it never claimed
    /// is dropped, never delivered.
    pub async fn complete(
        &self,
        request_id: &str,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        outcome: &ExecOutcome,
    ) -> DaoResult<bool> {
        let outcome = bson::to_bson(outcome)?;
        self.base
            .update_one(
                doc! {
                    "request_id": request_id,
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "state": ExecPending::CLAIMED,
                },
                doc! { "$set": { "state": ExecPending::DONE, "outcome": outcome } },
            )
            .await
    }

    /// The caller withdrew the command. Only a row nobody claimed yet: a
    /// claimed command is the device's to stop (`rc:rpc.cancel`).
    pub async fn cancel(&self, request_id: &str, tenant_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! {
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "state": ExecPending::PENDING,
                },
                doc! { "$set": { "state": ExecPending::CANCELLED } },
            )
            .await
    }

    /// The row as it stands, whatever its state. The caller reads it when
    /// the worker answers first, to tell "withdrawn in time" from "the
    /// service is already running it".
    pub async fn find(&self, request_id: &str) -> DaoResult<Option<ExecPending>> {
        self.base.find_one(doc! { "request_id": request_id }).await
    }

    /// The posted outcome, once the row is `done`. Polled by the caller,
    /// which waits on the pod holding the device's socket while the
    /// service's result can land on any pod.
    pub async fn outcome(&self, request_id: &str) -> DaoResult<Option<ExecOutcome>> {
        Ok(self
            .base
            .find_one(doc! { "request_id": request_id, "state": ExecPending::DONE })
            .await?
            .and_then(|row| row.outcome))
    }
}
