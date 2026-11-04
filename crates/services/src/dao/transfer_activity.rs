// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-101 P3 — clipboard and file traffic the devices report for remote
//! sessions (`transfer_activity`). A claim, kept beside `remote_audit`'s
//! decision; see [`TransferActivityEvent`].

use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::TransferActivityEvent;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct TransferActivityDao {
    pub base: BaseDao<TransferActivityEvent>,
}

impl TransferActivityDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, TransferActivityEvent::COLLECTION),
        }
    }

    /// Keep one sample's rows.
    pub async fn record_many(&self, events: &[TransferActivityEvent]) -> DaoResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        self.base.collection().insert_many(events).await?;
        Ok(())
    }

    /// "What crossed the clipboard and file channels of this machine?"
    /// Newest first, `_id` breaking a tie in one millisecond: a report's rows
    /// go in as one ordered insert, so `_id` order is arrival order.
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<TransferActivityEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1, "_id": -1 }),
                params,
            )
            .await
    }
}
