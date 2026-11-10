// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-99 P1d — what devices report about privacy mode in remote sessions
//! (`privacy_activity`): the curtain up, down and why, a request refused.
//!
//! | | `remote_audit` (`SessionRequested`) | `privacy_activity` |
//! |---|---|---|
//! | written by | the SERVER, from its own decision | the DEVICE, reporting |
//! | authority | authoritative | a claim by a host that may be compromised |
//! | answers | was `PRIVACY` granted, and if not why | what the host then did with it |
//!
//! Correlate on `session_id`. ⚠️ No rows is not proof that no curtain went
//! up: a compromised host can stay silent, and the grant in `remote_audit` is
//! what survives it. Rows TTL out after 90 days (the `remote` module's index
//! plan).

use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::PrivacyActivityEvent;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct PrivacyActivityDao {
    pub base: BaseDao<PrivacyActivityEvent>,
}

impl PrivacyActivityDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, PrivacyActivityEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: PrivacyActivityEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// "When was this machine's screen covered, and by whose session?"
    /// Newest first. `_id` breaks a tie: reports in one millisecond are
    /// common (on, then off), and the hub records each as its frame arrives,
    /// so `_id` order is arrival order.
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<PrivacyActivityEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1, "_id": -1 }),
                params,
            )
            .await
    }
}
