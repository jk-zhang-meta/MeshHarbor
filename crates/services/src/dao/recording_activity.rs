// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P3 — remote screen-recording activity (`recording_activity`).
//!
//! What a device REPORTS about a recording made from a remote-control
//! session: the host's answer to the just-in-time prompt, the start, the stop
//! (size, length, why), a download. The same split `ssh_activity` makes
//! against `ssh_audit`:
//!
//! | | `remote_audit` (`SessionRequested`) | `recording_activity` |
//! |---|---|---|
//! | written by | the SERVER, from its own decision | the DEVICE, reporting |
//! | authority | authoritative | a claim by a host that may be compromised |
//! | answers | was `RECORD` granted, and if not why | what the host then did |
//!
//! Correlate on `session_id`. ⚠️ No rows is not proof that nothing was
//! recorded — a compromised host can stay silent; the grant in `remote_audit`
//! is what survives it. Never content: the recording itself stays on the
//! device. Rows TTL out after 90 days (the `remote` module's index plan).

use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::RecordingActivityEvent;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct RecordingActivityDao {
    pub base: BaseDao<RecordingActivityEvent>,
}

impl RecordingActivityDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, RecordingActivityEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: RecordingActivityEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// "What was recorded on this machine?" Newest first, `_id` breaking a
    /// tie in one millisecond (the hub records each claim as it arrives, so
    /// `_id` order is arrival order).
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<RecordingActivityEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1, "_id": -1 }),
                params,
            )
            .await
    }
}
