// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! DAO for the `agent_crashes` MongoDB collection.
//!
//! Backs the Task 9 crash-log feature. The agent's `crash_uploader`
//! POSTs an [`AgentCrashPayload`] to `/api/agent/crash`; the route
//! handler resolves `tenant_id` + `agent_id` from the agent JWT,
//! stamps `reported_at` from the server clock, and calls
//! [`AgentCrashDao::record`].
//!
//! Admin UI reads via [`AgentCrashDao::list_for_agent_in_tenant`]
//! which respects the tenant boundary so a cross-tenant query
//! returns an empty list rather than another tenant's data.
//!
//! TTL: the `agent_crashes` collection has a TTL index on
//! `reported_at` set to 90 days in `crates/db/src/indexes.rs`. The
//! DAO doesn't manage retention — Mongo does.

use bson::{DateTime, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_remote_control::models::{AgentCrashPayload, AgentCrashRecord};
use mongodb::Database;

use super::base::{BaseDao, DaoError, DaoResult};

pub struct AgentCrashDao {
    pub base: BaseDao<AgentCrashRecord>,
}

impl AgentCrashDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, AgentCrashRecord::COLLECTION),
        }
    }

    /// Persist a crash record. `tenant_id` + `agent_id` are resolved
    /// from the agent JWT by the route handler; `reported_at` is the
    /// server clock at ingest time. Returns the inserted record's
    /// ObjectId.
    pub async fn record(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        payload: AgentCrashPayload,
    ) -> DaoResult<ObjectId> {
        let record = AgentCrashRecord {
            id: None,
            tenant_id,
            agent_id,
            reported_at: DateTime::now(),
            payload,
        };
        self.base.insert_one(&record).await
    }

    /// List the most-recent N crash records for `agent_id` scoped to
    /// `tenant_id`. Sorted by `crashed_at_unix` desc so the latest
    /// crash is row 0 in the admin UI. Tenant-scoping is mandatory:
    /// the query filters on BOTH `tenant_id` AND `agent_id` so a
    /// cross-tenant call returns an empty Vec rather than another
    /// tenant's data (defence-in-depth against route-level mistakes).
    pub async fn list_for_agent_in_tenant(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        limit: i64,
    ) -> DaoResult<Vec<AgentCrashRecord>> {
        let filter = doc! { "tenant_id": tenant_id, "agent_id": agent_id };
        let mut cursor = self
            .base
            .collection()
            .find(filter)
            .sort(doc! { "crashedAtUnix": -1 })
            .limit(limit)
            .await
            .map_err(DaoError::Mongo)?;

        let mut out = Vec::new();
        while let Some(rec) = cursor.try_next().await.map_err(DaoError::Mongo)? {
            out.push(rec);
        }
        Ok(out)
    }
}
