// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! DAO for the `agent_logs` MongoDB collection — rc.58.
//!
//! Backs the centralized log-collection feature. Uploaders (agent
//! worker, browser, install wizard) POST a batch to the API; the
//! route handler authenticates, validates, then calls
//! [`AgentLogDao::record_batch`]. Admin UI reads via
//! [`AgentLogDao::list_recent`] which respects the tenant boundary.
//!
//! TTL: the collection has a 7-day TTL index on `created_at` set in
//! `crates/db/src/indexes.rs`. The DAO doesn't manage retention.

use bson::{Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_db::models::{AgentLogBatch, LogSource};
use mongodb::Database;

use super::base::{BaseDao, DaoError, DaoResult};

pub struct AgentLogDao {
    pub base: BaseDao<AgentLogBatch>,
}

impl AgentLogDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, AgentLogBatch::COLLECTION),
        }
    }

    /// Persist one batch. `created_at` is server-stamped by the
    /// caller. Returns the inserted record's ObjectId.
    pub async fn record_batch(&self, batch: AgentLogBatch) -> DaoResult<ObjectId> {
        self.base.insert_one(&batch).await
    }

    /// List the most-recent batches for an agent in a tenant. Sorted by
    /// `created_at` desc. Tenant-scoping is mandatory — the query
    /// filters BOTH `tenant_id` AND `agent_id` so a cross-tenant call
    /// returns an empty Vec rather than another tenant's data.
    pub async fn list_recent_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        limit: i64,
    ) -> DaoResult<Vec<AgentLogBatch>> {
        let filter = doc! { "tenant_id": tenant_id, "agent_id": agent_id };
        self.fetch(filter, limit).await
    }

    /// Variant for `source = "browser"` batches (no agent_id; scoped
    /// by user_id within the tenant). Used by the future admin UI's
    /// "user's recent viewer activity" panel.
    pub async fn list_recent_for_user(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        limit: i64,
    ) -> DaoResult<Vec<AgentLogBatch>> {
        let filter = doc! { "tenant_id": tenant_id, "user_id": user_id };
        self.fetch(filter, limit).await
    }

    /// Drill-down: batches matching a specific `session_id` across
    /// sources. Useful when investigating a single remote-control
    /// session — pulls both agent and browser batches that carried
    /// the same session hex.
    pub async fn list_for_session(
        &self,
        tenant_id: ObjectId,
        session_id: &str,
        limit: i64,
    ) -> DaoResult<Vec<AgentLogBatch>> {
        let filter = doc! { "tenant_id": tenant_id, "session_id": session_id };
        self.fetch(filter, limit).await
    }

    /// Source-filtered listing — admin UI uses this when the operator
    /// picks "show only `installer` logs". Tenant-scoped.
    pub async fn list_by_source(
        &self,
        tenant_id: ObjectId,
        source: LogSource,
        limit: i64,
    ) -> DaoResult<Vec<AgentLogBatch>> {
        let filter = doc! {
            "tenant_id": tenant_id,
            "source": source.as_str(),
        };
        self.fetch(filter, limit).await
    }

    /// Shared cursor walk — sort by `created_at` desc, limit N.
    async fn fetch(&self, filter: Document, limit: i64) -> DaoResult<Vec<AgentLogBatch>> {
        let mut cursor = self
            .base
            .collection()
            .find(filter)
            .sort(doc! { "created_at": -1 })
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
