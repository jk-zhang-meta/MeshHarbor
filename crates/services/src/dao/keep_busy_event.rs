// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-92 P7 — the permanent keep-busy history (`keep_busy_events`).
//!
//! One collection, two sources, told apart by `source` and never merged in
//! the reader's mind: `server` rows are the server's own decisions (an
//! admin's change to the org's policy, written from the settings route);
//! `device` rows are CLAIMS a device made on its heartbeat, derived from two
//! consecutive briefs. The split is the one `ssh_audit` / `ssh_activity`
//! make with two collections.
//!
//! **No TTL, by decision** (operator, 2026-10-11: "permanent history"). The
//! index set lives with the fleet module (`crates/modules/fleet/src/lib.rs`
//! `indexes()`), never in the db crate's plan.
//!
//! Writes are best-effort for the heartbeat path: a failed insert is logged
//! by the caller and the heartbeat goes on. Every read is tenant-scoped —
//! an `agent_id` alone is never a key (CLAUDE.md, Security Baseline).

use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::KeepBusyEvent;

use super::base::{BaseDao, DaoResult};

pub struct KeepBusyEventDao {
    pub base: BaseDao<KeepBusyEvent>,
}

/// The most rows one listing hands back; the route clamps to it.
pub const MAX_LIMIT: i64 = 200;

impl KeepBusyEventDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, KeepBusyEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: KeepBusyEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// Newest first, within ONE tenant: optionally one device's, optionally
    /// only rows strictly older than `before` (the cursor for "load more"),
    /// at most `limit` (clamped to `1..=MAX_LIMIT`).
    pub async fn list(
        &self,
        tenant_id: ObjectId,
        agent_id: Option<ObjectId>,
        before: Option<DateTime>,
        limit: i64,
    ) -> DaoResult<Vec<KeepBusyEvent>> {
        let mut filter = doc! { "tenant_id": tenant_id };
        if let Some(agent_id) = agent_id {
            filter.insert("agent_id", agent_id);
        }
        if let Some(before) = before {
            filter.insert("at", doc! { "$lt": before });
        }
        let mut cursor = self
            .base
            .collection()
            .find(filter)
            // `_id` as the tie-breaker: two rows in one millisecond must
            // page stably.
            .sort(doc! { "at": -1, "_id": -1 })
            .limit(limit.clamp(1, MAX_LIMIT))
            .await?;
        let mut items = Vec::new();
        use futures::TryStreamExt;
        while let Some(doc) = cursor.try_next().await? {
            items.push(doc);
        }
        Ok(items)
    }

    /// The newest row about ONE device (device rows are the only ones that
    /// carry an `agent_id`), for the heartbeat path's restart dedupe.
    pub async fn latest_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> DaoResult<Option<KeepBusyEvent>> {
        Ok(self
            .base
            .collection()
            .find_one(doc! { "tenant_id": tenant_id, "agent_id": agent_id })
            .sort(doc! { "at": -1, "_id": -1 })
            .await?)
    }
}
