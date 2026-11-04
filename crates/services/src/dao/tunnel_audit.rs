// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::TunnelAuditEvent;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct TunnelAuditDao {
    pub base: BaseDao<TunnelAuditEvent>,
}

impl TunnelAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, TunnelAuditEvent::COLLECTION),
        }
    }

    /// Append a single event. Append-only — never edit a row after
    /// insert (90 d TTL handles cleanup). Used by every interesting
    /// happening in `ws/tunnel.rs` and the agent's `tunnel::dialer`.
    pub async fn append(&self, event: &TunnelAuditEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(event).await
    }

    /// All events for one `tunnel forward` invocation, oldest-first.
    /// Backs the admin "session reconstruct" view.
    pub async fn list_for_session(
        &self,
        tunnel_session_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<TunnelAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tunnel_session_id": tunnel_session_id },
                Some(doc! { "at": 1 }),
                params,
            )
            .await
    }

    /// All events for a tenant, newest-first. Compound index
    /// `(tenant_id, at)` makes this efficient. Backs the admin search
    /// view's default "last 24h" tab.
    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<TunnelAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }

    /// "Who connected to db.intranet:5432 in the last 7 days?" —
    /// backed by the compound `(tenant_id, dst_host, at)` index in
    /// `crates/db/src/indexes.rs`. T4 admin UI search uses this.
    /// `dst_port` is optional so callers can answer "any port on
    /// this host" too.
    pub async fn search_by_destination(
        &self,
        tenant_id: ObjectId,
        dst_host: &str,
        dst_port: Option<u16>,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<TunnelAuditEvent>> {
        let mut filter = doc! { "tenant_id": tenant_id, "dst_host": dst_host };
        if let Some(p) = dst_port {
            filter.insert("dst_port", p as i32);
        }
        self.base
            .find_paginated(filter, Some(doc! { "at": -1 }), params)
            .await
    }
}
