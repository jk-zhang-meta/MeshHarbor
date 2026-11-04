// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::RemoteAuditEvent;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct RemoteAuditDao {
    pub base: BaseDao<RemoteAuditEvent>,
}

impl RemoteAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, RemoteAuditEvent::COLLECTION),
        }
    }

    pub async fn list_for_session(
        &self,
        session_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<RemoteAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "session_id": session_id },
                Some(doc! { "at": 1 }),
                params,
            )
            .await
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<RemoteAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                params,
            )
            .await
    }
}
