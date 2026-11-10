// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::{self, recording::*};
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct RecordingDao {
    pub base: BaseDao<models::Recording>,
}

impl RecordingDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, models::Recording::COLLECTION),
        }
    }

    pub async fn create(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        recording_type: RecordingType,
        storage_file: StorageFile,
        started_at: DateTime,
        ended_at: DateTime,
    ) -> DaoResult<models::Recording> {
        let now = DateTime::now();
        let recording = models::Recording {
            id: None,
            tenant_id,
            room_id,
            recording_type,
            status: RecordingStatus::Processing,
            file: storage_file,
            started_at,
            ended_at,
            visibility: Visibility::Private,
            allow_download: true,
            expires_at: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let id = self.base.insert_one(&recording).await?;
        self.base.find_by_id(id).await
    }

    pub async fn find_by_room(
        &self,
        room_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<models::Recording>> {
        self.base
            .find_paginated(
                doc! { "room_id": room_id, "deleted_at": null },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    pub async fn update_status(&self, id: ObjectId, status: RecordingStatus) -> DaoResult<bool> {
        self.base
            .update_by_id(
                id,
                doc! { "$set": { "status": bson::to_bson(&status).unwrap_or_default() } },
            )
            .await
    }

    pub async fn soft_delete(&self, tenant_id: ObjectId, id: ObjectId) -> DaoResult<bool> {
        self.base.soft_delete_in_tenant(tenant_id, id).await
    }
}
