// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_db::models::{Notification, NotificationSource, NotificationType};

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct NotificationDao {
    pub base: BaseDao<Notification>,
}

impl NotificationDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, Notification::COLLECTION),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        notification_type: NotificationType,
        title: String,
        body: String,
        link: Option<String>,
        source: NotificationSource,
    ) -> DaoResult<Notification> {
        let notification = Notification {
            id: None,
            tenant_id,
            user_id,
            notification_type,
            title,
            body,
            link,
            source,
            is_read: false,
            read_at: None,
            created_at: DateTime::now(),
        };
        let id = self.base.insert_one(&notification).await?;
        self.base.find_by_id(id).await
    }

    pub async fn find_for_user(
        &self,
        user_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<Notification>> {
        self.base
            .find_paginated(
                doc! { "user_id": user_id },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    pub async fn find_unread_for_user(
        &self,
        user_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<Notification>> {
        self.base
            .find_paginated(
                doc! { "user_id": user_id, "is_read": false },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    pub async fn unread_count(&self, user_id: ObjectId) -> DaoResult<u64> {
        self.base
            .collection()
            .count_documents(doc! { "user_id": user_id, "is_read": false })
            .await
            .map_err(Into::into)
    }

    pub async fn mark_read(&self, notification_id: ObjectId, user_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": notification_id, "user_id": user_id },
                doc! { "$set": { "is_read": true, "read_at": DateTime::now() } },
            )
            .await
    }

    pub async fn mark_all_read(&self, user_id: ObjectId) -> DaoResult<u64> {
        let result = self
            .base
            .collection()
            .update_many(
                doc! { "user_id": user_id, "is_read": false },
                doc! { "$set": { "is_read": true, "read_at": DateTime::now() } },
            )
            .await?;
        Ok(result.modified_count)
    }

    /// P4 — one aggregation feeding `/api/user/unread-summary`: the user's
    /// unread notifications grouped per tenant, with mention + consent
    /// sub-counts split out (the discriminants are the snake_case serde
    /// names of [`NotificationType`]).
    pub async fn unread_by_tenant(&self, user_id: ObjectId) -> DaoResult<Vec<TenantUnread>> {
        use futures::TryStreamExt;

        let pipeline = vec![
            doc! { "$match": { "user_id": user_id, "is_read": false } },
            doc! { "$group": {
                "_id": "$tenant_id",
                "total": { "$sum": 1 },
                "mentions": { "$sum": { "$cond": [ { "$eq": ["$notification_type", "mention"] }, 1, 0 ] } },
                "consents": { "$sum": { "$cond": [ { "$eq": ["$notification_type", "consent_request"] }, 1, 0 ] } },
            }},
        ];

        let mut cursor = self.base.collection().aggregate(pipeline).await?;
        let mut results = Vec::new();
        while let Some(d) = cursor.try_next().await? {
            if let Ok(tenant_id) = d.get_object_id("_id") {
                results.push(TenantUnread {
                    tenant_id,
                    total: d.get_i32("total").unwrap_or(0).max(0) as u64,
                    mentions: d.get_i32("mentions").unwrap_or(0).max(0) as u64,
                    consents: d.get_i32("consents").unwrap_or(0).max(0) as u64,
                });
            }
        }
        Ok(results)
    }
}

/// One tenant's unread-notification slice (see [`NotificationDao::unread_by_tenant`]).
#[derive(Debug, Clone)]
pub struct TenantUnread {
    pub tenant_id: ObjectId,
    pub total: u64,
    pub mentions: u64,
    pub consents: u64,
}
