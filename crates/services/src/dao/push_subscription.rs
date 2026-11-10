// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::PushSubscription;
use mongodb::Database;

use super::base::{BaseDao, DaoResult};

pub struct PushSubscriptionDao {
    pub base: BaseDao<PushSubscription>,
}

impl PushSubscriptionDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, PushSubscription::COLLECTION),
        }
    }

    pub async fn subscribe(
        &self,
        user_id: ObjectId,
        endpoint: String,
        auth: String,
        p256dh: String,
    ) -> DaoResult<PushSubscription> {
        // Upsert by endpoint to avoid duplicates
        if let Ok(Some(sub)) = self
            .base
            .find_one(doc! { "user_id": user_id, "endpoint": &endpoint })
            .await
        {
            return Ok(sub);
        }

        let sub = PushSubscription {
            id: None,
            user_id,
            endpoint,
            keys: meshharbor_db::models::PushKeys { auth, p256dh },
            created_at: DateTime::now(),
        };

        let id = self.base.insert_one(&sub).await?;
        self.base.find_by_id(id).await
    }

    pub async fn unsubscribe(&self, user_id: ObjectId, endpoint: &str) -> DaoResult<bool> {
        let count = self
            .base
            .hard_delete(doc! { "user_id": user_id, "endpoint": endpoint })
            .await?;
        Ok(count > 0)
    }

    pub async fn find_by_user(&self, user_id: ObjectId) -> DaoResult<Vec<PushSubscription>> {
        self.base.find_many(doc! { "user_id": user_id }, None).await
    }

    pub async fn find_by_users(&self, user_ids: &[ObjectId]) -> DaoResult<Vec<PushSubscription>> {
        self.base
            .find_many(doc! { "user_id": { "$in": user_ids } }, None)
            .await
    }
}
