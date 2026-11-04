// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::ActivationCode;
use mongodb::Database;

use super::base::{BaseDao, DaoResult};

pub struct ActivationCodeDao {
    pub base: BaseDao<ActivationCode>,
}

impl ActivationCodeDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, ActivationCode::COLLECTION),
        }
    }

    pub async fn create(
        &self,
        user_id: ObjectId,
        token: String,
        ttl_minutes: u64,
    ) -> DaoResult<ActivationCode> {
        // Delete any existing codes for this user
        self.base.hard_delete(doc! { "user_id": user_id }).await?;

        let now = DateTime::now();
        let valid_to_ms = now.timestamp_millis() + (ttl_minutes as i64 * 60 * 1000);
        let valid_to = DateTime::from_millis(valid_to_ms);

        let code = ActivationCode {
            id: None,
            user_id,
            token,
            valid_to,
            created_at: now,
        };

        let id = self.base.insert_one(&code).await?;
        self.base.find_by_id(id).await
    }

    pub async fn find_valid(
        &self,
        user_id: ObjectId,
        token: &str,
    ) -> DaoResult<Option<ActivationCode>> {
        self.base
            .find_one(doc! {
                "user_id": user_id,
                "token": token,
                "valid_to": { "$gt": DateTime::now() },
            })
            .await
    }

    pub async fn delete_for_user(&self, user_id: ObjectId) -> DaoResult<u64> {
        self.base.hard_delete(doc! { "user_id": user_id }).await
    }
}
