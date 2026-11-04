// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::{ConsentRequest, consent_request::ConsentRequestStatus};
use mongodb::Database;

use super::base::{BaseDao, DaoResult};

pub struct ConsentRequestDao {
    pub base: BaseDao<ConsentRequest>,
}

impl ConsentRequestDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, ConsentRequest::COLLECTION),
        }
    }

    /// Create a pending owner-consent request with a fresh capability token.
    /// `ttl_secs` bounds the link's validity (should match the session's async
    /// consent timeout). Returns the row so the caller can read the `token`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        session_id: ObjectId,
        agent_id: ObjectId,
        controller_user_id: ObjectId,
        controller_name: String,
        owner_user_id: ObjectId,
        ttl_secs: i64,
    ) -> DaoResult<ConsentRequest> {
        let now = DateTime::now();
        let token = nanoid::nanoid!(21);
        let expires_at = DateTime::from_millis(now.timestamp_millis() + ttl_secs * 1000);
        let req = ConsentRequest {
            id: None,
            tenant_id,
            session_id,
            agent_id,
            controller_user_id,
            controller_name,
            owner_user_id,
            token,
            status: ConsentRequestStatus::Pending,
            expires_at,
            created_at: now,
            updated_at: now,
        };
        let id = self.base.insert_one(&req).await?;
        self.base.find_by_id(id).await
    }

    pub async fn find_by_token(&self, token: &str) -> DaoResult<Option<ConsentRequest>> {
        self.base.find_one(doc! { "token": token }).await
    }

    /// Atomically flip `Pending` → `status`. Returns `true` only if THIS call
    /// performed the transition — the `status: "pending"` guard makes it a
    /// single-use resolve (defeats token replay / a double approve+deny race).
    pub async fn resolve(&self, id: ObjectId, status: ConsentRequestStatus) -> DaoResult<bool> {
        let status_bson = bson::to_bson(&status).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                doc! { "_id": id, "status": "pending" },
                doc! { "$set": { "status": status_bson, "updated_at": DateTime::now() } },
            )
            .await
    }
}
