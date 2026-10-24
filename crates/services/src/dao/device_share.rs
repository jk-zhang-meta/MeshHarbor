// SPDX-License-Identifier: AGPL-3.0-only
//! The grant ledger; expiry is enforced in queries, not eventual TTL cleanup.
use super::base::{BaseDao, DaoResult};
use bson::{DateTime, Document, doc, oid::ObjectId};
use mongodb::{Database, options::ReturnDocument};
use roomler_ai_db::models::DeviceShareGrant;

pub struct DeviceShareDao {
    pub base: BaseDao<DeviceShareGrant>,
}
impl DeviceShareDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, DeviceShareGrant::COLLECTION),
        }
    }
    pub fn live_filter(recipient: ObjectId, device: ObjectId, now: DateTime) -> Document {
        doc! {"recipient_user_id":recipient,"device_id":device,"revoked_at":null,"created_at":{"$lte":now},"expires_at":{"$gt":now}}
    }
    /// One grant must itself allow the requested operation; no implicit service union.
    pub async fn active_for(
        &self,
        recipient: ObjectId,
        device: ObjectId,
        now: DateTime,
    ) -> DaoResult<Vec<DeviceShareGrant>> {
        let mut cursor = self
            .base
            .collection()
            .find(Self::live_filter(recipient, device, now))
            .sort(doc! {"created_at":-1,"_id":-1})
            .limit(128)
            .await?;
        use futures::TryStreamExt;
        let mut grants = Vec::new();
        while let Some(grant) = cursor.try_next().await? {
            grants.push(grant)
        }
        Ok(grants)
    }
    pub async fn revoke(
        &self,
        id: ObjectId,
        owner: ObjectId,
        expected_revision: u32,
        now: DateTime,
    ) -> DaoResult<Option<DeviceShareGrant>> {
        let row=self.base.collection().find_one_and_update(
            doc!{"_id":id,"owner_user_id":owner,"revoked_at":null,"revision":i64::from(expected_revision)},
            doc!{"$set":{"revoked_at":now},"$inc":{"revision":1}},
        ).return_document(ReturnDocument::After).await?;
        Ok(row)
    }
}
