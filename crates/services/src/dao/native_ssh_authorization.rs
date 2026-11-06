// SPDX-License-Identifier: AGPL-3.0-only
//! Shared bounded slots and atomic transitions; expiry never relies on TTL cleanup.
use super::base::{BaseDao, DaoResult};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bson::{DateTime, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_db::models::{NativeSshAuditEvent, NativeSshAuthorization, NativeSshScope};
use mongodb::{Database, options::ReturnDocument};
use sha2::{Digest, Sha256};

pub fn hash_secret(purpose: &str, value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(purpose.as_bytes());
    hash.update([0]);
    hash.update(value.as_bytes());
    hex::encode(hash.finalize())
}

pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn random_code() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

pub enum Poll {
    Found(NativeSshAuthorization),
    Limited,
    Invalid,
}

pub struct NativeSshAuthorizationDao {
    pub base: BaseDao<NativeSshAuthorization>,
}

fn duplicate_key(error: &mongodb::error::Error) -> bool {
    match error.kind.as_ref() {
        mongodb::error::ErrorKind::Command(e) => e.code == 11000,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(e)) => {
            e.code == 11000
        }
        _ => false,
    }
}

fn request_filter(row: &NativeSshAuthorization, state: &str) -> bson::Document {
    doc! {
        "authorization_id": row.authorization_id, "state": state,
        "expires_at": {"$eq": row.expires_at, "$gt": DateTime::now()},
        "share_grant_id": row.share_grant_id, "public_key": &row.public_key,
        "code_challenge": &row.code_challenge, "session_secs": row.session_secs as i64,
        "user_code_hash": &row.user_code_hash, "device_code_hash": &row.device_code_hash,
    }
}

impl NativeSshAuthorizationDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, NativeSshAuthorization::COLLECTION),
        }
    }

    /// Fixed global IDs cap storage even under concurrent anonymous starts.
    /// Unique client/share slot indexes enforce both quotas in the same write.
    /// Finished requests retain their slot until expiry, also bounding start rate.
    pub async fn reserve(&self, row: &NativeSshAuthorization) -> DaoResult<bool> {
        let coll = self.base.collection();
        let mut data = bson::to_document(row)?;
        data.remove("_id");
        // ObjectId parsing has already canonicalized aliases such as hex case.
        let share_hash = hash_secret("share", &row.share_grant_id.to_hex());
        data.insert("share_hash", share_hash.as_str());
        // Snapshots only choose candidates. Uniqueness and the expiry CAS, not
        // these reads, arbitrate concurrent claims across all server processes.
        for _ in 0..NativeSshAuthorization::GLOBAL_SLOTS {
            let now = DateTime::now();
            // Reclaim explicit expiry even if Mongo's TTL monitor has not run.
            coll.delete_many(doc! {"expires_at": {"$lte": now}}).await?;
            let rows: Vec<NativeSshAuthorization> = coll
                .find(doc! {})
                .limit(i64::from(NativeSshAuthorization::GLOBAL_SLOTS) + 1)
                .await?
                .try_collect()
                .await?;
            // The partial share index deliberately tolerates legacy rows. It
            // does NOT meter them: until every live legacy row expires, deny
            // all new starts identically, without rewriting old authorizations.
            // Old-version writers must be stopped before enabling this code.
            if rows.len() >= NativeSshAuthorization::GLOBAL_SLOTS as usize
                || rows
                    .iter()
                    .any(|old| old.share_hash.is_none() || old.share_slot.is_none())
            {
                return Ok(false);
            }
            let Some(client_slot) = (0..NativeSshAuthorization::CLIENT_SLOTS).find(|slot| {
                !rows
                    .iter()
                    .any(|old| old.client_hash == row.client_hash && old.client_slot == *slot)
            }) else {
                return Ok(false);
            };
            let Some(share_slot) = (0..NativeSshAuthorization::SHARE_SLOTS).find(|slot| {
                !rows.iter().any(|old| {
                    old.share_hash.as_deref() == Some(share_hash.as_str())
                        && old.share_slot == Some(*slot)
                })
            }) else {
                return Ok(false);
            };
            let Some(id) = (0..NativeSshAuthorization::GLOBAL_SLOTS)
                .map(|slot| {
                    ObjectId::from_bytes([
                        109, 104, 115, 115, 104, 97, 117, 116, 104, 0, 0, slot as u8,
                    ])
                })
                .find(|id| !rows.iter().any(|old| old.id == Some(*id)))
            else {
                return Ok(false);
            };
            data.insert("client_slot", i64::from(client_slot));
            data.insert("share_slot", i64::from(share_slot));
            let claimed = coll
                .find_one_and_update(
                    doc! {"_id": id, "expires_at": {"$lte": now}},
                    doc! {"$set": data.clone()},
                )
                .upsert(true)
                .await;
            match claimed {
                // ReturnDocument defaults to Before: an upsert legitimately returns None.
                Ok(_) => return Ok(true),
                Err(e) if duplicate_key(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }

    pub async fn pending(
        &self,
        id: ObjectId,
        user_code: &str,
    ) -> DaoResult<Option<NativeSshAuthorization>> {
        Ok(self
            .base
            .collection()
            .find_one(doc! {
                "authorization_id": id, "user_code_hash": hash_secret("user", user_code),
                "state": "pending", "expires_at": {"$gt": DateTime::now()},
            })
            .await?)
    }

    pub async fn preview(
        &self,
        row: &NativeSshAuthorization,
        user_code: &str,
        scope: &NativeSshScope,
        revision: &str,
    ) -> DaoResult<bool> {
        let Some(binding) = scope.binding.as_ref() else {
            return Ok(false);
        };
        if binding.request_expires_at <= DateTime::now() {
            return Ok(false);
        }
        let mut filter = request_filter(row, "pending");
        filter.insert("user_code_hash", hash_secret("user", user_code));
        filter.insert(
            "preview_revision_hash",
            bson::to_bson(&row.preview_revision_hash)?,
        );
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                filter,
                doc! {"$set": {"preview_scope": bson::to_bson(scope)?,
                "preview_revision_hash": hash_secret("preview", revision)}},
            )
            .await?
            .is_some())
    }

    pub async fn decide(
        &self,
        row: &NativeSshAuthorization,
        user_code: &str,
        revision: &str,
        approve: bool,
    ) -> DaoResult<bool> {
        let Some(scope) = row.preview_scope.as_ref() else {
            return Ok(false);
        };
        let Some(binding) = scope.binding.as_ref() else {
            return Ok(false);
        };
        let mut filter = request_filter(row, "pending");
        filter.insert("user_code_hash", hash_secret("user", user_code));
        filter.insert("preview_revision_hash", hash_secret("preview", revision));
        filter.insert("preview_scope", bson::to_bson(scope)?);
        filter.insert(
            "preview_scope.binding.request_expires_at",
            doc! {"$gt": DateTime::now()},
        );
        if binding.request_expires_at <= DateTime::now() {
            return Ok(false);
        }
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                filter,
                doc! {"$set": {"state": if approve {"approved"} else {"denied"},
                "scope": bson::to_bson(&approve.then_some(scope))?},
                "$unset": {"preview_scope": "", "preview_revision_hash": ""}},
            )
            .await?
            .is_some())
    }

    pub async fn poll(&self, device_code: &str, verifier: &str) -> DaoResult<Poll> {
        let filter = doc! {"device_code_hash": hash_secret("device", device_code),
        "code_challenge": code_challenge(verifier), "expires_at": {"$gt": DateTime::now()}};
        let Some(row) = self.base.collection().find_one(filter.clone()).await? else {
            return Ok(Poll::Invalid);
        };
        if row.polls >= NativeSshAuthorization::MAX_POLLS {
            return Ok(Poll::Limited);
        }
        let mut filter = filter;
        filter.insert("authorization_id", row.authorization_id);
        filter.insert(
            "polls",
            doc! {"$lt": i64::from(NativeSshAuthorization::MAX_POLLS)},
        );
        Ok(
            match self
                .base
                .collection()
                .find_one_and_update(filter, doc! {"$inc": {"polls": 1}})
                .return_document(ReturnDocument::After)
                .await?
            {
                Some(row) => Poll::Found(row),
                None => Poll::Limited,
            },
        )
    }

    pub async fn exchange(
        &self,
        row: &NativeSshAuthorization,
        grant: &str,
        grant_expires_at: DateTime,
    ) -> DaoResult<bool> {
        let Some(binding) = row.scope.as_ref().and_then(|scope| scope.binding.as_ref()) else {
            return Ok(false);
        };
        if binding.request_expires_at <= DateTime::now() {
            return Ok(false);
        }
        let mut filter = request_filter(row, "approved");
        filter.insert("grant_hash", bson::Bson::Null);
        filter.insert("scope", bson::to_bson(&row.scope)?);
        filter.insert(
            "scope.binding.request_expires_at",
            doc! {"$gt": DateTime::now()},
        );
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                filter,
                doc! {"$set": {"state": "exchanged", "grant_hash": hash_secret("grant", grant),
                "grant_expires_at": grant_expires_at}},
            )
            .await?
            .is_some())
    }

    pub async fn exchanged(&self, grant: &str) -> DaoResult<Option<NativeSshAuthorization>> {
        let now = DateTime::now();
        Ok(self
            .base
            .collection()
            .find_one(doc! {
                "grant_hash": hash_secret("grant", grant),
                "state": "exchanged",
                "expires_at": {"$gt": now},
                "grant_expires_at": {"$gt": now},
            })
            .await?)
    }

    pub async fn by_grant_hash(&self, grant: &str) -> DaoResult<Option<NativeSshAuthorization>> {
        Ok(self
            .base
            .collection()
            .find_one(doc! {
                "grant_hash": hash_secret("grant", grant),
            })
            .await?)
    }

    pub async fn consume(&self, row: &NativeSshAuthorization, grant: &str) -> DaoResult<bool> {
        let Some(binding) = row.scope.as_ref().and_then(|scope| scope.binding.as_ref()) else {
            return Ok(false);
        };
        let Some(grant_expires_at) = row.grant_expires_at else {
            return Ok(false);
        };
        let now = DateTime::now();
        if binding.request_expires_at <= now
            || binding.share_expires_at <= now
            || grant_expires_at <= now
        {
            return Ok(false);
        }
        let grant_hash = hash_secret("grant", grant);
        if row.grant_hash.as_deref() != Some(grant_hash.as_str()) {
            return Ok(false);
        }
        let mut filter = request_filter(row, "exchanged");
        filter.insert("grant_hash", grant_hash);
        filter.insert(
            "grant_expires_at",
            doc! {"$eq": grant_expires_at, "$gt": now},
        );
        filter.insert("scope", bson::to_bson(&row.scope)?);
        filter.insert("scope.binding.request_expires_at", doc! {"$gt": now});
        filter.insert("scope.binding.share_expires_at", doc! {"$gt": now});
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                filter,
                doc! {"$set": {"state": "used", "used_at": now, "updated_at": now}},
            )
            .await?
            .is_some())
    }
}

pub struct NativeSshAuditDao {
    pub base: BaseDao<NativeSshAuditEvent>,
}

impl NativeSshAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, NativeSshAuditEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: NativeSshAuditEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }
}
