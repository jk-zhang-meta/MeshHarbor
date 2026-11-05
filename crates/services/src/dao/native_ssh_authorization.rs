// SPDX-License-Identifier: AGPL-3.0-only
//! Shared bounded slots and atomic transitions; expiry never relies on TTL cleanup.
use super::base::{BaseDao, DaoResult};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::{NativeSshAuthorization, NativeSshScope};
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

impl NativeSshAuthorizationDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, NativeSshAuthorization::COLLECTION),
        }
    }

    /// Fixed global IDs cap storage even under concurrent anonymous starts.
    /// A unique (client_hash, client_slot) index independently caps each client.
    /// Finished requests retain their slot until expiry, also bounding start rate.
    pub async fn reserve(&self, row: &NativeSshAuthorization) -> DaoResult<bool> {
        let coll = self.base.collection();
        let now = DateTime::now();
        let mut data = bson::to_document(row)?;
        data.remove("_id");
        for client_slot in 0..NativeSshAuthorization::CLIENT_SLOTS {
            data.insert("client_slot", i64::from(client_slot));
            if let Some(old) = coll
                .find_one(doc! {
                    "client_hash": &row.client_hash, "client_slot": i64::from(client_slot)
                })
                .await?
            {
                if old.expires_at <= now && coll.find_one_and_update(
                    doc! {"_id": old.id, "authorization_id": old.authorization_id, "expires_at": {"$lte": now}},
                    doc! {"$set": data.clone()},
                ).await?.is_some() {
                    return Ok(true);
                }
                continue;
            }
            for slot in 0..NativeSshAuthorization::GLOBAL_SLOTS {
                let id = ObjectId::from_bytes([
                    109, 104, 115, 115, 104, 97, 117, 116, 104, 0, 0, slot as u8,
                ]);
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

    pub async fn decide(
        &self,
        id: ObjectId,
        user_code: &str,
        scope: Option<&NativeSshScope>,
    ) -> DaoResult<bool> {
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                doc! {"authorization_id": id, "user_code_hash": hash_secret("user", user_code),
                "state": "pending", "expires_at": {"$gt": DateTime::now()}},
                doc! {"$set": {"state": if scope.is_some() {"approved"} else {"denied"},
                "scope": bson::to_bson(&scope)?}},
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
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                doc! {"authorization_id": row.authorization_id, "state": "approved",
                "expires_at": {"$gt": DateTime::now()}, "grant_hash": null},
                doc! {"$set": {"state": "exchanged", "grant_hash": hash_secret("grant", grant),
                "grant_expires_at": grant_expires_at}},
            )
            .await?
            .is_some())
    }
}
