// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{Document, doc, oid::ObjectId};
use mongodb::{Collection, Database};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum DaoError {
    #[error("MongoDB error: {0}")]
    Mongo(#[from] mongodb::error::Error),
    #[error("BSON serialization error: {0}")]
    BsonSer(#[from] bson::ser::Error),
    #[error("BSON deserialization error: {0}")]
    BsonDe(#[from] bson::de::Error),
    #[error("Entity not found")]
    NotFound,
    #[error("Duplicate key: {0}")]
    DuplicateKey(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    /// FR-82 — "not in this tenant", distinct from a permission refusal all
    /// the way to the wire (`ApiError::NotAMember` ⇒ `error: "not_a_member"`).
    /// A variant rather than a magic string, because the client's behaviour
    /// forks on it and a `Forbidden("Not a member of this room")` must not be
    /// swept into the same branch by a substring match.
    #[error("Forbidden: Not a member")]
    NotAMember,
    #[error("Validation: {0}")]
    Validation(String),
}

pub type DaoResult<T> = Result<T, DaoError>;

/// Which index a `DuplicateKey` actually collided on.
///
/// MongoDB's E11000 text names it — `…collection: db.users index: email_1 dup
/// key: {…}` — and [`BaseDao::insert_one`] preserves that message verbatim.
/// The information is therefore always present; what goes wrong is callers
/// discarding it and then *asserting* a cause.
///
/// That is not hypothetical. `find_or_create_by_oauth` retried five times on
/// the assumption that every duplicate was a username clash, and reported
/// "Failed to generate unique username after retries" for a collision that was
/// really on `email` — which is why a genuine account-takeover defect read as
/// fixture noise for two sessions (#613). **A retry loop must confirm it is
/// retrying the thing it can actually change.**
///
/// Returns `None` when the message carries no index name (older servers and
/// some mongos paths phrase it differently); callers must treat `None` as
/// "unknown", never as "not this index".
pub fn duplicate_key_index(message: &str) -> Option<&str> {
    let rest = message.split_once(" index: ")?.1;
    let name = match rest.split_once(" dup key") {
        Some((name, _)) => name,
        None => rest.split_whitespace().next()?,
    }
    .trim();
    (!name.is_empty()).then_some(name)
}

/// Whether a `DuplicateKey` collided on `field`.
///
/// Reads the **dup key document** (`dup key: { email: "…" }`), not the index
/// name. The name is ambiguous: Mongo builds it by joining `<key>_<direction>`
/// pairs with `_`, and our own field names contain underscores, so
/// `tenant_id_1_machine_id_1` cannot be split back into fields without
/// guessing — and `email_verified_1` would match a naive search for "email".
/// The dup-key document names the fields outright.
///
/// Conservative by construction: an unparseable message returns `false`, so a
/// caller asking "is this MY field?" never gets a false yes and never retries
/// a collision it cannot resolve.
pub fn duplicate_key_is_on(message: &str, field: &str) -> bool {
    let Some(doc) = message
        .split_once(" dup key: {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(doc, _)| doc)
    else {
        return false;
    };
    doc.split(',').any(|pair| {
        pair.split_once(':')
            .is_some_and(|(key, _)| key.trim().trim_matches('"') == field)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
    /// ISO 8601 timestamp — return only items created before this date
    #[serde(default)]
    pub before: Option<String>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: default_page(),
            per_page: default_per_page(),
            before: None,
        }
    }
}

fn default_page() -> u64 {
    1
}

fn default_per_page() -> u64 {
    25
}

const MAX_PER_PAGE: u64 = 100;

impl PaginationParams {
    /// Clamp per_page to MAX_PER_PAGE to prevent abuse
    pub fn clamped_per_page(&self) -> u64 {
        self.per_page.min(MAX_PER_PAGE)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
}

pub struct BaseDao<T: Send + Sync> {
    collection: Collection<T>,
}

impl<T> BaseDao<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Unpin + Send + Sync,
{
    pub fn new(db: &Database, collection_name: &str) -> Self {
        Self {
            collection: db.collection::<T>(collection_name),
        }
    }

    pub fn collection(&self) -> &Collection<T> {
        &self.collection
    }

    pub async fn find_by_id(&self, id: ObjectId) -> DaoResult<T> {
        self.collection
            .find_one(doc! { "_id": id })
            .await?
            .ok_or(DaoError::NotFound)
    }

    /// The row by id, in this tenant, **tombstone included**. For a collection
    /// that soft-deletes (`deleted_at`) this is the ANY lookup: it answers for
    /// a removed row exactly as for a live one, which is right for the readers
    /// whose job is the tombstone (a revocation check that must say *why*, an
    /// audit view of something since removed) and wrong for everything else —
    /// a GET, a write, a session start want [`Self::find_live_by_id_in_tenant`].
    /// Reaching for this one on a tombstoned collection is a decision; say why
    /// at the call site.
    pub async fn find_by_id_in_tenant(&self, tenant_id: ObjectId, id: ObjectId) -> DaoResult<T> {
        self.collection
            .find_one(doc! { "_id": id, "tenant_id": tenant_id })
            .await?
            .ok_or(DaoError::NotFound)
    }

    /// The row by id, in this tenant, and LIVE — `NotFound` for a tombstone,
    /// the same answer a bogus or foreign id gets (#1821: the per-id view and
    /// the listing disagreed, so a removed device was still readable and
    /// writable by anyone holding its id).
    ///
    /// The predicate is `deleted_at: null`, which matches null OR absent: a
    /// row that never carried the field was never tombstoned, and this is the
    /// predicate every live-scoped listing in this crate already uses, so the
    /// two views agree by construction. ⚠️ Not `{ "$type": "null" }` — that
    /// spelling belongs to the PARTIAL UNIQUE INDEXES (`index_unique_partial`),
    /// where a filter must name an explicit value; in a query it is strictly
    /// narrower and the only rows it drops are LIVE ones whose field is
    /// missing, i.e. it would 404 a live device on every per-device route. A
    /// tombstone always carries a `DateTime`, so neither spelling can match one.
    pub async fn find_live_by_id_in_tenant(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
    ) -> DaoResult<T> {
        self.collection
            .find_one(doc! { "_id": id, "tenant_id": tenant_id, "deleted_at": null })
            .await?
            .ok_or(DaoError::NotFound)
    }

    pub async fn find_one(&self, filter: Document) -> DaoResult<Option<T>> {
        Ok(self.collection.find_one(filter).await?)
    }

    pub async fn find_by_ids(&self, ids: &[ObjectId]) -> DaoResult<Vec<T>> {
        let filter = doc! { "_id": { "$in": ids } };
        self.find_many(filter, None).await
    }

    pub async fn find_many(&self, filter: Document, sort: Option<Document>) -> DaoResult<Vec<T>> {
        let mut cursor = if let Some(sort) = sort {
            self.collection.find(filter).sort(sort).await?
        } else {
            self.collection.find(filter).await?
        };

        let mut results = Vec::new();
        use futures::TryStreamExt;
        while let Some(doc) = cursor.try_next().await? {
            results.push(doc);
        }
        Ok(results)
    }

    pub async fn find_paginated(
        &self,
        filter: Document,
        sort: Option<Document>,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<T>> {
        let per_page = params.clamped_per_page();
        let total = self.collection.count_documents(filter.clone()).await?;
        let skip = (params.page - 1) * per_page;

        let sort = sort.unwrap_or_else(|| doc! { "created_at": -1 });

        let mut cursor = self
            .collection
            .find(filter)
            .sort(sort)
            .skip(skip)
            .limit(per_page as i64)
            .await?;

        let mut items = Vec::new();
        use futures::TryStreamExt;
        while let Some(doc) = cursor.try_next().await? {
            items.push(doc);
        }

        let total_pages = if per_page > 0 {
            total.div_ceil(per_page)
        } else {
            0
        };

        Ok(PaginatedResult {
            items,
            total,
            page: params.page,
            per_page,
            total_pages,
        })
    }

    pub async fn text_search(
        &self,
        query: &str,
        additional_filter: Document,
        limit: i64,
    ) -> DaoResult<Vec<T>> {
        let mut filter = doc! { "$text": { "$search": query } };
        for (k, v) in additional_filter.iter() {
            filter.insert(k, v.clone());
        }

        let mut cursor = self
            .collection
            .find(filter)
            .sort(doc! { "score": { "$meta": "textScore" } })
            .limit(limit)
            .await?;

        let mut results = Vec::new();
        use futures::TryStreamExt;
        while let Some(doc) = cursor.try_next().await? {
            results.push(doc);
        }
        Ok(results)
    }

    pub async fn insert_one(&self, doc: &T) -> DaoResult<ObjectId> {
        let result = self.collection.insert_one(doc).await.map_err(|e| {
            if let mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                ref write_error,
            )) = *e.kind
                && write_error.code == 11000
            {
                return DaoError::DuplicateKey(write_error.message.clone());
            }
            DaoError::Mongo(e)
        })?;

        let id = result
            .inserted_id
            .as_object_id()
            .expect("inserted_id should be ObjectId");
        debug!(?id, "Inserted document");
        Ok(id)
    }

    pub async fn update_one(&self, filter: Document, update: Document) -> DaoResult<bool> {
        let update_with_timestamp = doc! {
            "$set": {
                "updated_at": bson::DateTime::now(),
            },
            "$setOnInsert": {},
        };

        // Merge update into the $set
        let mut final_update = update;
        if let Ok(set_doc) = final_update.get_document_mut("$set") {
            set_doc.insert("updated_at", bson::DateTime::now());
        } else {
            let mut merged = update_with_timestamp;
            for (key, value) in final_update.iter() {
                if key == "$set" {
                    if let Ok(existing_set) = merged.get_document_mut("$set")
                        && let Some(new_set) = value.as_document()
                    {
                        for (k, v) in new_set.iter() {
                            existing_set.insert(k, v.clone());
                        }
                    }
                } else {
                    merged.insert(key, value.clone());
                }
            }
            final_update = merged;
        }

        let result = self.collection.update_one(filter, final_update).await?;
        Ok(result.modified_count > 0)
    }

    pub async fn update_by_id(&self, id: ObjectId, update: Document) -> DaoResult<bool> {
        self.update_one(doc! { "_id": id }, update).await
    }

    /// Bulk update; stamps `updated_at` like [`Self::update_one`].
    /// Returns the modified-document count.
    pub async fn update_many(&self, filter: Document, update: Document) -> DaoResult<u64> {
        let mut final_update = update;
        if let Ok(set_doc) = final_update.get_document_mut("$set") {
            set_doc.insert("updated_at", bson::DateTime::now());
        } else {
            final_update.insert("$set", doc! { "updated_at": bson::DateTime::now() });
        }
        let result = self.collection.update_many(filter, final_update).await?;
        Ok(result.modified_count)
    }

    pub async fn soft_delete(&self, id: ObjectId) -> DaoResult<bool> {
        self.update_one(
            doc! { "_id": id },
            doc! { "$set": { "deleted_at": bson::DateTime::now() } },
        )
        .await
    }

    pub async fn soft_delete_in_tenant(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
    ) -> DaoResult<bool> {
        self.update_one(
            doc! { "_id": id, "tenant_id": tenant_id },
            doc! { "$set": { "deleted_at": bson::DateTime::now() } },
        )
        .await
    }

    pub async fn hard_delete(&self, filter: Document) -> DaoResult<u64> {
        let result = self.collection.delete_many(filter).await?;
        Ok(result.deleted_count)
    }

    pub async fn count(&self, filter: Document) -> DaoResult<u64> {
        Ok(self.collection.count_documents(filter).await?)
    }
}

/// Escape user input for a Mongo `$regex` filter — every PCRE metacharacter
/// becomes literal. One shared implementation (lifted from `RoomDao::explore`)
/// so search endpoints can't diverge on which characters they neutralize.
pub fn escape_regex(input: &str) -> String {
    input
        .chars()
        .flat_map(|c| {
            if ".*+?^${}()|[]\\".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod duplicate_key_tests {
    use super::*;

    /// The exact string MongoDB 7 produces for a single-field unique index.
    const EMAIL: &str = "E11000 duplicate key error collection: meshharbor.users \
index: email_1 dup key: { email: \"victim@corp.example\" }";
    const USERNAME: &str = "E11000 duplicate key error collection: meshharbor.users \
index: username_1 dup key: { username: \"victim_a1b2c3\" }";
    const COMPOUND: &str = "E11000 duplicate key error collection: meshharbor.agents \
index: tenant_id_1_machine_id_1 dup key: { tenant_id: ObjectId('68a1'), machine_id: \"m-1\" }";

    #[test]
    fn names_the_index() {
        assert_eq!(duplicate_key_index(EMAIL), Some("email_1"));
        assert_eq!(
            duplicate_key_index(COMPOUND),
            Some("tenant_id_1_machine_id_1")
        );
        assert_eq!(duplicate_key_index("something else entirely"), None);
    }

    /// The regression that matters: an EMAIL collision must not read as a
    /// username one. This is the check the retry loop was missing.
    #[test]
    fn an_email_collision_is_not_a_username_collision() {
        assert!(duplicate_key_is_on(EMAIL, "email"));
        assert!(
            !duplicate_key_is_on(EMAIL, "username"),
            "retrying this would burn attempts and then blame the wrong field"
        );
        assert!(duplicate_key_is_on(USERNAME, "username"));
        assert!(!duplicate_key_is_on(USERNAME, "email"));
    }

    #[test]
    fn compound_indexes_name_every_field() {
        assert!(duplicate_key_is_on(COMPOUND, "tenant_id"));
        assert!(duplicate_key_is_on(COMPOUND, "machine_id"));
        assert!(!duplicate_key_is_on(COMPOUND, "username"));
    }

    /// ⚠️ Reading the index NAME instead of the dup-key document would answer
    /// yes here, because `email_verified_1` contains "email". Underscores are
    /// legal in our field names, so the name cannot be split back into fields.
    #[test]
    fn a_field_that_merely_prefixes_another_does_not_match() {
        let msg = "E11000 duplicate key error collection: meshharbor.users \
index: email_verified_1 dup key: { email_verified: true }";
        assert!(duplicate_key_is_on(msg, "email_verified"));
        assert!(!duplicate_key_is_on(msg, "email"));
    }

    /// Unknown must never read as "not my field" — a caller that retries on
    /// `false` would loop forever on an unparseable message, so `false` here
    /// has to mean "don't retry", which is what the callers do.
    #[test]
    fn an_unparseable_message_is_conservative() {
        assert!(!duplicate_key_is_on(
            "E11000 duplicate key error",
            "username"
        ));
        assert!(!duplicate_key_is_on("", "username"));
    }
}
