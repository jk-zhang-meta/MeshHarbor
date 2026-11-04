// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::recording::{StorageProvider, Visibility};
use meshharbor_db::models::{self, FileContext, ScanStatus};
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct FileDao {
    pub base: BaseDao<models::File>,
}

impl FileDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, models::File::COLLECTION),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        uploaded_by: ObjectId,
        context: FileContext,
        filename: String,
        content_type: String,
        size: u64,
        storage_bucket: String,
        storage_key: String,
        url: String,
    ) -> DaoResult<models::File> {
        let now = DateTime::now();
        let file = models::File {
            id: None,
            tenant_id,
            uploaded_by,
            context,
            filename: filename.clone(),
            display_name: Some(filename),
            description: None,
            storage_provider: StorageProvider::MinIO,
            storage_bucket,
            storage_key,
            url,
            content_type,
            size,
            checksum: None,
            dimensions: None,
            duration: None,
            thumbnails: Vec::new(),
            version: 1,
            previous_version_id: None,
            is_current_version: true,
            external_source: None,
            scan_status: ScanStatus::Pending,
            visibility: Visibility::Private,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let id = self.base.insert_one(&file).await?;
        self.base.find_by_id(id).await
    }

    /// FR-11: optional name search + sort shared by the file lists. `q` is
    /// escaped-regex over filename/display_name; sort whitelist is owned by
    /// the routes (this just maps key→field). `_id` tiebreak keeps skip/limit
    /// pages disjoint under ties.
    fn q_filter(mut filter: bson::Document, q: Option<&str>) -> bson::Document {
        if let Some(q) = q.map(str::trim).filter(|q| !q.is_empty()) {
            let escaped = super::base::escape_regex(q);
            filter.insert(
                "$or",
                vec![
                    doc! { "filename": { "$regex": &escaped, "$options": "i" } },
                    doc! { "display_name": { "$regex": &escaped, "$options": "i" } },
                ],
            );
        }
        filter
    }

    fn sort_doc(sort: Option<&str>, desc: bool) -> bson::Document {
        let dir = if desc { -1 } else { 1 };
        match sort {
            Some("filename") => doc! { "filename": dir, "_id": dir },
            Some("size") => doc! { "size": dir, "_id": dir },
            Some("created_at") => doc! { "created_at": dir, "_id": dir },
            // Default: today's order, unchanged.
            _ => doc! { "created_at": -1, "_id": -1 },
        }
    }

    /// FR-32 — bytes currently stored by the tenant, for the plan
    /// `storage_bytes` gate.
    ///
    /// The only one of the counted limits that is a SUM rather than a count, so
    /// it needs an aggregation rather than `count`. Soft-deleted files are
    /// excluded, which matches what the customer sees in the files list — a
    /// quota that counted invisible rows would be unactionable, because there
    /// would be nothing they could delete to get back under it.
    ///
    /// ⚠ Returns 0 for a tenant with no files: `$group` emits no document at
    /// all for an empty match, so the `None` case is "nothing stored", not an
    /// error.
    pub async fn sum_storage_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        let pipeline = vec![
            doc! { "$match": { "tenant_id": tenant_id, "deleted_at": null } },
            doc! { "$group": { "_id": null, "total": { "$sum": "$size" } } },
        ];
        let mut cursor = self.base.collection().aggregate(pipeline).await?;
        use futures::TryStreamExt;
        if let Some(d) = cursor.try_next().await? {
            // `$sum` widens to i64/f64 depending on the stored BSON types, so
            // read defensively rather than assuming one of them.
            let total = d
                .get_i64("total")
                .map(|v| v.max(0) as u64)
                .or_else(|_| d.get_i32("total").map(|v| v.max(0) as u64))
                .or_else(|_| d.get_f64("total").map(|v| v.max(0.0) as u64))
                .unwrap_or(0);
            return Ok(total);
        }
        Ok(0)
    }

    pub async fn find_by_room(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        params: &PaginationParams,
        q: Option<&str>,
        sort: Option<&str>,
        desc: bool,
    ) -> DaoResult<PaginatedResult<models::File>> {
        self.base
            .find_paginated(
                Self::q_filter(
                    doc! {
                        "tenant_id": tenant_id,
                        "context.room_id": room_id,
                        "deleted_at": null,
                    },
                    q,
                ),
                Some(Self::sort_doc(sort, desc)),
                params,
            )
            .await
    }

    pub async fn find_by_user(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<models::File>> {
        self.base
            .find_paginated(
                doc! {
                    "tenant_id": tenant_id,
                    "uploaded_by": user_id,
                    "deleted_at": null,
                },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    pub async fn find_by_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
        q: Option<&str>,
        sort: Option<&str>,
        desc: bool,
    ) -> DaoResult<PaginatedResult<models::File>> {
        self.base
            .find_paginated(
                Self::q_filter(
                    doc! {
                        "tenant_id": tenant_id,
                        "deleted_at": null,
                    },
                    q,
                ),
                Some(Self::sort_doc(sort, desc)),
                params,
            )
            .await
    }

    pub async fn soft_delete(&self, tenant_id: ObjectId, file_id: ObjectId) -> DaoResult<bool> {
        self.base.soft_delete_in_tenant(tenant_id, file_id).await
    }
}
