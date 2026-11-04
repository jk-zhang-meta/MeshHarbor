// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use dashmap::DashMap;
use mongodb::Database;
use meshharbor_db::models::BackgroundTask;

use crate::dao::base::{BaseDao, DaoResult};

/// Hybrid in-memory + MongoDB task store (pattern from lgr/pcon_plus)
pub struct TaskStore {
    pub db_dao: BaseDao<BackgroundTask>,
    pub cache: DashMap<ObjectId, BackgroundTask>,
}

impl TaskStore {
    pub fn new(db: &Database) -> Self {
        Self {
            db_dao: BaseDao::new(db, BackgroundTask::COLLECTION),
            cache: DashMap::new(),
        }
    }

    pub async fn insert(&self, task: &BackgroundTask) -> DaoResult<ObjectId> {
        let id = self.db_dao.insert_one(task).await?;
        let mut cached = task.clone();
        cached.id = Some(id);
        self.cache.insert(id, cached);
        Ok(id)
    }

    pub async fn get(&self, id: ObjectId) -> DaoResult<BackgroundTask> {
        // Check cache first
        if let Some(task) = self.cache.get(&id) {
            return Ok(task.clone());
        }
        // Fall back to DB
        let task = self.db_dao.find_by_id(id).await?;
        self.cache.insert(id, task.clone());
        Ok(task)
    }

    pub async fn update_progress(
        &self,
        id: ObjectId,
        progress: u8,
        log_entry: Option<String>,
    ) -> DaoResult<()> {
        let mut update = doc! {
            "$set": {
                "progress": progress as i32,
                "updated_at": DateTime::now(),
            }
        };

        if let Some(log) = &log_entry {
            update.insert("$push", doc! { "logs": log });
        }

        self.db_dao.update_by_id(id, update).await?;

        // Update cache
        if let Some(mut task) = self.cache.get_mut(&id) {
            task.progress = progress;
            if let Some(log) = log_entry {
                task.logs.push(log);
            }
            task.updated_at = DateTime::now();
        }

        Ok(())
    }

    pub async fn complete(
        &self,
        id: ObjectId,
        file_path: Option<String>,
        file_name: Option<String>,
    ) -> DaoResult<()> {
        let now = DateTime::now();
        self.db_dao
            .update_by_id(
                id,
                doc! {
                    "$set": {
                        "status": "completed",
                        "progress": 100,
                        "file_path": file_path.as_deref(),
                        "file_name": file_name.as_deref(),
                        "completed_at": now,
                        "updated_at": now,
                    }
                },
            )
            .await?;

        if let Some(mut task) = self.cache.get_mut(&id) {
            task.status = meshharbor_db::models::TaskStatus::Completed;
            task.progress = 100;
            task.file_path = file_path;
            task.file_name = file_name;
            task.completed_at = Some(now);
            task.updated_at = now;
        }

        Ok(())
    }

    pub async fn fail(&self, id: ObjectId, error: String) -> DaoResult<()> {
        let now = DateTime::now();
        self.db_dao
            .update_by_id(
                id,
                doc! {
                    "$set": {
                        "status": "failed",
                        "error": &error,
                        "completed_at": now,
                        "updated_at": now,
                    }
                },
            )
            .await?;

        if let Some(mut task) = self.cache.get_mut(&id) {
            task.status = meshharbor_db::models::TaskStatus::Failed;
            task.error = Some(error);
            task.completed_at = Some(now);
            task.updated_at = now;
        }

        Ok(())
    }

    pub fn cleanup_cache(&self) {
        self.cache.retain(|_, task| {
            matches!(
                task.status,
                meshharbor_db::models::TaskStatus::Pending
                    | meshharbor_db::models::TaskStatus::Processing
            )
        });
    }
}
