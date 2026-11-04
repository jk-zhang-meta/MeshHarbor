// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_db::models::{BackgroundTask, TaskCategory, TaskStatus};
use std::sync::Arc;

use crate::dao::base::{DaoResult, PaginatedResult, PaginationParams};

use super::task_store::TaskStore;

pub struct TaskService {
    store: Arc<TaskStore>,
}

impl TaskService {
    pub fn new(db: &Database) -> Self {
        Self {
            store: Arc::new(TaskStore::new(db)),
        }
    }

    pub fn store(&self) -> &Arc<TaskStore> {
        &self.store
    }

    pub async fn create_task(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        task_type: String,
        category: TaskCategory,
        params: serde_json::Value,
    ) -> DaoResult<BackgroundTask> {
        let now = DateTime::now();
        let expires_at = DateTime::from_millis(now.timestamp_millis() + 24 * 60 * 60 * 1000);
        let task = BackgroundTask {
            id: None,
            tenant_id,
            user_id,
            task_type,
            category,
            status: TaskStatus::Pending,
            params,
            logs: Vec::new(),
            progress: 0,
            file_path: None,
            file_name: None,
            error: None,
            started_at: None,
            completed_at: None,
            expires_at,
            created_at: now,
            updated_at: now,
        };

        let id = self.store.insert(&task).await?;
        self.store.get(id).await
    }

    pub async fn get_task(&self, task_id: ObjectId) -> DaoResult<BackgroundTask> {
        self.store.get(task_id).await
    }

    pub async fn list_user_tasks(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<BackgroundTask>> {
        self.store
            .db_dao
            .find_paginated(
                doc! { "tenant_id": tenant_id, "user_id": user_id },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    pub fn spawn_task<F>(&self, task_id: ObjectId, fut: F)
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            // Mark as processing
            let _ = store
                .update_progress(task_id, 0, Some("Task started".to_string()))
                .await;

            match fut.await {
                Ok(()) => {
                    tracing::info!(?task_id, "Background task completed");
                }
                Err(error) => {
                    tracing::error!(?task_id, %error, "Background task failed");
                    let _ = store.fail(task_id, error).await;
                }
            }
        });
    }
}
