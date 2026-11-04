// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-111 P4a — `touch_presets`: an org's on-screen control presets, the
//! `remote` module's collection (spec `docs/fr/FR-111-touch-controls.md` §3d).
//!
//! Every lookup and write is scoped to the tenant, so a foreign id gets the
//! same `NotFound` / `false` a bogus one does. The name is unique per tenant
//! (the module's unique index), and a clash on it is
//! [`DaoError::DuplicateKey`], on a create and on a rename alike. Rows are
//! deleted, not tombstoned: nothing holds a preset's id but a browser's
//! remembered choice, which falls back to off when the id is gone.

use bson::{DateTime, doc, oid::ObjectId};
use mongodb::{Database, options::ReturnDocument};
use meshharbor_remote_control::models::{TouchControl, TouchPreset};

use super::base::{BaseDao, DaoError, DaoResult};

pub struct TouchPresetDao {
    pub base: BaseDao<TouchPreset>,
}

impl TouchPresetDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, TouchPreset::COLLECTION),
        }
    }

    /// The org's presets, by name.
    pub async fn list(&self, tenant_id: ObjectId) -> DaoResult<Vec<TouchPreset>> {
        self.base
            .find_many(doc! { "tenant_id": tenant_id }, Some(doc! { "name": 1 }))
            .await
    }

    pub async fn count(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base.count(doc! { "tenant_id": tenant_id }).await
    }

    /// Insert one. A name the org already has is `DuplicateKey`.
    pub async fn create(&self, preset: &TouchPreset) -> DaoResult<ObjectId> {
        self.base.insert_one(preset).await
    }

    /// Replace a preset's name and controls, within the tenant, answering the
    /// stored row. `None` when this tenant has no such preset. Matched, not
    /// "modified": saving an unchanged preset is still a success.
    pub async fn replace(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
        name: &str,
        controls: &[TouchControl],
        by: ObjectId,
    ) -> DaoResult<Option<TouchPreset>> {
        let controls = bson::to_bson(controls)?;
        self.base
            .collection()
            .find_one_and_update(
                doc! { "_id": id, "tenant_id": tenant_id },
                doc! { "$set": {
                    "name": name,
                    "controls": controls,
                    "updated_by": by,
                    "updated_at": DateTime::now(),
                } },
            )
            .return_document(ReturnDocument::After)
            .await
            .map_err(duplicate_name)
    }

    /// Delete one, within the tenant; `false` when there was none.
    pub async fn delete(&self, tenant_id: ObjectId, id: ObjectId) -> DaoResult<bool> {
        Ok(self
            .base
            .hard_delete(doc! { "_id": id, "tenant_id": tenant_id })
            .await?
            > 0)
    }
}

/// A rename onto a name the org already has: `findAndModify` reports the
/// unique index's clash as a COMMAND error (an insert reports a write error,
/// which `BaseDao::insert_one` maps), and both are `DuplicateKey` here.
fn duplicate_name(e: mongodb::error::Error) -> DaoError {
    match *e.kind {
        mongodb::error::ErrorKind::Command(ref c) if c.code == 11000 => {
            DaoError::DuplicateKey(c.message.clone())
        }
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(ref w))
            if w.code == 11000 =>
        {
            DaoError::DuplicateKey(w.message.clone())
        }
        _ => DaoError::Mongo(e),
    }
}
