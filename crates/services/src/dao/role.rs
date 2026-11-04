// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::Role;
use mongodb::Database;

use super::base::{BaseDao, DaoError, DaoResult};

pub struct RoleDao {
    pub base: BaseDao<Role>,
}

impl RoleDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, Role::COLLECTION),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        name: String,
        description: Option<String>,
        color: Option<u32>,
        perms: u64,
        is_default: bool,
        is_managed: bool,
        position: u32,
    ) -> DaoResult<Role> {
        let now = DateTime::now();
        let role = Role {
            id: None,
            tenant_id,
            name,
            description,
            color,
            position,
            permissions: perms,
            is_default,
            is_managed,
            is_mentionable: true,
            is_hoisted: false,
            created_at: now,
            updated_at: now,
        };
        let id = self.base.insert_one(&role).await?;
        self.base.find_by_id(id).await
    }

    pub async fn find_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<Vec<Role>> {
        self.base
            .find_many(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "position": 1 }),
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        role_id: ObjectId,
        tenant_id: ObjectId,
        name: Option<String>,
        description: Option<String>,
        color: Option<u32>,
        perms: Option<u64>,
        position: Option<u32>,
    ) -> DaoResult<bool> {
        let mut set_doc = doc! { "updated_at": DateTime::now() };
        if let Some(n) = name {
            set_doc.insert("name", n);
        }
        if let Some(d) = description {
            set_doc.insert("description", d);
        }
        if let Some(c) = color {
            set_doc.insert("color", c as i64);
        }
        if let Some(p) = perms {
            set_doc.insert("permissions", p as i64);
        }
        if let Some(pos) = position {
            set_doc.insert("position", pos as i64);
        }

        self.base
            .update_one(
                doc! { "_id": role_id, "tenant_id": tenant_id },
                doc! { "$set": set_doc },
            )
            .await
    }

    pub async fn delete(&self, role_id: ObjectId, tenant_id: ObjectId) -> DaoResult<bool> {
        // Prevent deleting default/managed roles
        let role = self.base.find_by_id(role_id).await?;
        if role.is_default || role.is_managed {
            return Err(DaoError::Forbidden(
                "Cannot delete default or managed roles".into(),
            ));
        }

        let result = self
            .base
            .collection()
            .delete_one(doc! { "_id": role_id, "tenant_id": tenant_id })
            .await?;
        Ok(result.deleted_count > 0)
    }

    // FR-82 — `seed_defaults` lived here: a SECOND set of managed-role
    // definitions, Titlecased, with no `guest`, and with a `Moderator` that
    // carried `MANAGE_MEETINGS` and not `REMOTE_CONTROL` — the reverse of the
    // copy that actually ran (`TenantDao::create_default_roles`). It had no
    // callers, so the divergence was invisible and would have shipped a
    // different org the day someone wired it up. The definitions now live
    // once, in `meshharbor_db::models::role::MANAGED_ROLES`.
}
