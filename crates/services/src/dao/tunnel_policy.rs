// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::{
    DestinationRule, PolicySubject, PolicyTarget, TunnelPolicy,
};

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct TunnelPolicyDao {
    pub base: BaseDao<TunnelPolicy>,
}

impl TunnelPolicyDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, TunnelPolicy::COLLECTION),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        name: String,
        subjects: Vec<PolicySubject>,
        targets: Vec<PolicyTarget>,
        allowlist: Vec<DestinationRule>,
        max_concurrent_flows: Option<u32>,
        max_bytes_per_session: Option<u64>,
    ) -> DaoResult<TunnelPolicy> {
        let now = DateTime::now();
        let policy = TunnelPolicy {
            id: None,
            tenant_id,
            name,
            subjects,
            targets,
            allowlist,
            max_concurrent_flows,
            max_bytes_per_session,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let id = self.base.insert_one(&policy).await?;
        self.base.find_by_id(id).await
    }

    /// All live (non-soft-deleted) policies for a tenant. The
    /// server-side ACL gate fetches this set on every
    /// `TcpForwardRequest` and runs the in-memory evaluator. v1
    /// keeps it simple — no cache; admin UI is the only write path
    /// and writes are rare.
    pub async fn list_active_for_tenant(
        &self,
        tenant_id: ObjectId,
    ) -> DaoResult<Vec<TunnelPolicy>> {
        self.base
            .find_many(
                doc! { "tenant_id": tenant_id, "deleted_at": null },
                Some(doc! { "created_at": -1 }),
            )
            .await
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<TunnelPolicy>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "deleted_at": null },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    /// The per-policy lookup the admin routes want: this id, this tenant, and
    /// LIVE. A deleted policy is `NotFound` here exactly as it is absent from
    /// [`Self::list_for_tenant`] and from the gate's
    /// [`Self::list_active_for_tenant`] — the per-id view disagreeing with
    /// both was #1829 (the #1821 hole, on this DAO): `GET …/tunnel-policy/{id}`
    /// served a deleted policy and `PUT` edited it. A deleted policy is never
    /// served, edited or compiled; the evaluator additionally skips any row
    /// with `deleted_at` set (`tunnel_core::policy`), as defence in depth.
    ///
    /// There is deliberately no un-suffixed `find_in_tenant` any more: a
    /// caller chooses LIVE or [`Self::find_any_in_tenant`] by name.
    ///
    /// The predicate is `deleted_at: null` (null OR absent), the one every
    /// listing on this collection uses. `tunnel_policies` has no unique index
    /// at all; its only `deleted_at` index is the plain compound
    /// `(tenant_id, deleted_at)` that serves exactly this equality — a
    /// `$type: "null"` predicate would not even be served by it.
    pub async fn find_live_in_tenant(
        &self,
        tenant_id: ObjectId,
        policy_id: ObjectId,
    ) -> DaoResult<TunnelPolicy> {
        self.base
            .find_live_by_id_in_tenant(tenant_id, policy_id)
            .await
    }

    /// The per-policy lookup that also returns a TOMBSTONE. No caller today:
    /// the only legitimate one is an audit or decision log that names a
    /// removed policy by id and must still be able to show what it said.
    /// Never for a GET of the policy itself, never for a write, never to
    /// compile — those are [`Self::find_live_in_tenant`] and
    /// [`Self::list_active_for_tenant`]. It exists so that a future reader
    /// that genuinely needs the tombstone chooses it BY NAME, with a reason at
    /// the call site, rather than reaching through `base`.
    pub async fn find_any_in_tenant(
        &self,
        tenant_id: ObjectId,
        policy_id: ObjectId,
    ) -> DaoResult<TunnelPolicy> {
        self.base.find_by_id_in_tenant(tenant_id, policy_id).await
    }

    /// The filter every write below goes through: this row, in this tenant,
    /// and LIVE (#1829). The routes look the policy up live first; this
    /// closes the window between that read and the write, and holds for a
    /// caller that never did the read. A tombstone matches nothing, so the
    /// write reports `false` and the removal time it carries stays as it was.
    fn live_row(tenant_id: ObjectId, policy_id: ObjectId) -> bson::Document {
        doc! { "_id": policy_id, "tenant_id": tenant_id, "deleted_at": null }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        tenant_id: ObjectId,
        policy_id: ObjectId,
        name: Option<String>,
        subjects: Option<Vec<PolicySubject>>,
        targets: Option<Vec<PolicyTarget>>,
        allowlist: Option<Vec<DestinationRule>>,
        max_concurrent_flows: Option<Option<u32>>,
        max_bytes_per_session: Option<Option<u64>>,
    ) -> DaoResult<bool> {
        let mut set = doc! { "updated_at": DateTime::now() };
        if let Some(n) = name {
            set.insert("name", n);
        }
        if let Some(s) = subjects {
            set.insert("subjects", bson::to_bson(&s).unwrap_or(bson::Bson::Null));
        }
        if let Some(t) = targets {
            set.insert("targets", bson::to_bson(&t).unwrap_or(bson::Bson::Null));
        }
        if let Some(a) = allowlist {
            set.insert("allowlist", bson::to_bson(&a).unwrap_or(bson::Bson::Null));
        }
        if let Some(c) = max_concurrent_flows {
            set.insert(
                "max_concurrent_flows",
                c.map(|v| bson::Bson::Int64(v as i64))
                    .unwrap_or(bson::Bson::Null),
            );
        }
        if let Some(b) = max_bytes_per_session {
            set.insert(
                "max_bytes_per_session",
                b.map(|v| bson::Bson::Int64(v as i64))
                    .unwrap_or(bson::Bson::Null),
            );
        }
        self.base
            .update_one(Self::live_row(tenant_id, policy_id), doc! { "$set": set })
            .await
    }

    /// Tombstone a LIVE row. `deleted_at` is the removal time and is written
    /// once: a repeat on a tombstone matches nothing and reports `false`, which
    /// the route answers with 404 (#1829) — before this, a repeat `DELETE`
    /// re-stamped the removal time and reported success for a removal someone
    /// else did.
    pub async fn soft_delete(&self, tenant_id: ObjectId, policy_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, policy_id),
                doc! { "$set": { "deleted_at": DateTime::now() } },
            )
            .await
    }
}
