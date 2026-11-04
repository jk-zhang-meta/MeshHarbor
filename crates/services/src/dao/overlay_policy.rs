// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::{
    OverlayPolicy, OverlayRule, OverlaySelector, OverlayTarget,
};

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

/// CRUD for the overlay L3 ACL. Mirrors [`super::tunnel_policy::TunnelPolicyDao`]
/// deliberately — same soft-delete + tenant-scoping conventions — but the rows
/// drive netmap shaping rather than per-flow forward decisions.
pub struct OverlayPolicyDao {
    pub base: BaseDao<OverlayPolicy>,
}

impl OverlayPolicyDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, OverlayPolicy::COLLECTION),
        }
    }

    pub async fn create(
        &self,
        tenant_id: ObjectId,
        name: String,
        enabled: bool,
        sources: Vec<OverlaySelector>,
        via: Vec<OverlayTarget>,
        destinations: Vec<OverlayRule>,
    ) -> DaoResult<OverlayPolicy> {
        let now = DateTime::now();
        let policy = OverlayPolicy {
            id: None,
            tenant_id,
            name,
            enabled,
            sources,
            via,
            destinations,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let id = self.base.insert_one(&policy).await?;
        self.base.find_by_id(id).await
    }

    /// All live policies for a tenant, newest first.
    ///
    /// Read on every overlay join and on every re-fan. Unlike the tunnel gate
    /// (which reads per FLOW), the overlay reads per NETMAP EVENT — joins,
    /// leaves and admin edits — so the query rate is orders of magnitude lower
    /// and a cache would be premature.
    pub async fn list_active_for_tenant(
        &self,
        tenant_id: ObjectId,
    ) -> DaoResult<Vec<OverlayPolicy>> {
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
    ) -> DaoResult<PaginatedResult<OverlayPolicy>> {
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
    /// [`Self::list_for_tenant`] and from the netmap compiler's
    /// [`Self::list_active_for_tenant`] — the per-id view disagreeing with
    /// both was #1829 (the #1821 hole, on this DAO): `GET …/overlay-acl/{id}`
    /// served a deleted policy and `PUT` edited it (and re-fanned the tenant
    /// for the edit). A deleted policy is never served, edited or compiled;
    /// the evaluator additionally skips any row with `deleted_at` set or
    /// `enabled: false` (`tunnel_core::policy`), as defence in depth.
    ///
    /// There is deliberately no un-suffixed `find_in_tenant` any more: a
    /// caller chooses LIVE or [`Self::find_any_in_tenant`] by name.
    ///
    /// The predicate is `deleted_at: null` (null OR absent), the one both
    /// listings on this collection use. ⚠️ The `$type: "null"` partial unique
    /// indexes the overlay carries are on `overlay_nodes`, NOT on this
    /// collection — `overlay_policies` declares no index set at all — and even
    /// `OverlayNodeDao`'s own live lookups query with equality-null, keeping
    /// `$type` an index-only spelling. Copying it into a query here would gain
    /// nothing against a tombstone (one always carries a `DateTime`) and would
    /// 404 a live policy whose field is absent, on every per-policy route.
    pub async fn find_live_in_tenant(
        &self,
        tenant_id: ObjectId,
        policy_id: ObjectId,
    ) -> DaoResult<OverlayPolicy> {
        self.base
            .find_live_by_id_in_tenant(tenant_id, policy_id)
            .await
    }

    /// The per-policy lookup that also returns a TOMBSTONE. No caller today:
    /// the only legitimate one is an audit or decision log (the relay-mint
    /// and ACL decision rows) that names a removed policy by id and must
    /// still be able to show what it said. Never for a GET of the policy
    /// itself, never for a write, never to compile — those are
    /// [`Self::find_live_in_tenant`] and [`Self::list_active_for_tenant`]. It
    /// exists so that a future reader that genuinely needs the tombstone
    /// chooses it BY NAME, with a reason at the call site, rather than
    /// reaching through `base`.
    pub async fn find_any_in_tenant(
        &self,
        tenant_id: ObjectId,
        policy_id: ObjectId,
    ) -> DaoResult<OverlayPolicy> {
        self.base.find_by_id_in_tenant(tenant_id, policy_id).await
    }

    /// The filter every write below goes through: this row, in this tenant,
    /// and LIVE (#1829). The routes look the policy up live first; this
    /// closes the window between that read and the write, and holds for a
    /// caller that never did the read. A tombstone matches nothing, so the
    /// write reports `false` — in particular `enabled: true` can never be
    /// written back onto a deleted policy — and the removal time it carries
    /// stays as it was.
    fn live_row(tenant_id: ObjectId, policy_id: ObjectId) -> bson::Document {
        doc! { "_id": policy_id, "tenant_id": tenant_id, "deleted_at": null }
    }

    // Same shape (and same allow) as `TunnelPolicyDao::update`: every field is
    // an independent `Option` so a PATCH can leave the rest untouched.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        tenant_id: ObjectId,
        policy_id: ObjectId,
        name: Option<String>,
        enabled: Option<bool>,
        sources: Option<Vec<OverlaySelector>>,
        via: Option<Vec<OverlayTarget>>,
        destinations: Option<Vec<OverlayRule>>,
    ) -> DaoResult<bool> {
        let mut set = doc! { "updated_at": DateTime::now() };
        if let Some(n) = name {
            set.insert("name", n);
        }
        if let Some(e) = enabled {
            set.insert("enabled", e);
        }
        if let Some(s) = sources {
            set.insert("sources", bson::to_bson(&s).unwrap_or(bson::Bson::Null));
        }
        if let Some(v) = via {
            set.insert("via", bson::to_bson(&v).unwrap_or(bson::Bson::Null));
        }
        if let Some(d) = destinations {
            set.insert(
                "destinations",
                bson::to_bson(&d).unwrap_or(bson::Bson::Null),
            );
        }
        self.base
            .update_one(Self::live_row(tenant_id, policy_id), doc! { "$set": set })
            .await
    }

    /// Tombstone a LIVE row. `deleted_at` is the removal time and is written
    /// once: a repeat on a tombstone matches nothing and reports `false`, which
    /// the route answers with 404 (#1829) — before this, a repeat `DELETE`
    /// re-stamped the removal time, reported `deleted: true` and re-fanned
    /// the whole tenant for a removal someone else did.
    pub async fn soft_delete(&self, tenant_id: ObjectId, policy_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, policy_id),
                doc! { "$set": { "deleted_at": DateTime::now() } },
            )
            .await
    }
}
