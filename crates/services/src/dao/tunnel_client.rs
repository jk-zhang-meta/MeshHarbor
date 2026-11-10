// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::models::{AgentStatus, OsKind, TunnelClient};
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct TunnelClientDao {
    pub base: BaseDao<TunnelClient>,
}

impl TunnelClientDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, TunnelClient::COLLECTION),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        owner_user_id: ObjectId,
        name: String,
        machine_id: String,
        os: OsKind,
        client_version: String,
    ) -> DaoResult<TunnelClient> {
        let now = DateTime::now();
        let client = TunnelClient {
            id: None,
            tenant_id,
            owner_user_id,
            name,
            display_name: None,
            tags: Vec::new(),
            name_admin_set: false,
            machine_id,
            os,
            client_version,
            status: AgentStatus::Offline,
            last_seen_at: now,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            // FR-103 — only a removal advances it.
            token_gen: 0,
        };
        let id = self.base.insert_one(&client).await?;
        self.base.find_by_id(id).await
    }

    /// Locate a tunnel client by `(tenant_id, machine_id)` regardless
    /// of soft-delete state. Mirrors `AgentDao::find_by_tenant_and_machine`
    /// — the unique index covers soft-deleted rows, so the enroll path
    /// calls this first and rehydrates instead of failing with E11000.
    pub async fn find_by_tenant_and_machine(
        &self,
        tenant_id: ObjectId,
        machine_id: &str,
    ) -> DaoResult<Option<TunnelClient>> {
        self.base
            .find_one(doc! {
                "tenant_id": tenant_id,
                "machine_id": machine_id,
            })
            .await
    }

    /// Refresh at re-enrollment: clear `deleted_at`, refresh
    /// os / client_version, bump `updated_at`. Returns the
    /// updated row so the caller can mint a fresh tunnel-client token.
    ///
    /// `name` refreshes ONLY while `name_admin_set` is unset — same
    /// rehydrate-clobber protection as `AgentDao::rehydrate`.
    pub async fn rehydrate(
        &self,
        client_id: ObjectId,
        name: &str,
        os: OsKind,
        client_version: &str,
    ) -> DaoResult<TunnelClient> {
        let os_bson = bson::to_bson(&os).unwrap_or(bson::Bson::Null);
        self.base
            .update_by_id(
                client_id,
                doc! {
                    "$set": {
                        "os": os_bson,
                        "client_version": client_version,
                        "updated_at": DateTime::now(),
                        "deleted_at": bson::Bson::Null,
                    }
                },
            )
            .await?;
        self.base
            .update_one(
                doc! { "_id": client_id, "name_admin_set": { "$ne": true } },
                doc! { "$set": { "name": name } },
            )
            .await?;
        self.base.find_by_id(client_id).await
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<TunnelClient>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "deleted_at": null },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    /// Every non-tombstoned tunnel client in the tenant, unpaginated —
    /// mirrors `AgentDao::list_all_active_for_tenant` for the unified device
    /// list's in-memory compose.
    pub async fn list_all_active_for_tenant(
        &self,
        tenant_id: ObjectId,
    ) -> DaoResult<Vec<TunnelClient>> {
        self.base
            .find_many(doc! { "tenant_id": tenant_id, "deleted_at": null }, None)
            .await
    }

    /// S5 — active (non-tombstoned) tunnel clients in the tenant, for
    /// the plan cap check at enrollment.
    pub async fn count_active_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base
            .count(doc! { "tenant_id": tenant_id, "deleted_at": null })
            .await
    }

    /// The per-client lookup every admin route wants: this id, this tenant,
    /// and LIVE. A removed client is `NotFound` here exactly as it is absent
    /// from [`Self::list_for_tenant`] — the two disagreeing was #1829 (the
    /// #1821 hole, on this DAO): `PUT …/tunnel-client/{id}` renamed and
    /// re-tagged a tombstone, and a repeat `DELETE` re-ran the whole removal
    /// on it and re-stamped the removal time.
    ///
    /// There is deliberately no un-suffixed `find_in_tenant` any more: a
    /// caller chooses LIVE or [`Self::find_any_in_tenant`] by name, and the
    /// compiler asks the question of every future call site too.
    ///
    /// The predicate is `deleted_at: null` (null OR absent) — the one every
    /// live listing on this collection uses, so the two views agree by
    /// construction. The `tunnel_clients` unique index is unconditional (same
    /// re-enroll-rehydrates contract as `agents`), so no `$type: "null"`
    /// partial-index rule binds here; see `BaseDao::find_live_by_id_in_tenant`.
    pub async fn find_live_in_tenant(
        &self,
        tenant_id: ObjectId,
        client_id: ObjectId,
    ) -> DaoResult<TunnelClient> {
        self.base
            .find_live_by_id_in_tenant(tenant_id, client_id)
            .await
    }

    /// The per-client lookup that also returns a TOMBSTONE — for the two
    /// readers whose job is the tombstone, and nothing else: the tunnel WS
    /// connect-time check and the 60 s revocation poll (`ws::tunnel`). Both
    /// read `deleted_at` to send the typed `rc:tunnel.revoked` the CLI logs
    /// and stops reconnecting on. With a LIVE lookup a removal would reach
    /// them as `Err(NotFound)` — the poll keeps the socket OPEN on an error
    /// (a Mongo blip must not revoke a healthy fleet), so a deleted client
    /// would never be kicked, and the connect path would drop the socket
    /// with no frame, leaving the CLI reconnecting forever against what
    /// reads as a network fault.
    ///
    /// Never for a write, never for an admin route — those are
    /// [`Self::find_live_in_tenant`].
    pub async fn find_any_in_tenant(
        &self,
        tenant_id: ObjectId,
        client_id: ObjectId,
    ) -> DaoResult<TunnelClient> {
        self.base.find_by_id_in_tenant(tenant_id, client_id).await
    }

    /// The filter every ADMIN-driven setter below writes through: this row,
    /// in this tenant, and LIVE (#1829). The routes look the client up live
    /// first; this closes the window between that read and the write, and
    /// holds for a caller that never did the read ("a gate applies at every
    /// entry point, or it is a courtesy"). A tombstone matches nothing, so the
    /// setter reports `false` and the removal time it carries stays as it was.
    ///
    /// The DEVICE-written fields (`mark_status`, `touch_heartbeat`) keep the
    /// plain by-id filter: their writer is the tunnel WS handler, which only
    /// runs after the connect-time check admitted a live row and whose poll
    /// re-reads the row before every heartbeat. `rehydrate` is the one write
    /// whose JOB is the tombstone (re-enrolment revives it) and keeps its own
    /// filter too.
    fn live_row(tenant_id: ObjectId, client_id: ObjectId) -> bson::Document {
        doc! { "_id": client_id, "tenant_id": tenant_id, "deleted_at": null }
    }

    pub async fn mark_status(&self, client_id: ObjectId, status: AgentStatus) -> DaoResult<bool> {
        self.base
            .update_by_id(
                client_id,
                doc! {
                    "$set": {
                        "status": bson::to_bson(&status).unwrap(),
                        "last_seen_at": DateTime::now(),
                    }
                },
            )
            .await
    }

    /// Per plan §"What changed from v1" #4 — the WS handler polls
    /// this row every 60 s and closes the connection if `status`
    /// leaves `{Online, Offline}` (e.g. an admin sets `Quarantined`).
    /// The 60 s lag is acceptable for v1; a Redis pub/sub fast-path
    /// is a 3-day add later if it bites in practice.
    pub async fn touch_heartbeat(&self, client_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_by_id(
                client_id,
                doc! { "$set": { "last_seen_at": DateTime::now() } },
            )
            .await
    }

    pub async fn rename(
        &self,
        tenant_id: ObjectId,
        client_id: ObjectId,
        name: &str,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, client_id),
                doc! { "$set": { "name": name, "name_admin_set": true } },
            )
            .await
    }

    /// Set/clear the friendly display label (display-only, like the agent's).
    pub async fn set_display_name(
        &self,
        tenant_id: ObjectId,
        client_id: ObjectId,
        display_name: Option<&str>,
    ) -> DaoResult<bool> {
        let update = match display_name {
            Some(v) => doc! { "$set": { "display_name": v } },
            None => doc! { "$unset": { "display_name": "" } },
        };
        self.base
            .update_one(Self::live_row(tenant_id, client_id), update)
            .await
    }

    /// Replace the client's whole tag list.
    pub async fn set_tags(
        &self,
        tenant_id: ObjectId,
        client_id: ObjectId,
        tags: &[String],
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, client_id),
                doc! { "$set": { "tags": tags.to_vec() } },
            )
            .await
    }

    pub async fn quarantine(&self, tenant_id: ObjectId, client_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, client_id),
                doc! { "$set": {
                    "status": bson::to_bson(&AgentStatus::Quarantined).unwrap(),
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// Tombstone a LIVE row. `deleted_at` is the removal time and is written
    /// once: a repeat on a tombstone matches nothing and reports `false`
    /// rather than re-stamping it. The route 404s a repeat `DELETE` before
    /// reaching here (#1829).
    /// FR-103: the same update advances `token_gen`, so every tunnel-client
    /// token minted before the removal is refused, including after the same
    /// laptop re-enrolls and revives the row (as `AgentDao::soft_delete`).
    pub async fn soft_delete(&self, tenant_id: ObjectId, client_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, client_id),
                doc! {
                    "$set": { "deleted_at": DateTime::now() },
                    "$inc": { "token_gen": 1 },
                },
            )
            .await
    }
}
