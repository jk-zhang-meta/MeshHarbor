// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, Document, doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_db::models::{
    Plan, RcFeaturePolicy, Role, Tenant, TenantMember, TenantSettings, role,
};

use super::base::{BaseDao, DaoError, DaoResult};

pub struct TenantDao {
    pub base: BaseDao<Tenant>,
    pub members: BaseDao<TenantMember>,
    pub roles: BaseDao<Role>,
    /// The durable record of what [`TenantDao::reconcile_managed_roles`]
    /// granted. Held here rather than reached for through a `Database` handle
    /// because `BaseDao` deliberately owns only its collection.
    pub reconcile_audit: BaseDao<role::RoleReconcileEvent>,
}

/// One `(role name, stored mask)` group [`TenantDao::reconcile_managed_roles`]
/// decided about. Returned rather than merely logged so the caller can report
/// what actually changed, and so the arithmetic is assertable without a
/// database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleReconcileGroup {
    pub name: String,
    pub stored: u64,
    /// The definition's mask, or `stored` for a managed row the table does
    /// not own (nothing is owed, and nothing is written).
    pub target: u64,
    /// `stored | target` — what the rows were set to. Equal to `stored` when
    /// nothing was owed.
    pub reconciled: u64,
    pub rows: u64,
}

impl RoleReconcileGroup {
    /// The bits this group gained. Zero for a group already at its
    /// definition, which is what every group reads on a second run.
    pub fn gained(&self) -> u64 {
        self.reconciled & !self.stored
    }
}

impl TenantDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, Tenant::COLLECTION),
            members: BaseDao::new(db, TenantMember::COLLECTION),
            roles: BaseDao::new(db, Role::COLLECTION),
            reconcile_audit: BaseDao::new(db, role::RoleReconcileEvent::COLLECTION),
        }
    }

    /// Phase 2 MagicDNS — set the tenant's overlay DNS domain + upstream
    /// nameservers (`None` domain disables MagicDNS). Returns the updated tenant.
    pub async fn set_magic_dns(
        &self,
        tenant_id: ObjectId,
        domain: Option<String>,
        nameservers: Vec<String>,
    ) -> DaoResult<Tenant> {
        self.base
            .update_by_id(
                tenant_id,
                doc! { "$set": {
                    "settings.magic_dns_domain": domain,
                    "settings.magic_dns_nameservers": nameservers,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    /// Archive (or restore) an organization.
    ///
    /// `is_archived` has existed on the model since the beginning and was
    /// never read by anything, so "retire an organization" had no meaning
    /// and a throwaway org was permanent (docs/multi-org.md §12). It means
    /// this now: **an archived org stops acting and keeps everything it
    /// knows.** No enrollment, no new remote-control session, no devices in
    /// its mesh, hidden from the switcher — and every room, message, file,
    /// member and audit row still there, so restoring it is one call.
    ///
    /// Deliberately NOT a delete. An org's data is entangled with people who
    /// belong to other orgs, and there is no undo for erasure; if true
    /// erasure is ever needed it belongs in a separate, explicitly
    /// destructive job layered on top of this.
    pub async fn set_archived(&self, tenant_id: ObjectId, archived: bool) -> DaoResult<Tenant> {
        self.base
            .update_by_id(
                tenant_id,
                doc! { "$set": {
                    "is_archived": archived,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    /// Fleet RPC gate 1 — the org-wide kill-switch. Off by default on every
    /// row; turning it on still leaves each device closed until its own
    /// `ExecPolicy` is enabled.
    pub async fn set_remote_exec_enabled(
        &self,
        tenant_id: ObjectId,
        enabled: bool,
    ) -> DaoResult<Tenant> {
        self.base
            .update_by_id(
                tenant_id,
                doc! { "$set": {
                    "settings.remote_exec_enabled": enabled,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    /// FR-94 — refuse Windows commands that could not run as SYSTEM, rather
    /// than run them as the signed-in user. A separate field written only
    /// when the caller says something about it (see the route), so a body
    /// that names only the kill-switch leaves this alone.
    pub async fn set_exec_require_system(
        &self,
        tenant_id: ObjectId,
        required: bool,
    ) -> DaoResult<Tenant> {
        self.base
            .update_by_id(
                tenant_id,
                doc! { "$set": {
                    "settings.exec_require_system": required,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    /// FR-92 — the org's keep-busy settings: the DENY (`false` = allowed, the
    /// default) and, since P8, the default pattern. Each field is written only when
    /// the caller SAID something about it: `None` leaves the stored value
    /// alone, so the pre-P8 body `{keep_busy_denied}` still changes nothing
    /// else. For the default pattern, `Some(None)` clears it back to the
    /// product default. The pattern is validated by the route, not here.
    pub async fn set_keep_busy_settings(
        &self,
        tenant_id: ObjectId,
        denied: Option<bool>,
        default_pattern: Option<Option<String>>,
    ) -> DaoResult<Tenant> {
        let mut set = doc! { "updated_at": DateTime::now() };
        if let Some(denied) = denied {
            set.insert("settings.keep_busy_denied", denied);
        }
        if let Some(pattern) = default_pattern {
            // A stored `null` deserialises to `None` like an absent field,
            // so clearing writes null rather than needing a second operator.
            set.insert("settings.keep_busy_default_pattern", pattern);
        }
        self.base
            .update_by_id(tenant_id, doc! { "$set": set })
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    /// FR-101 P4b — set or clear the org's session limits: the maximum length
    /// and (P4b-2) the idle limit. For each, the outer `None` leaves it as it
    /// is, `Some(None)` removes the field (no limit) rather than storing a
    /// `null` an older build would also have to read, and `Some(Some(secs))`
    /// sets it. Each is its own dotted path, so two admins changing different
    /// limits cannot lose each other's change. The route validates the range.
    pub async fn set_rc_session_limits(
        &self,
        tenant_id: ObjectId,
        max_secs: Option<Option<u32>>,
        idle_secs: Option<Option<u32>>,
    ) -> DaoResult<Tenant> {
        let mut set = doc! { "updated_at": DateTime::now() };
        let mut unset = Document::new();
        for (path, value) in [
            ("settings.rc_limits.max_secs", max_secs),
            ("settings.rc_limits.idle_secs", idle_secs),
        ] {
            match value {
                Some(Some(secs)) => {
                    set.insert(path, i64::from(secs));
                }
                Some(None) => {
                    unset.insert(path, "");
                }
                None => {}
            }
        }
        let mut update = doc! { "$set": set };
        if !unset.is_empty() {
            update.insert("$unset", unset);
        }
        self.base.update_by_id(tenant_id, update).await?;
        self.base.find_by_id(tenant_id).await
    }

    /// FR-101 P2 — set features of the org's remote-desktop session policy.
    /// Only the `Some` ones are written, each as its own dotted `$set`, so two
    /// admins changing different features cannot lose each other's change,
    /// and a feature nobody named keeps its value. The route validates.
    pub async fn set_rc_session_policy(
        &self,
        tenant_id: ObjectId,
        clipboard: Option<RcFeaturePolicy>,
        files: Option<RcFeaturePolicy>,
        audio: Option<RcFeaturePolicy>,
    ) -> DaoResult<Tenant> {
        let mut set = doc! { "updated_at": DateTime::now() };
        for (field, value) in [("clipboard", clipboard), ("files", files), ("audio", audio)] {
            if let Some(v) = value {
                set.insert(format!("settings.rc_session.{field}"), bson::to_bson(&v)?);
            }
        }
        self.base
            .update_by_id(tenant_id, doc! { "$set": set })
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    /// Roomler SSH's org kill-switch (gate 1). A separate switch from
    /// [`Self::set_remote_exec_enabled`] because they are separate grants.
    pub async fn set_remote_ssh_enabled(
        &self,
        tenant_id: ObjectId,
        enabled: bool,
    ) -> DaoResult<Tenant> {
        self.base
            .update_by_id(
                tenant_id,
                doc! { "$set": {
                    "settings.remote_ssh_enabled": enabled,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    /// FR-51 — the ephemeral-key org switch (gate 1 of the key path). Checked
    /// on every key USE as well as at mint, so flipping it off is an org-wide
    /// revocation of all outstanding keys, immediately, burning nothing.
    pub async fn set_ephemeral_keys_enabled(
        &self,
        tenant_id: ObjectId,
        enabled: bool,
    ) -> DaoResult<Tenant> {
        self.base
            .update_by_id(
                tenant_id,
                doc! { "$set": {
                    "settings.ephemeral_keys_enabled": enabled,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(tenant_id).await
    }

    pub async fn create(
        &self,
        name: String,
        slug: String,
        owner_id: ObjectId,
    ) -> DaoResult<Tenant> {
        let now = DateTime::now();
        let tenant = Tenant {
            id: None,
            name,
            slug,
            description: None,
            icon: None,
            owner_id,
            plan: Plan::Free,
            features: Vec::new(),
            settings: TenantSettings::default(),
            billing: None,
            integrations: None,
            is_archived: false,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let tenant_id = self.base.insert_one(&tenant).await?;

        // Create default roles
        self.create_default_roles(tenant_id).await?;

        // Add owner as first member
        let owner_role = self.get_role_by_name(tenant_id, "owner").await?;
        self.add_member(tenant_id, owner_id, vec![owner_role.id.unwrap()], None)
            .await?;

        self.base.find_by_id(tenant_id).await
    }

    /// Seed the system-managed roles for a brand-new tenant.
    ///
    /// FR-82 — built from `MANAGED_ROLES`, which is now the only place these
    /// masks are written down. The five `Role` literals that used to live
    /// here were one of two divergent copies, and neither of them was ever
    /// re-applied to a tenant that already existed.
    async fn create_default_roles(&self, tenant_id: ObjectId) -> DaoResult<()> {
        let now = DateTime::now();
        for def in role::MANAGED_ROLES {
            self.roles
                .insert_one(&Role {
                    id: None,
                    tenant_id,
                    name: def.name.to_string(),
                    description: Some(def.description.to_string()),
                    color: def.color,
                    position: def.position,
                    permissions: def.permissions,
                    is_default: def.is_default,
                    is_managed: true,
                    is_mentionable: def.is_mentionable,
                    is_hoisted: def.is_hoisted,
                    created_at: now,
                    updated_at: now,
                })
                .await?;
        }
        Ok(())
    }

    pub async fn get_role_by_name(&self, tenant_id: ObjectId, name: &str) -> DaoResult<Role> {
        self.roles
            .find_one(doc! { "tenant_id": tenant_id, "name": name })
            .await?
            .ok_or(DaoError::NotFound)
    }

    /// Bring every system-managed role in EVERY tenant up to its definition
    /// in `MANAGED_ROLES` (FR-82).
    ///
    /// ⚠️ **Additive: `new = stored | definition`, never a replace.** A
    /// managed role's mask is editable through `PUT …/role/{id}` (only
    /// *deletion* is refused), so an org may legitimately have added a bit to
    /// one. Overwriting would silently revoke that; OR-ing cannot. The cost
    /// of the choice, stated so nobody has to rediscover it: a bit REMOVED
    /// from a definition — a tightening — does not propagate, and needs its
    /// own migration that says out loud whose permissions it is taking away.
    ///
    /// ⚠️ Groups by `(name, permissions)` and issues one `update_many` per
    /// group, so the whole deployment costs as many writes as it has distinct
    /// drift strata (measured: 12 across 72 orgs / 360 managed roles), not
    /// one per role. Matching on the exact stored value also makes it a
    /// no-op on a second run and safe against a concurrent editor: a role
    /// changed underneath us simply falls out of its group's filter.
    ///
    /// A managed row whose name is not in the table is left alone and
    /// reported — drift that is visible beats drift that is corrected by
    /// guesswork.
    pub async fn reconcile_managed_roles(&self) -> DaoResult<Vec<RoleReconcileGroup>> {
        use futures::TryStreamExt;

        let mut cursor = self
            .roles
            .collection()
            .aggregate(vec![
                doc! { "$match": { "is_managed": true } },
                doc! { "$group": {
                    "_id": { "name": "$name", "permissions": "$permissions" },
                    "rows": { "$sum": 1 },
                } },
            ])
            .await?;

        // Drain the cursor BEFORE writing anything: the updates below target
        // the collection this aggregation reads, and "iterate and mutate the
        // same collection" is a shape worth not having, whatever the server
        // happens to guarantee about a `$group` cursor's batches.
        let mut strata: Vec<(String, u64, u64)> = Vec::new();
        while let Some(doc) = cursor.try_next().await? {
            let Ok(id) = doc.get_document("_id") else {
                continue;
            };
            let Ok(name) = id.get_str("name") else {
                continue;
            };
            // `permissions` is written as i64 (see `RoleDao::update`), but a
            // row seeded before that cast could be an i32 — read both rather
            // than skipping a whole stratum on a type mismatch.
            let stored = id
                .get_i64("permissions")
                .ok()
                .or_else(|| id.get_i32("permissions").ok().map(i64::from))
                .unwrap_or(0)
                .max(0) as u64;
            // `$sum: 1` is an Int32 today; read Int64 too rather than
            // reporting `rows = 0` for a real group if that ever changes.
            let rows = doc
                .get_i32("rows")
                .map(i64::from)
                .or_else(|_| doc.get_i64("rows"))
                .unwrap_or(0)
                .max(0) as u64;
            strata.push((name.to_string(), stored, rows));
        }

        let mut groups = Vec::with_capacity(strata.len());
        for (name, stored, rows) in strata {
            let Some(def) = role::ManagedRole::by_name(&name) else {
                // Not ours to define. Report it; do not touch it.
                groups.push(RoleReconcileGroup {
                    name,
                    stored,
                    target: stored,
                    reconciled: stored,
                    rows,
                });
                continue;
            };

            let reconciled = stored | def.permissions;
            if reconciled != stored {
                self.roles
                    .collection()
                    .update_many(
                        doc! { "is_managed": true, "name": &name, "permissions": stored as i64 },
                        doc! { "$set": {
                            "permissions": reconciled as i64,
                            "updated_at": DateTime::now(),
                        } },
                    )
                    .await?;
                // The durable record, written HERE rather than at the call
                // site so it cannot drift from the write it describes: the
                // two are one statement apart and share `stored`/`reconciled`
                // directly. FR-82 shipped with only an INFO line, and the
                // measurement afterwards was that it survived ~10 minutes —
                // `kubectl logs` serves the current container, the pod rolled,
                // and a one-way grant across 63 orgs had no record left.
                //
                // ⚠️ Best-effort, exactly like `config_audit`: a failed insert
                // is logged and the reconcile continues. The roles are already
                // correct at this point, and refusing to finish the migration
                // because its receipt could not be filed would trade a real
                // outage for a bookkeeping one.
                let event = role::RoleReconcileEvent {
                    id: None,
                    at: DateTime::now(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    role: name.clone(),
                    rows: rows as i64,
                    stored: stored as i64,
                    granted: reconciled as i64,
                    gained: (reconciled & !stored) as i64,
                    gained_names: role::permissions::names(reconciled & !stored),
                };
                if let Err(e) = self.reconcile_audit.insert_one(&event).await {
                    tracing::warn!(
                        role = %name,
                        error = %e,
                        "managed-role reconcile: the roles were updated but the audit row \
                         could not be written — the grant is applied and unrecorded"
                    );
                }
            }
            groups.push(RoleReconcileGroup {
                name,
                stored,
                target: def.permissions,
                reconciled,
                rows,
            });
        }

        groups.sort_by(|a, b| a.name.cmp(&b.name).then(a.stored.cmp(&b.stored)));
        Ok(groups)
    }

    pub async fn add_member(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        role_ids: Vec<ObjectId>,
        invited_by: Option<ObjectId>,
    ) -> DaoResult<TenantMember> {
        let now = DateTime::now();
        let member = TenantMember {
            id: None,
            tenant_id,
            user_id,
            nickname: None,
            role_ids,
            joined_at: now,
            is_pending: false,
            is_muted: false,
            notification_override: None,
            invited_by,
            last_seen_at: None,
            created_at: now,
            updated_at: now,
        };

        let id = self.members.insert_one(&member).await?;
        self.members.find_by_id(id).await
    }

    pub async fn find_by_slug(&self, slug: &str) -> DaoResult<Tenant> {
        self.base
            .find_one(doc! { "slug": slug, "deleted_at": null })
            .await?
            .ok_or(DaoError::NotFound)
    }

    pub async fn find_user_tenants(&self, user_id: ObjectId) -> DaoResult<Vec<Tenant>> {
        let memberships = self
            .members
            .find_many(doc! { "user_id": user_id }, None)
            .await?;

        let tenant_ids: Vec<ObjectId> = memberships.iter().map(|m| m.tenant_id).collect();

        if tenant_ids.is_empty() {
            return Ok(Vec::new());
        }

        self.base
            .find_many(
                doc! { "_id": { "$in": tenant_ids }, "deleted_at": null },
                Some(doc! { "name": 1 }),
            )
            .await
    }

    /// FR-32 — members in the tenant, for the plan `max_members` gate.
    ///
    /// `tenant_members` rows are hard-deleted by [`Self::remove_member`], so
    /// unlike the agent and tunnel-client counts there is no tombstone to
    /// exclude. Pending members ARE counted: an unaccepted invite already holds
    /// the seat, and not counting them would let a tenant sit permanently over
    /// its cap by never having invitees accept.
    pub async fn count_members(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.members.count(doc! { "tenant_id": tenant_id }).await
    }

    pub async fn is_member(&self, tenant_id: ObjectId, user_id: ObjectId) -> DaoResult<bool> {
        let count = self
            .members
            .count(doc! { "tenant_id": tenant_id, "user_id": user_id })
            .await?;
        Ok(count > 0)
    }

    /// FR-11: drop a user's membership row. Hard delete — `TenantMember` has
    /// no `deleted_at`, and a removed member re-added later is a NEW
    /// membership (fresh joined_at/roles), not a revival. Returns whether a
    /// row was actually removed. Owner/permission policy lives in the route.
    pub async fn remove_member(&self, tenant_id: ObjectId, user_id: ObjectId) -> DaoResult<bool> {
        let n = self
            .members
            .hard_delete(doc! { "tenant_id": tenant_id, "user_id": user_id })
            .await?;
        Ok(n > 0)
    }

    pub async fn assign_role(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        role_id: ObjectId,
    ) -> DaoResult<bool> {
        self.members
            .update_one(
                doc! { "tenant_id": tenant_id, "user_id": user_id },
                doc! { "$addToSet": { "role_ids": role_id }, "$set": { "updated_at": DateTime::now() } },
            )
            .await
    }

    pub async fn remove_role(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
        role_id: ObjectId,
    ) -> DaoResult<bool> {
        self.members
            .update_one(
                doc! { "tenant_id": tenant_id, "user_id": user_id },
                doc! { "$pull": { "role_ids": role_id }, "$set": { "updated_at": DateTime::now() } },
            )
            .await
    }

    pub async fn get_member_permissions(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
    ) -> DaoResult<u64> {
        let member = self
            .members
            .find_one(doc! { "tenant_id": tenant_id, "user_id": user_id })
            .await?
            .ok_or(DaoError::NotAMember)?;

        let roles = self
            .roles
            .find_many(doc! { "_id": { "$in": &member.role_ids } }, None)
            .await?;

        let combined = roles.iter().fold(0u64, |acc, r| acc | r.permissions);
        Ok(combined)
    }

    /// The role ids a member holds in a tenant (empty if not a member). Used by
    /// the remote-control session gate to test `access_policy.allowed_role_ids`
    /// overlap without re-deriving the combined permission bitfield.
    pub async fn member_role_ids(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
    ) -> DaoResult<Vec<ObjectId>> {
        Ok(self
            .members
            .find_one(doc! { "tenant_id": tenant_id, "user_id": user_id })
            .await?
            .map(|m| m.role_ids)
            .unwrap_or_default())
    }

    /// P4 — every member's user id for one tenant, in one query. The
    /// `device:presence` fan-out recipient set (device listing visibility is
    /// member-gated, so presence events follow the same audience). Callers
    /// cache this briefly — a fleet reconnect storm must not turn into a
    /// per-event membership scan.
    pub async fn member_user_ids(&self, tenant_id: ObjectId) -> DaoResult<Vec<ObjectId>> {
        Ok(self
            .members
            .find_many(doc! { "tenant_id": tenant_id }, None)
            .await?
            .into_iter()
            .map(|m| m.user_id)
            .collect())
    }

    /// FR-88 P1a — `(user_id, tenant_id)` for every membership any of
    /// `user_ids` holds, in one query. The activation view's join: a sign-up
    /// is "activated" through any org the person belongs to (the one their
    /// registration created, or one they were invited into).
    pub async fn memberships_for_users(
        &self,
        user_ids: &[ObjectId],
    ) -> DaoResult<Vec<(ObjectId, ObjectId)>> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .members
            .find_many(doc! { "user_id": { "$in": user_ids } }, None)
            .await?
            .into_iter()
            .map(|m| (m.user_id, m.tenant_id))
            .collect())
    }
}
