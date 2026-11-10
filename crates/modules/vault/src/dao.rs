// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The vault's collections: secrets, versions and audit (P3-1), roles and
//! policies (P3-2).
//!
//! ⚠️ A metadata read never loads a sealed value: the version listing
//! projects `ciphertext`, `nonce` and `dek_wrapped` away, so describing a
//! secret cannot leak what it describes even through a log of the row.

use bson::{DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_services::dao::base::{BaseDao, DaoError, DaoResult, escape_regex};
use mongodb::{Database, options::ReturnDocument};
use serde::{Deserialize, Serialize};

use crate::model::{
    VaultActivity, VaultApproval, VaultAuditEvent, VaultLease, VaultPolicy, VaultRole, VaultSecret,
    VaultVersion, approval_status,
};

/// The most roles, and the most policies, an organization keeps.
pub const MAX_ROLES: i64 = 200;
pub const MAX_POLICIES: i64 = 500;

/// The most secrets one listing answers with.
pub const MAX_LIST: i64 = 1000;
/// The most versions one verify opens.
pub const MAX_VERIFY: i64 = 10_000;

pub struct VaultSecretDao {
    pub base: BaseDao<VaultSecret>,
}

impl VaultSecretDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultSecret::COLLECTION),
        }
    }

    /// A new secret. `DuplicateKey` when a live secret holds its path.
    pub async fn create(&self, secret: &VaultSecret) -> DaoResult<ObjectId> {
        self.base.insert_one(secret).await
    }

    /// The organization's live secrets, by path; under `prefix` when one is
    /// given (a folder: `staging/` lists what is in it).
    pub async fn list_live(
        &self,
        tenant_id: ObjectId,
        prefix: Option<&str>,
    ) -> DaoResult<Vec<VaultSecret>> {
        let mut filter = doc! { "tenant_id": tenant_id, "deleted_at": null };
        if let Some(p) = prefix.filter(|p| !p.is_empty()) {
            filter.insert("path", doc! { "$regex": format!("^{}", escape_regex(p)) });
        }
        let mut cursor = self
            .base
            .collection()
            .find(filter)
            .sort(doc! { "path": 1 })
            .limit(MAX_LIST)
            .await?;
        let mut out = Vec::new();
        while let Some(s) = cursor.try_next().await? {
            out.push(s);
        }
        Ok(out)
    }

    /// A live secret of this organization: `NotFound` for a tombstone, a
    /// foreign id or a bogus one alike.
    pub async fn get_live(&self, tenant_id: ObjectId, id: ObjectId) -> DaoResult<VaultSecret> {
        self.base.find_live_by_id_in_tenant(tenant_id, id).await
    }

    /// P3-3b — the organization's live secret at `path`, as a lease names it.
    pub async fn find_live_by_path(
        &self,
        tenant_id: ObjectId,
        path: &str,
    ) -> DaoResult<Option<VaultSecret>> {
        self.base
            .find_one(doc! { "tenant_id": tenant_id, "path": path, "deleted_at": null })
            .await
    }

    /// Set metadata on a live secret. `false` when there is none.
    pub async fn update_live(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
        mut set: Document,
    ) -> DaoResult<bool> {
        set.insert("updated_at", DateTime::now());
        let r = self
            .base
            .collection()
            .update_one(
                doc! { "_id": id, "tenant_id": tenant_id, "deleted_at": null },
                doc! { "$set": set },
            )
            .await?;
        Ok(r.matched_count > 0)
    }

    /// P3-3c — a secret of this organization by id, tombstoned or not: what
    /// tells a revocation that its secret was deleted rather than disabled.
    pub async fn find_any(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
    ) -> DaoResult<Option<VaultSecret>> {
        Ok(self
            .base
            .collection()
            .find_one(doc! { "_id": id, "tenant_id": tenant_id })
            .await?)
    }

    /// Tombstone a live secret. A compare-and-set: `true` only for the call
    /// that moved it from live — two concurrent deletes cannot both act on
    /// one secret.
    pub async fn tombstone(&self, tenant_id: ObjectId, id: ObjectId) -> DaoResult<bool> {
        let now = DateTime::now();
        let r = self
            .base
            .collection()
            .update_one(
                doc! { "_id": id, "tenant_id": tenant_id, "deleted_at": null },
                doc! { "$set": { "deleted_at": now, "updated_at": now } },
            )
            .await?;
        Ok(r.modified_count > 0)
    }

    /// The next version number of `field` on a live secret, handed out by
    /// an `$inc` — two writers never get one number. `None` when the secret
    /// is not live. `field` must be checked ([`crate::rrn::check_field`]):
    /// it is a key in the document.
    pub async fn next_version(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
        field: &str,
    ) -> DaoResult<Option<i64>> {
        let seq = format!("fields.{field}.seq");
        let after = self
            .base
            .collection()
            .find_one_and_update(
                doc! { "_id": id, "tenant_id": tenant_id, "deleted_at": null },
                doc! { "$inc": { seq.as_str(): 1_i64 } },
            )
            .return_document(ReturnDocument::After)
            .await?;
        Ok(after.and_then(|s| s.fields.get(field).map(|f| f.seq)))
    }

    /// Point `field` at version `n` once its row is stored — `$max`, so a
    /// slower writer of an older number never moves it back. `false` when
    /// the secret stopped being live meanwhile.
    pub async fn mark_current(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
        field: &str,
        n: i64,
    ) -> DaoResult<bool> {
        let now = DateTime::now();
        let r = self
            .base
            .collection()
            .update_one(
                doc! { "_id": id, "tenant_id": tenant_id, "deleted_at": null },
                doc! {
                    "$max": { format!("fields.{field}.current"): n },
                    "$set": { format!("fields.{field}.updated_at"): now, "updated_at": now },
                },
            )
            .await?;
        Ok(r.matched_count > 0)
    }

    pub async fn count_live(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base
            .count(doc! { "tenant_id": tenant_id, "deleted_at": null })
            .await
    }
}

/// A version as a metadata read sees it: everything but the sealed bytes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionMeta {
    pub field: String,
    pub n: i64,
    pub kek: String,
    pub created_by: ObjectId,
    pub created_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,
}

pub struct VaultVersionDao {
    pub base: BaseDao<VaultVersion>,
}

impl VaultVersionDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultVersion::COLLECTION),
        }
    }

    pub async fn insert(&self, v: &VaultVersion) -> DaoResult<ObjectId> {
        self.base.insert_one(v).await
    }

    /// P3-3b — one version, sealed bytes and all: what a lease opens.
    pub async fn get(
        &self,
        secret_id: ObjectId,
        field: &str,
        n: i64,
    ) -> DaoResult<Option<VaultVersion>> {
        self.base
            .find_one(doc! { "secret_id": secret_id, "field": field, "n": n })
            .await
    }

    /// A secret's versions, newest first per field — never their bytes.
    pub async fn list_meta(&self, secret_id: ObjectId) -> DaoResult<Vec<VersionMeta>> {
        let mut cursor = self
            .base
            .collection()
            .clone_with_type::<VersionMeta>()
            .find(doc! { "secret_id": secret_id })
            .projection(doc! { "ciphertext": 0, "nonce": 0, "dek_wrapped": 0 })
            .sort(doc! { "field": 1, "n": -1 })
            .await?;
        let mut out = Vec::new();
        while let Some(v) = cursor.try_next().await? {
            out.push(v);
        }
        Ok(out)
    }

    /// Every version of a secret, gone: what deleting it destroys.
    pub async fn delete_for_secret(&self, secret_id: ObjectId) -> DaoResult<u64> {
        self.base.hard_delete(doc! { "secret_id": secret_id }).await
    }

    pub async fn delete_one(&self, id: ObjectId) -> DaoResult<u64> {
        self.base.hard_delete(doc! { "_id": id }).await
    }

    /// Versions of `field` below `keep_from`, gone: a field keeps its last
    /// few, and an old value is no less sensitive for being old.
    pub async fn prune(&self, secret_id: ObjectId, field: &str, keep_from: i64) -> DaoResult<u64> {
        self.base
            .hard_delete(doc! { "secret_id": secret_id, "field": field, "n": { "$lt": keep_from } })
            .await
    }

    pub async fn count(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base.count(doc! { "tenant_id": tenant_id }).await
    }

    /// Versions whose data key was wrapped to another KEK than `recipient`.
    pub async fn count_other_kek(&self, tenant_id: ObjectId, recipient: &str) -> DaoResult<u64> {
        self.base
            .count(doc! { "tenant_id": tenant_id, "kek": { "$ne": recipient } })
            .await
    }

    /// The organization's versions, sealed, for a verify: at most
    /// [`MAX_VERIFY`].
    pub async fn scan(&self, tenant_id: ObjectId) -> DaoResult<Vec<VaultVersion>> {
        let mut cursor = self
            .base
            .collection()
            .find(doc! { "tenant_id": tenant_id })
            .sort(doc! { "_id": 1 })
            .limit(MAX_VERIFY)
            .await?;
        let mut out = Vec::new();
        while let Some(v) = cursor.try_next().await? {
            out.push(v);
        }
        Ok(out)
    }
}

pub struct VaultAuditDao {
    pub base: BaseDao<VaultAuditEvent>,
}

impl VaultAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultAuditEvent::COLLECTION),
        }
    }

    pub async fn record(&self, event: &VaultAuditEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(event).await
    }

    /// P3-2b — the Cedar decisions since `since` (the rows that carry the
    /// request they decided), newest first, at most `limit`: what a replay
    /// decides again.
    pub async fn decisions_since(
        &self,
        tenant_id: ObjectId,
        since: DateTime,
        limit: i64,
    ) -> DaoResult<Vec<VaultAuditEvent>> {
        let mut cursor = self
            .base
            .collection()
            .find(doc! {
                "tenant_id": tenant_id,
                "at": { "$gte": since },
                "request": { "$exists": true },
            })
            .sort(doc! { "at": -1, "_id": -1 })
            .limit(limit)
            .await?;
        let mut out = Vec::new();
        while let Some(e) = cursor.try_next().await? {
            out.push(e);
        }
        Ok(out)
    }

    /// The organization's decisions, newest first, before `before` when
    /// given (the next page).
    pub async fn recent(
        &self,
        tenant_id: ObjectId,
        before: Option<DateTime>,
        limit: i64,
    ) -> DaoResult<Vec<VaultAuditEvent>> {
        let mut filter = doc! { "tenant_id": tenant_id };
        if let Some(b) = before {
            filter.insert("at", doc! { "$lt": b });
        }
        let mut cursor = self
            .base
            .collection()
            .find(filter)
            .sort(doc! { "at": -1, "_id": -1 })
            .limit(limit)
            .await?;
        let mut out = Vec::new();
        while let Some(e) = cursor.try_next().await? {
            out.push(e);
        }
        Ok(out)
    }
}

/// `DuplicateKey` on the path index, told apart from any other collision.
pub fn is_path_taken(e: &DaoError) -> bool {
    matches!(e, DaoError::DuplicateKey(msg)
        if meshharbor_services::dao::base::duplicate_key_is_on(msg, "path"))
}

/// `DuplicateKey` on a `name` index (roles, policies).
pub fn is_name_taken(e: &DaoError) -> bool {
    matches!(e, DaoError::DuplicateKey(msg)
        if meshharbor_services::dao::base::duplicate_key_is_on(msg, "name"))
}

/// Every live row of `T` in an organization, sorted, at most `limit`.
async fn live_rows<T>(
    base: &BaseDao<T>,
    tenant_id: ObjectId,
    sort: Document,
    limit: i64,
) -> DaoResult<Vec<T>>
where
    T: Serialize + for<'de> Deserialize<'de> + Unpin + Send + Sync,
{
    let mut cursor = base
        .collection()
        .find(doc! { "tenant_id": tenant_id, "deleted_at": null })
        .sort(sort)
        .limit(limit)
        .await?;
    let mut out = Vec::new();
    while let Some(r) = cursor.try_next().await? {
        out.push(r);
    }
    Ok(out)
}

/// Tombstone a live row: a compare-and-set, `true` only for the call that
/// moved it from live.
async fn tombstone_row<T>(base: &BaseDao<T>, filter: Document) -> DaoResult<bool>
where
    T: Serialize + for<'de> Deserialize<'de> + Unpin + Send + Sync,
{
    let mut filter = filter;
    filter.insert("deleted_at", bson::Bson::Null);
    let r = base
        .collection()
        .update_one(filter, doc! { "$set": { "deleted_at": DateTime::now() } })
        .await?;
    Ok(r.modified_count > 0)
}

pub struct VaultRoleDao {
    pub base: BaseDao<VaultRole>,
}

impl VaultRoleDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultRole::COLLECTION),
        }
    }

    /// A new role. `DuplicateKey` on `name` when a live role holds it.
    pub async fn create(&self, role: &VaultRole) -> DaoResult<ObjectId> {
        self.base.insert_one(role).await
    }

    pub async fn list_live(&self, tenant_id: ObjectId) -> DaoResult<Vec<VaultRole>> {
        live_rows(&self.base, tenant_id, doc! { "name": 1 }, MAX_ROLES).await
    }

    pub async fn count_live(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base
            .count(doc! { "tenant_id": tenant_id, "deleted_at": null })
            .await
    }

    pub async fn tombstone(&self, tenant_id: ObjectId, name: &str) -> DaoResult<bool> {
        tombstone_row(&self.base, doc! { "tenant_id": tenant_id, "name": name }).await
    }
}

pub struct VaultPolicyDao {
    pub base: BaseDao<VaultPolicy>,
}

impl VaultPolicyDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultPolicy::COLLECTION),
        }
    }

    /// A new policy. `DuplicateKey` on `name` when a live policy holds it.
    pub async fn create(&self, policy: &VaultPolicy) -> DaoResult<ObjectId> {
        self.base.insert_one(policy).await
    }

    /// The organization's live policies, oldest first.
    pub async fn list_live(&self, tenant_id: ObjectId) -> DaoResult<Vec<VaultPolicy>> {
        live_rows(
            &self.base,
            tenant_id,
            doc! { "created_at": 1, "_id": 1 },
            MAX_POLICIES,
        )
        .await
    }

    pub async fn count_live(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base
            .count(doc! { "tenant_id": tenant_id, "deleted_at": null })
            .await
    }

    pub async fn get_live(&self, tenant_id: ObjectId, id: ObjectId) -> DaoResult<VaultPolicy> {
        self.base.find_live_by_id_in_tenant(tenant_id, id).await
    }

    /// Replace a live policy's name, description and text — only from the
    /// revision the writer read. `None` when that revision is not the live
    /// one any more (or the policy is gone); the new row otherwise.
    pub async fn replace(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
        rev: i64,
        set: Document,
    ) -> DaoResult<Option<VaultPolicy>> {
        let mut set = set;
        set.insert("updated_at", DateTime::now());
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                doc! { "_id": id, "tenant_id": tenant_id, "deleted_at": null, "rev": rev },
                doc! { "$set": set, "$inc": { "rev": 1_i64 } },
            )
            .return_document(ReturnDocument::After)
            .await?)
    }

    pub async fn tombstone(&self, tenant_id: ObjectId, id: ObjectId) -> DaoResult<bool> {
        tombstone_row(&self.base, doc! { "_id": id, "tenant_id": tenant_id }).await
    }
}

/// P3-3b — `vault_leases`: what was released to which session.
pub struct VaultLeaseDao {
    pub base: BaseDao<VaultLease>,
}

impl VaultLeaseDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultLease::COLLECTION),
        }
    }

    /// Record a lease; its id is the one the device is told.
    pub async fn insert(&self, lease: &VaultLease) -> DaoResult<ObjectId> {
        self.base.insert_one(lease).await
    }

    /// P3-3c — a device's leases that have not expired, revoked or not: what
    /// its pod checks, and what each of its hellos is told again.
    pub async fn unexpired_for_device(
        &self,
        device_id: ObjectId,
        now: DateTime,
    ) -> DaoResult<Vec<VaultLease>> {
        self.collect(doc! { "device_id": device_id, "expires_at": { "$gt": now } })
            .await
    }

    /// P3-3c — a secret's live leases (one field's, when given) that have not
    /// expired: what a change to the secret takes back.
    pub async fn live_for_secret(
        &self,
        secret_id: ObjectId,
        field: Option<&str>,
        now: DateTime,
    ) -> DaoResult<Vec<VaultLease>> {
        let mut filter =
            doc! { "secret_id": secret_id, "expires_at": { "$gt": now }, "revoked_at": null };
        if let Some(f) = field {
            filter.insert("field", f);
        }
        self.collect(filter).await
    }

    /// P3-3c — take a lease back. A compare-and-set on `revoked_at`: of two
    /// pods taking one lease back, one acts and records it.
    pub async fn revoke(&self, id: ObjectId, why: &str, at: DateTime) -> DaoResult<bool> {
        let r = self
            .base
            .collection()
            .update_one(
                doc! { "_id": id, "revoked_at": null },
                doc! { "$set": { "revoked_at": at, "revoked_why": why } },
            )
            .await?;
        Ok(r.modified_count > 0)
    }

    /// P3-4d — whether every one of `ids` was released to this device, for
    /// this session in this organization, in `mode` toward `audience`: the
    /// one test a device's report of using them must pass. P3-6b-2b — or in
    /// `short-lived`, which serves any use: its audience is where its
    /// credential was minted, never the use's target.
    pub async fn all_released_for(
        &self,
        ids: &[ObjectId],
        tenant_id: ObjectId,
        device_id: ObjectId,
        session_id: ObjectId,
        mode: &str,
        audience: &str,
    ) -> DaoResult<bool> {
        let n = self
            .base
            .collection()
            .count_documents(doc! {
                "_id": { "$in": ids },
                "tenant_id": tenant_id,
                "device_id": device_id,
                "session_id": session_id,
                "$or": [
                    { "mode": mode, "audience": audience },
                    { "mode": "short-lived" },
                ],
            })
            .await?;
        Ok(usize::try_from(n).is_ok_and(|n| n == ids.len()))
    }

    async fn collect(&self, filter: Document) -> DaoResult<Vec<VaultLease>> {
        let mut cursor = self.base.collection().find(filter).await?;
        let mut out = Vec::new();
        while let Some(l) = cursor.try_next().await? {
            out.push(l);
        }
        Ok(out)
    }
}

/// FR-90 P3-4d — what devices report doing with their leases: claims, kept
/// apart from the vault's decisions.
pub struct VaultActivityDao {
    pub base: BaseDao<VaultActivity>,
}

impl VaultActivityDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultActivity::COLLECTION),
        }
    }

    pub async fn insert(&self, row: &VaultActivity) -> DaoResult<ObjectId> {
        self.base.insert_one(row).await
    }

    /// The organization's reports, newest first, before `before` when given
    /// (the next page); one session's, or those naming one lease, when
    /// asked.
    pub async fn recent(
        &self,
        tenant_id: ObjectId,
        session_id: Option<ObjectId>,
        lease_id: Option<ObjectId>,
        before: Option<DateTime>,
        limit: i64,
    ) -> DaoResult<Vec<VaultActivity>> {
        let mut filter = doc! { "tenant_id": tenant_id };
        if let Some(s) = session_id {
            filter.insert("session_id", s);
        }
        if let Some(l) = lease_id {
            filter.insert("lease_ids", l);
        }
        if let Some(b) = before {
            filter.insert("at", doc! { "$lt": b });
        }
        let mut cursor = self
            .base
            .collection()
            .find(filter)
            .sort(doc! { "at": -1, "_id": -1 })
            .limit(limit)
            .await?;
        let mut out = Vec::new();
        while let Some(a) = cursor.try_next().await? {
            out.push(a);
        }
        Ok(out)
    }
}

/// FR-90 P3-4e — what one approval is FOR: this session at this fence on
/// this device, this secret's field, in this mode toward this audience.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalKey<'a> {
    pub tenant_id: ObjectId,
    pub session_id: ObjectId,
    pub fence: i64,
    pub device_id: ObjectId,
    pub secret_id: ObjectId,
    pub field: &'a str,
    pub mode: &'a str,
    pub audience: &'a str,
}

/// FR-90 P3-4e — the approvals policies asked for, and their answers.
pub struct VaultApprovalDao {
    pub base: BaseDao<VaultApproval>,
}

impl VaultApprovalDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, VaultApproval::COLLECTION),
        }
    }

    /// A new pending approval. `None` when one is pending for the same
    /// request already: the unique index arbitrates two asks at once, and
    /// the loser reads the winner's ([`Self::live_for`]).
    pub async fn insert_pending(&self, row: &VaultApproval) -> DaoResult<Option<ObjectId>> {
        match self.base.insert_one(row).await {
            Ok(id) => Ok(Some(id)),
            Err(DaoError::DuplicateKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// One request's approvals that may still be answered or used, newest
    /// first: whether its deny waits on a card, stands on a person's no, or
    /// is lifted by their yes.
    pub async fn live_for(
        &self,
        key: &ApprovalKey<'_>,
        now: DateTime,
    ) -> DaoResult<Vec<VaultApproval>> {
        let mut cursor = self
            .base
            .collection()
            .find(doc! {
                "tenant_id": key.tenant_id,
                "session_id": key.session_id,
                "fence": key.fence,
                "device_id": key.device_id,
                "secret_id": key.secret_id,
                "field": key.field,
                "mode": key.mode,
                "audience": key.audience,
                "status": { "$in": [
                    approval_status::PENDING,
                    approval_status::APPROVED,
                    approval_status::DENIED,
                ] },
                "expires_at": { "$gt": now },
            })
            .sort(doc! { "requested_at": -1, "_id": -1 })
            .limit(16)
            .await?;
        let mut out = Vec::new();
        while let Some(a) = cursor.try_next().await? {
            out.push(a);
        }
        Ok(out)
    }

    /// One request's approvals past their deadline that nothing has ended
    /// yet. A pending one holds the request's one pending place in the
    /// unique index, so it is ended before a new card is opened.
    pub async fn stale_for(
        &self,
        key: &ApprovalKey<'_>,
        now: DateTime,
    ) -> DaoResult<Vec<VaultApproval>> {
        let mut cursor = self
            .base
            .collection()
            .find(doc! {
                "tenant_id": key.tenant_id,
                "session_id": key.session_id,
                "fence": key.fence,
                "device_id": key.device_id,
                "secret_id": key.secret_id,
                "field": key.field,
                "mode": key.mode,
                "audience": key.audience,
                "status": { "$in": [approval_status::PENDING, approval_status::APPROVED] },
                "expires_at": { "$lte": now },
            })
            .limit(16)
            .await?;
        let mut out = Vec::new();
        while let Some(a) = cursor.try_next().await? {
            out.push(a);
        }
        Ok(out)
    }

    /// One approval of the organization.
    pub async fn find_in_tenant(
        &self,
        tenant_id: ObjectId,
        id: ObjectId,
    ) -> DaoResult<Option<VaultApproval>> {
        Ok(self
            .base
            .collection()
            .find_one(doc! { "_id": id, "tenant_id": tenant_id })
            .await?)
    }

    /// A driver's answer, while the approval is pending and not past its
    /// deadline: a yes is usable for `use_secs` from now, a no stands until
    /// the card's own deadline. `None` when someone answered first or
    /// nobody did in time.
    pub async fn answer(
        &self,
        id: ObjectId,
        approve: bool,
        by: ObjectId,
        now: DateTime,
        use_secs: u32,
    ) -> DaoResult<Option<VaultApproval>> {
        let mut set = doc! {
            "status": if approve { approval_status::APPROVED } else { approval_status::DENIED },
            "answered_by": by,
            "answered_at": now,
        };
        if approve {
            set.insert(
                "expires_at",
                DateTime::from_millis(now.timestamp_millis() + i64::from(use_secs) * 1000),
            );
        }
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "status": approval_status::PENDING,
                    "expires_at": { "$gt": now },
                },
                doc! { "$set": set },
            )
            .return_document(ReturnDocument::After)
            .await?)
    }

    /// Spend a yes on `lease_id`. Winning this compare-and-set IS the one
    /// use: `false` when the yes is spent already or past its use.
    pub async fn spend(&self, id: ObjectId, lease_id: ObjectId, now: DateTime) -> DaoResult<bool> {
        let r = self
            .base
            .collection()
            .update_one(
                doc! {
                    "_id": id,
                    "status": approval_status::APPROVED,
                    "expires_at": { "$gt": now },
                },
                doc! { "$set": {
                    "status": approval_status::USED,
                    "lease_id": lease_id,
                    "used_at": now,
                } },
            )
            .await?;
        Ok(r.modified_count == 1)
    }

    /// End an approval nobody can act on any more — pending or approved, to
    /// `expired` or `withdrawn`. `None` when another call ended it first, so
    /// its card is edited once.
    pub async fn end(&self, id: ObjectId, status: &str) -> DaoResult<Option<VaultApproval>> {
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "status": { "$in": [approval_status::PENDING, approval_status::APPROVED] },
                },
                doc! { "$set": { "status": status } },
            )
            .return_document(ReturnDocument::After)
            .await?)
    }

    /// Its card, once posted.
    pub async fn set_card(
        &self,
        id: ObjectId,
        room_id: ObjectId,
        message_id: ObjectId,
    ) -> DaoResult<()> {
        self.base
            .collection()
            .update_one(
                doc! { "_id": id },
                doc! { "$set": { "room_id": room_id, "message_id": message_id } },
            )
            .await?;
        Ok(())
    }
}
