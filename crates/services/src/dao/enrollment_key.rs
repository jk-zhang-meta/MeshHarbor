// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-51 P2 — ephemeral enrollment keys (`enrollment_keys`) and their per-use
//! audit trail (`enrollment_key_uses`).
//!
//! The load-bearing method is [`EnrollmentKeyDao::claim_use`]: ONE atomic
//! `find_one_and_update` that checks all three liveness conditions (not
//! revoked, not expired, ceiling not reached) and increments `uses` in the
//! same operation — so N racing enrollments can never mint more than
//! `max_uses` devices between them, and a revocation takes effect on the very
//! next use. This is the same arbitrate-with-the-database shape as the
//! overlay block allocator and the `used_tokens` single-use claim.

use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::models::{EnrollmentKey, EnrollmentKeyUse};
use mongodb::Database;
use mongodb::options::ReturnDocument;

use super::base::{BaseDao, DaoResult};

pub struct EnrollmentKeyDao {
    pub base: BaseDao<EnrollmentKey>,
    uses: BaseDao<EnrollmentKeyUse>,
}

/// Why [`EnrollmentKeyDao::claim_use`] refused — resolved AFTER the atomic
/// claim missed, purely so the refusal can be audited and reported honestly
/// (the FR-51 stance that an address-starved device must never be
/// indistinguishable from an offline one applies to credentials too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// No live key row carries this `jti` in this tenant.
    Unknown,
    Revoked,
    Expired,
    /// `uses` reached `max_uses`.
    Exhausted,
}

impl KeyRefusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyRefusal::Unknown => "unknown_key",
            KeyRefusal::Revoked => "revoked",
            KeyRefusal::Expired => "expired",
            KeyRefusal::Exhausted => "exhausted",
        }
    }
}

impl EnrollmentKeyDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, EnrollmentKey::COLLECTION),
            uses: BaseDao::new(db, EnrollmentKeyUse::COLLECTION),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        jti: String,
        label: String,
        created_by: ObjectId,
        max_uses: i64,
        expires_at: DateTime,
        ephemeral_ttl_secs: Option<u64>,
    ) -> DaoResult<EnrollmentKey> {
        let now = DateTime::now();
        let key = EnrollmentKey {
            id: None,
            tenant_id,
            jti,
            label,
            created_by,
            max_uses,
            uses: 0,
            expires_at,
            revoked_at: None,
            ephemeral_ttl_secs,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        };
        let id = self.base.insert_one(&key).await?;
        self.base.find_by_id(id).await
    }

    /// Newest first — the operator's list view. Includes revoked and expired
    /// keys on purpose: a dead key is a record, not clutter, until it ages
    /// out of relevance (pruning is a P4 concern, decided explicitly then).
    pub async fn list_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<Vec<EnrollmentKey>> {
        self.base
            .find_many(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "created_at": -1 }),
            )
            .await
    }

    /// Atomically consume one use. `Ok(Some(key))` = the enrollment may
    /// proceed, and the returned row carries the TTL to stamp on the device.
    /// `Ok(None)` = refused — resolve why with [`Self::refusal_reason`].
    ///
    /// All three liveness conditions live INSIDE the filter, so there is no
    /// read-then-write window: a concurrent revoke, the expiry instant, or a
    /// racing final use each simply make the filter miss.
    pub async fn claim_use(
        &self,
        tenant_id: ObjectId,
        jti: &str,
    ) -> DaoResult<Option<EnrollmentKey>> {
        let now = DateTime::now();
        let updated = self
            .base
            .collection()
            .find_one_and_update(
                doc! {
                    "tenant_id": tenant_id,
                    "jti": jti,
                    "revoked_at": null,
                    "expires_at": { "$gt": now },
                    // Field-vs-field comparison needs $expr; the ceiling is
                    // checked and the counter bumped in ONE operation.
                    "$expr": { "$lt": ["$uses", "$max_uses"] },
                },
                doc! {
                    "$inc": { "uses": 1 },
                    "$set": { "last_used_at": now, "updated_at": now },
                },
            )
            .return_document(ReturnDocument::After)
            .await?;
        Ok(updated)
    }

    /// Why a [`Self::claim_use`] miss missed — for the audit line and the
    /// caller's response. Read-after-miss is fine here: this only ever
    /// EXPLAINS a refusal that already happened, it grants nothing.
    pub async fn refusal_reason(&self, tenant_id: ObjectId, jti: &str) -> DaoResult<KeyRefusal> {
        let key = self
            .base
            .find_one(doc! { "tenant_id": tenant_id, "jti": jti })
            .await?;
        Ok(match key {
            None => KeyRefusal::Unknown,
            Some(k) if k.revoked_at.is_some() => KeyRefusal::Revoked,
            Some(k) if k.expires_at <= DateTime::now() => KeyRefusal::Expired,
            Some(k) if k.uses >= k.max_uses => KeyRefusal::Exhausted,
            // The claim missed but every condition now reads live — a race
            // resolved between the two reads. The caller retries or reports
            // it as transient; calling it anything specific would be a guess.
            Some(_) => KeyRefusal::Unknown,
        })
    }

    /// Revoke — dead from the next use onward, whatever the expiry says.
    /// Scoped to the tenant like every other admin write. Idempotent: `false`
    /// = no live key matched (already revoked, or never existed here).
    pub async fn revoke(&self, tenant_id: ObjectId, key_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": key_id, "tenant_id": tenant_id, "revoked_at": null },
                doc! { "$set": { "revoked_at": DateTime::now(), "updated_at": DateTime::now() } },
            )
            .await
    }

    /// P4 — stamp the device's use-row with its removal, closing the
    /// lifecycle record (born → removed) in the one place that survives the
    /// hard delete. Keyed by `agent_id`: ObjectIds are unique across the
    /// deployment, so a device has at most one birth row. Best-effort like
    /// [`Self::record_use`] — `false` (no matching row) is a device that was
    /// never key-minted (DAO-marked in tests, or pre-P2), and that is fine.
    pub async fn record_removal(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        reason: &str,
    ) -> DaoResult<bool> {
        self.uses
            .update_one(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id, "removed_at": null },
                doc! { "$set": { "removed_at": DateTime::now(), "removal": reason } },
            )
            .await
    }

    /// Control 4 — one audit row per successful use. Best-effort in the
    /// caller (a failed insert is logged, never a refused enrollment: the
    /// atomic claim is the ENFORCEMENT, this row is the RECORD).
    pub async fn record_use(
        &self,
        tenant_id: ObjectId,
        key_id: ObjectId,
        agent_id: ObjectId,
        machine_id: &str,
        machine_name: &str,
    ) -> DaoResult<ObjectId> {
        self.uses
            .insert_one(&EnrollmentKeyUse {
                id: None,
                tenant_id,
                key_id,
                agent_id,
                machine_id: machine_id.to_string(),
                machine_name: machine_name.to_string(),
                created_at: DateTime::now(),
                // Born now; `record_removal` closes the lifecycle later.
                removed_at: None,
                removal: None,
            })
            .await
    }

    /// The use trail for one key, newest first (the P4 detail view; public
    /// now so tests can assert control 4 without raw collection reads).
    pub async fn list_uses(
        &self,
        tenant_id: ObjectId,
        key_id: ObjectId,
    ) -> DaoResult<Vec<EnrollmentKeyUse>> {
        self.uses
            .find_many(
                doc! { "tenant_id": tenant_id, "key_id": key_id },
                Some(doc! { "created_at": -1 }),
            )
            .await
    }
}
