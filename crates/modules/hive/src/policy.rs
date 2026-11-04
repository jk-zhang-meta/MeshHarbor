// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2c-2a — an organization's policy for its sessions' replicasets
//! (`hive_policies`): how many copies, of what, kept how long, and where a
//! copy may never go (spec §3b, decision 2).
//!
//! One document per tenant, written by an `ADMINISTRATOR` and audited.
//! Absent, it is decision 2's defaults ([`HivePolicy::defaults`]). Placement
//! (P2c-2b) reads it; nothing here moves a copy.
//!
//! | Rule | Why |
//! |---|---|
//! | only an `ADMINISTRATOR` writes it | where copies of every session go is the organization's choice, and a copy is everything the agent saw |
//! | a write names the revision it read | two administrators editing at once must not overwrite each other in silence |
//! | an archive device must be a live device of this organization, never an ephemeral one | a designation of a foreign or deleted device would place nothing and read as if it did; an ephemeral one is hard-deleted once it goes quiet |
//! | restricted tags are normalized as device tags are | a tag only ever takes a device out, and that holds only if the two compare equal |
//!
//! ⚠️ Behind `hive.replicaset` (default off): with it off both routes answer
//! as if they were not there.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::role::permissions;
use meshharbor_services::dao::base::{BaseDao, DaoError, DaoResult};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};

use crate::HiveState;
use crate::model::HiveAuditEvent;
use crate::routes::{member_tenant, parse_oid};

/// The most members a session's replicaset holds, the primary included.
pub const MAX_MEMBERS: u32 = 8;

/// The longest a policy keeps an ended session, in days (ten years).
pub const MAX_RETENTION_DAYS: u32 = 3650;

/// The most archive replicas one organization designates.
pub const MAX_ARCHIVES: usize = 16;

/// What `prefer` may name, in the order a policy lists them.
pub const PREFER_WORDS: [&str; 1] = ["owner_devices"];

/// An organization's replica policy, as stored.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HivePolicy {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub replicaset: ReplicasetRules,
    /// How long a session is kept after it ends; 0 keeps it for ever.
    pub retention_days: u32,
    /// The archive replicas an `ADMINISTRATOR` designated: live devices of
    /// this organization, never ephemeral. That is the administrator's half;
    /// the device's own `hive_archive` is the other, read where placement
    /// runs, so either may come first.
    #[serde(default)]
    pub archive_devices: Vec<ObjectId>,
    /// Bumped by every write; a write names the revision it was made from.
    pub revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime>,
}

/// Who holds a session's copies.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReplicasetRules {
    /// The primary and `min - 1` more copies: fewer is shown, never accepted
    /// in silence.
    pub min: u32,
    pub max: u32,
    /// Every archive replica the rules allow joins.
    pub archive: bool,
    /// Who joins after the archives, in order: `owner_devices`, the session
    /// owner's own devices, last seen first, until `min`.
    pub prefer: Vec<String>,
    /// A session on a device carrying one of these replicates only to devices
    /// carrying it too.
    pub restricted_tags: Vec<String>,
}

impl HivePolicy {
    pub const COLLECTION: &'static str = "hive_policies";

    /// Decision 2's defaults, for an organization that has written none.
    pub fn defaults(tenant_id: ObjectId) -> Self {
        Self {
            id: None,
            tenant_id,
            replicaset: ReplicasetRules {
                min: 2,
                max: 4,
                archive: true,
                prefer: vec!["owner_devices".into()],
                restricted_tags: vec!["prod".into()],
            },
            retention_days: 90,
            archive_devices: Vec::new(),
            revision: 0,
            updated_by: None,
            updated_at: None,
        }
    }
}

/// The rules as a write may set them, normalized, or why not.
pub fn validate(rules: ReplicasetRules, retention_days: u32) -> Result<ReplicasetRules, String> {
    if !(1..=MAX_MEMBERS).contains(&rules.min) {
        return Err(format!("min must be between 1 and {MAX_MEMBERS}"));
    }
    if !(rules.min..=MAX_MEMBERS).contains(&rules.max) {
        return Err(format!("max must be between min and {MAX_MEMBERS}"));
    }
    let mut prefer: Vec<String> = Vec::new();
    for word in rules.prefer {
        let word = word.trim().to_string();
        if !PREFER_WORDS.contains(&word.as_str()) {
            return Err(format!(
                "prefer names {word:?}; it may name {}",
                PREFER_WORDS.join(", ")
            ));
        }
        if prefer.contains(&word) {
            return Err(format!("prefer names {word:?} twice"));
        }
        prefer.push(word);
    }
    let restricted_tags = meshharbor_mod_fleet::agent::normalize_tags(rules.restricted_tags)
        .map_err(|e| format!("restricted_tags: {e}"))?;
    if retention_days > MAX_RETENTION_DAYS {
        return Err(format!(
            "retention_days must be between 0 and {MAX_RETENTION_DAYS}"
        ));
    }
    Ok(ReplicasetRules {
        prefer,
        restricted_tags,
        ..rules
    })
}

/// The policies, one per tenant.
pub struct PolicyDao {
    base: BaseDao<HivePolicy>,
}

/// A write made from a revision that is no longer the stored one.
pub struct Stale;

impl PolicyDao {
    pub fn new(db: &mongodb::Database) -> Self {
        Self {
            base: BaseDao::new(db, HivePolicy::COLLECTION),
        }
    }

    /// The tenant's policy, if it has written one.
    pub async fn get(&self, tenant_id: ObjectId) -> DaoResult<Option<HivePolicy>> {
        self.base.find_one(doc! { "tenant_id": tenant_id }).await
    }

    /// Write `policy` over revision `read`, which must still be the stored
    /// one (0: none stored yet); the stored policy, at `read + 1`.
    pub async fn put(
        &self,
        mut policy: HivePolicy,
        read: i64,
    ) -> DaoResult<Result<HivePolicy, Stale>> {
        policy.revision = read + 1;
        if read == 0 {
            // The unique index on `tenant_id` arbitrates two first writes.
            return match self.base.insert_one(&policy).await {
                Ok(id) => Ok(Ok(HivePolicy {
                    id: Some(id),
                    ..policy
                })),
                Err(DaoError::DuplicateKey(_)) => Ok(Err(Stale)),
                Err(e) => Err(e),
            };
        }
        // The whole policy, serialized: a field listed by hand here is one a
        // later field is silently missing from.
        let mut fields = bson::to_document(&policy)?;
        fields.remove("_id");
        let matched = self
            .base
            .update_one(
                doc! { "tenant_id": policy.tenant_id, "revision": read },
                doc! { "$set": fields },
            )
            .await?;
        if !matched {
            return Ok(Err(Stale));
        }
        Ok(self.get(policy.tenant_id).await?.ok_or(Stale))
    }
}

/// The policy as the API carries it.
#[derive(Serialize, Debug)]
pub struct PolicyView {
    pub replicaset: ReplicasetRules,
    pub retention_days: u32,
    pub archive_devices: Vec<String>,
    pub revision: i64,
    /// Nothing written yet: these are decision 2's defaults.
    pub is_default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl PolicyView {
    fn of(p: &HivePolicy, is_default: bool) -> Self {
        Self {
            replicaset: p.replicaset.clone(),
            retention_days: p.retention_days,
            archive_devices: p.archive_devices.iter().map(|d| d.to_hex()).collect(),
            revision: p.revision,
            is_default,
            updated_by: p.updated_by.map(|u| u.to_hex()),
            updated_at: p
                .updated_at
                .map(|t| t.try_to_rfc3339_string().unwrap_or_default()),
        }
    }
}

/// A write.
#[derive(Deserialize, Debug)]
pub struct PutPolicy {
    pub replicaset: ReplicasetRules,
    pub retention_days: u32,
    #[serde(default)]
    pub archive_devices: Vec<String>,
    /// The revision this write was made from: the one a read answered.
    pub revision: i64,
}

/// The replicaset's server switch: off, these routes are not there.
fn replicaset_on(state: &HiveState) -> Result<(), ApiError> {
    if state.replicaset {
        Ok(())
    } else {
        Err(ApiError::NotFound(
            "replica policies are off on this server".into(),
        ))
    }
}

/// `GET /api/tenant/{tenant_id}/hive/policy` — the organization's replica
/// policy, for any of its members: the defaults until an administrator
/// writes one.
pub async fn get_policy(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<PolicyView>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    replicaset_on(&state)?;
    Ok(Json(match state.policies.get(tid).await? {
        Some(p) => PolicyView::of(&p, false),
        None => PolicyView::of(&HivePolicy::defaults(tid), true),
    }))
}

/// `PUT /api/tenant/{tenant_id}/hive/policy` — an administrator sets it,
/// from the revision they read. Every attempt is audited, refused or set.
pub async fn put_policy(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<PutPolicy>,
) -> Result<Json<PolicyView>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    replicaset_on(&state)?;
    let refused = |reason: &'static str| audit(&state, tid, auth.user_id, "refused", Some(reason));
    let perms = state
        .tenants
        .get_member_permissions(tid, auth.user_id)
        .await?;
    if !permissions::has(perms, permissions::ADMINISTRATOR) {
        refused("no_permission").await;
        return Err(ApiError::Forbidden(
            "only the organization's administrators set where its sessions are copied".into(),
        ));
    }
    let rules = match validate(body.replicaset, body.retention_days) {
        Ok(r) => r,
        Err(why) => {
            refused("invalid").await;
            return Err(ApiError::BadRequest(why));
        }
    };
    if body.archive_devices.len() > MAX_ARCHIVES {
        refused("invalid").await;
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_ARCHIVES} archive devices"
        )));
    }
    let mut archives: Vec<ObjectId> = Vec::new();
    for raw in &body.archive_devices {
        let Ok(device) = parse_oid(raw, "archive device") else {
            refused("invalid").await;
            return Err(ApiError::BadRequest(format!("{raw} is not a device id")));
        };
        // LIVE and in this org: anything else answers like a bogus id. A
        // lookup that failed is the database's answer, not the caller's.
        let agent = match state.fleet.agents.find_live_in_tenant(tid, device).await {
            Ok(agent) => agent,
            Err(DaoError::NotFound) => {
                refused("not_a_device").await;
                return Err(ApiError::BadRequest(format!(
                    "{raw} is not a device of this organization"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        // FR-51 fixes `ephemeral` at enrollment, and the reaper hard-deletes
        // such a row once it goes quiet: it could neither keep a session for
        // the retention nor acknowledge a purge, ever.
        if agent.ephemeral {
            refused("ephemeral").await;
            return Err(ApiError::BadRequest(format!(
                "{raw} is an ephemeral device, which is never an archive replica"
            )));
        }
        if !archives.contains(&device) {
            archives.push(device);
        }
    }
    let policy = HivePolicy {
        id: None,
        tenant_id: tid,
        replicaset: rules,
        retention_days: body.retention_days,
        archive_devices: archives,
        revision: 0,
        updated_by: Some(auth.user_id),
        updated_at: Some(DateTime::now()),
    };
    match state.policies.put(policy, body.revision).await? {
        Ok(stored) => {
            audit(&state, tid, auth.user_id, "set", None).await;
            // P2c-4 — the org's live sessions are placed again under it. The
            // policy is stored either way; one that could not be applied now
            // is applied at the next change placement reads.
            if let Err(e) = crate::placement::replace_tenant(&state, tid, None).await {
                tracing::warn!(%e, tenant = %tid, "hive: the new policy was not applied to live sessions yet");
            }
            Ok(Json(PolicyView::of(&stored, false)))
        }
        Err(Stale) => {
            refused("stale").await;
            Err(ApiError::Conflict(
                "the policy changed since it was read: read it again".into(),
            ))
        }
    }
}

async fn audit(
    state: &HiveState,
    tid: ObjectId,
    user: ObjectId,
    outcome: &str,
    reason: Option<&'static str>,
) {
    let event = HiveAuditEvent {
        id: None,
        tenant_id: tid,
        user_id: user,
        target_id: None,
        device_id: None,
        session_id: None,
        action: "policy".into(),
        outcome: outcome.into(),
        reason: reason.map(str::to_string),
        sessions: None,
        at: DateTime::now(),
    };
    if let Err(e) = state.audit.record(event).await {
        tracing::warn!(%e, tenant = %tid, "hive: a policy decision was not audited");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(min: u32, max: u32) -> ReplicasetRules {
        ReplicasetRules {
            min,
            max,
            archive: true,
            prefer: vec!["owner_devices".into()],
            restricted_tags: vec!["prod".into()],
        }
    }

    /// Decision 2's defaults, as the spec writes them, pass the policy's own
    /// rules.
    #[test]
    fn the_defaults_are_decision_twos_and_valid() {
        let d = HivePolicy::defaults(ObjectId::new());
        assert_eq!(d.replicaset, rules(2, 4));
        assert_eq!(d.retention_days, 90);
        assert!(d.archive_devices.is_empty());
        assert_eq!(d.revision, 0);
        assert_eq!(
            validate(d.replicaset.clone(), d.retention_days),
            Ok(d.replicaset)
        );
    }

    #[test]
    fn a_policy_is_held_to_its_bounds() {
        let bad = |r: ReplicasetRules, days: u32, needle: &str| {
            let e = validate(r, days).unwrap_err();
            assert!(e.contains(needle), "{needle:?} in {e:?}");
        };
        bad(rules(0, 4), 90, "min must be");
        bad(rules(9, 9), 90, "min must be");
        bad(rules(3, 2), 90, "max must be");
        bad(rules(2, 9), 90, "max must be");
        bad(rules(2, 4), MAX_RETENTION_DAYS + 1, "retention_days");
        let mut unknown = rules(2, 4);
        unknown.prefer = vec!["anyone".into()];
        bad(unknown, 90, "it may name owner_devices");
        let mut twice = rules(2, 4);
        twice.prefer = vec!["owner_devices".into(), "owner_devices".into()];
        bad(twice, 90, "twice");
        let mut long = rules(2, 4);
        long.restricted_tags = vec!["x".repeat(41)];
        bad(long, 90, "restricted_tags");
        assert!(validate(rules(1, 1), 0).is_ok(), "one copy, kept for ever");
    }

    /// Restricted tags are normalized as device tags are, so a tag compares
    /// equal to the one a device carries.
    #[test]
    fn restricted_tags_are_normalized_as_device_tags_are() {
        let mut r = rules(2, 4);
        r.restricted_tags = vec![" prod ".into(), "".into(), "prod".into(), "pci".into()];
        assert_eq!(
            validate(r, 90).unwrap().restricted_tags,
            ["prod", "pci"],
            "trimmed, empties dropped, once each, in order"
        );
    }
}
