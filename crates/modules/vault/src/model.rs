// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! What the vault stores (`docs/meshharbor-hive-design.md` §8.2).
//!
//! | Collection | One row per | Holds |
//! |---|---|---|
//! | `vault_secrets` | secret | its path, kind, audiences, the counters of its fields — never a value |
//! | `vault_versions` | value written | the sealed value, its nonce, its wrapped data key ([`crate::crypto`]) |
//! | `vault_audit` | decision | who asked for what, allowed or denied, and why; 90 days |

use std::collections::BTreeMap;

use bson::{Binary, DateTime, oid::ObjectId, spec::BinarySubtype};
use serde::{Deserialize, Serialize};

/// The kinds the vault accepts. `template` and `llm_credential` come with the
/// steps that give them meaning; a row is read whatever its kind says, so a
/// server rolled back past one still lists what a later one wrote.
pub const KINDS: &[&str] = &[KIND_STATIC, KIND_STRUCTURED, KIND_DYNAMIC];
/// One field, `value`.
pub const KIND_STATIC: &str = "static";
/// Named fields: a username, a password, a host…
pub const KIND_STRUCTURED: &str = "structured";
/// P3-6b — an issuer, for a credential minted per lease: its fields are
/// those its `provider` names
/// (`meshharbor_remote_control::vault::providers`), and a session never
/// gets one of them. It is used in `short-lived` mode alone, and that mode
/// uses nothing else (the guardrails `dynamic-only-short-lived` and
/// `short-lived-only-dynamic`).
pub const KIND_DYNAMIC: &str = "dynamic";

/// A secret: the name and the rules, never the value (`vault_secrets`).
///
/// ⚠️ Tombstoned, not deleted: `deleted_at` is set, the row stays, and its
/// path is free again — the unique index covers live rows only, so it is
/// serialised as an explicit `null` while live (the index's filter is
/// `$type: "null"`, which does not match an absent field).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultSecret {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// Unique among the organization's live secrets; the RRN is
    /// `rrn:{org slug}:secret:{path}` ([`crate::rrn`]). Never changes.
    pub path: String,
    /// [`KINDS`], as a string: an unknown kind still reads.
    pub kind: String,
    /// P3-6b — a dynamic secret's provider, and only a dynamic secret's.
    /// Never changes, as its kind never does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default)]
    pub description: String,
    /// Each field's counter and current version, by name. A field appears
    /// with its first value.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldState>,
    /// Where a value may be presented: host patterns, a knowhow entity, a
    /// named upstream. Stored as given in P3-1; P3-5 is where the daemon
    /// holds a use to them.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// The programs a value may be handed to, as `argv[0]` (P3-4's
    /// `vault_exec`).
    #[serde(default)]
    pub exec_allow: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub owner_id: ObjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_days: Option<u32>,
    /// P3-5's per-secret kill switch: a disabled secret is never USED. An
    /// administrator still reads its metadata and writes its value.
    #[serde(default)]
    pub disabled: bool,
    pub created_by: ObjectId,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

impl VaultSecret {
    pub const COLLECTION: &'static str = "vault_secrets";
}

/// One field's versions, on its secret.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldState {
    /// The last version number handed out. An `$inc` on the secret, so two
    /// writers never get one number; a number whose write failed is a gap,
    /// never reused.
    pub seq: i64,
    /// The newest version stored: the one a use reads. `0` until the first
    /// value lands.
    #[serde(default)]
    pub current: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime>,
}

/// One value, sealed (`vault_versions`). Unique on (secret, field, number).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultVersion {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub secret_id: ObjectId,
    pub field: String,
    pub n: i64,
    /// The value under this version's data key.
    pub ciphertext: Binary,
    pub nonce: Binary,
    /// The data key, `age`-encrypted to the KEK.
    pub dek_wrapped: Binary,
    /// The KEK's recipient (`age1…`) the data key was wrapped to.
    pub kek: String,
    pub created_by: ObjectId,
    pub created_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,
}

impl VaultVersion {
    pub const COLLECTION: &'static str = "vault_versions";
}

/// Bytes as BSON binary (subtype generic).
pub fn binary(bytes: Vec<u8>) -> Binary {
    Binary {
        subtype: BinarySubtype::Generic,
        bytes,
    }
}

/// One decision (`vault_audit`): who asked to do what, allowed or denied,
/// and the server's reason. Written by the server from its own decision,
/// BEFORE it acts on an allow — a decision it cannot record is not acted
/// on. 90-day TTL, like the other audits.
///
/// The device's own report of using a value is a different claim, by a host
/// that may be compromised, and goes to `vault_activity` (P3-3), never here.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// `user` in P3-1; `session` and `device` principals arrive with P3-2
    /// and P3-3. P3-9-1 — `user` again for a person's `secret:connect`: the
    /// device's owner, with the device and no session.
    pub principal: String,
    pub user_id: ObjectId,
    /// The action as a policy names it: `secret:list` | `secret:write` |
    /// `secret:delete` | `vault:verify`; P3-2 adds `policy:write`.
    pub action: String,
    /// What exactly: `list` | `describe` | `create` | `update` | `value` |
    /// `delete` | `verify`; P3-2 adds `role_create` | `role_delete` |
    /// `policy_create` | `policy_update` | `policy_delete`.
    pub op: String,
    /// `allow` | `deny`.
    pub decision: String,
    /// The server's reason word: `administrator` (P3-1's one allow) or
    /// `not_administrator`.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<ObjectId>,
    /// The secret's RRN as it was named at the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// For `value`, the version the write was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<i64>,
    /// P3-2 — the role (`role:<name>`) or policy (`policy:<id>`) a
    /// `policy:write` was about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// P3-2b — for a Cedar decision, the session and the device it was
    /// decided for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<ObjectId>,
    /// P3-2b — for a Cedar decision, the request exactly as it was decided
    /// ([`crate::policy::Ask`], in [`crate::policy::Ask::to_doc`]'s form), so
    /// `simulate`'s replay decides it again under a changed set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<bson::Document>,
    pub at: DateTime,
}

impl VaultAuditEvent {
    pub const COLLECTION: &'static str = "vault_audit";
}

/// P3-2 — a vault role (`vault_roles`): a name an agent session assumes at
/// its start, which policies then permit things to. Unique among the
/// organization's live roles; tombstoned, never deleted, and never while a
/// live policy names it — a role re-created under an old name would inherit
/// every policy that still named it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultRole {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// One spelling: [`crate::rrn::check_tag`]'s rule. The Cedar entity is
    /// `MeshHarbor::Role::"<name>"`.
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub created_by: ObjectId,
    pub created_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

impl VaultRole {
    pub const COLLECTION: &'static str = "vault_roles";
}

/// P3-2 — a policy the organization wrote (`vault_policies`): ONE Cedar
/// statement, valid against the vault's schema and naming only its
/// organization when it was stored ([`crate::policy::check_policy`]).
/// The guardrails are not rows: they are code, in every set.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultPolicy {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// For people; unique among the organization's live policies.
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub text: String,
    /// `permit` | `forbid`, read from the text when it was stored.
    pub effect: String,
    /// Bumped by every write: a write names the revision it read.
    pub rev: i64,
    pub created_by: ObjectId,
    pub updated_by: ObjectId,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

impl VaultPolicy {
    pub const COLLECTION: &'static str = "vault_policies";
}

/// P3-3b — a value released to one agent session (`vault_leases`): which
/// version of which field, to which session at which fence on which device,
/// sealed to which device key, until when. Written after the decision is
/// recorded and before the sealed value is sent: a lease the vault could
/// not write is not sent. Its `_id` is the lease id the device is told.
///
/// Never a value: the row says what was released, the sealed box went to
/// the device and was not kept.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultLease {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub secret_id: ObjectId,
    /// The field leased; empty for a dynamic secret's bundle, which is the
    /// secret as a whole.
    pub field: String,
    /// The field's version leased; `0` for a bundle.
    pub n: i64,
    /// P3-6b — a bundle's fields, each at the version it carried. A newer
    /// version of any field of the secret, one the bundle did not carry
    /// included, takes the lease back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<BTreeMap<String, i64>>,
    /// The session it was released to. P3-9-1 — absent for a PERSON's lease
    /// (`mh connect`, [`crate::connect`]), which no session holds, and
    /// only for one: a lease with no session is checked as its owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ObjectId>,
    /// The session's fence; `0` for a person's lease.
    pub fence: i64,
    pub device_id: ObjectId,
    /// The principal the policy decided for: the session's owner, or
    /// (P3-9-1) for a person's lease the device's owner as its row named
    /// them, which the lease stands on until the row names another.
    pub owner_id: ObjectId,
    /// The device key the value was sealed to (`agents.vault_key` at the
    /// time): a later hello with another key means another process, which
    /// cannot open it (P3-3c revokes on it).
    pub sealed_to: String,
    pub mode: String,
    #[serde(default)]
    pub audience: String,
    pub issued_at: DateTime,
    pub expires_at: DateTime,
    /// P3-3c — revoked before its expiry, and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_why: Option<String>,
}

impl VaultLease {
    pub const COLLECTION: &'static str = "vault_leases";
}

/// FR-90 P3-4d — one use of leased values a device REPORTS
/// (`rc:vault.activity`): a command `vault_exec` ran, or a file
/// `vault_render` wrote.
///
/// ⚠️ A CLAIM, by a host that may be compromised: hence its own collection,
/// apart from [`VaultAuditEvent`], the server's own decisions, as
/// `ssh_activity` is kept apart from `ssh_audit`. Join them on the leases.
///
/// ⚠️ An empty result is not evidence of disuse: the device's own
/// `vault_activity_log` defaults off, and a device that never opted in looks
/// exactly like one nobody used.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultActivity {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub device_id: ObjectId,
    pub session_id: ObjectId,
    pub fence: i64,
    /// `exec` | `render`.
    pub kind: String,
    /// The leases whose values were used: each one released to this device,
    /// for this session, in the use's mode and toward its target.
    pub lease_ids: Vec<ObjectId>,
    /// `exec`: the program's bare name; `render`: the file's.
    pub target: String,
    /// `exec`: how the command ended; absent when it was killed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub timed_out: bool,
    /// When the server received it.
    pub at: DateTime,
}

impl VaultActivity {
    pub const COLLECTION: &'static str = "vault_activity";
}

/// P3-4e — where an approval stands. `pending` waits for a driver;
/// `approved` and `denied` are their answer; `used` is a yes a lease spent;
/// `expired` is one nobody answered, or nobody used, in time; `withdrawn` is
/// one for a session that has since moved or ended.
pub mod approval_status {
    pub const PENDING: &str = "pending";
    pub const APPROVED: &str = "approved";
    pub const DENIED: &str = "denied";
    pub const USED: &str = "used";
    pub const EXPIRED: &str = "expired";
    pub const WITHDRAWN: &str = "withdrawn";
}

/// P3-4e — a person's approval a policy asked for (`context has approval`):
/// ONE use of one secret's field, by one session at its fence on its
/// device, in one mode, toward one audience, for at most `ttl_s`. Its card
/// is a message the session authors in its room, bound to
/// `{module: "vault", ref: <approval id>}`.
///
/// ⚠️ Single use: the lease a yes allows wins a compare-and-set on
/// `approved` before its allow is recorded, so one yes never becomes two
/// leases.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultApproval {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub session_id: ObjectId,
    pub fence: i64,
    pub device_id: ObjectId,
    /// The session's owner, whom its audit rows name.
    pub owner_id: ObjectId,
    pub secret_id: ObjectId,
    /// The secret's RRN when it was asked for.
    pub rrn: String,
    pub field: String,
    pub mode: String,
    pub audience: String,
    /// The longest lease a yes allows, in seconds: what was asked, clamped.
    pub ttl_s: i64,
    /// One of [`approval_status`].
    pub status: String,
    pub requested_at: DateTime,
    /// Until when it may be answered; once it is approved, until when it
    /// may be used.
    pub expires_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<DateTime>,
    /// The lease that spent a yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<DateTime>,
    /// Its card: the session's room, and the message in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<ObjectId>,
}

impl VaultApproval {
    pub const COLLECTION: &'static str = "vault_approvals";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_secret_stores_an_explicit_null_tombstone() {
        // The unique index's filter is `deleted_at: {$type: "null"}`, which
        // an absent field does not match: a live row without the field
        // would escape the index, and two could share a path.
        let now = DateTime::now();
        let s = VaultSecret {
            id: None,
            tenant_id: ObjectId::new(),
            path: "db".into(),
            kind: KIND_STATIC.into(),
            provider: None,
            description: String::new(),
            fields: BTreeMap::new(),
            audiences: Vec::new(),
            exec_allow: Vec::new(),
            tags: Vec::new(),
            owner_id: ObjectId::new(),
            rotation_days: None,
            disabled: false,
            created_by: ObjectId::new(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let d = bson::to_document(&s).unwrap();
        assert_eq!(d.get("deleted_at"), Some(&bson::Bson::Null));
        assert!(d.get("_id").is_none());
    }

    #[test]
    fn sealed_bytes_are_stored_as_binary() {
        let now = DateTime::now();
        let v = VaultVersion {
            id: None,
            tenant_id: ObjectId::new(),
            secret_id: ObjectId::new(),
            field: "value".into(),
            n: 1,
            ciphertext: binary(vec![1, 2, 3]),
            nonce: binary(vec![0; 24]),
            dek_wrapped: binary(vec![9; 40]),
            kek: "age1example".into(),
            created_by: ObjectId::new(),
            created_at: now,
            expires_at: None,
        };
        let raw = bson::to_raw_document_buf(&v).unwrap();
        let back: VaultVersion = bson::from_slice(raw.as_bytes()).unwrap();
        assert_eq!(back.ciphertext.bytes, vec![1, 2, 3]);
        assert!(matches!(
            raw.get("ciphertext").unwrap(),
            Some(bson::RawBsonRef::Binary(_))
        ));
        // And through the other entry point the driver uses for updates.
        let d = bson::to_document(&v).unwrap();
        assert!(matches!(d.get("nonce"), Some(bson::Bson::Binary(_))));
        let back: VaultVersion = bson::from_document(d).unwrap();
        assert_eq!(back.nonce.bytes.len(), 24);
    }

    #[test]
    fn a_field_without_a_value_yet_reads() {
        // `$inc` creates `{seq: 1}` before the version lands.
        let d = bson::doc! { "seq": 1_i64 };
        let f: FieldState = bson::from_document(d).unwrap();
        assert_eq!(
            f,
            FieldState {
                seq: 1,
                current: 0,
                updated_at: None
            }
        );
    }
}
