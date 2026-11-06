// SPDX-License-Identifier: AGPL-3.0-only
//! One browser-approved native SSH request. Never an account credential.
use bson::{DateTime, Document, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeSshScope {
    pub device_id: ObjectId,
    pub tenant_id: ObjectId,
    pub owner_user_id: ObjectId,
    pub recipient_user_id: ObjectId,
    pub approval_revision: u32,
    pub share_revision: u32,
    pub ssh_account: String,
    pub ssh_policy: Document,
    // Legacy approvals have no displayed-scope binding and cannot be exchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<NativeSshBinding>,
}

/// Server-owned display and authority snapshot. Contains no codes or credentials.
/// Policy values supplement existing revisions; they are not cross-document epochs.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeSshBinding {
    pub authorization_id: ObjectId,
    pub share_grant_id: ObjectId,
    pub public_key: String,
    pub code_challenge: String,
    pub recipient_username: String,
    pub recipient_display_name: String,
    pub device_name: String,
    pub device_os: String,
    pub request_expires_at: DateTime,
    pub share_expires_at: DateTime,
    pub session_secs: u64,
    pub security: Document,
}

/// The fixed `_id` is a capacity slot, not the public authorization ID.
/// Only hashes of user/device codes and the resulting grant are persisted.
#[derive(Clone, Serialize, Deserialize)]
pub struct NativeSshAuthorization {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub authorization_id: ObjectId,
    pub client_hash: String,
    pub client_slot: u32,
    // Missing only on legacy rows or before reserve assigns the shared quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_slot: Option<u32>,
    pub share_grant_id: ObjectId,
    pub public_key: String,
    pub code_challenge: String,
    pub user_code_hash: String,
    pub device_code_hash: String,
    pub session_secs: u64,
    pub state: String,
    pub polls: u32,
    pub scope: Option<NativeSshScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_scope: Option<NativeSshScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_revision_hash: Option<String>,
    pub grant_hash: Option<String>,
    pub grant_expires_at: Option<DateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<DateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime>,
    pub created_at: DateTime,
    pub expires_at: DateTime,
}

impl NativeSshAuthorization {
    pub const COLLECTION: &'static str = "native_ssh_authorizations";
    pub const GLOBAL_SLOTS: u32 = 64;
    pub const CLIENT_SLOTS: u32 = 8;
    pub const SHARE_SLOTS: u32 = 8;
    pub const MAX_POLLS: u32 = 60;
    pub const REQUEST_TTL_SECS: i64 = 300;
    pub const GRANT_TTL_SECS: i64 = 60;
}
