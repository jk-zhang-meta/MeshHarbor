// SPDX-License-Identifier: AGPL-3.0-only
//! One browser-approved native SSH request. Never an account credential.
use bson::{DateTime, Document, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct NativeSshScope {
    pub device_id: ObjectId,
    pub tenant_id: ObjectId,
    pub owner_user_id: ObjectId,
    pub recipient_user_id: ObjectId,
    pub approval_revision: u32,
    pub share_revision: u32,
    pub ssh_account: String,
    pub ssh_policy: Document,
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
    pub share_grant_id: ObjectId,
    pub public_key: String,
    pub code_challenge: String,
    pub user_code_hash: String,
    pub device_code_hash: String,
    pub session_secs: u64,
    pub state: String,
    pub polls: u32,
    pub scope: Option<NativeSshScope>,
    pub grant_hash: Option<String>,
    pub grant_expires_at: Option<DateTime>,
    pub created_at: DateTime,
    pub expires_at: DateTime,
}

impl NativeSshAuthorization {
    pub const COLLECTION: &'static str = "native_ssh_authorizations";
    pub const GLOBAL_SLOTS: u32 = 64;
    pub const CLIENT_SLOTS: u32 = 8;
    pub const MAX_POLLS: u32 = 60;
    pub const REQUEST_TTL_SECS: i64 = 300;
    pub const GRANT_TTL_SECS: i64 = 60;
}
