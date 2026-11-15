// SPDX-License-Identifier: AGPL-3.0-only
//! Revocable native GUI user sessions and single-use loopback browser handoffs.
//! Stores only metadata and secret digests — never bearer JWTs or raw tickets.
use super::base::DaoResult;
use super::native_ssh_authorization::hash_secret;
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::{Database, options::ReturnDocument};
use serde::{Deserialize, Serialize};

pub const SESSIONS_COLLECTION: &str = "native_user_sessions";
pub const HANDOFF_COLLECTION: &str = "native_handoff_tickets";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeUserSession {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: ObjectId,
    pub security_revision: i64,
    pub approval_revision: u32,
    pub trusted_frontend_origin_prefix: String,
    pub created_at: DateTime,
    pub expires_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeHandoffTicket {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub ticket_hash: String,
    pub native_sid: ObjectId,
    pub user_id: ObjectId,
    pub form_origin: String,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_id: Option<ObjectId>,
    pub created_at: DateTime,
    pub expires_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<DateTime>,
}

pub fn hash_ticket(raw: &str) -> String {
    hash_secret("native-handoff-ticket", raw)
}

pub async fn create_session(db: &Database, row: &NativeUserSession) -> DaoResult<()> {
    db.collection::<NativeUserSession>(SESSIONS_COLLECTION)
        .insert_one(row)
        .await?;
    Ok(())
}

pub async fn find_session(db: &Database, id: ObjectId) -> DaoResult<Option<NativeUserSession>> {
    Ok(db
        .collection::<NativeUserSession>(SESSIONS_COLLECTION)
        .find_one(doc! { "_id": id })
        .await?)
}

pub async fn revoke_session(db: &Database, id: ObjectId, user_id: ObjectId) -> DaoResult<bool> {
    let now = DateTime::now();
    let res = db
        .collection::<NativeUserSession>(SESSIONS_COLLECTION)
        .update_one(
            doc! { "_id": id, "user_id": user_id },
            doc! { "$set": { "revoked_at": now } },
        )
        .await?;
    Ok(res.matched_count == 1)
}

pub async fn issue_handoff(db: &Database, row: &NativeHandoffTicket) -> DaoResult<()> {
    db.collection::<NativeHandoffTicket>(HANDOFF_COLLECTION)
        .insert_one(row)
        .await?;
    Ok(())
}

pub async fn consume_handoff(
    db: &Database,
    raw_ticket: &str,
    form_origin: &str,
    now: DateTime,
) -> DaoResult<Option<NativeHandoffTicket>> {
    Ok(db
        .collection::<NativeHandoffTicket>(HANDOFF_COLLECTION)
        .find_one_and_update(
            doc! {
                "ticket_hash": hash_ticket(raw_ticket),
                "form_origin": form_origin,
                "consumed_at": null,
                "expires_at": { "$gt": now },
            },
            doc! { "$set": { "consumed_at": now } },
        )
        .return_document(ReturnDocument::After)
        .await?)
}

pub async fn find_consumed_handoff(
    db: &Database,
    id: ObjectId,
    now: DateTime,
) -> DaoResult<Option<NativeHandoffTicket>> {
    Ok(db
        .collection::<NativeHandoffTicket>(HANDOFF_COLLECTION)
        .find_one(doc! {
            "_id": id,
            "consumed_at": { "$ne": null },
            "expires_at": { "$gt": now },
        })
        .await?)
}
