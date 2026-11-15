//! One authoritative user document: replacement, credentials and consumption share a CAS.
use super::base::{DaoError, DaoResult};
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::User;
use mongodb::{Database, options::ReturnDocument};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct PendingEmailChange {
    pub request_id: ObjectId,
    pub email: String,
    pub token_hash: String,
    pub expires_at: DateTime,
    pub security_revision: i64,
    pub approval_revision: u32,
    pub new_password_hash: Option<String>,
}

pub async fn begin(db: &Database, user: &User, pending: PendingEmailChange) -> DaoResult<bool> {
    Ok(db.collection::<User>(User::COLLECTION).update_one(
        doc! {"_id":user.id, "deleted_at":null, "password_hash":&user.password_hash,
              "security_rev":pending.security_revision, "account_approval.revision":i64::from(pending.approval_revision)},
        doc! {"$set":{"pending_email_change":bson::to_bson(&pending)?,"updated_at":DateTime::now()}},
    ).await?.matched_count == 1)
}

pub async fn confirm(
    db: &Database,
    request: ObjectId,
    token_hash: &str,
) -> DaoResult<Option<User>> {
    // No preliminary "consume" write: duplicate-email or storage failure cannot
    // consume a valid request or leave half of a credential change committed.
    let result = db.collection::<User>(User::COLLECTION).find_one_and_update(
        doc! {"deleted_at":null, "pending_email_change.request_id":request,
            "pending_email_change.token_hash":token_hash,
            "pending_email_change.expires_at":{"$gt":DateTime::now()},
            "$expr":{"$and":[
                {"$eq":["$security_rev","$pending_email_change.security_revision"]},
                {"$eq":["$account_approval.revision","$pending_email_change.approval_revision"]},
                {"$lt":["$security_rev",i64::MAX]},
                {"$lt":["$account_approval.revision",i64::from(u32::MAX)]}
            ]}},
        vec![doc! {"$set":{
            "email":"$pending_email_change.email", "is_verified":true,
            "password_hash":{"$ifNull":["$pending_email_change.new_password_hash","$password_hash"]},
            "security_rev":{"$add":["$security_rev",1_i64]},
            "account_approval.revision":{"$add":["$account_approval.revision",1_i64]},
            "updated_at":DateTime::now()
        }},doc! {"$unset":["pending_email_change","unverified_email"]}],
    ).return_document(ReturnDocument::After).await;
    match result {
        Err(e) if e.to_string().contains("E11000") => {
            Err(DaoError::DuplicateKey("email already registered".into()))
        }
        other => other.map_err(DaoError::from),
    }
}
