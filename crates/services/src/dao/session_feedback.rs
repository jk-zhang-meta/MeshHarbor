// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P9b — `session_feedback`: a person's rating of one remote session
//! (spec §3f, D10), the `remote` module's collection.
//!
//! One row per session **per person** — the unique index on
//! `(session_id, user_id)` is the arbiter, so two posts by one person for one
//! session (a double click, two tabs) store one and answer the other
//! `AlreadyRated`, while the controller and each watcher of a session rate it
//! once each: a rating is one person's experience. Rows carry a thumb, reason
//! codes and ids, never text. They expire after 25 months (the module's TTL
//! on `ts`) and go with the user ([`SessionFeedbackDao::purge_user`] is the
//! one call an account deletion makes for them; no account hard-delete path
//! exists today, so the TTL is what bounds them for now).

use bson::{doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_remote_control::models::SessionFeedback;

use super::base::{BaseDao, DaoError, DaoResult, duplicate_key_is_on};

pub struct SessionFeedbackDao {
    pub base: BaseDao<SessionFeedback>,
}

/// What [`SessionFeedbackDao::record`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    Stored(ObjectId),
    /// This person already rated this session; nothing was written.
    AlreadyRated,
}

impl SessionFeedbackDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, SessionFeedback::COLLECTION),
        }
    }

    /// Insert one rating. A duplicate on `(session_id, user_id)` — the
    /// dup-key document names both — is `AlreadyRated`; a duplicate on
    /// anything else is the error it is.
    pub async fn record(&self, feedback: &SessionFeedback) -> DaoResult<Recorded> {
        match self.base.insert_one(feedback).await {
            Ok(id) => Ok(Recorded::Stored(id)),
            Err(DaoError::DuplicateKey(msg))
                if duplicate_key_is_on(&msg, "session_id")
                    && duplicate_key_is_on(&msg, "user_id") =>
            {
                Ok(Recorded::AlreadyRated)
            }
            Err(e) => Err(e),
        }
    }

    /// One person's rating of one session, when there is one.
    pub async fn find_for_session_and_user(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
    ) -> DaoResult<Option<SessionFeedback>> {
        self.base
            .find_one(doc! { "session_id": session_id, "user_id": user_id })
            .await
    }

    /// Everything one person ever answered, removed — spec principle 7: rows
    /// never outlive their owner. Idempotent.
    pub async fn purge_user(&self, user_id: ObjectId) -> DaoResult<u64> {
        self.base.hard_delete(doc! { "user_id": user_id }).await
    }
}

#[cfg(test)]
mod tests {
    use meshharbor_remote_control::models::{
        FEEDBACK_REASONS, FeedbackRating, SessionFeedback, SessionFeedbackRequest,
    };

    /// The vocabulary is the whole of what can be stored: a thumb and codes,
    /// deduplicated in vocabulary order; anything else is a code back.
    #[test]
    fn a_request_validates_to_the_vocabulary_and_nothing_else() {
        let ok = SessionFeedbackRequest {
            rating: "down".into(),
            reasons: vec!["other".into(), "lag".into(), "lag".into()],
        };
        assert_eq!(
            ok.validate().unwrap(),
            (
                FeedbackRating::Down,
                vec!["lag".to_string(), "other".to_string()]
            )
        );
        let up = SessionFeedbackRequest {
            rating: "up".into(),
            reasons: vec![],
        };
        assert_eq!(up.validate().unwrap(), (FeedbackRating::Up, vec![]));
        let bad_rating = SessionFeedbackRequest {
            rating: "meh".into(),
            reasons: vec![],
        };
        assert_eq!(bad_rating.validate(), Err("unknown_rating"));
        let bad_reason = SessionFeedbackRequest {
            rating: "down".into(),
            reasons: vec!["the host was slow today".into()],
        };
        assert_eq!(bad_reason.validate(), Err("unknown_reason"));
        let too_many = SessionFeedbackRequest {
            rating: "down".into(),
            reasons: vec!["lag".into(); FEEDBACK_REASONS.len() + 1],
        };
        assert_eq!(too_many.validate(), Err("too_many_reasons"));
        // An eighth key — a comment — fails the parse itself.
        assert!(
            serde_json::from_str::<SessionFeedbackRequest>(
                r#"{"rating":"up","reasons":[],"comment":"my password is hunter2"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<SessionFeedbackRequest>(r#"{"rating":"up"}"#).is_ok(),
            "reasons default to none"
        );
    }

    /// The stored shape round-trips with the thumb as its wire spelling.
    #[test]
    fn a_row_round_trips() {
        let row = SessionFeedback {
            id: None,
            session_id: bson::oid::ObjectId::new(),
            tenant_id: bson::oid::ObjectId::new(),
            user_id: bson::oid::ObjectId::new(),
            agent_id: bson::oid::ObjectId::new(),
            rating: FeedbackRating::Down,
            reasons: vec!["lag".into()],
            ts: bson::DateTime::now(),
        };
        let doc = bson::to_document(&row).unwrap();
        assert_eq!(doc.get_str("rating").unwrap(), "down");
        assert!(doc.get("_id").is_none());
        let back: SessionFeedback = bson::from_document(doc).unwrap();
        assert_eq!(back, row);
        assert_eq!(SessionFeedback::MIN_SESSION_SECS, 30);
        assert_eq!(SessionFeedback::TTL_SECONDS, 25 * 30 * 86_400);
    }
}
