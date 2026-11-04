// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc};
use mongodb::Database;
use rand::RngCore;
use meshharbor_db::models::Subscriber;

use super::base::{BaseDao, DaoResult};

/// How long before a confirmation may be sent to the same address again.
///
/// ⚠️ This is the only thing standing between a public, unauthenticated form
/// and a mail bomb: without it, submitting a stranger's address in a loop sends
/// them one email per request, from our own domain — so the deliverability
/// damage lands on us, not on whoever ran the loop. The per-IP limiter does not
/// cover it, because the interesting attack is distributed and the victim is
/// the address, not the endpoint.
const RESEND_COOLDOWN_SECS: i64 = 15 * 60;

/// What actually happened, so the caller can decide whether to send mail.
///
/// ⚠️ This must never reach the HTTP response. `POST /api/subscribe` answers
/// 202 for every arm — a response that distinguishes `Created` from
/// `AlreadyConfirmed` is an oracle that reveals whether an address is on the
/// list, and the same address is very often a `users.email`, which is a unique
/// index AND the account-linking key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeOutcome {
    /// A new row. Send the confirmation.
    Created,
    /// Known but never confirmed — resend, so a lost first mail is recoverable.
    PendingResend,
    /// Already on the list and confirmed. Send nothing; re-mailing a confirmed
    /// subscriber every time a form is submitted is how a sender gets reported.
    AlreadyConfirmed,
    /// Previously unsubscribed, and has now asked again. Treated as fresh
    /// consent: the row is revived UNCONFIRMED with a new confirm token, so
    /// re-entry always costs a deliberate click.
    Resubscribed,
}

pub struct SubscriberDao {
    pub base: BaseDao<Subscriber>,
}

fn random_token() -> String {
    let mut b = [0u8; 24];
    rand::rng().fill_bytes(&mut b);
    // Hex, not base64: these travel in a URL path, and the standard base64
    // alphabet's `+` and `/` do not survive that without escaping.
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl SubscriberDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, Subscriber::COLLECTION),
        }
    }

    /// Idempotent by email. Returns what happened AND the confirm token to mail,
    /// if one should be mailed.
    pub async fn subscribe(
        &self,
        email: &str,
        source: &str,
    ) -> DaoResult<(SubscribeOutcome, Option<String>)> {
        let email = Subscriber::normalize_email(email);

        if let Some(existing) = self.base.find_one(doc! { "email": &email }).await? {
            let id = existing.id.expect("stored subscriber has an id");

            // FR-102 P5 — a SUPPRESSED address (a hard bounce or a spam
            // report) asking again is treated like a withdrawn one: the
            // confirmation click is the fresh consent — and the proof the
            // mailbox works — that lifts the suppression.
            if existing.unsubscribed_at.is_some() || existing.suppressed_at.is_some() {
                // Fresh consent after a withdrawal. Deliberately NOT restored to
                // `confirmed`: whatever the old state was, re-entry is a new
                // decision and has to be re-proved.
                let token = random_token();
                self.base
                    .update_by_id(
                        id,
                        doc! {
                            "$set": {
                                "confirmed": false,
                                "confirm_token": &token,
                                "confirm_sent_at": DateTime::now(),
                                "source": source,
                                "created_at": DateTime::now(),
                            },
                            "$unset": {
                                "unsubscribed_at": "",
                                "confirmed_at": "",
                                "unsubscribed_via": "",
                                "suppressed_at": "",
                                "suppressed_reason": "",
                            },
                        },
                    )
                    .await?;
                return Ok((SubscribeOutcome::Resubscribed, Some(token)));
            }

            if existing.confirmed {
                return Ok((SubscribeOutcome::AlreadyConfirmed, None));
            }

            // Known, unconfirmed. Resending is right — the usual cause of a
            // stuck row is a first mail that never arrived — but only outside
            // the cooldown, or this branch IS the mail bomb.
            let cooled = existing
                .confirm_sent_at
                .map(|t| {
                    DateTime::now().timestamp_millis() - t.timestamp_millis()
                        >= RESEND_COOLDOWN_SECS * 1000
                })
                .unwrap_or(true);
            if !cooled {
                return Ok((SubscribeOutcome::PendingResend, None));
            }

            let token = match existing.confirm_token {
                Some(t) => t,
                None => random_token(),
            };
            self.base
                .update_by_id(
                    id,
                    doc! { "$set": { "confirm_token": &token, "confirm_sent_at": DateTime::now() } },
                )
                .await?;
            return Ok((SubscribeOutcome::PendingResend, Some(token)));
        }

        let confirm_token = random_token();
        let sub = Subscriber {
            id: None,
            email,
            source: source.to_string(),
            confirmed: false,
            confirm_token: Some(confirm_token.clone()),
            confirm_sent_at: Some(DateTime::now()),
            unsubscribe_token: random_token(),
            created_at: DateTime::now(),
            confirmed_at: None,
            unsubscribed_at: None,
            unsubscribed_via: None,
            suppressed_at: None,
            suppressed_reason: None,
        };
        self.base.insert_one(&sub).await?;
        Ok((SubscribeOutcome::Created, Some(confirm_token)))
    }

    /// Single-use: the token is cleared, so a link in a forwarded email cannot
    /// re-confirm an address its owner has since unsubscribed.
    pub async fn confirm(&self, token: &str) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "confirm_token": token },
                doc! {
                    "$set": { "confirmed": true, "confirmed_at": DateTime::now() },
                    "$unset": { "confirm_token": "" },
                },
            )
            .await
    }

    /// The row is kept and stamped, never deleted — see the model. Idempotent,
    /// because a mail client that prefetches links will call this more than once.
    ///
    /// FR-102 P5 — `via` is the slug of the issue whose link was followed
    /// (the link's `i=`, already checked against the issue list by the
    /// route). The stamp is written ONCE, by the click that ends a live
    /// subscription: a repeat click (a prefetcher, a second tab) changes
    /// neither the time the person left nor the issue they left from.
    /// `true` when the token names a row — this click or an earlier one.
    pub async fn unsubscribe(&self, token: &str, via: Option<&str>) -> DaoResult<bool> {
        let mut set = doc! { "confirmed": false, "unsubscribed_at": DateTime::now() };
        let mut unset = doc! { "confirm_token": "" };
        match via {
            Some(slug) => {
                set.insert("unsubscribed_via", slug);
            }
            None => {
                unset.insert("unsubscribed_via", "");
            }
        }
        let stamped = self
            .base
            .update_one(
                doc! { "unsubscribe_token": token, "unsubscribed_at": null },
                doc! { "$set": set, "$unset": unset },
            )
            .await?;
        if stamped {
            return Ok(true);
        }
        Ok(self
            .base
            .find_one(doc! { "unsubscribe_token": token })
            .await?
            .is_some())
    }

    /// FR-102 P5 — the subscriber an Event Webhook event names, by its
    /// address (normalised — a read path).
    pub async fn id_by_email(&self, email: &str) -> DaoResult<Option<bson::oid::ObjectId>> {
        let email = Subscriber::normalize_email(email);
        Ok(self
            .base
            .find_one(doc! { "email": &email })
            .await?
            .and_then(|s| s.id))
    }

    /// FR-102 P5 (D6) — SendGrid reported a hard bounce or a spam report:
    /// the fan-out never mails this subscriber again until fresh consent.
    /// The FIRST reason stays (a replayed event changes nothing); `true` when
    /// this call suppressed it.
    pub async fn suppress(
        &self,
        id: bson::oid::ObjectId,
        reason: &str,
        at: DateTime,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": id, "suppressed_at": null },
                doc! { "$set": { "suppressed_at": at, "suppressed_reason": reason } },
            )
            .await
    }

    /// Confirmed and not withdrawn — the only set that may be mailed.
    ///
    /// ⚠️ `"unsubscribed_at": null`, deliberately **not** `{"$type": "null"}`.
    /// The field is `skip_serializing_if = "Option::is_none"`, so it is ABSENT
    /// on a normal row rather than explicitly null; `$type: "null"` matches only
    /// an explicit null and would return an empty list forever — a mailing list
    /// that silently has no members. The `$type` form is right for the partial
    /// *index* filters in `indexes.rs`, and wrong here; the two are not
    /// interchangeable.
    pub async fn mailable(&self) -> DaoResult<Vec<Subscriber>> {
        self.base
            .find_many(
                doc! { "confirmed": true, "unsubscribed_at": null },
                Some(doc! { "created_at": -1 }),
            )
            .await
    }

    /// Whether this address is currently subscribed (confirmed, not
    /// withdrawn). Read path — so it normalizes, like every read path must.
    pub async fn is_subscribed(&self, email: &str) -> DaoResult<bool> {
        let email = Subscriber::normalize_email(email);
        Ok(self
            .base
            .find_one(doc! { "email": &email, "confirmed": true, "unsubscribed_at": null })
            .await?
            .is_some())
    }

    /// FR-58 — the signed-in toggle. The caller has already proven ownership
    /// of `email` (a VERIFIED account address), so subscribing here is
    /// pre-confirmed — no confirmation mail, no oracle concerns (the caller
    /// is asking about their own address). Unsubscribing stamps the row like
    /// every other withdrawal; re-toggling on is fresh consent and flips it
    /// straight back to confirmed for the same ownership reason.
    pub async fn set_account_subscription(&self, email: &str, subscribed: bool) -> DaoResult<bool> {
        let email = Subscriber::normalize_email(email);
        let existing = self.base.find_one(doc! { "email": &email }).await?;
        match (existing, subscribed) {
            (None, false) => Ok(false),
            (None, true) => {
                let sub = Subscriber {
                    id: None,
                    email,
                    source: "account".to_string(),
                    confirmed: true,
                    confirm_token: None,
                    confirm_sent_at: None,
                    unsubscribe_token: random_token(),
                    created_at: DateTime::now(),
                    confirmed_at: Some(DateTime::now()),
                    unsubscribed_at: None,
                    unsubscribed_via: None,
                    suppressed_at: None,
                    suppressed_reason: None,
                };
                self.base.insert_one(&sub).await?;
                Ok(true)
            }
            (Some(row), true) => {
                // Fresh consent on proven ownership — it also lifts a
                // suppression (FR-102 P5): the owner is asking for the mail.
                let id = row.id.expect("stored subscriber has an id");
                self.base
                    .update_by_id(
                        id,
                        doc! {
                            "$set": {
                                "confirmed": true,
                                "confirmed_at": DateTime::now(),
                                "source": "account",
                            },
                            "$unset": {
                                "unsubscribed_at": "",
                                "confirm_token": "",
                                "unsubscribed_via": "",
                                "suppressed_at": "",
                                "suppressed_reason": "",
                            },
                        },
                    )
                    .await?;
                Ok(true)
            }
            (Some(row), false) => {
                if row.unsubscribed_at.is_some() {
                    // Already out: the time they left, and the issue they
                    // left from (FR-102 P5), stay as they were.
                    return Ok(false);
                }
                let id = row.id.expect("stored subscriber has an id");
                self.base
                    .update_by_id(
                        id,
                        doc! {
                            "$set": { "confirmed": false, "unsubscribed_at": DateTime::now() },
                            "$unset": { "confirm_token": "", "unsubscribed_via": "" },
                        },
                    )
                    .await?;
                Ok(false)
            }
        }
    }
}
