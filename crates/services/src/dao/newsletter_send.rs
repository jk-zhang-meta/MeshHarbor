// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use std::collections::HashMap;

use bson::{DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use mongodb::Database;
use meshharbor_db::models::{IssueCounts, NewsletterSend, SendStatus};
use serde::Serialize;

use super::base::{BaseDao, DaoError, DaoResult};

/// FR-102 P5 — the longest bounce or drop reason kept on a row.
pub const MAX_REASON_CHARS: usize = 200;

/// A ledger row still `claimed` after this long is STALE — the crash-window
/// residue the status surface reports and `retry_stale` may re-attempt.
/// Here, below both readers (the `saas` fan-out and the host's newsletter
/// view, FR-102 P5), so the two cannot disagree on what "stale" means.
pub const STALE_ROW_SECS: i64 = 15 * 60;

/// [`STALE_ROW_SECS`] before `now`.
pub fn stale_cutoff_at(now: DateTime) -> DateTime {
    DateTime::from_millis(now.timestamp_millis() - STALE_ROW_SECS * 1000)
}

/// FR-102 P5 (D6) — one of the four SendGrid events the newsletter records.
/// Every other event kind (`processed`, `deferred`, `open`, `click`, …) has
/// no variant: there is no way to record what this type cannot say.
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryEvent {
    Delivered {
        at: DateTime,
    },
    /// `hard` = SendGrid's bounce `type` was `bounce` (the address is gone);
    /// otherwise `blocked` (the receiving server refused this message).
    Bounced {
        at: DateTime,
        hard: bool,
        reason: Option<String>,
    },
    Dropped {
        at: DateTime,
        reason: Option<String>,
    },
    SpamReport {
        at: DateTime,
    },
}

impl DeliveryEvent {
    /// Whether this event suppresses the address (D6): a hard bounce or a
    /// spam report. A block or a drop does not.
    pub fn suppresses(&self) -> Option<&'static str> {
        match self {
            DeliveryEvent::Bounced { hard: true, .. } => Some("bounce"),
            DeliveryEvent::SpamReport { .. } => Some("spamreport"),
            _ => None,
        }
    }

    pub fn at(&self) -> DateTime {
        match self {
            DeliveryEvent::Delivered { at }
            | DeliveryEvent::Bounced { at, .. }
            | DeliveryEvent::Dropped { at, .. }
            | DeliveryEvent::SpamReport { at } => *at,
        }
    }

    /// The update one event makes: each time as `$min`, so the earliest
    /// report wins and a replay (or SendGrid's own duplicate) writes nothing
    /// new.
    fn update(&self) -> Document {
        let clamp = |r: &Option<String>| -> bson::Bson {
            match r {
                Some(r) => bson::Bson::String(
                    r.chars()
                        .filter(|c| !c.is_control())
                        .take(MAX_REASON_CHARS)
                        .collect(),
                ),
                None => bson::Bson::Null,
            }
        };
        match self {
            DeliveryEvent::Delivered { at } => doc! { "$min": { "delivery.delivered_at": at } },
            DeliveryEvent::Bounced { at, hard, reason } => doc! {
                "$min": { "delivery.bounced_at": at },
                "$set": {
                    "delivery.bounce_type": if *hard { "bounce" } else { "blocked" },
                    "delivery.reason": clamp(reason),
                },
            },
            DeliveryEvent::Dropped { at, reason } => doc! {
                "$min": { "delivery.dropped_at": at },
                "$set": { "delivery.reason": clamp(reason) },
            },
            DeliveryEvent::SpamReport { at } => {
                doc! { "$min": { "delivery.spam_reported_at": at } }
            }
        }
    }
}

/// FR-102 P5 — what SendGrid reported for one issue's messages so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DeliveryCounts {
    pub delivered: i64,
    /// Every bounce, hard and blocked.
    pub bounced: i64,
    /// Bounces of `type: bounce` — each suppressed its address.
    pub hard_bounced: i64,
    pub dropped: i64,
    /// Spam reports.
    pub complaints: i64,
}

/// FR-58 — the per-recipient delivery ledger. See the model docs: the unique
/// `{issue_id, subscriber_id}` index is the at-most-once invariant; everything
/// here leans on it.
pub struct NewsletterSendDao {
    pub base: BaseDao<NewsletterSend>,
}

impl NewsletterSendDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, NewsletterSend::COLLECTION),
        }
    }

    /// Claim-first: insert the row BEFORE the send attempt. `Ok(None)` means
    /// another pass (or pod) already holds this recipient — skip, that is the
    /// idempotence working, not an error.
    pub async fn try_claim(
        &self,
        issue_id: ObjectId,
        subscriber_id: ObjectId,
        email: &str,
    ) -> DaoResult<Option<ObjectId>> {
        let row = NewsletterSend {
            id: None,
            issue_id,
            subscriber_id,
            email: email.to_string(),
            status: SendStatus::Claimed,
            error: None,
            claimed_at: DateTime::now(),
            updated_at: DateTime::now(),
            sent_at: None,
            delivery: None,
        };
        match self.base.insert_one(&row).await {
            Ok(id) => Ok(Some(id)),
            Err(DaoError::DuplicateKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn mark_sent(&self, id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_by_id(
                id,
                doc! { "$set": { "status": "sent", "sent_at": DateTime::now() } },
            )
            .await
    }

    pub async fn mark_failed(&self, id: ObjectId, error: &str) -> DaoResult<bool> {
        self.base
            .update_by_id(id, doc! { "$set": { "status": "failed", "error": error } })
            .await
    }

    pub async fn mark_suppressed(&self, id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_by_id(id, doc! { "$set": { "status": "suppressed" } })
            .await
    }

    /// Rows stuck `claimed` from before `cutoff` — the crash-window residue.
    pub async fn stale_rows(
        &self,
        issue_id: ObjectId,
        cutoff: DateTime,
    ) -> DaoResult<Vec<NewsletterSend>> {
        self.base
            .find_many(
                doc! { "issue_id": issue_id, "status": "claimed", "updated_at": { "$lt": cutoff } },
                Some(doc! { "claimed_at": 1 }),
            )
            .await
    }

    /// Per-row CAS so two resuming pods can't both re-attempt one recipient:
    /// only the caller that flips `updated_at` forward owns the retry.
    pub async fn reclaim(&self, id: ObjectId, cutoff: DateTime) -> DaoResult<bool> {
        let res = self
            .base
            .collection()
            .find_one_and_update(
                doc! { "_id": id, "status": "claimed", "updated_at": { "$lt": cutoff } },
                doc! { "$set": { "claimed_at": DateTime::now(), "updated_at": DateTime::now() } },
            )
            .await?;
        Ok(res.is_some())
    }

    /// A sample of failed rows for the status surface (capped by the caller).
    pub async fn failed_sample(
        &self,
        issue_id: ObjectId,
        limit: usize,
    ) -> DaoResult<Vec<NewsletterSend>> {
        let mut rows = self
            .base
            .find_many(
                doc! { "issue_id": issue_id, "status": "failed" },
                Some(doc! { "updated_at": 1 }),
            )
            .await?;
        rows.truncate(limit);
        Ok(rows)
    }

    /// FR-102 P5 — record one SendGrid event on the ledger row of
    /// `(issue, subscriber)`, through the unique pair's index. `false` when
    /// there is no such row (a test-send, an issue sent before the ledger).
    /// `status` is never touched: it is our disposition, `delivery` theirs.
    pub async fn record_delivery(
        &self,
        issue_id: ObjectId,
        subscriber_id: ObjectId,
        event: &DeliveryEvent,
    ) -> DaoResult<bool> {
        let r = self
            .base
            .collection()
            .update_one(
                doc! { "issue_id": issue_id, "subscriber_id": subscriber_id },
                event.update(),
            )
            .await?;
        Ok(r.matched_count == 1)
    }

    /// FR-102 P5 — [`DeliveryCounts`] per issue, for the given issues (one
    /// aggregation over the `(issue_id, status)` index). An issue with no
    /// ledger rows is absent from the map.
    pub async fn delivery_counts(
        &self,
        issue_ids: &[ObjectId],
    ) -> DaoResult<HashMap<ObjectId, DeliveryCounts>> {
        if issue_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let has = |field: &str| doc! { "$cond": [{ "$ifNull": [field, false] }, 1, 0] };
        let rows: Vec<Document> = self
            .base
            .collection()
            .aggregate(vec![
                doc! { "$match": { "issue_id": { "$in": issue_ids } } },
                doc! { "$group": {
                    "_id": "$issue_id",
                    "delivered": { "$sum": has("$delivery.delivered_at") },
                    "bounced": { "$sum": has("$delivery.bounced_at") },
                    "hard_bounced": { "$sum": { "$cond": [
                        { "$eq": ["$delivery.bounce_type", "bounce"] }, 1, 0
                    ] } },
                    "dropped": { "$sum": has("$delivery.dropped_at") },
                    "complaints": { "$sum": has("$delivery.spam_reported_at") },
                } },
            ])
            .await?
            .try_collect()
            .await?;
        let n = |d: &Document, k: &str| match d.get(k) {
            Some(bson::Bson::Int32(v)) => i64::from(*v),
            Some(bson::Bson::Int64(v)) => *v,
            _ => 0,
        };
        Ok(rows
            .iter()
            .filter_map(|d| {
                Some((
                    d.get_object_id("_id").ok()?,
                    DeliveryCounts {
                        delivered: n(d, "delivered"),
                        bounced: n(d, "bounced"),
                        hard_bounced: n(d, "hard_bounced"),
                        dropped: n(d, "dropped"),
                        complaints: n(d, "complaints"),
                    },
                ))
            })
            .collect())
    }

    /// The honest totals. `stale` is computed against `cutoff`, not merely
    /// "still claimed" — a row claimed two seconds ago is in flight, not stuck.
    pub async fn counts(&self, issue_id: ObjectId, cutoff: DateTime) -> DaoResult<IssueCounts> {
        let col = self.base.collection();
        Ok(IssueCounts {
            total: col.count_documents(doc! { "issue_id": issue_id }).await? as i64,
            sent: col
                .count_documents(doc! { "issue_id": issue_id, "status": "sent" })
                .await? as i64,
            failed: col
                .count_documents(doc! { "issue_id": issue_id, "status": "failed" })
                .await? as i64,
            suppressed: col
                .count_documents(doc! { "issue_id": issue_id, "status": "suppressed" })
                .await? as i64,
            stale: col
                .count_documents(
                    doc! { "issue_id": issue_id, "status": "claimed", "updated_at": { "$lt": cutoff } },
                )
                .await? as i64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime {
        DateTime::parse_rfc3339_str("2026-10-15T08:00:00Z").unwrap()
    }

    /// D6 — only a hard bounce and a spam report suppress the address.
    #[test]
    fn only_a_hard_bounce_or_a_spam_report_suppresses() {
        let bounce = |hard| DeliveryEvent::Bounced {
            at: at(),
            hard,
            reason: None,
        };
        assert_eq!(bounce(true).suppresses(), Some("bounce"));
        assert_eq!(bounce(false).suppresses(), None);
        assert_eq!(
            DeliveryEvent::SpamReport { at: at() }.suppresses(),
            Some("spamreport")
        );
        assert_eq!(DeliveryEvent::Delivered { at: at() }.suppresses(), None);
        assert_eq!(
            DeliveryEvent::Dropped {
                at: at(),
                reason: None
            }
            .suppresses(),
            None
        );
    }

    /// Every time is a `$min` (the earliest report wins, a replay changes
    /// nothing) and a reason is cut to 200 characters, controls dropped.
    #[test]
    fn an_event_writes_its_time_as_min_and_a_clamped_reason() {
        let d = DeliveryEvent::Delivered { at: at() }.update();
        assert_eq!(
            d.get_document("$min")
                .unwrap()
                .get_datetime("delivery.delivered_at")
                .unwrap(),
            &at()
        );
        assert!(d.get("$set").is_none(), "a delivery sets nothing else");

        let long = format!("550 5.1.1\r\n{}", "x".repeat(400));
        let b = DeliveryEvent::Bounced {
            at: at(),
            hard: true,
            reason: Some(long),
        }
        .update();
        let set = b.get_document("$set").unwrap();
        assert_eq!(set.get_str("delivery.bounce_type").unwrap(), "bounce");
        let reason = set.get_str("delivery.reason").unwrap();
        assert_eq!(reason.chars().count(), MAX_REASON_CHARS);
        assert!(!reason.contains('\r') && !reason.contains('\n'));
        assert!(
            b.get_document("$min")
                .unwrap()
                .get_datetime("delivery.bounced_at")
                .is_ok()
        );

        let blocked = DeliveryEvent::Bounced {
            at: at(),
            hard: false,
            reason: None,
        }
        .update();
        let set = blocked.get_document("$set").unwrap();
        assert_eq!(set.get_str("delivery.bounce_type").unwrap(), "blocked");
        assert_eq!(set.get("delivery.reason"), Some(&bson::Bson::Null));

        let s = DeliveryEvent::SpamReport { at: at() }.update();
        assert!(
            s.get_document("$min")
                .unwrap()
                .get_datetime("delivery.spam_reported_at")
                .is_ok()
        );
    }
}
