// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc};
use meshharbor_db::models::NewsletterIssue;
use mongodb::Database;

use super::base::{BaseDao, DaoResult};

/// FR-58 — the newsletter issue store.
///
/// Create is explicit and update is filtered to drafts. Deliberately NOT an
/// upsert-by-slug: a typo'd slug on update must 404, never quietly mint a
/// second issue. Two concurrent creates on one slug are arbitrated by the
/// unique index (`DuplicateKey` → 409 at the route).
pub struct NewsletterIssueDao {
    pub base: BaseDao<NewsletterIssue>,
}

impl NewsletterIssueDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, NewsletterIssue::COLLECTION),
        }
    }

    pub async fn create(&self, issue: &NewsletterIssue) -> DaoResult<bson::oid::ObjectId> {
        self.base.insert_one(issue).await
    }

    pub async fn get_by_slug(&self, slug: &str) -> DaoResult<Option<NewsletterIssue>> {
        self.base.find_one(doc! { "slug": slug }).await
    }

    pub async fn list(&self) -> DaoResult<Vec<NewsletterIssue>> {
        self.base
            .find_many(doc! {}, Some(doc! { "created_at": -1 }))
            .await
    }

    /// Update the editable fields of a DRAFT. `false` = no draft row matched —
    /// the caller distinguishes "absent" (404) from "not a draft any more"
    /// (409) by reading the row, because the two have different fixes.
    pub async fn update_draft(&self, slug: &str, set: bson::Document) -> DaoResult<bool> {
        let mut set = set;
        set.insert("updated_at", DateTime::now());
        self.base
            .update_one(
                doc! { "slug": slug, "status": "draft" },
                doc! { "$set": set },
            )
            .await
    }

    /// One CAS claims the send: a `draft`, or a `sending` whose claim went
    /// stale (the pod died mid-fan-out) — re-POSTing send IS the resume path.
    /// A `completed` issue is never re-claimable: one issue, one send; stale
    /// rows at completion are terminal ambiguity, reported, not re-openable.
    pub async fn claim_for_send(
        &self,
        slug: &str,
        pod_id: &str,
        stale_after_secs: i64,
    ) -> DaoResult<Option<NewsletterIssue>> {
        let cutoff =
            DateTime::from_millis(DateTime::now().timestamp_millis() - stale_after_secs * 1000);
        let claimed = self
            .base
            .collection()
            .find_one_and_update(
                doc! {
                    "slug": slug,
                    "$or": [
                        { "status": "draft" },
                        { "status": "sending", "claimed_at": { "$lt": cutoff } },
                    ],
                },
                doc! { "$set": {
                    "status": "sending",
                    "claimed_by": pod_id,
                    "claimed_at": DateTime::now(),
                    "updated_at": DateTime::now(),
                } },
            )
            .return_document(mongodb::options::ReturnDocument::After)
            .await?;
        Ok(claimed)
    }

    /// FR-102 P5 — what the fan-out tagged this issue's messages with, set
    /// when it starts: the `utm_campaign` its links carry (`None` with the
    /// tags off), and whether its delivery events are recorded (every
    /// message names the issue for SendGrid, AND this server verifies the
    /// Event Webhook — without the key, SendGrid's posts are refused and
    /// the issue's delivery can never be measured). Re-stamped by a resume.
    pub async fn stamp_send_tags(
        &self,
        slug: &str,
        campaign: Option<&str>,
        delivery_events: bool,
    ) -> DaoResult<bool> {
        let update = match campaign {
            Some(c) => doc! { "$set": { "campaign": c, "delivery_events": delivery_events } },
            None => doc! {
                "$set": { "delivery_events": delivery_events },
                "$unset": { "campaign": "" },
            },
        };
        self.base.update_one(doc! { "slug": slug }, update).await
    }

    /// Keep the claim visibly alive while the fan-out runs. Scoped to this
    /// pod's own claim so a superseded task can't extend a claim it lost.
    pub async fn heartbeat(&self, slug: &str, pod_id: &str) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "slug": slug, "status": "sending", "claimed_by": pod_id },
                doc! { "$set": { "claimed_at": DateTime::now() } },
            )
            .await
    }

    /// Terminal — `completed`, never "sent": the counts carry the truth.
    pub async fn complete(
        &self,
        slug: &str,
        counts: meshharbor_db::models::IssueCounts,
    ) -> DaoResult<bool> {
        let counts = bson::to_bson(&counts)?;
        self.base
            .update_one(
                doc! { "slug": slug, "status": "sending" },
                doc! {
                    "$set": {
                        "status": "completed",
                        "counts": counts,
                        "sent_at": DateTime::now(),
                        "updated_at": DateTime::now(),
                    },
                    "$unset": { "claimed_by": "", "claimed_at": "" },
                },
            )
            .await
    }
}
