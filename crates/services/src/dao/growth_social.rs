// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P8 — social reach, as the promotion pipeline pushes it (spec §3j,
//! D11): `growth_posts` and `growth_post_snapshots`.
//!
//! Core-level collections, like `growth_daily`: written by the `saas`
//! module's ingest routes through this DAO, read by the host's Channels and
//! Campaigns views — which keep reading what was pushed even on a server
//! that no longer mounts `saas` (and say why nothing new arrives).
//!
//! * A **post** is `(platform, platform_id)` — unique, so a re-push is an
//!   update of the same row: the account, format, url, publish time, the
//!   normalised campaign key and an optional `cost_cents`. Never its text:
//!   the ingest refuses any field that looks like a caption, a body or a
//!   title, and this shape has nowhere to put one.
//! * A **snapshot** is `(platform, platform_id, snapshot)` with `snapshot`
//!   one of `T+1d` · `T+7d` · `T+28d` — unique, and written ONCE: a second
//!   push of the same snapshot changes nothing (AC18). Its `metrics` keep the
//!   platform's own raw names, numbers only — a metric is only comparable to
//!   itself.
//!
//! Aggregates about our own content, no person: kept indefinitely (§3p).

use std::collections::BTreeMap;

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use mongodb::Database;
use serde::{Deserialize, Serialize};

use super::base::DaoResult;

pub const GROWTH_POSTS: &str = "growth_posts";
pub const GROWTH_POST_SNAPSHOTS: &str = "growth_post_snapshots";
/// The snapshot labels, in age order.
pub const SNAPSHOTS: [&str; 3] = ["T+1d", "T+7d", "T+28d"];
/// The most posts one view loads — far above the pipeline's cadence; a
/// bound, not a page.
pub const MAX_POSTS: i64 = 5_000;

/// The campaign key a post's link carries, normalised at ingest — the same
/// four fields as `meshharbor_core::campaign::CampaignKey`, which this crate
/// sits below.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PostKey {
    pub source: String,
    #[serde(default)]
    pub medium: Option<String>,
    #[serde(default)]
    pub campaign: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

/// One post, as stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrowthPost {
    #[serde(rename = "_id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub platform: String,
    pub platform_id: String,
    /// The account it was posted from (a handle of OURS, never a person's).
    pub account: String,
    pub format: String,
    pub url: String,
    pub published_at: DateTime,
    pub key: PostKey,
    /// What the post cost, when it cost anything (an X post with a link is
    /// billed per post).
    #[serde(default)]
    pub cost_cents: Option<i64>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

/// A post as the ingest hands it over: validated, normalised.
#[derive(Debug, Clone, PartialEq)]
pub struct NewPost {
    pub platform: String,
    pub platform_id: String,
    pub account: String,
    pub format: String,
    pub url: String,
    pub published_at: DateTime,
    pub key: PostKey,
    pub cost_cents: Option<i64>,
}

/// One metric snapshot, as stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PostSnapshot {
    #[serde(rename = "_id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub platform: String,
    pub platform_id: String,
    /// `T+1d` · `T+7d` · `T+28d`.
    pub snapshot: String,
    pub taken_at: DateTime,
    /// The platform's own metric names, verbatim; numbers only.
    pub metrics: BTreeMap<String, f64>,
    pub received_at: DateTime,
}

/// What a push did to its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Upserted {
    /// A new row.
    Created,
    /// An existing row whose fields changed.
    Updated,
    /// An existing row, already holding exactly this.
    Unchanged,
    /// A snapshot already stored: written once, never again.
    Duplicate,
}

pub struct GrowthSocialDao {
    db: Database,
}

impl GrowthSocialDao {
    pub fn new(db: &Database) -> Self {
        Self { db: db.clone() }
    }

    fn posts(&self) -> mongodb::Collection<Document> {
        self.db.collection::<Document>(GROWTH_POSTS)
    }

    fn snapshots(&self) -> mongodb::Collection<Document> {
        self.db.collection::<Document>(GROWTH_POST_SNAPSHOTS)
    }

    /// Create or update the post `(platform, platform_id)`. Idempotent: the
    /// same push twice is `Unchanged` the second time; a push that differs
    /// replaces the mutable fields (the newest description of the post wins)
    /// and is `Updated`.
    pub async fn upsert_post(&self, p: &NewPost, now: DateTime) -> DaoResult<Upserted> {
        let filter = doc! { "platform": &p.platform, "platform_id": &p.platform_id };
        let key = bson::to_bson(&p.key)?;
        let r = self
            .posts()
            .update_one(
                filter.clone(),
                doc! {
                    "$set": {
                        "account": &p.account,
                        "format": &p.format,
                        "url": &p.url,
                        "published_at": p.published_at,
                        "key": key,
                        "cost_cents": p.cost_cents.map(Bson::Int64).unwrap_or(Bson::Null),
                    },
                    "$setOnInsert": { "created_at": now, "updated_at": now },
                },
            )
            .upsert(true)
            .await?;
        if r.upserted_id.is_some() {
            return Ok(Upserted::Created);
        }
        if r.modified_count > 0 {
            self.posts()
                .update_one(filter, doc! { "$set": { "updated_at": now } })
                .await?;
            return Ok(Upserted::Updated);
        }
        Ok(Upserted::Unchanged)
    }

    /// Whether the post was ever pushed.
    pub async fn post_exists(&self, platform: &str, platform_id: &str) -> DaoResult<bool> {
        Ok(self
            .posts()
            .find_one(doc! { "platform": platform, "platform_id": platform_id })
            .projection(doc! { "_id": 1 })
            .await?
            .is_some())
    }

    /// Store a snapshot ONCE: the first push of `(platform, platform_id,
    /// snapshot)` is `Created`, every later one `Duplicate` and changes
    /// nothing — the stored values are the first observation's.
    pub async fn insert_snapshot_once(&self, s: &PostSnapshot) -> DaoResult<Upserted> {
        let metrics: Document = s
            .metrics
            .iter()
            .map(|(k, v)| (k.clone(), Bson::Double(*v)))
            .collect();
        let r = self
            .snapshots()
            .update_one(
                doc! { "platform": &s.platform, "platform_id": &s.platform_id, "snapshot": &s.snapshot },
                doc! { "$setOnInsert": {
                    "taken_at": s.taken_at,
                    "metrics": metrics,
                    "received_at": s.received_at,
                } },
            )
            .upsert(true)
            .await?;
        Ok(if r.upserted_id.is_some() {
            Upserted::Created
        } else {
            Upserted::Duplicate
        })
    }

    /// The posts published in `[from, to)`, oldest first, bounded by
    /// [`MAX_POSTS`]. Lenient per row: one unreadable row costs itself.
    pub async fn posts_published_between(
        &self,
        from: DateTime,
        to: DateTime,
    ) -> DaoResult<Vec<GrowthPost>> {
        let docs: Vec<Document> = self
            .posts()
            .find(doc! { "published_at": { "$gte": from, "$lt": to } })
            .sort(doc! { "published_at": 1 })
            .limit(MAX_POSTS)
            .await?
            .try_collect()
            .await?;
        Ok(docs
            .into_iter()
            .filter_map(|d| match bson::from_document::<GrowthPost>(d) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(error = %e, "growth_posts: skipping an unreadable row");
                    None
                }
            })
            .collect())
    }

    /// Every snapshot of the given posts.
    pub async fn snapshots_of(&self, posts: &[GrowthPost]) -> DaoResult<Vec<PostSnapshot>> {
        if posts.is_empty() {
            return Ok(Vec::new());
        }
        let or: Vec<Document> = posts
            .iter()
            .map(|p| doc! { "platform": &p.platform, "platform_id": &p.platform_id })
            .collect();
        let docs: Vec<Document> = self
            .snapshots()
            .find(doc! { "$or": or })
            .await?
            .try_collect()
            .await?;
        Ok(docs
            .into_iter()
            .filter_map(|d| bson::from_document::<PostSnapshot>(d).ok())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_post_and_a_snapshot_round_trip_and_carry_no_text_field() {
        let post = GrowthPost {
            id: None,
            platform: "linkedin".into(),
            platform_id: "urn:li:share:7123".into(),
            account: "meshharbor".into(),
            format: "post".into(),
            url: "https://www.linkedin.com/feed/update/urn:li:share:7123".into(),
            published_at: DateTime::now(),
            key: PostKey {
                source: "linkedin".into(),
                medium: Some("post".into()),
                campaign: Some("20261019-ssh".into()),
                content: None,
            },
            cost_cents: Some(500),
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
        };
        let doc = bson::to_document(&post).unwrap();
        assert!(!doc.contains_key("_id"), "the store assigns the id");
        for text in ["caption", "body", "text", "title", "description"] {
            assert!(!doc.contains_key(text), "{text}");
        }
        let back: GrowthPost = bson::from_document(doc).unwrap();
        assert_eq!(back, post);

        let snap = PostSnapshot {
            id: None,
            platform: "youtube".into(),
            platform_id: "dQw4w9WgXcQ".into(),
            snapshot: "T+7d".into(),
            taken_at: DateTime::now(),
            metrics: [
                ("views".to_string(), 120.0),
                ("averageViewPercentage".to_string(), 41.5),
            ]
            .into_iter()
            .collect(),
            received_at: DateTime::now(),
        };
        let back: PostSnapshot = bson::from_document(bson::to_document(&snap).unwrap()).unwrap();
        assert_eq!(back, snap);
        assert_eq!(SNAPSHOTS, ["T+1d", "T+7d", "T+28d"]);
    }

    #[test]
    fn the_outcomes_spell_as_the_wire_does() {
        for (o, s) in [
            (Upserted::Created, "created"),
            (Upserted::Updated, "updated"),
            (Upserted::Unchanged, "unchanged"),
            (Upserted::Duplicate, "duplicate"),
        ] {
            assert_eq!(serde_json::to_string(&o).unwrap(), format!("\"{s}\""));
        }
    }
}
