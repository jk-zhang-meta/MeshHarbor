// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::{
    AuthorType, ContentType, Mentions, Message, MessageAttachment, MessageType, ReactionSummary,
};
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct MessageDao {
    pub base: BaseDao<Message>,
}

impl MessageDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, Message::COLLECTION),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        author_id: ObjectId,
        content: String,
        thread_id: Option<ObjectId>,
        referenced_message_id: Option<ObjectId>,
        nonce: Option<String>,
        mentions: Option<Mentions>,
    ) -> DaoResult<Message> {
        self.create_with_attachments(
            tenant_id,
            room_id,
            author_id,
            content,
            thread_id,
            referenced_message_id,
            nonce,
            mentions,
            Vec::new(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_attachments(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        author_id: ObjectId,
        content: String,
        thread_id: Option<ObjectId>,
        referenced_message_id: Option<ObjectId>,
        nonce: Option<String>,
        mentions: Option<Mentions>,
        attachments: Vec<MessageAttachment>,
    ) -> DaoResult<Message> {
        let now = DateTime::now();
        let message_type = if referenced_message_id.is_some() {
            MessageType::Reply
        } else {
            MessageType::Default
        };

        let message = Message {
            id: None,
            tenant_id,
            room_id,
            thread_id,
            is_thread_root: false,
            thread_metadata: None,
            author_id,
            author_type: AuthorType::User,
            author_display: None,
            binding: None,
            content,
            content_type: ContentType::Markdown,
            message_type,
            embeds: Vec::new(),
            attachments,
            mentions: mentions.unwrap_or_default(),
            reaction_summary: Vec::new(),
            referenced_message_id,
            is_pinned: false,
            is_edited: false,
            edited_at: None,
            nonce,
            readby: vec![author_id], // Author has read their own message
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let id = self.base.insert_one(&message).await?;

        // Update thread metadata on parent message when a thread reply is created
        if let Some(parent_id) = thread_id {
            let _ = self.update_thread_metadata(parent_id, author_id).await;
        }

        self.base.find_by_id(id).await
    }

    /// FR-90 — a message whose author is not a user: an agent session's turn
    /// stub. `author_id` is the session's id, `author_display` the name a
    /// client shows ("Claude · mars"), `binding` what the owning module calls
    /// it. Never a reply, never mentions anyone, read by nobody yet.
    ///
    /// Not reachable from the REST route — only a module that owns sessions
    /// writes these, so no user can post as an agent.
    pub async fn create_agent(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        author_id: ObjectId,
        author_display: String,
        binding: meshharbor_db::models::Binding,
        content: String,
    ) -> DaoResult<Message> {
        let now = DateTime::now();
        let message = Message {
            id: None,
            tenant_id,
            room_id,
            thread_id: None,
            is_thread_root: false,
            thread_metadata: None,
            author_id,
            author_type: AuthorType::Bot,
            author_display: Some(author_display),
            binding: Some(binding),
            content,
            content_type: ContentType::Markdown,
            message_type: MessageType::Default,
            embeds: Vec::new(),
            attachments: Vec::new(),
            mentions: Mentions::default(),
            reaction_summary: Vec::new(),
            referenced_message_id: None,
            is_pinned: false,
            is_edited: false,
            edited_at: None,
            nonce: None,
            readby: Vec::new(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let id = self.base.insert_one(&message).await?;
        self.base.find_by_id(id).await
    }

    /// FR-90 — replace an agent message's content (a turn's stub as the turn
    /// progresses). Only a live `bot` message in this tenant AND this room
    /// moves, so this can never rewrite what a person wrote, nor a message
    /// the caller did not name the room of.
    pub async fn update_agent_content(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        message_id: ObjectId,
        content: String,
    ) -> DaoResult<Option<Message>> {
        let updated = self
            .base
            .update_one(
                doc! {
                    "_id": message_id,
                    "tenant_id": tenant_id,
                    "room_id": room_id,
                    "author_type": "bot",
                    "deleted_at": null,
                },
                doc! { "$set": { "content": content, "updated_at": DateTime::now() } },
            )
            .await?;
        if !updated {
            return Ok(None);
        }
        Ok(Some(self.base.find_by_id(message_id).await?))
    }

    /// FR-32 — live messages in the tenant, for **reporting only**.
    ///
    /// `max_message_history` is deliberately NOT gated. It is a retention
    /// bound, not a cap on an action, and the three ways to enforce one are all
    /// bad in P1: deleting destroys customer data irreversibly, refusing writes
    /// turns a chat product read-only, and bounding reads honestly means
    /// touching `find_in_room`, `find_pinned`, `find_thread_replies`, both
    /// export paths and full-text search — miss the exports and the limit is
    /// theatre, since anyone can dump the full history to PDF.
    ///
    /// But P1's question — *who would be denied* — needs no gate to answer.
    /// This count answers it, so P2 and P3 get their input at the cost of one
    /// query instead of a six-call-site retention view built on a limit that
    /// may not survive re-pricing (messages are small documents; this limit has
    /// almost no cost basis and exists for upgrade pressure).
    pub async fn count_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base
            .count(doc! { "tenant_id": tenant_id, "deleted_at": null })
            .await
    }

    pub async fn find_in_room(
        &self,
        room_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<Message>> {
        let mut filter = doc! { "room_id": room_id, "deleted_at": null, "thread_id": null };

        // Support cursor-based pagination via `before` timestamp
        if let Some(ref before) = params.before
            && let Ok(dt) = bson::DateTime::parse_rfc3339_str(before)
        {
            filter.insert("created_at", doc! { "$lt": dt });
        }

        self.base
            .find_paginated(filter, Some(doc! { "created_at": -1 }), params)
            .await
    }

    pub async fn find_thread_replies(
        &self,
        thread_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<Message>> {
        self.base
            .find_paginated(
                doc! { "thread_id": thread_id, "deleted_at": null },
                Some(doc! { "created_at": 1 }),
                params,
            )
            .await
    }

    pub async fn find_pinned(&self, room_id: ObjectId) -> DaoResult<Vec<Message>> {
        self.base
            .find_many(
                doc! { "room_id": room_id, "is_pinned": true, "deleted_at": null },
                Some(doc! { "created_at": -1 }),
            )
            .await
    }

    pub async fn update_content(
        &self,
        tenant_id: ObjectId,
        message_id: ObjectId,
        author_id: ObjectId,
        content: String,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! {
                    "_id": message_id,
                    "tenant_id": tenant_id,
                    "author_id": author_id,
                    "deleted_at": null,
                },
                doc! {
                    "$set": {
                        "content": content,
                        "is_edited": true,
                        "edited_at": DateTime::now(),
                    }
                },
            )
            .await
    }

    pub async fn toggle_pin(
        &self,
        tenant_id: ObjectId,
        message_id: ObjectId,
        pinned: bool,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": message_id, "tenant_id": tenant_id },
                doc! { "$set": { "is_pinned": pinned } },
            )
            .await
    }

    /// Atomically update thread metadata on the parent message when a reply is created.
    pub async fn update_thread_metadata(
        &self,
        parent_id: ObjectId,
        reply_author_id: ObjectId,
    ) -> DaoResult<bool> {
        let now = DateTime::now();
        // First, ensure thread_metadata is not null (MongoDB $inc/$addToSet fail on null subdocs)
        let _ = self
            .base
            .collection()
            .update_one(
                doc! { "_id": parent_id, "thread_metadata": null },
                doc! { "$set": {
                    "thread_metadata": {
                        "reply_count": 0_i32,
                        "last_reply_at": null,
                        "last_reply_user_id": null,
                        "participant_ids": [],
                    },
                }},
            )
            .await;
        // Now safely increment/update the nested fields
        self.base
            .update_one(
                doc! { "_id": parent_id },
                doc! {
                    "$set": {
                        "is_thread_root": true,
                        "thread_metadata.last_reply_at": now,
                        "thread_metadata.last_reply_user_id": reply_author_id,
                    },
                    "$inc": {
                        "thread_metadata.reply_count": 1_i32,
                    },
                    "$addToSet": {
                        "thread_metadata.participant_ids": reply_author_id,
                    },
                },
            )
            .await
    }

    /// Mark messages in a room as read by a user
    pub async fn mark_read(
        &self,
        room_id: ObjectId,
        user_id: ObjectId,
        message_ids: &[ObjectId],
    ) -> DaoResult<u64> {
        let result = self
            .base
            .collection()
            .update_many(
                doc! {
                    "_id": { "$in": message_ids },
                    "room_id": room_id,
                    "readby": { "$ne": user_id },
                },
                doc! { "$addToSet": { "readby": user_id } },
            )
            .await?;
        Ok(result.modified_count)
    }

    /// Mark EVERY unread message in the room read for this user — the exact
    /// same filter as `unread_count`, so the badge is guaranteed to reach 0.
    /// (2026-08-04: unread counted messages outside the newest-25 fetch
    /// window and messages read inside the call view; a broken scroll-up
    /// cursor made the older ones unreachable → permanently stuck badges.)
    pub async fn mark_all_read(&self, room_id: ObjectId, user_id: ObjectId) -> DaoResult<u64> {
        let result = self
            .base
            .collection()
            .update_many(
                doc! {
                    "room_id": room_id,
                    "deleted_at": null,
                    "thread_id": null,
                    "readby": { "$ne": user_id },
                },
                doc! { "$addToSet": { "readby": user_id } },
            )
            .await?;
        Ok(result.modified_count)
    }

    /// Count unread messages for a user in a room
    pub async fn unread_count(&self, room_id: ObjectId, user_id: ObjectId) -> DaoResult<u64> {
        let count = self
            .base
            .collection()
            .count_documents(doc! {
                "room_id": room_id,
                "deleted_at": null,
                "thread_id": null,
                "readby": { "$ne": user_id },
            })
            .await?;
        Ok(count)
    }

    /// Count unread messages for a user across multiple rooms
    pub async fn unread_counts_by_room(
        &self,
        room_ids: &[ObjectId],
        user_id: ObjectId,
    ) -> DaoResult<Vec<(ObjectId, u64)>> {
        use bson::Bson;
        use futures::TryStreamExt;

        let pipeline = vec![
            doc! { "$match": {
                "room_id": { "$in": room_ids.iter().map(|id| Bson::ObjectId(*id)).collect::<Vec<_>>() },
                "deleted_at": null,
                "thread_id": null,
                "readby": { "$ne": user_id },
            }},
            doc! { "$group": {
                "_id": "$room_id",
                "count": { "$sum": 1 },
            }},
        ];

        let mut cursor = self.base.collection().aggregate(pipeline).await?;
        let mut results = Vec::new();
        while let Some(doc) = cursor.try_next().await? {
            if let (Some(room_id), Some(count)) =
                (doc.get_object_id("_id").ok(), doc.get_i32("count").ok())
            {
                results.push((room_id, count as u64));
            }
        }
        Ok(results)
    }

    pub async fn update_reaction_summary(
        &self,
        message_id: ObjectId,
        summary: &[ReactionSummary],
    ) -> DaoResult<bool> {
        let summary_bson: Vec<bson::Bson> = summary
            .iter()
            .map(|s| bson::to_bson(s).unwrap_or(bson::Bson::Null))
            .collect();

        self.base
            .update_one(
                doc! { "_id": message_id },
                doc! { "$set": { "reaction_summary": summary_bson } },
            )
            .await
    }
}
