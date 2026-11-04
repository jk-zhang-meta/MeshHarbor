// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use meshharbor_db::models::{EmojiRef, EmojiType, Reaction, ReactionSummary};

use super::base::{BaseDao, DaoError, DaoResult};
use super::message::MessageDao;

pub struct ReactionDao {
    pub base: BaseDao<Reaction>,
}

impl ReactionDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, Reaction::COLLECTION),
        }
    }

    pub async fn add(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        message_id: ObjectId,
        user_id: ObjectId,
        emoji: String,
    ) -> DaoResult<Reaction> {
        // Check if already reacted with same emoji
        let existing = self
            .base
            .find_one(doc! {
                "message_id": message_id,
                "user_id": user_id,
                "emoji.value": &emoji,
            })
            .await?;

        if existing.is_some() {
            return Err(DaoError::DuplicateKey(
                "Already reacted with this emoji".to_string(),
            ));
        }

        let reaction = Reaction {
            id: None,
            tenant_id,
            room_id,
            message_id,
            user_id,
            emoji: EmojiRef {
                emoji_type: EmojiType::Unicode,
                value: emoji,
                custom_emoji_id: None,
            },
            created_at: DateTime::now(),
        };

        let id = self.base.insert_one(&reaction).await?;
        self.base.find_by_id(id).await
    }

    pub async fn remove(
        &self,
        message_id: ObjectId,
        user_id: ObjectId,
        emoji: &str,
    ) -> DaoResult<bool> {
        let deleted = self
            .base
            .hard_delete(doc! {
                "message_id": message_id,
                "user_id": user_id,
                "emoji.value": emoji,
            })
            .await?;
        Ok(deleted > 0)
    }

    pub async fn get_summary(&self, message_id: ObjectId) -> DaoResult<Vec<ReactionSummary>> {
        use futures::TryStreamExt;

        let pipeline = vec![
            doc! { "$match": { "message_id": message_id } },
            doc! { "$group": { "_id": "$emoji.value", "count": { "$sum": 1 } } },
            doc! { "$sort": { "count": -1 } },
        ];

        let mut cursor = self
            .base
            .collection()
            .aggregate(pipeline)
            .await
            .map_err(DaoError::Mongo)?;

        let mut summaries = Vec::new();
        while let Some(doc) = cursor.try_next().await.map_err(DaoError::Mongo)? {
            let emoji = doc.get_str("_id").unwrap_or_default().to_string();
            let count = doc.get_i32("count").unwrap_or(0) as u32;
            summaries.push(ReactionSummary { emoji, count });
        }

        Ok(summaries)
    }

    pub async fn add_and_update_summary(
        &self,
        messages: &MessageDao,
        tenant_id: ObjectId,
        room_id: ObjectId,
        message_id: ObjectId,
        user_id: ObjectId,
        emoji: String,
    ) -> DaoResult<Reaction> {
        let reaction = self
            .add(tenant_id, room_id, message_id, user_id, emoji)
            .await?;

        let summary = self.get_summary(message_id).await?;
        messages
            .update_reaction_summary(message_id, &summary)
            .await?;

        Ok(reaction)
    }

    pub async fn remove_and_update_summary(
        &self,
        messages: &MessageDao,
        message_id: ObjectId,
        user_id: ObjectId,
        emoji: &str,
    ) -> DaoResult<bool> {
        let removed = self.remove(message_id, user_id, emoji).await?;
        if removed {
            let summary = self.get_summary(message_id).await?;
            messages
                .update_reaction_summary(message_id, &summary)
                .await?;
        }
        Ok(removed)
    }
}
