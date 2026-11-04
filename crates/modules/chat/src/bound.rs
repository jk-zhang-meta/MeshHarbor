// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 — what another module may do with chat, through chat: a room bound
//! to an object that module owns, and messages an agent writes into it.
//!
//! The first caller is `hive`: an agent session is a `Secret` room bound to
//! `{module: "hive", ref: <session id>}`, and each turn is a stub message the
//! session authors. Chat keeps its own invariants on this path exactly as on
//! the REST one — who may read the room, the fan-out to its members — and the
//! caller supplies only what it owns: the name, the binding, the content.
//!
//! [`BoundChat`] is STATELESS — the core plus two DAOs over `core.db` — so a
//! module built on chat re-creates it with [`BoundChat::new`] rather than
//! taking chat's state as its `Module::Deps` (FR-69 rule 5: only a live object
//! is a dependency; `remote`'s Hub is one, a DAO is not).
//!
//! None of this is reachable from a chat route: no user can bind a room or
//! post as an agent. Who belongs in a bound room is the binding module's
//! decision (P1c), made behind that module's own gated routes.

use std::collections::HashMap;
use std::sync::Arc;

use bson::oid::ObjectId;
use meshharbor_core::Core;
use meshharbor_db::models::{Binding, Message, Room};
use meshharbor_services::dao::base::{DaoError, DaoResult};
use meshharbor_services::dao::message::MessageDao;
use meshharbor_services::dao::room::RoomDao;

/// Chat's bound-room surface for another module.
#[derive(Clone)]
pub struct BoundChat {
    core: Core,
    rooms: Arc<RoomDao>,
    messages: Arc<MessageDao>,
}

impl BoundChat {
    /// Built from the core alone: nothing here outlives a call.
    pub fn new(core: &Core) -> Self {
        Self {
            rooms: Arc::new(RoomDao::new(&core.db)),
            messages: Arc::new(MessageDao::new(&core.db)),
            core: core.clone(),
        }
    }

    /// A `Secret` room bound to `binding`, with `owner` as its only member,
    /// at a `path` the caller guarantees unique.
    pub async fn create_bound_room(
        &self,
        tenant_id: ObjectId,
        name: String,
        path: String,
        owner: ObjectId,
        binding: Binding,
    ) -> DaoResult<Room> {
        self.rooms
            .create_bound(tenant_id, name, path, owner, binding)
            .await
    }

    /// FR-90 P1c — make `user` a member of a room bound to `module`. The
    /// module owns who belongs in ITS rooms: chat's own `join` refuses a
    /// Secret room to anyone not already in it, and no route reaches this.
    /// `Ok(false)` = already a member (the unique `{room_id, user_id}` index
    /// decides, so two concurrent adds make one row). A room that is not
    /// bound to `module` is [`DaoError::NotFound`]: a module manages its own
    /// rooms and nobody else's.
    pub async fn add_bound_member(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        module: &str,
        user: ObjectId,
    ) -> DaoResult<bool> {
        self.bound_room(tenant_id, room_id, module).await?;
        match self.rooms.join(tenant_id, room_id, user).await {
            Ok(_) => Ok(true),
            Err(DaoError::DuplicateKey(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// FR-90 P1c — remove `user` from a room bound to `module`. `Ok(false)`
    /// = they were not a member.
    pub async fn remove_bound_member(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        module: &str,
        user: ObjectId,
    ) -> DaoResult<bool> {
        self.bound_room(tenant_id, room_id, module).await?;
        self.rooms.leave(tenant_id, room_id, user).await
    }

    /// FR-90 P2g-2 — delete a room bound to `module`, with everything chat
    /// holds in it (its messages, reactions, members and files), as chat's
    /// own delete does. `Ok(false)` = no such room any more, or one not bound
    /// to `module`: a module deletes its own rooms and nobody else's.
    pub async fn delete_bound_room(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        module: &str,
    ) -> DaoResult<bool> {
        match self.bound_room(tenant_id, room_id, module).await {
            Ok(_) => {}
            Err(DaoError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        }
        self.rooms.cascade_delete(tenant_id, room_id).await?;
        Ok(true)
    }

    /// FR-90 P1c — who is in `room_id`, as user ids.
    pub async fn member_ids(&self, room_id: ObjectId) -> DaoResult<Vec<ObjectId>> {
        self.rooms.find_member_user_ids(room_id).await
    }

    async fn bound_room(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        module: &str,
    ) -> DaoResult<Room> {
        match self
            .rooms
            .base
            .find_one(bson::doc! { "_id": room_id, "tenant_id": tenant_id })
            .await?
        {
            Some(room) if room.binding.as_ref().is_some_and(|b| b.module == module) => Ok(room),
            _ => Err(DaoError::NotFound),
        }
    }

    /// Whether `user` is a member of `room_id` in `tenant_id` — chat's own
    /// rule, so a module deciding who may see what a room is about decides it
    /// exactly as the room's routes do.
    pub async fn is_member(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        user: ObjectId,
    ) -> DaoResult<bool> {
        self.rooms.is_member(tenant_id, room_id, user).await
    }

    /// FR-90 P2i-2 — which of `rooms` `user` is a member of in `tenant_id`:
    /// [`Self::is_member`]'s rule for many rooms at once, in one read. A
    /// module checking a person's right to read many things answers as
    /// chat's routes would for each.
    pub async fn member_rooms_of(
        &self,
        tenant_id: ObjectId,
        user: ObjectId,
        rooms: &[ObjectId],
    ) -> DaoResult<Vec<ObjectId>> {
        self.rooms.member_room_ids(tenant_id, user, rooms).await
    }

    /// FR-90 P2i-2 — every room `user` is a member of in `tenant_id`: each
    /// one [`Self::is_member`] answers yes for.
    pub async fn rooms_of(&self, tenant_id: ObjectId, user: ObjectId) -> DaoResult<Vec<ObjectId>> {
        self.rooms.rooms_of_member(tenant_id, user).await
    }

    /// Post a message authored by an agent (`author_id`, shown as
    /// `author_display`) into `room_id`, and fan it out to the room's members
    /// as `message:create` — the event every client already renders.
    pub async fn post_agent_message(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        author_id: ObjectId,
        author_display: String,
        binding: Binding,
        content: String,
    ) -> DaoResult<ObjectId> {
        let message = self
            .messages
            .create_agent(
                tenant_id,
                room_id,
                author_id,
                author_display,
                binding,
                content,
            )
            .await?;
        let id = message.id.expect("a stored message has an id");
        self.fan_out(room_id, "message:create", message).await;
        Ok(id)
    }

    /// Replace an agent message's content and fan out `message:update`.
    /// `false` = no such agent message in this tenant and room — a person's
    /// message is never touched by this path.
    pub async fn update_agent_message(
        &self,
        tenant_id: ObjectId,
        room_id: ObjectId,
        message_id: ObjectId,
        content: String,
    ) -> DaoResult<bool> {
        match self
            .messages
            .update_agent_content(tenant_id, room_id, message_id, content)
            .await?
        {
            Some(message) => {
                self.fan_out(room_id, "message:update", message).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn fan_out(&self, room_id: ObjectId, kind: &str, message: Message) {
        let members = match self.rooms.find_member_user_ids(room_id).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(room = %room_id, %e, "chat: agent message not fanned out — members unreadable");
                return;
            }
        };
        let response = crate::message::to_response(message, &HashMap::new(), None);
        let event = serde_json::json!({ "type": kind, "data": &response });
        meshharbor_core::ws::dispatcher::broadcast_with_redis(
            &self.core.ws_storage,
            &self.core.redis_pubsub,
            &members,
            &event,
        )
        .await;
    }
}
