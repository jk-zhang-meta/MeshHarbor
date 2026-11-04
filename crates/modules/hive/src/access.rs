// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1c — who may read a session, and who may drive it, in one place:
//! the viewer's grant, the session routes and the room's stubs all ask here,
//! so none of them can drift from the others.
//!
//! | who | reads it | prompts it, answers its approvals | stops it, names its drivers |
//! |---|---|---|---|
//! | its owner | ✅ | ✅ while it is live | ✅ |
//! | a driver the owner named | ✅ | ✅ while it is live | — |
//! | another member of its room | ✅ | — | — |
//! | anyone else, in the org or not | — (a 404, like a bogus id) | — | — |
//!
//! ⚠️ A room member who is not a driver READS and TALKS — "message the room"
//! is ordinary chat — but nothing they write reaches the harness: a
//! multi-user room would otherwise be a prompt-injection channel with a seat
//! for every member (design §4.5).
//!
//! ⚠️ P1j — an ADOPTED session has no drivers at all, its owner included:
//! it runs in a terminal, which holds the harness, so nothing typed here could
//! reach it. Its owner reads it and names readers; the rest of the table holds.
//!
//! ⚠️ P2g-2 — a PURGED session is read by nobody, its owner included: it is
//! deleted, and its tombstone waits only for its devices to answer. A viewer
//! grant to it would stream the transcript from a device the purge has not
//! reached yet.

use bson::oid::ObjectId;
use meshharbor_core::Core;
use meshharbor_mod_chat::bound::BoundChat;

use crate::HiveState;
use crate::model::{AgentSession, SessionOrigin};

/// May `user` read `s`? In the org, and its owner or in the session's room —
/// chat's own membership rule. The owner reads it even out of its room: a
/// Secret room cannot be re-entered, and leaving it must not lock the owner
/// out of their own session. A session from before rooms (P0b/P0c) is its
/// owner's alone.
pub(crate) async fn may_read(state: &HiveState, s: &AgentSession, user: ObjectId) -> bool {
    may_read_with(&state.core, &state.chat, s, user).await
}

/// [`may_read`], for a caller holding the core rather than hive's state.
async fn may_read_with(core: &Core, chat: &BoundChat, s: &AgentSession, user: ObjectId) -> bool {
    if s.purged.is_some() {
        return false;
    }
    if !matches!(core.tenants.is_member(s.tenant_id, user).await, Ok(true)) {
        return false;
    }
    if s.owner_id == user {
        return true;
    }
    match s.room_id {
        Some(room) => matches!(chat.is_member(s.tenant_id, room, user).await, Ok(true)),
        None => false,
    }
}

/// FR-90 P3-4e — [`may_read`], for a module that keeps its own cards in the
/// session's room (the vault): who sees one of them at all.
pub async fn may_read_session(core: &Core, s: &AgentSession, user: ObjectId) -> bool {
    may_read_with(core, &BoundChat::new(core), s, user).await
}

/// FR-90 P3-4e — may `user` answer such a card NOW? This table's rule, the
/// one hive's own approvals are answered by: a driver who reads the session,
/// while it is live.
pub async fn may_answer(core: &Core, s: &AgentSession, user: ObjectId) -> bool {
    drives_now(s, user) && may_read_session(core, s, user).await
}

/// May `user` — already known to READ `s` ([`may_read`]: a driver who left
/// the room or the org drives nothing) — prompt it and answer its approvals
/// NOW: a driver, and the session still live.
pub(crate) fn drives_now(s: &AgentSession, user: ObjectId) -> bool {
    s.origin != SessionOrigin::Adopted && s.drives(user) && !s.status.is_terminal()
}
