// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-126 P2 — the meeting whiteboard: one Excalidraw scene per room, relayed over the meeting
//! socket and kept with the room.
//!
//! The server never draws and never interprets a shape. It keeps, per room, the latest copy of
//! every element by id and merges by Excalidraw's own rule, so every browser converges on the
//! same scene whatever order the edits arrive in: the higher `version` wins, and on a tie the
//! lower `versionNonce`. A deleted element stays as a tombstone (`isDeleted`), or a late joiner
//! would bring it back.
//!
//! Who may draw: the connection must have joined the room's meeting (`dispatch_media_local`
//! gates every command but join and leave), so it is the meeting's own gate. The commands
//! follow the meeting's routing, so the board lives on the pod that owns the meeting.
//!
//! Kept with the room in `meeting_whiteboards` (`_id` = the room id), written at most every
//! [`FLUSH_AFTER`] while someone draws. A board leaves memory when its meeting is empty and it
//! has been written.
//!
//! Kill switch: `meetings.whiteboard = false` (`MESHHARBOR__MEETINGS__WHITEBOARD`).

use std::{collections::HashMap, sync::Arc, time::Duration};

use bson::{doc, oid::ObjectId};
use dashmap::DashMap;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::ConferenceState;

pub const COLLECTION: &str = "meeting_whiteboards";
/// One update's elements, serialized. A stroke is a few hundred bytes; a paste of many shapes
/// stays far below this.
pub const MAX_UPDATE_BYTES: usize = 512 * 1024;
/// A whole board, serialized. Below Mongo's 16 MiB document limit with room for BSON overhead.
pub const MAX_BOARD_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_ELEMENTS: usize = 20_000;
const MAX_ID_LEN: usize = 64;
const FLUSH_AFTER: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct Board {
    elements: HashMap<String, Value>,
    bytes: usize,
    tenant_id: Option<ObjectId>,
    dirty: bool,
    flush_scheduled: bool,
}

#[derive(Default)]
pub struct Whiteboards {
    boards: DashMap<ObjectId, Arc<Mutex<Option<Board>>>>,
}

/// Why an update was refused as a whole.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NotAList,
    TooLarge,
    BoardFull,
}

impl Refusal {
    fn message(&self) -> &'static str {
        match self {
            Refusal::NotAList => "Whiteboard update must carry a list of elements",
            Refusal::TooLarge => "Whiteboard update too large",
            Refusal::BoardFull => "The whiteboard is full",
        }
    }
}

/// An element's identity and order, or `None` for anything that is not a drawable element
/// this board keeps. Images are refused: their pixels travel as separate files, which this
/// board does not carry.
fn key(e: &Value) -> Option<(&str, u64, i64)> {
    let id = e.get("id")?.as_str()?;
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return None;
    }
    if e.get("type").and_then(Value::as_str) == Some("image") {
        return None;
    }
    let version = e.get("version")?.as_u64()?;
    let nonce = e.get("versionNonce")?.as_i64()?;
    Some((id, version, nonce))
}

/// Excalidraw's rule: `incoming` replaces `current` when it is newer.
fn wins(incoming: (u64, i64), current: (u64, i64)) -> bool {
    incoming.0 > current.0 || (incoming.0 == current.0 && incoming.1 < current.1)
}

impl Board {
    fn from_elements(elements: Vec<Value>) -> Self {
        let mut board = Board::default();
        for e in elements {
            if let Some((id, _, _)) = key(&e) {
                let id = id.to_string();
                board.bytes += serialized_len(&e);
                board.elements.insert(id, e);
            }
        }
        board
    }

    /// Merge `incoming` and return the elements that won (what the others must apply).
    pub fn merge(&mut self, incoming: &Value) -> Result<Vec<Value>, Refusal> {
        let list = incoming.as_array().ok_or(Refusal::NotAList)?;
        if serialized_len(incoming) > MAX_UPDATE_BYTES {
            return Err(Refusal::TooLarge);
        }
        let mut accepted = Vec::new();
        for e in list {
            let Some((id, version, nonce)) = key(e) else {
                continue;
            };
            let size = serialized_len(e);
            match self.elements.get(id) {
                Some(cur) => {
                    let (_, cv, cn) = key(cur).expect("stored elements have a key");
                    if !wins((version, nonce), (cv, cn)) {
                        continue;
                    }
                    let old = serialized_len(cur);
                    if self.bytes - old + size > MAX_BOARD_BYTES {
                        return Err(Refusal::BoardFull);
                    }
                    self.bytes = self.bytes - old + size;
                }
                None => {
                    if self.elements.len() >= MAX_ELEMENTS || self.bytes + size > MAX_BOARD_BYTES {
                        return Err(Refusal::BoardFull);
                    }
                    self.bytes += size;
                }
            }
            self.elements.insert(id.to_string(), e.clone());
            accepted.push(e.clone());
        }
        if !accepted.is_empty() {
            self.dirty = true;
        }
        Ok(accepted)
    }

    pub fn scene(&self) -> Vec<Value> {
        self.elements.values().cloned().collect()
    }
}

fn serialized_len(v: &Value) -> usize {
    serde_json::to_vec(v)
        .map(|b| b.len())
        .unwrap_or(usize::MAX / 4)
}

impl Whiteboards {
    fn slot(&self, rid: ObjectId) -> Arc<Mutex<Option<Board>>> {
        self.boards.entry(rid).or_default().clone()
    }
}

/// The room's board, read from Mongo the first time this pod needs it.
async fn loaded(
    state: &ConferenceState,
    rid: ObjectId,
) -> anyhow::Result<Arc<Mutex<Option<Board>>>> {
    let slot = state.whiteboards.slot(rid);
    {
        let mut guard = slot.lock().await;
        if guard.is_none() {
            let coll = state.db.collection::<bson::Document>(COLLECTION);
            let elements: Vec<Value> = match coll.find_one(doc! { "_id": rid }).await? {
                Some(d) => match d.get_array("elements") {
                    Ok(arr) => arr
                        .iter()
                        .map(|b| b.clone().into_relaxed_extjson())
                        .collect(),
                    Err(_) => Vec::new(),
                },
                None => Vec::new(),
            };
            let mut board = Board::from_elements(elements);
            board.tenant_id = state
                .rooms
                .base
                .find_by_id(rid)
                .await
                .ok()
                .map(|r| r.tenant_id);
            *guard = Some(board);
        }
    }
    Ok(slot)
}

fn room_id(data: Option<&Value>) -> Option<ObjectId> {
    data.and_then(|d| d.get("room_id"))
        .and_then(Value::as_str)
        .and_then(|s| ObjectId::parse_str(s).ok())
}

async fn switched_off(state: &ConferenceState, connection_id: &str) -> bool {
    if state.settings.meetings.whiteboard {
        return false;
    }
    crate::ws_media::send_media_error(
        state,
        connection_id,
        "The whiteboard is switched off on this server",
    )
    .await;
    true
}

/// `media:whiteboard_join` — answer the board as it is.
pub async fn handle_join(state: &ConferenceState, connection_id: &str, data: Option<&Value>) {
    if switched_off(state, connection_id).await {
        return;
    }
    let Some(rid) = room_id(data) else {
        crate::ws_media::send_media_error(state, connection_id, "Invalid room_id").await;
        return;
    };
    let slot = match loaded(state, rid).await {
        Ok(s) => s,
        Err(e) => {
            warn!(?rid, %e, "whiteboard: the board could not be read");
            crate::ws_media::send_media_error(
                state,
                connection_id,
                "The whiteboard could not be read",
            )
            .await;
            return;
        }
    };
    let elements = slot
        .lock()
        .await
        .as_ref()
        .map(Board::scene)
        .unwrap_or_default();
    let msg = json!({
        "type": "media:whiteboard_scene",
        "data": { "room_id": rid.to_hex(), "elements": elements },
    });
    meshharbor_core::ws::dispatcher::send_to_connection_routed(
        &state.ws_storage,
        &state.redis_pubsub,
        connection_id,
        &msg,
    )
    .await;
}

/// `media:whiteboard_update` — merge, relay what won to the rest of the meeting, keep it.
pub async fn handle_update(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    data: Option<&Value>,
) {
    if switched_off(state, connection_id).await {
        return;
    }
    let Some(rid) = room_id(data) else {
        crate::ws_media::send_media_error(state, connection_id, "Invalid room_id").await;
        return;
    };
    let incoming = data
        .and_then(|d| d.get("elements"))
        .cloned()
        .unwrap_or(Value::Null);
    let slot = match loaded(state, rid).await {
        Ok(s) => s,
        Err(e) => {
            warn!(?rid, %e, "whiteboard: the board could not be read");
            crate::ws_media::send_media_error(
                state,
                connection_id,
                "The whiteboard could not be read",
            )
            .await;
            return;
        }
    };
    let (accepted, schedule) = {
        let mut guard = slot.lock().await;
        let board = guard.get_or_insert_with(Board::default);
        match board.merge(&incoming) {
            Ok(accepted) => {
                let schedule = !accepted.is_empty() && !board.flush_scheduled;
                if schedule {
                    board.flush_scheduled = true;
                }
                (accepted, schedule)
            }
            Err(r) => {
                drop(guard);
                debug!(?rid, ?user_id, ?r, "whiteboard update refused");
                crate::ws_media::send_media_error(state, connection_id, r.message()).await;
                return;
            }
        }
    };
    if accepted.is_empty() {
        return;
    }
    let msg = json!({
        "type": "media:whiteboard_update",
        "data": { "room_id": rid.to_hex(), "user_id": user_id.to_hex(), "elements": accepted },
    });
    for cid in state
        .room_manager
        .get_other_connection_ids(&rid, connection_id)
    {
        meshharbor_core::ws::dispatcher::send_to_connection_routed(
            &state.ws_storage,
            &state.redis_pubsub,
            &cid,
            &msg,
        )
        .await;
    }
    if schedule {
        let state = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(FLUSH_AFTER).await;
            flush(&state, rid).await;
        });
    }
}

/// Write the board if it changed; drop it from memory when its meeting is empty.
pub async fn flush(state: &ConferenceState, rid: ObjectId) {
    let slot = state.whiteboards.slot(rid);
    let (elements, tenant_id) = {
        let mut guard = slot.lock().await;
        let Some(board) = guard.as_mut() else {
            return;
        };
        board.flush_scheduled = false;
        if !board.dirty {
            return;
        }
        board.dirty = false;
        (board.scene(), board.tenant_id)
    };
    let coll = state.db.collection::<bson::Document>(COLLECTION);
    let written = match bson::to_bson(&elements) {
        Ok(arr) => coll
            .replace_one(
                doc! { "_id": rid },
                doc! {
                    "_id": rid,
                    "tenant_id": tenant_id,
                    "elements": arr,
                    "updated_at": bson::DateTime::now(),
                },
            )
            .upsert(true)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from),
        Err(e) => Err(anyhow::Error::from(e)),
    };
    match written {
        Ok(()) => {
            if state.room_manager.get_participant_user_ids(&rid).is_empty() {
                let guard = slot.lock().await;
                if guard.as_ref().is_some_and(|b| !b.dirty) {
                    drop(guard);
                    state.whiteboards.boards.remove(&rid);
                }
            }
        }
        Err(e) => {
            warn!(?rid, %e, "whiteboard: the board could not be written; keeping it in memory");
            if let Some(b) = slot.lock().await.as_mut() {
                b.dirty = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(id: &str, version: u64, nonce: i64) -> Value {
        json!({ "id": id, "type": "rectangle", "version": version, "versionNonce": nonce, "x": 1 })
    }

    #[test]
    fn the_newer_copy_wins_whatever_the_order() {
        let mut a = Board::default();
        let mut b = Board::default();
        let edits = [
            el("r1", 1, 50),
            el("r1", 3, 7),
            el("r1", 2, 1),
            el("r1", 3, 5),
        ];
        for e in &edits {
            a.merge(&json!([e])).unwrap();
        }
        for e in edits.iter().rev() {
            b.merge(&json!([e])).unwrap();
        }
        // Version 3 with the lower nonce, on both boards.
        assert_eq!(a.elements["r1"]["versionNonce"], 5);
        assert_eq!(b.elements["r1"]["versionNonce"], 5);
    }

    #[test]
    fn only_what_won_is_relayed() {
        let mut b = Board::default();
        assert_eq!(b.merge(&json!([el("x", 2, 1)])).unwrap().len(), 1);
        assert!(
            b.merge(&json!([el("x", 1, 1)])).unwrap().is_empty(),
            "older"
        );
        assert!(
            b.merge(&json!([el("x", 2, 1)])).unwrap().is_empty(),
            "same copy"
        );
        assert_eq!(b.merge(&json!([el("x", 3, 9)])).unwrap().len(), 1);
    }

    #[test]
    fn tombstones_are_kept() {
        let mut b = Board::default();
        b.merge(&json!([el("x", 1, 1)])).unwrap();
        let mut gone = el("x", 2, 1);
        gone["isDeleted"] = json!(true);
        b.merge(&json!([gone])).unwrap();
        assert_eq!(b.scene().len(), 1);
        assert_eq!(b.scene()[0]["isDeleted"], true);
    }

    #[test]
    fn junk_and_images_are_skipped_and_bad_shapes_refused() {
        let mut b = Board::default();
        let got = b
            .merge(&json!([
                { "id": "", "version": 1, "versionNonce": 1 },
                { "id": "a".repeat(65), "version": 1, "versionNonce": 1 },
                { "id": "img", "type": "image", "version": 1, "versionNonce": 1 },
                { "id": "noversion", "versionNonce": 1 },
                "not an object",
                el("ok", 1, 1),
            ]))
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(b.merge(&json!({ "id": "x" })), Err(Refusal::NotAList));
        let big = json!([{ "id": "big", "version": 1, "versionNonce": 1, "pad": "x".repeat(MAX_UPDATE_BYTES) }]);
        assert_eq!(b.merge(&big), Err(Refusal::TooLarge));
    }

    #[test]
    fn a_full_board_refuses_more() {
        let mut b = Board::default();
        let pad = "x".repeat(400 * 1024);
        let mut n = 0;
        loop {
            let e = json!([{ "id": format!("p{n}"), "version": 1, "versionNonce": 1, "pad": pad }]);
            match b.merge(&e) {
                Ok(_) => n += 1,
                Err(r) => {
                    assert_eq!(r, Refusal::BoardFull);
                    break;
                }
            }
            assert!(n < 100, "never filled");
        }
        assert!(b.bytes <= MAX_BOARD_BYTES);
    }
}
