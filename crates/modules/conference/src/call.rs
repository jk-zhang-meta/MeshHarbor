// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Call lifecycle endpoints: start / join / leave / end / participants.
//!
//! FR-69 — conference's, not chat's: they drive mediasoup through the media
//! cluster and mint call sessions. Carved out of `room.rs` when the chat half
//! of that file moved into the `chat` module (P3); they stay in the host
//! until the `conference` module exists (P4), and `rooms` stays on
//! `ConferenceState` for them. Bodies unchanged.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use serde::Deserialize;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::ConferenceState;

// ── Call endpoints ──────────────────────────────────────────────

pub async fn call_start(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    // Stats PR-2 — transition-gated: only the caller that actually flips
    // the room to in_progress mints the call instance; a re-invoked
    // call/start (retry, second pod, second user) neither resets
    // actual_start_time nor creates a duplicate call_sessions doc.
    let call_id = ObjectId::new();
    if let Some(started_at) = state.rooms.start_call(rid, call_id).await?
        && state.settings.stats.enabled
        && let Err(e) = state
            .stats
            .create_call_session(call_id, tid, rid, auth.user_id, started_at)
            .await
    {
        tracing::debug!(room = %rid, %e, "call session create failed");
    }
    // C-4 — claim-or-route: creation is NX-claim-gated, so two pods
    // racing call/start build exactly ONE router. The claim loser skips
    // local creation — its members' `media:join` then routes to the
    // owner (the UI never reads these HTTP caps; the real ones arrive
    // via `media:router_capabilities` on the WS).
    let rtp_capabilities = match crate::media_cluster::resolve_media_route(&state, &rid, true).await
    {
        crate::media_cluster::MediaRoute::Local { .. } => state
            .room_manager
            .create_room(rid)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to create media room: {}", e)))?,
        crate::media_cluster::MediaRoute::Remote(pod) => {
            tracing::info!(room = %rid, owner = %pod, "call/start: conference already owned by another pod");
            serde_json::Value::Null
        }
    };

    // Notify all room members about the call
    let member_ids = state
        .rooms
        .find_member_user_ids(rid)
        .await
        .unwrap_or_default();
    if !member_ids.is_empty() {
        let room = state.rooms.base.find_by_id_in_tenant(tid, rid).await.ok();
        let room_name = room.map(|r| r.name).unwrap_or_default();
        let event = serde_json::json!({
            "type": "room:call_started",
            "data": {
                "room_id": rid.to_hex(),
                "room_name": room_name,
                "started_by": auth.user_id.to_hex(),
            }
        });
        meshharbor_core::ws::dispatcher::broadcast_with_redis(
            &state.ws_storage,
            &state.redis_pubsub,
            &member_ids,
            &event,
        )
        .await;

        // Create persistent call notifications + push for offline members via helper
        let caller_names = state
            .users
            .find_display_names(&[auth.user_id])
            .await
            .unwrap_or_default();
        let caller_name = caller_names
            .get(&auth.user_id)
            .cloned()
            .unwrap_or_else(|| auth.user_id.to_hex());

        meshharbor_core::notify::notify_call_started(
            &state,
            tid,
            rid,
            auth.user_id,
            &member_ids,
            &room_name,
            &caller_name,
            &tenant_id,
            &room_id,
        )
        .await;
    }

    Ok(Json(serde_json::json!({
        "started": true,
        "rtp_capabilities": rtp_capabilities,
    })))
}

/// Optional body for `call/join` / `call/leave`. Legacy clients (and the
/// Rust/e2e test helpers) post with NO body at all — `Option<Json<_>>`
/// keeps those working; `connection_id` scopes the call session to one WS
/// connection so the same user can join from several browsers/devices.
#[derive(Debug, Default, Deserialize)]
pub struct CallSessionBody {
    pub connection_id: Option<String>,
}

pub async fn call_join(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    body: Option<Json<CallSessionBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let connection_id = body.and_then(|Json(b)| b.connection_id);
    let user = state.users.base.find_by_id(auth.user_id).await?;

    let member = state
        .rooms
        .join_participant(
            tid,
            rid,
            auth.user_id,
            user.display_name,
            "web".to_string(),
            connection_id,
        )
        .await?;

    // Notify room members about updated participant count
    let room = state.rooms.base.find_by_id_in_tenant(tid, rid).await.ok();
    let participant_count = room.as_ref().map(|r| r.participant_count).unwrap_or(0);
    // #754: this was the string literal `"in_progress"`, which made the event
    // ASSERT a status the database might not hold. `call/join` never sets
    // `conference_status` — only `call/start` does — so joining a call that has
    // already auto-ended (last participant left) broadcast `in_progress` over a
    // room whose stored status was `ended`, and every client believed it.
    //
    // The room is already in hand two lines up, so the truthful value costs
    // nothing. Same shape as the `call_leave` broadcast below, fallback
    // included, so the two cannot drift apart again.
    let conference_status = room
        .as_ref()
        .and_then(|r| r.conference_status.clone())
        .unwrap_or_else(|| "in_progress".into());
    let member_ids = state
        .rooms
        .find_member_user_ids(rid)
        .await
        .unwrap_or_default();
    if !member_ids.is_empty() {
        let event = serde_json::json!({
            "type": "room:call_updated",
            "data": {
                "room_id": rid.to_hex(),
                "participant_count": participant_count,
                "conference_status": conference_status,
            }
        });
        meshharbor_core::ws::dispatcher::broadcast_with_redis(
            &state.ws_storage,
            &state.redis_pubsub,
            &member_ids,
            &event,
        )
        .await;
    }

    Ok(Json(serde_json::json!({
        "member_id": member.id.unwrap().to_hex(),
        "joined": true,
    })))
}

pub async fn call_leave(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    body: Option<Json<CallSessionBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let connection_id = body.and_then(|Json(b)| b.connection_id);
    close_call_media(&state, rid, auth.user_id, connection_id.as_deref()).await;
    finalize_call_leave_db(&state, rid, auth.user_id, connection_id.as_deref()).await?;

    Ok(Json(serde_json::json!({ "left": true })))
}

/// Media half of a call leave. With `connection_id` only that connection's
/// transports are dropped (multi-device: the same user's other browsers keep
/// theirs — the pre-2026-08 user-keyed close was exactly the bug that killed
/// the second browser's video); without it the legacy close-all-of-user path
/// runs. C-4: the media island may live on another pod — the owner then drops
/// the transports and broadcasts `media:peer_left` itself.
pub(crate) async fn close_call_media(
    state: &ConferenceState,
    rid: ObjectId,
    user_id: ObjectId,
    connection_id: Option<&str>,
) {
    match crate::media_cluster::resolve_media_route(state, &rid, false).await {
        crate::media_cluster::MediaRoute::Local { .. } => {
            let closed = match connection_id {
                // Ownership-checked: the conn id comes from an HTTP body, so
                // it must not be able to close another participant's media.
                Some(cid) => state
                    .room_manager
                    .close_participant_of_user(&rid, cid, &user_id),
                None => {
                    state.room_manager.close_participant_by_user(&rid, &user_id);
                    true
                }
            };

            // Broadcast peer_left to remaining participants (including the
            // leaver's OTHER connections — they key tiles by connection_id).
            let remaining = state.room_manager.get_participant_user_ids(&rid);
            if closed && !remaining.is_empty() {
                let mut data = serde_json::json!({
                    "room_id": rid.to_hex(),
                    "user_id": user_id.to_hex(),
                });
                if let Some(cid) = connection_id {
                    data["connection_id"] = serde_json::Value::String(cid.to_string());
                }
                let event = serde_json::json!({ "type": "media:peer_left", "data": data });
                meshharbor_core::ws::dispatcher::broadcast_with_redis(
                    &state.ws_storage,
                    &state.redis_pubsub,
                    &remaining,
                    &event,
                )
                .await;
            }
        }
        crate::media_cluster::MediaRoute::Remote(pod) => {
            crate::media_cluster::rpc_leave_user(state, &pod, &rid, &user_id, connection_id).await;
        }
    }
}

/// DB half of a call leave, shared by HTTP `call/leave` and the WS
/// disconnect path (which historically skipped it entirely — the "1 Active
/// call after refresh" bug): close the session, and only when the user's
/// LAST session closed broadcast the new count / auto-end the call.
pub async fn finalize_call_leave_db(
    state: &ConferenceState,
    rid: ObjectId,
    user_id: ObjectId,
    connection_id: Option<&str>,
) -> Result<(), ApiError> {
    let outcome = state
        .rooms
        .leave_participant(rid, user_id, connection_id)
        .await?;
    // Stats PR-2 — book the closed sessions' seconds into the live call,
    // clamped to the call window (a stale orphan closed by the legacy
    // close-all path must not book days into the current call).
    if !outcome.closed_sessions.is_empty() && state.settings.stats.enabled {
        book_call_minutes(state, rid, &outcome.closed_sessions).await;
    }
    if !outcome.was_last_session {
        // Another session of this user is still open (or nothing was closed):
        // the distinct-user count is unchanged — nothing to broadcast.
        return Ok(());
    }

    let room = state.rooms.base.find_by_id(rid).await.ok();
    let (count, status) = room
        .as_ref()
        .map(|r| (r.participant_count, r.conference_status.clone()))
        .unwrap_or((0, None));
    let member_ids = state
        .rooms
        .find_member_user_ids(rid)
        .await
        .unwrap_or_default();

    if count > 0 {
        if !member_ids.is_empty() {
            let event = serde_json::json!({
                "type": "room:call_updated",
                "data": {
                    "room_id": rid.to_hex(),
                    "participant_count": count,
                    "conference_status": status.clone().unwrap_or_else(|| "in_progress".into()),
                }
            });
            meshharbor_core::ws::dispatcher::broadcast_with_redis(
                &state.ws_storage,
                &state.redis_pubsub,
                &member_ids,
                &event,
            )
            .await;
        }
    } else if status.as_deref() == Some("in_progress") {
        let ended_call = state.rooms.end_call(rid).await?;
        if let Some(call_id) = ended_call
            && state.settings.stats.enabled
            && let Err(e) = state.stats.close_call_session(call_id, "last_left").await
        {
            tracing::debug!(room = %rid, %e, "call session close failed (last_left)");
        }
        // C-4 — the media island may live on another pod.
        crate::media_cluster::close_room_everywhere(state, &rid).await;

        if !member_ids.is_empty() {
            let event = serde_json::json!({
                "type": "room:call_ended",
                "data": {
                    "room_id": rid.to_hex(),
                }
            });
            meshharbor_core::ws::dispatcher::broadcast_with_redis(
                &state.ws_storage,
                &state.redis_pubsub,
                &member_ids,
                &event,
            )
            .await;
        }
    }

    Ok(())
}

/// Stats PR-2 — attribute just-closed session seconds to the room's live
/// call, clamped to the call window. Sessions that PRE-DATE the call
/// (orphans from a crash gap, closed late by the legacy close-all leave)
/// are skipped entirely — they must not book days into the current call.
async fn book_call_minutes(
    state: &ConferenceState,
    rid: ObjectId,
    closed: &[(bson::DateTime, bson::DateTime)],
) {
    let Ok(room) = state.rooms.base.find_by_id(rid).await else {
        return;
    };
    let Some(call_id) = room.current_call_id else {
        return;
    };
    let Ok(Some((started_at, ended_at))) = state.stats.call_window(call_id).await else {
        return;
    };
    let start_ms = started_at.timestamp_millis();
    let end_cap_ms = ended_at.map(|e| e.timestamp_millis());
    let mut secs = 0i64;
    for (joined, left) in closed {
        let j_ms = joined.timestamp_millis();
        if j_ms < start_ms {
            continue;
        }
        let mut l_ms = left.timestamp_millis();
        if let Some(cap) = end_cap_ms {
            l_ms = l_ms.min(cap);
        }
        secs += (l_ms - j_ms).max(0) / 1000;
    }
    if secs > 0
        && let Err(e) = state
            .stats
            .add_call_participant_seconds(call_id, secs)
            .await
    {
        tracing::debug!(room = %rid, %e, "call minutes booking failed");
    }
}

pub async fn call_end(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let ended_call = state.rooms.end_call(rid).await?;
    if let Some(call_id) = ended_call
        && state.settings.stats.enabled
        && let Err(e) = state.stats.close_call_session(call_id, "ended").await
    {
        tracing::debug!(room = %rid, %e, "call session close failed (ended)");
    }
    // C-4 — close the media island wherever it lives (local remove +
    // claim release, or `media.close_room` RPC to the owning pod, which
    // notifies its participants). The old local-only remove_room +
    // media:room_closed block was dead code: it read the participant
    // list AFTER removing the room, so the list was always empty — the
    // UI teardown signal is `room:call_ended` below.
    crate::media_cluster::close_room_everywhere(&state, &rid).await;

    // Notify all room members that the call has ended
    let member_ids = state
        .rooms
        .find_member_user_ids(rid)
        .await
        .unwrap_or_default();
    if !member_ids.is_empty() {
        let event = serde_json::json!({
            "type": "room:call_ended",
            "data": {
                "room_id": rid.to_hex(),
            }
        });
        meshharbor_core::ws::dispatcher::broadcast_with_redis(
            &state.ws_storage,
            &state.redis_pubsub,
            &member_ids,
            &event,
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "ended": true })))
}

pub async fn participants(
    State(state): State<ConferenceState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    crate::guards::require_room_in_tenant(&state, tid, rid, auth.user_id).await?;

    let parts = state.rooms.list_participants(rid).await?;
    let items: Vec<serde_json::Value> = parts
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.unwrap().to_hex(),
                "user_id": p.user_id.map(|u| u.to_hex()),
                "display_name": p.display_name,
                "role": p.role.as_ref().map(|r| format!("{:?}", r)),
                "is_muted": p.is_muted,
                "is_video_on": p.is_video_on,
                "is_screen_sharing": p.is_screen_sharing,
                "is_hand_raised": p.is_hand_raised,
            })
        })
        .collect();

    Ok(Json(items))
}
