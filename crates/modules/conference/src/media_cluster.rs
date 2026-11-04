// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! C-4 — media claim-or-route: mediasoup rooms become cluster-safe.
//!
//! A conference room is server-materialized state with no client-owned
//! socket, so ownership is a **SET-NX claim** (`roomler:own:media:<room>`)
//! — creation itself is mutually exclusive, which kills the S6 belt's
//! split-brain class (two pods silently building rival router islands
//! for one room). Every `media:*` command resolves placement first:
//!
//! - local room → serve with the local `RoomManager` (unchanged path);
//! - foreign claim → forward the command to the owning pod over the
//!   per-pod bus (`media.cmd`); replies and pushes come back
//!   **connection-addressed** on the global channel (`conn` envelope
//!   field) since the viewer's WS never moves;
//! - no claim → only `media:join` may materialize the room, gated on
//!   Mongo `in_progress` + winning the NX claim;
//! - directory unavailable → the S6 belt verbatim (get-or-create), with
//!   `MEDIA_BELT_FALLBACK_TOTAL` (core metrics) counting the accepted split risk.
//!
//! Claim lifetime: 30 s TTL, 10 s refresh (crash gap ≤30 s; graceful
//! shutdown compare-DELs for a zero-gap deploy handoff). A refresh
//! CONFLICT means a foreign pod owns the key (post-Redis-outage double
//! claim): the **claim-loser folds** — tears down its island and pushes
//! `media:room_closed {reason:"rehomed"}` so participants rejoin via
//! the normal join path, which lands on the surviving owner.

use std::sync::atomic::Ordering;

use bson::oid::ObjectId;
use tracing::{debug, info, warn};

use crate::ConferenceState;
use meshharbor_core::cluster::bus::BusError;
use meshharbor_core::cluster::directory::{ClaimOutcome, MEDIA_TTL_SECS, OwnerRecord, media_key};

/// Claim refresh cadence (TTL/3, same ratio as the 90/30 registries).
pub const MEDIA_REFRESH_SECS: u64 = 10;

/// Where a media command executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaRoute {
    /// Serve with the local room manager. `create` = the caller may
    /// materialize the room (claim won, or belt fallback with a live
    /// conference in Mongo).
    Local { create: bool },
    /// The named pod owns the room — forward over the bus.
    Remote(String),
}

/// Resolve placement for one room. `is_join` gates materialization —
/// only the join path (WS `media:join` / HTTP `call/start`) may create.
pub async fn resolve_media_route(
    state: &ConferenceState,
    rid: &ObjectId,
    is_join: bool,
) -> MediaRoute {
    if state.room_manager.has_room(rid) {
        return MediaRoute::Local { create: false };
    }
    let Some(dir) = state.cluster_directory.clone() else {
        return belt_fallback(state, rid, is_join).await;
    };
    let key = media_key(&rid.to_hex());
    match dir.get(&key).await {
        Err(e) => {
            warn!(room = %rid, %e, "media directory read failed");
            belt_fallback(state, rid, is_join).await
        }
        Ok(Some(raw)) => {
            if !dir.is_foreign(&raw) {
                // Ours (this pod + epoch) with no local room: trust it only
                // while we still hold the token — otherwise a lazy release
                // is racing us and the claim must be re-won from scratch.
                if state
                    .media_claim_tokens
                    .get(rid)
                    .map(|t| *t == raw)
                    .unwrap_or(false)
                {
                    return MediaRoute::Local { create: is_join };
                }
                return claim_missing(state, &dir, rid, is_join).await;
            }
            match OwnerRecord::parse(&raw) {
                Some(rec) if rec.pod_id == state.pod.pod_id => {
                    // Our pod's PREVIOUS process (stale epoch, e.g. after a
                    // crash-restart): prune the corpse and re-claim.
                    let _ = dir.release(&key, &raw).await;
                    claim_missing(state, &dir, rid, is_join).await
                }
                Some(rec) => MediaRoute::Remote(rec.pod_id),
                None => {
                    let _ = dir.release(&key, &raw).await;
                    claim_missing(state, &dir, rid, is_join).await
                }
            }
        }
        Ok(None) => claim_missing(state, &dir, rid, is_join).await,
    }
}

/// No claim exists: joins may materialize (Mongo-gated + NX-claimed);
/// everything else serves locally where the handler produces the natural
/// "room does not exist" outcome.
async fn claim_missing(
    state: &ConferenceState,
    dir: &meshharbor_core::cluster::directory::OwnershipDirectory,
    rid: &ObjectId,
    is_join: bool,
) -> MediaRoute {
    if !is_join {
        return MediaRoute::Local { create: false };
    }
    if !call_in_progress(state, rid).await {
        return MediaRoute::Local { create: false };
    }
    let token = dir.owner_token("media");
    match dir
        .claim_nx(&media_key(&rid.to_hex()), &token, MEDIA_TTL_SECS)
        .await
    {
        Ok(ClaimOutcome::Won) => {
            state.media_claim_tokens.insert(*rid, token);
            info!(room = %rid, "media claim won — materializing room on this pod");
            MediaRoute::Local { create: true }
        }
        Ok(ClaimOutcome::Foreign(raw)) => match OwnerRecord::parse(&raw) {
            Some(rec) if rec.pod_id != state.pod.pod_id => MediaRoute::Remote(rec.pod_id),
            // Our own stale record won the race window — rare; the next
            // attempt (UI retry / rejoin) prunes it via resolve.
            _ => MediaRoute::Local { create: false },
        },
        Err(e) => {
            warn!(room = %rid, %e, "media claim_nx failed");
            belt_fallback(state, rid, true).await
        }
    }
}

async fn call_in_progress(state: &ConferenceState, rid: &ObjectId) -> bool {
    state
        .rooms
        .base
        .find_by_id(*rid)
        .await
        .map(|r| r.conference_status.as_deref() == Some("in_progress"))
        .unwrap_or(false)
}

/// Directory unavailable — the S6 belt verbatim (Mongo-gated local
/// get-or-create), counted: each entry accepted split-brain risk for
/// the duration of the Redis outage.
async fn belt_fallback(state: &ConferenceState, rid: &ObjectId, is_join: bool) -> MediaRoute {
    if !is_join {
        return MediaRoute::Local { create: false };
    }
    let create = call_in_progress(state, rid).await;
    if create {
        let total = meshharbor_core::cluster::metrics::MEDIA_BELT_FALLBACK_TOTAL
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        warn!(
            room = %rid,
            media_belt_fallback_total = total,
            "media belt fallback — directory unavailable, serving get-or-create locally"
        );
    }
    MediaRoute::Local { create }
}

/// Forward one viewer command to the owning pod. Sends the viewer a
/// `media:error` on terminal failure. Returns whether the owner acked.
pub async fn forward_media_cmd(
    state: &ConferenceState,
    owner_pod: &str,
    user_id: &ObjectId,
    connection_id: &str,
    msg_type: &str,
    data: Option<&serde_json::Value>,
) -> bool {
    let Some(bus) = state.cluster_bus.clone() else {
        media_error(
            state,
            connection_id,
            "Conference is hosted on another server",
        )
        .await;
        return false;
    };
    let body = serde_json::json!({
        "user_id": user_id.to_hex(),
        "connection_id": connection_id,
        "msg_type": msg_type,
        "data": data,
    });
    // Router/transport-creating ops get the long deadline.
    let deadline = if msg_type == "media:join" {
        std::time::Duration::from_secs(5)
    } else {
        meshharbor_core::cluster::bus::RPC_DEADLINE
    };
    match bus
        .request_with_deadline(owner_pod, "media.cmd", body.clone(), deadline)
        .await
    {
        Ok(_) => true,
        // The presumed owner disclaims — its claim moved. Retry ONCE
        // toward the pod it names, then give up (bounded chain).
        Err(BusError::Nack(reason)) if reason.starts_with("not_owner:") => {
            let next = reason.trim_start_matches("not_owner:").to_string();
            if next.is_empty() || next == owner_pod {
                media_error(state, connection_id, "Conference moved — please rejoin").await;
                return false;
            }
            match bus
                .request_with_deadline(&next, "media.cmd", body, deadline)
                .await
            {
                Ok(_) => true,
                Err(e) => {
                    debug!(%e, "media.cmd retry toward re-declared owner failed");
                    media_error(state, connection_id, "Conference moved — please rejoin").await;
                    false
                }
            }
        }
        Err(BusError::Nack(reason)) => {
            media_error(state, connection_id, &format!("Conference error: {reason}")).await;
            false
        }
        // Deadline/Redis — the owner is presumed dead: prune the record
        // we acted on (compare-DEL against what we observed) so the next
        // join re-claims on a live pod.
        Err(e) => {
            warn!(%owner_pod, %e, "media.cmd RPC failed — pruning presumed-dead owner record");
            prune_owner_record(state, connection_id, user_id, msg_type, data, owner_pod).await
        }
    }
}

/// RPC-failure fallback: compare-DEL the dead owner's record; a JOIN then
/// re-resolves immediately (typically winning the claim locally) so the
/// viewer heals without a manual retry.
async fn prune_owner_record(
    state: &ConferenceState,
    connection_id: &str,
    user_id: &ObjectId,
    msg_type: &str,
    data: Option<&serde_json::Value>,
    owner_pod: &str,
) -> bool {
    let rid = data
        .and_then(|d| d.get("room_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| ObjectId::parse_str(s).ok());
    if let (Some(dir), Some(rid)) = (state.cluster_directory.clone(), rid) {
        let key = media_key(&rid.to_hex());
        if let Ok(Some(raw)) = dir.get(&key).await
            && OwnerRecord::parse(&raw).map(|r| r.pod_id) == Some(owner_pod.to_string())
        {
            let _ = dir.release(&key, &raw).await;
        }
        if msg_type == "media:join" {
            // One re-resolve: with the corpse pruned this usually claims
            // locally and serves the join in-place.
            if let MediaRoute::Local { create } = resolve_media_route(state, &rid, true).await {
                crate::ws_media::dispatch_media_local(
                    state,
                    user_id,
                    connection_id,
                    msg_type,
                    data,
                    create,
                )
                .await;
                return true;
            }
        }
    }
    media_error(
        state,
        connection_id,
        "Conference owner unreachable — please rejoin",
    )
    .await;
    false
}

async fn media_error(state: &ConferenceState, connection_id: &str, message: &str) {
    let msg = serde_json::json!({
        "type": "media:error",
        "data": { "message": message }
    });
    meshharbor_core::ws::dispatcher::send_to_connection_routed(
        &state.ws_storage,
        &state.redis_pubsub,
        connection_id,
        &msg,
    )
    .await;
}

/// Close a room's media island wherever it lives (call_end / last-leave
/// auto-end): locally = remove + release; foreign = `media.close_room`
/// RPC to the owner.
pub async fn close_room_everywhere(state: &ConferenceState, rid: &ObjectId) {
    if state.room_manager.has_room(rid) {
        state.room_manager.remove_room(rid);
        release_media_claim(state, rid).await;
        return;
    }
    match resolve_media_route(state, rid, false).await {
        MediaRoute::Remote(pod) => {
            if let Some(bus) = state.cluster_bus.clone()
                && let Err(e) = bus
                    .request(
                        &pod,
                        "media.close_room",
                        serde_json::json!({ "room_id": rid.to_hex() }),
                    )
                    .await
            {
                warn!(room = %rid, %pod, %e, "media.close_room RPC failed — pruning record");
                if let Some(dir) = state.cluster_directory.clone() {
                    let key = media_key(&rid.to_hex());
                    if let Ok(Some(raw)) = dir.get(&key).await
                        && OwnerRecord::parse(&raw).map(|r| r.pod_id) == Some(pod)
                    {
                        let _ = dir.release(&key, &raw).await;
                    }
                }
            }
        }
        MediaRoute::Local { .. } => release_media_claim(state, rid).await,
    }
}

/// Release our claim for one room (compare-DEL via the held token).
pub async fn release_media_claim(state: &ConferenceState, rid: &ObjectId) {
    if let Some((_, token)) = state.media_claim_tokens.remove(rid)
        && let Some(dir) = state.cluster_directory.clone()
        && let Err(e) = dir.release(&media_key(&rid.to_hex()), &token).await
    {
        debug!(room = %rid, %e, "media claim release failed (TTL is the backstop)");
    }
}

/// Tell a remote owner one user left the call (HTTP `call/leave` served
/// on a non-owner pod): the owner drops the participant's transports and
/// broadcasts `media:peer_left` itself. `connection_id: Some(_)` scopes the
/// close to that one connection (multi-device: the user's other browsers
/// keep their media); `None` is the legacy close-all-of-user path, kept as
/// the mixed-version fallback during rolls.
pub async fn rpc_leave_user(
    state: &ConferenceState,
    owner_pod: &str,
    rid: &ObjectId,
    user_id: &ObjectId,
    connection_id: Option<&str>,
) {
    let mut body = serde_json::json!({ "room_id": rid.to_hex(), "user_id": user_id.to_hex() });
    if let Some(cid) = connection_id {
        body["connection_id"] = serde_json::Value::String(cid.to_string());
    }
    if let Some(bus) = state.cluster_bus.clone()
        && let Err(e) = bus.request(owner_pod, "media.leave_user", body).await
    {
        debug!(room = %rid, %owner_pod, %e, "media.leave_user RPC failed");
    }
}

/// Best-effort leave for a REMOTE participant whose WS just closed on
/// this pod: the owner still holds their transports.
pub async fn forward_close_leave(state: &ConferenceState, user_id: &ObjectId, connection_id: &str) {
    let Some((_, rid)) = state.remote_media_conns.remove(connection_id) else {
        return;
    };
    let data = serde_json::json!({ "room_id": rid.to_hex() });
    match resolve_media_route(state, &rid, false).await {
        MediaRoute::Remote(pod) => {
            if let Some(bus) = state.cluster_bus.clone() {
                let body = serde_json::json!({
                    "user_id": user_id.to_hex(),
                    "connection_id": connection_id,
                    "msg_type": "media:leave",
                    "data": data,
                });
                if let Err(e) = bus.request(&pod, "media.cmd", body).await {
                    debug!(room = %rid, %pod, %e, "close-time media:leave forward failed");
                }
            }
        }
        // Folded home meanwhile — the plain local leave covers it.
        MediaRoute::Local { .. } => {
            crate::ws_media::dispatch_media_local(
                state,
                user_id,
                connection_id,
                "media:leave",
                Some(&data),
                false,
            )
            .await;
        }
    }
}

/// The claim-loser rule: tear down the local island and push a rejoin
/// signal; participants re-enter via the normal join path, which routes
/// to the surviving owner.
pub async fn fold_media_room(state: &ConferenceState, rid: &ObjectId, reason: &str) {
    warn!(room = %rid, reason, "folding local media-room island");
    meshharbor_core::cluster::metrics::bump(&meshharbor_core::cluster::metrics::MEDIA_FOLD_TOTAL);
    // The key belongs to the foreign owner now — drop the token WITHOUT
    // a release.
    state.media_claim_tokens.remove(rid);
    let conns: Vec<String> = state
        .room_manager
        .rooms_ref()
        .get(rid)
        .map(|room| room.participants.iter().map(|p| p.key().clone()).collect())
        .unwrap_or_default();
    state.room_manager.remove_room(rid);
    let event = serde_json::json!({
        "type": "media:room_closed",
        "data": { "room_id": rid.to_hex(), "reason": "rehomed" }
    });
    for conn in &conns {
        meshharbor_core::ws::dispatcher::send_to_connection_routed(
            &state.ws_storage,
            &state.redis_pubsub,
            conn,
            &event,
        )
        .await;
    }
}

/// One claim-maintenance pass: lazy-release tokens whose room is gone,
/// refresh the rest, fold on CONFLICT. Public so tests drive it directly.
pub async fn refresh_media_claims_once(state: &ConferenceState) {
    let Some(dir) = state.cluster_directory.clone() else {
        return;
    };
    let held: Vec<(ObjectId, String)> = state
        .media_claim_tokens
        .iter()
        .map(|e| (*e.key(), e.value().clone()))
        .collect();
    for (rid, token) in held {
        let key = media_key(&rid.to_hex());
        if !state.room_manager.has_room(&rid) {
            // Room closed (call ended / island folded elsewhere): release
            // lazily so the next join can claim fresh.
            if state.media_claim_tokens.remove(&rid).is_some() {
                let _ = dir.release(&key, &token).await;
            }
            continue;
        }
        match dir.refresh_if_mine(&key, &token, MEDIA_TTL_SECS).await {
            Ok(true) => {}
            Ok(false) => fold_media_room(state, &rid, "claim held by a foreign pod").await,
            // Redis flap: never fold on an ERROR — the 30 s TTL is the
            // backstop and the next pass re-asserts.
            Err(e) => debug!(room = %rid, %e, "media claim refresh failed"),
        }
    }

    // Adopt-or-fold for TOKENLESS local rooms (belt-created while the
    // directory was down, or a claim lost to TTL during a flap): on
    // recovery each holder races the NX claim — the winner adopts its
    // island, the loser folds. This is what auto-resolves a belt-era
    // split within one beat of Redis returning.
    let orphans: Vec<ObjectId> = state
        .room_manager
        .rooms_ref()
        .iter()
        .map(|e| *e.key())
        .filter(|rid| !state.media_claim_tokens.contains_key(rid))
        .collect();
    for rid in orphans {
        let key = media_key(&rid.to_hex());
        let token = dir.owner_token("media");
        match dir.claim_nx(&key, &token, MEDIA_TTL_SECS).await {
            Ok(ClaimOutcome::Won) => {
                info!(room = %rid, "adopted tokenless local media room (claim re-won)");
                state.media_claim_tokens.insert(rid, token);
            }
            Ok(ClaimOutcome::Foreign(raw)) => match OwnerRecord::parse(&raw) {
                // Our own stale-epoch corpse: prune, then retry once.
                Some(rec) if rec.pod_id == state.pod.pod_id && dir.is_foreign(&raw) => {
                    let _ = dir.release(&key, &raw).await;
                    if let Ok(ClaimOutcome::Won) = dir.claim_nx(&key, &token, MEDIA_TTL_SECS).await
                    {
                        info!(room = %rid, "adopted tokenless local media room (stale epoch pruned)");
                        state.media_claim_tokens.insert(rid, token);
                    }
                }
                // Same-process record without a token (release race):
                // leave it — the next pass settles.
                Some(_) if !dir.is_foreign(&raw) => {}
                _ => {
                    fold_media_room(state, &rid, "belt-era split — foreign pod holds the claim")
                        .await
                }
            },
            Err(e) => debug!(room = %rid, %e, "orphan media room claim attempt failed"),
        }
    }
}

/// Wire the C-4 machinery: bus handlers (owner side) + the claim
/// heartbeat. Called once at the end of `ConferenceState::new` (the bus
/// handlers need the fully-built state).
/// Graceful shutdown: compare-DEL every media claim this pod holds so a
/// deploy hands each room off with a ZERO-length ownerless window instead
/// of waiting out the 30 s TTL. Conference's `Module::shutdown`; the host's
/// `shutdown_cleanup` used to do this inline (C-4).
pub async fn release_all_claims(state: &ConferenceState) {
    let Some(dir) = &state.cluster_directory else {
        return;
    };
    let held: Vec<(ObjectId, String)> = state
        .media_claim_tokens
        .iter()
        .map(|e| (*e.key(), e.value().clone()))
        .collect();
    for (rid, token) in held {
        state.media_claim_tokens.remove(&rid);
        if let Err(e) = dir.release(&media_key(&rid.to_hex()), &token).await {
            debug!(room = %rid, %e, "shutdown: media claim release failed");
        }
    }
}

pub fn wire_media_cluster(state: &ConferenceState) {
    if let Some(bus) = &state.cluster_bus {
        // media.cmd — execute one viewer command against the local room.
        let st = state.clone();
        bus.register("media.cmd", move |body| {
            let st = st.clone();
            Box::pin(async move { handle_media_cmd_rpc(st, body).await })
        });

        // media.leave_user — HTTP call/leave served on a non-owner pod.
        // With `connection_id` the close is scoped to that one connection
        // (same-user other devices keep their transports); without it we
        // keep the legacy close-all-of-user behaviour (mixed-version rolls).
        let st = state.clone();
        bus.register("media.leave_user", move |body| {
            let st = st.clone();
            Box::pin(async move {
                let rid = parse_oid(&body, "room_id")?;
                let uid = parse_oid(&body, "user_id")?;
                let conn_id = body.get("connection_id").and_then(|v| v.as_str());
                let closed = match conn_id {
                    Some(cid) => st.room_manager.close_participant_of_user(&rid, cid, &uid),
                    None => {
                        st.room_manager.close_participant_by_user(&rid, &uid);
                        true
                    }
                };
                let remaining = st.room_manager.get_participant_user_ids(&rid);
                if closed && !remaining.is_empty() {
                    let mut data =
                        serde_json::json!({ "room_id": rid.to_hex(), "user_id": uid.to_hex() });
                    if let Some(cid) = conn_id {
                        data["connection_id"] = serde_json::Value::String(cid.to_string());
                    }
                    let event = serde_json::json!({ "type": "media:peer_left", "data": data });
                    meshharbor_core::ws::dispatcher::broadcast_with_redis(
                        &st.ws_storage,
                        &st.redis_pubsub,
                        &remaining,
                        &event,
                    )
                    .await;
                }
                Ok(serde_json::json!({ "ok": true }))
            })
        });

        // media.close_room — call_end/auto-end served on a non-owner pod.
        let st = state.clone();
        bus.register("media.close_room", move |body| {
            let st = st.clone();
            Box::pin(async move {
                let rid = parse_oid(&body, "room_id")?;
                let conns: Vec<String> = st
                    .room_manager
                    .rooms_ref()
                    .get(&rid)
                    .map(|room| room.participants.iter().map(|p| p.key().clone()).collect())
                    .unwrap_or_default();
                st.room_manager.remove_room(&rid);
                release_media_claim(&st, &rid).await;
                let event = serde_json::json!({
                    "type": "media:room_closed",
                    "data": { "room_id": rid.to_hex(), "reason": "ended" }
                });
                for conn in &conns {
                    meshharbor_core::ws::dispatcher::send_to_connection_routed(
                        &st.ws_storage,
                        &st.redis_pubsub,
                        conn,
                        &event,
                    )
                    .await;
                }
                Ok(serde_json::json!({ "ok": true }))
            })
        });
    }

    if state.cluster_directory.is_some() {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(MEDIA_REFRESH_SECS)).await;
                refresh_media_claims_once(&st).await;
            }
        });
    }
}

/// Owner-side execution of a forwarded command. Re-resolves placement
/// (the claim may have moved since the caller looked): still ours →
/// dispatch against the local handlers, whose replies/pushes ride the
/// conn-addressed channel back; moved → structured NACK naming the new
/// owner so the caller can retry once.
async fn handle_media_cmd_rpc(
    state: ConferenceState,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let uid = parse_oid(&body, "user_id")?;
    let conn = body
        .get("connection_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing connection_id".to_string())?
        .to_string();
    let msg_type = body
        .get("msg_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing msg_type".to_string())?
        .to_string();
    let data = body.get("data").cloned().filter(|d| !d.is_null());
    let rid = data
        .as_ref()
        .and_then(|d| d.get("room_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| ObjectId::parse_str(s).ok())
        .ok_or_else(|| "missing room_id".to_string())?;

    match resolve_media_route(&state, &rid, msg_type == "media:join").await {
        MediaRoute::Remote(pod) => Err(format!("not_owner:{pod}")),
        MediaRoute::Local { create } => {
            crate::ws_media::dispatch_media_local(
                &state,
                &uid,
                &conn,
                &msg_type,
                data.as_ref(),
                create,
            )
            .await;
            Ok(serde_json::json!({ "ok": true }))
        }
    }
}

fn parse_oid(body: &serde_json::Value, field: &str) -> Result<ObjectId, String> {
    body.get(field)
        .and_then(|v| v.as_str())
        .and_then(|s| ObjectId::parse_str(s).ok())
        .ok_or_else(|| format!("missing {field}"))
}
