// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The `media:*` namespace on the user socket: join / transports / produce /
//! consume / pause / close / leave / play_audio / stop_audio — and the socket
//! close, which is a leave the client never sent.
//!
//! FR-69 P4 — moved from the host's `ws/handler.rs` unchanged below the
//! [`Media`] handler: [`route_and_dispatch_media`] is the C-4 placement gate
//! (local room → serve here; foreign claim → forward over the bus), and
//! [`dispatch_media_local`] is shared with the owner-side `media.cmd` bus
//! handler in `media_cluster.rs`, which is why it must never re-enter the
//! gate. Replies are connection-addressed and routed, so an error raised
//! while executing a forwarded command still reaches the viewer's pod.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::oid::ObjectId;
use hmac::{Hmac, Mac};
use mediasoup::prelude::*;
use meshharbor_core::{WsCtx, WsHandler};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::ConferenceState;

/// The namespace handler the module registers for `Role::User` / `media`.
pub struct Media {
    pub state: ConferenceState,
}

#[async_trait]
impl WsHandler for Media {
    async fn handle(&self, ctx: &WsCtx, msg: serde_json::Value) -> anyhow::Result<()> {
        let msg_type = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let data = msg.get("data");
        route_and_dispatch_media(
            &self.state,
            &ctx.principal,
            &ctx.connection_id,
            msg_type,
            data,
        )
        .await;
        Ok(())
    }

    async fn closed(&self, ctx: &WsCtx) {
        on_closed(&self.state, &ctx.principal, &ctx.connection_id).await;
    }
}

/// The socket closed: drop this connection's media — its local island, or
/// the transports a remote owner holds for it — and close its call session
/// in Mongo. Historically the disconnect path cleaned only media, and a
/// refresh mid-call left Mongo at `in_progress`/count>=1 forever ("1 Active
/// call" until a manual re-join + hangup); the Mongo lookup is the fallback
/// for a session whose `media:join` never happened (HTTP call/join only).
pub async fn on_closed(state: &ConferenceState, user_id: &ObjectId, connection_id: &str) {
    // Capture the call room BEFORE the media maps are consumed below
    // (`forward_close_leave` removes the remote_media_conns entry) — the
    // DB half of the leave still needs it.
    let remote_media_rid = state
        .remote_media_conns
        .get(connection_id)
        .map(|e| *e.value());
    let local_media_rid = state.room_manager.get_connection_room(connection_id);

    // C-4 — the conn may have joined a room OWNED BY ANOTHER POD: tell
    // the owner to drop its transports (best-effort; no-op when the map
    // has no entry).
    crate::media_cluster::forward_close_leave(state, user_id, connection_id).await;

    if let Some(room_id) = local_media_rid {
        let remaining_conns = state
            .room_manager
            .get_other_connection_ids(&room_id, connection_id);

        state
            .room_manager
            .close_participant(&room_id, connection_id);

        if !remaining_conns.is_empty() {
            let event = serde_json::json!({
                "type": "media:peer_left",
                "data": {
                    "user_id": user_id.to_hex(),
                    "connection_id": connection_id,
                    "room_id": room_id.to_hex(),
                }
            });
            for conn_id in &remaining_conns {
                meshharbor_core::ws::dispatcher::send_to_connection_routed(
                    &state.ws_storage,
                    &state.redis_pubsub,
                    conn_id,
                    &event,
                )
                .await;
            }
        }
    }

    // DB half of the leave: close this connection's call session, broadcast
    // the new count, auto-end when it was the last one.
    let db_rid = match local_media_rid.or(remote_media_rid) {
        Some(rid) => Some(rid),
        None => state
            .rooms
            .find_call_room_for_connection(*user_id, connection_id)
            .await
            .ok()
            .flatten(),
    };
    if let Some(rid) = db_rid
        && let Err(e) =
            crate::call::finalize_call_leave_db(state, rid, *user_id, Some(connection_id)).await
    {
        warn!(?user_id, %connection_id, room = %rid, %e, "disconnect call-leave DB cleanup failed");
    }
}

async fn route_and_dispatch_media(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    msg_type: &str,
    data: Option<&serde_json::Value>,
) {
    use crate::media_cluster::{MediaRoute, forward_media_cmd, resolve_media_route};

    let rid = data
        .and_then(|d| d.get("room_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| ObjectId::parse_str(s).ok());
    let Some(rid) = rid else {
        // Missing/invalid room_id — the local handlers own the error shape.
        dispatch_media_local(state, user_id, connection_id, msg_type, data, false).await;
        return;
    };
    let is_join = msg_type == "media:join";
    match resolve_media_route(state, &rid, is_join).await {
        MediaRoute::Local { create } => {
            // A conn whose room came home (fold/rehome) no longer needs
            // close-time forwarding to a remote owner.
            state.remote_media_conns.remove(connection_id);
            dispatch_media_local(state, user_id, connection_id, msg_type, data, create).await;
        }
        MediaRoute::Remote(owner) => {
            let ok = forward_media_cmd(state, &owner, user_id, connection_id, msg_type, data).await;
            // Track remote membership so WS close can tell the owner to
            // drop the transports. (The prune fallback may have served
            // the join LOCALLY after all — skip the marker then.)
            if is_join && ok && !state.room_manager.has_room(&rid) {
                state
                    .remote_media_conns
                    .insert(connection_id.to_string(), rid);
            } else if msg_type == "media:leave" {
                state.remote_media_conns.remove(connection_id);
            }
        }
    }
}

/// Execute one media command against the LOCAL room manager. Shared by
/// the WS dispatch above and the owner-side `media.cmd` bus handler
/// (`ws/media_cluster.rs`) — which is why it must never re-enter the
/// placement gate.
pub async fn dispatch_media_local(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    msg_type: &str,
    data: Option<&serde_json::Value>,
    create_allowed: bool,
) {
    match msg_type {
        "media:join" => {
            handle_media_join(state, user_id, connection_id, data, create_allowed).await;
        }
        "media:connect_transport" => {
            handle_media_connect_transport(state, connection_id, data).await;
        }
        "media:produce" => {
            handle_media_produce(state, user_id, connection_id, data).await;
        }
        "media:consume" => {
            handle_media_consume(state, user_id, connection_id, data).await;
        }
        "media:producer_close" => {
            handle_media_producer_close(state, user_id, connection_id, data).await;
        }
        "media:producer_pause" => {
            handle_media_producer_pause(state, user_id, connection_id, data).await;
        }
        "media:leave" => {
            handle_media_leave(state, user_id, connection_id, data).await;
        }
        "media:play_audio" => {
            handle_play_audio(state, user_id, connection_id, data).await;
        }
        "media:stop_audio" => {
            handle_stop_audio(state, user_id, connection_id, data).await;
        }
        _ => {
            debug!(?user_id, msg_type, "Unknown media message type");
        }
    }
}

async fn send_media_error(state: &ConferenceState, connection_id: &str, message: &str) {
    let msg = serde_json::json!({
        "type": "media:error",
        "data": { "message": message }
    });
    // Conn-addressed + routed: an error raised while executing a
    // forwarded command must reach the viewer's pod.
    meshharbor_core::ws::dispatcher::send_to_connection_routed(
        &state.ws_storage,
        &state.redis_pubsub,
        connection_id,
        &msg,
    )
    .await;
}

async fn handle_media_join(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
    create_allowed: bool,
) {
    let room_id_str = match data.and_then(|d| d.get("room_id")).and_then(|c| c.as_str()) {
        Some(s) => s,
        None => {
            send_media_error(state, connection_id, "Missing room_id").await;
            return;
        }
    };

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => {
            send_media_error(state, connection_id, "Invalid room_id").await;
            return;
        }
    };

    let mut room_exists = state.room_manager.has_room(&rid);
    debug!(?user_id, %connection_id, ?rid, room_exists, create_allowed, "media:join room check");
    if !room_exists && create_allowed {
        // C-4 — materialization is claim-gated: `create_allowed` comes
        // from the placement resolver (NX claim won, or the belt
        // fallback with a live conference while the directory is down).
        // The Mongo in_progress check lives in the resolver too.
        match state.room_manager.create_room(rid).await {
            Ok(_) => {
                info!(?rid, "media:join materialized conference room on this pod");
                room_exists = true;
            }
            Err(e) => {
                warn!(?rid, %e, "media:join room create failed");
            }
        }
    }
    if !room_exists {
        send_media_error(state, connection_id, "Room does not exist").await;
        return;
    }

    // FR-32 P1b — plan `video_max_participants`. Counted from the pod-local
    // room registry rather than Mongo, because that is where a live call
    // actually exists; the tenant-affinity LB co-locates a tenant's conference
    // on ONE pod, so the local count is the whole call. ⚠ Distinct USERS, not
    // connections: one person on laptop and phone is one participant.
    //
    // A rejoining participant is already in the map, so `>=` would refuse them
    // their own seat — hence the membership test before the count.
    let room = state.rooms.base.find_by_id(rid).await.ok();
    // FR-115 P4b — the org that pays for this meeting's TURN relay, named in
    // the TURN username below so coturn's statistics name it.
    let room_org = room.as_ref().map(|r| r.tenant_id);
    if let Some(room) = room.as_ref()
        && let Ok(tenant) = state.tenants.base.find_by_id(room.tenant_id).await
    {
        let present = state.room_manager.get_participant_user_ids(&rid);
        // FR-102 P4 — through core, which also counts the collision per org.
        if !present.contains(user_id)
            && let Err(d) = meshharbor_core::quota::check(
                state,
                &tenant,
                meshharbor_services::quota::Limit::VideoMaxParticipants,
                present.len() as u64,
            )
        {
            send_media_error(state, connection_id, &d.message()).await;
            return;
        }
    }

    let transport_pair = match state
        .room_manager
        .create_transports(rid, *user_id, connection_id.to_string())
        .await
    {
        Ok(tp) => tp,
        Err(e) => {
            send_media_error(
                state,
                connection_id,
                &format!("Failed to create transports: {}", e),
            )
            .await;
            return;
        }
    };

    if let Some(room) = state.room_manager.rooms_ref().get(&rid) {
        let caps = serde_json::to_value(room.router.rtp_capabilities()).unwrap_or_default();
        let msg = serde_json::json!({
            "type": "media:router_capabilities",
            "data": { "rtp_capabilities": caps }
        });
        meshharbor_core::ws::dispatcher::send_to_connection_routed(
            &state.ws_storage,
            &state.redis_pubsub,
            connection_id,
            &msg,
        )
        .await;
    }

    // ⚠️ `Some("")` is "configured" to the type system and "not configured" to
    // everyone else. Treat a blank URL as absent, or we advertise an ICE server
    // the browser refuses outright and no one can join a call at all.
    let turn_url_configured = state
        .settings
        .turn
        .url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());
    // FR-115 P4b — the TURN user, charged to the room's org when it is known
    // (`<expiry>:<user>:org-<org>`), so coturn's statistics name the org that
    // pays; coturn reads only the expiry part.
    let turn_user = match room_org {
        Some(org) => {
            meshharbor_remote_control::turn_creds::charged(&user_id.to_hex(), &org.to_hex())
        }
        None => user_id.to_hex(),
    };
    let ice_servers: Vec<serde_json::Value> = if let Some(url) = turn_url_configured {
        let (turn_username, turn_credential) =
            if let Some(ref secret) = state.settings.turn.shared_secret {
                let expiry = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 86400;
                let username = format!("{}:{}", expiry, turn_user);
                let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
                    .expect("HMAC key length is valid");
                mac.update(username.as_bytes());
                let credential = BASE64.encode(mac.finalize().into_bytes());
                debug!(%username, "Generated TURN ephemeral credentials");
                (username, credential)
            } else {
                (
                    state
                        .settings
                        .turn
                        .username
                        .as_deref()
                        .unwrap_or("")
                        .to_string(),
                    state
                        .settings
                        .turn
                        .password
                        .as_deref()
                        .unwrap_or("")
                        .to_string(),
                )
            };
        // Build TURN URLs with multiple transport variants.
        // UDP TURN often fails behind NAT/firewalls, so include TCP and TLS
        // fallbacks. Also emit `turn:HOST:443?transport=udp` because many
        // corporate firewalls allow UDP/443 (QUIC) but block UDP/3478.
        let urls = meshharbor_remote_control::turn_url::expand_turn_url(
            url,
            &meshharbor_remote_control::turn_url::VariantCaps::media(),
        );
        vec![serde_json::json!({
            "urls": urls,
            "username": turn_username,
            "credential": turn_credential,
        })]
    } else {
        vec![]
    };

    let force_relay = state.settings.turn.force_relay.unwrap_or(false);

    if force_relay {
        info!("force_relay=true — clients will use iceTransportPolicy='relay' via TURN server");
    }

    info!(
        %connection_id,
        force_relay,
        // The RESOLVED per-pod announced IP (S6 map), not the static setting —
        // on a multi-pod deployment they differ and the static one misleads.
        announced_ip = %state
            .room_manager
            .announced_ip()
            .unwrap_or(state.settings.mediasoup.announced_ip.as_str()),
        turn_url = ?state.settings.turn.url,
        send_ice_candidates = %transport_pair.send_transport.ice_candidates,
        recv_ice_candidates = %transport_pair.recv_transport.ice_candidates,
        "media:join transport_created ICE diagnostics"
    );

    let msg = serde_json::json!({
        "type": "media:transport_created",
        "data": {
            "send_transport": transport_pair.send_transport,
            "recv_transport": transport_pair.recv_transport,
            "ice_servers": ice_servers,
            "force_relay": force_relay,
        }
    });
    meshharbor_core::ws::dispatcher::send_to_connection_routed(
        &state.ws_storage,
        &state.redis_pubsub,
        connection_id,
        &msg,
    )
    .await;

    let producers = state.room_manager.get_producer_ids(&rid, connection_id);
    for (uid, conn_id, pid, kind, source) in producers {
        let msg = serde_json::json!({
            "type": "media:new_producer",
            "data": {
                "producer_id": pid.to_string(),
                "user_id": uid.to_hex(),
                "connection_id": conn_id,
                "kind": match kind { MediaKind::Audio => "audio", MediaKind::Video => "video" },
                "source": source,
            }
        });
        meshharbor_core::ws::dispatcher::send_to_connection_routed(
            &state.ws_storage,
            &state.redis_pubsub,
            connection_id,
            &msg,
        )
        .await;
    }
}

async fn handle_media_connect_transport(
    state: &ConferenceState,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let data = match data {
        Some(d) => d,
        None => return,
    };

    let room_id_str = match data.get("room_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };
    let transport_id = match data.get("transport_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };
    let dtls_parameters: DtlsParameters = match data
        .get("dtls_parameters")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(p) => p,
        None => return,
    };

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => return,
    };

    if let Err(e) = state
        .room_manager
        .connect_transport(&rid, connection_id, transport_id, dtls_parameters)
        .await
    {
        warn!(%connection_id, %e, "connect_transport failed");
    }
}

async fn handle_media_produce(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let data = match data {
        Some(d) => d,
        None => {
            send_media_error(state, connection_id, "Missing data").await;
            return;
        }
    };

    let room_id_str = match data.get("room_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            send_media_error(state, connection_id, "Missing room_id").await;
            return;
        }
    };
    let kind: MediaKind = match data
        .get("kind")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(k) => k,
        None => {
            send_media_error(state, connection_id, "Invalid kind").await;
            return;
        }
    };
    let rtp_parameters: RtpParameters = match data
        .get("rtp_parameters")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(p) => p,
        None => {
            send_media_error(state, connection_id, "Invalid rtp_parameters").await;
            return;
        }
    };
    let source = data
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or(match kind {
            MediaKind::Audio => "audio",
            MediaKind::Video => "camera",
        })
        .to_string();

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => {
            send_media_error(state, connection_id, "Invalid room_id").await;
            return;
        }
    };

    match state
        .room_manager
        .produce(&rid, connection_id, kind, rtp_parameters, source.clone())
        .await
    {
        Ok(producer_id) => {
            let result_msg = serde_json::json!({
                "type": "media:produce_result",
                "data": { "id": producer_id.to_string() }
            });
            meshharbor_core::ws::dispatcher::send_to_connection_routed(
                &state.ws_storage,
                &state.redis_pubsub,
                connection_id,
                &result_msg,
            )
            .await;

            let other_conns = state
                .room_manager
                .get_other_connection_ids(&rid, connection_id);

            if !other_conns.is_empty() {
                let event = serde_json::json!({
                    "type": "media:new_producer",
                    "data": {
                        "producer_id": producer_id.to_string(),
                        "user_id": user_id.to_hex(),
                        "connection_id": connection_id,
                        "kind": match kind { MediaKind::Audio => "audio", MediaKind::Video => "video" },
                        "source": source,
                    }
                });
                for conn_id in &other_conns {
                    meshharbor_core::ws::dispatcher::send_to_connection_routed(
                        &state.ws_storage,
                        &state.redis_pubsub,
                        conn_id,
                        &event,
                    )
                    .await;
                }
            }
        }
        Err(e) => {
            send_media_error(state, connection_id, &format!("produce failed: {}", e)).await;
        }
    }
}

async fn handle_media_consume(
    state: &ConferenceState,
    _user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let data = match data {
        Some(d) => d,
        None => {
            send_media_error(state, connection_id, "Missing data").await;
            return;
        }
    };

    let room_id_str = match data.get("room_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            send_media_error(state, connection_id, "Missing room_id").await;
            return;
        }
    };
    let producer_id_str = match data.get("producer_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            send_media_error(state, connection_id, "Missing producer_id").await;
            return;
        }
    };
    let rtp_capabilities: RtpCapabilities = match data
        .get("rtp_capabilities")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(c) => c,
        None => {
            send_media_error(state, connection_id, "Invalid rtp_capabilities").await;
            return;
        }
    };

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => {
            send_media_error(state, connection_id, "Invalid room_id").await;
            return;
        }
    };

    let producer_id = match producer_id_str.parse::<ProducerId>() {
        Ok(id) => id,
        Err(_) => {
            send_media_error(state, connection_id, "Invalid producer_id").await;
            return;
        }
    };

    match state
        .room_manager
        .consume(&rid, connection_id, producer_id, &rtp_capabilities)
        .await
    {
        Ok(consumer_info) => {
            let msg = serde_json::json!({
                "type": "media:consumer_created",
                "data": {
                    "id": consumer_info.id,
                    "producer_id": consumer_info.producer_id,
                    "kind": consumer_info.kind,
                    "rtp_parameters": consumer_info.rtp_parameters,
                    // FR-30 P4 — the pause EVENT only reaches whoever was
                    // already in the room, so the state has to ride the
                    // subscription too. Without it, joining after someone
                    // muted shows no badge until their next toggle.
                    "producer_paused": consumer_info.producer_paused,
                }
            });
            meshharbor_core::ws::dispatcher::send_to_connection_routed(
                &state.ws_storage,
                &state.redis_pubsub,
                connection_id,
                &msg,
            )
            .await;
        }
        Err(e) => {
            send_media_error(state, connection_id, &format!("consume failed: {}", e)).await;
        }
    }
}

/// FR-30 — relay "my camera/mic just went off (or back on)" to the room.
///
/// Without this a peer cannot tell: `producer.pause()` in mediasoup-client is
/// LOCAL, and a track with `enabled = false` keeps its RTP stream alive with
/// black frames, so the receiving track stays `live` and UNMUTED. Measured on
/// prod 2026-08-29 — the far side saw `enabled:true, readyState:"live",
/// muted:false` after the sender switched their camera off, which is why
/// "hide participants without video" could never hide anyone.
///
/// Shaped exactly like `handle_media_producer_close` below, and additive: an
/// older client never sends this and ignores the event it would receive.
async fn handle_media_producer_pause(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let Some(data) = data else { return };
    let Some(room_id_str) = data.get("room_id").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(producer_id_str) = data.get("producer_id").and_then(|v| v.as_str()) else {
        return;
    };
    // Absent means "pause": the only caller that omits it is a client that
    // predates the resume half, and pausing is the safe reading.
    let paused = data.get("paused").and_then(|v| v.as_bool()).unwrap_or(true);

    let Ok(rid) = ObjectId::parse_str(room_id_str) else {
        return;
    };
    let Ok(producer_id) = producer_id_str.parse::<ProducerId>() else {
        return;
    };

    if !state
        .room_manager
        .set_producer_paused(&rid, connection_id, &producer_id, paused)
        .await
    {
        // The producer is not ours, or is already gone. Say nothing: fanning
        // out an unverified claim would let one participant blank another's
        // tile for everybody.
        return;
    }

    let other_conns = state
        .room_manager
        .get_other_connection_ids(&rid, connection_id);
    if other_conns.is_empty() {
        return;
    }

    let event = serde_json::json!({
        "type": "media:producer_paused",
        "data": {
            "producer_id": producer_id.to_string(),
            "user_id": user_id.to_hex(),
            "paused": paused,
        }
    });
    for conn_id in &other_conns {
        meshharbor_core::ws::dispatcher::send_to_connection_routed(
            &state.ws_storage,
            &state.redis_pubsub,
            conn_id,
            &event,
        )
        .await;
    }
}

async fn handle_media_producer_close(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let data = match data {
        Some(d) => d,
        None => return,
    };

    let room_id_str = match data.get("room_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };
    let producer_id_str = match data.get("producer_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => return,
    };

    let producer_id = match producer_id_str.parse::<ProducerId>() {
        Ok(id) => id,
        Err(_) => return,
    };

    if state
        .room_manager
        .close_producer(&rid, connection_id, &producer_id)
    {
        state
            .room_manager
            .remove_rtp_tap(&rid, &producer_id.to_string());

        let other_conns = state
            .room_manager
            .get_other_connection_ids(&rid, connection_id);

        if !other_conns.is_empty() {
            let event = serde_json::json!({
                "type": "media:producer_closed",
                "data": {
                    "producer_id": producer_id.to_string(),
                    "user_id": user_id.to_hex(),
                }
            });
            for conn_id in &other_conns {
                meshharbor_core::ws::dispatcher::send_to_connection_routed(
                    &state.ws_storage,
                    &state.redis_pubsub,
                    conn_id,
                    &event,
                )
                .await;
            }
        }
    }
}

async fn handle_media_leave(
    state: &ConferenceState,
    user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let room_id_str = match data.and_then(|d| d.get("room_id")).and_then(|c| c.as_str()) {
        Some(s) => s,
        None => return,
    };

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => return,
    };

    let other_conns = state
        .room_manager
        .get_other_connection_ids(&rid, connection_id);

    state.room_manager.close_participant(&rid, connection_id);

    if !other_conns.is_empty() {
        let event = serde_json::json!({
            "type": "media:peer_left",
            "data": {
                "user_id": user_id.to_hex(),
                "connection_id": connection_id,
                "room_id": rid.to_hex(),
            }
        });
        for conn_id in &other_conns {
            meshharbor_core::ws::dispatcher::send_to_connection_routed(
                &state.ws_storage,
                &state.redis_pubsub,
                conn_id,
                &event,
            )
            .await;
        }
    }
}

async fn handle_play_audio(
    state: &ConferenceState,
    _user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let data = match data {
        Some(d) => d,
        None => return,
    };

    let room_id_str = match data.get("room_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };
    let file_id = match data.get("file_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => return,
    };
    let fid = match ObjectId::parse_str(file_id) {
        Ok(id) => id,
        Err(_) => return,
    };

    // Look up the room to get tenant_id
    let room = match state.rooms.base.find_by_id(rid).await {
        Ok(r) => r,
        Err(e) => {
            warn!(%e, "Failed to find room for file playback");
            return;
        }
    };

    // FR-69 P3 — `files` is the `chat` module's; a DAO is a stateless handle
    // on the collection, so this playback path builds its own until the
    // media handlers move with conference (P4).
    let files = meshharbor_services::dao::file::FileDao::new(&state.db);
    let file = match files.base.find_by_id_in_tenant(room.tenant_id, fid).await {
        Ok(f) => f,
        Err(e) => {
            warn!(%e, "Failed to find file for playback");
            return;
        }
    };

    let playback_id = String::new();

    let file_url = format!(
        "/api/tenant/{}/file/{}/download",
        room.tenant_id.to_hex(),
        fid.to_hex(),
    );
    let msg = serde_json::json!({
        "type": "media:audio_playback",
        "data": {
            "action": "start",
            "file_url": file_url,
            "file_id": file_id,
            "filename": file.filename,
            "playback_id": playback_id,
            "room_id": room_id_str,
        }
    });

    meshharbor_core::ws::dispatcher::send_to_connection_routed(
        &state.ws_storage,
        &state.redis_pubsub,
        connection_id,
        &msg,
    )
    .await;
    let other_conns = state
        .room_manager
        .get_other_connection_ids(&rid, connection_id);
    for cid in &other_conns {
        meshharbor_core::ws::dispatcher::send_to_connection_routed(
            &state.ws_storage,
            &state.redis_pubsub,
            cid,
            &msg,
        )
        .await;
    }

    info!(%rid, %file_id, %playback_id, "Audio playback started");
}

async fn handle_stop_audio(
    state: &ConferenceState,
    _user_id: &ObjectId,
    connection_id: &str,
    data: Option<&serde_json::Value>,
) {
    let data = match data {
        Some(d) => d,
        None => return,
    };

    let room_id_str = match data.get("room_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };
    let playback_id = match data.get("playback_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };

    let rid = match ObjectId::parse_str(room_id_str) {
        Ok(id) => id,
        Err(_) => return,
    };

    let msg = serde_json::json!({
        "type": "media:audio_playback",
        "data": {
            "action": "stop",
            "playback_id": playback_id,
            "room_id": room_id_str,
        }
    });

    meshharbor_core::ws::dispatcher::send_to_connection_routed(
        &state.ws_storage,
        &state.redis_pubsub,
        connection_id,
        &msg,
    )
    .await;
    let other_conns = state
        .room_manager
        .get_other_connection_ids(&rid, connection_id);
    for cid in &other_conns {
        meshharbor_core::ws::dispatcher::send_to_connection_routed(
            &state.ws_storage,
            &state.redis_pubsub,
            cid,
            &msg,
        )
        .await;
    }

    info!(%rid, %playback_id, "Audio playback stopped");
}
