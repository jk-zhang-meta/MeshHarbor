// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::state::AppState;

// FR-69 P7b — what every upgrade shares moved to core: the query shape, the
// affinity check and the "say why, then close" refusal. Re-exported so the
// paths in this crate read as before.
pub use roomler_core::ws::upgrade::{WsParams, send_goodbye_and_close, tid_matches_claim};

pub async fn ws_upgrade(
    State(state): State<AppState>,
    Query(params): Query<WsParams>,
    // Wave 2 — the User-Agent and forwarded-for header are read HERE,
    // at the only point where they exist. The UA yields a browser
    // family; the IP resolves to a country and is then dropped (see
    // `user_analytics`) — neither the address nor the raw UA is stored.
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    match params.role.as_deref() {
        // Native clients. They have no cookie jar, so the URL is the only
        // place their credential can be — and accepting a cookie for these
        // roles would mean a logged-in browser could open an AGENT socket.
        // FR-69 P7b — the upgrades are their owners': the agent socket is
        // fleet's, the tunnel-client socket is network's. The host keeps the
        // `/ws` route and this role gate; a role whose module is not mounted
        // is refused with 503 rather than silently dropped.
        Some("agent") => match params.token {
            Some(t) => state.modules.agent_upgrade(t, params.tid, ws).await,
            None => unauthorized("agent role requires ?token="),
        },
        Some("tunnel-client") => match params.token {
            Some(t) => state.modules.tunnel_client_upgrade(t, params.tid, ws),
            None => unauthorized("tunnel-client role requires ?token="),
        },
        _ => {
            // Browser. Prefer the query token while older bundles are still
            // cached and still sending it; otherwise the session cookie.
            match params.token {
                Some(t) => ws_upgrade_user(state, t, params.tid, headers, ws).await,
                None => {
                    let Some(t) = session_cookie(&headers) else {
                        return unauthorized("no session");
                    };
                    // ⚠️ A cookie is AMBIENT: the browser attaches it to a
                    // handshake the page never had to prove it could obtain.
                    // A WebSocket upgrade is not subject to CORS, so any page
                    // on the internet may open a socket here — meaning that
                    // once a cookie is accepted, "who is asking" has to be
                    // answered by the request rather than by the credential.
                    //
                    // `SameSite=Lax` already keeps the cookie off a
                    // cross-site handshake, so this is the second lock, not
                    // the only one. It applies ONLY to the cookie path: a
                    // query token is a credential the caller had to get hold
                    // of first, and native clients send no Origin at all.
                    if !origin_is_ours(&state, &headers) {
                        return forbidden("origin not permitted for cookie auth");
                    }
                    ws_upgrade_user(state, t, params.tid, headers, ws).await
                }
            }
        }
    }
}

fn unauthorized(why: &str) -> Response {
    debug!(reason = %why, "ws upgrade refused");
    Response::builder()
        .status(401)
        .body("Unauthorized".into())
        .unwrap()
}

fn forbidden(why: &str) -> Response {
    // The reason stays server-side: it names our own configuration.
    debug!(reason = %why, "ws upgrade refused");
    Response::builder()
        .status(403)
        .body("Forbidden".into())
        .unwrap()
}

/// The `access_token` session cookie, if the browser sent one.
fn session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    crate::cookies::get(headers, "access_token")
}

/// Is this handshake coming from a page we serve?
///
/// A browser ALWAYS sends `Origin` on a WebSocket handshake, so an absent one
/// means the caller is not a browser — and a non-browser presenting a browser
/// session cookie is not a case worth accommodating. Refuse.
fn origin_is_ours(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let policy = crate::origin::policy_from_settings(&state.settings);
    crate::origin::is_trusted(&policy, origin)
}

async fn ws_upgrade_user(
    state: AppState,
    token: String,
    tid: Option<String>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let claims = match state.auth.verify_access_token(&token) {
        Ok(c) => c,
        Err(_) => {
            return Response::builder()
                .status(401)
                .body("Unauthorized".into())
                .unwrap();
        }
    };

    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return Response::builder()
                .status(400)
                .body("Invalid user ID".into())
                .unwrap();
        }
    };

    // A valid signature is not current account admission. This is deliberately
    // shared with HTTP/OAuth/refresh, rather than a separate socket policy.
    if roomler_core::admission::authorize_claims(&state.core, &claims)
        .await
        .is_err()
    {
        return forbidden("account admission denied");
    }

    // S6 — user JWTs carry no tenant claim, so a present `tid` is
    // validated against `tenant_members`. Rejecting a non-member claim
    // matters: `tid` is attacker-choosable in the URL, and accepting an
    // arbitrary value would let a user steer their affinity onto any
    // tenant's pod (harmless for data access — every route re-checks
    // membership — but it would poison the co-location guarantee).
    if let Some(t) = &tid {
        let tenant_ok = match ObjectId::parse_str(t) {
            Ok(tenant_oid) => state
                .tenants
                .is_member(tenant_oid, user_id)
                .await
                .unwrap_or(false),
            Err(_) => false,
        };
        if !tenant_ok {
            return Response::builder()
                .status(403)
                .body("Not a member of the claimed tenant".into())
                .unwrap();
        }
    }

    let username = claims.username.clone();

    // Wave 2 — analytics identity, resolved before the upgrade consumes
    // the headers. `client_ip_from_headers` applies the same trusted-hop
    // rule the rate limiter uses, so a client-forged XFF can't move
    // itself to another country.
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let ip = crate::middleware::client_ip::client_ip_from_headers(
        &headers,
        state.settings.app.rate_limit_trusted_hops,
    );
    let analytics_tenant = tid.as_deref().and_then(|t| ObjectId::parse_str(t).ok());

    ws.max_message_size(crate::ws::MAX_WS_MESSAGE_BYTES)
        .max_frame_size(crate::ws::MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let session =
                crate::user_analytics::open_session(&state, user_id, analytics_tenant, &ua, ip)
                    .await;
            handle_socket(socket, state.clone(), user_id, username, tid, claims).await;
            if let Some(id) = session {
                crate::user_analytics::close_session(&state, id).await;
            }
        })
}

async fn handle_socket(
    socket: WebSocket,
    state: AppState,
    user_id: ObjectId,
    username: String,
    // PR-1 rehome — the (validated) affinity key this conn dialed with,
    // kept for the cross-pod direction rule. None = key-less dial that
    // hashed on client IP.
    dialed_tid: Option<String>,
    claims: roomler_ai_services::auth::Claims,
) {
    // Close the upgrade-to-registration race before registering any controller.
    if !admission_current(&state.core, &claims).await {
        return;
    }
    let connection_id = Uuid::new_v4().to_string();
    let conn_established_ms = bson::DateTime::now().timestamp_millis();
    info!(?user_id, %connection_id, "WebSocket connected");

    let (sender, mut receiver) = socket.split();
    let sender = Arc::new(Mutex::new(sender));

    state
        .ws_storage
        .add(user_id, connection_id.clone(), sender.clone());

    // Register this tab with the remote-control Hub so `rc:*` replies find us.
    // Each browser tab gets its own controller tx; the Hub routes by tx, not
    // by user id, so multiple tabs don't cross signals. FR-69 P7b — the Hub
    // is the fleet module's; a pod without it has no controller plane, and
    // the tab's `rc:*` frames fall through unhandled.
    let rc = state.modules.register_controller(user_id, sender.clone());

    // The watchdog races the ENTIRE session, not only receiver.next(): slow
    // writes, initialization and stalled module handlers must not prevent revoke.
    let revoked = run_until_revoked(
        async {
            // S6 — mirror into the cross-pod online registry (advisory; the 30 s
            // heartbeat in main.rs re-asserts it and the 90 s TTL self-heals).
            if let Some(pubsub) = &state.redis_pubsub
                && let Err(e) = pubsub.online_add(&user_id.to_hex()).await
            {
                tracing::debug!("online-registry add failed: {e}");
            }

            {
                // `connection_id` lets the client scope its call sessions to this
                // exact WS connection (call/join + call/leave bodies) — the id is
                // minted per socket, so consumers must re-read it after any redial.
                let msg = serde_json::json!({
                    "type": "connected",
                    "user_id": user_id.to_hex(),
                    "connection_id": connection_id,
                });
                let mut guard = sender.lock().await;
                let _ = guard
                    .send(Message::text(serde_json::to_string(&msg).unwrap()))
                    .await;
            }

            // Resolve a human-friendly display name for this controller once per
            // connection. It's the identity shown to the viewee — the "Being
            // viewed by" overlay caption + its initials avatar — and in owner
            // approval notifications. The JWT only carries the login username, so
            // look up the profile's display_name here, falling back to the
            // username when it's unset.
            let controller_display = match state.users.base.find_by_id(user_id).await {
                Ok(u) if !u.display_name.trim().is_empty() => u.display_name,
                _ => username,
            };

            while let Some(msg) = receiver.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if !admission_current(&state.core, &claims).await {
                            break;
                        }
                        handle_client_message(
                            &state,
                            &user_id,
                            &connection_id,
                            &controller_display,
                            rc.as_ref().map(|(tx, _)| tx),
                            &text,
                            dialed_tid.as_deref(),
                            conn_established_ms,
                        )
                        .await;
                    }
                    Ok(Message::Ping(data)) => {
                        let mut guard = sender.lock().await;
                        let _ = guard.send(Message::Pong(data)).await;
                    }
                    Ok(Message::Close(_)) => {
                        break;
                    }
                    Err(e) => {
                        warn!(?user_id, %connection_id, %e, "WebSocket error");
                        break;
                    }
                    _ => {}
                }
            }
        },
        async {
            if !state.settings.auth.account_approval.enabled {
                std::future::pending::<()>().await;
            }
            loop {
                if !admission_current(&state.core, &claims).await {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        },
    )
    .await;
    if revoked {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            sender.lock().await.send(Message::Close(None)).await
        })
        .await;
    }

    // Cleanup
    state.modules.unregister_controller(user_id, rc.as_ref());
    // PR-2 — this conn may have rc sessions proxied on OTHER pods: tell
    // each owner (fire-and-forget; the relay's janitor sweep is the
    // belt), mirroring the C-4 media leave-forwarding below. The `remote`
    // module's (FR-69 P6); a no-op when it is not mounted.
    state.modules.remote_conn_closed(&connection_id);
    state.ws_storage.remove(&user_id, &connection_id, &sender);

    // S6 — drop this pod's online-registry claim once the user's LAST
    // local connection is gone (other pods' claims are theirs to clear).
    if !state.ws_storage.is_connected(&user_id)
        && let Some(pubsub) = &state.redis_pubsub
        && let Err(e) = pubsub.online_remove(&user_id.to_hex()).await
    {
        tracing::debug!("online-registry remove failed: {e}");
    }

    // FR-69 P4 — the modules' per-connection state: conference drops this
    // connection's transports (local, or at the owning pod) and closes its
    // call session — a leave the client never sent.
    let ctx = roomler_core::WsCtx {
        connection_id: connection_id.clone(),
        role: roomler_core::Role::User,
        principal: user_id,
        tenant_id: dialed_tid
            .as_deref()
            .and_then(|t| ObjectId::parse_str(t).ok()),
    };
    state.modules.ws_closed(&ctx).await;

    info!(?user_id, %connection_id, "WebSocket disconnected");
}

/// Dropping the losing session future releases any sender lock before cleanup.
async fn run_until_revoked(
    session: impl std::future::Future<Output = ()>,
    revocation: impl std::future::Future<Output = ()>,
) -> bool {
    tokio::select! {
        biased;
        _ = revocation => true,
        _ = session => false,
    }
}

async fn admission_current(
    core: &roomler_core::Core,
    claims: &roomler_ai_services::auth::Claims,
) -> bool {
    if !core.settings.auth.account_approval.enabled {
        return true;
    }
    // User JWT expiry must apply to long-lived sockets as well as new requests.
    if claims.exp <= chrono::Utc::now().timestamp() {
        return false;
    }
    roomler_core::admission::authorize_claims(core, claims)
        .await
        .is_ok()
}

#[allow(clippy::too_many_arguments)]
async fn handle_client_message(
    state: &AppState,
    user_id: &ObjectId,
    connection_id: &str,
    username: &str,
    rc_controller_tx: Option<&roomler_ai_remote_control::session::ClientTx>,
    text: &str,
    dialed_tid: Option<&str>,
    conn_established_ms: i64,
) {
    // Remote-control messages use a `t` discriminator prefixed with "rc:".
    // Peek at the raw JSON before full parse so we don't pay the cost on
    // every media/presence message. The frame is the `remote` module's
    // (FR-69 P6): its authz gate + dispatch run there, with this
    // connection's Hub-registered sender; `false` = not an rc:* frame, or
    // no `remote` module mounted — either way the arms below get it. No
    // sender (no fleet module) = no controller plane at all.
    if text.contains("\"rc:")
        && let Some(tx) = rc_controller_tx
        && state
            .modules
            .remote_controller_frame(
                *user_id,
                username,
                tx,
                text,
                dialed_tid,
                conn_established_ms,
                connection_id,
            )
            .await
    {
        return;
    }

    let parsed: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return,
    };

    let msg_type = parsed.get("type").and_then(|t| t.as_str()).unwrap_or("");
    let data = parsed.get("data");

    debug!(?user_id, %connection_id, msg_type, "WS message received");

    match msg_type {
        "ping" => {
            let pong = serde_json::json!({ "type": "pong" });
            super::dispatcher::send_to_user(&state.ws_storage, user_id, &pong).await;
        }
        "presence:update" => {
            if let Some(presence) = data
                .and_then(|d| d.get("presence"))
                .and_then(|p| p.as_str())
            {
                let event = serde_json::json!({
                    "type": "presence:update",
                    "data": {
                        "user_id": user_id.to_hex(),
                        "presence": presence,
                    }
                });
                // S6 — broadcast-flag envelope: each pod delivers to its
                // OWN local users. The previous recipient list was this
                // pod's `all_user_ids()`, which silently excluded every
                // user connected to the other pod.
                super::dispatcher::broadcast_all_with_redis(
                    &state.ws_storage,
                    &state.redis_pubsub,
                    &event,
                )
                .await;
            }
        }
        _ => {
            // FR-69 — a module's namespace (`typing:*` is chat's). The host
            // knows the socket; the module knows the message.
            if let Some(handler) = state.modules.ws_handler(roomler_core::Role::User, msg_type) {
                let ctx = roomler_core::WsCtx {
                    connection_id: connection_id.to_string(),
                    role: roomler_core::Role::User,
                    principal: *user_id,
                    tenant_id: dialed_tid.and_then(|t| ObjectId::parse_str(t).ok()),
                };
                if let Err(e) = handler.handle(&ctx, parsed.clone()).await {
                    debug!(?user_id, msg_type, %e, "module WS handler failed");
                }
            } else {
                debug!(?user_id, msg_type, "Unknown WS message type");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, header::COOKIE};

    fn with_cookie(raw: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, HeaderValue::from_str(raw).unwrap());
        h
    }

    #[tokio::test]
    async fn account_approval_watchdog_cancels_stalled_session_and_releases_lock() {
        let sender = Arc::new(Mutex::new(()));
        let session_sender = sender.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let revoked = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_until_revoked(
                async move {
                    let _held = session_sender.lock().await;
                    let _ = started_tx.send(());
                    // A handler/write that never finishes, with the sender held.
                    std::future::pending::<()>().await;
                },
                async move {
                    let _ = started_rx.await;
                },
            ),
        )
        .await
        .unwrap();
        assert!(revoked);
        assert!(
            sender.try_lock().is_ok(),
            "cleanup must not inherit held locks"
        );
    }

    #[tokio::test]
    async fn account_approval_watchdog_preserves_completed_session() {
        assert!(!run_until_revoked(async {}, std::future::pending()).await);
    }

    #[test]
    fn reads_the_session_cookie_among_others() {
        // Real browsers send several; the session must be found wherever it
        // sits, and a cookie whose name merely ENDS with ours must not match.
        assert_eq!(
            session_cookie(&with_cookie("access_token=abc.def.ghi")).as_deref(),
            Some("abc.def.ghi")
        );
        assert_eq!(
            session_cookie(&with_cookie("theme=dark; access_token=t0k; lang=en")).as_deref(),
            Some("t0k")
        );
        assert_eq!(
            session_cookie(&with_cookie("other_access_token=nope")),
            None,
            "a different cookie ending in our name must not be picked up"
        );
    }

    #[test]
    fn no_cookie_header_and_an_empty_value_both_yield_none() {
        assert_eq!(session_cookie(&HeaderMap::new()), None);
        assert_eq!(session_cookie(&with_cookie("access_token=")), None);
        assert_eq!(session_cookie(&with_cookie("theme=dark")), None);
    }
}
