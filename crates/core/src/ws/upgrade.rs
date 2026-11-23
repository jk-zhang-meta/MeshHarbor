// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! What every WebSocket upgrade shares (FR-69 P7b): the frame ceiling, the
//! query shape the three roles and `/derp` dial with, the affinity check,
//! and the "say why, then close" refusal. The upgrades themselves live with
//! their owners — the user socket in the host, the agent socket in `fleet`,
//! the tunnel-client socket and `/derp` in `network` — and each of them
//! needs exactly these four.

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use serde::Deserialize;
use tracing::{debug, warn};

/// Upper bound on one inbound WebSocket message AND on one frame, applied to
/// every upgrade.
///
/// axum inherits tungstenite's defaults (64 MiB message, 16 MiB frame), and
/// nothing else bounds a post-upgrade frame: `tower_governor` is HTTP
/// middleware and never sees them, so an authenticated peer could make the
/// server buffer multi-MiB messages on every connection it opens.
///
/// Everything that legitimately crosses these sockets is control-plane —
/// signalling JSON, a netmap, an MTU-sized DERP packet — so 8 MiB is orders of
/// magnitude above real traffic while removing that amplification. Deliberately
/// generous rather than tight: a cap that is merely large is safe, whereas one
/// tuned close to the real maximum silently drops a big-but-valid netmap on the
/// day a fleet grows.
pub const MAX_WS_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// The query every socket dial carries.
#[derive(Debug, Deserialize)]
pub struct WsParams {
    /// The credential, when it travels in the URL.
    ///
    /// **Optional since the session-cookie path landed.** A browser on our own
    /// origin no longer needs it: the handshake is same-origin, so the
    /// `access_token` cookie is attached automatically and the host's
    /// `session_cookie` reads it. Native clients (the agent, the tunnel CLI)
    /// have no cookie jar and always send it.
    ///
    /// Why the browser should stop sending it: a query string is written to
    /// every access log it passes through and kept in browser history, and
    /// long-lived sockets reconnect constantly — so a 7-day credential piled
    /// up in plaintext on disk. `files/nginx-pod.conf` currently answers that
    /// with `access_log off` on `/ws`, which is a stopgap to be removed once
    /// nothing emits `?token=` any more.
    #[serde(default)]
    pub token: Option<String>,
    /// Optional connection role. Defaults to `"user"` to preserve existing
    /// browser behaviour. Set to `"agent"` by the native remote-control agent.
    #[serde(default)]
    pub role: Option<String>,
    /// S6 — optional tenant-affinity key. The front load-balancer hashes
    /// on it so one tenant's users, agents, tunnel clients and DERP
    /// sockets co-locate on one pod (the in-memory rc-hub / tunnel-hub /
    /// mediasoup state is pod-local). The SERVER only validates it:
    /// agent/tunnel JWTs carry `tenant_id` → must match; user JWTs carry
    /// no tenant claim → validated via a `tenant_members` lookup.
    /// Absent = legacy client → accepted (the LB pins those to pod 1).
    #[serde(default)]
    pub tid: Option<String>,
    /// FR-128 — an agent that came through a zone's management entry presents the entry's
    /// attestation of its address here (`meshharbor_remote_control::management_entry`). Read
    /// only for `role=agent`; checked by the fleet module before anything reads the origin.
    #[serde(default)]
    pub entry: Option<String>,
}

/// Validate a claimed affinity `tid` against a token-derived tenant id.
/// `None` (param absent) is always fine — validation only rejects a
/// PRESENT-but-wrong claim (mis-routed or forged affinity key).
pub fn tid_matches_claim(tid: &Option<String>, claim_tenant_hex: &str) -> bool {
    match tid {
        None => true,
        Some(t) => t == claim_tenant_hex,
    }
}

/// rc.53: push a server-initiated close frame WITH a structured
/// `ServerMsg` text frame in front of it, so the agent / tunnel-client
/// learns WHY the connection is being closed before the socket
/// drops. Used at the WS-handler refusal sites (the agent and
/// tunnel-client upgrades) when the row is deleted or quarantined.
///
/// Tungstenite serialises both frames into the same outbound TCP
/// buffer; the OS delivers them in order. No `sleep` guard is needed
/// — the `.await` on `send(Close)` completes the underlying flush.
/// On send-error we still attempt the close so the agent at least
/// gets the TCP FIN; on close-send-error we just drop (the socket
/// is already dead, nothing further to do).
pub async fn send_goodbye_and_close<M: serde::Serialize>(
    socket: WebSocket,
    msg: &M,
    close_code: u16,
    close_reason: &str,
) {
    let mut socket = socket;
    let json = match serde_json::to_string(msg) {
        Ok(s) => s,
        Err(e) => {
            warn!(%e, "failed to serialise Goodbye payload; closing without it");
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };
    if let Err(e) = socket.send(Message::Text(json.into())).await {
        warn!(%e, "Goodbye text-send failed; attempting close anyway");
    }
    if let Err(e) = socket
        .send(Message::Close(Some(CloseFrame {
            code: close_code,
            reason: close_reason.to_string().into(),
        })))
        .await
    {
        debug!(%e, "Goodbye close-send failed (socket may already be dropped)");
    }
    // socket drops here; tungstenite has flushed both frames into
    // the outbound TCP buffer before the close-send `.await`
    // returned.
}
