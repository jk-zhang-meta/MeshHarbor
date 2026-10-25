// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! WebSocket handler for `roomler` clients (`role=tunnel-client`).
//!
//! T2.5 wires the server-side ACL gate. Lifecycle:
//!
//! 1. Verify the TunnelClient JWT at WS upgrade (`ws::handler::
//!    ws_upgrade_tunnel_client`) and run a connect-time revocation
//!    check on the row.
//! 2. Drive the WS read loop: parse each text frame as
//!    `signaling::ClientMsg`, dispatch on the `rc:tunnel.*` variants:
//!    - `TunnelHello`: cap-negotiation handshake.
//!    - `TunnelOpen`: cross-tenant gate (defence-in-depth) + audit
//!      the session start. T2.6+ will add the actual WebRTC offer/
//!      answer + DC-pool negotiation; for now we reply with a
//!      `TunnelOpened` stub so downstream tests can drive the
//!      dispatch surface.
//!    - `TcpForwardRequest`: invoke
//!      `tunnel_core::policy::check_forward_request` against the
//!      live `tunnel_policies` for the agent's tenant. Audit either
//!      `TcpAccept` or `TcpReject`. T2.6+ relays accepts to the
//!      agent's WS; today we reply with a stub `TcpForwardAccept`
//!      that downstream tests assert on.
//!    - Other variants land in T2.6+ (data-plane relays).
//! 3. Periodic revocation re-check (60 s) — re-reads `tunnel_clients.
//!    status`, sends `TunnelRevoked` if the row turns bad mid-session.
//!
//! Audit context: every `tunnel forward` invocation gets one
//! `tunnel_session_id` (assigned by the server on `TunnelOpen`).
//! Every flow + peer event references it for correlation in the
//! audit log (see `crates/services/src/dao/tunnel_audit.rs`).

use axum::extract::ws::{Message, WebSocket};
use bson::{DateTime, oid::ObjectId};
use futures::{SinkExt, StreamExt, stream::SplitSink};
use roomler_ai_remote_control::{
    models::{AgentStatus, OsKind, RelayMode, TunnelAuditEvent, TunnelAuditKind},
    signaling::{
        ClientMsg, CloseReason, REJECT_REASON_NO_SESSION, REJECT_REASON_SESSION_MISMATCH,
        RejectKind, ServerMsg,
    },
    vault::{NET_GRANT_REFUSED, NetKind, canonical_net_host},
};
use roomler_ai_services::auth::AuthService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};
use tunnel_core::policy::{
    GateResult, Principal, ProtocolKind, ResolvedSubject, check_forward_request,
};
use tunnel_core::transport::{TRANSPORT_QUIC_V1, TRANSPORT_WEBRTC_DC_V1};

use crate::NetworkState;
use crate::agent_arms::pump_server_messages;
use axum::{extract::WebSocketUpgrade, response::Response};
use roomler_core::ws::upgrade::{MAX_WS_MESSAGE_BYTES, send_goodbye_and_close, tid_matches_claim};
use roomler_core::{business_authority::AuthenticatedDevice, client_ip::ConnectionOrigin};

/// Outbound channel capacity. Per-tunnel-client. Generous because a
/// single peer multiplexes many flows; the dominant traffic is per-
/// flow audit relays + ICE trickle, both small and sporadic.
const OUTBOUND_CAP: usize = 256;

/// Cadence of the revocation re-check. 60 s is the v1 default —
/// cheap (one Mongo find_by_id per minute per active connection)
/// and matches the existing agent heartbeat rhythm.
const REVOCATION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

fn authority_identity_current(
    presented_generation: u32,
    row_generation: u32,
    claimed_owner: ObjectId,
    current_owner: ObjectId,
) -> bool {
    presented_generation == row_generation && claimed_owner == current_owner
}

async fn observe_business_connection(
    state: &NetworkState,
    tenant_id: ObjectId,
    client_id: ObjectId,
    owner_user_id: ObjectId,
    presented_generation: u32,
    origin: &ConnectionOrigin,
    connection_id: &str,
) -> Option<AuthenticatedDevice> {
    let current = tokio::time::timeout(Duration::from_secs(3), async {
        let row = state
            .tunnel_clients
            .find_live_in_tenant(tenant_id, client_id)
            .await?;
        if matches!(row.status, AgentStatus::Quarantined)
            || !authority_identity_current(
                presented_generation,
                row.token_gen,
                owner_user_id,
                row.owner_user_id,
            )
        {
            return Err(roomler_core::ApiError::Unauthorized(
                "Current client identity required for business evidence".into(),
            ));
        }
        roomler_core::admission::authorize_user_id(&state.core, row.owner_user_id, None).await?;
        AuthenticatedDevice::from_tunnel_client(&row)
    })
    .await;
    let device = match current {
        Ok(Ok(device)) => device,
        _ => {
            warn!(%client_id, "business identity unavailable; retaining management socket without authority");
            return None;
        }
    };
    if !matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            roomler_core::business_authority::record_connection_observation(
                &state.core,
                &device,
                origin,
                connection_id,
            ),
        )
        .await,
        Ok(Ok(_))
    ) {
        warn!(%client_id, "business observation unavailable; no business authority inferred");
    }
    Some(device)
}

/// Drive a tunnel-client WS until either the client closes, the
/// signalling layer errors, or the revocation re-check kills the
/// connection. Replaces the T1 stub message loop with real
/// `rc:tunnel.*` dispatch.
pub async fn handle_tunnel_client_socket(
    state: NetworkState,
    socket: WebSocket,
    tunnel_client_id: ObjectId,
    tenant_id: ObjectId,
    owner_user_id: ObjectId,
    dialed_tid: Option<String>,
    connection_origin: ConnectionOrigin,
    presented_generation: u32,
) {
    info!(%tunnel_client_id, %tenant_id, %owner_user_id, "tunnel-client WS connected");
    let conn_established_ms = bson::DateTime::now().timestamp_millis();
    let connection_id = uuid::Uuid::new_v4().to_string();
    // MeshHarbor #21 — this connection's opening observation is the client's
    // zone evidence (`org_relay::node_zone`), as an agent's is from its hello.
    state
        .org_relay
        .bind_live_conn(tunnel_client_id, &connection_id);
    let business_observation = roomler_core::business_authority::ObservationTask::spawn({
        let (state, origin, connection_id) = (state.clone(), connection_origin.clone(), connection_id.clone());
        async move {
            observe_business_connection(
                &state,
                tenant_id,
                tunnel_client_id,
                owner_user_id,
                presented_generation,
                &origin,
                &connection_id,
            )
            .await
        }
    });

    let (socket_tx, mut socket_rx) = socket.split();
    let socket_tx = Arc::new(Mutex::new(socket_tx));

    // Outbound channel pattern — mirrors the agent WS handler's
    // Hub-owned mpsc. All `ServerMsg` writes go through `outbound_tx`;
    // a single pump task drains the receiver onto the socket. Once
    // the tunnel-session is established we register a clone of
    // `outbound_tx` in `NetworkState::tunnel_clients_by_session` so the
    // agent's WS handler can push relayed `TcpForwardAccept` etc.
    // back to this client.
    let (outbound_tx, outbound_rx) = mpsc::channel::<ServerMsg>(OUTBOUND_CAP);
    let pump = tokio::spawn(pump_server_messages(outbound_rx, socket_tx.clone()));

    // Register this connection in the overlay registry (keyed by
    // tunnel_client_id) so the overlay broker can fan netmaps/deltas to
    // it as a node. Harmless if the client never joins the overlay;
    // removed on disconnect below.
    state
        .overlay_nodes_by_id
        .insert(tunnel_client_id, outbound_tx.clone());

    // Look up tunnel-client metadata once for audit-row enrichment
    // (client_version + client_os). Best-effort — audit rows still
    // get written if this fails, just with empty version/os.
    //
    // LIVE (#1829): the connect-time check already refused a tombstone; a
    // removal in the gap between it and here means there is nothing to
    // enrich with, the WARN below names the client, and the 60 s poll's
    // kick is on its way.
    let (client_version, client_os) = match state
        .tunnel_clients
        .find_live_in_tenant(tenant_id, tunnel_client_id)
        .await
    {
        Ok(c) => (c.client_version, c.os),
        Err(e) => {
            warn!(%tunnel_client_id, %e, "tunnel-client lookup failed; audit rows will be sparse");
            (
                String::new(),
                roomler_ai_remote_control::models::OsKind::Linux,
            )
        }
    };

    // Per-connection session state. Set on `TunnelOpen` and carried
    // by every audit row + outbound message.
    let mut session: Option<TunnelSession> = None;

    // Transports the client advertised in `rc:tunnel.hello`. Captured
    // here so `TunnelOpen` can intersect them with the requested
    // transport (Phase 1c). Empty until hello arrives → quic-v1 is
    // never negotiated, which is the safe default.
    let mut client_supported_transports: Vec<String> = Vec::new();

    // Bundle the originator identity + reply channel once. Every tunnel
    // handler is subject-agnostic (P3b-2) and takes this by ref, so the
    // very same open/forward/relay/audit code serves an agent driving the
    // tunnel-client role over its own WS (see
    // `relay_tunnel_client_msg_from_agent`). `client_version` is moved in
    // here; `client_os` + the ids are Copy, so the locals remain for the
    // logs / revocation task / overlay teardown below.
    let orig = Originator {
        principal: Principal::TunnelClient(tunnel_client_id),
        tenant_id,
        owner_user_id,
        client_version,
        client_os,
        outbound_tx: outbound_tx.clone(),
        dialed_tid,
        conn_established_ms,
    };

    // Periodic revocation re-check task — same as T1 stub, but now
    // sends a typed `TunnelRevoked` `ServerMsg` instead of an
    // ad-hoc JSON frame.
    let revocation_handle = spawn_revocation_check(
        state.clone(),
        socket_tx.clone(),
        outbound_tx.clone(),
        tunnel_client_id,
        tenant_id,
    );

    // Main read loop.
    while let Some(msg) = socket_rx.next().await {
        let text = match msg {
            Ok(Message::Text(t)) => t,
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };

        let parsed: ClientMsg = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                warn!(%tunnel_client_id, %e, "tunnel-client sent malformed JSON; dropping");
                send_error(
                    &outbound_tx,
                    None,
                    "bad_request",
                    &format!("malformed JSON: {e}"),
                )
                .await;
                continue;
            }
        };

        // Overlay `rc:overlay.*` variants are brokered separately (this
        // tunnel-client is an overlay node). Consumed messages return
        // None; everything else falls through to the tunnel match below.
        let Some(parsed) = crate::overlay::relay_overlay_msg_from_node(
            &state,
            crate::overlay::NodeIdentity::TunnelClient(tunnel_client_id),
            parsed,
        )
        .await
        else {
            continue;
        };

        match parsed {
            ClientMsg::TunnelHello {
                role: _,
                version,
                supported_transports,
            } => {
                debug!(%tunnel_client_id, %version, ?supported_transports, "rc:tunnel.hello");
                // Stash the advertised transports; `TunnelOpen`
                // intersects them with the requested transport to pick
                // the data plane (quic-v1 when both name it, else the
                // webrtc-dc-v1 default).
                client_supported_transports = supported_transports;
            }

            ClientMsg::TunnelOpen {
                agent_id,
                transport,
                open_nonce,
                derp_pubkey,
                net_grant,
            } => {
                // The dedicated CLI is single-open, so `open_nonce` is
                // normally None; the server echoes back whatever it sent.
                // A grant here is refused: a session's flows ride only its
                // own device's WS (FR-90 P3-7-2a).
                session = handle_tunnel_open(
                    &state,
                    &orig,
                    agent_id,
                    transport,
                    open_nonce,
                    derp_pubkey,
                    net_grant,
                    &client_supported_transports,
                )
                .await;
            }

            ClientMsg::TcpForwardRequest {
                session_id,
                flow_id,
                dst_host,
                dst_port,
            } => {
                handle_forward_request(
                    ProtocolKind::Tcp,
                    &state,
                    &orig,
                    session.as_ref(),
                    session_id,
                    flow_id,
                    &dst_host,
                    dst_port,
                )
                .await;
            }

            ClientMsg::UdpForwardRequest {
                session_id,
                flow_id,
                dst_host,
                dst_port,
            } => {
                handle_forward_request(
                    ProtocolKind::Udp,
                    &state,
                    &orig,
                    session.as_ref(),
                    session_id,
                    flow_id,
                    &dst_host,
                    dst_port,
                )
                .await;
            }

            ClientMsg::TunnelTerminate { session_id, reason } => {
                info!(%tunnel_client_id, %session_id, ?reason, "rc:tunnel.terminate");
                // Relay the teardown to the agent so it tears down
                // its peer state too. Best-effort — agent may be
                // offline.
                if let Some(s) = session.as_ref()
                    && s.tunnel_session_id == session_id
                {
                    let _ = state.fleet.rc_hub.send_to_agent(
                        s.agent_id,
                        ServerMsg::TunnelTerminate {
                            session_id: s.tunnel_session_id,
                            reason,
                        },
                    );
                }
                if let Some(s) = session.take() {
                    state.tunnel_clients_by_session.remove(&s.tunnel_session_id);
                    unindex_session_target(
                        &state.tunnel_sessions_by_target_agent,
                        s.agent_id,
                        s.tunnel_session_id,
                    );
                    audit_peer_close(&state, &s, &orig).await;
                }
            }

            ClientMsg::TcpHalfClose {
                session_id,
                flow_id,
                direction,
            } => {
                // Tunnel-client → server → agent: relay the half-close
                // for the agent's audit + write-half teardown. The
                // data-plane FIN itself rides the in-band SCTP
                // sentinel; this WS message is audit-only.
                relay_half_close_to_agent(
                    &state,
                    session.as_ref(),
                    tunnel_client_id,
                    session_id,
                    flow_id,
                    direction,
                )
                .await;
            }

            ClientMsg::TcpClosed {
                session_id,
                flow_id,
                reason,
                bytes_in,
                bytes_out,
            } => {
                // Relay flow-close to agent + append audit row. The byte
                // counts come from the endpoint because the payload never
                // passes through here.
                relay_tcp_closed_to_agent(
                    &state,
                    &orig,
                    session.as_ref(),
                    session_id,
                    flow_id,
                    reason,
                    (bytes_in, bytes_out),
                )
                .await;
            }

            ClientMsg::UdpClosed {
                session_id,
                flow_id,
                reason,
            } => {
                // Relay UDP flow-close to agent + append audit row.
                relay_udp_closed_to_agent(
                    &state,
                    &orig,
                    session.as_ref(),
                    session_id,
                    flow_id,
                    reason,
                )
                .await;
            }

            ClientMsg::TunnelSdpOffer { session_id, sdp } => {
                // Relay SDP offer to the agent so it can build its
                // answerer-side TunnelPeer. Server-side route is
                // session-id-gated; cross-tenant + agent-online
                // checks already happened on TunnelOpen.
                relay_sdp_offer_to_agent(&state, session.as_ref(), session_id, sdp).await;
            }

            ClientMsg::TunnelIce {
                session_id,
                candidate,
            } => {
                relay_ice_to_agent(&state, session.as_ref(), session_id, candidate).await;
            }

            ClientMsg::TunnelQuicCandidate { session_id, addrs } => {
                // QUIC-over-TURN (Phase 3c): the client's relay
                // address(es). Relay to the agent so it can install a
                // TURN permission for the client BEFORE the handshake.
                relay_quic_candidate_to_agent(&state, session.as_ref(), session_id, addrs).await;
            }

            ClientMsg::TunnelSdpAnswer { .. } => {
                // Clients only emit offers, agents only emit answers.
                // A client SDP answer means the wire is being abused.
                debug!(%tunnel_client_id, "client emitted TunnelSdpAnswer — ignoring");
            }

            ClientMsg::TcpForwardAccept { .. }
            | ClientMsg::TcpForwardReject { .. }
            | ClientMsg::UdpForwardAccept { .. }
            | ClientMsg::UdpForwardReject { .. } => {
                // Client → server: clients never originate these
                // (server-side ACL + agent are the deciders). Tests
                // exercise the wire; just log so we notice if a
                // misbehaving client emits one.
                debug!(%tunnel_client_id, ?parsed, "client emitted server-only tunnel msg — ignoring");
            }

            // Non-tunnel rc:* — explicitly ignored on this WS role.
            other => {
                debug!(%tunnel_client_id, ?other, "non-tunnel rc:* on tunnel-client WS — ignored");
            }
        }
    }

    revocation_handle.abort();

    // Overlay teardown: drop this node from the registry + mark it
    // offline so peers' netmaps lose it. Best-effort; no-op if the
    // client never joined the overlay.
    state.overlay_nodes_by_id.remove(&tunnel_client_id);
    state
        .org_relay
        .unbind_live_conn(tunnel_client_id, &connection_id);
    crate::overlay::handle_overlay_leave(
        &state,
        crate::overlay::NodeIdentity::TunnelClient(tunnel_client_id),
    )
    .await;

    if let Some(s) = session {
        state.tunnel_clients_by_session.remove(&s.tunnel_session_id);
        unindex_session_target(
            &state.tunnel_sessions_by_target_agent,
            s.agent_id,
            s.tunnel_session_id,
        );
        // Best-effort: tell the agent the peer is gone so it tears
        // down its side.
        let _ = state.fleet.rc_hub.send_to_agent(
            s.agent_id,
            ServerMsg::TunnelTerminate {
                session_id: s.tunnel_session_id,
                reason: CloseReason::ClientShutdown,
            },
        );
        audit_peer_close(&state, &s, &orig).await;
    }
    // Drop our outbound_tx so the pump task can exit cleanly. Any
    // clones in tunnel_clients_by_session were just removed; any
    // clones the revocation task held are dropped when its handle
    // aborts. Defensive `pump.abort()` covers the edge case where
    // some other clone is still alive.
    drop(outbound_tx);
    pump.abort();
    business_observation.finish(&state.core, &connection_id).await;
    info!(%tunnel_client_id, "tunnel-client WS disconnected");
}

/// Per-connection state created on `TunnelOpen` and consumed by every
/// subsequent flow event for audit correlation.
#[derive(Debug, Clone)]
pub struct TunnelSession {
    pub tunnel_session_id: ObjectId,
    agent_id: ObjectId,
    agent_tenant_id: ObjectId,
    #[allow(dead_code)] // T2.6 will plumb this into the agent-WS relay
    transport: String,
    /// FR-90 P3-7-2a — the grant this tunnel was opened under: its flows
    /// are an agent SESSION's, decided for the session and held to the
    /// grant. `None` for a device's or a person's own tunnel.
    grant: Option<SessionGrant>,
}

impl TunnelSession {
    /// FR-90 P3-7-2a — whose flows these are, as the audit records them: the
    /// session's owner under a grant, else the originator's.
    fn flow_user(&self, orig: &Originator) -> ObjectId {
        self.grant
            .as_ref()
            .map_or(orig.owner_user_id, |g| g.owner_user_id)
    }

    /// FR-90 P3-7-2a — the session a row names, under a grant.
    fn grant_session_id(&self) -> Option<ObjectId> {
        self.grant.as_ref().map(|g| g.session_id)
    }

    /// FR-90 P3-7-2a — the grant a row names, under a grant.
    fn grant_id(&self) -> Option<String> {
        self.grant.as_ref().map(|g| g.grant_id.clone())
    }
}

/// FR-90 P3-7-2a — a grant the vault signed (P3-7-1b), bound to one tunnel at
/// its open. It holds only from the device it names, toward the exit it
/// names, until its end; the flows it carries are the session's.
#[derive(Debug, Clone)]
struct SessionGrant {
    session_id: ObjectId,
    /// The device the session runs on: the connection that carries its flows.
    device: ObjectId,
    /// The person the session acts for: its flows' `user_id`.
    owner_user_id: ObjectId,
    /// The grant's id, as the vault recorded its allow (`grant:<id>`).
    grant_id: String,
    /// A forward's one destination, its host canonical; `None` for SOCKS.
    dst: Option<(String, u16)>,
    /// Its end, in seconds since the epoch.
    exp: i64,
}

impl SessionGrant {
    /// The principal its flows are decided for.
    fn principal(&self) -> Principal {
        Principal::Session {
            session_id: self.session_id,
            agent_id: self.device,
        }
    }

    /// Whether one flow stays inside the grant: TCP only, before its end, and
    /// for a forward toward its one destination, in the spelling the vault
    /// decided it in (`canonical_net_host`). The reason it does not,
    /// otherwise. Checked before any policy is read.
    fn admits(
        &self,
        proto: ProtocolKind,
        dst_host: &str,
        dst_port: u16,
        now_s: i64,
    ) -> Result<(), &'static str> {
        if proto != ProtocolKind::Tcp {
            return Err("a session's grant carries TCP only");
        }
        if now_s >= self.exp {
            return Err("the session's grant has ended");
        }
        if let Some((host, port)) = &self.dst
            && (canonical_net_host(dst_host).as_deref() != Some(host.as_str()) || dst_port != *port)
        {
            return Err("outside the session's grant");
        }
        Ok(())
    }
}

/// FR-90 P3-7-2a — verify a grant presented at `rc:tunnel.open` and bind it to
/// the tunnel. `verify_net_grant` checks its signature, its audience, its
/// kind, its destination and its life; this checks it names THIS
/// connection's device as its origin, this open's target as its exit, and
/// this originator's organization. The reason it does not hold, otherwise.
///
/// ⚠️ Only from an agent's own WS: a session's flows ride its device's
/// connection, never a person's tunnel client.
fn bind_net_grant(
    auth: &AuthService,
    orig: &Originator,
    exit: ObjectId,
    token: &str,
) -> Result<SessionGrant, &'static str> {
    let Principal::Agent(origin) = orig.principal else {
        return Err("a session's grant rides only its own device's connection");
    };
    let claims = auth
        .verify_net_grant(token)
        .map_err(|_| "not a grant this server signed, or it has ended")?;
    let id =
        |hex: &str| ObjectId::parse_str(hex).map_err(|_| "a grant naming an id that is not one");
    if id(&claims.tenant_id)? != orig.tenant_id {
        return Err("a grant for another organization");
    }
    if id(&claims.origin_agent_id)? != origin {
        return Err("a grant for another device");
    }
    if id(&claims.exit_agent_id)? != exit {
        return Err("a grant for another exit");
    }
    let dst = match NetKind::from_wire(&claims.net) {
        Some(NetKind::Socks) => None,
        Some(NetKind::Forward) => Some((claims.dst_host.clone(), claims.dst_port)),
        None => return Err("a grant of a kind this build cannot name"),
    };
    Ok(SessionGrant {
        session_id: id(&claims.sub)?,
        device: origin,
        owner_user_id: id(&claims.owner_user_id)?,
        grant_id: claims.jti,
        dst,
        exp: claims.exp,
    })
}

/// Identity + reply channel of whoever originated a tunnel-CLIENT session
/// on this server. Two principals drive the identical handlers:
///   * `Principal::TunnelClient` — a dedicated `roomler` WS
///     (`handle_tunnel_client_socket`).
///   * `Principal::Agent` — an enrolled agent driving the tunnel-client
///     role over its own agent WS (P3b-2,
///     `relay_tunnel_client_msg_from_agent`).
///
/// Bundling the per-originator values here lets ONE subject-agnostic set
/// of handlers serve both WS roles instead of duplicating the open /
/// forward / relay / audit logic per role.
#[derive(Clone)]
pub struct Originator {
    pub principal: Principal,
    /// The originator's own tenant. For an agent origin this is the
    /// agent's tenant — the value the cross-tenant gate compares against
    /// the TARGET agent's tenant.
    pub tenant_id: ObjectId,
    pub owner_user_id: ObjectId,
    pub client_version: String,
    pub client_os: OsKind,
    /// The originator's outbound `ServerMsg` channel. For a tunnel-client
    /// WS this is its per-connection `outbound_tx`; for an agent it is a
    /// clone of the agent's Hub-owned `registered_tx`, so a target's
    /// answers relayed via `tunnel_clients_by_session[session_id]` reach
    /// the agent's socket through its EXISTING pump — no target-side change.
    pub outbound_tx: mpsc::Sender<ServerMsg>,
    /// PR-1 rehome — the affinity key this conn DIALED with (`None` =
    /// key-less legacy dial that hashed on client IP) and when it
    /// established. Direction inputs for the cross-pod open-reject: only
    /// a correctly-keyed, provably-newer conn justifies nudging the
    /// target agent's WS.
    pub dialed_tid: Option<String>,
    pub conn_established_ms: i64,
}

impl Originator {
    /// The originating tunnel-client row id, or `None` for an agent origin.
    fn tunnel_client_id(&self) -> Option<ObjectId> {
        match self.principal {
            Principal::TunnelClient(id) => Some(id),
            Principal::Agent(_) | Principal::Session { .. } => None,
        }
    }
    /// The originating agent id, or `None` for a dedicated-client origin.
    /// (An originator is a connection, so never a session; its arm names
    /// the device the session runs on.)
    fn origin_agent_id(&self) -> Option<ObjectId> {
        match self.principal {
            Principal::Agent(id) | Principal::Session { agent_id: id, .. } => Some(id),
            Principal::TunnelClient(_) => None,
        }
    }
    /// Stable id for log lines, regardless of principal kind.
    fn log_id(&self) -> ObjectId {
        match self.principal {
            Principal::TunnelClient(id)
            | Principal::Agent(id)
            | Principal::Session { agent_id: id, .. } => id,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tunnel_open(
    state: &NetworkState,
    orig: &Originator,
    agent_id: ObjectId,
    transport: String,
    open_nonce: Option<String>,
    // R4 - the client's DERP identity from TunnelOpen (quic-derp-v1 only).
    derp_pubkey: Option<String>,
    // FR-90 P3-7-2a - an agent session's grant, from the vault.
    net_grant: Option<String>,
    client_supported: &[String],
) -> Option<TunnelSession> {
    // 1. Fetch the agent (any tenant — we need the row to enforce
    // the cross-tenant gate ourselves). `find_in_tenant` is wrong
    // here because it scopes by tenant — we need the agent's actual
    // tenant_id to compare. Use a direct lookup via the base DAO.
    let agent = match state.fleet.agents.base.find_by_id(agent_id).await {
        Ok(a) => a,
        Err(_) => {
            send_msg(
                &orig.outbound_tx,
                ServerMsg::Error {
                    session_id: None,
                    code: "agent_not_found".into(),
                    message: format!("agent {agent_id} does not exist"),
                    open_nonce: open_nonce.clone(),
                },
            )
            .await;
            return None;
        }
    };

    // 2. Cross-tenant gate (Sev0 — see plan §"Multi-tenancy gotcha").
    // The originator's tenant is the client tenant; for an agent origin
    // it is the agent's own tenant.
    if agent.tenant_id != orig.tenant_id {
        warn!(
            origin = %orig.log_id(), %agent_id, client_tenant_id = %orig.tenant_id,
            agent_tenant_id = %agent.tenant_id,
            "tunnel originator tried to open a peer to a cross-tenant agent"
        );
        send_msg(
            &orig.outbound_tx,
            ServerMsg::Error {
                session_id: None,
                code: "cross_tenant".into(),
                message: "agent belongs to a different tenant".into(),
                open_nonce: open_nonce.clone(),
            },
        )
        .await;
        return None;
    }

    // 3. Refuse if the TARGET agent is soft-deleted or quarantined —
    // early signal beats waiting for the relay step to fail.
    if agent.deleted_at.is_some() || matches!(agent.status, AgentStatus::Quarantined) {
        send_msg(
            &orig.outbound_tx,
            ServerMsg::Error {
                session_id: None,
                code: "agent_unavailable".into(),
                message: "agent is quarantined or deleted".into(),
                open_nonce: open_nonce.clone(),
            },
        )
        .await;
        return None;
    }

    // 3a½ (C-3). REHOME gate: the target agent isn't in THIS pod's hub but
    // a FOREIGN pod holds a fresh presence record — a cross-pod split, not
    // an offline agent. Without this, the open would "succeed" and every
    // forward would then bounce off `agent unreachable` FOREVER (the client
    // keeps its parked WS and never re-dials). Reject the open with the
    // rehome code — the CLI driver bails on open-errors, its reconnect
    // loop dials a FRESH WS, and the LB re-hashes it onto the owner pod —
    // and nudge the owner to cycle the agent if idle so both ends
    // converge. Plain hub-miss with no foreign record keeps today's
    // behaviour (the P7 terminate machinery owns real agent flaps).
    if !state.fleet.rc_hub.is_agent_online(agent_id)
        && let Some(redis) = &state.redis_pubsub
        && let Ok(Ok(Some(owner))) = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            redis.agent_presence_foreign(&agent_id.to_hex()),
        )
        .await
    {
        let record = roomler_core::cluster::directory::OwnerRecord::parse(&owner);
        let owner_pod = record
            .as_ref()
            .map(|r| r.pod_id.clone())
            .unwrap_or_default();
        let agent_since_ms = record.map(|r| r.since_ms).unwrap_or(0);
        warn!(
            origin = %orig.log_id(), %agent_id, %owner_pod,
            "tunnel open rejected: agent homed on another pod (rehome)"
        );
        // PR-1 direction rule (twin of the rc path): only a correctly-
        // keyed conn that is provably NEWER than the target agent's
        // registration justifies cycling that agent's WS; a key-less /
        // wrong-keyed / older-or-ambiguous originator is itself the
        // mis-placed party and its own fresh redial converges it.
        // `agent` (the target's row) is already fetched above.
        match roomler_ai_mod_fleet::nudge::rehome_direction(
            orig.dialed_tid.as_deref(),
            &agent.tenant_id.to_hex(),
            orig.conn_established_ms,
            agent_since_ms,
            state.settings.rc.rehome_direction_guard_ms,
        ) {
            roomler_ai_mod_fleet::nudge::RehomeDirection::ControllerMove { reason } => {
                roomler_core::cluster::metrics::bump(
                    &roomler_core::cluster::metrics::RC_REHOME_CONTROLLER_TOTAL,
                );
                info!(
                    origin = %orig.log_id(), %agent_id, %owner_pod, reason,
                    "cross-pod tunnel miss: originator re-dials (nudge suppressed)"
                );
            }
            roomler_ai_mod_fleet::nudge::RehomeDirection::NudgeAgent => {
                roomler_ai_mod_fleet::nudge::spawn_agent_nudge(
                    &state.fleet,
                    owner_pod.clone(),
                    agent_id.to_hex(),
                );
            }
        }
        roomler_core::cluster::metrics::bump(&roomler_core::cluster::metrics::TUNNEL_REHOME_TOTAL);
        // Pod identity stays in server logs; the wire carries only the
        // actionable fact + the open_nonce so the CLI fails the exact
        // pending flow and its reconnect loop dials fresh.
        send_msg(
            &orig.outbound_tx,
            ServerMsg::Error {
                session_id: None,
                code: "agent_on_other_pod".into(),
                message: "agent is homed on another pod; re-dial and retry".into(),
                open_nonce: open_nonce.clone(),
            },
        )
        .await;
        return None;
    }

    // 3b. Defence-in-depth for an AGENT origin (P3b-2 Risk 7): refuse if
    // the ORIGINATING agent's row is soft-deleted / quarantined. Its WS
    // auth already gated it at connect and the Hub closes a deleted
    // agent's socket, but re-checking at the origination entry point stops
    // a mid-session quarantine from spawning a fresh tunnel.
    if let Principal::Agent(origin_id) = orig.principal {
        let origin_ok = matches!(
            state.fleet.agents.base.find_by_id(origin_id).await,
            Ok(a) if a.deleted_at.is_none() && !matches!(a.status, AgentStatus::Quarantined)
        );
        if !origin_ok {
            send_msg(
                &orig.outbound_tx,
                ServerMsg::Error {
                    session_id: None,
                    code: "origin_unavailable".into(),
                    message: "originating agent is quarantined or deleted".into(),
                    open_nonce: open_nonce.clone(),
                },
            )
            .await;
            return None;
        }
    }

    // 3c. FR-90 P3-7-2a — an agent SESSION's grant. Bound here, or the open
    // is refused: a grant that does not hold must never fall back to the
    // device's own principal, which would hand the session whatever its
    // device may reach.
    let grant = match net_grant.as_deref() {
        None => None,
        Some(token) => match bind_net_grant(&state.core.auth, orig, agent_id, token) {
            Ok(g) => {
                info!(
                    origin = %orig.log_id(), %agent_id, session = %g.session_id,
                    grant = %g.grant_id, forward = g.dst.is_some(),
                    "tunnel open: bound to an agent session's grant"
                );
                Some(g)
            }
            Err(why) => {
                warn!(
                    origin = %orig.log_id(), %agent_id, why,
                    "tunnel open refused: its session grant does not hold"
                );
                send_msg(
                    &orig.outbound_tx,
                    ServerMsg::Error {
                        session_id: None,
                        code: NET_GRANT_REFUSED.into(),
                        message: why.into(),
                        open_nonce: open_nonce.clone(),
                    },
                )
                .await;
                return None;
            }
        },
    };

    // Transport negotiation (Phase 1c + Phase 4 agent-version gate).
    // Negotiate quic-v1 only when the client requested it, advertised it
    // in rc:tunnel.hello, AND the target agent's reported version
    // actually speaks the QUIC tunnel setup. Otherwise fall back to the
    // proven webrtc-dc-v1.
    //
    // The agent-version gate is what makes `--transport auto` safe as
    // the client default: a pre-rc.104 agent silently ignores the
    // TunnelQuicSetup below and never replies, so without this gate the
    // client would burn its full QUIC_READY_TIMEOUT (30 s) before
    // falling back. `agent_version` is refreshed on every agent WS
    // connect (update_hello), so it's current for any *online* agent —
    // and only an online agent can be tunneled to (send_to_agent fails
    // otherwise).
    let agent_speaks_quic = tunnel_core::transport::agent_supports_quic(&agent.agent_version);
    // R4 - quic-derp-v1: negotiated only when the client REQUESTED it,
    // advertised it, sent its DERP identity, and the agent's version can
    // serve it (a pre-R4 agent would ignore the setup's transport field,
    // stand up a TURN relay, and the client would burn its 30s ready-wait).
    // A derp request that cannot be honored degrades to plain quic-v1 when
    // possible (better than webrtc through a captured path), else webrtc.
    let agent_speaks_derp =
        tunnel_core::transport::agent_supports_derp_tunnel(&agent.agent_version);
    let derp_requested = transport == tunnel_core::transport::TRANSPORT_QUIC_DERP_V1;
    let negotiated_transport = if derp_requested {
        if client_supported
            .iter()
            .any(|t| t == tunnel_core::transport::TRANSPORT_QUIC_DERP_V1)
            && agent_speaks_derp
            && derp_pubkey.is_some()
        {
            tunnel_core::transport::TRANSPORT_QUIC_DERP_V1.to_string()
        } else if client_supported.iter().any(|t| t == TRANSPORT_QUIC_V1) && agent_speaks_quic {
            debug!(
                %agent_id, agent_version = %agent.agent_version, agent_speaks_derp,
                had_pubkey = derp_pubkey.is_some(),
                "client requested quic-derp-v1 -> negotiating quic-v1 (derp leg unavailable)"
            );
            TRANSPORT_QUIC_V1.to_string()
        } else {
            TRANSPORT_WEBRTC_DC_V1.to_string()
        }
    } else if transport == TRANSPORT_QUIC_V1 {
        if client_supported.iter().any(|t| t == TRANSPORT_QUIC_V1) && agent_speaks_quic {
            TRANSPORT_QUIC_V1.to_string()
        } else {
            debug!(
                %agent_id, agent_version = %agent.agent_version, agent_speaks_quic,
                "client requested quic-v1 → negotiating webrtc-dc-v1 (agent too old, or client didn't advertise quic)"
            );
            TRANSPORT_WEBRTC_DC_V1.to_string()
        }
    } else {
        transport.clone()
    };
    // Mint a per-session bearer token for quic-v1; the agent validates
    // the direct P2P link by string-equality (see
    // tunnel_core::transport::quic::server_authenticate). `None` for
    // webrtc-dc-v1 keeps those sessions byte-identical on the wire.
    let quic_auth_token = if negotiated_transport == TRANSPORT_QUIC_V1
        || negotiated_transport == tunnel_core::transport::TRANSPORT_QUIC_DERP_V1
    {
        Some(mint_quic_token())
    } else {
        None
    };

    // 4. Create the session id + register the outbound channel so the
    // agent WS handler can relay TcpForwardAccept/Reject/HalfClose/Closed
    // (+ TunnelQuicReady) back to the originator. For an agent origin this
    // channel IS the agent's own socket, so the existing target->client
    // relay path serves it unchanged. The caller stores the returned
    // session (in its `Option` or its per-agent session map).
    let tunnel_session_id = ObjectId::new();
    let new_session = TunnelSession {
        tunnel_session_id,
        agent_id,
        agent_tenant_id: agent.tenant_id,
        transport: negotiated_transport.clone(),
        grant,
    };
    state
        .tunnel_clients_by_session
        .insert(tunnel_session_id, orig.outbound_tx.clone());
    // C-3 — ownership record: which pod owns this session's WS legs
    // (observability + the C-6 metrics; refreshed by the directory
    // heartbeat while the map entry above lives, TTL-reaped after).
    if let Some(dir) = &state.cluster_directory {
        let token = dir.owner_token(&tunnel_session_id.to_hex());
        if let Err(e) = dir
            .claim_lww(
                &roomler_core::cluster::directory::tunnel_key(&tunnel_session_id.to_hex()),
                &token,
            )
            .await
        {
            debug!(%tunnel_session_id, %e, "tunnel ownership claim failed");
        } else {
            state
                .tunnel_presence_tokens
                .insert(tunnel_session_id, token);
        }
    }
    // P7 flap resilience: index the session by its TARGET agent so
    // `terminate_sessions_targeting_agent` can kill it the moment that
    // agent's WS drops (the agent's tunnel peers die with its socket).
    state
        .tunnel_sessions_by_target_agent
        .entry(agent_id)
        .or_default()
        .insert(tunnel_session_id);

    // 5. Audit the open. RelayMode is "Direct" until ICE finishes —
    // T2.7 updates this after candidate selection. Under a grant the row
    // names the session, its grant, and the session's owner (P3-7-2a).
    let grant_id = new_session.grant_id();
    let _ = state
        .tunnel_audit
        .append(&TunnelAuditEvent {
            id: None,
            tenant_id: orig.tenant_id,
            tunnel_session_id,
            tunnel_client_id: orig.tunnel_client_id(),
            origin_agent_id: orig.origin_agent_id(),
            agent_id,
            user_id: new_session.flow_user(orig),
            at: DateTime::now(),
            kind: TunnelAuditKind::PeerOpen,
            flow_id: None,
            dst_host: None,
            dst_port: None,
            bytes_in: 0,
            bytes_out: 0,
            message_count: 0,
            duration_ms: None,
            relay: RelayMode::Direct,
            client_src_ip: None, // T2.6 — extract X-Forwarded-For at upgrade
            agent_src_port: None,
            client_version: orig.client_version.clone(),
            client_os: orig.client_os,
            reason: None,
            session_id: new_session.grant_session_id(),
            grant_id: grant_id.clone(),
        })
        .await;

    // QUIC-over-TURN (Phase 3c): mint short-lived coturn creds for THIS
    // session and hand the SAME set to both peers so each can allocate
    // its own TURN relay. Empty when no TURN `shared_secret` is
    // configured (dev / direct-only) — the QUIC path then stays on
    // host/srflx candidates. `user_id` for the HMAC is the session id so
    // both peers derive identical, session-scoped creds.
    // FR-115 P4b — charged to the tunnel's org, so coturn's statistics name it.
    let quic_ice_servers = roomler_ai_remote_control::turn_creds::ice_servers_for(
        &roomler_ai_remote_control::turn_creds::charged(
            &tunnel_session_id.to_hex(),
            &orig.tenant_id.to_hex(),
        ),
        // Region-keyed map; `None` = default region until the agent's
        // relay_home is threaded through (probe reports, PR3).
        state.turn_map.cfg_for(None),
    );

    // For quic-v1, tell the agent to stand up its endpoint + authorize
    // this token NOW. The client is already registered in
    // `tunnel_clients_by_session` (step 4), so the agent's
    // `TunnelQuicReady` can race back and be relayed to the client
    // while it's still processing the `TunnelOpened` below.
    if let Some(token) = quic_auth_token.clone()
        && let Err(e) = state.fleet.rc_hub.send_to_agent(
            agent_id,
            ServerMsg::TunnelQuicSetup {
                session_id: tunnel_session_id,
                quic_auth_token: token,
                ice_servers: quic_ice_servers.clone(),
                transport: (negotiated_transport == tunnel_core::transport::TRANSPORT_QUIC_DERP_V1)
                    .then(|| negotiated_transport.clone()),
                client_derp_pubkey: if negotiated_transport
                    == tunnel_core::transport::TRANSPORT_QUIC_DERP_V1
                {
                    derp_pubkey.clone()
                } else {
                    None
                },
            },
        )
    {
        warn!(%agent_id, %e, "TunnelQuicSetup relay failed; client will fall back to webrtc-dc-v1");
    }

    // 6. Reply with TunnelOpened carrying the NEGOTIATED transport +
    // (for quic-v1) the bearer token. ICE candidates + actual SDP come
    // in T2.7 for the webrtc path; quic carries its own handshake. The
    // SCTP rwnd value mirrors the vendored webrtc patch's target so the
    // CLI's `diagnose` subcommand can verify the patch took effect.
    send_msg(
        &orig.outbound_tx,
        ServerMsg::TunnelOpened {
            session_id: tunnel_session_id,
            transport: negotiated_transport,
            dc_pool_size: 8,
            sctp_rwnd_bytes: 8 * 1024 * 1024,
            ice_servers: quic_ice_servers,
            quic_auth_token,
            open_nonce,
            // P3-7-2a — the device's proof the grant was bound: a device
            // that sent one and finds no echo carries no session flow here.
            net_grant_id: grant_id,
        },
    )
    .await;

    Some(new_session)
}

/// Mint an opaque per-session QUIC bearer token. The server hands the
/// SAME value to the client (`TunnelOpened.quic_auth_token`) and the
/// agent (`TunnelQuicSetup.quic_auth_token`); the agent authenticates
/// the direct P2P QUIC connection by string-equality. It needs no
/// shared secret or verifiable signature because both endpoints receive
/// it over their already-authenticated WS connections — it only needs
/// to be unguessable. Two v4 UUIDs = 244 bits of randomness.
fn mint_quic_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Build the transport-appropriate reject ServerMsg. TCP and UDP
/// forwards share the identical gate logic; only the wire discriminator
/// differs.
fn forward_reject_msg(
    proto: ProtocolKind,
    session_id: ObjectId,
    flow_id: u32,
    kind: RejectKind,
    reason: String,
) -> ServerMsg {
    match proto {
        ProtocolKind::Udp => ServerMsg::UdpForwardReject {
            session_id,
            flow_id,
            kind,
            reason,
        },
        _ => ServerMsg::TcpForwardReject {
            session_id,
            flow_id,
            kind,
            reason,
        },
    }
}

/// Build the transport-appropriate forward ServerMsg (server → agent).
fn forward_forward_msg(
    proto: ProtocolKind,
    session_id: ObjectId,
    flow_id: u32,
    dst_host: String,
    dst_port: u16,
    owner_user_id: ObjectId,
) -> ServerMsg {
    match proto {
        ProtocolKind::Udp => ServerMsg::UdpForwardForward {
            session_id,
            flow_id,
            dst_host,
            dst_port,
            owner_user_id,
        },
        _ => ServerMsg::TcpForwardForward {
            session_id,
            flow_id,
            dst_host,
            dst_port,
            owner_user_id,
        },
    }
}

/// Server-side forward gate + relay, shared by TCP CONNECT
/// (`proto = Tcp`) and UDP ASSOCIATE (`proto = Udp`) forwards. The ACL
/// eval, cross-tenant gate, agent-liveness re-check, and audit trail are
/// identical; `proto` selects the wire discriminator + the policy
/// protocol axis.
#[allow(clippy::too_many_arguments)]
async fn handle_forward_request(
    proto: ProtocolKind,
    state: &NetworkState,
    orig: &Originator,
    session: Option<&TunnelSession>,
    request_session_id: ObjectId,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
) {
    let Some(s) = session else {
        // No prior TunnelOpen — client is using the wire wrong.
        send_msg(
            &orig.outbound_tx,
            forward_reject_msg(
                proto,
                request_session_id,
                flow_id,
                RejectKind::AgentError,
                REJECT_REASON_NO_SESSION.into(),
            ),
        )
        .await;
        return;
    };
    if s.tunnel_session_id != request_session_id {
        send_msg(
            &orig.outbound_tx,
            forward_reject_msg(
                proto,
                request_session_id,
                flow_id,
                RejectKind::AgentError,
                REJECT_REASON_SESSION_MISMATCH.into(),
            ),
        )
        .await;
        return;
    }

    // FR-90 P3-7-2a — a session's flow is held to its grant before any
    // policy is read: TCP only, before the grant's end, and a forward toward
    // its one destination.
    if let Some(g) = &s.grant {
        let now_s = DateTime::now().timestamp_millis().div_euclid(1000);
        if let Err(why) = g.admits(proto, dst_host, dst_port, now_s) {
            info!(origin = %orig.log_id(), session = %g.session_id, %flow_id, %dst_host, %dst_port, ?proto, why, "session flow rejected by its grant");
            audit_tcp_reject(
                state,
                s,
                orig,
                flow_id,
                dst_host,
                dst_port,
                RejectKind::AclDenied,
                why,
            )
            .await;
            send_msg(
                &orig.outbound_tx,
                forward_reject_msg(
                    proto,
                    request_session_id,
                    flow_id,
                    RejectKind::AclDenied,
                    why.into(),
                ),
            )
            .await;
            return;
        }
    }

    // Re-fetch the agent row each time so a quarantine that lands
    // mid-session bites the next forward.
    let agent = match state.fleet.agents.base.find_by_id(s.agent_id).await {
        Ok(a) => a,
        Err(_) => {
            audit_tcp_reject(
                state,
                s,
                orig,
                flow_id,
                dst_host,
                dst_port,
                RejectKind::AgentError,
                "agent row vanished",
            )
            .await;
            send_msg(
                &orig.outbound_tx,
                forward_reject_msg(
                    proto,
                    request_session_id,
                    flow_id,
                    RejectKind::AgentError,
                    "agent row vanished".into(),
                ),
            )
            .await;
            return;
        }
    };

    // Active policies for the agent's tenant. Server-side ACL is
    // the auth boundary; the agent runs its own minimal allowlist
    // as defence-in-depth (T2.6).
    let policies = match state
        .tunnel_policies
        .list_active_for_tenant(s.agent_tenant_id)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            warn!(origin = %orig.log_id(), %e, "policy fetch failed; defaulting to deny");
            Vec::new()
        }
    };

    let subject = ResolvedSubject {
        // FR-90 P3-7-2a — under a grant, the session's owner.
        user_id: s.flow_user(orig),
        // T2.6 will resolve role_ids via the existing tenant
        // membership lookup. For T2.5 we use an empty list — only
        // UserId / TunnelClientId / AgentId / AllUsers policy subjects
        // match.
        role_ids: Vec::new(),
        // Subject-agnostic (P3b-2): a tunnel-client WS carries
        // `Principal::TunnelClient`, an agent driving the client role over
        // its own WS carries `Principal::Agent`. The ACL evaluator
        // discriminates the id-specific subjects on the principal kind.
        // FR-90 P3-7-2a — a tunnel opened under a session's grant carries
        // `Principal::Session`, which no subject matches before decision 20.
        principal: s
            .grant
            .as_ref()
            .map_or(orig.principal, SessionGrant::principal),
    };

    let result = check_forward_request(
        orig.tenant_id,
        &agent,
        &policies,
        &subject,
        dst_host,
        dst_port,
        proto,
    );

    match result {
        GateResult::Allow { policy_id, .. } => {
            debug!(origin = %orig.log_id(), %flow_id, %dst_host, %dst_port, ?proto, %policy_id, "forward allowed by policy; relaying to agent");
            // T2.10c: relay to the agent's WS. The agent dials dst,
            // then replies with `ClientMsg::TcpForwardAccept` /
            // `UdpForwardAccept` (or Reject) which the agent WS handler
            // routes back to us via `tunnel_clients_by_session`.
            let relay = state.fleet.rc_hub.send_to_agent(
                s.agent_id,
                forward_forward_msg(
                    proto,
                    request_session_id,
                    flow_id,
                    dst_host.to_string(),
                    dst_port,
                    // Under a grant, the session's owner (P3-7-2a).
                    s.flow_user(orig),
                ),
            );
            match relay {
                Ok(()) => {
                    // Server side accepted-relayed; the actual
                    // accept (or agent-side reject) lands later
                    // via the agent's WS.
                    audit_tcp_accept(state, s, orig, flow_id, dst_host, dst_port).await;
                }
                Err(e) => {
                    // Agent not online or its channel is wedged.
                    warn!(origin = %orig.log_id(), %flow_id, agent = %s.agent_id, %e, "agent relay failed");
                    roomler_ai_mod_fleet::nudge::note_agent_offline_evidence(
                        state,
                        s.agent_id.to_hex(),
                        "tunnel_forward",
                    );
                    audit_tcp_reject(
                        state,
                        s,
                        orig,
                        flow_id,
                        dst_host,
                        dst_port,
                        RejectKind::AgentError,
                        &format!("agent unreachable: {e}"),
                    )
                    .await;
                    send_msg(
                        &orig.outbound_tx,
                        forward_reject_msg(
                            proto,
                            request_session_id,
                            flow_id,
                            RejectKind::AgentError,
                            format!("agent unreachable: {e}"),
                        ),
                    )
                    .await;
                }
            }
        }
        GateResult::Reject { kind, reason } => {
            info!(origin = %orig.log_id(), %flow_id, %dst_host, %dst_port, ?proto, ?kind, %reason, "forward rejected");
            audit_tcp_reject(state, s, orig, flow_id, dst_host, dst_port, kind, &reason).await;
            send_msg(
                &orig.outbound_tx,
                forward_reject_msg(proto, request_session_id, flow_id, kind, reason),
            )
            .await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit helpers — every interesting decision appends one row.
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn audit_tcp_accept(
    state: &NetworkState,
    session: &TunnelSession,
    orig: &Originator,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
) {
    let _ = state
        .tunnel_audit
        .append(&TunnelAuditEvent {
            id: None,
            tenant_id: session.agent_tenant_id,
            tunnel_session_id: session.tunnel_session_id,
            tunnel_client_id: orig.tunnel_client_id(),
            origin_agent_id: orig.origin_agent_id(),
            agent_id: session.agent_id,
            user_id: session.flow_user(orig),
            at: DateTime::now(),
            kind: TunnelAuditKind::TcpAccept,
            flow_id: Some(flow_id),
            dst_host: Some(dst_host.to_string()),
            dst_port: Some(dst_port),
            bytes_in: 0,
            bytes_out: 0,
            message_count: 0,
            duration_ms: None,
            relay: RelayMode::Direct,
            client_src_ip: None,
            agent_src_port: None,
            client_version: orig.client_version.clone(),
            client_os: orig.client_os,
            reason: None,
            session_id: session.grant_session_id(),
            grant_id: session.grant_id(),
        })
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn audit_tcp_reject(
    state: &NetworkState,
    session: &TunnelSession,
    orig: &Originator,
    flow_id: u32,
    dst_host: &str,
    dst_port: u16,
    kind: RejectKind,
    reason: &str,
) {
    let _ = state
        .tunnel_audit
        .append(&TunnelAuditEvent {
            id: None,
            tenant_id: session.agent_tenant_id,
            tunnel_session_id: session.tunnel_session_id,
            tunnel_client_id: orig.tunnel_client_id(),
            origin_agent_id: orig.origin_agent_id(),
            agent_id: session.agent_id,
            user_id: session.flow_user(orig),
            at: DateTime::now(),
            kind: TunnelAuditKind::TcpReject,
            flow_id: Some(flow_id),
            dst_host: Some(dst_host.to_string()),
            dst_port: Some(dst_port),
            bytes_in: 0,
            bytes_out: 0,
            message_count: 0,
            duration_ms: None,
            relay: RelayMode::Direct,
            client_src_ip: None,
            agent_src_port: None,
            client_version: orig.client_version.clone(),
            client_os: orig.client_os,
            reason: Some(format!("{kind:?}: {reason}")),
            session_id: session.grant_session_id(),
            grant_id: session.grant_id(),
        })
        .await;
}

async fn audit_peer_close(state: &NetworkState, session: &TunnelSession, orig: &Originator) {
    let _ = state
        .tunnel_audit
        .append(&TunnelAuditEvent {
            id: None,
            tenant_id: session.agent_tenant_id,
            tunnel_session_id: session.tunnel_session_id,
            tunnel_client_id: orig.tunnel_client_id(),
            origin_agent_id: orig.origin_agent_id(),
            agent_id: session.agent_id,
            user_id: session.flow_user(orig),
            at: DateTime::now(),
            kind: TunnelAuditKind::PeerClose,
            flow_id: None,
            dst_host: None,
            dst_port: None,
            bytes_in: 0,
            bytes_out: 0,
            message_count: 0,
            duration_ms: None,
            relay: RelayMode::Direct,
            client_src_ip: None,
            agent_src_port: None,
            client_version: orig.client_version.clone(),
            client_os: orig.client_os,
            reason: None,
            session_id: session.grant_session_id(),
            grant_id: session.grant_id(),
        })
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Push `msg` onto the per-connection outbound channel. The pump task
/// serialises + writes to the socket. A closed channel means the
/// socket has gone away or the pump exited — log + drop.
async fn send_msg(outbound: &mpsc::Sender<ServerMsg>, msg: ServerMsg) {
    if let Err(e) = outbound.send(msg).await {
        debug!(%e, "outbound channel closed; dropping ServerMsg");
    }
}

async fn send_error(
    outbound: &mpsc::Sender<ServerMsg>,
    session_id: Option<ObjectId>,
    code: &str,
    message: &str,
) {
    send_msg(
        outbound,
        ServerMsg::Error {
            session_id,
            code: code.into(),
            message: message.into(),
            open_nonce: None,
        },
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Client → agent relays for `TcpHalfClose` / `TcpClosed`
// ─────────────────────────────────────────────────────────────────────────────

/// Relay a `ClientMsg::TcpHalfClose` from the tunnel-client to the
/// connected agent. Audit-only on the data plane (the in-band SCTP
/// sentinel does the actual mailbox close on the peer); this message
/// gives the agent's audit path a half-close event to record.
async fn relay_half_close_to_agent(
    state: &NetworkState,
    session: Option<&TunnelSession>,
    tunnel_client_id: ObjectId,
    request_session_id: ObjectId,
    flow_id: u32,
    direction: roomler_ai_remote_control::signaling::Direction,
) {
    let Some(s) = session else {
        debug!(%tunnel_client_id, %flow_id, "half-close on dead session — ignoring");
        return;
    };
    if s.tunnel_session_id != request_session_id {
        debug!(%tunnel_client_id, %flow_id, "half-close with mismatched session_id — ignoring");
        return;
    }
    if let Err(e) = state.fleet.rc_hub.send_to_agent(
        s.agent_id,
        ServerMsg::TcpHalfClose {
            session_id: request_session_id,
            flow_id,
            direction,
        },
    ) {
        debug!(%tunnel_client_id, %flow_id, %e, "half-close relay to agent failed");
    }
}

/// Relay a `ClientMsg::TcpClosed` from the tunnel-client to the
/// agent and append an audit row. The flow is fully closed at this
/// point; `tunnel_audit` records the close reason so admins can
/// reconstruct the lifecycle.
async fn relay_tcp_closed_to_agent(
    state: &NetworkState,
    orig: &Originator,
    session: Option<&TunnelSession>,
    request_session_id: ObjectId,
    flow_id: u32,
    reason: CloseReason,
    // `(bytes_in, bytes_out)` as the reporting endpoint counted them.
    bytes: (u64, u64),
) {
    let Some(s) = session else {
        return;
    };
    if s.tunnel_session_id != request_session_id {
        return;
    }
    if let Err(e) = state.fleet.rc_hub.send_to_agent(
        s.agent_id,
        ServerMsg::TcpClosed {
            session_id: request_session_id,
            flow_id,
            reason,
        },
    ) {
        debug!(origin = %orig.log_id(), %flow_id, %e, "tcp-closed relay to agent failed");
    }
    audit_tcp_close(state, s, orig, flow_id, reason, bytes).await;
}

/// UDP analogue of [`relay_tcp_closed_to_agent`]: relay a UDP-flow close
/// to the agent + append an audit row. Reuses [`audit_tcp_close`] — the
/// close accounting is L4-agnostic (flow_id + reason).
async fn relay_udp_closed_to_agent(
    state: &NetworkState,
    orig: &Originator,
    session: Option<&TunnelSession>,
    request_session_id: ObjectId,
    flow_id: u32,
    reason: CloseReason,
) {
    let Some(s) = session else {
        return;
    };
    if s.tunnel_session_id != request_session_id {
        return;
    }
    if let Err(e) = state.fleet.rc_hub.send_to_agent(
        s.agent_id,
        ServerMsg::UdpClosed {
            session_id: request_session_id,
            flow_id,
            reason,
        },
    ) {
        debug!(origin = %orig.log_id(), %flow_id, %e, "udp-closed relay to agent failed");
    }
    // UDP flows carry no byte counts: SOCKS5 UDP-ASSOCIATE datagrams run
    // on per-flow `FlowStats` with no session aggregate, and `UdpClosed`
    // has no counters to forward. Zero here means "not counted", same as
    // a pre-wave-3 client — not "no traffic".
    audit_tcp_close(state, s, orig, flow_id, reason, (0, 0)).await;
}

/// Relay a tunnel-client SDP offer to the agent. Cheap session_id
/// validation only — the heavy gates (cross-tenant, agent online)
/// already fired on TunnelOpen, so reaching here means the session
/// is sound.
async fn relay_sdp_offer_to_agent(
    state: &NetworkState,
    session: Option<&TunnelSession>,
    request_session_id: ObjectId,
    sdp: String,
) {
    let Some(s) = session else {
        debug!(%request_session_id, "SDP offer on dead session — ignoring");
        return;
    };
    if s.tunnel_session_id != request_session_id {
        debug!(%request_session_id, "SDP offer session_id mismatch — ignoring");
        return;
    }
    if let Err(e) = state.fleet.rc_hub.send_to_agent(
        s.agent_id,
        ServerMsg::TunnelSdpOffer {
            shared_lease: None,
            session_id: request_session_id,
            sdp,
        },
    ) {
        warn!(%request_session_id, %e, "SDP offer relay to agent failed");
    }
}

/// Relay a tunnel ICE candidate to the agent. Symmetric to
/// [`relay_sdp_offer_to_agent`].
async fn relay_ice_to_agent(
    state: &NetworkState,
    session: Option<&TunnelSession>,
    request_session_id: ObjectId,
    candidate: serde_json::Value,
) {
    let Some(s) = session else {
        return;
    };
    if s.tunnel_session_id != request_session_id {
        return;
    }
    if let Err(e) = state.fleet.rc_hub.send_to_agent(
        s.agent_id,
        ServerMsg::TunnelIce {
            session_id: request_session_id,
            candidate,
        },
    ) {
        debug!(%request_session_id, %e, "tunnel ICE relay to agent failed");
        roomler_ai_mod_fleet::nudge::note_agent_offline_evidence(
            state,
            s.agent_id.to_hex(),
            "tunnel_ice",
        );
    }
}

/// Relay the tunnel-client's QUIC relay candidate(s) to the agent so it
/// can install a TURN permission for the client's relay address before
/// the QUIC handshake (Phase 3c). Mirror of [`relay_ice_to_agent`].
async fn relay_quic_candidate_to_agent(
    state: &NetworkState,
    session: Option<&TunnelSession>,
    request_session_id: ObjectId,
    addrs: Vec<String>,
) {
    let Some(s) = session else {
        return;
    };
    if s.tunnel_session_id != request_session_id {
        return;
    }
    if let Err(e) = state.fleet.rc_hub.send_to_agent(
        s.agent_id,
        ServerMsg::TunnelQuicCandidate {
            session_id: request_session_id,
            addrs,
        },
    ) {
        debug!(%request_session_id, %e, "tunnel QUIC candidate relay to agent failed");
    }
}

/// Append the flow-close audit row.
///
/// `bytes` = `(in, out)` **as the reporting endpoint counted them**. The
/// server cannot measure this itself — tunnel payload rides the peer-to-peer
/// data channel — which is why these two columns held a literal 0 on every
/// row written before wave 3, and why the tunnel byte series was flat.
/// `(0, 0)` from a pre-wave-3 client is therefore still the honest answer:
/// nobody counted.
async fn audit_tcp_close(
    state: &NetworkState,
    session: &TunnelSession,
    orig: &Originator,
    flow_id: u32,
    reason: CloseReason,
    bytes: (u64, u64),
) {
    let _ = state
        .tunnel_audit
        .append(&TunnelAuditEvent {
            id: None,
            tenant_id: session.agent_tenant_id,
            tunnel_session_id: session.tunnel_session_id,
            tunnel_client_id: orig.tunnel_client_id(),
            origin_agent_id: orig.origin_agent_id(),
            agent_id: session.agent_id,
            user_id: session.flow_user(orig),
            at: DateTime::now(),
            kind: TunnelAuditKind::TcpClosed,
            flow_id: Some(flow_id),
            dst_host: None,
            dst_port: None,
            bytes_in: bytes.0,
            bytes_out: bytes.1,
            message_count: 0,
            duration_ms: None,
            relay: RelayMode::Direct,
            client_src_ip: None,
            agent_src_port: None,
            client_version: orig.client_version.clone(),
            client_os: orig.client_os,
            reason: Some(format!("{reason:?}")),
            session_id: session.grant_session_id(),
            grant_id: session.grant_id(),
        })
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Revocation re-check (lifted from T1 stub, now sends typed ServerMsg)
// ─────────────────────────────────────────────────────────────────────────────

fn spawn_revocation_check(
    state: NetworkState,
    socket_tx: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    outbound_tx: mpsc::Sender<ServerMsg>,
    tunnel_client_id: ObjectId,
    tenant_id: ObjectId,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REVOCATION_CHECK_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            // ANY, deliberately (#1829): this read's job IS the tombstone.
            // `deleted_at` decides between the heartbeat arm and the typed
            // `rc:tunnel.revoked` kick below, while the `Err` arm means "row
            // unreadable" and keeps the socket OPEN (a Mongo blip must not
            // revoke a healthy fleet). A LIVE lookup would fold a removal
            // into that `Err` arm — and a deleted client would never be
            // kicked, for as long as its session lived.
            match state
                .tunnel_clients
                .find_any_in_tenant(tenant_id, tunnel_client_id)
                .await
            {
                Ok(c)
                    if c.deleted_at.is_none()
                        && matches!(c.status, AgentStatus::Online | AgentStatus::Offline) =>
                {
                    let _ = state.tunnel_clients.touch_heartbeat(tunnel_client_id).await;
                }
                Ok(_) => {
                    info!(%tunnel_client_id, "tunnel-client revoked mid-session; closing WS");
                    send_msg(
                        &outbound_tx,
                        ServerMsg::TunnelRevoked {
                            reason: "status changed to Quarantined or soft-deleted".into(),
                        },
                    )
                    .await;
                    // Give the pump a moment to flush the revocation
                    // message before slamming the socket shut.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let mut guard = socket_tx.lock().await;
                    let _ = guard.close().await;
                    return;
                }
                Err(e) => {
                    warn!(
                        %tunnel_client_id, %e,
                        "tunnel-client revocation re-check lookup failed; keeping connection open"
                    );
                }
            }
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// P3b-2: an agent driving the tunnel-CLIENT role over its own agent WS
// ─────────────────────────────────────────────────────────────────────────────

/// Agent-WS interception for the tunnel-CLIENT role (P3b-2, identity model
/// (b)). An enrolled agent may ORIGINATE tunnel-client sessions over its
/// own agent WS. This runs FIRST in the agent read-loop — ahead of the
/// target-side [`crate::agent_arms::relay_tunnel_msg_from_agent`] —
/// and consumes the variants where THIS agent acts as the tunnel
/// *originator*, driving the same subject-agnostic handlers with
/// `Principal::Agent`.
///
/// Returns `None` when consumed; `Some(parsed)` to pass the message on to
/// the target-side handler (this agent is the tunnel TARGET for that
/// session, not its originator).
///
/// Demux (P3b-2 Risk 1). The client-only-by-type variants
/// (`TunnelHello` / `TunnelOpen` / `Tcp|UdpForwardRequest` /
/// `TunnelSdpOffer` / `TunnelQuicCandidate`) are always originator-side
/// here — an agent never emits them as a target. The genuinely
/// bidirectional ones (`TunnelIce` / `TunnelTerminate` / `TcpHalfClose` /
/// `TcpClosed` / `UdpClosed`) are consumed ONLY for a session THIS agent
/// originated (`session_id ∈ sessions`); otherwise they fall through so
/// the existing target-side path relays the agent's answer back to the far
/// originating client. The reply path for an originated session reuses
/// `tunnel_clients_by_session[session_id]` — registered on open with the
/// agent's OWN outbound channel — so a target's answers reach this agent's
/// socket unchanged.
pub async fn relay_tunnel_client_msg_from_agent(
    state: &NetworkState,
    orig: &Originator,
    sessions: &mut std::collections::HashMap<ObjectId, TunnelSession>,
    supported_transports: &mut Vec<String>,
    parsed: ClientMsg,
) -> Option<ClientMsg> {
    match parsed {
        ClientMsg::TunnelHello {
            role: _,
            version,
            supported_transports: advertised,
        } => {
            debug!(agent = %orig.log_id(), %version, ?advertised, "agent tunnel-client hello");
            *supported_transports = advertised;
            None
        }
        ClientMsg::TunnelOpen {
            agent_id,
            transport,
            open_nonce,
            derp_pubkey,
            net_grant,
        } => {
            if let Some(s) = handle_tunnel_open(
                state,
                orig,
                agent_id,
                transport,
                open_nonce,
                derp_pubkey,
                // FR-90 P3-7-2a — an agent session's grant, bound here.
                net_grant,
                supported_transports,
            )
            .await
            {
                // PR-1 — mirror into the by-ORIGIN index (the per-conn
                // map below is invisible to the nudge busy check; without
                // this a routes-only agent read as idle and got cycled).
                if let Some(origin_agent) = orig.origin_agent_id() {
                    state
                        .tunnel_sessions_by_origin_agent
                        .entry(origin_agent)
                        .or_default()
                        .insert(s.tunnel_session_id);
                }
                sessions.insert(s.tunnel_session_id, s);
            }
            None
        }
        ClientMsg::TcpForwardRequest {
            session_id,
            flow_id,
            dst_host,
            dst_port,
        } => {
            handle_forward_request(
                ProtocolKind::Tcp,
                state,
                orig,
                sessions.get(&session_id),
                session_id,
                flow_id,
                &dst_host,
                dst_port,
            )
            .await;
            None
        }
        ClientMsg::UdpForwardRequest {
            session_id,
            flow_id,
            dst_host,
            dst_port,
        } => {
            handle_forward_request(
                ProtocolKind::Udp,
                state,
                orig,
                sessions.get(&session_id),
                session_id,
                flow_id,
                &dst_host,
                dst_port,
            )
            .await;
            None
        }
        ClientMsg::TunnelSdpOffer { session_id, sdp } => {
            relay_sdp_offer_to_agent(state, sessions.get(&session_id), session_id, sdp).await;
            None
        }
        ClientMsg::TunnelQuicCandidate { session_id, addrs } => {
            relay_quic_candidate_to_agent(state, sessions.get(&session_id), session_id, addrs)
                .await;
            None
        }
        // ── genuinely bidirectional: consume only if WE originated it ──
        ClientMsg::TunnelIce {
            session_id,
            candidate,
        } => {
            if sessions.contains_key(&session_id) {
                relay_ice_to_agent(state, sessions.get(&session_id), session_id, candidate).await;
                None
            } else {
                Some(ClientMsg::TunnelIce {
                    session_id,
                    candidate,
                })
            }
        }
        ClientMsg::TcpHalfClose {
            session_id,
            flow_id,
            direction,
        } => {
            if sessions.contains_key(&session_id) {
                relay_half_close_to_agent(
                    state,
                    sessions.get(&session_id),
                    orig.log_id(),
                    session_id,
                    flow_id,
                    direction,
                )
                .await;
                None
            } else {
                Some(ClientMsg::TcpHalfClose {
                    session_id,
                    flow_id,
                    direction,
                })
            }
        }
        ClientMsg::TcpClosed {
            session_id,
            flow_id,
            reason,
            bytes_in,
            bytes_out,
        } => {
            if sessions.contains_key(&session_id) {
                relay_tcp_closed_to_agent(
                    state,
                    orig,
                    sessions.get(&session_id),
                    session_id,
                    flow_id,
                    reason,
                    (bytes_in, bytes_out),
                )
                .await;
                None
            } else {
                Some(ClientMsg::TcpClosed {
                    session_id,
                    flow_id,
                    reason,
                    bytes_in,
                    bytes_out,
                })
            }
        }
        ClientMsg::UdpClosed {
            session_id,
            flow_id,
            reason,
        } => {
            if sessions.contains_key(&session_id) {
                relay_udp_closed_to_agent(
                    state,
                    orig,
                    sessions.get(&session_id),
                    session_id,
                    flow_id,
                    reason,
                )
                .await;
                None
            } else {
                Some(ClientMsg::UdpClosed {
                    session_id,
                    flow_id,
                    reason,
                })
            }
        }
        ClientMsg::TunnelTerminate { session_id, reason } => {
            if let Some(s) = sessions.remove(&session_id) {
                // We originated this session — tear it down like the
                // tunnel-client socket's terminate arm: tell the target
                // agent, drop the reply-channel registration, audit close.
                let _ = state.fleet.rc_hub.send_to_agent(
                    s.agent_id,
                    ServerMsg::TunnelTerminate {
                        session_id: s.tunnel_session_id,
                        reason,
                    },
                );
                state.tunnel_clients_by_session.remove(&s.tunnel_session_id);
                unindex_session_target(
                    &state.tunnel_sessions_by_target_agent,
                    s.agent_id,
                    s.tunnel_session_id,
                );
                if let Some(origin_agent) = orig.origin_agent_id() {
                    unindex_session_target(
                        &state.tunnel_sessions_by_origin_agent,
                        origin_agent,
                        s.tunnel_session_id,
                    );
                }
                audit_peer_close(state, &s, orig).await;
                None
            } else {
                Some(ClientMsg::TunnelTerminate { session_id, reason })
            }
        }
        // Everything else — target-side answers + non-tunnel rc:* — passes
        // through to the target-side interception / Hub.
        other => Some(other),
    }
}

/// Admission fence: all sessions lose forwarding before any audit IO.
pub(crate) fn fence_originated_sessions(
    state: &NetworkState,
    sessions: &std::collections::HashMap<ObjectId, TunnelSession>,
) {
    for s in sessions.values() {
        state.tunnel_clients_by_session.remove(&s.tunnel_session_id);
        let _ = state.fleet.rc_hub.send_to_agent(
            s.agent_id,
            ServerMsg::TunnelTerminate {
                session_id: s.tunnel_session_id,
                reason: CloseReason::ServerTerminated,
            },
        );
    }
}

/// Tear down every tunnel session an agent originated when its WS drops.
/// Mirrors the tunnel-client socket's disconnect path: for each session,
/// tell the target agent, drop the reply-channel registration, and audit
/// the close. Consumes the map.
pub async fn teardown_agent_originated_sessions(
    state: &NetworkState,
    orig: &Originator,
    sessions: std::collections::HashMap<ObjectId, TunnelSession>,
) {
    for (_session_id, s) in sessions {
        state.tunnel_clients_by_session.remove(&s.tunnel_session_id);
        unindex_session_target(
            &state.tunnel_sessions_by_target_agent,
            s.agent_id,
            s.tunnel_session_id,
        );
        // PR-1 — the by-ORIGIN twin (same shape, keyed by the closing
        // originator; see the TunnelOpen relay arm's mirror insert).
        if let Some(origin_agent) = orig.origin_agent_id() {
            unindex_session_target(
                &state.tunnel_sessions_by_origin_agent,
                origin_agent,
                s.tunnel_session_id,
            );
        }
        let _ = state.fleet.rc_hub.send_to_agent(
            s.agent_id,
            ServerMsg::TunnelTerminate {
                session_id: s.tunnel_session_id,
                reason: CloseReason::ClientShutdown,
            },
        );
        audit_peer_close(state, &s, orig).await;
    }
}

/// Drop one session from the by-target-agent index (see
/// `NetworkState::tunnel_sessions_by_target_agent`), tidying away the agent's
/// entry once its set is empty. The guard is dropped before `remove_if` so
/// the two DashMap operations never overlap on the same shard.
fn unindex_session_target(
    index: &dashmap::DashMap<ObjectId, std::collections::HashSet<ObjectId>>,
    agent_id: ObjectId,
    session_id: ObjectId,
) {
    if let Some(mut set) = index.get_mut(&agent_id) {
        set.remove(&session_id);
    }
    index.remove_if(&agent_id, |_, set| set.is_empty());
}

/// P7 flap resilience: when an agent's WS drops, every tunnel session
/// TARGETING it is dead — the agent's per-connection tunnel peers died with
/// its socket, so even after it reconnects it will reject every forward on
/// those sessions with "tunnel session not open on agent", forever. Push
/// `rc:tunnel.terminate` to each such session's client so its flow
/// supervisor re-opens promptly instead of discovering the corpse one
/// rejected flow at a time. Clients ack with their own `TunnelTerminate`,
/// which runs the normal per-connection teardown + audit; the global
/// reply-channel entry is left for that ack path (pre-P7 clients without
/// the ack still end their session on our terminate, and their entry is
/// swept on their own disconnect, exactly as today).
pub async fn terminate_sessions_targeting_agent(state: &NetworkState, agent_id: ObjectId) {
    // R3 — optional grace before terminating sessions when the target agent's
    // control WS drops. `0` (default) = terminate immediately (pre-R3). `>0` =
    // keep the sessions (their QUIC data plane + the nudge busy-gate index rely
    // on it) and terminate only if the agent is STILL offline after the window.
    // A same-pod re-register (hub) or cross-pod one (fresh foreign Redis
    // presence) cancels it — no explicit cancel registry needed. Pairs with the
    // agent's `tunnel_peers_survive_reattach`.
    let grace = state.settings.rc.tunnel_grace_secs;
    if grace == 0 {
        terminate_agent_sessions_now(state, agent_id);
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(grace)).await;
        if state.fleet.rc_hub.is_agent_online(agent_id) {
            debug!(%agent_id, "R3 grace: agent re-registered on this pod — tunnel sessions kept");
            return;
        }
        // A fresh FOREIGN presence record ⇒ the agent re-registered on another
        // pod; keep the sessions (its reclaimed peers serve them). A wedged or
        // unreachable Redis falls through to terminate — fail-safe: never keep a
        // session alive on an unverifiable presence — bounded by the same 250 ms
        // as the open-time rehome probe.
        if let Some(redis) = &state.redis_pubsub
            && let Ok(Ok(Some(_))) = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                redis.agent_presence_foreign(&agent_id.to_hex()),
            )
            .await
        {
            debug!(%agent_id, "R3 grace: agent re-registered on another pod — tunnel sessions kept");
            return;
        }
        info!(%agent_id, grace_secs = grace, "R3 grace expired — agent still offline; terminating tunnel sessions");
        terminate_agent_sessions_now(&state, agent_id);
    });
}

/// Immediately terminate every tunnel session targeting `agent_id`: drop the
/// by-target index and push `TunnelTerminate` to each client. The pre-R3
/// behaviour, now also the grace-expiry path.
pub(crate) fn terminate_agent_sessions_now(state: &NetworkState, agent_id: ObjectId) {
    let Some((_, session_ids)) = state.tunnel_sessions_by_target_agent.remove(&agent_id) else {
        return;
    };
    for sid in session_ids {
        // Clone the tx out of the map guard before awaiting — holding a
        // DashMap ref across an await point can deadlock the shard.
        let tx = state
            .tunnel_clients_by_session
            .get(&sid)
            .map(|e| e.value().clone());
        if let Some(tx) = tx {
            info!(%agent_id, session_id = %sid, "target agent WS dropped — terminating tunnel session");
            // try_send, not send: this runs on the AGENT's WS teardown path,
            // and an awaited send on a wedged client channel (blackholed
            // socket, full cap-256 buffer) would stall unregister +
            // mark_status(offline) behind an unrelated client. A dropped
            // push is fine — the client still heals via the session-gone
            // reject on its next forward.
            let msg = ServerMsg::TunnelTerminate {
                session_id: sid,
                reason: CloseReason::ServerTerminated,
            };
            if let Err(e) = tx.try_send(msg) {
                debug!(%agent_id, session_id = %sid, %e, "terminate push dropped (client channel full/closed)");
            }
        }
    }
}

/// The `/ws?role=tunnel-client` upgrade (FR-69 P7b, from the host): verify the
/// tunnel-client JWT, the affinity key and the row, say why on refusal, then
/// run the loop. The host keeps the `/ws` route and the role gate.
pub fn ws_upgrade_tunnel_client(
    state: NetworkState,
    token: String,
    tid: Option<String>,
    connection_origin: ConnectionOrigin,
    ws: WebSocketUpgrade,
) -> Response {
    let claims = match state.auth.verify_tunnel_client_token(&token) {
        Ok(c) => c,
        Err(_) => {
            return Response::builder()
                .status(401)
                .body("Unauthorized (tunnel-client)".into())
                .unwrap();
        }
    };

    // S6 — a present affinity key must match the token's tenant.
    if !tid_matches_claim(&tid, &claims.tenant_id) {
        return Response::builder()
            .status(403)
            .body("tid does not match token tenant".into())
            .unwrap();
    }

    let tunnel_client_id = match ObjectId::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return Response::builder()
                .status(400)
                .body("Invalid tunnel-client ID".into())
                .unwrap();
        }
    };
    let tenant_id = match ObjectId::parse_str(&claims.tenant_id) {
        Ok(id) => id,
        Err(_) => {
            return Response::builder()
                .status(400)
                .body("Invalid tenant ID".into())
                .unwrap();
        }
    };
    let owner_user_id = match ObjectId::parse_str(&claims.owner_user_id) {
        Ok(id) => id,
        Err(_) => {
            return Response::builder()
                .status(400)
                .body("Invalid owner user ID".into())
                .unwrap();
        }
    };
    let token_gen = claims.generation;

    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
        // Connect-time revocation check. Periodic re-check (every 60 s)
        // lives in `ws::tunnel::handle_tunnel_client_socket`.
        //
        // ANY, deliberately (#1829): the tombstone is what this read is FOR
        // — `deleted_at` below selects the typed `rc:tunnel.revoked` goodbye
        // (close 4003, "re-enrol to revive") the CLI logs and stops on. A
        // LIVE lookup would turn a removal into the `Err` arm's frameless
        // `return`, and the CLI would reconnect forever against what reads
        // as a network fault.
        let client = match state
            .tunnel_clients
            .find_any_in_tenant(tenant_id, tunnel_client_id)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!(%tunnel_client_id, %e, "tunnel-client lookup failed on WS connect");
                return;
            }
        };
        if client.deleted_at.is_some()
            || matches!(
                client.status,
                roomler_ai_remote_control::models::AgentStatus::Quarantined
            )
        {
            // rc.53: mirror of the agent refusal path. Tunnel-clients
            // have their own taxonomy (`ServerMsg::TunnelRevoked`) and
            // the periodic re-check in `handle_tunnel_client_socket`
            // already emits it on mid-session revocation — extend the
            // same notification to the connect-time refusal so the CLI
            // logs "tunnel revoked" instead of opaque socket close.
            info!(%tunnel_client_id, "tunnel-client is quarantined or deleted; refusing WS with rc:tunnel.revoked");
            let revoked = roomler_ai_remote_control::signaling::ServerMsg::TunnelRevoked {
                reason: "tunnel-client row was deleted or quarantined; re-enrol to revive".into(),
            };
            send_goodbye_and_close(socket, &revoked, 4003, "tunnel_client_deleted").await;
            return;
        }
        // FR-103 — a token minted before this client was removed and
        // re-enrolled. To the CLI that is a revoked credential: it stops and
        // says to re-enroll, which is exactly the remedy.
        if let Some(reason) = roomler_ai_mod_fleet::auth_agent::generation_refusal(
            token_gen,
            client.token_gen,
            state.fleet.settings.rc.token_generation_check,
        ) {
            info!(%tunnel_client_id, reason, row_gen = client.token_gen, "tunnel-client token predates its removal; refusing WS with rc:tunnel.revoked");
            let revoked = roomler_ai_remote_control::signaling::ServerMsg::TunnelRevoked {
                reason: reason.into(),
            };
            send_goodbye_and_close(socket, &revoked, 4003, "tunnel_client_superseded").await;
            return;
        }
        handle_tunnel_client_socket(
            state,
            socket,
            tunnel_client_id,
            tenant_id,
            owner_user_id,
            tid,
            connection_origin,
            token_gen,
        )
        .await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_cannot_upgrade_an_old_token_to_the_current_generation() {
        let owner = ObjectId::new();
        assert!(authority_identity_current(4, 4, owner, owner));
        assert!(!authority_identity_current(3, 4, owner, owner));
        assert!(!authority_identity_current(5, 4, owner, owner));
    }

    #[test]
    fn authority_uses_the_current_owner_not_only_the_signed_old_claim() {
        assert!(!authority_identity_current(
            4,
            4,
            ObjectId::new(),
            ObjectId::new(),
        ));
    }

    fn grant(dst: Option<(&str, u16)>, exp: i64) -> SessionGrant {
        SessionGrant {
            session_id: ObjectId::new(),
            device: ObjectId::new(),
            owner_user_id: ObjectId::new(),
            grant_id: "g1".into(),
            dst: dst.map(|(h, p)| (h.to_string(), p)),
            exp,
        }
    }

    /// FR-90 P3-7-2a — a flow stays inside its session's grant: TCP only,
    /// before its end, and a forward toward its one destination, in any
    /// spelling of its host. SOCKS names no destination: the policies decide.
    #[test]
    fn a_flow_is_held_to_its_sessions_grant() {
        let now = 1_000;
        let forward = grant(Some(("db.internal", 5432)), now + 60);
        assert_eq!(
            forward.admits(ProtocolKind::Tcp, "db.internal", 5432, now),
            Ok(())
        );
        assert_eq!(
            forward.admits(ProtocolKind::Tcp, "DB.Internal.", 5432, now),
            Ok(()),
            "one spelling"
        );
        for (host, port) in [
            ("db.internal", 22),
            ("other.internal", 5432),
            ("010.0.0.5", 5432),
            ("", 5432),
        ] {
            assert!(
                forward.admits(ProtocolKind::Tcp, host, port, now).is_err(),
                "{host}:{port}"
            );
        }
        assert!(
            forward
                .admits(ProtocolKind::Udp, "db.internal", 5432, now)
                .is_err(),
            "TCP only"
        );
        assert!(
            forward
                .admits(ProtocolKind::Tcp, "db.internal", 5432, now + 60)
                .is_err(),
            "not at its end"
        );
        let socks = grant(None, now + 60);
        assert_eq!(
            socks.admits(ProtocolKind::Tcp, "anything.example", 443, now),
            Ok(())
        );
        assert!(
            socks
                .admits(ProtocolKind::Udp, "anything.example", 53, now)
                .is_err()
        );
        assert!(
            socks
                .admits(ProtocolKind::Tcp, "anything.example", 443, now + 61)
                .is_err()
        );
    }

    /// FR-90 P3-7-2a — a grant's flows are decided for its session, on the
    /// device that carries them, never for the device itself.
    #[test]
    fn a_grants_flows_are_decided_for_its_session() {
        let g = grant(None, 1);
        assert_eq!(
            g.principal(),
            Principal::Session {
                session_id: g.session_id,
                agent_id: g.device,
            }
        );
        assert_ne!(g.principal(), Principal::Agent(g.device));
    }

    /// An auth service under a secret made at run time.
    fn auth() -> AuthService {
        AuthService::new(roomler_ai_config::JwtSettings {
            secret: format!("p372a-{}-{}", ObjectId::new(), ObjectId::new()),
            previous_secrets: String::new(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 3600,
            issuer: "roomler-ai-test".into(),
        })
    }

    fn originator(principal: Principal, tenant_id: ObjectId) -> Originator {
        let (outbound_tx, _) = mpsc::channel(1);
        Originator {
            principal,
            tenant_id,
            owner_user_id: ObjectId::new(),
            client_version: String::new(),
            client_os: OsKind::Linux,
            outbound_tx,
            dialed_tid: None,
            conn_established_ms: 0,
        }
    }

    /// FR-90 P3-7-2a — a grant binds only where it holds: on an agent's own
    /// connection, signed by this server, in its organization, from the device
    /// it names and toward the exit it names. What it binds is the session's,
    /// as the grant names it. Each refusal is in its own words.
    #[test]
    fn a_grant_binds_only_where_it_holds() {
        use roomler_ai_services::auth::NetGrant;
        let ours = auth();
        let (tenant, device, exit) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let (session, owner, grant_id) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let exp = DateTime::now().timestamp_millis().div_euclid(1000) + 60;
        let sign = |by: &AuthService, dst: Option<(&str, u16)>| {
            by.issue_net_grant(&NetGrant {
                session_id: session,
                tenant_id: tenant,
                fence: 1,
                owner_user_id: owner,
                origin_agent_id: device,
                exit_agent_id: exit,
                net: if dst.is_some() {
                    NetKind::Forward
                } else {
                    NetKind::Socks
                },
                dst,
                grant_id,
                exp,
            })
            .expect("a grant that holds together is signed")
        };
        let on_device = originator(Principal::Agent(device), tenant);

        let forward = sign(&ours, Some(("db.internal", 5432)));
        let g = bind_net_grant(&ours, &on_device, exit, &forward).expect("it holds");
        assert_eq!(
            (g.session_id, g.device, g.owner_user_id, g.grant_id.as_str()),
            (session, device, owner, grant_id.to_hex().as_str())
        );
        assert_eq!(
            (g.dst, g.exp),
            (Some(("db.internal".to_string(), 5432)), exp)
        );
        let socks = sign(&ours, None);
        assert_eq!(
            bind_net_grant(&ours, &on_device, exit, &socks)
                .expect("it holds")
                .dst,
            None
        );

        let elsewhere = ObjectId::new();
        for (orig, open_exit, token, why) in [
            (
                originator(Principal::TunnelClient(device), tenant),
                exit,
                socks.clone(),
                "a session's grant rides only its own device's connection",
            ),
            (
                originator(Principal::Agent(device), tenant),
                exit,
                sign(&auth(), None),
                "not a grant this server signed, or it has ended",
            ),
            (
                originator(Principal::Agent(device), tenant),
                exit,
                "a.b.c".to_string(),
                "not a grant this server signed, or it has ended",
            ),
            (
                originator(Principal::Agent(device), elsewhere),
                exit,
                socks.clone(),
                "a grant for another organization",
            ),
            (
                originator(Principal::Agent(elsewhere), tenant),
                exit,
                socks.clone(),
                "a grant for another device",
            ),
            (
                originator(Principal::Agent(device), tenant),
                elsewhere,
                socks.clone(),
                "a grant for another exit",
            ),
        ] {
            assert_eq!(
                bind_net_grant(&ours, &orig, open_exit, &token).err(),
                Some(why),
                "{why}"
            );
        }
    }
}
