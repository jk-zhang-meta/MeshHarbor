// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `network`'s half of the agent socket (FR-69 P5c → P7b): what the module
//! registers through the core's `AgentSocketRegistry` from its init, so the
//! socket — the fleet module's — dispatches every message to its owner
//! without naming this crate. (`remote`'s half registers itself the same way.)
//!
//! The order inside the network handler is the socket's old pipeline
//! verbatim: the tunnel-client relay (this agent as an ORIGINATOR of
//! tunnels), the tunnel relay (this agent as a TARGET), the overlay relay,
//! then the five explicit arms. Each stage consumes what it owns and hands
//! the rest on; what none of them owns goes back to the socket for the Hub's
//! own dispatch, exactly as before.
//!
//! Per-connection state (the tunnel originator with its sessions and
//! transports, the probe-persist throttle) is keyed by the connection id the
//! socket minted — never by agent id: two connections of one agent overlap
//! during a displacement, and the old one's teardown must not find the new
//! one's sessions.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bson::oid::ObjectId;
use dashmap::DashMap;
use roomler_ai_remote_control::signaling::ClientMsg;
use roomler_core::{AgentCtx, AgentMsgHandler, AgentSocketLifecycle};
use tokio::sync::Mutex;
use tracing::debug;

use crate::NetworkState;
use crate::agent_arms::{
    handle_agent_ssh_request, handle_derp_ticket_request, handle_relay_probe_report,
    record_key_rotation_report, record_ssh_activity, relay_tunnel_msg_from_agent,
};
use crate::overlay::NodeIdentity;
use crate::tunnel::{
    Originator, TunnelSession, relay_tunnel_client_msg_from_agent,
    teardown_agent_originated_sessions, terminate_sessions_targeting_agent,
};

/// What the network arms keep per connection. The originator is shared
/// (`Arc`) so the teardown can take the sessions out from under a handler
/// call that still holds the lock, without a `Clone` on the originator.
struct NetConn {
    orig: Arc<Originator>,
    sessions: HashMap<ObjectId, TunnelSession>,
    transports: Vec<String>,
    last_probe_persist: Option<std::time::Instant>,
    /// MeshHarbor #19 — the inventory snapshot this connection is sending.
    inventory: crate::net_inventory::Assembly,
}

/// `network`'s half of the agent socket, over the host's tunnel, overlay,
/// relay, DERP-ticket, SSH and key-rotation code.
pub struct NetworkAgentSocket {
    state: NetworkState,
    conns: DashMap<String, Arc<Mutex<NetConn>>>,
}

impl NetworkAgentSocket {
    pub fn new(state: NetworkState) -> Self {
        Self {
            state,
            conns: DashMap::new(),
        }
    }

    fn conn(&self, ctx: &AgentCtx) -> Option<Arc<Mutex<NetConn>>> {
        self.conns.get(&ctx.conn_id).map(|e| e.value().clone())
    }
}

#[async_trait]
impl AgentMsgHandler for NetworkAgentSocket {
    async fn handle(&self, ctx: &AgentCtx, msg: ClientMsg) -> Option<ClientMsg> {
        let state = &self.state;
        let msg = match msg {
            ClientMsg::SharedSshPrepared {
                session_id,
                accepted,
            } => {
                crate::shared_ssh::prepared(state, ctx, session_id, accepted).await;
                return None;
            }
            ClientMsg::SharedSshLeaseChallenge {
                session_id,
                grant_id,
                lease_epoch,
                challenge_id,
            } => {
                crate::shared_ssh::renew(
                    state,
                    ctx,
                    session_id,
                    grant_id,
                    lease_epoch,
                    challenge_id,
                )
                .await;
                return None;
            }
            other => other,
        };
        if !crate::shared_ssh::agent_frame_allowed(state, ctx, &msg) {
            return None;
        }
        let Some(conn) = self.conn(ctx) else {
            // No hello ran for this connection (cannot happen: the socket
            // calls `hello` before it reads); hand the message back rather
            // than drop it silently.
            debug!(agent = %ctx.agent_id, conn = %ctx.conn_id, "network arm without a connection record");
            return Some(msg);
        };
        let mut conn = conn.lock().await;
        let NetConn {
            orig,
            sessions,
            transports,
            last_probe_persist,
            inventory,
        } = &mut *conn;
        // P3b-2 — this agent as a tunnel ORIGINATOR (declared routes).
        let msg =
            relay_tunnel_client_msg_from_agent(state, orig.as_ref(), sessions, transports, msg)
                .await?;
        // This agent as a tunnel TARGET.
        let msg = relay_tunnel_msg_from_agent(state, msg).await?;
        // The overlay node behind this socket.
        let msg = crate::overlay::relay_overlay_msg_from_node(
            state,
            NodeIdentity::Agent(ctx.agent_id),
            msg,
        )
        .await?;
        match msg {
            ClientMsg::RelayProbeReport { results } => {
                handle_relay_probe_report(state, ctx.agent_id, &results, last_probe_persist).await;
                None
            }
            ClientMsg::NetInventory {
                boot_id,
                seq,
                page,
                pages,
                observed_at_ms,
                inventory: body,
            } => {
                let page = crate::net_inventory::Page {
                    boot_id,
                    seq,
                    page,
                    pages,
                    observed_at_ms,
                    inventory: *body,
                };
                crate::net_inventory::receive(state, ctx, inventory, page).await;
                None
            }
            ClientMsg::ManagedForwardStatus { statuses, confirm } => {
                crate::managed_forward::record_status(state, ctx.tenant_id, ctx.agent_id, statuses)
                    .await;
                // The status arrived over this connection after the nft
                // change: the control path survived it. Say so on the same
                // connection, so the agent's watchdog keeps the change.
                if let Some(generation) = confirm {
                    let _ = ctx.tx.try_send(
                        roomler_ai_remote_control::signaling::ServerMsg::ManagedForwardConfirm {
                            generation,
                        },
                    );
                }
                None
            }
            ClientMsg::DerpTicketRequest {} => {
                handle_derp_ticket_request(state, ctx.agent_id, &ctx.tx).await;
                None
            }
            ClientMsg::SshRequest {
                request_id,
                target,
                public_key,
                session_secs,
                ssh_ticket,
            } => {
                let state = state.clone();
                let (tenant_id, agent_id, reply_tx) = (ctx.tenant_id, ctx.agent_id, ctx.tx.clone());
                tokio::spawn(async move {
                    handle_agent_ssh_request(
                        &state,
                        tenant_id,
                        agent_id,
                        request_id,
                        target,
                        public_key,
                        session_secs,
                        ssh_ticket,
                        reply_tx,
                    )
                    .await;
                });
                None
            }
            // FR-83 — the target's answer to a grant. The agent id is the
            // authenticated socket's, never the frame's: an ack confirms only
            // the grant that was pushed to THIS device.
            ClientMsg::SshGrantAck { grant_id, refused } => {
                if !state
                    .ssh_grant_acks
                    .deliver(&grant_id, ctx.agent_id, refused)
                {
                    // The caller gave up (past the bound) or never waited.
                    // Worth a line: a stream of these from one device says its
                    // control connection is slower than the bound.
                    debug!(
                        agent_id = %ctx.agent_id, %grant_id, ?refused,
                        "ssh: grant ack with no waiter — late, or not this device's grant"
                    );
                }
                None
            }
            ClientMsg::SshActivity {
                grant_id,
                caller,
                kind,
                detail,
                exit_code,
                allowed,
            } => {
                let state = state.clone();
                let (tenant_id, agent_id) = (ctx.tenant_id, ctx.agent_id);
                tokio::spawn(async move {
                    record_ssh_activity(
                        &state, tenant_id, agent_id, grant_id, caller, kind, detail, exit_code,
                        allowed,
                    )
                    .await;
                });
                None
            }
            ClientMsg::KeyRotated {
                request_id,
                outcome,
                old_public_key,
                new_public_key,
                key_epoch,
                detail,
            } => {
                let state = state.clone();
                let (tenant_id, agent_id) = (ctx.tenant_id, ctx.agent_id);
                tokio::spawn(async move {
                    record_key_rotation_report(
                        &state,
                        tenant_id,
                        agent_id,
                        request_id,
                        outcome,
                        old_public_key,
                        new_public_key,
                        key_epoch,
                        detail,
                    )
                    .await;
                });
                None
            }
            other => Some(other),
        }
    }
}

#[async_trait]
impl AgentSocketLifecycle for NetworkAgentSocket {
    async fn hello(&self, ctx: &AgentCtx) {
        // MeshHarbor #20 — the forwards this agent should run, on every
        // (re)connect; its caps land with the hello, so give them a moment.
        {
            let (state, tid, aid) = (self.state.clone(), ctx.tenant_id, ctx.agent_id);
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                crate::managed_forward::push_to(&state, tid, aid).await;
            });
        }
        let orig = Originator {
            principal: tunnel_core::policy::Principal::Agent(ctx.agent_id),
            tenant_id: ctx.tenant_id,
            owner_user_id: ctx.owner_user_id,
            client_version: ctx.agent_version.clone(),
            client_os: ctx.os,
            outbound_tx: ctx.tx.clone(),
            dialed_tid: ctx.dialed_tid.clone(),
            conn_established_ms: ctx.conn_established_ms,
        };
        self.conns.insert(
            ctx.conn_id.clone(),
            Arc::new(Mutex::new(NetConn {
                orig: Arc::new(orig),
                sessions: HashMap::new(),
                transports: Vec::new(),
                last_probe_persist: None,
                inventory: Default::default(),
            })),
        );
        // MeshHarbor `auto`: this connection's opening observation is the
        // agent's zone evidence from now on; an implicit session vouched for
        // by the connection it displaced does not carry over.
        if self
            .state
            .org_relay
            .bind_live_conn(ctx.agent_id, &ctx.conn_id)
            .is_some()
        {
            crate::org_relay::revoke_implicit_for_agent(
                &self.state,
                ctx.agent_id,
                "connection_displaced",
            )
            .await;
        }
    }

    /// The device's warm-relay choice mirrored onto its overlay node.
    async fn heartbeat(&self, ctx: &AgentCtx, warm_relay: Option<&str>) {
        if let Err(e) = self
            .state
            .overlay_nodes
            .set_warm_relay_for_agent(ctx.agent_id, warm_relay)
            .await
        {
            tracing::warn!(agent = %ctx.agent_id, %e, "overlay-node warm-relay mirror failed");
        }
    }

    fn revoked(&self, ctx: &AgentCtx) {
        crate::overlay::revoke_agent_admission(&self.state, ctx.agent_id);
        let events = crate::org_relay::revoke_agent_sync(
            &self.state,
            ctx.tenant_id,
            ctx.agent_id,
            "account_admission_revoked",
        );
        let audit = self.state.peer_relay_audit.clone();
        if !events.is_empty() {
            tokio::spawn(async move {
                for event in events {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        audit.record(event),
                    )
                    .await;
                }
            });
        }
        crate::tunnel::terminate_agent_sessions_now(&self.state, ctx.agent_id);
        // Dispatch has been cancelled before this synchronous hook, releasing
        // its per-connection mutex. Leave records for the normal audit cleanup.
        if let Some(conn) = self.conns.get(&ctx.conn_id) {
            if let Ok(conn) = conn.try_lock() {
                crate::tunnel::fence_originated_sessions(&self.state, &conn.sessions);
            }
        }
    }

    /// Before the Hub unregistration, regardless of who owns the slot: the
    /// tunnel sessions this connection originated die with its peers (P3b-2),
    /// and every session targeting the agent is unrecoverable on a new
    /// connection instance (P7 flap resilience).
    async fn closing(&self, ctx: &AgentCtx) {
        // MeshHarbor `auto`: what this connection's zone vouched for ends here.
        if self
            .state
            .org_relay
            .unbind_live_conn(ctx.agent_id, &ctx.conn_id)
        {
            crate::org_relay::revoke_implicit_for_agent(
                &self.state,
                ctx.agent_id,
                "connection_closed",
            )
            .await;
        }
        if let Some((_, conn)) = self.conns.remove(&ctx.conn_id) {
            let conn = match Arc::try_unwrap(conn) {
                Ok(m) => m.into_inner(),
                Err(arc) => {
                    // A handler call still holds the lock: wait for it and
                    // take the state out from under it rather than skip the
                    // teardown.
                    let mut guard = arc.lock().await;
                    NetConn {
                        orig: guard.orig.clone(),
                        sessions: std::mem::take(&mut guard.sessions),
                        transports: std::mem::take(&mut guard.transports),
                        last_probe_persist: guard.last_probe_persist.take(),
                        inventory: Default::default(),
                    }
                }
            };
            teardown_agent_originated_sessions(&self.state, conn.orig.as_ref(), conn.sessions)
                .await;
        }
        terminate_sessions_targeting_agent(&self.state, ctx.agent_id).await;
    }

    /// The overlay leave, ONLY if the Hub removal was this connection's:
    /// unconditional, a displaced connection's late teardown would mark the
    /// node Offline after the replacing connection's re-join set it Online
    /// (rc.307 B).
    async fn closed(&self, ctx: &AgentCtx, removal_was_ours: bool) {
        if removal_was_ours {
            crate::overlay::handle_overlay_leave(&self.state, NodeIdentity::Agent(ctx.agent_id))
                .await;
        }
    }
}
