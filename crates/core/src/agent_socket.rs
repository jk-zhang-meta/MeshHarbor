// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The agent socket's seam (FR-69 P5c): the module that OWNS the socket
//! (`fleet`) dispatches every message to the module that OWNS the message,
//! and lets the other modules keep per-connection state through a small
//! lifecycle — without naming them.
//!
//! One `/ws?role=agent` socket, one `rc:*` enum, one owner per variant
//! ([`ClientMsg::namespace`], P5b). The loop, the hello, the Hub
//! registration, presence and the teardown ORDER are fleet's; what `remote`
//! and `network` do with their messages, and what they set up on hello and
//! release on close, is theirs — registered here, invoked in
//! [`crate::hooks::HOOK_ORDER`]. Until those two are extracted the host
//! registers their handlers under their ids (the P5a shape for hooks).
//!
//! # The teardown order, written once
//!
//! 1. every lifecycle's [`AgentSocketLifecycle::closing`] (network: tear down
//!    the tunnel sessions this agent originated, terminate those targeting it);
//! 2. fleet: `Hub::unregister_agent` with the connection's own sender, which
//!    answers `removal_was_ours` — a displaced handler's late teardown must
//!    not evict the newer connection;
//! 3. every lifecycle's [`AgentSocketLifecycle::closed`] with that answer
//!    (network: the overlay leave, ONLY if ours);
//! 4. fleet, only if ours: the Offline write, the presence compare-DEL, the
//!    `device:presence` OFFLINE transition.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bson::oid::ObjectId;
use roomler_ai_remote_control::{
    models::OsKind,
    signaling::{ClientMsg, ServerMsg},
};
use tokio::sync::mpsc;

use crate::hooks::HOOK_ORDER;

/// What every arm of the agent socket needs about the connection it serves.
/// One value per CONNECTION (a displacing connection for the same agent gets
/// its own `conn_id`), cloned into the modules' handlers.
#[derive(Clone)]
pub struct AgentCtx {
    /// Unique per connection — the key a module uses for per-connection
    /// state, never `agent_id` (two connections of one agent overlap during
    /// a displacement, and the old one's teardown must not find the new
    /// one's state).
    pub conn_id: String,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub owner_user_id: ObjectId,
    /// From the hello: what the device runs.
    pub agent_version: String,
    pub os: OsKind,
    /// PR-1 rehome — the (validated) affinity key this connection dialed
    /// with; `None` = a key-less dial that hashed on client IP.
    pub dialed_tid: Option<String>,
    pub conn_established_ms: i64,
    /// The Hub's outbound sender for this connection — how an arm answers
    /// the device (a reply routed through the Hub's pump, never a second
    /// writer on the socket).
    pub tx: mpsc::Sender<ServerMsg>,
}

/// A module's handler for the client messages it owns. Returns the message
/// back when it did NOT consume it, so the socket can hand it to the Hub's
/// own dispatch (session signalling, consent, ping) exactly as before.
#[async_trait]
pub trait AgentMsgHandler: Send + Sync {
    async fn handle(&self, ctx: &AgentCtx, msg: ClientMsg) -> Option<ClientMsg>;
}

/// What a module sets up when an agent connects and releases when it goes —
/// the per-connection state its arms need. Every method is optional.
#[async_trait]
pub trait AgentSocketLifecycle: Send + Sync {
    /// The hello landed and the Hub registration succeeded: create what the
    /// arms will need, keyed by `ctx.conn_id`.
    async fn hello(&self, ctx: &AgentCtx) {
        let _ = ctx;
    }

    /// A heartbeat arrived (after the Hub saw it). `warm_relay` is what the
    /// device reported holding; a module mirroring it onto its own records
    /// does so here.
    async fn heartbeat(&self, ctx: &AgentCtx, warm_relay: Option<&str>) {
        let _ = (ctx, warm_relay);
    }

    /// Security revocation, after dispatch cancellation and identity-gated
    /// hub removal. Must synchronously fence in-memory data-plane access;
    /// persistence belongs in closing/closed and must not delay revocation.
    fn revoked(&self, ctx: &AgentCtx) {
        let _ = ctx;
    }

    /// The socket is closing, BEFORE the Hub unregistration: release what
    /// must go regardless of who owns the slot (tunnel sessions live on this
    /// connection's peers and die with it).
    async fn closing(&self, ctx: &AgentCtx) {
        let _ = ctx;
    }

    /// The Hub answered whether this connection's removal was its own.
    /// Anything that must not run for a displaced connection (the overlay
    /// leave, which would ghost the replacing connection's node) checks
    /// `removal_was_ours`.
    async fn closed(&self, ctx: &AgentCtx, removal_was_ours: bool) {
        let _ = (ctx, removal_was_ours);
    }
}

/// What one module registers for the agent socket.
#[derive(Clone, Default)]
pub struct AgentSocketHooks {
    pub handler: Option<Arc<dyn AgentMsgHandler>>,
    pub lifecycle: Option<Arc<dyn AgentSocketLifecycle>>,
}

/// The registry on `Core` (`core.agent_socket`): handlers by owning module
/// id, lifecycles in [`HOOK_ORDER`]. Shared (an `Arc`) so a registration
/// made after a `Core` was cloned is visible to that clone.
#[derive(Clone, Default)]
pub struct AgentSocketRegistry {
    inner: Arc<RwLock<Vec<(&'static str, AgentSocketHooks)>>>,
}

impl std::fmt::Debug for AgentSocketRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<&'static str> = inner.iter().map(|(id, _)| *id).collect();
        f.debug_struct("AgentSocketRegistry")
            .field("modules", &ids)
            .finish()
    }
}

impl AgentSocketRegistry {
    /// Register a module's hooks. A second registration for the same id
    /// replaces the first.
    pub fn register(&self, module: &'static str, hooks: AgentSocketHooks) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.retain(|(id, _)| *id != module);
        inner.push((module, hooks));
    }

    /// The handler the module with this id registered, if any.
    pub fn handler(&self, module: &str) -> Option<Arc<dyn AgentMsgHandler>> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner
            .iter()
            .find(|(id, _)| *id == module)
            .and_then(|(_, h)| h.handler.clone())
    }

    /// Every registered lifecycle, in [`HOOK_ORDER`].
    pub fn lifecycles(&self) -> Vec<(&'static str, Arc<dyn AgentSocketLifecycle>)> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        HOOK_ORDER
            .iter()
            .filter_map(|id| {
                inner
                    .iter()
                    .find(|(m, _)| m == id)
                    .and_then(|(_, h)| h.lifecycle.clone())
                    .map(|l| (*id, l))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Consumes;

    #[async_trait]
    impl AgentMsgHandler for Consumes {
        async fn handle(&self, _ctx: &AgentCtx, msg: ClientMsg) -> Option<ClientMsg> {
            match msg {
                ClientMsg::Ping { .. } => None,
                other => Some(other),
            }
        }
    }

    fn ctx() -> AgentCtx {
        let (tx, _rx) = mpsc::channel(1);
        AgentCtx {
            conn_id: "c1".into(),
            agent_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            owner_user_id: ObjectId::new(),
            agent_version: "0.4.63".into(),
            os: OsKind::Linux,
            dialed_tid: None,
            conn_established_ms: 0,
            tx,
        }
    }

    #[tokio::test]
    async fn a_handler_returns_what_it_does_not_consume() {
        let reg = AgentSocketRegistry::default();
        reg.register(
            "network",
            AgentSocketHooks {
                handler: Some(Arc::new(Consumes)),
                lifecycle: None,
            },
        );
        let h = reg.handler("network").expect("registered");
        assert!(h.handle(&ctx(), ClientMsg::Ping { id: 1 }).await.is_none());
        assert!(
            h.handle(&ctx(), ClientMsg::OverlayLeave {}).await.is_some(),
            "an unowned message comes back for the Hub's dispatch"
        );
        assert!(reg.handler("remote").is_none());
    }

    #[test]
    fn lifecycles_come_out_in_hook_order_regardless_of_registration_order() {
        struct L;
        #[async_trait]
        impl AgentSocketLifecycle for L {}
        let reg = AgentSocketRegistry::default();
        for id in ["fleet", "network", "remote"] {
            reg.register(
                id,
                AgentSocketHooks {
                    handler: None,
                    lifecycle: Some(Arc::new(L)),
                },
            );
        }
        let order: Vec<&str> = reg.lifecycles().into_iter().map(|(id, _)| id).collect();
        assert_eq!(order, vec!["remote", "network", "fleet"]);
    }
}
