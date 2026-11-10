// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `hive` — agent sessions, the server side (FR-90 P0b).
//!
//! What the server holds about an agent session: the record — who started
//! it, on which device, in which folder, where it is in its life — and the
//! audit of every start and stop. Never what is IN a session: the transcript
//! lives on the devices that run and replicate it, and no frame this module
//! sends or reads carries a prompt, a tool call or an output
//! (`docs/meshharbor-hive-design.md` §3.3).
//!
//! Running a session is remote code execution on a device, so it is gated
//! like exec and SSH: the server's gates in [`routes`] (`HIVE_RUN` in no
//! managed role below `ADMINISTRATOR`, a per-(user, device) ceiling), then
//! the device's own, which survive a compromised server — `hive_enabled`
//! (default off), the account `hive_accounts` maps the starter to (never
//! SYSTEM/root, never one the server names), the folder confined to
//! `hive_roots`.
//!
//! The module's switch is the one that defaults OFF (`[modules] hive`): it is
//! FR-90's P0 kill switch, so a roll that ships this code exposes nothing
//! until an operator turns it on.
//!
//! Built on `fleet` (`hive → fleet`): the Hub carries the frames and knows
//! which connections advertise `hive`. And on `chat` (`hive → chat`, P0d): a
//! session is a `Secret` room bound to it, where the session posts a stub per
//! turn ([`room`]).
//!
//! The one thing here a session's model reads is the [`brain`]'s core memory
//! (P1e): facts people curate, rendered into a frozen snapshot per session
//! and sent with its start — curated text, never a session's content, and
//! shown to a session only where the device's own `hive_core_memory` allows.

use std::sync::Arc;

use axum::{
    Router,
    extract::FromRef,
    routing::{get, post, put},
};
use meshharbor_config::Settings;
use meshharbor_core::{
    AgentSocketHooks, Capabilities, Core, Hooks, Module, Role, TenantCtx, WsHandlerSpec,
    WsRegistration, rate_limit::RateLimiter,
};
use meshharbor_db::indexes::{IndexSet, index, index_ttl, index_unique};
use meshharbor_mod_chat::bound::BoundChat;
use meshharbor_mod_fleet::FleetState;

pub mod access;
pub mod acks;
mod adopt;
pub mod agent_socket;
pub mod brain;
pub mod dao;
pub mod fork;
pub mod hooks;
pub mod lease;
pub mod manage;
pub mod model;
pub mod participants;
pub mod placement;
pub mod policy;
pub mod promote;
pub mod purge;
pub mod replica;
pub mod retention;
pub mod room;
pub mod routes;
pub mod scope;
pub mod stream;
mod vault_gate;
pub mod view;

/// The module's state: the core, the fleet module it is built on, and what
/// hive owns.
#[derive(Clone)]
pub struct HiveState {
    pub core: Core,
    /// `hive → fleet`: the Hub and the agent rows.
    pub fleet: FleetState,
    /// `hive → chat` (P0d): a session is a room, and its turns are messages
    /// in it, written through chat so chat keeps its own invariants.
    /// Stateless, so re-created here rather than taken as a dependency.
    pub chat: BoundChat,
    pub sessions: Arc<dao::AgentSessionDao>,
    /// P1a-2 — every approval a session asked a driver for.
    pub approvals: Arc<dao::AgentApprovalDao>,
    pub audit: Arc<dao::HiveAuditDao>,
    /// Start requests waiting for their device's answer (pod-local).
    pub start_acks: Arc<acks::StartAcks>,
    /// The per-(user, device) start ceiling.
    pub start_limiter: Arc<RateLimiter>,
    /// P0d-2 — the view grants this pod minted (pod-local).
    pub view_grants: Arc<view::ViewGrants>,
    /// The per-(user, session) view-open ceiling.
    pub view_limiter: Arc<RateLimiter>,
    /// P1j — the per-device adopt-offer ceiling.
    pub adopt_limiter: Arc<RateLimiter>,
    /// P1e — core memory: facts, budgets, revisions, session snapshots.
    pub brain: Arc<brain::BrainDao>,
    /// P1g — the organizations agent sessions serve (`hive.tenants`).
    pub scope: Arc<scope::TenantScope>,
    /// P2c-2a — the organizations' replica policies.
    pub policies: Arc<policy::PolicyDao>,
    /// P2d — the replica stream grants this pod minted (pod-local).
    pub stream_grants: Arc<stream::StreamGrants>,
    /// The per-(member, session) want ceiling.
    pub stream_limiter: Arc<RateLimiter>,
    /// P2c — the replicaset's server switch (`hive.replicaset`, default off).
    pub replicaset: bool,
    /// P2e-3 — the promote routes waiting for a member's prepare answer
    /// (pod-local).
    pub prepare_acks: Arc<promote::PrepareAcks>,
    /// P2e-3 — how long each step of a promotion may take.
    pub promote_bounds: promote::Bounds,
    /// P2f-2b — a teleport's prepare tells its target it may take the
    /// workspace against what its clone holds (`hive.teleport_have_want`,
    /// default off).
    pub teleport_have_want: bool,
    /// P2f-3 — how long a fork waits for its device's copy to reach the
    /// session's last checkpoint (`hive.fork_copy_secs`).
    pub fork_copy: std::time::Duration,
    /// P2g-2 — the purges of deleted sessions, kept until every device that
    /// held one has answered.
    pub purges: Arc<purge::PurgeDao>,
    /// P2g-3a — how often retention sweeps (`hive.retention_sweep_secs`;
    /// zero = no sweep).
    pub retention_sweep: std::time::Duration,
}

impl std::ops::Deref for HiveState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<HiveState> for Core {
    fn from_ref(state: &HiveState) -> Self {
        state.core.clone()
    }
}

impl Module for HiveState {
    const ID: &'static str = "hive";

    /// The Hub is one live object, so `fleet` is the dependency. Chat is
    /// stateless and re-created ([`BoundChat::new`], FR-69 rule 5).
    type Deps = FleetState;

    async fn init(core: Core, settings: &Settings, fleet: FleetState) -> anyhow::Result<Self> {
        let db = &core.db;
        let scope = scope::TenantScope::parse(&settings.hive.tenants);
        scope.log();
        let state = Self {
            sessions: Arc::new(dao::AgentSessionDao::new(db)),
            approvals: Arc::new(dao::AgentApprovalDao::new(db)),
            audit: Arc::new(dao::HiveAuditDao::new(db)),
            start_acks: Arc::new(acks::StartAcks::new()),
            start_limiter: Arc::new(RateLimiter::new()),
            view_grants: Arc::new(view::ViewGrants::new()),
            view_limiter: Arc::new(RateLimiter::new()),
            adopt_limiter: Arc::new(RateLimiter::new()),
            brain: Arc::new(brain::BrainDao::new(db)),
            scope: Arc::new(scope),
            policies: Arc::new(policy::PolicyDao::new(db)),
            stream_grants: Arc::new(stream::StreamGrants::new()),
            stream_limiter: Arc::new(RateLimiter::new()),
            replicaset: settings.hive.replicaset,
            prepare_acks: Arc::new(promote::PrepareAcks::new()),
            promote_bounds: promote::Bounds::of(&settings.hive),
            teleport_have_want: settings.hive.teleport_have_want,
            fork_copy: std::time::Duration::from_secs(settings.hive.fork_copy_secs),
            purges: Arc::new(purge::PurgeDao::new(db)),
            retention_sweep: std::time::Duration::from_secs(settings.hive.retention_sweep_secs),
            chat: BoundChat::new(&core),
            fleet,
            core,
        };
        // The agent socket is fleet's; the device's `rc:hive.*` answers are
        // dispatched here by `ClientMsg::namespace()`, and every connection's
        // hello runs this module's reconcile.
        let socket = Arc::new(agent_socket::HiveAgentSocket::new(state.clone()));
        state.core.agent_socket.register(
            Self::ID,
            AgentSocketHooks {
                handler: Some(socket.clone()),
                lifecycle: Some(socket),
            },
        );
        // P2g-3a — what retention no longer keeps, purged: one pod a cycle.
        retention::spawn(state.clone());
        Ok(state)
    }

    /// P1g — the module switch, or a `hive.tenants` list.
    fn enabled(settings: &Settings) -> bool {
        settings.hive_on()
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        Capabilities::enabled(Self::ID)
    }

    fn routes(&self) -> Router {
        let session = Router::new()
            .route("/", get(routes::list).post(routes::start))
            // P2g-2 — its owner deletes it from every device that held it.
            .route("/{session_id}", get(routes::get_one).delete(purge::purge))
            .route("/{session_id}/purge", get(purge::get_purge))
            .route("/{session_id}/stop", post(routes::stop))
            // P2e-3 — its owner moves it to a member of its replicaset.
            .route("/{session_id}/promote", post(promote::promote))
            // P2f-1 — or to a device that holds no copy of it.
            .route("/{session_id}/teleport", post(promote::teleport))
            // P2f-3 — a new session, its own, from this one's conversation.
            .route("/{session_id}/fork", post(fork::fork))
            // P2f-4b — an ended terminal session made a managed one.
            .route("/{session_id}/manage", post(manage::manage))
            // P1c — who besides the owner takes part, and how.
            .route("/{session_id}/participant", get(participants::list))
            .route(
                "/{session_id}/participant/{user_id}",
                put(participants::set).delete(participants::remove),
            );
        // P1e — core memory, the facts people keep for the org's sessions.
        let brain = Router::new()
            .route("/", get(brain::list).post(brain::create))
            .route("/{fact_id}", put(brain::edit).delete(brain::archive));
        Router::new()
            // P1g — whether agent sessions serve this organization.
            .route("/tenant/{tenant_id}/hive", get(routes::serves))
            // P2c-2a — where the organization's sessions are copied.
            .route(
                "/tenant/{tenant_id}/hive/policy",
                get(policy::get_policy).put(policy::put_policy),
            )
            .nest("/tenant/{tenant_id}/hive/session", session)
            .nest("/tenant/{tenant_id}/hive/brain", brain)
            .with_state(self.clone())
    }

    /// P0d-2 — the viewer peer's signalling on the user socket
    /// (`hive:view.*`, [`view`]).
    fn ws(&self) -> WsRegistration {
        WsRegistration {
            handlers: vec![WsHandlerSpec {
                role: Role::User,
                namespace: "hive",
                handler: Arc::new(view::HiveView {
                    state: self.clone(),
                }),
            }],
            upgrades: Vec::new(),
        }
    }

    fn indexes(&self) -> Vec<IndexSet> {
        vec![
            IndexSet {
                collection: model::AgentSession::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    // The caller's own sessions, newest first.
                    index(bson::doc! { "tenant_id": 1, "owner_id": 1, "created_at": -1 }),
                    // A device's sessions: reconcile-on-connect, device removal.
                    index(bson::doc! { "tenant_id": 1, "location.device_id": 1, "status": 1 }),
                    // An org's live sessions: archive.
                    index(bson::doc! { "tenant_id": 1, "status": 1 }),
                ],
            },
            // P1a-2 — approvals: one record per (session, approval), so a
            // replayed frame posts no second stub; 90 days, like the audit.
            IndexSet {
                collection: model::AgentApproval::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "session_id": 1, "approval_id": 1 }),
                    index(bson::doc! { "tenant_id": 1, "requested_at": -1 }),
                    index_ttl(bson::doc! { "requested_at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // The server's decisions — 90-day retention, like the exec and
            // SSH audits.
            IndexSet {
                collection: model::HiveAuditEvent::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "session_id": 1, "at": 1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // P2c-2a — one replica policy per organization: the unique index
            // arbitrates two first writes.
            IndexSet {
                collection: policy::HivePolicy::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index_unique(bson::doc! { "tenant_id": 1 })],
            },
            // P1e — a scope instance's facts, in the order they render.
            IndexSet {
                collection: brain::BrainFact::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index(bson::doc! {
                    "tenant_id": 1, "scope": 1, "owner_id": 1, "status": 1, "created_at": 1
                })],
            },
            // P1e — ONE spend counter per scope instance: the unique index is
            // what turns a write that does not fit into a refusal.
            IndexSet {
                collection: brain::BrainBudget::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index_unique(
                    bson::doc! { "tenant_id": 1, "scope": 1, "owner_id": 1 },
                )],
            },
            // P1e — a session's snapshot, kept for its start's re-send.
            IndexSet {
                collection: brain::SessionMemory::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index_ttl(
                    bson::doc! { "created_at": 1 },
                    brain::SessionMemory::TTL_SECS,
                )],
            },
            // P2g-2 — the purges: what a device that connects has still to
            // answer, the owner's read of one, and a completed one's 90
            // days. A purge still pending has no `done_at`, so it never
            // expires.
            IndexSet {
                collection: model::HivePurge::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "devices.device_id": 1, "done_at": 1 }),
                    index(bson::doc! { "tenant_id": 1, "session_id": 1, "owner_id": 1 }),
                    index_ttl(bson::doc! { "done_at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
        ]
    }

    fn hooks(&self) -> Hooks {
        let h = hooks::HiveHooks::new(self.clone());
        Hooks {
            tenant: Some(h.clone()),
            fleet: Some(h),
            session: None,
        }
    }
}
