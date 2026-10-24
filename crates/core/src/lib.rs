// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `roomler-core` — the server's composition contract (FR-69).
//!
//! The server is becoming a **modular monolith**: one small core plus six
//! pillar modules, each a crate behind the one [`Module`] contract defined
//! here, composed by a thin host under `#[cfg(feature)]` into named build
//! profiles. Same process, same container, same wire — what changes is where
//! code lives and what a build links. The design, every decision's trade-off
//! and the phase plan are in `docs/fr/FR-69-modular-monolith.md`.
//!
//! # What lives here
//!
//! * [`Module`] — the trait every pillar module implements: routes, WebSocket
//!   namespaces, index specs, jobs, lifecycle hooks, capabilities.
//! * [`Core`] — the server-wide services modules build on: identity and
//!   tenancy, notifications and their channels, storage, the `/ws` registry
//!   and its Redis fan-out ([`ws`]), the cluster identity/directory/bus
//!   ([`cluster`]), TURN credentials and relay load, the metering sink. P1
//!   moved it here from the api crate, with the modules that hold its fields
//!   ([`storage`], [`user_analytics`], [`rate_limit`], [`relay_load`]).
//! * [`graph`] — the module set and the allowed dependency edges, as data, with
//!   a test that keeps them a DAG.
//! * [`composition`] — the snapshot that gates every module move: the router's
//!   paths with their allowed methods, the index plan, the wire names.
//!
//! # The rules, in one place
//!
//! * **Core membership.** Something lives in core only if at least two modules
//!   need it *and* it is identity, tenancy or infrastructure. Everything else
//!   belongs to a module.
//! * **A DAG, not peers.** Any module may call core; `conference → chat`,
//!   `remote → fleet`, `network → fleet`. Core never calls a module: the inverse
//!   flows (tenant archive, agent removal) are [`hooks`] that core invokes in a
//!   fixed order ([`hooks::HOOK_ORDER`]).
//! * **Static composition.** The host composes concrete module types under
//!   feature cfgs — no `Vec<Box<dyn Module>>`, no link-time registry. A module
//!   that forgets its indexes, jobs or hooks does not compile.
//! * **The wire and the documents do not move.** One `/ws` socket with an
//!   exhaustive per-variant namespace map (P5); `/derp` unchanged; DAOs and
//!   indexes change owner, never shape.
//!
//! # Naming
//!
//! Server-side crates are `roomler-ai-*`; this crate is the one exception by
//! design, `roomler-core`. Module crates are `roomler-ai-mod-<name>`. The
//! daemon's shared building blocks are `roomler-node-core`
//! (`crates/agent-core`), which held the name `roomler-core` from FR-21 until
//! FR-69.

pub mod admission;
pub mod agent_socket;
pub mod attribution;
pub mod business_authority;
pub mod campaign;
pub mod capabilities;
pub mod client_ip;
pub mod cluster;
pub mod composition;
pub mod cookies;
pub mod error;
pub mod extractors;
pub mod graph;
pub mod growth;
pub mod guards;
pub mod hooks;
pub mod job;
pub mod module;
pub mod net;
pub mod notify;
pub mod origin;
pub mod quota;
pub mod rate_limit;
pub mod relay_load;
pub mod state;
pub mod storage;
pub mod turn;
pub mod user_analytics;
pub mod ws;

pub use agent_socket::{
    AgentCtx, AgentMsgHandler, AgentSocketHooks, AgentSocketLifecycle, AgentSocketRegistry,
};
pub use capabilities::{Capabilities, TenantCtx};
pub use error::ApiError;
pub use hooks::{
    FleetLifecycle, HookRegistry, Hooks, ReleasedLease, RenamePropagation, RoleAsk, RoleVerdict,
    SessionGate, TenantLifecycle,
};
pub use job::{Cadence, Job, JobFuture};
pub use module::Module;
pub use roomler_ai_db::indexes::{IndexOp, IndexPlan, IndexSet};
pub use state::Core;
pub use ws::{Role, UpgradeSpec, WsCtx, WsHandler, WsHandlerSpec, WsRegistration};

pub mod device_share;
