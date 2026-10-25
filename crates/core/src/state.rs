// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-69 P1 — the server core, split out of the api crate's `AppState`.
//!
//! `Core` holds the 27 fields every pillar needs and no pillar owns: identity
//! and tenancy (users, tenants, roles, invites, auth), notifications and
//! their channels (email, push, OAuth), storage, the `/ws` socket registry and
//! its Redis fan-out, the cluster identity/directory/bus, TURN credentials
//! and relay load, the metering sink, and the background-task service.
//! The host's `AppState` keeps a `Core` as its first field and **derefs to
//! it**, so every `state.settings` / `state.users` / `state.db` in the tree
//! reads exactly as before — the split changes ownership, not call sites.
//!
//! The handler-side seam is `State<Core>`: a handler that needs only the
//! core takes it instead of the host state, which is what the module crates
//! take from P2 on. The `FromRef<AppState> for Core` impl that makes the
//! extractor work while the router's state is still `AppState` lives in the
//! api crate (the orphan rules put it next to `AppState`); this crate never
//! learns that type exists.
//!
//! P1a introduced the split inside the api crate; P1b moved the type here
//! unchanged, together with the modules that hold its fields
//! ([`crate::ws`], [`crate::cluster`], [`crate::storage`],
//! [`crate::user_analytics`], [`crate::rate_limit`], [`crate::relay_load`]).

use std::{collections::HashSet, sync::Arc};

use bson::oid::ObjectId;
use mongodb::Database;
use roomler_ai_config::Settings;
use roomler_ai_remote_control::turn_creds::{RelayLoadMap, TurnMap};
use roomler_ai_services::{
    AuthService, EmailService, OAuthService, PushService, TaskService,
    dao::{
        activation_code::ActivationCodeDao, invite::InviteDao, notification::NotificationDao,
        push_subscription::PushSubscriptionDao, role::RoleDao, stats::StatsDao, tenant::TenantDao,
        used_token::UsedTokenDao, user::UserDao,
    },
};

use crate::{
    cluster::{bus::PodBus, directory::OwnershipDirectory, identity::PodIdentity},
    storage::FileStorage,
    user_analytics::GeoIp,
    ws::{redis_pubsub::RedisPubSub, storage::WsStorage},
};

/// The server-wide services every module builds on. See the module docs.
#[derive(Clone)]
pub struct Core {
    pub db: Database,
    pub settings: Settings,
    pub auth: Arc<AuthService>,
    pub users: Arc<UserDao>,
    pub activation_codes: Arc<ActivationCodeDao>,
    pub tenants: Arc<TenantDao>,
    pub invites: Arc<InviteDao>,
    pub roles: Arc<RoleDao>,
    pub notifications: Arc<NotificationDao>,
    pub oauth: Option<Arc<OAuthService>>,
    pub email: Option<Arc<EmailService>>,
    pub push: Option<Arc<PushService>>,
    pub push_subscriptions: Arc<PushSubscriptionDao>,
    /// Single-use ledger for enrollment-token jtis. See
    /// [`roomler_ai_services::dao::used_token`].
    pub used_tokens: Arc<UsedTokenDao>,
    /// Background-task service (export jobs and the like).
    pub tasks: Arc<TaskService>,

    /// The `/ws` connection registry — every role's sockets, keyed by
    /// principal and by connection id.
    pub ws_storage: Arc<WsStorage>,
    pub redis_pubsub: Option<Arc<RedisPubSub>>,
    /// True while the Redis pub/sub subscriber holds a live subscription —
    /// flipped by `RedisPubSub::subscribe_with_reconnect` (started in
    /// `AppState::new` since C-2, so TestApps exercise cross-pod delivery),
    /// read by `/health/ready`.
    pub redis_sub_alive: Arc<std::sync::atomic::AtomicBool>,
    /// File-storage backend for uploads + export artifacts (local disk or
    /// S3/MinIO, picked from `s3.enabled` at startup). See [`crate::storage`].
    pub storage: Arc<FileStorage>,

    /// Observability sample sinks (`stats_*` collections) — idempotent
    /// deterministic-`_id` upserts, so every collector is 2-pod safe.
    /// Writers gate on `settings.stats.enabled`.
    pub stats: Arc<StatsDao>,
    /// Stats PR-3 — platform-operator allowlist parsed from
    /// `ROOMLER__STATS__PLATFORM_ADMINS` (user OBJECTIDS, deliberately not
    /// emails: OAuth links accounts by bare email, so an email allowlist
    /// would turn a provider-asserted address into platform-root).
    pub platform_admins: Arc<HashSet<ObjectId>>,
    /// Wave 2 — optional country resolver for the user analytics. The
    /// client IP is resolved at connect time and DROPPED; no address is
    /// ever stored. Absent database ⇒ every session reads `unknown`.
    pub geoip: Arc<GeoIp>,
    /// MeshHarbor — the business zone each live connection on this process
    /// was observed in (`business_authority::connection_zone`).
    pub business_zones: crate::business_authority::LiveZones,

    // C-1 — cluster foundation (None without Redis; consumers fail soft).
    /// Stable pod identity + process epoch.
    pub pod: PodIdentity,
    /// Entity → owning-pod records (LWW / NX namespaces).
    pub cluster_directory: Option<OwnershipDirectory>,
    /// FR-115 P3b — the cluster-wide count of concurrent remote sessions per
    /// payer (`cluster::session_slots`). `None` without Redis, and every
    /// claim then falls back to P3's count on the hub that owns the device.
    pub session_slots: Option<crate::cluster::session_slots::SessionSlots>,
    /// Per-pod request/reply bus.
    pub cluster_bus: Option<Arc<PodBus>>,

    /// Region-keyed TURN issuance (the Hub holds its own clone). Built once at
    /// startup from `turn.*` + `relay.*` settings; `cfg_for(None)` == the
    /// legacy single-region config. Core, not remote-desktop: RC, tunnels and
    /// the mediasoup ICE servers all issue from it.
    pub turn_map: Arc<TurnMap>,
    /// P6b — live per-region load written by the `/stats` poller; consulted
    /// by the Hub (session freeze) and the overlay pair-region pick.
    pub relay_load: RelayLoadMap,
    /// FR-69 D6 — the inverse edges: every module's registered lifecycle
    /// hooks, invoked in `HOOK_ORDER` by whoever runs a cascade. Shared, so a
    /// registration made after this `Core` was cloned is visible to the clone.
    pub hooks: crate::hooks::HookRegistry,
    /// FR-69 P5c — the agent socket's seam: the message handlers and the
    /// per-connection lifecycles the modules register for `/ws?role=agent`,
    /// dispatched by `fleet` (the socket's owner) per `ClientMsg::namespace()`.
    pub agent_socket: crate::agent_socket::AgentSocketRegistry,
    /// FR-115 — this server sells plans: the hosted `saas` module is compiled
    /// in and mounted. Every plan limit binds only then. A self-hosted server
    /// (built without `saas`, as the published image and the compose build
    /// both are) holds every org to no limit at all: self-hosting is free and
    /// unlimited, and an org there is `free` only because nobody sold it
    /// anything. Set once, by the host.
    pub plans_sold: bool,
}
