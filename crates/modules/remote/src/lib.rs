// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `remote` — remote desktop as a module (FR-69 P6): what a CONTROLLER
//! reaches. The session routes (get / terminate / audit), TURN credentials
//! and the relay-region listing; the `rc:*` dispatch a browser tab drives
//! with its authz + consent-mode gate; the cross-pod RC relay (PR-2); and
//! the agent-side session-stats merge.
//!
//! The session state machine itself is NOT here: the Hub is the fleet
//! module's (its consumers span fleet, remote and network), and this crate
//! is built ON fleet — the first module whose [`Module::Deps`] is another
//! module's state, because the Hub is one live object and a module that
//! re-created it would dispatch into an empty registry. `remote → fleet` is
//! the graph edge; nothing here names the host.
//!
//! # What the host keeps
//!
//! The user socket: its upgrade, the Hub registration of the controller's
//! sender and the pump. It hands each `rc:*` text frame to
//! [`controller::handle_controller_frame`] WITH that sender (through the
//! host's `Modules::remote_controller_frame`), and forwards a closed
//! connection to [`relay::forward_conn_closed`]. A namespace handler could
//! not carry the sender, which is why the controller path is a call the host
//! makes rather than a `Module::ws` registration.

use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, FromRef},
    routing::{get, post, put},
};
use meshharbor_config::Settings;
use meshharbor_core::{
    AgentSocketHooks, Capabilities, Core, Module, TenantCtx, rate_limit::RateLimiter,
};
use meshharbor_db::indexes::{IndexSet, index, index_ttl, index_unique};
use meshharbor_mod_fleet::FleetState;
use meshharbor_remote_control::models::{
    SessionFeedback, SessionFeedbackRequest, TouchPreset, TouchPresetRequest,
};
use meshharbor_services::dao::{
    privacy_activity::PrivacyActivityDao, recording_activity::RecordingActivityDao,
    remote_audit::RemoteAuditDao, remote_session::RemoteSessionDao,
    session_feedback::SessionFeedbackDao, touch_preset::TouchPresetDao,
    transfer_activity::TransferActivityDao,
};

pub mod agent_socket;
pub mod controller;
/// FR-130 P1b-2 — `POST /api/admin/rc-sessions/close-dead`, the one-time
/// close of the session rows a pod that died before FR-130 left open.
pub mod dead_rows;
pub mod device_share;
pub mod extauth;
/// FR-130 P1b-2 — `rc:session.rejoin`, the viewer's claim on a session held
/// for it, answered on the pod its socket reached.
pub mod rejoin;
pub mod relay;
/// FR-130 — the answer to a device's claim on the sessions it kept, and the
/// registration read.
pub mod resume;
pub mod routes;
/// FR-130 P1b-2 — an end someone asked for, of a session no hub on this pod
/// holds, written to its row.
pub mod row_end;
pub mod session_policy;
pub mod slots;
/// FR-130 P1b-2 — the sweep: the rows nobody will ever claim, ended at their
/// own last clock, one pod at a time.
pub mod sweep;
pub mod touch_presets;

/// The module's state: the core, the fleet module it is built on, and what
/// remote owns.
#[derive(Clone)]
pub struct RemoteState {
    pub core: Core,
    /// `remote → fleet`: the Hub, the agent rows, the nudge machinery.
    pub fleet: FleetState,
    pub remote_sessions: Arc<RemoteSessionDao>,
    pub remote_audit: Arc<RemoteAuditDao>,
    /// FR-85 P3 — what devices report about remote recordings (the host's
    /// claims; the server's grant decision stays in `remote_audit`).
    pub recording_activity: Arc<RecordingActivityDao>,
    /// FR-101 P3 — the clipboard and file traffic devices report (again the
    /// host's claims, beside the `CLIPBOARD` / `FILES` grant in
    /// `remote_audit`).
    pub transfer_activity: Arc<TransferActivityDao>,
    /// FR-99 P1d — what devices report about privacy mode: the curtain up,
    /// down and why (the host's claims, beside the `PRIVACY` grant in
    /// `remote_audit`).
    pub privacy_activity: Arc<PrivacyActivityDao>,
    /// FR-102 P9b — the ratings people give a session from the viewer: a
    /// thumb and reason codes, one per session, never text.
    pub session_feedback: Arc<SessionFeedbackDao>,
    /// FR-111 P4a — the org's on-screen control presets, which every
    /// member's viewer offers beside the built-ins.
    pub touch_presets: Arc<TouchPresetDao>,
    /// FR-101 P4a — the per-(caller, device) ceiling on session requests,
    /// checked after the authz gate (`controller::SESSION_REQUESTS_PER_MINUTE`).
    pub session_request_limiter: Arc<RateLimiter>,
    pub(crate) shared_scopes: Arc<dashmap::DashMap<bson::oid::ObjectId, device_share::ShareScope>>,
    pub(crate) shared_lease_limiter: Arc<RateLimiter>,
    /// PR-2 relay — owner-side proxy controllers for cross-pod rc sessions,
    /// keyed by the ORIGIN connection id. See [`relay`].
    pub rc_proxy_controllers: Arc<relay::ProxyControllers>,
    /// PR-2 relay — controller-side: conn id → owner pods hosting its
    /// proxied rc sessions (a WS close forwards `rc.conn_closed` there;
    /// mirrors conference's `remote_media_conns`).
    pub remote_rc_conns: Arc<relay::RemoteRcConns>,
    /// FR-52 P3c — the external-access login relay: attempts in flight and
    /// the waiters for the device's answers. Pod-local, like the Hub it
    /// relays through. See [`extauth`].
    pub extauth: Arc<extauth::ExtauthRelay>,
    /// FR-130 P1b-2 — per agent connection, the sessions its registration
    /// ended without seeing their end, so the device's own end of one
    /// replaces the inferred reason (`resume::device_end`).
    pub registration_ends: Arc<resume::RegistrationEnds>,
    /// FR-130 P1b-2 (review 2, N7) — where this pod's sweep reads the quiet
    /// rows on from (`sweep::Cursor`).
    pub sweep_cursor: Arc<sweep::Cursor>,
    /// FR-130 (review 2, N14) — how many times this pod has run the resume
    /// gate (`controller::resume_gate`). The integration tests' counting
    /// seam for the rejoin's rate limit; nothing reads it in production.
    #[doc(hidden)]
    pub resume_gate_runs: Arc<std::sync::atomic::AtomicU64>,
    /// FR-130 (review 2, N14) — when each viewer last ran the resume gate
    /// for a session no hub on this pod holds (`rejoin::gate_due`): its
    /// rejoin runs the gate at most once per 5 s per session and viewer, and
    /// always before a bind or a relay.
    pub rejoin_gates: Arc<rejoin::GateRuns>,
}

impl std::ops::Deref for RemoteState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<RemoteState> for Core {
    fn from_ref(state: &RemoteState) -> Self {
        state.core.clone()
    }
}

impl Module for RemoteState {
    const ID: &'static str = "remote";

    type Deps = FleetState;

    async fn init(core: Core, _settings: &Settings, fleet: FleetState) -> anyhow::Result<Self> {
        let db = &core.db;
        let state = Self {
            remote_sessions: Arc::new(RemoteSessionDao::new(db)),
            remote_audit: Arc::new(RemoteAuditDao::new(db)),
            recording_activity: Arc::new(RecordingActivityDao::new(db)),
            transfer_activity: Arc::new(TransferActivityDao::new(db)),
            privacy_activity: Arc::new(PrivacyActivityDao::new(db)),
            session_feedback: Arc::new(SessionFeedbackDao::new(db)),
            touch_presets: Arc::new(TouchPresetDao::new(db)),
            session_request_limiter: Arc::new(RateLimiter::new()),
            shared_scopes: Arc::new(dashmap::DashMap::new()),
            shared_lease_limiter: Arc::new(RateLimiter::new()),
            rc_proxy_controllers: Arc::new(relay::ProxyControllers::new()),
            remote_rc_conns: Arc::new(relay::RemoteRcConns::new()),
            extauth: Arc::new(extauth::ExtauthRelay::new()),
            registration_ends: Arc::new(resume::RegistrationEnds::new()),
            sweep_cursor: Arc::new(sweep::Cursor::default()),
            resume_gate_runs: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            rejoin_gates: Arc::new(rejoin::GateRuns::new()),
            fleet,
            core,
        };
        // PR-2 — the cross-pod rc signalling relay: owner-side rc.cmd /
        // rc.conn_closed / rc.conn_alive + the proxy janitor sweep.
        relay::wire_rc_relay(&state);
        // FR-130 P1b-2 — the sweep of the session rows nobody will claim, and
        // the answer the dead-row close asks of the pod that holds a device's
        // socket: does your hub hold this session?
        sweep::spawn(state.clone());
        dead_rows::wire_session_held(&state);
        // The agent socket is fleet's; this module's arm (the session-stats
        // merge) is dispatched to it by `ClientMsg::namespace()` (P5c).
        // FR-130 — and its lifecycle answers a hello's claims on the sessions
        // the device kept, and ends what earlier connections left open.
        state.core.agent_socket.register(
            Self::ID,
            AgentSocketHooks {
                handler: Some(Arc::new(agent_socket::RemoteAgentSocket::new(
                    state.clone(),
                ))),
                lifecycle: Some(Arc::new(agent_socket::RemoteAgentLifecycle::new(
                    state.clone(),
                ))),
            },
        );
        Ok(state)
    }

    fn enabled(settings: &Settings) -> bool {
        settings.modules.remote
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        Capabilities::enabled(Self::ID)
    }

    /// Exactly the paths the host mounted before P6.
    fn routes(&self) -> Router {
        // Remote-control session routes (tenant-scoped).
        let session = Router::new()
            .route("/{session_id}", get(routes::get_session))
            .route("/{session_id}/terminate", post(routes::terminate_session))
            .route("/{session_id}/audit", get(routes::session_audit))
            // FR-102 P9b — the viewer's post-session rating: a thumb and
            // reason codes from a person who was in the session; the empty
            // 404 while `growth.feedback` is off.
            .route(
                "/{session_id}/feedback",
                post(routes::session_feedback).layer(DefaultBodyLimit::max(
                    SessionFeedbackRequest::MAX_BODY_BYTES,
                )),
            );
        // TURN credentials (user-scoped, no tenant prefix).
        let turn = Router::new().route("/credentials", get(routes::turn_credentials));
        // Multi-region relay PoP topology (user-scoped, read-only, no secrets).
        let relay = Router::new().route("/regions", get(routes::relay_regions));
        // FR-85 P3 — what devices reported about remote recordings (read with
        // the session audit, under the same permission).
        let recording = Router::new().route("/{agent_id}", get(routes::recording_activity));
        // FR-101 P3 — the clipboard and file traffic devices reported, read
        // the same way.
        let transfers = Router::new().route("/{agent_id}", get(routes::transfer_activity));
        // FR-99 P1d — what devices reported about privacy mode, read the same
        // way.
        let privacy = Router::new().route("/{agent_id}", get(routes::privacy_activity));

        Router::new()
            .route(
                "/device-shares/{share_id}/remote",
                get(device_share::device),
            )
            // FR-130 P1b-2 — a platform operator's one-time close of the
            // rows a pod that died before FR-130 left open: a dry run unless
            // the body says otherwise.
            .route("/admin/rc-sessions/close-dead", post(dead_rows::close_dead))
            .nest("/tenant/{tenant_id}/session", session)
            .nest("/tenant/{tenant_id}/recording-activity", recording)
            .nest("/tenant/{tenant_id}/transfer-activity", transfers)
            .nest("/tenant/{tenant_id}/privacy-activity", privacy)
            // FR-101 P2a — the org's session policy (clipboard, files, audio):
            // GET for any member, PUT with MANAGE_TENANT.
            .route(
                "/tenant/{tenant_id}/rc-session-policy",
                get(session_policy::get_policy).put(session_policy::set_policy),
            )
            // FR-101 P4b — the org's session limits (the maximum length):
            // GET for any member, PUT with MANAGE_TENANT.
            .route(
                "/tenant/{tenant_id}/rc-session-limits",
                get(session_policy::get_limits).put(session_policy::set_limits),
            )
            // FR-111 P4a — the org's on-screen control presets: GET for any
            // member, writes with MANAGE_TENANT, a preset resolved within the
            // tenant, the body read strictly and capped.
            .route(
                "/tenant/{tenant_id}/touch-preset",
                get(touch_presets::list)
                    .post(touch_presets::create)
                    .layer(DefaultBodyLimit::max(TouchPresetRequest::MAX_BODY_BYTES)),
            )
            .route(
                "/tenant/{tenant_id}/touch-preset/{preset_id}",
                put(touch_presets::update)
                    .delete(touch_presets::delete)
                    .layer(DefaultBodyLimit::max(TouchPresetRequest::MAX_BODY_BYTES)),
            )
            .nest("/turn", turn)
            .nest("/relay", relay)
            .with_state(self.clone())
    }

    /// The collections this module owns. The first two are the specs the db
    /// crate's plan held before P6, unchanged — `remote_sessions` has two
    /// sets there (the session indexes, then the Wave-3 per-tenant usage
    /// read), in that order. `recording_activity` is FR-85 P3's,
    /// `transfer_activity` FR-101 P3's, `privacy_activity` FR-99 P1d's,
    /// `session_feedback` FR-102 P9b's, `touch_presets` FR-111 P4a's.
    fn indexes(&self) -> Vec<IndexSet> {
        vec![
            IndexSet {
                collection: "remote_sessions",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "agent_id": 1, "created_at": -1 }),
                    index(bson::doc! { "controller_user_id": 1, "created_at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "phase": 1 }),
                    // 25-month retention from `created_at` — the privacy
                    // policy's §7 (see `RemoteSession::TTL_SECONDS`).
                    index_ttl(
                        bson::doc! { "created_at": 1 },
                        meshharbor_remote_control::models::RemoteSession::TTL_SECONDS,
                    ),
                ],
            },
            // Remote-control audit log — 90-day retention.
            IndexSet {
                collection: "remote_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "session_id": 1, "at": 1 }),
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // Wave 3 — per-user usage reads scan sessions by (tenant, time).
            IndexSet {
                collection: "remote_sessions",
                pre_ops: Vec::new(),
                indexes: vec![index(bson::doc! { "tenant_id": 1, "created_at": -1 })],
            },
            // FR-130 P1b-2 (P1b-1's review, L3) — the registration read: a
            // device's live rows, oldest first, at each registration of a device
            // announced a window. Without it the read walked the device's whole
            // history, for every device of a roll. Part two — every live row
            // by age, for the sweep and the dead-row close: only live sessions
            // and the rows a dead pod left are Active, so the phase bounds the
            // read.
            IndexSet {
                collection: "remote_sessions",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "agent_id": 1, "phase": 1, "created_at": 1 }),
                    index(bson::doc! { "phase": 1, "created_at": 1 }),
                ],
            },
            // FR-85 P3 — remote-recording activity the devices report (a
            // claim, beside `remote_audit`'s decision) — 90-day retention,
            // like the audit it is read with.
            IndexSet {
                collection: "recording_activity",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "session_id": 1, "at": 1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // FR-102 P9b — one rating per session PER PERSON: a rating is one
            // person's experience (the controller and a watcher of the same
            // session may sit on different networks), so the unique index is
            // `(session_id, user_id)` — the arbiter between two posts by one
            // person, never between two people. Read per org over time by the
            // digest, purged per user with the account; kept 25 months (§3p).
            IndexSet {
                collection: "session_feedback",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "session_id": 1, "user_id": 1 }),
                    index(bson::doc! { "tenant_id": 1, "ts": -1 }),
                    index(bson::doc! { "user_id": 1 }),
                    index_ttl(bson::doc! { "ts": 1 }, SessionFeedback::TTL_SECONDS),
                ],
            },
            // FR-101 P3 — clipboard and file traffic the devices report (a
            // claim, like `recording_activity`) — 90-day retention, like the
            // audit it is read with.
            IndexSet {
                collection: "transfer_activity",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "session_id": 1, "at": 1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // FR-99 P1d — privacy mode as the devices report it (a claim, like
            // `recording_activity`) — 90-day retention, like the audit it is
            // read with.
            IndexSet {
                collection: "privacy_activity",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "session_id": 1, "at": 1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // FR-111 P4a — the org's on-screen control presets: a name is
            // unique per org (the index arbitrates two admins saving one name
            // at once), and the listing reads by tenant in name order, which
            // this index serves too.
            IndexSet {
                collection: TouchPreset::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index_unique(bson::doc! { "tenant_id": 1, "name": 1 })],
            },
        ]
    }
}
