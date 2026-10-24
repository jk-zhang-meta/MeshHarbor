// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `fleet` — device management as a module (FR-69 P5a): agents, enrollment
//! tokens and keys, presence and its tokens, the agent Hub, crash and log
//! ingest, releases and installer proxies, owner consent, remote config, and
//! fleet RPC (exec) with its audit.
//!
//! The Hub came here from `roomler-ai-remote-control` — its consumers are
//! fleet's (the agent socket, presence, exec, consent, org join, forced
//! updates) and `remote`/`network` reach it through this crate, which is the
//! direction the module graph allows (`remote → fleet`, `network → fleet`).
//! The wire crate is wire-only for the server now.
//!
//! # What stays in the host for one more step
//!
//! The agent SOCKET (`ws/remote_control.rs::handle_agent_socket`) and the
//! controller-side `rc:*` dispatch are still the host's: its `rc:*` arms
//! call into overlay, tunnel and org-relay code that has not moved yet, and
//! a socket cannot dispatch to a module it cannot name. P5b moves the socket
//! here behind a core-owned handler registry. Until then the host keeps
//! `Arc` ALIASES of the handles below on `AppState` (`rc_hub`, `agents`, the
//! presence maps…), initialised FROM this module, so every host call site
//! reads as before and the object has one owner.
//!
//! # First use of the hooks
//!
//! Removing an agent releases its overlay lease first — `network`'s, which
//! fleet cannot call. [`removal::remove_agent_device`] runs the holders
//! through [`roomler_core::hooks::HookRegistry`] in `HOOK_ORDER` and then
//! deletes the row and kicks the socket; renaming an agent propagates the
//! MagicDNS label the same way. The host registers its transitional
//! implementation of those hooks under the `network` id.

use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, FromRef},
    routing::{delete, get, post, put},
};
use bson::oid::ObjectId;
use dashmap::DashMap;
use roomler_ai_config::Settings;
use roomler_ai_db::indexes::{
    IndexSet, index, index_text, index_ttl, index_unique, index_unique_partial,
};
use roomler_ai_remote_control::{audit::AuditSink, models::AgentStatus};
use roomler_ai_services::dao::{
    agent::AgentDao, agent_crash::AgentCrashDao, agent_log::AgentLogDao,
    config_audit::ConfigAuditDao, consent_request::ConsentRequestDao,
    enroll_token_issued::EnrollTokenIssuedDao, enrollment_key::EnrollmentKeyDao,
    exec_audit::ExecAuditDao, exec_pending::ExecPendingDao, external_rc_audit::ExternalRcAuditDao,
    keep_busy_event::KeepBusyEventDao, setup_diagnostics::SetupDiagnosticsDao,
};
use roomler_core::{Capabilities, Core, Module, TenantCtx, rate_limit::RateLimiter};
use tokio::sync::mpsc;

pub mod agent;
pub mod agent_crash;
pub mod agent_exec;
pub mod agent_log;
pub mod agent_org;
pub mod agent_release;
pub mod auth_agent;
pub mod consent;
pub mod consent_consumer;
pub mod ctrl;
pub mod enroll_key;
pub mod exec_service;
pub mod external_access;
pub mod hub;
pub mod install_trace;
pub mod keep_busy;
pub mod nudge;
pub mod presence;
mod release_delivery;
pub mod releases;
pub mod remote_config;
pub mod removal;
pub mod setup_diagnostics;
pub mod setup_release;
pub mod socket;
pub mod tenant_hooks;
pub mod tunnel_release;

pub use hub::Hub;

/// The module's state: the core plus what fleet owns.
#[derive(Clone)]
pub struct FleetState {
    pub core: Core,
    pub agents: Arc<AgentDao>,
    /// FR-51 P2 — reusable ephemeral enrollment keys + their per-use audit.
    pub enrollment_keys: Arc<EnrollmentKeyDao>,
    /// FR-102 P3 — one row per standard enrollment token minted, by jti,
    /// marked when it is redeemed: "tokens issued → redeemed" in the digest.
    /// An id ledger; the token itself is never stored.
    pub enroll_tokens: Arc<EnrollTokenIssuedDao>,
    /// FR-102 P3b — the setup wizard's opt-in step diagnostics, one row per
    /// boundary a ticked run reported; written by `POST /api/setup/diagnostics`
    /// only. No address, no User-Agent, no person: a random run id and codes.
    pub setup_diagnostics: Arc<SetupDiagnosticsDao>,
    pub agent_crashes: Arc<AgentCrashDao>,
    pub agent_logs: Arc<AgentLogDao>,
    /// Phase 4 — owner-side consent requests (email/push approve-link tokens).
    pub consent_requests: Arc<ConsentRequestDao>,
    /// Fleet-RPC attempt log — every exec, allowed or denied.
    pub exec_audit: Arc<ExecAuditDao>,
    /// FR-94 — commands waiting for a Windows device's SYSTEM service to
    /// claim them, and the results it posts back. Shared through Mongo: the
    /// service's calls can land on any pod.
    pub exec_pending: Arc<ExecPendingDao>,
    /// FR-52 — cross-org access decisions: who opened a device to
    /// outsiders, and every refusal. The server's own record, never the
    /// session's.
    pub external_rc_audit: Arc<ExternalRcAuditDao>,
    /// Remote-config decisions (`docs/remote-config.md`): what was ASKED for
    /// on a device, granted or refused — never what the device did.
    pub config_audit: Arc<ConfigAuditDao>,
    /// FR-92 P7 — the permanent keep-busy history: the server's own policy
    /// changes and the devices' reported ons and offs, told apart by
    /// `source`. No TTL (operator, 2026-10-11).
    pub keep_busy_events: Arc<KeepBusyEventDao>,
    pub rc_hub: Arc<Hub>,
    /// Phase A-1 — the Redis presence owner-token per locally-registered
    /// agent WS. Written/removed by the agent socket; read by the shutdown
    /// sweep so it can compare-DEL each key (an unconditional DEL could erase
    /// a claim an agent already re-made on the surviving pod mid-roll).
    pub agent_presence_tokens: Arc<DashMap<ObjectId, String>>,
    /// P4 — per-tenant `device:presence` batching + member-list cache.
    pub presence_fanout: Arc<presence::PresenceFanout>,
    /// PR-1 rehome — owner-side per-agent nudge pacing (cooldown trio).
    pub agent_nudge_cooldowns: Arc<nudge::NudgeCooldowns>,
    /// PR-1 rehome — requester-side per-agent throttle for `rc.agent_nudge`
    /// RPCs (click storms sent 11 in 15 s pre-PR-1).
    pub agent_nudge_throttle: Arc<nudge::NudgeRequestThrottle>,
    /// The per-(caller, device) exec ceiling (`rate_limit.rs`).
    pub exec_rate_limiter: Arc<RateLimiter>,
    /// The GitHub-releases cache behind every installer and latest-release
    /// proxy; busted fleet-wide over the bus by `POST /api/releases/refresh`.
    pub releases_cache: Arc<releases::ReleasesCache>,
    /// FR-102 P3c — `growth.internal_networks`, parsed once at boot: a fetch
    /// from inside is counted as `internal` (`install_trace::count_fetch`).
    pub internal_networks: Arc<roomler_core::growth::InternalNetworks>,
}

impl std::ops::Deref for FleetState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<FleetState> for Core {
    fn from_ref(state: &FleetState) -> Self {
        state.core.clone()
    }
}

/// FR-102 P3c — `growth.internal_networks`, parsed once. An entry it cannot
/// use (not an address, host bits set, a prefix too short to be one network)
/// is echoed in a warning here, once, with its reason, so the operator can fix
/// it, and skipped; the rest still apply. The networks in effect are logged
/// as CIDRs, so a widened or missing range is visible at boot rather than as
/// a quiet shift in the counts.
fn internal_networks_from(settings: &Settings) -> roomler_core::growth::InternalNetworks {
    let (nets, refused) =
        roomler_core::growth::InternalNetworks::parse(&settings.growth.internal_networks);
    if !refused.is_empty() {
        tracing::warn!(
            refused = ?refused,
            "growth.internal_networks: skipping entries it cannot use, each with its reason; the rest still apply"
        );
    }
    if !nets.is_empty() {
        tracing::info!(
            networks = ?nets.networks(),
            "install trace: fetches from these internal networks count as `internal`"
        );
    }
    nets
}

impl Module for FleetState {
    const ID: &'static str = "fleet";

    type Deps = ();

    async fn init(core: Core, settings: &Settings, _deps: ()) -> anyhow::Result<Self> {
        let db = &core.db;
        let agents = Arc::new(AgentDao::new(db));
        let enrollment_keys = Arc::new(EnrollmentKeyDao::new(db));
        let consent_requests = Arc::new(ConsentRequestDao::new(db));

        let (audit_sink, _audit_handle) = AuditSink::spawn(core.db.clone());
        // Phase 4 — owner-side consent: the Hub emits a `ConsentEvent` for each
        // Email/Push session; the consumer resolves the owner + persists a
        // `ConsentRequest` + sends the email / web-push. Wiring `Some(consent_tx)`
        // is what turns those modes on; with `None` (tests) they'd just time out.
        let (consent_tx, consent_rx) = mpsc::channel::<hub::ConsentEvent>(64);
        let rc_hub = Arc::new(Hub::new_with_consent(
            audit_sink,
            (*core.turn_map).clone(),
            Some(consent_tx),
            core.relay_load.clone(),
        ));
        // FR-115 P3b — the hub keeps its sessions' slots: renews this pod's
        // leases every round, and gives a slot back when its session ends.
        // Empty until `rc.session_slots` has a caller claim one.
        if let Some(slots) = core.session_slots.clone() {
            rc_hub.set_session_slots(slots.clone());
            let hub = rc_hub.clone();
            let pod_id = core.pod.pod_id.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                    roomler_core::cluster::session_slots::SLOT_RENEW_SECS,
                ));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    let leases = hub.slot_leases();
                    match slots.renew(&leases).await {
                        // A lease Redis no longer had: put it back only for a
                        // session this hub still holds (a Redis restart), never
                        // for one released while the round was in flight.
                        Ok(missing) => {
                            let live: Vec<_> = missing
                                .into_iter()
                                .filter(|l| hub.session_snapshot(l.session).is_some())
                                .collect();
                            if let Err(e) = slots.restore(&live, &pod_id).await {
                                tracing::warn!(%e, "session slots: restoring lost leases failed");
                            }
                        }
                        Err(e) => tracing::warn!(
                            %e,
                            leases = leases.len(),
                            "session slots: renewal failed; the leases expire unless the next round lands"
                        ),
                    }
                }
            });
        }
        consent_consumer::spawn_consent_consumer(
            consent_rx,
            consent_consumer::ConsentConsumerDeps {
                agents: agents.clone(),
                users: core.users.clone(),
                consent_requests: consent_requests.clone(),
                push_subscriptions: core.push_subscriptions.clone(),
                email: core.email.clone(),
                push: core.push.clone(),
                base_url: settings.oauth.base_url.clone(),
                notifications: core.notifications.clone(),
                ws_storage: core.ws_storage.clone(),
                redis_pubsub: core.redis_pubsub.clone(),
            },
        );

        // The releases cache: `POST /api/releases/refresh` lands on ONE pod,
        // and the bus handler is how the other pods get busted too.
        let releases_cache = releases::ReleasesCache::new();
        if let Some(bus) = &core.cluster_bus {
            let cache = releases_cache.clone();
            let pod_id = core.pod.pod_id.clone();
            bus.register(releases::BUS_CLASS_REFRESH, move |body| {
                let cache = cache.clone();
                let pod_id = pod_id.clone();
                Box::pin(async move {
                    let expect = body
                        .get("expect_tag")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    let report = cache.force_refresh(&pod_id, expect.as_deref()).await;
                    serde_json::to_value(report).map_err(|e| e.to_string())
                })
            });
        }

        let state = Self {
            agents,
            enrollment_keys,
            enroll_tokens: Arc::new(EnrollTokenIssuedDao::new(db)),
            setup_diagnostics: Arc::new(SetupDiagnosticsDao::new(db)),
            agent_crashes: Arc::new(AgentCrashDao::new(db)),
            agent_logs: Arc::new(AgentLogDao::new(db)),
            consent_requests,
            exec_audit: Arc::new(ExecAuditDao::new(db)),
            exec_pending: Arc::new(ExecPendingDao::new(db)),
            external_rc_audit: Arc::new(ExternalRcAuditDao::new(db)),
            config_audit: Arc::new(ConfigAuditDao::new(db)),
            keep_busy_events: Arc::new(KeepBusyEventDao::new(db)),
            rc_hub,
            agent_presence_tokens: Arc::new(DashMap::new()),
            presence_fanout: Arc::new(presence::PresenceFanout::default()),
            agent_nudge_cooldowns: Arc::new(DashMap::new()),
            agent_nudge_throttle: Arc::new(DashMap::new()),
            exec_rate_limiter: Arc::new(RateLimiter::new()),
            releases_cache,
            internal_networks: Arc::new(internal_networks_from(settings)),
            core,
        };

        // C-1 — the directory heartbeat: every 30 s, re-assert this pod's
        // agent presence records (gated on STILL holding the hub slot).
        // Redundant with the per-received-heartbeat refresh in the socket
        // handler — deliberately: it heals a record lost to a Redis flap
        // even while the agent is quiet. A CONFLICT (foreign owner) is the
        // fold signal: log it; the socket-level machinery (displacement
        // Goodbye / A2b counter) owns the reaction.
        if let Some(dir) = &state.cluster_directory {
            let dir = dir.clone();
            let hub = state.rc_hub.clone();
            let tokens = state.agent_presence_tokens.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    for entry in tokens.iter() {
                        let (agent_id, token) = (*entry.key(), entry.value().clone());
                        if !hub.is_agent_online(agent_id) {
                            continue;
                        }
                        let key = roomler_core::cluster::directory::agent_key(&agent_id.to_hex());
                        match dir.refresh_if_mine(&key, &token, 90).await {
                            Ok(true) => {}
                            Ok(false) => tracing::warn!(
                                agent = %agent_id,
                                "directory heartbeat CONFLICT — foreign pod owns this agent's record"
                            ),
                            Err(e) => {
                                tracing::debug!(agent = %agent_id, %e, "directory heartbeat failed");
                            }
                        }
                    }
                }
            });
        }
        // P4 — the presence staleness sweep (cluster-singleton per cycle via
        // a DB-name-scoped Redis NX claim; first tick a full interval out so
        // tests driving `run_presence_sweep` directly stay deterministic).
        presence::spawn_sweeper(state.clone());
        // C-2/PR-1 — the owner-side idle-agent nudge handler (P7b, from the
        // host): cycles an agent's socket iff every holder reads it idle.
        nudge::register_bus_handler(&state);
        Ok(state)
    }

    fn enabled(settings: &Settings) -> bool {
        settings.modules.fleet
    }

    /// Fleet's side of the tenant cascade (device revocation on archive).
    /// Fleet is the CALLER of the agent cascade, never a holder of it.
    fn hooks(&self) -> roomler_core::Hooks {
        tenant_hooks::hooks(self)
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        Capabilities::enabled(Self::ID)
    }

    /// Exactly the paths the host mounted before P5a. The sub-routes under
    /// `/tenant/{tenant_id}/agent/{agent_id}/…` that belong to `remote` and
    /// `network` (ssh, ssh-policy, peer-relay-policy, overlay-key/rotate) are
    /// NOT here — the host still mounts those under the same prefix.
    fn routes(&self) -> Router {
        let agent = Router::new()
            .route("/", get(agent::list_agents))
            .route("/enroll-token", post(agent::issue_enrollment_token))
            // FR-51 P2 — reusable ephemeral enrollment keys (static segments
            // win over the `{agent_id}` param below, same as `/enroll-token`).
            .route(
                "/enroll-key",
                get(enroll_key::list_keys).post(enroll_key::mint_key),
            )
            .route("/enroll-key/{key_id}", delete(enroll_key::revoke_key))
            .route("/enroll-key/{key_id}/uses", get(enroll_key::list_key_uses))
            // S1a — operator-forced self-update: bulk + per-agent.
            .route("/update", post(agent::trigger_agents_update))
            .route("/{agent_id}/update", post(agent::trigger_agent_update))
            // Multi-org — add an already-enrolled device to a SECOND org.
            .route("/{agent_id}/join-org", post(agent_org::join_org))
            .route("/{agent_id}/join-targets", get(agent_org::join_targets))
            .route(
                "/{agent_id}",
                get(agent::get_agent)
                    .put(agent::update_agent)
                    .delete(agent::delete_agent),
            )
            .route("/{agent_id}/crash", get(agent_crash::list_for_agent))
            // rc.58 — centralized log batch ingest + listing.
            .route(
                "/{agent_id}/logs",
                post(agent_log::ingest_agent).get(agent_log::list_for_agent),
            )
            // Fleet RPC — remote command execution.
            .route("/exec", post(agent_exec::exec_bulk))
            .route("/{agent_id}/exec", post(agent_exec::exec))
            .route(
                "/{agent_id}/exec/{request_id}/cancel",
                post(agent_exec::cancel),
            )
            .route("/{agent_id}/exec-policy", put(agent_exec::set_policy))
            // FR-94 — revoke a device's SYSTEM service without removing it.
            .route("/{agent_id}/exec-anchor", delete(exec_service::unanchor))
            // FR-52 gate 2 — approve a device for control by someone OUTSIDE
            // the org. MANAGE_AGENTS + REMOTE_CONTROL to grant, MANAGE_AGENTS
            // alone to clear (external_access.rs says why); audited both arms.
            .route(
                "/{agent_id}/external-access-policy",
                put(external_access::set_policy),
            )
            // FR-52 §5 — mint or rotate the connect code an outsider names
            // this device by. Rotation IS the revocation story for a leak.
            .route(
                "/{agent_id}/connect-code",
                post(external_access::rotate_connect_code),
            )
            // Remote config — records an INTENT for the device to reconcile.
            .route(
                "/{agent_id}/desired-config",
                put(remote_config::set_desired_config),
            );

        // NB `/tenant/{tenant_id}/device` (the device listing) is NOT here: it
        // joins agents with tunnel clients and overlay nodes — a cross-pillar
        // view the host keeps until `network` exists.
        let exec_audit = Router::new().route("/", get(agent_exec::audit));
        // FR-52 — the org switch (gate 1) + the approved-device list, and
        // the decision log. Approval itself is on the agent router, since
        // gate 2 is per device.
        let external_access = Router::new().route(
            "/",
            get(external_access::get_settings).put(external_access::set_enabled),
        );
        let external_rc_audit = Router::new().route("/", get(external_access::audit));
        let exec_settings = Router::new().route(
            "/",
            get(agent_exec::get_org_settings).put(agent_exec::set_org_settings),
        );
        // FR-92 — the org's keep-busy deny + default pattern (any member
        // reads, MANAGE_TENANT sets), and the permanent history (P7,
        // MANAGE_AGENTS).
        let keep_busy_settings = Router::new().route(
            "/",
            get(keep_busy::get_org_settings).put(keep_busy::set_org_settings),
        );
        let keep_busy_history = Router::new().route("/", get(keep_busy::history));
        // FR-51 P2 — the ephemeral-key class switch (MANAGE_TENANT).
        let ephemeral_key_settings = Router::new().route(
            "/",
            get(enroll_key::get_org_settings).put(enroll_key::set_org_settings),
        );
        let log = Router::new().route("/browser", post(agent_log::ingest_browser));

        // Public agent endpoints: enrollment uses an admin-issued enrollment
        // token (no user JWT); the release proxies are unauthenticated because
        // the agent's auto-updater calls them before any session; crash ingest
        // and self-unenroll authenticate with the agent's own JWT (`AuthAgent`).
        let public_agent = Router::new()
            .route("/enroll", post(agent::enroll_agent))
            .route("/latest-release", get(agent_release::latest_release))
            .route(
                "/artifacts/{tag}/{filename}",
                get(release_delivery::artifact_proxy),
            )
            .route(
                "/installer/{flavour}/health",
                get(agent_release::installer_health),
            )
            .route("/installer/{flavour}", get(agent_release::installer_proxy))
            .route("/crash", post(agent_crash::ingest))
            .route("/self/unenroll", post(agent::self_unenroll))
            // FR-103 — a device renews its own agent token (a bounded grace
            // past `exp`, the row checked like `AuthAgent`).
            .route("/self/renew", post(agent::self_renew))
            // FR-94 — a Windows device's SYSTEM service. The anchor takes an
            // admin-issued enrollment token, and the claim and the result take
            // the service's OWN credential (`AuthAgentService`), never the
            // agent token the signed-in user can read.
            .route("/anchor", post(exec_service::anchor))
            .route("/service/renew", post(exec_service::renew))
            .route("/service/rpc/{request_id}/claim", post(exec_service::claim))
            .route(
                "/service/rpc/{request_id}/result",
                post(exec_service::result),
            );

        // Public owner-consent routes (Phase 4). No auth extractor — the
        // unguessable token IS the capability.
        let public_consent = Router::new()
            .route("/{token}/approve", post(consent::approve_consent))
            .route("/{token}/deny", post(consent::deny_consent));

        // `/api/tunnel/{latest-release,installer/{platform}}` — the roomler
        // CLI binary's proxy, a separate namespace from the agent's.
        let public_tunnel_release = Router::new()
            .route("/latest-release", get(tunnel_release::latest_release))
            .route(
                "/installer/{platform}/health",
                get(tunnel_release::installer_health),
            )
            .route(
                "/installer/{platform}",
                get(tunnel_release::installer_proxy),
            );

        // `/api/setup/…` — the unified `roomler-setup` wizard's proxy. The
        // static `/install.sh` + `/install.ps1` segments win over `/{platform}`.
        //
        // FR-102 P3b — `/diagnostics` is static too, so it wins over the
        // `/{platform}` catch-all for EVERY method: `POST` is the wizard's
        // opt-in diagnostics (body capped by its own layer; the handler
        // answers the empty 404 while `growth.setup_diagnostics` is off),
        // and a `GET /api/setup/diagnostics` is now a 405 where it used to
        // fall into the proxy and be refused as an unknown platform (400).
        // `GET /api/setup/diagnostics/health` still reaches the proxy's
        // `/{platform}/health` and is refused there as before.
        let public_setup = Router::new()
            .route("/latest-release", get(setup_release::setup_latest_release))
            .route("/install.sh", get(setup_release::install_script_sh))
            .route("/install.ps1", get(setup_release::install_script_ps1))
            .route(
                "/diagnostics",
                post(setup_diagnostics::ingest)
                    .layer(DefaultBodyLimit::max(setup_diagnostics::MAX_BODY_BYTES)),
            )
            .route(
                "/{platform}/health",
                get(setup_release::setup_installer_health),
            )
            .route("/{platform}", get(setup_release::setup_installer_proxy));

        // `/api/releases/refresh` — bearer-authenticated cache-bust called by
        // the release workflows on every published tag.
        let releases = Router::new().route("/refresh", post(releases::refresh));

        Router::new()
            .nest("/tenant/{tenant_id}/agent", agent)
            .nest("/tenant/{tenant_id}/exec-audit", exec_audit)
            .nest("/tenant/{tenant_id}/external-access", external_access)
            .nest("/tenant/{tenant_id}/external-rc-audit", external_rc_audit)
            .nest("/tenant/{tenant_id}/exec-settings", exec_settings)
            .nest("/tenant/{tenant_id}/keep-busy-settings", keep_busy_settings)
            .nest("/tenant/{tenant_id}/keep-busy-history", keep_busy_history)
            .nest(
                "/tenant/{tenant_id}/ephemeral-key-settings",
                ephemeral_key_settings,
            )
            .nest("/log", log)
            .nest("/agent", public_agent)
            .nest("/consent", public_consent)
            .nest("/tunnel", public_tunnel_release)
            .nest("/setup", public_setup)
            .nest("/releases", releases)
            .with_state(self.clone())
    }

    /// The twelve collections this module owns. The first eight specs are the
    /// ones the db crate's plan held before P5a, unchanged; `keep_busy_events`
    /// (FR-92 P7), `exec_pending` (FR-94), `enroll_token_issued` (FR-102 P3)
    /// and `setup_diagnostics` (FR-102 P3b) were born here.
    fn indexes(&self) -> Vec<IndexSet> {
        vec![
            // The agent socket records private business source observations
            // (core business_authority). Their expiry index must exist whenever
            // fleet runs, not only when the network module is mounted; the
            // network module declares the same idempotent spec for clients.
            IndexSet {
                collection: roomler_core::business_authority::OBSERVATIONS_COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index_ttl(bson::doc! { "expires_at": 1 }, 0)],
            },
            IndexSet {
                collection: "consent_requests",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "token": 1 }),
                    index(bson::doc! { "session_id": 1 }),
                    index_ttl(bson::doc! { "expires_at": 1 }, 0),
                ],
            },
            IndexSet {
                collection: "agents",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "tenant_id": 1, "machine_id": 1 }),
                    index(bson::doc! { "tenant_id": 1, "status": 1 }),
                    index(bson::doc! { "owner_user_id": 1 }),
                    // FR-51 — the reaper's candidate scan (ESR).
                    index(bson::doc! { "ephemeral": 1, "deleted_at": 1, "last_seen_at": 1 }),
                    // FR-52 — the connect code an outsider names a device by.
                    // Unique GLOBALLY, not per tenant: a stranger types a code
                    // with no org context, so it has to resolve on its own.
                    //
                    // ⚠️ Deliberately NOT scoped to live rows. A tombstone keeps
                    // its code reserved forever, so a code can never be recycled
                    // onto a new device and point someone holding the old note at
                    // a DIFFERENT machine. The cost is one reserved string per
                    // removed device, which is the cheap side of that trade.
                    index_unique_partial(
                        bson::doc! { "connect_code": 1 },
                        bson::doc! { "connect_code": { "$exists": true } },
                    ),
                ],
            },
            IndexSet {
                collection: "agent_crashes",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "agent_id": 1, "crashed_at_unix": -1 }),
                    // FR-102 decision 15 (operator, 2026-10-17): 30 days, as the
                    // privacy policy's §7 says. A report names the device's hostname
                    // and carries a log tail. Every reader fits inside it: the
                    // digest's 28-day window, the nightly per-day freeze, the
                    // per-device list of the last 50.
                    index_ttl(bson::doc! { "reported_at": 1 }, 30 * 24 * 60 * 60),
                ],
            },
            IndexSet {
                collection: "enrollment_keys",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "jti": 1 }),
                    index(bson::doc! { "tenant_id": 1, "created_at": -1 }),
                ],
            },
            // FR-51 P2 — one row per successful key use: the trail that
            // survives the reap. 90-day TTL like the other audit collections.
            IndexSet {
                collection: "enrollment_key_uses",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "key_id": 1, "created_at": -1 }),
                    index_ttl(bson::doc! { "created_at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // FR-102 P3 — one row per standard enrollment token minted, `_id`
            // the jti, marked at redemption. The digest reads a day range
            // over `issued_at` with an exclusion filter on `tenant_id`; 90
            // days like the other enrollment trails (spec §3p).
            IndexSet {
                collection: roomler_ai_services::dao::enroll_token_issued::ENROLL_TOKEN_ISSUED,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "issued_at": 1, "tenant_id": 1 }),
                    index_ttl(
                        bson::doc! { "issued_at": 1 },
                        roomler_ai_services::dao::enroll_token_issued::ENROLL_TOKEN_ISSUED_TTL_SECS,
                    ),
                ],
            },
            // FR-102 P3b — the wizard's opt-in step diagnostics. `run` serves
            // the per-run cap's count; the TTL index on `ts` doubles as the
            // digest's and the nightly freeze's range scan. 90 days (spec
            // §3p); the frozen daily counts in `growth_daily` outlive it.
            IndexSet {
                collection: roomler_ai_services::dao::setup_diagnostics::SETUP_DIAGNOSTICS,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "run": 1 }),
                    index_ttl(
                        bson::doc! { "ts": 1 },
                        roomler_ai_services::dao::setup_diagnostics::SETUP_DIAGNOSTICS_TTL_SECS,
                    ),
                ],
            },
            // FR-52 — the server's own record of every external-access
            // decision, granted or refused. Same 90-day TTL and the same
            // reason as exec_audit: the REFUSED rows are the point.
            IndexSet {
                collection: "external_rc_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "user_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            IndexSet {
                collection: "exec_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "user_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // FR-94 — commands waiting for a Windows device's SYSTEM service.
            // `request_id` is unique: the claim, the result, the cancel and
            // the waiter's poll each address ONE row by it, and nothing lists
            // a device's rows (the doorbell names the request). The TTL
            // (`expires_at`, after `claim_by`) only keeps the collection
            // small. Expiry is enforced by the claim's own `claim_by` filter,
            // not by the TTL monitor, which runs once a minute.
            IndexSet {
                collection: "exec_pending",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "request_id": 1 }),
                    index_ttl(bson::doc! { "expires_at": 1 }, 0),
                ],
            },
            // A config change that opens exec is the same class of event as
            // using it, so it must not age out sooner than exec_audit.
            IndexSet {
                collection: "config_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "user_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            IndexSet {
                collection: "agent_logs",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "agent_id": 1, "created_at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "user_id": 1, "created_at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "source": 1, "created_at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "session_id": 1 }),
                    index_text(bson::doc! { "lines.msg": "text" }),
                    index_ttl(bson::doc! { "created_at": 1 }, 7 * 24 * 60 * 60),
                ],
            },
            // FR-92 P7 — the keep-busy history. ⚠️ Deliberately NO TTL,
            // unlike every audit collection above: the operator asked for a
            // PERMANENT history (2026-10-11). Rows outlive the device (the
            // name is denormalised), so there is no cascade to run either.
            IndexSet {
                collection: "keep_busy_events",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "agent_id": 1, "at": -1 }),
                ],
            },
        ]
    }

    /// Phase A-1 graceful shutdown: make this pod's death honest BEFORE the
    /// process exits, so a roll never strands `agents.status = 'Online'` rows
    /// and stale presence claims (the green-but-dead badge class). Fire every
    /// registered agent's displacement-cancel notify — each read loop exits
    /// within milliseconds and runs its OWN teardown; the bulk writes are
    /// belt-and-braces for sockets that don't finish in time. Agents see a
    /// plain socket close (never a Goodbye) and reconnect with backoff.
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        let state = self.clone();
        async move {
            let ids = state.rc_hub.cancel_all_agents();
            if ids.is_empty() {
                return;
            }
            tracing::info!(
                agents = ids.len(),
                "shutdown: cancelling local agent sockets + bulk offline sweep"
            );
            // Give the per-socket teardowns a beat to do the fine-grained cleanup.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            if let Err(e) = state
                .agents
                .mark_status_many(&ids, AgentStatus::Offline)
                .await
            {
                tracing::warn!(%e, "shutdown: bulk mark_status(Offline) failed");
            }
            if let Some(redis) = &state.redis_pubsub {
                for id in &ids {
                    if let Some((_, token)) = state.agent_presence_tokens.remove(id)
                        && let Err(e) = redis
                            .agent_presence_del_if_owned(&id.to_hex(), &token)
                            .await
                    {
                        tracing::debug!(agent = %id, %e, "shutdown: presence release failed");
                    }
                }
            }
        }
    }
}
