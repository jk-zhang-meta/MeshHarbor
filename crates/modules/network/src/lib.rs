// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `network` — pillar 2's server side as a module (FR-69 P7a): the overlay
//! mesh (IPAM, netmaps, leases, the L3 ACL, relay grants, the DERP ACL
//! cache), tunnels (clients, policies, audit), peer relays (FR-19), Roomler
//! SSH (the grant decision, its audit and the device-reported activity) and
//! overlay-key rotation.
//!
//! Built on `fleet` (the P6 `Module::Deps` seam): the Hub, the agent rows and
//! the nudge machinery are one live object each. `network → fleet` is the
//! graph edge; nothing here names the host.
//!
//! # What P7a moves, and what waits for P7b
//!
//! P7a is the ENGINE, the ROUTES and the HOOKS: everything a request or a
//! socket arm calls into. The sockets themselves — the tunnel-client loop,
//! the `/derp` upgrade with its cluster convergence and census, the
//! ephemeral-node reaper, the network half of the agent socket — are still
//! the host's and reach the engine through `AppState::network()`; that is
//! why the host links this crate unconditionally until P7b, when they move
//! and `network` becomes a feature.

use std::sync::Arc;

use axum::{
    Router,
    extract::FromRef,
    routing::{delete, get, post, put},
};
use bson::oid::ObjectId;
use dashmap::DashMap;
use roomler_ai_config::Settings;
use roomler_ai_db::indexes::{
    IndexOp, IndexSet, index, index_ttl, index_unique, index_unique_partial,
};
use roomler_ai_mod_fleet::FleetState;
use roomler_ai_remote_control::signaling::ServerMsg;
use roomler_ai_services::dao::{
    key_rotation_audit::KeyRotationAuditDao, overlay_network::OverlayNetworkDao,
    overlay_node::OverlayNodeDao, overlay_policy::OverlayPolicyDao,
    peer_relay_audit::PeerRelayAuditDao, ssh_activity::SshActivityDao, ssh_audit::SshAuditDao,
    ssh_pending::SshPendingDao, tunnel_audit::TunnelAuditDao, tunnel_client::TunnelClientDao,
    tunnel_policy::TunnelPolicyDao,
};
use roomler_core::{
    Capabilities, Core, Hooks, Module, TenantCtx, WsRegistration, rate_limit::RateLimiter,
    ws::UpgradeSpec,
};
use std::collections::HashSet;
use tokio::sync::mpsc;

pub mod agent_arms;
pub mod agent_socket;
pub mod business_isolation;
pub mod net_inventory;
pub mod derp;
pub mod derp_acl;
pub mod derp_cluster;
pub mod derp_types;
pub mod ephemeral;
pub mod hooks;
pub mod org_relay;
pub mod overlay;
pub mod relay_allowance;
pub mod shared_ssh;
pub mod ssh_grant_acks;
pub mod tunnel;
pub mod turn_usage;
pub mod routes {
    pub mod agent_ssh;
    pub mod business_authority;
    pub mod net_inventory;
    pub mod overlay_block;
    pub mod overlay_key;
    pub mod overlay_policy;
    pub mod overlay_route;
    pub mod peer_relay;
    pub mod tunnel;
}

/// Outbound channel for a connected node, keyed by its id. Used here for
/// **tunnel-client** overlay nodes (`overlay_nodes_by_id`); the host keeps
/// an alias of the same shape for its per-forward-session map until P7b.
pub type TunnelClientOutbound = Arc<DashMap<ObjectId, mpsc::Sender<ServerMsg>>>;

/// The module's state: the core, the fleet module it is built on, and what
/// network owns.
#[derive(Clone)]
pub struct NetworkState {
    pub core: Core,
    /// `network → fleet`: the Hub (agent nodes are reached through it), the
    /// agent rows, presence, the nudge machinery.
    pub fleet: FleetState,

    // tunnel subsystem
    pub tunnel_clients: Arc<TunnelClientDao>,
    pub tunnel_policies: Arc<TunnelPolicyDao>,
    pub tunnel_audit: Arc<TunnelAuditDao>,

    // Overlay-network subsystem (Tailscale-style L3 mesh)
    pub overlay_networks: Arc<OverlayNetworkDao>,
    pub overlay_nodes: Arc<OverlayNodeDao>,
    /// Overlay L3 ACL. Read on every netmap event (join / leave / admin edit),
    /// not per flow — the overlay data plane never touches the server.
    pub overlay_policies: Arc<OverlayPolicyDao>,
    /// Connection-lifetime WS outbound channels for **tunnel-client**
    /// overlay nodes, keyed by `tunnel_client_id` (agent nodes are reached
    /// via the Hub's `send_to_agent`). Used by the overlay broker to fan
    /// netmaps/deltas to client nodes.
    pub overlay_nodes_by_id: TunnelClientOutbound,
    /// Live join snapshots, for fail-closed security removal without Mongo IO.
    pub admission_nodes: Arc<DashMap<ObjectId, roomler_ai_remote_control::models::OverlayNode>>,
    /// DERP relay registry: `(network_id, wg_pubkey)` → the outbound frame
    /// sender for that node's live `/derp` WS. The pubkey-addressed
    /// forwarding map for the both-UDP-blocked carrier tier. The relay that
    /// fills it is the host's until P7b.
    pub derp_registry: derp_types::DerpRegistry,
    /// Overlay ACL — per-network relay allow tables consulted by the DERP
    /// forward path. Precomputed because forwarding is a synchronous
    /// per-datagram path; a missing entry fails OPEN. See [`derp_acl`].
    pub derp_acl: derp_acl::DerpAclCache,
    /// C-5 — per-connection rehome-close signals (cluster convergence).
    pub derp_cancels: derp_types::DerpCancelRegistry,
    /// P7 — per-pair TURN-relay churn state for the forced-DERP escalation,
    /// keyed by the symmetric `pair_key`. Manual TTL (checked on access) +
    /// a size-capped retain sweep — see [`overlay::PairChurn`].
    pub relay_pair_churn: Arc<DashMap<String, overlay::PairChurn>>,
    /// FR-19 — the org-relay mint's pod-local state: minted sessions (keyed
    /// by pair), per-relay VNI cursors, the server-wide generation clock,
    /// join extras (primary-org flag, relay port) and reachability reports.
    /// Pod-local is correct here for the same reason `relay_pair_churn` is:
    /// tenant affinity puts a tenant's nodes on ONE pod, and the relay's own
    /// table is the truth a restart falls back on (sessions then run out
    /// their `max_lifetime`).
    pub org_relay: Arc<org_relay::OrgRelayState>,
    /// #1186 — the sender the host's Redis ctrl subscriber feeds cross-pod
    /// `overlay_removes` envelopes into; the applier draining it is spawned
    /// by [`Module::init`]. Bounded + `try_send` on the feeding side: losing
    /// one under pressure costs a push the peer's rejoin heals.
    pub overlay_ctrl_tx: mpsc::Sender<serde_json::Value>,

    // Decision logs
    /// Roomler-SSH grant log — every session request, granted or refused.
    pub ssh_audit: Arc<SshAuditDao>,
    /// P8 — device-reported session activity. Separate from `ssh_audit`
    /// because one is the server's decision and the other is a claim by the
    /// device; see `SshActivityEvent`.
    pub ssh_activity: Arc<SshActivityDao>,
    /// FR-40 — overlay-key rotation orders, dispatched or refused.
    pub key_rotation_audit: Arc<KeyRotationAuditDao>,
    /// FR-19 peer-relay decisions: approvals (who made a device a relay) and
    /// mints (what the server routed through it), granted or refused.
    pub peer_relay_audit: Arc<PeerRelayAuditDao>,

    // Ceilings
    /// Per-(caller, device) ceiling for the SSH control plane. Shared by the
    /// HTTP route and the device-originated WS leg — both funnel through the
    /// same `dispatch`, so neither transport is unlimited.
    pub ssh_rate_limiter: Arc<RateLimiter>,
    pub(crate) shared_ssh_sessions: Arc<DashMap<ObjectId, shared_ssh::SharedSshSession>>,
    pub(crate) shared_ssh_slots: Arc<tokio::sync::Semaphore>,
    pub(crate) ssh_shared_lease_limiter: Arc<RateLimiter>,
    /// FR-83 — grants whose caller is held until the target acknowledges
    /// them. Pod-local like the Hub's exec waiters: the push only succeeds
    /// when the target's socket is here, and its ack arrives on that socket.
    pub ssh_grant_acks: Arc<ssh_grant_acks::SshGrantAcks>,
    /// FR-105 — grants routed to a Windows device's SYSTEM service, waiting
    /// for its claim. Shared (Mongo), unlike the acks: the claim can land on
    /// any pod, and the caller waiting on another one reads it here.
    pub ssh_pending: Arc<SshPendingDao>,
    /// FR-19 — per-(requesting node, relay node) mint ceiling
    /// (`peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE`), checked by the mint
    /// in [`overlay`] AFTER the identity gates so a refusal is attributable.
    pub relay_rate_limiter: Arc<RateLimiter>,
    /// FR-40 — one rotation order per device per minute. Keyed on the DEVICE
    /// (the limiter's `caller` slot carries the device id too): a second
    /// admin clicking inside the window is the same storm, not a new budget.
    pub key_rotation_rate_limiter: Arc<RateLimiter>,

    // The sockets' live state (P7b, from the host)
    /// Multi-region DERP ticket signer (`relay.derp_ticket_private_key`).
    /// `None` = no key configured — ticket requests go unanswered and agents
    /// keep using the central `/derp`.
    pub derp_ticket: Option<Arc<roomler_ai_remote_control::derp_ticket::DerpTicketSigner>>,
    /// C-3 — directory owner-tokens for LOCAL tunnel sessions
    /// (`roomler:own:tunnel:<session>`). Written on open; refreshed by the
    /// directory heartbeat while the session map still holds the session;
    /// never explicitly released — the 90 s TTL reaps ≤90 s after any of
    /// the four teardown paths drops the map entry.
    pub tunnel_presence_tokens: Arc<DashMap<ObjectId, String>>,
    /// Per-tunnel-session WS outbound channels, keyed by the
    /// `tunnel_session_id` issued on `rc:tunnel.open`. The tunnel WS handler
    /// registers its sender on TunnelOpen success and unregisters on
    /// disconnect / TunnelTerminate; the agent socket's tunnel relay reads
    /// this map to relay `TcpForwardAccept` / `TcpForwardReject` /
    /// `TcpHalfClose` / `TcpClosed` / `TunnelTerminate` from agent → client.
    pub tunnel_clients_by_session: TunnelClientOutbound,
    /// P7 flap resilience: which tunnel sessions TARGET a given agent —
    /// `agent_id → {tunnel_session_id}`. Maintained by `tunnel`'s open +
    /// teardown paths and drained by
    /// [`tunnel::terminate_sessions_targeting_agent`] when the agent's WS
    /// drops: the agent's per-connection tunnel peers died with its socket,
    /// so every session targeting it is unrecoverable and its client must
    /// re-open rather than forward into a corpse forever.
    pub tunnel_sessions_by_target_agent: Arc<DashMap<ObjectId, HashSet<ObjectId>>>,
    /// PR-1 rehome — which tunnel sessions a given agent ORIGINATED
    /// (P3b-2 agent-as-tunnel-client, i.e. declared routes) —
    /// `origin_agent_id → {tunnel_session_id}`. Twin of the by-target index
    /// above, consulted by fleet's `rc.agent_nudge` busy check through
    /// [`roomler_core::hooks::FleetLifecycle::agent_busy`]: the
    /// per-connection session map is invisible there, so without this a
    /// routes-only agent read as IDLE and got its WS cycled (tearing every
    /// declared route plus its overlay carriers).
    pub tunnel_sessions_by_origin_agent: Arc<DashMap<ObjectId, HashSet<ObjectId>>>,
    /// C-5 — directory owner-tokens for LOCAL derp registrations
    /// (`roomler:own:derp:<net>:<pubkey>`); refreshed by the directory
    /// heartbeat while the registry holds the key.
    pub derp_presence_tokens: Arc<DashMap<derp_types::DerpKey, String>>,
    /// C-5 — per-(network, pubkey) rehome pacing (60 s cooldown, 3
    /// attempts / 10 min, then the split-evidence counter).
    pub derp_rehome_cooldowns: Arc<derp_cluster::RehomeCooldowns>,
}

impl std::ops::Deref for NetworkState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<NetworkState> for Core {
    fn from_ref(state: &NetworkState) -> Self {
        state.core.clone()
    }
}

impl Module for NetworkState {
    const ID: &'static str = "network";

    type Deps = FleetState;

    async fn init(core: Core, settings: &Settings, fleet: FleetState) -> anyhow::Result<Self> {
        let db = &core.db;
        // #1186 — see `overlay_ctrl_tx`.
        let (overlay_ctrl_tx, overlay_ctrl_rx) = mpsc::channel::<serde_json::Value>(256);
        // Multi-region DERP tickets: load the signer when a key is configured;
        // log the derived public key so the operator can copy it to PoPs.
        // Regions carrying derp_urls without a key = loud warn, never fatal.
        let derp_ticket = match settings.relay.derp_ticket_private_key.as_deref() {
            Some(key) => {
                match roomler_ai_remote_control::derp_ticket::DerpTicketSigner::from_pkcs8_b64(key)
                {
                    Ok(s) => {
                        tracing::info!(
                            public_key = %s.public_key_b64(),
                            "derp ticket signer loaded — set DERP_TICKET_PUBLIC_KEY to this on every PoP relay"
                        );
                        Some(Arc::new(s))
                    }
                    Err(e) => {
                        tracing::error!(%e, "ROOMLER__RELAY__DERP_TICKET_PRIVATE_KEY is unusable; regional DERP disabled");
                        None
                    }
                }
            }
            None => {
                if core.turn_map.enabled && core.turn_map.specs.iter().any(|s| s.derp_url.is_some())
                {
                    tracing::warn!(
                        "relay regions carry derp_urls but no ROOMLER__RELAY__DERP_TICKET_PRIVATE_KEY is set — regional DERP disabled"
                    );
                }
                None
            }
        };
        let state = Self {
            derp_ticket,
            tunnel_presence_tokens: Arc::new(DashMap::new()),
            tunnel_clients_by_session: Arc::new(DashMap::new()),
            tunnel_sessions_by_target_agent: Arc::new(DashMap::new()),
            tunnel_sessions_by_origin_agent: Arc::new(DashMap::new()),
            derp_presence_tokens: Arc::new(DashMap::new()),
            derp_rehome_cooldowns: Arc::new(DashMap::new()),
            tunnel_clients: Arc::new(TunnelClientDao::new(db)),
            tunnel_policies: Arc::new(TunnelPolicyDao::new(db)),
            tunnel_audit: Arc::new(TunnelAuditDao::new(db)),
            // P2b — carving is opt-in per deployment. With the flag off the
            // DAO behaves exactly as it did pre-P2b (no registry reads at all).
            overlay_networks: Arc::new(
                OverlayNetworkDao::new(db).with_block_prefix(
                    settings
                        .overlay
                        .blocks_enabled
                        .then_some(settings.overlay.block_prefix),
                ),
            ),
            overlay_nodes: Arc::new(OverlayNodeDao::new(db)),
            overlay_policies: Arc::new(OverlayPolicyDao::new(db)),
            overlay_nodes_by_id: Arc::new(DashMap::new()),
            admission_nodes: Arc::new(DashMap::new()),
            derp_registry: Arc::new(DashMap::new()),
            derp_acl: Arc::new(DashMap::new()),
            derp_cancels: Arc::new(DashMap::new()),
            relay_pair_churn: Arc::new(DashMap::new()),
            org_relay: Arc::new(org_relay::OrgRelayState::new()),
            overlay_ctrl_tx,
            ssh_audit: Arc::new(SshAuditDao::new(db)),
            ssh_activity: Arc::new(SshActivityDao::new(db)),
            key_rotation_audit: Arc::new(KeyRotationAuditDao::new(db)),
            peer_relay_audit: Arc::new(PeerRelayAuditDao::new(db)),
            ssh_rate_limiter: Arc::new(RateLimiter::new()),
            shared_ssh_sessions: Arc::new(DashMap::new()),
            shared_ssh_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            ssh_shared_lease_limiter: Arc::new(RateLimiter::new()),
            ssh_grant_acks: Arc::new(ssh_grant_acks::SshGrantAcks::new()),
            ssh_pending: Arc::new(SshPendingDao::new(db)),
            relay_rate_limiter: Arc::new(RateLimiter::new()),
            key_rotation_rate_limiter: Arc::new(RateLimiter::new()),
            fleet,
            core,
        };
        // #1186 — apply cross-pod `overlay_removes` envelopes (the channel is
        // fed by the host's redis ctrl subscriber; with no Redis the sender
        // side never fires and this task just parks).
        overlay::spawn_removes_applier(state.clone(), overlay_ctrl_rx);

        // P7b — the sockets' machinery, from the host's `AppState::new`.
        // The agent socket is fleet's; this module's half (the tunnel and
        // overlay relays with their per-connection state, SSH, key rotation,
        // DERP tickets, probe reports) is dispatched to it by
        // `ClientMsg::namespace()` (P5c).
        let arms = Arc::new(agent_socket::NetworkAgentSocket::new(state.clone()));
        state.core.agent_socket.register(
            Self::ID,
            roomler_core::AgentSocketHooks {
                handler: Some(arms.clone()),
                lifecycle: Some(arms),
            },
        );
        // C-5 — derp rehome: the owner-side close handler.
        derp_cluster::wire_derp_cluster(&state);
        // Split-brain observability: the per-pod DERP registry census.
        derp::spawn_registry_census(&state);
        // FR-51 — the ephemeral-node reaper (cluster-singleton per cycle via
        // the DB-name-scoped claim pattern). Spawns NOTHING unless
        // `rc.ephemeral_reaper_enabled` — the P1 kill switch, default off.
        ephemeral::spawn_reaper(state.clone());
        // FR-20 P1 — drain the per-network DERP byte counters into the
        // `stats_usage` cost ledger every 60 s. Runs on BOTH pods on purpose:
        // each writes only the bytes it relayed, into the same deterministic
        // `_id`, and `$inc` sums them.
        derp::spawn_derp_usage_flush(state.clone());
        // FR-115 P4a — the relay allowance: the over-allowance job (one pod
        // per tick) and every pod's refresh. Throttles nothing unless
        // `relay_allowance.enabled`, and never on a server that sells no plans.
        relay_allowance::spawn(state.clone());
        // FR-115 P4b — coturn's statistics DB into `turn_bytes` per org.
        // Subscribes to nothing unless `relay_allowance.turn_attribution`.
        turn_usage::spawn(state.clone());
        // C-3/C-5 — the directory heartbeat for this module's classes
        // (tunnel sessions, derp registrations). The agent-presence half is
        // fleet's, spawned by its init.
        if let Some(dir) = &state.cluster_directory {
            let dir = dir.clone();
            let tunnel_tokens = state.tunnel_presence_tokens.clone();
            let tunnel_sessions = state.tunnel_clients_by_session.clone();
            let derp_tokens = state.derp_presence_tokens.clone();
            let derp_reg = state.derp_registry.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    // C-3 — tunnel session records: refresh while the session
                    // map holds the session (its four teardown paths all drop
                    // the map entry, which stops the refresh here; the 90 s
                    // TTL then reaps the record — no explicit release).
                    let dead: Vec<ObjectId> = tunnel_tokens
                        .iter()
                        .filter(|e| !tunnel_sessions.contains_key(e.key()))
                        .map(|e| *e.key())
                        .collect();
                    for sid in dead {
                        tunnel_tokens.remove(&sid);
                    }
                    for entry in tunnel_tokens.iter() {
                        let (sid, token) = (*entry.key(), entry.value().clone());
                        let key = roomler_core::cluster::directory::tunnel_key(&sid.to_hex());
                        if let Err(e) = dir.refresh_if_mine(&key, &token, 90).await {
                            tracing::debug!(session = %sid, %e, "tunnel directory refresh failed");
                        }
                    }
                    // C-5 — derp registration records: prune tokens whose
                    // registry entry is gone (socket closed / displaced),
                    // refresh the rest. A CONFLICT here just means the
                    // node re-registered on another pod (LWW) while our
                    // stale socket lingers — nothing to fold.
                    let dead: Vec<derp_types::DerpKey> = derp_tokens
                        .iter()
                        .filter(|e| !derp_reg.contains_key(e.key()))
                        .map(|e| *e.key())
                        .collect();
                    for k in dead {
                        derp_tokens.remove(&k);
                    }
                    for entry in derp_tokens.iter() {
                        let ((net, pk), token) = (*entry.key(), entry.value().clone());
                        let key = roomler_core::cluster::directory::derp_key(
                            &net.to_hex(),
                            &derp_cluster::pk_hex(&pk),
                        );
                        if let Err(e) = dir.refresh_if_mine(&key, &token, 90).await {
                            tracing::debug!(network = %net, %e, "derp directory refresh failed");
                        }
                    }
                }
            });
        }
        Ok(state)
    }

    fn enabled(settings: &Settings) -> bool {
        settings.modules.network
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        Capabilities::enabled(Self::ID)
    }

    /// Exactly the paths the host mounted before P7a.
    fn routes(&self) -> Router {
        // The per-device sub-routes under the fleet module's `/agent` prefix
        // (the rest of `/tenant/{tenant_id}/agent` is fleet's).
        let agent = Router::new()
            // FR-40 — order the device to retire its overlay key
            // (MANAGE_AGENTS; cap-gated, audited, queued for an offline device).
            .route(
                "/{agent_id}/overlay-key/rotate",
                post(routes::overlay_key::rotate_overlay_key),
            )
            // Roomler SSH — ask for a session on one device. Answers 200 with
            // either where to dial or which gate refused; a denial is a policy
            // outcome the caller must read, not a transport failure.
            .route("/{agent_id}/ssh", post(routes::agent_ssh::request_session))
            // Gate 3's twin, and the same MANAGE_AGENTS-not-SSH_DEVICE split.
            .route("/{agent_id}/ssh-policy", put(routes::agent_ssh::set_policy))
            // FR-19 gate 3 — approve a device as an org relay. MANAGE_AGENTS +
            // EXEC_DEVICE (there is no free permission bit; routes/peer_relay.rs
            // says why), audited on both arms.
            .route(
                "/{agent_id}/peer-relay-policy",
                put(routes::peer_relay::set_policy),
            );

        // roomler-cli routes — same enrollment two-step shape as the agent,
        // but a distinct audience (`TunnelClient` JWT) so a leaked agent token
        // can't impersonate a client and vice-versa.
        let tunnel_client = Router::new()
            .route("/", get(routes::tunnel::list_tunnel_clients))
            .route(
                "/enroll-token",
                post(routes::tunnel::issue_tunnel_enrollment_token),
            )
            // matchit gives the static `/enroll-token` above precedence over
            // this parameterised segment, so there is no shadowing.
            .route(
                "/{client_id}",
                put(routes::tunnel::update_tunnel_client)
                    .delete(routes::tunnel::delete_tunnel_client),
            );
        let tunnel_policy = Router::new()
            .route(
                "/",
                get(routes::tunnel::list_tunnel_policies)
                    .post(routes::tunnel::create_tunnel_policy),
            )
            .route(
                "/{policy_id}",
                get(routes::tunnel::get_tunnel_policy)
                    .put(routes::tunnel::update_tunnel_policy)
                    .delete(routes::tunnel::delete_tunnel_policy),
            );
        // Phase 1 subnet router — admin approves which advertised routes a
        // node may actually route for peers.
        let overlay_node = Router::new()
            .route("/", get(routes::overlay_route::list_overlay_nodes))
            .route(
                "/{node_id}/approved-routes",
                put(routes::overlay_route::set_approved_routes),
            )
            .route(
                "/{node_id}/exit-node",
                put(routes::overlay_route::set_exit_node),
            )
            // Evict a node from the mesh + release its address back to the pool.
            .route(
                "/{node_id}",
                delete(routes::overlay_route::evict_overlay_node),
            );
        // Overlay L3 ACL — shapes the netmap each node receives. `/mode`
        // carries the tenant-wide posture (off | warn | enforce); it is `off`
        // by default so deploying the feature can never black-hole a live mesh.
        // MeshHarbor #19 — the nodes' reported network inventory, read-only.
        let net_inventory = Router::new()
            .route("/", get(routes::net_inventory::list))
            .route("/{agent_id}", get(routes::net_inventory::get));
        let overlay_policy = Router::new()
            .route(
                "/",
                get(routes::overlay_policy::list).post(routes::overlay_policy::create),
            )
            .route(
                "/mode",
                get(routes::overlay_policy::get_mode).put(routes::overlay_policy::set_mode),
            )
            .route(
                "/{policy_id}",
                get(routes::overlay_policy::get)
                    .put(routes::overlay_policy::update)
                    .delete(routes::overlay_policy::delete),
            );
        // FR-19 — peer relays: the org switch + approved-relay listing, and
        // the decision log. Approval itself is on the agent router (gate 3 is
        // per device).
        let peer_relay = Router::new().route(
            "/",
            get(routes::peer_relay::get_settings).put(routes::peer_relay::set_mode),
        );
        let peer_relay_audit = Router::new().route("/", get(routes::peer_relay::audit));
        let ssh_audit = Router::new().route("/", get(routes::agent_ssh::audit));
        let ssh_activity = Router::new().route("/", get(routes::agent_ssh::activity));
        // Roomler SSH — its own org kill-switch (gate 1). A separate switch
        // from the exec one on purpose: allowing bounded diagnostic commands
        // is not the same decision as allowing interactive sessions.
        let ssh_settings = Router::new().route(
            "/",
            get(routes::agent_ssh::get_org_settings).put(routes::agent_ssh::set_org_settings),
        );
        // Phase 2 MagicDNS — the tenant's overlay DNS domain + upstreams.
        let magic_dns = Router::new().route(
            "/",
            get(routes::overlay_route::get_magic_dns).put(routes::overlay_route::set_magic_dns),
        );
        // Multi-org P2b — the tenant's overlay address block + the renumber
        // migration onto it. `renumber` defaults to a DRY RUN.
        let overlay_block = Router::new()
            .route("/", get(routes::overlay_block::get_block))
            .route("/renumber", post(routes::overlay_block::renumber))
            // FR-47 P3 — return leaked host ordinals to the recycle pool.
            // Platform-operator only (checked in-handler, like the block
            // reclaim route) and dry-run by default.
            .route(
                "/reconcile-hosts",
                post(routes::overlay_block::reconcile_hosts),
            );
        // Public: enrollment (no user JWT; auth is in-handler — the
        // TunnelClient bearer token — so it rides the no-middleware router).
        // FR-105 — a Windows device's SYSTEM service, with its OWN credential
        // (auth in-handler, the service token): it publishes its SSH endpoint
        // and claims the grants routed to it. Beside fleet's
        // `/agent/service/rpc/*`, which it mirrors.
        let agent_service_ssh = Router::new()
            .route(
                "/service/ssh-host-key",
                put(routes::agent_ssh::publish_service_endpoint),
            )
            .route(
                "/service/ssh/{grant_id}/claim",
                post(routes::agent_ssh::claim_service_grant),
            );
        let public_tunnel = Router::new()
            .route("/enroll", post(routes::tunnel::enroll_tunnel_client))
            .route("/agents", get(routes::tunnel::list_tenant_agents))
            // FR-103 — a client renews its own token (a bounded grace past
            // `exp`, the row checked).
            .route("/renew", post(routes::tunnel::renew_tunnel_client));

        // The unified device listing is NOT here. It joins fleet's agents
        // with this module's tunnel clients and overlay nodes, and P7b put
        // it in this crate on the strength of the graph edge — which left a
        // `remote` profile (fleet + remote, no network) with a devices page
        // whose listing 404s. It is the HOST's composition view
        // (`crates/api/src/routes/device.rs`): fleet rows always, this
        // module's rows only when it is mounted.

        Router::new()
            .route(
                "/admin/business-authority/{kind}/{tenant_id}/{device_id}",
                get(routes::business_authority::get).put(routes::business_authority::approve),
            )
            .route("/device-shares/{id}/ssh", get(shared_ssh::metadata))
            .route("/device-shares/{id}/ssh/ws", get(shared_ssh::connect))
            .nest("/tenant/{tenant_id}/agent", agent)
            .nest("/tenant/{tenant_id}/tunnel-client", tunnel_client)
            .nest("/tenant/{tenant_id}/tunnel-policy", tunnel_policy)
            .nest("/tenant/{tenant_id}/overlay-node", overlay_node)
            .nest("/tenant/{tenant_id}/overlay-acl", overlay_policy)
            .nest("/tenant/{tenant_id}/net-inventory", net_inventory)
            .nest("/tenant/{tenant_id}/magic-dns", magic_dns)
            .nest("/tenant/{tenant_id}/overlay-block", overlay_block)
            .nest("/tenant/{tenant_id}/peer-relay", peer_relay)
            .nest("/tenant/{tenant_id}/peer-relay-audit", peer_relay_audit)
            .nest("/tenant/{tenant_id}/ssh-audit", ssh_audit)
            .nest("/tenant/{tenant_id}/ssh-activity", ssh_activity)
            .nest("/tenant/{tenant_id}/ssh-settings", ssh_settings)
            .nest("/tunnel-client", public_tunnel)
            .nest("/agent", agent_service_ssh)
            // The block registry is GLOBAL, so reclaiming from it is a
            // platform operation, not a tenant one. Dry-run by default.
            .route(
                "/admin/overlay-block/reclaim",
                post(routes::overlay_block::reclaim),
            )
            // FR-54 — overlay networks whose organization no longer exists.
            // Platform-operator only (checked in-handler), dry-run by default.
            .route(
                "/admin/overlay-network/orphans",
                post(routes::overlay_block::orphans),
            )
            .with_state(self.clone())
    }

    /// The sets for the running deployment's schema switch.
    fn indexes(&self) -> Vec<IndexSet> {
        self.indexes_for(self.settings.overlay.multi_block_enabled)
    }

    /// The eleven collections this module owns, for an explicit `multi_block`
    /// schema. The specs are the ones the db crate's plan held before P7a,
    /// unchanged, in the plan's order.
    fn indexes_for(&self, multi_block: bool) -> Vec<IndexSet> {
        // Multi-org P2b — the GLOBAL overlay block registry. Deliberately NOT
        // tenant-scoped: its entire job is guaranteeing that two tenants can
        // never hold overlapping slices of 100.64.0.0/10.
        //
        // `slot` unique is the structural half of that guarantee — the
        // allocator computes aligned, monotonic starts, so two racers either
        // collide on the same slot (this index arbitrates) or claim disjoint
        // ranges. Without it the allocator would need a lock.
        //
        // `network_id` unique is scoped to ASSIGNED rows: a renumbered tenant
        // keeps its quarantined predecessors forever (they hold their slots
        // out of circulation), and only one of its blocks may be live at a
        // time. FR-47 P5c — `slot` unique is what makes overlap
        // unrepresentable and is ALWAYS present. The `network_id`
        // partial-unique is the separate "one assigned block per network"
        // rule, which multi-block removes.
        let mut overlay_block_indexes = vec![
            index_unique(bson::doc! { "slot": 1 }),
            // The allocator's "highest end" probe — one indexed sort+limit.
            index(bson::doc! { "end_slot": -1 }),
            index(bson::doc! { "tenant_id": 1 }),
            // Multi-block reads a network's blocks in allocation order.
            index(bson::doc! { "network_id": 1, "seq": 1 }),
        ];
        let mut overlay_block_ops = Vec::new();
        if multi_block {
            // Drop the guard rather than merely stop creating it: a
            // deployment that ran single-block already HAS the index, and an
            // existing index would refuse the second block with a duplicate
            // key — which the allocator's retry loop would then misreport as
            // "lost too many races" rather than as the schema problem it is.
            // The drop runs in `apply_op`, which tolerates both "nothing to
            // drop" outcomes (27 and 26) — see the comment there for why both
            // are normal.
            overlay_block_ops.push(IndexOp::DropIndexIfPresent {
                index: "network_id_1",
                why: "multi-block schema — one-block-per-network guard removed",
            });
        } else {
            overlay_block_indexes.push(index_unique_partial(
                bson::doc! { "network_id": 1 },
                bson::doc! { "state": "assigned" },
            ));
        }

        vec![
            // Central-use approvals and observed source addresses are private
            // security records, not ordinary Agent/TunnelClient JSON fields.
            // Role approvals need no set here: their deterministic `_id` is the
            // only key, and MongoDB rejects an empty createIndexes request.
            IndexSet {
                collection: roomler_core::business_authority::OBSERVATIONS_COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![index_ttl(bson::doc! { "expires_at": 1 }, 0)],
            },
            // MeshHarbor #19 — one reported inventory row per agent (`_id`),
            // read per tenant; a node that stops reporting ages out.
            IndexSet {
                collection: crate::net_inventory::COLLECTION,
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "received_at": -1 }),
                    index_ttl(bson::doc! { "expires_at": 1 }, 0),
                ],
            },
            // tunnel clients — same uniqueness contract as agents
            // (re-enroll-on-same-machine rehydrates the soft-deleted row in
            // place). `owner_user_id` index speeds the "my tunnel clients"
            // view on the user-facing dashboard.
            IndexSet {
                collection: "tunnel_clients",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "tenant_id": 1, "machine_id": 1 }),
                    index(bson::doc! { "tenant_id": 1, "status": 1 }),
                    index(bson::doc! { "owner_user_id": 1 }),
                ],
            },
            // Overlay networks — one IPAM row per tenant. Unique on tenant_id
            // so `get_or_create` races collapse to one network.
            IndexSet {
                collection: "overlay_networks",
                pre_ops: Vec::new(),
                indexes: vec![index_unique(bson::doc! { "tenant_id": 1 })],
            },
            IndexSet {
                collection: "overlay_blocks",
                pre_ops: overlay_block_ops,
                indexes: overlay_block_indexes,
            },
            // Overlay nodes — virtual-LAN membership above agents/tunnel_clients.
            //
            // All three unique indexes are scoped to LIVE rows, because
            // removing a device from the fleet TOMBSTONES its node in place
            // (keeping the address and name as the forensic record of who
            // held them) and returns the host number to
            // `overlay_networks.free_hosts` for reuse. A non-scoped unique
            // index would let a tombstone go on holding its IP and its name
            // forever, which is exactly the leak the release feature exists
            // to close.
            //
            // The filter is `$type: "null"`, NOT `{deleted_at: null}`:
            // equality-to-null in Mongo also matches ABSENT, whereas `$type`
            // matches only an explicit BSON null. `OverlayNode.deleted_at` is
            // declared without `skip_serializing_if`/`serde(default)`, so it
            // is written on every insert and required on every read —
            // "absent" is unreachable and `$type` is exact. Tradeoff: a
            // `$type`-filtered partial index is NOT usable by the planner for
            // a `{deleted_at: null}` query predicate. That is fine — these
            // three enforce uniqueness; the plain (tenant_id, network_id,
            // deleted_at) index below is what serves the netmap build query.
            IndexSet {
                collection: "overlay_nodes",
                pre_ops: Vec::new(),
                indexes: vec![
                    // Rehydrate key. Many tombstones per machine (a machine
                    // can be removed and re-enrolled repeatedly, taking a
                    // fresh lease each time) must coexist with AT MOST ONE
                    // live row.
                    index_unique_partial(
                        bson::doc! { "tenant_id": 1, "machine_id": 1 },
                        bson::doc! { "deleted_at": { "$type": "null" } },
                    ),
                    // No two LIVE nodes share an overlay address.
                    index_unique_partial(
                        bson::doc! { "tenant_id": 1, "network_id": 1, "overlay_ip": 1 },
                        bson::doc! { "deleted_at": { "$type": "null" } },
                    ),
                    index(bson::doc! { "tenant_id": 1, "network_id": 1, "deleted_at": 1 }),
                    // Phase 0 — per-network-unique node name (MagicDNS). The
                    // `name > ""` half keeps the empty names on pre-Phase-0
                    // rows (backfilled on next rejoin) from colliding; the
                    // `deleted_at` half releases the name on removal so the
                    // next device can take it.
                    index_unique_partial(
                        bson::doc! { "tenant_id": 1, "network_id": 1, "name": 1 },
                        bson::doc! { "$and": [
                            { "name": { "$gt": "" } },
                            { "deleted_at": { "$type": "null" } },
                        ] },
                    ),
                    // Backs the by-node_ref lookups on the removal paths.
                    index(bson::doc! { "tenant_id": 1, "node_ref.id": 1 }),
                ],
            },
            // Tunnel policies — tenant-scoped allowlists. The server-side ACL
            // gate fetches `list_active_for_tenant(tenant_id)` on every
            // TcpForwardRequest; the (tenant_id, deleted_at) compound index
            // covers that query precisely.
            IndexSet {
                collection: "tunnel_policies",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "deleted_at": 1 }),
                    index(bson::doc! { "tenant_id": 1, "name": 1 }),
                ],
            },
            // Tunnel audit log — 90-day retention mirroring remote_audit.
            // Compound index on (tenant_id, dst_host, at) backs the admin
            // "who connected to X in the last 7 days?" query in T4. The
            // standalone (session_id, at) entry mirrors the remote_audit
            // pattern for per-session reconstruction.
            IndexSet {
                collection: "tunnel_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tunnel_session_id": 1, "at": 1 }),
                    index(bson::doc! { "tenant_id": 1, "dst_host": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // FR-40 overlay-key rotation orders — who ordered which device to
            // retire its key, dispatched or refused. Same 90-day TTL as the
            // other audit logs.
            IndexSet {
                collection: "key_rotation_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "agent_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // FR-19 peer-relay decisions — approvals (who made a device a
            // relay) and mints (what was routed through it), granted or
            // refused. `agent_id` answers both halves of the incident-review
            // question in one query, `requester_node_id` is what a rate-limit
            // forensics pass walks, and the TTL is the same 90 days as the
            // other decision logs: making a device a chokepoint for the
            // tenant's traffic is the same class of event as opening exec on
            // it.
            IndexSet {
                collection: "peer_relay_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "requester_node_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // Roomler-SSH grant decisions. Same three questions as
            // `exec_audit`, same 90-day TTL — an SSH session is the bigger
            // power of the two, so its log must not be the shorter-lived one.
            IndexSet {
                collection: "ssh_audit",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "user_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // Roomler-SSH session activity (P8) — what devices REPORT doing
            // inside a session, as opposed to `ssh_audit`'s record of what the
            // server DECIDED. Separate collection on purpose (see
            // `SshActivityEvent`): one is authoritative, the other is a claim
            // by the host. Same 90-day TTL, and `grant_id` is indexed because
            // correlating a reported action back to the authoritative
            // decision row is the main thing a reader does here.
            IndexSet {
                collection: "ssh_activity",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "at": -1 }),
                    index(bson::doc! { "agent_id": 1, "at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "grant_id": 1, "at": -1 }),
                    index_ttl(bson::doc! { "at": 1 }, 90 * 24 * 60 * 60),
                ],
            },
            // Wave 3 — per-user usage reads scan the tunnel audit by (user,
            // time); its tenant-leading indexes could not serve a cross-org
            // "what did this user do" query.
            IndexSet {
                collection: "tunnel_audit",
                pre_ops: Vec::new(),
                indexes: vec![index(bson::doc! { "user_id": 1, "at": -1 })],
            },
            // FR-105 — SSH grants waiting for a Windows device's SYSTEM
            // service, as `exec_pending` holds its commands. `grant_id` is
            // unique: the claim, the cancel and the waiter's poll each address
            // ONE row by it. The TTL only keeps the collection small; a stale
            // claim is refused by the claim's own `claim_by` filter.
            IndexSet {
                collection: "ssh_pending",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "grant_id": 1 }),
                    index_ttl(bson::doc! { "expires_at": 1 }, 0),
                ],
            },
        ]
    }

    /// The inverse edges: the agent cascade (the overlay lease release BEFORE
    /// the row delete and the kick, the MagicDNS rename propagation, the
    /// tunnel-busy answer to fleet's nudge) and the tenant cascade (release
    /// every mesh node, quarantine the block) — registered under this
    /// module's id, run in `HOOK_ORDER`.
    fn hooks(&self) -> Hooks {
        Hooks {
            fleet: Some(Arc::new(hooks::NetworkHooks {
                state: self.clone(),
            })),
            tenant: Some(Arc::new(hooks::NetworkTenantHooks {
                state: self.clone(),
            })),
            session: None,
        }
    }

    /// `/derp` — the pubkey-addressed relay for the both-UDP-blocked carrier
    /// tier — is this module's upgrade endpoint (P7b). The host mounts it at
    /// the root next to `/ws`; the path never moves (agents dial it across
    /// every release).
    fn ws(&self) -> WsRegistration {
        WsRegistration {
            handlers: Vec::new(),
            upgrades: vec![UpgradeSpec {
                path: "/derp",
                router: Router::new()
                    .route("/derp", get(derp::derp_upgrade))
                    .with_state(self.clone()),
            }],
        }
    }

    /// C-6 — release the directory records for the tunnel sessions and derp
    /// registrations this pod owns, so a graceful deploy hands each entity
    /// off with a ZERO-length ownerless window instead of waiting out the
    /// 90 s TTLs. Runs before fleet's agent sweep (reverse composition order),
    /// exactly where the host's `shutdown_cleanup` ran it.
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        let state = self.clone();
        async move {
            let Some(dir) = &state.cluster_directory else {
                return;
            };
            // Tunnel session records (their sessions die with this pod; the
            // CLI redials and re-opens on the survivor).
            let held: Vec<(ObjectId, String)> = state
                .tunnel_presence_tokens
                .iter()
                .map(|e| (*e.key(), e.value().clone()))
                .collect();
            for (sid, token) in held {
                state.tunnel_presence_tokens.remove(&sid);
                let _ = dir
                    .release(
                        &roomler_core::cluster::directory::tunnel_key(&sid.to_hex()),
                        &token,
                    )
                    .await;
            }
            // Derp registrations (+ the per-network member index, so the
            // survivor's convergence sweep sees a clean roster).
            let held: Vec<(derp_types::DerpKey, String)> = state
                .derp_presence_tokens
                .iter()
                .map(|e| (*e.key(), e.value().clone()))
                .collect();
            for ((net, pk), token) in held {
                state.derp_presence_tokens.remove(&(net, pk));
                let net_hex = net.to_hex();
                let member = derp_cluster::pk_hex(&pk);
                if let Ok(true) = dir
                    .release(
                        &roomler_core::cluster::directory::derp_key(&net_hex, &member),
                        &token,
                    )
                    .await
                {
                    let _ = dir
                        .set_remove(
                            &roomler_core::cluster::directory::derpnet_key(&net_hex),
                            &member,
                        )
                        .await;
                }
            }
        }
    }
}
