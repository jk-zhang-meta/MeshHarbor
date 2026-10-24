// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-69 — the host's composition: which module crates this build links,
//! which of them the operator switched on, and how they are mounted.
//!
//! Static on purpose (spec D4): every module is a concrete type behind a
//! Cargo feature and a `#[cfg]` block here, so a module that forgets its
//! routes, indexes or hooks does not compile, and the set of modules a
//! binary carries is readable in one place. The runtime switch
//! (`[modules] <id> = false`) is the per-module kill switch during the roll
//! that introduced it: the module still links, but nothing of it is mounted.
//!
//! Until every pillar has been extracted, the host's own routes and state
//! carry the rest; `EXTRACTED` says which switches actually do something, and
//! `init` says so at boot for the ones that do not yet.
//!
//! P4 added the three surfaces a stateful module needs beyond routes:
//! [`Modules::ws_closed`] (a socket closed — every handler for that role is
//! told), [`Modules::run_startup_jobs`] (the host's startup lease drives the
//! modules' leader-gated jobs) and [`Modules::shutdown`] (reverse composition
//! order). P5a added [`Modules::register_hooks`] (each module's inverse edges
//! into the core registry) and `fleet` — the one module the host cannot run
//! without yet: its handles still serve the host's network code, so `fleet`
//! is a required dependency and its switch refuses to boot rather than
//! unmounting (spec: the P5 kill switch is "redeploy the previous tag").
//! P6 added `remote`, the first module built ON another (`remote → fleet`):
//! its `Module::Deps` is the fleet state, supplied here in composition order
//! — and the two host → module calls the controller socket makes
//! ([`Modules::remote_controller_frame`], [`Modules::remote_conn_closed`]),
//! because the socket mints the controller's Hub sender and the module's
//! dispatch needs it.

use std::sync::Arc;

use axum::Router;
use roomler_ai_config::Settings;
use roomler_core::{
    Core, IndexSet, Job, Module, Role, WsCtx, WsHandler, WsHandlerSpec, graph, job::Cadence,
};
use tracing::{error, info, warn};

/// The module ids whose crates exist — the switches that are effective.
pub const EXTRACTED: &[&str] = &[
    #[cfg(feature = "saas")]
    "saas",
    #[cfg(feature = "chat")]
    "chat",
    #[cfg(feature = "conference")]
    "conference",
    #[cfg(feature = "fleet")]
    "fleet",
    #[cfg(feature = "remote")]
    "remote",
    #[cfg(feature = "network")]
    "network",
    #[cfg(feature = "hive")]
    "hive",
    #[cfg(feature = "vault")]
    "vault",
];

/// The modules this build links, initialised — `None` where the operator
/// switched one off.
#[derive(Clone, Default)]
pub struct Modules {
    #[cfg(feature = "saas")]
    pub saas: Option<roomler_ai_mod_saas::SaasState>,
    #[cfg(feature = "chat")]
    pub chat: Option<roomler_ai_mod_chat::ChatState>,
    #[cfg(feature = "conference")]
    pub conference: Option<roomler_ai_mod_conference::ConferenceState>,
    /// P5a/P7b — device management; `None` when switched off (the agent
    /// socket is then refused with 503 and the device listing shows no
    /// agents).
    #[cfg(feature = "fleet")]
    pub fleet: Option<roomler_ai_mod_fleet::FleetState>,
    /// P6 — built on `fleet`; `None` when switched off (the controller's
    /// `rc:*` frames then fall through unhandled and the session routes are
    /// absent, while the Hub — fleet's — keeps serving the agents).
    #[cfg(feature = "remote")]
    pub remote: Option<roomler_ai_mod_remote::RemoteState>,
    /// P7 — built on `fleet`; `None` when switched off (the tunnel-client
    /// socket is refused with 503, `/derp` is not mounted, the overlay and
    /// tunnel routes are absent).
    #[cfg(feature = "network")]
    pub network: Option<roomler_ai_mod_network::NetworkState>,
    /// FR-90 — agent sessions, built on `fleet`; `None` when switched off
    /// (the default): the session routes are absent and a device's
    /// `rc:hive.*` frames reach no handler.
    #[cfg(feature = "hive")]
    pub hive: Option<roomler_ai_mod_hive::HiveState>,
    /// FR-90 P3-1 — the vault, on core alone; `None` when switched off (the
    /// default): its routes are absent.
    #[cfg(feature = "vault")]
    pub vault: Option<roomler_ai_mod_vault::VaultState>,
    /// Every mounted module's WebSocket namespace handlers, collected at
    /// init so the socket dispatch can look one up per message.
    ws: Vec<WsHandlerSpec>,
}

impl Modules {
    /// Initialise every linked module the settings do not switch off, in
    /// composition order (`graph::MODULES`) — so a module's `Deps` are
    /// always initialised before it. Logs each switch that is off for a
    /// module that is not extracted yet — that switch unmounts nothing.
    pub async fn init(core: Core, settings: &Settings) -> anyhow::Result<Self> {
        for id in settings.switched_off() {
            // A default-off module (FR-90 `hive`) that this build does not
            // link is the default state, not something an operator did.
            if !EXTRACTED.contains(&id)
                && !roomler_ai_config::ModulesSettings::DEFAULT_OFF.contains(&id)
            {
                warn!(
                    module = id,
                    "[modules] switch is OFF in config but that module is not yet extracted — \
                     nothing is unmounted (FR-69)"
                );
            }
        }
        debug_assert!(
            EXTRACTED.iter().all(|id| graph::MODULES.contains(id)),
            "every extracted module must be in the graph"
        );

        #[allow(unused_mut)]
        let mut modules = Self::default();

        #[cfg(feature = "saas")]
        {
            modules.saas =
                init_one::<roomler_ai_mod_saas::SaasState>(core.clone(), settings, ()).await?;
            if let Some(m) = &modules.saas {
                modules.ws.extend(m.ws().handlers);
            }
        }
        #[cfg(feature = "chat")]
        {
            modules.chat =
                init_one::<roomler_ai_mod_chat::ChatState>(core.clone(), settings, ()).await?;
            if let Some(m) = &modules.chat {
                modules.ws.extend(m.ws().handlers);
            }
        }
        #[cfg(feature = "conference")]
        {
            modules.conference =
                init_one::<roomler_ai_mod_conference::ConferenceState>(core.clone(), settings, ())
                    .await?;
            if let Some(m) = &modules.conference {
                modules.ws.extend(m.ws().handlers);
            }
        }
        #[cfg(feature = "fleet")]
        {
            modules.fleet =
                init_one::<roomler_ai_mod_fleet::FleetState>(core.clone(), settings, ()).await?;
            if let Some(m) = &modules.fleet {
                modules.ws.extend(m.ws().handlers);
            }
        }
        #[cfg(feature = "remote")]
        {
            // `remote → fleet`: the Hub is one live object, so the module is
            // built on fleet's state rather than re-creating it. A fleet
            // that is switched off simply means no `remote` either — the
            // switch is logged by `init_one` for fleet.
            if let Some(fleet) = modules.fleet.clone() {
                modules.remote =
                    init_one::<roomler_ai_mod_remote::RemoteState>(core.clone(), settings, fleet)
                        .await?;
                if let Some(m) = &modules.remote {
                    modules.ws.extend(m.ws().handlers);
                }
            }
        }
        #[cfg(feature = "network")]
        {
            // `network → fleet`, the same seam.
            if let Some(fleet) = modules.fleet.clone() {
                modules.network =
                    init_one::<roomler_ai_mod_network::NetworkState>(core.clone(), settings, fleet)
                        .await?;
                if let Some(m) = &modules.network {
                    modules.ws.extend(m.ws().handlers);
                }
            }
        }
        #[cfg(feature = "hive")]
        {
            // `hive → fleet`, the same seam: a session's frames ride the
            // agent socket, and its gate reads the Hub's per-connection caps.
            // `hive → chat` (P0d): a session is a room. Chat is stateless and
            // hive re-creates what it needs of it, but a session nobody could
            // read is no session — so chat switched off means no `hive` too.
            if let Some(fleet) = modules.fleet.clone() {
                if modules.chat.is_some() {
                    modules.hive =
                        init_one::<roomler_ai_mod_hive::HiveState>(core.clone(), settings, fleet)
                            .await?;
                    if let Some(m) = &modules.hive {
                        modules.ws.extend(m.ws().handlers);
                    }
                } else if settings.hive_on() {
                    warn!(
                        "module hive is switched on but chat is off — hive is not mounted \
                         (a session is a chat room)"
                    );
                }
            }
        }
        #[cfg(feature = "vault")]
        {
            // No module state as a dependency: its `vault → hive` edge
            // (P3-3b) reads session records through hive's stateless DAO, so
            // a vault mounted without hive simply finds no session to lease
            // for. Its switch defaults off, like hive's.
            modules.vault =
                init_one::<roomler_ai_mod_vault::VaultState>(core.clone(), settings, ()).await?;
            if let Some(m) = &modules.vault {
                modules.ws.extend(m.ws().handlers);
            }
        }

        let _ = core;
        Ok(modules)
    }

    /// The module ids actually mounted on this pod.
    pub fn mounted(&self) -> Vec<&'static str> {
        #[allow(unused_mut)]
        let mut ids = Vec::new();
        #[cfg(feature = "saas")]
        if self.saas.is_some() {
            ids.push("saas");
        }
        #[cfg(feature = "chat")]
        if self.chat.is_some() {
            ids.push("chat");
        }
        #[cfg(feature = "conference")]
        if self.conference.is_some() {
            ids.push("conference");
        }
        #[cfg(feature = "fleet")]
        if self.fleet.is_some() {
            ids.push("fleet");
        }
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            ids.push("remote");
        }
        #[cfg(feature = "network")]
        if self.network.is_some() {
            ids.push("network");
        }
        #[cfg(feature = "hive")]
        if self.hive.is_some() {
            ids.push("hive");
        }
        #[cfg(feature = "vault")]
        if self.vault.is_some() {
            ids.push("vault");
        }
        ids
    }

    /// Mount every module's governed routes onto the `/api` router.
    pub fn mount<S>(&self, api: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        #[allow(unused_mut)]
        let mut api = api;
        #[cfg(feature = "saas")]
        if let Some(saas) = &self.saas {
            api = api.merge(saas.routes().with_state(()));
        }
        #[cfg(feature = "chat")]
        if let Some(chat) = &self.chat {
            api = api.merge(chat.routes().with_state(()));
        }
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            api = api.merge(conference.routes().with_state(()));
        }
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            api = api.merge(fleet.routes().with_state(()));
        }
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            api = api.merge(remote.routes().with_state(()));
        }
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            api = api.merge(network.routes().with_state(()));
        }
        #[cfg(feature = "hive")]
        if let Some(hive) = &self.hive {
            api = api.merge(hive.routes().with_state(()));
        }
        #[cfg(feature = "vault")]
        if let Some(vault) = &self.vault {
            api = api.merge(vault.routes().with_state(()));
        }
        api
    }

    /// Mount every mounted module's own upgrade endpoints at the root (P7b:
    /// `/derp` is the network module's). The paths never move — agents in
    /// the field dial them across every release.
    pub fn mount_upgrades<S>(&self, root: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        #[allow(unused_mut)]
        let mut root = root;
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            for up in network.ws().upgrades {
                root = root.merge(up.router.with_state(()));
            }
        }
        root
    }

    /// P7b — the `/ws?role=agent` upgrade is the fleet module's. A build or
    /// deployment without `fleet` answers 503: an agent that dials a pod
    /// with no fleet module must learn it is not a credential problem.
    #[allow(unused_variables)]
    pub async fn agent_upgrade(
        &self,
        token: String,
        tid: Option<String>,
        origin: roomler_core::client_ip::ConnectionOrigin,
        ws: axum::extract::WebSocketUpgrade,
    ) -> axum::response::Response {
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            return roomler_ai_mod_fleet::socket::ws_upgrade_agent(
                fleet.clone(),
                token,
                tid,
                origin,
                ws,
            )
            .await;
        }
        module_unavailable("fleet")
    }

    /// P7b — the `/ws?role=tunnel-client` upgrade is the network module's;
    /// 503 without it, for the same reason.
    #[allow(unused_variables)]
    pub fn tunnel_client_upgrade(
        &self,
        token: String,
        tid: Option<String>,
        origin: roomler_core::client_ip::ConnectionOrigin,
        ws: axum::extract::WebSocketUpgrade,
    ) -> axum::response::Response {
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            return roomler_ai_mod_network::tunnel::ws_upgrade_tunnel_client(
                network.clone(),
                token,
                tid,
                origin,
                ws,
            );
        }
        module_unavailable("network")
    }

    /// P7b — register a browser connection with the remote-control Hub
    /// (fleet's) so `rc:*` replies find it, and pump those replies onto the
    /// socket. `None` when fleet is not mounted: the tab has no controller
    /// plane, and its `rc:*` frames fall through unhandled.
    #[allow(unused_variables)]
    pub fn register_controller(
        &self,
        user_id: bson::oid::ObjectId,
        sender: roomler_core::ws::storage::WsSender,
    ) -> Option<ControllerRegistration> {
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            let (tx, rx) = fleet.rc_hub.register_controller(user_id);
            let pump = tokio::spawn(roomler_ai_mod_fleet::socket::pump_server_messages(
                rx, sender,
            ));
            return Some((tx, pump));
        }
        None
    }

    /// The inverse of [`Self::register_controller`], at socket close.
    #[allow(unused_variables)]
    pub fn unregister_controller(
        &self,
        user_id: bson::oid::ObjectId,
        rc: Option<&ControllerRegistration>,
    ) {
        #[cfg(feature = "fleet")]
        if let (Some(fleet), Some((tx, pump))) = (&self.fleet, rc) {
            fleet.rc_hub.unregister_controller(user_id, tx);
            pump.abort();
        }
    }

    /// P7b — apply one cross-pod rc control event (consent verdicts, admin
    /// kicks) to the local Hub; a no-op without fleet.
    #[allow(unused_variables)]
    pub fn apply_rc_ctrl(&self, ctrl: &serde_json::Value) {
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            roomler_ai_mod_fleet::ctrl::apply_rc_ctrl(&fleet.rc_hub, ctrl);
        }
    }

    /// P7b — the sender the host's Redis ctrl subscriber feeds cross-pod
    /// `overlay_removes` envelopes into (#1186); `None` without network.
    pub fn overlay_ctrl_sender(&self) -> Option<tokio::sync::mpsc::Sender<serde_json::Value>> {
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            return Some(network.overlay_ctrl_tx.clone());
        }
        None
    }

    /// The fleet module's live gauge for the cluster status snapshot:
    /// agents online on this pod. Zero when the module is not mounted.
    pub fn fleet_gauges(&self) -> FleetGauges {
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            return FleetGauges {
                agents_online: fleet.rc_hub.online_agents().len(),
            };
        }
        FleetGauges::default()
    }

    /// The network module's live gauges for the cluster status snapshot:
    /// tunnel sessions and DERP registrations on this pod. Zero when the
    /// module is not mounted.
    pub fn network_gauges(&self) -> NetworkGauges {
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            return NetworkGauges {
                tunnel_sessions: network.tunnel_clients_by_session.len(),
                derp_registrations: network.derp_registry.len(),
            };
        }
        NetworkGauges::default()
    }

    /// Mount every module's ungoverned routes onto the root router (the
    /// ones with their own authentication, like the Stripe webhook).
    pub fn mount_unlimited<S>(&self, root: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        #[allow(unused_mut)]
        let mut root = root;
        #[cfg(feature = "saas")]
        if let Some(saas) = &self.saas {
            root = root.merge(saas.unlimited_routes().with_state(()));
        }
        #[cfg(feature = "chat")]
        if let Some(chat) = &self.chat {
            root = root.merge(chat.unlimited_routes().with_state(()));
        }
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            root = root.merge(conference.unlimited_routes().with_state(()));
        }
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            root = root.merge(fleet.unlimited_routes().with_state(()));
        }
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            root = root.merge(remote.unlimited_routes().with_state(()));
        }
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            root = root.merge(network.unlimited_routes().with_state(()));
        }
        #[cfg(feature = "hive")]
        if let Some(hive) = &self.hive {
            root = root.merge(hive.unlimited_routes().with_state(()));
        }
        #[cfg(feature = "vault")]
        if let Some(vault) = &self.vault {
            root = root.merge(vault.unlimited_routes().with_state(()));
        }
        root
    }

    /// Every mounted module's index sets, in composition order, for the
    /// running deployment's settings. Applied by the host after the core plan.
    pub fn index_sets(&self) -> Vec<IndexSet> {
        #[allow(unused_mut)]
        let mut sets = Vec::new();
        #[cfg(feature = "saas")]
        if let Some(saas) = &self.saas {
            sets.extend(saas.indexes());
        }
        #[cfg(feature = "chat")]
        if let Some(chat) = &self.chat {
            sets.extend(chat.indexes());
        }
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            sets.extend(conference.indexes());
        }
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            sets.extend(fleet.indexes());
        }
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            sets.extend(remote.indexes());
        }
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            sets.extend(network.indexes());
        }
        #[cfg(feature = "hive")]
        if let Some(hive) = &self.hive {
            sets.extend(hive.indexes());
        }
        #[cfg(feature = "vault")]
        if let Some(vault) = &self.vault {
            sets.extend(vault.indexes());
        }
        sets
    }

    /// The same sets for an explicit `multi_block` schema — what the
    /// composition snapshot records, once per schema (P7a: the overlay block
    /// registry's two plans are the network module's now).
    pub fn index_sets_for(&self, multi_block: bool) -> Vec<IndexSet> {
        #[allow(unused_mut)]
        let mut sets = Vec::new();
        #[cfg(feature = "saas")]
        if let Some(saas) = &self.saas {
            sets.extend(saas.indexes_for(multi_block));
        }
        #[cfg(feature = "chat")]
        if let Some(chat) = &self.chat {
            sets.extend(chat.indexes_for(multi_block));
        }
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            sets.extend(conference.indexes_for(multi_block));
        }
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            sets.extend(fleet.indexes_for(multi_block));
        }
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            sets.extend(remote.indexes_for(multi_block));
        }
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            sets.extend(network.indexes_for(multi_block));
        }
        #[cfg(feature = "hive")]
        if let Some(hive) = &self.hive {
            sets.extend(hive.indexes_for(multi_block));
        }
        #[cfg(feature = "vault")]
        if let Some(vault) = &self.vault {
            sets.extend(vault.indexes_for(multi_block));
        }
        sets
    }

    /// Every mounted module's declared jobs, in composition order.
    fn jobs(&self) -> Vec<Job> {
        #[allow(unused_mut)]
        let mut jobs = Vec::new();
        #[cfg(feature = "saas")]
        if let Some(saas) = &self.saas {
            jobs.extend(saas.jobs());
        }
        #[cfg(feature = "chat")]
        if let Some(chat) = &self.chat {
            jobs.extend(chat.jobs());
        }
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            jobs.extend(conference.jobs());
        }
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            jobs.extend(fleet.jobs());
        }
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            jobs.extend(remote.jobs());
        }
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            jobs.extend(network.jobs());
        }
        #[cfg(feature = "hive")]
        if let Some(hive) = &self.hive {
            jobs.extend(hive.jobs());
        }
        #[cfg(feature = "vault")]
        if let Some(vault) = &self.vault {
            jobs.extend(vault.jobs());
        }
        jobs
    }

    /// Register every mounted module's hooks (its inverse edges) into the
    /// core registry, under the module's id. The host adds its transitional
    /// implementations for the modules not extracted yet right after this.
    pub fn register_hooks(&self, core: &Core) {
        #[cfg(feature = "saas")]
        if let Some(saas) = &self.saas {
            core.hooks
                .register(roomler_ai_mod_saas::SaasState::ID, saas.hooks());
        }
        #[cfg(feature = "chat")]
        if let Some(chat) = &self.chat {
            core.hooks
                .register(roomler_ai_mod_chat::ChatState::ID, chat.hooks());
        }
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            core.hooks.register(
                roomler_ai_mod_conference::ConferenceState::ID,
                conference.hooks(),
            );
        }
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            core.hooks
                .register(roomler_ai_mod_fleet::FleetState::ID, fleet.hooks());
        }
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            core.hooks
                .register(roomler_ai_mod_remote::RemoteState::ID, remote.hooks());
        }
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            core.hooks
                .register(roomler_ai_mod_network::NetworkState::ID, network.hooks());
        }
        #[cfg(feature = "hive")]
        if let Some(hive) = &self.hive {
            core.hooks
                .register(roomler_ai_mod_hive::HiveState::ID, hive.hooks());
        }
        #[cfg(feature = "vault")]
        if let Some(vault) = &self.vault {
            core.hooks
                .register(roomler_ai_mod_vault::VaultState::ID, vault.hooks());
        }
    }

    /// Run every mounted module's startup jobs, in composition order — the
    /// leader-gated ones only when this pod holds the startup lease. A job
    /// that fails is logged and the next one runs: maintenance must never
    /// keep a pod from serving. Periodic jobs are declared but not scheduled
    /// by the host yet (no module needs one); a stray declaration is logged
    /// so it cannot be silently ignored.
    pub async fn run_startup_jobs(&self, leader: bool) {
        for job in self.jobs() {
            match job.cadence {
                Cadence::AtStartup => {
                    if job.leader_gated && !leader {
                        info!(
                            job = job.name,
                            "leader-gated startup job skipped — the lease is held elsewhere"
                        );
                        continue;
                    }
                    match (job.run)().await {
                        Ok(()) => info!(job = job.name, "startup job done"),
                        Err(e) => error!(job = job.name, %e, "startup job failed"),
                    }
                }
                Cadence::Every(_) => warn!(
                    job = job.name,
                    "periodic module jobs are not scheduled by the host yet (FR-69) — declared, not run"
                ),
            }
        }
    }

    /// The handler a module registered for this role and message type, if
    /// any. The namespace is the message type's prefix before the first
    /// `:` (`typing:start` → `typing`), matching how the wire groups.
    pub fn ws_handler(&self, role: Role, msg_type: &str) -> Option<Arc<dyn WsHandler>> {
        let namespace = msg_type.split(':').next().unwrap_or(msg_type);
        self.ws
            .iter()
            .find(|spec| spec.role == role && spec.namespace == namespace)
            .map(|spec| spec.handler.clone())
    }

    /// A socket closed: tell every handler registered for its role, in
    /// registration order, after the host's own cleanup.
    pub async fn ws_closed(&self, ctx: &WsCtx) {
        for spec in self.ws.iter().filter(|spec| spec.role == ctx.role) {
            spec.handler.closed(ctx).await;
        }
    }

    /// Orderly stop of every mounted module, in REVERSE composition order
    /// (a module stops before the ones it depends on).
    pub async fn shutdown(&self) {
        #[cfg(feature = "vault")]
        if let Some(vault) = &self.vault {
            vault.shutdown().await;
        }
        #[cfg(feature = "hive")]
        if let Some(hive) = &self.hive {
            hive.shutdown().await;
        }
        #[cfg(feature = "network")]
        if let Some(network) = &self.network {
            network.shutdown().await;
        }
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            remote.shutdown().await;
        }
        #[cfg(feature = "fleet")]
        if let Some(fleet) = &self.fleet {
            fleet.shutdown().await;
        }
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            conference.shutdown().await;
        }
        #[cfg(feature = "chat")]
        if let Some(chat) = &self.chat {
            chat.shutdown().await;
        }
        #[cfg(feature = "saas")]
        if let Some(saas) = &self.saas {
            saas.shutdown().await;
        }
    }

    /// Conference's orphaned-call closer, for the host's stats rollup loop.
    /// `(0, 0)` when the module is not mounted — there are no call sessions
    /// to close then.
    pub async fn close_orphaned_call_state(&self) -> (u64, u64) {
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            return roomler_ai_mod_conference::maintenance::close_orphaned_call_state(conference)
                .await;
        }
        (0, 0)
    }

    /// The live media gauges for the cluster status snapshot:
    /// `(per-room rows, participants_total, consumers_total)`. Empty when
    /// the module is not mounted.
    pub fn media_gauges(&self) -> (Vec<serde_json::Value>, usize, usize) {
        #[cfg(feature = "conference")]
        if let Some(conference) = &self.conference {
            let g = conference.media_gauges();
            return (g.rooms, g.participants_total, g.consumers_total);
        }
        (Vec::new(), 0, 0)
    }

    /// P6 — one `rc:*` text frame from a controller browser tab, with the
    /// connection's Hub-registered sender (minted by the host's socket, which
    /// is why this is a call and not a namespace handler). `true` = the
    /// module took it (dispatched, or answered a refusal on the sender);
    /// `false` = not an rc:* frame, or no `remote` module mounted.
    #[allow(clippy::too_many_arguments, unused_variables)]
    pub async fn remote_controller_frame(
        &self,
        user_id: bson::oid::ObjectId,
        controller_name: &str,
        controller_tx: &roomler_ai_remote_control::session::ClientTx,
        text: &str,
        dialed_tid: Option<&str>,
        conn_established_ms: i64,
        connection_id: &str,
    ) -> bool {
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            return roomler_ai_mod_remote::controller::handle_controller_frame(
                remote,
                roomler_ai_mod_remote::controller::ControllerFrame {
                    user_id,
                    controller_name,
                    controller_tx,
                    text,
                    dialed_tid,
                    conn_established_ms,
                    connection_id,
                },
            )
            .await;
        }
        false
    }

    /// P6 — a controller browser socket closed: the owner pods hosting rc
    /// sessions proxied for it are told (PR-2). A no-op when the module is
    /// not mounted.
    #[allow(unused_variables)]
    pub fn remote_conn_closed(&self, connection_id: &str) {
        #[cfg(feature = "remote")]
        if let Some(remote) = &self.remote {
            roomler_ai_mod_remote::relay::forward_conn_closed(remote, connection_id);
        }
    }
}

/// The fleet module's live gauge (`Modules::fleet_gauges`).
#[derive(Debug, Clone, Copy, Default)]
pub struct FleetGauges {
    pub agents_online: usize,
}

/// The network module's live gauges (`Modules::network_gauges`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkGauges {
    pub tunnel_sessions: usize,
    pub derp_registrations: usize,
}

/// What [`Modules::register_controller`] hands the user socket: the tab's
/// Hub sender (the `rc:*` dispatch addresses replies to it) and the task
/// pumping the Hub's replies onto the socket, aborted at close.
pub type ControllerRegistration = (
    roomler_ai_remote_control::session::ClientTx,
    tokio::task::JoinHandle<()>,
);

/// 503 for a socket role whose module this pod does not mount: the caller
/// dialed the right place with the right credential and must not read the
/// refusal as either being wrong.
#[allow(dead_code)]
fn module_unavailable(module: &str) -> axum::response::Response {
    warn!(
        module,
        "socket upgrade refused — module not mounted on this pod"
    );
    axum::response::Response::builder()
        .status(503)
        .body(format!("{module} module not mounted").into())
        .unwrap()
}

/// Initialise one module unless its switch is off.
#[allow(dead_code)]
async fn init_one<M: Module>(
    core: Core,
    settings: &Settings,
    deps: M::Deps,
) -> anyhow::Result<Option<M>> {
    if !M::enabled(settings) {
        info!(
            module = M::ID,
            "module switched off by config — not mounted"
        );
        return Ok(None);
    }
    let module = M::init(core, settings, deps).await?;
    info!(module = M::ID, "module mounted");
    Ok(Some(module))
}
