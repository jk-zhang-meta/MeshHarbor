// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::oid::ObjectId;
use mongodb::Database;
use roomler_ai_config::Settings;
use roomler_ai_services::{
    AuthService, EmailService, OAuthService, PushService, TaskService,
    dao::{
        activation_code::ActivationCodeDao, invite::InviteDao, notification::NotificationDao,
        overlay_network::OverlayNetworkDao, push_subscription::PushSubscriptionDao, role::RoleDao,
        tenant::TenantDao, user::UserDao,
    },
};
use roomler_core::turn::build_turn_map;

use std::sync::Arc;

use crate::core_state::Core;
use crate::ws::redis_pubsub::RedisPubSub;
use crate::ws::storage::WsStorage;

#[derive(Clone)]
pub struct AppState {
    /// FR-69 P1 — the 27 core fields (identity, tenancy, notifications,
    /// storage, the socket registry, the cluster bus, TURN credentials,
    /// metering). `AppState` derefs to it, so `state.settings`,
    /// `state.users` and the rest read exactly as before, while the
    /// module-owned fields below wait for their module PRs. See
    /// [`crate::core_state`].
    pub core: Core,

    /// FR-69 P2 — the module crates this build links, initialised (or `None`
    /// where the operator switched one off). Mounted by `build_router`;
    /// their index sets applied by the host after the core plan. P4 — the
    /// mediasoup room manager, the recordings DAO and the media cluster maps
    /// live on `modules.conference` now; the host holds no room state.
    pub modules: crate::compose::Modules,
    // FR-69 P7b — nothing pillar-owned is left here. The fleet handles the
    // host aliased since P5a and the sockets' live state (tunnel session
    // maps, presence tokens, the DERP ticket signer) are their modules';
    // the composition views that need a module reach it through
    // `modules.fleet` / `modules.network`, absent when it is not mounted.
}

/// FR-69 P1 — every `state.<core field>` in the tree keeps reading through
/// this. Transitional on purpose: when the last module-owned field has left
/// `AppState` (P7), the host state IS the core and this goes with it.
impl std::ops::Deref for AppState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

impl AppState {
    /// The fleet module's state, for callers that KNOW it is mounted — the
    /// integration tests (which build every module) and nothing in the host
    /// since P7b: host code that may run without the module reads
    /// `modules.fleet` and handles `None`.
    #[cfg(feature = "fleet")]
    pub fn fleet(&self) -> &roomler_ai_mod_fleet::FleetState {
        self.modules
            .fleet
            .as_ref()
            .expect("the fleet module is mounted")
    }

    /// The network module's state, under the same rule as [`Self::fleet`].
    #[cfg(feature = "network")]
    pub fn network(&self) -> &roomler_ai_mod_network::NetworkState {
        self.modules
            .network
            .as_ref()
            .expect("the network module is mounted")
    }
}

impl AppState {
    pub async fn new(db: Database, settings: Settings) -> anyhow::Result<Self> {
        let auth = Arc::new(AuthService::new(settings.jwt.clone()));
        // A secret rotation is otherwise invisible in the record. The correct
        // shape is `verify_keys` going 1 → 2 while `signing_kid` changes; a new
        // `signing_kid` with `verify_keys=1` is the flag-day mistake — every
        // live token, including every agent's one-year token, just died.
        {
            let (signing_kid, verify_keys) = auth.key_summary();
            tracing::info!(%signing_kid, verify_keys, "jwt: signing key");
        }
        let users = Arc::new(UserDao::new(&db));
        let activation_codes = Arc::new(ActivationCodeDao::new(&db));
        let tenants = Arc::new(TenantDao::new(&db));
        let invites = Arc::new(InviteDao::new(&db));
        let notifications = Arc::new(NotificationDao::new(&db));
        let roles = Arc::new(RoleDao::new(&db));
        let tasks = Arc::new(TaskService::new(&db));

        let ws_storage = Arc::new(WsStorage::new());

        let oauth = if !settings.oauth.google.client_id.is_empty()
            || !settings.oauth.facebook.client_id.is_empty()
            || !settings.oauth.github.client_id.is_empty()
            || !settings.oauth.linkedin.client_id.is_empty()
            || !settings.oauth.microsoft.client_id.is_empty()
        {
            Some(Arc::new(OAuthService::new(settings.oauth.clone())))
        } else {
            None
        };

        // `from_settings` picks SendGrid when `email.api_key` is set
        // (prod), SMTP when `email.smtp_host` + `email.smtp_port` are
        // set (e2e Mailpit), or returns None otherwise (dev / no email).
        let email = EmailService::from_settings(&settings.email).map(Arc::new);

        let push_subscriptions = Arc::new(PushSubscriptionDao::new(&db));
        let push = if !settings.push.vapid_private_key.is_empty() {
            match PushService::new(
                &settings.push.vapid_private_key,
                settings.push.contact.clone(),
            ) {
                Ok(svc) => Some(Arc::new(svc)),
                Err(e) => {
                    tracing::warn!("Failed to initialize push service: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let storage = Arc::new(crate::storage::FileStorage::from_settings(&settings.s3)?);

        // C-1 — cluster identity precedes the Redis layer: the pub/sub
        // origin, the ownership directory and the per-pod bus all speak
        // `<pod_id>/<epoch>`.
        let pod = crate::cluster::identity::PodIdentity::resolve(settings.app.pod_id.clone());
        tracing::info!(pod_id = %pod.pod_id, epoch = %pod.epoch, "cluster identity resolved");

        let redis_pubsub = match RedisPubSub::new(&settings.redis.url, pod.origin()).await {
            Ok(ps) => Some(Arc::new(ps)),
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize Redis Pub/Sub: {} — cross-instance WS delivery disabled",
                    e
                );
                None
            }
        };

        // C-1 — ownership directory + per-pod bus, both riding the
        // pub/sub publisher's connection manager. Absent Redis ⇒ absent
        // cluster layer ⇒ every consumer fails soft to pod-local
        // behavior (the standing degradation rule). Constructed HERE
        // (not main.rs) so two-pod TestApps exercise them.
        let (cluster_directory, cluster_bus) = match &redis_pubsub {
            Some(ps) => (
                Some(crate::cluster::directory::OwnershipDirectory::new(
                    ps.connection(),
                    pod.origin(),
                )),
                Some(crate::cluster::bus::PodBus::start(
                    pod.clone(),
                    ps.connection(),
                    settings.redis.url.clone(),
                )),
            ),
            None => (None, None),
        };
        // FR-115 P3b — remote-session slots, on the same connection manager
        // and the same fail-soft rule; scoped to this database.
        let session_slots = redis_pubsub.as_ref().map(|ps| {
            roomler_core::cluster::session_slots::SessionSlots::new(ps.connection(), db.name())
        });

        // Remote-control subsystem
        let used_tokens = Arc::new(roomler_ai_services::dao::used_token::UsedTokenDao::new(&db));
        let stats = Arc::new(roomler_ai_services::dao::stats::StatsDao::new(&db));
        // Stats PR-3 — malformed allowlist entries are skipped LOUDLY (a
        // silent skip would read as "dashboards mysteriously 404").
        let platform_admins: std::collections::HashSet<ObjectId> = settings
            .stats
            .platform_admins
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                if s.is_empty() {
                    return None;
                }
                match ObjectId::parse_str(s) {
                    Ok(id) => Some(id),
                    Err(_) => {
                        tracing::warn!(
                            entry = %s,
                            "ROOMLER__STATS__PLATFORM_ADMINS entry is not a 24-hex ObjectId — skipped"
                        );
                        None
                    }
                }
            })
            .collect();
        if !platform_admins.is_empty() {
            tracing::info!(count = platform_admins.len(), "platform admins configured");
        }
        let platform_admins = Arc::new(platform_admins);
        let geoip = Arc::new(crate::user_analytics::GeoIp::open(
            settings.stats.geoip_mmdb.as_deref(),
        ));

        let turn_map = Arc::new(build_turn_map(&settings));
        // P6b — live per-region load (written by the /stats poller, consulted
        // at issuance). Spawned only when regions are enabled and at least
        // one carries a derp_url (the stats host). The stats sink makes each
        // poll tick durable (`stats_relay` buckets) when stats are enabled.
        let relay_load: roomler_ai_remote_control::turn_creds::RelayLoadMap = Default::default();
        crate::relay_load::spawn_poller(
            turn_map.clone(),
            relay_load.clone(),
            &settings.relay,
            settings.stats.enabled.then(|| stats.clone()),
            // FR-20 B — the network → tenant resolver. Gated on the same flag:
            // stats off ⇒ no metering, and the load poller is unaffected.
            //
            // A plain DAO rather than the configured `overlay_networks` below:
            // that one is constructed later in this function AND carries the
            // block-prefix allocator config, which only the ALLOCATION paths
            // need. The poller does exactly one read — `_id` → `tenant_id` —
            // so a read-only instance is both sufficient and honest about it.
            settings
                .stats
                .enabled
                .then(|| Arc::new(OverlayNetworkDao::new(&db))),
            // FR-115 P4a-2 — the over-allowance set, pushed to the PoPs on
            // the same poll. Not gated on stats (it is a throttle, not
            // metering); without Redis or a ticket key, no push, and no PoP
            // throttles.
            redis_pubsub.clone().and_then(|redis| {
                crate::relay_load::AllowancePush::new(&settings.relay, redis, db.name())
            }),
        );

        // C-1 — the directory heartbeat: every 30 s, re-assert this pod's
        // agent presence records (gated on STILL holding the hub slot).
        // Redundant with the per-received-heartbeat refresh in the socket
        // handler — deliberately: this sweep is the single pattern later
        // stages extend to tunnel/derp/media registries, and it heals a
        // record lost to a Redis flap even while the agent is quiet.
        // A CONFLICT (foreign owner) is the fold signal: log it; the
        // socket-level machinery (displacement Goodbye / A2b counter)
        // owns the reaction.
        // C-2 — the global-channel subscriber + forwarder, MOVED here from
        // main.rs so two-pod TestApps exercise cross-pod delivery (chat,
        // presence, and the new rc ctrl events). Same reconnect-and-backoff
        // subscription; the forwarder gains the ctrl lane.
        let redis_sub_alive = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // FR-69 P1/P5a — the core, then the modules, BEFORE the host tasks
        // below: the fleet module's init builds the Hub and the presence and
        // nudge maps that the global-channel subscriber, the nudge handler
        // and the tail spawns capture. The core's fields are cloned in
        // (every one is an `Arc`, a handle, or `Settings` once), so the
        // locals stay usable for the rest of the constructor.
        let core = Core {
            db: db.clone(),
            settings: settings.clone(),
            auth: auth.clone(),
            users: users.clone(),
            activation_codes: activation_codes.clone(),
            tenants: tenants.clone(),
            invites: invites.clone(),
            roles: roles.clone(),
            notifications: notifications.clone(),
            oauth: oauth.clone(),
            email: email.clone(),
            push: push.clone(),
            push_subscriptions: push_subscriptions.clone(),
            used_tokens: used_tokens.clone(),
            tasks: tasks.clone(),
            ws_storage: ws_storage.clone(),
            redis_pubsub: redis_pubsub.clone(),
            redis_sub_alive: redis_sub_alive.clone(),
            storage: storage.clone(),
            stats: stats.clone(),
            platform_admins: platform_admins.clone(),
            geoip: geoip.clone(),
            business_zones: Default::default(),
            pod: pod.clone(),
            cluster_directory: cluster_directory.clone(),
            session_slots: session_slots.clone(),
            cluster_bus: cluster_bus.clone(),
            turn_map: turn_map.clone(),
            relay_load: relay_load.clone(),
            hooks: roomler_core::HookRegistry::default(),
            agent_socket: roomler_core::AgentSocketRegistry::default(),
            // FR-115 — plans bind only where they are sold (`saas` compiled
            // in and switched on); self-hosting stays free and unlimited.
            plans_sold: cfg!(feature = "saas") && settings.modules.saas,
        };
        // FR-69 P2 — the module crates, after the core and before the host
        // state that mounts them.
        let modules = crate::compose::Modules::init(core.clone(), &core.settings).await?;
        // P5a — the host serves the agent socket from the fleet module's
        // handles until P5b moves the socket; a build that switches fleet
        // off has nothing to serve it from, so it refuses to boot rather
        // than come up with a dead socket.
        // FR-69 P7b — every pillar is a module now; a switched-off module is
        // simply not mounted, and the host's two cross-pod ctrl lanes below
        // skip the arm whose owner is absent.
        // #1186 — `overlay_removes` ctrl envelopes need the FULL state to
        // re-fan (a Mongo peer read + the overlay send paths), which this
        // subscriber closure cannot capture (it is spawned mid-construction;
        // `apply_rc_ctrl` is hub-only for the same reason). The network
        // module owns the channel and its applier (P7a); the subscriber only
        // holds the sender. Bounded + try_send: losing one under pressure
        // costs a push the peer's rejoin heals.
        let overlay_ctrl_tx = modules.overlay_ctrl_sender();
        if let Some(pubsub) = &redis_pubsub {
            let (redis_tx, _) = tokio::sync::broadcast::channel::<String>(1024);
            let mut redis_rx = redis_tx.subscribe();
            let own_instance = pubsub.instance_id().to_string();
            let fwd_storage = ws_storage.clone();
            let ctrl_modules = modules.clone();
            RedisPubSub::subscribe_with_reconnect(
                settings.redis.url.clone(),
                redis_tx,
                redis_sub_alive.clone(),
            );
            tokio::spawn(async move {
                loop {
                    match redis_rx.recv().await {
                        Ok(payload) => {
                            let Ok(envelope) = serde_json::from_str::<serde_json::Value>(&payload)
                            else {
                                continue;
                            };
                            // Self-echo guard: this instance already delivered
                            // locally at publish time.
                            if envelope["origin"].as_str() == Some(own_instance.as_str()) {
                                continue;
                            }
                            // C-2 — rc control events (consent verdicts, admin
                            // kicks): idempotent hub operations every pod
                            // applies locally; the one holding the entity acts.
                            if let Some(ctrl) = envelope.get("ctrl") {
                                // #1186 — the one state-needing ctrl event
                                // rides its own channel to the post-
                                // construction applier.
                                if ctrl.get("evt").and_then(|v| v.as_str())
                                    == Some("overlay_removes")
                                {
                                    if let Some(tx) = &overlay_ctrl_tx {
                                        let _ = tx.try_send(ctrl.clone());
                                    }
                                    continue;
                                }
                                ctrl_modules.apply_rc_ctrl(ctrl);
                                continue;
                            }
                            // C-4 — conn-addressed delivery (media replies +
                            // pushes from a room's owner pod): whichever pod
                            // holds the socket delivers; everyone else drops.
                            if let Some(conn) = envelope["conn"].as_str() {
                                if let Some(message) = envelope.get("message") {
                                    crate::ws::dispatcher::send_to_connection(
                                        &fwd_storage,
                                        conn,
                                        message,
                                    )
                                    .await;
                                }
                                continue;
                            }
                            // S6 broadcast envelopes (presence fan-out): each
                            // pod delivers to its own local connections.
                            if envelope["broadcast"].as_bool() == Some(true) {
                                if let Some(message) = envelope.get("message") {
                                    let ids = fwd_storage.all_user_ids();
                                    crate::ws::dispatcher::broadcast(&fwd_storage, &ids, message)
                                        .await;
                                }
                                continue;
                            }
                            if let (Some(user_ids_val), Some(message)) =
                                (envelope["user_ids"].as_array(), envelope.get("message"))
                            {
                                let ids: Vec<ObjectId> = user_ids_val
                                    .iter()
                                    .filter_map(|v| {
                                        v.as_str().and_then(|s| ObjectId::parse_str(s).ok())
                                    })
                                    .collect();
                                crate::ws::dispatcher::broadcast(&fwd_storage, &ids, message).await;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("Redis Pub/Sub forwarder lagged; dropped {n} events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                tracing::error!("Redis Pub/Sub forwarding task ended (channel closed)");
            });
            tracing::info!("Redis Pub/Sub cross-instance WS delivery enabled");

            // S6 — online-registry heartbeat (also moved from main.rs).
            let hb_pubsub = pubsub.clone();
            let hb_storage = ws_storage.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    for uid in hb_storage.all_user_ids() {
                        if let Err(e) = hb_pubsub.online_add(&uid.to_hex()).await {
                            tracing::debug!("online-registry heartbeat failed: {e}");
                            break; // Redis down — retry whole set next tick.
                        }
                    }
                }
            });
        }

        let state = Self { core, modules };

        // FR-69 P4 — the media claim-or-route bus handlers + claim heartbeat
        // and the media sampler are wired by the `conference` module's init.
        // PR-2 — the cross-pod rc signalling relay is wired by the `remote`
        // module's init (FR-69 P6).
        // #1186 — the cross-pod `overlay_removes` applier is spawned by the
        // network module's init (P7a); the subscriber above feeds its channel.
        // Stats PR-1 — the rollup compactor (raw → _1h → _1d), cluster-
        // singleton per cycle via the same DB-name-scoped claim pattern.
        // No-op task when `stats.enabled=false`.
        crate::stats_rollup::spawn_stats_rollup(state.clone());
        // FR-102 P1d — the daily growth digest: once the clock passes
        // `growth.digest_hour_utc`, yesterday's digest is computed, stored
        // and mailed once (the `growth_digests._id` insert decides which pod).
        // No-op unless `growth.digest_enabled` (default OFF).
        crate::growth::digest::spawn_digest_loop(state.clone());
        // FR-102 P2 — the nightly `growth_org_daily` fold: once per UTC day
        // per cluster (a Redis claim keyed by the day), the last three
        // closed days are recomputed; an empty collection is first filled
        // over the sources' horizon. No-op unless `growth.enabled`.
        crate::growth::org_daily::spawn_org_daily_loop(state.clone());
        // FR-102 P10 — the weekly roll-up (once the clock passes Monday
        // `digest_hour_utc`, the past ISO week is computed, stored in
        // `growth_weekly` and mailed once through the digest's claim) and
        // the alert evaluator (hourly; a rule opens one `growth_alerts` row,
        // mails once a day, clears itself). No-ops unless
        // `growth.weekly_enabled` / `growth.alerts` (both default OFF).
        crate::growth::weekly::spawn_weekly_loop(state.clone());
        crate::growth::alerts::spawn_alert_loop(state.clone());

        // FR-69 P5a — the inverse edges (D6). Each mounted module registers
        // its hooks (since P7a that includes the network steps of the agent
        // cascade — overlay release, MagicDNS rename — under the module's own
        // id), so the fleet module's cascades run in HOOK_ORDER through the
        // core registry.
        state.modules.register_hooks(&state.core);

        Ok(state)
    }
}

/// Phase A-1 graceful shutdown (SIGTERM/CTRL-C): make this pod's death
/// honest BEFORE the process exits, so a roll never strands
/// `agents.status = 'Online'` rows + stale presence claims (the
/// green-but-dead badge class). Budget: well under the ~3 s drain window
/// `main.rs` allows.
///
/// Mechanics: fire every registered agent's displacement-cancel notify —
/// each read loop exits within milliseconds and runs its OWN teardown
/// (identity-gated unregister, mark-offline, presence compare-DEL); the
/// bulk writes below are belt-and-braces for sockets that don't finish
/// in time. Agents see a plain socket close (never a Goodbye — those are
/// fatal client-side) and reconnect with backoff through the LB.
pub async fn shutdown_cleanup(state: &AppState) {
    // FR-69 P4/P5a/P7b — the modules release what they own, in reverse
    // composition order: network its tunnel-session and derp-registration
    // directory records (C-6: a graceful deploy hands each entity off with
    // a ZERO-length ownerless window instead of waiting out the 90 s TTLs),
    // then fleet the agent sweep (cancel every local agent socket, bulk-mark
    // them Offline, compare-DEL their presence claims), then conference its
    // media claims. The host holds nothing of its own to release any more.
    state.modules.shutdown().await;
}

#[cfg(test)]
mod notify_semantics_tests {

    /// A `Notify` signal must survive a task that is NOT parked on
    /// `notified()` at the instant it is fired.
    ///
    /// These two tests outlive FR-28's reverted P0 on purpose. The hazard
    /// is general: anywhere a `select!`-driven loop is signalled, the
    /// future is rebuilt each iteration, so there is no registered waiter
    /// while the loop is doing work. `notify_waiters` drops the signal
    /// there; `notify_one` stores a permit. FR-28 P0 shipped the wrong one
    /// and the field measured it (12 `hard-errored` lines vs a baseline of
    /// 8) — the code is gone, the lesson should not be.
    ///
    /// ⚠️ This is the test the first version needed and did not have. It
    /// only checked the env kill switch, which cannot observe the defect:
    /// `notify_waiters()` wakes waiters registered AT THAT MOMENT and
    /// stores nothing, while the real socket loop rebuilds its
    /// `cancel.notified()` future every `select!` iteration. So exactly
    /// the busy sockets — the ones carrying a live session — missed it,
    /// and the field test measured MORE `hard-errored` lines (12) than
    /// the undrained baseline (8).
    #[tokio::test]
    async fn cancel_reaches_a_socket_that_is_not_currently_awaiting() {
        let cancel = std::sync::Arc::new(tokio::sync::Notify::new());

        // Fire while nobody is parked — the busy-forwarding case.
        cancel.notify_one();

        // The loop comes back around and awaits: it must return at once.
        let woke =
            tokio::time::timeout(std::time::Duration::from_millis(200), cancel.notified()).await;
        assert!(
            woke.is_ok(),
            "a cancel fired while the socket was busy must still be observed"
        );
    }

    /// The same shape with `notify_waiters`, pinned so the difference is
    /// documented rather than rediscovered: it is LOST when nobody waits.
    #[tokio::test]
    async fn notify_waiters_loses_a_signal_when_nobody_is_parked() {
        let cancel = std::sync::Arc::new(tokio::sync::Notify::new());
        cancel.notify_waiters();
        let woke =
            tokio::time::timeout(std::time::Duration::from_millis(100), cancel.notified()).await;
        assert!(
            woke.is_err(),
            "notify_waiters stores no permit — this is the bug"
        );
    }
}
