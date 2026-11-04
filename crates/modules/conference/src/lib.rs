// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `conference` — the mediasoup SFU rooms, the `media:*` WebSocket
//! namespace, the call lifecycle, recordings and the media sampler, as a
//! module (FR-69 P4).
//!
//! The collaboration pillar's real-time half, and the crate that owns
//! `mediasoup`: with P4 the C++ worker build leaves `services`, `core` and
//! the api crate's graphs — a profile without conferencing no longer compiles
//! it at all (spec D9). Rooms are chat's, which is why this crate depends on
//! `meshharbor-mod-chat` (for the room guards) and not the other way round.
//!
//! # Shape
//!
//! [`ConferenceState`] = [`Core`] + what conference owns: the two DAOs (rooms
//! for call state, recordings), the [`RoomManager`] over the worker pool, and
//! the two cluster maps (`media_claim_tokens`, `remote_media_conns`) the C-4
//! claim-or-route placement keeps per pod. It derefs to `Core`, so the moved
//! handlers read `state.ws_storage`, `state.stats`, `state.cluster_bus` as
//! they did on the host's `AppState`.
//!
//! Three contract surfaces are used here for the first time:
//!
//! - [`meshharbor_core::WsHandler::closed`] — a participant's transports and its
//!   call session must be dropped when its socket closes, not only on an
//!   explicit `media:leave`. The host tells every namespace handler about the
//!   close; this one acts.
//! - [`Module::jobs`] — the stale-call reset that ran inline in `main.rs`
//!   under the startup lease is now a leader-gated startup job the host runs
//!   under the same lease.
//! - [`Module::shutdown`] — the graceful release of this pod's media claims
//!   (a zero-length ownerless window on a deploy) moved out of the host's
//!   `shutdown_cleanup`.
//!
//! The bus handlers (`media.cmd`, `media.leave_user`, …) and the 10 s claim
//! heartbeat are wired in [`Module::init`] — they need only this state, so the
//! "registered on the built AppState" step the host used to run is gone.

use std::sync::Arc;

use axum::{
    Router,
    extract::FromRef,
    routing::{delete, get, post},
};
use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_config::Settings;
use meshharbor_db::indexes::{IndexSet, index, index_ttl};
use meshharbor_services::dao::{recording::RecordingDao, room::RoomDao};
use meshharbor_core::{
    Capabilities, Core, Job, Module, Role, TenantCtx, WsHandlerSpec, WsRegistration,
};

use crate::media::{room_manager::RoomManager, worker_pool::WorkerPool};

pub mod call;
pub mod guards;
pub mod maintenance;
pub mod media;
pub mod media_cluster;
pub mod media_stats;
pub mod meeting_cap;
pub mod recording;
pub mod ws_media;

/// The module's state: the core plus what conference owns.
#[derive(Clone)]
pub struct ConferenceState {
    pub core: Core,
    pub rooms: Arc<RoomDao>,
    pub recordings: Arc<RecordingDao>,
    pub room_manager: Arc<RoomManager>,
    /// C-4 — media rooms this pod OWNS (`meshharbor:own:media:<room>` claim
    /// tokens) — refreshed every 10 s, compare-DELed on close/shutdown.
    pub media_claim_tokens: Arc<DashMap<ObjectId, String>>,
    /// C-4 — connections that joined a room owned by ANOTHER pod
    /// (`connection_id → room_id`), so the socket close can tell the owner
    /// to drop the transports.
    pub remote_media_conns: Arc<DashMap<String, ObjectId>>,
}

impl std::ops::Deref for ConferenceState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<ConferenceState> for Core {
    fn from_ref(state: &ConferenceState) -> Self {
        state.core.clone()
    }
}

/// The live media gauges the cluster status snapshot reports (the
/// PipeTransport trigger inputs). Computed on demand — never stored.
#[derive(Debug, Default, Clone)]
pub struct MediaGauges {
    pub rooms: Vec<serde_json::Value>,
    pub participants_total: usize,
    pub consumers_total: usize,
}

impl ConferenceState {
    /// Per-room participant/consumer counts on this pod.
    pub fn media_gauges(&self) -> MediaGauges {
        let mut gauges = MediaGauges::default();
        for room in self.room_manager.rooms_ref().iter() {
            let participants = room.participants.len();
            let consumers: usize = room.participants.iter().map(|p| p.consumers.len()).sum();
            gauges.participants_total += participants;
            gauges.consumers_total += consumers;
            gauges.rooms.push(serde_json::json!({
                "room_id": room.key().to_hex(),
                "participants": participants,
                "consumers": consumers,
            }));
        }
        gauges
    }
}

impl Module for ConferenceState {
    const ID: &'static str = "conference";

    type Deps = ();

    async fn init(core: Core, settings: &Settings, _deps: ()) -> anyhow::Result<Self> {
        let db = &core.db;
        let worker_pool = Arc::new(WorkerPool::new(&settings.mediasoup).await?);
        let room_manager = Arc::new(RoomManager::new(worker_pool, &settings.mediasoup));
        let state = Self {
            rooms: Arc::new(RoomDao::new(db)),
            recordings: Arc::new(RecordingDao::new(db)),
            room_manager,
            media_claim_tokens: Arc::new(DashMap::new()),
            remote_media_conns: Arc::new(DashMap::new()),
            core,
        };
        // C-4 — the owner-side bus handlers + the 10 s claim heartbeat.
        media_cluster::wire_media_cluster(&state);
        // Stats PR-1 — the per-pod media sampler (no-op unless stats are on).
        media_stats::spawn_media_sampler(state.clone());
        // FR-115 P5 — the meeting-length cap's sweep (every pod; its writes
        // are conditional, so two pods warn and end a meeting once).
        meeting_cap::spawn(state.clone());
        Ok(state)
    }

    fn enabled(settings: &Settings) -> bool {
        settings.modules.conference
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        Capabilities::enabled(Self::ID)
    }

    /// Exactly the paths the host mounted before P4: the call lifecycle under
    /// `/room/{room_id}/call/*` (note the singular `participant`) and the
    /// recording routes.
    fn routes(&self) -> Router {
        let call = Router::new()
            .route("/{room_id}/call/start", post(call::call_start))
            .route("/{room_id}/call/join", post(call::call_join))
            .route("/{room_id}/call/leave", post(call::call_leave))
            .route("/{room_id}/call/end", post(call::call_end))
            .route("/{room_id}/call/participant", get(call::participants));

        let recording = Router::new()
            .route("/", get(recording::list))
            .route("/", post(recording::create))
            .route("/{recording_id}", delete(recording::delete));

        Router::new()
            .nest("/tenant/{tenant_id}/room", call)
            .nest("/tenant/{tenant_id}/room/{room_id}/recording", recording)
            .with_state(self.clone())
    }

    /// `media:*` on the user socket — and the socket close, through
    /// [`meshharbor_core::WsHandler::closed`].
    fn ws(&self) -> WsRegistration {
        WsRegistration {
            handlers: vec![WsHandlerSpec {
                role: Role::User,
                namespace: "media",
                handler: Arc::new(ws_media::Media {
                    state: self.clone(),
                }),
            }],
            upgrades: Vec::new(),
        }
    }

    /// The two collections this module owns. The specs are the ones the db
    /// crate's plan held before P4, unchanged.
    fn indexes(&self) -> Vec<IndexSet> {
        vec![
            IndexSet {
                collection: "recordings",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "room_id": 1, "recording_type": 1 }),
                    index(bson::doc! { "tenant_id": 1, "status": 1 }),
                ],
            },
            // One document per call instance (PR-2 lifecycle). `ended_at: null`
            // scan backs the orphan sweep; TTL on started_at bounds the ledger.
            IndexSet {
                collection: "call_sessions",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "started_at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "room_id": 1, "started_at": -1 }),
                    index(bson::doc! { "ended_at": 1 }),
                    index_ttl(bson::doc! { "started_at": 1 }, 730 * 24 * 60 * 60),
                ],
            },
        ]
    }

    /// The stale-call reset: no call can be active at server startup, so
    /// every `in_progress` room is ended and its orphaned sessions closed.
    /// Leader-gated — the host runs it under its startup lease, exactly where
    /// it ran inline before P4.
    fn jobs(&self) -> Vec<Job> {
        let state = self.clone();
        vec![Job::at_startup("stale-call-reset", true, move || {
            let state = state.clone();
            async move { maintenance::stale_call_reset(&state).await }
        })]
    }

    /// C-4 — release this pod's media claims so a graceful deploy hands each
    /// room off with a zero-length ownerless window instead of the 30 s TTL.
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        let state = self.clone();
        async move { media_cluster::release_all_claims(&state).await }
    }
}
