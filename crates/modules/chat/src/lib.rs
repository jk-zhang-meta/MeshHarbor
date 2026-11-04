// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `chat` — rooms, messages, reactions, files, search, export, Giphy, and
//! the typing indicator, as a module (FR-69 P3).
//!
//! The collaboration pillar's text half. Rooms are also the container calls
//! run in, which is why `conference` (P4) depends on this crate and not the
//! other way round; the call endpoints that used to share `room.rs` stayed in
//! the host as `routes/call.rs` until then.
//!
//! # Shape
//!
//! [`ChatState`] = [`Core`] + the DAOs this module owns (rooms, messages,
//! reactions, files) + the Giphy client. It derefs to `Core`, so handlers
//! read `state.tenants`, `state.storage`, `state.ws_storage` exactly as they
//! did on the host's `AppState`; `impl FromRef<ChatState> for Core` lets the
//! core extractors serve this router unchanged.
//!
//! This is the first module with a **WebSocket namespace**: `typing:*` on
//! the user socket is handled by [`typing::Typing`], registered through
//! [`Module::ws`]. The socket, the role gate and the fan-out stay in core.

use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, FromRef},
    routing::{delete, get, post, put},
};
use meshharbor_config::Settings;
use meshharbor_db::indexes::{IndexSet, index, index_text, index_unique, index_unique_sparse};
use meshharbor_services::{
    GiphyService,
    dao::{file::FileDao, message::MessageDao, reaction::ReactionDao, room::RoomDao},
};
use meshharbor_core::{Capabilities, Core, Module, Role, TenantCtx, WsHandlerSpec, WsRegistration};

pub mod bound;
pub mod export;
pub mod file;
pub mod giphy;
pub mod guards;
pub mod media_type;
pub mod message;
pub mod reaction;
pub mod room;
pub mod search;
pub mod typing;
pub mod user_unread;

/// The module's state: the core plus what chat owns.
#[derive(Clone)]
pub struct ChatState {
    pub core: Core,
    pub rooms: Arc<RoomDao>,
    pub messages: Arc<MessageDao>,
    pub reactions: Arc<ReactionDao>,
    pub files: Arc<FileDao>,
    pub giphy: Option<Arc<GiphyService>>,
}

impl std::ops::Deref for ChatState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

/// `State<Core>` in this module's handlers, and the core extractors.
impl FromRef<ChatState> for Core {
    fn from_ref(state: &ChatState) -> Self {
        state.core.clone()
    }
}

/// Upload body ceiling for the two file routes (audio attachments).
const UPLOAD_LIMIT: usize = 100 * 1024 * 1024;

impl Module for ChatState {
    const ID: &'static str = "chat";

    type Deps = ();

    async fn init(core: Core, settings: &Settings, _deps: ()) -> anyhow::Result<Self> {
        let db = &core.db;
        let giphy = if !settings.giphy.api_key.is_empty() {
            Some(Arc::new(GiphyService::new(settings.giphy.api_key.clone())))
        } else {
            None
        };
        Ok(Self {
            rooms: Arc::new(RoomDao::new(db)),
            messages: Arc::new(MessageDao::new(db)),
            reactions: Arc::new(ReactionDao::new(db)),
            files: Arc::new(FileDao::new(db)),
            giphy,
            core,
        })
    }

    fn enabled(settings: &Settings) -> bool {
        settings.modules.chat
    }

    fn capabilities(&self, _tenant: &TenantCtx) -> Capabilities {
        Capabilities::enabled(Self::ID)
    }

    /// Exactly the paths the host mounted before P3. The call endpoints
    /// under `/room/{room_id}/call/*` and the recording routes are NOT here:
    /// they are conference's, still mounted by the host.
    fn routes(&self) -> Router {
        // Room routes (under tenant) — replaces channel + conference
        let room = Router::new()
            .route("/", get(room::list))
            .route("/", post(room::create))
            .route("/explore", get(room::explore))
            .route("/{room_id}", get(room::get))
            .route("/{room_id}", put(room::update))
            .route("/{room_id}", delete(room::delete))
            .route("/{room_id}/join", post(room::join))
            .route("/{room_id}/leave", post(room::leave))
            .route("/{room_id}/member", get(room::members));

        // Message routes (under tenant/room)
        let message = Router::new()
            .route("/", get(message::list))
            .route("/", post(message::create))
            .route("/pin", get(message::pinned))
            .route("/{message_id}", put(message::update))
            .route("/{message_id}", delete(message::delete))
            .route("/{message_id}/pin", put(message::toggle_pin))
            .route("/{message_id}/thread", get(message::thread_replies))
            .route("/{message_id}/reaction", post(reaction::add))
            .route("/{message_id}/reaction/{emoji}", delete(reaction::remove))
            .route("/read", post(message::mark_read))
            .route("/read-all", post(message::read_all))
            .route("/unread-count", get(message::unread_count));

        // Room file routes (100 MB body limit for audio uploads)
        let room_file = Router::new()
            .route("/", get(file::list))
            .route("/upload", post(file::upload_room))
            .layer(DefaultBodyLimit::max(UPLOAD_LIMIT));

        // File-by-ID routes (under tenant — no room prefix needed)
        let file_by_id = Router::new()
            .route("/", get(file::list_tenant_files))
            .route("/upload", post(file::upload))
            .route("/{file_id}", get(file::get))
            .route("/{file_id}/download", get(file::download))
            .route("/{file_id}", delete(file::delete))
            .layer(DefaultBodyLimit::max(UPLOAD_LIMIT));

        // Export (the xlsx conversation export; the PDF one is the host's
        // integration route, next to it under the same prefix).
        let export = Router::new().route("/conversation", post(export::export_conversation));

        let search = Router::new().route("/", get(search::search));

        // Giphy proxy routes
        let giphy = Router::new()
            .route("/search", get(giphy::search))
            .route("/trending", get(giphy::trending));

        Router::new()
            .nest("/tenant/{tenant_id}/room", room)
            .nest("/tenant/{tenant_id}/room/{room_id}/message", message)
            .nest("/tenant/{tenant_id}/room/{room_id}/file", room_file)
            .nest("/tenant/{tenant_id}/file", file_by_id)
            .nest("/tenant/{tenant_id}/export", export)
            .nest("/tenant/{tenant_id}/search", search)
            .nest("/giphy", giphy)
            // P4 — the caller's unread state across every org: chat's, because
            // it counts messages. A static segment, so it wins over the host's
            // `/user/{user_id}` capture.
            .route("/user/unread-summary", get(user_unread::unread_summary))
            .with_state(self.clone())
    }

    /// `typing:start` / `typing:stop` on the user socket.
    fn ws(&self) -> WsRegistration {
        WsRegistration {
            handlers: vec![WsHandlerSpec {
                role: Role::User,
                namespace: "typing",
                handler: Arc::new(typing::Typing {
                    state: self.clone(),
                }),
            }],
            upgrades: Vec::new(),
        }
    }

    /// The six collections this module owns. The specs are the ones the db
    /// crate's plan held before P3, unchanged.
    fn indexes(&self) -> Vec<IndexSet> {
        vec![
            IndexSet {
                collection: "rooms",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "tenant_id": 1, "parent_id": 1, "position": 1 }),
                    index_unique(bson::doc! { "tenant_id": 1, "path": 1 }),
                    index(bson::doc! { "tenant_id": 1, "name": 1 }),
                    index(bson::doc! { "tenant_id": 1, "is_default": 1 }),
                    index_unique_sparse(bson::doc! { "meeting_code": 1 }),
                    index_text(bson::doc! { "name": "text", "purpose": "text", "tags": "text" }),
                ],
            },
            IndexSet {
                collection: "room_members",
                pre_ops: Vec::new(),
                indexes: vec![
                    index_unique(bson::doc! { "room_id": 1, "user_id": 1 }),
                    index(bson::doc! { "user_id": 1, "tenant_id": 1 }),
                ],
            },
            IndexSet {
                collection: "messages",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(bson::doc! { "room_id": 1, "created_at": -1 }),
                    index(bson::doc! { "thread_id": 1, "created_at": 1 }),
                    index(bson::doc! { "tenant_id": 1, "author_id": 1, "created_at": -1 }),
                    index(bson::doc! { "room_id": 1, "is_pinned": 1 }),
                    index(bson::doc! { "mentions.users": 1 }),
                    index_text(bson::doc! { "content": "text" }),
                ],
            },
            IndexSet {
                collection: "reactions",
                pre_ops: Vec::new(),
                indexes: vec![index_unique(
                    bson::doc! { "message_id": 1, "emoji.value": 1, "user_id": 1 },
                )],
            },
            IndexSet {
                collection: "files",
                pre_ops: Vec::new(),
                indexes: vec![
                    index(
                        bson::doc! { "tenant_id": 1, "context.context_type": 1, "context.entity_id": 1 },
                    ),
                    index(bson::doc! { "tenant_id": 1, "uploaded_by": 1, "created_at": -1 }),
                    index(bson::doc! { "tenant_id": 1, "context.room_id": 1, "created_at": -1 }),
                    index(
                        bson::doc! { "external_source.provider": 1, "external_source.external_id": 1 },
                    ),
                ],
            },
            IndexSet {
                collection: "custom_emojis",
                pre_ops: Vec::new(),
                indexes: vec![index_unique(bson::doc! { "tenant_id": 1, "name": 1 })],
            },
        ]
    }
}
