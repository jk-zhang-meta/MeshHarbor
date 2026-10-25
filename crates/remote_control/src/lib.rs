// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `roomler-ai-remote-control` — TeamViewer-style remote desktop subsystem for Roomler AI.
//!
//! This crate is signaling and state-management only. It never touches video
//! frames or input events; those flow over a direct WebRTC PeerConnection
//! between the controller browser and the native agent.
//!
//! Module map:
//!
//! - [`hub`]         — process-global registry of online agents and live sessions
//! - [`connect_code`] — FR-52: the dictatable handle an outsider names a device by
//! - [`session`]     — session state machine (Pending → AwaitingConsent → Active → Closed)
//! - [`signaling`]   — `rc:*` WebSocket message types and dispatch
//! - [`consent`]     — controller-requested-control consent flow
//! - [`permissions`] — per-session capability bitfield (input, clipboard, files, audio)
//! - [`turn_creds`]  — short-lived TURN credentials (HMAC over coturn shared secret)
//! - [`turn_url`]    — port-correct TURN URL parsing + transport-variant expansion
//! - [`audit`]       — write-side of the remote_audit collection
//! - [`models`]      — Mongo-backed entities (Agent, RemoteSession, RemoteAuditEvent)
//! - [`hive`]        — FR-90 Hive vocabulary: session refusals, run states, limits
//! - [`error`]       — unified error type
//!
//! This crate intentionally does NOT depend on the mediasoup crate. The SFU
//! bridge for N-watcher sessions lives in a sibling crate (`sfu`) and is
//! invoked via a trait object passed into [`hub::Hub::new`].

// P3e Phase 3: `audit` (the Mongo-backed DAO) and `hub` (the server-side
// session hub, whose constructor takes an AuditSink) are SERVER-only — no
// agent-side crate names either — and they are the only production code in
// this crate that touches the mongodb driver. Gating them keeps the driver
// (and ~40 transitive crates) out of every agent/CLI/tray/derp-relay binary;
// `server` is a default feature, so api/services/tests are unchanged, and
// agent-side consumers opt out with `default-features = false`.
#[cfg(feature = "server")]
pub mod audit;
/// Shared hard-region and protected-management decision model. Authority-bearing
/// inputs must be produced by authenticated server/verifier paths, not wire DTOs.
pub mod business_reachability;
pub mod connect_code;
pub mod consent;
pub mod derp_frame;
pub mod derp_ticket;
pub mod error;
pub mod hive;
pub mod models;
pub mod net_inventory;
pub mod permissions;
pub mod serde_helpers;
/// FR-101 P1b — how an agent or the CLI reaches its server: over TLS.
pub mod server_url;
pub mod session;
/// FR-102 P3b — the setup wizard's opt-in diagnostics: the one record of
/// `POST /api/setup/diagnostics` and the vocabularies both ends check.
pub mod setup_diagnostics;
pub mod signaling;
pub mod turn_creds;
pub mod turn_url;
/// FR-90 P3-3b — the vault's lease vocabulary: refusal words and bounds both
/// ends read.
pub mod vault;
pub mod worker_pick;

pub use error::{Error, Result};
pub use models::{Agent, AgentStatus, RemoteSession, SessionPhase};
pub use permissions::Permissions;
pub use signaling::{ClientMsg, ServerMsg};
