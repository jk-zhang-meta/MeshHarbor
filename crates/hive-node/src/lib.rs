// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 — Hive on the device.
//!
//! A Hive session's transcript never reaches the server (FR-90 D1): it lives on
//! the session's **replicaset**, a list of the org's own devices that each hold
//! a full copy. This crate is the part of that which needs no daemon:
//!
//! - [`event`] — what a session records ([`TranscriptEvent`]);
//! - [`chain`] — how events are numbered, fenced and hash-chained, so two
//!   members can prove they hold the same history ([`EventEnvelope`]);
//! - [`stream_json`] — the adapter from Claude Code's `--output-format
//!   stream-json` to events;
//! - [`store`] — the replica store every member keeps (SQLite with an FTS5
//!   index);
//! - [`launch`] — the harness command line and environment for one session;
//! - [`roots`] — confining a session's folder to the device's `hive_roots`;
//! - [`checkpoint`] — what a checkpoint takes of a session's config directory
//!   (FR-90 P2b), and how a member puts it back together.
//! - [`stream`] — the replica stream between a member and its source: the
//!   messages, their framing, and the opening exchange (FR-90 P2d).
//!
//! What it deliberately does not do: spawn processes, drop privileges, or talk
//! to the network. The daemon does those, with the one privilege path it
//! already has (`meshharbord::exec::apply_run_as`).
//!
//! Design: `docs/roomler-hive-design.md` §4.3–§4.4; spec:
//! `docs/fr/FR-90-hive-agent-sessions.md`.

pub mod chain;
pub mod checkpoint;
pub mod event;
pub mod launch;
pub mod roots;
pub mod store;
pub mod stream;
pub mod stream_json;

pub use chain::{ChainError, ChainTip, EventEnvelope, FenceEnd, GENESIS};
pub use event::{TranscriptEvent, Usage, approval_outcome};
