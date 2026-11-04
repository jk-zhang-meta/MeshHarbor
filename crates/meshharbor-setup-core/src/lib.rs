// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Shared install-wizard machinery for the unified `meshharbor-setup`
//! app. (Through P4a-P4c-1 it also served the two legacy wizard
//! crates via path-compatible shims, keeping their behaviour
//! byte-identical until both were retired in P4c-2.)
//!
//! Layering rule (also spelled out in Cargo.toml): this crate is the
//! EVENT-SHAPE-FREE mechanics layer. No `tauri`, no `meshharbord`,
//! no `meshharbor` — the apps own the Tauri surface, the
//! ProgressEvent wire shapes, and the agent/tunnel lib calls.
//! Mechanics here communicate through plain callbacks (`FnMut(u64)`
//! byte ticks) and returned reports, which is what lets one copy
//! serve wizards with different (frozen) wire contracts.

#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]

pub mod asset_resolver;
pub mod extract;
pub mod integration;
pub mod msi_runner;
pub mod progress;
pub mod token_peek;
pub mod tunnel_enroll;
pub mod wizard_state;
