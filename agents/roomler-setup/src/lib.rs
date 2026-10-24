// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Roomler Setup — lib surface of the unified wizard.
//!
//! The wizard's binary entry point lives in `src/main.rs`; everything
//! else (Tauri invoke handlers, the two install orchestrators, proxy
//! resolution, role mapping) lives here so unit tests can execute
//! without spawning the Tauri webview EXE (which would require
//! elevation on Windows when run from a non-admin shell).
//!
//! One app, four roles (see [`role::Role`]): the three daemon roles
//! drive the MSI pipeline ([`orchestrator_agent`]); the tunnel-client
//! role drives the archive pipeline ([`orchestrator_tunnel`]) — both
//! relocated (P4a) from the legacy wizard crates retired in P4c-2.
//! Mechanics (asset resolver, MSI runner,
//! extract, integration, enroll HTTP, unified ProgressEvent) come
//! from `wizard_shared` (`crates/roomler-setup-core`); the agent- and
//! tunnel-coupled calls stay here.

#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]

pub mod commands;
/// FR-102 P3b — the opt-in setup diagnostics: the recorder, its gate, the
/// buffer until the server is known, and the fire-and-forget sender.
pub mod diagnostics;
pub mod orchestrator_agent;
pub mod orchestrator_tunnel;
pub mod proxy;
pub mod role;
// Internal only: live Unix roles remain gated until reviewed local bundles ship.
pub(crate) mod unix_local_install;

use std::sync::atomic::{AtomicBool, AtomicU32};

/// `true` while a `cmd_install` future is in flight. Set by the
/// active orchestrator on entry; cleared on success / cancel / error.
/// The single-instance callback in `main.rs` consults this to decide
/// whether to surface a "wizard busy" snackbar (in-progress) or focus
/// the existing window (idle).
///
/// Static-with-atomic rather than `OnceLock<Arc<AtomicBool>>` because
/// it's referenced from both the Tauri-runtime thread (callback) and
/// the cmd_install async future (different tokio task) — atomic-only
/// is the right primitive. No need for the extra Arc layer.
///
/// DELIBERATELY process-wide and shared by BOTH orchestrators (the
/// legacy wizards kept per-crate copies): only one install runs at a
/// time regardless of role, so one trio of statics serves the whole
/// app.
pub static INSTALL_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// `true` while a pre-spawn cancel is pending. `cmd_cancel_in_progress`
/// flips it; the active orchestrator checks it at each await point and
/// bails with "install cancelled by operator". Reset to `false` on
/// every `cmd_install` entry. Unlike the legacy wizards (which kept
/// this module-local in their orchestrators and opted OUT of
/// mid-stream download cancel), the unified app passes THIS flag into
/// `wizard_shared::asset_resolver::download` so a cancel also aborts
/// an in-flight download between chunks.
pub static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// PID of the active msiexec process. `0` = none (no msiexec
/// currently running under wizard supervision). Registered by the
/// daemon orchestrator right after `spawn_installer_for_flavour_with_
/// properties` returns; reset to `0` on every `cmd_install` entry and
/// exit. `cmd_force_kill_msi` reads this to attach + TerminateProcess.
/// (Legacy home: module-local in the agent wizard's orchestrator; the
/// tunnel pipeline never touches it — no msiexec to hammer.)
pub static ACTIVE_MSI_PID: AtomicU32 = AtomicU32::new(0);
