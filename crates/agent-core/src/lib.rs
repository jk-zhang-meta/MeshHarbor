// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Daemon-free agent building blocks (P3e lever E).
//!
//! Everything a THIN client needs to cohabit with the daemon — config
//! load/save, enrollment, machine-id derivation, log files + tailing, the
//! needs-attention sentinel — without any of the daemon's data plane
//! (capture, encode, input, webrtc, overlay). `roomlerd` re-exports
//! each module under its old `crate::` path; the desktop companion depends
//! on this crate directly.
//!
//! Module notes:
//! * [`notify`] carries the sentinel primitives; the rc.53 worker-aware
//!   wrappers stayed in `roomlerd` (they probe the SystemContext
//!   worker role — daemon-only machinery).
//! * [`apps_config`] carries ONLY the `[virtual_desktop_apps]` serde shapes
//!   that [`config::AgentConfig`] embeds; the launch machinery stays in
//!   `roomlerd::apps` and re-exports them.
//! * [`acl`] evaluates over shapes canonical in
//!   `roomler_ai_remote_control::models` (where `dst_matches` also lives
//!   since this split).

pub mod acl;
pub mod appdirs;
pub mod apps_config;
/// FR-84 D6 — the companion's login-start registration (Run value, XDG
/// entry), shared so the daemon and the companion spell it identically.
pub mod companion_autostart;
pub mod config;
pub mod config_surface;
pub mod crash_recorder;
/// FR-84 D6 — the companion's per-user state (Welcome done, login opt-out).
pub mod desktop_state;
pub mod enrollment;
/// FR-84 D4 — the `files_dir` validator: shape (shared with the config
/// surface), placement (the SYSTEM/root-inside-the-active-profile rule) and
/// writability, run by the daemon at set time and at every drop.
pub mod files_dir;
pub mod logging;
pub mod logs_upload;
pub mod machine;
pub mod notify;
pub mod recording_dir;
/// macOS privacy-permission probes. Here rather than in `roomlerd`
/// because the desktop companion needs them too and deliberately does NOT
/// depend on the agent (P3e lever E) — the whole point of that split is that
/// the tray links no transport crates. Re-exported by `roomlerd` under
/// `crate::tcc`, so existing call sites are unchanged.
#[cfg(target_os = "macos")]
pub mod tcc;
#[cfg(any(target_os = "macos", test))]
mod privacy_cache;
/// FR-103 — one enrollment's live agent token, read at the moment of use.
pub mod token_slot;
