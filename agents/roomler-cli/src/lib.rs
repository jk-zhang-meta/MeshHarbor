// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `roomler` library surface.
//!
//! Re-export of `tunnel_core` so consumers of the binary have one
//! import path, plus the CLI-specific helpers used by [`cli`].
//! End-to-end tests in `crates/tests/` drive this lib in-process
//! against a `TestApp`, mirroring how `roomlerd` is driven from
//! `crates/tests/src/remote_control.rs`.

/// The whole `roomler` command surface (clap definitions + dispatch).
///
/// Lives in the LIB, not in `main.rs`, so it has two callers: the
/// standalone `roomler` binary (tunnel-only hosts) and `meshharbord cli`
/// (daemon hosts, via the `roomler` shim). Before P3e lever D the MSI
/// shipped a second full binary for the latter — 22 MiB of which ~92 %
/// duplicated crates the daemon already contains.
pub mod cli;
pub mod config;
/// FR-90 P3-9-2b — `meshharbor connect`: a vault secret's upstream through a
/// local endpoint the daemon serves, held in the foreground.
pub mod connectcmd;
/// FR-103 — the tunnel client renews its own token, and the renewal rule
/// `roomlerd` shares.
pub mod credential;
pub mod forward;
/// FR-90 P1j-3 — `meshharbor hive adopt | unadopt | hook`.
pub mod hive_hooks;
/// Thin-client read verbs (`status`/`peers`/`flows`) over the daemon LocalAPI.
pub mod localclient;
pub mod mesh;
/// Display names on the CLI: the peers↔devices join and the device-selector
/// rule for `ping` / `exec` / `ssh` (pure; `docs/device-naming.md`).
pub mod names;
pub mod native_auth;
pub mod share_sshcmd;
pub mod sshcmd;
pub mod update;

pub use tunnel_core::forward as core_forward;
pub use tunnel_core::{auth, mux, policy, signaling, socks5, transport, udp};
