// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `mh` library surface.
//!
//! Re-export of `tunnel_core` so consumers of the binary have one
//! import path, plus the CLI-specific helpers used by [`cli`].
//! End-to-end tests in `crates/tests/` drive this lib in-process
//! against a `TestApp`, mirroring how `meshharbord` is driven from
//! `crates/tests/src/remote_control.rs`.

/// The whole `mh` command surface (clap definitions + dispatch).
///
/// Lives in the LIB, not in `main.rs`, so it has two callers: the
/// standalone `mh` binary (tunnel-only hosts) and `meshharbord cli`
/// (daemon hosts, via the `mh` shim). Before P3e lever D the MSI
/// shipped a second full binary for the latter — 22 MiB of which ~92 %
/// duplicated crates the daemon already contains.
pub mod cli;
pub mod config;
/// FR-103 — the tunnel client renews its own token, and the renewal rule
/// `meshharbord` shares.
pub mod credential;
pub mod forward;
/// Thin-client read verbs (`status`/`peers`/`flows`) over the daemon LocalAPI.
pub mod localclient;
pub mod mesh;
/// Display names on the CLI: the peers↔devices join and the device-selector
/// rule for `ping` / `exec` / `ssh` (pure; `docs/device-naming.md`).
pub mod names;
pub mod native_auth;
/// FR-139 — `mh nvitop` (alias `mh gpu`) fleet GPU viewer, TUI watch, users, and free picker.
pub mod nvitop;
pub mod rdpcmd;
pub mod share_sshcmd;
/// FR-141 — Built-in resumable `mh ssh` client (`meshharbor-pty@v1`), shadow
/// VT100 top-row reconnect overlay, escapes, and local `0600` session store.
pub mod ssh_resume;
pub mod sshcmd;
pub mod update;

pub use tunnel_core::forward as core_forward;
pub use tunnel_core::{auth, mux, policy, signaling, socks5, transport, udp};
