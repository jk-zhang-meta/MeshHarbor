// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P0c — agent sessions on this device (cargo feature `hive`).
//!
//! The device half of `rc:hive.*`. The server asks for a session to start or
//! stop; this module applies the DEVICE's own gates — `hive_enabled`, the
//! account `hive_accounts` maps the starter to, the folder confined to
//! `hive_roots`, capacity, a harness to run — answers `rc:hive.start_ack`,
//! launches Claude Code headless as that account through the one privilege
//! path exec and SSH already share, keeps the transcript in the replica store,
//! and reports each session's lifecycle with `rc:hive.state`. Only metadata
//! crosses the control WS (`docs/roomler-hive-design.md` §3.3).
//!
//! # What P0 covers
//!
//! Linux, a named account (`RunAs::Named`), the harness as the daemon's child.
//! The re-exec'd `hive-host` — Windows' console user, macOS — is P1; a daemon
//! restart still takes every harness down with it, and P1d-2 resumes the
//! sessions (below). Elsewhere the build does not advertise `hive`, so no
//! server sends it a start.
//!
//! # Whose frames count
//!
//! Only the PRIMARY enrollment's. `hive_enabled` and the account map belong to
//! the device's owner; a secondary org's admin must not start sessions on a
//! device that org merely borrows — the rule `rc:agent.update` already follows.
//!
//! # Root on a Mac (decision 15)
//!
//! [`sudo`]: a Mac refuses a start as an account whose `sudo` needs no
//! password, unless the device's owner allows it. Its `sudo` reads the
//! account's groups from the directory, so the groups a session drops
//! (decision 13) cannot keep it from root there.

//!
//! # Reading a session from a browser (P0d-2)
//!
//! [`view`]: a view grant from the server, a data-only WebRTC peer to the
//! browser, and the transcript — pages, the live feed, prompts from a viewer
//! that may drive — over its one DataChannel. The server relays the
//! handshake and never sees what flows over the peer.
//!
//! # Approvals (P1a)
//!
//! [`toolbelt`]: the session's `roomler` MCP server, whose `approve` is
//! Claude Code's permission tool — every tool call that needs one waits for a
//! driver, who answers over the viewer peer. Claude Code reaches it through
//! `meshharbord hive-mcp <socket>` ([`relay`]), started as the session's
//! account.
//!
//! # Updates (P1d-1)
//!
//! An update restarts the daemon, and with it every session's harness, so the
//! updater asks [`turns_running`] first and waits for those turns, at most
//! [`update_wait`] (`hive_update_wait_secs`). Once it goes ahead,
//! [`begin_update`] holds new prompts and starts so none begins in the gap;
//! [`end_update`] releases them when no restart came after all.
//!
//! # Restarts (P1d-2)
//!
//! [`hosted`]: what the device hosts is kept on disk, and the next daemon
//! resumes it at its first connection — every gate applied again as the
//! device is configured then, Claude Code relaunched with `--resume`, the
//! turn count carried on, a turn the restart cut reported interrupted and
//! its open approvals withdrawn — before its manifest goes out. The daemon
//! calls [`begin_shutdown`] the moment its shutdown is signalled: a harness
//! that ends after that went down with it, its session is kept rather than
//! ended, and what the device hosts is frozen for the next daemon to report.
//!
//! # Core memory (P1e)
//!
//! The server sends a session's core memory — facts people keep in the org's
//! brain, rendered when the session was created — in `rc:hive.memory`, just
//! before its start ([`handle_memory`]). It reaches the session only where
//! the device's own `hive_core_memory` allows (default off): Claude Code
//! reads `CLAUDE.md` as the user's own overriding instructions. The daemon
//! writes the files into its own runtime directory, and the wrapper copies
//! each one into the session's config directory AS THE ACCOUNT, only when
//! nothing is there yet — so a resume keeps what the session has.

mod checkpointer;
#[cfg(unix)]
mod child;
pub mod framing;
pub mod gates;
mod hosted;
mod importer;
mod lines;
mod materializer;
/// FR-90 P3-7-3c — `net_socks` and `net_forward`: a session's own egress, on
/// a loopback listener served to its account alone.
#[cfg(feature = "vault")]
mod net_tools;
mod packer;
/// FR-90 P3-9-2b — `meshharbor connect`'s endpoints, held for the LocalAPI
/// connection that asked.
#[cfg(feature = "vault")]
pub(crate) mod person_connect;
mod procs;
mod purger;
mod resume_note;
mod sidecar;
/// FR-90 P3-8-2b-2 — `ssh_run`: one command on another device of the
/// organization, through this daemon's own SSH client.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
mod ssh_tools;
mod store;
mod sudo;
mod supervisor;
mod toolbelt;
/// FR-90 P3-5b-2 — `vault_connect`: an endpoint that signs in to a database
/// with a secret's value, for the session's account, as long as its leases.
#[cfg(feature = "vault")]
mod vault_connect;
/// FR-90 P3-4c-1 — `vault_exec`: a command run with values from the vault.
#[cfg(feature = "vault")]
mod vault_exec;
/// FR-90 P3-4c-2 — `vault_render`: a template written with values from the
/// vault into the session's secrets directory.
#[cfg(feature = "vault")]
mod vault_render;
/// FR-90 P3-4c-3 — `vault_request`: a lease asked for ahead, which a use
/// takes.
#[cfg(feature = "vault")]
mod vault_request;
pub mod view;
mod workspace;

pub use checkpointer::{CHECKPOINT_SUBCOMMAND, checkpoint_args, checkpoint_main};
pub use importer::{IMPORT_SUBCOMMAND, import_args, import_main};
pub use materializer::{MATERIALIZE_SUBCOMMAND, materialize_args, materialize_main};
pub use packer::{PACK_SUBCOMMAND, pack_args, pack_main};
pub use purger::{PURGE_SUBCOMMAND, purge_args, purge_main};
pub use resume_note::{
    NOTE_FILE as RESUME_NOTE_FILE, RESUME_NOTE_SUBCOMMAND, note_args, note_main,
};
#[cfg(all(unix, feature = "hive-test-launcher"))]
pub use supervisor::init_as_daemon;
pub use supervisor::{
    Author, CoreMemory, Moved, REMOVAL_PURGE_LIMIT, StartOrder, Supervisor, adopt_enabled,
    archive_enabled, begin_shutdown, begin_update, end_update, finish_removal_purge, global,
    handle_adopt_ack, handle_demote, handle_drain, handle_lease, handle_memory, handle_move,
    handle_prepare, handle_purge, handle_purge_all, handle_replica_candidate, handle_replica_close,
    handle_replica_dial, handle_replica_grant, handle_replica_join, handle_replica_refused,
    handle_retain, handle_start, handle_stop, init, on_connected, replica_enabled, stream_enabled,
    turns_running, update_wait, wind_down,
};
pub use toolbelt::{relay, relay_args};
pub use view::{
    SearchGrant, ViewGrant, handle_search_grant, handle_view_close, handle_view_grant,
    handle_view_ice, handle_view_offer, handle_view_renew,
};
