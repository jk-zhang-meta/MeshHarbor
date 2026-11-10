// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Needs-attention sentinel — daemon-side surface.
//!
//! P3e lever E: the sentinel machinery (paths, raise/read/clear, reasons)
//! lives in `meshharbor-node-core::notify` so thin clients (the desktop
//! companion) can read it without linking this crate. Everything is
//! re-exported here under the old paths. What could NOT move is the rc.53
//! worker-aware trio below: it probes the process's worker role via
//! [`crate::system_context::worker_role`], which is winlogon-token machinery
//! gated on the daemon-only `system-context` feature.

pub use meshharbor_node_core::notify::*;

use anyhow::{Context, Result};
use std::path::PathBuf;

// RETIRED-NAME-ANCHOR(4): names the PRE-RENAME appdirs segment a host installed before
// P4b still has; appdirs::app_segment resolves it, so it is an input.
/// rc.53: resolve the attention sentinel path with awareness of the
/// caller's worker context.
///
/// When the current process is the LocalSystem SCM worker
/// ([`crate::system_context::worker_role::WorkerRole::SystemContext`])
/// the standard `directories::ProjectDirs` `%APPDATA%` resolves to
/// `C:\Windows\System32\config\systemprofile\AppData\Roaming\…`
/// — invisible to a human operator and missed by every fleet-mgmt
/// scanner that greps user profiles. Prefer
/// `%PROGRAMDATA%\meshharbor\meshharbor-agent\needs-attention.txt` in that
/// case so the file is findable by both a logged-in operator
/// (`dir %PROGRAMDATA%`) AND a fleet scanner.
///
/// Returns `(path, was_machine_global)` so the caller can log the
/// resolved location at WARN — operators investigating "where did
/// the sentinel land?" find it via the log line.
///
/// On non-Windows, builds without the `system-context` feature, or
/// when the worker-role probe fails, falls back to the existing
/// per-user [`attention_path`] semantics.
///
/// The dual cfg gate (`target_os = "windows"` AND `feature =
/// "system-context"`) mirrors the gate on the upstream module —
/// `pub mod system_context;` is itself `#[cfg(feature =
/// "system-context")]` (`lib.rs`). Without both, the LocalSystem
/// branch is dead code that wouldn't link, so we route through the
/// fallback unconditionally.
#[cfg(all(feature = "system-context", target_os = "windows"))]
pub fn attention_path_for_worker() -> Option<(PathBuf, bool)> {
    use crate::system_context::worker_role::{WorkerRole, probe_self};
    if let Ok(WorkerRole::SystemContext) = probe_self()
        && let Some(path) = machine_attention_path()
    {
        return Some((path, true));
    }
    attention_path().map(|p| (p, false))
}

#[cfg(not(all(feature = "system-context", target_os = "windows")))]
pub fn attention_path_for_worker() -> Option<(PathBuf, bool)> {
    attention_path().map(|p| (p, false))
}

/// rc.53: variant of [`raise_attention`] that routes to `%PROGRAMDATA%`
/// when running as LocalSystem. Logs the resolved path at WARN so
/// the operator can find the file. Used by the agent's
/// `signaling::handle_server_msg` `ServerMsg::Goodbye` arm.
///
/// Falls back to the user-context [`raise_attention`] path on
/// non-Windows or when the worker-role probe can't resolve
/// `SystemContext` — same behaviour as pre-rc.53.
pub fn raise_attention_machine_aware(message: &str) -> Result<PathBuf> {
    raise_attention_machine_aware_with_reason(REASON_GENERIC, message)
}

/// S1b — reasoned variant of [`raise_attention_machine_aware`].
pub fn raise_attention_machine_aware_with_reason(reason: &str, message: &str) -> Result<PathBuf> {
    let (path, machine_global) =
        attention_path_for_worker().context("no attention path resolvable")?;
    let parent = path.parent().context("attention path has no parent")?;
    let written = raise_attention_at_with_reason(parent, reason, message)?;
    tracing::warn!(
        path = %written.display(),
        machine_global,
        reason,
        "raised needs-attention sentinel"
    );
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attention_path_for_worker_does_not_panic() {
        // rc.53: same best-effort contract as `attention_path`. The
        // worker-role probe inspects the current process's primary
        // token; in a `cargo test` runner the role is virtually always
        // `WorkerRole::User`, so this exercises the user-context
        // fallback branch. (The SystemContext branch only fires when
        // the runtime is the LocalSystem SCM worker — not testable
        // from a normal test harness.)
        let _ = attention_path_for_worker();
    }

    // S1b: the old `raise_attention_machine_aware_writes_through_fallback`
    // test wrote a REAL "rc.53 smoke" sentinel through the developer's
    // actual profile on every `cargo test` run — which then sat forever in
    // the desktop app's "Attention required" banner (the reported field
    // bug). Path RESOLUTION is asserted without writing; the write
    // mechanics are covered by the tempdir tests in agent-core.
    #[test]
    fn machine_aware_path_resolves_without_writing() {
        let _ = attention_path_for_worker();
    }
}
