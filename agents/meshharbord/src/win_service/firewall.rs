// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #1698 — the Defender rule for the worker's UDP, written by the SCM host
//! BEFORE the first worker spawn, plus the one-time removal of the Block
//! rules a Windows Security prompt left behind on hosts installed earlier.
//!
//! The host runs as LocalSystem, so it can write the rule the worker itself
//! writes only after the fact (`overlay::tun`'s detached hygiene thread). On
//! an ATTENDED perMachine install the worker runs in the signed-in user's
//! session; the first off-loopback UDP bind with no rule for its path raises
//! the interactive "Allow access?" prompt, and the prompt writes per-profile
//! **Block** rules for the exe the moment it appears. Defender lets an
//! explicit Block beat an Allow, so the overlay's own rule — added a few
//! hundred ms later — lost on every Public-profile network until someone
//! clicked Allow. A rule that exists before the first bind means no prompt,
//! and so no Block rules.
//!
//! Everything here is best-effort and bounded: a failure is logged and the
//! worker spawns anyway. Where a GPO forbids local rules
//! (`AllowLocalFirewallRules=False`, `docs/overlay-wfp.md`) the rule is
//! written and inert — netsh still answers success, so nothing here reads
//! that as a failure. The per-user (Scheduled Task) flavour has no service
//! host and cannot elevate; it is untouched.
//!
//! The rule's ONE definition, the store parser and the cleanup predicate
//! live in `tunnel_core::winfw`; this module is the host's use of them.

#![cfg(target_os = "windows")]

use std::path::Path;
use std::time::{Duration, Instant};

use tunnel_core::winfw::{self, CleanupOutcome, EnsureOutcome, UdpInAllowRule};

/// Per `netsh` call. netsh answers in well under a second; the bound is for
/// a wedged firewall service, and it is per call so a wedged delete costs
/// ~10 s, not 20 (a delete that times out skips the add).
pub(crate) const NETSH_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The PowerShell removal. A cold `powershell` plus the NetSecurity module
/// import is 3–8 s on a slow guest; this spawn happens only when the store
/// holds something to remove, i.e. once per host that ever saw the prompt.
pub(crate) const REMOVE_TIMEOUT: Duration = Duration::from_secs(30);

/// What the prep achieved — a summary for the caller's log line and for the
/// startup-sequence tests. Never a reason not to spawn the worker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FirewallPrep {
    /// The kill switch (`ROOMLERD_TUN_HYGIENE=0`) was set; nothing ran.
    pub skipped: bool,
    /// `netsh add` returned success for the worker's rule.
    pub rule_installed: bool,
    /// Inbound Block rules for the worker's path that PowerShell removed.
    pub blocks_removed: usize,
}

/// Ensure the inbound-UDP allow rule for `worker_exe` exists, then remove
/// any inbound Block rule whose program is exactly that path. Synchronous
/// and bounded (≤ 2 × [`NETSH_CALL_TIMEOUT`] + [`REMOVE_TIMEOUT`] in the
/// worst case; ~0.5 s typically, and no PowerShell at all when there is
/// nothing to remove). Call it once per service start, BEFORE the supervisor
/// spawns anything — the ordering is the fix.
pub(crate) fn prepare_before_first_spawn(worker_exe: &Path) -> FirewallPrep {
    if winfw::hygiene_disabled(tunnel_core::env::node_env("TUN_HYGIENE").as_deref()) {
        tracing::info!(
            "service: firewall prep skipped — Windows net hygiene disabled via ROOMLERD_TUN_HYGIENE"
        );
        return FirewallPrep {
            skipped: true,
            ..FirewallPrep::default()
        };
    }

    let rule = UdpInAllowRule::for_exe(worker_exe);
    let started = Instant::now();
    let rule_installed = match winfw::ensure_udp_in_allow(&rule, NETSH_CALL_TIMEOUT) {
        EnsureOutcome::Installed => {
            tracing::info!(
                rule = %rule.name,
                program = %rule.program,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "service: firewall inbound-UDP allow installed for the worker BEFORE its first bind (#1698)"
            );
            true
        }
        EnsureOutcome::AddFailed { status, stderr } => {
            tracing::warn!(
                rule = %rule.name,
                ?status,
                %stderr,
                "service: firewall rule add refused; the worker starts anyway (a GPO that \
                 forbids local rules makes the rule inert, not this path fatal)"
            );
            false
        }
        EnsureOutcome::Failed(e) => {
            tracing::warn!(
                rule = %rule.name,
                error = %e,
                "service: netsh did not answer; the worker starts anyway"
            );
            false
        }
    };

    let started = Instant::now();
    // Only rules the Windows Security prompt wrote (their store id carries
    // its signature) — a Block an administrator placed deliberately is theirs
    // and stays, whatever its program.
    let blocks_removed = match winfw::remove_prompt_block_rules_for(worker_exe, REMOVE_TIMEOUT) {
        CleanupOutcome::NothingToRemove => {
            tracing::debug!(
                "service: no prompt-written inbound Block rules for this binary in the firewall store"
            );
            0
        }
        CleanupOutcome::Removed { ids, remaining } => {
            tracing::info!(
                count = ids.len(),
                ?ids,
                ?remaining,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "service: removed prompt-written inbound Block rules for this binary (#1698)"
            );
            ids.len()
        }
        CleanupOutcome::RemoveFailed {
            ids,
            status,
            stderr,
        } => {
            tracing::warn!(
                ?ids,
                ?status,
                %stderr,
                "service: could not remove the inbound Block rules for this binary; the worker \
                 starts anyway (inbound UDP stays blocked on Public networks until they go)"
            );
            0
        }
        CleanupOutcome::Failed { ids, error } => {
            tracing::warn!(
                ?ids,
                error = %error,
                "service: PowerShell did not answer while removing Block rules; the worker \
                 starts anyway"
            );
            0
        }
        CleanupOutcome::StoreUnreadable(e) => {
            tracing::debug!(
                error = %e,
                "service: firewall rule store unreadable; skipping the Block-rule cleanup"
            );
            0
        }
    };

    FirewallPrep {
        skipped: false,
        rule_installed,
        blocks_removed,
    }
}
