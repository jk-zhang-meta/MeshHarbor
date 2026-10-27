// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2h-1 — `meshharbord enroll --archive-replica`: an archive replica of
//! the organization, as the archive image enrolls one (spec §3b, "The image").
//!
//! An archive replica is an always-on device that holds copies of the org's
//! sessions for their retention and serves a session's room when no other
//! member is online. It runs no session itself. Its whole posture is written
//! WITH the enrolled config, as `--overlay` writes `overlay_enabled`, so its
//! first start is already one; a script appending keys to the file after
//! enrollment would land them under whatever `[table]` came last.
//!
//! | Key | Value | Why |
//! |---|---|---|
//! | `hive_replica` | on | it holds copies of the org's sessions |
//! | `hive_archive` | on | it offers itself as an archive replica; an `ADMINISTRATOR` still designates it before it joins anything |
//! | `hive_enabled` | off | it runs no session and calls no model |
//! | `exec_enabled`, `ssh_enabled` | off | it reaches the org's network for no one |
//! | `forward_acl.enabled` | off | no tunnel exit: an empty allowlist would otherwise trust the server |
//! | `auto_update` | off | it updates by a new container on the same volume, never by a package installed inside one |
//! | `overlay_enabled`, `netstack_socks_port` | on, the userspace stack on the container's loopback | FR-90 P2k-4 (F4): on the mesh it holds a DERP connection, and a member's ladder offers the derp rung only while it holds one, so a primary that only DERP reaches could never be followed. A container has no TUN; the stack changes no route and needs no privilege, and its SOCKS5 front is on the loopback, the container's own on a network of its own |
//!
//! An archive replica enrolled before its posture joined the mesh joins it
//! at its next start in the image ([`reconcile_at_start`]), which is how it
//! is updated: a new container on the same volume.
//!
//! ⚠️ Only into a FRESH config, and never an ephemeral one: the volume IS the
//! device (its config holds the agent token and the WireGuard key, its store
//! every session placed there), and FR-51 hard-deletes an ephemeral device
//! once it falls silent. Both are refused before the single-use token is
//! spent.

use anyhow::{Result, bail};

use crate::config::AgentConfig;

/// Whether `enroll --archive-replica` may go ahead: checked before the
/// enrollment token is spent, so a refusal leaves no device row behind.
/// `existing` = a config is already at the target path.
pub fn preflight(existing: bool, ephemeral: bool) -> Result<()> {
    if !cfg!(hive_host) {
        bail!(
            "--archive-replica: this build holds no copies of agent sessions (it was \
             built without the `hive` feature, or for a system that runs none)"
        );
    }
    if ephemeral {
        bail!(
            "--archive-replica cannot be --ephemeral: an ephemeral device is deleted \
             once it falls silent, and an archive replica keeps the org's sessions \
             for their retention. Use a standard enrollment token."
        );
    }
    if existing {
        bail!(
            "--archive-replica needs a fresh config: the volume is the device, and an \
             existing enrollment would be turned into an archive replica in place. \
             Point --config at an empty volume."
        );
    }
    Ok(())
}

/// The archive replica's posture, onto the enrolled config before its first
/// save: the table in the module's docs.
pub fn apply(cfg: &mut AgentConfig) {
    cfg.hive_replica = true;
    cfg.hive_archive = true;
    cfg.hive_enabled = false;
    cfg.exec_enabled = false;
    cfg.ssh_enabled = false;
    cfg.forward_acl.enabled = false;
    cfg.auto_update = Some(false);
    join_mesh(cfg);
    tracing::info!(
        "archive replica: holds the org's copies; runs no session, takes no command \
         or SSH session, is no tunnel exit, and never updates itself; on the mesh, \
         in the userspace stack"
    );
}

/// FR-90 P2k-4 (F4) — the loopback port of an archive replica's userspace
/// stack. Nothing outside the container reaches it.
pub const NETSTACK_SOCKS_PORT: u16 = 11080;

/// The process runs in the archive replica image, which says so in its
/// environment (`Dockerfile.hive-archive`).
pub const IMAGE_ENV: &str = "ROOMLERD_ARCHIVE_IMAGE";

/// FR-90 P2k-4 (F4) — the mesh half of the posture: on the overlay, in the
/// userspace stack. A port already configured is kept. True when it changed
/// anything.
pub fn join_mesh(cfg: &mut AgentConfig) -> bool {
    let mut changed = false;
    if !cfg.overlay_enabled {
        cfg.overlay_enabled = true;
        changed = true;
    }
    if cfg.netstack_socks_port.is_none() {
        cfg.netstack_socks_port = Some(NETSTACK_SOCKS_PORT);
        changed = true;
    }
    changed
}

/// FR-90 P2k-4 (F4) — at a start in the archive image: an archive replica
/// enrolled before its posture joined the mesh joins it now. Outside the
/// image nothing changes, so a device whose owner offers it as an archive
/// replica keeps the overlay its owner chose. True when the config changed
/// and is to be saved.
pub fn reconcile_at_start(cfg: &mut AgentConfig, in_image: bool) -> bool {
    in_image && cfg.hive_archive && cfg.hive_replica && join_mesh(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An archive replica holds copies and offers itself, and runs nothing,
    /// reaches nothing and updates by a new container: whatever the fresh
    /// config said.
    #[test]
    fn the_archive_posture_is_written_with_the_enrollment() {
        let mut cfg = crate::config::test_fixture();
        cfg.hive_enabled = true;
        cfg.exec_enabled = true;
        cfg.ssh_enabled = true;
        assert!(
            cfg.forward_acl.enabled,
            "an empty allowlist trusts the server by default"
        );
        apply(&mut cfg);
        assert!(cfg.hive_replica && cfg.hive_archive);
        assert!(!cfg.hive_enabled, "it runs no session");
        assert!(
            !cfg.exec_enabled && !cfg.ssh_enabled,
            "it reaches nothing for anyone"
        );
        assert!(!cfg.forward_acl.enabled, "no tunnel exit");
        assert_eq!(cfg.auto_update, Some(false), "no self-update");
        assert!(cfg.overlay_enabled, "on the mesh (F4)");
        assert_eq!(
            cfg.netstack_socks_port,
            Some(NETSTACK_SOCKS_PORT),
            "in the userspace stack: a container has no TUN"
        );
    }

    /// FR-90 P2k-4 (F4) — an archive replica enrolled before its posture
    /// joined the mesh joins it at its next start in the image, once; a port
    /// it had is kept; outside the image nothing changes.
    #[test]
    fn an_archive_from_the_image_joins_the_mesh_at_its_start_and_nothing_else_does() {
        let archive = || {
            let mut cfg = crate::config::test_fixture();
            cfg.hive_replica = true;
            cfg.hive_archive = true;
            cfg.overlay_enabled = false;
            cfg.netstack_socks_port = None;
            cfg
        };
        let mut cfg = archive();
        assert!(reconcile_at_start(&mut cfg, true), "it joins");
        assert!(cfg.overlay_enabled && cfg.netstack_socks_port == Some(NETSTACK_SOCKS_PORT));
        assert!(
            !reconcile_at_start(&mut cfg, true),
            "once: nothing to save again"
        );

        let mut kept = archive();
        kept.netstack_socks_port = Some(1080);
        assert!(reconcile_at_start(&mut kept, true));
        assert_eq!(
            kept.netstack_socks_port,
            Some(1080),
            "a port it had is kept"
        );

        let mut outside = archive();
        assert!(
            !reconcile_at_start(&mut outside, false),
            "nothing outside the image changes"
        );
        assert!(!outside.overlay_enabled, "the owner's own choice stays");

        let mut not_archive = archive();
        not_archive.hive_archive = false;
        assert!(
            !reconcile_at_start(&mut not_archive, true),
            "not an archive replica: left alone"
        );
    }

    /// Refused before the token is spent: an ephemeral enrollment, and an
    /// existing config. A fresh, standard one goes ahead where the build
    /// holds copies.
    #[test]
    fn only_a_fresh_standard_enrollment_becomes_an_archive_replica() {
        let ephemeral = preflight(false, true).unwrap_err().to_string();
        let existing = preflight(true, false).unwrap_err().to_string();
        if cfg!(hive_host) {
            assert!(ephemeral.contains("ephemeral"), "{ephemeral}");
            assert!(existing.contains("fresh config"), "{existing}");
            assert!(preflight(false, false).is_ok());
        } else {
            assert!(ephemeral.contains("hive"), "{ephemeral}");
            assert!(preflight(false, false).is_err());
        }
    }
}
