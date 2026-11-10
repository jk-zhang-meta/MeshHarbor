// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Config shapes for the remote app-launch feature (`[virtual_desktop_apps]`
//! in the agent config.toml).
//!
//! P3e lever E: ONLY the serde types live here — [`crate::config::AgentConfig`]
//! embeds [`VirtualDesktopAppsConfig`], so the types must be nameable without
//! the launch machinery. The window-manager trait, the platform backends, and
//! the process-global `APPS_CONFIG` install stay in `meshharbord`'s
//! `apps` module, which re-exports these types under their old paths.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Remote app-launch config. Default: enabled with a seeded bash/tmux
/// entry so a fresh VD host offers "New bash session" out of the box.
/// Operators add htop/mc/… per host. Mirrors the [`crate::acl`]
/// allowlist pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualDesktopAppsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Friendly key → command spec. The browser sends only the KEY.
    #[serde(default)]
    pub allowlist: BTreeMap<String, AppSpec>,
}

/// One launchable app. `command` is argv (no shell interpolation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSpec {
    /// argv[0..] — executed directly, never through a shell.
    pub command: Vec<String>,
    /// Display label; falls back to the key when absent.
    #[serde(default)]
    pub label: Option<String>,
    /// Wrap in a terminal (Linux `xterm -e …`) — for TUI apps.
    #[serde(default)]
    pub terminal: bool,
    /// tmux-backed shell: launch creates/attaches a persistent session.
    #[serde(default)]
    pub tmux: bool,
}

fn default_true() -> bool {
    true
}

impl Default for VirtualDesktopAppsConfig {
    fn default() -> Self {
        let mut allowlist = BTreeMap::new();
        // Seed an OS-appropriate shell so a fresh host has one launchable
        // entry out of the box; operators add more in the TOML.
        #[cfg(target_os = "windows")]
        allowlist.insert(
            "cmd".to_string(),
            AppSpec {
                command: vec!["cmd.exe".to_string()],
                label: Some("New Command Prompt".to_string()),
                terminal: false,
                tmux: false,
            },
        );
        #[cfg(not(target_os = "windows"))]
        allowlist.insert(
            "bash".to_string(),
            AppSpec {
                command: vec!["bash".to_string()],
                label: Some("New bash session".to_string()),
                terminal: true,
                tmux: true,
            },
        );
        Self {
            enabled: true,
            allowlist,
        }
    }
}
