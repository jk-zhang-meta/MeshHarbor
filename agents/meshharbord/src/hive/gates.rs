// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The device's own gates for a session start — pure functions over the
//! `hive_*` config keys, so the whole decision is testable as a table.
//!
//! Every gate fails CLOSED: off, nobody, nowhere. None of them takes an
//! answer from the server — the start frame names who is asking and where,
//! never which account, and this module is where "who" becomes an account.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bson::oid::ObjectId;
use meshharbor_node_core::config::AgentConfig;
use meshharbor_remote_control::hive::HiveRefusal;

/// `hive_max_sessions` when unset.
pub const DEFAULT_MAX_SESSIONS: usize = 4;

/// `hive_update_wait_secs` when unset: AC7's bound, 30 minutes.
pub const DEFAULT_UPDATE_WAIT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// The `hive_*` keys, read once at daemon start — they are restart-required
/// on the config surface, so a snapshot is the truth until the next start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiveConfig {
    pub enabled: bool,
    pub accounts: BTreeMap<String, String>,
    pub roots: Vec<PathBuf>,
    pub max_sessions: usize,
    pub harness: Option<PathBuf>,
    pub api_key_helper: Option<String>,
    /// Sent as `anthropic-workspace-id` with the key (P0g).
    pub api_workspace_id: Option<String>,
    /// P1d-1 (AC7) — how long an update waits for running turns.
    pub update_wait: std::time::Duration,
    /// P1e — whether a session here is shown the org's core memory.
    pub core_memory: bool,
    /// P1j — whether this device's people may adopt their terminal
    /// sessions (`hive_adopt`).
    pub adopt: bool,
    /// Decision 15 — whether a Mac runs sessions as an account whose `sudo`
    /// needs no password (`hive_allow_passwordless_sudo`).
    pub allow_passwordless_sudo: bool,
    /// P2c — whether this device holds copies of its owner's sessions run
    /// elsewhere (`hive_replica`).
    pub replica: bool,
    /// P2c — whether it offers itself as the org's archive (`hive_archive`):
    /// only ever with `replica`.
    pub archive: bool,
    /// P2c — the most it keeps as a replica, in MiB (`hive_store_quota_mib`).
    pub store_quota_mib: Option<u32>,
    /// FR-90 P3-7-3c — whether a session here is offered its own egress
    /// (`hive_net`): `net_socks` and `net_forward`, where the vault is too.
    pub net: bool,
    /// FR-90 P3-8-2b-2 — whether a session here is offered `ssh_run`
    /// (`hive_ssh`): one command on another device, where the vault is too.
    pub ssh: bool,
}

impl HiveConfig {
    pub fn from_agent(cfg: &AgentConfig) -> Self {
        Self {
            enabled: cfg.hive_enabled,
            accounts: cfg.hive_accounts.clone(),
            roots: cfg.hive_roots.iter().map(PathBuf::from).collect(),
            max_sessions: cfg
                .hive_max_sessions
                .map(|n| n as usize)
                .unwrap_or(DEFAULT_MAX_SESSIONS),
            harness: cfg.hive_harness.as_deref().map(PathBuf::from),
            api_key_helper: cfg.hive_api_key_helper.clone(),
            api_workspace_id: cfg.hive_api_workspace_id.clone(),
            update_wait: cfg
                .hive_update_wait_secs
                .map(|s| std::time::Duration::from_secs(u64::from(s)))
                .unwrap_or(DEFAULT_UPDATE_WAIT),
            core_memory: cfg.hive_core_memory,
            // The owner's word on every OS: FR-97 P4c adopts on Windows too,
            // through a named pipe (P1i-2 had held it off there).
            adopt: cfg.hive_adopt,
            allow_passwordless_sudo: cfg.hive_allow_passwordless_sudo,
            replica: cfg.hive_replica,
            archive: cfg.hive_archive && cfg.hive_replica,
            store_quota_mib: cfg.hive_store_quota_mib,
            net: cfg.hive_net,
            ssh: cfg.hive_ssh,
        }
    }

    /// Every gate closed — what a daemon that never read a config holds.
    pub fn closed() -> Self {
        Self {
            enabled: false,
            accounts: BTreeMap::new(),
            roots: Vec::new(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            harness: None,
            api_key_helper: None,
            api_workspace_id: None,
            update_wait: DEFAULT_UPDATE_WAIT,
            core_memory: false,
            adopt: false,
            allow_passwordless_sudo: false,
            replica: false,
            archive: false,
            store_quota_mib: None,
            net: false,
            ssh: false,
        }
    }
}

/// The local account a MeshHarbor user's sessions run as, or `no_account`.
///
/// By user id first — it never changes — then by the address the server sent:
/// that is the account's PROVEN address, or the `.invalid` placeholder
/// `users.email` holds for one that never proved it, which must match
/// nothing. Addresses compare case-insensitively, as mail does.
pub fn account_for(
    cfg: &HiveConfig,
    user_id: &ObjectId,
    user_email: &str,
) -> Result<String, HiveRefusal> {
    if let Some(account) = cfg.accounts.get(&user_id.to_hex()) {
        return Ok(account.clone());
    }
    let email = user_email.trim();
    let unproven = email.to_ascii_lowercase().ends_with(".invalid");
    if !email.is_empty()
        && !unproven
        && let Some((_, account)) = cfg
            .accounts
            .iter()
            .find(|(user, _)| user.eq_ignore_ascii_case(email))
    {
        return Ok(account.clone());
    }
    Err(HiveRefusal::NoAccount)
}

/// The folder resolved and confined to `hive_roots`, or
/// `folder_not_allowed` — which also covers a folder that does not exist,
/// since nothing can be confined that cannot be resolved.
pub fn folder_for(cfg: &HiveConfig, folder: &str) -> Result<PathBuf, HiveRefusal> {
    meshharbor_hive_node::roots::confine(Path::new(folder), &cfg.roots)
        .map_err(|_| HiveRefusal::FolderNotAllowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(accounts: &[(&str, &str)]) -> HiveConfig {
        HiveConfig {
            enabled: true,
            accounts: accounts
                .iter()
                .map(|(u, a)| (u.to_string(), a.to_string()))
                .collect(),
            ..HiveConfig::closed()
        }
    }

    /// FR-90 P3-7-3c — `hive_net` is the owner's word, read into the snapshot
    /// as it is, and closed in a daemon that read no config.
    #[test]
    fn hive_net_is_the_owners_word() {
        let mut agent = crate::config::test_fixture();
        agent.hive_net = true;
        assert!(HiveConfig::from_agent(&agent).net);
        agent.hive_net = false;
        assert!(!HiveConfig::from_agent(&agent).net);
        assert!(!HiveConfig::closed().net);
    }

    /// FR-90 P3-8-2b-2 — so is `hive_ssh`, and neither key opens the other.
    #[test]
    fn hive_ssh_is_the_owners_word() {
        let mut agent = crate::config::test_fixture();
        agent.hive_ssh = true;
        let hive = HiveConfig::from_agent(&agent);
        assert!(hive.ssh);
        assert!(!hive.net, "hive_ssh is not egress");
        agent.hive_ssh = false;
        agent.hive_net = true;
        assert!(!HiveConfig::from_agent(&agent).ssh, "nor egress SSH");
        assert!(!HiveConfig::closed().ssh);
    }

    /// `hive_adopt` is the owner's word, on Windows too since FR-97 P4c
    /// (P1i-2 read it off there).
    #[test]
    fn hive_adopt_is_the_owners_word() {
        let mut agent = crate::config::test_fixture();
        agent.hive_adopt = true;
        assert!(HiveConfig::from_agent(&agent).adopt);
        agent.hive_adopt = false;
        assert!(!HiveConfig::from_agent(&agent).adopt);
    }

    /// P2c — the replica keys are the owner's word, and an archive is only
    /// ever a replica too: `hive_archive` alone reads off.
    #[test]
    fn an_archive_is_only_ever_a_replica_too() {
        let mut agent = crate::config::test_fixture();
        let hive = HiveConfig::from_agent(&agent);
        assert!(!hive.replica && !hive.archive && hive.store_quota_mib.is_none());
        agent.hive_archive = true;
        assert!(
            !HiveConfig::from_agent(&agent).archive,
            "no replica, no archive"
        );
        agent.hive_replica = true;
        agent.hive_store_quota_mib = Some(2048);
        let hive = HiveConfig::from_agent(&agent);
        assert!(hive.replica && hive.archive);
        assert_eq!(hive.store_quota_mib, Some(2048));
    }

    #[test]
    fn a_closed_config_has_every_gate_shut() {
        let c = HiveConfig::closed();
        assert!(!c.enabled);
        assert!(c.accounts.is_empty() && c.roots.is_empty());
        assert_eq!(
            account_for(&c, &ObjectId::new(), "dev@example.com"),
            Err(HiveRefusal::NoAccount)
        );
    }

    #[test]
    fn the_id_wins_then_the_proven_address_case_insensitively() {
        let id = ObjectId::new();
        let c = cfg(&[(&id.to_hex(), "by-id"), ("Dev@Example.com", "by-mail")]);
        assert_eq!(account_for(&c, &id, "dev@example.com").unwrap(), "by-id");
        assert_eq!(
            account_for(&c, &ObjectId::new(), "DEV@example.COM").unwrap(),
            "by-mail"
        );
        assert_eq!(
            account_for(&c, &ObjectId::new(), "other@example.com"),
            Err(HiveRefusal::NoAccount)
        );
    }

    /// An account that never proved its address carries a `.invalid`
    /// placeholder, and a map entry spelled like it must not let it in.
    #[test]
    fn an_unproven_address_matches_nothing() {
        let c = cfg(&[("x@users.meshharbor.invalid", "dev")]);
        assert_eq!(
            account_for(&c, &ObjectId::new(), "x@users.meshharbor.invalid"),
            Err(HiveRefusal::NoAccount)
        );
        assert_eq!(
            account_for(&c, &ObjectId::new(), ""),
            Err(HiveRefusal::NoAccount)
        );
    }

    #[test]
    fn empty_roots_mean_nowhere_and_a_missing_folder_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(&[]);
        let folder = dir.path().to_string_lossy().to_string();
        assert_eq!(
            folder_for(&c, &folder),
            Err(HiveRefusal::FolderNotAllowed),
            "empty hive_roots is nowhere"
        );
        c.roots = vec![dir.path().to_path_buf()];
        let inside = dir.path().join("app");
        std::fs::create_dir(&inside).unwrap();
        assert!(folder_for(&c, &inside.to_string_lossy()).is_ok());
        assert_eq!(
            folder_for(&c, &dir.path().join("missing").to_string_lossy()),
            Err(HiveRefusal::FolderNotAllowed)
        );
    }
}
