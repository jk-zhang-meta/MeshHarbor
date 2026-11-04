// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-2b — whether a session may take a vault role, or keep it as it
//! moves to another device.
//!
//! Hive owns the session and never calls the vault (`vault → hive` in the
//! module graph), so it asks the vault's gate through core's hook registry
//! ([`meshharbor_core::SessionGate`]):
//!
//! | When | Who is asked about | The device in the question |
//! |---|---|---|
//! | a start that names a role | the starter | the device it starts on |
//! | a promote or a teleport of a session with a role | the person moving it | the device it moves TO |
//! | a fork of a session with a role | the person forking it | the device the fork runs on |
//!
//! A role is decided with its device because a policy may say "on a build
//! box only": a session that moved with its role unchecked would carry the
//! build box's powers to a laptop.
//!
//! ⚠️ No gate (the vault not mounted) refuses: a session never starts, or
//! moves, without the role it holds having been decided.

use bson::oid::ObjectId;
use meshharbor_remote_control::models::{Agent, OsKind};
use meshharbor_core::RoleAsk;
use tracing::warn;

use crate::HiveState;

/// Why a role was not allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RoleDeny {
    /// The vault's policies refused it; the gate's reason (the policies
    /// that decided it, or `default_deny`, `unknown_role`, …).
    Refused(String),
    /// No vault is mounted to decide it.
    Unavailable,
    /// The vault failed to decide or to record its decision.
    Undecided,
}

/// The longest role name the start accepts; the vault decides the rest.
pub(crate) const MAX_ROLE_LEN: usize = 64;

/// A role as typed, trimmed: refused only when no role could be named so
/// (empty, too long, a control character). Whether it is one of the
/// organization's roles is the vault's answer.
pub(crate) fn clean_role(raw: &str) -> Result<String, String> {
    let role = raw.trim();
    if role.is_empty() || role.len() > MAX_ROLE_LEN || role.chars().any(char::is_control) {
        return Err(format!("role must be 1 to {MAX_ROLE_LEN} bytes, printable"));
    }
    Ok(role.to_string())
}

/// The agent row's OS as the vault's policies spell it (`OsKind`, snake
/// case — the row's own serialisation, never a re-casing).
fn os_name(os: OsKind) -> &'static str {
    match os {
        OsKind::Linux => "linux",
        OsKind::Macos => "macos",
        OsKind::Windows => "windows",
    }
}

/// Ask the vault whether `user` may take `role` for `session_id` on
/// `device`.
pub(crate) async fn assume(
    state: &HiveState,
    tenant_id: ObjectId,
    user: ObjectId,
    role: &str,
    session_id: ObjectId,
    device: &Agent,
    purpose: &'static str,
) -> Result<(), RoleDeny> {
    let Some(gate) = state.core.hooks.session_gate() else {
        return Err(RoleDeny::Unavailable);
    };
    let ask = RoleAsk {
        tenant_id,
        user_id: user,
        role: role.to_string(),
        session_id,
        device_id: device.id.unwrap_or_default(),
        device_os: os_name(device.os).to_string(),
        device_tags: device.tags.clone(),
        device_owner: device.owner_user_id,
        purpose,
    };
    match gate.role_assume(&ask).await {
        Ok(v) if v.allow => Ok(()),
        Ok(v) => Err(RoleDeny::Refused(v.reason)),
        Err(e) => {
            warn!(session = %session_id, role, purpose, %e, "hive: the vault could not decide a role");
            Err(RoleDeny::Undecided)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_is_refused_only_when_none_could_be_named() {
        assert_eq!(clean_role(" dev ").unwrap(), "dev");
        assert!(clean_role("").is_err());
        assert!(clean_role("   ").is_err());
        assert!(clean_role(&"r".repeat(MAX_ROLE_LEN + 1)).is_err());
        assert!(clean_role("de\nv").is_err());
        // Not this side's to judge: the vault answers `unknown_role`.
        assert_eq!(clean_role("Deployer").unwrap(), "Deployer");
    }

    #[test]
    fn the_os_is_spelled_as_the_row_stores_it() {
        for (os, name) in [
            (OsKind::Linux, "linux"),
            (OsKind::Macos, "macos"),
            (OsKind::Windows, "windows"),
        ] {
            assert_eq!(os_name(os), name);
            assert_eq!(
                serde_json::to_value(os).unwrap(),
                serde_json::json!(name),
                "the row's own spelling"
            );
        }
    }
}
