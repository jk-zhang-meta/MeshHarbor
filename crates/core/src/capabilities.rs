// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! What a module offers a tenant — computed, never stored.

use std::collections::BTreeMap;

use bson::oid::ObjectId;
use meshharbor_db::models::tenant::{Plan, TenantSettings};
use serde::{Deserialize, Serialize};

/// The tenant a capability question is asked for.
///
/// Carries the two documents a module needs to answer — the plan (limits and
/// flags) and the tenant's own settings (`remote_exec_enabled`,
/// `magic_dns_domain`, …). Both keep living in core's `tenants` document with
/// their serde defaults, so a build without a module simply ignores that
/// module's fields (FR-69 D8).
#[derive(Debug, Clone)]
pub struct TenantCtx {
    pub tenant_id: ObjectId,
    pub plan: Plan,
    pub settings: TenantSettings,
}

/// One module's answer: on or off, with the flags and limits that apply.
///
/// `GET /api/capabilities` is a map of these keyed by [`crate::Module::ID`];
/// the SPA hides navigation from it, the daemon reads it in the hello, the CLI
/// prints it. The unauthenticated form carries only the module list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// The module id this answer is about.
    pub module: String,
    /// Compiled ∩ runtime-enabled ∩ plan ∩ tenant settings.
    pub enabled: bool,
    /// Feature flags within the module (`exec`, `ssh`, `recordings`, …).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub flags: BTreeMap<String, bool>,
    /// Numeric ceilings within the module (`max_devices`, …).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, u64>,
}

impl Capabilities {
    /// A module that is present and on.
    pub fn enabled(module: &str) -> Self {
        Self {
            module: module.to_string(),
            enabled: true,
            ..Self::default()
        }
    }

    /// A module that is present but off for this tenant (plan, settings, or
    /// the runtime switch). Present-but-off is a different answer from
    /// absent: the UI can explain the first and must stay silent on the second.
    pub fn disabled(module: &str) -> Self {
        Self {
            module: module.to_string(),
            enabled: false,
            ..Self::default()
        }
    }

    pub fn flag(mut self, name: &str, on: bool) -> Self {
        self.flags.insert(name.to_string(), on);
        self
    }

    pub fn limit(mut self, name: &str, ceiling: u64) -> Self {
        self.limits.insert(name.to_string(), ceiling);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_and_wire_shape() {
        let c = Capabilities::enabled("network")
            .flag("ssh", true)
            .limit("max_devices", 30);
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "module": "network",
                "enabled": true,
                "flags": { "ssh": true },
                "limits": { "max_devices": 30 }
            })
        );
        // Empty maps are omitted on the wire — the unauthenticated form is
        // meant to stay small.
        let off = serde_json::to_value(Capabilities::disabled("chat")).unwrap();
        assert_eq!(
            off,
            serde_json::json!({ "module": "chat", "enabled": false })
        );
    }
}
