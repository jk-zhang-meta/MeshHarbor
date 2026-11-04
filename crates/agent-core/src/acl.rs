// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(4): names the PRE-RENAME appdirs segment a host installed before
// P4b still has; appdirs::app_segment resolves it, so it is an input.
//! Agent-side forward allowlist — the second gate after the
//! server-side ACL in `api/ws/tunnel.rs`.
//!
//! Config-driven via `[tunnel]` block in `~/.config/meshharbor-agent/
//! config.toml`. Operators on org-controlled hosts narrow what the
//! server's tenant-wide policies permit (e.g. "this VM only ever
//! forwards to db.intranet:5432, never ssh"). On self-controlled
//! hosts the operator leaves `forward_allowlist` empty + sets
//! `enable_tunnel_forwards = true` to trust the server unconditionally.
//!
//! Data shapes (`HostPattern`, `PortRange`, `DestinationRule`) are
//! canonical in `meshharbor_remote_control::models` and re-exported
//! by `tunnel-core::policy`. The agent's ACL re-uses them so a
//! single rule shape covers both gates and the same `dst_matches`
//! helper applies.

use meshharbor_remote_control::models::{DestinationRule, ProtocolKind, dst_matches};
use serde::{Deserialize, Serialize};

/// Why the agent rejected a forward request. Maps to wire-level
/// `RejectKind::AgentAclDenied` (the agent's local denial — distinct
/// from the server's `AclDenied`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Reject { reason: String },
}

impl AclDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, AclDecision::Allow)
    }
}

/// Operator-configured local gate. Default in `AgentConfig` is
/// `enabled: true` + `allowlist: vec![]` (trust the server). The
/// operator narrows by adding rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentForwardAcl {
    /// Master switch. `false` = reject every forward. Self-controlled
    /// hosts that never want to act as a tunnel target set this to
    /// `false` even though the operator may also be enrolled to issue
    /// forwards from the same machine elsewhere.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Operator's narrower allowlist. Empty + enabled = "trust the
    /// server's policy decision". Non-empty + enabled = "additional
    /// restriction beyond the server's gate".
    #[serde(default)]
    pub allowlist: Vec<DestinationRule>,
}

fn default_enabled() -> bool {
    true
}

impl Default for AgentForwardAcl {
    fn default() -> Self {
        // Match the serde `default_enabled` behaviour so a fresh
        // AgentForwardAcl::default() and a missing-from-TOML config
        // both produce the same value. Operator opts out via
        // `enabled = false`; opts into narrower allowlist via
        // `allowlist = [...]`.
        Self {
            enabled: true,
            allowlist: Vec::new(),
        }
    }
}

impl AgentForwardAcl {
    /// Belt-and-suspenders check. Called AFTER the server's gate has
    /// already approved the request (otherwise the agent would never
    /// see a `ServerMsg::TcpForwardForward` / `UdpForwardForward`).
    /// `proto` is the request's L4 protocol so a narrowed local rule
    /// (`proto = tcp`/`udp`) can reject a mismatched forward.
    pub fn check(&self, dst_host: &str, dst_port: u16, proto: ProtocolKind) -> AclDecision {
        if !self.enabled {
            return AclDecision::Reject {
                reason: "agent has tunnel forwards disabled".into(),
            };
        }
        if self.allowlist.is_empty() {
            // Empty + enabled = trust the server's gate.
            return AclDecision::Allow;
        }
        for rule in &self.allowlist {
            if rule.proto.permits(proto) && dst_matches(rule, dst_host, dst_port) {
                return AclDecision::Allow;
            }
        }
        AclDecision::Reject {
            reason: format!("{dst_host}:{dst_port} ({proto:?}) not in agent allowlist"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::models::{HostPattern, PortRange};

    fn rule(p: HostPattern, low: u16, high: u16) -> DestinationRule {
        DestinationRule {
            host_pattern: p,
            port_range: PortRange { low, high },
            proto: ProtocolKind::Any,
        }
    }

    #[test]
    fn default_acl_is_enabled_trust_server() {
        // Default `AgentForwardAcl::default()` = enabled + empty
        // allowlist = trust the server. Important: in v1 a fresh
        // install accepts forwards once an admin configures
        // `tunnel_policies` server-side.
        let acl = AgentForwardAcl::default();
        assert!(acl.enabled);
        assert!(acl.allowlist.is_empty());
        assert!(acl.check("db.intranet", 5432, ProtocolKind::Tcp).is_allow());
    }

    #[test]
    fn disabled_rejects_everything_even_with_allowlist() {
        let acl = AgentForwardAcl {
            enabled: false,
            allowlist: vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        };
        assert!(matches!(
            acl.check("db", 5432, ProtocolKind::Tcp),
            AclDecision::Reject { .. }
        ));
    }

    #[test]
    fn empty_allowlist_with_enabled_trusts_server() {
        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![],
        };
        // Server has already gated this request, so the agent accepts
        // any (dst_host, dst_port) the server sent down.
        assert!(acl.check("anywhere", 1, ProtocolKind::Tcp).is_allow());
        assert!(
            acl.check("evil.example", 65535, ProtocolKind::Tcp)
                .is_allow()
        );
    }

    #[test]
    fn nonempty_allowlist_narrows_server_gate() {
        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![rule(HostPattern::Exact("db.intranet".into()), 5432, 5432)],
        };
        assert!(acl.check("db.intranet", 5432, ProtocolKind::Tcp).is_allow());
        // Same host, wrong port — rejected even though the server
        // approved it (server's policy may allow a broader port
        // range; agent operator chose to narrow further).
        assert!(matches!(
            acl.check("db.intranet", 22, ProtocolKind::Tcp),
            AclDecision::Reject { .. }
        ));
    }

    #[test]
    fn wildcard_rule_matches_subdomains() {
        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![rule(HostPattern::Wildcard("*.intranet".into()), 1, 65535)],
        };
        assert!(acl.check("db.intranet", 5432, ProtocolKind::Tcp).is_allow());
        assert!(acl.check("ssh.intranet", 22, ProtocolKind::Tcp).is_allow());
        assert!(matches!(
            acl.check("evilintranet", 80, ProtocolKind::Tcp),
            AclDecision::Reject { .. }
        ));
    }

    #[test]
    fn cidr_rule_matches_ip_only() {
        let acl = AgentForwardAcl {
            enabled: true,
            allowlist: vec![rule(HostPattern::Cidr("10.0.0.0/24".into()), 5432, 5432)],
        };
        assert!(acl.check("10.0.0.5", 5432, ProtocolKind::Tcp).is_allow());
        assert!(matches!(
            acl.check("10.0.1.5", 5432, ProtocolKind::Tcp),
            AclDecision::Reject { .. }
        ));
    }
}
