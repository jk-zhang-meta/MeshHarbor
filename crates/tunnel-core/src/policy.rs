// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! ACL evaluation primitives.
//!
//! Data shapes are canonical in `meshharbor_remote_control::models`
//! (single source of truth for both the DB rows and the eval logic).
//! This module re-exports them and adds the pure-function evaluator.
//!
//! Evaluation is server-side per plan §7 (defence-in-depth) — the
//! agent runs its own minimal allowlist as a second gate, but the
//! authoritative decision is the server's.
//!
//! Cross-tenant gating happens UPSTREAM of `evaluate` — the caller
//! must filter `policies` to a single tenant before calling here.
//! `evaluate` does NOT receive a `tenant_id` to enforce this
//! contract explicitly: there's no field for it to check, so the
//! responsibility lands cleanly on the caller (the WS handler in
//! `api/ws/tunnel.rs`). The integration test in
//! `crates/tests/src/tunnel_tests.rs` locks the cross-tenant gate.

use bson::oid::ObjectId;

pub use meshharbor_remote_control::models::{
    Agent, AgentStatus, DestinationRule, HostPattern, PolicySubject, PolicyTarget, PortRange,
    ProtocolKind, TunnelPolicy,
};
pub use meshharbor_remote_control::signaling::RejectKind;

/// The concrete principal that ORIGINATED a tunnel request. Historically
/// this was always a `TunnelClient`; the node-stack unification (P3b-2) lets
/// an enrolled **agent** originate tunnels over its own WS, so the principal
/// is now a typed union rather than a bare `tunnel_client_id`. `AllUsers` /
/// `UserId{owner}` / `RoleId` policy subjects match a tunnel client or an
/// agent (they key on `user_id`/`role_ids`); only the id-specific subjects
/// (`TunnelClientId` / `AgentId`) discriminate on the principal kind.
///
/// FR-90 P3-7-2a — `Session` is an agent session's own flow, carried by the
/// device it runs on under a grant the vault signed (`net_grant`). It
/// matches NO subject yet: which subjects may name a session is decision 20,
/// and until it is made a session reaches nothing its owner or its device
/// may ([`subject_matches`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    TunnelClient(ObjectId),
    Agent(ObjectId),
    /// FR-90 P3-7-2a — an agent session, by its id, on the device (`agent_id`)
    /// whose own WS carries its flows.
    Session {
        session_id: ObjectId,
        agent_id: ObjectId,
    },
}

/// Concrete identity for the requesting tunnel origin. The caller
/// resolves this once per request (from the WS handler's auth
/// context + a Mongo lookup for `role_ids`) and hands it to
/// [`evaluate`].
#[derive(Debug, Clone)]
pub struct ResolvedSubject {
    pub user_id: ObjectId,
    pub role_ids: Vec<ObjectId>,
    pub principal: Principal,
}

/// Outcome of an ACL evaluation. On allow, carries the policy id +
/// the rule that matched + the per-policy ceilings so the caller
/// can plumb them into the per-session counters. On deny, carries
/// a human-readable reason — the caller maps that to the wire-level
/// `RejectKind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow {
        policy_id: ObjectId,
        rule: DestinationRule,
        max_concurrent_flows: Option<u32>,
        max_bytes_per_session: Option<u64>,
    },
    Deny {
        reason: String,
    },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

/// Run the full ACL check: does any policy in `policies` permit
/// `subject` to reach `(dst_host, dst_port)` on `agent_id`?
///
/// First-match-wins semantics — policies are evaluated in the order
/// the caller supplies them (typically `created_at DESC` for newest-
/// wins). Default-deny if no policy matches.
///
/// Cross-tenant: callers MUST pre-filter `policies` to the
/// agent's tenant. See module docs.
pub fn evaluate(
    policies: &[TunnelPolicy],
    subject: &ResolvedSubject,
    agent_id: ObjectId,
    dst_host: &str,
    dst_port: u16,
    proto: ProtocolKind,
) -> Decision {
    for policy in policies {
        if policy.deleted_at.is_some() {
            continue;
        }
        if !subject_matches(&policy.subjects, subject) {
            continue;
        }
        if !target_matches(&policy.targets, agent_id) {
            continue;
        }
        if let Some(rule) = policy
            .allowlist
            .iter()
            .find(|r| r.proto.permits(proto) && dst_matches(r, dst_host, dst_port))
        {
            return Decision::Allow {
                policy_id: policy.id.unwrap_or_else(ObjectId::new),
                rule: rule.clone(),
                max_concurrent_flows: policy.max_concurrent_flows,
                max_bytes_per_session: policy.max_bytes_per_session,
            };
        }
    }
    Decision::Deny {
        reason: "no policy matches".into(),
    }
}

/// Does any `PolicySubject` in `subjects` match the requesting
/// `ResolvedSubject`? `AllUsers` is the catch-all, for a person's tunnel
/// client and for an agent.
///
/// ⚠️ FR-90 P3-7-2a — an agent SESSION matches no subject, `AllUsers`
/// included: which subjects may name a session is decision 20, and a session
/// that matched its owner's subjects would reach whatever its owner may.
/// Checked first, before any subject is read, so a subject added later
/// cannot match a session by accident.
pub fn subject_matches(subjects: &[PolicySubject], req: &ResolvedSubject) -> bool {
    if matches!(req.principal, Principal::Session { .. }) {
        return false;
    }
    subjects.iter().any(|s| match s {
        PolicySubject::AllUsers => true,
        PolicySubject::UserId { user_id } => *user_id == req.user_id,
        PolicySubject::RoleId { role_id } => req.role_ids.contains(role_id),
        // Id-specific subjects discriminate on the principal KIND: a
        // `TunnelClientId` subject only matches a tunnel-client principal, an
        // `AgentId` subject only an agent principal. Never cross the kinds —
        // an agent_id must not satisfy a tunnel_client_id subject even on a
        // (vanishingly unlikely) ObjectId collision.
        PolicySubject::TunnelClientId { tunnel_client_id } => {
            matches!(req.principal, Principal::TunnelClient(id) if id == *tunnel_client_id)
        }
        PolicySubject::AgentId { agent_id } => {
            matches!(req.principal, Principal::Agent(id) if id == *agent_id)
        }
    })
}

/// Does any `PolicyTarget` in `targets` match `agent_id`? `AllAgents`
/// is the catch-all (within the policy's tenant).
pub fn target_matches(targets: &[PolicyTarget], agent_id: ObjectId) -> bool {
    targets.iter().any(|t| match t {
        PolicyTarget::AllAgents => true,
        PolicyTarget::AgentId { agent_id: id } => *id == agent_id,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Server-side ACL gate (T2.4)
// ────────────────────────────────────────────────────────────────────────────

/// Result of the full server-side gate for a `TcpForwardRequest`.
/// On allow, carries the per-policy ceilings so the caller plumbs
/// them into the per-session counters. On reject, carries the wire-
/// level `RejectKind` + a human-readable reason — the caller maps
/// these straight into a `TcpForwardReject` ServerMsg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateResult {
    Allow {
        policy_id: ObjectId,
        rule: DestinationRule,
        max_concurrent_flows: Option<u32>,
        max_bytes_per_session: Option<u64>,
    },
    Reject {
        kind: RejectKind,
        reason: String,
    },
}

impl GateResult {
    pub fn is_allow(&self) -> bool {
        matches!(self, GateResult::Allow { .. })
    }
}

/// The full server-side gate that runs on every `TcpForwardRequest`.
/// Pure function — caller pre-fetches the agent row + the active
/// policies for the agent's tenant.
///
/// Sequence:
/// 1. **Cross-tenant gate** (plan §"Multi-tenancy gotcha") —
///    `client_tenant_id` MUST equal `agent.tenant_id`. Defence-in-
///    depth: the WS upgrade's tenant_id check already covers this,
///    but a cross-tenant `agent_id` snuck in via a forwarded
///    `TcpForwardRequest` must still bounce.
/// 2. **Agent availability** — refuse if the agent is soft-deleted
///    or quarantined. (Status reads as `Offline` are still allowed —
///    the WS may simply not be live; the request will fail at the
///    relay step with a connection-refused.)
/// 3. **ACL eval** — see [`evaluate`].
///
/// Locked by the `cross_tenant_gate_blocks_*` tests below.
pub fn check_forward_request(
    client_tenant_id: ObjectId,
    agent: &Agent,
    policies: &[TunnelPolicy],
    subject: &ResolvedSubject,
    dst_host: &str,
    dst_port: u16,
    proto: ProtocolKind,
) -> GateResult {
    // 1. Cross-tenant gate
    if client_tenant_id != agent.tenant_id {
        return GateResult::Reject {
            kind: RejectKind::CrossTenant,
            reason: format!(
                "client tenant {} ≠ agent tenant {}",
                client_tenant_id, agent.tenant_id
            ),
        };
    }
    // 2. Agent availability
    if agent.deleted_at.is_some() {
        return GateResult::Reject {
            kind: RejectKind::AgentError,
            reason: "agent has been deleted".into(),
        };
    }
    if matches!(agent.status, AgentStatus::Quarantined) {
        return GateResult::Reject {
            kind: RejectKind::AgentError,
            reason: "agent is quarantined".into(),
        };
    }
    // 3. ACL eval
    let agent_id = match agent.id {
        Some(id) => id,
        None => {
            return GateResult::Reject {
                kind: RejectKind::AgentError,
                reason: "agent missing _id".into(),
            };
        }
    };
    match evaluate(policies, subject, agent_id, dst_host, dst_port, proto) {
        Decision::Allow {
            policy_id,
            rule,
            max_concurrent_flows,
            max_bytes_per_session,
        } => GateResult::Allow {
            policy_id,
            rule,
            max_concurrent_flows,
            max_bytes_per_session,
        },
        Decision::Deny { reason } => GateResult::Reject {
            kind: RejectKind::AclDenied,
            reason,
        },
    }
}

// `dst_matches` / `host_matches` moved to `remote_control::models` in P3e
// lever E — the matcher now lives next to the shapes it matches over, and
// `meshharbor-node-core`'s ACL can call it without this crate's data plane.
// Re-exported here so every existing `policy::dst_matches` caller (the
// forward gate, the agent ACL tests, T2.3's evaluate flow) is unchanged.
pub use meshharbor_remote_control::models::{dst_matches, host_matches};

// ────────────────────────────────────────────────────────────────────────────
// Overlay L3 ACL
// ────────────────────────────────────────────────────────────────────────────
//
// The overlay is a different enforcement problem from the tunnel and gets its
// own evaluator rather than a reused `evaluate`:
//
//   * The tunnel gate answers "may this origin dial host:port through this
//     agent" — one boolean per TCP/UDP flow, decided while the broker is in
//     the path. The overlay's data plane is end-to-end WireGuard with the
//     server nowhere near it, so the server's only lever is WHAT IT TELLS EACH
//     NODE: which peers exist and which of their routes to install.
//   * The answer is therefore not a boolean but "is this peer visible, and
//     which subset of its approved routes does this recipient get".
//   * `HostPattern::Exact`/`Wildcard` can never match a packet's destination,
//     so overlay rules are CIDR-only ([`OverlayRule`]).
//
// Same skeleton as [`evaluate`] though: first match wins, default-deny, and
// soft-deleted rows are skipped.

pub use meshharbor_remote_control::models::{
    OverlayAclMode, OverlayPolicy, OverlayRule, OverlaySelector, OverlayTarget,
};

/// The node a netmap is being built FOR.
#[derive(Debug, Clone)]
pub struct OverlaySource {
    pub node_id: ObjectId,
    /// Owner of the backing agent / tunnel client. `None` when the backing row
    /// is gone — such a node then matches only `AllNodes` / `NodeId` rules.
    pub owner_user_id: Option<ObjectId>,
    pub role_ids: Vec<ObjectId>,
}

/// The peer being considered for inclusion in that netmap.
#[derive(Debug, Clone, Copy)]
pub struct OverlayPeerRef<'a> {
    pub node_id: ObjectId,
    pub overlay_ip: &'a str,
    pub approved_routes: &'a [String],
}

/// What a source node may see of one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayAccess {
    /// May the source dial the peer's own overlay address at all? When false
    /// the peer must be withheld from the netmap **and**, if it was already
    /// installed, revoked with an explicit `removes` — dropping it from a full
    /// netmap or shipping `reachable: false` does NOT tear down a live peer.
    pub visible: bool,
    /// The subset of the peer's `approved_routes` this source may install.
    pub routes: Vec<String>,
}

impl OverlayAccess {
    /// The pre-ACL behaviour: full visibility, every approved route.
    pub fn permissive(peer: OverlayPeerRef<'_>) -> Self {
        Self {
            visible: true,
            routes: peer.approved_routes.to_vec(),
        }
    }

    pub fn denied() -> Self {
        Self {
            visible: false,
            routes: Vec::new(),
        }
    }
}

/// Does `outer` cover `inner`? Accepts a bare address for `inner` (a peer's
/// overlay IP) as well as a prefix (an approved route).
fn cidr_covers(outer: &str, inner: &str) -> bool {
    let Ok(outer) = outer.trim().parse::<ipnet::IpNet>() else {
        return false;
    };
    if let Ok(net) = inner.trim().parse::<ipnet::IpNet>() {
        return outer.contains(&net);
    }
    match inner.trim().parse::<std::net::IpAddr>() {
        Ok(ip) => outer.contains(&ip),
        Err(_) => false,
    }
}

fn source_matches(selectors: &[OverlaySelector], src: &OverlaySource) -> bool {
    selectors.iter().any(|s| match s {
        OverlaySelector::AllNodes => true,
        OverlaySelector::NodeId { node_id } => *node_id == src.node_id,
        OverlaySelector::UserId { user_id } => src.owner_user_id == Some(*user_id),
        OverlaySelector::RoleId { role_id } => src.role_ids.contains(role_id),
    })
}

fn via_matches(targets: &[OverlayTarget], peer_id: ObjectId) -> bool {
    targets.iter().any(|t| match t {
        OverlayTarget::AllNodes => true,
        OverlayTarget::NodeId { node_id } => *node_id == peer_id,
    })
}

/// Decide what `source` may see of `peer`.
///
/// Cross-tenant gating is the CALLER's job, exactly as for [`evaluate`] —
/// there is no `tenant_id` parameter precisely so the contract stays explicit.
///
/// ⚠️ `port_range` / `proto` on a matched rule are deliberately **not**
/// consulted here: the netmap can express peer visibility and route lists and
/// nothing finer, so honouring them at this layer would silently widen a
/// port-narrowed rule into full peer access. They are carried for the
/// node-side ingress filter, which is the only layer that can apply them.
pub fn evaluate_overlay(
    policies: &[OverlayPolicy],
    source: &OverlaySource,
    peer: OverlayPeerRef<'_>,
) -> OverlayAccess {
    let mut visible = false;
    let mut routes: Vec<String> = Vec::new();

    for policy in policies {
        if policy.deleted_at.is_some() || !policy.enabled {
            continue;
        }
        if !source_matches(&policy.sources, source) {
            continue;
        }
        if !via_matches(&policy.via, peer.node_id) {
            continue;
        }
        for rule in &policy.destinations {
            if cidr_covers(&rule.cidr, peer.overlay_ip) {
                visible = true;
            }
            for route in peer.approved_routes {
                if cidr_covers(&rule.cidr, route) && !routes.iter().any(|r| r == route) {
                    routes.push(route.clone());
                }
            }
        }
    }

    // A granted subnet route is useless if the gateway itself is unreachable,
    // so any route grant implies visibility of the node that carries it.
    if !routes.is_empty() {
        visible = true;
    }
    OverlayAccess { visible, routes }
}

/// P4 — the rules `source` may use when sending INTO the node `via_node_id`.
///
/// The REVERSE direction of [`evaluate_overlay`]: that answers "what may this
/// recipient see of a peer", this answers "what may that peer address through
/// this recipient". The server compiles it per (recipient, peer) and ships it on
/// the peer's `NetmapPeer.ingress_rules`, so the node can enforce port/proto —
/// the dimensions the netmap's `routes` list structurally cannot express, which
/// is why they were stored and distributed but never enforced until now.
///
/// Returns the UNION of every matching policy's destinations, not a first-match
/// decision: these are grants, and the node treats any single match as allow.
/// An empty result therefore means "denied", which is why the caller must ship
/// `Some(vec![])` rather than `None` — see `NetmapPeer::ingress_rules`.
pub fn evaluate_overlay_ingress(
    policies: &[OverlayPolicy],
    source: &OverlaySource,
    via_node_id: ObjectId,
) -> Vec<OverlayRule> {
    let mut out: Vec<OverlayRule> = Vec::new();
    for policy in policies {
        if policy.deleted_at.is_some() || !policy.enabled {
            continue;
        }
        if !source_matches(&policy.sources, source) {
            continue;
        }
        if !via_matches(&policy.via, via_node_id) {
            continue;
        }
        out.extend(policy.destinations.iter().cloned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(p: HostPattern, low: u16, high: u16) -> DestinationRule {
        DestinationRule {
            host_pattern: p,
            port_range: PortRange { low, high },
            proto: ProtocolKind::Any,
        }
    }

    /// A `proto`-narrowed rule for the UDP/TCP gating tests below.
    fn rule_proto(p: HostPattern, low: u16, high: u16, proto: ProtocolKind) -> DestinationRule {
        DestinationRule {
            host_pattern: p,
            port_range: PortRange { low, high },
            proto,
        }
    }

    /// Test wrapper: `evaluate` with `proto = Tcp` — the pre-UDP
    /// default the bulk of these cases exercise. The proto-specific
    /// gating is locked separately in `proto_*` tests.
    fn eval_tcp(
        policies: &[TunnelPolicy],
        subject: &ResolvedSubject,
        agent_id: ObjectId,
        dst_host: &str,
        dst_port: u16,
    ) -> Decision {
        evaluate(
            policies,
            subject,
            agent_id,
            dst_host,
            dst_port,
            ProtocolKind::Tcp,
        )
    }

    /// Test wrapper: `check_forward_request` with `proto = Tcp`.
    fn check_tcp(
        client_tenant_id: ObjectId,
        agent: &Agent,
        policies: &[TunnelPolicy],
        subject: &ResolvedSubject,
        dst_host: &str,
        dst_port: u16,
    ) -> GateResult {
        check_forward_request(
            client_tenant_id,
            agent,
            policies,
            subject,
            dst_host,
            dst_port,
            ProtocolKind::Tcp,
        )
    }

    #[test]
    fn exact_host_matches_case_insensitive() {
        let r = rule(HostPattern::Exact("db.intranet".into()), 5432, 5432);
        assert!(dst_matches(&r, "db.intranet", 5432));
        assert!(dst_matches(&r, "DB.INTRANET", 5432));
        assert!(!dst_matches(&r, "other.intranet", 5432));
    }

    #[test]
    fn wildcard_requires_subdomain_dot() {
        let r = rule(HostPattern::Wildcard("*.intranet".into()), 1, 65535);
        assert!(dst_matches(&r, "db.intranet", 80));
        assert!(dst_matches(&r, "deeply.nested.intranet", 80));
        // Bare suffix isn't a subdomain match — "intranet" alone fails.
        assert!(!dst_matches(&r, "intranet", 80));
        // Look-alike suffix without the dot fails.
        assert!(!dst_matches(&r, "evilintranet", 80));
    }

    #[test]
    fn cidr_matches_ip() {
        let r = rule(HostPattern::Cidr("10.0.0.0/24".into()), 5432, 5432);
        assert!(dst_matches(&r, "10.0.0.5", 5432));
        assert!(dst_matches(&r, "10.0.0.255", 5432));
        assert!(!dst_matches(&r, "10.0.1.5", 5432));
        // Hostname (non-IP) on a CIDR rule fails — caller must resolve first.
        assert!(!dst_matches(&r, "db.intranet", 5432));
    }

    #[test]
    fn port_range_inclusive() {
        let r = rule(HostPattern::Exact("h".into()), 5000, 5010);
        assert!(dst_matches(&r, "h", 5000));
        assert!(dst_matches(&r, "h", 5005));
        assert!(dst_matches(&r, "h", 5010));
        assert!(!dst_matches(&r, "h", 4999));
        assert!(!dst_matches(&r, "h", 5011));
    }

    #[test]
    fn default_deny_when_pattern_unmatched() {
        let r = rule(HostPattern::Exact("a".into()), 1, 1);
        assert!(!dst_matches(&r, "b", 1));
    }

    // ─── Full eval_tcp() coverage (T2.3) ─────────────────────────────

    use bson::DateTime;

    fn policy(
        subjects: Vec<PolicySubject>,
        targets: Vec<PolicyTarget>,
        allowlist: Vec<DestinationRule>,
    ) -> TunnelPolicy {
        TunnelPolicy {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            name: "test".into(),
            subjects,
            targets,
            allowlist,
            max_concurrent_flows: None,
            max_bytes_per_session: None,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            deleted_at: None,
        }
    }

    fn subject(user_id: ObjectId) -> ResolvedSubject {
        ResolvedSubject {
            user_id,
            role_ids: vec![],
            principal: Principal::TunnelClient(ObjectId::new()),
        }
    }

    #[test]
    fn empty_policy_list_denies() {
        let d = eval_tcp(&[], &subject(ObjectId::new()), ObjectId::new(), "h", 1);
        assert!(matches!(d, Decision::Deny { .. }));
    }

    /// FR-90 P3-7-2a — a session matches no subject before decision 20, not
    /// even one that names its owner, its device, its id, or everyone: a
    /// policy written for people and devices opens nothing to a session.
    #[test]
    fn a_session_matches_no_subject_yet() {
        let (owner, device, session, role) = (
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
        );
        let req = ResolvedSubject {
            user_id: owner,
            role_ids: vec![role],
            principal: Principal::Session {
                session_id: session,
                agent_id: device,
            },
        };
        let aid = ObjectId::new();
        for subjects in [
            vec![PolicySubject::AllUsers],
            vec![PolicySubject::UserId { user_id: owner }],
            vec![PolicySubject::RoleId { role_id: role }],
            vec![PolicySubject::AgentId { agent_id: device }],
            vec![PolicySubject::TunnelClientId {
                tunnel_client_id: session,
            }],
        ] {
            assert!(!subject_matches(&subjects, &req), "{subjects:?}");
            let p = policy(
                subjects.clone(),
                vec![PolicyTarget::AllAgents],
                vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
            );
            assert!(
                matches!(eval_tcp(&[p], &req, aid, "db", 5432), Decision::Deny { .. }),
                "{subjects:?}"
            );
        }
        // The same subjects match the device itself, as before.
        let device_req = ResolvedSubject {
            user_id: owner,
            role_ids: vec![role],
            principal: Principal::Agent(device),
        };
        assert!(subject_matches(&[PolicySubject::AllUsers], &device_req));
        assert!(subject_matches(
            &[PolicySubject::AgentId { agent_id: device }],
            &device_req
        ));
    }

    #[test]
    fn user_id_exact_match_allows() {
        let uid = ObjectId::new();
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::UserId { user_id: uid }],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let d = eval_tcp(&[p], &subject(uid), aid, "db", 5432);
        assert!(d.is_allow(), "{d:?}");
    }

    #[test]
    fn user_id_mismatch_denies() {
        let uid = ObjectId::new();
        let aid = ObjectId::new();
        let other_user = ObjectId::new();
        let p = policy(
            vec![PolicySubject::UserId { user_id: uid }],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let d = eval_tcp(&[p], &subject(other_user), aid, "db", 5432);
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn role_id_match_allows_when_any_role_matches() {
        let aid = ObjectId::new();
        let role_a = ObjectId::new();
        let role_b = ObjectId::new();
        let p = policy(
            vec![PolicySubject::RoleId { role_id: role_a }],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let req = ResolvedSubject {
            user_id: ObjectId::new(),
            role_ids: vec![role_b, role_a],
            principal: Principal::TunnelClient(ObjectId::new()),
        };
        assert!(eval_tcp(&[p], &req, aid, "db", 5432).is_allow());
    }

    #[test]
    fn tunnel_client_id_match_allows() {
        let aid = ObjectId::new();
        let cid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::TunnelClientId {
                tunnel_client_id: cid,
            }],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let req = ResolvedSubject {
            user_id: ObjectId::new(),
            role_ids: vec![],
            principal: Principal::TunnelClient(cid),
        };
        assert!(eval_tcp(&[p], &req, aid, "db", 5432).is_allow());
    }

    // ─── agent-principal subject matching (P3b-2) ────────────────────

    /// Build a `ResolvedSubject` whose principal is an agent originating a
    /// tunnel (the P3b-2 case). `user_id` is the agent's owner.
    fn agent_subject(owner_user_id: ObjectId, agent_id: ObjectId) -> ResolvedSubject {
        ResolvedSubject {
            user_id: owner_user_id,
            role_ids: vec![],
            principal: Principal::Agent(agent_id),
        }
    }

    #[test]
    fn agent_id_subject_matches_agent_principal() {
        let target = ObjectId::new();
        let origin_agent = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AgentId {
                agent_id: origin_agent,
            }],
            vec![PolicyTarget::AgentId { agent_id: target }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let req = agent_subject(ObjectId::new(), origin_agent);
        assert!(eval_tcp(&[p], &req, target, "db", 5432).is_allow());
    }

    #[test]
    fn agent_principal_does_not_match_tunnel_client_subject() {
        // An `AgentId`-kinded principal must NOT satisfy a `TunnelClientId`
        // subject even if the raw ObjectId happened to be equal — the kinds
        // are disjoint. Use the SAME id for both to prove the kind gate, not
        // an id mismatch, is what denies.
        let aid = ObjectId::new();
        let shared = ObjectId::new();
        let p = policy(
            vec![PolicySubject::TunnelClientId {
                tunnel_client_id: shared,
            }],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let req = agent_subject(ObjectId::new(), shared);
        assert!(matches!(
            eval_tcp(&[p], &req, aid, "db", 5432),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn tunnel_client_principal_does_not_match_agent_subject() {
        // The reverse of the above — a tunnel-client principal must not
        // satisfy an `AgentId` subject.
        let aid = ObjectId::new();
        let shared = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AgentId { agent_id: shared }],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let req = ResolvedSubject {
            user_id: ObjectId::new(),
            role_ids: vec![],
            principal: Principal::TunnelClient(shared),
        };
        assert!(matches!(
            eval_tcp(&[p], &req, aid, "db", 5432),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn all_users_subject_matches_agent_principal() {
        // The de-risking property: an `AllUsers` policy authorizes an
        // agent-originated tunnel with no new subject type needed.
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let req = agent_subject(ObjectId::new(), ObjectId::new());
        assert!(eval_tcp(&[p], &req, aid, "db", 5432).is_allow());
    }

    #[test]
    fn user_id_subject_matches_agent_principal_by_owner() {
        // An agent principal is authorized by a `UserId{owner}` policy —
        // the owner drives the match, independent of principal kind.
        let owner = ObjectId::new();
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::UserId { user_id: owner }],
            vec![PolicyTarget::AllAgents],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let req = agent_subject(owner, ObjectId::new());
        assert!(eval_tcp(&[p], &req, aid, "db", 5432).is_allow());
    }

    #[test]
    fn all_users_subject_matches_any_user() {
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        assert!(eval_tcp(&[p], &subject(ObjectId::new()), aid, "db", 5432).is_allow());
    }

    #[test]
    fn all_agents_target_matches_any_agent() {
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        assert!(eval_tcp(&[p], &subject(ObjectId::new()), ObjectId::new(), "db", 5432).is_allow());
    }

    #[test]
    fn target_mismatch_denies() {
        let policy_agent = ObjectId::new();
        let other_agent = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AgentId {
                agent_id: policy_agent,
            }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let d = eval_tcp(&[p], &subject(ObjectId::new()), other_agent, "db", 5432);
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn first_match_wins_across_policies() {
        // Two policies — first is too restrictive (only port 5432),
        // second allows 22. Evaluator should walk through and return
        // the SECOND policy's allow when asked for port 22.
        let aid = ObjectId::new();
        let p1 = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let p2 = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule(HostPattern::Exact("ssh".into()), 22, 22)],
        );
        assert!(eval_tcp(&[p1, p2], &subject(ObjectId::new()), aid, "ssh", 22).is_allow());
    }

    #[test]
    fn soft_deleted_policy_is_ignored() {
        let aid = ObjectId::new();
        let mut p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        p.deleted_at = Some(DateTime::now());
        // Even though the policy would otherwise match, the soft-
        // deleted flag stops it. Defence in depth — DAO's
        // list_active_for_tenant already filters, but a stale cache
        // shouldn't allow access.
        let d = eval_tcp(&[p], &subject(ObjectId::new()), aid, "db", 5432);
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn multiple_destination_rules_any_match_allows() {
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![
                rule(HostPattern::Exact("db".into()), 5432, 5432),
                rule(HostPattern::Exact("ssh".into()), 22, 22),
            ],
        );
        assert!(eval_tcp(&[p], &subject(ObjectId::new()), aid, "ssh", 22).is_allow());
    }

    #[test]
    fn dst_mismatch_with_subject_target_match_still_denies() {
        // Subject + target match, but dst is not allowlisted —
        // strict default-deny on the destination axis.
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
        );
        let d = eval_tcp(&[p], &subject(ObjectId::new()), aid, "evil-dst", 5432);
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn allow_carries_policy_id_and_rule() {
        let aid = ObjectId::new();
        let uid = ObjectId::new();
        let r = rule(HostPattern::Exact("db".into()), 5432, 5432);
        let mut p = policy(
            vec![PolicySubject::UserId { user_id: uid }],
            vec![PolicyTarget::AgentId { agent_id: aid }],
            vec![r.clone()],
        );
        p.max_concurrent_flows = Some(32);
        p.max_bytes_per_session = Some(1024 * 1024 * 1024);
        let expected_pid = p.id.unwrap();

        match eval_tcp(&[p], &subject(uid), aid, "db", 5432) {
            Decision::Allow {
                policy_id,
                rule: matched,
                max_concurrent_flows,
                max_bytes_per_session,
            } => {
                assert_eq!(policy_id, expected_pid);
                assert_eq!(matched, r);
                assert_eq!(max_concurrent_flows, Some(32));
                assert_eq!(max_bytes_per_session, Some(1024 * 1024 * 1024));
            }
            d => panic!("expected allow, got {d:?}"),
        }
    }

    #[test]
    fn deny_carries_human_reason() {
        let d = eval_tcp(&[], &subject(ObjectId::new()), ObjectId::new(), "h", 1);
        match d {
            Decision::Deny { reason } => assert!(!reason.is_empty()),
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn cidr_target_works_end_to_end() {
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule(HostPattern::Cidr("10.0.0.0/24".into()), 5432, 5432)],
        );
        assert!(
            eval_tcp(
                std::slice::from_ref(&p),
                &subject(ObjectId::new()),
                aid,
                "10.0.0.5",
                5432
            )
            .is_allow()
        );
        assert!(matches!(
            eval_tcp(&[p], &subject(ObjectId::new()), aid, "10.1.0.5", 5432),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn subject_matches_helper_covers_all_users_alone() {
        let req = subject(ObjectId::new());
        assert!(subject_matches(&[PolicySubject::AllUsers], &req));
        assert!(!subject_matches(&[], &req));
    }

    #[test]
    fn target_matches_helper_covers_all_agents_alone() {
        assert!(target_matches(&[PolicyTarget::AllAgents], ObjectId::new()));
        assert!(!target_matches(&[], ObjectId::new()));
    }

    // ─── Server-side gate (T2.4) ─────────────────────────────────────

    use meshharbor_remote_control::models::{AgentCaps, OsKind};

    fn agent_for(tenant_id: ObjectId, status: AgentStatus, deleted: bool) -> Agent {
        Agent {
            id: Some(ObjectId::new()),
            tenant_id,
            owner_user_id: ObjectId::new(),
            access_policy_rev: None,
            enrolled_by: None,
            name: "test-agent".into(),
            display_name: None,
            tags: Vec::new(),
            name_admin_set: false,
            machine_id: "m".into(),
            // FR-51 — a permanent fixture device; the ephemeral shape has its
            // own tests in `crates/tests/src/ephemeral_tests.rs`.
            ephemeral: false,
            ephemeral_ttl_secs: None,
            enroll_key_id: None,
            os: OsKind::Linux,
            arch: None,
            arch_emulated: false,
            agent_version: "0".into(),
            companion_version: None,
            keep_busy: None,
            ssh_host_pubkey: String::new(),
            vault_key: String::new(),
            peer_auth_key: String::new(),
            agent_token_hash: String::new(),
            token_gen: 0,
            token_exp: None,
            status,
            last_seen_at: DateTime::now(),
            last_presence: None,
            warm_relay_endpoint: None,
            displays: vec![],
            capabilities: AgentCaps::default(),
            access_policy: Default::default(),
            exec_policy: Default::default(),
            exec_anchor: None,
            ssh_service: None,
            enrolled_with_jti: None,
            install: None,
            ssh_policy: Default::default(),
            peer_relay_policy: Default::default(),
            external_access_policy: Default::default(),
            connect_code: None,
            connect_code_rotated_at: None,
            desired_config: Default::default(),
            config_report: None,
            key_rotation: None,
            key_rotation_report: None,
            overlay_identity: None,
            routes: Vec::new(),
            advertised_routes: Vec::new(),
            relay_home: None,
            relay_rtt: None,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            deleted_at: deleted.then(DateTime::now),
        }
    }

    fn allow_all_policy_for(tenant_id: ObjectId) -> TunnelPolicy {
        TunnelPolicy {
            id: Some(ObjectId::new()),
            tenant_id,
            name: "any".into(),
            subjects: vec![PolicySubject::AllUsers],
            targets: vec![PolicyTarget::AllAgents],
            allowlist: vec![rule(HostPattern::Exact("db".into()), 5432, 5432)],
            max_concurrent_flows: None,
            max_bytes_per_session: None,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            deleted_at: None,
        }
    }

    #[test]
    fn cross_tenant_gate_blocks_even_with_allow_all_policy() {
        // The Sev0 case from plan §"Multi-tenancy gotcha". A
        // tenant-A tunnel client sending TcpForwardRequest with a
        // tenant-B agent_id must be rejected even if a permissive
        // allow-all policy exists somewhere.
        let tenant_a = ObjectId::new();
        let tenant_b = ObjectId::new();
        let agent_in_b = agent_for(tenant_b, AgentStatus::Online, false);
        // A policy in tenant B that would otherwise allow this.
        let p = allow_all_policy_for(tenant_b);

        let result = check_tcp(
            tenant_a, // ← client is in tenant A
            &agent_in_b,
            &[p],
            &subject(ObjectId::new()),
            "db",
            5432,
        );
        match result {
            GateResult::Reject { kind, .. } => assert_eq!(kind, RejectKind::CrossTenant),
            r => panic!("expected CrossTenant reject, got {r:?}"),
        }
    }

    #[test]
    fn cross_tenant_gate_runs_before_acl_eval() {
        // Pass an EMPTY policy list — same-tenant would deny via ACL.
        // Cross-tenant must reject with CrossTenant, not AclDenied —
        // the kind drives the audit log; mixing them up makes
        // forensic queries unreliable.
        let tenant_a = ObjectId::new();
        let tenant_b = ObjectId::new();
        let agent_in_b = agent_for(tenant_b, AgentStatus::Online, false);
        let result = check_tcp(
            tenant_a,
            &agent_in_b,
            &[],
            &subject(ObjectId::new()),
            "db",
            5432,
        );
        match result {
            GateResult::Reject { kind, .. } => assert_eq!(kind, RejectKind::CrossTenant),
            _ => panic!("expected CrossTenant"),
        }
    }

    #[test]
    fn deleted_agent_rejects_with_agent_error() {
        let tenant = ObjectId::new();
        let agent = agent_for(tenant, AgentStatus::Online, true);
        let result = check_tcp(
            tenant,
            &agent,
            &[allow_all_policy_for(tenant)],
            &subject(ObjectId::new()),
            "db",
            5432,
        );
        match result {
            GateResult::Reject { kind, .. } => assert_eq!(kind, RejectKind::AgentError),
            r => panic!("expected AgentError, got {r:?}"),
        }
    }

    #[test]
    fn quarantined_agent_rejects_with_agent_error() {
        let tenant = ObjectId::new();
        let agent = agent_for(tenant, AgentStatus::Quarantined, false);
        let result = check_tcp(
            tenant,
            &agent,
            &[allow_all_policy_for(tenant)],
            &subject(ObjectId::new()),
            "db",
            5432,
        );
        assert!(matches!(
            result,
            GateResult::Reject {
                kind: RejectKind::AgentError,
                ..
            }
        ));
    }

    #[test]
    fn happy_path_allows_with_policy_ceilings_plumbed() {
        let tenant = ObjectId::new();
        let agent = agent_for(tenant, AgentStatus::Online, false);
        let mut p = allow_all_policy_for(tenant);
        p.max_concurrent_flows = Some(16);
        p.max_bytes_per_session = Some(500 * 1024 * 1024);
        let expected_pid = p.id.unwrap();

        let result = check_tcp(tenant, &agent, &[p], &subject(ObjectId::new()), "db", 5432);
        match result {
            GateResult::Allow {
                policy_id,
                max_concurrent_flows,
                max_bytes_per_session,
                ..
            } => {
                assert_eq!(policy_id, expected_pid);
                assert_eq!(max_concurrent_flows, Some(16));
                assert_eq!(max_bytes_per_session, Some(500 * 1024 * 1024));
            }
            r => panic!("expected allow, got {r:?}"),
        }
    }

    #[test]
    fn same_tenant_no_policy_rejects_as_acl_denied_not_cross_tenant() {
        // Distinct from CrossTenant — wire form must be AclDenied for
        // the dashboard's "policy gaps" report to be accurate.
        let tenant = ObjectId::new();
        let agent = agent_for(tenant, AgentStatus::Online, false);
        let result = check_tcp(tenant, &agent, &[], &subject(ObjectId::new()), "db", 5432);
        match result {
            GateResult::Reject { kind, .. } => assert_eq!(kind, RejectKind::AclDenied),
            _ => panic!("expected AclDenied"),
        }
    }

    #[test]
    fn offline_agent_status_still_passes_gate() {
        // Offline doesn't block — the WS handler will surface the
        // unreachable-agent failure separately. Gate's job is auth +
        // policy, not liveness.
        let tenant = ObjectId::new();
        let agent = agent_for(tenant, AgentStatus::Offline, false);
        let result = check_tcp(
            tenant,
            &agent,
            &[allow_all_policy_for(tenant)],
            &subject(ObjectId::new()),
            "db",
            5432,
        );
        assert!(result.is_allow());
    }

    // ─── proto gating (UDP ASSOCIATE) ────────────────────────────────

    #[test]
    fn any_proto_rule_permits_both_tcp_and_udp() {
        let aid = ObjectId::new();
        let p = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule_proto(
                HostPattern::Exact("dns".into()),
                53,
                53,
                ProtocolKind::Any,
            )],
        );
        assert!(
            evaluate(
                std::slice::from_ref(&p),
                &subject(ObjectId::new()),
                aid,
                "dns",
                53,
                ProtocolKind::Tcp
            )
            .is_allow()
        );
        assert!(
            evaluate(
                &[p],
                &subject(ObjectId::new()),
                aid,
                "dns",
                53,
                ProtocolKind::Udp
            )
            .is_allow()
        );
    }

    #[test]
    fn udp_rule_denies_tcp_request_and_vice_versa() {
        let aid = ObjectId::new();
        let udp_only = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule_proto(
                HostPattern::Exact("dns".into()),
                53,
                53,
                ProtocolKind::Udp,
            )],
        );
        assert!(
            evaluate(
                std::slice::from_ref(&udp_only),
                &subject(ObjectId::new()),
                aid,
                "dns",
                53,
                ProtocolKind::Udp
            )
            .is_allow()
        );
        assert!(matches!(
            evaluate(
                &[udp_only],
                &subject(ObjectId::new()),
                aid,
                "dns",
                53,
                ProtocolKind::Tcp
            ),
            Decision::Deny { .. }
        ));

        let tcp_only = policy(
            vec![PolicySubject::AllUsers],
            vec![PolicyTarget::AllAgents],
            vec![rule_proto(
                HostPattern::Exact("db".into()),
                5432,
                5432,
                ProtocolKind::Tcp,
            )],
        );
        assert!(
            evaluate(
                std::slice::from_ref(&tcp_only),
                &subject(ObjectId::new()),
                aid,
                "db",
                5432,
                ProtocolKind::Tcp
            )
            .is_allow()
        );
        assert!(matches!(
            evaluate(
                &[tcp_only],
                &subject(ObjectId::new()),
                aid,
                "db",
                5432,
                ProtocolKind::Udp
            ),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn check_forward_request_gates_udp_proto() {
        let tenant = ObjectId::new();
        let agent = agent_for(tenant, AgentStatus::Online, false);
        let mut p = allow_all_policy_for(tenant);
        p.allowlist = vec![rule_proto(
            HostPattern::Exact("db".into()),
            5432,
            5432,
            ProtocolKind::Udp,
        )];
        assert!(
            check_forward_request(
                tenant,
                &agent,
                std::slice::from_ref(&p),
                &subject(ObjectId::new()),
                "db",
                5432,
                ProtocolKind::Udp
            )
            .is_allow()
        );
        match check_forward_request(
            tenant,
            &agent,
            &[p],
            &subject(ObjectId::new()),
            "db",
            5432,
            ProtocolKind::Tcp,
        ) {
            GateResult::Reject { kind, .. } => assert_eq!(kind, RejectKind::AclDenied),
            r => panic!("expected AclDenied, got {r:?}"),
        }
    }

    // ── Overlay ACL ────────────────────────────────────────────────────────

    fn ov_policy(
        sources: Vec<OverlaySelector>,
        via: Vec<OverlayTarget>,
        cidrs: &[&str],
    ) -> OverlayPolicy {
        OverlayPolicy {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            name: "p".into(),
            enabled: true,
            sources,
            via,
            destinations: cidrs
                .iter()
                .map(|c| OverlayRule {
                    cidr: (*c).to_string(),
                    port_range: PortRange {
                        low: 1,
                        high: u16::MAX,
                    },
                    proto: ProtocolKind::Any,
                })
                .collect(),
            created_at: bson::DateTime::now(),
            updated_at: bson::DateTime::now(),
            deleted_at: None,
        }
    }

    fn ov_source(node_id: ObjectId) -> OverlaySource {
        OverlaySource {
            node_id,
            owner_user_id: None,
            role_ids: Vec::new(),
        }
    }

    #[test]
    fn overlay_default_denies_with_no_policies() {
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "100.64.0.7",
            approved_routes: &[],
        };
        let got = evaluate_overlay(&[], &ov_source(ObjectId::new()), peer);
        assert_eq!(got, OverlayAccess::denied());
    }

    #[test]
    fn overlay_cidr_covering_peer_ip_grants_visibility() {
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "100.64.0.7",
            approved_routes: &[],
        };
        let p = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::AllNodes],
            &["100.64.0.0/10"],
        );
        assert!(evaluate_overlay(&[p], &ov_source(ObjectId::new()), peer).visible);
    }

    #[test]
    fn overlay_grants_only_covered_routes() {
        let routes = vec!["10.84.6.0/24".to_string(), "10.66.0.0/16".to_string()];
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "100.64.0.7",
            approved_routes: &routes,
        };
        // A /16 supernet covers the /24 but not the unrelated 10.66 block.
        let p = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::AllNodes],
            &["10.84.0.0/16"],
        );
        let got = evaluate_overlay(&[p], &ov_source(ObjectId::new()), peer);
        assert_eq!(got.routes, vec!["10.84.6.0/24".to_string()]);
        // A route grant implies the gateway is reachable, else it is useless.
        assert!(got.visible);
    }

    #[test]
    fn overlay_via_scopes_the_grant_to_one_peer() {
        let router = ObjectId::new();
        let other = ObjectId::new();
        let routes = vec!["10.84.6.0/24".to_string()];
        let p = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::NodeId { node_id: router }],
            &["10.84.0.0/16"],
        );
        let via_router = OverlayPeerRef {
            node_id: router,
            overlay_ip: "100.64.0.7",
            approved_routes: &routes,
        };
        let via_other = OverlayPeerRef {
            node_id: other,
            overlay_ip: "100.64.0.8",
            approved_routes: &routes,
        };
        let src = ov_source(ObjectId::new());
        assert!(
            !evaluate_overlay(std::slice::from_ref(&p), &src, via_router)
                .routes
                .is_empty()
        );
        assert!(evaluate_overlay(&[p], &src, via_other).routes.is_empty());
    }

    #[test]
    fn overlay_source_selectors_discriminate() {
        let me = ObjectId::new();
        let owner = ObjectId::new();
        let role = ObjectId::new();
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "100.64.0.7",
            approved_routes: &[],
        };
        let by_node = ov_policy(
            vec![OverlaySelector::NodeId { node_id: me }],
            vec![OverlayTarget::AllNodes],
            &["100.64.0.0/10"],
        );
        assert!(evaluate_overlay(std::slice::from_ref(&by_node), &ov_source(me), peer).visible);
        assert!(
            !evaluate_overlay(&[by_node], &ov_source(ObjectId::new()), peer).visible,
            "a NodeId source must not match a different node"
        );

        let by_user = ov_policy(
            vec![OverlaySelector::UserId { user_id: owner }],
            vec![OverlayTarget::AllNodes],
            &["100.64.0.0/10"],
        );
        let mut src = ov_source(me);
        src.owner_user_id = Some(owner);
        assert!(evaluate_overlay(std::slice::from_ref(&by_user), &src, peer).visible);
        assert!(
            !evaluate_overlay(&[by_user], &ov_source(me), peer).visible,
            "an ownerless node must not match a UserId source"
        );

        let by_role = ov_policy(
            vec![OverlaySelector::RoleId { role_id: role }],
            vec![OverlayTarget::AllNodes],
            &["100.64.0.0/10"],
        );
        let mut src = ov_source(me);
        src.role_ids = vec![role];
        assert!(evaluate_overlay(&[by_role], &src, peer).visible);
    }

    #[test]
    fn overlay_disabled_and_deleted_policies_are_skipped() {
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "100.64.0.7",
            approved_routes: &[],
        };
        let src = ov_source(ObjectId::new());

        let mut disabled = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::AllNodes],
            &["100.64.0.0/10"],
        );
        disabled.enabled = false;
        assert!(!evaluate_overlay(&[disabled], &src, peer).visible);

        let mut deleted = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::AllNodes],
            &["100.64.0.0/10"],
        );
        deleted.deleted_at = Some(bson::DateTime::now());
        assert!(!evaluate_overlay(&[deleted], &src, peer).visible);
    }

    #[test]
    fn overlay_malformed_cidr_never_grants() {
        let routes = vec!["10.84.6.0/24".to_string()];
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "100.64.0.7",
            approved_routes: &routes,
        };
        let p = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::AllNodes],
            &["not-a-cidr", "10.84.6.0"], // bare address, no prefix
        );
        let got = evaluate_overlay(&[p], &ov_source(ObjectId::new()), peer);
        assert_eq!(got, OverlayAccess::denied());
    }

    #[test]
    fn overlay_v6_cidrs_match() {
        let routes = vec!["fd72:6f6f:6d6c::/64".to_string()];
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "fd72:6f6f:6d6c::6440:7",
            approved_routes: &routes,
        };
        let p = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::AllNodes],
            &["fd72:6f6f:6d6c::/48"],
        );
        let got = evaluate_overlay(&[p], &ov_source(ObjectId::new()), peer);
        assert!(got.visible);
        assert_eq!(got.routes, routes);
    }

    #[test]
    fn overlay_default_route_grant_covers_everything() {
        let routes = vec!["10.84.6.0/24".to_string(), "0.0.0.0/0".to_string()];
        let peer = OverlayPeerRef {
            node_id: ObjectId::new(),
            overlay_ip: "100.64.0.7",
            approved_routes: &routes,
        };
        let p = ov_policy(
            vec![OverlaySelector::AllNodes],
            vec![OverlayTarget::AllNodes],
            &["0.0.0.0/0"],
        );
        // An exit node's /0 is only distributed when an admin explicitly grants
        // /0 — the client still refuses to auto-install it (P5/A1).
        let got = evaluate_overlay(&[p], &ov_source(ObjectId::new()), peer);
        assert_eq!(got.routes, routes);
    }
}
