// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Staged edge construction for an already-authorized relay candidate set.
//!
//! This is not an authorization source. Callers must obtain each relay from
//! the current same-tenant, live, primary, capacity and both-member ACL gates;
//! an implicit grant must not be used to bypass cross-zone policy.

use crate::business_isolation::Mode;
use bson::oid::ObjectId;
use roomler_ai_remote_control::models::{MAX_PEER_RELAY_BACKBONE_EDGES, PeerRelayBackboneEdge};
use roomler_core::business_authority::BusinessZone;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub(super) struct EligibleRelay {
    pub node_id: ObjectId,
    pub agent_id: ObjectId,
    pub zone: Option<BusinessZone>,
    pub bridge_ready: bool,
    /// True when eligibility depends on the same-zone implicit server role.
    pub implicit: bool,
    pub approved_edges: Vec<PeerRelayBackboneEdge>,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct GraphEdge {
    pub from: usize,
    pub to: usize,
    pub endpoint: String,
    /// Exact approval bit, retained for per-edge revalidation and audit.
    pub cross_border: bool,
}
#[derive(Debug)]
pub(super) struct EdgeGraph {
    /// Stable node/agent ordering shared with the search and the mint.
    pub relays: Vec<EligibleRelay>,
    pub edges: Vec<GraphEdge>,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum GraphError {
    InvalidOverlay,
    DuplicateRelay,
    TooManyEdges,
    DuplicateTarget,
}

/// Consume a gate-approved candidate set, sort it deterministically and keep
/// only usable approved directed edges. A missing/ineligible target, disabled
/// bridge or invalid endpoint is never offered. In Enforce mode an
/// unauthorized or unknown-zone crossing is also withheld.
/// Duplicate relay identities or malformed approval tables fail closed.
pub(super) fn build(
    mut relays: Vec<EligibleRelay>,
    overlay_cidr: &str,
    isolation: Mode,
) -> Result<EdgeGraph, GraphError> {
    if overlay_cidr.parse::<ipnet::IpNet>().is_err() {
        return Err(GraphError::InvalidOverlay);
    }
    relays.sort_by_key(|r| (r.agent_id, r.node_id));
    let mut by_agent = HashMap::new();
    let mut node_ids = HashSet::new();
    for (i, relay) in relays.iter().enumerate() {
        if by_agent.insert(relay.agent_id, i).is_some() || !node_ids.insert(relay.node_id) {
            return Err(GraphError::DuplicateRelay);
        }
    }
    let mut edges = Vec::new();
    for (from, relay) in relays.iter().enumerate() {
        if relay.approved_edges.len() > MAX_PEER_RELAY_BACKBONE_EDGES {
            return Err(GraphError::TooManyEdges);
        }
        let mut seen = HashSet::new();
        for approved in &relay.approved_edges {
            let Ok(target) = ObjectId::parse_str(&approved.relay_agent_id) else {
                continue;
            };
            if !seen.insert(target) {
                return Err(GraphError::DuplicateTarget);
            }
            let Some(&to) = by_agent.get(&target) else {
                continue;
            };
            let crossing_not_authorized = !matches!((relay.zone, relays[to].zone), (Some(a), Some(b)) if a == b)
                && (!approved.cross_border || relay.implicit || relays[to].implicit);
            if from == to
                || !relay.bridge_ready
                || (isolation == Mode::Enforce && crossing_not_authorized)
                || !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                    &approved.endpoint,
                    overlay_cidr,
                )
            {
                continue;
            }
            if isolation == Mode::Warn && crossing_not_authorized {
                tracing::info!(source = %relay.agent_id, target = %relays[to].agent_id,
                    "org-relay [isolation warn]: would withhold backbone edge by zone policy");
            }
            edges.push(GraphEdge {
                from,
                to,
                endpoint: approved.endpoint.clone(),
                cross_border: approved.cross_border,
            });
        }
    }
    edges.sort_by(|a, b| (a.from, a.to, &a.endpoint).cmp(&(b.from, b.to, &b.endpoint)));
    Ok(EdgeGraph { relays, edges })
}

#[cfg(test)]
mod tests {
    use super::*;
    use BusinessZone::{Mainland as M, NonMainland as N};
    fn build(relays: Vec<EligibleRelay>, cidr: &str) -> Result<EdgeGraph, GraphError> {
        super::build(relays, cidr, Mode::Enforce)
    }

    fn relay(agent: ObjectId, zone: BusinessZone) -> EligibleRelay {
        EligibleRelay {
            node_id: ObjectId::new(),
            agent_id: agent,
            zone: Some(zone),
            bridge_ready: true,
            implicit: false,
            approved_edges: vec![],
        }
    }
    fn edge(target: ObjectId, endpoint: &str, cross_border: bool) -> PeerRelayBackboneEdge {
        PeerRelayBackboneEdge {
            relay_agent_id: target.to_hex(),
            endpoint: endpoint.into(),
            cross_border,
        }
    }
    #[test]
    fn filters_by_actual_approved_edges_zone_readiness_and_overlay() {
        let ids: Vec<_> = (0..4).map(|_| ObjectId::new()).collect();
        let mut a = relay(ids[0], M);
        let mut b = relay(ids[1], M);
        let c = relay(ids[2], N);
        let d = relay(ids[3], N);
        a.approved_edges = vec![
            edge(ids[1], "10.0.0.1:3478", false),
            edge(ids[2], "10.0.0.2:3478", false),
            edge(ids[3], "100.64.0.1:3478", true),
            edge(ObjectId::new(), "10.0.0.5:3478", true),
        ];
        b.approved_edges = vec![edge(ids[2], "10.0.0.3:3478", true)];
        let graph = build(vec![d, c, b, a], "100.64.0.0/10").unwrap();
        let actual: Vec<_> = graph
            .edges
            .iter()
            .map(|e| {
                (
                    graph.relays[e.from].agent_id,
                    graph.relays[e.to].agent_id,
                    e.endpoint.as_str(),
                )
            })
            .collect();
        assert!(actual.contains(&(ids[0], ids[1], "10.0.0.1:3478")));
        assert!(actual.contains(&(ids[1], ids[2], "10.0.0.3:3478")));
        assert_eq!(actual.len(), 2);
        let mut disabled = graph.relays.clone();
        disabled
            .iter_mut()
            .find(|r| r.agent_id == ids[1])
            .unwrap()
            .bridge_ready = false;
        let graph = build(disabled, "100.64.0.0/10").unwrap();
        assert_eq!(graph.edges.len(), 1);
        let only = &graph.edges[0];
        assert_eq!(
            (
                graph.relays[only.from].agent_id,
                graph.relays[only.to].agent_id
            ),
            (ids[0], ids[1])
        );
        assert!(!only.cross_border);
    }
    #[test]
    fn rejects_duplicate_identities_and_approval_table_duplicates() {
        let id = ObjectId::new();
        assert!(matches!(
            build(vec![relay(id, M), relay(id, M)], "100.64.0.0/10"),
            Err(GraphError::DuplicateRelay)
        ));
        let a = relay(ObjectId::new(), M);
        let mut b = relay(ObjectId::new(), M);
        b.node_id = a.node_id;
        assert!(matches!(
            build(vec![a, b], "100.64.0.0/10"),
            Err(GraphError::DuplicateRelay)
        ));
        let a_id = ObjectId::new();
        let b_id = ObjectId::new();
        let mut a = relay(a_id, M);
        a.approved_edges = vec![
            edge(b_id, "10.0.0.1:3478", false),
            edge(b_id, "10.0.0.2:3478", false),
        ];
        assert!(matches!(
            build(vec![a, relay(b_id, M)], "100.64.0.0/10"),
            Err(GraphError::DuplicateTarget)
        ));
        assert!(matches!(
            build(vec![], "not-cidr"),
            Err(GraphError::InvalidOverlay)
        ));
    }
    #[test]
    fn unknown_zone_is_never_treated_as_proven_same_zone() {
        let a_id = ObjectId::new();
        let b_id = ObjectId::new();
        let mut a = relay(a_id, M);
        let mut b = relay(b_id, M);
        a.zone = None;
        b.zone = None;
        a.approved_edges = vec![edge(b_id, "10.0.0.1:3478", false)];
        assert!(
            build(vec![a.clone(), b.clone()], "100.64.0.0/10")
                .unwrap()
                .edges
                .is_empty()
        );
        a.approved_edges[0].cross_border = true;
        assert_eq!(
            build(vec![a.clone(), b.clone()], "100.64.0.0/10")
                .unwrap()
                .edges
                .len(),
            1
        );
        b.implicit = true;
        assert!(
            build(vec![a.clone(), b], "100.64.0.0/10")
                .unwrap()
                .edges
                .is_empty()
        );
        let c = relay(b_id, M);
        a.approved_edges[0].cross_border = false;
        assert!(build(vec![a, c], "100.64.0.0/10").unwrap().edges.is_empty());
    }
    #[test]
    fn off_and_warn_keep_approved_edges_without_enforcing_zones() {
        let mut a = relay(ObjectId::new(), M);
        let mut b = relay(ObjectId::new(), N);
        a.implicit = true;
        a.approved_edges = vec![edge(b.agent_id, "10.0.0.1:3478", false)];
        for mode in [Mode::Off, Mode::Warn] {
            let known = super::build(vec![a.clone(), b.clone()], "100.64.0.0/10", mode).unwrap();
            assert_eq!(known.edges.len(), 1);
            assert!(!known.edges[0].cross_border);
            b.zone = None;
            let unknown = super::build(vec![a.clone(), b.clone()], "100.64.0.0/10", mode).unwrap();
            assert_eq!(unknown.edges.len(), 1);
            assert!(!unknown.edges[0].cross_border);
            b.zone = Some(N);
        }
        assert!(build(vec![a, b], "100.64.0.0/10").unwrap().edges.is_empty());
    }

    #[test]
    fn cross_zone_requires_explicit_grants_on_both_relays() {
        let a_id = ObjectId::new();
        let b_id = ObjectId::new();
        let mut a = relay(a_id, M);
        let b = relay(b_id, N);
        a.approved_edges = vec![edge(b_id, "10.0.0.2:3478", true)];
        let allowed = build(vec![a.clone(), b.clone()], "100.64.0.0/10").unwrap();
        assert_eq!(allowed.edges.len(), 1);
        assert!(allowed.edges[0].cross_border);
        let mut implicit_source = a.clone();
        implicit_source.implicit = true;
        assert!(
            build(vec![implicit_source, b.clone()], "100.64.0.0/10")
                .unwrap()
                .edges
                .is_empty()
        );
        let mut implicit_target = b;
        implicit_target.implicit = true;
        assert!(
            build(vec![a, implicit_target], "100.64.0.0/10")
                .unwrap()
                .edges
                .is_empty()
        );
    }
    #[test]
    fn self_edges_bad_ids_and_non_unicast_endpoints_are_not_offered() {
        let ids: Vec<_> = (0..6).map(|_| ObjectId::new()).collect();
        let mut a = relay(ids[0], M);
        a.approved_edges = vec![
            edge(ids[0], "10.0.0.1:3478", false),
            edge(ids[1], "127.0.0.1:3478", false),
            edge(ids[2], "10.0.0.2:0", false),
            edge(ids[3], "localhost:3478", false),
            edge(ids[4], "[::ffff:10.0.0.4]:3478", false),
            PeerRelayBackboneEdge {
                relay_agent_id: "bad-id".into(),
                endpoint: "10.0.0.5:3478".into(),
                cross_border: false,
            },
        ];
        let mut all = vec![a];
        all.extend(ids[1..].iter().map(|id| relay(*id, M)));
        assert!(build(all, "100.64.0.0/10").unwrap().edges.is_empty());
    }

    #[test]
    fn rejects_oversized_tables_and_is_deterministic() {
        let mut exact = relay(ObjectId::new(), M);
        exact.approved_edges = (0..MAX_PEER_RELAY_BACKBONE_EDGES)
            .map(|_| edge(ObjectId::new(), "10.0.0.1:3478", false))
            .collect();
        assert!(build(vec![exact], "100.64.0.0/10").is_ok());
        let mut a = relay(ObjectId::new(), M);
        a.approved_edges = (0..=MAX_PEER_RELAY_BACKBONE_EDGES)
            .map(|_| edge(ObjectId::new(), "10.0.0.1:3478", false))
            .collect();
        assert!(matches!(
            build(vec![a], "100.64.0.0/10"),
            Err(GraphError::TooManyEdges)
        ));
        let mut b = relay(ObjectId::new(), M);
        let mut c = relay(ObjectId::new(), M);
        let d = relay(ObjectId::new(), M);
        b.approved_edges = vec![
            edge(d.agent_id, "10.0.0.4:3478", false),
            edge(c.agent_id, "10.0.0.3:3478", false),
        ];
        c.approved_edges
            .push(edge(d.agent_id, "10.0.0.5:3478", false));
        let forward = build(vec![b.clone(), c.clone(), d.clone()], "100.64.0.0/10").unwrap();
        b.approved_edges.reverse();
        let reverse = build(vec![d, c, b], "100.64.0.0/10").unwrap();
        assert_eq!(forward.edges.len(), 3);
        assert_eq!(
            forward
                .relays
                .iter()
                .map(|r| r.agent_id)
                .collect::<Vec<_>>(),
            reverse
                .relays
                .iter()
                .map(|r| r.agent_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(forward.edges, reverse.edges);
    }
}
