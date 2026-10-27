// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Staged edge construction for an already-authorized relay candidate set.
//!
//! This is not an authorization source. Callers must obtain each relay from
//! the current same-tenant, live, primary, capacity and both-member ACL gates;
//! an implicit grant must not be used to bypass cross-zone policy.

use bson::oid::ObjectId;
use roomler_ai_remote_control::models::{MAX_PEER_RELAY_BACKBONE_EDGES, PeerRelayBackboneEdge};
use roomler_core::business_authority::BusinessZone;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub(super) struct EligibleRelay {
    pub node_id: ObjectId,
    pub agent_id: ObjectId,
    pub zone: BusinessZone,
    pub bridge_ready: bool,
    pub approved_edges: Vec<PeerRelayBackboneEdge>,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct GraphEdge {
    pub from: usize,
    pub to: usize,
    pub endpoint: String,
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
/// bridge, invalid endpoint or unauthorized zone crossing is never offered.
/// Duplicate relay identities or malformed approval tables fail closed.
pub(super) fn build(
    mut relays: Vec<EligibleRelay>,
    overlay_cidr: &str,
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
            if from == to
                || !relay.bridge_ready
                || (relay.zone != relays[to].zone && !approved.cross_border)
                || !crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                    &approved.endpoint,
                    overlay_cidr,
                )
            {
                continue;
            }
            edges.push(GraphEdge {
                from,
                to,
                endpoint: approved.endpoint.clone(),
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
    fn relay(agent: ObjectId, zone: BusinessZone) -> EligibleRelay {
        EligibleRelay {
            node_id: ObjectId::new(),
            agent_id: agent,
            zone,
            bridge_ready: true,
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
    fn rejects_oversized_tables_and_is_deterministic() {
        let mut a = relay(ObjectId::new(), M);
        a.approved_edges = (0..=MAX_PEER_RELAY_BACKBONE_EDGES)
            .map(|_| edge(ObjectId::new(), "10.0.0.1:3478", false))
            .collect();
        assert!(matches!(
            build(vec![a], "100.64.0.0/10"),
            Err(GraphError::TooManyEdges)
        ));
        let mut b = relay(ObjectId::new(), M);
        let c = relay(ObjectId::new(), M);
        b.approved_edges
            .push(edge(c.agent_id, "10.0.0.3:3478", false));
        let forward = build(vec![b.clone(), c.clone()], "100.64.0.0/10").unwrap();
        let reverse = build(vec![c, b], "100.64.0.0/10").unwrap();
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
