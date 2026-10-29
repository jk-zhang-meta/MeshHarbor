// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Path selection from the live-gate snapshot. This does not reserve
//! capacity or send grants; the mint rechecks them before use.

use super::{
    path_candidate::PreparedGraph,
    path_search::{self, OrientedPath, SearchEdge, SearchRelay},
};
use crate::NetworkState;
use roomler_ai_remote_control::models::PeerRelayDenyReason as Deny;
use std::time::Instant;

pub(super) struct SelectedPath {
    pub prepared: PreparedGraph,
    pub path: OrientedPath,
}

/// Compute both member orientations using only edges and relay identities from
/// the same previously authorized snapshot. The caller must revalidate all
/// policy, connections, capacity and endpoints at the future mint boundary.
pub(super) fn select(
    state: &NetworkState,
    prepared: PreparedGraph,
) -> Result<Option<SelectedPath>, Deny> {
    select_inner(state, prepared, false)
}

/// Actual multi-hop grants require known member zones and matching end relays.
pub(super) fn select_for_mint(
    state: &NetworkState,
    prepared: PreparedGraph,
) -> Result<Option<SelectedPath>, Deny> {
    if prepared.requester_zone.is_none() || prepared.peer_zone.is_none() {
        return Err(Deny::ZoneDenied);
    }
    select_inner(state, prepared, true)
}

/// Validate edge indexes before looking up probe provenance. The search
/// rejects invalid graphs too, but it runs after these lookups.
fn checked_edge_endpoints<'a>(
    graph: &'a super::path_graph::EdgeGraph,
    edge: &super::path_graph::GraphEdge,
) -> Result<(&'a super::path_graph::EligibleRelay, &'a super::path_graph::EligibleRelay), Deny> {
    let from = graph.relays.get(edge.from).ok_or(Deny::PolicyUnreadable)?;
    let to = graph.relays.get(edge.to).ok_or(Deny::PolicyUnreadable)?;
    Ok((from, to))
}

fn select_inner(
    state: &NetworkState,
    prepared: PreparedGraph,
    require_ends: bool,
) -> Result<Option<SelectedPath>, Deny> {
    if prepared.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    let now = Instant::now();
    let a = prepared.requester_id;
    let b = prepared.peer_id;
    // Both nodes must have current live connections and have joined. A
    // replacement connection invalidates earlier observations even before
    // its own overlay join; the final mint still must revalidate atomically.
    let cutoff = |reporter, reporter_identity, target, target_identity| {
        let r_join = state.org_relay.probe_join_at.get(&reporter).map(|at| *at)?;
        let t_join = state.org_relay.probe_join_at.get(&target).map(|at| *at)?;
        let r_bind = state
            .org_relay
            .live_conns
            .get(&reporter_identity)
            .map(|c| c.bound_at)?;
        let t_bind = state
            .org_relay
            .live_conns
            .get(&target_identity)
            .map(|c| c.bound_at)?;
        if r_join < r_bind || t_join < t_bind {
            return None;
        }
        let r_endpoint = state
            .org_relay
            .probe_endpoint_at
            .get(&reporter)
            .map(|at| *at)
            .unwrap_or(r_join);
        let t_endpoint = state
            .org_relay
            .probe_endpoint_at
            .get(&target)
            .map(|at| *at)
            .unwrap_or(t_join);
        let r_policy = state
            .org_relay
            .probe_policy_at
            .get(&reporter_identity)
            .map(|at| *at)
            .unwrap_or(r_bind);
        let t_policy = state
            .org_relay
            .probe_policy_at
            .get(&target_identity)
            .map(|at| *at)
            .unwrap_or(t_bind);
        Some(
            r_join
                .max(t_join)
                .max(r_endpoint)
                .max(t_endpoint)
                .max(r_policy)
                .max(t_policy),
        )
    };
    let restrict_ends = prepared.restrict_ends || require_ends;
    let mut forward = Vec::with_capacity(prepared.graph.relays.len());
    let mut reverse = Vec::with_capacity(prepared.graph.relays.len());
    for relay in &prepared.graph.relays {
        let plan = prepared
            .plans
            .get(&relay.node_id)
            .ok_or(Deny::PolicyUnreadable)?;
        let a_probe = super::scoped_probe_verdict(
            &state.org_relay.probes,
            a,
            relay.node_id,
            &plan.endpoints,
            cutoff(
                a,
                prepared.requester_identity,
                relay.node_id,
                relay.agent_id,
            ),
            now,
        );
        let b_probe = super::scoped_probe_verdict(
            &state.org_relay.probes,
            b,
            relay.node_id,
            &plan.endpoints,
            cutoff(b, prepared.peer_identity, relay.node_id, relay.agent_id),
            now,
        );
        let load = state.org_relay.sessions_on_relay(relay.node_id);
        forward.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (!restrict_ends || relay.zone == prepared.requester_zone).then_some(a_probe),
            exit: (!restrict_ends || relay.zone == prepared.peer_zone).then_some(b_probe),
            load,
        });
        reverse.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (!restrict_ends || relay.zone == prepared.peer_zone).then_some(b_probe),
            exit: (!restrict_ends || relay.zone == prepared.requester_zone).then_some(a_probe),
            load,
        });
    }
    let edges: Vec<_> = prepared
        .graph
        .edges
        .iter()
        .map(|edge| {
            let (from, to) = checked_edge_endpoints(&prepared.graph, edge)?;
            Ok(SearchEdge {
                from: edge.from,
                to: edge.to,
                verdict: super::scoped_probe_verdict(
                    &state.org_relay.backbone_probes,
                    from.node_id,
                    to.node_id,
                    std::slice::from_ref(&edge.endpoint),
                    cutoff(from.node_id, from.agent_id, to.node_id, to.agent_id),
                    now,
                ),
            })
        })
        .collect::<Result<Vec<_>, Deny>>()?;
    let chosen = path_search::shortest_either_direction(&forward, &reverse, &edges)
        .map_err(|_| Deny::PolicyUnreadable)?;
    if prepared.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    Ok(chosen.map(|path| SelectedPath { prepared, path }))
}

#[cfg(test)]
mod checked_edge_tests {
    use super::*;
    use crate::org_relay::path_graph::{EdgeGraph, EligibleRelay, GraphEdge};
    use bson::oid::ObjectId;

    #[test]
    fn malformed_edge_indexes_return_error_and_valid_edges_resolve() {
        let node_id = ObjectId::new();
        let graph = EdgeGraph {
            relays: vec![EligibleRelay {
                node_id, agent_id: ObjectId::new(), zone: None, bridge_ready: false,
                implicit: false, approved_edges: Vec::new(),
            }],
            edges: Vec::new(),
        };
        let edge = |from, to| GraphEdge { from, to, endpoint: "10.0.0.1:3478".into(), cross_border: false };
        let (from, to) = checked_edge_endpoints(&graph, &edge(0, 0)).expect("valid indexes");
        assert_eq!(from.node_id, node_id);
        assert_eq!(to.node_id, node_id);
        assert!(matches!(checked_edge_endpoints(&graph, &edge(1, 0)), Err(Deny::PolicyUnreadable)));
        assert!(matches!(checked_edge_endpoints(&graph, &edge(0, 1)), Err(Deny::PolicyUnreadable)));
        assert!(matches!(checked_edge_endpoints(&graph, &edge(usize::MAX, usize::MAX)), Err(Deny::PolicyUnreadable)));
    }
}
