// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Staged path selection from the live-gate snapshot. This does not reserve
//! capacity or send grants, and is not yet used by production signaling.

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
    if prepared.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    let now = Instant::now();
    let a = prepared.requester_id;
    let b = prepared.peer_id;
    // Both the reporting node and target must have joined before the
    // measurement. Missing join evidence is conservatively unknown.
    let cutoff = |reporter, target| {
        let a = state.org_relay.probe_join_at.get(&reporter).map(|at| *at);
        let b = state.org_relay.probe_join_at.get(&target).map(|at| *at);
        a.zip(b).map(|(a, b)| a.max(b))
    };
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
            cutoff(a, relay.node_id),
            now,
        );
        let b_probe = super::scoped_probe_verdict(
            &state.org_relay.probes,
            b,
            relay.node_id,
            &plan.endpoints,
            cutoff(b, relay.node_id),
            now,
        );
        let load = state.org_relay.sessions_on_relay(relay.node_id);
        forward.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (relay.zone == prepared.requester_zone).then_some(a_probe),
            exit: (relay.zone == prepared.peer_zone).then_some(b_probe),
            load,
        });
        reverse.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (relay.zone == prepared.peer_zone).then_some(b_probe),
            exit: (relay.zone == prepared.requester_zone).then_some(a_probe),
            load,
        });
    }
    let edges: Vec<_> = prepared
        .graph
        .edges
        .iter()
        .map(|edge| SearchEdge {
            from: edge.from,
            to: edge.to,
            verdict: super::scoped_probe_verdict(
                &state.org_relay.backbone_probes,
                prepared.graph.relays[edge.from].node_id,
                prepared.graph.relays[edge.to].node_id,
                std::slice::from_ref(&edge.endpoint),
                cutoff(
                    prepared.graph.relays[edge.from].node_id,
                    prepared.graph.relays[edge.to].node_id,
                ),
                now,
            ),
        })
        .collect();
    let chosen = path_search::shortest_either_direction(&forward, &reverse, &edges)
        .map_err(|_| Deny::PolicyUnreadable)?;
    if prepared.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    Ok(chosen.map(|path| SelectedPath { prepared, path }))
}
