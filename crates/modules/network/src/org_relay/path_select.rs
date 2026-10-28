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
    select_inner(state, prepared, false, false)
}

/// Actual multi-hop grants require known member zones and matching end relays.
pub(super) fn select_for_mint(
    state: &NetworkState,
    prepared: PreparedGraph,
    same_zone_only: bool,
) -> Result<Option<SelectedPath>, Deny> {
    if prepared.requester_zone.is_none() || prepared.peer_zone.is_none() {
        return Err(Deny::ZoneDenied);
    }
    select_inner(state, prepared, true, same_zone_only)
}

fn select_inner(
    state: &NetworkState,
    mut prepared: PreparedGraph,
    require_ends: bool,
    same_zone_only: bool,
) -> Result<Option<SelectedPath>, Deny> {
    if prepared.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    // Actual multi-hop mint cannot represent implicit or unknown-zone
    // relays, and every crossing must be explicitly approved. Apply these
    // gates before ranking so an unusable path cannot hide a valid one.
    // Keep edge indexes in the filtered graph for the fresh mint checks.
    let eligible: Vec<bool> = prepared
        .graph
        .relays
        .iter()
        .map(|relay| {
            !require_ends
                || (!relay.implicit
                    && relay.zone.is_some()
                    && (!same_zone_only
                        || (prepared.requester_zone.is_some()
                            && prepared.requester_zone == prepared.peer_zone
                            && relay.zone == prepared.requester_zone)))
        })
        .collect();
    if require_ends {
        if prepared
            .graph
            .edges
            .iter()
            .any(|edge| edge.from >= eligible.len() || edge.to >= eligible.len())
        {
            return Err(Deny::PolicyUnreadable);
        }
        let relays = &prepared.graph.relays;
        prepared.graph.edges.retain(|edge| {
            eligible[edge.from]
                && eligible[edge.to]
                && (relays[edge.from].zone == relays[edge.to].zone || edge.cross_border)
        });
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
    let mut single_forward = Vec::with_capacity(prepared.graph.relays.len());
    let mut single_reverse = Vec::with_capacity(prepared.graph.relays.len());
    for (relay, eligible) in prepared.graph.relays.iter().zip(eligible) {
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
        // These candidates are comparison-only: with no backbone edges they
        // can never introduce an otherwise ineligible relay into a long path.
        single_forward.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (!prepared.restrict_ends || relay.zone == prepared.requester_zone)
                .then_some(a_probe),
            exit: (!prepared.restrict_ends || relay.zone == prepared.peer_zone).then_some(b_probe),
            load,
        });
        single_reverse.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (!prepared.restrict_ends || relay.zone == prepared.peer_zone)
                .then_some(b_probe),
            exit: (!prepared.restrict_ends || relay.zone == prepared.requester_zone)
                .then_some(a_probe),
            load,
        });
        forward.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (eligible && (!restrict_ends || relay.zone == prepared.requester_zone))
                .then_some(a_probe),
            exit: (eligible && (!restrict_ends || relay.zone == prepared.peer_zone))
                .then_some(b_probe),
            load,
        });
        reverse.push(SearchRelay {
            node_id: relay.node_id,
            ingress: (eligible && (!restrict_ends || relay.zone == prepared.peer_zone))
                .then_some(b_probe),
            exit: (eligible && (!restrict_ends || relay.zone == prepared.requester_zone))
                .then_some(a_probe),
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
                    prepared.graph.relays[edge.from].agent_id,
                    prepared.graph.relays[edge.to].node_id,
                    prepared.graph.relays[edge.to].agent_id,
                ),
                now,
            ),
        })
        .collect();
    let mut chosen = path_search::shortest_either_direction(&forward, &reverse, &edges)
        .map_err(|_| Deny::PolicyUnreadable)?;
    if require_ends {
        let single = path_search::shortest_either_direction(&single_forward, &single_reverse, &[])
            .map_err(|_| Deny::PolicyUnreadable)?;
        if let Some(single) = single
            && chosen
                .as_ref()
                .is_none_or(|path| single.path.rank_key() <= path.path.rank_key())
        {
            chosen = Some(single);
        }
    }
    if prepared.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    Ok(chosen.map(|path| SelectedPath { prepared, path }))
}
