// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Fresh authorization for a client-specified ordered relay path.
//!
//! This is a planning snapshot, not a reservation or a grant. Before any
//! future trial delivery the owner must repeat authorization as appropriate,
//! check the epoch, and reserve every node under the shared trial claim lock.

use super::*;
use roomler_ai_remote_control::signaling::RelayPathWire;

#[derive(Clone, PartialEq, Eq)]
struct MemberIdentity {
    node_id: ObjectId,
    node_ref: NodeRef,
    public_key: String,
    network_id: ObjectId,
    tenant_id: ObjectId,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct TrialRelay {
    pub node_id: ObjectId,
    pub agent_id: ObjectId,
    pub zone: BusinessZone,
    pub node_ref: NodeRef,
    pub endpoints: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct TrialEdge {
    pub source: ObjectId,
    pub target: ObjectId,
    pub endpoint: String,
    pub requires_cross_border_approval: bool,
}

#[derive(Clone)]
pub(super) struct TrialPathPlan {
    pub epoch: u64,
    pub path: RelayPathWire,
    pub requester_at_exit: bool,
    pub member_zones: [BusinessZone; 2],
    requester: MemberIdentity,
    peer: MemberIdentity,
    pub relays: Vec<TrialRelay>,
    pub edges: Vec<TrialEdge>,
}

impl TrialPathPlan {
    /// A local fence and capacity snapshot, not an atomic reservation. A
    /// later admission must recheck capacity under the trial lock itself.
    pub(super) fn locally_current(&self, state: &NetworkState) -> bool {
        let pair = pair_key(self.requester.node_id, self.peer.node_id);
        if self.epoch != state.org_relay.eligibility_generation()
            || crate::overlay::org_fallback_forced_derp(state, &pair)
        {
            return false;
        }
        let available =
            trial::path_has_capacity_snapshot(&state.org_relay, self.path.relay_node_ids());
        available
            && self.epoch == state.org_relay.eligibility_generation()
            && !crate::overlay::org_fallback_forced_derp(state, &pair)
    }

    fn same_authorized_path(&self, fresh: &Self) -> bool {
        self.path == fresh.path
            && self.requester_at_exit == fresh.requester_at_exit
            && self.member_zones == fresh.member_zones
            && self.requester == fresh.requester
            && self.peer == fresh.peer
            && self.relays == fresh.relays
            && self.edges == fresh.edges
    }
}

fn member_identity(node: &OverlayNode) -> Result<MemberIdentity, PeerRelayDenyReason> {
    Ok(MemberIdentity {
        node_id: node.id.ok_or(PeerRelayDenyReason::RequesterUnsupported)?,
        node_ref: node.node_ref.clone(),
        public_key: node.wg_public_key.clone(),
        network_id: node.network_id,
        tenant_id: node.tenant_id,
    })
}

/// Re-read the caller's member rows, policy and live graph, then validate the
/// exact requested sequence. Client data selects identities only: private
/// endpoints and crossing approvals are taken from the current graph.
pub(super) async fn plan(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    path: &RelayPathWire,
    requester_at_exit: bool,
) -> Result<TrialPathPlan, PeerRelayDenyReason> {
    use PeerRelayDenyReason as D;
    let nodes = path.relay_node_ids();
    if nodes.len() < 2 {
        // The existing single-relay trial handles one relay separately.
        return Err(D::RequesterUnsupported);
    }
    let a = requester.id.ok_or(D::RequesterUnsupported)?;
    let b = peer.id.ok_or(D::PeerUnsupported)?;
    let epoch = state.org_relay.eligibility_generation();
    let fresh_a = state
        .overlay_nodes
        .base
        .find_by_id(a)
        .await
        .map_err(|_| D::PolicyUnreadable)?;
    let fresh_b = state
        .overlay_nodes
        .base
        .find_by_id(b)
        .await
        .map_err(|_| D::PolicyUnreadable)?;
    for (old, fresh) in [(requester, &fresh_a), (peer, &fresh_b)] {
        if member_identity(old)? != member_identity(fresh)? || old.tenant_id != fresh.tenant_id {
            return Err(D::RequesterUnsupported);
        }
    }
    if fresh_a.tenant_id != fresh_b.tenant_id {
        return Err(D::CrossTenant);
    }
    if fresh_a.deleted_at.is_some() {
        return Err(D::RequesterUnsupported);
    }
    if fresh_b.deleted_at.is_some() {
        return Err(D::PeerUnsupported);
    }
    if fresh_a.network_id != fresh_b.network_id || fresh_a.node_ref == fresh_b.node_ref {
        return Err(D::RequesterUnsupported);
    }
    if peer_relay_mode(state, fresh_a.tenant_id).await != PeerRelayMode::On {
        return Err(D::OrgDisabled);
    }
    for id in [a, b] {
        let extra = state.org_relay.join_extras(id);
        if !extra.supports_path_trial_v1 || !extra.supports_path_backbone_v1 {
            return Err(D::RequesterUnsupported);
        }
    }
    // Pair visibility is independent from each relay's two-member ACL.
    let acl = try_load_acl(state, fresh_a.tenant_id, PolicyLoad::Always)
        .await
        .map_err(|_| D::PolicyUnreadable)?;
    if acl.enforcing() {
        for (source, destination) in [(&fresh_a, &fresh_b), (&fresh_b, &fresh_a)] {
            let source = try_overlay_source_of(state, source)
                .await
                .map_err(|_| D::PolicyUnreadable)?;
            let routes = destination.effective_routes();
            if !evaluate_overlay(
                &acl.policies,
                &source,
                OverlayPeerRef {
                    node_id: destination.id.ok_or(D::PeerUnsupported)?,
                    overlay_ip: &destination.overlay_ip,
                    approved_routes: &routes,
                },
            )
            .visible
            {
                return Err(D::AclDenied);
            }
        }
    }
    let prepared = path_candidate::prepare(state, &fresh_a, &fresh_b, true).await?;
    if prepared.warn_only || prepared.eligibility_epoch != epoch {
        return Err(D::PolicyUnreadable);
    }
    let first_zone = if requester_at_exit {
        prepared.peer_zone
    } else {
        prepared.requester_zone
    }
    .ok_or(D::ZoneDenied)?;
    let last_zone = if requester_at_exit {
        prepared.requester_zone
    } else {
        prepared.peer_zone
    }
    .ok_or(D::ZoneDenied)?;
    let mut indices = Vec::with_capacity(nodes.len());
    let mut relays = Vec::with_capacity(nodes.len());
    let mut unique = std::collections::HashSet::with_capacity(nodes.len());
    for &node_id in nodes {
        if !unique.insert(node_id) {
            return Err(D::RequesterUnsupported);
        }
        let index = prepared
            .graph
            .relays
            .iter()
            .position(|relay| relay.node_id == node_id)
            .ok_or(D::NoRelay)?;
        let relay = &prepared.graph.relays[index];
        let plan = prepared.plans.get(&node_id).ok_or(D::PolicyUnreadable)?;
        if relay.implicit || relay.zone.is_none() {
            return Err(D::ZoneDenied);
        }
        indices.push(index);
        relays.push(TrialRelay {
            node_id,
            agent_id: relay.agent_id,
            zone: relay.zone.ok_or(D::ZoneDenied)?,
            node_ref: plan.relay.node_ref.clone(),
            endpoints: plan.endpoints.clone(),
        });
    }
    if prepared.graph.relays[indices[0]].zone != Some(first_zone)
        || prepared.graph.relays[*indices.last().ok_or(D::NoRelay)?].zone != Some(last_zone)
    {
        return Err(D::ZoneDenied);
    }
    let mut edges = Vec::with_capacity(nodes.len() - 1);
    for (position, pair) in indices.windows(2).enumerate() {
        let from = &prepared.graph.relays[pair[0]];
        let to = &prepared.graph.relays[pair[1]];
        let from_zone = from.zone.ok_or(D::ZoneDenied)?;
        let to_zone = to.zone.ok_or(D::ZoneDenied)?;
        let crossing = from_zone != to_zone;
        let edge = prepared
            .graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == pair[0] && edge.to == pair[1] && (!crossing || edge.cross_border)
            })
            .ok_or(D::ZoneDenied)?;
        edges.push(TrialEdge {
            source: nodes[position],
            target: nodes[position + 1],
            endpoint: edge.endpoint.clone(),
            requires_cross_border_approval: crossing,
        });
    }
    let result = TrialPathPlan {
        epoch,
        path: path.clone(),
        requester_at_exit,
        member_zones: [first_zone, last_zone],
        requester: member_identity(&fresh_a)?,
        peer: member_identity(&fresh_b)?,
        relays,
        edges,
    };
    if !result.locally_current(state) {
        return Err(D::PolicyUnreadable);
    }
    Ok(result)
}

/// Reconstruct and compare an earlier plan. A replaced relay endpoint, edge,
/// or member identity cannot silently reuse its stale trial candidate.
pub(super) async fn reauthorize(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    expected: &TrialPathPlan,
) -> Result<TrialPathPlan, PeerRelayDenyReason> {
    let fresh = plan(
        state,
        requester,
        peer,
        &expected.path,
        expected.requester_at_exit,
    )
    .await?;
    if !expected.same_authorized_path(&fresh) {
        return Err(PeerRelayDenyReason::PolicyUnreadable);
    }
    Ok(fresh)
}
