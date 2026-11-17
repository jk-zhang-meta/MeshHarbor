// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Fresh authorization for a client-specified ordered relay path.
//!
//! This is a planning snapshot, not a reservation or a grant. Before any
//! future trial delivery the owner must repeat authorization as appropriate,
//! check the epoch, and reserve every node under the shared trial claim lock.

use super::*;
use meshharbor_remote_control::signaling::RelayPathWire;

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
    pub zone: Option<BusinessZone>,
    pub node_ref: NodeRef,
    pub relay_port: u16,
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
    pub member_zones: Option<[BusinessZone; 2]>,
    requester: MemberIdentity,
    peer: MemberIdentity,
    pub relays: Vec<TrialRelay>,
    pub edges: Vec<TrialEdge>,
}

impl TrialPathPlan {
    /// A local fence and capacity snapshot, not an atomic reservation. A
    /// later admission must recheck capacity under the trial lock itself.
    pub(super) fn locally_current(&self, state: &NetworkState) -> bool {
        self.locally_current_reusing(state, None)
    }

    fn locally_current_reusing(&self, state: &NetworkState, trial_id: Option<ObjectId>) -> bool {
        let pair = pair_key(self.requester.node_id, self.peer.node_id);
        if self.epoch != state.org_relay.eligibility_generation()
            || crate::overlay::org_fallback_forced_derp(state, &pair)
        {
            return false;
        }
        let available = trial::path_has_capacity_reusing(
            &state.org_relay,
            self.path.relay_node_ids(),
            trial_id,
        );
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
    plan_reusing(state, requester, peer, path, requester_at_exit, None).await
}

pub(super) async fn plan_reusing(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    path: &RelayPathWire,
    requester_at_exit: bool,
    reuse: Option<(ObjectId, &OrgRelaySession)>,
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
    let now_dt = bson::DateTime::now();
    if fresh_a.deleted_at.is_some() || !fresh_a.is_key_authorized_at(now_dt) {
        return Err(D::RequesterUnsupported);
    }
    if fresh_b.deleted_at.is_some() || !fresh_b.is_key_authorized_at(now_dt) {
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
        let (Some(_), Some(_)) = (fresh_a.id, fresh_b.id) else {
            return Err(D::PeerUnsupported);
        };
        let src_a = try_overlay_source_of(state, &fresh_a)
            .await
            .map_err(|_| D::PolicyUnreadable)?;
        let src_b = try_overlay_source_of(state, &fresh_b)
            .await
            .map_err(|_| D::PolicyUnreadable)?;
        if !crate::overlay::pair_trial_visible(&acl.policies, &fresh_a, &src_a, &fresh_b, &src_b) {
            return Err(D::AclDenied);
        }
    }
    let prepared = path_candidate::prepare_reusing(
        state,
        &fresh_a,
        &fresh_b,
        true,
        reuse.map(|(_, session)| session),
    )
    .await?;
    if prepared.warn_only || prepared.eligibility_epoch != epoch {
        return Err(D::PolicyUnreadable);
    }
    let nz_active = prepared.network_zones_active;
    let first_zone = if requester_at_exit {
        prepared.peer_zone
    } else {
        prepared.requester_zone
    };
    let last_zone = if requester_at_exit {
        prepared.requester_zone
    } else {
        prepared.peer_zone
    };
    let (first_id, last_id) = if requester_at_exit { (b, a) } else { (a, b) };
    let mut indices = Vec::with_capacity(nodes.len());
    let mut relays = Vec::with_capacity(nodes.len());
    let mut unique = std::collections::HashSet::with_capacity(nodes.len());
    for (pos, &node_id) in nodes.iter().enumerate() {
        if !unique.insert(node_id) {
            return Err(D::RequesterUnsupported);
        }
        let forbidden_member = if pos == 0 {
            node_id == last_id
        } else if pos + 1 == nodes.len() {
            node_id == first_id
        } else {
            node_id == first_id || node_id == last_id
        };
        if forbidden_member || (!nz_active && (node_id == a || node_id == b)) {
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
        if relay.implicit || ((!nz_active || prepared.restrict_ends) && relay.zone.is_none()) {
            return Err(D::ZoneDenied);
        }
        indices.push(index);
        relays.push(TrialRelay {
            node_id,
            agent_id: relay.agent_id,
            zone: if !nz_active || prepared.restrict_ends {
                Some(relay.zone.ok_or(D::ZoneDenied)?)
            } else {
                relay.zone
            },
            node_ref: plan.relay.node_ref.clone(),
            relay_port: plan.relay_port,
            endpoints: plan.endpoints.iter().take(4).cloned().collect(),
        });
    }
    let first_relay_entry = &prepared.graph.relays[indices[0]];
    let last_relay_entry = &prepared.graph.relays[*indices.last().ok_or(D::NoRelay)?];
    let gw_ends_ok = if requester_at_exit {
        prepared.matches_peer_end(first_relay_entry)
            && prepared.matches_requester_end(last_relay_entry)
    } else {
        prepared.matches_requester_end(first_relay_entry)
            && prepared.matches_peer_end(last_relay_entry)
    };
    if !gw_ends_ok {
        return Err(D::ZoneDenied);
    }
    let member_zones = if prepared.restrict_ends {
        let first = first_zone.ok_or(D::ZoneDenied)?;
        let last = last_zone.ok_or(D::ZoneDenied)?;
        if first_relay_entry.zone != Some(first) || last_relay_entry.zone != Some(last) {
            return Err(D::ZoneDenied);
        }
        Some([first, last])
    } else {
        None
    };
    let mut edges = Vec::with_capacity(nodes.len() - 1);
    for (position, pair) in indices.windows(2).enumerate() {
        let from = &prepared.graph.relays[pair[0]];
        let to = &prepared.graph.relays[pair[1]];
        let crossing = if nz_active && !prepared.restrict_ends {
            from.zone != to.zone && from.zone.is_some() && to.zone.is_some()
        } else {
            let from_zone = from.zone.ok_or(D::ZoneDenied)?;
            let to_zone = to.zone.ok_or(D::ZoneDenied)?;
            from_zone != to_zone
        };
        let edge = prepared
            .graph
            .edges
            .iter()
            .find(|edge| {
                edge.from == pair[0]
                    && edge.to == pair[1]
                    && ((nz_active && !prepared.restrict_ends) || !crossing || edge.cross_border)
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
        member_zones,
        requester: member_identity(&fresh_a)?,
        peer: member_identity(&fresh_b)?,
        relays,
        edges,
    };
    if !result.locally_current_reusing(state, reuse.map(|(id, _)| id)) {
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
    reauthorize_reusing(state, requester, peer, expected, None).await
}

pub(super) async fn reauthorize_reusing(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    expected: &TrialPathPlan,
    reuse: Option<(ObjectId, &OrgRelaySession)>,
) -> Result<TrialPathPlan, PeerRelayDenyReason> {
    let fresh = plan_reusing(
        state,
        requester,
        peer,
        &expected.path,
        expected.requester_at_exit,
        reuse,
    )
    .await?;
    if !expected.same_authorized_path(&fresh) {
        return Err(PeerRelayDenyReason::PolicyUnreadable);
    }
    Ok(fresh)
}

/// Hysteresis for upgrading a bound `OrgRelaySession` (single-hop or multi-hop,
/// ordinary or finalized trial incumbent) via bilateral make-before-break
/// `PathTrial`: candidate path must be fully measured reachable (`class == 0`)
/// AND beat `current` either because `current` is measured unreachable
/// (`class == 2`) or because both are measured reachable and `candidate`'s
/// effective SLA cost is at least 25% AND 20 ms lower.
pub(super) fn bound_upgrade_clearly_better(candidate: (u8, u128), current: (u8, u128)) -> bool {
    candidate.0 == 0
        && (current.0 == 2
            || (current.0 == 0
                && candidate.1.saturating_mul(4) <= current.1.saturating_mul(3)
                && current.1.saturating_sub(candidate.1) >= 20))
}

/// Evaluate the incumbent `OrgRelaySession`'s `(class, effective_cost_ms)`
/// across its member-to-ingress, intermediate backbone hops (if any), and
/// member-to-exit legs.
pub(super) fn incumbent_session_sla_rank(
    org_relay: &OrgRelayState,
    current_session: &OrgRelaySession,
    now: Instant,
) -> (u8, u128) {
    let relays: Vec<ObjectId> = current_session.relay_nodes().collect();
    if relays.is_empty() {
        return (2, u128::MAX);
    }
    let m0 = current_session.members[0].party.node_id;
    let m1 = current_session.members[1].party.node_id;
    let self_zero = path_search::SlaVerdict::Reachable {
        rtt_ms: 0,
        jitter_ms: 0,
        loss_permille: 0,
    };
    let mut legs = Vec::with_capacity(relays.len() + 1);
    legs.push(if !current_session.hops.is_empty() && m0 == relays[0] {
        self_zero
    } else {
        org_relay.sla_verdict(m0, relays[0], now)
    });
    for pair in relays.windows(2) {
        legs.push(org_relay.backbone_sla_verdict(pair[0], pair[1], now));
    }
    let last_relay = *relays.last().unwrap();
    legs.push(if !current_session.hops.is_empty() && m1 == last_relay {
        self_zero
    } else {
        org_relay.sla_verdict(m1, last_relay, now)
    });
    let loads = relays.iter().map(|&r| org_relay.sessions_on_relay(r));
    let (class, eff_cost, _, _, _, _, _) = path_search::evaluate_sla_legs(legs, loads);
    (class, eff_cost)
}

/// Select an authorized single-hop or multi-hop candidate path that beats a
/// currently bound `OrgRelaySession` by [`bound_upgrade_clearly_better`],
/// respecting all `NetworkZone` gateway constraints and capability gates.
pub(super) async fn plan_bound_upgrade(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    current_session: &OrgRelaySession,
) -> Option<(RelayPathWire, bool)> {
    let (req_id, peer_id) = (requester.id?, peer.id?);
    let now = Instant::now();
    if now < current_session.bind_by || now >= current_session.expires_at {
        return None;
    }
    for id in [req_id, peer_id] {
        let extra = state.org_relay.join_extras(id);
        if !extra.supports_path_trial_v1 || !extra.supports_path_backbone_v1 {
            return None;
        }
    }
    let incumbent_relays: Vec<ObjectId> = current_session.relay_nodes().collect();
    if incumbent_relays.is_empty() {
        return None;
    }
    let incumbent_req_at_exit =
        !current_session.hops.is_empty() && current_session.members[1].party.node_id == req_id;
    let current_rank = incumbent_session_sla_rank(&state.org_relay, current_session, now);
    if current_rank.0 == 1 {
        return None;
    }

    let mut best_choice: Option<((u8, u128), RelayPathWire, bool)> = None;

    // Evaluate multi-hop + single-hop graph selection (when MTU <= 1360) and
    // single-hop candidate ranking, picking the lowest-SLA-cost authorized upgrade.
    if let Ok(prepared) = path_candidate::prepare(state, requester, peer, true).await
        && !prepared.warn_only
        && let Ok(Some(selected)) = path_select::select_for_mint(state, prepared, false)
    {
        let cand_rank = (
            selected.path.path.class,
            selected.path.path.effective_cost_ms,
        );
        let relay_ids: Vec<ObjectId> = selected
            .path
            .path
            .relays
            .iter()
            .filter_map(|&idx| selected.prepared.graph.relays.get(idx).map(|r| r.node_id))
            .collect();
        let requester_at_exit = relay_ids.len() > 1 && selected.path.flipped;
        let same_as_incumbent = relay_ids == incumbent_relays
            && (relay_ids.len() <= 1 || requester_at_exit == incumbent_req_at_exit);
        if relay_ids.len() == selected.path.path.relays.len()
            && !same_as_incumbent
            && bound_upgrade_clearly_better(cand_rank, current_rank)
            && let Ok(wire) = RelayPathWire::new(relay_ids)
        {
            best_choice = Some((cand_rank, wire, requester_at_exit));
        }
    }

    if let Ok(plans) = plan_mint_candidates(state, requester, peer).await
        && let Some(best) = plans.into_iter().next()
        && let Some(best_id) = best.relay.id
        && !(incumbent_relays.len() == 1 && incumbent_relays[0] == best_id)
    {
        let load = state.org_relay.sessions_on_relay(best_id);
        let (class, eff_cost, _, _, _, _, _) =
            super::sla_rank_key(&state.org_relay, req_id, peer_id, best_id, load, now);
        let cand_rank = (class, eff_cost);
        if bound_upgrade_clearly_better(cand_rank, current_rank)
            && best_choice
                .as_ref()
                .is_none_or(|(prev, _, _)| cand_rank < *prev)
            && let Ok(wire) = RelayPathWire::new(vec![best_id])
        {
            best_choice = Some((cand_rank, wire, false));
        }
    }
    best_choice.map(|(_, wire, requester_at_exit)| (wire, requester_at_exit))
}
