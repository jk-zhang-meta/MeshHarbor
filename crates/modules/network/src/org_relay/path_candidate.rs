// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Construction of a path graph from the existing live relay gates.
//! It does not mint, send messages, or reserve resources. The caller must
//! re-authorize and reserve the selected path before sending any grants.

use super::{
    OrgRelaySession, Plan, TrialUnknownZoneDiagnostics, ZoneScope, node_zone, path_graph,
    peer_relay_mode, plan_mint_candidates_with_trial_diagnostics,
};
use crate::NetworkState;
use bson::oid::ObjectId;
use roomler_ai_remote_control::models::{
    NodeRef, OverlayNode, PeerRelayDenyReason as Deny, PeerRelayMode, peer_relay_limits as limits,
};
use roomler_core::business_authority::BusinessZone;
use std::collections::HashMap;

pub(super) struct PreparedGraph {
    pub graph: path_graph::EdgeGraph,
    pub requester_id: ObjectId,
    pub peer_id: ObjectId,
    pub requester_identity: ObjectId,
    pub peer_identity: ObjectId,
    pub plans: HashMap<ObjectId, Plan>,
    pub requester_zone: Option<BusinessZone>,
    pub peer_zone: Option<BusinessZone>,
    /// Ordinary enforced pairs bind path ends to the members' zones.
    /// A topology-linked server pair may use either permitted relay zone.
    pub restrict_ends: bool,
    pub eligibility_epoch: u64,
    pub warn_only: bool,
}

/// Convert only a Plan produced by the current candidate gate. It checks that
/// the overlay row and its backing agent really are the same tenant identity;
/// eligibility and the current zone are obtained separately by the caller.
fn eligible_from_plan(
    plan: &Plan,
    tenant: ObjectId,
    network: ObjectId,
    zone: Option<BusinessZone>,
    bridge_ready: bool,
) -> Result<path_graph::EligibleRelay, Deny> {
    let node_id = plan.relay.id.ok_or(Deny::PolicyUnreadable)?;
    if plan.relay.tenant_id != tenant
        || plan.relay.network_id != network
        || !matches!(&plan.relay.node_ref, NodeRef::Agent { agent_id } if *agent_id == plan.relay_agent_id)
    {
        return Err(Deny::PolicyUnreadable);
    }
    Ok(path_graph::EligibleRelay {
        node_id,
        agent_id: plan.relay_agent_id,
        zone,
        bridge_ready,
        implicit: plan.implicit,
        approved_edges: plan.backbone_edges.clone(),
    })
}

/// Snapshot a graph only from existing per-pair gates. More than one edge is
/// possible, but this function is not a
/// session reservation: it cannot by itself authorize any later bridge grant.
pub(super) async fn prepare(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    for_trial: bool,
) -> Result<PreparedGraph, Deny> {
    prepare_reusing(state, requester, peer, for_trial, None).await
}

/// Reauthorize an already-held path without treating its own slots as new
/// capacity on any relay in that path. Callers still validate every leg.
pub(super) async fn prepare_reusing(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    for_trial: bool,
    reuse: Option<&OrgRelaySession>,
) -> Result<PreparedGraph, Deny> {
    if requester.tenant_id != peer.tenant_id {
        return Err(Deny::CrossTenant);
    }
    if requester.network_id != peer.network_id || requester.node_ref == peer.node_ref {
        return Err(Deny::RequesterUnsupported);
    }
    let (Some(a), Some(b)) = (requester.id, peer.id) else {
        return Err(Deny::RequesterUnsupported);
    };
    if a == b {
        return Err(Deny::RequesterUnsupported);
    }
    let epoch = state.org_relay.eligibility_generation();
    let mode = peer_relay_mode(state, requester.tenant_id).await;
    if mode == PeerRelayMode::Off {
        return Err(Deny::OrgDisabled);
    }
    let (a_extra, b_extra) = (
        state.org_relay.join_extras(a),
        state.org_relay.join_extras(b),
    );
    if for_trial && (!a_extra.supports_path_backbone_v1 || !b_extra.supports_path_backbone_v1) {
        return Err(Deny::RequesterUnsupported);
    }
    use crate::business_isolation::{self as iso, Mode};
    let enforce_zone = iso::mode(state) == Mode::Enforce;
    let (za, zb) = (
        node_zone(state, requester).await,
        node_zone(state, peer).await,
    );
    // The existing mint handles two known, different zones as a cross-border
    // line even for linked servers. The topology exception applies only when
    // the pair is not known to cross the boundary.
    let known_crossing = matches!((za, zb), (Some(a), Some(b)) if a != b);
    // The server topology is a pair-level gate, even when Side-scope relay
    // candidates are used for a cross-zone path. Without this explicit check,
    // the Side gate alone could route two unlinked servers around that rule.
    let server_pair = if enforce_zone {
        match (&requester.node_ref, &peer.node_ref) {
            (NodeRef::Agent { agent_id: a }, NodeRef::Agent { agent_id: b }) => {
                // `business_isolation::lines` deliberately hides role/DB
                // failures for netmap shaping. The authorization snapshot
                // must not mistake a failed read for a non-server pair.
                let servers = roomler_core::business_authority::current_server_agents(
                    &state.core,
                    requester.tenant_id,
                )
                .await
                .map_err(|_| Deny::PolicyUnreadable)?;
                if servers.iter().any(|agent| agent.id == Some(*a))
                    && servers.iter().any(|agent| agent.id == Some(*b))
                {
                    let network = state
                        .overlay_networks
                        .find_for_tenant(requester.tenant_id)
                        .await
                        .map_err(|_| Deny::PolicyUnreadable)?
                        .ok_or(Deny::PolicyUnreadable)?;
                    let pair = roomler_ai_remote_control::models::ServerLink::ordered(*a, *b);
                    Some(
                        network
                            .server_links
                            .iter()
                            .any(|link| link.enabled && (link.a, link.b) == pair),
                    )
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };
    if server_pair == Some(false) {
        return Err(Deny::ZoneDenied);
    }
    let linked_servers = enforce_zone && !known_crossing && server_pair == Some(true);
    if enforce_zone && !linked_servers && (za.is_none() || zb.is_none()) {
        return Err(Deny::ZoneDenied);
    }
    if enforce_zone
        && !linked_servers
        && za != zb
        && (!a_extra.supports_backbone_only_v1 || !b_extra.supports_backbone_only_v1)
    {
        return Err(Deny::ZoneDenied);
    }
    let network = state
        .overlay_networks
        .get_or_create(requester.tenant_id)
        .await
        .map_err(|_| Deny::PolicyUnreadable)?;
    if network.id != Some(requester.network_id) || network.peer_relay_mode != mode {
        return Err(Deny::PolicyUnreadable);
    }
    if network.mtu > limits::BACKBONE_MAX_OVERLAY_MTU {
        return Err(Deny::RequesterUnsupported);
    }

    // Outside Enforce, preserve the existing Pair gate's Off/Warn behavior.
    // In Enforce, the members have known zones (checked above), and a
    // crossing requires explicit Side-scope authorizations.
    let scopes = match (enforce_zone, linked_servers, za, zb) {
        (true, true, _, _) => vec![(ZoneScope::Pair, None)],
        (true, false, Some(a), Some(b)) if a != b => {
            vec![(ZoneScope::Side(a), Some(a)), (ZoneScope::Side(b), Some(b))]
        }
        (true, false, Some(a), Some(_)) => vec![(ZoneScope::Pair, Some(a))],
        (false, _, _, _) => vec![(ZoneScope::Pair, None)],
        _ => return Err(Deny::ZoneDenied),
    };
    let mut inputs = Vec::new();
    let mut plans = HashMap::new();
    let mut trial_diagnostic = TrialUnknownZoneDiagnostics::default();
    for (scope, expected_zone) in scopes {
        let diagnostic = if for_trial {
            Some(&mut trial_diagnostic)
        } else {
            None
        };
        let candidates = plan_mint_candidates_with_trial_diagnostics(
            state, requester, peer, reuse, scope, diagnostic,
        )
        .await?;
        for plan in candidates {
            let relay_zone = node_zone(state, &plan.relay).await;
            if enforce_zone && !linked_servers && relay_zone != expected_zone {
                if for_trial
                    && !plan.implicit
                    && relay_zone.is_none()
                    && expected_zone.is_some()
                    && plan.relay.tenant_id == requester.tenant_id
                    && plan.relay.network_id == requester.network_id
                    && matches!(&plan.relay.node_ref, NodeRef::Agent { agent_id } if *agent_id == plan.relay_agent_id)
                {
                    trial_diagnostic.filtered(plan.relay_agent_id);
                }
                continue;
            }
            if plan.relay.node_ref == requester.node_ref || plan.relay.node_ref == peer.node_ref {
                return Err(Deny::PolicyUnreadable);
            }
            if enforce_zone && !linked_servers && za != zb && plan.implicit {
                return Err(Deny::PolicyUnreadable);
            }
            let node_id = plan.relay.id.ok_or(Deny::PolicyUnreadable)?;
            let ready = state.org_relay.join_extras(node_id).relay_backbone_ready;
            let eligible = eligible_from_plan(
                &plan,
                requester.tenant_id,
                requester.network_id,
                relay_zone,
                ready,
            )?;
            if plans.insert(eligible.node_id, plan).is_some() {
                return Err(Deny::PolicyUnreadable);
            }
            inputs.push(eligible);
        }
    }
    if inputs.is_empty() {
        return Err(Deny::NoRelay);
    }
    let graph = path_graph::build(inputs, &network.cidr, iso::mode(state))
        .map_err(|_| Deny::PolicyUnreadable)?;
    // This detects known policy/join changes during reads, not all races; a
    // future mint must validate again under its own reservation boundary.
    if epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    Ok(PreparedGraph {
        graph,
        requester_id: a,
        peer_id: b,
        requester_identity: match &requester.node_ref {
            NodeRef::Agent { agent_id } => *agent_id,
            NodeRef::TunnelClient { tunnel_client_id } => *tunnel_client_id,
        },
        peer_identity: match &peer.node_ref {
            NodeRef::Agent { agent_id } => *agent_id,
            NodeRef::TunnelClient { tunnel_client_id } => *tunnel_client_id,
        },
        plans,
        requester_zone: za,
        peer_zone: zb,
        restrict_ends: enforce_zone && !linked_servers,
        eligibility_epoch: epoch,
        warn_only: mode == PeerRelayMode::Warn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::DateTime;
    use roomler_core::business_authority::BusinessZone::Mainland;
    fn plan(tenant: ObjectId, agent: ObjectId, node_id: ObjectId, implicit: bool) -> Plan {
        let mut node: OverlayNode = serde_json::from_value(serde_json::json!({
            "tenant_id": tenant, "node_ref": {"kind":"agent", "id": agent},
            "network_id":ObjectId::new(), "machine_id":"m", "name":"n", "overlay_ip":"100.64.0.9",
            "wg_public_key":"k", "status":"online", "last_seen_at":DateTime::now(),
            "created_at":DateTime::now(), "updated_at":DateTime::now()
        }))
        .unwrap();
        node.id = Some(node_id);
        Plan {
            relay: node,
            relay_agent_id: agent,
            endpoints: vec![],
            backbone_edges: vec![],
            implicit,
        }
    }
    #[test]
    fn gate_output_conversion_preserves_identity_and_implicit_provenance() {
        let tenant = ObjectId::new();
        let agent = ObjectId::new();
        let id = ObjectId::new();
        let p = plan(tenant, agent, id, true);
        let network = p.relay.network_id;
        let e = eligible_from_plan(&p, tenant, network, Some(Mainland), false).unwrap();
        assert_eq!(
            (e.node_id, e.agent_id, e.zone, e.bridge_ready, e.implicit),
            (id, agent, Some(Mainland), false, true)
        );
        assert!(eligible_from_plan(&p, ObjectId::new(), network, Some(Mainland), true).is_err());
        assert!(eligible_from_plan(&p, tenant, ObjectId::new(), Some(Mainland), true).is_err());
        let mut stale = p.clone();
        stale.relay.node_ref = NodeRef::Agent {
            agent_id: ObjectId::new(),
        };
        assert!(eligible_from_plan(&stale, tenant, network, Some(Mainland), true).is_err());
        let mut missing = p;
        missing.relay.id = None;
        assert!(eligible_from_plan(&missing, tenant, network, Some(Mainland), true).is_err());
    }
}
