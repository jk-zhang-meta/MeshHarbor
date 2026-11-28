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
use meshharbor_core::business_authority::BusinessZone;
use meshharbor_remote_control::models::{
    NodeRef, OverlayNode, PeerRelayDenyReason as Deny, PeerRelayMode, peer_relay_limits as limits,
};
use std::collections::{HashMap, HashSet};

pub(super) struct PreparedGraph {
    pub graph: path_graph::EdgeGraph,
    pub requester_id: ObjectId,
    pub peer_id: ObjectId,
    pub requester_identity: ObjectId,
    pub peer_identity: ObjectId,
    pub plans: HashMap<ObjectId, Plan>,
    pub requester_zone: Option<BusinessZone>,
    pub peer_zone: Option<BusinessZone>,
    /// Ordinary `#21` enforced pairs bind path ends to the members' `BusinessZone`s.
    pub restrict_ends: bool,
    /// True when Logical Network Zones (`OverlayNetwork::zones`) are configured.
    pub network_zones_active: bool,
    /// True when symmetric `RouterOnly` / `UnresolvedStrict` requires `backbone_only`.
    pub network_zones_backbone_only: bool,
    pub requester_gateways: Option<HashSet<ObjectId>>,
    pub peer_gateways: Option<HashSet<ObjectId>>,
    pub eligibility_epoch: u64,
    pub warn_only: bool,
}

impl PreparedGraph {
    pub(super) fn matches_requester_end(&self, relay: &path_graph::EligibleRelay) -> bool {
        self.requester_gateways
            .as_ref()
            .is_none_or(|gw| gw.contains(&relay.agent_id))
            && (!self.restrict_ends || relay.zone == self.requester_zone)
    }

    pub(super) fn matches_peer_end(&self, relay: &path_graph::EligibleRelay) -> bool {
        self.peer_gateways
            .as_ref()
            .is_none_or(|gw| gw.contains(&relay.agent_id))
            && (!self.restrict_ends || relay.zone == self.peer_zone)
    }
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
    let iso_mode = iso::mode(state);
    let enforce_zone = iso_mode == Mode::Enforce;
    let nz_snap = crate::network_zones::TenantZoneSnapshot::load(state, requester.tenant_id).await;
    if nz_snap.read_failed {
        return Err(Deny::PolicyUnreadable);
    }
    let network_zones_active = nz_snap.has_zones();
    let (requester_gateways, peer_gateways, network_zones_backbone_only) = if network_zones_active {
        let req_res = nz_snap.resolve_node_sync(requester);
        let peer_res = nz_snap.resolve_node_sync(peer);
        if matches!(
            req_res,
            meshharbor_remote_control::models::DeviceZoneResolution::UnresolvedStrict
        ) || matches!(
            peer_res,
            meshharbor_remote_control::models::DeviceZoneResolution::UnresolvedStrict
        ) {
            return Err(Deny::ZoneDenied);
        }
        let req_gw = nz_snap.gateway_set_for(req_res).unwrap_or_default();
        let peer_gw = nz_snap.gateway_set_for(peer_res).unwrap_or_default();
        if req_gw.is_empty() || peer_gw.is_empty() {
            return Err(Deny::ZoneDenied);
        }
        let bb_only = crate::network_zones::TenantZoneSnapshot::pair_requires_backbone_only(
            req_res, peer_res,
        );
        if bb_only
            && req_gw.is_disjoint(&peer_gw)
            && (!a_extra.supports_backbone_only_v1 || !b_extra.supports_backbone_only_v1)
        {
            return Err(Deny::ZoneDenied);
        }
        (Some(req_gw), Some(peer_gw), bb_only)
    } else {
        (None, None, false)
    };
    // FR-125 — the two members' logical zones: a link that crosses zones may
    // join exactly these two, and nothing else.
    let pair_nz_zones: Option<(String, String)> = if network_zones_active {
        use meshharbor_remote_control::models::DeviceZoneResolution::Resolved;
        match (
            nz_snap.resolve_node_sync(requester),
            nz_snap.resolve_node_sync(peer),
        ) {
            (Resolved(a), Resolved(b)) => Some((a.id.clone(), b.id.clone())),
            _ => None,
        }
    } else {
        None
    };
    let enforce_pair_zone = enforce_zone;
    let unknown_role_mode = iso::unknown_role_mode(state);
    if enforce_zone || unknown_role_mode != Mode::Off {
        let roles = match meshharbor_core::business_authority::current_approved_roles(
            &state.core,
            requester.tenant_id,
        )
        .await
        {
            Ok(roles) => (unknown_role_mode != Mode::Off).then_some(roles),
            Err(_) if enforce_zone => {
                return Err(Deny::PolicyUnreadable);
            }
            Err(_) => None,
        };
        if let Some(roles) = roles.as_ref() {
            let req_known = roles.contains_key(&iso::Lines::ref_identity(&requester.node_ref));
            let peer_known = roles.contains_key(&iso::Lines::ref_identity(&peer.node_ref));
            if !req_known || !peer_known {
                let mut unknown_devices = Vec::new();
                if !req_known {
                    unknown_devices.push(iso::Lines::node_label(requester));
                }
                if !peer_known {
                    unknown_devices.push(iso::Lines::node_label(peer));
                }
                if enforce_zone && unknown_role_mode == Mode::Enforce {
                    return Err(Deny::ZoneDenied);
                }
                iso::log_unknown_role_with_peers(
                    requester.tenant_id,
                    "path_candidate",
                    &unknown_devices,
                );
            }
        }
    }
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
                let servers = meshharbor_core::business_authority::current_server_agents(
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
                    let pair = meshharbor_remote_control::models::ServerLink::ordered(*a, *b);
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
    if enforce_pair_zone && !linked_servers && (za.is_none() || zb.is_none()) {
        return Err(Deny::ZoneDenied);
    }
    if enforce_pair_zone
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

    // Outside Enforce, preserve the existing Pair gate's Off/Warn behavior (or
    // load the full approved tenant router graph when Logical Network Zones are active).
    let scopes = if network_zones_active && !enforce_pair_zone {
        vec![(ZoneScope::NetworkZoneGraph, None)]
    } else {
        match (enforce_pair_zone, linked_servers, za, zb) {
            (true, true, _, _) => vec![(ZoneScope::Pair, None)],
            (true, false, Some(a), Some(b)) if a != b => {
                vec![(ZoneScope::Side(a), Some(a)), (ZoneScope::Side(b), Some(b))]
            }
            (true, false, Some(a), Some(_)) => vec![(ZoneScope::Pair, Some(a))],
            (false, _, _, _) => vec![(ZoneScope::Pair, None)],
            _ => return Err(Deny::ZoneDenied),
        }
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
            state,
            requester,
            peer,
            reuse,
            scope,
            network_zones_active,
            diagnostic,
        )
        .await?;
        for plan in candidates {
            let relay_zone = node_zone(state, &plan.relay).await;
            if enforce_pair_zone && !linked_servers && relay_zone != expected_zone {
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
            if !network_zones_active
                && (plan.relay.node_ref == requester.node_ref
                    || plan.relay.node_ref == peer.node_ref)
            {
                return Err(Deny::PolicyUnreadable);
            }
            if ((enforce_pair_zone && !linked_servers && za != zb) || network_zones_active)
                && plan.implicit
            {
                return Err(Deny::PolicyUnreadable);
            }
            let node_id = plan.relay.id.ok_or(Deny::PolicyUnreadable)?;
            let ready = state.org_relay.join_extras(node_id).relay_backbone_ready;
            let mut eligible = eligible_from_plan(
                &plan,
                requester.tenant_id,
                requester.network_id,
                relay_zone,
                ready,
            )?;
            if network_zones_active && !enforce_zone && !eligible.implicit {
                for edge in &mut eligible.approved_edges {
                    edge.cross_border = true;
                }
            }
            if plans.insert(eligible.node_id, plan).is_some() {
                return Err(Deny::PolicyUnreadable);
            }
            inputs.push(eligible);
        }
    }
    if inputs.is_empty() {
        return Err(Deny::NoRelay);
    }
    // Same-zone routers auto-mesh: when Logical Network Zones are configured,
    // two approved routers in the SAME resolved NetworkZone may forward directly
    // to each other's primary reachable relay endpoint unless overridden by an
    // explicit `approved_backbone_edges` entry.
    //
    // FR-125 (`app.relay_auto_links`, outside legacy #21 Enforce): relays link
    // to relays freely, by measurement. A link source→target exists on the
    // endpoint the SOURCE measured reachable (fastest first) — directed, since
    // a machine's addresses may admit different sources or none — and across
    // zones too, where the zone rule is the only filter: a crossing link joins
    // the pair's two zones and nothing else; the path's ends stay on the
    // zones' gateways (`matches_requester_end` / `matches_peer_end`). A
    // same-zone link exists as it did before FR-125, on the fastest endpoint
    // the source measured reachable, else the first; a crossing link exists
    // only where it was measured to work. Without auto links, cross-zone
    // router forwarding is restricted to admin-configured edges.
    let auto_links = crate::org_relay::relay_auto_links(state) && !enforce_zone;
    if network_zones_active {
        let peer_snapshots: Vec<(ObjectId, ObjectId, Option<String>)> = inputs
            .iter()
            .map(|r| {
                let z = match nz_snap.resolve_agent(r.agent_id) {
                    meshharbor_remote_control::models::DeviceZoneResolution::Resolved(z) => {
                        Some(z.id.clone())
                    }
                    _ => None,
                };
                (r.agent_id, r.node_id, z)
            })
            .collect();
        for src in &mut inputs {
            let Some(src_zone) = peer_snapshots
                .iter()
                .find(|(aid, _, _)| *aid == src.agent_id)
                .and_then(|(_, _, z)| z.as_deref())
            else {
                continue;
            };
            for (dst_agent, dst_node, dst_zone) in &peer_snapshots {
                if src.approved_edges.len()
                    >= meshharbor_remote_control::models::MAX_PEER_RELAY_BACKBONE_EDGES
                {
                    break;
                }
                let Some(dst_zone) = dst_zone.as_deref() else {
                    continue;
                };
                if *dst_agent == src.agent_id {
                    continue;
                }
                let same_zone = dst_zone == src_zone;
                if !same_zone {
                    let joins_pair = pair_nz_zones.as_ref().is_some_and(|(a, b)| {
                        (src_zone == a && dst_zone == b) || (src_zone == b && dst_zone == a)
                    });
                    if !auto_links || !joins_pair {
                        continue;
                    }
                }
                let has_explicit = src
                    .approved_edges
                    .iter()
                    .any(|e| ObjectId::parse_str(&e.relay_agent_id).ok() == Some(*dst_agent));
                if has_explicit {
                    continue;
                }
                let Some(dst_plan) = plans.get(dst_node) else {
                    continue;
                };
                let candidates: Vec<String> = dst_plan
                    .endpoints
                    .iter()
                    .filter(|ep| {
                        crate::routes::peer_relay::valid_backbone_endpoint(ep)
                            && crate::routes::peer_relay::backbone_endpoint_outside_overlay(
                                ep,
                                &network.cidr,
                            )
                    })
                    .cloned()
                    .collect();
                let Some(first) = candidates.first() else {
                    continue;
                };
                let endpoint = if auto_links {
                    let cutoff = state.org_relay.probe_cutoff(
                        src.node_id,
                        src.agent_id,
                        *dst_node,
                        *dst_agent,
                    );
                    match state.org_relay.measured_backbone_endpoint(
                        src.node_id,
                        *dst_node,
                        &candidates,
                        cutoff,
                        std::time::Instant::now(),
                    ) {
                        // A crossing is never a guess: only a public address
                        // this source measured working since both last joined.
                        Some(ep) if same_zone || crate::org_relay::valid_static_endpoint(&ep) => ep,
                        // Same zone: the link exists as before FR-125, on the
                        // first endpoint, and its measured verdict ranks it.
                        _ if same_zone => first.clone(),
                        _ => continue,
                    }
                } else {
                    first.clone()
                };
                src.approved_edges
                    .push(meshharbor_remote_control::models::PeerRelayBackboneEdge {
                        relay_agent_id: dst_agent.to_hex(),
                        endpoint,
                        cross_border: !enforce_zone || !same_zone,
                    });
            }
        }
    }
    let (requester_gateways, peer_gateways) = member_relays_end_at_themselves(
        &nz_snap,
        &mut inputs,
        (a, requester_gateways),
        (b, peer_gateways),
    );
    let graph =
        path_graph::build(inputs, &network.cidr, iso_mode).map_err(|_| Deny::PolicyUnreadable)?;
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
        restrict_ends: enforce_pair_zone && !linked_servers,
        network_zones_active,
        network_zones_backbone_only,
        requester_gateways,
        peer_gateways,
        eligibility_epoch: epoch,
        warn_only: mode == PeerRelayMode::Warn,
    })
}

/// A pair member that is itself an approved relay may end its own path at
/// itself: the leg into it is dialed by the relay before it, to an address
/// that relay measured, instead of the member dialing out to a gateway. A
/// relay whose machine lets others in at one address but cannot dial out
/// from another (an entry-only forward, an egress that drops the relay port)
/// is otherwise unreachable as a device even though it carries other pairs.
///
/// The zone rule still holds. For this pair the member keeps no link that
/// crosses zones out of it or into it, so it never becomes its zone's border
/// unless it is one of the zone's gateways (and then nothing changes here).
/// The gateway sets are per pair, so adding the member to its own side's set
/// affects only this pair — its selection, mint, trial and discovery all read
/// the same sets; `session_zone::check` applies the same rule on reuse.
fn member_relays_end_at_themselves(
    nz: &crate::network_zones::TenantZoneSnapshot,
    inputs: &mut [path_graph::EligibleRelay],
    (a, requester_gateways): (ObjectId, Option<HashSet<ObjectId>>),
    (b, peer_gateways): (ObjectId, Option<HashSet<ObjectId>>),
) -> (Option<HashSet<ObjectId>>, Option<HashSet<ObjectId>>) {
    if !member_self_end_enabled() {
        return (requester_gateways, peer_gateways);
    }
    let mut sets = [requester_gateways, peer_gateways];
    for (member, gateways) in [a, b].into_iter().zip(sets.iter_mut()) {
        let Some(gateways) = gateways.as_mut() else {
            continue; // no logical zones: no gateway rule to relax
        };
        let Some(own) = inputs
            .iter()
            .find(|r| r.node_id == member && !r.implicit)
            .map(|r| r.agent_id)
        else {
            continue; // not a relay: it attaches to a gateway as before
        };
        if gateways.contains(&own) || !nz.same_resolved_zone(own, own) {
            continue; // already a gateway, or its own zone is unresolved
        }
        let own_hex = own.to_hex();
        for src in inputs.iter_mut() {
            if src.agent_id == own {
                src.approved_edges.retain(|e| {
                    ObjectId::parse_str(&e.relay_agent_id)
                        .is_ok_and(|to| nz.same_resolved_zone(own, to))
                });
            } else if !nz.same_resolved_zone(own, src.agent_id) {
                src.approved_edges.retain(|e| e.relay_agent_id != own_hex);
            }
        }
        gateways.insert(own);
    }
    let [requester_gateways, peer_gateways] = sets;
    (requester_gateways, peer_gateways)
}

/// Kill switch for `member_relays_end_at_themselves`, read once:
/// `MESHHARBOR__ORG_RELAY__MEMBER_SELF_END=0` mints no new such path, and the
/// reuse check stops accepting the ones already installed.
pub(super) fn member_self_end_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("MESHHARBOR__ORG_RELAY__MEMBER_SELF_END").as_deref(),
            Ok("0") | Ok("false") | Ok("off")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::DateTime;
    use meshharbor_core::business_authority::BusinessZone::Mainland;
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
            relay_port: crate::org_relay::limits::DEFAULT_RELAY_PORT,
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
