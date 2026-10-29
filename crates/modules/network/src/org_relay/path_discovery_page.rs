// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Freshly authorize one bounded page of arbitrary-hop discovery metadata.
use super::*;
use roomler_ai_remote_control::signaling::OrgRelayDiscoveryScanWire as Scan;

pub(super) async fn page(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    checkpoint: Option<&RelayPathWire>,
    after: Option<&OrgRelayDiscoveryCursorWire>,
) -> (Vec<OrgRelayCandidateWire>, Scan) {
    let unavailable = || (Vec::new(), Scan::Unavailable);
    if peer_relay_mode(state, requester.tenant_id).await != PeerRelayMode::On {
        return (Vec::new(), Scan::Stale);
    }
    for node in [requester, peer] {
        let Some(id) = node.id else { return (Vec::new(), Scan::Stale) };
        let extras = state.org_relay.join_extras(id);
        if !extras.supports_path_trial_v1 || !extras.supports_path_backbone_v1 {
            return (Vec::new(), Scan::Stale);
        }
    }
    let Ok(network) = state.overlay_networks.get_or_create(requester.tenant_id).await else { return unavailable() };
    if network.mtu > limits::BACKBONE_MAX_OVERLAY_MTU { return (Vec::new(), Scan::Stale) }
    let prepared = match path_candidate::prepare(state, requester, peer, true).await {
        Ok(prepared) if !prepared.warn_only => prepared,
        _ => return unavailable(),
    };
    let epoch = prepared.eligibility_epoch;
    let scanned = path_discovery::scan(&prepared.graph, prepared.requester_zone, prepared.peer_zone,
        prepared.restrict_ends, after, checkpoint, 3, path_discovery::MAX_EXPANSIONS);
    if scanned.stale { return (Vec::new(), Scan::Stale) }
    let count = scanned.paths.len();
    let last = scanned.paths.last().cloned().or_else(|| after.cloned());
    let mut candidates = Vec::new();
    for identity in scanned.paths {
        let plan = match path_trial_plan::plan(state, requester, peer, &identity.path, identity.requester_at_exit).await {
            Ok(plan) => plan,
            Err(PeerRelayDenyReason::PolicyUnreadable) => return unavailable(),
            Err(_) => continue,
        };
        if plan.epoch != epoch { return unavailable() }
        let relay = if identity.requester_at_exit { plan.relays.last() } else { plan.relays.first() };
        let Some(relay) = relay else { return unavailable() };
        candidates.push(OrgRelayCandidateWire {
            path: identity.path, requester_at_exit: identity.requester_at_exit,
            endpoints: relay.endpoints.clone(),
        });
    }
    if state.org_relay.eligibility_generation() != epoch { return unavailable() }
    // An exactly full page may have a later orientation/path. Resume after
    // the last scanned identity; a subsequent exhausted page wraps the ring.
    let after = if scanned.checkpoint.is_some() || count == 3 { last } else { None };
    (candidates, Scan::Progress { scan_next: false, checkpoint: scanned.checkpoint, after })
}
