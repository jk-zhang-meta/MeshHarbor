// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Region evidence for an already-established formal session. Uncertainty
//! prevents a fresh grant but is not evidence for tearing down working data.

use super::{
    OrgRelaySession,
    trial::{PartyZone, current_party_zone},
};
use crate::{NetworkState, business_isolation as iso};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Decision {
    Fits,
    Uncertain { retryable: bool },
    Invalid,
}

fn relation_invalid(a: PartyZone, b: PartyZone, crossing: bool) -> bool {
    matches!((a, b), (PartyZone::Known(a), PartyZone::Known(b)) if (a != b) != crossing)
}

pub(super) async fn check(state: &NetworkState, session: &OrgRelaySession) -> Decision {
    let epoch = state.org_relay.eligibility_generation();
    let mode = iso::mode(state);
    let topo = iso::lines(state, mode, session.tenant_id).await;
    if topo.restricted_read_failed || (mode != iso::Mode::Off && topo.roles_read_failed) {
        return Decision::Uncertain { retryable: true };
    }
    if topo.has_network_zones() {
        if session.implicit {
            return Decision::Invalid;
        }
        let m0 = topo
            .network_zones
            .resolve_ref(state, session.tenant_id, &session.members[0].party.node_ref)
            .await;
        let m1 = topo
            .network_zones
            .resolve_ref(state, session.tenant_id, &session.members[1].party.node_ref)
            .await;
        let Some(gw0) = topo.network_zones.gateway_set_for(m0) else {
            return Decision::Invalid;
        };
        let Some(gw1) = topo.network_zones.gateway_set_for(m1) else {
            return Decision::Invalid;
        };
        if session.hops.is_empty() {
            if !gw0.contains(&session.relay_agent_id) || !gw1.contains(&session.relay_agent_id) {
                return Decision::Invalid;
            }
        } else {
            let last_agent = session
                .hops
                .last()
                .map(|h| h.relay_agent_id)
                .unwrap_or(session.relay_agent_id);
            if !gw0.contains(&session.relay_agent_id) || !gw1.contains(&last_agent) {
                return Decision::Invalid;
            }
            let Ok(relays) = state
                .fleet
                .agents
                .list_relay_approved(session.tenant_id)
                .await
            else {
                return Decision::Uncertain { retryable: true };
            };
            let by_id: std::collections::HashMap<_, _> =
                relays.iter().filter_map(|a| a.id.map(|id| (id, a))).collect();
            let mut prev_agent = session.relay_agent_id;
            if !by_id.contains_key(&prev_agent) {
                return Decision::Invalid;
            }
            for hop in &session.hops {
                let Some(src) = by_id.get(&prev_agent) else {
                    return Decision::Invalid;
                };
                if !by_id.contains_key(&hop.relay_agent_id) {
                    return Decision::Invalid;
                }
                let explicit_for_target = src
                    .peer_relay_policy
                    .approved_backbone_edges
                    .iter()
                    .find(|e| {
                        bson::oid::ObjectId::parse_str(&e.relay_agent_id).ok()
                            == Some(hop.relay_agent_id)
                    });
                let has_edge = match explicit_for_target {
                    Some(e) => e.endpoint == hop.private_endpoint,
                    None => {
                        topo.network_zones
                            .same_resolved_zone(prev_agent, hop.relay_agent_id)
                            && crate::routes::peer_relay::valid_backbone_endpoint(
                                &hop.private_endpoint,
                            )
                    }
                };
                if !has_edge {
                    return Decision::Invalid;
                }
                prev_agent = hop.relay_agent_id;
            }
        }
        if mode == iso::Mode::Off {
            if epoch != state.org_relay.eligibility_generation() {
                return Decision::Uncertain { retryable: true };
            }
            return Decision::Fits;
        }
    }

    let single_hop_ctx = if session.hops.is_empty() {
        if mode == iso::Mode::Off {
            return Decision::Fits;
        }
        Some((mode, topo))
    } else {
        None
    };

    let parties: Vec<_> = std::iter::once(&session.members[0].party)
        .chain(std::iter::once(&session.relay))
        .chain(session.hops.iter().map(|hop| &hop.relay))
        .chain(std::iter::once(&session.members[1].party))
        .collect();
    let mut zones = Vec::with_capacity(parties.len());
    let mut read_failed = false;
    // Read every party: an unknown early relay cannot hide a later confirmed
    // deletion or a known edge whose region relationship has changed.
    for party in &parties {
        let observed = tokio::time::timeout(
            Duration::from_secs(3),
            current_party_zone(
                state,
                session.tenant_id,
                party.node_id,
                &party.node_ref,
                true,
            ),
        )
        .await;
        zones.push(match observed {
            Ok(Ok(zone)) => zone,
            _ => {
                read_failed = true;
                PartyZone::Unknown
            }
        });
    }
    let unknown = zones.contains(&PartyZone::Unknown);
    let mut invalid = zones.contains(&PartyZone::Invalid);
    if !session.hops.is_empty() {
        invalid |= relation_invalid(zones[0], zones[1], false);
        for (index, hop) in session.hops.iter().enumerate() {
            invalid |= relation_invalid(
                zones[index + 1],
                zones[index + 2],
                hop.requires_cross_border_approval,
            );
        }
        invalid |= relation_invalid(zones[zones.len() - 2], zones[zones.len() - 1], false);
    } else if let Some((mode, topo)) = single_hop_ctx {
        if !unknown && !invalid {
            let permit = iso::permit_refs_with_lines(
                state,
                mode,
                &topo,
                session.tenant_id,
                &session.members[0].party.node_ref,
                &session.members[1].party.node_ref,
            )
            .await;
            invalid = match zones[1] {
                PartyZone::Known(relay) => !permit.relay_zones().contains(&relay),
                _ => true,
            };
        }
    }
    #[cfg(feature = "path-planner-test-support")]
    super::candidate_test_support::pause_session_zone_if_armed(&session.pair_key).await;
    let epoch_changed = epoch != state.org_relay.eligibility_generation();
    // Confirmed invalidity wins: callers revoke only the captured session's
    // exact pair/VNI/generation, never a concurrently installed replacement.
    if invalid {
        Decision::Invalid
    } else if unknown || epoch_changed {
        Decision::Uncertain {
            retryable: read_failed || epoch_changed,
        }
    } else {
        Decision::Fits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_core::business_authority::BusinessZone::{Mainland, NonMainland};

    #[test]
    fn uncertain_edges_do_not_hide_a_later_known_violation() {
        let zones = [
            PartyZone::Unknown,
            PartyZone::Known(Mainland),
            PartyZone::Known(NonMainland),
        ];
        assert!(!relation_invalid(zones[0], zones[1], false));
        assert!(relation_invalid(zones[1], zones[2], false));
        assert!(!relation_invalid(zones[1], zones[2], true));
    }
}
