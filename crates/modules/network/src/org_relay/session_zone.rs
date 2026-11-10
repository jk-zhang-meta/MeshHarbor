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

#[derive(Clone, Copy, PartialEq, Eq)]
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
    let parties: Vec<_> = std::iter::once(&session.members[0].party)
        .chain(std::iter::once(&session.relay))
        .chain(session.hops.iter().map(|hop| &hop.relay))
        .chain(std::iter::once(&session.members[1].party))
        .collect();
    let mut zones = Vec::with_capacity(parties.len());
    let mut read_failed = false;
    // Read every party: an unknown early relay cannot hide a later confirmed
    // deletion or a known edge whose region relationship has changed.
    for party in parties {
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
    let mut unknown = zones.contains(&PartyZone::Unknown);
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
    } else if !unknown && !invalid {
        let mode = iso::mode(state);
        let topo = iso::lines(state, mode, session.tenant_id).await;
        if topo.roles_read_failed {
            unknown = true;
            read_failed = true;
        } else {
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
