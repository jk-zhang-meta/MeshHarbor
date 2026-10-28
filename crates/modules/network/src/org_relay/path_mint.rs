// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Cross-zone multi-relay mint. Rechecks the selected path against a fresh
//! gate snapshot and records each crossing before claiming or sending it.

use super::*;
use roomler_ai_remote_control::models::PeerRelayDenyReason as Deny;

/// A selected edge is addressed by identities and endpoint, not graph index:
/// the fresh snapshot is independently ordered and may have changed.
struct ChosenEdge {
    source_node: ObjectId,
    source_agent: ObjectId,
    target_node: ObjectId,
    target_agent: ObjectId,
    endpoint: String,
    cross_border: bool,
}

/// Attempt a selected multi-relay cross-zone path. No grants are sent if
/// a policy, live identity, edge, capacity, VNI or crossing audit check fails.
pub(super) async fn mint(
    state: &NetworkState,
    requester: &OverlayNode,
    peer: &OverlayNode,
    warn_only: bool,
    charged_relay: &mut Option<ObjectId>,
) -> Result<bool, Deny> {
    let (Some(a), Some(b)) = (requester.id, peer.id) else {
        return Err(Deny::RequesterUnsupported);
    };
    let Ok(original) = path_candidate::prepare(state, requester, peer, false).await else {
        return Ok(false); // Established two-relay planning remains available.
    };
    if original.warn_only != warn_only {
        return Err(Deny::PolicyUnreadable);
    }
    let Some(selected) = path_select::select(state, original).unwrap_or(None) else {
        return Ok(false);
    };
    let graph = &selected.prepared.graph;
    let indices = &selected.path.path.relays;
    let edge_indices = &selected.path.path.edges;
    // Keep the established one/two-relay behavior when search selects it;
    // longer measured paths have no fixed maximum.
    if indices.len() < 3 {
        return Ok(false);
    }
    if edge_indices.len() + 1 != indices.len() {
        return Err(Deny::PolicyUnreadable);
    }
    let mut chosen = Vec::with_capacity(edge_indices.len());
    for (i, &edge_index) in edge_indices.iter().enumerate() {
        let edge = graph.edges.get(edge_index).ok_or(Deny::PolicyUnreadable)?;
        if edge.from != indices[i] || edge.to != indices[i + 1] {
            return Err(Deny::PolicyUnreadable);
        }
        let source = graph.relays.get(edge.from).ok_or(Deny::PolicyUnreadable)?;
        let target = graph.relays.get(edge.to).ok_or(Deny::PolicyUnreadable)?;
        chosen.push(ChosenEdge {
            source_node: source.node_id,
            source_agent: source.agent_id,
            target_node: target.node_id,
            target_agent: target.agent_id,
            endpoint: edge.endpoint.clone(),
            cross_border: edge.cross_border,
        });
    }
    let flipped = selected.path.flipped;
    // Re-read the actual member rows and rerun all live/ACL/edge gates. A
    // replaced identity or changed public key cannot inherit the old request.
    let fresh_a = state
        .overlay_nodes
        .base
        .find_by_id(a)
        .await
        .map_err(|_| Deny::PolicyUnreadable)?;
    let fresh_b = state
        .overlay_nodes
        .base
        .find_by_id(b)
        .await
        .map_err(|_| Deny::PolicyUnreadable)?;
    if fresh_a.node_ref != requester.node_ref
        || fresh_b.node_ref != peer.node_ref
        || fresh_a.wg_public_key != requester.wg_public_key
        || fresh_b.wg_public_key != peer.wg_public_key
        || fresh_a.tenant_id != requester.tenant_id
        || fresh_b.tenant_id != peer.tenant_id
        || fresh_a.network_id != requester.network_id
        || fresh_b.network_id != peer.network_id
    {
        return Err(Deny::PolicyUnreadable);
    }
    let fresh = path_candidate::prepare(state, &fresh_a, &fresh_b, false).await?;
    if fresh.warn_only != warn_only {
        return Err(Deny::PolicyUnreadable);
    }
    let mut relay_nodes = Vec::with_capacity(indices.len());
    relay_nodes.push((chosen[0].source_node, chosen[0].source_agent));
    relay_nodes.extend(chosen.iter().map(|e| (e.target_node, e.target_agent)));
    let mut seen = std::collections::HashSet::new();
    let mut relays = Vec::with_capacity(relay_nodes.len());
    for (node_id, agent_id) in relay_nodes {
        if !seen.insert(node_id) {
            return Err(Deny::PolicyUnreadable);
        }
        let index = fresh
            .graph
            .relays
            .iter()
            .position(|r| r.node_id == node_id && r.agent_id == agent_id)
            .ok_or(Deny::PolicyUnreadable)?;
        let relay = &fresh.graph.relays[index];
        // Mixed implicit/explicit grants cannot be represented by the current
        // session-wide implicit flag and ACL-reconciliation logic.
        if relay.implicit {
            return Err(Deny::PolicyUnreadable);
        }
        let plan = fresh.plans.get(&node_id).ok_or(Deny::PolicyUnreadable)?;
        relays.push((index, relay, plan));
    }
    let (first_member, last_member) = if flipped {
        (&fresh_b, &fresh_a)
    } else {
        (&fresh_a, &fresh_b)
    };
    let first_zone = if flipped {
        fresh.peer_zone
    } else {
        fresh.requester_zone
    };
    let last_zone = if flipped {
        fresh.requester_zone
    } else {
        fresh.peer_zone
    };
    if first_zone.is_none()
        || last_zone.is_none()
        || relays[0].1.zone != first_zone
        || relays[relays.len() - 1].1.zone != last_zone
    {
        return Err(Deny::ZoneDenied);
    }
    let member = |node: &OverlayNode| SessionMember {
        party: SessionParty {
            node_id: node.id.unwrap_or_default(),
            node_ref: node.node_ref.clone(),
        },
        wg_public_key: node.wg_public_key.clone(),
        bind_secret: random_secret(),
    };
    let now = Instant::now();
    let mut session = OrgRelaySession {
        tenant_id: fresh_a.tenant_id,
        pair_key: pair_key(a, b),
        vni: 1,
        generation: state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1,
        relay: SessionParty {
            node_id: relays[0].1.node_id,
            node_ref: relays[0].2.relay.node_ref.clone(),
        },
        relay_agent_id: relays[0].1.agent_id,
        implicit: false,
        members: [member(first_member), member(last_member)],
        endpoints: relays[0].2.endpoints.clone(),
        expires_at: now + Duration::from_secs(u64::from(limits::MAX_LIFETIME_SECS)),
        bind_by: now + Duration::from_secs(u64::from(limits::BIND_SECS)),
        hops: Vec::with_capacity(chosen.len()),
    };
    for (i, selected_edge) in chosen.iter().enumerate() {
        let (from_index, from, _) = relays[i];
        let (to_index, to, plan) = relays[i + 1];
        let edge = fresh
            .graph
            .edges
            .iter()
            .find(|e| {
                e.from == from_index
                    && e.to == to_index
                    && e.endpoint == selected_edge.endpoint
                    && e.cross_border == selected_edge.cross_border
            })
            .ok_or(Deny::PolicyUnreadable)?;
        let (Some(from_zone), Some(to_zone)) = (from.zone, to.zone) else {
            return Err(Deny::ZoneDenied);
        };
        let crossing = from_zone != to_zone;
        if crossing && !edge.cross_border {
            return Err(Deny::ZoneDenied);
        }
        session.hops.push(LineLeg {
            relay: SessionParty {
                node_id: to.node_id,
                node_ref: plan.relay.node_ref.clone(),
            },
            relay_agent_id: to.agent_id,
            vni: 1,
            generation: state.org_relay.lamport.fetch_add(1, Ordering::Relaxed) + 1,
            endpoints: plan.endpoints.clone(),
            private_endpoint: edge.endpoint.clone(),
            requires_cross_border_approval: crossing,
            bridge_id: ObjectId::new(),
            bridge_secrets: [random_secret(), random_secret()],
        });
    }
    if !session
        .hops
        .iter()
        .any(|hop| hop.requires_cross_border_approval)
    {
        return Err(Deny::ZoneDenied);
    }
    path_delivery::build(&session, Instant::now()).map_err(|_| Deny::PolicyUnreadable)?;
    if fresh.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    // Bound real mint attempts before writing potentially many crossing rows.
    // Like the established cross-zone line, a failed later claim may consume
    // a requester/ingress rate token; warn-only previews do not consume one.
    if !warn_only
        && !state.relay_rate_limiter.check(
            a,
            session.relay.node_id,
            limits::MINT_RATE_LIMIT_PER_MINUTE,
        )
    {
        return Err(Deny::RateLimited);
    }
    if !warn_only {
        *charged_relay = Some(session.relay.node_id);
    }
    // Each recorded row identifies both source and target agents. A failed or
    // timed-out audit refuses the candidate before claiming or sending it.
    #[cfg(feature = "path-planner-test-support")]
    if super::candidate_test_support::take_nhop_audit_failure(&session.pair_key) {
        return Err(Deny::PolicyUnreadable);
    }
    for (i, hop) in session
        .hops
        .iter()
        .enumerate()
        .filter(|(_, h)| h.requires_cross_border_approval)
    {
        let (source_agent, source_node) = if i == 0 {
            (session.relay_agent_id, session.relay.node_id)
        } else {
            (
                session.hops[i - 1].relay_agent_id,
                session.hops[i - 1].relay.node_id,
            )
        };
        let event = PeerRelayAuditEvent {
            id: None,
            tenant_id: session.tenant_id,
            action: PeerRelayAuditAction::Mint,
            agent_id: Some(source_agent),
            user_id: None,
            requester_node_id: Some(a),
            peer_node_id: Some(b),
            relay_node_id: Some(source_node),
            serve: None,
            vni: None,
            warn_only,
            at: DateTime::now(),
            denied: None,
            reason: Some(format!("cross_border_edge:{}", hop.relay_agent_id)),
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(3), state.peer_relay_audit.record(event))
                .await,
            Ok(Ok(_))
        ) {
            return Err(Deny::PolicyUnreadable);
        }
    }
    if fresh.eligibility_epoch != state.org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    if warn_only {
        return Ok(true);
    }
    let epoch = fresh.eligibility_epoch;
    #[cfg(feature = "path-planner-test-support")]
    super::candidate_test_support::pause_nhop_preclaim_if_armed(&session.pair_key).await;
    let mut delivery = None;
    let claim = trial::claim_mint(&state.org_relay, &mut session, |candidate| {
        if epoch != state.org_relay.eligibility_generation()
            || crate::overlay::org_fallback_forced_derp(state, &candidate.pair_key)
        {
            return false;
        }
        delivery = path_delivery::build(candidate, Instant::now()).ok();
        delivery.is_some()
    });
    match claim {
        trial::MintClaim::Inserted => {}
        // A concurrent winner may have a different path or authorization;
        // leave it untouched and let the requester retry through normal gates.
        trial::MintClaim::Existing(_) => return Ok(true),
        trial::MintClaim::Full => return Err(Deny::NoRelay),
        trial::MintClaim::Rejected => return Err(Deny::PolicyUnreadable),
    }
    let delivery = delivery.ok_or(Deny::PolicyUnreadable)?;
    #[cfg(feature = "path-planner-test-support")]
    super::candidate_test_support::pause_nhop_delivery_if_armed(&session.pair_key).await;
    // Check again after claim. Revocation/send ordering across asynchronous
    // channels remains an existing wider issue and is not solved here.
    if epoch != state.org_relay.eligibility_generation() {
        state
            .org_relay
            .sessions
            .remove_if(&session.pair_key, |_, current| {
                current.vni == session.vni && current.generation == session.generation
            });
        return Err(Deny::PolicyUnreadable);
    }
    let Some(member0) = member_message(&session, 0) else {
        revoke_where(state, "nhop_delivery_expired", |current| {
            current.pair_key == session.pair_key
                && current.vni == session.vni
                && current.generation == session.generation
        })
        .await;
        return Err(Deny::PolicyUnreadable);
    };
    let Some(member1) = member_message(&session, 1) else {
        revoke_where(state, "nhop_delivery_expired", |current| {
            current.pair_key == session.pair_key
                && current.vni == session.vni
                && current.generation == session.generation
        })
        .await;
        return Err(Deny::PolicyUnreadable);
    };
    let members = [
        (session.members[0].party.node_ref.clone(), member0),
        (session.members[1].party.node_ref.clone(), member1),
    ];
    let current = || {
        epoch == state.org_relay.eligibility_generation()
            && session.bind_by > Instant::now()
            && state
                .org_relay
                .active_session(&session.pair_key)
                .is_some_and(|entry| {
                    entry.vni == session.vni && entry.generation == session.generation
                })
    };
    // No await or external IO while held. Revocation takes the same guard and
    // queues revoke frames after any already-queued delivery frames.
    let delivered = match state.org_relay.delivery_guard.lock() {
        Ok(_guard) => {
            let mut ok = true;
            #[cfg(feature = "path-planner-test-support")]
            let mut sent = 0usize;
            for (target, message) in delivery
                .relays
                .into_iter()
                .chain(delivery.bridges)
                .chain(members)
            {
                if !current() {
                    ok = false;
                    break;
                }
                // The fixture pauses precisely between the check and first
                // send to test ordering against a concurrent policy revoke.
                #[cfg(feature = "path-planner-test-support")]
                if sent == 0 {
                    super::candidate_test_support::pause_nhop_before_first_if_armed(
                        &session.pair_key,
                    );
                }
                if !push_control(state, &target, message) {
                    ok = false;
                    break;
                }
                #[cfg(feature = "path-planner-test-support")]
                {
                    sent += 1;
                }
            }
            ok && current()
        }
        Err(_) => false,
    };
    if !delivered {
        revoke_where(state, "nhop_delivery_failed", |entry| {
            entry.pair_key == session.pair_key
                && entry.vni == session.vni
                && entry.generation == session.generation
        })
        .await;
        return Err(Deny::PolicyUnreadable);
    }
    Ok(true)
}
