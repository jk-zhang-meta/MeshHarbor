// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Path selection from the live-gate snapshot. This does not reserve
//! capacity or send grants; the mint rechecks them before use.

use super::{
    OrgRelayState,
    path_candidate::PreparedGraph,
    path_search::{self, OrientedSlaPath, SearchEdgeWithSla, SearchRelayWithSla, SlaSearchPath},
};
use crate::NetworkState;
use meshharbor_remote_control::models::PeerRelayDenyReason as Deny;
use std::time::Instant;

pub(super) struct SelectedPath {
    pub prepared: PreparedGraph,
    pub path: OrientedSlaPath,
}

/// Compute both member orientations using only edges and relay identities from
/// the same previously authorized snapshot. The caller must revalidate all
/// policy, connections, capacity and endpoints at the future mint boundary.
pub(super) fn select(
    state: &NetworkState,
    prepared: PreparedGraph,
) -> Result<Option<SelectedPath>, Deny> {
    select_from_prepared(&state.org_relay, prepared, false, false)
}

/// Actual multi-hop grants require known member zones and matching end relays.
pub(super) fn select_for_mint(
    state: &NetworkState,
    prepared: PreparedGraph,
    same_zone_only: bool,
) -> Result<Option<SelectedPath>, Deny> {
    if !prepared.network_zones_active
        && (prepared.requester_zone.is_none() || prepared.peer_zone.is_none())
    {
        return Err(Deny::ZoneDenied);
    }
    select_from_prepared(&state.org_relay, prepared, true, same_zone_only)
}

/// Validate edge indexes before looking up probe provenance. The search
/// rejects invalid graphs too, but it runs after these lookups.
fn checked_edge_endpoints<'a>(
    graph: &'a super::path_graph::EdgeGraph,
    edge: &super::path_graph::GraphEdge,
) -> Result<
    (
        &'a super::path_graph::EligibleRelay,
        &'a super::path_graph::EligibleRelay,
    ),
    Deny,
> {
    let from = graph.relays.get(edge.from).ok_or(Deny::PolicyUnreadable)?;
    let to = graph.relays.get(edge.to).ok_or(Deny::PolicyUnreadable)?;
    Ok((from, to))
}

pub(super) fn select_from_prepared(
    org_relay: &OrgRelayState,
    mut prepared: PreparedGraph,
    require_ends: bool,
    same_zone_only: bool,
) -> Result<Option<SelectedPath>, Deny> {
    if prepared.eligibility_epoch != org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    // Actual multi-hop mint cannot represent implicit or unknown-zone
    // relays, and every crossing must be explicitly approved. Apply these
    // gates before ranking so an unusable path cannot hide a valid one.
    // Keep edge indexes in the filtered graph for the fresh mint checks.
    let nz_active = prepared.network_zones_active;
    let restrict_bz = prepared.restrict_ends || (require_ends && !nz_active);
    let eligible: Vec<bool> = prepared
        .graph
        .relays
        .iter()
        .map(|relay| {
            !require_ends
                || (!relay.implicit
                    && (!restrict_bz || relay.zone.is_some())
                    && (!same_zone_only
                        || nz_active
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
                && ((!restrict_bz && nz_active)
                    || relays[edge.from].zone == relays[edge.to].zone
                    || edge.cross_border)
        });
    }
    let now = Instant::now();
    let a = prepared.requester_id;
    let b = prepared.peer_id;
    // Both nodes must have current live connections and have joined. A
    // replacement connection invalidates earlier observations even before
    // its own overlay join; the final mint still must revalidate atomically.
    let cutoff = |reporter, reporter_identity, target, target_identity| {
        org_relay.probe_cutoff(reporter, reporter_identity, target, target_identity)
    };
    let mut forward = Vec::with_capacity(prepared.graph.relays.len());
    let mut reverse = Vec::with_capacity(prepared.graph.relays.len());
    let mut best_single = None;
    for (index, (relay, eligible)) in prepared.graph.relays.iter().zip(eligible).enumerate() {
        let plan = prepared
            .plans
            .get(&relay.node_id)
            .ok_or(Deny::PolicyUnreadable)?;
        let is_a = relay.node_id == a;
        let is_b = relay.node_id == b;
        let self_zero = path_search::SlaVerdict::Reachable {
            rtt_ms: 0,
            jitter_ms: 0,
            loss_permille: 0,
        };
        let a_probe = if is_a {
            self_zero
        } else {
            super::scoped_sla_verdict(
                &org_relay.probes,
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
            )
        };
        let b_probe = if is_b {
            self_zero
        } else {
            super::scoped_sla_verdict(
                &org_relay.probes,
                b,
                relay.node_id,
                &plan.endpoints,
                cutoff(b, prepared.peer_identity, relay.node_id, relay.agent_id),
                now,
            )
        };
        let load = org_relay.sessions_on_relay(relay.node_id);
        // Compare the established single-relay planner's actual SLA rank. Its
        // missing-RTT and probe-freshness semantics differ from path search.
        // This candidate cannot introduce an ineligible relay into a long path.
        // Never allow a 1-hop self-relay (`!is_a && !is_b`).
        let req_end_ok = prepared
            .requester_gateways
            .as_ref()
            .is_none_or(|gw| gw.contains(&relay.agent_id))
            && (!restrict_bz || relay.zone == prepared.requester_zone);
        let peer_end_ok = prepared
            .peer_gateways
            .as_ref()
            .is_none_or(|gw| gw.contains(&relay.agent_id))
            && (!restrict_bz || relay.zone == prepared.peer_zone);
        if !is_a && !is_b && req_end_ok && peer_end_ok {
            let (class, eff_cost, rtt, jitter_ms, loss_permille, unknown_legs, unreachable_legs) =
                super::sla_rank_key(org_relay, a, b, relay.node_id, load, now);
            let rank = (class, eff_cost, load, rtt);
            if best_single.as_ref().is_none_or(|(_, best, _)| rank < *best) {
                best_single = Some((
                    index,
                    rank,
                    (jitter_ms, loss_permille, unknown_legs, unreachable_legs),
                ));
            }
        }
        forward.push(SearchRelayWithSla {
            node_id: relay.node_id,
            ingress: (eligible && req_end_ok && !is_b).then_some(a_probe),
            exit: (eligible && peer_end_ok && !is_a).then_some(b_probe),
            load,
            is_start_member: is_a,
            is_end_member: is_b,
        });
        reverse.push(SearchRelayWithSla {
            node_id: relay.node_id,
            ingress: (eligible && peer_end_ok && !is_a).then_some(b_probe),
            exit: (eligible && req_end_ok && !is_b).then_some(a_probe),
            load,
            is_start_member: is_b,
            is_end_member: is_a,
        });
    }
    let edges: Vec<_> = prepared
        .graph
        .edges
        .iter()
        .map(|edge| {
            let (from, to) = checked_edge_endpoints(&prepared.graph, edge)?;
            Ok(SearchEdgeWithSla {
                from: edge.from,
                to: edge.to,
                verdict: super::scoped_sla_verdict(
                    &org_relay.backbone_probes,
                    from.node_id,
                    to.node_id,
                    std::slice::from_ref(&edge.endpoint),
                    cutoff(from.node_id, from.agent_id, to.node_id, to.agent_id),
                    now,
                ),
            })
        })
        .collect::<Result<Vec<_>, Deny>>()?;
    let mut chosen = path_search::shortest_either_direction_sla(&forward, &reverse, &edges)
        .map_err(|_| Deny::PolicyUnreadable)?;
    if require_ends
        && let Some((
            index,
            (class, eff_cost, load, rtt),
            (jitter_ms, effective_loss_permille, unknown_legs, unreachable_legs),
        )) = best_single
    {
        let min_multi_hops = if nz_active { 2 } else { 3 };
        // Unknown/down paths conservatively prefer the established one-relay
        // fallback. Fully measured paths compete on effective SLA cost.
        let single_wins = chosen.as_ref().is_none_or(|path| {
            path.path.relays.len() >= min_multi_hops
                && (class < path.path.class
                    || (class == path.path.class
                        && (class != 0 || eff_cost <= path.path.effective_cost_ms)))
        });
        if single_wins {
            chosen = Some(OrientedSlaPath {
                flipped: false,
                path: SlaSearchPath::single(
                    index,
                    class,
                    rtt,
                    jitter_ms,
                    effective_loss_permille,
                    load,
                    eff_cost,
                    unknown_legs,
                    unreachable_legs,
                ),
            });
        }
    }
    if prepared.eligibility_epoch != org_relay.eligibility_generation() {
        return Err(Deny::PolicyUnreadable);
    }
    if require_ends {
        explain(org_relay, &prepared, &forward, &edges, chosen.as_ref(), now);
    }
    Ok(chosen.map(|path| SelectedPath { prepared, path }))
}

/// Field diagnostic (FR-125): for a pair whose two ends are relays, log at
/// most once per pair per [`EXPLAIN_EVERY`] what the planner saw — each
/// relay's ingress/exit and load, every link with its verdict (and, when it
/// is not a measurement, the ages of the latest record and of the cutoff) —
/// and what it chose. Read-only; changes no decision.
fn explain(
    org_relay: &OrgRelayState,
    prepared: &PreparedGraph,
    forward: &[SearchRelayWithSla],
    edges: &[SearchEdgeWithSla],
    chosen: Option<&OrientedSlaPath>,
    now: Instant,
) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    const EXPLAIN_EVERY: std::time::Duration = std::time::Duration::from_secs(600);
    static LAST: OnceLock<Mutex<HashMap<(bson::oid::ObjectId, bson::oid::ObjectId), Instant>>> =
        OnceLock::new();
    let (a, b) = (prepared.requester_id, prepared.peer_id);
    let relays = &prepared.graph.relays;
    if !relays.iter().any(|r| r.node_id == a) || !relays.iter().any(|r| r.node_id == b) {
        return;
    }
    let key = if a < b { (a, b) } else { (b, a) };
    {
        let Ok(mut last) = LAST.get_or_init(Default::default).lock() else {
            return;
        };
        if last
            .get(&key)
            .is_some_and(|at| now.saturating_duration_since(*at) < EXPLAIN_EVERY)
        {
            return;
        }
        last.retain(|_, at| now.saturating_duration_since(*at) < EXPLAIN_EVERY);
        last.insert(key, now);
    }
    let short = |i: usize| {
        relays.get(i).map_or_else(
            || "?".to_owned(),
            |r| {
                let h = r.node_id.to_hex();
                h[h.len() - 6..].to_owned()
            },
        )
    };
    let verdict = |v: Option<path_search::SlaVerdict>| match v {
        None => "-".to_owned(),
        Some(path_search::SlaVerdict::Reachable {
            rtt_ms,
            jitter_ms,
            loss_permille,
        }) => format!("R{rtt_ms}/j{jitter_ms}/l{loss_permille}"),
        Some(path_search::SlaVerdict::Unknown) => "U".to_owned(),
        Some(path_search::SlaVerdict::Unreachable) => "X".to_owned(),
    };
    let relay_list: Vec<String> = forward
        .iter()
        .enumerate()
        .map(|(i, r)| {
            format!(
                "{}:in={},ex={},load={}",
                short(i),
                verdict(r.ingress),
                verdict(r.exit),
                r.load
            )
        })
        .collect();
    let edge_list: Vec<String> = edges
        .iter()
        .zip(prepared.graph.edges.iter())
        .map(|(e, g)| {
            let mut s = format!(
                "{}>{}@{}:{}",
                short(e.from),
                short(e.to),
                g.endpoint,
                verdict(Some(e.verdict))
            );
            if !matches!(e.verdict, path_search::SlaVerdict::Reachable { .. })
                && let (Some(from), Some(to)) = (relays.get(e.from), relays.get(e.to))
            {
                let cutoff =
                    org_relay.probe_cutoff(from.node_id, from.agent_id, to.node_id, to.agent_id);
                s.push_str(&format!(
                    "[{}]",
                    org_relay.backbone_record_ages(
                        from.node_id,
                        to.node_id,
                        &g.endpoint,
                        cutoff,
                        now
                    )
                ));
            }
            s
        })
        .collect();
    let chosen = chosen.map_or_else(
        || "none".to_owned(),
        |p| {
            let ids: Vec<String> = p.path.relays.iter().map(|&i| short(i)).collect();
            format!(
                "{} flipped={} class={} cost={}ms rtt={}ms",
                ids.join(">"),
                p.flipped,
                p.path.class,
                p.path.effective_cost_ms,
                p.path.rtt
            )
        },
    );
    // WARN, not INFO: production servers log at `warn`, and this line exists
    // to be read there. Remove it with the field investigation it serves.
    tracing::warn!(
        requester = %a,
        peer = %b,
        %chosen,
        relays = %relay_list.join(" "),
        links = %edge_list.join(" "),
        "org-relay: path explain (field diagnostic)"
    );
}

#[cfg(test)]
mod checked_edge_tests {
    use super::*;
    use crate::org_relay::path_graph::{EdgeGraph, EligibleRelay, GraphEdge};
    use bson::oid::ObjectId;

    #[test]
    fn malformed_edge_indexes_return_error_and_valid_edges_resolve() {
        let node_id = ObjectId::new();
        let graph = EdgeGraph {
            relays: vec![EligibleRelay {
                node_id,
                agent_id: ObjectId::new(),
                zone: None,
                bridge_ready: false,
                implicit: false,
                approved_edges: Vec::new(),
            }],
            edges: Vec::new(),
        };
        let edge = |from, to| GraphEdge {
            from,
            to,
            endpoint: "10.0.0.1:3478".into(),
            cross_border: false,
        };
        let (from, to) = checked_edge_endpoints(&graph, &edge(0, 0)).expect("valid indexes");
        assert_eq!(from.node_id, node_id);
        assert_eq!(to.node_id, node_id);
        assert!(matches!(
            checked_edge_endpoints(&graph, &edge(1, 0)),
            Err(Deny::PolicyUnreadable)
        ));
        assert!(matches!(
            checked_edge_endpoints(&graph, &edge(0, 1)),
            Err(Deny::PolicyUnreadable)
        ));
        assert!(matches!(
            checked_edge_endpoints(&graph, &edge(usize::MAX, usize::MAX)),
            Err(Deny::PolicyUnreadable)
        ));
    }

    #[test]
    fn lossy_20ms_relay_loses_to_lossless_30ms_relay_in_production_selection() {
        use super::super::Plan;
        use meshharbor_core::business_authority::BusinessZone;
        use meshharbor_remote_control::models::OverlayNode;
        use meshharbor_remote_control::signaling::RelayProbeTargetWire;
        use std::collections::HashMap;

        let org_relay = OrgRelayState::new();
        let tenant_id = ObjectId::new();
        let network_id = ObjectId::new();
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let (a_ident, b_ident) = (ObjectId::new(), ObjectId::new());
        let (r_lossy_node, r_lossy_agent) = (ObjectId::new(), ObjectId::new());
        let (r_clean_node, r_clean_agent) = (ObjectId::new(), ObjectId::new());
        let ep_lossy = "198.51.100.10:3478".to_string();
        let ep_clean = "198.51.100.20:3478".to_string();

        for (ident, node) in [
            (a_ident, a),
            (b_ident, b),
            (r_lossy_agent, r_lossy_node),
            (r_clean_agent, r_clean_node),
        ] {
            org_relay.bind_live_conn(ident, "conn-1");
            assert!(
                org_relay
                    .note_join_from_connection(ident, "conn-1", node, Default::default())
                    .is_some()
            );
        }
        let targets = [
            RelayProbeTargetWire {
                relay_node_id: r_lossy_node,
                endpoints: vec![ep_lossy.clone()],
            },
            RelayProbeTargetWire {
                relay_node_id: r_clean_node,
                endpoints: vec![ep_clean.clone()],
            },
        ];
        org_relay.offer_probes(a, &targets);
        org_relay.offer_probes(b, &targets);

        // Both members measure r_lossy answering 2/3 probes (333 permille loss) at 20 ms,
        // and r_clean answering 3/3 probes (0 permille loss) at 30 ms.
        for member in [a, b] {
            assert!(org_relay.record_probe_with_sla(
                member,
                r_lossy_node,
                ep_lossy.clone(),
                true,
                Some(20),
                Some(0),
                Some(333),
            ));
            assert!(org_relay.record_probe_with_sla(
                member,
                r_clean_node,
                ep_clean.clone(),
                true,
                Some(30),
                Some(0),
                Some(0),
            ));
        }

        let make_node = |node_id: ObjectId, agent_id: ObjectId, ip: &str| -> OverlayNode {
            let mut n: OverlayNode = serde_json::from_value(serde_json::json!({
                "_id": node_id,
                "tenant_id": tenant_id,
                "node_ref": { "kind": "agent", "id": agent_id },
                "network_id": network_id,
                "machine_id": format!("m-{node_id}"),
                "name": format!("n-{node_id}"),
                "overlay_ip": ip,
                "wg_public_key": "k",
                "status": "online",
                "last_seen_at": bson::DateTime::now(),
                "created_at": bson::DateTime::now(),
                "updated_at": bson::DateTime::now(),
            }))
            .expect("valid OverlayNode");
            n.id = Some(node_id);
            n
        };

        let build_prepared = || {
            let mut plans = HashMap::new();
            plans.insert(
                r_lossy_node,
                Plan {
                    relay: make_node(r_lossy_node, r_lossy_agent, "100.64.0.10"),
                    relay_agent_id: r_lossy_agent,
                    relay_port: crate::org_relay::limits::DEFAULT_RELAY_PORT,
                    endpoints: vec![ep_lossy.clone()],
                    backbone_edges: Vec::new(),
                    implicit: false,
                },
            );
            plans.insert(
                r_clean_node,
                Plan {
                    relay: make_node(r_clean_node, r_clean_agent, "100.64.0.20"),
                    relay_agent_id: r_clean_agent,
                    relay_port: crate::org_relay::limits::DEFAULT_RELAY_PORT,
                    endpoints: vec![ep_clean.clone()],
                    backbone_edges: Vec::new(),
                    implicit: false,
                },
            );
            PreparedGraph {
                graph: EdgeGraph {
                    relays: vec![
                        EligibleRelay {
                            node_id: r_lossy_node,
                            agent_id: r_lossy_agent,
                            zone: Some(BusinessZone::NonMainland),
                            bridge_ready: false,
                            implicit: false,
                            approved_edges: Vec::new(),
                        },
                        EligibleRelay {
                            node_id: r_clean_node,
                            agent_id: r_clean_agent,
                            zone: Some(BusinessZone::NonMainland),
                            bridge_ready: false,
                            implicit: false,
                            approved_edges: Vec::new(),
                        },
                    ],
                    edges: Vec::new(),
                },
                requester_id: a,
                peer_id: b,
                requester_identity: a_ident,
                peer_identity: b_ident,
                plans,
                requester_zone: Some(BusinessZone::NonMainland),
                peer_zone: Some(BusinessZone::NonMainland),
                restrict_ends: true,
                network_zones_active: false,
                network_zones_backbone_only: false,
                requester_gateways: None,
                peer_gateways: None,
                eligibility_epoch: org_relay.eligibility_generation(),
                warn_only: false,
            }
        };

        // Graph search (`require_ends = false`) selects lossless 30 ms relay (index 1).
        let sel_graph = select_from_prepared(&org_relay, build_prepared(), false, false)
            .expect("selection succeeds")
            .expect("a relay is selected");
        assert_eq!(sel_graph.path.path.relays, vec![1]);
        assert_eq!(sel_graph.path.path.effective_loss_permille, 0);

        // Mint selection (`require_ends = true`, exercising `best_single` too) also selects index 1.
        let sel_mint = select_from_prepared(&org_relay, build_prepared(), true, false)
            .expect("mint selection succeeds")
            .expect("a relay is selected");
        assert_eq!(sel_mint.path.path.relays, vec![1]);
        assert_eq!(sel_mint.path.path.effective_loss_permille, 0);
    }
}
