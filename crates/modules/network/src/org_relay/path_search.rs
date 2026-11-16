// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Directed relay-path search over a graph already authorized by the caller.
//!
//! The caller must build the graph from same-tenant relays, per-member grants,
//! current zone and
//! backbone policy, and approved edges. Search alone grants no authority.

use super::ProbeVerdict;
use bson::oid::ObjectId;
use meshharbor_remote_control::models::peer_relay_limits::MAX_SESSIONS_PER_RELAY;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

/// Free-flow relay load threshold (`12.5%` of [`MAX_SESSIONS_PER_RELAY`]):
/// below or at this session count a relay adds zero congestion latency penalty.
pub(super) const FREE_LOAD_SESSIONS: usize = MAX_SESSIONS_PER_RELAY / 8;

/// Weight on RTT jitter (ms) in effective SLA path cost (`rtt + 2 * jitter + ...`).
pub(super) const JITTER_COST_WEIGHT: u128 = 2;

/// Non-linear convex queueing/saturation penalty (in ms) for a relay carrying
/// `load` sessions against [`MAX_SESSIONS_PER_RELAY`] (normalized by utilization):
/// - `<= 12.5%` (`0..=FREE_LOAD_SESSIONS`): `0 ms` (free-flow regime; ties still break
///   on convex load concentration before raw load and hop count);
/// - `12.5%..=75%`: smooth quadratic ramp (`2 ms` at 25%, `18 ms` at 50%, `50 ms` at 75%);
/// - `> 75%` (approaching saturation): adds a steep convex saturation knee
///   (`104 ms` at 87.5%, `156 ms` at 93.75%, `226 ms` at 100%, capped smoothly so
///   `usize::MAX` never overflows).
pub(super) fn load_congestion_penalty_ms(load: usize) -> u128 {
    if load <= FREE_LOAD_SESSIONS {
        return 0;
    }
    let cap = MAX_SESSIONS_PER_RELAY.max(1) as u128;
    let cap_sq = cap * cap;
    let excess = (load - FREE_LOAD_SESSIONS).min(MAX_SESSIONS_PER_RELAY) as u128;
    let base_convex = (excess * excess * 128) / cap_sq;
    let sat_knee = (MAX_SESSIONS_PER_RELAY * 3) / 4;
    let sat_convex = if load > sat_knee {
        let over = (load - sat_knee).min(MAX_SESSIONS_PER_RELAY / 2) as u128;
        (over * over * 2048) / cap_sq
    } else {
        0
    };
    base_convex + sat_convex
}

/// Convex per-relay tie-breaking weight (`min(load, 1_000_000)^2`), preferring
/// balanced load across relays over concentrating sessions on one node.
fn convex_load_units(load: usize) -> u128 {
    let c = load.min(1_000_000) as u128;
    c * c
}

/// Additive log-survival loss penalty in micro-ms (`1_000` units = `1 ms`):
/// `-ln(1 - p) * 1_000_000`, where `p = loss_permille / 1000`.
///
/// Because `-ln(prod_i (1 - p_i)) == sum_i (-ln(1 - p_i))`, summing this non-negative
/// integer cost across hops preserves Bellman's Principle of Optimality in single-label
/// Dijkstra while modeling exact multi-hop compounding packet loss (~`10 ms` per `1%`
/// loss at low loss, escalating super-linearly as survival probability drops).
pub(super) fn leg_loss_penalty_us(loss_permille: u16) -> u128 {
    if loss_permille == 0 {
        return 0;
    }
    let p = f64::from(loss_permille.min(999)) / 1000.0;
    (-((1.0 - p).ln()) * 1_000_000.0).round() as u128
}

/// Evaluate an ordered sequence of `SlaVerdict` legs and per-relay loads,
/// returning `(class, effective_cost_ms, raw_rtt_ms, jitter_ms, effective_loss_permille, unknown_legs, unreachable_legs)`.
pub(super) fn evaluate_sla_legs(
    legs: impl IntoIterator<Item = SlaVerdict>,
    relay_loads: impl IntoIterator<Item = usize>,
) -> (u8, u128, u128, u128, u16, u128, u128) {
    let mut class = 0u8;
    let mut rtt = 0u128;
    let mut jitter_ms = 0u128;
    let mut eff_us = 0u128;
    let mut unknown_legs = 0u128;
    let mut unreachable_legs = 0u128;
    let mut reachable_losses = Vec::new();
    for v in legs {
        let (c, r, j, l) = v.leg_metrics();
        class = class.max(c);
        match c {
            0 => {
                rtt += u128::from(r);
                jitter_ms += u128::from(j);
                reachable_losses.push(l);
                eff_us += u128::from(r) * 1_000
                    + JITTER_COST_WEIGHT * u128::from(j) * 1_000
                    + leg_loss_penalty_us(l);
            }
            1 => unknown_legs += 1,
            _ => unreachable_legs += 1,
        }
    }
    let mut load_congestion_us = 0u128;
    for load in relay_loads {
        load_congestion_us += load_congestion_penalty_ms(load) * 1_000;
    }
    let total_eff_us = if class == 0 || !reachable_losses.is_empty() {
        eff_us + load_congestion_us
    } else {
        load_congestion_us
    };
    let effective_cost_ms = (total_eff_us + 500) / 1_000;
    let effective_loss_permille = if unreachable_legs > 0 {
        1000
    } else {
        compounding_loss_permille(reachable_losses)
    };
    (
        class,
        effective_cost_ms,
        rtt,
        jitter_ms,
        effective_loss_permille,
        unknown_legs,
        unreachable_legs,
    )
}

/// End-to-end compounded packet loss in permille (`0..=1000`) across independent
/// legs: `round(1000 * (1 - prod_i (1 - p_i)))`.
pub(super) fn compounding_loss_permille(legs: impl IntoIterator<Item = u16>) -> u16 {
    let survival = legs.into_iter().fold(1.0_f64, |acc, permille| {
        acc * (1.0 - f64::from(permille.min(1000)) / 1000.0)
    });
    ((1.0 - survival).clamp(0.0, 1.0) * 1000.0).round() as u16
}

/// Multi-metric SLA standing for one member-to-relay or relay-to-relay leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SlaVerdict {
    /// Measured reachable leg (`loss_permille >= 1000` is classified as unreachable).
    Reachable {
        rtt_ms: u32,
        jitter_ms: u32,
        loss_permille: u16,
    },
    Unknown,
    Unreachable,
}

impl From<ProbeVerdict> for SlaVerdict {
    fn from(v: ProbeVerdict) -> Self {
        match v {
            ProbeVerdict::Reachable(rtt_ms) => SlaVerdict::Reachable {
                rtt_ms,
                jitter_ms: 0,
                loss_permille: 0,
            },
            ProbeVerdict::Unknown => SlaVerdict::Unknown,
            ProbeVerdict::Unreachable => SlaVerdict::Unreachable,
        }
    }
}

impl SlaVerdict {
    fn leg_metrics(self) -> (u8, u32, u32, u16) {
        match self {
            SlaVerdict::Reachable {
                rtt_ms,
                jitter_ms,
                loss_permille,
            } if loss_permille < 1000 => (0, rtt_ms, jitter_ms, loss_permille),
            SlaVerdict::Reachable { .. } | SlaVerdict::Unreachable => (2, 0, 0, 1000),
            SlaVerdict::Unknown => (1, 0, 0, 0),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(super) struct SearchRelay {
    /// Stable overlay identity, matching the authorized graph index.
    pub node_id: ObjectId,
    pub ingress: Option<ProbeVerdict>,
    pub exit: Option<ProbeVerdict>,
    pub load: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SearchRelayWithSla {
    /// Stable overlay identity, matching the authorized graph index.
    pub node_id: ObjectId,
    pub ingress: Option<SlaVerdict>,
    pub exit: Option<SlaVerdict>,
    pub load: usize,
}

impl From<SearchRelay> for SearchRelayWithSla {
    fn from(r: SearchRelay) -> Self {
        Self {
            node_id: r.node_id,
            ingress: r.ingress.map(SlaVerdict::from),
            exit: r.exit.map(SlaVerdict::from),
            load: r.load,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(super) struct SearchEdge {
    pub from: usize,
    pub to: usize,
    pub verdict: ProbeVerdict,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SearchEdgeWithSla {
    pub from: usize,
    pub to: usize,
    pub verdict: SlaVerdict,
}

impl From<SearchEdge> for SearchEdgeWithSla {
    fn from(e: SearchEdge) -> Self {
        Self {
            from: e.from,
            to: e.to,
            verdict: SlaVerdict::from(e.verdict),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SearchPath {
    pub relays: Vec<usize>,
    /// Indexes in the caller's edge slice, in order. Parallel edges stay distinct.
    pub edges: Vec<usize>,
    pub class: u8,
    pub rtt: u128,
    pub load: u128,
    pub unknown_legs: u128,
    pub unreachable_legs: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SlaSearchPath {
    pub relays: Vec<usize>,
    /// Indexes in the caller's edge slice, in order. Parallel edges stay distinct.
    pub edges: Vec<usize>,
    pub class: u8,
    /// Sum of raw propagation/echo RTTs across reachable legs (ms).
    pub rtt: u128,
    /// Sum of RTT jitter across reachable legs (ms).
    pub jitter_ms: u128,
    /// End-to-end compounded packet loss across reachable legs in permille (`0..=1000`).
    pub effective_loss_permille: u16,
    /// Sum of raw session loads across relays on the path.
    pub load: u128,
    /// Multi-metric effective SLA cost (ms):
    /// `rtt + 2 * jitter_ms + compounding_loss_penalty_ms + sum(load_congestion_penalty_ms)`.
    pub effective_cost_ms: u128,
    pub unknown_legs: u128,
    pub unreachable_legs: u128,
    cost_key: Cost,
}

#[allow(clippy::too_many_arguments)]
impl SlaSearchPath {
    pub(super) fn single(
        relay_index: usize,
        class: u8,
        rtt: u128,
        jitter_ms: u128,
        effective_loss_permille: u16,
        load: usize,
        effective_cost_ms: u128,
        unknown_legs: u128,
        unreachable_legs: u128,
    ) -> Self {
        let eff_us = effective_cost_ms * 1_000;
        let convex = convex_load_units(load);
        let raw_load = load as u128;
        let cost_key = if class == 0 {
            (eff_us, convex, raw_load, 1, rtt, jitter_ms)
        } else {
            (unreachable_legs, 1, unknown_legs, eff_us, convex, raw_load)
        };
        Self {
            relays: vec![relay_index],
            edges: Vec::new(),
            class,
            rtt,
            jitter_ms,
            effective_loss_permille,
            load: raw_load,
            effective_cost_ms,
            unknown_legs,
            unreachable_legs,
            cost_key,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn into_search_path(self) -> SearchPath {
        SearchPath {
            relays: self.relays,
            edges: self.edges,
            class: self.class,
            rtt: self.rtt,
            load: self.load,
            unknown_legs: self.unknown_legs,
            unreachable_legs: self.unreachable_legs,
        }
    }
}

/// A common ordering for forward and reverse searches. `flipped` means the
/// second member is the ingress. A tie keeps the forward orientation.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct OrientedPath {
    pub flipped: bool,
    pub path: SearchPath,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct OrientedSlaPath {
    pub flipped: bool,
    pub path: SlaSearchPath,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SearchPath {
    /// Effective congestion-aware cost (ms) using per-relay loads from `relays`
    /// when provided, or Jensen's even-split bound over `self.load` otherwise.
    pub(super) fn effective_cost_ms(&self, relays: Option<&[SearchRelay]>) -> u128 {
        let congestion = match relays {
            Some(slice) => self
                .relays
                .iter()
                .filter_map(|&idx| slice.get(idx))
                .map(|r| load_congestion_penalty_ms(r.load))
                .sum(),
            None if !self.relays.is_empty() => {
                let hops = self.relays.len() as u128;
                let avg = usize::try_from(self.load / hops).unwrap_or(usize::MAX);
                hops * load_congestion_penalty_ms(avg)
            }
            None => 0,
        };
        self.rtt + congestion
    }

    fn rank_key(&self) -> (u8, u128, u128, u128, u128, u128) {
        let hops = self.relays.len() as u128;
        let eff = self.effective_cost_ms(None);
        if self.class == 0 {
            (0, eff, self.load, hops, self.rtt, 0)
        } else {
            (
                self.class,
                self.unreachable_legs,
                hops,
                self.unknown_legs,
                eff,
                self.load,
            )
        }
    }
}

/// Both inputs must describe the same relays in the same order; only the
/// member-to-relay probe legs may differ. Directed backbone edges do not
/// reverse merely because the requesting member changes.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn shortest_either_direction(
    forward: &[SearchRelay],
    reverse: &[SearchRelay],
    edges: &[SearchEdge],
) -> Result<Option<OrientedPath>, InvalidGraph> {
    let fwd_sla: Vec<SearchRelayWithSla> = forward.iter().copied().map(Into::into).collect();
    let rev_sla: Vec<SearchRelayWithSla> = reverse.iter().copied().map(Into::into).collect();
    let edge_sla: Vec<SearchEdgeWithSla> = edges.iter().copied().map(Into::into).collect();
    Ok(
        shortest_either_direction_sla(&fwd_sla, &rev_sla, &edge_sla)?.map(|o| OrientedPath {
            flipped: o.flipped,
            path: o.path.into_search_path(),
        }),
    )
}

/// Multi-metric SLA counterpart to [`shortest_either_direction`], incorporating
/// RTT, jitter, compounding multi-hop loss, and non-linear relay saturation.
pub(super) fn shortest_either_direction_sla(
    forward: &[SearchRelayWithSla],
    reverse: &[SearchRelayWithSla],
    edges: &[SearchEdgeWithSla],
) -> Result<Option<OrientedSlaPath>, InvalidGraph> {
    if forward.len() != reverse.len()
        || forward
            .iter()
            .zip(reverse)
            .any(|(a, b)| a.node_id != b.node_id || a.load != b.load)
    {
        return Err(InvalidGraph);
    }
    let a = shortest_sla(forward, edges)?;
    let b = shortest_sla(reverse, edges)?;
    Ok(match (a, b) {
        (None, None) => None,
        (Some(path), None) => Some(OrientedSlaPath {
            flipped: false,
            path,
        }),
        (None, Some(path)) => Some(OrientedSlaPath {
            flipped: true,
            path,
        }),
        (Some(a), Some(b)) if (a.class, a.cost_key) <= (b.class, b.cost_key) => {
            Some(OrientedSlaPath {
                flipped: false,
                path: a,
            })
        }
        (Some(_), Some(b)) => Some(OrientedSlaPath {
            flipped: true,
            path: b,
        }),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct InvalidGraph;

type Cost = (u128, u128, u128, u128, u128, u128);

/// Search without a fixed hop limit over relays and edges authorized by the
/// caller. Invalid edge indexes reject the whole graph.
///
/// Paths first minimize the worst leg class. With all legs measured reachable,
/// prefer multi-metric effective SLA cost (`rtt + 2*jitter + compounding_loss +
/// load_congestion_penalty`), then convex load concentration, total load, and
/// relay count. If any leg is unknown or unreachable, prefer fewer unreachable
/// legs, then fewer relays, fewer unknown legs, known effective SLA cost, and
/// load.
///
/// Class thresholds are searched separately: a later worse leg can equalize
/// prefix classes. Inside a threshold every cost component adds non-negative
/// exact amounts (including `-ln(1 - loss)` for compounding multi-hop packet
/// loss and per-relay convex saturation), so Dijkstra's single-label ordering
/// is exact.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn shortest(
    relays: &[SearchRelay],
    edges: &[SearchEdge],
) -> Result<Option<SearchPath>, InvalidGraph> {
    let sla_relays: Vec<SearchRelayWithSla> = relays.iter().copied().map(Into::into).collect();
    let sla_edges: Vec<SearchEdgeWithSla> = edges.iter().copied().map(Into::into).collect();
    Ok(shortest_sla(&sla_relays, &sla_edges)?.map(SlaSearchPath::into_search_path))
}

/// Multi-metric SLA Dijkstra search over relays and directed backbone edges.
pub(super) fn shortest_sla(
    relays: &[SearchRelayWithSla],
    edges: &[SearchEdgeWithSla],
) -> Result<Option<SlaSearchPath>, InvalidGraph> {
    fn step(threshold: u8, verdict: SlaVerdict, relay_load: Option<usize>) -> Cost {
        let (class, rtt_ms, jitter_ms, loss_permille) = verdict.leg_metrics();
        let hops = u128::from(relay_load.is_some());
        let raw_load = relay_load.unwrap_or_default() as u128;
        let convex_load = relay_load.map_or(0, convex_load_units);
        let congestion_us = relay_load.map_or(0, load_congestion_penalty_ms) * 1_000;
        let leg_sla_us = if class == 0 {
            u128::from(rtt_ms) * 1_000
                + JITTER_COST_WEIGHT * u128::from(jitter_ms) * 1_000
                + leg_loss_penalty_us(loss_permille)
        } else {
            0
        };
        let eff_us = leg_sla_us + congestion_us;
        if threshold == 0 {
            (
                eff_us,
                convex_load,
                raw_load,
                hops,
                u128::from(rtt_ms),
                u128::from(jitter_ms),
            )
        } else {
            (
                u128::from(class == 2),
                hops,
                u128::from(class == 1),
                eff_us,
                convex_load,
                raw_load,
            )
        }
    }
    fn add(a: Cost, b: Cost) -> Cost {
        (
            a.0 + b.0,
            a.1 + b.1,
            a.2 + b.2,
            a.3 + b.3,
            a.4 + b.4,
            a.5 + b.5,
        )
    }
    let mut identities = HashSet::new();
    if relays.iter().any(|relay| !identities.insert(relay.node_id)) {
        return Err(InvalidGraph);
    }
    let mut adjacency = vec![Vec::new(); relays.len()];
    for (index, edge) in edges.iter().enumerate() {
        if edge.from >= relays.len() || edge.to >= relays.len() {
            return Err(InvalidGraph);
        }
        adjacency[edge.from].push(index);
    }
    for threshold in 0..=2 {
        let mut costs: Vec<Option<Cost>> = vec![None; relays.len()];
        let mut previous: Vec<Option<(usize, usize)>> = vec![None; relays.len()];
        let mut queue = BinaryHeap::new();
        for (i, relay) in relays.iter().enumerate() {
            let Some(verdict) = relay.ingress else {
                continue;
            };
            if verdict.leg_metrics().0 <= threshold {
                let cost = step(threshold, verdict, Some(relay.load));
                costs[i] = Some(cost);
                queue.push(Reverse((cost, i)));
            }
        }
        let mut best: Option<(Cost, usize)> = None;
        while let Some(Reverse((cost, node))) = queue.pop() {
            if costs[node] != Some(cost) {
                continue;
            }
            if let Some(verdict) = relays[node].exit
                && verdict.leg_metrics().0 <= threshold
            {
                let candidate = (add(cost, step(threshold, verdict, None)), node);
                if best.is_none_or(|current| candidate < current) {
                    best = Some(candidate);
                }
            }
            for &edge_index in &adjacency[node] {
                let edge = &edges[edge_index];
                if edge.verdict.leg_metrics().0 > threshold {
                    continue;
                }
                let next = add(
                    cost,
                    step(threshold, edge.verdict, Some(relays[edge.to].load)),
                );
                if costs[edge.to].is_none_or(|old| next < old) {
                    costs[edge.to] = Some(next);
                    previous[edge.to] = Some((node, edge_index));
                    queue.push(Reverse((next, edge.to)));
                }
            }
        }
        if let Some((cost, mut node)) = best {
            let mut path = vec![node];
            let mut used_edges = Vec::new();
            while let Some((prev, edge_index)) = previous[node] {
                used_edges.push(edge_index);
                node = prev;
                path.push(node);
            }
            path.reverse();
            used_edges.reverse();

            let mut rtt = 0u128;
            let mut jitter_ms = 0u128;
            let mut load = 0u128;
            let mut unknown_legs = 0u128;
            let mut unreachable_legs = 0u128;
            let mut reachable_losses = Vec::with_capacity(used_edges.len() + 2);
            let mut observe_leg = |v: SlaVerdict| {
                let (c, r, j, l) = v.leg_metrics();
                match c {
                    0 => {
                        rtt += u128::from(r);
                        jitter_ms += u128::from(j);
                        reachable_losses.push(l);
                    }
                    1 => unknown_legs += 1,
                    _ => unreachable_legs += 1,
                }
            };
            if let Some(ing) = relays[path[0]].ingress {
                observe_leg(ing);
            }
            for (hop_idx, &relay_idx) in path.iter().enumerate() {
                load += relays[relay_idx].load as u128;
                if hop_idx > 0 {
                    observe_leg(edges[used_edges[hop_idx - 1]].verdict);
                }
            }
            if let Some(ex) = relays[*path.last().unwrap()].exit {
                observe_leg(ex);
            }
            let effective_loss_permille = if unreachable_legs > 0 {
                1000
            } else {
                compounding_loss_permille(reachable_losses)
            };
            let eff_us = if threshold == 0 { cost.0 } else { cost.3 };
            let effective_cost_ms = (eff_us + 500) / 1_000;
            return Ok(Some(SlaSearchPath {
                relays: path,
                edges: used_edges,
                class: threshold,
                rtt,
                jitter_ms,
                effective_loss_permille,
                load,
                effective_cost_ms,
                unknown_legs,
                unreachable_legs,
                cost_key: cost,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProbeVerdict::{Reachable as R, Unknown as U, Unreachable as X};

    fn relay(
        ingress: Option<ProbeVerdict>,
        exit: Option<ProbeVerdict>,
        load: usize,
    ) -> SearchRelay {
        SearchRelay {
            node_id: ObjectId::new(),
            ingress,
            exit,
            load,
        }
    }
    fn edge(from: usize, to: usize, verdict: ProbeVerdict) -> SearchEdge {
        SearchEdge { from, to, verdict }
    }

    #[test]
    fn later_unknown_equalizes_prefix_classes_without_losing_shorter_path() {
        let nodes = [
            relay(Some(R(100)), None, 0),
            relay(Some(U), None, 0),
            relay(None, None, 0),
            relay(None, Some(U), 0),
        ];
        let edges = [edge(0, 2, R(0)), edge(2, 3, R(0)), edge(1, 3, R(0))];
        let result = shortest(&nodes, &edges).unwrap().unwrap();
        assert_eq!(result.relays, [1, 3]);
        assert_eq!((result.class, result.rtt), (1, 0));
    }

    #[test]
    fn uncertain_paths_prefer_fewer_failures_then_hops() {
        let nodes = [
            relay(Some(U), Some(U), 100),
            relay(Some(U), None, 0),
            relay(None, None, 0),
            relay(None, Some(U), 0),
        ];
        let edges = [edge(1, 2, U), edge(2, 3, U)];
        assert_eq!(shortest(&nodes, &edges).unwrap().unwrap().relays, [0]);
        let nodes = [
            relay(Some(X), None, 0),
            relay(None, Some(R(0)), 0),
            relay(None, Some(R(0)), 0),
        ];
        let edges = [edge(0, 1, R(500)), edge(0, 2, X)];
        let path = shortest(&nodes, &edges).unwrap().unwrap();
        assert_eq!(path.relays, [0, 1]);
        assert_eq!(path.unreachable_legs, 1);
    }

    #[test]
    fn long_directed_chain_and_cycle_preserve_order_and_never_repeat() {
        let mut nodes: Vec<_> = (0..7).map(|_| relay(None, None, 1)).collect();
        nodes[0].ingress = Some(R(1));
        nodes[6].exit = Some(R(1));
        let mut edges: Vec<_> = (0..6).map(|i| edge(i, i + 1, R(2))).collect();
        edges.push(edge(4, 1, R(0)));
        let result = shortest(&nodes, &edges).unwrap().unwrap();
        assert_eq!(result.relays, [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(result.edges, [0, 1, 2, 3, 4, 5]);
        assert_eq!((result.class, result.rtt, result.load), (0, 14, 7));
        assert_eq!(shortest(&nodes, &edges[6..]).unwrap(), None);
    }

    #[test]
    fn class_precedes_rtt_then_load_then_hops() {
        let nodes = [
            relay(Some(R(50)), Some(R(50)), 3),
            relay(Some(U), Some(R(0)), 0),
            relay(Some(R(50)), Some(R(50)), 1),
            relay(Some(X), Some(R(0)), 0),
        ];
        let best = shortest(&nodes, &[]).unwrap().unwrap();
        assert_eq!(
            (best.relays, best.class, best.rtt, best.load),
            (vec![2], 0, 100, 1)
        );
        let unknown = [relay(Some(U), Some(R(0)), 0), relay(Some(X), Some(R(0)), 0)];
        assert_eq!(shortest(&unknown, &[]).unwrap().unwrap().class, 1);
    }

    #[test]
    fn exact_large_rtt_does_not_equalize_prefixes_and_lose_load_tiebreak() {
        // Within free-flow capacity (`<= FREE_LOAD_SESSIONS`), a 1 ms advantage at
        // `u32::MAX` never saturates/equalizes and still wins despite higher load.
        let nodes = [
            relay(Some(R(u32::MAX - 1)), None, FREE_LOAD_SESSIONS),
            relay(Some(R(u32::MAX)), None, 0),
            relay(None, Some(R(u32::MAX)), 0),
        ];
        let edges = [edge(0, 2, R(1)), edge(1, 2, R(1))];
        let path = shortest(&nodes, &edges).unwrap().unwrap();
        assert_eq!(path.relays, [0, 2]);
        assert_eq!(path.rtt, 2 * u128::from(u32::MAX));

        // Even at over-saturation (`load = 100`), a large RTT advantage exceeding the
        // bounded congestion penalty (`1000 ms > 640 ms`) is preserved without u32 overflow.
        let saturated_faster = [
            relay(Some(R(u32::MAX - 1_000)), None, 100),
            relay(Some(R(u32::MAX)), None, 0),
            relay(None, Some(R(u32::MAX)), 0),
        ];
        let edges_1000 = [edge(0, 2, R(1_000)), edge(1, 2, R(1_000))];
        let path = shortest(&saturated_faster, &edges_1000).unwrap().unwrap();
        assert_eq!(path.relays, [0, 2]);
        assert_eq!(path.rtt, 2 * u128::from(u32::MAX));
    }

    #[test]
    fn agrees_with_exhaustive_simple_paths_across_probe_classes() {
        let nodes = [
            relay(Some(R(3)), None, 4),
            relay(Some(U), None, 1),
            relay(None, None, 2),
            relay(None, Some(U), 1),
        ];
        let pairs = [(0, 2), (1, 2), (2, 3), (0, 3), (1, 3), (2, 0), (3, 1)];
        let verdicts = [R(2), U, X];
        for mut case in 0..3usize.pow(pairs.len() as u32) {
            let edges: Vec<_> = pairs
                .iter()
                .map(|&(a, b)| {
                    let verdict = verdicts[case % 3];
                    case /= 3;
                    edge(a, b, verdict)
                })
                .collect();
            check_against_oracle(&nodes, &edges);
        }
    }

    #[test]
    fn later_cheaper_parallel_edge_is_returned() {
        let nodes = [relay(Some(R(0)), None, 0), relay(None, Some(R(0)), 0)];
        let edges = [edge(0, 1, R(10)), edge(0, 1, R(1)), edge(0, 0, R(0))];
        let path = shortest(&nodes, &edges).unwrap().unwrap();
        assert_eq!(path.relays, [0, 1]);
        assert_eq!(path.edges, [1]);
        assert_eq!(path.rtt, 1);
    }

    // This oracle enumerates simple paths and scores them only after a path
    // ends; it does not share the production queue or incremental cost code.
    type Score = (u8, u128, u128, u128, u128, u128, u128);
    fn oracle_key(legs: &[ProbeVerdict], loads: &[usize]) -> Score {
        let down = legs.iter().filter(|v| matches!(v, X)).count() as u128;
        let unknown = legs.iter().filter(|v| matches!(v, U)).count() as u128;
        let rtt: u128 = legs
            .iter()
            .map(|v| match v {
                R(ms) => u128::from(*ms),
                _ => 0,
            })
            .sum();
        let raw_load: u128 = loads.iter().map(|&l| l as u128).sum();
        let convex_load: u128 = loads
            .iter()
            .map(|&l| {
                let c = l.min(1_000_000) as u128;
                c * c
            })
            .sum();
        let congestion_ms: u128 = loads.iter().map(|&l| load_congestion_penalty_ms(l)).sum();
        let eff_us = (rtt + congestion_ms) * 1_000;
        let hops = loads.len() as u128;
        if down > 0 {
            (2, down, hops, unknown, eff_us, convex_load, raw_load)
        } else if unknown > 0 {
            (1, 0, hops, unknown, eff_us, convex_load, raw_load)
        } else {
            (0, eff_us, convex_load, raw_load, hops, rtt, 0)
        }
    }
    fn brute(
        node: usize,
        seen: u64,
        nodes: &[SearchRelay],
        edges: &[SearchEdge],
        legs: &mut Vec<ProbeVerdict>,
        loads: &mut Vec<usize>,
        best: &mut Option<Score>,
    ) {
        if let Some(exit) = nodes[node].exit {
            legs.push(exit);
            let candidate = oracle_key(legs, loads);
            if best.is_none_or(|old| candidate < old) {
                *best = Some(candidate);
            }
            legs.pop();
        }
        for e in edges
            .iter()
            .filter(|e| e.from == node && seen & (1 << e.to) == 0)
        {
            legs.push(e.verdict);
            loads.push(nodes[e.to].load);
            brute(e.to, seen | (1 << e.to), nodes, edges, legs, loads, best);
            loads.pop();
            legs.pop();
        }
    }
    fn check_against_oracle(nodes: &[SearchRelay], edges: &[SearchEdge]) -> Option<SearchPath> {
        let mut expected = None;
        for (i, node) in nodes.iter().enumerate() {
            if let Some(ingress) = node.ingress {
                brute(
                    i,
                    1 << i,
                    nodes,
                    edges,
                    &mut vec![ingress],
                    &mut vec![node.load],
                    &mut expected,
                );
            }
        }
        let result = shortest(nodes, edges).unwrap();
        if let Some(path) = &result {
            assert!(!path.relays.is_empty());
            assert_eq!(path.edges.len() + 1, path.relays.len());
            let mut seen = 0u64;
            let mut legs = vec![nodes[path.relays[0]].ingress.unwrap()];
            let mut loads = Vec::new();
            let mut load = 0u128;
            for (i, &node) in path.relays.iter().enumerate() {
                assert_eq!(seen & (1 << node), 0, "relay repeats");
                seen |= 1 << node;
                loads.push(nodes[node].load);
                load += nodes[node].load as u128;
                if i > 0 {
                    let e = edges[path.edges[i - 1]];
                    assert_eq!((e.from, e.to), (path.relays[i - 1], node));
                    legs.push(e.verdict);
                }
            }
            legs.push(nodes[*path.relays.last().unwrap()].exit.unwrap());
            let actual = oracle_key(&legs, &loads);
            assert_eq!(Some(actual), expected, "nodes={nodes:?} edges={edges:?}");
            let down = legs.iter().filter(|v| matches!(v, X)).count() as u128;
            let unknown = legs.iter().filter(|v| matches!(v, U)).count() as u128;
            let rtt: u128 = legs
                .iter()
                .map(|v| match v {
                    R(ms) => u128::from(*ms),
                    _ => 0,
                })
                .sum();
            assert_eq!(
                (
                    path.class,
                    path.unreachable_legs,
                    path.unknown_legs,
                    path.rtt,
                    path.load
                ),
                (actual.0, down, unknown, rtt, load)
            );
        } else {
            assert_eq!(expected, None, "nodes={nodes:?} edges={edges:?}");
        }
        result
    }
    #[test]
    fn varied_graphs_match_independent_oracle_and_reconstructed_route() {
        fn next(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }
        fn pick(state: &mut u64) -> ProbeVerdict {
            match next(state) % 6 {
                0 => R(0),
                1 => R(1),
                2 => R(20),
                3 => R(u32::MAX),
                4 => U,
                _ => X,
            }
        }
        let mut state = 0x9e3779b97f4a7c15;
        let mut classes = [0usize; 3];
        let mut missing = 0;
        let mut zero_load = 0;
        for _ in 0..1024 {
            let n = 1 + (next(&mut state) % 5) as usize;
            let mut nodes = Vec::new();
            for _ in 0..n {
                let ingress = (!next(&mut state).is_multiple_of(3)).then(|| pick(&mut state));
                let exit = (!next(&mut state).is_multiple_of(3)).then(|| pick(&mut state));
                let load = match next(&mut state) % 5 {
                    0 => usize::MAX,
                    n => (n - 1) as usize,
                };
                if load == 0 {
                    zero_load += 1;
                }
                nodes.push(relay(ingress, exit, load));
            }
            let edge_count = (next(&mut state) % 13) as usize;
            let mut edges = Vec::new();
            for _ in 0..edge_count {
                let from = (next(&mut state) % n as u64) as usize;
                let to = (next(&mut state) % n as u64) as usize;
                edges.push(edge(from, to, pick(&mut state)));
            }
            match check_against_oracle(&nodes, &edges) {
                Some(path) => classes[path.class as usize] += 1,
                None => missing += 1,
            }
        }
        assert!(classes.iter().all(|n| *n > 0), "classes: {classes:?}");
        assert!(missing > 0 && zero_load > 0);
    }
    #[test]
    fn zero_cost_cycle_and_parallel_classes_are_handled() {
        let nodes = [relay(Some(R(0)), None, 0), relay(None, Some(R(0)), 0)];
        let edges = [
            edge(0, 1, U),
            edge(0, 1, R(5)),
            edge(1, 0, R(0)),
            edge(0, 0, R(0)),
        ];
        let path = check_against_oracle(&nodes, &edges).unwrap();
        assert_eq!(path.edges, [1]);
    }

    #[test]
    fn both_directions_compare_the_same_policy_and_keep_edge_direction() {
        let forward = [relay(Some(R(15)), None, 1), relay(None, Some(R(15)), 2)];
        let mut reverse = [relay(None, Some(R(5)), 1), relay(Some(R(5)), None, 2)];
        for (a, b) in forward.iter().zip(&mut reverse) {
            b.node_id = a.node_id;
        }
        let edges = [edge(0, 1, R(10)), edge(1, 0, R(10))];
        let chosen = shortest_either_direction(&forward, &reverse, &edges)
            .unwrap()
            .unwrap();
        assert!(chosen.flipped);
        assert_eq!(chosen.path.relays, [1, 0]);
        assert_eq!(chosen.path.edges, [1]);
        assert_eq!(chosen.path.rtt, 20);
        let chosen = shortest_either_direction(&forward, &reverse, &edges[..1])
            .unwrap()
            .unwrap();
        assert!(!chosen.flipped);
        assert_eq!(chosen.path.relays, [0, 1]);
    }

    #[test]
    fn direction_ties_are_stable_and_mismatched_inputs_fail_closed() {
        let forward = [relay(Some(R(1)), Some(R(1)), 3)];
        let mut reverse = [relay(Some(R(1)), Some(R(1)), 3)];
        reverse[0].node_id = forward[0].node_id;
        let chosen = shortest_either_direction(&forward, &reverse, &[])
            .unwrap()
            .unwrap();
        assert!(!chosen.flipped);
        assert!(shortest_either_direction(&forward, &[], &[]).is_err());
        let mut bad_load = reverse;
        bad_load[0].load = 4;
        assert!(shortest_either_direction(&forward, &bad_load, &[]).is_err());
        assert!(
            shortest_either_direction(&forward, &[relay(Some(R(1)), Some(R(1)), 3)], &[]).is_err()
        );
        assert!(shortest_either_direction(&[], &[], &[]).unwrap().is_none());
        assert!(shortest_either_direction(&forward, &reverse, &[edge(0, 1, R(0))]).is_err());
    }

    #[test]
    fn direction_comparison_uses_failure_count_and_hops_before_unknown_rtt() {
        let a = SearchPath {
            relays: vec![0],
            edges: vec![],
            class: 1,
            rtt: 100,
            load: 99,
            unknown_legs: 1,
            unreachable_legs: 0,
        };
        let b = SearchPath {
            relays: vec![0, 1],
            edges: vec![0],
            class: 1,
            rtt: 0,
            load: 0,
            unknown_legs: 1,
            unreachable_legs: 0,
        };
        assert!(a.rank_key() < b.rank_key());
        let c = SearchPath {
            relays: vec![0, 1],
            edges: vec![0],
            class: 2,
            rtt: 500,
            load: 0,
            unknown_legs: 0,
            unreachable_legs: 1,
        };
        let d = SearchPath {
            relays: vec![0],
            edges: vec![],
            class: 2,
            rtt: 0,
            load: 0,
            unknown_legs: 0,
            unreachable_legs: 2,
        };
        assert!(c.rank_key() < d.rank_key());
    }

    #[test]
    fn invalid_or_empty_graph_is_not_a_zero_cost_route() {
        assert_eq!(shortest(&[], &[]).unwrap(), None);
        let repeated = relay(Some(R(0)), Some(R(0)), 0);
        assert_eq!(shortest(&[repeated, repeated], &[]), Err(InvalidGraph));
        assert_eq!(shortest(&[], &[edge(0, 0, R(0))]), Err(InvalidGraph));
        assert_eq!(
            shortest(&[relay(None, None, 0)], &[edge(0, 2, R(0))]),
            Err(InvalidGraph)
        );
        assert_eq!(shortest(&[relay(Some(R(0)), None, 0)], &[]).unwrap(), None);
    }

    #[test]
    fn convex_load_saturation_steers_close_rtt_away_from_congested_relay() {
        let sat_94 = (MAX_SESSIONS_PER_RELAY * 15) / 16;
        let idle = MAX_SESSIONS_PER_RELAY / 32;
        // Relay 0 is 30 ms total RTT but near saturation (93.75% => +156 ms congestion);
        // Relay 1 is 45 ms total RTT and nearly idle (3.125% => +0 ms congestion).
        let fwd = [
            relay(Some(R(15)), Some(R(15)), sat_94),
            relay(Some(R(22)), Some(R(23)), idle),
        ];
        let mut rev = fwd;
        for (a, b) in fwd.iter().zip(&mut rev) {
            b.node_id = a.node_id;
        }
        let chosen = shortest_either_direction(&fwd, &rev, &[]).unwrap().unwrap();
        assert_eq!(
            chosen.path.relays,
            [1],
            "idle 45 ms relay beats 94%-saturated 30 ms relay"
        );
        assert_eq!((chosen.path.rtt, chosen.path.load), (45, idle as u128));

        // Convexity: two balanced half-loaded relays (43.75% + 43.75% => 2 * 12 = 24 ms)
        // beat a single heavily saturated relay of equal total load (87.5% => 104 ms).
        let half = (MAX_SESSIONS_PER_RELAY * 7) / 16;
        let sat_87 = half * 2;
        let nodes = [
            relay(Some(R(15)), None, half),
            relay(None, Some(R(15)), half),
            relay(Some(R(20)), Some(R(20)), sat_87),
        ];
        let edges = [edge(0, 1, R(10))];
        let best = shortest(&nodes, &edges).unwrap().unwrap();
        assert_eq!(
            best.relays,
            [0, 1],
            "two balanced relays beat one 87.5%-saturated relay of equal total load"
        );
    }

    #[test]
    fn multi_metric_sla_search_accounts_for_jitter_and_compounding_loss() {
        let sla_relay = |ing, ex, load| SearchRelayWithSla {
            node_id: ObjectId::new(),
            ingress: ing,
            exit: ex,
            load,
        };
        let reach = |rtt_ms, jitter_ms, loss_permille| SlaVerdict::Reachable {
            rtt_ms,
            jitter_ms,
            loss_permille,
        };

        // Path A ([0 -> 1]): low raw RTT (10+10+10 = 30 ms) but 10% loss on each of 3 legs
        // => compounded loss = 1 - 0.9^3 = 27.1% (271 permille), ~316 ms loss penalty!
        // Path B ([2]): 55 ms total RTT (27 + 28 ms), 2 ms jitter, 0% loss => ~63 ms effective!
        let fwd = [
            sla_relay(Some(reach(10, 0, 100)), None, 4),
            sla_relay(None, Some(reach(10, 0, 100)), 4),
            sla_relay(Some(reach(27, 1, 0)), Some(reach(28, 1, 0)), 4),
        ];
        let mut rev = fwd;
        for (a, b) in fwd.iter().zip(&mut rev) {
            b.node_id = a.node_id;
        }
        let edges = [SearchEdgeWithSla {
            from: 0,
            to: 1,
            verdict: reach(10, 0, 100),
        }];
        let chosen = shortest_either_direction_sla(&fwd, &rev, &edges)
            .unwrap()
            .unwrap();
        assert_eq!(
            chosen.path.relays,
            [2],
            "clean 55 ms relay beats compounding 3x10%-loss path"
        );
        assert_eq!(chosen.path.rtt, 55);
        assert_eq!(chosen.path.jitter_ms, 2);
        assert_eq!(chosen.path.effective_loss_permille, 0);
        assert_eq!(chosen.path.effective_cost_ms, 55 + 2 * 2);

        // Verify compounding loss math directly when only the 2-hop path exists:
        // 1 - 0.9^3 = 0.271 => 271 permille.
        let only_lossy = shortest_sla(&fwd[..2], &edges).unwrap().unwrap();
        assert_eq!(only_lossy.effective_loss_permille, 271);
        assert!(only_lossy.effective_cost_ms > 300);

        // High-jitter path (40 ms RTT, 35 ms jitter per leg = 70 ms jitter => 40 + 140 = 180 ms)
        // loses to stable 70 ms path (70 + 4 = 74 ms).
        let jitter_vs_stable = [
            sla_relay(Some(reach(20, 35, 0)), Some(reach(20, 35, 0)), 2),
            sla_relay(Some(reach(35, 1, 0)), Some(reach(35, 1, 0)), 2),
        ];
        let best = shortest_sla(&jitter_vs_stable, &[]).unwrap().unwrap();
        assert_eq!(best.relays, [1]);

        // 1000 permille (100% loss) is classified as Unreachable (class 2), never class 0!
        let total_loss = [sla_relay(Some(reach(5, 0, 1000)), Some(reach(5, 0, 0)), 0)];
        let dead = shortest_sla(&total_loss, &[]).unwrap().unwrap();
        assert_eq!(
            (
                dead.class,
                dead.unreachable_legs,
                dead.effective_loss_permille
            ),
            (2, 1, 1000)
        );
    }
}
