// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Directed relay-path search over a graph already authorized by the caller.
//!
//! This module is staged: no production planner calls it yet. The caller must
//! build the graph from same-tenant relays, per-member grants, current zone and
//! backbone policy, and approved edges. Search alone grants no authority.

use super::{ProbeVerdict, rank_legs};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

#[derive(Clone, Copy, Debug)]
pub(super) struct SearchRelay {
    pub ingress: Option<ProbeVerdict>,
    pub exit: Option<ProbeVerdict>,
    pub load: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SearchEdge {
    pub from: usize,
    pub to: usize,
    pub verdict: ProbeVerdict,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SearchPath {
    pub relays: Vec<usize>,
    /// Indexes in the caller's edge slice, in order. Parallel edges stay distinct.
    pub edges: Vec<usize>,
    pub class: u8,
    pub rtt: u128,
    pub load: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct InvalidGraph;

/// Search without a fixed hop limit. Every relay and edge passed here must
/// already satisfy the caller's authorization and zone rules. An invalid edge
/// rejects the whole graph instead of silently changing the candidate set.
///
/// A single lexicographic Dijkstra label for `(worst class, RTT)` is unsound:
/// a later unknown/unreachable leg can equalize different prefix classes.
/// Instead search separately for each allowed class, first reachable then
/// unknown then unreachable. Within one class bound all costs are nonnegative,
/// so ordinary Dijkstra is valid. Hops break equal-cost ties and rule out cycles.
/// Sums use u128 rather than saturating u32/usize: saturation can equalize
/// prefixes later and invalidate the single-label property. Integration must
/// reconcile this exact scoring with the legacy u32-saturating rank policy.
pub(super) fn shortest(
    relays: &[SearchRelay],
    edges: &[SearchEdge],
) -> Result<Option<SearchPath>, InvalidGraph> {
    let mut adjacency = vec![Vec::new(); relays.len()];
    for (index, edge) in edges.iter().enumerate() {
        if edge.from >= relays.len() || edge.to >= relays.len() {
            return Err(InvalidGraph);
        }
        adjacency[edge.from].push(index);
    }
    // Cost: total known RTT, total relay load, number of relays.
    type Cost = (u128, u128, usize);
    for threshold in 0..=2 {
        let mut costs: Vec<Option<Cost>> = vec![None; relays.len()];
        let mut previous: Vec<Option<(usize, usize)>> = vec![None; relays.len()];
        let mut queue = BinaryHeap::new();
        for (i, relay) in relays.iter().enumerate() {
            let Some(verdict) = relay.ingress else {
                continue;
            };
            let (class, rtt) = rank_legs([verdict]);
            if class <= threshold {
                let cost = (u128::from(rtt), relay.load as u128, 1);
                costs[i] = Some(cost);
                queue.push(Reverse((cost, i)));
            }
        }
        let mut best: Option<(Cost, usize)> = None;
        while let Some(Reverse((cost, node))) = queue.pop() {
            if costs[node] != Some(cost) {
                continue;
            }
            if let Some(verdict) = relays[node].exit {
                let (class, rtt) = rank_legs([verdict]);
                if class <= threshold {
                    let candidate = ((cost.0 + u128::from(rtt), cost.1, cost.2), node);
                    if best.is_none_or(|current| candidate < current) {
                        best = Some(candidate);
                    }
                }
            }
            for &edge_index in &adjacency[node] {
                let edge = &edges[edge_index];
                let (class, rtt) = rank_legs([edge.verdict]);
                if class > threshold {
                    continue;
                }
                let next = (
                    cost.0 + u128::from(rtt),
                    cost.1 + relays[edge.to].load as u128,
                    cost.2.saturating_add(1),
                );
                if costs[edge.to].is_none_or(|old| next < old) {
                    costs[edge.to] = Some(next);
                    previous[edge.to] = Some((node, edge_index));
                    queue.push(Reverse((next, edge.to)));
                }
            }
        }
        if let Some(((rtt, load, _), mut node)) = best {
            let mut path = vec![node];
            let mut used_edges = Vec::new();
            while let Some((prev, edge_index)) = previous[node] {
                used_edges.push(edge_index);
                node = prev;
                path.push(node);
            }
            path.reverse();
            used_edges.reverse();
            return Ok(Some(SearchPath {
                relays: path,
                edges: used_edges,
                class: threshold,
                rtt,
                load,
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
            ingress,
            exit,
            load,
        }
    }
    fn edge(from: usize, to: usize, verdict: ProbeVerdict) -> SearchEdge {
        SearchEdge { from, to, verdict }
    }

    #[test]
    fn later_unknown_equalizes_prefix_classes_without_losing_the_best_path() {
        let nodes = [
            relay(Some(R(100)), None, 0),
            relay(Some(U), None, 0),
            relay(None, Some(U), 0),
        ];
        let edges = [edge(0, 2, R(0)), edge(1, 2, R(0))];
        let result = shortest(&nodes, &edges).unwrap().unwrap();
        assert_eq!(result.relays, [1, 2]);
        assert_eq!((result.class, result.rtt), (1, 0));
    }

    #[test]
    fn long_directed_chain_and_cycle_preserve_order_and_never_repeat() {
        let mut nodes = vec![relay(None, None, 1); 7];
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
        let nodes = [
            relay(Some(R(u32::MAX - 1)), None, 100),
            relay(Some(R(u32::MAX)), None, 0),
            relay(None, Some(R(u32::MAX)), 0),
        ];
        let edges = [edge(0, 2, R(1)), edge(1, 2, R(1))];
        let path = shortest(&nodes, &edges).unwrap().unwrap();
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
            let mut expected: Option<(u8, u128, u128, usize)> = None;
            fn walk(
                node: usize,
                visited: u64,
                score: (u8, u128, u128, usize),
                nodes: &[SearchRelay],
                edges: &[SearchEdge],
                best: &mut Option<(u8, u128, u128, usize)>,
            ) {
                let (class, rtt, load, hops) = score;
                if let Some(v) = nodes[node].exit {
                    let (c, r) = rank_legs([v]);
                    let candidate = (class.max(c), rtt + u128::from(r), load, hops);
                    if best.is_none_or(|old| candidate < old) {
                        *best = Some(candidate);
                    }
                }
                for edge in edges
                    .iter()
                    .filter(|e| e.from == node && visited & (1 << e.to) == 0)
                {
                    let (c, r) = rank_legs([edge.verdict]);
                    walk(
                        edge.to,
                        visited | (1 << edge.to),
                        (
                            class.max(c),
                            rtt + u128::from(r),
                            load + nodes[edge.to].load as u128,
                            hops + 1,
                        ),
                        nodes,
                        edges,
                        best,
                    );
                }
            }
            for (i, n) in nodes.iter().enumerate() {
                if let Some(v) = n.ingress {
                    let (c, r) = rank_legs([v]);
                    walk(
                        i,
                        1 << i,
                        (c, u128::from(r), n.load as u128, 1),
                        &nodes,
                        &edges,
                        &mut expected,
                    );
                }
            }
            let found = shortest(&nodes, &edges)
                .unwrap()
                .map(|p| (p.class, p.rtt, p.load, p.relays.len()));
            assert_eq!(found, expected);
        }
    }

    #[test]
    fn invalid_or_empty_graph_is_not_a_zero_cost_route() {
        assert_eq!(shortest(&[], &[]).unwrap(), None);
        assert_eq!(shortest(&[], &[edge(0, 0, R(0))]), Err(InvalidGraph));
        assert_eq!(
            shortest(&[relay(None, None, 0)], &[edge(0, 2, R(0))]),
            Err(InvalidGraph)
        );
        assert_eq!(shortest(&[relay(Some(R(0)), None, 0)], &[]).unwrap(), None);
    }
}
