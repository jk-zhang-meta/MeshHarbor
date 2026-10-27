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
    pub unknown_legs: u128,
    pub unreachable_legs: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct InvalidGraph;

/// Search without a fixed hop limit over relays and edges authorized by the
/// caller. Invalid edge indexes reject the whole graph.
///
/// Paths first minimize the worst leg class. With all legs measured reachable,
/// prefer RTT, load, then relay count. If any leg is unknown or unreachable,
/// prefer fewer unreachable legs, then fewer relays, fewer unknown legs,
/// known RTT, and load. This conservatively avoids rewarding longer paths for
/// unmeasured/down links having zero measured RTT. Legacy production ranking
/// differs; this staged policy must not be enabled until integration review.
///
/// Class thresholds are searched separately: a later worse leg can equalize
/// prefix classes. Inside a threshold every cost component adds non-negative
/// exact amounts, so Dijkstra's single-label ordering is valid. Relay count
/// strictly increases along edges, ruling out cycles. Wide sums avoid saturation
/// equalizing prefix scores and invalidating the ordering.
pub(super) fn shortest(
    relays: &[SearchRelay],
    edges: &[SearchEdge],
) -> Result<Option<SearchPath>, InvalidGraph> {
    type Cost = (u128, u128, u128, u128, u128);
    fn step(threshold: u8, verdict: ProbeVerdict, relay_load: Option<usize>) -> Cost {
        let (class, rtt) = rank_legs([verdict]);
        let hops = u128::from(relay_load.is_some());
        let load = relay_load.unwrap_or_default() as u128;
        if threshold == 0 {
            (u128::from(rtt), load, hops, 0, 0)
        } else {
            (
                u128::from(class == 2),
                hops,
                u128::from(class == 1),
                u128::from(rtt),
                load,
            )
        }
    }
    fn add(a: Cost, b: Cost) -> Cost {
        (a.0 + b.0, a.1 + b.1, a.2 + b.2, a.3 + b.3, a.4 + b.4)
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
            if rank_legs([verdict]).0 <= threshold {
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
                && rank_legs([verdict]).0 <= threshold
            {
                let candidate = (add(cost, step(threshold, verdict, None)), node);
                if best.is_none_or(|current| candidate < current) {
                    best = Some(candidate);
                }
            }
            for &edge_index in &adjacency[node] {
                let edge = &edges[edge_index];
                if rank_legs([edge.verdict]).0 > threshold {
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
            let (rtt, load, unknown_legs, unreachable_legs) = if threshold == 0 {
                (cost.0, cost.1, 0, 0)
            } else {
                (cost.3, cost.4, cost.2, cost.0)
            };
            return Ok(Some(SearchPath {
                relays: path,
                edges: used_edges,
                class: threshold,
                rtt,
                load,
                unknown_legs,
                unreachable_legs,
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
    type Score = (u8, u128, u128, u128, u128, u128);
    fn oracle_key(legs: &[ProbeVerdict], load: u128, hops: usize) -> Score {
        let down = legs.iter().filter(|v| matches!(v, X)).count() as u128;
        let unknown = legs.iter().filter(|v| matches!(v, U)).count() as u128;
        let rtt: u128 = legs
            .iter()
            .map(|v| match v {
                R(ms) => u128::from(*ms),
                _ => 0,
            })
            .sum();
        if down > 0 {
            (2, down, hops as u128, unknown, rtt, load)
        } else if unknown > 0 {
            (1, 0, hops as u128, unknown, rtt, load)
        } else {
            (0, rtt, load, hops as u128, 0, 0)
        }
    }
    fn brute(
        node: usize,
        seen: u64,
        nodes: &[SearchRelay],
        edges: &[SearchEdge],
        legs: &mut Vec<ProbeVerdict>,
        load: u128,
        best: &mut Option<Score>,
    ) {
        if let Some(exit) = nodes[node].exit {
            legs.push(exit);
            let candidate = oracle_key(legs, load, seen.count_ones() as usize);
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
            brute(
                e.to,
                seen | (1 << e.to),
                nodes,
                edges,
                legs,
                load + nodes[e.to].load as u128,
                best,
            );
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
                    node.load as u128,
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
            let mut load = 0u128;
            for (i, &node) in path.relays.iter().enumerate() {
                assert_eq!(seen & (1 << node), 0, "relay repeats");
                seen |= 1 << node;
                load += nodes[node].load as u128;
                if i > 0 {
                    let e = edges[path.edges[i - 1]];
                    assert_eq!((e.from, e.to), (path.relays[i - 1], node));
                    legs.push(e.verdict);
                }
            }
            legs.push(nodes[*path.relays.last().unwrap()].exit.unwrap());
            let actual = oracle_key(&legs, load, path.relays.len());
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
