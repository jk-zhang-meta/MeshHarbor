// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Bounded traversal of an already authorized relay graph for trial hints.
//! This is metadata only; each returned path must be reauthorized before use.

use super::path_graph::EdgeGraph;
use bson::oid::ObjectId;
use meshharbor_core::business_authority::BusinessZone;
use meshharbor_remote_control::signaling::{OrgRelayDiscoveryCursorWire, RelayPathWire};
use std::collections::{HashMap, HashSet};

/// Bound CPU per metadata request, independently from path length. A graph
/// larger than the budget can require a different ranking/discovery strategy;
/// we never claim this bounded search enumerates every simple path.
pub(super) const MAX_EXPANSIONS: usize = 8192;

struct Frame {
    node: usize,
    next: usize,
    emitted: bool,
}

/// A budget checkpoint is the next unexpanded path prefix, not a candidate.
/// It must not be submitted as a trial or treated as authorization.
#[derive(Debug)]
pub(super) struct ScanPage {
    pub paths: Vec<OrgRelayDiscoveryCursorWire>,
    pub checkpoint: Option<RelayPathWire>,
    pub stale: bool,
    /// The trusted prefix vanished and scanning advanced to its successor.
    pub rebased: bool,
}

/// Find the first currently valid prefix not less than the trusted stored
/// prefix. Deletions advance to a successor instead of resetting to the first
/// branch. Newly inserted earlier branches are covered after ring wrap.
fn seek_resume(
    graph: &EdgeGraph,
    roots: &[usize],
    next: &[Vec<usize>],
    wanted: &[ObjectId],
) -> Option<(Vec<usize>, bool)> {
    let (&first, _) = roots
        .iter()
        .map(|i| (i, graph.relays[*i].node_id))
        .find(|(_, id)| *id >= wanted[0])?;
    let mut path = vec![first];
    let mut visited = HashSet::from([first]);
    if graph.relays[first].node_id != wanted[0] {
        return Some((path, true));
    }
    for target in &wanted[1..] {
        let parent = *path.last().expect("root exists");
        let candidate = next[parent]
            .iter()
            .copied()
            .find(|&i| graph.relays[i].node_id >= *target && !visited.contains(&i));
        if let Some(child) = candidate {
            path.push(child);
            visited.insert(child);
            if graph.relays[child].node_id != *target {
                return Some((path, true));
            }
            continue;
        }
        // Walk back until there is a lexically later unvisited sibling.
        while path.len() > 1 {
            let removed = path.pop().expect("nonempty");
            visited.remove(&removed);
            let ancestor = *path.last().expect("root exists");
            if let Some(child) = next[ancestor].iter().copied().find(|&i| {
                graph.relays[i].node_id > graph.relays[removed].node_id && !visited.contains(&i)
            }) {
                path.push(child);
                return Some((path, true));
            }
        }
        let root_id = graph.relays[path[0]].node_id;
        return roots
            .iter()
            .copied()
            .find(|&i| graph.relays[i].node_id > root_id)
            .map(|i| (vec![i], true));
    }
    Some((path, false))
}

/// Lexical DFS over simple directed paths, resuming after a complete cursor.
/// At most `limit` results and `budget` node expansions are produced. Branches
/// lexically earlier than the cursor are skipped without expanding descendants.
/// No recursion and no hard hop-count limit are used.
pub(super) fn paths(
    graph: &EdgeGraph,
    requester_zone: Option<BusinessZone>,
    peer_zone: Option<BusinessZone>,
    restrict_ends: bool,
    after: Option<&OrgRelayDiscoveryCursorWire>,
    limit: usize,
    budget: usize,
) -> Vec<OrgRelayDiscoveryCursorWire> {
    scan(
        graph,
        requester_zone,
        peer_zone,
        restrict_ends,
        after,
        None,
        limit,
        budget,
    )
    .paths
}

/// Resume a budget-exhausted DFS directly at its saved prefix. Ancestors are
/// reconstructed rather than charged again, so long paths also make progress.
/// A missing prefix/edge seeks its lexical successor on the fresh graph; each
/// result must still be reauthorized. Ring wrap and safe checkpoint binding are
/// caller responsibilities, and continuous graph churn has no fairness claim.
// Keep graph, endpoint constraints, continuation positions and work budgets
// explicit at the existing traversal seam; no new configuration wrapper.
#[allow(clippy::too_many_arguments)]
pub(super) fn scan(
    graph: &EdgeGraph,
    requester_zone: Option<BusinessZone>,
    peer_zone: Option<BusinessZone>,
    restrict_ends: bool,
    after: Option<&OrgRelayDiscoveryCursorWire>,
    resume: Option<&RelayPathWire>,
    limit: usize,
    budget: usize,
) -> ScanPage {
    if limit == 0
        || budget == 0
        || (restrict_ends && (requester_zone.is_none() || peer_zone.is_none()))
    {
        return ScanPage {
            paths: Vec::new(),
            checkpoint: None,
            stale: false,
            rebased: false,
        };
    }
    let mut roots: Vec<_> = (0..graph.relays.len())
        .filter(|&i| {
            let relay = &graph.relays[i];
            !relay.implicit
                && relay.zone.is_some()
                && (!restrict_ends || relay.zone == requester_zone || relay.zone == peer_zone)
        })
        .collect();
    roots.sort_by_key(|&i| graph.relays[i].node_id);
    let mut next = vec![Vec::new(); graph.relays.len()];
    for edge in &graph.edges {
        let (Some(from), Some(to)) = (graph.relays.get(edge.from), graph.relays.get(edge.to))
        else {
            return ScanPage {
                paths: Vec::new(),
                checkpoint: None,
                stale: true,
                rebased: false,
            };
        };
        if from.implicit || to.implicit {
            continue;
        }
        let (Some(from_zone), Some(to_zone)) = (from.zone, to.zone) else {
            continue;
        };
        if from_zone != to_zone && !edge.cross_border {
            continue;
        }
        next[edge.from].push(edge.to);
    }
    for edges in &mut next {
        edges.sort_by_key(|&i| graph.relays[i].node_id);
        edges.dedup();
    }
    let mut resumed = None;
    let mut rebased = false;
    if let Some(prefix) = resume {
        let by_id: HashMap<_, _> = graph
            .relays
            .iter()
            .enumerate()
            .map(|(index, relay)| (relay.node_id, index))
            .collect();
        if by_id.len() != graph.relays.len() {
            return ScanPage {
                paths: Vec::new(),
                checkpoint: None,
                stale: true,
                rebased: false,
            };
        }
        let Some((indexes, changed)) = seek_resume(graph, &roots, &next, prefix.relay_node_ids())
        else {
            return ScanPage {
                paths: Vec::new(),
                checkpoint: None,
                stale: false,
                rebased: true,
            };
        };
        rebased = changed;
        resumed = Some(indexes);
    }
    let mut result = Vec::new();
    let mut expanded = 0usize;
    for root in roots {
        if result.len() >= limit {
            break;
        }
        if let Some(prefix) = &resumed
            && graph.relays[root].node_id < graph.relays[prefix[0]].node_id
        {
            continue;
        }
        if after.is_some_and(|cursor| graph.relays[root].node_id < cursor.path.relay_node_ids()[0])
        {
            continue;
        }
        if expanded >= budget {
            return ScanPage {
                paths: result,
                checkpoint: RelayPathWire::new(vec![graph.relays[root].node_id]).ok(),
                stale: false,
                rebased,
            };
        }
        let path = match resumed.take() {
            Some(prefix) if prefix[0] == root => prefix,
            other => {
                resumed = other;
                vec![root]
            }
        };
        let mut visited: HashSet<_> = path.iter().copied().collect();
        let mut stack: Vec<_> = path
            .iter()
            .enumerate()
            .map(|(i, &node)| {
                if let Some(&child) = path.get(i + 1) {
                    let child_pos = next[node]
                        .iter()
                        .position(|&n| n == child)
                        .expect("validated prefix");
                    Frame {
                        node,
                        next: child_pos + 1,
                        emitted: true,
                    }
                } else {
                    Frame {
                        node,
                        next: 0,
                        emitted: false,
                    }
                }
            })
            .collect();
        let mut path = path;
        expanded += 1;
        while !stack.is_empty() && expanded <= budget && result.len() < limit {
            let frame = stack.last_mut().expect("nonempty");
            if !frame.emitted {
                frame.emitted = true;
                if path.len() >= 3 {
                    let first = graph.relays[path[0]].zone;
                    let last = graph.relays[frame.node].zone;
                    for flip in [false, true] {
                        let valid = !restrict_ends
                            || if flip {
                                first == peer_zone && last == requester_zone
                            } else {
                                first == requester_zone && last == peer_zone
                            };
                        if !valid {
                            continue;
                        }
                        let ids: Vec<ObjectId> =
                            path.iter().map(|&i| graph.relays[i].node_id).collect();
                        let identity = OrgRelayDiscoveryCursorWire {
                            path: RelayPathWire::new(ids).expect("visited prevents loops"),
                            requester_at_exit: flip,
                        };
                        if after.is_none_or(|cursor| identity > *cursor) {
                            result.push(identity);
                            if result.len() >= limit {
                                break;
                            }
                        }
                    }
                }
                continue;
            }
            let node = frame.node;
            if frame.next == next[node].len() {
                stack.pop();
                visited.remove(&node);
                path.pop();
                continue;
            }
            let child = next[node][frame.next];
            frame.next += 1;
            if visited.contains(&child) {
                continue;
            }
            if let Some(cursor) = after {
                // If the first differing node is smaller, the entire subtree
                // precedes the cursor. Equal prefixes must remain traversable.
                let mut order = std::cmp::Ordering::Equal;
                for (node, wanted) in path
                    .iter()
                    .map(|&i| graph.relays[i].node_id)
                    .chain(std::iter::once(graph.relays[child].node_id))
                    .zip(cursor.path.relay_node_ids())
                {
                    order = node.cmp(wanted);
                    if !order.is_eq() {
                        break;
                    }
                }
                if order.is_lt() {
                    continue;
                }
            }
            if expanded >= budget {
                let ids = path
                    .iter()
                    .copied()
                    .chain(std::iter::once(child))
                    .map(|i| graph.relays[i].node_id)
                    .collect();
                return ScanPage {
                    paths: result,
                    checkpoint: RelayPathWire::new(ids).ok(),
                    stale: false,
                    rebased,
                };
            }
            visited.insert(child);
            path.push(child);
            stack.push(Frame {
                node: child,
                next: 0,
                emitted: false,
            });
            expanded += 1;
        }
    }
    ScanPage {
        paths: result,
        checkpoint: None,
        stale: false,
        rebased,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::org_relay::path_graph::{EligibleRelay, GraphEdge};
    use meshharbor_core::business_authority::BusinessZone::{Mainland as M, NonMainland as N};
    fn relay(n: u8, zone: BusinessZone) -> EligibleRelay {
        EligibleRelay {
            node_id: ObjectId::from_bytes([n; 12]),
            agent_id: ObjectId::new(),
            zone: Some(zone),
            bridge_ready: true,
            implicit: false,
            approved_edges: vec![],
        }
    }
    fn edge(from: usize, to: usize, cross: bool) -> GraphEdge {
        GraphEdge {
            from,
            to,
            endpoint: "10.1.0.2:3478".into(),
            cross_border: cross,
        }
    }
    #[test]
    fn finds_three_and_four_relays_even_when_direct_edge_exists_and_cursor_resumes() {
        let g = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, N), relay(4, N)],
            edges: vec![
                edge(0, 3, true),
                edge(0, 1, false),
                edge(1, 2, true),
                edge(2, 3, false),
            ],
        };
        let first = paths(&g, Some(M), Some(N), true, None, 1, MAX_EXPANSIONS);
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0].path.relay_node_ids(),
            &[
                g.relays[0].node_id,
                g.relays[1].node_id,
                g.relays[2].node_id
            ]
        );
        let second = paths(
            &g,
            Some(M),
            Some(N),
            true,
            Some(&first[0]),
            1,
            MAX_EXPANSIONS,
        );
        assert_eq!(second.len(), 1);
        assert_eq!(
            second[0].path.relay_node_ids(),
            &[
                g.relays[0].node_id,
                g.relays[1].node_id,
                g.relays[2].node_id,
                g.relays[3].node_id
            ]
        );
    }
    #[test]
    fn excludes_loops_implicit_nodes_and_unapproved_crossings() {
        let mut g = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, N)],
            edges: vec![edge(0, 1, false), edge(1, 0, false), edge(1, 2, false)],
        };
        assert!(paths(&g, Some(M), Some(N), true, None, 3, 100).is_empty());
        g.edges[2].cross_border = true;
        assert_eq!(paths(&g, Some(M), Some(N), true, None, 3, 100).len(), 1);
        g.relays[1].implicit = true;
        assert!(paths(&g, Some(M), Some(N), true, None, 3, 100).is_empty());
    }
    #[test]
    fn unrestricted_modes_allow_unknown_member_zones_but_not_unapproved_crossings() {
        let mut g = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, N)],
            edges: vec![edge(0, 1, false), edge(1, 2, false)],
        };
        assert!(paths(&g, None, None, false, None, 3, 100).is_empty());
        g.edges[1].cross_border = true;
        assert_eq!(paths(&g, None, None, false, None, 3, 100).len(), 2);
        assert!(paths(&g, None, None, true, None, 3, 100).is_empty());
    }

    #[test]
    fn expansion_budget_does_not_encode_a_hop_ceiling() {
        let mut g = EdgeGraph {
            relays: (0..32).map(|n| relay(n, M)).collect(),
            edges: vec![],
        };
        g.edges = (0..31).map(|n| edge(n, n + 1, false)).collect();
        let prefix =
            RelayPathWire::new(g.relays[..31].iter().map(|n| n.node_id).collect()).unwrap();
        let cursor = OrgRelayDiscoveryCursorWire {
            path: prefix,
            requester_at_exit: true,
        };
        let found = paths(&g, Some(M), Some(M), true, Some(&cursor), 1, MAX_EXPANSIONS);
        assert_eq!(found[0].path.relay_node_ids().len(), 32);
    }

    #[test]
    fn checkpoint_advances_past_dead_work_and_long_prefixes() {
        let mut g = EdgeGraph {
            relays: (0..12).map(|n| relay(n, M)).collect(),
            edges: vec![],
        };
        // Root 0 has a dead branch before a long branch. Budget 1 is smaller
        // than the valid path itself, so replaying the prefix cannot progress.
        g.edges = vec![edge(0, 1, false), edge(0, 2, false)];
        g.edges.extend((2..11).map(|n| edge(n, n + 1, false)));
        let mut checkpoint = None;
        let mut found_long = false;
        for _ in 0..200 {
            let page = scan(
                &g,
                Some(M),
                Some(M),
                true,
                None,
                checkpoint.as_ref(),
                100,
                1,
            );
            assert!(!page.stale);
            found_long |= page
                .paths
                .iter()
                .any(|p| p.path.relay_node_ids().len() == 11);
            checkpoint = page.checkpoint;
            if checkpoint.is_none() {
                break;
            }
        }
        assert!(found_long, "budget checkpoints must reach the long path");
        assert!(checkpoint.is_none(), "stable finite graph must finish");
    }

    #[test]
    fn checkpoint_rebases_after_removed_edge() {
        let mut g = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, M)],
            edges: vec![edge(0, 1, false), edge(1, 2, false)],
        };
        let page = scan(&g, Some(M), Some(M), true, None, None, 3, 1);
        let checkpoint = page.checkpoint.expect("budget checkpoint");
        g.edges.clear();
        let page = scan(&g, Some(M), Some(M), true, None, Some(&checkpoint), 3, 1);
        assert!(!page.stale);
        assert!(page.rebased);
        assert!(page.paths.is_empty());
    }

    #[test]
    fn removed_prefix_rebases_to_later_authorized_branch() {
        let mut g = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, M), relay(4, M)],
            edges: vec![
                edge(0, 1, false),
                edge(1, 3, false),
                edge(0, 2, false),
                edge(2, 3, false),
            ],
        };
        let old = scan(&g, Some(M), Some(M), true, None, None, 100, 2);
        let checkpoint = old.checkpoint.unwrap();
        assert_eq!(
            checkpoint.relay_node_ids(),
            &[
                g.relays[0].node_id,
                g.relays[1].node_id,
                g.relays[3].node_id
            ]
        );
        g.edges.retain(|e| !(e.from == 0 && e.to == 1));
        let page = scan(
            &g,
            Some(M),
            Some(M),
            true,
            None,
            Some(&checkpoint),
            100,
            100,
        );
        assert!(!page.stale && page.rebased);
        assert!(page.paths.iter().any(|p| p.path.relay_node_ids()
            == [
                g.relays[0].node_id,
                g.relays[2].node_id,
                g.relays[3].node_id
            ]));
        assert!(page.paths.iter().all(|p| {
            !p.path
                .relay_node_ids()
                .windows(2)
                .any(|w| w == [g.relays[0].node_id, g.relays[1].node_id])
        }));
    }

    #[test]
    fn inserted_earlier_branch_is_seen_after_ring_wrap() {
        let mut g = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, M), relay(4, M)],
            edges: vec![edge(0, 2, false), edge(2, 3, false)],
        };
        let checkpoint = scan(&g, Some(M), Some(M), true, None, None, 100, 2)
            .checkpoint
            .unwrap();
        g.edges.extend([edge(0, 1, false), edge(1, 3, false)]);
        let tail = scan(
            &g,
            Some(M),
            Some(M),
            true,
            None,
            Some(&checkpoint),
            100,
            100,
        );
        assert!(!tail.stale && tail.checkpoint.is_none());
        let early = [
            g.relays[0].node_id,
            g.relays[1].node_id,
            g.relays[3].node_id,
        ];
        assert!(tail.paths.iter().all(|p| p.path.relay_node_ids() != early));
        // The caller starts a new traversal after the explicit end-of-ring.
        let wrapped = scan(&g, Some(M), Some(M), true, None, None, 100, 100);
        assert!(
            wrapped
                .paths
                .iter()
                .any(|p| p.path.relay_node_ids() == early)
        );
    }

    #[test]
    fn invalidated_relay_cannot_remain_in_a_rebased_path() {
        let mut g = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, M), relay(4, M)],
            edges: vec![
                edge(0, 1, false),
                edge(1, 3, false),
                edge(0, 2, false),
                edge(2, 3, false),
            ],
        };
        let checkpoint = scan(&g, Some(M), Some(M), true, None, None, 100, 2)
            .checkpoint
            .unwrap();
        g.relays[1].zone = None;
        let page = scan(
            &g,
            Some(M),
            Some(M),
            true,
            None,
            Some(&checkpoint),
            100,
            100,
        );
        assert!(page.rebased && !page.stale);
        assert!(
            page.paths
                .iter()
                .all(|p| !p.path.relay_node_ids().contains(&g.relays[1].node_id))
        );
    }

    #[test]
    fn deleted_root_advances_to_next_root_without_restart() {
        let old = EdgeGraph {
            relays: vec![relay(1, M), relay(2, M), relay(3, M), relay(4, M)],
            edges: vec![edge(0, 1, false), edge(1, 3, false)],
        };
        let checkpoint = scan(&old, Some(M), Some(M), true, None, None, 100, 2)
            .checkpoint
            .unwrap();
        let fresh = EdgeGraph {
            relays: old.relays[1..].to_vec(),
            edges: vec![edge(0, 1, false), edge(1, 2, false)],
        };
        let page = scan(
            &fresh,
            Some(M),
            Some(M),
            true,
            None,
            Some(&checkpoint),
            100,
            100,
        );
        assert!(page.rebased && !page.stale);
        assert!(page.paths.iter().any(|p| p.path.relay_node_ids()
            == [
                fresh.relays[0].node_id,
                fresh.relays[1].node_id,
                fresh.relays[2].node_id
            ]));
    }

    #[test]
    fn rebased_scan_matches_lexical_suffix_after_graph_changes() {
        for seed in 0..128usize {
            let relays: Vec<_> = (1..=5).map(|n| relay(n, M)).collect();
            let make_edges = |s: usize| -> Vec<GraphEdge> {
                (0..5)
                    .flat_map(|a| {
                        (0..5)
                            .filter(move |&b| a != b && (a * 11 + b * 7 + s * 3) % 5 < 2)
                            .map(move |b| edge(a, b, false))
                    })
                    .collect()
            };
            let old = EdgeGraph {
                relays: relays.clone(),
                edges: make_edges(seed),
            };
            let fresh = EdgeGraph {
                relays,
                edges: make_edges(seed + 1),
            };
            let Some(checkpoint) =
                scan(&old, Some(M), Some(M), true, None, None, 1000, 2).checkpoint
            else {
                continue;
            };
            let expected: Vec<_> = paths(&fresh, Some(M), Some(M), true, None, 10000, 100000)
                .into_iter()
                .filter(|p| p.path.relay_node_ids() >= checkpoint.relay_node_ids())
                .collect();
            let got = scan(
                &fresh,
                Some(M),
                Some(M),
                true,
                None,
                Some(&checkpoint),
                10000,
                100000,
            );
            assert!(!got.stale && got.checkpoint.is_none());
            assert_eq!(got.paths, expected, "seed {seed}");
        }
    }

    #[test]
    fn checkpoint_pages_match_unbounded_traversal_without_duplicates() {
        let g = EdgeGraph {
            relays: (0..6).map(|n| relay(n, M)).collect(),
            edges: vec![
                edge(0, 1, false),
                edge(0, 2, false),
                edge(1, 2, false),
                edge(1, 3, false),
                edge(2, 3, false),
                edge(3, 4, false),
                edge(4, 1, false),
                edge(4, 5, false),
            ],
        };
        let expected = paths(&g, Some(M), Some(M), true, None, 1000, 10000);
        let mut seen = Vec::new();
        let mut checkpoint = None;
        for _ in 0..1000 {
            let page = scan(
                &g,
                Some(M),
                Some(M),
                true,
                None,
                checkpoint.as_ref(),
                1000,
                2,
            );
            assert!(!page.stale);
            seen.extend(page.paths);
            checkpoint = page.checkpoint;
            if checkpoint.is_none() {
                break;
            }
        }
        assert!(checkpoint.is_none());
        assert_eq!(seen, expected);
    }

    #[test]
    fn checkpoint_crosses_the_real_expansion_budget() {
        let mut relays = Vec::new();
        for n in 0u32..8194 {
            let mut id = [0u8; 12];
            id[8..].copy_from_slice(&n.to_be_bytes());
            let mut r = relay(0, if n == 8193 { N } else { M });
            r.node_id = ObjectId::from_bytes(id);
            relays.push(r);
        }
        let g = EdgeGraph {
            relays,
            edges: (0..8193).map(|n| edge(n, n + 1, n == 8192)).collect(),
        };
        let first = scan(&g, Some(M), Some(N), true, None, None, 3, MAX_EXPANSIONS);
        assert!(first.paths.is_empty());
        let checkpoint = first.checkpoint.expect("first page reaches budget");
        let second = scan(
            &g,
            Some(M),
            Some(N),
            true,
            None,
            Some(&checkpoint),
            3,
            MAX_EXPANSIONS,
        );
        assert!(!second.stale);
        assert!(
            second
                .paths
                .iter()
                .any(|p| p.path.relay_node_ids().len() == 8194)
        );
    }
}
