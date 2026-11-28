// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The module set and the allowed dependency edges, as data.
//!
//! This is the DAG from the spec (`docs/fr/FR-69-modular-monolith.md`, D6)
//! written down where a test can hold it. The host's composition order is a
//! topological order of this graph; the hook order is its reverse.

/// Every module, in the order the host composes them (dependencies first).
pub const MODULES: &[&str] = &["fleet", "remote", "network"];

/// The allowed **module → module** call edges. Every module may call core;
/// core calls no module. Anything not listed here is forbidden — in particular
/// `remote ↔ network`.
pub const EDGES: &[(&str, &str)] = &[("remote", "fleet"), ("network", "fleet")];

/// The modules `id` may call, besides core.
pub fn depends_on(id: &str) -> impl Iterator<Item = &'static str> {
    EDGES
        .iter()
        .filter(move |(from, _)| *from == id)
        .map(|(_, to)| *to)
}

/// Whether `from` may call `to` (a module, not core).
pub fn is_allowed_edge(from: &str, to: &str) -> bool {
    EDGES.contains(&(from, to))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_edge_names_known_modules() {
        for (from, to) in EDGES {
            assert!(MODULES.contains(from), "unknown module {from}");
            assert!(MODULES.contains(to), "unknown module {to}");
        }
    }

    #[test]
    fn composition_order_is_topological() {
        // A module must come after everything it depends on.
        for (i, id) in MODULES.iter().enumerate() {
            for dep in depends_on(id) {
                let j = MODULES.iter().position(|m| *m == dep).expect("known");
                assert!(j < i, "{id} depends on {dep} but is composed before it");
            }
        }
    }

    #[test]
    fn graph_is_a_dag() {
        // No module may reach itself by following edges.
        fn reaches(from: &str, target: &str, depth: usize) -> bool {
            if depth > MODULES.len() {
                return true; // a cycle would loop forever; treat as reachable
            }
            depends_on(from).any(|d| d == target || reaches(d, target, depth + 1))
        }
        for id in MODULES {
            assert!(!reaches(id, id, 0), "{id} reaches itself");
        }
    }

    #[test]
    fn the_forbidden_pairs_stay_forbidden() {
        for (a, b) in [("remote", "network")] {
            assert!(!is_allowed_edge(a, b), "{a} -> {b} must not be allowed");
            assert!(!is_allowed_edge(b, a), "{b} -> {a} must not be allowed");
        }
    }
}
