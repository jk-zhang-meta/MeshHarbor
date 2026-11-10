// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The composition snapshot — the gate every module move passes through.
//!
//! A module PR is "pure moves plus signature changes", and this is what makes
//! that a checked claim rather than a reviewer's impression. The snapshot
//! records, for the full profile:
//!
//! * **routes** — every path the built router serves, with the methods it
//!   allows (sorted, so registration order is irrelevant);
//! * **indexes** — the index plan for both `multi_block` values: every
//!   collection, every `IndexModel`, every pre-creation op, in the order
//!   `ensure_indexes` applies them;
//! * **wire** — every `#[serde(rename = "…")]` name in the RC signalling
//!   source, in source order.
//!
//! `crates/tests` builds it from the real server and asserts it equals the
//! committed baseline (`crates/tests/fixtures/composition.baseline.json`).
//!
//! # Where the routes come from
//!
//! axum's `Router` has no public route iterator, but its `Debug` output is
//! precise: the path router prints `RouteId(n): "<path>"` for every route and,
//! for each `MethodRouter`, its accumulated `allow_header`. [`routes_from_debug`]
//! parses exactly that, and [`tests::routes_of_a_real_router`] pins the
//! parser against the axum version in the lockfile — if a bump changes the
//! format, that test fails loudly instead of the baseline silently emptying.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One served path with the methods it accepts (`"GET,HEAD,POST"`, or `"*"`
/// for `any`/service routes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RouteEntry {
    pub path: String,
    pub methods: String,
}

/// The full snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub routes: Vec<RouteEntry>,
    pub indexes: serde_json::Value,
    pub wire: Vec<String>,
    /// FR-69 P5b — every client wire tag with the module that owns it
    /// (`ClientMsg::namespace()`'s table). A sorted map, so the rendering is
    /// stable; `default` so a baseline recorded before the section existed
    /// still parses and reports the section as the diff.
    #[serde(default)]
    pub namespaces: std::collections::BTreeMap<String, String>,
}

/// The client wire tags with their owning module ids, as the snapshot
/// records them (FR-69 D7): the table the wire crate keeps next to the
/// exhaustive `ClientMsg::namespace()` match.
pub fn namespaces() -> std::collections::BTreeMap<String, String> {
    meshharbor_remote_control::signaling::CLIENT_MSG_OWNERS
        .iter()
        .map(|(tag, owner)| (tag.to_string(), owner.id().to_string()))
        .collect()
}

impl Snapshot {
    /// A one-line summary for logs and the FR's field log.
    pub fn summary(&self) -> String {
        // Either shape: a plan object (`{ "sets": [...] }`) or the sorted
        // array `index_sets_json` produces.
        let sets = |k: &str| {
            self.indexes
                .get(k)
                .and_then(|p| p.get("sets").or(Some(p)))
                .and_then(|s| s.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        };
        format!(
            "routes={} index_sets(single_block)={} index_sets(multi_block)={} wire_names={} namespaces={}",
            self.routes.len(),
            sets("single_block"),
            sets("multi_block"),
            self.wire.len(),
            self.namespaces.len()
        )
    }
}

/// The routes of a built router, sorted by path.
pub fn routes_of<S>(router: &axum::Router<S>) -> Vec<RouteEntry>
where
    S: Clone + Send + Sync + 'static,
{
    routes_from_debug(&format!("{router:?}"))
}

/// Parse the compact (`{:?}`) Debug output of an `axum::Router`.
///
/// Only the `path_router` section is read; the fallback router's entries are
/// not routes a client can name.
pub fn routes_from_debug(debug: &str) -> Vec<RouteEntry> {
    let section = between(debug, "path_router: ", ", fallback_router: ").unwrap_or(debug);
    let paths = scan_paths(section);
    let methods = scan_methods(section);
    let mut out: Vec<RouteEntry> = paths
        .into_iter()
        .map(|(id, path)| RouteEntry {
            path,
            methods: methods.get(&id).cloned().unwrap_or_else(|| "?".to_string()),
        })
        .collect();
    out.sort();
    out
}

/// Every `#[serde(rename = "…")]` string in `source`, in order.
///
/// The RC wire enums live in `crates/remote_control/src/signaling.rs` and are
/// deliberately NOT moved by FR-69; this keeps "the wire did not change" a
/// checked statement while their owners move around them.
pub fn wire_names(source: &str) -> Vec<String> {
    const NEEDLE: &str = "rename = \"";
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(i) = rest.find(NEEDLE) {
        rest = &rest[i + NEEDLE.len()..];
        let Some(end) = rest.find('"') else { break };
        out.push(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    out
}

/// The index plan as JSON, for the snapshot.
pub fn index_plan_json(multi_block: bool) -> serde_json::Value {
    serde_json::to_value(meshharbor_db::indexes::index_plan(multi_block))
        .expect("an index plan is plain data")
}

/// The full set of index sets a host applies — the core plan plus every
/// mounted module's — as JSON, **sorted by collection** so the snapshot does
/// not depend on which crate a set happens to live in. A module PR moves
/// sets between crates; it must not change them, and this is what checks
/// that.
pub fn index_sets_json(mut sets: Vec<meshharbor_db::indexes::IndexSet>) -> serde_json::Value {
    sets.sort_by(|a, b| a.collection.cmp(b.collection));
    serde_json::to_value(sets).expect("index sets are plain data")
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)? + i;
    Some(&s[i..j])
}

/// `RouteId(n): "<path>"` entries.
fn scan_paths(s: &str) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    let mut rest = s;
    while let Some((id, after)) = next_route_id(rest) {
        rest = after;
        let Some(quoted) = after.strip_prefix(": \"") else {
            continue;
        };
        let Some(end) = end_of_quoted(quoted) else {
            break;
        };
        out.insert(id, unescape(&quoted[..end]));
        rest = &quoted[end + 1..];
    }
    out
}

/// `RouteId(n): MethodRouter(MethodRouter { …, allow_header: … })` and
/// `RouteId(n): Route(Route)` entries.
fn scan_methods(s: &str) -> BTreeMap<u32, String> {
    const ALLOW: &str = "allow_header: ";
    let mut out = BTreeMap::new();
    let mut rest = s;
    while let Some((id, after)) = next_route_id(rest) {
        rest = after;
        let Some(endpoint) = after.strip_prefix(": ") else {
            continue;
        };
        if let Some(mr) = endpoint.strip_prefix("MethodRouter(") {
            let Some(k) = mr.find(ALLOW) else { break };
            let tail = &mr[k + ALLOW.len()..];
            let methods = if let Some(bytes) = tail.strip_prefix("Bytes(b\"") {
                let end = bytes.find('"').unwrap_or(bytes.len());
                normalise_methods(&bytes[..end])
            } else if tail.starts_with("Skip") {
                "*".to_string()
            } else {
                // `None`: a MethodRouter with no method — reachable only from
                // an empty `MethodRouter::new()`, never from a real route.
                String::new()
            };
            out.insert(id, methods);
            rest = tail;
        } else if endpoint.starts_with("Route(") {
            out.insert(id, "*".to_string());
            rest = endpoint;
        }
    }
    out
}

/// Finds the next `RouteId(<digits>)`; returns the id and the text after `)`.
fn next_route_id(s: &str) -> Option<(u32, &str)> {
    const NEEDLE: &str = "RouteId(";
    let mut rest = s;
    loop {
        let i = rest.find(NEEDLE)?;
        rest = &rest[i + NEEDLE.len()..];
        let close = rest.find(')')?;
        match rest[..close].trim().parse::<u32>() {
            Ok(id) => return Some((id, &rest[close + 1..])),
            Err(_) => continue,
        }
    }
}

/// Index of the closing quote of a Debug-escaped string body.
fn end_of_quoted(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(i),
            _ => {}
        }
    }
    None
}

fn unescape(s: &str) -> String {
    // Paths are ASCII; the only escapes Debug would emit for them are `\"`
    // and `\\`, which never occur in a route. Keep it honest anyway.
    s.replace("\\\"", "\"").replace("\\\\", "\\")
}

fn normalise_methods(raw: &str) -> String {
    let mut m: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    m.sort_unstable();
    m.dedup();
    m.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P5b — every owner the wire crate names is a module the graph knows,
    /// and the snapshot section carries the whole table.
    #[test]
    fn every_client_message_owner_is_a_module() {
        for (tag, owner) in meshharbor_remote_control::signaling::CLIENT_MSG_OWNERS {
            assert!(
                crate::graph::MODULES.contains(&owner.id()),
                "{tag} names `{}`, which is not a module",
                owner.id()
            );
        }
        let map = namespaces();
        assert_eq!(
            map.len(),
            meshharbor_remote_control::signaling::CLIENT_MSG_OWNERS.len()
        );
        assert_eq!(map.get("rc:agent.hello").map(String::as_str), Some("fleet"));
    }
    use axum::{
        Router,
        routing::{any, delete, get, post},
    };

    async fn h() {}

    fn entry(path: &str, methods: &str) -> RouteEntry {
        RouteEntry {
            path: path.to_string(),
            methods: methods.to_string(),
        }
    }

    /// Pins the parser against the axum in the lockfile. If this fails after
    /// a bump, the Debug format moved — fix the parser, do not loosen the test.
    #[test]
    fn routes_of_a_real_router() {
        let r: Router = Router::new()
            .route("/a", get(h).post(h))
            .route("/api/x/{id}", delete(h))
            .nest("/n", Router::new().route("/b", post(h)))
            .route("/any", any(h))
            .layer(tower::ServiceBuilder::new()); // a no-op layer must not hide routes
        assert_eq!(
            routes_of(&r),
            vec![
                entry("/a", "GET,HEAD,POST"),
                entry("/any", "*"),
                entry("/api/x/{id}", "DELETE"),
                entry("/n/b", "POST"),
            ]
        );
    }

    #[test]
    fn a_router_with_state_is_read_the_same_way() {
        #[derive(Clone)]
        struct S;
        let r: Router<S> = Router::new().route("/s", get(h));
        assert_eq!(routes_of(&r), vec![entry("/s", "GET,HEAD")]);
    }

    #[test]
    fn methods_are_order_independent() {
        assert_eq!(normalise_methods("POST,GET,HEAD"), "GET,HEAD,POST");
        assert_eq!(normalise_methods("GET, GET"), "GET");
    }

    #[test]
    fn wire_names_come_out_in_source_order() {
        let src = r#"
            #[serde(tag = "t")]
            pub enum M {
                #[serde(rename = "rc:agent.hello")]
                Hello,
                #[serde(rename_all = "snake_case")]
                Other { #[serde(rename = "b")] b: u8 },
                #[serde(rename = "rc:overlay.join")]
                Join,
            }
        "#;
        assert_eq!(
            wire_names(src),
            vec!["rc:agent.hello", "b", "rc:overlay.join"]
        );
    }

    /// The core plan is plain data — and since FR-69 P7a it carries NO set
    /// that varies with the `multi_block` schema switch: `overlay_blocks`, the
    /// one that did (multi-block DROPS the one-block-per-network guard
    /// instead of creating it), is the network module's, reachable through
    /// `Module::indexes_for(multi_block)` and pinned by the composition
    /// baseline for both values. A core set that started varying again would
    /// be a plan the snapshot records twice without anyone deciding so.
    #[test]
    fn index_plan_is_plain_data_and_no_core_set_varies_by_multi_block() {
        let single = index_plan_json(false);
        let multi = index_plan_json(true);
        assert_eq!(single["sets"], multi["sets"]);
        assert!(
            single["sets"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["collection"] != "overlay_blocks"),
            "overlay_blocks is the network module's set, not the core plan's"
        );
        // The switch is still recorded on the plan itself.
        assert_eq!(single["multi_block"], false);
        assert_eq!(multi["multi_block"], true);
    }
}
