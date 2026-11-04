// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-69 — the composition baseline.
//!
//! Every module PR in the decoupling program is "pure moves plus signature
//! changes". This test is what makes that a checked claim: it builds the real
//! server, snapshots what the full profile is composed of, and asserts the
//! snapshot is byte-identical to the committed baseline in
//! `crates/tests/fixtures/composition.baseline.json`.
//!
//! The snapshot holds three things, each chosen because a move can break it
//! while every other test stays green:
//!
//! * **routes** — every served path with its allowed methods, read from the
//!   built router (a dropped or re-pathed route in a move shows up here even if
//!   no integration test exercises it);
//! * **indexes** — the index plan for both `multi_block` values, in
//!   application order (a module that takes its collections with it must take
//!   its index specs unchanged);
//! * **wire** — every `rename = "…"` name in the RC signalling source, in
//!   order (the enum is deliberately NOT moved by FR-69; this keeps "the wire
//!   did not change" a statement with a check behind it).
//!
//! Deliberately NOT here: settings keys (the config crate is untouched by the
//! program) and the WebSocket namespace map (it exists from P5 and is baselined
//! when it does).
//!
//! **To update the baseline** — only when a change is intended, and say why in
//! the commit message so the reviewer can diff the JSON against the claim:
//!
//! ```text
//! COMPOSITION_UPDATE=1 cargo test -p meshharbor-tests composition_matches_baseline
//! ```
//!
//! **Without a local server build** (a Windows dev box has no OpenSSL or
//! mediasoup toolchain; the server lane on this project is Linux): push the
//! change with the baseline file absent, and the integration lane prints the
//! snapshot between `BEGIN/END COMPOSITION BASELINE` markers in the failing
//! test's output. Save those lines as the baseline file, push again, and the
//! lane goes green. The baseline is then what CI itself composed — the
//! environment the gate runs in.
//!
//! The precondition asserts (a route count, an index-set count, a wire-name
//! count) are load-bearing in the `harness_tests` sense: without them an empty
//! snapshot would match an empty baseline and the test would pass proving
//! nothing — which is exactly how a parser that silently stopped matching
//! axum's Debug format would present.

use std::{collections::BTreeSet, path::PathBuf};

use meshharbor_api::build_router;
use meshharbor_core::composition::{Snapshot, index_sets_json, routes_of, wire_names};

use crate::fixtures::test_app::TestApp;

/// The RC wire, read at compile time from its one source of truth.
const SIGNALING_SOURCE: &str = include_str!("../../remote_control/src/signaling.rs");

/// Floors the snapshot must clear before it is compared. They are far below
/// the real numbers on purpose: they catch "the extractor found nothing", not
/// "a route was added".
const MIN_ROUTES: usize = 100;
const MIN_INDEX_SETS: usize = 40;
const MIN_WIRE_NAMES: usize = 80;
/// P5b — `ClientMsg` has 44 variants today; a table that shrank to a
/// handful would mean the owner map is not the one the socket dispatches on.
const MIN_NAMESPACES: usize = 40;

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/composition.baseline.json")
}

async fn snapshot() -> Snapshot {
    // Every compiled module MOUNTED, including FR-90's `hive` and `vault`,
    // whose switches default off: a default-off module's routes and indexes
    // are still a claim this build makes, and a change to them must be a
    // reviewed line in the baseline rather than invisible until someone turns
    // it on.
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.modules.vault = true;
    })
    .await;
    // A second router from the same state: the one `TestApp` serves is owned
    // by its listener task, and `build_router` is pure composition.
    let router = build_router(app.state.clone());
    // The sets a host applies: the core plan (per `multi_block` schema) plus
    // every mounted module's, sorted by collection — see `index_sets_json`.
    let all_sets = |multi_block: bool| {
        let mut sets = meshharbor_db::indexes::index_plan(multi_block).sets;
        sets.extend(app.state.modules.index_sets_for(multi_block));
        index_sets_json(sets)
    };
    Snapshot {
        routes: routes_of(&router),
        indexes: serde_json::json!({
            "single_block": all_sets(false),
            "multi_block": all_sets(true),
        }),
        wire: wire_names(SIGNALING_SOURCE),
        // P5b — the owner of every client wire tag. Recorded so a module PR
        // that re-homes a message (or a new variant that names an owner) is
        // a visible line in the baseline diff, not a silent re-route.
        namespaces: meshharbor_core::composition::namespaces(),
    }
}

fn index_set_count(s: &Snapshot) -> usize {
    s.indexes["single_block"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
}

#[tokio::test]
async fn composition_matches_baseline() {
    let actual = snapshot().await;
    println!("composition: {}", actual.summary());

    // Preconditions — see the module docs for why these are load-bearing.
    assert!(
        actual.routes.len() >= MIN_ROUTES,
        "only {} routes found — the router extractor stopped matching axum's Debug output",
        actual.routes.len()
    );
    assert!(
        index_set_count(&actual) >= MIN_INDEX_SETS,
        "only {} index sets — the index plan is not what ensure_indexes applies",
        index_set_count(&actual)
    );
    assert!(
        actual.wire.len() >= MIN_WIRE_NAMES,
        "only {} wire names — the signalling source was not read",
        actual.wire.len()
    );
    assert!(
        actual.namespaces.len() >= MIN_NAMESPACES,
        "only {} client namespaces — the owner table is not the one next to ClientMsg",
        actual.namespaces.len()
    );

    let rendered = serde_json::to_string_pretty(&actual).expect("a snapshot is plain data") + "\n";
    let path = baseline_path();

    if std::env::var_os("COMPOSITION_UPDATE").is_some() {
        std::fs::write(&path, &rendered).expect("write the baseline");
        println!("composition baseline rewritten at {}", path.display());
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        // No baseline yet: print the snapshot so it can be recorded from the
        // test output (the CI log) on a machine that cannot build the server.
        println!("-----BEGIN COMPOSITION BASELINE-----");
        print!("{rendered}");
        println!("-----END COMPOSITION BASELINE-----");
        panic!(
            "no baseline at {} ({e}) — record one with COMPOSITION_UPDATE=1, or save the \
             snapshot printed above as that file",
            path.display()
        )
    });
    // A checkout with `core.autocrlf=true` hands the file back with CRLF;
    // the snapshot is rendered with LF. Compare content, not line endings.
    let expected = expected.replace("\r\n", "\n");
    if expected == rendered {
        return;
    }

    let expected: Snapshot = serde_json::from_str(&expected).expect("the baseline parses");
    let mut report = String::new();
    diff_lists(
        "route",
        &expected
            .routes
            .iter()
            .map(|r| format!("{} {}", r.methods, r.path))
            .collect::<Vec<_>>(),
        &actual
            .routes
            .iter()
            .map(|r| format!("{} {}", r.methods, r.path))
            .collect::<Vec<_>>(),
        &mut report,
    );
    diff_lists("wire name", &expected.wire, &actual.wire, &mut report);
    let owners = |m: &std::collections::BTreeMap<String, String>| {
        m.iter()
            .map(|(tag, owner)| format!("{tag} -> {owner}"))
            .collect::<Vec<_>>()
    };
    diff_lists(
        "namespace",
        &owners(&expected.namespaces),
        &owners(&actual.namespaces),
        &mut report,
    );
    if expected.indexes != actual.indexes {
        report.push_str("index plan: differs — diff fixtures/composition.baseline.json\n");
    }
    if report.is_empty() {
        report.push_str("ordering or formatting only — re-record to see the diff\n");
    }
    panic!(
        "the composition differs from the baseline:\n{report}\
         If the change is intended, re-record with COMPOSITION_UPDATE=1 and say why in the \
         commit message (docs/fr/FR-69-modular-monolith.md, D15)."
    );
}

fn diff_lists(what: &str, expected: &[String], actual: &[String], report: &mut String) {
    let exp: BTreeSet<&String> = expected.iter().collect();
    let act: BTreeSet<&String> = actual.iter().collect();
    for missing in exp.difference(&act) {
        report.push_str(&format!("{what} missing: {missing}\n"));
    }
    for extra in act.difference(&exp) {
        report.push_str(&format!("{what} unexpected: {extra}\n"));
    }
}
