// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-135 AC2 — no native code builds a reqwest client outside `http_client`.
//!
//! `reqwest::Client::new()`, `Client::builder()` and `reqwest::get` all honour the proxy
//! environment and the system proxy, so one of them anywhere in the daemon, `mh`, the companion
//! or the wizard puts that client's traffic back through a proxy app in system-proxy mode. A line
//! that must build one anyway (a test's positive control, the hive sidecar's provider upstream)
//! carries `fr-135: allowed` with its reason, on the line or the line above.
//!
//! WebSocket clients need no guard: `tokio-tungstenite` has no proxy support at all.

use std::path::{Path, PathBuf};

const MARKER: &str = "fr-135: allowed";

/// Native code: every agent binary and the crates they link. The server crates are not scanned —
/// their outbound calls (push, OAuth, Stripe) are the server operator's network, not a device's.
const ROOTS: [&str; 8] = [
    "agents",
    "crates/agent-core",
    "crates/tunnel-core",
    "crates/meshharbor-setup-core",
    "crates/hive-node",
    "crates/localapi",
    "crates/tcp-turn-conn",
    "crates/remote_control",
];

const FORBIDDEN: [&str; 8] = [
    "reqwest::Client::builder(",
    "reqwest::Client::new(",
    "reqwest::Client::default(",
    "reqwest::ClientBuilder::new(",
    "reqwest::ClientBuilder::default(",
    "reqwest::get(",
    "reqwest::blocking::",
    "use reqwest::get",
];

/// `(line number, line)` for each forbidden construction in `src` without the marker.
fn violations(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        let constructs = FORBIDDEN.iter().any(|p| code.contains(p))
            // An import would let a bare `Client::new()` through unseen.
            || (code.starts_with("use reqwest::") && code.contains("Client"));
        let allowed = line.contains(MARKER) || (i > 0 && lines[i - 1].contains(MARKER));
        if constructs && !allowed {
            out.push((i + 1, line.trim().to_string()));
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            if name != "target" && name != "node_modules" && name != "vendored" {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn the_scanner_catches_each_construction_and_honours_the_marker() {
    for bad in [
        "    let c = reqwest::Client::new();",
        "    let c = reqwest::Client::builder().build()?;",
        "    let c = reqwest::ClientBuilder::default().build()?;",
        "    let r = reqwest::get(url).await?;",
        "use reqwest::get;",
        "use reqwest::Client;",
        "use reqwest::{Client, StatusCode};",
    ] {
        assert_eq!(violations(bad).len(), 1, "not caught: {bad}");
    }
    assert!(violations("// reqwest::Client::new() in a comment").is_empty());
    assert!(violations("    // fr-135: allowed — why\n    reqwest::Client::new();").is_empty());
    assert!(violations("    meshharbor_node_core::http_client::builder()").is_empty());
}

#[test]
fn no_native_code_builds_a_reqwest_client_outside_the_helper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let me = Path::new(file!()).file_name().unwrap();
    let mut files = Vec::new();
    for r in ROOTS {
        rust_files(&root.join(r), &mut files);
    }
    let mut found = Vec::new();
    let mut helper_uses = 0;
    for f in &files {
        if f.file_name() == Some(me) {
            continue;
        }
        let src = std::fs::read_to_string(f).unwrap();
        helper_uses += src.matches("http_client::builder").count()
            + src.matches("http_client::client()").count();
        for (n, line) in violations(&src) {
            found.push(format!("{}:{n}: {line}", f.display()));
        }
    }
    // A scan of the wrong directory finds nothing and passes; this one must have found the code.
    assert!(
        helper_uses >= 20,
        "only {helper_uses} helper uses in {} files: is the scan root right?",
        files.len()
    );
    assert!(
        found.is_empty(),
        "build these through `meshharbor_node_core::http_client::builder()` (FR-135: no proxy \
         unless the device opted in), or mark the line `{MARKER}` with the reason:\n{}",
        found.join("\n")
    );
}
