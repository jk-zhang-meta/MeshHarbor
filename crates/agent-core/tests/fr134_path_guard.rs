// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-134 — no native code opens a WebSocket outside the management-path helpers.
//!
//! HTTP clients are already guarded by `fr135_proxy_guard.rs` (every native `reqwest::Client`
//! comes from `http_client::builder()`, which installs `ManagementPathResolver`). This companion
//! guard covers native WebSocket clients so no new centre WebSocket dialer can bypass the
//! management path ladder. A line inside a dial helper itself (or a loopback test) carries
//! `fr-134: allowed` with its reason on the line or the line above.

use std::path::{Path, PathBuf};

const MARKER: &str = "fr-134: allowed";

const ROOTS: [&str; 7] = [
    "agents",
    "crates/agent-core",
    "crates/tunnel-core",
    "crates/hive-node",
    "crates/localapi",
    "crates/tcp-turn-conn",
    "crates/remote_control",
];

const FORBIDDEN: [&str; 4] = [
    "connect_async(",
    "client_async_tls_with_config(",
    "client_async_with_config(",
    "client_async(",
];

fn violations(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        let dials = FORBIDDEN.iter().any(|p| code.contains(p));
        let allowed = line.contains(MARKER) || (i > 0 && lines[i - 1].contains(MARKER));
        if dials && !allowed {
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
fn scanner_catches_raw_ws_dials_and_honours_marker() {
    for bad in [
        "    let (ws, _) = connect_async(&url).await?;",
        "    let (ws, _) = tokio_tungstenite::connect_async(req).await?;",
        "    client_async_tls_with_config(url, stream, None, None).await",
    ] {
        assert_eq!(violations(bad).len(), 1, "not caught: {bad}");
    }
    assert!(violations("// connect_async(url) in comment").is_empty());
    assert!(violations("    // fr-134: allowed — why\n    connect_async(url).await?;").is_empty());
    assert!(violations("    crate::ws_connect::connect_centre(&url).await?;").is_empty());
}

#[test]
fn no_native_code_opens_a_ws_outside_the_management_path_helpers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let me = Path::new(file!()).file_name().unwrap();
    let mut files = Vec::new();
    for r in ROOTS {
        rust_files(&root.join(r), &mut files);
    }
    let mut found = Vec::new();
    let mut routed_uses = 0;
    for f in &files {
        if f.file_name() == Some(me) {
            continue;
        }
        let src = std::fs::read_to_string(f).unwrap();
        routed_uses += src.matches("connect_centre(").count()
            + src.matches("connect_ws_via_management_path(").count()
            + src.matches("connect_via(").count();
        for (n, line) in violations(&src) {
            found.push(format!("{}:{n}: {line}", f.display()));
        }
    }
    assert!(
        routed_uses >= 3,
        "only {routed_uses} routed WS uses in {} files: is the scan root right?",
        files.len()
    );
    assert!(
        found.is_empty(),
        "dial WebSockets through the management-path helpers (`ws_connect::connect_centre` / \
         `connect_ws_via_management_path`), or mark the line `{MARKER}` with the reason:\n{}",
        found.join("\n")
    );
}
