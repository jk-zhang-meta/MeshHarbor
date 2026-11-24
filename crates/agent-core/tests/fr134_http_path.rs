// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-134 — native HTTP clients built through `http_client::builder()` follow the management path
//! ladder automatically (active daemon route, or kept/local entries with ordered failover for
//! out-of-daemon processes such as `mh`).

use axum::{Router, routing::get};
use meshharbor_node_core::{
    http_client,
    management_path::{self as mp, Candidate, Pushed},
};
use std::time::Duration;
use tokio::net::TcpListener;

async fn spawn_echo(tag: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/ping", get(move || async move { tag }));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

#[tokio::test]
async fn http_client_follows_active_entry_and_cli_entry_failover_automatically() {
    // 1. Out-of-daemon / pre-connect case: LAST is not Direct; centre host has a dead entry first
    //    and a live entry second, with `direct = false`. `http_client::builder()` resolves the
    //    unresolvable `.invalid` centre name to `[dead, live]` and reaches the live entry.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let live_addr = spawn_echo("via-live-entry").await;

    let centre_a = "centre-a.fr134.invalid";
    mp::note_config(
        &format!("https://{centre_a}"),
        &[dead_addr.to_string(), live_addr.to_string()],
    );
    mp::note_pushed(
        centre_a,
        &Pushed {
            direct: false,
            entries: Vec::new(),
        },
    );

    let client = http_client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let body = client
        .get(format!("http://{centre_a}/ping"))
        .send()
        .await
        .expect("HTTP request should fail over from dead entry to live entry")
        .text()
        .await
        .unwrap();
    assert_eq!(body, "via-live-entry");

    // 2. Active daemon control-socket route: `note_connected(Entry(entry_b))` steers even an
    //    already-constructed `reqwest::Client` to `entry_b` dynamically without rebuilding it.
    let entry_b = spawn_echo("via-active-route").await;
    let centre_b = "centre-b.fr134.invalid";
    mp::note_connected(centre_b, Candidate::Entry(entry_b), false);
    assert_eq!(mp::entry_retry_after(), None);

    let body = client
        .get(format!("http://{centre_b}/ping"))
        .send()
        .await
        .expect("existing HTTP client should dynamically follow active ROUTE")
        .text()
        .await
        .unwrap();
    assert_eq!(body, "via-active-route");

    // 3. Last-resort direct arms `entry_retry_after()`, and moving back to an entry clears it.
    mp::note_connected(centre_b, Candidate::Direct, true);
    assert!(
        mp::entry_retry_after().is_some(),
        "last-resort direct must arm entry retry"
    );
    mp::note_connected(centre_b, Candidate::Entry(entry_b), false);
    assert_eq!(
        mp::entry_retry_after(),
        None,
        "returning to an entry must disarm entry retry"
    );
    mp::set_route(centre_b, None);
}
