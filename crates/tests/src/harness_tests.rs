// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Tests of the test harness itself.
//!
//! Everything else in this crate tests the product. This module tests
//! `TestApp`, because the fixture silently stopped doing one of its two jobs
//! and nothing noticed for months.
//!
//! `Drop for TestApp` dropped each test's database from a detached
//! `tokio::spawn`. Every test here is a plain `#[tokio::test]` — a
//! current-thread runtime — so the body finished, `Drop` queued the task, and
//! `block_on` returned before it was ever polled; the runtime was then dropped
//! with the task still in the queue. Detached is not "later". Once the runtime
//! goes, it is never.
//!
//! It stayed invisible because a leaked database breaks nothing locally: tests
//! pass, the disk grows a little. It surfaced only at scale — ~246 WiredTiger
//! files per database (one per collection AND per index) crossed mongod's
//! 64 000-descriptor ceiling around the 260th database and aborted the server
//! mid-suite (`EMFILE` → fatal assertion 50853), which then read as dozens of
//! unrelated tests failing on `Connection refused`.
//!
//! CI asserts this too, but a check that lives only in one workflow only ever
//! protects that workflow. This one travels with the suite — build host, WSL,
//! a laptop — wherever it is run.

use crate::fixtures::test_app::TestApp;
use mongodb::Client;

/// `TestApp`'s teardown must actually drop the database, before `drop` returns.
#[tokio::test]
async fn testapp_teardown_drops_its_database() {
    let app = TestApp::spawn().await;
    let db_name = app.db.name().to_string();
    let uri = app.settings.database.url.clone();

    // Observe through a SEPARATE client. The point of the test is what is true
    // of the server, not what the about-to-be-torn-down client believes.
    let probe = Client::with_uri_str(&uri)
        .await
        .expect("probe client should reach the test mongod");

    // ⚠️ The precondition is load-bearing, not decoration. Without it, a
    // database that never existed would satisfy the assertion below and this
    // test would pass while proving nothing — the exact vacuous-green shape it
    // exists to rule out.
    let before = probe
        .list_database_names()
        .await
        .expect("listDatabases should succeed");
    assert!(
        before.iter().any(|n| n == &db_name),
        "precondition failed: {db_name} does not exist while its TestApp is \
         alive, so this test cannot say anything about teardown"
    );

    drop(app);

    let after = probe
        .list_database_names()
        .await
        .expect("listDatabases should succeed");
    assert!(
        !after.iter().any(|n| n == &db_name),
        "TestApp's teardown did not drop {db_name}. Cleanup must complete \
         BEFORE `drop` returns — a detached `tokio::spawn` here never runs at \
         all, because this test's current-thread runtime is dropped with the \
         task still queued. Left unfixed, each leaked database holds ~246 \
         WiredTiger files open and a full suite exhausts mongod's descriptors \
         mid-run."
    );
}

/// Regression test for post-`dropDatabase` DB resurrection:
///
/// Many test rigs (`Rig`, `TwoRelays`, `Searchable`, and in-process agent
/// loops) store `app: TestApp` as their first struct field and keep live
/// HTTP/WebSocket connections or background tasks in later fields. Rust drops
/// struct fields in declaration order, so `app` drops BEFORE those sockets
/// close. Without severing `TestApp`'s server and Mongo gate in `Drop`, an
/// already-accepted connection or detached handler writes (`insert_one` /
/// `upsert`) milliseconds AFTER `dropDatabase` and resurrects the dropped DB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn testapp_teardown_severs_post_drop_writers() {
    let app = TestApp::spawn().await;
    let db_name = app.db.name().to_string();
    let uri = app.settings.database.url.clone();
    let probe = Client::with_uri_str(&uri).await.expect("probe client");

    // Warm a pooled HTTP/1.1 keep-alive connection on `app.client` BEFORE drop,
    // matching rigs/tasks whose connection outlives `TestApp` field drop order.
    let _seeded = app.seed_tenant("teardown-keepalive").await;
    let keepalive_client = app.client.clone();
    let register_url = app.url("/api/auth/register");

    drop(app);

    let _ = keepalive_client
        .post(&register_url)
        .json(&serde_json::json!({
            "email": "ghost-after-drop@test.meshharbor.invalid",
            "username": "ghostafterdrop",
            "display_name": "Ghost After Drop",
            "password": "Password123!",
        }))
        .send()
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let after = probe.list_database_names().await.expect("listDatabases");
    assert!(
        !after.iter().any(|n| n == &db_name),
        "post-drop connection resurrected {db_name} after TestApp::drop"
    );
}

/// `TestApp::spawn_pair` points two pods at ONE shared database: dropping pod 1
/// must keep the shared database alive for pod 2, and dropping pod 2 must leave
/// zero database behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn testapp_spawn_pair_refcounts_shared_database() {
    let (app1, app2) = TestApp::spawn_pair(|_| {}).await;
    let pair_db = app1.db.name().to_string();
    let uri = app1.settings.database.url.clone();
    assert_eq!(pair_db, app2.db.name());
    let probe = Client::with_uri_str(&uri).await.expect("probe client");
    let _seeded = app1.seed_tenant("pair-refcount").await;

    drop(app1);
    let mid_pair = probe.list_database_names().await.expect("listDatabases");
    assert!(
        mid_pair.iter().any(|n| n == &pair_db),
        "dropping pod 1 of spawn_pair prematurely dropped shared DB {pair_db}"
    );

    drop(app2);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let after_pair = probe.list_database_names().await.expect("listDatabases");
    assert!(
        !after_pair.iter().any(|n| n == &pair_db),
        "spawn_pair leaked shared DB {pair_db} after both pods dropped"
    );
}
