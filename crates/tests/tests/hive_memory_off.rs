// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1e-4 — the device's gate, end to end: with `hive_core_memory` off
//! (the default), a session gets none of the org's core memory although the
//! server sent it, and its transcript says why.
//!
//! The pair of `hive_memory.rs`, which runs the same device with the gate on
//! and finds both files: the same harness, the same facts, only the gate
//! differs. Its own binary because the device's Hive supervisor is
//! process-global. The absence here means something because the transcript
//! shows the frame ARRIVED — the server rendered a snapshot, pinned its
//! revision, sent it to a device that advertises `hive-memory` — and the
//! device's own setting is what kept it from the session.
#![cfg(target_os = "linux")]

use meshharbor_tests::fixtures::test_app::TestApp;
use serde_json::json;

mod hive_support;
use hive_support::*;

#[test]
fn a_device_whose_owner_did_not_opt_in_shows_its_sessions_no_core_memory() {
    let joined = std::thread::Builder::new()
        .name("hive-memory-off".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario())
        })
        .unwrap()
        .join();
    if let Err(panic) = joined {
        std::panic::resume_unwind(panic);
    }
}

async fn scenario() {
    let fact = random("orgfact");
    let on_device = random("devicefact");

    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hivememoff").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let dev = memory_device(&app, &seeded, false).await;

    let (st, body) = keep_fact(&app, &tid, &admin, json!({"scope": "org", "text": fact})).await;
    assert_eq!(st, 200, "the org fact is kept: {body}");
    let (st, body) = keep_fact(
        &app,
        &tid,
        &admin,
        json!({"scope": "device", "owner_id": dev.id, "text": on_device}),
    )
    .await;
    assert_eq!(st, 200, "the device fact is kept: {body}");

    let a = start(&app, &seeded, &dev.id, &dev.work_a).await;
    let sid = a["id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid, "idle").await,
        "the session never came up"
    );
    let launched = until_file(&dev.work_a, ".launched").await.is_some();

    let mut ws = UserWs::open(&app, &admin).await;
    let mut viewer = view(&mut ws, &sid).await;
    let note = transcript_note(&mut viewer, "This start came with").await;
    viewer.close(&mut ws).await;
    let rev = session(&app, &seeded, &sid).await["brain_rev"].as_i64();

    let config = dev.config_dir(&sid);
    let given = [
        dev.work_a.join(".claude_md").exists(),
        dev.work_a.join(".memory_md").exists(),
    ];
    let in_config = [
        files_named(&config, "CLAUDE.md"),
        files_named(&config, "MEMORY.md"),
    ];
    let written = dev.runtime_memory(&sid).exists();
    dev.stop().await;

    assert!(launched, "the harness ran");
    let rev = rev.expect("the server rendered a snapshot and pinned its revision");
    assert!(
        note.as_deref()
            .is_some_and(|n| n.contains(&format!("brain revision {rev})"))
                && n.contains("hive_core_memory is off")),
        "the frame arrived, and the transcript says why the session has none: {note:?}"
    );
    assert_eq!(given, [false, false], "the harness found no core memory");
    assert!(
        in_config.iter().all(Vec::is_empty),
        "nothing where Claude Code reads it: {in_config:?}"
    );
    assert!(!written, "the daemon did not even write its own copy");
}
