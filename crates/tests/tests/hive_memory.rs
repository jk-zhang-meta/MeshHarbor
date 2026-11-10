// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1e-4 — AC8, end to end: a fact kept in the org's brain reaches the
//! NEXT session's core memory and not the running one, and a write over a
//! scope's budget fails visibly.
//!
//! A real server and a real device in-process, in a binary of its own like
//! the canary (`hive_canary.rs`): the device's Hive supervisor is
//! process-global. This device's owner turned core memory on
//! (`hive_core_memory`); the gate off is `hive_memory_off.rs`, a binary of its
//! own for the same reason. The harness records what it finds where Claude
//! Code reads core memory, at its start and at every turn
//! (`MEMORY_HARNESS`): what a model would have been given.
//!
//! | step | session A, running | session B, started after |
//! |---|---|---|
//! | an org fact and a device fact are kept, then A starts | `CLAUDE.md` holds the org fact, the auto-memory `MEMORY.md` the device fact | — |
//! | a second org fact is kept | unchanged, at its next turn too | — |
//! | B starts | — | both org facts, at a later revision |
//! | org facts past the budget | `409 over_budget` with the numbers; nothing evicted | — |
#![cfg(target_os = "linux")]

use meshharbor_tests::fixtures::test_app::TestApp;
use serde_json::{Value, json};

mod hive_support;
use hive_support::*;

#[test]
fn a_fact_reaches_the_next_session_and_not_the_running_one() {
    // Its own thread with a deep stack, and a current-thread runtime, as the
    // canary: several servers' worth of tasks live in one body.
    let joined = std::thread::Builder::new()
        .name("hive-memory".into())
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
    let first = random("orgfirst");
    let second = random("orgsecond");
    let on_device = random("devicefact");

    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hivemem").await;
    let tid = seeded.tenant_id.clone();
    let admin = seeded.admin.access_token.clone();
    let dev = memory_device(&app, &seeded, true).await;

    // ── An org fact and a device fact; session A starts ─────────────────────
    let (st, body) = keep_fact(&app, &tid, &admin, json!({"scope": "org", "text": first})).await;
    assert_eq!(st, 200, "the org fact is kept: {body}");
    let (st, body) = keep_fact(
        &app,
        &tid,
        &admin,
        json!({"scope": "device", "owner_id": dev.id, "text": on_device, "kind": "path"}),
    )
    .await;
    assert_eq!(st, 200, "the device fact is kept: {body}");

    let a = start(&app, &seeded, &dev.id, &dev.work_a).await;
    let sid_a = a["id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid_a, "idle").await,
        "A never came up"
    );
    // Both copies are made before `.launched`: read neither before it.
    until_file(&dev.work_a, ".launched").await;
    let a_claude = std::fs::read_to_string(dev.work_a.join(".claude_md")).ok();
    let a_memory = std::fs::read_to_string(dev.work_a.join(".memory_md")).ok();

    // ── A second org fact, while A runs ──────────────────────────────────────
    let (st, body) = keep_fact(&app, &tid, &admin, json!({"scope": "org", "text": second})).await;
    assert_eq!(st, 200, "the second org fact is kept: {body}");

    // What A's transcript says it was given; then A's next turn, and what
    // its harness finds then.
    let mut ws = UserWs::open(&app, &admin).await;
    let mut viewer = view(&mut ws, &sid_a).await;
    let a_note = transcript_note(&mut viewer, "Core memory").await;
    viewer
        .send(json!({"op": "prompt", "id": "a1", "text": "the next turn"}))
        .await;
    assert_eq!(viewer.recv_op("prompt").await["ok"], true);
    until_file(&dev.work_a, ".turned").await;
    let a_turn = std::fs::read_to_string(dev.work_a.join(".claude_md.turn")).ok();
    viewer.close(&mut ws).await;

    // ── Session B starts after the second fact ───────────────────────────────
    let b = start(&app, &seeded, &dev.id, &dev.work_b).await;
    let sid_b = b["id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid_b, "idle").await,
        "B never came up"
    );
    until_file(&dev.work_b, ".launched").await;
    let b_claude = std::fs::read_to_string(dev.work_b.join(".claude_md")).ok();

    // ── Past the org's budget ────────────────────────────────────────────────
    // Facts of the longest kind until one does not fit.
    let mut refusal = None;
    for _ in 0..8 {
        let pad: String = format!("{} {}", random("pad"), "x".repeat(500))
            .chars()
            .take(500)
            .collect();
        let (st, body) = keep_fact(&app, &tid, &admin, json!({"scope": "org", "text": pad})).await;
        if st == 409 {
            refusal = Some(body);
            break;
        }
        assert_eq!(st, 200, "a fact that fits is kept: {body}");
    }
    let brain: Value = app
        .auth_get(&format!("/api/tenant/{tid}/hive/brain"), &admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rev_a = session(&app, &seeded, &sid_a).await["brain_rev"].as_i64();
    let rev_b = session(&app, &seeded, &sid_b).await["brain_rev"].as_i64();
    dev.stop().await;

    // ── Session A: the org fact and the device fact, and nothing later ───────
    let a_claude = a_claude.expect("A's harness found CLAUDE.md where Claude Code reads it");
    assert!(a_claude.contains(&first), "{a_claude}");
    assert!(!a_claude.contains(&second), "{a_claude}");
    assert!(
        a_memory.as_deref().is_some_and(|m| m.contains(&on_device)),
        "the device fact, in the auto-memory index: {a_memory:?}"
    );
    assert_eq!(
        a_turn.as_deref(),
        Some(a_claude.as_str()),
        "a fact kept while A runs never reaches A, not even at its next turn"
    );
    let (rev_a, rev_b) = (rev_a.expect("A pinned a revision"), rev_b.expect("B too"));
    assert!(
        a_note
            .as_deref()
            .is_some_and(|n| n.contains(&format!("revision {rev_a}:"))),
        "A's transcript names the revision it got ({rev_a}): {a_note:?}"
    );

    // ── Session B: both org facts ────────────────────────────────────────────
    let b_claude = b_claude.expect("B's harness found CLAUDE.md");
    assert!(
        b_claude.contains(&first) && b_claude.contains(&second),
        "the next session gets the fact: {b_claude}"
    );
    assert!(
        rev_b > rev_a,
        "B pinned a later revision: {rev_b} vs {rev_a}"
    );

    // ── The budget: refused visibly, with the numbers; nothing evicted ──────
    let refusal = refusal.expect("a write past the org's budget is refused");
    assert_eq!(refusal["error"], "over_budget", "{refusal}");
    assert_eq!(refusal["scope"], "org", "{refusal}");
    assert_eq!(refusal["budget"], 3000, "{refusal}");
    assert_eq!(refusal["needed"], 500, "{refusal}");
    let used = refusal["used"].as_i64().unwrap();
    assert!(used <= 3000 && used + 500 > 3000, "{refusal}");
    assert!(
        refusal["message"].as_str().is_some_and(|m| !m.is_empty()),
        "said in words: {refusal}"
    );
    let org_used = brain["budgets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["scope"] == "org")
        .and_then(|b| b["used"].as_i64());
    assert_eq!(org_used, Some(used), "the refused write spent nothing");
    let kept: Vec<&str> = brain["facts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["text"].as_str())
        .collect();
    assert!(
        kept.contains(&first.as_str()) && kept.contains(&second.as_str()),
        "nothing is evicted to make room: {kept:?}"
    );
}
