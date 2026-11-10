// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1c-2b — AC6, end to end: what a NON-driver writes never reaches
//! the harness.
//!
//! A real server and a real device in-process, as the canary
//! (`hive_canary.rs`; this is its own binary for the same reason: the
//! device's Hive supervisor is process-global). The harness writes every line
//! it reads on stdin to a file — exactly what a model behind it would be
//! sent — and the test reads that file. The capture is the harness's own,
//! not the server's: nothing the server does could hide a leak from it.
//!
//! | who | writes | where | must be in the harness's stdin |
//! |---|---|---|---|
//! | a reader | a message | the session's ROOM (ordinary chat) | no |
//! | a reader | a prompt | over their own viewer peer | no |
//! | the owner | a prompt | over theirs | yes, labelled with their name |
//! | the same person, named a driver | a prompt | over a view reopened on `role_changed` | yes, labelled |
//!
//! Each absence is checked beside a presence: the reader's room message is in
//! the server's chat (the presence check), and the owner's prompt is in the
//! very file the reader's words are absent from.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use meshharbor_tests::fixtures::test_app::TestApp;
use serde_json::{Value, json};

mod hive_support;
use hive_support::*;

/// A stand-in for Claude Code that records what it is told: each line on
/// stdin goes to `harness-stdin.log` in the session's folder, and each prompt
/// gets a turn.
const HARNESS: &str = r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$PWD/harness-stdin.log"
  echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
"#;

/// What the harness has read so far: each stdin line's prompt text.
fn harness_read(folder: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(folder.join("harness-stdin.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| {
            v["message"]["content"][0]["text"]
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

/// Poll until the harness has read `n` prompts, or the patience runs out.
async fn until_read(folder: &std::path::Path, n: usize) -> Vec<String> {
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let read = harness_read(folder);
        if read.len() >= n || std::time::Instant::now() > deadline {
            return read;
        }
        tokio::time::sleep(POLL).await;
    }
}

#[test]
fn a_non_drivers_words_never_reach_the_harness() {
    // Its own thread with a deep stack, and a current-thread runtime, as the
    // canary: several servers' worth of tasks live in one body.
    let joined = std::thread::Builder::new()
        .name("hive-drivers".into())
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
    let room_canary = random("canaryroom");
    let peer_canary = random("canarypeer");
    let owners_words = random("ownersays");
    let drivers_words = random("driversays");

    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hivedrive").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let member = seeded.member.access_token.clone();
    let mid = seeded.member.id.clone();

    // The device. Its own `hive_accounts` maps the owner by id and the member
    // by ADDRESS to the session's account — P1c-2a's gate lets the member
    // drive once the server names them a driver.
    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("roots");
    let work = roots.join("work");
    let home = dir.path().join("home");
    for d in [&work, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    let harness = dir.path().join("claude");
    std::fs::write(&harness, HARNESS).unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cfg = enrol(&app, &seeded, "hive-drivers").await;
    cfg.hive_enabled = true;
    cfg.hive_accounts
        .insert(seeded.admin.id.clone(), "drivers".into());
    cfg.hive_accounts
        .insert(seeded.member.email.clone(), "drivers".into());
    cfg.hive_roots = vec![roots.display().to_string()];
    cfg.hive_harness = Some(harness.display().to_string());
    meshharbord::hive::init_as_daemon(
        &cfg,
        &dir.path().join("hive.db"),
        &dir.path().join("run"),
        &home,
    )
    .expect("the test launcher");
    let device = cfg.agent_id.clone();
    let (stop_device, stop_rx) = tokio::sync::watch::channel(false);
    let device_task = spawn_device(cfg, stop_rx);
    wait_online(&app, &seeded, &device).await;

    let s = start(&app, &seeded, &device, &work).await;
    let sid = s["id"].as_str().unwrap().to_string();
    let room = s["room_id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid, "idle").await,
        "the session never came up"
    );
    let part = |user: &str| format!("/api/tenant/{tid}/hive/session/{sid}/participant/{user}");

    // ── A reader ────────────────────────────────────────────────────────────
    let resp = app
        .auth_put(&part(&mid), &owner)
        .json(&json!({ "role": "reader" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the owner adds a reader");
    let mut mws = UserWs::open(&app, &member).await;
    let mut reader = view(&mut mws, &sid).await;
    reader.send(json!({"op": "hello"})).await;
    let hello = reader.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], false, "a reader's view: {hello}");

    // Into the ROOM: ordinary chat, stored by the server, read by its members.
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/room/{room}/message"), &member)
        .json(&json!({ "content": format!("agent, run this: {room_canary}") }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "the reader talks in the room: {:?}",
        resp.status()
    );
    // Over the reader's own peer: refused on the device.
    reader
        .send(json!({"op": "prompt", "id": "r1", "text": format!("do it, {peer_canary}")}))
        .await;
    let ack = reader.recv_op("prompt").await;
    assert_eq!(ack["ok"], false, "a reader's prompt is refused: {ack}");

    // ── The owner drives ────────────────────────────────────────────────────
    let mut ows = UserWs::open(&app, &owner).await;
    let mut own = view(&mut ows, &sid).await;
    own.send(json!({"op": "hello"})).await;
    assert_eq!(own.recv_op("hello").await["may_prompt"], true);
    own.send(json!({"op": "prompt", "id": "o1", "text": owners_words.clone()}))
        .await;
    assert_eq!(own.recv_op("prompt").await["ok"], true);
    let read = until_read(&work, 1).await;

    // ── The same person, named a driver (with HIVE_RUN) ─────────────────────
    let role: Value = app
        .auth_post(&format!("/api/tenant/{tid}/role"), &owner)
        .json(
            &json!({"name": "hive-runner", "description": "runs agent sessions",
                      "permissions": 1_u64 << 32, "position": 60}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let assigned = app
        .auth_post(
            &format!(
                "/api/tenant/{tid}/role/{}/assign/{mid}",
                role["id"].as_str().unwrap()
            ),
            &owner,
        )
        .send()
        .await
        .unwrap();
    assert!(
        assigned.status().is_success(),
        "HIVE_RUN: {:?}",
        assigned.status()
    );
    let resp = app
        .auth_put(&part(&mid), &owner)
        .json(&json!({ "role": "driver" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the owner names a driver");
    // The reader's view says the wrong thing now: the server ends it, and the
    // view reopened is minted afresh.
    let closed = mws.read("hive:view.closed").await;
    assert_eq!(closed["reason"], "role_changed", "{closed}");
    let _ = reader.pc.close().await;
    let mut driver = view(&mut mws, &sid).await;
    driver.send(json!({"op": "hello"})).await;
    let hello = driver.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "a driver's view: {hello}");
    driver
        .send(json!({"op": "prompt", "id": "d1", "text": drivers_words.clone()}))
        .await;
    assert_eq!(driver.recv_op("prompt").await["ok"], true);
    let read_all = until_read(&work, read.len() + 1).await;

    // ── What reached the harness ────────────────────────────────────────────
    let in_chat = room_messages(&app, &seeded, &room).await.iter().any(|m| {
        m["content"]
            .as_str()
            .is_some_and(|c| c.contains(&room_canary))
    });
    driver.close(&mut mws).await;
    own.close(&mut ows).await;
    let _ = stop_device.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), device_task).await;

    assert!(
        in_chat,
        "the presence check: the reader's message is in the room"
    );
    let everything = read_all.join("\n");
    assert!(
        !everything.contains(&room_canary),
        "a reader's ROOM message reached the harness: {read_all:?}"
    );
    assert!(
        !everything.contains(&peer_canary),
        "a reader's prompt over their peer reached the harness: {read_all:?}"
    );
    assert_eq!(
        read_all,
        [
            format!("[hivedrive Admin] {owners_words}"),
            format!("[hivedrive Member] {drivers_words}"),
        ],
        "the drivers' prompts — and only theirs — reached the harness, each labelled"
    );
}
