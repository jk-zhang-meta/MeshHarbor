// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2g-3d — the device's own clock, end to end: a real server, and
//! each device a process of its own (this test binary again, asked to be a
//! device by [`device_process`], which an ordinary run passes at once). The
//! server's retention sweep is OFF here, so only a device's clock can purge.
//!
//! | step | the devices | what the test reads |
//! |---|---|---|
//! | a session on A, B its member; a prompt | A runs it and checkpoints; B follows the stream | B's copy at A's checkpoint |
//! | the owner stops it; it ended two days ago, its org keeps one | A ends the run | the record `ended` |
//! | B comes back | B asks what keeps its copy, hears the end, and purges it on its own clock | B's row refused `purged`, as its manifest says |
//! | each store | B keeps only the purged id; A, connected all along with a live word, keeps its copy | B's store `is_purged`, A's events |
//!
//! ⚠️ The stream rides `direct` on loopback: the tests build carries no
//! overlay, as in the canary. ⚠️ A process holds one supervisor, so neither
//! device runs in this one.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use meshharbor_tests::fixtures::seed::SeededTenant;
use meshharbor_tests::fixtures::test_app::TestApp;
use serde_json::{Value, json};

mod hive_support;
use hive_support::*;

/// A stand-in for Claude Code: one answer and a turn's end per prompt.
const HARNESS: &str = r#"#!/bin/sh
first=1
while IFS= read -r line; do
  case "$line" in
    *'"type":"control_request"'*)
      echo '{"type":"control_response","response":{"subtype":"success"}}'
      continue ;;
  esac
  if [ "$first" = 1 ]; then
    echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
    first=0
  fi
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
"#;

/// Set to a device's directory when the scenario starts this binary as that
/// device.
const DEVICE_ENV: &str = "HIVE_RETAIN_DEVICE";

/// How long a step that crosses the stream may take on a loaded runner.
const LONG: Duration = Duration::from_secs(90);

/// A device's process: this binary again, from the config the scenario
/// enrolled and saved in its directory, until its stdin closes. An ordinary
/// run passes it at once. With `RUST_LOG` set, it logs to its stderr.
#[test]
fn device_process() {
    let Ok(dir) = std::env::var(DEVICE_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let name = format!(
        "device-{}",
        dir.file_name().unwrap_or_default().to_string_lossy()
    );
    if std::env::var("RUST_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .with_thread_names(true)
            .try_init();
    }
    let joined = std::thread::Builder::new()
        .name(name.clone())
        .stack_size(16 << 20)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name(name)
                .build()
                .unwrap();
            rt.block_on(async move {
                let cfg = meshharbord::config::load(&dir.join("config.toml"))
                    .expect("the device's config");
                meshharbord::hive::init_as_daemon(
                    &cfg,
                    &dir.join("hive.db"),
                    &dir.join("run"),
                    &dir.join("home"),
                )
                .expect("the device's launcher");
                let (stop, stop_rx) = tokio::sync::watch::channel(false);
                let device = spawn_device(cfg, stop_rx);
                // Until the scenario closes our stdin.
                let _ = tokio::task::spawn_blocking(|| {
                    let mut sink = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink);
                })
                .await;
                let _ = stop.send(true);
                let _ = tokio::time::timeout(Duration::from_secs(10), device).await;
            });
        })
        .unwrap()
        .join();
    if let Err(panic) = joined {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn a_member_back_after_its_sessions_days_purges_its_copy_on_its_own_clock() {
    // Its own thread with a deep stack, and a current-thread runtime, as the
    // canary: several servers' worth of tasks live in one body.
    let joined = std::thread::Builder::new()
        .name("hive-retain".into())
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

/// A device's directory: a folder root with `work` in it, a home, the
/// harness. Its `work`.
fn device_dir(dir: &Path) -> PathBuf {
    let work = dir.join("roots").join("work");
    for d in [&work, &dir.join("home")] {
        std::fs::create_dir_all(d).unwrap();
    }
    let harness = dir.join("claude");
    std::fs::write(&harness, HARNESS).unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    work
}

/// A device that runs the owner's sessions and holds copies of them.
fn runs_and_holds(cfg: &mut meshharbord::config::AgentConfig, seeded: &SeededTenant, dir: &Path) {
    cfg.hive_enabled = true;
    cfg.hive_replica = true;
    cfg.hive_accounts
        .insert(seeded.admin.id.clone(), "keeper".into());
    cfg.hive_roots = vec![dir.join("roots").display().to_string()];
    cfg.hive_harness = Some(dir.join("claude").display().to_string());
}

/// The device `cfg` describes, as a process of its own, online.
async fn device(
    app: &TestApp,
    seeded: &SeededTenant,
    dir: &Path,
    cfg: &meshharbord::config::AgentConfig,
) -> tokio::process::Child {
    meshharbord::config::save(&dir.join("config.toml"), cfg).expect("the device's config");
    let child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "device_process",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DEVICE_ENV, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("the device's process");
    wait_online(app, seeded, &cfg.agent_id).await;
    child
}

/// Close the device's stdin and wait for its process to end.
async fn stop(mut child: tokio::process::Child) {
    drop(child.stdin.take());
    let _ = tokio::time::timeout(Duration::from_secs(20), child.wait()).await;
}

/// Poll until the server no longer holds the device online.
async fn wait_offline(app: &TestApp, seeded: &SeededTenant, agent_id: &str) {
    let deadline = Instant::now() + WAIT;
    loop {
        let row: Value = app
            .auth_get(
                &format!("/api/tenant/{}/agent/{agent_id}", seeded.tenant_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap_or(Value::Null);
        if row["status"].as_str() == Some("offline") {
            return;
        }
        assert!(Instant::now() < deadline, "the device never went offline");
        tokio::time::sleep(POLL).await;
    }
}

/// `device`'s row in the session's replicaset, as the server keeps it.
fn member<'a>(s: &'a Value, device: &str) -> Option<&'a Value> {
    s["replicaset"]["members"]
        .as_array()?
        .iter()
        .find(|m| m["device_id"] == device)
}

/// Poll the session until `pred` holds, within `bound`.
async fn until_session(
    app: &TestApp,
    seeded: &SeededTenant,
    sid: &str,
    bound: Duration,
    what: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + bound;
    loop {
        let s = session(app, seeded, sid).await;
        if pred(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "{what}: {s}");
        tokio::time::sleep(POLL).await;
    }
}

/// Every event of `sid` the store at `db` holds, and whether it keeps `sid`
/// purged. Read with the device stopped: the store is its own.
fn held(db: &Path, sid: &str) -> (usize, bool) {
    let store = meshharbor_hive_node::store::Store::open(db).expect("the device's store");
    let events = store.page(sid, 0, 100_000).expect("its copy").len();
    (events, store.is_purged(sid).expect("its purged ids"))
}

/// The word the store at `db` keeps for `sid`: its days, and the end it
/// names. Read with the device stopped.
fn word_of(db: &Path, sid: &str) -> Option<(u32, Option<i64>)> {
    let store = meshharbor_hive_node::store::Store::open(db).expect("the device's store");
    store
        .retains()
        .expect("its words")
        .into_iter()
        .find(|w| w.session == sid)
        .map(|w| (w.days, w.ended_ms))
}

async fn scenario() {
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        // Only a device's clock purges here.
        s.hive.retention_sweep_secs = 0;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hiveretain").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let dir = tempfile::tempdir().unwrap();
    let policy = json!({
        "replicaset": {
            "min": 2, "max": 4, "archive": true,
            "prefer": ["owner_devices"], "restricted_tags": ["prod"],
        },
        "retention_days": 1,
        "archive_devices": [],
        "revision": 0,
    });
    let resp = app
        .auth_put(&format!("/api/tenant/{tid}/hive/policy"), &owner)
        .json(&policy)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);

    // ── A and B, each in a process of its own, each holding copies ─────────
    let a_dir = dir.path().join("a");
    let a_work = device_dir(&a_dir);
    let mut a_cfg = enrol(&app, &seeded, "hive-retain-a").await;
    runs_and_holds(&mut a_cfg, &seeded, &a_dir);
    let a = a_cfg.agent_id.clone();
    let a_proc = device(&app, &seeded, &a_dir, &a_cfg).await;
    let b_dir = dir.path().join("b");
    device_dir(&b_dir);
    let mut b_cfg = enrol(&app, &seeded, "hive-retain-b").await;
    runs_and_holds(&mut b_cfg, &seeded, &b_dir);
    let b = b_cfg.agent_id.clone();
    let b_proc = device(&app, &seeded, &b_dir, &b_cfg).await;

    // ── The session on A, B its member, and a prompt ───────────────────────
    let s = start(&app, &seeded, &a, &a_work).await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid, "idle").await,
        "the session never came up"
    );
    until_session(&app, &seeded, &sid, LONG, "B never took its copy", |s| {
        member(s, &b).is_some_and(|m| m["state"] == "joined")
    })
    .await;
    let mut ws = UserWs::open(&app, &owner).await;
    let mut on_a = view(&mut ws, &sid).await;
    on_a.send(json!({"op": "hello"})).await;
    let hello = on_a.recv_op("hello").await;
    let tip = hello["tip"].as_u64().unwrap_or(0);
    on_a.send(json!({"op": "follow", "after": tip})).await;
    on_a.send(json!({"op": "prompt", "id": "p1", "text": "a prompt"}))
        .await;
    assert_eq!(on_a.recv_op("prompt").await["ok"], true);
    on_a.events_until(|e| e["event"]["kind"] == "turn").await;
    on_a.close(&mut ws).await;
    until_session(&app, &seeded, &sid, LONG, "B's copy never caught up", |s| {
        let a_cp = member(s, &a).and_then(|m| m["tip"]["checkpoint_seq"].as_u64());
        let b_cp = member(s, &b).and_then(|m| m["tip"]["checkpoint_seq"].as_u64());
        a_cp.is_some() && a_cp == b_cp
    })
    .await;

    // ── The session ends; as if it had two days ago, its org keeping one ──
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/stop"),
            &owner,
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{:?}", resp.text().await);
    assert!(
        reached(&app, &seeded, &sid, "ended").await,
        "the session never ended"
    );
    let two_days_ago =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 2 * 86_400_000);
    app.db
        .collection::<bson::Document>("agent_sessions")
        .update_one(
            bson::doc! { "_id": bson::oid::ObjectId::parse_str(&sid).unwrap() },
            bson::doc! { "$set": { "ended_at": two_days_ago } },
        )
        .await
        .unwrap();

    // ── B goes and comes back: it hears the end, and its clock purges ──────
    stop(b_proc).await;
    wait_offline(&app, &seeded, &b).await;
    let (b_events, b_purged) = held(&b_dir.join("hive.db"), &sid);
    assert!(
        b_events > 0 && !b_purged,
        "B holds a copy: {b_events} events"
    );
    // B connected before the session existed, so the word it keeps is the
    // one it asked for when it took its copy: a live session's.
    assert_eq!(
        word_of(&b_dir.join("hive.db"), &sid),
        Some((1, None)),
        "B kept the word it asked for when it took its copy"
    );
    let began = Instant::now();
    let b_proc = device(&app, &seeded, &b_dir, &b_cfg).await;
    let s = until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "B's manifest never said its clock purged its copy",
        |s| member(s, &b).is_some_and(|m| m["state"] == "refused"),
    )
    .await;
    eprintln!(
        "hive_retain: B purged on its own clock within {} ms of coming back",
        began.elapsed().as_millis()
    );
    assert_eq!(
        member(&s, &b).unwrap()["refusal"],
        "purged",
        "its row says how: {s}"
    );

    // ── Each store: B keeps only the purged id; A, connected throughout with
    //    a live session's word, keeps its copy ─────────────────────────────
    stop(a_proc).await;
    stop(b_proc).await;
    assert_eq!(
        held(&b_dir.join("hive.db"), &sid),
        (0, true),
        "B's store keeps only the purged id"
    );
    let (a_events, a_purged) = held(&a_dir.join("hive.db"), &sid);
    assert!(
        a_events > 0 && !a_purged,
        "A was connected throughout, its word a live session's: {a_events} events"
    );
    assert_eq!(
        word_of(&a_dir.join("hive.db"), &sid),
        Some((1, None)),
        "A kept the word it asked for when it started the session"
    );
}
