// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2g — a session purged for real, end to end (AC11's shape): a real
//! server, and each device a process of its own (this test binary again,
//! asked to be a device by [`device_process`], which an ordinary run passes
//! at once). Nothing is seeded on the record: the route issues the purge, and
//! each device's answer is its own frame, from its own purge (P2g-1).
//!
//! | step | the devices | what the test reads |
//! |---|---|---|
//! | a session on A, B its member; a prompt | A runs it and checkpoints the turn's end; B follows the stream | B's copy, in its own store |
//! | B goes offline; `DELETE …/session/{sid}` | A stops the run, purges its copy and, as the account, the session's state directory | the answer `purging`; A's part `done` / `done`; A's harness gone, its runtime and state directories gone; the session and its room gone for the owner |
//! | B comes back | B hears its purge first and purges its copy | B's part `done` / `not_there`; the purge complete, its tombstone gone |
//! | each store | it keeps the purged id, and nothing else of the session | `is_purged`, and no event of it |
//!
//! P2g-4a, a second scenario on the same pair: A, the primary, is removed
//! from the organization while online.
//!
//! | step | the devices | what the test reads |
//! |---|---|---|
//! | `DELETE …/agent/{a}` | A is told to stop the session, then to purge all it holds | the session ended `device_removed` |
//! | A runs on | A stops the run, purges its copy and, as the account, the session's state directory | A's harness gone, its runtime and state directories gone |
//! | each store | A keeps the purged id and nothing else of it; B, which stays, keeps its copy | `is_purged`, and the events |
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

/// A stand-in for Claude Code, as far as a purge asks: it keeps the session's
/// history where Claude Code does (the path the launch names), and writes its
/// pid to `$HOME/harness.pid`, so the test sees the run stop.
const HARNESS: &str = r#"#!/bin/sh
echo $$ > "$HOME/harness.pid"
sid=""; prev=""
for a in "$@"; do
  case "$prev" in --session-id|--resume) sid="$a" ;; esac
  prev="$a"
done
hist="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/$sid.jsonl"
first=1
while IFS= read -r line; do
  case "$line" in
    *'"type":"control_request"'*)
      echo '{"type":"control_response","response":{"subtype":"success"}}'
      continue ;;
  esac
  mkdir -p "${hist%/*}" && printf '%s\n' "$line" >> "$hist"
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
const DEVICE_ENV: &str = "HIVE_PURGE_DEVICE";

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
                let cfg =
                    meshharbord::config::load(&dir.join("config.toml")).expect("the device's config");
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
fn a_purge_reaches_a_member_that_was_offline_and_each_device_keeps_only_its_id() {
    run(Scenario::Purge);
}

/// P2g-4a — the primary of a running session, removed from its organization
/// while online: it stops the run, which ends `device_removed`, and purges
/// its copy and, as the account, what the account held of it. Its member,
/// which stays, keeps its copy.
#[test]
fn a_removed_device_purges_what_it_held_and_its_member_keeps_its_copy() {
    run(Scenario::Removal);
}

/// Which scenario a test runs.
#[derive(Clone, Copy, Debug)]
enum Scenario {
    Purge,
    Removal,
}

/// The scenario on its own thread with a deep stack, and a current-thread
/// runtime, as the canary: several servers' worth of tasks live in one body.
fn run(which: Scenario) {
    let joined = std::thread::Builder::new()
        .name(format!("hive-purge-{which:?}"))
        .stack_size(16 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    match which {
                        Scenario::Purge => scenario().await,
                        Scenario::Removal => removal().await,
                    }
                })
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
        .insert(seeded.admin.id.clone(), "purger".into());
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

/// The owner's read of the purge of `sid`.
async fn purge_view(app: &TestApp, seeded: &SeededTenant, sid: &str) -> Value {
    app.auth_get(
        &format!("/api/tenant/{}/hive/session/{sid}/purge", seeded.tenant_id),
        &seeded.admin.access_token,
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap_or(Value::Null)
}

/// Poll the purge of `sid` until `pred` holds, within `bound`.
async fn until_purge(
    app: &TestApp,
    seeded: &SeededTenant,
    sid: &str,
    bound: Duration,
    what: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + bound;
    loop {
        let p = purge_view(app, seeded, sid).await;
        if pred(&p) {
            return p;
        }
        assert!(Instant::now() < deadline, "{what}: {p}");
        tokio::time::sleep(POLL).await;
    }
}

/// `device`'s entry in a purge.
fn entry<'a>(p: &'a Value, device: &str) -> &'a Value {
    p["devices"]
        .as_array()
        .and_then(|d| d.iter().find(|e| e["device_id"] == device))
        .unwrap_or(&Value::Null)
}

/// Every event of `sid` the store at `db` holds, and whether it keeps `sid`
/// purged. Read with the device stopped: the store is its own.
fn held(db: &Path, sid: &str) -> (usize, bool) {
    let store = meshharbor_hive_node::store::Store::open(db).expect("the device's store");
    let events = store.page(sid, 0, 100_000).expect("its copy").len();
    (events, store.is_purged(sid).expect("its purged ids"))
}

/// Whether the process `pid` names is still there.
fn alive(pid: &str) -> bool {
    Path::new("/proc").join(pid.trim()).exists()
}

/// The server, `hive.replicaset` on, and an organization whose sessions are
/// copied to a second device.
async fn replicaset(tag: &str) -> (TestApp, SeededTenant) {
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant(tag).await;
    let policy = json!({
        "replicaset": {
            "min": 2, "max": 4, "archive": true,
            "prefer": ["owner_devices"], "restricted_tags": ["prod"],
        },
        "retention_days": 90,
        "archive_devices": [],
        "revision": 0,
    });
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/hive/policy", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&policy)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);
    (app, seeded)
}

/// A session on A, B its member, after a prompt whose turn B's copy holds;
/// each device a process of its own.
struct Pair {
    a: String,
    a_dir: PathBuf,
    a_proc: tokio::process::Child,
    b: String,
    b_cfg: meshharbord::config::AgentConfig,
    b_dir: PathBuf,
    b_proc: tokio::process::Child,
    sid: String,
    room: String,
    /// A's harness, which runs the session.
    a_pid: String,
    /// A's runtime directory of the session.
    a_run: PathBuf,
    /// What A's account holds of the session.
    a_state: PathBuf,
}

/// [`Pair`], its devices' directories under `dir`, its machines named after
/// `tag`.
async fn pair(app: &TestApp, seeded: &SeededTenant, dir: &Path, tag: &str) -> Pair {
    let owner = seeded.admin.access_token.clone();

    // ── A and B, each in a process of its own, each holding copies ─────────
    let a_dir = dir.join("a");
    let a_work = device_dir(&a_dir);
    let mut a_cfg = enrol(app, seeded, &format!("{tag}-a")).await;
    runs_and_holds(&mut a_cfg, seeded, &a_dir);
    let a = a_cfg.agent_id.clone();
    let a_proc = device(app, seeded, &a_dir, &a_cfg).await;
    let b_dir = dir.join("b");
    device_dir(&b_dir);
    let mut b_cfg = enrol(app, seeded, &format!("{tag}-b")).await;
    runs_and_holds(&mut b_cfg, seeded, &b_dir);
    let b = b_cfg.agent_id.clone();
    let b_proc = device(app, seeded, &b_dir, &b_cfg).await;

    // ── The session on A, B its member, and a prompt ───────────────────────
    let s = start(app, seeded, &a, &a_work).await;
    let sid = s["id"].as_str().unwrap().to_string();
    let room = s["room_id"].as_str().unwrap().to_string();
    assert!(
        reached(app, seeded, &sid, "idle").await,
        "the session never came up"
    );
    until_session(app, seeded, &sid, LONG, "B never took its copy", |s| {
        member(s, &b).is_some_and(|m| m["state"] == "joined")
    })
    .await;
    let mut ws = UserWs::open(app, &owner).await;
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
    // B's copy reached A's last checkpoint, as B last said.
    until_session(app, seeded, &sid, LONG, "B's copy never caught up", |s| {
        let a_cp = member(s, &a).and_then(|m| m["tip"]["checkpoint_seq"].as_u64());
        let b_cp = member(s, &b).and_then(|m| m["tip"]["checkpoint_seq"].as_u64());
        a_cp.is_some() && a_cp == b_cp
    })
    .await;
    let a_pid =
        std::fs::read_to_string(a_dir.join("home").join("harness.pid")).expect("A's harness ran");
    assert!(alive(&a_pid), "A's harness runs the session");
    let a_run = a_dir.join("run").join(&sid);
    assert!(a_run.exists(), "A holds the session's runtime directory");
    let a_state = a_dir.join("home").join(".roomler").join("hive").join(&sid);
    assert!(a_state.exists(), "A's account holds the session's state");
    Pair {
        a,
        a_dir,
        a_proc,
        b,
        b_cfg,
        b_dir,
        b_proc,
        sid,
        room,
        a_pid,
        a_run,
        a_state,
    }
}

async fn scenario() {
    let (app, seeded) = replicaset("hivepurge").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let dir = tempfile::tempdir().unwrap();
    let Pair {
        a,
        a_dir,
        a_proc,
        b,
        b_cfg,
        b_dir,
        b_proc,
        sid,
        room,
        a_pid,
        a_run,
        a_state,
    } = pair(&app, &seeded, dir.path(), "hive-purge").await;

    // ── B goes offline: its copy is in its store ───────────────────────────
    stop(b_proc).await;
    wait_offline(&app, &seeded, &b).await;
    let (b_events, b_purged) = held(&b_dir.join("hive.db"), &sid);
    assert!(
        b_events > 0 && !b_purged,
        "B holds a copy: {b_events} events"
    );

    // ── The purge: A, online, purges at once ───────────────────────────────
    let resp = app
        .auth_delete(&format!("/api/tenant/{tid}/hive/session/{sid}"), &owner)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let answer: Value = resp.json().await.unwrap();
    assert_eq!(answer["outcome"], "purging", "{answer}");
    let began = Instant::now();
    let p = until_purge(&app, &seeded, &sid, LONG, "A never answered", |p| {
        entry(p, &a)["state"] == "done"
    })
    .await;
    eprintln!("hive_purge: A purged in {} ms", began.elapsed().as_millis());
    assert_eq!(
        (
            entry(&p, &a)["store"].as_str(),
            entry(&p, &a)["account"].as_str()
        ),
        (Some("done"), Some("done")),
        "{p}"
    );
    assert_eq!(entry(&p, &b)["state"], "pending", "B is offline: {p}");
    assert!(p.get("done_at").is_none(), "{p}");
    assert!(!alive(&a_pid), "A's run of it stopped");
    assert!(!a_run.exists(), "A's runtime directory went");
    assert!(!a_state.exists(), "A's account state went");
    assert!(
        session(&app, &seeded, &sid).await["id"].is_null(),
        "the session is gone for its owner"
    );
    let resp = app
        .auth_get(
            &format!("/api/tenant/{tid}/room/{room}/message?per_page=10"),
            &owner,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "its room went with it");

    // ── B comes back: it hears its purge, and purges its copy ──────────────
    let b_proc = device(&app, &seeded, &b_dir, &b_cfg).await;
    let p = until_purge(
        &app,
        &seeded,
        &sid,
        LONG,
        "the purge never completed",
        |p| p["done_at"].is_string(),
    )
    .await;
    assert_eq!(
        (
            entry(&p, &b)["store"].as_str(),
            entry(&p, &b)["account"].as_str()
        ),
        (Some("done"), Some("not_there")),
        "B held a copy, and no workplace: it never ran the session: {p}"
    );
    let gone = app
        .db
        .collection::<bson::Document>("agent_sessions")
        .find_one(bson::doc! { "_id": bson::oid::ObjectId::parse_str(&sid).unwrap() })
        .await
        .unwrap();
    assert!(gone.is_none(), "the tombstone went with the purge");

    // ── Each store keeps the purged id, and nothing else of it ─────────────
    stop(a_proc).await;
    stop(b_proc).await;
    for (who, d) in [("A", &a_dir), ("B", &b_dir)] {
        let (events, purged) = held(&d.join("hive.db"), &sid);
        assert_eq!((events, purged), (0, true), "{who}'s store");
    }
}

/// P2g-4a — [`a_removed_device_purges_what_it_held_and_its_member_keeps_its_copy`].
async fn removal() {
    let (app, seeded) = replicaset("hiveremove").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let dir = tempfile::tempdir().unwrap();
    let p = pair(&app, &seeded, dir.path(), "hive-remove").await;

    // ── A, which runs the session, is removed while online ─────────────────
    let resp = app
        .auth_delete(&format!("/api/tenant/{tid}/agent/{}", p.a), &owner)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);
    let ended = session(&app, &seeded, &p.sid).await;
    assert_eq!(
        (ended["status"].as_str(), ended["end_reason"].as_str()),
        (Some("ended"), Some("device_removed")),
        "{ended}"
    );
    // What A held of it goes, as A runs on: nothing answers a removal's
    // purge, so the test watches A's disk.
    let began = Instant::now();
    while p.a_state.exists() {
        assert!(
            began.elapsed() < LONG,
            "A never purged what its account held of the session"
        );
        tokio::time::sleep(POLL).await;
    }
    eprintln!(
        "hive_purge: the removed device purged in {} ms",
        began.elapsed().as_millis()
    );
    assert!(!alive(&p.a_pid), "A's run of it stopped");
    assert!(!p.a_run.exists(), "A's runtime directory went");

    // ── A's store keeps only the purged id; B, which stays, its copy ───────
    stop(p.a_proc).await;
    stop(p.b_proc).await;
    assert_eq!(
        held(&p.a_dir.join("hive.db"), &p.sid),
        (0, true),
        "A's store"
    );
    let (events, purged) = held(&p.b_dir.join("hive.db"), &p.sid);
    assert!(events > 0 && !purged, "B keeps its copy: {events} events");
}
