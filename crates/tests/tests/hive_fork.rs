// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2f-3 — a session forked for real, end to end: a real server, and
//! each device a process of its own (this test binary again, asked to be a
//! device by [`device_process`], which an ordinary run passes at once).
//! Nothing is seeded on the record: the route makes the fork, and the device
//! puts it in place from its own copy of the session it forks.
//!
//! | step | the devices | what the test reads |
//! |---|---|---|
//! | a session on A, B its member; two prompts | A runs it and checkpoints each turn's end; B follows the stream | — |
//! | `POST …/fork {device_id: B, folder}` | the route waits for B's copy to hold A's last checkpoint; B puts the session's last checkpoint in place under the fork's ids, and launches `--resume <parent> --fork-session --session-id <fork>` | the answer `accepted`; the fork's record naming its parent; the harness's argv; the fork's note |
//! | a prompt on the fork | B's harness answers from the parent's conversation, now the fork's own | `history: 3`: the parent's two prompts, then this one; the folder's file |
//! | the parent | A runs it on as it was | its harness alive, nothing of the fork's prompt in it |
//! | a fork on A, the parent's own device, in a folder of its own | A puts it in place from its own store | `history: 3` again |
//! | P2f-3c — a fork onto C, which holds no copies (`hive_replica` off) | C prepares as a teleport's target, joins in that role and takes its copy from A; once it caught up, the fork is made there | the answer `joining`; `history: 3`; C let go from the session's replicaset, its copy gone and nothing kept against the session (P2k-3); the session never moved |
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

/// A stand-in for Claude Code, as far as a fork asks. It keeps the session's
/// history where Claude Code does (the path the launch names), and refuses as
/// it does: `--session-id` for an id whose history exists, `--resume` for one
/// without. As Claude Code does (FR-90 §8, probe 5), `--resume <parent>
/// --fork-session --session-id <id>` makes the parent's history, under this
/// session's pinned project name, the start of `<id>`'s own, and leaves the
/// parent's as it was; this one writes it at the first prompt. `recall`
/// answers with how many prompts the history holds. Its argv goes to
/// `$HOME/harness.argv` at each launch, the latest launch's.
const HARNESS: &str = r#"#!/bin/sh
echo $$ > "$HOME/harness.pid"
printf '%s\n' "$@" > "$HOME/harness.argv"
mode=""; sid=""; prev=""; parent=""; fork=""
for a in "$@"; do
  case "$prev" in --session-id|--resume) mode="$prev"; sid="$a" ;; esac
  case "$prev" in --resume) parent="$a" ;; esac
  case "$a" in --fork-session) fork=1 ;; esac
  prev="$a"
done
hist="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/$sid.jsonl"
from="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/$parent.jsonl"
if [ -n "$fork" ] && [ ! -e "$from" ]; then
  echo "No conversation found with session ID: $parent" >&2; exit 1
fi
if [ "$mode" = "--session-id" ] && [ -e "$hist" ]; then
  echo "Error: Session ID $sid is already in use." >&2; exit 1
fi
if [ "$mode" = "--resume" ] && [ ! -e "$hist" ]; then
  echo "No conversation found with session ID: $sid" >&2; exit 1
fi
first=1
while IFS= read -r line; do
  case "$line" in
    *'"type":"control_request"'*)
      echo '{"type":"control_response","response":{"subtype":"success"}}'
      continue ;;
  esac
  printf '%s\n' "$line" >> "$HOME/harness.stdin"
  if [ -n "$fork" ] && [ ! -e "$hist" ]; then
    mkdir -p "${hist%/*}" && cp "$from" "$hist"
  fi
  mkdir -p "${hist%/*}" && printf '%s\n' "$line" >> "$hist"
  if [ "$first" = 1 ]; then
    echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
    first=0
  fi
  case "$line" in
    *recall*)
      n=$(wc -l < "$hist" | tr -d ' ')
      echo '{"type":"assistant","message":{"content":[{"type":"text","text":"history: '"$n"'"}]}}'
      ;;
    *)
      echo '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
      ;;
  esac
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
"#;

/// What the session's folder holds before its first turn: the work a fork
/// takes with it.
const WORK: &str = "the session's work, to be forked\n";

/// The bound on each step.
const LONG: Duration = Duration::from_secs(90);

/// Set to a device's directory when the scenario starts this binary as that
/// device.
const DEVICE_ENV: &str = "HIVE_FORK_DEVICE";

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
fn a_fork_runs_from_its_parents_copy_on_a_member_and_on_the_parents_own_device() {
    // Its own thread with a deep stack, and a current-thread runtime, as the
    // canary: several servers' worth of tasks live in one body.
    let joined = std::thread::Builder::new()
        .name("hive-fork".into())
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
        .insert(seeded.admin.id.clone(), "forker".into());
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

/// `device`'s row in the session's replicaset, as the server keeps it.
fn member<'a>(s: &'a Value, device: &str) -> Option<&'a Value> {
    s["replicaset"]["members"]
        .as_array()?
        .iter()
        .find(|m| m["device_id"] == device)
}

/// Poll the session until `pred` holds, within `bound`; the record either way.
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

/// One prompt over `b`, and its turn's end.
async fn prompt(b: &mut Browser, id: &str, text: &str) -> Vec<Value> {
    b.send(json!({"op": "prompt", "id": id, "text": text}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack["ok"], true, "{id}: {ack}");
    b.events_until(|e| e["event"]["kind"] == "turn").await
}

/// A prompt on `sid` over a viewer: what its turn said.
async fn recall(ws: &mut UserWs, sid: &str, id: &str) -> Vec<Value> {
    let mut v = view(ws, sid).await;
    v.send(json!({"op": "hello"})).await;
    let hello = v.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "{sid}: {hello}");
    let tip = hello["tip"].as_u64().unwrap_or(0);
    v.send(json!({"op": "follow", "after": tip})).await;
    let turn = prompt(&mut v, id, "recall").await;
    v.close(ws).await;
    turn
}

/// Fork `sid` onto `device`, in `folder`: the route's answer.
async fn fork(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    device: &str,
    folder: &Path,
) -> Value {
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/hive/session/{sid}/fork"), token)
        .json(&json!({ "device_id": device, "folder": folder }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    resp.json().await.unwrap()
}

/// The note `dir`'s device left for `sid`: what Claude Code is told as the
/// launch starts. Empty: none left.
fn note_of(dir: &Path, sid: &str) -> String {
    std::fs::read_to_string(
        dir.join("run")
            .join(sid)
            .join(meshharbord::hive::RESUME_NOTE_FILE),
    )
    .unwrap_or_default()
}

/// Whether the process `pid` names is still there.
fn alive(pid: &str) -> bool {
    Path::new("/proc").join(pid.trim()).exists()
}

async fn scenario() {
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hivefork").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let dir = tempfile::tempdir().unwrap();
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
        .auth_put(&format!("/api/tenant/{tid}/hive/policy"), &owner)
        .json(&policy)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);

    // ── A and B, each in a process of its own, each holding copies ─────────
    let a_dir = dir.path().join("a");
    let a_work = device_dir(&a_dir);
    std::fs::write(a_work.join("notes.md"), WORK).unwrap();
    let mut a_cfg = enrol(&app, &seeded, "hive-fork-a").await;
    runs_and_holds(&mut a_cfg, &seeded, &a_dir);
    let a = a_cfg.agent_id.clone();
    let a_proc = device(&app, &seeded, &a_dir, &a_cfg).await;
    let b_dir = dir.path().join("b");
    device_dir(&b_dir);
    let mut b_cfg = enrol(&app, &seeded, "hive-fork-b").await;
    runs_and_holds(&mut b_cfg, &seeded, &b_dir);
    let b = b_cfg.agent_id.clone();
    let b_proc = device(&app, &seeded, &b_dir, &b_cfg).await;

    // ── The session on A, B its member, and two prompts ────────────────────
    let s = start(&app, &seeded, &a, &a_work).await;
    let sid = s["id"].as_str().unwrap().to_string();
    let room = s["room_id"].as_str().unwrap().to_string();
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
    for (id, text) in [("p1", "the first prompt"), ("p2", "the second prompt")] {
        let turn = prompt(&mut on_a, id, text).await;
        assert!(
            turn.iter().any(|e| e["event"]["kind"] == "turn"),
            "{id}: the turn never ended: {turn:?}"
        );
    }
    on_a.close(&mut ws).await;
    let a_pid =
        std::fs::read_to_string(a_dir.join("home").join("harness.pid")).expect("A's harness ran");
    let parent_harness = session(&app, &seeded, &sid).await["harness_session"]
        .as_str()
        .unwrap()
        .to_string();

    // The fork's gate reads what the devices report on their own time: the
    // turn's stub and the checkpoint A took at its end. The viewer saw the
    // turn end before either reached the server, so wait for both (the
    // #2065 lesson: wait for the operation's last write).
    until_stored(&app, &sid, "the turn's stub and A's checkpoint", |s| {
        s.get_document("last_turn").is_ok() && stored_checkpoint(s, &a).is_some()
    })
    .await;

    // ── The fork, on B: from B's own copy, under the fork's ids ────────────
    let b_fork = b_dir.join("roots").join("fork");
    std::fs::create_dir_all(&b_fork).unwrap();
    let began = Instant::now();
    let answer = fork(&app, &tid, &owner, &sid, &b, &b_fork).await;
    assert_eq!(answer["outcome"], "accepted", "{answer}");
    eprintln!(
        "hive_fork: forked on B in {} ms",
        began.elapsed().as_millis()
    );
    let fsid = answer["session"]["id"].as_str().unwrap().to_string();
    let fharness = answer["session"]["harness_session"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(answer["session"]["parent_session_id"], sid.as_str());
    assert_ne!(fharness, parent_harness, "a harness id of its own");
    assert!(
        reached(&app, &seeded, &fsid, "idle").await,
        "the fork never came up on B"
    );
    let argv = std::fs::read_to_string(b_dir.join("home").join("harness.argv")).unwrap();
    let argv: Vec<&str> = argv.lines().collect();
    assert!(
        argv.windows(5).any(|w| w
            == [
                "--resume",
                parent_harness.as_str(),
                "--fork-session",
                "--session-id",
                fharness.as_str()
            ]),
        "B's harness resumes the parent's conversation as the fork: {argv:?}"
    );
    let note = note_of(&b_dir, &fsid);
    assert!(
        note.starts_with("This session is a fork:") && note.contains("Those turns worked in "),
        "the fork is told it is one: {note:?}"
    );
    assert_eq!(
        std::fs::read_to_string(b_fork.join("notes.md"))
            .ok()
            .as_deref(),
        Some(WORK),
        "the parent's folder, in the fork's"
    );
    let turn = recall(&mut ws, &fsid, "f1").await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 3")),
        "the fork's harness holds the parent's two prompts, then its own: {turn:?}"
    );
    let froom = answer["session"]["room_id"].as_str().unwrap().to_string();
    assert_ne!(froom, room, "a room of its own");
    for (in_room, want) in [(&room, "forked the session into"), (&froom, "A fork of")] {
        let noted = until_room_message(&app, &seeded, in_room, |m| {
            m["content"].as_str().is_some_and(|c| c.contains(want))
        })
        .await;
        assert!(noted, "the room says: {want}");
    }

    // ── The parent runs on as it was ───────────────────────────────────────
    assert!(alive(&a_pid), "A's harness runs the parent still");
    let a_read =
        std::fs::read_to_string(a_dir.join("home").join("harness.stdin")).unwrap_or_default();
    assert!(
        !a_read.contains("recall"),
        "nothing of the fork's prompt reached the parent: {a_read}"
    );
    let parent = session(&app, &seeded, &sid).await;
    assert_eq!(parent["device_id"], a.as_str());
    assert_eq!(parent["status"], "idle", "{parent}");

    // ── A fork on A, the parent's own device, in a folder of its own ───────
    let a_fork = a_dir.join("roots").join("fork");
    std::fs::create_dir_all(&a_fork).unwrap();
    let answer = fork(&app, &tid, &owner, &sid, &a, &a_fork).await;
    assert_eq!(answer["outcome"], "accepted", "{answer}");
    let fsid_a = answer["session"]["id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &fsid_a, "idle").await,
        "the fork never came up on A"
    );
    let turn = recall(&mut ws, &fsid_a, "f2").await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 3")),
        "A's fork holds the parent's two prompts, then its own: {turn:?}"
    );
    assert_eq!(
        std::fs::read_to_string(a_fork.join("notes.md"))
            .ok()
            .as_deref(),
        Some(WORK)
    );

    // ── P2f-3c — a fork onto C, which holds no copy of the session ─────────
    // C holds no copies at all (`hive_replica` off): it takes one as a
    // teleport's target does, and the fork is made there once it has.
    let c_dir = dir.path().join("c");
    device_dir(&c_dir);
    let mut c_cfg = enrol(&app, &seeded, "hive-fork-c").await;
    runs_and_holds(&mut c_cfg, &seeded, &c_dir);
    c_cfg.hive_replica = false;
    let c = c_cfg.agent_id.clone();
    let c_proc = device(&app, &seeded, &c_dir, &c_cfg).await;
    assert!(
        member(&session(&app, &seeded, &sid).await, &c).is_none(),
        "C holds no copy"
    );
    let c_fork = c_dir.join("roots").join("fork");
    std::fs::create_dir_all(&c_fork).unwrap();
    let began = Instant::now();
    let answer = fork(&app, &tid, &owner, &sid, &c, &c_fork).await;
    assert_eq!(answer["outcome"], "joining", "{answer}");
    let fsid_c = until_forked_on(&app, &sid, &c).await;
    assert!(
        reached(&app, &seeded, &fsid_c, "idle").await,
        "the fork never came up on C"
    );
    eprintln!(
        "hive_fork: forked onto C, which held no copy, in {} ms",
        began.elapsed().as_millis()
    );
    let turn = recall(&mut ws, &fsid_c, "f3").await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 3")),
        "C's fork holds the parent's two prompts, then its own: {turn:?}"
    );
    assert_eq!(
        std::fs::read_to_string(c_fork.join("notes.md"))
            .ok()
            .as_deref(),
        Some(WORK),
        "the parent's folder, in C's fork's"
    );
    // P2g-4b — C took its copy only to fork it, and the session holds its
    // `min` copies without it (A's and B's): once the fork's start was
    // answered, that copy is purged and C's row goes. The fork runs on.
    until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "C's copy of the session was never purged",
        |s| member(s, &c).is_none() && s["promotion"].is_null(),
    )
    .await;
    let turn = recall(&mut ws, &fsid_c, "f4").await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 4")),
        "C's fork runs on without the copy it was made from: {turn:?}"
    );
    let parent = session(&app, &seeded, &sid).await;
    assert_eq!(
        (parent["device_id"].as_str(), parent["fence"].as_u64()),
        (Some(a.as_str()), Some(1)),
        "the session never moved: {parent}"
    );

    stop(c_proc).await;
    // P2k-3 — C was let go as a member, not purged with the session: its copy
    // goes whole, and its store keeps nothing against the session, so a later
    // teleport or fork may hand it a copy again.
    let (events, purged) = held(&c_dir.join("hive.db"), &sid);
    assert_eq!(
        (events, purged),
        (0, false),
        "C's store holds nothing of the session, and does not refuse it"
    );
    stop(b_proc).await;
    stop(a_proc).await;
}

/// Every event of `sid` the store at `db` holds, and whether it keeps `sid`
/// purged. Read with the device stopped: the store is its own.
fn held(db: &Path, sid: &str) -> (usize, bool) {
    let store = meshharbor_hive_node::store::Store::open(db).expect("the device's store");
    let events = store.page(sid, 0, 100_000).expect("its copy").len();
    (events, store.is_purged(sid).expect("its purged ids"))
}

/// The stored session `sid`, once `pred` holds of it, within [`LONG`].
async fn until_stored(
    app: &TestApp,
    sid: &str,
    what: &str,
    pred: impl Fn(&bson::Document) -> bool,
) -> bson::Document {
    let id = bson::oid::ObjectId::parse_str(sid).unwrap();
    let deadline = Instant::now() + LONG;
    loop {
        let s = app
            .db
            .collection::<bson::Document>("agent_sessions")
            .find_one(bson::doc! { "_id": id })
            .await
            .unwrap()
            .expect("the session's record");
        if pred(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "{what}: {s}");
        tokio::time::sleep(POLL).await;
    }
}

/// The checkpoint the stored session's member row of `device` names.
fn stored_checkpoint(s: &bson::Document, device: &str) -> Option<i64> {
    let id = bson::oid::ObjectId::parse_str(device).ok()?;
    s.get_document("replicaset")
        .ok()?
        .get_array("members")
        .ok()?
        .iter()
        .filter_map(|m| m.as_document())
        .find(|m| m.get_object_id("device_id").ok() == Some(id))?
        .get_document("tip")
        .ok()?
        .get_i64("checkpoint_seq")
        .ok()
}

/// The fork of `parent` made on `device`, once there is one, within [`LONG`].
async fn until_forked_on(app: &TestApp, parent: &str, device: &str) -> String {
    let filter = bson::doc! {
        "parent.session_id": bson::oid::ObjectId::parse_str(parent).unwrap(),
        "location.device_id": bson::oid::ObjectId::parse_str(device).unwrap(),
    };
    let deadline = Instant::now() + LONG;
    loop {
        if let Some(s) = app
            .db
            .collection::<bson::Document>("agent_sessions")
            .find_one(filter.clone())
            .await
            .unwrap()
        {
            return s.get_object_id("_id").unwrap().to_hex();
        }
        assert!(
            Instant::now() < deadline,
            "no fork of {parent} was made on {device}"
        );
        tokio::time::sleep(POLL).await;
    }
}
