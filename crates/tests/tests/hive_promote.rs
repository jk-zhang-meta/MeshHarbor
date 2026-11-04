// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2e-5c — a session promoted for real, end to end: a real server, the
//! primary in-process, and every other device a process of its own (this test
//! binary again, asked to be a device by [`device_process`], which an ordinary
//! run passes at once: a process holds one Hive supervisor). Nothing is
//! seeded on the record. The route starts the promotion, and each step after
//! it is a device's own frame.
//!
//! | step | the devices | what the test reads |
//! |---|---|---|
//! | a session on A, placed with B; two prompts | A runs it and checkpoints each turn's end; B follows the stream | B's tip at A's, as the server last heard it |
//! | `POST …/promote {device_id: B, folder}` | B prepares; A drains; B's copy reaches the drained tip; the lease moves | the answer `promoting`; the record at fence 2 on B, keeping where fence 1 ended; the room's "Moved" note |
//! | the moved start | B takes the session over from its copy, the history and the folder put in place, then `--resume` | a prompt over a viewer, answered by B's harness, which remembers A's two prompts; the folder's file |
//! | the old primary | A is demoted: its harness stops, and it holds a member's copy at fence 2 | A's harness gone; A's member row joined |
//! | a third device, joined after the move (P2e-5b) | its join names where fence 1 ended, so it takes the whole history below its floor | its tip at B's; its store, event for event, B's, and fence 1's end in it |
//! | a move back to A, into a folder holding work of its own | A prepares and the lease moves, but its take-over refuses to write over that work: the lease moves back to B at fence 4, and B resumes its own state | the record on B at fence 4; the room says the move did not happen; A's folder as it was; B remembers all three prompts; C at B's tip, holding three fences' ends |
//! | B unreachable (P2e-6a): its process gone, then waited out | refused while B may still call the model; then A's own ready names where its copy ends, and the lease moves there with no drain | `primary_offline`, then `promoting`; the record on A at fence 5, fence 4 ending at A's tip, which was B's; the room's "cannot be reached"; A remembers all four prompts; C at A's tip, its store A's, event for event |
//!
//! ⚠️ The streams ride `direct` on loopback: the tests build carries no
//! overlay, as in the canary.
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

/// A stand-in for Claude Code, as far as a promotion asks. It keeps the
/// session's history where Claude Code does (the path the launch names), and
/// refuses as it does: `--session-id` for an id whose history exists,
/// `--resume` for one without. `recall` answers with how many prompts that
/// history holds, so a test sees what a resumed process remembers. A
/// `control_request` is answered, never taken as a prompt. Each prompt goes to
/// `$HOME/harness.stdin`, and the process's pid to `$HOME/harness.pid`: the
/// device's home, never the session's folder, which moves with the session.
const HARNESS: &str = r#"#!/bin/sh
echo $$ > "$HOME/harness.pid"
mode=""; sid=""; prev=""
for a in "$@"; do
  case "$prev" in --session-id|--resume) mode="$prev"; sid="$a" ;; esac
  prev="$a"
done
hist="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/$sid.jsonl"
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

/// What the folder holds before the session's first turn: the work a
/// promotion must carry to the other device.
const WORK: &str = "the session's work\n";

/// The bound on the steps a device's tip report paces (at most every 5 s,
/// and at each checkpoint) and on the promotion's own steps.
const LONG: Duration = Duration::from_secs(90);

/// Set to a device's directory when the scenario starts this binary as that
/// device.
const DEVICE_ENV: &str = "HIVE_PROMOTE_DEVICE";

/// A device's process: this binary again, from the config the scenario
/// enrolled and saved in its directory, until its stdin closes. An ordinary
/// run passes it at once.
#[test]
fn device_process() {
    let Ok(dir) = std::env::var(DEVICE_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let joined = std::thread::Builder::new()
        .name("hive-promote-device".into())
        .stack_size(16 << 20)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
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
fn a_session_moves_to_its_member_and_a_member_joined_after_the_move_takes_its_history() {
    // Its own thread with a deep stack, and a current-thread runtime, as the
    // canary: several servers' worth of tasks live in one body.
    let joined = std::thread::Builder::new()
        .name("hive-promote".into())
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
        .insert(seeded.admin.id.clone(), "promoter".into());
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

/// `device`'s own row once it answered its join as the primary. The device
/// takes that join and the start behind it up in tasks of their own
/// (`handle_replica_join`, `handle_start`), so its answer may reach the
/// server after the start's: a session read idle on its new primary says
/// nothing yet of the primary's row. Once it moved on from `pending`, that
/// is the device's answer.
async fn answered_as_primary(
    app: &TestApp,
    seeded: &SeededTenant,
    sid: &str,
    device: &str,
) -> Value {
    let s = until_session(
        app,
        seeded,
        sid,
        LONG,
        &format!("{device} never answered its join as the primary"),
        |s| member(s, device).is_some_and(|m| m["role"] == "primary" && m["state"] != "pending"),
    )
    .await;
    member(&s, device).cloned().unwrap_or_default()
}

/// Where the primary's store ends `sid`, as a viewer hears it.
async fn primary_tip(ws: &mut UserWs, sid: &str) -> u64 {
    let mut b = view(ws, sid).await;
    b.send(json!({"op": "hello"})).await;
    let tip = b.recv_op("hello").await["tip"].as_u64().unwrap_or(0);
    b.close(ws).await;
    tip
}

/// One prompt over `b`, and its turn's end.
async fn prompt(b: &mut Browser, id: &str, text: &str) -> Vec<Value> {
    b.send(json!({"op": "prompt", "id": id, "text": text}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack["ok"], true, "{id}: {ack}");
    b.events_until(|e| e["event"]["kind"] == "turn").await
}

/// `POST …/promote`, its answer's outcome.
async fn promote(
    app: &TestApp,
    tid: &str,
    token: &str,
    sid: &str,
    to: &str,
    folder: &Path,
) -> Value {
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/promote"),
            token,
        )
        .json(&json!({ "device_id": to, "folder": folder }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    resp.json().await.unwrap()
}

/// Every event of `sid` the store at `db` holds, as kept.
fn copy_of(db: &Path, sid: &str) -> Vec<meshharbor_hive_node::EventEnvelope> {
    let store = meshharbor_hive_node::store::Store::open(db).expect("the device's store");
    store.page(sid, 0, 100_000).expect("its copy")
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

/// As if the server last heard from the device `secs` ago.
async fn heard_last(app: &TestApp, agent_id: &str, secs: u64) {
    let ms = i64::try_from(secs * 1000).unwrap();
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            bson::doc! { "_id": bson::oid::ObjectId::parse_str(agent_id).unwrap() },
            bson::doc! { "$set": {
                "last_seen_at": bson::DateTime::from_millis(
                    bson::DateTime::now().timestamp_millis() - ms,
                ),
            } },
        )
        .await
        .unwrap();
}

/// FR-90 P2e-7 — the resume note `dir`'s device left for `sid`, and the
/// `SessionStart` hook its settings carry: what Claude Code would be told as
/// it resumes there. Empty: none left.
fn resume_note_of(dir: &Path, sid: &str) -> (String, Value) {
    let run = dir.join("run").join(sid);
    let note =
        std::fs::read_to_string(run.join(meshharbord::hive::RESUME_NOTE_FILE)).unwrap_or_default();
    let settings: Value = std::fs::read_to_string(run.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    (note, settings["hooks"]["SessionStart"][0].clone())
}

/// FR-90 P2f-1a — whether the device's stored row advertises the verb `word`,
/// as its last hello said.
async fn advertises(app: &TestApp, agent_id: &str, word: &str) -> bool {
    let row = app
        .db
        .collection::<bson::Document>("agents")
        .find_one(bson::doc! { "_id": bson::oid::ObjectId::parse_str(agent_id).unwrap() })
        .await
        .unwrap()
        .unwrap_or_default();
    row.get_document("capabilities")
        .and_then(|c| c.get_array("rpc"))
        .is_ok_and(|rpc| rpc.iter().any(|v| v.as_str() == Some(word)))
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
    let seeded = app.seed_tenant("hivepromote").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let dir = tempfile::tempdir().unwrap();

    // ── A, the primary, in this process; B, the member, in its own ─────────
    let a_dir = dir.path().join("a");
    let a_work = device_dir(&a_dir);
    std::fs::write(a_work.join("notes.md"), WORK).unwrap();
    let mut a_cfg = enrol(&app, &seeded, "hive-promote-a").await;
    runs_and_holds(&mut a_cfg, &seeded, &a_dir);
    meshharbord::hive::init_as_daemon(
        &a_cfg,
        &a_dir.join("hive.db"),
        &a_dir.join("run"),
        &a_dir.join("home"),
    )
    .expect("the test launcher");
    let a = a_cfg.agent_id.clone();
    let (stop_a, stop_rx) = tokio::sync::watch::channel(false);
    let a_task = spawn_device(a_cfg, stop_rx);
    wait_online(&app, &seeded, &a).await;

    let b_dir = dir.path().join("b");
    let b_work = device_dir(&b_dir);
    let mut b_cfg = enrol(&app, &seeded, "hive-promote-b").await;
    runs_and_holds(&mut b_cfg, &seeded, &b_dir);
    let b = b_cfg.agent_id.clone();
    let b_proc = device(&app, &seeded, &b_dir, &b_cfg).await;
    // P2f-1a — every build that runs agent sessions takes part in a
    // teleport, the device in this process and the one in its own alike.
    // P2f-3a — and starts a fork. P2f-4a — and, on Unix, where terminals
    // are adopted, makes an ended one a managed session. P2g-1 — and purges
    // a session, answering per part. P2g-4a — and every session it holds,
    // at its removal.
    for (name, id) in [("A", &a), ("B", &b)] {
        for verb in [
            "hive-teleport",
            "hive-fork",
            "hive-manage",
            "hive-purge",
            "hive-purge-all",
        ] {
            assert!(advertises(&app, id, verb).await, "{name} advertises {verb}");
        }
    }

    // ── The session on A, placed with B, and two prompts ───────────────────
    let s = start(&app, &seeded, &a, &a_work).await;
    let sid = s["id"].as_str().unwrap().to_string();
    let room = s["room_id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid, "idle").await,
        "the session never came up"
    );
    until_session(&app, &seeded, &sid, WAIT, "B never took its copy", |s| {
        member(s, &b).is_some_and(|m| m["state"] == "joined")
    })
    .await;
    let mut ws = UserWs::open(&app, &owner).await;
    let mut on_a = view(&mut ws, &sid).await;
    on_a.send(json!({"op": "hello"})).await;
    let hello = on_a.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "{hello}");
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
    assert!(alive(&a_pid), "A's harness runs the session");
    let want = primary_tip(&mut ws, &sid).await;
    until_session(&app, &seeded, &sid, LONG, "B's copy never caught up", |s| {
        member(s, &b).is_some_and(|m| m["tip"]["seq"].as_u64() == Some(want))
    })
    .await;

    // ── The promotion: prepared, drained, synced, moved ────────────────────
    let answer = promote(&app, &tid, &owner, &sid, &b, &b_work).await;
    assert_eq!(answer["outcome"], "promoting", "B is ready: {answer}");
    let moved = until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "the lease never moved to B",
        |s| {
            s["device_id"] == b.as_str()
                && s["fence"] == 2
                && s["promotion"].is_null()
                && s["status"] == "idle"
        },
    )
    .await;
    assert_eq!(moved["folder"], b_work.display().to_string(), "{moved}");
    // B heard its join as the primary before its start (§3b: the target's
    // floor rises with its join, before it writes), and holds the session.
    let row = answered_as_primary(&app, &seeded, &sid, &b).await;
    assert_eq!(
        (row["role"].as_str(), row["state"].as_str()),
        (Some("primary"), Some("joined")),
        "B's own row, as the primary: {row}"
    );
    let noted = until_room_message(&app, &seeded, &room, |m| {
        m["content"]
            .as_str()
            .is_some_and(|c| c.contains("🔀 Moved from"))
    })
    .await;
    assert!(noted, "the room says who moved it where");

    // ── B runs it, from its copy: the folder, and the conversation ─────────
    assert_eq!(
        std::fs::read_to_string(b_work.join("notes.md"))
            .ok()
            .as_deref(),
        Some(WORK),
        "the folder came with the session"
    );
    // P2e-7 — and told it moved: the note left for its `SessionStart` hook,
    // which its settings carry.
    let (note, hook) = resume_note_of(&b_dir, &sid);
    assert!(
        note.contains("moved to this device by")
            && note.contains("It ran on hive-promote-a, in ")
            && note.contains("Paths in earlier turns under "),
        "B's resume note: {note:?}"
    );
    assert_eq!(hook["matcher"], "resume", "{hook}");
    let mut on_b = view(&mut ws, &sid).await;
    on_b.send(json!({"op": "hello"})).await;
    let hello = on_b.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "B serves it now: {hello}");
    let tip = hello["tip"].as_u64().unwrap_or(0);
    on_b.send(json!({"op": "follow", "after": tip})).await;
    let turn = prompt(&mut on_b, "p3", "recall").await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 3")),
        "B's harness resumed A's conversation, its two prompts and this one: {turn:?}"
    );
    on_b.close(&mut ws).await;
    let b_read =
        std::fs::read_to_string(b_dir.join("home").join("harness.stdin")).unwrap_or_default();
    assert!(
        b_read.contains("recall") && !b_read.contains("the first prompt"),
        "B's harness took the new prompt, and only that: {b_read}"
    );

    // ── A, demoted: its harness stopped, a member's copy kept ──────────────
    let deadline = Instant::now() + WAIT;
    while alive(&a_pid) {
        assert!(Instant::now() < deadline, "A's harness still runs");
        tokio::time::sleep(POLL).await;
    }
    let a_read =
        std::fs::read_to_string(a_dir.join("home").join("harness.stdin")).unwrap_or_default();
    assert!(
        !a_read.contains("recall"),
        "nothing after the move reached A: {a_read}"
    );
    until_session(
        &app,
        &seeded,
        &sid,
        WAIT,
        "A never took its member's copy",
        |s| member(s, &a).is_some_and(|m| m["state"] == "joined" && m["role"] != "primary"),
    )
    .await;

    // ── C, a member joined after the move (P2e-5b) ──────────────────────────
    let c_dir = dir.path().join("c");
    std::fs::create_dir_all(c_dir.join("home")).unwrap();
    let mut c_cfg = enrol(&app, &seeded, "hive-promote-c").await;
    c_cfg.hive_replica = true;
    let c = c_cfg.agent_id.clone();
    let c_proc = device(&app, &seeded, &c_dir, &c_cfg).await;
    // A third copy: placement takes C, at fence 2, its join naming where
    // fence 1 ended.
    let policy = json!({
        "replicaset": {
            "min": 3, "max": 4, "archive": true,
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
    let want = primary_tip(&mut ws, &sid).await;
    let synced = until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "C's copy never reached B's tip: the history below its floor was refused",
        |s| {
            member(s, &c).is_some_and(|m| {
                m["state"] == "joined"
                    && m["tip"]["fence"] == 2
                    && m["tip"]["seq"].as_u64() == Some(want)
            })
        },
    )
    .await;
    assert_eq!(synced["fence"], 2, "{synced}");
    let record = meshharbor_mod_hive::dao::AgentSessionDao::new(&app.db)
        .find(bson::oid::ObjectId::parse_str(&sid).unwrap())
        .await
        .unwrap()
        .expect("the session's record");
    assert_eq!(
        record.fences.len(),
        1,
        "the record keeps where fence 1 ended: {:?}",
        record.fences
    );
    assert_eq!(record.fences[0].fence, 1);

    // ── A move that fails at its start moves back (P2e-3) ──────────────────
    // B to A, into a folder of A's that holds someone's own work: A prepares
    // and the lease moves, but A's take-over refuses to write over that work,
    // so the lease moves back to B at the fence after A's, and B resumes its
    // own state, nothing put in place.
    let other = a_dir.join("roots").join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("theirs.txt"), "someone's own work\n").unwrap();
    let answer = promote(&app, &tid, &owner, &sid, &a, &other).await;
    assert_eq!(answer["outcome"], "promoting", "A is ready: {answer}");
    until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "the lease never moved back to B",
        |s| {
            s["device_id"] == b.as_str()
                && s["fence"] == 4
                && s["promotion"].is_null()
                && s["status"] == "idle"
        },
    )
    .await;
    let row = answered_as_primary(&app, &seeded, &sid, &b).await;
    assert_eq!(
        (row["role"].as_str(), row["state"].as_str()),
        (Some("primary"), Some("joined")),
        "B, the primary again, took its join up ahead of its start: {row}"
    );
    let noted = until_room_message(&app, &seeded, &room, |m| {
        m["content"]
            .as_str()
            .is_some_and(|c| c.contains("did not happen"))
    })
    .await;
    assert!(noted, "the room says the move did not happen");
    assert_eq!(
        std::fs::read_to_string(other.join("theirs.txt"))
            .ok()
            .as_deref(),
        Some("someone's own work\n"),
        "A's take-over wrote nothing over that work"
    );
    assert!(
        !other.join("notes.md").exists(),
        "nor put the session there"
    );
    // P2e-7 — the lease back is no move from elsewhere: B is told nothing,
    // and the note its own move left is gone.
    assert_eq!(
        resume_note_of(&b_dir, &sid).0,
        "",
        "no resume note on a move back"
    );
    let mut on_b = view(&mut ws, &sid).await;
    on_b.send(json!({"op": "hello"})).await;
    let hello = on_b.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "B serves it again: {hello}");
    let tip = hello["tip"].as_u64().unwrap_or(0);
    on_b.send(json!({"op": "follow", "after": tip})).await;
    let turn = prompt(&mut on_b, "p4", "recall").await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 4")),
        "B resumed its own state, all three prompts and this one: {turn:?}"
    );
    on_b.close(&mut ws).await;
    // C followed every move: joined at the newest fence, its copy at B's tip.
    let want = primary_tip(&mut ws, &sid).await;
    until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "C's copy never reached B's tip at fence 4",
        |s| {
            member(s, &c).is_some_and(|m| {
                m["state"] == "joined"
                    && m["tip"]["fence"] == 4
                    && m["tip"]["seq"].as_u64() == Some(want)
            })
        },
    )
    .await;
    let record = meshharbor_mod_hive::dao::AgentSessionDao::new(&app.db)
        .find(bson::oid::ObjectId::parse_str(&sid).unwrap())
        .await
        .unwrap()
        .expect("the session's record");
    assert_eq!(
        record.fences.iter().map(|m| m.fence).collect::<Vec<_>>(),
        [1, 2, 3],
        "where fence 1, fence 2 and A's fence 3 ended: {:?}",
        record.fences
    );
    assert_eq!(
        (record.fences[2].seq, &record.fences[2].hash),
        (record.fences[1].seq, &record.fences[1].hash),
        "A's fence ran nothing: it ended where it began"
    );

    // ── B unreachable: waited out, then moved to A with no drain (P2e-6a) ──
    // A holds B's whole history at fence 4. B's process stops, so nothing
    // drains it: refused while B may still call the model, then moved to
    // where A's own ready says its copy ends, into a folder of A's own.
    use meshharbor_remote_control::hive::promote_limits::UNREACHABLE_SECS;
    let want = primary_tip(&mut ws, &sid).await;
    until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "A's copy never reached B's tip at fence 4",
        |s| {
            member(s, &a).is_some_and(|m| {
                m["state"] == "joined"
                    && m["tip"]["fence"] == 4
                    && m["tip"]["seq"].as_u64() == Some(want)
            })
        },
    )
    .await;
    stop(b_proc).await;
    wait_offline(&app, &seeded, &b).await;
    let again = a_dir.join("roots").join("again");
    std::fs::create_dir_all(&again).unwrap();
    let answer = promote(&app, &tid, &owner, &sid, &a, &again).await;
    assert_eq!(
        (answer["outcome"].as_str(), answer["reason"].as_str()),
        (Some("refused"), Some("primary_offline")),
        "B just went: {answer}"
    );
    heard_last(&app, &b, UNREACHABLE_SECS + 1).await;
    let answer = promote(&app, &tid, &owner, &sid, &a, &again).await;
    assert_eq!(
        answer["outcome"], "promoting",
        "A is ready, and B unreachable: {answer}"
    );
    let moved = until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "the lease never moved to A",
        |s| {
            s["device_id"] == a.as_str()
                && s["fence"] == 5
                && s["promotion"].is_null()
                && s["status"] == "idle"
        },
    )
    .await;
    assert_eq!(moved["folder"], again.display().to_string(), "{moved}");
    let noted = until_room_message(&app, &seeded, &room, |m| {
        m["content"]
            .as_str()
            .is_some_and(|c| c.contains("cannot be reached"))
    })
    .await;
    assert!(noted, "the room says what the session goes on from");
    assert_eq!(
        std::fs::read_to_string(again.join("notes.md"))
            .ok()
            .as_deref(),
        Some(WORK),
        "the folder came with the session, from A's copy"
    );
    // P2e-7 — A was told it moved, from B.
    let (note, _) = resume_note_of(&a_dir, &sid);
    assert!(
        note.contains("It ran on hive-promote-b, in "),
        "A's resume note: {note:?}"
    );
    let mut on_a = view(&mut ws, &sid).await;
    on_a.send(json!({"op": "hello"})).await;
    let hello = on_a.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "A serves it now: {hello}");
    let tip = hello["tip"].as_u64().unwrap_or(0);
    on_a.send(json!({"op": "follow", "after": tip})).await;
    let turn = prompt(&mut on_a, "p5", "recall").await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 5")),
        "A resumed B's state from its copy, all four prompts and this one: {turn:?}"
    );
    on_a.close(&mut ws).await;
    let record = meshharbor_mod_hive::dao::AgentSessionDao::new(&app.db)
        .find(bson::oid::ObjectId::parse_str(&sid).unwrap())
        .await
        .unwrap()
        .expect("the session's record");
    assert_eq!(
        record.fences.iter().map(|m| m.fence).collect::<Vec<_>>(),
        [1, 2, 3, 4],
        "{:?}",
        record.fences
    );
    assert_eq!(
        record.fences[3].seq,
        i64::try_from(want).unwrap(),
        "fence 4 ends at A's tip, which was B's: nothing it held was lost"
    );
    // C follows A at fence 5.
    let want = primary_tip(&mut ws, &sid).await;
    until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "C's copy never reached A's tip at fence 5",
        |s| {
            member(s, &c).is_some_and(|m| {
                m["state"] == "joined"
                    && m["tip"]["fence"] == 5
                    && m["tip"]["seq"].as_u64() == Some(want)
            })
        },
    )
    .await;

    // ── The devices gone, their stores read ─────────────────────────────────
    stop(c_proc).await;
    let _ = stop_a.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), a_task).await;
    let on_a = copy_of(&a_dir.join("hive.db"), &sid);
    let on_b = copy_of(&b_dir.join("hive.db"), &sid);
    let on_c = copy_of(&c_dir.join("hive.db"), &sid);
    assert_eq!(on_c, on_a, "C's copy is A's history, event for event");
    assert_eq!(
        on_c.get(..on_b.len()),
        Some(&on_b[..]),
        "B's history is where A's and C's begin: the move lost none of it"
    );
    let fences: Vec<u64> = {
        let mut f: Vec<u64> = on_c.iter().map(|e| e.fence).collect();
        f.dedup();
        f
    };
    assert_eq!(fences, [1, 2, 4, 5], "A's fence 3 wrote nothing: {on_c:?}");
    let c_store = meshharbor_hive_node::store::Store::open(&c_dir.join("hive.db")).unwrap();
    let c_ends: Vec<(u64, u64, String)> = c_store
        .fence_ends(&sid)
        .unwrap()
        .iter()
        .map(|e| (e.fence, e.seq, hex::encode(e.hash)))
        .collect();
    let kept: Vec<(u64, u64, String)> = record
        .fences
        .iter()
        .map(|m| (m.fence as u64, m.seq as u64, m.hash.clone()))
        .collect();
    assert_eq!(c_ends, kept, "C keeps every fence's end as the record does");
}
