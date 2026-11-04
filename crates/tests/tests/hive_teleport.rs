// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2f-1 — a session teleported for real, end to end: a real server,
//! and each device a process of its own (this test binary again, asked to be
//! a device by [`device_process`], which an ordinary run passes at once). The
//! target holds no copy of the session, and its owner never let it hold
//! copies at all (`hive_replica` off): what lets it take the session is the
//! teleport's prepare. Nothing is seeded on the record; the route starts the
//! teleport, and each step after it is a device's own frame.
//!
//! | step | the devices | what the test reads |
//! |---|---|---|
//! | a session on A, alone; two prompts | A runs it, and checkpoints nothing: it has no member | B is no member |
//! | `POST …/teleport {device_id: B, folder}` | B prepares with every gate but the copy, and joins in the `teleport` role; A is told it has a member, checkpoints at once and says where its copy ends; B's copy follows the stream there | the answer `teleporting` |
//! | the drain, the sync and the move | as a promotion's | the record at fence 2 on B, in B's folder; the room's notes |
//! | the moved start | B takes the session over from the copy it took, the history and the folder put in place, then `--resume` | the folder's file; B's resume note; a prompt answered by B's harness, which remembers A's two prompts |
//! | the old primary | A is demoted, its harness stopped; it holds copies, so it stays a member | A's harness gone; A's row a member's |
//!
//! P2f-2b — the teleport twice, once for each [`Folder`]: a folder in no
//! repository, the target's empty, the server's `teleport_have_want` off as
//! it ships; and the person's own repository, the target's folder a clone of
//! it from a remote as it were (`--no-local`), the server saying `have_want`.
//! The target then asks the primary for the workspace's first pack against
//! its clone's `HEAD`, and keeps the answer as a substitute: it holds none of
//! the whole pack's own blobs, the folder comes whole all the same, and the
//! clone's `HEAD` is still the person's.
//!
//! P2f-2d — into the clone, first with the person's own file in it: B's
//! prepare refuses `folder_dirty` before anything moves, naming a sibling for
//! the person to make; the file gone, the teleport goes ahead.
//!
//! P2f-2c — then, into the clone, B's process is stopped, its store read, and
//! started again: it resumes the session on the server's word, its store
//! keeping where it runs it. A third device C joins after the move. B, the
//! new primary, holds that first pack only as a substitute: its hello says
//! so, C asks for the pack by a want with no haves, and B makes it again from
//! its clone. C's copy reaches B's tip, keeping a substitute against nothing.
//!
//! ⚠️ The stream rides `direct` on loopback: the tests build carries no
//! overlay, as in the canary. ⚠️ A process holds one supervisor, so the two
//! scenarios share this binary only because neither device runs in it.
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

/// A stand-in for Claude Code, as far as a teleport asks. It keeps the
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
/// teleport must carry to the other device.
const WORK: &str = "the session's work, to be teleported\n";

/// The bound on the teleport, its joining step included.
const LONG: Duration = Duration::from_secs(90);

/// Set to a device's directory when the scenario starts this binary as that
/// device.
const DEVICE_ENV: &str = "HIVE_TELEPORT_DEVICE";

/// Where the session's folder is, on either device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Folder {
    /// In no repository: its checkpoints go to a shadow; the target's folder
    /// is empty. The server's `teleport_have_want` is off, as it ships.
    Plain,
    /// P2f-2b — the person's own repository, with history; the target's
    /// folder a clone of it. The server's `teleport_have_want` is on.
    Clone,
}

/// The person's history in [`Folder::Clone`]: a file the clone holds, and
/// big enough that a pack which carries it is told from one which does not.
fn history() -> String {
    (0..2_000u64)
        .map(|i| {
            let n = i.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17);
            format!("pub const C{i}: u64 = {n:#018x};\n")
        })
        .collect()
}

/// `git` as the person runs it in `dir`: its output, trimmed.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .args([
            "-c",
            "user.name=Person",
            "-c",
            "user.email=person@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A device's process: this binary again, from the config the scenario
/// enrolled and saved in its directory, until its stdin closes. An ordinary
/// run passes it at once. With `RUST_LOG` set, it logs to its stderr, each
/// line naming the device by its thread.
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
fn a_session_teleports_to_a_device_that_held_no_copy_and_runs_there_from_it() {
    run(Folder::Plain);
}

/// P2f-2b — into a clone of the person's repository, taking only what the
/// clone lacks.
#[test]
fn a_session_teleports_into_a_clone_taking_the_workspace_against_its_head() {
    run(Folder::Clone);
}

/// The scenario on its own thread with a deep stack, and a current-thread
/// runtime, as the canary: several servers' worth of tasks live in one body.
fn run(folder: Folder) {
    let joined = std::thread::Builder::new()
        .name(format!("hive-teleport-{folder:?}"))
        .stack_size(16 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario(folder))
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

/// A device that runs the owner's sessions; one that `holds` copies too.
fn runs(
    cfg: &mut meshharbord::config::AgentConfig,
    seeded: &SeededTenant,
    dir: &Path,
    holds: bool,
) {
    cfg.hive_enabled = true;
    cfg.hive_replica = holds;
    cfg.hive_accounts
        .insert(seeded.admin.id.clone(), "teleporter".into());
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

/// One prompt over `b`, and its turn's end.
async fn prompt(b: &mut Browser, id: &str, text: &str) -> Vec<Value> {
    b.send(json!({"op": "prompt", "id": id, "text": text}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack["ok"], true, "{id}: {ack}");
    b.events_until(|e| e["event"]["kind"] == "turn").await
}

/// Where the primary's chain of `sid` ends, as a viewer's hello says.
async fn primary_tip(ws: &mut UserWs, sid: &str) -> u64 {
    let mut b = view(ws, sid).await;
    b.send(json!({"op": "hello"})).await;
    let tip = b.recv_op("hello").await["tip"].as_u64().unwrap_or(0);
    b.close(ws).await;
    tip
}

/// The resume note `dir`'s device left for `sid`: what Claude Code would be
/// told as it resumes there. Empty: none left.
fn resume_note_of(dir: &Path, sid: &str) -> String {
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

async fn scenario(folder: Folder) {
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.hive.teleport_have_want = folder == Folder::Clone;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hiveteleport").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let dir = tempfile::tempdir().unwrap();

    // ── A, the primary, and B, the target, each in a process of its own ────
    let a_dir = dir.path().join("a");
    let a_work = device_dir(&a_dir);
    // The person's `HEAD`, where the folder is their repository.
    let person_head = (folder == Folder::Clone).then(|| {
        git(&a_work, &["init", "-q"]);
        std::fs::write(a_work.join("lib.rs"), history()).unwrap();
        git(&a_work, &["add", "-A"]);
        git(&a_work, &["commit", "-q", "-m", "the person's history"]);
        git(&a_work, &["rev-parse", "HEAD"])
    });
    std::fs::write(a_work.join("notes.md"), WORK).unwrap();
    let mut a_cfg = enrol(&app, &seeded, "hive-teleport-a").await;
    runs(&mut a_cfg, &seeded, &a_dir, true);
    let a = a_cfg.agent_id.clone();
    let a_proc = device(&app, &seeded, &a_dir, &a_cfg).await;

    // B runs the owner's sessions, and holds no copies of any.
    let b_dir = dir.path().join("b");
    let b_work = device_dir(&b_dir);
    if folder == Folder::Clone {
        let from = a_work.display().to_string();
        git(&b_dir, &["clone", "-q", "--no-local", &from, "roots/work"]);
    }
    let mut b_cfg = enrol(&app, &seeded, "hive-teleport-b").await;
    runs(&mut b_cfg, &seeded, &b_dir, false);
    let b = b_cfg.agent_id.clone();
    let b_proc = device(&app, &seeded, &b_dir, &b_cfg).await;

    // ── The session on A, alone, and two prompts ───────────────────────────
    let s = start(&app, &seeded, &a, &a_work).await;
    let sid = s["id"].as_str().unwrap().to_string();
    let room = s["room_id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid, "idle").await,
        "the session never came up"
    );
    let alone = session(&app, &seeded, &sid).await;
    assert!(
        member(&alone, &b).is_none(),
        "B holds no copies: placement chose nobody: {alone}"
    );
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

    // ── P2f-2d — into a clone holding the person's own work: refused at the
    // prepare, before anything moves, a sibling named for them to make ─────
    if folder == Folder::Clone {
        std::fs::write(b_work.join("theirs.txt"), "the person's own work\n").unwrap();
        let resp = app
            .auth_post(
                &format!("/api/tenant/{tid}/hive/session/{sid}/teleport"),
                &owner,
            )
            .json(&json!({ "device_id": b, "folder": b_work }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let refused: Value = resp.json().await.unwrap();
        assert_eq!(
            (refused["outcome"].as_str(), refused["reason"].as_str()),
            (Some("refused"), Some("folder_dirty")),
            "{refused}"
        );
        // The room's words, escaped for Markdown.
        let said = refused["message"]
            .as_str()
            .unwrap_or_default()
            .replace('\\', "");
        assert!(
            said.contains("holds work of its own")
                && said.contains("git worktree add")
                && said.contains("work-hive-"),
            "a sibling named: {refused}"
        );
        let s = session(&app, &seeded, &sid).await;
        assert_eq!(s["device_id"], a.as_str(), "nothing moved: {s}");
        assert!(member(&s, &b).is_none(), "B took nothing: {s}");
        std::fs::remove_file(b_work.join("theirs.txt")).unwrap();
    }

    // ── The teleport: prepared, joined, caught up, drained, synced, moved ──
    let began = Instant::now();
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/teleport"),
            &owner,
        )
        .json(&json!({ "device_id": b, "folder": b_work }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let answer: Value = resp.json().await.unwrap();
    assert_eq!(answer["outcome"], "teleporting", "B is ready: {answer}");
    let moved = until_session(
        &app,
        &seeded,
        &sid,
        LONG,
        "the session never moved to B",
        |s| {
            s["device_id"] == b.as_str()
                && s["fence"] == 2
                && s["promotion"].is_null()
                && s["status"] == "idle"
        },
    )
    .await;
    eprintln!(
        "hive_teleport: teleported in {} ms",
        began.elapsed().as_millis()
    );
    assert_eq!(moved["folder"], b_work.display().to_string(), "{moved}");
    let row = answered_as_primary(&app, &seeded, &sid, &b).await;
    assert_eq!(
        (row["role"].as_str(), row["state"].as_str()),
        (Some("primary"), Some("joined")),
        "B's own row, as the primary: {row}"
    );
    for want in ["which holds no copy of it yet", "🔀 Moved from"] {
        let noted = until_room_message(&app, &seeded, &room, |m| {
            m["content"].as_str().is_some_and(|c| c.contains(want))
        })
        .await;
        assert!(noted, "the room says: {want}");
    }

    // ── B runs it, from the copy it took: the folder and the conversation ──
    assert_eq!(
        std::fs::read_to_string(b_work.join("notes.md"))
            .ok()
            .as_deref(),
        Some(WORK),
        "the folder came with the session"
    );
    if let Some(head) = &person_head {
        assert_eq!(
            std::fs::read_to_string(b_work.join("lib.rs")).ok(),
            Some(history()),
            "the person's history, as the clone held it"
        );
        assert_eq!(
            &git(&b_work, &["rev-parse", "HEAD"]),
            head,
            "the clone's HEAD is the person's still"
        );
    }
    let note = resume_note_of(&b_dir, &sid);
    assert!(
        note.contains("moved to this device by")
            && note.contains("It ran on hive-teleport-a, in ")
            && note.contains("Paths in earlier turns under "),
        "B's resume note: {note:?}"
    );
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

    // ── A, demoted: its harness stopped; it holds copies, so a member ──────
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
        |s| member(s, &a).is_some_and(|m| m["state"] == "joined" && m["role"] == "owner"),
    )
    .await;

    stop(b_proc).await;

    // ── P2f-2b — what B took in place of the workspace's whole pack ────────
    // Read with B's process gone, and before C asks: the pack B makes again
    // for C can come out byte for byte the whole pack's, and B keeps it.
    let whole = person_head.as_ref().map(|head| {
        let store = meshharbor_hive_node::store::Store::open(&b_dir.join("hive.db"))
            .expect("B's store, its process gone");
        let whole = store
            .of_kind(&sid, "checkpoint", 1_000)
            .expect("B's copy of the chain")
            .iter()
            .find_map(
                |e| match meshharbor_hive_node::TranscriptEvent::from_json(&e.event_json) {
                    Some(meshharbor_hive_node::TranscriptEvent::Checkpoint(cp)) => cp
                        .workspace
                        .filter(|ws| ws.base.is_none() && !ws.pack.is_empty()),
                    _ => None,
                },
            )
            .expect("a checkpoint holding the workspace's pack whole");
        let sub = store
            .substitute(&sid, &whole.commit)
            .unwrap()
            .expect("B keeps a substitute for the whole pack");
        assert_eq!(
            sub.against,
            vec![head.clone()],
            "thin against the clone's HEAD"
        );
        for c in &whole.pack {
            assert!(
                !store.has_blob(&sid, &c.hash.0).unwrap(),
                "B holds none of the whole pack's own blobs"
            );
        }
        let (took, whole_len) = (len(&sub.chunks), len(&whole.pack));
        eprintln!("hive_teleport: took {took} bytes of a {whole_len}-byte whole pack");
        assert!(
            took * 4 < whole_len,
            "the clone's history did not come again: {took} of {whole_len}"
        );
        // P2f-2c — and where it runs the session, beyond the run.
        let kept = store
            .workplace(&sid)
            .unwrap()
            .expect("B keeps where the session is worked on");
        assert_eq!(kept.folder, b_work.display().to_string(), "{kept:?}");
        whole
    });

    // ── P2f-2c — B back, then C, a member joined after the move ────────────
    // B holds the workspace's first pack only as a substitute: C asks for it
    // by a want with no haves, and B makes it again from its clone.
    if let Some(whole) = &whole {
        // B resumes the session it runs, on the server's word.
        let b_proc = device(&app, &seeded, &b_dir, &b_cfg).await;
        let c_dir = dir.path().join("c");
        std::fs::create_dir_all(c_dir.join("home")).unwrap();
        let mut c_cfg = enrol(&app, &seeded, "hive-teleport-c").await;
        c_cfg.hive_replica = true;
        let c = c_cfg.agent_id.clone();
        let c_proc = device(&app, &seeded, &c_dir, &c_cfg).await;
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
        until_session(
            &app,
            &seeded,
            &sid,
            LONG,
            "C's copy never reached B's tip: the whole pack B stands in for never came",
            |s| {
                member(s, &c).is_some_and(|m| {
                    m["state"] == "joined"
                        && m["tip"]["fence"] == 2
                        && m["tip"]["seq"].as_u64() == Some(want)
                })
            },
        )
        .await;
        stop(c_proc).await;
        stop(b_proc).await;
        let c_store = meshharbor_hive_node::store::Store::open(&c_dir.join("hive.db"))
            .expect("C's store, its process gone");
        let made_again = c_store
            .substitute(&sid, &whole.commit)
            .unwrap()
            .expect("C keeps the whole pack B made again, as a substitute");
        assert!(
            made_again.against.is_empty(),
            "whole: against nothing, {made_again:?}"
        );
        eprintln!(
            "hive_teleport: C took a {}-byte whole pack, made again by B",
            len(&made_again.chunks)
        );
    }
    stop(a_proc).await;
}

/// The bytes `chunks` carry.
fn len(chunks: &[meshharbor_hive_node::checkpoint::Chunk]) -> u64 {
    chunks.iter().map(|c| c.len).sum()
}
