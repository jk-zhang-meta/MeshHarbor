// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2f-4 — an ended terminal session made a managed one, end to end: a
//! real server, and the device a process of its own (this test binary again,
//! asked to be one by [`device_process`], which an ordinary run passes at
//! once). The terminal is the real hook client (`mh hive hook`'s
//! `mirror_at`) reading a real transcript file, as Claude Code runs it.
//! Nothing is seeded on the record: the hooks adopt the session, end it, and
//! the route makes it managed; the device puts the terminal's own history in
//! place and resumes it.
//!
//! | step | the device | what the test reads |
//! |---|---|---|
//! | `SessionStart`, `Stop`, `SessionEnd` from the hook client | adopts the terminal session, mirrors its lines, ends it | the record `adopted`, then `ended` (`exited`) |
//! | `POST …/manage` | at its first start: the terminal's history from `~/.claude/projects/<the folder's name>/` under the managed session's names; `--resume` | `accepted`; the same record, `started`; the harness's argv; the note |
//! | a prompt over a viewer | the harness answers from the terminal's history | `history: 4`: the terminal's three lines, then this one |
//!
//! ⚠️ The hook client and the daemon run as this test's own account, which
//! the device's `hive_accounts` maps the owner to: the account the kernel
//! names at the hello is the one the managed session runs as.
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

/// A stand-in for Claude Code, as far as a resume asks. It keeps the history
/// where the launch names it, refuses `--resume` for an id without one, and
/// appends each prompt to it; `recall` answers with how many lines the
/// history holds. Its argv goes to `$HOME/harness.argv` at each launch.
const HARNESS: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$HOME/harness.argv"
mode=""; sid=""; prev=""
for a in "$@"; do
  case "$prev" in --session-id|--resume) mode="$prev"; sid="$a" ;; esac
  prev="$a"
done
hist="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/$sid.jsonl"
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

/// The terminal's Claude Code session.
const TERMINAL: &str = "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f74";

/// The bound on each step.
const LONG: Duration = Duration::from_secs(90);

/// Set to the device's directory when the scenario starts this binary as it.
const DEVICE_ENV: &str = "HIVE_MANAGE_DEVICE";

/// The device's process: this binary again, from the config the scenario
/// enrolled and saved in its directory, until its stdin closes. An ordinary
/// run passes it at once. With `RUST_LOG` set, it logs to its stderr.
#[test]
fn device_process() {
    let Ok(dir) = std::env::var(DEVICE_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    if std::env::var("RUST_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .with_thread_names(true)
            .try_init();
    }
    let joined = std::thread::Builder::new()
        .name("device".into())
        .stack_size(16 << 20)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("device")
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
fn an_ended_terminal_session_is_made_a_managed_one_and_resumes_its_history() {
    // Its own thread with a deep stack, and a current-thread runtime, as the
    // canary: a server's worth of tasks live in one body.
    let joined = std::thread::Builder::new()
        .name("hive-manage".into())
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

/// This test's own account: the one the hook client runs as.
fn me() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .expect("the test's account in USER")
}

/// Claude Code's name for a folder's project directory.
fn project_name(folder: &Path) -> String {
    folder
        .display()
        .to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// One hook run of the terminal: the input Claude Code writes to a hook's
/// stdin, read as the hook reads it.
async fn hook(socket: &Path, transcript: &Path, cwd: &Path, event: &str) {
    let raw = json!({
        "session_id": TERMINAL,
        "transcript_path": transcript,
        "cwd": cwd,
        "hook_event_name": event,
        "reason": "exit",
    });
    let input = meshharbor_cli::hive_hooks::hook_input(raw.to_string().as_bytes())
        .expect("Claude Code's hook input");
    meshharbor_cli::hive_hooks::mirror_at(socket, &input)
        .await
        .expect("the hook ran clean");
}

/// A prompt on `sid` over a viewer: what its turn said.
async fn recall(ws: &mut UserWs, sid: &str) -> Vec<Value> {
    let mut v = view(ws, sid).await;
    v.send(json!({"op": "hello"})).await;
    let hello = v.recv_op("hello").await;
    assert_eq!(
        hello["may_prompt"], true,
        "a managed session is prompted: {hello}"
    );
    let tip = hello["tip"].as_u64().unwrap_or(0);
    v.send(json!({"op": "follow", "after": tip})).await;
    v.send(json!({"op": "prompt", "id": "r1", "text": "recall"}))
        .await;
    let ack = v.recv_op("prompt").await;
    assert_eq!(ack["ok"], true, "{ack}");
    let turn = v.events_until(|e| e["event"]["kind"] == "turn").await;
    v.close(ws).await;
    turn
}

/// Poll the session until `pred` holds, within `bound`; the record either way.
async fn until_session(
    app: &TestApp,
    seeded: &SeededTenant,
    sid: &str,
    what: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + LONG;
    loop {
        let s = session(app, seeded, sid).await;
        if pred(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "{what}: {s}");
        tokio::time::sleep(POLL).await;
    }
}

async fn scenario() {
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hivemanage").await;
    let tid = seeded.tenant_id.clone();
    let owner = seeded.admin.access_token.clone();
    let dir = tempfile::tempdir().unwrap();

    // ── The device, which adopts and runs the owner's sessions ─────────────
    let a_dir = dir.path().join("a");
    let work = a_dir.join("roots").join("work");
    for d in [&work, &a_dir.join("home")] {
        std::fs::create_dir_all(d).unwrap();
    }
    let harness = a_dir.join("claude");
    std::fs::write(&harness, HARNESS).unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cfg = enrol(&app, &seeded, "hive-manage-a").await;
    cfg.hive_enabled = true;
    cfg.hive_adopt = true;
    cfg.hive_accounts.insert(seeded.admin.id.clone(), me());
    cfg.hive_roots = vec![a_dir.join("roots").display().to_string()];
    cfg.hive_harness = Some(harness.display().to_string());
    meshharbord::config::save(&a_dir.join("config.toml"), &cfg).expect("the device's config");
    let a = cfg.agent_id.clone();
    let mut proc = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "device_process",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DEVICE_ENV, &a_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("the device's process");
    wait_online(&app, &seeded, &a).await;
    let socket = a_dir.join("run").join("adopt.sock");
    let deadline = Instant::now() + LONG;
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the adopt socket never came up");
        tokio::time::sleep(POLL).await;
    }

    // ── The terminal: a transcript where Claude Code keeps it, and its hooks ──
    let project = a_dir
        .join("home")
        .join(".claude")
        .join("projects")
        .join(project_name(&work));
    std::fs::create_dir_all(&project).unwrap();
    let transcript = project.join(format!("{TERMINAL}.jsonl"));
    std::fs::write(
        &transcript,
        format!(
            "{{\"type\":\"permission-mode\",\"permissionMode\":\"bypassPermissions\",\"sessionId\":\"{TERMINAL}\"}}\n\
             {{\"type\":\"user\",\"sessionId\":\"{TERMINAL}\",\"message\":{{\"role\":\"user\",\"content\":\"tidy the build\"}},\"isSidechain\":false,\"uuid\":\"1\"}}\n\
             {{\"type\":\"assistant\",\"sessionId\":\"{TERMINAL}\",\"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"done\"}}]}},\"isSidechain\":false}}\n"
        ),
    )
    .unwrap();
    hook(&socket, &transcript, &work, "SessionStart").await;
    hook(&socket, &transcript, &work, "Stop").await;
    let list: Value = app
        .auth_get(&format!("/api/tenant/{tid}/hive/session"), &owner)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sid = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["harness_session"] == TERMINAL)
        .and_then(|s| s["id"].as_str())
        .expect("the terminal session adopted")
        .to_string();
    hook(&socket, &transcript, &work, "SessionEnd").await;
    let ended = until_session(&app, &seeded, &sid, "its terminal never ended", |s| {
        s["status"] == "ended"
    })
    .await;
    assert_eq!(
        (ended["origin"].as_str(), ended["end_reason"].as_str()),
        (Some("adopted"), Some("exited")),
        "{ended}"
    );

    // ── Made a managed one: from the terminal's own history ────────────────
    let began = Instant::now();
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tid}/hive/session/{sid}/manage"),
            &owner,
        )
        .json(&json!({ "folder": work }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let answer: Value = resp.json().await.unwrap();
    assert_eq!(answer["outcome"], "accepted", "{answer}");
    eprintln!(
        "hive_manage: made managed in {} ms",
        began.elapsed().as_millis()
    );
    assert_eq!(
        answer["session"]["id"],
        sid.as_str(),
        "the same record: {answer}"
    );
    assert_eq!(answer["session"]["origin"], "started", "{answer}");
    let idle = until_session(&app, &seeded, &sid, "it never came up", |s| {
        s["status"] == "idle"
    })
    .await;
    assert_eq!(idle["account"].as_str(), Some(me().as_str()), "{idle}");

    // A prompt: the harness answers from the terminal's history.
    let mut ws = UserWs::open(&app, &owner).await;
    let turn = recall(&mut ws, &sid).await;
    assert!(
        turn.iter().any(|e| text_of(e).contains("history: 4")),
        "the terminal's three lines, then the prompt: {turn:?}"
    );
    let argv = std::fs::read_to_string(a_dir.join("home").join("harness.argv")).unwrap();
    assert!(
        argv.lines()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w == ["--resume", TERMINAL]),
        "resumed: {argv}"
    );
    let note = std::fs::read_to_string(
        a_dir
            .join("run")
            .join(&sid)
            .join(meshharbord::hive::RESUME_NOTE_FILE),
    )
    .unwrap_or_default();
    assert!(
        note.starts_with("This session ran in a terminal on this device"),
        "told where it ran: {note:?}"
    );
    assert!(
        std::fs::read_to_string(&transcript)
            .unwrap()
            .lines()
            .count()
            == 3,
        "the terminal's own file is as it left it"
    );
    // The device's stdin closes: it stops.
    drop(proc.stdin.take());
    let _ = tokio::time::timeout(Duration::from_secs(20), proc.wait()).await;
}
