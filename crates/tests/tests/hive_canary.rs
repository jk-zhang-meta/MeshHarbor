// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P0f — AC2, the canary: what a session says reaches its device, and
//! nothing the server keeps.
//!
//! A real server (`TestApp`, module `hive` on) and a real device in-process:
//! `meshharbord`'s signalling loop, its Hive supervisor, its replica store and
//! its viewer peer — sessions launched as this test's own account through
//! `hive::init_as_daemon` (feature `hive-test-launcher`). This file is its own
//! test BINARY because that supervisor is process-global: in the lib's test
//! binary, every other in-process agent would re-point it at its socket.
//!
//! Three canaries, three channels into a session:
//!
//! | canary | how it enters | must be in | must NOT be in |
//! |---|---|---|---|
//! | `prompt` | a prompt typed over the viewer peer | the device's store, the viewer | Mongo · object store · server logs · any frame the server sent the browser |
//! | `tool` | a tool's output (a file in the session's folder) | the same | the same |
//! | `stderr` | what a crashing harness writes to stderr | the device's store, as a note | the same |
//!
//! Each absence is checked next to a PRESENCE that proves the check can see:
//! the session's title (metadata, the server's by design) is found in Mongo;
//! a probe file uploaded through the files API is found in the object store;
//! the session's id is found in a server log line and in a frame. An absence
//! that cannot fail proves nothing.
//!
//! "Shown failing first" (AC2): on the code before this test, the `stderr`
//! canary reached the server — a crashing harness's stderr tail rode the
//! `ended` detail into the session record and the room's ended note. The
//! negative controls are in the FR-90 step log.
//!
//! # Two devices (P2d-6)
//!
//! With the replicaset on, each session is placed on a second device that
//! holds copies, and every canary must reach ITS store too, over the replica
//! stream (P2d-3), while the server carries the stream's signalling and the
//! member's tips. The member is a process of its own, because a process
//! holds one supervisor: this test binary again, asked to be a device by
//! [`member_device_process`], which an ordinary run passes at once. Its
//! store is read after it is gone.
//!
//! ⚠️ The stream rides `direct` here, on loopback: the tests build carries
//! no overlay, so neither device has a DERP connection, and no stream frame
//! crosses the server's `/derp`. That the `derp` rung carries ciphertext
//! only is held by the device's own tests (P2d-2c); the server's relay, in
//! the field run (P2k).
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bson::{Document, doc};
use futures::TryStreamExt;
use meshharbor_tests::fixtures::seed::SeededTenant;
use meshharbor_tests::fixtures::test_app::TestApp;
use serde_json::{Value, json};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

// The server, the in-process device, a browser's socket and viewer peer, the
// harness's side of a toolbelt — shared with `hive_drivers.rs`.
mod hive_support;
use hive_support::*;

/// A stand-in for Claude Code. Each prompt: one tool call that reads
/// `canary-tool.txt` in the session's folder, and its result. A prompt with
/// `crash` in it writes `canary-stderr.txt` to stderr and exits 3.
const HARNESS: &str = r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *crash*) cat canary-stderr.txt >&2; exit 3 ;;
  esac
  out=$(cat canary-tool.txt)
  echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":["Bash"]}'
  echo '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"cat canary-tool.txt"}}]}}'
  echo '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"'"$out"'","is_error":false}]}}'
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"read it"}]}}'
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
"#;

// ─── The log watch ──────────────────────────────────────────────────────────

/// Every event and span field of this thread's runtime that carries one of
/// the watched strings: (target, string). Installed as the thread's default
/// subscriber around a current-thread runtime, so the server's tasks and the
/// device's all log through it.
#[derive(Clone, Default)]
struct Watch {
    strings: Arc<Mutex<Vec<String>>>,
    hits: Arc<Mutex<Vec<(String, String)>>>,
}

impl Watch {
    fn watch(&self, s: &str) {
        self.strings.lock().unwrap().push(s.to_string());
    }

    fn check(&self, target: &str, fields: &str) {
        for s in self.strings.lock().unwrap().iter() {
            if fields.contains(s.as_str()) {
                self.hits
                    .lock()
                    .unwrap()
                    .push((target.to_string(), s.clone()));
            }
        }
    }

    /// The SERVER's lines that carried `s`: every crate of the server is
    /// `meshharbor_*` or `meshharbor_core`; the device's are `meshharbord` and
    /// `meshharbor_node_core`, and its store `meshharbor_hive_node`.
    fn server_hits(&self, s: &str) -> Vec<String> {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, w)| {
                w == s && (t.starts_with("meshharbor") || t.starts_with("meshharbor_core"))
            })
            .map(|(t, _)| t.clone())
            .collect()
    }
}

struct Fields(String);

impl Visit for Fields {
    fn record_str(&mut self, _: &Field, v: &str) {
        self.0.push_str(v);
        self.0.push(' ');
    }
    fn record_debug(&mut self, _: &Field, v: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{v:?} "));
    }
}

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Watch {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut f = Fields(String::new());
        event.record(&mut f);
        self.check(event.metadata().target(), &f.0);
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, S>) {
        let mut f = Fields(String::new());
        attrs.record(&mut f);
        self.check(attrs.metadata().target(), &f.0);
    }

    fn on_record(&self, span: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let mut f = Fields(String::new());
        values.record(&mut f);
        let target = ctx
            .span(span)
            .map(|s| s.metadata().target().to_string())
            .unwrap_or_default();
        self.check(&target, &f.0);
    }
}

// ─── The server's side, read past the API ───────────────────────────────────

/// Every document in the test's database whose raw BSON holds `needle` —
/// bytes, so a string inside a binary field is found too.
async fn in_mongo(db: &mongodb::Database, needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for coll in db.list_collection_names().await.unwrap() {
        let mut cur = db
            .collection::<Document>(&coll)
            .find(doc! {})
            .await
            .unwrap();
        while let Some(d) = cur.try_next().await.unwrap() {
            let raw = bson::to_vec(&d).unwrap();
            if contains(&raw, needle.as_bytes()) {
                hits.push(format!(
                    "{coll} {}",
                    d.get("_id").map(|i| i.to_string()).unwrap_or_default()
                ));
            }
        }
    }
    hits
}

/// Every file under the object store's root whose name or bytes hold `needle`.
fn in_storage(root: &Path, needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.to_string_lossy().contains(needle) {
                hits.push(format!("name {}", p.display()));
            }
            match e.file_type() {
                Ok(t) if t.is_dir() => dirs.push(p),
                Ok(t) if t.is_file() => {
                    let small = e.metadata().map(|m| m.len() <= 64 << 20).unwrap_or(false);
                    if small
                        && let Ok(bytes) = std::fs::read(&p)
                        && contains(&bytes, needle.as_bytes())
                    {
                        hits.push(format!("bytes {}", p.display()));
                    }
                }
                _ => {}
            }
        }
    }
    hits
}

// ─── The test ───────────────────────────────────────────────────────────────

#[test]
fn what_a_session_says_reaches_its_device_and_nothing_the_server_keeps() {
    let watch = Watch::default();
    let w = watch.clone();
    // Its own thread: a deep stack (the suite wants 8 MiB), and a
    // current-thread runtime under a thread-default subscriber, so every
    // task of the server and the device logs through the watch.
    let joined = std::thread::Builder::new()
        .name("hive-canary".into())
        .stack_size(16 << 20)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let subscriber = tracing_subscriber::registry().with(w.clone());
            tracing::subscriber::with_default(subscriber, || rt.block_on(scenario(w)));
        })
        .unwrap()
        .join();
    if let Err(panic) = joined {
        std::panic::resume_unwind(panic);
    }
}

/// P2d-6 — set to the member's directory when the scenario starts this
/// binary as the member device.
const MEMBER_ENV: &str = "HIVE_CANARY_MEMBER";

/// P2d-6 — the member device's process: this binary again, a device that
/// holds copies (`hive_replica`, agent sessions off), from the config the
/// scenario enrolled and saved in its directory, until its stdin closes. An
/// ordinary run passes it at once.
#[test]
fn member_device_process() {
    let Ok(dir) = std::env::var(MEMBER_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let joined = std::thread::Builder::new()
        .name("hive-canary-member".into())
        .stack_size(16 << 20)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let cfg =
                    meshharbord::config::load(&dir.join("config.toml")).expect("the member's config");
                meshharbord::hive::init_as_daemon(
                    &cfg,
                    &dir.join("hive.db"),
                    &dir.join("run"),
                    &dir.join("home"),
                )
                .expect("the member's launcher");
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

/// P2d-6 — where the primary's store ends `sid`, as a viewer hears it: the
/// test never opens a store a running device writes.
async fn primary_tip(ws: &mut UserWs, sid: &str) -> Option<u64> {
    let mut b = view(ws, sid).await;
    b.send(json!({"op": "hello"})).await;
    let tip = b.recv_op("hello").await["tip"].as_u64();
    b.close(ws).await;
    tip
}

/// P2d-6 — whether `member`'s copy of `sid`, as the server last heard it,
/// ends at `want`, the primary's tip, within [`WAIT`].
async fn member_caught_up(
    app: &TestApp,
    seeded: &SeededTenant,
    sid: &str,
    member: &str,
    want: Option<u64>,
) -> bool {
    let deadline = Instant::now() + WAIT;
    while want.is_some() && Instant::now() < deadline {
        let s = session(app, seeded, sid).await;
        let has = s["replicaset"]["members"]
            .as_array()
            .and_then(|m| m.iter().find(|m| m["device_id"] == member))
            .and_then(|m| m["tip"]["seq"].as_u64());
        if has == want {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    false
}

/// P2d-6 — every event of `sid` the store at `db` holds, its JSON as kept.
fn copy_of(db: &Path, sid: &str) -> String {
    let store = meshharbor_hive_node::store::Store::open(db).expect("the member's store");
    let events = store.page(sid, 0, 100_000).expect("the member's copy");
    events
        .iter()
        .map(|e| e.event_json.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn scenario(watch: Watch) {
    let prompt_canary = random("canaryprompt");
    let tool_canary = random("canarytool");
    let stderr_canary = random("canarystderr");
    // P1a-2 — what an approval would run, and what a driver told the model.
    let approval_canary = random("canaryapproval");
    let deny_canary = random("canarydeny");
    let title_probe = random("probetitle");
    let file_probe = random("probefile");
    for c in [
        &prompt_canary,
        &tool_canary,
        &stderr_canary,
        &approval_canary,
        &deny_canary,
    ] {
        watch.watch(c);
    }

    // The API's per-IP limiter is not what this test is about, and its 429
    // would end a run before the server's side is searched.
    // P2d-6 — the replicaset on: each session is placed on the member too.
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hivecanary").await;
    upload_probe(&app, &seeded, &file_probe).await;

    // The device: a folder root holding the two sessions' folders, a home,
    // the harness, the store.
    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("roots");
    let work = roots.join(&title_probe);
    let crash = roots.join("crash");
    let home = dir.path().join("home");
    for d in [&work, &crash, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(work.join("canary-tool.txt"), &tool_canary).unwrap();
    std::fs::write(crash.join("canary-stderr.txt"), &stderr_canary).unwrap();
    std::fs::write(crash.join("canary-tool.txt"), "unused").unwrap();
    let harness = dir.path().join("claude");
    std::fs::write(&harness, HARNESS).unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut cfg = enrol(&app, &seeded, "hive-canary").await;
    cfg.hive_enabled = true;
    cfg.hive_accounts
        .insert(seeded.admin.id.clone(), "canary".into());
    cfg.hive_roots = vec![roots.display().to_string()];
    cfg.hive_harness = Some(harness.display().to_string());
    cfg.hive_max_sessions = Some(2);
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

    // P2d-6 — the member: a device that holds copies, in a process of its
    // own, online before the first session so placement takes it.
    let member_dir = dir.path().join("member");
    std::fs::create_dir_all(member_dir.join("home")).unwrap();
    let mut member_cfg = enrol(&app, &seeded, "hive-canary-member").await;
    member_cfg.hive_replica = true;
    let member = member_cfg.agent_id.clone();
    meshharbord::config::save(&member_dir.join("config.toml"), &member_cfg)
        .expect("the member's config");
    let mut member_process = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "member_device_process",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MEMBER_ENV, &member_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("the member's process");
    wait_online(&app, &seeded, &member).await;
    let mut ws = UserWs::open(&app, &seeded.admin.access_token).await;

    // ── Session 1: a prompt over the peer, and a tool's output ──────────────
    let s1 = start(&app, &seeded, &device, &work).await;
    let sid1 = s1["id"].as_str().unwrap().to_string();
    let room1 = s1["room_id"].as_str().unwrap().to_string();
    watch.watch(&sid1);
    assert!(
        reached(&app, &seeded, &sid1, "idle").await,
        "session 1 never came up"
    );
    let mut b = view(&mut ws, &sid1).await;
    b.send(json!({"op": "hello"})).await;
    let hello = b.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "{hello}");
    let tip = hello["tip"].as_u64().unwrap_or(0);
    b.send(json!({"op": "follow", "after": tip})).await;
    b.send(json!({"op": "prompt", "id": "p1", "text": format!("read the file, {prompt_canary}")}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack["ok"], true, "the device took the prompt: {ack}");
    // The turn, as far as it gets — everything after this point is checked
    // only once the server's side has been searched, so a leak is reported
    // as a leak rather than as whatever it broke on the way.
    let live1 = b.events_until(|e| e["event"]["kind"] == "turn").await;
    let turn_ref = format!("{sid1}#1");
    let deadline = Instant::now() + WAIT;
    let mut stub_done = false;
    while !stub_done && Instant::now() < deadline {
        stub_done = room_messages(&app, &seeded, &room1).await.iter().any(|m| {
            m["binding"]["ref"] == turn_ref.as_str()
                && m["content"].as_str().is_some_and(|c| c.contains("done"))
        });
        if !stub_done {
            tokio::time::sleep(POLL).await;
        }
    }
    // ── An approval in session 1 (P1a-2): the test plays the harness ────────
    // asking, through the session's toolbelt as Claude Code would, and the
    // browser is the driver who answers.
    let socket = dir.path().join("run").join(&sid1).join("toolbelt.sock");
    let mut harness = Harness::connect(&socket).await;
    harness
        .send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"}}))
        .await;
    let _ = harness.answer(0).await;
    harness
        .send(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "approve",
                "arguments": {"tool_name": "Bash", "tool_use_id": "toolu_canary",
                              "input": {"command": format!("echo {approval_canary}")}},
            }}),
        )
        .await;
    let open = b.recv_op("approvals").await;
    let approval = open["pending"][0].as_str().unwrap_or_default().to_string();
    let approval_ref = format!("{sid1}!{approval}");
    let stub_opened = until_room_message(&app, &seeded, &room1, |m| {
        m["binding"]["ref"] == approval_ref.as_str()
            && m["content"]
                .as_str()
                .is_some_and(|c| c.contains("Approval needed"))
    })
    .await;
    b.send(
        json!({"op": "answer", "id": "a1", "approval": approval, "decision": "deny",
        "message": format!("not now, {deny_canary}")}),
    )
    .await;
    let answered = b.recv_op("answer").await;
    let verdict = harness.answer(1).await;
    let stub_denied = until_room_message(&app, &seeded, &room1, |m| {
        m["binding"]["ref"] == approval_ref.as_str()
            && m["content"]
                .as_str()
                .is_some_and(|c| c.contains("denied by"))
    })
    .await;

    b.send(json!({"op": "page", "after": 0, "limit": 500}))
        .await;
    let stored1 = b.recv_op("page").await;
    b.close(&mut ws).await;
    let _ = app
        .auth_post(
            &format!("/api/tenant/{}/hive/session/{sid1}/stop", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await;
    let stopped1 = reached(&app, &seeded, &sid1, "ended").await;

    // ── Session 2: a harness that dies talking ───────────────────────────────
    let s2 = start(&app, &seeded, &device, &crash).await;
    let sid2 = s2["id"].as_str().unwrap().to_string();
    let up2 = reached(&app, &seeded, &sid2, "idle").await;
    let mut b2 = view(&mut ws, &sid2).await;
    b2.send(json!({"op": "hello"})).await;
    let tip2 = b2.recv_op("hello").await["tip"].as_u64().unwrap_or(0);
    b2.send(json!({"op": "follow", "after": tip2})).await;
    b2.send(json!({"op": "prompt", "id": "p2", "text": "crash"}))
        .await;
    let live2 = b2
        .events_until(|e| {
            e["event"]["kind"] == "note"
                && e["event"]["text"]
                    .as_str()
                    .is_some_and(|t| t.contains(stderr_canary.as_str()))
        })
        .await;
    let ended2 = reached(&app, &seeded, &sid2, "ended").await;
    b2.close(&mut ws).await;

    // P2d-6 — the member follows both sessions to their ends, over the
    // stream, while the primary is still up to serve them; then it goes.
    let want1 = primary_tip(&mut ws, &sid1).await;
    let want2 = primary_tip(&mut ws, &sid2).await;
    let caught1 = member_caught_up(&app, &seeded, &sid1, &member, want1).await;
    let caught2 = member_caught_up(&app, &seeded, &sid2, &member, want2).await;
    drop(member_process.stdin.take());
    let member_exit = tokio::time::timeout(Duration::from_secs(20), member_process.wait()).await;

    let _ = stop_device.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), device_task).await;

    // ── The server's side ───────────────────────────────────────────────────
    let uploads = meshharbor_core::storage::local_upload_dir();
    let frames = ws.seen.lock().unwrap().clone();
    let in_frames = |s: &str| frames.iter().filter(|f| f.contains(s)).count();

    // The checks can see: each channel holds what it is supposed to.
    assert!(
        !in_mongo(&app.db, &title_probe).await.is_empty(),
        "the Mongo scan must find the session's title, which the server holds"
    );
    assert!(
        !in_storage(&uploads, &file_probe).is_empty(),
        "the object-store walk must find the probe file under {}",
        uploads.display()
    );
    assert!(
        !watch.server_hits(&sid1).is_empty(),
        "the log watch must see the server log the session's id"
    );
    assert!(
        in_frames(&sid1) > 0,
        "the frame capture must see the session's id"
    );

    // And none of them holds what the session said.
    let mut leaks = Vec::new();
    for (what, canary) in [
        ("the prompt", &prompt_canary),
        ("the tool's output", &tool_canary),
        ("the harness's stderr", &stderr_canary),
        ("what an approval would run", &approval_canary),
        ("what a driver told the model", &deny_canary),
    ] {
        for hit in in_mongo(&app.db, canary).await {
            leaks.push(format!("{what} is in Mongo: {hit}"));
        }
        for hit in in_storage(&uploads, canary) {
            leaks.push(format!("{what} is in the object store: {hit}"));
        }
        for target in watch.server_hits(canary) {
            leaks.push(format!("{what} is in a server log line ({target})"));
        }
        if in_frames(canary) > 0 {
            leaks.push(format!("{what} is in a frame the server sent the browser"));
        }
    }
    assert!(
        leaks.is_empty(),
        "what a session says reached the server:\n  {}",
        leaks.join("\n  ")
    );

    // ── The device's side: everything is there ──────────────────────────────
    let live1: Vec<String> = live1.iter().map(text_of).collect();
    assert!(
        live1
            .iter()
            .any(|e| e.contains("user_message") && e.contains(prompt_canary.as_str())),
        "the viewer saw the prompt: {live1:#?}"
    );
    assert!(
        live1
            .iter()
            .any(|e| e.contains("tool_result") && e.contains(tool_canary.as_str())),
        "the viewer saw the tool's output: {live1:#?}"
    );
    assert!(
        live1.iter().any(|e| e.contains("\"turn\"")),
        "the turn completed: {live1:#?}"
    );
    let stored1 = stored1.to_string();
    assert!(
        stored1.contains(prompt_canary.as_str()) && stored1.contains(tool_canary.as_str()),
        "the device's store holds both: {stored1}"
    );
    assert!(stub_done, "the server stubbed the turn as done");

    // P1a-2 — the approval: the driver's answer reached the harness, with
    // the driver's words; the server knew only THAT it waited, and how it
    // ended, and who answered.
    assert!(
        !approval.is_empty(),
        "the viewer was told an approval is open: {open}"
    );
    assert_eq!(
        answered["ok"], true,
        "the device took the driver's answer: {answered}"
    );
    let said: Value = serde_json::from_str(
        verdict["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("{}"),
    )
    .unwrap_or_default();
    assert_eq!(said["behavior"], "deny", "{verdict}");
    assert!(
        said["message"]
            .as_str()
            .is_some_and(|m| m.contains(deny_canary.as_str())),
        "the harness read the driver's reason: {said}"
    );
    assert!(
        stub_opened,
        "the room's stub said the session needs approval"
    );
    assert!(stub_denied, "and then how it ended");
    let record = app
        .db
        .collection::<Document>("agent_approvals")
        .find_one(doc! { "approval_id": &approval })
        .await
        .unwrap()
        .expect("the approval is on the record");
    assert_eq!(record.get_str("status").unwrap(), "denied", "{record}");
    assert_eq!(
        record.get_object_id("answered_by").unwrap().to_hex(),
        seeded.admin.id,
        "who answered: {record}"
    );
    let notified = app
        .db
        .collection::<Document>("notifications")
        .find_one(doc! { "notification_type": "approval_request" })
        .await
        .unwrap()
        .expect("the driver was notified");
    assert!(
        notified
            .get_str("link")
            .is_ok_and(|l| l.ends_with(&format!("/room/{room1}"))),
        "the notification leads to the session's room: {notified}"
    );
    assert!(
        stored1.contains(approval_canary.as_str()) && stored1.contains(deny_canary.as_str()),
        "the device's store holds what was asked and what the driver said: {stored1}"
    );
    assert!(stopped1, "session 1 ended on its stop");
    assert!(up2, "session 2 came up");
    assert!(
        live2
            .iter()
            .any(|e| text_of(e).contains(stderr_canary.as_str())),
        "the harness's last words are in the transcript: {live2:#?}"
    );
    assert!(ended2, "session 2 ended when its harness died");
    let s2 = session(&app, &seeded, &sid2).await;
    assert!(
        s2["detail"].as_str().is_some_and(|d| d.contains("code 3")),
        "the server knows HOW it ended: {s2}"
    );

    // ── The member's side (P2d-6): every canary in its copy too ─────────────
    assert!(
        matches!(&member_exit, Ok(Ok(s)) if s.success()),
        "the member's process ended cleanly: {member_exit:?}"
    );
    assert!(
        caught1 && caught2,
        "the member's copies reached the primary's tips: session 1 {caught1}, session 2 {caught2}"
    );
    let member_db = member_dir.join("hive.db");
    let (copy1, copy2) = (copy_of(&member_db, &sid1), copy_of(&member_db, &sid2));
    // A replicated session checkpoints at each turn's end, and a member
    // applies a checkpoint only once it holds every blob it names: its
    // checkpoint is the blobs' crossing too.
    assert!(
        copy1.contains("\"kind\":\"checkpoint\""),
        "a checkpoint reached the member: {copy1}"
    );
    assert!(
        !copy1.contains("was not taken"),
        "and every checkpoint was taken: {copy1}"
    );
    for (what, canary, copy) in [
        ("the prompt", &prompt_canary, &copy1),
        ("the tool's output", &tool_canary, &copy1),
        ("what an approval would run", &approval_canary, &copy1),
        ("what a driver told the model", &deny_canary, &copy1),
        ("the harness's stderr", &stderr_canary, &copy2),
    ] {
        assert!(
            copy.contains(canary.as_str()),
            "the member's copy holds {what}"
        );
    }
}
