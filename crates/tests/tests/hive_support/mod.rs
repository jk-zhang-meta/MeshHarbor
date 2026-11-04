// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 — what the Hive test binaries share: a real server (`TestApp`), a
//! real device in-process (`roomlerd`'s signalling loop), a browser's user
//! socket and its viewer peer, and the harness's side of a toolbelt. Each
//! binary is its own process because the device's Hive supervisor is
//! process-global (`hive_canary.rs`, `hive_drivers.rs`, `hive_memory.rs`,
//! `hive_memory_off.rs`).
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use meshharbor_tests::fixtures::seed::SeededTenant;
use meshharbor_tests::fixtures::test_app::TestApp;
use meshharbord::config::AgentConfig;
use meshharbord::encode::EncoderPreference;
use meshharbord::hive::framing::{self, Bounds, Reassembler};
use meshharbord::{enrollment, signaling};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

pub const WAIT: Duration = Duration::from_secs(20);
/// Between two reads of a state the server applies after the frame.
pub const POLL: Duration = Duration::from_millis(250);

pub fn random(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

// ─── The browser's user socket ──────────────────────────────────────────────

pub type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The browser's `/ws`. Every frame the server sends is kept in `seen`,
/// whether or not the test reads it.
pub struct UserWs {
    pub sink: futures::stream::SplitSink<Ws, Message>,
    pub rx: mpsc::UnboundedReceiver<Value>,
    pub seen: Arc<Mutex<Vec<String>>>,
}

impl UserWs {
    pub async fn open(app: &TestApp, token: &str) -> Self {
        let url = format!(
            "ws://{}/ws?token={}",
            app.addr,
            token
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        );
        let (ws, _) = connect_async(&url).await.expect("user ws connect");
        let (sink, mut stream) = ws.split();
        let (tx, rx) = mpsc::unbounded_channel();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let keep = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                if let Message::Text(text) = msg {
                    keep.lock().unwrap().push(text.to_string());
                    if let Ok(v) = serde_json::from_str::<Value>(&text) {
                        let _ = tx.send(v);
                    }
                }
            }
        });
        Self { sink, rx, seen }
    }

    pub async fn send(&mut self, kind: &str, data: Value) {
        self.sink
            .send(Message::Text(
                json!({ "type": kind, "data": data }).to_string().into(),
            ))
            .await
            .unwrap();
    }

    /// The `data` of the next frame of `kind`; a refusal on the way fails.
    pub async fn read(&mut self, kind: &str) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("no {kind} in time"));
            let f = tokio::time::timeout(left, self.rx.recv())
                .await
                .unwrap_or_else(|_| panic!("no {kind} in time"))
                .expect("the user socket is open");
            assert_ne!(f["type"], "hive:view.refused", "refused: {f}");
            if f["type"] == kind {
                return f["data"].clone();
            }
        }
    }
}

// ─── The browser's viewer peer ──────────────────────────────────────────────

pub struct Browser {
    pub grant: String,
    pub pc: Arc<RTCPeerConnection>,
    pub inbox: mpsc::Receiver<Value>,
    pub dc: Arc<RTCDataChannel>,
    pub next_id: u32,
}

impl Browser {
    pub async fn send(&mut self, v: Value) {
        let bytes = serde_json::to_vec(&v).unwrap();
        for frame in framing::encode(self.next_id, &bytes) {
            self.dc.send(&Bytes::from(frame)).await.unwrap();
        }
        self.next_id = self.next_id.wrapping_add(1);
    }

    pub async fn recv_op(&mut self, op: &str) -> Value {
        loop {
            let v = tokio::time::timeout(WAIT, self.inbox.recv())
                .await
                .unwrap_or_else(|_| panic!("no {op:?} from the device in time"))
                .expect("the channel is open");
            if v["op"] == op {
                return v;
            }
        }
    }

    /// Transcript events as they arrive, until one matches `until` or the
    /// patience runs out — what arrived, either way.
    pub async fn events_until(&mut self, until: impl Fn(&Value) -> bool) -> Vec<Value> {
        let deadline = Instant::now() + WAIT;
        let mut got = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(left, self.inbox.recv()).await {
                Ok(Some(v)) if v["op"] == "events" => {
                    for e in v["events"].as_array().cloned().unwrap_or_default() {
                        let done = until(&e);
                        got.push(e);
                        if done {
                            return got;
                        }
                    }
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        got
    }

    pub async fn close(self, ws: &mut UserWs) {
        ws.send("hive:view.close", json!({ "grant_id": self.grant }))
            .await;
        let _ = self.pc.close().await;
    }
}

/// Open `session`'s viewer as the SPA does: `hive:view.open`, a peer dialled
/// only after `ready`, our offer before our candidates, theirs buffered until
/// the answer.
pub async fn view(ws: &mut UserWs, session: &str) -> Browser {
    ws.send(
        "hive:view.open",
        json!({ "session_id": session, "ref": session }),
    )
    .await;
    let ready = ws.read("hive:view.ready").await;
    let grant = ready["grant_id"].as_str().unwrap().to_string();

    let api = APIBuilder::new().build();
    let pc = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    let dc = pc.create_data_channel("hive", None).await.unwrap();
    let (inbox_tx, inbox) = mpsc::channel(1024);
    {
        let reasm = Arc::new(Mutex::new(Reassembler::new(Bounds {
            max_message_bytes: 8 * 1024 * 1024,
            max_in_flight: 4,
        })));
        dc.on_message(Box::new(move |msg| {
            let inbox = inbox_tx.clone();
            let reasm = Arc::clone(&reasm);
            Box::pin(async move {
                let done = reasm.lock().unwrap().push(&msg.data);
                if let Ok(Some(m)) = done
                    && let Ok(v) = serde_json::from_slice::<Value>(&m)
                {
                    let _ = inbox.send(v).await;
                }
            })
        }));
    }
    let (cand_tx, mut cand_rx) = mpsc::unbounded_channel::<Value>();
    pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let tx = cand_tx.clone();
        Box::pin(async move {
            if let Some(c) = c
                && let Ok(init) = c.to_json()
            {
                let _ = tx.send(serde_json::to_value(init).unwrap());
            }
        })
    }));
    let offer = pc.create_offer(None).await.unwrap();
    pc.set_local_description(offer.clone()).await.unwrap();
    ws.send(
        "hive:view.offer",
        json!({ "grant_id": grant, "sdp": offer.sdp }),
    )
    .await;

    let deadline = Instant::now() + WAIT;
    let mut answered = false;
    let mut theirs: Vec<RTCIceCandidateInit> = Vec::new();
    while dc.ready_state() != RTCDataChannelState::Open {
        assert!(Instant::now() < deadline, "the viewer channel never opened");
        while let Ok(c) = cand_rx.try_recv() {
            ws.send(
                "hive:view.ice",
                json!({ "grant_id": grant, "candidate": c }),
            )
            .await;
        }
        let Ok(Some(f)) = tokio::time::timeout(Duration::from_millis(50), ws.rx.recv()).await
        else {
            continue;
        };
        if f["data"]["grant_id"] != grant.as_str() {
            continue;
        }
        match f["type"].as_str() {
            Some("hive:view.answer") => {
                let sdp = f["data"]["sdp"].as_str().unwrap().to_string();
                pc.set_remote_description(RTCSessionDescription::answer(sdp).unwrap())
                    .await
                    .unwrap();
                answered = true;
                for c in theirs.drain(..) {
                    let _ = pc.add_ice_candidate(c).await;
                }
            }
            Some("hive:view.ice") => {
                if let Ok(init) =
                    serde_json::from_value::<RTCIceCandidateInit>(f["data"]["candidate"].clone())
                {
                    if answered {
                        let _ = pc.add_ice_candidate(init).await;
                    } else {
                        theirs.push(init);
                    }
                }
            }
            Some("hive:view.closed") => panic!("the device closed the viewer: {f}"),
            _ => {}
        }
    }
    Browser {
        grant,
        pc,
        inbox,
        dc,
        next_id: 0,
    }
}

// ─── Scaffolding ────────────────────────────────────────────────────────────

pub async fn enrol(app: &TestApp, seeded: &SeededTenant, machine: &str) -> AgentConfig {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    enrollment::enroll(enrollment::EnrollInputs {
        server_url: &app.base_url,
        enrollment_token: et["enrollment_token"].as_str().unwrap(),
        machine_id: machine,
        machine_name: machine,
        install: None,
    })
    .await
    .expect("agent enrollment")
}

/// `roomlerd run`'s signalling loop, with the handles `main.rs` gives it.
pub fn spawn_device(
    cfg: AgentConfig,
    stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (view_tx, _view_rx) = tokio::sync::watch::channel(Default::default());
        let broker = meshharbord::consent::ConsentBroker::new(
            meshharbord::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("roomler-test-consent-{}", cfg.agent_id)),
        )
        .expect("consent broker init");
        let exec_enabled = cfg.exec_enabled;
        let remote_config_enabled = cfg.remote_config_enabled;
        let _ = signaling::run(
            signaling::OrgCtx::primary(meshharbord::token_slot::TokenSlot::new(
                cfg.agent_token.clone(),
            )),
            meshharbord::delegate::Delegation::Off,
            cfg,
            EncoderPreference::Software,
            stop,
            connected,
            view_tx,
            Default::default(),
            broker,
            meshharbord::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            meshharbord::remote_config::RemoteConfigServices::new(
                PathBuf::from("unused-in-tests.toml"),
                Arc::new(tokio::sync::Mutex::new(())),
                exec_enabled,
                remote_config_enabled,
            ),
            meshharbord::rc_sessions::RcSessionRegistry::new(),
        )
        .await;
    })
}

pub async fn wait_online(app: &TestApp, seeded: &SeededTenant, agent_id: &str) {
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
        if row["is_online"] == true {
            return;
        }
        assert!(Instant::now() < deadline, "the device never came online");
        tokio::time::sleep(POLL).await;
    }
}

/// `POST …/hive/session`, retrying only the refusals that race the device's
/// registration (the row reads online a moment before the Hub holds its
/// capabilities); both come before any session exists.
pub async fn start(app: &TestApp, s: &SeededTenant, device: &str, folder: &Path) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let body: Value = app
            .auth_post(
                &format!("/api/tenant/{}/hive/session", s.tenant_id),
                &s.admin.access_token,
            )
            .json(&json!({ "device_id": device, "folder": folder }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let racing = body["outcome"] == "refused"
            && body["session"].is_null()
            && matches!(
                body["reason"].as_str(),
                Some("device_offline" | "device_unsupported")
            );
        if !racing {
            assert_eq!(body["outcome"], "accepted", "{body}");
            return body["session"].clone();
        }
        assert!(Instant::now() < deadline, "the start kept racing: {body}");
        tokio::time::sleep(POLL).await;
    }
}

/// The session's record — `Null` when the answer is not one (the reads
/// before the server's side is searched must not fail the test first).
pub async fn session(app: &TestApp, s: &SeededTenant, sid: &str) -> Value {
    app.auth_get(
        &format!("/api/tenant/{}/hive/session/{sid}", s.tenant_id),
        &s.admin.access_token,
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap_or(Value::Null)
}

/// Poll until the session's status is `want`; `false` when it never was.
pub async fn reached(app: &TestApp, s: &SeededTenant, sid: &str, want: &str) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if session(app, s, sid).await["status"] == want {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    false
}

/// The session room's messages, as its owner reads them.
pub async fn room_messages(app: &TestApp, s: &SeededTenant, room: &str) -> Vec<Value> {
    let v: Value = app
        .auth_get(
            &format!(
                "/api/tenant/{}/room/{room}/message?per_page=100",
                s.tenant_id
            ),
            &s.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_or(Value::Null);
    v["items"].as_array().cloned().unwrap_or_default()
}

/// A probe file through the files API, into the org's first room — what the
/// object-store walk must be able to find.
pub async fn upload_probe(app: &TestApp, s: &SeededTenant, content: &str) {
    let room = &s.rooms[0].id;
    app.auth_post(
        &format!("/api/tenant/{}/room/{room}/join", s.tenant_id),
        &s.admin.access_token,
    )
    .send()
    .await
    .unwrap();
    let part = reqwest::multipart::Part::bytes(content.as_bytes().to_vec())
        .file_name("probe.txt")
        .mime_str("text/plain")
        .unwrap();
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("room_id", room.clone());
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/file/upload", s.tenant_id),
            &s.admin.access_token,
        )
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the probe upload");
}

/// FR-90 P1a-2 — the harness's side of a session's toolbelt: what Claude
/// Code sends through its relay, played by the test.
pub struct Harness {
    pub rd: tokio::io::Lines<tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>>,
    pub wr: tokio::net::unix::OwnedWriteHalf,
}

impl Harness {
    pub async fn connect(socket: &Path) -> Self {
        use tokio::io::AsyncBufReadExt;
        let s = tokio::net::UnixStream::connect(socket)
            .await
            .unwrap_or_else(|e| panic!("the session's toolbelt at {}: {e}", socket.display()));
        let (rd, wr) = s.into_split();
        Self {
            rd: tokio::io::BufReader::new(rd).lines(),
            wr,
        }
    }

    pub async fn send(&mut self, v: Value) {
        use tokio::io::AsyncWriteExt;
        let mut line = v.to_string();
        line.push('\n');
        self.wr.write_all(line.as_bytes()).await.unwrap();
    }

    /// The answer to request `id`, skipping progress.
    pub async fn answer(&mut self, id: u64) -> Value {
        loop {
            let line = tokio::time::timeout(WAIT, self.rd.next_line())
                .await
                .expect("the toolbelt answered in time")
                .unwrap()
                .expect("the toolbelt is open");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }
}

/// Whether a message in `room` matches `pred` within the test's patience.
pub async fn until_room_message(
    app: &TestApp,
    s: &SeededTenant,
    room: &str,
    pred: impl Fn(&Value) -> bool,
) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if room_messages(app, s, room).await.iter().any(&pred) {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    false
}

pub fn text_of(e: &Value) -> String {
    e["event"].to_string()
}

// ─── Core memory (P1e) ──────────────────────────────────────────────────────

/// A stand-in for Claude Code that records its core memory: what it finds
/// where Claude Code reads it — `$CLAUDE_CONFIG_DIR/CLAUDE.md`, and the
/// auto-memory `MEMORY.md` under the pinned project name — copied to
/// `.claude_md` / `.memory_md` in the session's folder when it starts (then
/// `.launched`), and to `.claude_md.turn` / `.memory_md.turn` at each turn
/// (then `.turned`). ⚠️ Read a copy only once its marker is there: `cp`
/// writes the first file before the second exists, and a file while it is
/// being written (CI lost that race once, reading `.memory_md` too early).
/// What a model would have been given, not what the server meant to send.
pub const MEMORY_HARNESS: &str = r#"#!/bin/sh
mem() {
  if [ -f "$CLAUDE_CONFIG_DIR/CLAUDE.md" ]; then cp "$CLAUDE_CONFIG_DIR/CLAUDE.md" "$PWD/.claude_md$1"; fi
  m="$CLAUDE_CONFIG_DIR/projects/$CLAUDE_CODE_PROJECT_DIR_NAME/memory/MEMORY.md"
  if [ -f "$m" ]; then cp "$m" "$PWD/.memory_md$1"; fi
}
mem ""
touch "$PWD/.launched"
while IFS= read -r line; do
  mem ".turn"
  touch "$PWD/.turned"
  echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
"#;

/// Poll until `folder/name` exists: its content, or `None` when it never
/// came.
pub async fn until_file(folder: &Path, name: &str) -> Option<String> {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(s) = std::fs::read_to_string(folder.join(name)) {
            return Some(s);
        }
        if Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// `POST …/hive/brain` as `token`: the status and the answer.
pub async fn keep_fact(app: &TestApp, tid: &str, token: &str, body: Value) -> (u16, Value) {
    let resp = app
        .auth_post(&format!("/api/tenant/{tid}/hive/brain"), token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// A device in-process whose sessions run [`MEMORY_HARNESS`] in `roots/a` or
/// `roots/b` as the seeded admin, with its owner's `hive_core_memory` as
/// given. Online when returned.
pub struct MemoryDevice {
    pub dir: tempfile::TempDir,
    pub work_a: PathBuf,
    pub work_b: PathBuf,
    pub home: PathBuf,
    pub id: String,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

pub async fn memory_device(
    app: &TestApp,
    seeded: &SeededTenant,
    core_memory: bool,
) -> MemoryDevice {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("roots");
    let (work_a, work_b) = (roots.join("a"), roots.join("b"));
    let home = dir.path().join("home");
    for d in [&work_a, &work_b, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    let harness = dir.path().join("claude");
    std::fs::write(&harness, MEMORY_HARNESS).unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cfg = enrol(app, seeded, "hive-memory").await;
    cfg.hive_enabled = true;
    cfg.hive_accounts
        .insert(seeded.admin.id.clone(), "memory".into());
    cfg.hive_roots = vec![roots.display().to_string()];
    cfg.hive_harness = Some(harness.display().to_string());
    cfg.hive_core_memory = core_memory;
    meshharbord::hive::init_as_daemon(
        &cfg,
        &dir.path().join("hive.db"),
        &dir.path().join("run"),
        &home,
    )
    .expect("the test launcher");
    let id = cfg.agent_id.clone();
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_device(cfg, stop_rx);
    wait_online(app, seeded, &id).await;
    MemoryDevice {
        dir,
        work_a,
        work_b,
        home,
        id,
        stop,
        task,
    }
}

impl MemoryDevice {
    /// The session's own config directory: where Claude Code reads
    /// `CLAUDE.md`, and under `projects/` the auto-memory index.
    pub fn config_dir(&self, sid: &str) -> PathBuf {
        self.home.join(".roomler/hive").join(sid).join("claude")
    }

    /// The daemon's own copy of a session's core memory, which the account
    /// copies in.
    pub fn runtime_memory(&self, sid: &str) -> PathBuf {
        self.dir.path().join("run").join(sid).join("memory")
    }

    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
        drop(self.dir);
    }
}

/// Every file named `name` under `dir`, at any depth.
pub fn files_named(dir: &Path, name: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            found.extend(files_named(&p, name));
        } else if p.file_name().is_some_and(|n| n == name) {
            found.push(p);
        }
    }
    found
}

/// The session's first transcript note that starts with `prefix`, reading
/// its transcript from the start. The viewer must be fresh: nothing else is
/// awaited on it first.
pub async fn transcript_note(viewer: &mut Browser, prefix: &str) -> Option<String> {
    viewer.send(json!({"op": "hello"})).await;
    viewer.recv_op("hello").await;
    viewer.send(json!({"op": "follow", "after": 0})).await;
    let is_it = |e: &Value| {
        e["event"]["kind"] == "note"
            && e["event"]["text"]
                .as_str()
                .is_some_and(|t| t.starts_with(prefix))
    };
    viewer
        .events_until(is_it)
        .await
        .iter()
        .find(|e| is_it(e))
        .and_then(|e| e["event"]["text"].as_str().map(str::to_string))
}
