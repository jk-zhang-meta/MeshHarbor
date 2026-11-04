// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The toolbelt over a real socket (on Windows a named pipe, P1i-2), with the
//! test playing Claude Code: the messages it sends are the ones FR-90 P1a's
//! contract probe recorded from Claude Code 2.1.293 (spec §8).

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use super::*;

const WAIT: Duration = Duration::from_secs(10);

#[cfg(unix)]
fn me() -> PeerId {
    // SAFETY: getuid reads our own credentials.
    unsafe { libc::getuid() }
}

#[cfg(windows)]
fn me() -> PeerId {
    crate::hive_win::own_sid().unwrap()
}

struct Belt {
    _dir: tempfile::TempDir,
    toolbelt: Toolbelt,
    events: mpsc::Receiver<ApprovalEvent>,
}

fn belt(timing: Timing) -> Belt {
    belt_for(me(), timing)
}

fn belt_for(peer: PeerId, timing: Timing) -> Belt {
    belt_running(peer, run(), timing)
}

/// P3-4b — a toolbelt serving `run`.
fn belt_running(peer: PeerId, run: Run, timing: Timing) -> Belt {
    let dir = tempfile::tempdir().unwrap();
    let (tx, events) = mpsc::channel(64);
    #[cfg(unix)]
    let toolbelt = open(dir.path(), None, peer, run, tx, timing).unwrap();
    #[cfg(windows)]
    let toolbelt = open(peer, run, tx, timing).unwrap();
    Belt {
        _dir: dir,
        toolbelt,
        events,
    }
}

/// A run on a device that takes no leases: no vault tools.
fn run() -> Run {
    Run {
        session: ObjectId::new(),
        fence: 1,
        vault: None,
        #[cfg(feature = "vault")]
        exec: None,
        #[cfg(feature = "vault")]
        net: None,
        #[cfg(all(feature = "vault", feature = "ssh-server"))]
        ssh: None,
    }
}

fn quick() -> Timing {
    Timing {
        timeout: Duration::from_secs(30),
        progress_every: Duration::from_secs(30),
    }
}

/// Claude Code's side of one connection — the harness, through its relay.
pub(crate) struct Client {
    rd: tokio::io::Lines<BufReader<Box<dyn AsyncRead + Unpin + Send>>>,
    wr: Box<dyn AsyncWrite + Unpin + Send>,
}

impl Client {
    async fn connect(b: &Belt) -> Self {
        Self::at(b.toolbelt.socket()).await
    }

    /// Connect to the toolbelt at `path` (a socket; on Windows a pipe name),
    /// as the relay does.
    pub(crate) async fn at(path: &Path) -> Self {
        let (rd, wr) = connect(path).await.unwrap();
        let rd: Box<dyn AsyncRead + Unpin + Send> = Box::new(rd);
        Self {
            rd: BufReader::new(rd).lines(),
            wr: Box::new(wr),
        }
    }

    pub(crate) async fn send(&mut self, v: Value) {
        let mut line = v.to_string();
        line.push('\n');
        self.wr.write_all(line.as_bytes()).await.unwrap();
    }

    pub(crate) async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(WAIT, self.rd.next_line())
            .await
            .expect("an answer in time")
            .unwrap()
            .expect("the connection is open");
        serde_json::from_str(&line).unwrap()
    }

    /// The `approve` verdict for request `id`, skipping progress.
    pub(crate) async fn verdict(&mut self, id: u64) -> Value {
        loop {
            let m = self.recv().await;
            if m.get("method") == Some(&json!("notifications/progress")) {
                continue;
            }
            assert_eq!(m["id"], id, "{m}");
            let text = m["result"]["content"][0]["text"].as_str().unwrap();
            return serde_json::from_str(text).unwrap();
        }
    }
}

/// Claude Code's `tools/call` for one permission prompt, as recorded.
pub(crate) fn call(id: u64, tool: &str, input: Value) -> Value {
    json!({
        "method": "tools/call",
        "params": {
            "name": "approve",
            "arguments": {"tool_name": tool, "input": input, "tool_use_id": "toolu_01FAKE"},
            "_meta": {"claudecode/toolUseId": "toolu_01FAKE", "progressToken": id},
        },
        "jsonrpc": "2.0",
        "id": id,
    })
}

async fn next_event(b: &mut Belt) -> ApprovalEvent {
    tokio::time::timeout(WAIT, b.events.recv())
        .await
        .expect("an approval event in time")
        .expect("the channel is open")
}

async fn opened(b: &mut Belt) -> (String, String, Value) {
    match next_event(b).await {
        ApprovalEvent::Opened {
            id,
            tool_name,
            input,
            ..
        } => (id, tool_name, input),
        other => panic!("expected an opened approval, got {other:?}"),
    }
}

async fn closed(b: &mut Belt) -> (String, Ended) {
    match next_event(b).await {
        ApprovalEvent::Closed { id, ended } => (id, ended),
        other => panic!("expected a closed approval, got {other:?}"),
    }
}

fn dev() -> Author {
    Author {
        user_id: ObjectId::new(),
        name: "Dev".into(),
    }
}

/// Claude Code's start-up, as recorded: a `server/discover` probe that must
/// be told no (it then initializes), `initialize`, `notifications/initialized`,
/// `tools/list`.
#[tokio::test]
async fn the_server_answers_the_handshake_claude_code_sends() {
    let b = belt(quick());
    let mut c = Client::connect(&b).await;
    c.send(json!({"jsonrpc": "2.0", "id": "server-discover-probe-1", "method": "server/discover", "params": {}}))
        .await;
    let probe = c.recv().await;
    assert_eq!(probe["id"], "server-discover-probe-1");
    assert_eq!(probe["error"]["code"], -32601, "{probe}");

    c.send(json!({"method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "claude-code", "version": "2.1.293"}}, "jsonrpc": "2.0", "id": 0}))
        .await;
    let init = c.recv().await;
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(init["result"]["serverInfo"]["name"], "meshharbor");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    c.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
        .await;
    let list = c.recv().await;
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1, "{list}");
    assert_eq!(tools[0]["name"], "approve");
    assert_eq!(
        tools[0]["inputSchema"]["required"],
        json!(["tool_name", "input"])
    );

    // A version from the future is answered in the newest this server
    // speaks; ping, an unknown tool and garbage each get their own error.
    c.send(json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2099-01-01"}}))
        .await;
    assert_eq!(c.recv().await["result"]["protocolVersion"], "2025-11-25");
    c.send(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}))
        .await;
    assert_eq!(c.recv().await["result"], json!({}));
    c.send(json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "exec", "arguments": {}}}))
        .await;
    assert_eq!(c.recv().await["error"]["code"], -32602);
    c.wr.write_all(b"{not json\n").await.unwrap();
    assert_eq!(c.recv().await["error"]["code"], -32700);
}

/// Allowed: the call returns the input it asked about, unchanged. Denied:
/// the model reads who said no, and what they said.
#[tokio::test]
async fn an_allowed_call_runs_as_asked_and_a_denied_one_is_told_why() {
    let mut b = belt(quick());
    let mut c = Client::connect(&b).await;
    let input = json!({"file_path": "/tmp/x.txt", "content": "hello\n"});
    c.send(call(2, "Write", input.clone())).await;
    let (id, tool, asked) = opened(&mut b).await;
    assert_eq!((tool.as_str(), &asked), ("Write", &input));
    assert_eq!(b.toolbelt.pending().ids(), std::slice::from_ref(&id));
    assert!(b.toolbelt.pending().answer(
        &id,
        Answer {
            decision: Decision::Allow,
            by: dev(),
        }
    ));
    assert_eq!(
        c.verdict(2).await,
        json!({"behavior": "allow", "updatedInput": input})
    );
    let (closed_id, ended) = closed(&mut b).await;
    assert_eq!(closed_id, id);
    assert!(matches!(
        ended,
        Ended::Answered(Answer {
            decision: Decision::Allow,
            ..
        })
    ));
    assert!(b.toolbelt.pending().ids().is_empty());
    assert!(
        !b.toolbelt.pending().answer(
            &id,
            Answer {
                decision: Decision::Allow,
                by: dev()
            }
        ),
        "an answered approval takes no second answer"
    );

    c.send(call(3, "Bash", json!({"command": "rm -rf build"})))
        .await;
    let (id, _, _) = opened(&mut b).await;
    b.toolbelt.pending().answer(
        &id,
        Answer {
            decision: Decision::Deny {
                message: Some("not now".into()),
            },
            by: dev(),
        },
    );
    assert_eq!(
        c.verdict(3).await,
        json!({"behavior": "deny", "message": "Dev denied this: not now"})
    );
    assert!(matches!(closed(&mut b).await.1, Ended::Answered(_)));
}

/// Nobody answering is a denial that says so, and the waiting call says it is
/// still waiting meanwhile.
#[tokio::test]
async fn nobody_answering_is_a_denial_that_says_so() {
    let mut b = belt(Timing {
        timeout: Duration::from_millis(400),
        progress_every: Duration::from_millis(100),
    });
    let mut c = Client::connect(&b).await;
    c.send(call(7, "Bash", json!({"command": "make"}))).await;
    let (id, _, _) = opened(&mut b).await;
    let first = c.recv().await;
    assert_eq!(first["method"], "notifications/progress", "{first}");
    assert_eq!(first["params"]["progressToken"], 7);
    let v = c.verdict(7).await;
    assert_eq!(v["behavior"], "deny");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .starts_with("Nobody answered"),
        "{v}"
    );
    let (closed_id, ended) = closed(&mut b).await;
    assert_eq!(closed_id, id);
    assert!(matches!(ended, Ended::Expired));
}

/// The harness letting go withdraws what it asked: a cancellation gets no
/// answer (MCP), and a closed relay takes every open call with it.
#[tokio::test]
async fn a_cancelled_or_abandoned_call_is_withdrawn() {
    let mut b = belt(quick());
    let mut c = Client::connect(&b).await;
    c.send(call(5, "Bash", json!({"command": "sleep 1"}))).await;
    opened(&mut b).await;
    c.send(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 5, "reason": "interrupted"}}))
        .await;
    assert!(matches!(closed(&mut b).await.1, Ended::Withdrawn));
    c.send(json!({"jsonrpc": "2.0", "id": 6, "method": "ping"}))
        .await;
    assert_eq!(
        c.recv().await["id"],
        6,
        "the cancelled call was not answered; the next request was"
    );

    c.send(call(8, "Bash", json!({"command": "sleep 2"}))).await;
    opened(&mut b).await;
    drop(c);
    assert!(matches!(closed(&mut b).await.1, Ended::Withdrawn));
    assert!(b.toolbelt.pending().ids().is_empty());
}

/// Ending the toolbelt — the session ending — withdraws what is open and
/// takes the socket away.
#[tokio::test]
async fn the_toolbelt_ends_with_its_session() {
    let mut b = belt(quick());
    let mut c = Client::connect(&b).await;
    c.send(call(2, "Bash", json!({"command": "ls"}))).await;
    opened(&mut b).await;
    let socket = b.toolbelt.socket().to_path_buf();
    let Belt {
        _dir,
        toolbelt,
        mut events,
    } = b;
    drop(toolbelt);
    let ended = tokio::time::timeout(WAIT, events.recv()).await.unwrap();
    assert!(matches!(
        ended,
        Some(ApprovalEvent::Closed {
            ended: Ended::Withdrawn,
            ..
        })
    ));
    #[cfg(unix)]
    assert!(!socket.exists(), "the socket went with the session");
    // A pipe is gone once its last instance is: the listening one, and the
    // connected one whose task the stop ended.
    #[cfg(windows)]
    {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            match connect(&socket).await {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                other => {
                    drop(other);
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "the pipe went with the session"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

/// P1i-2 — a toolbelt is its session account's alone on Windows too. One made
/// for another account (SYSTEM's, here) drops this one's connection unanswered:
/// its DACL admits this test process as an administrator (CI's runner is
/// elevated), and the daemon checks every client's account again. And its name
/// cannot be taken twice.
#[cfg(windows)]
#[tokio::test]
async fn the_pipe_is_the_sessions_alone() {
    let other = belt_for("S-1-5-18".into(), quick());
    let mut c = Client::connect(&other).await;
    // A write may already find the pipe closing: that is the refusal too.
    let _ =
        c.wr.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
            .await;
    let got = tokio::time::timeout(WAIT, c.rd.next_line()).await.unwrap();
    assert!(
        matches!(got, Ok(None) | Err(_)),
        "another account's connection is dropped: {got:?}"
    );

    let b = belt(quick());
    let name = b.toolbelt.socket().to_string_lossy().into_owned();
    let sddl = crate::hive_win::toolbelt_pipe_sddl(&me());
    assert!(
        pipe_instance(&name, &sddl, true).is_err(),
        "a name in use is never joined as the first"
    );
}

/// The socket is the session account's alone: `0600`; a connection from any
/// other uid is dropped unanswered; and what sits where the socket goes is
/// removed only if it is a socket.
#[cfg(unix)]
#[tokio::test]
async fn the_socket_is_the_sessions_alone() {
    let b = belt(quick());
    let mode = std::fs::metadata(b.toolbelt.socket())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let other = belt_for(me().wrapping_add(1), quick());
    let mut c = Client::connect(&other).await;
    c.send(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await;
    let got = tokio::time::timeout(WAIT, c.rd.next_line()).await.unwrap();
    assert!(
        matches!(got, Ok(None) | Err(_)),
        "another account's connection is dropped: {got:?}"
    );

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("toolbelt.sock"), b"not a socket").unwrap();
    let (tx, _rx) = mpsc::channel(4);
    let refused = open(dir.path(), None, me(), run(), tx.clone(), quick());
    assert!(refused.is_err(), "a file in the socket's place is refused");
    std::fs::remove_file(dir.path().join("toolbelt.sock")).unwrap();
    let first = open(dir.path(), None, me(), run(), tx.clone(), quick()).unwrap();
    std::mem::forget(first); // leaves a stale socket, as a crash would
    let again = open(dir.path(), None, me(), run(), tx, quick());
    assert!(again.is_ok(), "a stale socket is replaced");
}

/// P3-4b — a vault that answers as told and records what it was asked; with
/// `hold`, each answer waits until the test releases it. P3-4c-1: it leases
/// in `exec` mode the `values` it holds by `secret` or `secret#field`, and
/// remembers each lease it holds and each it was told to let go of.
#[derive(Default)]
struct FakeVault {
    asked: std::sync::Mutex<Vec<(String, ObjectId, u64, String)>>,
    hold: Option<tokio::sync::Notify>,
    #[cfg(feature = "vault")]
    values: HashMap<String, Vec<u8>>,
    #[cfg(feature = "vault")]
    held: std::sync::Mutex<HashMap<String, Vec<u8>>>,
    #[cfg(feature = "vault")]
    released: std::sync::Mutex<Vec<String>>,
    #[cfg(feature = "vault")]
    issued: std::sync::atomic::AtomicUsize,
    /// P3-4c-2 — each file a tool attached to a lease.
    #[cfg(feature = "vault")]
    attached: std::sync::Mutex<Vec<(String, std::path::PathBuf)>>,
    /// P3-4c-3 — each lease's time left (the TTL it was asked for, unless a
    /// test shortens it), and the leases asked for ahead: (id, handle, mode,
    /// audience).
    #[cfg(feature = "vault")]
    lefts: std::sync::Mutex<HashMap<String, Duration>>,
    #[cfg(feature = "vault")]
    ahead: std::sync::Mutex<Vec<(String, String, String, String)>>,
    /// P3-4d-2 — each use reported.
    #[cfg(feature = "vault")]
    reports: std::sync::Mutex<Vec<crate::vault::Report>>,
    /// P3-5b-2 — what each lease stops when it is let go.
    #[cfg(feature = "vault")]
    stops: std::sync::Mutex<Vec<(String, CancellationToken)>>,
    /// P3-6b-2b — the dynamic secrets, each with its credential's fields;
    /// the leases asked for in `short-lived`; each mint asked for, by lease;
    /// and each lease's credential once minted, made once per lease.
    #[cfg(feature = "vault")]
    dynamic: HashMap<String, Vec<String>>,
    #[cfg(feature = "vault")]
    short: std::sync::Mutex<Vec<String>>,
    #[cfg(feature = "vault")]
    mints: std::sync::Mutex<Vec<String>>,
    #[cfg(feature = "vault")]
    credentials: std::sync::Mutex<HashMap<String, String>>,
    /// FR-90 P3-7-3c — each egress asked for, and the vault's word when it
    /// refuses them; granted as asked otherwise, a forward's host in the
    /// vault's one spelling.
    #[cfg(feature = "vault")]
    nets: std::sync::Mutex<Vec<crate::vault::NetAsk>>,
    #[cfg(feature = "vault")]
    net_refusal: Option<String>,
    /// FR-90 P3-8-2b-2 — each SSH ticket asked for, and the vault's word
    /// when it refuses them; granted otherwise, for a `named` account on a
    /// Linux target.
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    sshs: std::sync::Mutex<Vec<crate::vault::SshAsk>>,
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    ssh_refusal: Option<String>,
}

impl FakeVault {
    fn asked(&self) -> Vec<(String, ObjectId, u64, String)> {
        self.asked.lock().unwrap().clone()
    }

    /// P3-6b-2b — the leases asked for, without the descriptions a use reads
    /// first.
    #[cfg(feature = "vault")]
    fn leases_asked(&self) -> Vec<(String, ObjectId, u64, String)> {
        self.asked()
            .into_iter()
            .filter(|a| a.0 != "describe")
            .collect()
    }
}

#[async_trait::async_trait]
impl VaultTools for FakeVault {
    #[cfg(feature = "vault")]
    async fn lease(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        ttl_secs: u32,
    ) -> Result<String, String> {
        let key = handle.to_string();
        self.asked.lock().unwrap().push((
            format!("lease_{mode}"),
            session,
            fence,
            format!("{key} for {audience} {ttl_secs}s"),
        ));
        let value = self
            .values
            .get(&key)
            .ok_or_else(|| "the vault refused: no_secret".to_string())?;
        let n = self
            .issued
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = format!("L{n}");
        if mode == crate::vault::SHORT_LIVED {
            self.short.lock().unwrap().push(id.clone());
        }
        self.held.lock().unwrap().insert(id.clone(), value.clone());
        self.lefts
            .lock()
            .unwrap()
            .insert(id.clone(), Duration::from_secs(u64::from(ttl_secs)));
        Ok(id)
    }

    #[cfg(feature = "vault")]
    async fn lease_ahead(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        ttl_secs: u32,
    ) -> Result<String, String> {
        let leased = self
            .lease(session, fence, handle, mode, audience, ttl_secs)
            .await;
        if let Some(last) = self.asked.lock().unwrap().last_mut() {
            last.0 = format!("ahead_{mode}");
        }
        let id = leased?;
        self.ahead.lock().unwrap().push((
            id.clone(),
            handle.to_string(),
            mode.into(),
            audience.into(),
        ));
        Ok(id)
    }

    #[cfg(feature = "vault")]
    fn ahead(
        &self,
        _session: ObjectId,
        _fence: u64,
        handle: &super::super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        at_least: Duration,
    ) -> Option<String> {
        let key = handle.to_string();
        self.ahead
            .lock()
            .unwrap()
            .iter()
            .find(|(id, h, m, a)| {
                *h == key
                    && m == mode
                    && a == audience
                    && self.left(id).is_some_and(|l| l >= at_least)
            })
            .map(|(id, ..)| id.clone())
    }

    #[cfg(feature = "vault")]
    fn left(&self, lease_id: &str) -> Option<Duration> {
        if !self.held.lock().unwrap().contains_key(lease_id) {
            return None;
        }
        self.lefts.lock().unwrap().get(lease_id).copied()
    }

    #[cfg(feature = "vault")]
    fn report(&self, r: crate::vault::Report) {
        self.reports.lock().unwrap().push(r);
    }

    #[cfg(feature = "vault")]
    async fn net(&self, ask: crate::vault::NetAsk) -> Result<crate::vault::NetGrant, String> {
        let mut nets = self.nets.lock().unwrap();
        nets.push(ask.clone());
        if let Some(why) = &self.net_refusal {
            return Err(why.clone());
        }
        Ok(crate::vault::NetGrant {
            grant_id: format!("g{}", nets.len()),
            token: format!("grant-of-{}", ask.session_id),
            dst: ask.dst.map(|(host, port)| {
                (
                    meshharbor_remote_control::vault::canonical_net_host(&host).unwrap_or(host),
                    port,
                )
            }),
            until: std::time::Instant::now() + Duration::from_secs(u64::from(ask.ttl_secs)),
        })
    }

    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    async fn ssh(&self, ask: crate::vault::SshAsk) -> Result<crate::vault::SshTicket, String> {
        let mut sshs = self.sshs.lock().unwrap();
        sshs.push(ask.clone());
        if let Some(why) = &self.ssh_refusal {
            return Err(why.clone());
        }
        Ok(crate::vault::SshTicket {
            ticket_id: format!("t{}", sshs.len()),
            ticket: format!("ticket-of-{}", ask.session_id),
            os: "linux".into(),
            account: "named".into(),
            until: std::time::Instant::now() + Duration::from_secs(u64::from(ask.ttl_secs)),
        })
    }

    #[cfg(feature = "vault")]
    fn attach(&self, lease_id: &str, path: &Path) -> bool {
        if !self.held.lock().unwrap().contains_key(lease_id) {
            return false;
        }
        self.attached
            .lock()
            .unwrap()
            .push((lease_id.to_string(), path.to_path_buf()));
        true
    }

    #[cfg(feature = "vault")]
    fn stop_with(&self, lease_id: &str, stop: CancellationToken) -> bool {
        if !self.held.lock().unwrap().contains_key(lease_id) {
            return false;
        }
        self.stops
            .lock()
            .unwrap()
            .push((lease_id.to_string(), stop));
        true
    }

    #[cfg(feature = "vault")]
    fn value(&self, lease_id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        // As the daemon's client: a `short-lived` lease lends no bundle.
        if self.short.lock().unwrap().iter().any(|l| l == lease_id) {
            return None;
        }
        self.held
            .lock()
            .unwrap()
            .get(lease_id)
            .map(|v| zeroize::Zeroizing::new(v.clone()))
    }

    #[cfg(feature = "vault")]
    async fn mint(&self, lease_id: &str) -> Result<(), String> {
        self.mints.lock().unwrap().push(lease_id.to_string());
        if !self.held.lock().unwrap().contains_key(lease_id) {
            return Err("the lease ended before its credential was minted".into());
        }
        self.credentials
            .lock()
            .unwrap()
            .entry(lease_id.to_string())
            .or_insert_with(|| format!("cred-{lease_id}"));
        Ok(())
    }

    /// A field's value is its credential's tag and the field's place in the
    /// provider's list: `cred-L0:0` for `user`, `cred-L0:1` for the next.
    #[cfg(feature = "vault")]
    fn minted(&self, lease_id: &str, field: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        if !self.held.lock().unwrap().contains_key(lease_id) {
            return None;
        }
        let at = meshharbor_remote_control::vault::providers::POSTGRES
            .minted
            .iter()
            .position(|f| *f == field)?;
        let tag = self.credentials.lock().unwrap().get(lease_id)?.clone();
        Some(zeroize::Zeroizing::new(format!("{tag}:{at}").into_bytes()))
    }

    #[cfg(feature = "vault")]
    fn release(&self, lease_ids: &[String]) {
        let mut held = self.held.lock().unwrap();
        for id in lease_ids {
            held.remove(id);
            self.released.lock().unwrap().push(id.clone());
            // What it served stops, as the daemon's client stops it.
            for (lease, stop) in self.stops.lock().unwrap().iter() {
                if lease == id {
                    stop.cancel();
                }
            }
        }
    }

    async fn list(&self, session: ObjectId, fence: u64, prefix: &str) -> Result<Value, String> {
        self.asked
            .lock()
            .unwrap()
            .push(("list".into(), session, fence, prefix.into()));
        if let Some(hold) = &self.hold {
            hold.notified().await;
        }
        if prefix == "refused/" {
            return Err("the vault refused: no_role".into());
        }
        Ok(json!({
            "secrets": [{"rrn": "rrn:grox:secret:db/main", "path": "db/main", "kind": "static"}],
            "more": false,
        }))
    }

    async fn describe(&self, session: ObjectId, fence: u64, secret: &str) -> Result<Value, String> {
        self.asked
            .lock()
            .unwrap()
            .push(("describe".into(), session, fence, secret.into()));
        #[cfg(feature = "vault")]
        if let Some(fields) = self.dynamic.get(secret) {
            return Ok(json!({
                "rrn": format!("rrn:grox:secret:{secret}"),
                "path": secret,
                "kind": "dynamic",
                "provider": "postgres",
                "fields": fields,
            }));
        }
        Ok(json!({"rrn": format!("rrn:grox:secret:{secret}"), "path": secret, "kind": "static"}))
    }
}

/// A `tools/call` of one of the toolbelt's own tools, as Claude Code sends it.
fn tool_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {"claudecode/toolUseId": "toolu_01FAKE"}},
        "jsonrpc": "2.0",
        "id": id,
    })
}

/// P3-4b — the vault tools are offered where the device takes leases, and
/// nowhere else: elsewhere they are unknown tools. Their settings names are
/// the names offered, under the `meshharbor` server.
#[tokio::test]
async fn the_vault_tools_are_offered_only_where_the_device_takes_leases() {
    let without = belt(quick());
    let mut c = Client::connect(&without).await;
    c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
        .await;
    let names: Vec<Value> = c.recv().await["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(names, [json!("approve")]);
    c.send(tool_call(2, "vault_list", json!({}))).await;
    assert_eq!(c.recv().await["error"]["code"], -32602, "not offered here");

    let vault = Arc::new(FakeVault::default());
    let with = belt_running(
        me(),
        Run {
            session: ObjectId::new(),
            fence: 1,
            vault: Some(vault.clone()),
            #[cfg(feature = "vault")]
            exec: None,
            #[cfg(feature = "vault")]
            net: None,
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            ssh: None,
        },
        quick(),
    );
    let mut c = Client::connect(&with).await;
    c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
        .await;
    let list = c.recv().await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names[..3], ["approve", "vault_list", "vault_describe"]);
    // P3-4c — and, in a build with the vault, its uses, (P3-5b-2) an
    // endpoint, and (P3-4c-3) a lease asked for ahead.
    #[cfg(feature = "vault")]
    assert_eq!(
        names[3..],
        [
            "vault_exec",
            "vault_render",
            "vault_connect",
            "vault_request"
        ]
    );
    #[cfg(not(feature = "vault"))]
    assert_eq!(names.len(), 3);
    for t in &tools[1..3] {
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{t}");
    }
    assert_eq!(
        tools[2]["inputSchema"]["required"],
        json!(["secret"]),
        "{list}"
    );
    let named: Vec<String> = VAULT_TOOL_NAMES
        .iter()
        .map(|n| format!("mcp__meshharbor__{n}"))
        .collect();
    assert_eq!(
        named, VAULT_TOOLS,
        "what the settings allow is what is offered"
    );
    assert!(
        vault.asked().is_empty(),
        "listing the tools asks the vault nothing"
    );
}

/// P3-4b — a vault tool answers what the vault says for the session's run
/// (its session and its fence), as text, or why not, as an error; nothing
/// asks a person, and a call without its argument asks the vault nothing.
#[tokio::test]
async fn a_vault_tool_answers_what_the_vault_says_for_the_sessions_run() {
    let vault = Arc::new(FakeVault::default());
    let sid = ObjectId::new();
    let mut b = belt_running(
        me(),
        Run {
            session: sid,
            fence: 7,
            vault: Some(vault.clone()),
            #[cfg(feature = "vault")]
            exec: None,
            #[cfg(feature = "vault")]
            net: None,
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            ssh: None,
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    c.send(tool_call(1, "vault_list", json!({"prefix": "db/"})))
        .await;
    let listed = c.recv().await;
    assert_eq!(listed["id"], 1);
    assert!(listed["result"].get("isError").is_none(), "{listed}");
    let text: Value =
        serde_json::from_str(listed["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["secrets"][0]["path"], "db/main");
    assert_eq!(text["more"], false);

    c.send(tool_call(2, "vault_describe", json!({"secret": "db/main"})))
        .await;
    let described = c.recv().await;
    let text: Value =
        serde_json::from_str(described["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["rrn"], "rrn:grox:secret:db/main");

    c.send(tool_call(3, "vault_describe", json!({}))).await;
    let missing = c.recv().await;
    assert_eq!(missing["result"]["isError"], true, "{missing}");
    assert!(
        missing["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("secret is required")
    );

    c.send(tool_call(4, "vault_list", json!({"prefix": "refused/"})))
        .await;
    let refused = c.recv().await;
    assert_eq!(refused["result"]["isError"], true, "{refused}");
    assert_eq!(
        refused["result"]["content"][0]["text"],
        "the vault refused: no_role"
    );

    assert_eq!(
        vault.asked(),
        [
            ("list".to_string(), sid, 7, "db/".to_string()),
            ("describe".to_string(), sid, 7, "db/main".to_string()),
            ("list".to_string(), sid, 7, "refused/".to_string()),
        ]
    );
    assert!(
        b.events.try_recv().is_err(),
        "a vault tool opens no approval"
    );
}

/// P3-4b — a vault call the harness cancels gets no answer, as MCP asks,
/// and the next one is answered as usual.
#[tokio::test]
async fn a_cancelled_vault_call_gets_no_answer() {
    let vault = Arc::new(FakeVault {
        hold: Some(tokio::sync::Notify::new()),
        ..FakeVault::default()
    });
    let b = belt_running(
        me(),
        Run {
            session: ObjectId::new(),
            fence: 1,
            vault: Some(vault.clone()),
            #[cfg(feature = "vault")]
            exec: None,
            #[cfg(feature = "vault")]
            net: None,
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            ssh: None,
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    c.send(tool_call(5, "vault_list", json!({}))).await;
    tokio::time::timeout(WAIT, async {
        while vault.asked().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the call reached the vault");
    c.send(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 5, "reason": "interrupted"}}))
        .await;
    c.send(json!({"jsonrpc": "2.0", "id": 6, "method": "ping"}))
        .await;
    assert_eq!(
        c.recv().await["id"],
        6,
        "nothing answers the cancelled call"
    );
    // Released now: had the call outlived its cancellation, it would answer
    // here, and the next call would wait forever for a release.
    vault.hold.as_ref().unwrap().notify_one();
    c.send(tool_call(7, "vault_list", json!({}))).await;
    let next = c.recv().await;
    assert_eq!(next["id"], 7, "{next}");
    assert_eq!(vault.asked().len(), 2);
}

/// P3-4c-1 — a toolbelt whose run's commands run as this daemon, from `dir`,
/// with `values` in its vault.
#[cfg(all(feature = "vault", unix))]
fn exec_belt(dir: &Path, values: &[(&str, &[u8])]) -> (Belt, Arc<FakeVault>, ObjectId) {
    let vault = FakeVault {
        values: values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect(),
        ..FakeVault::default()
    };
    exec_belt_with(dir, vault)
}

/// P3-6b-2b — [`exec_belt`]'s, whose vault holds `db/dyn`, a dynamic
/// Postgres secret (its bundle, never lent as a value), and `api/main`, a
/// stored one.
#[cfg(all(feature = "vault", unix))]
fn dynamic_belt(dir: &Path) -> (Belt, Arc<FakeVault>, ObjectId) {
    let minted = meshharbor_remote_control::vault::providers::POSTGRES.minted;
    let vault = FakeVault {
        values: [
            ("db/dyn".to_string(), b"the-issuer-bundle".to_vec()),
            ("api/main".to_string(), format!("api-{}", 7).into_bytes()),
        ]
        .into_iter()
        .collect(),
        dynamic: [(
            "db/dyn".to_string(),
            minted.iter().map(|f| f.to_string()).collect(),
        )]
        .into_iter()
        .collect(),
        ..FakeVault::default()
    };
    exec_belt_with(dir, vault)
}

#[cfg(all(feature = "vault", unix))]
fn exec_belt_with(dir: &Path, vault: FakeVault) -> (Belt, Arc<FakeVault>, ObjectId) {
    let vault = Arc::new(vault);
    let sid = ObjectId::new();
    // The run's own directory, as the supervisor makes it before a launch.
    std::fs::create_dir_all(dir.join("run")).unwrap();
    let belt = belt_running(
        me(),
        Run {
            session: sid,
            fence: 5,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: Some(super::super::vault_exec::ExecTarget {
                account: None,
                home: dir.to_path_buf(),
                folder: dir.to_path_buf(),
                session_dir: dir.join("run"),
                owner: None,
            }),
        },
        quick(),
    );
    (belt, vault, sid)
}

/// The answer to a `vault_exec` call: its JSON, or its error text.
#[cfg(all(feature = "vault", unix))]
async fn exec_answer(c: &mut Client, id: u64, args: Value) -> Result<Value, String> {
    c.send(tool_call(id, "vault_exec", args)).await;
    let m = c.recv().await;
    assert_eq!(m["id"], id, "{m}");
    let text = m["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    if m["result"]["isError"] == true {
        Err(text)
    } else {
        Ok(serde_json::from_str(&text).unwrap())
    }
}

/// P3-4c-1 — `vault_exec` is offered with the reads, and never allowed in
/// the settings: each call asks a person first.
#[cfg(feature = "vault")]
#[tokio::test]
async fn vault_exec_is_offered_and_never_allowed_unasked() {
    let vault = Arc::new(FakeVault::default());
    let b = belt_running(
        me(),
        Run {
            session: ObjectId::new(),
            fence: 1,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: None,
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
        .await;
    let list = c.recv().await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let exec = tools
        .iter()
        .find(|t| t["name"] == "vault_exec")
        .expect("offered");
    assert_eq!(exec["annotations"]["readOnlyHint"], false, "{exec}");
    assert_eq!(exec["inputSchema"]["required"], json!(["argv", "env"]));
    // P3-4c-2 — and `vault_render`, the same way.
    let render = tools
        .iter()
        .find(|t| t["name"] == "vault_render")
        .expect("offered");
    assert_eq!(render["annotations"]["readOnlyHint"], false, "{render}");
    assert_eq!(
        render["inputSchema"]["required"],
        json!(["template", "dest"])
    );
    // P3-5b-2 — and `vault_connect`: no value handed on, but it acts as the
    // secret's user.
    let connect = tools
        .iter()
        .find(|t| t["name"] == "vault_connect")
        .expect("offered");
    assert_eq!(connect["annotations"]["readOnlyHint"], false, "{connect}");
    assert_eq!(
        connect["inputSchema"]["required"],
        json!(["handle", "engine", "upstream"])
    );
    for tool in [
        "mcp__meshharbor__vault_exec",
        "mcp__meshharbor__vault_render",
        "mcp__meshharbor__vault_connect",
    ] {
        assert!(
            !VAULT_TOOLS.contains(&tool),
            "the settings never allow {tool}: a person approves every call"
        );
    }
    // And the settings ASK for each use offered, so no other settings file
    // can allow one past the person.
    let uses: Vec<String> = VAULT_USE_NAMES
        .iter()
        .map(|n| format!("mcp__meshharbor__{n}"))
        .collect();
    assert_eq!(
        uses, VAULT_USE_TOOLS,
        "what the settings ask for is every use offered"
    );
}

/// P3-4c-1 — a command runs as the session's run would, with the value in
/// its environment, from the run's folder; the value comes back scrubbed,
/// the lease is asked for that program and let go after.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_exec_runs_with_the_value_and_answers_it_scrubbed() {
    let dir = tempfile::tempdir().unwrap();
    let value: &[u8] = b"s3cr3t-pw-81";
    let (b, vault, sid) = exec_belt(dir.path(), &[("db/main#password", value)]);
    let mut c = Client::connect(&b).await;
    // `CARGO_MANIFEST_DIR` is in this test's own environment: the child, run
    // with a clean one, must not see it.
    assert!(
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        "the daemon-side variable the child must not inherit"
    );
    let answer = exec_answer(
        &mut c,
        1,
        json!({
            "argv": ["sh", "-c", "printf '%s|%s|%s' \"$PW\" \"$(pwd)\" \"$CARGO_MANIFEST_DIR\""],
            "env": {"PW": "db/main#password"},
        }),
    )
    .await
    .unwrap();
    let here = dir.path().canonicalize().unwrap();
    assert_eq!(
        answer["stdout"],
        format!("[vault:PW]|{}|", here.display()),
        "{answer}"
    );
    assert_eq!(answer["exit_code"], 0);
    assert_eq!(answer["timed_out"], false);
    assert!(!answer.to_string().contains("s3cr3t"), "{answer}");
    assert_eq!(
        vault.leases_asked(),
        [(
            "lease_exec".to_string(),
            sid,
            5,
            "db/main#password for sh 90s".to_string()
        )]
    );
    assert_eq!(*vault.released.lock().unwrap(), ["L0"]);
    assert!(
        vault.held.lock().unwrap().is_empty(),
        "let go after the run"
    );
    // P3-4d-2 — and the use is reported: the lease, the program, how it
    // ended; never a value.
    assert_eq!(
        *vault.reports.lock().unwrap(),
        [crate::vault::Report {
            session_id: sid,
            fence: 5,
            kind: meshharbor_remote_control::vault::VaultActivityKind::Exec,
            lease_ids: vec!["L0".into()],
            target: "sh".into(),
            exit_code: Some(0),
            timed_out: false,
        }]
    );
}

/// P3-4c-1 — one refused lease runs nothing, and the leases already held are
/// let go; a path, a program nowhere to be found, or a reserved name is
/// refused before anything is asked.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn a_refusal_runs_nothing_and_a_bad_call_asks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _) = exec_belt(dir.path(), &[("db/main", b"first-value-1")]);
    let mut c = Client::connect(&b).await;
    let refused = exec_answer(
        &mut c,
        1,
        json!({"argv": ["sh", "-c", "touch ran"], "env": {"A": "db/main", "B": "db/missing"}}),
    )
    .await
    .unwrap_err();
    assert_eq!(refused, "B: the vault refused: no_secret");
    assert!(!dir.path().join("ran").exists(), "nothing ran");
    assert_eq!(*vault.released.lock().unwrap(), ["L0"]);
    assert!(vault.held.lock().unwrap().is_empty());
    let asked = vault.asked().len();
    for (args, says) in [
        (
            json!({"argv": ["/bin/sh", "-c", "true"], "env": {"A": "db/main"}}),
            "bare name",
        ),
        (
            json!({"argv": ["no-such-program-p34c"], "env": {"A": "db/main"}}),
            "was not found",
        ),
        (
            json!({"argv": ["sh"], "env": {"LD_PRELOAD": "db/main"}}),
            "cannot be handed",
        ),
        (
            json!({"argv": ["sh"], "env": {"PATH": "db/main"}}),
            "cannot be handed",
        ),
        (json!({"argv": ["sh"], "env": {}}), "env must map"),
        (
            json!({"argv": ["sh"], "env": {"A": "db/main"}, "timeout_s": 0}),
            "timeout_s",
        ),
    ] {
        let why = exec_answer(&mut c, 2, args.clone()).await.unwrap_err();
        assert!(why.contains(says), "{args}: {why}");
    }
    assert_eq!(
        vault.asked().len(),
        asked,
        "a bad call asks the vault nothing"
    );
    assert!(
        vault.reports.lock().unwrap().is_empty(),
        "nothing ran, nothing is reported"
    );
}

/// P3-4c-1 — the timeout kills the command and everything it started, and
/// the lease is let go.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn a_command_past_its_timeout_is_killed_with_its_group() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _) = exec_belt(dir.path(), &[("db/main", b"slow-value-22")]);
    let mut c = Client::connect(&b).await;
    let started = std::time::Instant::now();
    // A child that would touch the file two seconds in, had the group been
    // left alive past the one-second timeout.
    let answer = exec_answer(
        &mut c,
        1,
        json!({
            "argv": ["sh", "-c", "(sleep 2; touch survived) & sleep 30"],
            "env": {"A": "db/main"},
            "timeout_s": 1,
        }),
    )
    .await
    .unwrap();
    assert_eq!(answer["timed_out"], true, "{answer}");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(vault.held.lock().unwrap().is_empty());
    // P3-4d-2 — reported as killed: no exit code, timed out.
    let reports = vault.reports.lock().unwrap().clone();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!((reports[0].exit_code, reports[0].timed_out), (None, true));
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        !dir.path().join("survived").exists(),
        "the group died with the command"
    );
}

/// P3-4c-2 — a template is rendered into the run's secrets directory with
/// its values; the file is private, attached to each of its leases, and the
/// leases are kept, since the file lives with them. The answer is a path,
/// never a value.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_render_writes_the_file_and_keeps_its_leases() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = exec_belt(
        dir.path(),
        &[
            ("db/main#user", b"app-user-01"),
            ("db/main#password", b"pw-render-77"),
        ],
    );
    let mut c = Client::connect(&b).await;
    c.send(tool_call(
        1,
        "vault_render",
        json!({
            "template": "user={{ db/main#user }}\npass={{db/main#password}}\nuser again={{ db/main#user }}\n",
            "dest": "db.env",
            "ttl_s": 60,
        }),
    ))
    .await;
    let m = c.recv().await;
    assert!(m["result"].get("isError").is_none(), "{m}");
    assert!(
        !m.to_string().contains("pw-render"),
        "the answer carries no value"
    );
    let answer: Value =
        serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let path = PathBuf::from(answer["path"].as_str().unwrap());
    let secrets = dir.path().join("run").join("secrets");
    assert_eq!(path, secrets.join("db.env"));
    assert_eq!(answer["ttl_s"], 60);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"user=app-user-01\npass=pw-render-77\nuser again=app-user-01\n"
    );
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&secrets), 0o711);
    assert_eq!(
        vault.leases_asked(),
        [
            (
                "lease_file".to_string(),
                sid,
                5,
                "db/main#user for db.env 60s".to_string()
            ),
            (
                "lease_file".to_string(),
                sid,
                5,
                "db/main#password for db.env 60s".to_string()
            ),
        ]
    );
    assert_eq!(
        *vault.attached.lock().unwrap(),
        [("L0".to_string(), path.clone()), ("L1".to_string(), path)]
    );
    assert!(
        vault.released.lock().unwrap().is_empty(),
        "kept: the file lives with its leases"
    );
    // P3-4d-2 — and the use is reported: both leases, the file's name.
    let reports = vault.reports.lock().unwrap().clone();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(
        reports[0].kind,
        meshharbor_remote_control::vault::VaultActivityKind::Render
    );
    assert_eq!(reports[0].lease_ids, ["L0", "L1"]);
    assert_eq!(reports[0].target, "db.env");
    assert_eq!(reports[0].exit_code, None);
}

/// P3-4c-2 — one refused lease writes nothing and lets the others go.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn a_refused_render_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _) = exec_belt(dir.path(), &[("db/main", b"render-first-1")]);
    let mut c = Client::connect(&b).await;
    c.send(tool_call(
        1,
        "vault_render",
        json!({"template": "{{ db/main }} {{ db/missing }}", "dest": "out"}),
    ))
    .await;
    let m = c.recv().await;
    assert_eq!(m["result"]["isError"], true, "{m}");
    assert_eq!(
        m["result"]["content"][0]["text"],
        "db/missing: the vault refused: no_secret"
    );
    assert!(!dir.path().join("run").join("secrets").join("out").exists());
    assert_eq!(*vault.released.lock().unwrap(), ["L0"]);
    assert!(vault.attached.lock().unwrap().is_empty());
    assert!(
        vault.reports.lock().unwrap().is_empty(),
        "nothing written, nothing reported"
    );
}

/// P3-4c-3 — `vault_request` is offered with the reads and allowed like
/// them; it asks a lease ahead and answers the lease, never a value; a
/// refusal answers why.
#[cfg(feature = "vault")]
#[tokio::test]
async fn vault_request_asks_a_lease_ahead_and_answers_no_value() {
    // Made at runtime: a literal beside `password` reads as one to a scanner.
    let value = format!("ahead-{}", 11);
    let vault = Arc::new(FakeVault {
        values: [("db/main#password".to_string(), value.clone().into_bytes())].into(),
        ..FakeVault::default()
    });
    let sid = ObjectId::new();
    let b = belt_running(
        me(),
        Run {
            session: sid,
            fence: 1,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: None,
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
        .await;
    let list = c.recv().await;
    let request = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "vault_request")
        .expect("offered")
        .clone();
    assert_eq!(
        request["inputSchema"]["required"],
        json!(["handle", "mode", "audience"])
    );
    let allowed: Vec<String> = VAULT_AHEAD_NAMES
        .iter()
        .map(|n| format!("mcp__meshharbor__{n}"))
        .collect();
    assert_eq!(allowed, VAULT_AHEAD_TOOLS, "allowed is what is offered");
    assert!(!VAULT_USE_TOOLS.contains(&VAULT_AHEAD_TOOLS[0]));
    c.send(tool_call(
        2,
        "vault_request",
        json!({"handle": "db/main#password", "mode": "exec", "audience": "psql", "ttl_s": 600}),
    ))
    .await;
    let m = c.recv().await;
    assert!(m["result"].get("isError").is_none(), "{m}");
    assert!(!m.to_string().contains(&value), "no value: {m}");
    let answer: Value =
        serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        answer,
        json!({"lease_id": "L0", "handle": "db/main#password", "mode": "exec",
               "audience": "psql", "ttl_s": 600})
    );
    assert_eq!(
        vault.leases_asked(),
        [(
            "ahead_exec".to_string(),
            sid,
            1,
            "db/main#password for psql 600s".to_string()
        )]
    );
    assert!(vault.released.lock().unwrap().is_empty(), "kept");
    c.send(tool_call(
        3,
        "vault_request",
        json!({"handle": "db/missing", "mode": "file", "audience": "db.env"}),
    ))
    .await;
    let m = c.recv().await;
    assert_eq!(m["result"]["isError"], true, "{m}");
    assert_eq!(
        m["result"]["content"][0]["text"],
        "db/missing: the vault refused: no_secret"
    );
}

/// P3-4c-3 — `vault_exec` takes a lease asked for ahead for its program
/// instead of asking, and keeps it; one that would end during the command
/// is not taken, and the call then asks and lets go of its own.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_exec_takes_a_lease_asked_for_ahead_and_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    // Made at runtime: a literal beside `password` reads as one to a scanner.
    let value = format!("ahead-{}", 42);
    let (b, vault, sid) = exec_belt(dir.path(), &[("db/main#password", value.as_bytes())]);
    let mut c = Client::connect(&b).await;
    c.send(tool_call(
        1,
        "vault_request",
        json!({"handle": "db/main#password", "mode": "exec", "audience": "sh", "ttl_s": 600}),
    ))
    .await;
    assert!(c.recv().await["result"].get("isError").is_none());
    let run = json!({
        "argv": ["sh", "-c", "printf '%s' \"$PW\""],
        "env": {"PW": "db/main#password"},
    });
    let answer = exec_answer(&mut c, 2, run.clone()).await.unwrap();
    assert_eq!(answer["stdout"], "[vault:PW]", "{answer}");
    assert_eq!(
        vault.leases_asked(),
        [(
            "ahead_exec".to_string(),
            sid,
            5,
            "db/main#password for sh 600s".to_string()
        )],
        "taken: nothing asked again"
    );
    assert!(vault.released.lock().unwrap().is_empty(), "kept");
    // Ending within the command's 60 s: not taken.
    vault
        .lefts
        .lock()
        .unwrap()
        .insert("L0".into(), Duration::from_secs(5));
    let answer = exec_answer(&mut c, 3, run).await.unwrap();
    assert_eq!(answer["stdout"], "[vault:PW]", "{answer}");
    assert_eq!(vault.leases_asked()[1].0, "lease_exec");
    assert_eq!(
        *vault.released.lock().unwrap(),
        ["L1"],
        "its own let go, the one asked for ahead kept"
    );
}

/// P3-4c-3 — `vault_render` takes a lease asked for ahead toward its file,
/// asks for the rest, and its file lives until the first of them ends; a
/// lease asked for ahead toward another file is not taken.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_render_takes_a_lease_asked_for_ahead_toward_its_file() {
    let dir = tempfile::tempdir().unwrap();
    // Made at runtime: a literal beside `password` reads as one to a scanner.
    let pass = format!("render-{}", 78);
    let (b, vault, _) = exec_belt(
        dir.path(),
        &[
            ("db/main#user", b"app-user-02"),
            ("db/main#password", pass.as_bytes()),
        ],
    );
    let mut c = Client::connect(&b).await;
    c.send(tool_call(
        1,
        "vault_request",
        json!({"handle": "db/main#user", "mode": "file", "audience": "db.env", "ttl_s": 600}),
    ))
    .await;
    assert!(c.recv().await["result"].get("isError").is_none());
    c.send(tool_call(
        2,
        "vault_render",
        json!({
            "template": "user={{ db/main#user }}\npass={{ db/main#password }}\n",
            "dest": "db.env",
            "ttl_s": 60,
        }),
    ))
    .await;
    let m = c.recv().await;
    assert!(m["result"].get("isError").is_none(), "{m}");
    let answer: Value =
        serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(answer["ttl_s"], 60, "until the first of its leases ends");
    let path = PathBuf::from(answer["path"].as_str().unwrap());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        format!("user=app-user-02\npass={pass}\n").into_bytes()
    );
    let kinds: Vec<String> = vault.leases_asked().into_iter().map(|a| a.3).collect();
    assert_eq!(
        kinds,
        [
            "db/main#user for db.env 600s",
            "db/main#password for db.env 60s"
        ],
        "the user's taken, only the password asked for"
    );
    assert_eq!(
        *vault.attached.lock().unwrap(),
        [("L0".to_string(), path.clone()), ("L1".to_string(), path)]
    );
    assert!(vault.released.lock().unwrap().is_empty(), "both kept");
    // A file from the lease asked for ahead alone lives as long as it.
    let render = |id: u64, dest: &str| {
        tool_call(
            id,
            "vault_render",
            json!({"template": "{{ db/main#user }}", "dest": dest, "ttl_s": 60}),
        )
    };
    c.send(render(3, "db.env")).await;
    let m = c.recv().await;
    let answer: Value =
        serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(answer["ttl_s"], 600, "as long as the lease it took: {m}");
    assert_eq!(vault.leases_asked().len(), 2, "taken: nothing asked");
    // One that would end before the file is asked to: not taken.
    vault
        .lefts
        .lock()
        .unwrap()
        .insert("L0".into(), Duration::from_secs(30));
    c.send(render(4, "db.env")).await;
    assert!(c.recv().await["result"].get("isError").is_none());
    assert_eq!(vault.leases_asked()[2].3, "db/main#user for db.env 60s");
    // Nor one asked for ahead toward another file.
    c.send(render(5, "other.env")).await;
    assert!(c.recv().await["result"].get("isError").is_none());
    assert_eq!(
        vault.leases_asked()[3].3,
        "db/main#user for other.env 60s",
        "asked for afresh toward another file"
    );
}

/// P3-6b-2b — the names a call gives one dynamic secret share ONE
/// `short-lived` lease of it, described first, and the credential minted
/// once for that lease; a stored secret beside it is leased as before. The
/// bundle is never read as a value, and both leases go when the call ends.
/// (The env's order is the JSON map's: what is asserted here holds in any.)
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_exec_hands_a_dynamic_secret_one_credential_minted_for_its_one_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = dynamic_belt(dir.path());
    let mut c = Client::connect(&b).await;
    // Both names from one credential: its tag, then `:0` for the user and
    // `:1` for the next field.
    let answer = exec_answer(
        &mut c,
        1,
        json!({
            "argv": ["sh", "-c", "[ \"${DBU%:0}\" = \"${DBP%:1}\" ] && [ \"${DBU#cred-}\" != \"$DBU\" ] && printf same; printf '|%s' \"$API\""],
            "env": {"DBU": "db/dyn#user", "DBP": "db/dyn#password", "API": "api/main"},
        }),
    )
    .await
    .unwrap();
    assert_eq!(answer["stdout"], "same|[vault:API]", "{answer}");
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let described: Vec<String> = vault
        .asked()
        .into_iter()
        .filter(|a| a.0 == "describe")
        .map(|a| a.3)
        .collect();
    assert_eq!(
        sorted(described),
        ["api/main", "db/dyn"],
        "each secret once"
    );
    let leases = vault.leases_asked();
    assert_eq!(
        sorted(leases.iter().map(|a| format!("{} {}", a.0, a.3)).collect()),
        [
            "lease_exec api/main for sh 90s",
            "lease_short-lived db/dyn for  90s"
        ],
        "one lease for the dynamic secret's two names: {leases:?}"
    );
    assert!(leases.iter().all(|a| a.1 == sid && a.2 == 5));
    let short = vault.short.lock().unwrap().clone();
    assert_eq!(short.len(), 1);
    assert_eq!(*vault.mints.lock().unwrap(), short, "minted once");
    assert_eq!(
        sorted(vault.released.lock().unwrap().clone()),
        ["L0", "L1"],
        "both let go after the run"
    );
    let reports = vault.reports.lock().unwrap().clone();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(sorted(reports[0].lease_ids.clone()), ["L0", "L1"]);
}

/// P3-6b-2b — a dynamic secret serves its credential's fields alone: a call
/// naming any other (an issuer's), or the secret whole, is refused before
/// anything is leased or minted.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_exec_refuses_a_dynamic_secrets_other_fields_before_any_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _) = dynamic_belt(dir.path());
    let mut c = Client::connect(&b).await;
    for handle in ["db/dyn#admin_password", "db/dyn"] {
        let why = exec_answer(
            &mut c,
            1,
            json!({"argv": ["sh", "-c", "touch ran"], "env": {"DBX": handle}}),
        )
        .await
        .unwrap_err();
        assert_eq!(
            why,
            "DBX: db/dyn is a dynamic secret: name a field of the credential minted for it, \
             #user, #password, #host, #port, #database",
            "{handle}"
        );
    }
    assert!(vault.leases_asked().is_empty(), "nothing leased");
    assert!(vault.mints.lock().unwrap().is_empty(), "nothing minted");
    assert!(!dir.path().join("ran").exists(), "nothing ran");
}

/// P3-6b-2b — a template's placeholders of one dynamic secret are written
/// from one credential, and the file lives with that one lease.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_render_writes_a_dynamic_secret_from_one_credential() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = dynamic_belt(dir.path());
    let mut c = Client::connect(&b).await;
    c.send(tool_call(
        1,
        "vault_render",
        json!({
            "template": "u={{ db/dyn#user }} p={{ db/dyn#password }}\n",
            "dest": "pg.env",
            "ttl_s": 60,
        }),
    ))
    .await;
    let m = c.recv().await;
    assert!(m["result"].get("isError").is_none(), "{m}");
    let answer: Value =
        serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let path = PathBuf::from(answer["path"].as_str().unwrap());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"u=cred-L0:0 p=cred-L0:1\n".to_vec()
    );
    assert_eq!(
        vault.asked(),
        [
            ("describe".to_string(), sid, 5, "db/dyn".to_string()),
            (
                "lease_short-lived".to_string(),
                sid,
                5,
                "db/dyn for  60s".to_string()
            ),
        ]
    );
    assert_eq!(*vault.mints.lock().unwrap(), ["L0"]);
    assert_eq!(*vault.attached.lock().unwrap(), [("L0".to_string(), path)]);
    assert!(
        vault.released.lock().unwrap().is_empty(),
        "kept: the file lives with its lease"
    );
}

/// P3-6b-2b — a dynamic secret asked for ahead is asked for whole, in
/// `short-lived`, whatever its use, and minted at its first use, not
/// before; each use that takes it shares the one credential. It is never
/// asked for toward a proxy: `vault_connect` serves no dynamic secret.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_request_asks_a_dynamic_secret_whole_and_its_uses_share_one_credential() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = dynamic_belt(dir.path());
    let mut c = Client::connect(&b).await;
    c.send(tool_call(
        1,
        "vault_request",
        json!({"handle": "db/dyn#user", "mode": "exec", "audience": "sh"}),
    ))
    .await;
    let m = c.recv().await;
    assert!(m["result"].get("isError").is_none(), "{m}");
    let answer: Value =
        serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        answer,
        json!({"lease_id": "L0", "handle": "db/dyn", "mode": "short-lived",
               "provider": "postgres", "ttl_s": 300})
    );
    assert_eq!(
        vault.leases_asked(),
        [(
            "ahead_short-lived".to_string(),
            sid,
            5,
            "db/dyn for  300s".to_string()
        )]
    );
    assert!(
        vault.mints.lock().unwrap().is_empty(),
        "minted at its first use, not before"
    );
    let run =
        json!({"argv": ["sh", "-c", "printf '%s' \"${DBU%:0}\""], "env": {"DBU": "db/dyn#user"}});
    let first = exec_answer(&mut c, 2, run.clone()).await.unwrap();
    let second = exec_answer(&mut c, 3, run).await.unwrap();
    assert_eq!(first["stdout"], "cred-L0", "{first}");
    assert_eq!(second["stdout"], first["stdout"], "one credential");
    assert_eq!(vault.leases_asked().len(), 1, "taken: nothing asked again");
    assert_eq!(*vault.mints.lock().unwrap(), ["L0", "L0"]);
    assert!(vault.released.lock().unwrap().is_empty(), "kept");
    c.send(tool_call(
        4,
        "vault_request",
        json!({"handle": "db/dyn#user", "mode": "proxy", "audience": "db.internal:5432"}),
    ))
    .await;
    let m = c.recv().await;
    assert_eq!(m["result"]["isError"], true, "{m}");
    assert_eq!(
        m["result"]["content"][0]["text"],
        "db/dyn#user: vault_connect does not sign in with a dynamic secret's credential: \
         vault_exec and vault_render serve it"
    );
    assert_eq!(vault.leases_asked().len(), 1, "nothing asked for a proxy");
}

/// P3-5b-2 — the answer to a `vault_connect` call: its JSON, or its error
/// text.
#[cfg(feature = "vault")]
async fn connect_answer(c: &mut Client, id: u64, args: Value) -> Result<Value, String> {
    c.send(tool_call(id, "vault_connect", args)).await;
    let m = c.recv().await;
    assert_eq!(m["id"], id, "{m}");
    let text = m["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    if m["result"]["isError"] == true {
        Err(text)
    } else {
        Ok(serde_json::from_str(&text).unwrap())
    }
}

/// P3-5b-2 — `vault_connect` leases the secret's user and password, and its
/// CA, toward the upstream it names, and serves an endpoint only the
/// session's account reaches. A client that sends no password gets a session
/// there as the secret's user, and the answer holds no value. When a lease
/// goes, the endpoint goes with every connection it held, and the call's
/// other leases are let go rather than held to their expiry.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_connect_serves_an_endpoint_that_signs_in_as_the_secrets_user() {
    use crate::vault_proxy::testing::{Saw, Upstreams, fake, made, message, next, startup};
    let pw = made();
    let (ca, port, mut saw) = fake(Upstreams::Scram(pw.clone())).await;
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = exec_belt(
        dir.path(),
        &[
            ("db/main#user", b"app"),
            ("db/main#password", pw.as_bytes()),
            ("pki/db-ca", ca.as_bytes()),
        ],
    );
    let upstream = format!("localhost:{port}");
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "db/main",
            "engine": "postgres",
            "upstream": upstream,
            "database": "orders",
            "ca": "pki/db-ca",
            "ttl_s": 60,
        }),
    )
    .await
    .unwrap();
    assert!(
        !answer.to_string().contains(&pw),
        "the answer holds no value"
    );
    let host = PathBuf::from(answer["host"].as_str().unwrap());
    let proxies = dir.path().join("run").join("proxies");
    assert_eq!(host.parent(), Some(proxies.as_path()));
    assert_eq!(answer["port"], 5432);
    assert_eq!(answer["database"], "orders");
    assert_eq!(answer["ttl_s"], 60);
    assert_eq!(answer["env"]["PGHOST"], json!(host.to_string_lossy()));
    assert_eq!(answer["env"]["PGDATABASE"], "orders");
    assert!(
        answer["uri"]
            .as_str()
            .unwrap()
            .starts_with("postgresql:///orders?host=/"),
        "{answer}"
    );
    let socket = host.join(".s.PGSQL.5432");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&proxies), 0o711);
    assert_eq!(mode(&host), 0o711);
    assert_eq!(mode(&socket), 0o600);
    let lease = |h: &str| {
        (
            "lease_proxy".to_string(),
            sid,
            5,
            format!("{h} for {upstream} 60s"),
        )
    };
    assert_eq!(
        vault.asked(),
        [
            lease("db/main#user"),
            lease("db/main#password"),
            lease("pki/db-ca")
        ]
    );

    // A client with no password: a session, as the secret's user.
    let mut pg = tokio::net::UnixStream::connect(&socket).await.unwrap();
    pg.write_all(&startup(&[("user", "whoever"), ("database", "orders")]))
        .await
        .unwrap();
    assert_eq!(next(&mut pg).await, (b'R', vec![0, 0, 0, 0]));
    assert_eq!(next(&mut pg).await.0, b'S');
    assert_eq!(next(&mut pg).await.0, b'K');
    assert_eq!(next(&mut pg).await.0, b'Z');
    assert_eq!(
        saw.recv().await.unwrap(),
        Saw::Startup(vec![
            ("user".into(), "app".into()),
            ("database".into(), "orders".into()),
        ])
    );
    pg.write_all(&message(b'Q', b"select 1\0")).await.unwrap();
    assert_eq!(next(&mut pg).await.0, b'C');
    assert_eq!(next(&mut pg).await.0, b'Z');
    assert_eq!(saw.recv().await.unwrap(), Saw::Query("select 1".into()));
    assert!(
        vault.released.lock().unwrap().is_empty(),
        "kept while the endpoint serves"
    );

    // The password's lease goes: the endpoint closes, its connection with it,
    // and the call's other leases are let go.
    vault.release(&["L1".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut pg, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection ended with the lease");
    let gone = async {
        while host.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(WAIT, gone)
        .await
        .expect("the endpoint's directory goes");
    let released = || {
        let mut r = vault.released.lock().unwrap().clone();
        r.sort();
        r.dedup();
        r
    };
    let lets_go = async {
        while released().len() < 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(WAIT, lets_go)
        .await
        .expect("the call's leases are let go");
    assert_eq!(released(), ["L0", "L1", "L2"]);
    assert!(
        tokio::net::UnixStream::connect(&socket).await.is_err(),
        "nothing left to dial"
    );
}

/// P3-5b-2 — a refused lease opens no endpoint and lets the call's others
/// go; a call the device refuses asks the vault nothing.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn a_refused_connect_opens_no_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _) = exec_belt(dir.path(), &[("db/main#user", b"app")]);
    let mut c = Client::connect(&b).await;
    let refused = connect_answer(
        &mut c,
        1,
        json!({"handle": "db/main", "engine": "postgres", "upstream": "db.internal:5432"}),
    )
    .await;
    assert_eq!(
        refused,
        Err("db/main#password: the vault refused: no_secret".into())
    );
    assert_eq!(*vault.released.lock().unwrap(), ["L0"]);
    assert!(vault.stops.lock().unwrap().is_empty());
    assert!(
        !dir.path().join("run").join("proxies").exists(),
        "no endpoint"
    );
    let asked = vault.asked().len();
    for bad in [
        json!({"handle": "db/main#password", "engine": "postgres", "upstream": "db.internal:5432"}),
        json!({"handle": "db/main", "engine": "mysql", "upstream": "db.internal:5432"}),
        json!({"handle": "db/main", "engine": "postgres", "upstream": "db.internal"}),
    ] {
        assert!(connect_answer(&mut c, 2, bad).await.is_err());
    }
    assert_eq!(vault.asked().len(), asked, "nothing asked of the vault");
}

/// P3-5b-2 — a run holds a bounded number of endpoints: one more is refused
/// before the vault is asked, and an endpoint that closes gives its place
/// back.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn a_run_holds_a_bounded_number_of_endpoints() {
    use super::super::vault_connect::MAX_ENDPOINTS;
    use crate::vault_proxy::testing::{Upstreams, fake, made};
    // An upstream to name, never dialled: its CA is what the endpoint trusts.
    let (ca, port, _saw) = fake(Upstreams::Trusting).await;
    let pw = made();
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _) = exec_belt(
        dir.path(),
        &[
            ("db/main#user", b"app"),
            ("db/main#password", pw.as_bytes()),
            ("pki/db-ca", ca.as_bytes()),
        ],
    );
    let call = json!({
        "handle": "db/main",
        "engine": "postgres",
        "upstream": format!("localhost:{port}"),
        "ca": "pki/db-ca",
    });
    let mut c = Client::connect(&b).await;
    let mut first = None;
    for id in 0..MAX_ENDPOINTS as u64 {
        let answer = connect_answer(&mut c, id, call.clone()).await.unwrap();
        first.get_or_insert(PathBuf::from(answer["host"].as_str().unwrap()));
    }
    let asked = vault.asked().len();
    let refused = connect_answer(&mut c, 100, call.clone()).await.unwrap_err();
    assert!(refused.contains("endpoints already"), "{refused}");
    assert_eq!(vault.asked().len(), asked, "nothing asked of the vault");
    // The first endpoint's CA lease goes, and with it the endpoint.
    vault.release(&["L2".to_string()]);
    let first = first.unwrap();
    let gone = async {
        while first.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(WAIT, gone).await.unwrap();
    let mut again = Err(String::new());
    for id in 200..250 {
        again = connect_answer(&mut c, id, call.clone()).await;
        if again.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(again.is_ok(), "its place is given back: {again:?}");
}

/// P3-5b-2 — a connection from any account but the session's is refused,
/// root's included: the socket is handed to the session's account, and each
/// connection's uid is checked again. Handing a socket to another account
/// needs root, as the daemon has; anywhere else this test says so and stops.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn a_proxy_connection_from_another_account_is_refused() {
    use crate::vault_proxy::testing::{Upstreams, fake, made, startup};
    // SAFETY: geteuid reads our own credentials; it cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: handing a socket to another account needs root");
        return;
    }
    let pw = made();
    let (ca, port, mut saw) = fake(Upstreams::Scram(pw.clone())).await;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(FakeVault {
        values: [
            ("db/main#user", b"app".to_vec()),
            ("db/main#password", pw.as_bytes().to_vec()),
            ("pki/db-ca", ca.as_bytes().to_vec()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        ..FakeVault::default()
    });
    std::fs::create_dir_all(dir.path().join("run")).unwrap();
    // The session runs as an account that is not this test's.
    let other = (4242, 4242);
    let b = belt_running(
        me(),
        Run {
            session: ObjectId::new(),
            fence: 5,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: Some(super::super::vault_exec::ExecTarget {
                account: None,
                home: dir.path().to_path_buf(),
                folder: dir.path().to_path_buf(),
                session_dir: dir.path().join("run"),
                owner: Some(other),
            }),
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "db/main",
            "engine": "postgres",
            "upstream": format!("localhost:{port}"),
            "ca": "pki/db-ca",
        }),
    )
    .await
    .unwrap();
    let socket = PathBuf::from(answer["host"].as_str().unwrap()).join(".s.PGSQL.5432");
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&socket).unwrap();
        assert_eq!((m.uid(), m.gid()), other, "handed to the session's account");
    }
    // Root passes the socket's own permissions; the endpoint's check does not.
    let mut pg = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let _ = pg.write_all(&startup(&[("database", "d")])).await;
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut pg, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection was closed");
    assert!(rest.is_empty(), "and answered nothing: {rest:?}");
    assert!(saw.try_recv().is_err(), "no upstream was dialled");
}

/// P3-5b-4 — a vault holding a secret's user and password, and the CA its
/// upstream's certificate is made under.
#[cfg(all(feature = "vault", windows))]
fn proxy_vault(password: &str, ca: &str) -> Arc<FakeVault> {
    Arc::new(FakeVault {
        values: [
            ("db/main#user", b"app".to_vec()),
            ("db/main#password", password.as_bytes().to_vec()),
            ("pki/db-ca", ca.as_bytes().to_vec()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        ..FakeVault::default()
    })
}

/// P3-5b-4 — on Windows the endpoint is a loopback port. The answer names it,
/// and says the loopback leg is plain. A client of this account gets a
/// session as the secret's user, and when a lease goes, the connection goes.
#[cfg(all(feature = "vault", windows))]
#[tokio::test]
async fn vault_connect_serves_a_loopback_endpoint() {
    use crate::vault_proxy::testing::{Saw, Upstreams, fake, made, message, next, startup};
    let pw = made();
    let (ca, port, mut saw) = fake(Upstreams::Scram(pw.clone())).await;
    let vault = proxy_vault(&pw, &ca);
    let b = belt_running(
        me(),
        Run {
            session: ObjectId::new(),
            fence: 5,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: None,
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "db/main",
            "engine": "postgres",
            "upstream": format!("localhost:{port}"),
            "database": "orders",
            "ca": "pki/db-ca",
        }),
    )
    .await
    .unwrap();
    assert!(
        !answer.to_string().contains(&pw),
        "the answer holds no value"
    );
    assert_eq!(answer["host"], "127.0.0.1");
    assert_eq!(answer["env"]["PGSSLMODE"], "disable");
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    assert_eq!(
        answer["uri"],
        format!("postgresql://127.0.0.1:{dial}/orders?sslmode=disable")
    );
    let mut pg = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    pg.write_all(&startup(&[("user", "whoever"), ("database", "orders")]))
        .await
        .unwrap();
    assert_eq!(next(&mut pg).await, (b'R', vec![0, 0, 0, 0]));
    assert_eq!(next(&mut pg).await.0, b'S');
    assert_eq!(next(&mut pg).await.0, b'K');
    assert_eq!(next(&mut pg).await.0, b'Z');
    assert_eq!(
        saw.recv().await.unwrap(),
        Saw::Startup(vec![
            ("user".into(), "app".into()),
            ("database".into(), "orders".into()),
        ])
    );
    pg.write_all(&message(b'Q', b"select 1\0")).await.unwrap();
    assert_eq!(next(&mut pg).await.0, b'C');
    assert_eq!(next(&mut pg).await.0, b'Z');
    // The password's lease goes, and with it the connection.
    vault.release(&["L1".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut pg, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection ended with the lease");
}

/// P3-5b-4 — a loopback connection from a process that does not run as the
/// session's account is refused. Here the session's account is another's,
/// so this test's own connection is the one refused.
#[cfg(all(feature = "vault", windows))]
#[tokio::test]
async fn a_loopback_connection_from_another_account_is_refused() {
    use crate::vault_proxy::testing::{Upstreams, fake, made, startup};
    let pw = made();
    let (ca, port, mut saw) = fake(Upstreams::Scram(pw.clone())).await;
    let vault = proxy_vault(&pw, &ca);
    // SYSTEM, unless this test is SYSTEM: then LOCAL SERVICE.
    let other = match crate::hive_win::own_sid().unwrap().as_str() {
        "S-1-5-18" => "S-1-5-19",
        _ => "S-1-5-18",
    }
    .to_string();
    let answer = super::super::vault_connect::call(
        vault,
        ObjectId::new(),
        5,
        None,
        &other,
        &json!({
            "handle": "db/main",
            "engine": "postgres",
            "upstream": format!("localhost:{port}"),
            "ca": "pki/db-ca",
        }),
    )
    .await
    .unwrap();
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let mut pg = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    let _ = pg.write_all(&startup(&[("database", "d")])).await;
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut pg, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection was closed");
    assert!(rest.is_empty(), "and answered nothing: {rest:?}");
    assert!(saw.try_recv().is_err(), "no upstream was dialled");
}

/// P3-5c-2 — `vault_connect` serves the MongoDB engine on Unix. The socket
/// is one a driver dials by its path, and the answer's `uri` names it. A
/// handshake from a client with no credentials is answered by a connection
/// signed in as the secret's user, and the connection ends with its lease.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_connect_serves_mongodb_on_a_socket_a_driver_dials_by_its_path() {
    use crate::vault_proxy::testing::{
        MongoSaw, MongoUpstreams, fake_mongo, made, mongo_command, mongo_reply, op_query,
    };
    let pw = made();
    let (ca, port, mut saw) = fake_mongo(MongoUpstreams::Scram(pw.clone())).await;
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = exec_belt(
        dir.path(),
        &[
            ("db/docs#user", b"app"),
            ("db/docs#password", pw.as_bytes()),
            ("pki/db-ca", ca.as_bytes()),
        ],
    );
    let upstream = format!("localhost:{port}");
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "db/docs",
            "engine": "mongodb",
            "upstream": upstream,
            "database": "orders",
            "ca": "pki/db-ca",
            "auth_source": "users",
            "ttl_s": 60,
        }),
    )
    .await
    .unwrap();
    assert!(
        !answer.to_string().contains(&pw),
        "the answer holds no value"
    );
    let socket = PathBuf::from(answer["host"].as_str().unwrap());
    assert!(socket.ends_with("mongodb-27017.sock"), "{answer}");
    assert_eq!(answer["port"], Value::Null);
    let uri = answer["uri"].as_str().unwrap();
    assert!(
        uri.starts_with("mongodb://%2F")
            && uri.ends_with("mongodb-27017.sock/orders?directConnection=true"),
        "{uri}"
    );
    assert_eq!(answer["env"]["MONGODB_URI"], uri);
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut m = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let handshake = bson::doc! { "isMaster": 1, "client": { "driver": { "name": "a-test" } } };
    m.write_all(&op_query(7, "admin.$cmd", &handshake))
        .await
        .unwrap();
    let (op, to, reply) = mongo_reply(&mut m).await;
    assert_eq!((op, to), (1, 7), "an OP_REPLY to the handshake");
    assert_eq!(reply.get_bool("ismaster"), Ok(true));
    let command = |name: &str, db: &str| MongoSaw::Command(name.into(), db.into());
    let seen: Vec<MongoSaw> = std::iter::from_fn(|| saw.try_recv().ok()).collect();
    assert_eq!(
        seen,
        [
            command("saslStart", "users"),
            MongoSaw::User("app".into()),
            command("saslContinue", "users"),
            MongoSaw::Query("admin.$cmd".into(), "isMaster".into()),
            MongoSaw::Metadata(true),
        ],
        "signed in in the call's auth database"
    );
    m.write_all(&mongo_command(
        8,
        &bson::doc! { "ping": 1, "$db": "orders" },
    ))
    .await
    .unwrap();
    let (op, to, reply) = mongo_reply(&mut m).await;
    assert_eq!((op, to), (2013, 8));
    assert_eq!(reply.get_f64("ok"), Ok(1.0));
    let lease = |h: &str| {
        (
            "lease_proxy".to_string(),
            sid,
            5,
            format!("{h} for {upstream} 60s"),
        )
    };
    assert_eq!(
        vault.asked(),
        [
            lease("db/docs#user"),
            lease("db/docs#password"),
            lease("pki/db-ca")
        ]
    );
    vault.release(&["L1".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut m, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection ended with the lease");
}

/// P3-5c-2 — and on Windows: a loopback port, `directConnection=true`, a
/// handshake answered by a connection signed in as the secret's user.
#[cfg(all(feature = "vault", windows))]
#[tokio::test]
async fn vault_connect_serves_mongodb_on_a_loopback_port() {
    use crate::vault_proxy::testing::{
        MongoUpstreams, fake_mongo, made, mongo_command, mongo_reply, op_query,
    };
    let pw = made();
    let (ca, port, _saw) = fake_mongo(MongoUpstreams::Scram(pw.clone())).await;
    let vault = proxy_vault(&pw, &ca);
    let b = belt_running(
        me(),
        Run {
            session: ObjectId::new(),
            fence: 5,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: None,
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "db/main",
            "engine": "mongodb",
            "upstream": format!("localhost:{port}"),
            "database": "orders",
            "ca": "pki/db-ca",
        }),
    )
    .await
    .unwrap();
    assert_eq!(answer["host"], "127.0.0.1");
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    assert_eq!(
        answer["uri"],
        format!("mongodb://127.0.0.1:{dial}/orders?directConnection=true")
    );
    let mut m = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    let handshake = bson::doc! { "isMaster": 1, "client": { "driver": { "name": "a-test" } } };
    m.write_all(&op_query(7, "admin.$cmd", &handshake))
        .await
        .unwrap();
    let (_, to, reply) = mongo_reply(&mut m).await;
    assert_eq!(to, 7);
    assert_eq!(reply.get_bool("ismaster"), Ok(true));
    m.write_all(&mongo_command(
        8,
        &bson::doc! { "ping": 1, "$db": "orders" },
    ))
    .await
    .unwrap();
    let (_, to, reply) = mongo_reply(&mut m).await;
    assert_eq!((to, reply.get_f64("ok")), (8, Ok(1.0)));
    vault.release(&["L1".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut m, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection ended with the lease");
}

/// P3-5d-2 — a toolbelt for an HTTP endpoint's call, with `values` in its
/// vault: on Unix a run whose commands run as this daemon, on Windows the
/// session's account as the toolbelt holds it.
#[cfg(all(feature = "vault", unix))]
fn http_belt(dir: &Path, values: &[(&str, &[u8])]) -> (Belt, Arc<FakeVault>, ObjectId) {
    exec_belt(dir, values)
}

#[cfg(all(feature = "vault", windows))]
fn http_belt(dir: &Path, values: &[(&str, &[u8])]) -> (Belt, Arc<FakeVault>, ObjectId) {
    let _ = dir;
    let vault = Arc::new(FakeVault {
        values: values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect(),
        ..FakeVault::default()
    });
    let sid = ObjectId::new();
    let belt = belt_running(
        me(),
        Run {
            session: sid,
            fence: 5,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: None,
        },
        quick(),
    );
    (belt, vault, sid)
}

/// P3-5d-2 — one HTTP response on `s`, within 10 s, read whole: its head,
/// then its body by its `content-length`.
#[cfg(feature = "vault")]
async fn http_response<S: AsyncRead + Unpin>(s: &mut S) -> String {
    use tokio::io::AsyncReadExt;
    let read = async {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if got.len() >= end + 4 + length {
                    return String::from_utf8_lossy(&got).into_owned();
                }
            }
            let n = s.read(&mut buf).await.unwrap();
            assert!(
                n > 0,
                "the endpoint hung up mid-response: {:?}",
                String::from_utf8_lossy(&got)
            );
            got.extend_from_slice(&buf[..n]);
        }
    };
    tokio::time::timeout(WAIT, read)
        .await
        .expect("a response within 10 s")
}

/// P3-5d-2 — `vault_connect` serves an HTTP upstream on a loopback port.
/// The answer names the endpoint and git's way through it, never the value;
/// a request with no credential reaches the upstream with the secret's
/// token; and the connection ends with its lease.
#[cfg(feature = "vault")]
#[tokio::test]
async fn vault_connect_serves_an_http_upstream_on_a_loopback_port() {
    use crate::vault_proxy::testing::{fake_http, made};
    let token = made();
    let (ca, port, mut saw) = fake_http().await;
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = http_belt(
        dir.path(),
        &[
            ("git/bot#token", token.as_bytes()),
            ("pki/git-ca", ca.as_bytes()),
        ],
    );
    let upstream = format!("https://localhost:{port}");
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "git/bot",
            "engine": "http",
            "upstream": upstream,
            "auth": "bearer",
            "ca": "pki/git-ca",
            "ttl_s": 60,
        }),
    )
    .await
    .unwrap();
    assert!(
        !answer.to_string().contains(&token),
        "the answer holds no value"
    );
    assert_eq!(answer["host"], "127.0.0.1");
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let uri = format!("http://127.0.0.1:{dial}");
    assert_eq!(answer["uri"], uri);
    assert_eq!(answer["database"], Value::Null);
    let env = &answer["env"];
    assert_eq!(env["GIT_CONFIG_COUNT"], "1");
    assert_eq!(env["GIT_CONFIG_KEY_0"], format!("url.{uri}/.insteadOf"));
    assert_eq!(env["GIT_CONFIG_VALUE_0"], format!("{upstream}/"));
    assert_eq!(env["GIT_TERMINAL_PROMPT"], "0");
    let mut h = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    h.write_all(b"GET /api/x?y=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let response = http_response(&mut h).await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let s = tokio::time::timeout(WAIT, saw.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.target, "/api/x?y=1");
    assert_eq!(s.values("authorization"), [format!("Bearer {token}")]);
    let lease = |h: &str| {
        (
            "lease_proxy".to_string(),
            sid,
            5,
            format!("{h} for {upstream} 60s"),
        )
    };
    assert_eq!(vault.asked(), [lease("git/bot#token"), lease("pki/git-ca")]);
    vault.release(&["L1".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut h, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection ended with the lease");
}

/// FR-90 P3-9-2 — a person's leases over the fake vault: each asked for
/// recorded with the endpoint it is for, refused while `refuse` says so, and
/// every lease an endpoint was given let go when it closes.
#[cfg(feature = "vault")]
struct FakePersonLeases {
    vault: Arc<FakeVault>,
    asked: std::sync::Mutex<Vec<(u64, String)>>,
    refuse: std::sync::Mutex<Option<super::super::vault_connect::Refused>>,
    given: std::sync::Mutex<Vec<(u64, String)>>,
    dropped: std::sync::Mutex<Vec<u64>>,
}

#[cfg(feature = "vault")]
impl FakePersonLeases {
    fn over(vault: &Arc<FakeVault>) -> Arc<Self> {
        Arc::new(Self {
            vault: Arc::clone(vault),
            asked: Default::default(),
            refuse: Default::default(),
            given: Default::default(),
            dropped: Default::default(),
        })
    }

    /// The leases endpoint `id` holds now, in the order they were given.
    fn holding(&self, id: u64) -> Vec<String> {
        let held = self.vault.held.lock().unwrap();
        self.given
            .lock()
            .unwrap()
            .iter()
            .filter(|(e, l)| *e == id && held.contains_key(l))
            .map(|(_, l)| l.clone())
            .collect()
    }

    fn asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

#[cfg(feature = "vault")]
#[async_trait::async_trait]
impl super::super::vault_connect::PersonLeases for FakePersonLeases {
    async fn connect(
        &self,
        id: u64,
        handle: &super::super::vault_exec::Handle,
        upstream: &str,
        ttl_secs: u32,
    ) -> Result<String, super::super::vault_connect::Refused> {
        self.asked
            .lock()
            .unwrap()
            .push((id, format!("{handle} for {upstream} {ttl_secs}s")));
        if let Some(refused) = self.refuse.lock().unwrap().clone() {
            return Err(refused);
        }
        let lease = self
            .vault
            .lease(ObjectId::default(), 0, handle, "proxy", upstream, ttl_secs)
            .await
            .map_err(|why| super::super::vault_connect::Refused { why, again: false })?;
        self.given.lock().unwrap().push((id, lease.clone()));
        Ok(lease)
    }

    fn drop_person(&self, id: u64) {
        self.dropped.lock().unwrap().push(id);
        let mine: Vec<String> = self
            .given
            .lock()
            .unwrap()
            .iter()
            .filter(|(e, _)| *e == id)
            .map(|(_, l)| l.clone())
            .collect();
        self.vault.release(&mine);
    }
}

/// FR-90 P3-9-2 — a person's HTTP endpoint over the fake vault, `token` its
/// bearer and `ca` its upstream's CA, renewed on a quick clock: its answer,
/// its control, and the upstream it reaches.
#[cfg(feature = "vault")]
async fn person_http(
    dir: &Path,
    vault: &Arc<FakeVault>,
    leases: &Arc<FakePersonLeases>,
    port: u16,
) -> Result<(Value, super::super::vault_connect::Control), String> {
    use super::super::vault_connect::{At, Person, Timing as Renewing, open_person};
    // Unix: the person's own directory under the runtime, the daemon's at
    // `0711`, which a database's socket would be made under.
    #[cfg(unix)]
    let place = {
        // SAFETY: geteuid reads our own credentials.
        let uid = unsafe { libc::geteuid() };
        let place = super::super::vault_connect::person_dir(dir, uid)?;
        let mode = std::fs::metadata(&place).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o711, "{}", place.display());
        assert_eq!(place, dir.join(format!("person-{uid}")));
        place
    };
    #[cfg(unix)]
    let at = At {
        dir: &place,
        owner: None,
    };
    #[cfg(windows)]
    let sid = {
        let _ = dir;
        me()
    };
    #[cfg(windows)]
    let at = At(&sid);
    let person = Person {
        leases: Arc::clone(leases) as Arc<dyn super::super::vault_connect::PersonLeases>,
        // Each test's own account, so the endpoints of tests that run at
        // once are counted apart.
        account: ObjectId::new().to_hex(),
        timing: Renewing {
            margin_div: 3,
            floor: Duration::from_millis(100),
            recheck: Duration::from_millis(50),
        },
    };
    let args = json!({
        "handle": "git/bot",
        "engine": "http",
        "upstream": format!("https://localhost:{port}"),
        "auth": "bearer",
        "ca": "pki/git-ca",
        "ttl_s": 60,
    });
    open_person(Arc::clone(vault) as Arc<dyn VaultTools>, person, at, &args).await
}

/// FR-90 P3-9-2 — a fake vault holding `git/bot`'s token and the upstream's
/// CA.
#[cfg(feature = "vault")]
fn person_vault(token: &str, ca: &str) -> Arc<FakeVault> {
    Arc::new(FakeVault {
        values: [
            ("git/bot#token".to_string(), token.as_bytes().to_vec()),
            ("pki/git-ca".to_string(), ca.as_bytes().to_vec()),
        ]
        .into_iter()
        .collect(),
        ..FakeVault::default()
    })
}

/// Wait up to 10 s for `done`.
#[cfg(feature = "vault")]
async fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "not within 10 s: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One request through a person's endpoint at `dial`, on `h`: what the
/// upstream saw of its credential.
#[cfg(feature = "vault")]
async fn bearer_through(
    h: &mut tokio::net::TcpStream,
    saw: &mut mpsc::UnboundedReceiver<crate::vault_proxy::testing::HttpSaw>,
) -> Vec<String> {
    h.write_all(b"GET /api/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let response = http_response(h).await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let s = tokio::time::timeout(WAIT, saw.recv())
        .await
        .unwrap()
        .unwrap();
    s.values("authorization")
        .into_iter()
        .map(String::from)
        .collect()
}

/// FR-90 P3-9-2 — a person's endpoint serves with leases asked for the
/// device's owner, and renews them while it is held (decision 25): a margin
/// before they end every field is asked for again, the connections it serves
/// stay up, a new one reads the new leases, and the old ones are let go.
/// Closing it lets go of every lease it holds and stops serving.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_persons_endpoint_renews_its_leases_while_it_is_held() {
    use crate::vault_proxy::testing::{fake_http, made};
    let token = made();
    let (ca, port, mut saw) = fake_http().await;
    let vault = person_vault(&token, &ca);
    let leases = FakePersonLeases::over(&vault);
    let dir = tempfile::tempdir().unwrap();
    let (answer, control) = person_http(dir.path(), &vault, &leases, port)
        .await
        .unwrap();
    assert!(!answer.to_string().contains(&token), "no value: {answer}");
    let id = answer["id"]
        .as_u64()
        .expect("a person's endpoint names its id");
    assert_eq!(id, control.id);
    assert!(
        answer["note"].as_str().unwrap().contains("renewed"),
        "{answer}"
    );
    let upstream = format!("https://localhost:{port}");
    assert_eq!(
        *leases.asked.lock().unwrap(),
        [
            (id, format!("git/bot#token for {upstream} 60s")),
            (id, format!("pki/git-ca for {upstream} 60s")),
        ]
    );
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let mut kept = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    assert_eq!(
        bearer_through(&mut kept, &mut saw).await,
        [format!("Bearer {token}")]
    );

    // A margin before its leases end, they are asked for again.
    let first = leases.holding(id);
    assert_eq!(first.len(), 2);
    for l in &first {
        vault
            .lefts
            .lock()
            .unwrap()
            .insert(l.clone(), Duration::from_secs(1));
    }
    until("one renewal", || control.state().renewals == 1).await;
    assert_eq!(leases.asked(), 4);
    let second = leases.holding(id);
    assert_eq!(second.len(), 2);
    assert!(
        first
            .iter()
            .all(|l| vault.released.lock().unwrap().contains(l)),
        "the old leases are let go"
    );
    assert!(control.state().left > Duration::from_secs(30));

    // The connection it served stays up, and a new one reads the new
    // leases.
    assert_eq!(
        bearer_through(&mut kept, &mut saw).await,
        [format!("Bearer {token}")]
    );
    vault
        .held
        .lock()
        .unwrap()
        .insert(second[0].clone(), b"rotated-token".to_vec());
    let mut fresh = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    assert_eq!(
        bearer_through(&mut fresh, &mut saw).await,
        ["Bearer rotated-token".to_string()]
    );

    // Closed: every lease it holds is let go, and it serves no more.
    control.close("the person left");
    until("the endpoint's leases let go", || {
        leases.dropped.lock().unwrap().contains(&id)
    })
    .await;
    assert!(leases.holding(id).is_empty());
    assert_eq!(control.state().closed.as_deref(), Some("the person left"));
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut kept, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "its connections end with it");
}

/// FR-90 P3-9-2 — a lease of a person's endpoint taken back before its
/// renewal (`rc:vault.revoke`) cuts every connection it serves, and is asked
/// for again at once: the endpoint serves on under the new leases.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_lease_taken_back_cuts_a_persons_connections_and_is_asked_for_again() {
    use crate::vault_proxy::testing::{fake_http, made};
    let token = made();
    let (ca, port, mut saw) = fake_http().await;
    let vault = person_vault(&token, &ca);
    let leases = FakePersonLeases::over(&vault);
    let dir = tempfile::tempdir().unwrap();
    let (answer, control) = person_http(dir.path(), &vault, &leases, port)
        .await
        .unwrap();
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let mut live = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    assert_eq!(
        bearer_through(&mut live, &mut saw).await,
        [format!("Bearer {token}")]
    );
    let mut rest = Vec::new();
    let open = tokio::time::timeout(
        Duration::from_millis(300),
        tokio::io::AsyncReadExt::read_to_end(&mut live, &mut rest),
    )
    .await;
    assert!(open.is_err(), "kept alive until something cuts it");

    let taken = leases.holding(control.id)[0].clone();
    vault.release(&[taken]);
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut live, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "a lease taken back cuts its connection");
    until("asked for again", || control.state().renewals == 1).await;
    assert_eq!(control.state().closed, None);
    let mut after = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    assert_eq!(
        bearer_through(&mut after, &mut saw).await,
        [format!("Bearer {token}")]
    );
    control.close("done");
}

/// FR-90 P3-9-2 — a renewal the vault cannot answer is asked again while the
/// leases last; one it refuses leaves the endpoint serving to its leases'
/// end, then closed with why, every lease let go.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_renewal_refused_serves_to_the_leases_end_then_closes() {
    use super::super::vault_connect::Refused;
    use crate::vault_proxy::testing::{fake_http, made};
    let token = made();
    let (ca, port, mut saw) = fake_http().await;
    let vault = person_vault(&token, &ca);
    let leases = FakePersonLeases::over(&vault);
    let dir = tempfile::tempdir().unwrap();
    let (answer, control) = person_http(dir.path(), &vault, &leases, port)
        .await
        .unwrap();
    let id = control.id;
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let held = leases.holding(id);
    for l in &held {
        vault
            .lefts
            .lock()
            .unwrap()
            .insert(l.clone(), Duration::from_secs(1));
    }

    // Unanswered: asked again, and nothing is refused yet.
    *leases.refuse.lock().unwrap() = Some(Refused {
        why: "the vault did not answer".into(),
        again: true,
    });
    until("asked again", || leases.asked() >= 4).await;
    assert_eq!(control.state().refused, None);

    // Refused: it serves on under the leases it holds.
    *leases.refuse.lock().unwrap() = Some(Refused {
        why: "the vault refused: denied".into(),
        again: false,
    });
    until("the refusal", || control.state().refused.is_some()).await;
    assert_eq!(
        control.state().refused.as_deref(),
        Some("git/bot#token: the vault refused: denied")
    );
    let mut h = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    assert_eq!(
        bearer_through(&mut h, &mut saw).await,
        [format!("Bearer {token}")]
    );
    assert_eq!(leases.holding(id), held, "nothing was given in their place");

    // Its leases end: it closes, saying why.
    vault.release(&held);
    until("closed", || control.state().closed.is_some()).await;
    assert_eq!(
        control.state().closed.as_deref(),
        Some(
            "its leases ended, and the vault refused to renew them: git/bot#token: the vault \
             refused: denied"
        )
    );
    until("the endpoint's leases let go", || {
        leases.dropped.lock().unwrap().contains(&id)
    })
    .await;
}

/// FR-90 P3-9-2b — the daemon holds a person's endpoint for the LocalAPI
/// connection that opened it: served to the account that asked, on Unix under
/// that account's directory of a runtime root it makes if no session has
/// yet, read by its id, and let go with its leases when that connection
/// closes. A second release finds nothing.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_persons_endpoint_is_held_by_its_id_until_its_connection_lets_go() {
    use super::super::person_connect;
    use super::super::vault_connect::{PersonLeases, Timing as Renewing};
    use crate::vault_proxy::testing::{fake_http, made};
    use tunnel_core::localapi::{Asker, ConnectArgs};
    let token = made();
    let (ca, port, mut saw) = fake_http().await;
    let vault = person_vault(&token, &ca);
    let leases = FakePersonLeases::over(&vault);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("meshharbor-hive");
    #[cfg(unix)]
    let asker = {
        // SAFETY: geteuid and getegid read our own credentials.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Asker::Unix { uid, gid }
    };
    #[cfg(windows)]
    let asker = Asker::Windows { sid: me() };
    let args = ConnectArgs {
        handle: "git/bot".into(),
        engine: "http".into(),
        upstream: format!("https://localhost:{port}"),
        auth: Some("bearer".into()),
        ca: Some("pki/git-ca".into()),
        ttl_s: Some(60),
        ..ConnectArgs::default()
    };
    let (id, answer) = person_connect::open_with(
        Arc::clone(&vault) as Arc<dyn VaultTools>,
        Arc::clone(&leases) as Arc<dyn PersonLeases>,
        &root,
        &asker,
        &args,
        Renewing::DAEMON,
    )
    .await
    .unwrap();
    assert_eq!(answer["id"], json!(id));
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "made as a session's start makes it");
        // SAFETY: geteuid reads our own credentials.
        let uid = unsafe { libc::geteuid() };
        assert!(root.join(format!("person-{uid}")).is_dir());
    }
    let state = person_connect::state(id).expect("held");
    assert!(state.left_s > 0 && state.left_s <= 60, "{state:?}");
    assert_eq!(
        (state.renewals, state.refused, state.closed),
        (0, None, None)
    );
    // It serves the account that asked: this test's.
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let mut h = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    assert_eq!(
        bearer_through(&mut h, &mut saw).await,
        [format!("Bearer {token}")]
    );

    // Its connection closes: let go, its leases with it.
    person_connect::release(id);
    assert_eq!(person_connect::state(id), None);
    until("its leases let go", || {
        leases.dropped.lock().unwrap().contains(&id)
    })
    .await;
    assert!(leases.holding(id).is_empty());
    person_connect::release(id);
}

/// P3-5e-2 — `vault_connect` serves a Kubernetes API server. The secret's
/// cert and key are leased and presented in each connection's handshake,
/// and the answer is a kubeconfig with no credential, naming the endpoint.
/// A request through it reaches the API server with no `Authorization` and
/// no impersonation; `kubectl exec`'s upgrade is joined through it; and the
/// joined stream ends when the lease is let go.
#[cfg(feature = "vault")]
#[tokio::test]
async fn vault_connect_serves_a_kubernetes_api_server() {
    use tokio::io::AsyncReadExt;

    use crate::vault_proxy::testing::fake_http_mtls;
    let mut f = fake_http_mtls().await;
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = http_belt(
        dir.path(),
        &[
            ("k8s/prod#cert", f.cert.as_bytes()),
            ("k8s/prod#key", f.key.as_bytes()),
            ("pki/k8s-ca", f.ca.as_bytes()),
        ],
    );
    let upstream = format!("https://localhost:{}", f.port);
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "k8s/prod",
            "engine": "kubernetes",
            "upstream": upstream,
            "auth": "client-cert",
            "ca": "pki/k8s-ca",
            "ttl_s": 60,
        }),
    )
    .await
    .unwrap();
    assert!(
        !answer.to_string().contains(f.key.trim()),
        "the answer holds no key"
    );
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let uri = format!("http://127.0.0.1:{dial}");
    assert_eq!(answer["uri"], uri);
    let kubeconfig = answer["kubeconfig"].as_str().unwrap();
    assert!(
        kubeconfig.contains(&format!("    server: {uri}\n")),
        "{kubeconfig}"
    );
    assert!(
        kubeconfig.contains("current-context: meshharbor-vault\n")
            && kubeconfig.contains("  user: {}\n"),
        "one context, a user with no credential: {kubeconfig}"
    );
    let mut h = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    h.write_all(
        b"GET /api/v1/namespaces HTTP/1.1\r\nHost: 127.0.0.1\r\nImpersonate-User: admin\r\n\r\n",
    )
    .await
    .unwrap();
    let response = http_response(&mut h).await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let s = tokio::time::timeout(WAIT, f.saw.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.target, "/api/v1/namespaces");
    assert!(
        s.values("authorization").is_empty() && s.values("impersonate-user").is_empty(),
        "the certificate is the handshake's, and nobody is impersonated: {s:?}"
    );
    let mut x = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    x.write_all(
        b"GET /exec HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n",
    )
    .await
    .unwrap();
    let head = http_response(&mut x).await;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    x.write_all(b"stdin").await.unwrap();
    let mut echoed = [0u8; 5];
    tokio::time::timeout(WAIT, x.read_exact(&mut echoed))
        .await
        .expect("an echo within 10 s")
        .unwrap();
    assert_eq!(&echoed, b"stdin");
    let lease = |h: &str| {
        (
            "lease_proxy".to_string(),
            sid,
            5,
            format!("{h} for {upstream} 60s"),
        )
    };
    assert_eq!(
        vault.asked(),
        [
            lease("k8s/prod#cert"),
            lease("k8s/prod#key"),
            lease("pki/k8s-ca")
        ]
    );
    vault.release(&["L1".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(WAIT, x.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the exec stream ended with its lease");
}

/// P3-5e-2 — a cert and key TLS cannot present are refused at the call, and
/// its leases let go; the refusal names neither value.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_certificate_tls_cannot_present_is_refused_at_the_call() {
    use crate::vault_proxy::testing::made;
    let (cert, key) = (made(), made());
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _sid) = http_belt(
        dir.path(),
        &[
            ("k8s/prod#cert", cert.as_bytes()),
            ("k8s/prod#key", key.as_bytes()),
        ],
    );
    let mut c = Client::connect(&b).await;
    let refused = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "k8s/prod",
            "engine": "kubernetes",
            "upstream": "https://k8s.internal:6443",
            "auth": "client-cert",
        }),
    )
    .await
    .unwrap_err();
    assert!(
        refused.contains("not a client certificate TLS can present"),
        "{refused}"
    );
    assert!(
        !refused.contains(&cert) && !refused.contains(&key),
        "the refusal names no value: {refused}"
    );
    assert_eq!(
        *vault.released.lock().unwrap(),
        ["L0", "L1"],
        "its leases let go"
    );
    assert!(vault.stops.lock().unwrap().is_empty(), "no endpoint served");
}

/// P3-5f-2 — one message to the SSH agent on `s`, and its answer: the
/// agent protocol's framing, a length and then the message.
#[cfg(feature = "vault")]
async fn agent_ask<S>(s: &mut S, message: &[u8]) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut framed = u32::try_from(message.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    s.write_all(&framed).await.unwrap();
    let mut len = [0u8; 4];
    tokio::time::timeout(WAIT, s.read_exact(&mut len))
        .await
        .expect("an answer within 10 s")
        .unwrap();
    let mut answer = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut answer).await.unwrap();
    answer
}

/// P3-5f-2 — a `vault_connect` call for an SSH agent toward
/// `ssh://git@build.internal:2222`, the secret's `pem` and `host` in the
/// vault: the answer, checked for what every system answers alike, and the
/// leases it asked for.
#[cfg(feature = "vault")]
async fn ssh_answer(b: &Belt, vault: &FakeVault, sid: ObjectId, pem: &str, host: &str) -> Value {
    let upstream = "ssh://git@build.internal:2222";
    let mut c = Client::connect(b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({"handle": "ssh/deploy", "engine": "ssh", "upstream": upstream, "ttl_s": 60}),
    )
    .await
    .unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    for piece in body.as_bytes().chunks(16).filter(|p| p.len() == 16) {
        assert!(
            !answer
                .to_string()
                .contains(std::str::from_utf8(piece).unwrap()),
            "the answer holds no piece of the key"
        );
    }
    assert_eq!(answer["env"]["SSH_AUTH_SOCK"], answer["host"], "{answer}");
    assert_eq!(answer["uri"], upstream);
    assert_eq!(answer["port"], Value::Null);
    assert_eq!(
        answer["known_hosts"],
        format!("[build.internal]:2222 {host}\n")
    );
    let lease = |h: &str| {
        (
            "lease_proxy".to_string(),
            sid,
            5,
            format!("{h} for {upstream} 60s"),
        )
    };
    assert_eq!(
        vault.asked(),
        [lease("ssh/deploy#key"), lease("ssh/deploy#host_keys")]
    );
    answer
}

/// P3-5f-2 — what the agent answers on `s`: the one key, under the secret's
/// name; a binding to the secret's host, taken; a sign-in as the audience's
/// user signed, and as another refused, so the upstream's user reached it.
#[cfg(feature = "vault")]
async fn the_agent_signs_in_as_git_alone<S>(
    s: &mut S,
    public: &[u8],
    host_pair: &ring::signature::Ed25519KeyPair,
    host_key: &[u8],
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::vault_proxy::testing::strings;
    let mut listed = vec![12, 0, 0, 0, 1];
    listed.extend_from_slice(&u32::try_from(public.len()).unwrap().to_be_bytes());
    listed.extend_from_slice(public);
    listed.extend_from_slice(&10u32.to_be_bytes());
    listed.extend_from_slice(b"ssh/deploy");
    assert_eq!(agent_ask(s, &[11]).await, listed);
    // A binding to the secret's host, as `ssh` sends one after its key
    // exchange: taken.
    let session_id: [u8; 32] = rand::random();
    let mut bind = vec![27];
    bind.extend(strings(&[
        b"session-bind@openssh.com",
        host_key,
        &session_id,
        &strings(&[b"ssh-ed25519", host_pair.sign(&session_id).as_ref()]),
    ]));
    bind.push(0);
    assert_eq!(agent_ask(s, &bind).await, [6], "the binding taken");
    let sign = |user: &[u8]| {
        let mut data = strings(&[&session_id]);
        data.push(50);
        data.extend(strings(&[user, b"ssh-connection", b"publickey"]));
        data.push(1);
        data.extend(strings(&[b"ssh-ed25519", public]));
        let mut m = vec![13];
        m.extend(strings(&[public, &data]));
        m.extend_from_slice(&0u32.to_be_bytes());
        m
    };
    assert_eq!(agent_ask(s, &sign(b"root")).await, [5], "as root");
    assert_eq!(agent_ask(s, &sign(b"git")).await[0], 14, "as git");
}

/// P3-5f-2 — `vault_connect` serves an SSH agent on a socket. It leases the
/// secret's `key` and `host_keys` toward the upstream, and answers the
/// agent's socket in `SSH_AUTH_SOCK` and the hosts' keys as `known_hosts`,
/// with no key in the answer. The agent lists the one key, under the
/// secret's name, takes a binding to the secret's host, and signs a sign-in
/// as the audience's user alone. When a lease goes, the socket goes with
/// every connection it held.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn vault_connect_serves_an_ssh_agent() {
    use tokio::io::AsyncReadExt;

    use crate::vault_proxy::testing::{openssh_key, ssh_host};
    let (pem, public) = openssh_key();
    let (host_pair, host_key, host) = ssh_host();
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = exec_belt(
        dir.path(),
        &[
            ("ssh/deploy#key", pem.as_bytes()),
            ("ssh/deploy#host_keys", host.as_bytes()),
        ],
    );
    let answer = ssh_answer(&b, &vault, sid, &pem, &host).await;
    let socket = answer["host"].as_str().unwrap().to_string();
    assert!(socket.ends_with("/ssh-agent.sock"), "{answer}");
    let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
    the_agent_signs_in_as_git_alone(&mut s, &public, &host_pair, &host_key).await;
    // A lease let go closes the agent, and the connection it held.
    vault.release(&["L0".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(WAIT, s.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the agent's connection ended with its lease");
    assert!(
        tokio::net::UnixStream::connect(&socket).await.is_err(),
        "the socket went with it"
    );
}

/// P3-5f-3 — on Windows the agent is a named pipe, `\\.\pipe\meshharbor-vault-*`,
/// as Win32-OpenSSH dials `SSH_AUTH_SOCK`: the same answer, the same agent,
/// and the pipe gone, with every connection it held, when a lease goes.
#[cfg(all(feature = "vault", windows))]
#[tokio::test]
async fn vault_connect_serves_an_ssh_agent_on_a_named_pipe() {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ClientOptions;

    use crate::vault_proxy::testing::{openssh_key, ssh_host};
    let (pem, public) = openssh_key();
    let (host_pair, host_key, host) = ssh_host();
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, sid) = http_belt(
        dir.path(),
        &[
            ("ssh/deploy#key", pem.as_bytes()),
            ("ssh/deploy#host_keys", host.as_bytes()),
        ],
    );
    let answer = ssh_answer(&b, &vault, sid, &pem, &host).await;
    let name = answer["host"].as_str().unwrap().to_string();
    assert!(name.starts_with(r"\\.\pipe\meshharbor-vault-"), "{answer}");
    let mut s = ClientOptions::new().open(&name).unwrap();
    the_agent_signs_in_as_git_alone(&mut s, &public, &host_pair, &host_key).await;
    // A second connection, while the first holds its instance, finds the
    // next one listening (busy only for as long as it takes to make it).
    let mut t = None;
    for _ in 0..50 {
        match ClientOptions::new().open(&name) {
            Ok(c) => {
                t = Some(c);
                break;
            }
            Err(e) if e.raw_os_error() == Some(231) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("a second connection: {e}"),
        }
    }
    let mut t = t.expect("a second connection within 5 s");
    assert_eq!(
        agent_ask(&mut t, &[11]).await[0],
        12,
        "the key listed to it too"
    );
    // A lease let go closes the agent, and the connections it held.
    vault.release(&["L0".to_string()]);
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(WAIT, s.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the agent's connection ended with its lease");
    let ended = tokio::time::timeout(WAIT, t.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "and the second one");
    // And the pipe with it: no instance left, so its name is gone. (A pipe
    // whose every instance is busy is another error: never taken for gone.)
    let mut gone = false;
    for _ in 0..50 {
        match ClientOptions::new().open(&name) {
            Err(e) if e.raw_os_error() == Some(2) => {
                gone = true;
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(gone, "the pipe went with its lease");
}

/// P3-5f-3 — Windows' own `ssh.exe` (Win32-OpenSSH, 8.9 or later, so it
/// binds) signs in through `vault_connect`'s agent pipe with nothing but the
/// answer: `SSH_AUTH_SOCK`, and `known_hosts` written to a file. The host is
/// russh, in the test, and lets in only the secret's key.
#[cfg(all(feature = "vault", feature = "ssh-server", windows))]
#[tokio::test]
async fn win32_openssh_signs_in_through_vault_connect() {
    use russh::keys::ssh_key;

    use crate::vault_proxy::testing::{WIN32_SSH, openssh_key, present, run_win32_ssh, sshd};
    if !present(WIN32_SSH) {
        return;
    }
    let host_key =
        ssh_key::PrivateKey::from_openssh(crate::ssh::generate_host_key().unwrap()).unwrap();
    let host_line = host_key.public_key().to_openssh().unwrap();
    let (pem, public) = openssh_key();
    let port = sshd(host_key, ssh_key::PublicKey::from_bytes(&public).unwrap()).await;
    let dir = tempfile::tempdir().unwrap();
    let (b, _vault, _sid) = http_belt(
        dir.path(),
        &[
            ("ssh/deploy#key", pem.as_bytes()),
            ("ssh/deploy#host_keys", host_line.as_bytes()),
        ],
    );
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "ssh/deploy",
            "engine": "ssh",
            "upstream": format!("ssh://git@127.0.0.1:{port}"),
        }),
    )
    .await
    .unwrap();
    let known_hosts = dir.path().join("known_hosts");
    std::fs::write(&known_hosts, answer["known_hosts"].as_str().unwrap()).unwrap();
    let empty = dir.path().join("empty_config");
    std::fs::write(&empty, "").unwrap();
    let agent = answer["env"]["SSH_AUTH_SOCK"].as_str().unwrap();
    let out = run_win32_ssh(agent, port, &known_hosts, &empty).await;
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{log}");
    assert!(
        log.contains("bound agent to hostkey"),
        "ssh.exe bound the agent: {log}"
    );
}

/// P3-5f-2 — a key the agent cannot sign with is refused at the call, and
/// its leases let go; the refusal names no byte of the value.
#[cfg(feature = "vault")]
#[tokio::test]
async fn an_ssh_key_the_agent_cannot_sign_with_is_refused_at_the_call() {
    use crate::vault_proxy::testing::{made, ssh_host_line};
    let (key, host) = (made(), ssh_host_line());
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _sid) = http_belt(
        dir.path(),
        &[
            ("ssh/deploy#key", key.as_bytes()),
            ("ssh/deploy#host_keys", host.as_bytes()),
        ],
    );
    let mut c = Client::connect(&b).await;
    let refused = connect_answer(
        &mut c,
        1,
        json!({"handle": "ssh/deploy", "engine": "ssh", "upstream": "ssh://git@build.internal"}),
    )
    .await
    .unwrap_err();
    assert!(
        refused.starts_with("ssh/deploy: key is not an OpenSSH private key"),
        "{refused}"
    );
    assert!(
        !refused.contains(&key),
        "the refusal names no value: {refused}"
    );
    assert_eq!(
        *vault.released.lock().unwrap(),
        ["L0", "L1"],
        "its leases let go"
    );
    assert!(vault.stops.lock().unwrap().is_empty(), "no endpoint served");
}

/// P3-5f-2 — OpenSSH's own `ssh` signs in through `vault_connect`'s agent
/// with nothing but the answer: its `env`, and its `known_hosts` written to a
/// file. The host is russh, in the test, and lets in only the secret's key.
#[cfg(all(feature = "vault", feature = "ssh-server", unix))]
#[tokio::test]
async fn openssh_signs_in_through_vault_connect() {
    use russh::keys::ssh_key;

    use crate::vault_proxy::testing::{openssh_key, present, run_ssh, sshd};
    if !present("ssh") {
        return;
    }
    let host_key =
        ssh_key::PrivateKey::from_openssh(crate::ssh::generate_host_key().unwrap()).unwrap();
    let host_line = host_key.public_key().to_openssh().unwrap();
    let (pem, public) = openssh_key();
    let port = sshd(host_key, ssh_key::PublicKey::from_bytes(&public).unwrap()).await;
    let dir = tempfile::tempdir().unwrap();
    let (b, _vault, _sid) = exec_belt(
        dir.path(),
        &[
            ("ssh/deploy#key", pem.as_bytes()),
            ("ssh/deploy#host_keys", host_line.as_bytes()),
        ],
    );
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "ssh/deploy",
            "engine": "ssh",
            "upstream": format!("ssh://git@127.0.0.1:{port}"),
        }),
    )
    .await
    .unwrap();
    let known_hosts = dir.path().join("known_hosts");
    std::fs::write(&known_hosts, answer["known_hosts"].as_str().unwrap()).unwrap();
    let agent = std::path::PathBuf::from(answer["env"]["SSH_AUTH_SOCK"].as_str().unwrap());
    let out = run_ssh(&agent, port, &known_hosts).await;
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{log}");
    assert!(
        log.contains("bound agent to hostkey"),
        "ssh bound the agent: {log}"
    );
}

/// P3-5d-2 — a value `Authorization` cannot carry is refused at the call,
/// before any endpoint is served, and its lease let go: here a token with a
/// space. The refusal names no value.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_value_authorization_cannot_carry_is_refused_at_the_call() {
    use crate::vault_proxy::testing::made;
    let spaced = format!("{} {}", made(), made());
    let dir = tempfile::tempdir().unwrap();
    let (b, vault, _sid) = http_belt(dir.path(), &[("git/bot#token", spaced.as_bytes())]);
    let mut c = Client::connect(&b).await;
    let refused = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "git/bot",
            "engine": "http",
            "upstream": "https://git.example",
            "auth": "bearer",
        }),
    )
    .await
    .unwrap_err();
    assert!(
        refused.contains("Authorization header can carry"),
        "{refused}"
    );
    assert!(
        !refused.contains(&spaced),
        "the refusal names no value: {refused}"
    );
    assert_eq!(*vault.released.lock().unwrap(), ["L0"], "its lease let go");
    assert!(vault.stops.lock().unwrap().is_empty(), "no endpoint served");
}

/// P3-5d-2 — git goes through an HTTP endpoint by the answer's `env` alone:
/// `git ls-remote <upstream>/<repo>` lists the repository's refs, and the
/// upstream saw git's request carry the secret's user and password, which
/// git never had.
#[cfg(feature = "vault")]
#[tokio::test]
async fn git_goes_through_an_http_endpoint_by_its_env() {
    use base64::Engine as _;

    use crate::vault_proxy::testing::{fake_http, made};
    let password = made();
    let (ca, port, mut saw) = fake_http().await;
    let dir = tempfile::tempdir().unwrap();
    let (b, _vault, _sid) = http_belt(
        dir.path(),
        &[
            ("git/bot#user", b"x-access-token"),
            ("git/bot#password", password.as_bytes()),
            ("pki/git-ca", ca.as_bytes()),
        ],
    );
    let upstream = format!("https://localhost:{port}");
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "git/bot",
            "engine": "http",
            "upstream": upstream,
            "auth": "basic",
            "ca": "pki/git-ca",
        }),
    )
    .await
    .unwrap();
    // git's own configuration, and none of this machine's; run outside any
    // repository, which `ls-remote <url>` needs none of.
    let config = dir.path().join("empty.gitconfig");
    std::fs::write(&config, "").unwrap();
    let mut git = std::process::Command::new("git");
    git.args(["ls-remote", &format!("{upstream}/org/repo.git")])
        .current_dir(dir.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("HOME", dir.path());
    for (k, v) in answer["env"].as_object().unwrap() {
        git.env(k, v.as_str().unwrap());
    }
    let out = tokio::time::timeout(WAIT, tokio::task::spawn_blocking(move || git.output()))
        .await
        .expect("git within 10 s")
        .unwrap()
        .expect("git runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("refs/heads/main"),
        "git ls-remote: {}\n{stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let s = tokio::time::timeout(WAIT, saw.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.target, "/org/repo.git/info/refs?service=git-upload-pack");
    let pair =
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{password}"));
    assert_eq!(s.values("authorization"), [format!("Basic {pair}")]);
}

/// P3-5d-2 — on Linux, a loopback connection from any account but the
/// session's is refused, read from the kernel's table of sockets; on macOS
/// (P3-5d-3), from the descriptors each process holds. Here the session's
/// account is another's, so this test's own connection is the one refused:
/// closed, answered nothing, and nothing sent upstream.
#[cfg(all(feature = "vault", unix))]
#[tokio::test]
async fn an_http_connection_from_another_account_is_refused() {
    use crate::vault_proxy::testing::{fake_http, made};
    let (ca, port, mut saw) = fake_http().await;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(FakeVault {
        values: [
            ("git/bot#token", made().into_bytes()),
            ("pki/git-ca", ca.into_bytes()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        ..FakeVault::default()
    });
    std::fs::create_dir_all(dir.path().join("run")).unwrap();
    // The session runs as an account that is not this test's.
    let other = me().wrapping_add(4242);
    let b = belt_running(
        me(),
        Run {
            session: ObjectId::new(),
            fence: 5,
            vault: Some(vault.clone()),
            net: None,
            #[cfg(feature = "ssh-server")]
            ssh: None,
            exec: Some(super::super::vault_exec::ExecTarget {
                account: None,
                home: dir.path().to_path_buf(),
                folder: dir.path().to_path_buf(),
                session_dir: dir.path().join("run"),
                owner: Some((other, other)),
            }),
        },
        quick(),
    );
    let mut c = Client::connect(&b).await;
    let answer = connect_answer(
        &mut c,
        1,
        json!({
            "handle": "git/bot",
            "engine": "http",
            "upstream": format!("https://localhost:{port}"),
            "auth": "bearer",
            "ca": "pki/git-ca",
        }),
    )
    .await
    .unwrap();
    let dial = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let mut h = tokio::net::TcpStream::connect(("127.0.0.1", dial))
        .await
        .unwrap();
    let _ = h
        .write_all(b"GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await;
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(
        WAIT,
        tokio::io::AsyncReadExt::read_to_end(&mut h, &mut rest),
    )
    .await;
    assert!(ended.is_ok(), "the connection was closed");
    assert!(rest.is_empty(), "and answered nothing: {rest:?}");
    assert!(saw.try_recv().is_err(), "nothing reached the upstream");
}

/// P3-7-3c — the answer to a `net_socks` or `net_forward` call: its JSON,
/// or its error text.
#[cfg(feature = "vault")]
async fn net_answer(c: &mut Client, id: u64, tool: &str, args: Value) -> Result<Value, String> {
    c.send(tool_call(id, tool, args)).await;
    let m = c.recv().await;
    assert_eq!(m["id"], id, "{m}");
    let text = m["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    if m["result"]["isError"] == true {
        Err(text)
    } else {
        Ok(serde_json::from_str(&text).unwrap())
    }
}

/// P3-7-3c — a toolbelt whose device offers its sessions egress: a hub of
/// its own with no agent WS, so a flow holds what it admits and carries
/// nothing.
#[cfg(feature = "vault")]
fn net_belt(
    vault: FakeVault,
    fence: u64,
) -> (
    Belt,
    Arc<FakeVault>,
    ObjectId,
    crate::tunnel::client_mgr::TunnelClientHub,
) {
    let vault = Arc::new(vault);
    let session = ObjectId::new();
    let hub = crate::tunnel::client_mgr::TunnelClientHub::new("test".into());
    let b = belt_running(
        me(),
        Run {
            session,
            fence,
            vault: Some(vault.clone()),
            exec: None,
            net: Some(hub.clone()),
            #[cfg(feature = "ssh-server")]
            ssh: None,
        },
        quick(),
    );
    (b, vault, session, hub)
}

/// P3-7-3c — whether a connection ended: closed by the other end, or
/// refused, within `within`.
#[cfg(feature = "vault")]
async fn ended(s: &mut tokio::net::TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 16];
    matches!(
        tokio::time::timeout(within, tokio::io::AsyncReadExt::read(s, &mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

/// P3-7-3c — whether `port` on loopback is dialled in vain, within `WAIT`:
/// its listener is gone.
#[cfg(feature = "vault")]
async fn nothing_listens_on(port: u16) -> bool {
    for _ in 0..40 {
        match tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(("127.0.0.1", port))).await
        {
            Ok(Err(_)) => return true,
            Ok(Ok(s)) => drop(s),
            Err(_) => return false,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// P3-7-3c — `net_socks` and `net_forward` are offered where the device's
/// owner offers its sessions egress and the vault is offered, and nowhere
/// else: elsewhere they are unknown tools, and the vault is asked nothing.
/// Their settings names are the names offered, under the `meshharbor` server.
#[cfg(feature = "vault")]
#[tokio::test]
async fn the_net_tools_are_offered_only_where_the_owner_offers_egress() {
    let names = |list: &Value| -> Vec<String> {
        list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let vault = Arc::new(FakeVault::default());
    let hub = crate::tunnel::client_mgr::TunnelClientHub::new("test".into());
    // The vault without egress, and egress without the vault.
    let offers: [(Option<Arc<dyn VaultTools>>, _); 2] =
        [(Some(vault.clone()), None), (None, Some(hub.clone()))];
    for (offered, net) in offers {
        let b = belt_running(
            me(),
            Run {
                session: ObjectId::new(),
                fence: 1,
                vault: offered,
                exec: None,
                net,
                #[cfg(feature = "ssh-server")]
                ssh: None,
            },
            quick(),
        );
        let mut c = Client::connect(&b).await;
        c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
            .await;
        let listed = names(&c.recv().await);
        assert!(!listed.iter().any(|n| n.starts_with("net_")), "{listed:?}");
        for (id, tool) in [(2, "net_socks"), (3, "net_forward")] {
            c.send(tool_call(
                id,
                tool,
                json!({"exit": ObjectId::new().to_hex()}),
            ))
            .await;
            assert_eq!(c.recv().await["error"]["code"], -32602, "not offered here");
        }
    }
    assert!(vault.nets.lock().unwrap().is_empty(), "nothing asked");
    assert!(hub.flows_snapshot().is_empty(), "nothing opened");

    let (b, vault, _, _) = net_belt(FakeVault::default(), 1);
    let mut c = Client::connect(&b).await;
    c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
        .await;
    let list = c.recv().await;
    let listed = names(&list);
    let net = &listed[listed.len() - 2..];
    assert_eq!(net, ["net_socks", "net_forward"], "{list}");
    let tools = list["result"]["tools"].as_array().unwrap();
    for t in &tools[tools.len() - 2..] {
        assert_eq!(t["annotations"]["readOnlyHint"], false, "{t}");
        assert_eq!(t["annotations"]["openWorldHint"], true, "{t}");
    }
    assert_eq!(
        tools[tools.len() - 1]["inputSchema"]["required"],
        json!(["exit", "host", "port"]),
        "{list}"
    );
    let named: Vec<String> = net.iter().map(|n| format!("mcp__meshharbor__{n}")).collect();
    assert_eq!(
        named, NET_TOOLS,
        "what the settings ask a person about is what is offered"
    );
    assert!(
        vault.nets.lock().unwrap().is_empty(),
        "listing the tools asks the vault nothing"
    );
}

/// P3-7-3c — `net_socks` asks the vault for the session's run, serves a
/// SOCKS5 proxy on loopback whose URL carries the session's id and a
/// capability made for that listener, and holds a connection from the
/// session's account. The answer carries no grant token, and the tool opens
/// no approval of its own: the harness asked one before calling it. When
/// the run ends here, its listeners end, and every connection they held.
#[cfg(feature = "vault")]
#[tokio::test]
async fn net_socks_serves_a_proxy_for_the_sessions_run_until_it_ends() {
    use super::super::net_tools::{DEFAULT_TTL_SECS, drop_run};
    let (mut b, vault, sid, hub) = net_belt(FakeVault::default(), 3);
    let exit = ObjectId::new();
    let mut c = Client::connect(&b).await;
    let answer = net_answer(
        &mut c,
        1,
        "net_socks",
        json!({"exit": exit.to_hex(), "ttl_s": 60}),
    )
    .await
    .unwrap();
    assert_eq!(
        *vault.nets.lock().unwrap(),
        [crate::vault::NetAsk {
            session_id: sid,
            fence: 3,
            exit,
            dst: None,
            ttl_secs: 60,
        }]
    );
    assert_eq!(answer["host"], "127.0.0.1");
    let port = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let proxy = answer["proxy"].as_str().unwrap();
    let (user, rest) = proxy
        .strip_prefix("socks5h://")
        .and_then(|p| p.split_once(':'))
        .unwrap();
    let (capability, at) = rest.split_once('@').unwrap();
    assert_eq!(user, sid.to_hex(), "the session's id: {proxy}");
    assert_eq!(capability.len(), 64, "{proxy}");
    assert!(capability.bytes().all(|b| b.is_ascii_hexdigit()), "{proxy}");
    assert_eq!(at, format!("127.0.0.1:{port}"));
    let expires = answer["expires_in_secs"].as_u64().unwrap();
    assert!((58..=60).contains(&expires), "{answer}");
    assert!(
        !answer.to_string().contains("grant-of-"),
        "the grant's token stays on the device: {answer}"
    );
    assert!(
        b.events.try_recv().is_err(),
        "the tool opens no approval of its own"
    );
    // The flow is the hub's, shown without its credential.
    let shown = hub.flows_snapshot();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].local_addr, format!("127.0.0.1:{port}"));
    assert!(
        !format!("{shown:?}").contains(capability),
        "the capability is not shown: {shown:?}"
    );

    // The session's account is admitted, and held: no carrier here.
    let mut held = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    assert!(
        !ended(&mut held, Duration::from_millis(300)).await,
        "held open"
    );

    // Another listener, with a capability of its own and the default time.
    let again = net_answer(&mut c, 2, "net_socks", json!({"exit": exit.to_hex()}))
        .await
        .unwrap();
    assert_ne!(again["proxy"], answer["proxy"]);
    assert_eq!(vault.nets.lock().unwrap()[1].ttl_secs, DEFAULT_TTL_SECS);

    // The run ends here: both listeners end, and what they held.
    assert_eq!(drop_run(sid, 3), 2);
    assert!(ended(&mut held, WAIT).await, "the held connection ended");
    assert!(nothing_listens_on(port).await, "the listener is gone");
    assert!(hub.flows_snapshot().is_empty());
    assert_eq!(drop_run(sid, 3), 0, "nothing left to end");
}

/// P3-7-3c — `net_forward` asks for the destination as the session names
/// it, and serves the one the vault granted, in the vault's spelling; its
/// answer is an address, with no credential.
#[cfg(feature = "vault")]
#[tokio::test]
async fn net_forward_serves_the_one_destination_the_vault_granted() {
    let (b, vault, sid, hub) = net_belt(FakeVault::default(), 4);
    let exit = ObjectId::new();
    let mut c = Client::connect(&b).await;
    let answer = net_answer(
        &mut c,
        1,
        "net_forward",
        json!({"exit": exit.to_hex(), "host": "DB.Internal.", "port": 5432}),
    )
    .await
    .unwrap();
    assert_eq!(
        vault.nets.lock().unwrap()[0].dst,
        Some(("DB.Internal.".to_string(), 5432))
    );
    assert_eq!(answer["destination"], "db.internal:5432");
    let port = answer["port"].as_u64().unwrap();
    assert_eq!(answer["address"], format!("127.0.0.1:{port}"));
    assert!(answer.get("proxy").is_none(), "{answer}");
    let shown = hub.flows_snapshot();
    assert_eq!(shown[0].target.as_deref(), Some("db.internal:5432"));
    assert_eq!(super::super::net_tools::drop_run(sid, 4), 1);
}

/// P3-7-3c — a refusal from the vault opens no listener and is the
/// session's answer; a call the device refuses asks the vault nothing.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_refused_net_call_opens_no_listener() {
    let (b, vault, sid, hub) = net_belt(
        FakeVault {
            net_refusal: Some("the vault refused: no_role".into()),
            ..FakeVault::default()
        },
        5,
    );
    let exit = ObjectId::new().to_hex();
    let mut c = Client::connect(&b).await;
    assert_eq!(
        net_answer(&mut c, 1, "net_socks", json!({"exit": exit})).await,
        Err("the vault refused: no_role".into())
    );
    assert!(hub.flows_snapshot().is_empty(), "no listener");
    for (id, tool, bad) in [
        (2, "net_socks", json!({})),
        (3, "net_socks", json!({"exit": "mars"})),
        (4, "net_forward", json!({"exit": exit, "port": 5432})),
        (
            5,
            "net_forward",
            json!({"exit": exit, "host": "db", "port": 0}),
        ),
    ] {
        assert!(net_answer(&mut c, id, tool, bad).await.is_err());
    }
    assert_eq!(vault.nets.lock().unwrap().len(), 1, "nothing more asked");
    assert_eq!(super::super::net_tools::drop_run(sid, 5), 0);
}

/// P3-7-3c — a run holds a bounded number of listeners: one more is refused
/// before the vault is asked, and a listener that ended (its grant's end,
/// a refusal) gives its place back.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_run_holds_a_bounded_number_of_net_listeners() {
    use super::super::net_tools::{MAX_FLOWS, drop_run};
    let (b, vault, sid, hub) = net_belt(FakeVault::default(), 6);
    let exit = ObjectId::new().to_hex();
    let mut c = Client::connect(&b).await;
    let mut first = None;
    for id in 0..MAX_FLOWS as u64 {
        let answer = net_answer(&mut c, id, "net_socks", json!({"exit": exit}))
            .await
            .unwrap();
        first.get_or_insert(answer["port"].as_u64().unwrap());
    }
    let refused = net_answer(
        &mut c,
        100,
        "net_forward",
        json!({"exit": exit, "host": "db", "port": 22}),
    )
    .await
    .unwrap_err();
    assert!(refused.contains("egress listeners already"), "{refused}");
    assert_eq!(vault.nets.lock().unwrap().len(), MAX_FLOWS, "nothing asked");
    // The first one ends as the hub ends a flow at its grant's end.
    let first = format!("127.0.0.1:{}", first.unwrap());
    let flow = hub
        .flows_snapshot()
        .into_iter()
        .find(|f| f.local_addr == first)
        .unwrap();
    assert!(hub.kill_flow(&flow.id));
    net_answer(
        &mut c,
        101,
        "net_forward",
        json!({"exit": exit, "host": "db", "port": 22}),
    )
    .await
    .expect("its place is given back");
    assert_eq!(drop_run(sid, 6), MAX_FLOWS);
}

/// P3-7-3c — a connection from any account but the session's is closed at
/// once, while the listener lives on: here the session's account is
/// another's, so this test's own connection is the one refused.
#[cfg(feature = "vault")]
#[tokio::test]
async fn a_net_connection_from_another_account_is_refused() {
    let vault = FakeVault::default();
    let hub = crate::tunnel::client_mgr::TunnelClientHub::new("test".into());
    #[cfg(unix)]
    let other = me().wrapping_add(4242);
    // SYSTEM, unless this test is SYSTEM: then LOCAL SERVICE.
    #[cfg(windows)]
    let other = match me().as_str() {
        "S-1-5-18" => "S-1-5-19",
        _ => "S-1-5-18",
    }
    .to_string();
    let sid = ObjectId::new();
    let answer = super::super::net_tools::call(
        "net_socks",
        &vault,
        &hub,
        sid,
        7,
        other,
        &json!({"exit": ObjectId::new().to_hex()}),
    )
    .await
    .unwrap();
    let port = u16::try_from(answer["port"].as_u64().unwrap()).unwrap();
    let mut refused = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    assert!(
        ended(&mut refused, WAIT).await,
        "a connection from another account is closed"
    );
    assert_eq!(hub.flows_snapshot().len(), 1, "the listener lives on");
    assert_eq!(super::super::net_tools::drop_run(sid, 7), 1);
}

/// FR-90 P3-8-2b-2 — one run the stand-in was asked for: the target, the
/// ticket's id and text, the command, the timeout.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
type AskedRun = (ObjectId, String, String, String, Duration);

/// FR-90 P3-8-2b-2 — what a toolbelt's `ssh_run` runs on, if anything.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
type Runner = Option<Arc<dyn super::super::ssh_tools::SshRunner>>;

/// FR-90 P3-8-2b-2 — a stand-in for the daemon's SSH client: what it was
/// asked to run, and its word when it fails.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
#[derive(Default)]
struct FakeSsh {
    ran: std::sync::Mutex<Vec<AskedRun>>,
    failure: Option<String>,
}

#[cfg(all(feature = "vault", feature = "ssh-server"))]
#[async_trait::async_trait]
impl super::super::ssh_tools::SshRunner for FakeSsh {
    async fn run(
        &self,
        target: ObjectId,
        ticket: &crate::vault::SshTicket,
        command: &str,
        timeout: Duration,
    ) -> Result<super::super::ssh_tools::Ran, String> {
        self.ran.lock().unwrap().push((
            target,
            ticket.ticket_id.clone(),
            ticket.ticket.clone(),
            command.to_string(),
            timeout,
        ));
        if let Some(why) = &self.failure {
            return Err(why.clone());
        }
        Ok(super::super::ssh_tools::Ran {
            exit_code: Some(3),
            stdout: "out\n".into(),
            stderr: "err\n".into(),
            truncated: true,
        })
    }
}

/// FR-90 P3-8-2b-2 — a toolbelt whose device offers its sessions `ssh_run`.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
fn ssh_belt(vault: FakeVault, ssh: FakeSsh) -> (Belt, Arc<FakeVault>, Arc<FakeSsh>, ObjectId) {
    let vault = Arc::new(vault);
    let ssh = Arc::new(ssh);
    let session = ObjectId::new();
    let b = belt_running(
        me(),
        Run {
            session,
            fence: 4,
            vault: Some(vault.clone()),
            exec: None,
            net: None,
            ssh: Some(ssh.clone()),
        },
        quick(),
    );
    (b, vault, ssh, session)
}

/// FR-90 P3-8-2b-2 — `ssh_run` is offered where the device's owner offers it
/// and the vault is offered, and nowhere else: elsewhere it is an unknown
/// tool, and nothing is asked or run. Its settings name is the name offered.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
#[tokio::test]
async fn ssh_run_is_offered_only_where_the_owner_offers_it() {
    let names = |list: &Value| -> Vec<String> {
        list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let vault = Arc::new(FakeVault::default());
    let ssh = Arc::new(FakeSsh::default());
    // The vault without SSH, and SSH without the vault.
    let offers: [(Option<Arc<dyn VaultTools>>, Runner); 2] =
        [(Some(vault.clone()), None), (None, Some(ssh.clone()))];
    for (offered, runner) in offers {
        let b = belt_running(
            me(),
            Run {
                session: ObjectId::new(),
                fence: 1,
                vault: offered,
                exec: None,
                net: None,
                ssh: runner,
            },
            quick(),
        );
        let mut c = Client::connect(&b).await;
        c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
            .await;
        let listed = names(&c.recv().await);
        assert!(!listed.iter().any(|n| n == "ssh_run"), "{listed:?}");
        let args = json!({"device": ObjectId::new().to_hex(), "command": "uptime"});
        c.send(tool_call(2, "ssh_run", args)).await;
        assert_eq!(c.recv().await["error"]["code"], -32602, "not offered here");
    }
    assert!(vault.sshs.lock().unwrap().is_empty(), "nothing asked");
    assert!(ssh.ran.lock().unwrap().is_empty(), "nothing run");

    let (b, vault, _, _) = ssh_belt(FakeVault::default(), FakeSsh::default());
    let mut c = Client::connect(&b).await;
    c.send(json!({"method": "tools/list", "jsonrpc": "2.0", "id": 1}))
        .await;
    let list = c.recv().await;
    let listed = names(&list);
    assert_eq!(listed.last().map(String::as_str), Some("ssh_run"), "{list}");
    let tool = list["result"]["tools"].as_array().unwrap().last().unwrap();
    assert_eq!(
        tool["inputSchema"]["required"],
        json!(["device", "command"]),
        "{tool}"
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["timeout_s"]["maximum"],
        300
    );
    assert_eq!(tool["annotations"]["readOnlyHint"], false, "{tool}");
    assert_eq!(tool["annotations"]["destructiveHint"], true, "{tool}");
    assert_eq!(
        [format!("mcp__meshharbor__{}", listed.last().unwrap())],
        SSH_TOOLS,
        "what the settings ask a person about is what is offered"
    );
    assert!(
        vault.sshs.lock().unwrap().is_empty(),
        "listing the tools asks the vault nothing"
    );
}

/// FR-90 P3-8-2b-2 — `ssh_run` asks the vault for a ticket for the session's
/// run toward the device it names, lasting the server's answer, the target's
/// prompt and the command; hands that ticket and the command, as written, to
/// the daemon's client; and answers what ran, naming the ticket by its id
/// alone. It opens no approval of its own: the harness asked one before
/// calling it.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
#[tokio::test]
async fn ssh_run_runs_the_one_command_under_the_vaults_ticket() {
    let (mut b, vault, ssh, session) = ssh_belt(FakeVault::default(), FakeSsh::default());
    let mut c = Client::connect(&b).await;
    let target = ObjectId::new();
    let command = "Get-Service meshharbor* | Format-Table -Auto";
    let args = json!({"device": target.to_hex(), "command": command, "timeout_s": 90});
    let answer = net_answer(&mut c, 2, "ssh_run", args).await.unwrap();
    assert_eq!(
        answer,
        json!({
            "device": target.to_hex(),
            "os": "linux",
            "account": "named",
            "ticket_id": "t1",
            "exit_code": 3,
            "stdout": "out\n",
            "stderr": "err\n",
            "truncated": true,
        })
    );
    assert!(
        !answer.to_string().contains("ticket-of-"),
        "the ticket never reaches the session: {answer}"
    );
    let lasts = crate::ssh_client::ASK_WAIT.as_secs() + crate::ssh_client::PROMPT_SECS + 90;
    assert_eq!(
        vault.sshs.lock().unwrap().clone(),
        [crate::vault::SshAsk {
            session_id: session,
            fence: 4,
            target,
            ttl_secs: u32::try_from(lasts).unwrap(),
        }]
    );
    assert_eq!(
        ssh.ran.lock().unwrap().clone(),
        [(
            target,
            "t1".to_string(),
            format!("ticket-of-{session}"),
            command.to_string(),
            Duration::from_secs(90),
        )]
    );
    assert!(b.events.try_recv().is_err(), "no approval of its own");
}

/// FR-90 P3-8-2b-2 — a call the tool refuses asks the vault nothing; the
/// vault's refusal is its own word and runs nothing; and a run that fails
/// says why, in the client's words.
#[cfg(all(feature = "vault", feature = "ssh-server"))]
#[tokio::test]
async fn a_refused_ssh_run_runs_nothing() {
    let target = ObjectId::new().to_hex();
    let (b, vault, ssh, _) = ssh_belt(FakeVault::default(), FakeSsh::default());
    let mut c = Client::connect(&b).await;
    let two_lines = json!({"device": target, "command": "uptime\nreboot"});
    let e = net_answer(&mut c, 2, "ssh_run", two_lines)
        .await
        .unwrap_err();
    assert!(e.contains("not one this tool runs"), "{e}");
    let too_long = json!({"device": target, "command": "uptime", "timeout_s": 301});
    let e = net_answer(&mut c, 3, "ssh_run", too_long)
        .await
        .unwrap_err();
    assert!(e.contains("1 to 300"), "{e}");
    assert!(
        vault.sshs.lock().unwrap().is_empty(),
        "the vault was asked nothing"
    );
    assert!(ssh.ran.lock().unwrap().is_empty());

    let refusing = FakeVault {
        ssh_refusal: Some("the vault refused: denied".into()),
        ..FakeVault::default()
    };
    let (b, vault, ssh, _) = ssh_belt(refusing, FakeSsh::default());
    let mut c = Client::connect(&b).await;
    let args = json!({"device": target, "command": "uptime"});
    let e = net_answer(&mut c, 2, "ssh_run", args.clone())
        .await
        .unwrap_err();
    assert_eq!(e, "the vault refused: denied");
    assert_eq!(vault.sshs.lock().unwrap().len(), 1);
    assert!(
        ssh.ran.lock().unwrap().is_empty(),
        "a refused ticket runs nothing"
    );

    let failing = FakeSsh {
        failure: Some("the server refused the session: session_not_allowed".into()),
        ..FakeSsh::default()
    };
    let (b, _, ssh, _) = ssh_belt(FakeVault::default(), failing);
    let mut c = Client::connect(&b).await;
    let e = net_answer(&mut c, 2, "ssh_run", args).await.unwrap_err();
    assert_eq!(e, "the server refused the session: session_not_allowed");
    assert_eq!(ssh.ran.lock().unwrap().len(), 1);
}

/// More open approvals than Claude Code ever asks for, and a question the
/// surface cannot show, are refused at once — nothing is opened for them.
#[tokio::test]
async fn too_many_approvals_and_structured_questions_are_refused_at_once() {
    let mut b = belt(quick());
    let mut c = Client::connect(&b).await;
    for id in 0..MAX_PENDING as u64 {
        c.send(call(10 + id, "Bash", json!({"command": "true"})))
            .await;
        opened(&mut b).await;
    }
    c.send(call(99, "Bash", json!({"command": "true"}))).await;
    let v = c.verdict(99).await;
    assert_eq!(v["behavior"], "deny");
    assert!(v["message"].as_str().unwrap().contains("Too many"), "{v}");

    c.send(call(
        100,
        "AskUserQuestion",
        json!({"questions": [{"question": "Which?"}]}),
    ))
    .await;
    let v = c.verdict(100).await;
    assert_eq!(v["behavior"], "deny");
    assert!(v["message"].as_str().unwrap().contains("plain text"), "{v}");
    assert_eq!(b.toolbelt.pending().ids().len(), MAX_PENDING);
}

/// The relay is a pipe: a message in, the daemon's answer out, and it ends
/// when the harness closes its side.
#[tokio::test]
async fn the_relay_pipes_both_ways_and_ends_with_the_harness() {
    let b = belt(quick());
    let (mut harness_in, relay_in) = tokio::io::duplex(1024);
    let (relay_out, harness_out) = tokio::io::duplex(1024);
    let socket = b.toolbelt.socket().to_path_buf();
    let relay = tokio::spawn(async move { relay_io(&socket, relay_in, relay_out).await });
    harness_in
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
        .await
        .unwrap();
    let mut lines = BufReader::new(harness_out).lines();
    let answer = tokio::time::timeout(WAIT, lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&answer).unwrap()["id"], 1);
    drop(harness_in);
    tokio::time::timeout(WAIT, relay)
        .await
        .expect("the relay ends with the harness")
        .unwrap()
        .unwrap();

    // Nothing to relay to is an error the harness sees, never a silent pipe.
    #[cfg(unix)]
    let nowhere = Path::new("/nonexistent/toolbelt.sock");
    #[cfg(windows)]
    let nowhere = Path::new(r"\\.\pipe\meshharbor-hive-nowhere");
    let gone = relay_io(nowhere, tokio::io::empty(), tokio::io::sink()).await;
    assert!(gone.is_err());
}

/// FR-90 P3-4e-2 — what the model is told when a lease needed a person: a
/// card nobody answered in time names its approval and says to ask again
/// once someone can answer it; a `denied` says a driver may have said no.
#[cfg(feature = "vault")]
#[test]
fn a_tool_says_plainly_what_an_approval_came_to() {
    use crate::vault::LeaseError;
    let waited = vault_why(LeaseError::AwaitingApproval("A1".into()));
    assert!(waited.contains("approval A1"), "{waited}");
    assert!(waited.contains("nobody answered"), "{waited}");
    let no = vault_why(LeaseError::Refused("denied".into()));
    assert!(no.contains("said no"), "{no}");
    assert_eq!(
        vault_why(LeaseError::Refused("no_role".into())),
        "the vault refused: no_role"
    );
    assert_eq!(APPROVAL_WINDOW, Duration::from_secs(600));
}
