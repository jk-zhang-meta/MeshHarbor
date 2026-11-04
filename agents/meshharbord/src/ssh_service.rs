// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-105 — meshharbor SSH through a Windows device's SYSTEM service
//! (`docs/fr/FR-105-meshharbor-ssh-as-system.md`).
//!
//! On an attended install the worker, the process that holds the overlay and
//! intercepts the SSH port, runs as the signed-in user, and every input its own
//! SSH server reads (the grant table, the host key, `ssh_authorized_keys`,
//! the forward allowlist) is that user's to write. Harmless while a session
//! runs as that user; an escalation once one runs as SYSTEM. So a session that
//! runs through the service never has its transport terminate in the worker:
//!
//! - **Port 2223** ([`ssh_limits::SERVICE_PORT`]) is the service's. The worker
//!   intercepts it beside its own 2222 and carries each connection, byte for
//!   byte, to [`PIPE_NAME`] ([`splice_framed`]). It carries ciphertext only:
//!   the session's keys live in the service, so a worker that reads, drops or
//!   rewrites bytes breaks the session and learns nothing.
//! - **The grant is pulled, never relayed.** The worker rings the doorbell with
//!   a grant id (`DoorbellRequest::SshGrant`); the service claims the grant
//!   from the server with its own credential and holds it in its own table
//!   (`claim_grant`). A forged ring claims nothing the server did not mint
//!   for this device.
//! - **The host key is the service's**, beside the anchor and as private, and
//!   the service publishes it with its own credential (`svc::publish_once`).
//!   A caller pins it from the grant response, so a worker that answered on
//!   2223 itself could not complete a handshake.
//! - **The person still consents**, at their screen. The service asks the
//!   worker that carried the connection, over the same pipe ([`Frame::Ask`]),
//!   and the worker asks exactly as it does for a session of its own. A
//!   worker that answers "yes" itself lets through only a session the server
//!   already granted.
//!
//! What a session here may run as is the anchor's `ssh` ceiling (the machine
//! administrator's), never anything the signed-in user wrote. Refused here in
//! v1: `ssh_authorized_keys` sessions and `direct-tcpip` forwards, whose inputs
//! are the user's to edit.
//!
//! The pipe carries frames, not raw bytes, so the consent questions can share
//! it with the session: a kind byte, a big-endian `u32` length, then the
//! payload (raw for [`Frame::Data`], JSON for the rest).
//!
//! [`ssh_limits::SERVICE_PORT`]: meshharbor_remote_control::models::ssh_limits::SERVICE_PORT

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};

/// The SSH pipe. One per machine, like the doorbell, and made with its DACL.
pub const PIPE_NAME: &str = r"\\.\pipe\meshharbor-ssh-service";

/// `MESHHARBORD_SSH_VIA_SERVICE=0` (or `false`/`off`/`no`) withdraws `ssh-system`
/// from every connection, so the server routes no SSH grant to the service,
/// and the worker refuses one that arrives anyway.
pub const KILL_SWITCH_ENV: &str = "MESHHARBORD_SSH_VIA_SERVICE";

/// The largest [`Frame::Data`] payload. A peer that announces more is cut off
/// unread.
pub const MAX_DATA: usize = 64 * 1024;
/// The largest control payload ([`Frame::Hello`], [`Frame::Ask`],
/// [`Frame::Answer`]).
const MAX_CONTROL: usize = 4 * 1024;

const KIND_HELLO: u8 = 1;
const KIND_DATA: u8 = 2;
const KIND_EOF: u8 = 3;
const KIND_ASK: u8 = 4;
const KIND_ANSWER: u8 = 5;

/// Frames queued for one pipe's writer.
const OUT_QUEUE: usize = 64;
/// How long the service waits for the worker's [`Frame::Hello`].
const HELLO_WAIT: Duration = Duration::from_secs(5);
/// How much longer than the person's own window the service waits for the
/// worker's answer: the worker may first start the desktop companion.
const ANSWER_GRACE: Duration = Duration::from_secs(20);
/// The longest refusal reason relayed to a caller's terminal.
const MAX_REASON: usize = 400;

/// One frame on the SSH pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Worker → service, first and once.
    Hello(Hello),
    /// SSH transport bytes, either way. Ciphertext: the worker holds no key.
    Data(Vec<u8>),
    /// The sender will send no more `Data`.
    Eof,
    /// Service → worker: ask the person at this device.
    Ask(ConsentAsk),
    /// Worker → service: the person's answer.
    Answer(ConsentAnswer),
}

impl Frame {
    fn name(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::Data(_) => "data",
            Self::Eof => "eof",
            Self::Ask(_) => "ask",
            Self::Answer(_) => "answer",
        }
    }
}

/// The worker's opening frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The caller's overlay address, as the worker saw it: a claim by a
    /// process the signed-in user owns, logged and never trusted for
    /// anything. Who the caller is comes from the grant.
    pub peer: String,
}

/// The service's question for the person at the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentAsk {
    /// Matches the answer to the question; per connection.
    pub id: u32,
    /// The grant id, which the person's decision is filed under.
    pub sentinel: String,
    /// Who asks, from the server's grant.
    pub caller: String,
    /// "open an interactive shell", "run a command", "transfer files over
    /// SFTP".
    pub what: String,
    /// The person's window, in seconds.
    pub timeout_secs: u64,
}

/// The person's answer, through the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentAnswer {
    pub id: u32,
    pub granted: bool,
    /// Why not, for the caller's terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

fn from_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], what: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("an SSH pipe {what} frame: {e}"))
}

/// Write one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<(), String> {
    let (kind, payload): (u8, std::borrow::Cow<'_, [u8]>) = match frame {
        Frame::Hello(h) => (KIND_HELLO, to_json(h)?.into()),
        Frame::Data(d) => (KIND_DATA, d.as_slice().into()),
        Frame::Eof => (KIND_EOF, (&[][..]).into()),
        Frame::Ask(a) => (KIND_ASK, to_json(a)?.into()),
        Frame::Answer(a) => (KIND_ANSWER, to_json(a)?.into()),
    };
    let limit = if kind == KIND_DATA {
        MAX_DATA
    } else {
        MAX_CONTROL
    };
    if payload.len() > limit {
        return Err(format!(
            "an SSH pipe {} frame of {} bytes (the most is {limit})",
            frame.name(),
            payload.len()
        ));
    }
    let mut header = [0u8; 5];
    header[0] = kind;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    let io = |e: std::io::Error| format!("writing the SSH pipe: {e}");
    w.write_all(&header).await.map_err(io)?;
    w.write_all(&payload).await.map_err(io)?;
    w.flush().await.map_err(io)
}

/// Read one frame. `Ok(None)` = the other end closed between frames; inside a
/// frame, a close is an error. Anything malformed or oversized is an error,
/// unread past its header.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>, String> {
    let io = |e: std::io::Error| format!("reading the SSH pipe: {e}");
    let mut header = [0u8; 5];
    if r.read(&mut header[..1]).await.map_err(io)? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut header[1..]).await.map_err(io)?;
    let kind = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let limit = match kind {
        KIND_DATA => MAX_DATA,
        KIND_HELLO | KIND_EOF | KIND_ASK | KIND_ANSWER => MAX_CONTROL,
        other => return Err(format!("an SSH pipe frame of unknown kind {other}")),
    };
    if len > limit {
        return Err(format!(
            "an SSH pipe frame of {len} bytes (the most is {limit})"
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.map_err(io)?;
    Ok(Some(match kind {
        KIND_HELLO => Frame::Hello(from_json(&payload, "hello")?),
        KIND_DATA => Frame::Data(payload),
        KIND_EOF if payload.is_empty() => Frame::Eof,
        KIND_EOF => return Err("an SSH pipe eof frame with a payload".into()),
        KIND_ASK => Frame::Ask(from_json(&payload, "ask")?),
        _ => Frame::Answer(from_json(&payload, "answer")?),
    }))
}

/// Write every frame `rx` yields until it closes or the pipe fails, then
/// close the pipe's write side.
async fn write_frames<W: AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::Receiver<Frame>) {
    while let Some(frame) = rx.recv().await {
        if let Err(e) = write_frame(&mut w, &frame).await {
            tracing::debug!(%e, "ssh-service: the SSH pipe stopped taking frames");
            break;
        }
    }
    let _ = w.shutdown().await;
}

/// A refusal reason as a caller's terminal may show it: no control characters
/// (a terminal escape from a process the signed-in user owns must not reach
/// the caller's screen) and at most [`MAX_REASON`] characters.
pub fn clean_reason(reason: &str) -> String {
    let mut out: String = reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON)
        .collect();
    if reason.chars().count() > MAX_REASON {
        out.push('…');
    }
    out
}

/// What a connection's relay says when its worker went away mid-question.
const WORKER_GONE: &str = "the connection to the person at this device closed before they answered";

/// The SYSTEM service's way to ask the person at the device: through the
/// worker that carried this connection. One per connection; cheap to clone.
#[derive(Clone)]
pub struct ConsentRelay {
    out: mpsc::Sender<Frame>,
    inner: Arc<RelayInner>,
}

struct RelayInner {
    next: AtomicU32,
    waiting: std::sync::Mutex<std::collections::HashMap<u32, oneshot::Sender<ConsentAnswer>>>,
    closed: AtomicBool,
}

impl ConsentRelay {
    /// A relay whose questions go out through `out`, the pipe's writer.
    pub fn new(out: mpsc::Sender<Frame>) -> Self {
        Self {
            out,
            inner: Arc::new(RelayInner {
                next: AtomicU32::new(1),
                waiting: std::sync::Mutex::new(std::collections::HashMap::new()),
                closed: AtomicBool::new(false),
            }),
        }
    }

    fn waiting(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<u32, oneshot::Sender<ConsentAnswer>>>
    {
        self.inner.waiting.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Ask the person, and wait for the answer. `Err` is what the caller's
    /// terminal is told: the worker's reason, cleaned, or why no answer came.
    pub async fn ask(
        &self,
        sentinel: &str,
        caller: &str,
        what: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let id = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut waiting = self.waiting();
            if self.inner.closed.load(Ordering::SeqCst) {
                return Err(WORKER_GONE.into());
            }
            waiting.insert(id, tx);
        }
        let ask = ConsentAsk {
            id,
            sentinel: sentinel.to_string(),
            caller: caller.to_string(),
            what: what.to_string(),
            timeout_secs: timeout.as_secs(),
        };
        if self.out.send(Frame::Ask(ask)).await.is_err() {
            self.waiting().remove(&id);
            return Err(WORKER_GONE.into());
        }
        match tokio::time::timeout(timeout + ANSWER_GRACE, rx).await {
            Ok(Ok(answer)) if answer.granted => Ok(()),
            Ok(Ok(answer)) => {
                Err(answer
                    .reason
                    .as_deref()
                    .map(clean_reason)
                    .unwrap_or_else(|| {
                        "the person at this device did not approve this session".to_string()
                    }))
            }
            Ok(Err(_)) => Err(WORKER_GONE.into()),
            Err(_) => {
                self.waiting().remove(&id);
                Err(format!(
                    "no answer from the person at this device within {}s",
                    (timeout + ANSWER_GRACE).as_secs()
                ))
            }
        }
    }

    /// An answer arrived: hand it to whoever asked. `false` = nobody was
    /// waiting on that id (late, or never asked), and it is dropped.
    pub fn answer(&self, answer: ConsentAnswer) -> bool {
        match self.waiting().remove(&answer.id) {
            Some(tx) => tx.send(answer).is_ok(),
            None => false,
        }
    }

    /// The worker is gone: every question still waiting is refused, and any
    /// asked later is refused at once.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        self.waiting().clear();
    }
}

/// The caller's address from a [`Hello`]; unparseable reads as unknown.
fn peer_of(hello: &Hello) -> std::net::SocketAddr {
    hello
        .peer
        .parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
}

/// The service's side of one connection on the SSH pipe: wait for the
/// worker's [`Frame::Hello`], then run `session` over an in-memory stream
/// while carrying [`Frame::Data`] both ways and the person's answers to its
/// relay. Returns when the session and the pipe are both done.
pub async fn serve_framed<P, F, Fut>(pipe: P, session: F) -> Result<(), String>
where
    P: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(tokio::io::DuplexStream, std::net::SocketAddr, ConsentRelay) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(pipe);
    let hello = match tokio::time::timeout(HELLO_WAIT, read_frame(&mut rd)).await {
        Ok(Ok(Some(Frame::Hello(h)))) => h,
        Ok(Ok(Some(other))) => {
            return Err(format!(
                "the worker sent a {} frame before its hello",
                other.name()
            ));
        }
        Ok(Ok(None)) => return Err("the worker hung up before its hello".into()),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("no hello from the worker within 5 s".into()),
    };
    let peer = peer_of(&hello);

    let (out_tx, out_rx) = mpsc::channel::<Frame>(OUT_QUEUE);
    let writer = tokio::spawn(write_frames(wr, out_rx));
    let relay = ConsentRelay::new(out_tx.clone());
    let (session_end, pump_end) = tokio::io::duplex(MAX_DATA);
    let mut session = tokio::spawn(session(session_end, peer, relay.clone()));
    let (mut pump_rd, mut pump_wr) = tokio::io::split(pump_end);

    // The session's bytes, out to the worker, then its end.
    let outbound = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATA];
        loop {
            match pump_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.send(Frame::Data(buf[..n].to_vec())).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = out_tx.send(Frame::Eof).await;
    });

    // The worker's bytes and answers, in, until the pipe closes or the
    // session ends.
    let mut session_over = false;
    let inbound = loop {
        tokio::select! {
            frame = read_frame(&mut rd) => match frame {
                Ok(Some(Frame::Data(bytes))) => {
                    if pump_wr.write_all(&bytes).await.is_err() {
                        break Ok(());
                    }
                }
                Ok(Some(Frame::Eof)) => {
                    let _ = pump_wr.shutdown().await;
                }
                Ok(Some(Frame::Answer(answer))) => {
                    if !relay.answer(answer) {
                        tracing::debug!("ssh-service: an answer nobody was waiting for");
                    }
                }
                Ok(Some(other)) => {
                    break Err(format!("the worker sent an unexpected {} frame", other.name()));
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            },
            _ = &mut session => {
                session_over = true;
                break Ok(());
            }
        }
    };
    relay.close();
    drop(pump_wr);
    if !session_over {
        let _ = session.await;
    }
    let _ = outbound.await;
    drop(relay);
    let _ = writer.await;
    inbound
}

/// The worker's side: carry one intercepted connection (`client`) to the
/// service over `pipe`, byte for byte, and answer the service's questions
/// with `answer`. Returns when the pipe closes.
pub async fn splice_framed<C, P, A, AFut>(
    client: C,
    pipe: P,
    peer: std::net::SocketAddr,
    answer: A,
) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    P: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: Fn(ConsentAsk) -> AFut + Send + Sync + 'static,
    AFut: Future<Output = ConsentAnswer> + Send + 'static,
{
    let (mut prd, pwr) = tokio::io::split(pipe);
    let (out_tx, out_rx) = mpsc::channel::<Frame>(OUT_QUEUE);
    // Not awaited: it ends once every sender is gone, which a question still
    // being asked may delay past this function.
    tokio::spawn(write_frames(pwr, out_rx));
    out_tx
        .send(Frame::Hello(Hello {
            peer: peer.to_string(),
        }))
        .await
        .map_err(|_| "the SSH pipe closed".to_string())?;
    let (mut crd, mut cwr) = tokio::io::split(client);

    // The caller's bytes, to the service, then their end.
    let up = {
        let out_tx = out_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATA];
            loop {
                match crd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out_tx.send(Frame::Data(buf[..n].to_vec())).await.is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = out_tx.send(Frame::Eof).await;
        })
    };

    let answer = Arc::new(answer);
    let result = loop {
        match read_frame(&mut prd).await {
            Ok(Some(Frame::Data(bytes))) => {
                if cwr.write_all(&bytes).await.is_err() {
                    break Ok(());
                }
            }
            Ok(Some(Frame::Eof)) => {
                let _ = cwr.shutdown().await;
            }
            Ok(Some(Frame::Ask(ask))) => {
                // Asked off this loop: a person has up to a prompt's window
                // to answer, and the session's bytes keep flowing meanwhile.
                let (answer, out_tx) = (Arc::clone(&answer), out_tx.clone());
                tokio::spawn(async move {
                    let reply = answer(ask).await;
                    let _ = out_tx.send(Frame::Answer(reply)).await;
                });
            }
            Ok(Some(other)) => {
                break Err(format!(
                    "the SYSTEM service sent an unexpected {} frame",
                    other.name()
                ));
            }
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    up.abort();
    let _ = cwr.shutdown().await;
    result
}

// ────────────────────────────────────────────────────────────────────────────
// What both sides read
// ────────────────────────────────────────────────────────────────────────────

/// Is this process's SSH pipe up? Set by the service's runner.
static SSH_PIPE_UP: AtomicBool = AtomicBool::new(false);

/// The service's health reply about SSH: the anchor's ceiling while this
/// process serves the SSH pipe, else nothing (no word for the worker to
/// advertise).
pub fn served_ceiling(
    anchor: &crate::exec_service::Anchor,
) -> Option<meshharbor_remote_control::models::SshServiceCeiling> {
    SSH_PIPE_UP.load(Ordering::SeqCst).then_some(anchor.ssh)
}

/// Is the kill switch set?
pub fn disabled() -> bool {
    crate::exec_service::disabled_by(std::env::var(KILL_SWITCH_ENV).ok().as_deref())
}

/// Should the connection for `agent_id` advertise `ssh-system`? Only where
/// this build can carry a session to the service (Windows, `ssh-server`), the
/// person has `ssh_enabled` on (their half: their worker intercepts the port),
/// the kill switch is not set, and the service said it serves SSH for exactly
/// this device with a ceiling above off.
pub fn advertised_for(agent_id: &str, ssh_enabled: bool) -> bool {
    cfg!(all(windows, feature = "ssh-server"))
        && ssh_enabled
        && !disabled()
        && crate::exec_service::ssh_served_for(agent_id)
}

/// Put `ssh-system` in `rpc`, or take it out, by equality: `ssh` is a prefix
/// of it and stays either way.
pub fn apply_word(rpc: &mut Vec<String>, on: bool) {
    let word = meshharbor_remote_control::models::RpcCap::SshSystem.wire();
    rpc.retain(|w| w != word);
    if on {
        rpc.push(word.to_string());
    }
}

/// The SHA-256 fingerprint of a host key's public half, as `anchor status`
/// prints it.
#[cfg(feature = "ssh-server")]
pub fn fingerprint_of(pem: &str) -> Option<String> {
    use russh::keys::ssh_key::{HashAlg, PrivateKey};
    let key = PrivateKey::from_openssh(pem).ok()?;
    Some(key.public_key().fingerprint(HashAlg::Sha256).to_string())
}

/// The OpenSSH public half of a host key, as the server stores it.
#[cfg(feature = "ssh-server")]
#[cfg_attr(not(windows), allow(dead_code))]
fn public_half(pem: &str) -> Result<String, String> {
    use russh::keys::ssh_key::PrivateKey;
    let key = PrivateKey::from_openssh(pem).map_err(|e| format!("the host key: {e}"))?;
    key.public_key()
        .to_openssh()
        .map_err(|e| format!("the host key's public half: {e}"))
}

// ────────────────────────────────────────────────────────────────────────────
// The service's side (Windows)
// ────────────────────────────────────────────────────────────────────────────

/// What a claim hands the service: the server's `ClaimedSshGrant`.
#[cfg(all(windows, feature = "ssh-server"))]
#[derive(Debug, Deserialize)]
struct ClaimedSshGrant {
    grant_id: String,
    public_key: String,
    caller: String,
    account_mode: String,
    expires_at_ms: u64,
    session_secs: u64,
    #[serde(default)]
    consent_mode: Option<meshharbor_remote_control::models::ConsentMode>,
    /// FR-90 P3-8-2a — an agent session's grant, held to one command by this
    /// service's server. Absent from every other grant's claim.
    #[serde(default)]
    one_command: bool,
}

/// A grant's claim must beat the server's window for it
/// (`ssh_limits::GRANT_ACK_TIMEOUT_SECS`, 10 s from the push).
#[cfg(all(windows, feature = "ssh-server"))]
const CLAIM_TIMEOUT: Duration = Duration::from_secs(8);
#[cfg(all(windows, feature = "ssh-server"))]
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(all(windows, feature = "ssh-server"))]
fn http(total: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(concat!("meshharbord-ssh-service/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .timeout(total)
        .build()
        .map_err(|e| format!("building the HTTP client: {e}"))
}

/// Where the service claims `grant_id`. FR-90 P3-8-2a — `one_command=true`:
/// this build holds an agent session's grant to one command. The server hands
/// such a grant to no claim that does not say so, so a service older than its
/// worker cannot take one.
#[cfg(all(windows, feature = "ssh-server"))]
fn claim_url(server: &str, grant_id: &str, tenant_id: &str) -> String {
    format!("{server}/api/agent/service/ssh/{grant_id}/claim?tid={tenant_id}&one_command=true")
}

/// What the service publishes of its SSH endpoint. FR-90 P3-8-2a — with
/// `one_command`: this build holds an agent session's grant to one command,
/// so the server may route one here. A service before it says nothing, and
/// the worker serves those.
#[cfg(all(windows, feature = "ssh-server"))]
fn endpoint_body(
    host_pubkey: &str,
    ceiling: meshharbor_remote_control::models::SshServiceCeiling,
) -> serde_json::Value {
    serde_json::json!({
        "host_pubkey": host_pubkey,
        "ceiling": ceiling,
        "one_command": true,
    })
}

/// Claim `grant_id` from the server with the service's own credential and hold
/// it in this process's grant table, where the service's SSH server redeems
/// it. The claim is the server's acknowledgement: the caller is told to dial
/// once it lands.
#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) async fn claim_grant(
    anchor: &crate::exec_service::Anchor,
    grant_id: &str,
) -> Result<(), String> {
    use meshharbor_remote_control::models::SshServiceCeiling;
    if anchor.ssh == SshServiceCeiling::Off {
        return Err(
            "SSH through the SYSTEM service is off on this device (`meshharbord anchor ssh`, \
             elevated)"
                .into(),
        );
    }
    if !SSH_PIPE_UP.load(Ordering::SeqCst) {
        return Err("the SYSTEM service's SSH pipe is not up".into());
    }
    let resp = http(CLAIM_TIMEOUT)?
        .post(claim_url(&anchor.server, grant_id, &anchor.tenant_id))
        .bearer_auth(&anchor.service_token)
        .send()
        .await
        .map_err(|e| format!("the SYSTEM service could not reach the server: {e}"))?;
    match resp.status().as_u16() {
        200 => {
            let claimed: ClaimedSshGrant = resp
                .json()
                .await
                .map_err(|e| format!("the server's claim answer: {e}"))?;
            if claimed.grant_id != grant_id {
                return Err("the server answered a claim for another grant".into());
            }
            let ClaimedSshGrant {
                grant_id,
                public_key,
                caller,
                account_mode,
                expires_at_ms,
                session_secs,
                consent_mode,
                one_command,
            } = claimed;
            tracing::info!(
                %grant_id, %caller, %account_mode, one_command,
                "ssh-service: claimed a grant for the SYSTEM service's SSH"
            );
            // No named account: the service never serves one.
            crate::ssh::record_grant(
                grant_id,
                public_key,
                caller,
                account_mode,
                None,
                consent_mode,
                expires_at_ms,
                session_secs,
                one_command,
            )
            .map_err(|e| e.to_string())
        }
        404 => Err("the server has no such SSH grant pending for this device".into()),
        401 => Err(
            "this device's SYSTEM service credential is no longer accepted (re-anchored or \
             un-anchored); anchor it again"
                .into(),
        ),
        s => Err(format!("the server refused the claim: HTTP {s}")),
    }
}

#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) mod svc {
    //! The SSH pipe and the endpoint publisher, in the SYSTEM service.

    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use meshharbor_remote_control::models::SshServiceCeiling;
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use tokio::sync::Semaphore;
    use tracing::{debug, error, info, warn};

    /// Sessions served at once; more are refused, not queued.
    const MAX_SESSIONS: usize = 8;
    /// How often the publisher compares what it published with the anchor.
    const PUBLISH_CHECK_EVERY: Duration = Duration::from_secs(60);
    /// Re-publish an unchanged endpoint this often, so a server that lost
    /// the record gets it back.
    const REPUBLISH_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
    /// After a failed publish, wait this long before the next try.
    const RETRY_AFTER: Duration = Duration::from_secs(5 * 60);

    pub async fn run() {
        tokio::spawn(publish_loop());
        loop {
            if let Err(e) = serve().await {
                // A pipe someone else made first, or none at all: say so and
                // retry, as the doorbell does.
                error!(%e, "ssh-service: the SSH pipe is down; retrying in 30 s");
            }
            super::SSH_PIPE_UP.store(false, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    fn instance(first: bool) -> Result<NamedPipeServer, String> {
        crate::exec_service::pipe_instance(super::PIPE_NAME, first)
            .map_err(|e| format!("the SSH pipe: {e}"))
    }

    async fn serve() -> Result<(), String> {
        let mut server = instance(true)?;
        super::SSH_PIPE_UP.store(true, Ordering::SeqCst);
        info!(pipe = super::PIPE_NAME, "ssh-service: the SSH pipe is up");
        let slots = Arc::new(Semaphore::new(MAX_SESSIONS));
        loop {
            if let Err(e) = server.connect().await {
                debug!(%e, "ssh-service: an SSH pipe connection failed");
                server = instance(false)?;
                continue;
            }
            let connected = server;
            server = instance(false)?;
            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                warn!(
                    max = MAX_SESSIONS,
                    "ssh-service: refusing a connection — too many sessions"
                );
                continue;
            };
            tokio::spawn(async move {
                if let Err(e) = serve_one(connected).await {
                    info!(%e, "ssh-service: connection ended");
                }
                drop(permit);
            });
        }
    }

    /// One connection, under the anchor and the key as they stand NOW: an
    /// administrator's change applies to the next session.
    async fn serve_one(pipe: NamedPipeServer) -> Result<(), String> {
        let anchor = crate::exec_service::load_anchor()?
            .ok_or("this device is not anchored for the SYSTEM service")?;
        if anchor.ssh == SshServiceCeiling::Off {
            return Err("SSH through the SYSTEM service is off on this device".into());
        }
        let pem = crate::exec_service::load_host_key()?
            .ok_or("the SYSTEM service has no SSH host key yet")?;
        let ceiling = anchor.ssh;
        super::serve_framed(pipe, move |stream, peer, relay| async move {
            crate::ssh::serve_for_service(stream, peer, &pem, ceiling, relay).await;
        })
        .await
    }

    /// What was last published, and when.
    struct Published {
        agent_id: String,
        anchored_at: String,
        ceiling: SshServiceCeiling,
        host_pubkey: String,
        at: Instant,
    }

    async fn publish_loop() {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut last: Option<Published> = None;
        let mut retry_at: Option<Instant> = None;
        loop {
            if retry_at.is_none_or(|t| Instant::now() >= t) {
                match publish_once(&mut last).await {
                    Ok(()) => retry_at = None,
                    Err(e) => {
                        warn!(%e, "ssh-service: could not publish the SSH endpoint; will retry");
                        retry_at = Some(Instant::now() + RETRY_AFTER);
                    }
                }
            }
            tokio::time::sleep(PUBLISH_CHECK_EVERY).await;
        }
    }

    /// Publish the endpoint when it differs from what the server last heard
    /// (another anchor, another ceiling, another key), or every
    /// [`REPUBLISH_EVERY`]. Nothing without an anchor: the record a server
    /// holds names the anchor it was published under, so a re-anchor or an
    /// un-anchor retires it there.
    async fn publish_once(last: &mut Option<Published>) -> Result<(), String> {
        let Some(anchor) = crate::exec_service::load_anchor()? else {
            *last = None;
            return Ok(());
        };
        let pem = crate::exec_service::ensure_host_key()?;
        let host_pubkey = super::public_half(&pem)?;
        let unchanged = last.as_ref().is_some_and(|p| {
            p.agent_id == anchor.agent_id
                && p.anchored_at == anchor.anchored_at
                && p.ceiling == anchor.ssh
                && p.host_pubkey == host_pubkey
                && p.at.elapsed() < REPUBLISH_EVERY
        });
        if unchanged {
            return Ok(());
        }
        let resp = super::http(super::PUBLISH_TIMEOUT)?
            .put(format!(
                "{}/api/agent/service/ssh-host-key?tid={}",
                anchor.server, anchor.tenant_id
            ))
            .bearer_auth(&anchor.service_token)
            .json(&super::endpoint_body(&host_pubkey, anchor.ssh))
            .send()
            .await
            .map_err(|e| format!("could not reach the server: {e}"))?;
        match resp.status().as_u16() {
            200..=299 => {
                info!(ceiling = ?anchor.ssh, "ssh-service: published the SSH endpoint");
                *last = Some(Published {
                    agent_id: anchor.agent_id,
                    anchored_at: anchor.anchored_at,
                    ceiling: anchor.ssh,
                    host_pubkey,
                    at: Instant::now(),
                });
                Ok(())
            }
            401 => Err(
                "the server no longer accepts this anchor's credential; anchor the device again"
                    .into(),
            ),
            404 => Err("this server does not take a SYSTEM service's SSH endpoint yet".into()),
            s => Err(format!("HTTP {s}")),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// The worker's side (Windows)
// ────────────────────────────────────────────────────────────────────────────

/// Carry one connection to the service's port over the SSH pipe, answering
/// the service's questions as this worker asks for its own sessions.
/// `services` is the worker's own ([`crate::ssh::Asker::Here`]).
#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) async fn carry<C>(
    client: C,
    peer: std::net::SocketAddr,
    services: crate::ssh::SessionServices,
) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Every instance busy is retried briefly: the service makes the next one
    // as soon as it takes a connection.
    let mut pipe = None;
    for _ in 0..20 {
        if let Some(p) = crate::exec_service::open_system_pipe(PIPE_NAME, "SSH")? {
            pipe = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pipe = pipe.ok_or("the SYSTEM service's SSH pipe stayed busy")?;
    // A live session holds the machine awake, as the worker's own does.
    let _awake = services
        .power_activity
        .as_ref()
        .map(crate::power::ActivityGuard::new);
    let asker = services.asker.clone();
    splice_framed(client, pipe, peer, move |ask| {
        let asker = asker.clone();
        async move { answer_here(ask, &asker).await }
    })
    .await
}

/// The person's answer to a question the service relayed, asked here as the
/// worker asks for its own sessions.
#[cfg(all(windows, feature = "ssh-server"))]
async fn answer_here(ask: ConsentAsk, asker: &crate::ssh::Asker) -> ConsentAnswer {
    let id = ask.id;
    let verdict = match asker {
        // The grant id is a file name in the broker's directory: never let
        // anything else become one.
        _ if !crate::exec_service::valid_object_id(&ask.sentinel) => {
            Err("the SYSTEM service asked about a malformed grant".to_string())
        }
        crate::ssh::Asker::Here { broker, indicator } => {
            crate::ssh::ask_here(
                broker,
                indicator,
                &clean_reason(&ask.caller),
                &ask.sentinel,
                &clean_reason(&ask.what),
                crate::consent::DEFAULT_PROMPT_TIMEOUT,
            )
            .await
        }
        crate::ssh::Asker::Worker(_) => {
            Err("this worker has nobody to ask (a misbuilt server)".to_string())
        }
    };
    ConsentAnswer {
        id,
        granted: verdict.is_ok(),
        reason: verdict.err(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn round_trip(frame: Frame) -> Frame {
        let (mut a, mut b) = tokio::io::duplex(2 * MAX_DATA);
        write_frame(&mut a, &frame).await.unwrap();
        read_frame(&mut b).await.unwrap().unwrap()
    }

    /// Every frame kind reads back as it was written; the bytes of a `Data`
    /// frame are not touched.
    #[tokio::test]
    async fn every_frame_round_trips() {
        let frames = [
            Frame::Hello(Hello {
                peer: "100.64.0.9:51234".into(),
            }),
            Frame::Data((0..=255u8).cycle().take(MAX_DATA).collect()),
            Frame::Data(Vec::new()),
            Frame::Eof,
            Frame::Ask(ConsentAsk {
                id: 7,
                sentinel: "6ace07367d06cf41e19e54b0".into(),
                caller: "alice@example.com".into(),
                what: "run a command".into(),
                timeout_secs: 30,
            }),
            Frame::Answer(ConsentAnswer {
                id: 7,
                granted: false,
                reason: Some("denied".into()),
            }),
        ];
        for frame in frames {
            assert_eq!(round_trip(frame.clone()).await, frame);
        }
    }

    /// The wire is shared by two builds of one release, so its layout is
    /// locked: kind, big-endian length, payload.
    #[tokio::test]
    async fn the_frame_layout_is_locked() {
        let mut out = Vec::new();
        write_frame(&mut out, &Frame::Data(vec![0xAB, 0xCD]))
            .await
            .unwrap();
        assert_eq!(out, [2, 0, 0, 0, 2, 0xAB, 0xCD]);
        let mut out = Vec::new();
        write_frame(&mut out, &Frame::Eof).await.unwrap();
        assert_eq!(out, [3, 0, 0, 0, 0]);
        let mut out = Vec::new();
        write_frame(
            &mut out,
            &Frame::Answer(ConsentAnswer {
                id: 1,
                granted: true,
                reason: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(out[0], 5);
        assert_eq!(&out[5..], br#"{"id":1,"granted":true}"#);
    }

    /// Nothing oversized is written, and nothing announced oversized is read:
    /// a peer cannot make the other side allocate what it claims.
    #[tokio::test]
    async fn oversized_and_unknown_frames_are_refused() {
        let mut sink = Vec::new();
        assert!(
            write_frame(&mut sink, &Frame::Data(vec![0; MAX_DATA + 1]))
                .await
                .is_err()
        );
        let too_big = (MAX_DATA as u32 + 1).to_be_bytes();
        let mut bytes: &[u8] = &[2, too_big[0], too_big[1], too_big[2], too_big[3]];
        assert!(read_frame(&mut bytes).await.is_err());
        let control_big = (MAX_CONTROL as u32 + 1).to_be_bytes();
        let mut bytes: &[u8] = &[
            4,
            control_big[0],
            control_big[1],
            control_big[2],
            control_big[3],
        ];
        assert!(read_frame(&mut bytes).await.is_err());
        let mut bytes: &[u8] = &[9, 0, 0, 0, 0];
        assert!(read_frame(&mut bytes).await.is_err(), "unknown kind");
        let mut bytes: &[u8] = &[3, 0, 0, 0, 1, 0];
        assert!(read_frame(&mut bytes).await.is_err(), "eof with a payload");
        let mut bytes: &[u8] = &[4, 0, 0, 0, 2, b'{', b'x'];
        assert!(
            read_frame(&mut bytes).await.is_err(),
            "an ask that is not JSON"
        );
    }

    /// A close between frames is the end; a close inside one is an error.
    #[tokio::test]
    async fn a_close_is_clean_only_between_frames() {
        let mut empty: &[u8] = &[];
        assert_eq!(read_frame(&mut empty).await.unwrap(), None);
        let mut cut: &[u8] = &[2, 0, 0];
        assert!(read_frame(&mut cut).await.is_err());
        let mut cut: &[u8] = &[2, 0, 0, 0, 4, 1, 2];
        assert!(read_frame(&mut cut).await.is_err());
    }

    #[test]
    fn a_reason_reaches_a_terminal_without_control_characters() {
        assert_eq!(clean_reason("no\x1b[2Jthanks\r\n"), "no [2Jthanks  ");
        let long = "x".repeat(MAX_REASON + 50);
        let cleaned = clean_reason(&long);
        assert_eq!(cleaned.chars().count(), MAX_REASON + 1);
        assert!(cleaned.ends_with('…'));
    }

    /// A question goes out as an `Ask`; the matching answer decides it, and a
    /// refusal's reason reaches the caller cleaned.
    #[tokio::test]
    async fn the_relay_asks_and_hears_the_answer() {
        let (tx, mut rx) = mpsc::channel(8);
        let relay = ConsentRelay::new(tx);
        let asking = {
            let relay = relay.clone();
            tokio::spawn(async move {
                relay
                    .ask(
                        "6ace07367d06cf41e19e54b0",
                        "alice",
                        "run a command",
                        Duration::from_secs(30),
                    )
                    .await
            })
        };
        let Some(Frame::Ask(ask)) = rx.recv().await else {
            panic!("an ask frame")
        };
        assert_eq!(ask.sentinel, "6ace07367d06cf41e19e54b0");
        assert_eq!(ask.what, "run a command");
        assert_eq!(ask.timeout_secs, 30);
        assert!(!relay.answer(ConsentAnswer {
            id: ask.id + 1,
            granted: true,
            reason: None,
        }));
        assert!(relay.answer(ConsentAnswer {
            id: ask.id,
            granted: false,
            reason: Some("not\x07now".into()),
        }));
        assert_eq!(asking.await.unwrap(), Err("not now".to_string()));

        let granted = {
            let relay = relay.clone();
            tokio::spawn(async move {
                relay
                    .ask(
                        "6ace07367d06cf41e19e54b0",
                        "alice",
                        "x",
                        Duration::from_secs(30),
                    )
                    .await
            })
        };
        let Some(Frame::Ask(ask)) = rx.recv().await else {
            panic!("an ask frame")
        };
        relay.answer(ConsentAnswer {
            id: ask.id,
            granted: true,
            reason: None,
        });
        assert_eq!(granted.await.unwrap(), Ok(()));
    }

    /// The worker going away refuses every question, waiting or not.
    #[tokio::test]
    async fn a_closed_relay_refuses() {
        let (tx, mut rx) = mpsc::channel(8);
        let relay = ConsentRelay::new(tx);
        let waiting = {
            let relay = relay.clone();
            tokio::spawn(async move {
                relay
                    .ask(
                        "6ace07367d06cf41e19e54b0",
                        "alice",
                        "x",
                        Duration::from_secs(30),
                    )
                    .await
            })
        };
        assert!(matches!(rx.recv().await, Some(Frame::Ask(_))));
        relay.close();
        assert_eq!(waiting.await.unwrap(), Err(WORKER_GONE.to_string()));
        assert_eq!(
            relay
                .ask(
                    "6ace07367d06cf41e19e54b0",
                    "alice",
                    "x",
                    Duration::from_secs(30)
                )
                .await,
            Err(WORKER_GONE.to_string())
        );
    }

    /// Nobody answering is a refusal, after the person's window and a grace.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_question_is_refused() {
        let (tx, _rx) = mpsc::channel(8);
        let relay = ConsentRelay::new(tx);
        let verdict = relay
            .ask(
                "6ace07367d06cf41e19e54b0",
                "alice",
                "x",
                Duration::from_secs(30),
            )
            .await;
        assert!(verdict.unwrap_err().contains("no answer"));
    }

    /// A worker that speaks before its hello, or not at all, is dropped.
    #[tokio::test(start_paused = true)]
    async fn the_service_wants_a_hello_first() {
        let (svc, mut worker) = tokio::io::duplex(1024);
        let serving = tokio::spawn(serve_framed(svc, |_, _, _| async {}));
        write_frame(&mut worker, &Frame::Data(vec![1, 2, 3]))
            .await
            .unwrap();
        assert!(
            serving
                .await
                .unwrap()
                .unwrap_err()
                .contains("before its hello")
        );

        let (svc, _worker) = tokio::io::duplex(1024);
        let silent = serve_framed(svc, |_, _, _| async {}).await;
        assert!(silent.unwrap_err().contains("within 5 s"));
    }

    /// The pump carries bytes both ways and ends when the session does.
    #[tokio::test]
    async fn the_pipe_carries_a_session_both_ways() {
        let (svc_pipe, worker_pipe) = tokio::io::duplex(4 * MAX_DATA);
        // The "session": an echo that stops at its client's EOF.
        let serving = tokio::spawn(serve_framed(svc_pipe, |stream, peer, _relay| async move {
            assert_eq!(peer.to_string(), "100.64.0.9:5000");
            let (mut r, mut w) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        }));
        let (mut client, carried) = tokio::io::duplex(4 * MAX_DATA);
        let splicing = tokio::spawn(splice_framed(
            carried,
            worker_pipe,
            "100.64.0.9:5000".parse().unwrap(),
            |ask: ConsentAsk| async move {
                ConsentAnswer {
                    id: ask.id,
                    granted: false,
                    reason: None,
                }
            },
        ));
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        assert!(serving.await.unwrap().is_ok());
        assert!(splicing.await.unwrap().is_ok());
    }

    #[test]
    fn ssh_system_is_added_and_removed_by_equality() {
        let mut rpc: Vec<String> = ["ssh", "ssh-consent"].map(String::from).to_vec();
        apply_word(&mut rpc, true);
        apply_word(&mut rpc, true);
        assert_eq!(rpc, ["ssh", "ssh-consent", "ssh-system"]);
        apply_word(&mut rpc, false);
        assert_eq!(rpc, ["ssh", "ssh-consent"], "`ssh` stays");
    }

    /// FR-90 P3-8-2a — the SYSTEM service says it holds one command, on its
    /// claim and when it publishes, since the worker's `ssh-one-command`
    /// speaks only for the worker; and a claimed grant carries the field into
    /// the service's table, false in every claim but an agent session's.
    #[cfg(all(windows, feature = "ssh-server"))]
    #[test]
    fn the_service_says_it_holds_one_command_and_a_claimed_grant_carries_it() {
        let url = claim_url("https://meshharbor.example", "g1", "t1");
        assert_eq!(
            url,
            "https://meshharbor.example/api/agent/service/ssh/g1/claim?tid=t1&one_command=true"
        );
        let body = endpoint_body(
            "a host key",
            meshharbor_remote_control::models::SshServiceCeiling::System,
        );
        assert_eq!(body["one_command"], serde_json::json!(true), "{body}");
        assert_eq!(body["ceiling"], serde_json::json!("system"), "{body}");

        let mut answer = serde_json::json!({
            "grant_id": "g1",
            "public_key": "k",
            "caller": "agent session 0 of someone (via a device)",
            "account_mode": "daemon",
            "expires_at_ms": 1,
            "session_secs": 60,
        });
        let person: ClaimedSshGrant = serde_json::from_value(answer.clone()).unwrap();
        assert!(!person.one_command, "absent from every other grant");
        answer["one_command"] = serde_json::json!(true);
        let session: ClaimedSshGrant = serde_json::from_value(answer).unwrap();
        assert!(session.one_command);
    }
}
