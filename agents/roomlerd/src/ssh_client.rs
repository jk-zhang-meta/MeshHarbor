// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-8-2b — this daemon's own SSH client, for an agent session's ONE
//! command on another device of its organization (the tool `ssh_run`,
//! P3-8-2b-2; the FR-90 spec's §3e "P3-8, `ssh_run`, as designed").
//!
//! The session never holds a key. For each call this daemon:
//! 1. mints an ed25519 key, its private half in this process's memory alone,
//!    dropped when the call ends ([`mint_key`]);
//! 2. asks the server for the target's grant (`rc:ssh.request`), presenting
//!    the vault's ticket (P3-8-1a) beside the key's public half ([`ask`]);
//! 3. refuses an answer that does not echo the ticket, since a server before
//!    P3-8-1b ignored it and answered as the device owner's, and one that
//!    names no host key, since the target could then not be checked
//!    ([`admit`]);
//! 4. dials the target's overlay address ([`OverlayDialer`]), pins its host
//!    key to the answer's, and runs ONE `exec`, which the target holds the
//!    session to anyway (P3-8-2a) ([`exec_one`]);
//! 5. reads the exit status and both streams, each to [`MAX_STREAM`] bytes,
//!    within the call's time.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bson::oid::ObjectId;
use russh::keys::ssh_key::{
    PublicKey,
    private::{Ed25519Keypair, PrivateKey},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use roomler_ai_remote_control::ClientMsg;

use crate::ssh_origin::SshGrantAnswer;

/// The longest command line, in bytes: one line for the target's own shell.
pub const MAX_COMMAND: usize = 8 * 1024;
/// The most of each stream an answer holds, as `vault_exec`'s.
pub const MAX_STREAM: usize = 64 * 1024;
/// The longest a call may ask to run.
pub const MAX_TIMEOUT_SECS: u64 = 300;
/// What a person at the target may take to answer its consent prompt
/// (`consent.rs`'s window), on top of the command's own time.
pub const PROMPT_SECS: u64 = 30;
/// How long the server has to answer the request: a gate decision, one push
/// to the target and its acknowledgement (FR-83), as for `meshharbor ssh`.
pub const ASK_WAIT: Duration = Duration::from_secs(30);

/// What one call ran to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// The command's exit status. `None` when it ended without one: a
    /// signal, or the session ended first.
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    /// Either stream was cut at [`MAX_STREAM`].
    pub truncated: bool,
}

/// Why a call did not run, in words a session can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The command is not one line within the bound.
    BadCommand(&'static str),
    /// The server refused the request, in its own words.
    Refused(String),
    /// The answer did not echo the ticket presented: a server too old to
    /// hold a session to its ticket would have answered as the device
    /// owner's. Nothing is dialled.
    NotEchoed,
    /// The answer named no host key, so the target could not be checked.
    NoHostKey,
    /// The answer was not whole.
    BadAnswer(&'static str),
    /// The target could not be reached over the overlay.
    Dial(String),
    /// The target presented another host key than the answer named.
    WrongHostKey,
    /// The target did not admit the call's key.
    NotAdmitted,
    /// The SSH session failed, or the server connection dropped.
    Session(String),
    /// The call's time ran out.
    TimedOut,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCommand(why) => write!(f, "the command is not one this tool runs: {why}"),
            Self::Refused(why) => write!(f, "the server refused the session: {why}"),
            Self::NotEchoed => f.write_str(
                "the server did not hold the request to this session's ticket (it is too \
                 old to); nothing was run",
            ),
            Self::NoHostKey => f.write_str(
                "the target device publishes no SSH host key, so it cannot be checked; nothing \
                 was run",
            ),
            Self::BadAnswer(why) => write!(f, "the server's answer is not whole: {why}"),
            Self::Dial(why) => write!(f, "the target device could not be reached: {why}"),
            Self::WrongHostKey => f.write_str(
                "the device that answered is not the target: its host key is another; nothing \
                 was run",
            ),
            Self::NotAdmitted => f.write_str("the target device did not admit the session"),
            Self::Session(why) => write!(f, "the SSH session failed: {why}"),
            Self::TimedOut => f.write_str("the command did not finish in its time"),
        }
    }
}

impl std::error::Error for RunError {}

/// Check a command line before anything is asked: not empty, one line, and
/// within [`MAX_COMMAND`]. SSH carries a string, which the target's shell
/// reads (PowerShell on Windows, bash elsewhere); a second line would be a
/// second command.
pub fn check_command(command: &str) -> Result<(), RunError> {
    if command.trim().is_empty() {
        return Err(RunError::BadCommand("it is empty"));
    }
    if command.len() > MAX_COMMAND {
        return Err(RunError::BadCommand("it is longer than 8 KiB"));
    }
    if command.contains(['\n', '\r', '\0']) {
        return Err(RunError::BadCommand("it is more than one line"));
    }
    Ok(())
}

/// The call's key: ed25519, seeded from the OS CSPRNG, as `meshharbor ssh`
/// mints one (`agents/roomler-cli/src/sshcmd.rs`), under a comment of its own.
/// Its private half never leaves this process.
pub fn mint_key() -> PrivateKey {
    let seed: [u8; 32] = rand::random();
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    key.set_comment("roomler-hive-session");
    key
}

/// Where the answer lets the call go, once checked.
#[derive(Debug, Clone)]
pub struct Admission {
    pub address: String,
    pub port: u16,
    pub host_key: PublicKey,
}

/// Check the server's answer before anything dials. A refusal is the
/// server's word. Otherwise it must echo `ticket_id`, and name an address, a
/// port and a host key that parses.
pub fn admit(answer: &SshGrantAnswer, ticket_id: &str) -> Result<Admission, RunError> {
    if let Some(why) = &answer.error {
        return Err(RunError::Refused(why.clone()));
    }
    if answer.ssh_ticket_id.as_deref() != Some(ticket_id) {
        return Err(RunError::NotEchoed);
    }
    let host_key = answer
        .host_pubkey
        .as_deref()
        .filter(|k| !k.trim().is_empty())
        .ok_or(RunError::NoHostKey)?;
    let host_key = PublicKey::from_openssh(host_key.trim())
        .map_err(|_| RunError::BadAnswer("its host key does not parse"))?;
    let address = answer
        .address
        .clone()
        .filter(|a| !a.is_empty())
        .ok_or(RunError::BadAnswer("it names no address"))?;
    let port = answer.port.ok_or(RunError::BadAnswer("it names no port"))?;
    Ok(Admission {
        address,
        port,
        host_key,
    })
}

/// Ask the server for `target`'s grant through `sink`, the primary's
/// control connection, presenting `ticket` and the call key's public half.
/// The waiter is registered before the frame is sent, so a fast answer has
/// somewhere to land.
pub async fn ask(
    sink: &mpsc::Sender<ClientMsg>,
    target: ObjectId,
    public_key: &str,
    session_secs: u64,
    ticket: &str,
    wait: Duration,
) -> Result<SshGrantAnswer, RunError> {
    let request_id = ObjectId::new().to_hex();
    let (_guard, rx) = crate::ssh_origin::expect_response(&request_id);
    sink.send(ClientMsg::SshRequest {
        request_id,
        target: target.to_hex(),
        public_key: public_key.to_string(),
        session_secs,
        ssh_ticket: Some(ticket.to_string()),
    })
    .await
    .map_err(|_| RunError::Session("the server connection is down".into()))?;
    match tokio::time::timeout(wait, rx).await {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(_)) => Err(RunError::Session(
            "the server connection dropped while awaiting the grant".into(),
        )),
        Err(_) => Err(RunError::TimedOut),
    }
}

/// A stream an SSH session runs over: an OS socket, or the netstack's.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// How this daemon reaches an overlay address: through the OS's routes on an
/// L3 overlay node, or through its userspace stack on a netstack node.
#[async_trait::async_trait]
pub trait OverlayDialer: Send + Sync {
    async fn dial(&self, address: &str, port: u16) -> Result<Box<dyn Stream>, String>;
}

/// The OS's routes: an overlay with a TUN, where the overlay's addresses
/// route like any other, as `roomler proxy` dials them.
pub struct OsDialer;

/// How long a dial may take before it is given up.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The dialer this daemon's overlay uses: its userspace stack's on a
/// netstack node, the OS's routes on one with a TUN.
pub fn dialer_for(cfg: &crate::config::AgentConfig) -> Arc<dyn OverlayDialer> {
    crate::overlay::netstack_dialer(cfg).unwrap_or_else(|| Arc::new(OsDialer))
}

#[async_trait::async_trait]
impl OverlayDialer for OsDialer {
    async fn dial(&self, address: &str, port: u16) -> Result<Box<dyn Stream>, String> {
        let connect = tokio::net::TcpStream::connect((address, port));
        match tokio::time::timeout(DIAL_TIMEOUT, connect).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                Ok(Box::new(s))
            }
            Ok(Err(e)) => Err(format!("{address}:{port}: {e}")),
            Err(_) => Err(format!("{address}:{port}: no answer in {DIAL_TIMEOUT:?}")),
        }
    }
}

/// The client's side of the handshake: the target's key must be the one the
/// answer named, compared by key data (a comment is not part of a key).
struct Pinned {
    expected: PublicKey,
    /// Set when the target presented another key, so the failure can say so.
    mismatch: Arc<AtomicBool>,
}

impl russh::client::Handler for Pinned {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let same = key.key_data() == self.expected.key_data();
        if !same {
            self.mismatch.store(true, Ordering::SeqCst);
        }
        Ok(same)
    }
}

/// Append to a stream's bytes up to [`MAX_STREAM`]; `cut` is set when any
/// is dropped.
fn push_bounded(buf: &mut Vec<u8>, data: &[u8], cut: &mut bool) {
    let room = MAX_STREAM.saturating_sub(buf.len());
    if data.len() > room {
        *cut = true;
    }
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

/// Run ONE command over an SSH session on `stream`, the target's host key
/// pinned to `host_key`, authenticating with `key`, all within `timeout`.
/// The session is ended when the command is, or when the time is.
pub async fn exec_one<S>(
    stream: S,
    host_key: PublicKey,
    key: PrivateKey,
    command: &str,
    timeout: Duration,
) -> Result<Ran, RunError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mismatch = Arc::new(AtomicBool::new(false));
    let handler = Pinned {
        expected: host_key,
        mismatch: mismatch.clone(),
    };
    let run = async move {
        let config = Arc::new(russh::client::Config::default());
        let mut session = match russh::client::connect_stream(config, stream, handler).await {
            Ok(s) => s,
            Err(_) if mismatch.load(Ordering::SeqCst) => return Err(RunError::WrongHostKey),
            Err(e) => return Err(RunError::Session(e.to_string())),
        };
        let hash = session
            .best_supported_rsa_hash()
            .await
            .map_err(|e| RunError::Session(e.to_string()))?
            .flatten();
        let auth = session
            .authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .map_err(|e| RunError::Session(e.to_string()))?;
        if !auth.success() {
            return Err(RunError::NotAdmitted);
        }
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| RunError::Session(e.to_string()))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| RunError::Session(e.to_string()))?;
        let (mut out, mut err, mut cut) = (Vec::new(), Vec::new(), false);
        let mut exit_code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => push_bounded(&mut out, data, &mut cut),
                russh::ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    push_bounded(&mut err, data, &mut cut)
                }
                russh::ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                russh::ChannelMsg::Failure => {
                    // The target refused the exec itself; what it said is on
                    // stderr, which arrives before the failure.
                    let why = String::from_utf8_lossy(&err).trim().to_string();
                    return Err(RunError::Session(if why.is_empty() {
                        "the target refused the command".into()
                    } else {
                        why
                    }));
                }
                _ => {}
            }
        }
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
        Ok(Ran {
            exit_code,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
            truncated: cut,
        })
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| RunError::TimedOut)?
}

/// One call, whole: check the command, mint the key, ask the server for the
/// grant under `ticket_id`'s ticket, check the answer, dial the target and
/// run the command, all within `timeout` plus the target's prompt.
pub async fn run(
    sink: &mpsc::Sender<ClientMsg>,
    dialer: &dyn OverlayDialer,
    target: ObjectId,
    ticket: &str,
    ticket_id: &str,
    command: &str,
    timeout: Duration,
) -> Result<Ran, RunError> {
    check_command(command)?;
    let timeout = timeout.min(Duration::from_secs(MAX_TIMEOUT_SECS));
    let key = mint_key();
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| RunError::Session(e.to_string()))?;
    // The SSH session is bounded by the command's time and the prompt; the
    // network module clamps it to what is left of the ticket.
    let session_secs = timeout.as_secs() + PROMPT_SECS;
    let answer = ask(sink, target, &public, session_secs, ticket, ASK_WAIT).await?;
    let admission = admit(&answer, ticket_id)?;
    let stream = dialer
        .dial(&admission.address, admission.port)
        .await
        .map_err(RunError::Dial)?;
    exec_one(
        stream,
        admission.host_key,
        key,
        command,
        timeout + Duration::from_secs(PROMPT_SECS),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_key_line(seed: u8) -> String {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
            .public_key()
            .to_openssh()
            .unwrap()
    }

    fn answer(ticket_id: Option<&str>, host: Option<String>) -> SshGrantAnswer {
        SshGrantAnswer {
            address: Some("100.64.0.9".into()),
            port: Some(2222),
            host_pubkey: host,
            grant_id: Some("g1".into()),
            expires_at_ms: Some(1),
            error: None,
            ssh_ticket_id: ticket_id.map(String::from),
        }
    }

    /// One line, within the bound, not empty: a second line would be a
    /// second command for the target's shell.
    #[test]
    fn a_command_is_one_line_within_its_bound() {
        assert!(check_command("uname -a").is_ok());
        assert!(check_command(&"x".repeat(MAX_COMMAND)).is_ok());
        for bad in ["", "   ", "uname\nwhoami", "uname\r", "a\0b"] {
            assert!(
                matches!(check_command(bad), Err(RunError::BadCommand(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            check_command(&"x".repeat(MAX_COMMAND + 1)),
            Err(RunError::BadCommand(_))
        ));
    }

    /// Nothing dials on an answer that does not echo the ticket presented:
    /// a server before P3-8-1b ignored the ticket and answered as the
    /// device owner's. Nor on one with no host key, or one that refused.
    #[test]
    fn nothing_dials_without_the_echo_and_a_host_key() {
        let key = host_key_line(7);
        let admitted = admit(&answer(Some("k1"), Some(key.clone())), "k1").expect("admitted");
        assert_eq!(
            (admitted.address.as_str(), admitted.port),
            ("100.64.0.9", 2222)
        );

        assert_eq!(
            admit(&answer(None, Some(key.clone())), "k1").unwrap_err(),
            RunError::NotEchoed,
            "an older server's answer, as the owner's"
        );
        assert_eq!(
            admit(&answer(Some("k2"), Some(key.clone())), "k1").unwrap_err(),
            RunError::NotEchoed,
            "another ticket's"
        );
        assert_eq!(
            admit(&answer(Some("k1"), None), "k1").unwrap_err(),
            RunError::NoHostKey
        );
        assert_eq!(
            admit(&answer(Some("k1"), Some("  ".into())), "k1").unwrap_err(),
            RunError::NoHostKey
        );
        assert!(matches!(
            admit(&answer(Some("k1"), Some("not a key".into())), "k1").unwrap_err(),
            RunError::BadAnswer(_)
        ));
        let mut refused = answer(Some("k1"), Some(key));
        refused.error = Some("no SSH policy on this device admits agent sessions".into());
        assert_eq!(
            admit(&refused, "k1").unwrap_err(),
            RunError::Refused("no SSH policy on this device admits agent sessions".into())
        );
    }

    /// A stream keeps at most its bound, and says when it dropped any.
    #[test]
    fn a_stream_keeps_its_bound_and_says_when_it_cut() {
        let (mut buf, mut cut) = (Vec::new(), false);
        push_bounded(&mut buf, &vec![b'a'; MAX_STREAM - 1], &mut cut);
        assert!(!cut);
        push_bounded(&mut buf, b"bc", &mut cut);
        assert_eq!(buf.len(), MAX_STREAM);
        assert!(cut);
        push_bounded(&mut buf, b"d", &mut cut);
        assert_eq!(buf.len(), MAX_STREAM);
    }

    /// The request presents the ticket and the key, and its answer comes
    /// back to its asker; the server connection's end is said as such.
    #[tokio::test]
    async fn the_request_presents_the_ticket_and_waits_for_its_answer() {
        let (tx, mut rx) = mpsc::channel(4);
        let target = ObjectId::new();
        let asker = tokio::spawn(async move {
            ask(
                &tx,
                target,
                "ssh-ed25519 AAAA",
                90,
                "the-ticket",
                Duration::from_secs(5),
            )
            .await
        });
        let request_id = match rx.recv().await.unwrap() {
            ClientMsg::SshRequest {
                request_id,
                target: t,
                public_key,
                session_secs,
                ssh_ticket,
            } => {
                assert_eq!(t, target.to_hex());
                assert_eq!(public_key, "ssh-ed25519 AAAA");
                assert_eq!(session_secs, 90);
                assert_eq!(ssh_ticket.as_deref(), Some("the-ticket"));
                request_id
            }
            other => panic!("{other:?}"),
        };
        crate::ssh_origin::deliver(&request_id, answer(Some("k1"), None));
        let got = asker.await.unwrap().expect("answered");
        assert_eq!(got.ssh_ticket_id.as_deref(), Some("k1"));

        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        assert!(matches!(
            ask(&tx, target, "k", 1, "t", Duration::from_secs(1)).await,
            Err(RunError::Session(_))
        ));
    }

    /// The call's key is ed25519 and new each time.
    #[test]
    fn a_call_mints_a_key_of_its_own() {
        let (a, b) = (mint_key(), mint_key());
        assert_eq!(a.algorithm(), russh::keys::ssh_key::Algorithm::Ed25519);
        assert_ne!(a.public_key().key_data(), b.public_key().key_data());
    }
}
