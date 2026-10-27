// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1a — a session's toolbelt: the `roomler` MCP server, one per
//! session, and in P1 its one tool, `approve` — Claude Code's
//! `--permission-prompt-tool`, which it calls and waits on before every tool
//! call nothing else allowed (`docs/roomler-hive-design.md` §7.1).
//!
//! # How the harness reaches it
//!
//! Claude Code starts its MCP servers itself, as the session's account, and
//! talks to them over stdio. So the server it starts is a relay — `roomlerd
//! hive-mcp <socket>` ([`relay`]) — that pipes its stdin and stdout to the
//! session's socket, and the daemon speaks MCP on the other end. The socket
//! is `<runtime>/<sid>/toolbelt.sock`: owned by the session's account, `0600`,
//! in a directory only the daemon writes, so the kernel admits that account
//! and root; the daemon checks the peer's uid again on every connection. It
//! is deliberately not the LocalAPI socket: on a root daemon that one is
//! root-only, and most of its verbs trust the socket alone.
//!
//! On Windows (P1i-2) it is a named pipe, `\\.\pipe\roomler-hive-<session>-<nonce>`,
//! whose DACL admits SYSTEM and Administrators (the daemon is one or the
//! other) and the session's account by SID, to read and write only, and whose
//! clients' accounts are checked again by SID.
//!
//! # An approval
//!
//! `tools/call approve {tool_name, input, tool_use_id}` opens an approval:
//! the session records it, reports `awaiting_approval`, and tells its
//! viewers; a DRIVER answers over the viewer peer; the call returns
//! `{"behavior":"allow","updatedInput":…}` or `{"behavior":"deny","message":…}`
//! as one text block — the contract pinned against Claude Code 2.1.293 (FR-90
//! spec §8). Nobody answering within [`APPROVAL_TIMEOUT`] is a denial that
//! says so; the harness letting go (`notifications/cancelled`, a closed relay)
//! or the session ending withdraws it.
//!
//! ⚠️ What fails, fails CLOSED: a relay that cannot reach the socket leaves
//! Claude Code without its permission tool, and every call that needs one
//! then errors and the harness exits (measured: "MCP tool
//! mcp__roomler__approve … not found", exit 1). Nothing runs unapproved.
//!
//! ⚠️ Claude Code's permission prompts are UX, not the boundary: the device's
//! own gates — the mapped account, `hive_roots` — are. A process running as
//! the session's account can connect here too; all it can do is ASK, and the
//! answer goes back to whoever asked.
//!
//! # The vault tools (FR-90 P3-4b)
//!
//! Where the primary connection takes leases ([`daemon_vault`]), the server
//! also offers `vault_list` and `vault_describe`: what the session's role may
//! LIST of the org's vault — names, kinds, fields, audiences, the programs a
//! value may be handed to — and never a value. Each call goes to the server on
//! that connection as the session at its fence, the vault decides it with
//! Cedar's `secret:list` and records it, and the answer is the tool's text.
//! They are reads whose gate is that policy, so the session's settings allow
//! them ([`VAULT_TOOLS`]) instead of asking a person; anyone else who can
//! connect here learns only what the session itself could.
//!
//! # The vault's uses (FR-90 P3-4c)
//!
//! Offered with them: `vault_exec`, one command run as the session's account
//! with values from the vault in its environment, its output scrubbed
//! ([`super::vault_exec`]), and `vault_render`, a template written with values
//! into the session's secrets directory ([`super::vault_render`]). Each hands
//! a value on, so the settings ASK for every call ([`VAULT_USE_TOOLS`]), which
//! no repository's own allow rule overrides, and the vault decides each lease.
//! And `vault_request` ([`super::vault_request`]) asks for a lease ahead, which
//! a use naming the same secret toward the same audience takes; it hands the
//! session nothing, so the settings allow it with the reads
//! ([`VAULT_AHEAD_TOOLS`]).
//!
//! # `proxy` (FR-90 P3-5b-2)
//!
//! `vault_connect` serves an endpoint for the session's account that
//! authenticates to a database with a secret's value
//! ([`super::vault_connect`]): the session gets a connection string with no
//! credential in it, for as long as the leases. Asked for in the settings with
//! the other uses: it acts as the secret's user.
//!
//! # `ssh_run` (FR-90 P3-8-2b-2)
//!
//! Where the device's owner turned `hive_ssh` on, one command on another
//! device of the organization over Roomler SSH ([`super::ssh_tools`]). The
//! vault decides it (`ssh:run`) and answers with a ticket; this daemon's own
//! SSH client then runs it as the account the target maps, with a key minted
//! for the call, which the session never holds. Asked for in the settings on
//! every call ([`SSH_TOOLS`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use bson::oid::ObjectId;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::lines::LineReader;
use super::supervisor::Author;

/// How long an approval waits for a person before it is a denial. Under the
/// tool-call timeout the session's MCP config sets ([`TOOL_TIMEOUT_MS`]), so
/// what the model reads is our answer, never a transport error.
pub(crate) const APPROVAL_TIMEOUT: Duration = Duration::from_secs(25 * 60);
/// The toolbelt's tool-call timeout in the session's MCP config.
pub(crate) const TOOL_TIMEOUT_MS: u64 = 30 * 60 * 1000;
/// Approvals one session holds open at once. Claude Code asks one at a time
/// (measured: two parallel writes were two calls, the second after the
/// first was answered), so more than this is not Claude Code.
const MAX_PENDING: usize = 4;
/// The largest MCP message taken from the harness: a `Write` approval
/// carries the whole file.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Progress while an approval waits, so no idle timer on the harness's side
/// takes a person thinking for a server that died.
const PROGRESS_EVERY: Duration = Duration::from_secs(60);
/// The relay's subcommand: `meshharbord hive-mcp <socket>`.
pub const RELAY_SUBCOMMAND: &str = "hive-mcp";
#[cfg(unix)]
const SOCKET: &str = "toolbelt.sock";
/// The MCP versions this server answers in. It uses `initialize`,
/// `tools/list`, `tools/call`, `ping` and two notifications, which read the
/// same in each.
const PROTOCOL_VERSIONS: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
/// Longest tool name or tool-use id kept from a call.
const MAX_NAME: usize = 256;

/// What a driver decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    Allow,
    /// `message` goes to the model with the denial.
    Deny {
        message: Option<String>,
    },
}

/// A driver's answer to one approval.
#[derive(Debug, Clone)]
pub(crate) struct Answer {
    pub decision: Decision,
    pub by: Author,
}

/// How an approval ended.
#[derive(Debug, Clone)]
pub(crate) enum Ended {
    Answered(Answer),
    /// Nobody answered within the timeout.
    Expired,
    /// The harness let go, or the session ended, first.
    Withdrawn,
}

/// What the toolbelt tells its session's task — in order, on one channel,
/// so the transcript and the run state stay the task's alone to write.
#[derive(Debug)]
pub(crate) enum ApprovalEvent {
    Opened {
        id: String,
        tool_name: String,
        tool_use_id: Option<String>,
        input: Value,
    },
    Closed {
        id: String,
        ended: Ended,
    },
}

/// A session's open approvals: the toolbelt opens them; a driver's answer,
/// the timeout, or the session's end closes them.
#[derive(Default)]
pub(crate) struct Pending {
    map: Mutex<HashMap<String, oneshot::Sender<Answer>>>,
}

impl Pending {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<Answer>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Open `id`; `None` when [`MAX_PENDING`] are open already.
    fn open(&self, id: &str) -> Option<oneshot::Receiver<Answer>> {
        let mut map = self.lock();
        if map.len() >= MAX_PENDING {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        map.insert(id.to_string(), tx);
        Some(rx)
    }

    /// Answer `id`. `false` when it is not open — answered already, expired,
    /// withdrawn, or never this session's.
    pub(crate) fn answer(&self, id: &str, answer: Answer) -> bool {
        match self.lock().remove(id) {
            Some(tx) => tx.send(answer).is_ok(),
            None => false,
        }
    }

    /// The ids open now.
    pub(crate) fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.lock().keys().cloned().collect();
        ids.sort();
        ids
    }

    fn forget(&self, id: &str) {
        self.lock().remove(id);
    }

    /// FR-90 P2e-4 — withdraw `id`: its call sees the answer channel close,
    /// tells the harness so, and the session hears it ended `withdrawn`. An
    /// approval that opens while the session drains for a move.
    pub(crate) fn withdraw(&self, id: &str) {
        self.forget(id);
    }

    /// Withdraw every open approval: their calls see the answer channel close.
    pub(crate) fn withdraw_all(&self) {
        self.lock().clear();
    }
}

/// How long an approval waits, and how often it says it still is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timing {
    pub timeout: Duration,
    pub progress_every: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            timeout: APPROVAL_TIMEOUT,
            progress_every: PROGRESS_EVERY,
        }
    }
}

/// The one account a connection is taken from, the session's: its uid on
/// Unix, its SID string on Windows (P1i-2).
#[cfg(unix)]
pub(crate) type PeerId = u32;
#[cfg(windows)]
pub(crate) type PeerId = String;

/// FR-90 P3-4b — what a session's vault tools ask the vault: its metadata,
/// decided for the session's role by the vault's own `secret:list`, and from
/// P3-4c-1 the leases a command is handed. The daemon's is its lease client
/// ([`daemon_vault`]); a test's stands in for it.
#[async_trait::async_trait]
pub(crate) trait VaultTools: Send + Sync {
    async fn list(&self, session: ObjectId, fence: u64, prefix: &str) -> Result<Value, String>;
    async fn describe(&self, session: ObjectId, fence: u64, secret: &str) -> Result<Value, String>;
    /// P3-4c — lease `handle` in `mode` toward `audience` (`exec`: the
    /// program; `file`: the file's name), for `ttl_secs`: the lease's id, or
    /// why not.
    #[cfg(feature = "vault")]
    async fn lease(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        ttl_secs: u32,
    ) -> Result<String, String>;
    /// P3-4c-3 — lease `handle` AHEAD (`vault_request`): held until its
    /// expiry, its revocation or the run's end, and taken by a use tool that
    /// asks for the same secret, mode and audience. Its id, or why not.
    #[cfg(feature = "vault")]
    async fn lease_ahead(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        ttl_secs: u32,
    ) -> Result<String, String>;
    /// P3-4c-3 — how long a held lease has left; `None` once it is let go.
    #[cfg(feature = "vault")]
    fn left(&self, lease_id: &str) -> Option<Duration>;
    /// P3-4c-3 — a lease asked for ahead for this run, `handle`, `mode` and
    /// `audience`, with at least `at_least` left.
    #[cfg(feature = "vault")]
    fn ahead(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        at_least: Duration,
    ) -> Option<String>;
    /// P3-4c-2 — `path` was written with `lease_id`'s value: removed when the
    /// lease is let go. `false` when the lease is no longer held.
    #[cfg(feature = "vault")]
    fn attach(&self, lease_id: &str, path: &std::path::Path) -> bool;
    /// P3-5b-2 — `stop` is cancelled when `lease_id` is let go: what a tool
    /// serves with its value (a proxy endpoint) ends with it. `false` when the
    /// lease is no longer held.
    #[cfg(feature = "vault")]
    fn stop_with(&self, lease_id: &str, stop: CancellationToken) -> bool;
    /// The value a held lease holds, while it is held: never a dynamic
    /// secret's bundle, which holds its issuer's fields.
    #[cfg(feature = "vault")]
    fn value(&self, lease_id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>>;
    /// P3-6b-2b — mint the credential a dynamic secret's lease serves, once
    /// per lease: a second use waits for the first's credential.
    #[cfg(feature = "vault")]
    async fn mint(&self, lease_id: &str) -> Result<(), String>;
    /// P3-6b-2b — one field of the credential minted for a lease, by the name
    /// a session gives it, while the lease is held.
    #[cfg(feature = "vault")]
    fn minted(&self, lease_id: &str, field: &str) -> Option<zeroize::Zeroizing<Vec<u8>>>;
    /// Let go of these leases now.
    #[cfg(feature = "vault")]
    fn release(&self, lease_ids: &[String]);
    /// P3-4d-2 — a use of leased values, reported where the device's owner
    /// has it report; nothing otherwise. Never waits.
    #[cfg(feature = "vault")]
    fn report(&self, r: crate::vault::Report);
    /// FR-90 P3-7-3c — a session's own egress through `ask.exit`, granted by
    /// the vault's `net:socks` or `net:forward`, or why not.
    #[cfg(feature = "vault")]
    async fn net(&self, ask: crate::vault::NetAsk) -> Result<crate::vault::NetGrant, String>;
    /// FR-90 P3-8-2b-2 — a ticket to run one command on `ask.target`,
    /// granted by the vault's `ssh:run` for the account that device maps, or
    /// why not. Only a build with the SSH client asks for one.
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    async fn ssh(&self, ask: crate::vault::SshAsk) -> Result<crate::vault::SshTicket, String>;
}

/// FR-90 P3-4b — the run a toolbelt serves, and what it offers that run.
pub(crate) struct Run {
    pub(crate) session: ObjectId,
    /// The fence the session runs at here: the vault believes a session's
    /// request only at its record's fence.
    pub(crate) fence: u64,
    /// The vault, where this device takes leases; without it the vault tools
    /// are not offered.
    pub(crate) vault: Option<Arc<dyn VaultTools>>,
    /// P3-4c-1 — where and as whom the session's commands run; none where no
    /// command runs (Windows: no sandbox for a value there).
    #[cfg(feature = "vault")]
    pub(crate) exec: Option<super::vault_exec::ExecTarget>,
    /// FR-90 P3-7-3c — the hub a session's own egress opens its flows on,
    /// where the device's owner turned `hive_net` on and the vault is
    /// offered; without it `net_socks` and `net_forward` are not offered.
    #[cfg(feature = "vault")]
    pub(crate) net: Option<crate::tunnel::client_mgr::TunnelClientHub>,
    /// FR-90 P3-8-2b-2 — how `ssh_run` reaches another device, where the
    /// device's owner turned `hive_ssh` on and the vault is offered; without
    /// it `ssh_run` is not offered.
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    pub(crate) ssh: Option<Arc<dyn super::ssh_tools::SshRunner>>,
}

/// What every connection of one session's toolbelt shares.
struct Ctx {
    session: ObjectId,
    /// P3-4b — the run's fence, and its vault tools' answers.
    fence: u64,
    vault: Option<Arc<dyn VaultTools>>,
    /// P3-4c-1 — where `vault_exec` runs a command.
    #[cfg(feature = "vault")]
    exec: Option<super::vault_exec::ExecTarget>,
    /// FR-90 P3-7-3c — where `net_socks` and `net_forward` open their flows.
    #[cfg(feature = "vault")]
    net: Option<crate::tunnel::client_mgr::TunnelClientHub>,
    /// FR-90 P3-8-2b-2 — how `ssh_run` runs its command.
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    ssh: Option<Arc<dyn super::ssh_tools::SshRunner>>,
    /// The only account a connection is taken from: the session's.
    peer: PeerId,
    pending: Arc<Pending>,
    events: mpsc::Sender<ApprovalEvent>,
    timing: Timing,
}

/// FR-90 P3-4b — the vault tools this server offers where the device takes
/// leases: reads of the vault's metadata, never a value.
const VAULT_TOOL_NAMES: [&str; 2] = ["vault_list", "vault_describe"];

/// FR-90 P3-4c — and its uses: a value handed to one command (c-1), or
/// written into the session's secrets directory (c-2), and (P3-5b-2) an
/// endpoint that authenticates with one. Offered with the reads, and asked
/// for in the settings ([`VAULT_USE_TOOLS`]): each call asks a person first.
#[cfg(feature = "vault")]
const VAULT_USE_NAMES: [&str; 3] = ["vault_exec", "vault_render", "vault_connect"];

/// FR-90 P3-4c-3 — and a lease asked for ahead, which a use takes. Allowed
/// in the settings like the reads ([`VAULT_AHEAD_TOOLS`]): it hands the
/// session nothing, and its gate is the vault's own `secret:use`, decided
/// and recorded by the server. Each use of the lease still asks a person.
#[cfg(feature = "vault")]
const VAULT_AHEAD_NAMES: [&str; 1] = ["vault_request"];

/// Whether `name` is one of the vault tools this build offers.
fn is_vault_tool(name: &str) -> bool {
    #[cfg(feature = "vault")]
    if VAULT_USE_NAMES.contains(&name) || VAULT_AHEAD_NAMES.contains(&name) {
        return true;
    }
    VAULT_TOOL_NAMES.contains(&name)
}

/// The vault tools, as Claude Code names them: allowed in the session's
/// settings wherever they are offered, since they read and their gate is the
/// vault's own `secret:list`, not a person's approval.
pub(crate) const VAULT_TOOLS: [&str; 2] =
    ["mcp__roomler__vault_list", "mcp__roomler__vault_describe"];

/// FR-90 P3-4c — the vault's uses, as Claude Code names them: ASKED for in
/// the session's settings (`permissions.ask`) wherever they are offered.
/// Leaving them out of `allow` is not enough: a repository's own
/// `.claude/settings.json` loads too, and an allow there would skip the
/// person. Claude Code reads deny, then ask, then allow, across every
/// settings file, so this ask prompts whatever another file allows.
#[cfg(feature = "vault")]
pub(crate) const VAULT_USE_TOOLS: [&str; 3] = [
    "mcp__roomler__vault_exec",
    "mcp__roomler__vault_render",
    "mcp__roomler__vault_connect",
];

/// FR-90 P3-4c-3 — asking a lease ahead, as Claude Code names it: allowed
/// with the reads wherever it is offered.
#[cfg(feature = "vault")]
pub(crate) const VAULT_AHEAD_TOOLS: [&str; 1] = ["mcp__roomler__vault_request"];

/// FR-90 P3-7-3c — a session's own egress, as its settings name it: asked of
/// a person on every call, like the vault's uses. Each opens a listener this
/// session reaches a network through.
#[cfg(feature = "vault")]
pub(crate) const NET_TOOLS: [&str; 2] = ["mcp__roomler__net_socks", "mcp__roomler__net_forward"];

/// FR-90 P3-8-2b-2 — `ssh_run`, as the session's settings name it: asked of
/// a person on every call. Each runs a command on another device, as the
/// account that device maps.
#[cfg(feature = "vault")]
pub(crate) const SSH_TOOLS: [&str; 1] = ["mcp__roomler__ssh_run"];

/// FR-90 P3-4b — the daemon's vault for a run's toolbelt: its lease client,
/// where the primary connection takes leases; otherwise none, and the vault
/// tools are not offered.
pub(crate) fn daemon_vault() -> Option<Arc<dyn VaultTools>> {
    #[cfg(feature = "vault")]
    if crate::vault::CLIENT.takes_leases() {
        return Some(Arc::new(DaemonVault));
    }
    None
}

#[cfg(feature = "vault")]
struct DaemonVault;

/// Why a vault tool got no answer, for the model.
#[cfg(feature = "vault")]
fn vault_why(e: crate::vault::LeaseError) -> String {
    use crate::vault::LeaseError;
    match e {
        // P3-4e-2 — what the model needs to act on: a person said no, which
        // asking again will not change.
        LeaseError::Refused(word) if word == "denied" => {
            "the vault refused: denied (its policies do not allow this use, or a driver of this \
             session said no to it)"
                .into()
        }
        LeaseError::Refused(word) => format!("the vault refused: {word}"),
        // The tool waited the card's whole window ([`APPROVAL_WINDOW`]).
        LeaseError::AwaitingApproval(id) => format!(
            "this use needs a person's approval, and nobody answered its card in the session's \
             room in time (approval {id}); ask again once a driver is there to answer a new card"
        ),
        LeaseError::NotConnected => "this device is not connected to its server".into(),
        LeaseError::NoAnswer => "the vault did not answer".into(),
        LeaseError::Unopenable => "the vault's answer did not open".into(),
        LeaseError::NotAsked => "the vault's answer granted something other than was asked".into(),
    }
}

/// P3-4e-2 — how long a vault tool waits for a person to answer a card the
/// vault posted for its lease: the card's own window, after which it ends.
#[cfg(feature = "vault")]
pub(crate) const APPROVAL_WINDOW: Duration = Duration::from_secs(
    roomler_ai_remote_control::vault::lease_limits::APPROVAL_ANSWER_SECS as u64,
);

/// P3-4c-3 — a lease ask for `vault_request`, or the query that finds what
/// one leased.
#[cfg(feature = "vault")]
fn ahead_ask(
    session: ObjectId,
    fence: u64,
    handle: &super::vault_exec::Handle,
    mode: &str,
    audience: &str,
    ttl_secs: u32,
) -> crate::vault::LeaseAsk {
    crate::vault::LeaseAsk {
        session_id: session,
        fence,
        secret: handle.secret.clone(),
        field: handle.field.clone(),
        mode: mode.into(),
        audience: audience.into(),
        ttl_secs,
        ahead: true,
    }
}

#[cfg(feature = "vault")]
#[async_trait::async_trait]
impl VaultTools for DaemonVault {
    async fn list(&self, session: ObjectId, fence: u64, prefix: &str) -> Result<Value, String> {
        let l = crate::vault::CLIENT
            .list(session, fence, prefix)
            .await
            .map_err(vault_why)?;
        Ok(json!({ "secrets": l.secrets, "more": l.more }))
    }

    async fn describe(&self, session: ObjectId, fence: u64, secret: &str) -> Result<Value, String> {
        let s = crate::vault::CLIENT
            .describe(session, fence, secret)
            .await
            .map_err(vault_why)?;
        Ok(json!(s))
    }

    async fn lease(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        ttl_secs: u32,
    ) -> Result<String, String> {
        // P3-4e-2 — through a card the vault posts, if its policies ask for
        // a person's yes: the call waits for the answer.
        let info = crate::vault::CLIENT
            .request_until_approved(
                crate::vault::LeaseAsk {
                    session_id: session,
                    fence,
                    secret: handle.secret.clone(),
                    field: handle.field.clone(),
                    mode: mode.into(),
                    audience: audience.into(),
                    ttl_secs,
                    ahead: false,
                },
                APPROVAL_WINDOW,
            )
            .await
            .map_err(vault_why)?;
        Ok(info.lease_id)
    }

    async fn lease_ahead(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        ttl_secs: u32,
    ) -> Result<String, String> {
        let info = crate::vault::CLIENT
            .request_until_approved(
                ahead_ask(session, fence, handle, mode, audience, ttl_secs),
                APPROVAL_WINDOW,
            )
            .await
            .map_err(vault_why)?;
        Ok(info.lease_id)
    }

    fn left(&self, lease_id: &str) -> Option<Duration> {
        crate::vault::CLIENT.left(lease_id)
    }

    fn ahead(
        &self,
        session: ObjectId,
        fence: u64,
        handle: &super::vault_exec::Handle,
        mode: &str,
        audience: &str,
        at_least: Duration,
    ) -> Option<String> {
        crate::vault::CLIENT.find_ahead(
            &ahead_ask(session, fence, handle, mode, audience, 0),
            at_least,
        )
    }

    fn attach(&self, lease_id: &str, path: &std::path::Path) -> bool {
        crate::vault::CLIENT.attach(lease_id, path)
    }

    fn stop_with(&self, lease_id: &str, stop: CancellationToken) -> bool {
        crate::vault::CLIENT.stop_with(lease_id, stop)
    }

    fn value(&self, lease_id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        crate::vault::CLIENT.with_value(lease_id, |v| zeroize::Zeroizing::new(v.to_vec()))
    }

    async fn mint(&self, lease_id: &str) -> Result<(), String> {
        crate::vault::CLIENT.mint(lease_id).await
    }

    fn minted(&self, lease_id: &str, field: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        crate::vault::CLIENT.minted(lease_id, field)
    }

    fn release(&self, lease_ids: &[String]) {
        crate::vault::CLIENT.release(lease_ids);
    }

    fn report(&self, r: crate::vault::Report) {
        crate::vault::CLIENT.report(r);
    }

    async fn net(&self, ask: crate::vault::NetAsk) -> Result<crate::vault::NetGrant, String> {
        crate::vault::CLIENT.net(ask).await.map_err(vault_why)
    }

    #[cfg(feature = "ssh-server")]
    async fn ssh(&self, ask: crate::vault::SshAsk) -> Result<crate::vault::SshTicket, String> {
        crate::vault::CLIENT.ssh(ask).await.map_err(vault_why)
    }
}

/// One session's toolbelt: its socket, its open approvals, and the switch
/// that ends both. Dropping it is the shutdown — the session task owns it,
/// so the toolbelt ends exactly when the session does.
pub(crate) struct Toolbelt {
    /// The socket's path; on Windows the pipe's name (`\\.\pipe\…`).
    socket: PathBuf,
    pending: Arc<Pending>,
    stop: CancellationToken,
}

impl Toolbelt {
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn pending(&self) -> Arc<Pending> {
        Arc::clone(&self.pending)
    }
}

impl Drop for Toolbelt {
    fn drop(&mut self) {
        self.stop.cancel();
        self.pending.withdraw_all();
        // A pipe is gone with its last instance; a socket stays a file.
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Bind `dir/toolbelt.sock` for one session and start serving it.
///
/// `owner` is the account the socket is handed to (`None` keeps the
/// daemon's, for a session that runs as the daemon — tests only); `uid` is
/// the one peer a connection is taken from.
#[cfg(unix)]
pub(crate) fn open(
    dir: &Path,
    owner: Option<(u32, u32)>,
    uid: u32,
    run: Run,
    events: mpsc::Sender<ApprovalEvent>,
    timing: Timing,
) -> Result<Toolbelt, String> {
    let socket = dir.join(SOCKET);
    // A socket left by an earlier run of the same session is removed; anything
    // else in its place — a link, a file — is refused, never followed.
    match std::fs::symlink_metadata(&socket) {
        Ok(m) => {
            use std::os::unix::fs::FileTypeExt;
            if !m.file_type().is_socket() {
                return Err(format!("{} is not a socket", socket.display()));
            }
            std::fs::remove_file(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", socket.display())),
    }
    let listener = UnixListener::bind(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    // Bound under the daemon's umask: until these two calls, only the daemon
    // can connect. Then the session's account, and nobody else.
    let handed = owner
        .map(|(u, g)| std::os::unix::fs::chown(&socket, Some(u), Some(g)))
        .unwrap_or(Ok(()))
        .and_then(|()| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        });
    if let Err(e) = handed {
        let _ = std::fs::remove_file(&socket);
        return Err(format!("{}: {e}", socket.display()));
    }
    let pending = Arc::new(Pending::default());
    let stop = CancellationToken::new();
    let ctx = Arc::new(Ctx {
        session: run.session,
        fence: run.fence,
        vault: run.vault,
        #[cfg(feature = "vault")]
        exec: run.exec,
        #[cfg(feature = "vault")]
        net: run.net,
        #[cfg(all(feature = "vault", feature = "ssh-server"))]
        ssh: run.ssh,
        peer: uid,
        pending: Arc::clone(&pending),
        events,
        timing,
    });
    tokio::spawn(serve(listener, ctx, stop.clone()));
    Ok(Toolbelt {
        socket,
        pending,
        stop,
    })
}

#[cfg(unix)]
async fn serve(listener: UnixListener, ctx: Arc<Ctx>, stop: CancellationToken) {
    loop {
        let got = tokio::select! {
            _ = stop.cancelled() => return,
            got = listener.accept() => got,
        };
        match got {
            Ok((stream, _)) => match stream.peer_cred() {
                Ok(c) if c.uid() == ctx.peer => {
                    let (rd, wr) = stream.into_split();
                    tokio::spawn(connection(rd, wr, Arc::clone(&ctx), stop.child_token()));
                }
                Ok(c) => warn!(
                    session = %ctx.session, uid = c.uid(),
                    "hive: a toolbelt connection from another account — refused"
                ),
                Err(e) => {
                    warn!(session = %ctx.session, %e, "hive: a toolbelt peer could not be identified — refused")
                }
            },
            Err(e) => {
                // Out of descriptors and the like: back off rather than spin.
                warn!(session = %ctx.session, %e, "hive: the toolbelt could not accept");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// P1i-2 — one session's toolbelt on Windows: a named pipe,
/// `\\.\pipe\roomler-hive-<session>-<nonce>`, made with
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name someone already holds is
/// refused, never joined. Its DACL ([`crate::hive_win::toolbelt_pipe_sddl`])
/// admits SYSTEM and Administrators (the daemon is one or the other), and the
/// session's account (`peer`, a SID) to read and write, and no remote client.
/// Each client's account is checked again, as Unix checks a uid, so an
/// administrator connecting is taken only when it is the session's account.
#[cfg(windows)]
pub(crate) fn open(
    peer: PeerId,
    run: Run,
    events: mpsc::Sender<ApprovalEvent>,
    timing: Timing,
) -> Result<Toolbelt, String> {
    let session = run.session;
    let name = format!(
        r"\\.\pipe\roomler-hive-{}-{}",
        session.to_hex(),
        hex::encode(rand::random::<[u8; 16]>())
    );
    let sddl = crate::hive_win::toolbelt_pipe_sddl(&peer);
    let first = pipe_instance(&name, &sddl, true).map_err(|e| format!("{name}: {e}"))?;
    let pending = Arc::new(Pending::default());
    let stop = CancellationToken::new();
    let ctx = Arc::new(Ctx {
        session,
        fence: run.fence,
        vault: run.vault,
        #[cfg(feature = "vault")]
        exec: run.exec,
        #[cfg(feature = "vault")]
        net: run.net,
        #[cfg(all(feature = "vault", feature = "ssh-server"))]
        ssh: run.ssh,
        peer,
        pending: Arc::clone(&pending),
        events,
        timing,
    });
    tokio::spawn(serve_pipe(first, name.clone(), sddl, ctx, stop.clone()));
    Ok(Toolbelt {
        socket: PathBuf::from(name),
        pending,
        stop,
    })
}

/// One listening instance of a toolbelt's pipe, or (P3-5f-3) of a vault SSH
/// agent's, under `sddl`, local clients only.
#[cfg(windows)]
pub(crate) fn pipe_instance(
    name: &str,
    sddl: &str,
    first: bool,
) -> std::io::Result<NamedPipeServer> {
    let mut sd = crate::hive_win::Sddl::new(sddl)?;
    // SAFETY: the attributes live in `sd` across the call, and the system
    // copies the descriptor into the instance.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, sd.attributes().cast())
    }
}

#[cfg(windows)]
async fn serve_pipe(
    mut server: NamedPipeServer,
    name: String,
    sddl: String,
    ctx: Arc<Ctx>,
    stop: CancellationToken,
) {
    use std::os::windows::io::AsRawHandle;
    loop {
        let got = tokio::select! {
            _ = stop.cancelled() => return,
            got = server.connect() => got,
        };
        // The next instance before this client is looked at, so a second
        // connection always finds one listening.
        let next = match pipe_instance(&name, &sddl, false) {
            Ok(next) => next,
            Err(e) => {
                warn!(session = %ctx.session, %e, "hive: the toolbelt pipe takes no more connections");
                return;
            }
        };
        let client = std::mem::replace(&mut server, next);
        if let Err(e) = got {
            warn!(session = %ctx.session, %e, "hive: the toolbelt could not accept");
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        match crate::hive_win::pipe_client_sid(client.as_raw_handle() as _) {
            Ok(sid) if sid == ctx.peer => {
                let (rd, wr) = tokio::io::split(client);
                tokio::spawn(connection(rd, wr, Arc::clone(&ctx), stop.child_token()));
            }
            Ok(sid) => warn!(
                session = %ctx.session, %sid,
                "hive: a toolbelt connection from another account — refused"
            ),
            Err(e) => {
                warn!(session = %ctx.session, %e, "hive: a toolbelt peer could not be identified — refused")
            }
        }
    }
}

fn reply(id: &Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

fn error(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// The one tool, as `tools/list` describes it. Claude Code keeps the
/// permission-prompt tool out of the model's own tool list (measured), so
/// this is read by the harness, not the model.
fn approve_tool() -> Value {
    json!({
        "name": "approve",
        "description": "Asks a driver of this Roomler session whether a tool call may run. \
                        Claude Code calls it before any tool call that needs approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
                "input": {"type": "object"},
                "tool_use_id": {"type": "string"},
            },
            "required": ["tool_name", "input"],
        },
    })
}

/// FR-90 P3-4b — the vault tools, as `tools/list` describes them: offered
/// only where this device takes leases. The reads, and from P3-4c the uses
/// (`vault_exec`, `vault_render`) and a lease asked for ahead
/// (`vault_request`).
fn vault_tools() -> Vec<Value> {
    #[cfg_attr(not(feature = "vault"), allow(unused_mut))]
    let mut tools = vec![
        json!({
            "name": "vault_list",
            "description": "Lists the Roomler vault secrets this session's role may list, under a \
                            folder when one is given: each one's RRN, kind, fields, audiences, \
                            and the programs a value may be handed to. Never a value.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prefix": {"type": "string", "description": "a folder, such as db/"},
                },
            },
            "annotations": {"readOnlyHint": true},
        }),
        json!({
            "name": "vault_describe",
            "description": "Describes one Roomler vault secret this session's role may list, by \
                            its path or RRN: its kind, fields, audiences, the programs a value \
                            may be handed to, and whether it is disabled. Never a value.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "secret": {"type": "string", "description": "a path, or rrn:<org>:secret:<path>"},
                },
                "required": ["secret"],
            },
            "annotations": {"readOnlyHint": true},
        }),
    ];
    #[cfg(feature = "vault")]
    tools.push(json!({
        "name": "vault_exec",
        "description": "Runs one command with values from the Roomler vault in its environment, \
                        as this session's account, from its folder. argv[0] is the program's bare \
                        name: it must be on each stored secret's exec_allow, and installed in the \
                        system's own directories. env maps each variable to a secret (a path, or \
                        rrn:<org>:secret:<path>, with #<field> for a structured secret's field). \
                        A dynamic secret (vault_describe names its provider) gives each variable \
                        naming it a field of one credential minted for this call, such as #user \
                        and #password, taken back when the call ends. The output comes back with \
                        each value replaced by [vault:NAME]. A person approves every call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "argv": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 64,
                    "description": "the program's bare name, then its arguments",
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "NAME → secret, such as {\"PGPASSWORD\": \"db/main#password\"}",
                },
                "timeout_s": {"type": "integer", "minimum": 1, "maximum": 300},
            },
            "required": ["argv", "env"],
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
    }));
    #[cfg(feature = "vault")]
    tools.push(json!({
        "name": "vault_render",
        "description": "Writes a template with values from the Roomler vault into this session's \
                        secrets directory, as a file only this session's account can read, and \
                        answers its path. Put each secret in the template as {{ a/path }} (or \
                        {{ rrn:<org>:secret:<path>#<field> }}). A dynamic secret's placeholders \
                        are written from one credential minted for the file. The file is removed \
                        when its lease ends (ttl_s, 30 to 900 seconds), and a minted credential \
                        is taken back with it. Claude Code's Read tool may not \
                        open it: hand its path to the program that needs it. A person approves \
                        every call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "template": {"type": "string", "description": "the file's text, with {{ secret }} placeholders"},
                "dest": {"type": "string", "description": "a bare file name, such as kubeconfig"},
                "ttl_s": {"type": "integer", "minimum": 30, "maximum": 900},
            },
            "required": ["template", "dest"],
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false},
    }));
    #[cfg(feature = "vault")]
    tools.push(json!({
        "name": "vault_connect",
        "description": "Opens an endpoint on this device that signs in to a database (Postgres or \
                        MongoDB) as a Roomler vault secret's user; that presents a secret's \
                        credential on every request it sends on to an HTTP upstream (an API, a \
                        git server) or a Kubernetes API server; or that is an SSH agent holding \
                        a secret's key, which signs ssh in to one host; and answers how to \
                        connect to it. A database client connects with the answer's uri (or \
                        host and port), with any user name and no password; an HTTP client sends \
                        its requests to the uri with no credential, and git takes the answer's \
                        env and the upstream's own URLs; kubectl takes the answer's kubeconfig, \
                        written to a file of your own and named in KUBECONFIG; ssh (OpenSSH 8.9 \
                        or later) takes the answer's env, SSH_AUTH_SOCK, and its known_hosts, \
                        written to a file of your own and named in -o UserKnownHostsFile. \
                        Nothing it answers holds the secret's value. handle names a structured \
                        secret: user and password fields (a database, or auth basic), a token \
                        field (auth bearer), cert and key fields (auth client-cert, PEM), or key \
                        and host_keys fields (ssh: an OpenSSH private key, and the host's public \
                        keys). upstream is exactly as the secret's audiences name it: the \
                        database's host:port; for http and kubernetes an origin, https://host or \
                        https://host:port; for ssh, ssh://host, ssh://host:port or \
                        ssh://user@host. ca names a secret holding the upstream's CA certificate \
                        (PEM) when the system does not trust it. The endpoint closes with its \
                        lease (ttl_s, 30 to 900 seconds). A dynamic secret is not served here: \
                        vault_exec and vault_render serve it. A person approves every call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "handle": {"type": "string", "description": "a structured secret: a path or rrn:<org>:secret:<path>, with no #field"},
                "engine": {"type": "string", "enum": ["postgres", "mongodb", "http", "kubernetes", "ssh"]},
                "upstream": {"type": "string", "description": "a database's host:port, such as db.internal:5432; for http and kubernetes an origin, such as https://github.com or https://k8s.internal:6443; for ssh, such as ssh://git@github.com or ssh://deploy@build.internal:2222"},
                "auth": {"type": "string", "enum": ["basic", "bearer", "client-cert"], "description": "http and kubernetes: the secret's user and password (basic, http only) or its token (bearer), sent as Authorization, or its cert and key (client-cert), presented in the TLS handshake"},
                "database": {"type": "string", "description": "the database to name in the connection string"},
                "ca": {"type": "string", "description": "a secret whose value is the upstream's CA certificate, PEM"},
                "auth_source": {"type": "string", "description": "mongodb: the database the secret's user is defined in (default admin)"},
                "ttl_s": {"type": "integer", "minimum": 30, "maximum": 900},
            },
            "required": ["handle", "engine", "upstream"],
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
    }));
    #[cfg(feature = "vault")]
    tools.push(json!({
        "name": "vault_request",
        "description": "Asks the Roomler vault for a lease ahead of using it, and answers the \
                        lease's id and how long it lasts, never a value. mode is exec (for \
                        vault_exec, audience the program's bare name), file (for vault_render, \
                        audience the file's bare name) or proxy (for vault_connect, audience the \
                        upstream as it names it, a database's host:port, an origin for http \
                        and kubernetes, or an ssh:// host, one lease per field it signs in \
                        with: #user and #password, #token, #cert and #key, or #key and \
                        #host_keys). A later use that names the same \
                        secret toward the same \
                        audience takes this lease instead of asking again, while it lasts \
                        (ttl_s, 30 to 900 seconds). A dynamic secret is asked for whole, in \
                        short-lived mode, for exec or file alike: its first use mints its \
                        credential, and every later use shares it. Each of those calls still \
                        asks a person.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "handle": {"type": "string", "description": "a secret: a path or rrn:<org>:secret:<path>, with #<field> for a structured secret's field"},
                "mode": {"type": "string", "enum": ["exec", "file", "proxy"]},
                "audience": {"type": "string", "description": "exec: the program's bare name, such as psql; file: the file's bare name, such as kubeconfig; proxy: the upstream's host:port, for http and kubernetes its origin, such as https://github.com, or for ssh its host, such as ssh://git@github.com"},
                "ttl_s": {"type": "integer", "minimum": 30, "maximum": 900},
            },
            "required": ["handle", "mode", "audience"],
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false},
    }));
    tools
}

/// FR-90 P3-7-3c — a session's own egress: SOCKS through an exit, or a
/// forward to one destination, each a loopback listener served to the
/// session's account alone. Offered where the device's owner turned
/// `hive_net` on and the vault is offered ([`Run::net`]).
#[cfg(feature = "vault")]
fn net_tools() -> Vec<Value> {
    let exit = json!({"type": "string", "description": "the id of the Roomler device of this organization the flows leave from (24 hex characters)"});
    let ttl = json!({"type": "integer", "minimum": 30, "maximum": 900});
    vec![
        json!({
            "name": super::net_tools::SOCKS,
            "description": "Opens a SOCKS5 proxy on this device whose connections leave from another \
                            Roomler device of the organization (exit), as the organization's vault \
                            and tunnel policies allow this session, and answers its proxy URL, \
                            socks5h://user:password@127.0.0.1:port (curl -x, or ALL_PROXY), and how \
                            long it serves. Only this session's account may connect, with the URL's \
                            credential, and only CONNECT: no UDP. It closes at its end (ttl_s, 30 to \
                            900 seconds), and every connection with it. A person approves every call.",
            "inputSchema": {
                "type": "object",
                "properties": {"exit": exit, "ttl_s": ttl},
                "required": ["exit"],
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true},
        }),
        json!({
            "name": super::net_tools::FORWARD,
            "description": "Opens a port on this device's loopback that forwards to one destination \
                            (host:port) from another Roomler device of the organization (exit), as \
                            the organization's vault and tunnel policies allow this session, and \
                            answers the address to connect to and how long it serves. Only this \
                            session's account may connect. It closes at its end (ttl_s, 30 to 900 \
                            seconds), and every connection with it. A person approves every call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "exit": exit,
                    "host": {"type": "string", "description": "the destination's host, a name or an address, as the exit resolves it"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "ttl_s": ttl,
                },
                "required": ["exit", "host", "port"],
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": true},
        }),
    ]
}

/// FR-90 P3-8-2b-2 — one command on another device of the organization over
/// Roomler SSH. Offered where the device's owner turned `hive_ssh` on and the
/// vault is offered ([`Run::ssh`]).
#[cfg(all(feature = "vault", feature = "ssh-server"))]
fn ssh_tools() -> Vec<Value> {
    use super::ssh_tools::{DEFAULT_TIMEOUT_SECS, RUN};
    use crate::ssh_client::{MAX_COMMAND, MAX_TIMEOUT_SECS};
    vec![json!({
        "name": RUN,
        "description": format!(
            "Runs one command on another Roomler device of the organization (device) over \
             Roomler SSH, as the account that device's SSH policy maps, which may be SYSTEM or \
             root there, and answers the device's os, the account it ran as, the exit code, \
             stdout and stderr (each at most 64 KiB, truncated says whether either was cut). \
             The organization's vault decides whether this session may, and the device's own \
             gates still hold: a person there may be asked first. command is one line of at \
             most {MAX_COMMAND} bytes for the device's own shell, PowerShell on Windows and bash \
             elsewhere; there is no terminal and no input. timeout_s bounds the command (1 to \
             {MAX_TIMEOUT_SECS} seconds, {DEFAULT_TIMEOUT_SECS} if not given). A person approves \
             every call."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "the id of the Roomler device of this organization to run on (24 hex characters), never this one"},
                "command": {"type": "string", "description": "the command, one line, for that device's shell"},
                "timeout_s": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECS},
            },
            "required": ["device", "command"],
        },
        "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
    })]
}

/// One vault tool call, from asking to answering: what the vault says, as
/// text, or why it said nothing, as an error the model reads.
async fn vault_tool(
    ctx: Arc<Ctx>,
    id: Value,
    name: String,
    args: Value,
    out: mpsc::Sender<String>,
    calls: Calls,
    cancel: CancellationToken,
) {
    let key = id.to_string();
    let answered = tokio::select! {
        a = ask_vault(&ctx, &name, &args) => Some(a),
        _ = cancel.cancelled() => None,
    };
    calls.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
    // A cancelled request gets no answer (MCP); a closed one cannot.
    let Some(answered) = answered else {
        return;
    };
    let result = match answered {
        Ok(v) => json!({"content": [{"type": "text", "text": v.to_string()}]}),
        Err(why) => json!({"content": [{"type": "text", "text": why}], "isError": true}),
    };
    let _ = out.send(reply(&id, result)).await;
}

/// What the vault answers one vault tool call, for the session's run.
async fn ask_vault(ctx: &Ctx, name: &str, args: &Value) -> Result<Value, String> {
    let Some(vault) = &ctx.vault else {
        return Err("this device offers no vault".into());
    };
    #[cfg(feature = "vault")]
    if name == "vault_exec" {
        return super::vault_exec::call(
            vault.as_ref(),
            ctx.session,
            ctx.fence,
            ctx.exec.as_ref(),
            args,
        )
        .await;
    }
    #[cfg(feature = "vault")]
    if name == "vault_render" {
        return super::vault_render::call(
            vault.as_ref(),
            ctx.session,
            ctx.fence,
            ctx.exec.as_ref(),
            args,
        )
        .await;
    }
    #[cfg(feature = "vault")]
    if name == "vault_request" {
        return super::vault_request::call(vault.as_ref(), ctx.session, ctx.fence, args).await;
    }
    #[cfg(feature = "vault")]
    if name == super::net_tools::SOCKS || name == super::net_tools::FORWARD {
        let Some(hub) = &ctx.net else {
            return Err("this device offers its sessions no egress (hive_net)".into());
        };
        #[cfg(unix)]
        let peer = ctx.peer;
        #[cfg(windows)]
        let peer = ctx.peer.clone();
        return super::net_tools::call(
            name,
            vault.as_ref(),
            hub,
            ctx.session,
            ctx.fence,
            peer,
            args,
        )
        .await;
    }
    #[cfg(all(feature = "vault", feature = "ssh-server"))]
    if name == super::ssh_tools::RUN {
        let Some(runner) = &ctx.ssh else {
            return Err("this device offers its sessions no SSH (hive_ssh)".into());
        };
        return super::ssh_tools::call(
            vault.as_ref(),
            runner.as_ref(),
            ctx.session,
            ctx.fence,
            args,
        )
        .await;
    }
    #[cfg(feature = "vault")]
    if name == "vault_connect" {
        return super::vault_connect::call(
            Arc::clone(vault),
            ctx.session,
            ctx.fence,
            ctx.exec.as_ref(),
            &ctx.peer,
            args,
        )
        .await;
    }
    if name == "vault_list" {
        let prefix = args.get("prefix").and_then(Value::as_str).unwrap_or("");
        return vault.list(ctx.session, ctx.fence, prefix).await;
    }
    match args.get("secret").and_then(Value::as_str) {
        Some(secret) if !secret.is_empty() => vault.describe(ctx.session, ctx.fence, secret).await,
        _ => Err("secret is required: a path, or rrn:<org>:secret:<path>".into()),
    }
}

/// The `initialize` result: the client's version when this server knows it,
/// else the newest it does.
fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = asked
        .filter(|v| PROTOCOL_VERSIONS.contains(v))
        .unwrap_or(PROTOCOL_VERSIONS[PROTOCOL_VERSIONS.len() - 1]);
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "roomler", "version": env!("CARGO_PKG_VERSION")},
    })
}

/// In-flight calls on one connection, by request id, so a cancellation can
/// name one.
type Calls = Arc<Mutex<HashMap<String, CancellationToken>>>;

async fn connection(
    rd: impl AsyncRead + Unpin + Send + 'static,
    mut wr: impl AsyncWrite + Unpin + Send + 'static,
    ctx: Arc<Ctx>,
    stop: CancellationToken,
) {
    let (out, mut outbox) = mpsc::channel::<String>(64);
    let writer = tokio::spawn(async move {
        while let Some(line) = outbox.recv().await {
            if wr.write_all(line.as_bytes()).await.is_err() || wr.write_all(b"\n").await.is_err() {
                break;
            }
        }
    });
    let calls: Calls = Default::default();
    let mut lines = LineReader::new(BufReader::new(rd), MAX_MESSAGE);
    loop {
        let line = tokio::select! {
            _ = stop.cancelled() => break,
            line = lines.next_line() => line,
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) | Err(_) => break,
        };
        if line.is_empty() {
            // Blank, or longer than any message this server takes.
            continue;
        }
        let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
            let _ = out.send(error(&Value::Null, -32700, "not JSON")).await;
            continue;
        };
        on_message(&ctx, &out, &calls, &stop, msg).await;
    }
    // The harness let go: whatever it was still waiting for is withdrawn.
    let waiting: Vec<CancellationToken> = calls
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drain()
        .map(|(_, t)| t)
        .collect();
    for t in waiting {
        t.cancel();
    }
    drop(out);
    let _ = writer.await;
}

async fn on_message(
    ctx: &Arc<Ctx>,
    out: &mpsc::Sender<String>,
    calls: &Calls,
    stop: &CancellationToken,
    msg: Value,
) {
    let method = msg.get("method").and_then(Value::as_str);
    let id = msg.get("id").filter(|i| !i.is_null()).cloned();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let (Some(method), Some(id)) = (method, id) else {
        // A notification, or a response to a request this server never
        // makes.
        if method == Some("notifications/cancelled") {
            let named = params.get("requestId").map(Value::to_string);
            if let Some(key) = named
                && let Some(t) = calls.lock().unwrap_or_else(|e| e.into_inner()).remove(&key)
            {
                t.cancel();
            }
        }
        return;
    };
    let answer = match method {
        "initialize" => reply(&id, initialize(&params)),
        "ping" => reply(&id, json!({})),
        "tools/list" => {
            let mut tools = vec![approve_tool()];
            if ctx.vault.is_some() {
                tools.extend(vault_tools());
            }
            // FR-90 P3-7-3c — a session's own egress, where the owner offers it.
            #[cfg(feature = "vault")]
            if ctx.vault.is_some() && ctx.net.is_some() {
                tools.extend(net_tools());
            }
            // FR-90 P3-8-2b-2 — and one command on another device, likewise.
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            if ctx.vault.is_some() && ctx.ssh.is_some() {
                tools.extend(ssh_tools());
            }
            reply(&id, json!({ "tools": tools }))
        }
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            #[cfg(feature = "vault")]
            let net = ctx.net.is_some()
                && (name == super::net_tools::SOCKS || name == super::net_tools::FORWARD);
            #[cfg(not(feature = "vault"))]
            let net = false;
            #[cfg(all(feature = "vault", feature = "ssh-server"))]
            let ssh = ctx.ssh.is_some() && name == super::ssh_tools::RUN;
            #[cfg(not(all(feature = "vault", feature = "ssh-server")))]
            let ssh = false;
            let vault = ctx.vault.is_some() && (is_vault_tool(name) || net || ssh);
            if name != "approve" && !vault {
                error(&id, -32602, "unknown tool")
            } else {
                let cancel = stop.child_token();
                calls
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.to_string(), cancel.clone());
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);
                if vault {
                    tokio::spawn(vault_tool(
                        Arc::clone(ctx),
                        id,
                        name.to_string(),
                        args,
                        out.clone(),
                        Arc::clone(calls),
                        cancel,
                    ));
                    return;
                }
                let progress = params
                    .get("_meta")
                    .and_then(|m| m.get("progressToken"))
                    .cloned();
                tokio::spawn(approve(
                    Arc::clone(ctx),
                    id,
                    args,
                    progress,
                    out.clone(),
                    Arc::clone(calls),
                    cancel,
                ));
                return;
            }
        }
        // `server/discover` among them: Claude Code probes with it and, told
        // no, initializes (measured). Silence here would stall its start.
        _ => error(&id, -32601, "method not found"),
    };
    let _ = out.send(answer).await;
}

fn new_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

fn clamp(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_NAME)
        .collect()
}

/// What the model is told for each way an approval ends but "allowed".
fn denial(ended: &Ended, timeout: Duration) -> String {
    match ended {
        Ended::Answered(Answer {
            decision: Decision::Deny { message: Some(m) },
            by,
        }) => format!("{} denied this: {m}", by.name),
        Ended::Answered(Answer { by, .. }) => format!("{} denied this tool call.", by.name),
        Ended::Expired => {
            let secs = timeout.as_secs();
            let waited = if secs >= 60 {
                format!("{} minutes", secs / 60)
            } else {
                format!("{secs} seconds")
            };
            format!(
                "Nobody answered this approval within {waited}, so it did not run. If it is \
                 still needed, say so in your reply."
            )
        }
        Ended::Withdrawn => "This approval was withdrawn before anyone answered.".to_string(),
    }
}

/// One `approve` call, from asking to answering.
#[allow(clippy::too_many_arguments)]
async fn approve(
    ctx: Arc<Ctx>,
    id: Value,
    args: Value,
    progress: Option<Value>,
    out: mpsc::Sender<String>,
    calls: Calls,
    cancel: CancellationToken,
) {
    let key = id.to_string();
    let verdict = run_approval(&ctx, &args, progress.as_ref(), &out, &cancel).await;
    calls.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
    // A cancelled request gets no answer (MCP); a closed one cannot.
    if !cancel.is_cancelled() {
        let text = verdict.to_string();
        let _ = out
            .send(reply(
                &id,
                json!({"content": [{"type": "text", "text": text}]}),
            ))
            .await;
    }
}

/// Open the approval, wait for its end, record it, and say what the harness
/// is to do.
async fn run_approval(
    ctx: &Ctx,
    args: &Value,
    progress: Option<&Value>,
    out: &mpsc::Sender<String>,
    cancel: &CancellationToken,
) -> Value {
    let deny = |message: String| json!({"behavior": "deny", "message": message});
    let tool_name = clamp(args.get("tool_name").and_then(Value::as_str).unwrap_or(""));
    if tool_name.is_empty() {
        return deny("The approval request named no tool.".into());
    }
    // Taken out of the model's tools at launch; if it comes anyway, the
    // answer it needs is the person's choices, which no card here asks for.
    if tool_name == "AskUserQuestion" {
        return deny(
            "This session cannot show structured questions. Ask in plain text in your reply \
             instead."
                .into(),
        );
    }
    let input = args.get("input").cloned().unwrap_or_else(|| json!({}));
    let tool_use_id = args
        .get("tool_use_id")
        .and_then(Value::as_str)
        .map(clamp)
        .filter(|s| !s.is_empty());
    let approval = new_id();
    let Some(mut answered) = ctx.pending.open(&approval) else {
        warn!(session = %ctx.session, "hive: too many approvals open — one refused");
        return deny("Too many approvals are already waiting in this session.".into());
    };
    let opened = ApprovalEvent::Opened {
        id: approval.clone(),
        tool_name: tool_name.clone(),
        tool_use_id,
        input: input.clone(),
    };
    if ctx.events.send(opened).await.is_err() {
        // The session task is gone: the session is ending.
        ctx.pending.forget(&approval);
        return deny(denial(&Ended::Withdrawn, ctx.timing.timeout));
    }
    info!(session = %ctx.session, %approval, tool = %tool_name, "hive: approval asked");

    let deadline = tokio::time::sleep(ctx.timing.timeout);
    tokio::pin!(deadline);
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + ctx.timing.progress_every,
        ctx.timing.progress_every,
    );
    let mut step: u64 = 0;
    let mut ended = loop {
        tokio::select! {
            got = &mut answered => break match got {
                Ok(a) => Ended::Answered(a),
                Err(_) => Ended::Withdrawn,
            },
            _ = &mut deadline => break Ended::Expired,
            _ = cancel.cancelled() => break Ended::Withdrawn,
            _ = tick.tick(), if progress.is_some() => {
                step += 1;
                let note = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": progress,
                        "progress": step,
                        "message": "waiting for a person to answer",
                    },
                });
                let _ = out.send(note.to_string()).await;
            }
        }
    };
    ctx.pending.forget(&approval);
    // An answer that landed as the clock ran out still counts: the person
    // answered in time.
    if matches!(ended, Ended::Expired)
        && let Ok(a) = answered.try_recv()
    {
        ended = Ended::Answered(a);
    }
    let verdict = match &ended {
        Ended::Answered(Answer {
            decision: Decision::Allow,
            ..
        }) => json!({"behavior": "allow", "updatedInput": input}),
        other => deny(denial(other, ctx.timing.timeout)),
    };
    match &ended {
        Ended::Answered(a) => info!(
            session = %ctx.session, %approval, allowed = (a.decision == Decision::Allow),
            by = %a.by.user_id, "hive: approval answered"
        ),
        Ended::Expired => info!(session = %ctx.session, %approval, "hive: approval expired"),
        Ended::Withdrawn => debug!(session = %ctx.session, %approval, "hive: approval withdrawn"),
    }
    let _ = ctx
        .events
        .send(ApprovalEvent::Closed {
            id: approval,
            ended,
        })
        .await;
    verdict
}

// ─── The relay: what Claude Code starts as the session's MCP server ─────────

/// `meshharbord hive-mcp <socket>` → the socket, or `None` for every other
/// invocation. Read from raw argv, like the embedded CLI, so the relay runs
/// none of the daemon's start-up: it is started by Claude Code, as the
/// session's account, once per session.
pub fn relay_args() -> Option<PathBuf> {
    let mut it = std::env::args_os();
    let _exe = it.next()?;
    if it.next()? != RELAY_SUBCOMMAND {
        return None;
    }
    let socket = it.next()?;
    if it.next().is_some() {
        return None;
    }
    Some(PathBuf::from(socket))
}

/// Pipe this process's stdin and stdout to the session's toolbelt until
/// either side ends. The relay is bytes only: every message is read, bounded
/// and answered by the daemon.
pub async fn relay(socket: &Path) -> anyhow::Result<()> {
    relay_io(socket, tokio::io::stdin(), tokio::io::stdout()).await
}

/// The toolbelt's two halves for a client (the relay, a test): the socket.
#[cfg(unix)]
pub(crate) async fn connect(
    socket: &Path,
) -> std::io::Result<(
    tokio::net::unix::OwnedReadHalf,
    tokio::net::unix::OwnedWriteHalf,
)> {
    Ok(UnixStream::connect(socket).await?.into_split())
}

/// On Windows (P1i-2): the pipe, opened with exactly the access its DACL
/// grants. The instant every instance is taken (the server makes the next one
/// as it takes a client) is waited out, briefly.
#[cfg(windows)]
pub(crate) async fn connect(
    name: &Path,
) -> std::io::Result<(
    tokio::io::ReadHalf<NamedPipeClient>,
    tokio::io::WriteHalf<NamedPipeClient>,
)> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match crate::hive_win::open_toolbelt_pipe(name) {
            Ok(c) => return Ok(tokio::io::split(c)),
            Err(e)
                if e.raw_os_error()
                    == Some(windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn relay_io(
    socket: &Path,
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
) -> anyhow::Result<()> {
    let (mut rd, mut wr) = connect(socket).await.with_context(|| {
        format!(
            "the session's toolbelt at {} is unreachable",
            socket.display()
        )
    })?;
    let up = async {
        let _ = tokio::io::copy(&mut input, &mut wr).await;
        let _ = wr.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut rd, &mut output).await;
        let _ = output.flush().await;
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
