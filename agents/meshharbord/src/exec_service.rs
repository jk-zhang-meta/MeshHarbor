// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-94 — Fleet RPC as SYSTEM on Windows, the device's half
//! (`docs/fr/FR-94-fleet-rpc-system-on-windows.md`).
//!
//! On an attended install the worker, the process that holds the agent
//! socket, runs as the signed-in user, and everything it reads (the agent
//! token, the server origin, `exec_enabled`) sits in that user's writable
//! `%APPDATA%`. So the SYSTEM service in session 0 trusts none of it:
//!
//! - **The anchor** (`%ProgramData%\roomler\roomler\exec-service\anchor.json`)
//!   is the service's ONLY source of the server origin, the device, and its
//!   own credential. An elevated administrator writes it
//!   (`roomlerd anchor create`), and the service reads it only from a file
//!   and a directory owned by SYSTEM or Administrators that grant nobody
//!   else write: a folder a standard user made there first is never
//!   trusted ([`load_anchor`]).
//! - **The doorbell** (`\\.\pipe\roomler-exec-service`) carries a request id
//!   and nothing else. The service claims the command from the server with
//!   its own credential, runs it, and posts the result to the server itself,
//!   so SYSTEM's output never passes through a process the user owns.
//! - **The worker** asks the person (consent), rings, and advertises
//!   `exec-system` only on the connection of the device the service is
//!   anchored for ([`advertised_for`]).
//!
//! ⚠️ Nothing the signed-in user can write may decide what SYSTEM runs
//! (FR-94 §4). A forged ring claims nothing the server did not queue for this
//! device; a squatted pipe is refused by its owner, and a planted anchor by
//! its owner and its DACL.
//!
//! Gate 4 has two halves on this path, and both must say yes: the person's
//! `exec_enabled`, checked by the worker before it rings, exactly as for a
//! command it runs itself, and the anchor's `exec_enabled`, the machine
//! administrator's, checked by the service before it claims.

use serde::{Deserialize, Serialize};

/// The doorbell's pipe. One per machine, like the daemon.
pub const PIPE_NAME: &str = r"\\.\pipe\roomler-exec-service";

/// `ROOMLERD_EXEC_VIA_SERVICE=0` (or `false`/`off`/`no`) withdraws
/// `exec-system` from every connection, so the server routes nothing to the
/// service. The FR's P3 kill switch.
pub const KILL_SWITCH_ENV: &str = "ROOMLERD_EXEC_VIA_SERVICE";

/// The anchor file's schema version.
const ANCHOR_VERSION: u32 = 1;

/// A request or a reply on the doorbell is one line; anything longer is
/// refused unread.
const MAX_LINE: usize = 4 * 1024;

/// Renew the service credential once fewer than this many seconds of its
/// one-year life are left.
const RENEW_BEFORE_SECS: i64 = 120 * 24 * 60 * 60;

/// Is the kill switch set? Only an explicit "off" spelling counts: an unset
/// or unparseable value leaves the feature as the anchor says.
pub fn disabled_by(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("0" | "false" | "off" | "no")
    )
}

/// A Mongo ObjectId in hex: every id this module puts in a URL path or
/// compares (request, device, org). Strict, so a ring cannot smuggle a path
/// into the claim URL.
pub fn valid_object_id(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The server origin the service may talk to, normalised (no trailing `/`).
///
/// HTTPS only, except a loopback test server: the claim's answer IS the
/// command SYSTEM runs, so a plain-HTTP origin would let anyone on the path
/// hand SYSTEM a command of their choosing.
pub fn origin_ok(server: &str) -> Result<String, String> {
    let url =
        reqwest::Url::parse(server.trim()).map_err(|e| format!("{server:?} is not a URL: {e}"))?;
    let host = url.host_str().unwrap_or_default();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        other => {
            return Err(format!(
                "the SYSTEM service talks to its server over https only, not {other}: the \
                 server's answer is the command SYSTEM runs (plain http is allowed for a \
                 loopback test server only)"
            ));
        }
    }
    if url.query().is_some() || url.fragment().is_some() || host.is_empty() {
        return Err(format!(
            "{server:?} must be a bare origin, like https://roomler.ai"
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// What an elevated administrator wrote, and all the SYSTEM service trusts.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Anchor {
    pub version: u32,
    /// The server's origin: where the service claims commands and posts
    /// results. Only ever from here, never from the user's config.
    pub server: String,
    pub tenant_id: String,
    pub agent_id: String,
    /// The device's name as the server knew it at anchoring, for
    /// `roomlerd anchor status`.
    #[serde(default)]
    pub device_name: String,
    /// The service's credential (`TokenType::AgentService`).
    pub service_token: String,
    /// Gate 4 for the SYSTEM path, the machine administrator's half. The
    /// worker checks the person's `exec_enabled` before it rings.
    pub exec_enabled: bool,
    /// RFC 3339.
    #[serde(default)]
    pub anchored_at: String,
    /// FR-105 — how far roomler SSH through this service may go, the
    /// machine administrator's (`roomlerd anchor ssh <…>`). Default off: an
    /// anchor made for exec never silently serves SYSTEM SSH, and an anchor
    /// file older than FR-105 reads as off.
    #[serde(default)]
    pub ssh: meshharbor_remote_control::models::SshServiceCeiling,
    /// Keys a newer build wrote, kept so that this build's save (a renewal,
    /// `anchor exec`) never erases them: the #2078 shape, a clean save that
    /// drops what it does not know.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Never prints the credential: an anchor goes into logs and error messages.
impl std::fmt::Debug for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Anchor")
            .field("version", &self.version)
            .field("server", &self.server)
            .field("tenant_id", &self.tenant_id)
            .field("agent_id", &self.agent_id)
            .field("device_name", &self.device_name)
            .field("service_token", &"[redacted]")
            .field("exec_enabled", &self.exec_enabled)
            .field("anchored_at", &self.anchored_at)
            .field("ssh", &self.ssh)
            // Names only: a newer build's value is not this build's to judge
            // safe to print.
            .field("extra", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Anchor {
    /// Everything [`load_anchor`] requires of a file's content once its
    /// owner and DACL have passed.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != ANCHOR_VERSION {
            return Err(format!(
                "anchor version {} is not {ANCHOR_VERSION}: anchor the device again with this \
                 build",
                self.version
            ));
        }
        origin_ok(&self.server)?;
        if !valid_object_id(&self.tenant_id) || !valid_object_id(&self.agent_id) {
            return Err("the anchor's org or device id is malformed".into());
        }
        if self.service_token.trim().is_empty() {
            return Err("the anchor holds no credential".into());
        }
        Ok(())
    }
}

/// One request on the doorbell. A request id is the most it ever carries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DoorbellRequest {
    /// Is the service anchored, and for which device? Answers no secret.
    Health,
    /// Claim this command from the server and run it.
    Ring { request_id: String },
    /// Kill this command, if the service is running it.
    Cancel { request_id: String },
    /// FR-105 — claim this SSH grant from the server and hold it for the
    /// service's own SSH endpoint (`ssh_service`).
    SshGrant { grant_id: String },
}

/// The service's answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DoorbellReply {
    Health {
        anchored: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_id: Option<String>,
        #[serde(default)]
        exec_enabled: bool,
        /// Why an anchor that exists is not used (not trusted, malformed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        problem: Option<String>,
        version: String,
        /// FR-105 — the anchor's SSH ceiling, when this service serves SSH
        /// (its pipe is up). Absent from a service that does not, including
        /// every one older than FR-105.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ssh: Option<meshharbor_remote_control::models::SshServiceCeiling>,
    },
    /// `claimed: true` = the service holds the command now, and the server
    /// hears the result from it. Anything else names why nothing runs.
    Rang {
        claimed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Cancelled {
        found: bool,
    },
    Refused {
        error: String,
    },
}

/// The `exp` of a JWT, read without verifying it: the service only uses it
/// to decide when to renew its own credential, which the server verifies.
pub fn token_expiry(token: &str) -> Option<i64> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("exp")?
        .as_i64()
}

/// Renew when fewer than [`RENEW_BEFORE_SECS`] are left, or when the expiry
/// cannot be read at all.
pub fn renewal_due(exp: Option<i64>, now: i64) -> bool {
    exp.is_none_or(|exp| exp - now < RENEW_BEFORE_SECS)
}

/// Rings are the only request that costs the server a call (and, when
/// refused, an audit row), so they are rate limited: a token bucket of
/// [`RingLimiter::BURST`], refilled at [`RingLimiter::PER_MINUTE`].
#[derive(Debug)]
pub struct RingLimiter {
    tokens: f64,
    last: std::time::Instant,
}

impl Default for RingLimiter {
    fn default() -> Self {
        Self::new(std::time::Instant::now())
    }
}

impl RingLimiter {
    pub const BURST: f64 = 10.0;
    pub const PER_MINUTE: f64 = 30.0;

    pub fn new(now: std::time::Instant) -> Self {
        Self {
            tokens: Self::BURST,
            last: now,
        }
    }

    /// Take one ring's token at `now`, if there is one.
    pub fn allow(&mut self, now: std::time::Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * Self::PER_MINUTE / 60.0).min(Self::BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Read one `\n`-terminated line of at most [`MAX_LINE`] bytes.
async fn read_line<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<String, String> {
    use tokio::io::AsyncReadExt as _;
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = r
            .read(&mut byte)
            .await
            .map_err(|e| format!("reading the doorbell: {e}"))?;
        if n == 0 {
            return Err("the other end closed the doorbell mid-line".into());
        }
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() >= MAX_LINE {
            return Err(format!("a doorbell line longer than {MAX_LINE} bytes"));
        }
        buf.push(byte[0]);
    }
    String::from_utf8(buf).map_err(|_| "a doorbell line that is not UTF-8".to_string())
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    value: &T,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt as _;
    let mut line = serde_json::to_string(value).map_err(|e| e.to_string())?;
    line.push('\n');
    w.write_all(line.as_bytes())
        .await
        .map_err(|e| format!("writing the doorbell: {e}"))?;
    w.flush()
        .await
        .map_err(|e| format!("writing the doorbell: {e}"))
}

/// The service's side of one connection: one request, one reply. Generic
/// over the stream so the tests can drive it without a pipe.
pub async fn serve_connection<S, F, Fut>(mut stream: S, handle: F)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    F: FnOnce(DoorbellRequest) -> Fut,
    Fut: std::future::Future<Output = DoorbellReply>,
{
    // A peer that connects and says nothing is dropped, so a handful of
    // idle connections cannot hold every instance.
    let line = match tokio::time::timeout(std::time::Duration::from_secs(5), read_line(&mut stream))
        .await
    {
        Ok(Ok(line)) => line,
        Ok(Err(e)) => {
            tracing::debug!(%e, "exec-service: a doorbell connection sent nothing usable");
            return;
        }
        Err(_) => return,
    };
    let reply = match serde_json::from_str::<DoorbellRequest>(&line) {
        Ok(req) => handle(req).await,
        Err(_) => DoorbellReply::Refused {
            error: "not a doorbell request".into(),
        },
    };
    if let Err(e) = write_line(&mut stream, &reply).await {
        tracing::debug!(%e, "exec-service: could not answer a doorbell connection");
    }
}

/// The worker's side of one connection: send `req`, wait up to `wait` for
/// the reply.
pub async fn exchange<S>(
    mut stream: S,
    req: &DoorbellRequest,
    wait: std::time::Duration,
) -> Result<DoorbellReply, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_line(&mut stream, req).await?;
    let line = tokio::time::timeout(wait, read_line(&mut stream))
        .await
        .map_err(|_| {
            format!(
                "the SYSTEM service did not answer within {} s",
                wait.as_secs()
            )
        })??;
    serde_json::from_str(&line).map_err(|e| format!("the SYSTEM service's answer: {e}"))
}

// ────────────────────────────────────────────────────────────────────────────
// The worker's side
// ────────────────────────────────────────────────────────────────────────────

/// The device the service last said it is anchored for, from the health
/// watch. `None` = not anchored, no service, or not asked yet.
static ANCHORED_AGENT: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

fn anchored_agent() -> Option<String> {
    match ANCHORED_AGENT.read() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Only the Windows health watch sets it; elsewhere nothing is ever anchored.
#[cfg_attr(not(windows), allow(dead_code))]
fn set_anchored_agent(agent: Option<String>) {
    let mut g = match ANCHORED_AGENT.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if *g != agent {
        tracing::info!(
            anchored_for = ?agent,
            "exec-service: the SYSTEM service's anchor changed"
        );
        *g = agent;
    }
}

/// Should the connection for `agent_id` advertise `exec-system`? Only when
/// this device's SYSTEM service answered that it is anchored for exactly that
/// device, and the kill switch is not set. The anchor names one device, so a
/// secondary org's connection never offers it.
pub fn advertised_for(agent_id: &str) -> bool {
    if disabled_by(std::env::var(KILL_SWITCH_ENV).ok().as_deref()) {
        return false;
    }
    anchored_agent().is_some_and(|a| a == agent_id)
}

/// FR-105 — the SSH ceiling the service last said it serves (its health
/// reply's `ssh`): `None` = no SSH pipe, no anchor, or a service older than
/// FR-105.
static SERVICE_SSH: std::sync::RwLock<
    Option<meshharbor_remote_control::models::SshServiceCeiling>,
> = std::sync::RwLock::new(None);

/// Only the Windows health watch sets it.
#[cfg_attr(not(windows), allow(dead_code))]
fn set_service_ssh(ssh: Option<meshharbor_remote_control::models::SshServiceCeiling>) {
    let mut g = match SERVICE_SSH.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if *g != ssh {
        tracing::info!(?ssh, "ssh-service: the SYSTEM service's SSH changed");
        *g = ssh;
    }
}

/// FR-105 — does this device's SYSTEM service serve SSH for `agent_id`: anchored
/// for exactly that device, its SSH pipe up, and a ceiling above off? The
/// worker's half of `ssh-system` (`ssh_service::advertised_for`).
pub fn ssh_served_for(agent_id: &str) -> bool {
    let ssh = match SERVICE_SSH.read() {
        Ok(g) => *g,
        Err(poisoned) => *poisoned.into_inner(),
    };
    anchored_agent().is_some_and(|a| a == agent_id)
        && ssh.is_some_and(|c| c != meshharbor_remote_control::models::SshServiceCeiling::Off)
}

/// Put `exec-system` in `rpc`, or take it out, by equality: `exec` is a
/// prefix of it and stays either way.
pub fn apply_word(rpc: &mut Vec<String>, on: bool) {
    let word = meshharbor_remote_control::models::RpcCap::ExecSystem.wire();
    rpc.retain(|w| w != word);
    if on {
        rpc.push(word.to_string());
    }
}

/// How often the worker asks the service whether it is anchored. A change
/// reaches the server on the next heartbeat after it.
#[cfg(windows)]
const HEALTH_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// Keep [`advertised_for`]'s answer fresh: ask the service now, then every
/// [`HEALTH_EVERY`]. A no-op off Windows.
pub fn spawn_health_watch() {
    #[cfg(windows)]
    tokio::spawn(async {
        loop {
            let (agent, ssh) = match win::ask(
                &DoorbellRequest::Health,
                std::time::Duration::from_secs(3),
            )
            .await
            {
                Ok(DoorbellReply::Health {
                    anchored: true,
                    agent_id,
                    problem: None,
                    ssh,
                    ..
                }) => (agent_id, ssh),
                Ok(DoorbellReply::Health {
                    problem: Some(p), ..
                }) => {
                    tracing::warn!(problem = %p, "exec-service: the SYSTEM service's anchor is not used");
                    (None, None)
                }
                Ok(_) => (None, None),
                Err(e) => {
                    tracing::debug!(%e, "exec-service: no answer from the SYSTEM service");
                    (None, None)
                }
            };
            set_anchored_agent(agent);
            set_service_ssh(ssh);
            tokio::time::sleep(HEALTH_EVERY).await;
        }
    });
}

/// Ring the service for `request_id`. `Ok` = the service claimed the command
/// and will post its result to the server itself. `Err` names why nothing
/// runs, for the worker to report as the command's answer.
pub async fn ring(request_id: &str) -> Result<(), String> {
    if !valid_object_id(request_id) {
        return Err("a malformed request id".into());
    }
    #[cfg(windows)]
    {
        let req = DoorbellRequest::Ring {
            request_id: request_id.to_string(),
        };
        // The service claims over HTTPS before it answers.
        match win::ask(&req, std::time::Duration::from_secs(30)).await? {
            DoorbellReply::Rang { claimed: true, .. } => Ok(()),
            DoorbellReply::Rang { error, .. } => {
                Err(error
                    .unwrap_or_else(|| "the SYSTEM service did not take the command".to_string()))
            }
            DoorbellReply::Refused { error } => Err(error),
            other => Err(format!("the SYSTEM service answered {other:?}")),
        }
    }
    #[cfg(not(windows))]
    {
        Err("only a Windows device runs commands through a SYSTEM service".into())
    }
}

/// FR-105 — hand an SSH grant to the service: it claims the grant from the
/// server with its own credential, and that claim is the server's
/// acknowledgement. `Err` names why the service did not take it, for the
/// worker to answer the server with a refusal.
pub async fn ring_ssh(grant_id: &str) -> Result<(), String> {
    if !valid_object_id(grant_id) {
        return Err("a malformed grant id".into());
    }
    #[cfg(windows)]
    {
        let req = DoorbellRequest::SshGrant {
            grant_id: grant_id.to_string(),
        };
        // Past the service's own claim timeout, and inside the server's
        // window for the claim (10 s from the push).
        match win::ask(&req, std::time::Duration::from_secs(10)).await? {
            DoorbellReply::Rang { claimed: true, .. } => Ok(()),
            DoorbellReply::Rang { error, .. } => Err(error
                .unwrap_or_else(|| "the SYSTEM service did not take the SSH grant".to_string())),
            DoorbellReply::Refused { error } => Err(error),
            other => Err(format!("the SYSTEM service answered {other:?}")),
        }
    }
    #[cfg(not(windows))]
    {
        Err("only a Windows device serves SSH through a SYSTEM service".into())
    }
}

/// Ask the service to kill `request_id`. `true` = it was running there.
pub async fn cancel(request_id: &str) -> bool {
    if !valid_object_id(request_id) {
        return false;
    }
    #[cfg(windows)]
    {
        let req = DoorbellRequest::Cancel {
            request_id: request_id.to_string(),
        };
        matches!(
            win::ask(&req, std::time::Duration::from_secs(5)).await,
            Ok(DoorbellReply::Cancelled { found: true })
        )
    }
    #[cfg(not(windows))]
    {
        false
    }
}

// ────────────────────────────────────────────────────────────────────────────
// The anchor file
// ────────────────────────────────────────────────────────────────────────────

/// `%ProgramData%\roomler\roomler\exec-service`. Windows only: no other
/// platform anchors a device.
#[cfg(windows)]
pub fn anchor_dir() -> std::path::PathBuf {
    meshharbor_node_core::appdirs::machine_global_dir().join("exec-service")
}

/// `…\exec-service\anchor.json`.
#[cfg(windows)]
pub fn anchor_path() -> std::path::PathBuf {
    anchor_dir().join("anchor.json")
}

/// The anchor, if there is one this process may trust. `Ok(None)` = none.
/// `Err` = a file is there, but its owner, its DACL, its directory or its
/// content says nobody should act on it.
#[cfg(windows)]
pub fn load_anchor() -> Result<Option<Anchor>, String> {
    win::load_anchor(&anchor_dir(), &anchor_path())
}

#[cfg(not(windows))]
pub fn load_anchor() -> Result<Option<Anchor>, String> {
    Ok(None)
}

/// FR-105 — `…\exec-service\ssh_host_ed25519_key`: the SYSTEM service's own
/// SSH host key, beside the anchor and as private.
#[cfg(windows)]
pub fn host_key_path() -> std::path::PathBuf {
    anchor_dir().join(HOST_KEY_FILE)
}

#[cfg(windows)]
const HOST_KEY_FILE: &str = "ssh_host_ed25519_key";

/// FR-105 — the SSH pipe is made with the doorbell's DACL and opened with its
/// owner check.
#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) use win::{open_system_pipe, pipe_instance};

/// FR-105 — the service's host key (OpenSSH PEM), if there is one this process
/// may trust: the same owner and DACL rules as the anchor.
#[cfg(windows)]
pub fn load_host_key() -> Result<Option<String>, String> {
    win::read_private(
        &anchor_dir(),
        &host_key_path(),
        "the SSH host key",
        16 * 1024,
    )
}

/// FR-105 — the host key, made now if there is none. Only an anchored device's
/// directory ever holds one: the caller has the anchor already.
#[cfg(all(windows, feature = "ssh-server"))]
pub fn ensure_host_key() -> Result<String, String> {
    if let Some(pem) = load_host_key()? {
        return Ok(pem);
    }
    let pem = crate::ssh::generate_host_key().map_err(|e| format!("making a host key: {e}"))?;
    win::write_private(HOST_KEY_FILE, pem.as_bytes())?;
    tracing::info!("ssh-service: made the SYSTEM service's SSH host key");
    Ok(pem)
}

// ────────────────────────────────────────────────────────────────────────────
// The service's side
// ────────────────────────────────────────────────────────────────────────────

/// What a claim hands the service: the command, from the server. The
/// server's `ClaimedExec`.
#[derive(Debug, Clone, Deserialize)]
pub struct Claimed {
    pub request_id: String,
    pub shell: String,
    pub command: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    #[serde(default)]
    pub cwd: Option<String>,
    pub caller: String,
    /// `system` or `console_user`.
    pub run_as: String,
}

/// What the service posts: the server's `ExecOutcome`.
#[derive(Debug, Serialize)]
pub struct Posted<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub stdout: &'a str,
    pub stderr: &'a str,
    pub truncated: bool,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
    /// The identity it ran as; absent when it never ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<&'a str>,
}

/// The identity a claim's `run_as` names, and since FR-97 P5a an
/// `rc:rpc.exec` frame's on Linux and macOS. An unknown word is a refusal,
/// never the daemon: a newer server naming a mode this build does not know
/// must not have its intent upgraded (`exec::RunAs::from_wire`'s rule).
pub fn run_as_of(word: &str) -> Result<(crate::exec::RunAs, &'static str), String> {
    match word {
        "system" => Ok((crate::exec::RunAs::Daemon, "system")),
        "console_user" => Ok((crate::exec::RunAs::ConsoleUser, "console_user")),
        other => Err(format!(
            "the server asked to run as {other:?}, which this build does not know; refusing \
             rather than run it as SYSTEM or root"
        )),
    }
}

/// Start the doorbell and the credential renewal in the SYSTEM service, on
/// a thread and a runtime of their own: `service_main` is synchronous and
/// must never wait on either. A no-op off Windows.
pub fn spawn_service_runner() {
    #[cfg(windows)]
    {
        let spawned = std::thread::Builder::new()
            .name("roomler-svc-exec".into())
            .spawn(|| {
                match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("roomler-svc-exec")
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(svc::run()),
                    Err(e) => tracing::error!(%e, "exec-service: no runtime; the doorbell is down"),
                }
            });
        if let Err(e) = spawned {
            tracing::error!(%e, "exec-service: could not start the doorbell thread");
        }
    }
}

#[cfg(windows)]
mod svc {
    //! The doorbell server and the runner, in the SYSTEM service.

    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{Mutex, Semaphore};
    use tracing::{error, info, warn};

    use super::{
        Anchor, Claimed, DoorbellReply, DoorbellRequest, Posted, RingLimiter, load_anchor,
        renewal_due, run_as_of, token_expiry, valid_object_id,
    };

    /// Connections handled at once; the accept loop waits beyond it.
    const MAX_CONNECTIONS: usize = 16;
    /// How often the service checks whether its credential needs renewing.
    const RENEW_CHECK_EVERY: Duration = Duration::from_secs(12 * 60 * 60);

    pub async fn run() {
        tokio::spawn(renew_loop());
        // FR-105 — the SSH pipe and the endpoint publisher, beside the
        // doorbell. They serve nothing until an administrator turns the
        // anchor's `ssh` on.
        #[cfg(feature = "ssh-server")]
        tokio::spawn(crate::ssh_service::svc::run());
        let limiter = Arc::new(Mutex::new(RingLimiter::default()));
        loop {
            if let Err(e) = super::win::serve(Arc::clone(&limiter)).await {
                // A pipe someone else created first (`first_pipe_instance`),
                // or no pipe at all: say so, and try again, because a
                // squatter may exit.
                error!(%e, "exec-service: the doorbell is down; retrying in 30 s");
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    pub fn connection_slots() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(MAX_CONNECTIONS))
    }

    /// One request, answered.
    pub async fn handle(req: DoorbellRequest, limiter: Arc<Mutex<RingLimiter>>) -> DoorbellReply {
        match req {
            DoorbellRequest::Health => health(),
            DoorbellRequest::Ring { request_id } => ring(request_id, limiter).await,
            DoorbellRequest::Cancel { request_id } => {
                let found =
                    valid_object_id(&request_id) && crate::exec::shared().cancel(&request_id).await;
                info!(%request_id, found, "exec-service: cancel");
                DoorbellReply::Cancelled { found }
            }
            DoorbellRequest::SshGrant { grant_id } => ssh_grant(grant_id, limiter).await,
        }
    }

    fn health() -> DoorbellReply {
        let version = env!("CARGO_PKG_VERSION").to_string();
        match load_anchor() {
            Ok(Some(a)) => DoorbellReply::Health {
                anchored: true,
                agent_id: Some(a.agent_id.clone()),
                exec_enabled: a.exec_enabled,
                problem: None,
                version,
                ssh: crate::ssh_service::served_ceiling(&a),
            },
            Ok(None) => DoorbellReply::Health {
                anchored: false,
                agent_id: None,
                exec_enabled: false,
                problem: None,
                version,
                ssh: None,
            },
            Err(e) => DoorbellReply::Health {
                anchored: false,
                agent_id: None,
                exec_enabled: false,
                problem: Some(e),
                version,
                ssh: None,
            },
        }
    }

    /// FR-105 — claim an SSH grant for the service's own endpoint. Rate
    /// limited with the rings: a claim costs the server a call and, refused,
    /// an audit row.
    async fn ssh_grant(grant_id: String, limiter: Arc<Mutex<RingLimiter>>) -> DoorbellReply {
        if !valid_object_id(&grant_id) {
            return DoorbellReply::Refused {
                error: "a malformed grant id".into(),
            };
        }
        if !limiter.lock().await.allow(std::time::Instant::now()) {
            warn!(%grant_id, "ssh-service: grant refused, too many rings");
            return refused("the SYSTEM service is refusing rings for a moment: too many");
        }
        let anchor = match load_anchor() {
            Ok(Some(a)) => a,
            Ok(None) => {
                return refused("this device is not anchored (`roomlerd anchor create`, elevated)");
            }
            Err(e) => {
                error!(%e, "ssh-service: the anchor cannot be trusted");
                return refused(format!("this device's anchor cannot be trusted: {e}"));
            }
        };
        #[cfg(feature = "ssh-server")]
        {
            match crate::ssh_service::claim_grant(&anchor, &grant_id).await {
                Ok(()) => DoorbellReply::Rang {
                    claimed: true,
                    error: None,
                },
                Err(e) => {
                    warn!(%grant_id, %e, "ssh-service: grant not claimed");
                    refused(e)
                }
            }
        }
        #[cfg(not(feature = "ssh-server"))]
        {
            let _ = anchor;
            refused("this build of roomlerd serves no SSH")
        }
    }

    fn refused(error: impl Into<String>) -> DoorbellReply {
        DoorbellReply::Rang {
            claimed: false,
            error: Some(error.into()),
        }
    }

    async fn ring(request_id: String, limiter: Arc<Mutex<RingLimiter>>) -> DoorbellReply {
        if !valid_object_id(&request_id) {
            return DoorbellReply::Refused {
                error: "a malformed request id".into(),
            };
        }
        if !limiter.lock().await.allow(std::time::Instant::now()) {
            warn!(%request_id, "exec-service: ring refused, too many rings");
            return refused("the SYSTEM service is refusing rings for a moment: too many");
        }
        let anchor = match load_anchor() {
            Ok(Some(a)) => a,
            Ok(None) => {
                return refused(
                    "this device is not anchored for SYSTEM exec (`roomlerd anchor create`, \
                     elevated)",
                );
            }
            Err(e) => {
                error!(%e, "exec-service: the anchor cannot be trusted");
                return refused(format!("this device's anchor cannot be trusted: {e}"));
            }
        };
        if !anchor.exec_enabled {
            return refused(
                "remote execution through the SYSTEM service is off on this device \
                 (`roomlerd anchor exec on`, elevated)",
            );
        }
        let claimed = match claim(&anchor, &request_id).await {
            Ok(c) => c,
            Err(e) => {
                warn!(%request_id, %e, "exec-service: claim refused");
                return refused(e);
            }
        };
        let (run_as, ran_as) = match run_as_of(&claimed.run_as) {
            Ok(v) => v,
            Err(e) => {
                // Claimed, so the server waits for THIS service's answer.
                post_result(&anchor, &request_id, &failed(&e), None).await;
                return DoorbellReply::Rang {
                    claimed: true,
                    error: None,
                };
            }
        };
        info!(
            %request_id, caller = %claimed.caller, run_as = ran_as,
            "exec-service: running a command for the server"
        );
        tokio::spawn(run_and_post(anchor, claimed, run_as, ran_as));
        DoorbellReply::Rang {
            claimed: true,
            error: None,
        }
    }

    fn failed(error: &str) -> crate::exec::ExecOutcome {
        crate::exec::ExecOutcome {
            error: Some(error.to_string()),
            ..Default::default()
        }
    }

    /// `total` bounds each request. A claim's is shorter than the worker's
    /// wait for the doorbell's answer (30 s), so a slow server is reported to
    /// the worker rather than abandoned by it.
    fn client(total: Duration) -> Result<reqwest::Client, String> {
        reqwest::Client::builder()
            .user_agent(concat!("roomlerd-exec-service/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(total)
            .build()
            .map_err(|e| format!("building the HTTP client: {e}"))
    }

    const CLAIM_TIMEOUT: Duration = Duration::from_secs(20);
    const POST_TIMEOUT: Duration = Duration::from_secs(30);

    fn url(anchor: &Anchor, path: &str) -> String {
        // `tid` lets the front proxy send the call to the org's pod, where the
        // caller usually waits; any other pod works too, a little later.
        format!("{}{path}?tid={}", anchor.server, anchor.tenant_id)
    }

    async fn claim(anchor: &Anchor, request_id: &str) -> Result<Claimed, String> {
        let resp = client(CLAIM_TIMEOUT)?
            .post(url(
                anchor,
                &format!("/api/agent/service/rpc/{request_id}/claim"),
            ))
            .bearer_auth(&anchor.service_token)
            .send()
            .await
            .map_err(|e| format!("the SYSTEM service could not reach the server: {e}"))?;
        match resp.status().as_u16() {
            200 => {
                let c: Claimed = resp
                    .json()
                    .await
                    .map_err(|e| format!("the server's claim answer: {e}"))?;
                if c.request_id != request_id {
                    return Err("the server answered a claim for another command".into());
                }
                Ok(c)
            }
            404 => Err("the server has no such command pending for this device".into()),
            401 => Err(
                "this device's SYSTEM service credential is no longer accepted (re-anchored or \
                 un-anchored); anchor it again"
                    .into(),
            ),
            s => Err(format!("the server refused the claim: HTTP {s}")),
        }
    }

    async fn run_and_post(
        anchor: Anchor,
        claimed: Claimed,
        run_as: crate::exec::RunAs,
        ran_as: &'static str,
    ) {
        // Masked out of whatever the command prints, as the agent token is.
        crate::exec::register_secret(&anchor.service_token);
        let request_id = claimed.request_id.clone();
        let req = crate::exec::ExecRequest {
            request_id: claimed.request_id,
            shell: claimed.shell,
            command: claimed.command,
            timeout_ms: claimed.timeout_ms,
            max_output_bytes: claimed.max_output_bytes,
            cwd: claimed.cwd,
            caller: claimed.caller,
            run_as,
            // Fleet RPC: where it always started (FR-97 P5b is SSH's).
            start_in_home: false,
        };
        let outcome = crate::exec::shared()
            .run(req, &crate::exec::redactor())
            .await;
        post_result(&anchor, &request_id, &outcome, Some(ran_as)).await;
    }

    /// Post the outcome, retrying a network failure: the caller waits on it.
    /// A 4xx is final (the row is gone, or the credential is).
    async fn post_result(
        anchor: &Anchor,
        request_id: &str,
        outcome: &crate::exec::ExecOutcome,
        ran_as: Option<&str>,
    ) {
        let body = Posted {
            exit_code: outcome.exit_code,
            stdout: &outcome.stdout,
            stderr: &outcome.stderr,
            truncated: outcome.truncated,
            duration_ms: outcome.duration_ms,
            error: outcome.error.as_deref(),
            ran_as,
        };
        let client = match client(POST_TIMEOUT) {
            Ok(c) => c,
            Err(e) => {
                error!(%request_id, %e, "exec-service: cannot post the result");
                return;
            }
        };
        for (attempt, backoff) in [(1, 2u64), (2, 5), (3, 0)] {
            let sent = client
                .post(url(
                    anchor,
                    &format!("/api/agent/service/rpc/{request_id}/result"),
                ))
                .bearer_auth(&anchor.service_token)
                .json(&body)
                .send()
                .await;
            match sent {
                Ok(r) if r.status().is_success() => {
                    info!(%request_id, exit_code = ?outcome.exit_code, "exec-service: result posted");
                    return;
                }
                Ok(r) if r.status().is_client_error() => {
                    error!(%request_id, status = %r.status(), "exec-service: the server refused the result");
                    return;
                }
                Ok(r) => {
                    warn!(%request_id, attempt, status = %r.status(), "exec-service: result post failed")
                }
                Err(e) => warn!(%request_id, attempt, %e, "exec-service: result post failed"),
            }
            if backoff > 0 {
                tokio::time::sleep(Duration::from_secs(backoff)).await;
            }
        }
        error!(%request_id, "exec-service: the result never reached the server");
    }

    /// Renew the credential well before it expires, under the same anchor.
    async fn renew_loop() {
        tokio::time::sleep(Duration::from_secs(5 * 60)).await;
        loop {
            if let Err(e) = renew_if_due().await {
                warn!(%e, "exec-service: credential renewal failed; will retry");
            }
            tokio::time::sleep(RENEW_CHECK_EVERY).await;
        }
    }

    async fn renew_if_due() -> Result<(), String> {
        let Some(anchor) = load_anchor()? else {
            return Ok(());
        };
        let now = chrono::Utc::now().timestamp();
        if !renewal_due(token_expiry(&anchor.service_token), now) {
            return Ok(());
        }
        let resp = client(POST_TIMEOUT)?
            .post(url(&anchor, "/api/agent/service/renew"))
            .bearer_auth(&anchor.service_token)
            .send()
            .await
            .map_err(|e| format!("could not reach the server: {e}"))?;
        if resp.status().as_u16() == 401 {
            return Err(
                "the server no longer accepts this anchor's credential; anchor the device again"
                    .into(),
            );
        }
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        #[derive(serde::Deserialize)]
        struct Renewed {
            service_token: String,
        }
        let renewed: Renewed = resp.json().await.map_err(|e| e.to_string())?;
        // Swap the credential into the anchor as it stands NOW: an
        // administrator may have changed it during the call (`exec off`), and
        // writing back the copy loaded before it would undo that. Anchored
        // again meanwhile: the new anchor's credential stands.
        let Some(mut current) = load_anchor()? else {
            return Ok(());
        };
        if current.agent_id != anchor.agent_id || current.service_token != anchor.service_token {
            return Ok(());
        }
        current.service_token = renewed.service_token;
        super::win::store_anchor(&current)?;
        info!("exec-service: credential renewed");
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// `roomlerd anchor`
// ────────────────────────────────────────────────────────────────────────────

/// What `roomlerd anchor` was asked to do.
#[derive(Debug, Clone)]
pub enum AnchorAction {
    /// Anchor this machine's device for SYSTEM exec.
    Create {
        server: String,
        token: String,
        device: String,
        force: bool,
        exec_enabled: bool,
        /// FR-105 — the SSH ceiling to anchor with. `None` keeps the one
        /// the replaced anchor of the SAME device had, and is off otherwise.
        ssh: Option<meshharbor_remote_control::models::SshServiceCeiling>,
    },
    /// Show the anchor (never its credential).
    Status,
    /// Turn the anchor's gate 4 on or off.
    Exec { on: bool },
    /// FR-105 — how far roomler SSH through the SYSTEM service may go.
    Ssh {
        ceiling: meshharbor_remote_control::models::SshServiceCeiling,
    },
    /// Delete the anchor from this machine.
    Remove,
}

/// FR-105 — the CLI's spelling of a ceiling (`off`, `console_user`,
/// `system`), the wire's.
pub fn parse_ssh_ceiling(
    word: &str,
) -> Result<meshharbor_remote_control::models::SshServiceCeiling, String> {
    use meshharbor_remote_control::models::SshServiceCeiling;
    match word.trim() {
        "off" => Ok(SshServiceCeiling::Off),
        "console_user" => Ok(SshServiceCeiling::ConsoleUser),
        "system" => Ok(SshServiceCeiling::System),
        other => Err(format!(
            "{other:?} is not one of off | console_user | system"
        )),
    }
}

/// `roomlerd anchor …`. Every action but `status` needs an elevated prompt;
/// `status` does too, in practice, because the file is Administrators-only.
pub async fn anchor_cli(action: AnchorAction) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        win::anchor_cli(action).await
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        anyhow::bail!(
            "only a Windows device is anchored: a Linux or macOS daemon already runs commands as \
             root"
        )
    }
}

#[cfg(windows)]
mod win {
    //! Windows: the anchor's DACL rules, the doorbell pipe, elevation.

    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::windows::io::AsRawHandle as _;
    use std::path::Path;
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
    use tokio::sync::Mutex;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_BUSY, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
    };
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
        GetAce, GetAclInformation, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SetFileSecurityW, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, OPEN_EXISTING,
        READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{Anchor, AnchorAction, DoorbellReply, DoorbellRequest, RingLimiter};

    /// The anchor's directory: Administrators own it, SYSTEM and
    /// Administrators alone may touch it, inheritance off.
    const DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    /// The anchor file itself: the same, explicitly.
    const FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
    /// The doorbell. SYSTEM owns it (the worker checks), and makes every
    /// instance. Administrators and interactive users may read it and write
    /// data to it (`0x12008b`), and nothing more: not
    /// `FILE_CREATE_PIPE_INSTANCE`, with which a user could add an instance
    /// of their own and take the next worker's connection. Below Medium
    /// integrity nothing may write to it.
    const PIPE_SDDL: &str =
        "O:SYD:P(A;;GA;;;SY)(A;;0x12008b;;;BA)(A;;0x12008b;;;IU)S:(ML;;NW;;;ME)";

    /// Access bits that let a holder change a file's content, its name, its
    /// DACL or its owner, or a directory's entries.
    const WRITE_LIKE: u32 = 0x2 // FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x4 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x10 // FILE_WRITE_EA
        | 0x40 // FILE_DELETE_CHILD
        | 0x100 // FILE_WRITE_ATTRIBUTES
        | 0x1_0000 // DELETE
        | 0x4_0000 // WRITE_DAC
        | 0x8_0000 // WRITE_OWNER
        | 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000; // GENERIC_WRITE
    /// ACE types (`winnt.h`), stable ABI; the `SystemServices` feature that
    /// names them is not one this crate enables.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    /// `INHERIT_ONLY_ACE`: applies to children only, never to the object.
    const INHERIT_ONLY_ACE: u8 = 0x08;

    /// A security descriptor from SDDL, and the `SECURITY_ATTRIBUTES` that
    /// hand it to a directory or a pipe instance. Freed on drop. (FR-90's
    /// `hive_win::Sddl` is the same thing, compiled only with `hive`.)
    struct Sddl {
        sa: SECURITY_ATTRIBUTES,
        psd: PSECURITY_DESCRIPTOR,
    }

    // SAFETY: a LocalAlloc'd buffer with no thread affinity; the accept loop
    // holds one across `.await`.
    unsafe impl Send for Sddl {}

    impl Sddl {
        fn new(sddl: &str) -> std::io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: a NUL-terminated string; `psd` receives a LocalAlloc'd
            // descriptor, freed in Drop; the size out-param is optional.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1,
                    &mut psd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self {
                sa: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: psd,
                    bInheritHandle: 0,
                },
                psd,
            })
        }

        fn attributes(&mut self) -> *mut SECURITY_ATTRIBUTES {
            &raw mut self.sa
        }
    }

    impl Drop for Sddl {
        fn drop(&mut self) {
            // SAFETY: the one descriptor ConvertStringSecurityDescriptor… made.
            unsafe { LocalFree(self.psd as _) };
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn is_well_known(sid: PSID, kind: i32) -> bool {
        // SAFETY: `sid` points into a descriptor that outlives the call.
        !sid.is_null() && unsafe { IsWellKnownSid(sid, kind) } != 0
    }

    fn is_trusted_sid(sid: PSID) -> bool {
        is_well_known(sid, WinLocalSystemSid) || is_well_known(sid, WinBuiltinAdministratorsSid)
    }

    /// The owner and DACL of the object behind `handle`: owned by SYSTEM or
    /// Administrators, and no allow-ACE that lets anyone else write. A NULL
    /// DACL (everyone, everything) and any ACE this does not recognise are
    /// refusals: this is the trust root of SYSTEM exec, and it fails closed.
    fn check_private(handle: HANDLE, what: &str) -> Result<(), String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a live handle opened with READ_CONTROL; the out-params point
        // into `psd`, freed below.
        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut psd,
            )
        };
        if rc != 0 {
            return Err(format!("{what}: reading its security: Win32 error {rc}"));
        }
        let verdict = (|| {
            if !is_trusted_sid(owner) {
                return Err(format!(
                    "{what} is not owned by SYSTEM or Administrators (made by someone else \
                     first?)"
                ));
            }
            if dacl.is_null() {
                return Err(format!("{what} has no DACL: everyone may write it"));
            }
            let mut info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            // SAFETY: `dacl` is a valid ACL inside `psd`; `info` is sized.
            let ok = unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut info).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            };
            if ok == 0 {
                return Err(format!("{what}: reading its DACL failed"));
            }
            for i in 0..info.AceCount {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                // SAFETY: `i` < AceCount; `ace` points into the ACL.
                if unsafe { GetAce(dacl, i, &mut ace) } == 0 || ace.is_null() {
                    return Err(format!("{what}: reading its DACL failed"));
                }
                // SAFETY: every ACE starts with an ACE_HEADER.
                let header = unsafe { &*(ace as *const ACE_HEADER) };
                if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                match header.AceType {
                    ACCESS_DENIED_ACE_TYPE => continue,
                    ACCESS_ALLOWED_ACE_TYPE => {
                        // ACCESS_ALLOWED_ACE: header (4), mask (4), then the
                        // SID, which `GetAce` guarantees fits in AceSize.
                        // SAFETY: the type says this is the layout.
                        let mask = unsafe {
                            std::ptr::read_unaligned((ace as *const u8).add(4) as *const u32)
                        };
                        // SAFETY: the SID starts 8 bytes in, inside the ACE.
                        let sid = unsafe { (ace as *mut u8).add(8) } as PSID;
                        if mask & WRITE_LIKE != 0 && !is_trusted_sid(sid) {
                            return Err(format!(
                                "{what} lets someone other than SYSTEM or Administrators \
                                 change it"
                            ));
                        }
                    }
                    other => {
                        return Err(format!(
                            "{what} carries an access rule of a kind this check does not \
                             read (type {other})"
                        ));
                    }
                }
            }
            Ok(())
        })();
        // SAFETY: the descriptor GetSecurityInfo allocated.
        unsafe { LocalFree(psd as _) };
        verdict
    }

    pub fn load_anchor(dir: &Path, path: &Path) -> Result<Option<Anchor>, String> {
        let Some(text) = read_private(dir, path, "the anchor file", 64 * 1024)? else {
            return Ok(None);
        };
        let anchor: Anchor =
            serde_json::from_str(&text).map_err(|e| format!("the anchor file: {e}"))?;
        anchor.validate()?;
        Ok(Some(anchor))
    }

    /// Read `path`, a file in the anchor's directory `dir`, if both are
    /// private: owned by SYSTEM or Administrators and writable by nobody
    /// else. `Ok(None)` = not there. `what` names it in errors.
    pub(crate) fn read_private(
        dir: &Path,
        path: &Path,
        what: &str,
        max_len: u64,
    ) -> Result<Option<String>, String> {
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(path) {
            return Err(format!("{} is a link", link.display()));
        }
        let dir_handle = match std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        let meta = dir_handle
            .metadata()
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{} is not a plain directory", dir.display()));
        }
        check_private(
            dir_handle.as_raw_handle() as HANDLE,
            "the anchor's directory",
        )?;
        let file = match std::fs::OpenOptions::new()
            .access_mode(GENERIC_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let meta = file
            .metadata()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{} is not a plain file", path.display()));
        }
        if meta.len() > max_len {
            return Err(format!("{what} is too large to be one"));
        }
        // Checked on the handle the content is read from, not by name: a name
        // can be swapped between a check and a read; an open file cannot.
        check_private(file.as_raw_handle() as HANDLE, what)?;
        use std::io::Read as _;
        let mut text = String::new();
        let mut bounded = (&file).take(max_len);
        bounded
            .read_to_string(&mut text)
            .map_err(|e| format!("reading {what}: {e}"))?;
        Ok(Some(text))
    }

    /// Make the anchor's directory private, or take over the plain directory
    /// already there: as its maker, a standard user who made it first would
    /// keep WRITE_DAC whatever its DACL said.
    fn private_dir(dir: &Path) -> Result<(), String> {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(dir) {
            return Err(format!("{} is a link", link.display()));
        }
        let mut sd = Sddl::new(DIR_SDDL).map_err(|e| e.to_string())?;
        let name = wide(dir);
        match std::fs::symlink_metadata(dir) {
            Ok(m) => {
                if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(format!("{} is not a plain directory", dir.display()));
                }
                // SAFETY: a NUL-terminated path; the descriptor lives in `sd`.
                let ok = unsafe {
                    SetFileSecurityW(
                        name.as_ptr(),
                        OWNER_SECURITY_INFORMATION
                            | DACL_SECURITY_INFORMATION
                            | PROTECTED_DACL_SECURITY_INFORMATION,
                        sd.psd,
                    )
                };
                if ok == 0 {
                    return Err(format!(
                        "{}: {} (if another account made this directory, delete it and \
                         anchor again)",
                        dir.display(),
                        std::io::Error::last_os_error()
                    ));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // SAFETY: a NUL-terminated path; the attributes live in `sd`.
                if unsafe { CreateDirectoryW(name.as_ptr(), sd.attributes()) } == 0 {
                    return Err(format!(
                        "{}: {}",
                        dir.display(),
                        std::io::Error::last_os_error()
                    ));
                }
                Ok(())
            }
            Err(e) => Err(format!("{}: {e}", dir.display())),
        }
    }

    /// Write the anchor: into a private directory, through a temporary file
    /// given the file's own DACL before it takes the name.
    pub fn store_anchor(anchor: &Anchor) -> Result<(), String> {
        anchor.validate()?;
        let text = serde_json::to_string_pretty(anchor).map_err(|e| e.to_string())?;
        write_private("anchor.json", text.as_bytes())
    }

    /// Write `bytes` as `name` in the anchor's directory, made private first,
    /// through a temporary file given the file's own DACL before it takes the
    /// name. The directory's inherited DACL already admits only SYSTEM and
    /// Administrators, so not even the temporary file is ever readable by
    /// anyone else (FR-105's host key is a private key).
    pub(crate) fn write_private(name: &str, bytes: &[u8]) -> Result<(), String> {
        let dir = super::anchor_dir();
        private_dir(&dir)?;
        let path = dir.join(name);
        let tmp = dir.join(format!("{name}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
        let sd = Sddl::new(FILE_SDDL).map_err(|e| e.to_string())?;
        let name = wide(&tmp);
        // SAFETY: a NUL-terminated path; the descriptor lives in `sd`.
        let ok = unsafe {
            SetFileSecurityW(
                name.as_ptr(),
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                sd.psd,
            )
        };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {e}", tmp.display()));
        }
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", path.display())
        })
    }

    /// Is this process elevated (or SYSTEM)? Only such a process may write
    /// the anchor, and saying so up front beats an access-denied halfway.
    fn process_is_elevated() -> bool {
        if crate::win_identity::process_is_local_system() {
            return true;
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: our own process's pseudo-handle; the token is closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        // SAFETY: a live token; `elevation` is sized for TokenElevation.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevation).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
        };
        // SAFETY: the handle OpenProcessToken gave us, closed once.
        unsafe { CloseHandle(token) };
        ok != 0 && elevation.TokenIsElevated != 0
    }

    /// Is the doorbell's server end owned by SYSTEM? A standard user cannot
    /// make an object SYSTEM owns, so a pipe someone squatted fails this.
    fn pipe_owned_by_system(handle: HANDLE) -> Result<bool, String> {
        let kinds: [SE_OBJECT_TYPE; 2] = [SE_FILE_OBJECT, SE_KERNEL_OBJECT];
        let mut last = 0u32;
        for kind in kinds {
            let mut owner: PSID = std::ptr::null_mut();
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: a live pipe handle opened with READ_CONTROL (inside
            // GENERIC_READ); `owner` points into `psd`, freed below.
            let rc = unsafe {
                GetSecurityInfo(
                    handle,
                    kind,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut psd,
                )
            };
            if rc == 0 {
                let system = is_well_known(owner, WinLocalSystemSid);
                // SAFETY: the descriptor GetSecurityInfo allocated.
                unsafe { LocalFree(psd as _) };
                return Ok(system);
            }
            last = rc;
        }
        Err(format!(
            "reading the doorbell's owner: {}",
            std::io::Error::from_raw_os_error(last as i32)
        ))
    }

    /// Open the doorbell with exactly the access its DACL grants, at the
    /// identification level (the service never acts as the worker), and
    /// refuse it unless SYSTEM owns it. `Ok(None)` = every instance is busy.
    fn open_doorbell() -> Result<Option<NamedPipeClient>, String> {
        open_system_pipe(super::PIPE_NAME, "doorbell")
    }

    /// Open one of the SYSTEM service's pipes (`what` names it in errors) the
    /// way [`open_doorbell`] opens the doorbell: the access its DACL grants,
    /// identification level, and SYSTEM must own it, so a pipe a user squatted
    /// is refused. FR-105's SSH pipe is opened the same way.
    pub(crate) fn open_system_pipe(
        pipe: &str,
        what: &str,
    ) -> Result<Option<NamedPipeClient>, String> {
        let name = wide(Path::new(pipe));
        // SAFETY: a NUL-terminated name; the handle goes to tokio or is
        // closed.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | FILE_WRITE_DATA,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) {
                return Ok(None);
            }
            return Err(format!("no SYSTEM service {what}: {e}"));
        }
        match pipe_owned_by_system(handle) {
            Ok(true) => {}
            Ok(false) => {
                // SAFETY: ours, closed once.
                unsafe { CloseHandle(handle) };
                return Err(format!(
                    "the {what} pipe is not owned by SYSTEM: refusing it (another process \
                     created it first?)"
                ));
            }
            Err(e) => {
                // SAFETY: ours, closed once.
                unsafe { CloseHandle(handle) };
                return Err(e);
            }
        }
        // SAFETY: a pipe handle opened overlapped, owned by tokio from here.
        match unsafe { NamedPipeClient::from_raw_handle(handle as _) } {
            Ok(c) => Ok(Some(c)),
            Err(e) => {
                // SAFETY: tokio did not take it; closed once.
                unsafe { CloseHandle(handle) };
                Err(format!("the {what}: {e}"))
            }
        }
    }

    /// One request to the service, and its answer. Every instance busy is
    /// retried briefly: the service makes the next one as soon as it takes
    /// a connection.
    pub async fn ask(
        req: &DoorbellRequest,
        wait: std::time::Duration,
    ) -> Result<DoorbellReply, String> {
        for _ in 0..20 {
            if let Some(pipe) = open_doorbell()? {
                return super::exchange(pipe, req, wait).await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        Err("the SYSTEM service's doorbell stayed busy".into())
    }

    fn server_instance(first: bool) -> std::io::Result<NamedPipeServer> {
        pipe_instance(super::PIPE_NAME, first)
    }

    /// One server instance of a SYSTEM service pipe, with the doorbell's
    /// DACL ([`PIPE_SDDL`]): SYSTEM owns it, Administrators and interactive
    /// users may read and write data, and nobody else may add an instance.
    /// `first` refuses a name something else already holds. FR-105's SSH pipe
    /// is made the same way.
    pub(crate) fn pipe_instance(name: &str, first: bool) -> std::io::Result<NamedPipeServer> {
        let mut sd = Sddl::new(PIPE_SDDL)?;
        // SAFETY: the attributes live in `sd` until the call returns; the
        // system copies the descriptor into the instance.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, sd.attributes().cast())
        }
    }

    /// Serve the doorbell until an instance cannot be made.
    pub async fn serve(limiter: Arc<Mutex<RingLimiter>>) -> Result<(), String> {
        // `first_pipe_instance`: if anything else holds the name, fail rather
        // than join it.
        let mut server = server_instance(true).map_err(|e| format!("the doorbell pipe: {e}"))?;
        tracing::info!(pipe = super::PIPE_NAME, "exec-service: the doorbell is up");
        let slots = super::svc::connection_slots();
        loop {
            if let Err(e) = server.connect().await {
                // One peer's failed connection (it hung up first) must not
                // take the doorbell down for everyone: replace the instance.
                tracing::debug!(%e, "exec-service: a doorbell connection failed");
                server = server_instance(false).map_err(|e| format!("the doorbell pipe: {e}"))?;
                continue;
            }
            let connected = server;
            server = server_instance(false).map_err(|e| format!("the doorbell pipe: {e}"))?;
            let permit = Arc::clone(&slots)
                .acquire_owned()
                .await
                .map_err(|e| e.to_string())?;
            let limiter = Arc::clone(&limiter);
            tokio::spawn(async move {
                super::serve_connection(connected, |req| super::svc::handle(req, limiter)).await;
                drop(permit);
            });
        }
    }

    /// A ceiling as `anchor status` and `anchor ssh` say it.
    fn ssh_words(ceiling: meshharbor_remote_control::models::SshServiceCeiling) -> &'static str {
        use meshharbor_remote_control::models::SshServiceCeiling;
        match ceiling {
            SshServiceCeiling::Off => "OFF",
            SshServiceCeiling::ConsoleUser => "ON, as the signed-in user only",
            SshServiceCeiling::System => "ON, as SYSTEM or the signed-in user",
        }
    }

    fn require_elevated() -> anyhow::Result<()> {
        if !process_is_elevated() {
            anyhow::bail!(
                "run this from an elevated prompt (Run as administrator): the anchor is \
                 Administrators-only"
            );
        }
        Ok(())
    }

    pub async fn anchor_cli(action: AnchorAction) -> anyhow::Result<()> {
        match action {
            AnchorAction::Create {
                server,
                token,
                device,
                force,
                exec_enabled,
                ssh,
            } => create(&server, &token, &device, force, exec_enabled, ssh).await,
            AnchorAction::Status => status(),
            AnchorAction::Ssh { ceiling } => {
                require_elevated()?;
                let mut anchor = load_anchor(&super::anchor_dir(), &super::anchor_path())
                    .map_err(anyhow::Error::msg)?
                    .ok_or_else(|| anyhow::anyhow!("this device is not anchored"))?;
                anchor.ssh = ceiling;
                // The key before the ceiling: a service that reads the new
                // ceiling must find a key to publish with it.
                #[cfg(feature = "ssh-server")]
                if ceiling != meshharbor_remote_control::models::SshServiceCeiling::Off {
                    super::ensure_host_key().map_err(anyhow::Error::msg)?;
                }
                store_anchor(&anchor).map_err(anyhow::Error::msg)?;
                println!(
                    "SSH through the SYSTEM service is now {} on this device.\n\
                     The service publishes it to the server within a minute; nothing needs \
                     a restart.",
                    ssh_words(ceiling)
                );
                #[cfg(not(feature = "ssh-server"))]
                println!("Note: this build of roomlerd serves no SSH, so nothing uses it yet.");
                Ok(())
            }
            AnchorAction::Exec { on } => {
                require_elevated()?;
                let mut anchor = load_anchor(&super::anchor_dir(), &super::anchor_path())
                    .map_err(anyhow::Error::msg)?
                    .ok_or_else(|| anyhow::anyhow!("this device is not anchored"))?;
                anchor.exec_enabled = on;
                store_anchor(&anchor).map_err(anyhow::Error::msg)?;
                println!(
                    "Remote execution through the SYSTEM service is now {} on this device.",
                    if on { "ON" } else { "OFF" }
                );
                Ok(())
            }
            AnchorAction::Remove => {
                require_elevated()?;
                match std::fs::remove_file(super::anchor_path()) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        println!("This device was not anchored.");
                        return Ok(());
                    }
                    Err(e) => return Err(e.into()),
                }
                println!(
                    "The anchor is gone from this machine: commands go to the worker again \
                     (within a heartbeat), or are refused where the org requires SYSTEM.\n\
                     The server still records the anchor until an administrator removes it \
                     from the device's page."
                );
                Ok(())
            }
        }
    }

    async fn create(
        server: &str,
        token: &str,
        device: &str,
        force: bool,
        exec_enabled: bool,
        ssh: Option<meshharbor_remote_control::models::SshServiceCeiling>,
    ) -> anyhow::Result<()> {
        require_elevated()?;
        let server = super::origin_ok(server).map_err(anyhow::Error::msg)?;
        let device = device.trim();
        if !super::valid_object_id(device) {
            anyhow::bail!(
                "--device takes the device's id from its page in the dashboard (24 hex digits)"
            );
        }
        let host = std::env::var("COMPUTERNAME").unwrap_or_default();
        #[derive(serde::Deserialize)]
        struct Anchored {
            agent_id: String,
            tenant_id: String,
            name: String,
            service_token: String,
        }
        let resp = reqwest::Client::builder()
            .user_agent(concat!("roomlerd-anchor/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()?
            .post(format!("{server}/api/agent/anchor"))
            .json(&serde_json::json!({
                "enrollment_token": token,
                "agent_id": device,
                "host_name": host,
                "force": force,
            }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("the server refused the anchor (HTTP {status}): {body}");
        }
        let anchored: Anchored = resp.json().await?;
        if anchored.agent_id != device {
            anyhow::bail!("the server anchored a different device than asked; nothing written");
        }
        let replaced = load_anchor(&super::anchor_dir(), &super::anchor_path())
            .ok()
            .flatten();
        // FR-105 — an administrator re-anchoring the SAME device (a fresh
        // credential, a re-run wizard) keeps the SSH ceiling an administrator
        // chose for it; any other device starts off.
        let ssh = ssh.unwrap_or_else(|| {
            replaced
                .as_ref()
                .filter(|old| old.agent_id == anchored.agent_id)
                .map(|old| old.ssh)
                .unwrap_or_default()
        });
        #[cfg(feature = "ssh-server")]
        if ssh != meshharbor_remote_control::models::SshServiceCeiling::Off {
            super::ensure_host_key().map_err(anyhow::Error::msg)?;
        }
        let anchor = Anchor {
            version: super::ANCHOR_VERSION,
            server: server.clone(),
            tenant_id: anchored.tenant_id,
            agent_id: anchored.agent_id,
            device_name: anchored.name,
            service_token: anchored.service_token,
            exec_enabled,
            anchored_at: chrono::Utc::now().to_rfc3339(),
            ssh,
            extra: Default::default(),
        };
        store_anchor(&anchor).map_err(anyhow::Error::msg)?;
        if let Some(old) = replaced {
            println!(
                "Replaced the anchor for device {} ({}).",
                old.device_name, old.agent_id
            );
        }
        println!(
            "Anchored device {} ({}) at {server}.\n\
             Remote execution through the SYSTEM service: {}.\n\
             The worker offers it to the server within a minute; nothing needs a restart.",
            anchor.device_name,
            anchor.agent_id,
            if exec_enabled {
                "ON"
            } else {
                "OFF (`roomlerd anchor exec on`)"
            },
        );
        Ok(())
    }

    fn status() -> anyhow::Result<()> {
        match load_anchor(&super::anchor_dir(), &super::anchor_path()) {
            Ok(Some(a)) => {
                let expires = super::token_expiry(&a.service_token)
                    .and_then(|exp| chrono::DateTime::from_timestamp(exp, 0))
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| "unknown".into());
                println!(
                    "Anchored: device {} ({})\n  server:      {}\n  org:         {}\n  \
                     exec:        {}\n  ssh:         {}\n  anchored at: {}\n  credential:  \
                     renews itself; current one expires {expires}",
                    a.device_name,
                    a.agent_id,
                    a.server,
                    a.tenant_id,
                    if a.exec_enabled { "on" } else { "off" },
                    ssh_words(a.ssh),
                    a.anchored_at,
                );
                // FR-105 — the key a caller pins on the service's port.
                #[cfg(feature = "ssh-server")]
                if let Ok(Some(pem)) = super::load_host_key()
                    && let Some(fp) = crate::ssh_service::fingerprint_of(&pem)
                {
                    println!("  ssh host key: {fp}");
                }
                Ok(())
            }
            Ok(None) => {
                println!("This device is not anchored for SYSTEM exec.");
                Ok(())
            }
            Err(e) if !process_is_elevated() => anyhow::bail!(
                "could not read the anchor ({e}); it is Administrators-only, so run this \
                 elevated"
            ),
            Err(e) => anyhow::bail!("the anchor here cannot be trusted: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kill_switch_is_an_explicit_off() {
        for off in ["0", "false", "OFF", " no "] {
            assert!(disabled_by(Some(off)), "{off}");
        }
        for on in [None, Some(""), Some("1"), Some("true"), Some("maybe")] {
            assert!(!disabled_by(on), "{on:?}");
        }
    }

    #[test]
    fn only_an_object_id_reaches_a_url() {
        assert!(valid_object_id("6ace07367d06cf41e19e54b0"));
        for bad in [
            "",
            "6ace07367d06cf41e19e54b",
            "6ace07367d06cf41e19e54b00",
            "../../api/agent/anchor0000",
            "6ace07367d06cf41e19e54g0",
        ] {
            assert!(!valid_object_id(bad), "{bad}");
        }
    }

    /// The claim's answer is the command SYSTEM runs, so its origin must be
    /// authenticated: https, or a loopback test server.
    #[test]
    fn the_service_talks_https_only() {
        assert_eq!(
            origin_ok("https://roomler.ai/").unwrap(),
            "https://roomler.ai"
        );
        assert!(origin_ok("http://127.0.0.1:5001").is_ok());
        assert!(origin_ok("http://localhost:3000").is_ok());
        assert!(origin_ok("http://[::1]:3000").is_ok());
        assert!(origin_ok("http://roomler.ai").is_err());
        assert!(origin_ok("http://10.0.0.5").is_err());
        assert!(origin_ok("ftp://roomler.ai").is_err());
        assert!(origin_ok("https://roomler.ai/?x=1").is_err());
        assert!(origin_ok("roomler.ai").is_err());
    }

    fn anchor() -> Anchor {
        Anchor {
            version: 1,
            server: "https://roomler.ai".into(),
            tenant_id: "69a1dbbad2000f26adc875ce".into(),
            agent_id: "6ace07367d06cf41e19e54b0".into(),
            device_name: "HOST".into(),
            service_token: "test-only-service-credential-not-a-jwt".into(),
            exec_enabled: true,
            anchored_at: "2026-10-13T12:00:00Z".into(),
            ssh: Default::default(),
            extra: Default::default(),
        }
    }

    #[test]
    fn an_anchor_never_prints_its_credential() {
        let shown = format!("{:?}", anchor());
        assert!(!shown.contains("test-only-service-credential"), "{shown}");
        assert!(shown.contains("[redacted]"));
    }

    #[test]
    fn an_anchor_is_validated_whole() {
        assert!(anchor().validate().is_ok());
        let mut a = anchor();
        a.server = "http://roomler.ai".into();
        assert!(a.validate().is_err(), "plain http");
        let mut a = anchor();
        a.agent_id = "nope".into();
        assert!(a.validate().is_err(), "a malformed device");
        let mut a = anchor();
        a.version = 2;
        assert!(a.validate().is_err(), "a newer schema");
        let mut a = anchor();
        a.service_token = " ".into();
        assert!(a.validate().is_err(), "no credential");
        let back: Anchor =
            serde_json::from_str(&serde_json::to_string(&anchor()).unwrap()).unwrap();
        assert_eq!(back, anchor());
    }

    /// The wire is what an older service and a newer worker (or the reverse)
    /// both read, so its spellings are locked.
    #[test]
    fn the_doorbell_wire_is_locked() {
        assert_eq!(
            serde_json::to_string(&DoorbellRequest::Health).unwrap(),
            r#"{"t":"health"}"#
        );
        assert_eq!(
            serde_json::to_string(&DoorbellRequest::Ring {
                request_id: "6ace07367d06cf41e19e54b0".into()
            })
            .unwrap(),
            r#"{"t":"ring","request_id":"6ace07367d06cf41e19e54b0"}"#
        );
        assert_eq!(
            serde_json::to_string(&DoorbellReply::Rang {
                claimed: true,
                error: None
            })
            .unwrap(),
            r#"{"t":"rang","claimed":true}"#
        );
        let health: DoorbellReply = serde_json::from_str(
            r#"{"t":"health","anchored":true,"agent_id":"6ace07367d06cf41e19e54b0","exec_enabled":true,"version":"0.4.133"}"#,
        )
        .unwrap();
        assert!(matches!(
            health,
            DoorbellReply::Health {
                anchored: true,
                problem: None,
                ..
            }
        ));
    }

    #[test]
    fn exec_system_is_added_and_removed_by_equality() {
        let mut rpc: Vec<String> = ["exec", "originate"].map(String::from).to_vec();
        apply_word(&mut rpc, true);
        apply_word(&mut rpc, true);
        assert_eq!(rpc, ["exec", "originate", "exec-system"]);
        apply_word(&mut rpc, false);
        assert_eq!(rpc, ["exec", "originate"], "`exec` stays");
    }

    #[test]
    fn a_token_renews_well_before_it_expires() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"x","exp":2000000000}"#);
        let token = format!("eyJhbGciOiJIUzI1NiJ9.{payload}.sig");
        assert_eq!(token_expiry(&token), Some(2_000_000_000));
        assert_eq!(token_expiry("not-a-jwt"), None);
        let now = 2_000_000_000 - 200 * 24 * 60 * 60;
        assert!(!renewal_due(Some(2_000_000_000), now), "200 days left");
        assert!(
            renewal_due(Some(2_000_000_000), 2_000_000_000 - 60),
            "a minute left"
        );
        assert!(renewal_due(None, now), "unreadable: renew");
    }

    #[test]
    fn rings_are_rate_limited() {
        let t0 = std::time::Instant::now();
        let mut l = RingLimiter::new(t0);
        let allowed = (0..20).filter(|_| l.allow(t0)).count();
        assert_eq!(
            allowed,
            RingLimiter::BURST as usize,
            "a burst, then no more"
        );
        // Two seconds refill one ring at 30 a minute.
        assert!(l.allow(t0 + std::time::Duration::from_secs(2)));
        assert!(!l.allow(t0 + std::time::Duration::from_secs(2)));
    }

    /// An unknown identity is a refusal, never SYSTEM.
    #[test]
    fn an_unknown_run_as_is_refused() {
        assert_eq!(run_as_of("system").unwrap().1, "system");
        assert_eq!(run_as_of("console_user").unwrap().1, "console_user");
        assert!(run_as_of("named").is_err());
        assert!(run_as_of("").is_err());
    }

    /// One request, one reply, over any stream; garbage and an over-long
    /// line are answered or dropped, never acted on.
    #[tokio::test]
    async fn one_request_one_reply() {
        let (client, server) = tokio::io::duplex(8 * 1024);
        let served = tokio::spawn(serve_connection(server, |req| async move {
            match req {
                DoorbellRequest::Ring { request_id } => DoorbellReply::Rang {
                    claimed: request_id == "6ace07367d06cf41e19e54b0",
                    error: None,
                },
                _ => DoorbellReply::Refused { error: "no".into() },
            }
        }));
        let reply = exchange(
            client,
            &DoorbellRequest::Ring {
                request_id: "6ace07367d06cf41e19e54b0".into(),
            },
            std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            reply,
            DoorbellReply::Rang {
                claimed: true,
                error: None
            }
        );
        served.await.unwrap();

        // Not a request: refused, unread.
        let (mut client, server) = tokio::io::duplex(8 * 1024);
        let served = tokio::spawn(serve_connection(server, |_| async {
            never("a garbage line must never reach the handler")
        }));
        use tokio::io::AsyncWriteExt as _;
        client
            .write_all(b"{\"t\":\"exec\",\"command\":\"whoami\"}\n")
            .await
            .unwrap();
        let line = read_line(&mut client).await.unwrap();
        assert!(line.contains("refused"), "{line}");
        served.await.unwrap();

        // Longer than a line may be: dropped without an answer.
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(serve_connection(server, |_| async {
            never("an over-long line must never reach the handler")
        }));
        client.write_all(&vec![b'x'; MAX_LINE + 10]).await.unwrap();
        served.await.unwrap();
    }

    fn never(why: &str) -> DoorbellReply {
        panic!("{why}")
    }

    /// `%ProgramData%` lets a standard user create folders, so an anchor
    /// is trusted only from a directory and a file owned by SYSTEM or
    /// Administrators that grant nobody else write. A folder an ordinary
    /// account made, holding a well-formed anchor, is refused: by its owner
    /// when this runs unelevated, by its inherited user-writable DACL when it
    /// runs elevated (Administrators then own it). Either way, never read.
    #[cfg(windows)]
    #[test]
    fn an_anchor_in_a_folder_a_user_made_is_never_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("anchor.json");
        std::fs::write(&path, serde_json::to_string(&anchor()).unwrap()).unwrap();
        let err = win::load_anchor(dir.path(), &path).unwrap_err();
        assert!(err.contains("SYSTEM or Administrators"), "{err}");
        // And no file is not an error: nothing to trust.
        let empty = tempfile::tempdir().unwrap();
        let missing = empty.path().join("anchor.json");
        assert!(matches!(
            win::load_anchor(&empty.path().join("nope"), &missing),
            Ok(None)
        ));
    }
}
