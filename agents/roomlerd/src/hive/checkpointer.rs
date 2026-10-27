// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2b-3a — `meshharbord hive-checkpoint`: a session's checkpoint, taken AS
//! THE SESSION'S ACCOUNT and handed to the daemon on stdout.
//!
//! The daemon never opens a path in the account's tree (spec §3b). So it writes
//! a [`Request`] (where the session's config directory, folder and state
//! directory are, the checkpoint's number and turn, and the last checkpoint)
//! into the session's runtime directory, starts `meshharbord hive-checkpoint
//! <request>` as the account, as the Unix wrapper and Windows' `hive-prep` run,
//! and reads what it writes:
//!
//! ```text
//! "HIVECP1\n"                         the magic
//! u32 le · JSON {"checkpoint": …}     the header
//! u32 le                              how many blobs
//! ( u64 le · bytes ) × blobs          in the order the chunks name them:
//!                                     each file's, in path order, then the pack's
//! ```
//!
//! ⚠️ **What comes back is the account's word, and the agent runs as that
//! account.** [`read_frames`] and [`check`] hold it to the request before
//! anything reaches the store: the number and the turn; every path inside the
//! allowlist and shaped as it says; each blob the one its chunk names, in
//! order, at its length and hash; the sizes within the limits. A member checks
//! the whole of each file again when it assembles it.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use roomler_hive_node::checkpoint::{
    self, CHUNK_MAX, Checkpoint, Digest, MAX_FILES, MAX_NEW_BYTES, Previous, Skipped,
};
use serde::{Deserialize, Serialize};

use super::workspace::{self, Git};

/// The hidden subcommand: `meshharbord hive-checkpoint <request>`.
pub const CHECKPOINT_SUBCOMMAND: &str = "hive-checkpoint";

/// The first bytes of what the child writes.
const MAGIC: &[u8; 8] = b"HIVECP1\n";

/// The most header bytes read: a manifest of [`MAX_FILES`] files.
pub(super) const MAX_HEADER: usize = 16 * 1024 * 1024;

/// The most blobs one checkpoint names: every file in at most two chunks,
/// and a pack of [`workspace::MAX_PACK`].
const MAX_BLOBS: usize = 2 * MAX_FILES + workspace::MAX_PACK / CHUNK_MAX + 1;

/// The most bytes the daemon reads from the child at all.
pub(crate) const MAX_OUTPUT: u64 =
    MAX_NEW_BYTES + workspace::MAX_PACK as u64 + (MAX_HEADER as u64) + 16 * 1024 * 1024;

/// What the daemon asks of one checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Request {
    /// Bumped when the fields change their meaning; a child refuses another.
    pub v: u32,
    /// The Hive session id (24 hex): the workspace's ref name.
    pub sid: String,
    /// The harness's session id (a UUID): the config directory's names.
    pub harness_session: String,
    /// FR-90 P2f-3a — for a fork, the harness session it was made from:
    /// its history, sub-agent transcripts and tool results under this
    /// session's project directory are taken too ([`checkpoint::allowlist_of`]).
    /// Absent for every other session, so a request of a build before it
    /// reads the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_of: Option<String>,
    pub config_dir: PathBuf,
    pub folder: PathBuf,
    pub state_dir: PathBuf,
    pub n: u64,
    pub turn: u32,
    /// The last checkpoint, where this one starts; `None` for the first.
    #[serde(default)]
    pub previous: Option<Checkpoint>,
}

pub(crate) const REQUEST_V: u32 = 1;

/// The child's work, as the account: the config directory's allowlist and the
/// workspace, as one checkpoint, with its blobs in the order its chunks name
/// them. A workspace that cannot be taken is skipped, in words.
pub(crate) fn produce(req: &Request, git: &Git) -> Result<(Checkpoint, Vec<Vec<u8>>), String> {
    if req.v != REQUEST_V {
        return Err(format!(
            "a request of version {}; this build reads {REQUEST_V}",
            req.v
        ));
    }
    let prev = req
        .previous
        .as_ref()
        .map_or_else(Previous::none, Previous::from_checkpoint);
    let (mut cp, mut blobs) = checkpoint::take(
        &req.config_dir,
        &req.harness_session,
        req.fork_of.as_deref(),
        req.n,
        req.turn,
        &prev,
    )
    .map_err(|e| e.to_string())?;
    match workspace::checkpoint(
        git,
        &req.folder,
        &req.state_dir,
        &req.sid,
        req.n,
        req.turn,
        prev.workspace(),
    ) {
        workspace::Outcome::Taken {
            snap,
            blobs: mut pack,
        } => {
            cp.workspace = Some(snap);
            blobs.append(&mut pack);
        }
        workspace::Outcome::Skipped(why) => cp.skipped.push(Skipped {
            path: "the workspace".into(),
            why,
        }),
    }
    Ok((cp, blobs))
}

#[derive(Serialize, Deserialize)]
struct Header {
    checkpoint: Checkpoint,
}

/// The child's stdout: [`MAGIC`], the header, then the blobs.
pub(crate) fn write_frames(
    out: &mut impl Write,
    cp: &Checkpoint,
    blobs: &[Vec<u8>],
) -> std::io::Result<()> {
    let header = serde_json::to_vec(&Header {
        checkpoint: cp.clone(),
    })
    .map_err(std::io::Error::other)?;
    out.write_all(MAGIC)?;
    out.write_all(
        &u32::try_from(header.len())
            .map_err(std::io::Error::other)?
            .to_le_bytes(),
    )?;
    out.write_all(&header)?;
    out.write_all(
        &u32::try_from(blobs.len())
            .map_err(std::io::Error::other)?
            .to_le_bytes(),
    )?;
    for blob in blobs {
        out.write_all(&(blob.len() as u64).to_le_bytes())?;
        out.write_all(blob)?;
    }
    out.flush()
}

/// What the child wrote, read back within the limits; [`check`] then holds it
/// to the request.
pub(crate) fn read_frames(bytes: &[u8]) -> Result<(Checkpoint, Vec<Vec<u8>>), String> {
    let mut at = 0usize;
    let mut take = |n: usize, what: &str| -> Result<&[u8], String> {
        let end = at
            .checked_add(n)
            .filter(|&e| e <= bytes.len())
            .ok_or_else(|| format!("the checkpoint ends inside {what}"))?;
        let s = &bytes[at..end];
        at = end;
        Ok(s)
    };
    if take(MAGIC.len(), "its magic")? != MAGIC {
        return Err("not a checkpoint (no magic)".into());
    }
    let header_len =
        u32::from_le_bytes(take(4, "the header's length")?.try_into().unwrap()) as usize;
    if header_len > MAX_HEADER {
        return Err(format!("a header of {header_len} bytes"));
    }
    let header: Header = serde_json::from_slice(take(header_len, "the header")?)
        .map_err(|e| format!("the header: {e}"))?;
    let count = u32::from_le_bytes(take(4, "the blob count")?.try_into().unwrap()) as usize;
    if count > MAX_BLOBS {
        return Err(format!("{count} blobs"));
    }
    let mut blobs = Vec::with_capacity(count.min(1024));
    for i in 0..count {
        let len = u64::from_le_bytes(take(8, "a blob's length")?.try_into().unwrap());
        if len > CHUNK_MAX as u64 {
            return Err(format!("blob {i} is {len} bytes"));
        }
        blobs.push(take(len as usize, "a blob")?.to_vec());
    }
    if at != bytes.len() {
        return Err(format!("{} bytes after the last blob", bytes.len() - at));
    }
    Ok((header.checkpoint, blobs))
}

/// Hold what the child sent to the request: the number and turn; every path
/// inside the allowlist and shaped as it says; the blobs exactly the ones the
/// chunks name, in order; the workspace's names git's.
pub(crate) fn check(req: &Request, cp: &Checkpoint, blobs: &[Vec<u8>]) -> Result<(), String> {
    if cp.n != req.n || cp.turn != req.turn {
        return Err(format!(
            "checkpoint {} after turn {}, asked for {} after {}",
            cp.n, cp.turn, req.n, req.turn
        ));
    }
    let allow = checkpoint::allowlist_of(&req.harness_session, req.fork_of.as_deref())
        .map_err(|e| e.to_string())?;
    let mut new_bytes = 0u64;
    let mut next = blobs.iter();
    let mut last_path: Option<&str> = None;
    for f in &cp.files {
        if last_path.is_some_and(|p| p >= f.path.as_str()) {
            return Err(format!("{} is out of order", f.path));
        }
        last_path = Some(&f.path);
        if !allowed(&f.path, &allow) {
            return Err(format!("{} is not in the allowlist", f.path));
        }
        if f.growth != checkpoint::growth_of(&f.path, &req.harness_session) {
            return Err(format!(
                "{} is not taken the way the allowlist says",
                f.path
            ));
        }
        if f.mode > 0o777 {
            return Err(format!("{} has mode {:o}", f.path, f.mode));
        }
        for chunk in &f.chunks {
            let blob = next
                .next()
                .ok_or_else(|| format!("{} names a blob that is missing", f.path))?;
            if blob.len() as u64 != chunk.len || Digest::of(blob) != chunk.hash {
                return Err(format!("{}: a blob is not the one its chunk names", f.path));
            }
            new_bytes += chunk.len;
        }
    }
    if let Some(ws) = &cp.workspace {
        let is_id =
            |s: &str| (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
        let ids_ok = is_id(&ws.tree)
            && is_id(&ws.commit)
            && ws.base.as_deref().is_none_or(is_id)
            && ws.head.as_deref().is_none_or(is_id);
        let prefix_ok = ws.prefix.is_empty()
            || (ws.prefix.ends_with('/')
                && !ws.prefix.starts_with('/')
                && ws
                    .prefix
                    .split('/')
                    .all(|c| c != ".." && c != "." && !c.contains('\\')));
        if !ids_ok || !prefix_ok {
            return Err("the workspace names something that is not git's".into());
        }
        let mut offset = 0u64;
        for chunk in &ws.pack {
            let blob = next
                .next()
                .ok_or("the workspace names a blob that is missing")?;
            if chunk.offset != offset
                || blob.len() as u64 != chunk.len
                || Digest::of(blob) != chunk.hash
            {
                return Err("the workspace's pack is not the blobs it names".into());
            }
            offset += chunk.len;
        }
        if offset > workspace::MAX_PACK as u64 {
            return Err("the workspace's pack is over its limit".into());
        }
    }
    if next.next().is_some() {
        return Err("more blobs than the checkpoint names".into());
    }
    if new_bytes > MAX_NEW_BYTES {
        return Err(format!("{new_bytes} new bytes"));
    }
    Ok(())
}

/// Whether `path` is one of the allowlist's files, or a file under one of its
/// directories, with nothing in it that could step outside.
pub(super) fn allowed(path: &str, allow: &[checkpoint::AllowEntry]) -> bool {
    let shaped = !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    shaped
        && allow.iter().any(|e| {
            if e.is_dir {
                path.strip_prefix(&e.rel)
                    .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
            } else {
                path == e.rel
            }
        })
}

/// How long a checkpoint may run before the daemon ends it: a first one of a
/// large workspace hashes and packs all of it.
pub(crate) const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(120);

// A lock on a checkpoint's index is stale only well past the time any
// checkpoint, and the grace its group is ended in, may hold it.
const _: () = assert!(workspace::STALE_LOCK.as_secs() > CHECKPOINT_TIMEOUT.as_secs() + 60);

/// How the checkpoint's child is run.
#[derive(Clone)]
pub(crate) enum Runner {
    /// `meshharbord hive-checkpoint`, as the account: what a device does.
    Subprocess,
    /// In this process, through the same frames and checks: tests, where the
    /// binary is the test harness and not `roomlerd`. Git's discovery stops at
    /// `ceiling`, so a repository around the test's temp directory is never
    /// written to.
    /// The supervisor's tests are Unix's; so is every test runner. An
    /// integration test's device takes it too (`hive-test-launcher`, P2d-6):
    /// its binary is a test's, which knows no `hive-checkpoint`.
    #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
    InProcess { ceiling: PathBuf },
    /// Every checkpoint fails, for this reason (tests).
    #[cfg(all(test, unix))]
    Failing(&'static str),
    /// No checkpoint ever finishes (tests).
    #[cfg(all(test, unix))]
    Hangs,
}

/// A checkpoint that was not taken: its number, and why.
pub(crate) struct Failed {
    n: u64,
    why: String,
}

/// A replicated session's checkpoints (P2b-3b): built at launch for a session
/// the server joined as replicated, and owned by its task, which calls
/// [`Checkpoints::after_turn`] at each turn's end.
pub(crate) struct Checkpoints {
    run: Runner,
    /// The daemon's own directory for the session: where the request goes.
    runtime_dir: PathBuf,
    /// The account the child runs as; `None` when the session runs as the
    /// daemon (the test launcher).
    account: Option<String>,
    /// The account's ids, to hand it the request (Unix).
    owner: Option<(u32, u32)>,
    /// The child's environment on Unix: the account's own, as the harness's.
    /// Windows starts it with the console user's own block instead.
    #[cfg_attr(not(unix), allow(dead_code))]
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    harness_session: String,
    /// P2f-3a — the session a fork was made from, for its life.
    fork_of: Option<String>,
    config_dir: PathBuf,
    folder: PathBuf,
    state_dir: PathBuf,
    /// The last checkpoint taken, where the next one starts.
    last: Option<Checkpoint>,
    /// Whether `last` has been read back from the store (a resume).
    loaded: bool,
    /// The last failure said in the transcript, so each is said once.
    failed: Option<String>,
}

/// Where a session's checkpoints are taken from, and as whom.
pub(crate) struct Place {
    pub runtime_dir: PathBuf,
    pub account: Option<String>,
    pub owner: Option<(u32, u32)>,
    pub env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    pub harness_session: String,
    /// P2f-3a — for a fork, the harness session it was made from.
    pub fork_of: Option<String>,
    pub config_dir: PathBuf,
    pub folder: PathBuf,
    pub state_dir: PathBuf,
}

impl Checkpoints {
    pub(crate) fn new(run: Runner, place: Place) -> Self {
        Self {
            run,
            runtime_dir: place.runtime_dir,
            account: place.account,
            owner: place.owner,
            env: place.env,
            harness_session: place.harness_session,
            fork_of: place.fork_of,
            config_dir: place.config_dir,
            folder: place.folder,
            state_dir: place.state_dir,
            last: None,
            loaded: false,
            failed: None,
        }
    }

    /// P2f-2b — where this session runs, and as whom, for the `pack` a member
    /// asks of it ([`super::packer::Workplace`]): the account and environment
    /// its checkpoints are taken as, and its folder and state directory.
    pub(crate) fn workplace(&self) -> super::packer::Workplace {
        super::packer::Workplace {
            who: super::materializer::Who {
                account: self.account.clone(),
                env: self.env.clone(),
            },
            folder: self.folder.clone(),
            state_dir: self.state_dir.clone(),
        }
    }

    /// Take the checkpoint after `turn` and keep it: its blobs first, so a
    /// member that sees the event can fetch every one, then the event. One
    /// that fails is logged and answered, for the caller to [`Self::say`];
    /// the session goes on either way.
    pub(crate) async fn after_turn(
        &mut self,
        store: &super::store::StoreHandle,
        sid: &str,
        fence: u64,
        turn: u32,
    ) -> Result<(), Failed> {
        if !self.loaded {
            self.loaded = true;
            if let Ok(Some(env)) = store.last_of_kind(sid, "checkpoint").await
                && let Some(roomler_hive_node::TranscriptEvent::Checkpoint(c)) =
                    roomler_hive_node::TranscriptEvent::from_json(&env.event_json)
            {
                self.last = Some(c);
            }
        }
        let n = self.last.as_ref().map_or(1, |c| c.n + 1);
        let req = Request {
            v: REQUEST_V,
            sid: sid.to_string(),
            harness_session: self.harness_session.clone(),
            fork_of: self.fork_of.clone(),
            config_dir: self.config_dir.clone(),
            folder: self.folder.clone(),
            state_dir: self.state_dir.clone(),
            n,
            turn,
            previous: self.last.clone(),
        };
        let failed = |why: String| {
            tracing::warn!(session = sid, n, %why, "hive: a checkpoint was not taken");
            Failed { n, why }
        };
        let (cp, blobs) = self.take(&req).await.map_err(failed)?;
        for blob in blobs {
            store
                .put_blob(sid, blob)
                .await
                .map_err(|e| failed(format!("its blobs could not be kept: {e}")))?;
        }
        tracing::info!(
            session = sid,
            n,
            turn,
            files = cp.files.len(),
            workspace = cp.workspace.is_some(),
            "hive: a checkpoint was taken"
        );
        store.append(
            sid,
            fence,
            roomler_hive_node::TranscriptEvent::Checkpoint(cp.clone()),
        );
        self.last = Some(cp);
        self.failed = None;
        Ok(())
    }

    /// Say in the transcript that a checkpoint was not taken: once per
    /// reason, not at every turn's end while the reason holds.
    pub(crate) fn say(
        &mut self,
        store: &super::store::StoreHandle,
        sid: &str,
        fence: u64,
        failed: Failed,
    ) {
        if self.failed.as_deref() == Some(failed.why.as_str()) {
            return;
        }
        store.append(
            sid,
            fence,
            roomler_hive_node::TranscriptEvent::Note {
                text: format!("Checkpoint {} was not taken: {}", failed.n, failed.why),
            },
        );
        self.failed = Some(failed.why);
    }

    async fn take(&self, req: &Request) -> Result<(Checkpoint, Vec<Vec<u8>>), String> {
        match &self.run {
            #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
            Runner::InProcess { ceiling } => {
                let (cp, blobs) = produce(req, &Git::under(ceiling))?;
                let mut bytes = Vec::new();
                write_frames(&mut bytes, &cp, &blobs).map_err(|e| e.to_string())?;
                let (cp, blobs) = read_frames(&bytes)?;
                check(req, &cp, &blobs)?;
                Ok((cp, blobs))
            }
            #[cfg(all(test, unix))]
            Runner::Failing(why) => Err((*why).to_string()),
            #[cfg(all(test, unix))]
            Runner::Hangs => std::future::pending().await,
            Runner::Subprocess => {
                let path = write_request(&self.runtime_dir, req, self.owner)?;
                let exe = PathBuf::from(super::supervisor::own_exe()?);
                #[cfg(unix)]
                {
                    run_as(
                        &exe,
                        &path,
                        req,
                        self.account.as_deref(),
                        self.env.clone(),
                        CHECKPOINT_TIMEOUT,
                    )
                    .await
                }
                #[cfg(windows)]
                {
                    let account = self.account.clone().ok_or("no account to run as")?;
                    let req = req.clone();
                    tokio::task::spawn_blocking(move || {
                        run_as_console_user(&exe, &path, &req, &account, CHECKPOINT_TIMEOUT)
                    })
                    .await
                    .map_err(|e| format!("the checkpoint's thread: {e}"))?
                }
            }
        }
    }
}

/// The request, where only the daemon writes and the account reads it
/// ([`write_private`]).
fn write_request(dir: &Path, req: &Request, owner: Option<(u32, u32)>) -> Result<PathBuf, String> {
    let bytes = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    write_private(dir, "checkpoint.json", &bytes, owner)
}

/// `bytes` as `<dir>/<name>`, where only the daemon writes and the account
/// reads it: the session's runtime directory, the daemon's own. On Unix the
/// file is made `0600` and handed to the account through its descriptor,
/// never by a path; on Windows it takes the session directory's DACL,
/// readable by the account alone. Replaced whole, through a rename. A
/// checkpoint's request goes this way, and (P2f-2a) `hive-pack`'s.
pub(super) fn write_private(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    owner: Option<(u32, u32)>,
) -> Result<PathBuf, String> {
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let fail = |e: std::io::Error| format!("{}: {e}", tmp.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(fail)?;
        f.write_all(bytes).map_err(fail)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(fail)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = owner;
        std::fs::write(&tmp, bytes).map_err(fail)?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// The daemon's side on Unix: start `exe hive-checkpoint <request_path>` as
/// `account` (none in tests: as the daemon), with `env` and nothing of the
/// daemon's own, and hold what it writes to `req`.
#[cfg(unix)]
pub(crate) async fn run_as(
    exe: &Path,
    request_path: &Path,
    req: &Request,
    account: Option<&str>,
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    timeout: Duration,
) -> Result<(Checkpoint, Vec<Vec<u8>>), String> {
    use std::process::Stdio;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(CHECKPOINT_SUBCOMMAND)
        .arg(request_path)
        .env_clear()
        .envs(env)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Its own group, which a timeout or an abandoned checkpoint ends
        // whole, the git it started included ([`super::child::run_fed`]).
        .process_group(0);
    if let Some(account) = account {
        crate::exec::apply_session_run_as(&mut cmd, account)?;
    }
    let out = super::child::run_fed(
        cmd,
        CHECKPOINT_SUBCOMMAND,
        super::child::nothing,
        timeout,
        MAX_OUTPUT,
    )
    .await?;
    let (cp, blobs) = read_frames(&out)?;
    check(req, &cp, &blobs)?;
    Ok((cp, blobs))
}

/// The daemon's side on Windows: start `exe hive-checkpoint <request_path>`
/// as the user signed in at the console, `account` naming them as
/// `hive_accounts` does, and hold what it writes to `req`. Blocking: the
/// caller runs it off the runtime's threads.
#[cfg(windows)]
pub(crate) fn run_as_console_user(
    exe: &Path,
    request_path: &Path,
    req: &Request,
    account: &str,
    timeout: Duration,
) -> Result<(Checkpoint, Vec<Vec<u8>>), String> {
    use crate::hive_win;
    let console = hive_win::console_user().map_err(|(_, e)| e)?;
    hive_win::check_mapping(account, &console).map_err(|(_, e)| e)?;
    let line = hive_win::checkpoint_command_line(exe, request_path)?;
    // SAFETY: `console` holds the token `spawn_as` borrows, across the call.
    let out = unsafe { hive_win::run_checkpoint(console.spawn_as(), &line, timeout, MAX_OUTPUT) };
    drop(console);
    let out = out?;
    let (cp, blobs) = read_frames(&out)?;
    check(req, &cp, &blobs)?;
    Ok((cp, blobs))
}

/// This process's own request, when it was started as `roomlerd
/// hive-checkpoint <request>`.
pub fn checkpoint_args() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? != CHECKPOINT_SUBCOMMAND {
        return None;
    }
    let request = args.next()?;
    args.next().is_none().then(|| PathBuf::from(request))
}

/// The child: read the request, take the checkpoint as whoever this process
/// runs as (the session's account), write it to stdout. 0 on success; 1 with
/// a word on stderr otherwise.
pub fn checkpoint_main(request: &Path) -> i32 {
    let run = || -> Result<(), String> {
        let text =
            std::fs::read(request).map_err(|e| format!("reading {}: {e}", request.display()))?;
        if text.len() > MAX_HEADER {
            return Err("the request is too large".into());
        }
        let req: Request =
            serde_json::from_slice(&text).map_err(|e| format!("the request: {e}"))?;
        let (cp, blobs) = produce(&req, &Git::on_path())?;
        let stdout = std::io::stdout();
        let mut out = std::io::BufWriter::new(stdout.lock());
        write_frames(&mut out, &cp, &blobs).map_err(|e| format!("writing the checkpoint: {e}"))
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("roomlerd {CHECKPOINT_SUBCOMMAND}: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`super::run_as`], again while the script it runs is busy
    /// ([`super::super::child::unbusy`]): every test here writes the child
    /// it runs, and another test of this binary may fork meanwhile.
    #[cfg(unix)]
    async fn run_as(
        exe: &Path,
        request_path: &Path,
        req: &Request,
        account: Option<&str>,
        env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        timeout: Duration,
    ) -> Result<(Checkpoint, Vec<Vec<u8>>), String> {
        super::super::child::unbusy(|| {
            super::run_as(exe, request_path, req, account, env.clone(), timeout)
        })
        .await
    }

    const HID: &str = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9";
    const SID: &str = "6aca8ef5dac84dd57e492eb7";

    fn write(dir: &Path, rel: &str, text: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn request(tmp: &Path, n: u64, previous: Option<Checkpoint>) -> Request {
        Request {
            v: REQUEST_V,
            sid: SID.into(),
            harness_session: HID.into(),
            fork_of: None,
            config_dir: tmp.join("claude"),
            folder: tmp.join("work"),
            state_dir: tmp.join("state"),
            n,
            turn: n as u32,
            previous,
        }
    }

    fn session(tmp: &Path) {
        write(
            &tmp.join("claude"),
            &format!("projects/hive-{HID}/{HID}.jsonl"),
            "{\"t\":1}\n",
        );
        write(&tmp.join("claude"), "CLAUDE.md", "# rules\n");
        write(&tmp.join("work"), "main.rs", "fn main() {}\n");
    }

    /// The child's output, read back and held to the request, is what it
    /// took; a second checkpoint carries only what changed, and both resolve.
    #[test]
    fn a_checkpoint_round_trips_through_the_frames_and_holds_to_its_request() {
        let tmp = tempfile::tempdir().unwrap();
        session(tmp.path());
        let req = request(tmp.path(), 1, None);
        let (cp, blobs) = produce(&req, &Git::under(tmp.path())).unwrap();
        let mut bytes = Vec::new();
        write_frames(&mut bytes, &cp, &blobs).unwrap();
        let (back, back_blobs) = read_frames(&bytes).unwrap();
        assert_eq!(back, cp);
        assert_eq!(back_blobs, blobs);
        check(&req, &back, &back_blobs).unwrap();
        assert_eq!(cp.files.len(), 2);

        write(
            &tmp.path().join("claude"),
            &format!("projects/hive-{HID}/{HID}.jsonl"),
            "{\"t\":1}\n{\"t\":2}\n",
        );
        let req2 = request(tmp.path(), 2, Some(cp));
        let (cp2, blobs2) = produce(&req2, &Git::under(tmp.path())).unwrap();
        check(&req2, &cp2, &blobs2).unwrap();
        let history = cp2
            .files
            .iter()
            .find(|f| f.path.ends_with(".jsonl"))
            .unwrap();
        assert_eq!(history.chunks[0].offset, 8, "only the new line");
    }

    /// P2f-3a — a fork's checkpoint takes its parent's history beside its own
    /// and is held to the fork's allowlist: the same checkpoint held to a
    /// plain session's request is refused. Only a fork's request names a
    /// parent on the wire.
    #[test]
    fn a_forks_checkpoint_keeps_its_parents_history_and_is_held_to_it() {
        const PARENT: &str = "7d8e9fa0-b1c2-4d3e-8f40-5a6b7c8d9e0f";
        let tmp = tempfile::tempdir().unwrap();
        session(tmp.path());
        let config = tmp.path().join("claude");
        write(
            &config,
            &format!("projects/hive-{HID}/{PARENT}.jsonl"),
            "{\"p\":1}\n",
        );
        write(
            &config,
            &format!("projects/hive-{HID}/{PARENT}/tool-results/t1.txt"),
            "big output",
        );
        let mut req = request(tmp.path(), 1, None);
        req.fork_of = Some(PARENT.into());
        let (cp, blobs) = produce(&req, &Git::under(tmp.path())).unwrap();
        check(&req, &cp, &blobs).expect("a fork's checkpoint holds to the fork's request");
        let parents: Vec<&str> = cp
            .files
            .iter()
            .filter(|f| f.path.contains(PARENT))
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(
            parents.len(),
            2,
            "the parent's history and tool result, taken: {parents:?}"
        );
        let plain = request(tmp.path(), 1, None);
        let e = check(&plain, &cp, &blobs).unwrap_err();
        assert!(e.contains("not in the allowlist"), "{e}");
        assert!(!serde_json::to_string(&plain).unwrap().contains("fork_of"));
        assert!(serde_json::to_string(&req).unwrap().contains(PARENT));
    }

    /// Each kind of lie the account could tell is refused before the store
    /// sees it.
    #[test]
    fn what_does_not_hold_to_the_request_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        session(tmp.path());
        let req = request(tmp.path(), 1, None);
        let (cp, blobs) = produce(&req, &Git::under(tmp.path())).unwrap();
        check(&req, &cp, &blobs).unwrap();

        let refused = |cp: &Checkpoint, blobs: &[Vec<u8>], needle: &str| {
            let e = check(&req, cp, blobs).unwrap_err();
            assert!(e.contains(needle), "{e}");
        };
        let mut other = cp.clone();
        other.n = 9;
        refused(&other, &blobs, "asked for 1");

        let mut outside = cp.clone();
        outside.files[0].path = "../.ssh/id_ed25519".into();
        refused(&outside, &blobs, "not in the allowlist");
        let mut root = cp.clone();
        root.files[0].path = "sessions/1.key".into();
        refused(&root, &blobs, "not in the allowlist");
        let mut dotdot = cp.clone();
        dotdot.files[0].path = format!("projects/hive-{HID}/memory/../../../x");
        refused(&dotdot, &blobs, "not in the allowlist");

        let mut swapped = blobs.clone();
        swapped[0] = b"something else\n".to_vec();
        refused(&cp, &swapped, "not the one its chunk names");
        let mut extra = blobs.clone();
        extra.push(b"more".to_vec());
        refused(&cp, &extra, "more blobs");
        refused(&cp, &blobs[..blobs.len() - 1], "missing");

        let mut ws = cp.clone();
        if let Some(w) = ws.workspace.as_mut() {
            w.prefix = "../".into();
            refused(&ws, &blobs, "not git's");
        }
    }

    /// Bytes that are not a whole checkpoint are refused, never half read.
    #[test]
    fn truncated_or_padded_frames_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        session(tmp.path());
        let req = request(tmp.path(), 1, None);
        let (cp, blobs) = produce(&req, &Git::under(tmp.path())).unwrap();
        let mut bytes = Vec::new();
        write_frames(&mut bytes, &cp, &blobs).unwrap();
        assert!(read_frames(&bytes[..bytes.len() - 1]).is_err());
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(
            read_frames(&padded)
                .unwrap_err()
                .contains("after the last blob")
        );
        assert!(read_frames(b"HIVECP2\n").unwrap_err().contains("magic"));
        assert!(read_frames(b"").is_err());
    }

    /// The daemon's side, through a real child: what it writes is read,
    /// checked and answered; a child that writes something else, fails, or
    /// does not finish is refused in words.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_daemon_reads_and_checks_what_a_real_child_writes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        session(tmp.path());
        let req = request(tmp.path(), 1, None);
        let (cp, blobs) = produce(&req, &Git::under(tmp.path())).unwrap();
        let frames = tmp.path().join("frames.bin");
        let mut bytes = Vec::new();
        write_frames(&mut bytes, &cp, &blobs).unwrap();
        std::fs::write(&frames, &bytes).unwrap();
        let child = |name: &str, body: &str| {
            let p = tmp.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let request_path = tmp.path().join("checkpoint.json");
        let path = vec![("PATH".into(), "/usr/bin:/bin".into())];
        let fast = Duration::from_secs(10);

        let good = child(
            "good.sh",
            &format!(
                "[ \"$1\" = {CHECKPOINT_SUBCOMMAND} ] && cat {}",
                frames.display()
            ),
        );
        let (got, got_blobs) = run_as(&good, &request_path, &req, None, path.clone(), fast)
            .await
            .unwrap();
        assert_eq!((got, got_blobs), (cp.clone(), blobs.clone()));

        let lies = child("lies.sh", "printf 'HIVECP1\\n'");
        assert!(
            run_as(&lies, &request_path, &req, None, path.clone(), fast)
                .await
                .is_err()
        );
        let fails = child("fails.sh", "echo no such folder >&2; exit 3");
        let e = run_as(&fails, &request_path, &req, None, path.clone(), fast)
            .await
            .unwrap_err();
        assert!(e.contains("no such folder"), "{e}");
        let hangs = child("hangs.sh", "sleep 30");
        let e = run_as(
            &hangs,
            &request_path,
            &req,
            None,
            path,
            Duration::from_millis(300),
        )
        .await
        .unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
    }

    /// A checkpoint that is ended takes everything it started with it — its
    /// group, never the leader alone — TERM first, whether it ran out of time
    /// or was abandoned (a stop drops it). The grandchild stands for a `git
    /// add` hashing the folder, and leaves word only when TERM reaches it: a
    /// KILL cannot be trapped, and would leave a git's lock files behind.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_ended_checkpoint_takes_everything_it_started_with_it() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let req = request(tmp.path(), 1, None);
        let request_path = tmp.path().join("checkpoint.json");
        let path = vec![("PATH".into(), "/usr/bin:/bin".into())];
        let with_a_grandchild = |name: &str| {
            let p = tmp.path().join(name);
            let termed = tmp.path().join(format!("{name}.termed"));
            let body = format!(
                "sh -c 'trap \"echo > {}; exit 0\" TERM; while :; do sleep 0.05; done' &\nwait",
                termed.display()
            );
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            (p, termed)
        };
        let termed_within = |f: &Path| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !f.exists() {
                if std::time::Instant::now() > deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            true
        };

        let (late, late_termed) = with_a_grandchild("late.sh");
        let e = run_as(
            &late,
            &request_path,
            &req,
            None,
            path.clone(),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
        assert!(termed_within(&late_termed), "the timeout reached the group");

        let (dropped, dropped_termed) = with_a_grandchild("dropped.sh");
        let abandoned = tokio::time::timeout(
            Duration::from_secs(1),
            run_as(
                &dropped,
                &request_path,
                &req,
                None,
                path,
                Duration::from_secs(60),
            ),
        )
        .await;
        assert!(abandoned.is_err(), "still running when it was dropped");
        assert!(
            termed_within(&dropped_termed),
            "dropping it reached the group"
        );
    }

    /// A request of another version is refused, not read by guesswork.
    #[test]
    fn a_request_of_another_version_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut req = request(tmp.path(), 1, None);
        req.v = 2;
        assert!(
            produce(&req, &Git::under(tmp.path()))
                .unwrap_err()
                .contains("version 2")
        );
    }
}
