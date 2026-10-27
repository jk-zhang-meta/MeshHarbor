// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2b-4 — `meshharbord hive-materialize`: a checkpoint put back into a
//! session's config directory (P2b-4a) and its folder (P2b-4b) AS THE TARGET'S
//! ACCOUNT, from what the daemon streams to its stdin.
//!
//! The reverse of `hive-checkpoint` (P2b-3a), for the same reason: the daemon
//! never writes a path in an account's tree (spec §3b). It starts `roomlerd
//! hive-materialize` as the account and streams it the checkpoint it
//! materializes:
//!
//! ```text
//! "HIVEMZ1\n"                        the magic
//! u32 le · JSON {"target": …}        where to, every file's entry, the workspace's
//! ( u64 le · bytes ) × files         each file whole, in the entries' order
//! ( u64 le · bytes ) × packs         the workspace's packs, oldest first
//! ```
//!
//! The daemon reads each file and pack out of the chain chunk by chunk
//! ([`plan`], `checkpoint::chunks_of`), never holding a history whole, and the
//! child answers with one line on stdout, `{"files":N,"removed":M,…}`. The
//! folder goes through the account's own git ([`workspace`]): its packs into
//! the folder's repository, then git's own two-tree switch.
//!
//! ⚠️ **What comes in is another device's word.** A checkpoint was taken by
//! whichever member was primary, and this daemon only relays it. So the child
//! holds every name to the allowlist, and to what this OS can hold
//! ([`refusal`]), before it writes anything, and each file to its entry's
//! length and hash before any is put in place. A refusal writes nothing.
//!
//! ⚠️ The allowlisted part of the config directory ends up exactly the
//! checkpoint's: a file in it the checkpoint does not list is removed, and
//! nothing outside it is touched — a login (`.credentials.json`), the
//! harness's own state, the settings the daemon writes elsewhere.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use roomler_hive_node::checkpoint::{
    self, Checkpoint, Chunk, Digest, MAX_DEPTH, MAX_FILES, RepoKind, WorkspaceSnap,
};
use roomler_hive_node::store::Substitute;
use serde::{Deserialize, Serialize};

use super::checkpointer::{Runner, allowed};
use super::workspace::{self, Git};

/// The hidden subcommand: `meshharbord hive-materialize`, fed on its stdin.
pub const MATERIALIZE_SUBCOMMAND: &str = "hive-materialize";

/// The first bytes the daemon writes.
const MAGIC: &[u8; 8] = b"HIVEMZ1\n";

/// The most header bytes read: the entries of [`MAX_FILES`] files.
const MAX_HEADER: usize = 16 * 1024 * 1024;

/// The most the child answers: one line.
const MAX_ANSWER: u64 = 64 * 1024;

/// The longest path Windows' own `MAX_PATH` holds (260, with its NUL), which
/// Claude Code and `git` keep to unless long paths are turned on.
const WINDOWS_MAX_PATH: usize = 259;

/// Bumped when the fields change their meaning; a child refuses another.
pub(crate) const TARGET_V: u32 = 1;

/// How long a materialize may run: a first one of a long history writes all
/// of it.
pub(crate) const MATERIALIZE_TIMEOUT: Duration = Duration::from_secs(300);

/// Where a checkpoint is materialized, and what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Target {
    pub v: u32,
    /// The harness's session id (a UUID): the allowlist's names.
    pub harness_session: String,
    /// FR-90 P2f-3a — for a fork, the harness session it was made from: its
    /// allowlist is the fork's ([`checkpoint::allowlist_of`]). Absent for every
    /// other session, so a target of a build before it reads the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_of: Option<String>,
    /// The session's `CLAUDE_CONFIG_DIR` on this device.
    pub config_dir: PathBuf,
    /// Every file of the checkpoint, in path order; each arrives whole, in
    /// this order.
    pub files: Vec<Entry>,
    /// P2b-4b — the session's folder, when the last checkpoint took one: its
    /// packs arrive after the files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Workspace>,
}

/// Where the session's folder is materialized, and what goes in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Workspace {
    /// The Hive session id (24 hex): the temporary index's and the ref's
    /// names.
    pub sid: String,
    /// The session's folder on this device.
    pub folder: PathBuf,
    /// The session's state directory on this device: a shadow repository's
    /// home.
    pub state_dir: PathBuf,
    /// The last checkpoint's tree and commit.
    pub tree: String,
    pub commit: String,
    /// Each pack's length, in the order they arrive: from the last whole pack
    /// on, each thin against the one before.
    pub packs: Vec<u64>,
    /// P2f-2a — what the first pack is thin against when it is a substitute
    /// for a whole one ([`plan`]): commits the folder's repository holds
    /// already, every one of them, or nothing is materialized. Empty for a
    /// whole pack.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub against: Vec<String>,
}

/// One file as the checkpoint has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// Relative to the config directory, `/`-separated.
    pub path: String,
    pub len: u64,
    pub hash: Digest,
}

/// What a materialize did: the files it put in place, the ones the
/// checkpoint no longer lists that it removed, and the folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Done {
    pub files: usize,
    pub removed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Placed>,
}

/// The folder a materialize moved (P2b-4b): its repository's kind, and the
/// tree it was held to afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Placed {
    pub repo: RepoKind,
    pub tree: String,
}

/// Where on this device a session's checkpoint goes.
pub(crate) struct Dest {
    /// The Hive session id.
    pub sid: String,
    /// The harness's session id (a UUID).
    pub harness_session: String,
    /// P2f-3a — for a fork, the harness session it was made from.
    pub fork_of: Option<String>,
    pub config_dir: PathBuf,
    pub folder: PathBuf,
    pub state_dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Header {
    target: Target,
}

/// What the target's file system can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Os {
    Linux,
    /// Case-insensitive by default: two names that differ only in case are
    /// one file.
    Mac,
    /// Case-insensitive too, and it refuses device names, some characters, a
    /// trailing dot or space, and long paths.
    Windows,
}

impl Os {
    pub(crate) fn this() -> Self {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Mac
        } else {
            Os::Linux
        }
    }
}

// ─── the daemon's side ──────────────────────────────────────────────────────

/// What is streamed after the header: each file's chunks, then each pack's,
/// in the order the header names them.
pub(crate) struct Planned {
    pub files: Vec<Vec<Chunk>>,
    pub packs: Vec<Vec<Chunk>>,
}

/// The target for materializing the last of `chain` (oldest first) at
/// `dest`, and the chunks that make each of its files and packs. P2f-2a — a
/// whole pack one of `substitutes` stands in for is not read: the walk ends
/// at the substitute ([`packs_of`]).
pub(crate) fn plan(
    chain: &[Checkpoint],
    dest: &Dest,
    substitutes: &[Substitute],
) -> Result<(Target, Planned), String> {
    let last = chain.last().ok_or("no checkpoint to materialize")?;
    if last.files.len() > MAX_FILES {
        return Err(format!("{} files", last.files.len()));
    }
    let allow = checkpoint::allowlist_of(&dest.harness_session, dest.fork_of.as_deref())
        .map_err(|e| e.to_string())?;
    let mut files = Vec::with_capacity(last.files.len());
    let mut file_chunks = Vec::with_capacity(last.files.len());
    for f in &last.files {
        if !allowed(&f.path, &allow) {
            return Err(format!("{} is not in the allowlist", f.path));
        }
        let (cs, entry) = checkpoint::chunks_of(&f.path, chain).map_err(|e| e.to_string())?;
        files.push(Entry {
            path: entry.path.clone(),
            len: entry.len,
            hash: entry.hash,
        });
        file_chunks.push(cs);
    }
    let (workspace, packs) = match &last.workspace {
        None => (None, Vec::new()),
        Some(ws) => {
            let (packs, against) = packs_of(chain, ws, substitutes)?;
            let lens = packs
                .iter()
                .map(|p| p.iter().map(|c| c.len).sum())
                .collect();
            let target = Workspace {
                sid: dest.sid.clone(),
                folder: dest.folder.clone(),
                state_dir: dest.state_dir.clone(),
                tree: ws.tree.clone(),
                commit: ws.commit.clone(),
                packs: lens,
                against,
            };
            (Some(target), packs)
        }
    };
    Ok((
        Target {
            v: TARGET_V,
            harness_session: dest.harness_session.clone(),
            fork_of: dest.fork_of.clone(),
            config_dir: dest.config_dir.clone(),
            files,
            workspace,
        },
        Planned {
            files: file_chunks,
            packs,
        },
    ))
}

/// The packs that bring `last`'s commit, oldest first: back from it along
/// each `base` to a whole pack (one with no base), past the turns that
/// changed nothing (an empty pack, the same commit). Each pack's chunks must
/// follow one another from offset 0.
///
/// P2f-2a — a whole pack one of `substitutes` stands in for ends the walk at
/// the substitute, and what that is thin against comes back with the packs:
/// the folder's repository must hold every one of those commits. Only a
/// whole pack is ever stood in for; a thin one's commit is never looked up.
fn packs_of(
    chain: &[Checkpoint],
    last: &WorkspaceSnap,
    substitutes: &[Substitute],
) -> Result<(Vec<Vec<Chunk>>, Vec<String>), String> {
    let mut need = last.commit.as_str();
    let mut packs = Vec::new();
    for cp in chain.iter().rev() {
        let Some(ws) = cp.workspace.as_ref() else {
            break;
        };
        if ws.commit != need {
            return Err(format!(
                "checkpoint {}'s workspace is {}, where {need} was to come before",
                cp.n, ws.commit
            ));
        }
        if ws.pack.is_empty() {
            continue;
        }
        let sub = ws
            .base
            .is_none()
            .then(|| substitutes.iter().find(|s| s.commit == ws.commit))
            .flatten();
        let (chunks, what) = match sub {
            Some(s) => (
                &s.chunks,
                format!("the substitute for checkpoint {}'s pack", cp.n),
            ),
            None => (&ws.pack, format!("checkpoint {}'s pack", cp.n)),
        };
        if chunks.is_empty() {
            return Err(format!("{what} is empty"));
        }
        let mut offset = 0u64;
        for chunk in chunks {
            if chunk.offset != offset {
                return Err(format!("{what} has a gap"));
            }
            offset += chunk.len;
        }
        if offset > workspace::MAX_PACK as u64 {
            return Err(format!("{what} is over its limit"));
        }
        packs.push(chunks.clone());
        if let Some(s) = sub {
            packs.reverse();
            return Ok((packs, s.against.clone()));
        }
        match ws.base.as_deref() {
            Some(base) => need = base,
            None => {
                packs.reverse();
                return Ok((packs, Vec::new()));
            }
        }
    }
    Err("the chain does not reach a whole pack of the workspace".into())
}

/// FR-90 P2f-3a — the parent's `chain` (oldest first) as a fork's first start
/// puts it in place: the parent's own files ([`checkpoint::allowlist`]), each
/// moved from the parent's project directory to the fork's with its name
/// kept. So the parent's history becomes `projects/hive-<fork>/<parent>.jsonl`,
/// where `--resume <parent> --fork-session` finds it under the fork's pinned
/// project name, and its tool results stay where the history it is copied
/// into names them, relative to the project directory. `CLAUDE.md` stays
/// where it is. Every checkpoint is moved alike, so each file's chunks still
/// follow one another.
///
/// What the parent holds of a session further back (a fork's own parent) is
/// left out: the parent's history holds those turns already. The workspace is
/// the parent's, which the fork's [`Dest`] puts in place under the fork's id.
pub(crate) fn forked(
    chain: &[Checkpoint],
    parent: &str,
    fork: &str,
) -> Result<Vec<Checkpoint>, String> {
    let own = checkpoint::allowlist(parent).map_err(|e| e.to_string())?;
    // The fork's names hold too, and are never the parent's.
    checkpoint::allowlist_of(fork, Some(parent)).map_err(|e| e.to_string())?;
    let (from, to) = (
        format!("projects/hive-{parent}/"),
        format!("projects/hive-{fork}/"),
    );
    Ok(chain
        .iter()
        .map(|cp| Checkpoint {
            files: cp
                .files
                .iter()
                .filter(|f| allowed(&f.path, &own))
                .map(|f| checkpoint::FileSnap {
                    path: f
                        .path
                        .strip_prefix(&from)
                        .map_or_else(|| f.path.clone(), |rest| format!("{to}{rest}")),
                    ..f.clone()
                })
                .collect(),
            ..cp.clone()
        })
        .collect())
}

/// Where the daemon reads the blobs: the session's store; a map in tests.
pub(crate) enum Blobs<'a> {
    Store {
        store: &'a super::store::StoreHandle,
        session: &'a str,
    },
    #[cfg(test)]
    Map(&'a std::collections::HashMap<Digest, Vec<u8>>),
}

impl Blobs<'_> {
    async fn get(&self, hash: &Digest) -> Result<Option<Vec<u8>>, String> {
        match self {
            Blobs::Store { store, session } => store
                .get_blob(session, hash.0)
                .await
                .map_err(|e| e.to_string()),
            #[cfg(test)]
            Blobs::Map(m) => Ok(m.get(hash).cloned()),
        }
    }

    /// P2f-2a — the substitutes kept for `chain`'s whole packs whose own
    /// blobs are not all here: what [`plan`] ends its walk on. A whole pack
    /// that is here is read as it is, whatever stands in for it.
    async fn substitutes(&self, chain: &[Checkpoint]) -> Result<Vec<Substitute>, String> {
        let (store, session) = match self {
            Blobs::Store { store, session } => (store, session),
            #[cfg(test)]
            Blobs::Map(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        let whole = chain
            .iter()
            .filter_map(|c| c.workspace.as_ref())
            .filter(|ws| ws.base.is_none() && !ws.pack.is_empty());
        for ws in whole {
            let mut held = true;
            for chunk in &ws.pack {
                if !store
                    .has_blob(session, chunk.hash.0)
                    .await
                    .map_err(|e| e.to_string())?
                {
                    held = false;
                    break;
                }
            }
            if held {
                continue;
            }
            if let Some(sub) = store
                .substitute(session, &ws.commit)
                .await
                .map_err(|e| e.to_string())?
            {
                out.push(sub);
            }
        }
        Ok(out)
    }
}

/// Where the daemon writes the frames: a child's stdin, or on Windows the
/// thread that feeds its pipe.
pub(crate) trait Sink {
    async fn put(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

#[cfg(unix)]
impl Sink for tokio::process::ChildStdin {
    async fn put(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        tokio::io::AsyncWriteExt::write_all(self, bytes).await
    }
}

#[cfg(windows)]
impl Sink for tokio::sync::mpsc::Sender<Vec<u8>> {
    async fn put(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.send(bytes.to_vec())
            .await
            .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
    }
}

/// The in-process runner's: tests, and an integration test's device
/// (`hive-test-launcher`, P2d-6).
#[cfg(any(test, all(unix, feature = "hive-test-launcher")))]
impl Sink for Vec<u8> {
    async fn put(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// Why the frames stopped.
pub(crate) enum Stop {
    /// The child stopped reading: its own word says why.
    Pipe,
    /// The daemon's side: a blob the store lacks, or one that is not what its
    /// chunk names. The child got a short stream and wrote nothing.
    Source(String),
}

/// Write `target`'s frames to `out`: the header, then each file's bytes,
/// blob by blob, each held to its chunk before it goes.
pub(crate) async fn write_frames(
    out: &mut impl Sink,
    target: &Target,
    planned: &Planned,
    blobs: &Blobs<'_>,
) -> Result<(), Stop> {
    let header = serde_json::to_vec(&Header {
        target: target.clone(),
    })
    .map_err(|e| Stop::Source(e.to_string()))?;
    let header_len =
        u32::try_from(header.len()).map_err(|_| Stop::Source("the header is too large".into()))?;
    let pipe = |_: std::io::Error| Stop::Pipe;
    out.put(MAGIC).await.map_err(pipe)?;
    out.put(&header_len.to_le_bytes()).await.map_err(pipe)?;
    out.put(&header).await.map_err(pipe)?;
    for (entry, chunks) in target.files.iter().zip(&planned.files) {
        out.put(&entry.len.to_le_bytes()).await.map_err(pipe)?;
        put_chunks(out, &entry.path, chunks, blobs).await?;
    }
    let lens = target.workspace.as_ref().map_or(&[][..], |w| &w.packs[..]);
    for (i, (len, chunks)) in lens.iter().zip(&planned.packs).enumerate() {
        out.put(&len.to_le_bytes()).await.map_err(pipe)?;
        put_chunks(out, &format!("the workspace's pack {i}"), chunks, blobs).await?;
    }
    Ok(())
}

/// The bytes `chunks` name, blob by blob, each held to its chunk.
async fn put_chunks(
    out: &mut impl Sink,
    what: &str,
    chunks: &[Chunk],
    blobs: &Blobs<'_>,
) -> Result<(), Stop> {
    for chunk in chunks {
        let data = blobs.get(&chunk.hash).await.map_err(Stop::Source)?;
        let data = data
            .ok_or_else(|| Stop::Source(format!("{what}: the blob {} is missing", chunk.hash)))?;
        if data.len() as u64 != chunk.len || Digest::of(&data) != chunk.hash {
            return Err(Stop::Source(format!(
                "{what}: the blob {} is not what was named",
                chunk.hash
            )));
        }
        out.put(&data).await.map_err(|_| Stop::Pipe)?;
    }
    Ok(())
}

/// Who a session's children run as on this device.
pub(crate) struct Who {
    /// `None`: as the daemon (the test launcher).
    pub account: Option<String>,
    /// The child's environment on Unix: the account's own, as the harness's.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}

/// Materialize the last of `chain` (oldest first) at `dest`, the session's
/// place on this device, as `who`: the target's half of a promotion (P2e) and
/// of a teleport (P2f).
pub(crate) async fn materialize(
    run: &Runner,
    who: &Who,
    chain: &[Checkpoint],
    dest: &Dest,
    blobs: &Blobs<'_>,
) -> Result<Done, String> {
    let substitutes = blobs.substitutes(chain).await?;
    let (target, planned) = plan(chain, dest, &substitutes)?;
    match run {
        Runner::Subprocess => {
            let exe = PathBuf::from(super::supervisor::own_exe()?);
            #[cfg(unix)]
            {
                run_as(
                    &exe,
                    who.account.as_deref(),
                    who.env.clone(),
                    &target,
                    &planned,
                    blobs,
                    MATERIALIZE_TIMEOUT,
                )
                .await
            }
            #[cfg(windows)]
            {
                let account = who.account.clone().ok_or("no account to run as")?;
                run_as_console_user(&exe, account, &target, &planned, blobs, MATERIALIZE_TIMEOUT)
                    .await
            }
        }
        #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
        Runner::InProcess { ceiling } => {
            let mut bytes = Vec::new();
            write_frames(&mut bytes, &target, &planned, blobs)
                .await
                .map_err(|s| match s {
                    Stop::Source(e) => e,
                    Stop::Pipe => "the frames could not be written".into(),
                })?;
            materialize_from(&mut bytes.as_slice(), Os::this(), &Git::under(ceiling))
        }
        #[cfg(all(test, unix))]
        Runner::Failing(why) => Err((*why).to_string()),
        #[cfg(all(test, unix))]
        Runner::Hangs => std::future::pending().await,
    }
}

/// The child's one line.
fn read_answer(out: &[u8]) -> Result<Done, String> {
    serde_json::from_slice(out.trim_ascii())
        .map_err(|e| format!("{MATERIALIZE_SUBCOMMAND} answered something else: {e}"))
}

/// The daemon's side on Unix: start `exe hive-materialize` as `account` (none
/// in tests: as the daemon), with `env` and nothing of the daemon's own, and
/// stream it `target`'s files.
#[cfg(unix)]
pub(crate) async fn run_as(
    exe: &Path,
    account: Option<&str>,
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    target: &Target,
    planned: &Planned,
    blobs: &Blobs<'_>,
    timeout: Duration,
) -> Result<Done, String> {
    use super::child::{Fed, run_fed};
    use std::process::Stdio;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(MATERIALIZE_SUBCOMMAND)
        .env_clear()
        .envs(env)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Its own group, ended whole on a timeout or when abandoned.
        .process_group(0);
    if let Some(account) = account {
        crate::exec::apply_session_run_as(&mut cmd, account)?;
    }
    let feed = |mut stdin: tokio::process::ChildStdin| async move {
        // `stdin` is dropped at the end: the child's end of input.
        match write_frames(&mut stdin, target, planned, blobs).await {
            Ok(()) => Fed::Done,
            Err(Stop::Pipe) => Fed::Closed,
            Err(Stop::Source(e)) => Fed::Failed(e),
        }
    };
    let out = run_fed(cmd, MATERIALIZE_SUBCOMMAND, feed, timeout, MAX_ANSWER).await?;
    read_answer(&out)
}

/// The daemon's side on Windows: start `exe hive-materialize` as the user
/// signed in at the console, `account` naming them as `hive_accounts` does,
/// and stream it `target`'s files through a thread that feeds its pipe.
#[cfg(windows)]
pub(crate) async fn run_as_console_user(
    exe: &Path,
    account: String,
    target: &Target,
    planned: &Planned,
    blobs: &Blobs<'_>,
    timeout: Duration,
) -> Result<Done, String> {
    let (mut tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let exe = exe.to_path_buf();
    let child = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        use crate::hive_win;
        let console = hive_win::console_user().map_err(|(_, e)| e)?;
        hive_win::check_mapping(&account, &console).map_err(|(_, e)| e)?;
        let line = hive_win::materialize_command_line(&exe)?;
        // SAFETY: `console` holds the token `spawn_as` borrows, across the call.
        let out = unsafe {
            hive_win::run_fed(
                console.spawn_as(),
                &line,
                Some(rx),
                "the materialize",
                timeout,
                MAX_ANSWER,
            )
        };
        drop(console);
        out
    });
    let fed = write_frames(&mut tx, target, planned, blobs).await;
    // The child's end of input.
    drop(tx);
    let out = child
        .await
        .map_err(|e| format!("the materialize's thread: {e}"))?;
    match (fed, out) {
        (Err(Stop::Source(e)), _) => Err(e),
        (_, Err(e)) => Err(e),
        (Err(Stop::Pipe), Ok(_)) => Err(format!(
            "{MATERIALIZE_SUBCOMMAND} stopped reading before the end"
        )),
        (Ok(()), Ok(out)) => read_answer(&out),
    }
}

// ─── the child's side ───────────────────────────────────────────────────────

/// Whether this process was started as `meshharbord hive-materialize`.
pub fn materialize_args() -> bool {
    let mut args = std::env::args_os().skip(1);
    args.next().is_some_and(|a| a == MATERIALIZE_SUBCOMMAND) && args.next().is_none()
}

/// The child: materialize what arrives on stdin as whoever this process runs
/// as (the session's account), and answer on stdout. 0 on success; 1 with a
/// word on stderr otherwise.
pub fn materialize_main() -> i32 {
    let stdin = std::io::stdin();
    let mut input = std::io::BufReader::new(stdin.lock());
    let answer = materialize_from(&mut input, Os::this(), &Git::on_path())
        .and_then(|done| serde_json::to_string(&done).map_err(|e| e.to_string()));
    match answer {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// The child's work, as the account: read the frames from `r`; hold every
/// name to the allowlist and to what `os` can hold, and every place to being
/// a directory of its own, before writing anything; stage each file beside
/// where it goes and hold it to its entry. Then the workspace, through `git`:
/// its packs into the folder's repository, the commit's tree held to the
/// checkpoint's, the tree's names to what `os` can hold, and the folder to
/// being one it is safe to replace. Only when every check is passed is the
/// folder switched, the files put in place, and what the checkpoint no longer
/// lists removed.
pub(crate) fn materialize_from(r: &mut impl Read, os: Os, git: &Git) -> Result<Done, String> {
    let mut magic = [0u8; 8];
    if r.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return Err("not a materialize stream (no magic)".into());
    }
    let header_len = u32::from_le_bytes(read_array(r, "the header's length")?) as usize;
    if header_len > MAX_HEADER {
        return Err(format!("a header of {header_len} bytes"));
    }
    let mut header = vec![0u8; header_len];
    r.read_exact(&mut header)
        .map_err(|_| "the stream ends inside the header".to_string())?;
    let Header { target } =
        serde_json::from_slice(&header).map_err(|e| format!("the header: {e}"))?;
    if target.v != TARGET_V {
        return Err(format!(
            "a target of version {}; this build reads {TARGET_V}",
            target.v
        ));
    }
    if let Some(why) = refusal(&target, os) {
        return Err(why);
    }
    check_places(&target)?;
    make_private_dir_all(&target.config_dir)?;
    let mut staged = Staged::default();
    for (i, e) in target.files.iter().enumerate() {
        let len = u64::from_le_bytes(read_array(r, "a file's length")?);
        if len != e.len {
            return Err(format!(
                "{} arrives as {len} bytes; its entry says {}",
                e.path, e.len
            ));
        }
        make_parents(&target.config_dir, &e.path)?;
        let dest = place_of(&target.config_dir, &e.path);
        let tmp = dest.with_file_name(format!(".hive-mz-{i}.tmp"));
        let mut f = new_private(&tmp)?;
        staged.0.push((tmp, dest));
        let got = copy_exact(r, &mut f, len).map_err(|why| format!("{}: {why}", e.path))?;
        if got != e.hash {
            return Err(format!("{} is not the file its entry names", e.path));
        }
    }
    let prepared = match &target.workspace {
        None => None,
        Some(ws) => Some(prepare(r, os, git, ws)?),
    };
    let mut more = [0u8; 1];
    match r.read(&mut more) {
        Ok(0) => {}
        Ok(_) => return Err("bytes after the last frame".into()),
        Err(e) => return Err(format!("reading: {e}")),
    }
    let placed = match (&target.workspace, &prepared) {
        (Some(ws), Some((place, current))) => {
            workspace::switch(git, place, &ws.sid, current, &ws.tree, &ws.commit)
                .map_err(|e| format!("the workspace: {e}"))?;
            Some(Placed {
                repo: place.kind(),
                tree: ws.tree.clone(),
            })
        }
        _ => None,
    };
    staged.place()?;
    let removed = remove_unlisted(&target)?;
    Ok(Done {
        files: target.files.len(),
        removed,
        workspace: placed,
    })
}

/// The workspace, up to the switch: its packs into the folder's repository
/// (git checks each object as it lands), the commit's tree held to the
/// checkpoint's, every name in it to what `os` can hold, and the folder to
/// being one it is safe to replace. The folder itself is not touched.
fn prepare(
    r: &mut impl Read,
    os: Os,
    git: &Git,
    ws: &Workspace,
) -> Result<(workspace::Place, workspace::Current), String> {
    let at = |e: String| format!("the workspace: {e}");
    let place = workspace::place_for(git, &ws.folder, &ws.state_dir).map_err(at)?;
    // P2f-2a — a substitute's pack is thin against commits the folder's
    // repository must hold already: without them git could resolve none of
    // its deltas, and the tree would not be whole.
    if !ws.against.is_empty() {
        let held = workspace::place_holds(git, &place, &ws.against).map_err(at)?;
        if let Some(missing) = ws.against.iter().find(|c| !held.contains(c)) {
            return Err(at(format!(
                "the folder's repository holds no commit {missing}, which the copy's pack is thin against"
            )));
        }
    }
    for (i, &len) in ws.packs.iter().enumerate() {
        let got = u64::from_le_bytes(read_array(r, "a pack's length")?);
        if got != len {
            return Err(format!(
                "the workspace's pack {i} arrives as {got} bytes; the header says {len}"
            ));
        }
        workspace::index_pack(git, &place, r, len).map_err(at)?;
    }
    let tree = workspace::tree_of(git, &place, &ws.commit).map_err(at)?;
    if tree != ws.tree {
        return Err(format!(
            "the workspace: commit {} holds the tree {tree}, not the checkpoint's {}",
            ws.commit, ws.tree
        ));
    }
    let paths = workspace::tree_paths(git, &place, &ws.tree).map_err(at)?;
    if let Some(why) = names_refusal(&ws.folder, paths.iter().map(String::as_str), os) {
        return Err(at(why));
    }
    let current = workspace::judge(git, &place, &ws.sid, &ws.tree).map_err(at)?;
    Ok((place, current))
}

fn read_array<const N: usize>(r: &mut impl Read, what: &str) -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    r.read_exact(&mut b)
        .map_err(|_| format!("the stream ends inside {what}"))?;
    Ok(b)
}

/// Why `target` cannot be written on `os`, if it cannot: too many files, a
/// name out of order or outside the allowlist, one this OS cannot hold
/// ([`names_refusal`]), or a workspace that names something that is not git's.
pub(crate) fn refusal(target: &Target, os: Os) -> Option<String> {
    let allow = match checkpoint::allowlist_of(&target.harness_session, target.fork_of.as_deref()) {
        Ok(a) => a,
        Err(e) => return Some(e.to_string()),
    };
    if target.files.len() > MAX_FILES {
        return Some(format!("{} files", target.files.len()));
    }
    let mut last: Option<&str> = None;
    for e in &target.files {
        if last.is_some_and(|p| p >= e.path.as_str()) {
            return Some(format!("{} is out of order", e.path));
        }
        last = Some(&e.path);
        if !allowed(&e.path, &allow) {
            return Some(format!("{} is not in the allowlist", e.path));
        }
    }
    if let Some(why) = names_refusal(
        &target.config_dir,
        target.files.iter().map(|e| e.path.as_str()),
        os,
    ) {
        return Some(why);
    }
    if let Some(ws) = &target.workspace {
        let sid_ok = ws.sid.len() == 24
            && ws
                .sid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let is_id = |s: &str| {
            (s.len() == 40 || s.len() == 64)
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !sid_ok || !is_id(&ws.tree) || !is_id(&ws.commit) || !ws.against.iter().all(|c| is_id(c))
        {
            return Some("the workspace names something that is not git's".into());
        }
        if ws.packs.iter().any(|&l| l > workspace::MAX_PACK as u64) {
            return Some("a workspace pack is over its limit".into());
        }
        if ws.against.len() > workspace::MAX_HAVES {
            return Some(format!(
                "the workspace's first pack is thin against more than {} commits",
                workspace::MAX_HAVES
            ));
        }
    }
    None
}

/// Why `paths` (`/`-separated, under `base`) cannot all be held on `os`, if
/// they cannot. On Windows: a name it refuses ([`windows_name`]), or a path
/// past its length where it goes. On Windows and macOS: two names that are
/// one there, files or the directories on their way (`Dir/a` beside `dir/b`
/// is one directory).
fn names_refusal<'a>(
    base: &Path,
    paths: impl IntoIterator<Item = &'a str>,
    os: Os,
) -> Option<String> {
    let mut folded: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for p in paths {
        if os == Os::Windows {
            if let Some(why) = p.split('/').find_map(windows_name) {
                return Some(format!("{p}: {why}"));
            }
            let n = place_of(base, p).to_string_lossy().encode_utf16().count();
            if n > WINDOWS_MAX_PATH {
                return Some(format!(
                    "{p}: {n} characters where it goes, past Windows' {WINDOWS_MAX_PATH}"
                ));
            }
        }
        if os != Os::Linux {
            // Every prefix of the path, each directory on its way and itself.
            let ends = p.match_indices('/').map(|(i, _)| i).chain([p.len()]);
            for end in ends {
                let prefix = &p[..end];
                match folded.get(&prefix.to_lowercase()) {
                    Some(seen) if *seen != prefix => {
                        return Some(format!(
                            "{p}: {prefix} and {seen} differ only in case, and are one here"
                        ));
                    }
                    Some(_) => {}
                    None => {
                        folded.insert(prefix.to_lowercase(), prefix);
                    }
                }
            }
        }
    }
    None
}

/// Why Windows cannot hold a file or directory named `name`, if it cannot.
fn windows_name(name: &str) -> Option<&'static str> {
    let bad_char = name
        .chars()
        .any(|c| (c as u32) < 0x20 || matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'));
    if bad_char {
        return Some("a character Windows does not allow in a name");
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return Some("a name that ends in a space or a dot");
    }
    // A device name is reserved with any extension: `aux.md` is AUX.
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ');
    let stem = stem.to_uppercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    };
    let device = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered("COM")
        || numbered("LPT");
    device.then_some("a name Windows keeps for a device")
}

/// `rel` (`/`-separated) under `root`, in this OS's separators.
fn place_of(root: &Path, rel: &str) -> PathBuf {
    rel.split('/').fold(root.to_path_buf(), |p, c| p.join(c))
}

/// Every place a file goes is a directory of its own, all the way down from
/// the config directory, never a link to one; and no file goes where a
/// directory is. Checked before anything is written, so a refusal writes
/// nothing.
fn check_places(target: &Target) -> Result<(), String> {
    for e in &target.files {
        let mut dir = target.config_dir.clone();
        let parts: Vec<&str> = e.path.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            dir.push(part);
            match std::fs::symlink_metadata(&dir) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                Ok(_) => {
                    return Err(format!(
                        "{}: {} is not a directory of its own",
                        e.path,
                        dir.display()
                    ));
                }
                // Missing: made when the file is staged.
                Err(_) => break,
            }
        }
        if let Ok(m) = std::fs::symlink_metadata(place_of(&target.config_dir, &e.path))
            && m.is_dir()
            && !m.file_type().is_symlink()
        {
            return Err(format!("{}: a directory is where it goes", e.path));
        }
    }
    Ok(())
}

/// The directories `rel` goes in, under `root`, made where missing: private,
/// and never through a link.
fn make_parents(root: &Path, rel: &str) -> Result<(), String> {
    let mut dir = root.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        dir.push(part);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(_) => return Err(format!("{} is not a directory of its own", dir.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => make_private_dir(&dir)?,
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        }
    }
    Ok(())
}

fn make_private_dir(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    let made = {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    };
    #[cfg(not(unix))]
    let made = std::fs::create_dir(dir);
    match made {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

fn make_private_dir_all(dir: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// A new file only the account reads (Unix `0600`): the config directory is
/// the session's private state, whatever mode the checkpoint's OS kept.
fn new_private(path: &Path) -> Result<std::fs::File, String> {
    // A run before this one stopped here.
    let _ = std::fs::remove_file(path);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Copy exactly `len` bytes of `r` into `f`, answering their hash.
fn copy_exact(r: &mut impl Read, f: &mut std::fs::File, len: u64) -> Result<Digest, String> {
    let mut hasher = checkpoint::Hasher::new();
    let mut left = len;
    let mut buf = vec![0u8; 64 * 1024];
    while left > 0 {
        let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        let n = r
            .read(&mut buf[..want])
            .map_err(|e| format!("reading: {e}"))?;
        if n == 0 {
            return Err("the stream ends inside it".into());
        }
        hasher.update(&buf[..n]);
        f.write_all(&buf[..n])
            .map_err(|e| format!("writing: {e}"))?;
        left -= n as u64;
    }
    Ok(hasher.finish())
}

/// Files written beside where they go, and not yet put there: removed when
/// the materialize stops before [`Staged::place`] puts them.
#[derive(Default)]
struct Staged(Vec<(PathBuf, PathBuf)>);

impl Staged {
    fn place(mut self) -> Result<(), String> {
        while let Some((tmp, dest)) = self.0.pop() {
            if let Err(e) = std::fs::rename(&tmp, &dest) {
                let why = format!("{}: {e}", dest.display());
                self.0.push((tmp, dest));
                return Err(why);
            }
        }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        for (tmp, _) in &self.0 {
            let _ = std::fs::remove_file(tmp);
        }
    }
}

/// Remove every file in the allowlist the checkpoint does not list: never
/// through a link, and no deeper than a checkpoint looks.
fn remove_unlisted(target: &Target) -> Result<usize, String> {
    let listed: HashSet<&str> = target.files.iter().map(|e| e.path.as_str()).collect();
    let allow = checkpoint::allowlist_of(&target.harness_session, target.fork_of.as_deref())
        .map_err(|e| e.to_string())?;
    let mut removed = 0;
    for entry in &allow {
        let full = place_of(&target.config_dir, &entry.rel);
        let Ok(meta) = std::fs::symlink_metadata(&full) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if entry.is_dir && meta.is_dir() {
            removed += remove_under(&full, &entry.rel, &listed, 0)?;
        } else if !entry.is_dir && meta.is_file() && !listed.contains(entry.rel.as_str()) {
            std::fs::remove_file(&full).map_err(|e| format!("{}: {e}", entry.rel))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn remove_under(
    dir: &Path,
    rel: &str,
    listed: &HashSet<&str>,
    depth: usize,
) -> Result<usize, String> {
    if depth >= MAX_DEPTH {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{rel}: {e}"))? {
        let entry = entry.map_err(|e| format!("{rel}: {e}"))?;
        let name = entry.file_name();
        // A checkpoint never names it either.
        let Some(name) = name.to_str() else { continue };
        let child_rel = format!("{rel}/{name}");
        let child = entry.path();
        let meta = std::fs::symlink_metadata(&child).map_err(|e| format!("{child_rel}: {e}"))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            removed += remove_under(&child, &child_rel, listed, depth + 1)?;
        } else if meta.is_file() && !listed.contains(child_rel.as_str()) {
            std::fs::remove_file(&child).map_err(|e| format!("{child_rel}: {e}"))?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`super::run_as`], again while the script it runs is busy
    /// ([`super::super::child::unbusy`]): a test here writes the child it
    /// runs, and another test of this binary may fork meanwhile.
    #[cfg(unix)]
    async fn run_as(
        exe: &Path,
        account: Option<&str>,
        env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        target: &Target,
        planned: &Planned,
        blobs: &Blobs<'_>,
        timeout: Duration,
    ) -> Result<Done, String> {
        super::super::child::unbusy(|| {
            super::run_as(exe, account, env.clone(), target, planned, blobs, timeout)
        })
        .await
    }
    use roomler_hive_node::checkpoint::{Previous, take};
    use std::collections::{BTreeMap, HashMap};

    const HID: &str = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9";
    const SID: &str = "6aca8ef5dac84dd57e492eb7";

    /// The session's place beside `config`: its config directory, its folder
    /// (`work`) and its state directory (`state`).
    fn dest(config: &Path) -> Dest {
        Dest {
            sid: SID.into(),
            harness_session: HID.into(),
            fork_of: None,
            config_dir: config.to_path_buf(),
            folder: config.with_file_name("work"),
            state_dir: config.with_file_name("state"),
        }
    }

    fn write(dir: &Path, rel: &str, bytes: &[u8]) {
        let p = place_of(dir, rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn history() -> String {
        format!("projects/hive-{HID}/{HID}.jsonl")
    }

    fn memory(name: &str) -> String {
        format!("projects/hive-{HID}/memory/{name}")
    }

    /// Every regular file under `dir`, by `/`-separated path.
    fn files_under(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let name = e.file_name().into_string().unwrap();
                let r = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), &r, out);
                } else {
                    out.insert(r, std::fs::read(e.path()).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        if dir.exists() {
            walk(dir, "", &mut out);
        }
        out
    }

    /// Three checkpoints of `src`: the history appended to, a memory file
    /// added and one removed, `CLAUDE.md` rewritten. Their blobs, by hash.
    fn three_turns(src: &Path) -> (Vec<Checkpoint>, HashMap<Digest, Vec<u8>>) {
        let mut blobs = HashMap::new();
        let mut chain: Vec<Checkpoint> = Vec::new();
        let mut keep = |cp: Checkpoint, b: Vec<Vec<u8>>, chain: &mut Vec<Checkpoint>| {
            for blob in b {
                blobs.insert(Digest::of(&blob), blob);
            }
            chain.push(cp);
        };
        write(src, &history(), b"{\"t\":1}\n");
        write(src, &memory("a.md"), b"# a\n");
        write(src, "CLAUDE.md", b"# rules\n");
        let (cp, b) = take(src, HID, None, 1, 1, &Previous::none()).unwrap();
        keep(cp, b, &mut chain);
        write(src, &history(), b"{\"t\":1}\n{\"t\":2}\n");
        write(src, &memory("b.md"), b"# b\n");
        write(src, "CLAUDE.md", b"# rules, rewritten\n");
        let prev = Previous::from_checkpoint(chain.last().unwrap());
        let (cp, b) = take(src, HID, None, 2, 2, &prev).unwrap();
        keep(cp, b, &mut chain);
        std::fs::remove_file(place_of(src, &memory("a.md"))).unwrap();
        write(src, &history(), b"{\"t\":1}\n{\"t\":2}\n{\"t\":3}\n");
        let prev = Previous::from_checkpoint(chain.last().unwrap());
        let (cp, b) = take(src, HID, None, 3, 3, &prev).unwrap();
        keep(cp, b, &mut chain);
        (chain, blobs)
    }

    async fn frames_of(
        chain: &[Checkpoint],
        dir: &Path,
        blobs: &HashMap<Digest, Vec<u8>>,
    ) -> Vec<u8> {
        let (target, planned) = plan(chain, &dest(dir), &[]).unwrap();
        let mut bytes = Vec::new();
        assert!(
            write_frames(&mut bytes, &target, &planned, &Blobs::Map(blobs))
                .await
                .is_ok()
        );
        bytes
    }

    /// A chain of checkpoints, materialized into an empty config directory,
    /// gives back the session's files as they are now, byte for byte.
    #[tokio::test]
    async fn a_chain_materializes_into_an_empty_config_directory() {
        let src = tempfile::tempdir().unwrap();
        let (chain, blobs) = three_turns(src.path());
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        let bytes = frames_of(&chain, &config, &blobs).await;
        let done = materialize_from(&mut bytes.as_slice(), Os::this(), &Git::on_path()).unwrap();
        assert_eq!(
            done,
            Done {
                files: 3,
                removed: 0,
                workspace: None
            }
        );
        assert_eq!(files_under(&config), files_under(src.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(place_of(&config, &history())), 0o600);
            assert_eq!(
                mode(config.join(format!("projects/hive-{HID}/memory"))),
                0o700
            );
        }
    }

    /// P2f-3a — a parent's chain, moved under a fork's names and put in
    /// place: the parent's history where `--resume <parent> --fork-session`
    /// finds it under the fork's project, its tool results beside it, the
    /// memory and `CLAUDE.md`; nothing of a session further back. The fork's
    /// target is held to the fork's allowlist: the same files are refused
    /// for a plain session.
    #[tokio::test]
    async fn a_parents_chain_is_put_in_place_under_the_forks_names() {
        const FORK: &str = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b";
        const GRANDPARENT: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
        // The parent (`HID`), itself a fork of `GRANDPARENT`: two turns.
        let src = tempfile::tempdir().unwrap();
        let s = src.path();
        let p = format!("projects/hive-{HID}");
        write(s, &history(), b"{\"t\":1}\n");
        write(s, &format!("{p}/{HID}/tool-results/t1.txt"), b"big output");
        write(s, &memory("a.md"), b"# a\n");
        write(s, "CLAUDE.md", b"# rules\n");
        write(s, &format!("{p}/{GRANDPARENT}.jsonl"), b"further back\n");
        let mut blobs = HashMap::new();
        let (one, b) = take(s, HID, Some(GRANDPARENT), 1, 1, &Previous::none()).unwrap();
        blobs.extend(b.into_iter().map(|blob| (Digest::of(&blob), blob)));
        write(s, &history(), b"{\"t\":1}\n{\"t\":2}\n");
        let prev = Previous::from_checkpoint(&one);
        let (two, b) = take(s, HID, Some(GRANDPARENT), 2, 2, &prev).unwrap();
        blobs.extend(b.into_iter().map(|blob| (Digest::of(&blob), blob)));
        let chain = vec![one, two];
        assert!(
            chain[1].files.iter().any(|f| f.path.contains(GRANDPARENT)),
            "the parent keeps its own parent's history"
        );

        let moved = forked(&chain, HID, FORK).unwrap();
        let names: Vec<&str> = moved
            .iter()
            .flat_map(|c| &c.files)
            .map(|f| f.path.as_str())
            .collect();
        assert!(
            names
                .iter()
                .all(|p| *p == "CLAUDE.md" || p.starts_with(&format!("projects/hive-{FORK}/"))),
            "every file under the fork's project: {names:?}"
        );
        assert!(
            !names.iter().any(|p| p.contains(GRANDPARENT)),
            "nothing of a session further back: {names:?}"
        );
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        // An older copy's: the fork's allowlist ends up exactly the checkpoint's.
        write(
            &config,
            &format!("projects/hive-{FORK}/{HID}/tool-results/old.txt"),
            b"stale\n",
        );
        let fork = Dest {
            sid: SID.into(),
            harness_session: FORK.into(),
            fork_of: Some(HID.into()),
            config_dir: config.clone(),
            folder: dst.path().join("work"),
            state_dir: dst.path().join("state"),
        };
        let Ok((target, planned)) = plan(&moved, &fork, &[]) else {
            panic!("the fork's target holds the parent's files");
        };
        let mut bytes = Vec::new();
        assert!(
            write_frames(&mut bytes, &target, &planned, &Blobs::Map(&blobs))
                .await
                .is_ok()
        );
        materialize_from(&mut bytes.as_slice(), Os::this(), &Git::on_path())
            .expect("the parent's copy put in place under the fork's names");
        let f = format!("projects/hive-{FORK}");
        let placed: Vec<String> = files_under(&config).into_keys().collect();
        assert_eq!(
            placed,
            [
                "CLAUDE.md".to_string(),
                format!("{f}/{HID}.jsonl"),
                format!("{f}/{HID}/tool-results/t1.txt"),
                format!("{f}/memory/a.md"),
            ],
            "exactly the checkpoint's files"
        );
        assert_eq!(
            std::fs::read(roomler_hive_node::launch::parent_history_in(
                &config, FORK, HID
            ))
            .unwrap(),
            b"{\"t\":1}\n{\"t\":2}\n",
            "the parent's history, whole, where the fork's first launch reads it"
        );
        let plain = Dest {
            fork_of: None,
            ..fork
        };
        let Err(e) = plan(&moved, &plain, &[]) else {
            panic!("a plain session's target took a fork's files");
        };
        assert!(e.contains("not in the allowlist"), "{e}");
        assert!(forked(&chain, HID, HID).is_err(), "no fork of itself");
    }

    /// Materialized again over an older copy, the allowlist ends up exactly the
    /// checkpoint's: what it no longer lists is removed, and nothing outside
    /// the allowlist is touched.
    #[tokio::test]
    async fn what_the_checkpoint_no_longer_lists_goes_and_nothing_else() {
        let src = tempfile::tempdir().unwrap();
        let (chain, blobs) = three_turns(src.path());
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        write(&config, &memory("a.md"), b"# an older copy\n");
        write(&config, &memory("deep/old.md"), b"gone\n");
        write(
            &config,
            &format!("projects/hive-{HID}/memory/.hive-mz-7.tmp"),
            b"a stale stage\n",
        );
        let kept = [
            ".credentials.json".to_string(),
            "settings.json".into(),
            format!("projects/hive-{HID}/other.txt"),
            format!("projects/hive-{HID}/{HID}/file-history/x"),
        ];
        for k in &kept {
            write(&config, k, b"not the checkpoint's\n");
        }
        let bytes = frames_of(&chain, &config, &blobs).await;
        let done = materialize_from(&mut bytes.as_slice(), Os::this(), &Git::on_path()).unwrap();
        assert_eq!(
            done,
            Done {
                files: 3,
                removed: 3,
                workspace: None
            }
        );
        let now = files_under(&config);
        assert!(!now.contains_key(&memory("a.md")), "removed in the source");
        assert!(!now.contains_key(&memory("deep/old.md")));
        for k in &kept {
            assert_eq!(
                now[k], b"not the checkpoint's\n",
                "{k} is not the allowlist's"
            );
        }
        assert_eq!(now[&history()], b"{\"t\":1}\n{\"t\":2}\n{\"t\":3}\n");
    }

    /// A stream that does not hold up writes nothing: not the files before the
    /// one that failed, and no stage left behind.
    #[tokio::test]
    async fn a_refusal_writes_nothing() {
        let src = tempfile::tempdir().unwrap();
        let (chain, blobs) = three_turns(src.path());
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        let good = frames_of(&chain, &config, &blobs).await;
        let header_end = 12 + u32::from_le_bytes(good[8..12].try_into().unwrap()) as usize;

        let refused = |bytes: &[u8], needle: &str| {
            let e = materialize_from(&mut &bytes[..], Os::this(), &Git::on_path()).unwrap_err();
            assert!(e.contains(needle), "{needle:?} in {e:?}");
            assert_eq!(files_under(&config), BTreeMap::new(), "nothing written");
        };
        // The last file's last byte flipped: every file before it was staged.
        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 1;
        refused(&flipped, "is not the file its entry names");
        refused(&good[..good.len() - 1], "ends inside it");
        let mut padded = good.clone();
        padded.push(0);
        refused(&padded, "bytes after the last frame");
        refused(b"HIVEMZ2\n", "no magic");
        refused(&good[..header_end - 1], "inside the header");

        let (mut target, _) = plan(&chain, &dest(&config), &[]).unwrap();
        let reheader = |t: &Target| {
            let h = serde_json::to_vec(&Header { target: t.clone() }).unwrap();
            let mut b = MAGIC.to_vec();
            b.extend((h.len() as u32).to_le_bytes());
            b.extend(h);
            b.extend_from_slice(&good[header_end..]);
            b
        };
        target.v = 2;
        refused(&reheader(&target), "version 2");
        target.v = TARGET_V;
        for lie in ["../x", "projects/other/x", "sessions/1.key"] {
            let mut t = target.clone();
            t.files[0].path = lie.into();
            refused(&reheader(&t), "not in the allowlist");
        }
        let mut swapped = target.clone();
        swapped.files.swap(0, 1);
        refused(&reheader(&swapped), "out of order");
        let mut longer = target.clone();
        longer.files[0].len += 1;
        refused(&reheader(&longer), "its entry says");
    }

    /// P2f-2a — what a substitute's pack is thin against is held to git's
    /// ids, and to the most any request names, before anything is read.
    #[test]
    fn a_workspace_thin_against_what_is_no_commit_id_is_refused() {
        let target = |against: Vec<String>| Target {
            v: TARGET_V,
            harness_session: HID.into(),
            fork_of: None,
            config_dir: PathBuf::from("/c"),
            files: Vec::new(),
            workspace: Some(Workspace {
                sid: SID.into(),
                folder: PathBuf::from("/w"),
                state_dir: PathBuf::from("/s"),
                tree: "a".repeat(40),
                commit: "b".repeat(40),
                packs: vec![12],
                against,
            }),
        };
        assert_eq!(refusal(&target(vec!["c".repeat(40)]), Os::Linux), None);
        for bad in ["HEAD", "--all"] {
            let why = refusal(&target(vec![bad.to_string()]), Os::Linux);
            assert!(
                why.as_deref().is_some_and(|w| w.contains("not git's")),
                "against {bad} is refused: {why:?}"
            );
        }
        let many = vec!["c".repeat(40); workspace::MAX_HAVES + 1];
        let why = refusal(&target(many), Os::Linux);
        assert!(
            why.as_deref()
                .is_some_and(|w| w.contains("thin against more than")),
            "more than any request names is refused: {why:?}"
        );
    }

    /// For a Windows target, a name Windows cannot hold is refused before
    /// anything moves; for Windows and macOS, two names that are one file
    /// there are too. Linux holds both.
    #[test]
    fn windows_names_and_lengths_and_case_are_refused_where_they_must_be() {
        for (name, refused) in [
            ("aux.md", true),
            ("AUX", true),
            ("con", true),
            ("nul.txt", true),
            ("COM1.log", true),
            ("lpt9", true),
            ("COM¹", true),
            ("conin$", true),
            ("com10.md", false),
            ("console.md", false),
            ("auxiliary", false),
            ("a:b", true),
            ("a|b", true),
            ("a?", true),
            ("tab\there", true),
            ("x.", true),
            ("x ", true),
            ("notes.md", false),
            (".hidden", false),
        ] {
            assert_eq!(windows_name(name).is_some(), refused, "{name:?}");
        }
        let dir = PathBuf::from("/srv/state/claude");
        let target = |paths: &[String]| Target {
            v: TARGET_V,
            harness_session: HID.into(),
            fork_of: None,
            config_dir: dir.clone(),
            files: paths
                .iter()
                .map(|p| Entry {
                    path: p.clone(),
                    len: 0,
                    hash: Digest::of(b""),
                })
                .collect(),
            workspace: None,
        };
        let device = target(&[memory("aux.md")]);
        assert!(refusal(&device, Os::Linux).is_none());
        assert!(refusal(&device, Os::Mac).is_none());
        let why = refusal(&device, Os::Windows).unwrap();
        assert!(why.contains("keeps for a device"), "{why}");

        let long = target(&[memory(&"x".repeat(200))]);
        assert!(refusal(&long, Os::Linux).is_none());
        let why = refusal(&long, Os::Windows).unwrap();
        assert!(why.contains("past Windows' 259"), "{why}");

        let mut cased = vec![memory("Notes.md"), memory("notes.md")];
        cased.sort();
        let cased = target(&cased);
        assert!(refusal(&cased, Os::Linux).is_none());
        for os in [Os::Mac, Os::Windows] {
            let why = refusal(&cased, os).unwrap();
            assert!(why.contains("only in case"), "{why}");
        }
    }

    /// A session whose checkpoints took its folder too (a shadow): two turns of
    /// the config directory and the folder, by `hive-checkpoint`'s own
    /// `produce`. Their blobs, by hash.
    fn two_turns_with_a_folder(root: &Path) -> (Vec<Checkpoint>, HashMap<Digest, Vec<u8>>) {
        use super::super::checkpointer::{REQUEST_V, Request, produce};
        let git = Git::under(root);
        let req = |n: u64, previous: Option<Checkpoint>| Request {
            v: REQUEST_V,
            sid: SID.into(),
            harness_session: HID.into(),
            fork_of: None,
            config_dir: root.join("claude"),
            folder: root.join("work"),
            state_dir: root.join("state"),
            n,
            turn: n as u32,
            previous,
        };
        write(&root.join("claude"), &history(), b"{\"t\":1}\n");
        write(&root.join("work"), "main.rs", b"fn main() {}\n");
        let (one, b1) = produce(&req(1, None), &git).unwrap();
        write(&root.join("claude"), &history(), b"{\"t\":1}\n{\"t\":2}\n");
        write(&root.join("work"), "src/lib.rs", b"pub fn f() {}\n");
        let (two, b2) = produce(&req(2, Some(one.clone())), &git).unwrap();
        let blobs = b1
            .into_iter()
            .chain(b2)
            .map(|b| (Digest::of(&b), b))
            .collect();
        (vec![one, two], blobs)
    }

    /// [`files_under`], lines compared as LF on Windows: a move keeps git's
    /// tree, not the bytes, and a Windows checkout ends its lines as its git
    /// is configured to (design §6.3).
    fn lines_under(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        files_under(dir)
            .into_iter()
            .map(|(k, v)| {
                let v = if cfg!(windows) {
                    String::from_utf8_lossy(&v)
                        .replace("\r\n", "\n")
                        .into_bytes()
                } else {
                    v
                };
                (k, v)
            })
            .collect()
    }

    /// P2b-4b — a checkpoint that took the folder too materializes it, end to
    /// end through the frames: the config directory and the folder both, and
    /// the answer names the folder's repository and the tree it was held to.
    #[tokio::test]
    async fn a_checkpoint_with_its_folder_materializes_both() {
        let src = tempfile::tempdir().unwrap();
        let (chain, blobs) = two_turns_with_a_folder(src.path());
        let Some(ws) = chain[1].workspace.clone() else {
            return eprintln!("no git here");
        };
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        let bytes = frames_of(&chain, &config, &blobs).await;
        let done =
            materialize_from(&mut bytes.as_slice(), Os::this(), &Git::under(dst.path())).unwrap();
        assert_eq!(
            done.workspace,
            Some(Placed {
                repo: RepoKind::Shadow,
                tree: ws.tree.clone()
            })
        );
        assert_eq!(
            files_under(&config),
            files_under(&src.path().join("claude"))
        );
        assert_eq!(
            lines_under(&dst.path().join("work")),
            lines_under(&src.path().join("work"))
        );
    }

    /// `git` as a person runs it in `dir`: an identity of its own, nothing
    /// signed, nothing of the caller's git environment.
    fn git_in(dir: &Path, args: &[&str]) -> String {
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
                "-c",
                "core.autocrlf=false",
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

    /// A session's checkpoints, their blobs by hash, and the person's `HEAD`.
    type Turns = (Vec<Checkpoint>, HashMap<Digest, Vec<u8>>, String);

    /// Two checkpoints of a session whose folder (`work`) is a repository
    /// with a commit of its own, the person's `HEAD`: the first pack whole,
    /// the second thin against it. Their blobs by hash, and the `HEAD`.
    fn two_turns_in_a_repository(root: &Path) -> Option<Turns> {
        use super::super::checkpointer::{REQUEST_V, Request, produce};
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            return None;
        }
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        git_in(&work, &["init", "-q"]);
        write(&work, "lib.rs", b"pub fn f() {}\n");
        write(&work, "notes.md", b"# notes the session never touches\n");
        git_in(&work, &["add", "-A"]);
        git_in(&work, &["commit", "-q", "-m", "first"]);
        let head = git_in(&work, &["rev-parse", "HEAD"]);
        let git = Git::under(root);
        let req = |n: u64, previous: Option<Checkpoint>| Request {
            v: REQUEST_V,
            sid: SID.into(),
            harness_session: HID.into(),
            fork_of: None,
            config_dir: root.join("claude"),
            folder: work.clone(),
            state_dir: root.join("state"),
            n,
            turn: n as u32,
            previous,
        };
        write(&root.join("claude"), &history(), b"{\"t\":1}\n");
        write(&work, "main.rs", b"fn main() {}\n");
        let (one, b1) = produce(&req(1, None), &git).unwrap();
        write(&root.join("claude"), &history(), b"{\"t\":1}\n{\"t\":2}\n");
        write(&work, "src/x.rs", b"pub fn x() {}\n");
        let (two, b2) = produce(&req(2, Some(one.clone())), &git).unwrap();
        let blobs = b1
            .into_iter()
            .chain(b2)
            .map(|b| (Digest::of(&b), b))
            .collect();
        Some((vec![one, two], blobs, head))
    }

    /// [`lines_under`] of a clone, its git directory left out.
    #[cfg(unix)]
    fn work_under(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        lines_under(dir)
            .into_iter()
            .filter(|(k, _)| !k.starts_with(".git/"))
            .collect()
    }

    /// P2f-2a — a copy that holds no blob of the first checkpoint's whole
    /// pack, but a substitute for it thin against the person's `HEAD`, is
    /// materialized into a clone holding that `HEAD`, end to end through the
    /// store: the walk ends at the substitute, the later thin pack lands on
    /// top. With nothing standing in for the whole pack, it is not.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_substitute_against_the_clones_head_stands_in_for_the_whole_pack() {
        let src = tempfile::tempdir().unwrap();
        let Some((chain, blobs, head)) = two_turns_in_a_repository(src.path()) else {
            return eprintln!("no git here");
        };
        let one = chain[0].workspace.clone().unwrap();
        let two = chain[1].workspace.clone().unwrap();
        assert!(one.base.is_none() && two.base.is_some(), "whole, then thin");
        let (pack, against) = workspace::pack_against(
            &Git::under(src.path()),
            &src.path().join("work"),
            &src.path().join("state"),
            &one.commit,
            std::slice::from_ref(&head),
        )
        .unwrap();
        assert_eq!(against, vec![head.clone()]);
        let (chunks, sub_blobs) = checkpoint::chunk_bytes(&pack);
        let sub = Substitute {
            commit: one.commit.clone(),
            against,
            chunks,
        };

        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        git_in(
            dst.path(),
            &[
                "clone",
                "-q",
                "--no-local",
                &src.path().join("work").display().to_string(),
                "work",
            ],
        );
        let store = super::super::store::StoreHandle::spawn(None).unwrap();
        let whole: HashSet<Digest> = one.pack.iter().map(|c| c.hash).collect();
        for (hash, bytes) in &blobs {
            if !whole.contains(hash) {
                store
                    .put_named_blob(SID, hash.0, bytes.clone())
                    .await
                    .unwrap();
            }
        }
        let run = Runner::InProcess {
            ceiling: dst.path().to_path_buf(),
        };
        let who = Who {
            account: None,
            env: Vec::new(),
        };
        let at = Blobs::Store {
            store: &store,
            session: SID,
        };
        let e = materialize(&run, &who, &chain, &dest(&config), &at)
            .await
            .unwrap_err();
        assert!(
            e.contains("blob"),
            "nothing stands in for the whole pack: {e}"
        );

        for b in &sub_blobs {
            store
                .put_named_blob(SID, Digest::of(b).0, b.clone())
                .await
                .unwrap();
        }
        store.put_substitute(SID, sub.clone()).await.unwrap();
        let done = materialize(&run, &who, &chain, &dest(&config), &at)
            .await
            .unwrap();
        assert_eq!(
            done.workspace,
            Some(Placed {
                repo: RepoKind::Own,
                tree: two.tree.clone()
            })
        );
        assert_eq!(
            work_under(&dst.path().join("work")),
            work_under(&src.path().join("work"))
        );
        assert_eq!(
            files_under(&config),
            files_under(&src.path().join("claude"))
        );

        // A whole pack that is here is read as it is, whatever stands in for
        // it: this substitute is of no use in a folder that is new.
        let all = super::super::store::StoreHandle::spawn(None).unwrap();
        let every = blobs
            .iter()
            .map(|(h, b)| (*h, b.clone()))
            .chain(sub_blobs.iter().map(|b| (Digest::of(b), b.clone())));
        for (hash, bytes) in every {
            all.put_named_blob(SID, hash.0, bytes).await.unwrap();
        }
        all.put_substitute(SID, sub).await.unwrap();
        let fresh = tempfile::tempdir().unwrap();
        let fresh_run = Runner::InProcess {
            ceiling: fresh.path().to_path_buf(),
        };
        let at_all = Blobs::Store {
            store: &all,
            session: SID,
        };
        let done = materialize(
            &fresh_run,
            &who,
            &chain,
            &dest(&fresh.path().join("claude")),
            &at_all,
        )
        .await;
        assert!(
            done.is_ok(),
            "a whole pack that is here is read as it is: {done:?}"
        );
        assert_eq!(
            lines_under(&fresh.path().join("work")),
            work_under(&src.path().join("work"))
        );
    }

    /// P2f-2a — a substitute thin against a commit the folder's repository
    /// does not hold is refused before the folder is touched, and no config
    /// file lands either: git could resolve none of its deltas there.
    #[tokio::test]
    async fn a_substitute_where_its_commits_are_not_held_writes_nothing() {
        let src = tempfile::tempdir().unwrap();
        let Some((chain, mut blobs, head)) = two_turns_in_a_repository(src.path()) else {
            return eprintln!("no git here");
        };
        let one = chain[0].workspace.clone().unwrap();
        let (pack, against) = workspace::pack_against(
            &Git::under(src.path()),
            &src.path().join("work"),
            &src.path().join("state"),
            &one.commit,
            &[head],
        )
        .unwrap();
        let (chunks, sub_blobs) = checkpoint::chunk_bytes(&pack);
        for b in sub_blobs {
            blobs.insert(Digest::of(&b), b);
        }
        let sub = Substitute {
            commit: one.commit.clone(),
            against,
            chunks,
        };
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        let work = dst.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let (target, planned) = plan(&chain, &dest(&config), &[sub]).unwrap();
        let mut bytes = Vec::new();
        assert!(
            write_frames(&mut bytes, &target, &planned, &Blobs::Map(&blobs))
                .await
                .is_ok()
        );
        let got = materialize_from(&mut bytes.as_slice(), Os::this(), &Git::under(dst.path()));
        assert!(
            matches!(&got, Err(e) if e.contains("holds no commit")),
            "refused before anything is written, in words: {got:?}"
        );
        assert_eq!(
            files_under(&work),
            BTreeMap::new(),
            "the folder is untouched"
        );
        assert_eq!(
            files_under(&config),
            BTreeMap::new(),
            "no config file landed"
        );
    }

    /// P2f-2a — the walk ends at a substitute for a whole pack and hands back
    /// what it is thin against; one named for a thin pack's commit is never
    /// looked at, and none at all walks to the whole pack as before.
    #[test]
    fn the_walk_ends_at_a_whole_packs_substitute_only() {
        let src = tempfile::tempdir().unwrap();
        let Some((chain, _, head)) = two_turns_in_a_repository(src.path()) else {
            return eprintln!("no git here");
        };
        let (one, two) = (
            chain[0].workspace.clone().unwrap(),
            chain[1].workspace.clone().unwrap(),
        );
        let stand_in = |commit: &str| Substitute {
            commit: commit.to_string(),
            against: vec![head.clone()],
            chunks: vec![Chunk {
                offset: 0,
                len: 7,
                hash: Digest::of(b"a pack"),
            }],
        };
        let (packs, against) = packs_of(&chain, &two, &[stand_in(&one.commit)]).unwrap();
        assert_eq!(packs, vec![stand_in(&one.commit).chunks, two.pack.clone()]);
        assert_eq!(against, vec![head.clone()]);

        let (packs, against) = packs_of(&chain, &two, &[stand_in(&two.commit)]).unwrap();
        assert_eq!(
            packs,
            vec![one.pack.clone(), two.pack.clone()],
            "a thin pack is never stood in for"
        );
        assert!(against.is_empty());
        assert_eq!(
            packs_of(&chain, &two, &[]).unwrap(),
            (vec![one.pack.clone(), two.pack.clone()], Vec::new())
        );
        let empty = Substitute {
            chunks: Vec::new(),
            ..stand_in(&one.commit)
        };
        let e = packs_of(&chain, &two, &[empty]).unwrap_err();
        assert!(e.contains("is empty"), "{e}");
    }

    /// P2b-4b — a workspace whose commit does not hold the tree it claims is
    /// refused before the folder is touched, and no config file lands either.
    #[tokio::test]
    async fn a_workspace_that_is_not_what_it_claims_writes_nothing() {
        let src = tempfile::tempdir().unwrap();
        let (chain, blobs) = two_turns_with_a_folder(src.path());
        let Some(first) = chain[0].workspace.clone() else {
            return eprintln!("no git here");
        };
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        let (mut target, planned) = plan(&chain, &dest(&config), &[]).unwrap();
        // A real tree, the first turn's, but not the commit's.
        target.workspace.as_mut().unwrap().tree = first.tree;
        let mut bytes = Vec::new();
        assert!(
            write_frames(&mut bytes, &target, &planned, &Blobs::Map(&blobs))
                .await
                .is_ok()
        );
        let e = materialize_from(&mut bytes.as_slice(), Os::this(), &Git::under(dst.path()))
            .unwrap_err();
        assert!(e.contains("not the checkpoint's"), "{e}");
        assert!(!dst.path().join("work").exists(), "the folder is untouched");
        assert_eq!(
            files_under(&config),
            BTreeMap::new(),
            "no config file landed"
        );
    }

    /// P2b-4b — for a Windows target, a name in the folder's tree that Windows
    /// cannot hold is refused before the folder is touched. (The source is
    /// Unix: on Windows, writing `aux.md` opens the AUX device instead.)
    #[cfg(unix)]
    #[tokio::test]
    async fn a_windows_target_refuses_a_name_in_the_folder_it_cannot_hold() {
        let src = tempfile::tempdir().unwrap();
        write(
            &src.path().join("work"),
            "notes/aux.md",
            b"a device, on Windows\n",
        );
        let (chain, blobs) = two_turns_with_a_folder(src.path());
        if chain[1].workspace.is_none() {
            return eprintln!("no git here");
        }
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        let bytes = frames_of(&chain, &config, &blobs).await;
        let e = materialize_from(&mut bytes.as_slice(), Os::Windows, &Git::under(dst.path()))
            .unwrap_err();
        assert!(
            e.contains("notes/aux.md") && e.contains("keeps for a device"),
            "{e}"
        );
        assert!(!dst.path().join("work").exists(), "the folder is untouched");
    }

    /// A link in the target's allowlisted directories is never written
    /// through, and what it points at is left as it was.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_link_in_the_target_is_never_written_through() {
        let src = tempfile::tempdir().unwrap();
        let (chain, blobs) = three_turns(src.path());
        let dst = tempfile::tempdir().unwrap();
        let config = dst.path().join("claude");
        let elsewhere = dst.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(config.join(format!("projects/hive-{HID}"))).unwrap();
        std::os::unix::fs::symlink(
            &elsewhere,
            config.join(format!("projects/hive-{HID}/memory")),
        )
        .unwrap();
        let bytes = frames_of(&chain, &config, &blobs).await;
        let e = materialize_from(&mut bytes.as_slice(), Os::this(), &Git::on_path()).unwrap_err();
        assert!(e.contains("not a directory of its own"), "{e}");
        assert_eq!(files_under(&elsewhere), BTreeMap::new());
        assert!(!place_of(&config, &history()).exists(), "nothing written");
    }

    /// The daemon's side, through a real child: the frames arrive whole on its
    /// stdin and its answer is read; a child that refuses is answered in its
    /// own words, not as a broken pipe; a blob the store lacks is the answer
    /// even though the child took what it got.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_daemon_streams_a_real_child_and_reads_its_answer() {
        use std::os::unix::fs::PermissionsExt;
        let src = tempfile::tempdir().unwrap();
        let (mut chain, mut blobs) = three_turns(src.path());
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("claude");
        let child = |name: &str, body: &str| {
            let p = tmp.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let path = vec![("PATH".into(), "/usr/bin:/bin".into())];
        let fast = Duration::from_secs(10);
        let got = tmp.path().join("got.bin");
        let cat = child(
            "cat.sh",
            &format!(
                "[ \"$1\" = {MATERIALIZE_SUBCOMMAND} ] && cat > {} && echo '{{\"files\":3,\"removed\":0}}'",
                got.display()
            ),
        );
        let (target, planned) = plan(&chain, &dest(&config), &[]).unwrap();
        let done = run_as(
            &cat,
            None,
            path.clone(),
            &target,
            &planned,
            &Blobs::Map(&blobs),
            fast,
        )
        .await
        .unwrap();
        assert_eq!(
            done,
            Done {
                files: 3,
                removed: 0,
                workspace: None
            }
        );
        assert_eq!(
            std::fs::read(&got).unwrap(),
            frames_of(&chain, &config, &blobs).await
        );

        // A history of 8 MiB, so the feed is still writing when the child goes.
        let big: Vec<u8> = (0..8 * 1024 * 1024)
            .map(|i| b"0123456789\n"[i % 11])
            .collect();
        write(src.path(), &history(), &big);
        let prev = Previous::from_checkpoint(chain.last().unwrap());
        let (cp, b) = take(src.path(), HID, None, 4, 4, &prev).unwrap();
        for blob in b {
            blobs.insert(Digest::of(&blob), blob);
        }
        chain.push(cp);
        let (target, planned) = plan(&chain, &dest(&config), &[]).unwrap();
        let refuses = child("refuses.sh", "echo 'the folder is not allowed' >&2; exit 1");
        let e = run_as(
            &refuses,
            None,
            path.clone(),
            &target,
            &planned,
            &Blobs::Map(&blobs),
            fast,
        )
        .await
        .unwrap_err();
        assert!(e.contains("the folder is not allowed"), "{e}");

        let lacking: HashMap<Digest, Vec<u8>> = HashMap::new();
        let e = run_as(
            &cat,
            None,
            path,
            &target,
            &planned,
            &Blobs::Map(&lacking),
            fast,
        )
        .await
        .unwrap_err();
        assert!(e.contains("is missing"), "{e}");
    }
}
