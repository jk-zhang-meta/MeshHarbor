// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! File-transfer data-channel handler.
//!
//! Accepts uploads from the controller browser and writes them into
//! the controlled host's Downloads folder. Closes the final open
//! MEDIUM Known Issue on `docs/remote-control.md` (file-transfer DC
//! was accepted but log-only).
//!
//! Wire protocol on the `files` data channel:
//!
//! ```text
//! // Browser → Agent (control: string payloads)
//! { "t": "files:begin", "id": "<client-chosen-id>",
//!   "name": "report.pdf", "size": 1048576, "mime": "application/pdf" }
//! // Browser → Agent (data: binary payloads, one or many per transfer)
//! <raw ArrayBuffer bytes; appended in arrival order to the current
//!  transfer identified by the most recent files:begin>
//! { "t": "files:end", "id": "<same id>" }
//!
//! // Agent → Browser (all control: string payloads)
//! { "t": "files:accepted", "id": "<id>", "path": "C:\\...\\report.pdf" }
//! { "t": "files:progress", "id": "<id>", "bytes": 524288 }
//! { "t": "files:complete", "id": "<id>", "path": "...", "bytes": 1048576 }
//! { "t": "files:error",    "id": "<id>", "message": "<reason>" }
//! ```
//!
//! Design notes
//!
//! - One active transfer per DC. Concurrent transfers would require
//!   multiplexing binary chunks by id, which SCTP on a DC doesn't do
//!   for us — browsers would need to open one DC per transfer. Ship
//!   the simple path first; queue client-side.
//! - Destination: `~/Downloads` (or platform equivalent per
//!   `directories::UserDirs::download_dir()`). Falls back to the OS
//!   temp dir if the user has no Downloads (rare — headless CI).
//! - Filename safety: the browser-provided `name` is stripped to its
//!   basename and any character outside `[A-Za-z0-9._-]` is replaced
//!   with `_` so the agent never writes outside Downloads. Collisions
//!   append ` (N)` before the extension.
//! - Size cap: 2 GiB per transfer (below SCTP's 2^31-1 limit; well
//!   above any sane "drop a file onto a screen-share" use case).
//!   Configurable later.
//! - The writer is an owned `tokio::fs::File` behind a Mutex so a
//!   burst of binary chunks serializes on the filesystem without the
//!   handler blocking the DC read loop.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tunnel_core::env::node_env_os;

use crate::files_dir;

/// 2 GiB. SCTP DCs in webrtc-rs can carry larger payloads in theory
/// but per-transfer >2 GB is outside the "drop a file" use case and
/// would need chunk-resume which this MVP doesn't implement.
const MAX_TRANSFER_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Process-global flag for the `files:dir` browse capability. Set
/// once at startup from `AgentConfig::enable_remote_browse` (and the
/// `ROOMLERD_DISABLE_BROWSE` env-var escape hatch). Readers in
/// the DC hot path use [`is_remote_browse_enabled`] which compiles
/// to a single relaxed atomic load.
///
/// Default `true` (preserves self-controlled-host auto-grant
/// semantics from `docs/remote-control.md` §11.2). `set_remote_browse`
/// is called from `main.rs::Run` after config load; no
/// initialization race in practice because file-DC handlers can't
/// fire until a session opens, which is well after main has
/// settled.
///
/// ⚠️ The default is what a process that never loads the config sees —
/// the `caps-probe` child, above all. That is why the hello's `files`
/// list is assigned by `encode::caps::detect()` in the DAEMON (its second
/// reader, at the first hello, after `run_cmd` has stored the flag) and
/// never computed inside the child's `compute_caps` (#1672).
static REMOTE_BROWSE_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

pub fn set_remote_browse_enabled(enabled: bool) {
    REMOTE_BROWSE_ENABLED.store(enabled, std::sync::atomic::Ordering::Release);
}

pub fn is_remote_browse_enabled() -> bool {
    REMOTE_BROWSE_ENABLED.load(std::sync::atomic::Ordering::Acquire)
}

/// FR-84 D4 — the configured drop folder (`files_dir`), LIVE: seeded from
/// the config at startup (`main.rs::run_cmd`) and re-seeded by the daemon's
/// `ConfigSet` (`localapi_state::config_set`); read by every transfer. The
/// raw config VALUE is kept, not a resolved path: `~` expands against the
/// ACTIVE user at the moment of the drop, and the placement rule is judged
/// against the identity doing the writing then — one machine-global config
/// stays right for whoever is logged in.
///
/// A process-global like `REMOTE_BROWSE_ENABLED` above rather than a
/// per-transfer config-file read: the daemon already holds the only write
/// path that matters (the LocalAPI verb — remote configuration cannot carry
/// this key, `DesiredConfig` has no such field), the value is one string,
/// and a file read per drop would add a TOML parse plus a torn-read race
/// with the atomic save for no gain — a hand edit of the file is picked up
/// at the next start, exactly as every other key.
static FILES_DIR: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Bumped — under `FILES_DIR`'s write lock — every time the configured value
/// CHANGES, so a status answer computed for an older value can never
/// overwrite one computed for the current value.
static FILES_DIR_GEN: AtomicU64 = AtomicU64::new(0);

/// Seed / re-seed the configured drop folder. Blank = unset (the ladder).
/// A change also starts a background refresh of the status answer, so the
/// Overview has one long before anyone asks.
pub fn set_files_dir(value: Option<String>) {
    let value = value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let changed = {
        let mut g = FILES_DIR.write().unwrap_or_else(|e| e.into_inner());
        if *g == value {
            false
        } else {
            *g = value;
            FILES_DIR_GEN.fetch_add(1, Ordering::AcqRel);
            true
        }
    };
    if changed {
        spawn_effective_refresh();
    }
}

/// The configured drop folder, as spelled in the config (unexpanded).
pub fn configured_files_dir() -> Option<String> {
    FILES_DIR.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The value and its generation, read together.
fn configured_files_dir_and_gen() -> (Option<String>, u64) {
    let g = FILES_DIR.read().unwrap_or_else(|e| e.into_inner());
    (g.clone(), FILES_DIR_GEN.load(Ordering::Acquire))
}

/// Serialises the tests that set the process-global drop folder. A tokio
/// mutex because one of them (`localapi_state`) holds it across `.await`;
/// the sync tests take it with `blocking_lock`.
#[cfg(test)]
pub(crate) static FILES_DIR_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Who this process writes files as, for `files_dir`'s placement rule
/// (`roomler_node_core::files_dir`).
///
/// * Windows, `LocalSystem` — the winlogon-token worker in a user's session
///   (`system_context`), or any `meshharbord run` started under a SYSTEM token,
///   feature or no feature. Privileged; the active user is the one signed in
///   to THIS process's session, and their profile comes from their token
///   (`win_identity::session_user_profile_dir`), never from their name. No
///   user in the session (session 0, pre-logon) = no profile = every folder
///   refused, by design.
/// * Unix, root — privileged; the "active" profile is the daemon's own home.
///   A root daemon serves the console through KMS capture / uinput with no
///   per-user identity to resolve, its default ladder already lands in its
///   own folders, and the LocalAPI socket is owner-only (0600) — the pipe's
///   non-admin caller does not exist on Unix, so the rule is belt and braces.
/// * Everyone else — unprivileged: this process can only write where its own
///   user can, so the folder rules apply and the profile rule does not.
pub fn writer_context() -> files_dir::Writer {
    #[cfg(target_os = "windows")]
    {
        if crate::win_identity::process_is_local_system() {
            return files_dir::Writer {
                privileged: true,
                active_home: crate::win_identity::session_user_profile_dir(),
            };
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return files_dir::Writer {
                privileged: true,
                active_home: process_home(),
            };
        }
    }
    files_dir::Writer::unprivileged(process_home())
}

/// This process's own home. Windows asks the token (a registry read — never
/// the known-folder lookups `UserDirs` makes, which verify every folder and
/// so can touch a share a folder is redirected to).
fn process_home() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        crate::win_identity::own_profile_dir()
    }
    #[cfg(not(target_os = "windows"))]
    {
        directories::BaseDirs::new().map(|d| d.home_dir().to_string_lossy().into_owned())
    }
}

/// FR-97 P3d — who a received file is written as.
///
/// A Linux system install is root, and its sessions show the person at the
/// screen; a file sent to them used to land in root's own Downloads, where
/// they could not see it. It now lands in THEIR folder, and every path step
/// there (the staging folder, the data file, the final rename, a resume, the
/// orphan sweep) runs on a thread that took on their filesystem identity
/// (`crate::fs_identity`), never as root followed by a `chown`: in a folder
/// the person owns, a link they planted would otherwise be followed with
/// root's rights, and the staging folder's `meta.json`, which a resume reads,
/// is theirs to edit. "The person" is the one at seat0
/// (`companion::seat0_user`, FR-97 P5a's definition), never whoever asked.
/// `ROOMLERD_FILES_AS_SEAT_USER=0` keeps the daemon's own identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FsAs {
    /// This process: every Windows and macOS install, every user install,
    /// and a root daemon with nobody at seat0.
    Daemon,
    /// (Linux root) the person signed in at seat0.
    #[cfg(target_os = "linux")]
    Person {
        account: crate::fs_identity::Account,
        home: PathBuf,
    },
}

impl FsAs {
    /// Who a transfer starting now writes as.
    pub(crate) fn now() -> Self {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `geteuid` reads this process's own credentials.
            if unsafe { libc::geteuid() } == 0 && tunnel_core::env::flag("FILES_AS_SEAT_USER", true)
            {
                match seat_person() {
                    Ok(person) => return person,
                    Err(e) => tracing::debug!(
                        %e,
                        "files: nobody at seat0 — received files are written as the daemon"
                    ),
                }
            }
        }
        Self::Daemon
    }

    /// Run blocking filesystem work as this identity, on a blocking thread:
    /// an identity belongs to the thread that takes it on, never to an async
    /// worker.
    pub(crate) async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let who = self.clone();
        tokio::task::spawn_blocking(move || who.run_here(f))
            .await
            .context("a file-transfer step's thread")?
    }

    /// [`Self::run`] on THIS thread, which must be a blocking one.
    fn run_here<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        match self {
            Self::Daemon => f(),
            #[cfg(target_os = "linux")]
            Self::Person { account, .. } => {
                let _as_them = crate::fs_identity::FsIdentity::begin(account)
                    .map_err(|e| anyhow!("acting as {} for a received file: {e}", account.name))?;
                f()
            }
        }
    }

    /// The writer FR-84 D4's placement rules check: for the person, the
    /// daemon is still privileged, and the person's home is the active one.
    fn writer(&self) -> files_dir::Writer {
        match self {
            Self::Daemon => writer_context(),
            #[cfg(target_os = "linux")]
            Self::Person { home, .. } => files_dir::Writer {
                privileged: true,
                active_home: Some(home.to_string_lossy().into_owned()),
            },
        }
    }
}

/// The person at seat0, as an account (uid 0 refused) and a home.
#[cfg(target_os = "linux")]
fn seat_person() -> std::result::Result<FsAs, String> {
    let name = crate::companion::seat0_user().map_err(|e| format!("{e:#}"))?;
    let account = crate::fs_identity::Account::by_name(&name)?;
    let home = crate::exec::account_home(&name)?;
    Ok(FsAs::Person { account, home })
}

/// The person's Downloads: `XDG_DOWNLOAD_DIR` from their own
/// `user-dirs.dirs` when it names a folder inside their home that exists,
/// else `~/Downloads` when it exists, else their home. Read as the person
/// (the caller runs it under their identity).
#[cfg(target_os = "linux")]
fn person_downloads(home: &std::path::Path) -> PathBuf {
    let from_xdg = std::fs::read_to_string(home.join(".config/user-dirs.dirs"))
        .ok()
        .and_then(|text| xdg_download_dir(&text, home));
    if let Some(dir) = from_xdg.filter(|d| d.is_dir()) {
        return dir;
    }
    let plain = home.join("Downloads");
    if plain.is_dir() {
        return plain;
    }
    home.to_path_buf()
}

/// The pure half of [`person_downloads`]: `XDG_DOWNLOAD_DIR` out of a
/// `user-dirs.dirs`, with `$HOME` expanded, and only when it stays inside
/// `home` (the file is the person's to write, so it may name anything).
#[cfg(any(target_os = "linux", test))]
fn xdg_download_dir(text: &str, home: &std::path::Path) -> Option<PathBuf> {
    let value = text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("XDG_DOWNLOAD_DIR=")?;
        Some(rest.trim().trim_matches('"').to_string())
    })?;
    let path = match value.strip_prefix("$HOME") {
        Some(rel) => home.join(rel.trim_start_matches('/')),
        None => PathBuf::from(&value),
    };
    let inside = path
        .components()
        .all(|c| !matches!(c, std::path::Component::ParentDir))
        && path.starts_with(home)
        && path != home;
    inside.then_some(path)
}

/// FR-84 D4 — the SET-time gate: everything a drop will demand of the value
/// at use time (shape, placement for THIS writer, creatable and writable),
/// run now so a `ConfigSet` the daemon would not honour is refused with the
/// reason instead of saved and silently ignored. The refusal text is what the
/// desktop shows verbatim.
pub fn validate_files_dir_setting(raw: &str) -> Result<PathBuf, String> {
    // FR-97 P3d — for whoever a drop would be written as now, and as them:
    // the gate creates the folder and probes a write.
    let who = FsAs::now();
    let writer = who.writer();
    who.run_here(|| {
        Ok(files_dir::validate(
            raw,
            &writer,
            &files_dir::Rules::from_env(),
        ))
    })
    .unwrap_or_else(|e| Err(format!("{e:#}")))
}

/// `raw` as it resolves for `writer` right now — shape, placement, the
/// on-disk link check and "a folder could be here" — with nothing created
/// or written: what a drop would use, short of the write probe. Run under
/// the identity the writer describes.
fn resolve_without_creating(raw: &str, writer: &files_dir::Writer) -> Result<PathBuf, String> {
    let rules = files_dir::Rules::from_env();
    let p = files_dir::resolve(raw, writer, &rules)?;
    files_dir::check_placement_on_disk(&p, writer, &rules)?;
    files_dir::check_creatable(&p)?;
    Ok(p)
}

/// The configured folder via [`resolve_without_creating`], for `who` and
/// under their identity. `Ok(None)` = no folder configured.
fn configured_folder_without_creating(who: &FsAs) -> Result<Option<PathBuf>, String> {
    match configured_files_dir() {
        None => Ok(None),
        Some(raw) => resolve_without_creating(&raw, &who.writer()).map(Some),
    }
}

// ── NodeStatus.files_dir: answered from a cache, never from the disk ──────

/// The status answer and what it was computed for.
struct EffectiveFilesDir {
    /// The `FILES_DIR_GEN` it was computed for.
    generation: u64,
    computed_at: Option<std::time::Instant>,
    value: Option<String>,
}

static EFFECTIVE_FILES_DIR: std::sync::Mutex<EffectiveFilesDir> =
    std::sync::Mutex::new(EffectiveFilesDir {
        generation: 0,
        computed_at: None,
        value: None,
    });
static EFFECTIVE_REFRESHING: AtomicBool = AtomicBool::new(false);
/// How old a status answer may be before a read starts a refresh — long
/// enough that a 2 s poller does not re-resolve on every tick, short enough
/// that a folder deleted or a user switched shows up within one glance.
const EFFECTIVE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// FR-84 D4 — where a drop would land RIGHT NOW, for `NodeStatus.files_dir`:
/// the configured folder when it passes for this writer (it need not exist
/// yet — a drop creates it), else the default ladder.
///
/// NEVER touches the disk: the status verb is a synchronous read on the
/// LocalAPI's async dispatch, polled every 2 s by the companion, and the
/// honest answer needs the disk (a link out of the profile) and, through the
/// default ladder's known-folder lookups, possibly a Downloads redirected to
/// a share that is offline right now. So this answers from a cache and, when
/// the cached answer is older than [`EFFECTIVE_TTL`] or was computed for a
/// previous value, refreshes it on a background thread. `None` only before
/// the first refresh has landed (`set_files_dir` at startup starts one).
pub fn effective_files_dir() -> Option<String> {
    let current = FILES_DIR_GEN.load(Ordering::Acquire);
    let (value, fresh) = {
        let c = EFFECTIVE_FILES_DIR
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fresh =
            c.generation == current && c.computed_at.is_some_and(|at| at.elapsed() < EFFECTIVE_TTL);
        (c.value.clone(), fresh)
    };
    if !fresh {
        spawn_effective_refresh();
    }
    value
}

/// Compute the status answer now and cache it. BLOCKING (token, disk,
/// known-folder lookups): the daemon's `ConfigSet` runs it on its blocking
/// thread, so the status read right after a change is already the new
/// answer; everything else reaches it through [`spawn_effective_refresh`].
pub fn refresh_effective_files_dir() -> Option<String> {
    let (raw, generation) = configured_files_dir_and_gen();
    let value = compute_effective_files_dir(raw.as_deref());
    let mut c = EFFECTIVE_FILES_DIR
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // An answer for an OLDER value never replaces one for a newer value.
    if generation >= c.generation {
        *c = EffectiveFilesDir {
            generation,
            computed_at: Some(std::time::Instant::now()),
            value: value.clone(),
        };
    }
    value
}

/// One background refresh at a time; a read that finds one running simply
/// returns the cached answer.
fn spawn_effective_refresh() {
    if EFFECTIVE_REFRESHING.swap(true, Ordering::AcqRel) {
        return;
    }
    struct Done;
    impl Drop for Done {
        fn drop(&mut self) {
            EFFECTIVE_REFRESHING.store(false, Ordering::Release);
        }
    }
    let spawned = std::thread::Builder::new()
        .name("files-dir-status".into())
        .spawn(|| {
            let _done = Done;
            refresh_effective_files_dir();
        });
    if spawned.is_err() {
        EFFECTIVE_REFRESHING.store(false, Ordering::Release);
    }
}

fn compute_effective_files_dir(raw: Option<&str>) -> Option<String> {
    // FR-97 P3d — for whoever a drop would be written as now, and as them
    // (a blocking thread: the status refresh's own, or `ConfigSet`'s).
    let who = FsAs::now();
    who.run_here(|| Ok(compute_effective_files_dir_as(&who, raw)))
        .unwrap_or_else(|e| {
            tracing::debug!(%e, "files: the effective folder could not be computed as its writer");
            None
        })
}

fn compute_effective_files_dir_as(who: &FsAs, raw: Option<&str>) -> Option<String> {
    if let Some(raw) = raw {
        match resolve_without_creating(raw, &who.writer()) {
            Ok(p) => return Some(p.to_string_lossy().into_owned()),
            Err(e) => tracing::debug!(
                files_dir = %raw,
                %e,
                "files: the configured files_dir would be refused right now — reporting the default folder"
            ),
        }
    }
    default_download_dir_as(who, false)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Number of in-flight file transfers (incoming uploads + outgoing
/// downloads) summed across all DCs. The auto-updater reads this
/// before deciding whether to fire a scheduled install — see
/// `updater::run_periodic`. Incremented on `FilesHandler::begin` /
/// `resume_incoming` / `begin_outgoing` success; decremented via the
/// `Drop` impl on `IncomingTransfer` / `OutgoingTransfer` so every
/// exit path (success, error, panic, DC drop) releases the counter.
///
/// rc.19 added this static so the auto-update timer doesn't kill the
/// agent mid-upload (the field bug that motivated resumable
/// transfers in the first place — see plan
/// `~/.claude/plans/floating-splashing-nebula.md`).
pub static ACTIVE_TRANSFERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub fn active_transfer_count() -> usize {
    ACTIVE_TRANSFERS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Process-global registry of partial-upload staging dirs keyed by
/// transfer `id`. Populated by three writers:
///
/// 1. [`sweep_orphans`] at startup — walks known dest roots, registers
///    surviving `.roomler-partial/<id>/` dirs (after deleting any with
///    `created_at_unix` > 24h).
/// 2. [`FilesHandler::begin`] when a resumable upload starts — writes
///    `id → meta.json_path` so a same-process resume request on a
///    different DC can find the partial.
/// 3. [`FilesHandler::commit_partial`] (rename success) and
///    [`FilesHandler::cancel_incoming`] / error paths — remove the
///    registry entry alongside the on-disk staging cleanup.
///
/// rc.19 uses `LazyLock` over `OnceLock + get_or_init` because the
/// initial value is a closure-free `Mutex::new(HashMap::new())`. The
/// inner `std::sync::Mutex` is fine for HashMap lookups (sub-µs
/// critical section); no tokio async needed.
///
/// **Test isolation**: `cargo test` runs in parallel by default and
/// the registry is process-global, so use [`reset_partial_registry`]
/// at the start of every test that touches partial state.
pub(crate) static PARTIAL_REGISTRY: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, PartialEntry>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// One registered partial: its `meta.json`, and who staged it. FR-97 P3d —
/// a resume, a cancel and the sweep act on the partial AS whoever staged
/// it: in the person's own folder, `meta.json` is theirs to edit, and a
/// resume renames to the folder it names.
#[derive(Debug, Clone)]
pub(crate) struct PartialEntry {
    pub(crate) meta_path: PathBuf,
    pub(crate) who: FsAs,
}

/// Test-only escape hatch — clears the partial registry between
/// `cargo test` cases that touch the same global. Production code
/// never calls this.
///
/// Recovers from poison: cargo runs tests in parallel and a panic
/// in one test holding the lock would poison it for all subsequent
/// readers. The HashMap has no invariants a panic could break, so
/// recovering the inner value is sound.
#[cfg(test)]
pub fn reset_partial_registry() {
    let mut g = PARTIAL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    g.clear();
}

/// Per-partial metadata persisted next to the staging `data` file as
/// `<dest_dir>/.roomler-partial/<id>/meta.json`. Survives agent
/// restart so [`sweep_orphans`] can rebuild [`PARTIAL_REGISTRY`] from
/// disk at startup. `protocol_version` is bumped if the on-disk
/// format ever changes (v2 will add per-chunk SHA roots).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PartialMeta {
    pub protocol_version: u32,
    pub filename: String,
    pub expected_size: u64,
    pub dest_dir: PathBuf,
    /// The begin-time reserved final path. Advisory only — the real
    /// rename target is recomputed via `unique_path()` at end time
    /// per M4 fix (operator may have created a file at this path
    /// while the upload was in flight).
    pub reserved_final_path: PathBuf,
    pub created_at_unix: i64,
    /// Folder-upload context. `Some` when the begin envelope carried
    /// `rel_path`; needed at end time to recreate the directory tree
    /// for collision-resolution.
    #[serde(default)]
    pub rel_path: Option<String>,
}

/// Age threshold for [`sweep_orphans`] — partials older than this
/// get their dir + sidecar deleted at agent startup.
pub(crate) const PARTIAL_ORPHAN_TTL_SECS: i64 = 24 * 3600;

/// Granularity at which `chunk()` calls `sync_data()` so that the
/// page cache is flushed to disk at sub-1-MiB intervals.
///
/// rc.24 — was 1 MiB. the field-test host field repro showed sub-1-MiB files
/// never had a sync point mid-upload; if the agent process was
/// killed before `end()` flushed (e.g. msiexec auto-update,
/// SCM service restart), the file stayed 0 bytes on disk and
/// resume couldn't make progress because `bytesAcked` reset to 0
/// each cycle. Drop to 256 KiB so even small files persist
/// incrementally. Overhead on Windows: 4× more `FlushFileBuffers`
/// per MB ≈ 4-120 ms per MB vs the prior 1-30 ms; acceptable
/// because resume durability is the harder problem to solve.
pub(crate) const FSYNC_THRESHOLD_BYTES: u64 = 256 * 1024;

/// rc.22 — staging-strategy flag. When `true`, all upload staging on
/// Windows happens under `%PROGRAMDATA%\roomler\<segment>\staging\`
/// regardless of the upload's `dest_dir`. When `false`, staging lives
/// under `<dest_dir>/.roomler-partial/` (rc.19–rc.21 legacy layout).
///
/// **Why**: the field-test host field repro 2026-05-11 — ESET Security real-time
/// scanner intercepts per-chunk writes under `C:\Users\<user>\Downloads\`
/// aggressively enough to push the file-DC's SCTP buffer into overflow
/// during large uploads, ending in "reconnect budget exhausted after
/// 6 attempts" with no recoverable state. ESET scans `C:\ProgramData\`
/// writes less aggressively (service-writable, typical legitimate
/// staging location), so moving the per-chunk write loop to PROGRAMDATA
/// and only crossing into the user's Downloads at end-time rename keeps
/// ESET's hot path narrow.
///
/// Hypothesis-driven, not yet confirmed on the field; the env-var
/// escape hatch `ROOMLERD_STAGING_LEGACY_PER_DEST=1` reverts the
/// behavior without a rebuild if Option B turns out wrong. Cycles
/// back to `Option D` (escalate corporate-AV exclusion request) if
/// rc.22 still fails.
///
/// Defaults: Windows → `true`, other → `false`. Tests force `false`
/// via `cfg(test)` so the existing per-dest test assertions hold.
///
/// `dead_code` allow on non-Windows: the static + accessor are only
/// READ from inside `#[cfg(target_os = "windows")]` blocks elsewhere
/// in this file; on Linux/macOS the compiler can't see those reads
/// and would warn. We keep the symbols cross-platform so the
/// strategy-flag tests stay portable.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) static STAGE_IN_PROGRAMDATA: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| {
        if cfg!(test) {
            return false;
        }
        if node_env_os("STAGING_LEGACY_PER_DEST").is_some() {
            tracing::info!("files: STAGING_LEGACY_PER_DEST set; reverting to per-dest staging");
            return false;
        }
        cfg!(target_os = "windows")
    });

/// True when the rc.22 always-PROGRAMDATA staging strategy is active.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn stage_in_programdata() -> bool {
    *STAGE_IN_PROGRAMDATA
}

// RETIRED-NAME-ANCHOR(3): names the pre-rename segment because explaining the
// conditional resolution requires naming both halves. docs/fr/FR-21
/// Windows-only staging root: `%PROGRAMDATA%\roomler\<segment>\staging\`,
/// where `<segment>` is resolved per host by `appdirs::machine_global_dir()`
/// (the `roomler` segment on a fresh install; the pre-rename `roomler-agent`
/// one only where that tree already exists). Do NOT restate it as a literal —
/// FR-21 P4 fixed a viewer that did exactly that.
/// SYSTEM-writable, persistent across reboots, present on every Windows
/// install. Falls back to `C:\ProgramData` when the env var is unset
/// (matches the rc.21 download_dir() fallback shape).
#[cfg(target_os = "windows")]
pub(crate) fn staging_root_windows() -> PathBuf {
    crate::appdirs::machine_global_dir().join("staging")
}

/// Compute the canonical staging dir path for an upload `id`. On
/// Windows in production this is `%PROGRAMDATA%\roomler\<segment>\
/// staging\<id>` (rc.22, ESET fix; segment per `machine_global_dir()`). On other platforms or when the
/// legacy-per-dest escape hatch is set, falls back to the rc.19 layout
/// at `<dest_dir>/.roomler-partial/<id>`.
pub(crate) fn partial_dir_for(dest_dir: &std::path::Path, id: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if stage_in_programdata() {
            return staging_root_windows().join(id);
        }
    }
    dest_dir.join(".roomler-partial").join(id)
}

/// rc.22 — detect a "rename crosses devices" error from `tokio::fs::rename`.
/// `io::ErrorKind::CrossesDevices` (stable since Rust 1.85) catches the
/// portable case. For older toolchains or platforms without the
/// canonical mapping, fall back to checking the raw OS error code:
/// `17` on Windows (`ERROR_NOT_SAME_DEVICE`) and `18` on Linux/macOS
/// (`EXDEV`).
pub(crate) fn is_cross_volume_error(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::CrossesDevices {
        return true;
    }
    match err.raw_os_error() {
        Some(17) if cfg!(target_os = "windows") => true,
        Some(18) if cfg!(not(target_os = "windows")) => true,
        _ => false,
    }
}

/// Apply the Windows hidden attribute to `path`. Logs + continues on
/// failure (the staging path still works without the hidden bit;
/// operators on Linux/macOS get the dot-prefix hide instead).
#[cfg(target_os = "windows")]
fn set_hidden(path: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: wide is a valid null-terminated UTF-16 string from a
    // PathBuf. FILE_ATTRIBUTE_HIDDEN = 0x2.
    let ok =
        unsafe { windows_sys::Win32::Storage::FileSystem::SetFileAttributesW(wide.as_ptr(), 0x2) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(path = %path.display(), %err, "files: SetFileAttributesW failed; staging dir visible");
    }
}

#[cfg(not(target_os = "windows"))]
fn set_hidden(_path: &std::path::Path) {
    // Unix relies on the dot-prefix; nothing to do.
}

/// Walk the Downloads folder's `.roomler-partial/` dir at agent
/// startup, deleting any per-id subdir whose `meta.json` is older
/// than [`PARTIAL_ORPHAN_TTL_SECS`] and registering the survivors in
/// [`PARTIAL_REGISTRY`]. Returns the count of (kept, swept) pairs.
///
/// Called synchronously from `main.rs::run_cmd` BEFORE the signaling
/// task spawns, so no DC can carry a `files:resume` message until
/// the registry is populated. This closes the B1 race documented in
/// the plan.
///
/// **Coverage limitation**: this v1 sweep only walks Downloads. For
/// uploads with explicit `dest_path` to arbitrary locations, the
/// in-memory [`PARTIAL_REGISTRY`] populated at begin time covers
/// same-process resume. After agent restart those partials are
/// undiscoverable and the browser falls back to a fresh `files:begin`
/// with a new id; the orphan dirs are left on disk until the operator
/// cleans them (no automated cleanup for non-Downloads in v1).
pub async fn sweep_orphans() -> (usize, usize) {
    // rc.22 — when always-PROGRAMDATA staging is active, the sweep
    // scans `staging_root_windows()` DIRECTLY (no `.roomler-partial/`
    // parent — the staging root IS that parent). Otherwise fall back
    // to the legacy `<Downloads>/.roomler-partial/` layout.
    #[cfg(target_os = "windows")]
    {
        if stage_in_programdata() {
            let root = staging_root_windows();
            return sweep_orphans_root(&root).await;
        }
    }
    // FR-84 D4 — a partial lives next to the folder its transfer targeted:
    // walk the default folder AND the configured one (when set, usable and
    // different), so a `files_dir` change strands no resumable upload.
    // FR-97 P3d — for, and as, whoever a drop would be written as now: on a
    // Linux system install, the person at seat0, in their own folder.
    let who = FsAs::now();
    let w = who.clone();
    let roots = who
        .run(move || {
            let mut roots: Vec<PathBuf> = Vec::new();
            if let Ok(d) = default_download_dir_as(&w, false) {
                roots.push(d);
            }
            // Only a folder that still passes for this writer — the sweep
            // deletes, so it must never walk a configured value the
            // placement rule refuses.
            if let Ok(Some(c)) = configured_folder_without_creating(&w)
                && !roots.contains(&c)
            {
                roots.push(c);
            }
            Ok(roots)
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(%e, "sweep_orphans: could not resolve the drop folders as their writer");
            Vec::new()
        });
    if roots.is_empty() {
        tracing::debug!("sweep_orphans: Downloads dir not resolvable; skipping");
        return (0, 0);
    }
    let (mut kept, mut swept) = (0, 0);
    for root in &roots {
        let (k, s) = sweep_orphans_dir_as(&who, root.join(".roomler-partial")).await;
        kept += k;
        swept += s;
    }
    (kept, swept)
}

/// rc.22 — sweep a directory whose CHILDREN are per-id staging dirs.
/// Used when the staging root is `%PROGRAMDATA%\roomler\<segment>\
/// staging\` (no `.roomler-partial` parent). Mirror of [`sweep_orphans_in`]
/// minus the parent-join — the contents-of-directory loop is identical.
pub async fn sweep_orphans_root(dir: &std::path::Path) -> (usize, usize) {
    sweep_orphans_dir_as(&FsAs::Daemon, dir.to_path_buf()).await
}

/// Test-friendly variant taking an explicit root. Production code
/// calls [`sweep_orphans`] which forwards to this with `download_dir()`.
/// Tests that exercise the sweep logic pass a `tempfile::TempDir`
/// root to avoid polluting the user's real Downloads folder on
/// Windows (where `download_dir()` ignores HOME and resolves via
/// `KNOWNFOLDERID`).
pub async fn sweep_orphans_in(root: &std::path::Path) -> (usize, usize) {
    sweep_orphans_dir_as(&FsAs::Daemon, root.join(".roomler-partial")).await
}

/// Shared sweep body — reads `dir` as a directory whose children are
/// `<id>/{meta.json,data}` triples, removes those older than
/// [`PARTIAL_ORPHAN_TTL_SECS`] and registers survivors. Used by both
/// the legacy `<Downloads>/.roomler-partial/` layout and the rc.22
/// `%PROGRAMDATA%\roomler\<segment>\staging\` layout. FR-97 P3d — the
/// walk and every removal run as `who`, and a survivor is registered as
/// staged by `who`, so a later resume acts as them too.
async fn sweep_orphans_dir_as(who: &FsAs, dir: PathBuf) -> (usize, usize) {
    let now = chrono::Utc::now().timestamp();
    let walked = dir.clone();
    let (survivors, swept) = match who
        .run(move || Ok(sweep_orphans_dir_here(&walked, now)))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), %e, "sweep_orphans: could not act as the folder's writer");
            return (0, 0);
        }
    };
    let kept = survivors.len();
    if let Ok(mut g) = PARTIAL_REGISTRY.lock() {
        for (id, meta_path) in survivors {
            g.insert(
                id,
                PartialEntry {
                    meta_path,
                    who: who.clone(),
                },
            );
        }
    }
    if kept + swept > 0 {
        tracing::info!(kept, swept, "sweep_orphans: complete");
    }
    (kept, swept)
}

/// The sweep's filesystem half, on THIS (blocking) thread under the
/// caller's identity: the survivors as `(id, meta.json)`, and how many
/// partials were removed.
fn sweep_orphans_dir_here(dir: &std::path::Path, now: i64) -> (Vec<(String, PathBuf)>, usize) {
    let mut survivors = Vec::new();
    let mut swept = 0usize;
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(dir = %dir.display(), "sweep_orphans: dir absent; nothing to do");
            return (survivors, 0);
        }
        Err(e) => {
            tracing::warn!(dir = %dir.display(), %e, "sweep_orphans: read_dir failed");
            return (survivors, 0);
        }
    };
    for entry in rd.flatten() {
        let path = entry.path();
        // `DirEntry::file_type` does not follow a link: a link to a folder
        // is skipped, never walked.
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let id = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let meta_path = path.join("meta.json");
        let meta_bytes = match std::fs::read(&meta_path) {
            Ok(b) => b,
            Err(_) => {
                // No meta.json — partial state corrupt, prune.
                let _ = std::fs::remove_dir_all(&path);
                swept += 1;
                continue;
            }
        };
        let meta: PartialMeta = match serde_json::from_slice(&meta_bytes) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(meta = %meta_path.display(), %e, "sweep_orphans: corrupt meta.json; removing");
                let _ = std::fs::remove_dir_all(&path);
                swept += 1;
                continue;
            }
        };
        if now - meta.created_at_unix > PARTIAL_ORPHAN_TTL_SECS {
            tracing::info!(
                id = %id,
                age_h = (now - meta.created_at_unix) / 3600,
                "sweep_orphans: removing orphaned partial"
            );
            let _ = std::fs::remove_dir_all(&path);
            swept += 1;
            continue;
        }
        survivors.push((id, meta_path));
    }
    (survivors, swept)
}

/// Incoming control messages over the `files` DC (string payloads).
/// Binary payloads are handled separately — they're not JSON.
///
/// File-DC v2 (0.3.0) adds reverse-direction transfers (`Get`,
/// `Cancel`) and directory listing (`Dir`) on top of the original
/// upload pair. Old browsers continue to send only `Begin` / `End`
/// — backwards-compat is preserved by serde's `#[serde(tag = "t")]`
/// rejecting unknown variants on the agent side and the agent
/// emitting only the original variants when the operator never
/// triggers a download.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "t")]
pub(crate) enum FilesIncoming {
    #[serde(rename = "files:begin")]
    Begin {
        id: String,
        name: String,
        size: u64,
        #[serde(default)]
        mime: Option<String>,
        /// Folder-upload extension (file-DC v2.1). When `Some`, the
        /// browser is dropping a folder and this is the relative path
        /// of the file inside that folder, e.g.
        /// `MyFolder/sub/file.txt`. The agent recreates the directory
        /// structure under Downloads/<root> with per-component
        /// sanitisation (reuses the zip walker's safety rules).
        /// `None` for individual-file uploads (the original behavior;
        /// `name` is the basename, file lands in Downloads/).
        #[serde(default)]
        rel_path: Option<String>,
        /// Path-targeted upload extension (file-DC v2.2). When
        /// `Some(<host_dir>)`, the file lands under `<host_dir>/`
        /// instead of the default Downloads/. The browser sets this
        /// when the operator drops a file onto the browse drawer's
        /// current directory — natural completion of browse +
        /// upload. Validated via the same denylist as `files:get`
        /// downloads (rejects `\\?\GLOBALROOT…`, registry hives,
        /// non-directory paths). When `None` the file lands in
        /// Downloads/ as before. Stacks with `rel_path` for folder-
        /// drop-into-arbitrary-dir.
        #[serde(default)]
        dest_path: Option<String>,
    },
    #[serde(rename = "files:end")]
    End { id: String },
    /// Browser → Agent: download a single file from the host.
    /// Path is the absolute host path. Subject to denylist + read
    /// permission of the agent process.
    #[serde(rename = "files:get")]
    Get { id: String, path: String },
    /// Browser → Agent: download a folder as a streaming zip
    /// (Phase 4). `format` is currently always `"zip"`.
    #[serde(rename = "files:get-folder")]
    GetFolder {
        id: String,
        path: String,
        #[serde(default)]
        format: Option<String>,
    },
    /// Browser → Agent: cancel an in-flight transfer. file-DC v3
    /// (rc.19) extends this to also cancel incoming uploads — the
    /// agent removes the in-flight `IncomingTransfer` state AND the
    /// `.roomler-partial/<id>/` staging dir + PARTIAL_REGISTRY entry.
    /// Sent by the browser when the resume reconnect budget is
    /// exhausted (6 attempts) so the partial doesn't sit until the
    /// 24h orphan sweep.
    #[serde(rename = "files:cancel")]
    Cancel { id: String },
    /// Browser → Agent: list a directory. `path` is empty / `~` to
    /// list logical drives (Win) or `/` (Unix). `req_id` echoes back
    /// in the `dir-list` reply so the browser can match concurrent
    /// requests.
    #[serde(rename = "files:dir")]
    Dir { req_id: String, path: String },
    /// Browser → Agent: resume an upload that lost its DC mid-flight
    /// (file-DC v3, rc.19). The browser claims `bytesAcked` from the
    /// last `files:progress` envelope; the agent replies with
    /// `files:resumed { id, accepted_offset }` where `accepted_offset`
    /// may be < requested if the agent's on-disk size is smaller
    /// (truncated to a 256 KiB boundary matching `files:progress`
    /// cadence). On any failure the agent replies `files:error` and
    /// the browser falls back to a fresh `files:begin` with a new id.
    /// `sha256_prefix` is reserved for v2 (per-chunk integrity); v1
    /// agents ignore the field if present.
    #[serde(rename = "files:resume")]
    Resume {
        id: String,
        offset: u64,
        #[serde(default)]
        sha256_prefix: Option<String>,
    },
}

/// Outgoing control messages sent back to the browser. Flat `t`
/// discriminant mirrors the clipboard DC's pattern for consistency.
#[derive(Debug, Serialize)]
#[serde(tag = "t")]
#[allow(dead_code)] // DirList is wired in Phase 3 (browse drawer)
pub(crate) enum FilesOutgoing<'a> {
    #[serde(rename = "files:accepted")]
    Accepted { id: &'a str, path: &'a str },
    #[serde(rename = "files:progress")]
    Progress { id: &'a str, bytes: u64 },
    #[serde(rename = "files:complete")]
    Complete {
        id: &'a str,
        path: &'a str,
        bytes: u64,
    },
    #[serde(rename = "files:error")]
    Error { id: &'a str, message: &'a str },
    /// Agent → Browser: announce an outgoing transfer. `size` is
    /// `Some` for single files (known up-front) and `None` for
    /// streaming folder zips (Phase 4 — size unknown until end).
    #[serde(rename = "files:offer")]
    Offer {
        id: &'a str,
        name: &'a str,
        size: Option<u64>,
        mime: Option<&'a str>,
    },
    /// Agent → Browser: terminal frame for an outgoing transfer.
    /// Sent after the last binary chunk; carries the final byte
    /// count so the browser can verify a complete stream.
    #[serde(rename = "files:eof")]
    Eof { id: &'a str, bytes: u64 },
    /// Agent → Browser: directory listing reply. `parent` is the
    /// canonical parent path (or `None` at the root / drives view).
    /// Permission-denied per-entry results are dropped from the
    /// list silently — best-effort so a single inaccessible file
    /// doesn't sink the listing.
    #[serde(rename = "files:dir-list")]
    DirList {
        req_id: &'a str,
        path: &'a str,
        parent: Option<&'a str>,
        entries: &'a [DirEntryView],
    },
    /// Agent → Browser: directory listing failed (path doesn't
    /// exist, permission denied, browse disabled by config).
    #[serde(rename = "files:dir-error")]
    DirError { req_id: &'a str, message: &'a str },
    /// Agent → Browser: reply to `files:resume` confirming the byte
    /// offset from which the agent will accept appended chunks
    /// (file-DC v3, rc.19). `accepted_offset` is the largest 256 KiB-
    /// aligned offset ≤ the browser's requested offset AND ≤ the
    /// agent's on-disk size for the partial file. The browser MUST
    /// re-pump from `accepted_offset`, which may be 0 (full re-send)
    /// if the agent's partial was truncated to nothing or the staging
    /// file is gone. After this reply the browser sends a normal
    /// `files:end` once it has pumped the remaining bytes.
    #[serde(rename = "files:resumed")]
    Resumed { id: &'a str, accepted_offset: u64 },
}

/// Listing entry surfaced over `files:dir-list`. Sorted dirs-first
/// then files, both alphabetical case-insensitive. Permission-denied
/// entries are dropped from the result rather than failing the
/// whole list.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DirEntryView {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub mtime_unix: Option<i64>,
}

/// RAII guard that increments [`ACTIVE_TRANSFERS`] on creation and
/// decrements on drop. Embedded in `IncomingTransfer` /
/// `OutgoingTransfer` so every exit path (success, error, panic,
/// DC drop, abort) releases the counter automatically.
///
/// Pair with `sync_data` per [`FSYNC_THRESHOLD_BYTES`] (B2 fix) so
/// the counter only decrements after bytes are durable on disk;
/// otherwise a kill-between-write-and-sync could lose data while
/// the updater observed `active == 0` and fired an install.
pub(crate) struct ActiveTransferGuard;

impl ActiveTransferGuard {
    pub fn new() -> Self {
        ACTIVE_TRANSFERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveTransferGuard {
    fn drop(&mut self) {
        ACTIVE_TRANSFERS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Browser → Agent upload state. A single incoming transfer is
/// "active" at any time — files:begin starts one; files:end or the
/// DC closing finishes it.
pub(crate) struct IncomingTransfer {
    pub id: String,
    pub expected: u64,
    pub received: u64,
    pub file: File,
    /// Last byte count reported via files:progress. Progress is sent
    /// every ~256 KiB to keep the browser UI lively without flooding.
    pub last_progress: u64,
    /// rc.19: staging dir `<dest_dir>/.roomler-partial/<id>/`. The
    /// `data` file is inside; `meta.json` is alongside. `end()`
    /// renames `<dir>/data` to a fresh unique_path under `dest_dir`
    /// and removes this dir + the registry entry.
    pub partial_dir: PathBuf,
    /// rc.19: target directory captured at begin time so `end()` can
    /// re-run `unique_path()` against it (M4 fix).
    pub dest_dir: PathBuf,
    /// rc.19: sanitized basename captured at begin time for the same
    /// reason as `dest_dir`.
    pub filename: String,
    /// rc.19: byte count at the most recent `sync_data()` call. The
    /// `chunk()` path advances this every [`FSYNC_THRESHOLD_BYTES`]
    /// so kernel writeback is durable at the moment we ack progress
    /// over the wire (B2 fix — survives msiexec TerminateProcess).
    pub last_synced: u64,
    /// rc.19: folder-upload context preserved for end-time rename
    /// (used by `commit_partial` to recreate the directory tree).
    pub rel_path: Option<String>,
    /// FR-97 P3d: who this transfer writes as, fixed when it began (or
    /// resumed): the end-time rename and its cleanup run as them too, even
    /// after someone else has signed in at the screen.
    pub who: FsAs,
    /// rc.19: increments [`ACTIVE_TRANSFERS`] on creation, decrements
    /// on drop. Last field so it drops AFTER `file` — guarantees the
    /// kernel page cache has reached the disk-flush queue before the
    /// updater sees `active == 0`.
    pub _active_guard: ActiveTransferGuard,
}

/// Agent → Browser download state. One outgoing transfer is active
/// at any time. `cancel` stops its pump: a `files:cancel` from the
/// browser, or the session ending ([`FilesHandler::end_session`]).
pub(crate) struct OutgoingTransfer {
    pub id: String,
    pub path: PathBuf,
    /// Captured file size from the begin_outgoing stat. Useful for
    /// future per-transfer audit logging; not consulted by the pump
    /// today (which reads-until-EOF).
    #[allow(dead_code)]
    pub size: u64,
    /// #1730 — a TOKEN, not a flag: the pumps race every await against it.
    /// A flag read between awaits was never read by a pump parked inside
    /// one (a send on a channel whose peer vanished never returns), so a
    /// download cut by a dropped session held its file, its channel and
    /// this transfer's updater guard for good.
    pub cancel: tokio_util::sync::CancellationToken,
    /// rc.19: ACTIVE_TRANSFERS counter guard (see IncomingTransfer).
    pub _active_guard: ActiveTransferGuard,
}

/// Handle on the file-transfer subsystem for one data channel.
/// Thread-safe — cheap Arc clones are used inside the on_message and
/// on_close callbacks on the DC.
///
/// Incoming and outgoing transfers each get their own mutex so a
/// busy upload doesn't lock the download path (and vice versa).
/// One outgoing AND one incoming transfer can run concurrently;
/// queueing within a direction is enforced client-side.
#[derive(Clone)]
pub struct FilesHandler {
    incoming: Arc<Mutex<Option<IncomingTransfer>>>,
    outgoing: Arc<Mutex<Option<OutgoingTransfer>>>,
    /// Set by [`Self::end_session`]: nothing new begins on a session that
    /// is over. A message already in flight when the session ended would
    /// otherwise start a download after the teardown, whose pump outlives
    /// it (found in review; the clipboard's `stopped` is the same guard).
    ended: Arc<AtomicBool>,
}

impl Default for FilesHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl FilesHandler {
    pub fn new() -> Self {
        Self {
            incoming: Arc::new(Mutex::new(None)),
            outgoing: Arc::new(Mutex::new(None)),
            ended: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start a new incoming transfer (browser → host upload). Returns
    /// the absolute destination path so the caller can reply
    /// `files:accepted { id, path }`.
    ///
    /// `rel_path` is the file-DC v2.1 folder-upload extension. When
    /// `Some(<rel>)`, the browser is uploading a single file from a
    /// dropped folder and `rel` is its path relative to the folder
    /// root (e.g. `MyFolder/sub/file.txt`). The agent recreates the
    /// directory structure under Downloads/ with per-component
    /// sanitisation. When `None`, behaviour is the file-DC v1 default:
    /// `name` is the basename and the file lands in Downloads/
    /// directly (with collision-safe rename).
    ///
    /// `dest_path` is the file-DC v2.2 path-targeted-upload extension.
    /// When `Some(<host_dir>)`, the file lands under `<host_dir>/`
    /// instead of Downloads/. Subject to the existing
    /// [`validate_outgoing_path`] denylist (kernel-namespace prefixes,
    /// registry-hive container) plus a directory-existence check.
    /// On validation failure the file falls back to Downloads/ with
    /// a warning log (operator's intent was clear, refusing entirely
    /// would be confusing). Stacks with `rel_path` for
    /// folder-drop-into-arbitrary-dir.
    pub async fn begin(
        &self,
        id: String,
        name: String,
        expected: u64,
        rel_path: Option<&str>,
        dest_path: Option<&str>,
    ) -> Result<PathBuf> {
        // FR-97 P3d — who this transfer writes as, for its whole life: on a
        // Linux system install the person at seat0, in their own folder.
        self.begin_as(FsAs::now(), id, name, expected, rel_path, dest_path)
            .await
    }

    /// [`Self::begin`] as an explicit identity: the seam the root-only tests
    /// use, since a test runner has nobody at seat0.
    pub(crate) async fn begin_as(
        &self,
        who: FsAs,
        id: String,
        name: String,
        expected: u64,
        rel_path: Option<&str>,
        dest_path: Option<&str>,
    ) -> Result<PathBuf> {
        // Before anything lands on disk (a message straddling the session's
        // end); an upload that got past this is dropped by `end_session`.
        self.refuse_if_ended()?;
        if expected > MAX_TRANSFER_BYTES {
            return Err(anyhow!(
                "transfer size {expected} exceeds the {} B cap",
                MAX_TRANSFER_BYTES
            ));
        }
        // Resolve the target directory: dest_path (operator-chosen,
        // validated) or Downloads (default). When dest_path is set
        // but invalid (denylist hit / not a directory), fall back to
        // Downloads with a warning so the upload doesn't silently
        // drop the operator's data.
        let target_dir = match dest_path.filter(|p| !p.is_empty()) {
            Some(dp) => match resolve_dest_path_as(&who, dp).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        dest_path = dp,
                        %e,
                        "files: dest_path rejected; falling back to Downloads"
                    );
                    download_dir_for(&who)
                        .await
                        .context("resolving Downloads folder")?
                }
            },
            None => download_dir_for(&who)
                .await
                .context("resolving Downloads folder")?,
        };
        let filename = sanitize_filename(&name);

        // rc.19: stage at <dest_dir>/.roomler-partial/<id>/data so a
        // mid-upload DC drop leaves the partial discoverable (B1 +
        // B2 fixes). `end()` renames to a freshly-resolved final path.
        let partial_dir = partial_dir_for(&target_dir, &id);

        // Every step below touches the target folder, so all of it runs as
        // `who` (FR-97 P3d).
        let (reserved_final, meta_path, file) = {
            let (target_dir, partial_dir, filename, id) = (
                target_dir.clone(),
                partial_dir.clone(),
                filename.clone(),
                id.clone(),
            );
            let rel_for_path = rel_path.filter(|p| !p.is_empty()).map(str::to_string);
            let rel_for_meta = rel_path.map(str::to_string);
            who.run(move || {
                // Folder upload: resolve `rel_path` to a path under the
                // target dir, sanitising each component. Falls back to flat
                // upload when rel_path is empty / missing / refused by
                // sanitisation. This is the *reserved* final path; the real
                // rename target is recomputed at `end()` time per M4 fix.
                let reserved_final = match rel_for_path.as_deref() {
                    Some(rel) => {
                        resolve_folder_upload_path(&target_dir, rel).unwrap_or_else(|| {
                            tracing::warn!(
                                rel_path = rel,
                                "files: rel_path rejected; falling back to flat upload"
                            );
                            unique_path(&target_dir, &filename)
                        })
                    }
                    None => unique_path(&target_dir, &filename),
                };

                // B1 fix — reject if an existing partial dir is on disk for
                // this id. The browser MUST send `files:resume` instead, or
                // generate a new UUID. Without this check the data file
                // below would truncate the existing partial. The
                // `PARTIAL_REGISTRY` lookup is an optimisation — the
                // authoritative test is the on-disk dir. `symlink_metadata`:
                // a link planted there counts as "on disk" too.
                if std::fs::symlink_metadata(&partial_dir).is_ok() {
                    return Err(anyhow!(
                        "id {id} already has partial state; send files:resume"
                    ));
                }

                let parent_partial = partial_dir
                    .parent()
                    .expect("partial_dir has a parent by construction");
                std::fs::create_dir_all(parent_partial)
                    .with_context(|| format!("creating {}", parent_partial.display()))?;
                set_hidden(parent_partial);
                // `create_dir`, never `_all`: this id's folder is made now,
                // or the begin fails — an existing one is never adopted.
                std::fs::create_dir(&partial_dir)
                    .with_context(|| format!("creating {}", partial_dir.display()))?;

                // Write meta.json BEFORE opening the data file. If meta
                // write fails the staging dir is left empty (cheap to clean).
                let meta = PartialMeta {
                    protocol_version: 1,
                    filename: filename.clone(),
                    expected_size: expected,
                    dest_dir: target_dir.clone(),
                    reserved_final_path: reserved_final.clone(),
                    created_at_unix: chrono::Utc::now().timestamp(),
                    rel_path: rel_for_meta,
                };
                let meta_path = partial_dir.join("meta.json");
                let meta_bytes =
                    serde_json::to_vec_pretty(&meta).context("serialising partial meta.json")?;
                std::fs::write(&meta_path, &meta_bytes)
                    .with_context(|| format!("writing {}", meta_path.display()))?;

                // `create_new`: the folder is new, so the file must be too;
                // a link planted in its place refuses the open.
                let data_path = partial_dir.join("data");
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&data_path)
                    .with_context(|| format!("creating {}", data_path.display()))?;
                Ok((reserved_final, meta_path, file))
            })
            .await?
        };
        // The open file carries the identity's rights from here on; the
        // writes through it need no identity of their own.
        let file = File::from_std(file);

        // Populate the in-memory registry so a same-process resume
        // request (DC drop without agent restart) can find this
        // partial without re-running the orphan sweep.
        if let Ok(mut g) = PARTIAL_REGISTRY.lock() {
            g.insert(
                id.clone(),
                PartialEntry {
                    meta_path,
                    who: who.clone(),
                },
            );
        }

        let mut guard = self.incoming.lock().await;
        if guard.is_some() {
            // A previous transfer on THIS DC was in-flight and never
            // got files:end (browser closed or error). Drop it; the
            // partial dir + meta.json remain on disk for a future
            // resume attempt (or the orphan sweep after 24h).
        }
        *guard = Some(IncomingTransfer {
            id,
            expected,
            received: 0,
            file,
            last_progress: 0,
            partial_dir,
            dest_dir: target_dir,
            filename,
            last_synced: 0,
            rel_path: rel_path.map(|s| s.to_string()),
            who,
            _active_guard: ActiveTransferGuard::new(),
        });
        Ok(reserved_final)
    }

    /// Append binary data to the active incoming transfer. Returns
    /// the total byte count after this append, and whether this
    /// append crossed a progress-report threshold.
    pub async fn chunk(&self, data: &[u8]) -> Result<Option<ChunkProgress>> {
        let mut guard = self.incoming.lock().await;
        let Some(state) = guard.as_mut() else {
            // Chunk arrived without an active transfer. Browser sent
            // bytes before files:begin or after files:end — we choose
            // to drop rather than guess.
            return Err(anyhow!("no active transfer"));
        };
        state.received = state.received.saturating_add(data.len() as u64);
        if state.received > state.expected {
            return Err(anyhow!(
                "received {} bytes, expected {}",
                state.received,
                state.expected
            ));
        }
        state.file.write_all(data).await?;
        // rc.19 B2 fix — flush the kernel page cache to disk every
        // FSYNC_THRESHOLD_BYTES so a hard kill (msiexec
        // TerminateProcess, BSOD, power loss) loses at most one
        // window of progress, not the entire transfer. Tuned to
        // 1 MiB; see FSYNC_THRESHOLD_BYTES doc.
        if state.received - state.last_synced >= FSYNC_THRESHOLD_BYTES {
            // sync_data flushes file content + metadata required to
            // read it back, but skips timestamp metadata — faster
            // than sync_all and sufficient for our durability needs.
            // Failure is logged but not fatal; the next chunk will
            // try again. (Disk full / quota errors will surface on
            // the next write_all anyway.)
            if let Err(e) = state.file.sync_data().await {
                tracing::debug!(%e, "files: sync_data failed; will retry next window");
            }
            state.last_synced = state.received;
        }
        let progress = if state.received - state.last_progress >= 256 * 1024 {
            state.last_progress = state.received;
            Some(ChunkProgress {
                id: state.id.clone(),
                bytes: state.received,
            })
        } else {
            None
        };
        Ok(progress)
    }

    /// Finalize the active incoming transfer. Flushes + fsyncs the
    /// staging `data` file, renames it to a freshly-resolved unique
    /// final path under `dest_dir`, removes the `.roomler-partial/
    /// <id>/` dir + registry entry. Returns the *actual* final path
    /// (may differ from the begin-time reservation per M4 fix).
    pub async fn end(&self, id: &str) -> Result<(PathBuf, u64)> {
        let mut guard = self.incoming.lock().await;
        let Some(mut state) = guard.take() else {
            return Err(anyhow!("no active transfer to end"));
        };
        if state.id != id {
            // Put the state back so we don't drop someone else's
            // transfer on an id mismatch.
            let wrong_id = state.id.clone();
            *guard = Some(state);
            return Err(anyhow!(
                "files:end id={id} but active transfer is {wrong_id}"
            ));
        }
        state.file.flush().await?;
        state.file.sync_all().await.ok();
        if state.received != state.expected {
            // Don't commit the partial — leave the staging dir on disk
            // so a future files:resume can complete it. Re-insert the
            // state slot is wrong (we already moved file out of state),
            // but the partial dir IS the durable state. Browser will
            // get files:error and may retry via resume.
            return Err(anyhow!(
                "short transfer: received {} of {} bytes",
                state.received,
                state.expected
            ));
        }
        // Drop the file handle BEFORE the rename — Windows refuses
        // to rename an open file. tokio::fs::File::drop just queues
        // close, so we explicitly await... actually drop is fine
        // because end() returns shortly after; if it ever races, the
        // commit_partial below would error and the caller surfaces
        // it. We could `drop(state.file)` explicitly for clarity:
        drop(state.file);

        // M4 fix: re-run unique_path at rename time so an operator
        // who created a colliding file mid-upload doesn't make us
        // overwrite their work. FR-97 P3d: every step in the target
        // folder runs as whoever began the transfer.
        let (dest_dir, filename, rel, partial_dir) = (
            state.dest_dir.clone(),
            state.filename.clone(),
            state.rel_path.clone(),
            state.partial_dir.clone(),
        );
        let actual_final_path = state
            .who
            .run(move || {
                let actual_final_path = match rel.as_deref().filter(|p| !p.is_empty()) {
                    Some(rel) => resolve_folder_upload_path(&dest_dir, rel)
                        .unwrap_or_else(|| unique_path(&dest_dir, &filename)),
                    None => unique_path(&dest_dir, &filename),
                };
                if let Some(parent) = actual_final_path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating final parent {}", parent.display()))?;
                }

                let data_path = partial_dir.join("data");
                // rc.22 — the staging dir may now be on a different volume than
                // the final destination (PROGRAMDATA = C:, dest_path could be
                // D:\, a network mapped drive, or operator-redirected
                // Downloads). `rename` returns `ErrorKind::CrossesDevices` in
                // that case (Windows `ERROR_NOT_SAME_DEVICE` / Linux `EXDEV`);
                // fall back to copy + remove. Cross-volume costs an extra pass
                // through the file (35 MB ≈ 200 ms on NVMe, single-digit
                // seconds on HDD or 1 GbE SMB) which is acceptable for a
                // one-shot at end-time — the per-chunk write loop is what we
                // want to keep on PROGRAMDATA.
                match std::fs::rename(&data_path, &actual_final_path) {
                    Ok(()) => {}
                    Err(e) if is_cross_volume_error(&e) => {
                        tracing::info!(
                            from = %data_path.display(),
                            to = %actual_final_path.display(),
                            "files: cross-volume staging → final; copy+remove fallback"
                        );
                        std::fs::copy(&data_path, &actual_final_path).with_context(|| {
                            format!(
                                "cross-volume copy {} -> {}",
                                data_path.display(),
                                actual_final_path.display()
                            )
                        })?;
                        std::fs::remove_file(&data_path).ok();
                    }
                    Err(e) => {
                        return Err(anyhow::Error::from(e).context(format!(
                            "renaming {} -> {}",
                            data_path.display(),
                            actual_final_path.display()
                        )));
                    }
                }

                // Cleanup: remove the per-id staging dir, then the parent
                // `.roomler-partial/` dir if it's now empty so the staging
                // convention stays invisible (best-effort).
                let _ = std::fs::remove_dir_all(&partial_dir);
                if let Some(parent) = partial_dir.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
                Ok(actual_final_path)
            })
            .await?;
        if let Ok(mut g) = PARTIAL_REGISTRY.lock() {
            g.remove(&state.id);
        }

        Ok((actual_final_path, state.received))
    }

    /// Drop any in-flight incoming transfer (DC closed mid-upload).
    /// The staging dir is left on disk so a future `files:resume`
    /// can pick up where it left off. The 24h orphan sweep at the
    /// next agent startup cleans abandoned partials. Browser-driven
    /// `files:cancel` (rc.19 P2) deletes the staging dir immediately.
    pub async fn abort(&self) {
        let mut guard = self.incoming.lock().await;
        *guard = None;
    }

    /// The session is over: drop an upload's state (its file closes; the
    /// partial stays for a resume, as [`Self::abort`]) and stop a download
    /// at its pump's next check. A download over a link slower than disk
    /// waits on the channel's send buffer, and after a network drop that
    /// buffer never drains: only its cancel flag (or the channel's state)
    /// ends the pump, which otherwise ran on holding the file, the channel
    /// and the transfer guard the updater defers for (found in review).
    pub async fn end_session(&self) {
        // First, so a begin that takes its lock after this refuses, and one
        // that took it before is caught below.
        self.ended.store(true, Ordering::Release);
        self.abort().await;
        if let Some(state) = self.outgoing.lock().await.as_ref() {
            state.cancel.cancel();
        }
    }

    fn refuse_if_ended(&self) -> Result<()> {
        if self.ended.load(Ordering::Acquire) {
            return Err(anyhow!("the session is over"));
        }
        Ok(())
    }

    /// rc.19: cancel an in-flight incoming upload. Removes the per-id
    /// staging dir + registry entry. Called from the
    /// `FilesIncoming::Cancel` arm in peer.rs (P2 wiring) when the
    /// browser's reconnect budget is exhausted. Returns true when an
    /// upload matched the id (caller logs this for audit clarity).
    pub async fn cancel_incoming(&self, id: &str) -> bool {
        // First clear in-flight state if it matches.
        let mut cleared_state = false;
        {
            let mut guard = self.incoming.lock().await;
            if let Some(state) = guard.as_ref()
                && state.id == id
            {
                *guard = None;
                cleared_state = true;
            }
        }
        // Remove the staging dir if known via the registry. Even if
        // in-flight state didn't match, a partial from a previous DC
        // might still be on disk.
        let staging = {
            let g = match PARTIAL_REGISTRY.lock() {
                Ok(g) => g,
                Err(_) => return cleared_state,
            };
            // meta_path is <dest_dir>/.roomler-partial/<id>/meta.json;
            // parent is the per-id staging dir.
            g.get(id).and_then(|e| {
                e.meta_path
                    .parent()
                    .map(|p| (p.to_path_buf(), e.who.clone()))
            })
        };
        if let Some((dir, who)) = staging {
            // FR-97 P3d — removed as whoever staged it.
            let _ = who
                .run(move || {
                    let _ = std::fs::remove_dir_all(&dir);
                    if let Some(parent) = dir.parent() {
                        let _ = std::fs::remove_dir(parent);
                    }
                    Ok(())
                })
                .await;
            if let Ok(mut g) = PARTIAL_REGISTRY.lock() {
                g.remove(id);
            }
            true
        } else {
            cleared_state
        }
    }

    /// rc.19: resume a previously-started upload after a DC drop.
    /// Looks up the staging dir for `id`, truncates the partial
    /// `data` file to the largest 256 KiB-aligned offset ≤ both the
    /// browser's requested offset and the file's on-disk size, opens
    /// it for append at that offset, and reinstalls the
    /// `IncomingTransfer` state on THIS DC's `incoming` Mutex.
    /// Returns the `accepted_offset` the browser should pump from.
    ///
    /// Errors when:
    /// - the registry has no entry for this id AND no canonical
    ///   `Downloads/.roomler-partial/<id>/meta.json` exists on disk;
    /// - `meta.json` is corrupt;
    /// - the `incoming` Mutex on this DC already has another upload
    ///   in-flight (browser must not interleave begins/resumes).
    ///
    /// Truncating to a 256 KiB boundary matches the `files:progress`
    /// cadence (the browser's `bytesAcked` source) so a same-id
    /// resume after a transient blip almost always returns the
    /// browser's requested offset verbatim. The mask only kicks in
    /// when the agent's on-disk size is smaller than what the
    /// browser thinks it acked (B3 fix in the rc.19 plan).
    pub async fn resume_incoming(&self, id: &str, requested_offset: u64) -> Result<u64> {
        // Locate meta_path: registry first, then on-demand probe at
        // the canonical Downloads-rooted location for cross-restart
        // discovery survivors. Poison-tolerant — the HashMap has no
        // invariants a panicking test/peer could break.
        let entry = {
            let g = PARTIAL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            g.get(id).cloned()
        };
        let (meta_path, who) = match entry {
            Some(e) => (e.meta_path, e.who),
            None => {
                // On-demand fallback (sweep may have raced or the
                // partial lives under the staging root but registry
                // was cleared). rc.22 — the staging root depends on
                // the strategy: PROGRAMDATA on Windows (always-on by
                // default), or `<Downloads>/.roomler-partial/` for the
                // legacy escape-hatch path / non-Windows. FR-97 P3d —
                // probed, like everything after, as whoever a drop would
                // be written as now.
                let who = FsAs::now();
                let canonical = {
                    #[cfg(target_os = "windows")]
                    {
                        if stage_in_programdata() {
                            staging_root_windows().join(id).join("meta.json")
                        } else {
                            download_dir()
                                .context("resolving Downloads for on-demand resume probe")?
                                .join(".roomler-partial")
                                .join(id)
                                .join("meta.json")
                        }
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        download_dir_for(&who)
                            .await
                            .context("resolving Downloads for on-demand resume probe")?
                            .join(".roomler-partial")
                            .join(id)
                            .join("meta.json")
                    }
                };
                let probe = canonical.clone();
                if !who
                    .run(move || Ok(std::fs::metadata(&probe).is_ok()))
                    .await?
                {
                    return Err(anyhow!("no partial state for id {id}"));
                }
                (canonical, who)
            }
        };

        // FR-97 P3d — read, truncate and reopen as whoever staged the
        // partial: in the person's own folder, `meta.json` is theirs to
        // edit, and the end-time rename goes where it says.
        let (meta, partial_dir, accepted, file) = who
            .run(move || {
                let meta_bytes = std::fs::read(&meta_path)
                    .with_context(|| format!("reading {}", meta_path.display()))?;
                let meta: PartialMeta = serde_json::from_slice(&meta_bytes)
                    .with_context(|| format!("parsing {}", meta_path.display()))?;
                let partial_dir = meta_path
                    .parent()
                    .ok_or_else(|| anyhow!("meta_path has no parent"))?
                    .to_path_buf();
                let data_path = partial_dir.join("data");

                // disk_size — the source of truth for how much survived. May
                // be smaller than the browser's requested offset (kill
                // happened between sync_data calls).
                let disk_size = std::fs::metadata(&data_path)
                    .with_context(|| format!("stat {}", data_path.display()))?
                    .len();

                // B3 truncation: align to 256 KiB so resumes match the
                // existing files:progress cadence the browser uses for
                // bytesAcked.
                const ALIGN_MASK: u64 = !(256 * 1024 - 1);
                let accepted = requested_offset.min(disk_size) & ALIGN_MASK;

                // Truncate the file in place to accepted, then open for
                // append.
                {
                    let truncate_file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&data_path)
                        .with_context(|| format!("opening {} for truncate", data_path.display()))?;
                    truncate_file.set_len(accepted).with_context(|| {
                        format!("truncating {} to {accepted}", data_path.display())
                    })?;
                }
                let file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&data_path)
                    .with_context(|| format!("re-opening {} for append", data_path.display()))?;
                Ok((meta, partial_dir, accepted, file))
            })
            .await?;
        let file = File::from_std(file);

        // Reinstall state on THIS DC. Refuse if the slot is already
        // populated — browser is misbehaving if it sends resume
        // while another transfer is in-flight on the same DC.
        let mut guard = self.incoming.lock().await;
        if guard.is_some() {
            return Err(anyhow!(
                "files:resume {id} but another transfer is in-flight on this DC"
            ));
        }
        *guard = Some(IncomingTransfer {
            id: id.to_string(),
            expected: meta.expected_size,
            received: accepted,
            file,
            last_progress: accepted,
            partial_dir,
            dest_dir: meta.dest_dir.clone(),
            filename: meta.filename.clone(),
            last_synced: accepted,
            rel_path: meta.rel_path.clone(),
            who,
            _active_guard: ActiveTransferGuard::new(),
        });
        tracing::info!(
            id,
            requested_offset,
            accepted_offset = accepted,
            "files: resume accepted"
        );
        Ok(accepted)
    }

    /// The id of the currently-active incoming transfer, if any.
    /// Used by the peer-layer error path: when `chunk()` fails we
    /// need to send a `files:error` with the matching id so the
    /// browser's per-upload promise listener fires its reject.
    /// Without this the browser silently discards the error (its
    /// listener filters by id) and the upload spinner spins forever.
    pub async fn current_id(&self) -> Option<String> {
        let guard = self.incoming.lock().await;
        guard.as_ref().map(|s| s.id.clone())
    }

    /// Begin a new outgoing transfer (host → browser download).
    /// Validates the path, opens the file for reading, and stashes
    /// state. Returns metadata for the `files:offer` reply.
    ///
    /// The cancellation flag is returned so the pump can check it
    /// between chunks; calling [`Self::cancel_outgoing`] flips the
    /// flag and the next loop iteration will exit.
    pub async fn begin_outgoing(&self, id: String, path: &str) -> Result<OutgoingOffer> {
        let resolved = validate_outgoing_path(path).context("validating outgoing path")?;
        if is_agent_secret(&resolved) {
            return Err(anyhow!(
                "{} holds the agent's own credentials — file transfer never sends it",
                resolved.display()
            ));
        }

        // Stat to surface a real error before we set state, AND get
        // the size for the offer.
        let meta = tokio::fs::metadata(&resolved)
            .await
            .with_context(|| format!("stat {}", resolved.display()))?;
        if !meta.is_file() {
            return Err(anyhow!("not a regular file: {}", resolved.display()));
        }
        let size = meta.len();
        if size > MAX_TRANSFER_BYTES {
            return Err(anyhow!(
                "file size {size} exceeds the {} B cap",
                MAX_TRANSFER_BYTES
            ));
        }

        let name = resolved
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "download.bin".to_string());
        let mime = guess_mime(&name);
        let cancel = tokio_util::sync::CancellationToken::new();

        let mut guard = self.outgoing.lock().await;
        // Under the lock: `end_session` flags first, then takes it.
        self.refuse_if_ended()?;
        if guard.is_some() {
            return Err(anyhow!(
                "another outgoing transfer is already active; cancel it first"
            ));
        }
        *guard = Some(OutgoingTransfer {
            id: id.clone(),
            path: resolved.clone(),
            size,
            cancel: cancel.clone(),
            _active_guard: ActiveTransferGuard::new(),
        });

        Ok(OutgoingOffer {
            id,
            path: resolved,
            name,
            size: Some(size),
            mime,
            cancel,
        })
    }

    /// Open the outgoing transfer's file for reading. Caller pumps
    /// chunks via the returned handle.
    pub async fn open_outgoing(&self, id: &str) -> Result<File> {
        let guard = self.outgoing.lock().await;
        let Some(state) = guard.as_ref() else {
            return Err(anyhow!("no active outgoing transfer"));
        };
        if state.id != id {
            return Err(anyhow!(
                "outgoing id mismatch: requested {id}, active {}",
                state.id
            ));
        }
        File::open(&state.path)
            .await
            .with_context(|| format!("opening {}", state.path.display()))
    }

    /// Stop the active outgoing transfer if its id matches: its pump
    /// ends wherever it is waiting (#1730). Returns true if a matching
    /// transfer was found.
    pub async fn cancel_outgoing(&self, id: &str) -> bool {
        let guard = self.outgoing.lock().await;
        let Some(state) = guard.as_ref() else {
            return false;
        };
        if state.id != id {
            return false;
        }
        state.cancel.cancel();
        true
    }

    /// Clear the active outgoing transfer state. Called by the pump
    /// task when the transfer terminates (success, cancel, or error).
    pub async fn finish_outgoing(&self, id: &str) {
        let mut guard = self.outgoing.lock().await;
        if let Some(state) = guard.as_ref()
            && state.id == id
        {
            *guard = None;
        }
    }
}

/// Metadata returned from [`FilesHandler::begin_outgoing`]. The peer
/// layer uses these to format `files:offer` and to drive the pump
/// (its stop token, [`OutgoingTransfer::cancel`]).
pub struct OutgoingOffer {
    pub id: String,
    pub path: PathBuf,
    pub name: String,
    pub size: Option<u64>,
    pub mime: Option<&'static str>,
    pub cancel: tokio_util::sync::CancellationToken,
}

// ---------------------------------------------------------------------------
// Outgoing path validation

/// Per-OS denylist for paths the agent will refuse to download. These
/// are NOT a sandbox — the operator already has full remote-control
/// rights — but they stop a malicious browser from path-encoding its
/// way into registry hives or kernel-namespace prefixes that bypass
/// the normal Win32 ACL surface.
fn validate_outgoing_path(input: &str) -> Result<PathBuf> {
    if input.is_empty() {
        return Err(anyhow!("path is empty"));
    }
    if input.len() > 4096 {
        return Err(anyhow!("path exceeds 4096 bytes"));
    }

    // Platform-aware denylist.
    let lower = input.to_ascii_lowercase();
    if lower.contains("\\\\?\\globalroot") || lower.contains("//?/globalroot") {
        return Err(anyhow!("path uses kernel-namespace prefix (denied)"));
    }
    // Registry-hive container under Windows. Reading SAM / SECURITY
    // directly is meaningless without the registry API anyway, but
    // also explicitly closing the door helps the audit trail.
    if lower.contains("\\windows\\system32\\config\\")
        || lower.contains("/windows/system32/config/")
    {
        return Err(anyhow!("path is under registry-hive container (denied)"));
    }

    let path = PathBuf::from(input);
    // Canonicalise to dereference symlinks + resolve `..` segments.
    // If canonicalize fails (path doesn't exist, permission denied),
    // surface a friendly error.
    let canonical = std::fs::canonicalize(&path)
        .with_context(|| format!("canonicalising {}", path.display()))?;

    // Re-check the denylist on the canonical form so a symlink trick
    // can't bypass us.
    let canon_lower = canonical.to_string_lossy().to_ascii_lowercase();
    if canon_lower.contains("\\\\?\\globalroot") || canon_lower.contains("//?/globalroot") {
        return Err(anyhow!(
            "canonical path uses kernel-namespace prefix (denied)"
        ));
    }
    if canon_lower.contains("\\windows\\system32\\config\\")
        || canon_lower.contains("/windows/system32/config/")
    {
        return Err(anyhow!(
            "canonical path is under registry-hive container (denied)"
        ));
    }

    Ok(canonical)
}

/// Resolve a path-targeted upload's destination directory. Reuses
/// the same denylist as [`validate_outgoing_path`] (kernel-namespace
/// prefixes, registry-hive container) but additionally requires the
/// path to exist AND be a directory (uploads land at `<dir>/<name>`,
/// so the dir must be writeable on the host).
///
/// Used by [`FilesHandler::begin`] when the browser sends a
/// `dest_path` field on `files:begin`. On error, the caller falls
/// back to the default Downloads/ target with a warning log so the
/// upload doesn't silently drop the operator's data.
#[cfg(test)]
async fn resolve_dest_path(input: &str) -> Result<PathBuf> {
    resolve_dest_path_for(input, &writer_context(), &files_dir::Rules::from_env()).await
}

/// FR-97 P3d — [`resolve_dest_path`] for `who`, AS `who`: the path is
/// canonicalised (links followed) with their rights, and for the person at
/// seat0 the placement rule's active home is theirs.
async fn resolve_dest_path_as(who: &FsAs, input: &str) -> Result<PathBuf> {
    let (input, writer) = (input.to_string(), who.writer());
    who.run(move || resolve_dest_path_here(&input, &writer, &files_dir::Rules::from_env()))
        .await
}

/// [`resolve_dest_path`] for an explicit writer — the seam the tests use,
/// since a test process is never SYSTEM.
#[cfg(test)]
async fn resolve_dest_path_for(
    input: &str,
    writer: &files_dir::Writer,
    rules: &files_dir::Rules,
) -> Result<PathBuf> {
    let (input, writer, rules) = (input.to_string(), writer.clone(), rules.clone());
    FsAs::Daemon
        .run(move || resolve_dest_path_here(&input, &writer, &rules))
        .await
}

/// The body of the dest_path checks, on THIS (blocking) thread under the
/// identity `writer` describes.
fn resolve_dest_path_here(
    input: &str,
    writer: &files_dir::Writer,
    rules: &files_dir::Rules,
) -> Result<PathBuf> {
    let canonical = validate_outgoing_path(input).context("validating dest_path")?;
    if let Some(run) = agent_state_run(&canonical) {
        return Err(anyhow!(
            "dest_path {} is inside the agent's own configuration and state (…{run}…) — \
             file transfer never writes there",
            canonical.display()
        ));
    }
    let meta =
        std::fs::metadata(&canonical).with_context(|| format!("stat {}", canonical.display()))?;
    if !meta.is_dir() {
        return Err(anyhow!(
            "dest_path is not a directory: {}",
            canonical.display()
        ));
    }
    check_dest_placement(&canonical, writer, rules)
        .map_err(|e| anyhow!("dest_path refused: {e}"))?;
    Ok(canonical)
}

/// FR-84 D4's placement rule, applied to a per-upload destination: a
/// PRIVILEGED writer (SYSTEM / root) writes only inside the active user's
/// profile — the same place the drop folder itself must be — and, with
/// nobody signed in, nowhere a controller chose. A controller with FILES
/// acts on the person's files; writing where only the machine may is what
/// `exec` and SSH are gated for. An unprivileged writer is bounded by the
/// OS's own rights on the write.
fn check_dest_placement(
    canonical: &std::path::Path,
    writer: &files_dir::Writer,
    rules: &files_dir::Rules,
) -> Result<(), String> {
    if !writer.privileged {
        return Ok(());
    }
    let plain = files_dir::strip_verbatim(canonical.to_path_buf());
    let placed = files_dir::resolve(&plain.to_string_lossy(), writer, rules)?;
    files_dir::check_placement_on_disk(&placed, writer, rules)
}

/// Component runs that name the agent's OWN configuration and state — its
/// config (enrollment token, SSH host key, WireGuard keys), logs, caches —
/// matched anywhere in a canonical path, case-folded where the file system
/// is. Every profile's copy counts, not only this process's: a SYSTEM or
/// root worker can reach every user's.
#[cfg(target_os = "windows")]
const AGENT_STATE_RUNS: &[&[&str]] = &[
    &["programdata", "meshharbor"],
    &["appdata", "roaming", "meshharbor"],
    &["appdata", "local", "meshharbor"],
    &["programdata", "roomler"],
    &["appdata", "roaming", "roomler"],
    &["appdata", "local", "roomler"],
];
#[cfg(target_os = "macos")]
const AGENT_STATE_RUNS: &[&[&str]] = &[
    &["etc", "meshharbor"],
    &["library", "application support", "live.meshharbor.meshharbor"],
    &["library", "caches", "live.meshharbor.meshharbor"],
    &["var", "log", "meshharbor"],
    &["etc", "roomler"],
    &["library", "application support", "live.roomler.roomler"],
    &["library", "caches", "live.roomler.roomler"],
    // RETIRED-NAME-ANCHOR(4): a pre-rename Mac keeps its state (its config included) in the old segment's folder.
    &[
        "library",
        "application support",
        "live.roomler.roomler-agent",
    ],
    &["var", "log", "roomler"],
];
#[cfg(all(unix, not(target_os = "macos")))]
const AGENT_STATE_RUNS: &[&[&str]] = &[
    &["etc", "meshharbor"],
    &[".config", "meshharbor"],
    &[".local", "share", "meshharbor"],
    &[".local", "state", "meshharbor"],
    &[".cache", "meshharbor"],
    &["var", "log", "meshharbor"],
    &["etc", "roomler"],
    &[".config", "roomler"],
    &[".local", "share", "roomler"],
    &[".local", "state", "roomler"],
    // RETIRED-NAME-ANCHOR(2): a pre-rename host keeps its config and data in the old segment's trees.
    &[".config", "roomler-agent"],
    &[".local", "share", "roomler-agent"],
    &[".cache", "roomler"],
    &["var", "log", "roomler"],
];

/// File names inside the agent's state that carry secrets: the config and
/// every sibling the writer leaves (`.prev`, `.tmp.<pid>`, archived copies),
/// and the Wayland portal's restore tokens.
const AGENT_SECRET_PREFIXES: &[&str] = &["config.toml", "portal-restore-token"];

fn fold_case() -> bool {
    cfg!(any(target_os = "windows", target_os = "macos"))
}

/// The run of [`AGENT_STATE_RUNS`] `path` passes through, if any.
fn agent_state_run(path: &std::path::Path) -> Option<String> {
    let comps: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => {
                let s = s.to_string_lossy();
                Some(if fold_case() {
                    s.to_lowercase()
                } else {
                    s.into_owned()
                })
            }
            _ => None,
        })
        .collect();
    AGENT_STATE_RUNS.iter().find_map(|run| {
        comps
            .windows(run.len())
            .any(|w| w.iter().zip(run.iter()).all(|(a, b)| a == b))
            .then(|| run.join("/"))
    })
}

/// A secret-bearing file of the agent's own: never leaves the host by file
/// transfer, whatever the daemon's privilege. The rest of its state — logs,
/// crash dumps, uploads — stays reachable: that is how a supporter fetches
/// them from the drawer.
fn is_agent_secret(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy()) else {
        return false;
    };
    let name = if fold_case() {
        name.to_lowercase()
    } else {
        name.into_owned()
    };
    AGENT_SECRET_PREFIXES.iter().any(|p| name.starts_with(p)) && agent_state_run(path).is_some()
}

/// Best-effort MIME guess from a filename's extension. Used in the
/// `files:offer` so the browser's `showSaveFilePicker` shows the
/// right filter / so a Blob fallback can set the right type for a
/// later anchor download.
fn guess_mime(name: &str) -> Option<&'static str> {
    let dot = name.rfind('.')?;
    let ext = name[dot + 1..].to_ascii_lowercase();
    Some(match ext.as_str() {
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "csv" => "text/csv",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "exe" | "msi" => "application/octet-stream",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Directory listing

/// 3 second cap on a single `read_dir` enumeration. A disconnected
/// network drive can hang a Win32 `FindFirstFile` for tens of
/// seconds; with this timeout the listing fails fast as a
/// `dir-error` rather than blocking the entire pump.
const DIR_LIST_TIMEOUT_SECS: u64 = 3;

/// Sentinel meaning "wherever THIS host stages in-flight uploads". The caller
/// sends the token; the agent resolves it.
///
/// FR-21 P4. The viewer used to hardcode
// RETIRED-NAME-ANCHOR-BEGIN
// appdirs::app_segment() keeps resolving the pre-rename `roomler-agent`
// segment while that tree exists, so a host installed before the rename
// keeps finding its own staging dir and uploads. Every occurrence below is
// that fallback or a test pinning it — the retired name is the INPUT.
/// `C:\ProgramData\roomler\roomler-agent\staging`, but `machine_global_dir()`
/// resolves the `roomler` segment on a fresh install and only falls back to the
/// pre-rename `roomler-agent` segment when that tree already exists — so the
/// literal was correct on exactly one class of host and silently wrong on the
/// rest. Confirmed on a real SYSTEM-mode Windows host, where
/// `%PROGRAMDATA%\roomler\roomler-agent` does not exist at all.
///
/// A hardcoded copy of a path that a resolver made conditional is a defect
/// waiting for the resolver to take its other branch. The fix is not a better
/// literal — it is removing the caller's ability to hold one.
pub const STAGING_SENTINEL: &str = "<staging>";

/// List a directory. Empty / `~` / `/` enumerates roots (logical
/// drives on Windows; `/` on Unix); [`STAGING_SENTINEL`] resolves to this
/// host's staging root. Returns at most 10000 entries — a directory with more
/// is a degenerate case (deeply nested `node_modules` on a dev box) that we'd
/// rather refuse than stream a 1 MiB JSON listing.
pub async fn list_dir(path: &str) -> Result<DirListing> {
    if path.is_empty() || path == "~" || path == "/" {
        return Ok(DirListing {
            path: roots_label(),
            parent: None,
            entries: enumerate_roots(),
        });
    }
    if path == STAGING_SENTINEL {
        return list_staging().await;
    }
    list_canonical(&PathBuf::from(path)).await
}

/// Canonicalise, enumerate and shape one directory. Shared by the plain path
/// arm and the staging sentinel so the two can never drift in timeout, entry
/// cap or error wording.
async fn list_canonical(pb: &std::path::Path) -> Result<DirListing> {
    let canon =
        std::fs::canonicalize(pb).with_context(|| format!("canonicalising {}", pb.display()))?;
    let parent = canon.parent().map(|p| p.to_string_lossy().to_string());
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(DIR_LIST_TIMEOUT_SECS),
        tokio::fs::read_dir(&canon),
    )
    .await
    .map_err(|_| anyhow!("listing timed out"))?
    .with_context(|| format!("reading {}", canon.display()))?;

    let entries = collect_dir_entries(read).await;
    Ok(DirListing {
        path: canon.to_string_lossy().to_string(),
        parent,
        entries,
    })
}

/// Resolve [`STAGING_SENTINEL`] against THIS host's layout.
///
/// The staging dir is created per update and removed after, so it is absent
/// most of the time. Erroring then would make the quick-access button useless
/// except during the few seconds an update is in flight, so an absent staging
/// dir lists its parent — the machine-global root, which always exists and
/// holds `crashes/`, `service-logs/` and `uploads/` besides.
#[cfg(target_os = "windows")]
async fn list_staging() -> Result<DirListing> {
    let staging = staging_root_windows();
    let target = if staging.is_dir() {
        staging
    } else {
        crate::appdirs::machine_global_dir()
    };
    list_canonical(&target).await
}

/// Non-Windows hosts stage per-destination (`<dest>/.roomler-partial/<id>`),
/// so there is no single staging root to open. Say so rather than inventing a
/// path that would then be wrong in a new way.
#[cfg(not(target_os = "windows"))]
async fn list_staging() -> Result<DirListing> {
    Err(anyhow!(
        "this host has no single staging root — non-Windows agents stage \
         alongside each destination"
    ))
}

async fn collect_dir_entries(mut read: tokio::fs::ReadDir) -> Vec<DirEntryView> {
    let mut entries: Vec<DirEntryView> = Vec::new();
    let mut count: usize = 0;
    while let Ok(Some(entry)) = read.next_entry().await {
        count += 1;
        if count > 10_000 {
            break;
        }
        let name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue, // skip non-UTF-8 names
        };
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue, // permission denied / vanished — skip
        };
        let is_dir = meta.is_dir();
        let size = if is_dir { None } else { Some(meta.len()) };
        let mtime_unix = meta.modified().ok().and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64)
        });
        entries.push(DirEntryView {
            name,
            is_dir,
            size,
            mtime_unix,
        });
    }
    // Sort: dirs first then files; both alphabetical case-insensitive.
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    entries
}

#[cfg(target_os = "windows")]
fn enumerate_roots() -> Vec<DirEntryView> {
    let mut out = Vec::new();
    // GetLogicalDrives returns a bitmask; bit i set = drive (i + 'A')
    // is present. SAFETY: no preconditions; thread-safe.
    let mask: u32 = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    if mask == 0 {
        return out;
    }
    for i in 0u32..26 {
        if mask & (1 << i) != 0 {
            let letter = (b'A' + i as u8) as char;
            out.push(DirEntryView {
                name: format!("{letter}:\\"),
                is_dir: true,
                size: None,
                mtime_unix: None,
            });
        }
    }
    out
}

#[cfg(not(target_os = "windows"))]
fn enumerate_roots() -> Vec<DirEntryView> {
    vec![DirEntryView {
        name: "/".to_string(),
        is_dir: true,
        size: None,
        mtime_unix: None,
    }]
}

#[cfg(target_os = "windows")]
fn roots_label() -> String {
    "Drives".to_string()
}

#[cfg(not(target_os = "windows"))]
fn roots_label() -> String {
    "/".to_string()
}

/// Result of [`list_dir`].
pub struct DirListing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<DirEntryView>,
}

// ---------------------------------------------------------------------------
// Folder zip streaming (Phase 4 of file-DC v2)
//
// We expose async_zip 0.0.17 behind two helpers: `begin_outgoing_zip`
// validates the requested folder and stashes outgoing state (parallel
// to `begin_outgoing` for single-file downloads); `walk_and_zip` is
// the writer task that the peer layer calls inside a tokio::spawn,
// driven by a `tokio::io::duplex` pipe that gives async_zip natural
// backpressure when the DC reader can't keep up.

/// Maximum entries (files + dirs) we'll walk into a single zip
/// before bailing. A degenerate `node_modules` can have hundreds of
/// thousands of files; we'd rather refuse cleanly than stream a 50
/// MiB zip the operator didn't expect.
const ZIP_MAX_ENTRIES: u32 = 10_000;

/// Maximum entry-name length inside the zip (UTF-8 bytes). 4096 is
/// well above any realistic Windows MAX_PATH (260) or POSIX (4096)
/// path; rejection is a sanity check against pathological inputs.
const ZIP_MAX_ENTRY_PATH_LEN: usize = 4096;

impl FilesHandler {
    /// Begin a folder-download outgoing transfer. Validates the path
    /// (denylist + canonicalisation), confirms it's a directory, and
    /// stashes outgoing state. Returns an offer with `size = None`
    /// (folder zips have unknown size up front — it's a streaming
    /// stream).
    pub async fn begin_outgoing_zip(&self, id: String, path: &str) -> Result<OutgoingOffer> {
        let resolved = validate_outgoing_path(path).context("validating folder path")?;
        let meta = tokio::fs::metadata(&resolved)
            .await
            .with_context(|| format!("stat {}", resolved.display()))?;
        if !meta.is_dir() {
            return Err(anyhow!("not a directory: {}", resolved.display()));
        }
        let folder_name = resolved
            .file_name()
            .and_then(|s| s.to_str())
            .map(sanitize_filename)
            .unwrap_or_else(|| "folder".to_string());
        let zip_name = format!("{folder_name}.zip");
        let cancel = tokio_util::sync::CancellationToken::new();

        let mut guard = self.outgoing.lock().await;
        // Under the lock: `end_session` flags first, then takes it.
        self.refuse_if_ended()?;
        if guard.is_some() {
            return Err(anyhow!(
                "another outgoing transfer is already active; cancel it first"
            ));
        }
        *guard = Some(OutgoingTransfer {
            id: id.clone(),
            path: resolved.clone(),
            size: 0, // unknown for streaming zip
            cancel: cancel.clone(),
            _active_guard: ActiveTransferGuard::new(),
        });
        Ok(OutgoingOffer {
            id,
            path: resolved,
            name: zip_name,
            size: None,
            mime: Some("application/zip"),
            cancel,
        })
    }
}

/// Walk `root` recursively, writing every file as a Stored zip
/// entry (no compression). Cycle-safe via a canonical-path HashSet;
/// capped at [`ZIP_MAX_ENTRIES`] to avoid runaway zips.
///
/// `writer` should be the write end of a `tokio::io::duplex` pipe
/// whose read end is being pumped to the DC by the caller — that
/// duplex is what gives us backpressure (writes block when the
/// pipe is full, async_zip awaits, the whole producer chain
/// stalls until the DC reader drains).
///
/// Stored (no-compression) is the right default: most user content
/// is already compressed (jpeg/mp4/zip/exe), so deflate wastes CPU
/// for ~1% gain. Operators who specifically want a smaller zip
/// for log/source folders can use a normal compress-then-download
/// workflow — that's not the use case for the live remote-control
/// drawer.
pub async fn walk_and_zip<W>(
    writer: W,
    root: &std::path::Path,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<u32>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    use async_zip::tokio::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use std::collections::HashSet;
    use tokio_util::compat::FuturesAsyncWriteCompatExt;

    let root_canon = std::fs::canonicalize(root)
        .with_context(|| format!("canonicalising {}", root.display()))?;

    let mut zip = ZipFileWriter::with_tokio(writer);
    let mut stack: Vec<PathBuf> = vec![root_canon.clone()];
    let mut visited: HashSet<PathBuf> = HashSet::new();
    visited.insert(root_canon.clone());
    let mut count: u32 = 0;

    while let Some(dir) = stack.pop() {
        if cancel.is_cancelled() {
            return Err(anyhow!("cancelled by browser"));
        }
        let mut read_dir = match tokio::fs::read_dir(&dir).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(dir = %dir.display(), %e, "zip walk: skipping unreadable dir");
                continue;
            }
        };
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if cancel.is_cancelled() {
                return Err(anyhow!("cancelled by browser"));
            }
            count = count.saturating_add(1);
            if count > ZIP_MAX_ENTRIES {
                return Err(anyhow!(
                    "folder exceeds {ZIP_MAX_ENTRIES} entries — refusing to stream"
                ));
            }
            let path = entry.path();
            let meta = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue, // permission denied — skip
            };

            if meta.is_dir() {
                // Cycle protection: canonical path already visited?
                // (Else branch — already-visited — is a silent skip:
                // symlink loop or hard-linked dir.)
                if let Ok(canon) = std::fs::canonicalize(&path)
                    && visited.insert(canon)
                {
                    stack.push(path);
                }
                continue;
            }

            if !meta.is_file() {
                continue; // skip pipes / sockets / device files
            }
            if is_agent_secret(&path) {
                // A folder download of e.g. the machine-global root carries
                // its logs and crash dumps — never the agent's credentials.
                tracing::debug!(file = %path.display(), "zip walk: skipping the agent's own secret");
                continue;
            }

            // Per-component-sanitised relative path inside the zip.
            // Forward slashes per zip spec.
            let rel = match path.strip_prefix(&root_canon) {
                Ok(r) => r,
                Err(_) => continue, // weirdness — skip
            };
            let rel_safe = rel
                .components()
                .map(|c| sanitize_filename(&c.as_os_str().to_string_lossy()))
                .collect::<Vec<_>>()
                .join("/");
            if rel_safe.is_empty() || rel_safe.len() > ZIP_MAX_ENTRY_PATH_LEN {
                continue;
            }

            // Open the file + stream into a zip entry. Failures on
            // a single file are logged at debug and skipped — we
            // don't want one unreadable file to abort the whole
            // archive.
            let mut src = match tokio::fs::File::open(&path).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(file = %path.display(), %e, "zip walk: skipping unreadable file");
                    continue;
                }
            };
            let builder = ZipEntryBuilder::new(rel_safe.into(), Compression::Stored);
            let entry_writer = match zip.write_entry_stream(builder).await {
                Ok(w) => w,
                Err(e) => {
                    return Err(anyhow!("zip write_entry_stream failed: {e}"));
                }
            };
            // async_zip 0.0.17 returns a `futures::AsyncWrite`-shaped
            // EntryStreamWriter; wrap with compat_write so we can use
            // `tokio::io::copy` against our tokio::fs::File source.
            let mut entry_tokio = entry_writer.compat_write();
            if let Err(e) = tokio::io::copy(&mut src, &mut entry_tokio).await {
                return Err(anyhow!("zip copy failed for {}: {}", path.display(), e));
            }
            // Recover the inner futures-AsyncWrite to call .close().
            let entry_writer = entry_tokio.into_inner();
            if let Err(e) = entry_writer.close().await {
                return Err(anyhow!("zip entry close failed: {e}"));
            }
        }
    }

    if let Err(e) = zip.close().await {
        return Err(anyhow!("zip finalise failed: {e}"));
    }
    Ok(count)
}

/// Byte-count snapshot emitted after a chunk that crossed a progress
/// threshold. Owned so the caller can serialize it outside the state
/// lock.
pub struct ChunkProgress {
    pub id: String,
    pub bytes: u64,
}

// ---------------------------------------------------------------------------
// Filename + path helpers

/// Sanitize a browser-provided filename to a safe basename. Strips any
/// directory components and replaces characters outside
/// `[A-Za-z0-9._ -]` with `_`. Falls back to `download.bin` for empty
/// input.
pub fn sanitize_filename(name: &str) -> String {
    // Take the last path component. Browsers normally send just a
    // basename but some send full paths on some platforms (drag-and-
    // drop from Finder, etc.).
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_matches('.');
    if trimmed.is_empty() {
        "download.bin".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolve a folder-upload's relative path under Downloads/. Splits on
/// `/` (the canonical separator the browser sends — Chrome /
/// Firefox / Safari all return forward-slash relative paths from
/// `webkitGetAsEntry()`); sanitises each component with the existing
/// [`sanitize_filename`] rules so a malicious browser can't smuggle
/// `..` or absolute paths; rejects empty / single-component inputs
/// (those should use the flat-upload path); and applies
/// [`unique_path`] to the FILE component so a re-upload gets a
/// `(2)` rename suffix instead of overwriting.
///
/// Returns `None` for inputs that produce no usable path (all
/// components sanitised to empty, deeper than 32 levels — a sane
/// nesting cap that catches degenerate inputs while passing every
/// realistic project tree).
///
/// `dir` is the Downloads directory; the returned path lives under
/// `dir/<root>/<sub...>/<file>` with each segment safe.
fn resolve_folder_upload_path(dir: &std::path::Path, rel: &str) -> Option<PathBuf> {
    // Normalise separators: Windows-style backslashes can sneak in
    // if a buggy browser converts paths.
    let normalised = rel.replace('\\', "/");
    let mut components: Vec<String> = normalised
        .split('/')
        .filter(|c| !c.is_empty() && *c != "." && *c != "..")
        .map(sanitize_filename)
        .filter(|c| !c.is_empty() && c != "_")
        .collect();
    if components.len() < 2 {
        // Need at least <root>/<file>; otherwise the rel_path is
        // empty or a single basename — caller should fall back to
        // flat upload.
        return None;
    }
    if components.len() > 32 {
        return None; // pathological depth
    }
    // Last component is the file; everything before is dir hierarchy.
    let file_name = components.pop()?;
    let mut path = dir.to_path_buf();
    for c in &components {
        path.push(c);
    }
    // Apply collision-safe rename to the leaf file. The directory
    // prefix is shared across all files in a folder upload so we
    // intentionally do NOT version-suffix it — a re-upload of the
    // same folder merges files into the same destination directory
    // (each colliding file picks up its own `(2)` suffix). This
    // matches the behaviour operators expect from a desktop
    // file-manager paste-on-existing-folder.
    Some(unique_path(&path, &file_name))
}

/// Given a base directory and a desired filename, return a path that
/// doesn't collide with an existing file — appends `(2)`, `(3)` etc.
/// before the extension when needed.
fn unique_path(dir: &std::path::Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = split_stem_ext(name);
    for n in 2..1000u32 {
        let suffixed = if ext.is_empty() {
            format!("{stem} ({n})")
        } else {
            format!("{stem} ({n}).{ext}")
        };
        let p = dir.join(&suffixed);
        if !p.exists() {
            return p;
        }
    }
    // Exceedingly unlikely — hand back the original and let create()
    // overwrite.
    candidate
}

fn split_stem_ext(name: &str) -> (&str, &str) {
    if let Some(idx) = name.rfind('.')
        && idx > 0
        && idx < name.len() - 1
    {
        return (&name[..idx], &name[idx + 1..]);
    }
    (name, "")
}

/// Where an incoming transfer lands: the configured `files_dir` when it
/// passes for THIS writer at THIS moment, else the default ladder below.
///
/// FR-84 D4 — this is the USE-time gate, and the load-bearing one: it holds
/// even when the value reached the config file behind the daemon's back (a
/// hand edit, the desktop's direct-file fallback while the daemon was down,
/// a user switch since it was set). The full check runs per transfer —
/// shape, placement for the identity doing the writing and the user signed
/// in now, links followed, created if missing, a write probe — and a
/// refusal is logged and falls back rather than failing the drop.
/// FR-97 P3d — the drop folder for `who`, resolved as them (the configured
/// folder's gate creates it and probes a write).
async fn download_dir_for(who: &FsAs) -> Result<PathBuf> {
    let w = who.clone();
    who.run(move || download_dir_as(&w)).await
}

/// [`download_dir`] for `who`, on a thread under their identity. For the
/// person at seat0: the configured folder when it passes for them (inside
/// THEIR home, FR-84 D4's rule), else their own Downloads.
fn download_dir_as(who: &FsAs) -> Result<PathBuf> {
    match who {
        FsAs::Daemon => download_dir(),
        #[cfg(target_os = "linux")]
        FsAs::Person { home, .. } => {
            if let Some(raw) = configured_files_dir() {
                let writer = who.writer();
                match files_dir::validate(&raw, &writer, &files_dir::Rules::from_env()) {
                    Ok(dir) => return Ok(dir),
                    Err(e) => tracing::warn!(
                        files_dir = %raw,
                        active_home = ?writer.active_home,
                        %e,
                        "files: configured files_dir refused for the person at seat0 — this \
                         transfer lands in their Downloads"
                    ),
                }
            }
            Ok(person_downloads(home))
        }
    }
}

/// [`default_download_dir`] for `who`, on a thread under their identity.
fn default_download_dir_as(who: &FsAs, log: bool) -> Result<PathBuf> {
    match who {
        FsAs::Daemon => default_download_dir(log),
        #[cfg(target_os = "linux")]
        FsAs::Person { home, .. } => Ok(person_downloads(home)),
    }
}

fn download_dir() -> Result<PathBuf> {
    if let Some(raw) = configured_files_dir() {
        let writer = writer_context();
        match files_dir::validate(&raw, &writer, &files_dir::Rules::from_env()) {
            Ok(dir) => return Ok(dir),
            Err(e) => tracing::warn!(
                files_dir = %raw,
                privileged = writer.privileged,
                active_home = ?writer.active_home,
                %e,
                "files: configured files_dir refused — this transfer lands in the default folder"
            ),
        }
    }
    default_download_dir(true)
}

/// The default ladder — what `files_dir` unset has always meant. `log` =
/// false for the status answer, which is recomputed every few seconds while
/// the companion is open and must not repeat the fallback's warning each time.
fn default_download_dir(log: bool) -> Result<PathBuf> {
    // M3 A1 SystemContext fallback: when the worker is spawned by the
    // SCM service via winlogon-token, it runs as LocalSystem
    // (S-1-5-18) but in the user's interactive session.
    // `directories::UserDirs::new()` resolves Downloads to the
    // LocalSystem profile (`C:\Windows\System32\config\systemprofile\
    // Downloads\`) which usually doesn't exist — uploads fail (or
    // worse, succeed silently into a directory the user can't see).
    // Field repro the field-test host rc.7 2026-05-06: file upload via browse-
    // and-select hung because `create_dir_all` couldn't create the
    // SYSTEM-profile path. Same fallback shape as the rc.6 config
    // fix; see `system_context::user_profile`.
    #[cfg(all(feature = "system-context", target_os = "windows"))]
    {
        use crate::system_context::{user_profile, worker_role};
        if matches!(
            worker_role::probe_self(),
            Ok(worker_role::WorkerRole::SystemContext)
        ) && let Some(dl) = user_profile::active_user_downloads_path()
        {
            tracing::debug!(
                fallback_path = %dl.display(),
                "files: SystemContext worker — using active-user Downloads (default would be SYSTEM profile)"
            );
            return Ok(dl);
        }
    }

    if let Some(dirs) = directories::UserDirs::new()
        && let Some(dl) = dirs.download_dir()
    {
        return Ok(dl.to_path_buf());
    }
    // Windows-specific final fallback (the field-test host 2026-05-11 rc.20 field
    // repro): when the worker is LocalSystem and the user's `Downloads`
    // is Folder-Redirected to a network share (e.g.
    // `\\fileserver\UserData$\<user>\Downloads`) that SYSTEM can't
    // access, `active_user_downloads_path()` returns None AND
    // `UserDirs::new().download_dir()` returns None. Pre-rc.21 the
    // code fell back to `std::env::temp_dir()` = `C:\Windows\SystemTemp\`
    // — which Windows Defender / SmartScreen scan AGGRESSIVELY for
    // any `.exe`-named write. Defender held the staging `data` file
    // open during write, `write_all` never landed bytes, browser SCTP
    // buffer overflowed, retry budget exhausted. Switch the final
    // fallback to `%PROGRAMDATA%\roomler\roomler-agent\uploads\` —
    // SYSTEM-writable, persistent across reboots, NOT under
    // Defender's SystemTemp-scan policy. Operator can find their
    // landed files there via the `files:complete { path }` reply.
    #[cfg(target_os = "windows")]
    {
        let staging = crate::appdirs::machine_global_dir().join("uploads");
        if log {
            tracing::warn!(
                fallback_path = %staging.display(),
                "files: no user-accessible Downloads dir (Folder Redirection?); staging in PROGRAMDATA"
            );
        }
        Ok(staging)
    }
    // Non-Windows: keep the temp-dir final fallback (headless CI,
    // unusual service accounts on Linux/macOS — those don't have
    // Defender's SystemTemp-scan problem).
    #[cfg(not(target_os = "windows"))]
    {
        let _ = log;
        Ok(std::env::temp_dir())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-21 P4 — the sentinel must resolve on the AGENT, never in the viewer.
    ///
    /// The viewer used to hardcode `C:\ProgramData\roomler\roomler-agent\staging`,
    /// which `machine_global_dir()` only resolves to on a host that already
    /// carries the pre-rename tree. Verified broken on a real SYSTEM-mode
    /// Windows host, where that parent does not exist at all.
    #[tokio::test]
    async fn the_staging_sentinel_resolves_on_the_agent_and_never_errors() {
        let listing = list_dir(STAGING_SENTINEL).await;

        #[cfg(target_os = "windows")]
        {
            // Staging is transient, so the contract is "always lands somewhere
            // real": the staging dir when an update is in flight, otherwise the
            // machine-global root. Never an error, or the button is useless
            // except during the seconds an update is running.
            let listing = listing.expect("the sentinel must always resolve on Windows");
            let root = crate::appdirs::machine_global_dir();
            let root_s = root.to_string_lossy().to_lowercase();
            let got = listing.path.to_lowercase();
            assert!(
                got.contains(root_s.trim_start_matches(r"\\?\")),
                "resolved {got} is outside the machine-global root {root_s}"
            );
            // And it must NOT be the literal the viewer used to hold.
            assert!(
                !got.contains("roomler-agent") || root_s.contains("roomler-agent"),
                "resolved {got} used the pre-rename segment on a host whose root is {root_s}"
            );
        }

        #[cfg(not(target_os = "windows"))]
        {
            // No single staging root off Windows — saying so beats inventing a
            // path that would be wrong in a new way.
            //
            // Matched rather than `expect_err`: that would require
            // `DirListing: Debug`, which it does not implement. The arm compiles
            // only on Linux/macOS, so the mistake was invisible locally on
            // Windows and CI is what caught it.
            let msg = match listing {
                Ok(l) => panic!("non-Windows hosts have no staging root, got {}", l.path),
                Err(e) => e.to_string(),
            };
            assert!(
                msg.contains("no single staging root"),
                "unhelpful error: {msg}"
            );
        }
    }

    #[test]
    fn the_sentinel_is_not_a_path_anything_could_canonicalise() {
        // If this ever became a real path the viewer could send, the resolver
        // arm would be dead and the defect would come back silently.
        assert!(STAGING_SENTINEL.starts_with('<') && STAGING_SENTINEL.ends_with('>'));
        assert!(!STAGING_SENTINEL.contains(char::from(92)));
        assert!(!STAGING_SENTINEL.contains('/'));
    }

    /// Serializes every test that mutates the process-global HOME /
    /// USERPROFILE (`begin()` resolves the Downloads dir through them, and
    /// tests run in parallel threads). Without this the mutations race:
    /// `round_trip_begin_chunk_end` resolved its destination inside
    /// `concurrent_upload_and_download…`'s hijacked HOME and failed on the
    /// final rename (flake observed 2026-08-14 under full-suite
    /// parallelism). tokio Mutex, not std: the guard is held across the
    /// tests' awaits by design.
    static HOME_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A folder THIS writer may use: the temp dir for an ordinary test
    /// runner; inside the active home for a privileged one (a root CI
    /// container), where the profile rule would refuse the temp dir.
    fn scratch_drop_dir(tag: &str) -> PathBuf {
        let w = writer_context();
        let base = if w.privileged {
            PathBuf::from(w.active_home.expect("a privileged test runner has a home"))
        } else {
            std::env::temp_dir()
        };
        base.join(format!("roomler-files-dir-{tag}-{}", std::process::id()))
    }

    /// Where an upload with no `dest_path` lands for the length of a test:
    /// a scratch drop folder, set as the process-wide `files_dir` (the
    /// production override `download_dir()` answers first), and put back to
    /// unset when the guard drops, a failed assertion included. Hold
    /// `FILES_DIR_TEST_LOCK` while it lives.
    ///
    /// ⚠️ Never a HOME/USERPROFILE redirect: on Windows the default ladder
    /// resolves the Downloads known folder and ignores both, so those tests
    /// wrote into the developer's REAL Downloads (452 `upload (N).txt` had
    /// piled up there by 2026-09-26), and rewriting USERPROFILE mid-run
    /// raced `win_identity`'s test, which reads it.
    struct ScratchDrops(PathBuf);

    impl ScratchDrops {
        fn new(tag: &str) -> Self {
            let dir = scratch_drop_dir(tag);
            let _ = std::fs::remove_dir_all(&dir);
            set_files_dir(Some(dir.to_string_lossy().into_owned()));
            Self(dir)
        }
    }

    impl Drop for ScratchDrops {
        fn drop(&mut self) {
            set_files_dir(None);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// FR-84 D4 — the USE-time gate. A configured folder that passes is where
    /// the drop lands (created on first use); one the validator refuses —
    /// here a system root, the case a hand-edited config or the desktop's
    /// direct-file fallback can produce with no daemon to say no — falls back
    /// to the default ladder, per transfer, and the status answer names the
    /// folder a drop would really use. Unset = today's ladder.
    #[test]
    fn configured_files_dir_is_used_when_valid_and_ignored_when_not() {
        let _lock = FILES_DIR_TEST_LOCK.blocking_lock();
        let _home = HOME_ENV_LOCK.blocking_lock();
        set_files_dir(None);
        let default = default_download_dir(false).unwrap();
        let default_s = default.to_string_lossy().into_owned();
        assert_eq!(download_dir().unwrap(), default, "unset = the ladder");
        assert_eq!(
            refresh_effective_files_dir().as_deref(),
            Some(default_s.as_str())
        );

        let dir = scratch_drop_dir("use");
        let _ = std::fs::remove_dir_all(&dir);
        let spelled = dir.to_string_lossy().into_owned();
        set_files_dir(Some(format!("  {spelled}  ")));
        assert_eq!(
            configured_files_dir().as_deref(),
            Some(spelled.as_str()),
            "trimmed"
        );
        // Before the first drop the folder does not exist, and the status
        // still names it: the drop creates it. Looking created nothing.
        assert_eq!(
            refresh_effective_files_dir().as_deref(),
            Some(spelled.as_str())
        );
        assert!(!dir.exists(), "the status answer creates nothing");
        assert_eq!(download_dir().unwrap(), dir);
        assert!(dir.is_dir(), "created on first use");

        let bad = if cfg!(windows) {
            r"C:\Windows\Temp\roomler-drops"
        } else {
            "/usr/roomler-drops"
        };
        set_files_dir(Some(bad.to_string()));
        assert_eq!(
            download_dir().unwrap(),
            default,
            "a refused value never wins over the ladder"
        );
        assert_eq!(
            refresh_effective_files_dir().as_deref(),
            Some(default_s.as_str()),
            "status reports where a drop would really land"
        );
        assert!(
            !std::path::Path::new(bad).exists(),
            "a refused folder is never created"
        );

        set_files_dir(Some("   ".into()));
        assert_eq!(configured_files_dir(), None, "blank = unset");
        assert_eq!(download_dir().unwrap(), default);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FR-84 D4 — a value that passed when it was set and fails now (here the
    /// folder was replaced by a file; a user switch or a new link are the
    /// field versions). The drop does not fail and does not follow the stale
    /// value: it lands in the default folder, and the status says so.
    #[test]
    fn a_files_dir_that_became_invalid_falls_back_at_use_time() {
        let _lock = FILES_DIR_TEST_LOCK.blocking_lock();
        let _home = HOME_ENV_LOCK.blocking_lock();
        let dir = scratch_drop_dir("stale");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&dir);
        let spelled = dir.to_string_lossy().into_owned();
        validate_files_dir_setting(&spelled).expect("accepted at set time");
        set_files_dir(Some(spelled.clone()));
        assert_eq!(download_dir().unwrap(), dir);

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, b"not a folder any more").unwrap();
        let default = default_download_dir(false).unwrap();
        assert_eq!(
            download_dir().unwrap(),
            default,
            "the drop falls back instead of failing"
        );
        assert_eq!(
            refresh_effective_files_dir(),
            Some(default.to_string_lossy().into_owned()),
            "and the status answer follows"
        );
        assert!(
            validate_files_dir_setting(&spelled).is_err(),
            "the set-time gate would refuse it now too"
        );
        set_files_dir(None);
        let _ = std::fs::remove_file(&dir);
    }

    /// FR-84 D4 — the status read never computes: it answers from the cache
    /// (a disk or share lookup on the LocalAPI's async dispatch would stall
    /// every client), and an answer for an OLD value never overwrites the
    /// answer for the current one.
    #[test]
    fn effective_files_dir_answers_from_the_cache() {
        let _lock = FILES_DIR_TEST_LOCK.blocking_lock();
        let _home = HOME_ENV_LOCK.blocking_lock();
        let dir = scratch_drop_dir("cache");
        let spelled = dir.to_string_lossy().into_owned();
        set_files_dir(Some(spelled.clone()));
        assert_eq!(
            refresh_effective_files_dir().as_deref(),
            Some(spelled.as_str())
        );
        // Fresh ⇒ served from the cache, the same answer.
        assert_eq!(effective_files_dir().as_deref(), Some(spelled.as_str()));
        // A stale generation's late result is dropped on the floor.
        {
            let mut c = EFFECTIVE_FILES_DIR
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            c.generation += 1; // as if a newer value's answer had landed
        }
        refresh_effective_files_dir(); // computed for the (now older) current generation
        let c = EFFECTIVE_FILES_DIR
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            c.generation,
            FILES_DIR_GEN.load(Ordering::Acquire) + 1,
            "an older generation must not replace a newer one"
        );
        drop(c);
        // Put the cache back in step for whoever runs next.
        {
            let mut c = EFFECTIVE_FILES_DIR
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            c.generation = FILES_DIR_GEN.load(Ordering::Acquire);
            c.computed_at = None;
        }
        set_files_dir(None);
    }

    #[test]
    fn writer_context_describes_this_process() {
        let w = writer_context();
        assert!(w.active_home.is_some(), "a test runner has a home: {w:?}");
        #[cfg(target_os = "windows")]
        assert_eq!(w.privileged, crate::win_identity::process_is_local_system());
        #[cfg(unix)]
        assert_eq!(w.privileged, unsafe { libc::geteuid() } == 0);
    }

    #[test]
    fn sanitize_strips_path_components() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("C:\\Windows\\System32\\a.txt"), "a.txt");
        assert_eq!(sanitize_filename("normal.pdf"), "normal.pdf");
    }

    #[test]
    fn sanitize_replaces_unsafe_chars() {
        assert_eq!(
            sanitize_filename("my:weird*file?.txt"),
            "my_weird_file_.txt"
        );
    }

    #[test]
    fn sanitize_empty_input_falls_back() {
        assert_eq!(sanitize_filename(""), "download.bin");
        assert_eq!(sanitize_filename("/"), "download.bin");
        assert_eq!(sanitize_filename("///"), "download.bin");
    }

    #[test]
    fn split_stem_ext_handles_edges() {
        assert_eq!(split_stem_ext("report.pdf"), ("report", "pdf"));
        assert_eq!(split_stem_ext(".hidden"), (".hidden", ""));
        assert_eq!(split_stem_ext("trailing."), ("trailing.", ""));
        assert_eq!(split_stem_ext("noext"), ("noext", ""));
    }

    #[test]
    fn parse_files_begin() {
        let m: FilesIncoming =
            serde_json::from_str(r#"{"t":"files:begin","id":"abc","name":"x.bin","size":100}"#)
                .unwrap();
        match m {
            FilesIncoming::Begin {
                id,
                name,
                size,
                mime,
                ..
            } => {
                assert_eq!(id, "abc");
                assert_eq!(name, "x.bin");
                assert_eq!(size, 100);
                assert_eq!(mime, None);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_end() {
        let m: FilesIncoming = serde_json::from_str(r#"{"t":"files:end","id":"abc"}"#).unwrap();
        match m {
            FilesIncoming::End { id } => assert_eq!(id, "abc"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_begin_with_dest_path() {
        // Path-targeted upload extension (file-DC v2.2). The browser
        // sends `dest_path` when the operator drops onto the drawer's
        // current dir; the agent uses it as the upload target.
        let m: FilesIncoming = serde_json::from_str(
            r#"{"t":"files:begin","id":"f1","name":"x.bin","size":42,"dest_path":"C:\\Users\\me\\Documents"}"#,
        )
        .unwrap();
        match m {
            FilesIncoming::Begin {
                id,
                name,
                size,
                dest_path,
                rel_path,
                ..
            } => {
                assert_eq!(id, "f1");
                assert_eq!(name, "x.bin");
                assert_eq!(size, 42);
                assert_eq!(dest_path.as_deref(), Some("C:\\Users\\me\\Documents"));
                assert!(rel_path.is_none(), "dest_path doesn't imply rel_path");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_begin_with_dest_path_and_rel_path() {
        // The two extensions stack — folder-drop into an arbitrary
        // host directory.
        let m: FilesIncoming = serde_json::from_str(
            r#"{"t":"files:begin","id":"f1","name":"file.txt","size":42,"rel_path":"MyFolder/sub/file.txt","dest_path":"C:\\Projects"}"#,
        )
        .unwrap();
        match m {
            FilesIncoming::Begin {
                rel_path,
                dest_path,
                ..
            } => {
                assert_eq!(rel_path.as_deref(), Some("MyFolder/sub/file.txt"));
                assert_eq!(dest_path.as_deref(), Some("C:\\Projects"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_dest_path_accepts_existing_dir() {
        let base = scratch_drop_dir(&format!(
            "roomler-dest-ok-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        let resolved = resolve_dest_path(&base.to_string_lossy())
            .await
            .expect("dir should be accepted");
        // Canonicalisation may add a `\\?\` prefix on Windows; just
        // check the resolved path equals (or canonicalises to) the
        // input.
        assert!(resolved.exists());
        assert!(resolved.is_dir());
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn resolve_dest_path_rejects_file() {
        let base = std::env::temp_dir().join(format!(
            "roomler-dest-file-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        let f = base.join("not-a-dir.txt");
        tokio::fs::write(&f, b"hi").await.unwrap();
        let res = resolve_dest_path(&f.to_string_lossy()).await;
        assert!(res.is_err(), "regular file should be rejected");
        assert!(
            res.unwrap_err().to_string().contains("not a directory"),
            "error mentions not-a-directory"
        );
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn resolve_dest_path_rejects_globalroot() {
        // Same denylist as validate_outgoing_path. We never get to
        // the metadata check.
        let res = resolve_dest_path(r"\\?\GLOBALROOT\Device\HarddiskVolume2\foo").await;
        assert!(res.is_err());
    }

    /// A temp tree laid out like the agent's own per-user state on this
    /// platform, with a stand-in config holding a marker "secret".
    fn agent_state_fixture(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "roomler-statefixture-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = if cfg!(target_os = "windows") {
            base.join("AppData")
                .join("Roaming")
                .join("roomler")
                .join("roomler")
        } else if cfg!(target_os = "macos") {
            base.join("Library")
                .join("Application Support")
                .join("live.roomler.roomler")
        } else {
            base.join(".config").join("roomler")
        };
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("config.toml"), AGENT_SECRET_MARKER).unwrap();
        (base, state)
    }

    const AGENT_SECRET_MARKER: &[u8] = b"agent_token = \"marker-7f3a9c\"\n";

    // The agent's own configuration and state — its enrollment token, its
    // SSH host key, its logs — is never a file-transfer source or target,
    // whatever the daemon's privilege: a controller with FILES acts on the
    // person's files, not the daemon's.
    #[test]
    fn the_agents_own_state_is_recognised_in_every_spelling() {
        use std::path::Path;
        #[cfg(target_os = "windows")]
        {
            for p in [
                r"C:\ProgramData\roomler\roomler\config.toml",
                r"\\?\C:\PROGRAMDATA\Roomler\ROOMLER\service-logs\x.log",
                r"C:\Users\u\AppData\Roaming\roomler\roomler\config\config.toml",
                r"C:\Users\u\AppData\Local\roomler\roomler\data\desktop\desktop.log",
            ] {
                assert!(agent_state_run(Path::new(p)).is_some(), "{p}");
            }
            for p in [
                r"C:\Users\u\Documents\roomler\notes.txt",
                r"C:\ProgramData\Microsoft\x",
                r"C:\Users\u\AppData\Local\Temp\roomler-x\y",
            ] {
                assert!(agent_state_run(Path::new(p)).is_none(), "{p}");
            }
        }
        #[cfg(unix)]
        {
            for p in [
                "/etc/meshharbor/config.toml",
                "/private/etc/meshharbor/config.toml",
                "/home/u/.config/meshharbor/config.toml",
                "/root/.local/share/meshharbor/logs/roomlerd.log",
            ] {
                assert!(agent_state_run(Path::new(p)).is_some(), "{p}");
            }
            for p in ["/home/u/Documents/roomler/x", "/tmp/roomler-x/y"] {
                assert!(agent_state_run(Path::new(p)).is_none(), "{p}");
            }
        }
    }

    #[tokio::test]
    async fn an_upload_never_lands_in_the_agents_own_state() {
        let (base, state) = agent_state_fixture("up");
        let res = resolve_dest_path_for(
            &state.to_string_lossy(),
            &files_dir::Writer::unprivileged(None),
            &files_dir::Rules::from_env(),
        )
        .await;
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            res.is_err(),
            "agent state is never an upload target: {res:?}"
        );
    }

    #[tokio::test]
    async fn the_agents_own_config_is_never_a_download() {
        let (base, state) = agent_state_fixture("down");
        std::fs::write(state.join("config.toml.prev"), AGENT_SECRET_MARKER).unwrap();
        std::fs::create_dir_all(state.join("logs")).unwrap();
        std::fs::write(state.join("logs").join("roomlerd.log"), b"a log line\n").unwrap();
        let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
        let config = FilesHandler::new()
            .begin_outgoing("o1".into(), &path(&state.join("config.toml")))
            .await
            .is_err();
        let prev = FilesHandler::new()
            .begin_outgoing("o2".into(), &path(&state.join("config.toml.prev")))
            .await
            .is_err();
        // Support still works: the drawer lists the agent's folders and a
        // log downloads — only the secret-bearing files are refused.
        let log_ok = FilesHandler::new()
            .begin_outgoing("o3".into(), &path(&state.join("logs").join("roomlerd.log")))
            .await
            .is_ok();
        let listing_ok = list_dir(&path(&state)).await.is_ok();
        let _ = std::fs::remove_dir_all(&base);
        assert!(config, "the agent's config is never a download");
        assert!(prev, "nor its .prev sibling");
        assert!(log_ok, "a log is still a download");
        assert!(listing_ok, "the agent's folders are still listed");
    }

    #[tokio::test]
    async fn a_folder_download_leaves_the_agents_secrets_out() {
        let (base, state) = agent_state_fixture("zip");
        std::fs::write(base.join("keep.txt"), b"a person's file").unwrap();
        std::fs::write(state.join("service.log"), b"a diagnostic line").unwrap();
        let (zip_writer, mut zip_reader) = tokio::io::duplex(64 * 1024);
        let cancel = tokio_util::sync::CancellationToken::new();
        let root = base.clone();
        let walk = tokio::spawn(async move { walk_and_zip(zip_writer, &root, cancel).await });
        let drain = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut out = Vec::new();
            zip_reader.read_to_end(&mut out).await.unwrap();
            out
        });
        walk.await.unwrap().expect("walk_and_zip");
        let zip = drain.await.unwrap();
        let _ = std::fs::remove_dir_all(&base);
        let has = |needle: &[u8]| zip.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"a person's file"), "the person's file is in the zip");
        assert!(has(b"a diagnostic line"), "the agent's logs still are");
        assert!(!has(AGENT_SECRET_MARKER), "the agent's config never is");
    }

    // FR-84 D4's placement rule binds a per-upload destination too: a
    // PRIVILEGED writer (SYSTEM / root) writes only inside the active
    // user's profile, where the drop folder itself must be.
    #[tokio::test]
    async fn a_privileged_upload_stays_inside_the_active_profile() {
        let base = std::env::temp_dir().join(format!(
            "roomler-destpriv-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let home = base.join("home");
        let inside = home.join("Documents");
        let outside = base.join("elsewhere");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let home_s = std::fs::canonicalize(&home).unwrap();
        let home_s = files_dir::strip_verbatim(home_s)
            .to_string_lossy()
            .into_owned();
        let rules = files_dir::Rules::from_env();
        let system = files_dir::Writer {
            privileged: true,
            active_home: Some(home_s.clone()),
        };
        let nobody = files_dir::Writer {
            privileged: true,
            active_home: None,
        };
        let user = files_dir::Writer::unprivileged(Some(home_s));
        let ok_inside = resolve_dest_path_for(&inside.to_string_lossy(), &system, &rules).await;
        let outside_sys = resolve_dest_path_for(&outside.to_string_lossy(), &system, &rules).await;
        let no_one = resolve_dest_path_for(&inside.to_string_lossy(), &nobody, &rules).await;
        let outside_user = resolve_dest_path_for(&outside.to_string_lossy(), &user, &rules).await;
        let _ = std::fs::remove_dir_all(&base);
        assert!(ok_inside.is_ok(), "inside the profile: {ok_inside:?}");
        let e = outside_sys.expect_err("SYSTEM outside the profile is refused");
        assert!(format!("{e:#}").contains("profile"), "{e:#}");
        assert!(
            no_one.is_err(),
            "SYSTEM with nobody signed in writes nowhere it chose"
        );
        // An unprivileged writer is bounded by the OS's own rights, not here.
        assert!(outside_user.is_ok(), "{outside_user:?}");
    }

    #[tokio::test]
    async fn begin_with_dest_path_lands_in_dest() {
        let _lock = FILES_DIR_TEST_LOCK.lock().await;
        let _env = HOME_ENV_LOCK.lock().await;
        // End-to-end: a `begin` call with dest_path should produce a
        // path under the dest dir, not under Downloads.
        let base = scratch_drop_dir(&format!(
            "roomler-dest-e2e-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dest = base.join("dest");
        tokio::fs::create_dir_all(&dest).await.unwrap();
        // Should dest_path resolution ever fall through, the default folder
        // is a scratch one, never the developer's real Downloads.
        let _drops = ScratchDrops::new("dest-e2e");

        let h = FilesHandler::new();
        let path = h
            .begin(
                "d1".into(),
                "out.bin".into(),
                4,
                None,
                Some(&dest.to_string_lossy()),
            )
            .await
            .expect("begin");
        // The destination path's parent should canonicalise-match
        // dest. (canonicalize() of dest may add long-path prefixes on
        // Windows.)
        let dest_canon = std::fs::canonicalize(&dest).unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(parent, dest_canon, "lands under dest_path: {path:?}");

        // Cleanup.
        h.abort().await;
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[test]
    fn parse_files_begin_with_rel_path() {
        // Folder-upload extension (file-DC v2.1). When the browser
        // sends a `rel_path`, the agent recreates the directory
        // structure under Downloads/.
        let m: FilesIncoming = serde_json::from_str(
            r#"{"t":"files:begin","id":"f1","name":"file.txt","size":42,"rel_path":"MyFolder/sub/file.txt"}"#,
        )
        .unwrap();
        match m {
            FilesIncoming::Begin {
                id,
                name,
                size,
                rel_path,
                ..
            } => {
                assert_eq!(id, "f1");
                assert_eq!(name, "file.txt");
                assert_eq!(size, 42);
                assert_eq!(rel_path.as_deref(), Some("MyFolder/sub/file.txt"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_begin_without_rel_path_back_compat() {
        // Old browsers (file-DC v1) don't send rel_path; deserialise
        // as None via #[serde(default)].
        let m: FilesIncoming =
            serde_json::from_str(r#"{"t":"files:begin","id":"f1","name":"x.bin","size":100}"#)
                .unwrap();
        match m {
            FilesIncoming::Begin { rel_path, .. } => {
                assert!(rel_path.is_none(), "old browsers omit rel_path");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn resolve_folder_upload_simple_two_component() {
        let dir = std::env::temp_dir().join("roomler-folder-resolve-test");
        std::fs::create_dir_all(&dir).ok();
        let p = resolve_folder_upload_path(&dir, "MyFolder/file.txt").expect("simple");
        let s = p.to_string_lossy();
        assert!(s.contains("MyFolder"), "kept root: {s}");
        assert!(s.ends_with("file.txt"), "kept leaf: {s}");
    }

    #[test]
    fn resolve_folder_upload_deep_nesting() {
        let dir = std::env::temp_dir().join("roomler-folder-deep-test");
        std::fs::create_dir_all(&dir).ok();
        let p = resolve_folder_upload_path(&dir, "a/b/c/d/file.txt").expect("deep");
        let s = p.to_string_lossy();
        assert!(s.contains("a"));
        assert!(s.contains("b"));
        assert!(s.ends_with("file.txt"));
    }

    #[test]
    fn resolve_folder_upload_rejects_traversal_components() {
        // Sanitisation strips `..` and `.` components. Result is
        // safe even on a malicious browser.
        let dir = std::env::temp_dir().join("roomler-folder-traversal-test");
        std::fs::create_dir_all(&dir).ok();
        let p = resolve_folder_upload_path(&dir, "MyFolder/../../etc/passwd").expect("traversal");
        let s = p.to_string_lossy();
        // The `..` segments are filtered; only `MyFolder` + `etc` +
        // `passwd` survive, and the result lives under `dir`.
        assert!(
            s.starts_with(&*dir.to_string_lossy()),
            "stays under dir: {s}"
        );
        assert!(!s.contains(".."), "no traversal sequences: {s}");
    }

    #[test]
    fn resolve_folder_upload_rejects_single_component() {
        let dir = std::env::temp_dir().join("roomler-folder-single-test");
        std::fs::create_dir_all(&dir).ok();
        // No "/" → can't be a folder upload; caller should fall back
        // to flat upload.
        assert!(resolve_folder_upload_path(&dir, "justafile.txt").is_none());
    }

    #[test]
    fn resolve_folder_upload_rejects_empty() {
        let dir = std::env::temp_dir().join("roomler-folder-empty-test");
        std::fs::create_dir_all(&dir).ok();
        assert!(resolve_folder_upload_path(&dir, "").is_none());
    }

    #[test]
    fn resolve_folder_upload_normalises_backslash() {
        // A buggy browser that sends Windows-style separators
        // shouldn't break; we normalise to forward slashes before
        // splitting.
        let dir = std::env::temp_dir().join("roomler-folder-backslash-test");
        std::fs::create_dir_all(&dir).ok();
        let p = resolve_folder_upload_path(&dir, "MyFolder\\sub\\file.txt").expect("backslash");
        let s = p.to_string_lossy();
        assert!(s.contains("MyFolder"));
        assert!(s.contains("sub"));
        assert!(s.ends_with("file.txt"));
    }

    #[test]
    fn resolve_folder_upload_caps_extreme_depth() {
        let dir = std::env::temp_dir().join("roomler-folder-deep-cap-test");
        std::fs::create_dir_all(&dir).ok();
        let mut deep = String::from("a");
        for i in 1..50 {
            deep.push_str(&format!("/b{i}"));
        }
        deep.push_str("/file.txt");
        // 50 levels exceeds the 32-component cap.
        assert!(resolve_folder_upload_path(&dir, &deep).is_none());
    }

    #[test]
    fn parse_files_get() {
        let m: FilesIncoming =
            serde_json::from_str(r#"{"t":"files:get","id":"d1","path":"C:\\report.pdf"}"#).unwrap();
        match m {
            FilesIncoming::Get { id, path } => {
                assert_eq!(id, "d1");
                assert_eq!(path, "C:\\report.pdf");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_get_folder() {
        let m: FilesIncoming = serde_json::from_str(
            r#"{"t":"files:get-folder","id":"f1","path":"C:\\Logs","format":"zip"}"#,
        )
        .unwrap();
        match m {
            FilesIncoming::GetFolder { id, path, format } => {
                assert_eq!(id, "f1");
                assert_eq!(path, "C:\\Logs");
                assert_eq!(format.as_deref(), Some("zip"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_cancel() {
        let m: FilesIncoming = serde_json::from_str(r#"{"t":"files:cancel","id":"d1"}"#).unwrap();
        match m {
            FilesIncoming::Cancel { id } => assert_eq!(id, "d1"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_dir() {
        let m: FilesIncoming =
            serde_json::from_str(r#"{"t":"files:dir","req_id":"r1","path":""}"#).unwrap();
        match m {
            FilesIncoming::Dir { req_id, path } => {
                assert_eq!(req_id, "r1");
                assert_eq!(path, "");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---- rc.19 file-DC v3 resume wire-format locks ----

    #[test]
    fn parse_files_resume_without_sha_prefix() {
        let m: FilesIncoming =
            serde_json::from_str(r#"{"t":"files:resume","id":"u9","offset":4194304}"#).unwrap();
        match m {
            FilesIncoming::Resume {
                id,
                offset,
                sha256_prefix,
            } => {
                assert_eq!(id, "u9");
                assert_eq!(offset, 4_194_304);
                assert_eq!(sha256_prefix, None);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_files_resume_with_sha_prefix_is_accepted() {
        // v1 agents accept-and-ignore sha256_prefix; v2 agents will
        // verify. Locking the schema now so v2 doesn't break compat.
        let m: FilesIncoming = serde_json::from_str(
            r#"{"t":"files:resume","id":"u9","offset":0,"sha256_prefix":"deadbeef"}"#,
        )
        .unwrap();
        match m {
            FilesIncoming::Resume {
                sha256_prefix: Some(s),
                ..
            } => assert_eq!(s, "deadbeef"),
            other => panic!("expected Resume with sha_prefix, got {other:?}"),
        }
    }

    #[test]
    fn serialize_files_resumed() {
        let s = serde_json::to_string(&FilesOutgoing::Resumed {
            id: "u9",
            accepted_offset: 4_194_304,
        })
        .unwrap();
        assert!(s.contains("\"t\":\"files:resumed\""), "got: {s}");
        assert!(s.contains("\"id\":\"u9\""), "got: {s}");
        assert!(s.contains("\"accepted_offset\":4194304"), "got: {s}");
    }

    #[test]
    fn serialize_files_resumed_with_zero_offset() {
        // accepted_offset == 0 is a normal response — agent has no
        // partial state for this id, browser re-pumps from byte 0.
        // Field must serialise explicitly, not be elided.
        let s = serde_json::to_string(&FilesOutgoing::Resumed {
            id: "u9",
            accepted_offset: 0,
        })
        .unwrap();
        assert!(s.contains("\"accepted_offset\":0"), "got: {s}");
    }

    #[test]
    fn active_transfers_counter_starts_at_zero() {
        // Sanity check: in a fresh test run no transfer guards are
        // alive. Other tests in this file may temporarily increment
        // this counter but must always release the guard before
        // returning — verify the baseline.
        let n = active_transfer_count();
        // We can't assert == 0 because tests run in parallel and a
        // sibling test may be mid-flight. We CAN assert < 1000 (a
        // sensible upper bound that would catch a runaway leak).
        assert!(n < 1000, "active_transfer_count={n} suspicious");
    }

    #[test]
    fn serialize_files_offer() {
        let s = serde_json::to_string(&FilesOutgoing::Offer {
            id: "d1",
            name: "report.pdf",
            size: Some(1024),
            mime: Some("application/pdf"),
        })
        .unwrap();
        assert!(s.contains("\"t\":\"files:offer\""), "got: {s}");
        assert!(s.contains("\"id\":\"d1\""));
        assert!(s.contains("\"size\":1024"));
        // size: None must serialize as null (browser checks size === null
        // for streaming offers like folder zips).
        let s2 = serde_json::to_string(&FilesOutgoing::Offer {
            id: "f1",
            name: "Logs.zip",
            size: None,
            mime: None,
        })
        .unwrap();
        assert!(s2.contains("\"size\":null"), "got: {s2}");
    }

    #[test]
    fn serialize_files_eof() {
        let s = serde_json::to_string(&FilesOutgoing::Eof {
            id: "d1",
            bytes: 1024,
        })
        .unwrap();
        assert_eq!(s, r#"{"t":"files:eof","id":"d1","bytes":1024}"#);
    }

    #[test]
    fn validate_outgoing_path_rejects_globalroot() {
        let res = validate_outgoing_path(r"\\?\GLOBALROOT\Device\HarddiskVolume2\foo");
        assert!(res.is_err(), "should reject globalroot prefix");
        assert!(res.unwrap_err().to_string().contains("kernel-namespace"));
    }

    #[test]
    fn validate_outgoing_path_rejects_registry_hive_dir() {
        let res = validate_outgoing_path(r"C:\Windows\System32\config\SAM");
        assert!(res.is_err(), "should reject registry hive container");
        assert!(res.unwrap_err().to_string().contains("registry-hive"));
    }

    #[test]
    fn validate_outgoing_path_rejects_empty() {
        assert!(validate_outgoing_path("").is_err());
    }

    #[test]
    fn validate_outgoing_path_rejects_oversized() {
        let long = "a".repeat(5000);
        assert!(validate_outgoing_path(&long).is_err());
    }

    #[tokio::test]
    async fn list_dir_against_tempdir() {
        // Build a temp dir with one file + one subdir; verify the
        // listing is sorted dirs-first and each entry has the right
        // is_dir flag.
        let base = std::env::temp_dir().join(format!(
            "roomler-list-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        tokio::fs::create_dir(base.join("subdir")).await.unwrap();
        tokio::fs::write(base.join("file.txt"), b"hello")
            .await
            .unwrap();

        let listing = list_dir(&base.to_string_lossy()).await.expect("list_dir");
        assert_eq!(listing.entries.len(), 2);
        assert!(listing.entries[0].is_dir, "subdir should sort first");
        assert_eq!(listing.entries[0].name, "subdir");
        assert!(!listing.entries[1].is_dir);
        assert_eq!(listing.entries[1].name, "file.txt");
        assert_eq!(listing.entries[1].size, Some(5));

        // Cleanup best-effort.
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn list_dir_roots_returns_drives_or_root() {
        let listing = list_dir("").await.expect("list_dir empty");
        assert!(!listing.entries.is_empty(), "roots view must have entries");
        // Every entry must be a directory (drive root or "/").
        for e in &listing.entries {
            assert!(e.is_dir, "root entry should be a dir: {:?}", e);
        }
        // Parent must be None for the roots view.
        assert!(listing.parent.is_none());
    }

    #[tokio::test]
    async fn begin_outgoing_stats_a_real_file() {
        let base = std::env::temp_dir().join(format!(
            "roomler-out-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        let file_path = base.join("data.bin");
        tokio::fs::write(&file_path, vec![0u8; 4096]).await.unwrap();

        let h = FilesHandler::new();
        let offer = h
            .begin_outgoing("d1".into(), &file_path.to_string_lossy())
            .await
            .expect("begin_outgoing");
        assert_eq!(offer.id, "d1");
        assert_eq!(offer.size, Some(4096));
        assert_eq!(offer.name, "data.bin");

        // Cleanup
        h.finish_outgoing("d1").await;
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn walk_and_zip_round_trip() {
        // Build a 3-file folder, zip it, parse the zip back and
        // verify entry names + contents are preserved. Locks the
        // backbone of Phase 4 — sanitisation, recursion, and the
        // compat_write pipeline through async_zip.
        let base = std::env::temp_dir().join(format!(
            "roomler-zip-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let folder = base.join("payload");
        let subdir = folder.join("nested");
        tokio::fs::create_dir_all(&subdir).await.unwrap();
        tokio::fs::write(folder.join("a.txt"), b"first")
            .await
            .unwrap();
        tokio::fs::write(folder.join("b.bin"), vec![0u8; 8])
            .await
            .unwrap();
        tokio::fs::write(subdir.join("c.txt"), b"third")
            .await
            .unwrap();

        // Capture zip bytes via a duplex pipe + drain task — mirrors
        // the production topology (walk_and_zip writes to a duplex,
        // a separate task pumps the reader half to the DC).
        let (zip_writer, mut zip_reader) = tokio::io::duplex(64 * 1024);
        let cancel = tokio_util::sync::CancellationToken::new();
        let folder_clone = folder.clone();
        let cancel_clone = cancel.clone();
        let walk_handle = tokio::spawn(async move {
            crate::files::walk_and_zip(zip_writer, &folder_clone, cancel_clone).await
        });
        let drain_handle = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut out = Vec::new();
            zip_reader.read_to_end(&mut out).await.unwrap();
            out
        });
        let _count = walk_handle.await.unwrap().expect("walk_and_zip");
        let sink = drain_handle.await.unwrap();

        assert!(!sink.is_empty(), "zip output should be non-empty");
        // The zip MUST end with the End-of-Central-Directory record
        // (PKzip signature 0x06054b50). If walk_and_zip exited
        // without `.close()` we'd see truncated output.
        let last4 = &sink[sink.len() - 22..sink.len() - 22 + 4];
        // EOCD signature is 0x06054b50 little-endian = 50 4B 05 06
        assert_eq!(
            last4,
            &[0x50, 0x4B, 0x05, 0x06],
            "zip should end with EOCD record"
        );

        // Cleanup.
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn concurrent_upload_and_download_do_not_contend() {
        let _lock = FILES_DIR_TEST_LOCK.lock().await;
        let _env = HOME_ENV_LOCK.lock().await;
        // Critique #2 in the plan said an in-flight upload should
        // not block a concurrent download (and vice versa). Locks
        // the invariant: incoming + outgoing each have their own
        // mutex; one can be active while the other progresses.
        let base = std::env::temp_dir().join(format!(
            "roomler-concurrent-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        let download_src = base.join("source.bin");
        tokio::fs::write(&download_src, vec![0u8; 1024])
            .await
            .unwrap();

        // The upload lands in a scratch drop folder, never the dev's
        // real Downloads (see `ScratchDrops`).
        let _drops = ScratchDrops::new("concurrent");

        let h = FilesHandler::new();
        // Start an upload — populates `incoming`.
        let upload_path = h
            .begin("u1".into(), "upload.txt".into(), 5, None, None)
            .await
            .expect("begin upload");

        // Concurrently start a download — populates `outgoing`. If
        // the two states shared a mutex this would deadlock or block.
        let offer = h
            .begin_outgoing("d1".into(), &download_src.to_string_lossy())
            .await
            .expect("begin_outgoing");
        assert_eq!(offer.size, Some(1024));

        // Both should be reachable simultaneously.
        let active_id = h.current_id().await;
        assert_eq!(active_id.as_deref(), Some("u1"));
        // We can write a chunk to the upload while the download
        // state is still pinned.
        h.chunk(b"hello").await.expect("chunk");
        let (final_path, bytes) = h.end("u1").await.expect("end");
        assert_eq!(final_path, upload_path);
        assert_eq!(bytes, 5);
        // The whole point of the scratch folder: nothing a test uploads
        // ever lands in the real Downloads (red with a HOME/USERPROFILE
        // redirect on Windows, which the known folder ignores).
        if let Some(real) =
            directories::UserDirs::new().and_then(|u| u.download_dir().map(PathBuf::from))
        {
            assert!(
                !final_path.starts_with(&real),
                "a test upload landed in the real Downloads: {}",
                final_path.display()
            );
        }

        // The download is still active.
        let cancelled = h.cancel_outgoing("d1").await;
        assert!(cancelled);
        h.finish_outgoing("d1").await;

        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    /// The session is over: a download's pump is told to stop (and an
    /// upload's state goes, as [`FilesHandler::abort`]). Red without the
    /// download half: after a drop its pump waits on a send buffer that
    /// never drains, holding the file, the channel and the transfer guard
    /// the updater defers for.
    #[tokio::test]
    async fn a_session_end_stops_the_download() {
        let base = std::env::temp_dir().join(format!(
            "roomler-session-end-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        let file_path = base.join("x.bin");
        tokio::fs::write(&file_path, b"xx").await.unwrap();

        let h = FilesHandler::new();
        let offer = h
            .begin_outgoing("session-end-d1".into(), &file_path.to_string_lossy())
            .await
            .expect("begin_outgoing");
        assert!(!offer.cancel.is_cancelled());
        h.end_session().await;
        let told = offer.cancel.is_cancelled();
        // Twice is fine (the channel's own close may come after), and with
        // no upload in flight there is none left.
        h.end_session().await;
        let upload_left = h.current_id().await;
        // A message still in flight when the session ended begins nothing.
        // (The upload names this test's own folder, never the real
        // Downloads, should the refusal ever go.)
        h.finish_outgoing("session-end-d1").await;
        let late_download = h
            .begin_outgoing("session-end-d2".into(), &file_path.to_string_lossy())
            .await;
        let late_upload = h
            .begin(
                "session-end-u2".into(),
                "late.txt".into(),
                1,
                None,
                Some(&base.to_string_lossy()),
            )
            .await;

        let _ = tokio::fs::remove_dir_all(&base).await;
        assert!(told, "the download's pump was not told to stop");
        assert_eq!(upload_left, None);
        assert!(
            late_download.is_err(),
            "a download began after the session ended"
        );
        assert!(
            late_upload.is_err(),
            "an upload began after the session ended"
        );
    }

    #[tokio::test]
    async fn cancel_outgoing_flips_flag() {
        let base = std::env::temp_dir().join(format!(
            "roomler-cancel-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        let file_path = base.join("x.bin");
        tokio::fs::write(&file_path, b"xx").await.unwrap();

        let h = FilesHandler::new();
        let offer = h
            .begin_outgoing("c1".into(), &file_path.to_string_lossy())
            .await
            .expect("begin_outgoing");
        assert!(!offer.cancel.is_cancelled());
        let cancelled = h.cancel_outgoing("c1").await;
        assert!(cancelled);
        assert!(offer.cancel.is_cancelled());

        // Mismatched id → false, no flag change on a fresh transfer.
        let cancelled_other = h.cancel_outgoing("nonexistent").await;
        assert!(!cancelled_other);

        h.finish_outgoing("c1").await;
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn round_trip_begin_chunk_end() {
        let _lock = FILES_DIR_TEST_LOCK.lock().await;
        let _env = HOME_ENV_LOCK.lock().await;
        // `begin` with no dest_path uses the drop folder: a scratch one
        // here, never the dev's real Downloads (see `ScratchDrops`).
        let _drops = ScratchDrops::new("round-trip");
        let h = FilesHandler::new();

        let path = h
            .begin("t1".into(), "hello.txt".into(), 5, None, None)
            .await
            .unwrap();
        h.chunk(b"hello").await.unwrap();
        let (final_path, bytes) = h.end("t1").await.unwrap();
        assert_eq!(final_path, path);
        assert_eq!(bytes, 5);
        let got = tokio::fs::read(&final_path).await.unwrap();
        assert_eq!(got, b"hello");
    }

    // ---- rc.19 P1 — staging dir + meta.json + sweep + sync_data ----
    //
    // These tests use `dest_path` to override the upload's target
    // directory because Windows `download_dir()` resolves via
    // `KNOWNFOLDERID_Downloads`, NOT via HOME/USERPROFILE (a test with no
    // `dest_path` uses `ScratchDrops` instead). `dest_path` is the same
    // operator-chosen-target path the browser sends when dropping into
    // the drawer's current dir.

    /// Create an isolated `dest_path`-style tempdir for staging tests, so
    /// the staging dir is fully under our control on every platform.
    async fn stage_tmpdir() -> PathBuf {
        let base = scratch_drop_dir(&format!(
            "roomler-rc19-stage-{}-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            std::process::id()
        ));
        tokio::fs::create_dir_all(&base).await.unwrap();
        base
    }

    // rc.19 counter tests: ActiveTransferGuard wraps a process-
    // global AtomicUsize. Parallel tests share that global, so
    // before/after comparisons race fatally. The Drop contract is
    // structurally enforced by the type system — every transfer
    // struct owns a `_active_guard` field, every Drop on that field
    // decrements. No runtime test can cleanly assert "counter went
    // back down" without serialising every test that touches a
    // transfer. The updater-side `decide_defer` test in updater.rs
    // covers the gating logic; the counter mechanics fall out of
    // the type system.

    #[tokio::test]
    async fn begin_creates_staging_dir_with_meta_json() {
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-stage-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        h.begin(
            id.clone(),
            "report.pdf".into(),
            1024,
            None,
            Some(dest.to_str().unwrap()),
        )
        .await
        .expect("begin");

        // .roomler-partial/<id>/data + meta.json must exist before
        // any chunk arrives. `dest_path` is canonicalised by
        // `validate_outgoing_path` (Win adds `\\?\` UNC prefix), so
        // compare against the canonicalised root.
        let canonical_dest = tokio::fs::canonicalize(&dest).await.unwrap();
        let staging = canonical_dest.join(".roomler-partial").join(&id);
        assert!(
            staging.exists(),
            "staging dir missing: {}",
            staging.display()
        );
        let meta_path = staging.join("meta.json");
        let data_path = staging.join("data");
        assert!(meta_path.exists(), "meta.json missing");
        assert!(data_path.exists(), "data file missing");

        // meta.json round-trips.
        let bytes = tokio::fs::read(&meta_path).await.unwrap();
        let meta: PartialMeta = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(meta.protocol_version, 1);
        assert_eq!(meta.filename, "report.pdf");
        assert_eq!(meta.expected_size, 1024);
        assert_eq!(meta.dest_dir, canonical_dest);

        // Registry was populated. Lookup canonicalises to the same
        // path as what `begin()` stored. (Block-scoped, not drop():
        // clippy's await_holding_lock drop-tracking doesn't credit an
        // explicit drop and flags the guard against the await below.)
        {
            let g = PARTIAL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                g.get(&id).map(|e| e.meta_path.as_path()),
                Some(meta_path.as_path())
            );
        }

        h.abort().await;
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn end_renames_staging_to_final_and_cleans_dir() {
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-end-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let reserved = h
            .begin(
                id.clone(),
                "hello.txt".into(),
                5,
                None,
                Some(dest.to_str().unwrap()),
            )
            .await
            .expect("begin");
        h.chunk(b"hello").await.expect("chunk");
        let (final_path, bytes) = h.end(&id).await.expect("end");
        assert_eq!(bytes, 5);
        // M4 fix: final path matches the begin-time reservation when
        // there's no operator-induced collision.
        assert_eq!(final_path, reserved);
        // File on disk has the payload.
        let got = tokio::fs::read(&final_path).await.unwrap();
        assert_eq!(got, b"hello");
        // Staging dir + per-id dir + parent .roomler-partial/ are
        // all gone.
        let staging_parent = dest.join(".roomler-partial");
        assert!(!staging_parent.join(&id).exists(), "per-id dir leaked");
        // Registry entry removed. (Block-scoped for await_holding_lock.)
        {
            let g = PARTIAL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            assert!(g.get(&id).is_none(), "registry entry leaked");
        }
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn begin_rejects_existing_partial_dir_for_same_id() {
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-collide-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        // First begin → success, staging dir exists.
        h.begin(
            id.clone(),
            "a.txt".into(),
            4,
            None,
            Some(dest.to_str().unwrap()),
        )
        .await
        .expect("first begin");
        // Drop the in-flight state so the second begin doesn't
        // collide on the Mutex — only the on-disk dir should block.
        h.abort().await;

        // Second begin with the SAME id MUST fail — without this
        // guard, File::create(data) would truncate the partial and
        // destroy progress (B1 fix).
        let second = h
            .begin(
                id.clone(),
                "a.txt".into(),
                4,
                None,
                Some(dest.to_str().unwrap()),
            )
            .await;
        assert!(second.is_err(), "second begin should reject");
        let msg = second.unwrap_err().to_string();
        assert!(
            msg.contains("already has partial state") || msg.contains("send files:resume"),
            "unexpected error message: {msg}"
        );
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn chunk_syncs_data_at_fsync_threshold_boundary() {
        // rc.24 — was named "..._at_one_mib_boundary" when
        // FSYNC_THRESHOLD_BYTES was 1 MiB. After lowering to 256 KiB
        // (so sub-1-MiB uploads can survive a process kill), the
        // sync cadence changed but the contract is the same:
        // last_synced advances by exactly one threshold per chunk
        // that crosses the boundary.
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-sync-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        // Send 1.5× threshold total — one sync at threshold, none past.
        let size = (FSYNC_THRESHOLD_BYTES + FSYNC_THRESHOLD_BYTES / 2) as usize;
        h.begin(
            id.clone(),
            "big.bin".into(),
            size as u64,
            None,
            Some(dest.to_str().unwrap()),
        )
        .await
        .expect("begin");

        // 6 chunks × (threshold / 4) so we cross the threshold
        // exactly once on chunk 4, and stay short of the second
        // sync after chunk 6 = 1.5 × threshold.
        let chunk_size = (FSYNC_THRESHOLD_BYTES / 4) as usize;
        let chunk = vec![0xABu8; chunk_size];
        for _ in 0..6 {
            h.chunk(&chunk).await.expect("chunk");
        }

        // Verify the durable-at-sync-boundary contract that B2
        // actually guarantees: last_synced advanced past the
        // threshold exactly once. Chunks 1..4 = threshold → triggers
        // first sync (received == FSYNC_THRESHOLD_BYTES, delta ==
        // threshold). Chunks 5..6 = 1.5×threshold total → delta =
        // 0.5×threshold < threshold, no second sync.
        //
        // We do NOT assert on `tokio::fs::metadata(...).len()` here:
        // `tokio::fs::File` has an internal write buffer that
        // `write_all().await` populates without forcing an OS-level
        // write, and Linux + Windows tokio runtimes drain that
        // buffer at different cadences. The B2 production invariant
        // is "bytes 0..last_synced are durable", which IS testable
        // via the in-memory state; "bytes 0..received are visible
        // to stat()" depends on tokio's buffer state and isn't what
        // the resume protocol relies on. (Resume's B3 fix protects
        // the wire against any acked-bytes > disk-size mismatch.)
        let guard = h.incoming.lock().await;
        let state = guard.as_ref().expect("state");
        assert_eq!(state.last_synced, FSYNC_THRESHOLD_BYTES);
        assert_eq!(state.received, (6 * chunk_size) as u64);
        drop(guard);

        h.abort().await;
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn resume_round_trips_after_partial_upload() {
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-resume-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        // Total expected = 2 MiB. Send 1 MiB then abort to simulate
        // a DC drop. last_synced will be 1 MiB (one sync at the
        // boundary), disk_size == 1 MiB.
        h.begin(
            id.clone(),
            "big.bin".into(),
            2 * 1024 * 1024,
            None,
            Some(dest.to_str().unwrap()),
        )
        .await
        .expect("begin");
        let chunk = vec![0xCDu8; 256 * 1024];
        for _ in 0..4 {
            h.chunk(&chunk).await.expect("chunk");
        }
        // Simulated DC drop — state cleared, partial dir survives.
        h.abort().await;

        // Browser reconnects, sends files:resume claiming 1 MiB.
        let accepted = h
            .resume_incoming(&id, 1024 * 1024)
            .await
            .expect("resume_incoming");
        assert_eq!(accepted, 1024 * 1024);

        // Pump the remaining 1 MiB and finalise.
        for _ in 0..4 {
            h.chunk(&chunk).await.expect("post-resume chunk");
        }
        let (final_path, bytes) = h.end(&id).await.expect("end");
        assert_eq!(bytes, 2 * 1024 * 1024);
        let got_meta = tokio::fs::metadata(&final_path).await.unwrap();
        assert_eq!(got_meta.len(), 2 * 1024 * 1024);
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn resume_truncates_when_disk_size_below_requested() {
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-resume-truncate-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        // Begin a 2 MiB upload, send 512 KiB only (no sync because
        // 512 KiB < FSYNC_THRESHOLD_BYTES — that's irrelevant, we
        // care about disk size). Abort.
        h.begin(
            id.clone(),
            "small.bin".into(),
            2 * 1024 * 1024,
            None,
            Some(dest.to_str().unwrap()),
        )
        .await
        .expect("begin");
        let chunk = vec![0xEFu8; 256 * 1024];
        for _ in 0..2 {
            h.chunk(&chunk).await.expect("chunk");
        }
        h.abort().await;

        // Browser THINKS it sent 1 MiB but agent only has 512 KiB
        // on disk. Resume should accept 512 KiB (already aligned to
        // 256 KiB boundary; B3 mask is a no-op here).
        let accepted = h.resume_incoming(&id, 1024 * 1024).await.expect("resume");
        assert_eq!(accepted, 512 * 1024);

        // Browser pumps from 512 KiB.
        for _ in 0..6 {
            h.chunk(&chunk).await.expect("post-resume chunk");
        }
        let (_, bytes) = h.end(&id).await.expect("end");
        assert_eq!(bytes, 2 * 1024 * 1024);
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn resume_unknown_id_errors() {
        // Use a per-test unique id so a sibling test couldn't have
        // inserted it. No need to reset the registry (which would
        // race with parallel tests).
        let id = format!(
            "rc19-resume-unknown-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let h = FilesHandler::new();
        let res = h.resume_incoming(&id, 0).await;
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("no partial state") || msg.contains("Downloads"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn end_recomputes_unique_path_when_collision_appears_mid_upload() {
        // M4 fix: re-run unique_path at rename time. If the operator
        // creates a file at the begin-time reservation BETWEEN begin
        // and end, the rename target shifts to the next unique slot.
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-m4-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let reserved = h
            .begin(
                id.clone(),
                "doc.txt".into(),
                4,
                None,
                Some(dest.to_str().unwrap()),
            )
            .await
            .expect("begin");
        // Operator creates a file at the begin-time reservation.
        tokio::fs::write(&reserved, b"existing").await.unwrap();
        h.chunk(b"abcd").await.expect("chunk");
        let (final_path, bytes) = h.end(&id).await.expect("end");
        assert_eq!(bytes, 4);
        // The actual final path must NOT be the begin reservation —
        // unique_path appended a `(1)` suffix.
        assert_ne!(
            final_path, reserved,
            "M4 fix: end() should pick a new unique path"
        );
        // Original file content preserved (operator's `existing`
        // bytes weren't overwritten).
        let original = tokio::fs::read(&reserved).await.unwrap();
        assert_eq!(original, b"existing");
        // New upload landed at the colliding-renamed path.
        let uploaded = tokio::fs::read(&final_path).await.unwrap();
        assert_eq!(uploaded, b"abcd");
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn cancel_incoming_removes_staging_dir_and_registry() {
        let dest = stage_tmpdir().await;
        let h = FilesHandler::new();
        let id = format!(
            "rc19-cancel-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        h.begin(
            id.clone(),
            "doomed.bin".into(),
            1024,
            None,
            Some(dest.to_str().unwrap()),
        )
        .await
        .expect("begin");
        let canonical_dest = tokio::fs::canonicalize(&dest).await.unwrap();
        let staging = canonical_dest.join(".roomler-partial").join(&id);
        assert!(staging.exists(), "staging dir absent pre-cancel");
        // Confirm registry has the id pre-cancel.
        {
            let g = PARTIAL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            assert!(g.contains_key(&id));
        }
        let cleared = h.cancel_incoming(&id).await;
        assert!(cleared, "cancel_incoming should return true");
        assert!(!staging.exists(), "staging dir leaked after cancel");
        {
            let g = PARTIAL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            assert!(!g.contains_key(&id), "registry leaked entry after cancel");
        }
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    #[tokio::test]
    async fn sweep_orphans_deletes_stale_and_keeps_fresh() {
        let dest = stage_tmpdir().await;
        // Build two fake partial dirs by hand: one 25h old, one 1h old.
        let root = dest.join(".roomler-partial");
        let now = chrono::Utc::now().timestamp();
        let mk = |id: &str, age_secs: i64| {
            let dir = root.join(id);
            let meta = PartialMeta {
                protocol_version: 1,
                filename: format!("{id}.bin"),
                expected_size: 100,
                dest_dir: dest.clone(),
                reserved_final_path: dest.join(format!("{id}.bin")),
                created_at_unix: now - age_secs,
                rel_path: None,
            };
            (dir, meta)
        };
        let (stale_dir, stale_meta) = mk("rc19-sweep-stale", 25 * 3600);
        let (fresh_dir, fresh_meta) = mk("rc19-sweep-fresh", 3600);
        for (dir, meta) in [
            (stale_dir.clone(), stale_meta),
            (fresh_dir.clone(), fresh_meta),
        ] {
            tokio::fs::create_dir_all(&dir).await.unwrap();
            tokio::fs::write(
                dir.join("meta.json"),
                serde_json::to_vec_pretty(&meta).unwrap(),
            )
            .await
            .unwrap();
            tokio::fs::write(dir.join("data"), b"").await.unwrap();
        }

        let (kept, swept) = sweep_orphans_in(&dest).await;
        assert_eq!(swept, 1, "should sweep the 25h-old dir");
        assert_eq!(kept, 1, "should keep the 1h-old dir");
        assert!(!stale_dir.exists(), "stale dir should be removed");
        assert!(fresh_dir.exists(), "fresh dir should survive");
        // Fresh entry is in the registry. (Block-scoped for
        // await_holding_lock.)
        {
            let g = PARTIAL_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                g.contains_key("rc19-sweep-fresh"),
                "fresh id missing from registry: {:?}",
                g.keys().collect::<Vec<_>>()
            );
        }
        let _ = tokio::fs::remove_dir_all(&dest).await;
    }

    // ---- rc.22 — always-PROGRAMDATA staging strategy ----

    #[test]
    fn rc22_stage_in_programdata_is_false_under_cfg_test() {
        // cfg(test) forces the legacy per-dest layout so the existing
        // in-crate assertions on `<dest>/.roomler-partial/<id>` still
        // hold. Production on Windows flips this true; tests stay
        // false to keep isolation cheap.
        assert!(
            !stage_in_programdata(),
            "tests must use the legacy per-dest staging strategy"
        );
    }

    #[test]
    fn rc22_partial_dir_for_is_legacy_under_cfg_test() {
        // Pin the contract: in tests, partial_dir_for hands back the
        // rc.19 per-dest layout regardless of platform. The actual
        // staging-strategy-flag lock is `STAGE_IN_PROGRAMDATA`.
        let dest = std::path::Path::new("C:\\some\\dest");
        let got = partial_dir_for(dest, "abc-123");
        let want = dest.join(".roomler-partial").join("abc-123");
        assert_eq!(got, want);
    }

    #[test]
    fn rc22_is_cross_volume_error_recognises_kind() {
        // The portable case — Rust's ErrorKind::CrossesDevices (stable
        // 1.85+) directly maps to ERROR_NOT_SAME_DEVICE / EXDEV.
        let e = std::io::Error::from(std::io::ErrorKind::CrossesDevices);
        assert!(
            is_cross_volume_error(&e),
            "ErrorKind::CrossesDevices must be cross-volume"
        );
    }

    #[test]
    fn rc22_is_cross_volume_error_recognises_raw_os_error() {
        // Belt-and-suspenders for cases where ErrorKind didn't get
        // mapped (older runtimes / unusual error sources). Platform-
        // specific raw codes catch the gap.
        #[cfg(target_os = "windows")]
        {
            let e = std::io::Error::from_raw_os_error(17);
            assert!(
                is_cross_volume_error(&e),
                "Windows raw os error 17 must be cross-volume"
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            let e = std::io::Error::from_raw_os_error(18);
            assert!(
                is_cross_volume_error(&e),
                "Unix raw errno 18 must be cross-volume"
            );
        }
    }

    #[test]
    fn rc22_is_cross_volume_error_rejects_unrelated() {
        let e = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(
            !is_cross_volume_error(&e),
            "NotFound must not be misclassified as cross-volume"
        );
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(
            !is_cross_volume_error(&e),
            "PermissionDenied must not be misclassified as cross-volume"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rc22_staging_root_windows_under_programdata() {
        // Pin the path shape so an accidental edit (joining the wrong
        // component, e.g. uploads/ instead of staging/) fails this
        // test. Both halves matter — the prefix is the PROGRAMDATA
        // root that ESET is hypothesised to treat differently from
        // user Downloads; the suffix names what's there.
        let root = staging_root_windows();
        let s = root.to_string_lossy().to_lowercase();
        assert!(
            s.contains("programdata") || s.contains("c:\\"),
            "staging root must live under ProgramData: {}",
            root.display()
        );
        // S1b: either segment is valid — `roomler` on fresh/migrated
        // machines, legacy `roomler-agent` pre-migration.
        assert!(
            s.ends_with("roomler\\roomler-agent\\staging")
                || s.ends_with("roomler/roomler-agent/staging")
                || s.ends_with("roomler\\roomler\\staging")
                || s.ends_with("roomler/roomler/staging"),
            "staging root must end in roomler\\<segment>\\staging: {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn rc22_sweep_orphans_dir_handles_flat_layout() {
        // The new sweep_orphans_dir helper scans a directory whose
        // CHILDREN are per-id staging dirs — used when PROGRAMDATA
        // staging is active and there's no `.roomler-partial` parent.
        // This test mirrors `sweep_orphans_deletes_stale_and_keeps_fresh`
        // but writes the partials directly under the root instead of
        // under root/.roomler-partial/.
        let root = std::env::temp_dir().join(format!(
            "roomler-rc22-flat-{}-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            std::process::id()
        ));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let now = chrono::Utc::now().timestamp();
        let mk = |id: &str, age_secs: i64| {
            let dir = root.join(id);
            let meta = PartialMeta {
                protocol_version: 1,
                filename: format!("{id}.bin"),
                expected_size: 100,
                dest_dir: root.clone(),
                reserved_final_path: root.join(format!("{id}.bin")),
                created_at_unix: now - age_secs,
                rel_path: None,
            };
            (dir, meta)
        };
        let (stale_dir, stale_meta) = mk("rc22-stale", 25 * 3600);
        let (fresh_dir, fresh_meta) = mk("rc22-fresh", 3600);
        for (dir, meta) in [
            (stale_dir.clone(), stale_meta),
            (fresh_dir.clone(), fresh_meta),
        ] {
            tokio::fs::create_dir_all(&dir).await.unwrap();
            tokio::fs::write(
                dir.join("meta.json"),
                serde_json::to_vec_pretty(&meta).unwrap(),
            )
            .await
            .unwrap();
            tokio::fs::write(dir.join("data"), b"").await.unwrap();
        }
        let (kept, swept) = sweep_orphans_root(&root).await;
        assert_eq!(swept, 1, "should sweep the 25h-old dir");
        assert_eq!(kept, 1, "should keep the 1h-old dir");
        assert!(!stale_dir.exists());
        assert!(fresh_dir.exists());
        let _ = tokio::fs::remove_dir_all(&root).await;
    }
}
// RETIRED-NAME-ANCHOR-END

/// FR-97 P3d — a received file on a Linux system install, written as the
/// person at seat0. The identity half needs root: CI runs this module under
/// sudo with `ROOMLERD_TEST_REQUIRE_ROOT`, so it cannot pass by skipping.
/// `xdg_download_dir` is pure and runs everywhere.
#[cfg(test)]
mod seat_user_tests {
    use super::*;

    #[test]
    fn the_xdg_download_dir_is_taken_only_inside_home() {
        let home = std::path::Path::new("/home/ana");
        let pick = |text: &str| xdg_download_dir(text, home);
        assert_eq!(
            pick("XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n"),
            Some(home.join("Downloads"))
        );
        assert_eq!(
            pick(
                "# written by xdg-user-dirs-update\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOWNLOAD_DIR=\"$HOME/Téléchargements\"\n"
            ),
            Some(home.join("Téléchargements"))
        );
        assert_eq!(
            pick("XDG_DOWNLOAD_DIR=\"/home/ana/dl\""),
            Some(home.join("dl"))
        );
        // The file is the person's to write, so it may name anything: only a
        // folder inside their home is taken.
        assert_eq!(pick("XDG_DOWNLOAD_DIR=\"/etc\""), None);
        assert_eq!(pick("XDG_DOWNLOAD_DIR=\"$HOME/../bob\""), None);
        assert_eq!(
            pick("XDG_DOWNLOAD_DIR=\"$HOME/\""),
            None,
            "the home itself means unset"
        );
        assert_eq!(pick(""), None);
    }

    #[cfg(target_os = "linux")]
    mod as_root {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fn root() -> bool {
            // SAFETY: reads our own credentials.
            let root = unsafe { libc::geteuid() } == 0;
            if !root && std::env::var_os("ROOMLERD_TEST_REQUIRE_ROOT").is_some() {
                panic!("ROOMLERD_TEST_REQUIRE_ROOT is set and this test is not running as root");
            }
            root
        }

        /// A home `nobody` owns, as a person's is theirs.
        fn nobodys_home() -> (tempfile::TempDir, crate::fs_identity::Account) {
            let person =
                crate::fs_identity::Account::by_name("nobody").expect("the `nobody` account");
            let home = tempfile::tempdir().unwrap();
            std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            std::os::unix::fs::chown(home.path(), Some(person.uid), Some(person.gid)).unwrap();
            (home, person)
        }

        fn as_person(person: &crate::fs_identity::Account, home: &std::path::Path) -> FsAs {
            FsAs::Person {
                account: person.clone(),
                home: home.to_path_buf(),
            }
        }

        /// The file is born the person's, in their folder, and nothing of the
        /// staging is left. 0.4.143 wrote it `root:root` into `/tmp` (FR-97
        /// §8, P3d's red).
        #[tokio::test]
        async fn a_received_file_is_born_the_persons() {
            if !root() {
                return;
            }
            let (home, person) = nobodys_home();
            let h = FilesHandler::new();
            let id = format!("p3d-born-{}", std::process::id());
            h.begin_as(
                as_person(&person, home.path()),
                id.clone(),
                "probe.txt".into(),
                5,
                None,
                None,
            )
            .await
            .expect("begin as the person");
            h.chunk(b"hello").await.expect("chunk");
            let (path, bytes) = h.end(&id).await.expect("end");
            assert_eq!(bytes, 5);
            assert_eq!(
                path,
                home.path().join("probe.txt"),
                "no Downloads: their home"
            );
            let md = std::fs::metadata(&path).unwrap();
            assert_eq!(
                (md.uid(), md.gid()),
                (person.uid, person.gid),
                "born the person's"
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"hello");
            assert!(
                !home.path().join(".roomler-partial").exists(),
                "the staging is gone"
            );
        }

        /// A link the person planted where the staging goes is followed with
        /// THEIR rights: into a folder only root may write, the begin is
        /// refused and nothing lands there. The control: root's own rights go
        /// straight through the same link.
        #[tokio::test]
        async fn a_link_in_the_persons_folder_gets_only_the_persons_rights() {
            if !root() {
                return;
            }
            let (home, person) = nobodys_home();
            let roots_only = tempfile::tempdir().unwrap();
            std::fs::set_permissions(roots_only.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let link = home.path().join(".roomler-partial");
            std::os::unix::fs::symlink(roots_only.path(), &link).unwrap();
            std::os::unix::fs::lchown(&link, Some(person.uid), Some(person.gid)).unwrap();

            // The control: as root, the planted link leads straight in.
            let probe = link.join("root-probe");
            std::fs::create_dir(&probe).expect("root creates through the planted link");
            std::fs::remove_dir(&probe).unwrap();

            let h = FilesHandler::new();
            let id = format!("p3d-link-{}", std::process::id());
            let err = h
                .begin_as(
                    as_person(&person, home.path()),
                    id,
                    "probe.txt".into(),
                    5,
                    None,
                    None,
                )
                .await
                .expect_err("the person cannot write where the link leads");
            assert!(format!("{err:#}").contains("Permission denied"), "{err:#}");
            assert_eq!(
                std::fs::read_dir(roots_only.path()).unwrap().count(),
                0,
                "nothing landed in root's folder"
            );
        }

        /// Their Downloads when they have one, and the folder their own
        /// `user-dirs.dirs` names when it names one.
        #[tokio::test]
        async fn the_persons_downloads_is_theirs_to_name() {
            if !root() {
                return;
            }
            let (home, person) = nobodys_home();
            let theirs = |p: &std::path::Path| {
                std::fs::create_dir_all(p).unwrap();
                std::os::unix::fs::chown(p, Some(person.uid), Some(person.gid)).unwrap();
            };
            let who = as_person(&person, home.path());
            assert_eq!(
                download_dir_for(&who).await.unwrap(),
                home.path().to_path_buf()
            );
            theirs(&home.path().join("Downloads"));
            assert_eq!(
                download_dir_for(&who).await.unwrap(),
                home.path().join("Downloads")
            );
            theirs(&home.path().join(".config"));
            theirs(&home.path().join("Fichiers"));
            std::fs::write(
                home.path().join(".config/user-dirs.dirs"),
                "XDG_DOWNLOAD_DIR=\"$HOME/Fichiers\"\n",
            )
            .unwrap();
            assert_eq!(
                download_dir_for(&who).await.unwrap(),
                home.path().join("Fichiers")
            );
        }
    }
}
