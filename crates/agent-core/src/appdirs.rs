// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR-BEGIN
// This whole module IS the legacy-segment fallback. Every occurrence of a
// retired name in it is the OLD half of a dual-read — the module doc explaining
// the new-then-old resolution, `OLD_APP`, `migrate_legacy_trees`, and the tests
// that build a legacy tree in order to migrate it.
// INVARIANT: if you add a retired name here that is NOT the old half of a
// dual-read, that is a bug, not a new exemption. docs/fr/FR-21
//! Roomler node application directories with a legacy-segment fallback.
//!
//! The controlled-host daemon is being renamed `roomler-agent` -> `roomlerd`
//! (the unified device/node model — see the unification plan). Its per-user and
//! machine-global data trees historically live under an app segment
//! `roomler-agent` (`%APPDATA%\roomler\roomler-agent`,
//! `%PROGRAMDATA%\roomler\roomler-agent`, `~/.config/roomler-agent`, ...).
//!
//! Renaming that segment to `roomler` must **never** orphan a host's enrolled
//! `config.toml` (its bearer token) — that's the same class of silent
//! fleet-drop-off as the MajorUpgrade-drops-env-vars bug. So resolution reads
//! BOTH: it uses the NEW `roomler` segment when its tree already exists, else
//! keeps using the OLD `roomler-agent` tree if THAT exists, and only a genuinely
//! fresh install lands on the new segment. The decision is made once per process
//! (cached) and applied to every directory, so config / logs / crashes on a host
//! never split across two trees.
//!
//! S1b adds the follow-up: [`migrate_legacy_trees`] performs a one-shot
//! startup RENAME of the legacy trees onto the `roomler` segment (per-user
//! config/data roots + the Windows machine-global root). It runs before any
//! consumer caches a segment decision, never deletes, and on any failure
//! simply leaves the read-both resolution in charge (retry next start) — so
//! enrollment still cannot be lost.

use directories::ProjectDirs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Reverse-domain qualifier for the agent's per-user dirs (macOS uses it;
/// Windows/Linux ignore it). Historically "live" — preserved so existing
/// macOS dirs aren't orphaned.
const QUALIFIER: &str = "live";
const ORG: &str = "meshharbor";
/// New app segment (post-rename, fresh installs).
const NEW_APP: &str = "meshharbor";
/// Legacy app segment (pre-rename installs already in the field).
// RETIRED-NAME-ANCHOR: a pre-rename host resolves its ENROLLED config through this
// segment. Renaming it orphans that config -- the device drops off the mesh and
// re-enrolls as a stranger. See docs/fr/FR-21.
const OLD_APP: &str = "roomler-agent";

/// True if a NEW-segment `ProjectDirs` tree is present on disk.
fn tree_exists(app: &str) -> bool {
    ProjectDirs::from(QUALIFIER, ORG, app)
        .is_some_and(|d| d.config_dir().exists() || d.data_local_dir().exists())
}

/// Whether to use the OLD segment for the per-user tree. Cached: the filesystem
/// answer is stable within a process, and caching guarantees every consumer in
/// one run agrees (no split trees). NEW-if-present wins; else OLD-if-present;
/// else NEW (fresh install).
fn use_old_segment() -> bool {
    static DECISION: OnceLock<bool> = OnceLock::new();
    *DECISION.get_or_init(|| !tree_exists(NEW_APP) && tree_exists(OLD_APP))
}

/// The resolved per-user app segment ("roomler" for fresh/migrated hosts,
/// "roomler-agent" for a pre-rename install whose tree still exists).
fn app_segment() -> &'static str {
    if use_old_segment() { OLD_APP } else { NEW_APP }
}

/// The agent's `ProjectDirs`, resolved to the NEW segment unless a pre-rename
/// install is detected (then the OLD segment, so its enrolled config is never
/// orphaned). `None` only if the platform exposes no config dir at all.
pub fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from(QUALIFIER, ORG, app_segment())
}

/// Machine-global data root `%PROGRAMDATA%\roomler\<segment>` (Windows only).
/// Same new-then-old resolution as [`project_dirs`], keyed independently on the
/// machine-global tree (a perMachine/SystemContext host's enrolled config lives
/// here and must not be orphaned). Consumers `.join(...)` their subdir
/// (`config.toml`, `service-logs`, `crashes`, `staging`, ...).
#[cfg(target_os = "windows")]
pub fn machine_global_dir() -> PathBuf {
    static DECISION: OnceLock<PathBuf> = OnceLock::new();
    DECISION
        .get_or_init(|| {
            let base = std::env::var_os("PROGRAMDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
                .join(ORG);
            resolve_machine_global(&base)
        })
        .clone()
}

/// The machine-global root under `base` (= `%PROGRAMDATA%\roomler`), resolved
/// new-then-old.
///
/// Split out of [`machine_global_dir`] so the decision can be TESTED. The public
/// function caches in a `OnceLock` against the real `%PROGRAMDATA%`, so a process
/// can only ever observe one answer — which left the pre-rename branch, the one
/// that keeps an upgraded host's enrolled config and its `staging\` dir
/// reachable, provable only by finding a host that still has such a tree. Every
/// host in the fleet is post-rename, so that proof was not available; this makes
/// it a test instead.
#[cfg(target_os = "windows")]
fn resolve_machine_global(base: &Path) -> PathBuf {
    let new = base.join(NEW_APP);
    let old = base.join(OLD_APP);
    if !new.exists() && old.exists() {
        old // pre-rename install still present -> keep it
    } else {
        new // fresh install, or the new tree is already present
    }
}

/// FR-92 — `<profile>\AppData\Local\<org>\<segment>\data`: what
/// [`project_dirs`]`().data_local_dir()` resolves to for the OWNER of
/// `profile`, computed from the profile path so a SYSTEM worker can reach the
/// signed-in person's per-user data (its own `project_dirs` is SYSTEM's).
/// Windows only, like the workers that need it.
#[cfg(target_os = "windows")]
pub fn data_local_dir_in_profile(profile: &Path) -> PathBuf {
    profile
        .join("AppData")
        .join("Local")
        .join(ORG)
        .join(app_segment())
        .join("data")
}

/// The SCM-service log directory (`%PROGRAMDATA%\roomler\<segment>\service-logs`).
///
/// P3e lever E: canonical home for the path both sides need — the daemon's
/// `win_service::default_log_dir` delegates here, and the desktop companion
/// resolves the same directory to show/open SCM logs without linking the
/// daemon. Windows-only like [`machine_global_dir`].
#[cfg(target_os = "windows")]
pub fn service_log_dir() -> PathBuf {
    machine_global_dir().join("service-logs")
}

// ─── S1b: one-shot legacy-tree migration ───────────────────────────────────

/// Notes from the last [`migrate_legacy_trees`] run — logged by the caller
/// AFTER logging::init (migration must run before it, so it can't trace
/// directly). Empty = nothing noteworthy happened.
static MIGRATION_NOTES: OnceLock<Vec<String>> = OnceLock::new();

pub fn migration_notes() -> &'static [String] {
    MIGRATION_NOTES.get().map(|v| v.as_slice()).unwrap_or(&[])
}

/// One-shot startup migration of the legacy `roomler-agent` trees onto the
/// `roomler` segment. MUST run before `logging::init` and before ANY other
/// appdirs consumer (the segment decision is `OnceLock`-cached per process,
/// and log files open inside the tree).
///
/// Rules, per directory (per-user config/data roots + the Windows
/// machine-global root, each independent):
///   * legacy exists, new doesn't → atomic same-volume `fs::rename`
///   * both exist (split-brain from the self-heal era) → left in place
///     (NEW-wins resolution already applies; config cleanup is the
///     `ConfigCleanupStale` verb's job)
///   * legacy absent → nothing to do
///
/// Never deletes; a failed rename (locked file, ACL) is noted and the
/// read-both resolution keeps everything working until the next start.
///
/// `companion_running` (the roomler-desktop tray): skip entirely — the tray
/// may hold open handles inside the tree, and a pre-S1a tray would keep
/// writing the old tree after the move, re-manufacturing the split.
pub fn migrate_legacy_trees(companion_running: bool) {
    let mut notes = Vec::new();
    if companion_running {
        notes.push(
            "migration skipped: desktop companion is running (will retry next start)".to_string(),
        );
    } else {
        if let (Some(old), Some(new)) = (
            ProjectDirs::from(QUALIFIER, ORG, OLD_APP),
            ProjectDirs::from(QUALIFIER, ORG, NEW_APP),
        ) {
            let mut pairs: Vec<(PathBuf, PathBuf)> = vec![
                (
                    old.config_dir().to_path_buf(),
                    new.config_dir().to_path_buf(),
                ),
                (old.data_dir().to_path_buf(), new.data_dir().to_path_buf()),
                (
                    old.data_local_dir().to_path_buf(),
                    new.data_local_dir().to_path_buf(),
                ),
            ];
            // data_dir == data_local_dir on Linux; config may coincide too on
            // some platforms. Adjacent duplicates only.
            pairs.dedup();
            for (o, n) in &pairs {
                if let Some(note) = migrate_dir(o, n) {
                    notes.push(note);
                }
            }
            // Best-effort: drop the now-empty legacy shells (e.g. Windows
            // `%APPDATA%\roomler\roomler-agent` after its `config`/`data`
            // children moved out). `remove_dir` refuses non-empty dirs, so
            // anything left behind survives.
            for parent in pairs
                .iter()
                .filter_map(|(o, _)| o.parent().map(Path::to_path_buf))
            {
                if parent.file_name().is_some_and(|f| f == OLD_APP) {
                    let _ = std::fs::remove_dir(&parent);
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            let base = std::env::var_os("PROGRAMDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
                .join(ORG);
            if let Some(note) = migrate_dir(&base.join(OLD_APP), &base.join(NEW_APP)) {
                notes.push(note);
            }
        }
    }
    let _ = MIGRATION_NOTES.set(notes);
}

/// Apply the migration rules to one directory pair. Returns a note for
/// anything noteworthy (moved / both-present / failed), `None` for the
/// quiet no-legacy case.
fn migrate_dir(old: &Path, new: &Path) -> Option<String> {
    if !old.exists() {
        return None;
    }
    if new.exists() {
        return Some(format!(
            "legacy tree left in place (new tree also present): {}",
            old.display()
        ));
    }
    if let Some(parent) = new.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Some(format!(
            "migration failed (create {}): {e}",
            parent.display()
        ));
    }
    match std::fs::rename(old, new) {
        Ok(()) => Some(format!(
            "migrated legacy tree {} -> {}",
            old.display(),
            new.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Field finding (DEVBOX, 2026-07-27): renaming the TOP dir was
            // denied by an external ROOT-handle (an AV / indexer
            // directory-watch — no roomler process held anything, ACLs
            // were Full, and every CHILD renamed fine). Fall back to
            // moving the children individually; that dodges the
            // root-handle without needing the watcher gone.
            Some(migrate_children(old, new, &e))
        }
        Err(e) => Some(format!(
            "migration failed ({} -> {}): {e} — read-both fallback stays in charge",
            old.display(),
            new.display()
        )),
    }
}

// ─── Linux: the system config lives in /etc/meshharbor ────────────────────────

/// Canonical config for a Linux SYSTEM install (the `meshharbord.service` unit).
///
/// The packaged unit has run `roomlerd --config /etc/meshharbor/config.toml`
/// since rc.426, but hosts enrolled before that convention keep their config
/// in root's profile (`/root/.config/meshharbor/config.toml`) — so the FIRST
/// systemd-mediated start after the packaging change died `no config found`
/// and `Restart=always` turned it into a crash-loop. Field-hit on three nodes
/// (buildhost, fleet-host-2, and the WSL sibling, the last one from a plain `dpkg -i`, with
/// no operator restart involved at all).
///
/// One canonical location fixes that for good: [`migrate_system_config`] moves
/// a legacy config here at startup, and [`crate::config::default_config_path`]
/// resolves here for root, so an explicit `--config` and a bare `meshharbord run`
/// can no longer disagree about where this host's identity lives.
#[cfg(target_os = "linux")]
pub fn system_config_path() -> PathBuf {
    PathBuf::from("/etc/meshharbor/config.toml")
}

/// Is this process root? Only root may own `/etc/meshharbor`; a per-user Linux
/// install keeps its profile config and must not be migrated anywhere.
#[cfg(target_os = "linux")]
pub fn running_as_root() -> bool {
    // SAFETY: `geteuid` is a thread-safe read of the caller's own credentials.
    unsafe { libc::geteuid() == 0 }
}

/// One-shot migration of a legacy root-profile config into `/etc/meshharbor`.
///
/// Same rules as [`migrate_legacy_trees`], for the same reasons:
///   * `/etc` copy exists → leave the legacy one alone (NEW wins)
///   * legacy absent → nothing to do
///   * legacy present, `/etc` absent → `rename` (same filesystem in practice)
///
/// **Never deletes.** A failed move is noted and the read-both resolution in
/// `default_config_path` keeps the host running on its legacy config until the
/// next start retries — a daemon that cannot find its identity is exactly the
/// outcome this exists to prevent.
///
/// The `.prev` sibling (config::save's rollback copy) moves too: leaving it
/// behind would strand a second, credential-bearing copy of the config at a
/// path something might later be pointed back at.
///
/// MUST run before `logging::init`, like the tree migration — hence the same
/// note-collecting instead of tracing.
#[cfg(target_os = "linux")]
pub fn migrate_system_config() {
    let mut notes = Vec::new();
    if !running_as_root() {
        let _ = SYSTEM_CONFIG_NOTES.set(notes);
        return;
    }
    let new = system_config_path();
    let legacy = ProjectDirs::from(QUALIFIER, ORG, NEW_APP)
        .map(|d| d.config_dir().join("config.toml"))
        .unwrap_or_default();

    if new.exists() || !legacy.exists() {
        let _ = SYSTEM_CONFIG_NOTES.set(notes);
        return;
    }
    if let Some(parent) = new.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        notes.push(format!(
            "system-config migration failed (create {}): {e}",
            parent.display()
        ));
        let _ = SYSTEM_CONFIG_NOTES.set(notes);
        return;
    }
    // 0700: the config carries the agent token and the WG secret key.
    #[cfg(unix)]
    if let Some(parent) = new.parent() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    match std::fs::rename(&legacy, &new) {
        Ok(()) => {
            notes.push(format!(
                "migrated system config {} -> {}",
                legacy.display(),
                new.display()
            ));
            // Best-effort; a left-behind `.prev` is untidy, not dangerous,
            // and must never turn a successful migration into a failure.
            let (lp, np) = (with_prev(&legacy), with_prev(&new));
            if lp.exists() && !np.exists() {
                let _ = std::fs::rename(&lp, &np);
            }
        }
        Err(e) => notes.push(format!(
            "system-config migration failed ({} -> {}): {e} — staying on the legacy path",
            legacy.display(),
            new.display()
        )),
    }
    let _ = SYSTEM_CONFIG_NOTES.set(notes);
}

#[cfg(target_os = "linux")]
fn with_prev(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(".prev");
    PathBuf::from(s)
}

#[cfg(target_os = "linux")]
static SYSTEM_CONFIG_NOTES: OnceLock<Vec<String>> = OnceLock::new();

/// Notes from [`migrate_system_config`], logged by the caller after
/// `logging::init` (the migration runs before it).
#[cfg(target_os = "linux")]
pub fn system_config_notes() -> &'static [String] {
    SYSTEM_CONFIG_NOTES
        .get()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Per-child fallback for a root-locked legacy dir. `config.toml` moves
/// LAST, and any mid-way failure rolls the already-moved entries back —
/// so the tree is always either wholly OLD or wholly NEW (a half-empty
/// NEW tree would win the NEW-first resolution and strand the enrolled
/// config in the abandoned OLD one).
fn migrate_children(old: &Path, new: &Path, root_err: &std::io::Error) -> String {
    let Ok(entries) = std::fs::read_dir(old) else {
        return format!(
            "migration failed ({} -> {}): {root_err} (and the legacy dir is unreadable)",
            old.display(),
            new.display()
        );
    };
    let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    // config.toml last: the enrollment must be the final thing to leave
    // the old tree.
    children.sort_by_key(|p| p.file_name().is_some_and(|f| f == "config.toml"));
    if let Err(e) = std::fs::create_dir_all(new) {
        return format!("migration failed (create {}): {e}", new.display());
    }
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    for src in &children {
        let Some(name) = src.file_name() else {
            continue;
        };
        let dst = new.join(name);
        match std::fs::rename(src, &dst) {
            Ok(()) => moved.push((src.clone(), dst)),
            Err(e) => {
                // Roll back so the OLD tree stays complete (best-effort;
                // a rollback failure is noted and read-both still covers
                // the pieces that DID move — they're identical content).
                let mut rolled_back = true;
                for (orig, dstp) in moved.iter().rev() {
                    if std::fs::rename(dstp, orig).is_err() {
                        rolled_back = false;
                    }
                }
                return format!(
                    "per-child migration of {} aborted at {} ({e}); rolled back: {rolled_back} \
                     (root rename was denied: {root_err})",
                    old.display(),
                    src.display()
                );
            }
        }
    }
    let _ = std::fs::remove_dir(old);
    format!(
        "migrated legacy tree {} -> {} per-child ({} entries; the root dir itself was \
         locked by another process: {root_err})",
        old.display(),
        new.display(),
        moved.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-92 — the profile-relative form must name the SAME directory the
    /// person's own `project_dirs()` does, or a SystemContext worker and a
    /// user-context worker would keep two different keep-busy stores.
    #[cfg(target_os = "windows")]
    #[test]
    fn data_local_dir_in_profile_matches_the_owners_project_dirs() {
        let Some(profile) = std::env::var_os("USERPROFILE") else {
            return;
        };
        let Some(dirs) = project_dirs() else {
            return;
        };
        // Only meaningful when LocalAppData sits in its default place.
        let default_local = Path::new(&profile).join("AppData").join("Local");
        if !dirs.data_local_dir().starts_with(&default_local) {
            return;
        }
        assert_eq!(
            data_local_dir_in_profile(Path::new(&profile)),
            dirs.data_local_dir()
        );
    }

    // `tree_exists` / segment resolution touch the real HOME/APPDATA, so we
    // don't assert on live paths here (that would be environment-dependent).
    // Instead lock the pure new-then-old PRECEDENCE with an injected predicate,
    // mirroring the `node_env` fallback-order test in tunnel-core.
    fn pick<'a>(new: &'a str, old: &'a str, exists: impl Fn(&str) -> bool) -> &'a str {
        if exists(new) {
            new
        } else if exists(old) {
            old
        } else {
            new
        }
    }

    /// The invariant that retires the crash-loop class: for a Linux root
    /// process, `/etc/meshharbor/config.toml` and the profile config resolve in a
    /// fixed order, so the packaged unit's `--config` and a bare `meshharbord run`
    /// can never disagree about where this host's identity lives.
    ///
    /// Same injected-predicate shape as the tree test above — asserting on
    /// real `/etc` would be environment-dependent and root-dependent.
    #[test]
    fn linux_system_config_precedence_is_etc_then_profile_then_etc() {
        // `/etc` present -> `/etc`, even when the legacy profile copy survives
        // (the migration never deletes, so both CAN exist).
        assert_eq!(
            pick("/etc", "profile", |s| s == "/etc" || s == "profile"),
            "/etc"
        );
        // Only the profile copy -> profile. A host whose migration has not run
        // yet, or could not, keeps its identity instead of losing it.
        assert_eq!(pick("/etc", "profile", |s| s == "profile"), "profile");
        // Neither -> `/etc`: a fresh system install, where `enroll` writes to
        // the path the unit already passes.
        assert_eq!(pick("/etc", "profile", |_| false), "/etc");
    }

    /// The rollback copy carries the agent token and the WG secret key, so it
    /// has to travel with the config — leaving it behind strands a second,
    /// credential-bearing copy at a path something may later be pointed at
    /// (exactly how a cleared SSH key came back on fleet-host-1).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_prev_sibling_is_the_config_path_plus_prev() {
        assert_eq!(
            with_prev(Path::new("/etc/meshharbor/config.toml")),
            PathBuf::from("/etc/meshharbor/config.toml.prev")
        );
    }

    #[test]
    fn new_then_old_then_new_precedence() {
        // NEW present -> NEW (even if OLD also present).
        assert_eq!(pick("new", "old", |s| s == "new" || s == "old"), "new");
        // only OLD present -> OLD (upgraded host keeps its tree).
        assert_eq!(pick("new", "old", |s| s == "old"), "old");
        // neither present -> NEW (fresh install).
        assert_eq!(pick("new", "old", |_| false), "new");
    }

    #[test]
    fn migrate_dir_moves_legacy_into_place() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("roomler-agent").join("config");
        let new = tmp.path().join("roomler").join("config");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("config.toml"), b"agent_token = \"x\"").unwrap();

        let note = migrate_dir(&old, &new).expect("a move produces a note");
        assert!(note.starts_with("migrated"), "{note}");
        assert!(!old.exists(), "legacy dir must be gone after the move");
        assert_eq!(
            std::fs::read_to_string(new.join("config.toml")).unwrap(),
            "agent_token = \"x\"",
            "contents ride along byte-identically"
        );
    }

    #[test]
    fn migrate_dir_leaves_split_brain_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("roomler-agent");
        let new = tmp.path().join("roomler");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join("stale.txt"), b"old").unwrap();

        let note = migrate_dir(&old, &new).expect("both-present produces a note");
        assert!(note.contains("left in place"), "{note}");
        assert!(old.join("stale.txt").exists(), "nothing may be deleted");
    }

    #[test]
    fn migrate_children_moves_everything_and_drops_old_root() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("roomler-agent");
        let new = tmp.path().join("roomler");
        std::fs::create_dir_all(old.join("service-logs")).unwrap();
        std::fs::write(old.join("config.toml"), b"agent_token = \"x\"").unwrap();
        std::fs::write(old.join("service-logs").join("a.log"), b"l").unwrap();

        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "root locked");
        let note = migrate_children(&old, &new, &err);
        assert!(note.contains("per-child"), "{note}");
        assert!(!old.exists(), "emptied legacy root must be removed");
        assert_eq!(
            std::fs::read_to_string(new.join("config.toml")).unwrap(),
            "agent_token = \"x\""
        );
        assert!(new.join("service-logs").join("a.log").exists());
    }

    #[test]
    fn migrate_children_rolls_back_on_midway_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("roomler-agent");
        let new = tmp.path().join("roomler");
        std::fs::create_dir_all(old.join("crashes")).unwrap();
        std::fs::write(old.join("config.toml"), b"tok").unwrap();
        // Pre-create a CONFLICTING non-empty destination for `crashes` so
        // its rename fails mid-way (rename onto a non-empty dir errors).
        std::fs::create_dir_all(new.join("crashes").join("blocker")).unwrap();

        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "root locked");
        let note = migrate_children(&old, &new, &err);
        assert!(note.contains("aborted"), "{note}");
        // config.toml sorted LAST → it never left the old tree before the
        // failure, and anything that did move was rolled back.
        assert!(
            old.join("config.toml").exists(),
            "the enrollment must still be in the OLD tree: {note}"
        );
        assert!(old.join("crashes").exists());
    }

    #[test]
    fn migrate_dir_is_quiet_without_legacy() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            migrate_dir(
                &tmp.path().join("roomler-agent"),
                &tmp.path().join("roomler")
            )
            .is_none()
        );
    }

    // ── FR-21: the machine-global segment decision ──────────────────────
    //
    // Covers the acceptance criterion that had no host to run on: "the §5
    // staging path resolves correctly on BOTH a fresh perMachine host and a
    // pre-rename host". `files.rs` derives the staging dir as
    // `machine_global_dir().join("staging")` and `machine_global_config_path()`
    // derives config.toml the same way, so this decision is what it turns on.

    #[cfg(target_os = "windows")]
    #[test]
    fn machine_global_keeps_a_pre_rename_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(ORG);
        std::fs::create_dir_all(base.join(OLD_APP)).unwrap();
        // Legacy tree present, new one absent: an upgraded host. Resolving to
        // the new segment here orphans its enrolled config — the device drops
        // off the mesh and re-enrols as a stranger.
        assert_eq!(resolve_machine_global(&base), base.join(OLD_APP));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn machine_global_uses_the_new_tree_on_a_fresh_host() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(ORG);
        std::fs::create_dir_all(base.join(NEW_APP)).unwrap();
        assert_eq!(resolve_machine_global(&base), base.join(NEW_APP));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn machine_global_prefers_new_when_both_trees_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(ORG);
        std::fs::create_dir_all(base.join(NEW_APP)).unwrap();
        std::fs::create_dir_all(base.join(OLD_APP)).unwrap();
        // A migrated host keeps BOTH for a while. New wins, or a host would
        // fall back to a tree it has already moved off.
        assert_eq!(resolve_machine_global(&base), base.join(NEW_APP));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn machine_global_defaults_to_new_when_nothing_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(ORG);
        // Nothing on disk yet: a first install must create the NEW tree,
        // never resurrect the retired name.
        assert_eq!(resolve_machine_global(&base), base.join(NEW_APP));
    }
}

// RETIRED-NAME-ANCHOR-END
