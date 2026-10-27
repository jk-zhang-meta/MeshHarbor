// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — where a recording goes.
//!
//! **The default folder**, per user: Windows `Videos\Roomler` *only if* that
//! folder is local, not inside a cloud-sync root, and survives a real
//! create + write + delete probe — Defender's Controlled Folder Access lets
//! `metadata()` succeed and then blocks the write, and OneDrive's Known Folder
//! Move would upload gigabytes of screen recordings by default. Otherwise
//! `%USERPROFILE%\Roomler Recordings`. macOS `~/Movies/Roomler`; Linux the XDG
//! videos dir + `Roomler`. The reason for a fallback is carried to the UI.
//!
//! **The override** (`record_dir`) is validated by [`validate_record_dir`]: an
//! absolute local path, no `~`, no UNC or `\\?\` device path, no `..`, and no
//! symlink or junction in the part of the path a user controls.
//!
//! **The write rule.** The recorder writes into a folder only as that folder's
//! user (the identity rule — it runs as the console user at normal integrity),
//! staging in `<dir>/.roomler-partial/` and renaming on finish. When the folder
//! refuses the write (CFA, a folder policy, the Linux user unit's sandbox) it
//! falls back — the default folder, then `~/Roomler Recordings`, then its own
//! data dir — and the Recordings view says why.
//!
//! FR-85 P2c — the Linux user unit (`meshharbor.service`) runs the daemon with
//! `ProtectHome=read-only`; it lists `~/Videos` as writable, so the default
//! folder works there, and a folder anywhere else is named as the sandbox's
//! ([`sandboxed`]). Moving a finished file from the data dir into the chosen
//! folder as the person (roomler-desktop) was weighed and deferred: built only
//! if people ask for it (the operator, 2026-09-26).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The `record_dir` rules are shared with the config surface and
/// roomler-desktop, so they live in `roomler-node-core`.
pub use roomler_node_core::recording_dir::{link_component, validate_record_dir};

/// The folder recordings go to, and why it is that one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderChoice {
    pub dir: PathBuf,
    /// Why the preferred folder was not used, for the UI. `None` = it was.
    pub reason: Option<String>,
}

/// Name of the in-folder staging directory.
pub const PARTIAL_DIR: &str = ".roomler-partial";
/// Suffix of a recording still being written.
pub const PARTIAL_SUFFIX: &str = ".partial";

/// The recorder's own data dir (`…/recordings`), used when the destination
/// folder refuses the write. Local, never roaming: a roaming profile would
/// sync gigabytes at logoff.
pub fn data_dir() -> Option<PathBuf> {
    roomler_node_core::appdirs::project_dirs().map(|p| p.data_local_dir().join("recordings"))
}

/// FR-85 P1f — where an UNATTENDED recording goes (a service with nobody
/// signed in): the daemon's own folder, never a person's. The machine-global
/// tree on Windows (`%PROGRAMDATA%`, where the service's config lives too),
/// the daemon's own data dir elsewhere.
pub fn unattended_default() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        Some(roomler_node_core::appdirs::machine_global_dir().join("recordings"))
    }
    #[cfg(not(windows))]
    {
        data_dir()
    }
}

/// Create `dir` if it is missing and lock it to the service side: a
/// protected DACL of SYSTEM and Administrators on Windows (`%PROGRAMDATA%`
/// would otherwise hand Users read), the daemon's own account alone (0700)
/// elsewhere. Applied at every use, so a folder someone loosened is
/// tightened again before a recording goes in. A link anywhere on the path
/// is refused, never followed: a service writing through a link someone
/// planted is the primitive the identity rule exists to prevent.
pub fn prepare_unattended(dir: &Path) -> Result<()> {
    if let Some(link) = link_component(dir) {
        anyhow::bail!(
            "{} is a symbolic link or junction: an unattended recording is never written through one",
            link.display()
        );
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let meta = std::fs::symlink_metadata(dir).with_context(|| format!("{}", dir.display()))?;
    if !meta.file_type().is_dir() {
        anyhow::bail!("{} is not a plain folder", dir.display());
    }
    #[cfg(windows)]
    super::launch::win::lock_to_service_accounts(dir).map_err(anyhow::Error::msg)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("locking {}", dir.display()))?;
    }
    Ok(())
}

/// Resolve the folder for the next recording: `configured` when set and
/// usable, otherwise the per-OS default. Never fails outright — the last
/// resort is the recorder's own data dir.
pub fn resolve(configured: Option<&Path>) -> FolderChoice {
    if let Some(dir) = configured {
        match ensure_writable(dir) {
            Ok(()) => {
                return FolderChoice {
                    dir: dir.to_path_buf(),
                    reason: None,
                };
            }
            Err(e) => {
                let fallback = default_choice();
                let why = match sandboxed(&e) {
                    Some(sandbox) => format!(": it is {sandbox}"),
                    None => format!(" ({e:#})"),
                };
                return FolderChoice {
                    dir: fallback.dir,
                    reason: Some(format!(
                        "the configured folder {} is not writable{why}; using {}",
                        dir.display(),
                        fallback
                            .reason
                            .as_deref()
                            .map(|r| format!("the fallback — {r}"))
                            .unwrap_or_else(|| "the default".into())
                    )),
                };
            }
        }
    }
    default_choice()
}

/// FR-85 P2c — the words for a test write the SERVICE'S SANDBOX refused.
///
/// A read-only file system on Linux is, in practice, the user unit's
/// sandbox (`meshharbor.service`: `ProtectHome=read-only`, with only the
/// daemon's own folders and `~/Videos` writable), so the Recordings view
/// names it as that rather than showing "Read-only file system (os error
/// 30)", which tells nobody what to do. `None` for any other refusal, which
/// keeps its own words. Nothing else in the rule changes: the recording
/// still falls back, and the view shows the reason beside the folder.
pub fn sandboxed(e: &anyhow::Error) -> Option<&'static str> {
    let read_only = e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::ReadOnlyFilesystem)
    });
    (cfg!(target_os = "linux") && read_only).then_some(
        "read-only for the Roomler service (on a Linux desktop it runs sandboxed: it can write \
         only in ~/Videos and its own folders)",
    )
}

fn default_choice() -> FolderChoice {
    let home = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf());
    let videos = directories::UserDirs::new().and_then(|u| u.video_dir().map(Path::to_path_buf));
    let preferred = videos.map(|v| v.join("Roomler"));
    let alt = home.as_ref().map(|h| h.join("Roomler Recordings"));

    // Why the preferred folder was passed over — or it is the answer.
    let passed_over = match &preferred {
        Some(p) => match cloud_synced_reason(p) {
            Some(why) => why,
            None => match ensure_writable(p) {
                Ok(()) => {
                    return FolderChoice {
                        dir: p.clone(),
                        reason: None,
                    };
                }
                Err(e) => match sandboxed(&e) {
                    Some(sandbox) => format!("{} is {sandbox}", p.display()),
                    None => format!(
                        "{} refused a test write ({e:#}) — Controlled Folder Access, or a folder \
                         policy",
                        p.display()
                    ),
                },
            },
        },
        None => "this account has no Videos folder".into(),
    };
    if let Some(alt) = alt
        && ensure_writable(&alt).is_ok()
    {
        return FolderChoice {
            dir: alt,
            reason: Some(passed_over),
        };
    }
    let dir = data_dir().unwrap_or_else(std::env::temp_dir);
    FolderChoice {
        dir,
        // What passed the preferred folder over still says WHY: on a
        // sandboxed Linux service that is the one sentence that names the
        // cause (P2c: a localized Videos folder lands here).
        reason: Some(format!(
            "{passed_over}; no other folder of yours accepted a test write either, so the \
             recorder's own data folder"
        )),
    }
}

/// Why a folder must not be the DEFAULT: it sits inside a cloud-sync root or
/// on a network share. `None` = local.
pub fn cloud_synced_reason(dir: &Path) -> Option<String> {
    let roots: Vec<PathBuf> = ["OneDrive", "OneDriveCommercial", "OneDriveConsumer"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect();
    cloud_synced_reason_in(dir, &roots)
}

/// [`cloud_synced_reason`] against explicit sync roots (testable without
/// touching the process environment).
fn cloud_synced_reason_in(dir: &Path, sync_roots: &[PathBuf]) -> Option<String> {
    let s = dir.to_string_lossy();
    if s.starts_with(r"\\") {
        return Some(format!("{} is on a network share", dir.display()));
    }
    sync_roots
        .iter()
        .find(|root| !root.as_os_str().is_empty() && starts_with_ci(dir, root))
        .map(|root| {
            format!(
                "Videos is inside OneDrive ({}) — recordings would be uploaded",
                root.display()
            )
        })
}

fn starts_with_ci(path: &Path, prefix: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    let q = prefix.to_string_lossy().to_lowercase();
    let q = q.trim_end_matches(['\\', '/']);
    p == q || p.starts_with(&format!("{q}\\")) || p.starts_with(&format!("{q}/"))
}

/// Create `dir` if needed and prove it accepts a write: create a unique probe
/// file with `create_new`, write a byte, sync, delete. `metadata()` is not
/// evidence — Controlled Folder Access answers it and then refuses the write.
pub fn ensure_writable(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let probe = dir.join(format!(
        ".roomler-write-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let result = (|| -> std::io::Result<()> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        f.write_all(b"r")?;
        f.sync_all()
    })();
    let _ = std::fs::remove_file(&probe);
    result.with_context(|| format!("test write in {}", dir.display()))
}

/// The file name for a recording started at `now` (local time), made unique
/// in `dir` by appending ` (2)`, ` (3)`, … — a recording never replaces
/// another one.
pub fn unique_recording_name(dir: &Path, now: chrono::DateTime<chrono::Local>) -> String {
    let stem = format!("Roomler Recording {}", now.format("%Y-%m-%d %H-%M-%S"));
    let taken = |name: &str| {
        dir.join(name).exists()
            || dir
                .join(PARTIAL_DIR)
                .join(format!("{name}{PARTIAL_SUFFIX}"))
                .exists()
    };
    let first = format!("{stem}.mp4");
    if !taken(&first) {
        return first;
    }
    (2u32..)
        .map(|n| format!("{stem} ({n}).mp4"))
        .find(|n| !taken(n))
        .unwrap_or(first)
}

/// Bytes free on the volume holding `dir` (the longest mount point that
/// prefixes its canonical path). `None` when it cannot be told.
pub fn available_space(dir: &Path) -> Option<u64> {
    let canon = std::fs::canonicalize(dir).ok()?;
    let canon = strip_verbatim(&canon);
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|d| starts_with_ci(&canon, d.mount_point()) || canon.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| d.available_space())
}

/// `\\?\C:\x` → `C:\x`, so a canonical Windows path compares with a mount
/// point.
fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => p.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "roomler-fr85-folder-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// P1f — the unattended folder is made, locked to the daemon (0700), and
    /// tightened again when someone loosened it; a link on its path is
    /// refused, never followed.
    #[cfg(unix)]
    #[test]
    fn the_unattended_folder_is_made_locked_and_never_reached_through_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch("unattended");
        let dir = base.join("recordings");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        prepare_unattended(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        prepare_unattended(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700, "a loosened folder is tightened again");

        let target = base.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = base.join("linked");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(prepare_unattended(&link.join("recordings")).is_err());
        assert!(
            !target.join("recordings").exists(),
            "the folder was made through the link"
        );
    }

    #[test]
    fn a_writable_folder_passes_the_probe_and_keeps_nothing() {
        let d = scratch("probe");
        ensure_writable(&d).unwrap();
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            0,
            "the probe file is removed"
        );
    }

    #[test]
    fn the_probe_creates_a_missing_folder() {
        let d = scratch("create").join("a").join("b");
        ensure_writable(&d).unwrap();
        assert!(d.is_dir());
    }

    // The `record_dir` validator's own tests live with it, in
    // `roomler_node_core::recording_dir`.

    #[test]
    fn names_never_collide() {
        let d = scratch("names");
        let now = chrono::Local::now();
        let a = unique_recording_name(&d, now);
        std::fs::write(d.join(&a), b"x").unwrap();
        let b = unique_recording_name(&d, now);
        assert_ne!(a, b);
        assert!(b.ends_with(" (2).mp4"), "{b}");
        // A partial with the next name also counts as taken.
        std::fs::create_dir_all(d.join(PARTIAL_DIR)).unwrap();
        std::fs::write(
            d.join(PARTIAL_DIR).join(format!("{b}{PARTIAL_SUFFIX}")),
            b"x",
        )
        .unwrap();
        let c = unique_recording_name(&d, now);
        assert!(c.ends_with(" (3).mp4"), "{c}");
    }

    #[test]
    fn a_onedrive_folder_is_not_a_default() {
        let root = PathBuf::from(r"C:\Users\someone\OneDrive - Contoso");
        let inside = root.join("Videos").join("Roomler");
        assert!(cloud_synced_reason_in(&inside, std::slice::from_ref(&root)).is_some());
        // Case-insensitive, as Windows paths are.
        let upper = PathBuf::from(r"C:\USERS\SOMEONE\ONEDRIVE - CONTOSO\Videos");
        assert!(cloud_synced_reason_in(&upper, std::slice::from_ref(&root)).is_some());
        // A sibling that merely shares a prefix is not inside it.
        let sibling = PathBuf::from(r"C:\Users\someone\OneDrive - Contoso Archive\Videos");
        assert!(cloud_synced_reason_in(&sibling, std::slice::from_ref(&root)).is_none());
        assert!(cloud_synced_reason_in(Path::new(r"C:\Users\someone\Videos"), &[root]).is_none());
    }

    #[test]
    fn a_network_share_is_not_a_default() {
        assert!(cloud_synced_reason_in(Path::new(r"\\nas\videos\Roomler"), &[]).is_some());
    }

    #[test]
    fn a_configured_folder_that_refuses_writes_falls_back_with_a_reason() {
        // A FILE where a folder is expected cannot be created or written into.
        let d = scratch("fallback");
        let not_a_dir = d.join("file");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let choice = resolve(Some(&not_a_dir));
        assert_ne!(choice.dir, not_a_dir);
        assert!(choice.reason.unwrap().contains("not writable"));
    }

    /// FR-85 P2c — a folder the service's sandbox keeps read-only is NAMED
    /// as that (on Linux, where the user unit is the sandbox), and every
    /// other refusal keeps its own words. Red when the sandbox is not
    /// recognised: the view then shows only "Read-only file system".
    #[test]
    fn a_read_only_folder_is_named_as_the_services_sandbox() {
        let erofs =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem))
                .context("test write in /home/someone/Desktop/rec");
        let denied = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("test write in /home/someone/Desktop/rec");
        if cfg!(target_os = "linux") {
            let why = sandboxed(&erofs).expect("a read-only file system is the sandbox");
            assert!(
                why.contains("Roomler service") && why.contains("~/Videos"),
                "{why}"
            );
        } else {
            assert_eq!(
                sandboxed(&erofs),
                None,
                "only the Linux user unit sandboxes"
            );
        }
        assert_eq!(sandboxed(&denied), None, "a refusal of another kind");
    }

    #[test]
    fn free_space_is_reported_for_a_real_folder() {
        let d = scratch("space");
        assert!(available_space(&d).is_some_and(|b| b > 0));
    }
}
