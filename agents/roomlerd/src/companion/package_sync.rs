// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-117 P1 — on Linux the desktop companion's package tracks the daemon.
//!
//! The companion is its own package (`roomler-desktop`, a `.deb`, or an `.rpm`
//! on the hosts with no dpkg: FR-27, FR-93 P6d), installed ONCE by `install.sh`
//! or the wizard from a release asset. There is no apt or dnf repository, so
//! nothing ever upgraded it: `Update all` moved the daemon and left the
//! companion where it was (a Fedora Asahi box read 0.4.147 / 0.4.139 on
//! 2026-10-20). This is the Linux half of what `super::refresh_if_stale` does
//! on Windows: the process that installs updates AS ROOT on this host moves an
//! installed companion package to its OWN version (the companion follows the
//! daemon, not the feed), through the daemon's own verified download, with the
//! host's own package manager, which stays the source of truth.
//!
//! WHO runs it is the updater's decision, not this module's: the root daemon of
//! a system install (`updater::run_periodic`), or the root update helper of a
//! per-user install (`updater::run_update_helper`, FR-96). A per-user daemon,
//! which can install nothing, only wakes its helper ([`needs_sync`]).
//!
//! What it never does (FR-117 D1, D3):
//! - install a companion where none is installed: a headless node stays
//!   headless, and a person who removed it keeps it removed;
//! - downgrade one: a companion NEWER than the daemon is somebody's deliberate
//!   install, and the next daemon update catches up;
//! - prompt for a password: a non-root caller skips, with one log line.
//!
//! The decisions are pure and tested on every platform; the I/O is Linux-only.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::updater::GithubAsset;

/// Which package database owns the companion here. It decides the format of
/// the package that moves it forward: a `.deb` cannot install where rpm keeps
/// the books, nor an `.rpm` where dpkg does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PkgDb {
    Dpkg,
    Rpm,
}

impl PkgDb {
    /// The release asset's extension for this database.
    pub(crate) fn ext(self) -> &'static str {
        match self {
            Self::Dpkg => "deb",
            Self::Rpm => "rpm",
        }
    }
}

/// The version in `dpkg-query -W -f='${Status}|${Version}'`'s answer, but only
/// for a package that is INSTALLED. dpkg also answers for one it merely
/// remembers (removed with its config kept: `deinstall ok config-files`), and
/// that companion must stay removed.
pub(crate) fn dpkg_installed_version(raw: &str) -> Option<&str> {
    let (status, version) = raw.trim().split_once('|')?;
    // `want flag status`: the third word is the package's state.
    (status.split_whitespace().nth(2) == Some("installed"))
        .then_some(version.trim())
        .filter(|v| !v.is_empty())
}

/// What a sync does, decided before it touches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Nothing to do, and why: the kill switch, no companion installed, or a
    /// version that cannot be compared with ours.
    Nothing(&'static str),
    /// The companion is at our version already.
    InStep,
    /// The companion is NEWER than us: left alone (D1).
    Newer(String),
    /// The companion is older: move it to our version.
    Refresh { db: PkgDb, from: String },
}

/// The decision, from what the host reports.
pub(crate) fn plan(enabled: bool, installed: Option<(PkgDb, String)>, own: &str) -> Plan {
    if !enabled {
        return Plan::Nothing("ROOMLERD_COMPANION_SYNC=0");
    }
    let Some((db, version)) = installed else {
        return Plan::Nothing("no roomler-desktop package is installed");
    };
    if version == own {
        Plan::InStep
    } else if crate::updater::is_newer(own, &version) {
        Plan::Refresh { db, from: version }
    } else if crate::updater::is_newer(&version, own) {
        Plan::Newer(version)
    } else {
        Plan::Nothing("the installed companion's version cannot be compared with this daemon's")
    }
}

/// The companion's package in a release, for this arch and format:
/// `roomler-desktop-<version>-<arch>-unknown-linux-gnu.<deb|rpm>`. A POSITIVE
/// match on the companion's own name, the mirror of the daemon picker's
/// `is_daemon_asset`, so neither picker can ever take the other's package (the
/// FR-27 freeze, one axis over). Its `.asc` and `.sha256` end differently, so
/// they never match.
pub(crate) fn pick_asset<'a>(
    assets: &'a [GithubAsset],
    arch_tokens: &[&str],
    db: PkgDb,
) -> Option<&'a GithubAsset> {
    let suffix = format!("-unknown-linux-gnu.{}", db.ext());
    assets.iter().find(|a| {
        let name = a.name.to_ascii_lowercase();
        name.starts_with("roomler-desktop-")
            && name.ends_with(&suffix)
            && arch_tokens.iter().any(|t| name.contains(t))
    })
}

/// The command that installs `path` with the package database that owns the
/// companion, if this host has a tool for it. `has` says whether a tool is on
/// this host. Root only: nothing here escalates. One command, never a ladder.
///
/// - dpkg: `apt-get`, which resolves a new dependency from the distro's
///   repositories, waiting up to a minute for dpkg's lock (unattended-upgrades
///   holds it for minutes at a time), and `--no-remove`: a dependency change
///   that would REMOVE a package aborts instead. ⚠️ Deliberately no
///   `dpkg --install` fallback, unlike the daemon's own ladder: the companion
///   has real dependencies (webkit2gtk, GTK, the tray library), and dpkg with
///   one unmet leaves it half-configured, which breaks apt for the whole host,
///   the daemon's own next update included. A refusal costs one tick instead.
/// - rpm: the first of `dnf`, `zypper` and `yum`, `install.sh`'s order
///   (`desktop_rpm_tool`). None of them removes a package to install one
///   unless told to (dnf's `--allowerasing`; zypper non-interactive cancels a
///   conflict). Our `.rpm` carries no RPM signature (its `.asc` is checked
///   before this runs), so zypper must be told to take it.
pub(crate) fn install_commands(
    db: PkgDb,
    path: &str,
    has: impl Fn(&str) -> bool,
) -> Vec<(&'static str, Vec<String>)> {
    let own = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    match db {
        PkgDb::Dpkg => [(
            "apt-get",
            own(&[
                "install",
                "-y",
                "--no-remove",
                "-o",
                "DPkg::Lock::Timeout=60",
                path,
            ]),
        )]
        .into_iter()
        .filter(|(tool, _)| has(tool))
        .collect(),
        PkgDb::Rpm => [
            ("dnf", own(&["install", "-y", path])),
            (
                "zypper",
                own(&["--non-interactive", "install", "--allow-unsigned-rpm", path]),
            ),
            ("yum", own(&["install", "-y", path])),
        ]
        .into_iter()
        .find(|(tool, _)| has(tool))
        .into_iter()
        .collect(),
    }
}

/// The environment every install command runs with. ⚠️ `NEEDRESTART_SUSPEND`:
/// Ubuntu's needrestart runs after every apt transaction and, non-interactive,
/// RESTARTS the services it finds on stale libraries, this daemon among them:
/// the companion's install would end in a restart of the very process that ran
/// it, cutting every session (the trap a vmtest cell hit on 2026-10-19).
pub(crate) const INSTALL_ENV: [(&str, &str); 3] = [
    ("DEBIAN_FRONTEND", "noninteractive"),
    ("NEEDRESTART_SUSPEND", "1"),
    ("NEEDRESTART_MODE", "l"),
];

/// Is this `/proc/<pid>/exe` target a companion running the binary an upgrade
/// just replaced? The package manager renames the new file over the old one,
/// so the running image's link reads `… (deleted)`.
pub(crate) fn is_replaced_companion(exe_link: &str) -> bool {
    exe_link
        .strip_suffix(" (deleted)")
        .and_then(|p| p.rsplit('/').next())
        .is_some_and(|name| name == "roomler-desktop")
}

/// What one sync did, for the log and for FR-117 P3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Skipped(String),
    InStep,
    Moved {
        from: String,
        to: String,
        restarted: usize,
    },
    Failed(String),
}

/// [`sync`]'s question without the work: would it move the companion now? A
/// per-user daemon asks it at its start, to wake its root helper (FR-96) for a
/// skew it can see but cannot fix.
#[cfg(target_os = "linux")]
pub(crate) fn needs_sync() -> bool {
    matches!(
        plan(
            super::sync_enabled(),
            super::installed_package(),
            env!("CARGO_PKG_VERSION")
        ),
        Plan::Refresh { .. }
    )
}

/// FR-117 P1 — move an installed companion package to this daemon's own
/// version. Never fatal: every outcome is logged, and a failure is retried by
/// the caller's next tick.
#[cfg(target_os = "linux")]
pub(crate) async fn sync() -> Outcome {
    let outcome = sync_inner().await;
    match &outcome {
        Outcome::Moved {
            from,
            to,
            restarted,
        } => tracing::info!(
            %from, %to, restarted,
            "companion: the desktop companion package now matches this daemon"
        ),
        Outcome::Failed(why) => tracing::warn!(
            reason = %why,
            "companion: could not move the desktop companion package to this daemon's version; \
             it keeps its version, and the next update check retries"
        ),
        Outcome::Skipped(why) => tracing::debug!(reason = %why, "companion: package sync skipped"),
        Outcome::InStep => tracing::debug!("companion: the desktop companion package is in step"),
    }
    outcome
}

#[cfg(target_os = "linux")]
async fn sync_inner() -> Outcome {
    use std::sync::atomic::{AtomicBool, Ordering};
    // D1 and D3 say so once per process, not on every tick.
    static SAID_NEWER: AtomicBool = AtomicBool::new(false);
    static SAID_ROOT: AtomicBool = AtomicBool::new(false);

    let own = env!("CARGO_PKG_VERSION");
    let (db, from) = match plan(super::sync_enabled(), super::installed_package(), own) {
        Plan::Nothing(why) => return Outcome::Skipped(why.to_string()),
        Plan::InStep => return Outcome::InStep,
        Plan::Newer(v) => {
            if !SAID_NEWER.swap(true, Ordering::Relaxed) {
                tracing::info!(
                    companion = %v, daemon = own,
                    "companion: the installed desktop companion is NEWER than this daemon; \
                     leaving it (never a downgrade)"
                );
            }
            return Outcome::Skipped(format!("the companion ({v}) is newer than {own}"));
        }
        Plan::Refresh { db, from } => (db, from),
    };
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        if !SAID_ROOT.swap(true, Ordering::Relaxed) {
            tracing::info!(
                companion = %from, daemon = own,
                "companion: the desktop companion is behind this daemon, and moving it needs \
                 root; on a per-user install the root update helper does it"
            );
        }
        return Outcome::Skipped("not root".to_string());
    }

    let tag = format!("agent-v{own}");
    let release = match crate::updater::fetch_release_by_tag(&tag).await {
        Ok(r) => r,
        Err(e) => return Outcome::Failed(format!("fetching release {tag}: {e:#}")),
    };
    let Some(asset) = pick_asset(&release.assets, crate::updater::linux_arch_tokens(), db) else {
        return Outcome::Failed(format!(
            "release {tag} has no roomler-desktop .{} for this architecture",
            db.ext()
        ));
    };
    // The daemon's own trust path: the digest, the `.asc` against the key
    // pinned in this binary, the version binding (`.deb` and `.rpm` readers),
    // a fresh private staging dir. A refusal discards the download.
    let path = match crate::updater::download_asset(asset, &tag).await {
        Ok(p) => p,
        Err(e) => return Outcome::Failed(format!("{e:#}")),
    };
    let staged = path.clone();
    let installed = tokio::task::spawn_blocking(move || install(db, &staged)).await;
    crate::updater::discard_staging(&path);
    match installed {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Outcome::Failed(format!("{e:#}")),
        Err(e) => return Outcome::Failed(format!("the install task: {e}")),
    }
    super::forget_installed_version();
    let to = super::installed_version().unwrap_or_else(|| "<unknown>".to_string());
    if to != own {
        return Outcome::Failed(format!(
            "the package manager ran, yet the companion reads {to}, not {own}"
        ));
    }
    let restarted = tokio::task::spawn_blocking(restart_replaced)
        .await
        .unwrap_or(0);
    Outcome::Moved {
        from,
        to,
        restarted,
    }
}

/// Run [`install_commands`] in order until one succeeds, each bounded.
#[cfg(target_os = "linux")]
fn install(db: PkgDb, path: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    let path = path
        .to_str()
        .context("the staged package path is not UTF-8")?;
    let candidates = install_commands(db, path, tool_on_path);
    if candidates.is_empty() {
        match db {
            PkgDb::Dpkg => bail!("no apt-get on this host to install a .deb with"),
            PkgDb::Rpm => bail!("no dnf, zypper or yum on this host to install an .rpm with"),
        }
    }
    let mut last = String::new();
    for (tool, args) in candidates {
        match run_bounded(tool, &args, INSTALL_TIMEOUT) {
            Ok(()) => {
                tracing::info!(tool, "companion: package installed");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(tool, error = %format!("{e:#}"), "companion: package install failed");
                last = format!("{tool}: {e:#}");
            }
        }
    }
    bail!("every installer failed (last: {last})")
}

/// Long enough for dnf to refresh its metadata and fetch a new dependency;
/// short enough that a hung package manager costs a tick, not the updater.
#[cfg(target_os = "linux")]
const INSTALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

#[cfg(target_os = "linux")]
fn tool_on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(tool).is_file()))
}

/// Run `tool args…` with [`INSTALL_ENV`], its output captured for the error,
/// killed at `limit`.
#[cfg(target_os = "linux")]
fn run_bounded(tool: &str, args: &[String], limit: std::time::Duration) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use std::process::{Command, Stdio};
    let mut child = Command::new(tool)
        .args(args)
        .envs(INSTALL_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {tool}"))?;
    // Drained on its own thread: a package manager that fills the pipe while
    // nobody reads it would block, and look like a hang.
    let stderr = child.stderr.take().map(|mut s| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut err = String::new();
            let _ = s.read_to_string(&mut err);
            err
        })
    });
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("waiting")? {
            if status.success() {
                return Ok(());
            }
            let err = stderr.and_then(|t| t.join().ok()).unwrap_or_default();
            let tail: String = err.lines().rev().take(3).collect::<Vec<_>>().join(" | ");
            bail!("{status}: {tail}");
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            bail!("no answer within {} s; killed", limit.as_secs());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Stop every companion still running the replaced binary, and start the
/// companion again in the graphical session where one was stopped (D2): as on
/// Windows (#1686), a person's tray is put back, never left gone, and one that
/// was not running stays stopped. Returns how many were restarted.
#[cfg(target_os = "linux")]
fn restart_replaced() -> usize {
    let mut stopped_uids: Vec<u32> = Vec::new();
    for (pid, uid) in replaced_companion_pids() {
        // SAFETY: a plain signal to a pid read from /proc a moment ago. A pid
        // reused in between would have to be a new process whose exe link
        // reads "roomler-desktop (deleted)" too: not a stranger.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        let gone = (0..40).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(250));
            !std::path::Path::new(&format!("/proc/{pid}")).exists()
        });
        if gone {
            stopped_uids.push(uid);
        } else {
            tracing::warn!(
                pid,
                "companion: the old companion did not exit within 10 s; left running"
            );
        }
    }
    if stopped_uids.is_empty() {
        return 0;
    }
    let Some(exe) = super::linux_companion_path() else {
        return 0;
    };
    let sess = match super::graphical_session() {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(error = %format!("{e:#}"), "companion: no graphical session to start the new companion in; it starts at the next login");
            return 0;
        }
    };
    if !stopped_uids.contains(&sess.uid) {
        tracing::info!(
            "companion: the stopped companion belonged to a user who is not at the screen; it starts at their next login"
        );
        return 0;
    }
    match super::systemd_run_command(&sess, &exe, &[], false).output() {
        Ok(out) if out.status.success() => 1,
        Ok(out) => {
            tracing::warn!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "companion: could not start the new companion"
            );
            0
        }
        Err(e) => {
            tracing::warn!(error = %e, "companion: could not start the new companion");
            0
        }
    }
}

/// `(pid, uid)` of every process whose image is a replaced `roomler-desktop`.
#[cfg(target_os = "linux")]
fn replaced_companion_pids() -> Vec<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let link = std::fs::read_link(e.path().join("exe")).ok()?;
            if !is_replaced_companion(link.to_str()?) {
                return None;
            }
            let uid = std::fs::metadata(e.path()).ok()?.uid();
            Some((pid, uid))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> GithubAsset {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "browser_download_url": format!("https://example.invalid/{name}"),
        }))
        .expect("a GithubAsset")
    }

    /// The release 0.4.147 actually published, in GitHub's order.
    fn release_0_4_147() -> Vec<GithubAsset> {
        [
            "roomlerd-0.4.147-aarch64-unknown-linux-gnu.deb",
            "roomlerd-0.4.147-aarch64-unknown-linux-gnu.tar.gz",
            "roomler-desktop-0.4.147-aarch64-unknown-linux-gnu.deb",
            "roomler-desktop-0.4.147-aarch64-unknown-linux-gnu.deb.asc",
            "roomler-desktop-0.4.147-aarch64-unknown-linux-gnu.rpm",
            "roomler-desktop-0.4.147-aarch64-unknown-linux-gnu.rpm.asc",
            "roomler-desktop-0.4.147-aarch64-unknown-linux-gnu.rpm.sha256",
            "roomler-desktop-0.4.147-x86_64-pc-windows-msvc.exe",
            "roomler-desktop-0.4.147-x86_64-unknown-linux-gnu.deb",
            "roomler-desktop-0.4.147-x86_64-unknown-linux-gnu.deb.sha256",
            "roomler-desktop-0.4.147-x86_64-unknown-linux-gnu.rpm",
            "roomlerd-0.4.147-x86_64-unknown-linux-gnu.deb",
            "roomlerd-0.4.147-x86_64-unknown-linux-gnu.tar.gz",
        ]
        .into_iter()
        .map(asset)
        .collect()
    }

    #[test]
    fn only_an_installed_dpkg_package_counts() {
        assert_eq!(
            dpkg_installed_version("install ok installed|0.4.146-1"),
            Some("0.4.146-1")
        );
        assert_eq!(
            dpkg_installed_version("hold ok installed|0.4.146-1\n"),
            Some("0.4.146-1")
        );
        // Removed with its config kept: dpkg remembers it, and it is NOT there.
        assert_eq!(
            dpkg_installed_version("deinstall ok config-files|0.4.146-1"),
            None
        );
        assert_eq!(
            dpkg_installed_version("install ok half-installed|0.4.146-1"),
            None
        );
        assert_eq!(dpkg_installed_version("install ok installed|"), None);
        assert_eq!(dpkg_installed_version(""), None);
    }

    #[test]
    fn the_plan_moves_only_an_installed_older_companion() {
        let own = "0.4.148";
        let pkg = |db, v: &str| Some((db, v.to_string()));
        assert_eq!(
            plan(true, pkg(PkgDb::Rpm, "0.4.139"), own),
            Plan::Refresh {
                db: PkgDb::Rpm,
                from: "0.4.139".into()
            }
        );
        assert_eq!(
            plan(true, pkg(PkgDb::Dpkg, "0.4.147"), own),
            Plan::Refresh {
                db: PkgDb::Dpkg,
                from: "0.4.147".into()
            }
        );
        assert_eq!(plan(true, pkg(PkgDb::Dpkg, own), own), Plan::InStep);
        // D1: never a downgrade.
        assert_eq!(
            plan(true, pkg(PkgDb::Dpkg, "0.4.150"), own),
            Plan::Newer("0.4.150".into())
        );
        // A headless node, or a person who removed it: nothing is installed.
        assert!(matches!(plan(true, None, own), Plan::Nothing(_)));
        // The kill switch wins over everything.
        assert!(matches!(
            plan(false, pkg(PkgDb::Rpm, "0.4.139"), own),
            Plan::Nothing("ROOMLERD_COMPANION_SYNC=0")
        ));
        // A version nobody can compare is not a reason to install anything.
        assert!(matches!(
            plan(true, pkg(PkgDb::Dpkg, "garbage"), own),
            Plan::Nothing(_)
        ));
    }

    #[test]
    fn the_picker_takes_the_companion_for_this_arch_and_format_only() {
        let assets = release_0_4_147();
        let x86 = ["x86_64", "amd64"];
        let arm = ["aarch64", "arm64"];
        let name = |a: Option<&GithubAsset>| a.map(|a| a.name.clone());
        assert_eq!(
            name(pick_asset(&assets, &x86, PkgDb::Dpkg)).as_deref(),
            Some("roomler-desktop-0.4.147-x86_64-unknown-linux-gnu.deb")
        );
        assert_eq!(
            name(pick_asset(&assets, &x86, PkgDb::Rpm)).as_deref(),
            Some("roomler-desktop-0.4.147-x86_64-unknown-linux-gnu.rpm")
        );
        assert_eq!(
            name(pick_asset(&assets, &arm, PkgDb::Rpm)).as_deref(),
            Some("roomler-desktop-0.4.147-aarch64-unknown-linux-gnu.rpm")
        );
        assert_eq!(
            name(pick_asset(&assets, &arm, PkgDb::Dpkg)).as_deref(),
            Some("roomler-desktop-0.4.147-aarch64-unknown-linux-gnu.deb")
        );
        // Never the daemon's own package, never a sidecar, never another arch.
        for db in [PkgDb::Dpkg, PkgDb::Rpm] {
            for tokens in [&x86[..], &arm[..]] {
                let picked = pick_asset(&assets, tokens, db).expect("a companion");
                assert!(picked.name.starts_with("roomler-desktop-"));
                assert!(picked.name.ends_with(db.ext()), "{}", picked.name);
            }
        }
        // A release without it (a pre-FR-27 one) has nothing to pick.
        let daemon_only: Vec<GithubAsset> = release_0_4_147()
            .into_iter()
            .filter(|a| a.name.starts_with("roomlerd-"))
            .collect();
        assert!(pick_asset(&daemon_only, &x86, PkgDb::Dpkg).is_none());
        // An arch the release does not carry picks nothing.
        assert!(pick_asset(&assets, &["riscv64"], PkgDb::Dpkg).is_none());
    }

    #[test]
    fn a_deb_installs_through_apt_alone_never_removing_never_half_installing() {
        let p = "/tmp/roomler-update.x/c.deb";
        let c = install_commands(PkgDb::Dpkg, p, |_| true);
        // ONE command: a `dpkg --install` fallback would half-configure a
        // companion whose dependency apt could not meet, and break apt.
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, "apt-get");
        let args = &c[0].1;
        assert!(args.iter().any(|a| a == "--no-remove"), "{args:?}");
        assert!(
            args.iter().any(|a| a == "DPkg::Lock::Timeout=60"),
            "{args:?}"
        );
        assert_eq!(args.last().map(String::as_str), Some(p));
        // No apt-get: nothing, rather than bare dpkg.
        assert!(install_commands(PkgDb::Dpkg, p, |t| t == "dpkg").is_empty());
    }

    #[test]
    fn an_rpm_installs_with_the_first_tool_present_in_install_shs_order() {
        let p = "/tmp/roomler-update.x/c.rpm";
        let only = |t: &'static str| move |tool: &str| tool == t;
        assert_eq!(install_commands(PkgDb::Rpm, p, |_| true)[0].0, "dnf");
        assert_eq!(
            install_commands(PkgDb::Rpm, p, only("zypper"))[0].0,
            "zypper"
        );
        assert!(
            install_commands(PkgDb::Rpm, p, only("zypper"))[0]
                .1
                .iter()
                .any(|a| a == "--allow-unsigned-rpm"),
            "zypper refuses our unsigned-by-RPM package unless told"
        );
        assert_eq!(install_commands(PkgDb::Rpm, p, only("yum"))[0].0, "yum");
        assert!(install_commands(PkgDb::Rpm, p, |_| false).is_empty());
    }

    #[test]
    fn needrestart_is_suspended_for_every_install() {
        assert!(INSTALL_ENV.contains(&("NEEDRESTART_SUSPEND", "1")));
        assert!(INSTALL_ENV.contains(&("DEBIAN_FRONTEND", "noninteractive")));
    }

    #[test]
    fn only_a_companion_on_a_replaced_image_is_restarted() {
        assert!(is_replaced_companion("/usr/bin/roomler-desktop (deleted)"));
        assert!(is_replaced_companion(
            "/usr/local/bin/roomler-desktop (deleted)"
        ));
        // Running the installed binary: nothing to restart.
        assert!(!is_replaced_companion("/usr/bin/roomler-desktop"));
        // Another program whose image was replaced is not ours to touch.
        assert!(!is_replaced_companion("/usr/bin/meshharbord (deleted)"));
        assert!(!is_replaced_companion(
            "/usr/bin/roomler-desktop-helper (deleted)"
        ));
    }
}
