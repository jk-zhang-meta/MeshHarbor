// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! S1a PR-A — keep the `meshharbor-desktop` companion EXE at the daemon's
//! version.
//!
//! The desktop app is in NEITHER MSI flavour: it's a standalone release
//! asset placed beside the daemon by the setup wizard / `install.ps1`
//! (GAP-A), and the auto-updater only ever downloads `.msi` — so every
//! daemon self-update left `meshharbor-desktop.exe` stale forever (the
//! reported item 1 of the consolidation roadmap). This module runs at
//! daemon startup: when the sibling desktop EXE's recorded version
//! differs from our own `CARGO_PKG_VERSION`, download the matching
//! `meshharbor-desktop-*` asset from OUR OWN release tag (not latest — the
//! companion tracks the daemon, not the feed), rename-swap it, and
//! restart it if it was running.
//!
//! Version tracking is a sidecar marker (`meshharbor-desktop.exe.version`)
//! written on every successful swap — no PE version parsing. A
//! wizard-placed EXE with no marker counts as stale and gets swapped
//! once, after which the marker tracks.
//!
//! Ownership: ONE refresher per install (#1686). Under a running SCM service
//! the service host refreshes at its own start, and the worker does not —
//! the worker runs elevated by default, so "it cannot write `%ProgramFiles%`
//! and skips" stopped being true, and the two used to swap concurrently,
//! each renaming the other's fresh copy under a live companion. A per-user
//! task daemon owns `%LOCALAPPDATA%\Programs\MeshHarbor` and refreshes itself.
//! Running companions are found by the path they were started from and
//! stopped by pid before the swap (`win_service::companion_procs`), never by
//! image name. Failures are always skip-and-retry-next-start, never fatal.

// FR-27: unconditional now — `ensure_running` has a real body on every
// platform, where before this module was Windows-only.
use anyhow::{Context, Result};

/// FR-84 D6 — the one-shot post-install launch: its decision table and the
/// marker that makes it one-shot.
mod launch_once;

pub use launch_once::LaunchOwner;

/// FR-117 P1 — on Linux the companion's PACKAGE tracks the daemon. The
/// decisions are pure and tested everywhere; the I/O is Linux-only.
#[cfg(any(all(unix, not(target_os = "macos")), test))]
pub(crate) mod package_sync;

/// FR-117 P1 — move an installed companion package to this daemon's own
/// version. Linux only: there the companion is a separate `.deb`/`.rpm` that
/// nothing else moves (the macOS `.pkg` carries the app; Windows has
/// [`refresh_if_stale`]). The updater calls it as the host's ROOT update owner;
/// it is never fatal, and a failure is retried on the updater's next tick.
#[cfg(target_os = "linux")]
pub async fn sync_package() {
    let _ = package_sync::sync().await;
}

/// FR-117 P1 — would [`sync_package`] move the companion now? A per-user
/// daemon, which can install nothing, asks it to wake its root helper.
#[cfg(target_os = "linux")]
pub fn package_needs_sync() -> bool {
    package_sync::needs_sync()
}

/// FR-117 — the switch for what FR-117 added (`MESHHARBORD_COMPANION_SYNC=0`): the
/// Linux package sync and the Windows retry. Windows' refresh at start is older
/// than FR-117 and stays either way.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn sync_enabled() -> bool {
    tunnel_core::env::flag("COMPANION_SYNC", true)
}

/// FR-117 P2 — [`refresh_if_stale`] again every [`REFRESH_RETRY`], for as long
/// as the process that owns the refresh runs (#1686: the SCM host, or the
/// worker). Before this a failed refresh waited for the next restart, which on
/// a laptop that is never restarted is never, and nothing said why (a corp
/// laptop sat a version behind on 2026-10-20). One file read when the version
/// marker matches.
#[cfg(target_os = "windows")]
pub async fn refresh_periodically(respawn: RespawnContext) {
    loop {
        tokio::time::sleep(REFRESH_RETRY).await;
        if sync_enabled() {
            refresh_if_stale(respawn).await;
        }
    }
}

/// FR-117 P2 — the retry's period: the updater's own default interval.
#[cfg(target_os = "windows")]
const REFRESH_RETRY: std::time::Duration = crate::updater::CHECK_INTERVAL;

/// FR-84 D6 — open the companion ONCE after a fresh install, from whichever
/// process owns that on this host: the SCM host on a perMachine Windows
/// install, the worker everywhere else (per-user Scheduled Task, systemd
/// unit). Spawn-and-forget; waits up to ten minutes for what a fresh install
/// is still missing (the enrollment, the companion, a logged-on user), and
/// never launches twice — or at all on an install that ran before. See
/// `companion/launch_once.rs`.
pub async fn launch_once_after_install(owner: LaunchOwner) {
    launch_once::run(owner).await
}

/// FR-84 D6 — what the SCM service host does for the companion at every
/// start, after the version refresh: bring the machine-wide Run value in line
/// with the device switch and the installed EXE (the self-heal), then run the
/// post-install launcher.
#[cfg(target_os = "windows")]
pub async fn scm_host_startup() {
    sync_machine_autostart_logged(scm_companion_autostart());
    launch_once_after_install(LaunchOwner::ScmHost).await;
}

/// The device's `companion_autostart` as the SCM host can see it: from the
/// config the worker uses (machine-global, else the console user's); ON when
/// none is readable yet (a fresh install before enrollment).
#[cfg(target_os = "windows")]
pub fn scm_companion_autostart() -> bool {
    use crate::win_service::supervisor;
    let token = supervisor::active_console_session_id()
        .and_then(|sid| supervisor::query_user_token(sid).ok().flatten());
    launch_once::scm_worker_config(token.as_ref()).is_none_or(|c| c.companion_autostart)
}

/// FR-84 D6 — `HKLM\…\Run\MeshHarbor Desktop`: present iff the device switch is
/// on and the companion sits beside this daemon. Elevated callers only (the
/// SCM host, `service install --as-service`). Logs a change, not a no-op.
#[cfg(target_os = "windows")]
pub fn sync_machine_autostart_logged(companion_autostart: bool) {
    use meshharbor_node_core::companion_autostart::registry::Hive;
    // A person's opt-out never removes the MACHINE value — it serves every
    // account; the companion honours the opt-out at `--autostart` instead.
    sync_login_autostart(Hive::LocalMachine, companion_autostart, false);
}

/// FR-84 D6 — `HKCU\…\Run\MeshHarbor Desktop` for a per-user install: present
/// iff the device switch is on, the companion is installed, and THIS person
/// has not switched "Start at login" off (the companion's own state).
#[cfg(target_os = "windows")]
pub fn sync_user_autostart_logged(companion_autostart: bool) {
    use meshharbor_node_core::companion_autostart::registry::Hive;
    let opted_out = meshharbor_node_core::desktop_state::load().autostart_opt_out;
    sync_login_autostart(Hive::CurrentUser, companion_autostart, opted_out);
}

#[cfg(target_os = "windows")]
fn sync_login_autostart(
    hive: meshharbor_node_core::companion_autostart::registry::Hive,
    companion_autostart: bool,
    opted_out: bool,
) {
    use meshharbor_node_core::companion_autostart::{
        RunKeyAction, WINDOWS_RUN_SUBKEY, WINDOWS_RUN_VALUE_NAME, desired_run_value,
        registry::sync_value,
    };
    let Some(exe) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(DESKTOP_EXE)))
    else {
        return;
    };
    let desired = desired_run_value(companion_autostart, &exe, exe.exists(), opted_out);
    match sync_value(
        hive,
        WINDOWS_RUN_SUBKEY,
        WINDOWS_RUN_VALUE_NAME,
        desired.as_deref(),
    ) {
        Ok(RunKeyAction::Keep) => {}
        Ok(action) => tracing::info!(?hive, ?action, "companion login start (Run value) updated"),
        Err(e) => {
            tracing::warn!(?hive, error = %e, "companion login start (Run value): could not update")
        }
    }
}

/// FR-84 D6 — remove the Run value an uninstall leaves behind (`Ok(true)` =
/// there was one).
#[cfg(target_os = "windows")]
pub fn remove_login_autostart(machine: bool) -> Result<bool> {
    use meshharbor_node_core::companion_autostart::{
        WINDOWS_RUN_SUBKEY, WINDOWS_RUN_VALUE_NAME,
        registry::{Hive, delete_value},
    };
    let hive = if machine {
        Hive::LocalMachine
    } else {
        Hive::CurrentUser
    };
    delete_value(hive, WINDOWS_RUN_SUBKEY, WINDOWS_RUN_VALUE_NAME)
        .with_context(|| format!("removing the {hive:?} Run value"))
}

/// Who is calling the refresh — decides how a running desktop gets
/// respawned after the swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespawnContext {
    /// Caller runs as LocalSystem (SCM service host / SystemContext
    /// worker): respawn into the active interactive session via
    /// `CreateProcessAsUserW`.
    SystemService,
    /// Caller runs as the interactive user (perUser task daemon,
    /// attended run): plain spawn.
    UserSession,
}

#[cfg(target_os = "windows")]
pub const DESKTOP_EXE: &str = "meshharbor-desktop.exe";
#[cfg(target_os = "windows")]
const VERSION_MARKER: &str = "meshharbor-desktop.exe.version";
#[cfg(target_os = "windows")]
const OLD_SUFFIX: &str = "meshharbor-desktop.exe.old";
#[cfg(target_os = "windows")]
const NEW_SUFFIX: &str = "meshharbor-desktop.exe.new";

/// FR-27 — make sure the desktop companion is RUNNING, because it is the only
/// thing that renders a consent prompt.
///
/// Called when an attended prompt begins. Before this nothing started it: a
/// device set to `Prompt on host` whose operator had quit the menu-bar app (or
/// never launched it) showed nothing at all, sat out its 30 s window, and told
/// the controller "the user denied your request".
///
/// Best-effort by construction, and deliberately not fatal. Every failure path
/// logs WHY — that log line, plus the `no_prompt_surface` the caller then sends,
/// is the difference between a diagnosable refusal and a mystery.
///
/// ⚠️ Rate-limited process-wide. A burst of session requests must not turn into
/// a burst of `launchctl kickstart` / `CreateProcessAsUserW` calls; one attempt
/// per [`ENSURE_COOLDOWN`] is plenty, since a launch that works is visible
/// within a second and one that doesn't will not work any better on retry.
/// Returns whether a human can now, in fact, be shown a prompt on this host.
///
/// The caller reports `no_prompt_surface` on `false`, which is why this is a
/// verdict and not a fire-and-forget: without it the agent could only ever
/// report a TIMEOUT, and "nobody answered in 30 s" and "there is nobody to
/// ask, and there never was" need different things done about them.
pub async fn ensure_running() -> bool {
    use std::sync::Mutex;
    use std::time::Instant;
    // Both halves of the rate limit: when we last tried, and what we concluded.
    // A cooldown that returned an optimistic default would report a surface
    // that does not exist — worse than not rate-limiting at all.
    static LAST: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

    if let Some((at, verdict)) = *LAST.lock().unwrap()
        && at.elapsed() < ENSURE_COOLDOWN
    {
        return verdict;
    }

    let verdict = match ensure_running_inner().await {
        Ok(EnsureOutcome::AlreadyRunning) => {
            tracing::debug!("desktop companion is already running");
            true
        }
        Ok(EnsureOutcome::Started) => {
            tracing::info!("started the desktop companion for a prompt");
            true
        }
        Ok(EnsureOutcome::Unsupported) => {
            tracing::info!(
                "no desktop companion on this host — an on-screen prompt is not possible; \
                 answer with `meshharbord consent --list` / `--approve`, or set this device to \
                 email/push consent"
            );
            false
        }
        Err(e) => {
            tracing::warn!(
                error = %format!("{e:#}"),
                "could not start the desktop companion — an on-screen prompt is not possible"
            );
            false
        }
    };
    *LAST.lock().unwrap() = Some((Instant::now(), verdict));
    verdict
}

/// One attempt per this interval, process-wide.
const ENSURE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(20);

/// FR-27 — the version of the companion INSTALLED on this host, for the
/// heartbeat, or `None` when there is none / it cannot be read.
///
/// This exists because the daemon and the companion update through different
/// mechanisms on all three platforms (see [`refresh_if_stale`]), so a fleet
/// "Update all" moving `agent_version` says nothing about the companion. The
/// operator's report was exactly that: the daemon went forward and the desktop
/// stayed behind, with nothing on screen to say so.
///
/// ⚠️ Deliberately does NOT run the companion binary. `--version` on a GUI
/// binary is a process spawn on every heartbeat and, on Linux, a GTK-linked
/// executable started by a root daemon with no display; both are worse than a
/// file read. Every arm reads metadata the installer already wrote.
///
/// Cached for [`VERSION_TTL`]: the answer only changes when a package manager
/// runs, and the heartbeat is every 30 s.
pub fn installed_version() -> Option<String> {
    use std::time::Instant;

    if let Some((at, ref v)) = *VERSION_CACHE.lock().unwrap()
        && at.elapsed() < VERSION_TTL
    {
        return v.clone();
    }
    let v = installed_version_inner();
    *VERSION_CACHE.lock().unwrap() = Some((Instant::now(), v.clone()));
    v
}

const VERSION_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// [`installed_version`]'s cache: when it last read, and what.
static VERSION_CACHE: std::sync::Mutex<Option<(std::time::Instant, Option<String>)>> =
    std::sync::Mutex::new(None);

/// FR-117 — drop the cached version after something moved the companion, so
/// the next heartbeat reports the new one instead of a 10-minute-old answer
/// (the grid's skew would otherwise outlive the fix by that long).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn forget_installed_version() {
    *VERSION_CACHE.lock().unwrap() = None;
}

/// Windows: the sidecar marker [`refresh_if_stale`] writes on every swap. A
/// wizard-placed EXE with no marker reads as `None`, which is honest — the
/// daemon genuinely does not know what version it is until it swaps it once.
#[cfg(target_os = "windows")]
fn installed_version_inner() -> Option<String> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    if !dir.join(DESKTOP_EXE).exists() {
        return None;
    }
    let raw = std::fs::read_to_string(dir.join(VERSION_MARKER)).ok()?;
    sanitize_version(&raw)
}

/// macOS: `CFBundleShortVersionString` out of the app bundle's `Info.plist`.
/// Scanned as text rather than parsed: the plist is one we generate ourselves
/// (`release-agent.yml`), in the XML form, and a plist crate for one string
/// would be a dependency the thin-client work (P3e lever E) just spent effort
/// removing.
#[cfg(target_os = "macos")]
fn installed_version_inner() -> Option<String> {
    const PLIST: &str = "/Applications/MeshHarbor.app/Contents/Info.plist";
    let text = std::fs::read_to_string(PLIST).ok()?;
    let after = text.split("<key>CFBundleShortVersionString</key>").nth(1)?;
    let open = after.find("<string>")? + "<string>".len();
    let close = after[open..].find("</string>")? + open;
    sanitize_version(&after[open..close])
}

/// Linux: ask the package database that OWNS the companion here: dpkg for its
/// `meshharbor-desktop` .deb, rpm for the .rpm (FR-93 P6d). Reading the package
/// database is the one answer that stays true when the package manager
/// upgrades the companion without the daemon noticing.
#[cfg(all(unix, not(target_os = "macos")))]
fn installed_version_inner() -> Option<String> {
    installed_package().map(|(_, v)| v)
}

/// The companion's package on this host: which database owns it, and its
/// version as the release it names. FR-117 needs the first half too, because
/// the format of the package that moves it forward is that database's.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn installed_package() -> Option<(package_sync::PkgDb, String)> {
    // Not installed, or no such tool on this host: "no companion we can name",
    // not an error worth logging every 10 min.
    let query = |cmd: &str, args: &[&str]| -> Option<String> {
        let out = std::process::Command::new(cmd).args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    if let Some(raw) = query(
        "dpkg-query",
        &["-W", "-f=${Status}|${Version}", "meshharbor-desktop"],
    ) {
        // ⚠️ `dpkg-query -W` also answers for a package dpkg merely REMEMBERS:
        // removed with its config kept (`deinstall ok config-files`), version
        // and all. That is not an installed companion, and FR-117 must never
        // put back one a person removed.
        if let Some(v) = package_sync::dpkg_installed_version(&raw) {
            // cargo-deb appends a Debian revision (`0.4.16-1`); report the
            // upstream half so the grid can compare it with `agent_version`.
            return sanitize_version(v.split('-').next().unwrap_or(""))
                .map(|v| (package_sync::PkgDb::Dpkg, v));
        }
    }
    // `%{VERSION}` is the upstream half already (the release is its own tag).
    query("rpm", &["-q", "--qf", "%{VERSION}", "meshharbor-desktop"])
        .and_then(|raw| sanitize_version(&raw))
        .map(|v| (package_sync::PkgDb::Rpm, v))
}

/// A version string is about to be persisted on the device row and rendered in
/// the grid, and every arm above reads it off the host — so bound it. Empty
/// stays `None` (absent and blank must not look different downstream).
fn sanitize_version(raw: &str) -> Option<String> {
    let v: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
        .take(32)
        .collect();
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod version_tests {
    use super::sanitize_version;

    #[test]
    fn blank_and_whitespace_are_absent_not_empty() {
        assert_eq!(sanitize_version(""), None);
        assert_eq!(sanitize_version("   \n"), None);
    }

    #[test]
    fn ordinary_versions_survive_intact() {
        assert_eq!(sanitize_version("0.4.16\n"), Some("0.4.16".into()));
        assert_eq!(
            sanitize_version("0.3.0-rc.483"),
            Some("0.3.0-rc.483".into())
        );
    }

    #[test]
    fn host_supplied_junk_cannot_reach_the_grid() {
        // The Windows arm reads a file anyone able to write next to the daemon
        // could edit; the value ends up in a Vue table.
        assert_eq!(
            sanitize_version("<script>alert(1)</script>"),
            Some("scriptalert1script".into())
        );
        assert_eq!(sanitize_version(&"9".repeat(200)).unwrap().len(), 32);
    }
}

/// FR-97 P5a — who is at the screen, read from what `loginctl` and `stat`
/// print. Pure, so every platform's test build runs them.
#[cfg(test)]
mod console_tests {
    use super::{console_owner_person, seat0_active_session, session_person, show_field};

    /// `key=value` lines, the whole key and nothing but it: `NameX=` is not
    /// `Name`, and an empty value is no value.
    #[test]
    fn a_show_field_is_the_whole_key() {
        let text = "NameX=wrong\nName=ana\nDisplay=\nType=wayland\n";
        assert_eq!(show_field(text, "Name").as_deref(), Some("ana"));
        assert_eq!(show_field(text, "Display"), None);
        assert_eq!(show_field(text, "Seat"), None);
    }

    /// `loginctl show-seat seat0` with a session showing, and with none
    /// (a headless server, or a VM before anyone logged in).
    #[test]
    fn seat0s_active_session_or_nobody() {
        let seat = "Id=seat0\nActiveSession=2\nCanGraphical=yes\nSessions=2 c1\n";
        assert_eq!(seat0_active_session(seat).unwrap(), "2");
        let empty = "Id=seat0\nActiveSession=\nCanGraphical=no\nSessions=\n";
        let e = seat0_active_session(empty).unwrap_err().to_string();
        assert!(e.contains("seat0 has no active session"), "{e}");
    }

    /// The session's person: a user's graphical or text-console login is a
    /// person; GDM's greeter is the login screen; another class is nobody's.
    #[test]
    fn the_session_showing_is_a_person_or_the_login_screen() {
        let user = "Id=2\nName=ana\nUser=1000\nSeat=seat0\nType=wayland\nClass=user\nActive=yes\n";
        assert_eq!(session_person("2", user).unwrap(), "ana");
        let tty = "Id=5\nName=ops\nUser=1001\nSeat=seat0\nType=tty\nClass=user\nActive=yes\n";
        assert_eq!(session_person("5", tty).unwrap(), "ops");

        let greeter = "Id=c1\nName=gdm\nUser=120\nSeat=seat0\nType=wayland\nClass=greeter\n";
        let e = session_person("c1", greeter).unwrap_err().to_string();
        assert!(e.contains("the login screen is showing"), "{e}");

        let lock = "Id=9\nName=x\nUser=1000\nType=x11\nClass=lock-screen\n";
        let e = session_person("9", lock).unwrap_err().to_string();
        assert!(e.contains("class lock-screen, not a person's"), "{e}");

        let unnamed = "Id=3\nUser=1000\nType=x11\nClass=user\n";
        let e = session_person("3", unnamed).unwrap_err().to_string();
        assert!(e.contains("names no account"), "{e}");
    }

    /// `/dev/console`'s owner: a person, the login window (root), or a
    /// system account during Setup Assistant.
    #[test]
    fn the_consoles_owner_is_a_person_or_nobody() {
        assert_eq!(console_owner_person("ana\n").unwrap(), "ana");
        for login_window in ["root\n", "", "  \n"] {
            let e = console_owner_person(login_window).unwrap_err().to_string();
            assert!(e.contains("the login window is showing"), "{e}");
        }
        let e = console_owner_person("_mbsetupuser\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("system account _mbsetupuser"), "{e}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnsureOutcome {
    AlreadyRunning,
    Started,
    /// No companion ships for this platform / this install shape.
    Unsupported,
}

#[cfg(target_os = "windows")]
async fn ensure_running_inner() -> Result<EnsureOutcome> {
    if desktop_running() {
        return Ok(EnsureOutcome::AlreadyRunning);
    }
    let exe_dir = std::env::current_exe()
        .context("locating own exe")?
        .parent()
        .context("own exe has no parent dir")?
        .to_path_buf();
    let dest = exe_dir.join(DESKTOP_EXE);
    if !dest.exists() {
        // Not an error: `install.ps1 -SkipDesktop` is a supported choice, and
        // so is a daemon-only deployment. The caller reports
        // `no_prompt_surface` either way — this just keeps the log honest
        // about which of the two happened.
        return Ok(EnsureOutcome::Unsupported);
    }
    // A SYSTEM daemon has no desktop of its own — the companion has to be
    // launched INTO the interactive session, which is exactly what the
    // update-respawn path already does.
    let ctx = respawn_context_for_self();
    respawn_desktop(ctx, &dest);
    Ok(EnsureOutcome::Started)
}

/// Which spawn shape this process needs. Mirrors the probe `main.rs` does for
/// the update path, kept here so the consent path cannot pick a different one.
#[cfg(target_os = "windows")]
fn respawn_context_for_self() -> RespawnContext {
    #[cfg(feature = "system-context")]
    {
        use crate::system_context::worker_role;
        if matches!(
            worker_role::probe_self(),
            Ok(worker_role::WorkerRole::SystemContext)
        ) {
            return RespawnContext::SystemService;
        }
    }
    RespawnContext::UserSession
}

#[cfg(target_os = "macos")]
async fn ensure_running_inner() -> Result<EnsureOutcome> {
    const BUNDLE: &str = "/Applications/MeshHarbor.app";
    const LABEL: &str = "fans.itachi.meshharbor.desktop";

    if !std::path::Path::new(BUNDLE).exists() {
        // Not an error, for the same reason as the Windows arm: a daemon-only
        // install is a supported shape, and the caller reports
        // `no_prompt_surface` either way. Saying WHICH keeps the log honest.
        return Ok(EnsureOutcome::Unsupported);
    }
    if pgrep_running("meshharbor-desktop") {
        return Ok(EnsureOutcome::AlreadyRunning);
    }
    // The companion is a LaunchAgent in the console user's GUI domain. Ask
    // launchd rather than spawning it ourselves: the daemon half runs as root,
    // and a root-spawned GUI app would land in the wrong session with the
    // wrong TCC identity. `kickstart` is also idempotent.
    //
    // The console user is resolved the way the pkg's postinstall does
    // (`stat -f %Su /dev/console`) so the two agree by construction.
    let uid = console_user_uid().context("resolving the console user")?;
    let target = format!("gui/{uid}/{LABEL}");
    let out = std::process::Command::new("launchctl")
        .args(["kickstart", "-k", &target])
        .output()
        .context("spawning launchctl")?;
    if !out.status.success() {
        anyhow::bail!(
            "launchctl kickstart {target} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(EnsureOutcome::Started)
}

/// The uid of whoever owns the console (the GUI session). `None` at the login
/// window or over SSH — where there is, correctly, nobody to prompt.
#[cfg(target_os = "macos")]
fn console_user_uid() -> Result<u32> {
    let user = console_user_name()?;
    let out = std::process::Command::new("id")
        .args(["-u", &user])
        .output()
        .context("id -u")?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parsing the uid of console user '{user}'"))
}

/// The account of the person signed in at this Mac's screen: the owner of
/// `/dev/console`, which loginwindow hands to whoever logs in at the GUI and
/// takes back to root at the login window. Read the way the pkg's
/// postinstall reads it (`stat -f %Su /dev/console`), so the companion's
/// launch, the postinstall and FR-97 P5a's `console_user` agree by
/// construction. `Err` at the login window, and while the console belongs to
/// a system account (`_mbsetupuser` runs Setup Assistant).
#[cfg(target_os = "macos")]
pub(crate) fn console_user_name() -> Result<String> {
    let out = std::process::Command::new("stat")
        .args(["-f", "%Su", "/dev/console"])
        .output()
        .context("stat /dev/console")?;
    console_owner_person(&String::from_utf8_lossy(&out.stdout))
}

/// The pure half of [`console_user_name`]: `/dev/console`'s owner as `stat`
/// printed it, a person's account or why there is none. macOS names every
/// system account with a leading `_`.
#[cfg(any(target_os = "macos", test))]
fn console_owner_person(owner: &str) -> Result<String> {
    let user = owner.trim();
    if user.is_empty() || user == "root" {
        anyhow::bail!("nobody is signed in at this Mac's screen (the login window is showing)");
    }
    if user.starts_with('_') {
        anyhow::bail!(
            "nobody is signed in at this Mac's screen (the console belongs to the system \
             account {user})"
        );
    }
    Ok(user.to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
async fn ensure_running_inner() -> Result<EnsureOutcome> {
    let Some(path) = linux_companion_path() else {
        // Until FR-27's packaging phase there is no Linux companion at all,
        // and after it there still won't be on a headless server — which is
        // the correct state for a machine with no screen, not a fault.
        return Ok(EnsureOutcome::Unsupported);
    };

    // A root systemd daemon has no display of its own. Find the graphical
    // session's owner and its bus/display, then spawn as that user.
    let sess = graphical_session().context("finding a graphical login session")?;
    // FR-93 P6b — THAT user's companion (`pgrep -u`: another user's on a
    // shared machine is not this person's), started through the manager this
    // daemon may use. A per-user daemon has its own user manager; the system
    // manager would ask polkit for a password nobody is there to type. The
    // shape `launch_once` already has.
    if companion_running_for_uid(sess.uid) {
        return Ok(EnsureOutcome::AlreadyRunning);
    }
    // SAFETY: `geteuid` reads the caller's own credentials; it cannot fail.
    let user_manager = unsafe { libc::geteuid() } != 0;
    let out = systemd_run_command(&sess, &path, &[], user_manager)
        .output()
        .context("spawning systemd-run")?;
    if !out.status.success() {
        anyhow::bail!(
            "systemd-run failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(EnsureOutcome::Started)
}

/// Where the Linux companion lives: `/usr/bin` from its .deb, `/usr/local/bin`
/// for a hand install. One list, so every caller agrees on which file is
/// "the" companion.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn linux_companion_path() -> Option<std::path::PathBuf> {
    ["/usr/bin", "/usr/local/bin"]
        .iter()
        .map(|d| std::path::Path::new(d).join("meshharbor-desktop"))
        .find(|p| p.exists())
}

/// `systemd-run` for the companion in `sess`, as its own transient unit — so
/// it is NOT a child in the daemon's cgroup, which systemd kills with the
/// daemon on every restart or update.
///
/// * `user_manager = false` — a ROOT daemon: a system transient unit running
///   as the session's uid (`--uid=`), the shape FR-27's consent path has used
///   since it shipped.
/// * `user_manager = true` — a per-user daemon: the user's own manager
///   (`--user`); the system manager would ask polkit for a password nobody is
///   there to type.
///
/// Either way the session's bus and display go along as `--setenv`: a
/// transient unit starts with an empty environment.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn systemd_run_command(
    sess: &GraphicalSession,
    exe: &std::path::Path,
    args: &[&str],
    user_manager: bool,
) -> std::process::Command {
    let mut cmd = std::process::Command::new("systemd-run");
    if user_manager {
        cmd.arg("--user");
    }
    cmd.args(["--quiet", "--collect"]);
    if !user_manager {
        cmd.arg(format!("--uid={}", sess.uid));
    }
    cmd.args([
        format!("--setenv=XDG_RUNTIME_DIR=/run/user/{}", sess.uid),
        format!(
            "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{}/bus",
            sess.uid
        ),
    ]);
    if let Some(display) = &sess.display {
        cmd.arg(format!("--setenv=DISPLAY={display}"));
    }
    if let Some(wayland) = &sess.wayland_display {
        cmd.arg(format!("--setenv=WAYLAND_DISPLAY={wayland}"));
    }
    cmd.arg(exe.as_os_str());
    cmd.args(args);
    cmd
}

/// Is a `meshharbor-desktop` of THIS user running? `pgrep -u` so another user's
/// companion on a shared machine does not count as this person's.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn companion_running_for_uid(uid: u32) -> bool {
    std::process::Command::new("pgrep")
        .args(["-x", "-u", &uid.to_string(), "meshharbor-desktop"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

/// ⚠️ `pub(crate)` because FR-45's portal helper needs the same answer: the
/// portal is per-user-session and the daemon is root, so *both* the consent
/// companion and the capture helper have to find whoever is at the screen.
/// Two copies of this `loginctl` walk would be two things to keep in step
/// with a compositor that reports its session differently.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) struct GraphicalSession {
    pub(crate) uid: u32,
    /// The account NAME. `systemd-run --uid=` takes the number, but the
    /// verified privilege drop resolves by name (`getpwnam` gives it the home
    /// directory and supplementary groups a uid alone cannot), so both are
    /// carried rather than re-derived at each call site.
    ///
    /// ⚠️ The allow is scoped to lanes with no reader rather than blanket, so
    /// if the portal helper ever stops using this the warning comes back
    /// instead of staying suppressed forever. Kept unconditional (rather than
    /// `cfg`-gated) because gating one field fragments the struct, its single
    /// constructor and the guard that fills it, for a string that costs
    /// nothing to carry.
    #[cfg_attr(
        not(all(target_os = "linux", feature = "portal-capture")),
        allow(dead_code)
    )]
    pub(crate) name: String,
    pub(crate) display: Option<String>,
    pub(crate) wayland_display: Option<String>,
}

/// Session ids out of `loginctl list-sessions --no-legend`.
///
/// ⚠️ **Only the first column is parsed, and that is the whole point.** The
/// rest of the table is not stable across systemd releases — measured on the
/// fleet, systemd 255 lays it out `SESSION UID USER SEAT TTY STATE IDLE SINCE`
/// and systemd 257 lays it out `SESSION UID USER SEAT LEADER CLASS TTY IDLE
/// SINCE`. Anything read positionally from those would be a different field
/// per host. The id is column one on both; every real property comes from
/// `show-session`, which is key=value and version-stable.
///
/// ⚠️ Ids are NOT numeric — logind hands out `c1`, `c2` for greeter sessions —
/// so they stay strings.
#[cfg(all(unix, not(target_os = "macos")))]
fn session_ids(list_output: &str) -> Vec<&str> {
    list_output
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect()
}

/// The active graphical login session, via `loginctl`. `None` on a headless
/// box — again, the correct answer, not a failure.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn graphical_session() -> Result<GraphicalSession> {
    graphical_session_matching(None, false)
}

/// [`graphical_session`], optionally restricted to one user's sessions — a
/// per-user daemon may only open something in its OWN user's session — and
/// optionally to `Class=user`: a display manager's greeter (GDM runs one as
/// uid `gdm` at the login screen) IS an active graphical session, which the
/// consent path wants and the post-install launch must never open into.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn graphical_session_matching(
    want_uid: Option<u32>,
    users_only: bool,
) -> Result<GraphicalSession> {
    // ⚠️ NOT `-o value -p Id`. Those are `show-*` options; `list-sessions`
    // rejects them with `Unknown output 'value'` and exits 1, which this
    // function then read as an empty session list — i.e. "nobody is at the
    // screen" on every Linux host, always. Measured on systemd 255 (Ubuntu)
    // and 257 (Fedora): rejected on both, so it never worked anywhere rather
    // than regressing. The visible symptom was the FR-27 consent companion
    // silently never starting, which only shows up where the companion is the
    // chosen surface — GNOME/KDE Wayland, exactly the hosts FR-45 targets.
    let out = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend", "--no-pager"])
        .output()
        .context("spawning loginctl")?;
    for id in session_ids(&String::from_utf8_lossy(&out.stdout)) {
        let show = std::process::Command::new("loginctl")
            .args(["show-session", id, "--no-pager"])
            .output()
            .context("loginctl show-session")?;
        let text = String::from_utf8_lossy(&show.stdout);
        let field = |k: &str| show_field(&text, k);
        let ty = field("Type").unwrap_or_default();
        if ty != "x11" && ty != "wayland" {
            continue;
        }
        if field("Active").as_deref() != Some("yes") {
            continue;
        }
        if users_only && field("Class").as_deref() != Some("user") {
            continue;
        }
        let Some(uid) = field("User").and_then(|u| u.parse::<u32>().ok()) else {
            continue;
        };
        if want_uid.is_some_and(|w| w != uid) {
            continue;
        }
        // A session with no `Name` is not usable by the privilege drop, so
        // skip it rather than return one that will fail later — the next
        // session in the list may well be serviceable.
        let Some(name) = field("Name") else {
            continue;
        };
        return Ok(GraphicalSession {
            uid,
            name,
            display: field("Display"),
            wayland_display: (ty == "wayland").then(|| {
                // loginctl does not report WAYLAND_DISPLAY; the near-universal
                // default is what the compositor sets, and a wrong guess just
                // makes the app fall back to its own discovery.
                "wayland-0".to_string()
            }),
        });
    }
    anyhow::bail!("no active graphical session — nobody is at this machine's screen")
}

/// One property out of `loginctl show-*` output, which is `key=value` per
/// line and stable across systemd releases (see [`session_ids`]). `None`
/// when absent or empty.
#[cfg(any(all(unix, not(target_os = "macos")), test))]
fn show_field(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// FR-97 P5a — the account of the person signed in at this machine's own
/// screen and keyboard: the user of logind's `ActiveSession` on `seat0`, when
/// that session is a person's (`Class=user`), graphical or a text console.
///
/// Not [`graphical_session`], which takes the first active graphical session
/// ANYWHERE: a remote desktop's session (xrdp) sits on no seat, and logind
/// calls every seatless session active, so it would name someone who is not
/// at the screen at all. `seat0` is the machine's own screen by definition,
/// and its active session is the one showing, as Windows' console session
/// is. `Err` says why nobody is there: no logind, an empty seat, the login
/// screen.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn seat0_user() -> Result<String> {
    let loginctl = |args: &[&str]| -> Result<String> {
        let out = std::process::Command::new("loginctl")
            .args(args)
            .arg("--no-pager")
            .output()
            .context("spawning loginctl (is systemd-logind running?)")?;
        if !out.status.success() {
            anyhow::bail!(
                "loginctl {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let id = seat0_active_session(&loginctl(&["show-seat", "seat0"])?)?;
    session_person(&id, &loginctl(&["show-session", &id])?)
}

/// The pure half of [`seat0_user`]: the active session out of `loginctl
/// show-seat seat0`.
#[cfg(any(all(unix, not(target_os = "macos")), test))]
fn seat0_active_session(seat: &str) -> Result<String> {
    show_field(seat, "ActiveSession").ok_or_else(|| {
        anyhow::anyhow!(
            "nobody is signed in at this machine's screen (seat0 has no active session)"
        )
    })
}

/// The pure half of [`seat0_user`]: the person whose session `id` is, out of
/// `loginctl show-session <id>`, or why it is nobody's. A display manager's
/// greeter (GDM runs one as `gdm` at the login screen) is `Class=greeter`.
#[cfg(any(all(unix, not(target_os = "macos")), test))]
fn session_person(id: &str, session: &str) -> Result<String> {
    match show_field(session, "Class").as_deref() {
        Some("user") => {}
        Some("greeter") => anyhow::bail!(
            "nobody is signed in at this machine's screen (the login screen is showing, \
             session {id})"
        ),
        other => anyhow::bail!(
            "nobody is signed in at this machine's screen (seat0's session {id} is of class \
             {}, not a person's)",
            other.unwrap_or("unknown")
        ),
    }
    show_field(session, "Name")
        .ok_or_else(|| anyhow::anyhow!("seat0's session {id} names no account"))
}

/// Is a process with this exact name running? An exact-name match (`pgrep -x`)
/// cannot be fooled by a command line that merely mentions the binary. macOS
/// only: Linux asks for the session user's own (`companion_running_for_uid`,
/// FR-93 P6b).
#[cfg(target_os = "macos")]
fn pgrep_running(name: &str) -> bool {
    std::process::Command::new("pgrep")
        .args(["-x", name])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "windows", unix)))]
async fn ensure_running_inner() -> Result<EnsureOutcome> {
    Ok(EnsureOutcome::Unsupported)
}

/// Entry point — spawn-and-forget from daemon startup. Never fails the
/// caller; every error path logs and returns (retry on next start).
pub async fn refresh_if_stale(respawn: RespawnContext) {
    #[cfg(target_os = "windows")]
    if let Err(e) = refresh_inner(respawn).await {
        tracing::warn!(error = %format!("{e:#}"), "desktop companion refresh skipped");
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Windows-only BY DESIGN, not by omission — and FR-27 did not change
        // that even though the companion now ships on all three platforms.
        //
        // This function exists because the Windows companion is a standalone
        // EXE placed BESIDE the daemon by the wizard / install.ps1, in neither
        // MSI, so nothing else would ever move it forward. The macOS .pkg
        // carries `/Applications/MeshHarbor.app`. On Linux the companion is its
        // own `.deb`/`.rpm`, which ⚠️ NOTHING upgraded (there is no apt or dnf
        // repository): FR-117 moves it through the host's package manager, in
        // the updater's loop (`sync_package`), never by swapping a file the
        // package manager owns.
        let _ = respawn;
    }
}

#[cfg(target_os = "windows")]
async fn refresh_inner(respawn: RespawnContext) -> Result<()> {
    let own_version = env!("CARGO_PKG_VERSION");
    let exe_dir = std::env::current_exe()
        .context("locating own exe")?
        .parent()
        .context("own exe has no parent dir")?
        .to_path_buf();
    let dest = exe_dir.join(DESKTOP_EXE);
    let marker = exe_dir.join(VERSION_MARKER);

    // Fresh marker + EXE present → nothing to do (the common case on
    // every startup after the first successful swap).
    let recorded = std::fs::read_to_string(&marker)
        .ok()
        .map(|s| s.trim().to_string());
    if dest.exists() && recorded.as_deref() == Some(own_version) {
        return Ok(());
    }
    tracing::info!(
        own = own_version,
        recorded = recorded.as_deref().unwrap_or("<none>"),
        present = dest.exists(),
        "desktop companion is stale/missing — refreshing"
    );

    // Resolve the desktop asset from OUR OWN release tag. `agent-v<ver>`
    // is the tag scheme release-agent.yml pushes; a dev build whose
    // version was never released just logs a clean skip here.
    let tag = format!("agent-v{own_version}");
    let release = crate::updater::fetch_release_by_tag(&tag)
        .await
        .with_context(|| format!("fetching release {tag}"))?;
    let asset = pick_desktop_asset(&release.assets)
        .with_context(|| format!("no meshharbor-desktop asset in release {tag}"))?;
    // The tag is OUR OWN version, so there is no version claim to be lied to
    // about here — but pass it anyway: the day the desktop EXE gains a
    // readable version binding, this call site should not need finding.
    let staged = crate::updater::download_asset(asset, &tag)
        .await
        .with_context(|| format!("downloading {}", asset.name))?;

    // #1686 — the swap, in the order `swap` pins (see there), on the blocking
    // pool: it stops processes and waits for them.
    let outcome = tokio::task::spawn_blocking(move || {
        let mut ops = FsSwap {
            new: exe_dir.join(NEW_SUFFIX),
            old: exe_dir.join(OLD_SUFFIX),
            staged,
            dest,
            marker,
            version: own_version,
            respawn,
        };
        swap(&mut ops)
    })
    .await
    .context("the companion swap task")?;
    match outcome {
        SwapOutcome::Swapped { respawned, stopped } => {
            tracing::info!(
                version = own_version,
                respawned,
                ?stopped,
                "desktop companion refreshed"
            );
            Ok(())
        }
        SwapOutcome::Aborted {
            reason,
            respawned_old,
        } => {
            anyhow::bail!(
                "{reason} (the old companion is untouched; respawned it: {respawned_old})"
            )
        }
    }
}

/// #1686 — what the companion swap does to the disk and to running processes,
/// behind a seam so `swap`'s ORDER is tested on every platform.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) trait SwapOps {
    /// Copy the new EXE in BESIDE the old one (`…exe.new`); the old one and
    /// every running companion are still untouched.
    fn stage(&mut self) -> Result<()>;
    /// Running companions (pids) started from the installed path.
    fn running(&mut self) -> Vec<u32>;
    /// Stop those pids — each re-verified on the handle that kills it — and
    /// return the ones confirmed exited.
    fn stop(&mut self, pids: &[u32]) -> Vec<u32>;
    /// Installed EXE → `…exe.old`.
    fn rename_old_aside(&mut self) -> Result<()>;
    /// `…exe.new` → installed EXE (same directory: an atomic rename).
    fn promote_new(&mut self) -> Result<()>;
    /// `…exe.old` → installed EXE (rollback).
    fn restore_old(&mut self);
    /// Remove `…exe.new`.
    fn discard_new(&mut self);
    fn write_marker(&mut self);
    /// Start the companion at the installed path (whichever EXE is there).
    fn respawn(&mut self);
    /// Remove `…exe.old`, best-effort.
    fn remove_old(&mut self);
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SwapOutcome {
    Swapped {
        respawned: bool,
        stopped: Vec<u32>,
    },
    /// Nothing changed on disk. `respawned_old` = companions this swap had
    /// already stopped were started again, from the old EXE.
    Aborted {
        reason: String,
        respawned_old: bool,
    },
}

/// #1686 — the companion swap in the only order that can never leave a
/// companion dead, or a live image renamed:
///
/// 1. stage the new copy beside the old one — a failure here touches nothing;
/// 2. stop every running companion (verified per handle);
/// 3. if ANY could not be stopped, abort: renaming a live image aside is how
///    #1686 started, and a survivor would keep the single-instance lock anyway;
/// 4. only now rename old → `.old` and new → installed;
/// 5. respawn if something was running — the NEW one on success, the OLD one
///    on every abort after step 2 (a person's tray is never left gone).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))] // exercised by `swap_tests` everywhere
pub(crate) fn swap<O: SwapOps>(ops: &mut O) -> SwapOutcome {
    if let Err(e) = ops.stage() {
        return SwapOutcome::Aborted {
            reason: format!("staging the new companion failed: {e:#}"),
            respawned_old: false,
        };
    }
    let pids = ops.running();
    let stopped = if pids.is_empty() {
        Vec::new()
    } else {
        ops.stop(&pids)
    };
    // Put back what this swap stopped, from whatever EXE is installed.
    let abort = |ops: &mut O, reason: String, stopped: &[u32]| {
        ops.discard_new();
        let respawn = !stopped.is_empty();
        if respawn {
            ops.respawn();
        }
        SwapOutcome::Aborted {
            reason,
            respawned_old: respawn,
        }
    };
    if stopped.len() != pids.len() {
        return abort(
            ops,
            format!(
                "could not stop every running companion (running {pids:?}, stopped {stopped:?})"
            ),
            &stopped,
        );
    }
    if let Err(e) = ops.rename_old_aside() {
        return abort(
            ops,
            format!("moving the old companion aside failed: {e:#}"),
            &stopped,
        );
    }
    if let Err(e) = ops.promote_new() {
        ops.restore_old();
        return abort(
            ops,
            format!("putting the new companion in place failed: {e:#}"),
            &stopped,
        );
    }
    ops.write_marker();
    let respawned = !stopped.is_empty();
    if respawned {
        ops.respawn();
    }
    ops.remove_old();
    SwapOutcome::Swapped { respawned, stopped }
}

#[cfg(target_os = "windows")]
struct FsSwap {
    staged: std::path::PathBuf,
    dest: std::path::PathBuf,
    new: std::path::PathBuf,
    old: std::path::PathBuf,
    marker: std::path::PathBuf,
    version: &'static str,
    respawn: RespawnContext,
}

#[cfg(target_os = "windows")]
impl SwapOps for FsSwap {
    fn stage(&mut self) -> Result<()> {
        let _ = std::fs::remove_file(&self.new);
        std::fs::copy(&self.staged, &self.new)
            .map(|_| ())
            .context("copying the new desktop EXE beside the installed one")
    }
    fn running(&mut self) -> Vec<u32> {
        crate::win_service::companion_procs::find(&self.dest)
            .iter()
            .map(|p| p.pid)
            .collect()
    }
    fn stop(&mut self, pids: &[u32]) -> Vec<u32> {
        crate::win_service::companion_procs::terminate_verified(
            &self.dest,
            pids,
            std::time::Duration::from_secs(10),
        )
    }
    fn rename_old_aside(&mut self) -> Result<()> {
        // A `.old` from an earlier cycle: its process (if it had one) was
        // started from the installed path, so `running`/`stop` above found and
        // stopped it — the file is free now.
        let _ = std::fs::remove_file(&self.old);
        if self.dest.exists() {
            std::fs::rename(&self.dest, &self.old).context("renaming the desktop EXE aside")?;
        }
        Ok(())
    }
    fn promote_new(&mut self) -> Result<()> {
        std::fs::rename(&self.new, &self.dest).context("renaming the new desktop EXE into place")
    }
    fn restore_old(&mut self) {
        if self.old.exists() {
            let _ = std::fs::rename(&self.old, &self.dest);
        }
    }
    fn discard_new(&mut self) {
        let _ = std::fs::remove_file(&self.new);
    }
    fn write_marker(&mut self) {
        if let Err(e) = std::fs::write(&self.marker, format!("{}\n", self.version)) {
            tracing::warn!(error = %e, "could not write desktop version marker");
        }
    }
    fn respawn(&mut self) {
        respawn_desktop(self.respawn, &self.dest);
    }
    fn remove_old(&mut self) {
        // A stopped process may take a moment to release its image; a few
        // short retries, then leave it for the next cycle.
        for _ in 0..3 {
            if std::fs::remove_file(&self.old).is_ok() || !self.old.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

/// Prefer the signed EXE (no `-unsigned` infix) when both are present.
#[cfg(target_os = "windows")]
fn pick_desktop_asset(
    assets: &[crate::updater::GithubAsset],
) -> Option<&crate::updater::GithubAsset> {
    let is_desktop = |name: &str| {
        let lower = name.to_lowercase();
        lower.starts_with("meshharbor-desktop-") && lower.ends_with(".exe")
    };
    assets
        .iter()
        .find(|a| is_desktop(&a.name) && !a.name.to_lowercase().contains("-unsigned"))
        .or_else(|| assets.iter().find(|a| is_desktop(&a.name)))
}

/// The companion beside this daemon — the one install whose companion this
/// process refreshes, launches and asks about.
#[cfg(target_os = "windows")]
fn sibling_desktop() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(DESKTOP_EXE)))
}

/// Is the companion beside this daemon running? Matched by the path it was
/// STARTED from (#1686), not by image name: a companion whose file an update
/// renamed or deleted keeps running under a file-id image name, and a
/// `tasklist IMAGENAME` check stops seeing it. `pub`: the S1b appdirs
/// migration skips while the desktop runs (it may hold open handles inside
/// the tree being moved).
#[cfg(target_os = "windows")]
pub fn desktop_running() -> bool {
    sibling_desktop().is_some_and(|exe| !crate::win_service::companion_procs::find(&exe).is_empty())
}

/// Is the companion running in Terminal Services session `session`? The
/// launcher's question is "does THIS user already have it open", which a
/// machine-wide listing cannot answer on a host with more than one session.
#[cfg(target_os = "windows")]
pub(crate) fn desktop_running_in_session(session: u32) -> bool {
    sibling_desktop().is_some_and(|exe| {
        crate::win_service::companion_procs::find(&exe)
            .iter()
            .any(|p| p.session == Some(session))
    })
}

#[cfg(target_os = "windows")]
fn respawn_desktop(respawn: RespawnContext, dest: &std::path::Path) {
    match respawn {
        // FR-84 D6 / #1035 — NOT `std::process::Command`: that passes
        // `bInheritHandles = TRUE`, and a companion lives for months holding
        // whatever this daemon had marked inheritable at the spawn instant.
        RespawnContext::UserSession => {
            match crate::win_service::companion_spawn::spawn_detached_no_inherit(dest, &[]) {
                Ok(pid) => tracing::info!(pid, "desktop companion respawned (user session)"),
                Err(e) => tracing::warn!(error = %e, "desktop companion respawn failed"),
            }
        }
        RespawnContext::SystemService => {
            use crate::win_service::supervisor;
            let Some(session_id) = supervisor::active_console_session_id() else {
                tracing::info!(
                    "no active interactive session; desktop starts on next manual launch"
                );
                return;
            };
            match supervisor::query_user_token(session_id) {
                Ok(Some(token)) => {
                    // SAFETY: `token` is a live user token from
                    // WTSQueryUserToken, held for the duration of the call.
                    match unsafe { supervisor::spawn_in_session(token.raw(), dest, &[]) } {
                        Ok(_) => {
                            tracing::info!(session_id, "desktop companion respawned in session")
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "desktop companion session respawn failed")
                        }
                    }
                }
                Ok(None) => tracing::info!(
                    session_id,
                    "no user token for active session; desktop starts on next login"
                ),
                Err(e) => tracing::warn!(error = %e, "query_user_token failed for desktop respawn"),
            }
        }
    }
}

/// #1686 — the companion swap's ORDER, on every platform (the Windows ops
/// themselves are exercised by `win_service::companion_procs`' tests, which run
/// only where Windows does).
#[cfg(test)]
mod swap_tests {
    use super::{SwapOps, SwapOutcome, swap};
    use anyhow::{Result, anyhow};

    #[derive(Default)]
    struct Mock {
        calls: Vec<&'static str>,
        stage_fails: bool,
        running: Vec<u32>,
        /// `None` = stop everything asked.
        stops_only: Option<Vec<u32>>,
        aside_fails: bool,
        promote_fails: bool,
    }

    impl SwapOps for Mock {
        fn stage(&mut self) -> Result<()> {
            self.calls.push("stage");
            if self.stage_fails {
                Err(anyhow!("disk full"))
            } else {
                Ok(())
            }
        }
        fn running(&mut self) -> Vec<u32> {
            self.calls.push("running");
            self.running.clone()
        }
        fn stop(&mut self, pids: &[u32]) -> Vec<u32> {
            self.calls.push("stop");
            self.stops_only.clone().unwrap_or_else(|| pids.to_vec())
        }
        fn rename_old_aside(&mut self) -> Result<()> {
            self.calls.push("rename_old_aside");
            if self.aside_fails {
                Err(anyhow!("sharing violation"))
            } else {
                Ok(())
            }
        }
        fn promote_new(&mut self) -> Result<()> {
            self.calls.push("promote_new");
            if self.promote_fails {
                Err(anyhow!("access denied"))
            } else {
                Ok(())
            }
        }
        fn restore_old(&mut self) {
            self.calls.push("restore_old");
        }
        fn discard_new(&mut self) {
            self.calls.push("discard_new");
        }
        fn write_marker(&mut self) {
            self.calls.push("write_marker");
        }
        fn respawn(&mut self) {
            self.calls.push("respawn");
        }
        fn remove_old(&mut self) {
            self.calls.push("remove_old");
        }
    }

    #[test]
    fn a_running_companion_is_stopped_before_any_rename_and_respawned_after() {
        let mut m = Mock {
            running: vec![7, 9],
            ..Default::default()
        };
        let out = swap(&mut m);
        assert_eq!(
            out,
            SwapOutcome::Swapped {
                respawned: true,
                stopped: vec![7, 9]
            }
        );
        assert_eq!(
            m.calls,
            [
                "stage",
                "running",
                "stop",
                "rename_old_aside",
                "promote_new",
                "write_marker",
                "respawn",
                "remove_old"
            ]
        );
    }

    #[test]
    fn nothing_running_swaps_without_a_respawn() {
        let mut m = Mock::default();
        assert_eq!(
            swap(&mut m),
            SwapOutcome::Swapped {
                respawned: false,
                stopped: vec![]
            }
        );
        assert!(!m.calls.contains(&"stop") && !m.calls.contains(&"respawn"));
    }

    /// A failed copy leaves everything as it was — and, before this ordering,
    /// the companion had already been killed by then and was never respawned.
    #[test]
    fn a_failed_stage_touches_nothing_and_kills_nothing() {
        let mut m = Mock {
            stage_fails: true,
            running: vec![7],
            ..Default::default()
        };
        let out = swap(&mut m);
        assert!(matches!(
            out,
            SwapOutcome::Aborted {
                respawned_old: false,
                ..
            }
        ));
        assert_eq!(m.calls, ["stage"]);
    }

    /// Renaming a LIVE image aside is how #1686 began: if any companion
    /// survives the stop, nothing is renamed — and the ones that were stopped
    /// are started again, from the old EXE still installed.
    #[test]
    fn a_companion_that_would_not_stop_aborts_before_any_rename() {
        let mut m = Mock {
            running: vec![7, 9],
            stops_only: Some(vec![7]),
            ..Default::default()
        };
        let out = swap(&mut m);
        assert!(matches!(
            out,
            SwapOutcome::Aborted {
                respawned_old: true,
                ..
            }
        ));
        assert_eq!(
            m.calls,
            ["stage", "running", "stop", "discard_new", "respawn"]
        );
        assert!(!m.calls.contains(&"rename_old_aside"));
    }

    #[test]
    fn a_failed_move_aside_respawns_the_old_companion() {
        let mut m = Mock {
            running: vec![7],
            aside_fails: true,
            ..Default::default()
        };
        let out = swap(&mut m);
        assert!(matches!(
            out,
            SwapOutcome::Aborted {
                respawned_old: true,
                ..
            }
        ));
        assert_eq!(
            m.calls,
            [
                "stage",
                "running",
                "stop",
                "rename_old_aside",
                "discard_new",
                "respawn"
            ]
        );
    }

    #[test]
    fn a_failed_promote_restores_the_old_exe_then_respawns_it() {
        let mut m = Mock {
            running: vec![7],
            promote_fails: true,
            ..Default::default()
        };
        let out = swap(&mut m);
        assert!(matches!(
            out,
            SwapOutcome::Aborted {
                respawned_old: true,
                ..
            }
        ));
        assert_eq!(
            m.calls,
            [
                "stage",
                "running",
                "stop",
                "rename_old_aside",
                "promote_new",
                "restore_old",
                "discard_new",
                "respawn"
            ]
        );
    }

    /// Nothing was running and a rename failed: nothing to put back.
    #[test]
    fn an_abort_with_nothing_stopped_respawns_nothing() {
        let mut m = Mock {
            promote_fails: true,
            ..Default::default()
        };
        let out = swap(&mut m);
        assert!(matches!(
            out,
            SwapOutcome::Aborted {
                respawned_old: false,
                ..
            }
        ));
        assert!(!m.calls.contains(&"respawn"));
    }
}

#[cfg(all(test, unix, not(target_os = "macos")))]
mod tests {
    use super::session_ids;

    /// FR-84 D6 — the companion runs as its OWN transient unit, never in the
    /// daemon's cgroup; a root daemon targets the session's uid, a per-user
    /// daemon its own manager (no polkit prompt nobody can answer), and the
    /// session's bus + display travel along.
    #[test]
    fn systemd_run_command_for_root_and_for_a_user_daemon() {
        let sess = super::GraphicalSession {
            uid: 1000,
            name: "ana".into(),
            display: Some(":0".into()),
            wayland_display: Some("wayland-0".into()),
        };
        let argv = |user: bool| -> Vec<String> {
            let cmd = super::systemd_run_command(
                &sess,
                std::path::Path::new("/usr/bin/meshharbor-desktop"),
                &["--first-run"],
                user,
            );
            assert_eq!(cmd.get_program(), "systemd-run");
            cmd.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let root = argv(false);
        assert!(root.contains(&"--uid=1000".to_string()), "{root:?}");
        assert!(!root.contains(&"--user".to_string()), "{root:?}");
        for want in [
            "--collect",
            "--setenv=XDG_RUNTIME_DIR=/run/user/1000",
            "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            "--setenv=DISPLAY=:0",
            "--setenv=WAYLAND_DISPLAY=wayland-0",
        ] {
            assert!(root.contains(&want.to_string()), "{want} missing: {root:?}");
        }
        assert_eq!(
            &root[root.len() - 2..],
            ["/usr/bin/meshharbor-desktop", "--first-run"],
            "the program, then its own arguments, last"
        );
        let user = argv(true);
        assert_eq!(user[0], "--user");
        assert!(!user.iter().any(|a| a.starts_with("--uid=")), "{user:?}");
        assert!(user.contains(&"--setenv=DISPLAY=:0".to_string()));
    }

    /// Both samples are REAL `loginctl list-sessions --no-legend --no-pager`
    /// output, captured from fleet hosts on 2026-08-31. They are here because
    /// the column layout genuinely differs between the two releases, and the
    /// previous code's failure was invisible: it asked for a `show-*` output
    /// mode that `list-sessions` rejects, got an empty list, and reported
    /// "nobody is at this machine's screen" on a host with a logged-in user.
    /// A test over invented output would have passed just as happily.
    #[test]
    fn session_ids_survive_both_observed_column_layouts() {
        // systemd 255 (Ubuntu 24.04): SESSION UID USER SEAT TTY STATE IDLE SINCE
        let s255 = "7173 1000 gjovanov - -     active no  -\n\
                    7631 1000 gjovanov - pts/5 active yes 17h ago\n\
                    7767 1000 gjovanov - -     active no  -\n";
        assert_eq!(session_ids(s255), ["7173", "7631", "7767"]);

        // systemd 257 (Fedora 42): a LEADER and a CLASS column appear, so
        // every positional field after the first one shifts.
        let s257 = "1 1000 m1 -     1447   manager - no -\n\
                    3 1000 m1 seat0 101848 user    - no -\n\
                    5 1000 m1 -     434840 user    - no -\n";
        assert_eq!(session_ids(s257), ["1", "3", "5"]);
    }

    /// A headless host lists nothing, and blank lines must not become empty
    /// ids that then get handed to `show-session`.
    #[test]
    fn empty_and_blank_output_yields_no_ids() {
        assert!(session_ids("").is_empty());
        assert!(session_ids("\n   \n\t\n").is_empty());
    }

    /// Greeter sessions are `c1`, `c2`… — ids are strings, and a numeric
    /// parse would silently drop exactly the session a lock-screen prompt
    /// needs to find.
    #[test]
    fn non_numeric_greeter_ids_are_kept() {
        assert_eq!(session_ids("c1 42 gdm seat0 - active no -\n"), ["c1"]);
    }
}
