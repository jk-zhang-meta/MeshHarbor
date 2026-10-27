// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(3): the legacy scheduled-task name install/uninstall must still
// find.
//! Cross-platform auto-start-on-boot / login plumbing.
//!
//! `meshharbord service install` registers the agent so it launches
//! automatically on the next interactive login:
//!
//!   - **Windows**: Scheduled Task named `Roomler` (pre-P3D-rename hosts
//!     have `RoomlerAgent`, which `install()` retires and `uninstall()`
//!     deletes), ONLOGON trigger, LIMITED run level (matches the agent's
//!     un-elevated-by-design posture from `packaging/windows/README.txt`).
//!   - **Linux**: systemd user unit. The .deb already drops the unit
//!     file at `/usr/lib/systemd/user/meshharbor.service`; install
//!     here means `systemctl --user enable --now meshharbor.service`.
//!   - **macOS**: `launchctl load -w` the LaunchAgent plist. The .pkg
//!     postinstall drops it at `~/Library/LaunchAgents/com.roomler.agent.plist`;
//!     install here only needs to (re-)load it.
//!
//! All paths shell out to the system tool rather than talking to the
//! registries/D-Bus directly. Keeps the implementation small and means
//! we piggy-back on the OS's own permission prompts (e.g. macOS's
//! "Screen Recording" authorization that fires on first run).

use anyhow::{Context, Result, bail};
use std::path::Path;

/// #2293 — how this host's daemon is run, which decides what starts it again
/// after a removal stopped it (exit 7, `AGENT_DELETED_EXIT_CODE`), and so what
/// `roomlerd re-enroll` and the removal's sentinel tell the person:
///
/// | Install | After exit 7 |
/// |---|---|
/// | Linux, the system or the user unit | nothing: `RestartPreventExitStatus=7 8` |
/// | Windows, the `Roomler` service | its supervisor, at most 60 s apart, for good |
/// | Windows, the per-user task | `<RestartOnFailure>`: ten times, a minute apart |
/// | macOS, the LaunchDaemon or the LaunchAgent | launchd, on any failed exit |
///
/// Before #2293 both said "wait for the supervisor to relaunch", which on
/// Linux never comes, and offered `meshharbord run`, which by hand starts an
/// unmanaged orphan beside the unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Install {
    /// `meshharbord.service`: root, `/etc/meshharbor/config.toml`.
    LinuxSystem,
    /// `meshharbor.service`, the person's user unit.
    LinuxUser,
    /// The `Roomler` SCM service, whose supervisor runs the worker. It owns
    /// attended installs too, whose config is the person's.
    WindowsService,
    /// The per-user Scheduled Task (the perUser MSI).
    WindowsTask,
    /// launchd: the LaunchDaemon or the LaunchAgent.
    MacOs,
    /// No service manager this code knows.
    Other,
}

impl Install {
    /// The install a daemon with the config at `config_path` runs as.
    ///
    /// ⚠️ Windows asks the SCM (a read-only status query), not the path: an
    /// attended service install keeps its config in the person's profile, as
    /// a per-user install does. A failed query takes the per-user answer,
    /// whose words fit both.
    pub fn detect(config_path: &Path) -> Self {
        #[cfg(target_os = "linux")]
        {
            if config_path == crate::appdirs::system_config_path()
                || crate::appdirs::running_as_root()
            {
                Self::LinuxSystem
            } else {
                Self::LinuxUser
            }
        }
        #[cfg(target_os = "windows")]
        {
            let _ = config_path;
            match crate::win_service::status() {
                Ok(crate::win_service::InstalledStatus::NotInstalled) | Err(_) => Self::WindowsTask,
                Ok(_) => Self::WindowsService,
            }
        }
        #[cfg(target_os = "macos")]
        {
            let _ = config_path;
            Self::MacOs
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            let _ = config_path;
            Self::Other
        }
    }

    /// What `roomlerd re-enroll` ends with. `primary`: the enrollment it
    /// refreshed is the config's own. A secondary organization's loop ended
    /// at its goodbye, and only a daemon restart starts it again.
    pub fn after_re_enroll(self, primary: bool) -> &'static str {
        if !primary {
            return match self {
                Self::LinuxSystem => {
                    "This organization connects again when the daemon restarts: \
                     `sudo systemctl restart roomlerd`."
                }
                Self::Other => "This organization connects again when the daemon restarts.",
                _ => {
                    "This organization connects again when the daemon restarts: \
                     `roomler restart`."
                }
            };
        }
        match self {
            Self::LinuxSystem => {
                "Start the daemon: `sudo systemctl start roomlerd`. systemd does not \
                 restart a daemon the server removed (exit 7). If it is still running, \
                 `sudo systemctl restart roomlerd` makes it use the new token now."
            }
            Self::LinuxUser => {
                "Start the daemon: `meshharbord service start`. systemd does not restart \
                 a daemon the server removed (exit 7). If it is still running, \
                 `roomler restart` makes it use the new token now."
            }
            Self::WindowsService => {
                "The Roomler service starts the agent again within a minute, with the \
                 new token. If it is still running, `roomler restart` makes it use the \
                 new token now."
            }
            Self::WindowsTask => {
                "The agent's task starts it again within a minute, with the new token, \
                 but only ten times after a removal: if it is not back, start it with \
                 `meshharbord service start`. If it is still running, `roomler restart` \
                 makes it use the new token now."
            }
            Self::MacOs => {
                "launchd starts the agent again within seconds, with the new token. If \
                 it is still running, `roomler restart` makes it use the new token now."
            }
            Self::Other => "Start the daemon again: `meshharbord run`, or your service manager.",
        }
    }

    /// #2371 — what `meshharbord enroll` ends with. `secondary`: the enrollment
    /// added (or refreshed) an `[[orgs]]` entry, whose loop only a daemon
    /// restart starts. A fresh primary may land on a daemon that is stopped,
    /// waiting for its config, or running, so each step names a command that
    /// connects it in every one of those states. `meshharbord run` comes last, for
    /// a host without the package: beside a service manager it is an orphan.
    pub fn after_enroll(self, secondary: bool) -> &'static str {
        if secondary {
            return match self {
                Self::LinuxSystem => {
                    "This organization connects when the daemon restarts: \
                     `sudo systemctl restart roomlerd`."
                }
                Self::Other => "This organization connects when the daemon restarts.",
                _ => "This organization connects when the daemon restarts: `roomler restart`.",
            };
        }
        match self {
            Self::LinuxSystem => {
                "Start the daemon: `sudo systemctl restart roomlerd`, which starts it \
                 whether it was stopped, failed or running. On a host without the \
                 package: `meshharbord run`."
            }
            Self::LinuxUser => {
                "Start the daemon: `meshharbord service start` (`meshharbord service install` \
                 also starts it at every login). If it is running already, \
                 `roomler restart` connects it now. On a host without the package: \
                 `meshharbord run`."
            }
            Self::WindowsService => {
                "The Roomler service starts the agent within a minute. If it is running \
                 already, `roomler restart` connects it now."
            }
            Self::WindowsTask => {
                "Start the agent: `meshharbord service start` (`meshharbord service install` \
                 first, if this account has no task). If it is running already, \
                 `roomler restart` connects it now."
            }
            Self::MacOs => {
                "launchd starts the agent within seconds. If it is running already, \
                 `roomler restart` connects it now."
            }
            Self::Other => "Start the daemon: `meshharbord run`, or your service manager.",
        }
    }

    /// The last line of the removal's sentinel, after the `re-enroll` command
    /// it names.
    pub fn after_removal(self) -> &'static str {
        match self {
            Self::LinuxSystem => {
                "then start it: sudo systemctl start roomlerd\n\
                 (systemd does not restart a daemon the server removed)."
            }
            Self::LinuxUser => {
                "then start it: meshharbord service start\n\
                 (systemd does not restart a daemon the server removed)."
            }
            Self::WindowsService => {
                "and the Roomler service starts it again within a minute, with the new token."
            }
            Self::WindowsTask => {
                "and its task starts it again within a minute, but only ten times;\n\
                 after that: meshharbord service start"
            }
            Self::MacOs => "and launchd starts it again within seconds, with the new token.",
            Self::Other => "then start the daemon again.",
        }
    }
}

/// Status of the auto-start hook as reported by the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutostartStatus {
    /// Registered and will launch on next login.
    Installed,
    /// No trace of the hook — `install` would be a no-op if called
    /// repeatedly.
    NotInstalled,
    /// OS tool returned something unexpected or unreachable. Treat as
    /// inconclusive; operator should investigate manually.
    Unknown,
}

impl std::fmt::Display for AutostartStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutostartStatus::Installed => write!(f, "installed"),
            AutostartStatus::NotInstalled => write!(f, "not installed"),
            AutostartStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Register the agent to start on next interactive login. Idempotent:
/// re-running after a successful install is harmless on all three
/// platforms (Task Scheduler replaces with `/F`, systemctl enable on
/// an already-enabled unit is a no-op, launchctl load on an already-
/// loaded plist returns exit 0).
pub fn install() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::install()
    }
    #[cfg(target_os = "linux")]
    {
        linux::install()
    }
    #[cfg(target_os = "macos")]
    {
        macos::install()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        bail!("auto-start is not implemented on this platform")
    }
}

/// Tear down the auto-start hook. Idempotent: no-op when nothing is
/// installed (so `service uninstall` after a clean uninstall of the
/// MSI doesn't error out).
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::uninstall()
    }
    #[cfg(target_os = "linux")]
    {
        linux::uninstall()
    }
    #[cfg(target_os = "macos")]
    {
        macos::uninstall()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        bail!("auto-start is not implemented on this platform")
    }
}

/// FR-84 D3 — start the registered auto-start hook NOW: `schtasks /Run` the
/// task, `systemctl --user start` the unit, `launchctl kickstart` the agent.
///
/// The caller half of `Request::RestartDaemon` (`restart_by: "caller"`): the
/// Scheduled Task's own `<RestartOnFailure>` is a minute away at best, so the
/// companion / `roomler restart` runs this once the old daemon is gone. In
/// every flavour the daemon is then spawned by the OS's scheduler / service
/// manager — never as a child of the process calling this — so nothing of
/// the caller's is inherited by the daemon (#1035 is the reverse direction:
/// the daemon spawning the companion).
///
/// Harmless to repeat, which the caller relies on: a start that lands while
/// the old instance is still exiting is dropped by the task's `IgnoreNew`
/// policy, a running unit is a no-op, and a running LaunchAgent is left
/// alone (`kickstart` without `-k`). So the caller simply asks again until a
/// NEW daemon answers.
pub fn start() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::start()
    }
    #[cfg(target_os = "linux")]
    {
        linux::start()
    }
    #[cfg(target_os = "macos")]
    {
        macos::start()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        bail!("auto-start is not supported on this platform")
    }
}

/// FR-97 P4d — stop the running daemon of the config at `config_path` now,
/// cleanly, so a clean stop's work runs: an ephemeral device unenrolls itself.
/// Returns what happened, in words.
///
/// - Windows: the per-user daemon is asked through its own stop event, and its
///   task is ended (`TerminateProcess`) only if it does not leave in time.
/// - Linux: `systemctl --user stop`, a SIGTERM, which the daemon already turns
///   into a clean stop. A system install's unit is root's, so that one is named
///   rather than stopped.
/// - macOS: `launchctl kill SIGTERM` the LaunchAgent. The clean stop exits 0,
///   and the plist's `KeepAlive = {SuccessfulExit = false}` restarts only a
///   FAILED exit, so it stays down until the next login or `service start`.
///   P4d refused here, believing launchd would restart it; FR-97 P6c measured
///   on macOS 15 that it does not (exit 0, `runs` unchanged for 24 s), and the
///   stop confirms that each time rather than assuming it.
pub fn stop(config_path: &Path) -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        windows::stop(config_path)
    }
    #[cfg(target_os = "linux")]
    {
        if Install::detect(config_path) == Install::LinuxSystem {
            bail!(
                "this daemon is the system service, which runs as root: `sudo meshharbord service \
                 stop --as-service` stops it the same way, with a SIGTERM"
            );
        }
        linux::stop()
    }
    #[cfg(target_os = "macos")]
    {
        let _ = config_path;
        macos::stop()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = config_path;
        bail!("auto-start is not supported on this platform")
    }
}

/// FR-93 P5 (#2144) — at start, a per-user Linux daemon whose unit file wants it
/// by `graphical-session.target` as well, while only `default.target` links to
/// it (it was enabled before that target joined the unit's `[Install]`), enables
/// it again once, so the next login starts it again. Runs on its own thread and
/// never blocks the caller; a no-op as root and off Linux. Kill switch
/// `ROOMLERD_UNIT_REPAIR=0`.
pub fn repair_session_wants_at_start() {
    #[cfg(target_os = "linux")]
    linux::repair_session_wants_at_start();
}

/// #1705 — the desktop companion's service probes, recognised from RAW argv:
/// `Some(false)` for `service status`, `Some(true)` for
/// `service status --as-service`, `None` for everything else (any other
/// spelling takes the normal path, full startup included).
///
/// The companion runs both every 10 s (`probe_service_state`). They ask the
/// SERVICE MANAGER one question, so the daemon answers them before any of its
/// own startup — DPI and timer requests, the companion scan, the legacy-tree
/// migration, the persistent log file — which is read here, ahead of clap and
/// of every appdirs consumer. Taking the full startup, they flooded the
/// per-user log with ~17,000 starts a day on every companion host.
pub fn companion_probe(argv: &[String]) -> Option<bool> {
    let rest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    match rest.as_slice() {
        ["service", "status"] => Some(false),
        ["service", "status", "--as-service"] => Some(true),
        _ => None,
    }
}

/// Query whether the auto-start hook is currently registered.
pub fn status() -> Result<AutostartStatus> {
    #[cfg(target_os = "windows")]
    {
        windows::status()
    }
    #[cfg(target_os = "linux")]
    {
        linux::status()
    }
    #[cfg(target_os = "macos")]
    {
        macos::status()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Ok(AutostartStatus::Unknown)
    }
}

/// FR-97 P6c — `service <verb> --as-service` (alias `--system`) on Linux and
/// macOS: the root daemon, under the OS's own service manager. It is the verb
/// Windows has had for the SCM, and it registers what the package already
/// ships: systemd's `meshharbord.service`, launchd's `com.roomler.daemon`.
///
/// The decisions live here, free of `cfg`, so the Linux test run proves the
/// macOS ones too (CI only compiles macOS). The per-OS modules run the tools.
pub mod system {
    /// The OS a decision is for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Os {
        Linux,
        MacOs,
    }

    /// The root daemon's config on both: the system unit's `MESHHARBORD_CONFIG`
    /// and the LaunchDaemon's `--config` (pinned by tests against both).
    pub const CONFIG: &str = "/etc/meshharbor/config.toml";
    /// The system unit the `.deb` and the tarball ship.
    pub const LINUX_UNIT: &str = "meshharbord.service";
    /// Where that unit file is, on a usr-merged host and a split one.
    pub const LINUX_UNIT_FILES: [&str; 2] = [
        "/usr/lib/systemd/system/meshharbord.service",
        "/lib/systemd/system/meshharbord.service",
    ];
    // FR-96's update helper (`meshharbor-update.timer` + `.path`) is left as it
    // is, both ways: it steps aside by itself while this unit is enabled
    // (`SYSTEM_DAEMON_ENABLE_LINKS` in updater.rs) and serves again once it
    // is not, so one updater per host holds with no step here, and an
    // administrator's own disable of the helper is never undone.
    pub const MACOS_LABEL: &str = "com.roomler.daemon";
    pub const MACOS_PLIST: &str = "/Library/LaunchDaemons/com.roomler.daemon.plist";
    /// The plist the `.pkg` carries inside the bundle; its postinstall copies
    /// it to [`MACOS_PLIST`] when the marker below exists.
    pub const MACOS_PLIST_SOURCE: &str =
        "/Library/Roomler/roomlerd.app/Contents/Resources/com.roomler.daemon.plist";
    /// The postinstall's opt-in for the root half. Its ABSENCE makes the next
    /// package upgrade remove the LaunchDaemon, so install writes it and
    /// uninstall removes it: the verb and every later upgrade agree.
    pub const MACOS_MARKER: &str = "/etc/meshharbor/enable-daemon";
    const MACOS_DAEMON_BIN: &str = "/Library/Roomler/roomlerd.app/Contents/MacOS/roomlerd";

    /// Why `service install --as-service` cannot go ahead, or `None`. Asked
    /// before the service manager is touched, so a refusal changes nothing.
    ///
    /// ⚠️ A missing config is a refusal, not a warning: without one the
    /// daemon exits 1, which neither unit's `RestartPreventExitStatus` covers
    /// (`7 8`), so systemd and launchd would restart it every few seconds,
    /// for good. The root daemon is its own enrollment.
    pub fn install_refusal(
        os: Os,
        root: bool,
        shipped: bool,
        config_present: bool,
    ) -> Option<String> {
        if !root {
            return Some(format!(
                "registering the system service needs root: run `sudo meshharbord service install \
                 --as-service`. The {} runs as root.",
                what(os)
            ));
        }
        if !shipped {
            return Some(match os {
                Os::Linux => format!(
                    "{} is not on this host (looked in {}): reinstall the package or the tarball, \
                     which ship it",
                    LINUX_UNIT,
                    LINUX_UNIT_FILES.join(" and ")
                ),
                Os::MacOs => format!(
                    "{MACOS_PLIST_SOURCE} is missing: reinstall the .pkg, which ships it inside \
                     the bundle"
                ),
            });
        }
        if !config_present {
            return Some(format!(
                "{CONFIG} does not exist. The {} is its own enrollment, and without a config it \
                 would restart every few seconds. Enroll it first:\n  {}\nthen run this again.",
                what(os),
                enroll_hint(os)
            ));
        }
        None
    }

    fn what(os: Os) -> &'static str {
        match os {
            Os::Linux => "system daemon (meshharbord.service)",
            Os::MacOs => "root half (com.roomler.daemon)",
        }
    }

    /// The command that writes the root daemon's config. On a Mac it turns
    /// the overlay on too: the root half exists for the overlay (the
    /// per-user half captures the screen), as `install.sh --daemon-token` does.
    pub fn enroll_hint(os: Os) -> String {
        match os {
            Os::Linux => format!(
                "sudo roomlerd --config {CONFIG} enroll --server <url> --token <enrollment-jwt> \
                 --name <label>"
            ),
            Os::MacOs => format!(
                "sudo {MACOS_DAEMON_BIN} --config {CONFIG} enroll --server <url> --token \
                 <enrollment-jwt> --name <label> --overlay"
            ),
        }
    }

    /// The `service status --as-service` answer on Linux and macOS.
    ///
    /// ⚠️ It names its own unit and never reads `Roomler: …`: the companion
    /// polls this command every 10 s on every OS and reads a `Roomler:` line
    /// as WINDOWS' SCM service (`scm_answer` in roomler-desktop). A Unix host
    /// answering in that shape would be shown as one. Pinned by a test.
    pub fn status_line(os: Os, loaded: &str, enabled: &str) -> String {
        match os {
            Os::Linux => format!("{LINUX_UNIT}: {loaded}, {enabled}"),
            Os::MacOs => format!("{MACOS_LABEL}: {loaded}, {enabled}"),
        }
    }

    /// The real uid from a `/proc/<pid>/status`'s `Uid:` line.
    pub fn uid_of_status(status: &str) -> Option<u32> {
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|uid| uid.parse().ok())
    }

    /// The warning for a `roomlerd` that runs as another account beside the
    /// root one: one daemon per machine (CLAUDE.md), and the person's unit
    /// is theirs to stop.
    pub fn other_daemon_warning(pid: u32, uid: u32) -> String {
        format!(
            "another roomlerd runs as uid {uid} (pid {pid}). One daemon per machine: as that \
             account, run `systemctl --user disable --now meshharbor.service`"
        )
    }
}

/// FR-97 P6c — register the root daemon with the system service manager and
/// start it. Returns what was done, to print.
pub fn install_system() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        linux::install_system()
    }
    #[cfg(target_os = "macos")]
    {
        macos::install_system()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("the system service is registered with the SCM on Windows (win_service)")
    }
}

/// FR-97 P6c — stop the root daemon and deregister it. Idempotent. The config
/// stays: removing the enrollment is `install.sh --uninstall`'s.
pub fn uninstall_system() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        linux::uninstall_system()
    }
    #[cfg(target_os = "macos")]
    {
        macos::uninstall_system()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("the system service is deregistered from the SCM on Windows (win_service)")
    }
}

/// FR-97 P6c — the root daemon's state under its service manager.
pub fn status_system() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        Ok(linux::status_system())
    }
    #[cfg(target_os = "macos")]
    {
        Ok(macos::status_system())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("the system service's state comes from the SCM on Windows (win_service)")
    }
}

/// FR-97 P6c — start the registered root daemon now, through its manager.
pub fn start_system() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        linux::start_system()
    }
    #[cfg(target_os = "macos")]
    {
        macos::start_system()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("the system service is started through the SCM on Windows (win_service)")
    }
}

/// FR-97 P6c — stop the root daemon now: its clean stop runs, and an
/// ephemeral device removes itself. On a Mac through `launchctl kill SIGTERM`:
/// a clean exit stays down (the plist restarts only a failed one).
pub fn stop_system() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        linux::stop_system()
    }
    #[cfg(target_os = "macos")]
    {
        macos::stop_system()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("the system service is stopped through the SCM on Windows (win_service)")
    }
}

// ---------------------------------------------------------------------------
// Windows: Scheduled Task via schtasks.exe
//
// We register the task by writing a UTF-16-LE-BOM XML document to a temp
// file and pointing `schtasks /XML` at it, rather than the simpler
// `schtasks /Create /SC ONLOGON ...` line. The XML buys us:
//
//   * `<RestartOnFailure>` — Task Scheduler relaunches the agent up to
//     10 times at 1-minute intervals after a non-zero exit, bringing
//     Windows to parity with systemd `Restart=on-failure` and macOS
//     `KeepAlive`. The plain /SC ONLOGON path has none of this.
//   * `<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>` and
//     `<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>` — schtasks
//     defaults to BOTH true, which silently terminates the agent the
//     moment a laptop unplugs.
//   * `<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>` —
//     belt for the resilience-plan single-instance lock; if Task
//     Scheduler ever fires a second copy due to a logon-event glitch,
//     it's dropped at the scheduler level.
//   * Secondary `<EventTrigger>` on EventID 12 (Microsoft-Windows-
//     Kernel-General "operating system started") — covers the
//     auto-logon-kiosk case where the user is signed in by the OS
//     before the LogonTrigger has a chance to fire.
//
// Schema is pinned to v1.2 (compatible all the way back to Win 7) so
// the same XML works on every Win10 / Win11 build we ship to.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    /// Every `schtasks` spawn, without a console window: FR-84 D6's wizard
    /// calls [`start`] in-process, and a GUI process has no console for a
    /// child to share — each spawn would flash one.
    fn schtasks() -> Command {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut cmd = Command::new("schtasks");
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }

    /// Canonical scheduled-task name after the P3D rename.
    pub const NEW_TASK_NAME: &str = "Roomler";
    /// Pre-rename scheduled-task name, retired best-effort by `install()`
    /// and deleted by `uninstall()`.
    // RETIRED-NAME-ANCHOR: without this the pre-rename scheduled task survives an
    // upgrade forever, so the host runs TWO daemons. See docs/fr/FR-21.
    pub const LEGACY_TASK_NAME: &str = "RoomlerAgent";

    pub fn install() -> Result<()> {
        let exe = std::env::current_exe().context("locating current exe")?;
        let exe_str = exe.to_string_lossy().into_owned();
        let user = current_user_qualified().context("resolving current user")?;

        let xml = render_task_xml(&exe_str, &user);
        let xml_path = write_temp_xml(&xml).context("writing temp XML")?;

        let result = schtasks()
            .args([
                "/Create",
                "/TN",
                NEW_TASK_NAME,
                "/XML",
                xml_path.to_string_lossy().as_ref(),
                "/F",
            ])
            .output()
            .context("running schtasks /Create /XML")?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            // Keep the XML on disk so the operator can inspect it when
            // schtasks rejects the document (rare on supported builds,
            // but the schema is fussy about element order).
            return Err(anyhow::anyhow!(
                "schtasks /Create /XML failed ({}): {}\n(XML kept at {} for inspection)",
                result.status,
                stderr.trim(),
                xml_path.display()
            ));
        }
        let _ = std::fs::remove_file(&xml_path);
        // New task is registered — retire the pre-rename task best-effort.
        // Idempotent: a fresh install (no legacy task) just no-ops here.
        let _ = schtasks()
            .args(["/Delete", "/TN", LEGACY_TASK_NAME, "/F"])
            .output();
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        // Delete BOTH the new and legacy tasks. Each tolerates "not found"
        // so an idempotent uninstall works on a migrated host (only the
        // new task exists), a pre-rename host (only the legacy), or a
        // half-migrated host (both).
        delete_task(NEW_TASK_NAME)?;
        delete_task(LEGACY_TASK_NAME)?;
        Ok(())
    }

    /// FR-84 D3 — `schtasks /Run` the task: the canonical name, or the
    /// legacy one on a host that still runs it. A non-admin user may run a
    /// task registered under their own account, which is how the perUser
    /// MSI registers it. The scheduler spawns the daemon; this process is
    /// not its parent.
    pub fn start() -> Result<()> {
        let name = if task_exists(NEW_TASK_NAME) {
            NEW_TASK_NAME
        } else if task_exists(LEGACY_TASK_NAME) {
            LEGACY_TASK_NAME
        } else {
            bail!(
                "no auto-start task is registered (run `meshharbord service install` first, \
                 or start the service from an elevated prompt)"
            );
        };
        let output = schtasks()
            .args(["/Run", "/TN", name])
            .output()
            .context("running schtasks /Run")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "schtasks /Run /TN {name} failed ({}): {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    /// FR-97 P4d — how long a per-user daemon gets to leave after being
    /// asked: the SCM host's budget for its worker is 8 s, and this stop has
    /// the same work to do (an ephemeral device's unenroll among it), with
    /// margin.
    const USER_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

    /// FR-97 P4d — ask the per-user daemon of `config_path` to leave through
    /// its own stop event (`win_service::stop_event`), wait for it to go, and
    /// only then end the task, which is a `TerminateProcess`. A daemon from
    /// before P4d holds no event, so it gets the hard stop it always got.
    pub fn stop(config_path: &Path) -> Result<String> {
        use crate::win_service::stop_event::{
            signal_user_stop, user_stop_event_held, user_stop_event_name,
        };
        let name = user_stop_event_name(&crate::instance_lock::instance_id(config_path));
        match signal_user_stop(&name) {
            Ok(true) => {
                let asked = std::time::Instant::now();
                while asked.elapsed() < USER_STOP_GRACE {
                    if !user_stop_event_held(&name) {
                        return Ok(format!(
                            "The daemon stopped cleanly in {:.1} s.",
                            asked.elapsed().as_secs_f32()
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                end_task().with_context(|| {
                    format!(
                        "the daemon was asked to stop and had not left {} s later",
                        USER_STOP_GRACE.as_secs()
                    )
                })?;
                Ok(format!(
                    "The daemon had not stopped {} s after it was asked; ended its task \
                     (schtasks /End), a hard stop.",
                    USER_STOP_GRACE.as_secs()
                ))
            }
            Ok(false) => {
                end_task().context("no daemon for this config holds a stop event")?;
                if own_session() == Some(0) {
                    // An SSH login is session 0 too: the event lives in the
                    // person's session, which this one cannot see into.
                    return Ok(
                        "This command runs in session 0 (a service or an SSH login), \
                               where a per-user daemon's stop event cannot be seen, so it \
                               ended the task (schtasks /End), a hard stop. For a clean \
                               stop, run `meshharbord service stop` in the person's own session."
                            .into(),
                    );
                }
                Ok(
                    "No daemon for this config holds a stop event: none is running, or it is \
                     from before this command could ask one to leave. Ended the task \
                     (schtasks /End), a hard stop."
                        .into(),
                )
            }
            Err(e) => {
                end_task().with_context(|| format!("could not ask the daemon to stop ({e})"))?;
                Ok(format!(
                    "Could not ask the daemon to stop ({e}); ended its task (schtasks /End), a \
                     hard stop."
                ))
            }
        }
    }

    /// The Terminal Services session this process runs in. 0 is the services
    /// session, where an SSH login lands as well.
    fn own_session() -> Option<u32> {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let mut session = 0u32;
        // SAFETY: `session` is a valid out-pointer for the call, and the id is
        // this process's own.
        let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
        (ok != 0).then_some(session)
    }

    /// `schtasks /End` the registered task: a hard stop.
    fn end_task() -> Result<()> {
        let name = if task_exists(NEW_TASK_NAME) {
            NEW_TASK_NAME
        } else if task_exists(LEGACY_TASK_NAME) {
            LEGACY_TASK_NAME
        } else {
            bail!(
                "no per-user auto-start task is registered, so there is no task to end. A \
                 device that runs as the Roomler service stops with `meshharbord service stop \
                 --as-service`, elevated"
            );
        };
        let output = schtasks()
            .args(["/End", "/TN", name])
            .output()
            .context("running schtasks /End")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "schtasks /End /TN {name} failed ({}): {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    fn delete_task(name: &str) -> Result<()> {
        let output = schtasks()
            .args(["/Delete", "/TN", name, "/F"])
            .output()
            .context("running schtasks /Delete")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Task not found → idempotent uninstall, treat as success.
            //
            // Decide that by asking whether the task is STILL THERE, not by
            // reading schtasks' complaint: its messages are localized, and the
            // English-only equivalent of this check is exactly what took
            // winhost-a's overlay down on a German host (#373 — netsh answered
            // "Das Objekt ist bereits vorhanden." to an idempotent add and the
            // runtime aborted). Here the same miss would fail an uninstall that
            // had nothing left to do. The English match is kept as a fast path
            // so the common case costs no extra process spawn.
            if stderr.contains("cannot find")
                || stderr.contains("does not exist")
                || !task_exists(name)
            {
                return Ok(());
            }
            bail!(
                "schtasks /Delete failed ({}): {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    /// Does this scheduled task exist? Locale-proof.
    ///
    /// `schtasks /Query /TN <name>` prints the task's own NAME on success, and
    /// a name we chose is the same in every locale — unlike the error text.
    /// A query that fails to RUN reports `true` ("assume still there"), so a
    /// caller treating absence as success can never be fooled by a broken
    /// probe into skipping real work.
    fn task_exists(name: &str) -> bool {
        let Ok(out) = schtasks().args(["/Query", "/TN", name]).output() else {
            return true;
        };
        if !out.status.success() {
            return false;
        }
        String::from_utf8_lossy(&out.stdout).contains(name)
    }

    /// Is `name` provably ABSENT from the full task list?
    ///
    /// The independent, locale-proof half of [`query_task`]'s error path: a
    /// listing that succeeds and does not mention our name is real evidence of
    /// absence, in any language. `/FO CSV /NH` keeps the output machine-shaped
    /// rather than the localized table.
    ///
    /// Returns `false` — "not proven absent" — whenever the listing itself
    /// fails, so an unavailable or access-denied schtasks yields `Unknown`
    /// rather than a confident `NotInstalled`.
    fn task_absent_from_listing(name: &str) -> bool {
        let Ok(out) = schtasks().args(["/Query", "/FO", "CSV", "/NH"]).output() else {
            return false;
        };
        if !out.status.success() {
            return false;
        }
        !String::from_utf8_lossy(&out.stdout).contains(name)
    }

    pub fn status() -> Result<AutostartStatus> {
        // Query the new task first; fall back to the legacy task so a
        // pre-rename host mid-migration still reports Installed.
        match query_task(NEW_TASK_NAME)? {
            AutostartStatus::NotInstalled => query_task(LEGACY_TASK_NAME),
            other => Ok(other),
        }
    }

    fn query_task(name: &str) -> Result<AutostartStatus> {
        let output = schtasks()
            .args(["/Query", "/TN", name])
            .output()
            .context("running schtasks /Query")?;
        if output.status.success() {
            // Confirm it really named OUR task: a success whose output doesn't
            // mention it is not evidence of installation.
            if String::from_utf8_lossy(&output.stdout).contains(name) {
                Ok(AutostartStatus::Installed)
            } else {
                Ok(AutostartStatus::Unknown)
            }
        } else {
            // Localized stderr again (see `task_exists`). English strings stay
            // as a no-extra-spawn fast path; otherwise get an INDEPENDENT
            // locale-proof answer by listing the tasks and looking for our own
            // name — re-running the query that just failed would prove nothing.
            //
            // `Unknown` must stay distinct from `NotInstalled`: a caller that
            // reinstalls on `NotInstalled` would thrash the task every time
            // schtasks itself is unavailable or access-denied. So only a
            // successful listing that lacks our name downgrades to
            // `NotInstalled`.
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("cannot find")
                || stderr.contains("does not exist")
                || task_absent_from_listing(name)
            {
                Ok(AutostartStatus::NotInstalled)
            } else {
                Ok(AutostartStatus::Unknown)
            }
        }
    }

    /// Resolve the current user as `DOMAIN\username` (or `COMPUTERNAME\
    /// username` on a non-domain-joined machine). The Task Scheduler
    /// `Principal.UserId` field expects exactly that form, and so does
    /// `LogonTrigger.UserId` if we want the trigger scoped to one
    /// account rather than every interactive logon on the box.
    fn current_user_qualified() -> Result<String> {
        let user = std::env::var("USERNAME").context("reading %USERNAME%")?;
        let domain = std::env::var("USERDOMAIN")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_default();
        Ok(if domain.is_empty() {
            user
        } else {
            format!("{domain}\\{user}")
        })
    }

    /// Build the Task Scheduler XML that `schtasks /XML` consumes.
    /// Pure function — no I/O — so the test suite can pin the shape
    /// without touching the registry.
    fn render_task_xml(exe_path: &str, user: &str) -> String {
        let exe_xml = xml_escape(exe_path);
        let user_xml = xml_escape(user);
        // Schema 1.2 is the broadest compatible version (Win 7+). The
        // EventTrigger.Subscription is itself an XML query; its angle
        // brackets must be entity-encoded so the outer document parses.
        format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>roomlerd</Author>
    <Description>Roomler Daemon — keeps this device on your private Roomler mesh network and available for secure remote control (auto-start on logon, restart on failure).</Description>
    <URI>\Roomler</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_xml}</UserId>
    </LogonTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_xml}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>10</Count>
    </RestartOnFailure>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe_xml}</Command>
      <Arguments>run --supervisor task</Arguments>
    </Exec>
  </Actions>
</Task>
"#
        )
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    /// Persist the XML as UTF-16-LE with BOM. schtasks /XML on every
    /// supported Windows build accepts that encoding; UTF-8 sometimes
    /// works but is documented as unsupported and has been seen to
    /// fail with "The argument is incorrect" on Win10 22H2.
    fn write_temp_xml(xml_utf8: &str) -> Result<PathBuf> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("roomlerd-task-{}.xml", std::process::id()));
        let mut buf = Vec::with_capacity(xml_utf8.len() * 2 + 2);
        buf.extend_from_slice(&[0xFF, 0xFE]); // UTF-16-LE BOM
        for c in xml_utf8.encode_utf16() {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        std::fs::write(&path, &buf).with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn xml_template_pins_resilience_settings() {
            let xml = render_task_xml("C:\\path\\agent.exe", "DOMAIN\\user");
            // The five settings the resilience plan was specifically
            // about — losing any of these is the regression we're
            // guarding against.
            assert!(xml.contains("<RestartOnFailure>"));
            assert!(xml.contains("<Interval>PT1M</Interval>"));
            assert!(xml.contains("<Count>10</Count>"));
            assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
            assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
            assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
            assert!(xml.contains("<StartWhenAvailable>true</StartWhenAvailable>"));
            // Belt-and-braces triggers and the un-elevated-by-design
            // run level are also load-bearing.
            assert!(xml.contains("<LogonTrigger>"));
            assert!(xml.contains("<EventTrigger>"));
            assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
            // Pinned schema and references.
            assert!(xml.contains(r#"version="1.2""#));
            assert!(xml.contains("C:\\path\\agent.exe"));
            assert!(xml.contains("DOMAIN\\user"));
        }

        #[test]
        fn xml_template_excludes_schema_1_3_only_elements() {
            // 0.1.52 shipped these in a Schema 1.2 document and
            // schtasks /XML rejected the whole task with
            // `(39,7):DisallowStartOnRemoteAppSession: ERROR: The
            // task XML contains an unexpected node`. Both elements
            // are Schema 1.3+ only. Document stays at 1.2 (broadest
            // Win-version compat), so these are out — the resilience-
            // critical settings (RestartOnFailure, battery, etc.)
            // are all Schema 1.2 native and survive.
            let xml = render_task_xml("C:\\path\\agent.exe", "DOMAIN\\user");
            assert!(
                !xml.contains("DisallowStartOnRemoteAppSession"),
                "DisallowStartOnRemoteAppSession is Schema 1.3+; must not appear in a 1.2 document"
            );
            assert!(
                !xml.contains("UseUnifiedSchedulingEngine"),
                "UseUnifiedSchedulingEngine is Schema 1.3+; must not appear in a 1.2 document"
            );
        }

        #[test]
        fn xml_template_escapes_special_chars_in_paths_and_user() {
            let xml = render_task_xml("C:\\Users\\Joe & Sons\\app.exe", "DOM\\joe<sons");
            assert!(
                xml.contains("Joe &amp; Sons"),
                "ampersand should be entity-encoded"
            );
            assert!(
                xml.contains("joe&lt;sons"),
                "less-than should be entity-encoded"
            );
            // The bare ampersand in a path must NOT survive — that
            // would break XML parsing when schtasks reads the file.
            assert!(!xml.contains("Joe & Sons"));
        }

        /// FR-84 D3 — the worker learns it is task-supervised from its own
        /// argv, so `RestartDaemon` knows the relaunch is the CALLER's job
        /// (the task's `<RestartOnFailure>` is a minute away and `IgnoreNew`
        /// would drop a second instance anyway). Written against the literal
        /// so it compiles on the pre-D3 tree, where it is RED: the action was
        /// a bare `run`, which `supervision::detect` reads as an orphan and
        /// refuses to restart.
        #[test]
        fn xml_template_marks_the_worker_as_task_supervised() {
            let xml = render_task_xml("C:\\path\\agent.exe", "DOMAIN\\user");
            assert!(
                xml.contains("<Arguments>run --supervisor task</Arguments>"),
                "the task action must carry the supervisor flag: {xml}"
            );
        }

        #[test]
        fn write_temp_xml_uses_utf16_le_bom() {
            let path = write_temp_xml("<?xml?>").unwrap();
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(&bytes[..2], &[0xFF, 0xFE], "UTF-16-LE BOM missing");
            assert_eq!(
                &bytes[2..4],
                &[0x3C, 0x00],
                "first ASCII char `<` should be 0x3C 0x00 in UTF-16-LE"
            );
            let _ = std::fs::remove_file(&path);
        }
    }
}

// ---------------------------------------------------------------------------
// Linux: systemd user unit
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;

    /// S1b — the canonical unit name, matching what the .deb ships
    /// (`usr/lib/systemd/user/meshharbor.service`, ExecStart=/usr/bin/meshharbord).
    /// Pre-S1b `meshharbord service install` only knew the legacy name below and
    /// couldn't SEE the packaged unit — so a .deb host that also ran
    /// `service install` ended up with TWO enabled units (double-start).
    pub const UNIT: &str = "meshharbor.service";
    /// Legacy unit name written by pre-S1b `service install` runs.
    // RETIRED-NAME-ANCHOR(2): the unit name on hosts installed before P3d
    // Slice B. Install/uninstall must still find it or an upgraded host ends
    // up with two enabled units and a silent restart storm.
    const LEGACY_UNIT: &str = "roomler-agent.service";

    /// Which unit name is in force on this host: the canonical name when its
    /// unit file exists (or on a fresh host), the legacy name only when ONLY
    /// the legacy unit file exists.
    fn resolved_unit() -> &'static str {
        if unit_file_present_for(UNIT) {
            UNIT
        } else if unit_file_present_for(LEGACY_UNIT) {
            LEGACY_UNIT
        } else {
            UNIT
        }
    }

    pub fn install() -> Result<()> {
        // Prefer the packaged unit; fall back to a user-local drop-in
        // (under the CANONICAL name) when running out of cargo.
        let unit = resolved_unit();
        if unit == UNIT && !unit_file_present_for(UNIT) {
            install_user_unit_file()?;
        }
        systemctl(&["--user", "daemon-reload"])?;
        systemctl(&["--user", "enable", "--now", unit])?;
        // Kill the double-start hazard: when enabling the canonical unit,
        // best-effort disable a stray legacy one.
        if unit == UNIT {
            let _ = systemctl(&["--user", "disable", "--now", LEGACY_UNIT]);
        }
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        // Ignore non-zero exit — disabling a non-enabled unit is fine.
        // Both names, so an upgraded host is fully cleaned.
        let _ = systemctl(&["--user", "disable", "--now", UNIT]);
        let _ = systemctl(&["--user", "disable", "--now", LEGACY_UNIT]);
        Ok(())
    }

    /// FR-84 D3 — start the per-user unit now (the resolved name, so a host
    /// still on the legacy unit starts that one). systemd spawns the daemon.
    pub fn start() -> Result<()> {
        systemctl(&["--user", "start", resolved_unit()])
    }

    /// FR-97 P4d — stop the per-user unit now: systemd sends SIGTERM, which
    /// the daemon turns into a clean stop (an ephemeral device unenrolls).
    pub fn stop() -> Result<String> {
        systemctl(&["--user", "stop", resolved_unit()])?;
        Ok(format!(
            "systemd stopped {} (SIGTERM, a clean stop).",
            resolved_unit()
        ))
    }

    // ── FR-97 P6c: the root daemon, `meshharbord.service` ──

    pub fn install_system() -> Result<String> {
        let shipped = system::LINUX_UNIT_FILES
            .iter()
            .any(|p| std::path::Path::new(p).exists());
        if let Some(why) = system::install_refusal(
            system::Os::Linux,
            crate::appdirs::running_as_root(),
            shipped,
            std::path::Path::new(system::CONFIG).exists(),
        ) {
            bail!("{why}");
        }
        let mut done = Vec::new();
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", system::LINUX_UNIT])?;
        // `enable --now` starts the unit only when it is not active: a re-run
        // over a running one changes nothing.
        done.push(format!(
            "{} enabled and running (root, {})",
            system::LINUX_UNIT,
            system::CONFIG
        ));
        for (pid, uid) in other_daemons() {
            done.push(format!(
                "WARNING: {}",
                system::other_daemon_warning(pid, uid)
            ));
        }
        Ok(done.join("\n"))
    }

    pub fn uninstall_system() -> Result<String> {
        if !crate::appdirs::running_as_root() {
            bail!(
                "deregistering the system service needs root: run `sudo meshharbord service uninstall --as-service`"
            );
        }
        let mut done = Vec::new();
        let (enabled, active) = unit_state(system::LINUX_UNIT);
        if enabled == "not-found" {
            done.push(format!(
                "{} is not on this host: nothing to do",
                system::LINUX_UNIT
            ));
        } else if enabled == "disabled" && active != "active" {
            done.push(format!(
                "{} is already stopped and disabled; {} is kept",
                system::LINUX_UNIT,
                system::CONFIG
            ));
        } else {
            // `disable --now` waits for the stop: the daemon's clean stop runs.
            systemctl(&["disable", "--now", system::LINUX_UNIT])?;
            done.push(format!(
                "{} stopped (a clean stop) and disabled; {} is kept",
                system::LINUX_UNIT,
                system::CONFIG
            ));
        }
        Ok(done.join("\n"))
    }

    pub fn status_system() -> String {
        let (enabled, active) = unit_state(system::LINUX_UNIT);
        system::status_line(system::Os::Linux, &active, &enabled)
    }

    pub fn start_system() -> Result<String> {
        systemctl(&["start", system::LINUX_UNIT])?;
        Ok(format!("systemd started {}.", system::LINUX_UNIT))
    }

    pub fn stop_system() -> Result<String> {
        systemctl(&["stop", system::LINUX_UNIT])?;
        Ok(format!(
            "systemd stopped {} (SIGTERM, a clean stop).",
            system::LINUX_UNIT
        ))
    }

    /// A system unit's `(is-enabled, is-active)` answers; `not-found` when
    /// systemd has no such unit.
    fn unit_state(unit: &str) -> (String, String) {
        let ask = |verb: &str| {
            Command::new("systemctl")
                .args([verb, unit])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "not-found".to_string())
        };
        (ask("is-enabled"), ask("is-active"))
    }

    /// Every `roomlerd` that runs as an account other than root, from /proc.
    fn other_daemons() -> Vec<(u32, u32)> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return found;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            if comm.trim() != "meshharbord" {
                continue;
            }
            let status = std::fs::read_to_string(entry.path().join("status")).unwrap_or_default();
            if let Some(uid) = system::uid_of_status(&status)
                && uid != 0
            {
                found.push((pid, uid));
            }
        }
        found
    }

    /// FR-93 P5 (#2144) — the target that has to START the unit after a
    /// logout, because `PartOf=` stops it with the session.
    const SESSION_TARGET: &str = "graphical-session.target";

    /// The per-user unit's enablement: what `systemctl --user show` says, and
    /// what its unit file asks for.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct UnitEnablement {
        /// `UnitFileState`: `enabled`, `disabled`, `static`, …
        pub state: String,
        /// The targets that want the unit now: its `WantedBy=` property, from
        /// the `.wants` links the manager has loaded.
        pub wanted_by: Vec<String>,
        /// The targets its unit file's `[Install]` section names.
        pub install_wanted_by: Vec<String>,
    }

    /// Whether an enabled unit lacks a link its unit file asks for, the
    /// session target's: `enable` creates the links, so a unit enabled before
    /// its file named the target never got that one.
    pub(super) fn needs_session_wants(e: &UnitEnablement) -> bool {
        e.state == "enabled"
            && e.install_wanted_by.iter().any(|t| t == SESSION_TARGET)
            && !e.wanted_by.iter().any(|t| t == SESSION_TARGET)
    }

    /// The targets a unit file's `[Install]` section names in `WantedBy=`:
    /// every such line, space-separated, an empty assignment clearing the list
    /// (systemd's rule). Other sections and comments are not read.
    pub(super) fn install_wanted_by(unit_file: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut in_install = false;
        for raw in unit_file.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                in_install = line == "[Install]";
                continue;
            }
            if !in_install || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "WantedBy" {
                continue;
            }
            let value = value.trim();
            if value.is_empty() {
                out.clear();
            } else {
                out.extend(value.split_whitespace().map(str::to_string));
            }
        }
        out
    }

    /// What `systemctl --user show` says of `unit`, with its unit file read
    /// from disk: after a package upgrade the manager may still hold the old
    /// file, which nobody reloaded for this user. `None` without systemd, a
    /// user manager, or a unit file.
    fn enablement(unit: &str) -> Option<UnitEnablement> {
        let out = Command::new("systemctl")
            .args([
                "--user",
                "show",
                unit,
                "-p",
                "UnitFileState",
                "-p",
                "WantedBy",
                "-p",
                "FragmentPath",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let (mut state, mut wanted_by, mut fragment) = (String::new(), Vec::new(), String::new());
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("UnitFileState=") {
                state = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("WantedBy=") {
                wanted_by = v.split_whitespace().map(str::to_string).collect();
            } else if let Some(v) = line.strip_prefix("FragmentPath=") {
                fragment = v.trim().to_string();
            }
        }
        let file = std::fs::read_to_string(&fragment).ok()?;
        Some(UnitEnablement {
            state,
            wanted_by,
            install_wanted_by: install_wanted_by(&file),
        })
    }

    /// See the module-level [`super::repair_session_wants_at_start`].
    ///
    /// ⚠️ Through `systemctl`, never by writing the link: the unit's sandbox
    /// (`ProtectHome=read-only`) leaves `~/.config/systemd/user` read-only to
    /// the daemon, and the user manager, which makes the link, is outside it.
    pub(super) fn repair_session_wants_at_start() {
        if !tunnel_core::env::flag("UNIT_REPAIR", true) {
            return;
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let spawned = std::thread::Builder::new()
            .name("unit-repair".into())
            .spawn(|| {
                let unit = resolved_unit();
                let Some(e) = enablement(unit) else {
                    return;
                };
                if !needs_session_wants(&e) {
                    return;
                }
                match systemctl(&["--user", "enable", unit]) {
                    Ok(()) => tracing::info!(
                        unit,
                        wanted_by = ?e.wanted_by,
                        "per-user unit: enabled for graphical-session.target too, so the next login \
                         starts the daemon again (#2144)"
                    ),
                    Err(err) => tracing::warn!(
                        unit,
                        error = %format!("{err:#}"),
                        "per-user unit: could not enable it for graphical-session.target; after a \
                         logout the daemon stays down until the next boot (#2144)"
                    ),
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(%e, "per-user unit: no thread to check its enablement (#2144)");
        }
    }

    pub fn status() -> Result<AutostartStatus> {
        // Either name counts as installed (an upgraded host may still run
        // the legacy-named unit until its next `service install`).
        for unit in [UNIT, LEGACY_UNIT] {
            let output = Command::new("systemctl")
                .args(["--user", "is-enabled", unit])
                .output();
            match output {
                Ok(o) if o.status.success() => return Ok(AutostartStatus::Installed),
                Ok(_) => {}
                Err(_) => return Ok(AutostartStatus::Unknown),
            }
        }
        Ok(AutostartStatus::NotInstalled)
    }

    fn systemctl(args: &[&str]) -> Result<()> {
        let output = Command::new("systemctl")
            .args(args)
            .output()
            .context("running systemctl")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "systemctl {:?} failed ({}): {}",
                args,
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    fn unit_file_present_for(name: &str) -> bool {
        let candidates = [
            format!("/usr/lib/systemd/user/{name}"),
            format!("/usr/local/lib/systemd/user/{name}"),
            format!("/etc/systemd/user/{name}"),
        ];
        candidates.iter().any(|p| std::path::Path::new(p).exists())
            || user_unit_path_for(name)
                .map(|p| p.exists())
                .unwrap_or(false)
    }

    fn user_unit_path() -> Option<std::path::PathBuf> {
        user_unit_path_for(UNIT)
    }

    fn user_unit_path_for(name: &str) -> Option<std::path::PathBuf> {
        directories::BaseDirs::new().map(|d| d.config_dir().join("systemd/user").join(name))
    }

    /// The unit `service install` writes where no packaged one exists. Wanted
    /// by `graphical-session.target` too, like the packaged unit (#2144):
    /// `PartOf=` stops it with the session, so the session has to start it.
    pub(super) fn user_unit_text(exe: &str) -> String {
        format!(
            "[Unit]\n\
             Description=Roomler Daemon — keeps this device on your private Roomler mesh network and available for secure remote control\n\
             After=graphical-session.target\n\
             PartOf=graphical-session.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe} run\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             Environment=RUST_LOG=roomlerd=info,tunnel_core=info,warn\n\
             \n\
             [Install]\n\
             WantedBy=default.target graphical-session.target\n"
        )
    }

    fn install_user_unit_file() -> Result<()> {
        let exe = std::env::current_exe().context("locating current exe")?;
        let unit = user_unit_text(&exe.to_string_lossy());
        let path = user_unit_path().context("resolving user unit path")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("creating user unit dir")?;
        }
        std::fs::write(&path, unit).context("writing user unit file")?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ue(state: &str, wanted_by: &[&str], file_wants: &[&str]) -> UnitEnablement {
            UnitEnablement {
                state: state.to_string(),
                wanted_by: wanted_by.iter().map(|s| s.to_string()).collect(),
                install_wanted_by: file_wants.iter().map(|s| s.to_string()).collect(),
            }
        }

        /// #2144: enabled before the unit file named the session target, so
        /// only `default.target` links to it, and a user manager that outlives
        /// a logout never starts it again.
        #[test]
        fn an_enabled_unit_without_the_session_link_its_file_names_is_repaired() {
            let both = ["default.target", "graphical-session.target"];
            assert!(needs_session_wants(&ue(
                "enabled",
                &["default.target"],
                &both
            )));
        }

        #[test]
        fn nothing_to_repair_when_linked_disabled_or_the_file_is_older() {
            let both = ["default.target", "graphical-session.target"];
            assert!(
                !needs_session_wants(&ue("enabled", &both, &both)),
                "already linked"
            );
            assert!(
                !needs_session_wants(&ue("disabled", &[], &both)),
                "a unit the user switched off stays off"
            );
            assert!(!needs_session_wants(&ue("static", &[], &both)));
            assert!(
                !needs_session_wants(&ue("enabled", &["default.target"], &["default.target"])),
                "an older unit file: enabling again would add nothing"
            );
        }

        #[test]
        fn install_wanted_by_reads_only_the_install_section() {
            let file = "[Unit]\n\
                        WantedBy=not-this.target\n\
                        PartOf=graphical-session.target\n\
                        \n\
                        [Install]\n\
                        # WantedBy=commented.target\n\
                        WantedBy = default.target  graphical-session.target\n\
                        WantedBy=extra.target\n";
            assert_eq!(
                install_wanted_by(file),
                ["default.target", "graphical-session.target", "extra.target"]
            );
            assert_eq!(
                install_wanted_by("[Install]\nWantedBy=a.target\nWantedBy=\nWantedBy=b.target\n"),
                ["b.target"],
                "an empty assignment clears the list"
            );
            assert!(install_wanted_by("[Service]\nWantedBy=x.target\n").is_empty());
        }

        /// The two units a per-user install can run, the packaged one and the
        /// one `service install` writes, both stop with the session and are
        /// both started again by it.
        #[test]
        fn both_per_user_units_are_wanted_by_the_session_they_stop_with() {
            let packaged = include_str!("../packaging/linux/meshharbor.service");
            let written = user_unit_text("/usr/bin/meshharbord");
            for (name, unit) in [("packaged", packaged), ("written", written.as_str())] {
                assert!(unit.contains("PartOf=graphical-session.target"), "{name}");
                let wants = install_wanted_by(unit);
                assert!(
                    wants.iter().any(|t| t == "default.target"),
                    "{name}: {wants:?}"
                );
                assert!(
                    wants.iter().any(|t| t == SESSION_TARGET),
                    "{name}: {wants:?} (#2144)"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: LaunchAgent plist
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub const PLIST: &str = "com.roomler.agent";

    pub fn install() -> Result<()> {
        let plist = plist_path()?;
        if !plist.exists() {
            write_plist(&plist)?;
        }
        let output = Command::new("launchctl")
            .args(["load", "-w", plist.to_string_lossy().as_ref()])
            .output()
            .context("running launchctl load")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // launchctl returns non-zero when the plist is already
            // loaded — treat that as success.
            if stderr.contains("already loaded") || stderr.contains("service already loaded") {
                return Ok(());
            }
            bail!(
                "launchctl load failed ({}): {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let plist = plist_path()?;
        if !plist.exists() {
            return Ok(());
        }
        let _ = Command::new("launchctl")
            .args(["unload", "-w", plist.to_string_lossy().as_ref()])
            .output();
        Ok(())
    }

    /// FR-84 D3 — `launchctl kickstart gui/<uid>/com.roomler.agent`: start
    /// the loaded LaunchAgent now (no `-k`: a running one is left alone).
    /// launchd spawns the daemon. Fails when the agent is not bootstrapped —
    /// `service install` is the remedy, and the error says so.
    pub fn start() -> Result<()> {
        // SAFETY: `getuid` takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        let target = format!("gui/{uid}/{PLIST}");
        let output = Command::new("launchctl")
            .args(["kickstart", &target])
            .output()
            .context("running launchctl kickstart")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "launchctl kickstart {target} failed ({}): {} (is the LaunchAgent loaded? \
                 `meshharbord service install` loads it)",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }

    pub fn status() -> Result<AutostartStatus> {
        let output = Command::new("launchctl").args(["list", PLIST]).output();
        match output {
            Ok(o) if o.status.success() => Ok(AutostartStatus::Installed),
            Ok(_) => Ok(AutostartStatus::NotInstalled),
            Err(_) => Ok(AutostartStatus::Unknown),
        }
    }

    // ── FR-97 P6c: the root half, `com.roomler.daemon` ──

    fn running_as_root() -> bool {
        // SAFETY: `geteuid` is a thread-safe read of the caller's own credentials.
        unsafe { libc::geteuid() == 0 }
    }

    fn target() -> String {
        format!("system/{}", system::MACOS_LABEL)
    }

    /// Is the root half loaded, and its `state`?
    fn job_state() -> Option<String> {
        state_of(&target())
    }

    /// `bootout` returns while the job is still draining, and a `bootstrap`
    /// in that window fails "5: Input/output error" (the .pkg postinstall's
    /// `replace_launchd_service`, field-caught on self-updates): wait until
    /// launchd no longer knows the job.
    fn bootout_and_wait() {
        let _ = Command::new("launchctl")
            .args(["bootout", &target()])
            .output();
        for _ in 0..30 {
            if job_state().is_none() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    pub fn install_system() -> Result<String> {
        let source = std::path::Path::new(system::MACOS_PLIST_SOURCE);
        if let Some(why) = system::install_refusal(
            system::Os::MacOs,
            running_as_root(),
            source.exists(),
            std::path::Path::new(system::CONFIG).exists(),
        ) {
            bail!("{why}");
        }
        // The marker first: it is what keeps the job across the next .pkg
        // upgrade, whose postinstall removes the LaunchDaemon without it.
        std::fs::create_dir_all("/etc/meshharbor").context("creating /etc/meshharbor")?;
        if !std::path::Path::new(system::MACOS_MARKER).exists() {
            std::fs::write(system::MACOS_MARKER, b"")
                .with_context(|| format!("writing {}", system::MACOS_MARKER))?;
        }
        // Already registered with this very plist: nothing to redo. A reload
        // would be a stop, and an ephemeral device removes itself on a stop,
        // then restarts into exit 7, which `KeepAlive` restarts (a failed exit).
        let installed = std::fs::read(system::MACOS_PLIST).ok();
        if job_state().is_some() && installed.is_some() && installed == std::fs::read(source).ok() {
            return Ok(format!(
                "{} is already registered with the shipped plist: left as it is",
                system::MACOS_LABEL
            ));
        }
        std::fs::copy(source, system::MACOS_PLIST)
            .with_context(|| format!("copying {}", system::MACOS_PLIST))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(system::MACOS_PLIST, std::fs::Permissions::from_mode(0o644))
                .with_context(|| format!("chmod 644 {}", system::MACOS_PLIST))?;
        }
        bootout_and_wait();
        let mut last = String::new();
        for attempt in 1..=5 {
            let out = Command::new("launchctl")
                .args(["bootstrap", "system", system::MACOS_PLIST])
                .output()
                .context("running launchctl bootstrap")?;
            if out.status.success() {
                return Ok(format!(
                    "{} bootstrapped into the system domain (root, {}); {} keeps it across \
                     package upgrades",
                    system::MACOS_LABEL,
                    system::CONFIG,
                    system::MACOS_MARKER
                ));
            }
            last = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if attempt < 5 {
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
        bail!(
            "launchctl bootstrap system {} failed five times: {last}",
            system::MACOS_PLIST
        )
    }

    pub fn uninstall_system() -> Result<String> {
        if !running_as_root() {
            bail!(
                "deregistering the system service needs root: run `sudo meshharbord service uninstall --as-service`"
            );
        }
        let was_loaded = job_state().is_some();
        bootout_and_wait();
        let mut done = Vec::new();
        if was_loaded {
            done.push(format!("{} booted out (a clean stop)", system::MACOS_LABEL));
        }
        for path in [system::MACOS_PLIST, system::MACOS_MARKER] {
            match std::fs::remove_file(path) {
                Ok(()) => done.push(format!("removed {path}")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {path}")),
            }
        }
        if done.is_empty() {
            done.push(format!(
                "{} is not registered: nothing to do",
                system::MACOS_LABEL
            ));
        }
        done.push(format!("{} is kept", system::CONFIG));
        Ok(done.join("\n"))
    }

    pub fn status_system() -> String {
        let loaded = job_state().unwrap_or_else(|| "not loaded".to_string());
        let marker = if std::path::Path::new(system::MACOS_MARKER).exists() {
            "enabled"
        } else {
            "not enabled"
        };
        system::status_line(system::Os::MacOs, &loaded, marker)
    }

    pub fn start_system() -> Result<String> {
        let out = Command::new("launchctl")
            .args(["kickstart", &target()])
            .output()
            .context("running launchctl kickstart")?;
        if !out.status.success() {
            bail!(
                "launchctl kickstart {} failed ({}): {} (is it registered? `sudo roomlerd \
                 service install --as-service` registers it)",
                target(),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(format!("launchd started {}.", system::MACOS_LABEL))
    }

    /// SIGTERM through launchd: the daemon's clean stop, which exits 0. Both
    /// plists' `KeepAlive` is `{SuccessfulExit = false}`, so launchd restarts
    /// a job only after a FAILED exit and this one stays down until `after`.
    /// Measured on macOS 15 for both jobs (FR-97 P6c: exit 0, `runs`
    /// unchanged for 24 s), and checked here each time rather than assumed:
    /// the job must read `not running`, and still read it a moment later.
    fn sigterm_and_confirm(target: &str, label: &str, after: &str) -> Result<String> {
        if state_of(target).is_none() {
            bail!("{label} is not loaded: nothing to stop");
        }
        let out = Command::new("launchctl")
            .args(["kill", "SIGTERM", target])
            .output()
            .context("running launchctl kill")?;
        if !out.status.success() {
            bail!(
                "launchctl kill SIGTERM {target} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let down = || state_of(target).is_some_and(|s| s != "running");
        for _ in 0..30 {
            if down() {
                std::thread::sleep(std::time::Duration::from_secs(3));
                if down() {
                    return Ok(format!(
                        "launchd stopped {label} (SIGTERM, a clean stop). It starts again {after}."
                    ));
                }
                bail!(
                    "{label} stopped, and launchd started it again: its exit did not read as clean"
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        bail!("{label} still runs 30 s after its SIGTERM")
    }

    /// A launchd job's `state` (`running`, `not running`, …), `None` when
    /// launchd does not know it.
    fn state_of(target: &str) -> Option<String> {
        let out = Command::new("launchctl")
            .args(["print", target])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        Some(
            text.lines()
                .find_map(|l| l.trim().strip_prefix("state = ").map(str::to_string))
                .unwrap_or_else(|| "loaded".to_string()),
        )
    }

    /// FR-97 P6c (the stop P4d left refused) — the per-user LaunchAgent.
    pub fn stop() -> Result<String> {
        // SAFETY: `getuid` takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        sigterm_and_confirm(
            &format!("gui/{uid}/{PLIST}"),
            PLIST,
            "at the next login or with `meshharbord service start`",
        )
    }

    pub fn stop_system() -> Result<String> {
        sigterm_and_confirm(
            &target(),
            system::MACOS_LABEL,
            "at the next boot or with `sudo meshharbord service start --as-service`",
        )
    }

    fn plist_path() -> Result<std::path::PathBuf> {
        let home = directories::BaseDirs::new()
            .map(|d| d.home_dir().to_path_buf())
            .context("resolving home dir")?;
        Ok(home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{PLIST}.plist")))
    }

    fn write_plist(path: &std::path::Path) -> Result<()> {
        let exe = std::env::current_exe().context("locating current exe")?;
        let exe_str = exe.to_string_lossy();
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key><string>{PLIST}</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array><string>{exe_str}</string><string>run</string></array>\n\
             \t<key>RunAtLoad</key><true/>\n\
             \t<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n\
             \t<key>ProcessType</key><string>Interactive</string>\n\
             \t<key>EnvironmentVariables</key>\n\
             \t<dict><key>RUST_LOG</key><string>roomlerd=info,tunnel_core=info,warn</string></dict>\n\
             </dict>\n\
             </plist>\n"
        );
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("creating LaunchAgents dir")?;
        }
        std::fs::write(path, xml).context("writing LaunchAgent plist")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FR-97 P6c: the system service's decisions, on every OS ──

    #[test]
    fn a_system_install_is_refused_in_order_root_then_the_unit_then_the_config() {
        use system::{Os, install_refusal};
        for os in [Os::Linux, Os::MacOs] {
            let not_root = install_refusal(os, false, true, true).expect("refused");
            assert!(not_root.contains("needs root"), "{not_root}");
            // Root comes first: a non-root caller learns nothing it cannot act on.
            assert!(
                install_refusal(os, false, false, false)
                    .unwrap()
                    .contains("needs root")
            );
            let unshipped = install_refusal(os, true, false, true).expect("refused");
            assert!(unshipped.contains("reinstall"), "{unshipped}");
            let unenrolled = install_refusal(os, true, true, false).expect("refused");
            assert!(unenrolled.contains(system::CONFIG), "{unenrolled}");
            assert!(unenrolled.contains("enroll"), "{unenrolled}");
            assert_eq!(install_refusal(os, true, true, true), None);
        }
    }

    #[test]
    fn the_enroll_hint_writes_the_config_the_service_reads() {
        use system::{CONFIG, Os, enroll_hint};
        let linux = enroll_hint(Os::Linux);
        assert!(linux.starts_with("sudo roomlerd --config /etc/meshharbor/config.toml enroll "));
        let mac = enroll_hint(Os::MacOs);
        assert!(mac.contains(&format!("--config {CONFIG} enroll ")), "{mac}");
        // The root half exists for the overlay, as `install.sh --daemon-token`.
        assert!(mac.ends_with("--overlay"), "{mac}");
        assert!(
            !linux.contains("--overlay"),
            "a Linux system node is not forced onto the mesh"
        );
    }

    /// The companion polls `service status --as-service` on every OS and
    /// reads a `Roomler:` line as WINDOWS' SCM service (`scm_answer` in
    /// roomler-desktop). A Unix answer must never take that shape.
    #[test]
    fn the_unix_status_line_never_reads_as_windows_scm_answer() {
        use system::{Os, status_line};
        for os in [Os::Linux, Os::MacOs] {
            for (loaded, enabled) in [
                ("active", "enabled"),
                ("running", "enabled"),
                ("not loaded", "not enabled"),
            ] {
                let line = status_line(os, loaded, enabled);
                assert!(
                    !line.to_ascii_lowercase().starts_with("roomler:"),
                    "{line} would read as the SCM service"
                );
            }
        }
        assert_eq!(
            status_line(Os::Linux, "active", "enabled"),
            "meshharbord.service: active, enabled"
        );
        assert_eq!(
            status_line(Os::MacOs, "running", "enabled"),
            "com.roomler.daemon: running, enabled"
        );
    }

    #[test]
    fn the_real_uid_comes_from_the_status_uid_line() {
        let status = "Name:\troomlerd\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(system::uid_of_status(status), Some(1000));
        assert_eq!(system::uid_of_status("Uid:\t0\t0\t0\t0\n"), Some(0));
        assert_eq!(system::uid_of_status("Name:\tx\n"), None);
        assert_eq!(system::uid_of_status("Uid:\tnot-a-number\n"), None);
    }

    /// The paths are the packaging's, pinned against the files that ship
    /// them: a rename on either side fails here, not on a host.
    #[test]
    fn the_system_service_paths_are_the_packagings() {
        let unit = include_str!("../packaging/linux/meshharbord.service");
        assert!(
            unit.contains(&format!("Environment=MESHHARBORD_CONFIG={}", system::CONFIG)),
            "meshharbord.service's MESHHARBORD_CONFIG moved"
        );
        // That the update helper steps aside by THIS unit's enable link is
        // updater.rs's own lock (`the_system_daemon_links_are_its_install_target`).
        let plist = include_str!("../packaging/macos/com.roomler.daemon.plist");
        assert!(plist.contains(&format!("<string>{}</string>", system::MACOS_LABEL)));
        assert!(plist.contains(&format!("<string>{}</string>", system::CONFIG)));
        let postinstall = include_str!("../packaging/macos/postinstall");
        assert!(postinstall.contains(&format!(
            "DAEMON_PLIST_SOURCE=\"{}\"",
            system::MACOS_PLIST_SOURCE
        )));
        assert!(postinstall.contains(&format!("DAEMON_PLIST_TARGET=\"{}\"", system::MACOS_PLIST)));
        assert!(
            postinstall.contains(&format!("[ -f {} ]", system::MACOS_MARKER)),
            "the postinstall's daemon gate reads another marker"
        );
    }

    #[test]
    fn only_the_companions_two_probes_skip_the_daemon_startup() {
        let argv = |a: &[&str]| -> Vec<String> {
            std::iter::once("roomlerd")
                .chain(a.iter().copied())
                .map(String::from)
                .collect()
        };
        assert_eq!(companion_probe(&argv(&["service", "status"])), Some(false));
        assert_eq!(
            companion_probe(&argv(&["service", "status", "--as-service"])),
            Some(true)
        );
        // Everything else keeps the full startup: other service verbs, other
        // commands, a global flag in front, trailing extras, no command.
        for other in [
            &["service", "install"][..],
            &["service", "status", "--as-service", "--verbose"],
            &["--config", "x.toml", "service", "status"],
            &["run"],
            &["status"],
            &[],
        ] {
            assert_eq!(companion_probe(&argv(other)), None, "{other:?}");
        }
    }

    #[test]
    fn autostart_status_renders_human_readable() {
        assert_eq!(AutostartStatus::Installed.to_string(), "installed");
        assert_eq!(AutostartStatus::NotInstalled.to_string(), "not installed");
        assert_eq!(AutostartStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn status_returns_a_value_on_this_platform() {
        // The exact status depends on the test host. We only assert
        // that the call path doesn't panic and returns one of the
        // three known variants.
        match status() {
            Ok(
                AutostartStatus::Installed
                | AutostartStatus::NotInstalled
                | AutostartStatus::Unknown,
            ) => {}
            Err(_) => panic!("status() errored on this platform"),
        }
    }

    // ─── #2293: what brings a removed daemon back ────────────────────

    const EVERY: [Install; 6] = [
        Install::LinuxSystem,
        Install::LinuxUser,
        Install::WindowsService,
        Install::WindowsTask,
        Install::MacOs,
        Install::Other,
    ];

    #[test]
    fn a_service_managed_install_is_never_told_to_run_the_daemon_by_hand() {
        // `meshharbord run` beside a unit, a task or launchd is an unmanaged
        // orphan: the hint #2293 removed. Only a host with no service manager
        // may be told it.
        for i in EVERY {
            for primary in [true, false] {
                let says = i.after_re_enroll(primary);
                assert_eq!(
                    says.contains("meshharbord run"),
                    i == Install::Other && primary,
                    "{i:?} primary={primary}: {says}"
                );
                assert!(
                    !says.contains("wait for the supervisor"),
                    "{i:?}: the relaunch that never comes on Linux: {says}"
                );
            }
            assert!(!i.after_removal().contains("wait for the supervisor"));
        }
    }

    #[test]
    fn linux_names_the_start_systemd_will_not_make() {
        // exit 7 is in `RestartPreventExitStatus` for both units.
        let system = Install::LinuxSystem.after_re_enroll(true);
        assert!(system.contains("sudo systemctl start roomlerd"), "{system}");
        let user = Install::LinuxUser.after_re_enroll(true);
        assert!(user.contains("meshharbord service start"), "{user}");
        assert!(!user.contains("sudo"), "a user unit needs no root: {user}");
        assert!(
            Install::LinuxSystem
                .after_removal()
                .contains("sudo systemctl start roomlerd")
        );
        assert!(
            Install::LinuxUser
                .after_removal()
                .contains("meshharbord service start")
        );
    }

    #[test]
    fn the_per_user_windows_task_is_said_to_give_up() {
        // `<RestartOnFailure>` relaunches ten times, then the task stays
        // down until the next sign-in: unlike the service's supervisor.
        for says in [
            Install::WindowsTask.after_re_enroll(true),
            Install::WindowsTask.after_removal(),
        ] {
            assert!(says.contains("ten times"), "{says}");
            assert!(says.contains("meshharbord service start"), "{says}");
        }
        assert!(
            !Install::WindowsService
                .after_re_enroll(true)
                .contains("meshharbord service start"),
            "the service's supervisor restarts the worker for good"
        );
    }

    #[test]
    fn a_secondary_org_is_told_to_restart_the_daemon() {
        // Its loop ended at its goodbye; nothing but a restart starts it.
        for i in EVERY {
            let says = i.after_re_enroll(false);
            assert!(says.contains("restarts"), "{i:?}: {says}");
        }
        assert!(
            Install::LinuxSystem
                .after_re_enroll(false)
                .contains("sudo systemctl restart roomlerd")
        );
        assert!(
            Install::WindowsService
                .after_re_enroll(false)
                .contains("roomler restart")
        );
    }

    // ─── #2371: what connects a fresh enrollment ──────────────────────

    /// The first command a text names, between its first pair of backticks.
    fn first_command(says: &str) -> Option<&str> {
        let start = says.find('`')? + 1;
        let len = says[start..].find('`')?;
        Some(&says[start..start + len])
    }

    #[test]
    fn an_enrollment_never_leads_with_roomlerd_run_beside_a_service_manager() {
        // The same orphan #2293 removed from `re-enroll`: `meshharbord run` may
        // only be the fallback, for a host without the package, and is first
        // only where this code knows no service manager.
        for i in EVERY {
            let says = i.after_enroll(false);
            assert_eq!(
                first_command(says) == Some("meshharbord run"),
                i == Install::Other,
                "{i:?}: {says}"
            );
            assert!(!says.contains("wait for the supervisor"), "{i:?}: {says}");
        }
    }

    #[test]
    fn a_fresh_linux_enrollment_names_a_restart_that_works_in_every_state() {
        // A fresh primary may land on a unit that is stopped, failed (crash-
        // looping on a missing config) or running: `restart` starts all three.
        assert_eq!(
            first_command(Install::LinuxSystem.after_enroll(false)),
            Some("sudo systemctl restart roomlerd")
        );
        assert_eq!(
            first_command(Install::LinuxUser.after_enroll(false)),
            Some("meshharbord service start")
        );
        assert!(
            Install::LinuxUser
                .after_enroll(false)
                .contains("`roomler restart`")
        );
    }

    #[test]
    fn an_added_org_is_told_to_restart_the_daemon() {
        // A secondary org's loop starts only with the daemon (multi-org.md).
        for i in EVERY {
            let says = i.after_enroll(true);
            assert!(says.contains("restarts"), "{i:?}: {says}");
            assert!(!says.contains("meshharbord run"), "{i:?}: {says}");
        }
        assert_eq!(
            first_command(Install::LinuxSystem.after_enroll(true)),
            Some("sudo systemctl restart roomlerd")
        );
        assert_eq!(
            first_command(Install::MacOs.after_enroll(true)),
            Some("roomler restart")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_config_is_the_system_unit() {
        assert_eq!(
            Install::detect(&crate::appdirs::system_config_path()),
            Install::LinuxSystem
        );
    }
}
