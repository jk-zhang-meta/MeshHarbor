// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Post-install watcher subprocess.
//!
//! Spawned by the updater immediately before the agent exits to make
//! room for the installer. Tracks the installer process by PID,
//! captures its exit code, then verifies that the new binary on
//! disk reports the expected version. Writes a typed outcome JSON
//! to `<log_dir>/last-install.json` so an operator (or the next
//! startup of the agent) can read what actually happened.
//!
//! ## Why a separate process
//!
//! The agent's own EXE is about to be overwritten by msiexec /
//! dpkg / installer(8). We can't sit in the same process and wait
//! for that to finish, because:
//!   1. Windows MSI on a running EXE either fails outright with
//!      `ERROR_SHARING_VIOLATION` or schedules the rename for next
//!      reboot — neither of which is the intent.
//!   2. The exit-and-let-the-supervisor-relaunch flow that the
//!      Scheduled Task / systemd / launchd model relies on means
//!      the parent agent process IS exiting; there's no one home
//!      to call back into when the installer finishes.
//!
//! The watcher's binary image is mapped before the installer ran;
//! the file at the same path on disk is then overwritten by the
//! installer, but the watcher's mapped pages stay valid for the
//! lifetime of the process. When the watcher exits, the new
//! binary's pages are what subsequent invocations load.
//!
//! ## Why the watcher runs from a staged COPY on Windows
//!
//! Mapped pages survive the overwrite, but Windows Installer's
//! RestartManager doesn't care about pages — it enumerates the
//! *processes holding the files being replaced* and shuts down the
//! ones whose SID it can manage. A watcher spawned from
//! `<install>\roomlerd.exe` IS such a process, so RM killed it
//! seconds into every install that had contended files (field
//! forensic 2026-08-21 on the dev host: `last-install.json` frozen
//! at `InProgress`, watcher born 02:54:11, RM app-shutdown
//! 02:54:12) — the wedge-recovery and service-start safety nets
//! below never ran on exactly the installs that needed them. The
//! updater therefore copies the EXE into the update staging dir and
//! spawns the watcher from the copy (`updater::stage_watcher_exe`),
//! passing `--origin-exe <install-dir exe>` so flavour
//! classification and the version probe still target the real
//! install rather than the copy's %TEMP% location (which would
//! misclassify as PerUser — same trap as the install wizard,
//! see `spawn_installer_inner`'s doc).
//!
//! ## Lifecycle
//!
//! 1. Updater downloads installer.
//! 2. Updater spawns msiexec / dpkg / installer(8) as a child.
//! 3. Updater spawns `roomlerd post-install-watch
//!    --installer-pid <pid> --installer-path <path>
//!    --expected-version <tag>` — on Windows from a staged COPY of
//!    the EXE with `--origin-exe <install-dir exe>` appended (see
//!    "Why the watcher runs from a staged COPY" above).
//! 4. Updater exits the parent agent so the OS releases its EXE
//!    file lock.
//! 5. Watcher polls the installer PID until it exits or 10 min
//!    elapses. **Windows wedge recovery**: on timeout the watcher
//!    kills the wedged msiexec (plus any leftover msiexec worker
//!    holding the machine-wide `_MSIExecute` mutex) and re-runs the
//!    staged installer ONCE — the exact manual recovery that worked
//!    3/3 in the field (rc.226/rc.228/rc.232 self-update wedges).
//! 6. Watcher waits 2 s for the FS to settle, runs `<own-path>
//!    --version`, compares against the expected tag. Windows: when
//!    the own-path probe can't verify (P4b renamed the install
//!    folder, so a rename-hop watcher runs from the vacated dir),
//!    it falls back to probing `…\Roomler\roomlerd.exe` for the
//!    running flavour.
//! 7. Watcher writes `last-install.json` and exits. Windows
//!    perMachine: as a last act the watcher runs `sc start` on the
//!    SCM service — every observed wedge left the service STOPPED
//!    (the MSI never reached StartServices), and a host that stays
//!    down is worse than any install verdict. Elsewhere the agent comes back
//!    at the next logon (the per-user Scheduled Task), within 5 s (systemd,
//!    `Restart=always`), or through the `.pkg`'s postinstall (launchd skips a
//!    clean exit); the new binary reads `last-install.json` at startup.
//!
//! ## What this is NOT
//!
//! - It does NOT roll back failed installs. That's Phase 6.3's job
//!   (last-known-good rollback) — this watcher just records what
//!   happened.
//! - It does NOT verify install signatures. The MSI's Authenticode
//!   chain is checked by the OS at install time; we trust that.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
#[cfg(all(unix, not(target_os = "windows")))]
use std::time::Instant;

/// Wall-clock budget for waiting on the installer to finish.
/// Conservative — the longest-observed install in the field is
/// ~3 min on a Windows host with active EDR scanning the MSI.
pub const INSTALLER_BUDGET: Duration = Duration::from_secs(600);

/// Pause after installer exit before running the new binary's
/// `--version`. Lets the FS settle (cargo-wix MSI sometimes
/// fsyncs after process exit).
pub const POST_INSTALL_SETTLE: Duration = Duration::from_secs(2);

/// Persistent record of the most recent install attempt. Written
/// to `<log_dir>/last-install.json`. The new agent reads this at
/// startup to surface success / failure to the operator.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallOutcome {
    pub installer_pid: u32,
    pub installer_path: String,
    pub expected_version: String,
    pub started_unix: u64,
    pub finished_unix: Option<u64>,
    pub installer_exit_code: Option<i32>,
    pub new_binary_path: Option<String>,
    pub new_binary_version: Option<String>,
    pub status: InstallStatus,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum InstallStatus {
    /// Watcher is still waiting on the installer to exit. Persisted
    /// at watch-start so a watcher that itself crashes leaves a
    /// trail of "we got this far."
    InProgress,
    /// Installer exited 0 AND the new binary's `--version` output
    /// contained the expected version triple.
    SucceededVerified,
    /// Installer exited 0 but the version check failed (binary
    /// missing, wrong version, or `--version` didn't run). The
    /// install probably worked; surface this so an operator can
    /// investigate without us assuming the worst.
    SucceededUnverified,
    /// Installer exited with a non-zero code. The agent's old
    /// binary is still in place and the supervisor will keep
    /// running it on next logon.
    InstallerFailed,
    /// Installer didn't exit within `INSTALLER_BUDGET`. We give up
    /// rather than block the watcher process forever.
    Timeout,
}

/// Resolve the path of the persistent install-outcome JSON file.
/// Returns `None` only when [`crate::logging::log_dir`] does (i.e.
/// the platform doesn't expose a data dir or `logging::init()`
/// hasn't run).
pub fn outcome_path() -> Option<PathBuf> {
    crate::logging::log_dir().map(|d| d.join("last-install.json"))
}

/// Persist the outcome to `<log_dir>/last-install.json`. Atomic
/// rename via tempfile-then-replace would be nicer; for now a
/// straight write is fine — the file is small and corruption
/// downside is just "operator sees a partial JSON" which is
/// recoverable.
pub fn write_outcome(outcome: &InstallOutcome) -> Result<PathBuf> {
    let path = outcome_path().context("no log dir resolvable")?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(outcome).context("serialising install outcome")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Read the most recent install outcome, if any. Returns `None`
/// when the file doesn't exist (first install, or successful
/// install where the operator manually deleted it). Errors are
/// surfaced — a corrupt file is operator-actionable.
pub fn read_outcome() -> Result<Option<InstallOutcome>> {
    let Some(path) = outcome_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let parsed =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(parsed))
}

/// Run the watcher loop. Blocks until the installer exits or the
/// budget elapses, then writes the outcome JSON. Returns Ok(()) on
/// every observed outcome — the JSON's `status` field carries the
/// real verdict.
///
/// `origin_exe`: the daemon EXE inside the real install dir, passed
/// when the watcher runs from a staged copy (see the module docs).
/// `None` = the watcher runs from the install dir itself, so its own
/// `current_exe` is the correct probe/flavour source.
/// Whether the watcher must wait on `installer_pid` at all.
///
/// ⚠️ Waiting is never correct for an install that already completed in the
/// daemon's own process. On Linux BOTH install paths are synchronous — the
/// tarball path does the work inline and hands back `std::process::id()`
/// (`updater.rs`, `install_tarball_linux`), and the `.deb` path `wait()`s on its
/// child and hands back an already-reaped pid. So the pid handed over is either
/// the DAEMON's or a corpse, and polling it means the watcher's only exit
/// condition is **its own parent's death** — which is also precisely what kills
/// it, because the daemon's exit tears down the systemd unit's cgroup.
///
/// That is why `last-install.json` sat at `InProgress` on every Linux host: one
/// still showed `agent-v0.4.16` written 2026-08-29 while the host was running
/// 0.4.50. See FR-67 (#1267).
///
/// ⚠️ Windows keeps the wait: msiexec is genuinely asynchronous and
/// `recover_wedged_install` depends on observing its exit.
fn should_wait_for_installer(installer_pid: u32, already_exited: bool) -> bool {
    if already_exited {
        return false;
    }
    // A zero pid is not waitable; `kill(0, 0)` addresses the caller's whole
    // process group, which would make the poll succeed forever.
    installer_pid != 0
}

pub fn watch(
    installer_pid: u32,
    installer_path: PathBuf,
    expected_version: String,
    origin_exe: Option<PathBuf>,
    already_exited: bool,
) -> Result<InstallOutcome> {
    let started_unix = unix_now();
    let mut outcome = InstallOutcome {
        installer_pid,
        installer_path: installer_path.display().to_string(),
        expected_version: expected_version.clone(),
        started_unix,
        finished_unix: None,
        installer_exit_code: None,
        new_binary_path: None,
        new_binary_version: None,
        status: InstallStatus::InProgress,
        note: String::new(),
    };
    // Persist the InProgress state immediately so a watcher that
    // crashes mid-wait still leaves a forensic trail.
    let _ = write_outcome(&outcome);

    let exit = if should_wait_for_installer(installer_pid, already_exited) {
        wait_for_pid(installer_pid, INSTALLER_BUDGET)
    } else {
        // Nothing to observe: the install finished before this process
        // existed. Treat it as a clean exit and go straight to verifying the
        // binary that is now on disk.
        tracing::info!(
            installer_pid,
            "installer already completed synchronously — verifying without waiting"
        );
        WaitOutcome::Exited(0)
    };
    match exit {
        WaitOutcome::Exited(code) => {
            outcome.installer_exit_code = Some(code);
            if code != 0 {
                outcome.status = InstallStatus::InstallerFailed;
                outcome.note = format!("installer exited with {code}");
                tracing::error!(exit = code, "installer failed");
            } else {
                verify_new_binary(
                    &mut outcome,
                    &expected_version,
                    origin_exe.as_deref(),
                    already_exited,
                );
            }
        }
        WaitOutcome::Timeout => {
            // Windows: this is the field-reproduced msiexec wedge
            // (client alive forever, service left stopped). Kill it
            // and retry the staged installer once — see the module
            // docs, step 5.
            #[cfg(target_os = "windows")]
            recover_wedged_install(
                installer_pid,
                &installer_path,
                &expected_version,
                origin_exe.as_deref(),
                &mut outcome,
            );
            #[cfg(not(target_os = "windows"))]
            {
                outcome.status = InstallStatus::Timeout;
                outcome.note = format!(
                    "installer did not exit within {}s",
                    INSTALLER_BUDGET.as_secs()
                );
                tracing::error!("installer timed out");
            }
        }
        WaitOutcome::Error(e) => {
            outcome.status = InstallStatus::Timeout;
            outcome.note = format!("waiting for installer pid: {e}");
            tracing::error!(error = %e, "installer wait failed");
        }
    }
    outcome.finished_unix = Some(unix_now());
    // Last act on Windows perMachine: whatever the verdict, never
    // leave the host's SCM service stopped.
    #[cfg(target_os = "windows")]
    ensure_service_running(&mut outcome, install_flavour(origin_exe.as_deref()));
    let _ = write_outcome(&outcome);
    Ok(outcome)
}

/// The flavour of the install this watcher is watching. Prefers the
/// `--origin-exe` path (the real install dir) over the watcher's own
/// location — a staged-copy watcher runs from %TEMP%, which the path
/// heuristic would misclassify as PerUser and thereby skip the
/// perMachine service check AND pick the wrong elevation path on the
/// wedge retry.
#[cfg(target_os = "windows")]
fn install_flavour(origin: Option<&std::path::Path>) -> crate::updater::WindowsInstallFlavour {
    match origin {
        Some(p) => crate::updater::classify_install_flavour_from_path(p),
        None => crate::updater::current_install_flavour(),
    }
}

// RETIRED-NAME-ANCHOR(4): names the folder hosts installed BEFORE P4b; the
// migration reads it, so the old name is the input, not a leftover.
/// Installer exited 0 — give the FS a moment to settle, then run the
/// new binary's `--version`. Through rc.194 the watcher's own
/// current_exe path was ALSO the path the installer wrote to (msiexec
/// replaced the file in place while we were running; our memory map
/// stayed valid). P4b renamed the install folder (`roomler-agent` →
/// `Roomler`), so on the rename hop the watcher — spawned from the OLD
/// directory — only ever sees the stale pending-delete binary at its
/// own path; when that probe can't verify the expected version, fall
/// back to the flavour-derived RENAMED directory.
///
/// With `origin` set (staged-copy watcher) the probe targets the real
/// install path directly — the watcher's own path is a %TEMP% copy of
/// the OLD binary and would always report the pre-update version.
/// How long to let the filesystem settle before probing the new binary.
///
/// The pause exists for ONE reason, stated at [`POST_INSTALL_SETTLE`]: a
/// cargo-wix MSI sometimes fsyncs after the installer process exits. That is a
/// Windows concern about an installer we watched exit.
///
/// ⚠️ When the install completed synchronously it finished BEFORE this watcher
/// existed — there is nothing left to settle, and the wait is pure exposure.
/// Field-measured 2026-09-06 on three hosts: with the wait skipped (P1) the
/// watcher still died inside this 2 s sleep, killed by the cgroup teardown that
/// follows the daemon's exit, leaving `last-install.json` at `InProgress` even
/// though it had started and logged. Removing a sleep we never needed is the
/// cheap half of closing that race — far cheaper than moving the watcher into a
/// transient unit (FR-67 P6), which pays exit-path risk for the same outcome.
fn settle_before_probe(already_exited: bool) -> Duration {
    if already_exited {
        Duration::ZERO
    } else {
        POST_INSTALL_SETTLE
    }
}

fn verify_new_binary(
    outcome: &mut InstallOutcome,
    expected_version: &str,
    origin: Option<&std::path::Path>,
    already_exited: bool,
) {
    let settle = settle_before_probe(already_exited);
    if !settle.is_zero() {
        std::thread::sleep(settle);
    }
    let exe = origin
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::current_exe().ok());
    if let Some(p) = &exe {
        outcome.new_binary_path = Some(p.display().to_string());
        match std::process::Command::new(p).arg("--version").output() {
            Ok(out) if out.status.success() => {
                let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
                outcome.new_binary_version = Some(version.clone());
                if version_matches(&version, expected_version) {
                    outcome.status = InstallStatus::SucceededVerified;
                    outcome.note = format!("new binary at {} reports {version}", p.display());
                } else {
                    outcome.status = InstallStatus::SucceededUnverified;
                    outcome.note = format!(
                        "new binary at {} reports {version} but expected {expected_version}",
                        p.display()
                    );
                    #[cfg(target_os = "windows")]
                    try_renamed_dir_fallback(outcome, expected_version, Some(p), origin);
                }
            }
            Ok(out) => {
                outcome.status = InstallStatus::SucceededUnverified;
                outcome.note = format!(
                    "new binary `--version` exited {}",
                    out.status.code().unwrap_or(-1)
                );
                #[cfg(target_os = "windows")]
                try_renamed_dir_fallback(outcome, expected_version, Some(p), origin);
            }
            Err(e) => {
                outcome.status = InstallStatus::SucceededUnverified;
                outcome.note = format!("could not exec new binary --version: {e}");
                #[cfg(target_os = "windows")]
                try_renamed_dir_fallback(outcome, expected_version, Some(p), origin);
            }
        }
    } else {
        outcome.status = InstallStatus::SucceededUnverified;
        outcome.note = "could not resolve own current_exe path".into();
        #[cfg(target_os = "windows")]
        try_renamed_dir_fallback(outcome, expected_version, None, origin);
    }
}

/// Windows wedge recovery: the initial msiexec sat past
/// [`INSTALLER_BUDGET`] without exiting. Field pattern (3/3 on the
/// dev host, rc.226→rc.232): the client msiexec is alive but inert,
/// the service is already stopped, and a manual "kill every msiexec,
/// re-run the staged MSI" recovered every single time — the re-run
/// completes in under a minute. Automate exactly that, once.
///
/// The population sweep (not just our PID) matters: the Windows
/// Installer service's own msiexec worker can outlive the client and
/// keep the machine-wide `_MSIExecute` mutex held, which would wedge
/// the retry the same way. Killing mid-transaction is safe here
/// because the retry re-enters Windows Installer, which rolls back /
/// completes any suspended state before installing (observed in all
/// three manual recoveries).
#[cfg(target_os = "windows")]
fn recover_wedged_install(
    wedged_pid: u32,
    installer_path: &std::path::Path,
    expected_version: &str,
    origin: Option<&std::path::Path>,
    outcome: &mut InstallOutcome,
) {
    tracing::error!(
        wedged_pid,
        budget_s = INSTALLER_BUDGET.as_secs(),
        "installer wedged — killing msiexec and retrying the staged installer once"
    );
    outcome.note = format!(
        "installer wedged (no exit in {}s); killing msiexec and retrying once",
        INSTALLER_BUDGET.as_secs()
    );
    let _ = write_outcome(outcome);

    run_recovery_cmd("taskkill", &["/F", "/T", "/PID", &wedged_pid.to_string()]);
    std::thread::sleep(Duration::from_secs(5));
    run_recovery_cmd("taskkill", &["/F", "/IM", "msiexec.exe"]);
    std::thread::sleep(Duration::from_secs(5));

    // Spawn the retry against the ORIGIN install's flavour — a
    // staged-copy watcher's own path would classify PerUser and take
    // the non-elevated msiexec path, which a perMachine MSI rejects
    // (the 2026-05-15 wizard-class 1625 failure).
    let retry_pid =
        match crate::updater::spawn_installer_as_flavour(installer_path, install_flavour(origin)) {
            Ok(pid) => pid,
            Err(e) => {
                outcome.status = InstallStatus::Timeout;
                outcome.note = format!("installer wedged; retry spawn failed: {e:#}");
                tracing::error!(error = %e, "retry spawn after wedge failed");
                return;
            }
        };
    outcome.installer_pid = retry_pid;
    let _ = write_outcome(outcome);
    match wait_for_pid(retry_pid, INSTALLER_BUDGET) {
        WaitOutcome::Exited(0) => {
            outcome.installer_exit_code = Some(0);
            // `false`: this is the wedge-recovery retry, where we genuinely
            // waited on msiexec. That is exactly the case POST_INSTALL_SETTLE
            // was written for — cargo-wix can fsync after process exit — so the
            // pause is kept here.
            verify_new_binary(outcome, expected_version, origin, false);
            outcome.note = format!(
                "recovered by kill+retry after initial {}s wedge; {}",
                INSTALLER_BUDGET.as_secs(),
                outcome.note
            );
            tracing::info!("retry after wedge succeeded");
        }
        WaitOutcome::Exited(code) => {
            outcome.installer_exit_code = Some(code);
            outcome.status = InstallStatus::InstallerFailed;
            outcome.note = format!("retry after wedge exited with {code}");
            tracing::error!(exit = code, "retry after wedge failed");
        }
        WaitOutcome::Timeout => {
            run_recovery_cmd("taskkill", &["/F", "/T", "/PID", &retry_pid.to_string()]);
            outcome.status = InstallStatus::Timeout;
            outcome.note = format!(
                "retry also wedged (no exit in {}s); killed — see the msiexec /l*v log next to the MSI",
                INSTALLER_BUDGET.as_secs()
            );
            tracing::error!("retry after wedge also timed out");
        }
        WaitOutcome::Error(e) => {
            outcome.status = InstallStatus::Timeout;
            outcome.note = format!("waiting for retry installer pid: {e}");
            tracing::error!(error = %e, "retry installer wait failed");
        }
    }
}

/// Spawn a recovery shell-out, log its exit code, never fail the
/// watcher on it. taskkill exit codes are informational here (128 =
/// no such process — already gone, which is fine).
#[cfg(target_os = "windows")]
fn run_recovery_cmd(cmd: &str, args: &[&str]) {
    match std::process::Command::new(cmd).args(args).output() {
        Ok(out) => {
            tracing::info!(cmd, ?args, code = out.status.code(), "recovery command ran");
        }
        Err(e) => {
            tracing::warn!(cmd, ?args, error = %e, "recovery command failed to spawn");
        }
    }
}

/// Make sure the perMachine SCM service is running before the watcher
/// exits. Every observed wedge left the service STOPPED (msiexec never
/// reached StartServices), and nothing else restarts it until a
/// reboot. `sc start` is effectively idempotent for our purpose:
/// 1056 (already running) and 1060 (no such service — perUser /
/// attended flavours never register one) are success-equivalent.
///
/// Best-effort by design: on SystemContext hosts the updater — and
/// therefore this watcher — runs in the USER-session worker, whose
/// non-elevated token lacks SERVICE_START on a LocalSystem service
/// (`sc` exits 5). The verdict string records that honestly instead
/// of pretending the net exists where it can't act.
#[cfg(target_os = "windows")]
fn ensure_service_running(
    outcome: &mut InstallOutcome,
    flavour: crate::updater::WindowsInstallFlavour,
) {
    if flavour != crate::updater::WindowsInstallFlavour::PerMachine {
        return;
    }
    let name = crate::win_service::NEW_SERVICE_NAME;
    match std::process::Command::new("sc")
        .args(["start", name])
        .output()
    {
        Ok(out) => {
            // sc.exe exits with the raw win32 error code.
            let code = out.status.code().unwrap_or(-1);
            let verdict = match code {
                0 => "started",
                1056 => "already running",
                1060 => "not installed (non-SCM flavour)",
                1058 => "disabled — not starting",
                5 => "access denied (watcher context lacks SERVICE_START)",
                _ => "start attempt failed",
            };
            tracing::info!(service = name, code, verdict, "post-install service check");
            if !outcome.note.is_empty() {
                outcome.note.push_str("; ");
            }
            outcome
                .note
                .push_str(&format!("service {name}: {verdict} (sc exit {code})"));
        }
        Err(e) => {
            tracing::warn!(service = name, error = %e, "sc start failed to spawn");
        }
    }
}

// RETIRED-NAME-ANCHOR(4): same pre-P4b folder — the watcher must run from
// the directory being vacated, which still carries the retired name.
/// P4b folder-rename fallback: probe the daemon at the RENAMED
/// install directory for this flavour
/// (`…\Roomler\roomlerd.exe`) when the own-path probe couldn't
/// verify the expected version. On the rename-hop upgrade the
/// watcher runs from the vacated `roomler-agent\` directory, so its
/// own path never sees the freshly-installed binary. Record-only,
/// like the rest of the watcher: a version match here upgrades the
/// outcome to `SucceededVerified` with a rename-aware note; anything
/// else leaves the own-path verdict untouched.
#[cfg(target_os = "windows")]
fn try_renamed_dir_fallback(
    outcome: &mut InstallOutcome,
    expected_version: &str,
    own: Option<&std::path::Path>,
    origin: Option<&std::path::Path>,
) {
    let Some(candidate) = renamed_daemon_candidate(install_flavour(origin)) else {
        return;
    };
    if Some(candidate.as_path()) == own || !candidate.is_file() {
        return;
    }
    if let Ok(out) = std::process::Command::new(&candidate)
        .arg("--version")
        .output()
        && out.status.success()
    {
        let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if version_matches(&version, expected_version) {
            outcome.new_binary_path = Some(candidate.display().to_string());
            outcome.new_binary_version = Some(version.clone());
            outcome.status = InstallStatus::SucceededVerified;
            outcome.note = format!(
                "new binary verified at renamed install dir {} ({version}); watcher ran from the pre-rename path",
                candidate.display()
            );
        }
    }
}

/// The daemon EXE path inside the post-P4b (`Roomler\`) install dir
/// for the given flavour. Split out of [`try_renamed_dir_fallback`]
/// so the pure path derivation is unit-testable without shelling
/// anything. The flavour comes from [`install_flavour`] — origin-
/// aware, so a staged-copy watcher still probes the right root.
#[cfg(target_os = "windows")]
fn renamed_daemon_candidate(flavour: crate::updater::WindowsInstallFlavour) -> Option<PathBuf> {
    crate::updater::install_dir_with_name(flavour, crate::updater::INSTALL_FOLDER_NAME)
        .map(|dir| dir.join("roomlerd.exe"))
}

/// Whether a `--version` line (e.g. "roomlerd 0.1.50") contains
/// the version triple from `expected_tag` (e.g. "agent-v0.1.50").
/// Tolerant on the prefix so we don't have to track release-tool
/// formatting changes.
pub(crate) fn version_matches(version_output: &str, expected_tag: &str) -> bool {
    let Some(triple) = crate::updater::parse_version(expected_tag) else {
        return false;
    };
    let needle = format!("{}.{}.{}", triple.0, triple.1, triple.2);
    version_output.contains(&needle)
}

#[derive(Debug)]
enum WaitOutcome {
    Exited(i32),
    Timeout,
    // Constructed only in `wait_pid_windows` and the
    // non-windows-non-unix fallback; the unix wait path
    // never produces an error today.
    #[allow(dead_code)]
    Error(anyhow::Error),
}

fn wait_for_pid(pid: u32, budget: Duration) -> WaitOutcome {
    #[cfg(target_os = "windows")]
    {
        wait_pid_windows(pid, budget)
    }
    #[cfg(all(unix, not(target_os = "windows")))]
    {
        wait_pid_unix(pid, budget)
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = (pid, budget);
        WaitOutcome::Error(anyhow::anyhow!("unsupported platform"))
    }
}

#[cfg(target_os = "windows")]
fn wait_pid_windows(pid: u32, budget: Duration) -> WaitOutcome {
    type Handle = *mut std::ffi::c_void;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    // ERROR_INVALID_PARAMETER fires when OpenProcess is called for
    // a pid that doesn't exist (already exited or never existed).
    const ERROR_INVALID_PARAMETER: u32 = 87;

    unsafe extern "system" {
        fn OpenProcess(desired: u32, inherit: i32, pid: u32) -> Handle;
        fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
        fn GetExitCodeProcess(handle: Handle, code: *mut u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    // SAFETY: OpenProcess returns NULL on error and a valid handle
    // otherwise. We CloseHandle in every branch.
    let h = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_INVALID_PARAMETER {
            return WaitOutcome::Exited(0);
        }
        return WaitOutcome::Error(anyhow::anyhow!("OpenProcess({pid}) failed (err {err})"));
    }
    let result = unsafe { WaitForSingleObject(h, budget.as_millis() as u32) };
    let outcome = if result == WAIT_OBJECT_0 {
        let mut code: u32 = 0;
        // SAFETY: handle is valid and we own the out-pointer.
        let ok = unsafe { GetExitCodeProcess(h, &mut code) };
        if ok != 0 {
            WaitOutcome::Exited(code as i32)
        } else {
            WaitOutcome::Error(anyhow::anyhow!(
                "GetExitCodeProcess failed (err {})",
                unsafe { GetLastError() }
            ))
        }
    } else if result == WAIT_TIMEOUT {
        WaitOutcome::Timeout
    } else {
        WaitOutcome::Error(anyhow::anyhow!(
            "WaitForSingleObject returned {result} (err {})",
            unsafe { GetLastError() }
        ))
    };
    // SAFETY: closing our owned handle.
    unsafe {
        CloseHandle(h);
    }
    outcome
}

#[cfg(all(unix, not(target_os = "windows")))]
fn wait_pid_unix(pid: u32, budget: Duration) -> WaitOutcome {
    let pid_i = pid as libc::pid_t;
    let start = Instant::now();
    while start.elapsed() < budget {
        // SAFETY: kill(pid, 0) is the canonical "does this process
        // exist" probe — sends signal 0 (does nothing) but does
        // permission + existence checks.
        let r = unsafe { libc::kill(pid_i, 0) };
        if r != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::ESRCH {
                // Process is gone. We can't recover the exit code
                // because we weren't the parent (waitpid would need
                // to be); return Exited(0) and let the version check
                // be the source of truth on whether the install
                // actually worked.
                return WaitOutcome::Exited(0);
            }
            // EPERM means the process exists but we can't signal it.
            // Keep polling — we'll see ESRCH when it actually exits.
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    WaitOutcome::Timeout
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // P4b: pure path derivation behind the folder-rename fallback.
    // LOCALAPPDATA / ProgramFiles are always set on a real Windows
    // session (and on the Windows CI runners), so asserting suffixes
    // is host-state-independent.
    #[cfg(target_os = "windows")]
    #[test]
    fn renamed_daemon_candidate_targets_the_roomler_dir() {
        use crate::updater::WindowsInstallFlavour;
        let per_user = renamed_daemon_candidate(WindowsInstallFlavour::PerUser)
            .expect("install root env var set on Windows");
        assert!(
            per_user.ends_with(
                std::path::Path::new("Programs")
                    .join(crate::updater::INSTALL_FOLDER_NAME)
                    .join("roomlerd.exe")
            ),
            "unexpected perUser candidate {}",
            per_user.display()
        );
        let per_machine = renamed_daemon_candidate(WindowsInstallFlavour::PerMachine)
            .expect("ProgramFiles env var set on Windows");
        assert!(
            per_machine.ends_with(
                std::path::Path::new(crate::updater::INSTALL_FOLDER_NAME).join("roomlerd.exe")
            ) && per_machine
                .to_string_lossy()
                .to_lowercase()
                .contains("program files"),
            "unexpected perMachine candidate {}",
            per_machine.display()
        );
    }

    // Staged-copy watcher: the origin path decides the flavour; the
    // watcher's own %TEMP% location must not. `None` keeps the old
    // own-path classification (a test binary runs from target\ →
    // PerUser).
    #[cfg(target_os = "windows")]
    #[test]
    fn install_flavour_prefers_origin_path() {
        use crate::updater::WindowsInstallFlavour;
        assert_eq!(
            install_flavour(Some(std::path::Path::new(
                r"C:\Program Files\Roomler\roomlerd.exe"
            ))),
            WindowsInstallFlavour::PerMachine
        );
        assert_eq!(
            install_flavour(Some(std::path::Path::new(
                r"C:\Users\x\AppData\Local\Programs\Roomler\roomlerd.exe"
            ))),
            WindowsInstallFlavour::PerUser
        );
        assert_eq!(install_flavour(None), WindowsInstallFlavour::PerUser);
    }

    /// FR-67 P1 — the watcher must not wait for an install that already
    /// finished.
    ///
    /// On Linux both install paths complete inside the daemon: the tarball path
    /// installs inline and returns `std::process::id()`, and the `.deb` path
    /// `wait()`s on its child and returns an already-reaped pid. Polling that pid
    /// means the watcher's only exit condition is its own parent's death — and
    /// that death is exactly what tears down the unit's cgroup and kills it. The
    /// result was `last-install.json` frozen at `InProgress` on every Linux host,
    /// one of them still naming `agent-v0.4.16` while running 0.4.50.
    ///
    /// ⚠️ The first assertion is the load-bearing one and it is the shape of the
    /// real bug: the daemon's own pid, an install that is already done. It fails
    /// against the previous code, which called `wait_for_pid` unconditionally.
    ///
    /// ⚠️ The second pins what must NOT change — a genuinely asynchronous
    /// installer (msiexec, `installer -pkg`) is still waited on, because
    /// `recover_wedged_install` depends on observing its exit.
    /// FR-67 — the settle is exposure, not safety, once the install is done.
    ///
    /// `POST_INSTALL_SETTLE` exists for one documented reason: a cargo-wix MSI
    /// sometimes fsyncs after the installer process exits. That is a claim about
    /// an installer we *watched exit*. When the install completed synchronously
    /// it finished before this watcher existed, so there is nothing to settle.
    ///
    /// ⚠️ Field-measured on three hosts, 2026-09-06: with the wait skipped the
    /// watcher STILL died inside this 2 s sleep — the cgroup teardown that
    /// follows the daemon's exit landed first, and `last-install.json` stayed at
    /// `InProgress` despite the watcher having started and logged. The sleep was
    /// the whole remaining exposure window.
    ///
    /// ⚠️ The second assertion is the one that must not regress: an installer we
    /// genuinely waited on keeps the pause, because that is the case the
    /// constant was written for.
    #[test]
    fn a_synchronous_install_has_nothing_to_settle_for() {
        assert_eq!(
            settle_before_probe(true),
            Duration::ZERO,
            "the install finished before this process existed; the pause is pure              exposure to the teardown that is about to kill us"
        );

        assert_eq!(
            settle_before_probe(false),
            POST_INSTALL_SETTLE,
            "an installer we watched exit keeps the pause — cargo-wix can fsync              after process exit, which is why the constant exists"
        );
    }

    #[test]
    fn the_watcher_never_waits_on_an_already_completed_install() {
        assert!(
            !should_wait_for_installer(std::process::id(), true),
            "an install that already completed must not be waited on: the pid is this process or a corpse, and the wait ends only when we are killed"
        );

        assert!(
            should_wait_for_installer(4242, false),
            "a genuinely asynchronous installer must still be waited on; Windows wedge recovery depends on observing its exit"
        );

        assert!(
            !should_wait_for_installer(0, false),
            "pid 0 is not waitable — kill(0, 0) addresses the whole process group, so the poll would succeed forever"
        );
    }

    #[test]
    fn version_matches_when_output_contains_triple() {
        assert!(version_matches("roomlerd 0.1.50", "agent-v0.1.50"));
        assert!(version_matches("roomlerd 0.1.50", "0.1.50"));
        assert!(version_matches("roomlerd 0.1.50", "v0.1.50"));
        assert!(version_matches("roomlerd 1.2.3 (some-build-id)", "v1.2.3"));
        // RETIRED-NAME-ANCHOR(2): a ROLLBACK re-runs the previous binary, which
        // still prints the pre-FR-21 name. Prefix tolerance is the contract.
        assert!(version_matches("roomler-agent 0.1.50", "agent-v0.1.50"));
    }

    #[test]
    fn version_does_not_match_different_triple() {
        assert!(!version_matches("roomlerd 0.1.49", "agent-v0.1.50"));
        assert!(!version_matches("roomlerd 1.0.0", "agent-v0.0.1"));
        assert!(!version_matches(
            "totally unrelated string",
            "agent-v0.1.50"
        ));
    }

    #[test]
    fn version_does_not_match_unparseable_tag() {
        // We refuse to match against malformed tags so a
        // server-side typo can't smuggle a "successful" verdict
        // through.
        assert!(!version_matches("roomlerd 0.1.50", "not-a-version"));
        assert!(!version_matches("roomlerd 0.1.50", ""));
    }

    #[test]
    fn outcome_round_trips_through_json() {
        let outcome = InstallOutcome {
            installer_pid: 1234,
            installer_path: "C:/temp/foo.msi".into(),
            expected_version: "agent-v0.1.50".into(),
            started_unix: 100,
            finished_unix: Some(200),
            installer_exit_code: Some(0),
            new_binary_path: Some("C:/agent.exe".into()),
            new_binary_version: Some("roomlerd 0.1.50".into()),
            status: InstallStatus::SucceededVerified,
            note: "ok".into(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("\"installer_pid\":1234"));
        assert!(json.contains("\"status\":\"SucceededVerified\""));
        let parsed: InstallOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome, "round-trip must preserve all fields");
    }

    #[test]
    fn outcome_serialises_pending_state_with_optional_fields_null() {
        let outcome = InstallOutcome {
            installer_pid: 1,
            installer_path: "x".into(),
            expected_version: "v0.0.1".into(),
            started_unix: 0,
            finished_unix: None,
            installer_exit_code: None,
            new_binary_path: None,
            new_binary_version: None,
            status: InstallStatus::InProgress,
            note: "".into(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("\"finished_unix\":null"));
        assert!(json.contains("\"installer_exit_code\":null"));
        assert!(json.contains("\"status\":\"InProgress\""));
    }

    #[test]
    fn install_status_serialises_as_pascal_case() {
        // Lock the wire format — operators are likely to grep
        // last-install.json by status string, and we don't want a
        // refactor that flips this to snake_case to silently break
        // their dashboards.
        let cases = [
            (InstallStatus::InProgress, "\"InProgress\""),
            (InstallStatus::SucceededVerified, "\"SucceededVerified\""),
            (
                InstallStatus::SucceededUnverified,
                "\"SucceededUnverified\"",
            ),
            (InstallStatus::InstallerFailed, "\"InstallerFailed\""),
            (InstallStatus::Timeout, "\"Timeout\""),
        ];
        for (status, expected) in cases {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
        }
    }
}
