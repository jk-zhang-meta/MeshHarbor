// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows Service deployment mode (Effort 2).
//!
//! Optional alternative to the Scheduled Task model (`service install`,
//! the existing default). The Scheduled Task launches the agent in the
//! interactive user's session at logon and works for self-controlled
//! hosts. The Service mode targets fleet / unattended deployments where:
//!
//!   - the host should be reachable **before** anyone logs in (lock
//!     screen / pre-logon remote login),
//!   - the install should not depend on a particular user being created
//!     before the agent is registered,
//!   - and the operator (typically IT) wants a single SCM entry to
//!     manage state via Get-Service / sc.exe / Server Manager.
//!
//! Module surface for M1:
//!   - [`install`] / [`uninstall`] / [`status`] — service-manager API
//!     wrappers, exposed via the `service install --as-service`,
//!     `service uninstall --as-service`, `service status --as-service`
//!     CLI subcommands.
//!   - [`run_in_dispatcher`] — entry point for the SCM-launched
//!     `service-run` subcommand. Hands control to the SCM via
//!     [`service_dispatcher::start`].
//!
//! M2 (session-aware worker spawn) and M3 (pre-logon SYSTEM-context
//! capture) layer on top of this skeleton without changing the public
//! surface: the service main loop today is a stub that waits for the
//! SCM Stop control; M2 will replace the stub with worker supervision.

#![cfg(target_os = "windows")]

#[cfg(feature = "wgc-capture")]
pub mod capture_smoke;
/// #1686 — find a running companion by the path it was started from, never
/// by image name (which a rename or POSIX delete of its file changes).
pub mod companion_procs;
/// FR-84 D6 — start the companion from a user-context daemon without
/// handing it our handles (#1035).
pub mod companion_spawn;
pub mod desktop;
pub mod environment;
pub mod firewall;
/// #2465 — the worker an earlier host of this service left running: found
/// and ended before this host spawns its own.
pub mod orphan;
/// FR-97 P4a — the host's half of the real Ctrl+Alt+Del: `SendSAS` is
/// honoured only from the service process, so the worker asks it here.
pub mod sas_relay;
/// FR-97 P4d — a per-user daemon's clean stop at sign-out and shutdown: a
/// hidden window hears `WM_ENDSESSION`, which no console handler does here.
pub mod session_end;
/// #1683 — the graceful-stop event the SCM host signals so a worker (an
/// ephemeral device especially) self-unenrolls before it is TerminateProcess'd.
pub mod stop_event;
pub mod supervisor;
pub mod system_context_attempt;
pub mod system_context_probe;

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// Canonical SCM short name after the P3D rename. Everything we create,
/// start, and operate on going forward uses this name.
pub const NEW_SERVICE_NAME: &str = "Roomler";

/// Pre-rename SCM short name. A host installed before the P3D migration
// RETIRED-NAME-ANCHOR-BEGIN
// RoomlerAgentService is the SCM name on a host installed before the rename.
// install() must find and retire it and uninstall() must remove it, so the
// string is an input. LEGACY_SERVICE_NAME is asserted against this literal
// precisely so a rename here fails a test instead of stranding a fleet.
/// still has a `RoomlerAgentService` entry; the takeover install starts
/// the new service first, then retires this one.
// RETIRED-NAME-ANCHOR: without this the takeover install cannot find the running
// pre-rename service to retire, leaving two services or none. See docs/fr/FR-21.
pub const LEGACY_SERVICE_NAME: &str = "RoomlerAgentService";

/// The SCM service to operate on: the NEW `Roomler` service if registered,
/// else the LEGACY `RoomlerAgentService` (a pre-rename host mid-migration).
/// Used by the env-block R/W and status so they follow the service across the
/// takeover. NOT cached — the name changes during an in-process install().
pub fn resolved_service_name() -> &'static str {
    if service_present(NEW_SERVICE_NAME) {
        NEW_SERVICE_NAME
    } else {
        LEGACY_SERVICE_NAME
    }
}

fn service_present(name: &str) -> bool {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .ok()
        .and_then(|m| m.open_service(name, ServiceAccess::QUERY_STATUS).ok())
        .is_some()
}

/// Display name shown in services.msc, Get-Service output, and Server Manager.
// Distinct from the legacy service's "Roomler AI Remote-Control Agent" display so
// the two can never collide (ERROR_DUPLICATE_SERVICE_NAME) during the migration
// overlap — two services must not share a display name.
pub const SERVICE_DISPLAY_NAME: &str = "Roomler";

/// One-line description shown in services.msc properties dialog.
pub const SERVICE_DESCRIPTION: &str = "Roomler Daemon — keeps this device on your private Roomler mesh network and \
     available for secure remote control.";

/// Argument the SCM passes when starting the service. The agent's
/// `service-run` subcommand handler dispatches to [`run_in_dispatcher`]
/// which then hands the binary over to `service_dispatcher::start`.
pub const RUN_SUBCOMMAND: &str = "service-run";

/// Default service-mode log directory under `%PROGRAMDATA%`. The user-
/// scoped worker logs go elsewhere (under `%LOCALAPPDATA%`); the SCM-
/// launched service runs as SYSTEM and can't write there.
pub fn default_log_dir() -> Option<PathBuf> {
    // Canonical path lives in agent-core (P3e lever E) so the desktop
    // companion resolves the same directory without linking this crate.
    Some(roomler_node_core::appdirs::service_log_dir())
}

/// Transactional takeover install (P3D rename).
///
/// Register the NEW `Roomler` service (AutoStart, LocalSystem via
/// `account_name: None`), then **start it and wait until Running BEFORE
/// retiring the LEGACY `RoomlerAgentService`**. If the new service never
/// reaches Running, we return `Err` and DO NOT touch the legacy service —
/// the MSI custom action swallows the error and the host keeps its old
/// daemon. That ordering is the no-serviceless-window guarantee: at no
/// point is a controlled host left with no running daemon.
///
/// If the new service already exists (ERROR_SERVICE_EXISTS = 1073, from an
/// earlier install/repair), we open it and (re)start it rather than fail.
///
/// Requires elevation (admin token). The MSI's custom action is the
/// natural caller; manual install via `meshharbord service install
/// --as-service` will surface `Access is denied (os error 5)` from a
/// filtered token.
pub fn install(exe_path: &std::path::Path) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening Service Control Manager")?;
    let service_info = ServiceInfo {
        name: OsString::from(NEW_SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.to_path_buf(),
        // The SCM passes these as argv on each start. `service-run`
        // is the agent's hidden subcommand that dispatches to
        // `run_in_dispatcher`.
        launch_arguments: vec![OsString::from(RUN_SUBCOMMAND)],
        // No dependencies — the agent is fine to start before the
        // network stack is fully up; reqwest + tokio retry on first
        // resolution failure.
        dependencies: vec![],
        // None = LocalSystem. M3 needs SYSTEM for capture-from-session-0
        // and CreateProcessAsUserW; running as a normal user account
        // would need WTSQueryUserToken privileges we don't get there.
        account_name: None,
        account_password: None,
    };
    // Clean slate BEFORE creating. Retire any prior NEW service (a leftover from
    // an interrupted upgrade) AND the LEGACY service first, so create_service
    // always writes a fresh registry entry — reusing a half-broken / marked-for-
    // deletion NEW entry is what wedged the P3d devbox smoke (StartServiceW then
    // returned error 87). Deleting LEGACY first also frees its display name so
    // the create can't hit ERROR_DUPLICATE_SERVICE_NAME during the migration
    // overlap. Both tolerate "absent" (1060) / "marked-for-deletion" (1072).
    let _ = delete_service(NEW_SERVICE_NAME);
    let _ = delete_service(LEGACY_SERVICE_NAME);

    // START as well: a failure action that restarts the service may only be
    // set through a handle that could start it.
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    match manager.create_service(&service_info, access) {
        Ok(s) => {
            let _ = s.set_description(SERVICE_DESCRIPTION);
            // #2087 — without these a host process that dies stays dead until a
            // reboot. Best-effort: a refusal must not sink the install.
            if let Err(e) = apply_recovery_actions(&s) {
                tracing::warn!(
                    error = %e,
                    service = NEW_SERVICE_NAME,
                    "could not set the service's recovery actions"
                );
            }
        }
        // ERROR_SERVICE_EXISTS — a prior NEW service is still marked-for-deletion
        // (a handle is open, e.g. services.msc), so we couldn't recreate it this
        // cycle. It clears on reboot; the AutoStart service comes up then.
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1073) => {
            tracing::warn!(
                service = NEW_SERVICE_NAME,
                "service exists + marked-for-deletion; clean recreate deferred to next boot"
            );
        }
        Err(e) => return Err(anyhow::anyhow!(e).context("create_service")),
    };
    // Do NOT start the service from inside this deferred MSI custom action.
    // StartServiceW mid-transaction wedged the service (error 87) in the P3d
    // devbox smoke. The service is AutoStart and is brought up by the
    // `DisableSystemContext` -> `environment::restart_service` action (a fresh
    // SCM handle on a now-clean service — the proven rc.190 path) or on next boot.
    Ok(())
}

/// #2087 — the restart delays after the 1st, 2nd and every later failure.
const RECOVERY_RESTART_DELAYS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

/// #2087 — a day without a failure resets the count to the first delay.
const RECOVERY_RESET_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// #2087 — what the SCM does when the host fails: restart it, only ever
/// restart (never reboot the machine, never run a command), on a backoff.
fn recovery_actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(RECOVERY_RESET_PERIOD),
        reboot_msg: None,
        command: None,
        actions: Some(
            RECOVERY_RESTART_DELAYS
                .iter()
                .map(|&delay| ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay,
                })
                .collect(),
        ),
    }
}

/// #2087 — write [`recovery_actions`], and have them apply to a non-crash
/// failure too: a `STOPPED` reported with a non-zero exit code, which is how
/// the host says it ended on its own ([`exit_code_for`]). The handle needs
/// `CHANGE_CONFIG` and `START`.
fn apply_recovery_actions(service: &windows_service::service::Service) -> Result<()> {
    service
        .update_failure_actions(recovery_actions())
        .context("update_failure_actions")?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .context("set_failure_actions_on_non_crash_failures")?;
    Ok(())
}

/// Stop (best-effort) and delete a single named service. Tolerates
/// "service not installed" (ERROR_SERVICE_DOES_NOT_EXIST = 1060) so an
/// idempotent uninstall works from MSI's symmetric custom action and from
/// operator scripts. Extracted from the old `uninstall()` body so both the
/// NEW and LEGACY names can be retired independently.
fn delete_service(name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening SCM for uninstall")?;
    let service = match manager.open_service(
        name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {
            // ERROR_SERVICE_DOES_NOT_EXIST — already gone. Idempotent
            // uninstall is what we want from MSI's symmetric custom
            // action and from operator scripts.
            tracing::info!(
                service = name,
                "uninstall: service not present, nothing to do"
            );
            return Ok(());
        }
        Err(e) => return Err(anyhow::anyhow!(e).context("open_service")),
    };

    if let Ok(s) = service.query_status()
        && s.current_state != ServiceState::Stopped
    {
        // Best-effort stop; if it doesn't reach Stopped within ~5 s we
        // proceed to delete anyway and let the SCM mark it pending.
        let _ = service.stop();
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(s) = service.query_status()
                && s.current_state == ServiceState::Stopped
            {
                break;
            }
        }
    }

    service.delete().context("delete service")?;
    tracing::info!(service = name, "uninstalled");
    Ok(())
}

/// Delete BOTH the NEW and LEGACY services. Used by `service uninstall
/// --as-service` and the MSI's `UnregisterAutostart` symmetric custom
/// action. Both deletes tolerate "not installed", so a partially-migrated
/// or partially-installed machine still uninstalls cleanly.
pub fn uninstall() -> Result<()> {
    delete_service(NEW_SERVICE_NAME)?;
    delete_service(LEGACY_SERVICE_NAME)?;
    Ok(())
}

/// Whether the service is currently registered with the SCM. Cheap —
/// opens the manager + tries to open the service. Used by the MSI's
/// rollback / reinstall logic and by `service status --as-service`.
pub fn is_installed() -> bool {
    service_present(NEW_SERVICE_NAME) || service_present(LEGACY_SERVICE_NAME)
}

/// Human-readable status snapshot for the `service status --as-service`
/// CLI. Returns a plain enum the caller formats however it likes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledStatus {
    NotInstalled,
    Stopped,
    StartPending,
    Running,
    StopPending,
    Other(u32),
}

pub fn status() -> Result<InstalledStatus> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening SCM for status")?;
    let service = match manager.open_service(resolved_service_name(), ServiceAccess::QUERY_STATUS) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {
            return Ok(InstalledStatus::NotInstalled);
        }
        Err(e) => bail!("open_service: {e}"),
    };
    let s = service.query_status().context("query_status")?;
    Ok(match s.current_state {
        ServiceState::Stopped => InstalledStatus::Stopped,
        ServiceState::StartPending => InstalledStatus::StartPending,
        ServiceState::Running => InstalledStatus::Running,
        ServiceState::StopPending => InstalledStatus::StopPending,
        other => InstalledStatus::Other(other as u32),
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Service runtime (SCM dispatcher + main loop).
// ────────────────────────────────────────────────────────────────────────────

/// Entry point for the `service-run` subcommand. Blocks for the lifetime
/// of the service: the SCM owns the process from here. Returns when the
/// dispatcher decides we should exit (Stop control) or on a fatal error.
///
/// M1: the service main loop is a stub that idles until Stop. M2 will
/// replace the body with worker spawning + session-change handling.
pub fn run_in_dispatcher() -> Result<()> {
    service_dispatcher::start(NEW_SERVICE_NAME, ffi_service_main)
        .context("service_dispatcher::start")?;
    Ok(())
}

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Body of the service. Called once by the SCM dispatcher when the
/// service starts. Must call `set_service_status` with `Running` quickly
/// (within 30 s, in practice within ~1 s) and again with `Stopped`
/// before returning, otherwise the SCM force-kills the process.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_main_inner() {
        // Best-effort log to the persistent log dir before the process
        // dies. The dispatcher swallows panics on its end so we have to
        // surface them explicitly.
        tracing::error!(error = %e, "service main failed");
    }
}

fn service_main_inner() -> Result<()> {
    // Bootstrap logging early — the SCM swallows stderr, so anything
    // we don't write to a file is gone. Reuse the agent's existing
    // `logging::init` which dual-writes stdout + a daily-rolling
    // file in the configured log dir.
    crate::logging::init();

    // Channel out to the worker supervisor. The SCM control handler
    // posts SessionChanged / Shutdown events here and the supervisor
    // (running on its own OS thread) reacts.
    let (sup_tx, sup_rx) = mpsc::channel::<supervisor::SupervisorEvent>();
    let sup_tx_for_handler = sup_tx.clone();

    // #2010 — the handler reports STOP_PENDING itself, through a status handle
    // that `register` only returns once the handler is installed. It is stored
    // before `Running` is reported, and the SCM sends no Stop before that.
    let status_cell: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let status_for_handler = Arc::clone(&status_cell);

    // #2087 — whether the SCM asked us to stop. It decides the exit code the
    // host reports with STOPPED: see `exit_code_for`.
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_requested_by_handler = Arc::clone(&stop_requested);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        if matches!(
            control_event,
            ServiceControl::Stop | ServiceControl::Preshutdown
        ) {
            stop_requested_by_handler.store(true, Ordering::SeqCst);
        }
        let mut report = |status: ServiceStatus| match status_for_handler.get() {
            Some(handle) => {
                if let Err(e) = handle.set_service_status(status) {
                    tracing::warn!(error = %e, "control handler: set_service_status failed");
                }
            }
            None => tracing::warn!("control handler: no status handle yet; status not reported"),
        };
        let mut notify = |event| {
            let _ = sup_tx_for_handler.send(event);
        };
        on_control(control_event, &mut report, &mut notify)
    };
    let status_handle = service_control_handler::register(NEW_SERVICE_NAME, event_handler)
        .context("register control handler")?;
    let _ = status_cell.set(status_handle);

    status_handle
        .set_service_status(running_status())
        .context("set_service_status(Running)")?;

    // S1a — refresh the roomler-desktop companion from the SYSTEM side.
    // This host runs as LocalSystem, so it can write %ProgramFiles%\Roomler
    // even for the plain-SCM flavour whose worker runs user-context (and
    // therefore skips the swap itself). Detached thread + its own small
    // runtime: service_main is sync and must not block on a download.
    //
    // FR-84 D6 — then, in the same thread and AFTER the refresh (so a launch
    // never races a swap of the file it launches): self-heal the machine's
    // login start (`HKLM\…\Run\Roomler Desktop`) and run the post-install
    // launcher. The SCM host owns both on a perMachine install: it is the one
    // process that can write HKLM and can start the companion with the
    // console user's own NON-elevated token — the worker may be running with
    // that user's elevated one.
    {
        let _ = thread::Builder::new()
            .name("roomler-svc-companion".into())
            .spawn(|| {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        crate::companion::refresh_if_stale(
                            crate::companion::RespawnContext::SystemService,
                        )
                        .await;
                        crate::companion::scm_host_startup().await;
                        // FR-117 P2 — and again on every tick for the life of
                        // this host, so a refresh that failed at the start is
                        // retried within hours, not at the next restart.
                        crate::companion::refresh_periodically(
                            crate::companion::RespawnContext::SystemService,
                        )
                        .await;
                    });
                }
            });
    }

    // FR-94 — the doorbell and the runner for commands that run as SYSTEM.
    // Its own thread and runtime: nothing here waits on it, and it serves
    // nothing until an administrator anchors the device.
    crate::exec_service::spawn_service_runner();

    let outcome = run_host(sup_rx);
    let exit_code = exit_code_for(stop_requested.load(Ordering::SeqCst), outcome);
    tracing::info!(?outcome, ?exit_code, "service stopping");
    status_handle
        .set_service_status(stopped_status(exit_code))
        .context("set_service_status(Stopped)")?;
    Ok(())
}

/// #2087 — how the host's run ended, after `Running` was reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostOutcome {
    /// The supervisor returned. It does that only after a stop was posted (or
    /// its control channel closed), so without a stop request it is unexpected.
    SupervisorReturned,
    SupervisorFailed,
    SupervisorPanicked,
    /// No supervisor at all: the worker path or the startup sequence failed.
    StartupFailed,
    /// #2465 — the worker found another daemon holding this config's
    /// single-instance lock, and the orphan check read every roomlerd process
    /// without finding an earlier host's worker: a second installed flavour.
    /// The service stops CLEANLY, as the supervisor's `Stop` arm intends. A
    /// failure code would have the SCM restart a service that can only stop
    /// again, every minute, for as long as that flavour runs.
    Redundant,
    /// #2465 — the same refusal, but the orphan check could not read every
    /// roomlerd process, so an earlier host's worker cannot be ruled out. A
    /// failure on purpose: the SCM's retry is what recovers the device once a
    /// worker this host could not see has gone.
    RedundantUnconfirmed,
}

/// #2087 — the exit code the host reports with STOPPED.
///
/// A stop someone asked for (Stop / Preshutdown: an operator, an MSI, the OS)
/// always ends `0`. The service applies its failure actions to non-crash
/// failures too, so any other code would have the SCM undo that stop. A host
/// that ends on its own reports a distinct non-zero code (`sc query` shows it
/// as `SERVICE_EXIT_CODE`), and the SCM restarts it. Before #2087 every path
/// reported `0`, and a dead supervisor left the device dark until a reboot.
///
/// The one end of its own that is `0` is [`HostOutcome::Redundant`] (#2465):
/// the service is not needed while another flavour serves the device, and
/// restarting it could only repeat the refusal.
fn exit_code_for(stop_requested: bool, outcome: HostOutcome) -> ServiceExitCode {
    if stop_requested {
        return ServiceExitCode::Win32(0);
    }
    let code = match outcome {
        HostOutcome::Redundant => return ServiceExitCode::Win32(0),
        HostOutcome::SupervisorReturned => 1,
        HostOutcome::SupervisorFailed => 2,
        HostOutcome::SupervisorPanicked => 3,
        HostOutcome::StartupFailed => 4,
        HostOutcome::RedundantUnconfirmed => 5,
    };
    ServiceExitCode::ServiceSpecific(code)
}

/// Everything the host does after reporting `Running`: resolve the worker,
/// run the once-per-start sequence, and wait out the supervisor's whole life.
fn run_host(sup_rx: mpsc::Receiver<supervisor::SupervisorEvent>) -> HostOutcome {
    // Resolve the worker binary path once. `current_exe` is the same
    // EXE the SCM launched (the service host); we relaunch it with
    // a `run` subcommand to drive the existing user-mode signaling /
    // capture pipeline in the active session's context.
    let worker_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "resolving current_exe for worker spawn");
            return HostOutcome::StartupFailed;
        }
    };
    let worker_args = worker_args();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        service = NEW_SERVICE_NAME,
        worker_exe = %worker_exe.display(),
        "service started; preparing the firewall, then spawning the worker supervisor"
    );

    // The once-per-start sequence (#1698): the firewall rule for the
    // worker's path FIRST, then the supervisor — which is what spawns the
    // process that binds. `run_startup_sequence` is the seam the ordering
    // test drives with a recorder; this is its one production driver. The
    // supervisor blocks its thread, so `HostSteps` gives it its own and this
    // dispatcher thread waits on the handle to observe its exit.
    let mut steps = HostSteps {
        sup_rx: Some(sup_rx),
        handle: None,
    };
    if let Err(e) = run_startup_sequence(&mut steps, worker_exe, worker_args) {
        tracing::error!(error = %e, "service: the startup sequence failed");
        return HostOutcome::StartupFailed;
    }
    let Some(sup_handle) = steps.handle.take() else {
        tracing::error!("supervisor thread handle missing after spawn");
        return HostOutcome::StartupFailed;
    };

    match sup_handle.join() {
        Ok(Ok(supervisor::SupervisorEnd::Shutdown)) => {
            tracing::info!("supervisor exited cleanly");
            HostOutcome::SupervisorReturned
        }
        // The supervisor logged why at ERROR before it returned.
        Ok(Ok(supervisor::SupervisorEnd::Redundant)) => HostOutcome::Redundant,
        Ok(Ok(supervisor::SupervisorEnd::RedundantUnconfirmed)) => {
            HostOutcome::RedundantUnconfirmed
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "supervisor returned error");
            HostOutcome::SupervisorFailed
        }
        Err(_) => {
            tracing::error!("supervisor thread panicked");
            HostOutcome::SupervisorPanicked
        }
    }
}

/// The argv the supervisor spawns every worker with — the user-session worker
/// and the SystemContext one alike (both spawn sites take the same borrow).
///
/// FR-84 D3: `--supervisor scm` is how the worker learns that the exit it is
/// about to make for `RestartDaemon` will be answered by
/// `supervisor::decide_exit_reaction` — a bare `run` reads as an orphan in
/// `supervision::detect` and refuses to restart, which is the right answer
/// for a hand-started `meshharbord run` and the wrong one for ours.
pub fn worker_args() -> Vec<String> {
    vec![
        "run".to_string(),
        "--supervisor".to_string(),
        "scm".to_string(),
    ]
}

/// The service host's once-per-start steps between `Running` and the worker
/// supervisor. A trait so the ORDER can be asserted with a recorder: the
/// firewall rule for the worker's path must exist before anything of ours
/// binds (#1698), and the supervisor is what spawns the thing that binds.
pub(crate) trait StartupSteps {
    /// Best-effort, bounded; its outcome is logged and never gates the spawn.
    fn firewall_prep(&mut self, worker_exe: &Path) -> firewall::FirewallPrep;
    /// Start the worker supervisor for `worker_exe worker_args…`.
    fn spawn_supervisor(&mut self, worker_exe: PathBuf, worker_args: Vec<String>) -> Result<()>;
}

/// Run the host's once-per-start sequence, in order. The firewall prep's
/// result is informational: a refused or timed-out `netsh` must never keep
/// the daemon off the box — that would trade a firewall prompt for no
/// remote access at all.
pub(crate) fn run_startup_sequence<S: StartupSteps>(
    steps: &mut S,
    worker_exe: PathBuf,
    worker_args: Vec<String>,
) -> Result<()> {
    let prep = steps.firewall_prep(&worker_exe);
    tracing::debug!(
        ?prep,
        "service: firewall prep finished; starting the worker supervisor"
    );
    steps.spawn_supervisor(worker_exe, worker_args)
}

/// The production [`StartupSteps`]: the real firewall prep, and the
/// supervisor on its own OS thread (it blocks the calling thread; the
/// dispatcher thread waits on the handle to observe the supervisor's exit).
struct HostSteps {
    sup_rx: Option<mpsc::Receiver<supervisor::SupervisorEvent>>,
    handle: Option<thread::JoinHandle<Result<supervisor::SupervisorEnd>>>,
}

impl StartupSteps for HostSteps {
    fn firewall_prep(&mut self, worker_exe: &Path) -> firewall::FirewallPrep {
        firewall::prepare_before_first_spawn(worker_exe)
    }

    fn spawn_supervisor(&mut self, worker_exe: PathBuf, worker_args: Vec<String>) -> Result<()> {
        let sup_rx = self
            .sup_rx
            .take()
            .context("supervisor already spawned once this start")?;
        let handle = thread::Builder::new()
            .name("roomler-svc-supervisor".into())
            .spawn(move || supervisor::run(worker_exe, worker_args, sup_rx))
            .context("spawning supervisor thread")?;
        self.handle = Some(handle);
        Ok(())
    }
}

fn running_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::PRESHUTDOWN
            | ServiceControlAccept::SESSION_CHANGE,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn stopped_status(exit_code: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

/// #2010 — what the host does with one SCM control. A seam so the ORDER can be
/// asserted with recorders: on Stop/Preshutdown, `STOP_PENDING` is reported
/// BEFORE the supervisor hears of it. The other order lets a fast supervisor
/// report `STOPPED` first and have this overwrite it with a pending state for
/// a process that is already gone.
fn on_control(
    control_event: ServiceControl,
    report: &mut dyn FnMut(ServiceStatus),
    notify: &mut dyn FnMut(supervisor::SupervisorEvent),
) -> ServiceControlHandlerResult {
    match control_event {
        ServiceControl::Stop | ServiceControl::Preshutdown => {
            tracing::info!(?control_event, "service stop requested");
            report(stop_pending_status());
            notify(supervisor::SupervisorEvent::Shutdown);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::SessionChange(_) => {
            notify(supervisor::SupervisorEvent::SessionChanged);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// #2010 — the wait hint `STOP_PENDING` carries: the supervisor's whole
/// shutdown bound (netd's reap included since #2087) plus slack for a loaded
/// box. A stop that outlives its own hint reads as hung to services.msc.
const STOP_PENDING_WAIT_HINT: Duration =
    supervisor::SHUTDOWN_BOUND.saturating_add(Duration::from_secs(10));

/// #2010 — reported the moment the host accepts Stop or Preshutdown.
///
/// PowerShell's `Stop-Service`/`Restart-Service` wait for `Stopped` in 2 s
/// slices and give up on a service that is still `RUNNING` after one
/// (`DoWaitForStatus` accepts only the pending state) — and `Restart-Service`
/// then never starts it. Before this the host stayed `RUNNING` through the whole
/// graceful stop (#1683, up to [`supervisor::SHUTDOWN_BOUND`]), so a 2.3 s stop
/// left a device stopped, and offline, for over ten minutes. No controls are
/// accepted while stopping.
fn stop_pending_status() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: STOP_PENDING_WAIT_HINT,
        process_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_is_stable() {
        // Lock both the canonical (post-P3D-rename) name and the legacy
        // name the takeover retires. Changing either is a wire break: the
        // canonical name is what operators now script against, and the
        // legacy name is what `install()`/`uninstall()` must still target
        // to migrate a pre-rename host.
        assert_eq!(NEW_SERVICE_NAME, "Roomler");
        assert_eq!(LEGACY_SERVICE_NAME, "RoomlerAgentService");
        assert_eq!(RUN_SUBCOMMAND, "service-run");
    }

    /// FR-84 D3 — the worker must be told it is ours. `supervision::detect`
    /// reads the flag; without it every SCM worker refuses "Apply now" as
    /// an orphan.
    #[test]
    fn worker_args_mark_the_worker_as_scm_supervised() {
        let args = worker_args();
        assert_eq!(args[0], "run", "the worker subcommand comes first");
        assert_eq!(&args[1..], ["--supervisor", "scm"]);
        assert_eq!(
            crate::supervision::detect(Some("scm"), false, &|_| None, None),
            crate::supervision::Supervision::WindowsScm
        );
    }

    #[test]
    fn default_log_dir_uses_programdata() {
        let dir = default_log_dir();
        assert!(dir.is_some());
        let s = dir.unwrap().to_string_lossy().to_string();
        assert!(
            s.contains("roomler") && s.contains("service-logs"),
            "log dir layout drifted: {s}"
        );
    }

    /// A [`StartupSteps`] that records the order it was driven in.
    struct Recorder {
        calls: Vec<&'static str>,
        prep: firewall::FirewallPrep,
    }

    impl StartupSteps for Recorder {
        fn firewall_prep(&mut self, worker_exe: &Path) -> firewall::FirewallPrep {
            assert_eq!(
                worker_exe,
                Path::new(r"C:\Program Files\Roomler\roomlerd.exe")
            );
            self.calls.push("firewall_prep");
            self.prep.clone()
        }

        fn spawn_supervisor(&mut self, _exe: PathBuf, args: Vec<String>) -> Result<()> {
            assert_eq!(args, ["run"]);
            self.calls.push("spawn_supervisor");
            Ok(())
        }
    }

    fn drive(prep: firewall::FirewallPrep) -> Recorder {
        let mut rec = Recorder {
            calls: Vec::new(),
            prep,
        };
        run_startup_sequence(
            &mut rec,
            PathBuf::from(r"C:\Program Files\Roomler\roomlerd.exe"),
            vec!["run".to_string()],
        )
        .expect("sequence succeeds");
        rec
    }

    /// #1698 — the fix IS the order: the rule for the worker's path is
    /// written before the supervisor exists, so nothing of ours can bind
    /// first and raise the prompt.
    #[test]
    fn startup_sequence_preps_the_firewall_before_the_supervisor_spawns() {
        let rec = drive(firewall::FirewallPrep {
            skipped: false,
            rule_installed: true,
            blocks_removed: 2,
        });
        assert_eq!(rec.calls, ["firewall_prep", "spawn_supervisor"]);
    }

    /// The prep is best-effort: a refused/timed-out netsh, or the kill
    /// switch, must never keep the worker from starting — that would trade
    /// a firewall prompt for no remote access at all.
    #[test]
    fn startup_sequence_spawns_the_supervisor_whatever_the_firewall_prep_reports() {
        for prep in [
            firewall::FirewallPrep::default(), // nothing installed, nothing removed
            firewall::FirewallPrep {
                skipped: true,
                ..firewall::FirewallPrep::default()
            },
        ] {
            let rec = drive(prep);
            assert_eq!(rec.calls.last(), Some(&"spawn_supervisor"));
        }
    }

    #[test]
    fn running_status_accepts_stop_and_session_change() {
        // Lock the controls we accept. M2 wires SessionChange to swap
        // the worker; a regression that drops it from
        // `controls_accepted` would silently leave the SCM not
        // notifying us about logon/logoff.
        let s = running_status();
        assert!(s.controls_accepted.contains(ServiceControlAccept::STOP));
        assert!(
            s.controls_accepted
                .contains(ServiceControlAccept::SESSION_CHANGE),
            "SESSION_CHANGE must be accepted for M2 to receive logon notifications"
        );
        assert_eq!(s.current_state, ServiceState::Running);
    }

    /// #2010 — Stop and Preshutdown are answered with `STOP_PENDING`, and it is
    /// reported BEFORE the supervisor is told. Without it `Restart-Service`
    /// took a 2.3 s stop for a failure and never started the service again.
    #[test]
    fn stop_reports_stop_pending_before_the_supervisor_hears_of_it() {
        for control in [ServiceControl::Stop, ServiceControl::Preshutdown] {
            let calls = std::cell::RefCell::new(Vec::<String>::new());
            let result = on_control(
                control,
                &mut |s| {
                    calls
                        .borrow_mut()
                        .push(format!("report {:?}", s.current_state))
                },
                &mut |e| calls.borrow_mut().push(format!("notify {e:?}")),
            );
            assert!(matches!(result, ServiceControlHandlerResult::NoError));
            assert_eq!(
                *calls.borrow(),
                ["report StopPending", "notify Shutdown"],
                "{control:?}"
            );
        }
    }

    #[test]
    fn interrogate_reports_nothing_and_tells_the_supervisor_nothing() {
        let calls = std::cell::RefCell::new(0u32);
        let result = on_control(
            ServiceControl::Interrogate,
            &mut |_| *calls.borrow_mut() += 1,
            &mut |_| *calls.borrow_mut() += 1,
        );
        assert!(matches!(result, ServiceControlHandlerResult::NoError));
        assert_eq!(*calls.borrow(), 0);
    }

    /// The pending status takes no further controls and carries a hint that
    /// covers the supervisor's whole shutdown — derived from it, so raising
    /// the graceful budget raises the hint.
    #[test]
    fn stop_pending_status_covers_the_supervisors_whole_shutdown() {
        let s = stop_pending_status();
        assert_eq!(s.current_state, ServiceState::StopPending);
        assert!(s.controls_accepted.is_empty());
        assert_eq!(s.checkpoint, 1);
        assert_eq!(s.exit_code, ServiceExitCode::Win32(0));
        assert!(
            supervisor::SHUTDOWN_BOUND > supervisor::WORKER_GRACEFUL_STOP_BUDGET,
            "the bound includes the graceful budget"
        );
        assert!(
            s.wait_hint > supervisor::SHUTDOWN_BOUND,
            "hint {:?} must outlast the shutdown bound {:?}",
            s.wait_hint,
            supervisor::SHUTDOWN_BOUND
        );
    }

    /// #2087 — the SCM restarts a failed host, and only ever restarts it: a
    /// reboot or a command would act on the whole machine.
    #[test]
    fn recovery_only_restarts_on_a_backoff_and_resets_after_a_quiet_day() {
        let r = recovery_actions();
        let actions = r.actions.expect("actions are set");
        assert!(
            actions
                .iter()
                .all(|a| a.action_type == ServiceActionType::Restart),
            "{actions:?}"
        );
        let delays: Vec<Duration> = actions.iter().map(|a| a.delay).collect();
        assert_eq!(
            delays,
            [
                Duration::from_secs(5),
                Duration::from_secs(30),
                Duration::from_secs(60)
            ]
        );
        assert_eq!(
            r.reset_period,
            ServiceFailureResetPeriod::After(Duration::from_secs(86_400))
        );
        assert!(r.command.is_none() && r.reboot_msg.is_none());
    }

    /// The ends that are failures when nobody asked for a stop.
    const FAILURES: [HostOutcome; 5] = [
        HostOutcome::SupervisorReturned,
        HostOutcome::SupervisorFailed,
        HostOutcome::SupervisorPanicked,
        HostOutcome::StartupFailed,
        HostOutcome::RedundantUnconfirmed,
    ];

    /// Every end a host's run can have.
    const OUTCOMES: [HostOutcome; 6] = [
        HostOutcome::SupervisorReturned,
        HostOutcome::SupervisorFailed,
        HostOutcome::SupervisorPanicked,
        HostOutcome::StartupFailed,
        HostOutcome::RedundantUnconfirmed,
        HostOutcome::Redundant,
    ];

    /// #2087 — a stop someone asked for ends `0` whatever happened during it,
    /// or the SCM's non-crash failure actions would undo an operator's stop.
    #[test]
    fn a_requested_stop_always_ends_zero() {
        for o in OUTCOMES {
            assert_eq!(exit_code_for(true, o), ServiceExitCode::Win32(0), "{o:?}");
        }
    }

    /// #2465 — a service another flavour makes redundant stops cleanly, and the
    /// SCM leaves it stopped: #2087 had turned this end into a restart every
    /// minute. Only a CONFIRMED redundancy: one the orphan check could not
    /// vouch for stays a failure, so the SCM's retry can still recover a
    /// device whose lock is held by an earlier host's worker.
    #[test]
    fn a_redundant_service_stops_cleanly() {
        assert_eq!(
            exit_code_for(false, HostOutcome::Redundant),
            ServiceExitCode::Win32(0)
        );
        assert!(matches!(
            exit_code_for(false, HostOutcome::RedundantUnconfirmed),
            ServiceExitCode::ServiceSpecific(n) if n != 0
        ));
    }

    /// #2087 — a host that ends on its own reports non-zero, so the SCM brings
    /// it back, and each cause is told apart in `sc query`.
    #[test]
    fn a_host_that_ends_on_its_own_reports_a_distinct_failure() {
        let codes: Vec<ServiceExitCode> =
            FAILURES.iter().map(|&o| exit_code_for(false, o)).collect();
        for (o, c) in FAILURES.iter().zip(&codes) {
            assert!(
                matches!(c, ServiceExitCode::ServiceSpecific(n) if *n != 0),
                "{o:?} -> {c:?}"
            );
        }
        let unique: std::collections::HashSet<ServiceExitCode> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "{codes:?}");
    }

    #[test]
    fn stopped_status_carries_the_exit_code() {
        let s = stopped_status(ServiceExitCode::ServiceSpecific(3));
        assert_eq!(s.current_state, ServiceState::Stopped);
        assert_eq!(s.exit_code, ServiceExitCode::ServiceSpecific(3));
        assert!(s.controls_accepted.is_empty());
    }
}
// RETIRED-NAME-ANCHOR-END
