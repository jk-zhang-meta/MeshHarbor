// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D3 — who supervises this daemon process, decided once at startup from
//! evidence the supervisor itself left behind, never from the config file; and
//! the decision that rests on it, whether `Request::RestartDaemon` ("Apply
//! now") may go ahead.
//!
//! The mechanism of that verb is "exit, and let the supervisor relaunch me",
//! and that is only a restart if something *will* relaunch the process. An
//! orphan `meshharbord run` — a hand-started process, a pre-rc.435 root daemon, a
//! container's PID 1 — that exits on request is not restarted; it is **taken
//! offline**, by the person who pressed a button expecting the opposite
//! (`docs/remote-config.md` §7b). So the default answer is
//! [`Supervision::None`], and every other variant has to be earned by a signal
//! only that supervisor produces:
//!
//! | variant | evidence | who relaunches, and on what |
//! |---|---|---|
//! | `WindowsScm` | the SCM host spawns its workers as `run --supervisor scm` (`win_service::worker_args`) | the in-process supervisor — exit **0** is `ExitReaction::Respawn`, no backoff |
//! | `WindowsTask` | the per-user Scheduled Task's action is `run --supervisor task` (`service.rs`) | the **caller**: `<RestartOnFailure>` is a minute away at best, so whoever asked runs `meshharbord service start` once the old process is gone |
//! | `MacosSupervisor` | the FR-43 root daemon spawns `run --supervised` | the root daemon's poll loop, any exit, ≥ 1 s later |
//! | `Launchd` | `XPC_SERVICE_NAME` is one of OUR labels (`com.roomler.*`) | launchd — `KeepAlive{SuccessfulExit:false}` relaunches a **non-zero** exit only |
//! | `Systemd` | `INVOCATION_ID` is set AND this process sits in one of OUR units' cgroups | systemd — and at request time the unit's EFFECTIVE policy is read back (`systemctl show`) before anything exits |
//!
//! Hence two exit codes ([`Supervision::restart_exit_code`]): `0` under the
//! SCM, whose supervisor already treats a clean exit as "come straight back",
//! and [`crate::watchdog::RESTART_REQUESTED_EXIT_CODE`] everywhere else,
//! because launchd reads a `0` as "done, stay down".
//!
//! ⚠️ The two rows backed by the environment need more than the variable.
//! `INVOCATION_ID` alone is inherited: on a GNOME desktop every terminal is a
//! child of `gnome-terminal-server.service`, so a shell there carries a valid
//! `INVOCATION_ID`, and a hand-run `meshharbord run` from it would have read as
//! "systemd will restart me". The cgroup names the unit, and only our own unit
//! names count, by exact name. That still says nothing about what a drop-in did
//! to the unit's `Restart=`, nor whether this process is the unit's MAIN
//! process (the only one systemd restarts) rather than something the daemon
//! spawned — so [`systemd_restarts`] reads both back from systemd itself before
//! a restart is accepted. `XPC_SERVICE_NAME` is likewise set for every
//! LaunchServices app (`application.com.apple.Terminal.…`, or plain `0`),
//! hence the label prefix; a child of the job inherits it too, but a child of
//! a launchd job cannot outlive it as the device's only daemon (launchd kills
//! the job's process group), so the worst an inherited label can do is restart
//! a second, redundant daemon.
//!
//! The Windows flags and FR-43's `--supervised` are argv, which no child
//! inherits; they are only ever passed by the spawners above (both are hidden
//! flags — a person passing one by hand is lying to the daemon about who will
//! bring it back). [`detect_here`] ignores each outside its own platform.
//!
//! [`detect`], [`decide_restart`] and [`systemd_restarts`] are pure — every
//! input is a parameter — so the whole policy is a unit test on every
//! platform, including the two that have no CI test lane.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// A systemd unit this daemon runs in: one of [`SYSTEMD_UNITS`], and whether
/// it belongs to a user manager (`systemctl --user`) or the system one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemdUnit {
    pub name: &'static str,
    pub user: bool,
}

/// The supervisor a running daemon has positively identified. `None` is the
/// honest default and always refuses `RestartDaemon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervision {
    /// The Windows SCM service host's in-process worker supervisor
    /// (`win_service::supervisor`).
    WindowsScm,
    /// The per-user Windows Scheduled Task (`service.rs`).
    WindowsTask,
    /// A systemd unit — the packaged system unit or the per-user unit (both
    /// in [`SYSTEMD_UNITS`]).
    Systemd(SystemdUnit),
    /// A launchd job carrying one of our labels (`com.roomler.agent`,
    /// `com.roomler.daemon`).
    Launchd,
    /// The FR-43 macOS root daemon's GUI-worker supervisor
    /// (`macos_supervisor.rs`).
    MacosSupervisor,
    /// Nothing proved a supervisor. A restart request is refused.
    None,
}

/// The launchd label prefix every roomler job carries. A LaunchServices app's
/// `XPC_SERVICE_NAME` never starts with it. Both jobs that run `meshharbord run`
/// (`com.roomler.agent`, `com.roomler.daemon`) set
/// `KeepAlive{SuccessfulExit:false}` — asserted against the packaged plists by
/// `packaged_plists_relaunch_a_non_zero_exit`.
pub const LAUNCHD_LABEL_PREFIX: &str = "com.roomler.";

/// The systemd units a daemon may run under, by exact name: the packaged
/// system unit (`packaging/linux/meshharbord.service`) and the per-user unit the
/// .deb ships and `service install` enables (`meshharbor.service`). An exact
/// list on purpose — see the module doc.
///
/// The pre-rename unit name is deliberately NOT here: FR-46 retires it, and a
/// daemon still running under it is simply not recognised — it refuses a
/// restart (the safe direction; it is never taken offline) until
/// `meshharbord service install` moves it to the current unit.
pub const SYSTEMD_UNITS: [&str; 2] = ["meshharbord.service", "meshharbor.service"];

/// Environment variable systemd sets on the unit's own processes.
pub const SYSTEMD_INVOCATION_ENV: &str = "INVOCATION_ID";
/// Environment variable launchd sets on a job it started.
pub const LAUNCHD_LABEL_ENV: &str = "XPC_SERVICE_NAME";

/// The least time between two accepted restarts of one daemon, across process
/// lifetimes (the record is persisted — see [`restart_record_path`]).
///
/// This is what makes a restart LOOP impossible. The SCM supervisor answers
/// the exit a restart makes with an immediate respawn (`decide_exit_reaction`
/// maps 0 to `Respawn` with no backoff — exactly what one deliberate restart
/// wants, and a hot loop if anything could re-trigger it on every start). A
/// client that re-sends "Apply now" on every reconnect, or a script, gets one
/// restart per 30 s and a refusal naming the wait for everything else.
pub const RESTART_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// FR-43's own threshold (`macos_supervisor::HEALTHY_RUN`): a worker that
/// exits sooner counts as a failed start, and five of those in a row make the
/// root daemon give up on the GUI worker. A requested restart must never be
/// one of them, so a supervised worker younger than this refuses.
pub const MACOS_SUPERVISED_MIN_UPTIME: Duration = Duration::from_secs(30);

/// How long a `RestartDaemon` reason may be in the log and the record.
const REASON_MAX_CHARS: usize = 200;

/// The persisted record's file name, beside the config the daemon loaded.
pub const RESTART_RECORD_FILE: &str = "restart-request.json";

impl Supervision {
    /// The stable wire word (`Response::DaemonRestarting.supervisor`).
    pub const fn wire(self) -> &'static str {
        match self {
            Supervision::WindowsScm => "scm",
            Supervision::WindowsTask => "task",
            Supervision::Systemd(_) => "systemd",
            Supervision::Launchd => "launchd",
            Supervision::MacosSupervisor => "macos-supervisor",
            Supervision::None => "none",
        }
    }

    /// Something will relaunch a worker that exits.
    pub const fn is_supervised(self) -> bool {
        !matches!(self, Supervision::None)
    }

    /// The exit code that makes THIS supervisor bring the worker back.
    ///
    /// `0` under the SCM: `decide_exit_reaction(0, _)` is `Respawn` with the
    /// failure counter reset and no backoff (an auto-update's exit already
    /// relies on it), and it is the one code an SCM host older than D3 also
    /// respawns at once. The sentinel everywhere else: launchd's
    /// `KeepAlive{SuccessfulExit:false}` relaunches only a non-zero exit;
    /// systemd's `Restart=always` restarts anything outside
    /// `RestartPreventExitStatus=7 8` (and `on-failure`, the dev unit
    /// `service install` writes, restarts any non-zero code); the FR-43 loop
    /// respawns any exit; and the Task's `<RestartOnFailure>`, where it acts
    /// at all, acts only on a non-zero one. For `None` the value is never
    /// used — the verb refuses first.
    pub const fn restart_exit_code(self) -> i32 {
        match self {
            Supervision::WindowsScm => 0,
            _ => crate::watchdog::RESTART_REQUESTED_EXIT_CODE,
        }
    }

    /// Who performs the relaunch (`Response::DaemonRestarting.restart_by`):
    /// `"supervisor"`, or `"caller"` where the supervisor's own reaction is
    /// too slow (or too uncertain) to be the plan — the Scheduled Task, whose
    /// `IgnoreNew` policy also drops a start while the old instance is still
    /// exiting, so the caller keeps asking until a NEW process answers.
    pub const fn restart_by(self) -> &'static str {
        match self {
            Supervision::WindowsTask => "caller",
            _ => "supervisor",
        }
    }
}

/// Decide from the evidence. Pure; [`detect_here`] gathers the inputs.
///
/// * `flag` — the hidden `run --supervisor <scm|task>` argument the Windows
///   spawners pass. Anything but the two known words is treated as proving
///   nothing.
/// * `macos_supervised` — the FR-43 `run --supervised` flag.
/// * `env` — an environment lookup.
/// * `cgroup` — the content of `/proc/self/cgroup`, when readable.
pub fn detect(
    flag: Option<&str>,
    macos_supervised: bool,
    env: &dyn Fn(&str) -> Option<String>,
    cgroup: Option<&str>,
) -> Supervision {
    match flag {
        Some("scm") => return Supervision::WindowsScm,
        Some("task") => return Supervision::WindowsTask,
        Some(_) => return Supervision::None,
        None => {}
    }
    if macos_supervised {
        return Supervision::MacosSupervisor;
    }
    if env(LAUNCHD_LABEL_ENV).is_some_and(|label| label.starts_with(LAUNCHD_LABEL_PREFIX)) {
        return Supervision::Launchd;
    }
    let invoked_by_systemd = env(SYSTEMD_INVOCATION_ENV).is_some_and(|id| !id.trim().is_empty());
    if invoked_by_systemd && let Some(unit) = cgroup.and_then(systemd_unit_in_cgroup) {
        return Supervision::Systemd(unit);
    }
    Supervision::None
}

/// The unit of [`SYSTEMD_UNITS`] that `/proc/self/cgroup` places this process
/// in, if any.
///
/// Handles both hierarchies: v2 is one line, `0::/system.slice/meshharbord.service`
/// (or `…/user@1000.service/app.slice/meshharbor.service` for a user unit); v1 is
/// one line per controller, `1:name=systemd:/system.slice/meshharbord.service`.
/// The path is everything after the second `:`, and the unit is its LAST
/// component — a scope or sub-cgroup below the unit is not the unit. A path
/// under a `user@<uid>.service` belongs to that user's manager.
pub fn systemd_unit_in_cgroup(content: &str) -> Option<SystemdUnit> {
    content.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let (Some(_), Some(_), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        let path = path.trim_end_matches('/');
        let leaf = path.rsplit('/').next().unwrap_or("");
        let name = SYSTEMD_UNITS.iter().copied().find(|u| *u == leaf)?;
        let user = path.split('/').any(|c| c.starts_with("user@"));
        Some(SystemdUnit { name, user })
    })
}

/// [`detect`] on THIS process: the flags from the CLI (each only on the one
/// platform whose spawner passes it), the real environment, and
/// `/proc/self/cgroup` where it exists.
pub fn detect_here(flag: Option<&str>, macos_supervised: bool) -> Supervision {
    let flag = if cfg!(windows) { flag } else { None };
    let macos_supervised = cfg!(target_os = "macos") && macos_supervised;
    let env = |name: &str| std::env::var(name).ok();
    #[cfg(target_os = "linux")]
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok();
    #[cfg(not(target_os = "linux"))]
    let cgroup: Option<String> = None;
    detect(flag, macos_supervised, &env, cgroup.as_deref())
}

/// Everything [`decide_restart`] weighs, gathered before it is called.
#[derive(Debug, Clone, Copy)]
pub struct RestartInputs {
    pub supervision: Supervision,
    /// `local_restart_enabled`, read from the config file for THIS request.
    pub enabled: bool,
    /// Unix ms of the last accepted request, from the persisted record.
    pub last_request_ms: Option<u64>,
    /// Unix ms now.
    pub now_ms: u64,
    /// How long this process has been running.
    pub uptime: Duration,
    /// A local screen recording is running (FR-85) — a restart would end it.
    pub recording: bool,
    /// This process already accepted a restart and is on its way out.
    pub already_accepted: bool,
}

/// An accepted restart: what the caller is told, and how the process leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPlan {
    pub supervisor: &'static str,
    pub restart_by: &'static str,
    pub exit_code: i32,
}

/// Whether a `RestartDaemon` request may go ahead. Pure. `Err` carries the
/// refusal, worded for the person who asked (the desktop and the CLI show it
/// verbatim). The systemd policy check ([`systemd_restarts`]) comes after
/// this, because it needs a subprocess.
pub fn decide_restart(i: &RestartInputs) -> Result<RestartPlan, String> {
    if i.already_accepted {
        return Err("a restart is already under way".into());
    }
    if !i.supervision.is_supervised() {
        return Err(
            "this service is not running under a service manager it can identify (a Windows \
             service or scheduled task, systemd, launchd), so exiting would stop it for good \
             rather than restart it — restart it the way it was started"
                .into(),
        );
    }
    if !i.enabled {
        return Err(
            "restarting from this device is turned off (local_restart_enabled = false)".into(),
        );
    }
    if i.recording {
        return Err(
            "a screen recording is in progress — stop it first; a restart would end it".into(),
        );
    }
    let window = RESTART_MIN_INTERVAL.as_millis() as u64;
    // A record from further in the future than the window itself is a clock
    // that went backwards, not a restart that happened — ignore it rather than
    // refuse until the clock catches up. Anything closer is honoured.
    if let Some(last) = i.last_request_ms
        && last <= i.now_ms.saturating_add(window)
    {
        let ago = i.now_ms.saturating_sub(last);
        if ago < window {
            return Err(format!(
                "the service was asked to restart {} s ago — try again in {} s",
                ago / 1000,
                (window - ago).div_ceil(1000)
            ));
        }
    }
    if matches!(i.supervision, Supervision::MacosSupervisor)
        && i.uptime < MACOS_SUPERVISED_MIN_UPTIME
    {
        let left = MACOS_SUPERVISED_MIN_UPTIME - i.uptime;
        return Err(format!(
            "the service started {} s ago — try again in {} s (the macOS supervisor counts an \
             exit this soon as a failed start)",
            i.uptime.as_secs(),
            left.as_millis().div_ceil(1000)
        ));
    }
    Ok(RestartPlan {
        supervisor: i.supervision.wire(),
        restart_by: i.supervision.restart_by(),
        exit_code: i.supervision.restart_exit_code(),
    })
}

/// Would systemd restart this process after it exits with `exit_code`?
/// `show` is the output of `systemctl show <unit> --property=…` for the
/// properties [`SYSTEMD_SHOW_PROPERTIES`] names. Pure.
///
/// Mirrors systemd's own `service_shall_restart`: `RestartPreventExitStatus`
/// wins, then `RestartForceExitStatus`, then the `Restart=` policy, where a
/// code listed in `SuccessExitStatus` counts as a clean exit. And only the
/// unit's MAIN process is ever restarted — a process the daemon spawned sits
/// in the same cgroup with the same environment, and exiting it would restart
/// nothing.
pub fn systemd_restarts(show: &str, my_pid: u32, exit_code: i32) -> Result<(), String> {
    let prop = |key: &str| -> Option<&str> { systemd_prop(show, key) };
    let lists = |key: &str| -> bool {
        let code = exit_code.to_string();
        prop(key).is_some_and(|v| v.split_whitespace().any(|t| t == code))
    };
    let main_pid: u32 = prop("MainPID")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "systemd did not report the unit's main process".to_string())?;
    if main_pid != my_pid {
        return Err(format!(
            "this process (pid {my_pid}) is not the unit's main process (pid {main_pid}), which is \
             the only one systemd restarts"
        ));
    }
    if lists("RestartPreventExitStatus") {
        return Err(format!(
            "the unit lists exit status {exit_code} in RestartPreventExitStatus"
        ));
    }
    if lists("RestartForceExitStatus") {
        return Ok(());
    }
    let policy = prop("Restart")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "systemd did not report the unit's Restart= policy".to_string())?;
    let clean = exit_code == 0 || lists("SuccessExitStatus");
    let restarts = match policy {
        "always" => true,
        "on-failure" => !clean,
        "on-success" => clean,
        // on-abnormal / on-abort / on-watchdog react to signals, timeouts and
        // the watchdog — never to an exit status — and `no` to nothing.
        _ => false,
    };
    if restarts {
        Ok(())
    } else {
        Err(format!(
            "the unit's Restart={policy} would not restart an exit with status {exit_code}"
        ))
    }
}

/// The properties [`systemd_restarts`] and [`systemd_restart_within_secs`] read.
pub const SYSTEMD_SHOW_PROPERTIES: [&str; 7] = [
    "MainPID",
    "Restart",
    "RestartPreventExitStatus",
    "RestartForceExitStatus",
    "SuccessExitStatus",
    // FR-84 D3 / #1684 — how long a stop+restart of this unit can take, so the
    // caller's wait can follow the SUPERVISOR instead of a fixed guess: systemd
    // waits up to `TimeoutStopSec` for the cgroup to empty, then `RestartSec`
    // before relaunching.
    "TimeoutStopUSec",
    "RestartUSec",
];

/// One `systemctl show` property value (`Key=value`), trimmed, or `None`.
fn systemd_prop<'a>(show: &'a str, key: &str) -> Option<&'a str> {
    show.lines().find_map(|l| {
        l.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(str::trim)
    })
}

/// Parse a systemd `*USec=` property VALUE into whole seconds (rounded up), or
/// `None` if it is absent, `infinity`, or unparseable.
///
/// `systemctl show` prints these either as an integer count of MICROSECONDS
/// (older systemd) or as a human span like `1min 30s` / `500ms` / `2s` (newer)
/// — both forms are handled. `infinity` and anything we cannot read map to
/// `None`, so the caller falls back to its own default rather than trusting a
/// misread. Deliberately permissive-then-safe: the cost of `None` is "wait the
/// old fixed amount", never a wrong number.
pub fn parse_usec_secs(value: &str) -> Option<u64> {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("infinity") {
        return None;
    }
    // Integer microseconds (the machine form): all ASCII digits.
    if v.bytes().all(|b| b.is_ascii_digit()) {
        let us: u128 = v.parse().ok()?;
        return Some(us.div_ceil(1_000_000).min(u64::MAX as u128) as u64);
    }
    // Human form: whitespace-separated `<number><unit>` tokens, summed in
    // milliseconds. Any token we don't recognise fails the whole parse (safe).
    let mut total_ms: u128 = 0;
    for tok in v.split_whitespace() {
        let split = tok.find(|c: char| !c.is_ascii_digit())?;
        if split == 0 {
            return None; // no leading number
        }
        let (num, unit) = tok.split_at(split);
        let n: u128 = num.parse().ok()?;
        let ms = match unit {
            "us" | "usec" => n.div_ceil(1000),
            "ms" | "msec" => n,
            "s" | "sec" | "seconds" | "second" => n.checked_mul(1_000)?,
            "min" | "m" => n.checked_mul(60_000)?,
            "h" | "hr" | "hour" | "hours" => n.checked_mul(3_600_000)?,
            "d" | "day" | "days" => n.checked_mul(86_400_000)?,
            "w" | "week" | "weeks" => n.checked_mul(604_800_000)?,
            _ => return None,
        };
        total_ms = total_ms.checked_add(ms)?;
    }
    if total_ms == 0 {
        return None;
    }
    Some((total_ms.div_ceil(1_000)).min(u64::MAX as u128) as u64)
}

/// The upper bound, in seconds, on how long a stop + relaunch of this unit can
/// take: `TimeoutStopSec` (waiting for the cgroup to empty) + `RestartSec`.
/// Pure, from `systemctl show` output. `None` when neither is known — the
/// caller then keeps its own default wait. A known-but-`infinity` timeout also
/// yields `None` on that term (we cannot wait forever), leaving whatever the
/// other term contributes.
pub fn systemd_restart_within_secs(show: &str) -> Option<u64> {
    let stop = systemd_prop(show, "TimeoutStopUSec").and_then(parse_usec_secs);
    let restart = systemd_prop(show, "RestartUSec").and_then(parse_usec_secs);
    match (stop, restart) {
        (None, None) => None,
        _ => Some(stop.unwrap_or(0).saturating_add(restart.unwrap_or(0))),
    }
}

/// Ask systemd — the manager itself, not the unit file — whether it will
/// restart this process after `exit_code`. Bounded (5 s); any failure to get
/// an answer is a refusal, because "probably" is not a restart.
///
/// On success returns the unit's [`systemd_restart_within_secs`] hint (`None`
/// when systemd did not report the timers), read from the SAME `systemctl show`
/// so the restart verb can tell the caller how long the relaunch may take
/// (#1684) — a SIGTERM-deaf process in the cgroup can push a stop out to
/// `TimeoutStopSec + RestartSec`, well past a fixed 60 s wait.
pub async fn confirm_systemd(unit: SystemdUnit, exit_code: i32) -> Result<Option<u64>, String> {
    let mut cmd = tokio::process::Command::new("systemctl");
    if unit.user {
        cmd.arg("--user");
    }
    cmd.arg("show").arg(unit.name);
    for p in SYSTEMD_SHOW_PROPERTIES {
        cmd.arg(format!("--property={p}"));
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let scope = if unit.user { "--user " } else { "" };
    let out = match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            return Err(format!(
                "could not ask systemd about {} (systemctl {scope}show: {e})",
                unit.name
            ));
        }
        Err(_) => {
            return Err(format!(
                "systemd did not answer about {} within 5 s",
                unit.name
            ));
        }
    };
    if !out.status.success() {
        return Err(format!(
            "systemctl {scope}show {} failed ({}): {}",
            unit.name,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let show = String::from_utf8_lossy(&out.stdout);
    systemd_restarts(&show, std::process::id(), exit_code)
        .map_err(|why| format!("systemd would not restart {}: {why}", unit.name))?;
    Ok(systemd_restart_within_secs(&show))
}

/// Where the last accepted restart is recorded: beside the config file the
/// daemon loaded — the one directory every install flavour is guaranteed to
/// let the daemon write (`config::save` writes its temp file there) — and NOT
/// inside `config.toml`, so a restart request never rewrites the operator's
/// file. Keyed to the config like the single-instance lock, so two daemons on
/// one host (a perMachine service and a perUser task) never share a window.
pub fn restart_record_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name(RESTART_RECORD_FILE)
}

/// The persisted record of the last accepted restart.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RestartRecord {
    /// Unix ms the restart was accepted.
    pub at_ms: u64,
    /// The process that accepted it (and exited).
    pub pid: u32,
    /// [`Supervision::wire`].
    pub supervisor: String,
    /// What the caller said, sanitised ([`sanitize_reason`]).
    pub reason: String,
}

/// Read the last accepted restart's time. `Ok(None)` when there is no record,
/// or one that does not parse (it is only ever written whole — temp + rename —
/// so an unparseable one was put there by someone else, and a refusal forever
/// is not the right answer to it). Any OTHER read failure is an `Err`: the
/// caller refuses, because a record it cannot see is a loop it cannot bound.
pub fn read_last_request(path: &Path) -> Result<Option<u64>, String> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<RestartRecord>(&bytes) {
            Ok(rec) => Ok(Some(rec.at_ms)),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e,
                    "restart record unreadable — ignoring it");
                Ok(None)
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Persist `rec` durably BEFORE the restart is answered: temp file, fsync,
/// rename — the same discipline as `config::save`, so a crash mid-write
/// leaves the old record or the new one, never half of either.
pub fn write_record(path: &Path, rec: &RestartRecord) -> Result<(), String> {
    use std::io::Write as _;
    let body = serde_json::to_vec(rec).map_err(|e| format!("encoding the record: {e}"))?;
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("writing {}: {e}", path.display())
    })
}

/// A caller-supplied reason made safe for a log line and the record: control
/// characters (a newline would forge a log line) become spaces, and the whole
/// is capped at [`REASON_MAX_CHARS`] characters.
pub fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(REASON_MAX_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| {
            owned
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    const SYSTEM_UNIT_CGROUP: &str = "0::/system.slice/meshharbord.service\n";
    const USER_UNIT_CGROUP: &str =
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/meshharbor.service\n";
    const V1_CGROUP: &str = "12:pids:/system.slice/meshharbord.service\n\
                             1:name=systemd:/system.slice/meshharbord.service\n\
                             0::/system.slice/meshharbord.service\n";
    /// A shell under GNOME Terminal: a systemd child, with an INVOCATION_ID
    /// of its own, and nothing to do with us.
    const GNOME_TERMINAL_CGROUP: &str = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-1234.scope\n";
    /// A transient unit an operator made up — `Restart=` unknown.
    const TRANSIENT_CGROUP: &str = "0::/system.slice/roomler-manual.service\n";

    const SYSTEM: SystemdUnit = SystemdUnit {
        name: "meshharbord.service",
        user: false,
    };

    /// The whole table, one row per way a daemon gets started.
    #[test]
    fn detect_table() {
        let none = env_of(&[]);
        // The Windows spawners' flag wins outright and needs no environment.
        assert_eq!(
            detect(Some("scm"), false, &none, None),
            Supervision::WindowsScm
        );
        assert_eq!(
            detect(Some("task"), false, &none, None),
            Supervision::WindowsTask
        );
        // An unknown spawner word has proved nothing.
        assert_eq!(detect(Some("nssm"), false, &none, None), Supervision::None);
        assert_eq!(detect(Some(""), false, &none, None), Supervision::None);
        // FR-43: the root daemon's worker.
        assert_eq!(
            detect(None, true, &none, None),
            Supervision::MacosSupervisor
        );
        // The flag outranks the FR-43 marker, should both ever appear.
        assert_eq!(
            detect(Some("scm"), true, &none, None),
            Supervision::WindowsScm
        );
        // launchd: our labels only.
        for label in ["com.roomler.agent", "com.roomler.daemon"] {
            assert_eq!(
                detect(None, false, &env_of(&[(LAUNCHD_LABEL_ENV, label)]), None),
                Supervision::Launchd,
                "{label}"
            );
        }
        // A bare `meshharbord run` from Terminal.app / an unrelated job.
        for label in [
            "0",
            "application.com.apple.Terminal.12345",
            "com.example.roomler",
            "",
        ] {
            assert_eq!(
                detect(None, false, &env_of(&[(LAUNCHD_LABEL_ENV, label)]), None),
                Supervision::None,
                "{label:?} must not read as launchd"
            );
        }
        // systemd: the invocation id AND one of our units' cgroups.
        let invoked = env_of(&[(SYSTEMD_INVOCATION_ENV, "0123456789abcdef")]);
        for (cg, unit) in [
            (SYSTEM_UNIT_CGROUP, SYSTEM),
            (
                USER_UNIT_CGROUP,
                SystemdUnit {
                    name: "meshharbor.service",
                    user: true,
                },
            ),
            (V1_CGROUP, SYSTEM),
        ] {
            assert_eq!(
                detect(None, false, &invoked, Some(cg)),
                Supervision::Systemd(unit),
                "{cg}"
            );
        }
        // The id alone: a shell under GNOME Terminal inherits one.
        assert_eq!(
            detect(None, false, &invoked, Some(GNOME_TERMINAL_CGROUP)),
            Supervision::None
        );
        // The id without a readable cgroup file: not proven.
        assert_eq!(detect(None, false, &invoked, None), Supervision::None);
        // An empty id is no id (systemd never sets one empty; a wrapper might).
        assert_eq!(
            detect(
                None,
                false,
                &env_of(&[(SYSTEMD_INVOCATION_ENV, "")]),
                Some(SYSTEM_UNIT_CGROUP)
            ),
            Supervision::None
        );
        // Our cgroup without the id: something re-parented us there
        // (systemd-run --scope, a debugger); no restart promise.
        assert_eq!(
            detect(None, false, &none, Some(SYSTEM_UNIT_CGROUP)),
            Supervision::None
        );
        // A unit that merely resembles ours has whatever Restart= it has.
        assert_eq!(
            detect(None, false, &invoked, Some(TRANSIENT_CGROUP)),
            Supervision::None
        );
        // Nothing at all: the orphan `meshharbord run`.
        assert_eq!(detect(None, false, &none, None), Supervision::None);
    }

    #[test]
    fn cgroup_parsing_is_exact() {
        assert_eq!(systemd_unit_in_cgroup(SYSTEM_UNIT_CGROUP), Some(SYSTEM));
        assert_eq!(
            systemd_unit_in_cgroup(USER_UNIT_CGROUP),
            Some(SystemdUnit {
                name: "meshharbor.service",
                user: true
            })
        );
        // An older user manager puts services straight under user@.
        assert_eq!(
            systemd_unit_in_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/meshharbor.service\n"
            ),
            Some(SystemdUnit {
                name: "meshharbor.service",
                user: true
            })
        );
        assert_eq!(systemd_unit_in_cgroup(V1_CGROUP), Some(SYSTEM));
        // A trailing slash is tolerated; a prefix or suffix match is not.
        assert_eq!(
            systemd_unit_in_cgroup("0::/system.slice/meshharbord.service/\n"),
            Some(SYSTEM)
        );
        for not_ours in [
            "0::/system.slice/meshharbord.service.d\n",
            "0::/system.slice/xroomlerd.service\n",
            "0::/meshharbord.service.slice/foo.scope\n",
            "",
            "garbage without colons\n",
            // The unit name must be the LEAF: a service that spawned us into
            // a scope of its own is not the service.
            "0::/system.slice/meshharbord.service/child.scope\n",
        ] {
            assert_eq!(systemd_unit_in_cgroup(not_ours), None, "{not_ours:?}");
        }
    }

    /// The unit list must name what actually ships, or a packaged daemon
    /// would refuse to restart: the two packaging artefacts, which are also
    /// the names `service install` writes (`service.rs`, `UNIT`).
    #[test]
    fn the_unit_list_covers_the_shipped_units() {
        for shipped in ["meshharbord.service", "meshharbor.service"] {
            assert!(SYSTEMD_UNITS.contains(&shipped), "{shipped} missing");
        }
        // Both packaged unit files exist under the names the list carries.
        let _ = include_str!("../packaging/linux/meshharbord.service");
        let _ = include_str!("../packaging/linux/meshharbor.service");
    }

    /// Both launchd jobs that run `meshharbord run` must relaunch a NON-zero
    /// exit — that is the only reason the sentinel, and not 0, is what a
    /// launchd-supervised daemon exits with. A plist that dropped the key (or
    /// flipped it to `true`, "relaunch only a clean exit") would turn "Apply
    /// now" into "go offline" on every Mac.
    #[test]
    fn packaged_plists_relaunch_a_non_zero_exit() {
        for (label, plist) in [
            (
                "com.roomler.agent",
                include_str!("../packaging/macos/com.roomler.agent.plist"),
            ),
            (
                "com.roomler.daemon",
                include_str!("../packaging/macos/com.roomler.daemon.plist"),
            ),
        ] {
            assert!(label.starts_with(LAUNCHD_LABEL_PREFIX));
            assert!(
                plist.contains(&format!("<string>{label}</string>")),
                "{label}: label"
            );
            // `<key>KeepAlive</key> <dict> <key>SuccessfulExit</key> <false/>`,
            // whitespace-insensitive.
            let squashed: String = plist.split_whitespace().collect();
            assert!(
                squashed.contains("<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/>"),
                "{label}: KeepAlive must be {{SuccessfulExit: false}}"
            );
            assert!(
                plist.contains("<string>run</string>"),
                "{label}: runs `run`"
            );
        }
    }

    /// Every supervisor's exit code is the one that makes IT relaunch the
    /// worker, and the two words a caller reads off the answer.
    #[test]
    fn restart_exit_code_per_supervisor() {
        let sentinel = crate::watchdog::RESTART_REQUESTED_EXIT_CODE;
        let table = [
            (Supervision::WindowsScm, 0, "supervisor", "scm"),
            (Supervision::WindowsTask, sentinel, "caller", "task"),
            (
                Supervision::Systemd(SYSTEM),
                sentinel,
                "supervisor",
                "systemd",
            ),
            (Supervision::Launchd, sentinel, "supervisor", "launchd"),
            (
                Supervision::MacosSupervisor,
                sentinel,
                "supervisor",
                "macos-supervisor",
            ),
            (Supervision::None, sentinel, "supervisor", "none"),
        ];
        for (s, code, by, wire) in table {
            assert_eq!(s.restart_exit_code(), code, "{s:?}");
            assert_eq!(s.restart_by(), by, "{s:?}");
            assert_eq!(s.wire(), wire, "{s:?}");
            assert_eq!(s.is_supervised(), s != Supervision::None, "{s:?}");
        }
        // launchd relaunches a NON-zero exit only; a 0 there would leave the
        // Mac down. Pinned independently of the table above.
        assert_ne!(Supervision::Launchd.restart_exit_code(), 0);
        assert_ne!(Supervision::WindowsTask.restart_exit_code(), 0);
        // The SCM supervisor maps 0 to Respawn-without-backoff; the sentinel
        // must not collide with anything it special-cases either.
        assert_ne!(sentinel, crate::watchdog::STALL_EXIT_CODE);
        assert_ne!(sentinel, crate::watchdog::AGENT_DELETED_EXIT_CODE);
        assert_ne!(sentinel, crate::watchdog::ALREADY_RUNNING_EXIT_CODE);
    }

    /// And each of those codes is what the supervisor it was chosen for
    /// actually relaunches — checked against the supervisor's own logic
    /// where the tree has it.
    #[cfg(windows)]
    #[test]
    fn the_scm_code_is_respawned_at_once() {
        use crate::win_service::supervisor::{ExitReaction, decide_exit_reaction};
        let code = Supervision::WindowsScm.restart_exit_code() as u32;
        // Even from deep in a crash ladder: a requested restart resets it.
        assert_eq!(decide_exit_reaction(code, 6), (ExitReaction::Respawn, 0));
    }

    /// `detect_here` on the test process: whatever the host, a plain test
    /// runner is nobody's supervised worker unless it lies about it.
    #[test]
    fn detect_here_is_platform_gated_and_bare_is_unsupervised() {
        // The Windows flag counts only on Windows, FR-43's only on macOS: a
        // person passing either by hand elsewhere proves nothing.
        let expect_task = if cfg!(windows) {
            Supervision::WindowsTask
        } else {
            Supervision::None
        };
        // (`None` elsewhere only if the environment proves nothing either —
        // a test runner is never inside one of our units.)
        assert_eq!(detect_here(Some("task"), false), expect_task);
        let expect_fr43 = if cfg!(target_os = "macos") {
            Supervision::MacosSupervisor
        } else {
            Supervision::None
        };
        assert_eq!(detect_here(None, true), expect_fr43);
        let here = detect_here(None, false);
        assert!(
            matches!(here, Supervision::None),
            "a test process must not detect a supervisor: {here:?}"
        );
    }

    fn inputs(s: Supervision) -> RestartInputs {
        RestartInputs {
            supervision: s,
            enabled: true,
            last_request_ms: None,
            now_ms: 1_000_000_000,
            uptime: Duration::from_secs(3600),
            recording: false,
            already_accepted: false,
        }
    }

    #[test]
    fn restart_accepted_under_every_supervisor() {
        for s in [
            Supervision::WindowsScm,
            Supervision::WindowsTask,
            Supervision::Systemd(SYSTEM),
            Supervision::Launchd,
            Supervision::MacosSupervisor,
        ] {
            let plan = decide_restart(&inputs(s)).expect("supervised, enabled, idle");
            assert_eq!(plan.exit_code, s.restart_exit_code());
            assert_eq!(plan.restart_by, s.restart_by());
            assert_eq!(plan.supervisor, s.wire());
        }
    }

    /// The orphan `meshharbord run` is never taken offline — whatever else is
    /// true.
    #[test]
    fn restart_refused_when_unsupervised() {
        let err = decide_restart(&inputs(Supervision::None)).unwrap_err();
        assert!(err.contains("not running under a service manager"), "{err}");
        // Not even with everything else in its favour.
        let mut i = inputs(Supervision::None);
        i.uptime = Duration::from_secs(86_400);
        assert!(decide_restart(&i).is_err());
    }

    #[test]
    fn restart_refused_when_disabled() {
        let mut i = inputs(Supervision::WindowsScm);
        i.enabled = false;
        let err = decide_restart(&i).unwrap_err();
        assert!(err.contains("local_restart_enabled = false"), "{err}");
    }

    #[test]
    fn restart_refused_while_recording_or_already_accepted() {
        let mut i = inputs(Supervision::Launchd);
        i.recording = true;
        assert!(decide_restart(&i).unwrap_err().contains("recording"));
        let mut i = inputs(Supervision::Launchd);
        i.already_accepted = true;
        assert!(
            decide_restart(&i)
                .unwrap_err()
                .contains("already under way")
        );
    }

    /// The loop bound. A request inside the window of the last ACCEPTED one
    /// — whichever process accepted it — is refused with the wait; the edge
    /// of the window is allowed; a clock that jumped back past the window is
    /// not a restart that happened.
    #[test]
    fn restart_rate_limited() {
        let window = RESTART_MIN_INTERVAL.as_millis() as u64;
        let mut i = inputs(Supervision::WindowsScm);
        i.last_request_ms = Some(i.now_ms - 12_000);
        let err = decide_restart(&i).unwrap_err();
        assert!(err.contains("12 s ago"), "{err}");
        assert!(err.contains("try again in 18 s"), "{err}");
        // Exactly one window later: allowed.
        i.last_request_ms = Some(i.now_ms - window);
        assert!(decide_restart(&i).is_ok());
        // A little in the future (the clock stepped back a few seconds right
        // after a restart): still a restart that just happened.
        i.last_request_ms = Some(i.now_ms + 5_000);
        assert!(
            decide_restart(&i)
                .unwrap_err()
                .contains("try again in 30 s")
        );
        // Far in the future: a clock that went back an hour, not a restart.
        i.last_request_ms = Some(i.now_ms + 3_600_000);
        assert!(decide_restart(&i).is_ok());
    }

    /// Persisted across process lifetimes: what one process accepted and
    /// recorded, the next one — the relaunched daemon — refuses to repeat.
    #[test]
    fn restart_rate_limit_survives_the_process() {
        let dir = std::env::temp_dir().join(format!(
            "roomlerd-restart-record-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.toml");
        let path = restart_record_path(&config);
        assert_eq!(path, dir.join(RESTART_RECORD_FILE));
        assert_eq!(read_last_request(&path), Ok(None), "no record yet");

        let now = 1_700_000_000_000u64;
        write_record(
            &path,
            &RestartRecord {
                at_ms: now,
                pid: 4242,
                supervisor: "scm".into(),
                reason: "settings: overlay_enabled".into(),
            },
        )
        .unwrap();
        // The "next process": nothing in memory, only the file.
        let last = read_last_request(&path).unwrap();
        assert_eq!(last, Some(now));
        let mut i = inputs(Supervision::WindowsScm);
        i.now_ms = now + 4_000;
        i.last_request_ms = last;
        assert!(decide_restart(&i).unwrap_err().contains("4 s ago"));

        // A record someone else scribbled over is ignored, not a refusal
        // forever.
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(read_last_request(&path), Ok(None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_young_macos_worker_waits_out_the_fr43_threshold() {
        let mut i = inputs(Supervision::MacosSupervisor);
        i.uptime = Duration::from_secs(10);
        let err = decide_restart(&i).unwrap_err();
        assert!(err.contains("started 10 s ago"), "{err}");
        assert!(err.contains("try again in 20 s"), "{err}");
        // Old enough: allowed.
        i.uptime = MACOS_SUPERVISED_MIN_UPTIME;
        assert!(decide_restart(&i).is_ok());
        // The floor is FR-43's alone: nothing else counts an early exit
        // against the worker.
        for s in [
            Supervision::WindowsScm,
            Supervision::WindowsTask,
            Supervision::Systemd(SYSTEM),
            Supervision::Launchd,
        ] {
            let mut i = inputs(s);
            i.uptime = Duration::from_secs(1);
            assert!(decide_restart(&i).is_ok(), "{s:?}");
        }
        // It mirrors FR-43's own number.
        assert_eq!(
            MACOS_SUPERVISED_MIN_UPTIME,
            crate::macos_supervisor::HEALTHY_RUN
        );
    }

    /// `systemctl show` read back against systemd's own restart rules.
    #[test]
    fn systemd_policy_table() {
        let pid = 4242;
        let show = |restart: &str, prevent: &str, force: &str, success: &str| {
            format!(
                "MainPID={pid}\nRestart={restart}\nRestartPreventExitStatus={prevent}\n\
                 RestartForceExitStatus={force}\nSuccessExitStatus={success}\n"
            )
        };
        // The shipped units.
        assert_eq!(
            systemd_restarts(&show("always", "7 8", "", ""), pid, 9),
            Ok(())
        );
        // `service install`'s dev unit.
        assert_eq!(
            systemd_restarts(&show("on-failure", "", "", ""), pid, 9),
            Ok(())
        );
        // A drop-in that lists the sentinel as prevented: refused.
        assert!(systemd_restarts(&show("always", "7 8 9", "", ""), pid, 9).is_err());
        // Prevent wins over force, exactly like systemd.
        assert!(systemd_restarts(&show("always", "9", "9", ""), pid, 9).is_err());
        // Force wins over a policy that would not restart.
        assert_eq!(systemd_restarts(&show("no", "", "9", ""), pid, 9), Ok(()));
        // A code declared a success is a clean exit: on-failure ignores it,
        // on-success restarts it.
        assert!(systemd_restarts(&show("on-failure", "", "", "9"), pid, 9).is_err());
        assert_eq!(
            systemd_restarts(&show("on-success", "", "", "9"), pid, 9),
            Ok(())
        );
        assert!(systemd_restarts(&show("on-success", "", "", ""), pid, 9).is_err());
        // Policies that never look at an exit status.
        for p in ["no", "on-abnormal", "on-abort", "on-watchdog"] {
            let err = systemd_restarts(&show(p, "", "", ""), pid, 9).unwrap_err();
            assert!(err.contains(&format!("Restart={p}")), "{p}: {err}");
        }
        // Empty properties are omitted by some systemd versions.
        assert_eq!(
            systemd_restarts(&format!("MainPID={pid}\nRestart=always\n"), pid, 9),
            Ok(())
        );
        // A signal name in a status set is not the code.
        assert_eq!(
            systemd_restarts(&show("always", "7 8 SIGTERM", "", ""), pid, 9),
            Ok(())
        );
    }

    /// Only the unit's main process is restarted; anything in the cgroup that
    /// the daemon spawned has the same environment and would restart nothing.
    #[test]
    fn systemd_restarts_only_the_main_process() {
        let show = "MainPID=100\nRestart=always\nRestartPreventExitStatus=7 8\n";
        let err = systemd_restarts(show, 4242, 9).unwrap_err();
        assert!(err.contains("not the unit's main process"), "{err}");
        assert!(systemd_restarts("Restart=always\n", 4242, 9).is_err());
        assert!(systemd_restarts("MainPID=4242\n", 4242, 9).is_err());
        assert!(systemd_restarts("", 4242, 9).is_err());
    }

    /// FR-84 D3 / #1684 — the restart-within hint, from both `systemctl show`
    /// forms. Anything we cannot read is `None`, so the caller keeps its own
    /// fixed wait rather than trusting a misread number.
    #[test]
    fn parse_usec_covers_both_forms_and_fails_safe() {
        // Integer microseconds (older systemd's machine form).
        assert_eq!(parse_usec_secs("90000000"), Some(90));
        assert_eq!(parse_usec_secs("5000000"), Some(5));
        assert_eq!(parse_usec_secs("500000"), Some(1)); // 0.5 s rounds up
        assert_eq!(parse_usec_secs("0"), Some(0));
        // Human spans (newer systemd).
        assert_eq!(parse_usec_secs("1min 30s"), Some(90));
        assert_eq!(parse_usec_secs("2s"), Some(2));
        assert_eq!(parse_usec_secs("500ms"), Some(1));
        assert_eq!(parse_usec_secs("1h"), Some(3600));
        assert_eq!(parse_usec_secs("1min 30s 500ms"), Some(91)); // 90.5 s -> 91
        // Unreadable / infinite / empty -> None.
        assert_eq!(parse_usec_secs("infinity"), None);
        assert_eq!(parse_usec_secs(""), None);
        assert_eq!(parse_usec_secs("nonsense"), None);
        assert_eq!(parse_usec_secs("30x"), None);
        assert_eq!(parse_usec_secs("s"), None);
    }

    #[test]
    fn restart_within_sums_stop_and_restart() {
        // The shipped system unit: TimeoutStopSec=90s (systemd default),
        // RestartSec=5s.
        assert_eq!(
            systemd_restart_within_secs("TimeoutStopUSec=1min 30s\nRestartUSec=5s\n"),
            Some(95)
        );
        // Integer-microsecond form, same answer.
        assert_eq!(
            systemd_restart_within_secs("TimeoutStopUSec=90000000\nRestartUSec=5000000\n"),
            Some(95)
        );
        // Only one term known.
        assert_eq!(systemd_restart_within_secs("RestartUSec=5s\n"), Some(5));
        assert_eq!(
            systemd_restart_within_secs("TimeoutStopUSec=90000000\n"),
            Some(90)
        );
        // infinity stop + 5 s restart -> just the term we can bound.
        assert_eq!(
            systemd_restart_within_secs("TimeoutStopUSec=infinity\nRestartUSec=5s\n"),
            Some(5)
        );
        // Neither reported -> None (the caller keeps its own wait).
        assert_eq!(
            systemd_restart_within_secs("MainPID=1\nRestart=always\n"),
            None
        );
    }

    #[test]
    fn reasons_are_log_safe() {
        assert_eq!(sanitize_reason("  settings: a, b  "), "settings: a, b");
        assert_eq!(
            sanitize_reason("line one\nFAKE log line\r\u{1b}[31m"),
            "line one FAKE log line  [31m"
        );
        assert_eq!(
            sanitize_reason(&"x".repeat(500)).chars().count(),
            REASON_MAX_CHARS
        );
    }
}
