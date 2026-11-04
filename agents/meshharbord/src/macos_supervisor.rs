// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-43 P1 — the root daemon as supervisor of the GUI-session worker.
//!
//! macOS is the one platform where one process cannot serve both planes: a
//! root LaunchDaemon lives in session 0 with no WindowServer, so it can never
//! capture or inject; a GUI-session process is the console user, so it can
//! never create a `utun`. Windows escapes this because a SYSTEM process can
//! attach to the interactive desktop (`win_service/desktop.rs`); macOS has no
//! such API. Two processes are therefore forced — but two *enrollments* are
//! not, and this module is the first step of collapsing them (FR-43).
//!
//! P0 measured the mechanism on real hardware (2026-08-30, issue #971): from
//! the running root daemon, a capture in session 0 fails with "could not
//! create image from display", while the same call through
//! `launchctl asuser <console-uid>` produced an 8.4 MB screenshot in 233 ms —
//! and our own binary spawned that way reports both a live GUI session and its
//! TCC grants. So `launchctl asuser` is the launchd analogue of the Windows
//! supervisor's `WTSQueryUserToken` + `CreateProcessAsUserW`
//! (`win_service/supervisor.rs::spawn_in_session`), and this is the launchd
//! analogue of its `decide_spawn`.
//!
//! ## What P1 deliberately does NOT do
//!
//! It never fights launchd. If the LaunchAgent job is loaded in `gui/<uid>`,
//! **launchd owns the worker and this supervisor stands down** — because both
//! spawning would put two processes on ONE enrollment, and the hub displaces
//! the older control WS (`remote_control/src/hub.rs`), producing a
//! login/displace/relaunch loop that looks exactly like a flapping device.
//! That stand-down is what makes flipping the switch on a live Mac a no-op,
//! and it is why P1 can ship before the packaging change that stops
//! bootstrapping the LaunchAgent (P3).
//!
//! Kill switch: `macos_supervise_gui_worker`, default **off**. Off, this
//! module does nothing at all and the two halves behave byte-for-byte as they
//! do today.

use std::time::Duration;

/// How often the supervisor re-reads the world (console user, worker health).
/// launchd exposes no session-change callback we can subscribe to cheaply, so
/// this is a poll; 5 s is far below any human-noticeable login latency and
/// costs one `stat` plus, at most, one `launchctl print`.
pub const POLL: Duration = Duration::from_secs(5);

/// A worker that exits sooner than this is treated as failing, so the backoff
/// grows. Longer than this and the next failure starts from the floor again.
/// Same shape (and rationale) as the tunnel flow supervisor's run threshold:
/// a process that came up and served is not a crash loop.
pub const HEALTHY_RUN: Duration = Duration::from_secs(30);

/// Backoff floor for respawns.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// How many consecutive fast exits before the supervisor stops trying. The
/// 2026-08-30 outage looped because nothing bounded this: a worker that can
/// NEVER start is a configuration fault, and hammering it hides the cause.
pub const MAX_FAST_EXITS: u32 = 5;

/// Backoff ceiling for respawns.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// How many polls the supervisor keeps re-trying to start launchd's own worker
/// after it has released its own. Bounded because a Mac where launchd simply
/// refuses should not spawn a `launchctl` every [`POLL`] for the daemon's whole
/// life; 12 polls is a minute, which is far longer than a hand-back takes.
pub const KICKSTART_RETRIES: u32 = 12;

/// What the supervisor knows when it decides. Deliberately plain data: the
/// decision is pure so it can be tested on every platform, while the syscalls
/// that produce these fields are macOS-only. (macOS has no `cargo test` lane
/// in CI, so logic that only compiles there is logic nothing verifies.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inputs {
    /// The `macos_supervise_gui_worker` kill switch.
    pub enabled: bool,
    /// Only a root daemon can spawn into another user's session.
    pub is_root: bool,
    /// The console user's uid, or `None` at the login window / no session.
    pub console_uid: Option<u32>,
    /// Whether `gui/<uid>/com.roomler.agent` is loaded — i.e. launchd already
    /// owns a worker for this session.
    pub launch_agent_loaded: bool,
    /// Consecutive workers that exited faster than [`HEALTHY_RUN`]. A worker
    /// that can never start (no per-user enrollment on this Mac, say) would
    /// otherwise respawn forever; past [`MAX_FAST_EXITS`] the supervisor
    /// stops and says why.
    pub consecutive_fast_exits: u32,
    /// The uid our own live worker was spawned for, if we have one.
    pub worker_uid: Option<u32>,
}

/// The supervisor's next move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Switch off, or not root: do nothing, own nothing.
    Disabled,
    /// Nobody is logged in. Any worker we hold is meaningless — drop it.
    NoGuiSession,
    /// launchd owns this session's agent and we hold nothing: stand down.
    LaunchdOwns,
    /// launchd owns this session's agent **and we still hold a worker**:
    /// stop ours, then make sure theirs is actually running.
    ///
    /// A separate state from [`Action::LaunchdOwns`] because the hand-back is
    /// not just "drop ours" — see [`imp::kickstart_launch_agent`] for the race
    /// that makes the second half load-bearing.
    HandBack(u32),
    /// Spawn a worker for this uid.
    Spawn(u32),
    /// The console user changed under a worker we own: replace it.
    Replace(u32),
    /// Too many workers died on arrival — stop spawning and say why. Cleared
    /// by anything that changes the situation: a session change, the
    /// LaunchAgent returning, or the switch going off.
    GaveUp,
    /// Our worker matches the current session and is alive.
    Healthy,
}

/// The whole policy, in one testable place.
pub fn decide(i: Inputs) -> Action {
    if !i.enabled || !i.is_root {
        return Action::Disabled;
    }
    let Some(uid) = i.console_uid else {
        return Action::NoGuiSession;
    };
    // launchd first: never race the LaunchAgent for one enrollment. Checked
    // even when we already hold a worker, because the plist can be
    // bootstrapped back at any time (a re-install does exactly that) and the
    // loser of that race must be us, not the enrolled agent.
    if i.launch_agent_loaded {
        return match i.worker_uid {
            Some(_) => Action::HandBack(uid),
            None => Action::LaunchdOwns,
        };
    }
    match i.worker_uid {
        Some(w) if w == uid => Action::Healthy,
        Some(_) => Action::Replace(uid),
        None if i.consecutive_fast_exits >= MAX_FAST_EXITS => Action::GaveUp,
        None => Action::Spawn(uid),
    }
}

/// Grow the respawn backoff. `ran` is how long the worker that just exited
/// stayed up; a healthy run resets the ladder.
pub fn next_backoff(current: Duration, ran: Duration) -> Duration {
    if ran >= HEALTHY_RUN {
        return BACKOFF_MIN;
    }
    let doubled = current.saturating_mul(2);
    if doubled > BACKOFF_MAX {
        BACKOFF_MAX
    } else {
        doubled
    }
}

/// FR-97 P6e-2 — how a worker ended, read off its wait status.
///
/// The child the supervisor reaps is `sudo`, not the agent: `launchctl asuser`
/// execs into it. `sudo` passes its command's end through as its own, a signal
/// as the same signal and an exit code as the same code. Measured on macOS 15.7
/// with sudo 1.9.13 (FR-97 §8): `kill -9`, `-SEGV`, `-BUS`, `-ABRT`, `-TERM`
/// and `-HUP` on the worker came back as signals 9, 11, 10, 6, 15 and 1, and
/// `exit 7` as code 7. So this is the worker's own end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerEnd {
    /// It exited with this code.
    Code(i32),
    /// This signal ended it, in Darwin's numbering.
    Signal(i32),
}

/// The worker's end from the status `try_wait` returned. `None` only for a
/// status that carries neither, which a terminated child never has.
#[cfg(unix)]
pub fn worker_end(status: std::process::ExitStatus) -> Option<WorkerEnd> {
    use std::os::unix::process::ExitStatusExt;
    status
        .signal()
        .map(WorkerEnd::Signal)
        .or_else(|| status.code().map(WorkerEnd::Code))
}

// Darwin's signal numbers, which a wait status on a Mac carries. Spelt out
// rather than taken from `libc` because the pure half of this module also
// builds and tests on Linux and Windows, where some are numbered differently
// (SIGBUS is 7 on Linux) or are missing. The macOS build checks every one
// against `libc` (`imp`).
const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGQUIT: i32 = 3;
const SIGILL: i32 = 4;
const SIGTRAP: i32 = 5;
const SIGABRT: i32 = 6;
const SIGFPE: i32 = 8;
const SIGKILL: i32 = 9;
const SIGBUS: i32 = 10;
const SIGSEGV: i32 = 11;
const SIGSYS: i32 = 12;
const SIGTERM: i32 = 15;

const SIGNAL_NAMES: &[(i32, &str)] = &[
    (SIGHUP, "SIGHUP"),
    (SIGINT, "SIGINT"),
    (SIGQUIT, "SIGQUIT"),
    (SIGILL, "SIGILL"),
    (SIGTRAP, "SIGTRAP"),
    (SIGABRT, "SIGABRT"),
    (SIGFPE, "SIGFPE"),
    (SIGKILL, "SIGKILL"),
    (SIGBUS, "SIGBUS"),
    (SIGSEGV, "SIGSEGV"),
    (SIGSYS, "SIGSYS"),
    (SIGTERM, "SIGTERM"),
];

/// FR-97 P6e-2 — the crash record's summary for a worker's end, or `None`
/// when the end is not a crash.
///
/// A crash is an end the worker's own hooks could not record: a signal that
/// killed it before its panic hook ran (SIGKILL, SIGSEGV, SIGBUS…), or an exit
/// the agent did not choose. Not a crash:
/// - exit code 0;
/// - the codes the agent exits with on purpose (`ALREADY_RUNNING`,
///   `AGENT_DELETED`, `RESTART_REQUESTED`), and `STALL`, which the watchdog
///   recorded itself before it forced the exit. The Windows supervisor skips
///   the same list (`should_record_supervisor_crash`), plus a session-teardown
///   code that macOS has no equivalent of;
/// - SIGTERM, SIGHUP and SIGINT: a logout, a closed terminal or a person
///   ending the process on purpose.
///
/// ⚠️ `RESTART_REQUESTED_EXIT_CODE` is 9, and so is SIGKILL. Exit code 9 is a
/// restart someone asked for; signal 9 is a kill. Only the [`WorkerEnd`]
/// variant tells them apart, which is why this takes no flat number.
pub fn crash_summary(end: WorkerEnd, uid: u32, ran: Duration) -> Option<String> {
    use crate::watchdog::{
        AGENT_DELETED_EXIT_CODE, ALREADY_RUNNING_EXIT_CODE, RESTART_REQUESTED_EXIT_CODE,
        STALL_EXIT_CODE,
    };
    let how = match end {
        WorkerEnd::Code(
            0
            | STALL_EXIT_CODE
            | AGENT_DELETED_EXIT_CODE
            | ALREADY_RUNNING_EXIT_CODE
            | RESTART_REQUESTED_EXIT_CODE,
        ) => return None,
        WorkerEnd::Code(code) => format!("exited with code {code}"),
        WorkerEnd::Signal(SIGHUP | SIGINT | SIGTERM) => return None,
        WorkerEnd::Signal(sig) => match SIGNAL_NAMES.iter().find(|(n, _)| *n == sig) {
            Some((_, name)) => format!("was killed by {name} ({sig})"),
            None => format!("was killed by signal {sig}"),
        },
    };
    Some(format!(
        "macOS supervisor: the GUI worker (uid {uid}) {how} after {} s",
        ran.as_secs()
    ))
}

#[cfg(target_os = "macos")]
pub use imp::run;

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    // FR-97 P6e-2 — the Darwin numbers `crash_summary` reads, checked here, on
    // the one OS whose wait statuses carry them.
    const _: () = assert!(
        SIGHUP == libc::SIGHUP
            && SIGINT == libc::SIGINT
            && SIGQUIT == libc::SIGQUIT
            && SIGILL == libc::SIGILL
            && SIGTRAP == libc::SIGTRAP
            && SIGABRT == libc::SIGABRT
            && SIGFPE == libc::SIGFPE
            && SIGKILL == libc::SIGKILL
            && SIGBUS == libc::SIGBUS
            && SIGSEGV == libc::SIGSEGV
            && SIGSYS == libc::SIGSYS
            && SIGTERM == libc::SIGTERM
    );

    /// The LaunchAgent label the postinstall bootstraps. If this is loaded,
    /// we stand down — see the module docs.
    const AGENT_LABEL: &str = "com.roomler.agent";

    /// The console user's uid, or `None` when nobody is logged in.
    ///
    /// `/dev/console`'s owner is the canonical answer and the same one the
    /// pkg postinstall uses (`stat -f %Su /dev/console`). uid 0 means the
    /// login window: root "owns" the console with no Aqua session behind it,
    /// which is emphatically not a session we can spawn into.
    fn console_uid() -> Option<u32> {
        let uid = std::fs::metadata("/dev/console").ok()?.uid();
        (uid != 0).then_some(uid)
    }

    /// Is `gui/<uid>/com.roomler.agent` loaded? Exit status only — the output
    /// is launchd's own formatting and we depend on none of it.
    fn launch_agent_loaded(uid: u32) -> bool {
        Command::new("launchctl")
            .arg("print")
            .arg(format!("gui/{uid}/{AGENT_LABEL}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Spawn the agent into `uid`'s GUI session, **as that user**.
    ///
    /// ⚠️ `launchctl asuser <uid> <cmd>` joins the user's Mach bootstrap
    /// namespace but does **NOT** change credentials — `launchctl asuser 501
    /// id -u` prints `0`. Shipping without the `sudo -u` half cost a real
    /// outage on 2026-08-30: every worker started as ROOT, resolved root's
    /// profile config, died instantly with
    /// `no config found at /var/root/Library/Application Support/...`, and the
    /// supervisor respawned it on the backoff ladder for as long as the
    /// LaunchAgent stayed unloaded. The session half of the P0 spike was
    /// right; the identity half was never measured, because the probe used
    /// `caps` — which reports the GUI session and the TCC grants (both of
    /// which root-in-a-session genuinely has) and says nothing about *which*
    /// config the process would load.
    ///
    /// `sudo -u "#<uid>"` takes a numeric id, so this needs no `getpwuid`
    /// lookup and cannot pick the wrong account when a uid has several names.
    /// Verified on the MacBook: `asuser + sudo -u "#501"` yields uid 501,
    /// `has_input_permission: true`, and a config that resolves.
    ///
    /// No `--config`: the child now really is that user, so `appdirs`
    /// resolves the user's own config — the same enrollment the LaunchAgent
    /// would have used. P1 changes who launches the worker, nothing about its
    /// identity.
    fn spawn_worker(uid: u32, exe: &std::path::Path, secret: &str) -> std::io::Result<Child> {
        let mut child = Command::new("launchctl")
            .arg("asuser")
            .arg(uid.to_string())
            .arg("sudo")
            .arg("-u")
            .arg(format!("#{uid}"))
            .arg(exe)
            .arg("run")
            // FR-43 P2a — tell the worker it is ours, and that its
            // delegation-channel secret is waiting on stdin.
            //
            // ⚠️ This REPLACES the `ROOMLER_MACOS_SUPERVISED` environment
            // marker P1 shipped, which never arrived at a single worker:
            // `sudo` runs under the stock `Defaults env_reset` and discards the
            // parent's environment. Measured on the MacBook 2026-08-31 —
            // `ps -E` on a live supervised worker showed ZERO `ROOMLER_MACOS*`
            // variables. Nothing had noticed because nothing read the marker
            // yet, which is precisely what made it worth checking before
            // building on it.
            .arg("--supervised")
            // The secret goes on the pipe, never in argv: `ps` is world
            // readable and the pipe is only ours.
            .stdin(Stdio::piped())
            // Own process group, so `stop_worker` can take the whole
            // launchctl -> sudo -> agent chain down instead of orphaning it.
            .process_group(0)
            .spawn()?;
        // Write it and immediately drop the handle: the worker reads ONE line
        // and the EOF is what tells it there is no more. Holding the pipe open
        // would leave a worker that read a partial line waiting forever.
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            if let Err(e) = writeln!(stdin, "{secret}") {
                // Not fatal: the worker will time out waiting, log loudly, and
                // simply not attach. It is still a fully enrolled agent that
                // serves its own sessions, so the remote-desktop half keeps
                // working — degrading to P1 behaviour is the right failure.
                tracing::warn!(error = %e, "macOS supervisor: could not hand the worker its delegation secret");
            }
        }
        Ok(child)
    }

    /// Complete a hand-back: make sure launchd's own worker is running.
    ///
    /// Dropping our worker is only HALF of handing ownership back, because the
    /// hand-back is a race and launchd's side loses it **silently**:
    ///
    /// 1. the LaunchAgent is bootstrapped, so launchd starts its worker at
    ///    once;
    /// 2. that worker finds OUR worker holding the single-instance lock and
    ///    exits — with status **0**, logging `single-instance lock held by
    ///    another process; exiting`;
    /// 3. the plist's `KeepAlive{SuccessfulExit=false}` therefore treats that
    ///    as a job that ran and finished, and never retries it;
    /// 4. up to [`POLL`] later we notice `launch_agent_loaded` and stop our
    ///    worker — by which time launchd has already given up.
    ///
    /// Net effect: the Mac ends with **no user half at all**, and nothing
    /// scheduled to bring one back. Field-measured on 0.4.35, 2026-08-31,
    /// on the exact sequence #1029 was cut to fix — its process-group kill
    /// worked (no orphan survived), which is precisely what uncovered this:
    /// the two are the same root cause seen from opposite ends, namely that
    /// the loser of the lock race exits cleanly and is never retried.
    ///
    /// `launchctl kickstart` (deliberately **without** `-k`) starts the job if
    /// it is not running and is a no-op if it is, so this is idempotent and
    /// cannot disturb a healthy launchd-owned worker. It runs AFTER
    /// [`stop_worker`], which reaps the group, so the lock is free by then.
    ///
    /// Returns whether launchd accepted it. A failure has to be **retried by
    /// the caller**, because by then we have already stopped our own worker:
    /// the next poll sees [`Action::LaunchdOwns`] (we no longer hold one), so
    /// nothing would bring the hand-back back around on its own, and the Mac
    /// would sit with no user half — the exact outcome this function exists to
    /// prevent. [`KICKSTART_RETRIES`] bounds that, so a Mac where launchd
    /// genuinely refuses does not spawn a subprocess every [`POLL`] forever.
    fn kickstart_launch_agent(uid: u32) -> bool {
        let job = format!("gui/{uid}/{AGENT_LABEL}");
        match Command::new("launchctl")
            .arg("kickstart")
            .arg(&job)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(s) if s.success() => {
                tracing::info!(
                    uid,
                    job = %job,
                    "macOS supervisor: handed the worker back to launchd"
                );
                true
            }
            Ok(s) => {
                tracing::warn!(
                    uid,
                    job = %job,
                    status = ?s.code(),
                    "macOS supervisor: could not kickstart the LaunchAgent — \
                     this session may be left with no user half until launchd \
                     starts one"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    uid,
                    job = %job,
                    error = %e,
                    "macOS supervisor: could not run launchctl kickstart"
                );
                false
            }
        }
    }

    /// Stop a worker we own — the whole process GROUP, not just our child.
    ///
    /// `launchctl asuser … sudo -u '#uid' … run` gives us a three-deep chain
    /// (launchctl → sudo → agent), so killing the direct child leaves the
    /// agent alive and re-parented to launchd. Field-measured on 2026-08-30
    /// while restoring the Mac after the P1 test: the orphan kept running,
    /// held the agent's **single-instance lock**, and launchd's own
    /// LaunchAgent worker therefore exited with
    /// `single-instance lock held by another process; exiting` — cleanly, so
    /// `KeepAlive{SuccessfulExit=false}` never retried it. Net effect: turning
    /// the supervisor OFF left the Mac running an UNSUPERVISED orphan that
    /// nothing would restart. Handing ownership back has to be clean, or the
    /// kill switch is not one.
    ///
    /// [`spawn_worker`] therefore puts the chain in its own process group
    /// (`process_group(0)`), and this kills the group: SIGTERM, a short grace
    /// period, then SIGKILL for whatever is left.
    fn stop_worker(
        uid: u32,
        mut child: Child,
        why: &str,
        delegate: &crate::delegate::DelegateHost,
    ) {
        // FR-43 P2a — revoke FIRST, before the process is even signalled: a
        // worker being torn down must not be able to (re)attach on its way out,
        // and doing it here rather than at the four call sites is what makes
        // "someone forgot one" unrepresentable.
        delegate.revoke();
        let pgid = child.id() as i32;
        tracing::info!(
            uid,
            why,
            pgid,
            "macOS supervisor: stopping our GUI worker group"
        );
        // SAFETY: `kill` with a negative pid signals the process group; the
        // group is one we created in `spawn_worker`, so it contains only our
        // own descendants. A failure here is not actionable (the group may
        // already be gone), hence the ignored return.
        unsafe {
            libc::kill(-pgid, libc::SIGTERM);
        }
        for _ in 0..20 {
            match child.try_wait() {
                Ok(Some(_)) => break,
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        // SAFETY: same contract as above.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    /// Supervise for the process lifetime. Never returns an error to the
    /// caller: a supervisor that can take the daemon down with it would trade
    /// a missing remote-desktop half for a missing mesh — a worse failure
    /// than the one it exists to fix.
    pub async fn run(
        enabled: bool,
        delegate: crate::delegate::DelegateHost,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let is_root = unsafe { libc::geteuid() } == 0;
        if !enabled || !is_root {
            tracing::debug!(
                enabled,
                is_root,
                "macOS GUI-worker supervisor idle (switch off, or not root)"
            );
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "macOS supervisor: cannot resolve own exe — not supervising"
                );
                return;
            }
        };
        tracing::info!(
            exe = %exe.display(),
            "macOS GUI-worker supervisor ON (FR-43 P1) — stands down whenever the LaunchAgent is loaded"
        );

        let mut worker: Option<(u32, Child, Instant)> = None;
        let mut backoff = BACKOFF_MIN;
        let mut fast_exits: u32 = 0;
        let mut wait_until: Option<Instant> = None;
        let mut last_action: Option<Action> = None;
        // Polls left to keep re-trying launchd's own worker after a hand-back
        // whose kickstart failed. 0 = nothing owed. (`//`, not `///`: a doc
        // comment on a `let` is an `unused_doc_comments` warning, and this
        // module compiles only in the macOS lane, where warnings are denied.)
        let mut kickstart_debt: u32 = 0;

        loop {
            // Reap first, so `worker_uid` reflects reality this tick.
            //
            // The borrow of `worker` has to END before the assignment below —
            // hence the map/filter dance rather than mutating inside an
            // `if let ... = worker.as_mut()` body. (Windows never compiles
            // this module, so only the macOS lane would have caught it.)
            let exited = worker
                .as_mut()
                .and_then(|(uid, child, started)| match child.try_wait() {
                    Ok(Some(status)) => Some((*uid, started.elapsed(), status)),
                    _ => None,
                });
            if let Some((uid, ran, status)) = exited {
                backoff = next_backoff(backoff, ran);
                fast_exits = if ran >= HEALTHY_RUN {
                    0
                } else {
                    fast_exits + 1
                };
                tracing::warn!(
                    uid,
                    ran_secs = ran.as_secs(),
                    retry_in_secs = backoff.as_secs(),
                    %status,
                    "macOS supervisor: GUI worker exited"
                );
                // FR-97 P6e-2 — a worker killed by a signal never reaches its
                // own panic hook, so nothing else records it. The record goes
                // to this daemon's own crashes dir, which its own uploader
                // drains (`WriterContext::Supervisor`), so it reaches the
                // server on the daemon's enrollment. Ends this supervisor
                // causes never get here: `stop_worker` reaps its own child.
                if let Some(summary) = worker_end(status).and_then(|e| crash_summary(e, uid, ran)) {
                    crate::crash_recorder::record(
                        crate::crash_recorder::Reason::SupervisorDetected,
                        &summary,
                        crate::crash_recorder::WriterContext::Supervisor,
                    );
                }
                wait_until = Some(Instant::now() + backoff);
                worker = None;
            }

            let uid_now = console_uid();
            let action = decide(Inputs {
                enabled: true,
                is_root: true,
                console_uid: uid_now,
                // Only ask launchd when there is a session to ask about.
                launch_agent_loaded: uid_now.is_some_and(launch_agent_loaded),
                worker_uid: worker.as_ref().map(|(u, _, _)| *u),
                consecutive_fast_exits: fast_exits,
            });

            // Log transitions, not every tick: this loop runs every 5 s for
            // the daemon's whole life.
            if last_action != Some(action) {
                if matches!(action, Action::GaveUp) {
                    tracing::error!(
                        console_uid = ?uid_now,
                        fast_exits,
                        max = MAX_FAST_EXITS,
                        "macOS supervisor: the GUI worker died on arrival too many times — \
                         NOT retrying. Almost always this Mac has no per-user enrollment: \
                         the worker runs AS the console user and loads THAT user's config. \
                         Check with: launchctl asuser <uid> sudo -u '#<uid>' roomlerd caps"
                    );
                } else {
                    tracing::info!(?action, console_uid = ?uid_now, "macOS supervisor state");
                }
                last_action = Some(action);
            }

            match action {
                Action::Healthy | Action::Disabled => {}
                Action::GaveUp => {
                    // Logged once via the transition logger above; nothing to
                    // do until the situation changes.
                }
                Action::NoGuiSession => {
                    fast_exits = 0;
                    // Nobody is logged in, so there is no LaunchAgent to owe a
                    // kickstart to; forget any debt from the last session.
                    kickstart_debt = 0;
                    if let Some((uid, child, _)) = worker.take() {
                        stop_worker(uid, child, "GUI session ended", &delegate);
                    }
                }
                Action::LaunchdOwns => {
                    fast_exits = 0;
                    // We hold no worker here, so `HandBack` will never come
                    // around again — this is the ONLY place a failed hand-back
                    // can be retried from. See `kickstart_launch_agent`.
                    if kickstart_debt > 0 {
                        match uid_now {
                            // Cleared by success, not by reaching zero: those
                            // are opposite outcomes and must not share a
                            // branch.
                            Some(uid) if kickstart_launch_agent(uid) => kickstart_debt = 0,
                            Some(uid) => {
                                kickstart_debt -= 1;
                                if kickstart_debt == 0 {
                                    tracing::error!(
                                        uid,
                                        "macOS supervisor: gave up starting launchd's own \
                                         worker — this session has no user half until \
                                         launchd or an operator starts one"
                                    );
                                }
                            }
                            // Unreachable while the action is LaunchdOwns
                            // (`decide` returns NoGuiSession without a console
                            // uid), but a debt owed to a session that no longer
                            // exists is not a debt.
                            None => kickstart_debt = 0,
                        }
                    }
                }
                Action::HandBack(uid) => {
                    fast_exits = 0;
                    if let Some((held, child, _)) = worker.take() {
                        stop_worker(held, child, "launchd took ownership", &delegate);
                    }
                    kickstart_debt = if kickstart_launch_agent(uid) {
                        0
                    } else {
                        KICKSTART_RETRIES
                    };
                }
                Action::Replace(uid) => {
                    fast_exits = 0;
                    if let Some((old, child, _)) = worker.take() {
                        tracing::info!(
                            old_uid = old,
                            new_uid = uid,
                            "macOS supervisor: console user changed"
                        );
                        stop_worker(old, child, "console user changed", &delegate);
                    }
                    // Spawn on the next tick, through the normal Spawn arm.
                }
                Action::Spawn(uid) => {
                    if wait_until.is_none_or(|t| Instant::now() >= t) {
                        // Opens the per-uid socket AND mints the secret:
                        // the endpoint must exist before the child can dial it,
                        // and tying the two together means neither can be
                        // set up without the other.
                        let secret = delegate.open_for(uid);
                        match spawn_worker(uid, &exe, &secret) {
                            Ok(child) => {
                                tracing::info!(uid, "macOS supervisor: spawned GUI worker");
                                worker = Some((uid, child, Instant::now()));
                                wait_until = None;
                            }
                            Err(e) => {
                                backoff = next_backoff(backoff, Duration::ZERO);
                                wait_until = Some(Instant::now() + backoff);
                                tracing::warn!(
                                    uid,
                                    error = %e,
                                    retry_in_secs = backoff.as_secs(),
                                    "macOS supervisor: spawn failed"
                                );
                            }
                        }
                    }
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(POLL) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        if let Some((uid, child, _)) = worker.take() {
                            stop_worker(uid, child, "daemon shutting down", &delegate);
                        }
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Inputs {
        Inputs {
            enabled: true,
            is_root: true,
            console_uid: Some(501),
            launch_agent_loaded: false,
            worker_uid: None,
            consecutive_fast_exits: 0,
        }
    }

    #[test]
    fn off_or_unprivileged_does_nothing() {
        assert_eq!(
            decide(Inputs {
                enabled: false,
                ..base()
            }),
            Action::Disabled
        );
        assert_eq!(
            decide(Inputs {
                is_root: false,
                ..base()
            }),
            Action::Disabled
        );
        // Even holding a worker, the switch wins — flipping it off must
        // restore today's behaviour without a restart.
        assert_eq!(
            decide(Inputs {
                enabled: false,
                worker_uid: Some(501),
                ..base()
            }),
            Action::Disabled
        );
    }

    #[test]
    fn no_console_user_means_nothing_to_supervise() {
        assert_eq!(
            decide(Inputs {
                console_uid: None,
                ..base()
            }),
            Action::NoGuiSession
        );
        // Holding a worker for a session that has ended is not "healthy".
        assert_eq!(
            decide(Inputs {
                console_uid: None,
                worker_uid: Some(501),
                ..base()
            }),
            Action::NoGuiSession
        );
    }

    /// The property that makes P1 safe to flip on a live Mac: while the
    /// LaunchAgent is loaded we never spawn, so one enrollment is never
    /// served twice and the hub never displaces one of our own connections.
    #[test]
    fn launchd_ownership_wins_always() {
        assert_eq!(
            decide(Inputs {
                launch_agent_loaded: true,
                ..base()
            }),
            Action::LaunchdOwns
        );
        // Including when we already hold a worker: a re-install bootstraps
        // the plist back, and the loser of that race must be us. Holding one
        // makes it a HAND-BACK rather than a plain stand-down, because
        // dropping ours is only half the job.
        assert_eq!(
            decide(Inputs {
                launch_agent_loaded: true,
                worker_uid: Some(501),
                ..base()
            }),
            Action::HandBack(501)
        );
    }

    /// Handing back is two steps, so it is its own state.
    ///
    /// Field-measured on 0.4.35 (2026-08-31): stopping our worker without
    /// starting launchd's left the Mac with NO user half, because launchd's
    /// worker had already lost the single-instance lock race and exited **0**
    /// — which `KeepAlive{SuccessfulExit=false}` never retries. Collapsing
    /// this back into `LaunchdOwns` would silently restore that outage, so
    /// the distinction is asserted rather than assumed.
    #[test]
    fn handing_back_is_distinct_from_standing_down() {
        // Nothing held: there is nothing to hand back.
        assert_eq!(
            decide(Inputs {
                launch_agent_loaded: true,
                worker_uid: None,
                ..base()
            }),
            Action::LaunchdOwns
        );
        // The uid carried is the CONSOLE user's — the session whose
        // LaunchAgent has to end up running — not necessarily the uid our
        // stale worker was spawned for.
        assert_eq!(
            decide(Inputs {
                launch_agent_loaded: true,
                console_uid: Some(502),
                worker_uid: Some(501),
                ..base()
            }),
            Action::HandBack(502)
        );
        // No session means no LaunchAgent to hand back TO: dropping our
        // worker is the whole job, and kickstarting `gui/<nobody>` would
        // fail. `console_uid` is checked before `launch_agent_loaded`.
        assert_eq!(
            decide(Inputs {
                launch_agent_loaded: true,
                console_uid: None,
                worker_uid: Some(501),
                ..base()
            }),
            Action::NoGuiSession
        );
    }

    #[test]
    fn spawns_when_the_field_is_clear_and_holds_when_healthy() {
        assert_eq!(decide(base()), Action::Spawn(501));
        assert_eq!(
            decide(Inputs {
                worker_uid: Some(501),
                ..base()
            }),
            Action::Healthy
        );
    }

    #[test]
    fn console_user_change_replaces_the_worker() {
        assert_eq!(
            decide(Inputs {
                console_uid: Some(502),
                worker_uid: Some(501),
                ..base()
            }),
            Action::Replace(502)
        );
    }

    #[test]
    fn backoff_climbs_on_fast_exits_and_resets_after_a_real_run() {
        let mut b = BACKOFF_MIN;
        for _ in 0..10 {
            b = next_backoff(b, Duration::from_secs(1));
        }
        assert_eq!(b, BACKOFF_MAX, "must saturate, not grow without bound");
        assert_eq!(
            next_backoff(b, HEALTHY_RUN),
            BACKOFF_MIN,
            "a worker that actually ran resets the ladder"
        );
        // The boundary itself counts as healthy.
        assert_eq!(next_backoff(BACKOFF_MAX, HEALTHY_RUN), BACKOFF_MIN);
    }

    /// The 2026-08-30 outage in one assertion: a worker that dies on arrival
    /// must eventually STOP being respawned. Nothing bounded this, so the
    /// supervisor hammered a doomed worker for as long as the LaunchAgent
    /// stayed unloaded, and the machine looked simply dead.
    #[test]
    fn gives_up_after_enough_workers_die_on_arrival() {
        for n in 0..MAX_FAST_EXITS {
            assert_eq!(
                decide(Inputs {
                    consecutive_fast_exits: n,
                    ..base()
                }),
                Action::Spawn(501),
                "still trying at {n} failures"
            );
        }
        assert_eq!(
            decide(Inputs {
                consecutive_fast_exits: MAX_FAST_EXITS,
                ..base()
            }),
            Action::GaveUp
        );
    }

    /// Giving up must not be a latch: anything that changes the situation
    /// gets another go, because the usual fix (enrol the per-user half, log
    /// in) happens outside this process.
    #[test]
    fn giving_up_yields_to_a_changed_situation() {
        let wedged = Inputs {
            consecutive_fast_exits: MAX_FAST_EXITS + 3,
            ..base()
        };
        assert_eq!(
            decide(Inputs {
                launch_agent_loaded: true,
                ..wedged
            }),
            Action::LaunchdOwns
        );
        assert_eq!(
            decide(Inputs {
                console_uid: None,
                ..wedged
            }),
            Action::NoGuiSession
        );
        assert_eq!(
            decide(Inputs {
                enabled: false,
                ..wedged
            }),
            Action::Disabled
        );
        // And a live worker is still healthy — the counter only gates SPAWN.
        assert_eq!(
            decide(Inputs {
                worker_uid: Some(501),
                ..wedged
            }),
            Action::Healthy
        );
    }

    // FR-97 P6e-2 — which ends leave a crash record.
    #[test]
    fn a_kill_or_a_fault_leaves_a_record() {
        let ran = Duration::from_secs(42);
        for (sig, name) in [
            (9, "SIGKILL"),
            (11, "SIGSEGV"),
            (10, "SIGBUS"),
            (6, "SIGABRT"),
            (4, "SIGILL"),
        ] {
            let s = crash_summary(WorkerEnd::Signal(sig), 501, ran).expect("a crash");
            assert_eq!(
                s,
                format!(
                    "macOS supervisor: the GUI worker (uid 501) was killed by {name} ({sig}) after 42 s"
                )
            );
        }
        assert_eq!(
            crash_summary(WorkerEnd::Signal(24), 501, ran).as_deref(),
            Some("macOS supervisor: the GUI worker (uid 501) was killed by signal 24 after 42 s")
        );
        assert_eq!(
            crash_summary(WorkerEnd::Code(1), 501, ran).as_deref(),
            Some("macOS supervisor: the GUI worker (uid 501) exited with code 1 after 42 s")
        );
        // A panic on the main thread exits 101. The worker's own hook recorded
        // it on the WORKER's row; this record is the daemon's, so it stays.
        assert!(crash_summary(WorkerEnd::Code(101), 501, ran).is_some());
    }

    #[test]
    fn an_end_the_agent_chose_or_a_session_asked_for_is_not_a_crash() {
        use crate::watchdog::{
            AGENT_DELETED_EXIT_CODE, ALREADY_RUNNING_EXIT_CODE, RESTART_REQUESTED_EXIT_CODE,
            STALL_EXIT_CODE,
        };
        let ran = Duration::from_secs(42);
        for code in [
            0,
            STALL_EXIT_CODE,
            AGENT_DELETED_EXIT_CODE,
            ALREADY_RUNNING_EXIT_CODE,
            RESTART_REQUESTED_EXIT_CODE,
        ] {
            assert_eq!(
                crash_summary(WorkerEnd::Code(code), 501, ran),
                None,
                "code {code}"
            );
        }
        // SIGHUP, SIGINT, SIGTERM.
        for sig in [1, 2, 15] {
            assert_eq!(
                crash_summary(WorkerEnd::Signal(sig), 501, ran),
                None,
                "signal {sig}"
            );
        }
    }

    #[test]
    fn exit_code_nine_is_a_restart_and_signal_nine_a_kill() {
        // The collision this test exists for: renumber either and it is moot.
        assert_eq!(crate::watchdog::RESTART_REQUESTED_EXIT_CODE, 9);
        assert_eq!(SIGKILL, 9);
        let ran = Duration::from_secs(42);
        assert_eq!(crash_summary(WorkerEnd::Code(9), 501, ran), None);
        assert!(crash_summary(WorkerEnd::Signal(9), 501, ran).is_some());
    }

    /// The raw statuses are the ones measured on a Mac (FR-97 §8): perl's `$?`
    /// read 9 for `kill -9`, 11 for `-SEGV`, and 1792 for `exit 7`. The
    /// encoding is the traditional one, the same on Linux, so this runs there.
    #[cfg(unix)]
    #[test]
    fn a_wait_status_reads_as_its_signal_or_its_code() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;
        assert_eq!(
            worker_end(ExitStatus::from_raw(9)),
            Some(WorkerEnd::Signal(9))
        );
        assert_eq!(
            worker_end(ExitStatus::from_raw(11)),
            Some(WorkerEnd::Signal(11))
        );
        assert_eq!(
            worker_end(ExitStatus::from_raw(1792)),
            Some(WorkerEnd::Code(7))
        );
        assert_eq!(
            worker_end(ExitStatus::from_raw(0)),
            Some(WorkerEnd::Code(0))
        );
        // A signal that dumped core sets 0x80; it is still that signal.
        assert_eq!(
            worker_end(ExitStatus::from_raw(11 | 0x80)),
            Some(WorkerEnd::Signal(11))
        );
    }
}
