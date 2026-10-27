// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Liveness watchdog for the agent's main pumps.
//!
//! Each pump (signaling, encoder, capture) ticks the watchdog after
//! every iteration. A background tokio task scans for stalls and
//! force-exits the process via `std::process::exit(2)` when one is
//! detected — relying on the OS supervisor (Scheduled Task on
//! Windows with `RestartOnFailure`, `Restart=on-failure` on systemd,
//! `KeepAlive` on macOS) to relaunch a healthy copy.
//!
//! Why force-exit instead of panic? A panic on the watchdog task
//! doesn't unwind the application — `tokio::spawn` swallows it, the
//! agent continues with its hung pump. Hard exit is the only signal
//! that propagates to the supervisor's restart counter.
//!
//! ## Suspend / resume
//!
//! On a laptop close-lid → resume cycle, `Instant` is monotonic-but-
//! paused, so a 4-hour suspend looks like a 4-hour stall to a naive
//! scanner. The watchdog's `run` loop compares the actual sleep
//! duration to the expected scan interval; a delta beyond
//! [`SUSPEND_TOLERANCE`] is treated as a wall-clock jump and the
//! pump heartbeats are reset instead of triggering a stall exit.
//!
//! ## Watchdog-of-watchdog
//!
//! [`spawn_thread_watchdog`] starts a `std::thread` (NOT a tokio
//! task) that wakes every 30 s and force-exits if the async
//! watchdog's own heartbeat counter hasn't moved in 60 s. This is
//! the absolute last resort against a fully-deadlocked tokio
//! runtime — the only place in the codebase where we deliberately
//! step outside the async world.
//!
//! ## Global singleton
//!
//! The watchdog is a process-wide singleton accessed via
//! [`tick`] / [`gate`] / [`is_active`] free functions. Callers don't
//! need to thread an `Arc<Watchdog>` through their signatures, and
//! integration tests that don't [`install`] one just have ticks
//! become silent no-ops — the pump code stays clean.
//!
//! ## Stages (#2551)
//!
//! A tick says a pump is alive, not where it is. The signaling loop awaits
//! inside its select arms, so a stall is one arm whose await never returns,
//! and the INFO log is silent while it waits. Each arm therefore enters a
//! named stage ([`enter`]): a [`StageGuard`] that puts the pump back to
//! [`IDLE_STAGE`] when the arm's scope ends, however it ends. A stall report
//! then names the stage it froze in: `signaling=93s@ws.text:rc:ssh.response`
//! ([`stall_summary`]). The summary also reaches the crash sidecar, which
//! the next worker uploads, so the stage arrives even when the log line is
//! lost to the exit.

// FR-97 P6e (#1538) — the print macros panic on a failing stdout or stderr, and
// a panic on a watchdog thread is swallowed with the exit it was about to take.
// Lines go through `crate::logging::say_on_stderr` (and `tracing`).
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Default scan cadence. Cheap enough to run every 5 s without
/// noticeable CPU; granular enough that a 90 s stall surfaces
/// within ~95 s.
pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);

/// Suspend-detection threshold. If the watchdog loop sleeps for
/// `SCAN_INTERVAL + SUSPEND_TOLERANCE` or more, treat the gap as a
/// wall-clock jump (laptop suspend, VM resume) and reset pump
/// heartbeats instead of declaring everything stalled.
pub const SUSPEND_TOLERANCE: Duration = Duration::from_secs(60);

/// Sentinel exit code reserved for watchdog-forced terminations.
/// Distinct from 0 (clean) and 1 (unhandled error) so post-mortem
/// log aggregation can pick out watchdog kills cleanly.
pub const STALL_EXIT_CODE: i32 = 2;

/// rc.53: sentinel exit code reserved for "server-side `rc:goodbye`
/// said this agent's row is deleted / policy-rejected — operator
/// action required, do not respawn-spam." The supervisor treats this
/// distinctly from a generic non-zero exit:
///
///   * `should_record_supervisor_crash` excludes it (the agent
///     already raised a `needs-attention` sentinel; double-recording
///     would inflate fleet crash metrics — same rationale as the
///     `STALL_EXIT_CODE` exclusion).
///   * The respawn-alarm fast-path fires `error!` on the FIRST
///     code-7 exit (not after 8 like the generic alarm) so the
///     operator-action signal is visible in &lt;1 minute instead of
///     ~4 minutes (8 × ~30 s avg backoff).
///   * The supervisor still respawns indefinitely (an operator who
///     re-enrols with a fresh token between code-7 exits recovers
///     the host without a manual service restart).
pub const AGENT_DELETED_EXIT_CODE: i32 = 7;

// RETIRED-NAME-ANCHOR(2): names the legacy unit deliberately — the hazard
// being described is precisely that BOTH can be enabled at once.
/// rc.439: sentinel for "another process already holds this config's
/// single-instance lock, so this one is redundant — do NOT respawn it."
///
/// **Linux and Windows; NOT macOS.** Exit 0 means opposite things
/// depending on who is supervising, and this path needs the opposite of
/// what a self-update needs:
///
///   * **Linux** `Restart=always` restarts even on a *successful* exit —
///     it has to, because a self-update exits 0 on purpose and must come
///     back. So a 0 here is indistinguishable from that, and systemd
///     re-launches the redundant process every `RestartSec` forever.
///     Field 2026-08-21: buildhost / fleet-host-2 / fleet-host-1 each had two units enabled
///     (packaged `meshharbord.service` + a legacy `roomler-agent.service`),
///     and the loser burned 1500+ restarts at 5 s intervals for weeks
///     while the winner served happily, so nothing looked wrong.
///     `RestartPreventExitStatus` in both units lists this code.
///   * **macOS** `KeepAlive{SuccessfulExit:false}` relaunches only on an
///     UNsuccessful exit, so plain 0 is already correct there — emitting
///     this code would *create* the very loop it fixes on Linux.
///   * **Windows** `decide_exit_reaction` maps 0 to an immediate respawn
///     with NO backoff — the same bug in a worse shape than Linux's 5 s
///     spacing. Fixed by emitting this code here too and giving the
///     supervisor an `ExitReaction::Stop` arm for it, plus a
///     `should_record_supervisor_crash` exclusion. Both were required:
///     without the arm a non-zero code lands in the generic `else` and
///     respawns on the escalating ladder, and without the exclusion every
///     iteration banks a `SupervisorDetected` crash for what is a correct
///     refusal.
///
/// ⚠️ **Windows side-effect, accepted deliberately.** Nothing distinguishes
/// a supervisor-spawned worker from a directly launched one — both run
/// `Command::Run` — so the perUser *Scheduled Task* flavour now also exits
/// non-zero when it loses the lock, which trips its `<RestartOnFailure>`
/// (10 attempts, 1 min apart, then it stops for good). That is bounded and
/// self-terminating, unlike the supervisor loop this fixes, and it is
/// arguably the better signal: exiting 0 left the task reporting SUCCESS
/// while doing nothing, so an operator who had installed two conflicting
/// flavours got no indication at all. A "last run failed" task is a
/// visible, actionable state. If the 10 launches ever matter, the fix is a
/// supervised-worker marker on the spawn — not reverting to 0, which is
/// ambiguous with a self-update.
///
/// Emitted by the `AcquireOutcome::AlreadyRunning` arm in `main.rs`.
/// ⚠️ Three places must agree, in three different files, with nothing
/// coupling them: this constant, the Linux units'
/// `RestartPreventExitStatus`, and the Windows supervisor's `Stop` arm.
/// Renumbering it alone silently restores the loop on BOTH platforms.
/// The tests below assert the units; `already_running_stops_the_supervisor`
/// in `win_service::supervisor` asserts the Windows half.
pub const ALREADY_RUNNING_EXIT_CODE: i32 = 8;

/// FR-84 D3: sentinel for "a person asked this daemon to restart itself
/// (`Request::RestartDaemon`, the companion's *Apply now*) — relaunch me,
/// this was not a failure."
///
/// Why not 0: launchd's `KeepAlive{SuccessfulExit:false}` relaunches only
/// an UNsuccessful exit, and the per-user Scheduled Task's
/// `<RestartOnFailure>`, where it acts at all, acts only on a non-zero
/// code — a 0 under launchd leaves the device down. Why not any of the
/// codes above: each already means something to a supervisor (2 must come
/// back, 7 and 8 must NOT — they are `RestartPreventExitStatus=7 8` in the
/// Linux units), so this one must be OUTSIDE that list on both units, which
/// the test below asserts, and must not shadow the Windows supervisor's
/// arms. Nothing else in the tree exits 9.
///
/// Per supervisor (`supervision::Supervision::restart_exit_code`):
///
///   * **systemd** `Restart=always` restarts it after `RestartSec` — and the
///     daemon reads the unit's effective policy back from systemd before
///     it accepts (`supervision::systemd_restarts`).
///   * **launchd** relaunches it (non-zero), throttled by
///     `ThrottleInterval`.
///   * **the FR-43 macOS supervisor** respawns any exit after ≥ 1 s.
///   * **the Windows Scheduled Task**: the caller runs `meshharbord service
///     start` once the old process is gone (`restart_by: caller`); the
///     task's own `<RestartOnFailure>` is at most a floor a minute later.
///   * **the Windows SCM supervisor** does NOT see it: an SCM worker exits
///     **0**, which `decide_exit_reaction` already maps to an immediate
///     `Respawn` (and which an SCM host older than D3 respawns too). The
///     supervisor still maps this code to `Respawn` and excludes it from
///     crash recording, so a worker that emits it is never put on the crash
///     ladder for a restart it was asked for.
///
/// Emitted by `main` once `run_cmd` has completed the graceful
/// internal-shutdown path (`mark_clean_shutdown`, so nothing counts a
/// crash and the rollback detector never sees it) and the runtime has been
/// torn down exactly as an auto-update's exit tears it down. At most once
/// per `supervision::RESTART_MIN_INTERVAL`, across process lifetimes.
pub const RESTART_REQUESTED_EXIT_CODE: i32 = 9;

/// Process-wide singleton. Set by `install`; read by the free
/// functions and the `run` task.
static WATCHDOG: OnceLock<Arc<Watchdog>> = OnceLock::new();

/// #2551 — the stage a pump is in when no arm holds it: waiting in its
/// `select!` for the next event.
pub const IDLE_STAGE: &str = "select";

struct PumpState {
    last_tick: Instant,
    /// When false, the watchdog ignores this pump. Used to gate
    /// per-session pumps (encoder, capture) — they can legitimately
    /// go silent for hours when no controller is connected.
    active: bool,
    threshold: Duration,
    /// #2551 — where the pump is: the arm it entered, or [`IDLE_STAGE`].
    stage: Cow<'static, str>,
}

pub struct Watchdog {
    pumps: Mutex<HashMap<&'static str, PumpState>>,
    /// Counter the watchdog-of-watchdog reads. Bumped every scan
    /// cycle; if it stops bumping for >60 s the async watchdog is
    /// presumed dead and the std::thread fallback force-exits.
    own_heartbeat: AtomicU64,
}

impl Watchdog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pumps: Mutex::new(HashMap::new()),
            own_heartbeat: AtomicU64::new(0),
        })
    }

    /// Declare a pump and its stall threshold. `active=false` means
    /// the watchdog ignores ticks until the pump explicitly calls
    /// `gate(true)` — appropriate for per-session pumps.
    pub fn register(&self, name: &'static str, threshold: Duration, active: bool) {
        if let Ok(mut m) = self.pumps.lock() {
            m.insert(
                name,
                PumpState {
                    last_tick: Instant::now(),
                    active,
                    threshold,
                    stage: Cow::Borrowed(IDLE_STAGE),
                },
            );
        }
    }

    /// #2551 — record the stage a pump is in. A pump that was never
    /// registered keeps no stage, as [`Self::tick`] keeps no tick.
    pub fn set_stage(&self, name: &'static str, stage: impl Into<Cow<'static, str>>) {
        if let Ok(mut m) = self.pumps.lock()
            && let Some(p) = m.get_mut(name)
        {
            p.stage = stage.into();
        }
    }

    /// #2551 — the stage a pump is in, if it is registered.
    pub fn stage_of(&self, name: &str) -> Option<String> {
        let m = self.pumps.lock().ok()?;
        m.get(name).map(|p| p.stage.to_string())
    }

    /// #2551 — enter a stage on THIS watchdog until the guard drops. The
    /// free [`enter`] is the same on the installed one.
    pub fn enter(
        self: &Arc<Self>,
        name: &'static str,
        stage: impl Into<Cow<'static, str>>,
    ) -> StageGuard {
        self.set_stage(name, stage);
        StageGuard {
            wd: Some(Arc::clone(self)),
            pump: name,
        }
    }

    pub fn tick(&self, name: &'static str) {
        if let Ok(mut m) = self.pumps.lock()
            && let Some(p) = m.get_mut(name)
        {
            p.last_tick = Instant::now();
        }
    }

    /// Enable / disable watchdog for a pump. When transitioning
    /// `false` → `true` the tick is reset so a long gated-off
    /// window doesn't immediately fire on enable.
    pub fn gate(&self, name: &'static str, active: bool) {
        if let Ok(mut m) = self.pumps.lock()
            && let Some(p) = m.get_mut(name)
        {
            if active && !p.active {
                p.last_tick = Instant::now();
            }
            p.active = active;
        }
    }

    /// Pure scan: returns the (pump_name, stall_duration) pairs that
    /// have exceeded their threshold at the given clock instant.
    /// Names are sorted so test assertions are deterministic.
    pub fn scan_at(&self, now: Instant) -> Vec<(&'static str, Duration)> {
        let Ok(m) = self.pumps.lock() else {
            return Vec::new();
        };
        let mut stalled: Vec<_> = m
            .iter()
            .filter(|(_, p)| p.active)
            .filter_map(|(name, p)| {
                let elapsed = now.saturating_duration_since(p.last_tick);
                if elapsed > p.threshold {
                    Some((*name, elapsed))
                } else {
                    None
                }
            })
            .collect();
        stalled.sort_by_key(|(name, _)| *name);
        stalled
    }

    /// Force-reset every pump's heartbeat to `now`. Called by `run`
    /// when it detects a wall-clock jump (suspend/resume).
    fn reset_all(&self, now: Instant) {
        if let Ok(mut m) = self.pumps.lock() {
            for p in m.values_mut() {
                p.last_tick = now;
            }
        }
    }

    pub fn own_heartbeat(&self) -> u64 {
        self.own_heartbeat.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------------------
// Global singleton helpers
// ---------------------------------------------------------------------------

/// Install the process-wide watchdog. Subsequent `install` calls are
/// a no-op (returns `Err(arg)` so the caller can detect double-init
/// in debug builds; release builds ignore the result).
pub fn install(wd: Arc<Watchdog>) -> Result<(), Arc<Watchdog>> {
    WATCHDOG.set(wd)
}

/// Tick a registered pump. Silent no-op when no watchdog is
/// installed (the integration-test path) or the pump isn't
/// registered (the wrong-name typo case — better to silently miss
/// stall detection than crash on a typo in a hot path).
pub fn tick(name: &'static str) {
    if let Some(wd) = WATCHDOG.get() {
        wd.tick(name);
    }
}

/// Enable or disable watchdog for a pump. Same no-op semantics as
/// `tick` when no watchdog is installed.
pub fn gate(name: &'static str, active: bool) {
    if let Some(wd) = WATCHDOG.get() {
        wd.gate(name, active);
    }
}

/// #2551 — record the stage a pump is in, on the installed watchdog. Same
/// no-op semantics as [`tick`]. Use it to refine a stage inside an arm that
/// already holds a [`StageGuard`]; the guard still resets it on exit.
pub fn stage(name: &'static str, stage: impl Into<Cow<'static, str>>) {
    if let Some(wd) = WATCHDOG.get() {
        wd.set_stage(name, stage);
    }
}

/// #2551 — enter a stage until the returned guard drops: the first line of a
/// select arm, so a stall names the arm it froze in. A no-op guard when no
/// watchdog is installed.
pub fn enter(name: &'static str, stage: impl Into<Cow<'static, str>>) -> StageGuard {
    match WATCHDOG.get() {
        Some(wd) => wd.enter(name, stage),
        None => StageGuard {
            wd: None,
            pump: name,
        },
    }
}

/// #2551 — puts its pump back to [`IDLE_STAGE`] when it drops, so an arm that
/// leaves early (`continue`, `break`, `?`) cannot leave its name behind for a
/// later stall to be blamed on.
#[must_use = "the stage ends when the guard drops: bind it to a named variable"]
pub struct StageGuard {
    wd: Option<Arc<Watchdog>>,
    pump: &'static str,
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        if let Some(wd) = &self.wd {
            wd.set_stage(self.pump, IDLE_STAGE);
        }
    }
}

/// #2551 — the stall summary: `name=Ns` for each stalled pump, plus
/// `@stage` when its stage is known. The `name=Ns` prefix stays as it was,
/// so anything that parsed the old summary still does.
pub fn stall_summary(
    stalled: &[(&'static str, Duration)],
    stage_of: impl Fn(&'static str) -> Option<String>,
) -> String {
    stalled
        .iter()
        .map(|(n, d)| match stage_of(n) {
            Some(s) if !s.is_empty() => format!("{n}={}s@{s}", d.as_secs()),
            _ => format!("{n}={}s", d.as_secs()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether a watchdog is installed. Used by tests + diagnostic
/// commands to confirm the runtime configuration.
pub fn is_active() -> bool {
    WATCHDOG.get().is_some()
}

// ---------------------------------------------------------------------------
// Run loop + thread-watchdog
// ---------------------------------------------------------------------------

/// Run the scan loop. Returns when shutdown is signalled or
/// `on_stall` returns false. Production path passes
/// [`force_exit_on_stall`] which never returns (calls `exit`).
///
/// Thin wrapper over [`run_with_intervals`] that pins the cadence
/// to the production [`SCAN_INTERVAL`] + [`SUSPEND_TOLERANCE`]
/// constants. Tests use the inner function to drive the loop on
/// sub-second intervals; production callers go through `run` so
/// they can't accidentally drift those tuning knobs.
pub async fn run(
    wd: Arc<Watchdog>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    on_stall: impl Fn(&[(&'static str, Duration)]) -> bool + Send + 'static,
) {
    run_with_intervals(wd, shutdown, on_stall, SCAN_INTERVAL, SUSPEND_TOLERANCE).await
}

/// rc.58 Phase 4: testable variant of [`run`] with both the scan
/// cadence and the suspend-tolerance injected as parameters.
/// `pub(crate)` so unit tests in this crate can drive the loop on a
/// 25 ms scan interval (vs the production 5 s); external callers
/// stick with [`run`].
pub(crate) async fn run_with_intervals(
    wd: Arc<Watchdog>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    on_stall: impl Fn(&[(&'static str, Duration)]) -> bool + Send + 'static,
    scan_interval: Duration,
    suspend_tolerance: Duration,
) {
    let mut prev = Instant::now();
    loop {
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(scan_interval) => {},
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
            },
        }
        let now = Instant::now();
        // Bump our own heartbeat first so the std::thread watchdog-
        // of-watchdog doesn't flag us mid-iteration on a slow host.
        wd.own_heartbeat.fetch_add(1, Ordering::Release);

        let actual = now.saturating_duration_since(prev);
        if actual > scan_interval + suspend_tolerance {
            tracing::warn!(
                lag_secs = actual.as_secs(),
                "watchdog detected wall-clock jump (suspend/resume); resetting pump heartbeats"
            );
            wd.reset_all(now);
            prev = now;
            continue;
        }
        prev = now;

        let stalled = wd.scan_at(now);
        if !stalled.is_empty() && !on_stall(&stalled) {
            return;
        }
    }
}

/// Spawn the watchdog-of-watchdog on a dedicated `std::thread`.
/// Force-exits the process if the async watchdog's heartbeat
/// counter has not moved in >60 s — catches the case where the
/// tokio runtime itself is deadlocked.
pub fn spawn_thread_watchdog(wd: Arc<Watchdog>) {
    let _ = std::thread::Builder::new()
        .name("roomlerd-watchdog-of-watchdog".into())
        .spawn(move || {
            let mut prev_count = wd.own_heartbeat();
            let mut prev_at = Instant::now();
            loop {
                std::thread::sleep(Duration::from_secs(30));
                let now_count = wd.own_heartbeat();
                let now_at = Instant::now();
                if now_count != prev_count {
                    prev_count = now_count;
                    prev_at = now_at;
                    continue;
                }
                let stuck_for = now_at.saturating_duration_since(prev_at);
                if stuck_for > Duration::from_secs(60) {
                    // FR-97 P6e (#1538) — never `eprintln!` here: on a failing
                    // stderr it panics, this thread dies, and the exit below,
                    // the last line of defense, never happens.
                    crate::logging::say_on_stderr(format_args!(
                        "watchdog-of-watchdog: async watchdog has not heartbeat in {:?}; \
                         forcing exit({STALL_EXIT_CODE})",
                        stuck_for
                    ));
                    // P5/A2 — this exit bypasses RAII; drop any exit-node
                    // split-default first so a stalled host doesn't stay
                    // blackholed until the supervisor's restart reconciles it.
                    crate::purge_exit_routes();
                    std::process::exit(STALL_EXIT_CODE);
                }
            }
        });
}

/// Default stall handler — log + `std::process::exit(STALL_EXIT_CODE)`.
/// Returns `false` so `run` interprets it as "stop the loop" in the
/// extremely-unlikely-but-technically-possible case where exit
/// doesn't terminate the process.
pub fn force_exit_on_stall(stalled: &[(&'static str, Duration)]) -> bool {
    // #2551 — with the stage each pump froze in. This takes the pump lock
    // `scan_at` has just released; were it ever held for good, `scan_at` would
    // have blocked first, and the thread watchdog exits without it.
    let summary = stall_summary(stalled, |n| WATCHDOG.get().and_then(|wd| wd.stage_of(n)));
    // FR-97 P6e (#1538) — a panic here would lose the exit below (see the
    // module doc), so never `eprintln!`.
    crate::logging::say_on_stderr(format_args!(
        "watchdog: pumps stalled ({summary}); forcing exit({STALL_EXIT_CODE})"
    ));
    tracing::error!(stalled = %summary, "watchdog: forcing process exit");

    // Phase 1B (Task 9): emit a crash sidecar BEFORE process-exit
    // so the next agent startup can upload it to roomler.ai. Worker
    // context: the watchdog runs inside the worker process; the SCM
    // supervisor's own crash detection (Phase 1B site 3) excludes
    // STALL_EXIT_CODE explicitly to avoid double-recording.
    crate::crash_recorder::record(
        crate::crash_recorder::Reason::WatchdogStall,
        &format!("pumps stalled ({summary})"),
        crate::crash_recorder::WriterContext::Worker,
    );

    // P5/A2 — bypasses RAII; drop any exit-node split-default so the stall
    // doesn't leave the host blackholed until the supervisor restarts it.
    crate::purge_exit_routes();

    std::process::exit(STALL_EXIT_CODE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_pump_starts_unstalled() {
        let wd = Watchdog::new();
        wd.register("test", Duration::from_secs(30), true);
        assert!(wd.scan_at(Instant::now()).is_empty());
    }

    #[test]
    fn pump_stalls_after_threshold() {
        let wd = Watchdog::new();
        wd.register("test", Duration::from_millis(50), true);
        std::thread::sleep(Duration::from_millis(100));
        let stalled = wd.scan_at(Instant::now());
        assert_eq!(stalled.len(), 1);
        assert_eq!(stalled[0].0, "test");
        assert!(stalled[0].1 >= Duration::from_millis(50));
    }

    #[test]
    fn tick_resets_stall() {
        let wd = Watchdog::new();
        wd.register("test", Duration::from_millis(50), true);
        std::thread::sleep(Duration::from_millis(80));
        wd.tick("test");
        assert!(wd.scan_at(Instant::now()).is_empty());
    }

    #[test]
    fn gated_off_pump_never_stalls() {
        let wd = Watchdog::new();
        wd.register("test", Duration::from_millis(50), false);
        std::thread::sleep(Duration::from_millis(100));
        assert!(wd.scan_at(Instant::now()).is_empty());
    }

    #[test]
    fn gate_on_resets_tick_after_long_gap() {
        let wd = Watchdog::new();
        wd.register("test", Duration::from_millis(50), false);
        std::thread::sleep(Duration::from_millis(100));
        wd.gate("test", true);
        assert!(
            wd.scan_at(Instant::now()).is_empty(),
            "gate(true) on a previously-inactive pump must reset tick"
        );
    }

    #[test]
    fn gate_on_to_on_does_not_reset_tick() {
        // Repeated gate(true) calls should be idempotent — they
        // shouldn't paper over a real stall.
        let wd = Watchdog::new();
        wd.register("test", Duration::from_millis(50), true);
        std::thread::sleep(Duration::from_millis(80));
        wd.gate("test", true); // already active
        let stalled = wd.scan_at(Instant::now());
        assert_eq!(
            stalled.len(),
            1,
            "redundant gate(true) must not mask a stall"
        );
    }

    #[test]
    fn multiple_stalled_pumps_all_reported_sorted() {
        let wd = Watchdog::new();
        wd.register("zebra", Duration::from_millis(50), true);
        wd.register("alpha", Duration::from_millis(50), true);
        wd.register("calm", Duration::from_secs(60), true); // not stalled
        std::thread::sleep(Duration::from_millis(120));
        let stalled = wd.scan_at(Instant::now());
        let names: Vec<&str> = stalled.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["alpha", "zebra"], "must be sorted by name");
    }

    #[test]
    fn unknown_pump_tick_is_silent_noop() {
        let wd = Watchdog::new();
        wd.register("known", Duration::from_secs(30), true);
        wd.tick("nonexistent"); // must not panic
        assert!(wd.scan_at(Instant::now()).is_empty());
    }

    #[test]
    fn reset_all_brings_pumps_back_to_now() {
        let wd = Watchdog::new();
        wd.register("a", Duration::from_millis(50), true);
        std::thread::sleep(Duration::from_millis(100));
        let now = Instant::now();
        wd.reset_all(now);
        assert!(wd.scan_at(now).is_empty());
    }

    #[test]
    fn global_helpers_are_noops_when_uninstalled() {
        // No `install` call in this test — `tick` / `gate` must not
        // panic. The global is process-shared with other tests but
        // those don't install it either, so the assertion holds in
        // a fresh process. (cargo test runs in a dedicated process
        // per test binary.)
        tick("unregistered");
        gate("unregistered", true);
        // is_active may be true if a prior test in this run installed
        // it; that's fine — what matters is no panic.
    }

    #[test]
    fn rc58_cold_start_grace_signaling_pattern_does_not_false_stall() {
        // Replicates the rc.58 fix exactly:
        //   * `signaling` registered with `active=false` at process start
        //     (was `true` before rc.58, which produced the field-test
        //     host 2026-05-24 crash loop: cold start with an unreachable
        //     server force-exited at 90 s every cycle because the
        //     pump was counting silence against the threshold while
        //     the agent was legitimately retry-backoff'ing).
        //   * A simulated reconnect-backoff stretch (we sleep past the
        //     threshold to ensure we'd fire if the pump was active).
        //   * `gate(true)` after the (eventual) successful connect.
        //     This MUST reset `last_tick` so the live connection gets
        //     a clean budget — the `gate(false→true)` transition is
        //     what handles the reset (see `Watchdog::gate`).
        //   * Subsequent `gate(false)` on disconnect.
        //   * A second `gate(true)` (next reconnect) must again reset
        //     `last_tick` — this was the second half of the rc.58 bug:
        //     `last_tick` was global and stale across reconnects, so
        //     a successful hello at +1 s after reconnect still got
        //     killed because the pre-disconnect `last_tick` had
        //     already aged past 90 s.
        let wd = Watchdog::new();
        wd.register("signaling", Duration::from_millis(50), false);

        // Cold-start backoff: long gap with the pump inactive. MUST
        // NOT stall.
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            wd.scan_at(Instant::now()).is_empty(),
            "inactive pump must not stall during cold-start backoff"
        );

        // First successful connect → gate on.
        wd.gate("signaling", true);
        assert!(
            wd.scan_at(Instant::now()).is_empty(),
            "gate(false→true) must reset last_tick"
        );

        // Live connection ends → gate off.
        wd.gate("signaling", false);
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            wd.scan_at(Instant::now()).is_empty(),
            "gate(true→false) must keep the pump quiet during reconnect-backoff"
        );

        // Second connect (the post-disconnect reconnect that rc.58
        // fixes): gate on again MUST reset the timer.
        wd.gate("signaling", true);
        assert!(
            wd.scan_at(Instant::now()).is_empty(),
            "each gate(false→true) cycle must reset last_tick — \
             stale timestamps across reconnects was the second half of the rc.58 bug"
        );

        // Now that we're active and have NOT ticked for > threshold,
        // the watchdog MUST fire (proves the gating didn't accidentally
        // disable stall detection altogether).
        std::thread::sleep(Duration::from_millis(80));
        let stalled = wd.scan_at(Instant::now());
        assert_eq!(stalled.len(), 1, "active pump with no ticks must stall");
        assert_eq!(stalled[0].0, "signaling");
    }

    // ─── Phase 4: run() loop semantics ───────────────────────────────────────

    /// Run the loop with a tight 25 ms scan interval and a short
    /// suspend tolerance. Returns the JoinHandle + shutdown sender so
    /// the test can stop the loop cleanly.
    fn spawn_run_loop(
        wd: Arc<Watchdog>,
        on_stall: impl Fn(&[(&'static str, Duration)]) -> bool + Send + 'static,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            run_with_intervals(
                wd,
                rx,
                on_stall,
                Duration::from_millis(25),
                Duration::from_millis(500),
            )
            .await;
        });
        (handle, tx)
    }

    #[tokio::test]
    async fn run_loop_invokes_on_stall_for_stalled_pump() {
        // Pump with a near-zero threshold + active=true → the very
        // first scan after registration must see it as stalled and
        // invoke on_stall. Locks the "run() actually calls on_stall"
        // invariant that the unit-level scan_at tests can't reach.
        let wd = Watchdog::new();
        wd.register("p", Duration::from_millis(5), true);

        let calls = Arc::new(AtomicU64::new(0));
        let calls_clone = calls.clone();
        let (handle, tx) = spawn_run_loop(wd, move |stalled| {
            // Defensive: only count scans that found OUR pump stalled,
            // so an unrelated future pump can't quiet the assertion.
            if stalled.iter().any(|(name, _)| *name == "p") {
                calls_clone.fetch_add(1, Ordering::SeqCst);
            }
            true // keep loop running
        });

        // Three scan-intervals should comfortably allow ≥1 invocation
        // even under CI jitter. We test for ≥1 (not ==1) because the
        // loop scans repeatedly until on_stall returns false.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = tx.send(true);
        let _ = handle.await;

        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "on_stall must be invoked at least once for a stalled pump; got {}",
            calls.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn run_loop_exits_when_on_stall_returns_false() {
        // Production's on_stall (`force_exit_on_stall`) returns false
        // so the loop bails before its own next iteration — defensive
        // path for the unlikely case `std::process::exit` somehow
        // doesn't terminate the process. We exercise that path here
        // without actually exiting.
        let wd = Watchdog::new();
        wd.register("p", Duration::from_millis(5), true);
        let (handle, _tx) = spawn_run_loop(wd, |_| false /* stop the loop */);

        // The loop must return within a few scan intervals; if the
        // false-return contract was broken (e.g. someone flipped the
        // sign on the predicate) the join would block until the
        // test framework's timeout.
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run_loop must exit promptly when on_stall returns false")
            .expect("run_loop task must not panic");
    }

    #[tokio::test]
    async fn run_loop_exits_when_shutdown_signalled() {
        // No pump registered → no stalls. The loop should sit on its
        // tokio::select! awaiting either a scan tick or a shutdown
        // change. Send `true` and assert prompt exit.
        let wd = Watchdog::new();
        let (handle, tx) = spawn_run_loop(wd, |_| true);

        // Settle a bit so we know the loop is actively in the select
        // (not just about to start), then signal shutdown.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(true);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run_loop must exit promptly on shutdown signal")
            .expect("run_loop task must not panic");
    }

    #[tokio::test]
    async fn run_loop_bumps_own_heartbeat_each_scan() {
        // The watchdog-of-watchdog (spawn_thread_watchdog) reads
        // own_heartbeat to detect a fully-deadlocked tokio runtime.
        // If a refactor stops bumping the counter inside the scan
        // loop, the thread-watchdog would force-exit a perfectly
        // healthy process after 60 s. Pin the contract.
        let wd = Watchdog::new();
        let initial = wd.own_heartbeat();
        let (handle, tx) = spawn_run_loop(wd.clone(), |_| true);
        // ≥3 scan intervals worth of wall time.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = tx.send(true);
        let _ = handle.await;
        let after = wd.own_heartbeat();
        assert!(
            after >= initial + 3,
            "own_heartbeat must bump ≥3 times across 150ms / 25ms scan-interval; \
             initial={initial} after={after}"
        );
    }

    #[tokio::test]
    async fn run_loop_does_not_fire_stall_for_inactive_pump_during_long_idle() {
        // Locks the rc.58 cold-start fix at the loop level (the
        // earlier `rc58_cold_start_grace_signaling_pattern_does_not_
        // false_stall` covers it at the scan_at level). With the pump
        // registered active=false from the start, the loop must NEVER
        // see it as stalled even though we sleep long past the
        // threshold. A regression that flipped `active=true` default
        // back on would fire on_stall here.
        let wd = Watchdog::new();
        wd.register("signaling", Duration::from_millis(5), false);

        let stall_calls = Arc::new(AtomicU64::new(0));
        let stall_calls_clone = stall_calls.clone();
        let (handle, tx) = spawn_run_loop(wd, move |stalled| {
            if !stalled.is_empty() {
                stall_calls_clone.fetch_add(1, Ordering::SeqCst);
            }
            true
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = tx.send(true);
        let _ = handle.await;

        assert_eq!(
            stall_calls.load(Ordering::SeqCst),
            0,
            "inactive pump must not be reported as stalled — \
             this is the rc.58 cold-start grace contract"
        );
    }

    // ─── Phase 4: production-cadence constants pinned ────────────────────────

    #[test]
    fn scan_interval_is_reasonable() {
        // Too short → CPU waste from constant Mutex polls. Too long
        // → stall-detection latency exceeds the operator's "agent
        // looks frozen" patience window. The current 5 s value is
        // 18× under the 90 s signaling threshold, giving plenty of
        // scan opportunities to catch a stall.
        assert!(SCAN_INTERVAL >= Duration::from_secs(1));
        assert!(SCAN_INTERVAL <= Duration::from_secs(15));
    }

    #[test]
    fn suspend_tolerance_covers_realistic_resume_gap() {
        // SUSPEND_TOLERANCE distinguishes "the host was suspended"
        // from "a pump genuinely stalled". A laptop closed-lid →
        // open-lid cycle can take many seconds (NVMe wake, network
        // re-attach); 60 s is comfortable headroom. A regression
        // dropping this below ~10 s would start false-positive
        // "wall-clock jump" warns on busy hosts.
        assert!(SUSPEND_TOLERANCE >= Duration::from_secs(10));
    }

    #[test]
    fn exit_code_sentinels_are_distinct_and_documented() {
        // rc.53: the supervisor branches on these two specific codes
        // (`STALL_EXIT_CODE` excluded from crash recording, and
        // `AGENT_DELETED_EXIT_CODE` excluded AND fast-alarmed). A
        // future change that collides them — e.g. someone renumbers
        // AGENT_DELETED to 2 — would silently turn off the rc.53
        // fast-alarm signal because the existing STALL exclusion
        // would absorb it. This test fires before that ships.
        assert_ne!(
            STALL_EXIT_CODE, AGENT_DELETED_EXIT_CODE,
            "exit-code sentinels must be distinct so supervisor branches don't alias"
        );
        let all = [
            STALL_EXIT_CODE,
            AGENT_DELETED_EXIT_CODE,
            ALREADY_RUNNING_EXIT_CODE,
            RESTART_REQUESTED_EXIT_CODE,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "exit-code sentinels must all be distinct");
            }
        }
        // The constants are referenced by string in field-doc
        // (operator runbook + smoke matrix) — pin the literal values.
        assert_eq!(STALL_EXIT_CODE, 2);
        assert_eq!(AGENT_DELETED_EXIT_CODE, 7);
        assert_eq!(ALREADY_RUNNING_EXIT_CODE, 8);
        assert_eq!(RESTART_REQUESTED_EXIT_CODE, 9);
        // 0 and 1 are the ordinary exits; a sentinel on either would be
        // ambiguous with "done" / "an error" to every supervisor.
        for code in all {
            assert!(code > 1, "sentinel {code} collides with an ordinary exit");
        }
    }

    /// FR-84 D3 — the inverse of the test above for the restart sentinel: a
    /// requested restart MUST come back, so neither unit may list it in
    /// `RestartPreventExitStatus`. A unit that did would turn "Apply now" into
    /// "go offline" on every Linux host at once, with `systemctl is-active`
    /// reading `inactive` and nothing logging why.
    #[test]
    fn shipped_linux_units_restart_the_restart_requested_sentinel() {
        for (name, unit) in [
            (
                "meshharbord.service",
                include_str!("../packaging/linux/meshharbord.service"),
            ),
            (
                "meshharbor.service",
                include_str!("../packaging/linux/meshharbor.service"),
            ),
        ] {
            let codes: Vec<i32> = unit
                .lines()
                .find(|l| l.starts_with("RestartPreventExitStatus="))
                .unwrap_or_else(|| panic!("{name}: no RestartPreventExitStatus= line"))
                .trim_start_matches("RestartPreventExitStatus=")
                .split_whitespace()
                .map(|c| c.parse().expect("numeric exit code"))
                .collect();
            assert!(
                !codes.contains(&RESTART_REQUESTED_EXIT_CODE),
                "{name} must NOT list RESTART_REQUESTED_EXIT_CODE ({RESTART_REQUESTED_EXIT_CODE}); \
                 got {codes:?}"
            );
            // And the policy must be one that restarts a non-zero exit at all.
            assert!(
                unit.lines().any(|l| l.trim() == "Restart=always"),
                "{name}: the restart sentinel relies on Restart=always"
            );
        }
    }

    #[test]
    fn shipped_linux_units_prevent_restart_on_the_already_running_sentinel() {
        // The constant is only HALF the fix: systemd relaunches the
        // redundant process regardless unless the unit also lists the
        // code. The two live in different files with nothing coupling
        // them, so renumbering the constant alone would silently restore
        // the 5 s restart loop this exists to kill (buildhost / fleet-host-2 /
        // fleet-host-1, 1500+ restarts each, found 2026-08-21). Assert the
        // shipped units and the constants agree — in both directions.
        for (name, unit) in [
            (
                "meshharbord.service",
                include_str!("../packaging/linux/meshharbord.service"),
            ),
            (
                "meshharbor.service",
                include_str!("../packaging/linux/meshharbor.service"),
            ),
        ] {
            let line = unit
                .lines()
                .find(|l| l.starts_with("RestartPreventExitStatus="))
                .unwrap_or_else(|| panic!("{name}: no RestartPreventExitStatus= line"));
            let codes: Vec<i32> = line
                .trim_start_matches("RestartPreventExitStatus=")
                .split_whitespace()
                .map(|c| {
                    c.parse()
                        .unwrap_or_else(|_| panic!("{name}: non-numeric exit code {c:?}"))
                })
                .collect();

            assert!(
                codes.contains(&ALREADY_RUNNING_EXIT_CODE),
                "{name} must list ALREADY_RUNNING_EXIT_CODE ({ALREADY_RUNNING_EXIT_CODE}), \
                 else a redundant instance restart-loops every RestartSec forever; got {codes:?}"
            );
            assert!(
                codes.contains(&AGENT_DELETED_EXIT_CODE),
                "{name} must still list AGENT_DELETED_EXIT_CODE ({AGENT_DELETED_EXIT_CODE}); \
                 got {codes:?}"
            );
            // The inverse matters just as much: a watchdog-forced exit is
            // the case that MUST come back, so listing it here would turn
            // a stall into a permanently dead node.
            assert!(
                !codes.contains(&STALL_EXIT_CODE),
                "{name} must NOT list STALL_EXIT_CODE ({STALL_EXIT_CODE}) — a watchdog kill \
                 has to be restarted; got {codes:?}"
            );
        }
    }

    #[test]
    fn deb_postinst_is_a_unix_shell_script() {
        // This script exists so a unit change (like the exception asserted
        // above) is not inert until the host reboots — without a
        // `daemon-reload` systemd keeps enforcing its cached copy.
        //
        // It is authored from a Windows box, and a maintainer script with
        // CRLF endings has the shebang `#!/bin/sh\r`, which resolves to a
        // nonexistent interpreter. dpkg then fails to CONFIGURE the package
        // on every host it reaches — for a self-updating fleet, a
        // fleet-wide broken upgrade. `.gitattributes` pins `eol=lf`; this
        // asserts the result rather than trusting the config.
        let s = include_str!("../packaging/linux/debian/postinst");
        assert!(
            !s.contains('\r'),
            "postinst has CR bytes — `#!/bin/sh\\r` breaks dpkg configure fleet-wide"
        );
        assert!(
            s.starts_with("#!/bin/sh\n"),
            "postinst must open with a plain /bin/sh shebang; got {:?}",
            s.lines().next()
        );
        assert!(s.contains("daemon-reload"), "postinst must reload systemd");
        // The DAEMON is never enabled, started or restarted from a package
        // upgrade: that would change what runs on the host and would fight the
        // self-updater that invoked dpkg. FR-96 P5 — the ONE thing postinst
        // turns on is the package's update half, the timer and the path, the
        // Debian way (deb-systemd-helper), so an administrator's disable holds.
        let code: Vec<&str> = s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        for line in &code {
            for daemon in ["meshharbord.service", "meshharbor.service"] {
                assert!(
                    !line.contains(daemon),
                    "postinst must not act on the daemon unit `{daemon}`: {line}"
                );
            }
            for forbidden in [
                "systemctl enable",
                "systemctl start",
                "systemctl restart",
                "systemctl stop",
                "deb-systemd-invoke restart",
                "deb-systemd-invoke stop",
            ] {
                assert!(
                    !line.contains(forbidden),
                    "postinst must not `{forbidden}` — a package upgrade is not permission \
                     to change what is running: {line}"
                );
            }
        }
        assert!(
            code.contains(&"HELPER_UNITS=\"meshharbor-update.timer meshharbor-update.path\""),
            "postinst turns on exactly the update helper's timer and path"
        );
        assert!(
            code.iter()
                .any(|l| l.contains("deb-systemd-helper --quiet was-enabled \"$unit\""))
        );
        assert!(
            code.iter()
                .any(|l| l.contains("deb-systemd-helper enable \"$unit\""))
        );
        assert!(
            code.iter()
                .any(|l| l.contains("deb-systemd-helper update-state \"$unit\""))
        );
        assert!(
            code.iter()
                .any(|l| l.contains("deb-systemd-invoke start \"$unit\""))
        );
    }

    /// FR-96 P5 — prerm and postrm are the update half's bookkeeping only: the
    /// timer and the path stopped on removal (never on upgrade: the helper may
    /// be the process upgrading the package), masked on removal, purged and
    /// unmasked on purge. Like postinst, they never touch a daemon unit, and
    /// they ship as plain LF /bin/sh scripts.
    #[test]
    fn deb_prerm_and_postrm_touch_only_the_update_half() {
        for (name, s) in [
            ("prerm", include_str!("../packaging/linux/debian/prerm")),
            ("postrm", include_str!("../packaging/linux/debian/postrm")),
        ] {
            assert!(
                !s.contains('\r'),
                "{name} has CR bytes — dpkg cannot run it"
            );
            assert!(
                s.starts_with("#!/bin/sh\n"),
                "{name}: a plain /bin/sh shebang"
            );
            for line in s.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
                for daemon in ["meshharbord.service", "meshharbor.service"] {
                    assert!(
                        !line.contains(daemon),
                        "{name} must not act on `{daemon}`: {line}"
                    );
                }
                assert!(
                    !line.contains("restart"),
                    "{name} must not restart anything: {line}"
                );
            }
        }
        let prerm = include_str!("../packaging/linux/debian/prerm");
        assert!(
            prerm.contains("[ \"$1\" = remove ]"),
            "prerm stops on removal only"
        );
        assert!(prerm.contains("deb-systemd-invoke stop meshharbor-update.timer meshharbor-update.path"));
        let postrm = include_str!("../packaging/linux/debian/postrm");
        assert!(postrm.contains("deb-systemd-helper mask \"$unit\""));
        assert!(postrm.contains("deb-systemd-helper purge \"$unit\""));
        assert!(postrm.contains("deb-systemd-helper unmask \"$unit\""));
    }

    /// #2551 — a pump starts idle, an arm's guard names it, a refinement
    /// replaces the name, and the guard puts it back when it drops.
    #[test]
    fn a_stage_is_named_while_its_guard_lives() {
        let wd = Watchdog::new();
        wd.register("signaling", Duration::from_secs(90), true);
        assert_eq!(wd.stage_of("signaling").as_deref(), Some(IDLE_STAGE));
        {
            let _stage = wd.enter("signaling", "ws.text");
            assert_eq!(wd.stage_of("signaling").as_deref(), Some("ws.text"));
            wd.set_stage("signaling", format!("ws.text:{}", "rc:ssh.response"));
            assert_eq!(
                wd.stage_of("signaling").as_deref(),
                Some("ws.text:rc:ssh.response")
            );
        }
        assert_eq!(wd.stage_of("signaling").as_deref(), Some(IDLE_STAGE));
    }

    /// #2551 — an arm that leaves early (`continue` here) leaves no name
    /// behind, or a later stall in the select itself would be blamed on it.
    #[test]
    fn an_arm_that_leaves_early_leaves_no_stage_behind() {
        let wd = Watchdog::new();
        wd.register("signaling", Duration::from_secs(90), true);
        for round in 0..2 {
            let _stage = wd.enter("signaling", "outbound");
            if round == 0 {
                continue;
            }
        }
        assert_eq!(wd.stage_of("signaling").as_deref(), Some(IDLE_STAGE));
    }

    /// Like a tick, a stage on a pump nobody registered is dropped.
    #[test]
    fn an_unregistered_pump_keeps_no_stage() {
        let wd = Watchdog::new();
        wd.set_stage("nope", "keepalive");
        assert_eq!(wd.stage_of("nope"), None);
    }

    /// #2551 — the summary names each pump's stage after its `name=Ns`, which
    /// is unchanged, so a parser of the old summary still finds the pump.
    #[test]
    fn the_stall_summary_names_the_stage() {
        let one = [("signaling", Duration::from_secs(93))];
        assert_eq!(
            stall_summary(&one, |_| Some("ws.text:rc:ssh.response".into())),
            "signaling=93s@ws.text:rc:ssh.response"
        );
        assert_eq!(stall_summary(&one, |_| None), "signaling=93s");
        assert_eq!(
            stall_summary(&one, |_| Some(String::new())),
            "signaling=93s"
        );
        let two = [
            ("encoder", Duration::from_secs(31)),
            ("signaling", Duration::from_secs(104)),
        ];
        let s = stall_summary(&two, |n| {
            (n == "signaling").then(|| "heartbeat".to_string())
        });
        assert_eq!(s, "encoder=31s, signaling=104s@heartbeat");
        let pumps: Vec<&str> = s
            .split(", ")
            .map(|p| p.split('=').next().unwrap())
            .collect();
        assert_eq!(pumps, ["encoder", "signaling"]);
    }

    /// #2551 — end to end on one watchdog: a pump that froze inside an arm is
    /// reported stalled, with that arm's name.
    #[test]
    fn a_frozen_arm_is_named_in_the_stall_it_causes() {
        let wd = Watchdog::new();
        wd.register("signaling", Duration::from_secs(90), true);
        let _frozen = wd.enter("signaling", "device_end");
        let stalled = wd.scan_at(Instant::now() + Duration::from_secs(100));
        assert_eq!(stalled.len(), 1);
        let summary = stall_summary(&stalled, |n| wd.stage_of(n));
        assert!(summary.starts_with("signaling="), "{summary}");
        assert!(summary.ends_with("s@device_end"), "{summary}");
    }
}
