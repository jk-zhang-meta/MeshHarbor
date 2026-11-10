// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D6 — open the desktop companion ONCE after a fresh install.
//!
//! Every install path ends with the daemon starting (the MSI's service
//! start, `install.ps1`'s restart, the wizard, `install.sh`'s `systemctl
//! enable --now`), so the daemon is the one place that covers them all. What
//! it must never do is the opposite failure: resurrect a companion a person
//! quit. So the launch is guarded by a MARKER in the daemon's own data dir —
//! written BEFORE the spawn, and never again once written — and by a
//! fresh-install test (`last_known_good_version` is unset until a daemon has
//! run healthily for five minutes, so an UPGRADED install is adopted, not
//! launched into).
//!
//! This module holds the decision (pure, table-tested) and the marker
//! handling; `super::launch_once_after_install` drives it with real facts.
//!
//! macOS compiles the decision but never drives it — the `.pkg`'s LaunchAgent
//! already opens the companion after install and at login — hence the
//! dead-code allowance there and only there.
#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::path::Path;

/// The marker's file name, in the launcher's data dir.
pub(crate) const MARKER_FILE: &str = "companion-first-launch.json";

/// What the launcher can see at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LaunchFacts {
    /// The marker exists: this install's launch was already decided.
    pub marker_present: bool,
    /// The device's `companion_autostart` (ON when no config is readable).
    pub autostart_enabled: bool,
    /// A config is readable — the device is enrolled.
    pub enrolled: bool,
    /// No daemon had run healthily on this install before this start
    /// (latched at the first config seen; see [`FreshLatch`]).
    pub fresh_install: bool,
    /// The companion executable is installed.
    pub companion_present: bool,
    /// An interactive user session exists to open it in.
    pub session: bool,
    /// The companion is already running in that session.
    pub companion_running: bool,
}

/// Why the launcher is still waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitReason {
    /// No config yet (the wizard enrolls after its MSI starts the service).
    NotEnrolled,
    /// No companion yet (`install.sh` installs its .deb after the daemon's).
    NoCompanion,
    /// Nobody is logged on; the login autostart covers them later.
    NoSession,
}

/// What to do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaunchDecision {
    /// The marker exists — nothing, ever again, for this install.
    AlreadyDecided,
    /// `companion_autostart = false` — nothing, and no marker either.
    Disabled,
    /// An install that ran before this daemon: record the decision, launch
    /// nothing (an upgrade must not pop the companion up, and must not bring
    /// back one that was quit).
    Adopt,
    /// Someone already has it open: record the decision, launch nothing.
    RecordRunning,
    /// Not yet; look again shortly.
    Wait(WaitReason),
    /// Write the marker, then open the Welcome.
    Launch,
}

/// The decision, cheapest facts first. The ORDER is the policy:
///
/// 1. a marker ends it, whatever else is true — the one-shot guarantee;
/// 2. the device switch ends it without a marker (turned back on, a later
///    fresh start may still launch);
/// 3. nothing is known about an install with no config, so wait;
/// 4. an install that ran before is adopted — never launched into;
/// 5. then the companion, a session, and whether it is already up.
pub(crate) fn decide(f: &LaunchFacts) -> LaunchDecision {
    use LaunchDecision::*;
    if f.marker_present {
        return AlreadyDecided;
    }
    if !f.autostart_enabled {
        return Disabled;
    }
    if !f.enrolled {
        return Wait(WaitReason::NotEnrolled);
    }
    if !f.fresh_install {
        return Adopt;
    }
    if !f.companion_present {
        return Wait(WaitReason::NoCompanion);
    }
    if !f.session {
        return Wait(WaitReason::NoSession);
    }
    if f.companion_running {
        return RecordRunning;
    }
    Launch
}

/// Freshness is decided ONCE, at the first config the launcher sees, and
/// then held: the daemon it is part of promotes `last_known_good_version`
/// after five healthy minutes, and a fresh install that is still waiting for
/// its companion at that point must not flip to "upgrade".
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FreshLatch(Option<bool>);

impl FreshLatch {
    /// Observe a config's `last_known_good_version.is_none()`; the first
    /// observation sticks.
    pub(crate) fn observe(&mut self, lkgv_unset: bool) -> bool {
        *self.0.get_or_insert(lkgv_unset)
    }
}

/// How writing the marker and launching went.
#[derive(Debug)]
pub(crate) enum LaunchOutcome {
    Launched,
    /// The marker was already there — someone else decided first.
    AlreadyDecided,
    /// The marker could not be written: NOTHING was launched.
    MarkerFailed(String),
    /// The marker was written but the spawn failed; the marker is released
    /// again so a later look — or a later start — can try (nobody saw a
    /// window, so there is nothing to "resurrect").
    SpawnFailed(String),
}

/// Record `outcome` in the marker at `path` without launching anything
/// (the `Adopt` / `RecordRunning` decisions). `Ok(false)` = it already
/// existed.
pub(crate) fn record(path: &Path, outcome: &str) -> std::io::Result<bool> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // `create_new` is the arbiter: two launchers racing (a daemon restarted
    // mid-poll) cannot both win it, so they cannot both launch.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut f) => {
            let at_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let body = serde_json::json!({
                "outcome": outcome,
                "at_unix": at_unix,
                "version": env!("CARGO_PKG_VERSION"),
            });
            f.write_all(body.to_string().as_bytes())?;
            f.sync_all()?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Write the marker FIRST, then `spawn` — and never `spawn` when the write
/// fails or the marker already exists.
pub(crate) fn launch_behind_marker(
    path: &Path,
    spawn: impl FnOnce() -> anyhow::Result<()>,
) -> LaunchOutcome {
    match record(path, "launched") {
        Ok(true) => {}
        Ok(false) => return LaunchOutcome::AlreadyDecided,
        Err(e) => return LaunchOutcome::MarkerFailed(e.to_string()),
    }
    match spawn() {
        Ok(()) => LaunchOutcome::Launched,
        Err(e) => {
            // Nobody saw a window; release the marker so a later start can
            // try again. Best-effort — a marker we cannot remove just means
            // the login start covers this person instead.
            let _ = std::fs::remove_file(path);
            LaunchOutcome::SpawnFailed(format!("{e:#}"))
        }
    }
}

// ─── the driver ─────────────────────────────────────────────────────────────

/// How long after the daemon starts the launcher keeps looking. Long enough
/// for `install.sh` to install the companion .deb (and its webkit/GTK
/// dependencies) after the daemon's, and for the wizard to enroll after its
/// MSI started the service; after that the login start is the path.
const LAUNCH_WINDOW: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// Between looks. Every look is a few stats and, only when everything else is
/// ready, one process listing.
const POLL: std::time::Duration = std::time::Duration::from_secs(3);
/// After a spawn that FAILED (the marker was released): a transient cause —
/// a profile still loading at logon, `CreateEnvironmentBlock` refusing — gets
/// another try inside the window, at a pace that does not flood the log.
const RETRY_AFTER_SPAWN_FAILURE: std::time::Duration = std::time::Duration::from_secs(15);

/// Who runs the launch, and what it knows.
pub enum LaunchOwner {
    /// The Windows SCM service host (LocalSystem, session 0) — the perMachine
    /// launcher. It reads the config the worker uses (machine-global, else
    /// the console user's), writes its marker under `%PROGRAMDATA%`, and
    /// launches through `WTSQueryUserToken` + `CreateProcessAsUserW`: the
    /// console user's own, NON-elevated token, even when that user's worker
    /// runs elevated.
    #[cfg(target_os = "windows")]
    ScmHost,
    /// The daemon worker — the per-user Scheduled Task on Windows, the systemd
    /// unit on Linux — with what it read from its own config at start. The
    /// marker lives next to that config.
    Worker {
        config_path: std::path::PathBuf,
        companion_autostart: bool,
        lkgv_unset: bool,
    },
}

/// One look: the decision, the marker it concerns, and what was done.
struct Step {
    decision: LaunchDecision,
    facts: LaunchFacts,
    marker: std::path::PathBuf,
    /// Set when the step acted (`Adopt`, `RecordRunning`, `Launch`).
    note: Option<String>,
    /// The launch was attempted and FAILED, releasing the marker: look again.
    retry: bool,
}

/// Run the launcher to its end: a launch, a recorded decision, the kill
/// switch, or the window running out. Never fails the caller; every path
/// logs.
pub async fn run(owner: LaunchOwner) {
    #[cfg(target_os = "macos")]
    {
        // The .pkg's postinstall bootstraps the LaunchAgent (RunAtLoad), which
        // opens the companion after install and at every login already; a
        // second launcher would race it.
        let _ = owner;
        tracing::debug!("companion launch-once: macOS — the package's LaunchAgent does this");
    }
    #[cfg(not(target_os = "macos"))]
    {
        let owner = std::sync::Arc::new(owner);
        let started = std::time::Instant::now();
        let mut fresh = FreshLatch::default();
        let mut last: Option<LaunchDecision> = None;
        loop {
            let o = owner.clone();
            let joined = tokio::task::spawn_blocking(move || {
                let mut f = fresh;
                let step = step(&o, &mut f);
                (step, f)
            })
            .await;
            let Ok((step, latch)) = joined else {
                tracing::warn!("companion launch-once: the check panicked; giving up this start");
                return;
            };
            fresh = latch;
            if last != Some(step.decision) || step.note.is_some() {
                log_step(&step);
                last = Some(step.decision);
            }
            let pause = match step.decision {
                LaunchDecision::Wait(_) => POLL,
                LaunchDecision::Launch if step.retry => RETRY_AFTER_SPAWN_FAILURE,
                _ => return,
            };
            if started.elapsed() >= LAUNCH_WINDOW {
                tracing::info!(
                    decision = ?step.decision,
                    "companion launch-once: gave up — the login start covers it"
                );
                return;
            }
            tokio::time::sleep(pause).await;
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn log_step(step: &Step) {
    let marker = step.marker.display();
    match (step.decision, step.note.as_deref()) {
        (LaunchDecision::AlreadyDecided, _) => {
            tracing::debug!(%marker, "companion launch-once: already decided for this install")
        }
        (LaunchDecision::Disabled, _) => tracing::info!(
            "companion launch-once: companion_autostart is off — not opening the companion"
        ),
        (LaunchDecision::Wait(reason), _) => {
            tracing::info!(?reason, facts = ?step.facts, "companion launch-once: waiting")
        }
        (decision, Some(note)) => {
            tracing::info!(?decision, %marker, %note, "companion launch-once")
        }
        (decision, None) => tracing::info!(?decision, %marker, "companion launch-once"),
    }
}

/// What acting on a decision did.
#[cfg(not(target_os = "macos"))]
struct Acted {
    note: Option<String>,
    /// A launch was attempted and failed; the marker is released.
    retry: bool,
}

/// Act on a terminal decision: record it, or launch behind the marker.
#[cfg(not(target_os = "macos"))]
fn act(
    decision: LaunchDecision,
    marker: &Path,
    spawn: impl FnOnce() -> anyhow::Result<()>,
) -> Acted {
    let recorded = |outcome: &str| match record(marker, outcome) {
        Ok(true) => format!("recorded: {outcome}"),
        Ok(false) => "already recorded".to_string(),
        Err(e) => format!("could not record {outcome}: {e}"),
    };
    let done = |note: String| Acted {
        note: Some(note),
        retry: false,
    };
    match decision {
        LaunchDecision::Adopt => done(recorded("adopted")),
        LaunchDecision::RecordRunning => done(recorded("already_running")),
        LaunchDecision::Launch => match launch_behind_marker(marker, spawn) {
            LaunchOutcome::Launched => done("launched the companion with --first-run".into()),
            LaunchOutcome::AlreadyDecided => done("another launcher decided first".into()),
            LaunchOutcome::MarkerFailed(e) => {
                done(format!("marker not written ({e}) — launching NOTHING"))
            }
            LaunchOutcome::SpawnFailed(e) => Acted {
                note: Some(format!(
                    "spawn failed ({e}) — marker released; trying again shortly"
                )),
                retry: true,
            },
        },
        _ => Acted {
            note: None,
            retry: false,
        },
    }
}

#[cfg(not(target_os = "macos"))]
fn step(owner: &LaunchOwner, fresh: &mut FreshLatch) -> Step {
    match owner {
        #[cfg(target_os = "windows")]
        LaunchOwner::ScmHost => windows::step_scm_host(fresh),
        LaunchOwner::Worker {
            config_path,
            companion_autostart,
            lkgv_unset,
        } => {
            let marker = config_path
                .parent()
                .map(|d| d.join(MARKER_FILE))
                .unwrap_or_else(|| std::path::PathBuf::from(MARKER_FILE));
            let facts = LaunchFacts {
                marker_present: marker.exists(),
                autostart_enabled: *companion_autostart,
                // The worker only runs with a config, so it is enrolled.
                enrolled: true,
                fresh_install: fresh.observe(*lkgv_unset),
                ..LaunchFacts::default()
            };
            worker_step(facts, marker)
        }
    }
}

/// Finish a worker look: fill the platform facts only as far as the decision
/// needs them (the process listing last), then act.
#[cfg(not(target_os = "macos"))]
fn worker_step(facts: LaunchFacts, marker: std::path::PathBuf) -> Step {
    // The config-only facts first; the platform probes only when those alone
    // would launch.
    let pre = decide(&LaunchFacts {
        companion_present: true,
        session: true,
        ..facts
    });
    let (facts, decision, acted) = if matches!(pre, LaunchDecision::Launch) {
        platform_worker_launch(facts, &marker)
    } else {
        (facts, pre, act(pre, &marker, || Ok(())))
    };
    Step {
        decision,
        facts,
        marker,
        note: acted.note,
        retry: acted.retry,
    }
}

#[cfg(target_os = "windows")]
fn platform_worker_launch(
    facts: LaunchFacts,
    marker: &Path,
) -> (LaunchFacts, LaunchDecision, Acted) {
    windows::worker_launch(facts, marker)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_worker_launch(
    facts: LaunchFacts,
    marker: &Path,
) -> (LaunchFacts, LaunchDecision, Acted) {
    linux::worker_launch(facts, marker)
}

#[cfg(target_os = "windows")]
pub(crate) use windows::scm_worker_config;

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use crate::companion::{DESKTOP_EXE, desktop_running_in_session};
    use crate::win_service::{companion_spawn, supervisor};
    use meshharbor_node_core::companion_autostart::FIRST_RUN_ARG;

    fn sibling_companion() -> Option<std::path::PathBuf> {
        let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
        Some(dir.join(DESKTOP_EXE))
    }

    /// The config the worker on this machine uses, as the SCM host can read
    /// it: the machine-global one (SystemContext), else the console user's
    /// (plain perMachine). `None` = not enrolled yet, or not readable.
    pub(crate) fn scm_worker_config(
        token: Option<&supervisor::OwnedHandle>,
    ) -> Option<crate::config::AgentConfig> {
        if let Some(cfg) =
            crate::config::read_if_present(&crate::config::machine_global_config_path())
        {
            return Some(cfg);
        }
        let token = token?;
        // SAFETY: a live WTSQueryUserToken token, held for the call.
        let roaming = unsafe { companion_spawn::roaming_app_data_for_token(token.raw()) }?;
        let path = roaming
            .join("meshharbor")
            .join("meshharbor")
            .join("config")
            .join("config.toml");
        crate::config::read_if_present(&path)
    }

    pub(super) fn step_scm_host(fresh: &mut FreshLatch) -> Step {
        let marker = meshharbor_node_core::appdirs::machine_global_dir().join(MARKER_FILE);
        if marker.exists() {
            return Step {
                decision: LaunchDecision::AlreadyDecided,
                facts: LaunchFacts {
                    marker_present: true,
                    ..LaunchFacts::default()
                },
                marker,
                note: None,
                retry: false,
            };
        }
        let session = supervisor::active_console_session_id();
        let token = session.and_then(|sid| supervisor::query_user_token(sid).ok().flatten());
        let cfg = scm_worker_config(token.as_ref());
        let exe = sibling_companion();
        let mut facts = LaunchFacts {
            marker_present: false,
            autostart_enabled: cfg.as_ref().is_none_or(|c| c.companion_autostart),
            enrolled: cfg.is_some(),
            fresh_install: cfg
                .as_ref()
                .is_none_or(|c| fresh.observe(c.last_known_good_version.is_none())),
            companion_present: exe.as_ref().is_some_and(|p| p.exists()),
            session: token.is_some(),
            companion_running: false,
        };
        // The EXE may appear mid-install (the wizard places it after
        // enrolling): keep the machine's Run value in step while waiting.
        if facts.companion_present {
            crate::companion::sync_machine_autostart_logged(facts.autostart_enabled);
        }
        let mut decision = decide(&facts);
        if let (LaunchDecision::Launch, Some(sid)) = (decision, session) {
            facts.companion_running = desktop_running_in_session(sid);
            decision = decide(&facts);
        }
        let acted = act(decision, &marker, || {
            let (Some(token), Some(exe)) = (token.as_ref(), exe.as_ref()) else {
                anyhow::bail!("no user token or companion path");
            };
            // SAFETY: `token` is a live user token from WTSQueryUserToken,
            // held for the duration of the call. `spawn_in_session` passes
            // bInheritHandles = FALSE and attaches winsta0\default.
            let child =
                unsafe { supervisor::spawn_in_session(token.raw(), exe, &[FIRST_RUN_ARG]) }?;
            tracing::info!(
                pid = child.pid,
                "companion launch-once: started in the console session"
            );
            Ok(())
        });
        Step {
            decision,
            facts,
            marker,
            note: acted.note,
            retry: acted.retry,
        }
    }

    pub(super) fn worker_launch(
        mut facts: LaunchFacts,
        marker: &Path,
    ) -> (LaunchFacts, LaunchDecision, Acted) {
        let exe = sibling_companion();
        facts.companion_present = exe.as_ref().is_some_and(|p| p.exists());
        // Session 0 is services' session: nothing there is visible.
        let sid = companion_spawn::own_session_id().filter(|s| *s != 0);
        facts.session = sid.is_some();
        let mut decision = decide(&facts);
        if let (LaunchDecision::Launch, Some(sid)) = (decision, sid) {
            facts.companion_running = desktop_running_in_session(sid);
            decision = decide(&facts);
        }
        let acted = act(decision, marker, || {
            let exe = exe
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no companion path"))?;
            let pid = companion_spawn::spawn_detached_no_inherit(exe, &[FIRST_RUN_ARG])?;
            tracing::info!(pid, "companion launch-once: started (no inherited handles)");
            Ok(())
        });
        (facts, decision, acted)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux {
    use super::*;
    use meshharbor_node_core::companion_autostart::FIRST_RUN_ARG;

    pub(super) fn worker_launch(
        mut facts: LaunchFacts,
        marker: &Path,
    ) -> (LaunchFacts, LaunchDecision, Acted) {
        let exe = crate::companion::linux_companion_path();
        facts.companion_present = exe.is_some();
        // A root daemon opens it in whoever's graphical session is active; a
        // per-user daemon only in its own user's.
        // SAFETY: geteuid reads our own credentials.
        let euid = unsafe { libc::geteuid() };
        let want_uid = (euid != 0).then_some(euid);
        // `Class=user` only: never into a display manager's greeter.
        let sess = crate::companion::graphical_session_matching(want_uid, true).ok();
        facts.session = sess.is_some();
        let mut decision = decide(&facts);
        if let (LaunchDecision::Launch, Some(s)) = (decision, sess.as_ref()) {
            facts.companion_running = crate::companion::companion_running_for_uid(s.uid);
            decision = decide(&facts);
        }
        let acted = act(decision, marker, || {
            let (Some(exe), Some(s)) = (exe.as_ref(), sess.as_ref()) else {
                anyhow::bail!("no companion path or graphical session");
            };
            let out = crate::companion::systemd_run_command(s, exe, &[FIRST_RUN_ARG], euid != 0)
                .output()
                .map_err(|e| anyhow::anyhow!("spawning systemd-run: {e}"))?;
            if !out.status.success() {
                anyhow::bail!(
                    "systemd-run failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Ok(())
        });
        (facts, decision, acted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Everything true for a launch.
    fn ready() -> LaunchFacts {
        LaunchFacts {
            marker_present: false,
            autostart_enabled: true,
            enrolled: true,
            fresh_install: true,
            companion_present: true,
            session: true,
            companion_running: false,
        }
    }

    #[test]
    fn decision_table() {
        use LaunchDecision::*;
        use WaitReason::*;
        let r = ready();
        let table: &[(&str, LaunchFacts, LaunchDecision)] = &[
            ("all set", r, Launch),
            (
                "the marker wins over everything (a quit companion stays quit)",
                LaunchFacts {
                    marker_present: true,
                    ..r
                },
                AlreadyDecided,
            ),
            (
                "marker + kill switch",
                LaunchFacts {
                    marker_present: true,
                    autostart_enabled: false,
                    ..r
                },
                AlreadyDecided,
            ),
            (
                "kill switch",
                LaunchFacts {
                    autostart_enabled: false,
                    ..r
                },
                Disabled,
            ),
            (
                "kill switch beats waiting",
                LaunchFacts {
                    autostart_enabled: false,
                    enrolled: false,
                    ..r
                },
                Disabled,
            ),
            (
                "not enrolled yet",
                LaunchFacts {
                    enrolled: false,
                    ..r
                },
                Wait(NotEnrolled),
            ),
            (
                "an upgrade is adopted, not launched into",
                LaunchFacts {
                    fresh_install: false,
                    ..r
                },
                Adopt,
            ),
            (
                "an upgrade is adopted even with nobody logged on",
                LaunchFacts {
                    fresh_install: false,
                    session: false,
                    companion_present: false,
                    ..r
                },
                Adopt,
            ),
            (
                "the companion is not installed yet",
                LaunchFacts {
                    companion_present: false,
                    ..r
                },
                Wait(NoCompanion),
            ),
            (
                "nobody is logged on: no marker, the login start covers it",
                LaunchFacts {
                    session: false,
                    ..r
                },
                Wait(NoSession),
            ),
            (
                "already open: record, do not launch a second",
                LaunchFacts {
                    companion_running: true,
                    ..r
                },
                RecordRunning,
            ),
        ];
        for (why, facts, want) in table {
            assert_eq!(decide(facts), *want, "{why}: {facts:?}");
        }
    }

    #[test]
    fn freshness_is_latched_at_the_first_observation() {
        let mut fresh = FreshLatch::default();
        assert!(fresh.observe(true), "no healthy run yet ⇒ fresh");
        assert!(
            fresh.observe(false),
            "the daemon's own five-minute promotion must not turn a waiting fresh install into an upgrade"
        );
        let mut upgrade = FreshLatch::default();
        assert!(!upgrade.observe(false));
        assert!(!upgrade.observe(true));
    }

    #[test]
    fn the_marker_is_written_before_the_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(MARKER_FILE);
        let spawned = Cell::new(false);
        let out = launch_behind_marker(&marker, || {
            assert!(
                marker.exists(),
                "the marker must exist before anything is launched"
            );
            spawned.set(true);
            Ok(())
        });
        assert!(matches!(out, LaunchOutcome::Launched), "{out:?}");
        assert!(spawned.get());
        let raw = std::fs::read_to_string(&marker).unwrap();
        assert!(raw.contains("\"launched\""), "{raw}");
    }

    #[test]
    fn a_failed_marker_write_launches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        // The marker's parent is a regular FILE, so the write must fail.
        let not_a_dir = dir.path().join("plain-file");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let marker = not_a_dir.join(MARKER_FILE);
        let spawned = Cell::new(false);
        let out = launch_behind_marker(&marker, || {
            spawned.set(true);
            Ok(())
        });
        assert!(matches!(out, LaunchOutcome::MarkerFailed(_)), "{out:?}");
        assert!(!spawned.get(), "no marker ⇒ no launch");
    }

    #[test]
    fn an_existing_marker_launches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(MARKER_FILE);
        std::fs::write(&marker, b"{}").unwrap();
        let spawned = Cell::new(false);
        let out = launch_behind_marker(&marker, || {
            spawned.set(true);
            Ok(())
        });
        assert!(matches!(out, LaunchOutcome::AlreadyDecided), "{out:?}");
        assert!(!spawned.get());
    }

    #[test]
    fn a_failed_spawn_releases_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(MARKER_FILE);
        let marker_seen = Cell::new(false);
        let out = launch_behind_marker(&marker, || {
            marker_seen.set(marker.exists());
            anyhow::bail!("no such file")
        });
        assert!(matches!(out, LaunchOutcome::SpawnFailed(_)), "{out:?}");
        assert!(
            marker_seen.get(),
            "the spawn was attempted behind a written marker"
        );
        assert!(
            !marker.exists(),
            "nobody saw a window: a later start may try again"
        );
    }

    #[test]
    fn record_writes_once() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("sub").join(MARKER_FILE);
        assert!(record(&marker, "adopted").unwrap(), "first record writes");
        assert!(
            !record(&marker, "already_running").unwrap(),
            "the first decision stands"
        );
        let raw = std::fs::read_to_string(&marker).unwrap();
        assert!(raw.contains("\"adopted\""), "{raw}");
    }
}
