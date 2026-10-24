// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Self-update from the enrolled center or an explicitly selected HTTPS feed.
//!
//! No implicit upstream fallback. Release/download URL boundaries are checked
//! before I/O; the existing digest, publisher/signature and artifact-version
//! checks remain mandatory where they were mandatory before. An unavailable
//! trusted release leaves the currently installed product running.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tunnel_core::env::node_env;

#[path = "updater_origin.rs"]
mod origin;

/// Unenrolled MeshHarbor fallback only; enrolled/custom centers retain their prefix.
pub const DEFAULT_PROXY_URL: &str = "https://www.itachi.fans/meshharbor/api/agent/latest-release";

static UPDATE_CONFIG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Bind the binary's already-resolved --config path. No second config/account store.
pub fn set_update_config_path(path: PathBuf) -> Result<()> {
    if let Some(existing) = UPDATE_CONFIG_PATH.get() {
        if existing != &path {
            bail!("update config path already bound");
        }
    } else if UPDATE_CONFIG_PATH.set(path).is_err() {
        bail!("update config path binding raced");
    }
    Ok(())
}

fn update_origin() -> Result<origin::UpdateOrigin> {
    #[derive(Deserialize)]
    struct Center {
        server_url: String,
    }
    let center = match UPDATE_CONFIG_PATH.get() {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(raw) => Some(
                toml::from_str::<Center>(&raw)
                    .map_err(|_| {
                        anyhow::anyhow!("resolved update config is malformed or missing server_url")
                    })?
                    .server_url,
            ),
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && path
                        .symlink_metadata()
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(e) => return Err(e).context("reading resolved update config"),
        },
        None => None,
    };
    origin::UpdateOrigin::resolve(
        center.as_deref().unwrap_or(origin::DEFAULT_CENTER_URL),
        node_env("UPDATE_URL").as_deref(),
        node_env("UPDATE_ASSET_BASE_URL").as_deref(),
    )
    .map_err(anyhow::Error::msg)
}

fn update_redirect_policy(origin: origin::UpdateOrigin, asset: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if origin.permits_redirect(attempt.url().as_str(), asset, attempt.previous().len()) {
            attempt.follow()
        } else {
            attempt.error("update redirect escaped its explicit origin/prefix or redirect budget")
        }
    })
}

/// How often `run_periodic` wakes up and checks for a newer release.
///
/// A5 (2026-08-02): 24 h → **4 h**. The 24 h default was the fleet's
/// wedge-heal ceiling: an agent whose control WS was wedged/split missed
/// the server-pushed `rc:agent.update` (it rides that WS) and then sat
/// broken for up to a day (field: winhost-a/winhost-b ran a 4-day-old build
/// through the S6 split because their next check was hours away). The
/// original 24 h choice guarded GitHub's 60-req/IP/h unauthenticated
/// quota (field 2026-04-27: 8 MSI installs across 5 NAT'd boxes hit 403)
/// — the enrolled center now owns that cache/channel. There is no automatic
/// fallback to another publisher. Operators tune the same cadence through
/// `update_check_interval_h` / `ROOMLERD_UPDATE_INTERVAL_H`.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(4 * 3600);

/// Minimum download size before we trust an installer artifact. A
/// GitHub redirect to a deleted asset returns a tiny HTML page; this
/// guards against running that as an installer.
pub const MIN_INSTALLER_BYTES: usize = 1_000_000;

/// At-startup update-check cooldown. If we last spawned an installer
/// within this window, skip the immediate `check_once` and proceed
/// straight to the periodic interval. Prevents the install-storm
/// failure mode found on host `operator` (2026-05-02): SCM service
/// supervisor + auto-updater + freshly-downloaded MSI = each newly
/// spawned worker re-detects the same pending update, fires another
/// installer, exits clean (code=0), supervisor respawns, repeat. The
/// 0.1.61 supervisor patch (code=0 -> immediate respawn, no backoff)
/// makes the cycle tighter (~1.5 s per turn). 5 minutes is more than
/// enough headroom for a Win11 MSI to land + the new binary to start
/// up + reach the clean-run threshold.
pub const STARTUP_UPDATE_COOLDOWN: Duration = Duration::from_secs(300);

/// rc.19: short-cycle interval when the auto-updater defers because
/// file transfers are in flight. Keeps checking every hour so the
/// install fires shortly after the operator's last upload completes,
/// without waiting the full 24h CHECK_INTERVAL between checks.
pub const TRANSFER_DEFER_RECHECK: Duration = Duration::from_secs(3600);

/// rc.19: max number of consecutive defers before the auto-updater
/// fires anyway. Prevents a power-user who uploads every few hours
/// from indefinitely delaying security patches. 7 consecutive
/// defers at 1h cadence = ~7h max delay window (after the original
/// 24h interval elapsed); 7 at 24h = ~7 days.
pub const MAX_CONSECUTIVE_DEFERS: u32 = 7;

/// R5b — the network moved within this window ⇒ defer the periodic
/// update. An install restarts the daemon, which forfeits every
/// ESTABLISHED (grandfathered) flow — and on a corp path that
/// blackholes fresh TLS, a restart adjacent to a VPN transition locks
/// the machine out until the next transition (field 2026-08-16: both
/// control WSs RST at capture; only established flows rode through).
pub const NET_TRANSITION_WINDOW: Duration = Duration::from_secs(600);

/// R5b — short-cycle recheck while net-transition-deferred (the
/// transition settles in minutes, unlike an operator's upload session).
/// With the shared MAX_CONSECUTIVE_DEFERS cap the worst added delay is
/// ~14 min before the update forces through.
pub const NET_DEFER_RECHECK: Duration = Duration::from_secs(120);

/// #1755 — how soon a check that failed on the TRANSPORT runs again, by
/// consecutive failure; past the end of the table, the periodic interval.
/// Field: a machine used a few hours a day checks at boot, before its network
/// is up (a DNS failure one day, an asset download timing out the next). Each
/// failure cost the full interval, and it fell three releases behind while
/// online every day. A VERDICT (up to date, a draft, no installer for this
/// platform, a digest/signature/version refusal, an HTTP status such as
/// GitHub's 403 rate limit) keeps the full interval, so a bad release or a
/// spent quota is never hammered.
pub const TRANSPORT_RETRY: [Duration; 3] = [
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
];

/// The wait after `consecutive` transport failures in a row (1-based), never
/// longer than the periodic `interval`. Pure — tested directly.
pub fn transport_retry_after(consecutive: u32, interval: Duration) -> Duration {
    let step = TRANSPORT_RETRY
        .get(consecutive.saturating_sub(1) as usize)
        .copied()
        .unwrap_or(interval);
    step.min(interval)
}

/// #1755 — whether a fetch/download error is the transport failing (DNS,
/// connect, a timeout, a body cut off mid-download) rather than a verdict.
/// Typed: every HTTP call here fails with a `reqwest::Error` under `anyhow`
/// context, so this walks the chain for one — never the message text. An HTTP
/// STATUS is a verdict (`bail!`ed, not a `reqwest::Error`).
pub fn is_transport_failure(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|r| r.is_connect() || r.is_timeout() || r.is_request() || r.is_body())
    })
}

/// A failed fetch/download as its outcome: [`CheckOutcome::Unreachable`] when
/// the transport failed, else [`CheckOutcome::Skipped`].
fn failed(what: &str, e: anyhow::Error) -> CheckOutcome {
    let reason = format!("{what}: {e:#}");
    if is_transport_failure(&e) {
        CheckOutcome::Unreachable(reason)
    } else {
        CheckOutcome::Skipped(reason)
    }
}

/// #1755 — the periodic loop's bookkeeping after a check: a transport failure
/// extends the streak and returns the early recheck; any other outcome ends
/// the streak and leaves the normal cadence. Pure — tested directly.
pub fn recheck_after(
    outcome: &CheckOutcome,
    transport_failures: &mut u32,
    interval: Duration,
) -> Option<Duration> {
    if matches!(outcome, CheckOutcome::Unreachable(_)) {
        *transport_failures = transport_failures.saturating_add(1);
        Some(transport_retry_after(*transport_failures, interval))
    } else {
        *transport_failures = 0;
        None
    }
}

/// rc.19: gating decision for the periodic loop given the current
/// active-transfer count and consecutive-defer counter. Pure helper
/// so the gating logic is unit-testable without spinning the full
/// loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferDecision {
    /// Run the update check this cycle.
    Proceed,
    /// Skip this cycle; re-check in `TRANSFER_DEFER_RECHECK`.
    DeferOnce,
    /// Force the update through (consecutive defer limit reached).
    /// Logs warn at the call site.
    ForceAfterDefers,
}

/// Decide whether to gate the update check this cycle. Returns
/// `Proceed` when nothing gates (no transfers active, no fresh network
/// transition) OR the consecutive-defer limit has been reached. Pure /
/// no I/O — tested directly.
pub fn decide_defer(active: usize, net_transition: bool, consecutive_defers: u32) -> DeferDecision {
    if active == 0 && !net_transition {
        DeferDecision::Proceed
    } else if consecutive_defers >= MAX_CONSECUTIVE_DEFERS {
        DeferDecision::ForceAfterDefers
    } else {
        DeferDecision::DeferOnce
    }
}

/// FR-90 P1d-1 (AC7) — what the updater does about running agent turns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnWait {
    /// No turn running: go ahead.
    Proceed,
    /// Turns running and time left: wait.
    Wait,
    /// Turns still running after the whole wait: go ahead, cutting them.
    Cut,
}

/// Decide about `running` agent turns after `waited` of at most `max`. Pure
/// — tested directly. `max` zero cuts at once: the owner's choice.
pub fn decide_turn_wait(running: usize, waited: Duration, max: Duration) -> TurnWait {
    if running == 0 {
        TurnWait::Proceed
    } else if waited >= max {
        TurnWait::Cut
    } else {
        TurnWait::Wait
    }
}

/// How often the updater looks again while agent turns run.
const TURN_POLL: Duration = Duration::from_secs(5);
/// How often a deferral for agent turns is logged while it lasts.
const TURN_LOG_EVERY: Duration = Duration::from_secs(60);

/// The agent sessions mid-turn (ids), as the Hive supervisor sees them; none
/// in a build without agent sessions.
fn agent_turns_running() -> Vec<String> {
    #[cfg(hive_host)]
    {
        crate::hive::turns_running()
            .into_iter()
            .map(|s| s.to_hex())
            .collect()
    }
    #[cfg(not(hive_host))]
    {
        Vec::new()
    }
}

/// The device's `hive_update_wait_secs`; zero without agent sessions.
fn agent_turn_wait() -> Duration {
    #[cfg(hive_host)]
    {
        crate::hive::update_wait()
    }
    #[cfg(not(hive_host))]
    {
        Duration::ZERO
    }
}

/// Hold (or release) new agent prompts and starts around an install.
pub(crate) fn hold_agent_prompts(hold: bool) {
    #[cfg(hive_host)]
    {
        if hold {
            crate::hive::begin_update();
        } else {
            crate::hive::end_update();
        }
    }
    #[cfg(not(hive_host))]
    {
        let _ = hold;
    }
}

/// FR-90 P1d-1 (AC7) — wait for running agent turns before an installer
/// restarts the daemon, and with it every session's harness: at most the
/// device's `hive_update_wait_secs` (30 min by default), the deferral logged
/// when it starts and once a minute while it lasts. A turn is a person's work
/// in progress, so this holds a PUSHED update too — unlike a transfer — and
/// it is bounded, so a busy session cannot hold the device's updates back.
///
/// Once no turn runs, new prompts and starts are refused
/// ([`crate::hive::begin_update`]) BEFORE a last look, so none begins in the
/// gap; a prompt admitted before that still runs, and is waited for.
/// `false` = the daemon is shutting down instead.
pub(crate) async fn wait_for_agent_turns(
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    by: &'static str,
) -> bool {
    let max = agent_turn_wait();
    let started = Instant::now();
    let mut logged: Option<Instant> = None;
    let mut held = false;
    loop {
        let running = agent_turns_running();
        if running.is_empty() && !held {
            // Hold new prompts first, then look once more: a prompt that
            // arrived between the two looks began a turn to wait for.
            hold_agent_prompts(true);
            held = true;
            continue;
        }
        let waited = started.elapsed();
        match decide_turn_wait(running.len(), waited, max) {
            TurnWait::Proceed => {
                if logged.is_some() {
                    tracing::info!(
                        by,
                        waited_secs = waited.as_secs(),
                        "auto-updater: the agent turns are done — installing"
                    );
                }
                return true;
            }
            TurnWait::Cut => {
                hold_agent_prompts(true);
                tracing::warn!(
                    by,
                    waited_secs = waited.as_secs(),
                    turns = running.len(),
                    sessions = ?running,
                    "auto-updater: agent turns still running after the whole wait — installing anyway, which cuts them"
                );
                return true;
            }
            TurnWait::Wait => {
                if logged.is_none_or(|t| t.elapsed() >= TURN_LOG_EVERY) {
                    tracing::info!(
                        by,
                        turns = running.len(),
                        sessions = ?running,
                        waited_secs = waited.as_secs(),
                        max_secs = max.as_secs(),
                        "auto-updater: update deferred — agent turns running"
                    );
                    logged = Some(Instant::now());
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(TURN_POLL) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    hold_agent_prompts(false);
                    return false;
                }
            }
        }
    }
}

/// FR-90 P1h-2 (AC7 on macOS) — the daemon's half of the root update
/// helper's hold ([`tunnel_core::localapi::Request::HiveUpdateHold`]): the
/// wait above, then new prompts and starts held until
/// [`release_install_hold`]. On macOS the helper installs, never this
/// process, so this is the only wait there.
pub async fn hold_for_install(
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tunnel_core::localapi::Response {
    use tunnel_core::localapi::Response;
    if !cfg!(hive_host) {
        return Response::Error {
            message: "this build runs no agent sessions".into(),
        };
    }
    let started = Instant::now();
    if !wait_for_agent_turns(&mut shutdown, "update-helper").await {
        return Response::Error {
            message: "the daemon is stopping".into(),
        };
    }
    Response::HiveUpdateHeld {
        waited_secs: started.elapsed().as_secs(),
        cut: u32::try_from(agent_turns_running().len()).unwrap_or(u32::MAX),
    }
}

/// FR-90 P1h-2 — the helper's connection closed and this daemon is still
/// here, so its install did not happen: take prompts and starts again.
pub fn release_install_hold() {
    hold_agent_prompts(false);
    tracing::info!(
        "update-helper: the hold is released — agent prompts and starts are taken again"
    );
}

/// Work an installer would cut short: file transfers in flight, plus an
/// active screen recording (FR-85). An update restarts the daemon, and the
/// Windows installer's Restart Manager kills the recorder child outright
/// (it holds the image being replaced) — the partial survives and is
/// finalized `interrupted` later, but it is not the recording the person
/// was making. Same defer budget as a transfer: ≤ MAX_CONSECUTIVE_DEFERS.
pub(crate) fn active_work() -> usize {
    let transfers = crate::files::active_transfer_count();
    #[cfg(feature = "recording")]
    let recording = usize::from(crate::recording::manager::is_recording());
    #[cfg(not(feature = "recording"))]
    let recording = 0;
    transfers + recording
}

/// R5b — did a material MAJOR network change land inside
/// [`NET_TRANSITION_WINDOW`]? Feature-shaped: no-overlay builds have no
/// netstate and never defer on this input.
pub(crate) fn net_transition_recent() -> bool {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        tunnel_core::overlay::netstate::last_major_within(NET_TRANSITION_WINDOW)
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        false
    }
}

/// Marker file the agent touches *before* spawning the installer.
/// Path lives next to `last-install.json` so all update-related
/// state is in one directory and gets cleaned up by the same log-
/// retention policy. Returns `None` only when the platform doesn't
/// expose a data dir (very-stripped-down environments + tests
/// without `init()`).
pub fn update_attempt_marker_path() -> Option<PathBuf> {
    crate::logging::log_dir().map(|d| d.join("update-attempt"))
}

/// Touch the update-attempt marker. Call right before
/// `spawn_installer_inner` so the cooldown starts ticking from the
/// moment the installer process is launched. Best-effort: any I/O
/// failure is logged but does not block the update path (we'd
/// rather have a working install with a noisy crash counter than
/// no install at all).
fn record_update_attempt() {
    let Some(p) = update_attempt_marker_path() else {
        return;
    };
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&p, format!("{}\n", chrono::Utc::now().to_rfc3339())) {
        tracing::warn!(error = %e, path = %p.display(), "could not write update-attempt marker");
    }
}

/// Whether an update was attempted within the last `cooldown` seconds.
/// Read by `run_periodic` on its first iteration to suppress the
/// at-startup check when an install is already in flight.
fn recent_update_attempt(cooldown: Duration) -> bool {
    update_attempt_marker_path().is_some_and(|p| recent_update_attempt_at(&p, cooldown))
}

/// Inner pure-fn variant of `recent_update_attempt`. Takes the marker
/// path as an explicit argument so unit tests can drive it against a
/// `tempfile::TempDir` without depending on `logging::init()`.
fn recent_update_attempt_at(marker_path: &std::path::Path, cooldown: Duration) -> bool {
    let Ok(meta) = std::fs::metadata(marker_path) else {
        return false;
    };
    let Ok(mtime) = meta.modified() else {
        return false;
    };
    let elapsed = std::time::SystemTime::now()
        .duration_since(mtime)
        .unwrap_or_default();
    elapsed < cooldown
}

// ── FR-96 (#2055): the root update helper's run-spacing gate ─────────
// The Linux helper is woken by a world-writable wake path, so a local user can
// fire it as fast as they like. launchd throttles the macOS helper with
// `ThrottleInterval=60`; systemd's path unit has no equivalent that spaces
// rather than FAILS (its start/trigger limits are cliffs — see the unit file).
// So the helper spaces its OWN runs: a stamp in root's log dir, and a sleep for
// the remainder of the gap at the start of each run.

/// The least time between two update-helper runs — launchd's `ThrottleInterval`
/// (`com.roomler.update.plist`), made explicit for systemd. Locked to the plist
/// by `update_helper_min_gap_matches_launchd_throttle_interval`.
#[cfg(target_os = "linux")]
const UPDATE_HELPER_MIN_GAP: Duration = Duration::from_secs(60);

/// The helper's run-spacing stamp, beside `update-attempt` in the root-owned
/// log dir. Only root can write it, so no local user can shorten the gap.
#[cfg(target_os = "linux")]
fn update_helper_gate_marker_path() -> Option<PathBuf> {
    crate::logging::log_dir().map(|d| d.join("update-helper-run"))
}

/// How long this run must wait so runs are ≥ `min_gap` apart: the remainder of
/// the gap since `last`, or zero once it has passed.
///
/// ⚠️ No last run (`None`) or one in the FUTURE (a clock stepped back) means
/// the FULL gap — a missing or nonsensical stamp can only SLOW the helper,
/// never let it spin.
#[cfg(target_os = "linux")]
fn helper_gate_wait(
    last: Option<std::time::SystemTime>,
    now: std::time::SystemTime,
    min_gap: Duration,
) -> Duration {
    match last {
        Some(last) => match now.duration_since(last) {
            Ok(elapsed) => min_gap.saturating_sub(elapsed),
            Err(_) => min_gap, // `last` is in the future
        },
        None => min_gap,
    }
}

/// [`helper_gate_wait`] reading the stamp's mtime. ANY error reading it (absent,
/// unreadable, a non-directory in the path) yields the full gap — fail-safe.
#[cfg(target_os = "linux")]
fn helper_gate_wait_at(
    stamp: &std::path::Path,
    now: std::time::SystemTime,
    min_gap: Duration,
) -> Duration {
    let last = std::fs::metadata(stamp).and_then(|m| m.modified()).ok();
    helper_gate_wait(last, now, min_gap)
}

/// Record that the helper ran now, for the next run's [`helper_gate_wait`].
/// Best-effort like [`record_update_attempt`]; the caller logs a failure and
/// then the next run simply waits the full gap, which is safe.
#[cfg(target_os = "linux")]
fn stamp_helper_gate(stamp: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = stamp.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(stamp, format!("{}\n", chrono::Utc::now().to_rfc3339()))
}

/// What consuming the wake file did (FR-96), for the log line and the tests.
#[cfg(target_os = "linux")]
#[derive(Debug)]
enum WakeConsumed {
    /// Nothing was there.
    Nothing,
    /// A plain file — or a symlink, unlinked NOT followed — was removed.
    Removed,
    /// Something `unlink` refused (a planted directory) was moved aside into a
    /// fresh root-owned dir and removed there. `cleanup` is any error removing
    /// that dir afterwards; the move itself succeeded.
    MovedAside { cleanup: Option<std::io::Error> },
    /// The entry could be neither unlinked nor moved aside — e.g. a mount point
    /// (`EBUSY`) a local user planted with `fusermount3`. Logged; the helper
    /// continues. The wake path stays, so the service re-fires each gap, but
    /// the unit-level `StartLimitIntervalSec=0` + `Restart=` keep the PATH unit
    /// from failing.
    Stuck(std::io::Error),
}

/// Consume the wake file so `roomler-update.path`'s `PathExists=` turns false
/// and the unit returns to waiting.
///
/// `remove_file` never follows a symlink, so a planted link is unlinked, not
/// dereferenced. Anything `unlink` refuses — a planted DIRECTORY — is `rename`d
/// into a FRESH root-owned dir beside it (mkdtemp, so a local user cannot
/// pre-plant its name: a guessable `<wake>.<pid>` sibling could be planted
/// non-empty to make the rename fail) and removed there.
///
/// ⚠️ Why move-aside rather than leave it: `PathExists=` is level-triggered, so
/// an entry left at the path re-triggers the service the instant it ends — and
/// a helper that exits fast enough would hit the path unit's own trigger limit
/// and fail it. A local user must not be able to do that by planting one
/// directory.
#[cfg(target_os = "linux")]
fn consume_wake(wake: &std::path::Path) -> WakeConsumed {
    match std::fs::remove_file(wake) {
        Ok(()) => return WakeConsumed::Removed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return WakeConsumed::Nothing,
        Err(_) => {} // not an unlinkable file (a planted dir) — move it aside
    }
    let parent = wake
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/var/tmp"));
    let aside = match tempfile::Builder::new()
        .prefix(".roomler-update-check.aside.")
        .tempdir_in(parent)
    {
        Ok(d) => d,
        Err(e) => return WakeConsumed::Stuck(e),
    };
    match std::fs::rename(wake, aside.path().join("planted")) {
        Ok(()) => {
            let dir = aside.keep(); // ours to remove now; don't double-remove on Drop
            WakeConsumed::MovedAside {
                cleanup: std::fs::remove_dir_all(&dir).err(),
            }
        }
        // A mount point (EBUSY) or a race: `aside` drops and cleans itself (it
        // is empty); the entry stays, bounded by the unit-level guards above.
        Err(e) => WakeConsumed::Stuck(e),
    }
}

/// #1683 — how long after an installer was spawned a service stop is read as
/// **the installer's own stop**, not an operator's or the OS's.
///
/// On Windows the MSI always stops the `Roomler` service (a `StopServices`
/// standard action / the `RegisterService` CA's `delete_service`), and by then
/// the worker that spawned `msiexec` has already exited 0 and the SCM host has
/// respawned a fresh one. That fresh worker receives the stop as an
/// `os_initiated_stop` — the same arm a `sc stop` takes — so without this gate an
/// EPHEMERAL device would self-unenroll on every auto-update and the new version
/// would come up holding a dead token, exactly what FR-51 rules out ("the
/// internal arm is the updater restarting us; de-enrolling there would delete
/// the device on every update"). Linux never had this: `dpkg -i` does not
/// restart `roomlerd` at all.
///
/// 10 minutes because the MSI's stop can lag the spawn by minutes under EDR /
/// a slow host. The cost of a long window is small and fails safe: an operator
/// stop *inside* it leaves the ephemeral row to the server-side reaper — which
/// is today's behaviour on every Windows service host.
pub const UPDATE_STOP_WINDOW: Duration = Duration::from_secs(600);

/// #1683 — is an update in flight right now? True when this daemon (or the
/// worker this one replaced under the SCM host) spawned an installer within
/// [`UPDATE_STOP_WINDOW`]: `spawn_installer_with_watch` touches the
/// `update-attempt` marker right before it launches the installer, and the
/// rollback path goes through the same function. Platform-neutral.
pub fn update_in_flight() -> bool {
    recent_update_attempt(UPDATE_STOP_WINDOW)
}

/// #1683 — may an ephemeral device remove itself on this exit? Pure so the
/// whole policy is one table test. True ONLY for an ephemeral device, on an
/// OS/service-manager-initiated stop, with NO update in flight: the internal
/// arm (the updater restarting us) never unenrolls, and neither does the stop
/// the installer itself issues while it replaces the binary.
pub fn should_self_unenroll(
    ephemeral: bool,
    os_initiated_stop: bool,
    update_in_flight: bool,
) -> bool {
    ephemeral && os_initiated_stop && !update_in_flight
}

/// A parsed release from the GitHub API. Only the fields we need.
#[derive(Debug, Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub assets: Vec<GithubAsset>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub prerelease: bool,
}

#[derive(Debug, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    /// Kept in the wire deserialisation so future logic (e.g.
    /// comparing against a content-length header) can consult it.
    /// Not currently read by the in-loop path.
    #[serde(default)]
    #[allow(dead_code)]
    pub size: u64,
    /// GitHub Releases API exposes a `digest` field per asset of
    /// the form `"sha256:<hex>"` (added late 2024). When present,
    /// [`download_asset`] verifies the bytes' SHA256 against this
    /// hash and rejects mismatches. Absent on pre-2024 releases or
    /// when the proxy isn't forwarding it (older API server) — in
    /// that case we fall through to the [`MIN_INSTALLER_BYTES`]
    /// size floor as the only integrity gate.
    #[serde(default)]
    pub digest: Option<String>,
}

/// The outcome of a single check cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Running the latest (or newer) version; nothing to do.
    UpToDate { current: String, latest: String },
    /// Newer release found; installer downloaded to `installer_path`.
    /// Caller is responsible for spawning it and exiting.
    UpdateReady {
        current: String,
        latest: String,
        installer_path: PathBuf,
    },
    /// Check ended without an install for a reason that will not change by
    /// asking again soon (GitHub 403, no matching asset for this platform, a
    /// digest/signature/version refusal). Logged but non-fatal.
    Skipped(String),
    /// #1755 — the check could not reach the release server or finish the
    /// download (DNS, connect, timeout). Transient: the periodic loop
    /// rechecks on [`TRANSPORT_RETRY`] instead of the full interval.
    Unreachable(String),
}

/// Parse a git tag like `agent-v0.1.36`, `v0.1.36`, or
/// `agent-v0.3.0-rc.4` into a 4-tuple `(major, minor, patch, pre)`
/// for ordering. The `pre` field is `u64::MAX` for a non-pre-release
/// (final) version and the rc number for `-rc.N` / `-rcN` /
/// `-rc-N` pre-releases. This makes the natural tuple ordering match
/// semver: `0.3.0-rc.1 < 0.3.0-rc.4 < 0.3.0-rc.99 < 0.3.0`.
///
/// Unparseable tags compare as None and are treated as "not newer"
/// so a malformed server-side tag can't force a downgrade.
///
/// Field bug 2026-05-06: pre-0.3.0 implementation only returned a
/// 3-tuple; rc.3 vs rc.4 both parsed to `(0, 3, 0)` and
/// `is_newer(rc.4, rc.3)` returned false. The auto-updater logged
/// "up to date current=rc.3 latest=rc.4" indefinitely.
pub fn parse_version(tag: &str) -> Option<(u64, u64, u64, u64)> {
    let stripped = tag.trim_start_matches("agent-");
    let stripped = stripped.trim_start_matches('v');

    // Split on the FIRST '-' so the core (major.minor.patch) and the
    // pre-release suffix (rc.N / build.42 / etc.) are isolated.
    let (core, pre) = match stripped.find('-') {
        Some(i) => (&stripped[..i], Some(&stripped[i + 1..])),
        None => (stripped, None),
    };

    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts[1].parse::<u64>().ok()?;
    // After the '-' split, the patch is bare digits. If anything
    // non-digit-trailing snuck through (e.g. a build-metadata "+42"
    // that the find('-') missed), strip it for tolerance.
    let patch_str = parts[2].split(|c: char| !c.is_ascii_digit()).next()?;
    let patch = patch_str.parse::<u64>().ok()?;

    // Pre-release rank. Final (no pre-release) is highest so it
    // outranks every rc.N. Unknown pre-release labels also rank
    // u64::MAX so a forward-compat tag like `1.0.0-beta.5` doesn't
    // accidentally rank below an rc.
    let pre_rank = match pre {
        None => u64::MAX,
        Some(p) => parse_rc_rank(p).unwrap_or(u64::MAX),
    };

    Some((major, minor, patch, pre_rank))
}

/// Parse the pre-release suffix portion (after the leading `-`) for
/// `rc.N` / `rcN` / `rc-N` shapes. Returns `None` for non-rc
/// pre-releases — caller treats those as final-equivalent.
fn parse_rc_rank(pre: &str) -> Option<u64> {
    let after_rc = pre
        .strip_prefix("rc.")
        .or_else(|| pre.strip_prefix("rc-"))
        .or_else(|| pre.strip_prefix("rc"))?;
    after_rc.parse::<u64>().ok()
}

/// Return true if `latest` strictly outranks `current`.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Which Windows MSI flavour the running agent was installed with.
/// Used by [`pick_asset_for_platform`] to download the matching MSI
/// for in-place upgrade — installing the wrong flavour silently fails
/// the launch-condition check shipped in 0.2.5 and the auto-update
/// loop never makes forward progress (field repro: the field-test host
/// 2026-05-02, perUser agent on 0.2.0 picked the perMachine 0.2.5 MSI
/// alphabetically; UAC-elevated install rejected by the cross-flavour
/// guard; agent restarted at 0.2.0 forever).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsInstallFlavour {
    PerUser,
    PerMachine,
}

/// Discover this agent's install flavour from the running exe path.
/// Heuristic: anything under `\Program Files` (with or without ` (x86)`)
/// is perMachine; everything else (including `%LOCALAPPDATA%\Programs\`)
/// is perUser. Defaults to perUser on lookup failure — that matches the
/// historical install mode shipped before 0.2.1, and is the safe-side
/// guess because the perUser MSI installs without UAC and works against
/// any account.
#[cfg(target_os = "windows")]
pub fn current_install_flavour() -> WindowsInstallFlavour {
    let Ok(exe) = std::env::current_exe() else {
        return WindowsInstallFlavour::PerUser;
    };
    classify_install_flavour_from_path(&exe)
}

/// Pure-fn variant of [`current_install_flavour`] so unit tests can
/// drive it without a real filesystem. Lowercases for case-insensitive
/// match against the Windows convention `C:\Program Files\…`.
#[cfg(target_os = "windows")]
pub fn classify_install_flavour_from_path(p: &std::path::Path) -> WindowsInstallFlavour {
    let lower = p.to_string_lossy().to_lowercase();
    // Match both `\program files\` and `\program files (x86)\`. Use
    // path-separator-bracketed substring so a project literally named
    // "ProgramFiles" elsewhere on disk doesn't trip the check.
    if lower.contains("\\program files (x86)\\") || lower.contains("\\program files\\") {
        WindowsInstallFlavour::PerMachine
    } else {
        WindowsInstallFlavour::PerUser
    }
}

/// The MSI install folder name since P4b — both wxs files set
/// `APPLICATIONFOLDER Name='Roomler'`. `pub` (not `pub(crate)`): the
/// roomler-setup wizard's daemon orchestrator derives the CLI's
/// post-install path from it (same visibility-lift precedent as the
/// rc.27 wizard helpers).
#[cfg(target_os = "windows")]
pub const INSTALL_FOLDER_NAME: &str = "Roomler";

/// The pre-P4b install folder name both MSI flavours used through
/// rc.194. The `cleanup-legacy-install` vacated-dir sweep targets
/// this after a rename-hop upgrade.
#[cfg(target_os = "windows")]
// RETIRED-NAME-ANCHOR: the cleanup sweep needs the OLD folder name to find the
// vacated directory after a rename-hop upgrade. See docs/fr/FR-21.
pub(crate) const LEGACY_INSTALL_FOLDER_NAME: &str = "roomler-agent";

/// Resolve a flavour's MSI install directory for a given folder name:
/// perUser → `%LOCALAPPDATA%\Programs\<name>`, perMachine →
/// `%ProgramFiles%\<name>` (the same roots the two wxs files install
/// under). Callers pass [`INSTALL_FOLDER_NAME`] to find the current
/// install (post-install watcher fallback) or
/// [`LEGACY_INSTALL_FOLDER_NAME`] to find the directory a rename-hop
/// upgrade vacated (`install_cleanup` sweep). `None` when the root
/// env var is unset (effectively never on a real Windows session).
#[cfg(target_os = "windows")]
pub fn install_dir_with_name(
    flavour: WindowsInstallFlavour,
    folder_name: &str,
) -> Option<std::path::PathBuf> {
    match flavour {
        WindowsInstallFlavour::PerUser => std::env::var_os("LOCALAPPDATA").map(|root| {
            std::path::PathBuf::from(root)
                .join("Programs")
                .join(folder_name)
        }),
        WindowsInstallFlavour::PerMachine => std::env::var_os("ProgramFiles")
            .map(|root| std::path::PathBuf::from(root).join(folder_name)),
    }
}

/// Pick the asset that matches this build's platform. Returns an
/// explicit `None` when there's no match so the caller can log + skip
/// rather than downloading something wrong.
///
/// On Windows the GitHub Release ships two MSI flavours per tag
/// (perUser + perMachine); pick the one matching the running install
/// so the in-place upgrade actually lands. See
/// [`WindowsInstallFlavour`] for the why.
pub fn pick_asset_for_platform(assets: &[GithubAsset]) -> Option<&GithubAsset> {
    #[cfg(target_os = "windows")]
    {
        pick_asset_for_windows(assets, current_install_flavour())
    }
    #[cfg(not(target_os = "windows"))]
    {
        pick_asset_for_unix(assets)
    }
}

// RETIRED-NAME-ANCHOR(2): PUBLISHED asset names. Already-released files cannot be
// renamed and the picker matches them, so they stay verbatim. docs/fr/FR-21
/// Pure Windows asset picker. Filters by the `-perMachine-` infix in
/// the asset filename (cargo-wix names them
/// `roomler-agent-<v>-perMachine-x86_64-…msi`; the perUser MSI uses
/// `roomler-agent-<v>-x86_64-…msi` with no infix). Falls back to "any
/// MSI" only if the matching flavour is missing — better to attempt a
/// cross-flavour install (which will silently no-op) than to skip the
/// update entirely on a release that, for whatever reason, only shipped
/// one flavour.
#[cfg(any(target_os = "windows", test))]
pub fn pick_asset_for_windows(
    assets: &[GithubAsset],
    flavour: WindowsInstallFlavour,
) -> Option<&GithubAsset> {
    let want_per_machine = matches!(flavour, WindowsInstallFlavour::PerMachine);
    // First pass: prefer the matching flavour.
    for a in assets {
        let lower = a.name.to_lowercase();
        if !lower.ends_with(".msi") {
            continue;
        }
        let is_per_machine = lower.contains("-permachine-");
        if is_per_machine == want_per_machine {
            return Some(a);
        }
    }
    // Fallback: any MSI. Logged at warn so the field can see when the
    // release is missing the matching flavour.
    for a in assets {
        if a.name.to_lowercase().ends_with(".msi") {
            tracing::warn!(
                asset = %a.name,
                flavour = ?flavour,
                "no MSI matching install flavour; falling back to any MSI"
            );
            return Some(a);
        }
    }
    None
}

/// Pure non-Windows asset picker. .deb on Linux, .pkg on macOS. Kept
/// separate from the Windows path so the flavour-discovery branch
/// doesn't compile on platforms that don't need it. `allow(dead_code)`
/// because Windows test builds compile this for symmetry but don't
/// call it (`pick_asset_for_platform` short-circuits to the Windows
/// path on Windows).
#[cfg(any(not(target_os = "windows"), test))]
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub fn pick_asset_for_unix(assets: &[GithubAsset]) -> Option<&GithubAsset> {
    let mac = cfg!(target_os = "macos");
    let linux = cfg!(target_os = "linux");
    // The .deb match MUST be arch-qualified. It used to accept any `.deb`,
    // which was harmless only while exactly one Linux .deb existed per
    // release; the moment a second architecture ships, an x86_64 agent
    // would happily download an arm64 package (asset order is GitHub's,
    // not ours) and dpkg it. Match the arch token the release filenames
    // already carry (`…-x86_64-unknown-linux-gnu.deb`), keeping the
    // legacy `_amd64.deb` cargo-deb spelling for old releases.
    let arch_tokens = linux_arch_tokens();
    if mac {
        return assets
            .iter()
            .find(|a| a.name.to_lowercase().ends_with(".pkg"));
    }
    if !linux {
        return None;
    }
    pick_linux_asset(assets, arch_tokens, host_has_debian_tooling())
}

/// The arch tokens a Linux release asset's name carries for THIS build's
/// architecture (`…-x86_64-unknown-linux-gnu.deb`, plus cargo-deb's legacy
/// `_amd64.deb`). Empty for an architecture no release ships. One list for the
/// daemon's picker and FR-117's companion picker, so the two cannot drift.
#[cfg(any(not(target_os = "windows"), test))]
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) fn linux_arch_tokens() -> &'static [&'static str] {
    if cfg!(target_arch = "x86_64") {
        &["x86_64", "amd64"]
    } else if cfg!(target_arch = "aarch64") {
        &["aarch64", "arm64"]
    } else {
        &[]
    }
}

/// Is there anything on this host that can install a `.deb`?
///
/// Probes for the TOOL rather than reading `/etc/os-release`, because the
/// question that decides the download is "can the install actually run",
/// and a distro ID is only a proxy for it (a Debian derivative with dpkg
/// removed, or a Fedora box with dpkg added, both answer correctly here).
#[cfg(any(not(target_os = "windows"), test))]
#[cfg_attr(target_os = "windows", allow(dead_code))]
fn host_has_debian_tooling() -> bool {
    ["dpkg", "apt-get"].iter().any(|bin| {
        std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
            .unwrap_or(false)
    })
}

// RETIRED-NAME-ANCHOR: published asset names, as above. docs/fr/FR-21
/// Is this release asset the DAEMON's own package, as opposed to something
/// else in the same release that happens to be a `.deb` for the same arch?
///
/// FR-27 made this necessary: the Linux desktop companion now ships as its own
/// `roomler-desktop-…-x86_64-unknown-linux-gnu.deb`, so a release carries two
/// arch-matching `.deb`s and asset order is GitHub's, not ours. Without this
/// the daemon could download the COMPANION, `dpkg -i` it — which succeeds —
/// and never update itself: a silent, permanent freeze that looks like a
/// working update. Exactly the shape the arch guard in [`pick_linux_asset`]
/// was added for, one axis over.
///
/// Positive match, not a denylist of names we happen to know today. The
/// daemon's published asset names are a deliberately immutable surface
/// (`roomler-agent-…`, plus cargo-deb's `roomlerd_…` spelling on old
/// releases), so naming them is safe and a new sibling asset cannot creep
/// through by being unlisted. Locked by
/// `pick_linux_asset_never_takes_the_desktop_companion`.
///
/// Gated like its only caller: a Windows build has no Linux picker to call it.
#[cfg(any(not(target_os = "windows"), test))]
#[cfg_attr(target_os = "windows", allow(dead_code))]
// RETIRED-NAME-ANCHOR(2): the legacy arm. Since FR-46 (#1051) new releases publish
// `roomlerd-…`, so this prefix names only ALREADY-PUBLISHED assets — but it is a LIVE
// fallback, not decoration: a host updating from a release cut before the rename still
// finds its own `.deb` through it. Deletable once no such release is a candidate.
// Locked by `pick_linux_asset_takes_the_renamed_daemon_deb`. docs/fr/FR-46
fn is_daemon_asset(lower_name: &str) -> bool {
    lower_name.starts_with("roomler-agent") || lower_name.starts_with("roomlerd")
}

/// Choose the Linux asset: the right ARCH always, and the format this host
/// can actually install.
///
/// A `.deb` is preferred where dpkg/apt exist so the distro's package
/// manager stays the source of truth; everywhere else the self-contained
/// tarball is the only installable form. Falling back to the tarball when
/// a Debian host's `.deb` is missing keeps an absent artifact from becoming
/// a dead end. See `docs/linux-self-update.md`.
#[cfg(any(not(target_os = "windows"), test))]
#[cfg_attr(target_os = "windows", allow(dead_code))]
fn pick_linux_asset<'a>(
    assets: &'a [GithubAsset],
    arch_tokens: &[&str],
    debian_tooling: bool,
) -> Option<&'a GithubAsset> {
    let for_arch = |suffix: &str| {
        assets.iter().find(|a| {
            let lower = a.name.to_lowercase();
            lower.ends_with(suffix)
                && arch_tokens.iter().any(|t| lower.contains(t))
                && is_daemon_asset(&lower)
        })
    };
    let deb = for_arch(".deb");
    let tar = for_arch(".tar.gz");
    let picked = if debian_tooling {
        deb.or(tar)
    } else {
        // No dpkg/apt: a .deb here would download and then fail to install,
        // which is how `Update all` looked like a silent no-op on a Fedora
        // host (2026-08-15).
        tar
    };
    match picked {
        Some(a) => tracing::debug!(
            asset = %a.name,
            debian_tooling,
            deb_available = deb.is_some(),
            tar_available = tar.is_some(),
            "update: picked Linux asset"
        ),
        None => tracing::warn!(
            debian_tooling,
            deb_available = deb.is_some(),
            tar_available = tar.is_some(),
            "update: no installable Linux asset for this host — \
             a .deb needs dpkg/apt, otherwise a .tar.gz is required"
        ),
    }
    picked
}

/// Query exactly one trusted feed; failures never select a different publisher.
async fn fetch_latest_release() -> Result<GithubRelease> {
    let origin = update_origin()?;
    let releases = fetch_releases_from(origin.feed().as_str()).await?;
    pick_latest_release(releases).context("no published agent-v* release in trusted update feed")
}

async fn fetch_releases_from(url: &str) -> Result<Vec<GithubRelease>> {
    let origin = update_origin()?;
    if url != origin.feed().as_str() {
        bail!("manifest URL differs from the configured trusted update feed");
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("roomlerd/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .redirect(update_redirect_policy(origin, false))
        .build()
        .context("building reqwest client")?;
    let resp = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("GET releases")?;
    if !resp.status().is_success() {
        // 403 from GitHub's REST API is the unauthenticated 60-req-per-
        // IP-per-hour quota tripping. Surface the reset window from
        // the rate-limit headers so the operator can see "wait 47
        // minutes" instead of just "got 403". Headers may be absent
        // on edge-network errors; default to a vague message when
        // they are.
        let status = resp.status();
        if status.as_u16() == 403 {
            let limit = resp
                .headers()
                .get("x-ratelimit-limit")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("?")
                .to_string();
            let remaining = resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("?")
                .to_string();
            let reset_unix = resp
                .headers()
                .get("x-ratelimit-reset")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let resets_in_secs = reset_unix
                .map(|t| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    t.saturating_sub(now)
                })
                .unwrap_or(0);
            bail!(
                "GitHub API returned 403 Forbidden — rate-limited (limit={limit}, remaining={remaining}, resets in {resets_in_secs}s). Multiple agents on one IP share the unauthenticated 60/hr quota; cadence has been bumped to 24h to stay under it."
            );
        }
        bail!("GitHub API returned {}", status);
    }
    let releases: Vec<GithubRelease> = resp.json().await.context("parsing GitHub releases JSON")?;
    Ok(releases)
}

/// Given a vector of releases from GitHub (newest-first per API
/// contract), pick the highest-versioned `agent-v*` that isn't a
/// draft. Prereleases are tolerated because our 0.x history marked
/// them all that way and we still want those agents to update.
/// Exported for tests so the selection rule is locked.
pub fn pick_latest_release(mut releases: Vec<GithubRelease>) -> Option<GithubRelease> {
    releases.retain(|r| {
        !r.draft && r.tag_name.starts_with("agent-v") && parse_version(&r.tag_name).is_some()
    });
    if releases.is_empty() {
        return None;
    }
    releases.sort_by_key(|r| std::cmp::Reverse(parse_version(&r.tag_name)));
    releases.into_iter().next()
}

/// Name prefix of a private per-download staging directory. A cleanup
/// recognises its own by this prefix and removes nothing else.
#[cfg(any(target_os = "linux", target_os = "windows"))]
const STAGING_DIR_PREFIX: &str = "roomlerd-update.";

/// Where a just-downloaded installer is staged before it runs.
///
/// ⚠️ Linux: a FRESH private directory per download (mkdtemp — a random name,
/// created 0700 then relaxed to 0755, owned by the caller). NEVER the old fixed
/// `/tmp/roomlerd-update/<asset>`: `/tmp` is sticky but a SUBDIRECTORY of it is
/// not, so any local user could `mkdir /tmp/roomlerd-update` first (and own
/// it), then — in the window between this download's in-memory signature check
/// and the installer's own read of the PATH (`apt-get install <path>`,
/// `tar -xzf <path>`) — `rename` an attacker package over the genuine one,
/// making root install arbitrary code (dpkg maintainer scripts run as root).
/// A directory nobody else owns closes it: a non-owner cannot create, rename
/// or unlink inside it. 0755 (not 0700) so apt's `_apt` sandbox user can read
/// the `.deb` — else apt warns and falls back to an unsandboxed-root install
/// anyway, but the warning is noise we can avoid. FR-96 security review (#2055).
#[cfg(target_os = "linux")]
fn stage_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let td = tempfile::Builder::new()
        .prefix(STAGING_DIR_PREFIX)
        .tempdir_in(std::env::temp_dir())?;
    // mkdtemp created it 0700 and ours; relax to exactly 0755 with an explicit
    // chmod (bypassing umask) now that it exists and only we can reach it.
    std::fs::set_permissions(td.path(), std::fs::Permissions::from_mode(0o755))?;
    Ok(td.keep())
}

/// Windows: a fresh, private staging directory per download — Linux's #2055
/// fix, applied to the second OS with the identical flaw.
///
/// GHSA-r3xj-4wh9-xh2v: on an **unpatched Win10 SYSTEM** install (no
/// KB5053594 or the equivalent; Win11 and Server 2022+ are unaffected, and a
/// patched Win10 is not either — see the advisory for the version split),
/// `std::env::temp_dir()` for the SYSTEM account falls back to the Win32
/// `GetTempPath` behaviour and resolves to the SHARED `C:\Windows\Temp`,
/// whose default ACL lets any authenticated standard user create a
/// subdirectory there and own it. That is Linux's #2055 shape one OS over: a
/// local user pre-creates `roomlerd-update\`, owns it, and in the window
/// between this download's in-memory verification and `msiexec`'s own
/// re-read of the PATH, swaps in their own MSI — SYSTEM installs it.
///
/// Two cases, because only ONE of them can safely carry a hardened DACL:
///
/// * **This process is actually holding the SYSTEM token right now**
///   ([`running_as_system`] — the LIVE token, never "SystemContext is
///   configured": a perMachine service that has winlogon-token-swapped to
///   the console user (M3 A1) is no longer SYSTEM by the time this runs).
///   [`create_fresh_protected_dir`] makes a directory nobody but SYSTEM and
///   Administrators can read or write, DACL applied AT CREATION so there is
///   no window where it exists with the parent's permissive, inherited ACL.
/// * **Everyone else** — a perUser install (runs as the signed-in user, whose
///   `%TEMP%` is already a private, per-user trust boundary — nobody else
///   can write there regardless of the dir's own ACL) or a perMachine worker
///   that is not, right now, SYSTEM. A SYSTEM-and-Administrators-only DACL
///   would lock either of those OUT of its own staging dir, so they get
///   [`stage_dir_as_current_user`] instead: still fresh and privately named
///   (closing the swap window the same way Linux's mkdtemp does — a
///   non-owner cannot create, rename or unlink inside a directory it does
///   not own), just without the extra DACL that would backfire here.
///
/// A fresh dir per call also retires the old reason the shared name existed
/// (the companion refresh re-downloading `roomler-desktop.exe` under the same
/// name): each download is alone in its own directory now, so there is
/// nothing left for a shared name to coordinate.
#[cfg(target_os = "windows")]
fn stage_dir() -> std::io::Result<PathBuf> {
    if running_as_system() {
        create_fresh_protected_dir(&std::env::temp_dir())
    } else {
        stage_dir_as_current_user()
    }
}

/// Is this process, right now, holding the LocalSystem token? `S-1-5-18` is
/// the one well-known SID LocalSystem always has, on every Windows version —
/// unlike "is SystemContext configured", this reads the LIVE token, so a
/// worker that has winlogon-token-swapped to the console user (M3 A1)
/// correctly reads `false` here even on a SystemContext-enabled install.
#[cfg(target_os = "windows")]
fn running_as_system() -> bool {
    is_system_sid(crate::win_token::own_user_sid().as_deref())
}

/// Pure half of [`running_as_system`], so the comparison is unit-testable
/// without a real token.
#[cfg(target_os = "windows")]
fn is_system_sid(sid: Option<&str>) -> bool {
    sid == Some("S-1-5-18")
}

/// The non-SYSTEM staging dir: fresh and privately named, exactly like
/// Linux's mkdtemp (no chmod step needed — a per-user `%TEMP%` already keeps
/// other accounts out, so there is no inherited ACL here to harden).
#[cfg(target_os = "windows")]
fn stage_dir_as_current_user() -> std::io::Result<PathBuf> {
    let td = tempfile::Builder::new()
        .prefix(STAGING_DIR_PREFIX)
        .tempdir_in(std::env::temp_dir())?;
    Ok(td.keep())
}

/// A security descriptor built from SDDL, and the `SECURITY_ATTRIBUTES` that
/// hand it to `CreateDirectoryW`. Freed on drop.
///
/// Deliberately its own copy rather than a shared import: `hive_win::Sddl` is
/// the identical shape but compiles only with the optional `hive` feature,
/// and `win_service::stop_event` builds its descriptor inline for one event —
/// neither is reachable from every Windows build the way this fix must be.
/// `exec_service.rs` carries the same duplicate for the same reason (its own
/// doc comment says so); this is the fourth copy, not the first.
#[cfg(target_os = "windows")]
struct ProtectedDirSd {
    sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    psd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

#[cfg(target_os = "windows")]
impl ProtectedDirSd {
    /// `O:BA` — owner explicitly Administrators, same as the exec-service
    /// anchor dir's `DIR_SDDL` (`exec_service.rs`) and for the identical
    /// reason: an owner always keeps WRITE_DAC on its own object regardless
    /// of the DACL, so leaving the owner field out would default it to
    /// whichever token happened to call `CreateDirectoryW` — correct when
    /// that is SYSTEM (the only caller [`running_as_system`] permits in
    /// production), but a silent weakening if this were ever reached by
    /// anyone else. Naming the owner makes that reachable only by failing
    /// outright instead: an unprivileged caller cannot assign an owner it is
    /// not itself or a member of, so `CreateDirectoryW` refuses rather than
    /// quietly creating something weaker than the DACL below promises.
    /// `D:P` protected (no inheritance from the world-writable parent);
    /// SYSTEM and BUILTIN\Administrators get `FILE_ALL_ACCESS` (`OICI` —
    /// object+container inherit, so the installer, its `.log`, and the
    /// staged watcher copy this directory holds all inherit the same grant);
    /// nobody else is named, so nobody else gets anything.
    const SDDL: &'static str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        let wide: Vec<u16> = Self::SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string; `psd` receives a LocalAlloc'd
        // descriptor, freed in Drop. The size out-param is optional.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            sa: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            },
            psd,
        })
    }

    fn attributes(&mut self) -> *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        &raw mut self.sa
    }
}

#[cfg(target_os = "windows")]
impl Drop for ProtectedDirSd {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;
        // SAFETY: the one descriptor ConvertStringSecurityDescriptor… made.
        unsafe { LocalFree(self.psd as _) };
    }
}

/// Make a fresh, uniquely-named directory under `base`, its DACL set AT
/// CREATION ([`ProtectedDirSd`]) so there is never a moment where it exists
/// with the parent's permissive, inherited ACL. Retries on a name collision
/// with a fresh random suffix (mkdtemp semantics) — `tempfile` cannot be used
/// here because its `Builder` has no way to pass Windows security attributes.
#[cfg(target_os = "windows")]
fn create_fresh_protected_dir(base: &std::path::Path) -> std::io::Result<PathBuf> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    for _ in 0..8 {
        let name = format!("{}{:016x}", STAGING_DIR_PREFIX, rand::random::<u64>());
        let dir = base.join(name);
        let wide: Vec<u16> = dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut sd = ProtectedDirSd::new()?;
        // SAFETY: a NUL-terminated path; the descriptor lives in `sd` for the
        // duration of this call.
        let ok = unsafe { CreateDirectoryW(wide.as_ptr(), sd.attributes()) };
        if ok != 0 {
            return Ok(dir);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e);
        }
        // Name collision — try again with a fresh random suffix.
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique staging dir name",
    ))
}

/// macOS: the per-user `confstr(_CS_DARWIN_USER_TEMP_DIR)` temp dir is
/// already a trust boundary, so the historical shared dir is kept as-is.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn stage_dir() -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join("roomlerd-update");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Write the downloaded installer to its staging path.
///
/// ⚠️ Linux and Windows: `O_CREAT|O_EXCL` (`create_new`) — refuse to write
/// through anything already at the name rather than follow a symlink or
/// truncate a planted file. Belt to [`stage_dir`]'s braces (the fresh private
/// dir already means nobody else can plant here); kept because the cost is
/// one flag and what is written runs as root/SYSTEM.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn write_installer(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)
}

/// macOS: the shared staging dir reuses a file name per release, so a
/// create-or-truncate is what a repeated download needs.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn write_installer(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Whether `dir` is one of our private staging directories, by name
/// (`STAGING_DIR_PREFIX` + a random suffix) and location (directly in
/// `temp_dir()`). Name-and-place only, on purpose: the guard's job is to stop a
/// cleanup touching a path that is NOT ours — the old fixed `roomlerd-update`
/// (no trailing dot, so excluded) from a pre-fix build, or a wizard-supplied
/// installer elsewhere.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn is_staging_dir(dir: &std::path::Path) -> bool {
    dir.parent() == Some(std::env::temp_dir().as_path())
        && dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(STAGING_DIR_PREFIX))
}

/// Remove the private staging directory that holds `installer_path`, if it is
/// one of ours. Best-effort: a failure is logged, never fatal. `remove_dir_all`
/// does not follow symlinks (std ≥ 1.58.1); nobody else could have planted one
/// in a directory only we own (Linux: 0755 and caller-owned; Windows: SYSTEM
/// is the caller, or the per-user `%TEMP%` already keeps everyone else out).
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn discard_staging(installer_path: &std::path::Path) {
    let Some(dir) = installer_path.parent() else {
        return;
    };
    if !is_staging_dir(dir) {
        return;
    }
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            error = %e,
            dir = %dir.display(),
            "update: could not remove the private staging dir"
        ),
    }
}

/// How old an abandoned Windows staging directory must be before
/// [`sweep_stale_update_staging_at_start`] will remove it. Generous relative
/// to how long this daemon's own post-install watcher ever runs (a wedged
/// msiexec resolves via RestartManager well under a minute in every field
/// case logged here; the FR-93 lab's own forced-exit watchdog fires around
/// 90s) specifically so the sweep at the NEXT startup can never be unsure
/// whether THIS update's watcher might still be using its directory.
#[cfg(target_os = "windows")]
const STALE_STAGING_DIR_AGE: Duration = Duration::from_secs(3600);

/// Pure half of the sweep's age gate, so the threshold is unit-testable
/// without fabricating directory timestamps.
#[cfg(target_os = "windows")]
fn is_stale(age: Duration) -> bool {
    age >= STALE_STAGING_DIR_AGE
}

/// GHSA-r3xj-4wh9-xh2v — remove this daemon's own abandoned staging
/// directories from a PRIOR update, once, at startup (called from `main.rs`
/// next to the Linux `tarball_owner` repair, behind the same single-instance
/// lock).
///
/// ⚠️ Why startup, and not inside [`download_asset`] where the directory is
/// made: `download_asset` is shared plumbing — `check_once`, `pin_version`,
/// and the companion refresh (`crate::companion`) all call it, from
/// independent tokio tasks that are **not** serialised against each other. A
/// sweep run there could find and remove another call's directory while its
/// download is still in flight, or — worse — remove the directory a
/// just-spawned watcher is still retrying an install from. Neither hazard
/// exists at startup: this runs once, before any update task is spawned, so
/// every directory it can find was made by a PREVIOUS process generation
/// that already exited after creating it (every success path here ends in
/// [`spawn_installer_with_watch`] followed by `std::process::exit` — see its
/// doc comment). [`STALE_STAGING_DIR_AGE`] is the second, independent guard
/// for the one remaining edge: an update's watcher may still be running when
/// the FRESH binary it just installed reaches ITS OWN startup (an MSI install
/// restarts the service while the watcher is still polling it), so a
/// directory younger than the gate is left for a later start to reconsider
/// rather than risk deleting what that watcher is still using.
///
/// Best-effort: nothing to sweep is the normal case on every start, and a
/// removal failure — most likely a file a surviving watcher still holds open
/// — is logged and skipped, never fatal, exactly like Linux's
/// [`discard_staging`].
#[cfg(target_os = "windows")]
pub fn sweep_stale_update_staging_at_start() {
    let base = std::env::temp_dir();
    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(
                error = %e,
                dir = %base.display(),
                "update: could not list the temp dir for the staging sweep"
            );
            return;
        }
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !is_staging_dir(&dir) {
            continue;
        }
        let age = std::fs::metadata(&dir)
            .ok()
            .and_then(|m| m.created().ok())
            .and_then(|created| created.elapsed().ok());
        // Unknown age (exotic on NTFS) is treated the same as "too young":
        // the safe default when staleness can't be proven is to leave it for
        // a later start to judge, not to guess and remove it now.
        if !age.is_some_and(is_stale) {
            continue;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => tracing::info!(
                dir = %dir.display(),
                "update: removed a staging dir left by a prior update"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                dir = %dir.display(),
                "update: could not remove a stale staging dir"
            ),
        }
    }
}

/// Discard a staged download that will not be installed (a failed verification,
/// or the debug dry-run). Linux and Windows: the whole private dir (it holds
/// only this file). macOS: the file alone — its staging dir is shared across
/// downloads.
fn discard_download(path: &std::path::Path) {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        discard_staging(path);
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = std::fs::remove_file(path);
    }
}

/// Download an asset to a temp file and return the path. Verifies the
/// downloaded size against the asset metadata + the minimum plausible
/// size so we don't run a ~200 byte HTML error page as an installer.
/// `pub(crate)`: the S1a companion-refresh (`crate::companion`) reuses
/// the same verified-download plumbing for `roomler-desktop.exe`.
///
/// `claimed_release` is the tag the manifest offered this asset AS
/// (`agent-v0.3.0-rc.458`). It is not decoration: the artifact has to
/// self-identify as that release or it is discarded — see
/// [`crate::artifact_version`] for the downgrade this closes.
pub(crate) async fn download_asset(asset: &GithubAsset, claimed_release: &str) -> Result<PathBuf> {
    let origin = update_origin()?;
    origin::validate_asset_name(&asset.name).map_err(anyhow::Error::msg)?;
    let asset_url = origin
        .asset_url(&asset.browser_download_url)
        .map_err(anyhow::Error::msg)?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("roomlerd/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(600))
        .redirect(update_redirect_policy(origin.clone(), true))
        .build()
        .context("building download client")?;
    let resp = client.get(asset_url).send().await.context("GET asset")?;
    if !resp.status().is_success() {
        bail!("asset download returned {}", resp.status());
    }
    let bytes = resp.bytes().await.context("reading asset body")?;
    if bytes.len() < MIN_INSTALLER_BYTES {
        bail!(
            "asset {} is implausibly small: {} bytes (minimum {})",
            asset.name,
            bytes.len(),
            MIN_INSTALLER_BYTES
        );
    }
    // Transport-integrity check: when GitHub / our proxy gave us a digest,
    // verify the downloaded bytes match. This catches corruption mid-flight
    // (rare with TLS but possible with broken middleboxes).
    //
    // ⚠️ It is NOT a tamper anchor, which is why the signature check below
    // exists: this digest arrives in the SAME manifest, from the SAME origin,
    // as the URL we just fetched — anyone able to serve one can serve the
    // other, so a hostile mirror simply supplies a matching hash.
    if let Some(digest) = asset.digest.as_deref() {
        verify_sha256(&bytes, digest)
            .with_context(|| format!("verifying digest for {}", asset.name))?;
    } else {
        tracing::warn!(
            asset = %asset.name,
            "no digest field on asset; falling through to size floor only"
        );
    }
    let dir = stage_dir().context("creating the staging dir")?;
    let path = dir.join(&asset.name);
    write_installer(&path, &bytes).context("writing installer to disk")?;

    // Publisher check — the anchor the serving channel cannot forge. Whatever
    // is on disk here is about to run as SYSTEM, so it must be attributable to
    // us and not merely to "someone with a code-signing certificate": a valid
    // Authenticode signature alone would let any commercial cert holder
    // through, so the signer's name is checked too.
    //
    // Fail-closed, and the failure is SKIPPING the update: the file is
    // discarded and the agent keeps running the version it already has. That
    // is deliberately the safe direction — a false negative costs an update
    // cycle, a false positive costs the fleet.
    //
    // Windows: Authenticode + the signer-name check.
    #[cfg(windows)]
    {
        use crate::code_signature::{EXPECTED_PUBLISHER, verify_publisher};
        match verify_publisher(&path, EXPECTED_PUBLISHER) {
            Ok(signer) => {
                tracing::info!(asset = %asset.name, %signer, "installer signature verified");
            }
            Err(e) => {
                discard_download(&path);
                bail!(
                    "refusing to install {}: {e}. The download was discarded and this \
                     agent keeps its current version.",
                    asset.name
                );
            }
        }
    }

    // Linux/macOS: the detached GPG `.asc` verified against the key PINNED
    // in this binary (`pgp_verify`). Same fail-closed direction as Windows,
    // and the sidecar is REQUIRED: every release since rc.458 ships one, the
    // updater only ever moves FORWARD, and "the .asc is missing" means the
    // release's signing job failed — freezing on it, loudly, is correct.
    // (⚠️ the release workflow skips GPG signing gracefully when its secret
    // is absent; from this change on, that grace would freeze Linux/macOS
    // updates — the freeze is visible here as a refusal + sentinel, which is
    // the intended alarm, not a silent stall.)
    //
    // The sidecar URL is derived (`<asset-url>.asc` — GitHub names release
    // assets verbatim) and fetched over the SAME channel as the artifact.
    // That is fine: the point of the pin is that the channel cannot mint a
    // signature, only withhold one — and withholding is a refusal, not an
    // install.
    #[cfg(not(windows))]
    {
        let mut asc_url = origin
            .asset_url(&asset.browser_download_url)
            .map_err(anyhow::Error::msg)?;
        asc_url.set_path(&format!("{}.asc", asc_url.path()));
        let asc_url = origin
            .asset_url(asc_url.as_str())
            .map_err(anyhow::Error::msg)?;
        let asc = async {
            let resp = client
                .get(asc_url.clone())
                .send()
                .await
                .context("GET .asc sidecar")?;
            if !resp.status().is_success() {
                bail!("sidecar download returned {}", resp.status());
            }
            resp.text().await.context("reading .asc body")
        }
        .await;
        let verdict = match asc {
            Ok(asc) => crate::pgp_verify::verify_release_artifact(&bytes, &asc),
            Err(e) => Err(e.context(format!("fetching {asc_url}"))),
        };
        match verdict {
            Ok(()) => {
                tracing::info!(
                    asset = %asset.name,
                    "installer .asc verified against the pinned release signing key"
                );
            }
            Err(e) => {
                discard_download(&path);
                bail!(
                    "refusing to install {}: {e:#}. The download was discarded and this \
                     agent keeps its current version.",
                    asset.name
                );
            }
        }
    }

    // Version binding — the check above proves the bytes are OURS, this one
    // proves they are the RELEASE we were told to install. Both are needed:
    // `is_newer` decided to upgrade by reading the MANIFEST's tag, while the
    // signature verified the ARTIFACT, and until now nothing connected the
    // two. See `crate::artifact_version` for the full downgrade.
    //
    // Same fail-closed direction as the signature check, for the same reason:
    // a refusal costs an update cycle, a wrongly-accepted payload costs the
    // fleet.
    match crate::artifact_version::verify_artifact_version(&path, claimed_release) {
        Ok(found) => {
            tracing::info!(
                asset = %asset.name,
                claimed = %claimed_release,
                artifact_version = %found,
                "artifact self-identifies as the release it was offered as"
            );
        }
        // Not a refusal: nothing was proved either way. Since FR-97 P6a the
        // `.deb`, `.pkg` and tarball are bound too, so this is now a format no
        // reader handles, a reader that cannot run here (a `.deb` with no
        // `dpkg-deb`), or `ROOMLERD_ARTIFACT_VERSION_CHECK=0`. Logged at INFO:
        // a warning per update check would train operators to ignore it.
        Err(e @ crate::artifact_version::VersionError::Unsupported(_)) => {
            tracing::info!(asset = %asset.name, reason = %e, "no artifact-version binding available");
        }
        Err(e) => {
            discard_download(&path);
            bail!(
                "refusing to install {}: {e}. The download was discarded and this \
                 agent keeps its current version.",
                asset.name
            );
        }
    }

    Ok(path)
}

/// Verify a payload's SHA256 against a `"<algo>:<hex>"` formatted
/// digest string (GitHub's convention as of late 2024). Returns
/// `Err` on mismatch, unsupported algorithm, or malformed digest.
/// Pure function — no I/O — so the test suite can drive it without
/// network or filesystem.
pub(crate) fn verify_sha256(bytes: &[u8], digest: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    // Today only sha256 is in scope. Reject anything else explicitly
    // so a future GitHub change to e.g. `"sha512:..."` doesn't
    // silently disable verification — we'd rather fail loud and
    // ship a fix.
    let Some(expected_hex) = digest.strip_prefix("sha256:") else {
        bail!("unsupported digest algorithm in {digest:?}; expected sha256:<hex>");
    };
    if expected_hex.len() != 64 {
        bail!(
            "malformed sha256 digest length: got {} hex chars, want 64",
            expected_hex.len()
        );
    }
    let mut h = Sha256::new();
    h.update(bytes);
    let computed_hex = hex::encode(h.finalize());
    if !computed_hex.eq_ignore_ascii_case(expected_hex) {
        bail!("sha256 mismatch: computed {computed_hex}, expected {expected_hex}",);
    }
    Ok(())
}

/// Exact-tag lookup in the SAME trusted feed, including older entries returned
/// by that feed. No public same-center by-tag route exists today. If historical
/// recovery is absent from its list, refuse rather than guessing an upstream URL
/// or substituting the latest tag. Archive rollback availability remains a center
/// contract/acceptance requirement, not something this client can manufacture.
pub(crate) async fn fetch_release_by_tag(tag: &str) -> Result<GithubRelease> {
    let origin = update_origin()?;
    let releases = fetch_releases_from(origin.feed().as_str()).await?;
    releases
        .into_iter()
        .find(|r| r.tag_name == tag && !r.draft)
        .context("requested tag unavailable in trusted update feed; no upstream fallback")
}

/// Pin to a specific release tag. Used by the rollback path when
/// the crash-loop detector decides the current version is broken
/// and the last known-good version should be reinstalled.
///
/// Returns `CheckOutcome::UpdateReady` with an installer path on
/// success — caller spawns the installer. Returns `Skipped` on any
/// fetch / asset-pick / download failure so the agent can keep
/// running (broken rollback is better than a hard exit because
/// "the rollback recovery itself failed").
///
/// Network errors fold into `Skipped` like the rest of the
/// updater paths so a flaky link can't crash the agent.
pub async fn pin_version(tag: &str) -> CheckOutcome {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let release = match fetch_release_by_tag(tag).await {
        Ok(r) => r,
        Err(e) => return failed(&format!("pin fetch {tag}"), e),
    };
    let asset = match pick_asset_for_platform(&release.assets) {
        Some(a) => a,
        None => {
            return CheckOutcome::Skipped(format!("no platform installer in release {tag}"));
        }
    };
    // Bound before the match so the borrow for the version check ends before
    // the arm moves the tag into the outcome.
    let downloaded = download_asset(asset, &release.tag_name).await;
    match downloaded {
        Ok(path) => CheckOutcome::UpdateReady {
            current,
            latest: release.tag_name,
            installer_path: path,
        },
        Err(e) => failed(&format!("pin download {tag}"), e),
    }
}

/// Run one check cycle: GET releases → compare → download if needed.
/// Returns the outcome so the caller can log + decide whether to
/// spawn the installer. Never panics; network errors fold into
/// `Unreachable(...)` (#1755) and verdicts into `Skipped(...)`, so a flaky
/// link doesn't crash the agent.
pub async fn check_once() -> CheckOutcome {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let release = match fetch_latest_release().await {
        Ok(r) => r,
        Err(e) => return failed("fetch", e),
    };
    // Drafts are always skipped; prereleases are tolerated because
    // our 0.x release history marked them all `prerelease: true` and
    // we want those agents to update even though GitHub's own
    // /releases/latest endpoint excludes them. pick_latest_release
    // has already filtered by tag prefix.
    if release.draft {
        return CheckOutcome::Skipped(format!("latest release is draft: {}", release.tag_name));
    }
    let latest_parsed = match parse_version(&release.tag_name) {
        Some(_) => release.tag_name.clone(),
        None => return CheckOutcome::Skipped(format!("unparseable tag {}", release.tag_name)),
    };
    if !is_newer(&latest_parsed, &current) {
        return CheckOutcome::UpToDate {
            current,
            latest: latest_parsed,
        };
    }
    let asset = match pick_asset_for_platform(&release.assets) {
        Some(a) => a,
        None => {
            return CheckOutcome::Skipped(format!(
                "no installer asset for this platform in release {latest_parsed}"
            ));
        }
    };
    let downloaded = download_asset(asset, &latest_parsed).await;
    match downloaded {
        Ok(path) => CheckOutcome::UpdateReady {
            current,
            latest: latest_parsed,
            installer_path: path,
        },
        Err(e) => failed("download", e),
    }
}

/// Spawn the installer detached. Returns after the installer is
/// running so the caller can `std::process::exit(0)` — the agent's
/// binary is about to be overwritten.
///
/// - **Windows**: `msiexec /i <path> /qn /norestart`. Requires
///   per-user MSI (no UAC) — which is what cargo-wix emits by
///   default for our install mode.
/// - **Linux**: `pkexec apt-get install -y <path>`. Requires policykit
///   plus sudo-equivalent; a non-interactive fallback uses
///   `dpkg --install` directly (works when run as the user who
///   owns /usr/bin, e.g. in a cargo-installed dev env).
/// - **macOS**: `installer -pkg <path> -target /` — the same target
///   `scripts/install.sh` uses. It must be the volume root: the payload
///   paths are absolute and the launchd plists name them literally.
pub fn spawn_installer(installer_path: &std::path::Path) -> Result<()> {
    spawn_installer_with_watch(installer_path, None)
}

/// Spawn the installer for `installer_path` AND, when an
/// `expected_version` tag is provided, spawn a sibling
/// `roomlerd post-install-watch` process that captures the
/// installer's exit code + verifies the new binary's `--version`.
///
/// The watcher must be spawned *before* this function returns so the
/// installer's PID is still in the process table; once the parent
/// agent exits the installer is reparented to init/explorer and the
/// watcher polls it from there.
///
/// `expected_version=None` keeps the legacy "fire and forget" path —
/// useful for tests and the manual `self-update` CLI where the
/// outcome JSON adds nothing the operator can't see directly.
pub fn spawn_installer_with_watch(
    installer_path: &std::path::Path,
    expected_version: Option<&str>,
) -> Result<()> {
    // FR-90 P1d-1 — a DEBUG build under ROOMLERD_UPDATE_DRY_RUN installs
    // nothing by ANY path. The periodic and pushed updates stop earlier, in
    // `act_on_outcome`; this also covers the crash-loop rollback and the CLI.
    // Its field checks run on workstations whose packaged daemon must not be
    // replaced. Not compiled into a release build.
    #[cfg(debug_assertions)]
    if std::env::var_os("ROOMLERD_UPDATE_DRY_RUN").is_some() {
        bail!(
            "ROOMLERD_UPDATE_DRY_RUN is set: this debug build installs nothing ({})",
            installer_path.display()
        );
    }
    // Touch the cooldown marker BEFORE spawning the installer. The
    // run_periodic loop in any newly-spawned sibling worker (typical
    // under SCM supervision) reads this marker on its first iteration
    // to skip the immediate update check. Without this, the worker
    // detects the same pending update, spawns another installer, and
    // we get an install-storm. Field repro: operator 2026-05-02.
    record_update_attempt();
    let spawned = spawn_installer_inner(installer_path)?;
    if let Some(tag) = expected_version
        && let Err(e) = spawn_watcher(spawned, installer_path, tag)
    {
        // Don't fail the whole self-update flow on a watcher spawn
        // failure — the installer is already running and the agent
        // is about to exit; we lose the outcome JSON but the user
        // still gets the upgrade.
        // `{:#}` not `%e`: the anyhow *chain*. The bare display shows only
        // "spawning post-install-watch subprocess" and hides the ENOENT that
        // actually explains it — which is why 21 consecutive failures read as
        // one uninformative line.
        tracing::warn!(
            error = format!("{e:#}"),
            "post-install watcher spawn failed"
        );
    }
    Ok(())
}

/// Build the msiexec argv for this MSI flavour. Pure so it's unit-
/// testable without spawning processes.
///
/// - **perUser**: `/qn` (fully silent — no UI, no UAC). The MSI's
///   `InstallScope='perUser'` doesn't require elevation, so silent
///   install works from any user-token process (Scheduled Task,
///   interactive shell).
/// - **perMachine**: ALSO `/qn` since rc.236. History: rc.18 chose
///   `/qb!` because a perMachine MSI spawned non-elevated with `/qn`
///   silently fails (2026-05-10 field repro — msiexec can't raise
///   UAC in silent mode). That rationale is obsolete: every
///   perMachine spawn now goes through `spawn_msiexec_elevated`
///   (`ShellExecuteExW` verb=runas), so elevation happens BEFORE
///   msiexec runs and `/qn` has no UAC left to suppress. And `/qb!`
///   turned out to be the root cause of the 5/5-reproduced
///   self-update wedge (rc.226→rc.235 on the dev host): upgrading
///   over the RUNNING service trips FilesInUse (MSI error 1607,
///   confirmed via /l*v — the server loops on `SELECT Message FROM
///   Error WHERE Error = 1607`), and basic UI can neither display
///   nor auto-answer that dialog → msiexec sits at "Gathering
///   required information…" forever. `/qn` lets Windows Installer
///   auto-resolve FilesInUse via RestartManager — the exact manual
///   recovery that worked 4/4.
///
/// Both flavours append `/l*v <installer>.log` — a verbose MSI log
/// next to the staged installer. Three field wedges (rc.226, rc.228,
/// rc.232 self-updates on the dev host: msiexec alive but never
/// exiting, service left stopped) were undiagnosable because silent
/// installs leave no trace; the log names the exact action a wedged
/// run was in. The staging dir is recycled per update, so the log
/// doesn't accumulate.
#[cfg(any(target_os = "windows", test))]
pub fn msiexec_argv(installer: &std::path::Path, flavour: WindowsInstallFlavour) -> Vec<String> {
    let path = installer.to_string_lossy().into_owned();
    let ui = match flavour {
        WindowsInstallFlavour::PerUser => "/qn",
        WindowsInstallFlavour::PerMachine => "/qn",
    };
    let log = format!("{path}.log");
    vec![
        "/i".to_string(),
        path,
        ui.to_string(),
        "/norestart".to_string(),
        "/l*v".to_string(),
        log,
    ]
}

/// rc.44: variant of [`msiexec_argv`] that appends operator-supplied
/// MSI public properties (`KEY=VALUE`) after the base argv. Used by
/// the install wizard to flip `ENABLE_SYSTEM_CONTEXT=1` when the
/// operator picks the `permachine-system-context` flavour.
///
/// Properties are appended verbatim — no shell-quoting, no escaping.
/// Callers must ensure `VALUE` contains no whitespace; msiexec's
/// public-property grammar is space-separated `KEY=VALUE` tokens.
///
/// cfg-gated to match [`msiexec_argv`] (which it calls) — `msiexec_argv`
/// is `cfg(any(windows, test))`, so an ungated wrapper fails the
/// Linux/macOS release build with `E0425: cannot find function
/// msiexec_argv`. The `test` arm keeps the unit tests below buildable
/// on every CI runner.
#[cfg(any(target_os = "windows", test))]
pub fn msiexec_argv_with_properties(
    installer: &std::path::Path,
    flavour: WindowsInstallFlavour,
    properties: &[(&str, &str)],
) -> Vec<String> {
    let mut argv = msiexec_argv(installer, flavour);
    for (k, v) in properties {
        argv.push(format!("{k}={v}"));
    }
    argv
}

/// What [`spawn_installer_inner`] observed: the installer's pid, and whether it
/// had ALREADY finished by the time we returned.
///
/// ⚠️ The flag is reported by the dispatch itself rather than re-derived from the
/// artifact name, so the two cannot drift apart — the same coupling rule as
/// `install_path_before_rename` and the installer's own `.prev` rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallerSpawn {
    pub pid: u32,
    /// True when the install completed synchronously inside this call, so the
    /// pid names either this process or a corpse. Waiting on it is never
    /// correct — see `post_install::should_wait_for_installer`.
    pub already_exited: bool,
}

pub fn spawn_installer_inner(installer_path: &std::path::Path) -> Result<InstallerSpawn> {
    // Auto-updater entry point: classify the RUNNING agent EXE's
    // location to decide whether the in-place MSI swap needs UAC
    // elevation. Correct for self-update because the running EXE
    // IS the install whose flavour we're matching.
    //
    // **DO NOT** call this from the install wizard. The wizard's EXE
    // runs from wherever the operator double-clicked (`%TEMP%`,
    // Downloads, Desktop) so [`current_install_flavour`] returns
    // `PerUser` regardless of the host install state OR the operator-
    // selected flavour, and a perMachine MSI launched non-elevated
    // exits with `1625 ERROR_INSTALL_PACKAGE_REJECTED`. Wizard callers
    // must use [`spawn_installer_for_flavour`] with the SPA-selected
    // [`WindowsInstallFlavour`]. Field repro 2026-05-15 on a Windows
    // field-test host; see BLOCKER B6 in the rc.27/rc.28 master plan.
    #[cfg(target_os = "windows")]
    {
        // msiexec runs asynchronously; the watcher must observe its exit and
        // `recover_wedged_install` depends on that wait.
        spawn_installer_as_flavour(installer_path, current_install_flavour()).map(|pid| {
            InstallerSpawn {
                pid,
                already_exited: false,
            }
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        spawn_installer_for_flavour_inner(installer_path).map(|pid| InstallerSpawn {
            pid,
            // ⚠️ Linux only. BOTH arms of the Linux dispatch complete before
            // returning — the tarball path installs inline and hands back
            // `std::process::id()`, the `.deb` path `wait()`s on its child.
            // macOS spawns `installer -pkg` and genuinely must be waited on.
            already_exited: cfg!(target_os = "linux"),
        })
    }
}

// RETIRED-NAME-ANCHOR: the pre-rename machine-global path this cleanup exists to
// find. docs/fr/FR-21
/// Windows auto-update spawn for a caller that already KNOWS the
/// flavour of the install being replaced. [`spawn_installer_inner`]
/// delegates here with the running EXE's classification; the
/// post-install watcher's wedge retry passes the `--origin-exe`
/// flavour instead, because the watcher runs from a staged copy in
/// the %TEMP% staging dir and its own path would misclassify as
/// PerUser (the same trap as the wizard, documented above).
///
/// rc.56 SystemContext-preserve hotfix lives here so BOTH callers
/// get it.
///
/// Without this branch, the WiX `DisableSystemContext` deferred
/// CA fires on every auto-update msiexec because the WiX
/// `ENABLE_SYSTEM_CONTEXT` property defaults to `'0'` and the
/// CA is conditioned on `ENABLE_SYSTEM_CONTEXT="0" AND NOT
/// (REMOVE="ALL")` (see `wix-perMachine/main.wxs:344-346`).
/// The CA runs `roomlerd disable-system-context` which
/// strips `ROOMLERD_ENABLE_SYSTEM_SWAP` from the SCM
/// Environment block and restarts the service. After auto-update
/// the supervisor sees env-var-off, doesn't perform the M3 A1
/// winlogon-token swap, and the resulting LocalSystem worker
/// tries to read its config from `%APPDATA%` (LocalSystem
/// profile, empty) instead of the rc.52 machine-global
/// `%PROGRAMDATA%\roomler\roomler-agent\config.toml` path. Net
/// effect: every SystemContext-enabled host that auto-updates
/// loses pre-logon capability and crash-loops until an operator
/// re-runs the wizard. Field-reproduced 2026-05-24 on WINHOST-A
/// (rc.55 → reinstall).
///
/// Fix: detect the env var BEFORE invoking msiexec and pass
/// `ENABLE_SYSTEM_CONTEXT=1` so the WiX `EnableSystemContext`
/// CA fires instead. The detection reads the SCM Environment
/// REG_MULTI_SZ via the rc.27 helper — robust whether the
/// SystemContext was enabled via the wizard, the
/// `enable-system-context` CLI subcommand, or a prior MSI run.
///
/// #1727: the MSI itself no longer defaults the property to `'0'`. With
/// nothing passed it keeps the mode the machine was last switched to
/// (`roomlerd keep-system-context`, from the product's record of the last
/// enable/disable), which is what saves a person running `msiexec` by
/// hand. This branch stays: the live Environment it reads is better
/// evidence than that record.
#[cfg(target_os = "windows")]
pub fn spawn_installer_as_flavour(
    installer_path: &std::path::Path,
    flavour: WindowsInstallFlavour,
) -> Result<u32> {
    let properties = preserve_system_context_property(flavour);
    let props_ref: Vec<(&str, &str)> = properties
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    spawn_installer_for_flavour_with_properties(installer_path, flavour, &props_ref)
}

/// rc.56: read the current SCM Environment block. If the perMachine
/// service has `ROOMLERD_ENABLE_SYSTEM_SWAP=1` set, return
/// `vec![("ENABLE_SYSTEM_CONTEXT", "1")]` so the auto-update msiexec
/// invocation re-asserts the env var via the WiX `EnableSystemContext`
/// CA instead of stripping it via `DisableSystemContext`.
///
/// Thin wrapper around [`preserve_system_context_property_for`] that
/// reads the SCM env block; the inner pure helper is unit-tested
/// against synthetic env-var values without an SCM dependency.
#[cfg(target_os = "windows")]
fn preserve_system_context_property(flavour: WindowsInstallFlavour) -> Vec<(String, String)> {
    let env_value =
        crate::win_service::environment::read_service_env_var("ROOMLERD_ENABLE_SYSTEM_SWAP")
            .map_err(|e| {
                tracing::warn!(
                    error = %e,
                    "updater: failed to read SCM env var ROOMLERD_ENABLE_SYSTEM_SWAP; \
                     not passing ENABLE_SYSTEM_CONTEXT to msiexec (auto-update will proceed \
                     but may strip SystemContext if it was enabled)"
                );
                format!("{e}")
            });
    let result = preserve_system_context_property_for(flavour, env_value);
    if !result.is_empty() {
        tracing::info!(
            "updater: detected ROOMLERD_ENABLE_SYSTEM_SWAP=1 in service env; \
             passing ENABLE_SYSTEM_CONTEXT=1 to msiexec to preserve SystemContext mode \
             across auto-update (rc.56 hotfix)"
        );
    }
    result
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn preserve_system_context_property(_flavour: WindowsInstallFlavour) -> Vec<(String, String)> {
    Vec::new()
}

/// rc.56 pure decision logic. Split from the SCM read so the rules
/// are unit-testable without mocking the registry.
///
/// Returns `vec![("ENABLE_SYSTEM_CONTEXT", "1")]` iff:
///   * flavour is PerMachine (perUser installs have no SCM service)
///   * env_value == Ok(Some("1")) — the SCM block has the swap on
///
/// All other paths return an empty vec (pass nothing to msiexec):
///   * PerUser flavour
///   * env var absent (plain perMachine install — DisableSystemContext
///     is a harmless idempotent no-op)
///   * env var present but != "1" (operator may have set a non-"1"
///     truthy variant the agent's `system_swap_enabled` accepts, but
///     the WiX CA condition compares strictly against the string
///     `"1"`; we follow WiX's strictness here)
///   * SCM read error (best-effort; falling back matches pre-rc.56
///     behaviour — `enable-system-context` CLI remains the manual
///     escape hatch)
//
// cfg-gate so the function is only compiled where it's actually
// reachable: on Windows (the SCM wrapper at line 869 calls it) and
// under `cfg(test)` (the unit tests at lines 1959+ exercise it
// directly without going through the Windows wrapper). Without the
// gate, the Linux clippy job fails with `-D dead_code` because the
// non-Windows `preserve_system_context_property` stub returns early
// and never reaches this helper. Pre-existing master regression
// repro'd in CI run 26375071253; fix landed alongside the
// tunnel-wizard feature so the branch's CI can be green.
#[cfg(any(target_os = "windows", test))]
fn preserve_system_context_property_for(
    flavour: WindowsInstallFlavour,
    env_value: Result<Option<String>, String>,
) -> Vec<(String, String)> {
    if flavour != WindowsInstallFlavour::PerMachine {
        return Vec::new();
    }
    match env_value {
        Ok(Some(v)) if v == "1" => vec![("ENABLE_SYSTEM_CONTEXT".to_string(), "1".to_string())],
        _ => Vec::new(),
    }
}

/// Launch the platform installer for a downloaded artefact, using the
/// CALLER-SUPPLIED flavour to choose the elevation path on Windows.
/// Non-Windows ignores the flavour (Linux + macOS don't have perUser /
/// perMachine MSI variants).
///
/// Use this entry point from the install wizard, which already knows
/// the operator-selected flavour from the SPA's radio cards. The
/// auto-updater path stays on [`spawn_installer_inner`] which infers
/// the flavour from the running EXE — correct for self-update because
/// the running EXE IS the install being replaced.
pub fn spawn_installer_for_flavour(
    installer_path: &std::path::Path,
    #[cfg(target_os = "windows")] flavour: WindowsInstallFlavour,
    #[cfg(not(target_os = "windows"))] _flavour: WindowsInstallFlavour,
) -> Result<u32> {
    #[cfg(target_os = "windows")]
    {
        spawn_installer_for_flavour_with_properties(installer_path, flavour, &[])
    }
    #[cfg(not(target_os = "windows"))]
    {
        spawn_installer_for_flavour_inner(installer_path)
    }
}

/// rc.44: variant of [`spawn_installer_for_flavour`] that passes
/// MSI public properties (e.g. `ENABLE_SYSTEM_CONTEXT=1`) to msiexec.
/// Used by the install wizard to drive the WiX
/// `EnableSystemContext` / `DisableSystemContext` deferred custom
/// actions added in rc.44 P2.
///
/// Non-Windows ignores both the flavour and the properties — there's
/// no msiexec on Linux/macOS, so the properties are not surfaceable
/// to the platform installer anyway.
pub fn spawn_installer_for_flavour_with_properties(
    installer_path: &std::path::Path,
    #[cfg(target_os = "windows")] flavour: WindowsInstallFlavour,
    #[cfg(not(target_os = "windows"))] _flavour: WindowsInstallFlavour,
    #[cfg(target_os = "windows")] properties: &[(&str, &str)],
    #[cfg(not(target_os = "windows"))] _properties: &[(&str, &str)],
) -> Result<u32> {
    #[cfg(target_os = "windows")]
    {
        let argv = msiexec_argv_with_properties(installer_path, flavour, properties);
        match flavour {
            WindowsInstallFlavour::PerUser => {
                // /qn silent install; non-elevated msiexec inherits
                // the user token and writes under %LOCALAPPDATA%.
                let child = std::process::Command::new("msiexec")
                    .args(argv.iter().map(String::as_str).collect::<Vec<_>>())
                    .spawn()
                    .context("spawning msiexec (perUser)")?;
                Ok(child.id())
            }
            WindowsInstallFlavour::PerMachine => {
                // Elevate via ShellExecuteExW + verb="runas" so UAC
                // prompts (when caller is non-elevated) AND so msiexec
                // gets the admin token it needs to write under
                // %ProgramFiles%. Field bug 2026-05-10 the field-test host: plain
                // `Command::new("msiexec").args(["/i", path, "/qn"])`
                // silently fails because /qn suppresses the UAC
                // prompt on a perMachine manifest.
                spawn_msiexec_elevated(&argv)
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        spawn_installer_for_flavour_inner(installer_path)
    }
}

/// The ordered `.deb` install commands to try, for a given effective uid.
///
/// Pure so the ordering is unit-testable without spawning anything (same
/// shape as [`msiexec_argv`] on the Windows side).
///
/// * **root** — install directly. No polkit, no sudo, nothing that can
///   prompt. `apt-get` first because it resolves the package's `depends`;
///   `dpkg` as the offline fallback when apt's lists are unusable.
/// * **non-root** — escalate. `pkexec` needs a polkit *authentication
///   agent*, which does NOT exist in a systemd service / headless / WSL
///   context; `sudo -n` needs a passwordless rule. Both routinely fail,
///   which is exactly why the caller must check the exit status.
///
/// The historical bug this replaces: the old code did `pkexec …spawn()`
/// and treated a successful *spawn* as a successful *install*, falling
/// back to `dpkg` only when the pkexec BINARY was missing. On any host
/// with pkexec installed but no polkit agent (every headless box), the
/// spawn succeeded, pkexec died immediately, nothing was installed, and
/// the agent exited anyway — a silent no-op that left field hosts pinned
/// to an old build across many update attempts.
#[cfg(any(target_os = "linux", test))]
fn linux_install_candidates(euid: u32, path: &str) -> Vec<(&'static str, Vec<String>)> {
    let apt = |prefix: Vec<&str>| {
        let mut a: Vec<String> = prefix.into_iter().map(String::from).collect();
        a.extend(["apt-get", "install", "-y", path].map(String::from));
        a
    };
    if euid == 0 {
        vec![
            ("apt-get", vec!["install".into(), "-y".into(), path.into()]),
            ("dpkg", vec!["--install".into(), path.into()]),
        ]
    } else {
        vec![("pkexec", apt(vec![])), ("sudo", apt(vec!["-n"]))]
    }
}

/// Run [`linux_install_candidates`] in order and return the pid of the
/// first one that exits 0.
///
/// Deliberately WAITS on each child instead of firing and forgetting:
/// dpkg replacing a running `/usr/bin/roomlerd` is safe on Linux (it
/// unlinks and recreates) and takes seconds, and waiting is the only way
/// to know the install actually happened. The returned pid belongs to an
/// already-exited process, which is what the post-install watcher expects
/// on Unix anyway: `wait_pid_unix` reads `ESRCH`, reports `Exited(0)`, and
/// `verify_new_binary` re-runs `--version` — now a truthful check, because
/// the install really did finish before we got here.
///
/// Every candidate failing is a hard `Err`, so `run_periodic`'s existing
/// "installer spawn failed; will retry next cycle" branch keeps the
/// daemon ALIVE rather than exiting into a pointless restart.
/// The payload members a tarball MUST carry, relative to its prefix dir.
/// Asserted before anything installed is touched — a truncated download that
/// cleared the size floor must not half-install a host.
#[cfg(target_os = "linux")]
const TARBALL_REQUIRED: &[&str] = &["usr/bin/roomlerd", "usr/bin/roomler"];

/// Units ship in the tarball but are only written when ABSENT. An upgrade
/// must never revert a unit the operator edited — the field host carries a
/// hand-written unit with `ROOMLERD_VIRTUAL_DESKTOP=1`, and silently
/// reverting that would be a data-loss-class bug. A package manager does not
/// clobber modified conffiles either.
#[cfg(target_os = "linux")]
const TARBALL_INSTALL_IF_ABSENT: &[&str] = &[
    "usr/lib/systemd/system/roomlerd.service",
    "usr/lib/systemd/user/roomler.service",
    // FR-96 — the update half of a per-user install.
    "usr/lib/systemd/system/roomler-update.service",
    "usr/lib/systemd/system/roomler-update.timer",
    "usr/lib/systemd/system/roomler-update.path",
    // RETIRED-NAME-ANCHOR: a path INSIDE the shipped .deb; moving it needs the
    // package layout to move with it. docs/fr/FR-21
    "usr/share/doc/roomler-agent/README.Debian",
];

/// Install the universal tarball — the path for hosts with no dpkg/apt.
///
/// Extract to a staging dir, verify the payload, then move each file into
/// place. Replacing a RUNNING executable is safe on Linux when done by
/// rename-over: the running process keeps its inode and only new execs see
/// the new file. That is what dpkg does, and why the .deb path has always
/// been able to replace a live `/usr/bin/roomlerd`.
///
/// Returns a pid to match `run_linux_install_candidates`' contract; the work
/// is synchronous, so it reports our own.
#[cfg(target_os = "linux")]
fn install_tarball_linux(euid: u32, tarball: &std::path::Path) -> Result<u32> {
    use std::path::Path;

    if euid != 0 {
        // Unlike the .deb path there is no pkexec/sudo helper to delegate to:
        // extracting into /usr needs the privilege directly. Say so plainly
        // rather than failing deep inside a copy.
        bail!(
            "the tarball install needs root (euid {euid}); run the agent as a \
             system service, or install {} manually",
            tarball.display()
        );
    }

    let stage = tarball.with_extension("stage");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).context("creating the staging dir")?;

    let st = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(tarball)
        .arg("-C")
        .arg(&stage)
        .status()
        .context("spawning tar (is it installed?)")?;
    if !st.success() {
        bail!(
            "tar exited {:?} extracting {}",
            st.code(),
            tarball.display()
        );
    }

    // The archive carries a single versioned prefix dir.
    let prefix = std::fs::read_dir(&stage)
        .context("reading the staging dir")?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .with_context(|| format!("{} contained no payload dir", tarball.display()))?;

    for rel in TARBALL_REQUIRED {
        let src = prefix.join(rel);
        if !src.is_file() {
            bail!(
                "tarball is missing {rel} — refusing to install a partial payload \
                 from {}",
                tarball.display()
            );
        }
    }

    let place = |rel: &str, only_if_absent: bool| -> Result<bool> {
        let src = prefix.join(rel);
        if !src.is_file() {
            return Ok(false);
        }
        let dst = Path::new("/").join(rel);
        if only_if_absent && dst.exists() {
            tracing::info!(path = %dst.display(), "update: keeping the existing file");
            return Ok(false);
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        // Stage beside the target so the rename is same-filesystem (atomic),
        // then swap. Copy-then-rename, never write-in-place: a partial write
        // over a live binary would brick the host.
        let tmp = dst.with_extension("new");
        std::fs::copy(&src, &tmp).with_context(|| format!("copying {rel}"))?;
        let mode = std::fs::metadata(&src)?.permissions();
        std::fs::set_permissions(&tmp, mode).with_context(|| format!("chmod {rel}"))?;
        // Keep the outgoing binary for the rollback path.
        if dst.exists() && rel.starts_with("usr/bin/") {
            let _ = std::fs::rename(&dst, dst.with_extension("prev"));
        }
        std::fs::rename(&tmp, &dst).with_context(|| format!("installing {rel}"))?;
        Ok(true)
    };

    let mut installed = 0usize;
    for rel in TARBALL_REQUIRED {
        if place(rel, false)? {
            installed += 1;
        }
    }
    // Bundled libs are discovered, not enumerated: the set differs per arch
    // (FFmpeg + libvpx on x86_64, libvpx alone on aarch64) and shrinks as
    // linkage is trimmed.
    // RETIRED-NAME-ANCHOR: RPATH-bound — the binary resolves its bundled FFmpeg from
    // this directory, so the name cannot move without relinking. docs/fr/FR-21
    let libdir = prefix.join("usr/lib/roomler-agent");
    if libdir.is_dir() {
        for entry in std::fs::read_dir(&libdir).context("reading the bundled libs")? {
            let entry = entry?;
            if entry.path().is_file() {
                let rel = format!(
                    // RETIRED-NAME-ANCHOR(2): the bundled-library directory is
                    // baked into the binary as an RPATH. It cannot move without
                    // a relink, so the updater must stage into the same name.
                    "usr/lib/roomler-agent/{}",
                    entry.file_name().to_string_lossy()
                );
                if place(&rel, false)? {
                    installed += 1;
                }
            }
        }
    }
    for rel in TARBALL_INSTALL_IF_ABSENT {
        if place(rel, true)? {
            installed += 1;
        }
    }

    let _ = std::fs::remove_dir_all(&stage);
    tracing::info!(
        installed,
        tarball = %tarball.display(),
        "update install: tarball installed"
    );
    Ok(std::process::id())
}

#[cfg(target_os = "linux")]
fn run_linux_install_candidates(euid: u32, path: &str) -> Result<u32> {
    let mut attempts: Vec<String> = Vec::new();
    for (bin, args) in linux_install_candidates(euid, path) {
        let mut child = match std::process::Command::new(bin).args(&args).spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(bin, error = %e, "update install: candidate not spawnable");
                attempts.push(format!("{bin}: not spawnable ({e})"));
                continue;
            }
        };
        let pid = child.id();
        match child.wait() {
            Ok(st) if st.success() => {
                tracing::info!(bin, euid, "update install: package installed");
                return Ok(pid);
            }
            Ok(st) => {
                // pkexec exits 127 when it cannot find an authentication
                // agent — the headless case that used to pass silently.
                tracing::warn!(bin, code = st.code(), "update install: candidate failed");
                attempts.push(format!("{bin}: exit {:?}", st.code()));
            }
            Err(e) => {
                tracing::warn!(bin, error = %e, "update install: wait failed");
                attempts.push(format!("{bin}: wait failed ({e})"));
            }
        }
    }
    bail!(
        "no usable way to install the .deb as uid {euid} (tried {}). \
         Run the daemon as root via the packaged `roomlerd.service` system \
         unit, or install manually: sudo dpkg -i {path}",
        attempts.join("; ")
    )
}

/// Linux + macOS spawn body shared between
/// [`spawn_installer_inner`] and [`spawn_installer_for_flavour`].
/// Flavour is irrelevant outside Windows.
#[cfg(not(target_os = "windows"))]
fn spawn_installer_for_flavour_inner(installer_path: &std::path::Path) -> Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let path_str = installer_path.to_string_lossy().into_owned();
        // SAFETY: `geteuid` is always-succeeding and takes no arguments.
        let euid = unsafe { libc::geteuid() };
        let result = if path_str.ends_with(".tar.gz") {
            install_tarball_linux(euid, installer_path)
        } else {
            run_linux_install_candidates(euid, &path_str)
        };
        // FR-96 review — the installer file has now been consumed (apt/dpkg
        // read it, the tarball was extracted and placed), and on Linux no
        // watcher ever re-runs it (that path is Windows-only, post_install.rs).
        // Remove our private per-download staging dir — ours alone, guarded by
        // the prefix so a wizard-supplied path outside temp_dir() is untouched.
        // Without this a fresh mkdtemp dir per download would accrete in /tmp.
        discard_staging(installer_path);
        result
    }
    #[cfg(target_os = "macos")]
    {
        let path_str = installer_path.to_string_lossy().into_owned();

        // `installer -target /` writes /Library and /usr/local, so it REFUSES
        // to run as anyone but root — "Must be run as root to install this
        // package" — and exits immediately.
        //
        // Checking first is not defensive politeness. `Command::spawn`
        // SUCCEEDS here regardless, because the process really does start; it
        // is the installer that then fails. So without this check the agent
        // reads a guaranteed failure as a successful handoff and exits 0 —
        // and the LaunchAgent's `KeepAlive{SuccessfulExit=false}` deliberately
        // does NOT restart a clean exit. The two behaviours are individually
        // right and together they take the device off the network until a
        // human intervenes.
        //
        // Field-hit 2026-08-25: a per-user agent attempting rc.467 -> rc.468
        // put a MacBook offline for ~25 minutes. `/var/log/install.log` had no
        // entry at all, because the installer never got far enough to log one
        // — which is also why it looked like a mysterious "failed handoff"
        // rather than a permission error.
        //
        // The per-user half legitimately CANNOT self-update on macOS: the pkg
        // is a system install. Returning Err routes into the caller's existing
        // failure path, which logs, raises the operator sentinel, and keeps
        // running on the current version — the correct outcome for an agent
        // that cannot update. On a two-half install the ROOT daemon updates
        // the shared bundle, so the host still moves forward.
        let euid = unsafe { libc::geteuid() };
        // RETIRED-NAME-ANCHOR(21): the pre-P4b /Applications/roomler-agent.app path
        // this sweep still has to name, plus the .app bundle itself, which keys the
        // TCC grants and stays frozen until P5b. The macOS LOG path is no longer
        // among them — FR-46 P5a moved it to /var/log/roomler. docs/fr/FR-46
        if euid != 0 {
            bail!(
                "refusing to self-update: `installer -target /` requires root, but this \
                 agent runs as uid {euid} (the per-user LaunchAgent). Exiting here would \
                 take the agent offline without installing anything. Updates on macOS are \
                 owned by the root update helper (com.roomler.update) — wake it with \
                 `touch {MACOS_UPDATE_TRIGGER}` and watch /var/log/roomler/update.log, \
                 or install by hand: `sudo installer -pkg <pkg> -target /`."
            );
        }

        // `-target /`, NOT `CurrentUserHomeDirectory`.
        //
        // RETIRED-NAME-ANCHOR(3): the PRE-P4b /Applications bundle, swept on upgrade.
        // Without the old name the vacated .app is orphaned forever. docs/fr/FR-21
        // The pkg's payload is absolute: /Applications/roomler-agent.app plus
        // /usr/local/bin/roomler, and BOTH launchd plists name the bundle path
        // literally. A home-directory install relocates the payload under
        // ~/Applications, so the update "succeeds" and launchd keeps starting
        // the OLD binary at the path it still points to — an update that
        // silently does nothing, on the one platform whose grants are keyed to
        // the binary. `/` is also what scripts/install.sh uses, so the update
        // path and the install path finally agree.
        let child = std::process::Command::new("installer")
            .args(["-pkg", &path_str, "-target", "/"])
            .spawn()
            .context("spawning installer(8)")?;
        Ok(child.id())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!(
            "self-update spawn is not implemented on this platform ({:?})",
            installer_path
        )
    }
}

/// Launch msiexec with UAC elevation via `ShellExecuteExW` + verb=
/// "runas". This is the perMachine path: the MSI's perMachine manifest
/// requires admin rights, the Scheduled-Task / interactive-shell caller
/// holds only a Limited token, so the OS must prompt for consent
/// before msiexec gets a privileged token.
///
/// Returns the spawned msiexec's PID for the post-install watcher.
/// Returns `Err` when UAC was declined OR no interactive session is
/// present to display the dialog — the caller surfaces this to the
/// operator (CLI: stderr message; service mode: log + retry next
/// cycle).
#[cfg(target_os = "windows")]
pub fn spawn_msiexec_elevated(argv: &[String]) -> Result<u32> {
    spawn_elevated("msiexec.exe", argv)
        .map_err(|e| e.context("elevated msiexec — install not started"))
}

/// FR-104 — [`spawn_msiexec_elevated`] for any program: `ShellExecuteExW`
/// with the `runas` verb, so Windows shows its administrator prompt, and the
/// PID of the elevated process. The setup wizard runs `roomlerd anchor
/// create` this way after it enrolls a machine-wide install: the anchor's
/// POST, and the SYSTEM service's credential it returns, must stay inside an
/// elevated process (FR-94 §4).
///
/// ⚠️ Arguments are joined with spaces; one that contains a space is quoted.
/// An argument containing a `"` is not escaped, so none may (paths, origins,
/// ids and JWTs never do).
#[cfg(target_os = "windows")]
pub fn spawn_elevated(file: &str, argv: &[String]) -> Result<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::System::Threading::GetProcessId;
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };

    // Build wide-string buffers for ShellExecuteExW. The Win32 API
    // wants null-terminated UTF-16; OsStr::encode_wide returns the
    // codepoints sans terminator so we append a 0.
    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
    // ShellExecuteExW takes the args concatenated as a single string with
    // spaces between. Paths are quoted to survive any embedded spaces
    // in the temp-dir / installer name. Other args are bare.
    let parameters = argv
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let verb_w = to_wide("runas");
    let file_w = to_wide(file);
    let params_w = to_wide(&parameters);

    // SAFETY: SHELLEXECUTEINFOW is a plain POD struct; zero-init is
    // valid. cbSize must match the struct size. All pointer fields
    // outlive the call (locals on the stack live until after
    // ShellExecuteExW returns). hProcess is initialised to NULL and
    // populated by the API on success because SEE_MASK_NOCLOSEPROCESS
    // is set.
    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = verb_w.as_ptr();
    sei.lpFile = file_w.as_ptr();
    sei.lpParameters = params_w.as_ptr();
    sei.nShow = 1; // SW_SHOWNORMAL — harmless under /qn (no UI to draw)

    // SAFETY: all required fields populated above; passing a valid
    // pointer to a stack-allocated struct.
    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        // ERROR_CANCELLED = 1223 is the UAC-declined code. Other
        // errors (file not found, etc.) surface as "elevation
        // failed (err N)" — operator can paste into the issue.
        if err == 1223 {
            bail!("the administrator prompt was declined (UAC)");
        }
        bail!("ShellExecuteExW(runas) failed (err {err})");
    }
    if sei.hProcess.is_null() {
        // The API returned success but didn't give us a process
        // handle. Documented behaviour for cases like: no interactive
        // session, the verb didn't actually launch anything, the
        // launched program is already running and DDE-merged into
        // an existing instance. None of those are recoverable here.
        bail!("ShellExecuteExW returned success but no process handle (no interactive session?)");
    }
    // SAFETY: hProcess is a valid HANDLE from a successful
    // SEE_MASK_NOCLOSEPROCESS call. We MUST CloseHandle after
    // GetProcessId; the OS would otherwise leak the kernel object
    // for the elevated process until the agent itself exits.
    let pid = unsafe { GetProcessId(sei.hProcess) };
    unsafe { CloseHandle(sei.hProcess) };
    if pid == 0 {
        bail!("GetProcessId on the elevated {file} returned 0");
    }
    Ok(pid)
}

/// The real install path, when `exe` is the outgoing binary the installer
/// has just renamed aside.
///
/// The Unix tarball installer keeps the previous image for rollback with
/// `rename(dst, dst.with_extension("prev"))`, and only *then* is the watcher
/// spawned — so `current_exe()` resolves through `/proc/self/exe` to
/// `<name>.prev`, the OLD binary. A watcher that verifies its own path
/// therefore reads the pre-update version and reports a mismatch for a
/// perfectly good install.
///
/// Stripping the suffix is the exact inverse of the rename above, so the two
/// cannot drift apart without this function's test failing.
///
/// Returns `None` when `exe` is not a `.prev` path — there is then nothing to
/// correct and the caller keeps its existing behaviour.
#[cfg(not(target_os = "windows"))]
fn install_path_before_rename(exe: &std::path::Path) -> Option<PathBuf> {
    if exe.extension().and_then(|e| e.to_str()) != Some("prev") {
        return None;
    }
    Some(exe.with_extension(""))
}

/// Recover the real path when `/proc/self/exe` has picked up Linux's
/// `" (deleted)"` marker.
///
/// ⚠️ This is why the `.deb` path has never had a post-install watcher. `apt`
/// replaces `/usr/bin/roomlerd`, which unlinks the running image, so from that
/// moment `current_exe()` reads `/usr/bin/roomlerd (deleted)` — a path that does
/// not exist. `Command::spawn` on it fails ENOENT and the watcher is never born.
/// Field-measured 2026-09-06: **21 `post-install watcher spawn failed` in 7 days
/// and zero `post-install watcher started`**, with `last-install.json` frozen
/// since August on every host on that path.
///
/// The marker is appended by the kernel to the readlink result, so stripping it
/// is the exact inverse and the two cannot drift.
///
/// Returns `None` when there is no marker to strip — the caller then keeps the
/// path it already had.
#[cfg(not(target_os = "windows"))]
fn strip_deleted_suffix(exe: &std::path::Path) -> Option<PathBuf> {
    const MARKER: &str = " (deleted)";
    let s = exe.to_str()?;
    let stripped = s.strip_suffix(MARKER)?;
    if stripped.is_empty() {
        return None;
    }
    Some(PathBuf::from(stripped))
}

fn spawn_watcher(
    spawned: InstallerSpawn,
    installer_path: &std::path::Path,
    expected_version: &str,
) -> Result<()> {
    let installer_pid = spawned.pid;
    let exe = std::env::current_exe().context("locating own exe for watcher spawn")?;
    // Windows: launch the watcher from a staged COPY so it doesn't
    // hold the install-dir image — RestartManager shuts down every
    // manageable process holding a file the MSI replaces, and a
    // watcher killed at install start defends nothing (field
    // forensic 2026-08-21: last-install.json frozen at InProgress,
    // watcher born 02:54:11, RM app-shutdown 02:54:12). Unix package
    // managers replace files without stopping readers, so the
    // in-place spawn stays correct there.
    #[cfg(target_os = "windows")]
    let (launch, staged) = stage_watcher_exe(&exe, installer_path);
    #[cfg(not(target_os = "windows"))]
    let (launch, staged) = (exe.clone(), false);
    // The image we are about to re-exec may have been replaced by the install
    // that just ran. Recover the real path, and refuse rather than hand
    // `Command` something that is not there — an ENOENT here is silent apart
    // from one context-less WARN, which is how this went unnoticed for months.
    #[cfg(not(target_os = "windows"))]
    let launch = match strip_deleted_suffix(&launch) {
        Some(real) if real.is_file() => {
            tracing::info!(
                was = %launch.display(),
                now = %real.display(),
                "watcher exe was replaced by the install; using the new image"
            );
            real
        }
        _ => launch,
    };
    #[cfg(not(target_os = "windows"))]
    if !launch.is_file() {
        anyhow::bail!(
            "watcher exe {} does not exist (the install replaced it and the path              could not be recovered)",
            launch.display()
        );
    }
    let mut cmd = std::process::Command::new(&launch);
    cmd.arg("post-install-watch")
        .arg("--installer-pid")
        .arg(installer_pid.to_string())
        .arg("--installer-path")
        .arg(installer_path)
        .arg("--expected-version")
        .arg(expected_version);
    if spawned.already_exited {
        cmd.arg("--installer-already-exited");
    }
    if staged {
        // The copy's own path misclassifies flavour (%TEMP% →
        // PerUser) and probes the wrong binary; hand it the real
        // install path explicitly.
        cmd.arg("--origin-exe").arg(&exe);
    }
    // Unix has the SAME problem for a different reason (#1206): the tarball
    // installer renames the outgoing binary to `<name>.prev` BEFORE spawning
    // the watcher, so the watcher's own path is the old image. Without this
    // the verdict is always `SucceededUnverified` — which is worse than
    // useless, because a genuinely broken install then looks exactly like a
    // healthy one.
    #[cfg(not(target_os = "windows"))]
    if let Some(origin) = install_path_before_rename(&exe).filter(|_| !staged) {
        cmd.arg("--origin-exe").arg(&origin);
    }
    let _child = cmd
        .spawn()
        .context("spawning post-install-watch subprocess")?;
    tracing::info!(
        watcher_exe = %launch.display(),
        staged,
        "post-install watcher spawned"
    );
    // We deliberately don't capture the Child — when the parent
    // agent exits, the watcher is reparented to init/explorer
    // (Unix) / orphaned (Windows, where there's no init). Either
    // way it runs to completion on its own.
    Ok(())
}

/// Copy the running daemon EXE into the update staging directory
/// (the installer's own directory) and return the path to launch the
/// watcher from, plus whether it IS a staged copy. Fallback chain:
/// fixed name → PID-suffixed name (a previous update's watcher may
/// still be running from the fixed name; copying onto a running
/// image fails with a sharing violation) → the original EXE
/// (pre-fix behaviour — a watcher RestartManager may kill beats no
/// watcher at all).
///
/// The name deliberately avoids the "install"/"setup"/"update"/
/// "patch" substrings (Windows UAC's installer-detection heuristic
/// auto-elevates EXEs matching them — the P4 lib-naming rule).
#[cfg(target_os = "windows")]
fn stage_watcher_exe(
    exe: &std::path::Path,
    installer_path: &std::path::Path,
) -> (std::path::PathBuf, bool) {
    let Some(staging) = installer_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    else {
        return (exe.to_path_buf(), false);
    };
    let fixed = staging.join("roomlerd-watch.exe");
    match std::fs::copy(exe, &fixed) {
        Ok(_) => return (fixed, true),
        Err(e) => {
            tracing::debug!(error = %e, dest = %fixed.display(), "watcher stage copy (fixed name) failed; trying pid-suffixed name")
        }
    }
    let suffixed = staging.join(format!("roomlerd-watch-{}.exe", std::process::id()));
    match std::fs::copy(exe, &suffixed) {
        Ok(_) => (suffixed, true),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "staging watcher copy failed; spawning watcher from the install-dir EXE \
                 (RestartManager may shut it down mid-install)"
            );
            (exe.to_path_buf(), false)
        }
    }
}

/// Resolve the effective update-check cadence for this run. Order:
///
/// 1. `ROOMLERD_UPDATE_INTERVAL_H` env var (parses an unsigned
///    integer count of hours; non-positive or non-numeric is ignored
///    so a typo can't accidentally disable updates).
/// 2. `update_check_interval_h` field on `AgentConfig`, if set.
/// 3. Built-in [`CHECK_INTERVAL`] (4 h).
///
/// Logged at startup for operator transparency. Pure resolver lives
/// in [`resolve_check_interval_with`] so tests don't have to mutate
/// process env (which races between parallel test runs).
pub fn resolve_check_interval(cfg: &crate::config::AgentConfig) -> Duration {
    let env_val = node_env("UPDATE_INTERVAL_H");
    resolve_check_interval_with(env_val.as_deref(), cfg.update_check_interval_h)
}

/// Pure cadence resolver. Mirrors the precedence documented on
/// [`resolve_check_interval`]; `env_value` is whatever the env var
/// would have parsed to (caller's responsibility), `cfg_value` is
/// the config-file field. Both default-to-fall-through on invalid
/// input so a typo in either layer can't disable updates.
pub(crate) fn resolve_check_interval_with(
    env_value: Option<&str>,
    cfg_value: Option<u32>,
) -> Duration {
    if let Some(s) = env_value
        && let Ok(h) = s.trim().parse::<u32>()
        && h > 0
    {
        return Duration::from_secs(u64::from(h) * 3600);
    }
    if let Some(h) = cfg_value
        && h > 0
    {
        return Duration::from_secs(u64::from(h) * 3600);
    }
    CHECK_INTERVAL
}

/// S1a — process-wide forced-update trigger. The WS handler
/// (`rc:agent.update`) calls [`request_update_now`]; the periodic loop
/// consumes the channel. A `OnceLock` (not a threaded parameter) so the
/// signaling stack's signatures stay untouched — one updater per
/// process makes the singleton honest.
static UPDATE_TRIGGER: std::sync::OnceLock<tokio::sync::mpsc::Sender<Option<String>>> =
    std::sync::OnceLock::new();

/// Create the forced-update trigger channel and register its sender — for
/// a daemon whose updater will run. Called once from `run_cmd`; the
/// receiver goes to [`run_periodic`].
///
/// ⚠️ #1689: with auto-update off, NOTHING is installed, so
/// [`request_update_now`] reports `false` and its callers say so (the
/// `rc:agent.update` arm warns the push was dropped). Installing it anyway
/// with the receiver merely unused — the doc once promised it would be
/// "simply dropped" — kept that receiver alive for the whole of `run_cmd`:
/// every push queued into a channel nobody reads and reported delivered,
/// while the device stayed where it was.
pub fn install_update_trigger(
    auto_update_enabled: bool,
) -> Option<tokio::sync::mpsc::Receiver<Option<String>>> {
    if !auto_update_enabled {
        return None;
    }
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let _ = UPDATE_TRIGGER.set(tx);
    Some(rx)
}

/// FR-67 P7 — what an enrollment's caps say about a pushed `rc:agent.update`
/// (`AgentCaps::update_mode`, stamped by `signaling::stub_caps` at every
/// announcement): `self` when it acts on one, `primary_org` on a secondary
/// enrollment (the `rc:agent.update` arm ignores it there), `off` when
/// auto-update is off (no trigger is installed, so the arm drops it). The
/// trigger is installed in `run_cmd` before any signalling loop starts, so a
/// hello always reads it settled.
pub fn update_mode(is_primary: bool) -> &'static str {
    update_mode_for(is_primary, UPDATE_TRIGGER.get().is_some())
}

/// [`update_mode`] as a pure function of its two facts.
pub(crate) fn update_mode_for(is_primary: bool, takes_triggers: bool) -> &'static str {
    if !is_primary {
        "primary_org"
    } else if !takes_triggers {
        "off"
    } else {
        "self"
    }
}

/// Request an immediate update cycle (server-pushed `rc:agent.update`).
/// `pin` = optional release tag; `None` = latest. Returns `false` when
/// nothing is listening (auto-update disabled, trigger not installed)
/// or the small queue is full.
pub fn request_update_now(pin: Option<String>) -> bool {
    match UPDATE_TRIGGER.get() {
        Some(tx) => tx.try_send(pin).is_ok(),
        None => false,
    }
}

/// Act on a check outcome: log, and on `UpdateReady` spawn the
/// installer + signal shutdown. Returns `true` when the loop should
/// exit (installer running, agent about to be replaced). Shared by the
/// periodic and forced paths.
fn act_on_outcome(outcome: CheckOutcome, shutdown_tx: &tokio::sync::watch::Sender<bool>) -> bool {
    match outcome {
        CheckOutcome::UpToDate { current, latest } => {
            tracing::info!(current = %current, latest = %latest, "up to date");
            false
        }
        CheckOutcome::UpdateReady {
            current,
            latest,
            installer_path,
        } => {
            // FR-90 P1d-1 — a DEBUG build's field check of the wait: it
            // downloads and waits exactly as a real update does, then installs
            // nothing (a debug daemon on a workstation must not replace the
            // packaged one there). Not compiled into a release build.
            #[cfg(debug_assertions)]
            if std::env::var_os("ROOMLERD_UPDATE_DRY_RUN").is_some() {
                tracing::warn!(
                    current = %current,
                    latest = %latest,
                    path = %installer_path.display(),
                    "auto-updater: DRY RUN — would spawn the installer now; nothing installed"
                );
                hold_agent_prompts(false);
                // FR-96 review — the dry run downloaded but will not install, so
                // nothing else will clean the private staging dir up.
                #[cfg(target_os = "linux")]
                discard_staging(&installer_path);
                return false;
            }
            tracing::warn!(
                current = %current,
                latest = %latest,
                path = %installer_path.display(),
                "new release available — spawning installer and exiting"
            );
            if let Err(e) = spawn_installer_with_watch(&installer_path, Some(&latest)) {
                tracing::error!(error = %e, "installer spawn failed; will retry next cycle");
                // FR-90 P1d-1 — no restart is coming: take agent prompts again.
                hold_agent_prompts(false);
                // A failed install is otherwise INVISIBLE: the version the
                // server sees simply never moves, which reads as "the update
                // button does nothing". Raise the same operator sentinel the
                // fatal-Goodbye path uses so the host says why.
                let _ = crate::notify::raise_attention_machine_aware(&format!(
                    "Self-update to {latest} failed and this node is still on {current}. {e}"
                ));
                return false;
            }
            let _ = shutdown_tx.send(true);
            true
        }
        CheckOutcome::Skipped(reason) => {
            tracing::info!(reason = %reason, "update check skipped");
            false
        }
        CheckOutcome::Unreachable(reason) => {
            tracing::info!(
                reason = %reason,
                "update check could not reach the release server"
            );
            false
        }
    }
}

/// Periodic update loop. Returns only on shutdown. Runs `check_once`
/// immediately, then on a fixed cadence. On `UpdateReady` the loop
/// spawns the installer and sends `true` on the shutdown channel so
/// the rest of the agent tears down cleanly.
///
/// `trigger_rx` (S1a) delivers operator-forced cycles pushed over the
/// WS (`rc:agent.update`): those bypass the transfer-defer gate (the
/// operator asked NOW; a warn is logged if transfers are active) but
/// still honour the install-storm cooldown marker.
pub async fn run_periodic(
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    interval: Duration,
    mut trigger_rx: tokio::sync::mpsc::Receiver<Option<String>>,
) {
    // macOS: the agent processes install NOTHING — `com.roomler.update`
    // (the root update helper) owns check+download+verify+install, and this
    // loop reduces to forwarding rc:agent.update triggers to its wake file.
    // A runtime `cfg!` (not an attribute) so both bodies stay type-checked
    // on every platform.
    if cfg!(target_os = "macos") {
        return forward_triggers(shutdown, trigger_rx).await;
    }
    // FR-96 P2a — Linux has the same root half, `roomler-update.service`, on a
    // host whose installer enabled it (P3: a per-user install). There a
    // per-user daemon installs nothing either: it cannot write /usr, which is
    // the whole of #2046. Decided once, here, at the daemon's start; a change
    // takes effect at the next one (install.sh restarts a daemon whose answer
    // it just made stale: `restart_old_user_daemon`).
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let enabled = helper_enable_link_in(&UPDATE_HELPER_ENABLE_LINKS.map(std::path::Path::new));
        let helper_switch = tunnel_core::env::flag("UPDATE_HELPER", true);
        match decide_update_owner(euid, helper_switch, enabled) {
            UpdateOwner::Helper(link) => {
                tracing::info!(
                    enabled_by = %link.display(),
                    "auto-updater: the root update helper (roomler-update.service) owns updates \
                     on this host — forwarding rc:agent.update to its wake file, installing nothing here"
                );
                // FR-117 P1 — the helper moves the companion package too, but on
                // its own timer. A skew this daemon can see (it reads the package
                // database as well) wakes it now: the restart after the helper
                // installed this very binary is exactly that moment.
                if crate::companion::package_needs_sync() {
                    match queue_update_check() {
                        Ok(()) => tracing::info!(
                            "auto-updater: the desktop companion is behind this daemon; woke the \
                             root update helper to move it"
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "auto-updater: could not wake the root update helper for the companion"
                        ),
                    }
                }
                return forward_triggers(shutdown, trigger_rx).await;
            }
            // FR-96 P5 — the helper is off, and nothing this daemon spawns can
            // elevate (its unit's NoNewPrivileges): the in-process path would
            // download every release only to fail pkexec and sudo. Wait for the
            // helper instead. Not under the kill switch: that one is AC7's
            // "today's behaviour exactly".
            UpdateOwner::InProcess(_)
                if helper_switch && !can_install_in_process(euid, no_new_privs()) =>
            {
                return wait_for_the_helper(shutdown, trigger_rx, interval).await;
            }
            UpdateOwner::InProcess(why) => {
                tracing::info!(%why, "auto-updater: this daemon installs its own updates");
            }
            // FR-96 P5 — the .deb enables the helper on every install, a system
            // install's too, and there it steps aside (`run_update_helper`).
            UpdateOwner::InProcessBesideHelper(link) => tracing::info!(
                enabled_by = %link.display(),
                "auto-updater: this root daemon installs its own updates; the root update helper is \
                 enabled here too (the .deb enables it) and steps aside for a system install"
            ),
        }
    }
    let mut first = true;
    let mut consecutive_defers: u32 = 0;
    // #1755 — checks in a row that failed on the transport.
    let mut transport_failures: u32 = 0;
    // The recheck the LAST defer chose (fast for a net transition, the
    // hour for transfers) or a transport failure's early retry (#1755);
    // `None` = full periodic interval.
    let mut defer_recheck: Option<Duration> = None;
    loop {
        if *shutdown.borrow() {
            return;
        }
        // Cooldown carve-out: if this worker started inside the
        // recent-install window (a previous instance just spawned an
        // installer), skip the immediate check and treat the loop as
        // if the periodic interval had already elapsed once. Prevents
        // the install-storm — see STARTUP_UPDATE_COOLDOWN doc.
        //
        // The log line is intentionally emitted *before* the sleep so
        // operators verifying the storm fix in the field can grep the
        // log for "suppressed by recent-install cooldown" within the
        // 5-min window — the previous (0.1.62) ordering put the log
        // *after* the 24h sleep, which made the suppression invisible
        // until the next periodic wake-up. Field repro on operator
        // 2026-05-02: cooldown was working (no storm) but verification
        // by grep failed because the line hadn't been written yet.
        let skip_first_check = first && recent_update_attempt(STARTUP_UPDATE_COOLDOWN);
        if skip_first_check {
            tracing::info!(
                cooldown_secs = STARTUP_UPDATE_COOLDOWN.as_secs(),
                "auto-updater: at-startup check suppressed by recent-install cooldown"
            );
            // FR-117 P1 — a daemon that just updated itself moves the companion
            // NOW, not after the full interval this cooldown makes it sleep.
            #[cfg(target_os = "linux")]
            crate::companion::sync_package().await;
        }
        // Last-iteration's defer (if any) shortens the sleep — the hour
        // for transfers, [`NET_DEFER_RECHECK`] for a network transition —
        // so the install fires soon after the gate clears instead of
        // waiting the full periodic interval again.
        let next_interval = defer_recheck.take().unwrap_or(interval);
        let mut forced: Option<Option<String>> = None;
        if !first || skip_first_check {
            tokio::select! {
                _ = tokio::time::sleep(next_interval) => {},
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                },
                maybe = trigger_rx.recv() => {
                    // Sender lives in the process-wide OnceLock, so None
                    // (channel closed) is unreachable in practice; guard
                    // anyway so a closed channel can't hot-loop us.
                    if let Some(pin) = maybe {
                        forced = Some(pin);
                    }
                },
            }
        }
        first = false;

        // S1a — operator-forced cycle (rc:agent.update). Bypasses the
        // transfer-defer gate (explicit operator intent) but keeps the
        // install-storm cooldown; a pinned tag skips the is-newer check
        // (pin_version semantics — the admin chose the version).
        if let Some(pin) = forced {
            if recent_update_attempt(STARTUP_UPDATE_COOLDOWN) {
                tracing::info!(
                    "forced update suppressed by recent-install cooldown; try again shortly"
                );
                continue;
            }
            let active = active_work();
            if active > 0 {
                tracing::warn!(
                    active,
                    "forced update proceeding despite in-flight file transfers or a recording"
                );
            }
            let outcome = match pin {
                Some(tag) => pin_version(&tag).await,
                None => check_once().await,
            };
            // FR-117 P1 — an operator's update moves the companion too: on a
            // device whose daemon is already current, the companion lagging
            // behind it is all there is to update.
            #[cfg(target_os = "linux")]
            if !matches!(outcome, CheckOutcome::UpdateReady { .. }) {
                crate::companion::sync_package().await;
            }
            let retry = recheck_after(&outcome, &mut transport_failures, interval);
            // FR-90 P1d-1 — even a pushed update waits for running agent
            // turns (bounded): a person asked for the update, not for their
            // agent to be cut mid-step.
            if matches!(outcome, CheckOutcome::UpdateReady { .. })
                && !wait_for_agent_turns(&mut shutdown, "auto-updater").await
            {
                return;
            }
            if act_on_outcome(outcome, &shutdown_tx) {
                return;
            }
            schedule_transport_retry(&mut defer_recheck, retry, transport_failures);
            continue;
        }

        // rc.19 gate: don't fire an installer while file transfers
        // are in flight. Pair with resumable transfers — even with
        // resume the install + restart kills the WebRTC peer for
        // several seconds, which is a UX nuisance. Skip the cycle
        // when active > 0 unless we've deferred MAX_CONSECUTIVE_DEFERS
        // times in a row (security-vs-uptime trade-off documented in
        // the rc.19 plan M3 fix).
        let active = active_work();
        let net_transition = net_transition_recent();
        match decide_defer(active, net_transition, consecutive_defers) {
            DeferDecision::DeferOnce => {
                consecutive_defers = consecutive_defers.saturating_add(1);
                // R5b — a transition defer rechecks fast (the network
                // settles in minutes); a transfer defer keeps its hour.
                let recheck = if net_transition && active == 0 {
                    NET_DEFER_RECHECK
                } else {
                    TRANSFER_DEFER_RECHECK
                };
                defer_recheck = Some(recheck);
                tracing::info!(
                    active,
                    net_transition,
                    consecutive_defers,
                    next_check_secs = recheck.as_secs(),
                    "auto-updater: deferring — transfers or a recording in flight, or the network just moved"
                );
                continue;
            }
            DeferDecision::ForceAfterDefers => {
                tracing::warn!(
                    active,
                    consecutive_defers,
                    "auto-updater: forcing update after {} consecutive defers",
                    MAX_CONSECUTIVE_DEFERS
                );
                consecutive_defers = 0;
                // Fall through to check_once.
            }
            DeferDecision::Proceed => {
                consecutive_defers = 0;
            }
        }

        let outcome = check_once().await;
        // FR-117 P1 — the companion package follows this daemon. Here, in the
        // loop that runs the daemon's own install and never beside it, so two
        // package-manager runs of ours can never contend for dpkg's lock. Not
        // when an update is about to install: this daemon is on its way out,
        // and the next one moves the companion to ITS version at its start.
        #[cfg(target_os = "linux")]
        if !matches!(outcome, CheckOutcome::UpdateReady { .. }) {
            crate::companion::sync_package().await;
        }
        let retry = recheck_after(&outcome, &mut transport_failures, interval);
        // FR-90 P1d-1 — AC7: the installer waits for running agent turns.
        if matches!(outcome, CheckOutcome::UpdateReady { .. })
            && !wait_for_agent_turns(&mut shutdown, "auto-updater").await
        {
            return;
        }
        if act_on_outcome(outcome, &shutdown_tx) {
            return;
        }
        schedule_transport_retry(&mut defer_recheck, retry, transport_failures);
    }
}

/// #1755 — arm the loop's next sleep for a transport failure's early retry.
fn schedule_transport_retry(
    defer_recheck: &mut Option<Duration>,
    retry: Option<Duration>,
    transport_failures: u32,
) {
    if let Some(after) = retry {
        tracing::info!(
            consecutive = transport_failures,
            next_check_secs = after.as_secs(),
            "auto-updater: rechecking early — the last check failed on the network"
        );
        *defer_recheck = Some(after);
    }
}

// ─── macOS update half (`com.roomler.update` + `update-helper`) ──────────
//
// `installer -target /` needs root and the DEFAULT macOS install is the
// per-user LaunchAgent alone, so an in-process self-update is structurally
// impossible there (and on two-half Macs the exit-to-update dance raced
// launchd — field 2026-08-24/25: four UpdateNow pushes knocked the MacBook
// offline). The fix is a THIRD launchd unit the pkg installs by default:
// a root, non-long-running helper that owns check+download+verify+install,
// with the agents reduced to touching a wake file. No agent process is ever
// the installer's parent and none exits for an update — the pkg postinstall
// re-bootstraps both halves.

/// The wake file the agents touch and `com.roomler.update`'s `WatchPaths`
/// watches. Lives in the sticky world-writable /var/tmp ON PURPOSE: the
/// per-user agent is not root, and the file is a pure WAKE SIGNAL —
/// **its content is deliberately ignored**. Anything else would hand every
/// local user a primitive: a pin honoured from here would let an
/// unprivileged writer make root install a GENUINE-BUT-OLD release (the
/// exact downgrade class `artifact_version` closed on Windows). Whoever
/// writes it can cause an update CHECK, never choose what gets installed.
pub const MACOS_UPDATE_TRIGGER: &str = "/private/var/tmp/roomler-update-check";

/// FR-96 — the Linux twin of [`MACOS_UPDATE_TRIGGER`], watched by
/// `roomler-update.path`. The same rules for the same reasons: a WAKE whose
/// content is never read.
pub const LINUX_UPDATE_TRIGGER: &str = "/var/tmp/roomler-update-check";

/// The wake file this platform's root update helper watches.
pub fn update_trigger_path() -> &'static str {
    if cfg!(target_os = "macos") {
        MACOS_UPDATE_TRIGGER
    } else {
        LINUX_UPDATE_TRIGGER
    }
}

/// FR-96 P2a — where `systemctl enable` (and `enable --runtime`) puts the
/// links for the root helper's two wake sources: each unit's `WantedBy=`
/// target's `.wants` directory (locked to the units by
/// `the_enable_links_are_where_systemctl_enable_puts_the_units`).
///
/// A file check, deliberately not `systemctl is-enabled`: it needs no bus and
/// no child process, and it reads the same under the per-user unit's sandbox.
#[cfg(target_os = "linux")]
const UPDATE_HELPER_ENABLE_LINKS: [&str; 4] = [
    "/etc/systemd/system/paths.target.wants/roomler-update.path",
    "/etc/systemd/system/timers.target.wants/roomler-update.timer",
    "/run/systemd/system/paths.target.wants/roomler-update.path",
    "/run/systemd/system/timers.target.wants/roomler-update.timer",
];

/// The first of `links` that leads to a unit file, if any — a host whose root
/// update helper is enabled.
///
/// `exists()` FOLLOWS the link, on purpose: a link left dangling by a removed
/// package is not an enabled helper, and treating it as one would stop this
/// daemon updating at all (it would forward wakes nobody hears).
#[cfg(target_os = "linux")]
fn helper_enable_link_in(links: &[&std::path::Path]) -> Option<PathBuf> {
    links.iter().find(|l| l.exists()).map(|l| l.to_path_buf())
}

/// FR-96 P5 — a system install: `roomlerd.service` (`WantedBy=multi-user.target`)
/// enabled, read by link as [`UPDATE_HELPER_ENABLE_LINKS`] reads the helper's.
/// The helper steps aside there, because that root daemon installs its own
/// updates. Locked to the unit by `the_system_daemon_links_are_its_install_target`.
#[cfg(target_os = "linux")]
const SYSTEM_DAEMON_ENABLE_LINKS: [&str; 2] = [
    "/etc/systemd/system/multi-user.target.wants/roomlerd.service",
    "/run/systemd/system/multi-user.target.wants/roomlerd.service",
];

/// FR-96 P5 — does this process run with `no_new_privs`? A per-user daemon
/// under its unit's `NoNewPrivileges=true` does. The kernel then ignores the
/// setuid bit of everything it spawns: pkexec says "must be setuid root", and
/// sudo says the flag "prevents sudo from running as root" (measured on Ubuntu
/// 26.04, 2026-10-15).
#[cfg(target_os = "linux")]
fn no_new_privs() -> bool {
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer and only reads a flag.
    unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 }
}

/// FR-96 P5 — can THIS process install a release itself? Root can. A non-root
/// process can try the `.deb` ladder (pkexec, then `sudo -n`) only without
/// `no_new_privs`: a daemon started by hand, say. Under its unit, nothing it
/// spawns can elevate. Pure, so the rule is a unit test.
#[cfg(target_os = "linux")]
fn can_install_in_process(euid: u32, no_new_privs: bool) -> bool {
    euid == 0 || !no_new_privs
}

/// FR-96 P5 — how often a daemon waiting for the helper looks for it: the
/// check is one `stat` per link.
#[cfg(target_os = "linux")]
const HELPER_RECHECK: Duration = Duration::from_secs(10 * 60);

/// What turns updates on for a daemon that cannot install them itself.
#[cfg(target_os = "linux")]
const ENABLE_THE_HELPER: &str = "sudo systemctl enable --now roomler-update.timer roomler-update.path \
    (or reinstall the .deb, or re-run install.sh)";

/// FR-96 P5 — the [`run_periodic`] body of a per-user daemon that cannot install
/// (it runs with `no_new_privs`) on a host whose root update helper is off.
///
/// It downloads nothing and installs nothing: the in-process path would fetch
/// every release only to fail pkexec and sudo. It says once what turns updates
/// on, and again for each push. It hands over to the helper as soon as one is
/// enabled, on the next push or within [`HELPER_RECHECK`], with no restart: that
/// push is forwarded, and so is every later one.
#[cfg(target_os = "linux")]
async fn wait_for_the_helper(
    shutdown: tokio::sync::watch::Receiver<bool>,
    trigger_rx: tokio::sync::mpsc::Receiver<Option<String>>,
    interval: Duration,
) {
    tracing::warn!(
        how = ENABLE_THE_HELPER,
        "auto-updater: this daemon cannot install updates — it runs with no_new_privs (its \
         unit's NoNewPrivileges), so pkexec and sudo cannot elevate — and the root update helper \
         is not enabled. Nothing is downloaded until the helper is on"
    );
    wait_for_the_helper_with(
        std::path::Path::new(LINUX_UPDATE_TRIGGER),
        || helper_enable_link_in(&UPDATE_HELPER_ENABLE_LINKS.map(std::path::Path::new)),
        interval.min(HELPER_RECHECK),
        shutdown,
        trigger_rx,
    )
    .await
}

/// [`wait_for_the_helper`] against an explicit wake path and helper probe, so
/// a test can turn the helper on mid-wait.
#[cfg(target_os = "linux")]
async fn wait_for_the_helper_with(
    wake: &std::path::Path,
    helper_on: impl Fn() -> Option<PathBuf>,
    recheck: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut trigger_rx: tokio::sync::mpsc::Receiver<Option<String>>,
) {
    loop {
        let pushed = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
                continue;
            }
            _ = tokio::time::sleep(recheck) => false,
            maybe = trigger_rx.recv() => {
                // The sender lives in a process-wide OnceLock, so a closed
                // channel is unreachable in practice; never hot-loop on one.
                if maybe.is_none() { return; }
                true
            }
        };
        let Some(link) = helper_on() else {
            if pushed {
                tracing::warn!(
                    how = ENABLE_THE_HELPER,
                    "rc:agent.update received, but this daemon cannot install updates and the root \
                     update helper is not enabled"
                );
            }
            continue;
        };
        tracing::info!(
            enabled_by = %link.display(),
            "auto-updater: the root update helper is enabled now — handing updates to it"
        );
        if pushed {
            match queue_update_check_at(wake) {
                Ok(()) => tracing::info!(
                    trigger = %wake.display(),
                    "rc:agent.update queued for the root update helper (roomler-update.service); \
                     watch `journalctl -u roomler-update.service`"
                ),
                Err(e) => tracing::warn!(error = %e, "could not write the update-helper wake file"),
            }
        }
        return forward_triggers_to(wake, shutdown, trigger_rx).await;
    }
}

/// Who installs this Linux daemon's updates (FR-96 P2a).
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq)]
enum UpdateOwner {
    /// The root helper; this daemon forwards pushes to its wake file. Carries
    /// the enable link that said so, for the log line.
    Helper(PathBuf),
    /// This daemon, in-process, as before FR-96 — and why.
    InProcess(&'static str),
    /// A ROOT daemon on a host whose helper is ALSO enabled. It keeps
    /// installing (AC4: a system install is unchanged), and the caller warns:
    /// two updaters can race on the package manager's lock.
    InProcessBesideHelper(PathBuf),
}

/// FR-96 P2a — pure, so every combination is a unit test.
///
/// - A **root** daemon installs its own updates, helper or not. The helper is
///   the root half of a PER-USER install; a system install already has one.
/// - `ROOMLERD_UPDATE_HELPER=0` (`helper_switch == false`) gives back today's
///   in-process path exactly — FR-96's kill switch.
/// - Otherwise a per-user daemon steps aside iff the helper is enabled.
///
/// ⚠️ The safe direction on doubt is IN-PROCESS: a wrong "helper" answer
/// freezes the host (it forwards wakes nobody hears — #2046 again), while a
/// wrong "in-process" answer costs a failed pkexec at most, and the helper's
/// own timer still runs if it exists.
#[cfg(target_os = "linux")]
fn decide_update_owner(euid: u32, helper_switch: bool, enabled_by: Option<PathBuf>) -> UpdateOwner {
    if euid == 0 {
        return match enabled_by {
            Some(link) => UpdateOwner::InProcessBesideHelper(link),
            None => UpdateOwner::InProcess("a root daemon installs its own updates"),
        };
    }
    if !helper_switch {
        return UpdateOwner::InProcess(
            "ROOMLERD_UPDATE_HELPER=0 — the in-process path, as before FR-96",
        );
    }
    match enabled_by {
        Some(link) => UpdateOwner::Helper(link),
        None => UpdateOwner::InProcess(
            "the root update helper is not enabled on this host (roomler-update.path / .timer)",
        ),
    }
}

/// Touch the update-helper wake file. Portable (plain fs) so the forwarder
/// type-checks on every platform; called at runtime on macOS, and on Linux by
/// a per-user daemon whose host has the root helper enabled (FR-96 P2a,
/// through [`forward_triggers`]).
///
/// O_NOFOLLOW + O_EXCL-free create: /var/tmp is sticky, another local user
/// could have planted a symlink at this exact name — refuse to write
/// through it rather than clobber whatever it points at with our bytes.
pub fn queue_update_check() -> std::io::Result<()> {
    queue_update_check_at(std::path::Path::new(update_trigger_path()))
}

/// [`queue_update_check`] against an explicit path, so the `O_NOFOLLOW` rule
/// can be exercised without touching the real `/var/tmp`.
pub(crate) fn queue_update_check_at(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(path)?;
    // Timestamp only — human courtesy for whoever cats the file. The helper
    // never reads it (see the const doc: content is not trusted).
    writeln!(f, "{}", chrono::Utc::now().to_rfc3339())
}

/// The [`run_periodic`] body wherever a root update helper owns updates:
/// forward every `rc:agent.update` trigger to the wake file and do nothing
/// else. The periodic cadence lives in the helper's own schedule (the plist's
/// `StartInterval` on macOS, `roomler-update.timer` on Linux) — ONE owner of
/// "check+download+verify+install", zero in-process installs.
///
/// Taken by every macOS agent, and from FR-96 P2a by a Linux per-user daemon
/// on a host whose helper is enabled ([`decide_update_owner`]). Compiles on
/// every platform (portable tokio + fs) so the whole updater keeps
/// type-checking in cross-platform CI lanes.
async fn forward_triggers(
    shutdown: tokio::sync::watch::Receiver<bool>,
    trigger_rx: tokio::sync::mpsc::Receiver<Option<String>>,
) {
    forward_triggers_to(
        std::path::Path::new(update_trigger_path()),
        shutdown,
        trigger_rx,
    )
    .await
}

/// [`forward_triggers`] against an explicit wake path, so a test can prove a
/// push writes the wake file and takes no install path at all.
async fn forward_triggers_to(
    wake: &std::path::Path,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut trigger_rx: tokio::sync::mpsc::Receiver<Option<String>>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
            }
            maybe = trigger_rx.recv() => {
                let Some(pin) = maybe else { return };
                if let Some(tag) = pin {
                    // Deliberate: pins do NOT cross the trigger boundary
                    // (see MACOS_UPDATE_TRIGGER — content is untrusted).
                    // The helper installs LATEST; a pinned downgrade is a
                    // manual root install by design, on both platforms.
                    if cfg!(target_os = "macos") {
                        tracing::warn!(
                            %tag,
                            "rc:agent.update pin ignored on macOS — the update helper installs \
                             the latest release; pinned installs are manual (sudo installer -pkg …)"
                        );
                    } else {
                        tracing::warn!(
                            %tag,
                            "rc:agent.update pin ignored — the root update helper \
                             (roomler-update.service) installs the latest release; a pinned \
                             install is manual (sudo apt-get install ./<deb>, or the tarball)"
                        );
                    }
                }
                // RETIRED-NAME-ANCHOR(2): the anchor now covers only this comment's own
                // mention of the legacy paths. FR-46 P5a moved the live strings below to
                // /var/log/roomler and /etc/roomler; the legacy /var/log/roomler-agent and
                // /etc/roomler-agent are migrated by the .pkg postinstall. docs/fr/FR-46
                match queue_update_check_at(wake) {
                    Ok(()) if cfg!(target_os = "macos") => tracing::info!(
                        trigger = %wake.display(),
                        "rc:agent.update queued for the root update helper (com.roomler.update); \
                         watch /var/log/roomler/update.log"
                    ),
                    Ok(()) => tracing::info!(
                        trigger = %wake.display(),
                        "rc:agent.update queued for the root update helper (roomler-update.service); \
                         watch `journalctl -u roomler-update.service`"
                    ),
                    Err(e) if cfg!(target_os = "macos") => tracing::warn!(
                        error = %e,
                        "could not write the update-helper wake file — if this Mac has \
                         /etc/roomler/disable-auto-update set, updates are manual"
                    ),
                    // FR-96 P2a — on Linux the likely cause is the unit's own
                    // sandbox: a `roomler.service` from before P2a has no
                    // `ReadWritePaths=-/var/tmp`, and ProtectSystem=strict makes
                    // /var/tmp read-only (EROFS) wherever the user manager
                    // applies it (Fedora). Nothing is lost but latency.
                    Err(e) => tracing::warn!(
                        error = %e,
                        wake = %wake.display(),
                        "could not write the update-helper wake file — the push waits for the \
                         helper's own timer (every 6 h). Read-only file system = this daemon's \
                         unit predates FR-96 P2a: re-run install.sh to refresh it"
                    ),
                }
            }
        }
    }
}

/// How long the update helper waits for the daemon's word before it installs
/// anyway (FR-90 P1h-2). The daemon bounds its own wait by the device's
/// `hive_update_wait_secs` (30 min by default); this is only the ceiling for
/// a daemon that never answers.
#[cfg(target_os = "macos")]
const HOLD_CEILING: Duration = Duration::from_secs(2 * 60 * 60);

/// What the update helper got from the daemon before installing (FR-90 P1h-2).
#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) enum InstallHold {
    /// The daemon holds, for as long as the helper keeps this client: until
    /// `installer(8)` returns.
    Held {
        _client: tunnel_core::localapi::Client,
        waited_secs: u64,
        cut: u32,
    },
    /// No hold, and why: no daemon here, one older than the verb, a refusal,
    /// or no answer in time. The install goes ahead as it did before P1h-2.
    Without(String),
}

/// FR-90 P1h-2 (AC7 on macOS) — ask the root daemon at `socket` to hold for
/// its agent turns before the helper's `installer(8)` restarts it, and every
/// harness with it. Fail-open by design: a missing, older or silent daemon
/// never keeps an update from installing; it gets the install it got before.
#[cfg(any(target_os = "macos", all(test, unix)))]
pub(crate) async fn hold_daemon_for_install(socket: PathBuf, ceiling: Duration) -> InstallHold {
    use tunnel_core::localapi::{Request, Response, connect_unix_at};
    let mut client = match connect_unix_at(socket).await {
        Ok(c) => c,
        Err(e) => return InstallHold::Without(format!("no daemon to hold ({e})")),
    };
    match tokio::time::timeout(ceiling, client.request(&Request::HiveUpdateHold)).await {
        Ok(Ok(Response::HiveUpdateHeld { waited_secs, cut })) => InstallHold::Held {
            _client: client,
            waited_secs,
            cut,
        },
        Ok(Ok(Response::Error { message })) => {
            InstallHold::Without(format!("the daemon holds nothing: {message}"))
        }
        Ok(Ok(_)) => InstallHold::Without("an answer this helper does not know".into()),
        Ok(Err(e)) => InstallHold::Without(format!("the daemon's answer was lost: {e}")),
        Err(_) => InstallHold::Without(format!("no answer within {} s", ceiling.as_secs())),
    }
}

/// `roomlerd update-helper` — the body of `com.roomler.update` on macOS, and
/// of `roomler-update.service` on Linux (FR-96).
///
/// Root-only, single-shot: consume the wake file, honour the opt-out marker
/// and the install-storm cooldown, then check → download → verify → install,
/// **waiting** on the install (unlike every agent-side spawn there is nothing
/// here the install replaces-and-restarts, so waiting is safe and gives the
/// real outcome).
/// - macOS: `installer -pkg … -target /`, whose postinstall restarts the agent
///   halves.
/// - Linux: the root ladder the in-process updater uses on a system install
///   (`apt-get`/`dpkg`, or the tarball's own placement). A per-user daemon runs
///   the new binary from its next restart.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub async fn run_update_helper() -> anyhow::Result<()> {
    use anyhow::bail;

    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!(
            "update-helper must run as root (launchd's system domain on macOS, \
             roomler-update.service on Linux); euid={euid}. It is the body of that \
             unit, not meant to be run by hand except as `sudo roomlerd update-helper`."
        );
    }

    // Consume the wake file FIRST, unconditionally, content unread, before any
    // gate below — so a wake that loses to the cooldown does not re-fire the
    // job, and a `systemctl stop` during the Linux gate's sleep finds the file
    // already gone and does not re-trigger the path unit.
    #[cfg(target_os = "macos")]
    {
        // launchd WatchPaths is edge-triggered and ThrottleInterval spaces
        // relaunches, so macOS needs no in-helper gate. `remove_file` never
        // follows a symlink, so a planted link is unlinked, not dereferenced.
        let _ = std::fs::remove_file(update_trigger_path());
    }
    #[cfg(target_os = "linux")]
    {
        match consume_wake(std::path::Path::new(LINUX_UPDATE_TRIGGER)) {
            WakeConsumed::Nothing | WakeConsumed::Removed => {}
            WakeConsumed::MovedAside { cleanup: None } => tracing::warn!(
                "update-helper: a non-file was planted at the wake path; moved aside and removed"
            ),
            WakeConsumed::MovedAside { cleanup: Some(e) } => tracing::warn!(
                error = %e,
                "update-helper: moved a planted wake-path entry aside but could not remove it"
            ),
            WakeConsumed::Stuck(e) => tracing::warn!(
                error = %e,
                path = LINUX_UPDATE_TRIGGER,
                "update-helper: could not consume the wake path (a mount point planted there?); \
                 continuing — the path unit does not fail, the helper re-runs each gap"
            ),
        }

        // launchd's ThrottleInterval twin: space runs ≥ UPDATE_HELPER_MIN_GAP
        // apart whatever a local user does to the wake path. BEFORE the opt-out
        // and cooldown early-exits below — else an opted-out or cooled-down host
        // would return in milliseconds per wake, and a re-touching user is back
        // at the path unit's trigger limit. A broken or absent stamp means the
        // FULL gap (fail-safe: it can only slow us, never let us spin).
        let now = std::time::SystemTime::now();
        let wait = match update_helper_gate_marker_path() {
            Some(stamp) => helper_gate_wait_at(&stamp, now, UPDATE_HELPER_MIN_GAP),
            None => {
                tracing::warn!(
                    "update-helper: no log dir for the run-spacing stamp; waiting the full gap"
                );
                UPDATE_HELPER_MIN_GAP
            }
        };
        if !wait.is_zero() {
            tracing::info!(
                wait_secs = wait.as_secs(),
                "update-helper: spacing this run from the last (ThrottleInterval twin)"
            );
            tokio::time::sleep(wait).await;
        }
        if let Some(stamp) = update_helper_gate_marker_path()
            && let Err(e) = stamp_helper_gate(&stamp)
        {
            tracing::warn!(
                error = %e,
                "update-helper: could not write the run-spacing stamp; the next run waits the full gap"
            );
        }
        // FR-96 P5 — the .deb enables this helper on every install, a system
        // install's too. There the root daemon installs its own updates, so the
        // helper steps aside: one updater per host, whoever enabled what. After
        // the gate, so a flood of wakes is still paced.
        if let Some(link) =
            helper_enable_link_in(&SYSTEM_DAEMON_ENABLE_LINKS.map(std::path::Path::new))
        {
            tracing::info!(
                enabled_by = %link.display(),
                "update-helper: a system install — its root daemon (roomlerd.service) installs its \
                 own updates; stepping aside"
            );
            return Ok(());
        }
    }

    // The operator's opt-out. postinstall removes the launchd unit when this
    // marker is set, but a loaded job can linger until reboot (it must not
    // bootout its own ancestor mid-install) — so the helper honours the
    // marker itself, making the lingering job harmless.
    // FR-46 P5a — dual-read, and the SENSE is what makes it mandatory: this is
    // an OPT-OUT. Reading only the current path would auto-update a Mac whose
    // operator opted out under the legacy one, which is the one outcome the
    // marker exists to prevent. The .pkg postinstall migrates the directory, so
    // the legacy arm is normally dead; it covers a host whose move could not
    // happen and a helper still running from before the migration.
    // RETIRED-NAME-ANCHOR(6): the legacy opt-out marker, honoured as a fallback.
    // Deletable once no Mac can still have one. docs/fr/FR-46
    const OPT_OUT: [&str; 2] = [
        "/etc/roomler/disable-auto-update",
        "/etc/roomler-agent/disable-auto-update",
    ];
    if let Some(marker) = OPT_OUT.iter().find(|p| std::path::Path::new(p).exists()) {
        tracing::info!(marker = %marker, "auto-update opted out — exiting");
        return Ok(());
    }

    // FR-117 P1 — the companion package follows the INSTALLED daemon, which is
    // this binary (the unit runs /usr/bin/roomlerd). Before the install
    // cooldown, which guards the DAEMON's install: the run a per-user daemon's
    // restart wakes right after an update is exactly the one that must move
    // the companion, and it always falls inside that cooldown. If this run then
    // installs a newer daemon, that daemon's restart wakes the next run.
    #[cfg(target_os = "linux")]
    crate::companion::sync_package().await;

    if recent_update_attempt(STARTUP_UPDATE_COOLDOWN) {
        tracing::info!(
            cooldown_secs = STARTUP_UPDATE_COOLDOWN.as_secs(),
            "update-helper: suppressed by recent-install cooldown"
        );
        return Ok(());
    }

    match check_once().await {
        CheckOutcome::UpToDate { current, latest } => {
            tracing::info!(%current, %latest, "update-helper: up to date");
            Ok(())
        }
        // #1755 — no early retry here: launchd owns this helper's cadence.
        CheckOutcome::Skipped(reason) | CheckOutcome::Unreachable(reason) => {
            tracing::info!(%reason, "update-helper: check skipped");
            Ok(())
        }
        CheckOutcome::UpdateReady {
            current,
            latest,
            installer_path,
        } => install_from_helper(current, latest, installer_path).await,
    }
}

/// The macOS helper's install: hold the root daemon, then `installer(8)`.
#[cfg(target_os = "macos")]
async fn install_from_helper(
    current: String,
    latest: String,
    installer_path: PathBuf,
) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    // FR-90 P1h-2 (AC7 on macOS) — the root daemon runs agent sessions, and
    // the install restarts it with every harness: hold it for its running
    // turns first, as the in-process updater does on Linux. The hold ends
    // when `hold` is dropped, right after the installer returns; a failed
    // install takes prompts again.
    let hold =
        hold_daemon_for_install(tunnel_core::localapi::system_socket_path(), HOLD_CEILING).await;
    match &hold {
        InstallHold::Held {
            waited_secs, cut, ..
        } => tracing::info!(
            waited_secs,
            cut,
            "update-helper: the daemon holds for its agent turns"
        ),
        InstallHold::Without(why) => {
            tracing::info!(%why, "update-helper: installing without a hold")
        }
    }
    record_update_attempt();
    tracing::warn!(
        %current,
        %latest,
        pkg = %installer_path.display(),
        "update-helper: installing (installer -pkg … -target /)"
    );
    let status = std::process::Command::new("installer")
        .args(["-pkg"])
        .arg(&installer_path)
        .args(["-target", "/"])
        .status()
        .context("running installer(8)");
    drop(hold);
    let status = status?;
    if !status.success() {
        // Same operator sentinel act_on_outcome raises: a failed install is
        // otherwise invisible — the fleet version simply never moves.
        let _ = crate::notify::raise_attention_machine_aware(&format!(
            "Self-update to {latest} failed (installer exited {status}) and this \
             Mac is still on {current}. See /var/log/install.log."
        ));
        bail!(
            "installer(8) exited {status} installing {latest}; this Mac stays on \
             {current}. Details: /var/log/install.log"
        );
    }
    tracing::info!(
        %latest,
        "update-helper: installed — postinstall re-bootstrapped the agent halves"
    );
    Ok(())
}

/// FR-96 — the Linux helper's install: the ROOT ladder the in-process updater
/// uses on a system install (`apt-get`/`dpkg` for the `.deb`, the tarball's own
/// placement), waited on, then the new binary asked its version.
///
/// No hold: the daemon this serves runs as the user, and is not restarted by
/// the install at all. It runs the new binary from its next restart (P2 asks
/// it to restart once idle).
#[cfg(target_os = "linux")]
async fn install_from_helper(
    current: String,
    latest: String,
    installer_path: PathBuf,
) -> anyhow::Result<()> {
    use anyhow::bail;
    record_update_attempt();
    tracing::warn!(
        %current,
        %latest,
        package = %installer_path.display(),
        "update-helper: installing as root"
    );
    // Both arms of the Linux install finish before they return (a `.deb` is
    // waited on, the tarball is placed in-process), so the outcome is known.
    let path = installer_path.clone();
    let installed = tokio::task::spawn_blocking(move || spawn_installer_for_flavour_inner(&path))
        .await
        .map_err(|e| anyhow::anyhow!("the install did not finish: {e}"))
        .and_then(|r| r);
    if let Err(e) = installed {
        let _ = crate::notify::raise_attention_machine_aware(&format!(
            "Self-update to {latest} failed ({e:#}) and this machine is still on {current}."
        ));
        bail!("installing {latest} failed: {e:#}; this machine stays on {current}");
    }
    // What a per-user daemon will run next: the installed binary itself.
    let version = std::process::Command::new("/usr/bin/roomlerd")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    match version {
        Some(v) if crate::post_install::version_matches(&v, &latest) => tracing::info!(
            %latest,
            installed = %v,
            "update-helper: installed and verified — a per-user daemon restarts onto it once idle \
             (FR-96 P2b; an older one, at its next restart)"
        ),
        other => tracing::warn!(
            %latest,
            installed = ?other,
            "update-helper: installed, but /usr/bin/roomlerd does not report the release it was given"
        ),
    }
    Ok(())
}

/// FR-96 P3 — what this binary's update half can do, one word per line, for
/// an installer to read before it enables a per-user install's root helper
/// (`roomlerd update-helper --capabilities`, which any user may run):
///
/// - `wake-file`: the root helper exists and consumes the wake file (P1).
/// - `step-aside`: a per-user daemon on a host whose helper is enabled
///   forwards pushes to it and installs nothing itself (P2a). Enabling the
///   helper beside a daemon WITHOUT this would put two updaters on one host,
///   so `install.sh` enables it only when the installed binary lists it.
/// - `restart-on-replace`: a per-user daemon restarts onto its replaced
///   binary once idle (P2b). `install.sh` asks the RUNNING image (through
///   `/proc/<pid>/exe`) and leaves the restart to it when it can.
///
/// ⚠️ A word is never renamed or removed, because an installer matches on it;
/// words are only added. `the_capabilities_are_the_words_install_sh_matches`
/// pins the pair.
#[cfg(target_os = "linux")]
pub const UPDATE_HELPER_CAPABILITIES: &[&str] = &["wake-file", "step-aside", "restart-on-replace"];
/// macOS: the agents have always forwarded to `com.roomler.update`.
#[cfg(target_os = "macos")]
pub const UPDATE_HELPER_CAPABILITIES: &[&str] = &["wake-file", "step-aside"];
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub const UPDATE_HELPER_CAPABILITIES: &[&str] = &[];

/// FR-96 P3 — is this command line exactly `roomlerd update-helper
/// --capabilities`? `install.sh` runs that form and no other, so nothing else
/// is answered before the command line is parsed.
pub fn is_capabilities_query<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut rest = args.into_iter().skip(1);
    match (rest.next(), rest.next(), rest.next()) {
        (Some(verb), Some(flag), None) => {
            verb.as_ref() == "update-helper" && flag.as_ref() == "--capabilities"
        }
        _ => false,
    }
}

/// Answers `update-helper --capabilities` when that is this process's command
/// line, one word per line, and says whether it did. `daemon_main` asks before
/// clap parses anything: see there for why.
pub fn answer_capabilities_query() -> bool {
    if !is_capabilities_query(std::env::args_os()) {
        return false;
    }
    for word in UPDATE_HELPER_CAPABILITIES {
        println!("{word}");
    }
    true
}

/// FR-96 P3 — P2a's decision for THIS process: the enable link when the root
/// update helper owns this host's updates (a non-root process, the kill switch
/// unset, the helper enabled), `None` when this process installs its own.
/// `self-update` asks it through the same [`decide_update_owner`] the daemon's
/// [`run_periodic`] uses, so the CLI and the daemon can never disagree about
/// who installs.
#[cfg(target_os = "linux")]
pub fn helper_owns_updates() -> Option<PathBuf> {
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let enabled = helper_enable_link_in(&UPDATE_HELPER_ENABLE_LINKS.map(std::path::Path::new));
    match decide_update_owner(euid, tunnel_core::env::flag("UPDATE_HELPER", true), enabled) {
        UpdateOwner::Helper(link) => Some(link),
        UpdateOwner::InProcess(_) | UpdateOwner::InProcessBesideHelper(_) => None,
    }
}

// RETIRED-NAME-ANCHOR-BEGIN
// The fixtures below are REAL published release-asset names. Rewriting them would
// make these tests assert against files that never existed, and the picker they
// exercise matches on exactly those strings.
// INVARIANT: a retired name here must be one that was actually shipped.
// docs/fr/FR-21
#[cfg(test)]
mod tests {
    /// FR-67 P7 — the hello's word for each case the `rc:agent.update` arm
    /// handles: a secondary ignores the push whatever its updater, a primary
    /// with no trigger drops it, and only a primary with one acts.
    #[test]
    fn update_mode_names_what_the_update_arm_will_do() {
        assert_eq!(super::update_mode_for(false, true), "primary_org");
        assert_eq!(super::update_mode_for(false, false), "primary_org");
        assert_eq!(super::update_mode_for(true, false), "off");
        assert_eq!(super::update_mode_for(true, true), "self");
    }

    /// #1689 — a daemon whose updater is off must report an `rc:agent.update`
    /// push as undeliverable, so the arm's "update trigger dropped" warning
    /// fires. RED-FIRST against the old wiring (install unconditionally, hold
    /// the receiver unread until `run_cmd` returns): this assertion failed
    /// there, as in the field on 2026-09-26 — `{"delivered":true}`, one INFO
    /// line, no update, no warning. Installing nothing is what makes a held,
    /// unread receiver impossible rather than merely avoided.
    ///
    /// ⚠️ `UPDATE_TRIGGER` is process-global and tests share one process: a
    /// future test here that calls `install_update_trigger(true)` makes this
    /// one fail at random. Give such a test its own process, or none at all.
    #[test]
    fn a_disabled_updater_reports_a_push_undeliverable() {
        assert!(
            super::install_update_trigger(false).is_none(),
            "a disabled updater must install no trigger"
        );
        assert!(
            !super::request_update_now(None),
            "a push to a daemon whose updater is off must report undeliverable"
        );
    }

    /// FR-90 P1h-2 — the macOS update helper holds the daemon for exactly as
    /// long as it keeps the hold (until `installer(8)` returns), and installs
    /// without one when nothing holds: no daemon, a daemon older than the
    /// verb, one that never answers. Run on every Unix: the client is not
    /// macOS's, only its caller is.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_update_helper_holds_the_daemon_while_it_installs() {
        use std::time::Duration;
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        // A short path: a Unix socket's name is capped at 104 bytes on macOS.
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();

        // A daemon that holds, and says when the helper lets go.
        let sock = dir.path().join("hold.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let (gone_tx, mut gone_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = s.into_split();
            let mut rd = BufReader::new(rd);
            let mut asked = String::new();
            rd.read_line(&mut asked).await.unwrap();
            wr.write_all(b"{\"t\":\"hive_update_held\",\"d\":{\"waited_secs\":12,\"cut\":1}}\n")
                .await
                .unwrap();
            let mut rest = Vec::new();
            let _ = rd.read_to_end(&mut rest).await;
            let _ = gone_tx.send(asked);
        });
        let hold = super::hold_daemon_for_install(sock, Duration::from_secs(5)).await;
        let super::InstallHold::Held {
            waited_secs, cut, ..
        } = &hold
        else {
            panic!("the daemon held")
        };
        assert_eq!((*waited_secs, *cut), (12, 1));
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut gone_rx)
                .await
                .is_err(),
            "held while the installer runs"
        );
        drop(hold);
        let asked = tokio::time::timeout(Duration::from_secs(5), gone_rx)
            .await
            .expect("the daemon sees the hold end")
            .unwrap();
        assert_eq!(asked.trim_end(), r#"{"t":"hive_update_hold"}"#);

        // No daemon at all.
        let none =
            super::hold_daemon_for_install(dir.path().join("none.sock"), Duration::from_secs(5))
                .await;
        assert!(matches!(&none, super::InstallHold::Without(w) if w.contains("no daemon")));

        // A daemon older than the verb.
        let old = dir.path().join("old.sock");
        let older = tokio::net::UnixListener::bind(&old).unwrap();
        tokio::spawn(async move {
            let (s, _) = older.accept().await.unwrap();
            let (rd, mut wr) = s.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            wr.write_all(
                b"{\"t\":\"error\",\"d\":{\"message\":\"bad request: unknown variant `hive_update_hold`\"}}\n",
            )
            .await
            .unwrap();
        });
        let old = super::hold_daemon_for_install(old, Duration::from_secs(5)).await;
        assert!(matches!(&old, super::InstallHold::Without(w) if w.contains("holds nothing")));

        // One that never answers: the ceiling, and the install goes ahead.
        let silent = dir.path().join("silent.sock");
        let mute = tokio::net::UnixListener::bind(&silent).unwrap();
        let _mute = tokio::spawn(async move {
            let (s, _) = mute.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        });
        let late = super::hold_daemon_for_install(silent, Duration::from_millis(300)).await;
        assert!(matches!(&late, super::InstallHold::Without(w) if w.contains("no answer")));
    }

    /// #1206 — the post-install watcher must verify the INSTALL path, never
    /// its own path.
    ///
    /// The Unix tarball installer renames the outgoing binary to `<name>.prev`
    /// for rollback and only then spawns the watcher, so `current_exe()`
    /// resolves to the OLD image. Verifying that path made every healthy
    /// tarball update record `SucceededUnverified` — and a verdict that is
    /// always the same cannot distinguish a broken install from a good one,
    /// which is the entire reason the check exists.
    ///
    /// ⚠️ The first assertion is the load-bearing one: it is the exact input
    /// observed in the field (`/usr/bin/roomlerd.prev`, expected 0.4.48,
    /// reported 0.4.45). The second guards the inverse — a path that was NOT
    /// renamed must yield `None` so the caller's existing behaviour is
    /// untouched on every other platform and flow.
    /// FR-67 P2 — the `.deb` path had no watcher at all, and this is why.
    ///
    /// `apt` replaces `/usr/bin/roomlerd`, unlinking the running image, so from
    /// that instant `current_exe()` reads `/usr/bin/roomlerd (deleted)`.
    /// `Command::spawn` on that path fails ENOENT and the watcher is never born.
    ///
    /// Field-measured on a cluster node, 2026-09-06: **21 `post-install watcher
    /// spawn failed` in seven days and ZERO `post-install watcher started`**,
    /// with `last-install.json` untouched since 2026-08-29 while the host had
    /// moved from 0.4.16 to 0.4.73.
    ///
    /// ⚠️ The suffix is appended by the kernel to the readlink result, so
    /// stripping it is the exact inverse — the same coupling rule that keeps
    /// `install_path_before_rename` honest against the installer's own rename.
    ///
    /// ⚠️ The negative cases matter as much: a path that merely *contains* the
    /// word, or ends in it without the leading space, must be left alone.
    /// Mangling a real path would turn a spawn failure into a spawn of the
    /// wrong binary, which is worse.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn a_deleted_exe_path_is_recovered_so_the_watcher_can_spawn() {
        use std::path::{Path, PathBuf};

        assert_eq!(
            strip_deleted_suffix(Path::new("/usr/bin/roomlerd (deleted)")),
            Some(PathBuf::from("/usr/bin/roomlerd")),
            "the field case: apt replaced the image, so /proc/self/exe carries the marker"
        );

        assert_eq!(
            strip_deleted_suffix(Path::new("/usr/bin/roomlerd")),
            None,
            "an ordinary path has nothing to strip and must be left alone"
        );

        assert_eq!(
            strip_deleted_suffix(Path::new("/opt/my (deleted) tools/roomlerd")),
            None,
            "the marker only counts as a SUFFIX; a path that merely contains it is real"
        );

        assert_eq!(
            strip_deleted_suffix(Path::new("/usr/bin/roomlerd(deleted)")),
            None,
            "without the separating space this is a legitimate filename, not a marker"
        );

        assert_eq!(
            strip_deleted_suffix(Path::new(" (deleted)")),
            None,
            "stripping must never yield an empty path"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn watcher_verifies_the_install_path_not_its_own_renamed_path() {
        use super::install_path_before_rename;
        use std::path::{Path, PathBuf};

        // The field case.
        assert_eq!(
            install_path_before_rename(Path::new("/usr/bin/roomlerd.prev")),
            Some(PathBuf::from("/usr/bin/roomlerd")),
            "a `.prev` watcher path must resolve to the binary the installer wrote"
        );

        // Not renamed => nothing to correct.
        assert_eq!(
            install_path_before_rename(Path::new("/usr/bin/roomlerd")),
            None,
            "a non-`.prev` path must be left alone rather than mangled"
        );

        // The inverse of the installer's own rename, so the two cannot drift.
        let dst = Path::new("/usr/bin/roomlerd");
        let renamed = dst.with_extension("prev");
        assert_eq!(
            install_path_before_rename(&renamed).as_deref(),
            Some(dst),
            "must be the exact inverse of the installer's with_extension(\"prev\")"
        );
    }

    use super::*;

    /// A non-root macOS agent must FAIL the spawn rather than report a
    /// successful handoff.
    ///
    /// This is the whole bug in one assertion: `installer -target /` cannot
    /// run as the per-user LaunchAgent, but `Command::spawn` succeeds anyway
    /// (the process starts, then dies), so the agent used to exit 0 — and
    /// `KeepAlive{SuccessfulExit=false}` then declines to restart it. An
    /// error here is what keeps the agent alive on the old version.
    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_to_self_update_when_not_root() {
        // Running as root is a legitimate configuration (the system daemon),
        // and there the guard correctly does not apply — so skip rather than
        // assert the opposite and make the test environment-dependent.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // The path is never touched: the euid check comes first, which is the
        // point — a guaranteed-doomed install must not even be attempted.
        let err = spawn_installer_inner(std::path::Path::new("/tmp/nonexistent-roomler.pkg"))
            .expect_err("a non-root self-update must be an error, not a handoff");
        let msg = err.to_string();
        assert!(
            msg.contains("requires root"),
            "the refusal must say WHY, so an operator reading the log knows the \
             update did not silently fail — got: {msg}"
        );
    }

    #[test]
    fn resolve_check_interval_default_is_24h() {
        assert_eq!(
            resolve_check_interval_with(None, None),
            CHECK_INTERVAL,
            "no env, no config → built-in default"
        );
    }

    #[test]
    fn resolve_check_interval_uses_config_field_when_no_env() {
        assert_eq!(
            resolve_check_interval_with(None, Some(168)),
            Duration::from_secs(168 * 3600),
            "weekly via config field"
        );
    }

    #[test]
    fn resolve_check_interval_env_overrides_config() {
        assert_eq!(
            resolve_check_interval_with(Some("6"), Some(168)),
            Duration::from_secs(6 * 3600),
            "env must win over config when both set"
        );
    }

    #[test]
    fn resolve_check_interval_ignores_invalid_env() {
        // A typo in the env var must NOT silently fall back to "no
        // updates" — it falls through to the config / default layers.
        assert_eq!(
            resolve_check_interval_with(Some("not-a-number"), Some(48)),
            Duration::from_secs(48 * 3600)
        );
    }

    #[test]
    fn resolve_check_interval_ignores_zero_env_and_zero_config() {
        // Zero is ambiguous ("disable?" vs "tight loop?"). Both
        // layers fall through; the built-in default ultimately wins.
        assert_eq!(
            resolve_check_interval_with(Some("0"), Some(48)),
            Duration::from_secs(48 * 3600),
            "zero env → fall through to config"
        );
        assert_eq!(
            resolve_check_interval_with(None, Some(0)),
            CHECK_INTERVAL,
            "zero config → fall through to default"
        );
    }

    #[test]
    fn resolve_check_interval_trims_env_whitespace() {
        assert_eq!(
            resolve_check_interval_with(Some(" 12 "), None),
            Duration::from_secs(12 * 3600)
        );
    }

    #[test]
    fn recent_update_attempt_at_returns_false_when_marker_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("update-attempt");
        // No file at `p`: the OS returns ENOENT, function returns false.
        assert!(!recent_update_attempt_at(&p, Duration::from_secs(300)));
    }

    #[test]
    fn recent_update_attempt_at_returns_true_when_marker_fresh() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("update-attempt");
        std::fs::write(&p, b"now").expect("write marker");
        // File just written: mtime is roughly Instant::now(); a 5-min
        // cooldown definitely covers a sub-millisecond elapsed.
        assert!(recent_update_attempt_at(&p, Duration::from_secs(300)));
    }

    #[test]
    fn recent_update_attempt_at_returns_false_when_cooldown_too_short() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("update-attempt");
        std::fs::write(&p, b"now").expect("write marker");
        // Cooldown == 0: no window can be fresh enough. Locks the
        // boundary: a pathological zero must not bypass the gate.
        assert!(!recent_update_attempt_at(&p, Duration::ZERO));
    }

    #[test]
    fn recent_update_attempt_at_returns_false_when_marker_old() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("update-attempt");
        std::fs::write(&p, b"now").expect("write marker");
        // Sleep past the (tiny) cooldown so elapsed > cooldown.
        std::thread::sleep(Duration::from_millis(60));
        assert!(!recent_update_attempt_at(&p, Duration::from_millis(20)));
    }

    #[test]
    fn startup_update_cooldown_is_five_minutes() {
        // Lock the value: any future "make it shorter to retry faster"
        // change should require an explicit reason to land. A too-short
        // cooldown re-opens the install-storm window from operator.
        assert_eq!(STARTUP_UPDATE_COOLDOWN, Duration::from_secs(300));
    }

    /// #1683 — the whole self-unenroll policy as one table. The
    /// `(ephemeral, os_initiated_stop, update_in_flight) = (true, true, true)`
    /// row is the MSI update's own service stop: the SCM host respawned a
    /// worker after the updater's exit-0, and the installer then stopped the
    /// service. Before the gate, the inline condition unenrolled the device on
    /// every auto-update and the new version came up holding a dead token.
    #[test]
    fn should_self_unenroll_only_on_an_os_stop_with_no_update_in_flight() {
        let table: [((bool, bool, bool), bool); 8] = [
            ((false, false, false), false),
            ((false, false, true), false),
            // A permanent device never removes itself, whatever stopped it.
            ((false, true, false), false),
            ((false, true, true), false),
            // The internal arm (the updater restarting us): never.
            ((true, false, false), false),
            ((true, false, true), false),
            // The ONE case: ephemeral, an OS/service-manager stop, no update.
            ((true, true, false), true),
            // The installer's own service stop: the device stays enrolled.
            ((true, true, true), false),
        ];
        for ((ephemeral, os_stop, in_flight), want) in table {
            assert_eq!(
                should_self_unenroll(ephemeral, os_stop, in_flight),
                want,
                "ephemeral={ephemeral} os_initiated_stop={os_stop} update_in_flight={in_flight}"
            );
        }
    }

    #[test]
    fn update_stop_window_is_ten_minutes_and_outlasts_the_startup_cooldown() {
        // Lock the value and its relation: the MSI's stop can lag the installer
        // spawn by minutes under EDR, and the window must not be shorter than
        // the startup cooldown that already reads a fresh marker as "an
        // install is in flight".
        assert_eq!(UPDATE_STOP_WINDOW, Duration::from_secs(600));
        assert!(UPDATE_STOP_WINDOW >= STARTUP_UPDATE_COOLDOWN);
    }

    #[test]
    fn verify_sha256_accepts_matching_digest() {
        // Known SHA256 of "hello" (sha256sum gives this).
        let bytes = b"hello";
        let digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(bytes, digest).is_ok());
    }

    #[test]
    fn verify_sha256_is_case_insensitive_on_hex() {
        let bytes = b"hello";
        let digest = "sha256:2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824";
        assert!(verify_sha256(bytes, digest).is_ok());
    }

    #[test]
    fn verify_sha256_rejects_mismatch() {
        let bytes = b"hello";
        let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let err = verify_sha256(bytes, digest).unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn verify_sha256_rejects_wrong_algorithm() {
        let bytes = b"hello";
        // sha512 of "hello" is *much* longer than 64 hex chars but
        // we don't even reach that check — the prefix mismatch
        // fires first.
        let digest = "sha512:abc";
        let err = verify_sha256(bytes, digest).unwrap_err();
        assert!(err.to_string().contains("unsupported digest algorithm"));
    }

    #[test]
    fn verify_sha256_rejects_malformed_length() {
        let bytes = b"hello";
        let digest = "sha256:abc"; // far too short
        let err = verify_sha256(bytes, digest).unwrap_err();
        assert!(err.to_string().contains("malformed sha256 digest length"));
    }

    #[test]
    fn verify_sha256_rejects_missing_prefix() {
        // A bare hex string without the `sha256:` prefix would slip
        // past a naive `strip_prefix`. Reject explicitly.
        let bytes = b"hello";
        let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let err = verify_sha256(bytes, digest).unwrap_err();
        assert!(err.to_string().contains("unsupported digest algorithm"));
    }

    #[test]
    fn parse_version_handles_agent_prefix_and_v_prefix() {
        assert_eq!(parse_version("agent-v0.1.36"), Some((0, 1, 36, u64::MAX)));
        assert_eq!(parse_version("v0.1.36"), Some((0, 1, 36, u64::MAX)));
        assert_eq!(parse_version("0.1.36"), Some((0, 1, 36, u64::MAX)));
    }

    #[test]
    fn parse_version_handles_final_and_rc_shapes() {
        // Final versions: pre rank = u64::MAX so they outrank rc.N.
        assert_eq!(parse_version("agent-v1.2.3"), Some((1, 2, 3, u64::MAX)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3, u64::MAX)));
        // rc.N with dot separator (current convention as of 0.3.0).
        assert_eq!(parse_version("agent-v0.3.0-rc.1"), Some((0, 3, 0, 1)));
        assert_eq!(parse_version("agent-v0.3.0-rc.4"), Some((0, 3, 0, 4)));
        // rc.N without dot separator (legacy `0.1.36-rc1` shape).
        assert_eq!(parse_version("v1.2.3-rc1"), Some((1, 2, 3, 1)));
        // rc.N with hyphen separator (semver-ish).
        assert_eq!(parse_version("v1.2.3-rc-7"), Some((1, 2, 3, 7)));
        // Build metadata or other pre-release labels rank as final
        // so a forward-compat `-beta.5` tag doesn't accidentally
        // rank below an rc.
        assert_eq!(parse_version("v1.2.3-beta.5"), Some((1, 2, 3, u64::MAX)));
    }

    #[test]
    fn parse_version_rejects_malformed() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("v1.2"), None);
        assert_eq!(parse_version("not-a-version"), None);
        assert_eq!(parse_version("v1.2.x"), None);
    }

    #[test]
    fn is_newer_compares_major_minor_patch() {
        assert!(is_newer("agent-v0.2.0", "agent-v0.1.99"));
        assert!(is_newer("agent-v0.1.36", "agent-v0.1.35"));
        assert!(is_newer("agent-v1.0.0", "agent-v0.99.99"));
        assert!(!is_newer("agent-v0.1.35", "agent-v0.1.35"));
        assert!(!is_newer("agent-v0.1.34", "agent-v0.1.35"));
    }

    #[test]
    fn is_newer_orders_rc_within_same_release() {
        // Field bug 2026-05-06: rc.3 vs rc.4 both parsed to (0,3,0)
        // and `is_newer(rc.4, rc.3)` returned false. Lock the contract.
        assert!(is_newer("agent-v0.3.0-rc.4", "agent-v0.3.0-rc.3"));
        assert!(is_newer("agent-v0.3.0-rc.10", "agent-v0.3.0-rc.9"));
        assert!(!is_newer("agent-v0.3.0-rc.3", "agent-v0.3.0-rc.4"));
        assert!(!is_newer("agent-v0.3.0-rc.4", "agent-v0.3.0-rc.4"));
    }

    #[test]
    fn is_newer_ranks_final_above_rc_of_same_release() {
        // Final 0.3.0 is newer than every 0.3.0-rc.N.
        assert!(is_newer("agent-v0.3.0", "agent-v0.3.0-rc.4"));
        assert!(is_newer("agent-v0.3.0", "agent-v0.3.0-rc.99"));
        // And final does NOT trigger downgrade if the running version
        // is already final.
        assert!(!is_newer("agent-v0.3.0-rc.99", "agent-v0.3.0"));
    }

    #[test]
    fn is_newer_handles_cross_release_with_rc() {
        // 0.2.7 (final) < 0.3.0-rc.1 (early rc of next minor).
        assert!(is_newer("agent-v0.3.0-rc.1", "agent-v0.2.7"));
        // 0.3.0-rc.99 (very late rc) < 0.3.1 (next patch).
        assert!(is_newer("agent-v0.3.1", "agent-v0.3.0-rc.99"));
    }

    #[test]
    fn is_newer_refuses_downgrade_on_parse_failure() {
        // A malformed "latest" tag must NOT trigger a downgrade.
        assert!(!is_newer("bogus", "agent-v0.1.35"));
        assert!(!is_newer("agent-v0.1.36", "bogus"));
    }

    #[test]
    fn pick_asset_matches_platform_extension() {
        let assets = vec![
            GithubAsset {
                name: "roomler-agent-0.1.36-x86_64-pc-windows-msvc-unsigned.msi".into(),
                browser_download_url: "https://example.invalid/foo.msi".into(),
                size: 1234,
                digest: None,
            },
            GithubAsset {
                name: "roomler-agent-0.1.36_amd64.deb".into(),
                browser_download_url: "https://example.invalid/foo.deb".into(),
                size: 2345,
                digest: None,
            },
            // Both Linux arches, so this stays meaningful wherever it runs.
            // The fixture used to carry only the amd64 .deb, which quietly
            // assumed an x86_64 host — it fails on an aarch64 Linux box
            // (found by running this suite on a real arm64 agent, a target
            // CI has no job for).
            GithubAsset {
                name: "roomler-agent-0.1.36-aarch64-unknown-linux-gnu.deb".into(),
                browser_download_url: "https://example.invalid/foo-arm64.deb".into(),
                size: 2346,
                digest: None,
            },
            // Both Linux FORMATS too. `pick_asset_for_platform` consults the
            // host for dpkg/apt, so a .deb-only fixture makes this test pass
            // on Debian CI and fail on a Fedora box — an environment-dependent
            // test, which is how the arch assumption above hid for so long.
            // Carrying both keeps the assertion about the PLATFORM, not about
            // whatever package manager the runner happens to have.
            GithubAsset {
                name: "roomler-agent-0.1.36-x86_64-unknown-linux-gnu.tar.gz".into(),
                browser_download_url: "https://example.invalid/foo.tgz".into(),
                size: 2347,
                digest: None,
            },
            GithubAsset {
                name: "roomler-agent-0.1.36-aarch64-unknown-linux-gnu.tar.gz".into(),
                browser_download_url: "https://example.invalid/foo-arm64.tgz".into(),
                size: 2348,
                digest: None,
            },
            GithubAsset {
                name: "roomler-agent-0.1.36-x86_64-apple-darwin.pkg".into(),
                browser_download_url: "https://example.invalid/foo.pkg".into(),
                size: 3456,
                digest: None,
            },
        ];
        let pick = pick_asset_for_platform(&assets);
        assert!(pick.is_some(), "expected a pick on this platform");
        let name = &pick.unwrap().name;
        #[cfg(target_os = "windows")]
        assert!(name.ends_with(".msi"));
        #[cfg(target_os = "linux")]
        {
            // Either Linux format is correct — which one depends on whether
            // THIS host can run dpkg, which is not what this test is about.
            assert!(
                name.ends_with(".deb") || name.ends_with(".tar.gz"),
                "linux host took {name}"
            );
            // …and the one built for THIS arch, never the sibling.
            #[cfg(target_arch = "x86_64")]
            assert!(!name.contains("aarch64"), "x86_64 host picked {name}");
            #[cfg(target_arch = "aarch64")]
            assert!(name.contains("aarch64"), "aarch64 host picked {name}");
        }
        #[cfg(target_os = "macos")]
        assert!(name.ends_with(".pkg"));
        let _ = name; // silence unused warning on non-matched targets
    }

    // ── FR-96: the Linux update half ─────────────────────────────────

    /// The path unit must watch exactly the file the helper consumes and the
    /// per-user daemon touches. Three copies of one string; drift between them
    /// would leave every wake unheard, with nothing failing anywhere.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_update_units_watch_the_helper_wake_file() {
        assert_eq!(update_trigger_path(), LINUX_UPDATE_TRIGGER);
        let path_unit = include_str!("../packaging/linux/roomler-update.path");
        let watch = format!("PathExists={LINUX_UPDATE_TRIGGER}");
        assert!(
            path_unit.lines().any(|l| l.trim() == watch.as_str()),
            "roomler-update.path must watch {LINUX_UPDATE_TRIGGER}"
        );
        assert!(
            path_unit
                .lines()
                .any(|l| l.trim() == "Unit=roomler-update.service")
        );
        let service = include_str!("../packaging/linux/roomler-update.service");
        assert!(service.lines().any(|l| l.trim() == "Type=oneshot"));
        assert!(
            service
                .lines()
                .any(|l| l.trim() == "ExecStart=/usr/bin/roomlerd update-helper"),
            "roomler-update.service must run the helper"
        );
        // Woken by its timer and its path, never enabled on its own.
        assert!(!service.contains("[Install]"));
        // FR-96 review — the guards that keep a local user from wedging the
        // path unit (a touch burst, or an exec-failing helper). See the unit
        // comments for the measured cliffs these remove.
        assert!(
            service
                .lines()
                .any(|l| l.trim() == "StartLimitIntervalSec=0"),
            "the service must disable the start limit"
        );
        assert!(
            service.lines().any(|l| l.trim() == "Restart=on-failure"),
            "an exec-failing helper must auto-restart, not fail the path unit"
        );
        assert!(service.lines().any(|l| l.trim() == "RestartSec=60s"));
        assert!(
            !service
                .lines()
                .any(|l| l.trim_start().starts_with("PrivateTmp")),
            "PrivateTmp as a directive would hide /var/tmp; the wake could never be consumed \
             (the comment naming it is fine)"
        );
        let timer = include_str!("../packaging/linux/roomler-update.timer");
        assert!(timer.lines().any(|l| l.trim() == "OnUnitActiveSec=6h"));
        assert!(
            timer.lines().any(|l| l.trim() == "OnBootSec=5min"),
            "the first run: OnUnitActiveSec counts from a run, so without OnBootSec a timer \
             started after boot (by the .deb's postinst, or install.sh) would never fire. An \
             OnBootSec already past elapses at once"
        );
        assert!(timer.lines().any(|l| l.trim() == "WantedBy=timers.target"));
    }

    /// Every unit ships in both packages, and the tarball installs each only
    /// where absent, so an operator's edit survives an upgrade.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_update_units_ship_in_the_deb_and_the_tarball() {
        let cargo = include_str!("../Cargo.toml");
        let stage = include_str!("../../../scripts/stage-linux-tarball.sh");
        // The stage script installs all three in one loop line — assert once,
        // not per unit (it does not vary with `unit`).
        assert!(
            stage.contains("roomler-update.service roomler-update.timer roomler-update.path"),
            "the tarball stage must ship the three update units"
        );
        for unit in [
            "roomler-update.service",
            "roomler-update.timer",
            "roomler-update.path",
        ] {
            let dest = format!("usr/lib/systemd/system/{unit}");
            assert!(
                cargo.contains(&format!(r#"["packaging/linux/{unit}", "{dest}", "644"]"#)),
                "the .deb assets must ship {unit}"
            );
            assert!(
                TARBALL_INSTALL_IF_ABSENT.contains(&dest.as_str()),
                "the tarball installs {unit} only where absent"
            );
        }
    }

    /// The helper is root's alone. Run as anyone else it refuses before it
    /// touches the wake file, the network or the install.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_update_helper_refuses_to_run_as_anyone_but_root() {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            // A root runner would go on to the network; the refusal is the
            // only thing under test here.
            return;
        }
        let err = run_update_helper().await.expect_err("must refuse non-root");
        assert!(
            err.to_string().contains("must run as root"),
            "unexpected refusal: {err:#}"
        );
    }

    // ── FR-96 security review (#2055): the private staging dir ───────

    /// Every download gets its own directory, 0755 and owned by the caller, so
    /// no other local user can swap the installer between its verification and
    /// the installer's own read of the path.
    #[cfg(target_os = "linux")]
    #[test]
    fn staging_dir_is_fresh_private_and_ours() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let a = stage_dir().expect("stage_dir a");
        let b = stage_dir().expect("stage_dir b");
        assert_ne!(a, b, "each download gets a fresh directory");
        for d in [&a, &b] {
            assert!(
                is_staging_dir(d),
                "our own dir is recognised: {}",
                d.display()
            );
            let meta = std::fs::metadata(d).expect("stat");
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o755,
                "staging dir is 0755"
            );
            // SAFETY: geteuid takes no arguments and cannot fail.
            assert_eq!(
                meta.uid(),
                unsafe { libc::geteuid() },
                "owned by the caller"
            );
        }
        assert!(
            !is_staging_dir(std::env::temp_dir().as_path()),
            "temp_dir itself is not one of ours"
        );
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// The write refuses anything already at the name — a planted symlink
    /// (never followed) or a planted file (never truncated).
    #[cfg(target_os = "linux")]
    #[test]
    fn write_installer_refuses_a_planted_symlink_and_a_planted_file() {
        use std::io::ErrorKind;
        let tmp = tempfile::tempdir().expect("tempdir");
        // A symlink at the target: refused, and NOT written through.
        let canary = tmp.path().join("canary");
        std::fs::write(&canary, b"original").expect("canary");
        let link = tmp.path().join("installer-link");
        std::os::unix::fs::symlink(&canary, &link).expect("symlink");
        let err = write_installer(&link, b"payload").expect_err("must refuse a symlink");
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"original",
            "the symlink target was not written through"
        );
        // A plain file at the target: refused, NOT truncated.
        let existing = tmp.path().join("installer");
        std::fs::write(&existing, b"existing").expect("existing");
        let err = write_installer(&existing, b"payload").expect_err("must refuse an existing file");
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            b"existing",
            "not truncated"
        );
    }

    /// Cleanup removes our own staging dir whole, and refuses to touch anything
    /// that is not ours (a wrong-prefix sibling, a path outside temp_dir()).
    #[cfg(target_os = "linux")]
    #[test]
    fn discard_staging_removes_only_our_own_dir() {
        // Our own dir, with the installer in it: removed whole.
        let ours = stage_dir().expect("stage_dir");
        let installer = ours.join("roomlerd-0.4.0-x86_64-unknown-linux-gnu.deb");
        std::fs::write(&installer, b"x").expect("write installer");
        discard_staging(&installer);
        assert!(!ours.exists(), "our own staging dir is removed");

        // A sibling in temp_dir() with a DIFFERENT prefix: left alone.
        let not_ours = tempfile::Builder::new()
            .prefix("not-ours.")
            .tempdir_in(std::env::temp_dir())
            .expect("not-ours dir");
        let other = not_ours.path().join("foo.deb");
        std::fs::write(&other, b"y").expect("write other");
        discard_staging(&other);
        assert!(other.exists(), "a dir that is not ours is left alone");

        // A path whose parent is not a staging dir at all: a no-op, no panic.
        discard_staging(std::path::Path::new("/usr/bin/roomlerd"));
    }

    // ── GHSA-r3xj-4wh9-xh2v: the Windows private staging dir ──────────

    /// Every download gets its own directory, recognised by [`is_staging_dir`]
    /// and never the shared legacy name — exercised through the real
    /// [`stage_dir`] dispatcher, so this passes whichever branch the test
    /// process's own identity happens to route through (ordinary dev/CI
    /// accounts take the non-SYSTEM path; a field-verification run as SYSTEM
    /// — see the advisory's own field-verification note — takes the hardened
    /// one; both produce a fresh, recognised directory, which is all this
    /// asserts).
    #[cfg(target_os = "windows")]
    #[test]
    fn staging_dir_is_fresh_and_ours() {
        let a = stage_dir().expect("stage_dir a");
        let b = stage_dir().expect("stage_dir b");
        assert_ne!(a, b, "each download gets a fresh directory");
        for d in [&a, &b] {
            assert!(
                is_staging_dir(d),
                "our own dir is recognised: {}",
                d.display()
            );
        }
        assert!(
            !is_staging_dir(std::env::temp_dir().as_path()),
            "temp_dir itself is not one of ours"
        );
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn is_system_sid_recognises_only_local_system() {
        assert!(is_system_sid(Some("S-1-5-18")));
        assert!(!is_system_sid(None));
        assert!(!is_system_sid(Some("S-1-5-21-111-222-333-1001")));
        // BUILTIN\Administrators — a trusted group, but not SYSTEM, and the
        // whole point of the gate is to tell the two apart.
        assert!(!is_system_sid(Some("S-1-5-32-544")));
    }

    /// Read back `dir`'s owner + DACL and confirm only SYSTEM or
    /// BUILTIN\Administrators have any write-like access — the same shape as
    /// `exec_service`'s `check_private`, duplicated here for the same reason
    /// that one duplicates `hive_win::Sddl` (see [`ProtectedDirSd`]'s doc
    /// comment).
    #[cfg(target_os = "windows")]
    fn assert_dacl_is_system_and_admins_only(dir: &std::path::Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{
            CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        };
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
            GetAce, GetAclInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, OPEN_EXISTING, READ_CONTROL,
        };

        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;
        const INHERIT_ONLY_ACE: u8 = 0x08;
        const WRITE_LIKE: u32 = 0x2 // FILE_WRITE_DATA / FILE_ADD_FILE
            | 0x4 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
            | 0x10 // FILE_WRITE_EA
            | 0x40 // FILE_DELETE_CHILD
            | 0x100 // FILE_WRITE_ATTRIBUTES
            | 0x1_0000 // DELETE
            | 0x4_0000 // WRITE_DAC
            | 0x8_0000 // WRITE_OWNER
            | 0x1000_0000 // GENERIC_ALL
            | 0x4000_0000; // GENERIC_WRITE

        fn is_well_known(sid: PSID, kind: i32) -> bool {
            // SAFETY: `sid` points into a descriptor that outlives the call.
            !sid.is_null() && unsafe { IsWellKnownSid(sid, kind) } != 0
        }
        fn is_trusted(sid: PSID) -> bool {
            is_well_known(sid, WinLocalSystemSid) || is_well_known(sid, WinBuiltinAdministratorsSid)
        }

        let wide: Vec<u16> = dir
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: a NUL-terminated directory path; FILE_FLAG_BACKUP_SEMANTICS
        // is required to open a directory handle at all.
        let handle: HANDLE = unsafe {
            CreateFileW(
                wide.as_ptr(),
                READ_CONTROL,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            handle, INVALID_HANDLE_VALUE,
            "opening the staging dir for READ_CONTROL"
        );

        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `handle` was just opened with READ_CONTROL; the out-params
        // point into `psd`, freed below.
        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut psd,
            )
        };
        // SAFETY: a handle this function opened and owns exclusively.
        unsafe { CloseHandle(handle) };
        assert_eq!(rc, 0, "GetSecurityInfo on the staging dir");

        assert!(
            is_trusted(owner),
            "staging dir is owned by SYSTEM or Administrators"
        );
        assert!(
            !dacl.is_null(),
            "staging dir has a DACL (not NULL — everyone)"
        );

        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `dacl` is valid inside `psd`, which outlives this block.
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&raw mut info).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        assert_ne!(ok, 0, "reading the DACL's ACE count");

        for i in 0..info.AceCount {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `i` < AceCount; `ace` points into the ACL inside `psd`.
            assert_ne!(unsafe { GetAce(dacl, i, &mut ace) }, 0, "reading ACE {i}");
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            match header.AceType {
                ACCESS_DENIED_ACE_TYPE => {}
                ACCESS_ALLOWED_ACE_TYPE => {
                    // SAFETY: ACCESS_ALLOWED_ACE layout — header(4) + mask(4)
                    // + SID, which GetAce guarantees fits within AceSize.
                    let mask = unsafe {
                        std::ptr::read_unaligned((ace as *const u8).add(4) as *const u32)
                    };
                    let sid = unsafe { (ace as *mut u8).add(8) } as PSID;
                    if mask & WRITE_LIKE != 0 {
                        assert!(
                            is_trusted(sid),
                            "an ACE grants write-like access to someone other than \
                             SYSTEM/Administrators"
                        );
                    }
                }
                other => panic!("unexpected ACE type {other} on the staging dir"),
            }
        }
        // SAFETY: the descriptor GetSecurityInfo allocated.
        unsafe { LocalFree(psd as _) };
    }

    /// [`create_fresh_protected_dir`] is what [`stage_dir`] calls when
    /// [`running_as_system`] is true — exercised directly here because the
    /// test process itself is not SYSTEM. `ProtectedDirSd`'s SDDL names
    /// `O:BA` explicitly (see its doc comment), so an ordinary, unelevated
    /// test account cannot even assign that owner: `CreateDirectoryW` is
    /// expected to refuse outright rather than silently create something
    /// weaker than the DACL promises. Either outcome is correct and this
    /// asserts on whichever one this process's own privilege produces: if
    /// creation succeeds (a SYSTEM test run, or an elevated/Administrator
    /// one), the result MUST be exactly as hardened as designed; if it
    /// fails, nothing was left behind, which is the fail-closed direction
    /// every other check in [`download_asset`] already takes.
    #[cfg(target_os = "windows")]
    #[test]
    fn protected_staging_dir_either_locks_down_or_cleanly_refuses() {
        match create_fresh_protected_dir(&std::env::temp_dir()) {
            Ok(dir) => {
                assert!(
                    is_staging_dir(&dir),
                    "our own dir is recognised: {}",
                    dir.display()
                );
                assert_dacl_is_system_and_admins_only(&dir);
                let _ = std::fs::remove_dir_all(&dir);
            }
            Err(e) => eprintln!(
                "create_fresh_protected_dir refused, as expected for an unprivileged \
                 caller (a real Win10 SYSTEM host must still be field-verified): {e}"
            ),
        }
    }

    /// The SDDL string itself parses on every run, with no filesystem or
    /// privilege involved — the one assertion from the test above that does
    /// not depend on this process's own elevation.
    #[cfg(target_os = "windows")]
    #[test]
    fn protected_dir_sddl_parses() {
        ProtectedDirSd::new().expect("the staging dir's SDDL parses");
    }

    /// The write refuses anything already at the name — a planted file (never
    /// truncated) always; a planted symlink (never followed) when the test
    /// process holds `SeCreateSymbolicLinkPrivilege` (Developer Mode or
    /// elevation) to even create one — CI may have neither, so that half
    /// skips cleanly instead of flaking on an environment it doesn't control.
    #[cfg(target_os = "windows")]
    #[test]
    fn write_installer_refuses_a_planted_symlink_and_a_planted_file() {
        use std::io::ErrorKind;
        let tmp = tempfile::tempdir().expect("tempdir");
        let canary = tmp.path().join("canary");
        std::fs::write(&canary, b"original").expect("canary");
        let link = tmp.path().join("installer-link");
        match std::os::windows::fs::symlink_file(&canary, &link) {
            Ok(()) => {
                let err = write_installer(&link, b"payload").expect_err("must refuse a symlink");
                assert_eq!(err.kind(), ErrorKind::AlreadyExists);
                assert_eq!(
                    std::fs::read(&canary).unwrap(),
                    b"original",
                    "the symlink target was not written through"
                );
            }
            Err(e) => eprintln!(
                "skipping the symlink half: this test process cannot create one ({e}) — \
                 Developer Mode or elevation is not guaranteed on every runner"
            ),
        }
        let existing = tmp.path().join("installer");
        std::fs::write(&existing, b"existing").expect("existing");
        let err = write_installer(&existing, b"payload").expect_err("must refuse an existing file");
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            b"existing",
            "not truncated"
        );
    }

    /// Cleanup removes our own staging dir whole, and refuses to touch
    /// anything that is not ours (a wrong-prefix sibling, a path outside
    /// temp_dir()).
    #[cfg(target_os = "windows")]
    #[test]
    fn discard_staging_removes_only_our_own_dir_windows() {
        let ours = stage_dir().expect("stage_dir");
        let installer = ours.join("roomlerd-0.4.0-x86_64-pc-windows-msvc.msi");
        std::fs::write(&installer, b"x").expect("write installer");
        discard_staging(&installer);
        assert!(!ours.exists(), "our own staging dir is removed");

        let not_ours = tempfile::Builder::new()
            .prefix("not-ours.")
            .tempdir_in(std::env::temp_dir())
            .expect("not-ours dir");
        let other = not_ours.path().join("foo.msi");
        std::fs::write(&other, b"y").expect("write other");
        discard_staging(&other);
        assert!(other.exists(), "a dir that is not ours is left alone");

        // A path whose parent is not a staging dir at all: a no-op, no panic.
        discard_staging(std::path::Path::new(r"C:\Windows\System32\cmd.exe"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn staging_dir_is_stale_uses_the_one_hour_gate() {
        assert!(!is_stale(Duration::from_secs(0)));
        assert!(!is_stale(Duration::from_secs(3599)));
        assert!(is_stale(Duration::from_secs(3600)));
        assert!(is_stale(Duration::from_secs(7200)));
    }

    /// A freshly-made staging dir is, by definition, younger than the gate —
    /// the sweep must leave it alone (this is the regression test for the
    /// hazard [`sweep_stale_update_staging_at_start`]'s doc comment names:
    /// never race a directory that could still be in use). A non-staging
    /// sibling is untouched regardless of age.
    #[cfg(target_os = "windows")]
    #[test]
    fn sweep_leaves_a_fresh_staging_dir_alone() {
        let ours = stage_dir().expect("stage_dir");
        let sibling = tempfile::Builder::new()
            .prefix("not-ours.")
            .tempdir_in(std::env::temp_dir())
            .expect("sibling dir");
        sweep_stale_update_staging_at_start();
        assert!(ours.exists(), "a fresh staging dir survives the sweep");
        assert!(
            sibling.path().exists(),
            "a non-staging sibling is never touched"
        );
        let _ = std::fs::remove_dir_all(&ours);
    }

    // ── FR-96 security review (#2055): the run-spacing gate ──────────

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_gate_wait_is_the_remainder_of_the_gap() {
        let now = std::time::SystemTime::now();
        let last = now - Duration::from_secs(20);
        assert_eq!(
            helper_gate_wait(Some(last), now, Duration::from_secs(60)),
            Duration::from_secs(40)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_gate_wait_is_zero_after_the_gap() {
        let now = std::time::SystemTime::now();
        let last = now - Duration::from_secs(61);
        assert_eq!(
            helper_gate_wait(Some(last), now, Duration::from_secs(60)),
            Duration::ZERO
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_gate_wait_is_the_full_gap_with_no_stamp() {
        let now = std::time::SystemTime::now();
        assert_eq!(
            helper_gate_wait(None, now, Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    /// A stamp in the future (the clock stepped back) must not disable the gap.
    #[cfg(target_os = "linux")]
    #[test]
    fn helper_gate_wait_is_the_full_gap_for_a_future_stamp() {
        let now = std::time::SystemTime::now();
        let last = now + Duration::from_secs(5);
        assert_eq!(
            helper_gate_wait(Some(last), now, Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    /// A fresh stamp waits ≈ the gap; an unreadable one waits the FULL gap.
    #[cfg(target_os = "linux")]
    #[test]
    fn helper_gate_wait_at_reads_the_stamp_and_fails_safe_when_unreadable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let stamp = tmp.path().join("update-helper-run");
        stamp_helper_gate(&stamp).expect("write stamp");
        let now = std::time::SystemTime::now();
        let wait = helper_gate_wait_at(&stamp, now, Duration::from_secs(60));
        assert!(
            wait > Duration::from_secs(55) && wait <= Duration::from_secs(60),
            "a fresh stamp waits ~the gap, got {wait:?}"
        );
        // A stamp PATH that lies under a regular file (ENOTDIR on metadata):
        // the full gap, never zero.
        let a_file = tmp.path().join("afile");
        std::fs::write(&a_file, b"x").expect("write file");
        let bogus = a_file.join("update-helper-run");
        assert_eq!(
            helper_gate_wait_at(&bogus, now, Duration::from_secs(60)),
            Duration::from_secs(60),
            "an unreadable stamp must wait the full gap"
        );
    }

    /// The Linux gate must equal launchd's ThrottleInterval, so the two update
    /// halves cannot drift to different cadences unseen.
    #[cfg(target_os = "linux")]
    #[test]
    fn update_helper_min_gap_matches_launchd_throttle_interval() {
        assert_eq!(UPDATE_HELPER_MIN_GAP, Duration::from_secs(60));
        let plist = include_str!("../packaging/macos/com.roomler.update.plist");
        assert!(
            plist.contains("<key>ThrottleInterval</key>"),
            "the plist still carries the twin"
        );
        assert!(
            plist.contains("<integer>60</integer>"),
            "ThrottleInterval is 60 s"
        );
    }

    // ── FR-96 security review (#2055): consuming the wake ────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn consume_wake_removes_a_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wake = tmp.path().join("wake");
        std::fs::write(&wake, b"ts").expect("write");
        assert!(matches!(consume_wake(&wake), WakeConsumed::Removed));
        assert!(!wake.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn consume_wake_is_quiet_when_nothing_is_there() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            consume_wake(&tmp.path().join("absent")),
            WakeConsumed::Nothing
        ));
    }

    /// A symlink planted at the wake path is unlinked, never followed.
    #[cfg(target_os = "linux")]
    #[test]
    fn consume_wake_unlinks_a_symlink_without_following_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let canary = tmp.path().join("canary");
        std::fs::write(&canary, b"keep").expect("canary");
        let wake = tmp.path().join("wake");
        std::os::unix::fs::symlink(&canary, &wake).expect("symlink");
        assert!(matches!(consume_wake(&wake), WakeConsumed::Removed));
        assert!(!wake.exists(), "the link is gone");
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"keep",
            "the symlink target was not followed"
        );
    }

    /// A directory planted at the wake path (what unlink refuses, and what left
    /// in place would re-trigger the path unit forever) is moved aside and
    /// removed, leaving nothing behind.
    #[cfg(target_os = "linux")]
    #[test]
    fn consume_wake_moves_a_planted_directory_aside_and_removes_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wake = tmp.path().join("wake");
        std::fs::create_dir(&wake).expect("mkdir wake");
        std::fs::write(wake.join("x"), b"planted").expect("file in planted dir");
        match consume_wake(&wake) {
            WakeConsumed::MovedAside { cleanup } => {
                assert!(cleanup.is_none(), "removed cleanly: {cleanup:?}")
            }
            other => panic!("expected MovedAside, got {other:?}"),
        }
        assert!(!wake.exists(), "the planted directory is gone");
        let leftovers = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".roomler-update-check.aside.")
            })
            .count();
        assert_eq!(leftovers, 0, "no aside dir left behind");
    }

    /// `queue_update_check` refuses to write through a planted symlink
    /// (`O_NOFOLLOW`) — a per-user daemon must not be tricked into clobbering
    /// an arbitrary file through the sticky /var/tmp name.
    #[cfg(unix)]
    #[test]
    fn queue_update_check_refuses_a_planted_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let canary = tmp.path().join("canary");
        std::fs::write(&canary, b"keep").expect("canary");
        let link = tmp.path().join("wake");
        std::os::unix::fs::symlink(&canary, &link).expect("symlink");
        assert!(
            queue_update_check_at(&link).is_err(),
            "writing must refuse a symlink at the wake path"
        );
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"keep",
            "the symlink target was not written through"
        );
    }

    // ── FR-96 P2a: the per-user daemon steps aside for the root helper ─

    /// Every combination of who-is-asking × the kill switch × enabled. The
    /// only one that steps aside is a per-user daemon, switch on, helper
    /// enabled; a root daemon never does (AC4), and warns when it sees one.
    #[cfg(target_os = "linux")]
    #[test]
    fn update_owner_is_the_helper_only_for_a_per_user_daemon_with_it_enabled() {
        let link = || Some(PathBuf::from("/etc/systemd/system/paths.target.wants/x"));
        assert_eq!(
            decide_update_owner(1000, true, link()),
            UpdateOwner::Helper(link().unwrap())
        );
        assert!(matches!(
            decide_update_owner(1000, true, None),
            UpdateOwner::InProcess(_)
        ));
        assert!(
            matches!(
                decide_update_owner(1000, false, link()),
                UpdateOwner::InProcess(_)
            ),
            "ROOMLERD_UPDATE_HELPER=0 must give back the in-process path"
        );
        assert_eq!(
            decide_update_owner(0, true, link()),
            UpdateOwner::InProcessBesideHelper(link().unwrap()),
            "a root daemon keeps installing, and is told the two may race"
        );
        assert!(matches!(
            decide_update_owner(0, true, None),
            UpdateOwner::InProcess(_)
        ));
        assert!(matches!(
            decide_update_owner(0, false, link()),
            UpdateOwner::InProcessBesideHelper(_)
        ));
    }

    /// An enable link counts only if it LEADS to a unit file: a link left
    /// dangling by a removed package must not make this daemon forward wakes
    /// nobody hears (the safe direction is in-process).
    #[cfg(target_os = "linux")]
    #[test]
    fn helper_enable_link_follows_the_link_to_the_unit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let unit = tmp.path().join("roomler-update.path");
        let live = tmp.path().join("paths.target.wants-roomler-update.path");
        let dangling = tmp.path().join("timers.target.wants-roomler-update.timer");
        let absent = tmp.path().join("never-made");
        std::fs::write(&unit, b"[Path]\n").expect("unit");
        std::os::unix::fs::symlink(&unit, &live).expect("live link");
        std::os::unix::fs::symlink(tmp.path().join("removed.timer"), &dangling)
            .expect("dangling link");

        assert_eq!(
            helper_enable_link_in(&[absent.as_path(), dangling.as_path(), live.as_path()]),
            Some(live.clone()),
            "the first link that leads to a unit"
        );
        assert_eq!(
            helper_enable_link_in(&[absent.as_path(), dangling.as_path()]),
            None,
            "a dangling link is not an enabled helper"
        );
        assert_eq!(helper_enable_link_in(&[]), None);
    }

    /// The links the daemon looks for must be where `systemctl enable` (and
    /// `enable --runtime`) puts each unit: its `WantedBy=` target's `.wants`.
    /// Changing a unit's target without this list would leave every per-user
    /// daemon installing in-process beside an enabled helper, unseen.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_enable_links_are_where_systemctl_enable_puts_the_units() {
        let mut want = Vec::new();
        for (unit, text) in [
            (
                "roomler-update.path",
                include_str!("../packaging/linux/roomler-update.path"),
            ),
            (
                "roomler-update.timer",
                include_str!("../packaging/linux/roomler-update.timer"),
            ),
        ] {
            let target = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("WantedBy="))
                .unwrap_or_else(|| panic!("{unit} has no WantedBy="));
            for root in ["/etc/systemd/system", "/run/systemd/system"] {
                want.push(format!("{root}/{target}.wants/{unit}"));
            }
        }
        let mut have: Vec<String> = UPDATE_HELPER_ENABLE_LINKS
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.sort();
        have.sort();
        assert_eq!(have, want);
    }

    /// The per-user unit must let the daemon write the wake file: its sandbox
    /// (ProtectSystem=strict) leaves /var/tmp read-only wherever the user
    /// manager applies it, and then every push fails EROFS (Fedora).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_user_unit_lets_the_daemon_write_the_wake_file() {
        let unit = include_str!("../packaging/linux/roomler.service");
        let dir = std::path::Path::new(LINUX_UPDATE_TRIGGER)
            .parent()
            .expect("the wake file has a directory");
        let granted = unit
            .lines()
            .filter_map(|l| l.trim().strip_prefix("ReadWritePaths="))
            .flat_map(str::split_whitespace)
            .map(|p| p.trim_start_matches('-'))
            .any(|p| std::path::Path::new(p) == dir);
        assert!(
            granted,
            "roomler.service must carry ReadWritePaths= for {}",
            dir.display()
        );
    }

    /// FR-96 P5 — who can install a release in-process: root always, a non-root
    /// process only without `no_new_privs` (under its unit, never).
    #[cfg(target_os = "linux")]
    #[test]
    fn only_root_or_a_process_without_no_new_privs_installs_in_process() {
        assert!(can_install_in_process(0, false));
        assert!(can_install_in_process(0, true));
        assert!(
            can_install_in_process(1000, false),
            "a daemon started by hand"
        );
        assert!(
            !can_install_in_process(1000, true),
            "a per-user daemon under its unit"
        );
    }

    /// FR-96 P5 — the helper's step-aside reads the links that `systemctl
    /// enable roomlerd.service` makes.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_daemon_links_are_its_install_target() {
        let unit = include_str!("../packaging/linux/roomlerd.service");
        assert!(
            unit.lines()
                .any(|l| l.trim() == "WantedBy=multi-user.target"),
            "roomlerd.service's install target moved: update SYSTEM_DAEMON_ENABLE_LINKS"
        );
        for link in SYSTEM_DAEMON_ENABLE_LINKS {
            assert!(
                link.ends_with("/multi-user.target.wants/roomlerd.service"),
                "{link}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    async fn drained(tx: &tokio::sync::mpsc::Sender<Option<String>>) {
        for _ in 0..200 {
            if tx.capacity() == tx.max_capacity() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the push was never taken");
    }

    #[cfg(target_os = "linux")]
    async fn appears_soon(p: &std::path::Path) -> bool {
        for _ in 0..200 {
            if p.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// FR-96 P5 — a daemon that cannot install, on a host whose helper is off:
    /// a push writes no wake (nothing would hear it). Once the helper is on,
    /// the push that finds it is forwarded, and so is every later one. The
    /// loop ends on shutdown.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_daemon_waiting_for_the_helper_hands_over_once_it_is_enabled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wake = tmp.path().join("roomler-update-check");
        let on = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel(4);
        let (w, o) = (wake.clone(), on.clone());
        let task = tokio::spawn(async move {
            let probe = move || {
                o.load(std::sync::atomic::Ordering::SeqCst).then(|| {
                    PathBuf::from("/etc/systemd/system/paths.target.wants/roomler-update.path")
                })
            };
            wait_for_the_helper_with(
                &w,
                probe,
                Duration::from_secs(3600),
                shutdown_rx,
                trigger_rx,
            )
            .await
        });

        trigger_tx.send(None).await.expect("push");
        drained(&trigger_tx).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!wake.exists(), "with the helper off, a push wakes nothing");

        on.store(true, std::sync::atomic::Ordering::SeqCst);
        trigger_tx.send(None).await.expect("push");
        assert!(
            appears_soon(&wake).await,
            "the push that finds the helper on is forwarded"
        );

        std::fs::remove_file(&wake).expect("the helper consumes it");
        trigger_tx.send(None).await.expect("push");
        assert!(appears_soon(&wake).await, "and so is every later one");

        shutdown_tx.send(true).expect("shutdown");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the loop ends on shutdown")
            .expect("join");
    }

    /// FR-96 P5 — the periodic recheck hands over without a push, and invents
    /// no wake while doing it; the next push is then forwarded.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_daemon_waiting_for_the_helper_hands_over_on_its_recheck_too() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wake = tmp.path().join("roomler-update-check");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel(4);
        let w = wake.clone();
        let task = tokio::spawn(async move {
            let probe = || {
                Some(PathBuf::from(
                    "/etc/systemd/system/timers.target.wants/roomler-update.timer",
                ))
            };
            wait_for_the_helper_with(
                &w,
                probe,
                Duration::from_millis(20),
                shutdown_rx,
                trigger_rx,
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !wake.exists(),
            "the recheck hands over without inventing a wake"
        );
        trigger_tx.send(None).await.expect("push");
        assert!(appears_soon(&wake).await, "the next push is forwarded");

        shutdown_tx.send(true).expect("shutdown");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the loop ends on shutdown")
            .expect("join");
    }

    /// A push, on a host whose helper owns updates, writes the wake file and
    /// nothing else — a pinned push too (the pin never crosses the boundary;
    /// the helper installs the latest). The loop ends on shutdown.
    #[tokio::test]
    async fn a_forwarded_push_writes_the_wake_file_and_nothing_else() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wake = tmp.path().join("roomler-update-check");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel(4);
        let w = wake.clone();
        let task =
            tokio::spawn(async move { forward_triggers_to(&w, shutdown_rx, trigger_rx).await });

        async fn appears(p: &std::path::Path) -> bool {
            for _ in 0..200 {
                if p.exists() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            false
        }

        trigger_tx.send(None).await.expect("push");
        assert!(appears(&wake).await, "a push writes the wake file");

        std::fs::remove_file(&wake).expect("the helper consumes it");
        trigger_tx
            .send(Some("agent-v0.4.1".to_string()))
            .await
            .expect("pinned push");
        assert!(
            appears(&wake).await,
            "a pinned push still only wakes the helper"
        );

        shutdown_tx.send(true).expect("shutdown");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the forwarder ends on shutdown")
            .expect("no panic");
    }

    /// FR-96 P3 — the words `install.sh` matches are the words this binary
    /// prints. A rename on either side would silently leave every per-user
    /// install with its helper off, or its daemon never restarted onto a new
    /// binary.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_capabilities_are_the_words_install_sh_matches() {
        let script = include_str!("../../../scripts/install.sh");
        assert!(script.contains("update-helper --capabilities"));
        for word in ["step-aside", "restart-on-replace"] {
            assert!(UPDATE_HELPER_CAPABILITIES.contains(&word), "{word}");
            assert!(
                script.contains(&format!("grep -qx '{word}'")),
                "install.sh must match `{word}` as a whole line (grep -qx)"
            );
        }
        // `helper_on` is the daemon's own test, link for link: a script that
        // read the helper as off where the daemon reads it as on would skip
        // the restart that hands the daemon's updates over.
        for link in UPDATE_HELPER_ENABLE_LINKS {
            assert!(
                script.contains(link),
                "install.sh's helper_on must test {link}"
            );
        }
    }

    /// FR-96 P3 — only the exact form `install.sh` runs is answered before
    /// clap: any other command line, near misses included, goes to the parser.
    #[test]
    fn only_the_exact_capabilities_query_is_answered_before_parsing() {
        assert!(is_capabilities_query([
            "roomlerd",
            "update-helper",
            "--capabilities"
        ]));
        assert!(is_capabilities_query([
            "/proc/4242/exe",
            "update-helper",
            "--capabilities"
        ]));
        for argv in [
            &["roomlerd"][..],
            &["roomlerd", "update-helper"],
            &["roomlerd", "--capabilities"],
            &["roomlerd", "--capabilities", "update-helper"],
            &["roomlerd", "update-helper", "--capabilities", "extra"],
            &["roomlerd", "update-helper", "--capabilitie"],
            &["roomlerd", "run"],
        ] {
            assert!(!is_capabilities_query(argv), "{argv:?}");
        }
    }

    // ── Linux .deb install candidates ───────────────────────────────
    // The regression these lock: a non-root daemon must not be able to
    // conclude "installed" from pkexec merely being spawnable, and a
    // root daemon must never route through an escalator that can block
    // on a polkit agent that does not exist on a headless host.

    const DEB: &str = "/tmp/roomler-agent-update/roomler-agent.deb";

    #[test]
    fn linux_install_root_never_escalates() {
        let c = linux_install_candidates(0, DEB);
        assert!(
            c.iter().all(|(bin, _)| *bin != "pkexec" && *bin != "sudo"),
            "root must install directly — an escalator can hang on a \
             missing polkit agent: {c:?}"
        );
        assert_eq!(c[0].0, "apt-get", "apt-get first — it resolves depends");
        assert_eq!(c[1].0, "dpkg", "dpkg is the offline fallback");
    }

    #[test]
    fn linux_install_non_root_escalates_pkexec_then_sudo() {
        let c = linux_install_candidates(1000, DEB);
        let bins: Vec<&str> = c.iter().map(|(b, _)| *b).collect();
        assert_eq!(bins, vec!["pkexec", "sudo"]);
        assert_eq!(
            c[1].1.first().map(String::as_str),
            Some("-n"),
            "sudo must be non-interactive — a service has no tty to prompt on"
        );
    }

    #[test]
    fn linux_install_candidates_always_end_with_the_package_path() {
        for euid in [0, 1000] {
            for (bin, args) in linux_install_candidates(euid, DEB) {
                assert_eq!(
                    args.last().map(String::as_str),
                    Some(DEB),
                    "{bin} must receive the .deb path as its last argument"
                );
            }
        }
    }

    fn mk_release(tag: &str, draft: bool, prerelease: bool) -> GithubRelease {
        GithubRelease {
            tag_name: tag.to_string(),
            assets: vec![],
            draft,
            prerelease,
        }
    }

    #[test]
    fn pick_latest_release_picks_highest_agent_tag() {
        // GitHub returns newest-first but we shouldn't rely on that.
        // Mix them up on purpose.
        let releases = vec![
            mk_release("agent-v0.1.30", false, true),
            mk_release("agent-v0.1.36", false, true),
            mk_release("agent-v0.1.35", false, true),
            mk_release("agent-v0.2.0", false, true),
        ];
        let picked = pick_latest_release(releases).expect("should pick one");
        assert_eq!(picked.tag_name, "agent-v0.2.0");
    }

    #[test]
    fn pick_latest_release_skips_drafts() {
        let releases = vec![
            mk_release("agent-v0.2.0", true, false),
            mk_release("agent-v0.1.36", false, true),
        ];
        let picked = pick_latest_release(releases).expect("should pick non-draft");
        assert_eq!(picked.tag_name, "agent-v0.1.36");
    }

    #[test]
    fn pick_latest_release_tolerates_prereleases() {
        // Our 0.x policy marked every release as prerelease. The
        // picker must NOT filter them out — otherwise auto-update
        // is stuck at "no release found" for every existing agent.
        let releases = vec![mk_release("agent-v0.1.37", false, true)];
        assert_eq!(
            pick_latest_release(releases).map(|r| r.tag_name),
            Some("agent-v0.1.37".to_string())
        );
    }

    #[test]
    fn pick_latest_release_ignores_non_agent_tags() {
        // Stray tags from other subsystems on the same repo must be
        // ignored — we only consume agent-v* releases.
        let releases = vec![
            mk_release("v1.2.3", false, false),
            mk_release("backend-v9.9.9", false, false),
            mk_release("agent-v0.1.36", false, true),
        ];
        let picked = pick_latest_release(releases).expect("should pick agent tag");
        assert_eq!(picked.tag_name, "agent-v0.1.36");
    }

    #[test]
    fn pick_latest_release_returns_none_when_nothing_matches() {
        assert!(pick_latest_release(vec![]).is_none());
        assert!(pick_latest_release(vec![mk_release("random-1.0.0", false, false)]).is_none());
        assert!(pick_latest_release(vec![mk_release("agent-v0.1.0", true, false)]).is_none());
    }

    /// A release carrying BOTH Linux architectures must never hand an
    /// agent the other one. Before the arch qualifier, `ends_with(".deb")`
    /// matched whichever .deb GitHub listed first, so publishing an arm64
    /// package would have made every x86_64 agent dpkg a foreign binary.
    #[cfg(target_os = "linux")]
    #[test]
    fn pick_asset_never_crosses_linux_architectures() {
        let mk = |name: &str| GithubAsset {
            name: name.into(),
            browser_download_url: "https://example.invalid/x.deb".into(),
            size: 1,
            digest: None,
        };
        // arm64 deliberately FIRST, so a naive picker would take it. Both
        // FORMATS are present so the fixture is installable whether or not
        // this host has dpkg — `pick_asset_for_unix` probes for it, and a
        // .deb-only fixture would make the test's outcome depend on the
        // runner's distro instead of on the arch logic under test.
        let assets = vec![
            mk("roomler-agent-0.3.0-rc.366-aarch64-unknown-linux-gnu.deb"),
            mk("roomler-agent-0.3.0-rc.366-aarch64-unknown-linux-gnu.tar.gz"),
            mk("roomler-agent-0.3.0-rc.366-x86_64-unknown-linux-gnu.deb"),
            mk("roomler-agent-0.3.0-rc.366-x86_64-unknown-linux-gnu.tar.gz"),
        ];
        let name = &pick_asset_for_unix(&assets)
            .expect("a Linux asset must match")
            .name;
        #[cfg(target_arch = "x86_64")]
        assert!(name.contains("x86_64"), "x86_64 agent took {name}");
        #[cfg(target_arch = "aarch64")]
        assert!(name.contains("aarch64"), "aarch64 agent took {name}");
        let _ = name;
    }

    /// An x86_64-only release must be SKIPPED on arm64 rather than
    /// installed — the field case that made `Update all` a silent no-op
    /// on the aarch64 host (2026-08-15).
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    fn pick_asset_skips_x86_only_release_on_arm64() {
        let assets = vec![GithubAsset {
            name: "roomler-agent-0.3.0-rc.366-x86_64-unknown-linux-gnu.deb".into(),
            browser_download_url: "https://example.invalid/x.deb".into(),
            size: 1,
            digest: None,
        }];
        assert!(pick_asset_for_unix(&assets).is_none());
    }

    /// The format preference matrix. `.deb` where dpkg/apt exist so the
    /// distro's package manager stays the source of truth; the tarball
    /// everywhere else, because a .deb there downloads and then fails to
    /// install — exactly how `Update all` looked like a silent no-op on the
    /// Fedora field host.
    #[test]
    fn pick_linux_asset_prefers_the_installable_format() {
        let mk = |name: &str| GithubAsset {
            name: name.into(),
            browser_download_url: "https://example.invalid/x".into(),
            size: 1,
            digest: None,
        };
        let both = vec![
            mk("roomler-agent-0.3.0-x86_64-unknown-linux-gnu.deb"),
            mk("roomler-agent-0.3.0-x86_64-unknown-linux-gnu.tar.gz"),
        ];
        let x86 = &["x86_64", "amd64"][..];

        let debian = pick_linux_asset(&both, x86, true).expect("deb host picks something");
        assert!(
            debian.name.ends_with(".deb"),
            "debian host took {}",
            debian.name
        );

        let other = pick_linux_asset(&both, x86, false).expect("non-deb host picks something");
        assert!(
            other.name.ends_with(".tar.gz"),
            "fedora-like host took {}",
            other.name
        );

        // A Debian host whose .deb is missing still updates via the tarball
        // rather than treating an absent artifact as a dead end.
        let tar_only = vec![mk("roomler-agent-0.3.0-x86_64-unknown-linux-gnu.tar.gz")];
        assert!(
            pick_linux_asset(&tar_only, x86, true)
                .expect("falls back")
                .name
                .ends_with(".tar.gz")
        );

        // …but a host with no dpkg and only a .deb published must SKIP, not
        // download something it cannot install.
        let deb_only = vec![mk("roomler-agent-0.3.0-x86_64-unknown-linux-gnu.deb")];
        assert!(pick_linux_asset(&deb_only, x86, false).is_none());
    }

    /// FR-27 — a release now carries TWO arch-matching Linux `.deb`s: the
    /// daemon's and the desktop companion's. Installing the companion as a
    /// daemon update would succeed at the dpkg level and freeze the daemon on
    /// its old version forever, which is worse than a failed update because
    /// nothing reports it.
    #[test]
    fn pick_linux_asset_never_takes_the_desktop_companion() {
        let mk = |name: &str| GithubAsset {
            name: name.into(),
            browser_download_url: "https://example.invalid/x".into(),
            size: 1,
            digest: None,
        };
        let x86 = &["x86_64", "amd64"][..];

        // The companion listed FIRST — asset order is GitHub's, not ours, so
        // "the daemon's happens to come first" is not a property we may rely on.
        // RETIRED-NAME-ANCHOR(8): these are real PUBLISHED asset names, frozen by
        // release-agent.yml as an immutable surface. Renaming them here would make the
        // test pass against names no release actually carries. docs/fr/FR-21
        let release = vec![
            mk("roomler-desktop-0.4.15-x86_64-unknown-linux-gnu.deb"),
            mk("roomler-agent-0.4.15-x86_64-unknown-linux-gnu.deb"),
            mk("roomler-agent-0.4.15-x86_64-unknown-linux-gnu.tar.gz"),
        ];
        let picked = pick_linux_asset(&release, x86, true).expect("must still find the daemon deb");
        assert_eq!(
            picked.name,
            "roomler-agent-0.4.15-x86_64-unknown-linux-gnu.deb"
        );

        // With ONLY the companion published, there is nothing installable —
        // skipping is right; taking it is the freeze.
        let companion_only = vec![mk("roomler-desktop-0.4.15-x86_64-unknown-linux-gnu.deb")];
        assert!(pick_linux_asset(&companion_only, x86, true).is_none());

        // cargo-deb's own spelling, as old releases carry it, still counts.
        // RETIRED-NAME-ANCHOR(4): same published-asset surface as above. docs/fr/FR-21
        assert!(is_daemon_asset("roomlerd_0.4.15-1_amd64.deb"));
        assert!(is_daemon_asset(
            "roomler-agent-0.4.15-x86_64-unknown-linux-gnu.tar.gz"
        ));
        assert!(!is_daemon_asset(
            "roomler-desktop-0.4.15-x86_64-unknown-linux-gnu.deb"
        ));
    }

    /// FR-46 (#1051): the daemon's published asset is named `roomlerd-…` from
    /// this release on. The rename was argued from reading every picker; this
    /// asserts it instead, on the one path where the prefix is load-bearing.
    ///
    /// The other three paths cannot regress from a rename because they never
    /// look at the prefix (Windows keys on `.msi` + `-permachine-`, macOS on
    /// `.pkg`, `scripts/install.sh` on an arch+format suffix), and a pre-0.4.16
    /// agent takes the first arch-matching `.deb`, which the server orders
    /// daemon-first via a `roomler-desktop-` DENYLIST — so it is unaffected by
    /// what the daemon is called.
    ///
    /// ⚠️ The legacy arm must stay: already-published releases carry the old
    /// name and an older host may still be updating from one.
    #[test]
    fn pick_linux_asset_takes_the_renamed_daemon_deb() {
        let mk = |name: &str| GithubAsset {
            name: name.into(),
            browser_download_url: "https://example.invalid/x".into(),
            size: 1,
            digest: None,
        };
        let x86 = &["x86_64", "amd64"][..];

        // Companion FIRST again — asset order is GitHub's, not ours.
        let release = vec![
            mk("roomler-desktop-0.4.38-x86_64-unknown-linux-gnu.deb"),
            mk("roomlerd-0.4.38-x86_64-unknown-linux-gnu.deb"),
            mk("roomlerd-0.4.38-x86_64-unknown-linux-gnu.tar.gz"),
        ];
        let picked =
            pick_linux_asset(&release, x86, true).expect("must find the renamed daemon deb");
        assert_eq!(picked.name, "roomlerd-0.4.38-x86_64-unknown-linux-gnu.deb");

        assert!(is_daemon_asset(
            "roomlerd-0.4.38-x86_64-unknown-linux-gnu.deb"
        ));
        assert!(is_daemon_asset(
            "roomlerd-0.4.38-x86_64-unknown-linux-gnu.tar.gz"
        ));

        // RETIRED-NAME-ANCHOR(3): the legacy arm is a LIVE fallback for releases
        // already published under the old name — not decoration. docs/fr/FR-46
        assert!(is_daemon_asset(
            "roomler-agent-0.4.15-x86_64-unknown-linux-gnu.deb"
        ));
    }

    /// Format preference must never override architecture: a tarball for the
    /// wrong arch is as unusable as a .deb for the wrong arch.
    #[test]
    fn pick_linux_asset_never_crosses_arch_for_either_format() {
        let mk = |name: &str| GithubAsset {
            name: name.into(),
            browser_download_url: "https://example.invalid/x".into(),
            size: 1,
            digest: None,
        };
        // Wrong arch listed FIRST for both formats.
        let assets = vec![
            mk("roomler-agent-0.3.0-aarch64-unknown-linux-gnu.tar.gz"),
            mk("roomler-agent-0.3.0-aarch64-unknown-linux-gnu.deb"),
            mk("roomler-agent-0.3.0-x86_64-unknown-linux-gnu.tar.gz"),
            mk("roomler-agent-0.3.0-x86_64-unknown-linux-gnu.deb"),
        ];
        let x86 = &["x86_64", "amd64"][..];
        for tooling in [true, false] {
            let got = pick_linux_asset(&assets, x86, tooling).expect("a pick");
            assert!(got.name.contains("x86_64"), "x86_64 host took {}", got.name);
        }
        let arm = &["aarch64", "arm64"][..];
        for tooling in [true, false] {
            let got = pick_linux_asset(&assets, arm, tooling).expect("a pick");
            assert!(got.name.contains("aarch64"), "arm64 host took {}", got.name);
        }
    }

    #[test]
    fn pick_asset_returns_none_when_no_platform_match() {
        let assets = vec![GithubAsset {
            name: "roomler-agent-0.1.36.tar.gz".into(),
            browser_download_url: "https://example.invalid/foo.tgz".into(),
            size: 10,
            digest: None,
        }];
        assert!(pick_asset_for_platform(&assets).is_none());
    }

    fn mk_msi(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.into(),
            browser_download_url: format!("https://example.invalid/{name}"),
            size: 2_000_000,
            digest: None,
        }
    }

    /// Field repro: the GitHub release listing returns assets in
    /// alphabetical order, which puts `…-perMachine-…msi` ahead of
    /// the plain `…-x86_64-…msi`. A perUser agent calling the OLD
    /// (pre-0.2.6) picker happily returned the perMachine MSI as the
    /// "first .msi" and the cross-flavour launch condition silently
    /// rejected the install. Lock the new behaviour: perUser flavour
    /// picks the perUser MSI even when perMachine is alphabetically
    /// first.
    #[test]
    fn pick_asset_per_user_skips_per_machine_msi() {
        let assets = vec![
            mk_msi("roomler-agent-0.2.5-perMachine-x86_64-pc-windows-msvc-unsigned.msi"),
            mk_msi("roomler-agent-0.2.5-x86_64-pc-windows-msvc-unsigned.msi"),
        ];
        let pick = pick_asset_for_windows(&assets, WindowsInstallFlavour::PerUser)
            .expect("perUser must find its MSI");
        assert!(
            !pick.name.to_lowercase().contains("-permachine-"),
            "perUser picked {}",
            pick.name
        );
    }

    #[test]
    fn pick_asset_per_machine_picks_per_machine_msi() {
        let assets = vec![
            mk_msi("roomler-agent-0.2.5-x86_64-pc-windows-msvc-unsigned.msi"),
            mk_msi("roomler-agent-0.2.5-perMachine-x86_64-pc-windows-msvc-unsigned.msi"),
        ];
        let pick = pick_asset_for_windows(&assets, WindowsInstallFlavour::PerMachine)
            .expect("perMachine must find its MSI");
        assert!(
            pick.name.to_lowercase().contains("-permachine-"),
            "perMachine picked {}",
            pick.name
        );
    }

    /// Defensive fallback: if the release ships only one MSI flavour
    /// (e.g. an old 0.2.0 tag that predates the perMachine MSI), the
    /// agent should still self-update against the available MSI rather
    /// than skip the release entirely. The cross-flavour install will
    /// silently no-op against the launch condition; that's strictly
    /// better than agents stuck on an old version forever.
    #[test]
    fn pick_asset_per_machine_falls_back_when_only_per_user_present() {
        let assets = vec![mk_msi(
            "roomler-agent-0.2.0-x86_64-pc-windows-msvc-unsigned.msi",
        )];
        let pick = pick_asset_for_windows(&assets, WindowsInstallFlavour::PerMachine)
            .expect("fallback must produce something");
        assert!(pick.name.to_lowercase().ends_with(".msi"));
    }

    #[test]
    fn pick_asset_per_user_falls_back_when_only_per_machine_present() {
        let assets = vec![mk_msi(
            "roomler-agent-0.2.5-perMachine-x86_64-pc-windows-msvc-unsigned.msi",
        )];
        let pick = pick_asset_for_windows(&assets, WindowsInstallFlavour::PerUser)
            .expect("fallback must produce something");
        assert!(pick.name.to_lowercase().ends_with(".msi"));
    }

    #[test]
    fn pick_asset_per_user_returns_none_when_no_msi_at_all() {
        let assets = vec![GithubAsset {
            name: "roomler-agent-0.2.5_amd64.deb".into(),
            browser_download_url: "https://example.invalid/foo.deb".into(),
            size: 2_000_000,
            digest: None,
        }];
        assert!(pick_asset_for_windows(&assets, WindowsInstallFlavour::PerUser).is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn classify_install_flavour_recognises_program_files() {
        assert_eq!(
            classify_install_flavour_from_path(std::path::Path::new(
                r"C:\Program Files\roomler-agent\roomler-agent.exe"
            )),
            WindowsInstallFlavour::PerMachine
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn classify_install_flavour_recognises_program_files_x86() {
        // 32-bit installer on a 64-bit host lands here. We don't
        // ship one today but the path matcher must cover it so a
        // future 32-bit MSI doesn't get mis-classified as perUser.
        assert_eq!(
            classify_install_flavour_from_path(std::path::Path::new(
                r"C:\Program Files (x86)\roomler-agent\roomler-agent.exe"
            )),
            WindowsInstallFlavour::PerMachine
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn classify_install_flavour_recognises_localappdata() {
        // Default cargo-wix perUser destination on Win11.
        assert_eq!(
            classify_install_flavour_from_path(std::path::Path::new(
                r"C:\Users\operator\AppData\Local\Programs\roomler-agent\roomler-agent.exe"
            )),
            WindowsInstallFlavour::PerUser
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn classify_install_flavour_is_case_insensitive() {
        // Win32 paths are case-insensitive; a `PROGRAM FILES` spelling
        // (rare but possible from a misbehaving installer or
        // GetModuleFileName quirk) must still classify as perMachine.
        assert_eq!(
            classify_install_flavour_from_path(std::path::Path::new(
                r"C:\PROGRAM FILES\roomler-agent\roomler-agent.exe"
            )),
            WindowsInstallFlavour::PerMachine
        );
    }

    // ----- B6 regression: wizard-EXE locations are NOT classifiable ---

    #[cfg(target_os = "windows")]
    #[test]
    fn classify_wizard_exe_locations_returns_peruser_not_permachine() {
        // The install wizard EXE runs from wherever the operator
        // double-clicked it. Each of these paths classifies as
        // PerUser — which is wrong for the host's install state when
        // the operator picked perMachine in the wizard. Locks the
        // contract that the wizard MUST NOT rely on
        // `current_install_flavour`/`classify_install_flavour_from_path`
        // when deciding the spawn elevation path; instead use
        // `spawn_installer_for_flavour(path, operator_selected_flavour)`.
        // Field repro 2026-05-15 on a Windows field-test host: wizard ran from
        // %TEMP%, classified as PerUser, spawned msiexec /qn against
        // a perMachine MSI, Windows Installer returned 1625
        // ERROR_INSTALL_PACKAGE_REJECTED.
        let wizard_paths = [
            r"C:\Users\operator\Downloads\roomler-installer-0.3.0-rc.28-x86_64-pc-windows-msvc.exe",
            r"C:\Users\operator\Desktop\roomler-installer.exe",
            r"C:\Users\operator\AppData\Local\Temp\roomler-installer.exe",
            r"D:\Installers\roomler-installer.exe",
        ];
        for p in wizard_paths {
            assert_eq!(
                classify_install_flavour_from_path(std::path::Path::new(p)),
                WindowsInstallFlavour::PerUser,
                "wizard EXE at {p} unexpectedly classified as PerMachine"
            );
        }
    }

    // ----- stage_watcher_exe (RM-survivable watcher, 2026-08-21) ------

    #[cfg(target_os = "windows")]
    #[test]
    fn stage_watcher_exe_copies_next_to_the_installer() {
        let staging = std::env::temp_dir().join(format!("rw-stage-test-{}", std::process::id()));
        std::fs::create_dir_all(&staging).unwrap();
        let fake_exe = staging.join("fake-daemon.exe");
        std::fs::write(&fake_exe, b"MZ-fake").unwrap();
        let installer = staging.join("pkg.msi");

        let (launch, staged) = stage_watcher_exe(&fake_exe, &installer);
        assert!(staged, "copy into an existing staging dir must stage");
        assert_eq!(launch, staging.join("roomlerd-watch.exe"));
        assert_eq!(std::fs::read(&launch).unwrap(), b"MZ-fake");

        // A parent-less installer path has no staging dir — fall back
        // to spawning from the original EXE (pre-fix behaviour).
        let (fallback, staged) = stage_watcher_exe(&fake_exe, std::path::Path::new("pkg.msi"));
        assert!(!staged);
        assert_eq!(fallback, fake_exe);

        let _ = std::fs::remove_dir_all(&staging);
    }

    // ----- msiexec_argv (Plan rc.18 P1) -------------------------------

    #[test]
    fn msiexec_argv_per_user_uses_qn() {
        // perUser MSI installs without UAC; /qn (fully silent) is
        // correct AND the historical default — must not regress.
        let argv = msiexec_argv(
            std::path::Path::new(r"C:\Temp\roomler-agent.msi"),
            WindowsInstallFlavour::PerUser,
        );
        assert_eq!(argv[0], "/i");
        assert_eq!(argv[1], r"C:\Temp\roomler-agent.msi");
        assert_eq!(argv[2], "/qn");
        assert_eq!(argv[3], "/norestart");
        assert_eq!(argv[4], "/l*v");
        assert_eq!(argv[5], r"C:\Temp\roomler-agent.msi.log");
        assert_eq!(argv.len(), 6);
    }

    #[test]
    fn msiexec_argv_per_machine_uses_qn() {
        // rc.236: /qn, NOT /qb!. Basic UI can't display or answer the
        // FilesInUse dialog (MSI error 1607) raised when upgrading
        // over the running service → the 5/5-reproduced self-update
        // wedge. Elevation is handled by ShellExecuteExW(runas)
        // BEFORE msiexec runs, so /qn has no UAC to suppress — the
        // original rc.18 reason for /qb! no longer applies. Locks
        // against a well-meaning revert.
        let argv = msiexec_argv(
            std::path::Path::new(r"C:\Temp\roomler-agent-perMachine.msi"),
            WindowsInstallFlavour::PerMachine,
        );
        assert_eq!(argv[2], "/qn");
        // Other args identical to perUser shape.
        assert_eq!(argv[0], "/i");
        assert_eq!(argv[3], "/norestart");
    }

    #[test]
    fn msiexec_argv_always_includes_norestart() {
        // Both flavours: /norestart prevents a surprise reboot during
        // a service-context install. The post-install watcher restarts
        // the agent itself; the OS reboot is never needed.
        for flavour in [
            WindowsInstallFlavour::PerUser,
            WindowsInstallFlavour::PerMachine,
        ] {
            let argv = msiexec_argv(std::path::Path::new(r"C:\x.msi"), flavour);
            assert!(
                argv.iter().any(|a| a == "/norestart"),
                "missing /norestart for {flavour:?}"
            );
        }
    }

    #[test]
    fn msiexec_argv_path_is_second_arg() {
        // Argv order matters: msiexec expects `/i <path>` as the
        // first two tokens. Locks against a future refactor that
        // accidentally reorders.
        let argv = msiexec_argv(
            std::path::Path::new(r"D:\roomler-agent.msi"),
            WindowsInstallFlavour::PerUser,
        );
        assert_eq!(argv[0], "/i");
        assert_eq!(argv[1], r"D:\roomler-agent.msi");
    }

    // ----- rc.44 P4: msiexec_argv_with_properties (SystemContext) ----

    #[test]
    fn msiexec_argv_with_properties_appends_kv() {
        // Operator-supplied properties land AFTER the base /i path /qn
        // /norestart shape. Locks the wire format for the WiX CA's
        // condition (`ENABLE_SYSTEM_CONTEXT="1"`).
        let argv = msiexec_argv_with_properties(
            std::path::Path::new(r"C:\Temp\roomler-agent-perMachine.msi"),
            WindowsInstallFlavour::PerMachine,
            &[("ENABLE_SYSTEM_CONTEXT", "1")],
        );
        // Base shape preserved.
        assert_eq!(argv[0], "/i");
        assert_eq!(argv[2], "/qn");
        assert_eq!(argv[3], "/norestart");
        assert_eq!(argv[4], "/l*v");
        // Property appended verbatim after the base argv (incl. the
        // verbose-log pair), no shell-quoting.
        assert_eq!(argv[6], "ENABLE_SYSTEM_CONTEXT=1");
        assert_eq!(argv.len(), 7);
    }

    #[test]
    fn msiexec_argv_with_properties_explicit_disable_passes_zero() {
        // Plain perMachine over a SystemContext-on host: wizard passes
        // =0 explicitly so the WiX DisableSystemContext CA's condition
        // (`ENABLE_SYSTEM_CONTEXT="0"`) matches. Verifies the explicit
        // value survives the formatter.
        let argv = msiexec_argv_with_properties(
            std::path::Path::new(r"C:\Temp\roomler-agent-perMachine.msi"),
            WindowsInstallFlavour::PerMachine,
            &[("ENABLE_SYSTEM_CONTEXT", "0")],
        );
        assert!(argv.iter().any(|s| s == "ENABLE_SYSTEM_CONTEXT=0"));
    }

    #[test]
    fn msiexec_argv_with_properties_empty_matches_base() {
        // When the wizard passes no properties (perUser flavour), the
        // wrapper must produce byte-identical output to the base
        // msiexec_argv — no trailing whitespace, no extra tokens.
        let p = std::path::Path::new(r"C:\Temp\roomler-agent.msi");
        let base = msiexec_argv(p, WindowsInstallFlavour::PerUser);
        let with_empty = msiexec_argv_with_properties(p, WindowsInstallFlavour::PerUser, &[]);
        assert_eq!(base, with_empty);
    }

    #[test]
    fn msiexec_argv_with_properties_appends_multiple_in_order() {
        // Forward-compat: WiX may need additional public properties
        // in a future cycle (e.g. ENABLE_SYSTEM_CONTEXT=1 +
        // SYSTEM_CONTEXT_TIMEOUT_SECS=180). Order must be preserved.
        let argv = msiexec_argv_with_properties(
            std::path::Path::new(r"C:\Temp\roomler-agent-perMachine.msi"),
            WindowsInstallFlavour::PerMachine,
            &[("A", "1"), ("B", "two"), ("C", "3")],
        );
        let tail: Vec<&String> = argv.iter().skip(6).collect();
        assert_eq!(tail[0], "A=1");
        assert_eq!(tail[1], "B=two");
        assert_eq!(tail[2], "C=3");
    }

    // ----- rc.56 SystemContext-preserve hotfix (preserve_system_context_property_for) --

    #[test]
    fn preserve_system_context_per_user_always_empty() {
        // perUser installs have no SCM service to read from; even if the
        // env_value somehow returns "1" (impossible in production but
        // the test asserts robustness) the function must NOT pass the
        // property because perUser MSIs don't define the WiX
        // `EnableSystemContext` CA at all.
        assert_eq!(
            preserve_system_context_property_for(
                WindowsInstallFlavour::PerUser,
                Ok(Some("1".into())),
            ),
            Vec::<(String, String)>::new()
        );
        assert_eq!(
            preserve_system_context_property_for(WindowsInstallFlavour::PerUser, Ok(None),),
            Vec::<(String, String)>::new()
        );
        assert_eq!(
            preserve_system_context_property_for(
                WindowsInstallFlavour::PerUser,
                Err("nope".into()),
            ),
            Vec::<(String, String)>::new()
        );
    }

    #[test]
    fn preserve_system_context_per_machine_with_env_one_passes_property() {
        // THE headline rc.56 case: perMachine + service env var "1" ⇒
        // pass `ENABLE_SYSTEM_CONTEXT=1`. Without this assertion the
        // WiX DisableSystemContext CA would strip the env var on every
        // auto-update (field-repro WINHOST-A 2026-05-24, rc.55 self-update).
        let result = preserve_system_context_property_for(
            WindowsInstallFlavour::PerMachine,
            Ok(Some("1".into())),
        );
        assert_eq!(
            result,
            vec![("ENABLE_SYSTEM_CONTEXT".to_string(), "1".to_string())]
        );
    }

    #[test]
    fn preserve_system_context_per_machine_with_env_absent_returns_empty() {
        // Plain perMachine install (no SystemContext ever enabled):
        // env var absent ⇒ pass nothing. WiX default property `'0'`
        // runs DisableSystemContext which is an idempotent no-op when
        // there's nothing to disable.
        assert_eq!(
            preserve_system_context_property_for(WindowsInstallFlavour::PerMachine, Ok(None),),
            Vec::<(String, String)>::new()
        );
    }

    #[test]
    fn preserve_system_context_per_machine_with_env_non_one_returns_empty() {
        // Defensive: the WiX CA condition is strict (`="1"`). If the
        // operator set the env var to "true" / "yes" / "on" (which
        // `system_swap_enabled` ACCEPTS as truthy), we conservatively
        // do NOT pass the property — WiX wouldn't match the condition
        // anyway. The mismatch between agent truthy-parse and WiX
        // strict-compare is documented; rc.57 candidate: tighten
        // `system_swap_enabled` to also be strict.
        for v in ["0", "true", "yes", "on", "TRUE", "", "anything"] {
            assert_eq!(
                preserve_system_context_property_for(
                    WindowsInstallFlavour::PerMachine,
                    Ok(Some(v.into())),
                ),
                Vec::<(String, String)>::new(),
                "non-\"1\" env value {v:?} must NOT pass ENABLE_SYSTEM_CONTEXT"
            );
        }
    }

    #[test]
    fn preserve_system_context_per_machine_with_read_error_returns_empty() {
        // SCM read error (e.g. service masked or missing): fall back to
        // pre-rc.56 behaviour rather than blocking the auto-update.
        // Operator can re-enable SystemContext manually via
        // `roomlerd enable-system-context` if needed.
        assert_eq!(
            preserve_system_context_property_for(
                WindowsInstallFlavour::PerMachine,
                Err("SCM RegOpenKeyEx returned 5 ERROR_ACCESS_DENIED".into()),
            ),
            Vec::<(String, String)>::new()
        );
    }

    // ---- rc.19 P3 — transfer-gated update timing ----

    #[test]
    fn decide_defer_proceeds_with_no_active_transfers() {
        assert_eq!(decide_defer(0, false, 0), DeferDecision::Proceed);
        // Defers counter is irrelevant when active=0 — the gate
        // resets at every Proceed.
        assert_eq!(decide_defer(0, false, 5), DeferDecision::Proceed);
    }

    #[test]
    fn decide_defer_defers_when_active_and_under_limit() {
        assert_eq!(decide_defer(1, false, 0), DeferDecision::DeferOnce);
        assert_eq!(decide_defer(3, false, 6), DeferDecision::DeferOnce);
    }

    /// R5b — a fresh network transition gates exactly like an active
    /// transfer: an install restart adjacent to a VPN capture forfeits
    /// every grandfathered flow (field 2026-08-16), so the cycle defers
    /// (fast recheck) until the window passes or the defer cap forces it.
    #[test]
    fn decide_defer_defers_on_a_fresh_network_transition() {
        assert_eq!(decide_defer(0, true, 0), DeferDecision::DeferOnce);
        assert_eq!(decide_defer(0, true, 6), DeferDecision::DeferOnce);
        assert_eq!(
            decide_defer(0, true, MAX_CONSECUTIVE_DEFERS),
            DeferDecision::ForceAfterDefers
        );
        // Both gates at once still just defers once per cycle.
        assert_eq!(decide_defer(2, true, 0), DeferDecision::DeferOnce);
    }

    /// FR-90 P1d-1 (AC7) — running agent turns hold an install, bounded: no
    /// turn goes at once, a turn within the wait waits, a turn past it is
    /// cut; a wait of zero (the owner's choice) cuts at once.
    #[test]
    fn decide_turn_wait_waits_for_turns_within_the_bound() {
        let max = Duration::from_secs(1800);
        assert_eq!(decide_turn_wait(0, Duration::ZERO, max), TurnWait::Proceed);
        assert_eq!(
            decide_turn_wait(0, Duration::from_secs(5000), max),
            TurnWait::Proceed
        );
        assert_eq!(decide_turn_wait(1, Duration::ZERO, max), TurnWait::Wait);
        assert_eq!(
            decide_turn_wait(3, Duration::from_secs(1799), max),
            TurnWait::Wait
        );
        assert_eq!(decide_turn_wait(1, max, max), TurnWait::Cut);
        assert_eq!(
            decide_turn_wait(1, Duration::ZERO, Duration::ZERO),
            TurnWait::Cut
        );
    }

    #[test]
    fn decide_defer_forces_at_max_defers() {
        // Exactly at MAX_CONSECUTIVE_DEFERS should force.
        assert_eq!(
            decide_defer(1, false, MAX_CONSECUTIVE_DEFERS),
            DeferDecision::ForceAfterDefers
        );
        // And anything above it.
        assert_eq!(
            decide_defer(99, true, MAX_CONSECUTIVE_DEFERS + 50),
            DeferDecision::ForceAfterDefers
        );
    }

    #[test]
    // Compile-time contract lock — the constant-ness IS the point.
    #[allow(clippy::assertions_on_constants)]
    fn defer_constants_have_sensible_values() {
        // TRANSFER_DEFER_RECHECK should be shorter than CHECK_INTERVAL
        // (the whole point — react faster when uploads finish).
        assert!(TRANSFER_DEFER_RECHECK < CHECK_INTERVAL);
        // MAX_CONSECUTIVE_DEFERS at 1h cadence + 24h initial = at
        // most ~31h between successful update fires for a
        // chronically-busy host. Bounded.
        assert!(MAX_CONSECUTIVE_DEFERS >= 3 && MAX_CONSECUTIVE_DEFERS <= 24);
    }

    // ---- #1755 — a check that failed on the transport retries early ----

    /// The schedule climbs 5 → 15 → 60 min and then falls back to the
    /// periodic interval, and is never longer than the interval.
    #[test]
    fn transport_retry_climbs_then_falls_back_to_the_interval() {
        let four_h = Duration::from_secs(4 * 3600);
        assert_eq!(transport_retry_after(1, four_h), Duration::from_secs(300));
        assert_eq!(transport_retry_after(2, four_h), Duration::from_secs(900));
        assert_eq!(transport_retry_after(3, four_h), Duration::from_secs(3600));
        assert_eq!(transport_retry_after(4, four_h), four_h);
        assert_eq!(transport_retry_after(40, four_h), four_h);
        let ten_min = Duration::from_secs(600);
        assert_eq!(
            transport_retry_after(2, ten_min),
            ten_min,
            "never longer than the interval"
        );
    }

    /// The field bug: a failure at boot cost the full interval. Only a
    /// transport failure rechecks early; a verdict or a success keeps the
    /// cadence and ends the streak, so a bad release is never hammered.
    #[test]
    fn only_a_transport_failure_rechecks_early() {
        let four_h = Duration::from_secs(4 * 3600);
        let mut streak = 0;
        let unreachable = CheckOutcome::Unreachable("download: operation timed out".into());
        assert_eq!(
            recheck_after(&unreachable, &mut streak, four_h),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            recheck_after(&unreachable, &mut streak, four_h),
            Some(Duration::from_secs(900))
        );
        assert_eq!(streak, 2);

        let verdict = CheckOutcome::Skipped("no installer asset for this platform".into());
        assert_eq!(recheck_after(&verdict, &mut streak, four_h), None);
        assert_eq!(streak, 0, "a verdict ends the streak");
        assert_eq!(
            recheck_after(&unreachable, &mut streak, four_h),
            Some(Duration::from_secs(300)),
            "a new streak starts over"
        );
        let up = CheckOutcome::UpToDate {
            current: "0.4.110".into(),
            latest: "agent-v0.4.110".into(),
        };
        assert_eq!(recheck_after(&up, &mut streak, four_h), None);
        assert_eq!(streak, 0);
    }

    /// Classified by TYPE: a real `reqwest` connect failure, under `anyhow`
    /// context the way the updater wraps it, is a transport failure. The same
    /// words without the type are not, and neither is a verdict.
    #[tokio::test]
    async fn a_real_connect_failure_is_transport_and_its_text_is_not() {
        // A port that was just free: bind, read it, release it.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let err = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .expect_err("nothing listens there");
        let e = anyhow::Error::new(err).context("GET releases");
        assert!(is_transport_failure(&e), "{e:#}");
        assert!(matches!(failed("fetch", e), CheckOutcome::Unreachable(_)));

        let lookalike = anyhow::anyhow!(
            "GET releases: error sending request for url (http://127.0.0.1:{port}/): \
             client error (Connect): dns error"
        );
        assert!(!is_transport_failure(&lookalike), "text never classifies");
        assert!(matches!(
            failed("fetch", lookalike),
            CheckOutcome::Skipped(_)
        ));
        let rate_limited = anyhow::anyhow!("GitHub API returned 403 Forbidden — rate-limited");
        assert!(matches!(
            failed("fetch", rate_limited),
            CheckOutcome::Skipped(_)
        ));
    }
}
// RETIRED-NAME-ANCHOR-END
