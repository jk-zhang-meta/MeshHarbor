// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — keep busy: synthetic mouse patterns that keep a host active, and
//! that any real user takes over at once.
//!
//! An `INPUT` session turns it on from the viewer; the agent then moves the
//! pointer in a pattern so the OS idle clock never runs out (no screensaver,
//! no idle lock, no "Away"). Any real input — the person at the machine or a
//! controller — pauses it; it resumes after `resume_after` of quiet, and
//! stays on across disconnects, self-updates and reboots until switched off.
//!
//! Layout:
//! * [`patterns`] — the shapes, pure geometry;
//! * [`engine`] — the state machine, pure (a `Host` trait carries every OS
//!   fact, so it is unit-tested with a scripted fake);
//! * [`wire`] — `rc:keep-busy.*` on the control data channel;
//! * [`state`] — the per-person store;
//! * this file — the engine's thread and its process-global handle.
//!
//! The engine runs on its own thread and asks the input arbiter — the ONE OS
//! injector — to read and move the cursor. It is never a second injector.
//! See `docs/fr/FR-92-keep-busy.md`.

pub mod engine;
#[cfg(target_os = "linux")]
pub mod logind;
pub mod patterns;
pub mod state;
pub mod wire;

#[cfg(feature = "enigo-input")]
mod arbiter_io;
// FR-92 P9 — the pure half of the GNOME host: built everywhere so its rules
// are tests on every platform; used only where the host is.
#[cfg_attr(
    not(all(
        target_os = "linux",
        feature = "enigo-input",
        feature = "uinput-input",
        feature = "portal-capture"
    )),
    allow(dead_code)
)]
mod gnome;
#[cfg(all(
    target_os = "linux",
    feature = "enigo-input",
    feature = "uinput-input",
    feature = "portal-capture"
))]
mod host_gnome;
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
mod host_linux;
#[cfg(all(target_os = "macos", feature = "enigo-input"))]
mod host_mac;
/// FR-97 P2d-1 — the console session's lock, which `lock_state` reports too.
#[cfg(all(target_os = "macos", feature = "enigo-input"))]
pub(crate) use host_mac::screen_locked as mac_screen_locked;
#[cfg(all(target_os = "windows", feature = "enigo-input"))]
mod host_win;
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
mod host_x11;
/// FR-92 P9 — the child the daemon runs inside a person's GNOME session
/// (`roomlerd portal-helper --keep-busy`), and the daemon's link to it.
#[cfg(all(target_os = "linux", feature = "portal-capture"))]
pub mod session_helper;

pub use wire::SetRequest;

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bson::oid::ObjectId;

use engine::{Engine, Host, Reason, Settings, Snapshot};

/// Bumped by the input arbiter on every controller-caused injection, so the
/// engine knows — exactly — that a remote person is active.
static REMOTE_INPUT_EPOCH: AtomicU64 = AtomicU64::new(0);

/// FR-108 — the OS input-clock tick of the latest controller injection and of
/// keep busy's latest own move (`presence::os_tick`, the clock
/// `GetLastInputInfo` reports in), so a person's input can be told from the
/// machine's by WHEN it came. `0` = none yet in this process.
static LAST_REMOTE_INPUT_TICK: AtomicU32 = AtomicU32::new(0);
static LAST_OWN_MOVE_TICK: AtomicU32 = AtomicU32::new(0);

/// A controller's input reached the OS. Called by the arbiter for every
/// injected session event (never a heartbeat, never a denied event).
pub fn note_remote_input() {
    REMOTE_INPUT_EPOCH.fetch_add(1, Ordering::Relaxed);
    LAST_REMOTE_INPUT_TICK.store(crate::presence::os_tick(), Ordering::Relaxed);
}

/// The current remote-input epoch.
pub fn remote_input_epoch() -> u64 {
    REMOTE_INPUT_EPOCH.load(Ordering::Relaxed)
}

/// FR-108 — keep busy moved the pointer itself (a move the arbiter executed).
pub fn note_own_move() {
    LAST_OWN_MOVE_TICK.store(crate::presence::os_tick(), Ordering::Relaxed);
}

/// FR-108 — when the controller last injected, on the OS input clock.
pub fn last_remote_input_tick() -> Option<u32> {
    match LAST_REMOTE_INPUT_TICK.load(Ordering::Relaxed) {
        0 => None,
        t => Some(t),
    }
}

/// FR-108 — when keep busy last moved the pointer, on the OS input clock.
pub fn last_own_move_tick() -> Option<u32> {
    match LAST_OWN_MOVE_TICK.load(Ordering::Relaxed) {
        0 => None,
        t => Some(t),
    }
}

/// Is keep-busy built for this host at all? Windows (FR-92 P1), Linux X11
/// (P3a), macOS (P3b), and a GNOME session reached through uinput — Wayland,
/// or Xorg under a root daemon (P9). Any other Wayland desktop is detected
/// at run time and reported `unavailable` with its reason — the cap word
/// stays, so the viewer can say why. On a supervised Mac BOTH processes run an engine: the
/// GUI worker's is the one that moves (sessions are delegated to it), and
/// the root daemon's waits as "nobody signed in" — it has no GUI session —
/// while handing the worker the orgs' policy. The cap word also needs the
/// device owner's `keep_busy_enabled`.
pub fn supported_here() -> bool {
    cfg!(all(
        any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos"
        ),
        feature = "enigo-input"
    ))
}

/// What the engine thread is asked to do.
#[derive(Debug)]
pub enum Command {
    Set {
        session: Option<ObjectId>,
        set_by: String,
        settings: Settings,
    },
    Off {
        why: Reason,
    },
    DeviceEnabled(bool),
    /// One enrolled org's policy (`tenant` = its hex id). The engine thread
    /// keeps the last value per org, persists it, and applies the STRICTEST:
    /// any org's deny stops keep busy here.
    OrgPolicy {
        tenant: String,
        denied: bool,
    },
}

struct Service {
    tx: SyncSender<Command>,
    state: tokio::sync::watch::Receiver<Snapshot>,
}

static SERVICE: OnceLock<Service> = OnceLock::new();
/// The device owner's `keep_busy_enabled`, mirrored for the cap word.
static DEVICE_ENABLED: AtomicBool = AtomicBool::new(true);

/// Process-local microseconds for the hosts' "time since" clocks — offset
/// far from zero, so `t − idle` never underflows on a host that has been idle
/// longer than this process has been up.
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "macos"), feature = "enigo-input")),
    allow(dead_code)
)]
pub(crate) fn mono_us() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    (1u64 << 50) + start.elapsed().as_micros() as u64
}

pub(crate) fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Start the engine thread — once per process, from inside the tokio
/// runtime. `device_enabled` is the owner's `keep_busy_enabled`;
/// `enrolled_tenants` is every org this device is enrolled in (the primary
/// and each `[[orgs]]` entry, enabled or not), so a stored deny from an org
/// it has LEFT can be dropped ([`prune_departed_orgs`]).
///
/// ⚠️ It initialises the input arbiter FIRST: `arbiter::global()` captures
/// the tokio handle at its first call, and the engine thread (a plain std
/// thread) must never be that first caller.
pub fn start(device_enabled: bool, enrolled_tenants: Vec<String>) {
    DEVICE_ENABLED.store(device_enabled, Ordering::Relaxed);
    if !supported_here() {
        return;
    }
    SERVICE.get_or_init(|| {
        let _ = crate::input::arbiter::global();
        let (tx, rx) = sync_channel::<Command>(64);
        let now = Instant::now();
        let mut engine = Engine::new(wall_ms() ^ u64::from(std::process::id()));
        engine.set_device_enabled(device_enabled, now);
        let (out, state) = tokio::sync::watch::channel(engine.snapshot(now));
        std::thread::Builder::new()
            .name("keep-busy".into())
            .spawn(move || run(engine, rx, out, enrolled_tenants))
            .expect("spawn keep-busy thread");
        Service { tx, state }
    });
}

fn submit(cmd: Command) {
    if let Some(s) = SERVICE.get()
        && s.tx.try_send(cmd).is_err()
    {
        tracing::warn!("keep-busy: command queue full — command dropped");
    }
}

/// A controller's `rc:keep-busy.set`, already authorised by the arbiter
/// (the session holds INPUT and, in exclusive mode, the floor). An org deny
/// is the engine's to refuse — it is device-wide. `false`
/// when this host cannot run keep-busy — the arbiter then answers that
/// viewer with the reason, since no engine broadcast will.
pub fn submit_from_session(session: ObjectId, name: String, req: SetRequest) -> bool {
    if !supported_here() || SERVICE.get().is_none() {
        tracing::info!(%session, "keep-busy: set from a session on a host that cannot run it");
        return false;
    }
    submit(if req.on {
        Command::Set {
            session: Some(session),
            set_by: name,
            settings: req.settings,
        }
    } else {
        Command::Off {
            why: Reason::StoppedByController,
        }
    });
    true
}

/// FR-92 P10 — who a local start names: the person at the console. The
/// LocalAPI has already checked the peer stands where that person does (never
/// root, never a service, never another session); their account name is not
/// ours to report to every viewer and the org's history. ⚠️ On Windows a
/// `meshharbor exec` runs in the console session, passes that check and is named
/// this too (FR-92 §3g).
pub const LOCAL_SET_BY: &str = "the person at this computer";

/// FR-92 P10 — the person at the machine turns it ON (tray, CLI). `opts`
/// carries the viewer's own wire names, read by the viewer's own parser
/// ([`wire::parse_set`]): an unknown pattern is an error, never a circle.
/// Waits (bounded) for the engine's answer, so the caller sees `on` — or the
/// reason it refused (`org_denied`, `device_disabled`, …).
pub async fn start_locally_and_wait(
    opts: &tunnel_core::localapi::KeepBusyStartOpts,
    timeout: Duration,
) -> Result<Snapshot, String> {
    let mut val = serde_json::to_value(opts).map_err(|e| e.to_string())?;
    if let Some(m) = val.as_object_mut() {
        m.insert("on".into(), serde_json::Value::Bool(true));
    }
    let req = wire::parse_set(&val, wall_ms()).map_err(|e| e.to_string())?;
    let Some(mut rx) = subscribe() else {
        return Ok(snapshot());
    };
    // Mark what is published now as seen, so the wait below ends at the
    // engine's answer to THIS start: on, or a refusal it publishes too.
    let _seen = rx.borrow_and_update().rev;
    submit(Command::Set {
        session: None,
        set_by: LOCAL_SET_BY.into(),
        settings: req.settings,
    });
    let _ = tokio::time::timeout(timeout, rx.changed()).await;
    Ok(snapshot())
}

/// The person at the machine stops it (LocalAPI, tray, CLI).
pub fn stop_locally() {
    submit(Command::Off {
        why: Reason::StoppedLocally,
    });
}

/// [`stop_locally`], then wait (bounded) for the engine to say it is off, so
/// the tray and the CLI can answer with the truth instead of a guess.
pub async fn stop_locally_and_wait(timeout: Duration) -> Snapshot {
    let Some(mut rx) = subscribe() else {
        return snapshot();
    };
    stop_locally();
    let _ = tokio::time::timeout(timeout, async {
        while rx.borrow_and_update().on {
            if rx.changed().await.is_err() {
                break;
            }
        }
    })
    .await;
    snapshot()
}

/// How long a local `off` waits for the engine to say it stopped.
pub const LOCAL_OFF_WAIT: Duration = Duration::from_millis(800);

/// A LocalAPI keep-busy verb, answered by THIS process's engine: the status,
/// or (`off`) a local stop and then the status. One body for the LocalAPI
/// handlers and for a supervised Mac's GUI worker answering its daemon
/// (`delegate::DelegateFrame::KeepBusyAsk`), so the two cannot drift.
pub async fn answer_local(off: bool) -> tunnel_core::localapi::KeepBusyInfo {
    let s = if off {
        stop_locally_and_wait(LOCAL_OFF_WAIT).await
    } else {
        snapshot()
    };
    local_info(&s)
}

/// The LocalAPI's view of a snapshot (`roomler keep-busy status`, the tray).
pub fn local_info(s: &Snapshot) -> tunnel_core::localapi::KeepBusyInfo {
    tunnel_core::localapi::KeepBusyInfo {
        available: s.available,
        on: s.on,
        phase: s.phase.wire().into(),
        reason: s.reason.map(|r| r.wire().into()),
        sentence: s.reason.map(|r| r.sentence().into()),
        paused_by: s.paused_by.map(|p| p.wire().into()),
        resumes_in_ms: s.resumes_in.map(|d| d.as_millis() as u64),
        pattern: s.settings.pattern.wire().into(),
        set_by: s.set_by.clone(),
        set_at_ms: s.set_at_ms,
        auto_off_at_ms: s.settings.auto_off_at_ms,
    }
}

/// The owner's `keep_busy_enabled` changed (it is a live key).
pub fn set_device_enabled(enabled: bool) {
    DEVICE_ENABLED.store(enabled, Ordering::Relaxed);
    submit(Command::DeviceEnabled(enabled));
}

/// One enrolled org's keep-busy policy, as its server pushed it
/// (`rc:agent.keep_busy_policy`, on every connect and on change).
pub fn set_org_policy(tenant: &str, denied: bool) {
    submit(Command::OrgPolicy {
        tenant: tenant.to_string(),
        denied,
    });
}

/// The strictest of every enrolled org's last-known policy: one deny is
/// enough. Pure, so the rule is a unit test.
pub fn org_denied(policies: &std::collections::BTreeMap<String, bool>) -> bool {
    policies.values().any(|d| *d)
}

/// Drop the stored policy of every org this device is no longer enrolled
/// in, and say how many went. Without it, leaving an org that had denied
/// keep busy would deny it here for good: no server would ever push that
/// org's re-allow. An empty `enrolled` (no identity known) drops nothing.
pub fn prune_departed_orgs(
    policies: &mut std::collections::BTreeMap<String, bool>,
    enrolled: &[String],
) -> usize {
    if enrolled.is_empty() {
        return 0;
    }
    let before = policies.len();
    policies.retain(|tenant, _| enrolled.iter().any(|e| e == tenant));
    before - policies.len()
}

/// Should `AgentCaps.input` carry `keep-busy`? Built for this host, the
/// engine running, and the device owner allows it. An org deny does NOT
/// remove the word: the viewer shows the control disabled with the reason,
/// which says more than a control that silently vanished.
pub fn advertised() -> bool {
    supported_here() && SERVICE.get().is_some() && DEVICE_ENABLED.load(Ordering::Relaxed)
}

/// The current public state (a "not here" state when the engine is not
/// running on this host).
pub fn snapshot() -> Snapshot {
    match SERVICE.get() {
        Some(s) => s.state.borrow().clone(),
        None => Snapshot {
            rev: 0,
            available: false,
            on: false,
            phase: engine::Phase::Unavailable,
            reason: Some(Reason::Unsupported),
            paused_by: None,
            resumes_in: None,
            settings: Settings::default(),
            set_by: None,
            set_at_ms: None,
            detector: "none",
            warn: Vec::new(),
        },
    }
}

/// FR-92 P5b — keep busy for the heartbeat, so the device list can show
/// where it runs and who turned it on. `None` where this process cannot
/// speak for it: no engine here, or a macOS ROOT daemon — on a supervised Mac
/// the GUI worker runs keep busy, and the daemon's own engine (no GUI
/// session, nothing to move) would report a confident, wrong "off". Every
/// org's loop asks this one process-wide answer, so a secondary org cannot
/// get it wrong either.
pub fn brief() -> Option<roomler_ai_remote_control::models::KeepBusyBrief> {
    SERVICE.get()?;
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return None;
        }
    }
    Some(brief_of(&snapshot()))
}

/// The brief a snapshot makes. Pure. The pattern and who set it travel only
/// while it is on: an "off" row names nobody.
pub fn brief_of(s: &Snapshot) -> roomler_ai_remote_control::models::KeepBusyBrief {
    roomler_ai_remote_control::models::KeepBusyBrief {
        on: s.on,
        phase: s.phase.wire().to_string(),
        reason: s.reason.map(|r| r.wire().to_string()),
        pattern: s.on.then(|| s.settings.pattern.wire().to_string()),
        set_by: if s.on { s.set_by.clone() } else { None },
    }
}

/// A watch of the public state, for the per-session emitters and the
/// LocalAPI. `None` when the engine is not running on this host.
pub fn subscribe() -> Option<tokio::sync::watch::Receiver<Snapshot>> {
    SERVICE.get().map(|s| s.state.clone())
}

/// `rc:keep-busy.state` as JSON text. `refused` names why the receiving
/// viewer's own request was not applied.
pub fn state_json(refused: Option<&str>) -> String {
    wire::state_payload(&snapshot(), refused).to_string()
}

/// How often host warnings (focus-follows-mouse, …) are re-read.
const WARNINGS_EVERY: Duration = Duration::from_secs(300);

fn run(
    engine: Engine,
    rx: Receiver<Command>,
    out: tokio::sync::watch::Sender<Snapshot>,
    enrolled_tenants: Vec<String>,
) {
    #[cfg(all(target_os = "windows", feature = "enigo-input"))]
    {
        run_with(
            engine,
            rx,
            out,
            host_win::WinHost::new(),
            host_win::warnings,
            &enrolled_tenants,
        );
    }
    #[cfg(all(target_os = "linux", feature = "enigo-input"))]
    {
        // X11 where this process holds a real X display; otherwise (a root
        // daemon, Xwayland) a GNOME session through uinput — FR-92 P9.
        run_with(
            engine,
            rx,
            out,
            host_linux::LinuxHost::new(),
            host_x11::warnings,
            &enrolled_tenants,
        );
    }
    #[cfg(all(target_os = "macos", feature = "enigo-input"))]
    {
        run_with(
            engine,
            rx,
            out,
            host_mac::MacHost::new(),
            host_mac::warnings,
            &enrolled_tenants,
        );
    }
    #[cfg(not(all(
        any(target_os = "windows", target_os = "linux", target_os = "macos"),
        feature = "enigo-input"
    )))]
    {
        let _ = (engine, rx, out, enrolled_tenants);
    }
}

/// How often the signed-in person is looked up again, where it can change
/// under a running process ([`state::person_can_change`]).
const PERSON_EVERY: Duration = Duration::from_secs(10);

/// What a change of signed-in person does to keep busy.
#[derive(Debug, Clone, PartialEq)]
pub enum PersonSwitch {
    /// Their own stored keep busy — or none — replaces whatever ran.
    Restore(Option<engine::Activation>),
    /// Keep what runs, and store it as theirs: it was turned on while nobody
    /// was signed in — a technician at the login screen, signing them in.
    Adopt,
}

/// The person at the machine changed (`someone` = a person is signed in
/// now). Their own stored keep busy wins; failing that, one turned on while
/// NOBODY was signed in becomes theirs; anything else stops — keep busy is
/// never handed from one person to another. Pure, so the rule is a test.
pub fn person_switch(
    running: bool,
    set_while_nobody: bool,
    someone: bool,
    theirs: Option<engine::Activation>,
) -> PersonSwitch {
    match theirs {
        Some(a) => PersonSwitch::Restore(Some(a)),
        None if someone && running && set_while_nobody => PersonSwitch::Adopt,
        None => PersonSwitch::Restore(None),
    }
}

#[cfg_attr(
    not(all(
        any(target_os = "windows", target_os = "linux", target_os = "macos"),
        feature = "enigo-input"
    )),
    allow(dead_code)
)]
fn run_with<H: Host>(
    mut engine: Engine,
    rx: Receiver<Command>,
    out: tokio::sync::watch::Sender<Snapshot>,
    mut host: H,
    warnings: fn() -> Vec<&'static str>,
    enrolled_tenants: &[String],
) {
    // Whose store this is can change under a running process (a SYSTEM
    // worker, a root Linux daemon): then the person is looked up again.
    let person_moves = state::person_can_change();
    let mut path = state::default_path();
    let mut stored = path.as_deref().map(state::load_from).unwrap_or_default();
    let start = Instant::now();
    let mut person_at = start + PERSON_EVERY;
    // The running keep busy was turned on while nobody was signed in.
    let mut set_while_nobody = false;
    let departed = prune_departed_orgs(&mut stored.org_denied, enrolled_tenants);
    if departed > 0 {
        tracing::info!(
            departed,
            "keep-busy: dropped the stored policy of orgs this device has left"
        );
        if let Some(p) = path.as_deref()
            && let Err(e) = state::save_to(p, &stored)
        {
            tracing::warn!(path = %p.display(), error = %e, "keep-busy: could not save the store");
        }
    }
    if org_denied(&stored.org_denied) {
        engine.set_org_denied(true, start);
    }
    if let Some(act) = stored.activation(wall_ms()) {
        tracing::info!(
            pattern = act.settings.pattern.wire(),
            set_by = %act.set_by,
            "keep-busy: restored from the per-person store — waiting for an unlocked session"
        );
        engine.restore(act, start);
    }
    engine.set_warnings(warnings());
    let mut warnings_at = start + WARNINGS_EVERY;
    let mut last_act = engine.activation().cloned();
    let mut published = 0u64;
    let mut last_logged = (engine.snapshot(start).phase, engine.snapshot(start).reason);

    loop {
        let wake = match (engine.next_wake(), person_moves) {
            (w, false) => w,
            (Some(w), true) => Some(w.min(person_at)),
            (None, true) => Some(person_at),
        };
        let msg = match wake {
            Some(w) => rx.recv_timeout(w.saturating_duration_since(Instant::now())),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        let now = Instant::now();
        // Who is signed in, BEFORE a turn-on is applied: it must land in that
        // person's store, and never be undone by a switch a moment later.
        let asks_on = matches!(msg, Ok(Command::Set { .. }));
        if person_moves && (now >= person_at || asks_on) {
            person_at = now + PERSON_EVERY;
            // With nothing running and nothing stored for anyone, there is
            // nothing a login could restore — skip the lookup (on a root
            // Linux daemon it spawns `loginctl`).
            if asks_on || engine.is_on() || state::someone_left_it_on() {
                let now_path = state::default_path();
                if now_path != path {
                    let mut theirs = now_path
                        .as_deref()
                        .map(state::load_from)
                        .unwrap_or_default();
                    // The org's word is the DEVICE's, not a person's.
                    theirs.org_denied = stored.org_denied.clone();
                    let decision = person_switch(
                        engine.is_on(),
                        set_while_nobody,
                        now_path.is_some(),
                        theirs.activation(wall_ms()),
                    );
                    tracing::info!(
                        signed_in = now_path.is_some(),
                        adopted = decision == PersonSwitch::Adopt,
                        "keep-busy: the person at this computer changed"
                    );
                    match decision {
                        PersonSwitch::Adopt => {
                            theirs = theirs.with_activation(engine.activation());
                        }
                        PersonSwitch::Restore(act) => engine.switch_person(act, now),
                    }
                    path = now_path;
                    stored = theirs;
                    if let Some(p) = path.as_deref()
                        && let Err(e) = state::save_to(p, &stored)
                    {
                        tracing::warn!(path = %p.display(), error = %e, "keep-busy: could not save the store");
                    }
                    last_act = engine.activation().cloned();
                    set_while_nobody = false;
                }
            }
        }
        match msg {
            // The org policy needs the store, so it is handled here.
            Ok(Command::OrgPolicy { tenant, denied }) => {
                if stored.org_denied.get(&tenant) != Some(&denied) {
                    stored.org_denied.insert(tenant, denied);
                    if let Some(p) = path.as_deref()
                        && let Err(e) = state::save_to(p, &stored)
                    {
                        tracing::warn!(path = %p.display(), error = %e, "keep-busy: could not save the store");
                    }
                }
                engine.set_org_denied(org_denied(&stored.org_denied), now);
            }
            Ok(cmd) => apply(&mut engine, cmd, now),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        // Deadline-driven: a steady stream of commands must not starve the
        // ticks (a `recv_timeout` that keeps returning early never times out).
        if engine.next_wake().is_some_and(|w| Instant::now() >= w) {
            engine.tick(&mut host);
        }
        if now >= warnings_at {
            engine.set_warnings(warnings());
            warnings_at = now + WARNINGS_EVERY;
        }
        // Persist on/off edges only — never pause/resume.
        if engine.activation() != last_act.as_ref() {
            if last_act.is_none() {
                set_while_nobody = path.is_none();
            }
            if engine.activation().is_none() {
                set_while_nobody = false;
            }
            last_act = engine.activation().cloned();
            stored = stored.with_activation(last_act.as_ref());
            if let Some(p) = path.as_deref()
                && let Err(e) = state::save_to(p, &stored)
            {
                tracing::warn!(path = %p.display(), error = %e, "keep-busy: could not save the store");
            }
        }
        if engine.rev() != published {
            published = engine.rev();
            let snap = engine.snapshot(Instant::now());
            if (snap.phase, snap.reason) != last_logged {
                last_logged = (snap.phase, snap.reason);
                tracing::info!(
                    on = snap.on,
                    phase = snap.phase.wire(),
                    reason = snap.reason.map(Reason::wire).unwrap_or("-"),
                    paused_by = snap.paused_by.map(engine::Source::wire).unwrap_or("-"),
                    "keep-busy: state"
                );
            }
            let _ = out.send(snap);
        }
    }
    tracing::info!("keep-busy: engine thread exiting");
}

fn apply(engine: &mut Engine, cmd: Command, now: Instant) {
    match cmd {
        Command::Set {
            session,
            set_by,
            settings,
        } => {
            let pattern = settings.pattern.wire();
            match engine.set_on(settings, set_by.clone(), wall_ms(), now) {
                Ok(()) => tracing::info!(
                    session = ?session.map(|s| s.to_hex()),
                    %set_by,
                    pattern,
                    "keep-busy: turned on"
                ),
                Err(r) => {
                    tracing::info!(%set_by, reason = r.wire(), "keep-busy: turn-on refused");
                    // Publish anyway: the asking viewer must see why.
                    engine.touch();
                }
            }
        }
        Command::Off { why } => {
            tracing::info!(reason = why.wire(), "keep-busy: turned off");
            engine.turn_off(why, now);
        }
        Command::DeviceEnabled(b) => engine.set_device_enabled(b, now),
        // Handled in the loop, where the store is.
        Command::OrgPolicy { .. } => {}
    }
}

/// Virtual-screen pixel → the `0..=65535` range Windows'
/// `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` wants, rounded to
/// nearest, for a virtual screen at `(vx, vy)` of `vw × vh`. Pure and
/// ungated so the mapping is tested on every lane, not only where the
/// Windows input backend compiles.
pub fn normalise_virtual(x: i32, y: i32, vx: i32, vy: i32, vw: i32, vh: i32) -> Option<(i32, i32)> {
    if vw < 2 || vh < 2 {
        return None;
    }
    let map = |p: i32, origin: i32, span: i32| -> i32 {
        let local = (p - origin).clamp(0, span - 1) as i64;
        ((local * 65535 + (span as i64 - 1) / 2) / (span as i64 - 1)) as i32
    };
    Some((map(x, vx, vw), map(y, vy, vh)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inverse of what Windows does with an absolute VIRTUALDESK move:
    /// `pixel = origin + round(norm * (span - 1) / 65535)`.
    fn back(n: i32, origin: i32, span: i32) -> i32 {
        origin + ((n as f64) * (span - 1) as f64 / 65535.0).round() as i32
    }

    #[test]
    fn virtual_desk_mapping_round_trips_every_pixel_on_odd_layouts() {
        // A primary at (0,0) and a second monitor to its LEFT and above: the
        // virtual screen starts at a negative origin.
        for (vx, vy, vw, vh) in [
            (0, 0, 1920, 1080),
            (-2560, -360, 4480, 1440),
            (0, 0, 7680, 2160),
        ] {
            for x in (vx..vx + vw).step_by(7) {
                let (nx, _) = normalise_virtual(x, vy, vx, vy, vw, vh).unwrap();
                assert!((0..=65535).contains(&nx));
                assert_eq!(back(nx, vx, vw), x, "x={x} on {vw}@{vx}");
            }
            for y in (vy..vy + vh).step_by(5) {
                let (_, ny) = normalise_virtual(vx, y, vx, vy, vw, vh).unwrap();
                assert_eq!(back(ny, vy, vh), y, "y={y} on {vh}@{vy}");
            }
        }
    }

    #[test]
    fn virtual_desk_mapping_clamps_and_refuses_a_degenerate_screen() {
        assert_eq!(normalise_virtual(-10, -10, 0, 0, 1920, 1080), Some((0, 0)));
        assert_eq!(
            normalise_virtual(99_999, 99_999, 0, 0, 1920, 1080),
            Some((65535, 65535))
        );
        assert_eq!(normalise_virtual(0, 0, 0, 0, 1, 1080), None);
    }

    /// FR-92 — the strictest of every enrolled org: one deny is enough, and
    /// an org that never said anything (an older server) does not deny.
    #[test]
    fn one_orgs_deny_is_enough_and_silence_is_not_a_deny() {
        let mut m = std::collections::BTreeMap::new();
        assert!(!org_denied(&m), "no org has spoken: allowed");
        m.insert("primary".to_string(), false);
        assert!(!org_denied(&m));
        m.insert("secondary".to_string(), true);
        assert!(org_denied(&m), "a secondary org's deny holds device-wide");
        m.insert("secondary".to_string(), false);
        assert!(!org_denied(&m), "a re-allow clears it");
    }

    /// FR-92 — a device that LEFT an org which had denied keep busy must
    /// not stay denied for good: no server will ever push that org's
    /// re-allow. An empty enrolled list (no identity known) drops nothing.
    #[test]
    fn leaving_an_org_drops_its_stored_deny() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("primary".to_string(), false);
        m.insert("left".to_string(), true);
        assert_eq!(prune_departed_orgs(&mut m, &[]), 0);
        assert!(org_denied(&m), "nothing known: the deny stands");
        let enrolled = ["primary".to_string(), "joined-but-silent".to_string()];
        assert_eq!(prune_departed_orgs(&mut m, &enrolled), 1);
        assert!(!org_denied(&m), "the departed org's deny is gone");
        assert_eq!(m.len(), 1);
        assert_eq!(prune_departed_orgs(&mut m, &enrolled), 0, "idempotent");
    }

    fn act(by: &str) -> engine::Activation {
        engine::Activation {
            settings: Settings::default(),
            set_by: by.into(),
            set_at_ms: 1,
        }
    }

    /// FR-92 P3 — a new person at the machine gets THEIR keep busy, never
    /// the last person's; one turned on while nobody was signed in (a
    /// technician at the login screen) becomes the person's who signs in.
    #[test]
    fn keep_busy_is_never_handed_from_one_person_to_another() {
        use PersonSwitch::*;
        // Their own store wins, whatever ran.
        assert_eq!(
            person_switch(true, false, true, Some(act("Bob"))),
            Restore(Some(act("Bob")))
        );
        assert_eq!(
            person_switch(true, true, true, Some(act("Bob"))),
            Restore(Some(act("Bob")))
        );
        // Alice's keep busy, and Bob signs in with none stored: it stops.
        assert_eq!(person_switch(true, false, true, None), Restore(None));
        // Turned on at the login screen, then Bob signs in: it is his.
        assert_eq!(person_switch(true, true, true, None), Adopt);
        // Everyone signed out: it stops (it stays stored for its owner).
        assert_eq!(person_switch(true, false, false, None), Restore(None));
        assert_eq!(person_switch(true, true, false, None), Restore(None));
        // Nothing ran: nothing to adopt.
        assert_eq!(person_switch(false, true, true, None), Restore(None));
    }

    /// The code part of a line: what precedes a `//` comment. Comments name
    /// the banned APIs on purpose — to say why they are not used.
    fn code_of(line: &str) -> &str {
        line.split("//").next().unwrap_or("")
    }

    /// FR-92 AC8 — keep busy tells a person from itself WITHOUT a hook, raw
    /// input, a keyboard poll or an event tap: each is what a keylogger looks
    /// like to EDR, and a GPO-locked desktop running EDR is in the acceptance
    /// bar. This scans the module's own sources, every host included, and the
    /// injector's keep-busy reads. The banned names are assembled at run time,
    /// so this file cannot trip its own scan. Mouse BUTTON state may be read
    /// (once per resume); the keyboard's never.
    #[test]
    fn no_keylogger_shaped_api_anywhere_in_keep_busy() {
        let sources: [(&str, &str); 16] = [
            ("mod.rs", include_str!("mod.rs")),
            ("engine.rs", include_str!("engine.rs")),
            ("patterns.rs", include_str!("patterns.rs")),
            ("state.rs", include_str!("state.rs")),
            ("wire.rs", include_str!("wire.rs")),
            ("arbiter_io.rs", include_str!("arbiter_io.rs")),
            ("logind.rs", include_str!("logind.rs")),
            ("host_win.rs", include_str!("host_win.rs")),
            ("host_x11.rs", include_str!("host_x11.rs")),
            ("host_mac.rs", include_str!("host_mac.rs")),
            // FR-92 P9: the GNOME host, its helper, and uinput's move.
            ("gnome.rs", include_str!("gnome.rs")),
            ("host_gnome.rs", include_str!("host_gnome.rs")),
            ("host_linux.rs", include_str!("host_linux.rs")),
            ("session_helper.rs", include_str!("session_helper.rs")),
            (
                "input/uinput_backend.rs",
                include_str!("../input/uinput_backend.rs"),
            ),
            (
                "input/enigo_backend.rs",
                include_str!("../input/enigo_backend.rs"),
            ),
        ];
        let banned: Vec<String> = [
            // Windows: hooks, raw input, keyboard state.
            ["SetWindows", "HookEx"],
            ["RegisterRaw", "InputDevices"],
            ["GetRaw", "InputData"],
            ["GetKeyboard", "State"],
            // macOS: event taps, global monitors, HID managers.
            ["CGEventTap", "Create"],
            ["addGlobalMonitor", "ForEvents"],
            ["IOHIDManager", "Create"],
            // X11: the RECORD extension, raw XInput2 key events, keymap polls.
            ["record_create", "_context"],
            ["XRecord", "CreateContext"],
            ["RawKey", "Press"],
            ["query_", "keymap"],
            ["XQuery", "Keymap"],
            // Linux: reading input devices directly.
            ["/dev/input/", "event"],
        ]
        .iter()
        .map(|p| p.concat())
        .collect();
        let key_state = ["GetAsync", "KeyState"].concat();
        // Every file of this module is in the list: a new host must not slip
        // past the scan because nobody remembered to add it here.
        let listed: Vec<&str> = sources.iter().map(|(n, _)| *n).collect();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/keep_busy");
        for entry in std::fs::read_dir(&dir).expect("the keep_busy sources") {
            let file = entry.unwrap().file_name().to_string_lossy().into_owned();
            if file.ends_with(".rs") {
                assert!(listed.contains(&file.as_str()), "{file} is not scanned");
            }
        }
        for (name, src) in sources {
            let lines: Vec<&str> = src.lines().map(code_of).collect();
            for (i, code) in lines.iter().enumerate() {
                for b in &banned {
                    assert!(!code.contains(b.as_str()), "{name}:{}: uses {b}", i + 1);
                }
                // `GetAsyncKeyState` only ever with mouse buttons nearby: every
                // `VK_` within six lines of it must be a BUTTON.
                if code.contains(key_state.as_str()) {
                    let lo = i.saturating_sub(6);
                    let hi = (i + 7).min(lines.len());
                    for near in &lines[lo..hi] {
                        for tok in near.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                            assert!(
                                !tok.starts_with("VK_") || tok.contains("BUTTON"),
                                "{name}:{}: {key_state} beside a keyboard key ({tok})",
                                i + 1
                            );
                        }
                    }
                }
            }
        }
    }

    /// FR-92 P5b — the device list learns the phase, the reason, and — only
    /// while it is on — the pattern and who turned it on. An "off" row names
    /// nobody, whatever the snapshot still carries.
    #[test]
    fn the_brief_names_the_pattern_and_who_only_while_on() {
        let base = Snapshot {
            rev: 3,
            available: true,
            on: true,
            phase: engine::Phase::Running,
            reason: None,
            paused_by: None,
            resumes_in: None,
            settings: Settings {
                pattern: patterns::Pattern::Heart,
                ..Settings::default()
            },
            set_by: Some("Alice".into()),
            set_at_ms: Some(1),
            detector: "clock+cursor",
            warn: Vec::new(),
        };
        let b = brief_of(&base);
        assert!(b.on);
        assert_eq!(b.phase, "running");
        assert_eq!(b.reason, None);
        assert_eq!(b.pattern.as_deref(), Some("heart"));
        assert_eq!(b.set_by.as_deref(), Some("Alice"));

        let paused = Snapshot {
            phase: engine::Phase::Paused,
            reason: Some(Reason::UserActive),
            ..base.clone()
        };
        assert_eq!(brief_of(&paused).reason.as_deref(), Some("user_active"));

        let off = Snapshot {
            on: false,
            phase: engine::Phase::Off,
            reason: Some(Reason::StoppedLocally),
            ..base
        };
        let b = brief_of(&off);
        assert!(!b.on);
        assert_eq!(b.reason.as_deref(), Some("stopped_locally"));
        assert_eq!((b.pattern, b.set_by), (None, None));
    }

    #[test]
    fn the_remote_epoch_only_moves_forward() {
        let a = remote_input_epoch();
        note_remote_input();
        assert!(remote_input_epoch() > a);
    }

    /// Off this host's build (no Windows input backend) nothing is
    /// advertised and the state says why.
    #[test]
    fn without_the_engine_nothing_is_advertised_and_the_state_says_why() {
        if supported_here() {
            return;
        }
        assert!(!advertised());
        let s = snapshot();
        assert!(!s.available);
        assert_eq!(s.reason, Some(Reason::Unsupported));
        let v: serde_json::Value = serde_json::from_str(&state_json(None)).unwrap();
        assert_eq!(v["reason"], "unsupported");
    }
}
