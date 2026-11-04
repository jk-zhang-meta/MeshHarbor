// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — the keep-busy state machine.
//!
//! Pure: every OS fact arrives through [`Host`], so the whole decision
//! surface — when to move, when a human is present, when to resume, when to
//! give up — is unit-tested with a scripted fake host and a fake clock. The
//! split is the input arbiter's again (`ArbiterState` vs its worker).
//!
//! ## Who is a real user
//!
//! The engine only ever causes absolute mouse moves, so anything else is a
//! person. Each running tick it looks for, in this order:
//!
//! 1. controller input the arbiter injected since the last tick
//!    ([`Host::remote_epoch`]) — exact;
//! 2. the OS idle clock having moved past the baseline the engine read right
//!    after its OWN last move — a key, a scroll, a click, a moved mouse;
//! 3. the cursor not being where the engine left it.
//!
//! (3) without (2) is not a person — an app warped or confined the cursor —
//! and is reported as `cursor_contended`, with a growing back-off so the two
//! never fight. Hooks, raw input and key polling are deliberately absent:
//! EDR reads each as a keylogger, and a GPO-locked corporate desktop with EDR
//! is in the acceptance bar.

use std::time::{Duration, Instant};

use super::patterns::{self, Path, Pattern, Placement, Rect, SUBTLE_EVERY, Size, Speed};

/// Running cadence: smooth enough to look drawn, and ≥ two 15.6 ms ticks
/// apart so consecutive moves land on different `GetLastInputInfo` values.
pub const TICK_RUNNING: Duration = Duration::from_millis(33);
/// Cadence while `subtle` waits between nudges, and while paused.
pub const TICK_IDLE: Duration = Duration::from_millis(250);
pub const TICK_LOCKED: Duration = Duration::from_millis(500);
pub const TICK_NO_SESSION: Duration = Duration::from_secs(2);
/// How often an unavailable engine re-tries (a permission granted later, a
/// display that appears).
pub const TICK_UNAVAILABLE: Duration = Duration::from_secs(30);

/// A cursor further than this from where the engine put it has moved.
pub const CURSOR_TOLERANCE_PX: i32 = 1;
/// The calibration's out-and-back leg: far enough that "it moved" and "it
/// is stuck" are told apart beyond [`CURSOR_TOLERANCE_PX`], small enough
/// that nobody notices.
pub const CALIBRATION_NUDGE_PX: i32 = 3;
/// Speed ramps up over this long after every (re)start.
pub const EASE_IN: Duration = Duration::from_millis(400);
pub const DEFAULT_RESUME_AFTER: Duration = Duration::from_secs(30);
/// Ceiling of the `cursor_contended` back-off.
pub const CONTENDED_BACKOFF_MAX: Duration = Duration::from_secs(600);
/// Consecutive moves the idle clock never registered before the engine
/// stops claiming the host is busy.
pub const NOT_LANDING_LIMIT: u32 = 3;
/// Consecutive calibrations whose round trip failed before giving up.
pub const CALIBRATION_LIMIT: u32 = 2;
/// A `dt` larger than this (a stalled thread, a suspended laptop) is
/// clamped, so the pointer never leaps along the curve.
const MAX_STEP: Duration = Duration::from_millis(100);
/// The least time between two of the engine's OWN moves. Each move must
/// land on a different idle-clock reading, or `settle` cannot see it land:
/// `GetLastInputInfo` advances with the system timer (10–16 ms), and the
/// "seconds since" clocks carry a tolerance (`IdleMarker::tolerance`). Two
/// moves inside one timer tick read as ONE event. Before this spacing the
/// calibration's back leg followed the out leg by a few milliseconds, so it
/// usually never registered and the engine called the host `not_landing`.
/// Two 15.6 ms ticks, and above every host's tolerance.
pub const MIN_MOVE_GAP: Duration = Duration::from_millis(32);
/// While paused, a person who keeps working extends the pause. Republishing
/// every extension would flood the viewers; this is the floor between them.
const EXTENSION_REPUBLISH: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub pattern: Pattern,
    pub size: Size,
    pub speed: Speed,
    pub resume_after: Duration,
    /// Absolute wall-clock deadline (unix ms), never a remaining duration:
    /// the worker restarts on every self-update.
    pub auto_off_at_ms: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            pattern: Pattern::Circle,
            size: Size::M,
            speed: Speed::Normal,
            resume_after: DEFAULT_RESUME_AFTER,
            auto_off_at_ms: None,
        }
    }
}

/// The resume delays the viewer offers. Anything else is clamped into
/// `[MIN, MAX]` rather than refused.
pub const RESUME_AFTER_MIN: Duration = Duration::from_secs(5);
pub const RESUME_AFTER_MAX: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Off,
    /// Proving the read/write round trip before trusting the detector.
    Calibrating,
    Running,
    /// A person is active (or the cursor is contended, or a button is held).
    Paused,
    /// Lock screen, secure desktop — or nobody signed in (`reason`).
    Locked,
    /// This host cannot do it right now; `reason` says why.
    Unavailable,
}

impl Phase {
    pub fn wire(self) -> &'static str {
        match self {
            Phase::Off => "off",
            Phase::Calibrating => "calibrating",
            Phase::Running => "running",
            Phase::Paused => "paused",
            Phase::Locked => "locked",
            Phase::Unavailable => "unavailable",
        }
    }
}

/// Why the engine is where it is. A closed set with wire codes; the viewer
/// and the CLI turn each into a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    UserActive,
    CursorContended,
    ButtonHeld,
    Locked,
    NoSession,
    CalibrationFailed,
    NotLanding,
    Unsupported,
    Portal,
    /// A Wayland desktop: XTest reaches only Xwayland's own pointer.
    Wayland,
    NoIdleClock,
    NoPermission,
    DeviceDisabled,
    OrgDenied,
    Expired,
    StoppedByController,
    StoppedLocally,
}

impl Reason {
    pub fn wire(self) -> &'static str {
        match self {
            Reason::UserActive => "user_active",
            Reason::CursorContended => "cursor_contended",
            Reason::ButtonHeld => "button_held",
            Reason::Locked => "locked",
            Reason::NoSession => "no_session",
            Reason::CalibrationFailed => "calibration_failed",
            Reason::NotLanding => "not_landing",
            Reason::Unsupported => "unsupported",
            Reason::Portal => "portal",
            Reason::Wayland => "wayland",
            Reason::NoIdleClock => "no_idle_clock",
            Reason::NoPermission => "no_permission",
            Reason::DeviceDisabled => "device_disabled",
            Reason::OrgDenied => "org_denied",
            Reason::Expired => "expired",
            Reason::StoppedByController => "stopped_by_controller",
            Reason::StoppedLocally => "stopped_locally",
        }
    }

    /// The sentence a person reads. Composed here, once, so the viewer, the
    /// tray and the CLI cannot drift apart.
    pub fn sentence(self) -> &'static str {
        match self {
            Reason::UserActive => "Paused: someone is using this computer.",
            Reason::CursorContended => {
                "Paused: another program is moving the pointer, so keep busy backs off."
            }
            Reason::ButtonHeld => "Paused: a mouse button is held down.",
            Reason::Locked => "Paused: the screen is locked.",
            Reason::NoSession => "Waiting: nobody is signed in at this computer.",
            Reason::CalibrationFailed => {
                "Unavailable: the pointer did not go where it was sent, so the agent cannot tell a person from itself."
            }
            Reason::NotLanding => {
                "Unavailable: the system does not register the moves (a protected window or another desktop is in front)."
            }
            Reason::Unsupported => "Unavailable on this computer.",
            Reason::Portal => {
                "Unavailable: on this desktop the pointer is driven through a screen-sharing portal, which keep busy does not use yet."
            }
            Reason::Wayland => {
                "Unavailable on this Wayland desktop: here keep busy needs the system service with uinput input turned on, on GNOME."
            }
            Reason::NoIdleClock => {
                "Unavailable: this desktop does not report when it was last used, so a person could not take over."
            }
            Reason::NoPermission => {
                "Unavailable: the agent is not allowed to control the pointer here (macOS: Accessibility)."
            }
            Reason::DeviceDisabled => "Turned off on this computer (keep_busy_enabled = false).",
            Reason::OrgDenied => "Disabled by your organization.",
            Reason::Expired => "Turned off: the auto-off time was reached.",
            Reason::StoppedByController => "Turned off from the remote viewer.",
            Reason::StoppedLocally => "Turned off at this computer.",
        }
    }

    /// Reasons that mean "this host cannot", not "not right now" — they make
    /// the feature unavailable to a viewer, not merely paused.
    fn is_blocking(self) -> bool {
        matches!(
            self,
            Reason::Unsupported
                | Reason::Portal
                | Reason::Wayland
                | Reason::NoIdleClock
                | Reason::NoPermission
                | Reason::DeviceDisabled
                | Reason::OrgDenied
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Local,
    Remote,
}

impl Source {
    pub fn wire(self) -> &'static str {
        match self {
            Source::Local => "local",
            Source::Remote => "remote",
        }
    }
}

/// The interactive session, as the host sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Present,
    Locked,
    Absent,
    /// The host can never do this (`reason` says why).
    Unsupported(Reason),
}

/// The OS idle clock as a marker that changes whenever input arrives: the
/// instant of the last input, as `value ± tolerance` in the host's own unit.
/// `GetLastInputInfo` gives an exact tick (tolerance 0). Clocks that report
/// "time since" give an INTERVAL: the host only knows that the clock was read
/// somewhere between asking and hearing back, so the last input lies in
/// `[sent − idle, received − idle]` — however late the answer was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleMarker {
    pub value: u64,
    pub tolerance: u64,
}

impl IdleMarker {
    pub fn exact(value: u64) -> IdleMarker {
        IdleMarker {
            value,
            tolerance: 0,
        }
    }
    /// Different last inputs: the two intervals do not overlap. A slow read
    /// widens its own interval instead of shifting it, so latency can never
    /// make the engine's own move look like a person.
    pub fn differs(&self, other: &IdleMarker) -> bool {
        self.value.abs_diff(other.value) > self.tolerance + other.tolerance
    }

    /// A "time since the last input" reading the clock answered somewhere
    /// between `sent_us` and `recv_us` (µs, one monotonic clock): the last
    /// input lies in `[sent − idle, recv − idle]`, widened by the clock's own
    /// `grain_us`.
    pub fn within(sent_us: u64, recv_us: u64, idle_us: u64, grain_us: u64) -> IdleMarker {
        let lo = sent_us.saturating_sub(idle_us);
        let hi = recv_us.max(sent_us).saturating_sub(idle_us);
        IdleMarker {
            value: lo + (hi - lo) / 2,
            tolerance: (hi - lo).div_ceil(2) + grain_us,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// This host cannot (Noop injector, portal-owned input, no permission).
    Unsupported(Reason),
    /// The arbiter refused the move: a controller is holding a button.
    RemoteButtonHeld,
    /// Transient: the injector thread did not answer, an OS call failed.
    Failed(String),
}

/// Everything the engine needs from the world. The real implementation asks
/// the input arbiter (the one OS injector) to read and move the cursor, and
/// reads the idle clock, the lock state and the work area itself.
pub trait Host {
    fn now(&self) -> Instant;
    /// Wall clock, unix ms (auto-off only).
    fn wall_ms(&self) -> u64;
    fn session(&mut self) -> SessionState;
    /// `None` = this host has no idle clock.
    fn idle_marker(&mut self) -> Option<IdleMarker>;
    fn cursor(&mut self) -> Result<(i32, i32), HostError>;
    fn move_to(&mut self, p: (i32, i32)) -> Result<(), HostError>;
    /// After the engine's own move: poll (briefly) until the marker differs
    /// from `before` — our event landing — and return it. `None` = it never
    /// registered.
    fn settle(&mut self, before: IdleMarker) -> Option<IdleMarker>;
    /// Is a physical mouse button held? Read once per resume, never polled.
    fn buttons_held(&mut self) -> Result<bool, HostError>;
    /// The safe box (work area ∩ inset) of the monitor under `p`.
    fn safe_box_at(&mut self, p: (i32, i32)) -> Option<Rect>;
    /// Bumped by the arbiter on every controller-caused injection.
    fn remote_epoch(&self) -> u64;
    /// Block the engine's thread for `d` (the real host sleeps; the fake
    /// advances its clock). Only for [`MIN_MOVE_GAP`].
    fn wait(&mut self, d: Duration);
    /// FR-92 P9 — this host cannot read the pointer back (Wayland through
    /// uinput): `cursor` is where the engine last PUT it. A person is then
    /// seen by the idle clock alone (`detector` = `clock`), and a resume
    /// starts where keep busy stopped — the pointer jumps back.
    fn blind(&self) -> bool {
        false
    }
}

/// What someone asked for, and who.
#[derive(Debug, Clone, PartialEq)]
pub struct Activation {
    pub settings: Settings,
    pub set_by: String,
    pub set_at_ms: u64,
}

/// The public view, published to viewers, the LocalAPI and the heartbeat.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub rev: u64,
    /// Can it be turned on here at all (not denied, not blocked)?
    pub available: bool,
    pub on: bool,
    pub phase: Phase,
    pub reason: Option<Reason>,
    pub paused_by: Option<Source>,
    /// Remaining pause at publish time (the viewer counts down from it).
    pub resumes_in: Option<Duration>,
    pub settings: Settings,
    pub set_by: Option<String>,
    pub set_at_ms: Option<u64>,
    pub detector: &'static str,
    pub warn: Vec<&'static str>,
}

struct Glide {
    from: (f64, f64),
    to: (f64, f64),
    done: f64,
    len: f64,
}

struct Run {
    path: Path,
    placement: Placement,
    shape: Pattern,
    /// The safe box the run was placed in (the next loop reuses it).
    safe: Rect,
    /// Arc position since this loop started (unwrapped).
    s: f64,
    loop_start: f64,
    started: Instant,
    last_step: Instant,
    glide: Option<Glide>,
    rest_until: Option<Instant>,
    /// `subtle`: the next nudge, and whether the pointer is out by 1 px.
    subtle_next: Option<Instant>,
    subtle_out: Option<(i32, i32)>,
}

pub struct Engine {
    activation: Option<Activation>,
    device_enabled: bool,
    org_denied: bool,
    phase: Phase,
    reason: Option<Reason>,
    paused_by: Option<Source>,
    last_human: Option<Instant>,
    /// Paused for a contended cursor: not before this.
    hold_until: Option<Instant>,
    seen_remote: u64,
    /// Marker last seen while paused (continued activity extends the pause).
    last_marker: Option<IdleMarker>,
    /// Marker right after the engine's own last move.
    baseline: Option<IdleMarker>,
    /// Where the engine last put the cursor.
    expected: Option<(i32, i32)>,
    run: Option<Run>,
    contended_strikes: u32,
    calibration_strikes: u32,
    not_landing_strikes: u32,
    next_wake: Option<Instant>,
    loop_n: u64,
    seed: u64,
    rev: u64,
    last_publish: Option<Instant>,
    /// When the engine last moved the pointer ([`MIN_MOVE_GAP`]).
    last_move_at: Option<Instant>,
    warn: Vec<&'static str>,
    detector: &'static str,
}

impl Engine {
    pub fn new(seed: u64) -> Engine {
        Engine {
            activation: None,
            device_enabled: true,
            org_denied: false,
            phase: Phase::Off,
            reason: None,
            paused_by: None,
            last_human: None,
            hold_until: None,
            seen_remote: 0,
            last_marker: None,
            baseline: None,
            expected: None,
            run: None,
            contended_strikes: 0,
            calibration_strikes: 0,
            not_landing_strikes: 0,
            next_wake: None,
            loop_n: 0,
            seed,
            rev: 1,
            last_publish: None,
            last_move_at: None,
            warn: Vec::new(),
            detector: "clock+cursor",
        }
    }

    /// When the engine next wants a tick. `None` = only a command wakes it.
    pub fn next_wake(&self) -> Option<Instant> {
        self.next_wake
    }

    pub fn rev(&self) -> u64 {
        self.rev
    }

    pub fn activation(&self) -> Option<&Activation> {
        self.activation.as_ref()
    }

    pub fn is_on(&self) -> bool {
        self.activation.is_some()
    }

    /// Host-reported warnings (`focus_follows_mouse`, …).
    pub fn set_warnings(&mut self, warn: Vec<&'static str>) {
        if self.warn != warn {
            self.warn = warn;
            self.bump();
        }
    }

    pub fn snapshot(&self, now: Instant) -> Snapshot {
        let resumes_in = match (self.phase, self.last_human, self.activation.as_ref()) {
            (Phase::Paused, _, Some(_)) if self.hold_until.is_some() => {
                self.hold_until.map(|t| t.saturating_duration_since(now))
            }
            (Phase::Paused, Some(h), Some(a)) if self.reason == Some(Reason::UserActive) => {
                Some((h + a.settings.resume_after).saturating_duration_since(now))
            }
            _ => None,
        };
        let blocked = !self.device_enabled
            || self.org_denied
            || (self.phase == Phase::Unavailable && self.reason.is_some_and(Reason::is_blocking));
        Snapshot {
            rev: self.rev,
            available: !blocked,
            on: self.activation.is_some(),
            phase: self.phase,
            reason: self.reason,
            paused_by: self.paused_by,
            resumes_in,
            settings: self
                .activation
                .as_ref()
                .map(|a| a.settings.clone())
                .unwrap_or_default(),
            set_by: self.activation.as_ref().map(|a| a.set_by.clone()),
            set_at_ms: self.activation.as_ref().map(|a| a.set_at_ms),
            detector: self.detector,
            warn: self.warn.clone(),
        }
    }

    fn bump(&mut self) {
        self.rev = self.rev.wrapping_add(1);
    }

    /// Force a publish without a state change — a refused request must
    /// still reach the viewer that asked.
    pub fn touch(&mut self) {
        self.bump();
    }

    /// Change phase/reason/source; bumps `rev` only on a public change.
    fn set_phase(
        &mut self,
        phase: Phase,
        reason: Option<Reason>,
        by: Option<Source>,
        now: Instant,
    ) {
        if self.phase != phase || self.reason != reason || self.paused_by != by {
            self.phase = phase;
            self.reason = reason;
            self.paused_by = by;
            self.bump();
            self.last_publish = Some(now);
        }
    }

    // ─── commands ────────────────────────────────────────────────────────

    /// Turn on (or change the settings of a running engine). Refused while
    /// the device or the org says no.
    pub fn set_on(
        &mut self,
        settings: Settings,
        set_by: String,
        wall_ms: u64,
        now: Instant,
    ) -> Result<(), Reason> {
        if !self.device_enabled {
            return Err(Reason::DeviceDisabled);
        }
        if self.org_denied {
            return Err(Reason::OrgDenied);
        }
        let settings = Settings {
            resume_after: settings
                .resume_after
                .clamp(RESUME_AFTER_MIN, RESUME_AFTER_MAX),
            ..settings
        };
        self.activation = Some(Activation {
            settings,
            set_by,
            set_at_ms: wall_ms,
        });
        self.reset_run();
        self.contended_strikes = 0;
        self.hold_until = None;
        self.set_phase(Phase::Calibrating, None, None, now);
        // A settings change while already calibrating would not change the
        // phase; the activation itself is public, so publish regardless.
        self.bump();
        self.next_wake = Some(now);
        Ok(())
    }

    /// Restore a persisted activation at boot. Starts held until a session
    /// is confirmed: no cursor read or move happens before that — the first
    /// call into the arbiter creates and CACHES the OS injector, and on a
    /// host with no display yet that would be a Noop for the life of the
    /// process, breaking remote control too.
    pub fn restore(&mut self, activation: Activation, now: Instant) {
        if !self.device_enabled || self.org_denied {
            return;
        }
        self.activation = Some(activation);
        self.reset_run();
        self.set_phase(Phase::Locked, Some(Reason::NoSession), None, now);
        self.bump();
        self.next_wake = Some(now);
    }

    /// A different person signed in (or everyone signed out): their own
    /// stored keep busy — or none — replaces whatever ran. Not a turn-off:
    /// the previous person's preference stays theirs, so no reason is shown.
    pub fn switch_person(&mut self, activation: Option<Activation>, now: Instant) {
        self.activation = None;
        self.reset_run();
        self.hold_until = None;
        self.next_wake = None;
        self.set_phase(Phase::Off, None, None, now);
        self.bump();
        if let Some(a) = activation {
            self.restore(a, now);
        }
    }

    pub fn turn_off(&mut self, why: Reason, now: Instant) {
        let was_on = self.activation.take().is_some();
        self.reset_run();
        self.hold_until = None;
        self.next_wake = None;
        if was_on || self.reason != Some(why) {
            self.set_phase(Phase::Off, Some(why), None, now);
            self.bump();
        }
    }

    /// The device owner's `keep_busy_enabled`. Off stops a running engine.
    pub fn set_device_enabled(&mut self, enabled: bool, now: Instant) {
        if self.device_enabled == enabled {
            return;
        }
        self.device_enabled = enabled;
        if !enabled {
            self.turn_off(Reason::DeviceDisabled, now);
        } else {
            if self.reason == Some(Reason::DeviceDisabled) {
                self.set_phase(Phase::Off, None, None, now);
            }
            self.bump();
        }
    }

    /// The org's deny (strictest-of every enrolled org, computed by the
    /// caller). A deny stops a running engine.
    pub fn set_org_denied(&mut self, denied: bool, now: Instant) {
        if self.org_denied == denied {
            return;
        }
        self.org_denied = denied;
        if denied {
            self.turn_off(Reason::OrgDenied, now);
        } else {
            if self.reason == Some(Reason::OrgDenied) {
                self.set_phase(Phase::Off, None, None, now);
            }
            self.bump();
        }
    }

    fn reset_run(&mut self) {
        self.run = None;
        self.baseline = None;
        self.expected = None;
        self.last_marker = None;
        self.calibration_strikes = 0;
        self.not_landing_strikes = 0;
    }

    // ─── the tick ────────────────────────────────────────────────────────

    pub fn tick(&mut self, host: &mut impl Host) {
        let now = host.now();
        let Some(act) = self.activation.clone() else {
            self.next_wake = None;
            return;
        };
        if let Some(at) = act.settings.auto_off_at_ms
            && host.wall_ms() >= at
        {
            self.turn_off(Reason::Expired, now);
            return;
        }

        match host.session() {
            SessionState::Present => {}
            SessionState::Locked => {
                self.reset_run();
                self.hold_until = None;
                self.set_phase(Phase::Locked, Some(Reason::Locked), None, now);
                self.next_wake = Some(now + TICK_LOCKED);
                return;
            }
            SessionState::Absent => {
                self.reset_run();
                self.hold_until = None;
                self.set_phase(Phase::Locked, Some(Reason::NoSession), None, now);
                self.next_wake = Some(now + TICK_NO_SESSION);
                return;
            }
            SessionState::Unsupported(r) => {
                self.reset_run();
                self.set_phase(Phase::Unavailable, Some(r), None, now);
                self.next_wake = Some(now + TICK_UNAVAILABLE);
                return;
            }
        }

        match self.phase {
            // Coming back from the lock screen or a sign-in: a person just
            // typed a password. They have the floor; wait them out first.
            Phase::Locked | Phase::Off => {
                self.seen_remote = host.remote_epoch();
                self.last_marker = host.idle_marker();
                self.last_human = Some(now);
                self.set_phase(
                    Phase::Paused,
                    Some(Reason::UserActive),
                    Some(Source::Local),
                    now,
                );
                self.next_wake = Some(now + TICK_IDLE);
            }
            Phase::Unavailable => {
                // Retry from the top: a permission may have been granted.
                self.reset_run();
                self.calibrate(host, now, &act);
            }
            Phase::Calibrating => self.calibrate(host, now, &act),
            Phase::Paused => self.paused_tick(host, now, &act),
            Phase::Running => self.running_tick(host, now, &act),
        }
    }

    fn unavailable(&mut self, r: Reason, now: Instant) {
        self.reset_run();
        self.set_phase(Phase::Unavailable, Some(r), None, now);
        self.next_wake = Some(now + TICK_UNAVAILABLE);
    }

    fn host_error(&mut self, e: HostError, now: Instant) {
        match e {
            HostError::Unsupported(r) => self.unavailable(r, now),
            HostError::RemoteButtonHeld => {
                self.pause(Reason::ButtonHeld, Some(Source::Remote), now)
            }
            HostError::Failed(_) => {
                self.not_landing_strikes += 1;
                if self.not_landing_strikes >= NOT_LANDING_LIMIT {
                    self.unavailable(Reason::NotLanding, now);
                } else {
                    self.next_wake = Some(now + TICK_IDLE);
                }
            }
        }
    }

    fn pause(&mut self, why: Reason, by: Option<Source>, now: Instant) {
        self.run = None;
        self.baseline = None;
        self.expected = None;
        self.last_human = Some(now);
        self.set_phase(Phase::Paused, Some(why), by, now);
        self.next_wake = Some(now + TICK_IDLE);
    }

    /// Prove the round trip: the pointer goes where it is sent, and the idle
    /// clock registers the engine's own move. Only then is a divergence or
    /// a clock change evidence of a person.
    fn calibrate(&mut self, host: &mut impl Host, now: Instant, act: &Activation) {
        let cur = match host.cursor() {
            Ok(c) => c,
            Err(e) => return self.host_error(e, now),
        };
        let Some(before) = host.idle_marker() else {
            self.detector = "cursor";
            return self.unavailable(Reason::NoIdleClock, now);
        };
        self.detector = if host.blind() {
            "clock"
        } else {
            "clock+cursor"
        };
        // A short there-and-back, each leg VERIFIED. A move to the same point
        // may not count as input anywhere, and a pointer stuck (or confined)
        // at the anchor would pass a check that only looked at the return —
        // a calibration that cannot fail proves nothing.
        let out = if cur.0 >= CALIBRATION_NUDGE_PX {
            (cur.0 - CALIBRATION_NUDGE_PX, cur.1)
        } else {
            (cur.0 + CALIBRATION_NUDGE_PX, cur.1)
        };
        if let Err(e) = self.move_spaced(host, out) {
            return self.host_error(e, now);
        }
        let mid = host.settle(before);
        let there = match host.cursor() {
            Ok(c) => c,
            Err(e) => return self.host_error(e, now),
        };
        // Spaced from the out leg, so the two land on different clock readings.
        if let Err(e) = self.move_spaced(host, cur) {
            return self.host_error(e, now);
        }
        let after = mid.and_then(|m| host.settle(m));
        // The legs took real time (the spacing, two settles): schedule from
        // after them.
        let now = host.now();
        let back = match host.cursor() {
            Ok(c) => c,
            Err(e) => return self.host_error(e, now),
        };
        let near = |a: (i32, i32), b: (i32, i32)| {
            (a.0 - b.0).abs() <= CURSOR_TOLERANCE_PX && (a.1 - b.1).abs() <= CURSOR_TOLERANCE_PX
        };
        if !near(there, out) || !near(back, cur) {
            self.calibration_strikes += 1;
            if self.calibration_strikes >= CALIBRATION_LIMIT {
                return self.unavailable(Reason::CalibrationFailed, now);
            }
            self.set_phase(Phase::Calibrating, None, None, now);
            self.next_wake = Some(now + TICK_IDLE);
            return;
        }
        let Some(after) = after else {
            self.not_landing_strikes += 1;
            if self.not_landing_strikes >= NOT_LANDING_LIMIT {
                return self.unavailable(Reason::NotLanding, now);
            }
            self.set_phase(Phase::Calibrating, None, None, now);
            self.next_wake = Some(now + TICK_IDLE);
            return;
        };
        let Some(safe) = host.safe_box_at(cur) else {
            return self.unavailable(Reason::Unsupported, now);
        };
        self.calibration_strikes = 0;
        self.not_landing_strikes = 0;
        self.baseline = Some(after);
        self.expected = Some(cur);
        self.seen_remote = host.remote_epoch();
        self.run = Some(self.new_run(act, (cur.0 as f64, cur.1 as f64), safe, now));
        self.set_phase(Phase::Running, None, None, now);
        self.next_wake = Some(now + self.running_cadence(act));
    }

    /// Every move the engine makes, at least [`MIN_MOVE_GAP`] after its
    /// previous one: closer, and the idle clock reads the two as one event.
    fn move_spaced(&mut self, host: &mut impl Host, p: (i32, i32)) -> Result<(), HostError> {
        if let Some(t) = self.last_move_at {
            let since = host.now().saturating_duration_since(t);
            if since < MIN_MOVE_GAP {
                host.wait(MIN_MOVE_GAP - since);
            }
        }
        let r = host.move_to(p);
        self.last_move_at = Some(host.now());
        r
    }

    fn running_cadence(&self, act: &Activation) -> Duration {
        if act.settings.pattern == Pattern::Subtle {
            TICK_IDLE
        } else {
            TICK_RUNNING
        }
    }

    fn new_run(&mut self, act: &Activation, anchor: (f64, f64), safe: Rect, now: Instant) -> Run {
        let shape = act.settings.pattern.shape_for_loop(self.loop_n);
        let path = Path::for_shape(shape, self.loop_n, self.seed);
        let (placement, s0) = patterns::place(&path, anchor, safe, act.settings.size);
        let start = placement.to_screen(path.at(s0));
        let glide_len = ((start.0 - anchor.0).powi(2) + (start.1 - anchor.1).powi(2)).sqrt();
        Run {
            path,
            placement,
            shape,
            safe,
            s: s0,
            loop_start: s0,
            started: now,
            last_step: now,
            glide: (glide_len >= 1.0).then_some(Glide {
                from: anchor,
                to: start,
                done: 0.0,
                len: glide_len,
            }),
            rest_until: None,
            subtle_next: (act.settings.pattern == Pattern::Subtle).then_some(now + SUBTLE_EVERY),
            subtle_out: None,
        }
    }

    /// Any sign of a person since the engine's last move?
    fn detect(
        &mut self,
        host: &mut impl Host,
        now: Instant,
    ) -> Result<Option<(Reason, Option<Source>)>, HostError> {
        let remote = host.remote_epoch();
        if remote != self.seen_remote {
            self.seen_remote = remote;
            return Ok(Some((Reason::UserActive, Some(Source::Remote))));
        }
        // Cursor FIRST, then the clock: a person who moves between the two
        // reads shows up on the clock, never as a contended cursor.
        let cur = host.cursor()?;
        let marker = host.idle_marker();
        let clock_moved = match (marker, self.baseline) {
            (Some(m), Some(b)) => m.differs(&b),
            _ => false,
        };
        if clock_moved {
            return Ok(Some((Reason::UserActive, Some(Source::Local))));
        }
        let diverged = self.expected.is_some_and(|e| {
            (cur.0 - e.0).abs() > CURSOR_TOLERANCE_PX || (cur.1 - e.1).abs() > CURSOR_TOLERANCE_PX
        });
        if diverged {
            let _ = now;
            return Ok(Some((Reason::CursorContended, None)));
        }
        Ok(None)
    }

    fn running_tick(&mut self, host: &mut impl Host, now: Instant, act: &Activation) {
        match self.detect(host, now) {
            Err(e) => return self.host_error(e, now),
            Ok(Some((Reason::CursorContended, _))) => {
                self.contended_strikes += 1;
                let backoff = act
                    .settings
                    .resume_after
                    .saturating_mul(1u32 << self.contended_strikes.min(8))
                    .min(CONTENDED_BACKOFF_MAX);
                self.pause(Reason::CursorContended, None, now);
                self.hold_until = Some(now + backoff);
                self.next_wake = Some(now + TICK_IDLE);
                return;
            }
            Ok(Some((why, by))) => {
                self.pause(why, by, now);
                return;
            }
            Ok(None) => {}
        }
        let Some(target) = self.next_point(now, act) else {
            self.next_wake = Some(now + self.running_cadence(act));
            return;
        };
        if Some(target) == self.expected {
            self.next_wake = Some(now + self.running_cadence(act));
            return;
        }
        let before = self.baseline.unwrap_or(IdleMarker::exact(0));
        if let Err(e) = self.move_spaced(host, target) {
            return self.host_error(e, now);
        }
        self.expected = Some(target);
        match host.settle(before) {
            Some(m) => {
                self.baseline = Some(m);
                self.not_landing_strikes = 0;
            }
            None => {
                self.not_landing_strikes += 1;
                if self.not_landing_strikes >= NOT_LANDING_LIMIT {
                    return self.unavailable(Reason::NotLanding, now);
                }
            }
        }
        self.next_wake = Some(now + self.running_cadence(act));
    }

    /// The next point to move to, or `None` to stay put this tick.
    fn next_point(&mut self, now: Instant, act: &Activation) -> Option<(i32, i32)> {
        let speed = act.settings.speed.px_per_s();
        let loop_n = self.loop_n;
        let run = self.run.as_mut()?;

        if act.settings.pattern == Pattern::Subtle {
            // Out by 1 px, then back on the next tick — every SUBTLE_EVERY.
            if let Some(home) = run.subtle_out.take() {
                return Some(home);
            }
            let next = run.subtle_next?;
            if now < next {
                return None;
            }
            run.subtle_next = Some(now + SUBTLE_EVERY);
            let home = self.expected?;
            let out = if home.0 > 0 {
                (home.0 - 1, home.1)
            } else {
                (home.0 + 1, home.1)
            };
            if let Some(run) = self.run.as_mut() {
                run.subtle_out = Some(home);
            }
            return Some(out);
        }

        if let Some(until) = run.rest_until {
            if now < until {
                return None;
            }
            run.rest_until = None;
            run.last_step = now;
        }
        let dt = now
            .saturating_duration_since(run.last_step)
            .min(MAX_STEP)
            .as_secs_f64();
        run.last_step = now;
        let warm = now.saturating_duration_since(run.started).as_secs_f64() / EASE_IN.as_secs_f64();
        let ease = smoothstep(warm.min(1.0)).max(0.15);
        let advance_px = speed * ease * dt;

        if let Some(g) = run.glide.as_mut() {
            g.done = (g.done + advance_px).min(g.len);
            let f = g.done / g.len;
            let p = (
                g.from.0 + (g.to.0 - g.from.0) * f,
                g.from.1 + (g.to.1 - g.from.1) * f,
            );
            if g.done >= g.len {
                run.glide = None;
            }
            return Some((p.0.round() as i32, p.1.round() as i32));
        }

        let pace = run.path.speed_at(run.s);
        let prev = run.s - run.loop_start;
        run.s += advance_px * pace / run.placement.scale;
        let total = run.path.total();
        let covered = run.s - run.loop_start;
        // A rest (Wander) inside the stretch just covered?
        if let Some(rest) = run.path.rest_between(prev, covered.min(total)) {
            run.rest_until = Some(now + rest);
        }
        let p = run.placement.to_screen(run.path.at(run.s));
        let point = (p.0.round() as i32, p.1.round() as i32);
        if covered < total {
            return Some(point);
        }

        // Loop complete. Shapes that change per loop (Shuffle, Wander's fresh
        // waypoints, Lissajous's drift) start the next loop from HERE, inside
        // the same safe box, so the pointer never jumps.
        let (old_shape, safe, started) = (run.shape, run.safe, run.started);
        run.loop_start += total;
        self.loop_n = loop_n.wrapping_add(1);
        self.contended_strikes = 0;
        let next_shape = act.settings.pattern.shape_for_loop(self.loop_n);
        if next_shape != old_shape || matches!(next_shape, Pattern::Wander | Pattern::Lissajous) {
            let fresh = self.new_run(act, p, safe, now);
            // Keep the warm speed: no second ease-in between loops.
            self.run = Some(Run { started, ..fresh });
        }
        Some(point)
    }
}

fn smoothstep(x: f64) -> f64 {
    let x = x.clamp(0.0, 1.0);
    x * x * (3.0 - 2.0 * x)
}

impl Engine {
    /// While paused: a person who keeps working extends the pause; once they
    /// have been idle `resume_after` (and no button is held), recalibrate and
    /// resume from wherever they left the pointer.
    fn paused_tick(&mut self, host: &mut impl Host, now: Instant, act: &Activation) {
        let remote = host.remote_epoch();
        let mut extended = false;
        if remote != self.seen_remote {
            self.seen_remote = remote;
            self.last_human = Some(now);
            extended = true;
            if self.reason == Some(Reason::UserActive) {
                self.paused_by = Some(Source::Remote);
            }
        }
        let marker = host.idle_marker();
        if let (Some(m), Some(prev)) = (marker, self.last_marker)
            && m.differs(&prev)
        {
            self.last_human = Some(now);
            extended = true;
            // A contended pause that sees a real person becomes theirs.
            if self.reason == Some(Reason::CursorContended) {
                self.hold_until = None;
                self.set_phase(
                    Phase::Paused,
                    Some(Reason::UserActive),
                    Some(Source::Local),
                    now,
                );
            }
        }
        if marker.is_some() {
            self.last_marker = marker;
        }
        if extended
            && self
                .last_publish
                .is_none_or(|t| now.saturating_duration_since(t) >= EXTENSION_REPUBLISH)
        {
            self.bump();
            self.last_publish = Some(now);
        }

        let human_due = self
            .last_human
            .map(|h| h + act.settings.resume_after)
            .unwrap_or(now);
        let due = match self.hold_until {
            Some(h) => h.max(human_due),
            None => human_due,
        };
        if now < due {
            self.next_wake = Some(due.min(now + TICK_IDLE));
            return;
        }
        match host.buttons_held() {
            Ok(true) => {
                self.set_phase(
                    Phase::Paused,
                    Some(Reason::ButtonHeld),
                    Some(Source::Local),
                    now,
                );
                self.next_wake = Some(now + TICK_IDLE);
                return;
            }
            Ok(false) => {}
            // No way to read the buttons here: the calibration's move is a
            // move, never a press, so the worst case is a drag the person
            // started and then left for `resume_after` — rare enough to
            // accept rather than refuse the whole feature.
            Err(_) => {}
        }
        self.hold_until = None;
        self.set_phase(Phase::Calibrating, None, None, now);
        self.calibrate(host, now, act);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the OS puts the pointer for a requested point.
    type Warp = fn((i32, i32)) -> (i32, i32);

    /// A scripted world: a monitor, a cursor, an idle clock, a session.
    struct Fake {
        now: Instant,
        wall: u64,
        session: SessionState,
        marker: u64,
        has_clock: bool,
        cursor: (i32, i32),
        moves: Vec<(i32, i32)>,
        remote: u64,
        buttons: bool,
        clock_registers: bool,
        /// Where the OS actually puts the pointer for a requested point
        /// (`None` = exactly there).
        warp: Option<Warp>,
        move_err: Option<HostError>,
        reads_while_absent: u32,
        /// `Some(ms)`: the idle clock is a TIMESTAMP of this granularity, as
        /// `GetLastInputInfo`'s system-timer tick is, so two events inside
        /// one tick read as one. `None`: a counter every event moves.
        tick_ms: Option<u64>,
        started: Instant,
        /// FR-92 P9 — a host that cannot read the pointer back: `cursor`
        /// answers where the engine last put it (`placed`), or the middle.
        blind: bool,
        placed: Option<(i32, i32)>,
    }

    impl Fake {
        fn new() -> Fake {
            let now = Instant::now();
            Fake {
                now,
                wall: 1_000_000,
                session: SessionState::Present,
                marker: 100,
                has_clock: true,
                cursor: (960, 520),
                moves: Vec::new(),
                remote: 0,
                buttons: false,
                clock_registers: true,
                warp: None,
                move_err: None,
                reads_while_absent: 0,
                tick_ms: None,
                started: now,
                blind: false,
                placed: None,
            }
        }
        fn advance(&mut self, d: Duration) {
            self.now += d;
            self.wall += d.as_millis() as u64;
        }
        /// An input event reaching the idle clock.
        fn register(&mut self) {
            self.marker = match self.tick_ms {
                Some(t) => {
                    let ms = self.now.saturating_duration_since(self.started).as_millis() as u64;
                    1_000 + ms / t * t
                }
                None => self.marker + 1,
            };
        }
        /// A key, a scroll or a click: the clock moves, the pointer doesn't.
        fn human_key(&mut self) {
            self.register();
        }
        fn human_move(&mut self, to: (i32, i32)) {
            self.cursor = to;
            self.register();
        }
        /// An app moving the pointer: no input event at all.
        fn app_warp(&mut self, to: (i32, i32)) {
            self.cursor = to;
        }
        fn controller(&mut self, to: (i32, i32)) {
            self.remote += 1;
            self.cursor = to;
            self.register();
        }
    }

    impl Host for Fake {
        fn now(&self) -> Instant {
            self.now
        }
        fn wall_ms(&self) -> u64 {
            self.wall
        }
        fn session(&mut self) -> SessionState {
            self.session
        }
        fn idle_marker(&mut self) -> Option<IdleMarker> {
            self.has_clock.then_some(IdleMarker::exact(self.marker))
        }
        fn cursor(&mut self) -> Result<(i32, i32), HostError> {
            if self.session != SessionState::Present {
                self.reads_while_absent += 1;
            }
            if self.blind {
                return Ok(self.placed.unwrap_or((640, 400)));
            }
            Ok(self.cursor)
        }
        fn move_to(&mut self, p: (i32, i32)) -> Result<(), HostError> {
            if self.session != SessionState::Present {
                self.reads_while_absent += 1;
            }
            if let Some(e) = self.move_err.clone() {
                return Err(e);
            }
            self.moves.push(p);
            self.placed = Some(p);
            self.cursor = self.warp.map(|w| w(p)).unwrap_or(p);
            if self.clock_registers {
                self.register();
            }
            Ok(())
        }
        fn settle(&mut self, before: IdleMarker) -> Option<IdleMarker> {
            let now = IdleMarker::exact(self.marker);
            now.differs(&before).then_some(now)
        }
        fn buttons_held(&mut self) -> Result<bool, HostError> {
            Ok(self.buttons)
        }
        fn safe_box_at(&mut self, _p: (i32, i32)) -> Option<Rect> {
            patterns::safe_box(
                Rect::new(0.0, 0.0, 1920.0, 1080.0),
                Rect::new(0.0, 0.0, 1920.0, 1040.0),
            )
        }
        fn remote_epoch(&self) -> u64 {
            self.remote
        }
        fn wait(&mut self, d: Duration) {
            self.advance(d);
        }
        fn blind(&self) -> bool {
            self.blind
        }
    }

    fn settings(pattern: Pattern) -> Settings {
        Settings {
            pattern,
            ..Settings::default()
        }
    }

    /// Run ticks for `d`, honouring the engine's own wake times.
    fn run_for(e: &mut Engine, f: &mut Fake, d: Duration) {
        let end = f.now + d;
        while f.now < end {
            e.tick(f);
            let next = e
                .next_wake()
                .unwrap_or(end)
                .max(f.now + Duration::from_millis(1));
            let step = next
                .min(end)
                .saturating_duration_since(f.now)
                .max(Duration::from_millis(1));
            f.advance(step);
        }
    }

    fn on(e: &mut Engine, f: &mut Fake, p: Pattern) {
        e.set_on(settings(p), "Alice".into(), f.wall, f.now)
            .unwrap();
        e.tick(f); // calibrate
    }

    #[test]
    fn turning_on_calibrates_then_runs_and_moves_inside_the_safe_box() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
        let before = f.moves.len();
        run_for(&mut e, &mut f, Duration::from_secs(3));
        assert!(
            f.moves.len() > before + 50,
            "it should be drawing: {} moves",
            f.moves.len()
        );
        let safe = f.safe_box_at((0, 0)).unwrap();
        for m in &f.moves[2..] {
            assert!(
                safe.contains((m.0 as f64, m.1 as f64)),
                "{m:?} outside {safe:?}"
            );
        }
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
    }

    #[test]
    fn calibration_is_a_short_verified_there_and_back() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        assert_eq!(f.moves[0], (960 - CALIBRATION_NUDGE_PX, 520));
        assert_eq!(f.moves[1], (960, 520));
    }

    /// `GetLastInputInfo` advances with the system timer, so two moves inside
    /// one ~15.6 ms tick read as ONE event. The calibration's back leg used to
    /// follow the out leg by milliseconds, never registered, and the host read
    /// as `not_landing` — most enables on a real Windows box. Every own move
    /// is now spaced by `MIN_MOVE_GAP`, a recalibration's first move included.
    /// A "time since" reading is an interval: the clock answered somewhere
    /// between asking and hearing back. The same last input read again —
    /// even across a slow answer — overlaps; a newer input does not.
    #[test]
    fn a_time_since_reading_is_an_interval_that_latency_only_widens() {
        let m = IdleMarker::within(1_000, 1_400, 0, 0);
        assert_eq!((m.value, m.tolerance), (1_200, 200));
        // The same input (at ~1000–1400), read later and promptly.
        let again = IdleMarker::within(5_000, 5_010, 3_800, 0);
        assert!(!again.differs(&m), "{again:?} vs {m:?}");
        // The same input, read later and SLOWLY: wider, still the same.
        let slow = IdleMarker::within(5_000, 9_000, 3_800, 0);
        assert!(!slow.differs(&m), "{slow:?} vs {m:?}");
        // A newer input.
        let newer = IdleMarker::within(5_000, 5_010, 2_000, 0);
        assert!(newer.differs(&m));
        // The grain widens both sides.
        assert_eq!(IdleMarker::within(1_000, 1_000, 0, 7).tolerance, 7);
    }

    #[test]
    fn calibration_and_running_survive_a_coarse_idle_clock() {
        let mut f = Fake::new();
        f.tick_ms = Some(16);
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        let s = e.snapshot(f.now);
        assert_eq!((s.phase, s.reason), (Phase::Running, None));
        run_for(&mut e, &mut f, Duration::from_secs(2));
        let s = e.snapshot(f.now);
        assert_eq!((s.phase, s.reason), (Phase::Running, None));

        // A new pattern while running recalibrates at once.
        e.set_on(settings(Pattern::Star), "Alice".into(), f.wall, f.now)
            .unwrap();
        e.tick(&mut f);
        let s = e.snapshot(f.now);
        assert_eq!((s.phase, s.reason), (Phase::Running, None));
    }

    /// A pointer stuck at one spot round-trips "home → home" perfectly once
    /// that spot is the anchor. Only checking the out-leg catches it.
    #[test]
    fn a_pointer_stuck_at_the_anchor_fails_calibration() {
        let mut f = Fake::new();
        f.cursor = (5, 5);
        f.warp = Some(|_| (5, 5));
        let mut e = Engine::new(1);
        e.set_on(settings(Pattern::Circle), "A".into(), f.wall, f.now)
            .unwrap();
        run_for(&mut e, &mut f, Duration::from_secs(2));
        let s = e.snapshot(f.now);
        assert_eq!(
            (s.phase, s.reason),
            (Phase::Unavailable, Some(Reason::CalibrationFailed))
        );
    }

    #[test]
    fn a_key_pauses_it_within_one_tick_and_it_resumes_after_resume_after() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Triangle);
        run_for(&mut e, &mut f, Duration::from_secs(1));
        f.human_key();
        e.tick(&mut f);
        let s = e.snapshot(f.now);
        assert_eq!(s.phase, Phase::Paused);
        assert_eq!(s.reason, Some(Reason::UserActive));
        assert_eq!(s.paused_by, Some(Source::Local));
        let frozen = f.moves.len();
        run_for(&mut e, &mut f, Duration::from_secs(29));
        assert_eq!(
            f.moves.len(),
            frozen,
            "no move while a person has the floor"
        );
        run_for(&mut e, &mut f, Duration::from_secs(2));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
        assert!(f.moves.len() > frozen);
    }

    #[test]
    fn continued_activity_extends_the_pause() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        run_for(&mut e, &mut f, Duration::from_millis(500));
        f.human_key();
        e.tick(&mut f);
        // Keep typing every 10 s for a minute.
        for _ in 0..6 {
            run_for(&mut e, &mut f, Duration::from_secs(10));
            f.human_key();
        }
        assert_eq!(e.snapshot(f.now).phase, Phase::Paused);
        run_for(&mut e, &mut f, Duration::from_secs(25));
        assert_eq!(
            e.snapshot(f.now).phase,
            Phase::Paused,
            "25 s after the last key is not 30"
        );
        run_for(&mut e, &mut f, Duration::from_secs(6));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
    }

    #[test]
    fn a_moved_mouse_pauses_it_and_it_resumes_where_the_person_left_the_pointer() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        run_for(&mut e, &mut f, Duration::from_secs(1));
        f.human_move((300, 300));
        e.tick(&mut f);
        assert_eq!(e.snapshot(f.now).reason, Some(Reason::UserActive));
        let n = f.moves.len();
        run_for(&mut e, &mut f, Duration::from_secs(31));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
        // The first move after resuming is the calibration nudge AT the
        // person's pointer, then the drawing starts from there: no jump.
        assert_eq!(f.moves[n], (300 - CALIBRATION_NUDGE_PX, 300));
        assert_eq!(f.moves[n + 1], (300, 300));
        let first_draw = f.moves[n + 2];
        assert!(
            (first_draw.0 - 300).abs() <= 3 && (first_draw.1 - 300).abs() <= 3,
            "resumed with a jump to {first_draw:?}"
        );
    }

    /// FR-92 P9 — a host that cannot read the pointer back (Wayland through
    /// uinput). Calibration rests on the clock alone and says so; something
    /// moving the pointer WITHOUT input is invisible to it (no "contended");
    /// a person is seen by the clock; and a resume starts where keep busy
    /// STOPPED — the jump the docs promise — never where the person left it.
    #[test]
    fn a_blind_host_runs_on_the_clock_alone_and_resumes_where_it_stopped() {
        let mut f = Fake::new();
        f.blind = true;
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        let s = e.snapshot(f.now);
        assert_eq!(s.phase, Phase::Running);
        assert_eq!(s.detector, "clock");
        // Calibrated around the host's starting point, not the real pointer.
        assert_eq!(f.moves[0], (640 - CALIBRATION_NUDGE_PX, 400));
        assert_eq!(f.moves[1], (640, 400));
        run_for(&mut e, &mut f, Duration::from_secs(1));
        f.app_warp((10, 10));
        run_for(&mut e, &mut f, Duration::from_millis(300));
        assert_eq!(
            e.snapshot(f.now).phase,
            Phase::Running,
            "no input, no person"
        );
        f.human_move((1500, 900));
        e.tick(&mut f);
        let s = e.snapshot(f.now);
        assert_eq!(s.reason, Some(Reason::UserActive));
        assert_eq!(s.paused_by, Some(Source::Local));
        let stopped = *f.moves.last().unwrap();
        let n = f.moves.len();
        run_for(&mut e, &mut f, Duration::from_secs(31));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
        let resumed = f.moves[n];
        let near = |a: (i32, i32), b: (i32, i32)| (a.0 - b.0).abs() <= 4 && (a.1 - b.1).abs() <= 4;
        assert!(
            near(resumed, stopped),
            "resumed at {resumed:?}, stopped at {stopped:?}"
        );
        assert!(
            !near(resumed, (1500, 900)),
            "it cannot know where the person left it"
        );
    }

    #[test]
    fn controller_input_pauses_it_as_remote() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        run_for(&mut e, &mut f, Duration::from_millis(500));
        f.controller((800, 400));
        e.tick(&mut f);
        let s = e.snapshot(f.now);
        assert_eq!(s.reason, Some(Reason::UserActive));
        assert_eq!(s.paused_by, Some(Source::Remote));
    }

    #[test]
    fn an_app_warping_the_cursor_is_contended_not_a_person_and_backs_off() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        run_for(&mut e, &mut f, Duration::from_millis(500));
        f.app_warp((10, 10));
        e.tick(&mut f);
        let s = e.snapshot(f.now);
        assert_eq!(s.reason, Some(Reason::CursorContended));
        assert_eq!(s.paused_by, None);
        // The back-off is LONGER than resume_after (2× on the first strike).
        run_for(&mut e, &mut f, Duration::from_secs(35));
        assert_eq!(e.snapshot(f.now).phase, Phase::Paused);
        run_for(&mut e, &mut f, Duration::from_secs(30));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
    }

    #[test]
    fn a_held_button_blocks_the_resume_until_released() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        f.human_key();
        e.tick(&mut f);
        f.buttons = true;
        run_for(&mut e, &mut f, Duration::from_secs(60));
        let s = e.snapshot(f.now);
        assert_eq!(s.phase, Phase::Paused);
        assert_eq!(s.reason, Some(Reason::ButtonHeld));
        f.buttons = false;
        run_for(&mut e, &mut f, Duration::from_secs(1));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
    }

    #[test]
    fn a_move_refused_for_a_remote_drag_pauses_without_moving() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        f.move_err = Some(HostError::RemoteButtonHeld);
        f.advance(TICK_RUNNING);
        e.tick(&mut f);
        let s = e.snapshot(f.now);
        assert_eq!(s.reason, Some(Reason::ButtonHeld));
        assert_eq!(s.paused_by, Some(Source::Remote));
    }

    #[test]
    fn locked_holds_it_and_the_unlock_counts_as_a_person() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        f.session = SessionState::Locked;
        f.advance(TICK_RUNNING);
        e.tick(&mut f);
        assert_eq!(e.snapshot(f.now).phase, Phase::Locked);
        let n = f.moves.len();
        run_for(&mut e, &mut f, Duration::from_secs(120));
        assert_eq!(f.moves.len(), n, "never moves on the lock screen");
        f.session = SessionState::Present;
        e.tick(&mut f);
        let s = e.snapshot(f.now);
        assert_eq!(
            (s.phase, s.reason),
            (Phase::Paused, Some(Reason::UserActive))
        );
        run_for(&mut e, &mut f, Duration::from_secs(31));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
    }

    /// The boot-time restore must not touch the injector until a session is
    /// confirmed: the arbiter caches the first injector it creates, and a
    /// Noop cached before a display exists breaks remote control as well.
    #[test]
    fn a_restore_with_no_session_never_reads_or_moves_the_cursor() {
        let mut f = Fake::new();
        f.session = SessionState::Absent;
        let mut e = Engine::new(1);
        e.restore(
            Activation {
                settings: settings(Pattern::Star),
                set_by: "Alice".into(),
                set_at_ms: 1,
            },
            f.now,
        );
        run_for(&mut e, &mut f, Duration::from_secs(60));
        assert_eq!(f.reads_while_absent, 0);
        assert!(f.moves.is_empty());
        let s = e.snapshot(f.now);
        assert_eq!(
            (s.phase, s.reason),
            (Phase::Locked, Some(Reason::NoSession))
        );
        assert!(s.on);
        // Someone signs in: they get the floor first.
        f.session = SessionState::Present;
        e.tick(&mut f);
        assert_eq!(e.snapshot(f.now).reason, Some(Reason::UserActive));
        run_for(&mut e, &mut f, Duration::from_secs(31));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
    }

    /// A different person signs in: whatever ran stops with NO reason shown
    /// (it was not turned off — it was someone else's), and their own stored
    /// keep busy, if any, starts the way a boot restore does.
    #[test]
    fn a_new_person_gets_their_own_keep_busy_and_never_the_last_ones() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Heart);
        run_for(&mut e, &mut f, Duration::from_secs(1));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);

        e.switch_person(None, f.now);
        let s = e.snapshot(f.now);
        assert_eq!((s.on, s.phase, s.reason), (false, Phase::Off, None));
        let frozen = f.moves.len();
        run_for(&mut e, &mut f, Duration::from_secs(5));
        assert_eq!(f.moves.len(), frozen, "not one more move");

        let theirs = Activation {
            settings: settings(Pattern::Wave),
            set_by: "Bob".into(),
            set_at_ms: 9,
        };
        e.switch_person(Some(theirs), f.now);
        let s = e.snapshot(f.now);
        assert!(s.on);
        assert_eq!(s.set_by.as_deref(), Some("Bob"));
        assert_eq!(s.settings.pattern, Pattern::Wave);
        // As at boot: they have the floor first, then it runs.
        e.tick(&mut f);
        assert_eq!(e.snapshot(f.now).reason, Some(Reason::UserActive));
        run_for(&mut e, &mut f, Duration::from_secs(31));
        assert_eq!(e.snapshot(f.now).phase, Phase::Running);
    }

    #[test]
    fn a_pointer_that_does_not_go_where_sent_fails_calibration() {
        let mut f = Fake::new();
        f.warp = Some(|_| (5, 5));
        let mut e = Engine::new(1);
        e.set_on(settings(Pattern::Circle), "A".into(), f.wall, f.now)
            .unwrap();
        run_for(&mut e, &mut f, Duration::from_secs(2));
        let s = e.snapshot(f.now);
        assert_eq!(
            (s.phase, s.reason),
            (Phase::Unavailable, Some(Reason::CalibrationFailed))
        );
    }

    #[test]
    fn moves_the_idle_clock_never_registers_are_not_landing() {
        let mut f = Fake::new();
        f.clock_registers = false;
        let mut e = Engine::new(1);
        e.set_on(settings(Pattern::Circle), "A".into(), f.wall, f.now)
            .unwrap();
        run_for(&mut e, &mut f, Duration::from_secs(2));
        let s = e.snapshot(f.now);
        assert_eq!(
            (s.phase, s.reason),
            (Phase::Unavailable, Some(Reason::NotLanding))
        );
        assert!(s.available, "not landing is not a property of the host");
    }

    #[test]
    fn no_idle_clock_is_unavailable_and_blocking() {
        let mut f = Fake::new();
        f.has_clock = false;
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        let s = e.snapshot(f.now);
        assert_eq!(
            (s.phase, s.reason),
            (Phase::Unavailable, Some(Reason::NoIdleClock))
        );
        assert!(!s.available);
        assert!(
            f.moves.is_empty(),
            "refuses before moving, never runs keyboard-blind"
        );
    }

    #[test]
    fn device_disable_stops_it_and_refuses_a_new_enable() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        e.set_device_enabled(false, f.now);
        let s = e.snapshot(f.now);
        assert!(!s.on && !s.available);
        assert_eq!(s.reason, Some(Reason::DeviceDisabled));
        assert_eq!(
            e.set_on(settings(Pattern::Circle), "A".into(), f.wall, f.now),
            Err(Reason::DeviceDisabled)
        );
        e.set_device_enabled(true, f.now);
        let s = e.snapshot(f.now);
        assert!(
            s.available && !s.on,
            "re-enabling allows it; it does not turn it back on"
        );
    }

    #[test]
    fn org_deny_stops_it_and_refuses_a_new_enable() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        e.set_org_denied(true, f.now);
        let s = e.snapshot(f.now);
        assert!(!s.on && !s.available);
        assert_eq!(s.reason, Some(Reason::OrgDenied));
        assert_eq!(
            e.set_on(settings(Pattern::Circle), "A".into(), f.wall, f.now),
            Err(Reason::OrgDenied)
        );
        e.set_org_denied(false, f.now);
        assert!(e.snapshot(f.now).available);
    }

    #[test]
    fn auto_off_turns_it_off_at_the_wall_clock_deadline() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        let mut s = settings(Pattern::Circle);
        s.auto_off_at_ms = Some(f.wall + 10_000);
        e.set_on(s, "A".into(), f.wall, f.now).unwrap();
        run_for(&mut e, &mut f, Duration::from_secs(9));
        assert!(e.is_on());
        run_for(&mut e, &mut f, Duration::from_secs(2));
        let snap = e.snapshot(f.now);
        assert!(!snap.on);
        assert_eq!(snap.reason, Some(Reason::Expired));
    }

    #[test]
    fn subtle_only_nudges_one_pixel_and_back() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Subtle);
        let start = f.cursor;
        f.moves.clear();
        run_for(&mut e, &mut f, Duration::from_secs(100));
        // Two nudges (at 45 s and 90 s), each out and back.
        assert_eq!(f.moves.len(), 4, "{:?}", f.moves);
        for m in &f.moves {
            assert!((m.0 - start.0).abs() <= 1 && m.1 == start.1);
        }
        assert_eq!(f.cursor, start);
    }

    #[test]
    fn rev_bumps_on_public_changes_not_on_every_tick() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        on(&mut e, &mut f, Pattern::Circle);
        let r = e.rev();
        run_for(&mut e, &mut f, Duration::from_secs(5));
        assert_eq!(e.rev(), r, "drawing is not news");
        f.human_key();
        e.tick(&mut f);
        assert!(e.rev() > r);
    }

    #[test]
    fn resume_after_is_clamped() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        let mut s = settings(Pattern::Circle);
        s.resume_after = Duration::from_millis(1);
        e.set_on(s, "A".into(), f.wall, f.now).unwrap();
        assert_eq!(e.snapshot(f.now).settings.resume_after, RESUME_AFTER_MIN);
        let mut s = settings(Pattern::Circle);
        s.resume_after = Duration::from_secs(99_999);
        e.set_on(s, "A".into(), f.wall, f.now).unwrap();
        assert_eq!(e.snapshot(f.now).settings.resume_after, RESUME_AFTER_MAX);
        let _ = &mut f;
    }

    #[test]
    fn shuffle_changes_shape_between_loops_without_jumping() {
        let mut f = Fake::new();
        let mut e = Engine::new(1);
        let mut s = settings(Pattern::Shuffle);
        s.speed = Speed::Fast;
        e.set_on(s, "A".into(), f.wall, f.now).unwrap();
        e.tick(&mut f);
        run_for(&mut e, &mut f, Duration::from_secs(40));
        assert!(e.loop_n >= 2, "several loops in 40 s at fast: {}", e.loop_n);
        // No two consecutive moves are far apart: no jumps between loops.
        for w in f.moves.windows(2) {
            let d = (((w[1].0 - w[0].0).pow(2) + (w[1].1 - w[0].1).pow(2)) as f64).sqrt();
            assert!(
                d < 40.0,
                "a jump of {d} px between {:?} and {:?}",
                w[0],
                w[1]
            );
        }
    }
}
