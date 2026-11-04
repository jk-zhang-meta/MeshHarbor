// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-108 — is someone using this screen?
//!
//! Display match may switch the host's display only where nobody is using it.
//! "Nobody" means what FR-99's `lock_on_end` means by it: no local input for
//! [`crate::lock_on_end::UNATTENDED_AFTER`]. It is read FR-92's way, with no
//! hook, no raw input and no key polling: the session's idle clock
//! (`GetLastInputInfo`). That clock moves for every input, the person's and the
//! machine's alike (FR-108 P0 measured both), so this module follows it and
//! keeps the last move that the machine does not explain:
//!
//! - the controller's injections (`keep_busy::note_remote_input`, noted by the
//!   input arbiter for every injected event);
//! - keep busy's own pointer moves (`keep_busy::note_own_move`).
//!
//! What it answers ([`Presence`]):
//! - **Locked:** the secure desktop is up. The worker cannot switch it anyway
//!   (P0: `ChangeDisplaySettingsExW` returned `-1` there).
//! - **Attended:** unlocked, and a person touched the input within the window.
//! - **Idle:** unlocked, and nobody has, for at least that long. Idle time is
//!   NOT proof of an empty chair (rcfix 2026-11-04: a person reading at their
//!   Surface for five minutes had the panel switched to 800x600 under them), so
//!   display match never switches a physical display on it.
//! - **Unattended:** a POSITIVE "nobody is here": the screen was locked (held
//!   for [`LOCK_HELD_MS`], so a one-reading blip such as a UAC prompt on the
//!   secure desktop is no lock) after the person's last input, and no person
//!   has touched it since.
//!
//! Before the first reading nothing is known, and an unknown is never read as
//! "nobody": the first reading counts its last input as a person's.
//!
//! **Linux, an X11 session (FR-97 P3e-2).** The same tracker, fed by the X
//! server's idle clock (MIT-SCREEN-SAVER `ms_since_user_input`, which XTest
//! input resets as `GetLastInputInfo` counts injected input) and logind's
//! `LockedHint`, as the session's lock-hint emitter (FR-97 P3b) reads it every
//! two seconds: each read is a `loginctl` run, which a sampler twice a second
//! for the daemon's life would pay forever. The X server reports how long ago,
//! not when, so a reading is turned into a tick on [`os_tick`]'s clock and held
//! steady across the read's own jitter ([`steady`]). It samples only where
//! display match can switch a real X11 display (`display_match::x11_offered`);
//! everywhere else the answer stays `Attended`, as before.

#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", feature = "enigo-input")
))]
use std::sync::Mutex;
use std::time::Duration;

/// A move of the idle clock within this of a machine input's tick is that
/// input. Both are the same `GetTickCount` clock; the slack covers the system
/// timer (10–16 ms) and the time between the injector noting an input and the
/// OS recording it.
pub const MACHINE_SLACK_MS: u32 = 250;

/// How often the sampler reads the idle clock.
pub const SAMPLE_EVERY: Duration = Duration::from_millis(500);

/// FR-97 P3e-2 — Linux: two readings of the X idle clock within this of each
/// other name the same input. "Now minus the idle time" moves by the read's
/// own latency from one reading to the next, and the tracker would take every
/// such move for a new input, a person's.
pub const STEADY_MS: u32 = 50;

/// rcfix 2026-11-04 — a lock grounds "away" only once the sampler has seen it
/// held this long: several consecutive readings, never one. A lock that comes
/// and goes inside it (the probe reads any secure desktop, a UAC prompt too, as
/// locked) is flapping, and flapping is not an empty chair.
pub const LOCK_HELD_MS: u32 = 1_500;

/// Who is at the screen, as display match needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The secure desktop is up: locked, or the logon screen.
    Locked,
    /// A person touched the input within the window, or nothing is known.
    Attended,
    /// Nobody has touched the input for at least the window. Idle time alone:
    /// someone may be reading at the screen, so this never allows a switch.
    Idle,
    /// A positive signal that nobody is at the screen: a held lock after the
    /// person's last input, with no person's input since.
    Unattended,
}

/// The decision. `person_ms_ago` is `None` when no person's input is known,
/// which only happens where the idle clock cannot be read; that is never
/// taken for an empty chair. `away_since_lock` (P1b): the screen locked after
/// the person's last input and they have not touched it since, so whoever
/// unlocked it was the machine (the controller typing the password through
/// the session). A person who locked their screen and walked away a minute ago
/// is not at it, whatever the window says.
pub fn decide(
    locked: bool,
    person_ms_ago: Option<u64>,
    away_since_lock: bool,
    window: Duration,
) -> Presence {
    if locked {
        return Presence::Locked;
    }
    if away_since_lock {
        return Presence::Unattended;
    }
    match person_ms_ago {
        Some(ago) if ago >= window.as_millis() as u64 => Presence::Idle,
        _ => Presence::Attended,
    }
}

/// `a - b` on the wrapping 32-bit tick clock, signed.
fn tick_delta(a: u32, b: u32) -> i64 {
    i64::from(a.wrapping_sub(b) as i32)
}

/// Follows the idle clock and keeps the last move that was a person's, and
/// when the screen last locked.
#[derive(Debug, Default)]
pub struct Tracker {
    last_input: Option<u32>,
    last_person: Option<u32>,
    /// P1b — the tick of the reading that first saw the screen locked (after
    /// an unlocked one, or as the very first reading), recorded once that lock
    /// has been seen held for [`LOCK_HELD_MS`].
    last_lock: Option<u32>,
    /// The first reading of the lock run in progress, if the screen reads
    /// locked now.
    lock_run: Option<u32>,
}

impl Tracker {
    /// One reading of the idle clock (`input`), with the ticks of the latest
    /// machine inputs (the controller's injection, keep busy's move). The first
    /// reading is a person's whatever it is: nothing proves otherwise.
    pub fn observe(&mut self, input: u32, machine: &[Option<u32>]) {
        let first = self.last_input.is_none();
        if self.last_input == Some(input) {
            return;
        }
        self.last_input = Some(input);
        let explained = machine
            .iter()
            .flatten()
            .any(|&m| tick_delta(input, m).abs() <= i64::from(MACHINE_SLACK_MS));
        if first || !explained {
            self.last_person = Some(input);
        }
    }

    /// How long ago the last person's input was, at `now`.
    pub fn person_ms_ago(&self, now: u32) -> Option<u64> {
        self.last_person.map(|p| tick_delta(now, p).max(0) as u64)
    }

    /// P1b — one reading of the lock state, at `now`.
    pub fn observe_lock(&mut self, locked: bool, now: u32) {
        if !locked {
            self.lock_run = None;
            return;
        }
        let start = *self.lock_run.get_or_insert(now);
        if tick_delta(now, start) >= i64::from(LOCK_HELD_MS) {
            self.last_lock = Some(start);
        }
    }

    /// P1b — the screen locked after the person's last input: they left, and
    /// whoever unlocked it since did so as the machine. An input at the very
    /// tick of the lock reading counts as before it (the press that locked).
    /// With no person's input known this is false: never an empty chair.
    pub fn away_since_lock(&self) -> bool {
        matches!((self.last_lock, self.last_person), (Some(l), Some(p)) if tick_delta(p, l) <= 0)
    }
}

#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", feature = "enigo-input")
))]
static TRACKER: Mutex<Tracker> = Mutex::new(Tracker {
    last_input: None,
    last_person: None,
    last_lock: None,
    lock_run: None,
});

/// The OS input clock: Windows' `GetTickCount`, the clock `GetLastInputInfo`
/// reports in. Linux (FR-97 P3e-2): this process's monotonic clock in
/// milliseconds, plus one so a tick is never the `0` keep busy reads as "none
/// yet"; the X idle clock is turned into ticks of it. Elsewhere `0`, which
/// nothing here reads.
pub fn os_tick() -> u32 {
    #[cfg(target_os = "windows")]
    {
        // SAFETY: no arguments, no failure mode.
        unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount() }
    }
    #[cfg(target_os = "linux")]
    {
        static BASE: std::sync::LazyLock<std::time::Instant> =
            std::sync::LazyLock::new(std::time::Instant::now);
        (BASE.elapsed().as_millis() as u32).wrapping_add(1)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        0
    }
}

/// FR-97 P3e-2 — Linux: a reading of the X idle clock, as the tick of the last
/// input, held at `prev` while it stays within [`STEADY_MS`] of it. Pure.
pub fn steady(prev: Option<u32>, estimate: u32) -> u32 {
    match prev {
        Some(p) if tick_delta(estimate, p).abs() <= i64::from(STEADY_MS) => p,
        _ => estimate,
    }
}

/// FR-97 P3e-2 — Linux: the X11 session's idle clock, on a connection of its
/// own. `None` until a display answers; tried again at most every
/// [`x11_idle::RETRY`].
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
mod x11_idle {
    use std::time::{Duration, Instant};

    use x11rb::connection::Connection as _;
    use x11rb::protocol::screensaver::ConnectionExt as _;
    use x11rb::rust_connection::RustConnection;

    pub const RETRY: Duration = Duration::from_secs(30);

    pub struct Idle {
        conn: RustConnection,
        root: u32,
        last: Option<u32>,
    }

    pub static IDLE: std::sync::Mutex<(Option<Idle>, Option<Instant>)> =
        std::sync::Mutex::new((None, None));

    impl Idle {
        fn open() -> Option<Self> {
            let (conn, screen) = x11rb::connect(None)
                .map_err(|e| tracing::info!(%e, "presence: no X connection for the idle clock"))
                .ok()?;
            let root = conn.setup().roots.get(screen)?.root;
            Some(Self {
                conn,
                root,
                last: None,
            })
        }

        fn read(&mut self, now: u32) -> Option<u32> {
            let idle = self
                .conn
                .screensaver_query_info(self.root)
                .ok()?
                .reply()
                .ok()?
                .ms_since_user_input;
            let tick = super::steady(self.last, now.wrapping_sub(idle));
            self.last = Some(tick);
            Some(tick)
        }
    }

    /// The tick of the last input, or `None` when no display answers. A
    /// connection that fails a read is dropped and opened again later.
    pub fn last_input_tick(now: u32) -> Option<u32> {
        let mut slot = IDLE.lock().unwrap_or_else(|p| p.into_inner());
        let (idle, tried) = &mut *slot;
        if idle.is_none() && tried.is_none_or(|t| t.elapsed() >= RETRY) {
            *tried = Some(Instant::now());
            *idle = Idle::open();
        }
        let tick = idle.as_mut()?.read(now);
        if tick.is_none() {
            *idle = None;
        }
        tick
    }
}

#[cfg(target_os = "windows")]
fn last_input_tick() -> Option<u32> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: a stack LASTINPUTINFO with cbSize set, as the API requires.
    (unsafe { GetLastInputInfo(&mut lii) } != 0).then_some(lii.dwTime)
}

/// One reading into the tracker: the idle clock and the lock state. Returns
/// whether the screen is locked now, so a caller decides on one reading.
#[cfg(target_os = "windows")]
fn sample() -> bool {
    let locked = crate::lock_state::probe_lock_state() == crate::lock_state::LockState::Locked;
    let machine = [
        crate::keep_busy::last_remote_input_tick(),
        crate::keep_busy::last_own_move_tick(),
    ];
    let mut t = TRACKER.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(input) = last_input_tick() {
        t.observe(input, &machine);
    }
    // rcfix 2026-11-04 — "away" needs a positive lock: the input desktop being
    // a secure one (which a UAC prompt is too) AND the console session itself
    // reporting locked to WTS. An unknown WTS answer is no lock, so it can never
    // read as an empty chair. `locked` (the switch refusal) stays the desktop's.
    let session_locked = locked
        && crate::lock_state::probe_lock_state_service()
            == Some(crate::lock_state::LockState::Locked);
    t.observe_lock(session_locked, os_tick());
    locked
}

/// FR-97 P3e-2 — Linux: logind's `LockedHint`, as the session's P3b emitter
/// last read it (every `lock_state::HINT_POLL` while a session is
/// connected). Each ask is a `loginctl` run, so the sampler never asks itself.
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
static LINUX_LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// FR-97 P3e-2 — Linux: a reading of logind's lock hint, from the session's
/// P3b emitter, into the tracker: a lock seen after the person's last input
/// means they left (FR-108 P1b).
pub fn note_linux_lock_hint(locked: bool) {
    #[cfg(all(target_os = "linux", feature = "enigo-input"))]
    {
        LINUX_LOCKED.store(locked, std::sync::atomic::Ordering::Relaxed);
        TRACKER
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe_lock(locked, os_tick());
    }
    #[cfg(not(all(target_os = "linux", feature = "enigo-input")))]
    let _ = locked;
}

/// FR-97 P3e-2 — the Linux reading: the X idle clock, with the lock as the
/// session's emitter last read it ([`note_linux_lock_hint`]).
#[cfg(all(target_os = "linux", feature = "enigo-input"))]
fn sample() -> bool {
    let locked = LINUX_LOCKED.load(std::sync::atomic::Ordering::Relaxed);
    let input = x11_idle::last_input_tick(os_tick());
    if let Some(input) = input {
        // An input inside display match's own mode switch was the switch's:
        // the X server clamping the pointer into a smaller mode moves the idle
        // clock as a person would (FR-97 §8, 0.4.148's release check).
        let switched =
            crate::display_match::own_switch_explains(input, MACHINE_SLACK_MS).then_some(input);
        let machine = [
            crate::keep_busy::last_remote_input_tick(),
            crate::keep_busy::last_own_move_tick(),
            switched,
        ];
        TRACKER
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe(input, &machine);
    }
    locked
}

/// The sampler runs on this host: Windows, and (FR-97 P3e-2) a Linux X11
/// session whose real display display match can switch.
fn samples() -> bool {
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(all(target_os = "linux", feature = "enigo-input"))]
    {
        crate::display_match::x11_offered()
    }
    #[cfg(not(any(
        target_os = "windows",
        all(target_os = "linux", feature = "enigo-input")
    )))]
    {
        false
    }
}

/// Start the sampler (once per process, where [`samples`]): from here on every
/// move of the idle clock is classified. Called when the worker starts, so a
/// request mid-session can tell the controller's input from a person's.
pub fn start() {
    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", feature = "enigo-input")
    ))]
    {
        if !samples() {
            return;
        }
        static STARTED: std::sync::Once = std::sync::Once::new();
        STARTED.call_once(|| {
            sample();
            let spawned = std::thread::Builder::new()
                .name("presence".into())
                .spawn(|| {
                    loop {
                        std::thread::sleep(SAMPLE_EVERY);
                        sample();
                    }
                });
            if let Err(e) = spawned {
                tracing::warn!(%e, "presence: the sampler could not start; display match reads every screen as attended");
            }
        });
    }
}

/// Who is at the screen now. Where nothing [`samples`], nothing is read as
/// empty: `Attended`.
pub fn now() -> Presence {
    if !samples() {
        return Presence::Attended;
    }
    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", feature = "enigo-input")
    ))]
    {
        start();
        let locked = sample();
        let (ago, away) = {
            let t = TRACKER.lock().unwrap_or_else(|p| p.into_inner());
            (t.person_ms_ago(os_tick()), t.away_since_lock())
        };
        decide(locked, ago, away, crate::lock_on_end::UNATTENDED_AFTER)
    }
    #[cfg(not(any(
        target_os = "windows",
        all(target_os = "linux", feature = "enigo-input")
    )))]
    {
        Presence::Attended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(300);

    /// FR-97 P3e-2 — the X server says how long ago, so "now minus that"
    /// moves by each read's latency. Unheld, every reading would be a new
    /// input, a person's, and nobody would ever read as away.
    #[test]
    fn the_x_idle_clock_holds_across_its_own_jitter() {
        assert_eq!(steady(None, 777), 777);
        assert_eq!(steady(Some(10_000), 10_003), 10_000);
        assert_eq!(steady(Some(10_000), 9_990), 10_000);
        assert_eq!(steady(Some(10_000), 10_000 + STEADY_MS), 10_000);
        assert_eq!(steady(Some(10_000), 12_500), 12_500, "a new input");
        assert_eq!(
            steady(Some(u32::MAX - 5), 10),
            u32::MAX - 5,
            "across the wrap"
        );
        // The tracker, fed held readings, sees one input and keeps it.
        let mut t = Tracker::default();
        let mut last = None;
        for jitter in [0u32, 3, 1, 4, 2] {
            let tick = steady(last, 50_000 + jitter);
            last = Some(tick);
            t.observe(tick, &[]);
        }
        assert_eq!(t.person_ms_ago(50_000 + 400_000), Some(400_000));
        assert_eq!(
            decide(false, t.person_ms_ago(450_000), false, WINDOW),
            Presence::Idle
        );
    }

    /// FR-97 P3e-2 — Linux's tick is a real clock now, and never the `0` that
    /// keep busy reads as "none yet".
    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_tick_moves_and_is_never_zero() {
        let a = os_tick();
        std::thread::sleep(Duration::from_millis(20));
        let b = os_tick();
        assert_ne!(a, 0);
        assert!(tick_delta(b, a) >= 15, "{a} → {b}");
    }

    #[test]
    fn locked_wins_over_everything() {
        assert_eq!(decide(true, Some(0), false, WINDOW), Presence::Locked);
        assert_eq!(
            decide(true, Some(10_000_000), false, WINDOW),
            Presence::Locked
        );
        assert_eq!(decide(true, None, false, WINDOW), Presence::Locked);
    }

    #[test]
    fn a_person_inside_the_window_is_attended_and_outside_it_is_not() {
        assert_eq!(decide(false, Some(0), false, WINDOW), Presence::Attended);
        assert_eq!(
            decide(false, Some(299_999), false, WINDOW),
            Presence::Attended
        );
        assert_eq!(decide(false, Some(300_000), false, WINDOW), Presence::Idle);
        assert_eq!(
            decide(false, Some(3_600_000), false, WINDOW),
            Presence::Idle
        );
    }

    #[test]
    fn an_unknown_is_never_an_empty_chair() {
        assert_eq!(decide(false, None, false, WINDOW), Presence::Attended);
    }

    #[test]
    fn the_first_reading_is_a_persons() {
        let mut t = Tracker::default();
        // Even if it sits right on a controller injection: nothing proves it
        // was the machine's before the tracker existed.
        t.observe(1_000, &[Some(1_000), None]);
        assert_eq!(t.person_ms_ago(301_000), Some(300_000));
    }

    /// FR-97 P3e-2 — the Linux sampler passes an input inside display match's
    /// own switch as a machine tick: the X server's pointer clamp, not a person.
    #[test]
    fn our_own_display_switch_does_not_move_the_person() {
        let mut t = Tracker::default();
        t.observe(100_000, &[None, None, None]);
        t.observe(400_000, &[None, None, Some(400_000)]);
        assert_eq!(t.person_ms_ago(700_000), Some(600_000));
        // The same move with no switch to explain it is a person's.
        let mut u = Tracker::default();
        u.observe(100_000, &[None, None, None]);
        u.observe(400_000, &[None, None, None]);
        assert_eq!(u.person_ms_ago(700_000), Some(300_000));
    }

    #[test]
    fn machine_input_does_not_move_the_person() {
        let mut t = Tracker::default();
        t.observe(1_000, &[None, None]);
        // The controller injects at 500_000, keep busy moves at 600_000.
        t.observe(500_010, &[Some(500_000), None]);
        t.observe(600_100, &[Some(500_000), Some(600_000)]);
        assert_eq!(
            t.person_ms_ago(700_000),
            Some(699_000),
            "the person's input is still the one at 1_000"
        );
        assert_eq!(
            decide(false, t.person_ms_ago(700_000), false, WINDOW),
            Presence::Idle
        );
    }

    #[test]
    fn a_person_after_the_machine_is_seen() {
        let mut t = Tracker::default();
        t.observe(1_000, &[None, None]);
        t.observe(500_010, &[Some(500_000), None]);
        // Well past the controller's last injection: a person.
        t.observe(500_600, &[Some(500_000), None]);
        assert_eq!(t.person_ms_ago(501_000), Some(400));
        assert_eq!(
            decide(false, t.person_ms_ago(501_000), false, WINDOW),
            Presence::Attended
        );
    }

    #[test]
    fn the_slack_is_inclusive_and_symmetric() {
        let mut t = Tracker::default();
        t.observe(1_000, &[None, None]);
        // The OS may record the input a little before or after the note.
        t.observe(400_000 - MACHINE_SLACK_MS, &[Some(400_000), None]);
        t.observe(400_000 + MACHINE_SLACK_MS, &[Some(400_000), None]);
        assert_eq!(t.person_ms_ago(400_250), Some(399_250));
        t.observe(400_000 + MACHINE_SLACK_MS + 1, &[Some(400_000), None]);
        assert_eq!(t.person_ms_ago(400_251), Some(0));
    }

    #[test]
    fn the_tick_clock_wraps() {
        let mut t = Tracker::default();
        let before_wrap = u32::MAX - 1_000;
        t.observe(before_wrap, &[None, None]);
        // 2_000 ms later the clock has wrapped past zero.
        let now = before_wrap.wrapping_add(2_000);
        assert_eq!(t.person_ms_ago(now), Some(2_000));
        // A controller injection across the wrap still explains its input.
        let inj = before_wrap.wrapping_add(1_500);
        t.observe(inj.wrapping_add(20), &[Some(inj), None]);
        assert_eq!(t.person_ms_ago(now), Some(2_000));
    }

    /// P1b — the person locks the screen and walks away; the controller
    /// unlocks it by typing the password through the session. The person's
    /// last input came before the lock, so they are away, whatever the window.
    #[test]
    fn a_lock_after_the_persons_last_input_means_away() {
        let mut t = Tracker::default();
        t.observe(10_000, &[None, None]); // the press that locked (Win+L)
        t.observe_lock(true, 10_400); // the sampler sees the lock
        t.observe_lock(true, 10_900);
        t.observe_lock(true, 11_900); // held for LOCK_HELD_MS
        // The controller types the password: machine input, not a person's.
        t.observe(60_000, &[Some(60_010), None]);
        t.observe_lock(false, 60_500);
        assert!(t.away_since_lock());
        assert_eq!(
            decide(false, t.person_ms_ago(61_000), t.away_since_lock(), WINDOW),
            Presence::Unattended,
            "the person's last input is 51 s old, inside the window, but before the lock"
        );
    }

    /// P1b — the person unlocks it themselves: their input after the lock
    /// makes them present again.
    #[test]
    fn the_persons_own_unlock_is_the_person() {
        let mut t = Tracker::default();
        t.observe(10_000, &[None, None]);
        t.observe_lock(true, 10_400);
        t.observe(60_000, &[None, None]); // the person types the password
        t.observe_lock(false, 60_500);
        assert!(!t.away_since_lock());
        assert_eq!(
            decide(false, t.person_ms_ago(61_000), t.away_since_lock(), WINDOW),
            Presence::Attended
        );
    }

    /// P1b — a screen already locked when the tracker first looks: its last
    /// input came before that reading, so the person is away once unlocked.
    #[test]
    fn a_lock_seen_at_the_first_reading_counts() {
        let mut t = Tracker::default();
        t.observe_lock(true, 5_000);
        t.observe(4_000, &[None, None]);
        assert!(!t.away_since_lock(), "one reading is not yet a held lock");
        t.observe_lock(true, 6_500);
        assert!(t.away_since_lock());
    }

    #[test]
    fn no_lock_means_nothing_changes() {
        let mut t = Tracker::default();
        t.observe(1_000, &[None, None]);
        t.observe_lock(false, 2_000);
        assert!(!t.away_since_lock());
        // And with no person's input known, a lock alone is no empty chair.
        let mut u = Tracker::default();
        u.observe_lock(true, 2_000);
        assert!(!u.away_since_lock());
    }

    /// rcfix 2026-11-04 — the field incident: a person reading at the
    /// screen for longer than the window is Idle, never Unattended, so display
    /// match cannot take their panel on the idle clock alone.
    #[test]
    fn idle_time_is_never_an_empty_chair() {
        for ago in [300_000u64, 301_000, 86_400_000] {
            let p = decide(false, Some(ago), false, WINDOW);
            assert_eq!(p, Presence::Idle);
            assert_ne!(p, Presence::Unattended);
        }
    }

    /// rcfix 2026-11-04 — a lock that comes and goes faster than
    /// LOCK_HELD_MS (one probe reading of a secure desktop: a UAC prompt, a
    /// glitch) is flapping and grounds no "away"; nor does a run of such blips.
    #[test]
    fn a_flapping_lock_is_not_away() {
        let mut t = Tracker::default();
        t.observe(10_000, &[None, None]);
        for start in [10_500u32, 12_000, 13_500, 15_000] {
            t.observe_lock(true, start);
            t.observe_lock(true, start + 500);
            t.observe_lock(true, start + 1_000);
            t.observe_lock(false, start + 1_400);
        }
        assert!(!t.away_since_lock());
        assert_eq!(
            decide(false, t.person_ms_ago(20_000), t.away_since_lock(), WINDOW),
            Presence::Attended
        );
        // The same lock, held: away.
        t.observe_lock(true, 30_000);
        t.observe_lock(true, 31_500);
        assert!(t.away_since_lock());
    }

    #[test]
    fn locked_still_wins_over_away() {
        assert_eq!(decide(true, Some(0), true, WINDOW), Presence::Locked);
    }

    #[test]
    fn a_repeated_reading_changes_nothing() {
        let mut t = Tracker::default();
        t.observe(1_000, &[None, None]);
        t.observe(1_000, &[Some(1_000), None]);
        assert_eq!(t.person_ms_ago(2_000), Some(1_000));
    }

    fn code_of(line: &str) -> &str {
        line.split("//").next().unwrap_or("")
    }

    /// FR-108 AC6 — display match tells a person from the controller WITHOUT a
    /// hook, raw input or a keyboard poll, FR-92's rule: each is what a
    /// keylogger looks like to EDR, and a GPO-locked desktop running EDR is in
    /// the acceptance bar. The banned names are assembled at run time, so this
    /// file cannot trip its own scan.
    #[test]
    fn no_keylogger_shaped_api_in_display_match() {
        let sources = [
            ("presence.rs", include_str!("presence.rs")),
            ("display_match.rs", include_str!("display_match.rs")),
        ];
        let banned: Vec<String> = [
            ["SetWindows", "HookEx"],
            ["RegisterRaw", "InputDevices"],
            ["GetRaw", "InputData"],
            ["GetKeyboard", "State"],
            ["GetAsync", "KeyState"],
            // FR-97 P3e-2 — the Linux port reads the X idle clock only: never
            // XRecord, XInput2's event stream or an input device node.
            ["record_enable", "_context"],
            ["xi_select", "_events"],
            ["/dev/input", "/event"],
        ]
        .iter()
        .map(|p| p.concat())
        .collect();
        for (name, src) in sources {
            for (i, line) in src.lines().enumerate() {
                let code = code_of(line);
                for b in &banned {
                    assert!(!code.contains(b.as_str()), "{name}:{}: uses {b}", i + 1);
                }
            }
        }
    }
}
