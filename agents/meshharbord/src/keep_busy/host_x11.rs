// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 P3 — the X11 host for the keep-busy engine.
//!
//! Cursor reads and moves go through the input arbiter (enigo's XTest backend
//! on the injector thread), exactly as on Windows. What this file reads itself,
//! on the engine's thread, over its OWN X connection:
//!
//! * **the idle clock** — `MIT-SCREEN-SAVER` `QueryInfo.ms_since_user_input`,
//!   the counter `xprintidle`, the X screensaver and most desktops' idle
//!   monitors read. XTest input resets it, so the engine's own moves land on
//!   it; anything else that resets it is a person;
//! * **the buttons** — `QueryPointer`'s mask;
//! * **the geometry** — the RandR 1.5 monitor under the pointer, ∩
//!   `_NET_WORKAREA`;
//! * **the session** — logind's `LockedHint` for the session on our display
//!   ([`super::logind`]).
//!
//! ⚠️ **Xwayland is refused, from the display itself.** XTest there moves only
//! Xwayland's own pointer, which the compositor ignores, so a calibration
//! could PASS while nothing on the real screen moves. The question is what
//! THIS connection drives, so it is asked of the server (the `XWAYLAND`
//! extension, or RandR monitors named `XWAYLAND*`), not of the environment.

use std::time::{Duration, Instant};

use x11rb::connection::{Connection, RequestConnection as _};
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::screensaver::ConnectionExt as _;
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, KeyButMask, Window};
use x11rb::rust_connection::RustConnection;

use super::engine::{Host, HostError, IdleMarker, Reason, SessionState};
use super::patterns::{self, Rect};
use super::{arbiter_io, logind, mono_us};

/// How long `settle` polls for our own move to reach the idle counter.
const SETTLE_CAP: Duration = Duration::from_millis(50);
const SETTLE_POLL: Duration = Duration::from_millis(2);
/// The idle counter is whole SERVER milliseconds, and the server's own clock
/// is read in whole milliseconds too: a reading is good to ±2 ms on top of
/// its round trip.
pub const GRANULE_US: u64 = 2_000;
/// Retry a failed connect no faster than this.
const RECONNECT_EVERY: Duration = Duration::from_secs(5);
/// How stale the session facts (logind) may get while keep busy runs.
const SESSION_EVERY: Duration = Duration::from_secs(2);
/// How often a missing session is looked for again.
const RESOLVE_EVERY: Duration = Duration::from_secs(10);

/// The last input, from an idle reading the server made somewhere between
/// `sent_us` (we asked) and `recv_us` (we had the answer): it lies in
/// `[sent − idle, recv − idle]`, widened by the server's millisecond grain.
/// A read that comes back late is a WIDER interval, never a shifted one.
pub fn marker_from_window(sent_us: u64, recv_us: u64, idle_ms: u32) -> IdleMarker {
    IdleMarker::within(sent_us, recv_us, u64::from(idle_ms) * 1_000, GRANULE_US)
}

/// `_NET_WORKAREA` is four CARDINALs per virtual desktop; the current one's.
pub fn workarea(values: &[u32], desktop: u32) -> Option<Rect> {
    let i = desktop as usize * 4;
    let r = values.get(i..i + 4)?;
    if r[2] == 0 || r[3] == 0 {
        return None;
    }
    Some(Rect::new(
        r[0] as f64,
        r[1] as f64,
        (r[0] + r[2]) as f64,
        (r[1] + r[3]) as f64,
    ))
}

/// The monitor holding `p`, else the nearest one (the pointer can sit in a
/// gap of an L-shaped layout).
pub fn monitor_at(monitors: &[Rect], p: (i32, i32)) -> Option<Rect> {
    let (x, y) = (p.0 as f64, p.1 as f64);
    monitors
        .iter()
        .find(|m| m.contains((x, y)))
        .or_else(|| {
            monitors.iter().min_by(|a, b| {
                let d = |m: &Rect| {
                    let cx = x.clamp(m.x0, m.x1);
                    let cy = y.clamp(m.y0, m.y1);
                    (cx - x).powi(2) + (cy - y).powi(2)
                };
                d(a).total_cmp(&d(b))
            })
        })
        .copied()
}

/// An Xwayland server, by a monitor's name.
pub fn is_xwayland_monitor_name(name: &[u8]) -> bool {
    name.starts_with(b"XWAYLAND")
}

/// Why there is no X connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoDisplay {
    /// The server is not there (yet): it starts and restarts with logins.
    Unreachable,
    /// The server answered and said no — typically a root daemon without the
    /// display's `XAUTHORITY` — or the `DISPLAY` names nothing usable. Not
    /// something waiting fixes.
    Refused,
}

/// Which connect failures are a refusal rather than an absence.
pub fn classify(e: &x11rb::errors::ConnectError) -> NoDisplay {
    use x11rb::errors::ConnectError as E;
    match e {
        E::SetupAuthenticate(_)
        | E::SetupFailed(_)
        | E::DisplayParsingError(_)
        | E::InvalidScreen => NoDisplay::Refused,
        _ => NoDisplay::Unreachable,
    }
}

struct Conn {
    conn: RustConnection,
    root: Window,
    screen: Rect,
    xwayland: bool,
    has_idle: bool,
    randr_monitors: bool,
}

impl Conn {
    fn open() -> Result<Conn, (NoDisplay, String)> {
        let (conn, n) = x11rb::connect(None).map_err(|e| (classify(&e), e.to_string()))?;
        let s = conn
            .setup()
            .roots
            .get(n)
            .ok_or((NoDisplay::Refused, "no such screen".to_string()))?;
        let (root, screen) = (
            s.root,
            Rect::new(
                0.0,
                0.0,
                f64::from(s.width_in_pixels),
                f64::from(s.height_in_pixels),
            ),
        );
        let has_ext =
            |name: &'static str| conn.extension_information(name).ok().flatten().is_some();
        let has_idle = has_ext(x11rb::protocol::screensaver::X11_EXTENSION_NAME);
        let xwayland = has_ext("XWAYLAND");
        let randr_monitors = has_ext(x11rb::protocol::randr::X11_EXTENSION_NAME)
            && conn
                .randr_query_version(1, 5)
                .ok()
                .and_then(|c| c.reply().ok())
                .is_some_and(|v| (v.major_version, v.minor_version) >= (1, 5));
        let mut c = Conn {
            conn,
            root,
            screen,
            xwayland,
            has_idle,
            randr_monitors,
        };
        if !c.xwayland && c.randr_monitors {
            // Older Xwayland has no extension of its own; its monitors still
            // say what it is.
            c.xwayland = c
                .monitor_names()
                .iter()
                .any(|n| is_xwayland_monitor_name(n));
        }
        Ok(c)
    }

    fn monitor_names(&self) -> Vec<Vec<u8>> {
        let Some(reply) = self
            .conn
            .randr_get_monitors(self.root, true)
            .ok()
            .and_then(|c| c.reply().ok())
        else {
            return Vec::new();
        };
        reply
            .monitors
            .iter()
            .filter_map(|m| {
                self.conn
                    .get_atom_name(m.name)
                    .ok()
                    .and_then(|c| c.reply().ok())
                    .map(|r| r.name)
            })
            .collect()
    }

    fn idle_ms(&self) -> Result<u32, String> {
        self.conn
            .screensaver_query_info(self.root)
            .map_err(|e| e.to_string())?
            .reply()
            .map(|r| r.ms_since_user_input)
            .map_err(|e| e.to_string())
    }

    fn monitors(&self) -> Vec<Rect> {
        if !self.randr_monitors {
            return vec![self.screen];
        }
        let Some(reply) = self
            .conn
            .randr_get_monitors(self.root, true)
            .ok()
            .and_then(|c| c.reply().ok())
        else {
            return vec![self.screen];
        };
        let v: Vec<Rect> = reply
            .monitors
            .iter()
            .filter(|m| m.width > 0 && m.height > 0)
            .map(|m| {
                Rect::new(
                    f64::from(m.x),
                    f64::from(m.y),
                    f64::from(m.x) + f64::from(m.width),
                    f64::from(m.y) + f64::from(m.height),
                )
            })
            .collect();
        if v.is_empty() { vec![self.screen] } else { v }
    }

    fn cardinals(&self, name: &[u8]) -> Option<Vec<u32>> {
        let atom = self.conn.intern_atom(true, name).ok()?.reply().ok()?.atom;
        if atom == 0 {
            return None;
        }
        let prop = self
            .conn
            .get_property(false, self.root, atom, AtomEnum::CARDINAL, 0, 1024)
            .ok()?
            .reply()
            .ok()?;
        Some(prop.value32()?.collect())
    }

    fn work_area(&self) -> Option<Rect> {
        let values = self.cardinals(b"_NET_WORKAREA")?;
        let desktop = self
            .cardinals(b"_NET_CURRENT_DESKTOP")
            .and_then(|v| v.first().copied())
            .unwrap_or(0);
        workarea(&values, desktop).or_else(|| workarea(&values, 0))
    }

    fn buttons_held(&self) -> Result<bool, String> {
        let r = self
            .conn
            .query_pointer(self.root)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?;
        // Buttons 4 and 5 are the wheel: a click, never held.
        let held = u16::from(KeyButMask::BUTTON1 | KeyButMask::BUTTON2 | KeyButMask::BUTTON3);
        Ok(u16::from(r.mask) & held != 0)
    }
}

/// logind's view of the session on our display, refreshed while keep busy
/// runs. No `loginctl` at all (no systemd) means no facts — never "locked".
#[derive(Default)]
struct SessionFacts {
    current: Option<logind::Session>,
    checked: Option<Instant>,
    resolved: Option<Instant>,
}

impl SessionFacts {
    fn refresh(&mut self, now: Instant) {
        if self.checked.is_some_and(|t| now < t + SESSION_EVERY) {
            return;
        }
        self.checked = Some(now);
        if let Some(cur) = &self.current {
            // Still there, and still on our display? A logout ends it.
            self.current = logind::show(&cur.id).filter(|s| s.active || s.locked);
            if self.current.is_some() {
                return;
            }
        }
        if self.resolved.is_some_and(|t| now < t + RESOLVE_EVERY) {
            return;
        }
        self.resolved = Some(now);
        self.current = logind::session_for_display(None);
    }
}

pub struct X11Host {
    conn: Option<Conn>,
    next_connect: Option<Instant>,
    /// Why the last connect failed, while backing off.
    no_display: NoDisplay,
    facts: SessionFacts,
}

impl X11Host {
    pub fn new() -> X11Host {
        X11Host {
            conn: None,
            next_connect: None,
            no_display: NoDisplay::Unreachable,
            facts: SessionFacts::default(),
        }
    }

    /// The connection, (re)opened at most every [`RECONNECT_EVERY`]. An X
    /// server restarts with every login, so a dead connection is dropped and
    /// opened again rather than kept.
    fn conn(&mut self) -> Result<&Conn, NoDisplay> {
        if self.conn.is_none() {
            let now = Instant::now();
            if self.next_connect.is_some_and(|t| now < t) {
                return Err(self.no_display);
            }
            match Conn::open() {
                Ok(c) => {
                    tracing::info!(
                        xwayland = c.xwayland,
                        idle_clock = c.has_idle,
                        randr_monitors = c.randr_monitors,
                        "keep-busy: X display opened"
                    );
                    self.conn = Some(c);
                }
                Err((why, e)) => {
                    if why == NoDisplay::Refused && self.no_display != NoDisplay::Refused {
                        tracing::warn!(
                            error = %e,
                            "keep-busy: the X display refused this process (no XAUTHORITY for it?)"
                        );
                    } else {
                        tracing::debug!(error = %e, "keep-busy: no X display");
                    }
                    self.no_display = why;
                    self.next_connect = Some(now + RECONNECT_EVERY);
                    return Err(why);
                }
            }
        }
        self.conn.as_ref().ok_or(self.no_display)
    }

    /// A request failed on the connection: drop it, reopen later.
    fn lost(&mut self, why: &str) {
        tracing::debug!(%why, "keep-busy: X connection dropped");
        self.conn = None;
        self.no_display = NoDisplay::Unreachable;
        self.next_connect = Some(Instant::now() + RECONNECT_EVERY);
    }

    fn marker(&mut self) -> Option<IdleMarker> {
        let c = self.conn().ok()?;
        let sent = mono_us();
        let idle = c.idle_ms();
        let recv = mono_us();
        match idle {
            Ok(ms) => Some(marker_from_window(sent, recv, ms)),
            Err(e) => {
                self.lost(&e);
                None
            }
        }
    }
}

impl Host for X11Host {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_ms(&self) -> u64 {
        super::wall_ms()
    }

    fn session(&mut self) -> SessionState {
        if std::env::var_os("DISPLAY").is_none() {
            // A Wayland-only session, or a root daemon nobody gave a display.
            return SessionState::Unsupported(if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                Reason::Wayland
            } else {
                Reason::Unsupported
            });
        }
        let c = match self.conn() {
            Ok(c) => c,
            // The X server is not up yet, or is restarting for a login.
            Err(NoDisplay::Unreachable) => return SessionState::Absent,
            Err(NoDisplay::Refused) => return SessionState::Unsupported(Reason::Unsupported),
        };
        if c.xwayland {
            return SessionState::Unsupported(Reason::Wayland);
        }
        if !c.has_idle {
            return SessionState::Unsupported(Reason::NoIdleClock);
        }
        self.facts.refresh(Instant::now());
        match &self.facts.current {
            Some(s) if s.locked => SessionState::Locked,
            // The display manager's login screen: nobody is signed in.
            Some(s) if !s.is_user() => SessionState::Absent,
            _ => SessionState::Present,
        }
    }

    fn idle_marker(&mut self) -> Option<IdleMarker> {
        self.marker()
    }

    fn cursor(&mut self) -> Result<(i32, i32), HostError> {
        arbiter_io::cursor()
    }

    fn move_to(&mut self, p: (i32, i32)) -> Result<(), HostError> {
        arbiter_io::move_to(p)
    }

    fn settle(&mut self, before: IdleMarker) -> Option<IdleMarker> {
        let deadline = Instant::now() + SETTLE_CAP;
        loop {
            if let Some(m) = self.marker()
                && m.differs(&before)
            {
                return Some(m);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(SETTLE_POLL);
        }
    }

    fn buttons_held(&mut self) -> Result<bool, HostError> {
        let r = match self.conn() {
            Ok(c) => c.buttons_held(),
            Err(_) => return Err(HostError::Failed("no X display".into())),
        };
        r.map_err(|e| {
            self.lost(&e);
            HostError::Failed(e)
        })
    }

    fn safe_box_at(&mut self, p: (i32, i32)) -> Option<Rect> {
        let c = self.conn().ok()?;
        let monitor = monitor_at(&c.monitors(), p)?;
        let work = c.work_area().unwrap_or(monitor);
        patterns::safe_box(monitor, work)
    }

    fn remote_epoch(&self) -> u64 {
        super::remote_input_epoch()
    }

    fn wait(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Nothing X11 says reliably about focus-follows-mouse; no warnings.
pub fn warnings() -> Vec<&'static str> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Microseconds: a reading taken over a 400 µs round trip, idle 250 ms.
    #[test]
    fn the_idle_counter_becomes_an_interval_around_the_last_input() {
        let m = marker_from_window(10_000_000, 10_000_400, 250);
        assert_eq!(m.value, 9_750_200);
        assert_eq!(m.tolerance, 200 + GRANULE_US);
        // Read again 40 ms later with nothing new: the same last input.
        let again = marker_from_window(10_040_000, 10_040_300, 290);
        assert!(!again.differs(&m));
        // A key 20 ms after it: a different one.
        let key = marker_from_window(10_040_000, 10_040_300, 20);
        assert!(key.differs(&m));
        // A read answered 30 ms LATE is a wider interval, not a shifted one:
        // nothing new happened, and it does not say otherwise.
        let late = marker_from_window(10_040_000, 10_070_000, 290);
        assert!(!late.differs(&m), "{late:?} vs {m:?}");
        // An idle longer than the clock saturates, never wraps; and the real
        // clock starts far enough from zero that it cannot.
        assert_eq!(marker_from_window(5, 9, u32::MAX).value, 0);
        assert!(mono_us() > u64::from(u32::MAX) * 1_000);
        // A clock read backwards (never, but) is an empty window, not a panic.
        let _ = marker_from_window(10, 5, 0);
    }

    /// The bug this interval exists for: with the receive time taken as THE
    /// time of the reading, one late read (a loaded host) moved the instant
    /// by its delay and the engine paused for its own move. Measured on
    /// Xvfb under WSL with builds running: paused 0.3 s after starting.
    #[test]
    fn a_late_answer_never_reads_as_a_person() {
        // The engine's move at t = 5.000 s lands; settle reads it promptly.
        let baseline = marker_from_window(5_001_000, 5_001_300, 1);
        // 33 ms later, no new input: the server answers at once (idle 34 ms),
        // but the answer is read 25 ms late. Taken at receipt, that was an
        // input 24.7 ms after the move — a "person".
        let tick = marker_from_window(5_034_000, 5_059_000, 34);
        assert!(!tick.differs(&baseline), "{tick:?} vs {baseline:?}");
    }

    #[test]
    fn the_current_desktops_work_area_is_read() {
        // Two desktops: a 24 px top panel, then a 48 px left dock.
        let v = [0, 24, 1920, 1056, 48, 0, 1872, 1080];
        assert_eq!(workarea(&v, 0), Some(Rect::new(0.0, 24.0, 1920.0, 1080.0)));
        assert_eq!(workarea(&v, 1), Some(Rect::new(48.0, 0.0, 1920.0, 1080.0)));
        assert_eq!(workarea(&v, 2), None, "no such desktop");
        assert_eq!(workarea(&[0, 0, 0, 0], 0), None, "an empty area is none");
    }

    #[test]
    fn the_monitor_under_the_pointer_or_the_nearest() {
        let left = Rect::new(0.0, 0.0, 1920.0, 1080.0);
        // Taller, to the right, with a dead zone below `left`.
        let right = Rect::new(1920.0, 0.0, 4480.0, 1440.0);
        let all = [left, right];
        assert_eq!(monitor_at(&all, (100, 100)), Some(left));
        assert_eq!(monitor_at(&all, (3000, 1300)), Some(right));
        assert_eq!(monitor_at(&all, (1000, 1300)), Some(left), "nearest");
        assert_eq!(monitor_at(&[], (0, 0)), None);
    }

    /// A server that is not there yet (it restarts with every login) is
    /// waited for; one that refuses this process is not.
    #[test]
    fn a_refusal_is_told_from_an_absence() {
        use x11rb::errors::ConnectError as E;
        assert_eq!(classify(&E::InvalidScreen), NoDisplay::Refused);
        assert_eq!(
            classify(&E::IoError(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused
            ))),
            NoDisplay::Unreachable
        );
        assert_eq!(classify(&E::UnknownError), NoDisplay::Unreachable);
    }

    #[test]
    fn xwayland_monitors_are_recognised() {
        assert!(is_xwayland_monitor_name(b"XWAYLAND0"));
        assert!(is_xwayland_monitor_name(b"XWAYLAND12"));
        assert!(!is_xwayland_monitor_name(b"HDMI-1"));
        assert!(!is_xwayland_monitor_name(b"eDP-1"));
    }

    /// Every real-X test shares ONE display, and to keep busy another test's
    /// move IS a person — measured: run in parallel, the end-to-end test
    /// paused, correctly, 0.3 s in, for the other test's `move_mouse`. So
    /// they take turns (and CI runs the X step with `--test-threads=1`, for
    /// the capture tests on the same display).
    static ONE_DISPLAY: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Against a REAL X server: `MESHHARBORD_TEST_X11=1 xvfb-run -a cargo test
    /// -p meshharbord --features enigo-input --lib keep_busy::host_x11 --
    /// --test-threads=1`. XTest motion resets the idle counter, and the host
    /// sees our display as a plain X server with an idle clock and a geometry.
    #[test]
    fn against_a_real_x_server_the_idle_clock_sees_xtest_motion() {
        if std::env::var_os("MESHHARBORD_TEST_X11").is_none() {
            return;
        }
        let _turn = ONE_DISPLAY.lock().unwrap_or_else(|e| e.into_inner());
        use enigo::{Coordinate, Enigo, Mouse, Settings};
        let c = Conn::open().expect("an X display (xvfb-run)");
        assert!(!c.xwayland, "Xvfb is not Xwayland");
        assert!(c.has_idle, "Xvfb serves MIT-SCREEN-SAVER");
        let read = |c: &Conn| {
            let sent = mono_us();
            let idle = c.idle_ms().unwrap();
            marker_from_window(sent, mono_us(), idle)
        };
        std::thread::sleep(Duration::from_millis(300));
        let before = read(&c);
        // A move through the injector keep busy really uses.
        let mut enigo = Enigo::new(&Settings::default()).expect("enigo on the X display");
        enigo.move_mouse(200, 200, Coordinate::Abs).unwrap();
        let deadline = Instant::now() + SETTLE_CAP;
        let mut seen = None;
        while Instant::now() < deadline {
            let m = read(&c);
            if m.differs(&before) {
                seen = Some(m);
                break;
            }
            std::thread::sleep(SETTLE_POLL);
        }
        assert!(seen.is_some(), "XTest motion must reset the idle counter");
        // And a quiet moment after it, the last input holds still.
        let landed = seen.unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let later = read(&c);
        assert!(!later.differs(&landed), "{later:?} vs {landed:?}");
        // enigo and our own connection read the same pointer.
        assert_eq!(enigo.location().unwrap(), (200, 200));
        let mons = c.monitors();
        assert!(!mons.is_empty());
        assert!(!c.buttons_held().unwrap());
        println!("x11-real: XTest motion reset the idle counter; monitors {mons:?}");
    }

    /// The whole loop on a REAL X server: the engine, this host, and the input
    /// arbiter's own enigo injector. It calibrates (both legs on the real idle
    /// counter), draws, keeps the server's idle time near zero, and a key
    /// typed by SOMEONE ELSE (a second XTest client) pauses it as a local
    /// person. Ticks are driven here, so the interleaving is deterministic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn against_a_real_x_server_keep_busy_runs_and_a_typed_key_pauses_it() {
        if std::env::var_os("MESHHARBORD_TEST_X11").is_none() {
            return;
        }
        // The arbiter captures the runtime at its first call, from in here.
        let _ = crate::input::arbiter::global();
        tokio::task::spawn_blocking(|| {
            let _turn = ONE_DISPLAY.lock().unwrap_or_else(|e| e.into_inner());
            use crate::keep_busy::engine::{Engine, Phase, Settings, Source};
            use enigo::{Direction, Enigo, Key, Keyboard, Settings as EnigoSettings};
            let probe = Conn::open().expect("an X display (xvfb-run)");
            let mut host = X11Host::new();
            let mut e = Engine::new(7);
            let drive = |e: &mut Engine, host: &mut X11Host, for_: Duration| {
                let end = Instant::now() + for_;
                while Instant::now() < end {
                    if e.next_wake().is_some_and(|w| Instant::now() >= w) {
                        e.tick(host);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            };
            e.set_on(Settings::default(), "test".into(), 0, Instant::now())
                .unwrap();
            drive(&mut e, &mut host, Duration::from_secs(2));
            let s = e.snapshot(Instant::now());
            assert_eq!((s.phase, s.reason), (Phase::Running, None), "{s:?}");
            let idle = probe.idle_ms().unwrap();
            assert!(
                idle < 250,
                "the server sees the moves as activity: idle {idle} ms"
            );

            // One more move, then — well clear of it — someone types.
            drive(&mut e, &mut host, Duration::from_millis(40));
            std::thread::sleep(Duration::from_millis(25));
            let mut someone = Enigo::new(&EnigoSettings::default()).unwrap();
            someone.key(Key::Shift, Direction::Click).unwrap();
            std::thread::sleep(Duration::from_millis(5));
            e.tick(&mut host);
            let s = e.snapshot(Instant::now());
            assert_eq!(
                (s.phase, s.paused_by),
                (Phase::Paused, Some(Source::Local)),
                "{s:?}"
            );
            println!("x11-real: ran with idle {idle} ms, and a typed key paused it");
        })
        .await
        .unwrap();
    }
}
