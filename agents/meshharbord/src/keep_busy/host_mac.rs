// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 P3 — the macOS host for the keep-busy engine.
//!
//! Pointer reads and moves go through the input arbiter (enigo's CGEvent
//! backend on the injector thread), as on every host. What this file reads
//! itself, with plain CoreGraphics calls — the release build carries no AppKit
//! (`viewer-indicator-macos` is deliberately off there):
//!
//! * **the idle clock** — `CGEventSourceSecondsSinceLastEventType` over the
//!   session's COMBINED state: the engine's own posted moves reset it, and so
//!   does every person's input. (Posted input also resets `IOHIDSystem`'s
//!   idle time, which the screensaver and display sleep read — `power.rs`.)
//! * **the buttons** — `CGEventSourceButtonState` over the HID state:
//!   physical buttons only;
//! * **the session** — `CGSessionCopyCurrentDictionary`: none at all for a
//!   process outside a GUI session (the root LaunchDaemon of a supervised
//!   Mac, whose GUI worker runs keep busy instead), and otherwise its lock
//!   and on-console flags;
//! * **the geometry** — the display under the pointer, inset by MORE than the
//!   shared 48 px: without AppKit there is no `visibleFrame`, so the menu bar
//!   and a Dock on any edge are kept out by margin, and so are the hot
//!   corners that can start the screensaver or lock the screen.
//!
//! Points, not pixels, throughout — the space CGEvent moves and reads in.

use std::ffi::c_void;
use std::time::{Duration, Instant};

use super::arbiter_io;
use super::engine::{Host, HostError, IdleMarker, SessionState};
use super::patterns::{self, Rect};

/// How long `settle` polls for our own move to reach the idle clock.
const SETTLE_CAP: Duration = Duration::from_millis(50);
const SETTLE_POLL: Duration = Duration::from_millis(2);
/// The clock answers in fractional seconds; a millisecond of grain is ample.
pub const GRAIN_US: u64 = 1_000;
/// Beyond the shared 48 px edge inset: the menu bar (up to ~38 pt on a
/// notched display) and a Dock of the default size on any edge, with room
/// to spare. Patterns are sized from what is left.
pub const MAC_INSET_PT: f64 = 96.0;

#[repr(C)]
#[derive(Clone, Copy)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CGSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;

/// `kCGEventSourceStateCombinedSessionState`.
const COMBINED_SESSION_STATE: i32 = 0;
/// `kCGEventSourceStateHIDSystemState`.
const HID_SYSTEM_STATE: i32 = 1;
/// `kCGAnyInputEventType`.
const ANY_INPUT_EVENT: u32 = !0;
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// `kCFNumberSInt64Type`.
const CF_NUMBER_SINT64: isize = 4;

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventSourceSecondsSinceLastEventType(state: i32, event_type: u32) -> f64;
    fn CGEventSourceButtonState(state: i32, button: u32) -> bool;
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    fn CGGetDisplaysWithPoint(
        point: CGPoint,
        max_displays: u32,
        displays: *mut u32,
        matching: *mut u32,
    ) -> i32;
    fn CGMainDisplayID() -> u32;
    fn CGDisplayBounds(display: u32) -> CGRect;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        alloc: *const c_void,
        bytes: *const u8,
        num_bytes: isize,
        encoding: u32,
        is_external_representation: u8,
    ) -> CFStringRef;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFBooleanGetValue(boolean: CFTypeRef) -> bool;
    fn CFNumberGetTypeID() -> usize;
    fn CFNumberGetValue(number: CFTypeRef, the_type: isize, value: *mut c_void) -> bool;
}

/// A CoreFoundation object this code owns, released on drop.
struct Owned(CFTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a Create/Copy result we own, released exactly once.
            unsafe { CFRelease(self.0) };
        }
    }
}

fn cfstr(s: &str) -> Owned {
    // SAFETY: the bytes outlive the call, and CoreFoundation copies them.
    Owned(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            s.as_ptr(),
            s.len() as isize,
            CF_STRING_ENCODING_UTF8,
            0,
        )
    })
}

/// A dictionary value that is a CFBoolean — or a CFNumber, as some releases
/// store the lock flag — read as a bool. Anything else is `None`.
fn truthy(v: CFTypeRef) -> Option<bool> {
    if v.is_null() {
        return None;
    }
    // SAFETY: `v` is a live CF object borrowed from a dictionary we hold.
    let ty = unsafe { CFGetTypeID(v) };
    // SAFETY: plain type-id getters.
    if ty == unsafe { CFBooleanGetTypeID() } {
        // SAFETY: `v` is a CFBoolean, checked just above.
        return Some(unsafe { CFBooleanGetValue(v) });
    }
    // SAFETY: as above.
    if ty == unsafe { CFNumberGetTypeID() } {
        let mut n: i64 = 0;
        // SAFETY: `v` is a CFNumber; `n` is a live i64 for the SInt64 read.
        let ok = unsafe { CFNumberGetValue(v, CF_NUMBER_SINT64, (&mut n as *mut i64).cast()) };
        return ok.then_some(n != 0);
    }
    None
}

/// Where this process stands with the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Console {
    /// Not in a GUI session at all — the root LaunchDaemon.
    NoSession,
    Locked,
    /// Fast user switching: another user has the screen.
    NotOnConsole,
    Present,
}

/// The two session flags, as read from the dictionary (pure, so tested).
pub fn console_from(locked: Option<bool>, on_console: Option<bool>) -> Console {
    if locked == Some(true) {
        Console::Locked
    } else if on_console == Some(false) {
        Console::NotOnConsole
    } else {
        Console::Present
    }
}

/// FR-97 P2d-1 — this session's screen, for `lock_state`'s hints: `None`
/// outside a GUI session (the root LaunchDaemon has none to ask about), else
/// whether nobody can use it right now. Another user on the console (fast user
/// switching) counts as locked, as it does for keep busy: this session's
/// screen, and a consent panel drawn on it, are out of sight either way.
pub(crate) fn screen_locked() -> Option<bool> {
    match console() {
        Console::NoSession => None,
        Console::Locked | Console::NotOnConsole => Some(true),
        Console::Present => Some(false),
    }
}

fn console() -> Console {
    // SAFETY: no preconditions; NULL outside a GUI session. A Copy result,
    // so ours to release.
    let dict = Owned(unsafe { CGSessionCopyCurrentDictionary() });
    if dict.0.is_null() {
        return Console::NoSession;
    }
    let flag = |key: &str| {
        let k = cfstr(key);
        if k.0.is_null() {
            return None;
        }
        // SAFETY: a live dictionary and key; the value is borrowed (Get rule)
        // and read before the dictionary is released.
        truthy(unsafe { CFDictionaryGetValue(dict.0, k.0) })
    };
    console_from(
        flag("CGSSessionScreenIsLocked"),
        flag("kCGSSessionOnConsoleKey"),
    )
}

fn display_bounds(id: u32) -> Rect {
    // SAFETY: a plain value query; an unknown id yields an empty rect.
    let r = unsafe { CGDisplayBounds(id) };
    Rect::new(
        r.origin.x,
        r.origin.y,
        r.origin.x + r.size.width,
        r.origin.y + r.size.height,
    )
}

/// The display under `p`, else the main one.
fn display_at(p: (i32, i32)) -> Option<Rect> {
    let (mut id, mut n) = (0u32, 0u32);
    let at = CGPoint {
        x: f64::from(p.0),
        y: f64::from(p.1),
    };
    // SAFETY: room for exactly one id, as `max_displays` says.
    let err = unsafe { CGGetDisplaysWithPoint(at, 1, &mut id, &mut n) };
    let r = if err == 0 && n > 0 {
        display_bounds(id)
    } else {
        // SAFETY: no preconditions.
        display_bounds(unsafe { CGMainDisplayID() })
    };
    (r.w() > 0.0 && r.h() > 0.0).then_some(r)
}

/// The safe box on a display: the shared inset, plus the macOS margin that
/// stands in for `visibleFrame`.
pub fn mac_safe_box(display: Rect) -> Option<Rect> {
    let work = Rect::new(
        display.x0 + MAC_INSET_PT,
        display.y0 + MAC_INSET_PT,
        display.x1 - MAC_INSET_PT,
        display.y1 - MAC_INSET_PT,
    );
    patterns::safe_box(display, work)
}

fn idle_marker() -> Option<IdleMarker> {
    let sent = super::mono_us();
    // SAFETY: plain query.
    let secs =
        unsafe { CGEventSourceSecondsSinceLastEventType(COMBINED_SESSION_STATE, ANY_INPUT_EVENT) };
    let recv = super::mono_us();
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    Some(IdleMarker::within(
        sent,
        recv,
        (secs * 1_000_000.0) as u64,
        GRAIN_US,
    ))
}

pub struct MacHost;

impl MacHost {
    pub fn new() -> MacHost {
        MacHost
    }
}

impl Host for MacHost {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_ms(&self) -> u64 {
        super::wall_ms()
    }

    fn session(&mut self) -> SessionState {
        match console() {
            // Nobody this process can act for: the root daemon of a
            // supervised Mac, whose worker runs keep busy in the session.
            Console::NoSession => SessionState::Absent,
            Console::Locked | Console::NotOnConsole => SessionState::Locked,
            Console::Present => SessionState::Present,
        }
    }

    fn idle_marker(&mut self) -> Option<IdleMarker> {
        idle_marker()
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
            if let Some(m) = idle_marker()
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
        // Left, right, middle — physical (HID) state only.
        // SAFETY: plain queries.
        Ok((0..3u32).any(|b| unsafe { CGEventSourceButtonState(HID_SYSTEM_STATE, b) }))
    }

    fn safe_box_at(&mut self, p: (i32, i32)) -> Option<Rect> {
        mac_safe_box(display_at(p)?)
    }

    fn remote_epoch(&self) -> u64 {
        super::remote_input_epoch()
    }

    fn wait(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// No macOS setting changes what keep busy should say; no warnings.
pub fn warnings() -> Vec<&'static str> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_wins_then_the_console() {
        assert_eq!(console_from(Some(true), Some(true)), Console::Locked);
        assert_eq!(console_from(Some(true), Some(false)), Console::Locked);
        assert_eq!(console_from(None, Some(false)), Console::NotOnConsole);
        assert_eq!(console_from(Some(false), Some(true)), Console::Present);
        // Neither key (an older release): present.
        assert_eq!(console_from(None, None), Console::Present);
    }

    /// The Dock and the menu bar are kept out by margin: the safe box sits
    /// MAC_INSET_PT inside every edge of the display, never the bare 48.
    #[test]
    fn the_macos_box_keeps_clear_of_the_menu_bar_dock_and_corners() {
        let display = Rect::new(0.0, 0.0, 1512.0, 982.0);
        let b = mac_safe_box(display).unwrap();
        assert_eq!(b, Rect::new(96.0, 96.0, 1416.0, 886.0));
        // A second display to the left, with a negative origin.
        let left = Rect::new(-1920.0, 0.0, 0.0, 1080.0);
        let b = mac_safe_box(left).unwrap();
        assert_eq!(b, Rect::new(-1824.0, 96.0, -96.0, 984.0));
        // Too small to draw in: none.
        assert_eq!(mac_safe_box(Rect::new(0.0, 0.0, 200.0, 200.0)), None);
    }

    /// The real calls, on the Mac running the tests: the clock answers, and
    /// some display is found. (CI's macOS job compiles the crate; this runs
    /// wherever `cargo test` runs on a Mac.)
    #[test]
    fn the_real_calls_answer_on_a_mac() {
        assert!(idle_marker().is_some());
        assert!(display_at((0, 0)).is_some() || console() == Console::NoSession);
    }
}
