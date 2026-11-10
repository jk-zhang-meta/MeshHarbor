// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 P9 — keep busy on a GNOME session the agent reaches through uinput:
//! GNOME on Wayland, and GNOME on Xorg under a root daemon that has no X
//! display of its own.
//!
//! * **moves** go through the input arbiter's ONE injector, the uinput
//!   device below the compositor, as fractions of the desktop
//!   ([`arbiter_io::move_norm`]): the same kernel device a controller's
//!   input uses, so they reset the session's idle clock like a tablet would;
//! * **the idle clock** is Mutter's IdleMonitor, asked by a helper running
//!   AS the person inside their session ([`super::session_helper`]) and read
//!   as an interval ([`IdleMarker::within`]), like X11's;
//! * **the geometry** is Mutter's DisplayConfig, through the same helper;
//! * **the lock** is logind's `LockedHint`, which GNOME sets.
//!
//! ⚠️ **Blind.** Nothing on Wayland tells an unprivileged process where the
//! pointer is, and uinput cannot read it back. The engine is told where it
//! last PUT the pointer ([`Host::blind`]), so a person is seen by the idle
//! clock alone — every move, key, click and scroll reaches it — and after a
//! pause keep busy resumes where it stopped, not where the person left the
//! pointer: the pointer jumps back. Mouse buttons are not observable either:
//! a button held perfectly still for longer than `resume_after` is not
//! seen. Both are in `docs/keep-busy.md`.

use std::time::{Duration, Instant};

use super::engine::{Host, HostError, IdleMarker, Reason, SessionState};
use super::gnome::{self, Geometry, Helper, Seat};
use super::patterns::{self, Rect};
use super::session_helper::{Link, LinkError};
use super::{arbiter_io, logind, mono_us};

/// How long the helper has to say hello (it connects to the session bus and
/// asks Mutter twice).
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// One question's bound. A D-Bus round trip is a millisecond or two; a
/// helper that takes this long is dropped and started again.
const ASK_TIMEOUT: Duration = Duration::from_millis(250);
/// Retry a helper that failed no faster than this…
const RELINK_EVERY: Duration = Duration::from_secs(10);
/// …doubling after each failure up to this…
const RELINK_MAX: Duration = Duration::from_secs(300);
/// …and call it broken (while still retrying) after this many in a row.
const BROKEN_AFTER: u32 = 3;
/// How stale the session facts (logind) may get.
const SESSION_EVERY: Duration = Duration::from_secs(2);
/// How stale the monitor layout may get while keep busy runs.
const GEOMETRY_EVERY: Duration = Duration::from_secs(10);
/// After the arbiter refused a normalised move (its injector is not uinput
/// after all), how long that answer stands.
const REFUSAL_HOLDS: Duration = Duration::from_secs(60);
/// `settle`: how long our own move may take to reach the idle clock (helper
/// round trips included), and how often to look.
const SETTLE_CAP: Duration = Duration::from_millis(100);
const SETTLE_POLL: Duration = Duration::from_millis(2);

/// Is the arbiter's injector going to be the uinput device? Its own
/// `open_default` picks uinput first when this says yes.
fn uinput_ready() -> bool {
    crate::input::uinput_backend::env_enabled() && crate::input::uinput_backend::available()
}

#[derive(Default)]
struct Facts {
    current: Option<logind::Session>,
    checked: Option<Instant>,
}

impl Facts {
    fn refresh(&mut self, now: Instant) {
        if self.checked.is_some_and(|t| now < t + SESSION_EVERY) {
            return;
        }
        self.checked = Some(now);
        // No display to go by: the active graphical session (x11 or wayland).
        self.current = logind::sessions().and_then(|all| logind::pick(&all, None).cloned());
    }

    fn seat(&self) -> Seat {
        match &self.current {
            None => Seat::Nobody,
            Some(s) if !s.is_user() => Seat::Greeter,
            Some(s) => Seat::Person {
                locked: s.locked,
                wayland: s.kind == "wayland",
            },
        }
    }
}

pub struct GnomeHost {
    facts: Facts,
    link: Option<Link>,
    /// Whose session this is: the cursor and the layout below are theirs.
    person: Option<u32>,
    next_link: Option<Instant>,
    failures: u32,
    geom: Option<Geometry>,
    geom_at: Option<Instant>,
    /// Where the engine last put the pointer — all a blind host knows.
    cursor: Option<(i32, i32)>,
    refused_at: Option<Instant>,
}

impl GnomeHost {
    pub fn new() -> GnomeHost {
        GnomeHost {
            facts: Facts::default(),
            link: None,
            person: None,
            next_link: None,
            failures: 0,
            geom: None,
            geom_at: None,
            cursor: None,
            refused_at: None,
        }
    }

    fn uinput(&self) -> bool {
        let refused = self.refused_at.is_some_and(|t| t.elapsed() < REFUSAL_HOLDS);
        !refused && uinput_ready()
    }

    /// A helper in `uid`'s session: (re)started when there is none, or it
    /// belongs to someone else.
    fn helper_for(&mut self, uid: u32, now: Instant) -> Helper {
        if self.person != Some(uid) {
            // A different person: nothing of the last one's carries over.
            self.drop_link("the person changed");
            self.person = Some(uid);
            self.cursor = None;
            self.geom = None;
            self.failures = 0;
            self.next_link = None;
        }
        if self.link.as_mut().is_some_and(|l| !l.alive()) {
            // It went away (asked nothing for a while, or the session ended):
            // a new one, now — not "no idle clock".
            self.drop_link("the helper exited");
            self.next_link = None;
        }
        if let Some(l) = &self.link {
            return if l.idle_ok {
                Helper::Ready
            } else {
                Helper::NoIdleClock
            };
        }
        let waiting = if self.failures >= BROKEN_AFTER {
            Helper::Broken
        } else {
            Helper::Starting
        };
        if self.next_link.is_some_and(|t| now < t) {
            return waiting;
        }
        // Retried for as long as the session lasts, backing off: a session bus
        // that is late at login is not a broken host.
        let backoff = RELINK_EVERY
            .saturating_mul(1u32 << self.failures.min(5))
            .min(RELINK_MAX);
        self.next_link = Some(now + backoff);
        match Link::open(HELLO_TIMEOUT) {
            Ok(l) => {
                tracing::info!(
                    idle_clock = l.idle_ok,
                    geometry = l.geom_ok,
                    "keep-busy: GNOME session helper up"
                );
                let ok = l.idle_ok;
                self.link = Some(l);
                self.failures = 0;
                if ok {
                    Helper::Ready
                } else {
                    Helper::NoIdleClock
                }
            }
            Err(LinkError::NoSession) => Helper::Starting,
            Err(e) => {
                self.failures += 1;
                tracing::warn!(error = %e, failures = self.failures, "keep-busy: the GNOME session helper did not start");
                if self.failures >= BROKEN_AFTER {
                    Helper::Broken
                } else {
                    Helper::Starting
                }
            }
        }
    }

    fn drop_link(&mut self, why: &str) {
        if self.link.take().is_some() {
            tracing::debug!(%why, "keep-busy: GNOME session helper dropped");
        }
    }

    fn marker(&mut self) -> Option<IdleMarker> {
        let link = self.link.as_mut()?;
        let sent = mono_us();
        let r = link.idle_ms(ASK_TIMEOUT);
        let recv = mono_us();
        match r {
            Ok(ms) => Some(IdleMarker::within(
                sent,
                recv,
                ms.saturating_mul(1_000),
                gnome::GRAIN_US,
            )),
            Err(e) => {
                // A late answer would be read as the next one's: start over.
                self.drop_link(&e.to_string());
                None
            }
        }
    }

    fn geometry(&mut self) -> Option<&Geometry> {
        let stale = self.geom_at.is_none_or(|t| t.elapsed() >= GEOMETRY_EVERY);
        if stale && let Some(link) = self.link.as_mut() {
            self.geom_at = Some(Instant::now());
            match link.geometry(ASK_TIMEOUT) {
                Ok(g) if g.bounds().is_some() => self.geom = Some(g),
                Ok(_) => {}
                Err(e) => self.drop_link(&e.to_string()),
            }
        }
        self.geom.as_ref()
    }

    fn unsupported_reason(&self) -> Reason {
        match self.facts.seat() {
            Seat::Person { wayland: true, .. } => Reason::Wayland,
            _ => Reason::Unsupported,
        }
    }
}

impl Host for GnomeHost {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_ms(&self) -> u64 {
        super::wall_ms()
    }

    fn session(&mut self) -> SessionState {
        let now = Instant::now();
        self.facts.refresh(now);
        let seat = self.facts.seat();
        let uinput = self.uinput();
        let helper = match (&self.facts.current, seat) {
            // Only a person's unlocked session needs the helper at all.
            (Some(s), Seat::Person { locked: false, .. }) if uinput => {
                let uid = s.uid;
                self.helper_for(uid, now)
            }
            _ => Helper::Starting,
        };
        gnome::decide(seat, uinput, helper)
    }

    fn idle_marker(&mut self) -> Option<IdleMarker> {
        self.marker()
    }

    fn cursor(&mut self) -> Result<(i32, i32), HostError> {
        if let Some(c) = self.cursor {
            return Ok(c);
        }
        // Never moved yet: start in the middle of the primary monitor.
        let m = self
            .geometry()
            .and_then(Geometry::primary)
            .ok_or_else(|| HostError::Failed("no monitor layout from the session".into()))?;
        Ok((m.x + m.w / 2, m.y + m.h / 2))
    }

    fn move_to(&mut self, p: (i32, i32)) -> Result<(), HostError> {
        let bounds = self
            .geometry()
            .and_then(Geometry::bounds)
            .ok_or_else(|| HostError::Failed("no monitor layout from the session".into()))?;
        let (fx, fy) = gnome::to_unit(p, bounds);
        match arbiter_io::move_norm(fx, fy) {
            Ok(()) => {
                self.cursor = Some(p);
                Ok(())
            }
            // The arbiter's injector is not uinput after all.
            Err(HostError::Unsupported(_)) => {
                self.refused_at = Some(Instant::now());
                Err(HostError::Unsupported(self.unsupported_reason()))
            }
            Err(e) => Err(e),
        }
    }

    fn settle(&mut self, before: IdleMarker) -> Option<IdleMarker> {
        let deadline = Instant::now() + SETTLE_CAP;
        loop {
            if let Some(m) = self.marker()
                && m.differs(&before)
            {
                return Some(m);
            }
            if Instant::now() >= deadline || self.link.is_none() {
                return None;
            }
            std::thread::sleep(SETTLE_POLL);
        }
    }

    /// Not observable here (no global pointer query on Wayland, and uinput
    /// reads nothing back): reported as none held. See the module notes.
    fn buttons_held(&mut self) -> Result<bool, HostError> {
        Ok(false)
    }

    fn safe_box_at(&mut self, p: (i32, i32)) -> Option<Rect> {
        let m = self.geometry()?.monitor_at(p)?;
        // GNOME's work area is not published over D-Bus; the inset already
        // clears its top bar and the Activities corner.
        patterns::safe_box(m.rect(), m.rect())
    }

    fn remote_epoch(&self) -> u64 {
        super::remote_input_epoch()
    }

    fn wait(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn blind(&self) -> bool {
        true
    }
}
