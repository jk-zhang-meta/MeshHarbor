// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 P9 — which Linux host keep busy runs on.
//!
//! The X11 host (`host_x11.rs`) serves wherever this process holds a real X
//! display: a per-user daemon in an X11 session, or the virtual desktop. Its
//! verdict wins whenever it has one. Where it cannot — no `DISPLAY` at all
//! (a root daemon, on Wayland or on Xorg alike), or the display is Xwayland
//! (XTest there moves only Xwayland's own pointer) — the GNOME host
//! (`host_gnome.rs`) is asked: uinput moves, Mutter's idle clock. When that
//! cannot serve either, the more specific of the two reasons is shown.

use std::time::{Duration, Instant};

use super::engine::{Host, HostError, IdleMarker, Reason, SessionState};
use super::host_x11::X11Host;
use super::patterns::Rect;

#[cfg_attr(
    not(all(feature = "uinput-input", feature = "portal-capture")),
    allow(dead_code)
)]
/// Is this an X11 verdict the GNOME host may be able to do better than?
fn x11_cannot(s: SessionState) -> bool {
    matches!(
        s,
        SessionState::Unsupported(Reason::Wayland | Reason::Unsupported)
    )
}

#[cfg_attr(
    not(all(feature = "uinput-input", feature = "portal-capture")),
    allow(dead_code)
)]
/// The GNOME host's verdict, unless it only says "unsupported" where X11
/// said something more useful (a Wayland session needing uinput reads
/// better as "Wayland" than as "not on this computer").
pub fn merge(x11: SessionState, gnome: SessionState) -> SessionState {
    match (x11, gnome) {
        (
            SessionState::Unsupported(Reason::Wayland),
            SessionState::Unsupported(Reason::Unsupported),
        ) => x11,
        _ => gnome,
    }
}

pub struct LinuxHost {
    x11: X11Host,
    #[cfg(all(feature = "uinput-input", feature = "portal-capture"))]
    gnome: super::host_gnome::GnomeHost,
    /// Which host the engine's last `session()` chose.
    on_gnome: bool,
}

impl LinuxHost {
    pub fn new() -> LinuxHost {
        LinuxHost {
            x11: X11Host::new(),
            #[cfg(all(feature = "uinput-input", feature = "portal-capture"))]
            gnome: super::host_gnome::GnomeHost::new(),
            on_gnome: false,
        }
    }

    fn active(&mut self) -> &mut dyn Host {
        #[cfg(all(feature = "uinput-input", feature = "portal-capture"))]
        if self.on_gnome {
            return &mut self.gnome;
        }
        &mut self.x11
    }
}

impl Host for LinuxHost {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_ms(&self) -> u64 {
        super::wall_ms()
    }

    fn session(&mut self) -> SessionState {
        let x = self.x11.session();
        #[cfg(all(feature = "uinput-input", feature = "portal-capture"))]
        if x11_cannot(x) {
            if !self.on_gnome {
                tracing::info!(x11 = ?x, "keep-busy: no X display to drive — asking the GNOME session");
            }
            self.on_gnome = true;
            return merge(x, self.gnome.session());
        }
        if self.on_gnome {
            tracing::info!("keep-busy: an X display is back — driving it");
        }
        self.on_gnome = false;
        x
    }

    fn idle_marker(&mut self) -> Option<IdleMarker> {
        self.active().idle_marker()
    }

    fn cursor(&mut self) -> Result<(i32, i32), HostError> {
        self.active().cursor()
    }

    fn move_to(&mut self, p: (i32, i32)) -> Result<(), HostError> {
        self.active().move_to(p)
    }

    fn settle(&mut self, before: IdleMarker) -> Option<IdleMarker> {
        self.active().settle(before)
    }

    fn buttons_held(&mut self) -> Result<bool, HostError> {
        self.active().buttons_held()
    }

    fn safe_box_at(&mut self, p: (i32, i32)) -> Option<Rect> {
        self.active().safe_box_at(p)
    }

    fn remote_epoch(&self) -> u64 {
        super::remote_input_epoch()
    }

    fn wait(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn blind(&self) -> bool {
        #[cfg(all(feature = "uinput-input", feature = "portal-capture"))]
        if self.on_gnome {
            return self.gnome.blind();
        }
        self.x11.blind()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_what_x11_cannot_reach_goes_to_gnome_and_the_better_reason_shows() {
        use SessionState as S;
        assert!(x11_cannot(S::Unsupported(Reason::Wayland)));
        assert!(x11_cannot(S::Unsupported(Reason::Unsupported)));
        // An X display with no idle clock, a lock, a login screen: X11's word.
        assert!(!x11_cannot(S::Unsupported(Reason::NoIdleClock)));
        assert!(!x11_cannot(S::Locked));
        assert!(!x11_cannot(S::Absent));
        assert!(!x11_cannot(S::Present));
        // GNOME runs it, waits, or knows better: its verdict.
        assert_eq!(
            merge(S::Unsupported(Reason::Wayland), S::Present),
            S::Present
        );
        assert_eq!(
            merge(S::Unsupported(Reason::Unsupported), S::Locked),
            S::Locked
        );
        assert_eq!(
            merge(
                S::Unsupported(Reason::Wayland),
                S::Unsupported(Reason::NoIdleClock)
            ),
            S::Unsupported(Reason::NoIdleClock)
        );
        // Neither can: "Wayland" says more than "not on this computer".
        assert_eq!(
            merge(
                S::Unsupported(Reason::Wayland),
                S::Unsupported(Reason::Unsupported)
            ),
            S::Unsupported(Reason::Wayland)
        );
    }
}
