// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 P9 — the pure half of keep busy on a GNOME session reached through
//! uinput: the monitor layout Mutter reports, the line protocol to the
//! session helper, the mapping from desktop pixels to the fraction of the
//! desktop an absolute device moves to, and when the host can run at all.
//!
//! Pure on purpose — no D-Bus, no process, no device — so every rule here is
//! a unit test on every platform. The impure halves are
//! `session_helper.rs` (the child inside the person's session) and
//! `host_gnome.rs` (the engine's host).

use serde::{Deserialize, Serialize};

use super::engine::{Reason, SessionState};
use super::patterns::Rect;

/// Every line the helper writes for the daemon starts with this; anything
/// else on its stdout (a library's chatter) is ignored, never parsed.
pub const MARK: &str = "KB1 ";

/// Mutter's idle time is whole milliseconds, counted from its own clock:
/// good to ±1 ms on top of the round trip.
pub const GRAIN_US: u64 = 1_000;

/// One monitor, in the coordinates of the desktop Mutter maps an absolute
/// pointing device onto (logical pixels in GNOME's default layout mode).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Mon {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub primary: bool,
}

impl Mon {
    pub fn rect(&self) -> Rect {
        Rect::new(
            f64::from(self.x),
            f64::from(self.y),
            f64::from(self.x) + f64::from(self.w),
            f64::from(self.y) + f64::from(self.h),
        )
    }
}

/// What the helper reports for `geom`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Geometry {
    pub monitors: Vec<Mon>,
}

impl Geometry {
    /// Every monitor's bounding box: what an absolute device's `0..=1`
    /// spans. `None` without a monitor.
    pub fn bounds(&self) -> Option<Rect> {
        let mut it = self.monitors.iter().filter(|m| m.w > 0 && m.h > 0);
        let first = it.next()?.rect();
        Some(it.fold(first, |acc, m| {
            let r = m.rect();
            Rect::new(
                acc.x0.min(r.x0),
                acc.y0.min(r.y0),
                acc.x1.max(r.x1),
                acc.y1.max(r.y1),
            )
        }))
    }

    /// The primary monitor (else the first).
    pub fn primary(&self) -> Option<Mon> {
        self.monitors
            .iter()
            .find(|m| m.primary)
            .or_else(|| self.monitors.first())
            .copied()
    }

    /// The monitor holding `p`, else the primary.
    pub fn monitor_at(&self, p: (i32, i32)) -> Option<Mon> {
        let (x, y) = (f64::from(p.0), f64::from(p.1));
        self.monitors
            .iter()
            .find(|m| m.rect().contains((x, y)))
            .copied()
            .or_else(|| self.primary())
    }
}

/// A logical monitor as `GetCurrentState` lists it, reduced to what the
/// layout needs: its origin, scale, transform, and the connectors in it.
#[derive(Debug, Clone, PartialEq)]
pub struct LogicalIn {
    pub x: i32,
    pub y: i32,
    pub scale: f64,
    pub transform: u32,
    pub primary: bool,
    pub connectors: Vec<String>,
}

/// A physical monitor's CURRENT mode, in physical pixels.
#[derive(Debug, Clone, PartialEq)]
pub struct ModeIn {
    pub connector: String,
    pub width: i32,
    pub height: i32,
}

/// `layout-mode`: logical pixels (GNOME's default on Wayland) or physical.
pub const LAYOUT_LOGICAL: u32 = 1;
pub const LAYOUT_PHYSICAL: u32 = 2;

/// The monitors in the desktop's own coordinates. A logical monitor's size
/// is its first connector's current mode, turned for a 90°/270° transform
/// (Mutter's odd transforms, flipped or not), and divided by its scale in
/// the logical layout mode. A logical monitor whose connector has no
/// current mode is left out rather than guessed at.
pub fn layout(logical: &[LogicalIn], current: &[ModeIn], layout_mode: u32) -> Geometry {
    let monitors = logical
        .iter()
        .filter_map(|l| {
            let mode = l
                .connectors
                .iter()
                .find_map(|c| current.iter().find(|m| &m.connector == c))?;
            let (mut w, mut h) = (mode.width, mode.height);
            if l.transform % 2 == 1 {
                std::mem::swap(&mut w, &mut h);
            }
            if layout_mode != LAYOUT_PHYSICAL && l.scale > 0.0 {
                w = (f64::from(w) / l.scale).round() as i32;
                h = (f64::from(h) / l.scale).round() as i32;
            }
            (w > 0 && h > 0).then_some(Mon {
                x: l.x,
                y: l.y,
                w,
                h,
                primary: l.primary,
            })
        })
        .collect();
    Geometry { monitors }
}

/// Desktop pixel `p` as the fraction of `bounds` an absolute device moves
/// to — clamped, because a point past the edge must land ON the edge, never
/// wrap or be refused.
pub fn to_unit(p: (i32, i32), bounds: Rect) -> (f64, f64) {
    let w = (bounds.x1 - bounds.x0).max(1.0);
    let h = (bounds.y1 - bounds.y0).max(1.0);
    (
        ((f64::from(p.0) - bounds.x0) / w).clamp(0.0, 1.0),
        ((f64::from(p.1) - bounds.y0) / h).clamp(0.0, 1.0),
    )
}

/// One line from the helper.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// `hello idle=1 geom=1`: what the session can answer.
    Hello {
        idle: bool,
        geom: bool,
    },
    /// Milliseconds since the session's last input.
    Idle(u64),
    Geom(Geometry),
    /// `err <what> <why>`.
    Err(String),
}

/// A helper line, or `None` for anything that is not one (no mark, or a
/// shape this build does not know — a newer helper is never an error).
pub fn parse_reply(line: &str) -> Option<Reply> {
    let rest = line.trim_end().strip_prefix(MARK)?;
    let (verb, arg) = rest.split_once(' ').unwrap_or((rest, ""));
    match verb {
        "hello" => {
            let flag = |k: &str| arg.split_whitespace().any(|t| t == format!("{k}=1"));
            Some(Reply::Hello {
                idle: flag("idle"),
                geom: flag("geom"),
            })
        }
        "idle" => arg.trim().parse().ok().map(Reply::Idle),
        "geom" => serde_json::from_str(arg).ok().map(Reply::Geom),
        "err" => Some(Reply::Err(arg.to_string())),
        _ => None,
    }
}

/// What logind says about the session at the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seat {
    /// No graphical session, or `loginctl` is not there.
    Nobody,
    /// The display manager's login screen.
    Greeter,
    /// A person's session; `wayland` = its type.
    Person { locked: bool, wayland: bool },
}

/// The session helper, as far as the host knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Helper {
    /// Not answered yet (starting, or waiting out a retry).
    Starting,
    /// It answered, and Mutter's idle monitor did.
    Ready,
    /// It answered, and no idle monitor did: not GNOME.
    NoIdleClock,
    /// It cannot be run here (several attempts failed).
    Broken,
}

/// Can keep busy run on this GNOME host now? `uinput` = the arbiter's ONE
/// injector is the uinput device (it moves the real pointer below any
/// compositor).
pub fn decide(seat: Seat, uinput: bool, helper: Helper) -> SessionState {
    let wayland = matches!(seat, Seat::Person { wayland: true, .. });
    match seat {
        Seat::Nobody | Seat::Greeter => SessionState::Absent,
        // Locked is decided before anything else is asked: a lock screen is
        // a pause, whatever this host can do.
        Seat::Person { locked: true, .. } => SessionState::Locked,
        Seat::Person { .. } if !uinput => SessionState::Unsupported(if wayland {
            Reason::Wayland
        } else {
            Reason::Unsupported
        }),
        Seat::Person { .. } => match helper {
            Helper::Ready => SessionState::Present,
            // GNOME is the one desktop whose idle clock a session helper can
            // read; anything else (KDE, wlroots) has none to offer here.
            Helper::NoIdleClock => SessionState::Unsupported(Reason::NoIdleClock),
            Helper::Broken => SessionState::Unsupported(Reason::Unsupported),
            // Starting: wait, as for a desktop that is coming up.
            Helper::Starting => SessionState::Absent,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(c: &str, w: i32, h: i32) -> ModeIn {
        ModeIn {
            connector: c.into(),
            width: w,
            height: h,
        }
    }

    fn logical(x: i32, y: i32, scale: f64, transform: u32, primary: bool, c: &str) -> LogicalIn {
        LogicalIn {
            x,
            y,
            scale,
            transform,
            primary,
            connectors: vec![c.into()],
        }
    }

    /// The vmtest guest's shape: one virtual monitor, scale 1.
    #[test]
    fn one_monitor_at_scale_one_is_its_mode() {
        let g = layout(
            &[logical(0, 0, 1.0, 0, true, "Virtual-1")],
            &[mode("Virtual-1", 1280, 800)],
            LAYOUT_LOGICAL,
        );
        assert_eq!(
            g.monitors,
            vec![Mon {
                x: 0,
                y: 0,
                w: 1280,
                h: 800,
                primary: true
            }]
        );
        assert_eq!(g.bounds(), Some(Rect::new(0.0, 0.0, 1280.0, 800.0)));
    }

    /// A 4K panel at 200 % beside a 1080p one at 100 %, the logical layout:
    /// the scaled monitor is 1920 logical pixels wide, and the second
    /// monitor starts there.
    #[test]
    fn a_scaled_monitor_is_divided_by_its_scale_in_the_logical_layout() {
        let l = [
            logical(0, 0, 2.0, 0, true, "eDP-1"),
            logical(1920, 0, 1.0, 0, false, "DP-1"),
        ];
        let m = [mode("eDP-1", 3840, 2160), mode("DP-1", 1920, 1080)];
        let g = layout(&l, &m, LAYOUT_LOGICAL);
        assert_eq!(g.monitors[0].w, 1920);
        assert_eq!(g.monitors[0].h, 1080);
        assert_eq!(g.bounds(), Some(Rect::new(0.0, 0.0, 3840.0, 1080.0)));
        // The physical layout keeps physical pixels.
        let p = layout(&l, &m, LAYOUT_PHYSICAL);
        assert_eq!((p.monitors[0].w, p.monitors[0].h), (3840, 2160));
        // An absent layout-mode reads as logical (Wayland's default).
        assert_eq!(layout(&l, &m, 0).monitors[0].w, 1920);
    }

    #[test]
    fn a_portrait_monitor_swaps_its_mode_and_a_dark_one_is_left_out() {
        let g = layout(
            &[
                logical(0, 0, 1.0, 1, true, "DP-1"),
                logical(0, 0, 1.0, 7, false, "DP-2"),
                logical(5000, 0, 1.0, 0, false, "DP-3"),
            ],
            &[mode("DP-1", 1920, 1080), mode("DP-2", 1920, 1080)],
            LAYOUT_LOGICAL,
        );
        assert_eq!((g.monitors[0].w, g.monitors[0].h), (1080, 1920));
        assert_eq!(
            (g.monitors[1].w, g.monitors[1].h),
            (1080, 1920),
            "flipped 270"
        );
        assert_eq!(g.monitors.len(), 2, "DP-3 has no current mode");
    }

    /// A monitor LEFT of the primary has negative coordinates; the mapping
    /// is relative to the bounding box, and a point past an edge lands on it.
    #[test]
    fn pixels_map_into_the_bounding_box_and_clamp_at_its_edges() {
        let g = Geometry {
            monitors: vec![
                Mon {
                    x: -1280,
                    y: 0,
                    w: 1280,
                    h: 1024,
                    primary: false,
                },
                Mon {
                    x: 0,
                    y: 0,
                    w: 1920,
                    h: 1080,
                    primary: true,
                },
            ],
        };
        let b = g.bounds().unwrap();
        assert_eq!(b, Rect::new(-1280.0, 0.0, 1920.0, 1080.0));
        assert_eq!(to_unit((-1280, 0), b), (0.0, 0.0));
        assert_eq!(to_unit((320, 540), b), (0.5, 0.5));
        assert_eq!(to_unit((9999, -5), b), (1.0, 0.0));
        assert_eq!(g.primary().unwrap().x, 0);
        assert_eq!(g.monitor_at((-10, 10)).unwrap().x, -1280);
        assert_eq!(
            g.monitor_at((5000, 5000)).unwrap().x,
            0,
            "outside ⇒ primary"
        );
        assert_eq!(Geometry::default().bounds(), None);
    }

    #[test]
    fn helper_lines_parse_and_noise_does_not() {
        assert_eq!(
            parse_reply("KB1 hello idle=1 geom=0\n"),
            Some(Reply::Hello {
                idle: true,
                geom: false
            })
        );
        assert_eq!(parse_reply("KB1 idle 1234"), Some(Reply::Idle(1234)));
        assert_eq!(parse_reply("KB1 idle soon"), None);
        let g = Geometry {
            monitors: vec![Mon {
                x: 0,
                y: 0,
                w: 800,
                h: 600,
                primary: true,
            }],
        };
        let line = format!("KB1 geom {}", serde_json::to_string(&g).unwrap());
        assert_eq!(parse_reply(&line), Some(Reply::Geom(g)));
        assert_eq!(
            parse_reply("KB1 err idle no IdleMonitor"),
            Some(Reply::Err("idle no IdleMonitor".into()))
        );
        assert_eq!(parse_reply("idle 5"), None, "no mark");
        assert_eq!(parse_reply("KB1 wobble 5"), None, "a newer verb");
        assert_eq!(
            parse_reply("KB12 idle 5"),
            None,
            "a longer mark is not ours"
        );
    }

    #[test]
    fn the_session_decides_before_the_helper_does() {
        use Helper as H;
        use SessionState as S;
        let person = |locked, wayland| Seat::Person { locked, wayland };
        assert_eq!(decide(Seat::Nobody, true, H::Ready), S::Absent);
        assert_eq!(decide(Seat::Greeter, true, H::Ready), S::Absent);
        assert_eq!(decide(person(true, true), false, H::Broken), S::Locked);
        assert_eq!(
            decide(person(false, true), false, H::Ready),
            S::Unsupported(Reason::Wayland)
        );
        assert_eq!(
            decide(person(false, false), false, H::Ready),
            S::Unsupported(Reason::Unsupported)
        );
        assert_eq!(
            decide(person(false, true), true, H::NoIdleClock),
            S::Unsupported(Reason::NoIdleClock)
        );
        assert_eq!(
            decide(person(false, true), true, H::Broken),
            S::Unsupported(Reason::Unsupported)
        );
        assert_eq!(decide(person(false, true), true, H::Starting), S::Absent);
        assert_eq!(decide(person(false, true), true, H::Ready), S::Present);
        assert_eq!(decide(person(false, false), true, H::Ready), S::Present);
    }
}
