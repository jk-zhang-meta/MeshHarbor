// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — the shapes keep-busy draws, as pure geometry.
//!
//! Every shape is a closed curve in a unit space (its bounding box inside
//! `[-1, 1]²`), sampled densely and walked by ARC LENGTH so the pointer moves
//! at a constant speed whatever the curve's parametrisation does. [`Placement`]
//! maps the unit space onto the screen: anchored at the cursor, scaled to the
//! safe box, clamped inside it. Nothing here touches the OS, so every property
//! (closure, bounds, constant speed, anchoring) is a unit test.

use std::f64::consts::{PI, TAU};
use std::time::Duration;

/// A shape keep-busy can draw. The wire names are a compatibility surface
/// (the viewer stores them), matched by EQUALITY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pattern {
    Circle,
    Triangle,
    Square,
    /// A pentagram drawn in one stroke (vertex order 0, 2, 4, 1, 3).
    Star,
    /// The lemniscate of Gerono — an ∞.
    Figure8,
    Heart,
    /// A hypotrochoid (R = 5, r = 3, d = 5): a five-lobed rosette.
    Spirograph,
    /// 3:2 Lissajous whose phase drifts every loop, so it slowly morphs.
    Lissajous,
    /// An eight-petal rose, r = cos 4θ.
    Rose,
    /// A sine wave across and back.
    Wave,
    /// A smooth random loop with uneven speed and short rests — the most
    /// human-looking of them.
    Wander,
    /// Invisible: a 1 px there-and-back every [`SUBTLE_EVERY`]. Resets the
    /// idle clock with no visible motion and no cursor stream to a viewer.
    Subtle,
    /// A new visible pattern every loop.
    Shuffle,
}

/// How often [`Pattern::Subtle`] nudges. Comfortably inside a one-minute lock
/// policy and the five-minute "Away" of the presence apps.
pub const SUBTLE_EVERY: Duration = Duration::from_secs(45);

/// The rotation [`Pattern::Shuffle`] walks — every visible pattern.
pub const SHUFFLE_ORDER: [Pattern; 11] = [
    Pattern::Circle,
    Pattern::Triangle,
    Pattern::Heart,
    Pattern::Star,
    Pattern::Figure8,
    Pattern::Spirograph,
    Pattern::Square,
    Pattern::Lissajous,
    Pattern::Rose,
    Pattern::Wave,
    Pattern::Wander,
];

impl Pattern {
    pub const ALL: [Pattern; 13] = [
        Pattern::Circle,
        Pattern::Triangle,
        Pattern::Square,
        Pattern::Star,
        Pattern::Figure8,
        Pattern::Heart,
        Pattern::Spirograph,
        Pattern::Lissajous,
        Pattern::Rose,
        Pattern::Wave,
        Pattern::Wander,
        Pattern::Subtle,
        Pattern::Shuffle,
    ];

    pub fn wire(self) -> &'static str {
        match self {
            Pattern::Circle => "circle",
            Pattern::Triangle => "triangle",
            Pattern::Square => "square",
            Pattern::Star => "star",
            Pattern::Figure8 => "figure8",
            Pattern::Heart => "heart",
            Pattern::Spirograph => "spirograph",
            Pattern::Lissajous => "lissajous",
            Pattern::Rose => "rose",
            Pattern::Wave => "wave",
            Pattern::Wander => "wander",
            Pattern::Subtle => "subtle",
            Pattern::Shuffle => "shuffle",
        }
    }

    /// Equality, never a prefix match — the `ssh` / `ssh-consent` lesson.
    pub fn from_wire(s: &str) -> Option<Pattern> {
        Pattern::ALL.into_iter().find(|p| p.wire() == s)
    }

    /// The concrete shape drawn on loop `n` (Shuffle resolves per loop).
    pub fn shape_for_loop(self, n: u64) -> Pattern {
        match self {
            Pattern::Shuffle => SHUFFLE_ORDER[(n % SHUFFLE_ORDER.len() as u64) as usize],
            other => other,
        }
    }
}

/// Size, as the shape's extent over the safe box's short side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    S,
    M,
    L,
}

impl Size {
    pub fn wire(self) -> &'static str {
        match self {
            Size::S => "s",
            Size::M => "m",
            Size::L => "l",
        }
    }
    pub fn from_wire(s: &str) -> Option<Size> {
        match s {
            "s" => Some(Size::S),
            "m" => Some(Size::M),
            "l" => Some(Size::L),
            _ => None,
        }
    }
    /// The shape's diameter as a fraction of the safe box's short side.
    pub fn fraction(self) -> f64 {
        match self {
            Size::S => 0.14,
            Size::M => 0.26,
            Size::L => 0.42,
        }
    }
}

/// Pointer speed along the curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Slow,
    Normal,
    Fast,
}

impl Speed {
    pub fn wire(self) -> &'static str {
        match self {
            Speed::Slow => "slow",
            Speed::Normal => "normal",
            Speed::Fast => "fast",
        }
    }
    pub fn from_wire(s: &str) -> Option<Speed> {
        match s {
            "slow" => Some(Speed::Slow),
            "normal" => Some(Speed::Normal),
            "fast" => Some(Speed::Fast),
            _ => None,
        }
    }
    /// Pixels per second along the curve.
    pub fn px_per_s(self) -> f64 {
        match self {
            Speed::Slow => 120.0,
            Speed::Normal => 260.0,
            Speed::Fast => 520.0,
        }
    }
}

/// An axis-aligned rectangle in desktop pixels, `x0 ≤ x < x1`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x0: f64,
    pub y0: f64,
    pub x1: f64,
    pub y1: f64,
}

impl Rect {
    pub fn new(x0: f64, y0: f64, x1: f64, y1: f64) -> Rect {
        Rect { x0, y0, x1, y1 }
    }
    pub fn w(&self) -> f64 {
        (self.x1 - self.x0).max(0.0)
    }
    pub fn h(&self) -> f64 {
        (self.y1 - self.y0).max(0.0)
    }
    pub fn contains(&self, p: (f64, f64)) -> bool {
        p.0 >= self.x0 && p.0 <= self.x1 && p.1 >= self.y0 && p.1 <= self.y1
    }
    pub fn clamp(&self, p: (f64, f64)) -> (f64, f64) {
        (p.0.clamp(self.x0, self.x1), p.1.clamp(self.y0, self.y1))
    }
    fn intersect(&self, o: &Rect) -> Rect {
        Rect {
            x0: self.x0.max(o.x0),
            y0: self.y0.max(o.y0),
            x1: self.x1.min(o.x1),
            y1: self.y1.min(o.y1),
        }
    }
    fn inset(&self, by: f64) -> Rect {
        Rect {
            x0: self.x0 + by,
            y0: self.y0 + by,
            x1: self.x1 - by,
            y1: self.y1 - by,
        }
    }
}

/// How far from every edge of the monitor the pointer may go. Corners and
/// edges are where the hot spots live: GNOME's Activities corner, macOS hot
/// corners (which can start the screensaver or LOCK the screen), an
/// auto-hidden taskbar or Dock, the menu bar, Windows' Peek.
pub const EDGE_INSET_PX: f64 = 48.0;

/// The box keep-busy may draw in: the monitor's work area (taskbar, Dock and
/// menu bar excluded) intersected with an [`EDGE_INSET_PX`] inset of the
/// whole monitor. `None` when nothing usable is left (a tiny display).
pub fn safe_box(monitor: Rect, work_area: Rect) -> Option<Rect> {
    let b = work_area.intersect(&monitor.inset(EDGE_INSET_PX));
    (b.w() >= 32.0 && b.h() >= 32.0).then_some(b)
}

// ─── Paths ──────────────────────────────────────────────────────────────

/// A closed curve in unit space, sampled densely, with its cumulative arc
/// length, plus the per-segment speed and rests [`Pattern::Wander`] uses.
#[derive(Debug, Clone)]
pub struct Path {
    pts: Vec<(f64, f64)>,
    /// `cum[i]` = arc length from `pts[0]` to `pts[i]`; `cum.len() == pts.len()`.
    /// The closing segment `pts[n-1] → pts[0]` is included in `total`.
    cum: Vec<f64>,
    total: f64,
    /// Speed multiplier per sample index (1.0 unless Wander).
    speed: Vec<f64>,
    /// Rests: (arc position, duration). Sorted by position.
    rests: Vec<(f64, Duration)>,
}

const SAMPLES: usize = 720;

impl Path {
    /// The curve for `shape` on loop `n` (`n` only matters for Lissajous's
    /// drift and Wander's fresh waypoints). `seed` makes Wander deterministic.
    ///
    /// `shape` must be a drawable shape — [`Pattern::Subtle`] and
    /// [`Pattern::Shuffle`] are resolved by the engine first; they fall back
    /// to a circle here rather than panic.
    pub fn for_shape(shape: Pattern, n: u64, seed: u64) -> Path {
        let pts = match shape {
            Pattern::Circle | Pattern::Subtle | Pattern::Shuffle => {
                sample(|t| (t.cos(), t.sin()), 0.0, TAU)
            }
            Pattern::Triangle => polygon(&regular(3, -PI / 2.0)),
            Pattern::Square => polygon(&[(-1.0, -1.0), (1.0, -1.0), (1.0, 1.0), (-1.0, 1.0)]),
            Pattern::Star => {
                let v = regular(5, -PI / 2.0);
                polygon(&[v[0], v[2], v[4], v[1], v[3]])
            }
            Pattern::Figure8 => sample(|t| (t.sin(), t.sin() * t.cos() * 1.6), 0.0, TAU),
            Pattern::Heart => sample(
                |t| {
                    let x = 16.0 * t.sin().powi(3);
                    let y = 13.0 * t.cos()
                        - 5.0 * (2.0 * t).cos()
                        - 2.0 * (3.0 * t).cos()
                        - (4.0 * t).cos();
                    // Screen y grows downward.
                    (x / 17.0, -y / 17.0)
                },
                0.0,
                TAU,
            ),
            Pattern::Spirograph => {
                let (r_big, r, d) = (5.0, 3.0, 5.0);
                let k = (r_big - r) / r;
                let norm = r_big - r + d;
                sample(
                    move |t| {
                        (
                            ((r_big - r) * t.cos() + d * (k * t).cos()) / norm,
                            ((r_big - r) * t.sin() - d * (k * t).sin()) / norm,
                        )
                    },
                    0.0,
                    3.0 * TAU,
                )
            }
            Pattern::Lissajous => {
                let delta = PI / 2.0 + 0.15 * (n % 40) as f64;
                sample(
                    move |t| ((3.0 * t + delta).sin(), (2.0 * t).sin()),
                    0.0,
                    TAU,
                )
            }
            Pattern::Rose => sample(
                |t| {
                    let r = (4.0 * t).cos();
                    (r * t.cos(), r * t.sin())
                },
                0.0,
                TAU,
            ),
            Pattern::Wave => {
                // Across on y = a·sin(3πx), back on y = -a·sin(3πx): a closed
                // braid, so the loop ends where it started.
                let a = 0.4;
                sample(
                    move |t| {
                        if t < PI {
                            let x = -1.0 + 2.0 * t / PI;
                            (x, a * (3.0 * PI * x).sin())
                        } else {
                            let x = 1.0 - 2.0 * (t - PI) / PI;
                            (x, -a * (3.0 * PI * x).sin())
                        }
                    },
                    0.0,
                    TAU,
                )
            }
            Pattern::Wander => return wander(n, seed),
        };
        Path::from_points(pts)
    }

    fn from_points(pts: Vec<(f64, f64)>) -> Path {
        let n = pts.len();
        let speed = vec![1.0; n];
        Path::with_speed(pts, speed, Vec::new())
    }

    fn with_speed(pts: Vec<(f64, f64)>, speed: Vec<f64>, rests: Vec<(f64, Duration)>) -> Path {
        let mut cum = Vec::with_capacity(pts.len());
        let mut acc = 0.0;
        for i in 0..pts.len() {
            if i > 0 {
                acc += dist(pts[i - 1], pts[i]);
            }
            cum.push(acc);
        }
        let total = acc + dist(pts[pts.len() - 1], pts[0]);
        Path {
            pts,
            cum,
            total: total.max(1e-9),
            speed,
            rests,
        }
    }

    /// Arc length of one loop, in unit space.
    pub fn total(&self) -> f64 {
        self.total
    }

    /// The point at arc position `s` (wraps around the loop).
    pub fn at(&self, s: f64) -> (f64, f64) {
        let s = s.rem_euclid(self.total);
        // Binary search the segment.
        let i = match self.cum.binary_search_by(|c| c.total_cmp(&s)) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let a = self.pts[i];
        let (b, seg_start, seg_len) = if i + 1 < self.pts.len() {
            (self.pts[i + 1], self.cum[i], self.cum[i + 1] - self.cum[i])
        } else {
            (self.pts[0], self.cum[i], self.total - self.cum[i])
        };
        if seg_len <= 1e-12 {
            return a;
        }
        let f = ((s - seg_start) / seg_len).clamp(0.0, 1.0);
        (a.0 + (b.0 - a.0) * f, a.1 + (b.1 - a.1) * f)
    }

    /// Speed multiplier at arc position `s` (Wander's uneven pace).
    pub fn speed_at(&self, s: f64) -> f64 {
        let s = s.rem_euclid(self.total);
        let i = match self.cum.binary_search_by(|c| c.total_cmp(&s)) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        self.speed[i.min(self.speed.len() - 1)]
    }

    /// A rest that starts in `(from, to]` (unwrapped positions within one
    /// loop), if any.
    pub fn rest_between(&self, from: f64, to: f64) -> Option<Duration> {
        self.rests
            .iter()
            .find(|(pos, _)| *pos > from && *pos <= to)
            .map(|(_, d)| *d)
    }

    /// The bounding box of the sampled curve.
    pub fn bounds(&self) -> Rect {
        let mut r = Rect::new(f64::MAX, f64::MAX, f64::MIN, f64::MIN);
        for p in &self.pts {
            r.x0 = r.x0.min(p.0);
            r.y0 = r.y0.min(p.1);
            r.x1 = r.x1.max(p.0);
            r.y1 = r.y1.max(p.1);
        }
        r
    }

    /// Arc position of the sampled point nearest `p`.
    pub fn nearest(&self, p: (f64, f64)) -> f64 {
        let mut best = (f64::MAX, 0.0);
        for (i, q) in self.pts.iter().enumerate() {
            let d = dist(*q, p);
            if d < best.0 {
                best = (d, self.cum[i]);
            }
        }
        best.1
    }
}

fn dist(a: (f64, f64), b: (f64, f64)) -> f64 {
    ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
}

/// Sample a parametric curve over `[t0, t1)` at [`SAMPLES`] points, then
/// renormalise into `[-1, 1]²` (aspect kept, centred).
fn sample(f: impl Fn(f64) -> (f64, f64), t0: f64, t1: f64) -> Vec<(f64, f64)> {
    let pts: Vec<(f64, f64)> = (0..SAMPLES)
        .map(|i| f(t0 + (t1 - t0) * i as f64 / SAMPLES as f64))
        .collect();
    normalise(pts)
}

fn regular(n: usize, phase: f64) -> Vec<(f64, f64)> {
    (0..n)
        .map(|k| {
            let a = phase + TAU * k as f64 / n as f64;
            (a.cos(), a.sin())
        })
        .collect()
}

/// A closed polygon through `v`, sampled so each edge gets points in
/// proportion to its length (keeps the arc table dense on long edges).
fn polygon(v: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let n = v.len();
    let lens: Vec<f64> = (0..n).map(|i| dist(v[i], v[(i + 1) % n])).collect();
    let total: f64 = lens.iter().sum();
    let mut pts = Vec::with_capacity(SAMPLES);
    for i in 0..n {
        let steps = ((lens[i] / total) * SAMPLES as f64).round().max(1.0) as usize;
        let (a, b) = (v[i], v[(i + 1) % n]);
        for k in 0..steps {
            let f = k as f64 / steps as f64;
            pts.push((a.0 + (b.0 - a.0) * f, a.1 + (b.1 - a.1) * f));
        }
    }
    normalise(pts)
}

fn normalise(pts: Vec<(f64, f64)>) -> Vec<(f64, f64)> {
    let (mut x0, mut y0, mut x1, mut y1) = (f64::MAX, f64::MAX, f64::MIN, f64::MIN);
    for p in &pts {
        x0 = x0.min(p.0);
        y0 = y0.min(p.1);
        x1 = x1.max(p.0);
        y1 = y1.max(p.1);
    }
    let (cx, cy) = ((x0 + x1) / 2.0, (y0 + y1) / 2.0);
    let half = ((x1 - x0).max(y1 - y0) / 2.0).max(1e-9);
    pts.into_iter()
        .map(|(x, y)| ((x - cx) / half, (y - cy) / half))
        .collect()
}

/// SplitMix64 — a tiny deterministic generator so a Wander loop can be
/// reproduced in a test from its seed, with no dependency.
struct Mix(u64);
impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `[lo, hi)`.
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A closed Catmull-Rom loop through six random waypoints; each leg gets
/// its own pace, and some waypoints a short rest — the "human" pattern.
fn wander(n: u64, seed: u64) -> Path {
    let mut rng = Mix(seed ^ n.wrapping_mul(0xA24B_AED4_963E_E407));
    const WAYPOINTS: usize = 6;
    let w: Vec<(f64, f64)> = (0..WAYPOINTS)
        .map(|_| (rng.range(-1.0, 1.0), rng.range(-1.0, 1.0)))
        .collect();
    let per_leg = SAMPLES / WAYPOINTS;
    let mut pts = Vec::with_capacity(SAMPLES);
    let mut leg_pace = Vec::with_capacity(WAYPOINTS);
    let mut rest_at_leg_end = Vec::with_capacity(WAYPOINTS);
    for _ in 0..WAYPOINTS {
        leg_pace.push(rng.range(0.6, 1.4));
        rest_at_leg_end.push(if rng.range(0.0, 1.0) < 0.35 {
            Some(Duration::from_millis(rng.range(250.0, 900.0) as u64))
        } else {
            None
        });
    }
    let mut speed = Vec::with_capacity(SAMPLES);
    for leg in 0..WAYPOINTS {
        let p0 = w[(leg + WAYPOINTS - 1) % WAYPOINTS];
        let p1 = w[leg];
        let p2 = w[(leg + 1) % WAYPOINTS];
        let p3 = w[(leg + 2) % WAYPOINTS];
        for k in 0..per_leg {
            let t = k as f64 / per_leg as f64;
            pts.push(catmull_rom(p0, p1, p2, p3, t));
            speed.push(leg_pace[leg]);
        }
    }
    let pts = normalise(pts);
    // Rests sit at the END of a leg = the START of the next one.
    let base = Path::with_speed(pts, speed, Vec::new());
    let rests = (0..WAYPOINTS)
        .filter_map(|leg| {
            rest_at_leg_end[leg].map(|d| {
                let idx = ((leg + 1) * per_leg) % (per_leg * WAYPOINTS);
                (base.cum[idx], d)
            })
        })
        .filter(|(pos, _)| *pos > 0.0)
        .collect::<Vec<_>>();
    let mut rests = rests;
    rests.sort_by(|a, b| a.0.total_cmp(&b.0));
    Path { rests, ..base }
}

fn catmull_rom(
    p0: (f64, f64),
    p1: (f64, f64),
    p2: (f64, f64),
    p3: (f64, f64),
    t: f64,
) -> (f64, f64) {
    let t2 = t * t;
    let t3 = t2 * t;
    let f = |a: f64, b: f64, c: f64, d: f64| {
        0.5 * ((2.0 * b)
            + (-a + c) * t
            + (2.0 * a - 5.0 * b + 4.0 * c - d) * t2
            + (-a + 3.0 * b - 3.0 * c + d) * t3)
    };
    (f(p0.0, p1.0, p2.0, p3.0), f(p0.1, p1.1, p2.1, p3.1))
}

// ─── Placement ──────────────────────────────────────────────────────────

/// A path placed on screen: `screen = centre + scale · unit`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Placement {
    pub cx: f64,
    pub cy: f64,
    pub scale: f64,
}

impl Placement {
    pub fn to_screen(&self, u: (f64, f64)) -> (f64, f64) {
        (self.cx + self.scale * u.0, self.cy + self.scale * u.1)
    }
    pub fn to_unit(&self, p: (f64, f64)) -> (f64, f64) {
        ((p.0 - self.cx) / self.scale, (p.1 - self.cy) / self.scale)
    }
}

/// Place `path` so it starts AT the cursor when that fits, else as close to
/// it as the safe box allows. Returns the placement and the arc position to
/// start from (the point nearest the anchor — where a short glide lands when
/// the anchor itself could not be on the curve).
pub fn place(path: &Path, anchor: (f64, f64), safe: Rect, size: Size) -> (Placement, f64) {
    let short = safe.w().min(safe.h());
    let b = path.bounds();
    let ext = (b.w().max(b.h()) / 2.0).max(1e-9);
    // Diameter = fraction × short side, never more than the box allows.
    let scale = ((size.fraction() * short) / 2.0 / ext)
        .min(short / 2.0 / ext)
        .max(1.0);
    // Start at s = 0 with the centre chosen to put that point on the anchor.
    let start = path.at(0.0);
    let cx = anchor.0 - scale * start.0;
    let cy = anchor.1 - scale * start.1;
    // Clamp so the whole bounding box stays inside.
    let cx = cx.clamp(safe.x0 - scale * b.x0, safe.x1 - scale * b.x1);
    let cy = cy.clamp(safe.y0 - scale * b.y0, safe.y1 - scale * b.y1);
    let pl = Placement { cx, cy, scale };
    let s0 = if dist(pl.to_screen(start), anchor) < 1.0 {
        0.0
    } else {
        path.nearest(pl.to_unit(anchor))
    };
    (pl, s0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_SHAPES: [Pattern; 11] = SHUFFLE_ORDER;

    /// FR-92 P10 — the LocalAPI's copy of the pattern names (what
    /// `roomler keep-busy on --pattern` offers) is exactly this list, in this
    /// order: the companion and the CLI cannot link the agent.
    #[test]
    fn the_localapi_pattern_list_is_ours() {
        let ours: Vec<&str> = Pattern::ALL.iter().map(|p| p.wire()).collect();
        assert_eq!(ours, tunnel_core::localapi::KEEP_BUSY_PATTERNS);
    }

    #[test]
    fn wire_names_round_trip_and_match_by_equality() {
        for p in Pattern::ALL {
            assert_eq!(Pattern::from_wire(p.wire()), Some(p));
        }
        // A prefix is not a match — the ssh / ssh-consent lesson.
        assert_eq!(Pattern::from_wire("circ"), None);
        assert_eq!(Pattern::from_wire("circle "), None);
        assert_eq!(Pattern::from_wire("Circle"), None);
        for s in [Size::S, Size::M, Size::L] {
            assert_eq!(Size::from_wire(s.wire()), Some(s));
        }
        for s in [Speed::Slow, Speed::Normal, Speed::Fast] {
            assert_eq!(Speed::from_wire(s.wire()), Some(s));
        }
    }

    #[test]
    fn every_shape_is_normalised_into_the_unit_box() {
        for shape in ALL_SHAPES {
            for n in 0..3 {
                let p = Path::for_shape(shape, n, 7);
                let b = p.bounds();
                assert!(
                    b.x0 >= -1.0 - 1e-9 && b.x1 <= 1.0 + 1e-9,
                    "{shape:?} x out of the unit box: {b:?}"
                );
                assert!(
                    b.y0 >= -1.0 - 1e-9 && b.y1 <= 1.0 + 1e-9,
                    "{shape:?} y out of the unit box: {b:?}"
                );
                // And it is not degenerate.
                assert!(
                    b.w().max(b.h()) > 1.9,
                    "{shape:?} does not fill the box: {b:?}"
                );
            }
        }
    }

    /// A loop ends where it starts — the pointer never jumps from the end of
    /// one loop to the start of the next.
    #[test]
    fn every_loop_is_closed_and_continuous() {
        for shape in ALL_SHAPES {
            let p = Path::for_shape(shape, 1, 42);
            let total = p.total();
            let a = p.at(0.0);
            let b = p.at(total - 1e-9);
            assert!(
                dist(a, b) < 0.05,
                "{shape:?} does not close: {a:?} vs {b:?}"
            );
            // Continuity: a step of 1/1000 of the loop never moves more than
            // a sliver of the box.
            let step = total / 1000.0;
            for k in 0..1000 {
                let s = k as f64 * step;
                let d = dist(p.at(s), p.at(s + step));
                assert!(
                    d <= step * 1.0001 + 1e-9,
                    "{shape:?} jumps at s={s}: {d} > {step}"
                );
            }
        }
    }

    /// Walking by arc length is constant speed: equal arc steps are equal
    /// chord steps (up to the curvature within one tiny step).
    #[test]
    fn arc_length_walk_is_constant_speed() {
        for shape in [
            Pattern::Circle,
            Pattern::Heart,
            Pattern::Spirograph,
            Pattern::Star,
        ] {
            let p = Path::for_shape(shape, 0, 1);
            let step = p.total() / 2000.0;
            let mut min = f64::MAX;
            let mut max: f64 = 0.0;
            for k in 0..2000 {
                let s = k as f64 * step;
                let d = dist(p.at(s), p.at(s + step));
                min = min.min(d);
                max = max.max(d);
            }
            // Corners (star) shorten a chord; never by more than half.
            assert!(
                min > 0.5 * step,
                "{shape:?} stalls: min chord {min} vs step {step}"
            );
            assert!(max <= step * 1.0001, "{shape:?} overshoots: {max}");
        }
    }

    #[test]
    fn wander_is_deterministic_per_seed_and_fresh_per_loop() {
        let a = Path::for_shape(Pattern::Wander, 3, 99);
        let b = Path::for_shape(Pattern::Wander, 3, 99);
        let c = Path::for_shape(Pattern::Wander, 4, 99);
        assert_eq!(a.at(0.3), b.at(0.3));
        assert_ne!(a.at(0.3), c.at(0.3));
        // Its pace varies and stays in a human range.
        let paces: Vec<f64> = (0..50)
            .map(|k| a.speed_at(k as f64 * a.total() / 50.0))
            .collect();
        assert!(paces.iter().all(|v| (0.6..=1.4).contains(v)));
    }

    #[test]
    fn shuffle_walks_every_visible_pattern_and_never_subtle() {
        let seen: std::collections::HashSet<Pattern> = (0..SHUFFLE_ORDER.len() as u64)
            .map(|n| Pattern::Shuffle.shape_for_loop(n))
            .collect();
        assert_eq!(seen.len(), SHUFFLE_ORDER.len());
        assert!(!seen.contains(&Pattern::Subtle));
        assert!(!seen.contains(&Pattern::Shuffle));
        assert_eq!(Pattern::Circle.shape_for_loop(5), Pattern::Circle);
    }

    fn screen() -> (Rect, Rect) {
        // A 1920×1080 monitor with a 40 px taskbar at the bottom.
        (
            Rect::new(0.0, 0.0, 1920.0, 1080.0),
            Rect::new(0.0, 0.0, 1920.0, 1040.0),
        )
    }

    #[test]
    fn safe_box_keeps_out_of_every_edge_and_the_taskbar() {
        let (mon, work) = screen();
        let b = safe_box(mon, work).unwrap();
        assert_eq!(b.x0, EDGE_INSET_PX);
        assert_eq!(b.y0, EDGE_INSET_PX);
        assert_eq!(b.x1, 1920.0 - EDGE_INSET_PX);
        // The work area's bottom (1040) is above the inset line (1032)? No —
        // 1080 - 48 = 1032 is tighter than 1040, so the inset wins.
        assert_eq!(b.y1, 1080.0 - EDGE_INSET_PX);
        // A tall taskbar wins over the inset.
        let b2 = safe_box(mon, Rect::new(0.0, 0.0, 1920.0, 980.0)).unwrap();
        assert_eq!(b2.y1, 980.0);
        // A display too small to hold anything says so.
        assert!(
            safe_box(
                Rect::new(0.0, 0.0, 100.0, 100.0),
                Rect::new(0.0, 0.0, 100.0, 100.0)
            )
            .is_none()
        );
    }

    /// The whole loop stays inside the safe box, for every shape, size and
    /// anchor — including an anchor jammed into a corner.
    #[test]
    fn placed_paths_never_leave_the_safe_box() {
        let (mon, work) = screen();
        let safe = safe_box(mon, work).unwrap();
        let anchors = [
            (960.0, 520.0),
            (0.0, 0.0),
            (1919.0, 0.0),
            (0.0, 1079.0),
            (1919.0, 1079.0),
            (60.0, 900.0),
        ];
        for shape in ALL_SHAPES {
            let path = Path::for_shape(shape, 2, 5);
            for size in [Size::S, Size::M, Size::L] {
                for anchor in anchors {
                    let (pl, _) = place(&path, anchor, safe, size);
                    for k in 0..400 {
                        let p = pl.to_screen(path.at(k as f64 * path.total() / 400.0));
                        assert!(
                            safe.contains((p.0.round(), p.1.round())) || safe.contains(p),
                            "{shape:?}/{size:?} from {anchor:?} leaves the box at {p:?} ({safe:?})"
                        );
                    }
                }
            }
        }
    }

    /// With room around it, the loop starts exactly at the cursor — resuming
    /// never makes the pointer jump.
    #[test]
    fn with_room_the_loop_starts_at_the_cursor() {
        let (mon, work) = screen();
        let safe = safe_box(mon, work).unwrap();
        for shape in ALL_SHAPES {
            let path = Path::for_shape(shape, 0, 3);
            let anchor = (960.0, 520.0);
            let (pl, s0) = place(&path, anchor, safe, Size::M);
            assert_eq!(s0, 0.0, "{shape:?}");
            let first = pl.to_screen(path.at(s0));
            assert!(dist(first, anchor) < 1.0, "{shape:?} starts at {first:?}");
        }
    }

    /// Jammed in a corner, the loop is pushed inside and starts at the point
    /// nearest the cursor — the engine glides there.
    #[test]
    fn in_a_corner_the_loop_starts_nearest_the_cursor() {
        let (mon, work) = screen();
        let safe = safe_box(mon, work).unwrap();
        let path = Path::for_shape(Pattern::Circle, 0, 0);
        let anchor = (5.0, 5.0);
        let (pl, s0) = place(&path, anchor, safe, Size::M);
        let start = pl.to_screen(path.at(s0));
        // The nearest point of a circle pushed into the top-left corner is
        // its top-left arc.
        assert!(
            start.0 < pl.cx && start.1 < pl.cy,
            "{start:?} vs centre ({}, {})",
            pl.cx,
            pl.cy
        );
        assert!(safe.contains(start));
    }

    #[test]
    fn size_scales_the_shape() {
        let (mon, work) = screen();
        let safe = safe_box(mon, work).unwrap();
        let path = Path::for_shape(Pattern::Circle, 0, 0);
        let (s, _) = place(&path, (960.0, 520.0), safe, Size::S);
        let (m, _) = place(&path, (960.0, 520.0), safe, Size::M);
        let (l, _) = place(&path, (960.0, 520.0), safe, Size::L);
        assert!(s.scale < m.scale && m.scale < l.scale);
        let short = safe.w().min(safe.h());
        assert!((m.scale * 2.0 - Size::M.fraction() * short).abs() < 1.0);
    }
}
