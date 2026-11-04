// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Deterministic synthetic frame source for headless CI / Linux Pods.
//!
//! Emits a BGRA frame (320×240 unless told otherwise) at the requested fps
//! cap with a slow horizontal-gradient + frame-counter overlay so an encoder
//! sees real pixel deltas (not a constant black image — which several SW
//! encoders optimise into zero-byte skip frames, defeating the whole point
//! of exercising the encode pipeline in a test).
//!
//! Why a separate backend instead of running Xvfb in the Pod:
//! * Zero system deps — no `xvfb`, `xterm`, `libxcb*`. The agent-e2e
//!   Docker image stays under 100 MiB instead of dragging the X11
//!   stack in.
//! * Deterministic — the same frame counter produces the same pixels.
//!   Test assertions on `framesDecoded ≥ N` (Phase 2) have a fixed
//!   reference instead of whatever Xvfb's `xterm` happened to paint.
//! * No SCM-context surprise: `scrap` on Linux talks to an X server,
//!   which inside a Pod means `Xvfb :99` running on the same Pod.
//!   `synthetic` just produces bytes — no display dependency at all.
//!
//! Selected by setting `ROOMLERD_SYNTHETIC_FRAMES=1` at runtime
//! AND building with the `synthetic-frame-source` feature. Production
//! agents (`full`, `full-hw` feature sets) never opt in.
//!
//! ## FR-16 L0/L4 — the latency bench
//!
//! Every frame also carries a [`marker`]: its sequence number painted as
//! 16×16 luma blocks that survive 4:2:0, a high QP and a 4× downscale, read
//! back from the DECODED picture. The instant each frame was captured is kept
//! in [`clock`], so a test in the same process measures capture→decode on ONE
//! clock. The knobs, all read per session:
//!
//! | Env | Effect |
//! |---|---|
//! | `ROOMLERD_SYNTHETIC_SIZE=WxH` | frame size (even, 64×64 … 3840×2160); default 320×240 |
//! | `ROOMLERD_BENCH=1` | bench mode: the fps clamp rises from 60 to 240, and the gate below is honoured |
//! | `ROOMLERD_SYNTHETIC_GATE_MS=N` | bench only: hold each frame N ms after it is stamped, a planted capture-stage delay. The L0 test's negative control: a harness that cannot see it is not measuring latency |
//!
//! FR-98 C1: [`set_test_compositor`] (a test hook, bench mode only) makes
//! the source emulate an event-driven backend, frames landing on their own
//! clock behind the capture gate WGC would run (`capture::gate`), and the
//! clock then records when a frame LANDED, so L0 sees what the gate costs.

use crate::capture::{Damage, DirtyRect, DownscalePolicy, Frame, PixelFormat, ScreenCapture};
use anyhow::Result;
use std::time::{Duration, Instant};
use tunnel_core::env::node_env;

/// Default synthetic frame dimensions. Small enough that openh264 encodes
/// each frame in <5 ms on a 2-vCPU CI runner; large enough that the
/// resulting H.264 bitstream is meaningfully testable.
pub const FRAME_W: u32 = 320;
pub const FRAME_H: u32 = 240;
pub const FRAME_STRIDE: u32 = FRAME_W * 4; // BGRA = 4 bytes/pixel

/// Default frame cadence — 15 fps is plenty for a smoke test and
/// keeps CPU low under CI's vCPU constraints.
pub const DEFAULT_FPS: u32 = 15;

/// The fps clamp outside bench mode, and inside it.
const MAX_FPS: u32 = 60;
const MAX_FPS_BENCH: u32 = 240;

/// The largest synthetic frame (`ROOMLERD_SYNTHETIC_SIZE`).
const MAX_W: u32 = 3840;
const MAX_H: u32 = 2160;
const MIN_SIDE: u32 = 64;

pub struct SyntheticCapture {
    /// Wall-clock frame interval (1 / fps).
    interval: Duration,
    /// Start instant — `next_frame` computes a per-frame deadline as
    /// `start + (counter * interval)` and sleeps until then. This
    /// matches scrap_backend's "rate-limit so we don't burn CPU"
    /// posture.
    start: Instant,
    /// Monotonically increasing frame counter — also painted into
    /// the frame (small pixel-pattern in the top-left) so tests
    /// asserting "we got frame N" have a deterministic reference.
    counter: u64,
    width: u32,
    height: u32,
    /// FR-16 L0 — a planted delay between stamping a frame and handing it
    /// over (bench mode only). Zero in every real run.
    gate: Duration,
    /// FR-98 C1 — an emulated event-driven source behind a capture gate,
    /// set by a test (bench mode only). `None` in every real run.
    compositor: Option<Compositor>,
    /// #2284 — the gaps between frames, repeated, in place of `interval`
    /// (bench mode only). `None` in every real run.
    cadence: Option<&'static [Duration]>,
}

/// FR-98 C1 — what a test asks the synthetic source to emulate: a source
/// that delivers frames on its own clock, the way WGC's `FrameArrived` does,
/// read through the gate the WGC backend would run.
#[derive(Debug, Clone, Copy)]
pub struct TestCompositor {
    /// The emulated source's rate (a compositor's refresh).
    pub source_fps: u32,
    /// The rate the gate caps at, in place of the pump's target, so a test
    /// can pick one whose legacy period is a whole number of milliseconds.
    pub target_fps: u32,
    /// How far ahead of the legacy gate's cadence each frame lands, as a
    /// fraction of a period: 0 = on it, 0.75 = three quarters early.
    pub lead: f64,
    pub gate: super::gate::GateMode,
}

static TEST_COMPOSITOR: std::sync::Mutex<Option<TestCompositor>> = std::sync::Mutex::new(None);

/// Set (or clear) the emulated source every NEW synthetic session uses.
/// Honoured in bench mode only.
pub fn set_test_compositor(c: Option<TestCompositor>) {
    *TEST_COMPOSITOR.lock().unwrap_or_else(|p| p.into_inner()) = c;
}

/// The emulated source and its gate. Frame 0 is waiting when the first
/// call comes; frame `k ≥ 1` lands at `first + (k − lead) × period`, and the
/// slot holds only the newest frame, as WGC's does.
struct Compositor {
    period: Duration,
    lead: f64,
    first: Option<Instant>,
    taken: Option<u64>,
    gate: EmulatedGate,
}

enum EmulatedGate {
    /// `wgc_backend.rs`'s legacy rule, the same shape: sleep out the rest of
    /// a whole-millisecond period since the last call, then look at the slot.
    Legacy {
        period: Duration,
        last_call: Option<Instant>,
    },
    SlotFirst(super::gate::SlotFirst),
}

impl Compositor {
    fn new(c: TestCompositor) -> Self {
        let gate = match c.gate {
            super::gate::GateMode::Legacy => EmulatedGate::Legacy {
                period: Duration::from_millis(1000 / u64::from(c.target_fps.max(1))),
                last_call: None,
            },
            super::gate::GateMode::SlotFirst => {
                EmulatedGate::SlotFirst(super::gate::SlotFirst::new(c.target_fps))
            }
        };
        Self {
            period: Duration::from_micros(1_000_000 / u64::from(c.source_fps.max(1))),
            lead: c.lead.clamp(0.0, 0.99),
            first: None,
            taken: None,
            gate,
        }
    }

    fn arrival(period: Duration, lead: f64, first: Instant, k: u64) -> Instant {
        if k == 0 {
            first
        } else {
            first + period.mul_f64(k as f64 - lead)
        }
    }

    /// The newest frame that has landed by `t`.
    fn newest(period: Duration, lead: f64, first: Instant, t: Instant) -> u64 {
        let since = t.saturating_duration_since(first).as_secs_f64() / period.as_secs_f64();
        (since + lead).floor().max(0.0) as u64
    }

    /// Wait for the frame the gate hands out next; return its index and the
    /// instant it landed in the slot.
    ///
    /// A frame already in the slot landed at its scheduled arrival, and any
    /// wait since then is the gate's. When the slot is empty the frame is
    /// waited for, and it lands when that wait ends: WGC wakes the reader on
    /// `FrameArrived` itself, so the timer that stands in for that event
    /// here must not count its own overshoot (up to a timer tick on Windows)
    /// against either gate.
    async fn next(&mut self) -> (u64, Instant) {
        let (period, lead) = (self.period, self.lead);
        let first = *self.first.get_or_insert_with(Instant::now);
        let next = self.taken.map_or(0, |k| k + 1);
        let next_at = Self::arrival(period, lead, first, next);
        // The emulated `FrameArrived`: returns when the frame landed.
        let wait_for_frame = || async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(next_at)).await;
            Instant::now()
        };
        let (k, landed) = match &mut self.gate {
            EmulatedGate::Legacy {
                period: gp,
                last_call,
            } => {
                if let Some(last) = *last_call {
                    let elapsed = last.elapsed();
                    if elapsed < *gp {
                        tokio::time::sleep(*gp - elapsed).await;
                    }
                }
                *last_call = Some(Instant::now());
                let now = Instant::now();
                if next_at <= now {
                    let k = Self::newest(period, lead, first, now).max(next);
                    (k, Self::arrival(period, lead, first, k))
                } else {
                    (next, wait_for_frame().await)
                }
            }
            EmulatedGate::SlotFirst(gate) => {
                let woke = if next_at > Instant::now() {
                    Some(wait_for_frame().await)
                } else {
                    None
                };
                let wait = gate.wait(Instant::now());
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
                let now = Instant::now();
                gate.took(now);
                // The newest frame now: a fresher one may have landed while
                // the gate paced the source.
                let k = Self::newest(period, lead, first, now).max(next);
                let landed = match woke {
                    Some(at) if k == next => at,
                    _ => Self::arrival(period, lead, first, k),
                };
                (k, landed)
            }
        };
        self.taken = Some(k);
        (k, landed)
    }
}

/// #2284 — a repeating pattern of gaps between frames, set by a test (bench
/// mode only). Damage-driven frames come a few at a time and then pause, and
/// a source at a fixed rate cannot show a timestamp that lags one frame:
/// every gap is the same, so the previous one is right too.
static TEST_CADENCE: std::sync::Mutex<Option<&'static [Duration]>> = std::sync::Mutex::new(None);

/// Set (or clear) the cadence every NEW synthetic session uses. Honoured in
/// bench mode only, and ignored when a test compositor is set.
pub fn set_test_cadence(gaps: Option<&'static [Duration]>) {
    *TEST_CADENCE.lock().unwrap_or_else(|p| p.into_inner()) = gaps.filter(|g| !g.is_empty());
}

/// Where frame `k` falls on a repeating pattern of gaps: frame 0 at once,
/// frame `k` after the first `k` gaps of the pattern repeated.
fn cadence_offset(gaps: &[Duration], k: u64) -> Duration {
    let n = gaps.len() as u64;
    let round: Duration = gaps.iter().sum();
    round * (k / n) as u32 + gaps[..(k % n) as usize].iter().sum::<Duration>()
}

/// L0's planted gate, set by a test in the same process (µs; bench mode
/// only). An env var cannot carry it: the gate changes between cells of one
/// test binary, and changing the environment while webrtc's threads run is
/// unsound.
static TEST_GATE_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Set (or clear, with zero) the planted capture-stage delay every NEW
/// synthetic session uses. Honoured in bench mode only, like
/// `ROOMLERD_SYNTHETIC_GATE_MS`, which it overrides.
pub fn set_test_gate(gate: Duration) {
    TEST_GATE_US.store(
        gate.as_micros().min(5_000_000) as u64,
        std::sync::atomic::Ordering::Release,
    );
}

/// `ROOMLERD_BENCH` — truthy the way every other agent switch is.
fn bench_enabled() -> bool {
    matches!(
        node_env("BENCH").as_deref().map(str::trim),
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
    )
}

/// `WxH`, both even and in range, or `None` (the caller keeps the default).
fn parse_size(raw: &str) -> Option<(u32, u32)> {
    let (w, h) = raw.trim().split_once(['x', 'X'])?;
    let w: u32 = w.trim().parse().ok()?;
    let h: u32 = h.trim().parse().ok()?;
    if !(MIN_SIDE..=MAX_W).contains(&w) || !(MIN_SIDE..=MAX_H).contains(&h) {
        return None;
    }
    // Every encoder this source feeds wants 4:2:0-friendly even sides.
    Some((w & !1, h & !1))
}

impl SyntheticCapture {
    pub fn new(target_fps: u32) -> Self {
        let bench = bench_enabled();
        let fps = target_fps.clamp(1, if bench { MAX_FPS_BENCH } else { MAX_FPS });
        let (width, height) = node_env("SYNTHETIC_SIZE")
            .as_deref()
            .and_then(parse_size)
            .unwrap_or((FRAME_W, FRAME_H));
        let gate = if bench {
            match TEST_GATE_US.load(std::sync::atomic::Ordering::Acquire) {
                0 => node_env("SYNTHETIC_GATE_MS")
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(|ms| Duration::from_millis(ms.min(5_000)))
                    .unwrap_or(Duration::ZERO),
                us => Duration::from_micros(us),
            }
        } else {
            Duration::ZERO
        };
        let compositor = if bench {
            TEST_COMPOSITOR
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .map(Compositor::new)
        } else {
            None
        };
        let cadence = if bench {
            *TEST_CADENCE.lock().unwrap_or_else(|p| p.into_inner())
        } else {
            None
        };
        Self {
            interval: Duration::from_micros(1_000_000 / fps as u64),
            start: Instant::now(),
            counter: 0,
            width,
            height,
            gate,
            compositor,
            cadence,
        }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// Render a single default-size BGRA frame for the given counter value.
    /// Pure over the input — same counter always produces identical bytes.
    pub fn render(counter: u64) -> Vec<u8> {
        Self::render_sized(counter, FRAME_W, FRAME_H)
    }

    /// [`Self::render`] at any size. Pattern: horizontal gradient that shifts
    /// one pixel per frame, plus a 64-pixel "counter strip" in the top-left
    /// where each pixel column encodes one bit of the counter, plus the L4
    /// [`marker`] in the bottom-left.
    pub fn render_sized(counter: u64, width: u32, height: u32) -> Vec<u8> {
        Self::render_frame(counter, width, height, None)
    }

    /// [`Self::render_sized`], plus the last bench probe in the bottom-right
    /// marker when there is one (FR-16 L4). Pure over its inputs.
    pub fn render_frame(counter: u64, width: u32, height: u32, probe: Option<u16>) -> Vec<u8> {
        let mut data = vec![0u8; (width * height * 4) as usize];
        let shift = (counter % width as u64) as u32;
        for y in 0..height {
            for x in 0..width {
                let i = ((y * width + x) * 4) as usize;
                let gx = (x + shift) % width;
                // Diagonal gradient that wraps — the shift gives motion.
                let r = ((gx * 255) / width) as u8;
                let g = ((y * 255) / height) as u8;
                let b = (((gx + y) * 127) / (width + height)) as u8;
                // BGRA byte order.
                data[i] = b;
                data[i + 1] = g;
                data[i + 2] = r;
                data[i + 3] = 0xFF;
            }
        }
        // Counter strip: top-left 64×4 pixels, white = 1 bit, black = 0.
        // 64 bits of counter, MSB at x=0. A test that wants the
        // counter back reads the top-left 64 pixels' B channel.
        for bit in 0..64u32.min(width) {
            let on = (counter >> (63 - bit)) & 1 == 1;
            let colour = if on { 0xFF } else { 0x00 };
            for y in 0..4u32.min(height) {
                let i = ((y * width + bit) * 4) as usize;
                data[i] = colour;
                data[i + 1] = colour;
                data[i + 2] = colour;
                data[i + 3] = 0xFF;
            }
        }
        marker::paint_bgra(&mut data, width, height, width * 4, marker::seq_of(counter));
        if let Some(seq) = probe {
            marker::paint_bgra_at(
                marker::Corner::BottomRight,
                &mut data,
                width,
                height,
                width * 4,
                seq,
            );
        }
        data
    }
}

#[async_trait::async_trait]
impl ScreenCapture for SyntheticCapture {
    async fn next_frame(&mut self) -> Result<Option<Frame>> {
        let (data, captured) = if let Some(c) = self.compositor.as_mut() {
            // FR-98 C1 — an emulated event-driven source: the clock records
            // when the frame LANDED in the slot, so L0's number includes
            // whatever the gate made it wait.
            let (k, landed) = c.next().await;
            self.counter = k;
            let data = Self::render_frame(k, self.width, self.height, probe::latest());
            (data, landed)
        } else {
            // Sleep until this frame's nominal emission time. Computed
            // from the start instant + counter * interval so we don't
            // drift on a host where the encoder takes variable time per
            // frame (the deadline stays anchored to wall-clock, not to
            // "previous frame returned at X").
            let deadline = self.start
                + match self.cadence {
                    Some(gaps) => cadence_offset(gaps, self.counter),
                    None => self.interval * (self.counter as u32),
                };
            let now = Instant::now();
            if deadline > now {
                tokio::time::sleep(deadline - now).await;
            }
            let data = Self::render_frame(self.counter, self.width, self.height, probe::latest());
            // L0 — the capture instant, for a same-process test to read back
            // by the sequence number the marker carries.
            (data, Instant::now())
        };
        clock::record(marker::seq_of(self.counter), captured);
        if !self.gate.is_zero() {
            tokio::time::sleep(self.gate).await;
        }
        let frame = Frame {
            width: self.width,
            height: self.height,
            stride: self.width * 4,
            pixel_format: PixelFormat::Bgra,
            data,
            monotonic_us: (captured - self.start).as_micros() as u64,
            monitor: 0,
            // P8a — the shifting gradient repaints EVERY pixel each
            // frame, so the honest tracked damage is the full frame.
            // Also serves as the e2e oracle for the tracked path.
            damage: Damage::Tracked(vec![DirtyRect {
                x: 0,
                y: 0,
                w: self.width,
                h: self.height,
            }]),
            source: None,
        };
        self.counter += 1;
        Ok(Some(frame))
    }

    fn monitor_count(&self) -> u8 {
        1
    }

    /// FR-119 P2b. The pace stays the open's (`set_target_fps` is the
    /// default): a test that wants another rate opens the source at it.
    fn backend(&self) -> &'static str {
        "synthetic"
    }
}

/// Construct the synthetic capture honouring the same `target_fps` +
/// `_downscale` plumbing as scrap_backend / wgc_backend. Downscale is
/// ignored — the synthetic frames are sized by `ROOMLERD_SYNTHETIC_SIZE`.
pub fn primary(target_fps: u32, _downscale: DownscalePolicy) -> SyntheticCapture {
    SyntheticCapture::new(target_fps)
}

/// FR-16 L4 — the frame marker, now `capture::bench_marker` so release builds
/// (`roomlerd probe-target`) can paint it too. Re-exported under its old path.
pub use super::bench_marker as marker;

/// Is this process a bench target: the synthetic source selected AND bench
/// mode on? What the hello advertises as `bench` in `AgentCaps.video`, so a
/// viewer turns its probes on only where they mean something.
pub fn bench_active() -> bool {
    bench_enabled() && super::synthetic_env_enabled()
}

/// FR-16 L4 — the bench probe. A viewer in bench mode sends
/// `{"t":"probe","seq":N}` on the input DataChannel; the synthetic source
/// paints the last `N` it saw into the bottom-right [`marker`] of every frame
/// that follows, and the viewer times send → first decoded frame carrying
/// `N`. That is input to photon through the real pipeline, minus only the
/// host's own input stack, which `roomlerd probe-target` covers.
///
/// A probe never reaches an injector. Outside bench mode it is consumed and
/// dropped.
pub mod probe {
    use std::sync::atomic::{AtomicU32, Ordering};

    const NONE: u32 = u32::MAX;
    static LATEST: AtomicU32 = AtomicU32::new(NONE);

    /// Is `text` a probe? If it is, it is consumed here, recorded when bench
    /// mode is on, and the caller must not treat it as input.
    pub fn accept_json(text: &str) -> bool {
        // Every input message passes through here: a substring check first,
        // so pointer moves never pay for a second JSON parse.
        if !text.contains("\"probe\"") {
            return false;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
            return false;
        };
        if v.get("t").and_then(|t| t.as_str()) != Some("probe") {
            return false;
        }
        if super::bench_enabled()
            && let Some(seq) = v.get("seq").and_then(|s| s.as_u64())
        {
            LATEST.store((seq & 0x0FFF) as u32, Ordering::Release);
        }
        true
    }

    /// The last probe recorded, if any.
    pub fn latest() -> Option<u16> {
        match LATEST.load(Ordering::Acquire) {
            NONE => None,
            v => Some(v as u16),
        }
    }
}

/// FR-16 L0 — when each sequence number was captured, so a test in the same
/// process reads capture→decode latency on one clock. A ring of 4096 slots
/// indexed by the 12-bit sequence: at 30 fps that is 136 s before a slot is
/// reused, far longer than any frame stays in flight.
pub mod clock {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::{Duration, Instant};

    const SLOTS: usize = 4096;
    const EMPTY: i64 = i64::MIN;
    /// Signed microseconds from [`epoch`]. Signed, because the epoch is set
    /// on first use, which can come after the first instant handed in.
    static STAMPS: [AtomicI64; SLOTS] = [const { AtomicI64::new(EMPTY) }; SLOTS];

    fn epoch() -> Instant {
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        *EPOCH.get_or_init(Instant::now)
    }

    /// Record that `seq` was captured at `at`.
    pub fn record(seq: u16, at: Instant) {
        let e = epoch();
        let us = if at >= e {
            (at - e).as_micros() as i64
        } else {
            -((e - at).as_micros() as i64)
        };
        STAMPS[seq as usize % SLOTS].store(us, Ordering::Release);
    }

    /// When `seq` was last captured, if ever.
    pub fn captured_at(seq: u16) -> Option<Instant> {
        let us = STAMPS[seq as usize % SLOTS].load(Ordering::Acquire);
        if us == EMPTY {
            return None;
        }
        let e = epoch();
        Some(if us >= 0 {
            e + Duration::from_micros(us as u64)
        } else {
            e - Duration::from_micros(us.unsigned_abs())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2284: the cadence repeats, frame 0 comes at once, and frame `k`
    /// waits out the first `k` gaps.
    #[test]
    fn a_cadence_repeats_its_gaps() {
        const G: [Duration; 3] = [
            Duration::from_millis(33),
            Duration::from_millis(33),
            Duration::from_millis(200),
        ];
        let at = |k| cadence_offset(&G, k).as_millis();
        assert_eq!(
            [at(0), at(1), at(2), at(3), at(4), at(6)],
            [0, 33, 66, 266, 299, 532]
        );
    }

    #[test]
    fn render_emits_320x240_bgra() {
        let data = SyntheticCapture::render(0);
        assert_eq!(data.len(), (FRAME_W * FRAME_H * 4) as usize);
        // Alpha channel must be full.
        for chunk in data.chunks(4) {
            assert_eq!(chunk[3], 0xFF);
        }
    }

    #[test]
    fn render_is_deterministic_for_same_counter() {
        // Pure-over-counter contract: a test asserting "we got frame
        // N" needs the same bytes every time. A regression that
        // accidentally pulled in `rand::random()` for noise would
        // break this.
        let a = SyntheticCapture::render(42);
        let b = SyntheticCapture::render(42);
        assert_eq!(a, b);
    }

    #[test]
    fn consecutive_frames_differ() {
        // The shift-per-frame gives the encoder real pixel delta to
        // chew on. A regression that pinned `shift = 0` would yield
        // identical consecutive frames and an SW encoder would emit
        // zero-byte skip frames after the first IDR — defeating the
        // whole point of synthetic capture in CI.
        let f0 = SyntheticCapture::render(0);
        let f1 = SyntheticCapture::render(1);
        assert_ne!(f0, f1);
    }

    #[test]
    fn counter_strip_round_trips_via_b_channel() {
        // Decode the top-left strip and confirm it represents the
        // counter we passed in. Tests can rely on this to assert
        // frame ordering even after the bitstream has been encoded
        // + decoded round-trip.
        let counter: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let data = SyntheticCapture::render(counter);
        let mut recovered: u64 = 0;
        for bit in 0..64u32 {
            // Top-left row 0, column = bit. B channel is byte 0 of
            // the BGRA quad.
            let i = (bit * 4) as usize; // row 0 — offset is just column×4
            if data[i] == 0xFF {
                recovered |= 1 << (63 - bit);
            }
        }
        assert_eq!(recovered, counter);
    }

    #[test]
    fn monitor_count_is_one() {
        let cap = SyntheticCapture::new(15);
        assert_eq!(cap.monitor_count(), 1);
    }

    #[tokio::test]
    async fn next_frame_returns_a_full_size_frame() {
        let mut cap = SyntheticCapture::new(60); // fast for the test
        let f = cap
            .next_frame()
            .await
            .expect("no error")
            .expect("a frame, not None");
        assert_eq!(f.width, FRAME_W);
        assert_eq!(f.height, FRAME_H);
        assert_eq!(f.stride, FRAME_STRIDE);
        assert_eq!(f.pixel_format, PixelFormat::Bgra);
        assert_eq!(f.data.len(), (FRAME_W * FRAME_H * 4) as usize);
        assert_eq!(f.monitor, 0);
    }

    #[tokio::test]
    async fn fps_is_approximately_honoured() {
        // Rate-limit contract: 30 fps means ~33 ms between frames.
        // We don't pin tightly because CI vCPU jitter can shave/pad
        // by a few ms; ≥20 ms between two consecutive frames is the
        // smallest interval that proves we're not just emitting
        // them as fast as possible.
        let mut cap = SyntheticCapture::new(30);
        let _ = cap.next_frame().await.unwrap();
        let t0 = Instant::now();
        let _ = cap.next_frame().await.unwrap();
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(20),
            "expected ≥20 ms between frames at 30 fps; got {elapsed:?}"
        );
    }

    #[test]
    fn parse_size_accepts_even_in_range_and_refuses_the_rest() {
        assert_eq!(parse_size("640x360"), Some((640, 360)));
        assert_eq!(parse_size(" 1280X720 "), Some((1280, 720)));
        // Odd sides round down to even.
        assert_eq!(parse_size("641x361"), Some((640, 360)));
        assert_eq!(parse_size("32x32"), None);
        assert_eq!(parse_size("7680x4320"), None);
        assert_eq!(parse_size("wide"), None);
        assert_eq!(parse_size("640"), None);
    }

    #[test]
    fn crc4_matches_the_itu_polynomial() {
        // Hand-computed reference points for x⁴ + x + 1, init 0.
        assert_eq!(marker::crc4(0x000), 0x0);
        assert_eq!(marker::crc4(0x001), 0x3);
        // x¹¹·x⁴ = x¹⁵ ≡ 1: x has order 15 modulo this primitive polynomial.
        assert_eq!(marker::crc4(0x800), 0x1);
        // Every 1-bit error in the sequence changes the CRC.
        for s in [0x000u16, 0x123, 0xABC, 0xFFF] {
            for b in 0..12 {
                assert_ne!(
                    marker::crc4(s),
                    marker::crc4(s ^ (1 << b)),
                    "seq {s:#x} bit {b}"
                );
            }
        }
    }

    #[test]
    fn the_words_the_browser_decoder_pins_too() {
        // `ui/src/__tests__/workers/rcBenchMarker.spec.ts` pins the same
        // table against the browser's decoder: if either side drifts, one
        // of the two suites fails.
        for (seq, word) in [
            (0x000u16, 0x0000u16),
            (0x001, 0x0013),
            (0x800, 0x8001),
            (0x123, 0x1230),
            (0x5A5, 0x5A5D),
            (0xABC, 0xABCA),
            (0xFFF, 0xFFFE),
        ] {
            assert_eq!(marker::word(seq), word, "seq {seq:#05x}");
        }
        assert_eq!(
            (marker::BLOCK, marker::COLS, marker::ROWS, marker::MARGIN),
            (16, 8, 2, 8)
        );
    }

    /// The BT.601 limited-range luma of a BGRA pixel, as an encoder computes it.
    fn luma_of(bgra: &[u8], w: u32, h: u32) -> Vec<u8> {
        let mut y = vec![0u8; (w * h) as usize];
        for (i, px) in bgra.chunks_exact(4).enumerate() {
            let (b, g, r) = (px[0] as u32, px[1] as u32, px[2] as u32);
            y[i] = (16 + (66 * r + 129 * g + 25 * b + 128) / 256) as u8;
        }
        y
    }

    #[test]
    fn marker_round_trips_through_luma_at_every_sequence_boundary() {
        for counter in [0u64, 1, 2, 0x7FF, 0x800, 0xFFF, 0x1000, 0x1234_5678] {
            let data = SyntheticCapture::render_sized(counter, 320, 240);
            let y = luma_of(&data, 320, 240);
            assert_eq!(
                marker::decode_luma(&y, 320, 240, 320),
                Some(marker::seq_of(counter)),
                "counter {counter:#x}"
            );
        }
    }

    #[test]
    fn marker_survives_a_box_downscale() {
        // The viewer may decode a picture the agent downscaled. A 2× and a
        // 4× box filter keep each block's centre on its side of the threshold.
        let (w, h) = (640u32, 480u32);
        let data = SyntheticCapture::render_sized(0x5A5, w, h);
        let y = luma_of(&data, w, h);
        for k in [2u32, 4] {
            let (sw, sh) = (w / k, h / k);
            let mut small = vec![0u8; (sw * sh) as usize];
            for sy in 0..sh {
                for sx in 0..sw {
                    let mut sum = 0u32;
                    for dy in 0..k {
                        for dx in 0..k {
                            sum += y[((sy * k + dy) * w + sx * k + dx) as usize] as u32;
                        }
                    }
                    small[(sy * sw + sx) as usize] = (sum / (k * k)) as u8;
                }
            }
            assert_eq!(
                marker::decode_luma(&small, sw, sh, sw as usize),
                Some(0x5A5),
                "{k}×"
            );
        }
    }

    #[test]
    fn a_flipped_block_is_a_miss_never_a_wrong_number() {
        let data = SyntheticCapture::render_sized(0x321, 320, 240);
        let mut y = luma_of(&data, 320, 240);
        // Invert one block of the grid (bit 5: row 0, column 5).
        let (ox, oy) = marker::origin(320, 240).unwrap();
        for yy in oy..oy + marker::BLOCK {
            for xx in (ox + 5 * marker::BLOCK)..(ox + 6 * marker::BLOCK) {
                let i = (yy * 320 + xx) as usize;
                y[i] = 251 - y[i];
            }
        }
        let read = marker::decode_luma(&y, 320, 240, 320);
        assert_ne!(
            read,
            Some(0x321 ^ (1 << (11 - 5))),
            "a single misread block must not pass the CRC"
        );
        assert!(read.is_none() || read == Some(0x321), "got {read:?}");
    }

    #[test]
    fn the_probe_marker_reads_back_from_the_bottom_right_and_only_when_painted() {
        let y_of = |probe| {
            let data = SyntheticCapture::render_frame(0x123, 320, 240, probe);
            luma_of(&data, 320, 240)
        };
        let painted = y_of(Some(0x5A5));
        assert_eq!(
            marker::decode_luma_at(marker::Corner::BottomRight, &painted, 320, 240, 320),
            Some(0x5A5)
        );
        // The frame's own number is untouched beside it.
        assert_eq!(marker::decode_luma(&painted, 320, 240, 320), Some(0x123));
        // No probe yet: nothing to read, never a stale or invented number.
        let unpainted = y_of(None);
        assert_eq!(
            marker::decode_luma_at(marker::Corner::BottomRight, &unpainted, 320, 240, 320),
            None
        );
    }

    #[test]
    fn the_two_markers_never_overlap() {
        // Too narrow for both: the probe marker is refused, not squeezed in.
        assert!(marker::origin_at(marker::Corner::BottomLeft, 200, 240).is_some());
        assert_eq!(
            marker::origin_at(marker::Corner::BottomRight, 200, 240),
            None
        );
        let (lx, _) = marker::origin_at(marker::Corner::BottomLeft, 320, 240).unwrap();
        let (rx, _) = marker::origin_at(marker::Corner::BottomRight, 320, 240).unwrap();
        assert!(lx + marker::W + marker::MARGIN <= rx - marker::MARGIN);
    }

    #[test]
    fn only_a_probe_message_is_consumed_and_typing_the_word_still_reaches_input() {
        assert!(probe::accept_json(r#"{"t":"probe","seq":7}"#));
        assert!(!probe::accept_json(
            r#"{"t":"mouse_move","x":0.1,"y":0.2,"mon":0}"#
        ));
        // The substring pre-check must not swallow a person typing "probe".
        assert!(!probe::accept_json(r#"{"t":"key_text","text":"probe"}"#));
        assert!(!probe::accept_json("not json at all \"probe\""));
    }

    #[test]
    fn a_frame_too_small_for_the_marker_is_left_alone() {
        assert_eq!(marker::origin(100, 40), None);
        let mut data = vec![7u8; 100 * 40 * 4];
        marker::paint_bgra(&mut data, 100, 40, 400, 9);
        assert!(data.iter().all(|&b| b == 7));
    }

    #[test]
    fn the_clock_returns_what_was_recorded_and_nothing_else() {
        // An instant taken BEFORE the clock's epoch exists (the first call
        // sets it) must come back too: that is the first frame of every run.
        let t = Instant::now();
        clock::record(4095, t);
        let back = clock::captured_at(4095).expect("recorded");
        assert!(
            back.max(t) - back.min(t) < Duration::from_micros(2),
            "{t:?} came back as {back:?}"
        );
        // A later one, after the epoch.
        let t2 = Instant::now() + Duration::from_millis(5);
        clock::record(4094, t2);
        let back2 = clock::captured_at(4094).expect("recorded");
        assert!(back2.max(t2) - back2.min(t2) < Duration::from_micros(2));
        assert_eq!(
            clock::captured_at(4093),
            None,
            "an unwritten slot reads as never captured"
        );
    }
}
