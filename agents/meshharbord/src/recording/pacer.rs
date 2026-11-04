// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — the recorder's constant-frame-rate clock.
//!
//! Capture is change-driven (a still screen yields `Ok(None)`), and a
//! backend's `Frame.monotonic_us` has a different origin per backend — since
//! open on WGC/scrap/synthetic, wall-clock on the portal. Neither can time a
//! file. The recorder therefore owns its clock: one `Instant` taken when the
//! first frame is encoded, and every frame presented at a TICK of `1/fps`
//! on it. Ticks are pure arithmetic here so they can be tested without a
//! clock.
//!
//! ⚠️ A late tick is not re-timed onto a later grid slot by accident: the
//! tick index comes from elapsed time, so an encoder that falls behind
//! produces a gap in tick numbers (the previous sample simply lasts longer),
//! never a file that runs fast.

use std::collections::VecDeque;
use std::time::Duration;

use super::mp4::VIDEO_TIMESCALE;

/// Maps elapsed time to frame ticks and ticks to MP4 presentation times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    fps: u32,
}

impl Cadence {
    /// `fps` is clamped to 1..=60.
    pub fn new(fps: u32) -> Self {
        Self {
            fps: fps.clamp(1, 60),
        }
    }

    pub fn fps(&self) -> u32 {
        self.fps
    }

    /// Wall-clock length of one tick.
    pub fn interval(&self) -> Duration {
        Duration::from_nanos(1_000_000_000 / u64::from(self.fps))
    }

    /// The tick a frame encoded `elapsed` after the start belongs to (the
    /// nearest tick at or before it).
    pub fn tick_at(&self, elapsed: Duration) -> u64 {
        (elapsed.as_nanos() * u128::from(self.fps) / 1_000_000_000) as u64
    }

    /// Presentation time of `tick` in [`VIDEO_TIMESCALE`] units.
    pub fn pts(&self, tick: u64) -> u64 {
        tick * u64::from(VIDEO_TIMESCALE / self.fps)
    }

    /// Ticks per GOP for a keyframe every `seconds`.
    pub fn gop_ticks(&self, seconds: u32) -> u64 {
        u64::from(self.fps) * u64::from(seconds.max(1))
    }
}

/// Encoder output does not have to be one-for-one with input: openh264 splits
/// a keyframe into per-layer packets, and a backend with any output delay
/// returns a frame on a later call than the one that submitted it. This FIFO
/// hands every finished access unit the tick it was SUBMITTED at, so a
/// delayed encoder shifts nothing.
#[derive(Debug, Default)]
pub struct TickFifo {
    pending: VecDeque<u64>,
    last: Option<u64>,
}

impl TickFifo {
    pub fn submitted(&mut self, tick: u64) {
        self.pending.push_back(tick);
    }

    /// The tick of the next finished access unit. More access units than
    /// submissions (an encoder that emits extra) get strictly increasing
    /// ticks after the last one handed out, so PTS stays monotonic.
    pub fn finished(&mut self) -> u64 {
        let t = match self.pending.pop_front() {
            Some(t) => t,
            None => self.last.map(|l| l + 1).unwrap_or(0),
        };
        let t = match self.last {
            Some(l) if t <= l => l + 1,
            _ => t,
        };
        self.last = Some(t);
        t
    }

    /// Submissions still awaiting output.
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_follow_elapsed_time_not_call_count() {
        let c = Cadence::new(30);
        assert_eq!(c.tick_at(Duration::ZERO), 0);
        assert_eq!(c.tick_at(Duration::from_millis(33)), 0);
        assert_eq!(c.tick_at(Duration::from_millis(34)), 1);
        assert_eq!(c.tick_at(Duration::from_secs(10)), 300);
    }

    #[test]
    fn pts_is_exact_at_every_supported_rate() {
        for fps in [1u32, 5, 10, 15, 24, 25, 30, 50, 60] {
            let c = Cadence::new(fps);
            assert_eq!(
                c.pts(u64::from(fps)),
                u64::from(VIDEO_TIMESCALE),
                "{fps} fps"
            );
        }
    }

    #[test]
    fn fps_is_clamped() {
        assert_eq!(Cadence::new(0).fps(), 1);
        assert_eq!(Cadence::new(240).fps(), 60);
    }

    #[test]
    fn a_two_second_gop_at_30fps_is_60_ticks() {
        assert_eq!(Cadence::new(30).gop_ticks(2), 60);
        assert_eq!(Cadence::new(60).gop_ticks(0), 60, "0 s is treated as 1 s");
    }

    #[test]
    fn a_delayed_encoder_keeps_each_frames_own_tick() {
        let mut f = TickFifo::default();
        f.submitted(0);
        f.submitted(1); // tick 0's output arrives only now
        assert_eq!(f.finished(), 0);
        f.submitted(3); // tick 2 was skipped (the encoder fell behind)
        assert_eq!(f.finished(), 1);
        assert_eq!(f.finished(), 3);
        assert_eq!(f.in_flight(), 0);
    }

    #[test]
    fn extra_output_stays_strictly_increasing() {
        let mut f = TickFifo::default();
        f.submitted(5);
        assert_eq!(f.finished(), 5);
        assert_eq!(f.finished(), 6);
        assert_eq!(f.finished(), 7);
    }
}
