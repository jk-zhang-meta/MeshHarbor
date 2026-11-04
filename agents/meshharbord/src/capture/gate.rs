// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-98 C1 — when an event-driven capture backend may hand the pump the
//! frame its slot holds.
//!
//! **The legacy gate** (still the default) sleeps out the rest of a frame
//! period, measured from the last call, *before* it looks at the slot. A
//! frame that is already waiting pays that sleep. At an exact period (25,
//! 40, 50 fps) the wait can lock to the phase between the two clocks, every
//! frame paying the same amount, anywhere up to a whole period. Its period
//! is whole milliseconds, though, so at 30 and 60 fps its cadence runs
//! slightly fast and drifts out of the wait on its own: there the cost is
//! mostly the frames that land during a slow encode. And `1000 / 60` caps at
//! 62.5 fps, `1000 / 144` at 166 (FR-98 §4.1).
//!
//! **The slot-first gate** is a token bucket at the target rate that holds
//! up to two frames of credit. A waiting frame goes out at once while there
//! is a frame of credit, so a source at or below the target rate is never
//! held, whatever its phase. Only a source that outruns the target drains
//! the bucket, and only then is a frame paced, which still caps the long-run
//! rate at the target. The period is kept in microseconds.
//!
//! `ROOMLERD_CAPTURE_GATE=slot_first` selects it, read once per capture
//! open (FR-70: no per-frame reads in the pump). Anything else keeps the
//! legacy rule, whose code path in each backend is unchanged.

use std::time::{Duration, Instant};

/// Which gate an open uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    Legacy,
    SlotFirst,
}

impl GateMode {
    /// `slot_first` (or `slot-first`) selects the new gate. Unset, `legacy`
    /// and anything unrecognised keep the legacy rule: a typo must never
    /// change capture timing.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(|v| v.trim().to_ascii_lowercase()) {
            Some(v) if v == "slot_first" || v == "slot-first" => Self::SlotFirst,
            _ => Self::Legacy,
        }
    }

    /// `ROOMLERD_CAPTURE_GATE`, read when a capture backend opens.
    pub fn from_env() -> Self {
        Self::parse(tunnel_core::env::node_env("CAPTURE_GATE").as_deref())
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::SlotFirst => "slot_first",
        }
    }

    /// FR-119 P2b — the gate a granted rate runs: above
    /// [`SLOT_FIRST_ABOVE_FPS`] the slot-first gate, whatever the open chose
    /// (spec §3.4); at or below it, the open's own gate. The legacy rule
    /// sleeps out the rest of a period before it looks at the slot, so a frame
    /// that landed during the encode waits, and at 120 fps that wait comes out
    /// of an 8.3 ms budget.
    pub fn at_fps(opened: Self, fps: u32) -> Self {
        if fps > SLOT_FIRST_ABOVE_FPS {
            Self::SlotFirst
        } else {
            opened
        }
    }
}

/// FR-119 P2b — above this rate a granted session runs the slot-first gate.
pub const SLOT_FIRST_ABOVE_FPS: u32 = 60;

/// The legacy gate's period: whole milliseconds, as every backend has always
/// computed it. At 120 and 144 fps it is 8 and 6 ms, a little shorter than the
/// frames' own 8.3 and 6.9, so, as at 30 and 60, the cadence drifts out of the
/// wait instead of locking to a phase (the module comment).
pub fn legacy_period(fps: u32) -> Duration {
    Duration::from_millis(1000 / u64::from(fps.max(1)))
}

/// The slot-first bucket. Pure over the instants it is given, so the tests
/// drive it with a synthetic timeline.
#[derive(Debug, Clone)]
pub struct SlotFirst {
    period: Duration,
    /// Credit in frames at `at`.
    credit: f64,
    at: Option<Instant>,
}

impl SlotFirst {
    /// Frames of credit the bucket holds. One frame of slack absorbs any
    /// phase between the source's clock and the target's; more would let a
    /// faster source burst further above the target after an idle spell.
    pub const CAPACITY: f64 = 2.0;

    pub fn new(target_fps: u32) -> Self {
        Self {
            period: Duration::from_micros(1_000_000 / u64::from(target_fps.max(1))),
            credit: Self::CAPACITY,
            at: None,
        }
    }

    pub fn period(&self) -> Duration {
        self.period
    }

    fn credit_at(&self, now: Instant) -> f64 {
        let Some(at) = self.at else {
            return self.credit;
        };
        let earned = now.saturating_duration_since(at).as_secs_f64() / self.period.as_secs_f64();
        (self.credit + earned).min(Self::CAPACITY)
    }

    /// How long a frame available at `now` must wait before it may go out:
    /// zero while there is a frame of credit.
    pub fn wait(&self, now: Instant) -> Duration {
        let credit = self.credit_at(now);
        if credit >= 1.0 {
            Duration::ZERO
        } else {
            self.period.mul_f64(1.0 - credit)
        }
    }

    /// A frame went out at `now`.
    pub fn took(&mut self, now: Instant) {
        // A caller that took without waiting goes into debt, and its next
        // frame waits that much longer: the cap holds either way. The floor
        // only stops a runaway caller from banking unbounded debt.
        self.credit = (self.credit_at(now) - 1.0).max(-Self::CAPACITY);
        self.at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn only_slot_first_by_name_selects_the_new_gate() {
        assert_eq!(GateMode::parse(Some("slot_first")), GateMode::SlotFirst);
        assert_eq!(GateMode::parse(Some(" Slot-First ")), GateMode::SlotFirst);
        for raw in [
            None,
            Some(""),
            Some("legacy"),
            Some("slotfirst"),
            Some("1"),
            Some("on"),
        ] {
            assert_eq!(GateMode::parse(raw), GateMode::Legacy, "{raw:?}");
        }
    }

    /// FR-119 P2b — above 60 a granted rate runs the slot-first gate whatever
    /// the open chose; at 60 and below the open's choice stands.
    #[test]
    fn above_sixty_the_slot_first_gate_runs_whatever_the_open_chose() {
        for opened in [GateMode::Legacy, GateMode::SlotFirst] {
            assert_eq!(GateMode::at_fps(opened, 120), GateMode::SlotFirst);
            assert_eq!(GateMode::at_fps(opened, 144), GateMode::SlotFirst);
            assert_eq!(GateMode::at_fps(opened, 60), opened);
            assert_eq!(GateMode::at_fps(opened, 30), opened);
        }
    }

    /// The legacy period is whole milliseconds, a little under the frame
    /// period at 120 and 144, never over it.
    #[test]
    fn the_legacy_period_runs_a_little_fast_at_high_rates() {
        assert_eq!(legacy_period(60), Duration::from_millis(16));
        assert_eq!(legacy_period(120), Duration::from_millis(8));
        assert_eq!(legacy_period(144), Duration::from_millis(6));
        assert_eq!(legacy_period(0), Duration::from_secs(1));
        for fps in [120u32, 144] {
            assert!(legacy_period(fps) < SlotFirst::new(fps).period());
        }
    }

    #[test]
    fn the_period_is_microseconds_not_truncated_milliseconds() {
        assert_eq!(SlotFirst::new(144).period(), Duration::from_micros(6_944));
        assert_eq!(SlotFirst::new(60).period(), Duration::from_micros(16_666));
        assert_eq!(SlotFirst::new(0).period(), Duration::from_secs(1));
    }

    /// The legacy rule as each backend applies it: sleep out the rest of a
    /// whole-millisecond period since the last call, then look at the slot.
    /// Returns the instant the frame that arrived at `arrival` is taken.
    fn legacy_take(
        period_ms: u64,
        last_call: &mut Option<Instant>,
        call: Instant,
        arrival: Instant,
    ) -> Instant {
        let period = Duration::from_millis(period_ms);
        let after_sleep = match *last_call {
            Some(last) if call.saturating_duration_since(last) < period => last + period,
            _ => call,
        };
        *last_call = Some(after_sleep);
        after_sleep.max(arrival)
    }

    /// Per-frame wait from arrival to take, for a source at `src_us` per
    /// frame whose frames land `lead` of a period ahead of the legacy
    /// cadence, under both gates at `fps`. The pump comes back 5 ms after
    /// each take (encode + send). Returns (legacy, slot-first).
    fn waits(fps: u32, src_us: u64, lead: f64, frames: u32) -> (Vec<Duration>, Vec<Duration>) {
        let p = Duration::from_micros(src_us);
        let t0 = Instant::now();
        let arrival = |k: u32| {
            if k == 0 {
                t0
            } else {
                t0 + p.mul_f64(f64::from(k) - lead)
            }
        };
        let mut legacy_last = None;
        let mut gate = SlotFirst::new(fps);
        let (mut legacy_call, mut slot_call) = (t0, t0);
        let (mut legacy, mut slot) = (Vec::new(), Vec::new());
        for k in 0..frames {
            let a = arrival(k);
            let lt = legacy_take(1000 / u64::from(fps), &mut legacy_last, legacy_call, a);
            legacy.push(lt - a);
            legacy_call = lt + 5 * MS;

            let ready = slot_call.max(a);
            let st = ready + gate.wait(ready);
            gate.took(st);
            slot.push(st - a);
            slot_call = st + 5 * MS;
        }
        (legacy, slot)
    }

    fn mean(v: &[Duration]) -> Duration {
        v.iter().sum::<Duration>() / v.len().max(1) as u32
    }

    #[test]
    fn a_source_at_the_target_rate_is_never_held_whatever_its_phase() {
        // 25 fps both ends, a whole-millisecond period (40 ms), so the legacy
        // cadence and the source keep their phase: frames that land three
        // quarters of a period early wait those 30 ms, every one of them.
        let (legacy, slot) = waits(25, 40_000, 0.75, 60);
        assert!(
            legacy[1..].iter().all(|w| *w >= 29 * MS),
            "legacy waits {legacy:?}"
        );
        assert!(
            slot.iter().all(Duration::is_zero),
            "slot-first waits {slot:?}"
        );
    }

    #[test]
    fn a_truncated_legacy_period_drifts_out_of_the_wait_on_its_own() {
        // 30 fps: the legacy period truncates to 33 ms against a 33.333 ms
        // source, so its cadence slowly outruns the source. The phase slides
        // about 0.33 ms a frame, the wait decays, and once the pump is the
        // one waiting the legacy gate costs nothing either. This is why C1's
        // steady-state gain is expected to be small at 30 and 60 fps (FR-98
        // §4): the cost is real at an exact period, and right after a slow
        // encode lets frames queue, not on every frame forever.
        let (legacy, slot) = waits(30, 33_333, 0.75, 240);
        assert!(
            mean(&legacy[1..30]) > 15 * MS,
            "early legacy waits {:?}",
            &legacy[..30]
        );
        assert!(
            legacy[200..].iter().all(Duration::is_zero),
            "late legacy waits {:?}",
            &legacy[200..]
        );
        assert!(
            slot.iter().all(Duration::is_zero),
            "slot-first waits {slot:?}"
        );
    }

    #[test]
    fn a_source_that_outruns_the_target_is_paced_to_it() {
        // 144 Hz in, 60 fps out, over five seconds: the long-run rate is the
        // target's, plus at most the bucket's opening burst.
        let src = Duration::from_micros(6_944);
        let t0 = Instant::now();
        let mut gate = SlotFirst::new(60);
        let mut now = t0;
        let mut out = 0u32;
        let end = t0 + Duration::from_secs(5);
        while now < end {
            // The newest frame at or before `now` is what the slot holds.
            let wait = gate.wait(now);
            now += wait;
            gate.took(now);
            out += 1;
            // The pump returns at once; the next frame arrives on the source clock.
            let since = now.duration_since(t0).as_nanos() / src.as_nanos();
            now = t0 + src * (since as u32 + 1);
        }
        assert!(
            (300..=302).contains(&out),
            "{out} frames in 5 s at a 60 fps target"
        );
    }

    #[test]
    fn after_an_idle_spell_at_most_two_frames_go_back_to_back() {
        let t0 = Instant::now();
        let mut gate = SlotFirst::new(60);
        gate.took(t0);
        let later = t0 + Duration::from_secs(10);
        assert_eq!(gate.wait(later), Duration::ZERO);
        gate.took(later);
        assert_eq!(gate.wait(later), Duration::ZERO);
        gate.took(later);
        assert!(
            gate.wait(later) >= gate.period() - MS,
            "the third must wait a period"
        );
    }

    #[test]
    fn a_caller_that_ignores_the_wait_pays_it_on_the_next_frame() {
        let t0 = Instant::now();
        let mut gate = SlotFirst::new(30);
        for _ in 0..3 {
            gate.took(t0);
        }
        // Credit 2 − 3 = −1: two periods before the next frame may go.
        let w = gate.wait(t0);
        assert!(
            w >= gate.period() * 2 - MS && w <= gate.period() * 2 + MS,
            "{w:?}"
        );
    }
}
