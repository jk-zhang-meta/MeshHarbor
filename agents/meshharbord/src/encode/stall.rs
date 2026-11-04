// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-65 P0 — the pump stall watch's VERDICT, as a pure function.
//!
//! # Why this is a module and not four lines in the pump
//!
//! The decision "was this iteration a stall, and where did its time go" is the
//! instrument the whole FR turns on, and it had two properties that made it
//! impossible to check:
//!
//! 1. It lived inline in `media_pump_ffmpeg_dc`, which is behind the
//!    `ffmpeg-encoder` feature — **not** a default feature, so
//!    `cargo test -p meshharbord --lib` compiled none of it. The rule that
//!    decides whether an operator ever sees a stall was, in the lane everyone
//!    runs, unreachable.
//! 2. Its two subtractions are each a judgement that was *paid for in the
//!    field* (see below), and both are easy to "simplify" into something that
//!    looks equivalent and is not.
//!
//! Extracting it costs one struct and buys a test that runs on every push.
//!
//! # The two rules, and what each cost to learn
//!
//! **`work_us = iter − capture`, and the stall decision runs on THAT.** Capture
//! is change-driven, so a quiet screen sleeps *inside* capture and `capture_us`
//! accumulates the wait. At the original 250 ms bar those passes were invisible;
//! at the 100 ms bar they became the MAJORITY of warnings — field 2026-09-03, a
//! direct session logged seven in 45 s, every one shaped
//! `iter_ms=111 capture_ms=101.9`: 9 ms of work and 102 ms of idling. A watch
//! that cries about idling is one people learn to ignore, which costs exactly
//! the signal it exists for. The waiting is genuine: every capture backend hands
//! the device work to a thread that owns the `!Send` capturer and returns a
//! future, so the loop is idling by design.
//!
//! ⚠️ **The cost of that rule, stated so nobody rediscovers it as a bug:** a
//! pathological capture — a wedged DXGI duplication, an EDR filter stalling the
//! desktop, a driver hang — **cannot trip this watch**, and `pump_stalls`
//! under-counts by construction. `capture_us` is still reported, so a reader can
//! see it, but nothing ALERTS on it. If capture needs an alarm it needs its own
//! threshold, not this one widened back.
//!
//! **`other_us = iter − Σphases`, computed rather than left to a reader.** An
//! overrun whose named phases all read ~0 is itself the finding: the time went
//! somewhere still untimed. Field 2026-09-03: four stalls on CORPLAP-1, one on
//! the first pass of every session, `iter_ms` 513–1006 while the named phases
//! summed to 33–52 ms — 0.46–0.96 s in no phase at all. That was the initial
//! encoder open, and it hid for months behind a breakdown that *looked*
//! complete; it was spotted by eye on the fourth occurrence. A breakdown that
//! does not sum to its total is the most useful number in the line, so it must
//! not depend on somebody noticing.

/// One pump iteration's phase breakdown, in microseconds.
///
/// Every field is a DELTA for this pass (the pump keeps running accumulators
/// and subtracts the previous pass's marks), so the invariant a reader should
/// expect is `Σ phases ≤ iter_us` — and where it does not hold,
/// [`PassTiming::other_us`] is the gap that says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PassTiming {
    /// Wall-clock for the whole iteration.
    pub iter_us: u64,
    /// Time inside capture. ⚠️ Mostly *waiting for a frame to change* on a
    /// quiet screen — see the module docs before treating it as work.
    pub capture_us: u64,
    pub scale_us: u64,
    pub encode_us: u64,
    pub send_us: u64,
    /// A rate/dims change applied to an encoder that ALREADY EXISTS.
    ///
    /// ⚠️ `apply_us == 0` on a session's first pass is not a contradiction and
    /// misled this investigation for weeks: the first pass has no encoder to
    /// change, it CONSTRUCTS one, and that is [`Self::open_us`].
    pub apply_us: u64,
    /// Opening (or rebuilding) the encoder.
    pub open_us: u64,
    /// FR-1 P5 cadence pacing — the deliberate sleep to the next slot when the
    /// encoder cannot hold `target_fps`.
    ///
    /// ⚠️ **Idle by design, like [`Self::capture_us`], and excluded from
    /// [`Self::work_us`] for the same reason.** At a paced 2 fps this is ~500 ms
    /// of a single pass. Counting it as work would re-create the warning storm
    /// the `work_us` rule removed for capture, one door along.
    pub pace_us: u64,
    /// Reading the peer connection's ICE/candidate stats — the relay-escape
    /// re-check and FR-33's LAN-capture reason.
    ///
    /// ⚠️ This is **not** free and it is not obviously on the video path: it
    /// walks the stats graph and takes locks the ICE agent and SCTP association
    /// also hold, so it is at its slowest exactly when the session is busiest.
    pub stats_us: u64,
    /// The control DataChannel: taking its lock and sending `rc:video-info`.
    pub ctrl_us: u64,
    /// Adopting a finished background encoder rebuild.
    pub swap_us: u64,
    /// The backpressure gate — the congestion decision plus its short sleep, on
    /// the pass where the pump skips production entirely.
    ///
    /// 🔑 This is the arm that made the gap hard to see: it `continue`s BEFORE
    /// capture, so such a pass reports `capture_us == 0` and `encode_us == 0`
    /// and every millisecond it spent landed in [`Self::other_us`].
    pub gate_us: u64,
}

/// The pump's running phase accumulators, snapshotted at a pass boundary.
///
/// The pump keeps plain `u64` counters and marks them at the start of each
/// pass; [`Self::delta`] turns "then" and "now" into one [`PassTiming`]. Having
/// the subtraction in ONE place is the point — it used to be eleven inline
/// `saturating_sub`s in the warn macro, where a mismatched pair is invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PhaseAccum {
    pub capture_us: u64,
    pub scale_us: u64,
    pub encode_us: u64,
    pub send_us: u64,
    pub apply_us: u64,
    pub open_us: u64,
    pub pace_us: u64,
    pub stats_us: u64,
    pub ctrl_us: u64,
    pub swap_us: u64,
    pub gate_us: u64,
}

impl PhaseAccum {
    /// This pass's timing: `self` (now) minus `mark` (the pass start).
    ///
    /// Saturating throughout: an accumulator can only grow, so a negative delta
    /// means the mark was taken after the reading, which is a bug rather than a
    /// number to propagate.
    pub fn delta(self, mark: Self, iter_us: u64) -> PassTiming {
        PassTiming {
            iter_us,
            capture_us: self.capture_us.saturating_sub(mark.capture_us),
            scale_us: self.scale_us.saturating_sub(mark.scale_us),
            encode_us: self.encode_us.saturating_sub(mark.encode_us),
            send_us: self.send_us.saturating_sub(mark.send_us),
            apply_us: self.apply_us.saturating_sub(mark.apply_us),
            open_us: self.open_us.saturating_sub(mark.open_us),
            pace_us: self.pace_us.saturating_sub(mark.pace_us),
            stats_us: self.stats_us.saturating_sub(mark.stats_us),
            ctrl_us: self.ctrl_us.saturating_sub(mark.ctrl_us),
            swap_us: self.swap_us.saturating_sub(mark.swap_us),
            gate_us: self.gate_us.saturating_sub(mark.gate_us),
        }
    }
}

impl PassTiming {
    /// Time not spent waiting for input — the quantity the stall decision runs
    /// on. Saturating, so a capture delta that somehow exceeds the iteration
    /// (a clock that moved under us) reads 0 rather than wrapping to ~18
    /// billion milliseconds and reporting a stall on every idle pass.
    /// Time not spent waiting for input — the quantity the stall decision runs
    /// on. Saturating, so a capture delta that somehow exceeds the iteration
    /// (a clock that moved under us) reads 0 rather than wrapping to ~18
    /// billion milliseconds and reporting a stall on every idle pass.
    ///
    /// ⚠️ **Two deliberate idles are excluded, not one.** `capture_us` is
    /// waiting for the screen to change; `pace_us` is waiting for the next
    /// cadence slot because the encoder cannot hold `target_fps`. Both are the
    /// loop idling on purpose, and at a paced 2 fps the second is ~500 ms — so
    /// counting it would report a "stall" on every paced pass, which is the
    /// same mistake the 100 ms bar exposed for capture.
    pub fn work_us(&self) -> u64 {
        self.iter_us
            .saturating_sub(self.capture_us)
            .saturating_sub(self.pace_us)
    }

    /// Everything the pump explicitly timed.
    pub fn phases_us(&self) -> u64 {
        self.capture_us
            .saturating_add(self.scale_us)
            .saturating_add(self.encode_us)
            .saturating_add(self.send_us)
            .saturating_add(self.apply_us)
            .saturating_add(self.open_us)
            .saturating_add(self.pace_us)
            .saturating_add(self.stats_us)
            .saturating_add(self.ctrl_us)
            .saturating_add(self.swap_us)
            .saturating_add(self.gate_us)
    }

    /// `iter − Σphases`: time that fell into no named phase. **A non-trivial
    /// value here is a finding, not noise** — it is where the encoder open hid.
    pub fn other_us(&self) -> u64 {
        self.iter_us.saturating_sub(self.phases_us())
    }

    /// Does this pass warrant a stall warning at `warn_us`?
    ///
    /// ⚠️ Compares [`Self::work_us`], never `iter_us`. Swapping them back would
    /// re-create the idle-capture warning storm the 100 ms bar exposed.
    pub fn is_stall(&self, warn_us: u64) -> bool {
        self.work_us() >= warn_us
    }

    /// The single phase that dominated this pass, and its microseconds —
    /// `None` when nothing named accounts for it, which points at
    /// [`Self::other_us`].
    ///
    /// Reporting only; the pump logs the full breakdown. It exists so a test
    /// can assert ATTRIBUTION rather than merely that something was flagged
    /// (FR-65 AC2), because "a stall was caught" and "a stall was caught and
    /// blamed on the right phase" are different claims.
    pub fn dominant_phase(&self) -> Option<(&'static str, u64)> {
        let named: [(&'static str, u64); 11] = [
            ("capture", self.capture_us),
            ("scale", self.scale_us),
            ("encode", self.encode_us),
            ("send", self.send_us),
            ("apply", self.apply_us),
            ("open", self.open_us),
            ("pace", self.pace_us),
            ("stats", self.stats_us),
            ("ctrl", self.ctrl_us),
            ("swap", self.swap_us),
            ("gate", self.gate_us),
        ];
        let (name, us) = named.into_iter().max_by_key(|(_, us)| *us)?;
        if us == 0 || us < self.other_us() {
            return None;
        }
        Some((name, us))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact field shape from 2026-09-03: 9 ms of work, 102 ms of idling.
    /// Seven of these in 45 s on one direct session were the majority of the
    /// warnings at the 100 ms bar.
    #[test]
    fn an_idle_capture_wait_is_not_a_stall() {
        let pass = PassTiming {
            iter_us: 111_000,
            capture_us: 101_900,
            encode_us: 9_000,
            ..Default::default()
        };
        assert_eq!(pass.work_us(), 9_100);
        assert!(
            !pass.is_stall(100_000),
            "a pass that idled 102 ms inside capture must not warn"
        );
    }

    /// The same pass under the pre-0.4.60 rule, which judged on `iter_us`.
    /// Kept as a test so the regression has a name: this is what the storm was.
    #[test]
    fn the_same_pass_would_have_warned_under_the_old_rule() {
        let pass = PassTiming {
            iter_us: 111_000,
            capture_us: 101_900,
            encode_us: 9_000,
            ..Default::default()
        };
        assert!(
            pass.iter_us >= 100_000,
            "the old iter-based rule fired here — that is the storm this replaced"
        );
    }

    /// CORPLAP-1, 0.4.60, session 6a9a0602: the first pass of a session, whose
    /// 815 ms is the encoder open.
    #[test]
    fn an_encoder_open_is_a_stall_and_is_attributed_to_open() {
        let pass = PassTiming {
            iter_us: 815_677,
            capture_us: 9_973,
            encode_us: 16_104,
            open_us: 789_024,
            apply_us: 0,
            ..Default::default()
        };
        assert!(pass.is_stall(100_000));
        assert_eq!(pass.work_us(), 805_704);
        assert_eq!(pass.dominant_phase(), Some(("open", 789_024)));
        // The breakdown SUMS: 815 677 − (9 973 + 16 104 + 789 024) = 576 µs.
        assert!(
            pass.other_us() < 1_000,
            "a fully-attributed pass left {} µs unexplained",
            pass.other_us()
        );
    }

    /// The pre-#1279 shape, before `open_us` existed: the same pass with the
    /// open untimed. The remainder must surface as `other`, and `dominant_phase`
    /// must REFUSE to blame a named phase for it.
    #[test]
    fn an_untimed_phase_surfaces_as_other_and_blames_nobody() {
        let pass = PassTiming {
            iter_us: 773_062,
            capture_us: 8_837,
            encode_us: 15_821,
            ..Default::default()
        };
        assert!(pass.is_stall(100_000));
        assert_eq!(pass.other_us(), 773_062 - 8_837 - 15_821);
        assert!(
            pass.other_us() > 700_000,
            "the untimed remainder is the finding and must be visible"
        );
        assert_eq!(
            pass.dominant_phase(),
            None,
            "no named phase may be blamed when the remainder dwarfs them all"
        );
    }

    /// ⚠️ Guards the saturating subtraction. `capture_us > iter_us` should be
    /// impossible, but a wrapping subtraction here would compute ~1.8e19 µs and
    /// report a stall on EVERY pass — a log flood from an arithmetic edge.
    #[test]
    fn a_capture_delta_larger_than_the_iteration_cannot_wrap() {
        let pass = PassTiming {
            iter_us: 5_000,
            capture_us: 9_000,
            ..Default::default()
        };
        assert_eq!(pass.work_us(), 0);
        assert!(!pass.is_stall(100_000));
        assert_eq!(pass.other_us(), 0);
    }

    /// CORPLAP-2, 2026-09-04: `iter 662 / capture 0.0 / encode 0.0`, the whole
    /// pass in `other`. Zero capture AND zero encode is the signature of the
    /// backpressure gate, which `continue`s BEFORE capture — so every
    /// millisecond it spent was invisible.
    #[test]
    fn a_gate_skip_is_attributed_to_gate_not_to_other() {
        let pass = PassTiming {
            iter_us: 662_022,
            gate_us: 661_500,
            ..Default::default()
        };
        assert_eq!(pass.dominant_phase(), Some(("gate", 661_500)));
        assert!(
            pass.other_us() < 1_000,
            "the gate skip left {} us unexplained",
            pass.other_us()
        );
        assert!(pass.is_stall(100_000), "a 662 ms gate pass is real work");
    }

    /// A paced pass is the loop idling on purpose, exactly like a capture wait.
    /// At 2 fps the sleep is ~500 ms and it must NOT warn.
    #[test]
    fn a_cadence_sleep_is_idle_and_does_not_warn() {
        let pass = PassTiming {
            iter_us: 505_000,
            capture_us: 4_000,
            encode_us: 11_000,
            pace_us: 490_000,
            ..Default::default()
        };
        assert_eq!(pass.work_us(), 11_000, "pace is excluded from work");
        assert!(
            !pass.is_stall(100_000),
            "a 490 ms deliberate cadence sleep must not report a stall"
        );
        assert!(pass.other_us() < 1_000);
    }

    /// The stats read is the opposite case: not idle, and slowest exactly when
    /// the session is busiest, so it must both count as work and be blamed.
    #[test]
    fn an_ice_stats_read_counts_as_work_and_is_named() {
        let pass = PassTiming {
            iter_us: 171_500,
            capture_us: 300,
            encode_us: 13_600,
            stats_us: 157_000,
            ..Default::default()
        };
        assert!(pass.is_stall(100_000));
        assert_eq!(pass.dominant_phase(), Some(("stats", 157_000)));
        assert!(pass.other_us() < 1_000);
    }

    /// `PhaseAccum::delta` is the one place the eleven subtractions live.
    #[test]
    fn phase_accum_delta_subtracts_each_counter_once() {
        let mark = PhaseAccum {
            capture_us: 10,
            scale_us: 20,
            encode_us: 30,
            send_us: 40,
            apply_us: 50,
            open_us: 60,
            pace_us: 70,
            stats_us: 80,
            ctrl_us: 90,
            swap_us: 100,
            gate_us: 110,
        };
        let now = PhaseAccum {
            capture_us: 11,
            scale_us: 22,
            encode_us: 33,
            send_us: 44,
            apply_us: 55,
            open_us: 66,
            pace_us: 77,
            stats_us: 88,
            ctrl_us: 99,
            swap_us: 110,
            gate_us: 121,
        };
        let d = now.delta(mark, 1_000);
        assert_eq!(
            (
                d.capture_us,
                d.scale_us,
                d.encode_us,
                d.send_us,
                d.apply_us,
                d.open_us
            ),
            (1, 2, 3, 4, 5, 6)
        );
        assert_eq!(
            (d.pace_us, d.stats_us, d.ctrl_us, d.swap_us, d.gate_us),
            (7, 8, 9, 10, 11)
        );
        assert_eq!(d.iter_us, 1_000);
        // ⚠️ A counter that went BACKWARDS is a bug, not a number to propagate.
        let back = PhaseAccum::default().delta(mark, 500);
        assert_eq!(back.capture_us, 0);
        assert_eq!(back.gate_us, 0);
    }

    #[test]
    fn the_threshold_is_inclusive() {
        let pass = PassTiming {
            iter_us: 100_000,
            ..Default::default()
        };
        assert!(pass.is_stall(100_000), "a pass exactly at the bar warns");
        let just_under = PassTiming {
            iter_us: 99_999,
            ..Default::default()
        };
        assert!(!just_under.is_stall(100_000));
    }

    /// A slow ENCODE must still be caught and blamed on encode — the watch is
    /// not only about the open, and a rule tuned until nothing fires would be
    /// worse than no rule.
    #[test]
    fn a_slow_encode_is_caught_and_attributed_to_encode() {
        let pass = PassTiming {
            iter_us: 260_000,
            capture_us: 4_000,
            encode_us: 250_000,
            ..Default::default()
        };
        assert!(pass.is_stall(100_000));
        assert_eq!(pass.dominant_phase(), Some(("encode", 250_000)));
    }
}
