// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-35 — the constrained ceiling learns the pair.
//!
//! # Why this exists
//!
//! A relayed session runs under a fleet constant, `relay_max_bps` (3 Mbps),
//! opened at 85 % of it. Measured on the real `neo16 → CORPLAP-2` DERP path
//! (2026-08-29): that pair sustains ~6–9 Mbps and absorbs short bursts far
//! above; at a 25.5 Mbps cap the whole desktop landed as one 680 KB frame at
//! +0.3 s, while at the constant it is a 5.6 KB max-QP keyframe repaired by
//! inter frames over ~1.2 s. Other corp relays in the same fleet measured
//! ~2 Mbps. A constant cannot be right for both — and on NVENC every rate
//! change *down* forces a starved keyframe (FR-31), so within a session the
//! cap may only ever climb.
//!
//! # The rule
//!
//! The AIMD (`aimd.rs`) climbs additively inside a ceiling the pump hands it
//! every tick. This learner sits between the plan ceiling and the AIMD and
//! lifts that ceiling — above the nominal, up to `hi` — only on **delivery
//! evidence** collected once per viewer window (1 s):
//!
//! - the AIMD is *pinned* at the current ceiling (it wants more),
//! - the window actually *carried* ≥ 70 % of that ceiling (a quiet desktop
//!   sending 900 kbps is not evidence about an 8 Mbps cap — the parked
//!   measured-rate line's lesson: you cannot measure capacity you are not
//!   using),
//! - no decrease and no send stall in the trailing 10 s (the send channel
//!   filling, a blocked send, or viewer-age excess all mean the *pipe* is
//!   the limiter, not the cap),
//! - the viewer's paint age, when reported, sits within 1.5× its learned
//!   floor.
//!
//! Any decrease pulls the learned ceiling back to the post-decrease target
//! (never below the nominal), so an over-estimate is corrected by the same
//! signals that would have caught a bad constant. A blocked send longer than
//! [`HARD_STALL`] is answered with a ×0.5 cut instead of the AIMD's ×0.85 —
//! the 7.9 s stall in the P0 measurement was met by three ×0.85 steps over
//! four seconds.
//!
//! The session's *stable rate* — the highest target that held [`STABLE_HOLD`]
//! without a decrease — is what `rate_memory` persists per peer, so the next
//! session on the pair opens at [`SEED_PCT`] of it instead of at the constant.
//!
//! Pure: no clocks, no I/O, no encoder types; every method takes `now`.

use std::time::{Duration, Instant};

/// Trailing window that must be free of decreases and stalls before a step.
pub const GROW_CLEAN: Duration = Duration::from_secs(10);
/// Minimum spacing between two growth steps.
pub const GROW_INTERVAL: Duration = Duration::from_secs(5);
/// The AIMD's target must sit within this fraction of the ceiling ("pinned").
pub const PINNED_PCT: u64 = 90;
/// The window's delivered rate must reach this fraction of the ceiling.
pub const CARRIED_PCT: u64 = 70;
/// Viewer age bound relative to its learned floor. 2× (was 1.5×): on the
/// first field run the pair painted at 66–80 ms over a 43 ms floor during a
/// window drag it carried at 2.1–2.8 Mbps with no age events — 1.5× vetoed
/// exactly the windows that were the evidence.
pub const AGE_FLOOR_FACTOR_PCT: u64 = 200;
/// A blocked send at least this long is a HARD stall (×0.5, not ×0.85).
pub const HARD_STALL: Duration = Duration::from_secs(1);
/// A target must hold this long without a decrease to be the stable rate.
pub const STABLE_HOLD: Duration = Duration::from_secs(10);
/// Growth step = `max(ceiling / GROW_DIVISOR, GROW_MIN_STEP_BPS)` — the
/// AIMD's own additive step, so the two ladders agree.
pub const GROW_DIVISOR: u32 = 16;
pub const GROW_MIN_STEP_BPS: u32 = 150_000;
/// A remembered stable rate seeds the next session at this fraction.
pub const SEED_PCT: u64 = 85;
/// FR-59 P6 — a learned/seeded ceiling more than this multiple above the
/// session's MEASURED drain rate is contradicted by it and is abandoned.
/// 2× is deliberately loose: the learner's whole job is to sit ABOVE a
/// conservative nominal, and a measurement is lumpy on the TURN-TCP paths
/// this runs on, so the test must catch "12.8× wrong" (the field case)
/// without firing on ordinary headroom.
pub const CONTRADICTION_FACTOR: u32 = 2;

/// One growth step, for the pump's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grow {
    pub from_bps: u32,
    pub to_bps: u32,
}

#[derive(Debug)]
pub struct CeilingLearner {
    /// Upper bound the learned ceiling may reach; `0` = learning off.
    hi_bps: u32,
    /// The learned ceiling; `0` until something is learned or seeded.
    learned_bps: u32,
    /// The last plan (nominal) ceiling seen.
    nominal_bps: u32,
    last_decrease_at: Option<Instant>,
    last_stall_at: Option<Instant>,
    last_grow_at: Option<Instant>,
    stable_bps: u32,
    stable_candidate: Option<(u32, Instant)>,
}

impl CeilingLearner {
    /// `hi_bps` = 0 disables learning (the plan ceiling is returned verbatim).
    /// `seed_bps` = a remembered stable rate for this peer, applied at
    /// [`SEED_PCT`].
    pub fn new(hi_bps: u32, seed_bps: Option<u32>) -> Self {
        let learned = seed_bps
            .map(|s| ((s as u64) * SEED_PCT / 100) as u32)
            .unwrap_or(0);
        Self {
            hi_bps,
            learned_bps: learned,
            nominal_bps: 0,
            last_decrease_at: None,
            last_stall_at: None,
            last_grow_at: None,
            stable_bps: 0,
            stable_candidate: None,
        }
    }

    pub fn enabled(&self) -> bool {
        self.hi_bps > 0
    }

    /// The ceiling the AIMD should run under, given the plan's nominal one.
    /// Never below the plan; never above `hi`. Records the nominal: the
    /// learner's own judgements run against the frame actually encoded.
    pub fn effective_ceiling(&mut self, plan_ceiling_bps: u32) -> u32 {
        self.nominal_bps = plan_ceiling_bps;
        self.ceiling_for(plan_ceiling_bps)
    }

    /// FR-70 M3a.2 — [`Self::effective_ceiling`] without recording the
    /// nominal: the ceiling for some OTHER dims than the frame being encoded
    /// (a dims replacement's), which must not move the learner's reference.
    pub fn ceiling_for(&self, plan_ceiling_bps: u32) -> u32 {
        if self.hi_bps == 0 {
            return plan_ceiling_bps;
        }
        plan_ceiling_bps.max(self.learned_bps.min(self.hi_bps))
    }

    fn current_ceiling(&self) -> u32 {
        self.nominal_bps.max(self.learned_bps.min(self.hi_bps))
    }

    /// FR-59 P6 — a held goodput measurement this far below the learned
    /// ceiling ABANDONS it back to the nominal band, returning what was
    /// dropped (exactly once — a second call with nothing learned is a
    /// no-op, so the caller may drive this every frame and still log once).
    ///
    /// The rate memory keys on the nominated pair's REMOTE address
    /// (`peer.rs::nominated_remote_ip`), which on a relayed session is the
    /// relay's, not the viewer's. One fast day therefore writes a number
    /// every later session through that relay inherits for the memory's
    /// 7-day TTL — regardless of what network the client is on today.
    /// Field 2026-09-01: a 5 069 353 bps seed opened a session on a phone
    /// hotspot measured at 395 122 bps, 12.8× under it.
    ///
    /// ⚠ Compared against the RAW measurement, not `derived_ceiling_bps`:
    /// the question is "is the learned ceiling wildly above what this pipe
    /// carries", and folding the 85 % safety margin in would make the test
    /// fire slightly sooner for a reason that has nothing to do with the
    /// contradiction.
    ///
    /// ⚠ Applies to an in-session LEARNED ceiling too, not just a seed —
    /// a measurement that contradicts it is evidence either way, and
    /// resetting to nominal only costs a re-climb the learner already
    /// knows how to do.
    pub fn on_measurement(&mut self, measured_bps: u32, enabled: bool) -> Option<u32> {
        if !enabled || self.learned_bps == 0 || measured_bps == 0 {
            return None;
        }
        let contradicts = (self.learned_bps as u64)
            > (measured_bps as u64).saturating_mul(CONTRADICTION_FACTOR as u64);
        if !contradicts {
            return None;
        }
        let abandoned = self.learned_bps;
        self.learned_bps = 0;
        self.stable_bps = 0;
        self.stable_candidate = None;
        Some(abandoned)
    }

    /// Once per viewer window. `desired_bps` = the AIMD's current target,
    /// `sent_bps` = bytes the send task wrote in the window, as bits/s.
    pub fn on_window(
        &mut self,
        desired_bps: u32,
        sent_bps: u32,
        age: Option<(u16, u16)>,
        now: Instant,
    ) -> Option<Grow> {
        // Stable-rate tracking: the highest target that held STABLE_HOLD
        // with no decrease in between.
        match self.stable_candidate {
            Some((bps, since)) if bps == desired_bps => {
                let clean_since = self.last_decrease_at.is_none_or(|d| d <= since);
                if clean_since && now.duration_since(since) >= STABLE_HOLD {
                    self.stable_bps = self.stable_bps.max(bps);
                }
            }
            _ => self.stable_candidate = Some((desired_bps, now)),
        }

        if self.hi_bps == 0 {
            return None;
        }
        let ceiling = self.current_ceiling();
        if ceiling >= self.hi_bps || ceiling == 0 {
            return None;
        }
        let pinned = (desired_bps as u64) * 100 >= (ceiling as u64) * PINNED_PCT;
        let carried = (sent_bps as u64) * 100 >= (ceiling as u64) * CARRIED_PCT;
        let clean = self
            .last_decrease_at
            .is_none_or(|t| now.duration_since(t) >= GROW_CLEAN)
            && self
                .last_stall_at
                .is_none_or(|t| now.duration_since(t) >= GROW_CLEAN);
        let age_ok = match age {
            Some((a, floor)) if floor > 0 => {
                (a as u64) * 100 <= (floor as u64) * AGE_FLOOR_FACTOR_PCT
            }
            _ => true,
        };
        let spaced = self
            .last_grow_at
            .is_none_or(|t| now.duration_since(t) >= GROW_INTERVAL);
        if !(pinned && carried && clean && age_ok && spaced) {
            return None;
        }
        let step = (ceiling / GROW_DIVISOR).max(GROW_MIN_STEP_BPS);
        let to = ceiling.saturating_add(step).min(self.hi_bps);
        self.learned_bps = to;
        self.last_grow_at = Some(now);
        Some(Grow {
            from_bps: ceiling,
            to_bps: to,
        })
    }

    /// The AIMD decreased (full channel, overflow, stall or age excess) to
    /// `desired_after_bps`: the learned ceiling follows it down — never
    /// below the nominal — and the stable candidate restarts.
    pub fn on_decrease(&mut self, desired_after_bps: u32, now: Instant) {
        self.last_decrease_at = Some(now);
        self.stable_candidate = None;
        if self.learned_bps > self.nominal_bps {
            self.learned_bps = desired_after_bps.max(self.nominal_bps);
        }
    }

    /// A blocked send of `wait`. Returns `true` when it is a HARD stall the
    /// caller should answer with a ×0.5 cut.
    pub fn on_stall(&mut self, wait: Duration, now: Instant) -> bool {
        self.last_stall_at = Some(now);
        wait >= HARD_STALL
    }

    /// The session's stable rate when it exceeds the nominal (else `None`:
    /// nothing worth remembering — the constant would have done the same).
    pub fn stable_bps(&self) -> Option<u32> {
        (self.stable_bps > self.nominal_bps).then_some(self.stable_bps)
    }

    pub fn learned_bps(&self) -> u32 {
        self.learned_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOMINAL: u32 = 3_000_000;
    const HI: u32 = 8_000_000;

    fn t(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    /// Feed `n` clean windows one second apart with the AIMD pinned and the
    /// pipe carrying the ceiling; returns the growth events.
    fn drive(l: &mut CeilingLearner, base: Instant, from_s: u64, n: u64) -> Vec<Grow> {
        let mut out = Vec::new();
        for i in 0..n {
            let now = t(base, from_s + i);
            let c = l.effective_ceiling(NOMINAL);
            if let Some(g) = l.on_window(c, c, None, now) {
                out.push(g);
            }
        }
        out
    }

    /// FR-70 M3a.2 — asking the ceiling for a dims replacement's dims returns
    /// what the per-frame call would, and leaves the learner's nominal on the
    /// frame actually encoded.
    #[test]
    fn ceiling_for_answers_like_effective_ceiling_without_recording_the_nominal() {
        for (hi, seed) in [
            (0, None),
            (HI, None),
            (HI, Some(6_000_000)),
            (HI, Some(100_000_000)),
        ] {
            let mut l = CeilingLearner::new(hi, seed);
            l.effective_ceiling(NOMINAL);
            let asked = l.ceiling_for(1_200_000);
            assert_eq!(l.nominal_bps, NOMINAL, "asking must not move the nominal");
            let mut twin = CeilingLearner::new(hi, seed);
            twin.effective_ceiling(NOMINAL);
            assert_eq!(l.current_ceiling(), twin.current_ceiling());
            assert_eq!(asked, twin.effective_ceiling(1_200_000));
        }
    }

    #[test]
    fn disabled_returns_the_plan_verbatim() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(0, Some(20_000_000));
        assert_eq!(l.effective_ceiling(NOMINAL), NOMINAL);
        assert!(l.on_window(NOMINAL, NOMINAL, None, t(base, 60)).is_none());
        assert!(!l.enabled());
    }

    #[test]
    fn never_below_the_plan_and_never_above_hi() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, Some(100_000_000));
        // A wild seed is bounded by hi …
        assert_eq!(l.effective_ceiling(NOMINAL), HI);
        // … and a tiny seed never drags the plan down.
        let mut l2 = CeilingLearner::new(HI, Some(1_000_000));
        assert_eq!(l2.effective_ceiling(NOMINAL), NOMINAL);
        let _ = base;
    }

    #[test]
    fn seed_opens_at_85_percent_of_the_remembered_rate() {
        let mut l = CeilingLearner::new(HI, Some(6_000_000));
        assert_eq!(l.effective_ceiling(NOMINAL), 5_100_000);
    }

    /// FR-59 P6 — the field case: a seed learned through a relay on a fast
    /// day, met by a measurement 12.8× under it, is abandoned back to the
    /// nominal band; and it is abandoned exactly ONCE, so the caller can
    /// drive this per frame and still log a single line.
    #[test]
    fn a_measurement_that_contradicts_the_seed_abandons_it() {
        let mut l = CeilingLearner::new(HI, Some(5_964_000));
        // 85 % of the remembered rate — the seeded ceiling.
        assert_eq!(l.effective_ceiling(NOMINAL), 5_069_400);
        // The measured hotspot: 395 kbps, far under seed / 2.
        assert_eq!(l.on_measurement(395_122, true), Some(5_069_400));
        assert_eq!(l.effective_ceiling(NOMINAL), NOMINAL, "back to nominal");
        // Idempotent: nothing left to abandon ⇒ no second log line.
        assert_eq!(l.on_measurement(395_122, true), None);
    }

    /// The same call must be inert in every way that is not a
    /// contradiction — ordinary headroom, no evidence, and the kill switch.
    #[test]
    fn on_measurement_is_inert_without_a_contradiction() {
        // Ordinary headroom: a 5.1 M ceiling over a 3 M pipe is 1.7×, under
        // the 2× factor — exactly the case the learner exists to hold.
        let mut l = CeilingLearner::new(HI, Some(6_000_000));
        assert_eq!(l.on_measurement(3_000_000, true), None);
        assert_eq!(l.effective_ceiling(NOMINAL), 5_100_000);
        // A zero measurement is the absence of evidence, not evidence.
        assert_eq!(l.on_measurement(0, true), None);
        // Kill switch: the contradiction is real and still ignored.
        assert_eq!(l.on_measurement(395_122, false), None);
        assert_eq!(l.effective_ceiling(NOMINAL), 5_100_000);
        // Nothing learned or seeded ⇒ nothing to abandon.
        let mut bare = CeilingLearner::new(HI, None);
        assert_eq!(bare.on_measurement(1, true), None);
    }

    #[test]
    fn a_quiet_desktop_is_not_evidence() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, None);
        for i in 0..60 {
            let c = l.effective_ceiling(NOMINAL);
            // pinned, but the window carried only 900 kbps
            assert!(l.on_window(c, 900_000, None, t(base, i)).is_none());
        }
        assert_eq!(l.effective_ceiling(NOMINAL), NOMINAL);
    }

    #[test]
    fn grows_only_when_pinned_carried_clean_and_spaced() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, None);
        // The pump calls effective_ceiling() every tick BEFORE any window,
        // so the learner always knows the nominal; mirror that order.
        let _ = l.effective_ceiling(NOMINAL);
        // Not pinned: the AIMD sits well under the ceiling.
        assert!(l.on_window(2_000_000, NOMINAL, None, t(base, 1)).is_none());
        // Pinned + carried: the first step.
        let g = l
            .on_window(NOMINAL, NOMINAL, None, t(base, 2))
            .expect("first step");
        assert_eq!(g.from_bps, NOMINAL);
        assert_eq!(g.to_bps, NOMINAL + NOMINAL / GROW_DIVISOR);
        assert_eq!(l.effective_ceiling(NOMINAL), g.to_bps);
        // Spacing: the very next window cannot step again …
        let c = l.effective_ceiling(NOMINAL);
        assert!(l.on_window(c, c, None, t(base, 3)).is_none());
        // … but GROW_INTERVAL later it can.
        let c = l.effective_ceiling(NOMINAL);
        assert!(l.on_window(c, c, None, t(base, 7)).is_some());
    }

    #[test]
    fn a_decrease_pulls_the_ceiling_back_and_blocks_growth_for_grow_clean() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, None);
        let grows = drive(&mut l, base, 0, 30);
        assert!(
            grows.len() >= 4,
            "expected several steps, got {}",
            grows.len()
        );
        let before = l.effective_ceiling(NOMINAL);
        assert!(before > NOMINAL);
        // The pipe pushed back: the AIMD cut to 3.4 Mbps.
        l.on_decrease(3_400_000, t(base, 31));
        assert_eq!(l.effective_ceiling(NOMINAL), 3_400_000);
        // Clean-window rule: nothing for GROW_CLEAN even with perfect evidence.
        for i in 32..41 {
            let c = l.effective_ceiling(NOMINAL);
            assert!(
                l.on_window(c, c, None, t(base, i)).is_none(),
                "grew at +{i}s"
            );
        }
        let c = l.effective_ceiling(NOMINAL);
        assert!(l.on_window(c, c, None, t(base, 42)).is_some());
    }

    #[test]
    fn a_decrease_never_drops_below_the_nominal() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, Some(6_000_000));
        assert_eq!(l.effective_ceiling(NOMINAL), 5_100_000);
        l.on_decrease(1_500_000, t(base, 1));
        assert_eq!(l.effective_ceiling(NOMINAL), NOMINAL);
    }

    #[test]
    fn viewer_age_over_the_floor_band_blocks_growth() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, None);
        // The pump calls effective_ceiling() every tick BEFORE any window,
        // so the learner always knows the nominal; mirror that order.
        let _ = l.effective_ceiling(NOMINAL);
        // age 200 ms on a 60 ms floor: over 2× — no step.
        assert!(
            l.on_window(NOMINAL, NOMINAL, Some((200, 60)), t(base, 1))
                .is_none()
        );
        // age 80 ms on a 60 ms floor: within — step.
        assert!(
            l.on_window(NOMINAL, NOMINAL, Some((80, 60)), t(base, 2))
                .is_some()
        );
        // An unknown floor (0) is not a veto.
        let c = l.effective_ceiling(NOMINAL);
        assert!(l.on_window(c, c, Some((999, 0)), t(base, 8)).is_some());
    }

    #[test]
    fn hard_stall_is_one_second_and_stalls_block_growth() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, None);
        // The pump calls effective_ceiling() every tick BEFORE any window,
        // so the learner always knows the nominal; mirror that order.
        let _ = l.effective_ceiling(NOMINAL);
        assert!(!l.on_stall(Duration::from_millis(300), t(base, 1)));
        assert!(l.on_stall(Duration::from_millis(1000), t(base, 2)));
        assert!(l.on_stall(Duration::from_millis(7950), t(base, 3)));
        // No growth within GROW_CLEAN of a stall.
        assert!(l.on_window(NOMINAL, NOMINAL, None, t(base, 5)).is_none());
        assert!(l.on_window(NOMINAL, NOMINAL, None, t(base, 14)).is_some());
    }

    #[test]
    fn stable_rate_needs_a_hold_without_a_decrease_and_exceeds_the_nominal() {
        let base = Instant::now();
        let mut l = CeilingLearner::new(HI, None);
        let _ = l.effective_ceiling(NOMINAL);
        // 6 Mbps held for 9 s: not yet stable.
        for i in 0..10 {
            l.on_window(6_000_000, 6_000_000, None, t(base, i));
        }
        assert_eq!(l.stable_bps(), None);
        // The 10th second makes it stable.
        l.on_window(6_000_000, 6_000_000, None, t(base, 10));
        assert_eq!(l.stable_bps(), Some(6_000_000));
        // A decrease restarts the candidate; the recorded stable rate stays.
        l.on_decrease(4_000_000, t(base, 11));
        for i in 12..30 {
            l.on_window(4_000_000, 4_000_000, None, t(base, i));
        }
        assert_eq!(l.stable_bps(), Some(6_000_000));
        // A rate at or under the nominal is never worth remembering.
        let mut l2 = CeilingLearner::new(HI, None);
        let _ = l2.effective_ceiling(NOMINAL);
        for i in 0..20 {
            l2.on_window(NOMINAL, NOMINAL, None, t(base, i));
        }
        assert_eq!(l2.stable_bps(), None);
    }
}
