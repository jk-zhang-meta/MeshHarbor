// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-70 P1 — the remembered rate is a PRIOR: it may open a session, it may
//! never pin one.
//!
//! # What went wrong (field 2026-09-04, CORPLAP-1 → neo16, session `6a9abc30`)
//!
//! The rate memory held 200 kbps for the pair. That one number entered the
//! session through THREE doors: the AIMD opened at it (FR-59 P8), the
//! legibility floor was relieved to 85 % of it (FR-59 P1, which reads the
//! seed as a stand-in for a measurement), and the send-queue byte budget was
//! denominated in it (FR-59 P2: 450 ms × 200 kbps ⇒ the 16 KB minimum). The
//! third door sealed the other two. Every drag frame larger than 16 KB tripped
//! the budget gate; every trip was an AIMD decrease that also blocked the
//! additive increase for 5 s; and because the gate never let a queue form,
//! the agent's sends never blocked and the viewer's queue never grew — so
//! **nothing could ever measure the pipe and contradict the memory**. Four
//! minutes of `200k → 225k → 253k → 285k → 200k` with `goodput_bps=None`,
//! `send_stalls=0`, zero viewer-congested windows and a 55–108 ms paint age.
//! Every metric green; 0.013 bits per pixel on screen.
//!
//! A prior that produces no measurement cannot be corrected by evidence,
//! because it prevents the evidence. So it has to **decay**: while no live
//! measurement exists, the value standing in for one climbs toward the
//! nominal band — slowly enough that a genuinely slow pipe is over-driven by
//! no more than the AIMD's own additive step, and relentlessly enough that a
//! misremembered fast pair reaches the band inside a session. The moment a
//! live measurement arrives, it becomes the new base (the belief IS the
//! measurement now) and the decay starts again from there once it expires.
//!
//! # The rule
//!
//! - `base` = the last LIVE measurement this session, else the remembered
//!   seed. No seed and nothing measured ⇒ no prior (`None`), and the caller
//!   is byte-for-byte the unremembered session.
//! - The stand-in = `base × step^n`, where `n` counts UP once per
//!   [`DECAY_WINDOWS`] consecutive clean windows and DOWN once per
//!   [`DOWN_WINDOWS`] consecutive pushed-back windows; capped at the nominal
//!   band, where the floor relief is inert anyway (at the band the prior is
//!   simply gone — the session is the unremembered one).
//! - The PIPE pushes back through a send stall, a viewer age excess, a
//!   viewer-reported queue growth or a drain. A byte-budget skip is
//!   deliberately NOT a push-back — it is the pump's own throttle, and on the
//!   field session it was the prior's artefact.
//!
//! ⚠️ The down-step is not optional. A floor derived from a prior that sits
//! 5–10 % ABOVE the pipe grows a queue too slowly for either measurement to
//! latch (the link loop wants 100 ms of growth per window; the goodput
//! estimator wants the SCTP send buffer to fill), and the AIMD's decrease
//! cannot go below the floor — so without it that queue grows for minutes
//! with nothing able to answer. The age LEVEL sees it within seconds, and
//! two windows of it walk the prior back down until the queue drains. The
//! prior is therefore its own small AIMD, with the age loop as its sensor,
//! oscillating around the pipe's capacity when nothing measures it outright.
//!
//! ×1.25 per 10 s is +12.5 % per 5 s — the same slope as the AIMD's slow-band
//! additive step (`aimd::AI_SLOW_BAND_DIVISOR`), chosen for the same reason:
//! on a rebuild-bound encoder every rate move is an IDR, and a probe that
//! overshoots a 300 kbps pipe by more than the AIMD would have is a probe
//! the AIMD's own design already refused. From 200 kbps the band is ~10
//! steps (100 clean windows) away.
//!
//! Pure: no clocks, no I/O; the governor advances it once per viewer window.

/// Clean windows per decay step.
pub const DECAY_WINDOWS: u32 = 10;
/// The step from an UNMEASURED base (the remembered seed): ×5/4.
pub const DECAY_NUM: u64 = 5;
pub const DECAY_DEN: u64 = 4;
/// The step from a MEASURED base (the last live measurement): ×11/10.
///
/// A measured belief has far less reason to decay than a remembered one —
/// it was true of THIS session's pipe a moment ago. It still must not hold
/// forever (a transient stall measures a pipe at a tenth of itself, and
/// the AIMD's own step would take minutes to climb back), but the re-probe
/// it drives should stay inside the margin the link loop can answer before
/// the next step lands: the B0 cell for a genuine 300 kbps pipe showed
/// ×1.25 taking a SECOND step (to 33 % over the pipe) before the first
/// (6 % over) had grown a measurable queue; ×1.1 is answered within a step.
pub const DECAY_ANCHORED_NUM: u64 = 11;
pub const DECAY_ANCHORED_DEN: u64 = 10;
/// Consecutive pushed-back windows (with nothing measured) per step DOWN.
/// Two, not one: the age loop's own trigger is a streak, and a single
/// elevated window on a lumpy relay is a lump, not a verdict.
pub const DOWN_WINDOWS: u32 = 2;

#[derive(Debug)]
pub struct RatePrior {
    /// Kill switch: off ⇒ the stand-in is the constant seed (FR-59 P8 as
    /// shipped, byte-for-byte).
    decay: bool,
    /// What the rate memory said for this pair, when it said anything.
    seed_bps: Option<u32>,
    /// The last live measurement this session — outranks the seed as the
    /// base, because a belief that has been measured is no longer a belief.
    anchor_bps: Option<u32>,
    /// Net steps from the base: positive = decayed upward, negative = walked
    /// down by push-back.
    steps: i32,
    /// Consecutive clean windows toward the next step up.
    clean_run: u32,
    /// Consecutive pushed-back windows toward the next step down.
    dirty_run: u32,
    /// Where the decay stops: the nominal legibility floor. Above it the
    /// floor relief returns the nominal floor regardless, so a stand-in
    /// beyond it would only inflate the queue budget for no gain.
    band_bps: u32,
}

impl RatePrior {
    pub fn new(seed_bps: Option<u32>, band_bps: u32, decay: bool) -> Self {
        Self {
            decay,
            seed_bps: seed_bps.filter(|s| *s > 0),
            anchor_bps: None,
            steps: 0,
            clean_run: 0,
            dirty_run: 0,
            band_bps: band_bps.max(1),
        }
    }

    /// Once per viewer window. `live_bps` = a measurement held THIS window
    /// (blocked-send goodput, or the viewer's arrival rate while its queue
    /// grows); `pushed_back` = the pipe pushed back this window (a stall,
    /// an age excess, a growing viewer queue, a drain).
    pub fn on_window(&mut self, live_bps: Option<u32>, pushed_back: bool) {
        if let Some(live) = live_bps.filter(|l| *l > 0) {
            self.anchor_bps = Some(live);
            self.steps = 0;
            self.clean_run = 0;
            self.dirty_run = 0;
            return;
        }
        if pushed_back {
            self.clean_run = 0;
            self.dirty_run += 1;
            if self.dirty_run >= DOWN_WINDOWS {
                self.dirty_run = 0;
                self.steps = self.steps.saturating_sub(1);
            }
        } else {
            self.dirty_run = 0;
            self.clean_run += 1;
            if self.clean_run >= DECAY_WINDOWS {
                self.clean_run = 0;
                self.steps = self.steps.saturating_add(1);
            }
        }
    }

    /// The seed or the anchor — what the decay climbs FROM.
    pub fn base_bps(&self) -> Option<u32> {
        self.anchor_bps.or(self.seed_bps)
    }

    /// What stands in for a measurement while there is none. `None` = no
    /// prior in force: an unremembered pair that has measured nothing, or
    /// one whose prior has decayed all the way to the band — from there on
    /// the session must be byte-for-byte the unremembered one (nominal
    /// floor, nominal queue budget), not one carrying a residual 15 % relief.
    pub fn stand_in_bps(&self) -> Option<u32> {
        let base = self.base_bps()?;
        if !self.decay {
            return Some(base);
        }
        let (num, den) = if self.anchor_bps.is_some() {
            (DECAY_ANCHORED_NUM, DECAY_ANCHORED_DEN)
        } else {
            (DECAY_NUM, DECAY_DEN)
        };
        let mut v = u64::from(base);
        if self.steps >= 0 {
            for _ in 0..self.steps {
                if v >= u64::from(self.band_bps) {
                    break;
                }
                v = v * num / den;
            }
        } else {
            for _ in 0..self.steps.unsigned_abs() {
                v = v * den / num;
            }
        }
        let v = v.max(1);
        (v < u64::from(self.band_bps)).then_some(v as u32)
    }

    /// Net steps from the base (heartbeat / tests).
    pub fn steps(&self) -> i32 {
        self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BAND: u32 = 1_500_000;

    #[test]
    fn no_seed_and_nothing_measured_is_no_prior() {
        let mut p = RatePrior::new(None, BAND, true);
        assert_eq!(p.stand_in_bps(), None);
        for _ in 0..100 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), None, "clean time cannot invent a prior");
        // A zero seed is no seed.
        assert_eq!(RatePrior::new(Some(0), BAND, true).stand_in_bps(), None);
    }

    #[test]
    fn the_seed_stands_in_until_ten_clean_windows_then_steps_by_a_quarter() {
        let mut p = RatePrior::new(Some(200_000), BAND, true);
        assert_eq!(p.stand_in_bps(), Some(200_000));
        for _ in 0..9 {
            p.on_window(None, false);
        }
        assert_eq!(
            p.stand_in_bps(),
            Some(200_000),
            "nine windows is not a step"
        );
        p.on_window(None, false);
        assert_eq!(p.stand_in_bps(), Some(250_000));
        for _ in 0..10 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(312_500));
    }

    /// The field session: 200 kbps remembered, nothing ever measured, every
    /// window clean. The stand-in must reach the band within the session
    /// instead of holding it at the floor for four minutes.
    #[test]
    fn an_unmeasured_prior_decays_away_inside_a_session() {
        let mut p = RatePrior::new(Some(200_000), BAND, true);
        let mut windows = 0;
        while p.stand_in_bps().is_some() {
            p.on_window(None, false);
            windows += 1;
            assert!(windows <= 120, "the decay must not take longer than ~2 min");
        }
        // ~10 steps of ×1.25 from 200 k: 200→250→312→390→488→610→763→954→
        // 1192→1490→(≥ band ⇒ gone).
        assert!(
            (90..=110).contains(&windows),
            "expected the prior gone after ~100 clean windows, took {windows}"
        );
        // And it stays gone — the session is the unremembered one now.
        for _ in 0..50 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), None);
        // The base is still known (the memory write-back may want it).
        assert_eq!(p.base_bps(), Some(200_000));
    }

    /// The pipe pushing back with nothing measured walks the prior DOWN —
    /// the hazard this closes is a floor a few percent above the pipe,
    /// growing a queue too slowly for any measurement to latch.
    #[test]
    fn push_back_without_a_measurement_steps_the_prior_down() {
        let mut p = RatePrior::new(Some(200_000), BAND, true);
        for _ in 0..20 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(312_500));
        // One pushed-back window is a lump, not a verdict.
        p.on_window(None, true);
        assert_eq!(p.stand_in_bps(), Some(312_500));
        // Two running is a step down; it also discards partial progress
        // toward the next step up.
        p.on_window(None, true);
        assert_eq!(p.stand_in_bps(), Some(250_000));
        assert_eq!(p.steps(), 1);
        for _ in 0..2 {
            p.on_window(None, true);
        }
        assert_eq!(p.stand_in_bps(), Some(200_000));
        // Below the seed is allowed: the pipe is slower than remembered.
        for _ in 0..2 {
            p.on_window(None, true);
        }
        assert_eq!(p.stand_in_bps(), Some(160_000));
        assert_eq!(p.steps(), -1);
        // Clean again: the climb resumes from where it is, ten windows a step.
        for _ in 0..10 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(200_000));
    }

    /// A single pushed-back window between clean ones only resets the
    /// progress toward the next step up; it does not step down.
    #[test]
    fn a_lone_dirty_window_costs_only_the_partial_progress() {
        let mut p = RatePrior::new(Some(200_000), BAND, true);
        for _ in 0..10 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(250_000));
        for _ in 0..9 {
            p.on_window(None, false);
        }
        p.on_window(None, true);
        assert_eq!(
            p.stand_in_bps(),
            Some(250_000),
            "one lump: no step either way"
        );
        for _ in 0..10 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(312_500));
    }

    /// A measurement is the end of the belief: it becomes the base, and the
    /// decay starts over from it once the measurement is gone.
    #[test]
    fn a_live_measurement_re_anchors_and_restarts_the_decay() {
        let mut p = RatePrior::new(Some(200_000), BAND, true);
        for _ in 0..30 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(390_625));
        // The viewer reports a 300 kbps pipe (the probe found the truth).
        p.on_window(Some(300_000), true);
        assert_eq!(p.base_bps(), Some(300_000));
        assert_eq!(p.stand_in_bps(), Some(300_000));
        assert_eq!(p.steps(), 0);
        // While the measurement keeps arriving the base tracks it.
        p.on_window(Some(280_000), false);
        assert_eq!(p.stand_in_bps(), Some(280_000));
        // Gone again: decay from the measured value, not from the seed —
        // and at the gentler MEASURED rate (×1.1), since a re-probe of a
        // pipe measured a moment ago should stay inside what the link loop
        // can answer before the next step.
        for _ in 0..10 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(308_000));
        for _ in 0..10 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(338_800));
        // And the anchored step down is the same gentle ÷1.1.
        for _ in 0..2 {
            p.on_window(None, true);
        }
        assert_eq!(p.stand_in_bps(), Some(308_000));
    }

    /// A measurement at or above the band says the pipe is NOT slow: no
    /// prior is in force (no relief, nominal budget), exactly as if the
    /// pair had never been remembered.
    #[test]
    fn a_measurement_at_or_above_the_band_ends_the_prior() {
        let mut p = RatePrior::new(Some(200_000), BAND, true);
        p.on_window(Some(3_000_000), true);
        assert_eq!(p.stand_in_bps(), None);
        assert_eq!(p.base_bps(), Some(3_000_000));
        // A seed at or above the band is never handed in (the governor
        // filters it), but the type must not misbehave if it were.
        let fast = RatePrior::new(Some(6_000_000), BAND, true);
        assert_eq!(fast.stand_in_bps(), None);
    }

    /// The kill switch is FR-59 P8 verbatim: the seed is a constant.
    #[test]
    fn with_decay_off_the_seed_is_a_constant() {
        let mut p = RatePrior::new(Some(200_000), BAND, false);
        for _ in 0..200 {
            p.on_window(None, false);
        }
        assert_eq!(p.stand_in_bps(), Some(200_000));
        // A measurement still re-anchors — P8 never had that, but the
        // measurement outranks the seed at every consumer anyway, so the
        // only effect is what the memory records at session end.
        p.on_window(Some(900_000), true);
        assert_eq!(p.stand_in_bps(), Some(900_000));
        // And the raw seed above the band is returned raw with decay off,
        // exactly as `open_seed_bps` was consumed before.
        let fast = RatePrior::new(Some(6_000_000), BAND, false);
        assert_eq!(fast.stand_in_bps(), Some(6_000_000));
    }
}
