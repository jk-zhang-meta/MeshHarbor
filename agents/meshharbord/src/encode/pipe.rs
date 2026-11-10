// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-79 V3b / FR-74 — ONE belief about what the path carries.
//!
//! # Three symptoms, one defect
//!
//! Measured on the fleet across 2026-09-09/10, on three different hosts and
//! two different carriers:
//!
//! 1. **The gate cannot fire on a relay.** CORPLAP-3 ran a whole session with
//!    `goodput_bps=None` and `goodput_samples=(0, 5)` — five windows of blocked
//!    time, every one under `goodput::MIN_WINDOW_BLOCKED`, nothing accepted. So
//!    FR-79 V5's rule ("a stall while sending above the measured pipe is our
//!    fault") had no measurement to compare against and was inert on that host.
//! 2. **The ceiling sawtooths on a direct path.** Regal-Elena-PZ, 1920×1080
//!    HEVC over a direct carrier at 6–11 ms paint age: the ceiling is a
//!    bits-per-pixel CONSTANT (0.625 bpp = 38,880,000), the blocked-send
//!    goodput measured **6,028,814**, and the target oscillated between them
//!    with a two-to-three minute period for the life of the session — 4.5
//!    minutes to first reach the ceiling, then collapse to ~5.3 M, climb,
//!    collapse to ~6.1 M. Every collapse is a visible softening.
//! 3. **The rate memory has almost nothing to remember.** CORPLAP-2 accepted
//!    exactly ONE sample per session in two very different link conditions.
//!
//! Those are one defect: **there is no trustworthy, always-available estimate
//! of what the path carries.** Every loop that needs one either invents a
//! constant (FR-74's bpp ceiling), goes silent (FR-79's gate), or remembers a
//! number nobody measured (the pair memory).
//!
//! # What this type fixes, and it is a distinction the old code did not make
//!
//! Two different things were being averaged together by `pipe_bps`'s
//! `min(goodput, link_rx)`:
//!
//! - **A demonstrated floor** — *"this path carried at least X."* Available
//!   from EVERY window on EVERY carrier, because the viewer reports its
//!   arrival rate whether or not anything is congested. It needs no
//!   congestion, and it is a hard lower bound: those bytes actually arrived.
//! - **A capacity estimate** — *"this path carries about X."* Only available
//!   when the path pushed back: a blocked send, or the viewer's arrival rate
//!   while its queue is growing. It is an estimate of the LIMIT.
//!
//! Taking `min` of the two is wrong in the direction that hurts: an arrival
//! rate measured while the sender was idle is not a capacity, and a
//! blocked-send sample taken during one burst is not a reason to disbelieve a
//! delivery that already happened. Symptom 2 is exactly that error — the
//! collapse target was a 6 Mbps capacity sample on a path that had just
//! delivered far more.
//!
//! So: a floor is never allowed to lower the anchor, and the anchor is never
//! `None` once anything has been delivered.
//!
//! ⚠️ The floor is a MAX, not an average. An average of delivered rates
//! measures the CONTENT (an idle desktop sends ~300 kbps through a gigabit
//! path); only the peak says anything about the path.
//!
//! # ⚠️⚠️ What a quiet screen proves: nothing. The overnight shadow, 83 samples
//!
//! The first version expired the floor after 30 s, so that "a path which
//! genuinely degraded is not pinned to its old peak". 300 sweeps across the
//! fleet showed that reasoning is wrong, because it cannot tell a degraded path
//! from a still screen. Direct sessions spanned **11 kbps to 24.7 Mbps**, median
//! 270 kbps — and the extremes are the SAME HOSTS:
//!
//! ```text
//! CORPLAP-3  19:46-20:02  s=6aa307be  belief = 4.8 - 8.4 Mbps    (content moving)
//! CORPLAP-3  13:25-13:54  s=6aa3d669  belief = 12.8 kbps         (static screen)
//!                                     tgt=34,560,000  n=(10696, 0)
//! CORPLAP-2  19:39        s=6aa30771  belief = 24.7 Mbps
//! CORPLAP-1  07:40-07:44  s=6aa3aff5  belief = 10.3 - 10.8 Mbps
//! ```
//!
//! A host that demonstrated 8.4 Mbps read **13 kbps** hours later with nobody
//! typing, and the floor kept expiring to `None` entirely between reports. Had
//! FR-74 P5 anchored a ceiling on that, a still screen would have collapsed the
//! ceiling to the legibility floor and STARVED the next burst — making the
//! symptom this whole arc exists to fix strictly worse.
//!
//! So the rule is evidential, not temporal: **a delivery raises the floor and
//! nothing but contrary evidence lowers it.** A capacity sample below the floor
//! is that contrary evidence — the path got smaller, and the old demonstration
//! stops being true. Time is not evidence. Quiet is not evidence.
//!
//! ⚠️ The cost, accepted knowingly: a path that silently degrades keeps an
//! optimistic floor until something pushes back. That is the right trade,
//! because the floor only ever feeds a CEILING — a bound saying "you may try" —
//! and the capacity path cuts the moment trying fails. An optimistic bound
//! costs one burst; a pessimistic one costs every burst.
//!
//! # ⚠️⚠️ The two questions are NOT interchangeable, and the API says so
//!
//! There is deliberately no single `believed_bps()`. The first shadow session
//! showed why, within minutes of shipping — CORPLAP-1 on `relay:derp/tcp`,
//! `0.4.98`, an idle desktop:
//!
//! ```text
//! goodput_bps=None  goodput_samples=(0, 0)
//! pipe_belief=(Some(1802656), Some(1802656), None)   pipe_belief_n=(35, 0)
//! target_bps=3000000   viewer_age_ms=Some(59)
//! ```
//!
//! 35 deliveries, ZERO capacity samples, nothing congested, paint age 59 ms —
//! a perfectly healthy session. A rule that read `1,802,656` as "the pipe"
//! would have computed `3.0 M > 1.2 × 1.8 M` and concluded the session was
//! overdriving. It was not: 1.8 Mbps is what an idle desktop WEIGHS, and the
//! path was never asked for more.
//!
//! So each consumer must name its question:
//!
//! | question | accessor | `None` means |
//! |---|---|---|
//! | *"am I sending more than this path will take?"* (FR-79 V5) | [`Pipe::capacity_bps`] | no push-back ⇒ **no claim to contradict** ⇒ do not cut |
//! | *"what may the ceiling be?"* (FR-74 P5) | [`Pipe::ceiling_anchor_bps`] | nothing measured ⇒ fall back to the bpp bound |
//! | *"what has this path already proven?"* | [`Pipe::floor_bps`] | — |
//!
//! A floor is a LOWER BOUND. It says the path carried at least X. It never
//! says the path would refuse X + 1, and no amount of idle delivery makes it
//! say that.

use std::time::{Duration, Instant};

/// ⚠️⚠️ There is deliberately NO time window on the floor. The first version of
/// this type expired it after 30 s, and the overnight shadow showed why that is
/// wrong — see the module header's "what a quiet screen proves" section. A
/// demonstrated delivery is a FACT about the path; a quiet screen is not
/// evidence against it. Only contrary evidence retires it.
///
/// Kept as the doc anchor for that decision; nothing reads it.
pub const FLOOR_NEVER_EXPIRES: () = ();

/// A capacity estimate expires on the same clock the goodput estimator uses,
/// so "the path pushed back a minute ago" stops being an argument.
pub const CAPACITY_TTL: Duration = super::goodput::CONFIDENCE_TTL;

/// What this session believes about the path, and how it came to believe it.
#[derive(Debug, Default, Clone, Copy)]
pub struct Pipe {
    /// The largest rate the path has been DEMONSTRATED to carry, and when.
    floor: Option<(u32, Instant)>,
    /// What the path pushed back at, and when.
    capacity: Option<(u32, Instant)>,
    /// Counters for the heartbeat: deliveries folded, capacities folded.
    delivered_n: u32,
    capacity_n: u32,
}

impl Pipe {
    /// Every window, unconditionally: bytes that ARRIVED. Needs no congestion
    /// and no blocked send, which is the whole point — it is the one
    /// observation a relay-TCP session reliably produces.
    ///
    /// Keeps the MAX for the life of the session: a higher delivery always
    /// wins, and only [`Self::observe_capacity`] with a smaller number takes it
    /// back down.
    pub fn observe_delivered(&mut self, bps: u32, now: Instant) {
        if bps == 0 {
            return;
        }
        self.delivered_n = self.delivered_n.saturating_add(1);
        match self.floor {
            Some((best, _)) if bps <= best => {}
            _ => self.floor = Some((bps, now)),
        }
    }

    /// Only when the path PUSHED BACK: a blocked-send goodput sample, or the
    /// viewer's arrival rate while its transit queue was growing.
    ///
    /// ⚠️ This is also the ONLY thing that moves a floor DOWN, and it moves it
    /// by [`rate_memory::damp`] rather than snapping to it — the same
    /// down-fast/up-slow asymmetry FR-79 V4 already uses for the pair memory,
    /// not a second law.
    ///
    /// Snapping was wrong in both directions and the tests caught it:
    /// a single blocked-send sample of 6.03 Mbps must NOT erase a 20 Mbps
    /// delivery (that is the Regal sawtooth's collapse, rebuilt inside the
    /// estimator), but a path that has genuinely shrunk must not keep an
    /// optimistic floor forever either (that is the 38.88 Mbps constant, with
    /// extra steps). Damping says: one sample barely moves it, sustained
    /// evidence converges on it.
    pub fn observe_capacity(&mut self, bps: u32, now: Instant) {
        if bps == 0 {
            return;
        }
        self.capacity_n = self.capacity_n.saturating_add(1);
        self.capacity = Some((bps, now));
        // ⚠️ A capacity sample is ALSO a delivery. A blocked-send goodput of X
        // means X bits per second actually got through while the sender was
        // blocked — those bytes arrived. So it feeds the floor by the same law
        // as any other delivery: raise outright, lower damped.
        //
        // Missing this cost the anchor a real measurement. Field 2026-09-12,
        // CORPLAP-3 session `6aa53186`: capacity measured 13,163,844 at 11:04,
        // and four minutes later — one `CAPACITY_TTL` — the anchor had fallen
        // back to a content-driven floor of 4,050,945 while the target ran to
        // the 34,560,000 constant. A ceiling anchored there would cap a path
        // just measured at 13 Mbps to about 5.
        match self.floor {
            Some((floor, _)) if bps < floor => {
                self.floor = Some((super::rate_memory::damp(floor, bps), now));
            }
            Some((floor, _)) if bps <= floor => {}
            _ => self.floor = Some((bps, now)),
        }
    }

    /// The demonstrated lower bound: the most this path has EVER been shown to
    /// carry this session, minus anything a later push-back contradicted.
    ///
    /// ⚠️ No staleness filter, deliberately. See [`FLOOR_NEVER_EXPIRES`].
    pub fn floor_bps(&self, _now: Instant) -> Option<u32> {
        self.floor.map(|(bps, _)| bps)
    }

    /// The pushed-back estimate, while it is still fresh.
    pub fn capacity_bps(&self, now: Instant) -> Option<u32> {
        self.capacity
            .filter(|(_, at)| now.duration_since(*at) <= CAPACITY_TTL)
            .map(|(bps, _)| bps)
    }

    /// The anchor a CEILING may be built on: the most this path has been shown
    /// to be worth, from either kind of evidence.
    ///
    /// ⚠️ `max`, never `min`. A capacity estimate below something the path has
    /// just been shown to deliver is the estimate being wrong, not the
    /// delivery: the bytes arrived. Reading it the other way is symptom 2.
    ///
    /// ⚠️⚠️ **This is NOT the number to compare a target against when asking
    /// "am I sending more than this path can take?"** — use
    /// [`Self::capacity_bps`] for that, and accept `None` as "no claim to
    /// contradict". A floor is a LOWER BOUND: it says the path carried at
    /// least X, never that it would refuse X + 1.
    ///
    /// Measured the day this type shipped, CORPLAP-1 on `relay:derp/tcp`,
    /// `0.4.98`: an idle desktop gave `floor = 1,802,656` from 35 deliveries
    /// and ZERO capacity samples, while the target sat at 3,000,000. Nothing
    /// had pushed back and nothing was wrong — but a rule reading this as
    /// "the pipe" would have found 3.0 M > 1.2 × 1.8 M and cut a session that
    /// was never overdriving anything. The floor was the CONTENT's weight, not
    /// the path's limit.
    pub fn ceiling_anchor_bps(&self, now: Instant) -> Option<u32> {
        match (self.capacity_bps(now), self.floor_bps(now)) {
            (Some(c), Some(f)) => Some(c.max(f)),
            (c, f) => c.or(f),
        }
    }

    /// `(deliveries folded, capacities folded)` for the heartbeat — the pair
    /// that says WHY the belief is what it is, and the counter that authorises
    /// the deletions in FR-79 V3b's own acceptance.
    pub fn counts(&self) -> (u32, u32) {
        (self.delivered_n, self.capacity_n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    /// Symptom 1, CORPLAP-3: a session that never blocks a send still knows
    /// something about its path. Before this type it knew nothing at all, and
    /// FR-79 V5's rule was inert there.
    #[test]
    fn a_session_that_never_pushed_back_still_has_a_belief() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(900_000, now);
        p.observe_delivered(1_200_000, now + Duration::from_secs(1));
        assert_eq!(p.capacity_bps(now + Duration::from_secs(1)), None);
        assert_eq!(
            p.ceiling_anchor_bps(now + Duration::from_secs(1)),
            Some(1_200_000),
            "the belief falls back to what was demonstrably delivered"
        );
    }

    /// Symptom 2, Regal-Elena-PZ: a capacity sample of 6.03 Mbps arrives on a
    /// path that has just delivered 20 Mbps. The old `min` rule read 6 M and
    /// the target collapsed to it; the delivery is the harder fact.
    #[test]
    fn one_capacity_sample_does_not_collapse_the_belief_onto_itself() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(20_000_000, now);
        let t = now + Duration::from_secs(1);
        p.observe_capacity(6_028_814, t);
        let anchor = p.ceiling_anchor_bps(t).expect("an anchor");
        // ALPHA_DOWN halves the gap: 20 M -> ~13 M, not 6.03 M. Collapsing onto
        // the sample IS the Regal sawtooth, rebuilt inside the estimator.
        assert_eq!(anchor, 13_014_407);
        assert!(
            anchor > 6_028_814 * 2,
            "a single blocked-send sample must not erase a 20 Mbps delivery"
        );
    }

    /// ...but SUSTAINED push-back converges on it, so a path that really did
    /// shrink is believed at its new size rather than its old peak. Without
    /// this the floor would be the 38.88 Mbps constant with extra steps.
    #[test]
    fn sustained_push_back_converges_the_floor_onto_the_capacity() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(20_000_000, now);
        let mut t = now;
        for _ in 0..8 {
            t += Duration::from_secs(1);
            p.observe_capacity(6_028_814, t);
        }
        let anchor = p.ceiling_anchor_bps(t).expect("an anchor");
        assert!(
            anchor < 6_500_000,
            "eight consistent samples should converge on the measurement, got {anchor}"
        );
    }

    /// ...but on a path that really is slow, the capacity estimate stands: the
    /// floor is whatever that path actually delivered, which is also small.
    #[test]
    fn a_genuinely_slow_path_believes_its_measurement() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(1_050_000, now);
        p.observe_capacity(1_058_145, now + Duration::from_secs(1));
        assert_eq!(
            p.ceiling_anchor_bps(now + Duration::from_secs(1)),
            Some(1_058_145)
        );
    }

    /// The floor is a MAX, not an average — an idle desktop delivering
    /// 300 kbps through a fast path must not talk the belief down.
    #[test]
    fn an_idle_stretch_does_not_talk_the_floor_down() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(18_000_000, now);
        for i in 1..8 {
            p.observe_delivered(300_000, now + Duration::from_secs(i));
        }
        assert_eq!(p.floor_bps(now + Duration::from_secs(8)), Some(18_000_000));
    }

    /// The overnight shadow, verbatim: CORPLAP-3 demonstrated 8.4 Mbps at
    /// 20:02 and read 12,818 bps at 13:25 the next day with a static screen and
    /// `n=(10696, 0)` — ten thousand deliveries, not one push-back.
    ///
    /// A still screen is NOT evidence the path shrank. The floor must survive
    /// it, or FR-74 P5's ceiling would collapse on an idle desktop and starve
    /// the next burst — the very symptom this arc exists to remove.
    #[test]
    fn hours_of_a_still_screen_do_not_retire_what_the_path_demonstrated() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(8_409_584, now);
        // Seventeen hours of an idle desktop, one report a second.
        let mut t = now;
        for _ in 0..2_000 {
            t += Duration::from_secs(1);
            p.observe_delivered(12_818, t);
        }
        assert_eq!(
            p.floor_bps(t),
            Some(8_409_584),
            "the demonstration stands; quiet is not contrary evidence"
        );
        assert_eq!(p.counts(), (2_001, 0));
    }

    /// A push-back is the ONLY thing that moves the floor down, and it damps
    /// rather than snaps — see `one_capacity_sample_does_not_collapse_the_
    /// belief_onto_itself` and `sustained_push_back_converges_the_floor_onto_
    /// the_capacity` for the two halves of that law.
    #[test]
    fn nothing_but_a_push_back_moves_the_floor_down() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(18_000_000, now);
        let mut t = now;
        // Deliveries below the floor, however many, never lower it.
        for _ in 0..50 {
            t += Duration::from_secs(1);
            p.observe_delivered(20_000, t);
        }
        assert_eq!(p.floor_bps(t), Some(18_000_000));
        // One push-back does.
        p.observe_capacity(2_000_000, t);
        assert!(p.floor_bps(t).expect("a floor") < 18_000_000);
    }

    /// Field 2026-09-12, CORPLAP-3 session `6aa53186`, verbatim: a capacity of
    /// 13,163,844 measured at 11:04 against a content-driven floor of
    /// 4,050,945. One `CAPACITY_TTL` later the capacity had expired and the
    /// anchor fell back to the floor, while the target ran to the 34,560,000
    /// constant.
    ///
    /// A blocked-send goodput IS a delivery — those bytes got through at that
    /// rate — so it must raise the floor, and the anchor must survive the
    /// capacity expiring.
    #[test]
    fn a_capacity_sample_survives_its_own_expiry_by_raising_the_floor() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(4_050_945, now);
        p.observe_capacity(13_163_844, now + Duration::from_secs(1));
        let after_ttl = now + Duration::from_secs(1) + CAPACITY_TTL + Duration::from_secs(1);
        assert_eq!(p.capacity_bps(after_ttl), None, "the estimate aged out");
        assert_eq!(
            p.ceiling_anchor_bps(after_ttl),
            Some(13_163_844),
            "but the path demonstrably carried 13.16 Mbps, and that does not \
             stop being true when the estimate expires"
        );
    }

    /// A capacity estimate expires on the goodput estimator's own clock, so a
    /// push-back from a minute ago stops steering the session.
    #[test]
    fn a_capacity_estimate_expires() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_capacity(1_000_000, now);
        assert_eq!(p.capacity_bps(now + CAPACITY_TTL), Some(1_000_000));
        assert_eq!(
            p.capacity_bps(now + CAPACITY_TTL + Duration::from_secs(1)),
            None
        );
    }

    /// The first shadow session, verbatim: CORPLAP-1 on `relay:derp/tcp`,
    /// `0.4.98`, an idle desktop. 35 deliveries, ZERO capacity samples, target
    /// 3,000,000, paint age 59 ms — healthy.
    ///
    /// The anchor has a number (a ceiling may be built on it), but the
    /// over-drive question must still answer `None`: nothing pushed back, so
    /// there is no claim to contradict. Reading the anchor instead would have
    /// cut a session that was never overdriving — the floor is what the
    /// CONTENT weighed.
    #[test]
    fn a_healthy_idle_session_offers_a_ceiling_anchor_but_no_overdrive_verdict() {
        let now = t0();
        let mut p = Pipe::default();
        for i in 0..35 {
            p.observe_delivered(1_802_656, now + Duration::from_millis(i * 500));
        }
        let t = now + Duration::from_millis(35 * 500);
        assert_eq!(p.counts(), (35, 0), "35 deliveries, no push-back");
        assert_eq!(
            p.ceiling_anchor_bps(t),
            Some(1_802_656),
            "a ceiling may be anchored on what was demonstrably delivered"
        );
        assert_eq!(
            p.capacity_bps(t),
            None,
            "but NOTHING pushed back, so there is no capacity claim — and a \
             target of 3,000,000 here is not evidence of overdriving"
        );
    }

    /// Nothing observed at all is still `None` — the honest answer before the
    /// first frame, and the one FR-79 V5 reads as "no claim to contradict".
    #[test]
    fn an_untouched_pipe_believes_nothing() {
        assert_eq!(Pipe::default().ceiling_anchor_bps(t0()), None);
        assert_eq!(Pipe::default().counts(), (0, 0));
    }

    /// Zero is not an observation — a window that delivered nothing says
    /// nothing about the path, and must not become its floor.
    #[test]
    fn a_zero_window_is_not_evidence() {
        let now = t0();
        let mut p = Pipe::default();
        p.observe_delivered(0, now);
        p.observe_capacity(0, now);
        assert_eq!(p.ceiling_anchor_bps(now), None);
        assert_eq!(p.counts(), (0, 0));
    }
}
