// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-63 — slow-start for the session opener.
//!
//! # Why
//!
//! A session commits to a bitrate before it has any evidence about the pipe,
//! and the same host over-drove from BOTH directions on the same day
//! (CORPLAP-1 over a corp VPN, 2026-09-02/03):
//!
//! - opened at the **remembered** rate `6_134_627` → viewer age **6287 ms**;
//! - opened at the **nominal** relay cap `2_550_000` into a path measured at
//!   ~`213_000` → queue 444 ms, viewer age **1550 ms**, then six windows
//!   collapsing 921k → 783k → 566k → 347k → 295k → 251k → 213k.
//!
//! The second happened with the ceiling learner switched OFF, which is the
//! point: **no constant is safe**, because a constant is an assumption about a
//! band. A remembered rate is wrong when the network changed; the nominal is
//! wrong when the path is slow. FR-59 learned this for the *floor*; this is the
//! same lesson one level up, for the *opener*.
//!
//! # What
//!
//! Open at a rate almost any path carries, then **double while the evidence
//! stays clean** — the classic slow-start shape. The cost of opening too low is
//! a few seconds of soft picture; the cost of opening too high is a multi-second
//! stall the controller then needs ~12 s to dig out of. Those are not
//! symmetric, so the opener should be timid and fast rather than bold and slow.
//!
//! ⚠️ Growth is **exponential, not the additive step the AIMD uses**. An
//! additive ramp would take ~21 windows to cross 500 k → 2.5 M and would punish
//! every fast pair to protect the slow ones; doubling crosses it in 3.
//!
//! ⚠️ This module is PURE — no clock, no I/O, no encoder types. The caller
//! decides what "a clean window" means and when to stop.

/// Where a session opens, before any evidence. Low enough that the measured
/// 213 kbps field path is over-driven by ~1.4× for a single window instead of
/// 12×, and high enough to be legible while the ramp runs.
pub const OPEN_BPS: u32 = 300_000;

/// Multiplicative growth per clean window, in percent. ×2 — the whole point is
/// to reach a fast pair's real rate in a few windows rather than tens.
pub const GROWTH_PCT: u64 = 200;

/// FR-63 — the opener's ramp. Construct at session start, feed it one verdict
/// per window, and use [`SlowStart::target_bps`] as the ceiling the rate
/// controller may aim at until [`SlowStart::done`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlowStart {
    target_bps: u32,
    ceiling_bps: u32,
    done: bool,
}

impl SlowStart {
    /// Open at [`OPEN_BPS`], lifted to `floor_bps` and capped by `ceiling_bps`.
    ///
    /// ⚠️ The floor wins over [`OPEN_BPS`]: a caller that has *already* proven a
    /// higher rate (FR-59 P8's remembered-slow-pair open, say) must not be
    /// dragged back down by this. Slow-start only ever removes an
    /// **unevidenced** commitment.
    ///
    /// ⚠️ A ceiling at or below the open rate means there is nothing to ramp —
    /// `done` immediately, so a caller cannot loop forever waiting for it.
    pub fn new(floor_bps: u32, ceiling_bps: u32) -> Self {
        let ceiling = ceiling_bps.max(1);
        let target = OPEN_BPS.max(floor_bps).min(ceiling);
        Self {
            target_bps: target,
            ceiling_bps: ceiling,
            done: target >= ceiling,
        }
    }

    /// The rate the session may aim at right now.
    pub fn target_bps(&self) -> u32 {
        self.target_bps
    }

    /// Has the ramp finished — reached the ceiling, or been ended by evidence?
    /// Once true the caller hands control back to the normal rate controller.
    pub fn done(&self) -> bool {
        self.done
    }

    /// One window passed with no congestion: double, capped at the ceiling.
    /// Returns the new target.
    pub fn on_clean_window(&mut self) -> u32 {
        if self.done {
            return self.target_bps;
        }
        let grown =
            (u64::from(self.target_bps) * GROWTH_PCT / 100).min(u64::from(self.ceiling_bps)) as u32;
        self.target_bps = grown;
        if self.target_bps >= self.ceiling_bps {
            self.done = true;
        }
        self.target_bps
    }

    /// Evidence that the pipe is not keeping up. Slow-start ENDS here — it does
    /// not halve and continue.
    ///
    /// 🔑 The ramp's only job is to find the band without over-driving; once
    /// congestion has spoken there IS evidence, and the normal controller's
    /// decrease law is better at using it than a second guess from here. The
    /// target is left where it was so the caller can back off from a real
    /// number rather than from a constant.
    pub fn on_congestion(&mut self) -> u32 {
        self.done = true;
        self.target_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_low_regardless_of_a_high_ceiling() {
        // The two field ceilings that over-drove: the nominal relay cap and a
        // stale-high remembered rate. Neither may be the opening target.
        for ceiling in [2_550_000, 6_134_627] {
            let ss = SlowStart::new(0, ceiling);
            assert_eq!(ss.target_bps(), OPEN_BPS);
            assert!(!ss.done());
        }
    }

    #[test]
    fn doubles_while_clean_and_stops_at_the_ceiling() {
        let mut ss = SlowStart::new(0, 2_550_000);
        assert_eq!(ss.target_bps(), 300_000);
        assert_eq!(ss.on_clean_window(), 600_000);
        assert_eq!(ss.on_clean_window(), 1_200_000);
        assert_eq!(ss.on_clean_window(), 2_400_000);
        assert!(!ss.done(), "still below the ceiling");
        assert_eq!(ss.on_clean_window(), 2_550_000, "capped, never overshoots");
        assert!(ss.done());
        // Idempotent once finished.
        assert_eq!(ss.on_clean_window(), 2_550_000);
    }

    #[test]
    fn a_fast_pair_reaches_its_ceiling_in_a_handful_of_windows() {
        // The cost of a timid open must stay small for pairs that deserve rate:
        // 300k -> 6.13M is 5 windows, not the ~40 an additive step would need.
        let mut ss = SlowStart::new(0, 6_134_627);
        let mut windows = 0;
        while !ss.done() {
            ss.on_clean_window();
            windows += 1;
            assert!(windows < 10, "ramp must not crawl");
        }
        assert_eq!(windows, 5);
    }

    /// Regression fixture from the real trace (CORPLAP-1, 2026-09-03): the pipe
    /// measured ~213 kbps while the session opened at the 2.55 M nominal —
    /// 12× over, which cost 444 ms of queue and a 1550 ms paint.
    #[test]
    fn the_field_path_is_never_over_driven_more_than_slightly() {
        const MEASURED_PIPE_BPS: u32 = 213_180;
        const NOMINAL_THAT_OVER_DROVE: u32 = 2_550_000;

        // What shipped: a 12x over-drive on the very first frame.
        let old_ratio = f64::from(NOMINAL_THAT_OVER_DROVE) / f64::from(MEASURED_PIPE_BPS);
        assert!(old_ratio > 11.0, "sanity: the field really was ~12x over");

        // Slow-start's opening commitment on the same path.
        let ss = SlowStart::new(0, NOMINAL_THAT_OVER_DROVE);
        let new_ratio = f64::from(ss.target_bps()) / f64::from(MEASURED_PIPE_BPS);
        assert!(
            new_ratio < 1.5,
            "opening over-drive must be marginal, got {new_ratio:.2}x"
        );
    }

    #[test]
    fn congestion_ends_the_ramp_without_guessing_a_new_rate() {
        let mut ss = SlowStart::new(0, 2_550_000);
        ss.on_clean_window(); // 600k
        let at_congestion = ss.on_congestion();
        assert_eq!(at_congestion, 600_000, "leaves a real number, not a guess");
        assert!(ss.done());
        // A later clean window must not resurrect the ramp.
        assert_eq!(ss.on_clean_window(), 600_000);
    }

    #[test]
    fn a_proven_floor_wins_over_the_open_rate() {
        // FR-59 P8 opens a remembered-slow pair AT its remembered rate; that is
        // evidence, so slow-start must not drag it down. And a floor above the
        // ceiling still cannot exceed the ceiling.
        let ss = SlowStart::new(900_000, 2_550_000);
        assert_eq!(ss.target_bps(), 900_000);
        let ss = SlowStart::new(9_000_000, 2_550_000);
        assert_eq!(ss.target_bps(), 2_550_000);
        assert!(ss.done(), "nothing left to ramp");
    }

    #[test]
    fn a_degenerate_ceiling_terminates_immediately() {
        let mut ss = SlowStart::new(0, 0);
        assert!(ss.done(), "a zero ceiling must not loop");
        assert_eq!(ss.on_clean_window(), ss.target_bps());
    }
}
