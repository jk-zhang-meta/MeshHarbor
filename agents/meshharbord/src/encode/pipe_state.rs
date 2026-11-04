// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-71 T1a — which plane is the limiter this window: the sender, the path,
//! or the browser.
//!
//! # Why this exists
//!
//! Every rate loop in `encode/` reads one number, the viewer's paint age, and
//! every one of them reads an excursion as "the encoder produced too much".
//! On 2026-09-04 (CORPLAP-3, session `6a9abaa8`) a DERP/TCP head-of-line block
//! held frames in transit for 4.9 s while the sender's queue held 1485 bytes,
//! the worst pump pass was 28 ms and the encoder averaged 14 ms — nothing
//! sender-side was wrong, and the AIMD and the FR-15 age loop cut the rate
//! into a link that was never the limiter. FR-70 M0 split the age
//! (`viewer_rate::AgeSplit`: sender / transit / viewer); this module turns the
//! split, plus what the governor already knows about its own send queue, into
//! ONE verdict per viewer window.
//!
//! # The verdict
//!
//! - [`PipeState::Overproduced`] — the sender is the limiter: bytes in flight
//!   at the budget, budget-gate skips, blocked sends, or a send that waited
//!   [`SENDER_WAIT_MS`] or longer. Checked FIRST: whatever the path is doing,
//!   a full send queue is real back-pressure the controller must answer.
//! - [`PipeState::TransitStalled`] — the path is the limiter: the transit
//!   share of the age sits [`TRANSIT_SLACK_MS`] or more over its learned floor
//!   while the browser's share is near its own floor; or a GAP in the viewer's
//!   reports — silence from a viewer that has reported at least once this
//!   session — while the sender kept sending frames through a queue that
//!   passed every sender-side check (finding 4's silent windows). Silence
//!   before the first report is `Unknown`: the first field session on 0.4.67
//!   classified its opening window `TransitStalled` because the viewer's first
//!   report had simply not arrived yet, and a viewer that never reports must
//!   not hold a session forever under T1b.
//! - [`PipeState::ViewerLate`] — the browser is the limiter: its own share is
//!   [`VIEWER_SLACK_MS`] or more over its floor, or it reports `struggling`.
//! - [`PipeState::Clear`] — none of the above.
//! - [`PipeState::Unknown`] — no split this window (a pre-M0 viewer, or an
//!   age the viewer could not stamp): every loop behaves exactly as today.
//!
//! Floors are learned the way the FR-15 age loop learns its floor: the
//! smallest value seen, so a permanently slow path is not a permanent stall
//! and a stall never lowers the floor it is measured against.
//!
//! **T1a is SHADOW**: the verdict is logged and counted, nothing acts on it.
//! T1b (the hold) is a separate switch. Pure — no clocks, no I/O — so it
//! unit-tests on the default build and runs inside the B0 simulator.

/// Transit share this far over its floor is a stall, not jitter. Two hundred
/// milliseconds: FR-15's age slack is 70 ms for a *paint* excursion the loop
/// should act on; a transit *stall* is a coarser event (finding 4 was seconds,
/// the DERP fixture's are 1–4 s) and the cost of a false positive under T1b is
/// a held rate, so the bar is higher.
pub const TRANSIT_SLACK_MS: u16 = 200;
/// Browser share this far over its floor is the browser being late.
pub const VIEWER_SLACK_MS: u16 = 100;
/// A send that waited this long in the queue is the sender being the limiter.
pub const SENDER_WAIT_MS: f64 = 100.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeState {
    Unknown,
    Clear,
    Overproduced,
    TransitStalled,
    ViewerLate,
}

impl PipeState {
    pub fn as_str(self) -> &'static str {
        match self {
            PipeState::Unknown => "unknown",
            PipeState::Clear => "clear",
            PipeState::Overproduced => "overproduced",
            PipeState::TransitStalled => "transit-stalled",
            PipeState::ViewerLate => "viewer-late",
        }
    }

    fn index(self) -> usize {
        match self {
            PipeState::Unknown => 0,
            PipeState::Clear => 1,
            PipeState::Overproduced => 2,
            PipeState::TransitStalled => 3,
            PipeState::ViewerLate => 4,
        }
    }
}

/// The age split for one window, as [`super::viewer_rate::split_age`] hands
/// it out: the sender's share (`None` where the pump keeps no send-wait
/// figure), the transit share and the browser's share, all ms.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SplitMs {
    pub sender_ms: Option<f64>,
    pub transit_ms: u16,
    pub viewer_ms: u16,
}

/// Everything the classifier reads about one viewer window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowSignals {
    /// `None` = no split this window (pre-M0 viewer, or no age report).
    pub split: Option<SplitMs>,
    /// Did the viewer send ANY report this window? (`false` = a report gap.)
    pub reported: bool,
    /// Bytes the sender still holds for this session (the FR-59 P2 ledger)
    /// and the budget the gate compares it against.
    pub inflight_bytes: usize,
    pub budget_bytes: usize,
    /// Frames the byte-budget gate skipped this window.
    pub gate_skips: u32,
    /// Sends the goodput estimator accepted as blocked this window.
    pub blocked_sends: u32,
    /// The longest a frame waited in the send queue this window, ms.
    pub send_wait_max_ms: f64,
    /// Frames the send task wrote this window (0 = the sender was idle, so a
    /// report gap says nothing).
    pub frames_sent: u32,
    /// The viewer's own decode-backlog bit from `rc:decodestat`.
    pub struggling: bool,
}

#[derive(Debug, Default)]
pub struct PipeClassifier {
    transit_floor_ms: Option<u16>,
    viewer_floor_ms: Option<u16>,
    /// Has the viewer reported at all this session? A report GAP is only a
    /// gap once there was something to have a gap in.
    reported_once: bool,
    last: Option<PipeState>,
    counts: [u32; 5],
    /// How many of the `TransitStalled` verdicts came from the report-gap
    /// rule rather than the split. AC2 counts gap-holds and split-holds
    /// separately: the first field sessions showed ~2 % of a long relay
    /// session's windows are report gaps, which is ~1 hold a minute if the
    /// hold acts on them — a number the counter has to carry before the
    /// default flips.
    gap_stalls: u32,
}

impl PipeClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// One verdict per viewer window.
    pub fn classify(&mut self, s: &WindowSignals) -> PipeState {
        if s.reported {
            self.reported_once = true;
        }
        let state = self.decide(s);
        self.last = Some(state);
        self.counts[state.index()] = self.counts[state.index()].saturating_add(1);
        state
    }

    fn decide(&mut self, s: &WindowSignals) -> PipeState {
        // The sender first: a full queue is real back-pressure whatever the
        // path is doing, and it is the one case today's loops are right about.
        let overproduced = (s.budget_bytes > 0 && s.inflight_bytes >= s.budget_bytes)
            || s.gate_skips > 0
            || s.blocked_sends > 0
            || (s.send_wait_max_ms.is_finite() && s.send_wait_max_ms >= SENDER_WAIT_MS);
        if overproduced {
            return PipeState::Overproduced;
        }
        let Some(split) = s.split else {
            // Finding 4's silent windows: the viewer reported nothing while
            // the sender kept writing frames into a queue that passed every
            // sender-side check above. That is the path beyond the sender —
            // not "unknown", and not the sender. (An earlier draft also
            // required the queue to be under half the budget; the finding-4
            // cell showed a keyframe on a ramp step trips that for one
            // window, and the Overproduced screen above already owns the
            // "queue over budget" case.) Only once the viewer HAS reported:
            // the opening window of every session is silent because the
            // first report is still on its way (field, 0.4.67, session
            // `6a9c3933`: window 1 `transit-stalled`, 89 of the next 90
            // `clear`), and a viewer that never reports is not stalled — it
            // is a viewer this classifier knows nothing about.
            return if !s.reported && s.frames_sent > 0 && self.reported_once {
                self.gap_stalls = self.gap_stalls.saturating_add(1);
                PipeState::TransitStalled
            } else {
                PipeState::Unknown
            };
        };
        // Learn the floors from what arrived; a stall never lowers them,
        // because the minimum is what a stall cannot produce.
        let transit_floor = self
            .transit_floor_ms
            .map_or(split.transit_ms, |f| f.min(split.transit_ms));
        self.transit_floor_ms = Some(transit_floor);
        let viewer_floor = self
            .viewer_floor_ms
            .map_or(split.viewer_ms, |f| f.min(split.viewer_ms));
        self.viewer_floor_ms = Some(viewer_floor);

        let transit_excess = split.transit_ms.saturating_sub(transit_floor);
        let viewer_excess = split.viewer_ms.saturating_sub(viewer_floor);
        let transit_over = transit_excess >= TRANSIT_SLACK_MS;
        let viewer_over = viewer_excess >= VIEWER_SLACK_MS || s.struggling;
        match (transit_over, viewer_over) {
            (true, false) => PipeState::TransitStalled,
            (false, true) => PipeState::ViewerLate,
            // Both elevated: whichever share grew more is the limiter.
            (true, true) => {
                if transit_excess >= viewer_excess {
                    PipeState::TransitStalled
                } else {
                    PipeState::ViewerLate
                }
            }
            (false, false) => PipeState::Clear,
        }
    }

    /// The last verdict, for the heartbeat.
    pub fn last(&self) -> Option<PipeState> {
        self.last
    }

    /// Windows per state so far — `[unknown, clear, overproduced,
    /// transit_stalled, viewer_late]` — for the heartbeat.
    /// `TransitStalled` verdicts that came from the report-gap rule (a
    /// subset of `counts()[3]`); the rest came from the split.
    pub fn gap_stalls(&self) -> u32 {
        self.gap_stalls
    }

    pub fn counts(&self) -> [u32; 5] {
        self.counts
    }

    pub fn transit_floor_ms(&self) -> Option<u16> {
        self.transit_floor_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet(transit_ms: u16, viewer_ms: u16) -> WindowSignals {
        WindowSignals {
            split: Some(SplitMs {
                sender_ms: Some(0.1),
                transit_ms,
                viewer_ms,
            }),
            reported: true,
            inflight_bytes: 1_485,
            budget_bytes: 168_750,
            gate_skips: 0,
            blocked_sends: 0,
            send_wait_max_ms: 0.2,
            frames_sent: 30,
            struggling: false,
        }
    }

    /// The field split of 2026-09-05: 44 ms transit, 1–2 ms viewer, every
    /// window. Clear, and the floors settle on it.
    #[test]
    fn a_steady_relay_is_clear_and_learns_its_floors() {
        let mut c = PipeClassifier::new();
        for _ in 0..10 {
            assert_eq!(c.classify(&quiet(44, 2)), PipeState::Clear);
        }
        assert_eq!(c.transit_floor_ms(), Some(44));
        assert_eq!(c.counts(), [0, 10, 0, 0, 0]);
    }

    /// Finding 4: two windows with no report while the sender kept writing
    /// into a 1485-byte queue, then a 4903 ms age whose split is all
    /// transit. Every one of them is the PATH.
    #[test]
    fn finding_4_is_transit_stalled_in_every_window() {
        let mut c = PipeClassifier::new();
        for _ in 0..5 {
            c.classify(&quiet(80, 5));
        }
        let gap = WindowSignals {
            split: None,
            reported: false,
            ..quiet(0, 0)
        };
        assert_eq!(c.classify(&gap), PipeState::TransitStalled);
        assert_eq!(c.classify(&gap), PipeState::TransitStalled);
        let stalled = WindowSignals {
            split: Some(SplitMs {
                sender_ms: Some(0.3),
                transit_ms: 4_890,
                viewer_ms: 13,
            }),
            ..quiet(0, 0)
        };
        assert_eq!(c.classify(&stalled), PipeState::TransitStalled);
        // The stall did not become the floor.
        assert_eq!(c.transit_floor_ms(), Some(80));
        // And when the backlog drains the verdict returns to clear.
        assert_eq!(c.classify(&quiet(90, 6)), PipeState::Clear);
        assert_eq!(c.counts()[3], 3);
    }

    /// A report gap while the sender is IDLE, or while its queue is full,
    /// says nothing about the path.
    #[test]
    fn a_report_gap_alone_is_not_a_stall() {
        let mut c = PipeClassifier::new();
        let idle = WindowSignals {
            split: None,
            reported: false,
            frames_sent: 0,
            ..quiet(0, 0)
        };
        assert_eq!(c.classify(&idle), PipeState::Unknown);
        let full = WindowSignals {
            split: None,
            reported: false,
            inflight_bytes: 170_000,
            ..quiet(0, 0)
        };
        assert_eq!(c.classify(&full), PipeState::Overproduced);
        // A pre-M0 viewer that DID report, just without a split.
        let old = WindowSignals {
            split: None,
            reported: true,
            ..quiet(0, 0)
        };
        assert_eq!(c.classify(&old), PipeState::Unknown);
    }

    /// Field, 0.4.67, the first shadow session (CORPLAP-1 over a pinned
    /// relay, `6a9c3933`): the opening window read `transit-stalled` because
    /// the sender had written frames and the viewer's FIRST report had not
    /// arrived yet. Silence before any report is `Unknown`; the same silence
    /// after a report is the gap finding 4 showed. A viewer that never
    /// reports therefore never holds a session under T1b.
    #[test]
    fn silence_before_the_first_report_is_unknown_not_a_stall() {
        let mut c = PipeClassifier::new();
        let silent = WindowSignals {
            split: None,
            reported: false,
            frames_sent: 30,
            ..quiet(0, 0)
        };
        assert_eq!(c.classify(&silent), PipeState::Unknown);
        assert_eq!(c.classify(&silent), PipeState::Unknown);
        // The viewer speaks once…
        assert_eq!(c.classify(&quiet(40, 1)), PipeState::Clear);
        // …and from then on its silence is a gap.
        assert_eq!(c.classify(&silent), PipeState::TransitStalled);
        assert_eq!(c.counts(), [2, 1, 0, 1, 0]);
        // The gap counter names the rule: one of the stalls, all of them.
        assert_eq!(c.gap_stalls(), 1);
        // A split-driven stall is NOT a gap.
        let stalled = WindowSignals {
            split: Some(SplitMs {
                sender_ms: Some(0.1),
                transit_ms: 900,
                viewer_ms: 1,
            }),
            ..quiet(40, 1)
        };
        assert_eq!(c.classify(&stalled), PipeState::TransitStalled);
        assert_eq!(c.counts()[3], 2);
        assert_eq!(c.gap_stalls(), 1);
    }

    /// The thin-pipe cell: the budget gate skipping is the sender being the
    /// limiter, whatever the transit share reads.
    #[test]
    fn the_sender_wins_whenever_its_queue_pushes_back() {
        let mut c = PipeClassifier::new();
        c.classify(&quiet(80, 5));
        let gated = WindowSignals {
            gate_skips: 7,
            ..quiet(2_000, 5)
        };
        assert_eq!(c.classify(&gated), PipeState::Overproduced);
        let blocked = WindowSignals {
            blocked_sends: 3,
            ..quiet(80, 5)
        };
        assert_eq!(c.classify(&blocked), PipeState::Overproduced);
        let slow_send = WindowSignals {
            send_wait_max_ms: 250.0,
            ..quiet(80, 5)
        };
        assert_eq!(c.classify(&slow_send), PipeState::Overproduced);
        let at_budget = WindowSignals {
            inflight_bytes: 168_750,
            ..quiet(80, 5)
        };
        assert_eq!(c.classify(&at_budget), PipeState::Overproduced);
    }

    /// The Iris-Xe viewer of rc.188: decode queue backing up, the path fine.
    #[test]
    fn a_late_browser_is_viewer_late_not_a_stall() {
        let mut c = PipeClassifier::new();
        c.classify(&quiet(40, 10));
        assert_eq!(c.classify(&quiet(42, 900)), PipeState::ViewerLate);
        let struggling = WindowSignals {
            struggling: true,
            ..quiet(41, 12)
        };
        assert_eq!(c.classify(&struggling), PipeState::ViewerLate);
        // Both shares elevated: the bigger excess names the limiter.
        assert_eq!(c.classify(&quiet(3_000, 400)), PipeState::TransitStalled);
        assert_eq!(c.classify(&quiet(300, 2_000)), PipeState::ViewerLate);
    }

    /// The slack is a bar, not a trend: 199 ms over the floor is jitter.
    #[test]
    fn transit_jitter_under_the_slack_stays_clear() {
        let mut c = PipeClassifier::new();
        c.classify(&quiet(44, 2));
        assert_eq!(
            c.classify(&quiet(44 + TRANSIT_SLACK_MS - 1, 2)),
            PipeState::Clear
        );
        assert_eq!(
            c.classify(&quiet(44 + TRANSIT_SLACK_MS, 2)),
            PipeState::TransitStalled
        );
    }
}
