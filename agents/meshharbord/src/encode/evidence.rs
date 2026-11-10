// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// FR-79 V1 — one rule for every estimator: was this window evidence about the
// PIPE? Pure: no clock, no I/O, no configuration.
//
// # Why this exists
//
// On 2026-09-08 the same defect reached the rate three times on one host,
// through three different inputs, and each was answered with its own rule:
//
// 1. **12:15** — a send blocked for 2.9 s and 7.4 s inside pump passes that
//    spent every timed phase at zero and the rest in `other`. Four movers read
//    those blocked sends as the pipe's capacity: FR-35's hard halving, the
//    goodput fold, FR-59 P6's contradiction and P1's floor relief. 6.60 → 0.68
//    Mbps in 36 s on a path that carried 6.6 Mbps twenty seconds later.
// 2. **14:52** — a carrier demotion stalled the relay for six seconds. The
//    hold kept the rate through the stalled windows, and then the viewer's
//    arrival-rate report *for the stall* (70 kbps arriving while its queue
//    grew) landed in the first window after them and the P3 clamp read it:
//    7.45 M → 834 k.
// 3. **16:33–16:42** — the opening burst, read as capacity while it queued,
//    and a stall-contaminated measurement written back as the pair's rate.
//    Openers alternating between 1.26 M (visibly blurry for tens of seconds)
//    and 6.8 M (hundreds of frames dropped at the byte gate) against a pipe
//    measuring 1.8–3.4 M. That one is V2's; the rule is this one.
//
// The inputs differ; the defect does not. **A measurement taken while the pipe
// was not free to be measured is not a measurement of the pipe.** So there is
// one verdict per window, taken before any loop acts, and every consumer reads
// the same one — instead of a per-input rule bolted onto each consumer, which
// is how three rules with three kill switches arrived in three days.
//
// # What it deliberately does NOT do
//
// It does not decide what a consumer does with a valid window — that stays
// each loop's own law. It does not smooth, defer, quarantine or replay: an
// invalid window's numbers are DROPPED. The window after it is measured on its
// own merits, which is what every one of the three events wanted and what the
// deferral machinery in T2 was approximating with a buffer.

use super::pipe_state::PipeState;

/// Why a window is not evidence about the pipe. Ordered by how specific the
/// answer is: the agent's own stall explains a wait that never reached the
/// path at all, so it is checked first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// A pump pass overran its budget inside this window: the loop was not
    /// free, so whatever the sender waited for, the pipe is not the only
    /// candidate. (2026-09-08 12:15: 2.9 s and 7.4 s passes, every timed phase
    /// at 0 ms.)
    AgentStalled,
    /// The classifier says the transport stalled in this window.
    TransitStalled,
    /// The window BEFORE this one stalled. What arrives here is the stall's
    /// backlog draining and the viewer's account of it, not the pipe's rate.
    /// (2026-09-08 14:52.)
    StallShadow,
    /// The carrier moved under the session, so this window measures a
    /// different path from the one the estimate would be attributed to.
    /// (Six demote-follows onto DERP on 2026-09-08 alone.)
    CarrierChanged,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::AgentStalled => "agent-stalled",
            Reason::TransitStalled => "transit-stalled",
            Reason::StallShadow => "stall-shadow",
            Reason::CarrierChanged => "carrier-changed",
        }
    }

    /// FR-79 V5 — does this rejection ALSO say the send rate is too high?
    ///
    /// The gate answers one question: *is this window a measurement of the
    /// pipe?* V1 let every consumer read that answer as *does this window say
    /// anything at all*, and the two differ for exactly one reason. A stalled
    /// transport is not a measurement — but it is the transport pushing back,
    /// which is the only push-back a relay-TCP session produces at all.
    ///
    /// The other three say nothing about the rate, and each would be a
    /// regression if it cut:
    ///
    /// - `AgentStalled` implicates the LOOP, not the pipe. Cutting on it is
    ///   the 2026-09-08 12:15 defect exactly: 6.60 → 0.68 Mbps on a path that
    ///   carried 6.6 Mbps twenty seconds later.
    /// - `StallShadow` is the same stall seen a second time. Cutting on both
    ///   double-counts one event, which is how FR-35's halving overshot.
    /// - `CarrierChanged` measured a different path — that is a re-anchor to
    ///   the new carrier's memory, not a cut.
    ///
    /// ⚠️ True here is NOT "cut". A transit stall on a path we are NOT
    /// overdriving is FR-71's finding 4 (an 8 Mbps relay leg
    /// head-of-line-blocked for 4.9 s with 1485 bytes queued), where a cut
    /// costs quality for an event the sender did not cause. The governor
    /// makes that call against the measured pipe; this only says the window
    /// is admissible evidence for it.
    pub fn is_congestion(self) -> bool {
        match self {
            Reason::TransitStalled => true,
            Reason::AgentStalled | Reason::StallShadow | Reason::CarrierChanged => false,
        }
    }

    fn index(self) -> usize {
        match self {
            Reason::AgentStalled => 0,
            Reason::TransitStalled => 1,
            Reason::StallShadow => 2,
            Reason::CarrierChanged => 3,
        }
    }
}

/// Everything the verdict needs, all of it already held by the governor at the
/// window boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowFacts {
    /// This window's classifier verdict.
    pub state: PipeState,
    /// The previous window's, or `None` for the first window of a session.
    pub prev_state: Option<PipeState>,
    /// Did a pump pass overrun its stall budget inside this window? The
    /// FFmpeg pump counts them (`encode::stall`); a pump that keeps no
    /// send-side figures passes `false` and the remaining conditions stand.
    pub agent_stalled: bool,
    /// Did the overlay carrier under the session change since the last
    /// window? (V2 wires this; V1 always passes `false`.)
    pub carrier_changed: bool,
}

/// `None` = this window is evidence about the pipe.
pub fn rejected(f: WindowFacts) -> Option<Reason> {
    if f.agent_stalled {
        return Some(Reason::AgentStalled);
    }
    if f.state == PipeState::TransitStalled {
        return Some(Reason::TransitStalled);
    }
    if f.prev_state == Some(PipeState::TransitStalled) {
        return Some(Reason::StallShadow);
    }
    if f.carrier_changed {
        return Some(Reason::CarrierChanged);
    }
    None
}

/// Rejected windows per reason, for the heartbeat. One field replaces the four
/// counters T1b, T2 and T2b each added for their own rule.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rejections([u32; 4]);

impl Rejections {
    pub fn note(&mut self, r: Reason) {
        let i = r.index();
        self.0[i] = self.0[i].saturating_add(1);
    }

    /// `[agent-stalled, transit-stalled, stall-shadow, carrier-changed]`.
    pub fn counts(&self) -> [u32; 4] {
        self.0
    }

    pub fn total(&self) -> u32 {
        self.0.iter().copied().fold(0u32, u32::saturating_add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(state: PipeState) -> WindowFacts {
        WindowFacts {
            state,
            prev_state: Some(PipeState::Clear),
            agent_stalled: false,
            carrier_changed: false,
        }
    }

    /// The window a steady session produces is evidence, whatever the sender's
    /// queue did — a full queue on a free loop IS the pipe pushing back, and
    /// it is the one thing the goodput estimator can measure.
    #[test]
    fn a_clear_or_overproduced_window_on_a_free_loop_is_evidence() {
        assert_eq!(rejected(facts(PipeState::Clear)), None);
        assert_eq!(rejected(facts(PipeState::Overproduced)), None);
        assert_eq!(rejected(facts(PipeState::ViewerLate)), None);
        assert_eq!(rejected(facts(PipeState::Unknown)), None);
    }

    /// 2026-09-08 12:15: the pass stalled in `other` for 2.9 s and the send
    /// blocked for the same length. The verdict does not depend on what the
    /// classifier made of the window — the loop was not free, and that is
    /// enough.
    #[test]
    fn a_stalled_pump_pass_rejects_the_window_whatever_the_classifier_said() {
        for state in [
            PipeState::Clear,
            PipeState::Overproduced,
            PipeState::TransitStalled,
            PipeState::ViewerLate,
        ] {
            let f = WindowFacts {
                agent_stalled: true,
                ..facts(state)
            };
            assert_eq!(
                rejected(f),
                Some(Reason::AgentStalled),
                "state {}",
                state.as_str()
            );
        }
    }

    /// 2026-09-08 14:52: three stalled windows, then the viewer's report for
    /// the stall arrives in the fourth. Both are rejected, for their own
    /// reasons; the fifth is the pipe again.
    #[test]
    fn a_stall_and_its_shadow_are_rejected_and_the_window_after_is_not() {
        let stalled = facts(PipeState::TransitStalled);
        assert_eq!(rejected(stalled), Some(Reason::TransitStalled));
        let shadow = WindowFacts {
            state: PipeState::Overproduced,
            prev_state: Some(PipeState::TransitStalled),
            agent_stalled: false,
            carrier_changed: false,
        };
        assert_eq!(rejected(shadow), Some(Reason::StallShadow));
        let after = WindowFacts {
            state: PipeState::Clear,
            prev_state: Some(PipeState::Overproduced),
            agent_stalled: false,
            carrier_changed: false,
        };
        assert_eq!(rejected(after), None);
    }

    /// The shadow is exactly ONE window: a stall does not silence the session.
    #[test]
    fn the_shadow_does_not_extend_past_one_window() {
        let mut prev = Some(PipeState::TransitStalled);
        let mut rejections = Rejections::default();
        let mut seen = Vec::new();
        for state in [PipeState::Clear, PipeState::Clear, PipeState::Clear] {
            let r = rejected(WindowFacts {
                state,
                prev_state: prev,
                agent_stalled: false,
                carrier_changed: false,
            });
            if let Some(r) = r {
                rejections.note(r);
            }
            seen.push(r);
            prev = Some(state);
        }
        assert_eq!(seen, vec![Some(Reason::StallShadow), None, None]);
        assert_eq!(rejections.counts(), [0, 0, 1, 0]);
        assert_eq!(rejections.total(), 1);
    }

    /// A carrier change invalidates the window even when everything else about
    /// it looks clean: it measured a different path.
    #[test]
    fn a_carrier_change_rejects_an_otherwise_clean_window() {
        let f = WindowFacts {
            carrier_changed: true,
            ..facts(PipeState::Clear)
        };
        assert_eq!(rejected(f), Some(Reason::CarrierChanged));
    }

    /// FR-79 V5 — exactly ONE rejection also says the rate is too high, and
    /// which one is load-bearing in both directions. Adding `AgentStalled`
    /// here re-creates the 2026-09-08 12:15 defect (6.60 → 0.68 Mbps on a path
    /// that carried 6.6 Mbps twenty seconds later); adding `StallShadow`
    /// double-counts one stall; adding `CarrierChanged` cuts for a path the
    /// session is no longer on. Removing `TransitStalled` restores the
    /// CORPLAP-2 defect, where a session sending 1.8× its measured pipe
    /// stalled eleven times and ended at a HIGHER rate.
    #[test]
    fn only_a_transit_stall_also_speaks_about_the_rate() {
        assert!(Reason::TransitStalled.is_congestion());
        assert!(!Reason::AgentStalled.is_congestion());
        assert!(!Reason::StallShadow.is_congestion());
        assert!(!Reason::CarrierChanged.is_congestion());
    }

    /// The first window of a session has no predecessor and is not in anyone's
    /// shadow.
    #[test]
    fn the_first_window_of_a_session_is_evidence() {
        let f = WindowFacts {
            prev_state: None,
            ..facts(PipeState::Clear)
        };
        assert_eq!(rejected(f), None);
    }
}
