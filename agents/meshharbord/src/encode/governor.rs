// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P8c — the rate governor: ONE owner for the four rate controllers
//! the DC pumps previously threaded by hand.
//!
//! The encode inventory (P8 plan, 2026-08-20) found four control loops
//! that discover each other by accident inside the pump bodies:
//!
//! 1. **AIMD bitrate** (`aimd::AimdController`) — driven off
//!    send-channel occupancy at three different loop positions
//!    (capacity gate, pre-encode, try_send overflow).
//! 2. **Viewer-rate fps cap** (`viewer_rate::ViewerRateController`) —
//!    1 s windows folding the browser's decode report into a
//!    frame-skip divisor.
//! 3. **Encode pressure** (`encode_pressure::EncodePressure`) — the
//!    `encode_factor` maxrate scale, stepped once per 2 s heartbeat.
//! 4. **Auto-downscale tier** (`encode_pressure::DownscaleTier`) —
//!    the soft resolution cap when the bitrate lever is exhausted.
//!
//! This module changes NO behavior. The four controllers are owned
//! unchanged; every method here is a 1:1 relocation of a pump touch
//! point, so the pump calls the governor at exactly the positions it
//! previously mutated controller state — same order, same inputs,
//! same rate limits. What it buys structurally:
//!
//! - every cross-loop input is a **named parameter** (`send_depth` at
//!   construction, `send_capacity`, `ceiling_bps`, the decode report,
//!   `avg_encode_ms`) instead of ambient pump locals;
//! - `last_applied_bitrate` has ONE owner (the `applied_bps` mirror)
//!   instead of a per-pump local that each touch point must remember
//!   to update;
//! - the declared invariants at the bottom are tests, not tribal
//!   knowledge (divisor can't starve the refine signal; the skip gate
//!   never sheds a forced keyframe; the 1 s window gate holds).
//!
//! Behavioral unification (shared clock, merged MD signals) is a
//! LATER, separate decision once this soaks — deliberately not here.

use std::time::{Duration, Instant};

use super::aimd::AimdController;
use super::encode_pressure::{DownscaleTier, EncodePressure};
use super::goodput::{GoodputEstimator, GoodputSink};
use super::viewer_rate::{self, ViewerRateController};

/// A bitrate target the pump must apply to the live encoder
/// (`enc.set_bitrate(bps)`). Emitted at most once per underlying
/// AIMD move (`take_pending` is change-gated).
///
/// ⚠ Surfaced side effect, not a surprise: on QSV/AMF encoders
/// `set_bitrate` lands as a debounced encoder REBUILD whose first
/// frame is a key-flagged IDR — callers treat `Some(_)` as a
/// possible viewer resync point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedBitrate {
    pub bps: u32,
    /// Whether this target differs from the previously-applied one —
    /// the change-gated log condition the pumps use.
    pub changed: bool,
}

/// Outcome of a viewer-rate window fold (once per second).
#[derive(Debug, Clone, Copy)]
pub struct ViewerWindow {
    pub reported_fps: u32,
    pub struggling: bool,
    pub cap_fps: u32,
    pub skip_divisor: u32,
    /// Divisor moved this window — the pump's log condition is
    /// `changed || struggling`.
    pub changed: bool,
    /// FR-15 — the viewer's paint-age report this window (avg, floor-sample),
    /// ms. None = viewer sent no age (old web, or no frames painted).
    pub age_ms: Option<(u16, u16)>,
    /// FR-15 — the age loop judged the transport over-rate this window
    /// (constrained only). Two responses, both through machinery that
    /// already exists: it folds into the fps-cap `struggling` path (an
    /// instant, re-open-free byte cut) and it feeds the AIMD a congestion
    /// sample, so the decrease reaches the encoder through the pump's
    /// NORMAL apply arms on the next frame — including, on a thrifty
    /// constrained QSV session, the FR-10 deferral that keeps a re-open
    /// lump out of the middle of a drag.
    pub age_over: bool,
    /// FR-35 — the ceiling learner stepped the constrained ceiling up this
    /// window (for the pump's log line).
    pub ceiling_grown: Option<super::ceiling_learn::Grow>,
    /// FR-59 P3 — the viewer's transit queue has grown for two
    /// consecutive windows: the agent is putting bits in faster than they
    /// come out, whatever its own send queue says.
    pub link_congested: bool,
    /// FR-59 P3 — the ceiling that window's ARRIVAL rate justifies.
    /// `None` unless `link_congested` — see `viewer_rate::LinkLoop`.
    pub link_ceiling_bps: Option<u32>,
    /// FR-59 P4 — production is pausing this long so the transit queue
    /// can drain. `None` = no drain ordered this window.
    pub drain_for_ms: Option<u32>,
}

/// Outcome of a heartbeat tier step, emitted only when the
/// auto-downscale tier actually moved (rare: ≥5 saturated windows
/// down / ≥30 deep-headroom windows up, 60 s cooldown).
#[derive(Debug, Clone, Copy)]
pub struct TierChange {
    pub cap_long_edge: Option<u32>,
    pub ewma_encode_ms: f32,
}

/// Every rate kill switch the governor honours, resolved ONCE by the pump
/// from env/config so the governor itself stays pure.
///
/// A struct rather than a row of positional `bool`s: FR-59 added two more
/// to the two that were already there, and four adjacent bools at a call
/// site is a transposition waiting to happen — one that no test would
/// catch, because every one of them is a legal value in every position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernorFlags {
    /// Measured-rate stage 1 — a held goodput estimate clamps the nominal
    /// ceiling (`encode::measured_ceiling_enabled`). DIRECT paths only;
    /// see `pre_encode_tick`. False = observe-and-report only.
    pub measured_ceiling: bool,
    /// FR-15 — the constrained-transport age loop may ACT, not merely
    /// learn and report (`encode::relay_age_feedback_enabled`).
    pub age_feedback: bool,
    /// FR-59 P1 — the AIMD floor may descend toward a MEASURED pipe on a
    /// constrained transport (`encode::slow_link_floor_enabled`).
    pub floor_relief: bool,
    /// FR-59 P6 — a measurement that contradicts the FR-35 learned/seeded
    /// ceiling abandons it (`encode::seed_contradiction_enabled`).
    pub seed_contradiction: bool,
    /// FR-59 P3 — the viewer's own arrival rate may clamp the constrained
    /// ceiling while its transit queue is growing
    /// (`encode::viewer_rate_clamp_enabled`).
    pub viewer_rate_clamp: bool,
    /// FR-59 P4 — a transit queue too deep to cut our way out of is
    /// DRAINED by pausing production (`encode::queue_drain_enabled`).
    pub queue_drain: bool,
    /// FR-63 — the opener ramps instead of committing to a constant
    /// (`encode::rate_slow_start_enabled`).
    ///
    /// ⚠️ The ONE flag here that is **not** the shipped posture: it defaults
    /// OFF, in `Default` too, because this FR's rule is that no controller
    /// change ships live without field evidence. Every other field defaults
    /// on because it already earned that.
    pub slow_start: bool,
}

impl Default for GovernorFlags {
    /// All on — the shipped posture. Tests that care flip one field BY
    /// NAME; tests that do not get the production behaviour.
    fn default() -> Self {
        Self {
            measured_ceiling: true,
            age_feedback: true,
            floor_relief: true,
            seed_contradiction: true,
            viewer_rate_clamp: true,
            queue_drain: true,
            // FR-63 — see the field doc: OFF even here, until field evidence.
            slow_start: false,
        }
    }
}

impl GovernorFlags {
    /// The shipped posture, read from env/config. The pumps call this;
    /// tests construct the struct literally.
    #[cfg_attr(
        not(any(feature = "ffmpeg-encoder", feature = "vp9-444")),
        allow(dead_code)
    )]
    pub fn from_env() -> Self {
        Self {
            measured_ceiling: super::measured_ceiling_enabled(),
            age_feedback: super::relay_age_feedback_enabled(),
            floor_relief: super::slow_link_floor_enabled(),
            seed_contradiction: super::seed_contradiction_enabled(),
            viewer_rate_clamp: super::viewer_rate_clamp_enabled(),
            queue_drain: super::queue_drain_enabled(),
            slow_start: super::rate_slow_start_enabled(),
        }
    }
}

/// One `RateGovernor` per pump instance. See the module docs for
/// what it owns and why.
pub struct RateGovernor {
    // Loop 1 — AIMD. Lazily constructed at the first pre-encode tick
    // (needs the first frame's ceiling), exactly as the pumps did.
    aimd: Option<AimdController>,
    send_depth: usize,
    /// Mirror of the last applied bitrate, for the heartbeat + the
    /// change-gated log. 0 = nothing applied yet.
    applied_bps: u32,

    // Loop 2 — viewer-rate fps cap.
    viewer_rate: ViewerRateController,
    viewer_window_at: Instant,
    skip_divisor: u32,
    skip_counter: u32,
    frames_skipped_decode: u64,
    // Loop 2b (FR-15) — constrained-transport age feedback.
    age_loop: viewer_rate::AgeLoop,
    /// Last viewer age (window avg, learned floor) for the heartbeat.
    last_viewer_age: Option<(u16, u16)>,
    /// FR-70 M0 — the last window's age at ARRIVAL (ms), for the heartbeat's
    /// sender / transit / viewer split. `None` from a pre-M0 viewer.
    last_viewer_arrival: Option<u16>,
    /// FR-15 kill switch, resolved once by the pump
    /// (`encode::relay_age_feedback_enabled` — env/config
    /// `RELAY_AGE_FEEDBACK`). False = learn + report only, never act.
    age_feedback: bool,

    // Loops 3+4 — encode pressure + auto-downscale tier.
    pressure: EncodePressure,
    encode_factor: f32,
    tier: DownscaleTier,
    auto_res_cap: Option<u32>,
    // P5 (FR-1) — fps-first cadence pacing for HW encoders; sits between
    // the factor (masked while engaged) and the tier (unchanged).
    pace: super::encode_pressure::FpsPace,
    // FR-112 P2 — the software pump's pace (never below 30), kept apart from
    // the hardware one above: the VP9-444 pump feeds only this.
    sw_pace: super::encode_pressure::SoftwarePace,

    // Measured-rate v2 (2026-08-27) — CONSUMED at stage 1: the send
    // task reports per-frame blocked sends, the viewer-window tick
    // folds one window at a time, and `pre_encode_tick` clamps the
    // nominal ceiling to `derived_ceiling_bps(G)` while an estimate
    // holds. The heartbeat still reports the raw estimate + counts.
    goodput: GoodputEstimator,
    goodput_sink: GoodputSink,
    /// Stage-1 kill switch, resolved once by the pump
    /// (`encode::measured_ceiling_enabled` — env/config
    /// `MEASURED_CEILING`). False = observe-and-report only.
    measured_ceiling: bool,
    /// FR-35 — grows the constrained ceiling above the nominal on delivery
    /// evidence; inert (returns the plan) when `hi` is 0 or off-relay.
    learner: super::ceiling_learn::CeilingLearner,
    /// AIMD decrease count at the last tick — a change means the pipe pushed
    /// back since, which the learner must hear.
    last_decreases: u32,
    /// Send-task byte total at the last viewer window, for the window's
    /// delivered rate (the learner's "carried" evidence).
    last_sent_bytes: u64,

    /// FR-59 — the slow-link kill switches.
    slow_link: GovernorFlags,
    /// FR-59 P6 — the ceiling a measurement contradicted, parked here for
    /// the pump to log. Drained by `take_seed_abandoned`; the learner only
    /// ever reports an abandonment once, so this cannot spam.
    seed_abandoned_bps: Option<u32>,
    /// FR-59 P1 — the floor actually in force after the evidence-gated
    /// relief, for the heartbeat. `None` = the nominal floor stands.
    relieved_floor_bps: Option<u32>,
    /// FR-59 P3 — the viewer-side congestion loop.
    link_loop: viewer_rate::LinkLoop,
    /// FR-59 P3 — the viewer's ARRIVAL rate and when it was reported.
    /// Held only while its queue is growing (see `viewer_rate::LinkLoop`
    /// for why that gate is not optional), and expired by
    /// [`LINK_CEILING_TTL`] so a viewer that goes SILENT cannot pin the
    /// session forever — silence is not evidence of congestion. Stored
    /// RAW rather than pre-discounted, because it feeds two consumers
    /// with different margins: the P3 ceiling clamp and the P1 floor.
    link_rx_bps: Option<(u32, Instant)>,
    /// FR-59 P4 — production is paused until this instant so the transit
    /// queue can drain. An INSTANT rather than a countdown, because the
    /// pump polls it from a loop that may not tick at all while paused.
    drain_until: Option<Instant>,
    /// FR-59 P8 — a pair the rate memory remembers BELOW the nominal floor
    /// (the same seed P5 reads). The session OPENS at it, and until live
    /// evidence arrives it stands in as the pipe measurement, so the P1
    /// floor relief, the P2 queue budget and the P6 contradiction check all
    /// see the remembered rate rather than the 1.5 M fleet constant. `None`
    /// for an unremembered or a fast pair, and with the relief switched off
    /// — then nothing here changes. Field 2026-09-02: `seed_bps=387500` was
    /// logged and the session still opened at the 2.55 M relay cap (the
    /// FR-35 learner only ever RAISES the ceiling), a 372 KB opener into a
    /// ~300 kbps pipe — ten seconds of queue before any measurement spoke.
    ///
    /// ⚠️ FR-70 P1: this is what the session OPENS at, and nothing more. What
    /// stands in for a measurement afterwards is `prior`, which starts here
    /// and decays — the seed held a session at 200 kbps for four minutes
    /// through the floor relief AND the queue budget while nothing measured
    /// (field 2026-09-04, `6a9abc30`; see `encode::prior`).
    open_seed_bps: Option<u32>,
    /// FR-70 P1 — the belief about the pipe while nothing measures it: the
    /// seed, then the last live measurement, decaying toward the band on
    /// clean windows. Read wherever `open_seed_bps` used to stand in.
    prior: super::prior::RatePrior,
    /// FR-70 P1 — did a send stall land since the last viewer window? The
    /// prior's "clean" verdict needs the PIPE's push-back, and a stall is the
    /// one push-back that reaches the governor between windows.
    stall_seen: bool,
    /// FR-71 T1a — the per-window plane classifier (shadow).
    pipe: super::pipe_state::PipeClassifier,
    /// FR-71 T1a — what the pump measured about its own send side since the
    /// last viewer window, handed in just before the tick. `None` = the pump
    /// keeps no such figures (the VP9-444 pump), so the sender side reads as
    /// quiet and only the split and the viewer's report classify.
    window_sender: Option<WindowSenderStats>,
    /// FR-79 — windows the validity gate rejected, per reason. ONE field in
    /// place of the four T1b, T2 and T2b each added for their own rule.
    evidence: super::evidence::Rejections,
    /// FR-79 V3b / FR-74 — the ONE belief about what the path carries, fed by
    /// every window (a demonstrated floor) and by every push-back (a capacity
    /// estimate). SHADOW for now: computed and reported, read by no consumer,
    /// so the field can compare it against `pipe_bps` before anything acts.
    belief: super::pipe::Pipe,
    /// FR-35 — a send blocked ≥ `HARD_STALL` since the last window boundary.
    /// The ×0.5 it earns is applied there, where the gate can say whether the
    /// block was the pipe (FR-79).
    window_hard_stall: bool,
    /// FR-63 — the opener's ramp. Lazily built at the first CONSTRAINED tick
    /// because it needs that tick's RESOLVED ceiling, exactly as the AIMD is.
    /// `None` while the flag is off, on a direct transport, or once the ramp
    /// has finished — the three cases where the normal controller is already
    /// the right answer.
    slow_start: Option<super::slow_start::SlowStart>,
    /// FR-63 — has the "armed" line been logged for this session? The ramp is
    /// the only rate decision with no other trace, so a session where it did
    /// or did not engage would otherwise be indistinguishable in a log.
    slow_start_logged: bool,
    /// FR-63 — did any congestion signal arrive since the last viewer window?
    /// The ramp doubles on a clean window and ENDS on a dirty one, so this is
    /// the one bit of state that decides which.
    slow_start_congested: bool,
}

/// FR-71 T1a — what the pump measured about its own send side over one
/// viewer window, handed to [`RateGovernor::note_window_sender`] just before
/// the tick. Every field is a delta or a level for THAT window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowSenderStats {
    /// Bytes still held for this session (the FR-59 P2 ledger) and the
    /// budget the gate compares it against.
    pub inflight_bytes: usize,
    pub budget_bytes: usize,
    /// FR-79 — pump passes that overran their stall budget in this window.
    /// Non-zero means the agent's own loop was not free, so nothing this
    /// window measured is evidence about the pipe. A pump that keeps no
    /// send-side figures reports `0` and the gate's other conditions stand.
    pub stalled_passes: u32,
    /// Frames the byte-budget gate skipped this window.
    pub gate_skips: u32,
    /// The longest a frame waited in the send queue this window, ms, and
    /// the window's average (`None` where the pump keeps no such figure).
    pub send_wait_max_ms: f64,
    pub send_wait_avg_ms: Option<f64>,
    /// Frames the send task wrote this window.
    pub frames_sent: u32,
}
/// The viewer-rate fold cadence (unchanged from the pump bodies).
const VIEWER_WINDOW: Duration = Duration::from_secs(1);

/// FR-59 P3 — how long an arrival-rate ceiling outlives the window that
/// produced it. Generous enough to bridge a viewer that skips a report,
/// short enough that a viewer which goes away entirely cannot leave the
/// session clamped: silence is not evidence of congestion, and the loop
/// clears the clamp on the first non-congested window anyway.
const LINK_CEILING_TTL: Duration = Duration::from_secs(15);

/// FR-59 — queue depth (ms) at or below which the arrival-rate clamp is
/// released. Deliberately NOT zero: the estimate is a running integral of a
/// noisy derivative, so it rarely lands exactly on 0, and a release that
/// waits for perfection never fires. One `QUEUE_GROWTH_MS` worth of residue
/// is the same quantum the loop already treats as "not growing".
const LINK_RELEASE_DEPTH_MS: i32 = viewer_rate::QUEUE_GROWTH_MS as i32;

impl RateGovernor {
    /// `flags` carries every kill switch (see [`GovernorFlags`]); the
    /// pumps resolve them once from env/config, tests pass them
    /// explicitly, so the governor stays pure.
    pub fn new(
        target_fps: u32,
        send_depth: usize,
        flags: GovernorFlags,
        ceiling_hi_bps: u32,
        ceiling_seed_bps: Option<u32>,
        now: Instant,
    ) -> Self {
        Self {
            aimd: None,
            send_depth,
            applied_bps: 0,
            viewer_rate: ViewerRateController::new(target_fps),
            viewer_window_at: now,
            skip_divisor: 1,
            skip_counter: 0,
            frames_skipped_decode: 0,
            age_loop: viewer_rate::AgeLoop::new(),
            last_viewer_age: None,
            last_viewer_arrival: None,
            age_feedback: flags.age_feedback,
            pressure: EncodePressure::new(),
            encode_factor: 1.0,
            tier: DownscaleTier::new(),
            auto_res_cap: None,
            goodput: GoodputEstimator::new(),
            goodput_sink: GoodputSink::new(),
            pace: super::encode_pressure::FpsPace::new(),
            sw_pace: super::encode_pressure::SoftwarePace::new(),
            measured_ceiling: flags.measured_ceiling,
            learner: super::ceiling_learn::CeilingLearner::new(ceiling_hi_bps, ceiling_seed_bps),
            last_decreases: 0,
            last_sent_bytes: 0,
            slow_link: flags,
            seed_abandoned_bps: None,
            relieved_floor_bps: None,
            link_loop: viewer_rate::LinkLoop::new(),
            link_rx_bps: None,
            drain_until: None,
            open_seed_bps: ceiling_seed_bps
                .filter(|s| *s > 0 && *s < super::MIN_BITRATE_BPS && flags.floor_relief),
            // Seeded with the SAME filtered value: a seed at or above the
            // band never stood in for anything (the relief is inert there
            // and the P6 check would read it as a contradiction).
            prior: super::prior::RatePrior::new(
                ceiling_seed_bps
                    .filter(|s| *s > 0 && *s < super::MIN_BITRATE_BPS && flags.floor_relief),
                super::MIN_BITRATE_BPS,
                // FR-79 V3 — the prior always decays; the switch is gone (FR-70 P1
                // was field-verified with its own same-build control on 0.4.64).
                true,
            ),
            stall_seen: false,
            pipe: super::pipe_state::PipeClassifier::new(),
            window_sender: None,
            evidence: super::evidence::Rejections::default(),
            belief: super::pipe::Pipe::default(),
            window_hard_stall: false,
            slow_start: None,
            slow_start_logged: false,
            slow_start_congested: false,
        }
    }

    /// FR-59 P8 — the remembered rate this session opened at, when the pair
    /// is remembered slower than the nominal floor (see `open_seed_bps`).
    /// The pump opens its FIRST encoder at this rate so the governor's
    /// first tick does not rebuild an encoder it just opened at the ceiling.
    #[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
    pub fn open_seed_bps(&self) -> Option<u32> {
        self.open_seed_bps
    }

    /// FR-59 P4 — is production paused for a queue drain right now?
    ///
    /// Polled by the pump every iteration. Clearing the deadline here
    /// (rather than on a timer) is what tells the link loop the drain was
    /// SERVED, so the next deep window can order another one — without
    /// that hand-back a single drain would suppress every later one.
    pub fn draining(&mut self, now: Instant) -> bool {
        match self.drain_until {
            Some(until) if now < until => true,
            Some(_) => {
                self.drain_until = None;
                self.link_loop.drain_served();
                false
            }
            None => false,
        }
    }

    /// FR-59 P3/P4 — link-loop telemetry: congested windows, drains
    /// ordered, and the live queue-depth estimate (ms).
    pub fn link_stats(&self) -> (u32, u32, i32) {
        let (drains, depth) = self.link_loop.drain_stats();
        (self.link_loop.congested_windows(), drains, depth)
    }

    /// FR-79 V3b — the ONE belief, in SHADOW: `(believed, floor, capacity)`.
    ///
    /// Read it against `pipe_bps` in the heartbeat. Where they agree the new
    /// composition is safe to adopt; where `believed` has a number and
    /// `pipe_bps` is `None`, that is a session the old rule was blind on —
    /// which on the relay hosts is most of them.
    pub fn belief_bps(&self, now: Instant) -> (Option<u32>, Option<u32>, Option<u32>) {
        (
            self.belief.ceiling_anchor_bps(now),
            self.belief.floor_bps(now),
            self.belief.capacity_bps(now),
        )
    }

    /// FR-79 V3b — `(deliveries folded, capacities folded)`.
    pub fn belief_counts(&self) -> (u32, u32) {
        self.belief.counts()
    }

    /// FR-59 P6 — take the ceiling a measurement contradicted, if one was
    /// abandoned since the last call, so the pump can log it once.
    pub fn take_seed_abandoned(&mut self) -> Option<u32> {
        self.seed_abandoned_bps.take()
    }

    /// FR-59 P1 — the floor currently in force when the evidence-gated
    /// relief has lowered it; `None` while the nominal floor stands.
    /// Heartbeat telemetry: without it, "the floor let go" and "the pipe
    /// was never measured" look identical from a log.
    pub fn relieved_floor_bps(&self) -> Option<u32> {
        self.relieved_floor_bps
    }

    /// FR-35 — the ceiling the AIMD runs under: the plan's, lifted by what the
    /// learner has proven on a constrained session. Also the value the pump
    /// opens the encoder with, so the opening keyframe is sized by it.
    pub fn effective_ceiling(&mut self, plan_ceiling_bps: u32, constrained: bool) -> u32 {
        if constrained {
            self.learner.effective_ceiling(plan_ceiling_bps)
        } else {
            plan_ceiling_bps
        }
    }

    /// FR-70 M3a.2 — what [`Self::effective_ceiling`] would return, without
    /// recording anything: the per-frame call keeps the learner's nominal in
    /// step with the frame actually encoded, so the ceiling for a dims
    /// replacement's dims is asked here.
    pub fn ceiling_for(&self, plan_ceiling_bps: u32, constrained: bool) -> u32 {
        if constrained {
            self.learner.ceiling_for(plan_ceiling_bps)
        } else {
            plan_ceiling_bps
        }
    }

    /// FR-35 — the learned ceiling (0 = nothing learned or seeded), for the
    /// heartbeat.
    pub fn learned_ceiling_bps(&self) -> u32 {
        self.learner.learned_bps()
    }

    /// FR-35 P2 — the session's stable rate when it beats the nominal.
    pub fn stable_bps(&self) -> Option<u32> {
        self.learner.stable_bps()
    }

    /// Hand to the send task at spawn. It reports every frame's
    /// serialisation time; the sink keeps only genuinely blocked sends
    /// (≥ `goodput::MIN_BLOCKED_SEND`) and the governor folds one
    /// window per viewer tick.
    pub fn goodput_sink(&self) -> GoodputSink {
        self.goodput_sink.clone()
    }

    /// The measured delivered rate, or `None` for no confidence.
    ///
    /// Stage 1 consumes this in [`Self::pre_encode_tick`] as
    /// `ceiling := min(nominal, derived_ceiling_bps(G))` — measurement
    /// may only ever LOWER the clamp, because the nominal clamp also
    /// protects the TURN path.
    pub fn blocked_send_bps(&self, now: Instant) -> Option<u32> {
        self.goodput.estimate_bps(now)
    }

    /// FR-59 — what this session believes the PIPE carries: the agent's own
    /// blocked-send goodput, the viewer's arrival rate while its queue is
    /// growing, or the lower of the two. Constrained transports only.
    ///
    /// ⚠ Use this, not [`Self::blocked_send_bps`], for anything that
    /// asks "how fast is the link". Field 2026-09-02, a 150 kbit shaped
    /// link: `goodput_bps` was `None` in **every** window of a 47-window
    /// run, because the agent's sends never blocked — the queue was
    /// downstream. P2's queue budget read the goodput-only accessor and so
    /// could never engage (`frames_skipped_backpressure=0` throughout),
    /// while P1's floor relief, which reads the widened value, engaged and
    /// drove the target to 200 kbps. Same missing widening, one call site
    /// updated and the other not.
    pub fn pipe_bps(&self, now: Instant, constrained: bool) -> Option<u32> {
        if !constrained {
            return None;
        }
        let link = match self.link_rx_bps {
            Some((rx, at)) if now.duration_since(at) <= LINK_CEILING_TTL => Some(rx),
            _ => None,
        };
        match (self.goodput.estimate_bps(now), link) {
            (Some(g), Some(rx)) => Some(g.min(rx)),
            // FR-59 P8 — with no live evidence at all, the remembered rate
            // (lowest priority: any measurement outranks it). FR-70 P1: the
            // rate as it DECAYS, so the queue budget denominated in it cannot
            // seal the session against the measurement that would replace it.
            (g, rx) => g.or(rx).or(self.prior.stand_in_bps()),
        }
    }

    /// FR-59 P3 — is the viewer's arrival-rate clamp currently HELD (a live
    /// `link_rx_bps` within its TTL)? Test seam: with FR-70 P1 the floor no
    /// longer snaps to the constant on release, so "released" has to be
    /// read from the clamp itself rather than inferred from the floor.
    #[cfg(test)]
    pub fn link_loop_holding(&self) -> bool {
        self.link_rx_bps.is_some()
    }

    /// FR-70 P1 — what stands in for a pipe measurement right now, for the
    /// heartbeat: the remembered seed, or the last live measurement, as it
    /// decays toward the band on clean windows. `None` = no prior in force
    /// (an unremembered pair, or one whose prior has decayed away). Read it
    /// next to `slow_link_floor_bps` and `goodput_bps`: a relief that is
    /// letting go while `goodput_bps` stays `None` is this, working.
    pub fn prior_bps(&self) -> Option<u32> {
        self.prior.stand_in_bps()
    }

    /// `(accepted, rejected)` goodput WINDOWS — heartbeat telemetry.
    /// `(0, 0)` is the healthy signature of an unbound link (nothing
    /// ever blocked); rejected counts windows whose blocked time was
    /// too thin to trust.
    pub fn goodput_samples(&self) -> (u64, u64) {
        (self.goodput.accepted(), self.goodput.rejected())
    }

    /// Backpressure-gate arm: the send channel is FULL (or a shared-
    /// pipeline follower is congested) and the pump is about to skip
    /// production. Feed the full-occupancy sample so the multiplicative
    /// decrease runs DURING sustained congestion (the rc.171/Phase B
    /// starvation fix) — no-op until the AIMD exists (first frame not
    /// yet encoded).
    pub fn on_backpressure_skip(&mut self, now: Instant) -> Option<AppliedBitrate> {
        // FR-63 — congestion for the opener's ramp, recorded BEFORE the `?`
        // below so it is not lost when the AIMD has not been built yet. The
        // first frames of a session are exactly when that happens.
        self.slow_start_congested = true;
        let ctrl = self.aimd.as_mut()?;
        ctrl.observe(self.send_depth as u32, true, now);
        let bps = ctrl.take_pending()?;
        Some(self.record_applied(bps))
    }

    /// Pre-encode tick, every frame that reaches the encoder: lazily
    /// construct the AIMD at the session's first ceiling, push the
    /// current floor (area-scaled legibility minimum — see
    /// `encode::area_min_bitrate_bps`; the controller caps it at the
    /// live ceiling) and ceiling (quality preference × relay clamp —
    /// lowering clamps desired down immediately), and feed a non-full
    /// occupancy sample so the additive increase can recover once the
    /// link drains. Floor BEFORE ceiling so a transport flip to relay
    /// resolves both in one tick (the flat floor lands first, then the
    /// clamp isn't maxed against a stale big-screen floor).
    pub fn pre_encode_tick(
        &mut self,
        ceiling_bps: u32,
        floor_bps: u32,
        constrained: bool,
        send_capacity: usize,
        now: Instant,
    ) -> Option<AppliedBitrate> {
        // Stage 1 (2026-08-27) — clamp the nominal ceiling to the
        // measured pipe while an estimate holds: the session then tops
        // out just UNDER the drain rate instead of rediscovering it by
        // congesting the send queue on every burst (the "chunky" skips).
        // Only ever LOWERS the nominal; confidence decays via the
        // estimator's TTL, so silence reverts to the nominal band.
        //
        // DIRECT-ONLY (field 2026-08-27, CORPLAP-3 + CORPLAP-2 over the corp
        // relay, same day the clamp shipped): per-frame samples through
        // a lumpy TURN-TCP pipe read near-zero during TCP stalls, the
        // down-fast EWMA crashed the estimate, and the ceiling rode the
        // 1 Mbps floor — relay sessions got WORSE than the nominal
        // clamp they had before. The nominal relay clamp already IS the
        // physics bound there; the estimate stays OBSERVED on relay
        // (heartbeat `goodput_bps`) as the dataset for a future
        // lumpiness-robust design.
        let ceiling_bps = if self.measured_ceiling
            && !constrained
            && let Some(g) = self.goodput.estimate_bps(now)
        {
            ceiling_bps.min(super::goodput::derived_ceiling_bps(g))
        } else {
            ceiling_bps
        };
        // FR-59 P3 — the viewer's arrival rate, while it is still live.
        // Expired here rather than at the window fold because a viewer that
        // goes SILENT is silent, not congested, and the fold only runs when
        // a report arrives.
        let link_rx_bps = match self.link_rx_bps {
            Some((rx, at)) if now.duration_since(at) <= LINK_CEILING_TTL => Some(rx),
            Some(_) => {
                self.link_rx_bps = None;
                None
            }
            None => None,
        };
        // FR-59 — what this session believes the pipe carries, on a
        // constrained transport: the agent's own blocked-send goodput, the
        // viewer's arrival rate while its queue is growing, or the LOWER of
        // the two. P1, P3 and P6 all key off this one number.
        //
        // Deliberately consumed here even though stage 1 above refuses to
        // clamp the CEILING with the goodput half on relay: the uses have
        // opposite risk. Lowering a FLOOR, bounding a ceiling the receiver
        // says it cannot keep up with, and abandoning an over-ambitious
        // learned ceiling all SHED bits and cut latency; an under-estimated
        // nominal ceiling collapses quality, which is why stage 1 stays
        // direct-only.
        //
        // ⚠ The two halves are not redundant. The goodput estimate needs
        // the agent's own sends to BLOCK, and on the link this program
        // exists for they do not (field: `send_wait_max_ms` 0.1 ms while
        // the viewer ran 2.3 s behind) — the queue is downstream. The
        // viewer's half needs a viewer that reports. Either alone leaves a
        // real case uncovered.
        // FR-79 V3 — ONE belief, read through the one accessor. This block used
        // to compose it a third time, beside `pipe_bps` and the identical
        // `remembered_candidate_bps`; three copies of one law is how they drift.
        let measured_bps = self.pipe_bps(now, constrained);
        // FR-59 P6 — a measurement far under the learned/seeded ceiling
        // contradicts it. Must run BEFORE `effective_ceiling`, or this
        // frame is still planned at the ceiling the evidence just refuted.
        if let Some(g) = measured_bps
            && let Some(dropped) = self
                .learner
                .on_measurement(g, self.slow_link.seed_contradiction)
        {
            self.seed_abandoned_bps = Some(dropped);
        }
        // FR-35 — lift the constrained ceiling by what the learner has proven.
        let ceiling_bps = if constrained {
            self.learner.effective_ceiling(ceiling_bps)
        } else {
            ceiling_bps
        };
        // FR-59 P3 — and then bound it by what the VIEWER says is actually
        // arriving, while its transit queue is growing. Applied AFTER the
        // learner deliberately: the learner's evidence is what the pipe
        // carried in the past, and a live report that the receiver is
        // falling behind outranks it.
        let ceiling_bps = match link_rx_bps {
            Some(rx) if constrained => ceiling_bps
                .min(((rx as u64) * viewer_rate::LINK_CEILING_PCT / 100) as u32)
                .max(1),
            _ => ceiling_bps,
        };
        // FR-63 — the opener has no evidence yet, so it must not commit to
        // whatever constant the chain above produced. Build the ramp from THIS
        // tick's RESOLVED ceiling (the AIMD below is built the same way) and
        // cap the ceiling by it until the ramp finishes.
        //
        // Field 2026-09-03: this ceiling was 2_550_000 on a path measured at
        // 213_180 — 12× over, 444 ms of queue, a 1550 ms paint, then six
        // windows collapsing to the truth. The same host over-drove from the
        // OPPOSITE direction a day earlier with a remembered 6_134_627 and a
        // 6287 ms paint. No constant was safe; only measuring is.
        //
        // ⚠️ Constructed once and kept once `done` — dropping it would let
        // `get_or_insert_with` restart the ramp on the next tick and re-open a
        // session that had already earned its rate.
        //
        // ⚠️ The floor passed here is `open_seed_bps` — the rate THIS PAIR was
        // remembered at — and NOT `floor_bps`. `floor_bps` is
        // `area_min_bitrate_bps`, a flat 1.5 M on every constrained transport:
        // a fleet constant, which is precisely the thing this phase exists to
        // stop trusting. Passing it made `SlowStart::new` resolve
        // `300_000.max(1_500_000)` and open at 1.5 M — still 7× over the
        // 213 kbps field path, and one doubling from the ceiling, i.e. no ramp
        // at all. The floor parameter means "a rate already PROVEN", and only
        // the remembered seed is that.
        if self.slow_link.slow_start && constrained {
            let seeded = self.open_seed_bps;
            let ss = self.slow_start.get_or_insert_with(|| {
                super::slow_start::SlowStart::new(seeded.unwrap_or(0), ceiling_bps)
            });
            if !self.slow_start_logged {
                self.slow_start_logged = true;
                tracing::info!(
                    open_bps = ss.target_bps(),
                    ceiling_bps,
                    seed_bps = seeded,
                    "FR-63 slow-start armed — opening below the ceiling and \
                     doubling per clean window"
                );
            }
        }
        let ceiling_bps = match self.slow_start.as_ref() {
            Some(ss) if !ss.done() => ceiling_bps.min(ss.target_bps()).max(1),
            _ => ceiling_bps,
        };
        // FR-59 P1 — the legibility floor descends toward a measured pipe.
        // `MIN_BITRATE_BPS` is calibrated for the 2–9 Mbps band every
        // measured relay sat in; below it the floor is not a floor but a
        // PIN, because it is also the AIMD's `floor_bps` and the
        // multiplicative decrease bottoms out there.
        //
        // ⚠ Load-bearing for P3, not only for P1: `set_ceiling` raises any
        // ceiling back up to the floor, so without the relief the arrival-
        // rate clamp above would be silently undone on exactly the links it
        // exists for. Evidence-gated, so a session with no measurement at
        // all is byte-for-byte unchanged.
        let floor_bps = match measured_bps {
            Some(g) if self.slow_link.floor_relief => {
                let relieved = super::goodput::measured_floor_bps(
                    g,
                    floor_bps,
                    super::slow_link_min_bitrate_bps(),
                );
                self.relieved_floor_bps = (relieved < floor_bps).then_some(relieved);
                relieved
            }
            _ => {
                self.relieved_floor_bps = None;
                floor_bps
            }
        };
        // FR-63 — and the floor has to descend WITH the ramp, or the ceiling
        // cap above is silently undone: `set_ceiling` raises any ceiling back
        // up to the floor. That is the same coupling the P1 comment above
        // documents for the arrival clamp, and it bit this phase exactly as
        // predicted — 0.4.55 shipped the cap alone, so on a constrained path
        // the flat 1.5 M floor pinned the opener and slow-start was INERT
        // while looking wired.
        //
        // Bounded by `slow_link_min_bitrate` — the existing absolute stop, not
        // a new constant. Below roughly it a full-resolution frame is
        // illegible at any QP and the honest lever is fewer PIXELS, which the
        // relay resolution cap already applies. Only ever LOWERS the floor.
        let floor_bps = match self.slow_start.as_ref() {
            Some(ss) if !ss.done() => {
                let ramped = floor_bps.min(ss.target_bps().max(super::slow_link_min_bitrate_bps()));
                if ramped < floor_bps {
                    // The heartbeat's contract is "the floor actually in
                    // force"; leaving it None here would report that the
                    // nominal floor stands when it does not.
                    self.relieved_floor_bps = Some(ramped);
                }
                ramped
            }
            _ => floor_bps,
        };
        let depth = self.send_depth;
        let open_seed_bps = self.open_seed_bps;
        let ctrl = self.aimd.get_or_insert_with(|| {
            // FR-59 P1 — construct at the floor already in force rather
            // than the flat `MIN_BITRATE_BPS`, so the constructor's own
            // `initial.clamp(floor, ceiling)` and the `set_floor` on the
            // next line cannot momentarily disagree.
            // FR-59 P8 — and OPEN at the remembered rate when the pair is
            // remembered slower than the nominal floor: the ceiling is the
            // relay cap, and an opener sized by it is the burst this program
            // exists to prevent. The additive increase climbs from here.
            let initial = open_seed_bps.map_or(ceiling_bps, |s| s.min(ceiling_bps));
            AimdController::new(initial, floor_bps, ceiling_bps, depth as u32, now)
        });
        ctrl.set_floor(floor_bps);
        ctrl.set_ceiling(ceiling_bps);
        ctrl.observe(
            depth.saturating_sub(send_capacity) as u32,
            send_capacity == 0,
            now,
        );
        // FR-35 — any decrease (full channel, overflow, stall, age) since the
        // last tick pulls the learned ceiling back to the post-decrease target.
        let decreases = ctrl.decreases();
        if decreases != self.last_decreases {
            self.last_decreases = decreases;
            if constrained {
                self.learner.on_decrease(ctrl.desired(), now);
            }
        }
        let bps = ctrl.take_pending()?;
        Some(self.record_applied(bps))
    }

    /// try_send-Full arm: an encoded frame overflowed the send channel
    /// (a big IDR / motion frame the link can't drain) — a secondary
    /// congestion signal (rate-limited MD internally).
    pub fn on_send_overflow(&mut self, now: Instant) -> Option<AppliedBitrate> {
        // FR-63 — congestion for the opener's ramp; see `on_backpressure_skip`
        // for why this precedes the `?`.
        self.slow_start_congested = true;
        let ctrl = self.aimd.as_mut()?;
        ctrl.note_buffer_overflow(now);
        let bps = ctrl.take_pending()?;
        Some(self.record_applied(bps))
    }

    /// Feed the AIMD a congestion sample from a BLOCKED SEND, without
    /// consuming the move.
    ///
    /// `send_wait` measures the pipe's refusal to drain directly: no clock
    /// sync, no viewer, and it works on both transports — a frame that sat
    /// seconds inside the DataChannel send call is unambiguous congestion.
    /// It was telemetry-only on relay because the goodput clamp is
    /// direct-only (the FR-1 P2 relay regression), so the one signal that
    /// always works was the one nothing acted on.
    ///
    /// Deliberately NOT `on_send_overflow`: that one calls `take_pending`,
    /// which marks the move applied while the encoder is never told. The
    /// pump's own `pre_encode_tick` picks this up one frame later and
    /// routes it through the normal apply arms — the same discipline the
    /// FR-15 age loop follows.
    pub fn note_send_stall(&mut self, wait: Duration, now: Instant) {
        // FR-63 — a blocked send is congestion for the opener's ramp.
        self.slow_start_congested = true;
        // FR-70 P1 — and the pipe pushing back, for the prior's window verdict.
        self.stall_seen = true;
        // FR-35 — a send blocked ≥ 1 s is a HARD stall and earns ×0.5 rather
        // than the ×0.85 ladder. FR-79 — it is APPLIED at the window boundary,
        // because only there is it known whether the block was the pipe or a
        // pass the runtime stalled underneath it. The learner still notes the
        // stall here: it vetoes growth for a while either way.
        let hard = self.learner.on_stall(wait, now);
        if hard {
            self.window_hard_stall = true;
        } else if let Some(ctrl) = self.aimd.as_mut() {
            ctrl.note_buffer_overflow(now);
        }
    }

    /// A fresh encoder starts at its constructor's full-ceiling
    /// maxrate; force the AIMD to re-apply its current (possibly
    /// lower) target so the stream doesn't snap back up after a dim
    /// change / resolution switch.
    pub fn on_encoder_rebuilt(&mut self) {
        if let Some(ctrl) = self.aimd.as_mut() {
            ctrl.force_reapply();
        }
    }

    /// The VP9 pump's HISTORICAL rebuild behavior, preserved verbatim
    /// (P8c is structural-only): zero the applied-bitrate MIRROR so the
    /// next apply logs, WITHOUT `force_reapply` — the AIMD's internal
    /// last-applied is untouched, so the fresh encoder runs at its
    /// boot-time bitrate until the controller's next MD/AI/ceiling
    /// move actually shifts `desired`. ⚠ Named divergence from
    /// [`Self::on_encoder_rebuilt`] (the ffmpeg pump's semantics);
    /// unifying them is a behavioral decision for the post-soak pass.
    pub fn on_encoder_rebuilt_mirror_only(&mut self) {
        self.applied_bps = 0;
    }

    /// Once a second, fold the browser's decode report into the
    /// send-fps cap and the frame-skip divisor. `take_report` is
    /// called ONLY when the window is due (the pump's atomic swap
    /// consumes the report); `fold_followers` folds the shared
    /// pipeline's follower windows given this pump's own divisor
    /// (the stream paces to the slowest viewer).
    #[allow(clippy::too_many_arguments)] // one tick = the pump's per-window facts; a struct would only rename the list
    pub fn tick_viewer_window(
        &mut self,
        now: Instant,
        target_fps: u32,
        take_report: impl FnOnce() -> u32,
        take_age: impl FnOnce() -> u64,
        take_link: impl FnOnce() -> u64,
        constrained: bool,
        fold_followers: impl FnOnce(u32) -> u32,
        sent_bytes_total: u64,
    ) -> Option<ViewerWindow> {
        let elapsed = now.duration_since(self.viewer_window_at);
        if elapsed < VIEWER_WINDOW {
            return None;
        }
        self.viewer_window_at = now;
        // FR-79 — the PREVIOUS window's verdict, read before this one is
        // classified: it is one of the four facts the validity gate reads (see
        // `encode::evidence`).
        let prev_state = self.pipe.last();
        // FR-63 — one verdict per window for the opener's ramp: double if
        // nothing congested since the last one, otherwise END it. Taking the
        // flag first keeps the borrow of `self.slow_start` clean.
        let congested = std::mem::take(&mut self.slow_start_congested);
        // (Applied below, once the window's plane verdict is in: FR-71 T1b
        // holds the ramp on a stalled window, which is neither clean nor
        // congested.)
        // FR-35 — the window's delivered rate, from the send task's running
        // byte total (bits per second over the actual elapsed window).
        let sent_bps: u32 = {
            let bytes = sent_bytes_total.saturating_sub(self.last_sent_bytes);
            self.last_sent_bytes = sent_bytes_total;
            let ms = elapsed.as_millis().max(1) as u64;
            (bytes.saturating_mul(8000) / ms).min(u32::MAX as u64) as u32
        };
        // Fold the window's blocked-send samples in one byte-weighted
        // aggregate. Deliberately inside the window gate rather than per
        // frame — the send task is a different task, and this is the
        // existing once-a-second rendezvous.
        let raw_report = take_report();
        let (reported_fps, struggling) = viewer_rate::unpack_report(raw_report);
        // FR-15 — the viewer's paint age is the only sensor that sees the
        // whole constrained path (WG-over-DERP/TCP queues sit below every
        // agent counter). Sustained age over the learned floor drives BOTH
        // existing responses: the fps cap (folded into `struggling` — an
        // instant, re-open-free byte cut) and a rate-limited MD (returned
        // as `age_md` so the pump applies it under its normal — on thrifty
        // relay, FR-10-deferred — rules). Direct transports keep their own
        // machinery; the loop still LEARNS there so the heartbeat can show
        // ages on every transport.
        let raw_age = take_age();
        let report = viewer_rate::unpack_age(raw_age);
        // FR-70 M0 — the same window's age at ARRIVAL, when the viewer sends
        // it; the heartbeat splits the fused age with it. Stored beside the
        // report (absent ⇒ absent) — it is telemetry, no loop reads it.
        self.last_viewer_arrival = viewer_rate::unpack_age_arrival(raw_age);
        // FR-59 P3 — the viewer's own view of the link, taken here so the
        // verdict below can see whether the viewer said anything at all.
        let link = viewer_rate::unpack_link(take_link());
        // FR-79 V3b — the viewer's arrival rate is a DEMONSTRATED delivery:
        // those bytes reached the far end, whatever the queue was doing. It
        // arrives every window on every carrier, and until now it was thrown
        // away unless the link loop called the window congested — which is why
        // a relay-TCP session could finish knowing nothing about its own path
        // (CORPLAP-3, `goodput_samples=(0, 5)`). It is a FLOOR, never a
        // capacity: an idle desktop delivers 300 kbps through a gigabit path.
        if let Some((rx_bps, _)) = link {
            self.belief.observe_delivered(rx_bps, now);
        }
        // The window's blocked-send samples. Drained here rather than per
        // frame — the send task is a different task, and this is the existing
        // once-a-second rendezvous. Whether they are FOLDED is the gate's call,
        // taken below once the window has a verdict.
        let samples = self.goodput_sink.drain();
        let blocked_sends_n = samples.len() as u32;
        // FR-71 T1a — one verdict per window on which plane is the limiter,
        // taken BEFORE any loop acts on it, and with it FR-79's validity gate:
        // a window is evidence about the pipe only if the agent's own loop was
        // free, the transport did not stall, the window before it did not
        // either, and the carrier did not move. EVERY consumer below reads this
        // one verdict; none carries a rule of its own any more (V1 deleted
        // three that did: T1b's hold, T2's quarantine, T2b's shadow).
        //
        // The classifier runs on every constrained window — it stopped being a
        // shadow the moment the gate was built on it, so `transit_classify`
        // went with them. `samples` is this window's blocked sends; the
        // sender's other figures arrive from the pump via `note_window_sender`.
        let rejection = if constrained {
            let sender = self.window_sender.take();
            let split = match (report, self.last_viewer_arrival) {
                (Some((avg, _, _)), Some(arrival)) => {
                    let s = viewer_rate::split_age(
                        avg,
                        arrival,
                        sender.and_then(|s| s.send_wait_avg_ms),
                    );
                    Some(super::pipe_state::SplitMs {
                        sender_ms: s.sender_ms,
                        transit_ms: s.transit_ms,
                        viewer_ms: s.viewer_ms,
                    })
                }
                _ => None,
            };
            let signals = super::pipe_state::WindowSignals {
                split,
                reported: raw_report != 0 || report.is_some() || link.is_some(),
                inflight_bytes: sender.map_or(0, |s| s.inflight_bytes),
                budget_bytes: sender.map_or(0, |s| s.budget_bytes),
                gate_skips: sender.map_or(0, |s| s.gate_skips),
                blocked_sends: blocked_sends_n,
                send_wait_max_ms: sender.map_or(0.0, |s| s.send_wait_max_ms),
                frames_sent: sender.map_or(0, |s| s.frames_sent),
                struggling,
            };
            let state = self.pipe.classify(&signals);
            let rejected = super::evidence::rejected(super::evidence::WindowFacts {
                state,
                prev_state,
                // The pump counts its own stalled passes; a pump that keeps no
                // send-side figures (VP9-444) reports none and the remaining
                // conditions still stand.
                agent_stalled: sender.is_some_and(|s| s.stalled_passes > 0),
                // V2 wires the carrier; until then a change cannot be seen
                // here and the memory keying is where it will be read.
                carrier_changed: false,
            });
            if let Some(r) = rejected {
                self.evidence.note(r);
            }
            rejected
        } else {
            // A direct transport has the measured-ceiling clamp for this job and
            // no classifier verdict to gate on.
            None
        };
        let valid = rejection.is_none();
        // FR-79 V5 — the gate says whether this window MEASURES the pipe. It
        // was also being read as whether the window says anything at all, and
        // for a stalled transport those differ: the stall is the pipe pushing
        // back, and on a relay-TCP session it is the only push-back there is.
        //
        // That alone does not make it OUR fault. FR-71's finding 4 is the
        // other case — an 8 Mbps leg head-of-line-blocked for 4.9 s with 1485
        // bytes queued — where a cut costs quality for an event the sender did
        // not cause. The estimator is the discriminator: a stall while we are
        // sending above the last MEASURED capacity is the rate's doing; at or
        // below it, it is the transport's and T1b's answer still stands. With
        // nothing measured yet there is no claim to contradict, so no cut.
        //
        // Field 2026-09-09, CORPLAP-2 AV1 over DERP/TCP: the goodput estimator
        // accepted ONE sample all session (1,058,145 bps) while the target
        // ramped to 1,928,555; eleven windows stalled, paint age reached
        // 7,784 ms, and the rate ended HIGHER than it started — because every
        // loop below that can lower it reads `valid`.
        // ⚠️ `pipe_bps`, NOT `blocked_send_bps` — the invariant that accessor's
        // own doc states, and V5 shipped on the wrong side of it for one
        // release. The agent's sends only block when the queue is LOCAL; on a
        // relay-TCP path the queue is downstream, so the blocked-send source is
        // silent exactly where this rule is needed. Measured on 0.4.96,
        // 2026-09-09: CORPLAP-3 read `goodput_bps=None` with
        // `goodput_samples=(0, 5)` — every window's blocked time under
        // `MIN_WINDOW_BLOCKED` — so a goodput-only comparison could never fire
        // and V5 was inert on that host. `pipe_bps` composes the same goodput
        // with the viewer's arrival rate and falls back to the decaying prior,
        // which is what "how fast is the link" has meant since FR-59 P3.
        let stall_is_ours = rejection.is_some_and(|r| r.is_congestion())
            && match (
                self.pipe_bps(now, constrained),
                self.aimd.as_ref().map(|c| c.desired()),
            ) {
                // A fifth of slack so a session parked at the measurement does
                // not chatter in and out of cutting on rounding alone.
                (Some(pipe), Some(desired)) => desired > pipe.saturating_add(pipe / 5),
                _ => false,
            };
        // FR-79 — the fold is the gate's first consumer: an invalid window's
        // blocked sends are DROPPED, not held. What they measured was the
        // stall, and the next valid window measures the pipe on its own merits.
        if valid {
            // FR-79 V3b — a blocked send is the path RESISTING, so an accepted
            // fold is a capacity estimate, not a delivery. Only fold it into
            // the belief when the estimator actually accepted the window;
            // `observe_window` rejects anything under `MIN_WINDOW_BLOCKED`.
            if self.goodput.observe_window(&samples, now)
                && let Some(bps) = self.goodput.estimate_bps(now)
            {
                self.belief.observe_capacity(bps, now);
            }
        }
        // FR-35 — a send blocked ≥ `HARD_STALL` is a hard stall: ×0.5, bypassing
        // the ×0.85 ladder. It applies here rather than in `note_send_stall`
        // because only the window boundary knows whether the block was the
        // PIPE (2026-09-08 12:15: 2.9 s and 7.4 s blocked sends inside stalled
        // pump passes, on a path that carried 6.6 Mbps twenty seconds later).
        let hard_stall = std::mem::take(&mut self.window_hard_stall);
        if valid
            && hard_stall
            && let Some(ctrl) = self.aimd.as_mut()
        {
            ctrl.apply_hard_md(now);
        }
        // FR-63 — one verdict per window for the opener's ramp: double if
        // nothing congested since the last one, otherwise END it. Neither on
        // a held window (FR-71 T1b): a stall is not a clean window, and it is
        // not congestion either.
        if let Some(ss) = self.slow_start.as_mut()
            && !ss.done()
        {
            if valid {
                if congested {
                    ss.on_congestion();
                } else {
                    ss.on_clean_window();
                }
            } else if stall_is_ours {
                // FR-79 V5 — the ramp must END on a stall it caused. Reading
                // only valid windows, it saw a run of clean ones (an idle
                // screen produces those: nothing is offered, so nothing
                // congests) and kept doubling into a pipe it had already
                // overrun.
                ss.on_congestion();
            }
        }
        let mut age_over = false;
        // FR-59 — is the queue still DEEP right now? This is the LEVEL, not
        // the streak `age_over` needs, and it is what holds the P3 clamp.
        //
        // ⚠ The clamp cannot be held by the queue-growth integral, which is
        // what the first two attempts tried. `Σ(Δarrival − Δwire)` is a
        // DERIVATIVE: it sees the queue grow and falls silent the moment
        // growth stops — and growth stops as soon as the sender's cadence
        // stretches to match the drained rate, which is exactly what the
        // viewer-rate fps cap makes happen. Field 2026-09-02, adjacent
        // windows: paint age 505 ms while the depth integral read 10. The
        // age is an absolute measure against a learned floor and does not
        // vanish when growth does.
        let mut age_elevated = false;
        if let Some((avg, min, rtt)) = report {
            // P2 — half the viewer's own measured round trip is the smallest
            // age this path can physically produce; the loop uses it both to
            // reject impossible floor samples and to catch a session that was
            // congested from its first window.
            let triggered = self.age_loop.observe(avg, min, rtt / 2);
            // FR-71 T1b — the loop still LEARNS on a held window (a stall
            // never lowers a floor that is a minimum), it just does not fire.
            age_over = triggered && constrained && self.age_feedback && (valid || stall_is_ours);
            // FR-79 V5 — a stall we caused must not ERASE the streak that
            // would have cut for it. T1b's reset stands for every other
            // rejection, where the age is real but unattributable.
            if !valid && !stall_is_ours {
                self.age_loop.reset_streak();
            }
            // Same floor the age loop learned, falling back to the path's
            // physical minimum so a session with nothing learned yet still
            // has a bound rather than treating every age as elevated.
            let floor = self.age_loop.floor_ms().unwrap_or((rtt / 2).max(1));
            age_elevated = avg.saturating_sub(floor) >= viewer_rate::AGE_SLACK_MS;
        }
        let age_ms = report.map(|(avg, min, _)| (avg, min));
        self.last_viewer_age =
            report.map(|(avg, _, _)| (avg, self.age_loop.floor_ms().unwrap_or(0)));
        // FR-59 P3 — the viewer's own view of the link. Unlike the age
        // report above, neither quantity needs the clock probe, so this
        // still speaks in the windows where the age is absent or was
        // rejected as implausible — which on a jittery mobile path is most
        // of them. Learned on every transport, ACTED on when constrained
        // (a direct path has the measured-ceiling clamp for this job).
        let verdict = link
            .map(|(rx_bps, queue_ms)| self.link_loop.observe(rx_bps, queue_ms))
            .unwrap_or_default();
        // FR-79 — on an invalid window the clamp is neither armed nor released:
        // whatever it held before the stall, it still holds. The report that
        // lands in a stall's shadow is the stall's own arrival rate (field
        // 2026-09-08 14:52: 70 kbps while the queue grew, which set 834,800 on
        // a path that had just carried 7.45 M).
        let link_acts = constrained && self.slow_link.viewer_rate_clamp && valid;
        // FR-59 P4 — a queue too deep to cut our way out of. A rate cut
        // drains at `capacity − inflow`, which on a converged session is
        // nearly nothing: at 90 % of a 400 kbps pipe a 2 s backlog clears
        // at 40 kbps, i.e. over ~20 s. Stopping production sets inflow to
        // zero, so the same backlog clears in the ~2 s it represents.
        //
        // ⚠ Deliberately NO forced keyframe on resume: a pause loses no
        // frames, so the delta chain is intact, and an IDR at these rates
        // is itself seconds of transit — the cure would re-create the
        // disease. This is why P4 pauses rather than discarding the
        // agent-side queue (which is, on this path, 1–4 KB anyway: the
        // queue that matters is downstream and cannot be recalled).
        let drain_for_ms = verdict
            .drain_for_ms
            .filter(|_| constrained && self.slow_link.queue_drain);
        if let Some(ms) = drain_for_ms {
            self.drain_until = Some(now + Duration::from_millis(ms as u64));
        }
        if link_acts {
            match (verdict.congested, link) {
                (true, Some((rx_bps, _))) => {
                    // FR-79 V3b — an arrival rate measured while the viewer's
                    // queue is GROWING is the path's limit, not merely a
                    // delivery: the sender was offering more than arrived.
                    self.belief.observe_capacity(rx_bps, now);
                    self.link_rx_bps = Some((rx_bps, now));
                }
                // FR-59 — ONSET and HOLD read different sensors, because
                // they ask different questions.
                //
                // Onset (above) is "is the queue growing?" — the drift
                // derivative, which needs no clock probe and so speaks on
                // the links where the age report is absent or rejected.
                //
                // Release is "is the queue still DEEP?" — and the derivative
                // cannot answer that. Two attempts got this wrong the same
                // way: v1 released when growth stopped, v2 released when the
                // growth INTEGRAL drained. Both are made of growth, and
                // growth stops as soon as the sender's cadence stretches to
                // match the drained rate — which the viewer-rate fps cap
                // guarantees. Field 2026-09-02, adjacent windows: paint age
                // 505 ms while the integral read 10; the relief held in 2 of
                // 58 windows and peak age stayed at 2.5 s.
                //
                // So release only when BOTH say the queue is gone: the age
                // level is back near its learned floor AND the integral has
                // drained. Either one still reading deep holds the clamp,
                // and the AIMD's additive increase does the climbing back —
                // down fast, up slow.
                //
                // ⚠ `age_elevated` is false when the viewer reported no age
                // at all, so a session with no clock lock degrades to the
                // integral-only rule rather than holding the clamp forever.
                // The `LINK_CEILING_TTL` is the backstop for a viewer that
                // goes silent entirely.
                (false, Some(_))
                    if !age_elevated && self.link_loop.depth_ms() <= LINK_RELEASE_DEPTH_MS =>
                {
                    self.link_rx_bps = None
                }
                _ => {}
            }
        }
        // FR-59 P3 — a growing transit queue folds into `struggling` exactly
        // as FR-15's age excess does: an instant, re-open-free byte cut
        // through machinery that already exists.
        let link_over = link_acts && verdict.congested;
        let own_div = self.viewer_rate.observe(
            reported_fps,
            struggling || age_over || link_over,
            target_fps,
        );
        let new_div = own_div.max(fold_followers(own_div));
        let changed = new_div != self.skip_divisor;
        self.skip_divisor = new_div;
        // Feed the AIMD a congestion sample and STOP — deliberately no
        // `take_pending` here: consuming the move would mark it applied
        // while the encoder never heard about it. The pump's own
        // `pre_encode_tick` picks it up one frame later (≤33 ms) and
        // routes it through the existing apply arms.
        // FR-59 P3 — same treatment for a growing transit queue. This is
        // the arm the field case needed: the send channel was never full,
        // so nothing else in the loop could produce a decrease.
        // FR-79 V5 — and the same treatment for a transit stall we caused.
        // This is the arm the CORPLAP-2 session needed: the send channel was
        // never full (`bytes_inflight=0`, `send_wait_max_ms=0.3`), the viewer's
        // age report landed in a rejected window, so NOTHING in the loop could
        // produce a decrease while the transport stalled eleven times.
        // `note_buffer_overflow` is the rate-limited ×0.85 with its 500 ms
        // spacing — deliberately not `apply_hard_md`, which has no spacing at
        // all and would halve once per stalled window.
        if (age_over || link_over || stall_is_ours)
            && let Some(ctrl) = self.aimd.as_mut()
        {
            ctrl.note_buffer_overflow(now);
        }
        // FR-70 P1 — advance the prior. A LIVE measurement (blocked-send
        // goodput, or the viewer's arrival rate while its queue grows)
        // re-anchors it; a window in which the PIPE did not push back lets it
        // decay toward the band. Push-back is a send stall, an age excess,
        // a viewer-reported queue growth or a drain — deliberately NOT a
        // byte-budget skip, which is the pump's own throttle and on the
        // field session was the prior's own artefact (`encode::prior`).
        // `age_elevated` rather than `age_over` alone: the LEVEL speaks even
        // when the age loop is switched off from acting.
        // FR-71 T1b — a held window is neither clean nor pushed back, so the
        // prior does not move at all.
        if constrained && valid {
            let stall_seen = std::mem::take(&mut self.stall_seen);
            let live = self.goodput.estimate_bps(now).or(match self.link_rx_bps {
                Some((rx, at)) if now.duration_since(at) <= LINK_CEILING_TTL => Some(rx),
                _ => None,
            });
            let pushed_back =
                age_over || age_elevated || link_over || drain_for_ms.is_some() || stall_seen;
            self.prior.on_window(live, pushed_back);
        } else if constrained && stall_is_ours {
            // FR-79 V5 — no measurement (the stall's own numbers are not the
            // pipe's: that is the 14:52 defect), but the push-back is real, so
            // the prior re-anchors instead of decaying toward the band as it
            // would on a window where the pipe simply did not push back.
            self.prior.on_window(None, true);
        }
        // FR-35 — hand the learner this window's evidence.
        let ceiling_grown = if constrained {
            let desired = self.aimd.as_ref().map(|c| c.desired()).unwrap_or(0);
            self.learner
                .on_window(desired, sent_bps, self.last_viewer_age, now)
        } else {
            None
        };
        Some(ViewerWindow {
            reported_fps,
            struggling,
            cap_fps: self.viewer_rate.cap_fps(),
            skip_divisor: new_div,
            changed,
            age_ms,
            age_over,
            ceiling_grown,
            link_congested: link_over,
            link_ceiling_bps: verdict.ceiling_bps,
            drain_for_ms,
        })
    }

    /// FR-15 — the last viewer age report (window avg, learned floor), ms,
    /// for the pump heartbeats: field verification reads the loop from
    /// `agent_logs` instead of the viewer's screen.
    pub fn viewer_age(&self) -> Option<(u16, u16)> {
        self.last_viewer_age
    }

    /// FR-70 M0 — the fused paint age split by plane, when the viewer
    /// reported an arrival age: `sender_ms` is the pump's own send-queue
    /// wait for the window (`None` where the pump has no such figure),
    /// `transit_ms` is arrival − sender, `viewer_ms` is paint − arrival.
    /// `None` from a pre-M0 viewer, or a window with no age at all.
    pub fn viewer_age_split(&self, sender_ms: Option<f64>) -> Option<viewer_rate::AgeSplit> {
        let (age, _) = self.last_viewer_age?;
        let arrival = self.last_viewer_arrival?;
        Some(viewer_rate::split_age(age, arrival, sender_ms))
    }

    /// FR-71 T1a — the pump hands in what it measured about its own send
    /// side since the last viewer window, just before the tick. The tick
    /// consumes it; a pump that never calls this (the VP9-444 pump) classifies
    /// from the split and the viewer's report alone.
    pub fn note_window_sender(&mut self, stats: WindowSenderStats) {
        self.window_sender = Some(stats);
    }

    /// FR-71 T1a — the last window's verdict on which plane is the limiter,
    /// for the heartbeat. `None` before the first constrained window; FR-79
    /// made it load-bearing, so there is no longer a switch that stops it.
    pub fn pipe_state(&self) -> Option<super::pipe_state::PipeState> {
        self.pipe.last()
    }

    /// FR-71 AC2 — how many `transit-stalled` windows were report gaps
    /// (a subset of `pipe_state_counts()[3]`), so gap-holds and split-holds
    /// are counted apart in the heartbeat.
    pub fn pipe_gap_stalls(&self) -> u32 {
        self.pipe.gap_stalls()
    }

    /// FR-71 T1a — windows per verdict so far: `[unknown, clear, overproduced,
    /// transit_stalled, viewer_late]`.
    pub fn pipe_state_counts(&self) -> [u32; 5] {
        self.pipe.counts()
    }

    /// FR-79 — windows the validity gate rejected, as
    /// `[agent-stalled, transit-stalled, stall-shadow, carrier-changed]`.
    pub fn evidence_rejected(&self) -> [u32; 4] {
        self.evidence.counts()
    }

    /// FR-15 P2 — count of floor samples rejected as below the path's
    /// physical minimum. A climbing count means the clock probe is being
    /// skewed by the congestion it rides through; that is a different fault
    /// from a slow path and the heartbeat must not conflate them.
    pub fn viewer_age_implausible(&self) -> u32 {
        self.age_loop.implausible_samples()
    }

    /// The decode-pressure frame-skip gate: keep 1 of every
    /// `skip_divisor` delta frames. A frame carrying a forced keyframe
    /// is NEVER skipped (the browser needs the IDR to resync) and does
    /// not advance the counter — exactly the pump's original gate.
    pub fn should_skip_delta_frame(&mut self, force_keyframe: bool) -> bool {
        if self.skip_divisor > 1 && !force_keyframe {
            if self.skip_counter + 1 < self.skip_divisor {
                self.skip_counter += 1;
                self.frames_skipped_decode += 1;
                return true;
            }
            self.skip_counter = 0;
        }
        false
    }

    /// Per-heartbeat (2 s) step: fold the window's average encode time
    /// into the encode-pressure factor (applies to the ceiling from
    /// the next frame on), then the factor's saturation signal into
    /// the auto-downscale tier. Returns the tier change, if any, for
    /// the pump's log line.
    ///
    /// P5 (FR-1) — on a HW encoder (`is_hw`) the FIRST relief lever is
    /// CADENCE, not bitrate: encode time there is pixels-bound and
    /// nearly bitrate-independent, so the factor was pure quality loss
    /// (field: factor 0.4 with encode still ~25 ms). While the fps pace
    /// is engaged the exposed factor is masked at 1.0; the pressure's
    /// INTERNAL factor keeps marching so `tier_signal`'s
    /// exhausted-lever condition still fires when even the paced floor
    /// can't hold — resolution stays the second lever, exactly as
    /// before.
    pub fn heartbeat(
        &mut self,
        avg_encode_ms: f32,
        is_hw: bool,
        target_fps: u32,
        now: Instant,
    ) -> Option<TierChange> {
        self.encode_factor = self.pressure.observe(avg_encode_ms);
        let paced = if is_hw {
            self.pace.observe(self.pressure.ewma_ms(), target_fps)
        } else {
            None
        };
        if paced.is_some() {
            self.encode_factor = 1.0;
        }
        let new_cap = self.tier.observe(self.pressure.tier_signal(), now)?;
        self.auto_res_cap = new_cap;
        Some(TierChange {
            cap_long_edge: new_cap,
            ewma_encode_ms: self.pressure.ewma_ms(),
        })
    }

    /// The paced consumption rate for HW encoders (`None` = run at
    /// target). Consumed by the pump's cadence gate each loop.
    pub fn paced_fps(&self) -> Option<u32> {
        self.pace.paced()
    }

    /// FR-112 P2 — a software pump's cadence, once per heartbeat window
    /// ([`SoftwarePace`](super::encode_pressure::SoftwarePace): the
    /// sustainable rate in 5-fps steps, hysteretic, never below 30). Neither
    /// the bitrate factor nor the resolution tier is engaged here: libvpx's
    /// cost barely follows the bitrate (FR-112 §2), and the VP9-444 pump takes
    /// no tier. Returns [`Self::paced_software_fps`].
    pub fn pace_software(&mut self, avg_encode_ms: f32, target_fps: u32) -> Option<u32> {
        self.sw_pace.observe(avg_encode_ms, target_fps)
    }

    /// FR-112 P2 — the rate a software pump runs at (`None` = its target),
    /// never paced below 0.4.141's software target. The tier only ever adds
    /// frames.
    pub fn paced_software_fps(&self) -> Option<u32> {
        self.sw_pace.paced()
    }

    /// The encode-pressure maxrate scale (1.0 = full quality) —
    /// consumed by `policy::rate_plan` every frame.
    pub fn encode_factor(&self) -> f32 {
        self.encode_factor
    }

    /// The auto-downscale soft cap — consumed by `policy::plan_dims`'
    /// soft slot every frame.
    pub fn auto_res_cap(&self) -> Option<u32> {
        self.auto_res_cap
    }

    /// The last bitrate handed to `enc.set_bitrate` (0 = none yet) —
    /// heartbeat truth.
    pub fn applied_bps(&self) -> u32 {
        self.applied_bps
    }

    pub fn frames_skipped_decode(&self) -> u64 {
        self.frames_skipped_decode
    }

    fn record_applied(&mut self, bps: u32) -> AppliedBitrate {
        let changed = bps != self.applied_bps;
        self.applied_bps = bps;
        AppliedBitrate { bps, changed }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH: usize = 12;
    const CEILING: u32 = 12_000_000;

    fn gov(now: Instant) -> RateGovernor {
        RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                measured_ceiling: true,
                age_feedback: true,
                ..GovernorFlags::default()
            },
            0,
            None,
            now,
        )
    }

    /// FR-79 — the WIRING (the classifier is unit-tested in
    /// `encode::pipe_state`, the gate in `encode::evidence`, the laws in the
    /// B0 cells). A silent window while the pump kept sending is a transit
    /// stall; so is a report whose transit share dwarfs its floor. Neither is
    /// evidence about the pipe, so the age loop does not fire on the backlog's
    /// own elevated windows, and each rejection is attributable in the
    /// heartbeat. Before FR-79 this needed a kill switch (`transit_hold`) and
    /// its own counter; the rule is now unconditional.
    #[test]
    fn the_age_loop_does_not_fire_on_a_window_the_gate_rejected() {
        use crate::encode::pipe_state::PipeState;
        let start = Instant::now();
        let mut g = gov(start);
        let mut t = start;
        let sender = |frames_sent: u32| WindowSenderStats {
            inflight_bytes: 1_500,
            budget_bytes: 128_000,
            gate_skips: 0,
            send_wait_max_ms: 1.0,
            send_wait_avg_ms: Some(0.5),
            frames_sent,
            stalled_passes: 0,
        };
        // Three clean windows learn the floors (40 ms transit, 1 ms viewer).
        for _ in 0..3 {
            t += Duration::from_millis(1100);
            g.note_window_sender(sender(30));
            g.tick_viewer_window(
                t,
                30,
                || viewer_rate::pack_report(30, false),
                || viewer_rate::pack_age_with_arrival(42, 40, 80, 41),
                || 0,
                true,
                |o| o,
                0,
            )
            .expect("window due");
            assert_eq!(g.pipe_state(), Some(PipeState::Clear));
        }
        // Two silent windows with the pump still sending: finding 4's first
        // seconds.
        for _ in 0..2 {
            t += Duration::from_millis(1100);
            g.note_window_sender(sender(30));
            g.tick_viewer_window(t, 30, || 0, || 0, || 0, true, |o| o, 0)
                .expect("window due");
            assert_eq!(g.pipe_state(), Some(PipeState::TransitStalled));
        }
        // The backlog lands: two windows whose transit share is seconds.
        let mut fired = false;
        for _ in 0..2 {
            t += Duration::from_millis(1100);
            g.note_window_sender(sender(30));
            let w = g
                .tick_viewer_window(
                    t,
                    30,
                    || viewer_rate::pack_report(30, false),
                    || viewer_rate::pack_age_with_arrival(4000, 3500, 80, 3999),
                    || 0,
                    true,
                    |o| o,
                    0,
                )
                .expect("window due");
            assert_eq!(g.pipe_state(), Some(PipeState::TransitStalled));
            fired |= w.age_over;
        }
        assert!(
            !fired,
            "the age loop must not fire on windows that are not evidence"
        );
        // Four rejections, every one a transit stall — no agent stall, no
        // shadow (each window's predecessor stalled too, and the stall itself
        // is the more specific answer), no carrier change.
        assert_eq!(g.evidence_rejected(), [0, 4, 0, 0]);
    }
    /// FR-70 P1 — a remembered-slow pair, constrained, as the field ran it.
    fn remembered(seed_bps: u32, flags: GovernorFlags, now: Instant) -> RateGovernor {
        RateGovernor::new(30, DEPTH, flags, 8_000_000, Some(seed_bps), now)
    }

    /// FR-70 P1 — the WIRING (the law is unit-tested in `encode::prior`).
    ///
    /// Field 2026-09-04, CORPLAP-1 → neo16 (`6a9abc30`): a pair remembered
    /// at 200 kbps ran four minutes at `slow_link_floor_bps=Some(200000)`
    /// with `goodput_bps=None`, zero send stalls and zero viewer-congested
    /// windows. Nothing ever measured the pipe, and the memory held the
    /// floor AND the queue budget for the whole session. With nothing
    /// measuring, both must let go by themselves.
    #[test]
    fn an_unmeasured_prior_lets_the_floor_and_the_budget_go() {
        const PLAN_CEILING: u32 = 2_550_000;
        const FLOOR: u32 = crate::encode::MIN_BITRATE_BPS;
        let t0 = Instant::now();
        let mut g = remembered(200_000, GovernorFlags::default(), t0);
        g.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, t0);
        assert_eq!(
            g.applied_bps(),
            200_000,
            "opens at the remembered rate (P8)"
        );
        assert_eq!(g.relieved_floor_bps(), Some(200_000));
        assert_eq!(g.prior_bps(), Some(200_000));
        assert_eq!(
            g.pipe_bps(t0, true),
            Some(200_000),
            "the queue budget reads the seed"
        );

        // Ten clean windows, nothing measured: one decay step, and the floor
        // — and with it the AIMD's target — follows it up.
        let mut now = t0;
        for _ in 0..10 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(now, 30, || 0, || 0, || 0, true, |o| o, 0);
        }
        g.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, now);
        assert_eq!(g.prior_bps(), Some(250_000));
        assert_eq!(g.relieved_floor_bps(), Some(212_500));
        assert!(g.applied_bps() >= 212_500, "applied={}", g.applied_bps());
        assert_eq!(g.pipe_bps(now, true), Some(250_000));

        // Long enough, and the prior is gone: nominal floor, nominal budget —
        // the unremembered session, byte for byte.
        for _ in 0..110 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(now, 30, || 0, || 0, || 0, true, |o| o, 0);
        }
        g.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, now);
        assert_eq!(g.prior_bps(), None);
        assert_eq!(g.relieved_floor_bps(), None);
        assert_eq!(g.pipe_bps(now, true), None);
        assert!(g.applied_bps() >= FLOOR, "applied={}", g.applied_bps());
        // The memory has nothing better than the applied rate now, so the
        // pair is recorded at ≥ the band and stops re-seeding slow.
        assert_eq!(g.pipe_bps(now, true), None);
    }

    /// A probe that finds the pipe: the viewer reports its queue growing at
    /// 300 kbps of arrival. That is a MEASUREMENT — the floor follows the
    /// live value, the prior becomes it, and once the report releases the
    /// decay resumes from 300 k rather than from the seed.
    #[test]
    fn a_live_measurement_re_anchors_the_prior() {
        const PLAN_CEILING: u32 = 2_550_000;
        const FLOOR: u32 = crate::encode::MIN_BITRATE_BPS;
        let t0 = Instant::now();
        let mut g = remembered(200_000, GovernorFlags::default(), t0);
        g.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, t0);
        let mut now = t0;
        for _ in 0..20 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(now, 30, || 0, || 0, || 0, true, |o| o, 0);
        }
        assert_eq!(g.prior_bps(), Some(312_500));
        // Four windows of a growing transit queue at 300 kbps of arrival.
        for _ in 0..4 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(
                now,
                30,
                || 0,
                || 0,
                || viewer_rate::pack_link(300_000, 200),
                true,
                |o| o,
                0,
            );
        }
        assert_eq!(
            g.prior_bps(),
            Some(300_000),
            "re-anchored on the measurement"
        );
        assert_eq!(g.pipe_bps(now, true), Some(300_000));
        g.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, now);
        assert_eq!(
            g.relieved_floor_bps(),
            Some(255_000),
            "the floor follows the LIVE value, not the prior"
        );
        // The queue drains and the clamp releases; then nothing measures.
        for _ in 0..4 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(
                now,
                30,
                || 0,
                || 0,
                || viewer_rate::pack_link(300_000, -300),
                true,
                |o| o,
                0,
            );
        }
        for _ in 0..10 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(now, 30, || 0, || 0, || 0, true, |o| o, 0);
        }
        assert_eq!(
            g.prior_bps(),
            Some(330_000),
            "decays from the measurement, not from the seed — and gently (×1.1)"
        );
        assert_eq!(g.pipe_bps(now, true), Some(330_000));
    }

    /// The hazard the down-step closes: a prior a few percent ABOVE the pipe
    /// grows a queue too slowly for the link loop to latch (it wants 100 ms
    /// of growth per window) and the AIMD cannot decrease below the floor.
    /// The age LEVEL is what sees it — two elevated windows walk the prior
    /// back down until the queue drains.
    #[test]
    fn age_excess_without_a_measurement_walks_the_prior_down() {
        const PLAN_CEILING: u32 = 2_550_000;
        const FLOOR: u32 = crate::encode::MIN_BITRATE_BPS;
        let t0 = Instant::now();
        let mut g = remembered(200_000, GovernorFlags::default(), t0);
        g.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, t0);
        let mut now = t0;
        for _ in 0..30 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(now, 30, || 0, || 0, || 0, true, |o| o, 0);
        }
        assert_eq!(g.prior_bps(), Some(390_625));
        // The viewer's paint age sits 200 ms over a 100 ms floor, while its
        // queue-growth report stays under the link loop's onset — the slow
        // leak. No measurement exists; only the level speaks.
        let elevated = |g: &mut RateGovernor, now: &mut Instant| {
            *now += Duration::from_secs(1);
            g.tick_viewer_window(
                *now,
                30,
                || 0,
                || viewer_rate::pack_age(300, 100, 200),
                || viewer_rate::pack_link(380_000, 50),
                true,
                |o| o,
                0,
            );
        };
        elevated(&mut g, &mut now);
        assert_eq!(
            g.prior_bps(),
            Some(390_625),
            "one elevated window is a lump"
        );
        elevated(&mut g, &mut now);
        assert_eq!(g.prior_bps(), Some(312_500), "two running: one step down");
        g.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, now);
        assert_eq!(g.relieved_floor_bps(), Some(265_625));
        elevated(&mut g, &mut now);
        elevated(&mut g, &mut now);
        assert_eq!(g.prior_bps(), Some(250_000));
        // The queue drains, the age returns to its floor: the climb resumes.
        for _ in 0..12 {
            now += Duration::from_secs(1);
            g.tick_viewer_window(
                now,
                30,
                || 0,
                || viewer_rate::pack_age(105, 100, 200),
                || 0,
                true,
                |o| o,
                0,
            );
        }
        assert_eq!(g.prior_bps(), Some(312_500));
    }

    /// A direct transport has no prior in force at all — the relief, the
    /// budget and the memory are constrained-only machinery.
    #[test]
    fn a_direct_session_has_no_prior() {
        let t0 = Instant::now();
        let mut g = remembered(200_000, GovernorFlags::default(), t0);
        g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, t0);
        assert_eq!(g.relieved_floor_bps(), None);
        assert_eq!(g.pipe_bps(t0, false), None);
        assert_eq!(g.pipe_bps(t0, false), None);
    }

    /// FR-63 — the WIRING, not the law (the law is unit-tested in
    /// `encode::slow_start`). A constrained session must not open at whatever
    /// constant the ceiling chain resolved.
    ///
    /// Field 2026-09-03 (CORPLAP-1 over a corp VPN): it opened at 2_550_000
    /// into a path measured at 213_180 — 444 ms of queue, a 1550 ms paint,
    /// then six windows collapsing to the truth.
    #[test]
    fn slow_start_caps_the_opening_ceiling_only_when_enabled_and_constrained() {
        const PLAN_CEILING: u32 = 2_550_000;
        const FLOOR: u32 = 200_000;
        let open = crate::encode::slow_start::OPEN_BPS;
        let t0 = Instant::now();
        let mk = |slow_start: bool| {
            RateGovernor::new(
                30,
                DEPTH,
                GovernorFlags {
                    slow_start,
                    ..GovernorFlags::default()
                },
                0,
                None,
                t0,
            )
        };

        // ON + constrained: capped at the ramp's opening rate.
        let mut on = mk(true);
        on.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, t0);
        assert!(
            on.applied_bps() <= open,
            "opened at {} — slow-start must cap it at {open}",
            on.applied_bps()
        );

        // OFF: byte-for-byte the old behaviour — the session opens high.
        let mut off = mk(false);
        off.pre_encode_tick(PLAN_CEILING, FLOOR, true, DEPTH, t0);
        assert!(
            off.applied_bps() > open,
            "the kill switch must restore the old opener"
        );

        // ON but DIRECT: untouched. The over-drive this fixes was measured on
        // constrained transports, and a direct pair usually has the headroom.
        let mut direct = mk(true);
        direct.pre_encode_tick(PLAN_CEILING, FLOOR, false, DEPTH, t0);
        assert!(
            direct.applied_bps() > open,
            "slow-start must not touch a direct session"
        );
    }

    /// FR-63 — the REAL constrained floor must not be read as evidence.
    ///
    /// The test above passes `FLOOR = 200_000`, which is below
    /// [`slow_start::OPEN_BPS`] and therefore cannot detect the defect this
    /// locks: the wiring used to hand `SlowStart::new` the governor's
    /// `floor_bps`, which on every constrained transport is
    /// `area_min_bitrate_bps` — a flat `MIN_BITRATE_BPS` (1.5 M) fleet
    /// constant. `OPEN_BPS.max(1_500_000)` opened the session at 1.5 M: still
    /// 7× over the 213 kbps field path, and one doubling from the 2.55 M
    /// ceiling, i.e. no ramp at all while looking like one.
    ///
    /// The floor parameter means "a rate already PROVEN for this pair". A
    /// constant proves nothing, so only `open_seed_bps` may fill it.
    #[test]
    fn the_nominal_1_5m_floor_is_not_evidence_and_cannot_lift_the_opener() {
        const PLAN_CEILING: u32 = 2_550_000;
        let open = crate::encode::slow_start::OPEN_BPS;
        let t0 = Instant::now();

        let mut g = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                slow_start: true,
                ..GovernorFlags::default()
            },
            0,
            None, // no rate memory for this pair — nothing is proven
            t0,
        );
        // The real constrained floor, not a convenient small one.
        g.pre_encode_tick(
            PLAN_CEILING,
            crate::encode::MIN_BITRATE_BPS,
            true,
            DEPTH,
            t0,
        );
        assert!(
            g.applied_bps() <= open,
            "opened at {} — the flat {} floor must not lift the opener",
            g.applied_bps(),
            crate::encode::MIN_BITRATE_BPS
        );
    }

    /// FR-63 × FR-59 P8 — a rate the pair actually EARNED still wins.
    ///
    /// The counterpart to the test above: `open_seed_bps` is real evidence
    /// (this pair was measured at this rate), so slow-start must not drag a
    /// remembered-slow pair back down to `OPEN_BPS` and make it re-earn what
    /// it already proved. Field value from 2026-09-02: `seed_bps=387500`.
    #[test]
    fn a_remembered_rate_still_opens_the_session_above_the_ramp_floor() {
        const PLAN_CEILING: u32 = 2_550_000;
        const REMEMBERED: u32 = 387_500;
        let t0 = Instant::now();

        let mut g = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                slow_start: true,
                floor_relief: true, // `open_seed_bps` is gated on it
                ..GovernorFlags::default()
            },
            8_000_000,
            Some(REMEMBERED),
            t0,
        );
        g.pre_encode_tick(
            PLAN_CEILING,
            crate::encode::MIN_BITRATE_BPS,
            true,
            DEPTH,
            t0,
        );
        assert!(
            g.applied_bps() <= REMEMBERED,
            "opened at {} — must not exceed the remembered {REMEMBERED}",
            g.applied_bps()
        );
        assert!(
            g.applied_bps() > crate::encode::slow_start::OPEN_BPS,
            "opened at {} — a PROVEN rate must not be dragged down to the ramp floor",
            g.applied_bps()
        );
    }

    /// FR-59 P8 — a constrained governor with the FR-35 rate memory seeded.
    fn seeded(seed: Option<u32>, floor_relief: bool, now: Instant) -> RateGovernor {
        RateGovernor::new(
            15,
            DEPTH,
            GovernorFlags {
                floor_relief,
                viewer_rate_clamp: true,
                seed_contradiction: true,
                ..GovernorFlags::default()
            },
            8_000_000,
            seed,
            now,
        )
    }

    /// FR-59 P8 — a pair remembered BELOW the nominal floor opens AT the
    /// remembered rate, with the floor relief seeded from it. Field
    /// 2026-09-02: `seed_bps=387500` logged, then the encoder opened at the
    /// 2.55 M relay cap anyway (the FR-35 learner only ever RAISES the
    /// ceiling), a 372 KB opener burst into a ~300 kbps pipe — ten seconds
    /// of queue before the first measurement could say a word.
    #[test]
    fn remembered_slow_pair_opens_at_the_remembered_rate() {
        let now = Instant::now();
        let mut g = seeded(Some(387_500), true, now);
        let applied = g
            .pre_encode_tick(2_550_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, now)
            .expect("the first tick applies");
        assert_eq!(applied.bps, 387_500, "opens at the seed, not the ceiling");
        assert_eq!(
            g.relieved_floor_bps(),
            Some(super::super::goodput::measured_floor_bps(
                387_500,
                crate::encode::MIN_BITRATE_BPS,
                crate::encode::slow_link_min_bitrate_bps(),
            )),
            "the floor relief is seeded too, so the AIMD can hold the target there"
        );
        assert_eq!(g.open_seed_bps(), Some(387_500));
        assert_eq!(
            g.pipe_bps(now, true),
            Some(387_500),
            "P2's queue budget sees the seed until live evidence lands"
        );
        assert_eq!(
            g.pipe_bps(now, false),
            None,
            "a direct session never reads it"
        );
    }

    /// FR-59 P8 — kill switch: with the floor relief off the opener is the
    /// pre-P8 one, byte for byte.
    #[test]
    fn seed_opening_is_inert_without_the_floor_relief() {
        let now = Instant::now();
        let mut g = seeded(Some(387_500), false, now);
        let applied = g
            .pre_encode_tick(2_550_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, now)
            .expect("applies");
        assert_eq!(applied.bps, 2_550_000);
        assert_eq!(g.open_seed_bps(), None);
        assert_eq!(g.pipe_bps(now, true), None);
        assert_eq!(g.relieved_floor_bps(), None);
    }

    /// FR-59 P8 — a pair remembered FASTER than the nominal floor is the
    /// FR-35 learner's business (it lifts the ceiling), not P8's.
    #[test]
    fn a_fast_memory_still_opens_at_the_ceiling() {
        let now = Instant::now();
        let mut g = seeded(Some(4_677_606), true, now);
        let applied = g
            .pre_encode_tick(2_550_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, now)
            .expect("applies");
        assert!(
            applied.bps >= 2_550_000,
            "a seed above the nominal floor never lowers the opener: {}",
            applied.bps
        );
        assert_eq!(g.open_seed_bps(), None);
        assert_eq!(g.relieved_floor_bps(), None);
        assert_eq!(g.pipe_bps(now, true), None);
    }

    /// FR-35 — on a constrained session the learner lifts the ceiling above
    /// the nominal only on carried, clean windows, never above hi, and a
    /// direct session is untouched.
    #[test]
    fn ceiling_learner_lifts_the_constrained_ceiling_on_carried_windows() {
        let start = Instant::now();
        let mut g = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                measured_ceiling: false,
                age_feedback: false,
                ..GovernorFlags::default()
            },
            8_000_000,
            None,
            start,
        );
        let a = g
            .pre_encode_tick(
                3_000_000,
                crate::encode::MIN_BITRATE_BPS,
                true,
                DEPTH,
                start,
            )
            .expect("initial apply");
        assert_eq!(
            a.bps, 3_000_000,
            "opens at the nominal with nothing learned"
        );
        let mut bytes: u64 = 0;
        let mut grown = 0;
        for i in 1..=40u64 {
            bytes += 3_000_000 / 8; // the window carried 3 Mbps
            let now = start + Duration::from_secs(i);
            let w = g
                .tick_viewer_window(now, 30, || 0, || 0, || 0, true, |o| o, bytes)
                .expect("window due");
            if w.ceiling_grown.is_some() {
                grown += 1;
            }
            let _ = g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, now);
        }
        assert!(grown >= 3, "expected several steps, got {grown}");
        let lifted = g.effective_ceiling(3_000_000, true);
        assert!(lifted > 3_000_000 && lifted <= 8_000_000, "lifted={lifted}");
        assert_eq!(
            g.effective_ceiling(3_000_000, false),
            3_000_000,
            "direct is untouched"
        );
        // A quiet session (nothing carried) never lifts.
        let mut q = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                measured_ceiling: false,
                age_feedback: false,
                ..GovernorFlags::default()
            },
            8_000_000,
            None,
            start,
        );
        let _ = q.pre_encode_tick(
            3_000_000,
            crate::encode::MIN_BITRATE_BPS,
            true,
            DEPTH,
            start,
        );
        for i in 1..=30u64 {
            let now = start + Duration::from_secs(i);
            let w = q
                .tick_viewer_window(now, 30, || 0, || 0, || 0, true, |o| o, i * 100_000)
                .expect("window due");
            assert!(w.ceiling_grown.is_none());
        }
        assert_eq!(q.effective_ceiling(3_000_000, true), 3_000_000);
        // Learning off (hi = 0): the plan verbatim, seed ignored.
        let mut off = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                measured_ceiling: false,
                age_feedback: false,
                ..GovernorFlags::default()
            },
            0,
            Some(20_000_000),
            start,
        );
        assert_eq!(off.effective_ceiling(3_000_000, true), 3_000_000);
    }

    /// Stage 1: a held goodput estimate clamps the nominal ceiling to
    /// 85 % of the measured drain, so the target converges just under
    /// the pipe instead of congesting it every burst.
    #[test]
    fn measured_goodput_clamps_the_ceiling() {
        let start = Instant::now();
        let mut g = gov(start);
        let sink = g.goodput_sink();
        // One congested second: 40 × 30 KB frames, 24 ms serialisation
        // each = a 10 Mbps drain measurement.
        for _ in 0..40 {
            sink.record(30_000, Duration::from_millis(24));
        }
        let t1 = start + Duration::from_secs(2);
        assert!(
            g.tick_viewer_window(t1, 30, || 0, || 0, || 0, false, |o| o, 0)
                .is_some()
        );
        assert_eq!(g.blocked_send_bps(t1), Some(10_000_000));
        let applied = g
            .pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, t1)
            .expect("initial apply");
        assert_eq!(
            applied.bps, 8_500_000,
            "12M nominal clamped to 0.85 × 10M measured"
        );
    }

    /// FR-59 P1 — the whole point, end to end: on a CONSTRAINED transport
    /// with a measured pipe far under the legibility floor, the AIMD is
    /// actually allowed to converge below `MIN_BITRATE_BPS`.
    ///
    /// The pre-FR-59 arm is the regression this exists to prevent: with
    /// the relief off, the same congestion sequence bottoms out AT the
    /// floor — 3.8× the pipe — which is what pinned the field session at
    /// 1.5 Mbps on a 395 kbps hotspot while the viewer ran seconds behind.
    #[test]
    fn a_measured_slow_pipe_lets_the_floor_and_the_target_descend() {
        // 395 kbps measured: 12 × 1 KB frames each taking ~20 ms.
        fn feed_slow_pipe(g: &mut RateGovernor, start: Instant) -> Instant {
            let sink = g.goodput_sink();
            for _ in 0..12 {
                sink.record(1_000, Duration::from_micros(20_248));
            }
            let t1 = start + Duration::from_secs(2);
            assert!(
                g.tick_viewer_window(t1, 30, || 0, || 0, || 0, true, |o| o, 0)
                    .is_some()
            );
            t1
        }

        // Relief ON (shipped posture).
        let start = Instant::now();
        let mut g = gov(start);
        let t1 = feed_slow_pipe(&mut g, start);
        // Pinned exactly, so a drift in either the fixture or the
        // derivation shows up as its own failure rather than as a
        // confusing one in the floor assert below.
        let measured = g.blocked_send_bps(t1).expect("a held estimate");
        assert_eq!(measured, 395_100, "the field-class pipe, ~395 kbps");
        // Drive the AIMD down with a saturated channel. The MD is rate
        // limited to one per 500 ms, so walk the clock.
        let mut t = t1;
        for _ in 0..40 {
            t += Duration::from_millis(600);
            g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, 0, t);
        }
        let floor = g.relieved_floor_bps().expect("the relief engaged");
        assert_eq!(floor, 335_835, "85 % of the measured pipe");
        assert!(
            g.applied_bps() < crate::encode::MIN_BITRATE_BPS,
            "target {} must be free to fall below the 1.5 Mbps pin",
            g.applied_bps()
        );
        assert!(
            g.applied_bps() >= floor,
            "…but never below the relieved floor"
        );

        // Relief OFF — the pre-FR-59 pin.
        let start = Instant::now();
        let mut off = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                floor_relief: false,
                ..GovernorFlags::default()
            },
            0,
            None,
            start,
        );
        let t1 = feed_slow_pipe(&mut off, start);
        let mut t = t1;
        for _ in 0..40 {
            t += Duration::from_millis(600);
            off.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, 0, t);
        }
        assert_eq!(off.relieved_floor_bps(), None, "kill switch: no relief");
        assert_eq!(
            off.applied_bps(),
            crate::encode::MIN_BITRATE_BPS,
            "pinned at the floor, 3.8× the measured pipe"
        );
    }

    /// FR-59 P1 — a DIRECT session is untouched: the relief reads the
    /// constrained-only measurement, so nothing about a direct path can
    /// lower its floor (AC5).
    #[test]
    fn the_floor_relief_never_touches_a_direct_session() {
        let start = Instant::now();
        let mut g = gov(start);
        let sink = g.goodput_sink();
        for _ in 0..12 {
            sink.record(1_000, Duration::from_micros(20_248));
        }
        let t1 = start + Duration::from_secs(2);
        g.tick_viewer_window(t1, 30, || 0, || 0, || 0, false, |o| o, 0);
        let mut t = t1;
        for _ in 0..40 {
            t += Duration::from_millis(600);
            g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, 0, t);
        }
        assert_eq!(g.relieved_floor_bps(), None);
        assert_eq!(g.applied_bps(), crate::encode::MIN_BITRATE_BPS);
    }

    /// FR-59 P3 — the case the whole program exists for: the agent's own
    /// send NEVER blocks (so there is no goodput estimate at all), while
    /// the viewer reports its transit queue growing. Nothing else in the
    /// loop can see this — and the response has to reach the encoder.
    #[test]
    fn a_growing_viewer_queue_drives_the_rate_with_no_agent_side_evidence() {
        let start = Instant::now();
        let mut g = gov(start);
        // Not one blocked send: the queue is downstream of the agent.
        assert_eq!(g.blocked_send_bps(start), None);

        let mut t = start;
        let mut congested_seen = false;
        for i in 0..8 {
            t += Duration::from_millis(1100);
            let w = g
                .tick_viewer_window(
                    t,
                    30,
                    || viewer_rate::pack_report(30, false),
                    || 0, // no age: the clock probe never locked
                    || viewer_rate::pack_link(400_000, 250),
                    true,
                    |o| o,
                    0,
                )
                .expect("window due");
            if i >= 1 {
                assert!(w.link_congested, "window {i} should read congested");
                congested_seen = true;
            }
            // Walk the AIMD forward past its MD spacing.
            for _ in 0..4 {
                t += Duration::from_millis(200);
                g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
            }
        }
        assert!(congested_seen);
        // 90 % of the 400 kbps that actually arrived.
        assert!(
            g.applied_bps() <= 360_000,
            "target {} must be bounded by the arrival rate",
            g.applied_bps()
        );
        // …and the floor relief is what let it get there: without it
        // `set_ceiling` would have raised the clamp back to 1.5 Mbps.
        assert!(g.relieved_floor_bps().is_some());

        // A window that reports a DRAINING queue releases the clamp, and
        // the AIMD is free to climb again — recovery is not one-way.
        t += Duration::from_millis(1100);
        let w = g
            .tick_viewer_window(
                t,
                30,
                || viewer_rate::pack_report(30, false),
                || 0,
                || viewer_rate::pack_link(400_000, -200),
                true,
                |o| o,
                0,
            )
            .expect("window due");
        assert!(!w.link_congested);
        for _ in 0..40 {
            t += Duration::from_secs(6);
            g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        }
        assert!(
            g.applied_bps() > 360_000,
            "the clamp must not outlive the congestion (got {})",
            g.applied_bps()
        );
    }

    /// FR-59 P4 — a queue deep enough that a rate cut cannot clear it
    /// pauses production, the pause EXPIRES on its own, and expiring is
    /// what re-arms the next drain.
    #[test]
    fn a_deep_queue_pauses_production_and_the_pause_expires() {
        let start = Instant::now();
        let mut g = gov(start);
        assert!(!g.draining(start), "nothing to drain yet");

        let mut t = start;
        let mut ordered = None;
        for _ in 0..6 {
            t += Duration::from_millis(1100);
            let w = g
                .tick_viewer_window(
                    t,
                    30,
                    || viewer_rate::pack_report(30, false),
                    || 0,
                    || viewer_rate::pack_link(400_000, 300),
                    true,
                    |o| o,
                    0,
                )
                .expect("window due");
            if let Some(ms) = w.drain_for_ms {
                ordered = Some(ms);
                break;
            }
        }
        let ms = ordered.expect("a 900 ms-deep queue must order a drain");
        assert_eq!(ms, viewer_rate::DRAIN_MAX_MS, "bounded sub-second");
        // The pump is paused for exactly that long, and not a tick longer.
        assert!(g.draining(t));
        assert!(g.draining(t + Duration::from_millis(ms as u64 - 1)));
        assert!(!g.draining(t + Duration::from_millis(ms as u64)));
        // Expiry handed the drain back, so the loop may order another.
        let (_, drains, _) = g.link_stats();
        assert_eq!(drains, 1);
        let mut t2 = t + Duration::from_secs(1);
        let mut second = None;
        for _ in 0..6 {
            t2 += Duration::from_millis(1100);
            let w = g
                .tick_viewer_window(
                    t2,
                    30,
                    || viewer_rate::pack_report(30, false),
                    || 0,
                    || viewer_rate::pack_link(400_000, 300),
                    true,
                    |o| o,
                    0,
                )
                .expect("window due");
            if w.drain_for_ms.is_some() {
                second = Some(());
                break;
            }
        }
        assert!(second.is_some(), "a served drain must re-arm");
    }

    /// FR-59 P4 kill switch, and the direct-path guarantee: a drain is a
    /// visible freeze, so it must be impossible to get one where it was
    /// not asked for.
    #[test]
    fn the_drain_is_off_by_switch_and_on_direct() {
        for (label, flags, constrained) in [
            (
                "kill switch",
                GovernorFlags {
                    queue_drain: false,
                    ..GovernorFlags::default()
                },
                true,
            ),
            ("direct path", GovernorFlags::default(), false),
        ] {
            let start = Instant::now();
            let mut g = RateGovernor::new(30, DEPTH, flags, 0, None, start);
            let mut t = start;
            for _ in 0..10 {
                t += Duration::from_millis(1100);
                let w = g
                    .tick_viewer_window(
                        t,
                        30,
                        || viewer_rate::pack_report(30, false),
                        || 0,
                        || viewer_rate::pack_link(400_000, 400),
                        constrained,
                        |o| o,
                        0,
                    )
                    .expect("window due");
                assert_eq!(w.drain_for_ms, None, "{label}: must not order a drain");
                assert!(!g.draining(t), "{label}: must never pause");
            }
        }
    }

    /// FR-59 — the clamp must SURVIVE a window that merely stops growing.
    ///
    /// The field regression this locks (2026-09-02, 150 kbit, 47 windows):
    /// congestion is detected in bursts, so releasing on the first
    /// non-congested window made the relief flap — it held in 5 of 47
    /// windows while the depth estimate sat at 119–651 ms and paint age
    /// reached 4,656 ms. A session that has converged ONTO the pipe has
    /// zero growth and a full queue, which is precisely when releasing
    /// re-opens the overshoot.
    #[test]
    fn the_arrival_clamp_holds_until_the_queue_has_drained() {
        let start = Instant::now();
        let mut g = gov(start);
        let mut t = start;
        let step = |g: &mut RateGovernor, t: &mut Instant, q: i16| {
            *t += Duration::from_millis(1100);
            g.tick_viewer_window(
                *t,
                30,
                || viewer_rate::pack_report(30, false),
                || 0,
                || viewer_rate::pack_link(400_000, q),
                true,
                |o| o,
                0,
            )
            .expect("window due")
        };
        // Two growing windows arm the clamp and build depth to 600 ms.
        step(&mut g, &mut t, 300);
        assert!(step(&mut g, &mut t, 300).link_congested);
        // A FLAT window: growth stopped, but 600 ms of queue is still out
        // there. The clamp must hold.
        let w = step(&mut g, &mut t, 0);
        assert!(!w.link_congested, "not growing any more");
        t += Duration::from_millis(10);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        assert!(
            g.relieved_floor_bps().is_some(),
            "the clamp must survive a merely-not-growing window"
        );
        // Now drain it: negative drift until the integral is spent.
        for _ in 0..8 {
            step(&mut g, &mut t, -300);
        }
        t += Duration::from_millis(10);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        // …and release once the queue is actually gone. FR-70 P1: releasing
        // the CLAMP no longer snaps the floor back to the 1.5 M constant —
        // that snap forced the target 4× over a pipe just measured at 400 k
        // and re-created the queue the release had waited for. The last
        // measurement stays as the prior (400 k ⇒ a floor of 340 k), and
        // decays from there while nothing measures.
        assert_eq!(
            g.pipe_bps(t, true),
            Some(400_000),
            "the clamp released ⇒ the prior is the last measurement"
        );
        assert_eq!(
            g.relieved_floor_bps(),
            Some(340_000),
            "the floor follows the last MEASURED rate, not the constant"
        );
        // Ten clean windows later the prior has taken one decay step.
        let mut t2 = t;
        for _ in 0..10 {
            t2 += Duration::from_millis(1100);
            g.tick_viewer_window(t2, 30, || 0, || 0, || 0, true, |o| o, 0);
        }
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t2);
        assert_eq!(
            g.prior_bps(),
            Some(440_000),
            "×1.1 — a MEASURED base decays gently"
        );
        assert_eq!(g.relieved_floor_bps(), Some(374_000));
    }

    /// FR-59 — the clamp must survive the exact field shape that defeated
    /// both earlier release rules: **growth has stopped, and the queue is
    /// still deep**.
    ///
    /// Measured 2026-09-02 on adjacent windows: paint age 505 ms while the
    /// growth integral read 10. v1 released when growth stopped; v2
    /// released when the integral drained. Both are made of growth, and
    /// growth stops the moment the sender's cadence stretches to match the
    /// drained rate — which the viewer-rate fps cap guarantees. Only the
    /// age LEVEL sees a queue that has stopped growing.
    #[test]
    fn the_clamp_holds_on_a_deep_queue_that_stopped_growing() {
        const FLOOR: u16 = 110;
        let start = Instant::now();
        let mut g = gov(start);
        let mut t = start;
        // `rtt/2` is the physical bound; a floor sample at it is plausible.
        let win = |g: &mut RateGovernor, t: &mut Instant, q: i16, age: u16| {
            *t += Duration::from_millis(1100);
            g.tick_viewer_window(
                *t,
                30,
                || viewer_rate::pack_report(30, false),
                || viewer_rate::pack_age(age, FLOOR, FLOOR * 2),
                || viewer_rate::pack_link(400_000, q),
                true,
                |o| o,
                0,
            )
            .expect("window due")
        };
        // Two growing windows arm the clamp.
        win(&mut g, &mut t, 300, 400);
        assert!(win(&mut g, &mut t, 300, 500).link_congested);
        t += Duration::from_millis(10);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        assert!(g.relieved_floor_bps().is_some(), "clamp armed");

        // THE FIELD SHAPE: growth has stopped and the integral DRAINS —
        // field 2026-09-02 saw it fall 484 -> 10 across adjacent windows,
        // i.e. slightly negative drift as the cadence caught up — while
        // the standing queue stayed 505 ms deep.
        for _ in 0..10 {
            win(&mut g, &mut t, -80, 505);
        }
        assert!(
            g.link_stats().2 <= LINK_RELEASE_DEPTH_MS,
            "the integral has drained — this is what fooled v2"
        );
        t += Duration::from_millis(10);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        assert!(
            g.relieved_floor_bps().is_some(),
            "…but the queue is still 505 ms deep, so the clamp must HOLD"
        );

        // Now the queue genuinely clears: age returns to its floor.
        for _ in 0..3 {
            win(&mut g, &mut t, 0, FLOOR + 5);
        }
        t += Duration::from_millis(10);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        // …and releases once the age is back at the floor. The RELEASE is
        // the clamp letting go of the ceiling; FR-70 P1 keeps the floor at
        // the last measurement (400 k ⇒ 340 k) rather than the 1.5 M
        // constant — see `the_arrival_clamp_holds_until_the_queue_has_drained`.
        assert!(
            g.link_stats().2 <= LINK_RELEASE_DEPTH_MS && !g.link_loop_holding(),
            "the clamp must have released"
        );
        assert_eq!(g.relieved_floor_bps(), Some(340_000));
    }

    /// A viewer that reports NO age must not pin the clamp forever — it
    /// degrades to the integral-only rule.
    #[test]
    fn a_viewer_with_no_age_report_still_releases() {
        let start = Instant::now();
        let mut g = gov(start);
        let mut t = start;
        let win = |g: &mut RateGovernor, t: &mut Instant, q: i16| {
            *t += Duration::from_millis(1100);
            g.tick_viewer_window(
                *t,
                30,
                || viewer_rate::pack_report(30, false),
                || 0, // no age at all — the clock probe never locked
                || viewer_rate::pack_link(400_000, q),
                true,
                |o| o,
                0,
            )
        };
        win(&mut g, &mut t, 300);
        win(&mut g, &mut t, 300);
        t += Duration::from_millis(10);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        assert!(g.relieved_floor_bps().is_some());
        for _ in 0..10 {
            win(&mut g, &mut t, -300);
        }
        t += Duration::from_millis(10);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        // No age signal ⇒ the integral decides the RELEASE, as before; and
        // (FR-70 P1) the released clamp leaves the last measurement as the
        // floor's prior instead of snapping to the constant.
        assert!(!g.link_loop_holding(), "the clamp must have released");
        assert_eq!(g.relieved_floor_bps(), Some(340_000));
    }

    /// FR-59 — `pipe_bps` is the widened estimate every "how fast
    /// is the link" consumer must use. The field defect it closes: on a
    /// link whose sends never block there is NO goodput estimate, so the
    /// goodput-only accessor left P2's queue budget permanently inert while
    /// P1's floor relief — reading the widened value — engaged.
    #[test]
    fn the_pipe_estimate_includes_the_viewer_when_goodput_is_absent() {
        let start = Instant::now();
        let mut g = gov(start);
        // No blocked sends at all — the harness case.
        assert_eq!(g.blocked_send_bps(start), None);
        let mut t = start;
        for _ in 0..3 {
            t += Duration::from_millis(1100);
            g.tick_viewer_window(
                t,
                30,
                || viewer_rate::pack_report(30, false),
                || 0,
                || viewer_rate::pack_link(400_000, 300),
                true,
                |o| o,
                0,
            );
        }
        assert_eq!(
            g.blocked_send_bps(t),
            None,
            "the goodput-only view still sees nothing"
        );
        assert_eq!(
            g.pipe_bps(t, true),
            Some(400_000),
            "…while the widened view has the viewer's arrival rate"
        );
        // Direct transports never consume it.
        assert_eq!(g.pipe_bps(t, false), None);
    }

    /// FR-59 P3 kill switch, and the direct-path guarantee (AC5).
    #[test]
    fn the_viewer_link_clamp_is_off_by_switch_and_on_direct() {
        for (label, flags, constrained) in [
            (
                "kill switch",
                GovernorFlags {
                    viewer_rate_clamp: false,
                    ..GovernorFlags::default()
                },
                true,
            ),
            ("direct path", GovernorFlags::default(), false),
        ] {
            let start = Instant::now();
            let mut g = RateGovernor::new(30, DEPTH, flags, 0, None, start);
            let mut t = start;
            for _ in 0..8 {
                t += Duration::from_millis(1100);
                let w = g
                    .tick_viewer_window(
                        t,
                        30,
                        || viewer_rate::pack_report(30, false),
                        || 0,
                        || viewer_rate::pack_link(400_000, 250),
                        constrained,
                        |o| o,
                        0,
                    )
                    .expect("window due");
                assert!(!w.link_congested, "{label}: must not act");
                for _ in 0..4 {
                    t += Duration::from_millis(200);
                    g.pre_encode_tick(
                        CEILING,
                        crate::encode::MIN_BITRATE_BPS,
                        constrained,
                        DEPTH,
                        t,
                    );
                }
            }
            assert_eq!(
                g.applied_bps(),
                CEILING,
                "{label}: the target must be untouched"
            );
            assert_eq!(g.relieved_floor_bps(), None, "{label}");
        }
    }

    /// FR-59 P6 — a seeded ceiling that the first measured window
    /// contradicts is abandoned, reported ONCE, and the session plans at
    /// the nominal band instead.
    #[test]
    fn a_contradicted_seed_is_abandoned_and_reported_once() {
        let start = Instant::now();
        let mut g = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                measured_ceiling: true,
                age_feedback: true,
                ..GovernorFlags::default()
            },
            8_000_000,
            Some(5_964_000),
            start,
        );
        // Before any measurement the seed rules: 85 % of 5.964 M.
        assert_eq!(g.effective_ceiling(3_000_000, true), 5_069_400);
        let sink = g.goodput_sink();
        for _ in 0..12 {
            sink.record(1_000, Duration::from_micros(20_248));
        }
        let t1 = start + Duration::from_secs(2);
        g.tick_viewer_window(t1, 30, || 0, || 0, || 0, true, |o| o, 0);
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, 0, t1);
        assert_eq!(g.take_seed_abandoned(), Some(5_069_400));
        assert_eq!(g.take_seed_abandoned(), None, "reported exactly once");
        assert_eq!(
            g.effective_ceiling(3_000_000, true),
            3_000_000,
            "back to the nominal band"
        );
    }

    /// FR-79 V5 — the WIRING (the per-reason law is unit-tested in
    /// `encode::evidence`, and finding 4's opposite cell is the B0 sim's).
    ///
    /// A session that has MEASURED its pipe and is sending above it must come
    /// DOWN when the transport stalls. Before V5 every loop that can lower the
    /// rate read `valid` — the goodput fold, the hard MD, the ramp verdict,
    /// the age cut and the viewer clamp alike — so a `TransitStalled` window
    /// reached none of them. Measured with this change reverted: two stalled
    /// windows against a 1.0 Mbps measurement move a 3.0 Mbps target by
    /// nothing at all.
    ///
    /// Field 2026-09-09, CORPLAP-2 AV1 over DERP/TCP (`6aa10d91`): the
    /// estimator accepted ONE sample all session (1,058,145 bps) while the
    /// target ramped to 1,928,555; eleven windows stalled, paint age reached
    /// 7,784 ms, and the rate ENDED HIGHER than it started.
    #[test]
    fn a_transit_stall_above_the_measured_pipe_cuts_the_rate() {
        use crate::encode::pipe_state::PipeState;
        let start = Instant::now();
        let mut g = RateGovernor::new(
            30,
            DEPTH,
            // ⚠️ `measured_ceiling` OFF on purpose. With it on, the
            // measurement itself clamps the ceiling and the rate falls for
            // that reason alone — the cell would pass with this whole change
            // reverted, proving nothing. Off, the only thing left in the loop
            // that can lower the rate on a rejected window is V5.
            GovernorFlags {
                measured_ceiling: false,
                age_feedback: true,
                ..GovernorFlags::default()
            },
            8_000_000,
            None,
            start,
        );
        let mut t = start;
        let sender = |frames_sent: u32| WindowSenderStats {
            inflight_bytes: 1_500,
            budget_bytes: 128_000,
            gate_skips: 0,
            send_wait_max_ms: 1.0,
            send_wait_avg_ms: Some(0.5),
            frames_sent,
            stalled_passes: 0,
        };
        // Three clean windows learn the floors, then the session's ONE
        // measurement folds on the fourth: 1500 bytes per 12 ms = 1.0 Mbps.
        // (12 ms, not 8: `goodput::MIN_BLOCKED_SEND` drops anything under
        // 10 ms at the source, as headroom rather than evidence.)
        let sink = g.goodput_sink();
        for i in 0..4 {
            if i == 3 {
                for _ in 0..12 {
                    sink.record(1_500, Duration::from_millis(12));
                }
            }
            t += Duration::from_millis(1100);
            g.note_window_sender(sender(30));
            g.tick_viewer_window(
                t,
                30,
                || viewer_rate::pack_report(30, false),
                || viewer_rate::pack_age_with_arrival(42, 40, 80, 41),
                || 0,
                true,
                |o| o,
                0,
            )
            .expect("window due");
            // The measuring window carries blocked sends, so it reads
            // `Overproduced` — still VALID evidence, which is how the fold
            // gets its sample at all.
            if i < 3 {
                assert_eq!(g.pipe_state(), Some(PipeState::Clear));
            }
        }
        assert_eq!(
            g.blocked_send_bps(t),
            Some(1_000_000),
            "the one measurement"
        );
        // The rate sits at 3 Mbps — three times what the pipe measured.
        // ⚠️ A real send capacity, not 0: a zero reads as a saturated channel
        // and fires the backpressure MD, which would cut the rate here for a
        // reason that has nothing to do with the stall.
        let before = g
            .pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t)
            .map(|a| a.bps)
            .expect("a first target");
        assert!(before > 1_200_000, "the premise: above the measurement");
        // Two silent windows with the pump still sending: the transport
        // stalled, and it is OUR rate that is above the measurement.
        for _ in 0..2 {
            t += Duration::from_millis(1100);
            g.note_window_sender(sender(30));
            g.tick_viewer_window(t, 30, || 0, || 0, || 0, true, |o| o, 0)
                .expect("window due");
            assert_eq!(g.pipe_state(), Some(PipeState::TransitStalled));
        }
        let after = g
            .pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t)
            .map(|a| a.bps)
            .unwrap_or(before);
        assert!(
            after < before,
            "a transit stall above the measured pipe did not cut the rate \
             (before {before}, after {after})"
        );
        assert_eq!(
            g.evidence_rejected(),
            [0, 2, 0, 0],
            "both rejections were transit stalls"
        );
    }

    /// The kill switch keeps stage 1 observe-and-report only.
    #[test]
    fn measured_ceiling_disabled_keeps_nominal() {
        let start = Instant::now();
        let mut g = RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                measured_ceiling: false,
                age_feedback: true,
                ..GovernorFlags::default()
            },
            0,
            None,
            start,
        );
        let sink = g.goodput_sink();
        for _ in 0..40 {
            sink.record(30_000, Duration::from_millis(24));
        }
        let t1 = start + Duration::from_secs(2);
        g.tick_viewer_window(t1, 30, || 0, || 0, || 0, false, |o| o, 0);
        assert_eq!(g.blocked_send_bps(t1), Some(10_000_000));
        let applied = g
            .pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, t1)
            .expect("initial apply");
        assert_eq!(applied.bps, CEILING, "disabled = nominal band");
    }

    /// Relay sessions IGNORE the measured clamp (field 2026-08-27: the
    /// lumpy TURN-TCP pipe produced near-zero samples during stalls and
    /// the clamp rode the floor — worse than the nominal relay clamp).
    /// The estimate itself still folds (observe-only there).
    #[test]
    fn constrained_sessions_ignore_the_measured_clamp() {
        let start = Instant::now();
        let mut g = gov(start);
        let sink = g.goodput_sink();
        for _ in 0..40 {
            sink.record(30_000, Duration::from_millis(24));
        }
        let t1 = start + Duration::from_secs(2);
        g.tick_viewer_window(t1, 30, || 0, || 0, || 0, false, |o| o, 0);
        assert_eq!(g.blocked_send_bps(t1), Some(10_000_000));
        let applied = g
            .pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t1)
            .expect("initial apply");
        assert_eq!(
            applied.bps, CEILING,
            "constrained = nominal band, measurement observed but not consumed"
        );
    }

    /// The measurement may only ever LOWER the clamp — a pipe measured
    /// faster than the nominal ceiling changes nothing.
    #[test]
    fn measured_clamp_only_lowers() {
        let start = Instant::now();
        let mut g = gov(start);
        let sink = g.goodput_sink();
        // 40 × 60 KB over 24 ms each = 20 Mbps; derived 17M > 12M nominal.
        for _ in 0..40 {
            sink.record(60_000, Duration::from_millis(24));
        }
        let t1 = start + Duration::from_secs(2);
        g.tick_viewer_window(t1, 30, || 0, || 0, || 0, false, |o| o, 0);
        let applied = g
            .pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, t1)
            .expect("initial apply");
        assert_eq!(applied.bps, CEILING, "measurement never raises the ceiling");
    }

    #[test]
    fn first_pre_encode_tick_applies_the_initial_ceiling_once() {
        let now = Instant::now();
        let mut g = gov(now);
        // First tick constructs the AIMD at the ceiling; the seeded
        // last_applied=0 makes take_pending emit the initial target
        // exactly once.
        let applied = g
            .pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, now)
            .expect("initial apply");
        assert_eq!(applied.bps, CEILING);
        assert!(applied.changed);
        assert_eq!(g.applied_bps(), CEILING);
        // Same conditions again — change-gated, nothing to apply.
        assert!(
            g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, now)
                .is_none()
        );
    }

    #[test]
    fn sustained_full_channel_walks_bitrate_down_never_below_floor() {
        let start = Instant::now();
        let mut g = gov(start);
        g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, start);
        let mut last = g.applied_bps();
        // Full-channel gate arms spaced past the MD rate limit walk the
        // target down monotonically; the floor holds no matter how long
        // congestion lasts.
        for i in 1..=100u64 {
            let now = start + Duration::from_millis(600 * i);
            if let Some(applied) = g.on_backpressure_skip(now) {
                assert!(applied.bps <= last, "MD must never raise the target");
                last = applied.bps;
            }
            assert!(g.applied_bps() >= crate::encode::MIN_BITRATE_BPS);
        }
        assert!(
            last < CEILING,
            "sustained congestion must have decreased the target"
        );
    }

    #[test]
    fn lowering_the_ceiling_clamps_the_target_immediately() {
        let now = Instant::now();
        let mut g = gov(now);
        g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, now);
        // A transport flip to relay shrinks the ceiling; the very next
        // tick must emit the clamped target (refine can raise dims —
        // and thereby the requested ceiling — but the constrained
        // clamp always wins; see also the policy-level flatness test).
        let relay_ceiling = 3_000_000;
        let applied = g
            .pre_encode_tick(
                relay_ceiling,
                crate::encode::MIN_BITRATE_BPS,
                false,
                DEPTH,
                now,
            )
            .expect("clamp emits");
        assert_eq!(applied.bps, relay_ceiling);
    }

    /// The area-scaled floor rides the same tick: a collapsed target is
    /// lifted to the floor immediately, and a relay flip (flat floor +
    /// low ceiling, same call order as the pumps) restores MD room.
    #[test]
    fn floor_passes_through_to_the_controller() {
        let start = Instant::now();
        let mut g = gov(start);
        g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, start);
        // Sustained congestion walks the target to the flat floor.
        let mut now = start;
        for _ in 0..40 {
            now += Duration::from_millis(600);
            g.on_backpressure_skip(now);
        }
        assert_eq!(g.applied_bps(), crate::encode::MIN_BITRATE_BPS);
        // A big-screen floor lifts it on the next tick.
        let applied = g
            .pre_encode_tick(CEILING, 3_000_000, false, DEPTH, now)
            .expect("floor lift emits");
        assert_eq!(applied.bps, 3_000_000);
        // Relay flip: flat floor + 2 M ceiling in one tick — the clamp
        // wins, the stale floor cannot pin the target above it.
        let applied = g
            .pre_encode_tick(2_000_000, crate::encode::MIN_BITRATE_BPS, false, DEPTH, now)
            .expect("clamp emits");
        assert_eq!(applied.bps, 2_000_000);
    }

    #[test]
    fn rebuild_forces_a_reapply_of_the_current_target() {
        let now = Instant::now();
        let mut g = gov(now);
        g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, now);
        assert!(
            g.pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, now)
                .is_none()
        );
        // A fresh encoder starts at its constructor maxrate — the
        // governor must re-emit the (unchanged) desired target so the
        // pump re-applies it.
        g.on_encoder_rebuilt();
        let applied = g
            .pre_encode_tick(CEILING, crate::encode::MIN_BITRATE_BPS, false, DEPTH, now)
            .expect("post-rebuild reapply");
        assert_eq!(applied.bps, CEILING);
        assert!(
            !applied.changed,
            "reapply of the same value is not a change (no log)"
        );
    }

    #[test]
    fn viewer_window_is_one_second_gated_and_report_consumed_lazily() {
        let start = Instant::now();
        let mut g = gov(start);
        let mut consumed = 0u32;
        // Not due yet — the report closure must NOT run (the pump's
        // atomic swap would otherwise eat a report early).
        let r = g.tick_viewer_window(
            start + Duration::from_millis(300),
            30,
            || {
                consumed += 1;
                0
            },
            || 0,
            || 0,
            false,
            |own| own,
            0,
        );
        assert!(r.is_none());
        assert_eq!(consumed, 0, "report consumed before the window was due");
        let r = g.tick_viewer_window(
            start + Duration::from_millis(1100),
            30,
            || {
                consumed += 1;
                0
            },
            || 0,
            || 0,
            false,
            |own| own,
            0,
        );
        assert!(r.is_some());
        assert_eq!(consumed, 1);
    }

    #[test]
    fn skip_gate_keeps_one_in_n_and_never_sheds_forced_keyframes() {
        let start = Instant::now();
        let mut g = gov(start);
        // Fold a follower divisor of 3 in (own report healthy → own
        // divisor 1; the shared stream paces to the slowest viewer).
        let w = g
            .tick_viewer_window(
                start + Duration::from_secs(2),
                30,
                || 0,
                || 0,
                || 0,
                false,
                |_| 3,
                0,
            )
            .expect("window due");
        assert_eq!(w.skip_divisor, 3);
        assert!(w.changed);
        // Divisor 3 ⇒ skip, skip, keep — repeating.
        let pattern: Vec<bool> = (0..6).map(|_| g.should_skip_delta_frame(false)).collect();
        assert_eq!(pattern, [true, true, false, true, true, false]);
        assert_eq!(g.frames_skipped_decode(), 4);
        // A forced keyframe is NEVER shed and doesn't advance the cycle.
        assert!(!g.should_skip_delta_frame(true));
        assert!(
            g.should_skip_delta_frame(false),
            "cycle resumes where it was"
        );
    }

    /// Plan invariant (P8c #2): the divisor can never starve the
    /// refine/quiet-tick signal — the viewer-rate min_fps floor (12)
    /// bounds the divisor at ceil(target_fps / 12), so encoded frames
    /// keep flowing no matter how weak the reported decode rate is.
    #[test]
    fn divisor_never_starves_encoded_cadence() {
        let start = Instant::now();
        let mut g = gov(start);
        for i in 1..=30u64 {
            let now = start + Duration::from_secs(2 * i);
            // A viewer reporting 1 fps and struggling, forever.
            let w = g.tick_viewer_window(
                now,
                30,
                || viewer_rate::pack_report(1, true),
                || 0,
                || 0,
                false,
                |own| own,
                0,
            );
            let w = w.expect("2 s apart — every window due");
            assert!(
                w.skip_divisor <= 3,
                "divisor {} exceeds ceil(30/min_fps=12)=3 — encoded cadence starved",
                w.skip_divisor
            );
        }
    }

    /// P5 — on a HW encoder, sustained saturation engages the fps pace
    /// and MASKS the bitrate factor (pixels-bound encode time doesn't
    /// respond to bitrate); recovery releases both.
    #[test]
    fn hw_saturation_paces_fps_and_masks_the_factor() {
        let start = Instant::now();
        let mut g = gov(start);
        for i in 1..=10u64 {
            let _ = g.heartbeat(25.0, true, 60, start + Duration::from_secs(2 * i));
        }
        assert_eq!(g.paced_fps(), Some(40), "25 ms EWMA ⇒ ~40 fps pace");
        assert_eq!(g.encode_factor(), 1.0, "factor masked while paced");
        for i in 11..=30u64 {
            let _ = g.heartbeat(8.0, true, 60, start + Duration::from_secs(2 * i));
        }
        assert_eq!(g.paced_fps(), None, "recovered encoder releases the pace");
    }

    /// FR-15 — sustained viewer age over the learned floor on a
    /// CONSTRAINED transport lowers the target, and the decrease reaches
    /// the pump through the ordinary `pre_encode_tick` apply path (the
    /// window tick must never consume it itself).
    #[test]
    fn constrained_age_excess_lowers_the_target_through_the_normal_apply() {
        let start = Instant::now();
        let mut g = gov(start);
        // Establish the AIMD at the relay-ish ceiling.
        let ceiling = 3_000_000;
        let first = g
            .pre_encode_tick(ceiling, crate::encode::MIN_BITRATE_BPS, true, DEPTH, start)
            .expect("initial apply");
        assert_eq!(first.bps, ceiling);
        // Two windows at a ~60 ms floor, then sustained 200 ms age.
        let mut applied = first.bps;
        for (i, (avg, min)) in [(62u16, 60u16), (64, 61), (200, 62), (205, 63), (210, 63)]
            .into_iter()
            .enumerate()
        {
            let t = start + Duration::from_millis(1100 * (i as u64 + 1));
            let w = g
                .tick_viewer_window(
                    t,
                    30,
                    || viewer_rate::pack_report(30, false),
                    || viewer_rate::pack_age(avg, min, 100),
                    || 0,
                    true,
                    |o| o,
                    0,
                )
                .expect("window due");
            assert_eq!(w.age_ms, Some((avg, min)));
            if let Some(a) =
                g.pre_encode_tick(ceiling, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t)
            {
                applied = a.bps;
            }
        }
        assert!(
            applied < ceiling,
            "sustained age excess left the target at the open-loop ceiling ({applied})"
        );
        assert_eq!(g.viewer_age().map(|(_, f)| f), Some(60), "floor learned");
    }

    /// FR-15 — the same age history on a DIRECT transport changes
    /// nothing (direct owns the measured ceiling + byte gate), and the
    /// kill switch reverts constrained sessions to the same open loop.
    #[test]
    fn age_loop_is_constrained_only_and_respects_the_kill_switch() {
        let ceiling = 3_000_000;
        let ages = [(62u16, 60u16), (64, 61), (200, 62), (205, 63), (210, 63)];
        for (label, constrained, feedback) in
            [("direct", false, true), ("kill switch", true, false)]
        {
            let start = Instant::now();
            let mut g = RateGovernor::new(
                30,
                DEPTH,
                GovernorFlags {
                    measured_ceiling: false,
                    age_feedback: feedback,
                    ..GovernorFlags::default()
                },
                0,
                None,
                start,
            );
            let mut applied = g
                .pre_encode_tick(
                    ceiling,
                    crate::encode::MIN_BITRATE_BPS,
                    constrained,
                    DEPTH,
                    start,
                )
                .expect("initial apply")
                .bps;
            for (i, (avg, min)) in ages.into_iter().enumerate() {
                let t = start + Duration::from_millis(1100 * (i as u64 + 1));
                let w = g
                    .tick_viewer_window(
                        t,
                        30,
                        || viewer_rate::pack_report(30, false),
                        || viewer_rate::pack_age(avg, min, 100),
                        || 0,
                        constrained,
                        |o| o,
                        0,
                    )
                    .expect("window due");
                assert!(!w.age_over, "{label}: age must not act");
                if let Some(a) = g.pre_encode_tick(
                    ceiling,
                    crate::encode::MIN_BITRATE_BPS,
                    constrained,
                    DEPTH,
                    t,
                ) {
                    applied = a.bps;
                }
            }
            assert_eq!(applied, ceiling, "{label}: target moved anyway");
            // The floor is still LEARNED everywhere — the heartbeat reports
            // ages on every transport, it just doesn't act on them.
            assert_eq!(g.viewer_age().map(|(_, f)| f), Some(60), "{label}");
        }
    }

    /// FR-15 — a viewer that reports no age (pre-FR-15 web) leaves the
    /// constrained session byte-identical to the open-loop posture.
    #[test]
    fn absent_age_report_leaves_the_loop_off() {
        let start = Instant::now();
        let mut g = gov(start);
        let ceiling = 3_000_000;
        let mut applied = g
            .pre_encode_tick(ceiling, crate::encode::MIN_BITRATE_BPS, true, DEPTH, start)
            .expect("initial apply")
            .bps;
        for i in 1..=6u64 {
            let t = start + Duration::from_millis(1100 * i);
            let w = g
                .tick_viewer_window(
                    t,
                    30,
                    || viewer_rate::pack_report(30, false),
                    || 0, // no age slot written this window
                    || 0, // no link slot written this window
                    true,
                    |o| o,
                    0,
                )
                .expect("window due");
            assert_eq!(w.age_ms, None);
            assert!(!w.age_over);
            if let Some(a) =
                g.pre_encode_tick(ceiling, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t)
            {
                applied = a.bps;
            }
        }
        assert_eq!(applied, ceiling);
        assert_eq!(g.viewer_age(), None);
    }

    #[test]
    fn heartbeat_saturation_lowers_the_factor() {
        let start = Instant::now();
        let mut g = gov(start);
        assert_eq!(g.encode_factor(), 1.0);
        // Sustained encoder saturation (avg encode ≫ frame budget)
        // must walk the maxrate factor down; the tier may or may not
        // step within this horizon (its own windows + cooldown) — the
        // factor is the invariant here.
        for i in 1..=20u64 {
            let _ = g.heartbeat(100.0, false, 30, start + Duration::from_secs(2 * i));
        }
        assert!(
            g.encode_factor() < 1.0,
            "sustained saturation left the factor at full quality"
        );
        assert!(g.encode_factor() >= crate::encode::encode_pressure::FACTOR_FLOOR);
    }

    /// FR-71 T2 — a send blocked ≥ `HARD_STALL` followed by a window in which
    /// the pipe pushed back on NOTHING is a pause of the pipe, not its
    /// capacity: nothing halves, no ceiling is abandoned, no floor is relieved.
    /// Field 2026-09-08 12:15 UTC (CORPLAP-1 on the corp VPN, `6a9fed1d`): an
    /// overlay rekey storm blocked two sends for 2.9 s and 7.4 s on a pipe that
    /// carried 6.6 M at 50 ms twenty seconds later, and four movers read those
    /// blocked sends as a 1.6 M pipe — 6.60 → 0.68 M in 36 s, three minutes
    /// back. The hold (T1b) masked none of them.
    fn t2_governor(now: Instant) -> RateGovernor {
        RateGovernor::new(
            30,
            DEPTH,
            GovernorFlags {
                floor_relief: true,
                seed_contradiction: true,
                measured_ceiling: true,
                age_feedback: true,
                slow_start: false,
                ..GovernorFlags::default()
            },
            8_000_000,
            Some(6_600_000),
            now,
        )
    }

    fn t2_sender(frames_sent: u32) -> WindowSenderStats {
        WindowSenderStats {
            inflight_bytes: 0,
            budget_bytes: 128_000,
            gate_skips: 0,
            send_wait_max_ms: 0.1,
            send_wait_avg_ms: Some(0.05),
            frames_sent,
            stalled_passes: 0,
        }
    }

    /// One reported, unblocked window at 50 ms age, then the pump's tick.
    fn t2_clean_window(g: &mut RateGovernor, t: Instant) {
        g.note_window_sender(t2_sender(30));
        g.tick_viewer_window(
            t,
            30,
            || viewer_rate::pack_report(30, false),
            || viewer_rate::pack_age_with_arrival(50, 49, 80, 50),
            || 0,
            true,
            |o| o,
            0,
        )
        .expect("window due");
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
    }

    #[test]
    fn a_hard_stall_inside_a_stalled_pump_pass_cuts_nothing() {
        let start = Instant::now();
        let mut g = t2_governor(start);
        let mut t = start;
        for _ in 0..4 {
            t += Duration::from_millis(1100);
            t2_clean_window(&mut g, t);
        }
        let before = g.applied_bps();
        let ceiling_before = g.learned_ceiling_bps();
        // The opener runs at 85 % of the remembered 6.6 M.
        assert!(
            ceiling_before >= 5_000_000,
            "the seeded ceiling stands: {ceiling_before}"
        );
        assert!(
            before > 3_000_000,
            "the session runs above the nominal: {before}"
        );

        // The stall: one send blocked 2.9 s inside a pump pass that overran its
        // budget — the 12:15 shape, where every timed phase read 0 ms and the
        // rest was `other`.
        g.goodput_sink().record(25_000, Duration::from_millis(2900));
        t += Duration::from_millis(2900);
        g.note_send_stall(Duration::from_millis(2900), t);
        g.note_window_sender(WindowSenderStats {
            stalled_passes: 1,
            ..t2_sender(2)
        });
        g.tick_viewer_window(t, 30, || 0, || 0, || 0, true, |o| o, 0)
            .expect("window due");
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);

        // The next window: reported, nothing blocked, age at the floor — the
        // pipe is back exactly as it was.
        t += Duration::from_millis(1100);
        t2_clean_window(&mut g, t);

        assert_eq!(g.applied_bps(), before, "a pause must not halve the rate");
        assert_eq!(
            g.learned_ceiling_bps(),
            ceiling_before,
            "a pause is not a measurement that contradicts the learned ceiling"
        );
        assert_eq!(g.relieved_floor_bps(), None, "a pause relieves no floor");
        // The window was rejected for the agent's own stall, and nothing else
        // read it.
        assert_eq!(g.evidence_rejected()[0], 1, "the agent-stalled window");
    }

    /// …and the control: the same blocked send on a FREE loop is the pipe
    /// pushing back, which is the case FR-35's ×0.5 was written for. The gate
    /// accepts the window (a full queue on a free loop is exactly what the
    /// goodput estimator measures), so the halving applies at that window and
    /// the measurement folds.
    #[test]
    fn a_hard_stall_on_a_free_loop_still_halves_at_its_own_window() {
        let start = Instant::now();
        let mut g = t2_governor(start);
        let mut t = start;
        for _ in 0..4 {
            t += Duration::from_millis(1100);
            t2_clean_window(&mut g, t);
        }
        let before = g.applied_bps();
        // A thin pipe: the send blocks for 2.9 s and the viewer keeps
        // reporting, with no pump pass overrunning its budget.
        g.goodput_sink().record(25_000, Duration::from_millis(2900));
        t += Duration::from_millis(2900);
        g.note_send_stall(Duration::from_millis(2900), t);
        g.note_window_sender(t2_sender(12));
        g.tick_viewer_window(
            t,
            30,
            || viewer_rate::pack_report(12, false),
            || viewer_rate::pack_age_with_arrival(300, 50, 80, 299),
            || 0,
            true,
            |o| o,
            0,
        )
        .expect("window due");
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        assert_eq!(
            g.pipe_state(),
            Some(crate::encode::pipe_state::PipeState::Overproduced),
            "a blocked send on a free loop is the sender's own back-pressure"
        );
        assert!(
            g.applied_bps() <= before / 2 + 1_000,
            "a hard stall the gate accepted halves: {} vs {before}",
            g.applied_bps()
        );
        assert_eq!(
            g.evidence_rejected(),
            [0, 0, 0, 0],
            "every window was evidence"
        );
        assert!(
            g.relieved_floor_bps().is_some(),
            "an accepted measurement relieves the floor"
        );
    }

    /// FR-71 T2b — the viewer's arrival-rate report that lands in the first
    /// window AFTER a `transit-stalled` run describes the stall, not the pipe.
    /// Field 2026-09-08 14:52 UTC (CORPLAP-1, 0.4.90 with T2): a carrier
    /// demotion stalled the relay for six seconds; the hold kept 7.45 M through
    /// three stalled windows with 0 B in flight, then the viewer reported
    /// 70 kbps of arrivals with a growing queue and the P3 clamp set the
    /// target to 834,800 while the sender's queue read over budget — no send
    /// had blocked for a second, so T2 had nothing to defer.
    #[test]
    fn a_link_report_in_the_shadow_of_a_transit_stall_does_not_arm_the_clamp() {
        let start = Instant::now();
        let mut g = t2_governor(start);
        g.slow_link.viewer_rate_clamp = true;
        let mut t = start;
        for _ in 0..4 {
            t += Duration::from_millis(1100);
            t2_clean_window(&mut g, t);
        }
        let before = g.applied_bps();
        assert!(before > 3_000_000, "runs above the nominal: {before}");
        // The stall: a silent window, then two whose transit share is seconds
        // — the sender idle throughout.
        t += Duration::from_millis(1100);
        g.note_window_sender(t2_sender(30));
        g.tick_viewer_window(t, 30, || 0, || 0, || 0, true, |o| o, 0)
            .expect("window due");
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        for (age, arrival, link) in [
            (2135u16, 2134u16, 0u64),
            (3626, 3624, viewer_rate::pack_link(70_340, 300)),
        ] {
            t += Duration::from_millis(1100);
            g.note_window_sender(t2_sender(30));
            g.tick_viewer_window(
                t,
                30,
                || viewer_rate::pack_report(1, false),
                || viewer_rate::pack_age_with_arrival(age, age - 30, 80, arrival),
                || link,
                true,
                |o| o,
                0,
            )
            .expect("window due");
            assert_eq!(
                g.pipe_state(),
                Some(crate::encode::pipe_state::PipeState::TransitStalled)
            );
            g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        }
        assert_eq!(
            g.applied_bps(),
            before,
            "the hold keeps the rate through the stall"
        );
        // The window after: the backlog lands (age 5.8 s), the queue reads
        // over budget, and the viewer's link report says 70 kbps arrived
        // while its queue grew — the stall's own numbers.
        t += Duration::from_millis(1100);
        g.note_window_sender(WindowSenderStats {
            inflight_bytes: 200_000,
            budget_bytes: 128_000,
            gate_skips: 83,
            send_wait_max_ms: 278.0,
            send_wait_avg_ms: Some(19.9),
            frames_sent: 12,
            stalled_passes: 0,
        });
        g.tick_viewer_window(
            t,
            30,
            || viewer_rate::pack_report(7, false),
            || viewer_rate::pack_age_with_arrival(5785, 5700, 80, 5760),
            || viewer_rate::pack_link(834_800, 600),
            true,
            |o| o,
            0,
        )
        .expect("window due");
        g.pre_encode_tick(3_000_000, crate::encode::MIN_BITRATE_BPS, true, DEPTH, t);
        assert!(
            !g.link_loop_holding(),
            "a link report in the stall's shadow must not arm the arrival-rate clamp"
        );
        // Two shadowed reports: the second stalled window carried one too.
        assert_eq!(
            g.evidence_rejected()[2],
            1,
            "the window in the stall's shadow"
        );
        assert!(
            g.applied_bps() > before / 2,
            "no clamp to the stall's arrival rate: {} vs {before}",
            g.applied_bps()
        );
        // The windows after THAT are the pipe again: growing reports there act.
        for q in [900i16, 1200] {
            t += Duration::from_millis(1100);
            g.note_window_sender(t2_sender(30));
            g.tick_viewer_window(
                t,
                30,
                || viewer_rate::pack_report(30, false),
                || viewer_rate::pack_age_with_arrival(60, 50, 80, 59),
                || viewer_rate::pack_link(400_000, q),
                true,
                |o| o,
                0,
            )
            .expect("window due");
        }
        assert!(
            g.link_loop_holding(),
            "out of the shadow the clamp reads the reports again"
        );
        assert_eq!(
            g.evidence_rejected()[2],
            1,
            "the window in the stall's shadow"
        );
    }

    /// FR-112 P2 — the VP9-444 pump's pace is the software one (`SoftwarePace`,
    /// tested in `encode_pressure`): paced to what the encoder sustains, never
    /// below 30, and apart from the hardware pace, which it never moves.
    #[test]
    fn the_software_pace_is_its_own() {
        let mut g = gov(Instant::now());
        assert_eq!(g.pace_software(25.0, 60), Some(40), "1000 / 25 ms = 40 fps");
        assert_eq!(g.paced_software_fps(), Some(40));
        assert_eq!(g.paced_fps(), None, "the hardware pace is untouched");
        let mut g = gov(Instant::now());
        assert_eq!(g.pace_software(45.0, 60), Some(30), "22 fps: held at 30");
    }
}
