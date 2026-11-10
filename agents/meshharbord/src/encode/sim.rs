// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-63 B0 — a deterministic simulator for the remote-desktop rate laws.
//!
//! # Why this exists
//!
//! Every rate decision this codebase makes has been verified by opening a
//! session on somebody's laptop and reading a heartbeat. That works, and it
//! found real bugs, but it has two properties that keep costing us releases:
//!
//! 1. **The interesting cells are the ones we cannot summon.** FR-63's AC0b —
//!    "the opener's ramp removes the harm" — was blocked for a day because no
//!    reachable host could produce a pipe thin enough for the *baseline arm to
//!    fail*. Three cells were tried; each was genuinely constrained and none
//!    over-drove, because a 2.55 Mbps opener into a relay carrying ~3 Mbps is
//!    not an over-drive. The field case that motivated the whole phase was
//!    ~213 kbps, and nothing agent-side manufactures that.
//! 2. **A field run is not repeatable.** The pipe, the content and the encoder
//!    all move between arms, so a difference is never attributable with
//!    confidence to the one flag under test.
//!
//! A simulator fixes both, at the cost of being a *model*. So the rule for
//! reading anything this module prints:
//!
//! ⚠️ **A simulator result is evidence about the LAW, not about the fleet.** It
//! can prove that a rate law over-drives a 213 kbps token bucket; it cannot
//! prove that a corporate VPN behaves like a token bucket. Field verification
//! is not replaced by this — it is *aimed* by it. Acceptance criteria that say
//! "field-verified" still mean field-verified.
//!
//! # What is modelled, and what is not
//!
//! The harness drives the **shipped laws directly** — [`SlowStart`] and
//! [`AimdController`] are the real types, in the real order `governor.rs`
//! calls them (`set_floor` then `set_ceiling` then `observe`; one ramp verdict
//! per viewer window). Nothing here re-implements a law, so a fixture that
//! passes is a statement about production code rather than about a copy of it.
//!
//! Modelled: a token-bucket link with an RTT, a finite buffer, seeded loss and
//! scheduled stalls; the bounded send channel the AIMD actually observes
//! (occupancy and full-ness); CBR frame production with a keyframe multiplier;
//! and a viewer folding arrivals into `decodestat`-shaped windows (age, p95
//! age, `rx_bps`, `queue_ms` by the same Σ(Δarrival − Δwire) the browser's
//! `rc-hop-stats.ts` uses).
//!
//! NOT modelled, deliberately: the encoder's rate-following error (FR-62's
//! subject — here the encoder hits its target exactly, so a fixture failure is
//! never an encoder artefact), packet-level SCTP behaviour, the ICE ladder,
//! and anything about *pixels*. The send channel and the SCTP buffer are
//! collapsed into one queue, because they are in series and the slow end
//! governs; the AIMD's view of that queue is what it sees in production.
//!
//! # Test-only
//!
//! `#[cfg(test)]`, so this ships zero bytes. It builds on the DEFAULT feature
//! set — no FFmpeg, no capture backends — because `cargo test -p meshharbord
//! --lib` is the lane that runs it, and that lane compiles none of the pump.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::aimd::AimdController;
use super::pipe_state::PipeState;
use super::slow_start::SlowStart;

/// The tick the simulator advances by. One millisecond is fine enough that a
/// 30 fps frame (33 ms) and the AIMD's 500 ms decrease spacing are both many
/// ticks, and coarse enough that a 60 s scenario is 60 000 iterations.
const TICK: Duration = Duration::from_millis(1);

/// The viewer/heartbeat window, mirroring `governor::VIEWER_WINDOW`.
const WINDOW: Duration = Duration::from_secs(1);

/// The absolute legibility stop, mirroring the default of
/// `encode::slow_link_min_bitrate_bps()`. Explicit rather than read from the
/// environment: a simulator whose result depends on an env var is not
/// deterministic, which is the one property it exists to have.
const HARD_MIN_BPS: u32 = 200_000;

/// Send-channel depth on a constrained path (`peer.rs`: `if constrained { 4 }`).
const CONSTRAINED_DEPTH: u32 = 4;

// ---------------------------------------------------------------------------
// Deterministic RNG
// ---------------------------------------------------------------------------

/// xorshift64*, so loss is reproducible from a scenario's seed and a failing
/// fixture can be re-run byte-for-byte. `rand` is not a dependency of this
/// crate's default build and a simulator does not need a good generator — it
/// needs the SAME generator every time.
#[derive(Debug, Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point of xorshift; refuse it.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// True with probability `pct/100`.
    fn chance_pct(&mut self, pct: u32) -> bool {
        if pct == 0 {
            return false;
        }
        (self.next_u64() % 100) < u64::from(pct.min(100))
    }
}

// ---------------------------------------------------------------------------
// The pipe
// ---------------------------------------------------------------------------

/// A scheduled outage: the link carries nothing for `len` starting at `at`.
/// Models a DERP relay's reconnect or a Wi-Fi roam.
#[derive(Debug, Clone, Copy)]
pub struct Stall {
    pub at: Duration,
    pub len: Duration,
}

/// What the link does.
#[derive(Debug, Clone)]
pub struct PipeSpec {
    /// Drain rate from t=0 until the first entry of `rate_steps`.
    pub rate_bps: u32,
    /// Piecewise rate changes `(at, rate_bps)`, applied in order. A link that
    /// degrades mid-session (the airport hotspot) or recovers.
    pub rate_steps: Vec<(Duration, u32)>,
    /// Bytes the link will hold before tail-dropping.
    pub buffer_bytes: u32,
    /// Round trip; a frame's arrival is one half-RTT after its last byte
    /// leaves the sender.
    pub rtt: Duration,
    /// Seeded per-frame loss, percent.
    pub loss_pct: u32,
    pub stalls: Vec<Stall>,
    /// FR-71 — outages that delay ARRIVAL without stopping the sender: frames
    /// still leave the send channel at the pipe's rate and sit in transit
    /// until the stall ends. The shape of a DERP/TCP head-of-line block seen
    /// from the agent (finding 4: a 4.9 s paint with 1485 bytes in the queue),
    /// as opposed to [`Self::stalls`], which freezes the drain and so fills
    /// the sender's queue — a stall the sender CAN see.
    pub transit_stalls: Vec<Stall>,
}

impl PipeSpec {
    /// A steady link with no loss and no stalls.
    pub fn steady(rate_bps: u32, rtt_ms: u64, buffer_bytes: u32) -> Self {
        Self {
            rate_bps,
            rate_steps: Vec::new(),
            buffer_bytes,
            rtt: Duration::from_millis(rtt_ms),
            loss_pct: 0,
            stalls: Vec::new(),
            transit_stalls: Vec::new(),
        }
    }

    fn rate_at(&self, t: Duration) -> u32 {
        let mut rate = self.rate_bps;
        for (at, r) in &self.rate_steps {
            if t >= *at {
                rate = *r;
            }
        }
        rate
    }

    fn stalled_at(&self, t: Duration) -> bool {
        self.stalls.iter().any(|s| t >= s.at && t < s.at + s.len)
    }
}

/// One frame sitting in the send channel / link buffer.
#[derive(Debug, Clone, Copy)]
struct QFrame {
    bytes: u32,
    /// When the encoder produced it — the anchor for viewer age.
    produced: Duration,
    remaining_bits: u64,
}

/// A frame that reached the viewer.
#[derive(Debug, Clone, Copy)]
struct Arrival {
    bytes: u32,
    produced: Duration,
    /// When the last bit left the send channel — FR-71's sender/transit
    /// split: `sent − produced` is the sender's share, `at − sent` transit.
    sent: Duration,
    /// When the far end acked it — the moment it stops counting against the
    /// sender's channel (`inflight_bytes`).
    acked: Duration,
    /// When the viewer observed it (the paint, for the sim's instant viewer).
    at: Duration,
}

/// The link plus the bounded send channel in front of it.
#[derive(Debug)]
struct Pipe {
    spec: PipeSpec,
    depth: u32,
    queue: VecDeque<QFrame>,
    queued_bytes: u32,
    credit_bits: u64,
    rng: Rng,
    /// Frames whose last byte has left the sender but which have not yet
    /// arrived (in flight for half an RTT).
    in_flight: VecDeque<Arrival>,
    /// FR-71 — acked by the far SCTP end but not yet OBSERVED by the viewer:
    /// a transit stall beyond the ack point holds frames here, where the
    /// sender cannot count them (finding 4: `inflight=1485 B`, `age=4903 ms`).
    held: VecDeque<Arrival>,
    /// FR-71 — when the last held frame finishes crossing the link after a
    /// transit stall (the backlog drains at the link's rate, not at once).
    release_cursor: Duration,
}

impl Pipe {
    fn new(spec: PipeSpec, depth: u32, seed: u64) -> Self {
        Self {
            spec,
            depth: depth.max(1),
            queue: VecDeque::new(),
            queued_bytes: 0,
            credit_bits: 0,
            rng: Rng::new(seed),
            in_flight: VecDeque::new(),
            held: VecDeque::new(),
            release_cursor: Duration::ZERO,
        }
    }

    /// Frames waiting in the channel — what the AIMD reads as occupancy.
    fn occupied(&self) -> u32 {
        self.queue.len() as u32
    }

    /// FR-70 P1 — bytes handed to the transport and not yet delivered:
    /// queued behind the token bucket PLUS in flight for the half-RTT. The
    /// pump's `bytes_inflight` ledger, which the FR-59 P2 byte-budget gate
    /// compares against its budget.
    fn inflight_bytes(&self) -> usize {
        self.queued_bytes as usize
            + self
                .in_flight
                .iter()
                .map(|a| a.bytes as usize)
                .sum::<usize>()
    }

    /// Is the channel refusing frames?
    ///
    /// ⚠️ **Both limits report through this one predicate, and that is
    /// load-bearing.** An earlier version refused byte-full offers inside
    /// `offer` while `full()` reported only the frame-depth limit, so on a
    /// thin pipe (where three big frames fill a 32 KB buffer before four
    /// frames fill the channel) every frame was dropped and **the AIMD was
    /// never told**: it sat at its opening 2.55 Mbps for 40 s with no
    /// decrease, because its only congestion input was disconnected. In
    /// production backpressure propagates — a full SCTP buffer blocks the
    /// send task, which fills the bounded mpsc, which is what the pump's
    /// `try_send` failure and `on_backpressure_skip` report. A model that
    /// drops the signal is testing the law with its eyes shut.
    fn full(&self) -> bool {
        self.occupied() >= self.depth || self.queued_bytes >= self.spec.buffer_bytes
    }

    /// Offer a frame. `false` means the channel refused it — production's
    /// backpressure skip.
    fn offer(&mut self, bytes: u32, now: Duration) -> bool {
        if self.full() {
            return false;
        }
        self.queued_bytes += bytes;
        self.queue.push_back(QFrame {
            bytes,
            produced: now,
            remaining_bits: u64::from(bytes) * 8,
        });
        true
    }

    /// Advance one tick; return the frames that ARRIVED during it, and how
    /// many were lost in transit.
    ///
    /// ⚠️ The loss count is returned rather than discarded because a viewer
    /// that never learns about loss reports `frames_lost: 0` forever, and a
    /// fixture with `loss_pct` set would then be silently testing a lossless
    /// link — a green run proving the opposite of what it claims.
    fn advance(&mut self, now: Duration) -> (Vec<Arrival>, u32) {
        let mut lost = 0u32;
        if !self.spec.stalled_at(now) {
            // bits per tick = rate_bps × tick_ms / 1000
            let ms = TICK.as_millis() as u64;
            self.credit_bits += u64::from(self.spec.rate_at(now)) * ms / 1000;
        }
        while self.credit_bits > 0 {
            let Some(head) = self.queue.front_mut() else {
                // An idle link does not bank capacity: a token bucket that
                // accumulated while nothing was queued would let the next
                // frame teleport, which is exactly the "a fast sample is not
                // evidence" error `goodput.rs` documents.
                self.credit_bits = 0;
                break;
            };
            let take = self.credit_bits.min(head.remaining_bits);
            head.remaining_bits -= take;
            self.credit_bits -= take;
            if head.remaining_bits == 0 {
                let done = self.queue.pop_front().expect("front exists");
                self.queued_bytes = self.queued_bytes.saturating_sub(done.bytes);
                // FR-71: a transit stall BEYOND the ack point. The far SCTP
                // end acks on time, so the send channel drains at the pipe's
                // rate and `inflight_bytes` stays small — nothing the sender
                // can see moves; the frame is simply observed late, when the
                // stall lifts. (A stall BEFORE the ack point backs the sender
                // up and is `stalls`, the freeze model.)
                let acked = now + self.spec.rtt / 2;
                let mut observed = acked;
                for s in &self.spec.transit_stalls {
                    if observed >= s.at && observed < s.at + s.len {
                        observed = s.at + s.len;
                    }
                }
                // …and the backlog drains at the link's rate once the stall
                // lifts, not all at once: each held frame is observed after
                // the one before it has crossed the link, and a live frame
                // that arrives while the backlog is still draining queues
                // behind it. Only then — a frame observed at its own ack
                // time was already paced by the token bucket, and re-adding
                // its serialisation here shifted every steady-state cell.
                if observed > acked || self.release_cursor > acked {
                    observed = observed.max(self.release_cursor);
                    let ser_secs =
                        f64::from(done.bytes) * 8.0 / f64::from(self.spec.rate_at(now)).max(1.0);
                    self.release_cursor = observed + Duration::from_secs_f64(ser_secs);
                }
                if self.rng.chance_pct(self.spec.loss_pct) {
                    lost += 1;
                } else {
                    self.in_flight.push_back(Arrival {
                        bytes: done.bytes,
                        produced: done.produced,
                        sent: now,
                        acked,
                        at: observed,
                    });
                }
            }
        }
        // Two stages, both in order: the ack (what the sender accounts
        // for), then the viewer's observation (what the age measures).
        while let Some(front) = self.in_flight.front() {
            if front.acked <= now {
                self.held
                    .push_back(self.in_flight.pop_front().expect("front exists"));
            } else {
                break;
            }
        }
        let mut arrived = Vec::new();
        while let Some(front) = self.held.front() {
            if front.at <= now {
                arrived.push(self.held.pop_front().expect("front exists"));
            } else {
                break;
            }
        }
        (arrived, lost)
    }
}

// ---------------------------------------------------------------------------
// The encoder
// ---------------------------------------------------------------------------

/// How busy the screen is over time — scales frame size around the CBR mean.
#[derive(Debug, Clone)]
pub enum Motion {
    /// Every frame is the CBR size. The cleanest signal for a rate-law test.
    Steady,
    /// Quiet, with periodic bursts `factor`× the CBR size for `len`.
    Bursts {
        period: Duration,
        len: Duration,
        factor: u32,
    },
}

impl Motion {
    fn factor_at(&self, t: Duration) -> u32 {
        match self {
            Motion::Steady => 1,
            Motion::Bursts {
                period,
                len,
                factor,
            } => {
                let p = period.as_millis().max(1);
                let phase = t.as_millis() % p;
                if phase < len.as_millis() { *factor } else { 1 }
            }
        }
    }
}

/// A CBR encoder that hits its target exactly.
///
/// ⚠️ Deliberately perfect. FR-62 is the FR about an encoder that does NOT
/// follow its target; modelling that error here would make every FR-63 fixture
/// failure ambiguous between "the law is wrong" and "the encoder lagged".
#[derive(Debug)]
struct EncoderSim {
    fps: u32,
    /// A keyframe is this many times a delta frame.
    idr_factor: u32,
    frames: u64,
    /// FR-70 P1 — a REBUILD-BOUND encoder (QSV: every rate move is a new
    /// encoder, FR-62 A0 measured the in-place path dead): a target change
    /// emits a keyframe. Off = the perfect CBR encoder B0 shipped with.
    rebuild_idr: bool,
    last_target_bps: u32,
    /// Keyframes emitted after the opening one (the rebuild IDRs).
    rebuild_idrs: u32,
}

impl EncoderSim {
    fn new(fps: u32, idr_factor: u32) -> Self {
        Self {
            fps: fps.max(1),
            idr_factor: idr_factor.max(1),
            frames: 0,
            rebuild_idr: false,
            last_target_bps: 0,
            rebuild_idrs: 0,
        }
    }

    fn frame_interval(&self) -> Duration {
        Duration::from_micros(1_000_000 / u64::from(self.fps))
    }

    /// Bytes for the next frame at `target_bps`.
    fn produce(&mut self, target_bps: u32, motion: &Motion, t: Duration) -> u32 {
        let cbr = u64::from(target_bps) / u64::from(self.fps) / 8;
        let scaled = cbr * u64::from(motion.factor_at(t));
        let rebuilt = self.rebuild_idr && self.frames > 0 && target_bps != self.last_target_bps;
        let bytes = if self.frames == 0 {
            // The opening keyframe.
            cbr * u64::from(self.idr_factor)
        } else if rebuilt {
            // FR-70 P1 — the rebuild's keyframe, sized like the opener's.
            self.rebuild_idrs += 1;
            cbr * u64::from(self.idr_factor)
        } else {
            scaled
        };
        self.last_target_bps = target_bps;
        self.frames += 1;
        bytes.max(1).min(u64::from(u32::MAX)) as u32
    }
}

// ---------------------------------------------------------------------------
// The viewer
// ---------------------------------------------------------------------------

/// One `decodestat`-shaped window, the shape `tick_viewer_window` folds.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowStats {
    pub rx_bps: u32,
    pub age_ms: u32,
    pub age_p95_ms: u32,
    /// Σ(Δarrival − Δproduced) over the window — the browser's `QueueDrift`.
    /// Positive means the transit queue grew.
    pub queue_ms: i64,
    pub frames_rx: u32,
    pub frames_lost: u32,
    /// FR-71 — the M0 age split as the sim's viewer would report it:
    /// window-average sender share (`sent − produced`) and transit share
    /// (`at − sent`); the sim's viewer decodes instantly, so its share is 0.
    pub sender_ms: u32,
    /// The window's worst sender share — the pump's `send_wait_max`.
    pub sender_max_ms: u32,
    pub transit_ms: u32,
    /// The window's smallest paint age — the FR-15 age loop's floor sample.
    pub age_min_ms: u32,
    /// Sender-side facts the harness fills in AFTER the fold (the viewer
    /// cannot know them): bytes queued in the send channel at the window's
    /// close, frames the pump handed to the channel this window, and the
    /// path's physical one-way minimum (half the scenario's round trip —
    /// what the real loop gets from the viewer's clock probe).
    pub inflight_bytes: usize,
    pub frames_sent: u32,
    pub one_way_ms: u16,
}

/// Folds arrivals into windows.
#[derive(Debug, Default)]
struct ViewerSim {
    ages_ms: Vec<u32>,
    bytes: u64,
    last_arrival: Option<Arrival>,
    queue_drift_ms: i64,
    frames_rx: u32,
    frames_lost: u32,
    sender_ms_sum: u64,
    sender_max_ms: u32,
    transit_ms_sum: u64,
}

impl ViewerSim {
    fn on_arrival(&mut self, a: Arrival) {
        let age = a.at.saturating_sub(a.produced).as_millis() as u32;
        self.ages_ms.push(age);
        self.bytes += u64::from(a.bytes);
        self.frames_rx += 1;
        let sender_ms = a.sent.saturating_sub(a.produced).as_millis() as u32;
        self.sender_ms_sum += u64::from(sender_ms);
        self.sender_max_ms = self.sender_max_ms.max(sender_ms);
        self.transit_ms_sum += a.at.saturating_sub(a.sent).as_millis() as u64;
        if let Some(prev) = self.last_arrival {
            let d_arrival = a.at.saturating_sub(prev.at).as_millis() as i64;
            let d_produced = a.produced.saturating_sub(prev.produced).as_millis() as i64;
            self.queue_drift_ms += d_arrival - d_produced;
        }
        self.last_arrival = Some(a);
    }

    fn on_loss(&mut self) {
        self.frames_lost += 1;
    }

    /// Close the window and reset. `elapsed` is its real length.
    fn fold(&mut self, elapsed: Duration) -> WindowStats {
        self.ages_ms.sort_unstable();
        let n = self.ages_ms.len();
        let age_ms = if n == 0 {
            0
        } else {
            (self.ages_ms.iter().map(|v| u64::from(*v)).sum::<u64>() / n as u64) as u32
        };
        let age_p95_ms = if n == 0 {
            0
        } else {
            // Index of the p95 sample, clamped into range.
            self.ages_ms[((n * 95) / 100).min(n - 1)]
        };
        let ms = elapsed.as_millis().max(1) as u64;
        let stats = WindowStats {
            rx_bps: (self.bytes.saturating_mul(8000) / ms).min(u64::from(u32::MAX)) as u32,
            age_ms,
            age_p95_ms,
            queue_ms: self.queue_drift_ms,
            frames_rx: self.frames_rx,
            frames_lost: self.frames_lost,
            sender_ms: if n == 0 {
                0
            } else {
                (self.sender_ms_sum / n as u64) as u32
            },
            sender_max_ms: self.sender_max_ms,
            transit_ms: if n == 0 {
                0
            } else {
                (self.transit_ms_sum / n as u64) as u32
            },
            age_min_ms: if n == 0 { 0 } else { self.ages_ms[0] },
            inflight_bytes: 0,
            frames_sent: 0,
            one_way_ms: 0,
        };
        self.ages_ms.clear();
        self.bytes = 0;
        self.queue_drift_ms = 0;
        self.frames_rx = 0;
        self.frames_lost = 0;
        self.sender_ms_sum = 0;
        self.sender_max_ms = 0;
        self.transit_ms_sum = 0;
        stats
    }
}

// ---------------------------------------------------------------------------
// The law under test
// ---------------------------------------------------------------------------

/// Anything that decides a target bitrate, driven at the two positions the
/// governor drives one: every frame at the capacity gate, and once per viewer
/// window.
///
/// B1's `ratectl::Controller` implements this and runs the same fixtures, so
/// the numbers below become the baseline it has to beat rather than a
/// separate exercise.
pub trait RateLaw {
    fn label(&self) -> &'static str;
    /// At the capacity gate, before encoding. Returns the current target.
    fn on_frame(&mut self, occupied: u32, full: bool, now: Instant) -> u32;
    /// Once per viewer window, after folding.
    fn on_window(&mut self, w: &WindowStats, now: Instant);
    fn target_bps(&self) -> u32;
    /// FR-70 P1 — the FR-59 P2 byte budget this law would hand the pump's
    /// gate (`constrained_queue_budget_bytes` of the reference rate). Only
    /// consulted when the harness runs with [`SimOptions::budget_gate`];
    /// the default is "no budget", so every law that predates it is unchanged.
    fn queue_budget_bytes(&self) -> usize {
        usize::MAX
    }
    /// FR-70 P1 — what the law would hand the rate memory at session end
    /// (`RateGovernor::remembered_candidate_bps`), when it models one.
    fn remembered_candidate_bps(&self) -> Option<u32> {
        None
    }
    /// FR-71 T1a — how the law classified the window it just consumed, when
    /// it runs the shadow classifier (`RateGovernor::pipe_state`). Laws that
    /// predate it answer `None`, which the trace records as "not classified".
    fn pipe_state(&self) -> Option<super::pipe_state::PipeState> {
        None
    }
    /// FR-79 — windows the validity gate rejected (`RateGovernor::evidence_rejected`).
    fn rejected_windows(&self) -> u32 {
        0
    }
    /// FR-70 P1 — the pump skipped a frame at the FR-59 P2 byte-budget gate
    /// (`on_backpressure_skip`): a congestion sample for the AIMD, but NOT a
    /// blocked send — nothing was handed to the transport, so the goodput
    /// estimator sees nothing and the pipe is not measured. Conflating the
    /// two is exactly the sim error that made the first run of this cell
    /// "measure" a 20 Mbps pipe from a gate skip and escape the pin in 30 s.
    fn on_budget_skip(&mut self, now: Instant) {
        let _ = now;
    }
}

/// FR-70 P1 — how the law learns the pipe's rate from a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeasureRule {
    /// B0 as shipped: every window that delivered anything is a measurement
    /// (`measured = rx_bps`). ⚠️ More optimistic than the shipped governor,
    /// which measures only on PUSH-BACK — blocked sends (goodput) or the
    /// viewer's queue growing (the FR-59 P3 link loop). A law under this
    /// rule can never be pinned by a stale prior, because every clean window
    /// overwrites the prior with the truth; the field session of 2026-09-04
    /// ran under the shipped rule and was pinned for four minutes. Kept as
    /// the default so B0's recorded numbers stand; FR-63 should re-run its
    /// fixtures under [`MeasureRule::OnPushBack`] before relying on them.
    #[default]
    EveryWindow,
    /// The shipped governor's rule: the window's delivered rate counts only
    /// when the channel was FULL at some point (a blocked send) or the
    /// viewer reported its queue growing two windows running; released once
    /// the queue stops growing. With nothing measured, the FR-59 P8
    /// remembered rate stands in — decaying per [`super::prior`] when the
    /// law's `prior_decay` is on.
    OnPushBack,
}

/// FR-70 P1 — harness options that predate nothing: every default is B0 as
/// shipped, so a fixture that does not opt in runs byte-for-byte as before.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimOptions {
    /// The pump's FR-59 P2 byte-budget gate: a frame is skipped (and the
    /// law told the channel is full) while the bytes in flight exceed the
    /// law's `queue_budget_bytes()`.
    pub budget_gate: bool,
    /// A rebuild-bound encoder — every target change emits a keyframe.
    pub rebuild_idr: bool,
}

/// What a congested window does to the opener's ramp.
///
/// ⚠️ Only [`RampExit::EndsOnCongestion`] is SHIPPED — it is
/// `SlowStart::on_congestion`, driven here through the real type. The other two
/// are **models of candidate rules, deliberately not implemented in the
/// product**: B0 exists so a candidate can be measured before anybody argues
/// for it, and a candidate that lives only in the simulator costs nothing if
/// the numbers say no.
///
/// The question they answer was raised BY B0: on a pipe thinner than
/// `slow_start::OPEN_BPS` the opening window congests, the shipped rule ends
/// the ramp permanently, and the flat `area_min_bitrate_bps` floor immediately
/// re-pins the opener — so the ramp protects roughly one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RampExit {
    /// SHIPPED. Congestion ends the ramp; the AIMD and the flat floor take over.
    #[default]
    EndsOnCongestion,
    /// CANDIDATE (modelled). Congestion halves the ramp's target and the ramp
    /// keeps controlling, so the opener keeps descending toward the pipe
    /// instead of handing back to a constant.
    HalveAndContinue,
    /// CANDIDATE (modelled). The shipped ramp, but the FLOOR stays at the
    /// ramp's last target until a measurement exists.
    ///
    /// 🔑 This targets the actual mechanism rather than the ramp: the harm is
    /// not that the ramp stopped, it is that a flat constant re-pinned the
    /// session while there was still no evidence. FR-59 P1 already descends the
    /// floor toward a MEASURED pipe; the gap is that with nothing arriving
    /// there is no measurement, which is exactly when the constant is most
    /// wrong.
    HoldFloorUntilMeasured,
}

/// The shipped governor's rate path: the FR-59 floor relief, the FR-63
/// slow-start ramp and the AIMD, in the order `pre_encode_tick` runs them.
///
/// Arm A of the FR-63 A/B is this with `slow_start: false`; arm B is
/// `slow_start: true`. Nothing else differs, which is the property the field
/// cell could not guarantee.
#[derive(Debug)]
pub struct GovernorLaw {
    slow_start: bool,
    exit: RampExit,
    /// `HalveAndContinue`'s own target, since `SlowStart` cannot be told to
    /// halve — it only ends.
    cand_bps: Option<u32>,
    cand_done: bool,
    /// The ramp's target at the moment it ended, for `HoldFloorUntilMeasured`.
    ramp_last_bps: Option<u32>,
    floor_relief: bool,
    nominal_floor_bps: u32,
    nominal_ceiling_bps: u32,
    /// FR-59 P8's remembered-slow-pair open; `None` = no memory for this pair.
    seed_bps: Option<u32>,
    depth: u32,
    aimd: Option<AimdController>,
    ramp: Option<SlowStart>,
    ramp_congested: bool,
    measured_bps: Option<u32>,
    target: u32,
    /// The ramp's target AT ARMING. Recorded separately because the ramp
    /// doubles every clean window, so reading `SlowStart::target_bps()` after
    /// a run answers "where is the ramp now", not "where did it open" — the
    /// value the field log prints as `open_bps=`.
    ramp_open_bps: Option<u32>,
    /// FR-70 P1 — see [`MeasureRule`].
    measure: MeasureRule,
    /// FR-70 P1 — the remembered rate as a decaying prior (`super::prior`).
    prior: super::prior::RatePrior,
    prior_decay: bool,
    /// Did the channel report FULL at any frame since the last window?
    full_seen: bool,
    /// …and in the window before that (a saturated pipe, not a burst).
    full_seen_prev: bool,
    /// Consecutive windows with a growing viewer queue (the link loop's
    /// onset streak, `viewer_rate::QUEUE_OVER_WINDOWS`).
    growth_streak: u8,
    /// The scenario's frame rate, for the steady-window test above.
    fps: u32,
    /// The smallest window-average paint age seen — the FR-15 age loop's
    /// learned floor, for the prior's push-back verdict.
    age_floor_ms: u32,
    /// FR-71 T1a — the shadow classifier, fed exactly what the shipped
    /// governor feeds it (`RateGovernor::tick_viewer_window`).
    pipe: super::pipe_state::PipeClassifier,
    /// Budget-gate skips since the last window (the pump's `win_skips`).
    gate_skips_window: u32,
    /// FR-71 T1c — the FR-15 age loop, the REAL one, for the cut this law
    /// did not model before (`age_cut`; opt-in per cell, because the FR-63
    /// and FR-70 conclusions were taken without it).
    age_loop: super::viewer_rate::AgeLoop,
    age_cut: bool,
    /// FR-79 - run the validity gate (the shipped law). `false` is the
    /// pre-FR-79 control arm, kept so a cell can show the difference.
    stall_gate: bool,
    /// Windows the gate rejected.
    holds: u32,
    /// FR-79 - the previous window's verdict, the gate's shadow input.
    prev_state: Option<PipeState>,
}

impl GovernorLaw {
    pub fn new(nominal_floor_bps: u32, nominal_ceiling_bps: u32, slow_start: bool) -> Self {
        Self {
            slow_start,
            floor_relief: true,
            nominal_floor_bps,
            nominal_ceiling_bps,
            seed_bps: None,
            measure: MeasureRule::default(),
            prior: super::prior::RatePrior::new(None, nominal_floor_bps, false),
            prior_decay: false,
            full_seen: false,
            full_seen_prev: false,
            growth_streak: 0,
            fps: 30,
            age_floor_ms: u32::MAX,
            pipe: super::pipe_state::PipeClassifier::new(),
            gate_skips_window: 0,
            age_loop: super::viewer_rate::AgeLoop::new(),
            age_cut: false,
            stall_gate: true,
            prev_state: None,
            holds: 0,
            depth: CONSTRAINED_DEPTH,
            aimd: None,
            ramp: None,
            ramp_congested: false,
            measured_bps: None,
            target: nominal_ceiling_bps,
            ramp_open_bps: None,
            exit: RampExit::EndsOnCongestion,
            cand_bps: None,
            cand_done: false,
            ramp_last_bps: None,
        }
    }

    /// Swap in a CANDIDATE exit rule. Default is the shipped one, so every
    /// other fixture is unaffected.
    pub fn with_exit(mut self, exit: RampExit) -> Self {
        self.exit = exit;
        self
    }

    /// FR-59 P8 — this pair was remembered at `bps`.
    pub fn with_seed(mut self, bps: u32) -> Self {
        self.seed_bps = Some(bps);
        self.prior = super::prior::RatePrior::new(
            Some(bps).filter(|s| *s < self.nominal_floor_bps),
            self.nominal_floor_bps,
            self.prior_decay,
        );
        self
    }

    /// FR-70 P1 — how the law measures the pipe (see [`MeasureRule`]).
    pub fn with_measure(mut self, rule: MeasureRule) -> Self {
        self.measure = rule;
        self
    }

    /// FR-71 T1c — model the FR-15 age loop's CUT (`governor.rs`: two
    /// elevated windows ⇒ `note_buffer_overflow`), with the real `AgeLoop`.
    pub fn with_age_cut(mut self, on: bool) -> Self {
        self.age_cut = on;
        self
    }

    /// FR-79 - the validity gate: a window that is not evidence about the pipe
    /// moves nothing (no ramp step, no age cut, no measurement, no prior
    /// push-back). ON is the shipped law; OFF is the pre-FR-79 control arm,
    /// which is not a configuration the daemon has.
    pub fn with_stall_gate(mut self, on: bool) -> Self {
        self.stall_gate = on;
        self
    }
    /// FR-70 P1 — the scenario's frame rate (the steady-window test in
    /// [`MeasureRule::OnPushBack`] needs it).
    pub fn with_fps(mut self, fps: u32) -> Self {
        self.fps = fps.max(1);
        self
    }

    /// FR-70 P1 — the remembered rate decays while nothing measures
    /// (`rate_prior_decay`). Meaningful under [`MeasureRule::OnPushBack`]
    /// only; under `EveryWindow` a prior never survives the first window.
    pub fn with_prior_decay(mut self, on: bool) -> Self {
        self.prior_decay = on;
        self.prior = super::prior::RatePrior::new(
            self.seed_bps.filter(|s| *s < self.nominal_floor_bps),
            self.nominal_floor_bps,
            on,
        );
        self
    }

    /// FR-70 P1 — what the floor relief and the queue budget read: a live
    /// measurement, else (under the shipped rule) the prior's stand-in.
    fn pipe_bps(&self) -> Option<u32> {
        match self.measure {
            MeasureRule::EveryWindow => self.measured_bps,
            MeasureRule::OnPushBack => self.measured_bps.or(self.prior.stand_in_bps()),
        }
    }

    /// FR-59 P1's floor relief, on by default in production.
    pub fn with_floor_relief(mut self, on: bool) -> Self {
        self.floor_relief = on;
        self
    }

    /// The ramp's opening target, once armed — what the field log prints as
    /// `FR-63 slow-start armed open_bps=…`.
    pub fn ramp_open_bps(&self) -> Option<u32> {
        self.ramp_open_bps
    }
}

impl RateLaw for GovernorLaw {
    fn label(&self) -> &'static str {
        if self.slow_start {
            "arm B (rate_slow_start=true)"
        } else {
            "arm A (rate_slow_start=false)"
        }
    }

    fn on_frame(&mut self, occupied: u32, full: bool, now: Instant) -> u32 {
        let mut ceiling = self.nominal_ceiling_bps;

        // FR-63 — arm the ramp from THIS tick's resolved ceiling, seeded with
        // the remembered rate and NOT with the nominal floor (governor.rs
        // documents why: the flat floor is a fleet constant, and passing it
        // opened at 1.5 M — no ramp at all).
        if self.slow_start {
            let seed = self.seed_bps.unwrap_or(0);
            let armed = &mut self.ramp_open_bps;
            let ramp = self.ramp.get_or_insert_with(|| {
                let r = SlowStart::new(seed, ceiling);
                *armed = Some(r.target_bps());
                r
            });
            if self.exit == RampExit::HalveAndContinue {
                // The candidate opens exactly where the shipped ramp does; only
                // its response to congestion differs.
                let cand = *self.cand_bps.get_or_insert(ramp.target_bps());
                if !self.cand_done {
                    ceiling = ceiling.min(cand).max(1);
                }
            } else if !ramp.done() {
                ceiling = ceiling.min(ramp.target_bps()).max(1);
            }
        }

        // FR-59 P1 — the legibility floor descends toward a measured pipe
        // (FR-70 P1: or toward the remembered rate standing in for one).
        let mut floor = match self.pipe_bps() {
            Some(g) if self.floor_relief => {
                super::goodput::measured_floor_bps(g, self.nominal_floor_bps, HARD_MIN_BPS)
            }
            _ => self.nominal_floor_bps,
        };
        // FR-63 — and the floor descends WITH the ramp, or `set_ceiling`
        // raises the capped ceiling straight back to it. This coupling is
        // what made 0.4.55 ship the ramp inert.
        match self.exit {
            RampExit::HalveAndContinue => {
                if let Some(cand) = self.cand_bps
                    && !self.cand_done
                {
                    floor = floor.min(cand.max(HARD_MIN_BPS));
                }
            }
            RampExit::HoldFloorUntilMeasured => {
                // While the ramp runs, exactly as shipped. Once it has ended,
                // KEEP the floor at its last target until evidence arrives —
                // the shipped rule hands straight back to the flat constant.
                let held = match self.ramp.as_ref() {
                    Some(r) if !r.done() => Some(r.target_bps()),
                    _ if self.measured_bps.is_none() => self.ramp_last_bps,
                    _ => None,
                };
                if let Some(h) = held {
                    floor = floor.min(h.max(HARD_MIN_BPS));
                }
            }
            RampExit::EndsOnCongestion => {
                if let Some(ramp) = self.ramp.as_ref()
                    && !ramp.done()
                {
                    floor = floor.min(ramp.target_bps().max(HARD_MIN_BPS));
                }
            }
        }

        let depth = self.depth;
        let seed = self.seed_bps;
        let ctrl = self.aimd.get_or_insert_with(|| {
            let initial = seed.map_or(ceiling, |s| s.min(ceiling));
            AimdController::new(initial, floor, ceiling, depth, now)
        });
        ctrl.set_floor(floor);
        ctrl.set_ceiling(ceiling);
        ctrl.observe(occupied, full, now);
        if full {
            self.ramp_congested = true;
            self.full_seen = true;
        }
        self.target = ctrl.desired();
        self.target
    }

    fn pipe_state(&self) -> Option<super::pipe_state::PipeState> {
        self.pipe.last()
    }

    fn rejected_windows(&self) -> u32 {
        self.holds
    }

    fn on_budget_skip(&mut self, now: Instant) {
        // `RateGovernor::on_backpressure_skip`: the ramp's congestion bit and a
        // full-occupancy sample for the AIMD (the multiplicative decrease runs
        // DURING congestion). Deliberately not `full_seen`: no send blocked.
        self.ramp_congested = true;
        self.gate_skips_window += 1;
        if let Some(ctrl) = self.aimd.as_mut() {
            ctrl.observe(self.depth, true, now);
            self.target = ctrl.desired();
        }
    }

    fn queue_budget_bytes(&self) -> usize {
        // `rate_profile::constrained_queue_reference_bps` +
        // `constrained_queue_budget_bytes`, with the constants explicit
        // (450 ms, 16 KiB minimum) so the result cannot depend on the
        // environment.
        let reference = match self.pipe_bps() {
            Some(g) if g > 0 => self.nominal_ceiling_bps.min(g),
            _ => self.nominal_ceiling_bps,
        };
        ((u64::from(reference) * 450 / 8000) as usize).max(16 * 1024)
    }

    fn remembered_candidate_bps(&self) -> Option<u32> {
        if !self.prior_decay {
            return None;
        }
        self.measured_bps.or(self.prior.stand_in_bps())
    }

    fn on_window(&mut self, w: &WindowStats, now: Instant) {
        // One verdict per window, taking the flag first — governor.rs:833.
        let congested = std::mem::take(&mut self.ramp_congested);
        let full_seen = std::mem::take(&mut self.full_seen);
        // FR-71 — classify the window BEFORE anything acts on it, from the
        // same signals the shipped governor holds: the M0 split (the sim's
        // viewer decodes instantly, so its share is 0), the send channel's
        // occupancy against the budget, the gate's skips and the window's
        // worst send wait. FR-79 then decides whether the window was evidence
        // about the pipe at all — a rejected one moves nothing: no ramp step,
        // no age cut, no measurement, no prior push-back.
        let split = (w.frames_rx > 0).then(|| super::pipe_state::SplitMs {
            sender_ms: Some(f64::from(w.sender_ms)),
            transit_ms: w.transit_ms.min(u32::from(u16::MAX)) as u16,
            viewer_ms: 0,
        });
        let state = self.pipe.classify(&super::pipe_state::WindowSignals {
            split,
            reported: w.frames_rx > 0,
            inflight_bytes: w.inflight_bytes,
            budget_bytes: self.queue_budget_bytes(),
            gate_skips: std::mem::take(&mut self.gate_skips_window),
            blocked_sends: u32::from(full_seen),
            send_wait_max_ms: f64::from(w.sender_max_ms),
            frames_sent: w.frames_sent,
            struggling: false,
        });
        let rejected = super::evidence::rejected(super::evidence::WindowFacts {
            state,
            prev_state: self.prev_state.replace(state),
            // The sim has no pump passes and one carrier per scenario.
            agent_stalled: false,
            carrier_changed: false,
        });
        let hold = self.stall_gate && rejected.is_some();
        if hold {
            self.holds += 1;
        }
        if !hold
            && let Some(ramp) = self.ramp.as_mut()
            && !ramp.done()
        {
            // Remember where the ramp was BEFORE this verdict, so
            // `HoldFloorUntilMeasured` can hold the last live target rather
            // than whatever the ramp reports after it has ended.
            self.ramp_last_bps = Some(ramp.target_bps());
            if congested {
                ramp.on_congestion();
            } else {
                ramp.on_clean_window();
            }
        }
        // The candidate ramp, modelled: halve on congestion and keep going,
        // double on a clean window exactly as the shipped ramp does. It stops
        // only at the ceiling — congestion never ends it.
        if !hold
            && self.exit == RampExit::HalveAndContinue
            && let Some(cand) = self.cand_bps
            && !self.cand_done
        {
            let next = if congested {
                (cand / 2).max(HARD_MIN_BPS)
            } else {
                cand.saturating_mul(2).min(self.nominal_ceiling_bps)
            };
            self.cand_bps = Some(next);
            if next >= self.nominal_ceiling_bps {
                self.cand_done = true;
            }
        }
        // The window's delivered rate is the evidence the floor relief uses.
        // A window that delivered nothing is a stall, and a stall is NOT
        // evidence about the pipe's rate — the FR-63 design's `fps == 0`
        // rule, which the shipped governor does not yet have.
        match self.measure {
            MeasureRule::EveryWindow => {
                if w.frames_rx > 0 {
                    self.measured_bps = Some(w.rx_bps);
                }
            }
            MeasureRule::OnPushBack => {
                // The link loop's onset: two windows of a growing queue.
                self.growth_streak = if w.queue_ms >= i64::from(super::viewer_rate::QUEUE_GROWTH_MS)
                {
                    self.growth_streak.saturating_add(1)
                } else {
                    0
                };
                let congested = self.growth_streak >= 2;
                // A blocked sender measures the DRAIN rate (goodput is
                // Σbytes/Σblocked-time over blocked sends). The window's
                // arrival rate stands for it only when the channel was full
                // two windows running — a SATURATED pipe, whose arrival rate
                // over a whole window is its drain rate. A one-off full
                // window (the opener's keyframe draining) is a catch-up
                // burst that reads several times the pipe, which the real
                // estimator's byte-weighting over blocked time would not.
                let saturated = full_seen && self.full_seen_prev;
                self.full_seen_prev = full_seen;
                if (saturated || congested) && w.frames_rx > 0 && !hold {
                    // A blocked sender (goodput) or a growing viewer queue
                    // (link loop): the delivered rate IS the pipe's.
                    self.measured_bps = Some(w.rx_bps);
                } else if !congested && w.queue_ms <= 0 && !full_seen {
                    // Released: the queue is no longer growing and has
                    // drained (the governor's release rule, simplified).
                    self.measured_bps = None;
                }
                let live = self.measured_bps;
                // The age LEVEL against the session's learned floor — the
                // FR-15 `AgeLoop` in one line: the smallest window average
                // seen is the floor, and `AGE_SLACK_MS` over it is elevated.
                if w.frames_rx > 0 && w.age_ms > 0 {
                    self.age_floor_ms = self.age_floor_ms.min(w.age_ms);
                }
                let age_elevated = w.frames_rx > 0
                    && self.age_floor_ms < u32::MAX
                    && w.age_ms >= self.age_floor_ms + u32::from(super::viewer_rate::AGE_SLACK_MS);
                let pushed_back = full_seen || congested || age_elevated;
                if !hold {
                    self.prior.on_window(live, pushed_back);
                }
            }
        }
        // FR-71 T1c — the FR-15 age loop's CUT, with the real loop:
        // `governor.rs` fires `note_buffer_overflow` when the loop has seen
        // two elevated windows in a row. Under the hold the loop still
        // learns and its streak is reset, exactly as the governor does.
        if self.age_cut && w.frames_rx > 0 {
            let avg = w.age_ms.min(u32::from(u16::MAX)) as u16;
            let min = w.age_min_ms.min(u32::from(u16::MAX)) as u16;
            let triggered = self.age_loop.observe(avg, min, w.one_way_ms.max(1));
            if hold {
                self.age_loop.reset_streak();
            } else if triggered && let Some(ctrl) = self.aimd.as_mut() {
                ctrl.note_buffer_overflow(now);
                self.target = ctrl.desired();
            }
        }
    }

    fn target_bps(&self) -> u32 {
        self.target
    }
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// A complete cell: a link, content, and the session's nominal bounds.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: &'static str,
    pub pipe: PipeSpec,
    pub motion: Motion,
    pub fps: u32,
    pub duration: Duration,
    pub seed: u64,
    /// How many times a delta frame the opening keyframe is.
    ///
    /// ⚠️ **Sensitive, and uncapped on purpose.** The plan's figure is 25×,
    /// which at a 2.55 Mbps opener is a 265 KB keyframe — ten seconds of a
    /// 213 kbps pipe, and it dominates the first windows of any thin-pipe
    /// run. A real CBR encoder can bound this (`max_frame_size`, runtime-
    /// updatable in qsvenc — FR-31's lever), so a fixture that only holds at
    /// 25× would be a statement about our keyframe budget rather than about
    /// the rate law. Every conclusion drawn from these fixtures is therefore
    /// re-run at a small factor too; see `ac0b_conclusion_survives_a_small_keyframe`.
    pub idr_factor: u32,
}

/// One window of the run.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub t: Duration,
    /// The target at the window's close.
    pub target_bps: u32,
    /// The HIGHEST target committed to at any point inside the window.
    ///
    /// ⚠️ Not the same as `target_bps`, and the difference is the whole
    /// opener question: a session that opens at 2.55 Mbps and is cut to
    /// 1.2 Mbps by the first decrease shows `target_bps` 1.2 M for window 0
    /// while having actually committed to 2.55 M. Sampling only at the close
    /// hides exactly the commitment FR-63's B-opener exists to remove.
    pub peak_target_bps: u32,
    pub pipe_bps: u32,
    pub stats: WindowStats,
    pub skips: u32,
    /// FR-71 T1a — the law's shadow classification of this window (`None`
    /// for laws without the classifier).
    pub state: Option<super::pipe_state::PipeState>,
}

/// The result of a run, plus the assertions the plan names.
#[derive(Debug)]
pub struct Trace {
    pub law: &'static str,
    pub scenario: &'static str,
    pub rows: Vec<Row>,
    /// FR-70 P1 — frames the byte-budget gate skipped (0 unless modelled).
    pub gate_skips: u32,
    /// FR-70 P1 — keyframes a rebuild-bound encoder emitted for rate moves
    /// (0 unless modelled).
    pub rebuild_idrs: u32,
    /// FR-71 T1b — windows the law held (0 for laws without the hold).
    pub holds: u32,
    /// FR-70 P1 — what the law would hand the rate memory at the end.
    pub remembered_bps: Option<u32>,
}

impl Trace {
    /// Σ over windows of the bits committed above `margin`× the pipe's real
    /// rate. The plan's over-drive integral: the total volume of bits the law
    /// promised that the link was never going to carry.
    ///
    /// Uses each window's PEAK target, so it is an upper bound on the
    /// commitment rather than a window-close snapshot. Both arms are measured
    /// the same way, so the comparison is fair; the absolute number should be
    /// read as "bits promised", not "bits queued".
    pub fn overdrive_bits(&self, margin_pct: u32) -> u64 {
        self.rows
            .iter()
            .map(|r| {
                let allowed = u64::from(r.pipe_bps) * u64::from(margin_pct) / 100;
                u64::from(r.peak_target_bps).saturating_sub(allowed)
            })
            .sum()
    }

    /// The first window index from which the target stays within `pct` of the
    /// pipe for the rest of the run — the settling time.
    pub fn settled_window(&self, pct: u32) -> Option<usize> {
        (0..self.rows.len()).find(|&i| {
            self.rows[i..].iter().all(|r| {
                let hi = u64::from(r.pipe_bps) * u64::from(100 + pct) / 100;
                u64::from(r.target_bps) <= hi.max(1)
            })
        })
    }

    pub fn max_age_ms(&self) -> u32 {
        self.rows
            .iter()
            .map(|r| r.stats.age_p95_ms)
            .max()
            .unwrap_or(0)
    }

    pub fn peak_queue_ms(&self) -> i64 {
        self.rows
            .iter()
            .map(|r| r.stats.queue_ms)
            .max()
            .unwrap_or(0)
    }

    pub fn total_skips(&self) -> u32 {
        self.rows.iter().map(|r| r.skips).sum()
    }

    /// The highest target the law ever committed to, at any instant.
    pub fn peak_target_bps(&self) -> u32 {
        self.rows
            .iter()
            .map(|r| r.peak_target_bps)
            .max()
            .unwrap_or(0)
    }

    /// Windows whose p95 age exceeded `ms` — "how long was it bad for".
    pub fn windows_above_age(&self, ms: u32) -> usize {
        self.rows.iter().filter(|r| r.stats.age_p95_ms > ms).count()
    }

    /// A compact table, printed by a failing assertion so the reason is in
    /// the test output rather than behind a re-run.
    pub fn render(&self) -> String {
        let mut s = format!(
            "\n{} — {}\n  t  target_bps   peak_bps  pipe_bps   rx_bps  age  p95  queue  rx  lost  skips  snd/tr  inflight  state\n",
            self.scenario, self.law
        );
        for r in &self.rows {
            s.push_str(&format!(
                "{:>3}  {:>10}  {:>9}  {:>8}  {:>7}  {:>3}  {:>3}  {:>5}  {:>2}  {:>4}  {:>5}  {:>3}/{:<4} {:>8}  {}\n",
                r.t.as_secs(),
                r.target_bps,
                r.peak_target_bps,
                r.pipe_bps,
                r.stats.rx_bps,
                r.stats.age_ms,
                r.stats.age_p95_ms,
                r.stats.queue_ms,
                r.stats.frames_rx,
                r.stats.frames_lost,
                r.skips,
                r.stats.sender_ms,
                r.stats.transit_ms,
                r.stats.inflight_bytes,
                r.state.map_or("-", PipeState::as_str),
            ));
        }
        s
    }
}

/// Run one scenario against one law.
pub fn run(scenario: &Scenario, law: &mut dyn RateLaw) -> Trace {
    run_opts(scenario, law, SimOptions::default())
}

/// [`run`] with the FR-70 P1 harness options (see [`SimOptions`]).
pub fn run_opts(scenario: &Scenario, law: &mut dyn RateLaw, opts: SimOptions) -> Trace {
    let start = Instant::now();
    let mut pipe = Pipe::new(scenario.pipe.clone(), CONSTRAINED_DEPTH, scenario.seed);
    let mut enc = EncoderSim::new(scenario.fps, scenario.idr_factor);
    enc.rebuild_idr = opts.rebuild_idr;
    let mut viewer = ViewerSim::default();
    let mut rows = Vec::new();
    let mut gate_skips_total = 0u32;

    let frame_interval = enc.frame_interval();
    let mut next_frame = Duration::ZERO;
    let mut next_window = WINDOW;
    let mut skips_this_window = 0u32;
    let mut frames_sent_this_window = 0u32;
    let mut peak_target = 0u32;
    let mut t = Duration::ZERO;

    while t <= scenario.duration {
        // The capacity gate: the pump asks the law for a target every frame,
        // including the frames it goes on to skip — that is the FR-35 fix
        // ("the decrease runs DURING congestion").
        if t >= next_frame {
            let occupied = pipe.occupied();
            // FR-70 P1 — the FR-59 P2 byte-budget gate, when modelled: the
            // pump reads it as "the channel is full" and skips production,
            // exactly as `on_backpressure_skip` does.
            let over_budget = opts.budget_gate && pipe.inflight_bytes() >= law.queue_budget_bytes();
            let full = pipe.full();
            let mut target = law.on_frame(occupied, full, start + t);
            if over_budget && !full {
                // The gate, as the pump runs it: a congestion sample and a
                // skipped frame — NOT a blocked send (see `on_budget_skip`).
                gate_skips_total += 1;
                law.on_budget_skip(start + t);
                target = law.target_bps();
            }
            peak_target = peak_target.max(target);
            if full || over_budget {
                skips_this_window += 1;
            } else {
                let bytes = enc.produce(target, &scenario.motion, t);
                if pipe.offer(bytes, t) {
                    frames_sent_this_window += 1;
                } else {
                    skips_this_window += 1;
                }
            }
            next_frame += frame_interval;
        }

        let (arrived, lost) = pipe.advance(t);
        for a in arrived {
            viewer.on_arrival(a);
        }
        for _ in 0..lost {
            viewer.on_loss();
        }

        if t >= next_window {
            let mut stats = viewer.fold(WINDOW);
            // The sender-side half of the window, which the viewer's fold
            // cannot know (FR-71): what is still queued, and what was sent.
            stats.inflight_bytes = pipe.inflight_bytes();
            stats.frames_sent = frames_sent_this_window;
            stats.one_way_ms = (scenario.pipe.rtt / 2).as_millis().clamp(1, 65_535) as u16;
            law.on_window(&stats, start + t);
            rows.push(Row {
                t,
                target_bps: law.target_bps(),
                peak_target_bps: peak_target.max(law.target_bps()),
                pipe_bps: scenario.pipe.rate_at(t),
                stats,
                skips: skips_this_window,
                state: law.pipe_state(),
            });
            skips_this_window = 0;
            frames_sent_this_window = 0;
            peak_target = 0;
            next_window += WINDOW;
        }

        t += TICK;
    }

    Trace {
        law: law.label(),
        scenario: scenario.name,
        rows,
        gate_skips: gate_skips_total,
        rebuild_idrs: enc.rebuild_idrs,
        holds: law.rejected_windows(),
        remembered_bps: law.remembered_candidate_bps(),
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The four scenarios the plan names, plus the FR-63 AC0b cell.
///
/// Each is calibrated from a RECORDED field trace, not invented: the numbers
/// in the doc comments are the ones in `agent_logs` / the FR issue threads.
pub mod fixtures {
    use super::*;

    /// **AC0b — CORPLAP-1 over a corporate VPN, 2026-09-02.**
    ///
    /// The cell the field could not reproduce on demand. Recorded: the session
    /// opened at the nominal relay cap `2_550_000` into a path measured at
    /// ~`213_180`, producing 444 ms of queue and a **1550 ms** paint, then six
    /// windows collapsing 921k → 783k → 566k → 347k → 295k → 251k → 213k.
    ///
    /// This is the arm that must FAIL. An A/B whose baseline cannot fail is
    /// not a baseline — the lesson AC0b was blocked on for a day.
    pub fn corp_vpn_thin_pipe() -> Scenario {
        Scenario {
            name: "corp-vpn thin pipe (213 kbps, recorded 2026-09-02)",
            pipe: PipeSpec {
                rate_bps: 213_180,
                rate_steps: Vec::new(),
                // A relay that will hold roughly a second of this pipe.
                buffer_bytes: 32_000,
                rtt: Duration::from_millis(80),
                loss_pct: 0,
                stalls: Vec::new(),
                transit_stalls: Vec::new(),
            },
            motion: Motion::Steady,
            fps: 30,
            duration: Duration::from_secs(40),
            seed: 0x0902,
            idr_factor: 25,
        }
    }

    /// **Airport hotspot** — goodput wandering 65–395 kbps.
    pub fn airport_hotspot() -> Scenario {
        Scenario {
            name: "airport hotspot (65–395 kbps, wandering)",
            pipe: PipeSpec {
                rate_bps: 395_000,
                rate_steps: vec![
                    (Duration::from_secs(8), 120_000),
                    (Duration::from_secs(20), 65_000),
                    (Duration::from_secs(34), 240_000),
                ],
                buffer_bytes: 48_000,
                rtt: Duration::from_millis(120),
                loss_pct: 1,
                stalls: Vec::new(),
                transit_stalls: Vec::new(),
            },
            motion: Motion::Steady,
            fps: 30,
            duration: Duration::from_secs(50),
            seed: 0xA152,
            idr_factor: 25,
        }
    }

    /// **CORPLAP-1 DERP** — 20–400 kbps with 1–4 s stalls.
    pub fn derp_with_stalls() -> Scenario {
        Scenario {
            name: "DERP relay (20–400 kbps, 1–4 s stalls)",
            pipe: PipeSpec {
                rate_bps: 400_000,
                rate_steps: vec![
                    (Duration::from_secs(15), 120_000),
                    (Duration::from_secs(30), 400_000),
                ],
                buffer_bytes: 40_000,
                rtt: Duration::from_millis(150),
                loss_pct: 0,
                stalls: vec![
                    Stall {
                        at: Duration::from_secs(10),
                        len: Duration::from_secs(2),
                    },
                    Stall {
                        at: Duration::from_secs(25),
                        len: Duration::from_secs(4),
                    },
                ],
                transit_stalls: Vec::new(),
            },
            motion: Motion::Steady,
            fps: 30,
            duration: Duration::from_secs(50),
            seed: 0xDE12,
            idr_factor: 25,
        }
    }

    /// **LAN Wi-Fi burst** — a fast pipe with motion bursts.
    pub fn lan_wifi_burst() -> Scenario {
        Scenario {
            name: "LAN Wi-Fi (5 Mbps, motion bursts)",
            pipe: PipeSpec {
                rate_bps: 5_000_000,
                rate_steps: Vec::new(),
                buffer_bytes: 300_000,
                rtt: Duration::from_millis(8),
                loss_pct: 0,
                stalls: Vec::new(),
                transit_stalls: Vec::new(),
            },
            motion: Motion::Bursts {
                period: Duration::from_secs(6),
                len: Duration::from_millis(700),
                factor: 5,
            },
            fps: 30,
            duration: Duration::from_secs(40),
            seed: 0x1A40,
            idr_factor: 25,
        }
    }

    /// A genuinely fast pipe that hiccups WHILE the opener's ramp is still
    /// climbing — the cell that discriminates between the ramp-exit rules.
    ///
    /// 🔑 Every other fast cell lets the ramp reach its ceiling before anything
    /// congests, so all three exit rules return identical numbers there and
    /// prove only "no regression". Here a 250 ms outage lands at 2 s, two
    /// windows into a ramp that needs ~6 to cross 300 k → 20 M: a rule that
    /// halves on congestion gives away rate the link demonstrably has, and a
    /// rule that ends the ramp hands back to a floor that is, on this pipe,
    /// far too LOW rather than too high.
    pub fn fast_pipe_early_stall() -> Scenario {
        Scenario {
            name: "fast pipe with an early transient stall (20 Mbps, 250 ms at 2 s)",
            pipe: PipeSpec {
                rate_bps: 20_000_000,
                rate_steps: Vec::new(),
                buffer_bytes: 1_000_000,
                rtt: Duration::from_millis(6),
                loss_pct: 0,
                stalls: vec![Stall {
                    at: Duration::from_secs(2),
                    len: Duration::from_millis(250),
                }],
                transit_stalls: Vec::new(),
            },
            motion: Motion::Steady,
            fps: 30,
            duration: Duration::from_secs(40),
            seed: 0xFA57_5A11,
            idr_factor: 25,
        }
    }

    /// **FR-70 P1 — the pinned session, CORPLAP-1 → neo16, 2026-09-04
    /// (`6a9abc30`).** The overlay pair through the corp VPN's DERP path
    /// (host↔host over the mesh, `relay=false` but constrained, ~80 ms),
    /// remembered at 200 kbps, encoding at the slow-link profile's 15 fps
    /// on a rebuild-bound `hevc_qsv`. Recorded: four minutes of
    /// `200k → 225k → 253k → 285k → 200k`, `goodput_bps=None`, zero send
    /// stalls, zero viewer-congested windows, age 55–108 ms — the pipe never
    /// pushed back; the FR-59 P2 budget (16 KB at a 200 kbps reference)
    /// tripped on each rebuild's keyframe and every trip was a decrease.
    ///
    /// The pipe's real rate was never measured, so it is modelled FAST
    /// (20 Mbps): the point of the cell is that its rate does not matter —
    /// the memory shapes the session the same way whatever the pipe is.
    ///
    /// The content is a window drag: a burst of motion frames at 6× the CBR
    /// mean for 200 ms of every second (the HRD lets motion frames run to
    /// roughly the 2× window), which is what lifts the bytes in flight over
    /// a 16 KB budget on an 80 ms path. `idr_factor` 8, not the FR-63
    /// fixtures' 25: that figure is the 2.55 Mbps opener's; a 200 kbps
    /// opener was measured on 0.4.50 as "no burst" (FR-59 field log,
    /// 2026-09-02), and a keyframe is bounded by the HRD window, not by a
    /// constant multiple of a frame.
    pub fn corplap1_remembered_slow_relay() -> Scenario {
        Scenario {
            name: "CORPLAP-1 remembered slow (20 Mbps behind an 80 ms path, seed 200 kbps, 15 fps)",
            pipe: PipeSpec {
                rate_bps: 20_000_000,
                rate_steps: Vec::new(),
                buffer_bytes: 1_000_000,
                rtt: Duration::from_millis(100),
                loss_pct: 0,
                stalls: Vec::new(),
                transit_stalls: Vec::new(),
            },
            motion: Motion::Bursts {
                period: Duration::from_secs(1),
                len: Duration::from_millis(200),
                factor: 6,
            },
            fps: 15,
            duration: Duration::from_secs(180),
            seed: 0x6A9A_BC30,
            idr_factor: 8,
        }
    }

    /// **FR-70 P1 — the pair the memory was RIGHT about.** The same path at
    /// a genuine 300 kbps (the 2026-09-02 measurement of this pair under
    /// 0.4.49's over-drive), remembered at 200 kbps. The decay must probe
    /// it, get measured, and NOT over-drive it by more than the AIMD's own
    /// step would have.
    pub fn corplap1_genuinely_slow_relay() -> Scenario {
        Scenario {
            name: "CORPLAP-1 genuinely slow (300 kbps, 80 ms, seed 200 kbps, 15 fps)",
            pipe: PipeSpec {
                rate_bps: 300_000,
                rate_steps: Vec::new(),
                // A relay that holds ~1.5 s of this pipe.
                buffer_bytes: 60_000,
                rtt: Duration::from_millis(80),
                loss_pct: 0,
                stalls: Vec::new(),
                transit_stalls: Vec::new(),
            },
            motion: Motion::Bursts {
                period: Duration::from_secs(1),
                len: Duration::from_millis(200),
                factor: 6,
            },
            fps: 15,
            duration: Duration::from_secs(180),
            seed: 0x0902_0300,
            idr_factor: 8,
        }
    }

    /// **Fast pair misremembered slow** — a 20 Mbps pipe opened at a
    /// remembered 200 kbps. The ramp must not leave a fast pair crawling.
    pub fn fast_pair_misremembered() -> Scenario {
        Scenario {
            name: "fast pair misremembered slow (20 Mbps, seed 200 kbps)",
            pipe: PipeSpec {
                rate_bps: 20_000_000,
                rate_steps: Vec::new(),
                buffer_bytes: 1_000_000,
                rtt: Duration::from_millis(6),
                loss_pct: 0,
                stalls: Vec::new(),
                transit_stalls: Vec::new(),
            },
            motion: Motion::Steady,
            fps: 30,
            duration: Duration::from_secs(40),
            seed: 0xFA57,
            idr_factor: 25,
        }
    }

    /// **FR-71 — finding 4, the transit stall** (CORPLAP-3 over DERP,
    /// 2026-09-04, session `6a9abaa8`): a path good for 5.6–8.5 Mbps whose
    /// relay leg head-of-line-blocked for ~4.9 s with **1485 bytes** in the
    /// send queue — nothing sender-side was wrong, and the backlog then
    /// painted at once. Modelled as an 8 Mbps / 80 ms pipe with ONE
    /// `transit_stalls` entry: the sender keeps draining, the frames sit in
    /// transit, and every one of them lands when the stall lifts. The
    /// shipped law reads the paint age of that window as over-production and
    /// cuts; T1a must classify it `TransitStalled`, T1b must not cut.
    pub fn finding4_transit_stall() -> Scenario {
        Scenario {
            name: "finding 4: DERP transit stall (8 Mbps, 80 ms, 4.8 s stall at 12 s)",
            pipe: PipeSpec {
                rate_bps: 8_000_000,
                rate_steps: Vec::new(),
                buffer_bytes: 1_000_000,
                rtt: Duration::from_millis(80),
                loss_pct: 0,
                stalls: Vec::new(),
                transit_stalls: vec![Stall {
                    at: Duration::from_secs(12),
                    len: Duration::from_millis(4_800),
                }],
            },
            motion: Motion::Steady,
            fps: 30,
            duration: Duration::from_secs(40),
            seed: 0x6A9A_BAA8,
            idr_factor: 8,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    /// The relay cap a constrained session opens against, and the flat
    /// `area_min_bitrate_bps` floor under it. Both are the field constants
    /// from the 2026-09-02/03 CORPLAP-1 cell.
    const RELAY_CEILING_BPS: u32 = 2_550_000;
    const FLAT_FLOOR_BPS: u32 = 1_500_000;

    fn arm_a(floor: u32, ceiling: u32) -> GovernorLaw {
        GovernorLaw::new(floor, ceiling, false)
    }

    fn arm_b(floor: u32, ceiling: u32) -> GovernorLaw {
        GovernorLaw::new(floor, ceiling, true)
    }

    // -- the simulator itself -------------------------------------------------
    //
    // A fixture is only evidence if the harness under it is right. These test
    // the MODEL, the way the `harness` integration test asserts `TestApp`'s
    // own teardown rather than any product behaviour.

    #[test]
    fn pipe_delivers_at_its_rate_and_no_faster() {
        let mut pipe = Pipe::new(PipeSpec::steady(800_000, 0, 1_000_000), 8, 1);
        let mut delivered = 0u64;
        let mut t = Duration::ZERO;
        // Offer far more than the link can carry, then drain for a second.
        while t < Duration::from_secs(1) {
            let _ = pipe.offer(2_000, t);
            for a in pipe.advance(t).0 {
                delivered += u64::from(a.bytes);
            }
            t += TICK;
        }
        let bits = delivered * 8;
        assert!(
            (700_000..=800_000).contains(&bits),
            "a 800 kbps pipe delivered {bits} bits in a second"
        );
    }

    #[test]
    fn an_idle_pipe_does_not_bank_capacity() {
        // The "a fast sample is not evidence" error in model form: if the
        // bucket accrued while nothing was queued, the first frame after a
        // quiet stretch would arrive instantly and every viewer-measured rate
        // in every fixture would be fiction.
        let mut pipe = Pipe::new(PipeSpec::steady(100_000, 0, 1_000_000), 8, 1);
        let mut t = Duration::ZERO;
        while t < Duration::from_secs(5) {
            let _ = pipe.advance(t);
            t += TICK;
        }
        // 5 s of idling at 100 kbps would have banked 500 kbit. A 12 500-byte
        // frame is 100 kbit and must take ~1 s, not arrive at once.
        assert!(pipe.offer(12_500, t));
        let mut transit = None;
        let deadline = t + Duration::from_secs(3);
        while t < deadline {
            if let Some(a) = pipe.advance(t).0.first() {
                transit = Some(a.at.saturating_sub(a.produced));
                break;
            }
            t += TICK;
        }
        let transit = transit.expect("the frame must arrive within 3 s");
        assert!(
            transit >= Duration::from_millis(900),
            "100 kbit over a 100 kbps pipe took {transit:?} — the bucket banked while idle"
        );
    }

    #[test]
    fn a_stall_carries_nothing_and_then_recovers() {
        let spec = PipeSpec {
            stalls: vec![Stall {
                at: Duration::from_secs(1),
                len: Duration::from_secs(2),
            }],
            transit_stalls: Vec::new(),
            ..PipeSpec::steady(400_000, 0, 1_000_000)
        };
        let mut pipe = Pipe::new(spec, 64, 1);
        let mut in_stall = 0u64;
        let mut after = 0u64;
        let mut t = Duration::ZERO;
        while t < Duration::from_secs(5) {
            let _ = pipe.offer(1_000, t);
            for a in pipe.advance(t).0 {
                if t >= Duration::from_millis(1_200) && t < Duration::from_secs(3) {
                    in_stall += u64::from(a.bytes);
                } else if t >= Duration::from_secs(3) {
                    after += u64::from(a.bytes);
                }
            }
            t += TICK;
        }
        assert_eq!(in_stall, 0, "the link carried {in_stall} bytes mid-stall");
        assert!(after > 0, "the link never recovered after the stall");
    }

    #[test]
    fn viewer_queue_ms_is_flat_when_the_pipe_keeps_up() {
        // A link with ample headroom must show no transit-queue growth. This
        // is the signal every congestion decision keys off, so a model that
        // reported drift on a healthy link would make every fixture lie.
        let sc = Scenario {
            name: "headroom",
            pipe: PipeSpec::steady(8_000_000, 10, 500_000),
            motion: Motion::Steady,
            fps: 30,
            duration: Duration::from_secs(10),
            seed: 7,
            idr_factor: 25,
        };
        let mut law = arm_a(FLAT_FLOOR_BPS, 2_000_000);
        let tr = run(&sc, &mut law);
        assert!(
            tr.peak_queue_ms() < 40,
            "a pipe with 4x headroom grew a queue{}",
            tr.render()
        );
        // ⚠️ Window 0 is EXCLUDED, and the exclusion is the finding rather
        // than a convenience: the opening keyframe is 25x a delta frame, so
        // at 2 Mbps it is ~208 KB and takes ~208 ms to cross even an 8 Mbps
        // link. The model reproduced a real effect — an opening IDR paints
        // late on ANY link, which is what FR-31's keyframe budget is about —
        // and it is not what this test is asking. Steady state is.
        let steady = &tr.rows[1..];
        let worst = steady.iter().map(|r| r.stats.age_p95_ms).max().unwrap_or(0);
        assert!(
            worst < 120,
            "a pipe with 4x headroom painted late in steady state ({worst} ms){}",
            tr.render()
        );
    }

    // -- AC0b: the opener ------------------------------------------------------

    #[test]
    fn ac0b_the_baseline_arm_can_fail() {
        // 🔑 The property the FIELD could not produce, and the reason AC0b sat
        // open: an A/B whose baseline cannot fail proves nothing. Arm A opens
        // at the relay cap — 12x a pipe that carries 213 kbps.
        let sc = corp_vpn_thin_pipe();
        let mut law = arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let tr = run(&sc, &mut law);

        assert!(
            tr.peak_target_bps() >= 2_000_000,
            "arm A did not over-commit — the cell cannot fail{}",
            tr.render()
        );
        assert!(
            tr.max_age_ms() >= 1_000,
            "arm A did not produce a multi-second paint{}",
            tr.render()
        );
    }

    #[test]
    fn ac0b_slow_start_removes_the_overdrive() {
        let sc = corp_vpn_thin_pipe();
        let mut a = arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let mut b = arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let ta = run(&sc, &mut a);
        let tb = run(&sc, &mut b);

        // The ramp opens where `slow_start::OPEN_BPS` says, not at the cap.
        assert_eq!(
            b.ramp_open_bps(),
            Some(super::super::slow_start::OPEN_BPS),
            "the ramp did not arm at OPEN_BPS"
        );

        let od_a = ta.overdrive_bits(110);
        let od_b = tb.overdrive_bits(110);
        assert!(
            od_b * 4 < od_a,
            "slow-start did not materially cut the over-drive: A={od_a} B={od_b}{}{}",
            ta.render(),
            tb.render()
        );
        assert!(
            tb.max_age_ms() * 3 < ta.max_age_ms(),
            "slow-start did not cut the peak paint age: A={} B={}{}{}",
            ta.max_age_ms(),
            tb.max_age_ms(),
            ta.render(),
            tb.render()
        );
    }

    /// Prints the AC0b A/B table. `#[ignore]`d because it asserts nothing —
    /// it exists so the numbers quoted on #1243 can be regenerated on demand
    /// instead of being retyped from a scrollback.
    ///
    /// `cargo test -p meshharbord --lib ac0b_report -- --ignored --nocapture`
    #[test]
    #[ignore = "reporting aid; run with --ignored --nocapture"]
    fn ac0b_report() {
        let sc = corp_vpn_thin_pipe();
        let mut a = arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let mut b = arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let ta = run(&sc, &mut a);
        let tb = run(&sc, &mut b);
        println!("{}", ta.render());
        println!("{}", tb.render());
        for (n, t) in [("A", &ta), ("B", &tb)] {
            println!(
                "arm {n}: peak_target={} overdrive_bits(110)={} max_p95_age={}ms \
                 peak_queue={}ms skips={} windows_over_500ms={} settled(25%)={:?}",
                t.peak_target_bps(),
                t.overdrive_bits(110),
                t.max_age_ms(),
                t.peak_queue_ms(),
                t.total_skips(),
                t.windows_above_age(500),
                t.settled_window(25),
            );
        }
    }

    #[test]
    fn ac0b_conclusion_survives_a_small_keyframe() {
        // 🔑 Sensitivity check, and the reason it exists: at the plan's 25×
        // the opening keyframe of a 2.55 Mbps arm-A session is ~265 KB —
        // ten seconds of a 213 kbps pipe — so arm A's first ten windows
        // deliver NOTHING and the A/B partly measures who commits to a
        // smaller opening IDR. That is a real effect (it is what FR-31's
        // keyframe budget is about) but it is not the rate law, and a
        // conclusion that only holds at one keyframe size would be an
        // artefact. Re-run at 3×: the ordering must survive.
        let mut sc = corp_vpn_thin_pipe();
        sc.idr_factor = 3;

        let mut a = arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let mut b = arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let ta = run(&sc, &mut a);
        let tb = run(&sc, &mut b);

        assert!(
            tb.overdrive_bits(110) < ta.overdrive_bits(110),
            "with a small keyframe the ramp no longer cuts the over-drive: A={} B={}{}{}",
            ta.overdrive_bits(110),
            tb.overdrive_bits(110),
            ta.render(),
            tb.render()
        );
        assert!(
            tb.max_age_ms() < ta.max_age_ms(),
            "with a small keyframe the ramp no longer cuts the peak paint: A={} B={}{}{}",
            ta.max_age_ms(),
            tb.max_age_ms(),
            ta.render(),
            tb.render()
        );
    }

    /// The open decision B0 raised, measured instead of argued: on a pipe
    /// thinner than `OPEN_BPS` the shipped ramp ends at the first congested
    /// window and the flat floor re-pins the opener. Two candidate rules are
    /// modelled in [`RampExit`]; this reports all three side by side.
    ///
    /// `cargo test -p meshharbord --lib ramp_exit_report -- --ignored --nocapture`
    #[test]
    #[ignore = "reporting aid; run with --ignored --nocapture"]
    fn ramp_exit_report() {
        // ⚠️ Every candidate is run on a FAST cell as well as the thin one it
        // was designed for. A rule measured only where it was invented is how
        // a regression ships: "halve on congestion" is obviously good on a
        // 213 kbps pipe and could plausibly cripple a 20 Mbps pair.
        for (label, sc, ceiling) in [
            ("thin pipe 213k", corp_vpn_thin_pipe(), RELAY_CEILING_BPS),
            ("fast pair 20M", fast_pair_misremembered(), 20_000_000u32),
            ("LAN 5M bursts", lan_wifi_burst(), 5_000_000u32),
            // 🔑 THE DISCRIMINATING CELL. The two cells above return identical
            // numbers for all three rules — not because the rules agree, but
            // because the ramp REACHED ITS CEILING before anything congested
            // (300k doubling to 5 M takes ~5 windows; the LAN bursts start at
            // 6 s). They prove "no regression", not "better". The risk unique
            // to HalveAndContinue is a TRANSIENT congestion event while the
            // ramp is still climbing on a genuinely fast pipe: halving there
            // would give away rate the link actually has.
            (
                "fast pipe, stall at 2s",
                fast_pipe_early_stall(),
                20_000_000u32,
            ),
        ] {
            println!("--- {label}");
            for exit in [
                RampExit::EndsOnCongestion,
                RampExit::HalveAndContinue,
                RampExit::HoldFloorUntilMeasured,
            ] {
                let mut law = arm_b(FLAT_FLOOR_BPS, ceiling).with_exit(exit);
                let t = run(&sc, &mut law);
                let last = t.rows.last().map(|r| r.target_bps).unwrap_or(0);
                println!(
                    "  {exit:?}: peak={} final={} overdrive={} max_p95_age={}ms \
                     skips={} settled(25%)={:?} over500ms={}",
                    t.peak_target_bps(),
                    last,
                    t.overdrive_bits(110),
                    t.max_age_ms(),
                    t.total_skips(),
                    t.settled_window(25),
                    t.windows_above_age(500),
                );
            }
        }
    }

    // -- FR-63 B0 under the SHIPPED measurement rule (FR-70 P1 follow-up) ------
    //
    // Everything above measures the pipe with `MeasureRule::EveryWindow`: every
    // window that delivered anything hands the floor relief the delivered
    // rate. The shipped governor does not work that way — it measures only on
    // PUSH-BACK (blocked sends, or the viewer's queue growing), and its FR-59
    // P2 byte budget skips frames before a queue can form. FR-70 P1 found that
    // the difference is not cosmetic: under the shipped rule a remembered rate
    // pinned a session that `EveryWindow` would have freed in one window. So
    // the AC0b answer and the ramp-exit numbers are re-taken here under the
    // shipped rule, with the budget gate and a rebuild-bound encoder modelled,
    // and the conclusions that survive are the ones the field can rely on.

    /// The realistic harness: the shipped measurement rule, the FR-59 P2 byte
    /// budget at the gate, a rebuild-bound (QSV-shaped) encoder.
    fn run_shipped(sc: &Scenario, law: GovernorLaw) -> Trace {
        let mut law = law.with_measure(MeasureRule::OnPushBack).with_fps(sc.fps);
        run_opts(
            sc,
            &mut law,
            SimOptions {
                budget_gate: true,
                rebuild_idr: true,
            },
        )
    }

    // -- FR-71 T1a: the shadow classifier on the cells ------------------------

    fn states_between(tr: &Trace, from_s: u64, to_s: u64) -> Vec<(u64, Option<PipeState>)> {
        tr.rows
            .iter()
            .filter(|r| r.t.as_secs() >= from_s && r.t.as_secs() < to_s)
            .map(|r| (r.t.as_secs(), r.state))
            .collect()
    }

    /// FR-71 AC1 — every window inside finding 4's transit stall classifies
    /// `TransitStalled`, and no window of the run is `Overproduced`: the
    /// sender's queue never left its budget (1485 bytes in the field), so the
    /// one verdict the law must not reach is "the encoder produced too much".
    #[test]
    fn t1a_finding_4_stall_windows_classify_as_transit_stalled() {
        let sc = finding4_transit_stall();
        let tr = run_shipped(&sc, arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS));
        // The stall runs 12.0–16.8 s. Window [12,13) still receives the
        // frames that were in flight before the block, so it is an ordinary
        // window; [13,17) receive nothing, then the whole backlog at 16.88 s.
        let inside = states_between(&tr, 13, 17);
        assert_eq!(inside.len(), 4, "{}", tr.render());
        for (t, st) in &inside {
            assert_eq!(
                *st,
                Some(PipeState::TransitStalled),
                "window at {t} s{}",
                tr.render()
            );
        }
        assert!(
            tr.rows
                .iter()
                .all(|r| r.state != Some(PipeState::Overproduced)),
            "a transit stall read as over-production{}",
            tr.render()
        );
        // The windows either side of it read as what they are.
        for (t, st) in states_between(&tr, 4, 12)
            .iter()
            .chain(states_between(&tr, 20, 40).iter())
        {
            assert_eq!(
                *st,
                Some(PipeState::Clear),
                "window at {t} s{}",
                tr.render()
            );
        }
    }

    /// FR-71 AC1 — on the thin pipe every window the byte-budget gate or a
    /// full channel touched is `Overproduced`, and nothing on it is ever
    /// `TransitStalled`: a pipe that is simply too small for the target is
    /// the sender's problem, and the classifier must say so even while the
    /// viewer's reports are sparse.
    #[test]
    fn t1a_thin_pipe_budget_windows_classify_as_overproduced() {
        let sc = corp_vpn_thin_pipe();
        let tr = run_shipped(&sc, arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS));
        let gated: Vec<_> = tr.rows.iter().filter(|r| r.skips > 0).collect();
        assert!(
            !gated.is_empty(),
            "the thin pipe never gated a frame{}",
            tr.render()
        );
        for r in &gated {
            assert_eq!(
                r.state,
                Some(PipeState::Overproduced),
                "gated window at {} s{}",
                r.t.as_secs(),
                tr.render()
            );
        }
        assert!(
            tr.rows
                .iter()
                .all(|r| r.state != Some(PipeState::TransitStalled)),
            "a thin pipe read as a transit stall{}",
            tr.render()
        );
    }

    /// FR-71 — the B0 freeze stalls (`derp_with_stalls`) are NOT finding 4.
    /// A frozen drain backs the sender's own queue up, so the sender can see
    /// it and `Overproduced` is the honest verdict once the queue is over
    /// budget; a window may read `TransitStalled` only in the first second,
    /// before the queue has filled. What the classifier must never do on a
    /// stalled window is call it `Clear`.
    #[test]
    fn t1a_freeze_stalls_are_sender_visible() {
        let sc = derp_with_stalls();
        let tr = run_shipped(&sc, arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS));
        let mut inside = Vec::new();
        for s in &sc.pipe.stalls {
            let from = s.at.as_secs() + 1;
            let to = (s.at + s.len).as_secs();
            inside.extend(states_between(&tr, from, to));
        }
        assert!(
            !inside.is_empty(),
            "no window sits fully inside a stall{}",
            tr.render()
        );
        for (t, st) in &inside {
            assert!(
                matches!(
                    st,
                    Some(PipeState::Overproduced) | Some(PipeState::TransitStalled)
                ),
                "stalled window at {t} s read {st:?}{}",
                tr.render()
            );
        }
    }

    /// FR-71 — a law without the classifier records no verdict, so a trace
    /// cannot mistake "unclassified" for "clear".
    #[test]
    fn t1a_laws_without_the_classifier_record_no_state() {
        let sc = finding4_transit_stall();
        let mut law = arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let tr = run(&sc, &mut law);
        assert!(tr.rows.iter().any(|r| r.state.is_some()), "{}", tr.render());

        /// A constant-rate law with none of the governor's machinery.
        struct Flat(u32);
        impl RateLaw for Flat {
            fn label(&self) -> &'static str {
                "flat"
            }
            fn on_frame(&mut self, _occupied: u32, _full: bool, _now: Instant) -> u32 {
                self.0
            }
            fn on_window(&mut self, _w: &WindowStats, _now: Instant) {}
            fn target_bps(&self) -> u32 {
                self.0
            }
        }
        let mut flat = Flat(RELAY_CEILING_BPS);
        let tr = run(&sc, &mut flat);
        assert!(tr.rows.iter().all(|r| r.state.is_none()), "{}", tr.render());
    }

    /// `cargo test -p meshharbord --lib t1a_report -- --ignored --nocapture`
    #[test]
    #[ignore = "reporting aid; run with --ignored --nocapture"]
    fn t1a_report() {
        for sc in [
            finding4_transit_stall(),
            corp_vpn_thin_pipe(),
            derp_with_stalls(),
        ] {
            let tr = run_shipped(&sc, arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS));
            let counts = tr.rows.iter().fold([0u32; 5], |mut c, r| {
                if let Some(s) = r.state {
                    c[s as usize] += 1;
                }
                c
            });
            println!(
                "{}: states clear/over/transit/viewer/unknown = {counts:?}{}",
                sc.name,
                tr.render()
            );
        }
    }

    // -- FR-71 T1b: the hold, and T1c's FAIL-first cell -----------------------

    fn target_at(tr: &Trace, s: u64) -> u32 {
        tr.rows
            .iter()
            .find(|r| r.t.as_secs() == s)
            .map(|r| r.target_bps)
            .unwrap_or_else(|| panic!("no window at {s} s{}", tr.render()))
    }

    fn min_target_between(tr: &Trace, from_s: u64, to_s: u64) -> u32 {
        tr.rows
            .iter()
            .filter(|r| r.t.as_secs() >= from_s && r.t.as_secs() < to_s)
            .map(|r| r.target_bps)
            .min()
            .unwrap_or_else(|| panic!("no windows in [{from_s},{to_s}){}", tr.render()))
    }

    /// FR-79 AC2, the control — finding 4's cell with the FR-15 age loop's cut
    /// modelled and the validity gate OFF, i.e. the law as it stood before
    /// FR-71 T1b: the backlog windows fire the age loop and the AIMD cuts a
    /// rate the pipe never asked for. The gate is unconditional in the daemon,
    /// so this arm exists only to keep the failure on record.
    #[test]
    fn finding_4_cuts_the_rate_without_the_validity_gate() {
        let sc = finding4_transit_stall();
        let tr = run_shipped(
            &sc,
            arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS)
                .with_age_cut(true)
                .with_stall_gate(false),
        );
        let before = target_at(&tr, 11);
        let after_min = min_target_between(&tr, 16, 22);
        assert!(
            after_min < before,
            "the shipped law did not cut on the stall (before {before}, min after {after_min}){}",
            tr.render()
        );
        assert_eq!(tr.holds, 0, "{}", tr.render());
    }

    /// FR-79 AC2 — the same cell with the validity gate on (the shipped law):
    /// no cut during or after
    /// the stall, the ramp frozen through it, the path reading clear again
    /// within the stall's own length.
    #[test]
    fn finding_4_keeps_the_rate_with_the_validity_gate() {
        let sc = finding4_transit_stall();
        let tr = run_shipped(
            &sc,
            arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS)
                .with_age_cut(true)
                .with_stall_gate(true),
        );
        let before = target_at(&tr, 11);
        let during_min = min_target_between(&tr, 12, 22);
        assert!(
            during_min >= before,
            "the hold cut anyway (before {before}, min {during_min}){}",
            tr.render()
        );
        // Nothing cut through the silence. (The target may still CLIMB: the
        // AIMD's additive increase is per frame and the sender's queue is
        // genuinely clear during a transit stall — whether the hold should
        // also freeze that is an open decision on the FR, not this cell's
        // claim. What the T1a cell saw as "the ramp climbing" was this
        // additive increase; the ramp had ended by 5 s.)
        assert!(target_at(&tr, 17) >= target_at(&tr, 12), "{}", tr.render());
        assert!(tr.holds >= 4, "holds={}{}", tr.holds, tr.render());
        // Recovery within the stall's own length: the stall lifts at 16.8 s,
        // the backlog drains at the link's rate through 17–19 s (each of
        // those windows still reads stalled — the transit share IS the
        // backlog), and the first clear window must come no later than
        // 16.8 + 4.8 s. Measured: 20 s.
        let first_clear = tr
            .rows
            .iter()
            .find(|r| r.t.as_secs() >= 17 && r.state == Some(PipeState::Clear))
            .map(|r| r.t.as_secs())
            .unwrap_or_else(|| panic!("never recovered{}", tr.render()));
        assert!(
            first_clear <= 21,
            "recovered only at {first_clear} s{}",
            tr.render()
        );
        for (t, st) in states_between(&tr, 22, 30) {
            assert_eq!(st, Some(PipeState::Clear), "window at {t} s{}", tr.render());
        }
    }

    /// FR-71 AC4 — where nothing stalls the hold changes nothing: the thin
    /// pipe, the LAN burst and the genuinely slow relay trace identically
    /// with it on and off, and hold nothing.
    #[test]
    fn t1b_hold_is_inert_where_nothing_stalls() {
        for sc in [
            corp_vpn_thin_pipe(),
            lan_wifi_burst(),
            corplap1_genuinely_slow_relay(),
        ] {
            let off = run_shipped(
                &sc,
                arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS).with_age_cut(true),
            );
            let on = run_shipped(
                &sc,
                arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS)
                    .with_age_cut(true)
                    .with_stall_gate(true),
            );
            let off_t: Vec<u32> = off.rows.iter().map(|r| r.target_bps).collect();
            let on_t: Vec<u32> = on.rows.iter().map(|r| r.target_bps).collect();
            assert_eq!(
                off_t,
                on_t,
                "{}: the hold changed a cell with no stall{}{}",
                sc.name,
                off.render(),
                on.render()
            );
            assert_eq!(on.holds, 0, "{}: held a window with no stall", sc.name);
        }
    }

    /// `cargo test -p meshharbord --lib shipped_rule_report -- --ignored --nocapture`
    #[test]
    #[ignore = "reporting aid; run with --ignored --nocapture"]
    fn shipped_rule_report() {
        println!(
            "=== AC0b under the shipped rule: {}",
            corp_vpn_thin_pipe().name
        );
        let sc = corp_vpn_thin_pipe();
        for (n, slow_start) in [("A", false), ("B", true)] {
            let t = run_shipped(
                &sc,
                GovernorLaw::new(FLAT_FLOOR_BPS, RELAY_CEILING_BPS, slow_start),
            );
            println!(
                "arm {n}: peak_target={} overdrive_bits(110)={} max_p95_age={}ms peak_queue={}ms \
                 skips={} gate_skips={} rebuild_idrs={} windows_over_500ms={} settled(25%)={:?}{}",
                t.peak_target_bps(),
                t.overdrive_bits(110),
                t.max_age_ms(),
                t.peak_queue_ms(),
                t.total_skips(),
                t.gate_skips,
                t.rebuild_idrs,
                t.windows_above_age(500),
                t.settled_window(25),
                t.render()
            );
        }
        println!("=== AC0b under the shipped rule, keyframe 3x");
        let mut sc3 = corp_vpn_thin_pipe();
        sc3.idr_factor = 3;
        for (n, slow_start) in [("A", false), ("B", true)] {
            let t = run_shipped(
                &sc3,
                GovernorLaw::new(FLAT_FLOOR_BPS, RELAY_CEILING_BPS, slow_start),
            );
            println!(
                "arm {n}: peak_target={} overdrive_bits(110)={} max_p95_age={}ms skips={} settled(25%)={:?}",
                t.peak_target_bps(),
                t.overdrive_bits(110),
                t.max_age_ms(),
                t.total_skips(),
                t.settled_window(25),
            );
        }
        println!("=== ramp exit under the shipped rule");
        for (label, sc, ceiling) in [
            ("thin pipe 213k", corp_vpn_thin_pipe(), RELAY_CEILING_BPS),
            ("fast pair 20M", fast_pair_misremembered(), 20_000_000u32),
            ("LAN 5M bursts", lan_wifi_burst(), 5_000_000u32),
            (
                "fast pipe, stall at 2s",
                fast_pipe_early_stall(),
                20_000_000u32,
            ),
        ] {
            println!("--- {label}");
            for exit in [
                RampExit::EndsOnCongestion,
                RampExit::HalveAndContinue,
                RampExit::HoldFloorUntilMeasured,
            ] {
                let t = run_shipped(
                    &sc,
                    GovernorLaw::new(FLAT_FLOOR_BPS, ceiling, true).with_exit(exit),
                );
                let last = t.rows.last().map(|r| r.target_bps).unwrap_or(0);
                println!(
                    "  {exit:?}: peak={} final={} overdrive={} max_p95_age={}ms skips={} gate_skips={} \
                     settled(25%)={:?} over500ms={}",
                    t.peak_target_bps(),
                    last,
                    t.overdrive_bits(110),
                    t.max_age_ms(),
                    t.total_skips(),
                    t.gate_skips,
                    t.settled_window(25),
                    t.windows_above_age(500),
                );
            }
        }
        println!("=== the four fixtures under the shipped rule (arm B)");
        for (label, sc, ceiling) in [
            ("airport hotspot", airport_hotspot(), RELAY_CEILING_BPS),
            ("DERP with stalls", derp_with_stalls(), RELAY_CEILING_BPS),
            ("LAN 5M bursts", lan_wifi_burst(), 5_000_000u32),
            (
                "fast pair misremembered (seed 200k)",
                fast_pair_misremembered(),
                20_000_000u32,
            ),
        ] {
            let seeded = label.contains("seed");
            let mut law = GovernorLaw::new(FLAT_FLOOR_BPS, ceiling, true);
            if seeded {
                law = law.with_seed(200_000);
            }
            let t = run_shipped(&sc, law);
            let last = t
                .rows
                .last()
                .map(|r| (r.target_bps, r.pipe_bps))
                .unwrap_or((0, 0));
            println!(
                "--- {label}: peak={} final_target={} final_pipe={} max_p95_age={}ms over500ms={} settled(25%)={:?}",
                t.peak_target_bps(),
                last.0,
                last.1,
                t.max_age_ms(),
                t.windows_above_age(500),
                t.settled_window(25),
            );
        }
    }

    /// What survives of the AC0b answer under the shipped rule: the ramp
    /// still commits less (peak 1.5 M vs 2.55 M), still cuts the over-drive
    /// (3.2×, not the 4.8× `EveryWindow` reported) and still cuts the peak
    /// paint — but by 1.7×, not 8×. The 1 226 ms figure on #1243 was the
    /// optimistic rule finding the pipe in window 2; under the shipped rule
    /// arm B's floor snaps back to the flat 1.5 M when the ramp ends, and the
    /// session sawtooths for ~24 windows before push-back measures the pipe.
    #[test]
    fn ac0b_under_the_shipped_rule_the_ramp_still_commits_less() {
        let sc = corp_vpn_thin_pipe();
        let ta = run_shipped(
            &sc,
            GovernorLaw::new(FLAT_FLOOR_BPS, RELAY_CEILING_BPS, false),
        );
        let tb = run_shipped(
            &sc,
            GovernorLaw::new(FLAT_FLOOR_BPS, RELAY_CEILING_BPS, true),
        );
        assert!(
            tb.peak_target_bps() < ta.peak_target_bps(),
            "B={} A={}{}{}",
            tb.peak_target_bps(),
            ta.peak_target_bps(),
            ta.render(),
            tb.render()
        );
        let (od_a, od_b) = (ta.overdrive_bits(110), tb.overdrive_bits(110));
        assert!(
            od_b * 2 < od_a,
            "the ramp no longer halves the over-drive under the shipped rule: A={od_a} B={od_b}{}{}",
            ta.render(),
            tb.render()
        );
        assert!(
            tb.max_age_ms() < ta.max_age_ms(),
            "the ramp no longer cuts the peak paint under the shipped rule: A={} B={}{}{}",
            ta.max_age_ms(),
            tb.max_age_ms(),
            ta.render(),
            tb.render()
        );
        // The claim guard: FR-63's table must not quote a ~1.2 s arm-B peak
        // paint as the shipped behaviour. If this ever holds, the table is
        // out of date in the OTHER direction — update it, then relax this.
        assert!(
            tb.max_age_ms() >= 3 * 1_226,
            "arm B's peak paint under the shipped rule is now {} ms — the EveryWindow \
             figure (1 226 ms) has become true; update FR-63's AC0b table",
            tb.max_age_ms()
        );
    }

    /// The candidates are measured on the fast cells under the shipped rule
    /// too — and there they COST rate: halving on a transient congestion
    /// event gives away capacity the link has. The trade-off is real in both
    /// directions, which is the reason FR-63 B1's controller is designed to
    /// HOLD on congestion rather than end or halve.
    #[test]
    fn under_the_shipped_rule_the_candidates_win_the_thin_pipe_and_pay_on_lan_bursts() {
        let thin = corp_vpn_thin_pipe();
        let shipped = run_shipped(
            &thin,
            GovernorLaw::new(FLAT_FLOOR_BPS, RELAY_CEILING_BPS, true),
        );
        for exit in [RampExit::HalveAndContinue, RampExit::HoldFloorUntilMeasured] {
            let cand = run_shipped(
                &thin,
                GovernorLaw::new(FLAT_FLOOR_BPS, RELAY_CEILING_BPS, true).with_exit(exit),
            );
            assert!(
                cand.max_age_ms() * 3 < shipped.max_age_ms(),
                "{exit:?} no longer cuts the thin-pipe peak paint 3×: {} vs {}{}{}",
                cand.max_age_ms(),
                shipped.max_age_ms(),
                shipped.render(),
                cand.render()
            );
        }
        let lan = lan_wifi_burst();
        let shipped = run_shipped(&lan, GovernorLaw::new(FLAT_FLOOR_BPS, 5_000_000, true));
        let halve = run_shipped(
            &lan,
            GovernorLaw::new(FLAT_FLOOR_BPS, 5_000_000, true).with_exit(RampExit::HalveAndContinue),
        );
        let last = |t: &Trace| t.rows.last().map(|r| r.target_bps).unwrap_or(0);
        assert!(
            last(&halve) < last(&shipped),
            "HalveAndContinue stopped costing rate on LAN bursts ({} vs {}) — re-open the \
             exit-rule decision on #1243{}{}",
            last(&halve),
            last(&shipped),
            shipped.render(),
            halve.render()
        );
    }

    #[test]
    fn a_candidate_exit_rule_must_beat_the_shipped_one_to_be_worth_proposing() {
        // Not a product assertion — a guard on the CLAIM. If a candidate stops
        // beating the shipped rule on the cell that motivated it, the open
        // decision on #1243 is answered "no" and this test says so loudly
        // rather than the numbers quietly rotting in a comment.
        let sc = corp_vpn_thin_pipe();
        let mut shipped = arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let base = run(&sc, &mut shipped);

        for exit in [RampExit::HalveAndContinue, RampExit::HoldFloorUntilMeasured] {
            let mut law = arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS).with_exit(exit);
            let cand = run(&sc, &mut law);
            assert!(
                cand.peak_target_bps() <= base.peak_target_bps(),
                "{exit:?} committed MORE than the shipped rule ({} vs {}){}{}",
                cand.peak_target_bps(),
                base.peak_target_bps(),
                base.render(),
                cand.render()
            );
        }
    }

    // -- the four scenario fixtures -------------------------------------------

    #[test]
    fn airport_hotspot_tracks_a_wandering_pipe() {
        let sc = airport_hotspot();
        let mut law = arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let tr = run(&sc, &mut law);
        let last = tr.rows.last().expect("windows");
        assert!(
            u64::from(last.target_bps) <= u64::from(last.pipe_bps) * 3,
            "the target never came down to the pipe{}",
            tr.render()
        );
    }

    #[test]
    fn derp_stalls_do_not_drive_the_target_up() {
        let sc = derp_with_stalls();
        let mut law = arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS);
        let tr = run(&sc, &mut law);
        // A window that delivered nothing is a stall, and a stall is not
        // evidence that the pipe got faster.
        let mut stall_windows = 0;
        for w in tr.rows.windows(2) {
            let (prev, cur) = (w[0], w[1]);
            if cur.stats.frames_rx == 0 {
                stall_windows += 1;
                assert!(
                    cur.target_bps <= prev.target_bps,
                    "the target rose during a stall at t={:?}{}",
                    cur.t,
                    tr.render()
                );
            }
        }
        // ⚠️ Without this the test is VACUOUS: the assertion above lives
        // inside a conditional, so a fixture whose stalls stopped producing
        // empty windows would pass while checking nothing at all. The
        // scenario schedules a 2 s and a 4 s outage; at least one window must
        // have delivered nothing.
        assert!(
            stall_windows >= 2,
            "the fixture produced only {stall_windows} empty windows — the \
             assertion never ran on a real stall{}",
            tr.render()
        );
    }

    #[test]
    fn lan_burst_does_not_collapse_a_fast_pipe() {
        let sc = lan_wifi_burst();
        let mut law = arm_b(FLAT_FLOOR_BPS, 5_000_000);
        let tr = run(&sc, &mut law);
        assert!(
            tr.max_age_ms() < 600,
            "a 5 Mbps LAN pair painted late under motion bursts{}",
            tr.render()
        );
        // ⚠️ Same vacuity trap one level up: this scenario is only a BURST
        // test if the bursts actually cost something. A 5× motion burst on a
        // 5 Mbps link must move the paint age off its floor somewhere, or the
        // fixture is testing a steady link with a burst label.
        let quietest = tr
            .rows
            .iter()
            .map(|r| r.stats.age_p95_ms)
            .min()
            .unwrap_or(0);
        assert!(
            tr.max_age_ms() > quietest + 5,
            "the motion bursts had no measurable effect (p95 {quietest}..{}) — \
             this fixture is not exercising what it claims{}",
            tr.max_age_ms(),
            tr.render()
        );
    }

    #[test]
    fn fast_pair_recovers_from_a_slow_seed() {
        // FR-59 P8's remembered rate is a PRIOR, not a pin: a pair remembered
        // at 200 kbps that is now on 20 Mbps must climb away from the memory.
        //
        // ⚠️ FR-70 P1: this passes under B0's `EveryWindow` rule, which hands
        // the floor relief the delivered rate every window and so overwrites
        // the memory with the truth in the first second. The shipped governor
        // does not measure that way — see `p1_the_memory_pins_the_session`,
        // which is the same pair under the shipped rule.
        let sc = fast_pair_misremembered();
        let mut law = GovernorLaw::new(FLAT_FLOOR_BPS, 20_000_000, true).with_seed(200_000);
        let tr = run(&sc, &mut law);
        let last = tr.rows.last().expect("windows");
        assert!(
            last.target_bps > 400_000,
            "the session never climbed away from a stale 200 kbps memory{}",
            tr.render()
        );
    }

    // ── FR-70 P1 — the prior that pinned CORPLAP-1 ─────────────────────────

    /// The shipped rules on the recorded session: measurement on push-back
    /// only, the byte-budget gate, a rebuild-bound encoder, the remembered
    /// rate standing in as a constant (`rate_prior_decay=false`). This is
    /// the arm that must FAIL — the memory holds the session near the floor
    /// for the whole run while the pipe never once pushes back.
    fn p1_arm(decay: bool, sc: &Scenario, ceiling_bps: u32) -> Trace {
        let mut law = GovernorLaw::new(FLAT_FLOOR_BPS, ceiling_bps, false)
            .with_measure(MeasureRule::OnPushBack)
            .with_fps(sc.fps)
            .with_prior_decay(decay)
            .with_seed(200_000);
        run_opts(
            sc,
            &mut law,
            SimOptions {
                budget_gate: true,
                rebuild_idr: true,
            },
        )
    }

    /// The viewer's queue never grew past the link loop's onset threshold —
    /// the pipe never pushed back, so whatever the target did was the law's
    /// own doing.
    fn never_congested(tr: &Trace) -> bool {
        tr.rows
            .iter()
            .all(|r| r.stats.queue_ms < i64::from(super::super::viewer_rate::QUEUE_GROWTH_MS))
    }

    #[test]
    fn p1_the_memory_pins_the_session_under_the_shipped_rules() {
        let sc = corplap1_remembered_slow_relay();
        let tr = p1_arm(false, &sc, RELAY_CEILING_BPS);
        // Never the band: three minutes on a 20 Mbps pipe and the session has
        // not once reached the nominal 1.5 M floor an unremembered session
        // opens ABOVE. (The exact hover point is a geometry of the model —
        // the burst size at which a frame is still in flight when the next
        // is due — and is not a claim about the field's 200–285 k sawtooth;
        // the claim is that the budget stays denominated in the memory.)
        assert!(
            tr.peak_target_bps() < FLAT_FLOOR_BPS,
            "expected the memory to keep the session below the band, peak was {}{}",
            tr.peak_target_bps(),
            tr.render()
        );
        // And the pin is the GATE's doing, not the pipe's: the viewer's queue
        // never grew, the channel never filled — every skip is a budget skip.
        assert!(
            tr.gate_skips > 0,
            "the budget gate never engaged{}",
            tr.render()
        );
        assert!(tr.rebuild_idrs > 0);
        assert!(
            never_congested(&tr),
            "the pipe must never push back{}",
            tr.render()
        );
        // With decay off the law offers the memory nothing better than the
        // applied rate, which is the pinned one: the memory refreshes itself.
        assert_eq!(tr.remembered_bps, None);
    }

    #[test]
    fn p1_the_prior_decays_and_the_session_escapes() {
        let sc = corplap1_remembered_slow_relay();
        let tr = p1_arm(true, &sc, RELAY_CEILING_BPS);
        // ~10 decay steps from 200 k reach the band inside 110 s; from there
        // the nominal floor stands and the AIMD's ordinary step climbs to the
        // relay ceiling.
        let at_120 = tr
            .rows
            .iter()
            .find(|r| r.t >= Duration::from_secs(120))
            .expect("120 s");
        assert!(
            at_120.target_bps >= FLAT_FLOOR_BPS,
            "expected the band by 120 s, got {}{}",
            at_120.target_bps,
            tr.render()
        );
        let last = tr.rows.last().expect("windows");
        assert!(
            last.target_bps >= RELAY_CEILING_BPS,
            "the escape must reach the ceiling and hold: {}{}",
            last.target_bps,
            tr.render()
        );
        // The pipe still never pushed back — the climb was the prior letting
        // go, not evidence arriving.
        assert!(never_congested(&tr), "{}", tr.render());
        // The memory is left with nothing below the band to re-seed from:
        // the prior has decayed away, so the pump records the applied rate.
        assert_eq!(tr.remembered_bps, None, "the prior must be gone at the end");
        // And it costs nothing in delivered latency on a fast pipe.
        assert!(
            tr.max_age_ms() < 300,
            "max age {} ms{}",
            tr.max_age_ms(),
            tr.render()
        );
    }

    /// The same memory on the pipe it was RIGHT about: the decay probes
    /// upward, the probe gets MEASURED (the queue grows, the sender blocks),
    /// the prior re-anchors on the measurement — and from a measured base
    /// the re-probe is gentle, so the session sits near the pipe instead of
    /// running away from it, at a latency cost bounded against the arm
    /// that never probes at all.
    #[test]
    fn p1_a_genuinely_slow_pipe_is_measured_not_overdriven() {
        let sc = corplap1_genuinely_slow_relay();
        let held = p1_arm(false, &sc, RELAY_CEILING_BPS);
        let tr = p1_arm(true, &sc, RELAY_CEILING_BPS);
        let n = tr.rows.len();
        let last_minute = &tr.rows[n.saturating_sub(60)..];
        let peak = last_minute
            .iter()
            .map(|r| r.peak_target_bps)
            .max()
            .unwrap_or(0);
        assert!(
            peak <= 400_000,
            "the decay must not run away from a measured 300 kbps pipe: peak {peak}{}",
            tr.render()
        );
        // The probe was answered by a measurement, not by a runaway.
        let measured = tr
            .remembered_bps
            .expect("a measurement or a prior must stand");
        assert!(
            (200_000..=400_000).contains(&measured),
            "the memory should record roughly the pipe, got {measured}{}",
            tr.render()
        );
        // The latency cost of probing, against the arm that holds the memory
        // as a constant: the mean paint age over the run stays under FR-59's
        // 600 ms AC4 bar, and the worst window is not worse than the held
        // arm's by more than one probe's worth of queue.
        let mean = |t: &Trace| {
            t.rows
                .iter()
                .map(|r| u64::from(r.stats.age_ms))
                .sum::<u64>()
                / (t.rows.len().max(1) as u64)
        };
        assert!(
            mean(&tr) < 600,
            "mean age {} ms (held arm {} ms){}",
            mean(&tr),
            mean(&held),
            tr.render()
        );
        assert!(
            tr.max_age_ms() <= held.max_age_ms() + 500,
            "max age {} ms vs {} ms held{}",
            tr.max_age_ms(),
            held.max_age_ms(),
            tr.render()
        );
    }

    /// Reporting aid — both arms on both cells.
    ///
    /// `cargo test -p meshharbord --lib p1_report -- --ignored --nocapture`
    #[test]
    #[ignore = "reporting aid; run with --ignored --nocapture"]
    fn p1_report() {
        for sc in [
            corplap1_remembered_slow_relay(),
            corplap1_genuinely_slow_relay(),
        ] {
            for decay in [false, true] {
                let tr = p1_arm(decay, &sc, RELAY_CEILING_BPS);
                println!(
                    "\n=== {} — rate_prior_decay={decay}: peak {} bps, max age {} ms, gate skips {}, rebuild IDRs {}, remembered {:?}{}",
                    sc.name,
                    tr.peak_target_bps(),
                    tr.max_age_ms(),
                    tr.gate_skips,
                    tr.rebuild_idrs,
                    tr.remembered_bps,
                    tr.render()
                );
            }
        }
    }

    // -- FR-70 M3a: the plan producer on the cells -----------------------------

    /// FR-70 M3a — a `RateLaw` that runs the plan producer beside the
    /// governor law and counts every frame on which the producer's budget is
    /// not the law's own statement of the inline arithmetic.
    struct ShadowedLaw {
        inner: GovernorLaw,
        knobs: super::super::plan::PlanKnobs,
        checked: std::cell::Cell<u32>,
        diverged: std::cell::Cell<u32>,
        first: std::cell::RefCell<Option<String>>,
    }

    impl ShadowedLaw {
        fn new(inner: GovernorLaw) -> Self {
            // The sim's constants, explicit — exactly as
            // `GovernorLaw::queue_budget_bytes` states them, so nothing here
            // reads the environment.
            let knobs = super::super::plan::PlanKnobs {
                relay_max_bps: inner.nominal_ceiling_bps,
                constrained_queue_ms: 450,
                constrained_queue_measured: true,
                direct_queue_ms: 150,
                direct_hrd_pct: 100,
                refined_cap: None,
                priority_caps: super::super::PriorityCaps::default(),
            };
            Self {
                inner,
                knobs,
                checked: std::cell::Cell::new(0),
                diverged: std::cell::Cell::new(0),
                first: std::cell::RefCell::new(None),
            }
        }

        fn inputs(&self) -> super::super::plan::PlanInputs {
            super::super::plan::PlanInputs {
                constrained: true,
                target_fps: self.inner.fps,
                paced_fps: None,
                pipe_bps: self.inner.pipe_bps(),
                ceiling_reference_bps: self.inner.nominal_ceiling_bps,
                hrd_pct: 200,
                target_bps: self.inner.target_bps(),
                dims: super::super::policy::DimsInputs {
                    native_w: 1920,
                    native_h: 1200,
                    merged_target: crate::peer::TargetResolution::Native,
                    merged_priority_cap: None,
                    slow_link_cap: None,
                    refined: false,
                    refined_cap: None,
                    soft_cap: None,
                },
            }
        }
    }

    impl RateLaw for ShadowedLaw {
        fn label(&self) -> &'static str {
            self.inner.label()
        }

        fn on_frame(&mut self, occupied: u32, full: bool, now: Instant) -> u32 {
            self.inner.on_frame(occupied, full, now)
        }

        fn on_window(&mut self, w: &WindowStats, now: Instant) {
            self.inner.on_window(w, now)
        }

        fn target_bps(&self) -> u32 {
            self.inner.target_bps()
        }

        fn queue_budget_bytes(&self) -> usize {
            // The harness asks once per frame, before `on_frame` — the gate's
            // own cadence. The law's answer is the sim's statement of the
            // inline arithmetic with the constants explicit; the producer's
            // must equal it on every frame of every cell. The harness then
            // gates on the law's number, so the cell itself is unchanged.
            let inline = self.inner.queue_budget_bytes();
            let plan = super::super::plan::produce(&self.inputs(), &self.knobs, None);
            self.checked.set(self.checked.get() + 1);
            if plan.queue_budget_bytes != inline {
                self.diverged.set(self.diverged.get() + 1);
                let mut first = self.first.borrow_mut();
                if first.is_none() {
                    *first = Some(format!(
                        "frame {}: plan {} vs inline {} (pipe {:?}, target {})",
                        self.checked.get(),
                        plan.queue_budget_bytes,
                        inline,
                        self.inner.pipe_bps(),
                        self.inner.target_bps()
                    ));
                }
            }
            inline
        }

        fn remembered_candidate_bps(&self) -> Option<u32> {
            self.inner.remembered_candidate_bps()
        }

        fn pipe_state(&self) -> Option<PipeState> {
            self.inner.pipe_state()
        }

        fn rejected_windows(&self) -> u32 {
            self.inner.rejected_windows()
        }

        fn on_budget_skip(&mut self, now: Instant) {
            self.inner.on_budget_skip(now)
        }
    }

    /// FR-70 M3a — the plan producer reproduces the byte budget the B0 cells
    /// gate on, frame for frame, on every fixture: the four plan cells, the
    /// FR-63 AC0b cell, the early-stall cell, FR-70 P1's remembered-pair cells
    /// (seed 200 k, the prior pinned and decaying) and FR-71's finding-4 cell.
    /// One frame apart fails with the cell named. The negative control — a
    /// planted `+ 1` in the producer — fails every cell on its first frame;
    /// both runs are recorded in the spec's M3a section.
    #[test]
    fn the_plan_producer_reproduces_the_b0_cells_budget_frame_for_frame() {
        let seeded = |law: GovernorLaw, decay: bool| law.with_prior_decay(decay).with_seed(200_000);
        let cells: Vec<(&str, Scenario, GovernorLaw)> = vec![
            (
                "AC0b corp VPN thin pipe (arm B)",
                corp_vpn_thin_pipe(),
                arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS),
            ),
            (
                "airport hotspot (arm B)",
                airport_hotspot(),
                arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS),
            ),
            (
                "DERP with stalls (arm B)",
                derp_with_stalls(),
                arm_b(FLAT_FLOOR_BPS, RELAY_CEILING_BPS),
            ),
            (
                "LAN 5M bursts (arm B)",
                lan_wifi_burst(),
                arm_b(FLAT_FLOOR_BPS, 5_000_000),
            ),
            (
                "fast pipe, early stall (arm A)",
                fast_pipe_early_stall(),
                arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS),
            ),
            (
                "fast pair misremembered (seed 200k, arm B)",
                fast_pair_misremembered(),
                arm_b(FLAT_FLOOR_BPS, 20_000_000).with_seed(200_000),
            ),
            (
                "CORPLAP-1 remembered slow, prior pinned",
                corplap1_remembered_slow_relay(),
                seeded(arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS), false),
            ),
            (
                "CORPLAP-1 remembered slow, prior decaying",
                corplap1_remembered_slow_relay(),
                seeded(arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS), true),
            ),
            (
                "CORPLAP-1 genuinely slow, prior decaying",
                corplap1_genuinely_slow_relay(),
                seeded(arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS), true),
            ),
            (
                "finding 4 transit stall (arm A)",
                finding4_transit_stall(),
                arm_a(FLAT_FLOOR_BPS, RELAY_CEILING_BPS),
            ),
        ];
        for (label, sc, law) in cells {
            let law = law.with_measure(MeasureRule::OnPushBack).with_fps(sc.fps);
            let mut shadowed = ShadowedLaw::new(law);
            let tr = run_opts(
                &sc,
                &mut shadowed,
                SimOptions {
                    budget_gate: true,
                    rebuild_idr: true,
                },
            );
            assert!(
                shadowed.checked.get() > 100,
                "{label}: the harness asked for the budget only {} times",
                shadowed.checked.get()
            );
            assert_eq!(
                shadowed.diverged.get(),
                0,
                "{label}: the producer's budget diverged on {} of {} frames — first: {}{}",
                shadowed.diverged.get(),
                shadowed.checked.get(),
                shadowed.first.borrow().as_deref().unwrap_or("-"),
                tr.render()
            );
        }
    }
}
