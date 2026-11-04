// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Measured-rate v2 — estimate what the session is ACTUALLY delivering,
//! and (stage 1) derive the bitrate ceiling from it.
//!
//! ## Why
//!
//! Every constrained-path decision keys off a NOMINAL relay clamp
//! (3 Mbps) and a boolean `constrained`, and the DIRECT path had no
//! absolute anchor at all: sessions (re)open at the resolution-derived
//! ceiling (15 Mbps at 2880×1800) while the pipe drains ~10, and the
//! whole mismatch lands as send-queue lag + production skips (field
//! 2026-08-26, neo16↔Rozalina — the "sluggish, then chunky" drag).
//! The AIMD only observes send-channel occupancy, so it rediscovers the
//! pipe by congesting it on every burst.
//!
//! ## The one hard problem: a fast sample is not evidence
//!
//! Handing a frame to SCTP is not the same as delivering it. When the
//! socket buffer has headroom a frame serialises in microseconds, which
//! computes to an absurd throughput that says nothing about the pipe —
//! it is a LOWER BOUND ("at least this fast"), not a measurement.
//!
//! Stage 0 answered this with busy-period bracketing (only measure an
//! unbroken ≥300 ms stretch where the queue never dried), which turned
//! out to be structurally unsatisfiable on the sessions that need it:
//! at 40 fps a ~30 KB frame drains in ~24 ms — just under the ~25 ms
//! inter-arrival — so the queue momentarily dries between frames even
//! while the CUMULATIVE deficit grows. Field heartbeats read
//! `goodput_samples: "(0, N)"` all session.
//!
//! v2 keeps the philosophy and fixes the granularity: the send task
//! times each frame's chunked `dc.send()` serialisation. A frame whose
//! serialisation took at least [`MIN_BLOCKED_SEND`] was flow-controlled
//! by SCTP for its whole transit — its bytes-over-time IS the drain
//! rate during that window. Sub-threshold sends are buffer headroom and
//! are DISCARDED at the source, so no amount of idle traffic can bias
//! the estimate upward. The governor then folds one WINDOW at a time
//! (its existing 1 s cadence): the window's samples are aggregated
//! byte-weighted (Σbytes / Σelapsed) and the aggregate must carry at
//! least [`MIN_WINDOW_BLOCKED`] of genuinely-blocked time to count —
//! one lone borderline frame is not a window's worth of evidence.
//!
//! Consequences worth knowing:
//!
//! - On an idle/unbound link nothing qualifies, the estimate stays
//!   `None`, and every derived quantity falls back to the nominal band.
//! - Any sustained overrun (a drag burst, relay congestion) produces a
//!   steady stream of qualifying samples within its first seconds.
//!
//! ## Asymmetric adaptation
//!
//! Down fast, up slow. A VPN throttling mid-session is something to
//! believe immediately; one lucky burst is not evidence the pipe grew.
//! The estimate also decays to `None` after [`CONFIDENCE_TTL`] without a
//! qualifying window, so a stale number can never outlive the conditions
//! that produced it — silence reverts to the nominal band rather than
//! pinning whatever was last true.
//!
//! ## Stage 1 — consumption
//!
//! [`derived_ceiling_bps`] turns the estimate into a bitrate ceiling:
//! `0.85 × G`, floored at 1 Mbps (insurance against a pathological
//! sample bricking video — the EWMA recovers in 2-3 windows anyway).
//! The governor applies `ceiling := min(nominal, derived)` — the
//! measurement may only ever LOWER the clamp, because the nominal clamp
//! also protects the TURN path. Kill switch:
//! `ROOMLERD_MEASURED_CEILING=0` / config `measured_ceiling`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-frame source rule: a frame whose chunked serialisation took less
/// than this was absorbed by buffer headroom and measures nothing. At
/// 10 Mbps this is ~12.5 KB of genuinely-paced bytes — any motion frame
/// under congestion qualifies easily.
pub const MIN_BLOCKED_SEND: Duration = Duration::from_millis(10);

/// Per-window aggregate rule: the governor folds one window (~1 s) of
/// samples at a time; the window's summed blocked time must reach this
/// before its byte-weighted rate counts as a measurement.
pub const MIN_WINDOW_BLOCKED: Duration = Duration::from_millis(60);

/// How long an estimate outlives its last qualifying window.
pub const CONFIDENCE_TTL: Duration = Duration::from_secs(60);

/// Stage-1 safety margin: the ceiling derived from a measurement is 85 %
/// of it (same margin the REMB path uses), so the encoder converges just
/// UNDER the pipe instead of riding it.
pub const MEASURED_CEILING_PCT: u64 = 85;

/// EWMA weight for a window BELOW the current estimate — the pipe
/// shrank, believe it quickly.
pub(super) const ALPHA_DOWN: f64 = 0.50;

/// EWMA weight for a window ABOVE it — the pipe may have grown, or we
/// may have caught one good burst. Move slowly.
pub(super) const ALPHA_UP: f64 = 0.10;

/// Most samples the sink will hold before dropping the oldest. Bounds
/// the memory if the folding side ever stops draining; the estimator
/// only needs recent history, so the old ones are the right ones to lose.
const MAX_PENDING: usize = 256;

/// [`MEASURED_CEILING_PCT`] of a measured rate, floored at 1 Mbps.
pub fn derived_ceiling_bps(goodput_bps: u32) -> u32 {
    (((goodput_bps as u64) * MEASURED_CEILING_PCT / 100) as u32).max(1_000_000)
}

/// FR-59 P1 — the bitrate FLOOR a measured pipe justifies.
///
/// `MIN_BITRATE_BPS` (1.5 Mbps) is a legibility floor calibrated for the
/// 2–9 Mbps band every measured relay had sat in. It is also the AIMD's
/// `floor_bps`, so on a slower pipe it is not a floor but a **pin**: the
/// multiplicative decrease bottoms out there and the encoder keeps
/// emitting multiples of what the link carries. Field 2026-09-01
/// (CORPLAP-3 → neo16 over a phone hotspot): a measured 395 kbps pipe met
/// a 1.5 Mbps floor — 3.8× — and the excess became 2.3–7.1 s of viewer
/// paint age queued below every agent counter.
///
/// So the floor descends, but **only on evidence**: `goodput_bps` is a
/// held measurement, and this returns the nominal floor unchanged unless
/// the measurement is actually below it. `hard_min_bps` is the absolute
/// stop — below roughly that, a full-resolution frame is illegible at any
/// QP and the honest lever is fewer pixels, not fewer bits.
///
/// ⚠ Deliberately the same `MEASURED_CEILING_PCT` margin the ceiling
/// uses: the floor is "what the pipe carries", and if it were set AT the
/// measurement the AIMD could not converge below the drain rate it is
/// trying to sit under.
pub fn measured_floor_bps(goodput_bps: u32, nominal_floor_bps: u32, hard_min_bps: u32) -> u32 {
    let derived = ((goodput_bps as u64) * MEASURED_CEILING_PCT / 100) as u32;
    if derived >= nominal_floor_bps {
        return nominal_floor_bps;
    }
    derived.max(hard_min_bps).min(nominal_floor_bps)
}

/// One qualifying blocked send: how many bytes, serialised over how long
/// with SCTP flow control engaged the whole way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedSend {
    pub bytes: u64,
    pub elapsed: Duration,
}

/// The hand-off between the send task (which times each frame's
/// serialisation) and the pump (which folds one window at its existing
/// 1 s cadence).
///
/// A plain `std::sync::Mutex` on purpose: the send task holds it for a
/// push with no `.await` inside, at most once per frame, so an async
/// mutex would buy nothing and cost a yield on the video path.
#[derive(Clone, Default)]
pub struct GoodputSink {
    pending: Arc<Mutex<Vec<BlockedSend>>>,
}

impl GoodputSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called by the send task after each frame that reached the wire.
    /// The [`MIN_BLOCKED_SEND`] source rule is enforced HERE so callers
    /// report every frame unconditionally — a sub-threshold send is
    /// headroom, not evidence, and never enters the window. Cheap and
    /// infallible — a poisoned lock is ignored rather than propagated,
    /// because losing a telemetry sample must never take down the video
    /// path.
    pub fn record(&self, bytes: u64, elapsed: Duration) {
        if elapsed < MIN_BLOCKED_SEND || bytes == 0 {
            return;
        }
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        if pending.len() >= MAX_PENDING {
            pending.remove(0);
        }
        pending.push(BlockedSend { bytes, elapsed });
    }

    /// Called by the pump to take everything observed since last time.
    pub fn drain(&self) -> Vec<BlockedSend> {
        let Ok(mut pending) = self.pending.lock() else {
            return Vec::new();
        };
        std::mem::take(&mut *pending)
    }
}

/// Rolling estimate of the session's delivered rate.
#[derive(Debug, Default)]
pub struct GoodputEstimator {
    ewma_bps: Option<f64>,
    last_sample_at: Option<Instant>,
    /// Windows that qualified. Reported in the heartbeat so a field
    /// reader can tell "no confidence because the link is unbound" from
    /// "no confidence because nothing is wired up".
    accepted: u64,
    /// Non-empty windows whose blocked time was too thin to count. An
    /// unbound link now shows `(0, 0)` — nothing blocked, nothing to
    /// reject (the v1 signature was `(0, N)`).
    rejected: u64,
}

impl GoodputEstimator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one window's samples, byte-weighted. Returns whether the
    /// window qualified. An EMPTY window is not evidence of anything and
    /// counts as neither accepted nor rejected.
    pub fn observe_window(&mut self, samples: &[BlockedSend], now: Instant) -> bool {
        if samples.is_empty() {
            return false;
        }
        let bytes: u64 = samples.iter().map(|s| s.bytes).sum();
        let elapsed: Duration = samples.iter().map(|s| s.elapsed).sum();
        if elapsed < MIN_WINDOW_BLOCKED || bytes == 0 {
            self.rejected += 1;
            return false;
        }
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 {
            self.rejected += 1;
            return false;
        }
        let sample = (bytes as f64 * 8.0) / secs;
        self.ewma_bps = Some(match self.ewma_bps {
            // First qualifying window: adopt it outright. Seeding from a
            // nominal guess would bias every later reading toward a
            // number we are specifically trying to stop trusting.
            None => sample,
            Some(prev) => {
                let alpha = if sample < prev { ALPHA_DOWN } else { ALPHA_UP };
                prev + alpha * (sample - prev)
            }
        });
        self.last_sample_at = Some(now);
        self.accepted += 1;
        true
    }

    /// The current estimate, or `None` when there is no confidence —
    /// either nothing has qualified yet, or the last window aged out.
    /// Callers treat `None` as "fall back to the nominal band".
    pub fn estimate_bps(&self, now: Instant) -> Option<u32> {
        let last = self.last_sample_at?;
        if now.duration_since(last) > CONFIDENCE_TTL {
            return None;
        }
        let bps = self.ewma_bps?;
        // Saturating rather than wrapping: an absurd sample should read
        // as "very fast", never as "almost nothing".
        Some(bps.clamp(0.0, u32::MAX as f64) as u32)
    }

    pub fn accepted(&self) -> u64 {
        self.accepted
    }

    pub fn rejected(&self) -> u64 {
        self.rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(bytes: u64, ms: u64) -> BlockedSend {
        BlockedSend {
            bytes,
            elapsed: Duration::from_millis(ms),
        }
    }

    /// The whole design rests on this: a frame that serialised instantly
    /// is buffer headroom, not capacity, and must not reach the window
    /// at all. Not down-weighted — discarded, at the source.
    #[test]
    fn a_fast_send_is_discarded_at_the_source() {
        let sink = GoodputSink::new();
        // 250 KB in 1 ms computes to 2 Gbps. Believing it once would
        // poison the EWMA for minutes.
        sink.record(250_000, Duration::from_millis(1));
        sink.record(0, Duration::from_millis(50));
        assert!(sink.drain().is_empty());
        // A genuinely blocked send is kept.
        sink.record(30_000, Duration::from_millis(24));
        assert_eq!(sink.drain().len(), 1);
    }

    /// A congested drag second: ~40 frames of ~30 KB each taking ~24 ms
    /// to serialise = a clean ~10 Mbps measurement.
    #[test]
    fn a_congested_window_measures_the_drain_rate() {
        let mut est = GoodputEstimator::new();
        let t0 = Instant::now();
        let window: Vec<BlockedSend> = (0..40).map(|_| sample(30_000, 24)).collect();
        assert!(est.observe_window(&window, t0));
        let got = est.estimate_bps(t0).unwrap();
        assert_eq!(got, 10_000_000, "40×30KB over 40×24ms = 10 Mbps");
        assert_eq!(est.accepted(), 1);
    }

    /// A window with too little blocked time is rejected — one lone
    /// borderline frame is not a window's worth of evidence.
    #[test]
    fn a_thin_window_is_rejected_not_believed() {
        let mut est = GoodputEstimator::new();
        let t0 = Instant::now();
        assert!(!est.observe_window(&[sample(30_000, 24)], t0));
        assert_eq!(est.estimate_bps(t0), None);
        assert_eq!(est.rejected(), 1);
        assert_eq!(est.accepted(), 0);
    }

    /// An EMPTY window (idle link) is neither accepted nor rejected —
    /// the unbound-link heartbeat signature is now `(0, 0)`.
    #[test]
    fn an_empty_window_counts_as_nothing() {
        let mut est = GoodputEstimator::new();
        let t0 = Instant::now();
        assert!(!est.observe_window(&[], t0));
        assert_eq!((est.accepted(), est.rejected()), (0, 0));
        assert_eq!(est.estimate_bps(t0), None);
    }

    /// Down fast: a VPN throttling mid-session is worth believing at
    /// once. One window must move the estimate most of the way.
    #[test]
    fn the_estimate_falls_fast() {
        let mut est = GoodputEstimator::new();
        let t0 = Instant::now();
        est.observe_window(&[sample(250_000, 1000)], t0); // 2 Mbps
        est.observe_window(&[sample(125_000, 1000)], t0); // 1 Mbps
        let got = est.estimate_bps(t0).unwrap();
        assert_eq!(got, 1_500_000, "ALPHA_DOWN=0.5 halves the gap in one step");
    }

    /// Up slow: one lucky burst is not proof the pipe grew.
    #[test]
    fn the_estimate_rises_slowly() {
        let mut est = GoodputEstimator::new();
        let t0 = Instant::now();
        est.observe_window(&[sample(125_000, 1000)], t0); // 1 Mbps
        est.observe_window(&[sample(250_000, 1000)], t0); // 2 Mbps
        let got = est.estimate_bps(t0).unwrap();
        assert_eq!(got, 1_100_000, "ALPHA_UP=0.1 moves a tenth of the gap");
        assert!(
            got < 1_500_000,
            "rising must be slower than falling, or a burst sets the ceiling"
        );
    }

    /// A stale estimate is worse than none: conditions change, and a
    /// number that outlives its evidence would pin the session to a pipe
    /// that no longer exists.
    #[test]
    fn confidence_expires_without_fresh_windows() {
        let mut est = GoodputEstimator::new();
        let t0 = Instant::now();
        est.observe_window(&[sample(250_000, 1000)], t0);
        assert!(
            est.estimate_bps(t0 + CONFIDENCE_TTL).is_some(),
            "still fresh at the boundary"
        );
        assert_eq!(
            est.estimate_bps(t0 + CONFIDENCE_TTL + Duration::from_secs(1)),
            None,
            "past the TTL it must read as no-confidence, not as the old value"
        );
    }

    /// ...and comes back when evidence does.
    #[test]
    fn a_fresh_window_restores_confidence() {
        let mut est = GoodputEstimator::new();
        let t0 = Instant::now();
        est.observe_window(&[sample(250_000, 1000)], t0);
        let stale = t0 + CONFIDENCE_TTL + Duration::from_secs(1);
        assert_eq!(est.estimate_bps(stale), None);
        est.observe_window(&[sample(250_000, 1000)], stale);
        assert_eq!(est.estimate_bps(stale), Some(2_000_000));
    }

    /// Stage 1's derivation: 85 % of the measurement, floored at 1 Mbps
    /// so a pathological low can't brick video outright.
    #[test]
    fn derived_ceiling_is_85_pct_with_a_floor() {
        assert_eq!(derived_ceiling_bps(10_000_000), 8_500_000);
        assert_eq!(derived_ceiling_bps(2_000_000), 1_700_000);
        assert_eq!(derived_ceiling_bps(300_000), 1_000_000, "floored at 1M");
    }

    /// FR-59 P1 — the floor descends ONLY on evidence, and never past the
    /// hard minimum. The three cases that matter: a pipe wider than the
    /// nominal floor leaves it alone (no behaviour change on a healthy
    /// relay), a slow pipe lowers it to 85 % of the measurement, and a
    /// pathological pipe stops at the hard minimum instead of reaching 0.
    #[test]
    fn measured_floor_descends_only_on_evidence() {
        const NOMINAL: u32 = 1_500_000;
        const HARD: u32 = 200_000;
        // A healthy relay: measurement is above the floor ⇒ untouched.
        assert_eq!(measured_floor_bps(9_000_000, NOMINAL, HARD), NOMINAL);
        // Exactly at the boundary (85 % of 1.765 M ≈ the floor) ⇒ untouched.
        assert_eq!(measured_floor_bps(1_800_000, NOMINAL, HARD), NOMINAL);
        // The field case: 395 kbps measured ⇒ 335,853, well under the floor.
        assert_eq!(measured_floor_bps(395_122, NOMINAL, HARD), 335_853);
        // The worst field window: 64,850 ⇒ 55,122, clamped up to the hard min.
        assert_eq!(measured_floor_bps(64_850, NOMINAL, HARD), HARD);
        // A zero measurement can never drive the floor to zero.
        assert_eq!(measured_floor_bps(0, NOMINAL, HARD), HARD);
        // A hard minimum above the nominal floor can never RAISE it — the
        // relief is one-directional by construction.
        assert_eq!(measured_floor_bps(100_000, NOMINAL, 9_000_000), NOMINAL);
    }

    #[test]
    fn sink_round_trips_and_drains_once() {
        let sink = GoodputSink::new();
        sink.record(30_000, Duration::from_millis(20));
        sink.record(40_000, Duration::from_millis(30));
        let drained = sink.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0], sample(30_000, 20));
        assert!(sink.drain().is_empty(), "drain must consume");
    }

    /// If the folding side ever stops draining, the sink must not grow
    /// without bound — and it should keep the RECENT samples, since the
    /// estimator only cares about those.
    #[test]
    fn sink_is_bounded_and_drops_the_oldest() {
        let sink = GoodputSink::new();
        for i in 0..(MAX_PENDING as u64 + 10) {
            sink.record(10_000 + i, Duration::from_millis(20));
        }
        let drained = sink.drain();
        assert_eq!(drained.len(), MAX_PENDING);
        assert_eq!(drained[0].bytes, 10_010, "oldest dropped");
        assert_eq!(
            drained[MAX_PENDING - 1].bytes,
            10_000 + MAX_PENDING as u64 + 9
        );
    }

    /// The sink is shared across tasks; a clone must be the same sink,
    /// not a fresh one (a copy would silently swallow every sample).
    #[test]
    fn a_cloned_sink_shares_storage() {
        let sink = GoodputSink::new();
        let writer = sink.clone();
        writer.record(30_000, Duration::from_millis(20));
        assert_eq!(sink.drain().len(), 1);
    }
}
