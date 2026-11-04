// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Viewer-reported sustainable-rate controller for the DataChannel video pumps.
//!
//! Replaces the rc.184 keyframe-request-*rate* `DecodePressure` heuristic. That
//! design inferred viewer distress from how OFTEN the browser sent `rc:keyframe`
//! resync requests — but the browser debounces those to ~4/s (250 ms) while the
//! shed needed ≥4/s to escalate, so the two never coordinated: on a weak viewer
//! (Iris Xe) the agent kept firehosing 60 fps, the viewer's WebCodecs decode
//! queue backed up, it dropped deltas + asked for a (heavy) IDR, which was even
//! HARDER to decode → the periodic 1-2 s freeze the field reported on dragging a
//! window. An RTX-5090 viewer of the SAME host never stuttered — pure
//! viewer-decode binding, not capture/encode.
//!
//! Now the VIEWER measures its own decoded fps + whether it dropped frames to a
//! backlog this window and sends `{fps, struggling}` over the control DC
//! (`rc:decodestat`). This controller folds that DIRECT, measured signal into an
//! fps cap. When struggling, it clamps the cap to just below what the viewer
//! actually sustained, so the agent immediately sends fewer frames; after a run
//! of clean windows it probes the cap lazily back toward the capture rate (so a
//! transient dip recovers, but a viewer sitting just under its ceiling doesn't
//! oscillate).
//!
//! The pump converts the cap into the existing frame-skip divisor
//! (`ceil(capture_fps / cap_fps)`, keyframes never skipped), so the agent
//! SETTLES at the viewer's real sustainable fps. During a sustained window-drag
//! the viewer struggles every window → the cap holds → smooth reduced fps;
//! motion stops → it recovers. Because the divisor quantises (caps 31..60 all
//! map to 30 fps until the cap reaches capture_fps exactly), active use naturally
//! parks at the reduced rate and only climbs back to full fps after a long idle.
//!
//! Pure (no webrtc / capture / ffmpeg types) → unit-tests on the default
//! `cargo test --lib`. The pump features are what USE it, hence the dead_code
//! allow on the signalling-only build (mirrors `aimd` / `encode_pressure`).

use tunnel_core::env::node_env;

fn env_u32(suffix: &str, default: u32) -> u32 {
    node_env(suffix)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Lowest fps the controller will cap down to. Below this, motion is a
/// slideshow; deeper relief is the (manual) resolution lever's job, not more
/// fps shedding. Env `ROOMLERD_VIEWER_RATE_MIN_FPS` (default 12).
fn min_fps() -> u32 {
    env_u32("VIEWER_RATE_MIN_FPS", 12).max(1)
}

/// fps step per adjustment — down on struggle, and (unless overridden) up on
/// recovery. Env `ROOMLERD_VIEWER_RATE_STEP` (default 10).
fn fps_step() -> u32 {
    env_u32("VIEWER_RATE_STEP", 10).max(1)
}

/// P6 — separate fps step for the recovery climb, so burst-recovery is fast
/// without coarsening the shed clamp. Env `ROOMLERD_VIEWER_RATE_STEP_UP`;
/// defaults to 2× the down-step (P6 field bake 2026-07-26 — with recover=3
/// this recovers a shallow clamp in one ~3 s probe and a deep clamp in ~9 s;
/// the shed still steps down by the small `step`).
fn fps_step_up(default_step: u32) -> u32 {
    env_u32("VIEWER_RATE_STEP_UP", default_step.saturating_mul(2)).max(1)
}

/// Consecutive clean windows before the cap probes back UP one step. Lazy so a
/// viewer parked just under its ceiling doesn't oscillate every window.
/// Env `ROOMLERD_VIEWER_RATE_RECOVER` (default 3 — P6 field bake
/// 2026-07-26: the old 6 measured 15.5 s deep-clamp recovery on the canonical
/// pair (cap 12 → divisor 1, probes every 3.1 s, model-exact); 3 plus the 2×
/// up-step brings the common shallow clamp to ≤3 s and a deep clamp to ~9 s.
/// The viewer's P6 sustained-window struggle rule (2 consecutive bad windows)
/// damps the ceiling-oscillation risk that originally motivated 6).
fn recover_windows() -> u32 {
    env_u32("VIEWER_RATE_RECOVER", 3).max(1)
}

/// Slow-start recovery climb (shelf item, 2026-07-27). Only the FIRST probe
/// after a struggle is lazy (`recover` clean windows — confirmation the
/// struggle really ended); once climbing, every further clean window probes
/// again and each probe takes the larger of `step_up` and HALF THE REMAINING
/// GAP to the capture rate. Deep clamps recover in a handful of windows
/// (12→36→56→60 at 60 capture: ~5 s where the additive climb took ~9 s)
/// while the ceiling-parked oscillation guard is preserved — a re-struggle
/// drops out of slow-start and the next climb needs full confirmation again.
/// Env `ROOMLERD_VIEWER_RATE_SLOW_START=0` restores the pure additive
/// climb.
fn slow_start_enabled() -> bool {
    !matches!(
        node_env("VIEWER_RATE_SLOW_START").as_deref(),
        Some("0") | Some("false")
    )
}

/// Turns a stream of viewer decode reports into a send-fps cap for one DC pump.
/// Step it once per ~1 s observation window with `(reported_fps, struggling)`.
pub struct ViewerRateController {
    /// Current agreed send-fps cap. Starts at the capture rate (no cap).
    cap_fps: u32,
    /// The pump's capture target — the ceiling the cap can never exceed.
    capture_fps: u32,
    clean_streak: u32,
    min_fps: u32,
    step: u32,
    /// P6 — recovery climb step (defaults to `step`; env-tunable separately).
    step_up: u32,
    recover: u32,
    /// Slow-start state: true while a recovery climb is in progress (between
    /// the first post-struggle probe and reaching the capture rate). While
    /// climbing, probes fire every clean window instead of every `recover`.
    climbing: bool,
    /// Env kill for the slow-start climb (`VIEWER_RATE_SLOW_START=0`).
    slow_start: bool,
    enabled: bool,
}

impl ViewerRateController {
    pub fn new(capture_fps: u32) -> Self {
        let capture_fps = capture_fps.max(1);
        let step = fps_step();
        Self {
            cap_fps: capture_fps,
            capture_fps,
            clean_streak: 0,
            min_fps: min_fps().min(capture_fps),
            step,
            step_up: fps_step_up(step),
            recover: recover_windows(),
            climbing: false,
            slow_start: slow_start_enabled(),
            // Kill switch — default ON; `ROOMLERD_VIEWER_RATE=0` (or
            // `false`) pins the cap at the capture rate (divisor 1, no shedding)
            // so a misbehaving field host reverts without a rebuild.
            enabled: !matches!(
                node_env("VIEWER_RATE").as_deref(),
                Some("0") | Some("false")
            ),
        }
    }

    /// Fold one viewer report into the cap and return the frame-skip divisor the
    /// pump should apply. `reported_fps` = frames the viewer DECODED last window
    /// (0 if it sent no useful number); `struggling` = it dropped frames to a
    /// decode backlog (or its queue was backing up). `capture_fps` is passed each
    /// call so a mid-session capture-rate change (e.g. the SW auto-cap) re-seeds
    /// the ceiling.
    pub fn observe(&mut self, reported_fps: u32, struggling: bool, capture_fps: u32) -> u32 {
        self.capture_fps = capture_fps.max(1);
        self.min_fps = self.min_fps.min(self.capture_fps);
        // Keep the cap within the (possibly changed) bounds before deciding.
        self.cap_fps = self.cap_fps.clamp(self.min_fps, self.capture_fps);
        if !self.enabled {
            self.cap_fps = self.capture_fps;
            return 1;
        }
        if struggling {
            // Clamp to just below what the viewer actually managed. A nonsense
            // (0) report falls back to stepping the current cap down. Never
            // below min_fps, never above capture_fps.
            let managed = if reported_fps > 0 {
                reported_fps
            } else {
                self.cap_fps
            };
            let target = managed.min(self.cap_fps).saturating_sub(self.step);
            self.cap_fps = target.clamp(self.min_fps, self.capture_fps);
            self.clean_streak = 0;
            // A re-struggle ends any climb: the next one needs full
            // confirmation (`recover` clean windows) again.
            self.climbing = false;
        } else {
            self.clean_streak += 1;
            // Slow-start: only the FIRST probe after a struggle is lazy;
            // while climbing, every clean window probes again.
            let need = if self.climbing && self.slow_start {
                1
            } else {
                self.recover
            };
            if self.clean_streak >= need {
                let up = if self.slow_start {
                    // Half the remaining gap, floored at step_up, so deep
                    // clamps close fast and the climb still terminates.
                    self.step_up
                        .max(self.capture_fps.saturating_sub(self.cap_fps) / 2)
                } else {
                    self.step_up
                };
                self.cap_fps = (self.cap_fps + up).min(self.capture_fps);
                self.clean_streak = 0;
                self.climbing = self.cap_fps < self.capture_fps;
            }
        }
        self.divisor()
    }

    /// `ceil(capture_fps / cap_fps)`, clamped ≥ 1. Ceil (not round) guarantees
    /// the effective fps (`capture_fps / divisor`) never EXCEEDS the cap, so we
    /// stay at-or-under what the viewer said it can take.
    pub fn divisor(&self) -> u32 {
        let cap = self.cap_fps.max(1);
        self.capture_fps.div_ceil(cap).max(1)
    }

    /// Current cap, for the heartbeat log.
    pub fn cap_fps(&self) -> u32 {
        self.cap_fps
    }
}

/// Bit set in the packed report atomic when the viewer flagged a decode backlog
/// this window. The low 16 bits carry the reported decoded fps.
pub const STRUGGLE_BIT: u32 = 1 << 16;

/// Pack a viewer decode report into the shared atomic the control handler writes
/// and the pumps read. `fps` is clamped to 16 bits (ample for any real rate).
pub fn pack_report(fps: u32, struggling: bool) -> u32 {
    fps.min(0xFFFF) | if struggling { STRUGGLE_BIT } else { 0 }
}

/// Inverse of [`pack_report`]. The `0` swap-reset value (no report this window)
/// decodes to `(0, false)` — a clean window, which the controller treats as a
/// recovery tick.
pub fn unpack_report(raw: u32) -> (u32, bool) {
    (raw & 0xFFFF, raw & STRUGGLE_BIT != 0)
}

// ── FR-15 — viewer paint-age feedback ───────────────────────────────────────
// The FR-1 P7 age pill measures true end-to-end frame age at the viewer; the
// viewer piggybacks each window's avg + min onto `rc:decodestat`. On a
// CONSTRAINED transport that age is the only sensor that sees the whole path:
// the 2026-08-27 field session showed a 1000 ms age against a 26 KB agent
// queue — the backlog lives in the WG-over-DERP/TCP legs, below every agent
// counter. The loop here turns sustained age growth into the same responses
// the rest of the stack already knows: an fps cap (instant, no re-open) and a
// multiplicative decrease (applied under the FR-10 quiet/spacing rules).

/// Pack a viewer age report — window avg, window min, and the viewer's own
/// measured probe ROUND TRIP, all ms — into the shared `viewer_age` cell.
/// `0` is the swap-reset / no-report sentinel, so a genuine measurement is
/// floored at 1 ms; sub-ms end-to-end age is not physically possible, so
/// nothing real is lost.
///
/// The round trip rides along because P2's whole correction depends on it:
/// only the path's own timing says whether a reported floor is physically
/// possible, and the viewer is the one measuring it.
pub fn pack_age(age_ms: u16, age_min_ms: u16, rtt_ms: u16) -> u64 {
    (age_ms.max(1) as u64) | ((age_min_ms.max(1) as u64) << 16) | ((rtt_ms as u64) << 32)
}

/// Inverse of [`pack_age`] → `(avg, min, one_way)`; `0` (no report) → `None`.
pub fn unpack_age(raw: u64) -> Option<(u16, u16, u16)> {
    if raw == 0 {
        return None;
    }
    Some((
        (raw & 0xFFFF) as u16,
        ((raw >> 16) & 0xFFFF) as u16,
        ((raw >> 32) & 0xFFFF) as u16,
    ))
}

/// FR-70 M0 — [`pack_age`] plus the window's age at ARRIVAL (the frame's
/// last chunk reaching the viewer's worker, same clock mapping as the paint
/// age) in the fourth `u16`. `0` = the viewer did not report one (pre-M0),
/// so the slot reads as absent rather than as an instantaneous arrival.
pub fn pack_age_with_arrival(age_ms: u16, age_min_ms: u16, rtt_ms: u16, arrival_ms: u16) -> u64 {
    pack_age(age_ms, age_min_ms, rtt_ms) | ((arrival_ms as u64) << 48)
}

/// The arrival age carried by [`pack_age_with_arrival`]; `None` for no
/// report at all or a viewer that does not send one.
pub fn unpack_age_arrival(raw: u64) -> Option<u16> {
    if raw == 0 {
        return None;
    }
    let arrival = ((raw >> 48) & 0xFFFF) as u16;
    (arrival > 0).then_some(arrival)
}

/// FR-70 M0 — the fused paint age, split by plane.
///
/// `viewer_age_ms` fuses three latencies into one number, which is how a
/// 4903 ms relay stall (CORPLAP-3, 2026-09-04: `inflight=1485` bytes,
/// `iter_max=28 ms`) arrived looking like a pump problem. With the viewer
/// reporting the age at ARRIVAL as well, the three separate:
///
/// - **viewer** = paint age − arrival age: decode queue + decode + paint,
///   entirely inside the browser;
/// - **sender** = the agent's own send-queue wait for the window
///   (`send_wait_avg_ms`: enqueue → wire-complete), when the pump has it;
/// - **transit** = arrival age − sender: the network, the relay, the
///   receiver's socket — everything between the wire and the worker.
///
/// A `sender` of `None` (a pump with no send-wait figure) leaves `transit`
/// as the whole arrival age, an upper bound. Saturating throughout: the
/// three averages come from the same window but not the same frames.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AgeSplit {
    pub sender_ms: Option<f64>,
    pub transit_ms: u16,
    pub viewer_ms: u16,
}

pub fn split_age(age_ms: u16, arrival_ms: u16, sender_ms: Option<f64>) -> AgeSplit {
    let viewer_ms = age_ms.saturating_sub(arrival_ms);
    let transit_ms = match sender_ms {
        Some(s) if s.is_finite() && s > 0.0 => (f64::from(arrival_ms) - s).max(0.0).round() as u16,
        _ => arrival_ms,
    };
    AgeSplit {
        sender_ms,
        transit_ms,
        viewer_ms,
    }
}

/// FR-59 P3 — pack the viewer's LINK report: the bytes/s it actually
/// received this window, and how much the transit queue GREW during it
/// (ms, signed — negative means it drained).
///
/// Neither quantity needs the `rc:clock` probe, which is the point.
/// `rx_bps` is a byte count over a local interval. `queue_ms` is
/// `Σ(Δarrival − Δwire)`: the *difference* of two intervals, so the
/// unknown clock offset cancels exactly, and it stays meaningful in the
/// windows where FR-15's age is `None` or rejected as implausible —
/// which, on the link this exists for, is most of them (field
/// 2026-09-01: `viewer_age_ms=None` in 8 of 14 windows,
/// `viewer_age_implausible=60`).
///
/// `0` is the swap-reset / no-report sentinel, so bit 0 is a presence
/// marker rather than data — `rx_bps` of 0 with a 0 ms drift is a
/// legitimate report (a window that received nothing) and must not read
/// as silence.
pub fn pack_link(rx_bps: u32, queue_ms: i16) -> u64 {
    1 | ((queue_ms as u16 as u64) << 16) | ((rx_bps as u64) << 32)
}

/// Inverse of [`pack_link`] → `(rx_bps, queue_ms)`; `0` (no report) → `None`.
pub fn unpack_link(raw: u64) -> Option<(u32, i16)> {
    if raw == 0 {
        return None;
    }
    Some(((raw >> 32) as u32, ((raw >> 16) & 0xFFFF) as u16 as i16))
}

/// Everything one viewer tells the agent about how the stream is actually
/// landing: the rc.188 decode report (fps + struggling), the FR-15 paint
/// age, and the FR-59 P3 link report. ONE shared cell per session — the
/// control handler writes, the DC pump swaps once a viewer window, and a
/// follower's is read by the shared pipeline's fold. Every slot uses `0`
/// as "nothing reported this window", so a viewer that goes quiet decays
/// to no-signal instead of pinning a stale value.
#[derive(Debug, Default)]
pub struct ViewerFeedback {
    report: std::sync::atomic::AtomicU32,
    age: std::sync::atomic::AtomicU64,
    link: std::sync::atomic::AtomicU64,
    /// FR-119 P1 — the frame rate this viewer asked for with `rc:fps`; `0` =
    /// it never asked. Unlike the three reports above this is not a per-window
    /// signal: it stands until the viewer asks again, so it is read, never taken.
    fps_asked: std::sync::atomic::AtomicU32,
}

impl ViewerFeedback {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrite the decode report (see [`pack_report`]).
    pub fn store_report(&self, packed: u32) {
        self.report
            .store(packed, std::sync::atomic::Ordering::Relaxed);
    }

    /// Consume the decode report, leaving "no signal" behind.
    pub fn take_report(&self) -> u32 {
        self.report.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// FR-119 P1 — record the viewer's frame-rate ask (`rc:fps`).
    pub fn store_fps_ask(&self, fps: u32) {
        self.fps_asked
            .store(fps, std::sync::atomic::Ordering::Relaxed);
    }

    /// FR-119 P1 — the viewer's standing frame-rate ask, if it made one.
    pub fn fps_ask(&self) -> Option<u32> {
        match self.fps_asked.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            fps => Some(fps),
        }
    }

    /// The reported fps WITHOUT consuming the report — session telemetry
    /// reads what the user saw; the rate loop is the only consumer that
    /// may take it.
    pub fn peek_fps(&self) -> u32 {
        self.report.load(std::sync::atomic::Ordering::Relaxed) & 0xFFFF
    }

    /// FR-15 — overwrite the paint-age report (see [`pack_age`]).
    pub fn store_age(&self, packed: u64) {
        self.age.store(packed, std::sync::atomic::Ordering::Relaxed);
    }

    /// FR-15 — consume the paint-age report.
    pub fn take_age(&self) -> u64 {
        self.age.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// FR-59 P3 — overwrite the link report (see [`pack_link`]).
    pub fn store_link(&self, packed: u64) {
        self.link
            .store(packed, std::sync::atomic::Ordering::Relaxed);
    }

    /// FR-59 P3 — consume the link report.
    pub fn take_link(&self) -> u64 {
        self.link.swap(0, std::sync::atomic::Ordering::Relaxed)
    }
}

/// Age excess over the learned floor that counts a window as over-rate.
/// Below this the climb is within jitter noise; the field baseline that
/// motivated the loop was +60 ms felt as sluggish on an 85 ms-RTT relay.
pub const AGE_SLACK_MS: u16 = 70;
/// Consecutive over-rate windows before the loop reacts (mirrors the
/// viewer-side struggle fold: one bad window is a blip, not a trend).
const AGE_OVER_WINDOWS: u8 = 2;
/// Windows of floor memory (~30 s at the 1 s viewer window): long enough to
/// hold the floor through a sustained drag, short enough that a genuine
/// path change (VPN re-route raising the floor) re-baselines in half a
/// minute instead of over-triggering forever.
const AGE_FLOOR_RING: usize = 30;

/// FR-59 P3 — a window whose transit queue grew by at least this many ms
/// is over-rate. Deliberately well above zero: frame-interval jitter and
/// the ±1 ms of timestamp rounding both land in the drift sum, and a
/// window that grew 20 ms is not a session in trouble.
pub const QUEUE_GROWTH_MS: i16 = 100;
/// Consecutive growing windows before the loop acts — the same
/// one-bad-window-is-a-blip fold FR-15's age loop uses.
const QUEUE_OVER_WINDOWS: u8 = 2;
/// Safety margin on the arrival-rate ceiling, matching the measured
/// ceiling's own 85–90 % convention: converge just UNDER the pipe.
pub const LINK_CEILING_PCT: u64 = 90;

/// FR-59 P4 — estimated queue depth (ms) at which the session stops
/// waiting for the queue to drain and DRAINS it, by pausing production.
/// Well above `QUEUE_GROWTH_MS`: a growing queue wants a rate cut, and
/// only a queue that a rate cut cannot clear in reasonable time wants a
/// pause.
pub const DRAIN_THRESHOLD_MS: i32 = 700;
/// Longest pause the drain may take. A deliberate freeze that restores
/// liveness beats a permanent lag, but only while it stays sub-second —
/// past that the cure reads as the disease.
pub const DRAIN_MAX_MS: u32 = 600;
/// Shortest useful pause: below this the queue was not deep enough to be
/// worth a visible hitch.
pub const DRAIN_MIN_MS: u32 = 150;

/// What the FR-59 P3 link loop concluded from one viewer window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkVerdict {
    /// The transit queue has grown for [`QUEUE_OVER_WINDOWS`] consecutive
    /// windows — the session is putting bits in faster than they come out.
    pub congested: bool,
    /// The ceiling the viewer's measured ARRIVAL rate justifies. `None`
    /// unless `congested`; see the type docs for why that gate is not
    /// optional.
    pub ceiling_bps: Option<u32>,
    /// FR-59 P4 — how long to STOP producing so the transit queue can
    /// drain, if it has grown past [`DRAIN_THRESHOLD_MS`]. `None` = keep
    /// producing.
    ///
    /// A rate cut alone drains a queue at `capacity − inflow`, which is
    /// the slowest possible way to do it: converging to 90 % of a 400 kbps
    /// pipe drains a 2 s backlog at 40 kbps, i.e. over ~20 s. Pausing sets
    /// inflow to zero, so the same backlog clears in the ~2 s it
    /// represents. On a session already seconds behind, one deliberate
    /// sub-second freeze that restores liveness is the better trade.
    pub drain_for_ms: Option<u32>,
}

/// FR-59 P3 — the loop that reads congestion from where the queue actually
/// is: the viewer.
///
/// The agent's AIMD watches its own send-channel occupancy, which on a
/// relayed path is empty while seconds of video sit in the relay and the
/// carrier (field 2026-09-01: `bytes_inflight` 1–4 KB and
/// `send_wait_max_ms` 0.1 ms in the very windows the viewer reported
/// 2,284 ms of paint age). Only the receiver can see that queue.
///
/// ⚠ **`rx_bps` is a LOWER BOUND on capacity, not capacity** — it is
/// whatever the agent happened to send, which on a static desktop is a
/// few KB/s of keepalive deltas. Clamping the ceiling to it
/// unconditionally would ratchet a healthy session down to nothing and
/// never recover. So the arrival rate may bound the ceiling ONLY while
/// the queue is growing, because that is the one condition under which we
/// know the agent is overdriving the pipe and therefore that what arrived
/// is what the pipe carries. When the queue is flat or draining the
/// arrival rate says nothing about capacity, and the AIMD's normal
/// additive increase is left free to probe upward.
#[derive(Debug, Default)]
pub struct LinkLoop {
    growth_streak: u8,
    /// Windows judged congested — heartbeat telemetry, so "the loop never
    /// fired" and "the viewer never reported" are distinguishable.
    congested_windows: u32,
    /// FR-59 P4 — the running INTEGRAL of the per-window drift: an
    /// estimate of how deep the transit queue currently is, in ms. Floored
    /// at 0 (a link that delivers faster than it is fed has no queue, not
    /// a negative one) and reset when a drain is ordered, because after a
    /// pause the estimate is spent.
    depth_ms: i32,
    /// Drains ordered — heartbeat telemetry.
    drains: u32,
    /// Whether a drain is already outstanding, so consecutive windows
    /// cannot each order one before the first has been served.
    drain_pending: bool,
}

impl LinkLoop {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one viewer window. `rx_bps` = bytes/s the viewer actually
    /// received; `queue_ms` = how much the transit queue grew during it.
    pub fn observe(&mut self, rx_bps: u32, queue_ms: i16) -> LinkVerdict {
        self.growth_streak = if queue_ms >= QUEUE_GROWTH_MS {
            self.growth_streak.saturating_add(1)
        } else {
            0
        };
        let congested = self.growth_streak >= QUEUE_OVER_WINDOWS;
        if congested {
            self.congested_windows = self.congested_windows.saturating_add(1);
        }
        // P4 — integrate the derivative into a depth estimate. A draining
        // window subtracts, so a session that recovers on the rate cut
        // alone never reaches the drain threshold.
        self.depth_ms = (self.depth_ms + queue_ms as i32).max(0);
        let drain_for_ms = if !self.drain_pending && self.depth_ms >= DRAIN_THRESHOLD_MS {
            self.drain_pending = true;
            self.drains = self.drains.saturating_add(1);
            let ms = (self.depth_ms as u32).clamp(DRAIN_MIN_MS, DRAIN_MAX_MS);
            // The estimate is SPENT: whatever the pause actually clears,
            // the next windows re-measure it. Carrying it forward would
            // order a second drain immediately after the first.
            self.depth_ms = 0;
            Some(ms)
        } else {
            None
        };
        LinkVerdict {
            congested,
            ceiling_bps: (congested && rx_bps > 0)
                .then(|| ((rx_bps as u64) * LINK_CEILING_PCT / 100) as u32),
            drain_for_ms,
        }
    }

    /// FR-59 P4 — the pump has served the drain it was told to take.
    pub fn drain_served(&mut self) {
        self.drain_pending = false;
    }

    /// Windows this loop judged congested (heartbeat).
    pub fn congested_windows(&self) -> u32 {
        self.congested_windows
    }

    /// FR-59 — the live queue-depth estimate (ms). The clamp-release
    /// rule reads it: growth STOPPING is not the queue going away.
    pub fn depth_ms(&self) -> i32 {
        self.depth_ms
    }

    /// FR-59 P4 — drains ordered, and the live depth estimate (heartbeat).
    pub fn drain_stats(&self) -> (u32, i32) {
        (self.drains, self.depth_ms)
    }
}

/// P2 — a session sitting at this multiple of its own one-way delay is
/// over-queued no matter what floor it managed to learn. Without an
/// absolute rule, a session that starts congested teaches the loop that
/// congestion IS the floor and can then never trigger on excess: field
/// 2026-08-27, a viewer reported a learned floor of 1111 ms while its
/// window average ran 1 134–13 485 ms, and the loop stayed silent.
const AGE_OVER_QUEUE_MULTIPLE: u16 = 3;
/// Absolute floor for that rule, so a very short path still needs a
/// genuinely bad age before the loop fires on it.
const AGE_OVER_QUEUE_MIN_MS: u16 = 250;

/// FR-15 — the constrained-transport age loop. Feed one `observe` per
/// viewer window; it learns the session's age floor (min over the ring —
/// the floor is propagation+decode, not queue) and reports `true` once the
/// excess has persisted [`AGE_OVER_WINDOWS`] consecutive windows, staying
/// `true` each window while the overload lasts (the caller's MD is
/// rate-limited internally, so "true every window" is exactly the intended
/// ×0.85-per-window pressure).
#[derive(Debug)]
pub struct AgeLoop {
    ring: [u16; AGE_FLOOR_RING],
    len: usize,
    idx: usize,
    over_streak: u8,
    /// P2 — floor samples rejected as physically impossible. Surfaced in
    /// the heartbeat: a climbing count is the clock probe being biased by
    /// the very congestion it rides through, which is a different fault
    /// from "the path is slow" and wants a different fix.
    implausible: u32,
}

impl Default for AgeLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl AgeLoop {
    pub fn new() -> Self {
        Self {
            ring: [0; AGE_FLOOR_RING],
            len: 0,
            idx: 0,
            over_streak: 0,
            implausible: 0,
        }
    }

    /// Fold one viewer window. `age_ms` = window average, `age_min_ms` =
    /// window minimum (the floor sample — even a queued window usually
    /// contains one frame that rode a momentarily drained pipe).
    ///
    /// `one_way_ms` is half the viewer's own measured probe round trip: the
    /// smallest age the path can physically produce, since a frame cannot
    /// reach the screen faster than the wire allows. P2 uses it two ways.
    ///
    /// **A floor sample below it is rejected, not learned.** The `rc:clock`
    /// probe rides the SAME congested channel as the video it measures, so
    /// its midpoint assumption skews low exactly when the pipe is full;
    /// the resulting sub-physical ages then became the floor and made the
    /// loop hair-trigger. Field 2026-08-27: learned floors of 1–15 ms on
    /// relays whose own round trip was 86–210 ms, with the target visibly
    /// parked at the area floor in windows the path was fine.
    ///
    /// **And an age far above it fires regardless of the floor**, so a
    /// session that begins congested — and therefore never sees a good
    /// window to learn from — is still caught.
    pub fn observe(&mut self, age_ms: u16, age_min_ms: u16, one_way_ms: u16) -> bool {
        if age_min_ms >= one_way_ms {
            self.ring[self.idx] = age_min_ms.max(1);
            self.idx = (self.idx + 1) % AGE_FLOOR_RING;
            if self.len < AGE_FLOOR_RING {
                self.len += 1;
            }
        } else {
            self.implausible = self.implausible.saturating_add(1);
        }
        // Fall back to the physical bound while nothing plausible has been
        // learned — never to the sample we just rejected.
        let floor = self.floor_ms().unwrap_or(one_way_ms.max(1));
        let over_excess = age_ms.saturating_sub(floor) >= AGE_SLACK_MS;
        let over_queued = age_ms
            >= one_way_ms
                .saturating_mul(AGE_OVER_QUEUE_MULTIPLE)
                .max(AGE_OVER_QUEUE_MIN_MS);
        self.over_streak = if over_excess || over_queued {
            self.over_streak.saturating_add(1)
        } else {
            0
        };
        self.over_streak >= AGE_OVER_WINDOWS
    }

    /// The learned path floor (min of the ring), None before any report.
    pub fn floor_ms(&self) -> Option<u16> {
        self.ring[..self.len].iter().copied().min()
    }

    /// FR-71 T1b — a held window is not evidence of over-production: the
    /// floor ring keeps what it learned, the over-streak starts again, so
    /// the first elevated window AFTER a stall does not fire on the stall's
    /// own count.
    pub fn reset_streak(&mut self) {
        self.over_streak = 0;
    }

    /// P2 — floor samples rejected as below the path's physical minimum.
    pub fn implausible_samples(&self) -> u32 {
        self.implausible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FR-70 M0 — the arrival slot rides in the spare u16 of the age word and
    // is absent (not zero) for a viewer that does not send it.
    #[test]
    fn age_word_carries_the_arrival_age_without_disturbing_the_three_it_had() {
        let raw = pack_age_with_arrival(4903, 61, 80, 4890);
        assert_eq!(unpack_age(raw), Some((4903, 61, 80)));
        assert_eq!(unpack_age_arrival(raw), Some(4890));
        // The pre-M0 packer leaves the slot empty ⇒ absent.
        assert_eq!(unpack_age_arrival(pack_age(4903, 61, 80)), None);
        assert_eq!(
            unpack_age_arrival(pack_age_with_arrival(4903, 61, 80, 0)),
            None
        );
        // No report at all.
        assert_eq!(unpack_age_arrival(0), None);
        // The u16 ceiling survives the pack.
        assert_eq!(
            unpack_age_arrival(pack_age_with_arrival(1, 1, 0, u16::MAX)),
            Some(u16::MAX)
        );
    }

    // FR-70 M0 — finding 4 in numbers: a 4903 ms paint with a 12 ms send
    // wait and a 13 ms browser is a TRANSIT stall, and the split says so.
    #[test]
    fn the_split_attributes_a_relay_stall_to_transit() {
        let s = split_age(4903, 4890, Some(12.3));
        assert_eq!(s.viewer_ms, 13);
        assert_eq!(s.transit_ms, 4878);
        assert_eq!(s.sender_ms, Some(12.3));
        // A browser that is the problem: 66 ms of transit, 900 ms of decode.
        let s = split_age(966, 66, Some(2.0));
        assert_eq!(s.viewer_ms, 900);
        assert_eq!(s.transit_ms, 64);
        // No sender figure ⇒ transit is the whole arrival age (an upper bound).
        let s = split_age(966, 66, None);
        assert_eq!(s.transit_ms, 66);
        // Averages from different frames can invert; saturate, never wrap.
        let s = split_age(50, 60, Some(70.0));
        assert_eq!(s.viewer_ms, 0);
        assert_eq!(s.transit_ms, 0);
    }

    // Deterministic controller regardless of ambient env. `slow_start` is
    // pinned OFF here so these tests keep locking the pure additive climb;
    // the slow-start behaviour has its own fixture + tests below.
    fn ctrl(capture_fps: u32) -> ViewerRateController {
        ViewerRateController {
            cap_fps: capture_fps,
            capture_fps,
            clean_streak: 0,
            min_fps: 12,
            step: 10,
            step_up: 10,
            recover: 6,
            climbing: false,
            slow_start: false,
            enabled: true,
        }
    }

    // Slow-start fixture at the shipped defaults (recover 3, step_up 2×step).
    fn ctrl_ss(capture_fps: u32) -> ViewerRateController {
        ViewerRateController {
            cap_fps: capture_fps,
            capture_fps,
            clean_streak: 0,
            min_fps: 12,
            step: 10,
            step_up: 20,
            recover: 3,
            climbing: false,
            slow_start: true,
            enabled: true,
        }
    }

    #[test]
    fn no_struggle_stays_at_full_rate() {
        let mut c = ctrl(60);
        // A clean window keeps the cap at capture → divisor 1 (no skip).
        assert_eq!(c.observe(60, false, 60), 1);
        assert_eq!(c.cap_fps(), 60);
    }

    #[test]
    fn struggle_caps_below_managed_and_raises_divisor() {
        let mut c = ctrl(60);
        // Viewer was sent 60 but only decoded 35 and dropped frames → cap to
        // 35-10=25 → ceil(60/25)=3 (20 fps, safely under 25).
        let div = c.observe(35, true, 60);
        assert_eq!(c.cap_fps(), 25);
        assert_eq!(div, 3);
        assert!(60 / div <= c.cap_fps(), "effective fps must not exceed cap");
    }

    #[test]
    fn zero_report_while_struggling_steps_current_cap_down() {
        let mut c = ctrl(60);
        // No usable fps number but struggling → step the current cap (60) down.
        let div = c.observe(0, true, 60);
        assert_eq!(c.cap_fps(), 50);
        assert_eq!(div, 2); // ceil(60/50) = 2 → 30 fps
    }

    #[test]
    fn cap_floors_at_min_fps() {
        let mut c = ctrl(60);
        for _ in 0..20 {
            c.observe(5, true, 60);
        }
        assert_eq!(c.cap_fps(), 12, "never drops below min_fps");
        assert_eq!(c.divisor(), 5); // ceil(60/12)
    }

    #[test]
    fn recovery_probes_up_only_after_a_run_of_clean_windows() {
        let mut c = ctrl(60);
        c.observe(30, true, 60); // cap 20
        assert_eq!(c.cap_fps(), 20);
        // 5 clean windows: still parked (recover=6 not yet reached).
        for _ in 0..5 {
            c.observe(20, false, 60);
        }
        assert_eq!(c.cap_fps(), 20, "lazy recovery holds until the streak");
        // 6th clean window trips one +step probe.
        c.observe(20, false, 60);
        assert_eq!(c.cap_fps(), 30);
    }

    #[test]
    fn recovery_climbs_back_to_full_and_pins_divisor_1() {
        let mut c = ctrl(60);
        c.observe(0, true, 60); // cap 50
        // Enough clean windows to walk 50 → 60 (one +10 step per `recover`).
        for _ in 0..(6 * 2) {
            c.observe(60, false, 60);
        }
        assert_eq!(c.cap_fps(), 60);
        assert_eq!(c.divisor(), 1);
    }

    #[test]
    fn asymmetric_step_up_climbs_faster_without_coarsening_the_shed() {
        let mut c = ctrl(60);
        c.step_up = 30;
        // Shed still clamps by the (small) down-step: 35-10=25.
        c.observe(35, true, 60);
        assert_eq!(c.cap_fps(), 25);
        // One recovery streak climbs by the (big) up-step: 25+30=55.
        for _ in 0..6 {
            c.observe(25, false, 60);
        }
        assert_eq!(c.cap_fps(), 55);
        // Ceiling still respected on the next probe.
        for _ in 0..6 {
            c.observe(55, false, 60);
        }
        assert_eq!(c.cap_fps(), 60);
    }

    #[test]
    fn disabled_pins_divisor_1() {
        let mut c = ctrl(60);
        c.enabled = false;
        assert_eq!(c.observe(5, true, 60), 1);
        assert_eq!(c.observe(5, true, 60), 1);
        assert_eq!(c.cap_fps(), 60);
    }

    #[test]
    fn slow_start_recovers_a_deep_clamp_in_five_windows() {
        let mut c = ctrl_ss(60);
        // Hard struggle: managed 5 → clamp floors at min_fps 12.
        c.observe(5, true, 60);
        assert_eq!(c.cap_fps(), 12);
        // Confirmation phase: the first probe is still lazy (recover=3).
        c.observe(12, false, 60);
        c.observe(12, false, 60);
        assert_eq!(c.cap_fps(), 12, "held until the streak confirms");
        // w3: first probe = max(step_up 20, gap 48/2 = 24) → 36, climbing.
        c.observe(12, false, 60);
        assert_eq!(c.cap_fps(), 36);
        // w4: climbing → probe EVERY window: max(20, 24/2) = 20 → 56.
        c.observe(36, false, 60);
        assert_eq!(c.cap_fps(), 56);
        // w5: max(20, 4/2) = 20, capped at capture → 60, climb over.
        c.observe(56, false, 60);
        assert_eq!(c.cap_fps(), 60);
        assert_eq!(c.divisor(), 1);
    }

    #[test]
    fn restruggle_mid_climb_requires_full_confirmation_again() {
        let mut c = ctrl_ss(60);
        c.observe(5, true, 60); // cap 12
        for _ in 0..3 {
            c.observe(12, false, 60);
        }
        assert_eq!(c.cap_fps(), 36, "climb started");
        // The climb overshot the viewer → it struggles again.
        c.observe(30, true, 60);
        assert_eq!(c.cap_fps(), 20); // 30.min(36) - 10
        // Two clean windows do NOT probe — the climb latch was reset and
        // the first probe is lazy again (oscillation guard).
        c.observe(20, false, 60);
        c.observe(20, false, 60);
        assert_eq!(c.cap_fps(), 20);
        c.observe(20, false, 60);
        assert_eq!(c.cap_fps(), 40, "third clean window probes (gap 40/2 = 20)");
    }

    #[test]
    fn pack_unpack_round_trips() {
        assert_eq!(unpack_report(pack_report(30, true)), (30, true));
        assert_eq!(unpack_report(pack_report(58, false)), (58, false));
        // Swap-reset / no-signal decodes to a clean window.
        assert_eq!(unpack_report(0), (0, false));
        // fps saturates at 16 bits, struggle bit survives.
        assert_eq!(unpack_report(pack_report(999_999, true)), (0xFFFF, true));
    }

    #[test]
    fn mid_session_capture_fps_drop_reclamps_cap() {
        let mut c = ctrl(60);
        c.observe(30, true, 60); // cap 20 at 60 fps capture
        // SW auto-cap drops capture to 30; the cap (20) is still valid, divisor
        // recomputes against 30 → ceil(30/20)=2 (15 fps).
        let div = c.observe(20, false, 30);
        assert_eq!(c.divisor(), 2);
        assert_eq!(div, 2);
        assert!(c.cap_fps() <= 30);
    }

    // ── FR-15 — age packing + loop ──────────────────────────────────────

    /// Half of a 100 ms round trip — the shape of the relays this loop runs
    /// on, so the ~60 ms floors below are legal and a 2 ms one is not.
    const ONE_WAY: u16 = 50;

    #[test]
    fn age_pack_roundtrips_and_zero_is_no_report() {
        assert_eq!(unpack_age(pack_age(120, 62, 90)), Some((120, 62, 90)));
        assert_eq!(unpack_age(0), None);
        // A genuine 0 ms input is floored to 1 so it cannot collide with
        // the swap-reset sentinel. An absent round trip stays 0 — the
        // agent reads that as "no bound", not as "a 0 ms path".
        assert_eq!(unpack_age(pack_age(0, 0, 0)), Some((1, 1, 0)));
        assert_eq!(
            unpack_age(pack_age(u16::MAX, u16::MAX, u16::MAX)),
            Some((u16::MAX, u16::MAX, u16::MAX))
        );
    }

    /// FR-59 P3 — the link report round-trips, including a NEGATIVE drift
    /// (the queue drained) and a genuinely-zero window, neither of which
    /// may be confused with the swap-reset sentinel.
    #[test]
    fn link_pack_roundtrips_including_a_draining_queue() {
        assert_eq!(unpack_link(pack_link(395_122, 240)), Some((395_122, 240)));
        assert_eq!(unpack_link(0), None);
        // A window that received nothing and drifted not at all is a real
        // report — it says the stream stopped, which is not silence.
        assert_eq!(unpack_link(pack_link(0, 0)), Some((0, 0)));
        // The queue DRAINED: the sign has to survive the round trip, or a
        // recovering session reads as the worst congestion representable.
        assert_eq!(unpack_link(pack_link(1_000, -350)), Some((1_000, -350)));
        assert_eq!(
            unpack_link(pack_link(u32::MAX, i16::MIN)),
            Some((u32::MAX, i16::MIN))
        );
    }

    /// FR-59 P3 — the loop acts on a SUSTAINED growing queue, and the
    /// arrival-rate ceiling appears only then.
    #[test]
    fn link_loop_needs_two_growing_windows_and_gates_the_ceiling() {
        let mut l = LinkLoop::new();
        // One growing window is a blip — no verdict, and crucially no
        // ceiling, because `rx_bps` alone is not evidence of capacity.
        let v = l.observe(400_000, 250);
        assert!(!v.congested);
        assert_eq!(v.ceiling_bps, None);
        // Two in a row: now we know the agent is overdriving, so what
        // arrived IS what the pipe carries.
        let v = l.observe(400_000, 250);
        assert!(v.congested);
        assert_eq!(v.ceiling_bps, Some(360_000), "90 % of the arrival rate");
        assert_eq!(l.congested_windows(), 1);
        // A flat window breaks the streak immediately (down fast, up slow
        // is the AIMD's job; this loop only reports).
        let v = l.observe(400_000, 10);
        assert!(!v.congested);
        assert_eq!(v.ceiling_bps, None);
        // A DRAINING queue is emphatically not congestion.
        assert!(!l.observe(400_000, -300).congested);
    }

    /// FR-59 P4 — the depth INTEGRAL orders a drain, once, and the pump
    /// handing it back is what re-arms the next one.
    #[test]
    fn a_deep_queue_orders_one_drain_until_it_is_served() {
        let mut l = LinkLoop::new();
        // 300 ms of growth per window: over threshold on the third.
        assert_eq!(l.observe(400_000, 300).drain_for_ms, None);
        assert_eq!(l.observe(400_000, 300).drain_for_ms, None);
        let v = l.observe(400_000, 300);
        assert_eq!(v.drain_for_ms, Some(DRAIN_MAX_MS), "900 ms deep, capped");
        // Depth is SPENT — carrying it forward would order a second drain
        // on the very next window, before the first had any effect.
        assert_eq!(l.drain_stats().0, 1);
        // …and while the first is outstanding, no second is ordered even
        // as the estimate rebuilds past the threshold.
        for _ in 0..5 {
            assert_eq!(l.observe(400_000, 300).drain_for_ms, None);
        }
        assert_eq!(l.drain_stats().0, 1, "still exactly one drain ordered");
        // The pump served it; now the (already deep again) queue may order
        // another.
        l.drain_served();
        assert!(l.observe(400_000, 300).drain_for_ms.is_some());
        assert_eq!(l.drain_stats().0, 2);
    }

    /// A session that recovers on the rate cut alone must never reach the
    /// drain: the integral has to come back DOWN on a draining window, or
    /// every long session would eventually accumulate its way into a
    /// pause it never needed.
    #[test]
    fn a_recovering_queue_never_reaches_the_drain() {
        let mut l = LinkLoop::new();
        for _ in 0..200 {
            l.observe(400_000, 150);
            let v = l.observe(400_000, -150);
            assert_eq!(v.drain_for_ms, None);
        }
        assert_eq!(l.drain_stats().0, 0, "no drain in 400 windows");
        // And the depth estimate is floored at 0 — a link delivering
        // faster than it is fed has no queue, not a negative one.
        for _ in 0..50 {
            l.observe(400_000, -300);
        }
        assert_eq!(l.drain_stats().1, 0, "depth floored at zero");
        // Proof the floor held: one deep window alone cannot now trigger,
        // but it would if the estimate had gone arbitrarily negative and
        // needed climbing back.
        assert_eq!(
            l.observe(400_000, 800).drain_for_ms,
            Some(DRAIN_MAX_MS),
            "800 ms deep, capped at the bound"
        );
    }

    /// The invariant that keeps this loop from ratcheting a healthy
    /// session to nothing: a static desktop sends a few KB/s of keepalive
    /// deltas, so `rx_bps` is tiny — and must NOT become the ceiling while
    /// the queue is flat.
    #[test]
    fn a_quiet_stream_never_becomes_the_ceiling() {
        let mut l = LinkLoop::new();
        for _ in 0..50 {
            let v = l.observe(20_000, 0);
            assert!(!v.congested);
            assert_eq!(v.ceiling_bps, None, "an idle window is not a measurement");
        }
        assert_eq!(l.congested_windows(), 0);
    }

    #[test]
    fn age_loop_needs_two_consecutive_over_windows() {
        let mut l = AgeLoop::new();
        // Establish a ~60 ms floor.
        assert!(!l.observe(62, 60, ONE_WAY));
        assert!(!l.observe(64, 61, ONE_WAY));
        assert_eq!(l.floor_ms(), Some(60));
        // One over-window (140 vs floor 60 = +80 ≥ slack 70) is a blip…
        assert!(!l.observe(140, 62, ONE_WAY));
        // …a clean window resets the streak…
        assert!(!l.observe(65, 61, ONE_WAY));
        assert!(!l.observe(150, 63, ONE_WAY));
        // …and only the SECOND consecutive over-window triggers.
        assert!(l.observe(155, 64, ONE_WAY));
        // Staying over keeps triggering (one MD per window by design).
        assert!(l.observe(160, 64, ONE_WAY));
        // Recovery clears it immediately.
        assert!(!l.observe(70, 61, ONE_WAY));
    }

    #[test]
    fn age_loop_floor_rebaselines_after_a_path_change() {
        let mut l = AgeLoop::new();
        // A path whose true floor is ~220 ms — one-way 210 ms, so the
        // physical bound does not reject its own samples.
        let one_way = 210;
        l.observe(220, 215, one_way);
        for _ in 0..30 {
            l.observe(225, 220, one_way);
        }
        assert_eq!(l.floor_ms(), Some(220));
        // 225 vs a 220 floor is within slack, and well under 3× one-way.
        assert!(!l.observe(225, 220, one_way));
    }

    #[test]
    fn age_loop_within_slack_never_triggers() {
        let mut l = AgeLoop::new();
        l.observe(60, 58, ONE_WAY);
        for _ in 0..50 {
            // +65 ms of climb stays under the 70 ms slack, and 123 is under
            // the absolute 250 ms over-queue rule.
            assert!(!l.observe(123, 58, ONE_WAY));
        }
    }

    // ── P2 — the floor has to be physically possible ────────────────────

    /// The bug this closes: the `rc:clock` probe rides the congested
    /// channel, skews low, and the sub-physical age became the floor —
    /// after which a healthy window read as a huge excess and the loop cut
    /// quality on a fine path. Field 2026-08-27: 1–15 ms floors on relays
    /// whose round trip was 86–210 ms.
    #[test]
    fn a_sub_physical_floor_sample_is_rejected_not_learned() {
        let mut l = AgeLoop::new();
        // Legitimate floor first.
        l.observe(62, 60, ONE_WAY);
        assert_eq!(l.floor_ms(), Some(60));
        // Now the clock-skewed nonsense: a 2 ms floor on a 100 ms path.
        assert!(!l.observe(64, 2, ONE_WAY));
        assert_eq!(l.floor_ms(), Some(60), "the impossible sample was learned");
        assert_eq!(l.implausible_samples(), 1);
        // And a healthy window is still healthy — with the 2 ms floor it
        // would have read as +62 and started a trigger streak.
        assert!(!l.observe(70, 61, ONE_WAY));
        assert!(!l.observe(70, 61, ONE_WAY));
    }

    /// The other direction: a session congested from its FIRST window never
    /// sees a good sample, so `min(ring)` learns the congestion as the
    /// floor and excess can never grow. Field: a learned floor of 1111 ms
    /// against window averages of 1 134–13 485 ms, loop silent.
    #[test]
    fn a_session_congested_from_the_start_still_fires() {
        let mut l = AgeLoop::new();
        // Every sample is terrible, so the floor is terrible too.
        assert!(!l.observe(1134, 1111, ONE_WAY));
        // Second consecutive over-window trips it on the absolute rule
        // (1134 ≫ 3× the 50 ms one-way), despite zero excess over floor.
        assert!(l.observe(13485, 1111, ONE_WAY));
    }

    /// A viewer that reports no round trip (older web, or before the first
    /// probe lands) must not have its floors rejected — the bound goes
    /// inert and the loop behaves exactly as it did before P2.
    #[test]
    fn a_missing_round_trip_leaves_the_bound_inert() {
        let mut l = AgeLoop::new();
        assert!(!l.observe(62, 2, 0));
        assert_eq!(l.floor_ms(), Some(2), "nothing to reject against");
        assert_eq!(l.implausible_samples(), 0);
    }
}
