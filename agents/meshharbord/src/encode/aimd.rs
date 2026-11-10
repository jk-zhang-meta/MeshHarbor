// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Transport-agnostic AIMD bitrate controller shared by the DataChannel
//! video pumps (VP9-444 libvpx + FFmpeg HEVC/vp9_qsv).
//!
//! # Why this exists
//!
//! The DC pumps have no REMB/TWCC signal (that's an RTP-track thing), so
//! they substitute an AIMD (additive-increase / multiplicative-decrease)
//! controller that watches transport backpressure and drives
//! `VideoEncoder::set_bitrate`. Pre-this-module the VP9-444 pump inlined
//! that logic and drove it off `dc.buffered_amount()` — which on webrtc-rs
//! is the WRONG signal: the dedicated send task's `dc.send().await` blocks
//! under SCTP flow control, so bytes never pile up in the SCTP buffer and
//! `buffered_amount()` stays low even while the link is saturated. Worse,
//! the AIMD ran AFTER the pump's top-of-loop capacity gate, so under
//! sustained congestion (the send channel chronically full) the loop
//! `continue`d at the gate and the multiplicative-decrease NEVER ran —
//! the encoder stayed pinned at its 12.4 Mbps target while the DC drained
//! ~7 Mbps, collapsing to ~2 fps (field: DEVBOX-WSL, 2026-07-12,
//! 69k backpressure skips with `target_bps` never dropping).
//!
//! # The real signal: send-channel occupancy
//!
//! Both pumps feed a bounded `tokio::mpsc::channel(depth)` drained by a
//! single send task. When the link can't keep up the channel fills; the
//! pump's capacity gate skips frames. THAT gate is the true congestion
//! signal. This controller is driven from there:
//!
//! - **Multiplicative decrease** (×0.85, rate-limited to one per 500 ms):
//!   the channel is FULL (`capacity() == 0`). Asymmetric + instantaneous
//!   so we back off fast the moment we saturate.
//! - **Additive increase** (a small fixed step, NOT multiplicative): the
//!   channel has NOT been full for `AI_SETTLE` (5 s) AND a low-occupancy
//!   EWMA — cautious, so we only climb when the link has demonstrably
//!   drained. Additive so we converge just UNDER the link capacity with a
//!   small ripple rather than overshooting it every climb (a multiplicative
//!   increase sawtooths, showing up as a periodic pause+blur on a
//!   capacity-limited relay). The EWMA + the no-full-in-5s gate together
//!   tame the coarse signal on a shallow (depth-2) relay channel where
//!   occupancy flips 0↔full.
//!
//! The controller is **pure** — no ffmpeg / webrtc / tokio types, every
//! method takes an explicit `now: Instant` — so it unit-tests on the
//! default feature build (the FFmpeg pump is CI-only on the dev box) and
//! the MD-under-sustained-full regression test guards the starvation bug
//! directly.
//!
//! # Two `set_bitrate` semantics
//!
//! The controller emits ONE `desired_bps`. libvpx interprets it as a hard
//! CBR target; the FFmpeg HW encoders interpret it as a `maxrate` ceiling
//! (they run constant-quality with maxrate as the burst cap). Same number,
//! different meaning per pump — don't read the heartbeat value as wire rate.

use std::time::{Duration, Instant};

/// Multiplicative-decrease factor: ×0.85 on a full channel. Gentler than a
/// ×0.8 so the quality dip on each backoff is less eye-catching.
const MD_NUM: u32 = 85;
const MD_DEN: u32 = 100;
/// Additive-increase step per settle interval = `max(ceiling / AI_STEP_DIVISOR,
/// AI_MIN_STEP_BPS)`. ADDITIVE (not the old multiplicative ×1.1) so the
/// controller CONVERGES just under the link capacity with a small ripple
/// instead of overshooting it by a fixed percentage on every climb — the
/// sawtooth that showed up as a periodic pause+blur on a capacity-limited
/// relay. The step scales with the ceiling so recovery isn't glacial at high
/// (LAN) bitrates.
const AI_STEP_DIVISOR: u32 = 16;
const AI_MIN_STEP_BPS: u32 = 150_000;
/// FR-59 P8 — the additive step while `desired` sits BELOW the nominal floor
/// (`encode::MIN_BITRATE_BPS`), which only happens once the FR-59 floor
/// relief has let the controller follow a measured slow pipe:
/// `max(desired / AI_SLOW_BAND_DIVISOR, AI_SLOW_MIN_STEP_BPS)`. The nominal
/// step above is sized for the 2–9 Mbps band — at 350 kbps a +150 kbps step
/// is +43 %, a guaranteed overshoot on the very pipe that put the controller
/// there, and on a rebuild-bound HW encoder every such step is also an IDR
/// (~1 s of a 300 kbps link). +12.5 % per settle crosses a ladder rung every
/// 2–3 steps instead of on every one.
const AI_SLOW_BAND_DIVISOR: u32 = 8;
const AI_SLOW_MIN_STEP_BPS: u32 = 25_000;
/// At most one multiplicative decrease per this interval — avoids
/// free-falling the bitrate on a transient burst.
const MD_MIN_INTERVAL: Duration = Duration::from_millis(500);
/// The channel must be non-full (and occupancy low) for this long before
/// an additive increase — avoids ratcheting up between congestion events.
const AI_SETTLE: Duration = Duration::from_secs(5);
/// EWMA smoothing factor for the occupancy fraction (per `observe` call).
const OCC_ALPHA: f32 = 0.1;
/// Additive increase is gated on the smoothed occupancy being under this
/// fraction of the channel depth (belt-and-suspenders with the 5 s
/// no-full window — a depth-2 relay flipping 0↔full averages ~0.5 and is
/// correctly held back from climbing).
const AI_OCC_THRESHOLD: f32 = 0.25;

/// AIMD bitrate controller. See the module docs for the signal model.
///
/// Construct once per pump session with the initial target, the hard
/// floor (`encode::MIN_BITRATE_BPS`), the ceiling (quality/relay cap), and
/// the send-channel depth. Call `observe` at the capacity gate every loop
/// iteration, `set_ceiling` each frame with the current quality/relay cap,
/// and `take_pending` to learn when to actually call `set_bitrate`.
#[derive(Debug)]
pub struct AimdController {
    /// The bitrate the controller currently wants (bps).
    desired_bps: u32,
    /// Hard floor — never decrease below this (legibility minimum).
    floor_bps: u32,
    /// Ceiling — never increase above this (quality preference / relay cap).
    ceiling_bps: u32,
    /// The last value handed out by `take_pending`; `desired != this`
    /// means a `set_bitrate` is pending. Starts at 0 so the FIRST
    /// `take_pending` emits the initial target (the pump applies it once).
    last_applied_bps: u32,
    /// Send-channel depth, for the occupancy fraction.
    depth: u32,
    /// Smoothed occupancy fraction in [0, 1].
    occ_avg: f32,
    /// Last time a decrease OR increase was applied (rate-limits both).
    last_event_at: Instant,
    /// Last time the channel was observed full (or a buffer overflow was
    /// noted). AI is blocked until this is `AI_SETTLE` in the past.
    last_full_at: Instant,
    /// FR-35 — count of applied decreases, so the governor can tell the
    /// ceiling learner "the pipe pushed back" without reading the target.
    decreases: u32,
}

impl AimdController {
    /// `initial_bps` is the session's starting target (typically ==
    /// `ceiling_bps`). `depth` is the bounded send-channel depth.
    pub fn new(
        initial_bps: u32,
        floor_bps: u32,
        ceiling_bps: u32,
        depth: u32,
        now: Instant,
    ) -> Self {
        let desired = initial_bps.clamp(floor_bps, ceiling_bps.max(floor_bps));
        Self {
            desired_bps: desired,
            floor_bps,
            ceiling_bps: ceiling_bps.max(floor_bps),
            last_applied_bps: 0,
            depth: depth.max(1),
            occ_avg: 0.0,
            // Seed both timers in the past so the initial target applies
            // immediately and the settle window is measured from now.
            last_event_at: now,
            last_full_at: now,
            decreases: 0,
        }
    }

    /// Feed one send-channel occupancy sample. `occupied` is
    /// `depth - capacity()`, `full` is `capacity() == 0`. Call at the
    /// capacity gate on EVERY loop iteration (including the skip path) so
    /// the decrease runs DURING congestion — this is the fix for the
    /// starvation bug. Returns the (possibly unchanged) desired bitrate.
    pub fn observe(&mut self, occupied: u32, full: bool, now: Instant) -> u32 {
        let frac = (occupied.min(self.depth) as f32) / (self.depth as f32);
        self.occ_avg += OCC_ALPHA * (frac - self.occ_avg);

        if full {
            self.last_full_at = now;
            self.apply_md(now);
        } else if self.occ_avg < AI_OCC_THRESHOLD
            && now.duration_since(self.last_full_at) >= AI_SETTLE
            && now.duration_since(self.last_event_at) >= AI_SETTLE
        {
            self.apply_ai(now);
        }
        self.desired_bps
    }

    /// Secondary decrease trigger: the VP9 pump also polls
    /// `dc.buffered_amount()`; if it ever DOES spike over the high
    /// watermark, treat it as congestion (same rate-limited MD as a full
    /// channel). Harmless on the FFmpeg pump, which doesn't call it.
    pub fn note_buffer_overflow(&mut self, now: Instant) {
        self.last_full_at = now;
        self.apply_md(now);
    }

    /// Update the ceiling (quality preference × relay clamp), pushed each
    /// frame by the pump. Lowering it clamps `desired` down immediately;
    /// raising it just lets AI climb toward the new ceiling.
    pub fn set_ceiling(&mut self, ceiling_bps: u32) {
        self.ceiling_bps = ceiling_bps.max(self.floor_bps);
        if self.desired_bps > self.ceiling_bps {
            self.desired_bps = self.ceiling_bps;
        }
    }

    /// Update the floor (the area-scaled legibility minimum), pushed each
    /// frame by the pump alongside the ceiling. Capped at the CURRENT
    /// ceiling so a floor computed for a big direct session can never
    /// invert a lower relay clamp (which would pin `desired` at the
    /// ceiling and disable the multiplicative decrease). Raising it
    /// clamps `desired` up immediately — a rate-limited-enough event
    /// (dims change / transport flip) that `take_pending` emitting a
    /// `set_bitrate` for it is fine.
    pub fn set_floor(&mut self, floor_bps: u32) {
        self.floor_bps = floor_bps.max(1).min(self.ceiling_bps);
        if self.desired_bps < self.floor_bps {
            self.desired_bps = self.floor_bps;
        }
    }

    /// If the desired bitrate has moved since the last apply, return it
    /// (and record it) so the pump calls `enc.set_bitrate`. The controller
    /// only moves `desired` on rate-limited MD/AI/ceiling events, so this
    /// never thrashes — no extra hysteresis needed.
    pub fn take_pending(&mut self) -> Option<u32> {
        if self.desired_bps != self.last_applied_bps {
            self.last_applied_bps = self.desired_bps;
            Some(self.desired_bps)
        } else {
            None
        }
    }

    /// Force the next `take_pending` to re-emit the current desired bitrate
    /// — call after an encoder REBUILD (resolution change), which resets
    /// the encoder's rate control to its constructor value.
    pub fn force_reapply(&mut self) {
        self.last_applied_bps = 0;
    }

    /// Current desired bitrate (for heartbeat logging).
    pub fn desired(&self) -> u32 {
        self.desired_bps
    }

    fn apply_md(&mut self, now: Instant) {
        if now.duration_since(self.last_event_at) < MD_MIN_INTERVAL {
            return;
        }
        let next = (self.desired_bps / MD_DEN)
            .saturating_mul(MD_NUM)
            .max(self.floor_bps);
        if next < self.desired_bps {
            self.desired_bps = next;
            self.last_event_at = now;
            self.decreases += 1;
        }
    }

    /// FR-35 — a HARD stall (a send blocked ≥ 1 s): cut to ×0.5 at once,
    /// bypassing the ×0.85 ladder and its 500 ms spacing. The P0 field
    /// measurement met a 7.9 s stall with three ×0.85 steps over four
    /// seconds; the pipe had already collapsed by the first one.
    pub fn apply_hard_md(&mut self, now: Instant) {
        let next = (self.desired_bps / 2).max(self.floor_bps);
        self.last_full_at = now;
        if next < self.desired_bps {
            self.desired_bps = next;
            self.last_event_at = now;
            self.decreases += 1;
        }
    }

    /// FR-35 — decreases applied so far (monotonic).
    pub fn decreases(&self) -> u32 {
        self.decreases
    }

    fn apply_ai(&mut self, now: Instant) {
        let step = if self.desired_bps < super::MIN_BITRATE_BPS {
            // FR-59 P8 — see `AI_SLOW_BAND_DIVISOR`.
            (self.desired_bps / AI_SLOW_BAND_DIVISOR).max(AI_SLOW_MIN_STEP_BPS)
        } else {
            (self.ceiling_bps / AI_STEP_DIVISOR).max(AI_MIN_STEP_BPS)
        };
        let next = self.desired_bps.saturating_add(step).min(self.ceiling_bps);
        if next > self.desired_bps {
            self.desired_bps = next;
        }
        // Advance the event clock even if we were already at the ceiling,
        // so we don't re-evaluate AI every frame once settled.
        self.last_event_at = now;
    }
}

/// Bitrate ladder for [`coarsen_bitrate`]. ~1.33–1.5× spacing across the DC
/// pump's operating band, extending past the 12 Mbps FFmpeg maxrate cap so a
/// raised ceiling (direct/LAN, high resolution) still has rungs to climb.
///
/// FR-59 P8 — it also extends BELOW `encode::MIN_BITRATE_BPS`, down to the
/// lowest floor the `slow_link_min_bitrate` config allows. The ladder used to
/// bottom out at 1.5 M, which made it a second copy of the floor pin P1
/// removed from the AIMD: every relieved target between 200 k and 1.4 M
/// coarsened to the rung the encoder was already on, and `set_bitrate`
/// returned without touching it. Field 2026-09-02 (CORPLAP-1 over a ~300 kbps
/// relay): 4½ minutes of `target_bps=200000` in the heartbeat while every
/// frame on the wire was exactly 12 513 bytes — 1.5 M ÷ 15 fps ÷ 8.
const BITRATE_LADDER_BPS: &[u32] = &[
    100_000, 150_000, 200_000, 300_000, 400_000, 550_000, 750_000, 1_000_000, 1_500_000, 2_000_000,
    3_000_000, 4_500_000, 6_000_000, 8_000_000, 12_000_000, 16_000_000, 20_000_000, 25_000_000,
];

/// Snap a continuous AIMD bitrate to the nearest [`BITRATE_LADDER_BPS`] rung.
///
/// Only the FFmpeg HW pump uses this. Each maxrate change there is expensive:
/// on NVENC it forces an IDR (FFmpeg's `reconfig_encoder` sets `resetEncoder=1`
/// / `forceIDR=1`), and on QSV/AMF it's a full encoder rebuild — both are far
/// too heavy to run on every fine AIMD step. Coarsening to a rung means a
/// typical ×0.85 multiplicative-decrease step (−15 %) usually lands on the SAME
/// rung (no reconfigure) and only crosses a rung every ~2–3 steps, bounding the
/// reconfigure/IDR rate. The libvpx VP9-444 pump does NOT use this — libvpx
/// takes a hard bitrate target cheaply, so it drives the raw AIMD value.
///
/// Nearest (not floor) so we track the controller faithfully instead of always
/// under-shooting; the shed-on-full send gate absorbs the sub-rung slack. Pure
/// and always-compiled, so it unit-tests on the default `cargo test --lib` even
/// though the FFmpeg encoder that consumes it is CI-only on the dev box.
pub fn coarsen_bitrate(bps: u32) -> u32 {
    let first = BITRATE_LADDER_BPS[0];
    let last = BITRATE_LADDER_BPS[BITRATE_LADDER_BPS.len() - 1];
    if bps <= first {
        return first;
    }
    if bps >= last {
        return last;
    }
    let mut best = first;
    let mut best_dist = bps.abs_diff(best);
    for &rung in &BITRATE_LADDER_BPS[1..] {
        let d = bps.abs_diff(rung);
        // Strictly-smaller so ties resolve to the LOWER rung (we iterate
        // ascending) — a mild conservative bias on a congested link.
        if d < best_dist {
            best = rung;
            best_dist = d;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: u32 = 1_500_000;
    const CEIL: u32 = 12_000_000;

    fn ctrl(initial: u32, depth: u32, t0: Instant) -> AimdController {
        AimdController::new(initial, FLOOR, CEIL, depth, t0)
    }

    // (1) THE regression test for the starvation bug: sustained-full must
    // step the bitrate DOWN ×0.8 per 500 ms and floor at MIN_BITRATE.
    #[test]
    fn md_runs_under_sustained_full() {
        let t0 = Instant::now();
        let mut c = ctrl(12_000_000, 8, t0);
        assert_eq!(c.take_pending(), Some(12_000_000)); // initial applied

        // Hammer the gate as the pump would (every 2 ms), full each time.
        let mut t = t0;
        let mut last = 12_000_000u32;
        for _ in 0..20 {
            // advance ~600 ms so each step clears MD_MIN_INTERVAL
            t += Duration::from_millis(600);
            c.observe(8, true, t);
            if let Some(v) = c.take_pending() {
                assert!(v < last, "each MD step must decrease: {v} !< {last}");
                last = v;
            }
        }
        // Converges to the floor, never below.
        assert_eq!(c.desired(), FLOOR);
        assert_eq!(last, FLOOR);
    }

    // (3) MD is rate-limited: two fulls 100 ms apart → a single decrease.
    #[test]
    fn md_is_rate_limited() {
        let t0 = Instant::now();
        let mut c = ctrl(12_000_000, 8, t0);
        c.take_pending();

        let t1 = t0 + Duration::from_millis(600);
        c.observe(8, true, t1);
        let after_first = c.desired();
        assert!(after_first < 12_000_000);

        // 100 ms later, still full — must NOT decrease again.
        let t2 = t1 + Duration::from_millis(100);
        c.observe(8, true, t2);
        assert_eq!(
            c.desired(),
            after_first,
            "MD must be rate-limited to 500 ms"
        );
    }

    // (2) AI only after a 5 s settle, single ×1.1 step, never over ceiling.
    #[test]
    fn ai_climbs_after_settle() {
        let t0 = Instant::now();
        let mut c = ctrl(3_000_000, 8, t0);
        c.take_pending();

        // Not full, but before the settle window → no increase.
        let t1 = t0 + Duration::from_secs(4);
        c.observe(0, false, t1);
        assert_eq!(c.desired(), 3_000_000, "AI blocked before 5 s settle");

        // Past the settle window, occupancy long-since drained → one ×1.1.
        // Feed several low samples so the EWMA drops under threshold.
        let mut t = t0;
        for _ in 0..40 {
            t += Duration::from_millis(200);
            c.observe(0, false, t);
        }
        // t is now ~8 s in; exactly one additive increase should have fired
        // (the next is gated 5 s after the first, beyond the loop).
        let d = c.desired();
        let step = (CEIL / AI_STEP_DIVISOR).max(AI_MIN_STEP_BPS);
        assert!(d > 3_000_000, "AI should climb after settle: {d}");
        assert_eq!(d, 3_000_000 + step, "one additive AI step: {d}");
        assert!(d <= CEIL);
    }

    // (4) Oscillation guard: AI is blocked for 5 s AFTER an MD event.
    #[test]
    fn ai_blocked_for_5s_after_md() {
        let t0 = Instant::now();
        let mut c = ctrl(6_000_000, 8, t0);
        c.take_pending();

        // Trigger an MD.
        let t_md = t0 + Duration::from_millis(600);
        c.observe(8, true, t_md);
        let after_md = c.desired();
        assert!(after_md < 6_000_000);

        // 4 s after the MD, channel empty → still blocked (needs 5 s).
        let t_early = t_md + Duration::from_secs(4);
        // prime EWMA low
        let mut t = t_md;
        while t < t_early {
            t += Duration::from_millis(200);
            c.observe(0, false, t);
        }
        assert_eq!(c.desired(), after_md, "AI must stay blocked 5 s after MD");
    }

    // (5) take_pending hysteresis: no change → None; change → Some once.
    /// FR-35 — a hard stall halves the target at once and counts as a
    /// decrease; the ordinary ladder still moves ×0.85.
    #[test]
    fn hard_md_halves_at_once_and_counts() {
        let t0 = Instant::now();
        let mut c = ctrl(12_000_000, 4, t0);
        assert_eq!(c.take_pending(), Some(12_000_000));
        assert_eq!(c.decreases(), 0);
        c.apply_hard_md(t0 + Duration::from_millis(100));
        assert_eq!(c.desired(), 6_000_000);
        assert_eq!(c.decreases(), 1);
        // Never below the floor.
        let mut f = ctrl(FLOOR + 1, 4, t0);
        f.take_pending();
        f.apply_hard_md(t0 + Duration::from_millis(100));
        assert_eq!(f.desired(), FLOOR);
    }

    #[test]
    fn take_pending_only_on_change() {
        let t0 = Instant::now();
        let mut c = ctrl(5_000_000, 8, t0);
        assert_eq!(c.take_pending(), Some(5_000_000));
        assert_eq!(c.take_pending(), None, "no change → None");

        c.observe(0, false, t0 + Duration::from_millis(10)); // no event
        assert_eq!(c.take_pending(), None);
    }

    // (6b) Floor: raising it pulls desired up at once, but it can never
    // exceed the live ceiling (a relay clamp must keep its MD room).
    #[test]
    fn floor_raises_desired_and_respects_ceiling() {
        let t0 = Instant::now();
        let mut c = ctrl(12_000_000, 8, t0);
        c.take_pending();

        // Walk desired down to the 1.5 M construction floor.
        let mut t = t0;
        for _ in 0..40 {
            t += Duration::from_millis(600);
            c.observe(8, true, t);
        }
        assert_eq!(c.desired(), FLOOR);

        // An area-scaled floor lifts it immediately and emits a pending
        // apply.
        c.set_floor(3_000_000);
        assert_eq!(c.desired(), 3_000_000);
        assert_eq!(c.take_pending(), Some(3_000_000));

        // Transport flip to relay, in the governor's call order (floor
        // first, then ceiling): the flat floor returns and the relay
        // clamp lands in the same tick.
        c.set_floor(1_500_000);
        c.set_ceiling(2_000_000);
        assert_eq!(c.desired(), 2_000_000);

        // A floor request above the live ceiling is capped AT the
        // ceiling — never past it (no relay-clamp inversion).
        c.set_floor(5_000_000);
        assert_eq!(c.desired(), 2_000_000);
        assert!(c.desired() <= 2_000_000);
    }

    // (6) Ceiling clamp: lowering the ceiling pulls desired down at once.
    #[test]
    fn ceiling_clamps_desired_down() {
        let t0 = Instant::now();
        let mut c = ctrl(12_000_000, 8, t0);
        c.take_pending();

        c.set_ceiling(3_000_000); // relay clamp kicks in
        assert_eq!(c.desired(), 3_000_000);
        assert_eq!(c.take_pending(), Some(3_000_000));

        // Raising the ceiling does NOT jump desired — AI must climb.
        c.set_ceiling(12_000_000);
        assert_eq!(c.desired(), 3_000_000);
        assert_eq!(c.take_pending(), None);
    }

    // (7) Depth-2 anti-oscillation: alternating full/empty keeps occ_avg
    // near the middle and last_full_at fresh → AI never fires.
    #[test]
    fn alternating_full_empty_holds_ai_back() {
        let t0 = Instant::now();
        let mut c = ctrl(3_000_000, 2, t0);
        c.take_pending();
        // First full triggers an MD; capture the post-MD level, then keep
        // alternating and assert AI never climbs back above it.
        let mut t = t0;
        let mut floor_seen = 3_000_000u32;
        for i in 0..200 {
            t += Duration::from_millis(200); // 40 s total, well past settle
            let full = i % 2 == 0;
            c.observe(if full { 2 } else { 0 }, full, t);
            floor_seen = floor_seen.min(c.desired());
        }
        // A full event lands every other sample → last_full_at is never
        // 5 s stale → AI is permanently blocked, so desired only ever
        // decreased (or held), never climbed back up.
        assert_eq!(
            c.desired(),
            floor_seen,
            "AI must not climb while still hitting full"
        );
        assert!(
            c.desired() < 3_000_000,
            "sustained fulls should have decreased it"
        );
    }

    // (8) note_buffer_overflow is a secondary, rate-limited MD.
    #[test]
    fn buffer_overflow_is_secondary_md() {
        let t0 = Instant::now();
        let mut c = ctrl(8_000_000, 8, t0);
        c.take_pending();

        c.note_buffer_overflow(t0 + Duration::from_millis(600));
        let d = c.desired();
        assert!(d < 8_000_000, "buffer overflow should decrease bitrate");
        // ...and it blocks AI for 5 s just like a full channel.
        let mut t = t0 + Duration::from_millis(600);
        for _ in 0..20 {
            t += Duration::from_millis(200);
            c.observe(0, false, t);
        }
        // ~4.6 s of settle since the overflow → still blocked.
        assert_eq!(c.desired(), d, "AI blocked <5 s after a buffer overflow");
    }

    // (9) coarsen_bitrate: exact rungs are fixed points; out-of-range clamps.
    #[test]
    fn coarsen_clamps_and_fixes_rungs() {
        assert_eq!(
            coarsen_bitrate(50_000),
            100_000,
            "below the bottom rung → bottom rung"
        );
        assert_eq!(
            coarsen_bitrate(30_000_000),
            25_000_000,
            "above top → top rung"
        );
        for &rung in BITRATE_LADDER_BPS {
            assert_eq!(
                coarsen_bitrate(rung),
                rung,
                "exact rung {rung} is a fixed point"
            );
        }
    }

    // (10) coarsen_bitrate snaps to the NEAREST rung (ties → lower).
    #[test]
    fn coarsen_snaps_to_nearest_rung() {
        assert_eq!(
            coarsen_bitrate(3_400_000),
            3_000_000,
            "3.4M nearer 3M than 4.5M"
        );
        assert_eq!(
            coarsen_bitrate(4_080_000),
            4_500_000,
            "4.08M nearer 4.5M than 3M"
        );
        assert_eq!(
            coarsen_bitrate(5_000_000),
            4_500_000,
            "5.0M nearer 4.5M than 6M"
        );
        assert_eq!(
            coarsen_bitrate(5_300_000),
            6_000_000,
            "5.3M nearer 6M than 4.5M"
        );
        // Exact midpoint 3.75M (between 3M and 4.5M) → the lower rung (tie bias).
        assert_eq!(
            coarsen_bitrate(3_750_000),
            3_000_000,
            "midpoint ties to the lower rung"
        );
    }

    // (11) coarsen_bitrate is monotonic non-decreasing across the band.
    #[test]
    fn coarsen_is_monotonic() {
        let mut prev = 0u32;
        for bps in (50_000..=26_000_000).step_by(50_000) {
            let c = coarsen_bitrate(bps);
            assert!(
                c >= prev,
                "coarsen must be non-decreasing: {c} < {prev} at {bps}"
            );
            prev = c;
        }
    }

    // (12) FR-59 P8 — the ladder reaches the slow-link band. Field
    // 2026-09-02: it bottomed at 1.5 M, so every relieved target between
    // 200 k and 1.1 M coarsened to the rung the encoder already ran at and
    // `set_bitrate` returned without touching it — 4½ minutes of
    // `target_bps=200000` with 12 513-byte frames (= 1.5 M ÷ 15 fps ÷ 8).
    #[test]
    fn ladder_reaches_the_slow_link_band() {
        assert_eq!(coarsen_bitrate(387_500), 400_000);
        assert_eq!(coarsen_bitrate(254_930), 300_000);
        assert_eq!(coarsen_bitrate(200_000), 200_000);
        assert_ne!(
            coarsen_bitrate(200_000),
            coarsen_bitrate(super::super::MIN_BITRATE_BPS),
            "a relieved target must land on a different rung than the nominal floor"
        );
        // The bottom rung is at or below the lowest floor the config
        // permits (`slow_link_min_bitrate_bps` clamps at 50 k), so no
        // relieved floor can ever coarsen UP past itself by more than the
        // ladder's own spacing.
        assert!(BITRATE_LADDER_BPS[0] <= 100_000);
    }

    // (13) FR-59 P8 — below the nominal floor the additive step is relative
    // to `desired`, not to the (nominal) ceiling; above it, unchanged.
    #[test]
    fn ai_step_is_relative_below_the_nominal_floor() {
        let t0 = Instant::now();
        let mut slow = AimdController::new(348_000, 200_000, 2_550_000, 8, t0);
        slow.take_pending();
        let mut fast =
            AimdController::new(2_000_000, super::super::MIN_BITRATE_BPS, 2_550_000, 8, t0);
        fast.take_pending();
        let mut t = t0;
        for _ in 0..30 {
            t += Duration::from_millis(200); // 6 s of an idle channel → one AI
            slow.observe(0, false, t);
            fast.observe(0, false, t);
        }
        assert_eq!(
            slow.desired(),
            348_000 + 348_000 / AI_SLOW_BAND_DIVISOR,
            "+12.5 % in the slow band, not +150 k"
        );
        assert_eq!(
            fast.desired(),
            2_000_000 + 2_550_000 / AI_STEP_DIVISOR,
            "the nominal step above the floor is unchanged"
        );
    }
}
