// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Encode-pressure controller — auto-reduces the encoder's bitrate ceiling
//! when the *encoder itself* can't keep up, so a weak sender GPU stops
//! saturating and the periodic freeze goes away.
//!
//! Field root cause (WINHOST-A Iris Xe, `hevc_qsv`, 1920×1200@60): the shared
//! iGPU does DXGI capture AND HEVC encode, and under sustained window-drag
//! motion `avg_encode_ms` climbs from ~11 ms to 40-194 ms — the 194 ms
//! windows are the 1-2 s hangs. The operator's manual `FFMPEG_FPS=30` fixed
//! it: that halved the maxrate (`ffmpeg_maxrate_bps` = w×h×fps×0.07), so the
//! encoder emits smaller frames → ~3× faster encode → steady 11 ms, no
//! spikes. This controller does that automatically and per-session: it
//! watches the encode time and pulls a maxrate SCALE FACTOR down when the
//! encoder saturates, back up when it recovers — so a fast host / static
//! screen keeps full quality and only a struggling encoder gets throttled.
//!
//! Bitrate-first (not fps/resolution): lowering the ceiling is the least
//! visible lever (slightly more compression under motion, cleans up when
//! static — no framerate drop, no resize) and the field proved it's what
//! actually cut the encode time. fps / resolution tiers can layer on later
//! if the ceiling floor isn't enough.
//!
//! Pure (no ffmpeg/webrtc types) → unit-tested on the default `cargo test
//! --lib`. The pump multiplies its per-resolution maxrate ceiling by
//! `factor()` before feeding the AIMD, which then tracks the link down from
//! the reduced ceiling as usual (so the effective rate is the min of the
//! encode-limited and network-limited ceilings).

/// Never throttle the ceiling below this fraction of the resolution maxrate —
/// below ~40% the picture degrades more than the freeze it prevents.
pub const FACTOR_FLOOR: f32 = 0.4;

use tunnel_core::env::node_env;

fn env_f32(suffix: &str, default: f32) -> f32 {
    node_env(suffix)
        .and_then(|v| v.trim().parse::<f32>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(default)
}

pub struct EncodePressure {
    ewma_ms: f32,
    factor: f32,
    high_ms: f32,
    low_ms: f32,
    enabled: bool,
}

impl EncodePressure {
    pub fn new() -> Self {
        Self {
            ewma_ms: 0.0,
            // Saturate above `high_ms` (encoder can't hold ~40 fps), recover
            // below `low_ms`. Env-tunable so the field trigger can move
            // without a rebuild; kill switch pins the factor at 1.0.
            high_ms: env_f32("ENCODE_PRESSURE_HIGH_MS", 25.0),
            low_ms: env_f32("ENCODE_PRESSURE_LOW_MS", 15.0),
            factor: 1.0,
            enabled: !matches!(
                node_env("ENCODE_PRESSURE").as_deref(),
                Some("0") | Some("false")
            ),
        }
    }

    /// Step once per heartbeat window with that window's average encode time
    /// (ms). Returns the maxrate scale factor in `[FACTOR_FLOOR, 1.0]`.
    /// Hysteretic: a dead zone between `low_ms` and `high_ms` holds the
    /// factor steady so a session hovering near the threshold doesn't
    /// oscillate. Multiplicative down (fast relief) / up (lazy recovery).
    pub fn observe(&mut self, avg_encode_ms: f32) -> f32 {
        if !self.enabled {
            return 1.0;
        }
        const ALPHA: f32 = 0.4;
        // Seed on the first sample so we don't ramp slowly up from 0.
        if self.ewma_ms <= 0.0 {
            self.ewma_ms = avg_encode_ms;
        } else {
            self.ewma_ms = (1.0 - ALPHA) * self.ewma_ms + ALPHA * avg_encode_ms;
        }
        if self.ewma_ms > self.high_ms {
            self.factor = (self.factor * 0.8).max(FACTOR_FLOOR);
        } else if self.ewma_ms < self.low_ms {
            self.factor = (self.factor * 1.15).min(1.0);
        }
        self.factor
    }

    pub fn factor(&self) -> f32 {
        self.factor
    }

    pub fn ewma_ms(&self) -> f32 {
        self.ewma_ms
    }

    /// Classify the current pressure for the resolution tier tracker
    /// (shelf item 2026-07-27, "encode-bound auto-downscale"). Computed here
    /// because the EWMA + thresholds live here:
    ///
    /// * `Down` — the bitrate lever is EXHAUSTED (factor at the floor) and
    ///   the encoder is still saturated → shrinking pixels is the only lever
    ///   left.
    /// * `Up` — the encoder has DEEP headroom: factor fully recovered and
    ///   the EWMA is low enough that ~2.5× the work (one tier up ≈ 1.8-2.3×
    ///   the pixels) would still sit under `high_ms`. The predictive margin
    ///   is what prevents the down↔up ping-pong: "recovered at 1080p" is not
    ///   enough, it must be *fast* at 1080p.
    /// * `Hold` — anything in between.
    pub fn tier_signal(&self) -> TierSignal {
        const UP_HEADROOM: f32 = 2.5;
        if !self.enabled || self.ewma_ms <= 0.0 {
            return TierSignal::Hold;
        }
        if self.factor <= FACTOR_FLOOR + 1e-3 && self.ewma_ms > self.high_ms {
            TierSignal::Down
        } else if self.factor >= 1.0 - 1e-3 && self.ewma_ms * UP_HEADROOM < self.high_ms {
            TierSignal::Up
        } else {
            TierSignal::Hold
        }
    }
}

/// Pressure classification for [`DownscaleTier`]. See
/// [`EncodePressure::tier_signal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierSignal {
    Down,
    Up,
    Hold,
}

/// Floor for the paced rate — below ~15 fps the cure is a resolution tier,
/// not more pacing (and the viewer-rate floor uses the same figure).
pub const FPS_PACE_MIN: u32 = 15;

/// P5 (FR-1, 2026-08-27) — fps-FIRST relief for HW encoders.
///
/// On QSV/NVENC the encode time is pixels-bound and nearly
/// bitrate-independent, so the bitrate factor above cannot buy frame time
/// there — it only degrades quality (field: Rozalina rode factor 0.4 with
/// encode still ~25 ms). The correct first lever on HW is CADENCE: pace the
/// pump at the encoder's sustainable rate so consumed frames are EVENLY
/// spaced. Unpaced, a 60 Hz WGC feed consumed at ~40 fps drops ~33 % of
/// frames at random phases — alternating 16/33 ms motion deltas, which is
/// the residual "steps" judder even when latency is good.
///
/// Pure, quantized to 5 fps steps: engages only when the sustainable rate
/// sits ≥5 under target, steps DOWN as soon as the estimate quantizes lower
/// (a pace the encoder cannot hold is the judder above), floors at
/// [`FPS_PACE_MIN`] (beyond that the tier layer shrinks pixels). A step UP
/// waits until the estimate clears the higher step by `up_margin_fps`. With
/// 0 — the hardware pace, unchanged since P5 — an estimate hovering on a step
/// boundary moves the pace every window it crosses: two different 5-fps
/// steps always differ by a full quantum, so "moves only by ≥5" holds nothing.
/// The software pace runs with [`SW_PACE_UP_MARGIN_FPS`] (FR-112 P2d). Kill
/// switch `ROOMLERD_FPS_PACE=0` / config `fps_pace`.
pub struct FpsPace {
    paced: Option<u32>,
    enabled: bool,
    up_margin_fps: f32,
}

impl FpsPace {
    pub fn new() -> Self {
        Self::with_up_margin(0.0)
    }

    /// FR-112 P2d — a pace whose steps up wait for `up_margin_fps` of
    /// headroom over the step they move to.
    pub fn with_up_margin(up_margin_fps: f32) -> Self {
        Self {
            paced: None,
            enabled: !matches!(node_env("FPS_PACE").as_deref(), Some("0") | Some("false")),
            up_margin_fps,
        }
    }

    /// Step once per heartbeat window with the pressure EWMA. Returns the
    /// CURRENT paced fps (`None` = run at target).
    pub fn observe(&mut self, ewma_ms: f32, target_fps: u32) -> Option<u32> {
        if !self.enabled || ewma_ms <= 0.0 || !ewma_ms.is_finite() {
            return self.paced;
        }
        let sustainable = (1000.0 / ewma_ms).clamp(0.0, 240.0);
        // An estimate's pace: its 5-fps step, or `None` (the target) once
        // that step is within 5 of the target.
        let pace_for = |fps: f32| {
            let quantized = (fps.max(0.0) as u32 / 5) * 5;
            if quantized + 5 <= target_fps {
                // A target under the floor (a `ROOMLERD_FFMPEG_FPS` pin of
                // 5–14) floors at the target: `clamp` panics when its min
                // exceeds its max.
                Some(quantized.clamp(FPS_PACE_MIN.min(target_fps), target_fps))
            } else {
                None
            }
        };
        // `None` runs at the target, the highest rate of all.
        let rate = |pace: Option<u32>| pace.unwrap_or(u32::MAX);
        let down = pace_for(sustainable);
        let up = pace_for(sustainable - self.up_margin_fps);
        if rate(down) < rate(self.paced) {
            self.paced = down;
        } else if rate(up) > rate(self.paced) {
            self.paced = up;
        }
        self.paced
    }

    pub fn paced(&self) -> Option<u32> {
        self.paced
    }
}

impl Default for FpsPace {
    fn default() -> Self {
        Self::new()
    }
}

/// FR-112 P2 — a software pump's pace: its encode cost through [`FpsPace`],
/// never below 0.4.141's software target
/// ([`SW_PACE_FLOOR_FPS`](super::SW_PACE_FLOOR_FPS)). A host that cannot
/// sustain 30 then runs exactly as it did: its loop is slower than the 33 ms
/// cadence, so the gate never waits, and the bitrate base is 30's. Without the
/// floor, `FpsPace`'s 5-fps steps would pace a 27 fps host to 25.
///
/// Its own EWMA (α 0.4, seeded by the first window), not [`EncodePressure`]'s:
/// that one stops learning under `ROOMLERD_ENCODE_PRESSURE=0`, a kill switch
/// for the hardware path's bitrate factor that must not also switch the
/// software pace off. `ROOMLERD_FPS_PACE=0` still does, through `FpsPace`.
///
/// P2d: its steps up wait for [`SW_PACE_UP_MARGIN_FPS`] of headroom
/// (`ROOMLERD_SW_PACE_UP_MARGIN`, `0` = 0.4.142's pace). Without it, 0.4.142
/// undid a step three times, each one or two windows after taking it, on a
/// host that could not sustain 60 (the field trace in the tests).
pub struct SoftwarePace {
    ewma_ms: f32,
    pace: FpsPace,
}

/// FR-112 P2d — how far past a higher step (fps) a software encoder's
/// estimate must reach before its pace moves up to it. Half a step, narrower
/// than a step so a recovering encoder still climbs. An EWMA that swings less
/// than this across a step boundary no longer moves the pace; a wider swing
/// still can: the field trace's settled windows moved it by up to ±3.4 fps, and
/// one reversal survives there, three windows apart. The cost: an encoder that
/// sustains a step plus less than the margin runs a step lower after a dip
/// (55, not 60, at 60–62.5 fps).
pub const SW_PACE_UP_MARGIN_FPS: f32 = 2.5;

/// [`SW_PACE_UP_MARGIN_FPS`], or `ROOMLERD_SW_PACE_UP_MARGIN` (0–10; `0`,
/// `false`, `off` or `no` restores 0.4.142's pace, which steps up as soon as
/// it steps down).
fn sw_pace_up_margin() -> f32 {
    parse_sw_pace_up_margin(node_env("SW_PACE_UP_MARGIN").as_deref())
}

/// [`sw_pace_up_margin`] without the environment, which other tests read
/// concurrently. Anything unreadable is the default, as with every knob here.
fn parse_sw_pace_up_margin(value: Option<&str>) -> f32 {
    let Some(value) = value.map(str::trim) else {
        return SW_PACE_UP_MARGIN_FPS;
    };
    // The spellings of "off" the other switches here accept.
    if matches!(value.to_ascii_lowercase().as_str(), "false" | "off" | "no") {
        return 0.0;
    }
    value
        .parse::<f32>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| v.min(10.0))
        .unwrap_or(SW_PACE_UP_MARGIN_FPS)
}

impl SoftwarePace {
    pub fn new() -> Self {
        Self {
            ewma_ms: 0.0,
            pace: FpsPace::with_up_margin(sw_pace_up_margin()),
        }
    }

    /// Step once per heartbeat window with the window's average encode time
    /// (ms); a window that encoded nothing says nothing, so pass nothing.
    /// Returns [`Self::paced`].
    pub fn observe(&mut self, avg_encode_ms: f32, target_fps: u32) -> Option<u32> {
        if avg_encode_ms.is_finite() && avg_encode_ms > 0.0 {
            const ALPHA: f32 = 0.4;
            self.ewma_ms = if self.ewma_ms <= 0.0 {
                avg_encode_ms
            } else {
                (1.0 - ALPHA) * self.ewma_ms + ALPHA * avg_encode_ms
            };
            let _ = self.pace.observe(self.ewma_ms, target_fps);
        }
        self.paced()
    }

    /// The rate the pump runs at (`None` = its target), never below 30.
    pub fn paced(&self) -> Option<u32> {
        self.pace.paced().map(|p| p.max(super::SW_PACE_FLOOR_FPS))
    }
}

impl Default for SoftwarePace {
    fn default() -> Self {
        Self::new()
    }
}

/// Long-edge caps per tier: native → ~1440p-class → ~1080p-class floor.
/// Fed to `effective_target_resolution`'s SOFT slot, so an explicit
/// controller-side Fixed pick always wins (the auto tier only shapes
/// `Native`/auto sessions) and the relay hard cap still composes after.
pub const TIER_LONG_EDGES: [Option<u32>; 3] = [None, Some(2560), Some(1920)];

/// Consecutive saturated heartbeat windows (≈2 s each) before stepping a
/// tier DOWN — ≈10 s of bitrate-floor saturation.
pub const TIER_DOWN_WINDOWS: u32 = 5;

/// Consecutive deep-headroom windows before stepping back UP — ≈60 s of
/// proven-fast encode at the smaller resolution.
pub const TIER_UP_WINDOWS: u32 = 30;

/// Minimum spacing between ANY two tier changes. Each change is an encoder
/// rebuild + IDR + a wire dims change; churn is worse than either steady
/// state.
pub const TIER_CHANGE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// Resolution tier tracker layered on [`EncodePressure`] (the docstring's
/// "fps / resolution tiers can layer on later" — this is that layer, for
/// WINHOST-H-class hosts whose 4K panel saturates the encoder even at the
/// bitrate floor). Pure: step once per heartbeat window with the current
/// [`TierSignal`]; emits `Some(new_long_edge_cap)` exactly when the tier
/// changes. Kill switch `ROOMLERD_AUTO_DOWNSCALE=0`.
pub struct DownscaleTier {
    tier: usize,
    down_run: u32,
    up_run: u32,
    last_change: Option<std::time::Instant>,
    enabled: bool,
}

impl DownscaleTier {
    pub fn new() -> Self {
        Self {
            tier: 0,
            down_run: 0,
            up_run: 0,
            last_change: None,
            enabled: !matches!(
                node_env("AUTO_DOWNSCALE").as_deref(),
                Some("0") | Some("false")
            ),
        }
    }

    /// Current cap (`None` = native).
    pub fn cap(&self) -> Option<u32> {
        TIER_LONG_EDGES[self.tier]
    }

    /// Fold one heartbeat window's signal. Returns the NEW cap when the tier
    /// steps, `None` when it holds.
    pub fn observe(&mut self, signal: TierSignal, now: std::time::Instant) -> Option<Option<u32>> {
        if !self.enabled {
            return None;
        }
        match signal {
            TierSignal::Down => {
                self.down_run += 1;
                self.up_run = 0;
            }
            TierSignal::Up => {
                self.up_run += 1;
                self.down_run = 0;
            }
            TierSignal::Hold => {
                self.down_run = 0;
                self.up_run = 0;
            }
        }
        let cooled = self
            .last_change
            .is_none_or(|t| now.duration_since(t) >= TIER_CHANGE_COOLDOWN);
        if self.down_run >= TIER_DOWN_WINDOWS && self.tier + 1 < TIER_LONG_EDGES.len() && cooled {
            self.tier += 1;
            self.down_run = 0;
            self.last_change = Some(now);
            return Some(self.cap());
        }
        if self.up_run >= TIER_UP_WINDOWS && self.tier > 0 && cooled {
            self.tier -= 1;
            self.up_run = 0;
            self.last_change = Some(now);
            return Some(self.cap());
        }
        None
    }
}

impl Default for DownscaleTier {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for EncodePressure {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctrl() -> EncodePressure {
        EncodePressure {
            ewma_ms: 0.0,
            factor: 1.0,
            high_ms: 25.0,
            low_ms: 15.0,
            enabled: true,
        }
    }

    #[test]
    fn saturation_pulls_factor_down_to_floor() {
        let mut c = ctrl();
        // Sustained slow encode (~50 ms) → factor ratchets down.
        let mut last = 1.0;
        for _ in 0..30 {
            last = c.observe(50.0);
        }
        assert!(
            (last - FACTOR_FLOOR).abs() < 1e-3,
            "factor should floor at {FACTOR_FLOOR}, got {last}"
        );
    }

    #[test]
    fn recovery_returns_factor_to_one() {
        let mut c = ctrl();
        for _ in 0..30 {
            c.observe(50.0);
        }
        assert!(c.factor() < 1.0);
        // Encoder recovers (fast, ~8 ms) → factor climbs back to 1.0.
        let mut last = c.factor();
        for _ in 0..40 {
            last = c.observe(8.0);
        }
        assert!(
            (last - 1.0).abs() < 1e-3,
            "should recover to 1.0, got {last}"
        );
    }

    #[test]
    fn dead_zone_holds_factor_steady() {
        let mut c = ctrl();
        // One spike drops the factor; then feed dead-zone samples (20 ms,
        // between low=15 and high=25) until the EWMA settles below `high` and
        // the factor stops moving.
        c.observe(40.0);
        for _ in 0..6 {
            c.observe(20.0);
        }
        let settled = c.factor();
        assert!(settled < 1.0, "should have throttled under the spike");
        // EWMA now parked in the dead zone → factor holds steady.
        assert_eq!(c.observe(20.0), settled);
        assert_eq!(c.observe(20.0), settled);
    }

    #[test]
    fn disabled_pins_factor_at_one() {
        let mut c = EncodePressure {
            ewma_ms: 0.0,
            factor: 1.0,
            high_ms: 25.0,
            low_ms: 15.0,
            enabled: false,
        };
        assert_eq!(c.observe(200.0), 1.0);
        assert_eq!(c.observe(200.0), 1.0);
        assert_eq!(c.factor(), 1.0);
    }

    fn pressure(ewma_ms: f32, factor: f32) -> EncodePressure {
        EncodePressure {
            ewma_ms,
            factor,
            high_ms: 25.0,
            low_ms: 15.0,
            enabled: true,
        }
    }

    #[test]
    fn tier_signal_classifies_the_three_states() {
        // Bitrate lever exhausted + still saturated → Down.
        assert_eq!(pressure(40.0, FACTOR_FLOOR).tier_signal(), TierSignal::Down);
        // Saturated but the factor still has room → Hold (bitrate lever first).
        assert_eq!(pressure(40.0, 0.8).tier_signal(), TierSignal::Hold);
        // Fully recovered AND deep headroom (9 × 2.5 = 22.5 < 25) → Up.
        assert_eq!(pressure(9.0, 1.0).tier_signal(), TierSignal::Up);
        // Recovered but merely "ok" (12 × 2.5 = 30 > 25) → Hold, not Up —
        // the predictive margin that stops the down↔up ping-pong.
        assert_eq!(pressure(12.0, 1.0).tier_signal(), TierSignal::Hold);
        // No samples yet → Hold.
        assert_eq!(pressure(0.0, 1.0).tier_signal(), TierSignal::Hold);
    }

    fn tier() -> DownscaleTier {
        DownscaleTier {
            tier: 0,
            down_run: 0,
            up_run: 0,
            last_change: None,
            enabled: true,
        }
    }

    #[test]
    fn sustained_saturation_steps_down_one_tier_then_cooldown_blocks() {
        let mut t = tier();
        let now = std::time::Instant::now();
        for _ in 0..(TIER_DOWN_WINDOWS - 1) {
            assert_eq!(t.observe(TierSignal::Down, now), None);
        }
        assert_eq!(t.observe(TierSignal::Down, now), Some(Some(2560)));
        // Still saturated at the smaller res — cooldown blocks the next step.
        for _ in 0..(TIER_DOWN_WINDOWS * 2) {
            assert_eq!(t.observe(TierSignal::Down, now), None);
        }
        // After the cooldown the STILL-saturated run fires immediately —
        // FlipTracker semantics: the cooldown defers a persisted condition,
        // it doesn't demand 5 fresh windows of re-confirmation (the run was
        // continuous throughout; a Hold window would have reset it).
        let later = now + TIER_CHANGE_COOLDOWN + std::time::Duration::from_secs(1);
        assert_eq!(t.observe(TierSignal::Down, later), Some(Some(1920)));
        // 1080p-class is the floor — never steps below.
        let much_later = later + TIER_CHANGE_COOLDOWN + std::time::Duration::from_secs(1);
        for _ in 0..(TIER_DOWN_WINDOWS * 3) {
            assert_eq!(t.observe(TierSignal::Down, much_later), None);
        }
        assert_eq!(t.cap(), Some(1920));
    }

    #[test]
    fn a_hold_window_resets_both_runs() {
        let mut t = tier();
        let now = std::time::Instant::now();
        for _ in 0..(TIER_DOWN_WINDOWS - 1) {
            t.observe(TierSignal::Down, now);
        }
        t.observe(TierSignal::Hold, now); // saturation not consecutive
        for _ in 0..(TIER_DOWN_WINDOWS - 1) {
            assert_eq!(t.observe(TierSignal::Down, now), None);
        }
        assert_eq!(t.observe(TierSignal::Down, now), Some(Some(2560)));
    }

    #[test]
    fn sustained_deep_headroom_steps_back_up() {
        let mut t = DownscaleTier {
            tier: 2,
            down_run: 0,
            up_run: 0,
            last_change: None,
            enabled: true,
        };
        let now = std::time::Instant::now();
        for _ in 0..(TIER_UP_WINDOWS - 1) {
            assert_eq!(t.observe(TierSignal::Up, now), None);
        }
        assert_eq!(t.observe(TierSignal::Up, now), Some(Some(2560)));
        // Native requires another full run + cooldown.
        let later = now + TIER_CHANGE_COOLDOWN + std::time::Duration::from_secs(1);
        for _ in 0..(TIER_UP_WINDOWS - 1) {
            assert_eq!(t.observe(TierSignal::Up, later), None);
        }
        assert_eq!(t.observe(TierSignal::Up, later), Some(None));
        assert_eq!(t.cap(), None);
    }

    fn pace() -> FpsPace {
        FpsPace {
            paced: None,
            enabled: true,
            up_margin_fps: 0.0,
        }
    }

    fn margin_pace() -> FpsPace {
        FpsPace {
            up_margin_fps: SW_PACE_UP_MARGIN_FPS,
            ..pace()
        }
    }

    /// The EWMA (ms) of an encoder that sustains `fps`.
    fn ms(fps: f32) -> f32 {
        1000.0 / fps
    }

    #[test]
    fn pace_engages_quantized_in_whole_steps() {
        let mut p = pace();
        // Fast encoder (10 ms → 100 fps sustainable) → no pacing at 60.
        assert_eq!(p.observe(10.0, 60), None);
        // 25 ms → 40 sustainable → paced 40 (quantized, ≥5 under 60).
        assert_eq!(p.observe(25.0, 60), Some(40));
        // 24 ms → 41 → quantizes to 40 — the same step, held.
        assert_eq!(p.observe(24.0, 60), Some(40));
        // 29 ms → 34 → quantizes to 30 — a full quantum away, moves.
        assert_eq!(p.observe(29.0, 60), Some(30));
        // Recovery (12 ms → 83 sustainable ≥ target) → releases.
        assert_eq!(p.observe(12.0, 60), None);
    }

    #[test]
    fn pace_floors_at_min_and_respects_target() {
        let mut p = pace();
        // 200 ms → 5 sustainable → floored at FPS_PACE_MIN (the tier layer
        // owns anything below).
        assert_eq!(p.observe(200.0, 60), Some(FPS_PACE_MIN));
        // Near-target sustainable (17 ms → 58 → q 55 = target-5) engages at 55.
        let mut q = pace();
        assert_eq!(q.observe(17.0, 60), Some(55));
        // 16 ms → 62 → q 60: not ≥5 under target → releases.
        assert_eq!(q.observe(16.0, 60), None);
    }

    /// FR-112 P2d — two different 5-fps steps always differ by a full
    /// quantum, so with no margin an estimate hovering on a step boundary
    /// moves the pace every window it crosses: 0.4.142's software pace, and
    /// the hardware pace still.
    #[test]
    fn without_a_margin_a_hover_on_a_boundary_flaps() {
        let mut p = pace();
        let paces: Vec<_> = [55.3, 54.7, 55.3, 54.7, 55.3]
            .iter()
            .map(|fps| p.observe(ms(*fps), 60))
            .collect();
        assert_eq!(paces, [Some(55), Some(50), Some(55), Some(50), Some(55)]);
    }

    /// FR-112 P2d — with the margin the same hover takes one step down and
    /// holds there.
    #[test]
    fn with_the_margin_a_hover_on_a_boundary_holds() {
        let mut p = margin_pace();
        let paces: Vec<_> = [55.3, 54.7, 55.3, 54.7, 55.3, 55.3, 54.7]
            .iter()
            .map(|fps| p.observe(ms(*fps), 60))
            .collect();
        assert_eq!(
            paces,
            [
                Some(55),
                Some(50),
                Some(50),
                Some(50),
                Some(50),
                Some(50),
                Some(50)
            ]
        );
    }

    /// FR-112 P2d — the margin delays only the steps up: down at once (several
    /// steps if the estimate fell that far), up and back to the target only
    /// once the estimate clears the step by the margin.
    #[test]
    fn the_margin_delays_only_the_steps_up() {
        let mut p = margin_pace();
        assert_eq!(p.observe(ms(52.0), 60), Some(50), "engages at once");
        assert_eq!(p.observe(ms(56.0), 60), Some(50), "56: not 55 + 2.5 yet");
        assert_eq!(p.observe(ms(58.0), 60), Some(55), "58 clears 55 + 2.5");
        assert_eq!(p.observe(ms(61.0), 60), Some(55), "61: not 60 + 2.5 yet");
        assert_eq!(p.observe(ms(63.0), 60), None, "63 clears the target + 2.5");
        assert_eq!(
            p.observe(ms(59.0), 60),
            Some(55),
            "under the target: at once"
        );
        assert_eq!(
            p.observe(ms(41.0), 60),
            Some(40),
            "three steps down, at once"
        );
        assert_eq!(
            p.observe(ms(200.0), 60),
            None,
            "far past the target: released"
        );
    }

    /// FR-112 P2d — margin 0 is exactly the pace before it.
    #[test]
    fn a_zero_margin_is_the_old_pace() {
        // No whole multiple of 5: `ms` round-trips through f32, and on a step
        // boundary the round trip may land either side.
        let fps: [f32; 11] = [
            52.0, 56.0, 58.0, 61.0, 63.0, 59.0, 41.0, 57.4, 62.6, 9.0, 31.0,
        ];
        let mut p = pace();
        let mut old: Option<u32> = None;
        for f in fps {
            // 0.4.142's rule: the estimate's step, whatever the pace was.
            let q = (f.floor() as u32 / 5) * 5;
            old = (q + 5 <= 60).then(|| q.clamp(FPS_PACE_MIN, 60));
            assert_eq!(p.observe(ms(f), 60), old, "at {f} fps");
        }
        assert_eq!(old, Some(30));
    }

    /// A target under the floor (an operator's 5–14 fps pin on the hardware
    /// pump) with an encode slower than it: `clamp(15, target)` panicked and
    /// took the session's pump down. Found in FR-112 P2d's review; older than
    /// FR-112.
    #[test]
    fn a_target_under_the_floor_paces_at_the_target() {
        assert_eq!(pace().observe(200.0, 10), Some(10));
        assert_eq!(margin_pace().observe(200.0, 14), Some(14));
        assert_eq!(pace().observe(200.0, 15), Some(FPS_PACE_MIN));
    }

    /// FR-112 P2d — the margin's switch reads "off" as every other switch here
    /// does, and anything unreadable is the default.
    #[test]
    fn the_margin_switch_reads_off_like_the_others() {
        assert_eq!(parse_sw_pace_up_margin(None), SW_PACE_UP_MARGIN_FPS);
        for off in ["0", "false", "off", "no", " OFF ", "0.0"] {
            assert_eq!(parse_sw_pace_up_margin(Some(off)), 0.0, "{off:?}");
        }
        assert_eq!(parse_sw_pace_up_margin(Some("4")), 4.0);
        assert_eq!(parse_sw_pace_up_margin(Some("25")), 10.0, "capped");
        for junk in ["-1", "NaN", "inf", "two", ""] {
            assert_eq!(
                parse_sw_pace_up_margin(Some(junk)),
                SW_PACE_UP_MARGIN_FPS,
                "{junk:?}"
            );
        }
    }

    #[test]
    fn disabled_pace_never_engages() {
        let mut p = FpsPace {
            paced: None,
            enabled: false,
            up_margin_fps: SW_PACE_UP_MARGIN_FPS,
        };
        assert_eq!(p.observe(200.0, 60), None);
        assert_eq!(p.paced(), None);
    }

    #[test]
    fn disabled_tier_never_steps() {
        let mut t = DownscaleTier {
            tier: 0,
            down_run: 0,
            up_run: 0,
            last_change: None,
            enabled: false,
        };
        let now = std::time::Instant::now();
        for _ in 0..(TIER_DOWN_WINDOWS * 4) {
            assert_eq!(t.observe(TierSignal::Down, now), None);
        }
        assert_eq!(t.cap(), None);
    }

    fn sw_pace() -> SoftwarePace {
        SoftwarePace {
            ewma_ms: 0.0,
            pace: margin_pace(),
        }
    }

    /// FR-112 P2d — the field trace that found the flap: 0.4.142 on the Asahi
    /// host with `ROOMLERD_ENCODER_CLOCK=0` (a host that cannot sustain 60),
    /// VP9-444, a spinning cube, every window's `avg_encode_ms` from its
    /// heartbeats (2026-10-17 23:07Z). The lab viewer stalled and the rate
    /// controller fell, so the encode got cheaper as the session went on.
    const FIELD_TRACE_MS: [f32; 41] = [
        29.172, 31.996, 50.799, 42.658, 31.138, 30.422, 31.468, 22.511, 25.669, 21.652, 20.411,
        18.848, 20.46, 18.902, 19.933, 19.028, 18.094, 18.421, 19.267, 17.384, 18.524, 16.428,
        19.892, 20.908, 19.638, 16.807, 16.272, 17.875, 20.57, 21.785, 20.455, 18.342, 16.877,
        16.417, 16.032, 15.102, 13.947, 16.765, 17.628, 14.568, 14.751,
    ];

    fn replay(up_margin_fps: f32) -> Vec<Option<u32>> {
        let mut p = SoftwarePace {
            ewma_ms: 0.0,
            pace: FpsPace {
                up_margin_fps,
                ..pace()
            },
        };
        FIELD_TRACE_MS.iter().map(|ms| p.observe(*ms, 60)).collect()
    }

    /// The window indexes where the pace moved, and which way (`true` = up).
    fn moves(paces: &[Option<u32>]) -> Vec<(usize, bool)> {
        let rate = |p: Option<u32>| p.unwrap_or(u32::MAX);
        paces
            .windows(2)
            .enumerate()
            .filter(|(_, w)| w[0] != w[1])
            .map(|(i, w)| (i + 1, rate(w[1]) > rate(w[0])))
            .collect()
    }

    /// FR-112 P2d — margin 0 replays what 0.4.142 logged, window for window,
    /// including the three steps it undid one or two windows later. With the
    /// margin none comes back that soon, and the pace moves less.
    #[test]
    fn the_field_trace_replays_and_the_margin_calms_it() {
        let logged: Vec<Option<u32>> = [
            (8, Some(30)),
            (2, Some(35)),
            (1, Some(40)),
            (4, Some(45)),
            (6, Some(50)),
            (1, Some(55)),
            (4, Some(50)),
            (2, Some(55)),
            (1, Some(50)),
            (2, Some(45)),
            (2, Some(50)),
            (2, Some(55)),
            (6, None),
        ]
        .iter()
        .flat_map(|(n, pace)| std::iter::repeat_n(*pace, *n))
        .collect();
        assert_eq!(replay(0.0), logged, "margin 0 is what 0.4.142 logged");

        let undone_within_two = |m: &[(usize, bool)]| {
            m.windows(2)
                .filter(|w| w[0].1 != w[1].1 && w[1].0 - w[0].0 <= 2)
                .count()
        };
        let old = moves(&logged);
        let calm = moves(&replay(SW_PACE_UP_MARGIN_FPS));
        assert_eq!(undone_within_two(&old), 3);
        assert_eq!(undone_within_two(&calm), 0, "{calm:?}");
        assert_eq!((old.len(), calm.len()), (12, 8), "{old:?} vs {calm:?}");
        assert_eq!(
            replay(SW_PACE_UP_MARGIN_FPS).last(),
            Some(&None),
            "still recovers"
        );
    }

    /// FR-112 P2 — a software encoder that cannot hold 60 is paced to what it
    /// sustains, in 5-fps steps, and released to the target once it can.
    #[test]
    fn a_software_pump_is_paced_to_what_its_encoder_sustains() {
        let mut p = sw_pace();
        assert_eq!(p.observe(25.0, 60), Some(40), "1000 / 25 ms = 40 fps");
        let mut paced = Some(40);
        for _ in 0..20 {
            paced = p.observe(8.0, 60);
        }
        assert_eq!(paced, None, "an encoder that holds 60 runs at the target");
    }

    /// FR-112 P2 — and never below 0.4.141's 30: an encoder that sustains 22
    /// runs at 30's cadence and base, which on a loop that slow is exactly the
    /// unpaced 0.4.141 pump.
    #[test]
    fn a_software_pump_is_never_paced_below_thirty() {
        let mut p = sw_pace();
        assert_eq!(
            p.observe(45.0, 60),
            Some(30),
            "1000 / 45 ms = 22 fps: held at 30, not stepped to 20"
        );
        assert_eq!(
            sw_pace().observe(45.0, 30),
            Some(30),
            "a pinned 30 stays 30"
        );
    }

    /// FR-112 P2 — a window that encoded nothing moves nothing, and the pace
    /// does not depend on the hardware path's bitrate-factor kill switch.
    #[test]
    fn an_empty_window_leaves_the_pace_alone() {
        let mut p = sw_pace();
        assert_eq!(p.observe(25.0, 60), Some(40));
        assert_eq!(p.observe(0.0, 60), Some(40));
        assert_eq!(p.observe(f32::NAN, 60), Some(40));
        assert!(
            (p.ewma_ms - 25.0).abs() < 1e-3,
            "seeded by the first window only"
        );
    }
}
