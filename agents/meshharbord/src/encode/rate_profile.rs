// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P3 (Parsec-class plan) — transport/codec-aware rate-profile helpers for
//! the DC video pumps. Pure (no ffmpeg/webrtc/tokio types, explicit
//! `Instant`s), so everything here unit-tests on the default feature build
//! even though the callers are `ffmpeg-encoder`-gated.
//!
//! Three concerns live here:
//!
//! 1. **Persisted-flip rebuild** ([`FlipTracker`]): a mid-session
//!    relay↔direct ICE renomination already re-clamps the AIMD ceiling
//!    LIVE, but the encoder's fps/bufsize and the capture pacer were baked
//!    at pump start — a session that STARTED on the relay stayed at 30 fps
//!    forever after upgrading to direct (peer.rs pump-start
//!    `ffmpeg_target_fps(constrained)` + `capture::open_default`). The
//!    tracker decides when a flip has persisted long enough to be worth a
//!    full encoder rebuild + capture reopen (each costs an IDR + a brief
//!    hiccup, so: 2 consecutive 5 s checks to debounce ICE flapping, and at
//!    most one rebuild per 60 s — the rc.217 "recovery that re-triggers its
//!    own trigger needs a cooldown" lesson applied from day one).
//!
//! 2. **Codec rate factor** ([`codec_rate_factor_pct`]): the maxrate
//!    ceiling was codec-agnostic (0.07 bpp/s for everyone), but H.264
//!    needs ~1.5× the bits of HEVC/AV1 for the same screen-content text
//!    sharpness. Field 2026-07-26 (P2 rollout, WINHOST-A/WINHOST-H/WINHOST-B):
//!    H.264-DC motion "very smooth" but "text gets blurred from time to
//!    time" — transients exhausting the HEVC-sized budget. H.264 gets a
//!    150% ceiling; the relay clamp still applies AFTER the factor (pipe
//!    physics don't care which codec fills them).
//!
//! 3. **H.264 CQ adjustment** ([`h264_cq_adjust`]): at equal nominal
//!    quality numbers H.264 codes text visibly softer than HEVC (different
//!    QP scale + weaker intra prediction). The h264_* encoders get a
//!    2-step sharper constant-quality target off the shared `FFMPEG_CQ`
//!    base (env still wins as the base; the adjustment is relative).
//!
//! 4. **Idle-settle keyframe gate** ([`SettleKeyframeGate`]): the rc.187
//!    settle IDR, burst-gated so caret blinks stop metronoming forced IDRs.
//!
//! 5. **Scale-aware CQ bias** ([`scale_cq_bias`], P7): deep resolution
//!    rungs run far below the [3, 12] Mbps maxrate floor's bpp budget —
//!    spend the headroom on text sharpness instead of leaving it unused.
//!
//! 6. **Idle native-rung refinement** ([`IdleRefine`], P7): when the ONLY
//!    reason the encode is below native is a resolution cap and the scene
//!    has settled, lift the cap so the encoder rebuilds at native and ships
//!    one crisp still; the first motion burst restores the cap in ~300 ms.

use std::time::{Duration, Instant};

/// Consecutive transport-recheck observations (5 s apart in the pumps) that
/// must agree before a flip triggers a rebuild. 2 → a single flapping check
/// never rebuilds; a real renomination rebuilds within ~10 s.
pub const FLIP_REQUIRED_CONSECUTIVE: u8 = 2;

/// Minimum spacing between flip-rebuilds. An ICE path oscillating faster
/// than this keeps the live AIMD clamp (which follows every flip) but stops
/// paying the IDR + hiccup cost of a rebuild each time.
pub const FLIP_REBUILD_COOLDOWN: Duration = Duration::from_secs(60);

/// Debounced mid-session transport-flip → rebuild decision. `stable` is the
/// state the pump last BUILT for; `observe` is fed every transport recheck
/// with the currently-detected state and returns `Some(new_state)` exactly
/// when the pump should rebuild (encoder + capture pacer) for it.
#[derive(Debug)]
pub struct FlipTracker {
    stable: bool,
    pending: Option<(bool, u8)>,
    last_rebuild: Option<Instant>,
}

impl FlipTracker {
    pub fn new(initial_constrained: bool) -> Self {
        Self {
            stable: initial_constrained,
            pending: None,
            last_rebuild: None,
        }
    }

    pub fn observe(&mut self, detected: bool, now: Instant) -> Option<bool> {
        if detected == self.stable {
            // Back to (or still at) the built-for state — a flap resolved
            // itself; drop any pending count.
            self.pending = None;
            return None;
        }
        let count = match self.pending {
            Some((dir, n)) if dir == detected => n + 1,
            // First observation of this direction (or a direction change
            // mid-count — restart the count for the new direction).
            _ => 1,
        };
        self.pending = Some((detected, count));
        if count < FLIP_REQUIRED_CONSECUTIVE {
            return None;
        }
        if let Some(t) = self.last_rebuild
            && now.duration_since(t) < FLIP_REBUILD_COOLDOWN
        {
            // Persisted, but we rebuilt too recently — keep the pending
            // count saturated; the next observe after cooldown fires.
            self.pending = Some((detected, FLIP_REQUIRED_CONSECUTIVE));
            return None;
        }
        self.stable = detected;
        self.pending = None;
        self.last_rebuild = Some(now);
        Some(detected)
    }
}

/// Per-codec maxrate ceiling factor, in percent. Keyed by the pump's
/// `FfmpegDcCodec::label()` vocabulary ("HEVC" / "VP9" / "AV1" / "H264").
///
/// Built-ins (2026-07-28 field, DEVBOX→WINHOST-C/UHD 620): H264 keeps
/// its 150 % band (equal text sharpness genuinely needs ~1.5× the bits);
/// HEVC moves 100 → **125** — the "HEVC needs ⅔ the bits of H.264"
/// efficiency assumption fails for desktop drag-motion on realtime QSV
/// presets, and the starved band was the measured reason H.264 looked
/// visibly smoother than HEVC on the same direct path (13.1 vs 8.7 Mbps;
/// encode times were fine for both).
///
/// Operator override per codec: `ROOMLERD_RATE_FACTOR_<LABEL>` (legacy
/// `ROOMLER_NODE_` prefix + the `rate_factor_*` config keys accepted via
/// [`tunnel_core::env::node_env`]). Clamped to 50–400; garbage falls back
/// to the built-in. The pump re-reads per frame, so a REAL env var applies
/// live; config-key changes need a service restart (set-once fallback map).
pub fn codec_rate_factor_pct(codec_label: &str) -> usize {
    let builtin: usize = match codec_label {
        "H264" => 150,
        "HEVC" => 125,
        // VP9 (vp9_qsv 4:2:0 HW) joins HEVC at 125 (2026-07-28 field: same
        // realtime-preset starvation class vs the H264 band; AV1 stays 100 —
        // its realtime efficiency is genuinely better and no field signal
        // says otherwise yet).
        "VP9" => 125,
        _ => 100,
    };
    match tunnel_core::env::node_env(&format!("RATE_FACTOR_{codec_label}")) {
        Some(v) => match v.trim().parse::<usize>() {
            Ok(pct) => pct.clamp(50, 400),
            Err(_) => builtin,
        },
        None => builtin,
    }
}

/// FR-77 P3 — the chroma column of the ceiling table: the factor a 4:4:4
/// cell applies ON TOP of [`codec_rate_factor_pct`]. Built-in 150 for every
/// codec — what the libvpx 4:4:4 pump used before the column existed —
/// until a cell's field test sets its own through
/// `ROOMLERD_RATE_FACTOR_<CODEC>_444` (config `rate_factor_<codec>_444`),
/// clamped 50–400 like the codec factors. Always 100 for 4:2:0.
pub fn chroma_rate_factor_pct(codec_label: &str, chroma444: bool) -> usize {
    if !chroma444 {
        return 100;
    }
    const BUILTIN: usize = 150;
    match tunnel_core::env::node_env(&format!("RATE_FACTOR_{codec_label}_444")) {
        Some(v) => match v.trim().parse::<usize>() {
            Ok(pct) => pct.clamp(50, 400),
            Err(_) => BUILTIN,
        },
        None => BUILTIN,
    }
}

/// FR-119 P2a — the rate law's exponent above 60 fps. Bits per second grow as
/// `(fps / 60)^α`, not linearly: frames closer together differ less.
///
/// Measured offline (2026-10-21; NVENC on scrolling text at a fixed px/s, at
/// constant quality, 60 / 120 / 144 fps): α ran from ~0 to 0.8 by codec and
/// content, with HEVC on whole-pixel text motion at the top (0.77–0.80). 0.8 is
/// that upper envelope, so a ceiling above 60 never starves the motion it
/// exists for. P3's field cells refine it (FR-119 open decision 2). FR-112's
/// RTP bitrate base uses 0.5 (`bitrate_base_for_fps`); this law serves text
/// scrolls, the top of the range.
pub(crate) const HIGH_FPS_ALPHA: f64 = 0.8;

/// FR-119 P2a — the frame rate a ceiling is computed at: `fps` itself up to 60
/// (today's linear law, so every ceiling at or below 60 is byte-identical), and
/// above it the 60 fps rate scaled by `(fps / 60)^α`.
pub(crate) fn rate_law_fps(fps: u32) -> f64 {
    if fps <= 60 {
        fps as f64
    } else {
        60.0 * (fps as f64 / 60.0).powf(HIGH_FPS_ALPHA)
    }
}

/// P3 — codec-factor-aware ceiling. `factor_pct` scales the bpp-derived rate
/// AND the [3, 12] Mbps band proportionally (H.264 needs ~1.5× the bits of
/// HEVC/AV1 for the same screen-content text sharpness — field 2026-07-26:
/// P2 H.264-DC "text gets blurred from time to time" at the HEVC-sized
/// budget). The relay clamp applies AFTER the factor: a constrained pipe's
/// physics don't grow with the codec, so relayed H.264 stays at
/// `relay_max_bps` and keeps the known relay softness trade-off.
///
/// P8b — lives here (not `ffmpeg/encoder.rs`) because it's pure math with
/// no ffmpeg types, and `encode::policy` composes it on every build.
///
/// FR-74 P1 — the DIRECT ceiling is a content-generous bound, not the 0.07 bpp
/// motion-video budget. The cap is a ceiling, never a target: constant-quality
/// rate control spends what the content demands and the AIMD follows the pipe
/// BELOW the cap on evidence (viewer age, the byte-budget gate). With the 0.07
/// constant (9.68 Mbps at 1920×1200 @ 60) the operator's Notepad++ scroll on a
/// 4 ms direct path was unreadable while it moved, and the controller cut its
/// own cap as if it were congestion; at 40 Mbps (P0 cell B2) the same scroll
/// could not be reproduced on AV1, VP9 4:2:0 or H.264 — 0 cuts, 0 skips,
/// 15–23 Mbps sent, 26–43 fps. 0.25 bpp/s gives 34.6 Mbps at that geometry,
/// clamped to [3, 48] Mbps per codec factor. The CONSTRAINED branch keeps the
/// 0.07 / [3, 12] band (it is min'd with `relay_max_bps` anyway); relay paths
/// are unchanged byte for byte. `FFMPEG_MAXRATE_KBPS` stays the operator's
/// override in both directions.
///
/// FR-119 P2a — above 60 fps the rate follows [`rate_law_fps`], and the band's
/// top grows with it; at or below 60 every value is byte-identical.
pub(crate) fn ffmpeg_maxrate_bps_scaled(
    width: u32,
    height: u32,
    fps: u32,
    constrained: bool,
    factor_pct: usize,
) -> usize {
    if let Some(kbps) = tunnel_core::env::node_env("FFMPEG_MAXRATE_KBPS")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|k| *k > 0)
    {
        return kbps * 1000;
    }
    /// Relay / constrained: the motion-video budget the relay clamp sits under.
    const CONSTRAINED_BPP_PER_SECOND: f64 = 0.07;
    /// Direct: a screen-content bound — text in motion needs 3–4× a video's bits.
    const DIRECT_BPP_PER_SECOND: f64 = 0.25;
    let (bpp, band_top) = if constrained {
        (CONSTRAINED_BPP_PER_SECOND, 12_000_000_usize)
    } else {
        (DIRECT_BPP_PER_SECOND, 48_000_000_usize)
    };
    // FR-119 P2a — above 60 fps the band's top grows with the rate law, so a
    // 120 fps stream does not hit the 60 fps class's top and run softer per
    // frame than 60 would.
    let band_top = if fps > 60 {
        (band_top as f64 * rate_law_fps(fps) / 60.0) as usize
    } else {
        band_top
    };
    let raw = (width as f64 * height as f64 * rate_law_fps(fps) * bpp) as usize;
    let raw = raw.saturating_mul(factor_pct) / 100;
    let clamped = raw.clamp(
        3_000_000_usize.saturating_mul(factor_pct) / 100,
        band_top.saturating_mul(factor_pct) / 100,
    );
    // rc.166 freeze fix — on a constrained relay-TCP transport (WSL / corp
    // UDP-blocked) even the low end of the [3, 12] Mbps HEVC/vp9_qsv maxrate
    // band overruns the ~1-4 Mbps pipe. Pull it down to relay_max_bps (3 Mbps
    // default) so the FFmpeg DC pump matches the VP9-444 pump's relay clamp.
    if constrained {
        clamped.min(crate::encode::relay_max_bps() as usize)
    } else {
        clamped
    }
}

/// H.264 constant-quality adjustment: 2 steps sharper than the shared CQ
/// base, floored at the global minimum (10). No-op for every other encoder.
pub fn h264_cq_adjust(encoder_name: &str, cq: u32) -> u32 {
    if encoder_name.contains("h264") {
        cq.saturating_sub(2).max(10)
    } else {
        cq
    }
}

/// P4 — vp9_qsv runtime-forced-IDR verdict → `(long_gop, low_power)`.
/// `verdict` = `Some((honors_lp1, honors_lp0))` from the startup probe
/// (does the encoder emit a key-flagged packet after a runtime force, per
/// `low_power` mode?), `None` when the probe is disabled or never ran.
/// `forced_lp` = the `ROOMLERD_QSV_LOW_POWER` operator override.
///
/// The long GOP (on-demand-only keys — kills the residual ~1 Hz natural-key
/// pulse on VP9-over-DC Intel hosts) is granted ONLY for a mode the probe
/// MEASURED as honouring runtime forcing; everything else keeps the rc.219
/// containment (60-frame natural GOP + VDEnc). Preference order when both
/// modes honour: low_power=1 (the Iris Xe fps-unlock path).
pub fn vp9_qsv_config(verdict: Option<(bool, bool)>, forced_lp: Option<bool>) -> (bool, bool) {
    if let Some(lp) = forced_lp {
        let honors = match (verdict, lp) {
            (Some((h1, _)), true) => h1,
            (Some((_, h0)), false) => h0,
            (None, _) => false,
        };
        return (honors, lp);
    }
    match verdict {
        Some((true, _)) => (true, true),
        Some((false, true)) => (true, false),
        Some((false, false)) | None => (false, true),
    }
}

/// P7 (2026-08-20) — CQ sharpening steps for deep resolution rungs. When a
/// cap has shrunk the encode area well below native, the [3, 12] Mbps
/// maxrate floor grants 1.4-2.2× the 0.07-bpp design budget — headroom that
/// CQ-driven VBR never spends (it uses only what the quality target
/// demands). Trade it for text sharpness. Ladder on AREA ratio:
///   ≤ 32% area (~0.57 linear) → max_steps    (Smoother 1024 rung:
///                                             1920×1200→1024×640 = 28%)
///   ≤ 50% area (~0.71 linear) → max_steps/2  (Balanced relay 1280 rung:
///                                             1920×1200→1280×800 = 44%)
///   else 0 (near-native rungs already run at the design bpp).
/// NVENC/QSV quality steps cost ~7-10% bits each, so the default 4 steps ≈
/// 1.3-1.5× sustained bits — inside the floor headroom with margin, and the
/// UNCHANGED maxrate ceiling + HRD still bound the worst case (the bias can
/// only spend budget the design already allocated).
pub fn scale_cq_bias(enc_w: u32, enc_h: u32, native_w: u32, native_h: u32, max_steps: u32) -> u32 {
    let enc_area = enc_w as u64 * enc_h as u64;
    let native_area = native_w as u64 * native_h as u64;
    if enc_area == 0 || native_area == 0 || enc_area >= native_area {
        return 0;
    }
    // Integer percent avoids f32 wobble at the ladder boundaries.
    let pct = enc_area * 100 / native_area;
    if pct <= 32 {
        max_steps
    } else if pct <= 50 {
        max_steps / 2
    } else {
        0
    }
}

/// Env-resolved `max_steps` for [`scale_cq_bias`]:
/// `ROOMLERD_SCALE_CQ_BOOST`, default 4, `0` disables the bias.
pub fn scale_cq_boost_steps() -> u32 {
    tunnel_core::env::node_env("SCALE_CQ_BOOST")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(4)
}

/// Apply a SIGNED CQ bias with the shared global bounds ([10, 40] — the
/// `ffmpeg_cq` clamp: below 10 is near-lossless blow-out, above 40 is
/// visibly soft). Positive steps SHARPEN (subtract — the P7 deep-rung
/// posture), negative steps SOFTEN (add — the constrained-motion relief:
/// on a relay-clamped pipe the rung exists to keep MOTION fluid, and a
/// softer rung frame is a smaller, faster-arriving one). Composes with
/// [`h264_cq_adjust`]: 22 → 20 (h264) → 16 (deep rung) / 24 (relief 4);
/// one shared floor and ceiling.
pub fn apply_cq_bias(cq: u32, steps: i32) -> u32 {
    (cq as i32 - steps).clamp(10, 40) as u32
}

/// Constrained-motion CQ relief, in SOFTENING steps, applied by
/// `policy::rate_plan` when a constrained (relay) session runs below
/// native — i.e. exactly the motion phase the resolution rung exists
/// for. Field 2026-08-21 (winhost-a/corplap retest of rc.441): the P7
/// sharpening bias drove the constrained Smoother rung to CQ 18, whose
/// 25-40 KB deltas each took ~100-160 ms to traverse a ~2 Mbps relay —
/// bursty arrival the viewer read as decode pressure, parking the
/// viewer-rate divisor at 3 (the reported "9 fps, not fully smooth").
/// Softer motion frames are the fluidity lever the dial promises; the
/// at-rest image is untouched (native ⇒ bias 0 ⇒ base CQ + polish).
/// Env `ROOMLERD_CONSTRAINED_CQ_RELIEF` / config
/// `constrained_cq_relief` (default 4, 0 = no relief, max 12).
pub fn constrained_cq_relief() -> i32 {
    tunnel_core::env::node_env("CONSTRAINED_CQ_RELIEF")
        .and_then(|v| v.trim().parse::<i32>().ok())
        .map(|v| v.clamp(0, 12))
        .unwrap_or(4)
}

/// Constrained send-queue byte budget, expressed as milliseconds of the
/// relay ceiling. The DC pump's send channel is FRAME-count bounded
/// (depth 4 constrained), which bounds nothing in BYTES: four native
/// motion frames are ~0.5-1 MB ≈ 2-4 s of a ~2 Mbps relay — the field
/// "drag starts, ~0.5 s in it freezes, then continues" (the queue is the
/// freeze) and the "window drags seconds behind" lag. Budgeting the
/// in-flight bytes to a fraction of a second converts queue-lag into an
/// immediate production skip the viewer perceives as a lower — but
/// current — frame rate. Env `ROOMLERD_CONSTRAINED_QUEUE_MS` /
/// config `constrained_queue_ms` (default 450, 0 = unbounded, max 2000).
pub fn constrained_queue_ms() -> u64 {
    tunnel_core::env::node_env("CONSTRAINED_QUEUE_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|v| v.min(2000))
        .unwrap_or(450)
}

/// [`constrained_queue_ms`] resolved against a link ceiling into a byte
/// budget for the pump's backpressure gate. `0` ms disables the gate
/// (`usize::MAX`).
///
/// FR-59 P2 — floored at [`CONSTRAINED_QUEUE_MIN_BYTES`] so a momentarily
/// absurd reference rate cannot gate every single frame.
pub fn constrained_queue_budget_bytes(ceiling_bps: u32) -> usize {
    constrained_queue_budget_bytes_at(ceiling_bps, constrained_queue_ms())
}

/// [`constrained_queue_budget_bytes`] with the window explicit — the FR-70
/// M3a plan producer's form (`encode::plan`), which resolves
/// `constrained_queue_ms` ONCE per pump instead of per frame. The reader
/// above keeps its per-frame read and is this function applied, so the two
/// cannot drift (locked by `the_budget_readers_equal_their_explicit_window_forms`).
pub fn constrained_queue_budget_bytes_at(ceiling_bps: u32, queue_ms: u64) -> usize {
    if queue_ms == 0 {
        return usize::MAX;
    }
    (((ceiling_bps as u64).saturating_mul(queue_ms) / 8000) as usize)
        .max(CONSTRAINED_QUEUE_MIN_BYTES)
}

/// FR-59 P5 — a link at or below this remembered rate opens in the
/// slow-link profile (bps). Env `ROOMLERD_SLOW_LINK_PROFILE_BPS` /
/// config `slow_link_profile_bps` (default 1 000 000, 0 = never).
pub fn slow_link_profile_bps() -> u32 {
    tunnel_core::env::node_env("SLOW_LINK_PROFILE_BPS")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(1_000_000)
}

/// FR-59 P5 — what a session opens with when the pair is remembered as
/// slow: fewer pixels and fewer frames, resolved ONCE at pump start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlowLinkProfile {
    /// Long-edge resolution cap, px.
    pub max_long_edge: u32,
    /// Capture/send frame rate cap.
    pub max_fps: u32,
}

/// FR-59 P5 — resolve the opening profile from the rate the memory holds
/// for this pair.
///
/// The bitrate levers (P1–P4) can make the encoder TRACK a slow pipe, but
/// they cannot make 1920×1200 at 30 fps legible through it: at 400 kbps
/// that is ~1 700 bytes per frame, below what any encoder can do
/// something with. Halving the long edge quarters the pixel count and
/// halving the frame rate doubles the per-frame budget — together ~8× the
/// bits per pixel. That is the lever a bitrate floor cannot provide, and
/// it is why `slow_link_min_bitrate_bps` stops where it does rather than
/// chasing the pipe to zero.
///
/// ⚠ Resolved ONCE, at pump start, deliberately. `priority_relay_cap`'s
/// dims-caps are off by default because every mid-motion rung flip pays a
/// BLOCKING encoder open — field-measured 0.65–0.87 s on Iris Xe — plus a
/// fresh IDR behind the queued frames, and the user-felt result was worse
/// than never flipping. Opening at the right size costs neither.
///
/// ⚠ The input is the REMEMBERED rate, not a live measurement, because at
/// pump start there is no measurement yet and waiting for one would make
/// this a mid-session rung. That inherits FR-35's relay-keyed staleness
/// (see P6) — but the failure mode is benign and asymmetric: a fast link
/// misremembered as slow opens soft and stays usable, where a slow link
/// opened at native is the defect this FR exists for.
pub fn slow_link_profile(remembered_bps: Option<u32>, enabled: bool) -> Option<SlowLinkProfile> {
    if !enabled {
        return None;
    }
    let threshold = slow_link_profile_bps();
    if threshold == 0 {
        return None;
    }
    match remembered_bps {
        // A pair with no memory opens as it always has: an unknown link is
        // not a slow one, and guessing soft would degrade every FIRST
        // session on every healthy relay.
        Some(bps) if bps > 0 && bps <= threshold => Some(SlowLinkProfile {
            max_long_edge: 1280,
            max_fps: 15,
        }),
        _ => None,
    }
}

/// FR-59 P2 — the smallest constrained queue budget, one SCTP chunk. The
/// gate compares whole FRAMES in flight, so a budget under one chunk
/// would gate before anything could be in flight at all; this keeps the
/// pump able to have one frame on the wire while still being, at
/// 400 kbps, only ~330 ms of queue.
pub const CONSTRAINED_QUEUE_MIN_BYTES: usize = 16 * 1024;

/// FR-59 P2 — the reference rate [`constrained_queue_budget_bytes`] is
/// denominated in.
///
/// The budget used to be resolved ONCE at pump start against
/// `relay_max_bps()`, which makes "450 ms of queue" a claim about a
/// nominal 3 Mbps band rather than about this session's pipe. Field
/// 2026-09-01 (CORPLAP-3 → neo16 over a phone hotspot): 168 750 bytes of
/// budget against a MEASURED 395 kbps link is **3.4 seconds** of standing
/// queue, so `frames_dropped_backpressure` stayed 0 while viewer paint age
/// ran 2.3–7.1 s.
///
/// A held measurement may only ever LOWER the reference — the same
/// one-directional rule the measured CEILING clamp uses, and the reason
/// this is safe to consume where the ceiling is not: an under-estimate
/// makes the budget smaller, which sheds more and lowers latency, while
/// an under-estimated ceiling collapses quality. `enabled` false returns
/// the ceiling verbatim (the pre-FR-59 posture).
pub fn constrained_queue_reference_bps(
    ceiling_bps: u32,
    measured_bps: Option<u32>,
    enabled: bool,
) -> u32 {
    match measured_bps {
        Some(g) if enabled && g > 0 => ceiling_bps.min(g),
        _ => ceiling_bps,
    }
}

/// HRD/VBV window for CONSTRAINED sessions, as a percent of `maxrate`.
/// Default 200 (the rc.234 2× window — transients spend real bits, the
/// "IDR QP-collapse blur" fix), same as direct sessions.
///
/// ⚠ rc.442 shipped this at 75 % to bound the refine IDR's relay transit
/// (the crystallize-latency lever) and rc.443 REVERTED it the same day:
/// field 2026-08-21, corplap-3 (Iris Xe) — the FIRST session whose
/// av1_qsv ran with a sub-1× window died on its first settle IDR with
/// `send_frame: Invalid data found when processing input` (a quality-
/// floored native AV1 IDR is ~2 Mbit, larger than the whole 1.5 Mbit
/// reservoir; Intel's AV1 VDENC apparently ERRORS on an over-budget
/// forced IDR rather than QP-clamping), and the follow-on encode call
/// hung in the driver. corplap had run av1_qsv all day on rc.441's 2×
/// window with zero errors. Sub-100 values remain available per-host
/// for experiments (env `ROOMLERD_CONSTRAINED_HRD_PCT` / config
/// `constrained_hrd_pct`, clamp [25, 200]) but the DEFAULT must not
/// undercut a codec's forced-IDR floor; bounding IDR transit properly
/// is the measured-rate program's job (derive the window per codec
/// from measured goodput, with a keyframe-size floor).
pub fn constrained_hrd_pct() -> usize {
    tunnel_core::env::node_env("CONSTRAINED_HRD_PCT")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(25, 200))
        .unwrap_or(200)
}

/// DIRECT-path twin of [`constrained_queue_ms`] (field 2026-08-26,
/// neo16 viewing Rozalina, LAN direct): the direct pump had a
/// frame-count send bound only, so a drag burst at a stale-high maxrate
/// queued 100–345 KB ≈ 100–300+ ms of standing latency — the "sluggish,
/// bulky" drag. Budgeting the in-flight bytes converts that lag into an
/// immediate production skip, exactly the rc.442 constrained rationale.
/// Tighter default than the relay's 450 (a LAN's round trip is ~1 ms —
/// there is no transit to hide the queue behind). Env
/// `ROOMLERD_DIRECT_QUEUE_MS` / config `direct_queue_ms`
/// (default 150, 0 = unbounded, max 2000).
pub fn direct_queue_ms() -> u64 {
    tunnel_core::env::node_env("DIRECT_QUEUE_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|v| v.min(2000))
        .unwrap_or(150)
}

/// [`direct_queue_ms`] resolved against a REFERENCE RATE into a byte
/// budget for the direct arm of the pump's backpressure gate.
///
/// FR-74 P1 — the reference is the path's rate CEILING, never the AIMD's
/// applied target. It used to be the applied target, and that made the
/// gate self-reinforcing: the operator's baseline on CORPLAP-3 (2026-09-06)
/// took six ×0.85 cuts in 16 s, and at 2.5 Mbps the budget was ~47 KB — one
/// text frame tripped it, every +605 kbps climb was cut again, and the
/// session sat at 2–3.7 Mbps for minutes. With the ceiling as the reference
/// the budget is a fixed amount of link time at the rate the path is
/// allowed to carry; a burst the wire drains passes, a real backlog still
/// trips the gate and the AIMD still cuts on that evidence. `0` for either
/// input disables the gate (`usize::MAX`). Floored at 48 KiB so a post-IDR
/// drain doesn't stall production longer than the IDR's own transit.
pub fn direct_queue_budget_bytes(rate_bps: u32) -> usize {
    direct_queue_budget_bytes_at(rate_bps, direct_queue_ms())
}

/// [`direct_queue_budget_bytes`] with the window explicit — the plan
/// producer's form (FR-70 M3a); the reader above is this applied.
pub fn direct_queue_budget_bytes_at(rate_bps: u32, queue_ms: u64) -> usize {
    if queue_ms == 0 || rate_bps == 0 {
        return usize::MAX;
    }
    (((rate_bps as u64).saturating_mul(queue_ms) / 8000) as usize).max(48 * 1024)
}

/// FR-74 P1b — the HARD byte ceiling of the direct gate: the larger of the
/// link-time budget above and the encoder's own HRD/VBV reservoir
/// (`maxrate × hrd_pct / 100`, in bytes). A burst inside the reservoir is
/// one the encoder was CONFIGURED to emit (AV1 is floored at 200 % because
/// Intel's VDENC hangs otherwise — the rc.443 incident), so gating it on
/// bytes alone made the controller cut on a burst it had itself legalised:
/// the 0.4.77 gate read on CORPLAP-3 (2026-09-07, session `6a9e5b03`)
/// tripped once on an AV1 scroll at viewer age ≤ 20 ms and took two ×0.85
/// cuts for it. Below this ceiling the gate is the MEASURED wait's call
/// (`direct_gate_trips`); at or above it the gate trips on bytes regardless.
/// `0` for the rate disables the gate, like the soft budget.
pub fn direct_queue_hard_budget_bytes(rate_bps: u32, hrd_pct: usize) -> usize {
    direct_queue_hard_budget_bytes_at(rate_bps, hrd_pct, direct_queue_ms())
}

/// [`direct_queue_hard_budget_bytes`] with the window explicit — the plan
/// producer's form (FR-70 M3a); the reader above is this applied.
pub fn direct_queue_hard_budget_bytes_at(rate_bps: u32, hrd_pct: usize, queue_ms: u64) -> usize {
    let soft = direct_queue_budget_bytes_at(rate_bps, queue_ms);
    if soft == usize::MAX {
        return usize::MAX;
    }
    let reservoir = (rate_bps as u64).saturating_mul(hrd_pct as u64) / 100 / 8;
    soft.max(reservoir as usize)
}

/// FR-74 P1b / FR-70 M3a — the HRD window an encoder opens with, from the
/// transport's base percent: `av1_*` is floored at 200 % (Intel's VDENC errors
/// on a forced IDR over the reservoir, then hangs the driver — the rc.443
/// incident). The pure half of `ffmpeg::encoder::open_hrd_pct`, which resolves
/// the base from env; the plan producer takes the base once.
pub fn hrd_pct_for(encoder_name: &str, base_pct: usize) -> usize {
    if encoder_name.starts_with("av1_") {
        base_pct.max(200)
    } else {
        base_pct
    }
}

/// FR-74 P1b — the direct gate's decision. `inflight` trips the gate when it
/// reaches the hard ceiling, or when it reaches the soft (link-time) budget
/// AND the measured send wait — enqueue→wire-complete of recent frames, or
/// the live age of the frame at the head of the queue, whichever is larger —
/// has crossed the lag bound `direct_queue_ms` denominates. Bytes on their
/// own cannot tell a burst the wire is draining (a scroll on a LAN: 30+ Mbps
/// at 10–20 ms of wait) from a backlog the viewer feels (the same bytes at
/// 150+ ms on a thin Wi-Fi); the wait can, and it is the quantity the bound
/// was always meant to cap. A budget of `usize::MAX` (no reference rate yet)
/// never trips.
pub fn direct_gate_trips(
    inflight: usize,
    soft_budget: usize,
    hard_budget: usize,
    measured_wait_ms: f64,
    lag_bound_ms: u64,
) -> bool {
    if hard_budget != usize::MAX && inflight >= hard_budget {
        return true;
    }
    soft_budget != usize::MAX && inflight >= soft_budget && measured_wait_ms >= lag_bound_ms as f64
}

/// HRD/VBV window for DIRECT sessions, as a percent of `maxrate`.
/// Default 100 — HALF the rc.234 2× window. Field 2026-08-26 (neo16
/// viewing Rozalina, hevc_qsv 2880×1800 direct): the 2× reservoir
/// legalises drag-start bursts of seconds' worth of bits, which is
/// exactly the 100–345 KB standing send queue the viewer feels as lag;
/// 1× still lets a transient spend a full second's budget (the blur fix
/// stands) while halving the worst-case queue a burst can manufacture.
///
/// ⚠ NOT applied to `av1_*` encoders — `encoder_options` floors their
/// window at 200 regardless: Intel's AV1 VDENC ERRORS (then hangs the
/// driver) on a forced IDR that exceeds the reservoir instead of
/// QP-clamping like the H.264/HEVC paths — the rc.443 incident. Env
/// `ROOMLERD_DIRECT_HRD_PCT` / config `direct_hrd_pct`
/// (clamp [25, 200]).
pub fn direct_hrd_pct() -> usize {
    tunnel_core::env::node_env("DIRECT_HRD_PCT")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(25, 200))
        .unwrap_or(100)
}

/// Real frames since the last settle that make a motion episode "a burst"
/// worth an idle-settle resync IDR. A window-drag produces hundreds; a caret
/// blink, a clock tick, or a couple of keystrokes produce 1-3 and must NOT
/// qualify. Env `ROOMLERD_SETTLE_KF_MIN_BURST` overrides; `0` restores
/// the legacy rc.187 fire-on-every-settle behaviour.
pub const SETTLE_KF_MIN_BURST: u32 = 10;

/// Minimum spacing between settle IDRs — a scroll-pause-scroll pattern
/// re-settles every second or two and shouldn't pay an IDR each time.
pub const SETTLE_KF_MIN_GAP: Duration = Duration::from_secs(5);

/// Gate for the rc.187 idle-settle keyframe (field 2026-07-27, DEVBOX viewing
/// WINHOST-B): the settle IDR fired 60 ms after EVERY real frame, and a
/// blinking text caret (Windows default ~530 ms toggle) produces a real frame
/// per toggle — a ~2 Hz forced-IDR metronome, visible as text pulsing
/// blur→crystal on every codec (worst on av1_nvenc, whose budget-capped IDRs
/// are coarsest relative to their refinement). rc.187's actual purpose — a
/// standalone resync frame after MOTION where a viewer may have dropped
/// frames — only needs the IDR after a real burst, so: fire on the first
/// settle of an episode only if the episode carried `min_burst`+ real frames
/// AND the last settle IDR is `min_gap` in the past. Isolated blips ride as
/// ordinary tiny deltas (which is all they ever were).
#[derive(Debug)]
pub struct SettleKeyframeGate {
    min_burst: u32,
    min_gap: Duration,
    /// Real frames in the current motion episode (reset at each settle).
    burst: u32,
    /// One decision per episode: set at the first settle, cleared by the
    /// next real frame. Keeps the 60 ms keepalive ticks from re-deciding.
    decided_this_episode: bool,
    last_fired: Option<Instant>,
}

impl SettleKeyframeGate {
    pub fn new(min_burst: u32, min_gap: Duration) -> Self {
        Self {
            min_burst,
            min_gap,
            burst: 0,
            decided_this_episode: false,
            last_fired: None,
        }
    }

    /// Defaults + the `ROOMLERD_SETTLE_KF_MIN_BURST` override. `0` =
    /// legacy (fire on the first settle of every episode, no cooldown).
    pub fn from_env() -> Self {
        let min_burst = tunnel_core::env::node_env("SETTLE_KF_MIN_BURST")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(SETTLE_KF_MIN_BURST);
        let min_gap = if min_burst == 0 {
            Duration::ZERO
        } else {
            SETTLE_KF_MIN_GAP
        };
        Self::new(min_burst, min_gap)
    }

    /// A real (damage-carrying) frame arrived — the episode continues.
    pub fn note_real_frame(&mut self) {
        self.burst = self.burst.saturating_add(1);
        self.decided_this_episode = false;
    }

    /// Call on every idle-keepalive tick. Returns `Some(burst)` exactly when
    /// this settle should carry the resync IDR (the burst size is for the
    /// log); `None` otherwise. The first tick of a settle consumes the
    /// episode's burst and decides; later ticks are no-ops.
    pub fn should_fire_on_settle(&mut self, now: Instant) -> Option<u32> {
        if self.decided_this_episode {
            return None;
        }
        self.decided_this_episode = true;
        let burst = std::mem::take(&mut self.burst);
        if burst < self.min_burst {
            return None;
        }
        if let Some(t) = self.last_fired
            && now.duration_since(t) < self.min_gap
        {
            return None;
        }
        self.last_fired = Some(now);
        Some(burst)
    }
}

/// P7 (2026-08-20) — idle native-rung refinement ("crisp at rest").
///
/// The Smoother/relay resolution caps trade pixels for motion smoothness —
/// but when the user STOPS to READ, the stream stays at the low rung and
/// 9-10 pt text remains mush (the display_match.rs thesis: the only truly
/// crisp chain is 1:1 end-to-end). A settled desktop costs the link nothing
/// (the 60 ms keepalive re-encodes near-zero-byte deltas at ANY rung), so:
/// once the scene settles, lift the cap → the dims-keyed encoder rebuild
/// ships one crisp native IDR (~150-400 KB ⇒ 0.4-1.1 s progressive
/// crystallize over a 3 Mbps relay; HRD bufsize 750 KB fits it); the first
/// motion burst restores the cap within ~300 ms, before the relay melts.
///
/// Pure state machine, frame-cadence signals only — dirty-rect damage was
/// rejected because only the WGC backend populates rects (scrap/DXGI emit
/// none), so damage-based motion detection would silently misbehave on the
/// main field path. `Instant`s are passed in (the FlipTracker pattern) so
/// every behaviour below is unit-tested.
///
/// P7c (field 2026-08-20, winhost-b): frame COUNTING alone made interactive
/// terminals permanently blurry — every Enter scrolls output (a genuine
/// burst → Down), then caret blinks + keystrokes produced just enough
/// frames to hold the up-block, and the 10 s any-flip cooldown finished
/// the job: five Up→Down pairs in the log, each Up dead within ~1-2 s,
/// while the user read 9-pt text at the 1024 rung. The signal was wrong,
/// not the thresholds: a keystroke delta encodes to ~0.5-3 KB where a
/// scroll/drag frame is tens-to-hundreds — so significance is now keyed
/// on ENCODED BYTES (fed post-encode by the pump). Sub-threshold frames
/// are invisible to the machine: they neither chain a run, nor fill the
/// window, nor block the up-flip. Typing at native stays crisp; a held-
/// key glyph repeat no longer chains a fake "scroll"; the up-flip lands
/// ~1 s after the last SIGNIFICANT frame even mid-typing. The threshold
/// is deliberately judged at the CURRENT rung's frame sizes: at native
/// (where down-flipping actually protects the relay) the same content
/// encodes 2-3× bigger, so real motion clears the bar there first.
///
/// Window length for the frames-per-window rate rules. Doubles as the
/// emergent settle threshold: after motion stops, the window drains in
/// exactly this long, so the up-flip fires ~1 s after the last burst.
pub const REFINE_WINDOW: Duration = Duration::from_secs(1);

/// Significant frames per window still considered "quiet" for the UP-flip.
/// Since P7c only ≥`REFINE_MIN_FRAME_KB` frames count here, so this now
/// gates sparse REPAINT trickles (a big window animation at ≤2 fps still
/// refines; at ≥3 fps it must not — each up-flip is an encoder rebuild +
/// native IDR). Caret blinks and keystrokes are sub-threshold and never
/// reach the window at all.
pub const REFINE_SPARSE_MAX: u32 = 2;

/// Frames at or above this ENCODED size are "significant" — real motion
/// (scroll, drag, animation, video). Below it: caret blinks, keystroke
/// deltas, hover highlights — invisible to the state machine. Terminal
/// text compresses hard, so a few scrolled lines at the LOW rung can duck
/// under this — harmless: the stream just refines sooner. Env
/// `ROOMLERD_IDLE_REFINE_MIN_FRAME_KB` (0 = legacy: every real frame
/// counts).
///
/// P7c-2 — the threshold is defined AT the reference rung below and
/// scaled by the CURRENT encode area (`scaled_min_bytes`). A fixed byte
/// floor is a rung-dependent OSCILLATOR: field winhost-b 2026-08-20
/// (rc.425, ~15 fps of small-animation deltas — a corp-VPN dialog's
/// countdown + page motion): the same content encoded ~4 KB at 1024×640
/// (below the floor ⇒ "quiet" ⇒ Up) and 12-16 KB at native 1920×1200
/// (above ⇒ Down within ~2 s) — an endless Up/Down pair every ~6 s, each
/// burning two rebuilds + a ~300 KB native IDR on a 3 Mbps relay. Bytes
/// per CONTENT are ~proportional to encode area, so normalizing by area
/// makes significance rung-invariant: the animation is invisible at both
/// rungs (crisp text survives a ticking dialog), while a real scroll
/// (60-300 KB at native) clears the scaled bar everywhere.
pub const REFINE_MIN_FRAME_KB: u32 = 12;

/// The encode area `REFINE_MIN_FRAME_KB` was field-calibrated at (the
/// Smoother/relay rung where P7c's typing-vs-scroll separation was
/// measured). `scaled_min_bytes` scales the configured floor by
/// `encode_area / REFINE_REF_AREA`.
pub const REFINE_REF_AREA: u64 = 1024 * 640;

/// Absolute floor for the scaled threshold (guards tiny encode rungs
/// where the area ratio would otherwise count sub-KB caret noise).
pub const REFINE_MIN_BYTES_FLOOR: usize = 2048;

/// P8a — damaged-AREA significance floor, in permille of the frame,
/// for backends that report tracked damage (DXGI-direct metadata, WGC
/// DirtyRegions). Area is rung-INVARIANT (the same content damages the
/// same fraction at any encode rung), so this leg can't oscillate the
/// way a byte floor can — and it's judged at CAPTURE time, before the
/// viewer-rate divisor skip, closing that blind spot for tracked
/// motion.
///
/// P8a-2 ("sharp all the time", user directive 2026-08-21): on tracked
/// backends this floor is now the MAJOR-motion bar — only damage
/// covering at least this fraction of the frame counts as
/// rung-dropping motion. Everything below it (typing 1-5 ‰, popups
/// 20-50 ‰, a windowed terminal scroll 200-450 ‰) **never leaves
/// native**: wire cost scales with damaged area, so a 30 %-area scroll
/// at native costs about what a full-frame scroll costs at the 1024
/// rung, and the encoder's maxrate + AIMD absorb transients via QP —
/// which motion masks. The rung drop remains an optimization for
/// sustained LARGE-area motion (video, full-window drags, full-page
/// browser scrolls) where a clean lower rung beats QP-starved native
/// and decode load matters. Consequence accepted deliberately: a small
/// PiP video keeps the stream at native (rough video region, crisp
/// text everywhere else — this is a text-first product); the four load
/// mechanisms (maxrate, AIMD, send-channel shedding, viewer-rate
/// divisor) own link protection, not the rung. Untracked backends keep
/// the byte leg unchanged. Env
/// `ROOMLERD_IDLE_REFINE_MAJOR_AREA_PERMILLE` (0 = any non-empty
/// tracked damage counts, i.e. the pre-P8a-2 posture).
pub const REFINE_MAJOR_AREA_PERMILLE: u32 = 400;

/// P8a-2 — settle threshold on the tracked (damage-truth) path: the
/// up-flip fires this long after the last MAJOR-damage frame, replacing
/// the ~1 s window-drain the bytes path needs (byte significance is
/// noisy; absent damage is not). 500 ms clears wheel-notch gaps
/// (100-400 ms) so mid-scroll pauses don't churn IDRs; the 5 s up
/// cooldown bounds what remains. Env/config `idle_refine_settle_ms`.
pub const REFINE_SETTLE_TRACKED: Duration = Duration::from_millis(500);

/// Phase B field fix (2026-08-21, winhost-a/corplap) — the tracked settle on a
/// CONSTRAINED transport. On a ~3 Mbps relay every Up→Down pair costs two
/// encoder rebuilds plus two IDRs; a 500 ms settle fires the Up on
/// ordinary drag PAUSES, so an interactive session lives in permanent IDR
/// recovery — the field "freezing / window seconds behind" report. The
/// settle should comfortably cover the refined IDR's own transmission
/// time on the link it rides. 2000 ms → 1200 ms in rc.442: the byte-
/// budget send gate now keeps the queue drained, so the IDR's transit
/// starts immediately instead of behind a motion backlog, and a typical
/// (non-worst-case) native IDR is ~250-400 KB ≈ 1-1.6 s of a ~2 Mbps
/// relay — an occasional Up during a long drag pause costs one wasted
/// IDR, accepted for the ~0.8 s crystallize win. Deriving this from
/// measured goodput is the measured-rate program's job. Direct/LAN
/// keeps the crisp 500 ms. Env/config `idle_refine_settle_constrained_ms`.
pub const REFINE_SETTLE_TRACKED_CONSTRAINED: Duration = Duration::from_millis(1200);

/// Inter-arrival gap that CHAINS a motion run (≤80 ms ⇒ ≥12.5 fps damage —
/// a scroll/drag; typing produces 100-200 ms gaps and never chains).
pub const REFINE_MOTION_GAP: Duration = Duration::from_millis(80);

/// Chained-run length that DOWN-flips a refined session: 8 frames at
/// ≥12.5 fps ≈ 270 ms of sustained motion — fast enough that a scroll
/// doesn't melt a 3 Mbps relay with native-sized deltas.
pub const REFINE_DOWN_RUN: u32 = 8;

/// Frames-per-window rate that DOWN-flips regardless of chaining — catches
/// 80-250 ms-gap motion (10-12 fps window animations) within ≤1 s. Note the
/// asymmetry with `REFINE_SPARSE_MAX`: sustained 3-9 fps damage (typing,
/// slow spinners) neither re-refines NOR down-flips — once crisp, typing
/// stays crisp; the relay carries <10 fps of native deltas fine.
pub const REFINE_RATE_DOWN: u32 = 10;

/// Minimum spacing from the last UP-flip to the next one. Bounds the
/// worst-case churn (scroll-pause-scroll) to one rebuild pair per 5 s —
/// the same bound the old any-flip form gave, but a Down no longer taxes
/// the re-refine: after a lone scroll the stream is crisp again ~1 s
/// later instead of serving the full cooldown at the blurry rung (P7c —
/// the field log showed exactly that 10 s post-scroll blur on every
/// terminal Enter).
pub const REFINE_UP_COOLDOWN: Duration = Duration::from_secs(5);

/// What the pump should do about the resolution cap this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefineFlip {
    /// Scene settled — lift the cap (encoder rebuilds at native, crisp IDR).
    Up,
    /// Motion burst — restore the cap (encoder rebuilds at the low rung).
    Down,
}

/// See the module notes above. Owned by the ffmpeg DC pump; `note_real_frame`
/// is called post-encode for every damage-carrying capture (with the frame's
/// summed packet bytes), `on_keepalive` on every idle keepalive tick (≥60 ms
/// after the last real frame by construction).
/// Which significance leg produced the most recent note — decides the
/// up-flip's settle rule (P8a-2): `Area` = damage truth, quiet is
/// unambiguous, settle in `settle_tracked`; `Bytes` = noisy proxy, keep
/// the conservative window-drain. A mid-session backend swap
/// (Dxgi↔Gdi) flips this per-note, so the rule always matches the
/// signal actually in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigKind {
    Area,
    Bytes,
}

#[derive(Debug)]
pub struct IdleRefine {
    enabled: bool,
    /// Encoded-size floor for a frame to count as motion (P7c). 0 = every
    /// real frame counts (the pre-P7c behaviour).
    min_frame_bytes: usize,
    /// MAJOR-motion area floor in permille for tracked frames (P8a-2):
    /// only damage at/above it can restore the cap; smaller damage
    /// never leaves native.
    major_area_permille: u32,
    /// Up-flip settle on the tracked path (P8a-2).
    settle_tracked: Duration,
    /// Phase B — the settle on CONSTRAINED transports (see the constant's
    /// doc: the Up must outlast its own IDR's transmission time).
    settle_tracked_constrained: Duration,
    refined: bool,
    /// Length of the current ≤`REFINE_MOTION_GAP`-chained run.
    run: u32,
    last_real: Option<Instant>,
    last_kind: Option<SigKind>,
    /// Significant-frame arrivals within the trailing `REFINE_WINDOW`.
    window: std::collections::VecDeque<Instant>,
    /// Last UP-flip (cooldown anchor — a Down deliberately doesn't gate).
    last_up: Option<Instant>,
}

impl IdleRefine {
    pub fn new(
        enabled: bool,
        min_frame_bytes: usize,
        major_area_permille: u32,
        settle_tracked: Duration,
        settle_tracked_constrained: Duration,
    ) -> Self {
        Self {
            enabled,
            min_frame_bytes,
            major_area_permille,
            settle_tracked,
            settle_tracked_constrained,
            refined: false,
            run: 0,
            last_real: None,
            last_kind: None,
            window: std::collections::VecDeque::new(),
            last_up: None,
        }
    }

    /// Kill switch `ROOMLERD_IDLE_REFINE=0` (or `false`); byte floor
    /// `ROOMLERD_IDLE_REFINE_MIN_FRAME_KB` (0 = count every real
    /// frame); major-area floor
    /// `ROOMLERD_IDLE_REFINE_MAJOR_AREA_PERMILLE` (0 = any non-empty
    /// tracked damage restores the cap — the pre-P8a-2 posture); tracked
    /// settle `ROOMLERD_IDLE_REFINE_SETTLE_MS` (clamped 100-5000).
    /// node_env so the config-surface keys reach every read.
    pub fn from_env() -> Self {
        let enabled = !matches!(
            tunnel_core::env::node_env("IDLE_REFINE")
                .as_deref()
                .map(str::trim),
            Some("0") | Some("false")
        );
        let min_kb = tunnel_core::env::node_env("IDLE_REFINE_MIN_FRAME_KB")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(REFINE_MIN_FRAME_KB);
        let major_pm = tunnel_core::env::node_env("IDLE_REFINE_MAJOR_AREA_PERMILLE")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .map(|v| v.min(1000))
            .unwrap_or(REFINE_MAJOR_AREA_PERMILLE);
        let settle = tunnel_core::env::node_env("IDLE_REFINE_SETTLE_MS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|ms| Duration::from_millis(ms.clamp(100, 5000)))
            .unwrap_or(REFINE_SETTLE_TRACKED);
        let settle_constrained = tunnel_core::env::node_env("IDLE_REFINE_SETTLE_CONSTRAINED_MS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|ms| Duration::from_millis(ms.clamp(100, 10000)))
            .unwrap_or(REFINE_SETTLE_TRACKED_CONSTRAINED);
        Self::new(
            enabled,
            min_kb as usize * 1024,
            major_pm,
            settle,
            settle_constrained,
        )
    }

    /// Whether the pump should currently run WITHOUT the resolution cap.
    pub fn refined(&self) -> bool {
        self.refined
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&t) = self.window.front() {
            if now.duration_since(t) > REFINE_WINDOW {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }

    /// The significance floor for the CURRENT encode rung: the configured
    /// per-reference-rung floor scaled by encode area (see the P7c-2 notes
    /// on `REFINE_MIN_FRAME_KB` — a fixed floor oscillates across rungs).
    /// `min_frame_bytes == 0` stays 0 (legacy count-everything).
    fn scaled_min_bytes(&self, encode_area: u64) -> usize {
        if self.min_frame_bytes == 0 || encode_area == 0 {
            return self.min_frame_bytes;
        }
        let scaled = (self.min_frame_bytes as u64)
            .saturating_mul(encode_area)
            .div_ceil(REFINE_REF_AREA);
        (scaled as usize).max(REFINE_MIN_BYTES_FLOOR)
    }

    /// A real (damage-carrying) frame was encoded to `encoded_bytes` on the
    /// wire at `encode_area` pixels — the BYTES significance leg. Returns
    /// `Some(Down)` exactly when a refined session must drop back to the
    /// capped rung. Sub-threshold frames (caret, keystrokes, hover
    /// highlights, small persistent animations — judged against the
    /// rung-scaled floor) are ignored entirely: they don't chain the run,
    /// fill the window, or block the up-flip.
    pub fn note_real_frame(
        &mut self,
        now: Instant,
        encoded_bytes: usize,
        encode_area: u64,
    ) -> Option<RefineFlip> {
        if !self.enabled || encoded_bytes < self.scaled_min_bytes(encode_area) {
            return None;
        }
        self.note_significant(now, SigKind::Bytes)
    }

    /// P8a — the AREA significance leg, for frames whose backend reported
    /// tracked damage. Fed at CAPTURE time (before the viewer-rate divisor
    /// skip — tracked motion counts even when the frame is shed), with the
    /// damaged area in permille of the frame. Area is rung-invariant, so
    /// this leg cannot oscillate across encode rungs. P8a-2: only MAJOR
    /// damage (≥ `major_area_permille`) counts — smaller damage never
    /// restores the cap, so text work stays at native straight through its
    /// own scrolls. Empty damage (0 ‰) never counts. Tracked frames never
    /// take the bytes leg (the pump routes on `Damage::Tracked`, not on
    /// this floor).
    pub fn note_real_frame_area(&mut self, now: Instant, area_permille: u32) -> Option<RefineFlip> {
        if !self.enabled || !self.area_major(area_permille) {
            return None;
        }
        self.note_significant(now, SigKind::Area)
    }

    /// Whether tracked damage of `area_permille` is MAJOR motion (can
    /// restore the cap). The pump uses this for its flip log; sub-major
    /// tracked damage is invisible to the machine entirely.
    pub fn area_major(&self, area_permille: u32) -> bool {
        area_permille > 0 && area_permille >= self.major_area_permille
    }

    /// Whether `encoded_bytes` at `encode_area` clears the (rung-scaled)
    /// bytes floor — the pump uses this to route a frame to the bytes
    /// leg vs the QUIET tick (see the field note on `on_keepalive`).
    pub fn bytes_significant(&self, encoded_bytes: usize, encode_area: u64) -> bool {
        encoded_bytes >= self.scaled_min_bytes(encode_area)
    }

    /// Shared core of both significance legs: chain the run, fill the
    /// window, and Down-flip a refined session under sustained motion.
    fn note_significant(&mut self, now: Instant, kind: SigKind) -> Option<RefineFlip> {
        self.run = match self.last_real {
            Some(t) if now.duration_since(t) <= REFINE_MOTION_GAP => self.run.saturating_add(1),
            _ => 1,
        };
        self.last_real = Some(now);
        self.last_kind = Some(kind);
        self.prune(now);
        // Bounded: pruning keeps this at ~fps entries; the hard cap only
        // matters if a backend ever bursts far above real time.
        if self.window.len() >= 240 {
            self.window.pop_front();
        }
        self.window.push_back(now);
        if self.refined
            && (self.run >= REFINE_DOWN_RUN || self.window.len() as u32 >= REFINE_RATE_DOWN)
        {
            self.refined = false;
            return Some(RefineFlip::Down);
        }
        None
    }

    /// A QUIET tick: an idle keepalive, OR a real frame that neither
    /// significance leg noted (field corplap-3, 2026-08-21: GDI/scrap-
    /// class backends return a "real" frame on EVERY poll — `frames_empty=0`
    /// — so the keepalive arm never ran and refine was structurally inert;
    /// judging quiet by the SIGNAL — 48-byte encodes of a still screen —
    /// instead of capture cadence also lets the up-flip fire DURING
    /// sustained sub-major motion on tracked backends, completing the
    /// P8a-2 stay-native promise in the un-refined direction).
    ///
    /// `eligible` = a cap below native is currently
    /// in force AND the scope rules allow refinement (see
    /// `encode::idle_refine_applies`; the pump also requires the controller
    /// to have left resolution at Native — an explicit pick is the user's).
    /// Returns `Some(Up)` when the cap should lift; `eligible=false` clears
    /// `refined` silently (the cap situation changed externally — e.g. the
    /// dial moved to Sharper — so there is nothing to restore).
    pub fn on_keepalive(
        &mut self,
        eligible: bool,
        constrained: bool,
        now: Instant,
    ) -> Option<RefineFlip> {
        if !self.enabled {
            return None;
        }
        self.prune(now);
        if !eligible {
            // Phase B field fix — this reset used to be SILENT, which made
            // an eligibility flap look like an unexplained double-Up in the
            // field log. State changes must be visible.
            if self.refined {
                tracing::debug!(
                    "idle refine: eligibility lost while refined — resolution cap re-engages"
                );
            }
            self.refined = false;
            return None;
        }
        if self.refined {
            return None;
        }
        // P8a-2 — the settle rule depends on the signal in force. Damage
        // truth (Area): quiet is unambiguous — no MAJOR damage for the
        // settle window means the scene is still; fire without waiting
        // for the 1 s window drain. Bytes (or no note yet): keep the
        // conservative sparse-window rule (byte significance is noisy).
        // Phase B — the settle is TRANSPORT-AWARE: on a constrained relay
        // the refined IDR itself costs ~0.5-1 s of link time, so a 500 ms
        // settle fired on ordinary drag pauses and kept the session in
        // permanent IDR recovery (field 2026-08-21: "freezing / window
        // seconds behind" on winhost-a/corplap).
        let settle = if constrained {
            self.settle_tracked_constrained
        } else {
            self.settle_tracked
        };
        let quiet = match self.last_kind {
            Some(SigKind::Area) => self
                .last_real
                .is_none_or(|t| now.duration_since(t) >= settle),
            _ => self.window.len() as u32 <= REFINE_SPARSE_MAX,
        };
        if quiet
            && self
                .last_up
                .is_none_or(|t| now.duration_since(t) >= REFINE_UP_COOLDOWN)
        {
            self.refined = true;
            self.last_up = Some(now);
            // Fresh episode: the burst that preceded this settle must not
            // count toward the next Down (a stale ≥10-entry window would
            // let a single new frame down-flip immediately). Resumed real
            // motion re-downs via a fresh 8-frame run in ~270 ms.
            self.window.clear();
            self.run = 0;
            return Some(RefineFlip::Up);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-70 M3a — the explicit-window forms the plan producer calls are the
    /// per-frame readers' arithmetic exactly, whatever the window says, and
    /// at the shipped defaults they are the shipped constants.
    #[test]
    fn the_budget_readers_equal_their_explicit_window_forms() {
        let cms = constrained_queue_ms();
        let dms = direct_queue_ms();
        for rate in [0, 1, 200_000, 395_000, 3_000_000, 43_000_000, u32::MAX] {
            assert_eq!(
                constrained_queue_budget_bytes(rate),
                constrained_queue_budget_bytes_at(rate, cms)
            );
            assert_eq!(
                direct_queue_budget_bytes(rate),
                direct_queue_budget_bytes_at(rate, dms)
            );
            for hrd in [25, 100, 200] {
                assert_eq!(
                    direct_queue_hard_budget_bytes(rate, hrd),
                    direct_queue_hard_budget_bytes_at(rate, hrd, dms)
                );
            }
        }
        assert_eq!(constrained_queue_budget_bytes_at(3_000_000, 450), 168_750);
        assert_eq!(
            constrained_queue_budget_bytes_at(1, 450),
            CONSTRAINED_QUEUE_MIN_BYTES
        );
        assert_eq!(constrained_queue_budget_bytes_at(3_000_000, 0), usize::MAX);
        assert_eq!(direct_queue_budget_bytes_at(43_000_000, 150), 806_250);
        assert_eq!(direct_queue_budget_bytes_at(1, 150), 48 * 1024);
        assert_eq!(
            direct_queue_hard_budget_bytes_at(43_000_000, 100, 150),
            5_375_000
        );
        assert_eq!(
            direct_queue_hard_budget_bytes_at(43_000_000, 200, 150),
            10_750_000
        );
        assert_eq!(direct_queue_hard_budget_bytes_at(0, 100, 150), usize::MAX);
        assert_eq!(
            direct_queue_hard_budget_bytes_at(43_000_000, 100, 0),
            usize::MAX
        );
    }

    #[test]
    fn hrd_pct_for_floors_only_av1_at_200() {
        assert_eq!(hrd_pct_for("av1_qsv", 100), 200);
        assert_eq!(hrd_pct_for("av1_nvenc", 200), 200);
        assert_eq!(hrd_pct_for("hevc_qsv", 100), 100);
        assert_eq!(hrd_pct_for("hevc_nvenc", 75), 75);
        assert_eq!(hrd_pct_for("", 100), 100);
    }

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn flip_needs_two_consecutive_observations() {
        let mut f = FlipTracker::new(true); // built for relay
        let now = t0();
        assert_eq!(f.observe(false, now), None); // 1st direct sighting
        assert_eq!(f.observe(false, now), Some(false)); // 2nd → rebuild
        // Now built for direct; steady state is quiet.
        assert_eq!(f.observe(false, now), None);
    }

    #[test]
    fn a_single_flap_never_rebuilds() {
        let mut f = FlipTracker::new(true);
        let now = t0();
        assert_eq!(f.observe(false, now), None); // blip
        assert_eq!(f.observe(true, now), None); // back to stable → reset
        assert_eq!(f.observe(false, now), None); // count restarts at 1
        assert_eq!(f.observe(false, now), Some(false));
    }

    #[test]
    fn direction_change_mid_count_restarts_the_count() {
        let mut f = FlipTracker::new(false); // built for direct
        let now = t0();
        assert_eq!(f.observe(true, now), None); // relay ×1
        // (a detected==stable in between resets; tested above — here we jump
        // straight to a second relay sighting)
        assert_eq!(f.observe(true, now), Some(true));
    }

    #[test]
    fn cooldown_defers_but_does_not_lose_a_persisted_flip() {
        let mut f = FlipTracker::new(true);
        let now = t0();
        assert_eq!(f.observe(false, now), None);
        assert_eq!(f.observe(false, now), Some(false)); // rebuild at `now`
        // Path flips back to relay 10 s later — persisted, but inside the
        // 60 s cooldown → deferred.
        let later = now + Duration::from_secs(10);
        assert_eq!(f.observe(true, later), None);
        assert_eq!(f.observe(true, later), None); // count satisfied, cooldown blocks
        // After the cooldown the very next observation fires.
        let after = now + FLIP_REBUILD_COOLDOWN + Duration::from_secs(1);
        assert_eq!(f.observe(true, after), Some(true));
    }

    /// One test fn on purpose: the override assertions mutate process env
    /// and cargo runs #[test] fns in parallel threads.
    #[test]
    fn codec_factor_defaults_and_env_override() {
        // RELAY_ENV_LOCK, not "no other test touches these": `policy::tests`
        // READS `RATE_FACTOR_HEVC` through `rate_plan` and pins the ceilings it
        // produces, under this same lock. A write here between two of its reads
        // flips them (factor 50 puts a relay ceiling under the 3 Mbps clamp).
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _saved = tunnel_core::env::test_env::Saved::cleared("RATE_FACTOR_HEVC");
        // Built-in matrix (2026-07-28: HEVC 100 → 125, field-measured).
        assert_eq!(codec_rate_factor_pct("H264"), 150);
        assert_eq!(codec_rate_factor_pct("HEVC"), 125);
        assert_eq!(codec_rate_factor_pct("VP9"), 125);
        assert_eq!(codec_rate_factor_pct("AV1"), 100);

        // SAFETY: serialised by RELAY_ENV_LOCK against every test that reads
        // `RATE_FACTOR_*` (set_var is unsafe in edition 2024 because of
        // cross-thread env races).
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_HEVC", "140") };
        assert_eq!(codec_rate_factor_pct("HEVC"), 140);
        // Clamped to 50–400.
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_HEVC", "10") };
        assert_eq!(codec_rate_factor_pct("HEVC"), 50);
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_HEVC", "9000") };
        assert_eq!(codec_rate_factor_pct("HEVC"), 400);
        // Garbage falls back to the built-in.
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_HEVC", "fast") };
        assert_eq!(codec_rate_factor_pct("HEVC"), 125);
        unsafe { tunnel_core::env::test_env::clear("RATE_FACTOR_HEVC") };
        // Other codecs untouched by the HEVC var.
        assert_eq!(codec_rate_factor_pct("H264"), 150);
    }

    /// FR-77 P3 — the chroma column: 100 for 4:2:0 always; 150 built-in for
    /// a 4:4:4 cell, per-codec override through the `_444` twin of the codec
    /// factor, clamped and garbage-tolerant like it. One fn on purpose: env.
    #[test]
    fn chroma_column_defaults_and_env_override() {
        // Same lock as the codec column: `rate_plan` multiplies this factor in,
        // so any `policy::tests` case at a VP9 4:4:4 cell would read what this
        // writes. None exists today (they are all HEVC); the lock keeps that an
        // accident nobody has to remember.
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _saved = tunnel_core::env::test_env::Saved::cleared("RATE_FACTOR_VP9_444");
        for codec in ["H264", "HEVC", "VP9"] {
            assert_eq!(chroma_rate_factor_pct(codec, false), 100);
            assert_eq!(chroma_rate_factor_pct(codec, true), 150);
        }
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_VP9_444", "120") };
        assert_eq!(chroma_rate_factor_pct("VP9", true), 120);
        assert_eq!(
            chroma_rate_factor_pct("VP9", false),
            100,
            "4:2:0 never reads the column"
        );
        assert_eq!(
            chroma_rate_factor_pct("HEVC", true),
            150,
            "another codec's column is untouched"
        );
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_VP9_444", "10") };
        assert_eq!(chroma_rate_factor_pct("VP9", true), 50);
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_VP9_444", "9000") };
        assert_eq!(chroma_rate_factor_pct("VP9", true), 400);
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "RATE_FACTOR_VP9_444", "crisp") };
        assert_eq!(chroma_rate_factor_pct("VP9", true), 150);
        unsafe { tunnel_core::env::test_env::clear("RATE_FACTOR_VP9_444") };
        assert_eq!(chroma_rate_factor_pct("VP9", true), 150);
    }

    #[test]
    fn qsv_config_grants_long_gop_only_for_a_measured_honouring_mode() {
        // Unprobed → rc.219 containment.
        assert_eq!(vp9_qsv_config(None, None), (false, true));
        // Both modes honour → prefer low_power.
        assert_eq!(vp9_qsv_config(Some((true, true)), None), (true, true));
        // Only VDEnc honours.
        assert_eq!(vp9_qsv_config(Some((true, false)), None), (true, true));
        // Only VME (low_power=0) honours → long GOP on VME.
        assert_eq!(vp9_qsv_config(Some((false, true)), None), (true, false));
        // Neither honours → containment.
        assert_eq!(vp9_qsv_config(Some((false, false)), None), (false, true));
    }

    #[test]
    fn qsv_config_operator_override_wins_on_mode_but_not_on_gop_safety() {
        // Forced VME on a host whose VME honours → long GOP.
        assert_eq!(
            vp9_qsv_config(Some((false, true)), Some(false)),
            (true, false)
        );
        // Forced VDEnc on a host whose VDEnc ignores → containment GOP, VDEnc.
        assert_eq!(
            vp9_qsv_config(Some((false, true)), Some(true)),
            (false, true)
        );
        // Forced anything without a verdict → containment GOP in that mode.
        assert_eq!(vp9_qsv_config(None, Some(false)), (false, false));
        assert_eq!(vp9_qsv_config(None, Some(true)), (false, true));
    }

    // P7 — chroma factor composes multiplicatively with the codec factor.
    #[test]
    fn chroma_factor_composes_with_codec_factor() {
        assert_eq!(chroma_rate_factor_pct("HEVC", true), 150);
        assert_eq!(chroma_rate_factor_pct("HEVC", false), 100);
        // The pump's compose rule at the HEVC built-in (125): 4:4:4 → 187 %
        // of the base band; 4:2:0 leaves it unchanged. Literals only — the
        // codec-factor env test above mutates ROOMLERD_RATE_FACTOR_HEVC
        // and cargo runs tests in parallel threads.
        assert_eq!(125 * chroma_rate_factor_pct("HEVC", true) / 100, 187);
        assert_eq!(125 * chroma_rate_factor_pct("HEVC", false) / 100, 125);
    }

    #[test]
    fn h264_cq_is_two_steps_sharper_with_a_floor() {
        assert_eq!(h264_cq_adjust("h264_nvenc", 22), 20);
        assert_eq!(h264_cq_adjust("h264_qsv", 11), 10);
        assert_eq!(h264_cq_adjust("h264_amf", 10), 10);
        assert_eq!(h264_cq_adjust("hevc_qsv", 22), 22);
        assert_eq!(h264_cq_adjust("vp9_qsv", 22), 22);
    }

    // P7 — scale-aware CQ bias ladder.
    #[test]
    fn scale_cq_bias_full_at_smoother_rung() {
        // 1920×1200 → 1024×640 = 28% area; 2560×1600 → 1024×640 = 16%.
        assert_eq!(scale_cq_bias(1024, 640, 1920, 1200, 4), 4);
        assert_eq!(scale_cq_bias(1024, 640, 2560, 1600, 4), 4);
    }

    #[test]
    fn scale_cq_bias_half_at_relay_rung() {
        // 1920×1200 → 1280×800 = 44% area.
        assert_eq!(scale_cq_bias(1280, 800, 1920, 1200, 4), 2);
    }

    #[test]
    fn scale_cq_bias_zero_near_native() {
        // Snap-native leftovers and small trims spend nothing (1836×1148 =
        // 91% area), and equal dims are exactly zero.
        assert_eq!(scale_cq_bias(1836, 1148, 1920, 1200, 4), 0);
        assert_eq!(scale_cq_bias(1920, 1200, 1920, 1200, 4), 0);
    }

    #[test]
    fn scale_cq_bias_zero_dims_and_zero_steps_safe() {
        // Unpublished native dims (0) or a disabled knob (max_steps 0)
        // must never bias.
        assert_eq!(scale_cq_bias(1024, 640, 0, 0, 4), 0);
        assert_eq!(scale_cq_bias(0, 0, 1920, 1200, 4), 0);
        assert_eq!(scale_cq_bias(1024, 640, 1920, 1200, 0), 0);
        assert_eq!(scale_cq_bias(1280, 800, 1920, 1200, 0), 0);
    }

    #[test]
    fn cq_bias_composes_with_h264_adjust_at_the_floor() {
        // Floor is shared: 14 → 12 (h264) → 10 (bias clamps at the floor).
        assert_eq!(apply_cq_bias(h264_cq_adjust("h264_nvenc", 14), 4), 10);
        // Nominal cases: 22 → 20 (h264) → 16; HEVC skips the codec adjust.
        assert_eq!(apply_cq_bias(h264_cq_adjust("h264_nvenc", 22), 4), 16);
        assert_eq!(apply_cq_bias(h264_cq_adjust("hevc_nvenc", 22), 4), 18);
    }

    #[test]
    fn negative_cq_bias_softens_and_clamps_at_the_ceiling() {
        // Constrained-motion relief: negative steps ADD (soften).
        assert_eq!(apply_cq_bias(22, -4), 26);
        assert_eq!(apply_cq_bias(h264_cq_adjust("h264_qsv", 22), -4), 24);
        // The shared [10, 40] bounds hold in both directions.
        assert_eq!(apply_cq_bias(38, -6), 40);
        assert_eq!(apply_cq_bias(12, 6), 10);
        assert_eq!(apply_cq_bias(22, 0), 22);
    }

    /// FR-59 P5 — the profile engages only on REMEMBERED evidence that the
    /// pair is slow, and a pair with no memory opens exactly as before.
    #[test]
    fn the_slow_link_profile_engages_only_on_a_remembered_slow_pair() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The field pair: 395 kbps remembered ⇒ fewer pixels, fewer frames.
        let p = slow_link_profile(Some(395_122), true).expect("engages");
        assert_eq!(p.max_long_edge, 1280);
        assert_eq!(p.max_fps, 15);
        // A healthy relay is untouched.
        assert_eq!(slow_link_profile(Some(3_000_000), true), None);
        // ⚠ No memory is NOT evidence of a slow link — guessing soft would
        // degrade the FIRST session on every healthy relay.
        assert_eq!(slow_link_profile(None, true), None);
        assert_eq!(slow_link_profile(Some(0), true), None);
        // Kill switch.
        assert_eq!(slow_link_profile(Some(395_122), false), None);
    }

    /// FR-59 P2 — the reference rate is one-directional: a measurement may
    /// LOWER what the budget is denominated in, never raise it, and the
    /// kill switch restores the nominal ceiling verbatim.
    #[test]
    fn constrained_queue_reference_only_ever_lowers() {
        // The field case: a 3 Mbps nominal against a measured 395 kbps.
        assert_eq!(
            constrained_queue_reference_bps(3_000_000, Some(395_122), true),
            395_122
        );
        // A measurement ABOVE the ceiling never widens the budget — the
        // ceiling is still the rate the encoder is allowed to produce at.
        assert_eq!(
            constrained_queue_reference_bps(3_000_000, Some(9_000_000), true),
            3_000_000
        );
        // No estimate held (early session, idle link) ⇒ nominal.
        assert_eq!(
            constrained_queue_reference_bps(3_000_000, None, true),
            3_000_000
        );
        // A zero measurement is not evidence, it is the absence of it.
        assert_eq!(
            constrained_queue_reference_bps(3_000_000, Some(0), true),
            3_000_000
        );
        // Kill switch: the pre-FR-59 posture, ignoring a real measurement.
        assert_eq!(
            constrained_queue_reference_bps(3_000_000, Some(395_122), false),
            3_000_000
        );
    }

    #[test]
    fn constrained_queue_budget_resolves_ms_of_ceiling() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Default 450 ms of a 3 Mbps ceiling = 168,750 bytes.
        assert_eq!(constrained_queue_budget_bytes(3_000_000), 168_750);
        // Scales with the ceiling.
        assert_eq!(constrained_queue_budget_bytes(1_000_000), 56_250);
        // FR-59 P2 — the field reference: 450 ms of a MEASURED 395 kbps
        // pipe is 22,225 bytes, not the 168,750 the nominal band claimed.
        assert_eq!(constrained_queue_budget_bytes(395_122), 22_225);
        // …and an absurd reference stops at one SCTP chunk rather than
        // gating before a single frame can be in flight.
        assert_eq!(
            constrained_queue_budget_bytes(50_000),
            CONSTRAINED_QUEUE_MIN_BYTES
        );
        // Default knobs (env-free): relief 4 softening steps; HRD default
        // 200 (rc.443 — a sub-1× window killed av1_qsv on its settle IDR,
        // see `constrained_hrd_pct`).
        assert_eq!(constrained_cq_relief(), 4);
        assert_eq!(constrained_hrd_pct(), 200);
    }

    #[test]
    fn direct_queue_budget_and_hrd_defaults() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Default 150 ms of an 8 Mbps reference = 150,000 bytes.
        assert_eq!(direct_queue_budget_bytes(8_000_000), 150_000);
        // Floored at 48 KiB so a collapsed target can't stall production
        // longer than an IDR's own transit.
        assert_eq!(direct_queue_budget_bytes(1_500_000), 48 * 1024);
        // No reference rate yet (pre-first-frame) = unbounded gate.
        assert_eq!(direct_queue_budget_bytes(0), usize::MAX);
        // Direct HRD default is 1× maxrate; constrained keeps the rc.234 2×.
        assert_eq!(direct_hrd_pct(), 100);
    }

    /// FR-74 P1b — the hard ceiling is the encoder's reservoir when that is
    /// larger than the link-time budget, and the gate below it is the
    /// measured wait's call: a LAN scroll (bytes over the soft budget, wait
    /// small) passes; a thin-wire backlog (same bytes, wait over the bound)
    /// trips; the reservoir trips on bytes alone; no reference rate never trips.
    #[test]
    fn direct_gate_is_the_measured_waits_call_below_the_reservoir() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // 34.56 Mbps AV1 direct (0.4.77 defaults on CORPLAP-3): soft = 150 ms
        // = 648,000 bytes; the AV1 reservoir (200 %) = 8,640,000 bytes.
        let soft = direct_queue_budget_bytes(34_560_000);
        assert_eq!(soft, 648_000);
        let hard = direct_queue_hard_budget_bytes(34_560_000, 200);
        assert_eq!(hard, 8_640_000);
        // A codec at 100 % on a small rung: the reservoir (375 KB at 3 Mbps)
        // still exceeds the 56 KB soft budget, so the hard ceiling is it.
        assert_eq!(direct_queue_hard_budget_bytes(3_000_000, 100), 375_000);
        // ... and where the reservoir is SMALLER than the soft budget, the
        // soft budget stays the ceiling (the gate can never be stricter than P1).
        assert_eq!(direct_queue_hard_budget_bytes(8_000_000, 25), 250_000);
        assert_eq!(direct_queue_budget_bytes(8_000_000), 150_000);
        assert_eq!(direct_queue_hard_budget_bytes(0, 200), usize::MAX);
        let bound = direct_queue_ms();
        assert_eq!(bound, 150);
        // The 0.4.77 residual: 1.2 MB in flight on the scroll, 20 ms of wait.
        assert!(!direct_gate_trips(1_200_000, soft, hard, 20.0, bound));
        // The same bytes on a wire that is not keeping up.
        assert!(direct_gate_trips(1_200_000, soft, hard, 150.0, bound));
        // Below the soft budget the wait alone never gates.
        assert!(!direct_gate_trips(600_000, soft, hard, 400.0, bound));
        // At the reservoir, bytes gate regardless of the wait.
        assert!(direct_gate_trips(8_640_000, soft, hard, 0.0, bound));
        // No reference rate yet: nothing gates.
        assert!(!direct_gate_trips(
            50_000_000,
            usize::MAX,
            usize::MAX,
            5_000.0,
            bound
        ));
    }

    /// FR-74 P1 — the direct ceiling is the content-generous bound P0 measured
    /// clean (40 Mbps on CORPLAP-3: 0 cuts, 0 skips on AV1 / VP9 4:2:0 /
    /// H.264 scrolls); the constrained branch is unchanged, relay clamp and all.
    #[test]
    fn direct_ceiling_is_content_generous_and_the_relay_band_is_unchanged() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // 1920×1200 @ 60, factor 100: 0.25 bpp/s = 34.56 Mbps, inside [3, 48].
        assert_eq!(
            ffmpeg_maxrate_bps_scaled(1920, 1200, 60, false, 100),
            34_560_000
        );
        // H.264's 150 % factor scales the rate and the band together: 51.84 M
        // inside [4.5, 72] M.
        assert_eq!(
            ffmpeg_maxrate_bps_scaled(1920, 1200, 60, false, 150),
            51_840_000
        );
        // A 4K panel at 60 fps hits the 48 M top of the band.
        assert_eq!(
            ffmpeg_maxrate_bps_scaled(3840, 2160, 60, false, 100),
            48_000_000
        );
        // A small rung stays on the 3 M floor.
        assert_eq!(
            ffmpeg_maxrate_bps_scaled(640, 400, 30, false, 100),
            3_000_000
        );
        // Constrained: the 0.07 / [3, 12] band, then the relay clamp — the
        // 2026-09-05 fleet's relay sessions see exactly what they saw.
        let relay = crate::encode::relay_max_bps() as usize;
        assert_eq!(
            ffmpeg_maxrate_bps_scaled(1920, 1200, 60, true, 100),
            9_676_800.min(relay)
        );
        assert_eq!(
            ffmpeg_maxrate_bps_scaled(1920, 1200, 30, true, 125),
            6_048_000.min(relay)
        );
    }

    /// FR-119 P2a — at or below 60 fps the law is today's, byte for byte: the
    /// old formula, inlined here, against the new one across geometries,
    /// rates, transports and codec factors.
    #[test]
    fn the_rate_law_is_byte_identical_at_and_below_60() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let relay = crate::encode::relay_max_bps() as usize;
        let old = |w: u32, h: u32, fps: u32, constrained: bool, factor: usize| -> usize {
            let (bpp, top) = if constrained {
                (0.07, 12_000_000_usize)
            } else {
                (0.25, 48_000_000_usize)
            };
            let raw = (w as f64 * h as f64 * fps as f64 * bpp) as usize;
            let raw = raw.saturating_mul(factor) / 100;
            let clamped = raw.clamp(
                3_000_000_usize.saturating_mul(factor) / 100,
                top.saturating_mul(factor) / 100,
            );
            if constrained {
                clamped.min(relay)
            } else {
                clamped
            }
        };
        for (w, h) in [
            (640, 400),
            (1280, 800),
            (1920, 1080),
            (1920, 1200),
            (2560, 1600),
            (2880, 1800),
            (3840, 2160),
        ] {
            for fps in [1, 15, 24, 30, 45, 59, 60] {
                for constrained in [false, true] {
                    for factor in [100, 125, 150] {
                        assert_eq!(
                            ffmpeg_maxrate_bps_scaled(w, h, fps, constrained, factor),
                            old(w, h, fps, constrained, factor),
                            "{w}x{h}@{fps} constrained={constrained} factor={factor}"
                        );
                    }
                }
            }
        }
    }

    /// FR-119 P2a — above 60 the rate and the band's top follow (fps/60)^0.8.
    #[test]
    fn above_60_the_rate_law_follows_alpha() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(rate_law_fps(60), 60.0);
        let r120 = rate_law_fps(120) / 60.0; // 2^0.8
        assert!((r120 - 1.7411).abs() < 1e-3, "{r120}");
        let r144 = rate_law_fps(144) / 60.0; // 2.4^0.8
        assert!((r144 - 2.0145).abs() < 1e-3, "{r144}");
        // 1920×1080 at 144: 31.1 M × 2.0145 = 62.7 M, under the class's top
        // (48 M × 2.0145 = 96.7 M). Today's law clamped it to 48 M.
        let hd144 = ffmpeg_maxrate_bps_scaled(1920, 1080, 144, false, 100);
        assert!((62_000_000..63_500_000).contains(&hd144), "{hd144}");
        // 4K at 144 reaches the class's top, ~96.7 M, where today's gave 48 M.
        let uhd144 = ffmpeg_maxrate_bps_scaled(3840, 2160, 144, false, 100);
        assert!((96_000_000..97_500_000).contains(&uhd144), "{uhd144}");
        // Per frame, 120 fps gets less than 60 (frames closer together need
        // less), 2^0.8 / 2 = 0.87 of it, not the 0.5 a fixed band gives.
        let per_frame =
            |fps: u32| ffmpeg_maxrate_bps_scaled(1920, 1080, fps, false, 100) as f64 / fps as f64;
        let ratio = per_frame(120) / per_frame(60);
        assert!((0.86..0.88).contains(&ratio), "{ratio}");
    }

    fn gate() -> SettleKeyframeGate {
        SettleKeyframeGate::new(SETTLE_KF_MIN_BURST, SETTLE_KF_MIN_GAP)
    }

    #[test]
    fn caret_blink_never_fires_a_settle_keyframe() {
        // The field pattern: one real frame per caret toggle (~530 ms), a
        // settle 60 ms later, repeated forever. Pre-gate this forced ~2 IDRs
        // per second; the gate must fire ZERO.
        let mut g = gate();
        let mut now = t0();
        for _ in 0..20 {
            g.note_real_frame(); // the toggle's single damage frame
            assert_eq!(g.should_fire_on_settle(now), None); // settle +60 ms
            // keepalive ticks between toggles decide nothing further
            assert_eq!(g.should_fire_on_settle(now), None);
            now += Duration::from_millis(530);
        }
    }

    #[test]
    fn a_drag_burst_fires_exactly_once_on_the_first_settle() {
        let mut g = gate();
        let now = t0();
        for _ in 0..60 {
            g.note_real_frame(); // 1 s of real motion
        }
        assert_eq!(g.should_fire_on_settle(now), Some(60)); // first settle → IDR
        assert_eq!(g.should_fire_on_settle(now), None); // 60 ms later: nothing
        assert_eq!(g.should_fire_on_settle(now), None);
    }

    #[test]
    fn typing_trickle_below_the_burst_threshold_stays_quiet() {
        let mut g = gate();
        let now = t0();
        for _ in 0..(SETTLE_KF_MIN_BURST - 1) {
            g.note_real_frame();
        }
        assert_eq!(g.should_fire_on_settle(now), None);
        // The undersized burst is consumed, not accumulated: another small
        // trickle still doesn't reach the threshold.
        for _ in 0..(SETTLE_KF_MIN_BURST - 1) {
            g.note_real_frame();
        }
        assert_eq!(g.should_fire_on_settle(now), None);
    }

    #[test]
    fn cooldown_suppresses_a_second_burst_settle() {
        let mut g = gate();
        let now = t0();
        for _ in 0..30 {
            g.note_real_frame();
        }
        assert_eq!(g.should_fire_on_settle(now), Some(30));
        // Scroll-pause-scroll 2 s later: burst qualifies, cooldown blocks.
        let later = now + Duration::from_secs(2);
        for _ in 0..30 {
            g.note_real_frame();
        }
        assert_eq!(g.should_fire_on_settle(later), None);
        // Past the cooldown a fresh burst fires again.
        let after = now + SETTLE_KF_MIN_GAP + Duration::from_secs(1);
        for _ in 0..30 {
            g.note_real_frame();
        }
        assert_eq!(g.should_fire_on_settle(after), Some(30));
    }

    #[test]
    fn legacy_hatch_min_burst_zero_fires_every_episode() {
        // min_burst 0 + zero gap = rc.187 behaviour: first settle of EVERY
        // episode fires, keepalive ticks after it don't.
        let mut g = SettleKeyframeGate::new(0, Duration::ZERO);
        let mut now = t0();
        for _ in 0..5 {
            g.note_real_frame();
            assert!(g.should_fire_on_settle(now).is_some());
            assert_eq!(g.should_fire_on_settle(now), None); // same episode
            now += Duration::from_millis(530);
        }
    }

    // ── P7 — IdleRefine ────────────────────────────────────────────────

    /// A scroll/drag-sized encoded frame (well above the significance
    /// threshold at any rung).
    const BIG: usize = 50_000;
    /// A keystroke/caret-sized encoded frame (well below it).
    const SMALL: usize = 2_000;

    fn refine() -> IdleRefine {
        IdleRefine::new(
            true,
            REFINE_MIN_FRAME_KB as usize * 1024,
            REFINE_MAJOR_AREA_PERMILLE,
            REFINE_SETTLE_TRACKED,
            REFINE_SETTLE_TRACKED_CONSTRAINED,
        )
    }

    /// Drive `n` real frames of `bytes` at a fixed `gap`, asserting no Down
    /// fires.
    fn feed_quiet(
        r: &mut IdleRefine,
        mut now: Instant,
        n: u32,
        gap: Duration,
        bytes: usize,
    ) -> Instant {
        for _ in 0..n {
            assert_eq!(r.note_real_frame(now, bytes, REFINE_REF_AREA), None);
            now += gap;
        }
        now
    }

    /// Keepalives every 60 ms until the first Up (or `limit` elapses);
    /// returns (time of the Up, elapsed since start).
    fn tick_until_up(
        r: &mut IdleRefine,
        mut now: Instant,
        limit: Duration,
    ) -> Option<(Instant, Duration)> {
        let start = now;
        while now.duration_since(start) <= limit {
            if r.on_keepalive(true, false, now) == Some(RefineFlip::Up) {
                return Some((now, now.duration_since(start)));
            }
            now += Duration::from_millis(60);
        }
        None
    }

    #[test]
    fn refine_fires_about_1s_after_a_scroll_settles() {
        let mut r = refine();
        // 1 s scroll at 30 fps.
        let now = feed_quiet(&mut r, t0(), 30, Duration::from_millis(33), BIG);
        // Keepalives start 60 ms after the last real frame; the window must
        // drain (~1 s) before the up-flip fires.
        let (_, elapsed) = tick_until_up(&mut r, now, Duration::from_secs(3)).expect("must refine");
        assert!(
            elapsed >= Duration::from_millis(700) && elapsed <= Duration::from_millis(1300),
            "settle-to-refine took {elapsed:?} (want ≈1 s)"
        );
        assert!(r.refined());
    }

    #[test]
    fn caret_blink_neither_blocks_refine_nor_downflips() {
        let mut r = refine();
        let mut now = t0();
        // Refine first (quiet from the start).
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        // 20 s of caret blinks (~1.9 Hz): single tiny frames, 530 ms apart,
        // with keepalives in between — must stay refined throughout.
        for _ in 0..38 {
            assert_eq!(
                r.note_real_frame(now, SMALL, REFINE_REF_AREA),
                None,
                "caret blink must not down-flip"
            );
            for k in 1..=8 {
                assert_eq!(
                    r.on_keepalive(true, false, now + Duration::from_millis(60 * k)),
                    None
                );
            }
            now += Duration::from_millis(530);
        }
        assert!(r.refined());
    }

    #[test]
    fn typing_small_frames_never_block_the_upflip() {
        // P7c — the field regression this rewrite exists for: a terminal
        // user types continuously (~6 cps of keystroke-sized deltas) after a
        // scroll dropped the rung. The old frame-COUNT gate held the stream
        // blurry for the whole typing session; size-gated, the keystrokes
        // are invisible and the up-flip lands as soon as the (empty) window
        // and cooldown allow — crisp text WHILE typing.
        let mut r = refine();
        let mut now = t0();
        for _ in 0..30 {
            let _ = r.note_real_frame(now, SMALL, REFINE_REF_AREA);
            now += Duration::from_millis(160);
        }
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        assert!(r.refined());
    }

    #[test]
    fn held_key_repeat_never_downflips() {
        // Holding a key in a terminal repeats glyph-sized deltas at ~30 Hz —
        // gap-chained under the old counter (a fake "scroll"), invisible now.
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        let mut t = now + Duration::from_secs(1);
        for _ in 0..60 {
            assert_eq!(r.note_real_frame(t, SMALL, REFINE_REF_AREA), None);
            t += Duration::from_millis(33);
        }
        assert!(r.refined());
    }

    #[test]
    fn big_repaint_trickle_blocks_upflip() {
        // ≥3 significant frames/s (a window animation repainting large
        // regions) must still hold the up-flip — rebuild+IDR isn't free.
        let mut r = refine();
        let mut now = t0();
        let _ = r.note_real_frame(now, BIG, REFINE_REF_AREA);
        now += Duration::from_millis(160);
        let _ = r.note_real_frame(now, BIG, REFINE_REF_AREA);
        for _ in 0..30 {
            now += Duration::from_millis(160);
            let _ = r.note_real_frame(now, BIG, REFINE_REF_AREA);
            assert_eq!(
                r.on_keepalive(true, false, now + Duration::from_millis(60)),
                None
            );
        }
        assert!(!r.refined());
    }

    #[test]
    fn zero_threshold_restores_legacy_counting() {
        // min_frame_bytes = 0 (env IDLE_REFINE_MIN_FRAME_KB=0): every real
        // frame counts, so a small-frame trickle blocks the up-flip again.
        let mut r = IdleRefine::new(
            true,
            0,
            REFINE_MAJOR_AREA_PERMILLE,
            REFINE_SETTLE_TRACKED,
            REFINE_SETTLE_TRACKED_CONSTRAINED,
        );
        let mut now = t0();
        for _ in 0..10 {
            let _ = r.note_real_frame(now, SMALL, REFINE_REF_AREA);
            now += Duration::from_millis(160);
        }
        assert_eq!(r.on_keepalive(true, false, now), None);
        assert!(!r.refined());
    }

    #[test]
    fn scroll_burst_downflips_within_300ms() {
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        // 30 fps drag: the chained-run rule must fire by frame 8 (~270 ms).
        let mut t = now + Duration::from_secs(2);
        let mut fired_at = None;
        for i in 0..30 {
            if let Some(RefineFlip::Down) = r.note_real_frame(t, BIG, REFINE_REF_AREA) {
                fired_at = Some(i);
                break;
            }
            t += Duration::from_millis(33);
        }
        let frames = fired_at.expect("sustained scroll must down-flip");
        assert!(
            frames < 10,
            "down-flip took {frames} frames (want <10 ≈ 300 ms)"
        );
        assert!(!r.refined());
    }

    #[test]
    fn slow_motion_downflips_via_window_rate() {
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        // ~10.5 fps damage (95 ms gaps > the 80 ms chain gap): the run rule
        // never fires, the frames-per-window rate rule must within ≤1 s.
        let mut t = now + Duration::from_secs(2);
        let start = t;
        let mut fired = None;
        for _ in 0..40 {
            if let Some(RefineFlip::Down) = r.note_real_frame(t, BIG, REFINE_REF_AREA) {
                fired = Some(t.duration_since(start));
                break;
            }
            t += Duration::from_millis(95);
        }
        let took = fired.expect("10 fps sustained motion must down-flip");
        assert!(
            took <= Duration::from_millis(1100),
            "took {took:?} (want ≤ ~1 s)"
        );
    }

    #[test]
    fn window_animation_never_rerefines() {
        let mut r = refine();
        // A steady 5 fps spinner repainting big regions (200 ms gaps): >2
        // significant frames per window forever → the up-flip must never
        // fire, no matter how long it runs. Warm the window past the sparse
        // gate first (see big_repaint_trickle_blocks_upflip).
        let mut now = t0();
        for _ in 0..3 {
            let _ = r.note_real_frame(now, BIG, REFINE_REF_AREA);
            now += Duration::from_millis(200);
        }
        for _ in 0..100 {
            let _ = r.note_real_frame(now, BIG, REFINE_REF_AREA);
            assert_eq!(
                r.on_keepalive(true, false, now + Duration::from_millis(100)),
                None
            );
            now += Duration::from_millis(200);
        }
        assert!(!r.refined());
    }

    #[test]
    fn up_cooldown_measures_from_the_last_up_not_the_down() {
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        // Burst → down (~1.3 s after the Up).
        let mut t = now + Duration::from_secs(1);
        let mut down_at = None;
        for _ in 0..12 {
            if r.note_real_frame(t, BIG, REFINE_REF_AREA) == Some(RefineFlip::Down) {
                down_at = Some(t);
                break;
            }
            t += Duration::from_millis(33);
        }
        let down_at = down_at.expect("burst must down-flip");
        // Quiet again immediately. The re-up must respect the cooldown from
        // the UP (≥5 s after it) — but NOT serve a fresh cooldown from the
        // Down (P7c: the old any-flip anchor billed every scroll 10 s of
        // blur; the churn bound only needs up-to-up spacing).
        let up = tick_until_up(
            &mut r,
            down_at + Duration::from_millis(60),
            Duration::from_secs(15),
        )
        .expect("must eventually re-refine");
        assert!(
            up.0.duration_since(now) >= REFINE_UP_COOLDOWN,
            "re-refined {:?} after the first Up (cooldown {:?})",
            up.0.duration_since(now),
            REFINE_UP_COOLDOWN
        );
        assert!(
            up.0.duration_since(down_at) < REFINE_UP_COOLDOWN,
            "re-up served a fresh cooldown from the Down ({:?}) — the anchor \
             must be the last Up",
            up.0.duration_since(down_at)
        );
    }

    #[test]
    fn lone_scroll_rerefines_in_about_1s_once_cooldown_is_spent() {
        // The terminal-Enter case end-to-end: crisp for a while, one scroll
        // burst, typing resumes — the stream must be crisp again ~1 s after
        // the scroll (window drain), not a full extra cooldown later.
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        // Cooldown fully spent while crisp.
        let mut t = now + REFINE_UP_COOLDOWN + Duration::from_secs(1);
        // Enter → output scrolls: burst until the down-flip.
        let mut down_at = None;
        for _ in 0..12 {
            if r.note_real_frame(t, BIG, REFINE_REF_AREA) == Some(RefineFlip::Down) {
                down_at = Some(t);
                break;
            }
            t += Duration::from_millis(33);
        }
        let down_at = down_at.expect("scroll must down-flip");
        // Typing continues (small frames) with keepalives interleaved.
        let mut t = down_at + Duration::from_millis(160);
        let mut refined_at = None;
        while t.duration_since(down_at) <= Duration::from_secs(3) {
            let _ = r.note_real_frame(t, SMALL, REFINE_REF_AREA);
            if r.on_keepalive(true, false, t + Duration::from_millis(60)) == Some(RefineFlip::Up) {
                refined_at = Some(t + Duration::from_millis(60));
                break;
            }
            t += Duration::from_millis(160);
        }
        let refined_at = refined_at.expect("typing must not hold the blur");
        let took = refined_at.duration_since(down_at);
        assert!(
            took <= Duration::from_millis(1400),
            "re-refine took {took:?} after the scroll (want ≈1 s)"
        );
    }

    #[test]
    fn borderline_animation_does_not_oscillate_across_rungs() {
        // P7c-2 field lock (winhost-b, rc.425): ~15 fps of small-animation
        // deltas (a corp-VPN dialog's ticking countdown + page motion)
        // encoded ~4 KB at the 1024×640 rung (sub-floor ⇒ "quiet" ⇒ Up)
        // and ~14 KB at native 1920×1200 (over the FIXED 12 KiB floor ⇒
        // Down ~2 s later) — an endless flip pair every ~6 s, each burning
        // two rebuilds + a native IDR. With the rung-scaled floor the same
        // content is invisible at BOTH rungs.
        const NATIVE_AREA: u64 = 1920 * 1200;
        let mut r = refine();
        let mut now = t0();
        // Capped rung: the animation trickles 4 KB frames at ~15 fps.
        for _ in 0..30 {
            assert_eq!(r.note_real_frame(now, 4_000, REFINE_REF_AREA), None);
            now += Duration::from_millis(66);
        }
        // Animation frames are invisible ⇒ the window is quiet ⇒ Up fires.
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        // Refined at native: the SAME content now encodes ~14 KB — over
        // the old fixed floor (the oscillator), under the scaled one
        // (12 KiB × native/ref ≈ 42 KiB) ⇒ stays crisp.
        for _ in 0..60 {
            assert_eq!(
                r.note_real_frame(now, 14_000, NATIVE_AREA),
                None,
                "borderline animation at native must not down-flip"
            );
            now += Duration::from_millis(66);
        }
        assert!(r.refined(), "stays crisp through the ticking animation");
        // A REAL scroll at native (~120 KB frames) still restores the cap.
        let mut downed = false;
        for _ in 0..12 {
            if r.note_real_frame(now, 120_000, NATIVE_AREA) == Some(RefineFlip::Down) {
                downed = true;
                break;
            }
            now += Duration::from_millis(33);
        }
        assert!(downed, "real motion at native must still down-flip");
    }

    // ── P8a/P8a-2 — the AREA significance leg ──────────────────────────

    #[test]
    fn minor_area_motion_never_leaves_native() {
        // THE P8a-2 headline: a windowed terminal scroll (≈300 ‰, under
        // the 400 ‰ major bar) sustained at 30 fps must NOT restore the
        // cap — text work stays at native straight through its own
        // scrolls, no rung drop, no re-sharpen wait. Carets (1 ‰) and
        // popups (50 ‰) likewise.
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        let mut t = now + Duration::from_secs(1);
        for pm in [1u32, 50, 300] {
            assert!(!r.area_major(pm), "{pm} ‰ must be minor");
            for _ in 0..60 {
                assert_eq!(r.note_real_frame_area(t, pm), None);
                t += Duration::from_millis(33);
            }
            assert!(r.refined(), "still native through {pm} ‰ motion");
        }
    }

    #[test]
    fn major_motion_downs_and_resharpens_in_half_a_second() {
        // Sustained LARGE-area motion (video / full drag, 600 ‰) still
        // restores the cap within the run rule; once it stops, the
        // tracked settle lifts again ~500 ms later — not the ~1 s the
        // bytes path needs. (Spend the cooldown first so it doesn't
        // mask the settle timing.)
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        let mut t = now + REFINE_UP_COOLDOWN + Duration::from_secs(1);
        let mut down_at = None;
        for _ in 0..12 {
            if r.note_real_frame_area(t, 600) == Some(RefineFlip::Down) {
                down_at = Some(t);
                break;
            }
            t += Duration::from_millis(33);
        }
        let down_at = down_at.expect("major motion must down-flip");
        // Keepalives every 60 ms after the burst stops.
        let mut k = down_at + Duration::from_millis(60);
        let mut up_at = None;
        while k.duration_since(down_at) <= Duration::from_secs(3) {
            if r.on_keepalive(true, false, k) == Some(RefineFlip::Up) {
                up_at = Some(k);
                break;
            }
            k += Duration::from_millis(60);
        }
        let took = up_at.expect("must re-refine").duration_since(down_at);
        assert!(
            took >= REFINE_SETTLE_TRACKED
                && took <= REFINE_SETTLE_TRACKED + Duration::from_millis(200),
            "tracked settle took {took:?} (want ≈500 ms)"
        );
    }

    #[test]
    fn sparse_major_trickle_stays_native_without_churn() {
        // A 1 Hz full-screen repaint (dashboard refresh): each frame is
        // major but never sustains a run/rate, so no Down ever fires —
        // and between repaints the tracked settle keeps the stream
        // refined. Zero flip churn.
        let mut r = refine();
        let mut now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        now += Duration::from_secs(1);
        for _ in 0..30 {
            assert_eq!(r.note_real_frame_area(now, 900), None, "no Down");
            for k in 1..=8 {
                assert_eq!(
                    r.on_keepalive(true, false, now + Duration::from_millis(60 * k)),
                    None,
                    "already refined — no extra Ups either"
                );
            }
            now += Duration::from_secs(1);
        }
        assert!(r.refined());
    }

    #[test]
    fn bytes_after_area_swap_restores_the_window_rule() {
        // Mid-session Dxgi→Gdi swap: the signal degrades from damage
        // truth to bytes; the up-flip must fall back to the conservative
        // window-drain rule (the stale Area kind must not let a 500 ms
        // settle fire through ongoing byte-significant motion).
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        // Major area burst downs the rung.
        let mut t = now + REFINE_UP_COOLDOWN + Duration::from_secs(1);
        let mut downed = false;
        for _ in 0..12 {
            if r.note_real_frame_area(t, 800) == Some(RefineFlip::Down) {
                downed = true;
                break;
            }
            t += Duration::from_millis(33);
        }
        assert!(downed);
        // Backend swap: byte-significant motion continues at 5 fps.
        // Under the Area settle this would look "quiet" after 500 ms of
        // per-frame gaps... the Bytes kind must force the window rule.
        for _ in 0..30 {
            let _ = r.note_real_frame(t, BIG, REFINE_REF_AREA);
            assert_eq!(
                r.on_keepalive(true, false, t + Duration::from_millis(100)),
                None,
                "byte motion must hold the window rule after the swap"
            );
            t += Duration::from_millis(200);
        }
        assert!(!r.refined());
    }

    #[test]
    fn area_floor_zero_counts_any_tracked_damage_but_never_empty() {
        let mut r = IdleRefine::new(
            true,
            REFINE_MIN_FRAME_KB as usize * 1024,
            0,
            REFINE_SETTLE_TRACKED,
            REFINE_SETTLE_TRACKED_CONSTRAINED,
        );
        // 0 ‰ = provably-unchanged frame: never significant, even at
        // floor 0.
        assert!(!r.area_major(0));
        assert_eq!(r.note_real_frame_area(t0(), 0), None);
        // 1 ‰ (any non-empty damage) counts at floor 0 — the pre-P8a-2
        // posture, restorable by config.
        assert!(r.area_major(1));
        let mut now = t0();
        for _ in 0..10 {
            let _ = r.note_real_frame_area(now, 1);
            now += Duration::from_millis(160);
        }
        assert_eq!(
            r.on_keepalive(true, false, now + Duration::from_millis(60)),
            None,
            "ongoing tracked motion blocks the up-flip at floor 0 (settle unmet)"
        );
    }

    #[test]
    fn untracked_pip_video_still_downs_via_the_bytes_leg() {
        // On UNTRACKED backends (scrap/GDI/old-WGC) a PiP video still
        // encodes 30-60 KB/frame at native and must keep its Down-guard
        // via the bytes leg. (On TRACKED backends P8a-2 deliberately
        // keeps PiP at native — the pump never routes tracked frames
        // here; the encoder's maxrate + AIMD own the load.)
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        assert!(!r.area_major(25), "PiP is under the major bar");
        const NATIVE_AREA: u64 = 1920 * 1200;
        let mut t = now + Duration::from_secs(1);
        let mut downed = false;
        for _ in 0..15 {
            if r.note_real_frame(t, 50_000, NATIVE_AREA) == Some(RefineFlip::Down) {
                downed = true;
                break;
            }
            t += Duration::from_millis(33);
        }
        assert!(downed, "bytes leg must keep the untracked PiP Down-guard");
    }

    #[test]
    fn bytes_significant_matches_the_scaled_floor() {
        // The pump routes frames on this predicate (significant → bytes
        // leg; else → QUIET tick), so it must mirror note_real_frame's
        // internal gate exactly.
        let r = refine();
        assert!(!r.bytes_significant(4_000, REFINE_REF_AREA));
        assert!(r.bytes_significant(13_000, REFINE_REF_AREA));
        // Rung-scaled: 14 KB is motion at 1024×640 but stillness-noise
        // at native (floor 43 200 there).
        assert!(!r.bytes_significant(14_000, 1920 * 1200));
        assert!(r.bytes_significant(50_000, 1920 * 1200));
    }

    #[test]
    fn quiet_ticks_from_insignificant_frames_refine_an_always_some_backend() {
        // Field corplap-3: the capture returns a "real" frame on every
        // poll, so the keepalive arm never runs. The pump now feeds
        // on_keepalive after every insignificant frame — a stream of
        // 48-byte still-screen re-encodes must reach Up purely through
        // those quiet ticks.
        let mut r = refine();
        let mut now = t0();
        let mut upped = false;
        for _ in 0..30 {
            assert!(!r.bytes_significant(48, REFINE_REF_AREA));
            if r.on_keepalive(true, false, now) == Some(RefineFlip::Up) {
                upped = true;
                break;
            }
            now += Duration::from_millis(54);
        }
        assert!(upped, "quiet ticks alone must refine");
    }

    #[test]
    fn scaled_floor_tracks_encode_area_with_an_absolute_floor() {
        let r = refine();
        // At the reference rung the configured floor applies verbatim.
        assert_eq!(r.scaled_min_bytes(REFINE_REF_AREA), 12 * 1024);
        // Native 1920×1200 = 3.515625× the reference area, exactly 43200.
        assert_eq!(r.scaled_min_bytes(1920 * 1200), 43_200);
        // Small rungs scale down proportionally…
        assert_eq!(r.scaled_min_bytes(640 * 400), 4_800);
        // …but never below the absolute floor (caret noise stays invisible).
        assert_eq!(r.scaled_min_bytes(320 * 200), REFINE_MIN_BYTES_FLOOR);
        // Legacy count-everything (floor 0) never scales.
        let legacy = IdleRefine::new(
            true,
            0,
            REFINE_MAJOR_AREA_PERMILLE,
            REFINE_SETTLE_TRACKED,
            REFINE_SETTLE_TRACKED_CONSTRAINED,
        );
        assert_eq!(legacy.scaled_min_bytes(1920 * 1200), 0);
    }

    #[test]
    fn eligible_false_clears_refined_silently() {
        let mut r = refine();
        let now = t0();
        assert_eq!(r.on_keepalive(true, false, now), Some(RefineFlip::Up));
        assert!(r.refined());
        // Dial moved to Sharper (no cap to lift): silent clear, no Down.
        assert_eq!(
            r.on_keepalive(false, false, now + Duration::from_millis(60)),
            None
        );
        assert!(!r.refined());
    }

    #[test]
    fn disabled_never_flips() {
        let mut r = IdleRefine::new(
            false,
            0,
            0,
            REFINE_SETTLE_TRACKED,
            REFINE_SETTLE_TRACKED_CONSTRAINED,
        );
        let mut now = t0();
        for _ in 0..50 {
            assert_eq!(r.on_keepalive(true, false, now), None);
            assert_eq!(r.note_real_frame(now, BIG, REFINE_REF_AREA), None);
            now += Duration::from_millis(60);
        }
        assert!(!r.refined());
    }

    #[test]
    fn first_upflip_needs_no_prior_flip() {
        // A session that starts quiet refines on the very first keepalive —
        // the cooldown only spaces SUBSEQUENT up-flips.
        let mut r = refine();
        assert_eq!(r.on_keepalive(true, false, t0()), Some(RefineFlip::Up));
    }

    // Phase B field fix — the settle is transport-aware: on a constrained
    // relay every Up costs its own ~0.5-1 s IDR of link time, so firing on
    // ordinary drag pauses (500 ms) kept the field session in permanent
    // IDR recovery ("freezing / window seconds behind", winhost-a/corplap
    // 2026-08-21). Direct paths keep the crisp 500 ms.
    #[test]
    fn constrained_settle_outlasts_drag_pauses() {
        let start = t0();
        let mut relay = refine();
        let _ = relay.note_real_frame_area(start, 600);
        assert_eq!(
            relay.on_keepalive(true, true, start + Duration::from_millis(1100)),
            None,
            "a 1.1 s drag pause must not refine on a relay"
        );
        assert_eq!(
            relay.on_keepalive(true, true, start + Duration::from_millis(1200)),
            Some(RefineFlip::Up)
        );
        let mut direct = refine();
        let _ = direct.note_real_frame_area(start, 600);
        assert_eq!(
            direct.on_keepalive(true, false, start + Duration::from_millis(600)),
            Some(RefineFlip::Up),
            "direct paths keep the crisp 500 ms settle"
        );
    }
}
