// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FFmpeg encoder backend wrapping `ffmpeg-next`.
//!
//! rc.72 scope: BGRA→NV12 CPU path + encoder dispatch
//! (`hevc_nvenc` → `hevc_qsv` → `hevc_amf`). Behind
//! `MESHHARBORD_USE_FFMPEG=1` env var. MF cascade still default.
//!
//! rc.73+: D3D11VA zero-copy (capture's D3D11 texture fed directly to
//! NVENC / QSV / AMF without CPU readback). Defers Phase 8's critique
//! warning about late zero-copy refactors — we ship the CPU path first
//! to establish the encoder works at all, then swap to zero-copy in a
//! follow-up RC that doesn't add other behaviour.
//!
//! ## Encoder configuration
//!
//! - Input format: NV12 (single plane Y + interleaved UV at half-res both axes)
//! - Output format: HEVC Annex-B (4-byte start codes; the pre-flight WebCodecs
//!   spike confirmed Chrome accepts this without a hvcC description box)
//! - Rate control: CBR target via `bit_rate`; HW backends interpret this
//!   differently (NVENC = `NV_ENC_PARAMS_RC_CBR`, QSV = `CBR`, AMF = `CBR`)
//! - GOP: 240 frames (matches libvpx VP9-444 cadence — same DC framing
//!   anti-IDR-storm characteristics apply)
//! - Profile: Main 8-bit 4:2:0 (matches RustDesk; broadest browser
//!   WebCodecs support per the pre-flight spike)

use std::sync::{Arc, OnceLock};

use anyhow::{Context as _, Result, anyhow};
use ffmpeg_next::{codec, format, frame, util};

use super::hwframes;

use crate::capture::{DirtyRect, Frame, PixelFormat};
use crate::encode::{EncodedPacket, VideoEncoder};
use tunnel_core::env::node_env;

/// rc.234 — natural-GOP interval for encoders that HONOUR runtime keyframe
/// forcing (hevc_nvenc/qsv/amf, av1_*): effectively NEVER. These encoders'
/// only live media consumers are the reliable-DC pumps, where periodic IDRs
/// serve no transport purpose — every needed key (DC-open, browser resync,
/// lock transition) is forced on demand — and each routine IDR QP-starves
/// under the maxrate cap, painting the field-reported "text blurs every few
/// seconds then re-sharpens" pulse (2026-07-25, DEVBOX viewing WINHOST-A /
/// REGAL; the old value was 240 ≈ 4-6 s at real rates, stacked on the 4 s
/// pump backstop metronome removed in the same round). 64800 stays under
/// Intel Media SDK's u16 `GopPicSize` ceiling (65535) — at 60 fps that is
/// ~18 min, i.e. "on-demand only" in practice. The legacy RTP-track
/// constructors share this value, but that path's live codecs (H.264 via
/// openh264/MF) don't come through here; the caps probe doesn't care.
const KEYFRAME_INTERVAL: i32 = 64800;

/// rc.219 — vp9_qsv-only SHORT GOP. Field-proven (2026-07-24, WINHOST-A Iris
/// Xe): vp9_qsv CANNOT force keyframes at runtime — `frame.set_kind(I)` is
/// ignored AND the `forced_idr=1` option is accepted-but-ineffective
/// (rc.217 logs: the option in the accepted dict, yet every browser resync
/// still waited ~1 s of `kf_pending` and only an encoder REBUILD produced a
/// key-flagged frame). So for vp9_qsv the ONLY reliable resync source is a
/// NATURAL keyframe — make them frequent: 60 frames = 1 s at 60 fps (~5 s
/// at the 12 fps viewer-rate shed floor). VP9 keyframe overhead at this
/// cadence is a few percent of the stream; the browser's keyframe gate then
/// self-heals off natural keys and the pump's force-ignored rebuild fallback
/// becomes a true last resort instead of the primary (hiccuping) mechanism.
/// hevc_qsv / nvenc honour runtime forcing and keep [`KEYFRAME_INTERVAL`].
const VP9_QSV_KEYFRAME_INTERVAL: i32 = 60;

/// P4 — cached per-host verdict from the startup vp9_qsv IDR probe:
/// `(honors_low_power, honors_vme)` — does a runtime-forced keyframe
/// actually come out key-flagged, per `low_power` mode? Written once by
/// [`FfmpegEncoder::probe_and_cache_vp9_qsv_idr`] (caps.rs startup);
/// consulted by every vp9_qsv open via `vp9_qsv_runtime_config`. Unset →
/// the rc.219 containment (GOP 60 + VDEnc).
static VP9_QSV_IDR_VERDICT: OnceLock<(bool, bool)> = OnceLock::new();

/// Phase B — default fps for the non-DC-pump constructors (`new_hevc` /
/// `new_vp9`), which serve the caps probe + the legacy REMB-adaptive WebRTC
/// track path. The DataChannel pump threads its real per-session `target_fps`
/// through `new_hevc_adaptive` / `new_vp9_adaptive` instead (fixing the
/// pre-Phase-B latent bug where this was hardcoded 30 while the pump captured
/// at 60, so `set_frame_rate` + the maxrate math were computed for 30 fps).
const DEFAULT_ENCODER_FPS: i32 = 30;

/// Time-base denominator: microseconds, the unit of `Frame::monotonic_us`, so
/// a frame's pts IS its capture time ([`live_pts`]).
///
/// FR-119 P2a — it was 1000 (milliseconds), and a frame's pts was its capture
/// time divided by 1000. At 144 fps a period is 6.9 ms, and two frames
/// delivered within the same millisecond (a burst after a stall, the
/// latest-wins slot handing over back to back) got EQUAL pts, which an encoder
/// may reject or misorder. Every FFmpeg backend either rescales pts from the
/// codec time base itself (QSV to 90 kHz, AMF and VideoToolbox to their own
/// clocks) or carries it through untouched (NVENC, VAAPI). None assumes
/// milliseconds, so the unit is ours to choose.
const TIME_BASE_DEN: i32 = 1_000_000;

/// FR-119 P2a — a live frame's pts: its capture time, in the time base.
fn live_pts(monotonic_us: u64) -> i64 {
    monotonic_us as i64
}

/// FR-119 P2a — encoder ticks (the time base) to microseconds.
fn ticks_to_us(ticks: i64) -> u64 {
    (ticks.max(0) as u64) * 1_000_000 / TIME_BASE_DEN as u64
}

/// Codec dispatch order for HEVC. First successful `find_by_name +
/// open_as` wins. Matches RustDesk's order (NVIDIA → Intel → AMD), with
/// Apple's VideoToolbox appended.
///
/// The entries are DISJOINT BY PLATFORM: nvenc/qsv/amf can never exist on
/// macOS, and `hevc_videotoolbox` can never exist anywhere else. So the
/// order decides nothing except how many cheap registry misses precede the
/// hit. Appended rather than prepended purely so the existing fleet's
/// dispatch is unchanged — a Mac paying three misses costs nothing.
const HEVC_ENCODER_NAMES: &[&str] = &[
    "hevc_nvenc",
    "hevc_qsv",
    "hevc_amf",
    "hevc_videotoolbox",
    "hevc_vaapi",
    "hevc_d3d12va",
    "hevc_vulkan",
];

/// rc.83 — Codec dispatch order for VP9. Intel oneVPL only — NVIDIA
/// NVENC + AMD AMF never added VP9 encode (they skipped to AV1). On
/// non-Intel hosts the cascade falls through to libvpx SW via the
/// existing `media_pump_vp9_444_dc` path (no FFmpeg fallback here —
/// libvpx is what the caps probe advertises).
///
/// Gate 0 validated `hevc_qsv` on Iris Xe Tiger Lake; `vp9_qsv` on
/// the same iGPU family is the load-bearing assumption for the Iris
/// Xe fps unlock (CPU-bound 17 fps on libvpx SW → expected 30-60 fps
/// on iGPU HW).
const VP9_ENCODER_NAMES: &[&str] = &["vp9_qsv", "vp9_vaapi"];

/// rc.190 — Codec dispatch order for AV1 (the `data-channel-av1`
/// transport). HW-only, probe-gated by caps.rs — AV1 encode silicon:
/// NVIDIA Ada+ (`av1_nvenc`; RTX 5090 in the fleet), Intel Arc/DG2+
/// (`av1_qsv`; NOT the Gen12 Iris Xe/UHD iGPUs, which only DECODE AV1),
/// AMD RDNA3+ (`av1_amf`). Hosts without any of these simply don't
/// advertise the transport. Note the MF-AV1 NVENC known-issue
/// (`ActivateObject` 0x8000FFFF on RTX 5090 Blackwell) is MF-specific —
/// this path talks to the NVENC SDK via FFmpeg directly, and the probe
/// protects us if it ever shares the failure.
///
/// `av1_videotoolbox` is appended DELIBERATELY UNPROVEN. FFmpeg 8.1.2 does
/// ship the encoder (verified against the vendored dylib: libavcodec carries
/// a `VideoToolbox AV1 Encoder` long-name), but Apple has only ever announced
/// AV1 *decode* silicon — from M3 — so on current Macs the open is expected to
/// FAIL. That is the right shape here rather than a guess either way: the
/// cascade records `last_err` and moves on, and `caps.rs` only advertises the
/// AV1 transport if an open actually succeeded. So a Mac that lacks the block
/// silently doesn't offer AV1, and the first Mac that gains one starts
/// offering it with no code change.
///
/// ⚠️ Do not "confirm" a VideoToolbox encoder by grepping the dylib for
/// `*_videotoolbox` — that token also matches DECODE hwaccels (`vp9_`,
/// `mpeg2_`, `h263_`, `mpeg4_` all appear). The long-name string is what
/// distinguishes an encoder.
const AV1_ENCODER_NAMES: &[&str] = &[
    "av1_nvenc",
    "av1_qsv",
    "av1_amf",
    "av1_videotoolbox",
    "av1_vaapi",
    "av1_d3d12va",
    "av1_vulkan",
];

/// P2 (Parsec-class plan) — Codec dispatch order for H.264 over the
/// `data-channel-h264` transport. HW-only by construction (openh264 SW
/// stays on the legacy RTP-track path): H.264 encode silicon is the most
/// universally present of the four codecs (every NVENC generation, every
/// QSV generation, every AMF generation). Probe-gated in caps.rs like
/// HEVC/AV1 — hosts without H.264 HW simply don't advertise the transport
/// and explicit H.264 picks stay on the RTP track + `<video>` fallback.
///
/// `h264_videotoolbox` appended for Apple silicon — see the platform-
/// disjointness note on [`HEVC_ENCODER_NAMES`]. Every Mac has an H.264
/// encode block, so on macOS this is the reliable HW rung; HEVC is the
/// better-compression one and is tried first by the transport ranking,
/// not by this list.
const H264_ENCODER_NAMES: &[&str] = &[
    "h264_nvenc",
    "h264_qsv",
    "h264_amf",
    "h264_videotoolbox",
    "h264_vaapi",
    "h264_d3d12va",
    "h264_vulkan",
];

/// rc.86 — constant-quality target (lower = sharper, more bits).
/// Default 22 is a good screen-content sweet spot for HEVC/VP9 — fine
/// text edges stay crisp without a full lossless blow-out. Range
/// clamped to [10, 40]; below 10 is near-lossless (huge), above 40 is
/// visibly soft. Env-overridable for field tuning without a rebuild.
fn ffmpeg_cq() -> u32 {
    node_env("FFMPEG_CQ")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|c| c.clamp(10, 40))
        .unwrap_or(22)
}

/// rc.86 — bandwidth CEILING (maxrate/bufsize), NOT a target. With
/// constant-quality rate control the encoder uses only what the `cq`
/// quality demands (idle ≈ 0); this cap just bounds the worst-case
/// burst on a full-screen scene change. Derived at ~0.07 bpp/s — about
/// a third of the old 0.20-bpp/s *target* the pre-rc.86 path fed as a
/// VBR goal — clamped to [3, 12] Mbps. RustDesk holds ~3 Mbps at
/// 1920×1200; 0.07 bpp/s puts our 1920×1200 cap at ~4.8 Mbps, leaving
/// headroom for genuine motion without the 6-7 Mbps idle-ish bursts
/// the field saw on the old uncapped 13.8 Mbps target.
/// Env override `MESHHARBORD_FFMPEG_MAXRATE_KBPS` for field tuning.
///
/// `constrained` is THIS session's detected transport (Phase B). Pre-Phase-B
/// this read the process-wide `transport_is_constrained()` env flag, which
/// mis-classified an agent serving BOTH a direct-local and a cross-host-relay
/// session from one process (the WSL virtual-desktop case): the relay clamp
/// either throttled the direct session or missed the relay one. The DC pump
/// now passes its per-session `detect_constrained_transport` result.
pub(crate) fn ffmpeg_maxrate_bps(width: u32, height: u32, fps: u32, constrained: bool) -> usize {
    ffmpeg_maxrate_bps_scaled(width, height, fps, constrained, 100)
}

// P8b — the pure ceiling math moved to `rate_profile` (no ffmpeg types in
// it) so `encode::policy` composes it on EVERY build, feature-gated or not.
// Re-exported here so this module's callers keep their path.
pub(crate) use crate::encode::rate_profile::ffmpeg_maxrate_bps_scaled;

/// The three products of [`encoder_options`]: `(base, lowlat, summary)`.
type EncoderOptions = (Vec<(String, String)>, Vec<(String, String)>, String);

/// rc.86 — per-encoder private-option dictionary for constant-quality,
/// low-latency, screen-content tuning. Keys mirror the FFmpeg CLI: `-cq`,
/// `-preset`, `-tune`, `-spatial-aq`, `-maxrate` and friends. Any option the
/// encoder doesn't recognise on this FFmpeg build / driver combo makes
/// `open_as_with` fail; `build_encoder` then retries a plain open, so we
/// degrade to defaults rather than failing the session.
///
/// `preset`/`tune` are env-overridable so the field can trade quality vs
/// latency vs CPU without a rebuild.
///
/// Returns `(base, lowlat, summary)`:
///
/// * `base` — the quality/tuning private options, including `forced-idr`,
///   which is load-bearing for keyframe flagging.
/// * `lowlat` — the output-latency knobs some older drivers reject.
///   `build_encoder` applies these in a SEPARATE open tier so a rejection
///   drops ONLY them; a full-dict rejection would revert to encoder defaults
///   and lose `forced-idr` — the NVENC black-screen IDR bug.
/// * `summary` — a human-readable `key=value …` string built as we go, so the
///   logging doesn't depend on `Dictionary::iter()` (whose shape has moved
///   across ffmpeg-next minor versions).
///
/// Pure — no ffmpeg API calls.
fn encoder_options(
    name: &str,
    maxrate_bps: usize,
    cq: u32,
    qsv_low_power: bool,
    chroma444: bool,
    constrained: bool,
) -> EncoderOptions {
    // P3 — H.264 codes text visibly softer than HEVC at equal nominal
    // quality numbers; give the h264_* encoders a 2-step sharper CQ off the
    // shared FFMPEG_CQ base (env still sets the base — the adjust is
    // relative). See encode::rate_profile.
    let cq = crate::encode::rate_profile::h264_cq_adjust(name, cq);
    let mut base: Vec<(String, String)> = Vec::new();
    let mut lowlat: Vec<(String, String)> = Vec::new();
    let cap = maxrate_bps.to_string();
    // rc.234 — HRD window = 2× the ceiling (was 1×). With bufsize == maxrate
    // any transient (a resync IDR, a window-uncover burst, a vp9_qsv natural
    // key) had a one-second bit budget and QP-collapsed into visible blur
    // that the following deltas then slowly repaired. 2× lets the transient
    // spend real bits; the AVERAGE stays bounded by `maxrate`, and actual
    // congestion is owned by the DC send channel + AIMD, not the HRD.
    //
    // Constrained-transport window (rc.442/rc.443): rc.442 trimmed relay
    // sessions to 75 % of maxrate to bound the refine IDR's transit; the
    // SAME DAY the first av1_qsv session under the trimmed window died on
    // its settle IDR (`send_frame: Invalid data` then a driver hang — a
    // quality-floored AV1 IDR exceeds a sub-1× reservoir and Intel's AV1
    // VDENC errors rather than clamping). The default is back to 200 %
    // both ways; `constrained_hrd_pct` remains a per-host experiment knob.
    // Direct-path window (field 2026-08-26, neo16↔Rozalina): the fixed 2×
    // reservoir legalised drag-start bursts of seconds' worth of bits —
    // the 100-345 KB standing send queue the viewer feels as lag. Direct
    // sessions now default to 1× (`direct_hrd_pct`, env/config tunable);
    // constrained keeps its own knob. `av1_*` is floored at 200 BOTH ways:
    // Intel's AV1 VDENC ERRORS (then hangs the driver) on a forced IDR
    // that exceeds the reservoir instead of QP-clamping — the rc.443
    // incident; H.264/HEVC clamp gracefully.
    let hrd_pct = open_hrd_pct(name, constrained);
    let buf = (maxrate_bps.saturating_mul(hrd_pct) / 100).to_string();
    let cq_s = cq.to_string();
    let preset = node_env("FFMPEG_PRESET");
    let tune = node_env("FFMPEG_TUNE");

    // Resolve a low-latency knob: env override wins; an explicitly EMPTY env
    // value OMITS the knob (escape hatch for a driver that rejects it); unset
    // → the default. Defaults are ON.
    let lowlat_knob = |suffix: &str, default: &str| -> Option<String> {
        match node_env(suffix) {
            Some(v) if v.trim().is_empty() => None,
            Some(v) => Some(v.trim().to_string()),
            None => Some(default.to_string()),
        }
    };

    if name.contains("nvenc") {
        // NVENC constant-quality VBR: `cq` drives quality, `maxrate`
        // bounds the burst, bit_rate=0 (set in build_encoder) makes it
        // pure target-quality. `tune=ll` keeps it responsive for remote
        // desktop; bf=0 + rc-lookahead=0 minimise latency.
        //
        // P7 (2026-08-20) — spatial AQ is OFF by default for desktop
        // content (key OMITTED — FFmpeg's nvenc default is 0, so omission
        // carries zero open-rejection risk and the tiered open is
        // untouched). The old comment here claimed AQ "spends bits on
        // high-detail text regions"; it does the opposite — AQ shifts QP
        // toward low-detail areas where banding would show and AWAY from
        // high-frequency detail, and on a desktop that detail IS the text.
        // Same reason the libvpx screen path pins VP9E_SET_AQ_MODE=0
        // (libvpx.rs — "AQ mis-fires on desktop and softens text").
        // temporal-aq is not an alternative: it needs rc-lookahead>0 and
        // we run 0 for latency. `MESHHARBORD_NVENC_SPATIAL_AQ=1`
        // restores the pre-P7 behaviour for camera-heavy hosts
        // (video-in-a-window content).
        //
        // rc.98 — `forced-idr=1` is REQUIRED for our keyframe forcing to
        // work on NVENC. We force keyframes via `frame.set_kind(I)`
        // (pict_type=I) — on the DC-open frame, on browser PLI, on
        // scene-change. Without `forced-idr`, FFmpeg's nvenc manages its
        // own GOP and a forced pict_type=I is NOT emitted as a flagged IDR:
        // the output packet lacks AV_PKT_FLAG_KEY, so `pkt.is_key()` is
        // false → our framer marks the chunk `delta` → the browser's
        // WebCodecs decoder rejects the first frame with "A key frame is
        // required after configure() or flush()" → black screen (field:
        // DEVBOX, hevc_nvenc; hevc_qsv flags forced-I correctly,
        // which is why WINHOST-E rendered and this didn't). `forced-idr=1`
        // makes pict_type=I a true, key-flagged IDR.
        base.push(("rc".into(), "vbr".into()));
        base.push(("cq".into(), cq_s.clone()));
        base.push(("preset".into(), preset.as_deref().unwrap_or("p4").into()));
        base.push(("tune".into(), tune.as_deref().unwrap_or("ll").into()));
        // P7 — HEVC 4:4:4 needs the Range-extensions profile; without it
        // nvenc silently keeps Main and rejects the yuv444p frames. Only
        // ever set on the hevc_nvenc + chroma444 path (the pump's Rext
        // opt-in); a rejection fails the base-tier open and the caller's
        // 4:2:0 fallback takes over.
        // FR-77 — H.264's 4:4:4 profile is `high444p` (High 4:4:4
        // Predictive); `rext` is HEVC's Range Extensions and h264_nvenc
        // REJECTS it at open, which would have made the probe read
        // "h264_nvenc cannot do 4:4:4" for a driver that can.
        if chroma444 {
            let profile = if name.starts_with("h264") {
                "high444p"
            } else {
                "rext"
            };
            base.push(("profile".into(), profile.into()));
        }
        base.push(("rc-lookahead".into(), "0".into()));
        base.push(("bf".into(), "0".into()));
        base.push(("forced-idr".into(), "1".into()));
        if node_env("NVENC_SPATIAL_AQ").as_deref().map(str::trim) == Some("1") {
            base.push(("spatial-aq".into(), "1".into()));
        }
        base.push(("maxrate".into(), cap.clone()));
        base.push(("bufsize".into(), buf.clone()));
        // rc.130 — `delay=0`: emit each packet with ZERO output-queue delay.
        // NVENC's default output delay (~surfaces−1, ≈4 frames) is the
        // typing-latency bug: with change-driven DXGI capture a keystroke's
        // frame sits in the encoder ~4 frames, which at caret-blink rate
        // (~2 fps while typing) is ~2 s. Window-move (~60 fps) drains the
        // same 4 frames in ~66 ms → smooth. Independent of tune=ll/forced-idr.
        if let Some(v) = lowlat_knob("FFMPEG_NVENC_DELAY", "0") {
            lowlat.push(("delay".into(), v));
        }
    } else if name.contains("qsv") {
        // Intel QSV: ICQ-style quality via `global_quality`; `maxrate`
        // caps the burst. `low_power=1` uses the fixed-function VDENC path
        // (faster, lower power — the Iris Xe fps-unlock path). P4 — the
        // value is now caller-chosen: the vp9_qsv IDR probe measures BOTH
        // modes and `vp9_qsv_runtime_config` may pick low_power=0 (VME)
        // when only that mode honours runtime forced keyframes. HEVC/H.264
        // qsv callers keep low_power=1 (unchanged).
        // P7 — no AQ analogue is set here ON PURPOSE: `mbbrc` stays at the
        // driver default (its behaviour on the low_power VDENC path is
        // unverified) — aligned with the nvenc spatial-aq-off default.
        base.push(("global_quality".into(), cq_s.clone()));
        // FR-77 P3b — QSV's 4:4:4 profiles, set explicitly rather than left
        // to the runtime's derivation from the input format: `rext` for HEVC
        // (Range Extensions, Main 4:4:4) and `profile1` for VP9 (8-bit
        // 4:4:4). In `base` (tiers 1 and 2): a driver that rejects the key
        // falls to the defaults tier, where the runtime derives the profile
        // from the VUYX frames itself.
        if chroma444 {
            if name.starts_with("hevc") {
                base.push(("profile".into(), "rext".into()));
            } else if name.starts_with("vp9") {
                base.push(("profile".into(), "profile1".into()));
            }
        }
        if let Some(p) = preset.as_deref() {
            base.push(("preset".into(), p.into()));
        }
        base.push((
            "low_power".into(),
            if qsv_low_power { "1" } else { "0" }.into(),
        ));
        base.push(("maxrate".into(), cap.clone()));
        base.push(("bufsize".into(), buf.clone()));
        // rc.130 — `async_depth=1`: cap QSV's in-flight pipeline to one frame
        // so it emits immediately instead of buffering ~4 (low_power VDENC
        // respects it). Same typing-latency fix as NVENC `delay=0`.
        if let Some(v) = lowlat_knob("FFMPEG_QSV_ASYNC_DEPTH", "1") {
            lowlat.push(("async_depth".into(), v));
        }
        // rc.217 — `forced_idr=1` (NOTE: underscore — qsv spelling, vs
        // nvenc's `forced-idr`): the qsv mirror of the rc.98 NVENC fix.
        // Field 2026-07-24 (DEVBOX viewing WINHOST-A): vp9_qsv IGNORED runtime
        // keyframe forcing via `frame.set_kind(I)` — browser resync requests
        // and the 4 s backstop produced NO key-flagged packet, wedging the
        // viewer's keyframe gate until an encoder rebuild happened to emit a
        // real IDR (hevc_qsv honours bare pict_type, vp9_qsv evidently
        // needs the option). In the tier-protected `lowlat` group (not
        // `base`): the option dict is ALL-OR-NOTHING, so if some qsv build
        // rejects `forced_idr` we fall back to the quality tier instead of
        // losing global_quality/maxrate wholesale. Env-escapable like the
        // other knobs; the peer.rs rebuild fallback stays as the net.
        if let Some(v) = lowlat_knob("FFMPEG_QSV_FORCED_IDR", "1") {
            lowlat.push(("forced_idr".into(), v));
        }
    } else if name.contains("amf") {
        // AMD AMF: constant-QP-ish via qp_i/qp_p, latency-tuned VBR,
        // capped burst.
        // P7 — `vbaq` (AMF's AQ) defaults OFF in FFmpeg and stays unset —
        // aligned with the nvenc spatial-aq-off default; don't "fix" it.
        base.push(("rc".into(), "vbr_latency".into()));
        base.push(("qp_i".into(), cq_s.clone()));
        base.push(("qp_p".into(), cq_s.clone()));
        base.push(("maxrate".into(), cap.clone()));
        base.push(("bufsize".into(), buf.clone()));
        // rc.130 — `query_timeout=1`: minimise the output-poll block (AMF's
        // low-latency lever alongside vbr_latency).
        if let Some(v) = lowlat_knob("FFMPEG_AMF_QUERY_TIMEOUT", "1") {
            lowlat.push(("query_timeout".into(), v));
        }
    } else if name.ends_with("_vaapi") {
        // FR-77 P4 — VAAPI (Linux: Intel iHD, AMD radeonsi, Mesa's D3D12
        // frontend on WSL2). `rc_mode=VBR` anchored on `b:v` = `maxrate`
        // (set in `build_encoder`, like QSV/AMF) with the HRD window; no
        // `qp`/`quality` on top — the driver's VBR owns quality and the
        // governor owns the ceiling. Forced keyframes ride `pict_type=I`
        // (vaapi_encode turns a forced I picture into an IDR), so no
        // `forced-idr` twin is needed.
        base.push(("rc_mode".into(), "VBR".into()));
        base.push(("maxrate".into(), cap.clone()));
        base.push(("bufsize".into(), buf.clone()));
        // HEVC Rext for 4:4:4 (the packed VUYX pool); VP9 profile 1 is
        // derived by the driver from the surface format and has no option.
        if chroma444 && name.starts_with("hevc") {
            base.push(("profile".into(), "rext".into()));
        }
        // Tier-protected like the other vendors' latency knobs: one frame
        // in flight, so a keystroke's frame does not sit behind a queue.
        if let Some(v) = lowlat_knob("FFMPEG_VAAPI_ASYNC_DEPTH", "1") {
            lowlat.push(("async_depth".into(), v));
        }
    } else if name.ends_with("_d3d12va") {
        // FR-78 P1 — D3D12 video encode (Windows, the graphics driver's own
        // encode DDI). Same rate-control shape as VAAPI: `rc_mode=VBR` on
        // `b:v` = the cap with the HRD window, no `qp` on top — the d3d12va
        // constants are UPPERCASE like VAAPI's (`vbr` reads as an undefined
        // constant and drops the whole tier; measured on the dev box).
        // FFmpeg's d3d12va encoders default to `bf=2`: two B-frames of
        // reordering delay, which a remote desktop cannot carry — every
        // frame is a P-frame here, as on every other backend.
        base.push(("rc_mode".into(), "VBR".into()));
        base.push(("maxrate".into(), cap.clone()));
        base.push(("bufsize".into(), buf.clone()));
        base.push(("bf".into(), "0".into()));
        if let Some(v) = lowlat_knob("FFMPEG_D3D12_ASYNC_DEPTH", "1") {
            lowlat.push(("async_depth".into(), v));
        }
    } else if name.ends_with("_vulkan") {
        // FR-78 P1 — Vulkan video encode (Linux + Windows, whichever ICD
        // the loader finds). `rc_mode=vbr` on the cap with the HRD window;
        // the Vulkan tuning / usage hints are the closest thing this API has
        // to a low-latency preset, so they sit in the tier-protected group
        // with `async_depth`, where a driver that rejects them costs only
        // the knob, never the open. No B-frames, as above.
        base.push(("rc_mode".into(), "vbr".into()));
        base.push(("maxrate".into(), cap.clone()));
        base.push(("bufsize".into(), buf.clone()));
        base.push(("bf".into(), "0".into()));
        if chroma444 && name.starts_with("hevc") {
            base.push(("profile".into(), "rext".into()));
        }
        if let Some(v) = lowlat_knob("FFMPEG_VULKAN_TUNE", "ull") {
            lowlat.push(("tune".into(), v));
        }
        if let Some(v) = lowlat_knob("FFMPEG_VULKAN_USAGE", "stream") {
            lowlat.push(("usage".into(), v));
        }
        if let Some(v) = lowlat_knob("FFMPEG_VULKAN_ASYNC_DEPTH", "1") {
            lowlat.push(("async_depth".into(), v));
        }
    } else if name.contains("videotoolbox") {
        // Apple VideoToolbox (macOS). This branch exists because the chain
        // above has NO `else`: without it a `*_videotoolbox` name reached the
        // encoder with an EMPTY option dict — no `maxrate`, no `bufsize`, so
        // no HRD bound at all, and the ceiling the rate governor computes
        // would have been silently ignored.
        //
        // No `cq`/`qp_i`/`global_quality` here, unlike the three vendor
        // encoders: VT is ABR-anchored, and `build_encoder` already gives it
        // a real `bit_rate` (only `nvenc` is special-cased to 0). Adding a
        // quality knob on top would fight the rate control rather than
        // replace it.
        base.push(("maxrate".into(), cap.clone()));
        base.push(("bufsize".into(), buf.clone()));
        // `realtime` is the whole point for remote desktop: it tells VT to
        // favour hitting the frame deadline over spending longer per frame.
        // `prio_speed` pushes the same way on the encode-priority side.
        //
        // Both live in the tier-protected `lowlat` group, not `base` — the
        // option dict is ALL-OR-NOTHING, and these are the two keys whose
        // availability varies across macOS releases. If a future OS rejects
        // one we drop only the latency posture and keep the rate control,
        // instead of reverting to encoder defaults.
        if let Some(v) = lowlat_knob("FFMPEG_VT_REALTIME", "1") {
            lowlat.push(("realtime".into(), v));
        }
        if let Some(v) = lowlat_knob("FFMPEG_VT_PRIO_SPEED", "1") {
            lowlat.push(("prio_speed".into(), v));
        }
    }

    let summary = base
        .iter()
        .chain(lowlat.iter())
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");
    (base, lowlat, summary)
}

/// Build an ffmpeg option `Dictionary` from owned key/value pairs. `av_dict`
/// copies the strings, so the returned dict owns its data (`'static`).
fn dict_from_pairs(pairs: &[(String, String)]) -> ffmpeg_next::Dictionary<'static> {
    let mut d = ffmpeg_next::Dictionary::new();
    for (k, v) in pairs {
        d.set(k.as_str(), v.as_str());
    }
    d
}

/// FFmpeg-based video encoder.
///
/// Holds a `codec::encoder::Video` plus state for keyframe forcing,
/// bitrate updates, and BGRA→NV12 conversion. The `convert_buf`
/// scratch buffer is sized for the largest frame seen so far so we
/// don't reallocate every frame.
// Manually impl Debug — the underlying `codec::encoder::Video` doesn't
// derive Debug, and we want a short stable repr for tracing + the
// `Result<FfmpegEncoder, _>::unwrap_err()` in unit tests.
impl std::fmt::Debug for FfmpegEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfmpegEncoder")
            .field("encoder_name", &self.encoder_name)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("frame_count", &self.frame_count)
            .field("force_keyframe", &self.force_keyframe)
            .finish()
    }
}

pub struct FfmpegEncoder {
    /// Stable identifier for logs / `is_hardware` decisions, e.g.
    /// `"hevc_nvenc"`. Bound at construction time, never changes.
    encoder_name: &'static str,

    /// Encode width × height. Bound at construction; the agent currently
    /// re-creates the encoder on resolution changes.
    width: u32,
    height: u32,

    /// FFmpeg encoder handle. Owns the underlying AVCodecContext.
    encoder: codec::encoder::Video,

    /// Frame counter for pts + GOP timing.
    frame_count: u64,

    /// Set by `request_keyframe` to force the next frame to be IDR. The
    /// FFmpeg `Video::send_frame` path needs `frame.set_key_frame(true)`
    /// + `frame.set_pict_type(I)` to force IDR on HEVC encoders.
    force_keyframe: bool,

    /// Scratch buffer for the Y plane (NV12 and I444 alike). Reused across
    /// frames.
    plane_y: Vec<u8>,
    /// NV12: the interleaved UV plane (pixels/2 bytes). I444 (P7 HEVC Rext):
    /// the full-resolution U plane (pixels bytes). Reused across frames.
    plane_u: Vec<u8>,
    /// I444 only: the full-resolution V plane. Empty on NV12.
    plane_v: Vec<u8>,
    /// P7 — true when this encoder runs HEVC Rext 4:4:4 (`yuv444p` +
    /// `profile=rext`, hevc_nvenc only). Drives the convert/build format
    /// branches and is surfaced to the pump for `rc:video-info` truth.
    chroma444: bool,
    /// FR-77 P3b — the 4:4:4 input is the packed VUYX layout (QSV / VAAPI)
    /// rather than planar I444 (NVENC, software). Fixed at open from the
    /// encoder name; `adopt_rebuilt` only swaps in an encoder of the same
    /// name and chroma, so it never changes underneath a session.
    packed444: bool,
    /// The VUYX buffer (`w × h × 4`), filled from the I444 planes per frame
    /// when `packed444`; empty otherwise.
    packed: Vec<u8>,
    /// FR-77 P4 — the VAAPI frame pool of a `*_vaapi` encoder (`None` for
    /// every other backend); replaced together with the encoder on a rebuild.
    hw: Option<hwframes::Frames>,

    /// Target fps this session runs at — threaded from the DC pump's
    /// `target_fps` (Phase B). Reused on the QSV/AMF bitrate REBUILD so the
    /// rebuilt encoder keeps the session's real framerate. Fixes the
    /// pre-Phase-B latent bug where `new_with_dispatch` hardcoded 30.
    fps: i32,
    /// Constant-quality target, stored so the QSV/AMF bitrate rebuild reuses
    /// the same `cq` the session opened with.
    cq: u32,
    /// The maxrate ceiling (bps) the encoder is CURRENTLY running with. Updated
    /// in place on an NVENC reconfigure and on a QSV/AMF rebuild — `set_bitrate`
    /// consults it (coarsened) to decide whether a change is even needed.
    maxrate_bps: usize,
    /// FR-62 A1 — how a rate move is applied on this backend (resolved at
    /// open from the encoder name + the `encoder_inplace_rate` flag).
    /// `supports_dynamic_bitrate()` = "not a rebuild", so the pump routes an
    /// in-place move through its immediate-apply arm.
    rate_mode: RateReconfig,
    /// FR-62 A1 — the HRD/VBV buffer window as a percent of maxrate, captured
    /// at open so an in-place move sizes `rc_buffer_size` exactly as the open
    /// did (the pre-A1 NVENC arm wrote `rc_buffer_size = target`, i.e. a 1×
    /// window, silently resizing the reservoir on every move — the bug this
    /// field fixes).
    hrd_pct: usize,
    /// FR-62 A1 — the `encoder_inplace_rate` flag captured at open. Gates the
    /// corrected `hrd_pct` sizing so a flag-OFF session is byte-for-byte the
    /// pre-A1 behaviour (NVENC wrote a 1× buffer; that is preserved when off).
    inplace_rate: bool,
    /// This session's transport verdict at open time, stored so the QSV/AMF
    /// `set_bitrate` rebuild reuses the same HRD sizing the session opened
    /// with (constrained ⇒ the trimmed `constrained_hrd_pct` window).
    constrained: bool,
    /// FR-62 A1 counters (heartbeat): in-place rate writes, encoder rebuilds,
    /// and IDRs emitted — so the before/after of the in-place flag is one grep.
    rate_moves: u32,
    rebuilds: u32,
    /// FR-65 — background-swap ADOPTIONS.
    ///
    /// 🔑 Separate from `rebuilds` deliberately: P3's whole point is that a swap
    /// is stall-free, so folding the two would lose the distinction that
    /// matters. It exists because `adopt_rebuilt` incremented **neither**
    /// counter, and on a DIRECT QSV session every rate move goes through that
    /// path — so the heartbeat read `rate_moves=0 rebuilds=0` while the encoder
    /// was being rebuilt twice within five seconds. Field 2026-09-04,
    /// CORPLAP-1: two `background-rebuilt encoder adopted` lines at 11:03:03
    /// and 11:03:08 against a heartbeat reporting no rate activity at all.
    /// A counter that reads zero through the event it counts is worse than no
    /// counter: it cost this investigation a wrong conclusion.
    swaps: u32,
    idr_count: u64,
    /// FR-118 P0 — where `encode_sync`'s time goes, cumulative for this
    /// encoder (a background swap keeps the struct, so it keeps counting).
    stage: StageTimes,
    /// FR-85 P1b — a RECORDING encoder's GOP (frames between keyframes).
    /// `None` for every live encoder, whose keyframes are on demand only
    /// (`KEYFRAME_INTERVAL`); kept so a rebuild reproduces it.
    gop_override: Option<i32>,
    /// FR-85 P1b — PTS from this encoder's own frame counter instead of
    /// `Frame.monotonic_us`. A recording repeats the last frame on a still
    /// screen (constant frame rate), and a repeated frame must not repeat a
    /// timestamp. `false` for every live encoder.
    counter_pts: bool,
}

/// FR-85 P1b — what turns an FFmpeg open into a RECORDING encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordingOpen {
    /// Frames between keyframes.
    gop: i32,
    /// The constant-quality target before any bias.
    cq: u32,
}

/// FR-85 P1b — the recording's quality target: sharper than the live
/// default (22), because a file has no link to fit. `MESHHARBORD_RECORD_CQ`
/// overrides; clamped to the same [10, 40] as the live knob.
fn recording_cq() -> u32 {
    node_env("RECORD_CQ")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|c| c.clamp(10, 40))
        .unwrap_or(19)
}

/// FR-85 P1b — a recording encoder's ceiling. The live option sets are reused
/// as they are (every one of them is field-proven on the fleet), so what
/// `maxrate` MEANS differs per backend, and so does the number:
///
/// - NVENC runs constant-quality VBR with `bit_rate=0`: `maxrate` is only a
///   burst ceiling, so it is generous (~0.3 bpp·s, 10–80 Mbps);
/// - QSV / AMF / VAAPI / D3D12 / Vulkan / VideoToolbox anchor their rate
///   control ON `maxrate` (QSV opens as CBR when `b:v == maxrate`), so the
///   ceiling IS the bitrate: ~0.12 bpp·s, 6–40 Mbps — 1080p30 ≈ 7.5 Mbps,
///   4K30 ≈ 30 Mbps, ample for screen content.
///
/// True per-backend constant-quality modes (ICQ, CQP) are a follow-up that
/// needs field measurement on each vendor's hardware first.
pub(crate) fn recording_maxrate_bps(name: &str, width: u32, height: u32, fps: u32) -> usize {
    let px_per_s = u64::from(width) * u64::from(height) * u64::from(fps.max(1));
    let (bpp_milli, lo, hi) = if name.contains("nvenc") {
        (300u64, 10_000_000u64, 80_000_000u64)
    } else {
        (120u64, 6_000_000u64, 40_000_000u64)
    };
    (px_per_s * bpp_milli / 1000).clamp(lo, hi) as usize
}

/// FR-85 P1b — the PTS of frame `n` at `fps`, in the time base. Strictly
/// increasing for any fps up to the time base's resolution (a million),
/// which is what a counter-timed encoder needs. FR-119 P2a moved it from
/// milliseconds to the microsecond time base with the live pts.
fn recording_pts(n: u64, fps: i32) -> i64 {
    (n * TIME_BASE_DEN as u64 / u64::from(fps.max(1) as u32)) as i64
}

/// FR-62 A1 — how `set_bitrate` applies a rate move on a given backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateReconfig {
    /// NVENC: write `rc_max_rate` + `rc_buffer_size` on the `AVCodecContext`;
    /// `bit_rate` stays 0 (cq-driven VBR). FFmpeg's `reconfig_encoder` picks
    /// it up on the next `send_frame`.
    InPlaceVbr,
    /// QSV (CBR — our `rc_max_rate == bit_rate` config): write `bit_rate` +
    /// `rc_max_rate` + `rc_buffer_size` together; `qsvenc.c`'s per-frame
    /// `update_bitrate` re-reads them and resets the encoder's BRC.
    InPlaceCbr,
    /// QSV/AMF/VideoToolbox when in-place is off or unsupported — rebuild.
    Rebuild,
}

/// FR-62 A1 — resolve the apply path for a backend. NVENC is always in-place
/// (that is the pre-A1 behaviour); QSV goes in-place only when the flag is on,
/// else it rebuilds as before; AMF/VideoToolbox always rebuild (unmeasured /
/// no runtime path in FFmpeg n8.1.2). FR-78 P2 — VAAPI, D3D12 and Vulkan
/// rebuild too, and for the last two that is MEASURED (the A0 ladder on the
/// dev box: 20/20 rate-caused IDRs, 42–77 ms per apply, on `hevc_vulkan` and
/// `hevc_d3d12va`) — FFmpeg's `vulkan_encode` / `d3d12va_encode` set rate
/// control at session init and never re-read `rc_max_rate`.
pub(crate) fn resolve_rate_mode(name: &str, inplace_rate: bool) -> RateReconfig {
    if name.contains("nvenc") {
        RateReconfig::InPlaceVbr
    } else if inplace_rate && (name.contains("qsv") || name.contains("_amf")) {
        // AMF is unmeasured (no host); keep it Rebuild until A0 covers it —
        // only QSV opts in here.
        if name.contains("qsv") {
            RateReconfig::InPlaceCbr
        } else {
            RateReconfig::Rebuild
        }
    } else {
        RateReconfig::Rebuild
    }
}

/// FR-62 A2 — does our vendored FFmpeg force an IDR on an NVENC bitrate-only
/// reconfigure? **No.** `.github/ffmpeg-patches/0001-nvenc-no-idr-on-bitrate-reconfig`
/// drops `resetEncoder = forceIDR = 1` from `nvenc.c`'s `reconfig_encoder`, and
/// the A0 sweep measured 0/20 rate-caused IDRs on the RTX (both the default and
/// the constrained/relay HRD window). The const and the FFmpeg it describes ship
/// in the SAME binary — the release-agent drift gate makes an unpatched build
/// unshippable — so this can never be out of sync with the linked encoder. The
/// single flip point if a future FFmpeg revision restores the forced IDR.
const NVENC_RECONFIG_FORCES_IDR: bool = false;

/// FR-62 A2 — does a live rate move on this backend emit a keyframe the pump
/// must ration (defer / coalesce), given the NVENC escape-hatch state? Pure, so
/// the matrix is unit-tested without constructing an encoder. NVENC's in-place
/// VBR reconfigure does not (see [`NVENC_RECONFIG_FORCES_IDR`]); QSV's in-place
/// CBR path runs `MFXVideoENCODE_Reset`, whose new-sequence behaviour is
/// UNVALIDATED on real Intel silicon, so it is conservatively assumed to force
/// one until A0-QSV says otherwise; a rebuild always ships a fresh IDR.
pub(crate) fn reconfig_forces_idr_for(mode: RateReconfig, assume_nvenc_idr: bool) -> bool {
    match mode {
        RateReconfig::InPlaceVbr => NVENC_RECONFIG_FORCES_IDR || assume_nvenc_idr,
        RateReconfig::InPlaceCbr | RateReconfig::Rebuild => true,
    }
}

/// FR-62 A1 — per-encoder rate-apply counters, surfaced through
/// [`VideoEncoder::rate_stats`] into the DC pump heartbeat.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateStats {
    pub rate_moves: u32,
    pub rebuilds: u32,
    /// Background-swap adoptions — see `FfmpegEncoder::swaps`. A rate move on a
    /// direct QSV session lands here and in NEITHER of the two above.
    pub swaps: u32,
    pub idr_count: u64,
    /// FR-118 P0 — the encode stage, split.
    pub stage: StageTimes,
}

/// FR-118 P0 — where `encode_sync`'s time goes, cumulative for one encoder.
///
/// The heartbeat's `avg_encode_ms` times the whole call, so it cannot say how
/// much of a frame is the CPU round trip FR-118 would remove and how much is
/// the hardware encode. The four parts, in call order:
///
/// - `convert`: `convert_bgra` and the `AVFrame` build (CPU colour conversion
///   and a plane copy);
/// - `upload`: the hardware-frame upload, VAAPI / D3D12 / Vulkan only (zero
///   elsewhere);
/// - `submit`: `send_frame`, where NVENC, QSV and AMF upload a software frame
///   themselves;
/// - `drain`: receiving the packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StageTimes {
    /// Which encoder these counters belong to. An inline re-open builds a new
    /// encoder whose counters start at zero, so a window that crosses one must
    /// not be diffed against the old encoder's totals.
    pub encoder_id: u64,
    pub frames: u64,
    pub convert_us: u64,
    pub upload_us: u64,
    pub submit_us: u64,
    pub drain_us: u64,
}

impl StageTimes {
    fn for_new_encoder() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            encoder_id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ..Self::default()
        }
    }

    /// Per-frame milliseconds `[convert, upload, submit, drain]` over the
    /// window since `prev`. A different encoder than `prev`'s means everything
    /// this one counted is the window. `None` when the window encoded nothing.
    pub fn window_ms_since(&self, prev: &StageTimes) -> Option<[f64; 4]> {
        let base = if prev.encoder_id == self.encoder_id {
            *prev
        } else {
            StageTimes::default()
        };
        let frames = self.frames.saturating_sub(base.frames);
        if frames == 0 {
            return None;
        }
        let per_frame =
            |now: u64, then: u64| now.saturating_sub(then) as f64 / frames as f64 / 1000.0;
        Some([
            per_frame(self.convert_us, base.convert_us),
            per_frame(self.upload_us, base.upload_us),
            per_frame(self.submit_us, base.submit_us),
            per_frame(self.drain_us, base.drain_us),
        ])
    }
}

/// FR-62 A1 — the HRD/VBV window (percent of maxrate) this backend opens with:
/// `constrained_hrd_pct` on a relay session, `direct_hrd_pct` otherwise, floored
/// at 200 for `av1_*` (Intel's AV1 VDENC errors, then hangs, on a forced IDR
/// larger than the reservoir — the rc.443 incident). The single source of the
/// sizing so an open and an in-place move never disagree.
pub(crate) fn open_hrd_pct(name: &str, constrained: bool) -> usize {
    let base = if constrained {
        crate::encode::rate_profile::constrained_hrd_pct()
    } else {
        crate::encode::rate_profile::direct_hrd_pct()
    };
    // FR-70 M3a — the AV1 floor is the pure `hrd_pct_for`, which the plan
    // producer applies to a base it resolved once.
    crate::encode::rate_profile::hrd_pct_for(name, base)
}

impl FfmpegEncoder {
    /// Try to open an HEVC encoder via the dispatch cascade. Returns
    /// the first encoder that opens cleanly. Returns `Err` if all
    /// backends fail — the caller falls back to MF / NoopEncoder.
    ///
    /// Fixed-30-fps + env-based relay clamp. Used by the caps probe and the
    /// legacy REMB-adaptive WebRTC track path; the DataChannel pump uses
    /// [`Self::new_hevc_adaptive`] to thread its real per-session fps + ceiling.
    pub fn new_hevc(width: u32, height: u32) -> Result<Self> {
        let constrained = crate::encode::transport_is_constrained();
        let maxrate = ffmpeg_maxrate_bps(width, height, DEFAULT_ENCODER_FPS as u32, constrained);
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::Hevc),
            width,
            height,
            DEFAULT_ENCODER_FPS,
            maxrate,
            0,
            false,
            constrained,
        )
    }

    /// rc.83 — Try to open a VP9 HW encoder. Currently Intel oneVPL
    /// only (`vp9_qsv`). Returns `Err` on non-Intel hosts; the caller
    /// falls back to libvpx SW. Profile 0 (4:2:0 8-bit) is the only
    /// profile vp9_qsv supports — 4:4:4 sessions stay on libvpx
    /// regardless of this method's availability.
    pub fn new_vp9(width: u32, height: u32) -> Result<Self> {
        let constrained = crate::encode::transport_is_constrained();
        let maxrate = ffmpeg_maxrate_bps(width, height, DEFAULT_ENCODER_FPS as u32, constrained);
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::Vp9),
            width,
            height,
            DEFAULT_ENCODER_FPS,
            maxrate,
            0,
            false,
            constrained,
        )
    }

    /// Phase B — DataChannel-pump HEVC constructor. Threads the session's real
    /// `target_fps` and a per-session `maxrate_bps` ceiling (relay-aware, from
    /// the pump's `detect_constrained_transport`), so the encoder's framerate
    /// and burst cap match the actual link instead of the fixed-30 defaults.
    /// P7 — `cq_bias`: extra CQ sharpening steps for deep resolution rungs
    /// (`rate_profile::scale_cq_bias`, computed by the pump at each rebuild
    /// from encode-vs-native area); the probe constructors pass 0.
    ///
    /// P7 — `chroma444`: try HEVC Rext 4:4:4 first (kills ClearType chroma
    /// fringing — the RDP-AVC444 rationale). **nvenc-only**: NVENC supports
    /// HEVC 4:4:4 since Maxwell-gen2, QSV Rext ENCODE is unreliable and AMF
    /// has none, so the 4:4:4 attempt never cascades past hevc_nvenc. On
    /// rejection (driver / GPU-generation surprise) falls back to the full
    /// 4:2:0 cascade — the caller reads [`Self::chroma444`] for the truth.
    pub fn new_hevc_adaptive(
        width: u32,
        height: u32,
        fps: u32,
        maxrate_bps: usize,
        cq_bias: i32,
        chroma444: bool,
        constrained: bool,
    ) -> Result<Self> {
        if chroma444 {
            // FR-77 P3b — every backend the source matrix can open in 4:4:4,
            // minus the denylist (`cells::names_444`): hevc_nvenc (planar
            // yuv444p) and hevc_qsv (packed VUYX, denied by default until its
            // field test takes it off the list).
            let names = crate::encode::cells::names_444(
                meshharbor_remote_control::models::VideoCodec::Hevc,
            );
            if names.is_empty() {
                tracing::info!(
                    "HEVC 4:4:4 requested but no backend is allowed to try it — running 4:2:0"
                );
            } else {
                match Self::new_with_dispatch(
                    &names,
                    width,
                    height,
                    fps.max(1) as i32,
                    maxrate_bps,
                    cq_bias,
                    true,
                    constrained,
                ) {
                    Ok(enc) => return Ok(enc),
                    Err(e) => tracing::warn!(
                        %e,
                        tried = ?names,
                        "HEVC 4:4:4 (Rext) open failed — falling back to 4:2:0 Main"
                    ),
                }
            }
        }
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::Hevc),
            width,
            height,
            fps.max(1) as i32,
            maxrate_bps,
            cq_bias,
            false,
            constrained,
        )
    }

    /// Phase B — DataChannel-pump VP9 (`vp9_qsv`) constructor. See
    /// [`Self::new_hevc_adaptive`].
    ///
    /// FR-77 P3b — `chroma444`: the HARDWARE profile-1 cell (`vp9_qsv` over
    /// packed VUYX, `cells::names_444`). Deliberately NO 4:2:0 fallback on
    /// rejection: the caller's libvpx path is the one that emits profile 1,
    /// and the viewer configured its decoder for the profile it asked for —
    /// a VP9 profile mismatch is a blank canvas, not a softer picture.
    pub fn new_vp9_adaptive(
        width: u32,
        height: u32,
        fps: u32,
        maxrate_bps: usize,
        cq_bias: i32,
        chroma444: bool,
        constrained: bool,
    ) -> Result<Self> {
        if chroma444 {
            let names =
                crate::encode::cells::names_444(meshharbor_remote_control::models::VideoCodec::Vp9);
            if names.is_empty() {
                return Err(anyhow!("no VP9 backend is allowed to open 4:4:4"));
            }
            return Self::new_with_dispatch(
                &names,
                width,
                height,
                fps.max(1) as i32,
                maxrate_bps,
                cq_bias,
                true,
                constrained,
            );
        }
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::Vp9),
            width,
            height,
            fps.max(1) as i32,
            maxrate_bps,
            cq_bias,
            false,
            constrained,
        )
    }

    /// rc.190 — AV1 probe constructor (caps.rs). HW-only cascade
    /// (`av1_nvenc` → `av1_qsv` → `av1_amf`); `Err` on hosts without AV1
    /// encode silicon, which simply don't advertise `data-channel-av1`.
    pub fn new_av1(width: u32, height: u32) -> Result<Self> {
        let constrained = crate::encode::transport_is_constrained();
        let maxrate = ffmpeg_maxrate_bps(width, height, DEFAULT_ENCODER_FPS as u32, constrained);
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::Av1),
            width,
            height,
            DEFAULT_ENCODER_FPS,
            maxrate,
            0,
            false,
            constrained,
        )
    }

    /// rc.190 — DataChannel-pump AV1 constructor. See
    /// [`Self::new_hevc_adaptive`] for the fps/maxrate/cq_bias threading
    /// contract.
    pub fn new_av1_adaptive(
        width: u32,
        height: u32,
        fps: u32,
        maxrate_bps: usize,
        cq_bias: i32,
        constrained: bool,
    ) -> Result<Self> {
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::Av1),
            width,
            height,
            fps.max(1) as i32,
            maxrate_bps,
            cq_bias,
            false,
            constrained,
        )
    }

    /// P2 — H.264 probe constructor (caps.rs). HW-only cascade
    /// (`h264_nvenc` → `h264_qsv` → `h264_amf`); `Err` on hosts without
    /// H.264 encode silicon, which don't advertise `data-channel-h264`.
    pub fn new_h264(width: u32, height: u32) -> Result<Self> {
        let constrained = crate::encode::transport_is_constrained();
        let maxrate = ffmpeg_maxrate_bps(width, height, DEFAULT_ENCODER_FPS as u32, constrained);
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::H264),
            width,
            height,
            DEFAULT_ENCODER_FPS,
            maxrate,
            0,
            false,
            constrained,
        )
    }

    /// P2 — DataChannel-pump H.264 constructor. See
    /// [`Self::new_hevc_adaptive`] for the fps/maxrate threading contract.
    /// The name-substring-keyed `encoder_options` gives h264_nvenc/qsv/amf
    /// the same cq/maxrate/bufsize/forced-idr/low-latency knobs as their
    /// HEVC siblings, and the GOP site gives them `KEYFRAME_INTERVAL`
    /// (they honour runtime forced IDR → on-demand-only keys like
    /// HEVC/AV1). The bitstream is Annex-B with in-band SPS/PPS (FFmpeg
    /// default without `GLOBAL_HEADER` — the same contract the HEVC path
    /// ships and WebCodecs decodes description-less).
    /// P2 — DataChannel-pump H.264 constructor (see [`Self::new_hevc_adaptive`]).
    ///
    /// FR-77 P3b — `chroma444`: High 4:4:4 Predictive on the backends the
    /// source matrix allows (`h264_nvenc` today, `cells::names_444`). Like
    /// HEVC, a rejection falls back to the 4:2:0 cascade and the pump reports
    /// the truth through [`Self::chroma444`].
    pub fn new_h264_adaptive(
        width: u32,
        height: u32,
        fps: u32,
        maxrate_bps: usize,
        cq_bias: i32,
        chroma444: bool,
        constrained: bool,
    ) -> Result<Self> {
        if chroma444 {
            let names = crate::encode::cells::names_444(
                meshharbor_remote_control::models::VideoCodec::H264,
            );
            if names.is_empty() {
                tracing::info!(
                    "H.264 4:4:4 requested but no backend is allowed to try it — running 4:2:0"
                );
            } else {
                match Self::new_with_dispatch(
                    &names,
                    width,
                    height,
                    fps.max(1) as i32,
                    maxrate_bps,
                    cq_bias,
                    true,
                    constrained,
                ) {
                    Ok(enc) => return Ok(enc),
                    Err(e) => tracing::warn!(
                        %e,
                        tried = ?names,
                        "H.264 4:4:4 (High 4:4:4 Predictive) open failed — falling back to 4:2:0 High"
                    ),
                }
            }
        }
        Self::new_with_dispatch(
            &crate::encode::cells::names_420(meshharbor_remote_control::models::VideoCodec::H264),
            width,
            height,
            fps.max(1) as i32,
            maxrate_bps,
            cq_bias,
            false,
            constrained,
        )
    }

    /// P4 — resolve the (gop, low_power) a vp9_qsv open should use from the
    /// cached probe verdict + the `MESHHARBORD_QSV_LOW_POWER` override.
    /// Mapping lives in `encode::rate_profile::vp9_qsv_config` (pure,
    /// default-build tested); falls back to the rc.219 containment (GOP 60 +
    /// VDEnc) when unprobed.
    fn vp9_qsv_runtime_config() -> (i32, bool) {
        let forced_lp = node_env("QSV_LOW_POWER").and_then(|v| match v.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        });
        let (long_gop, low_power) = crate::encode::rate_profile::vp9_qsv_config(
            VP9_QSV_IDR_VERDICT.get().copied(),
            forced_lp,
        );
        (
            if long_gop {
                KEYFRAME_INTERVAL
            } else {
                VP9_QSV_KEYFRAME_INTERVAL
            },
            low_power,
        )
    }

    /// rc.445 — single-name open for a REBUILD whose backend is already
    /// proven this session: skips the cascade's dead prefix (a failed
    /// tiered open of an absent vendor's encoder costs 100-300 ms — pure
    /// stall when it precedes every mid-session rebuild). `name` must be
    /// one of the cascade names; an unknown/failed open just errs and the
    /// caller falls back to the full cascade.
    #[allow(clippy::too_many_arguments)]
    pub fn new_preferred(
        name: &'static str,
        width: u32,
        height: u32,
        fps: u32,
        maxrate_bps: usize,
        cq_bias: i32,
        constrained: bool,
    ) -> Result<Self> {
        // FR-78 P3 — a rebuild may only reuse a name the denylist allows. The
        // cascade that produced `name` was filtered and the list cannot change
        // under a running daemon, so this restates the invariant "a denied
        // cell is never opened" at the one entry the cascade does not cover;
        // it is not a live decision.
        if crate::encode::cells::cell_denied(
            &crate::encode::cells::denied_cells(),
            name,
            meshharbor_remote_control::models::ChromaFormat::Yuv420,
        ) {
            anyhow::bail!("{name}:yuv420 is on the device denylist");
        }
        Self::new_with_dispatch(
            &[name],
            width,
            height,
            fps.max(1) as i32,
            maxrate_bps,
            cq_bias,
            false,
            constrained,
        )
    }

    /// FR-77 — the cascade table for `codec`, in the order a session tries
    /// the backends. The capability probe walks the WHOLE table (every cell),
    /// a session stops at the first that opens; both read the same list, so
    /// what the probe advertises and what a session can reach cannot drift.
    pub(crate) fn cascade_names(
        codec: meshharbor_remote_control::models::VideoCodec,
    ) -> &'static [&'static str] {
        use meshharbor_remote_control::models::VideoCodec;
        match codec {
            VideoCodec::Hevc => HEVC_ENCODER_NAMES,
            VideoCodec::Av1 => AV1_ENCODER_NAMES,
            VideoCodec::H264 => H264_ENCODER_NAMES,
            VideoCodec::Vp9 => VP9_ENCODER_NAMES,
        }
    }

    /// FR-77 P3c — the cascade tables' own `&'static str` for a name that
    /// arrived as a runtime string (the 4:4:4 probe child reads its list
    /// from the environment). `None` for a name no table carries.
    pub fn static_name(name: &str) -> Option<&'static str> {
        HEVC_ENCODER_NAMES
            .iter()
            .chain(VP9_ENCODER_NAMES.iter())
            .chain(AV1_ENCODER_NAMES.iter())
            .chain(H264_ENCODER_NAMES.iter())
            .copied()
            .find(|n| *n == name)
    }

    /// FR-77 — open ONE named encoder at the probe's settings (30 fps, the
    /// standard ceiling, no CQ bias) in the requested chroma format. This is
    /// the capability probe's per-cell open; a session never calls it — it
    /// goes through the `*_adaptive` cascades, which stay untouched.
    pub fn new_named_probe(
        name: &'static str,
        width: u32,
        height: u32,
        chroma444: bool,
    ) -> Result<Self> {
        let constrained = crate::encode::transport_is_constrained();
        let maxrate = ffmpeg_maxrate_bps(width, height, DEFAULT_ENCODER_FPS as u32, constrained);
        Self::new_with_dispatch(
            &[name],
            width,
            height,
            DEFAULT_ENCODER_FPS,
            maxrate,
            0,
            chroma444,
            constrained,
        )
    }

    /// FR-77 — is a successful `*_qsv` open PROOF of hardware encode?
    ///
    /// Yes on the oneVPL (libvpl) build, and only there: FFmpeg's internal
    /// MFX session filters `mfxImplDescription.Impl = MFX_IMPL_TYPE_HARDWARE`
    /// (n9.0.1 `libavcodec/qsv.c:518-522`), so the dispatcher never enumerates
    /// Intel's CPU runtime — an open either lands on silicon or fails. The
    /// legacy libmfx build asks `MFX_IMPL_AUTO_ANY`, which CAN pick a software
    /// library. The two are told apart by `av1_qsv`, which configure only
    /// compiles under libvpl (`av1_qsv_encoder_deps="libvpl"`), so its mere
    /// registration is the flavour check — no FFI into libvpl needed.
    pub fn qsv_is_hardware_by_construction() -> bool {
        if ffmpeg_next::init().is_err() {
            return false;
        }
        codec::encoder::find_by_name("av1_qsv").is_some()
    }

    /// P4 — explicit-config vp9_qsv constructor for the IDR probe. Bypasses
    /// `vp9_qsv_runtime_config` (the probe must not consult the verdict it
    /// is in the middle of producing).
    fn new_vp9_qsv_probe(width: u32, height: u32, low_power: bool, gop: i32) -> Result<Self> {
        ffmpeg_next::init().context("ffmpeg_next::init failed")?;
        let cq = ffmpeg_cq();
        let (encoder, hw) = Self::build_encoder(
            "vp9_qsv", width, height, 30, 3_000_000, cq, low_power, gop, false, false, None,
        )?;
        let plane_pixels = (width as usize) * (height as usize);
        Ok(Self {
            encoder_name: "vp9_qsv",
            width,
            height,
            encoder,
            frame_count: 0,
            force_keyframe: false,
            plane_y: vec![0u8; plane_pixels],
            plane_u: vec![0u8; plane_pixels / 2],
            plane_v: Vec::new(),
            chroma444: false,
            packed444: false,
            packed: Vec::new(),
            hw,
            fps: 30,
            cq,
            maxrate_bps: 3_000_000,
            rate_mode: resolve_rate_mode("vp9_qsv", crate::encode::encoder_inplace_rate_enabled()),
            hrd_pct: open_hrd_pct("vp9_qsv", false),
            inplace_rate: crate::encode::encoder_inplace_rate_enabled(),
            constrained: false,
            rate_moves: 0,
            rebuilds: 0,
            swaps: 0,
            idr_count: 0,
            stage: StageTimes::for_new_encoder(),
            gop_override: None,
            counter_pts: false,
        })
    }

    /// P4 — startup probe (caps.rs): for each `low_power` mode, open vp9_qsv
    /// with an effectively-infinite GOP (so any post-frame-0 key must be
    /// FORCED — guards against a natural key faking a pass), feed synthetic
    /// frames, force a keyframe, and check whether a key-flagged packet
    /// comes out. Caches the per-host verdict for every later open. Returns
    /// the verdict for logging; ~100-300 ms per mode, once per process.
    pub fn probe_and_cache_vp9_qsv_idr() -> Option<(bool, bool)> {
        if let Some(v) = VP9_QSV_IDR_VERDICT.get() {
            return Some(*v);
        }
        let honors_lp1 = Self::vp9_qsv_idr_probe_variant(true);
        let honors_lp0 = Self::vp9_qsv_idr_probe_variant(false);
        let v = (honors_lp1, honors_lp0);
        let _ = VP9_QSV_IDR_VERDICT.set(v);
        Some(v)
    }

    /// FR-77 P3 — the vp9_qsv runtime-IDR verdict as measured, by the probe
    /// child (which ships it in its report envelope) or read back from the
    /// probe cache. `None` = never measured in this process.
    pub fn vp9_qsv_idr_verdict() -> Option<(bool, bool)> {
        VP9_QSV_IDR_VERDICT.get().copied()
    }

    /// FR-77 P3 — install a verdict measured elsewhere. First writer wins,
    /// exactly as the probe itself behaves. Before this existed the verdict
    /// lived only in the CHILD process (rc.433 moved the probe out of
    /// process) and every vp9_qsv session ran the GOP-60 containment.
    pub fn set_vp9_qsv_idr_verdict(verdict: (bool, bool)) {
        let _ = VP9_QSV_IDR_VERDICT.set(verdict);
    }

    fn vp9_qsv_idr_probe_variant(low_power: bool) -> bool {
        const W: u32 = 480;
        const H: u32 = 270;
        let mk = |i: u32| -> Arc<Frame> {
            // Mid-gray with one moving bright pixel so every frame has a
            // real (tiny) delta to code.
            let mut data = vec![128u8; (W * H * 4) as usize];
            let px = (i as usize * 5227) % ((W * H) as usize);
            data[px * 4] = 255;
            Arc::new(Frame {
                width: W,
                height: H,
                stride: W * 4,
                pixel_format: PixelFormat::Bgra,
                data,
                monotonic_us: i as u64 * 33_333,
                monitor: 0,
                damage: crate::capture::Damage::Unknown,
                source: None,
            })
        };
        let mut enc = match Self::new_vp9_qsv_probe(W, H, low_power, KEYFRAME_INTERVAL) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(low_power, %e, "vp9_qsv IDR probe: variant failed to open");
                return false;
            }
        };
        // Warm-up. Frame 0 is the natural stream-start key; anything AFTER
        // it flagged key means the long-GOP override isn't holding and a
        // later "forced" key would prove nothing → unusable, fail closed.
        for i in 0..4 {
            match enc.encode_sync(&mk(i)) {
                Ok(pkts) => {
                    if i > 0 && pkts.iter().any(|p| p.is_keyframe) {
                        tracing::debug!(
                            low_power,
                            "vp9_qsv IDR probe: spurious natural key during warm-up — failing closed"
                        );
                        return false;
                    }
                }
                Err(e) => {
                    tracing::debug!(low_power, %e, "vp9_qsv IDR probe: warm-up encode failed");
                    return false;
                }
            }
        }
        enc.request_keyframe();
        for i in 4..12 {
            match enc.encode_sync(&mk(i)) {
                Ok(pkts) => {
                    if pkts.iter().any(|p| p.is_keyframe) {
                        return true;
                    }
                }
                Err(e) => {
                    tracing::debug!(low_power, %e, "vp9_qsv IDR probe: post-force encode failed");
                    return false;
                }
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_dispatch(
        names: &[&'static str],
        width: u32,
        height: u32,
        fps: i32,
        maxrate_bps: usize,
        cq_bias: i32,
        chroma444: bool,
        constrained: bool,
    ) -> Result<Self> {
        Self::new_with_dispatch_opts(
            names,
            width,
            height,
            fps,
            maxrate_bps,
            cq_bias,
            chroma444,
            constrained,
            None,
        )
    }

    /// FR-85 P1b — a RECORDING encoder: the codec's 4:2:0 cascade (the device
    /// denylist honoured, exactly as a session's — `cells::names_420`), the
    /// live option sets (field-proven on every backend the fleet runs) with a
    /// sharper quality target and a recording-sized ceiling instead of the
    /// network's, a real GOP, and PTS from its own frame counter. The rate
    /// governor never touches it: nothing calls `set_bitrate` on a recording.
    pub fn new_recording(
        codec: meshharbor_remote_control::models::VideoCodec,
        width: u32,
        height: u32,
        fps: u32,
        gop_frames: u32,
    ) -> Result<Self> {
        let fps = fps.clamp(1, 60);
        let open = RecordingOpen {
            gop: gop_frames.max(1) as i32,
            cq: recording_cq(),
        };
        let mut last_err: Option<anyhow::Error> = None;
        // One name at a time: the ceiling depends on the backend.
        for name in crate::encode::cells::names_420(codec) {
            match Self::new_with_dispatch_opts(
                &[name],
                width,
                height,
                fps as i32,
                recording_maxrate_bps(name, width, height, fps),
                0,
                false,
                false,
                Some(open),
            ) {
                Ok(e) => return Ok(e),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no {codec:?} encoder is allowed on this device")))
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_dispatch_opts(
        names: &[&'static str],
        width: u32,
        height: u32,
        fps: i32,
        maxrate_bps: usize,
        cq_bias: i32,
        chroma444: bool,
        constrained: bool,
        recording: Option<RecordingOpen>,
    ) -> Result<Self> {
        // `ffmpeg_next::init()` is idempotent + cheap to call; safe to
        // run on each new encoder. Sets up codec registration.
        ffmpeg_next::init().context("ffmpeg_next::init failed")?;

        // rc.86 — RustDesk-parity rate control. Drive the encoder by
        // CONSTANT QUALITY (cq / global_quality) with a bandwidth CAP
        // (maxrate), not by the old 0.20-bpp/s VBR target. On screen
        // content this keeps text edges sharp (cq guarantees per-block
        // quality so nothing "crystallizes over seconds") while idle
        // frames cost ~0 and bursts are bounded by the cap. cq is
        // env-overridable; `fps` + `maxrate_bps` come from the caller
        // (Phase B threads the DC pump's real per-session values).
        // P7 — `cq_bias` sharpens deep resolution rungs (see
        // rate_profile::scale_cq_bias). Applied ONCE here: the encoder is
        // rebuilt on every dims change, so build-time application is exact,
        // and `self.cq` stores the biased value — the QSV/AMF set_bitrate
        // rebuild path reuses it verbatim (dims never change there).
        let base_cq = recording.map(|r| r.cq).unwrap_or_else(ffmpeg_cq);
        let cq = crate::encode::rate_profile::apply_cq_bias(base_cq, cq_bias);
        // P4 — vp9_qsv GOP/low_power from the cached startup IDR-probe
        // verdict (containment defaults when unprobed); ignored by every
        // other candidate name.
        let (qsv_gop, qsv_low_power) = Self::vp9_qsv_runtime_config();

        let mut last_err: Option<anyhow::Error> = None;
        for name in names {
            match Self::build_encoder(
                name,
                width,
                height,
                fps,
                maxrate_bps,
                cq,
                qsv_low_power,
                qsv_gop,
                chroma444,
                constrained,
                recording.map(|r| r.gop),
            ) {
                Ok((encoder, hw)) => {
                    tracing::info!(
                        encoder = name,
                        width,
                        height,
                        fps,
                        cq,
                        cq_bias,
                        maxrate_bps,
                        chroma444,
                        recording = recording.is_some(),
                        "ffmpeg encoder opened (constant-quality + maxrate cap)"
                    );
                    let plane_pixels = (width as usize) * (height as usize);
                    return Ok(Self {
                        encoder_name: name,
                        width,
                        height,
                        encoder,
                        frame_count: 0,
                        force_keyframe: false,
                        plane_y: vec![0u8; plane_pixels],
                        // NV12: UV is half-width × half-height × 2 channels
                        // = pixels / 2. I444: full-resolution U plane.
                        plane_u: vec![
                            0u8;
                            if chroma444 {
                                plane_pixels
                            } else {
                                plane_pixels / 2
                            }
                        ],
                        plane_v: vec![0u8; if chroma444 { plane_pixels } else { 0 }],
                        chroma444,
                        packed444: chroma444 && packed444_name(name),
                        packed: Vec::new(),
                        hw,
                        fps,
                        cq,
                        maxrate_bps,
                        rate_mode: resolve_rate_mode(
                            name,
                            crate::encode::encoder_inplace_rate_enabled(),
                        ),
                        hrd_pct: open_hrd_pct(name, constrained),
                        inplace_rate: crate::encode::encoder_inplace_rate_enabled(),
                        constrained,
                        rate_moves: 0,
                        rebuilds: 0,
                        swaps: 0,
                        idr_count: 0,
                        stage: StageTimes::for_new_encoder(),
                        gop_override: recording.map(|r| r.gop),
                        counter_pts: recording.is_some(),
                    });
                }
                Err(e) => {
                    // rc.85 — DEBUG not WARN. A candidate failing in the
                    // cascade is the cascade doing its job, not a warning
                    // condition. The CALLER logs the consequential outcome
                    // at the right level (caps.rs: INFO+%e for VP9, WARN
                    // for HEVC; peer.rs: falls through to libvpx/MF). The
                    // "; trying next" suffix lied for single-entry lists
                    // (VP9_ENCODER_NAMES = ["vp9_qsv"]). Error reason is
                    // preserved in `last_err` → surfaced by the caller.
                    tracing::debug!(encoder = name, error = %e, "ffmpeg encoder candidate failed to open");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no ffmpeg encoder candidates were tried")))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_encoder(
        name: &'static str,
        width: u32,
        height: u32,
        fps: i32,
        maxrate_bps: usize,
        cq: u32,
        qsv_low_power: bool,
        qsv_gop: i32,
        chroma444: bool,
        constrained: bool,
        gop_override: Option<i32>,
    ) -> Result<(codec::encoder::Video, Option<hwframes::Frames>)> {
        let codec = codec::encoder::find_by_name(name)
            .ok_or_else(|| anyhow!("ffmpeg encoder not registered: {}", name))?;

        let (base, lowlat, opt_summary) =
            encoder_options(name, maxrate_bps, cq, qsv_low_power, chroma444, constrained);

        // FR-77 P4 / FR-78 P1 — a `*_vaapi` / `*_d3d12va` / `*_vulkan`
        // encoder takes HARDWARE frames from a pool on one of the kind's
        // devices, and which device is decided by the OPEN: on a two-GPU
        // laptop the loader's device 0 is the iGPU, which may lack the
        // codec (no AV1 on an RDNA2 iGPU) or the video-encode queue
        // altogether (measured on the dev box: Vulkan device 0 had no
        // `VK_KHR_video_encode_queue`, the RTX did). So the whole
        // configure-and-open below runs once per candidate device until one
        // succeeds, and the winner is remembered for the next open.
        let open_with = |hw_frames: Option<hwframes::Frames>| -> Result<(
            codec::encoder::Video,
            Option<hwframes::Frames>,
        )> {
        // rc.86 — configure an unopened encoder. Factored into a closure
        // so we can rebuild it for the fallback path (open_*_with consumes
        // the encoder, so a failed open can't be retried on the same one).
        //
        // rc.89 fix: the UNOPENED encoder is `encoder::video::Video`,
        // which is a DIFFERENT type from `codec::encoder::Video` (the
        // OPENED encoder this fn returns). `open_as*` converts unopened →
        // opened. The closure must therefore declare the unopened type;
        // annotating it as the opened type was the rc.86 CI E0308.
        let configure = || -> Result<ffmpeg_next::encoder::video::Video> {
            let ctx = codec::Context::new_with_codec(codec);
            let mut enc = ctx.encoder().video().context("encoder().video() failed")?;
            enc.set_width(width);
            enc.set_height(height);
            if let Some(frames) = &hw_frames {
                // FR-77 P4 / FR-78 P1 — the encoder sees the kind's hardware
                // surfaces (VAAPI / D3D12 / Vulkan); the pool's sw_format
                // carries the real layout. A fresh ref per open attempt: a
                // rejected context frees the one it was given. The pixel
                // format goes in raw — ffmpeg-next's `Pixel` enum has no
                // D3D12 variant.
                let kind = hwframes::HwKind::of(name).expect("hw_frames exist only for a kind");
                // SAFETY: `enc` is an unopened, exclusively owned context;
                // `new_ref` hands over a reference FFmpeg unrefs on free.
                unsafe {
                    (*enc.as_mut_ptr()).pix_fmt = kind.pixel();
                    (*enc.as_mut_ptr()).hw_frames_ctx = frames.new_ref();
                }
            } else {
                // P7 — HEVC Rext 4:4:4 takes planar yuv444p; everything else
                // stays on the HW-native NV12 4:2:0. FR-77 P3b — QSV takes
                // the packed VUYX 4:4:4 instead (`chroma444_pixel`).
                enc.set_format(if chroma444 {
                    chroma444_pixel(name)
                } else {
                    format::Pixel::NV12
                });
            }
            // For NVENC constant-quality VBR we set bit_rate=0 so `cq`
            // drives quality and `maxrate` is the only ceiling (idle ≈ 0).
            // QSV/AMF keep `maxrate` as the VBR anchor since their
            // quality modes are less reliable about honouring b:v=0.
            let target_bps = if name.contains("nvenc") {
                0
            } else {
                maxrate_bps
            };
            enc.set_bit_rate(target_bps);
            // Time base: 1/1_000_000 (µs). Pts is set per frame from
            // `monotonic_us` itself (`live_pts`), FR-119 P2a.
            enc.set_time_base((1, TIME_BASE_DEN));
            enc.set_frame_rate(Some((fps, 1)));
            // rc.219 — vp9_qsv defaults to the short natural-key GOP
            // (runtime forcing historically ignored). P4 — the caller now
            // threads the PROBED per-host value (`vp9_qsv_runtime_config`):
            // hosts whose vp9_qsv measurably honours runtime forced IDRs
            // get KEYFRAME_INTERVAL (on-demand-only keys) instead.
            // FR-85 P1b — a recording keeps a real GOP: every fragment of its
            // MP4 starts on a keyframe, and an editor cut decodes at most one
            // GOP. `None` (every live open) is exactly the old rule.
            let gop = if let Some(g) = gop_override {
                g
            } else if name == "vp9_qsv" {
                qsv_gop
            } else {
                KEYFRAME_INTERVAL
            };
            enc.set_gop(gop as u32);
            enc.set_max_b_frames(0); // low-latency: no B-frames
            Ok(enc)
        };

        // TIERED open. The encoder's option dict is ALL-OR-NOTHING: if the
        // driver rejects any single private option, the WHOLE dict is
        // dropped. So the low-latency knobs (`delay`/`async_depth`/…) get
        // their own tier:
        //   1. quality + low-latency,
        //   2. quality ALONE (keeps `forced-idr` etc. if only a lowlat knob
        //      was rejected — a full revert to defaults would lose
        //      `forced-idr` → the NVENC black-screen IDR bug),
        //   3. plain defaults (blurry-but-working beats a black screen).
        let opened = 'open: {
            if !lowlat.is_empty() {
                let mut full = dict_from_pairs(&base);
                for (k, v) in &lowlat {
                    full.set(k.as_str(), v.as_str());
                }
                let enc = configure()?;
                match enc.open_as_with(codec, full) {
                    Ok(encoder) => {
                        tracing::info!(
                            encoder = name,
                            options = opt_summary,
                            "ffmpeg encoder opened with quality + low-latency options"
                        );
                        break 'open encoder;
                    }
                    Err(open_err) => {
                        tracing::warn!(
                            encoder = name,
                            %open_err,
                            "ffmpeg open rejected the low-latency knobs — retrying with quality options only"
                        );
                    }
                }
            }

            let base_summary = base
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ");
            let enc = configure()?;
            match enc.open_as_with(codec, dict_from_pairs(&base)) {
                Ok(encoder) => {
                    tracing::info!(
                        encoder = name,
                        options = base_summary,
                        "ffmpeg encoder opened with quality options"
                    );
                    encoder
                }
                Err(open_err) => {
                    tracing::warn!(
                        encoder = name,
                        %open_err,
                        attempted_options = base_summary,
                        "ffmpeg open_as_with rejected the quality options — retrying with encoder defaults"
                    );
                    let enc2 = configure()?;
                    enc2.open_as(codec)
                        .with_context(|| format!("open_as({}) fallback failed", name))?
                }
            }
        };
        Ok((opened, hw_frames))
        };

        match hwframes::HwKind::of(name) {
            Some(kind) => hwframes::open_on_some_device(kind, |dev| {
                let frames =
                    hwframes::Frames::new(dev, kind, kind.sw_format(chroma444), width, height)?;
                open_with(Some(frames))
            }),
            None => open_with(None),
        }
    }

    fn convert_bgra(&mut self, frame: &Frame) -> Result<()> {
        if frame.pixel_format != PixelFormat::Bgra {
            // Capture layer already produced NV12 — copy planes directly.
            // WGC + DXGI on Windows can emit NV12 in some configurations.
            // For rc.72 we only handle BGRA from scrap/DXGI which is our
            // current production path; NV12 from capture is a rc.73+ path.
            return Err(anyhow!(
                "ffmpeg encoder rc.72 requires BGRA capture input (got {:?})",
                frame.pixel_format
            ));
        }

        // BGRA→NV12 / BGRA→I444 via dcv_color_primitives. The crate is
        // already a dep for the libvpx VP9 4:4:4 path; both conversions use
        // the same SIMD primitives (and the same BT.601 matrix, so the P7
        // Rext path renders identically to the libvpx 4:4:4 path).
        //
        // P5 (FR-1, 2026-08-27) — big frames convert in ROW BANDS across
        // scoped threads. dcv's convert_image is single-threaded SIMD; at
        // 2880×1800 it was a large share of the 20-30 ms "encode" time
        // that capped the pump at ~40 fps. Bands split on EVEN row starts
        // (NV12's vertically-subsampled chroma pairs never straddle a cut;
        // BT.601 is pointwise per 2×2 block), so the banded output is
        // byte-identical to the full-frame call. Source slices read the
        // tail from the band start (immutable borrows may overlap);
        // destination slices are disjoint via split_at_mut. Sub-2 MPix
        // frames and the `par_convert` hatch keep the single-call path.
        use dcv_color_primitives::{
            ColorSpace, ImageFormat, PixelFormat as DcvPixelFormat, convert_image,
        };

        let w = self.width as usize;
        let h = self.height as usize;
        let stride = frame.stride as usize;
        let plane_pixels = w * h;
        let src_format = ImageFormat {
            pixel_format: DcvPixelFormat::Bgra,
            color_space: ColorSpace::Rgb,
            num_planes: 1,
        };
        let bands = Self::convert_bands(plane_pixels);

        if self.chroma444 {
            if self.plane_y.len() != plane_pixels {
                self.plane_y.resize(plane_pixels, 0);
                self.plane_u.resize(plane_pixels, 0);
                self.plane_v.resize(plane_pixels, 0);
            }
            let dst_format = ImageFormat {
                pixel_format: DcvPixelFormat::I444,
                color_space: ColorSpace::Bt601,
                num_planes: 3,
            };
            let dst_strides = [w, w, w];
            if bands <= 1 {
                let mut dst_planes: [&mut [u8]; 3] = {
                    let (y, rest) = (
                        &mut self.plane_y[..],
                        (&mut self.plane_u[..], &mut self.plane_v[..]),
                    );
                    [y, rest.0, rest.1]
                };
                convert_image(
                    self.width,
                    self.height,
                    &src_format,
                    Some(&[stride]),
                    &[&frame.data],
                    &dst_format,
                    Some(&dst_strides),
                    &mut dst_planes,
                )
                .map_err(|e| anyhow!("dcv BGRA→I444 convert failed: {:?}", e))?;
                return Ok(());
            }
            let cuts = Self::band_cuts(h, bands);
            let mut y_rest: &mut [u8] = &mut self.plane_y[..];
            let mut u_rest: &mut [u8] = &mut self.plane_u[..];
            let mut v_rest: &mut [u8] = &mut self.plane_v[..];
            std::thread::scope(|s| -> Result<()> {
                let mut handles = Vec::with_capacity(cuts.len());
                for &(r0, bh) in &cuts {
                    let (y_band, yr) = std::mem::take(&mut y_rest).split_at_mut(bh * w);
                    let (u_band, ur) = std::mem::take(&mut u_rest).split_at_mut(bh * w);
                    let (v_band, vr) = std::mem::take(&mut v_rest).split_at_mut(bh * w);
                    y_rest = yr;
                    u_rest = ur;
                    v_rest = vr;
                    let src = &frame.data[r0 * stride..];
                    let sf = &src_format;
                    let df = &dst_format;
                    let ds = &dst_strides;
                    handles.push(s.spawn(move || {
                        let mut dst: [&mut [u8]; 3] = [y_band, u_band, v_band];
                        convert_image(
                            w as u32,
                            bh as u32,
                            sf,
                            Some(&[stride]),
                            &[src],
                            df,
                            Some(ds),
                            &mut dst,
                        )
                    }));
                }
                for hnd in handles {
                    hnd.join()
                        .map_err(|_| anyhow!("convert band thread panicked"))?
                        .map_err(|e| anyhow!("dcv BGRA→I444 band convert failed: {:?}", e))?;
                }
                Ok(())
            })?;
            self.pack_if_needed();
            return Ok(());
        }

        if self.plane_y.len() != plane_pixels {
            self.plane_y.resize(plane_pixels, 0);
            self.plane_u.resize(plane_pixels / 2, 0);
        }
        let dst_format = ImageFormat {
            pixel_format: DcvPixelFormat::Nv12,
            color_space: ColorSpace::Bt601,
            num_planes: 2,
        };
        // Two-plane NV12: Y is width × height; UV is interleaved
        // width × (height / 2) bytes (== plane_pixels / 2 in interleaved form).
        let dst_strides = [w, w];

        if bands <= 1 {
            let mut dst_planes: [&mut [u8]; 2] = {
                let (y, uv) = (&mut self.plane_y[..], &mut self.plane_u[..]);
                [y, uv]
            };
            convert_image(
                self.width,
                self.height,
                &src_format,
                Some(&[stride]),
                &[&frame.data],
                &dst_format,
                Some(&dst_strides),
                &mut dst_planes,
            )
            .map_err(|e| anyhow!("dcv BGRA→NV12 convert failed: {:?}", e))?;
            self.pack_if_needed();
            return Ok(());
        }

        let cuts = Self::band_cuts(h, bands);
        let mut y_rest: &mut [u8] = &mut self.plane_y[..];
        let mut uv_rest: &mut [u8] = &mut self.plane_u[..];
        std::thread::scope(|s| -> Result<()> {
            let mut handles = Vec::with_capacity(cuts.len());
            for &(r0, bh) in &cuts {
                let (y_band, yr) = std::mem::take(&mut y_rest).split_at_mut(bh * w);
                let (uv_band, uvr) = std::mem::take(&mut uv_rest).split_at_mut((bh / 2) * w);
                y_rest = yr;
                uv_rest = uvr;
                let src = &frame.data[r0 * stride..];
                let sf = &src_format;
                let df = &dst_format;
                let ds = &dst_strides;
                handles.push(s.spawn(move || {
                    let mut dst: [&mut [u8]; 2] = [y_band, uv_band];
                    convert_image(
                        w as u32,
                        bh as u32,
                        sf,
                        Some(&[stride]),
                        &[src],
                        df,
                        Some(ds),
                        &mut dst,
                    )
                }));
            }
            for hnd in handles {
                hnd.join()
                    .map_err(|_| anyhow!("convert band thread panicked"))?
                    .map_err(|e| anyhow!("dcv BGRA→NV12 band convert failed: {:?}", e))?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// P5 — band count for the threaded convert: single-call under 2 MPix
    /// (thread spawn overhead beats the win there) or when hatched off
    /// (`MESHHARBORD_PAR_CONVERT=0` / config `par_convert`); else
    /// min(4, cores).
    fn convert_bands(plane_pixels: usize) -> usize {
        if plane_pixels < 2_000_000 || !crate::encode::par_convert_enabled() {
            return 1;
        }
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 4)
    }

    /// P5 — split `h` rows into up to `bands` cuts with EVEN row starts and
    /// even heights except possibly the last (the pump masks dims `& !1`,
    /// so `h` itself is even and every band height comes out even too).
    fn band_cuts(h: usize, bands: usize) -> Vec<(usize, usize)> {
        let rows_per = ((h / bands.max(1)).max(2) + 1) & !1;
        let mut cuts = Vec::with_capacity(bands);
        let mut r0 = 0;
        while r0 < h {
            let bh = rows_per.min(h - r0);
            cuts.push((r0, bh));
            r0 += bh;
        }
        cuts
    }

    /// FR-77 P3b — for a packed-4:4:4 backend, interleave the I444 planes
    /// into the VUYX buffer the frame is built from. A no-op on every other
    /// path.
    fn pack_if_needed(&mut self) {
        if self.packed444 {
            pack_vuyx(
                &self.plane_y,
                &self.plane_u,
                &self.plane_v,
                &mut self.packed,
            );
        }
    }

    fn build_av_frame(&self, monotonic_us: u64) -> Result<frame::Video> {
        let format = if self.chroma444 {
            if self.packed444 {
                format::Pixel::VUYX
            } else {
                format::Pixel::YUV444P
            }
        } else {
            format::Pixel::NV12
        };
        let mut av = frame::Video::new(format, self.width, self.height);

        // FR-85 P1b — a recording encoder times frames by its own counter: it
        // is fed the same frame again on a still screen, and a repeated frame
        // must not repeat a timestamp. Every live encoder keeps the capture
        // clock, exactly as before.
        let pts = if self.counter_pts {
            recording_pts(self.frame_count, self.fps)
        } else {
            live_pts(monotonic_us)
        };
        av.set_pts(Some(pts));

        if self.force_keyframe || self.frame_count == 0 {
            av.set_kind(util::picture::Type::I);
            // Note: set_key_frame doesn't exist on Video in ffmpeg-next 8.x;
            // set_kind(I) is the supported way to force IDR.
        }

        // Copy our converted planes into the AVFrame's plane buffers.
        // FFmpeg's allocator gives us width/height-aligned buffers; we
        // copy row-by-row to handle stride differences.
        //
        // rc.73 borrow-checker fix: capture strides before the mutable
        // borrow from data_mut(). `av.stride(N)` takes &self while
        // `av.data_mut(N)` takes &mut self — calling them on the same
        // expression triggers E0502.
        let w = self.width as usize;
        let rows = self.height as usize;
        let y_stride = av.stride(0);
        if self.chroma444 && self.packed444 {
            // FR-77 P3b — VUYX: ONE packed plane, four bytes per pixel.
            copy_plane_into_av(av.data_mut(0), y_stride, &self.packed, w * 4, rows);
        } else {
            copy_plane_into_av(av.data_mut(0), y_stride, &self.plane_y, w, rows);
            if self.chroma444 {
                // P7 — planar I444: three full-resolution planes.
                let u_stride = av.stride(1);
                copy_plane_into_av(av.data_mut(1), u_stride, &self.plane_u, w, rows);
                let v_stride = av.stride(2);
                copy_plane_into_av(av.data_mut(2), v_stride, &self.plane_v, w, rows);
            } else {
                // NV12: interleaved UV at half height.
                let uv_stride = av.stride(1);
                copy_plane_into_av(av.data_mut(1), uv_stride, &self.plane_u, w, rows / 2);
            }
        }

        Ok(av)
    }

    /// P7 — whether this encoder runs HEVC Rext 4:4:4. The pump reads it
    /// after every (re)build for `rc:video-info` truth (the 4:4:4 request
    /// may have fallen back to 4:2:0 at open time).
    pub fn chroma444(&self) -> bool {
        self.chroma444
    }

    fn drain_packets(&mut self) -> Result<Vec<EncodedPacket>> {
        let mut out = Vec::new();
        let mut packet = codec::packet::Packet::empty();
        loop {
            match self.encoder.receive_packet(&mut packet) {
                Ok(()) => {
                    let data = packet.data().unwrap_or(&[]).to_vec();
                    // FR-78 P3 — `av1_vulkan` emits temporal units without the
                    // temporal delimiter OBU every other AV1 encoder starts
                    // with; the viewer's decoders (Chrome's hardware AV1 and
                    // dav1d) cannot consume them. See the helper.
                    let data = if self.encoder_name.starts_with("av1_") {
                        with_av1_temporal_delimiter(data)
                    } else {
                        data
                    };
                    let is_keyframe = packet.is_key();
                    // FR-62 A1 — count every IDR emitted (heartbeat); read
                    // against `keyframe_requests` to isolate rate-caused ones.
                    if is_keyframe {
                        self.idr_count += 1;
                    }
                    // duration is in time_base units (1/1000 == ms); convert to us.
                    let duration_us = ticks_to_us(packet.duration());
                    // P8 Phase 5 — NVENC/QSV report the frame's average
                    // QP via quality-stats side data; absent = None.
                    let qp = packet
                        .side_data()
                        .find(|sd| sd.kind() == codec::packet::side_data::Type::QualityStats)
                        .and_then(|sd| crate::encode::qp_from_quality_stats(sd.data()));
                    out.push(EncodedPacket {
                        data,
                        is_keyframe,
                        duration_us,
                        qp,
                    });
                }
                Err(ffmpeg_next::Error::Other { errno }) if errno == ffmpeg_next::error::EAGAIN => {
                    break;
                }
                Err(ffmpeg_next::Error::Eof) => break,
                Err(e) => return Err(anyhow!("ffmpeg receive_packet failed: {}", e)),
            }
        }
        Ok(out)
    }
}

/// The two bytes of an AV1 temporal delimiter OBU: header `0x12` (type 2,
/// `obu_has_size_field` set) and a zero-length payload.
const AV1_TEMPORAL_DELIMITER: [u8; 2] = [0x12, 0x00];

/// FR-78 P3 (the dev box, RTX 5090, 2026-09-08) — an AV1 packet is one
/// temporal unit, and the AV1 spec starts every temporal unit with a temporal
/// delimiter OBU. `av1_nvenc` (and libaom, QSV, AMF) emit it; FFmpeg 9.0.1's
/// `av1_vulkan` on NVIDIA emits `sequence header · 240 B of padding · frame`
/// with no delimiter at all — and the viewer's decoders refuse the stream:
/// Chrome's hardware AV1 paints garbage, dav1d stalls, FFmpeg's own `obu`
/// demuxer does not even recognise the file. The same bytes with a delimiter
/// inserted before each unit decode cleanly (10/10 frames, dav1d), which is
/// the whole diagnosis. So every AV1 packet leaves the encoder with one:
/// prepended when the first OBU is anything else, untouched when it is
/// already there (the two-byte check reads the OBU header, not a magic
/// string — a delimiter carries no payload, so its size byte is `0x00`).
pub(crate) fn with_av1_temporal_delimiter(data: Vec<u8>) -> Vec<u8> {
    // `obu_type` is bits 6..3 of the header byte; a temporal delimiter is
    // type 2. The extension and size flags may vary, so mask the type only.
    let first_is_delimiter = data.first().is_some_and(|h| (h >> 3) & 0xF == 2);
    if data.is_empty() || first_is_delimiter {
        return data;
    }
    let mut out = Vec::with_capacity(data.len() + AV1_TEMPORAL_DELIMITER.len());
    out.extend_from_slice(&AV1_TEMPORAL_DELIMITER);
    out.extend_from_slice(&data);
    out
}

/// P3 (2026-08-27) — the parameters a BACKGROUND maxrate rebuild needs,
/// captured from the live encoder so the blocking open can run off the
/// pump task (`spawn_blocking`) while the current encoder keeps
/// producing frames.
#[derive(Debug, Clone, Copy)]
pub struct RebuildSpec {
    name: &'static str,
    width: u32,
    height: u32,
    fps: i32,
    maxrate_bps: usize,
    cq: u32,
    chroma444: bool,
    constrained: bool,
}

/// P3 — a background-opened replacement encoder plus the parameters it
/// was opened with, handed back to the pump for adoption between
/// frames. Opaque outside this module so ffmpeg types never leak into
/// peer.rs.
pub struct RebuiltEncoder {
    spec: RebuildSpec,
    inner: codec::encoder::Video,
    hw: Option<hwframes::Frames>,
}

impl RebuiltEncoder {
    pub fn maxrate_bps(&self) -> usize {
        self.spec.maxrate_bps
    }

    /// FR-70 M2 — the dims this replacement was opened at, so the pump can
    /// tell a dims swap from a stale rate swap before adopting.
    pub fn dims(&self) -> (u32, u32) {
        (self.spec.width, self.spec.height)
    }

    /// FR-119 P2b — the frame rate this replacement was opened at: a rate
    /// swap opened before an fps swap was adopted is stale, as one opened for
    /// dims the session has left is.
    pub fn fps(&self) -> u32 {
        self.spec.fps.max(1) as u32
    }
}

impl FfmpegEncoder {
    /// rc.445 — whether `set_bitrate` applies IN PLACE (NVENC) or as a
    /// blocking rebuild (QSV/AMF). The pump defers rebuild-bound applies
    /// to quiet moments — a mid-motion QSV open stalls the stream
    /// 0.65-0.87 s on Iris-Xe-class (field-measured) — or, since P3,
    /// routes them through the background swap (`rebuild_spec` /
    /// `open_rebuilt` / `adopt_rebuilt`).
    pub fn supports_dynamic_bitrate(&self) -> bool {
        // FR-62 A1 — "the pump may apply a rate move immediately" = any
        // in-place mode. A rebuild-bound backend still returns false so the
        // pump defers/swaps it (unchanged). QSV flips true only with the flag.
        !matches!(self.rate_mode, RateReconfig::Rebuild)
    }

    /// FR-62 A2 — does a live rate move on THIS encoder emit a keyframe the pump
    /// must ration? Delegates to [`reconfig_forces_idr_for`] with this session's
    /// resolved mode and the NVENC escape hatch. The pump's `held_increase` arm
    /// keys on this: NVENC (patched) applies a constrained increase LIVE, while
    /// QSV-CBR / rebuild-bound backends keep deferring until their reset cost is
    /// measured away. `MESHHARBORD_ENCODER_NVENC_ASSUME_IDR=1` reverts NVENC.
    pub fn reconfig_forces_idr(&self) -> bool {
        reconfig_forces_idr_for(self.rate_mode, crate::encode::nvenc_assume_reconfig_idr())
    }

    /// FR-62 A1 — rate-apply counters for the heartbeat.
    pub fn rate_stats(&self) -> RateStats {
        RateStats {
            rate_moves: self.rate_moves,
            rebuilds: self.rebuilds,
            swaps: self.swaps,
            idr_count: self.idr_count,
            stage: self.stage,
        }
    }

    /// FR-10 — the maxrate the encoder is CURRENTLY running with, for the
    /// thrifty relay's "is this deferred move big enough to pay an IDR
    /// for" ratio (`encode::relay_deferred_apply_allowed`).
    pub fn current_maxrate_bps(&self) -> u32 {
        self.maxrate_bps.min(u32::MAX as usize) as u32
    }

    /// P3 — capture the parameters a background maxrate rebuild needs.
    /// Mirrors `set_bitrate`'s coarsen + change gate: `None` = the
    /// target coarsens to the CURRENT rung, nothing to do.
    pub(crate) fn rebuild_spec(&self, bps: u32) -> Option<RebuildSpec> {
        let target = crate::encode::aimd::coarsen_bitrate(bps) as usize;
        if crate::encode::aimd::coarsen_bitrate(self.maxrate_bps as u32) as usize == target {
            return None;
        }
        Some(RebuildSpec {
            name: self.encoder_name,
            width: self.width,
            height: self.height,
            fps: self.fps,
            maxrate_bps: target,
            cq: self.cq,
            chroma444: self.chroma444,
            constrained: self.constrained,
        })
    }

    /// FR-70 M2 — the spec for a replacement at NEW dims, and since FR-119 P2b
    /// at a new frame rate, or both: the same backend, cq and chroma, the rate
    /// coarsened as `rebuild_spec` does. Never `None` — either change always
    /// needs a fresh encoder (the frame rate is fixed at open).
    pub(crate) fn rebuild_spec_at(
        &self,
        width: u32,
        height: u32,
        fps: u32,
        bps: u32,
    ) -> RebuildSpec {
        RebuildSpec {
            name: self.encoder_name,
            width,
            height,
            fps: fps.clamp(1, i32::MAX as u32) as i32,
            maxrate_bps: crate::encode::aimd::coarsen_bitrate(bps) as usize,
            cq: self.cq,
            chroma444: self.chroma444,
            constrained: self.constrained,
        }
    }

    /// P3 — BLOCKING open of the replacement encoder; run on
    /// `spawn_blocking`, never on the pump task. Mirrors the sync
    /// `set_bitrate` rebuild arm, including the P4 vp9_qsv
    /// gop/low_power re-resolve (a process-stable OnceLock, so this
    /// reproduces exactly the config the encoder was originally built
    /// with).
    pub(crate) fn open_rebuilt(spec: RebuildSpec) -> Result<RebuiltEncoder> {
        let (qsv_gop, qsv_low_power) = Self::vp9_qsv_runtime_config();
        let (inner, hw) = Self::build_encoder(
            spec.name,
            spec.width,
            spec.height,
            spec.fps,
            spec.maxrate_bps,
            spec.cq,
            qsv_low_power,
            qsv_gop,
            spec.chroma444,
            spec.constrained,
            // The background swap serves the live pump only; a recording
            // encoder is never rebuilt this way.
            None,
        )?;
        Ok(RebuiltEncoder { spec, inner, hw })
    }

    /// P3 — adopt a background-opened encoder between frames. Refuses
    /// (returning `false` and keeping the current encoder) when the
    /// session re-opened at different dims / a different backend /
    /// different chroma while the open was in flight — the replacement
    /// is stale. On adoption the state mirrors the sync rebuild arm:
    /// fresh GOP, first frame a forced IDR (the browser resyncs cleanly
    /// across the swap).
    pub(crate) fn adopt_rebuilt(&mut self, rebuilt: RebuiltEncoder) -> bool {
        let spec = rebuilt.spec;
        // FR-70 M2 — a replacement at other dims is adopted too: that is the
        // dims make-before-break. The pump guards the one case this used to
        // refuse (a rate swap opened for dims the session has since left) by
        // comparing `RebuiltEncoder::dims` with what it expects before
        // calling this. Backend and chroma still must match: the packets'
        // codec cannot change under a live decoder.
        if spec.name != self.encoder_name || spec.chroma444 != self.chroma444 {
            return false;
        }
        self.encoder = rebuilt.inner;
        self.hw = rebuilt.hw;
        self.width = spec.width;
        self.height = spec.height;
        // FR-119 P2b — and the frame rate it was opened at, which every later
        // spec copies (a rate swap, the synchronous rebuild).
        self.fps = spec.fps;
        self.maxrate_bps = spec.maxrate_bps;
        self.frame_count = 0;
        self.force_keyframe = true;
        // FR-65 — count it. This is a real rate move, and before this line the
        // heartbeat reported none: `rate_moves` counts only the in-place write
        // and `rebuilds` only the synchronous path, so a direct QSV session
        // (where every move is a background swap) read zero on both while
        // rebuilding repeatedly.
        self.swaps = self.swaps.saturating_add(1);
        true
    }

    /// P4 — the synchronous encode body (the async trait fn below never
    /// awaits); extracted so the startup vp9_qsv IDR probe can drive the
    /// encoder without an executor.
    pub(crate) fn encode_sync(&mut self, frame: &Frame) -> Result<Vec<EncodedPacket>> {
        if frame.width != self.width || frame.height != self.height {
            return Err(anyhow!(
                "frame size {}x{} doesn't match encoder size {}x{} — re-create the encoder on resolution change",
                frame.width,
                frame.height,
                self.width,
                self.height
            ));
        }

        // FR-118 P0 — each step timed apart (`StageTimes`). A frame that fails
        // part-way is not counted: it is not a frame the stage carried.
        let t0 = std::time::Instant::now();
        self.convert_bgra(frame)?;
        let av = self.build_av_frame(frame.monotonic_us)?;
        let t1 = std::time::Instant::now();
        // FR-77 P4 — a VAAPI encoder takes the pool's hardware frame, not the
        // software one it was built from.
        let av = match &self.hw {
            Some(frames) => frames.upload(&av)?,
            None => av,
        };
        let t2 = std::time::Instant::now();
        self.encoder
            .send_frame(&av)
            .map_err(|e| anyhow!("ffmpeg send_frame failed: {}", e))?;
        let t3 = std::time::Instant::now();

        self.force_keyframe = false;
        self.frame_count += 1;

        let packets = self.drain_packets()?;
        let t4 = std::time::Instant::now();
        let us = |a: std::time::Instant, b: std::time::Instant| (b - a).as_micros() as u64;
        self.stage.frames += 1;
        self.stage.convert_us += us(t0, t1);
        self.stage.upload_us += us(t1, t2);
        self.stage.submit_us += us(t2, t3);
        self.stage.drain_us += us(t3, t4);
        Ok(packets)
    }
}

#[async_trait::async_trait]
impl VideoEncoder for FfmpegEncoder {
    async fn encode(&mut self, frame: Arc<Frame>) -> Result<Vec<EncodedPacket>> {
        self.encode_sync(&frame)
    }

    fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    fn set_bitrate(&mut self, bps: u32) {
        // Phase B — runtime maxrate adaptivity, driven by the DC pump's AIMD.
        // The controller emits a CONTINUOUS desired bitrate; snap it to a
        // coarse ladder first so we don't reconfigure/rebuild on every fine
        // step (each change is heavy — see the two branches below). Only ACT
        // when the coarsened target differs from the coarsened current ceiling.
        let target = crate::encode::aimd::coarsen_bitrate(bps) as usize;
        if crate::encode::aimd::coarsen_bitrate(self.maxrate_bps as u32) as usize == target {
            return;
        }

        // FR-62 A1 — the HRD/VBV reservoir this move should size to. Pre-A1 the
        // NVENC arm wrote `rc_buffer_size = target` (a 1× window, silently
        // resizing the reservoir on every move); with the flag ON both in-place
        // arms size it to the window the session opened with. Flag OFF keeps the
        // 1× write so a flag-OFF session is byte-for-byte the pre-A1 behaviour.
        let bufsize = if self.inplace_rate {
            // Exactly the open sizing (`open_hrd_pct`), which on a constrained
            // session is deliberately < 1× — matching it is the point; a
            // `.max(target)` floor here would re-create the pre-A1 divergence.
            (target.saturating_mul(self.hrd_pct) / 100).max(1)
        } else {
            target
        };

        match self.rate_mode {
            RateReconfig::InPlaceVbr => {
                // NVENC: move the ceiling IN PLACE. FFmpeg's `reconfig_encoder`
                // (libavcodec/nvenc.c) reads `avctx->rc_max_rate` /
                // `rc_buffer_size` on the NEXT `send_frame` and calls
                // `nvEncReconfigureEncoder` when they change. Our NVENC config
                // is `rc=vbr` with `bit_rate=0` (cq-driven), so `bit_rate` stays
                // 0 and we modulate only the ceiling — the right lever for a
                // constant-quality stream. (FR-62 A0 measured this apply at
                // ~0.005 ms; the forced IDR it still triggers is what the A2
                // nvenc patch removes.)
                //
                // SAFETY: `self.encoder` owns the `AVCodecContext` and we hold
                // `&mut self`, so nothing reads/writes it concurrently. Writing
                // these RC fields between `send_frame` calls is exactly the
                // reconfigure contract FFmpeg's nvenc implements.
                unsafe {
                    let ctx = self.encoder.as_mut_ptr();
                    (*ctx).rc_max_rate = target as i64;
                    (*ctx).rc_buffer_size = bufsize as std::os::raw::c_int;
                }
                self.maxrate_bps = target;
                self.rate_moves += 1;
                tracing::debug!(
                    encoder = self.encoder_name,
                    maxrate_bps = target,
                    bufsize,
                    "ffmpeg set_bitrate: NVENC in-place maxrate reconfigure"
                );
            }
            RateReconfig::InPlaceCbr => {
                // FR-62 A1 — QSV in place. Our QSV runs CBR (`select_rc_mode`
                // picks CBR because we open with `rc_max_rate == bit_rate`), so
                // TargetKbps must move WITH MaxKbps: both are written.
                // `qsvenc.c`'s per-frame `update_parameters` → `update_bitrate`
                // re-reads them and calls `MFXVideoENCODE_Reset`, so no blocking
                // encoder rebuild (which is 0.65-0.87 s on Iris-Xe-class and the
                // reason the whole defer/swap machinery exists).
                //
                // ⚠️ **This path does not work on Iris Xe and the flag stays
                // OFF.** A0 measured `MFX_ERR_INCOMPATIBLE_VIDEO_PARAM` (-14) on
                // the FIRST rate change, leaving the encoder unusable. Two
                // explanations have now been tried and BOTH are dead, so do not
                // re-derive either:
                //
                // 1. "We open quality-driven (ICQ), so TargetKbps/MaxKbps aren't
                //    governing and MSDK rejects resetting them." Refuted by our
                //    own open path: `build_encoder` sets `bit_rate =
                //    maxrate_bps` and the option dict sets `maxrate` to the same
                //    value, so `select_rc_mode` takes its CBR branch before it
                //    reaches ICQ and `global_quality` is inert.
                // 2. "The third field is the trigger — `rc_buffer_size` maps to
                //    `BufferSizeInKB`, allocated at Init, and moves on every
                //    change." Refuted by MEASUREMENT on 0.4.62 (CORPLAP-1,
                //    2026-09-04): skipping the write entirely still fails -14,
                //    including the clean case where the encoder opened at 6 Mbps
                //    and the first move was DOWN to 4.5 Mbps while the buffer
                //    stayed at a generously valid 6 Mbps.
                //
                // ⇒ this driver rejects the BITRATE CHANGE ITSELF on Reset, in
                // both `low_power` modes (VME was measured identical). The
                // remaining candidate is `mfxExtEncoderResetOption` (the FR's
                // untested patch 0004), which is an FFmpeg-level change, not
                // something reachable from here. See `docs/fr/FR-62-*` and #1242.
                //
                // SAFETY: as InPlaceVbr — `&mut self` is exclusive.
                unsafe {
                    let ctx = self.encoder.as_mut_ptr();
                    (*ctx).bit_rate = target as i64;
                    (*ctx).rc_max_rate = target as i64;
                    (*ctx).rc_buffer_size = bufsize as std::os::raw::c_int;
                }
                self.maxrate_bps = target;
                self.rate_moves += 1;
                tracing::debug!(
                    encoder = self.encoder_name,
                    maxrate_bps = target,
                    bufsize,
                    "ffmpeg set_bitrate: QSV in-place CBR reconfigure"
                );
            }
            RateReconfig::Rebuild => {
                // QSV / AMF / VideoToolbox with the in-place flag off (or
                // unsupported): the driver reads RC params only at init, so
                // REBUILD with the new maxrate. The coarsen ladder + the AIMD's
                // rate limits bound how often the bucket — and thus this
                // rebuild — changes. P4 — re-resolve the vp9_qsv gop/low_power
                // (process-stable OnceLock, reproduces the original config).
                let (qsv_gop, qsv_low_power) = Self::vp9_qsv_runtime_config();
                match Self::build_encoder(
                    self.encoder_name,
                    self.width,
                    self.height,
                    self.fps,
                    target,
                    self.cq,
                    qsv_low_power,
                    qsv_gop,
                    self.chroma444,
                    self.constrained,
                    self.gop_override,
                ) {
                    Ok((enc, hw)) => {
                        self.encoder = enc;
                        self.hw = hw;
                        self.maxrate_bps = target;
                        self.frame_count = 0;
                        self.force_keyframe = true;
                        self.rebuilds += 1;
                        tracing::info!(
                            encoder = self.encoder_name,
                            maxrate_bps = target,
                            "ffmpeg set_bitrate: QSV/AMF encoder rebuilt for new maxrate"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            encoder = self.encoder_name,
                            maxrate_bps = target,
                            %e,
                            "ffmpeg set_bitrate: rebuild failed — keeping current encoder"
                        );
                    }
                }
            }
        }
    }

    fn set_roi_hints(&mut self, _rects: &[DirtyRect], _frame_dims: (u32, u32)) {
        // NVENC ROI maps + AMF QP maps land in rc.75+ alongside other
        // codec-specific tuning. Default no-op for rc.72.
    }

    fn name(&self) -> &'static str {
        self.encoder_name
    }

    fn is_hardware(&self) -> bool {
        // Every name in the dispatch tables is a HW backend — including
        // `*_videotoolbox`, which by default refuses to fall back to Apple's
        // software encoder (`allow_sw` defaults to 0 and we never set it), so
        // a successful open really does mean the media engine.
        true
    }
}

impl Drop for FfmpegEncoder {
    fn drop(&mut self) {
        // Best-effort flush — send EOF and drain any held packets so the
        // encoder doesn't log warnings about un-drained state.
        //
        // FR-77 P4 — ONLY for an encoder that has taken a frame. `frame_count`
        // is reset on every rebuild, so it counts frames sent to THIS inner
        // encoder. Flushing one that never got a frame has nothing to drain
        // and, on VAAPI, is not survivable: `hevc_vaapi` on jupiter (Mesa
        // 25.2.8 radeonsi, FFmpeg 9.0.1) SEGVs inside `avcodec_send_frame(NULL)`
        // when no picture was ever issued — measured under gdb 2026-09-08, the
        // caps-probe child (open, then drop) died on every start, so the host
        // advertised no hardware at all. In a session the same drop runs in
        // the daemon: a rebuild torn down before its first frame would take
        // the whole agent with it.
        if self.frame_count == 0 {
            return;
        }
        let _ = self.encoder.send_eof();
        let _ = self.drain_packets();
    }
}

/// FR-77 P3b — the pixel format a backend takes for 4:4:4. NVENC (and the
/// software cascade) take planar `yuv444p`; QSV and VAAPI take the PACKED
/// `VUYX` 4:4:4 — FFmpeg n9's `vp9_qsv` / `hevc_qsv` list VUYX and XV30 and
/// never planar 4:4:4, which is exactly why the P1 probe's 4:4:4 open of
/// `vp9_qsv` failed on CORPLAP-3.
fn chroma444_pixel(name: &str) -> format::Pixel {
    if packed444_name(name) {
        format::Pixel::VUYX
    } else {
        format::Pixel::YUV444P
    }
}

/// Backends whose 4:4:4 input is the packed VUYX layout.
fn packed444_name(name: &str) -> bool {
    // QSV takes VUYX straight from the pump; the hardware-frame kinds say
    // for themselves (VAAPI packed, Vulkan planar, D3D12 never 4:4:4).
    match hwframes::HwKind::of(name) {
        Some(kind) => kind.packed444(),
        None => name.contains("qsv"),
    }
}

/// Interleave three full-resolution planes into VUYX — V, U, Y, X per pixel,
/// FFmpeg's `AV_PIX_FMT_VUYX` byte order; X is undefined and written 0xFF.
/// The BT.601 I444 planes dcv produced are the source, so the packed path
/// renders identically to the planar one.
fn pack_vuyx(y: &[u8], u: &[u8], v: &[u8], packed: &mut Vec<u8>) {
    let n = y.len().min(u.len()).min(v.len());
    packed.resize(n * 4, 0xFF);
    for (i, px) in packed.chunks_exact_mut(4).enumerate().take(n) {
        px[0] = v[i];
        px[1] = u[i];
        px[2] = y[i];
        px[3] = 0xFF;
    }
}

fn copy_plane_into_av(
    dst: &mut [u8],
    dst_stride: usize,
    src: &[u8],
    src_width: usize,
    rows: usize,
) {
    for y in 0..rows {
        let dst_off = y * dst_stride;
        let src_off = y * src_width;
        if dst_off + src_width > dst.len() || src_off + src_width > src.len() {
            break;
        }
        dst[dst_off..dst_off + src_width].copy_from_slice(&src[src_off..src_off + src_width]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FR-118 P0 — the encode stage, split ─────────────────────────────

    fn stage(encoder_id: u64, frames: u64, us: [u64; 4]) -> StageTimes {
        StageTimes {
            encoder_id,
            frames,
            convert_us: us[0],
            upload_us: us[1],
            submit_us: us[2],
            drain_us: us[3],
        }
    }

    /// The heartbeat's window is the difference between two readings of the
    /// same encoder, per frame, in milliseconds.
    #[test]
    fn a_window_is_the_per_frame_difference_since_the_last_heartbeat() {
        let base = stage(7, 100, [500_000, 0, 200_000, 50_000]);
        let now = stage(7, 160, [1_100_000, 0, 320_000, 80_000]);
        assert_eq!(now.window_ms_since(&base), Some([10.0, 0.0, 2.0, 0.5]));
    }

    /// A window that encoded nothing reports nothing, never a division by
    /// zero, and never the last window's numbers again.
    #[test]
    fn a_window_without_a_frame_is_none() {
        let base = stage(7, 100, [500_000, 0, 200_000, 50_000]);
        assert_eq!(base.window_ms_since(&base), None);
        assert_eq!(
            StageTimes::default().window_ms_since(&StageTimes::default()),
            None
        );
    }

    /// An inline re-open builds a new encoder whose counters start at zero.
    /// Diffing it against the old one's totals would saturate every part to
    /// zero (or, with more frames, mix two encoders): the window is
    /// everything the new encoder counted.
    #[test]
    fn a_new_encoder_starts_its_own_window() {
        let old = stage(7, 5_000, [50_000_000, 0, 9_000_000, 1_000_000]);
        let new = stage(8, 40, [480_000, 40_000, 80_000, 20_000]);
        assert_eq!(new.window_ms_since(&old), Some([12.0, 1.0, 2.0, 0.5]));
        // Even when the new encoder has already counted MORE frames.
        let busy = stage(8, 6_000, [72_000_000, 0, 12_000_000, 3_000_000]);
        assert_eq!(busy.window_ms_since(&old), Some([12.0, 0.0, 2.0, 0.5]));
    }

    /// Every encoder gets its own id, so the rule above can tell them apart.
    #[test]
    fn each_new_encoder_gets_a_distinct_id() {
        let a = StageTimes::for_new_encoder();
        let b = StageTimes::for_new_encoder();
        assert_ne!(a.encoder_id, b.encoder_id);
        assert_ne!(a.encoder_id, 0, "0 is the default's id, never an encoder's");
    }

    // ── FR-85 P1b — the recording profile ───────────────────────────────

    #[test]
    fn a_recording_encoder_never_repeats_a_timestamp() {
        for fps in [1, 15, 24, 25, 30, 50, 60, 120, 144, 240] {
            let pts: Vec<i64> = (0..10_000u64).map(|n| recording_pts(n, fps)).collect();
            assert!(pts.windows(2).all(|w| w[1] > w[0]), "{fps} fps");
            // One second of frames is one second of time base.
            assert_eq!(
                recording_pts(u64::from(fps as u32), fps),
                i64::from(TIME_BASE_DEN),
                "{fps} fps"
            );
        }
        assert_eq!(
            recording_pts(7, 0),
            7 * i64::from(TIME_BASE_DEN),
            "fps 0 is treated as 1"
        );
    }

    // ── FR-119 P2a — microsecond pts ────────────────────────────────────

    /// Two live frames delivered within the same millisecond (a burst after a
    /// stall, or the latest-wins slot handing over back to back) get distinct
    /// pts. Under the millisecond time base both became `monotonic_us / 1000`,
    /// the same number, and at 144 fps (a 6.9 ms period) such pairs are
    /// ordinary.
    #[test]
    fn two_frames_in_one_millisecond_get_distinct_pts() {
        let first = 10_000_200u64;
        let second = first + 500; // 0.5 ms later
        assert_ne!(live_pts(first), live_pts(second));
        assert!(live_pts(second) > live_pts(first));
        // At 144 fps, every frame of a steady second strictly increases.
        let period_us = 1_000_000 / 144;
        let pts: Vec<i64> = (0..144u64).map(|n| live_pts(n * period_us)).collect();
        assert!(pts.windows(2).all(|w| w[1] > w[0]));
    }

    /// The pts IS the capture time, so a duration in ticks is microseconds.
    #[test]
    fn ticks_are_microseconds() {
        assert_eq!(ticks_to_us(6_944), 6_944);
        assert_eq!(ticks_to_us(16_667), 16_667);
        assert_eq!(ticks_to_us(-5), 0, "a negative duration is none");
        assert_eq!(TIME_BASE_DEN, 1_000_000);
    }

    #[test]
    fn the_recording_ceiling_is_generous_for_cq_nvenc_and_is_the_bitrate_elsewhere() {
        // NVENC: a burst ceiling over constant quality — generous.
        let nv = recording_maxrate_bps("h264_nvenc", 1920, 1080, 30);
        assert_eq!(nv, 18_662_400);
        // Everything that anchors rate control ON maxrate: ~0.12 bpp·s.
        let qsv = recording_maxrate_bps("h264_qsv", 1920, 1080, 30);
        assert_eq!(qsv, 7_464_960);
        assert!(nv > qsv);
        // Floors and caps.
        assert_eq!(recording_maxrate_bps("h264_vaapi", 320, 240, 30), 6_000_000);
        assert_eq!(
            recording_maxrate_bps("hevc_qsv", 7680, 4320, 60),
            40_000_000
        );
        assert_eq!(
            recording_maxrate_bps("hevc_nvenc", 320, 240, 30),
            10_000_000
        );
        // And far above the live ceiling, which clamps at 12 Mbps.
        assert!(qsv < 12_000_000 && nv > 12_000_000);
        assert!(recording_maxrate_bps("h264_qsv", 3840, 2160, 30) > 12_000_000);
    }

    #[test]
    fn the_recording_quality_target_is_sharper_than_the_live_one() {
        // Default only (no env set in this test binary for RECORD_CQ).
        if tunnel_core::env::node_env("RECORD_CQ").is_none() {
            assert_eq!(recording_cq(), 19);
            assert!(recording_cq() < 22, "the live default is 22");
        }
    }

    // FR-62 A1 — the apply path is resolved from the backend name + the flag.
    #[test]
    fn rate_mode_resolves_per_backend_and_flag() {
        // NVENC is always in-place (the pre-A1 behaviour), flag or not.
        assert_eq!(
            resolve_rate_mode("hevc_nvenc", false),
            RateReconfig::InPlaceVbr
        );
        assert_eq!(
            resolve_rate_mode("av1_nvenc", true),
            RateReconfig::InPlaceVbr
        );
        // QSV goes in-place ONLY with the flag; otherwise it rebuilds as before.
        assert_eq!(resolve_rate_mode("hevc_qsv", false), RateReconfig::Rebuild);
        assert_eq!(
            resolve_rate_mode("hevc_qsv", true),
            RateReconfig::InPlaceCbr
        );
        assert_eq!(resolve_rate_mode("vp9_qsv", true), RateReconfig::InPlaceCbr);
        // FR-78 P2 — D3D12 and Vulkan rebuild, MEASURED (the A0 ladder on the
        // dev box: 20/20 rate-caused IDRs); VAAPI by construction.
        for name in ["hevc_d3d12va", "hevc_vulkan", "av1_vulkan", "h264_vaapi"] {
            assert_eq!(
                resolve_rate_mode(name, true),
                RateReconfig::Rebuild,
                "{name}"
            );
            assert_eq!(
                resolve_rate_mode(name, false),
                RateReconfig::Rebuild,
                "{name}"
            );
        }
        // AMF is unmeasured — Rebuild even with the flag; so is VideoToolbox.
        assert_eq!(resolve_rate_mode("hevc_amf", true), RateReconfig::Rebuild);
        assert_eq!(
            resolve_rate_mode("hevc_videotoolbox", true),
            RateReconfig::Rebuild
        );
    }

    // FR-62 A2 — the pump rations a rate move only when the apply still costs an
    // IDR. NVENC (patched FFmpeg) does not; QSV-CBR (unmeasured reset) and every
    // rebuild do; and the escape hatch reverts NVENC to the rationing path.
    #[test]
    fn reconfig_forces_idr_per_backend() {
        // NVENC in-place: the A2 patch removed the forced IDR (measured 0/20).
        assert!(!reconfig_forces_idr_for(RateReconfig::InPlaceVbr, false));
        // …unless the escape hatch says to assume one anyway.
        assert!(reconfig_forces_idr_for(RateReconfig::InPlaceVbr, true));
        // QSV in-place CBR runs MFXVideoENCODE_Reset — conservatively an IDR
        // until A0-QSV clears it; the hatch is NVENC-only, so it can't relax QSV.
        assert!(reconfig_forces_idr_for(RateReconfig::InPlaceCbr, false));
        assert!(reconfig_forces_idr_for(RateReconfig::InPlaceCbr, true));
        // A rebuild always ships a fresh IDR.
        assert!(reconfig_forces_idr_for(RateReconfig::Rebuild, false));
    }

    // FR-62 A1 — the HRD window is the single source for open AND in-place
    // sizing; av1 is floored at 200 % (the rc.443 VDENC hang guard).
    #[test]
    fn open_hrd_pct_floors_av1_at_200() {
        assert!(open_hrd_pct("av1_qsv", false) >= 200);
        assert!(open_hrd_pct("av1_nvenc", true) >= 200);
        // non-av1 uses the direct/constrained knob (a plain positive percent).
        assert!(open_hrd_pct("hevc_qsv", false) > 0);
        assert!(open_hrd_pct("hevc_qsv", true) > 0);
    }

    /// Verify the encoder construction probe handles the all-failed case
    /// without panicking — important because the dispatch happens before
    /// any frames flow, and a panic here would kill the agent's media
    /// pump task with no useful telemetry.
    #[test]
    fn new_hevc_returns_err_when_all_names_unknown() {
        // Use synthetic names that vcpkg ffmpeg definitely doesn't ship.
        let res = FfmpegEncoder::new_with_dispatch(
            &["nope_nvenc_xx", "nope_qsv_xx", "nope_amf_xx"],
            640,
            360,
            30,
            3_000_000,
            0,
            false,
            false,
        );
        assert!(res.is_err(), "expected Err for unknown encoder names");
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("not registered") || msg.contains("encoder names tried"),
            "expected dispatch error, got: {msg}"
        );
    }

    /// P5 — the banded convert's row math: every band starts on an EVEN
    /// row (NV12 chroma pairs must not straddle a cut), heights cover `h`
    /// exactly, and small/degenerate inputs behave.
    #[test]
    fn band_cuts_are_even_and_cover_exactly() {
        for (h, bands) in [
            (1800usize, 4usize),
            (1798, 4),
            (1200, 3),
            (16, 4),
            (1080, 2),
        ] {
            let cuts = FfmpegEncoder::band_cuts(h, bands);
            let mut expect_r0 = 0;
            for &(r0, bh) in &cuts {
                assert_eq!(r0, expect_r0, "bands must be contiguous");
                assert_eq!(r0 % 2, 0, "band start must be even (h={h})");
                assert!(bh > 0);
                expect_r0 += bh;
            }
            assert_eq!(expect_r0, h, "bands must cover h exactly (h={h})");
            assert!(cuts.len() <= bands + 1);
        }
        // Even 2880×1800 in 4 bands: four equal 450-row cuts.
        assert_eq!(
            FfmpegEncoder::band_cuts(1800, 4),
            vec![(0, 450), (450, 450), (900, 450), (1350, 450)]
        );
    }

    /// Verify the dispatch order matches RustDesk's pattern + our docs.
    /// Locks the order so a refactor doesn't accidentally reorder.
    #[test]
    fn av1_dispatch_order_is_nvenc_qsv_amf_videotoolbox_vaapi_d3d12_vulkan() {
        // rc.190 — same vendor order as HEVC (NVIDIA → Intel → AMD), with
        // Apple after them. The videotoolbox entry is expected to FAIL to
        // open on current Macs (no AV1 encode silicon announced); it is
        // present so the caps probe answers the question instead of a code
        // comment. FR-77 P4 / FR-78 P1: the vendor-neutral rungs close the
        // table — VAAPI, then D3D12, then Vulkan.
        assert_eq!(
            AV1_ENCODER_NAMES,
            &[
                "av1_nvenc",
                "av1_qsv",
                "av1_amf",
                "av1_videotoolbox",
                "av1_vaapi",
                "av1_d3d12va",
                "av1_vulkan"
            ]
        );
    }

    /// FR-78 P3 — the temporal-delimiter repair for `av1_vulkan`'s packets:
    /// a unit that starts with a sequence header (the `av1_vulkan` shape) or
    /// a frame gets the delimiter prepended, one that already starts with a
    /// delimiter (the `av1_nvenc` shape — `12 00 0a 0b …`) is untouched, and
    /// the type check reads the OBU header bits, so a delimiter with the
    /// extension flag set still counts.
    #[test]
    fn av1_packets_start_with_a_temporal_delimiter() {
        let vulkan_shape = vec![0x0a, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x7a, 0xf0, 0x01, 0xaa];
        let repaired = with_av1_temporal_delimiter(vulkan_shape.clone());
        assert_eq!(&repaired[..2], &[0x12, 0x00]);
        assert_eq!(&repaired[2..], &vulkan_shape[..]);
        let nvenc_shape = vec![0x12, 0x00, 0x0a, 0x0b, 0x00, 0x00, 0x00, 0xbe];
        assert_eq!(
            with_av1_temporal_delimiter(nvenc_shape.clone()),
            nvenc_shape,
            "a unit that already starts with a delimiter is not doubled"
        );
        let frame_first = vec![0x32, 0x34, 0x10, 0x01];
        assert_eq!(
            &with_av1_temporal_delimiter(frame_first)[..2],
            &[0x12, 0x00]
        );
        let with_extension = vec![0x16, 0x00, 0x00, 0x32, 0x04];
        assert_eq!(
            with_av1_temporal_delimiter(with_extension.clone()),
            with_extension,
            "the type is read from the header bits, not a byte compare"
        );
        assert!(with_av1_temporal_delimiter(Vec::new()).is_empty());
    }

    /// FR-78 P3 — no session constructor may hand a raw cascade table to the
    /// dispatcher: every 4:2:0 list goes through `cells::names_420` and every
    /// 4:4:4 list through `names_444`, which is where the denylist lives.
    /// Read from the source because the constructors open real encoders and
    /// cannot be unit-tested for the list they were handed; on the 0.4.88
    /// tree this finds eight offenders (the jupiter session that ran on a
    /// denied `hevc_vaapi`).
    #[test]
    fn no_constructor_dispatches_a_raw_cascade_table() {
        let src = include_str!("encoder.rs");
        let lines: Vec<&str> = src.lines().collect();
        let offenders: Vec<String> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.trim_end().ends_with("Self::new_with_dispatch("))
            .filter_map(|(i, _)| {
                let next = lines.get(i + 1)?.trim();
                next.ends_with("_ENCODER_NAMES,")
                    .then(|| format!("line {}: {next}", i + 2))
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "raw cascade tables handed to the dispatcher (the denylist is bypassed): {offenders:?}"
        );
    }

    #[test]
    fn hevc_dispatch_order_is_nvenc_qsv_amf_videotoolbox_vaapi_d3d12_vulkan() {
        assert_eq!(
            HEVC_ENCODER_NAMES,
            &[
                "hevc_nvenc",
                "hevc_qsv",
                "hevc_amf",
                "hevc_videotoolbox",
                "hevc_vaapi",
                "hevc_d3d12va",
                "hevc_vulkan"
            ]
        );
    }

    #[test]
    fn h264_dispatch_order_is_nvenc_qsv_amf_videotoolbox_vaapi_d3d12_vulkan() {
        assert_eq!(
            H264_ENCODER_NAMES,
            &[
                "h264_nvenc",
                "h264_qsv",
                "h264_amf",
                "h264_videotoolbox",
                "h264_vaapi",
                "h264_d3d12va",
                "h264_vulkan"
            ]
        );
    }

    /// The vendor encoders are appended-to, never reordered: an existing
    /// fleet must keep resolving to exactly the encoder it resolved to
    /// before, so `*_videotoolbox` and the vendor-neutral rungs may only
    /// ever be appended, in the order they arrived.
    #[test]
    fn videotoolbox_and_the_hw_frame_rungs_are_appended_never_prepended() {
        for names in [HEVC_ENCODER_NAMES, H264_ENCODER_NAMES, AV1_ENCODER_NAMES] {
            let pos = |suffix: &str| {
                names
                    .iter()
                    .position(|n| n.ends_with(suffix))
                    .unwrap_or_else(|| panic!("every table should offer a {suffix} rung"))
            };
            let vt = pos("_videotoolbox");
            assert_eq!(
                vt,
                names.len() - 4,
                "videotoolbox must sit right before the hw-frame rungs in {names:?} — \
                 prepending it would change dispatch for every non-Apple host in the fleet"
            );
            // FR-77 P4 / FR-78 P1 — vaapi, then d3d12va, then vulkan close
            // every table, after the vendor names.
            assert!(pos("_vaapi") < pos("_d3d12va") && pos("_d3d12va") < pos("_vulkan"));
            assert!(
                names.last().is_some_and(|l| l.ends_with("_vulkan")),
                "{names:?}"
            );
        }
    }

    /// Without a `videotoolbox` arm in `encoder_options` the if/else-if
    /// chain falls off the end and the encoder is opened with an EMPTY
    /// option dict — no `maxrate`, no `bufsize`, so the ceiling the rate
    /// governor computed is silently discarded. Lock the bound.
    #[test]
    fn videotoolbox_gets_a_rate_ceiling() {
        let (base, lowlat, summary) =
            encoder_options("hevc_videotoolbox", 3_000_000, 22, false, false, false);
        let has = |v: &[(String, String)], k: &str| v.iter().any(|(a, _)| a == k);
        assert!(has(&base, "maxrate"), "missing maxrate: {summary}");
        assert!(has(&base, "bufsize"), "missing bufsize: {summary}");
        // Latency knobs belong to the tier-protected group so a rejection
        // drops only them and keeps the rate control.
        assert!(
            has(&lowlat, "realtime"),
            "realtime must be tiered: {summary}"
        );
        assert!(!has(&base, "realtime"), "realtime must not be in base");
        // VT is ABR-anchored — a constant-quality knob here would fight the
        // bitrate target rather than replace it.
        for k in ["cq", "qp_i", "qp_p", "global_quality", "rc"] {
            assert!(!has(&base, k), "unexpected {k} for videotoolbox: {summary}");
        }
    }

    /// The vendor branches must not start matching on the Apple name (they
    /// key off substrings, and a careless `contains` could overlap).
    #[test]
    fn videotoolbox_does_not_collide_with_the_vendor_branches() {
        for n in ["hevc_videotoolbox", "h264_videotoolbox", "av1_videotoolbox"] {
            assert!(!n.contains("nvenc"));
            assert!(!n.contains("qsv"));
            assert!(!n.contains("amf"));
        }
    }

    /// P7 — the Rext profile key must appear exactly when 4:4:4 is
    /// requested (and never leak into 4:2:0 sessions, where an unexpected
    /// profile override could change Main-profile behaviour).
    #[test]
    fn hevc_rext_profile_only_with_chroma444() {
        let (_, _, summary) = encoder_options("hevc_nvenc", 3_000_000, 22, true, true, false);
        assert!(
            summary.contains("profile=rext"),
            "chroma444 must set profile=rext, got: {summary}"
        );
        let (_, _, summary) = encoder_options("hevc_nvenc", 3_000_000, 22, true, false, false);
        assert!(
            !summary.contains("profile"),
            "4:2:0 must not set a profile, got: {summary}"
        );
    }

    /// FR-77 — H.264's 4:4:4 profile is `high444p`, never `rext` (HEVC's):
    /// h264_nvenc rejects `profile=rext` at open, so the old code would have
    /// read "this driver cannot do H.264 4:4:4" for a driver that can.
    #[test]
    fn h264_nvenc_444_uses_high444p_not_rext() {
        let (_, _, summary) = encoder_options("h264_nvenc", 3_000_000, 22, true, true, false);
        assert!(
            summary.contains("profile=high444p"),
            "h264 chroma444 must set profile=high444p, got: {summary}"
        );
        assert!(
            !summary.contains("rext"),
            "rext is HEVC-only, got: {summary}"
        );
        let (_, _, summary) = encoder_options("h264_nvenc", 3_000_000, 22, true, false, false);
        assert!(
            !summary.contains("profile"),
            "4:2:0 must not set a profile, got: {summary}"
        );
    }

    /// FR-77 — every name in every cascade table must be one the cell
    /// vocabulary can name, or the probe would open it and then advertise
    /// nothing for it (`from_ffmpeg_name` returns `None`), which reads as
    /// "this host cannot do that codec" on a host that can.
    #[test]
    fn every_cascade_name_is_in_the_cell_vocabulary() {
        use meshharbor_remote_control::models::{VideoBackend, VideoCodec};
        for codec in VideoCodec::ALL {
            for name in FfmpegEncoder::cascade_names(codec) {
                let (c, _) = VideoBackend::from_ffmpeg_name(name)
                    .unwrap_or_else(|| panic!("{name} is not in the cell vocabulary"));
                assert_eq!(c, codec, "{name} sits in the {codec:?} table");
            }
        }
    }

    /// HRD windows per transport (2026-08-26 drag-latency work): DIRECT
    /// defaults to 1× maxrate (`direct_hrd_pct` — the 2× reservoir was
    /// manufacturing the drag-start standing queue), CONSTRAINED keeps
    /// the rc.234 2× default (rc.443: a sub-1× window made av1_qsv error
    /// out on its first settle IDR and hang the driver), and `av1_*` is
    /// floored at 2× on BOTH transports because Intel's AV1 VDENC errors
    /// rather than QP-clamping on an over-reservoir IDR.
    #[test]
    fn hrd_window_defaults_per_transport() {
        let (_, _, summary) = encoder_options("hevc_qsv", 3_000_000, 22, true, false, false);
        assert!(
            summary.contains("bufsize=3000000"),
            "direct defaults to the 1x HRD window, got: {summary}"
        );
        let (_, _, summary) = encoder_options("hevc_qsv", 3_000_000, 22, true, false, true);
        assert!(
            summary.contains("bufsize=6000000"),
            "constrained keeps the 2x window (rc.443 av1_qsv IDR kill), got: {summary}"
        );
        let (_, _, summary) = encoder_options("av1_qsv", 3_000_000, 22, true, false, false);
        assert!(
            summary.contains("bufsize=6000000"),
            "av1 is floored at the 2x window even on direct, got: {summary}"
        );
    }

    // P7 (2026-08-20) — serialise the spatial-AQ env test against any future
    // sibling that touches the same var (the encode/mod.rs RELAY_ENV_LOCK
    // lesson: cargo's parallel runner interleaves env writers).
    static AQ_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// P7 — spatial AQ must be ABSENT from the nvenc option set by default
    /// (it softens desktop text) and restorable via env for camera-heavy
    /// hosts. `encoder_options` is pure (no ffmpeg calls), so this runs on
    /// every build.
    #[test]
    fn nvenc_spatial_aq_default_off_env_restores() {
        let _guard = AQ_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: same reasoning as encode/mod.rs::relay_max_bps_reads_env —
        // nothing else in the crate touches this var at test time, and any
        // future test that does must share AQ_ENV_LOCK.
        let prior = std::env::var("MESHHARBORD_NVENC_SPATIAL_AQ").ok();

        unsafe { tunnel_core::env::test_env::clear("NVENC_SPATIAL_AQ") };
        let (_, _, summary) = encoder_options("hevc_nvenc", 3_000_000, 22, true, false, false);
        assert!(
            !summary.contains("spatial-aq"),
            "spatial-aq must be omitted by default, got: {summary}"
        );
        // The load-bearing keys survive the omission.
        assert!(summary.contains("forced-idr=1"), "got: {summary}");
        assert!(summary.contains("rc=vbr"), "got: {summary}");

        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "NVENC_SPATIAL_AQ", "1") };
        let (_, _, summary) = encoder_options("hevc_nvenc", 3_000_000, 22, true, false, false);
        assert!(
            summary.contains("spatial-aq=1"),
            "env=1 must restore spatial-aq, got: {summary}"
        );

        // Any non-"1" value keeps it off (explicit-opt-in semantics).
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "NVENC_SPATIAL_AQ", "0") };
        let (_, _, summary) = encoder_options("hevc_nvenc", 3_000_000, 22, true, false, false);
        assert!(!summary.contains("spatial-aq"), "got: {summary}");

        match prior {
            Some(v) => unsafe {
                tunnel_core::env::test_env::set_as("MESHHARBORD_", "NVENC_SPATIAL_AQ", v)
            },
            None => unsafe { tunnel_core::env::test_env::clear("NVENC_SPATIAL_AQ") },
        }
    }

    /// FR-77 P3b — the 4:4:4 pixel format follows the backend: NVENC and the
    /// software names take planar yuv444p, QSV and VAAPI the packed VUYX the
    /// FFmpeg n9 sources list for them (never planar 4:4:4).
    #[test]
    fn chroma444_pixel_format_follows_the_backend() {
        assert_eq!(chroma444_pixel("hevc_nvenc"), format::Pixel::YUV444P);
        assert_eq!(chroma444_pixel("h264_nvenc"), format::Pixel::YUV444P);
        assert_eq!(chroma444_pixel("vp9_qsv"), format::Pixel::VUYX);
        assert_eq!(chroma444_pixel("hevc_qsv"), format::Pixel::VUYX);
        assert_eq!(chroma444_pixel("hevc_vaapi"), format::Pixel::VUYX);
        assert!(!packed444_name("hevc_nvenc"));
        assert!(packed444_name("vp9_qsv"));
    }

    /// FR-77 P3b — VUYX byte order (FFmpeg's `AV_PIX_FMT_VUYX`): V, U, Y, X per
    /// pixel, X written 0xFF; the buffer is resized to the plane length and
    /// a stale larger buffer is shrunk.
    #[test]
    fn vuyx_packing_layout_and_sizing() {
        let y = [10u8, 11, 12];
        let u = [20u8, 21, 22];
        let v = [30u8, 31, 32];
        let mut packed = vec![0u8; 64];
        pack_vuyx(&y, &u, &v, &mut packed);
        assert_eq!(packed.len(), 12);
        assert_eq!(&packed[..4], &[30, 20, 10, 0xFF]);
        assert_eq!(&packed[4..8], &[31, 21, 11, 0xFF]);
        assert_eq!(&packed[8..], &[32, 22, 12, 0xFF]);
        // Mismatched plane lengths pack the common prefix only.
        pack_vuyx(&y[..2], &u, &v, &mut packed);
        assert_eq!(packed.len(), 8);
    }

    /// FR-77 P3b — QSV's 4:4:4 profile keys appear exactly when 4:4:4 is
    /// requested, per codec, and never on the nvenc branch (which has its
    /// own `rext` / `high444p` keys).
    #[test]
    fn qsv_444_profiles_per_codec_only_with_chroma444() {
        let (_, _, s) = encoder_options("hevc_qsv", 3_000_000, 22, true, true, false);
        assert!(
            s.contains("profile=rext"),
            "hevc_qsv 4:4:4 must set rext, got: {s}"
        );
        let (_, _, s) = encoder_options("vp9_qsv", 3_000_000, 22, true, true, false);
        assert!(
            s.contains("profile=profile1"),
            "vp9_qsv 4:4:4 must set profile1, got: {s}"
        );
        for name in ["hevc_qsv", "vp9_qsv", "h264_qsv", "av1_qsv"] {
            let (_, _, s) = encoder_options(name, 3_000_000, 22, true, false, false);
            assert!(
                !s.contains("profile"),
                "{name} 4:2:0 must not set a profile, got: {s}"
            );
        }
        let (_, _, s) = encoder_options("h264_qsv", 3_000_000, 22, true, true, false);
        assert!(
            !s.contains("profile"),
            "h264_qsv has no 4:4:4 profile to set, got: {s}"
        );
    }

    /// FR-77 P4 — the VAAPI branch: VBR anchored on the cap with the HRD
    /// window, Rext for HEVC 4:4:4 only, `async_depth` in the protected tier,
    /// and never a `qp`/`quality` on top of the driver's VBR.
    #[test]
    fn vaapi_options_vbr_rext_and_async_depth() {
        let (base, lowlat, s) = encoder_options("hevc_vaapi", 3_000_000, 22, true, true, false);
        assert!(s.contains("rc_mode=VBR"), "{s}");
        assert!(s.contains("maxrate=3000000"), "{s}");
        assert!(s.contains("profile=rext"), "{s}");
        assert!(
            lowlat.iter().any(|(k, v)| k == "async_depth" && v == "1"),
            "{lowlat:?}"
        );
        assert!(
            !base.iter().any(|(k, _)| k == "qp" || k == "quality"),
            "{base:?}"
        );
        let (_, _, s) = encoder_options("vp9_vaapi", 3_000_000, 22, true, true, false);
        assert!(
            !s.contains("profile"),
            "vp9_vaapi has no profile option, got: {s}"
        );
        let (_, _, s) = encoder_options("h264_vaapi", 3_000_000, 22, true, false, false);
        assert!(s.contains("rc_mode=VBR") && !s.contains("profile"), "{s}");
    }

    /// FR-78 P1 — D3D12 and Vulkan take the same rate-control shape as
    /// VAAPI (VBR on the cap, an HRD window, no `qp`), never B-frames (two
    /// frames of reordering delay is FFmpeg's d3d12va default), and the
    /// Vulkan tuning / usage hints ride the tier-protected group.
    #[test]
    fn d3d12_and_vulkan_options_vbr_no_bframes() {
        let (base, lowlat, s) = encoder_options("hevc_d3d12va", 3_000_000, 22, true, false, false);
        assert!(s.contains("rc_mode=VBR"), "{s}");
        assert!(s.contains("maxrate=3000000"), "{s}");
        assert!(base.iter().any(|(k, v)| k == "bf" && v == "0"), "{base:?}");
        assert!(
            lowlat.iter().any(|(k, v)| k == "async_depth" && v == "1"),
            "{lowlat:?}"
        );
        assert!(
            !base.iter().any(|(k, _)| k == "qp" || k == "quality"),
            "{base:?}"
        );

        let (base, lowlat, s) = encoder_options("hevc_vulkan", 3_000_000, 22, true, true, false);
        assert!(s.contains("rc_mode=vbr"), "{s}");
        assert!(s.contains("profile=rext"), "{s}");
        assert!(base.iter().any(|(k, v)| k == "bf" && v == "0"), "{base:?}");
        assert!(
            lowlat.iter().any(|(k, v)| k == "tune" && v == "ull"),
            "{lowlat:?}"
        );
        assert!(
            lowlat.iter().any(|(k, v)| k == "usage" && v == "stream"),
            "{lowlat:?}"
        );
        let (_, _, s) = encoder_options("h264_vulkan", 3_000_000, 22, true, false, false);
        assert!(s.contains("rc_mode=vbr") && !s.contains("profile"), "{s}");
    }

    /// FR-77 P4 / FR-78 P1 — the hardware-frame names sit AFTER the vendor
    /// names in every table (VAAPI, then D3D12, then Vulkan), so a host with
    /// both a vendor SDK and a vendor-neutral path keeps its vendor path
    /// first, and the vocabulary can split each of them.
    #[test]
    fn hw_frame_names_close_every_cascade() {
        use super::super::hwframes::HwKind;
        use meshharbor_remote_control::models::{VideoBackend, VideoCodec};
        for (codec, last, kind) in [
            (VideoCodec::Hevc, "hevc_vulkan", HwKind::Vulkan),
            (VideoCodec::Av1, "av1_vulkan", HwKind::Vulkan),
            (VideoCodec::H264, "h264_vulkan", HwKind::Vulkan),
            (VideoCodec::Vp9, "vp9_vaapi", HwKind::Vaapi),
        ] {
            let names = FfmpegEncoder::cascade_names(codec);
            assert_eq!(names.last().copied(), Some(last), "{codec:?}: {names:?}");
            assert_eq!(HwKind::of(last), Some(kind));
        }
        for (name, backend) in [
            ("hevc_vaapi", VideoBackend::Vaapi),
            ("h264_d3d12va", VideoBackend::D3d12),
            ("av1_vulkan", VideoBackend::Vulkan),
        ] {
            assert_eq!(
                VideoBackend::from_ffmpeg_name(name).map(|(_, b)| b),
                Some(backend),
                "{name}"
            );
            assert_eq!(FfmpegEncoder::static_name(name), Some(name));
        }
        assert!(HwKind::of("hevc_nvenc").is_none() && HwKind::of("vp9_qsv").is_none());
    }
}
