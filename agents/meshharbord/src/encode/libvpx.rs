// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! VP9 profile 1 (8-bit 4:4:4) software encoder via libvpx.
//!
//! This is the encoder side of Phase Y (VP9 4:4:4 over RTCDataChannel),
//! see `docs/encoders.md`. Sits alongside the existing MF + openh264
//! cascade — the agent's caps probe decides which to advertise based on
//! browser support + host CPU budget. Output frames are length-prefixed
//! and shipped over a `video-bytes` DataChannel rather than a WebRTC
//! video track, which is what makes 4:4:4 actually reachable in the
//! browser (Chrome's WebRTC video pipeline forces 4:2:0 across every
//! codec; WebCodecs `VideoDecoder` doesn't).
//!
//! Choices that match RustDesk's production setup:
//!   - VP9 profile 1, 8-bit 4:4:4 (codec string `vp09.01.10.08`)
//!   - `tune=screen-content` for desktop content
//!   - `cpu-used` defaults to 6, env-overridable via
//!     `MESHHARBORD_VP9_CPU_USED` in 4..=9. Was 8 (fastest) pre-rc.33;
//!     6 matches RustDesk's default and doubles the per-macroblock
//!     mode-search budget so motion frames stop falling back to
//!     SKIP/INTRA at the CBR ceiling.
//!   - `lag-in-frames=0` — zero look-ahead, real-time priority
//!   - `kf-max-dist=∞` — periodic IDR disabled (rc.33). The 8 s
//!     periodic IDR competed with motion-frame bit budget; we now
//!     rely on `rc:vp9.request_keyframe` from the viewer + libvpx's
//!     internal scene-change detection (built into the screen-content
//!     tune). Matches RustDesk's pattern.
//!
//! Bound directly against `env_libvpx_sys` (raw FFI). The `vpx-encode`
//! 0.6 wrapper hardcoded `VPX_IMG_FMT_I420` in encode() and exposed no
//! `g_profile` setter, so profile-1 output was unreachable through it
//! — see the libvpx-FFI appendix in `docs/encoders.md`. Talking to libvpx
//! directly costs ~150 LOC of unsafe but lets us configure profile + I444
//! input + zero look-ahead + screen-content tuning, all of which matter
//! for correctness here.
//!
//! BGRA→I444 colour conversion uses `dcv_color_primitives` for AVX2
//! SIMD on x86_64. Without it the conversion is the bottleneck at
//! 1080p+.

#![cfg(feature = "vp9-444")]

use crate::capture::{Frame, PixelFormat};
use crate::encode::{EncodedPacket, VideoEncoder};
use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use std::os::raw::{c_int, c_uint};
use std::sync::Arc;
use tunnel_core::env::node_env;
use vpx_sys as vpx;

/// Initial bitrate target before any back-channel feedback. The
/// resolution-aware ceiling now lives in the VP9-444 pump (peer.rs):
/// it calls `set_bitrate(encode::initial_bitrate_for_fps(w, h, fps) *
/// quality_factor)` after every encoder rebuild so the encoder runs
/// at e.g. 25–30 Mbps at 4K Quality=High instead of the legacy 8 Mbps
/// flat cap. This constant remains as the boot-time default until the
/// first set_bitrate lands (typically the same loop iteration).
const DEFAULT_BITRATE_BPS: u32 = 8_000_000;

/// Keyframe interval in frames. 240 frames ≈ 8 s at 30 fps / 4 s at
/// 60 fps. Restored in rc.36 after the rc.33 `u32::MAX` value turned
/// out to produce visible "uncover-then-stabilise" blur on common
/// screen-content events (window maximize, app launch, Outlook open).
///
/// Why u32::MAX wasn't enough on its own (rc.33→rc.35): libvpx's
/// screen-content tune has internal scene-change detection that *can*
/// force an IDR on uncovered content, but its threshold is conservative
/// and we observed it not firing on common cases (window-restore,
/// notification toast, modal open). The post-event frame budget is
/// then spread across many deltas — each delta progressively adds
/// detail, producing the "blurry at first, sharp after a second" UX.
///
/// Restoring the periodic IDR every 240 frames is the simplest fix:
/// trades ~100 kbps of overhead for a hard quality-refresh floor.
/// Field-confirmed (the field-test host / a second field-test host, 2026-05-17).
///
/// Followup if this still leaves visible blur on rapid scene changes:
/// switch from `VPX_CBR` to `VPX_VBR` so the encoder can burst above
/// target on scene-change frames + dial in `VP9E_SET_CQ_LEVEL` for
/// content-aware QP.
const KEYFRAME_INTERVAL: u32 = 240;

/// Microsecond timebase numerator/denominator. PTS values are passed in
/// directly as microseconds.
const TIMEBASE_NUM: c_int = 1;
const TIMEBASE_DEN: c_int = 1_000_000;

/// VP9 chroma subsampling. Selects the encoder profile + the BGRA→YUV
/// conversion path + the size of the U/V plane buffers.
///
/// rc.61 — added so the operator can pick between sharpest-text
/// `Yuv444` (profile 1, default, ~1.5× bandwidth) and lower-bandwidth
/// `Yuv420` (profile 0, ~30% bandwidth saving, slight ClearType
/// softening on small text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vp9Chroma {
    /// VP9 profile 0 — horizontal+vertical 2:1 chroma subsampling. Same
    /// as WebRTC's default and what RustDesk uses by default.
    Yuv420,
    /// VP9 profile 1 — full 4:4:4 chroma. Currently the default; sharpest
    /// text rendering, needed for unaltered Windows ClearType.
    Yuv444,
}

impl Vp9Chroma {
    /// libvpx `g_profile` value (0 or 1).
    pub fn vpx_profile(self) -> c_uint {
        match self {
            Self::Yuv420 => 0,
            Self::Yuv444 => 1,
        }
    }
    /// String token used in `AgentCaps::vp9_chroma` + the browser side.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yuv420 => "yuv420",
            Self::Yuv444 => "yuv444",
        }
    }
}

pub struct Vp9Encoder {
    /// libvpx encoder context. Owned + freed in Drop.
    ctx: vpx::vpx_codec_ctx_t,
    /// Cached cfg so `set_bitrate` can mutate `rc_target_bitrate` and
    /// hand it back to libvpx via `vpx_codec_enc_config_set`.
    cfg: vpx::vpx_codec_enc_cfg_t,
    width: u32,
    height: u32,
    /// Target framerate this encoder was built for. Used to derive
    /// per-packet `duration_us` (and the synthetic PTS fallback when
    /// the input frame has no monotonic timestamp). Set at
    /// construction; the pump rebuilds the encoder on fps changes.
    target_fps: u32,
    /// Chroma format this encoder was built for. Drives plane sizing,
    /// BGRA→YUV conversion path, and the `img.fmt` / chroma-shift
    /// fields populated for each `vpx_codec_encode` call.
    chroma: Vp9Chroma,
    /// Reusable YUV plane buffers — re-allocated on resolution change.
    /// Y is always W*H; U/V are W*H for 4:4:4 or (W/2)*(H/2) for 4:2:0.
    /// Kept around between frames so steady-state encoding doesn't
    /// pressure the allocator.
    y_plane: Vec<u8>,
    u_plane: Vec<u8>,
    v_plane: Vec<u8>,
    /// Frame counter for keyframe forcing + the encoded-packet timestamp.
    frame_idx: u64,
    /// Keyframe-on-next-encode flag, set by `request_keyframe`.
    force_keyframe: bool,
    /// Most-recent bitrate target (as set by REMB/back-channel).
    target_bitrate: u32,
}

// `vpx_codec_ctx_t` contains raw `*const`/`*mut` pointers into
// C-allocated state (libvpx priv struct, iface vtable, error string).
// libvpx is documented as not internally thread-safe for shared
// access, but a single encoder context owned + driven by a single
// thread is fully supported — the entire RustDesk + WebRTC stack
// uses it that way, and our media_pump task is the sole owner of
// the `Vp9Encoder` instance from `encoder_dims` rebuild to drop.
// Safe to assert Send under that ownership invariant.
//
// Sync is intentionally NOT impl'd — libvpx mutates internal state
// on every encode() call, so concurrent shared-reference access
// would race. The pump's exclusive `&mut self` access prevents
// that automatically.
unsafe impl Send for Vp9Encoder {}

impl Vp9Encoder {
    /// Construct at the default 30 fps target + Yuv444 chroma (current
    /// default). Kept for tests and any caller that doesn't have an
    /// fps / chroma in scope.
    pub fn new(width: u32, height: u32) -> Result<Self> {
        Self::new_with_fps_chroma(width, height, 30, Vp9Chroma::Yuv444)
    }

    /// Construct with an explicit target framerate. Defaults chroma to
    /// `Yuv444` (pre-rc.61 behaviour). Caller in `peer.rs` resolves
    /// chroma from env + handshake and uses [`new_with_fps_chroma`].
    pub fn new_with_fps(width: u32, height: u32, target_fps: u32) -> Result<Self> {
        Self::new_with_fps_chroma(width, height, target_fps, Vp9Chroma::Yuv444)
    }

    /// Construct with an explicit target framerate AND chroma format.
    /// rc.61 — the chroma param is new; it picks libvpx profile 0
    /// (`Yuv420`) or 1 (`Yuv444`) and drives the U/V plane sizing.
    pub fn new_with_fps_chroma(
        width: u32,
        height: u32,
        target_fps: u32,
        chroma: Vp9Chroma,
    ) -> Result<Self> {
        if width == 0 || height == 0 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
            bail!("vp9-444: require non-zero, even dimensions, got {width}x{height}");
        }
        let target_fps = target_fps.clamp(1, 240);

        // SAFETY: libvpx public API. We hold no aliasing references to
        // the cfg / ctx during these calls, the iface pointer is
        // returned by libvpx and lives for the process lifetime, and
        // we check every return code.
        //
        // `vpx_codec_enc_cfg_t` contains `g_bit_depth: vpx_bit_depth_t`
        // which is an enum with no 0 variant (starts at VPX_BITS_8 = 8),
        // so `mem::zeroed()` would produce an invalid niche and panic
        // under the rustc 1.95 invalid-value-in-niche check. Use
        // MaybeUninit and let `vpx_codec_enc_config_default` write the
        // whole struct before we treat any fields as initialised.
        let iface = unsafe { vpx::vpx_codec_vp9_cx() };
        if iface.is_null() {
            bail!("vp9-444: vpx_codec_vp9_cx() returned null — libvpx VP9 codec not linked");
        }
        let mut cfg_uninit = std::mem::MaybeUninit::<vpx::vpx_codec_enc_cfg_t>::uninit();
        let err = unsafe { vpx::vpx_codec_enc_config_default(iface, cfg_uninit.as_mut_ptr(), 0) };
        if err != vpx::VPX_CODEC_OK {
            bail!("vp9-444: vpx_codec_enc_config_default failed: {err:?}");
        }
        // SAFETY: vpx_codec_enc_config_default returned OK, which by
        // libvpx's contract means it fully initialised the cfg struct.
        let mut cfg: vpx::vpx_codec_enc_cfg_t = unsafe { cfg_uninit.assume_init() };

        // VP9 profile selects the chroma format the encoder accepts +
        // emits. Profile 0 = 8-bit 4:2:0, Profile 1 = 8-bit 4:4:4.
        // Browser's `VideoDecoder` MUST be configured with the matching
        // codec string (`vp09.00.10.08` vs `vp09.01.10.08`); a mismatch
        // leaves the canvas blank. rc.61 — picked from the `chroma`
        // parameter (env-var-driven via `peer.rs::vp9_chroma_from_env`).
        cfg.g_profile = chroma.vpx_profile();
        cfg.g_w = width as c_uint;
        cfg.g_h = height as c_uint;
        cfg.g_timebase = vpx::vpx_rational {
            num: TIMEBASE_NUM,
            den: TIMEBASE_DEN,
        };
        cfg.rc_target_bitrate = DEFAULT_BITRATE_BPS / 1000; // libvpx wants kbps
        // rc.42 — rate-control mode env-var opt-in. Default stays CBR
        // (pre-rc.42 behaviour); MESHHARBORD_VP9_RC_MODE=vbr lets the
        // encoder burst on scene changes at the cost of a spikier
        // bitrate envelope. Plan rc.43 flips the default after one
        // cycle of field data. See [[plan]] cycle 1.1.
        let rc_mode = rc_mode_from_env();
        cfg.rc_end_usage = rc_mode;
        cfg.g_pass = vpx::vpx_enc_pass::VPX_RC_ONE_PASS;
        cfg.g_lag_in_frames = 0;
        cfg.g_threads = num_cpus_for_encode();
        cfg.g_error_resilient = 0;
        cfg.g_bit_depth = vpx::vpx_bit_depth::VPX_BITS_8;
        cfg.g_input_bit_depth = 8;
        // rc.234 — periodic IDRs are OFF by default. The rc.171 theory was
        // that a short periodic IDR (~3 s) "re-sharpens" screen-content text;
        // the field showed the exact inverse (2026-07-25, DEVBOX viewing
        // WINHOST-A/REGAL: "text blurs every ~3 s then stabilizes"): under the
        // rate cap each periodic keyframe QP-starves and IS the blur event,
        // while the deltas are what progressively re-sharpen static text.
        // The reliable SCTP DataChannel needs no periodic IDRs — first frame,
        // late join, and resync are all ON-DEMAND (`request_keyframe` is
        // synchronous on libvpx). `MESHHARBORD_VP9_KF_SECONDS=<1..60>`
        // restores a periodic cadence for operators who prefer the old
        // behaviour (rc.38/rc.171 history in git).
        match kf_seconds_from_env() {
            Some(kf_seconds) => {
                cfg.kf_mode = vpx::vpx_kf_mode::VPX_KF_AUTO;
                cfg.kf_min_dist = 0;
                // Knob cap ~60 s (the old 240-frame KEYFRAME_INTERVAL stays
                // as a sanity floor in case target_fps is somehow zero).
                let kf_cap = target_fps.saturating_mul(60).max(KEYFRAME_INTERVAL);
                cfg.kf_max_dist = target_fps.saturating_mul(kf_seconds).clamp(60, kf_cap);
            }
            None => {
                cfg.kf_mode = vpx::vpx_kf_mode::VPX_KF_DISABLED;
                cfg.kf_min_dist = 0;
                cfg.kf_max_dist = 0;
            }
        }
        // Real-time-friendly buffer sizing: 1s buffer at target bitrate
        // with a 0.5s initial / optimal floor. Matches RustDesk's defaults.
        cfg.rc_buf_sz = 1000;
        cfg.rc_buf_initial_sz = 500;
        cfg.rc_buf_optimal_sz = 600;
        cfg.rc_dropframe_thresh = 0;
        // RustDesk-aligned (rc.33): permissive undershoot, tight overshoot,
        // full QP range. Pre-rc.33 the 50/50 + max_q=56 combo forced libvpx
        // to drop *frames* once it hit the buffer ceiling under motion (it
        // couldn't raise QP past 56). Allowing the encoder to ride QP up
        // to 63 trades a momentary text-softness for a continuous frame
        // cadence — RustDesk's failure mode, materially smoother on
        // window-drag motion at 4K than our pre-rc.33 stutter mode.
        cfg.rc_undershoot_pct = 95;
        // rc.42 — VBR mode wants more overshoot headroom so scene-change
        // frames can splurge. CBR keeps the tight 25 % overshoot from
        // rc.33. Both modes share the same permissive 95 % undershoot
        // (idle frames go small no matter what).
        cfg.rc_overshoot_pct = if rc_mode == vpx::vpx_rc_mode::VPX_VBR {
            50
        } else {
            25
        };
        cfg.rc_min_quantizer = 0;
        cfg.rc_max_quantizer = 63;

        let mut ctx: vpx::vpx_codec_ctx_t = unsafe { std::mem::zeroed() };
        let init_err = unsafe {
            vpx::vpx_codec_enc_init_ver(
                &mut ctx,
                iface,
                &cfg,
                0,
                vpx::VPX_ENCODER_ABI_VERSION as c_int,
            )
        };
        if init_err != vpx::VPX_CODEC_OK {
            bail!("vp9-444: vpx_codec_enc_init_ver failed: {init_err:?}");
        }

        // Apply VP9 controls that have no Config-struct equivalent.
        // Failure here is non-fatal but logged — we'd rather encode
        // sub-optimally than refuse to start.
        // Plane allocation. Y is always full-resolution W×H. U/V are
        // full-resolution for 4:4:4, quarter-resolution for 4:2:0
        // (horizontal+vertical 2:1 subsampling). For odd W/H we round
        // UP via integer division on `(W+1)/2 * (H+1)/2` so we don't
        // underrun on a (theoretically possible) odd-dim probe.
        let y_plane_size = (width as usize) * (height as usize);
        let uv_plane_size = match chroma {
            Vp9Chroma::Yuv444 => y_plane_size,
            Vp9Chroma::Yuv420 => {
                let cw = (width as usize).div_ceil(2);
                let ch = (height as usize).div_ceil(2);
                cw * ch
            }
        };
        let mut enc = Self {
            ctx,
            cfg,
            width,
            height,
            target_fps,
            chroma,
            y_plane: vec![0; y_plane_size],
            u_plane: vec![0; uv_plane_size],
            v_plane: vec![0; uv_plane_size],
            frame_idx: 0,
            force_keyframe: true, // first frame is always keyframe
            target_bitrate: DEFAULT_BITRATE_BPS,
        };
        enc.apply_screen_content_controls();
        Ok(enc)
    }

    fn apply_screen_content_controls(&mut self) {
        // CPUUSED default 6 (RustDesk-aligned). Doubles the mode-search
        // budget per macroblock vs the pre-rc.33 default of 8, which
        // restores motion-frame quality at the cost of ~35-45% more
        // encode CPU on the encode thread. Operator escape hatch via
        // `MESHHARBORD_VP9_CPU_USED` (clamped 4..=9) lets a CPU-
        // starved host roll back to 7 or 8 without a rebuild.
        let cpu_used = cpu_used_from_env();
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP8E_SET_CPUUSED as c_int,
            cpu_used,
            "VP8E_SET_CPUUSED",
        );
        // SCREEN tune disables psychovisual prep that's tuned for camera
        // content, preserves sharp text edges. The single biggest lever
        // for desktop content quality at low bitrates.
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP9E_SET_TUNE_CONTENT as c_int,
            vpx::vp9e_tune_content::VP9E_CONTENT_SCREEN as c_int,
            "VP9E_SET_TUNE_CONTENT",
        );
        // AQ off: adaptive quantization tries to spend bits on faces /
        // edges, which on a desktop screenshot mis-fires and softens
        // text. Off matches RustDesk + Chrome's screen-share defaults.
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP9E_SET_AQ_MODE as c_int,
            0 as c_uint,
            "VP9E_SET_AQ_MODE",
        );
        // Resolution-adaptive tile-columns (rc.33). At 4K width, fixing
        // log2=2 (4 tile columns / 960px each) bottlenecked deadline
        // mode encoding on the slowest tile. log2=4 (16 cols / 240px)
        // halves the per-tile width and lets encode + decode threads
        // chew through tiles in parallel. RustDesk uses the same ladder.
        let tile_cols_log2: c_int = if self.width >= 3840 {
            4
        } else if self.width >= 1920 {
            2
        } else {
            1
        };
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP9E_SET_TILE_COLUMNS as c_int,
            tile_cols_log2,
            "VP9E_SET_TILE_COLUMNS",
        );
        // Row-MT (rc.33). Parallelises encode within each tile column;
        // combined with the wider tile-column count at 4K this gives
        // ~2x encode-fps headroom on the realtime deadline. Defaulted
        // off in libvpx pre-1.7, but we ship 1.12 via env-libvpx-sys.
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP9E_SET_ROW_MT as c_int,
            1 as c_uint,
            "VP9E_SET_ROW_MT",
        );
        // Frame-parallel decoding lets the browser decoder use its
        // tile-column-level parallelism path.
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP9E_SET_FRAME_PARALLEL_DECODING as c_int,
            1 as c_uint,
            "VP9E_SET_FRAME_PARALLEL_DECODING",
        );
        // Static threshold helps idle desktop frames skip macroblocks.
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP8E_SET_STATIC_THRESHOLD as c_int,
            100 as c_uint,
            "VP8E_SET_STATIC_THRESHOLD",
        );
        // Noise sensitivity off — desktop content has no noise.
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP9E_SET_NOISE_SENSITIVITY as c_int,
            0 as c_uint,
            "VP9E_SET_NOISE_SENSITIVITY",
        );
    }

    fn set_ctrl<T: Copy>(&mut self, id: c_int, value: T, name: &'static str) {
        // SAFETY: libvpx's variadic control ABI accepts an int-sized
        // argument for every VP9 control we touch (cpuused, tune,
        // aq_mode, tile_columns, frame_parallel, static_threshold,
        // noise_sensitivity). We only ever pass `c_int` or `c_uint`,
        // both of which are int-width on every supported target.
        let err = unsafe { vpx::vpx_codec_control_(&mut self.ctx, id, value) };
        if err != vpx::VPX_CODEC_OK {
            tracing::warn!(
                control = name,
                ?err,
                "vp9-444: ctrl set failed (encode will continue with default)"
            );
        }
    }

    /// Runtime cpu-used override. Used by the pump's motion-driven
    /// dynamic-cpu-used heuristic: bump from base (typically 6, env-
    /// configurable) to a faster preset (typically 8) when a
    /// scene-change spike fires, then drop back after motion subsides.
    /// Saves ~40-60 % per-frame encode time on iGPU-class hardware
    /// (the field-test host's Iris Xe is the field-validated case) where SW VP9
    /// 4:4:4 at 1920×1200 is CPU-bound to 8-12 fps with cpu-used=6.
    /// Quality drop is ~20 % per-frame, mostly invisible during motion
    /// (which is when this fires).
    pub fn set_speed(&mut self, cpu_used: c_int) {
        let clamped = cpu_used.clamp(0, 9);
        self.set_ctrl(
            vpx::vp8e_enc_control_id::VP8E_SET_CPUUSED as c_int,
            clamped,
            "VP8E_SET_CPUUSED (runtime)",
        );
    }

    /// FR-74 P3 — cap the WORST quality libvpx may pick (`rc_max_quantizer`,
    /// 0-63; 63 = q-index 255 = the libvpx default and the relay setting).
    ///
    /// Why a cap and not a mode: libvpx's one-pass CBR treats every mouse-wheel
    /// notch of a text scroll as a scene change — it resets its ambient q to
    /// the worst quality and walks it back down ~7 q-index per frame — so a
    /// choppy scroll is rendered at q 255 throughout while the encoder spends
    /// a fifth of its target (offline rounds 1-4, `fr74_p3_offline_*`; the
    /// same shape as CORPLAP-3's 8-13 Mbps at avg q 170-190 in the field).
    /// The target does not enter into it (a doubled target descends
    /// identically), VBR/CQ pin q at 255 for seconds of "debt", and cyclic
    /// refresh, overshoot and the content tune change nothing. Capping the
    /// worst quality is the one lever that bounds the damage without giving
    /// up the rest: notches sit AT the cap, a steady scroll still refines
    /// toward q 0 inside the budget, idle stays lossless, the target stays a
    /// real average bound (14.5 Mbps of 20.7 on the synthetic scroll at cap
    /// 16 vs 17 uncapped). A runtime config change; no IDR is forced.
    pub fn set_max_quantizer(&mut self, max_q: u32) {
        let max_q: c_uint = max_q.min(63);
        if self.cfg.rc_max_quantizer == max_q {
            return;
        }
        let min_q = self.cfg.rc_min_quantizer.min(max_q);
        self.cfg.rc_min_quantizer = min_q;
        self.cfg.rc_max_quantizer = max_q;
        // SAFETY: ctx is alive; cfg is the one libvpx accepted at init with
        // only the two quantizer bounds changed, which are runtime-settable.
        let err = unsafe { vpx::vpx_codec_enc_config_set(&mut self.ctx, &self.cfg) };
        if err != vpx::VPX_CODEC_OK {
            tracing::warn!(
                ?err,
                max_q,
                "vp9-444: vpx_codec_enc_config_set (max quantizer) failed"
            );
        } else {
            tracing::info!(max_q, min_q, "vp9-444: worst-quality cap applied");
        }
    }

    /// The current `rc_max_quantizer` (0-63).
    pub fn max_quantizer(&self) -> u32 {
        self.cfg.rc_max_quantizer
    }

    /// Uses `dcv_color_primitives` AVX2 path on x86_64 with SSE2
    /// fallback. In-place into `self.{y,u,v}_plane`.
    ///
    /// Convert BGRA → I444 or I420 into our reusable plane buffers,
    /// selected by `self.chroma`. Pre-rc.61 this was `bgra_to_i444`;
    /// the I420 path was added in rc.61 to support VP9 profile 0 for
    /// lower-bandwidth sessions.
    fn bgra_to_yuv(&mut self, frame: &Frame) -> Result<()> {
        if frame.width != self.width || frame.height != self.height {
            bail!(
                "vp9-444: frame dim mismatch — encoder configured {}x{}, got {}x{}",
                self.width,
                self.height,
                frame.width,
                frame.height
            );
        }
        // The SOURCE stride, not `width * 4`: a capture backend may hand us
        // padded rows (macOS IOSurfaces routinely do), and reading them at the
        // packed pitch shears the picture. The sibling backends have always
        // passed `frame.stride` through — `encode/ffmpeg/encoder.rs` and
        // `encode/mf/sync_pipeline.rs` — this one silently substituted
        // `width * 4` and was the second half of the macOS distortion.
        let src_stride = (frame.stride as usize).max((frame.width as usize) * 4);
        // Size the floor off the ACTUAL stride. The old `width * height * 4`
        // check passed on a padded buffer and then read past the last row.
        let expected = src_stride * (frame.height as usize);
        if frame.data.len() < expected {
            bail!(
                "vp9-444: BGRA buffer too small — need {} bytes ({}x{} at stride {}), got {}",
                expected,
                frame.width,
                frame.height,
                src_stride,
                frame.data.len()
            );
        }
        use dcv_color_primitives as dcv;
        let src_format = dcv::ImageFormat {
            pixel_format: dcv::PixelFormat::Bgra,
            color_space: dcv::ColorSpace::Rgb,
            num_planes: 1,
        };
        let (dst_pixfmt, uv_stride) = match self.chroma {
            Vp9Chroma::Yuv444 => (dcv::PixelFormat::I444, self.width as usize),
            Vp9Chroma::Yuv420 => (dcv::PixelFormat::I420, (self.width as usize).div_ceil(2)),
        };
        let dst_format = dcv::ImageFormat {
            pixel_format: dst_pixfmt,
            color_space: dcv::ColorSpace::Bt601,
            num_planes: 3,
        };
        let src_buffers: &[&[u8]] = &[&frame.data];
        let src_strides = &[src_stride];
        let dst_buffers: &mut [&mut [u8]] =
            &mut [&mut self.y_plane, &mut self.u_plane, &mut self.v_plane];
        let dst_strides = &[self.width as usize, uv_stride, uv_stride];
        dcv::convert_image(
            self.width,
            self.height,
            &src_format,
            Some(src_strides),
            src_buffers,
            &dst_format,
            Some(dst_strides),
            dst_buffers,
        )
        .map_err(|e| anyhow!("dcv BGRA→YUV failed: {e:?}"))?;
        Ok(())
    }
}

impl Drop for Vp9Encoder {
    fn drop(&mut self) {
        // SAFETY: ctx was successfully initialised in `new` (the
        // `bail!` paths above return before constructing Self), so
        // destroy is the matching teardown.
        unsafe {
            vpx::vpx_codec_destroy(&mut self.ctx);
        }
    }
}

impl Vp9Encoder {
    /// FR-70 M1b — the whole encode, synchronous: BGRA→YUV, `vpx_codec_encode`,
    /// the packet drain. The `VideoEncoder::encode` below is this behind an
    /// `Arc`; the encoder thread calls it directly.
    pub(crate) fn encode_sync(&mut self, frame: &Frame) -> Result<Vec<EncodedPacket>> {
        if frame.pixel_format != PixelFormat::Bgra {
            bail!("vp9-444: expected BGRA input, got {:?}", frame.pixel_format);
        }
        self.bgra_to_yuv(frame)?;

        // Build a vpx_image_t pointing at our three plane buffers. We
        // don't use vpx_img_wrap because that requires a single
        // contiguous buffer, and we have three separate Vecs that
        // dcv_color_primitives writes into directly. Manual setup
        // avoids the extra concat step.
        //
        // Chroma-dependent fields:
        //   - fmt: I444 vs I420
        //   - x_chroma_shift / y_chroma_shift: 0 for full chroma,
        //     1 for half-resolution chroma (each shift = ÷2)
        //   - bps: 24 (4:4:4 has 1 luma + 2 chroma samples per pixel)
        //          vs 12 (4:2:0 averages chroma over 4 pixels)
        //   - U/V stride: width for 4:4:4, width/2 for 4:2:0
        let mut img: vpx::vpx_image_t = unsafe { std::mem::zeroed() };
        let (img_fmt, x_shift, y_shift, bps, uv_stride) = match self.chroma {
            Vp9Chroma::Yuv444 => (
                vpx::vpx_img_fmt::VPX_IMG_FMT_I444,
                0u32,
                0u32,
                24,
                self.width as c_int,
            ),
            Vp9Chroma::Yuv420 => (
                vpx::vpx_img_fmt::VPX_IMG_FMT_I420,
                1u32,
                1u32,
                12,
                ((self.width as usize).div_ceil(2)) as c_int,
            ),
        };
        img.fmt = img_fmt;
        img.cs = vpx::vpx_color_space::VPX_CS_BT_601;
        img.range = vpx::vpx_color_range::VPX_CR_STUDIO_RANGE;
        img.w = self.width as c_uint;
        img.h = self.height as c_uint;
        img.d_w = self.width as c_uint;
        img.d_h = self.height as c_uint;
        img.r_w = self.width as c_uint;
        img.r_h = self.height as c_uint;
        img.bit_depth = 8;
        img.x_chroma_shift = x_shift;
        img.y_chroma_shift = y_shift;
        img.bps = bps;
        img.planes[vpx::VPX_PLANE_Y as usize] = self.y_plane.as_mut_ptr();
        img.planes[vpx::VPX_PLANE_U as usize] = self.u_plane.as_mut_ptr();
        img.planes[vpx::VPX_PLANE_V as usize] = self.v_plane.as_mut_ptr();
        img.stride[vpx::VPX_PLANE_Y as usize] = self.width as c_int;
        img.stride[vpx::VPX_PLANE_U as usize] = uv_stride;
        img.stride[vpx::VPX_PLANE_V as usize] = uv_stride;

        let pts = frame.monotonic_us as vpx::vpx_codec_pts_t;
        // Advance pts by one frame at the configured target fps when we
        // don't have a real timestamp; libvpx requires monotonic
        // non-zero progression.
        let frame_duration_us: i64 = 1_000_000 / (self.target_fps as i64).max(1);
        let pts = if pts <= 0 {
            (self.frame_idx as i64) * frame_duration_us
        } else {
            pts
        };
        let duration: u64 = frame_duration_us as u64;

        let force_kf = self.force_keyframe || self.frame_idx == 0;
        let flags: vpx::vpx_enc_frame_flags_t = if force_kf {
            vpx::VPX_EFLAG_FORCE_KF as vpx::vpx_enc_frame_flags_t
        } else {
            0
        };

        // SAFETY: ctx is initialised + alive; img points at planes
        // owned by &mut self for the duration of this call (libvpx
        // reads the planes synchronously during vpx_codec_encode and
        // does not retain them after return when g_lag_in_frames=0).
        let err = unsafe {
            vpx::vpx_codec_encode(
                &mut self.ctx,
                &img,
                pts,
                duration as std::os::raw::c_ulong,
                flags,
                vpx::VPX_DL_REALTIME as std::os::raw::c_ulong,
            )
        };
        if err != vpx::VPX_CODEC_OK {
            bail!("vp9-444: vpx_codec_encode failed: {err:?}");
        }

        // P8 Phase 5 (QP telemetry, record-only) — the quantizer libvpx
        // actually used for THIS frame (its native qindex scale, not the
        // H.264-style 0-51). Read once per encode call and stamped on
        // every packet the drain below yields. A control failure is a
        // telemetry gap (None), never an encode error.
        let last_qp: Option<i32> = {
            let mut q: c_int = -1;
            // SAFETY: the GET controls take a *mut int out-param through
            // the same variadic ABI as the SET calls above; ctx is alive.
            let err = unsafe {
                vpx::vpx_codec_control_(
                    &mut self.ctx,
                    vpx::vp8e_enc_control_id::VP8E_GET_LAST_QUANTIZER as c_int,
                    &mut q as *mut c_int,
                )
            };
            (err == vpx::VPX_CODEC_OK && q >= 0).then_some(q)
        };

        let mut out = Vec::new();
        let mut iter: vpx::vpx_codec_iter_t = std::ptr::null();
        loop {
            // SAFETY: get_cx_data is the documented drain pattern; iter
            // is updated by libvpx and the returned packet points at
            // memory owned by the encoder until the next encode call.
            // We copy the payload immediately so the packet's lifetime
            // ends at the bottom of the loop body.
            let pkt = unsafe { vpx::vpx_codec_get_cx_data(&mut self.ctx, &mut iter) };
            if pkt.is_null() {
                break;
            }
            let kind = unsafe { (*pkt).kind };
            if kind != vpx::vpx_codec_cx_pkt_kind::VPX_CODEC_CX_FRAME_PKT {
                continue;
            }
            // SAFETY: the union variant is `frame` for FRAME_PKT.
            let frame_pkt = unsafe { (*pkt).data.frame };
            let buf = frame_pkt.buf as *const u8;
            // `sz` field width varies across env-libvpx-sys's
            // pre-generated bindings (u32 on the 1.12 binding used by
            // the Windows release path; usize on 1.13 + the
            // bindgen-against-system-headers path used on Linux/macOS).
            // Cast through usize unconditionally — the value is a byte
            // count of an encoder packet, no realistic risk of overflow
            // on 64-bit hosts.
            let sz = frame_pkt.sz as usize;
            // SAFETY: libvpx guarantees the buffer is at least `sz`
            // bytes long and stays valid until the next encode() call.
            let slice = unsafe { std::slice::from_raw_parts(buf, sz) };
            let is_keyframe = (frame_pkt.flags & vpx::VPX_FRAME_IS_KEY) != 0;
            out.push(EncodedPacket {
                data: slice.to_vec(),
                is_keyframe,
                duration_us: duration,
                qp: last_qp,
            });
        }

        if force_kf {
            self.force_keyframe = false;
        }
        self.frame_idx += 1;
        Ok(out)
    }
}

/// FR-70 M1b — what the encoder thread needs from libvpx. No background
/// rebuild exists for this backend, so the rebuild types are uninhabited and
/// `adopt_rebuilt` can never be called; the pump's `set_speed` rides
/// [`crate::encode::thread::EncoderHandle::with`].
impl crate::encode::thread::EncoderOps for Vp9Encoder {
    type Rebuilt = std::convert::Infallible;
    type RebuildSpec = std::convert::Infallible;
    type Stats = ();

    // The VP9-444 pump never wrapped its encode in `block_in_place`; the
    // inline path stays a plain call, verbatim.
    const INLINE_BLOCK_IN_PLACE: bool = false;

    fn encode_sync(&mut self, frame: &Frame) -> Result<Vec<EncodedPacket>> {
        Vp9Encoder::encode_sync(self, frame)
    }
    fn set_bitrate(&mut self, bps: u32) {
        VideoEncoder::set_bitrate(self, bps)
    }
    fn request_keyframe(&mut self) {
        VideoEncoder::request_keyframe(self)
    }
    fn adopt_rebuilt(&mut self, rebuilt: std::convert::Infallible) -> bool {
        match rebuilt {}
    }
    fn rebuild_spec(&self, _bps: u32) -> Option<std::convert::Infallible> {
        None
    }
    fn caps(&self) -> crate::encode::thread::EncoderCaps {
        crate::encode::thread::EncoderCaps {
            name: VideoEncoder::name(self),
            supports_dynamic_bitrate: true,
            reconfig_forces_idr: false,
            chroma444: matches!(self.chroma, Vp9Chroma::Yuv444),
        }
    }
    fn current_maxrate_bps(&self) -> u32 {
        self.target_bitrate
    }
    fn rate_stats(&self) {}
}

#[async_trait]
impl VideoEncoder for Vp9Encoder {
    async fn encode(&mut self, frame: Arc<Frame>) -> Result<Vec<EncodedPacket>> {
        self.encode_sync(&frame)
    }

    fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    fn set_bitrate(&mut self, bps: u32) {
        let kbps = bps / 1000;
        if kbps == 0 || kbps == self.cfg.rc_target_bitrate {
            return;
        }
        self.cfg.rc_target_bitrate = kbps;
        self.target_bitrate = bps;
        // SAFETY: ctx is alive; cfg is consistent (we only mutated
        // rc_target_bitrate, leaving every other field at the value
        // libvpx already accepted in init).
        let err = unsafe { vpx::vpx_codec_enc_config_set(&mut self.ctx, &self.cfg) };
        if err != vpx::VPX_CODEC_OK {
            tracing::warn!(?err, kbps, "vp9-444: vpx_codec_enc_config_set failed");
        }
    }

    fn name(&self) -> &'static str {
        "libvpx-vp9-444"
    }

    fn is_hardware(&self) -> bool {
        // Pure SW. Caps probe treats this specially via the
        // `Vp9_444_Sw` ProbeResult variant — see `caps.rs` — so the
        // generic "drop SW heavy codec" rule doesn't fire on this
        // backend. SW VP9 4:4:4 IS the win, not a regression.
        false
    }
}

/// Pick a sensible thread count for the libvpx encoder. Cap raised
/// from 4 → 8 in rc.33: with the resolution-adaptive tile-columns
/// (log2=4 at 4K → 16 tile columns) plus row-mt, encode now scales
/// usefully past 4 threads. The 8-thread ceiling still protects
/// a busy host from drowning under VP9 work — past 8 threads VP9
/// encode parallelism flatlines on the screen-content path.
fn num_cpus_for_encode() -> c_uint {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    logical.clamp(1, 8) as c_uint
}

/// Read the `MESHHARBORD_VP9_CPU_USED` escape hatch. Default 6
/// (RustDesk-aligned, motion-quality optimal). Clamp to 4..=9 — values
/// outside that range are libvpx-internally undefined for VP9. Any
/// unparseable / unset value falls back to the default.
pub(crate) fn cpu_used_from_env() -> c_int {
    const DEFAULT_CPU_USED: i32 = 6;
    let raw = node_env("VP9_CPU_USED")
        .and_then(|v| v.trim().parse::<i32>().ok())
        .unwrap_or(DEFAULT_CPU_USED);
    raw.clamp(4, 9) as c_int
}

/// FR-74 P3 — the worst quality (`rc_max_quantizer`, 0-63) the libvpx pump
/// allows on a DIRECT transport. Default 16 (q-index 64): the sharpest of the
/// caps measured offline (16/20/24 cost the same bytes on a text scroll,
/// 14.0-14.7 Mbps of a 20.7 Mbps target) and the one that holds every
/// wheel-notch frame at a quality a reader can use. Relay/constrained
/// sessions keep libvpx's 63 — there the rate cap is what matters. Env
/// `MESHHARBORD_VP9_DIRECT_MAX_Q` overrides in both directions (63 restores the
/// pre-P3 behaviour); clamp [0, 63].
pub(crate) fn vp9_direct_max_q_from_env() -> u32 {
    const DEFAULT_DIRECT_MAX_Q: u32 = 16;
    node_env("VP9_DIRECT_MAX_Q")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|v| v.min(63))
        .unwrap_or(DEFAULT_DIRECT_MAX_Q)
}

/// The libvpx default and what constrained (relay) sessions run.
pub(crate) const VP9_MAX_Q_UNCAPPED: u32 = 63;

/// Seconds between periodic keyframes (IDRs) on the reliable-DC VP9 path.
///
/// rc.234 — `None` (the default, env unset) disables periodic IDRs
/// entirely: on the reliable DataChannel keys are on-demand only, and the
/// field proved the old ~3 s default was the "text blurs every ~3 s"
/// pulse the operator reported (each periodic key QP-starves under the
/// rate cap; deltas do the re-sharpening). Setting
/// `MESHHARBORD_VP9_KF_SECONDS=<1..60>` restores a periodic cadence.
pub(crate) fn kf_seconds_from_env() -> Option<u32> {
    node_env("VP9_KF_SECONDS")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|s| *s > 0)
        .map(|s| s.clamp(1, 60))
}

/// Read the `MESHHARBORD_VP9_RC_MODE` env var. Default `cbr` (pre-
/// rc.42 behaviour). Accepted: `cbr` | `vbr` | `cq`. Any unrecognised
/// value falls back to `cbr` with a debug-log line.
///
/// rc.42 ships this behind an env var (default cbr); rc.43 flips the
/// default to vbr after one field cycle on the field-test host confirms the
/// envelope is acceptable.
/// Resolve the VP9 chroma format for this session. rc.61.
///
/// Env var `MESHHARBORD_VP9_CHROMA` values:
///   - `""` / `"yuv444"` / `"444"` → [`Vp9Chroma::Yuv444`] (default).
///   - `"yuv420"` / `"420"` → [`Vp9Chroma::Yuv420`].
///
/// Lowercase + whitespace tolerant; anything else logs at debug and
/// falls back to Yuv444 (the pre-rc.61 default — preserves behaviour
/// for hosts that don't know about the new knob).
pub fn vp9_chroma_from_env() -> Vp9Chroma {
    let raw = node_env("VP9_CHROMA").unwrap_or_default();
    let parsed = match raw.trim().to_ascii_lowercase().as_str() {
        "" | "yuv444" | "444" => Vp9Chroma::Yuv444,
        "yuv420" | "420" => Vp9Chroma::Yuv420,
        other => {
            tracing::debug!(
                value = other,
                "vp9-444: unrecognised MESHHARBORD_VP9_CHROMA — falling back to yuv444"
            );
            Vp9Chroma::Yuv444
        }
    };
    tracing::info!(
        chroma = parsed.as_str(),
        env_value = %raw,
        "vp9-444: chroma format selected"
    );
    parsed
}

fn rc_mode_from_env() -> vpx::vpx_rc_mode {
    let raw = node_env("VP9_RC_MODE").unwrap_or_default();
    let parsed = match raw.trim().to_ascii_lowercase().as_str() {
        "" | "cbr" => vpx::vpx_rc_mode::VPX_CBR,
        "vbr" => vpx::vpx_rc_mode::VPX_VBR,
        "cq" => vpx::vpx_rc_mode::VPX_CQ,
        other => {
            tracing::debug!(
                value = other,
                "vp9-444: unrecognised MESHHARBORD_VP9_RC_MODE — falling back to cbr"
            );
            vpx::vpx_rc_mode::VPX_CBR
        }
    };
    tracing::info!(
        mode = ?parsed,
        env_value = %raw,
        "vp9-444: rate-control mode selected"
    );
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_bgra(w: u32, h: u32) -> Frame {
        let mut data = vec![0u8; (w * h * 4) as usize];
        for px in data.chunks_exact_mut(4) {
            px[0] = 64; // B
            px[1] = 192; // G
            px[2] = 128; // R
            px[3] = 255; // A
        }
        Frame {
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: PixelFormat::Bgra,
            data,
            monotonic_us: 0,
            monitor: 0,
            damage: crate::capture::Damage::Unknown,
            source: None,
        }
    }

    /// First-frame keyframe lock. With profile 1 + I444 + lag=0 the
    /// encoder MUST emit at least one packet on the first encode call,
    /// and that packet MUST be flagged `is_keyframe=true`. If this
    /// regresses we'd ship a session that never produces a decodable
    /// frame at the browser.
    #[tokio::test]
    async fn first_frame_is_keyframe() {
        let mut enc = Vp9Encoder::new(320, 240).expect("encoder init");
        let f = Arc::new(synth_bgra(320, 240));
        let packets = enc.encode(f).await.expect("encode ok");
        assert!(!packets.is_empty(), "expected output packets");
        assert!(
            packets.iter().any(|p| p.is_keyframe),
            "first frame must contain a keyframe"
        );
    }

    #[test]
    fn rejects_odd_dims() {
        assert!(Vp9Encoder::new(321, 240).is_err());
        assert!(Vp9Encoder::new(320, 241).is_err());
    }

    /// A padded source must convert to the same picture as a tight one.
    ///
    /// This converter substituted `width * 4` for `frame.stride` until
    /// rc.454, which is half of why macOS rendered a sheared screen (the
    /// other half was the capture backend inventing the stride). Every
    /// synthetic frame in this file happens to be tightly packed, so the
    /// substitution was indistinguishable from correct until a real
    /// IOSurface — which pads — reached it.
    ///
    /// The padding is filled with a value that is NOT the picture colour on
    /// purpose: if the stride is ignored, that filler bleeds into the output
    /// and the planes diverge.
    #[test]
    fn honours_source_stride() {
        let (w, h) = (32u32, 16u32);
        let stride = (w as usize) * 4 + 28; // 28 bytes of row padding
        let mut padded = vec![0xA5u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let off = y * stride + x * 4;
                padded[off] = 64; // B — must match synth_bgra
                padded[off + 1] = 192; // G
                padded[off + 2] = 128; // R
                padded[off + 3] = 255; // A
            }
        }

        let mut padded_frame = synth_bgra(w, h);
        padded_frame.data = padded;
        padded_frame.stride = stride as u32;

        let mut from_padded = Vp9Encoder::new(w, h).expect("encoder init");
        from_padded
            .bgra_to_yuv(&padded_frame)
            .expect("padded convert");

        let mut from_tight = Vp9Encoder::new(w, h).expect("encoder init");
        from_tight
            .bgra_to_yuv(&synth_bgra(w, h))
            .expect("tight convert");

        assert_eq!(from_padded.y_plane, from_tight.y_plane, "Y plane differs");
        assert_eq!(from_padded.u_plane, from_tight.u_plane, "U plane differs");
        assert_eq!(from_padded.v_plane, from_tight.v_plane, "V plane differs");
    }

    /// The size floor must be computed from the ACTUAL stride. The old check
    /// was `width * height * 4`, which a padded buffer one row short still
    /// satisfies — and the converter then reads past the end.
    #[test]
    fn rejects_padded_buffer_that_is_short_a_row() {
        let (w, h) = (32u32, 16u32);
        let stride = (w as usize) * 4 + 28;
        let mut frame = synth_bgra(w, h);
        frame.stride = stride as u32;
        // Big enough for the old `w*h*4` check, too small for the real rows.
        frame.data = vec![0u8; stride * (h as usize - 1)];

        let mut enc = Vp9Encoder::new(w, h).expect("encoder init");
        assert!(enc.bgra_to_yuv(&frame).is_err());
    }

    /// FR-74 P3 — the worst-quality cap round-trips through libvpx's config
    /// at runtime (no rebuild), clamps to the 0-63 scale, and never leaves
    /// `rc_min_quantizer` above it.
    #[test]
    fn max_quantizer_cap_round_trips_and_clamps() {
        let mut enc = Vp9Encoder::new(320, 240).expect("encoder init");
        assert_eq!(enc.max_quantizer(), 63, "libvpx default = uncapped");
        enc.set_max_quantizer(16);
        assert_eq!(enc.max_quantizer(), 16);
        enc.set_max_quantizer(99);
        assert_eq!(enc.max_quantizer(), 63, "clamped to the 0-63 scale");
        enc.set_max_quantizer(0);
        assert_eq!(enc.max_quantizer(), 0);
        assert!(enc.cfg.rc_min_quantizer <= enc.cfg.rc_max_quantizer);
        // A capped encoder still encodes, and its packets report q at or
        // under the cap's q-index (16 -> 64).
        enc.set_max_quantizer(16);
        let f = synth_bgra(320, 240);
        let packets = enc.encode_sync(&f).expect("encode ok");
        assert!(!packets.is_empty());
        for p in &packets {
            if let Some(q) = p.qp {
                assert!(q <= 64, "q-index {q} above the cap");
            }
        }
    }

    /// FR-74 P3 — the direct-path default is 16 and the env override clamps.
    #[test]
    fn direct_max_q_default_and_override() {
        let _guard = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { tunnel_core::env::test_env::clear("VP9_DIRECT_MAX_Q") };
        assert_eq!(vp9_direct_max_q_from_env(), 16);
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "VP9_DIRECT_MAX_Q", "24") };
        assert_eq!(vp9_direct_max_q_from_env(), 24);
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "VP9_DIRECT_MAX_Q", "200") };
        assert_eq!(vp9_direct_max_q_from_env(), 63);
        unsafe { tunnel_core::env::test_env::set_as("MESHHARBORD_", "VP9_DIRECT_MAX_Q", "junk") };
        assert_eq!(vp9_direct_max_q_from_env(), 16);
        unsafe { tunnel_core::env::test_env::clear("VP9_DIRECT_MAX_Q") };
        assert_eq!(VP9_MAX_Q_UNCAPPED, 63);
    }

    /// FR-74 P3 - an OFFLINE measurement of libvpx's rate control on the
    /// pattern the field shows: a long idle (duplicate frames at the 60 ms
    /// keepalive cadence, ~0 bits each), then a text scroll at 30 fps, then a
    /// stop. Per-frame q + bytes per arm, so the mechanism behind "8-13 Mbps
    /// spent of a 20.7 Mbps target at q 170-190" is read from numbers rather
    /// than argued. Ignored: it takes minutes and prints a report.
    /// `FR74_ARMS` picks the arms (comma-separated), default all. An arm name
    /// is a dash-separated list of knobs: `cbr`/`vbr`/`cq` (rc mode), `dups`/
    /// `nodups` (idle frames fed or not), `cpu5`, `x2` (double target),
    /// `tune0` (VP9E_CONTENT_DEFAULT instead of SCREEN), `aq3` (cyclic
    /// refresh), `maxq<N>` (rc_max_quantizer), `os<N>` (rc_overshoot_pct).
    #[test]
    #[ignore]
    fn fr74_p3_offline_scroll_rate_control() {
        use crate::encode::VideoEncoder;
        const W: u32 = 1920;
        const H: u32 = 1200;
        const TARGET_BPS: u32 = 20_736_000;
        const SCROLL_FRAMES: usize = 90;
        const SCROLL_PX: u32 = 24;
        const CHOPPY_NOTCHES: u32 = 12; // wheel notches: 54 px, then 4 repeat frames
        const CHOPPY_PX: u32 = 54;
        const IDLE_FRAMES: usize = 45; // 3 s at the 15/s keepalive cadence
        struct Page {
            w: u32,
            rows: u32,
            px: Vec<u8>, // grey (0 = black ink, 255 = paper), rows x w
        }
        impl Page {
            fn new(w: u32, rows: u32, seed: u64) -> Self {
                let mut s = seed;
                let mut rnd = move || {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    s
                };
                let mut px = vec![255u8; (w * rows) as usize];
                let line_h = 18u32;
                let glyph_h = 12u32;
                let cell_w = 8u32;
                let mut y = 6u32;
                let mut line_no = 1u32;
                while y + glyph_h < rows {
                    // line-number gutter: 6 cells, the digits as dense glyphs.
                    let mut x = 4u32;
                    for d in 0..6u32 {
                        let digit = (line_no / 10u32.pow(5 - d)) % 10;
                        Self::glyph(
                            &mut px,
                            w,
                            x,
                            y,
                            cell_w,
                            glyph_h,
                            0x9E37_79B9 ^ (digit as u64 + 1),
                        );
                        x += cell_w;
                    }
                    x += 2 * cell_w;
                    // words of 2..10 cells separated by a blank cell.
                    while x + cell_w * 10 < w {
                        let len = 2 + (rnd() % 9) as u32;
                        for _ in 0..len {
                            Self::glyph(&mut px, w, x, y, cell_w, glyph_h, rnd());
                            x += cell_w;
                        }
                        x += cell_w;
                    }
                    y += line_h;
                    line_no += 1;
                }
                Self { w, rows, px }
            }
            /// A glyph-like cell: a hash-driven mix of 1-2 px strokes, high
            /// contrast, lots of edges - what a ClearType page looks like to
            /// an encoder.
            fn glyph(px: &mut [u8], w: u32, x0: u32, y0: u32, cw: u32, gh: u32, h: u64) {
                for yy in 0..gh {
                    for xx in 1..cw - 1 {
                        let bit = (h >> ((yy * 5 + xx * 3) % 61)) & 1;
                        let stroke =
                            ((h >> ((xx + yy) % 63)) & 1) == 1 && (yy % 3 != 1 || bit == 1);
                        if stroke {
                            let i = ((y0 + yy) * w + x0 + xx) as usize;
                            px[i] = if bit == 1 { 0 } else { 40 };
                        }
                    }
                }
            }
            fn frame(&self, top: u32, h: u32, t_us: i64) -> Frame {
                let mut data = vec![0u8; (self.w * h * 4) as usize];
                for yy in 0..h {
                    let src = ((top + yy) % self.rows) * self.w;
                    for xx in 0..self.w {
                        let g = self.px[(src + xx) as usize];
                        let i = ((yy * self.w + xx) * 4) as usize;
                        data[i] = g;
                        data[i + 1] = g;
                        data[i + 2] = g;
                        data[i + 3] = 255;
                    }
                }
                Frame {
                    width: self.w,
                    height: h,
                    stride: self.w * 4,
                    pixel_format: PixelFormat::Bgra,
                    data,
                    monotonic_us: t_us as _,
                    monitor: 0,
                    damage: crate::capture::Damage::Unknown,
                    source: None,
                }
            }
        }
        let page = Page::new(
            W,
            H + SCROLL_FRAMES as u32 * SCROLL_PX + CHOPPY_NOTCHES * CHOPPY_PX + 64,
            0xC0FF_EE11,
        );
        let arms: Vec<String> = std::env::var("FR74_ARMS")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.split(',').map(|a| a.trim().to_string()).collect())
            .unwrap_or_else(|| {
                [
                    "cbr-dups",
                    "cbr-nodups",
                    "vbr-dups",
                    "cq-dups",
                    "cbr-dups-cpu5",
                    "cbr-nodups-x2",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect()
            });
        for arm in arms {
            let knobs: Vec<&str> = arm.split('-').collect();
            let has = |k: &str| knobs.contains(&k);
            let num = |prefix: &str| -> Option<u32> {
                knobs
                    .iter()
                    .find_map(|x| x.strip_prefix(prefix).and_then(|n| n.parse::<u32>().ok()))
            };
            let rc = if has("vbr") {
                "vbr"
            } else if has("cq") {
                "cq"
            } else {
                "cbr"
            };
            let cpu = if has("cpu5") { "5" } else { "6" };
            let dups = !has("nodups");
            let target = if has("x2") {
                TARGET_BPS * 2
            } else {
                TARGET_BPS
            };
            unsafe {
                tunnel_core::env::test_env::set_as("MESHHARBORD_", "VP9_RC_MODE", rc);
                tunnel_core::env::test_env::set_as("MESHHARBORD_", "VP9_CPU_USED", cpu);
            }
            let mut enc = Vp9Encoder::new_with_fps(W, H, 30).expect("encoder init");
            VideoEncoder::set_bitrate(&mut enc, target);
            if has("tune0") {
                enc.set_ctrl(
                    vpx::vp8e_enc_control_id::VP9E_SET_TUNE_CONTENT as c_int,
                    vpx::vp9e_tune_content::VP9E_CONTENT_DEFAULT as c_int,
                    "VP9E_SET_TUNE_CONTENT (arm)",
                );
            }
            if has("aq3") {
                enc.set_ctrl(
                    vpx::vp8e_enc_control_id::VP9E_SET_AQ_MODE as c_int,
                    3 as c_uint,
                    "VP9E_SET_AQ_MODE (arm)",
                );
            }
            let mut cfg_changed = false;
            if let Some(q) = num("maxq") {
                enc.cfg.rc_max_quantizer = q as c_uint;
                cfg_changed = true;
            }
            if let Some(os) = num("os") {
                enc.cfg.rc_overshoot_pct = os as c_uint;
                cfg_changed = true;
            }
            // `q<N>`: constant-quality mode (VPX_Q) at CQ level N on the
            // 0-63 scale - no rate control at all, bytes follow content.
            let cq_level = num("q");
            if cq_level.is_some() {
                enc.cfg.rc_end_usage = vpx::vpx_rc_mode::VPX_Q;
                cfg_changed = true;
            }
            if cfg_changed {
                let err = unsafe { vpx::vpx_codec_enc_config_set(&mut enc.ctx, &enc.cfg) };
                assert_eq!(err, vpx::VPX_CODEC_OK, "config_set for arm {arm}");
            }
            if let Some(q) = cq_level {
                enc.set_ctrl(
                    vpx::vp8e_enc_control_id::VP8E_SET_CQ_LEVEL as c_int,
                    q as c_uint,
                    "VP8E_SET_CQ_LEVEL (arm)",
                );
            }
            let mut t_us: i64 = 1_000;
            let mut idx = 0usize;
            let arm_name = arm.clone();
            let run = |enc: &mut Vp9Encoder, phase: &str, frame: &Frame, idx: &mut usize| {
                let pkts = enc.encode_sync(frame).expect("encode");
                let bytes: usize = pkts.iter().map(|p| p.data.len()).sum();
                let q = pkts.iter().filter_map(|p| p.qp).max().unwrap_or(-1);
                let kf = pkts.iter().any(|p| p.is_keyframe);
                println!(
                    "F arm={arm_name} phase={phase} idx={} q={q} bytes={bytes} kf={kf}",
                    *idx
                );
                *idx += 1;
                (q, bytes)
            };
            let mut phases: Vec<(&str, Vec<(i32, usize)>)> = Vec::new();
            // warm: the session opening, 20 real frames of the static page.
            let mut acc = Vec::new();
            for _ in 0..20 {
                let f = page.frame(0, H, t_us);
                acc.push(run(&mut enc, "warm", &f, &mut idx));
                t_us += 33_333;
            }
            phases.push(("warm", acc));
            // idle: the keepalive cadence feeds the SAME frame at 15/s, or
            // (nodups) nothing at all while the clock advances the same 3 s.
            let mut acc = Vec::new();
            if dups {
                for _ in 0..IDLE_FRAMES {
                    let f = page.frame(0, H, t_us);
                    acc.push(run(&mut enc, "idle", &f, &mut idx));
                    t_us += 66_667;
                }
            } else {
                t_us += 66_667 * IDLE_FRAMES as i64;
            }
            phases.push(("idle", acc));
            // scroll: 30 fps, 24 px per frame - every frame is new content.
            let mut acc = Vec::new();
            for i in 0..SCROLL_FRAMES as u32 {
                let f = page.frame((i + 1) * SCROLL_PX, H, t_us);
                acc.push(run(&mut enc, "scroll", &f, &mut idx));
                t_us += 33_333;
            }
            phases.push(("scroll", acc));
            // stop: the scrolled page held still, keepalive cadence (refine).
            let mut acc = Vec::new();
            let mut top = SCROLL_FRAMES as u32 * SCROLL_PX;
            for _ in 0..30 {
                let f = page.frame(top, H, t_us);
                acc.push(run(&mut enc, "stop", &f, &mut idx));
                t_us += 66_667;
            }
            phases.push(("stop", acc));
            // choppy: a mouse-wheel scroll - one 54 px notch, then four frames
            // of the same image (the 60 ms keepalive between notches), 12x.
            let mut acc = Vec::new();
            for _ in 0..CHOPPY_NOTCHES {
                top += CHOPPY_PX;
                let f = page.frame(top, H, t_us);
                acc.push(run(&mut enc, "choppy", &f, &mut idx));
                t_us += 33_333;
                for _ in 0..4 {
                    let f = page.frame(top, H, t_us);
                    acc.push(run(&mut enc, "choppy", &f, &mut idx));
                    t_us += 66_667;
                }
            }
            phases.push(("choppy", acc));
            for (name, rows) in &phases {
                if rows.is_empty() {
                    println!("S arm={arm} phase={name} (not fed)");
                    continue;
                }
                let n = rows.len() as f64;
                let mean_q = rows.iter().map(|r| r.0 as f64).sum::<f64>() / n;
                let max_q = rows.iter().map(|r| r.0).max().unwrap_or(-1);
                let total: usize = rows.iter().map(|r| r.1).sum();
                let secs = match *name {
                    "scroll" | "warm" => n / 30.0,
                    "choppy" => (CHOPPY_NOTCHES as f64) * (0.033_333 + 4.0 * 0.066_667),
                    _ => n / 15.0,
                };
                let first: Vec<i32> = rows.iter().take(10).map(|r| r.0).collect();
                let last: Vec<i32> = rows.iter().rev().take(5).map(|r| r.0).collect();
                // choppy: the q of the NOTCH frames only (every 5th) - the
                // frames a viewer sees the moving text on.
                let notch_q: Vec<i32> = if *name == "choppy" {
                    rows.iter().step_by(5).map(|r| r.0).collect()
                } else {
                    Vec::new()
                };
                println!(
                    "S arm={arm} phase={name} n={} mean_q={mean_q:.0} max_q={max_q} mean_kb={:.0} kbps={:.0} first10_q={first:?} last5_q={last:?} notch_q={notch_q:?}",
                    rows.len(),
                    total as f64 / n / 1000.0,
                    total as f64 * 8.0 / secs / 1000.0
                );
            }
        }
    }
}

#[cfg(test)]
mod fr112_bench {
    //! FR-112 P1 — what one VP9 frame costs at the encode box a 4K host sends
    //! (2048×1080), by bitrate, tile columns, speed and chroma, through the
    //! pump's own `encode_sync` (BGRA → YUV included). The thread asks for its
    //! clock first, as the encoder thread does, so the rows are what the CPU
    //! can do and not what a throttled core does (FR-112 §2). Run by name, in
    //! release, on the host it measures:
    //! `cargo test --release -p meshharbord --lib --features full,vp9-444,vp9-444-bindgen -- --ignored vp9_encode_cost_bench --nocapture --test-threads=1`
    use super::*;
    use std::time::Instant;

    const W: u32 = 2048;
    const H: u32 = 1080;

    fn xorshift(s: &mut u64) -> u8 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        (*s >> 24) as u8
    }

    /// Screen-like BGRA: a static text-like desktop, a window dragged 8 px a
    /// frame, and a 256×256 block that changes wholly (worst-case content).
    fn frames(n: usize) -> Vec<Frame> {
        let (w, h) = (W as usize, H as usize);
        let mut base = vec![0u8; w * h * 4];
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for row in 0..h {
            let text = (row / 18) % 3 != 2 && (row % 18) < 12;
            for col in 0..w {
                let v = if text && (col / 600) % 2 == 0 {
                    if xorshift(&mut s) > 150 { 30 } else { 235 }
                } else {
                    (200 + ((col + row) % 32) as u8).min(250)
                };
                let i = (row * w + col) * 4;
                base[i] = v;
                base[i + 1] = v;
                base[i + 2] = v;
                base[i + 3] = 255;
            }
        }
        (0..n)
            .map(|k| {
                let mut d = base.clone();
                let (wx, wy) = ((k * 8) % (w - 600), 300usize);
                let mut s = 0x1234_5678_9ABC_DEF0u64;
                for r in 0..400 {
                    for c in 0..600 {
                        let v = if r < 24 {
                            70
                        } else if (r / 16) % 2 == 0 && xorshift(&mut s) > 160 {
                            20
                        } else {
                            245
                        };
                        let i = ((wy + r) * w + wx + c) * 4;
                        d[i] = v;
                        d[i + 1] = v.saturating_add(10);
                        d[i + 2] = v;
                    }
                }
                let mut t = (k as u64 + 1).wrapping_mul(0x2545_F491_4F6C_DD1D);
                for r in 0..256 {
                    for c in 0..256 {
                        let i = ((700 + r) * w + 1600 + c) * 4;
                        d[i] = xorshift(&mut t);
                        d[i + 1] = xorshift(&mut t);
                        d[i + 2] = xorshift(&mut t);
                    }
                }
                Frame {
                    width: W,
                    height: H,
                    stride: W * 4,
                    pixel_format: PixelFormat::Bgra,
                    data: d,
                    monotonic_us: (k as u64) * 16_667,
                    monitor: 0,
                    damage: crate::capture::Damage::Unknown,
                    source: None,
                }
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn one(
        label: &str,
        fps: u32,
        chroma: Vp9Chroma,
        bps: u32,
        cpu: c_int,
        tiles_log2: Option<c_int>,
        max_q: u32,
        fr: &[Frame],
    ) {
        let mut enc = Vp9Encoder::new_with_fps_chroma(W, H, fps, chroma).expect("encoder");
        enc.set_max_quantizer(max_q);
        enc.set_speed(cpu);
        if let Some(t) = tiles_log2 {
            enc.set_ctrl(
                vpx::vp8e_enc_control_id::VP9E_SET_TILE_COLUMNS as c_int,
                t,
                "VP9E_SET_TILE_COLUMNS",
            );
        }
        VideoEncoder::set_bitrate(&mut enc, bps);
        for f in fr.iter().take(30) {
            enc.encode_sync(f).expect("warmup");
        }
        let (mut ms, mut bytes, mut qps) = (Vec::new(), 0usize, Vec::new());
        for f in fr.iter().skip(30) {
            let t = Instant::now();
            let p = enc.encode_sync(f).expect("encode");
            ms.push(t.elapsed().as_secs_f64() * 1000.0);
            bytes += p.iter().map(|x| x.data.len()).sum::<usize>();
            qps.extend(p.iter().filter_map(|x| x.qp));
        }
        ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = ms.len();
        let mean = ms.iter().sum::<f64>() / n as f64;
        let qp = if qps.is_empty() {
            -1.0
        } else {
            qps.iter().sum::<i32>() as f64 / qps.len() as f64
        };
        println!(
            "{label:<34} mean {mean:6.2} ms  p50 {:6.2}  p95 {:6.2}  max fps {:5.1}  {:7.0} B/frame  avg q {:4.1}",
            ms[n / 2],
            ms[n * 95 / 100],
            1000.0 / mean,
            bytes as f64 / n as f64,
            qp
        );
    }

    #[test]
    #[ignore = "a benchmark: run by name, in release, on the host it measures"]
    fn vp9_encode_cost_bench() {
        let clock = crate::encode::clock::ask_for_this_thread("bench");
        let fr = frames(150);
        println!(
            "{W}x{H}, 120 frames measured per row, {} logical CPUs, encoder threads {}, clock {clock:?}",
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            num_cpus_for_encode()
        );
        let q = vp9_direct_max_q_from_env();
        let (y444, y420) = (Vp9Chroma::Yuv444, Vp9Chroma::Yuv420);
        one(
            "444 30fps 17.5M cpu6 tiles4 (today)",
            30,
            y444,
            17_500_000,
            6,
            None,
            q,
            &fr,
        );
        one(
            "444 60fps 25M cpu6 tiles4",
            60,
            y444,
            25_000_000,
            6,
            None,
            q,
            &fr,
        );
        one(
            "444 60fps 25M cpu6 tiles8",
            60,
            y444,
            25_000_000,
            6,
            Some(3),
            q,
            &fr,
        );
        one(
            "444 60fps 25M cpu8 tiles8",
            60,
            y444,
            25_000_000,
            8,
            Some(3),
            q,
            &fr,
        );
        one(
            "420 60fps 25M cpu6 tiles4",
            60,
            y420,
            25_000_000,
            6,
            None,
            q,
            &fr,
        );
    }
}
