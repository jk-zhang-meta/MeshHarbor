// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! HW-downscale Phase A — the CPU resampler, extracted from peer.rs and
//! de-wasted.
//!
//! Field data (2026-08-21, corplap-3 h264_qsv + WINHOST-A hevc_qsv): the
//! Smoother rung's native→1024×640 downscale measured **26-45 ms/frame**
//! against a 3-8 ms hardware encode — and since P8a-2 the rung engages
//! only DURING motion, so the bill lands at the worst moment. The
//! algorithm's own cost model predicts 9-17 ms for that rung; the rest
//! was implementation waste, each piece individually removable:
//!
//! - the Lanczos tap tables were rebuilt EVERY frame (~1,664 inner Vec
//!   allocations + ~36k `sinf` calls for a pure function of the dims);
//! - the 9.8-13 MB i16 intermediate was freshly allocated AND zeroed per
//!   frame (every element is overwritten before it is read);
//! - the alpha lane was resampled through both passes and then discarded
//!   by every consumer (dcv BGRA→NV12/I444 ignores A) — 25 % dead MACs.
//!
//! [`Resampler`] owns the cached taps (flattened: one weights vec + a
//! `(start, len)` index — no per-column Vecs) and the pooled intermediate;
//! one instance per pump, like `RateGovernor`. The destination buffer is
//! deliberately NOT pooled — it moves into an `Arc<Frame>` that
//! `last_good_frame`/the encoder/the send path may hold arbitrarily long.
//!
//! `MESHHARBORD_SCALE_THREADS` (config key `scale_threads`, default
//! `min(available_parallelism, 4)` since FR-65 — it was 1) row-bands both
//! passes across N scoped threads — both are embarrassingly parallel, and on
//! HW-encode hosts the cores are idle during motion. It shipped as "a lever
//! for the field, not a policy", and the field then measured what leaving it
//! off costs: `avg_scale_ms = 23.6` on a constrained CORPLAP-1 session, and
//! 18.15 → 5.91 ms/frame going 1 → 4 threads in the bench. It is now policy.
//!
//! Phase B (GPU scale before readback, D3D11 VideoProcessor) makes this
//! whole module the FALLBACK on Windows GPU-capture backends; this stays
//! the primary path for GDI/scrap-class capture and non-Windows.

use std::sync::Arc;

use tunnel_core::env::node_env;

use crate::capture::{Frame, PixelFormat};
use crate::peer::TargetResolution;

/// Q12 fixed-point scale for the tap weights (each row sums to 4096).
const Q12_ONE: i32 = 4096;

/// rc.191 — kill switch for the Lanczos-3 downscale path.
/// `MESHHARBORD_LANCZOS=0` (or `false`) reverts every downscale to the
/// box filter without a rebuild.
fn lanczos_enabled() -> bool {
    !matches!(
        tunnel_core::env::node_env("LANCZOS").as_deref(),
        Some("0") | Some("false")
    )
}

/// P7 (2026-08-20) — minimum linear scale (as percent) at which the
/// Lanczos-3 downscale engages; shallower shrinks below it fall back to the
/// box filter. Default 34 covers the Smoother rungs (1920→1024 = 53%,
/// 2560→1024 = 40%) while leaving 4K sources on box (3840→1024 = 27%,
/// 3840→1280 = 33%, deliberately just under) — at ≤1/3 scale text is
/// sub-readable regardless of filter, and the horizontal pass over an
/// 8.3 MP source (~26–50 ms) would eat the 30 fps capture budget. `0` runs
/// Lanczos for every downscale; `56` restores the pre-P7 `> 0.55` gate.
fn lanczos_min_scale() -> f32 {
    // node_env (not raw std::env) so the `lanczos_min_pct` config-surface
    // key reaches this read through the fallback map.
    let pct = node_env("LANCZOS_MIN_PCT")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(34);
    (pct.min(100) as f32) / 100.0
}

/// P7 — the filter decision, extracted for tests. Inclusive floor so a
/// percent knob maps exactly (scale 0.34 passes a 34 floor).
fn use_lanczos_for_scale(scale: f32, min_scale: f32, enabled: bool) -> bool {
    enabled && scale >= min_scale
}

/// Phase A — worker count for the row-banded passes. Read once per
/// [`Resampler`] (per pump instance), clamped 1..=8; 1 = inline, no
/// threads spawned. Env `MESHHARBORD_SCALE_THREADS` / config key
/// `scale_threads`.
///
/// **FR-65: the default is now `min(available_parallelism, 4)`, was 1.** The
/// row-banding was implemented, correctness-tested
/// (`threaded_bands_match_single_thread`) — and switched off, so every
/// downscale ran single-threaded. Measured by `lanczos_cost_by_thread_count`
/// (release, 1920×1200 → 1280×800): **18.15 ms at 1 thread, 5.91 at 4
/// (3.07×), 4.00 at 8 (4.54×)** — near-linear to 4, then diminishing. The
/// field number it explains: CORPLAP-1 reported `avg_scale_ms = 23.6` on a
/// slower laptop CPU, and `0.0` at native resolution.
///
/// 🔑 Why this matters more than the raw milliseconds: the downscale engages
/// **only once the session has already downscaled** — i.e. only when the host
/// is already constrained — so the old default spent ~24 ms/frame of CPU
/// precisely where there was none to spare, capping the frame rate on the
/// sessions least able to afford it.
///
/// ⚠️ Capped at 4 rather than 8 on purpose: the gain from 4→8 is 1.5× while
/// the cost is doubling the cores taken from the encoder and the rest of the
/// daemon on a laptop. ⚠️ `available_parallelism` is honoured so a 2-core box
/// does not oversubscribe itself.
fn scale_threads() -> usize {
    node_env("SCALE_THREADS")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or_else(default_scale_threads)
        .clamp(1, 8)
}

fn default_scale_threads() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .min(4)
}

/// rc.191 — per-output-pixel Lanczos-3 tap table for one axis, in Q12
/// fixed point. For downscaling the kernel is stretched by `src/dst`
/// (support = 3·src/dst source pixels per output pixel); weights are
/// normalised to sum exactly 4096 so flat fields round-trip losslessly.
///
/// This is the REFERENCE builder — pure in (src, dst). The hot path
/// consumes the flattened form cached inside [`Resampler`]; tests assert
/// the flattening is lossless.
fn lanczos3_taps(src: u32, dst: u32) -> Vec<(i32, Vec<i32>)> {
    const A: f32 = 3.0;
    let ratio = src as f32 / dst as f32; // > 1 for downscale
    let support = A * ratio.max(1.0);
    let mut out = Vec::with_capacity(dst as usize);
    for i in 0..dst {
        let center = (i as f32 + 0.5) * ratio - 0.5;
        let lo = (center - support).ceil() as i32;
        let hi = (center + support).floor() as i32;
        let lo_c = lo.max(0);
        let hi_c = hi.min(src as i32 - 1);
        let mut weights = Vec::with_capacity((hi_c - lo_c + 1) as usize);
        let mut sum = 0.0f32;
        let scale_inv = 1.0 / ratio.max(1.0);
        for t in lo_c..=hi_c {
            let x = (t as f32 - center) * scale_inv;
            let w = if x.abs() < 1e-6 {
                1.0
            } else if x.abs() >= A {
                0.0
            } else {
                let pix = std::f32::consts::PI * x;
                (A * pix.sin() * (pix / A).sin()) / (pix * pix)
            };
            weights.push(w);
            sum += w;
        }
        // Normalise → Q12 fixed point; distribute rounding residue onto the
        // largest tap so the row sums to exactly 4096.
        let mut fixed: Vec<i32> = weights
            .iter()
            .map(|w| ((w / sum) * (Q12_ONE as f32)).round() as i32)
            .collect();
        let total: i32 = fixed.iter().sum();
        if let Some(max_idx) = fixed
            .iter()
            .enumerate()
            .max_by_key(|(_, v)| **v)
            .map(|(i, _)| i)
        {
            fixed[max_idx] += Q12_ONE - total;
        }
        out.push((lo_c, fixed));
    }
    out
}

/// One axis of cached, flattened taps: `index[i] = (lo, len)` into
/// `weights`. Rebuilt only when the `(src, dst)` key changes (a refine
/// rung flip — every few seconds at most, ~1 ms to rebuild), replacing
/// the per-frame table build the old free function paid.
#[derive(Default)]
struct AxisTaps {
    key: (u32, u32),
    index: Vec<(u32, u32)>,
    weights: Vec<i32>,
}

impl AxisTaps {
    /// `index[i] = (lo, len)`; weights flattened in row order (offsets are
    /// cumulative, recovered while iterating).
    fn ensure(&mut self, src: u32, dst: u32) {
        if self.key == (src, dst) && !self.index.is_empty() {
            return;
        }
        self.index.clear();
        self.weights.clear();
        for (lo, ws) in lanczos3_taps(src, dst) {
            self.index.push((lo as u32, ws.len() as u32));
            self.weights.extend_from_slice(&ws);
        }
        self.key = (src, dst);
    }
}

/// Pump-local resampler state: cached taps for both axes + the pooled
/// i16 intermediate. See the module docs for what each cache removes.
#[derive(Default)]
pub(crate) struct Resampler {
    h: AxisTaps,
    v: AxisTaps,
    /// Pooled horizontal-pass output (Q6 i16, stride-4 lanes, alpha lane
    /// never written or read). High-water sized; `resize` only ever grows
    /// it, and no per-frame zeroing happens — every element the vertical
    /// pass reads was written by the horizontal pass this frame.
    mid: Vec<i16>,
    /// Worker count, read once at construction (env/config).
    threads: usize,
}

impl Resampler {
    pub(crate) fn new() -> Self {
        Self {
            threads: scale_threads(),
            ..Self::default()
        }
    }

    /// Separable Lanczos-3 downscale for BGRA frames. P7: the kernel is a
    /// true scaled Lanczos (support = 3·ratio) so it anti-aliases correctly
    /// at ANY shrink — box is never *more* correct, only cheaper; box
    /// survives below the `lanczos_min_scale` floor purely as a CPU guard
    /// for huge (4K+) sources. Cost model: the horizontal pass is
    /// ≈18·src_area MACs independent of ratio (3 live lanes since Phase A),
    /// the vertical pass shrinks with scale, total ≈ 18·src_area·(1+scale).
    /// Q12 integer accumulation (i32), horizontal pass into the pooled i16
    /// intermediate (Q12 >> 6 = Q6; max |value| ≈ 255·4096·1.15/64 ≈ 18.8k —
    /// fits i16 with the ~15 % negative-lobe overshoot headroom), vertical
    /// pass back to u8 with clamping (the kernel has negative lobes).
    /// Output alpha is constant 0xFF — every consumer (dcv BGRA→NV12/I444)
    /// ignores it, so resampling it was pure waste.
    fn lanczos3(
        &mut self,
        src: &[u8],
        src_w: u32,
        src_h: u32,
        src_stride: u32,
        dst_w: u32,
        dst_h: u32,
    ) -> Vec<u8> {
        self.h.ensure(src_w, dst_w);
        self.v.ensure(src_h, dst_h);
        let mid_stride = (dst_w as usize) * 4;
        let mid_len = mid_stride * (src_h as usize);
        if self.mid.len() < mid_len {
            // Grows only; the (cheap, one-off) zeroing of the growth is
            // irrelevant — both passes fully overwrite/read within bounds.
            self.mid.resize(mid_len, 0);
        }

        let h_index = &self.h.index;
        let h_weights = &self.h.weights;
        let v_index = &self.v.index;
        let v_weights = &self.v.weights;
        let threads = self.threads.min(src_h.max(1) as usize);

        // ── Horizontal pass: src_h rows × dst_w columns ─────────────────
        let mid = &mut self.mid[..mid_len];
        let h_band = |rows: &mut [i16], y0: usize| {
            for (band_y, mid_row) in rows.chunks_exact_mut(mid_stride).enumerate() {
                let y = y0 + band_y;
                let row = &src[y * src_stride as usize..][..(src_w as usize) * 4];
                let mut woff = 0usize;
                for (x, (lo, len)) in h_index.iter().enumerate() {
                    let px = &row[(*lo as usize) * 4..][..(*len as usize) * 4];
                    let ws = &h_weights[woff..woff + *len as usize];
                    woff += *len as usize;
                    let mut acc = [0i32; 3];
                    for (chunk, w) in px.chunks_exact(4).zip(ws) {
                        acc[0] += w * chunk[0] as i32;
                        acc[1] += w * chunk[1] as i32;
                        acc[2] += w * chunk[2] as i32;
                    }
                    let di = x * 4;
                    mid_row[di] = (acc[0] >> 6) as i16;
                    mid_row[di + 1] = (acc[1] >> 6) as i16;
                    mid_row[di + 2] = (acc[2] >> 6) as i16;
                    // Lane 3 (alpha) deliberately untouched — never read.
                }
            }
        };
        if threads <= 1 {
            h_band(mid, 0);
        } else {
            let rows_per = (src_h as usize).div_ceil(threads);
            let h_band = &h_band;
            std::thread::scope(|s| {
                for (b, band) in mid.chunks_mut(rows_per * mid_stride).enumerate() {
                    s.spawn(move || h_band(band, b * rows_per));
                }
            });
        }

        // ── Vertical pass: Q6 · Q12 = Q18 → >> 18 back to u8, clamped ───
        let mid = &self.mid[..mid_len];
        let mut dst = vec![0u8; (dst_w as usize) * (dst_h as usize) * 4];
        // Weight offsets per output row (variable tap counts near edges).
        let mut v_offsets = Vec::with_capacity(v_index.len());
        {
            let mut off = 0usize;
            for (_, len) in v_index {
                v_offsets.push(off);
                off += *len as usize;
            }
        }
        let v_band = |rows: &mut [u8], y0: usize| {
            for (band_y, dst_row) in rows.chunks_exact_mut(mid_stride).enumerate() {
                let y = y0 + band_y;
                let (lo, len) = v_index[y];
                let ws = &v_weights[v_offsets[y]..v_offsets[y] + len as usize];
                for x in 0..dst_w as usize {
                    let mut acc = [0i32; 3];
                    for (k, w) in ws.iter().enumerate() {
                        let si = (lo as usize + k) * mid_stride + x * 4;
                        acc[0] += w * mid[si] as i32;
                        acc[1] += w * mid[si + 1] as i32;
                        acc[2] += w * mid[si + 2] as i32;
                    }
                    let di = x * 4;
                    dst_row[di] = ((acc[0] + (1 << 17)) >> 18).clamp(0, 255) as u8;
                    dst_row[di + 1] = ((acc[1] + (1 << 17)) >> 18).clamp(0, 255) as u8;
                    dst_row[di + 2] = ((acc[2] + (1 << 17)) >> 18).clamp(0, 255) as u8;
                    dst_row[di + 3] = 0xFF;
                }
            }
        };
        let threads_v = self.threads.min(dst_h.max(1) as usize);
        if threads_v <= 1 {
            v_band(&mut dst, 0);
        } else {
            let rows_per = (dst_h as usize).div_ceil(threads_v);
            let v_band = &v_band;
            std::thread::scope(|s| {
                for (b, band) in dst.chunks_mut(rows_per * mid_stride).enumerate() {
                    s.spawn(move || v_band(band, b * rows_per));
                }
            });
        }
        dst
    }
}

/// CPU box-filter downscale for BGRA frames. For each destination
/// pixel, averages the source pixels inside the mapped rectangle.
/// Handles non-integer ratios (e.g. 3840×2160 → 1920×1200). Survives
/// below the `lanczos_min_scale` floor purely as a CPU guard for huge
/// (4K+) sources — see [`use_lanczos_for_scale`].
fn downscale_bgra_box(
    src: &[u8],
    src_w: u32,
    src_h: u32,
    src_stride: u32,
    dst_w: u32,
    dst_h: u32,
) -> Vec<u8> {
    let mut dst = vec![0u8; (dst_w as usize) * (dst_h as usize) * 4];
    let src_w_u = src_w as u64;
    let src_h_u = src_h as u64;
    for dy in 0..dst_h {
        let sy_start = (dy as u64 * src_h_u / dst_h as u64) as u32;
        let sy_end_raw = ((dy as u64 + 1) * src_h_u).div_ceil(dst_h as u64) as u32;
        let sy_end = sy_end_raw.min(src_h);
        for dx in 0..dst_w {
            let sx_start = (dx as u64 * src_w_u / dst_w as u64) as u32;
            let sx_end_raw = ((dx as u64 + 1) * src_w_u).div_ceil(dst_w as u64) as u32;
            let sx_end = sx_end_raw.min(src_w);
            let mut b: u32 = 0;
            let mut g: u32 = 0;
            let mut r: u32 = 0;
            let mut a: u32 = 0;
            let mut n: u32 = 0;
            for sy in sy_start..sy_end {
                let row_base = (sy * src_stride) as usize;
                for sx in sx_start..sx_end {
                    let i = row_base + (sx as usize) * 4;
                    b += src[i] as u32;
                    g += src[i + 1] as u32;
                    r += src[i + 2] as u32;
                    a += src[i + 3] as u32;
                    n += 1;
                }
            }
            if let Some(divisor) = std::num::NonZeroU32::new(n) {
                let di = ((dy * dst_w + dx) as usize) * 4;
                dst[di] = (b / divisor.get()) as u8;
                dst[di + 1] = (g / divisor.get()) as u8;
                dst[di + 2] = (r / divisor.get()) as u8;
                dst[di + 3] = (a / divisor.get()) as u8;
            }
        }
    }
    dst
}

/// The dims `apply_target_resolution` produces for a frame of `native`
/// dims under `target` — the resampler's rule stated without a frame:
/// `Native` is the frame; a `Fixed` box at or above the frame is a no-op
/// (no upscaling); a zero box is a no-op; anything else is the box.
///
/// FR-70 M2 — the FFmpeg pump opens a make-before-break replacement at
/// these dims BEFORE any frame at them exists, so this and the function
/// below must agree; `target_dims_agrees_with_apply` locks them.
#[cfg_attr(not(feature = "ffmpeg-encoder"), allow(dead_code))]
pub(crate) fn target_dims(native: (u32, u32), target: TargetResolution) -> (u32, u32) {
    match target.fixed_dims() {
        None => native,
        Some((width, height)) => {
            if (width >= native.0 && height >= native.1) || width == 0 || height == 0 {
                native
            } else {
                (width, height)
            }
        }
    }
}

/// Downscale `frame` to the controller/policy-chosen resolution.
/// `TargetResolution::Native` is a no-op; `Fixed` sizes larger or equal
/// to the capture are also no-ops (upscaling serves no purpose — the
/// encoder just gets interpolated pixels). Returns the same `Arc<Frame>`
/// when no work is needed, so idle sessions don't pay the allocator cost.
///
/// rc.191 — filter selection by ratio; P7 (2026-08-20) — the floor is now
/// env-tunable and deep enough to cover the Smoother rungs. Box averaging
/// blends fractional neighbours into ClearType mush at ANY non-integer
/// ratio (rc.191 field: relay 0.67× and fit 0.75× "blurred/pixely" — and
/// the Smoother 1024 cap, 1920→1024 = 0.533×, fell straight through the
/// old `> 0.55` gate onto box: the exact text-mush case Lanczos was added
/// for). Kill switches: `MESHHARBORD_LANCZOS=0` (box everywhere),
/// `MESHHARBORD_LANCZOS_MIN_PCT=56` (restore the pre-P7 gate).
pub(crate) fn apply_target_resolution(
    rs: &mut Resampler,
    frame: Arc<Frame>,
    target: TargetResolution,
) -> Arc<Frame> {
    let Some((tw, th)) = target.fixed_dims() else {
        return frame;
    };
    if tw >= frame.width && th >= frame.height {
        // Cap at native — don't upscale.
        return frame;
    }
    if tw == 0 || th == 0 {
        return frame;
    }
    if frame.pixel_format != PixelFormat::Bgra {
        // Non-BGRA frames shouldn't reach this point today (both scrap
        // and WGC emit BGRA), but be defensive — pass through rather
        // than produce a mis-formatted downscale.
        return frame;
    }
    let scale = (tw as f32 / frame.width as f32).min(th as f32 / frame.height as f32);
    let downscaled = if use_lanczos_for_scale(scale, lanczos_min_scale(), lanczos_enabled()) {
        rs.lanczos3(&frame.data, frame.width, frame.height, frame.stride, tw, th)
    } else {
        downscale_bgra_box(&frame.data, frame.width, frame.height, frame.stride, tw, th)
    };
    Arc::new(Frame {
        width: tw,
        height: th,
        stride: tw * 4,
        pixel_format: PixelFormat::Bgra,
        data: downscaled,
        monotonic_us: frame.monotonic_us,
        monitor: frame.monitor,
        // P8a — damage survives the resample (it used to be dropped
        // here, which destroyed every tracked rect on the field path).
        damage: crate::capture::scale_damage(&frame.damage, frame.width, frame.height, tw, th),
        // Phase B — native-dims truth PROPAGATES: a frame that was
        // already backend-scaled keeps its original source; a native
        // frame records its own pre-scale dims.
        source: Some(frame.native_dims()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Damage;

    /// FR-70 M2 — `target_dims` is the resampler's rule without a frame;
    /// the pump opens the make-before-break replacement at what it returns.
    #[test]
    fn target_dims_is_native_for_native_zero_and_oversized_boxes() {
        let native = (1920, 1200);
        assert_eq!(target_dims(native, TargetResolution::Native), native);
        assert_eq!(
            target_dims(
                native,
                TargetResolution::Fixed {
                    width: 0,
                    height: 738
                }
            ),
            native
        );
        assert_eq!(
            target_dims(
                native,
                TargetResolution::Fixed {
                    width: 1214,
                    height: 0
                }
            ),
            native
        );
        // Fit on a stage larger than the host (2064×1150 at DPR 1.35) —
        // the box is at or above the frame on both axes: a no-op.
        assert_eq!(
            target_dims(
                native,
                TargetResolution::Fixed {
                    width: 2064,
                    height: 1200
                }
            ),
            native
        );
        assert_eq!(
            target_dims(
                native,
                TargetResolution::Fixed {
                    width: 1920,
                    height: 1200
                }
            ),
            native
        );
    }

    #[test]
    fn target_dims_is_the_box_when_it_is_below_the_frame() {
        let native = (1920, 1200);
        assert_eq!(
            target_dims(
                native,
                TargetResolution::Fixed {
                    width: 1214,
                    height: 758
                }
            ),
            (1214, 758)
        );
        assert_eq!(
            target_dims(
                native,
                TargetResolution::Fixed {
                    width: 944,
                    height: 590
                }
            ),
            (944, 590)
        );
        // One axis below the frame is enough to resample (the resampler
        // only passes through when BOTH are at or above it).
        assert_eq!(
            target_dims(
                native,
                TargetResolution::Fixed {
                    width: 2064,
                    height: 1150
                }
            ),
            (2064, 1150)
        );
    }

    /// The two functions must agree, or the replacement opens at dims no
    /// frame will ever have. Uses the real resampler on a small BGRA frame.
    #[test]
    fn target_dims_agrees_with_apply() {
        let (w, h) = (64u32, 40u32);
        let frame = Arc::new(Frame {
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: PixelFormat::Bgra,
            data: vec![0u8; (w * h * 4) as usize],
            monotonic_us: 0,
            monitor: 0,
            damage: Damage::Unknown,
            source: None,
        });
        let mut rs = Resampler::new();
        for target in [
            TargetResolution::Native,
            TargetResolution::Fixed {
                width: 32,
                height: 20,
            },
            TargetResolution::Fixed {
                width: 64,
                height: 40,
            },
            TargetResolution::Fixed {
                width: 128,
                height: 80,
            },
            TargetResolution::Fixed {
                width: 128,
                height: 20,
            },
            TargetResolution::Fixed {
                width: 0,
                height: 20,
            },
        ] {
            let out = apply_target_resolution(&mut rs, frame.clone(), target);
            assert_eq!(
                (out.width, out.height),
                target_dims((w, h), target),
                "target {target:?}"
            );
        }
    }

    /// The pre-Phase-A reference implementation (fresh taps, alpha
    /// resampled, per-frame buffers) — kept ONLY to pin the Resampler's
    /// colour output byte-identical on the B/G/R lanes.
    fn reference_lanczos3(
        src: &[u8],
        src_w: u32,
        src_h: u32,
        src_stride: u32,
        dst_w: u32,
        dst_h: u32,
    ) -> Vec<u8> {
        let h_taps = lanczos3_taps(src_w, dst_w);
        let v_taps = lanczos3_taps(src_h, dst_h);
        let mut mid = vec![0i16; (dst_w as usize) * (src_h as usize) * 4];
        for y in 0..src_h as usize {
            let row = y * src_stride as usize;
            let mid_row = y * (dst_w as usize) * 4;
            for (x, (lo, ws)) in h_taps.iter().enumerate() {
                let mut acc = [0i32; 4];
                for (k, w) in ws.iter().enumerate() {
                    let si = row + ((*lo as usize) + k) * 4;
                    acc[0] += w * src[si] as i32;
                    acc[1] += w * src[si + 1] as i32;
                    acc[2] += w * src[si + 2] as i32;
                    acc[3] += w * src[si + 3] as i32;
                }
                let di = mid_row + x * 4;
                mid[di] = (acc[0] >> 6) as i16;
                mid[di + 1] = (acc[1] >> 6) as i16;
                mid[di + 2] = (acc[2] >> 6) as i16;
                mid[di + 3] = (acc[3] >> 6) as i16;
            }
        }
        let mut dst = vec![0u8; (dst_w as usize) * (dst_h as usize) * 4];
        let mid_stride = (dst_w as usize) * 4;
        for (y, (lo, ws)) in v_taps.iter().enumerate() {
            let dst_row = y * mid_stride;
            for x in 0..dst_w as usize {
                let mut acc = [0i32; 4];
                for (k, w) in ws.iter().enumerate() {
                    let si = ((*lo as usize) + k) * mid_stride + x * 4;
                    acc[0] += w * mid[si] as i32;
                    acc[1] += w * mid[si + 1] as i32;
                    acc[2] += w * mid[si + 2] as i32;
                    acc[3] += w * mid[si + 3] as i32;
                }
                let di = dst_row + x * 4;
                dst[di] = ((acc[0] + (1 << 17)) >> 18).clamp(0, 255) as u8;
                dst[di + 1] = ((acc[1] + (1 << 17)) >> 18).clamp(0, 255) as u8;
                dst[di + 2] = ((acc[2] + (1 << 17)) >> 18).clamp(0, 255) as u8;
                dst[di + 3] = ((acc[3] + (1 << 17)) >> 18).clamp(0, 255) as u8;
            }
        }
        dst
    }

    /// Deterministic pseudo-noise source so the equivalence tests cover
    /// negative-lobe clamping, not just flat fields.
    fn noise_frame(w: u32, h: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity((w * h * 4) as usize);
        let mut state = 0x9e3779b9u32;
        for _ in 0..(w * h) {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            let b = state.to_le_bytes();
            v.extend_from_slice(&[b[0], b[1], b[2], 0xFF]);
        }
        v
    }

    // P7 (2026-08-20) — the Lanczos gate must cover the Smoother rungs. The
    // pre-P7 `scale > 0.55` gate sent the MAIN field case (Priority=Smoother
    // on a 1920×1200 panel → 1024×640 = 0.533×) to the box filter — the
    // exact ClearType-mush case Lanczos was added for in rc.191.
    #[test]
    fn lanczos_gate_covers_smoother_rungs() {
        // Default floor 0.34: the Smoother rungs take Lanczos…
        assert!(use_lanczos_for_scale(0.533, 0.34, true)); // 1920→1024
        assert!(use_lanczos_for_scale(0.40, 0.34, true)); // 2560→1024
        assert!(use_lanczos_for_scale(0.34, 0.34, true)); // inclusive floor
        // …while 4K sources stay on box (a CPU guard, not quality policy).
        assert!(!use_lanczos_for_scale(0.333, 0.34, true)); // 3840→1280
        assert!(!use_lanczos_for_scale(0.267, 0.34, true)); // 3840→1024
        // Kill switch wins regardless of ratio.
        assert!(!use_lanczos_for_scale(0.75, 0.34, false));
    }

    // P7 — the Q12 weight normalisation must hold at the newly-admitted
    // deep ratio: a constant-colour field survives 1920×1200 → 1024×640
    // exactly (any drift would band flat UI backgrounds).
    #[test]
    fn lanczos_flat_field_roundtrip_at_deep_ratio() {
        let (sw, sh, dw, dh) = (1920u32, 1200u32, 1024u32, 640u32);
        let mut src = vec![0u8; (sw * sh * 4) as usize];
        for px in src.chunks_exact_mut(4) {
            px.copy_from_slice(&[0x20, 0x80, 0xC0, 0xFF]);
        }
        let dst = Resampler::default().lanczos3(&src, sw, sh, sw * 4, dw, dh);
        assert_eq!(dst.len(), (dw * dh * 4) as usize);
        for px in dst.chunks_exact(4) {
            assert_eq!(px, [0x20, 0x80, 0xC0, 0xFF]);
        }
    }

    // P7 — lock the kernel-stretch behaviour the extended gate relies on:
    // at ratio r = src/dst the support is 3·r source pixels per side, so an
    // interior output pixel must see ≈2·3·r taps, and every row must still
    // sum to exactly 4096 (Q12) — the flat-field guarantee at any ratio.
    #[test]
    fn lanczos_taps_support_grows_with_ratio() {
        let taps = lanczos3_taps(1920, 1024); // r = 1.875 → support 5.625
        let (_lo, ws) = &taps[512]; // interior pixel, no edge clamping
        let expected = (2.0 * 3.0 * 1.875) as usize; // 11
        assert!(
            ws.len() >= expected && ws.len() <= expected + 2,
            "taps at r=1.875: {} (expected ≈{})",
            ws.len(),
            expected
        );
        for (_, ws) in &taps {
            assert_eq!(ws.iter().sum::<i32>(), 4096);
        }
    }

    // Phase A — the cached/flattened/alpha-skipping path is byte-identical
    // to the reference on B/G/R, and stamps A=0xFF.
    #[test]
    fn resampler_matches_reference_on_colour_lanes() {
        let (sw, sh, dw, dh) = (192u32, 120u32, 102u32, 64u32);
        let src = noise_frame(sw, sh);
        let expect = reference_lanczos3(&src, sw, sh, sw * 4, dw, dh);
        let got = Resampler::default().lanczos3(&src, sw, sh, sw * 4, dw, dh);
        assert_eq!(got.len(), expect.len());
        for (g, e) in got.chunks_exact(4).zip(expect.chunks_exact(4)) {
            assert_eq!(&g[..3], &e[..3], "colour lanes must match the reference");
            assert_eq!(g[3], 0xFF, "alpha is constant 0xFF");
        }
    }

    // Phase A — pooled-mid correctness across refine-style rung flips: the
    // second pass at each size must equal a fresh Resampler's output (a
    // stale-cache or under-sized-pool bug shows here).
    #[test]
    fn pooled_state_survives_rung_flips() {
        let src_a = noise_frame(192, 120);
        let src_b = noise_frame(160, 100);
        let mut rs = Resampler::new();
        let first = rs.lanczos3(&src_a, 192, 120, 192 * 4, 102, 64);
        let _other = rs.lanczos3(&src_b, 160, 100, 160 * 4, 80, 50);
        let again = rs.lanczos3(&src_a, 192, 120, 192 * 4, 102, 64);
        assert_eq!(first, again, "flip sequence must not corrupt cached state");
    }

    // Phase A — the thread lever must not change output.
    #[test]
    fn threaded_bands_match_single_thread() {
        let src = noise_frame(192, 120);
        let mut single = Resampler::default();
        let mut banded = Resampler {
            threads: 3,
            ..Resampler::default()
        };
        assert_eq!(
            single.lanczos3(&src, 192, 120, 192 * 4, 102, 64),
            banded.lanczos3(&src, 192, 120, 192 * 4, 102, 64),
        );
    }

    /// FR-65 — what the downscale actually costs, at the shape the field hit.
    /// `#[ignore]`d because it is a MEASUREMENT, not an assertion: thread
    /// scaling is hardware-dependent, so asserting a number here would only
    /// produce a test that fails on somebody else's laptop.
    ///
    /// Run: `cargo test -p meshharbord --lib -- --ignored --nocapture lanczos_cost`
    ///
    /// Context: CORPLAP-1 on the corp VPN reported `avg_scale_ms = 23.6` while
    /// downscaling its native panel to the constrained rung — and `0.0` at
    /// native resolution, so this path engages exactly when the host is already
    /// struggling. `scale_threads` defaults to **1**, so the row-banding below
    /// is implemented, correctness-tested (`threaded_bands_match_single_thread`)
    /// and switched off.
    #[test]
    #[ignore]
    fn lanczos_cost_by_thread_count() {
        const SW: u32 = 1920;
        const SH: u32 = 1200;
        const DW: u32 = 1280;
        const DH: u32 = 800;
        let src = noise_frame(SW, SH);
        println!(
            "available_parallelism = {:?}",
            std::thread::available_parallelism()
        );
        for threads in [1usize, 2, 4, 8] {
            let mut rs = Resampler {
                threads,
                ..Resampler::default()
            };
            // Warm the tap tables and the pooled intermediate so the numbers
            // describe steady state, not the first-frame build.
            let _ = rs.lanczos3(&src, SW, SH, SW * 4, DW, DH);
            const N: u32 = 20;
            let t = std::time::Instant::now();
            for _ in 0..N {
                let _ = rs.lanczos3(&src, SW, SH, SW * 4, DW, DH);
            }
            let per_ms = t.elapsed().as_secs_f64() * 1000.0 / f64::from(N);
            println!("lanczos3 {SW}x{SH} -> {DW}x{DH}  threads={threads}  {per_ms:.2} ms/frame");
        }
    }
}
