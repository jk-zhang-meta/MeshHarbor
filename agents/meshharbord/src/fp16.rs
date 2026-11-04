// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FP16 (scRGB) → BGRA8 sRGB pixel conversion for ACM / HDR desktops.
//!
//! ## Why (field WINHOST-F, 2026-07-23)
//!
//! Windows 11 Auto Color Management (ACM; Settings → Display → Advanced
//! display → "Automatically manage color for apps") makes the DWM composite
//! the desktop in IEEE half-float scRGB — even on SDR monitors with no HDR
//! support. Desktop Duplication then hands out
//! `DXGI_FORMAT_R16G16B16A16_FLOAT` (format 10) frames. ACM's hardware
//! floor is Intel 12th-gen / AMD RX 400 / NVIDIA Pascal, so every new
//! machine can arrive with it on. Before rc.207 the adapter-bound direct
//! backend refused non-BGRA8 desktops and fell back to the `scrap`
//! duplication path, which read those FP16 surfaces *as if* they were
//! BGRA8 — each 8-byte pixel became two garbled 4-byte pixels: a 2×
//! "zoomed", blue/purple, pixely mess flickering on every recomposited
//! (dragged) frame. This module lets the direct backend accept FP16 and
//! convert it properly instead.
//!
//! ## Approach
//!
//! One 64 KiB lookup table maps every possible half bit-pattern straight to
//! its 8-bit sRGB-encoded value (clamp to [0,1] → sRGB OETF → round). Rows
//! then convert with three table loads + one store per pixel — ~2-4 ms per
//! 1080p frame scalar, no SIMD needed at desktop sizes.
//!
//! ## Tone-map contract (v1)
//!
//! scRGB is linear with 1.0 = SDR reference white, so for an ACM'd SDR
//! desktop the clamp+encode reproduces the pre-ACM 8-bit desktop exactly
//! (modulo dithering). True-HDR content >1.0 clips to white and negative
//! (out-of-sRGB-gamut) values clip to 0 — acceptable for remote-desktop v1;
//! a real highlight tone-map can replace the clamp later without touching
//! the callers. NaN converts to 0.
//!
//! Everything here is pure integer/float math with no OS dependency, so it
//! compiles and tests under the default feature set on every platform even
//! though its only caller (`system_context::dxgi_direct`) is Windows-only.

/// Decode an IEEE 754 binary16 bit pattern to `f32`.
pub fn half_bits_to_f32(bits: u16) -> f32 {
    let sign = ((bits >> 15) & 1) as u32;
    let exp = ((bits >> 10) & 0x1F) as u32;
    let frac = (bits & 0x3FF) as u32;
    if exp == 0x1F {
        // Inf / NaN — widen the payload into the f32 exponent/mantissa.
        return f32::from_bits((sign << 31) | 0x7F80_0000 | (frac << 13));
    }
    if exp == 0 {
        // ±0 and subnormals: value = ±frac × 2⁻²⁴ (exact in f32).
        let magnitude = frac as f32 / 16_777_216.0;
        return if sign == 1 { -magnitude } else { magnitude };
    }
    // Normal: rebase the exponent (half bias 15 → f32 bias 127 ⇒ +112).
    f32::from_bits((sign << 31) | ((exp + 112) << 23) | (frac << 13))
}

/// Encode a linear-light value to an 8-bit sRGB code. Clamps to [0,1]
/// first (NaN → 0), so HDR highlights clip to white and out-of-gamut
/// negatives clip to black — the v1 tone-map contract above.
pub fn linear_to_srgb_u8(v: f32) -> u8 {
    // NOT `v.clamp(...)` — f32::clamp propagates NaN, and garbage FP16
    // payloads (e.g. uninitialized surface memory) must land on black.
    let c = if v.is_nan() { 0.0 } else { v.clamp(0.0, 1.0) };
    let s = if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    };
    (s * 255.0 + 0.5) as u8
}

/// Build the half-bits → sRGB-u8 lookup table (64 KiB, ~1 ms once).
pub fn build_half_to_srgb_lut() -> Box<[u8; 65536]> {
    let mut lut = vec![0u8; 65536].into_boxed_slice();
    for (i, slot) in lut.iter_mut().enumerate() {
        *slot = linear_to_srgb_u8(half_bits_to_f32(i as u16));
    }
    lut.try_into().expect("65536 entries by construction")
}

/// Convert one row of `px` RGBA16F pixels (8 bytes each, little-endian
/// halves, R-G-B-A channel order) into tightly-packed BGRA8. Alpha is
/// forced opaque — the desktop is opaque and FP16 alpha carries no useful
/// information for capture. Slices may be longer than needed; only the
/// first `px` pixels are read/written.
pub fn convert_row_rgba16f_to_bgra8(src: &[u8], dst: &mut [u8], px: usize, lut: &[u8; 65536]) {
    let src = &src[..px * 8];
    let dst = &mut dst[..px * 4];
    for (sp, dp) in src.chunks_exact(8).zip(dst.chunks_exact_mut(4)) {
        let r = u16::from_le_bytes([sp[0], sp[1]]) as usize;
        let g = u16::from_le_bytes([sp[2], sp[3]]) as usize;
        let b = u16::from_le_bytes([sp[4], sp[5]]) as usize;
        dp[0] = lut[b];
        dp[1] = lut[g];
        dp[2] = lut[r];
        dp[3] = 255;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HALF_ZERO: u16 = 0x0000;
    const HALF_HALF: u16 = 0x3800; // 0.5
    const HALF_ONE: u16 = 0x3C00; // 1.0
    const HALF_TWO: u16 = 0x4000; // 2.0
    const HALF_NEG_ONE: u16 = 0xBC00; // -1.0
    const HALF_INF: u16 = 0x7C00;
    const HALF_NAN: u16 = 0x7E00;

    #[test]
    fn half_decodes_key_values() {
        assert_eq!(half_bits_to_f32(HALF_ZERO), 0.0);
        assert_eq!(half_bits_to_f32(HALF_HALF), 0.5);
        assert_eq!(half_bits_to_f32(HALF_ONE), 1.0);
        assert_eq!(half_bits_to_f32(HALF_TWO), 2.0);
        assert_eq!(half_bits_to_f32(HALF_NEG_ONE), -1.0);
        assert_eq!(half_bits_to_f32(0x8000), 0.0); // -0
        assert!(half_bits_to_f32(HALF_INF).is_infinite());
        assert!(half_bits_to_f32(HALF_NAN).is_nan());
    }

    #[test]
    fn half_decodes_subnormals() {
        // Smallest positive subnormal: 2⁻²⁴.
        let tiny = half_bits_to_f32(0x0001);
        assert!((tiny - 5.960_464_5e-8).abs() < 1e-12);
        // Largest subnormal: 1023 × 2⁻²⁴, just below the smallest normal 2⁻¹⁴.
        let big_sub = half_bits_to_f32(0x03FF);
        let small_norm = half_bits_to_f32(0x0400);
        assert!(big_sub < small_norm);
        assert!((small_norm - 6.103_515_6e-5).abs() < 1e-10);
    }

    #[test]
    fn srgb_encode_checkpoints() {
        assert_eq!(linear_to_srgb_u8(0.0), 0);
        assert_eq!(linear_to_srgb_u8(1.0), 255);
        // Linear 0.5 → sRGB ≈ 0.7354 → 188.
        assert_eq!(linear_to_srgb_u8(0.5), 188);
        // The linear-segment boundary: 12.92 × 0.0031308 × 255 ≈ 10.3.
        assert_eq!(linear_to_srgb_u8(0.003_130_8), 10);
    }

    #[test]
    fn srgb_encode_clamps_hdr_and_garbage() {
        assert_eq!(linear_to_srgb_u8(2.0), 255); // HDR highlight → clip white
        assert_eq!(linear_to_srgb_u8(f32::INFINITY), 255);
        assert_eq!(linear_to_srgb_u8(-0.5), 0); // out-of-gamut → clip black
        assert_eq!(linear_to_srgb_u8(f32::NAN), 0);
    }

    #[test]
    fn lut_matches_scalar_path() {
        let lut = build_half_to_srgb_lut();
        for bits in [
            HALF_ZERO,
            HALF_HALF,
            HALF_ONE,
            HALF_TWO,
            HALF_NEG_ONE,
            HALF_INF,
            HALF_NAN,
        ] {
            assert_eq!(
                lut[bits as usize],
                linear_to_srgb_u8(half_bits_to_f32(bits))
            );
        }
        assert_eq!(lut[HALF_ONE as usize], 255);
        assert_eq!(lut[HALF_NAN as usize], 0);
    }

    /// Little-endian RGBA16F pixel from four half bit-patterns.
    fn px(r: u16, g: u16, b: u16, a: u16) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&r.to_le_bytes());
        out[2..4].copy_from_slice(&g.to_le_bytes());
        out[4..6].copy_from_slice(&b.to_le_bytes());
        out[6..8].copy_from_slice(&a.to_le_bytes());
        out
    }

    #[test]
    fn row_converts_channel_order_and_forces_alpha() {
        let lut = build_half_to_srgb_lut();
        // R=1.0, G=0.5, B=0.0 with a garbage alpha → BGRA [0, 188, 255, 255].
        let mut src = Vec::new();
        src.extend_from_slice(&px(HALF_ONE, HALF_HALF, HALF_ZERO, HALF_NAN));
        // Second pixel: pure blue → BGRA [255, 0, 0, 255].
        src.extend_from_slice(&px(HALF_ZERO, HALF_ZERO, HALF_ONE, HALF_ZERO));
        let mut dst = [0u8; 8];
        convert_row_rgba16f_to_bgra8(&src, &mut dst, 2, &lut);
        assert_eq!(dst, [0, 188, 255, 255, 255, 0, 0, 255]);
    }

    #[test]
    fn row_ignores_slack_beyond_px() {
        let lut = build_half_to_srgb_lut();
        // Row pitch padding after the pixel must be neither read nor written.
        let mut src = Vec::new();
        src.extend_from_slice(&px(HALF_ONE, HALF_ONE, HALF_ONE, HALF_ONE));
        src.extend_from_slice(&[0xAB; 16]); // pitch slack
        let mut dst = [0xCDu8; 12];
        convert_row_rgba16f_to_bgra8(&src, &mut dst, 1, &lut);
        assert_eq!(&dst[0..4], &[255, 255, 255, 255]);
        assert_eq!(&dst[4..], &[0xCD; 8]); // untouched
    }
}
